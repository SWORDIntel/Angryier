#![forbid(unsafe_code)]

//! Handwritten Intel 64 semantic providers for the Phase 4 corpus.
//!
//! Each provider implements `SemanticProvider` and emits rich semantic IR
//! for one instruction form. The corpus is deliberately small but exercises:
//!
//! - register-to-register data flow (MOV, ADD, SUB, XOR, AND, OR)
//! - immediate shift (SHL, SHR, SAR)
//! - flag computation (ZF, SF, CF) written to RFLAGS
//! - comparison without register write (CMP)
//! - conditional branch on RFLAGS (JZ, JNZ)
//! - unconditional jump (JMP)
//!
//! Flag simplification: the corpus computes ZF, SF, and CF. PF, AF, and OF
//! are left as 0. This is documented and will be completed in a later pass.

use crate::{forms, rflags, rule_id};
use angryier_arch_intel64::register_id;
use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder, SemanticContext, SemanticError,
    SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, ValueId,
};
use angryier_types::SemanticRuleId;

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U16: SemanticType = SemanticType::Scalar(ScalarType::BitVec(16));
const U8: SemanticType = SemanticType::Scalar(ScalarType::BitVec(8));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));

// ---------------------------------------------------------------------------
// Flag computation helpers
// ---------------------------------------------------------------------------

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

/// Widens a value to 64 bits so flag computation can use 64-bit constants.
/// x86 flag results for 32-bit operations are identical to the zero-extended
/// 64-bit computation (ZF is "result == 0", SF is the top bit of the result).
pub(crate) fn widen_to_u64(
    out: &mut dyn SemanticBuilder,
    value: ValueId,
    width_bits: u16,
) -> Result<ValueId, SemanticError> {
    if width_bits >= 64 {
        Ok(value)
    } else {
        out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[value])
    }
}

/// Emits a fall-through jump to the next instruction (address + length).
fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
    out.jump(next_pc)?;
    Ok(())
}

/// ZF and SF shifted flag values shared by every flag-writing helper.
/// `sign_bit` is the operand's sign position (63 for r64, 31 for r32, ...).
fn zf_sf(out: &mut dyn SemanticBuilder, result: ValueId, sign_bit: u16) -> Result<(ValueId, ValueId), SemanticError> {
    let zero = out.constant(U64, &0u64.to_le_bytes())?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let sixty_three = const_u64(out, u64::from(sign_bit))?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, sixty_three],
    )?;
    let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
    let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;
    Ok((zf_shifted, sf_shifted))
}

/// PF shifted flag value: PF = 1 when the low byte of `result` has even
/// parity (`pf = !lsb(result8 ^ result8>>4 ^ >>2 ^ >>1)`).
fn pf_flag(out: &mut dyn SemanticBuilder, result: ValueId) -> Result<ValueId, SemanticError> {
    let ff = const_u64(out, 0xff)?;
    let four = const_u64(out, 4)?;
    let two = const_u64(out, 2)?;
    let one = const_u64(out, 1)?;
    let pf_bit = const_u64(out, u64::from(rflags::PF_BIT))?;

    let low = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[result, ff])?;
    let a = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[low, four])?;
    let b = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[low, a])?;
    let c = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[b, two])?;
    let d = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[b, c])?;
    let e = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[d, one])?;
    let f = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[d, e])?;
    let g = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[f])?;
    let pf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[g, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[pf, pf_bit])
}

/// AF shifted flag value: AF = bit 4 of `left ^ right ^ result` (carry or
/// borrow out of bit 3 for both addition and subtraction).
fn af_flag(
    out: &mut dyn SemanticBuilder,
    left: ValueId,
    right: ValueId,
    result: ValueId,
) -> Result<ValueId, SemanticError> {
    let four = const_u64(out, 4)?;
    let one = const_u64(out, 1)?;
    let af_bit = const_u64(out, u64::from(rflags::AF_BIT))?;

    let a = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[left, right])?;
    let b = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[a, result])?;
    let c = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[b, four])?;
    let af = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[c, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[af, af_bit])
}

/// OF shifted flag value for addition:
/// `OF = ((left ^ result) & ~(left ^ right)) >> 63` on the widened u64 view.
fn of_add_flag(
    out: &mut dyn SemanticBuilder,
    left: ValueId,
    right: ValueId,
    result: ValueId,
    sign_bit: u16,
) -> Result<ValueId, SemanticError> {
    let sixty_three = const_u64(out, u64::from(sign_bit))?;
    let one = const_u64(out, 1)?;
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;

    let a = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[left, result])?;
    let b = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[left, right])?;
    let nb = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[b])?;
    let c = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[a, nb])?;
    let d = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[c, sixty_three],
    )?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[d, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of, of_bit])
}

/// OF shifted flag value for subtraction:
/// `OF = ((left ^ right) & (left ^ result)) >> 63` on the widened u64 view.
fn of_sub_flag(
    out: &mut dyn SemanticBuilder,
    left: ValueId,
    right: ValueId,
    result: ValueId,
    sign_bit: u16,
) -> Result<ValueId, SemanticError> {
    let sixty_three = const_u64(out, u64::from(sign_bit))?;
    let one = const_u64(out, 1)?;
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;

    let a = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[left, right])?;
    let b = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[left, result])?;
    let c = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[a, b])?;
    let d = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[c, sixty_three],
    )?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[d, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of, of_bit])
}

/// Folds shifted flag values into RFLAGS using an explicit clear mask —
/// for instructions where only a subset of the corpus flags are defined
/// (imul defines only CF/OF; undefined bits keep their incoming values).
fn compose_rflags_masked(
    out: &mut dyn SemanticBuilder,
    flags: &[ValueId],
    clear_mask: u64,
) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let mask = out.constant(U64, &clear_mask.to_le_bytes())?;
    let mut new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    for flag in flags {
        new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[new_rflags, *flag])?;
    }
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Folds shifted flag values into RFLAGS, preserving the non-corpus bits.
/// `preserve_cf` keeps the incoming CF (INC/DEC semantics).
fn compose_rflags(out: &mut dyn SemanticBuilder, flags: &[ValueId], preserve_cf: bool) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let mask_value = if preserve_cf {
        rflags::CORPUS_FLAG_MASK | (1 << rflags::CF_BIT)
    } else {
        rflags::CORPUS_FLAG_MASK
    };
    let mask = out.constant(U64, &mask_value.to_le_bytes())?;
    let mut new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    for flag in flags {
        new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[new_rflags, *flag])?;
    }
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

fn add_flag_values(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<Vec<ValueId>, SemanticError> {
    let sign_bit = width_bits - 1;
    let (zf, sf) = zf_sf(out, result, sign_bit)?;
    let pf = pf_flag(out, result)?;
    let af = af_flag(out, left, right, result)?;
    let of = of_add_flag(out, left, right, result, sign_bit)?;
    let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[result, left])?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
    Ok(vec![zf, sf, pf, af, of, cf])
}

/// CF and OF for a signed multiply: set when the full-width product's high
/// half is not the sign extension of the low half (result doesn't fit in
/// `width_bits`). Only CF/OF are architecturally defined for `imul`.
pub(crate) fn write_mul_flags(
    out: &mut dyn SemanticBuilder,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<(), SemanticError> {
    let double_ty = SemanticType::Scalar(ScalarType::BitVec(width_bits * 2));
    let single_ty = SemanticType::Scalar(ScalarType::BitVec(width_bits));
    let left2 = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), double_ty, &[left])?;
    let right2 = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), double_ty, &[right])?;
    let product = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), double_ty, &[left2, right2])?;
    let zero_off = const_u64(out, 0)?;
    let width_off = const_u64(out, u64::from(width_bits))?;
    let lo = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Extract),
        single_ty,
        &[product, zero_off],
    )?;
    let hi = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Extract),
        single_ty,
        &[product, width_off],
    )?;

    // expected_hi = sign-extension of lo's top bit: 0 or all-ones.
    let sign_off = const_u64(out, u64::from(width_bits - 1))?;
    let sign = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        single_ty,
        &[lo, sign_off],
    )?;
    let zero = out.constant(single_ty, &0u64.to_le_bytes()[..usize::from(width_bits / 8)])?;
    let expected_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), single_ty, &[zero, sign])?;

    // cf/of = hi != expected_hi
    let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[hi, expected_hi])?;
    let not_eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[eq])?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[not_eq])?;
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf, of_bit])?;

    compose_rflags_masked(out, &[cf, of], !((1 << rflags::CF_BIT) | (1 << rflags::OF_BIT)))
}

/// Shift family for flag computation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ShiftKind {
    Left,
    RightLogical,
    RightArith,
    RotateLeft,
    RotateRight,
}

/// Flags for shift/rotate instructions. CF = last bit out; OF = the
/// count-one formula (masked out by the caller's oracle when count > 1);
/// ZF/SF/PF on the result; AF left as the corpus's choice (undefined).
fn write_shift_flags(
    out: &mut dyn SemanticBuilder,
    operand: ValueId,
    count: ValueId,
    result: ValueId,
    kind: ShiftKind,
) -> Result<(), SemanticError> {
    let operand = widen_to_u64(out, operand, 64)?;
    let count = widen_to_u64(out, count, 64)?;
    let result = widen_to_u64(out, result, 64)?;

    let one = const_u64(out, 1)?;
    let sixty_three = const_u64(out, 63)?;
    let sixty_four = const_u64(out, 64)?;
    let zero = out.constant(U64, &0u64.to_le_bytes())?;

    // CF = last bit shifted out (dynamic count).
    let cf = match kind {
        ShiftKind::Left => {
            let shift = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[sixty_four, count])?;
            let raw = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                U64,
                &[operand, shift],
            )?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, one])?
        }
        ShiftKind::RightLogical | ShiftKind::RightArith => {
            let shift = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count, one])?;
            let raw = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                U64,
                &[operand, shift],
            )?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, one])?
        }
        ShiftKind::RotateLeft => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[result, one])?,
        ShiftKind::RotateRight => out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[result, sixty_three],
        )?,
    };

    // OF (count==1 semantics; masked by the oracle for count>1).
    let result_sign = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, sixty_three],
    )?;
    let of = match kind {
        ShiftKind::Left | ShiftKind::RotateLeft => {
            let raw = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[result_sign, cf])?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, one])?
        }
        ShiftKind::RightLogical => out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[operand, sixty_three],
        )?,
        ShiftKind::RightArith => zero,
        ShiftKind::RotateRight => {
            let bit62_off = const_u64(out, 62)?;
            let bit62 = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                U64,
                &[result, bit62_off],
            )?;
            let bit62 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[bit62, one])?;
            let raw = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[result_sign, bit62])?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, one])?
        }
    };
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of, of_bit])?;

    let (zf, sf) = zf_sf(out, result, 63)?;
    let pf = pf_flag(out, result)?;
    compose_rflags_masked(
        out,
        &[zf, sf, pf, of, cf],
        !((1 << rflags::CF_BIT)
            | (1 << rflags::PF_BIT)
            | (1 << rflags::ZF_BIT)
            | (1 << rflags::SF_BIT)
            | (1 << rflags::OF_BIT)),
    )
}

/// CF and OF for rotate instructions (the only architecturally defined
/// flags for rol/ror; count-one OF formula).
fn write_rotate_flags(out: &mut dyn SemanticBuilder, result: ValueId, kind: ShiftKind) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, 64)?;
    let one = const_u64(out, 1)?;
    let sixty_three = const_u64(out, 63)?;
    let result_sign = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, sixty_three],
    )?;
    let (cf, of) = match kind {
        ShiftKind::RotateLeft => {
            let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[result, one])?;
            let of = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[result_sign, cf])?;
            (cf, of)
        }
        ShiftKind::RotateRight => {
            let cf = result_sign;
            let bit62_off = const_u64(out, 62)?;
            let bit62 = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                U64,
                &[result, bit62_off],
            )?;
            let bit62 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[bit62, one])?;
            let of = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[cf, bit62])?;
            (cf, of)
        }
        _ => return Err(SemanticError::InvalidOperand),
    };
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of, of_bit])?;
    compose_rflags_masked(out, &[cf, of], !((1 << rflags::CF_BIT) | (1 << rflags::OF_BIT)))
}

fn sub_flag_values(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<Vec<ValueId>, SemanticError> {
    let sign_bit = width_bits - 1;
    let (zf, sf) = zf_sf(out, result, sign_bit)?;
    let pf = pf_flag(out, result)?;
    let af = af_flag(out, left, right, result)?;
    let of = of_sub_flag(out, left, right, result, sign_bit)?;
    let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[left, right])?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
    Ok(vec![zf, sf, pf, af, of, cf])
}

/// Computes ZF, SF, PF, AF, OF, and CF for an addition and writes RFLAGS.
/// `result = left + right` (wrapping). CF = carry out = `result < left`.
pub(crate) fn write_add_flags(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<(), SemanticError> {
    write_add_flags_impl(out, result, left, right, width_bits, false)
}

/// `write_add_flags` preserving the incoming CF — INC semantics.
pub(crate) fn write_add_flags_preserve_cf(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<(), SemanticError> {
    write_add_flags_impl(out, result, left, right, width_bits, true)
}

fn write_add_flags_impl(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
    preserve_cf: bool,
) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, width_bits)?;
    let left = widen_to_u64(out, left, width_bits)?;
    let right = widen_to_u64(out, right, width_bits)?;
    let mut flags = add_flag_values(out, result, left, right, width_bits)?;
    if preserve_cf {
        flags.pop(); // computed CF is not applied for INC/DEC
    }
    compose_rflags(out, &flags, preserve_cf)
}

/// Computes ZF, SF, PF, AF, OF, and CF for a subtraction and writes RFLAGS.
/// `result = left - right` (wrapping). CF = borrow = `left < right`.
pub(crate) fn write_sub_flags(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<(), SemanticError> {
    write_sub_flags_impl(out, result, left, right, width_bits, false)
}

/// `write_sub_flags` preserving the incoming CF — DEC semantics.
pub(crate) fn write_sub_flags_preserve_cf(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
) -> Result<(), SemanticError> {
    write_sub_flags_impl(out, result, left, right, width_bits, true)
}

fn write_sub_flags_impl(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    width_bits: u16,
    preserve_cf: bool,
) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, width_bits)?;
    let left = widen_to_u64(out, left, width_bits)?;
    let right = widen_to_u64(out, right, width_bits)?;
    let mut flags = sub_flag_values(out, result, left, right, width_bits)?;
    if preserve_cf {
        flags.pop(); // computed CF is not applied for INC/DEC
    }
    compose_rflags(out, &flags, preserve_cf)
}

/// Computes ZF, SF, and PF for a logical operation (CF=0, OF=0, AF=0) and
/// writes RFLAGS.
pub(crate) fn write_logical_flags(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    width_bits: u16,
) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, width_bits)?;
    let (zf, sf) = zf_sf(out, result, width_bits - 1)?;
    let pf = pf_flag(out, result)?;
    compose_rflags(out, &[zf, sf, pf], false)
}

/// Extracts ZF from RFLAGS. Returns a 1-bit value: 1 if ZF=0 (not set), 0 if ZF=1 (set).
fn read_zf_not_set(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    read_flag_not_set(out, rflags::ZF_BIT)
}

/// Extracts a flag bit from RFLAGS. Returns a 1-bit value: 1 if the flag is set.
fn read_flag_set(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let rflags_val = out.read_register(register_id::RFLAGS, U64)?;
    let bit_val = const_u64(out, u64::from(bit))?;
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[rflags_val, bit_val],
    )?;
    let mask = out.constant(U64, &1u64.to_le_bytes())?;
    let flag_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, mask])?;
    let one = out.constant(U64, &1u64.to_le_bytes())?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[flag_64, one])
}

/// Extracts a flag bit from RFLAGS. Returns a 1-bit value: 1 if the flag is NOT set.
fn read_flag_not_set(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let rflags_val = out.read_register(register_id::RFLAGS, U64)?;
    let bit_val = const_u64(out, u64::from(bit))?;
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[rflags_val, bit_val],
    )?;
    let mask = out.constant(U64, &1u64.to_le_bytes())?;
    let flag_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, mask])?;
    let zero = out.constant(U64, &0u64.to_le_bytes())?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[flag_64, zero])
}

fn receipt(offset: u64, context: &SemanticContext) -> SemanticReceipt {
    SemanticReceipt {
        rule_id: rule_id(offset),
        origin: SemanticOrigin::HandwrittenOverride,
        semantic_version: context.semantic_version,
    }
}

/// Writes only the ZF flag from `result == 0`, preserving CF, SF, and OF.
fn write_zf_only(out: &mut dyn SemanticBuilder, result: ValueId, width_bits: u16) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, width_bits)?;
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u64(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let zf_clear_mask = !(1u64 << rflags::ZF_BIT);
    let mask = out.constant(U64, &zf_clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;

    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Writes only the CF flag from `cf_value` (a 64-bit value of 0 or 1), preserving ZF, SF, and OF.
fn write_cf_only(out: &mut dyn SemanticBuilder, cf_value: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let cf_clear_mask = !(1u64 << rflags::CF_BIT);
    let mask = out.constant(U64, &cf_clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, cf_value])?;
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Providers: MOV r64, r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovR64R64;

impl SemanticProvider for MovR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        out.write_operand(0, src)?;
        fall_through(out, insn)?;
        Ok(receipt(0, context))
    }
}

// ---------------------------------------------------------------------------
// ADD r64, r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AddR64R64;

impl SemanticProvider for AddR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(1)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADD_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, right])?;
        write_add_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(1, context))
    }
}

// ---------------------------------------------------------------------------
// SUB r64, r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SubR64R64;

impl SemanticProvider for SubR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(2)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUB_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        write_sub_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(2, context))
    }
}

// ---------------------------------------------------------------------------
// XOR r64, r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct XorR64R64;

impl SemanticProvider for XorR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(3)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::XOR_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[left, right])?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(3, context))
    }
}

// ---------------------------------------------------------------------------
// AND r64, r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AndR64R64;

impl SemanticProvider for AndR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(4)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::AND_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[left, right])?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(4, context))
    }
}

// ---------------------------------------------------------------------------
// OR r64, r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct OrR64R64;

impl SemanticProvider for OrR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(5)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::OR_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[left, right])?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(5, context))
    }
}

// ---------------------------------------------------------------------------
// SHL r64, imm8
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ShlR64Imm8;

impl SemanticProvider for ShlR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(6)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SHL_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[left, count])?;
        write_shift_flags(out, left, count, result, ShiftKind::Left)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(6, context))
    }
}

// ---------------------------------------------------------------------------
// SHR r64, imm8 (logical shift right)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ShrR64Imm8;

impl SemanticProvider for ShrR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(7)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SHR_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[left, count],
        )?;
        write_shift_flags(out, left, count, result, ShiftKind::RightLogical)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(7, context))
    }
}

// ---------------------------------------------------------------------------
// SAR r64, imm8 (arithmetic shift right)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SarR64Imm8;

impl SemanticProvider for SarR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(8)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SAR_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U64,
            &[left, count],
        )?;
        write_shift_flags(out, left, count, result, ShiftKind::RightArith)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(8, context))
    }
}

// ---------------------------------------------------------------------------
// CMP r64, r64 (flags only, no register write)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmpR64R64;

impl SemanticProvider for CmpR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(9)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        write_sub_flags(out, result, left, right, 64)?;
        fall_through(out, insn)?;
        Ok(receipt(9, context))
    }
}

// ---------------------------------------------------------------------------
// JZ rel32 (jump if ZF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JzRel32;

impl SemanticProvider for JzRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(10)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JZ_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let zf_not_set = read_zf_not_set(out)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        // JZ: jump when ZF=1, i.e. when zf_not_set=0.
        // Branch(condition, taken_if_true, not_taken_if_false):
        //   condition=zf_not_set, taken(ZF=0)=next_pc, not_taken(ZF=1)=target
        out.branch(zf_not_set, next_pc, target)?;
        Ok(receipt(10, context))
    }
}

// ---------------------------------------------------------------------------
// JNZ rel32 (jump if ZF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JnzRel32;

impl SemanticProvider for JnzRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(11)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JNZ_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let zf_not_set = read_zf_not_set(out)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        // JNZ: jump when ZF=0, i.e. when zf_not_set=1.
        // Branch(condition, taken_if_true, not_taken_if_false):
        //   condition=zf_not_set, taken(ZF=0)=target, not_taken(ZF=1)=next_pc
        out.branch(zf_not_set, target, next_pc)?;
        Ok(receipt(11, context))
    }
}

// ---------------------------------------------------------------------------
// JMP rel32 (unconditional)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JmpRel32;

impl SemanticProvider for JmpRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(12)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JMP_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let target = out.read_operand(0, U64)?;
        out.jump(target)?;
        Ok(receipt(12, context))
    }
}

// ---------------------------------------------------------------------------
// MOV r64, imm64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovR64Imm64;

impl SemanticProvider for MovR64Imm64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(13)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R64_IMM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let imm = out.read_operand(1, U64)?;
        out.write_operand(0, imm)?;
        fall_through(out, insn)?;
        Ok(receipt(13, context))
    }
}

// ---------------------------------------------------------------------------
// ADD r64, imm32 (sign-extended to 64)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AddR64Imm32;

impl SemanticProvider for AddR64Imm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(14)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADD_R64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let imm32 = out.read_operand(1, U32)?;
        let right = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[imm32])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, right])?;
        write_add_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(14, context))
    }
}

// ---------------------------------------------------------------------------
// SUB r64, imm32 (sign-extended to 64)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SubR64Imm32;

impl SemanticProvider for SubR64Imm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(15)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUB_R64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let imm32 = out.read_operand(1, U32)?;
        let right = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[imm32])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        write_sub_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(15, context))
    }
}

// ---------------------------------------------------------------------------
// CMP r64, imm32 (sign-extended, flags only)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmpR64Imm32;

impl SemanticProvider for CmpR64Imm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(16)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let imm32 = out.read_operand(1, U32)?;
        let right = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[imm32])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        write_sub_flags(out, result, left, right, 64)?;
        fall_through(out, insn)?;
        Ok(receipt(16, context))
    }
}

// ---------------------------------------------------------------------------
// SHL r64, CL (shift left by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ShlR64Cl;

impl SemanticProvider for ShlR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(17)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SHL_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[left, count])?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(17, context))
    }
}

// ---------------------------------------------------------------------------
// SHR r64, CL (logical shift right by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ShrR64Cl;

impl SemanticProvider for ShrR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(18)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SHR_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[left, count],
        )?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(18, context))
    }
}

// ---------------------------------------------------------------------------
// SAR r64, CL (arithmetic shift right by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SarR64Cl;

impl SemanticProvider for SarR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(19)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SAR_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U64,
            &[left, count],
        )?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(19, context))
    }
}

// ---------------------------------------------------------------------------
// JC rel32 (jump if Carry, CF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JcRel32;

impl SemanticProvider for JcRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(20)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JC_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cf_set = read_flag_set(out, rflags::CF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        // JC: jump when CF=1, i.e. when cf_set=1.
        out.branch(cf_set, target, next_pc)?;
        Ok(receipt(20, context))
    }
}

// ---------------------------------------------------------------------------
// JNC rel32 (jump if Not Carry, CF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JncRel32;

impl SemanticProvider for JncRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(21)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JNC_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cf_not_set = read_flag_not_set(out, rflags::CF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        // JNC: jump when CF=0, i.e. when cf_not_set=1.
        out.branch(cf_not_set, target, next_pc)?;
        Ok(receipt(21, context))
    }
}

// ---------------------------------------------------------------------------
// JS rel32 (jump if Sign, SF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JsRel32;

impl SemanticProvider for JsRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(22)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JS_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let sf_set = read_flag_set(out, rflags::SF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        // JS: jump when SF=1, i.e. when sf_set=1.
        out.branch(sf_set, target, next_pc)?;
        Ok(receipt(22, context))
    }
}

// ---------------------------------------------------------------------------
// JNS rel32 (jump if Not Sign, SF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JnsRel32;

impl SemanticProvider for JnsRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(23)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JNS_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let sf_not_set = read_flag_not_set(out, rflags::SF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        // JNS: jump when SF=0, i.e. when sf_not_set=1.
        out.branch(sf_not_set, target, next_pc)?;
        Ok(receipt(23, context))
    }
}

// ---------------------------------------------------------------------------
// JL rel32 (jump if Less, SF!=OF; approximated as SF=1 since OF is always 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JlRel32;

impl SemanticProvider for JlRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(24)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JL_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JL: jump when SF!=OF. Since OF is always 0 in this corpus, this is SF=1.
        let sf_set = read_flag_set(out, rflags::SF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(sf_set, target, next_pc)?;
        Ok(receipt(24, context))
    }
}

// ---------------------------------------------------------------------------
// JGE rel32 (jump if Greater or Equal, SF==OF; approximated as SF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JgeRel32;

impl SemanticProvider for JgeRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(25)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JGE_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JGE: jump when SF==OF. Since OF is always 0 in this corpus, this is SF=0.
        let sf_not_set = read_flag_not_set(out, rflags::SF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(sf_not_set, target, next_pc)?;
        Ok(receipt(25, context))
    }
}

// ---------------------------------------------------------------------------
// INC r64 (increment, ZF/SF set, CF unchanged)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct IncR64;

impl SemanticProvider for IncR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(26)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::INC_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let one = const_u64(out, 1)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, one])?;
        write_add_flags_preserve_cf(out, result, left, one, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(26, context))
    }
}

// ---------------------------------------------------------------------------
// DEC r64 (decrement, ZF/SF set, CF unchanged)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct DecR64;

impl SemanticProvider for DecR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(27)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DEC_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let one = const_u64(out, 1)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, one])?;
        write_sub_flags_preserve_cf(out, result, left, one, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(27, context))
    }
}

// ---------------------------------------------------------------------------
// NEG r64 (negate, ZF/SF/CF set)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct NegR64;

impl SemanticProvider for NegR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(28)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NEG_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U64)?;
        let zero = const_u64(out, 0)?;
        // result = 0 - operand
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[zero, operand])?;
        // write_sub_flags computes CF = left < right = 0 < operand = (operand != 0)
        write_sub_flags(out, result, zero, operand, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(28, context))
    }
}

// ---------------------------------------------------------------------------
// NOT r64 (bitwise not, no flags modified)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct NotR64;

impl SemanticProvider for NotR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(29)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NOT_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[operand])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(29, context))
    }
}

// ---------------------------------------------------------------------------
// NOP (no operation)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Nop;

impl SemanticProvider for Nop {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(30)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NOP
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(30, context))
    }
}

// ===========================================================================
// Phase 4b expansion: memory load/store, multiply/divide, rotates, stack, LEA
// ===========================================================================

// ---------------------------------------------------------------------------
// MOV r64, [m64] (load from memory)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovR64Mem64;

impl SemanticProvider for MovR64Mem64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(31)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R64_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U64)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(31, context))
    }
}

// ---------------------------------------------------------------------------
// MOV [m64], r64 (store to memory)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovMem64R64;

impl SemanticProvider for MovMem64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(32)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_MEM64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U64)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(32, context))
    }
}

// ---------------------------------------------------------------------------
// ADD r64, [m64] (add from memory)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AddR64Mem64;

impl SemanticProvider for AddR64Mem64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(33)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADD_R64_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, right])?;
        write_add_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(33, context))
    }
}

// ---------------------------------------------------------------------------
// CMP r64, [m64] (compare with memory, flags only)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmpR64Mem64;

impl SemanticProvider for CmpR64Mem64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(34)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R64_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        write_sub_flags(out, result, left, right, 64)?;
        fall_through(out, insn)?;
        Ok(receipt(34, context))
    }
}

// ---------------------------------------------------------------------------
// IMUL r64, r64 (signed multiply, low 64 bits)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ImulR64R64;

impl SemanticProvider for ImulR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(35)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[left, right])?;
        write_mul_flags(out, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(35, context))
    }
}

// ---------------------------------------------------------------------------
// MUL r64, r64 (unsigned multiply, low 64 bits)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MulR64R64;

impl SemanticProvider for MulR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(36)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MUL_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[left, right])?;
        // Simplified: CF is cleared (no overflow detected in 64-bit IR).
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(36, context))
    }
}

// ---------------------------------------------------------------------------
// DIV r64, r64 (unsigned divide RAX / r64, quotient to RAX)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct DivR64R64;

impl SemanticProvider for DivR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(37)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIV_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dividend = out.read_register(RegisterId(register_id::GPR_BASE), U64)?;
        let divisor = out.read_operand(0, U64)?;
        let quotient = out.emit(
            SemanticOp::Primitive(PrimitiveOp::UnsignedDiv),
            U64,
            &[dividend, divisor],
        )?;
        write_zf_only(out, quotient, 64)?;
        out.write_register(RegisterId(register_id::GPR_BASE), quotient)?;
        fall_through(out, insn)?;
        Ok(receipt(37, context))
    }
}

// ---------------------------------------------------------------------------
// IDIV r64, r64 (signed divide RAX / r64, quotient to RAX)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct IdivR64R64;

impl SemanticProvider for IdivR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(38)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IDIV_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dividend = out.read_register(RegisterId(register_id::GPR_BASE), U64)?;
        let divisor = out.read_operand(0, U64)?;
        let quotient = out.emit(SemanticOp::Primitive(PrimitiveOp::SignedDiv), U64, &[dividend, divisor])?;
        write_zf_only(out, quotient, 64)?;
        out.write_register(RegisterId(register_id::GPR_BASE), quotient)?;
        fall_through(out, insn)?;
        Ok(receipt(38, context))
    }
}

// ---------------------------------------------------------------------------
// ROL r64, imm8 (rotate left)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RolR64Imm8;

impl SemanticProvider for RolR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(39)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ROL_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let shifted_left = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value, count_masked],
        )?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, complement],
        )?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_left, shifted_right],
        )?;
        write_rotate_flags(out, result, ShiftKind::RotateLeft)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(39, context))
    }
}

// ---------------------------------------------------------------------------
// ROR r64, imm8 (rotate right)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RorR64Imm8;

impl SemanticProvider for RorR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(40)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ROR_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_masked],
        )?;
        let shifted_left = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[value, complement])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_right, shifted_left],
        )?;
        write_rotate_flags(out, result, ShiftKind::RotateRight)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(40, context))
    }
}

// ---------------------------------------------------------------------------
// RCL r64, imm8 (rotate through carry left)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RclR64Imm8;

impl SemanticProvider for RclR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(41)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RCL_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let cf_1 = read_flag_set(out, rflags::CF_BIT)?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let one = const_u64(out, 1)?;
        let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count_masked, one])?;
        let shifted_left = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value, count_masked],
        )?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, complement],
        )?;
        // CF goes to position (count - 1); mask out that bit from shifted_right first.
        let bit_mask = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[one, count_minus_one],
        )?;
        let inv_bit_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[bit_mask])?;
        let shifted_right_masked = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U64,
            &[shifted_right, inv_bit_mask],
        )?;
        let cf_shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[cf_64, count_minus_one],
        )?;
        let partial = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_left, shifted_right_masked],
        )?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[partial, cf_shifted])?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted_right, one])?;
        write_cf_only(out, new_cf)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(41, context))
    }
}

// ---------------------------------------------------------------------------
// RCR r64, imm8 (rotate through carry right)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RcrR64Imm8;

impl SemanticProvider for RcrR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(42)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RCR_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let cf_1 = read_flag_set(out, rflags::CF_BIT)?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let one = const_u64(out, 1)?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_masked],
        )?;
        let shifted_left = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[value, complement])?;
        // CF goes to position (64 - count); mask out that bit from shifted_left first.
        let bit_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[one, complement])?;
        let inv_bit_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[bit_mask])?;
        let shifted_left_masked = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U64,
            &[shifted_left, inv_bit_mask],
        )?;
        let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, complement])?;
        let partial = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_right, shifted_left_masked],
        )?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[partial, cf_shifted])?;
        let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count_masked, one])?;
        let cf_raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_minus_one],
        )?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cf_raw, one])?;
        write_cf_only(out, new_cf)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(42, context))
    }
}

// ---------------------------------------------------------------------------
// PUSH r64 (decrement RSP, store register at [RSP])
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PushR64;

impl SemanticProvider for PushR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(43)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let value = out.read_operand(0, U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        // The decoded stack operand is reported relative to the pre-instruction
        // RSP, so the store lands at the post-decrement stack pointer.
        out.write_operand(1, value)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(43, context))
    }
}

// ---------------------------------------------------------------------------
// POP r64 (load from [RSP], write to register, increment RSP)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PopR64;

impl SemanticProvider for PopR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(44)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POP_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U64)?;
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, eight])?;
        out.write_operand(0, value)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(44, context))
    }
}

// ---------------------------------------------------------------------------
// PUSHF / POPF (push/pop the 64-bit RFLAGS image in 64-bit mode)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PushF;

impl SemanticProvider for PushF {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x166)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSHF
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        // Operand 0 is the suppressed RFLAGS read; operand 1 is the
        // suppressed stack write. Unlike PUSH r64, XED reports the pushf
        // stack operand at [rsp+0] — writing RSP first makes the store's
        // evaluated address land at [rsp-8].
        let value = out.read_operand(0, U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        out.write_operand(1, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x166, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PopF;

impl SemanticProvider for PopF {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x167)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POPF
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Operand 1 is the suppressed stack read; operand 0 is the
        // suppressed RFLAGS destination (XED models it ReadWrite).
        let value = out.read_operand(1, U64)?;
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, eight])?;
        out.write_operand(0, value)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(0x167, context))
    }
}

// ---------------------------------------------------------------------------
// LEA r64, [m] (compute effective address, no memory access)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct LeaR64Mem;

impl SemanticProvider for LeaR64Mem {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(45)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LEA_R64_MEM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let address = out.read_operand(1, U64)?;
        out.write_operand(0, address)?;
        fall_through(out, insn)?;
        Ok(receipt(45, context))
    }
}

// ---------------------------------------------------------------------------
// XCHG r64, r64 (swap two registers, no flags)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct XchgR64R64;

impl SemanticProvider for XchgR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(46)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::XCHG_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        out.write_operand(0, right)?;
        out.write_operand(1, left)?;
        fall_through(out, insn)?;
        Ok(receipt(46, context))
    }
}

// ---------------------------------------------------------------------------
// TEST r64, r64 (AND for flags only, no register write)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct TestR64R64;

impl SemanticProvider for TestR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(47)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::TEST_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[left, right])?;
        write_logical_flags(out, result, 64)?;
        fall_through(out, insn)?;
        Ok(receipt(47, context))
    }
}

// ---------------------------------------------------------------------------
// XADD r64, r64 (exchange and add: dest = dest + src, old dest -> src)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct XaddR64R64;

impl SemanticProvider for XaddR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(48)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::XADD_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dest = out.read_operand(0, U64)?;
        let src = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[dest, src])?;
        write_add_flags(out, result, dest, src, 64)?;
        out.write_operand(0, result)?;
        out.write_operand(1, dest)?;
        fall_through(out, insn)?;
        Ok(receipt(48, context))
    }
}

// ---------------------------------------------------------------------------
// BT r64, r64 (bit test: CF = bit(operand0, operand1), no write to operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BtR64R64;

impl SemanticProvider for BtR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(63)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BT_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let bit_index = out.read_operand(1, U64)?;
        let one = const_u64(out, 1)?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, bit_index],
        )?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
        write_cf_only(out, cf)?;
        fall_through(out, insn)?;
        Ok(receipt(63, context))
    }
}

// ---------------------------------------------------------------------------
// BTS r64, r64 (bit test and set: CF = bit, then set that bit in operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BtsR64R64;

impl SemanticProvider for BtsR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(64)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BTS_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let bit_index = out.read_operand(1, U64)?;
        let one = const_u64(out, 1)?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, bit_index],
        )?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
        write_cf_only(out, cf)?;
        let mask = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[one, bit_index])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[value, mask])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(64, context))
    }
}

// ---------------------------------------------------------------------------
// BTR r64, r64 (bit test and reset: CF = bit, then clear that bit in operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BtrR64R64;

impl SemanticProvider for BtrR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(65)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BTR_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let bit_index = out.read_operand(1, U64)?;
        let one = const_u64(out, 1)?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, bit_index],
        )?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
        write_cf_only(out, cf)?;
        let mask = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[one, bit_index])?;
        let not_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[value, not_mask])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(65, context))
    }
}

// ---------------------------------------------------------------------------
// BTC r64, r64 (bit test and complement: CF = bit, then complement that bit in operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BtcR64R64;

impl SemanticProvider for BtcR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(66)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BTC_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let bit_index = out.read_operand(1, U64)?;
        let one = const_u64(out, 1)?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, bit_index],
        )?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
        write_cf_only(out, cf)?;
        let mask = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[one, bit_index])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[value, mask])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(66, context))
    }
}

// ---------------------------------------------------------------------------
// CMOVZ r64, r64 (conditional move if ZF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmovzR64R64;

impl SemanticProvider for CmovzR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(59)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMOVZ_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_set(out, rflags::ZF_BIT)?;
        let dest = out.read_operand(0, U64)?;
        let src = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[cond, src, dest])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(59, context))
    }
}

// ---------------------------------------------------------------------------
// CMOVNZ r64, r64 (conditional move if ZF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmovnzR64R64;

impl SemanticProvider for CmovnzR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(60)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMOVNZ_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_not_set(out, rflags::ZF_BIT)?;
        let dest = out.read_operand(0, U64)?;
        let src = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[cond, src, dest])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(60, context))
    }
}

// ---------------------------------------------------------------------------
// CMOVL r64, r64 (conditional move if SF!=OF; OF always 0 so SF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmovlR64R64;

impl SemanticProvider for CmovlR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(61)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMOVL_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_set(out, rflags::SF_BIT)?;
        let dest = out.read_operand(0, U64)?;
        let src = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[cond, src, dest])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(61, context))
    }
}

// ---------------------------------------------------------------------------
// CMOVGE r64, r64 (conditional move if SF=OF; OF always 0 so SF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmovgeR64R64;

impl SemanticProvider for CmovgeR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(62)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMOVGE_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_not_set(out, rflags::SF_BIT)?;
        let dest = out.read_operand(0, U64)?;
        let src = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[cond, src, dest])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(62, context))
    }
}

// ---------------------------------------------------------------------------
// ROL r64, CL (rotate left by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RolR64Cl;

impl SemanticProvider for RolR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(55)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ROL_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let shifted_left = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value, count_masked],
        )?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, complement],
        )?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_left, shifted_right],
        )?;
        let one = const_u64(out, 1)?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted_right, one])?;
        write_cf_only(out, cf)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(55, context))
    }
}

// ---------------------------------------------------------------------------
// ROR r64, CL (rotate right by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RorR64Cl;

impl SemanticProvider for RorR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(56)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ROR_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_masked],
        )?;
        let shifted_left = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[value, complement])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_right, shifted_left],
        )?;
        let one = const_u64(out, 1)?;
        let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count_masked, one])?;
        let cf_raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_minus_one],
        )?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cf_raw, one])?;
        write_cf_only(out, cf)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(56, context))
    }
}

// ---------------------------------------------------------------------------
// RCL r64, CL (rotate through carry left by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RclR64Cl;

impl SemanticProvider for RclR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(57)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RCL_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let cf_1 = read_flag_set(out, rflags::CF_BIT)?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let one = const_u64(out, 1)?;
        let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count_masked, one])?;
        let shifted_left = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value, count_masked],
        )?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, complement],
        )?;
        // CF goes to position (count - 1); mask out that bit from shifted_right first.
        let bit_mask = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[one, count_minus_one],
        )?;
        let inv_bit_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[bit_mask])?;
        let shifted_right_masked = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U64,
            &[shifted_right, inv_bit_mask],
        )?;
        let cf_shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[cf_64, count_minus_one],
        )?;
        let partial = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_left, shifted_right_masked],
        )?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[partial, cf_shifted])?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted_right, one])?;
        write_cf_only(out, new_cf)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(57, context))
    }
}

// ---------------------------------------------------------------------------
// RCR r64, CL (rotate through carry right by CL register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RcrR64Cl;

impl SemanticProvider for RcrR64Cl {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(58)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RCR_R64_CL
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U64)?;
        let count = out.read_operand(1, U64)?;
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let cf_1 = read_flag_set(out, rflags::CF_BIT)?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let sixty_four = const_u64(out, 64)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let one = const_u64(out, 1)?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_masked],
        )?;
        let shifted_left = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[value, complement])?;
        // CF goes to position (64 - count); mask out that bit from shifted_left first.
        let bit_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[one, complement])?;
        let inv_bit_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[bit_mask])?;
        let shifted_left_masked = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U64,
            &[shifted_left, inv_bit_mask],
        )?;
        let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, complement])?;
        let partial = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_right, shifted_left_masked],
        )?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[partial, cf_shifted])?;
        let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count_masked, one])?;
        let cf_raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_minus_one],
        )?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cf_raw, one])?;
        write_cf_only(out, new_cf)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(58, context))
    }
}

// ---------------------------------------------------------------------------
// Register aliasing / partial writes / zero-sign extension helpers
// ---------------------------------------------------------------------------

/// Reads the full 64-bit source register from `operand_index`, extracts the
/// lower `src_ty` bits, and zero-extends the result to 64 bits.
///
/// In Intel 64, writing a 32-bit (or 8-bit) sub-register implicitly zero-extends
/// to the full 64-bit parent register. The semantic IR models this by reading
/// the full parent register, extracting the low bits, and zero-extending.
fn read_zero_extend(
    out: &mut dyn SemanticBuilder,
    operand_index: u8,
    src_ty: SemanticType,
) -> Result<ValueId, SemanticError> {
    // Read the operand at its declared width; the lowering narrows register
    // views when the decoded operand exposes more bits than requested.
    let src = out.read_operand(operand_index, src_ty)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[src])
}

/// Reads the operand at `src_ty` width and sign-extends the result to 64 bits.
fn read_sign_extend(
    out: &mut dyn SemanticBuilder,
    operand_index: u8,
    src_ty: SemanticType,
) -> Result<ValueId, SemanticError> {
    // Read the operand at its declared width and sign-extend to 64 bits. A
    // decoded operand may expose a narrower view than its parent register; the
    // lowering reads the parent's low bits for register operands.
    let src = out.read_operand(operand_index, src_ty)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[src])
}

// ---------------------------------------------------------------------------
// MOV r32, r32 (32-bit register move; zero-extends to 64-bit parent)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovR32R32;

impl SemanticProvider for MovR32R32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(49)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_zero_extend(out, 1, U32)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(49, context))
    }
}

// ---------------------------------------------------------------------------
// MOV r8, r8 (8-bit register move; zero-extends to 64-bit parent)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovR8R8;

impl SemanticProvider for MovR8R8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(50)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R8_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_zero_extend(out, 1, U8)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(50, context))
    }
}

// ---------------------------------------------------------------------------
// MOVZX r64, r32 (zero-extend 32-bit source to 64-bit destination)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovzxR64R32;

impl SemanticProvider for MovzxR64R32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(51)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVZX_R64_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_zero_extend(out, 1, U32)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(51, context))
    }
}

// ---------------------------------------------------------------------------
// MOVSX r64, r32 (sign-extend 32-bit source to 64-bit destination)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovsxR64R32;

impl SemanticProvider for MovsxR64R32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(52)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVSX_R64_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 1, U32)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(52, context))
    }
}

// ---------------------------------------------------------------------------
// MOVZX r64, r8 (zero-extend 8-bit source to 64-bit destination)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovzxR64R8;

impl SemanticProvider for MovzxR64R8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(53)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVZX_R64_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_zero_extend(out, 1, U8)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(53, context))
    }
}

// ---------------------------------------------------------------------------
// MOVSX r64, r8 (sign-extend 8-bit source to 64-bit destination)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovsxR64R8;

impl SemanticProvider for MovsxR64R8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(54)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVSX_R64_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 1, U8)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(54, context))
    }
}

// ---------------------------------------------------------------------------
// CLC (clear carry flag: CF = 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Clc;

impl SemanticProvider for Clc {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(67)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CLC
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let clear_cf_mask = !(1u64 << rflags::CF_BIT);
        let mask = out.constant(U64, &clear_cf_mask.to_le_bytes())?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;
        fall_through(out, insn)?;
        Ok(receipt(67, context))
    }
}

// ---------------------------------------------------------------------------
// STC (set carry flag: CF = 1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Stc;

impl SemanticProvider for Stc {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(68)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::STC
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let set_cf_mask = 1u64 << rflags::CF_BIT;
        let mask = out.constant(U64, &set_cf_mask.to_le_bytes())?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[old_rflags, mask])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;
        fall_through(out, insn)?;
        Ok(receipt(68, context))
    }
}

// ---------------------------------------------------------------------------
// CMC (complement carry flag: CF = ~CF)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cmc;

impl SemanticProvider for Cmc {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(69)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMC
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let toggle_cf_mask = 1u64 << rflags::CF_BIT;
        let mask = out.constant(U64, &toggle_cf_mask.to_le_bytes())?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[old_rflags, mask])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;
        fall_through(out, insn)?;
        Ok(receipt(69, context))
    }
}

// ---------------------------------------------------------------------------
// SETZ r8 (set operand 0 to 1 if ZF=1, else 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SetzR8;

impl SemanticProvider for SetzR8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(70)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SETZ_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_set(out, rflags::ZF_BIT)?;
        // The condition is written as a byte: 1 when set, 0 otherwise.
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[cond])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(70, context))
    }
}

// ---------------------------------------------------------------------------
// SETNZ r8 (set operand 0 to 1 if ZF=0, else 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SetnzR8;

impl SemanticProvider for SetnzR8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(71)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SETNZ_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_not_set(out, rflags::ZF_BIT)?;
        // The condition is written as a byte: 1 when set, 0 otherwise.
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[cond])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(71, context))
    }
}

// ---------------------------------------------------------------------------
// SETL r8 (set operand 0 to 1 if SF!=OF; OF always 0 so SF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SetlR8;

impl SemanticProvider for SetlR8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(72)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SETL_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_set(out, rflags::SF_BIT)?;
        // The condition is written as a byte: 1 when set, 0 otherwise.
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[cond])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(72, context))
    }
}

// ---------------------------------------------------------------------------
// SETGE r8 (set operand 0 to 1 if SF=OF; OF always 0 so SF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SetgeR8;

impl SemanticProvider for SetgeR8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(73)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SETGE_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cond = read_flag_not_set(out, rflags::SF_BIT)?;
        // The condition is written as a byte: 1 when set, 0 otherwise.
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[cond])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(73, context))
    }
}

// ---------------------------------------------------------------------------
// ADC r64, r64 (add with carry: result = left + right + CF)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AdcR64R64;

impl SemanticProvider for AdcR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(74)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADC_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let cf_1 = read_flag_set(out, rflags::CF_BIT)?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, right])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[sum, cf_64])?;
        write_add_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(74, context))
    }
}

// ---------------------------------------------------------------------------
// SBB r64, r64 (subtract with borrow: result = left - right - CF)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SbbR64R64;

impl SemanticProvider for SbbR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(75)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SBB_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let cf_1 = read_flag_set(out, rflags::CF_BIT)?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[diff, cf_64])?;
        write_sub_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(75, context))
    }
}

// ===========================================================================
// Phase 4c expansion: sign extension, CWD/CDQ, CMPXCHG, NOP2
// ===========================================================================

// ---------------------------------------------------------------------------
// CBW (sign-extend AL to AX; modeled as sign-extend lower 8 bits of operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cbw;

impl SemanticProvider for Cbw {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(76)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CBW
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 0, U8)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(76, context))
    }
}

// ---------------------------------------------------------------------------
// CWDE (sign-extend AX to EAX; modeled as sign-extend lower 16 bits of operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cwde;

impl SemanticProvider for Cwde {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(77)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CWDE
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 0, U16)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(77, context))
    }
}

// ---------------------------------------------------------------------------
// CDQE (sign-extend EAX to RAX; modeled as sign-extend lower 32 bits of operand 0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cdqe;

impl SemanticProvider for Cdqe {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(78)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CDQE
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 0, U32)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(78, context))
    }
}

// ---------------------------------------------------------------------------
// CWD (sign-extend AX to DX:AX; DX gets sign bits via arithmetic shift right)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cwd;

impl SemanticProvider for Cwd {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(79)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CWD
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 0, U16)?;
        let shift = const_u64(out, 15)?;
        let dx = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U64,
            &[value, shift],
        )?;
        out.write_operand(1, dx)?;
        fall_through(out, insn)?;
        Ok(receipt(79, context))
    }
}

// ---------------------------------------------------------------------------
// CDQ (sign-extend EAX to EDX:EAX; EDX gets sign bits via arithmetic shift right)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cdq;

impl SemanticProvider for Cdq {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(80)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CDQ
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = read_sign_extend(out, 0, U32)?;
        let shift = const_u64(out, 31)?;
        let edx = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U64,
            &[value, shift],
        )?;
        out.write_operand(1, edx)?;
        fall_through(out, insn)?;
        Ok(receipt(80, context))
    }
}

// ---------------------------------------------------------------------------
// CMPXCHG r64, r64 (compare RAX with dest; conditional swap)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmpxchgR64R64;

impl SemanticProvider for CmpxchgR64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(81)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMPXCHG_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dest = out.read_operand(0, U64)?;
        let source = out.read_operand(1, U64)?;
        let rax = out.read_register(RegisterId(register_id::GPR_BASE), U64)?;

        // eq = (dest == rax)
        let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[dest, rax])?;

        // If equal: dest <- source. If not equal: dest unchanged.
        let new_dest = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[eq, source, dest])?;

        // If equal: rax unchanged. If not equal: rax <- dest.
        let new_rax = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[eq, rax, dest])?;

        out.write_operand(0, new_dest)?;
        out.write_register(RegisterId(register_id::GPR_BASE), new_rax)?;

        // Set ZF from eq (1-bit): ZF=1 if equal, ZF=0 if not equal.
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
        let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[eq])?;
        let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;
        let zf_clear_mask = !(1u64 << rflags::ZF_BIT);
        let mask = out.constant(U64, &zf_clear_mask.to_le_bytes())?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;

        fall_through(out, insn)?;
        Ok(receipt(81, context))
    }
}

// ---------------------------------------------------------------------------
// NOP2 (multi-byte NOP variant; no operation, just fall through)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Nop2;

impl SemanticProvider for Nop2 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(82)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NOP2
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(82, context))
    }
}

// ---------------------------------------------------------------------------
// PUSH imm8 (sign-extended to 64, push onto stack)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PushImm8;

impl SemanticProvider for PushImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(83)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        // Read the 8-bit immediate and sign-extend it to 64-bit.
        let imm8 = out.read_operand(0, U8)?;
        let value = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[imm8])?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        out.write_operand(1, value)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(83, context))
    }
}

// ---------------------------------------------------------------------------
// PUSH imm32 (sign-extended to 64, push onto stack)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PushImm32;

impl SemanticProvider for PushImm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(84)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        // Read the 32-bit immediate and sign-extend it to 64-bit.
        let imm32 = out.read_operand(0, U32)?;
        let value = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[imm32])?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        out.write_operand(1, value)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(84, context))
    }
}

// ---------------------------------------------------------------------------
// CALL rel32 (push return address, jump to target)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CallRel32;

impl SemanticProvider for CallRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(85)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CALL_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        // The return address is the instruction address + length.
        let return_addr = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.write_operand(2, return_addr)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        let target = out.read_operand(0, U64)?;
        out.jump(target)?;
        Ok(receipt(85, context))
    }
}

// ---------------------------------------------------------------------------
// RET (pop return address, jump to it)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Ret;

impl SemanticProvider for Ret {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(86)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RET
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // RIP = [RSP]; RSP += 8. The return address is a computed target, so
        // the jump is indirect.
        let target = out.read_operand(1, U64)?;
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, eight])?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        out.jump_indirect(target)?;
        Ok(receipt(86, context))
    }
}

// ---------------------------------------------------------------------------
// JLE rel32 (jump if less or equal, signed: ZF=1 OR SF!=OF; OF=0 so ZF=1 OR SF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JleRel32;

impl SemanticProvider for JleRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(87)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JLE_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JLE: jump when ZF=1 OR SF!=OF. Since OF is always 0, this is ZF=1 OR SF=1.
        let zf_set = read_flag_set(out, rflags::ZF_BIT)?;
        let sf_set = read_flag_set(out, rflags::SF_BIT)?;
        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf_set, sf_set])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cond, target, next_pc)?;
        Ok(receipt(87, context))
    }
}

// ---------------------------------------------------------------------------
// JG rel32 (jump if greater, signed: ZF=0 AND SF==OF; OF=0 so ZF=0 AND SF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JgRel32;

impl SemanticProvider for JgRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(88)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JG_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JG: jump when ZF=0 AND SF==OF. Since OF is always 0, this is ZF=0 AND SF=0.
        let zf_not_set = read_flag_not_set(out, rflags::ZF_BIT)?;
        let sf_not_set = read_flag_not_set(out, rflags::SF_BIT)?;
        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[zf_not_set, sf_not_set])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cond, target, next_pc)?;
        Ok(receipt(88, context))
    }
}

// ---------------------------------------------------------------------------
// JA rel32 (jump if above, unsigned: CF=0 AND ZF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JaRel32;

impl SemanticProvider for JaRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(89)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JA_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JA: jump when CF=0 AND ZF=0.
        let cf_not_set = read_flag_not_set(out, rflags::CF_BIT)?;
        let zf_not_set = read_flag_not_set(out, rflags::ZF_BIT)?;
        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[cf_not_set, zf_not_set])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cond, target, next_pc)?;
        Ok(receipt(89, context))
    }
}

// ---------------------------------------------------------------------------
// JB rel32 (jump if below, unsigned: CF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JbRel32;

impl SemanticProvider for JbRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(90)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JB_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JB: jump when CF=1 (same as JC but a separate form).
        let cf_set = read_flag_set(out, rflags::CF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cf_set, target, next_pc)?;
        Ok(receipt(90, context))
    }
}

// ---------------------------------------------------------------------------
// JBE rel32 (jump if below or equal, unsigned: CF=1 OR ZF=1)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JbeRel32;

impl SemanticProvider for JbeRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(91)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JBE_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JBE: jump when CF=1 OR ZF=1.
        let cf_set = read_flag_set(out, rflags::CF_BIT)?;
        let zf_set = read_flag_set(out, rflags::ZF_BIT)?;
        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf_set, zf_set])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cond, target, next_pc)?;
        Ok(receipt(91, context))
    }
}

// ---------------------------------------------------------------------------
// JAE rel32 (jump if above or equal, unsigned: CF=0)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JaeRel32;

impl SemanticProvider for JaeRel32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(92)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JAE_REL32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // JAE: jump when CF=0 (same as JNC but a separate form).
        let cf_not_set = read_flag_not_set(out, rflags::CF_BIT)?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cf_not_set, target, next_pc)?;
        Ok(receipt(92, context))
    }
}

// ---------------------------------------------------------------------------
// LEAVE — RSP = RBP; RBP = [RBP]
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Leave;

impl SemanticProvider for Leave {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x200)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LEAVE
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let frame_pointer = out.read_operand(1, U64)?;
        let saved = out.read_operand(0, U64)?;
        out.write_operand(2, frame_pointer)?;
        out.write_operand(1, saved)?;
        fall_through(out, insn)?;
        Ok(receipt(0x200, context))
    }
}

// ---------------------------------------------------------------------------
// MOV [m64], imm32
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovMem64Imm32;

impl SemanticProvider for MovMem64Imm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x201)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_MEM64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U64)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x201, context))
    }
}

// ---------------------------------------------------------------------------
// CMP [m64], imm32 (flags only)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmpMem64Imm32;

impl SemanticProvider for CmpMem64Imm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x202)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_MEM64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[left, right])?;
        write_sub_flags(out, result, left, right, 64)?;
        fall_through(out, insn)?;
        Ok(receipt(0x202, context))
    }
}

// ---------------------------------------------------------------------------
// ADD [m64], r64
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AddMem64R64;

impl SemanticProvider for AddMem64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x203)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADD_MEM64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, right])?;
        write_add_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x203, context))
    }
}

// ---------------------------------------------------------------------------
// ADD [m64], imm32
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AddMem64Imm32;

impl SemanticProvider for AddMem64Imm32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x204)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADD_MEM64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[left, right])?;
        write_add_flags(out, result, left, right, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x204, context))
    }
}

// ---------------------------------------------------------------------------
// IMUL r64, [m64]
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ImulR64Mem64;

impl SemanticProvider for ImulR64Mem64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x205)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_R64_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[left, right])?;
        write_logical_flags(out, result, 64)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x205, context))
    }
}
