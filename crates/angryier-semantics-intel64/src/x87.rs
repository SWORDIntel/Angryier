#![forbid(unsafe_code)]

//! x87 FPU semantic family (first slice).
//!
//! State model: the eight x87 stack registers exist as 80-bit parents
//! (`X87_BASE..X87_BASE+7`) in the Intel 64 register file, and each slot holds
//! a 64-bit float payload in its low bits plus a 16-bit tag in its high bits:
//! `0x0000` marks a valid payload and `0xFFFF` marks an empty slot. The tag
//! word is therefore modeled inside the data plane — no extra architectural
//! state is required. The FPU status word (TOP and exception flags) has no
//! register in the file, so the stack pointer is modeled *logically*: pushes
//! and pops rotate the register contents, keeping logical ST(i) in physical
//! register i. This is observationally equivalent to hardware TOP renaming for
//! every instruction in this slice.
//!
//! Empty-slot reads produce the x87 QNaN real indefinite
//! (`0xFFF8_0000_0000_0000`), matching hardware with masked exceptions (the
//! masked state `fninit` establishes). Pushing onto a full stack likewise
//! loads the indefinite, matching masked hardware stack-overflow behavior.
//!
//! The FPU status word lives in its own 16-bit register (`register_id::X87_SW`)
//! holding TOP (bits 11..=13) and the condition codes C0/C1/C2/C3
//! (bits 8/9/10/14); exception and summary flags stay 0 in the masked model.
//! Although the data plane keeps logical ST(i) in physical slot i (so TOP is
//! architecturally "always 0" from the slot side), the status word mirrors the
//! hardware TOP arithmetic — decrement on push, increment on pop — so
//! `FSTSW AX` reports the same TOP a real CPU would after the same
//! push/pop sequence. `FSTCW` and full FPU state dumps remain unmodeled.
//!
//! Arithmetic runs on the f64 payload, following the SSE scalar-float
//! precedent: the concrete interpreter has no f80 arithmetic, and every
//! modeled operand crosses the f64 boundary exactly (memory forms are f32/f64,
//! and results are stored back through the same rounding the CPU applies).

use crate::{forms, rflags, rule_id};
use angryier_arch_intel64::X87_COUNT;
use angryier_arch_intel64::register_id;
use angryier_arch_intel64::register_id::X87_BASE;
use angryier_semantics::{
    DecodedInstructionView, FloatFormat, FloatingOp, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder,
    SemanticContext, SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType,
    ValueId,
};
use angryier_types::SemanticRuleId;

const U80: SemanticType = SemanticType::Scalar(ScalarType::BitVec(80));
const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U16: SemanticType = SemanticType::Scalar(ScalarType::BitVec(16));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));
const F32: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F32));
const F64: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F64));

/// x87 m64 real indefinite: stored by masked FST/FSTP on an empty source.
const INDEFINITE_F64: u64 = 0xFFF8_0000_0000_0000;
/// High 16 bits of an 80-bit stack slot carrying the empty tag.
const EMPTY_TAG: u16 = 0xFFFF;

fn const_u16(out: &mut dyn SemanticBuilder, value: u16) -> Result<ValueId, SemanticError> {
    out.constant(U16, &value.to_le_bytes())
}

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

fn const_f64(out: &mut dyn SemanticBuilder, bits: u64) -> Result<ValueId, SemanticError> {
    out.constant(F64, &bits.to_le_bytes())
}

fn st_reg(index: u32) -> RegisterId {
    RegisterId(X87_BASE + index)
}

// ---------------------------------------------------------------------------
// FPU status word (X87_SW): TOP tracking and FCOM condition codes
// ---------------------------------------------------------------------------

/// Status-word bit positions: C0/C1/C2/C3 and the TOP field.
pub(crate) const SW_C0_BIT: u16 = 8;
pub(crate) const SW_C1_BIT: u16 = 9;
pub(crate) const SW_C2_BIT: u16 = 10;
pub(crate) const SW_C3_BIT: u16 = 14;
pub(crate) const SW_TOP_SHIFT: u16 = 11;

/// Mirrors hardware TOP arithmetic on push (`delta = -1`) and pop
/// (`delta = +1`): TOP wraps modulo 8 through bits 11..=13 of the status
/// word. The data plane keeps ST(i) in physical slot i; only the reported
/// TOP follows the hardware rotation.
pub(crate) fn sw_adjust_top(out: &mut dyn SemanticBuilder, delta: i32) -> Result<(), SemanticError> {
    let old = out.read_register(register_id::X87_SW, U16)?;
    let top_shift = const_u16(out, SW_TOP_SHIFT)?;
    let top = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U16,
        &[old, top_shift],
    )?;
    let seven = const_u16(out, 7)?;
    let top = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[top, seven])?;
    // delta arrives as a 4-bit two's-complement constant; addition wraps mod 16
    // and the AND re-masks to the 3-bit TOP field, giving mod-8 wraparound.
    let delta_const = const_u16(out, (delta as u16) & 0xF)?;
    let adjusted = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[top, delta_const])?;
    let adjusted = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[adjusted, seven])?;
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
        U16,
        &[adjusted, top_shift],
    )?;
    let top_clear = const_u16(out, !(7 << SW_TOP_SHIFT))?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[old, top_clear])?;
    let merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[cleared, shifted])?;
    out.write_register(register_id::X87_SW, merged)?;
    Ok(())
}

/// Resets the status word to the `fninit` state (TOP=0, no condition codes,
/// no exception flags).
pub(crate) fn sw_clear(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    let zero = const_u16(out, 0)?;
    out.write_register(register_id::X87_SW, zero)?;
    Ok(())
}

/// Merges an FCOM-style comparison into the status-word condition codes.
/// `packed` is the `FloatingOp::Compare` result with ZF/CF/PF at their
/// RFLAGS positions (as consumed by `write_zf_cf_pf_packed`); the x87 status
/// word instead wants C0=CF (bit 8), C2=PF (bit 10), C3=ZF (bit 14).
pub(crate) fn write_fcom_condition_codes(
    out: &mut dyn SemanticBuilder,
    packed: ValueId,
    pop_delta: i32,
) -> Result<(), SemanticError> {
    let one = const_u64(out, 1)?;
    let zero = const_u64(out, 0)?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    let pf_bit = const_u64(out, u64::from(rflags::PF_BIT))?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let cf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[packed, cf_bit],
    )?;
    let c0 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cf_raw, one])?;
    let pf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[packed, pf_bit],
    )?;
    let c2 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[pf_raw, one])?;
    let zf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[packed, zf_bit],
    )?;
    let c3 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[zf_raw, one])?;

    // Repack the three one-bit codes into their status-word positions.
    let c0_pos = const_u64(out, 1 << SW_C0_BIT)?;
    let c2_pos = const_u64(out, 1 << SW_C2_BIT)?;
    let c3_pos = const_u64(out, 1 << SW_C3_BIT)?;
    let c0_merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[c0, c0_pos])?;
    let c2_merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[c2, c2_pos])?;
    let c3_merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[c3, c3_pos])?;
    let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[c0_merged, c2_merged])?;
    let codes = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[low, c3_merged])?;
    let codes = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[codes, zero])?;

    let old = out.read_register(register_id::X87_SW, U16)?;
    if pop_delta != 0 {
        // Adjust TOP and set condition codes in a single write so that neither
        // clobbers the other.
        let top_shift = const_u16(out, SW_TOP_SHIFT)?;
        let top = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U16,
            &[old, top_shift],
        )?;
        let seven = const_u16(out, 7)?;
        let top = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[top, seven])?;
        let delta_const = const_u16(out, (pop_delta as u16) & 0xF)?;
        let adjusted = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[top, delta_const])?;
        let adjusted = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[adjusted, seven])?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U16,
            &[adjusted, top_shift],
        )?;
        let clear = const_u16(
            out,
            !((1 << SW_C0_BIT) | (1 << SW_C2_BIT) | (1 << SW_C3_BIT) | (7 << SW_TOP_SHIFT)),
        )?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[old, clear])?;
        let with_codes = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[cleared, codes])?;
        let merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[with_codes, shifted])?;
        out.write_register(register_id::X87_SW, merged)?;
    } else {
        let clear = const_u16(out, !((1 << SW_C0_BIT) | (1 << SW_C1_BIT) | (1 << SW_C2_BIT) | (1 << SW_C3_BIT)))?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[old, clear])?;
        let merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[cleared, codes])?;
        out.write_register(register_id::X87_SW, merged)?;
    }
    Ok(())
}

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
    out.jump(next_pc)?;
    Ok(())
}

fn receipt(offset: u64, context: &SemanticContext) -> SemanticReceipt {
    SemanticReceipt {
        rule_id: rule_id(offset),
        origin: SemanticOrigin::HandwrittenOverride,
        semantic_version: context.semantic_version,
    }
}

/// Reads the raw 80-bit content of stack slot `index`.
fn read_st(out: &mut dyn SemanticBuilder, index: u32) -> Result<ValueId, SemanticError> {
    out.read_register(st_reg(index), U80)
}

/// Writes the raw 80-bit content of stack slot `index`.
fn write_st(out: &mut dyn SemanticBuilder, index: u32, value: ValueId) -> Result<(), SemanticError> {
    out.write_register(st_reg(index), value)?;
    Ok(())
}

/// Unpacks a stack slot into an f64 payload; an empty tag yields the x87
/// real indefinite (masked hardware behavior for empty-slot reads).
fn unpack_st(out: &mut dyn SemanticBuilder, raw: ValueId) -> Result<ValueId, SemanticError> {
    let zero = const_u64(out, 0)?;
    let sixty_four = const_u64(out, 64)?;
    let payload = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[raw, zero])?;
    let tag = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[raw, sixty_four])?;
    let zero_tag = const_u16(out, 0)?;
    let valid = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[tag, zero_tag])?;
    let indefinite = const_f64(out, INDEFINITE_F64)?;
    out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        F64,
        &[valid, payload, indefinite],
    )
}

/// Packs an f64 payload into the 80-bit stack-slot representation.
fn pack_st(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<ValueId, SemanticError> {
    let zero_tag = const_u16(out, 0)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U80, &[value, zero_tag])
}

/// The 80-bit empty-slot constant.
fn empty_slot(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    let mut bytes = [0u8; 10];
    bytes[8..].copy_from_slice(&EMPTY_TAG.to_le_bytes());
    out.constant(U80, &bytes)
}

/// Pushes `value` (an f64) onto the logical stack: slots rotate up and the
/// new payload lands in ST(0). Pushing onto a full stack (ST(7) valid) loads
/// the indefinite instead of the value, matching masked hardware overflow.
fn push_st(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<(), SemanticError> {
    let bottom = read_st(out, u32::from(X87_COUNT) - 1)?;
    let sixty_four = const_u64(out, 64)?;
    let bottom_tag = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[bottom, sixty_four])?;
    // The bottom slot carries the empty tag exactly when the stack has room.
    let empty_tag = const_u16(out, EMPTY_TAG)?;
    let has_room = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[bottom_tag, empty_tag])?;
    let indefinite = const_f64(out, INDEFINITE_F64)?;
    let pushed = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        F64,
        &[has_room, value, indefinite],
    )?;

    let mut sources = Vec::with_capacity(7);
    for index in 0..(X87_COUNT - 1) {
        sources.push(read_st(out, u32::from(index))?);
    }
    let packed = pack_st(out, pushed)?;
    for index in 0..(X87_COUNT - 1) {
        write_st(out, u32::from(index + 1), sources[usize::from(index)])?;
    }
    write_st(out, 0, packed)?;
    sw_adjust_top(out, -1)?;
    Ok(())
}

/// Pops the logical stack: slots rotate down and the bottom slot becomes
/// empty. The FSTP st(i) destination write is the caller's responsibility
/// (the stored value lands in slot i-1 of the post-pop stack).
fn pop_st(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    let mut sources = Vec::with_capacity(7);
    for index in 1..X87_COUNT {
        sources.push(read_st(out, u32::from(index))?);
    }
    let empty = empty_slot(out)?;
    for index in 0..(X87_COUNT - 1) {
        write_st(out, u32::from(index), sources[usize::from(index)])?;
    }
    write_st(out, u32::from(X87_COUNT) - 1, empty)?;
    sw_adjust_top(out, 1)?;
    Ok(())
}

/// Index of the x87 register named by the operand (parent id minus X87_BASE).
fn operand_st_index(insn: &dyn DecodedInstructionView, index: u8) -> Result<u32, SemanticError> {
    match insn.operand(index).map(|operand| operand.kind) {
        Some(angryier_arch::OperandKind::Register(view))
            if view.parent.0 >= X87_BASE && view.parent.0 < X87_BASE + u32::from(X87_COUNT) => Ok(view.parent.0 - X87_BASE),
        _ => Err(SemanticError::InvalidOperand),
    }
}

/// Merges a packed ZF/CF/PF flag word into RFLAGS (bits at RFLAGS positions).
fn write_zf_cf_pf_packed(out: &mut dyn SemanticBuilder, packed: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let clear_mask = !((1u64 << rflags::ZF_BIT) | (1u64 << rflags::CF_BIT) | (1u64 << rflags::PF_BIT));
    let mask = out.constant(U64, &clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, packed])?;
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// FINIT
// ---------------------------------------------------------------------------

/// FNINIT: marks every stack slot empty. The tag-in-data-plane analog of the
/// hardware tag-word reset; exceptions are masked (the masked-state model).
#[derive(Clone, Copy, Debug)]
pub struct Finit;

impl SemanticProvider for Finit {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x30B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FINIT
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let empty = empty_slot(out)?;
        for index in 0..X87_COUNT {
            write_st(out, u32::from(index), empty)?;
        }
        sw_clear(out)?;
        fall_through(out, insn)?;
        Ok(receipt(0x30B, context))
    }
}

// ---------------------------------------------------------------------------
// FLD: push from memory, st(i), or a constant
// ---------------------------------------------------------------------------

macro_rules! x87_load {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $convert:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let source = out.read_operand(1, $src_ty)?;
                let value = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[source])?
                } else {
                    source
                };
                push_st(out, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_load!(FldM32, forms::FLD_M32, 0x30C, F32, true);
x87_load!(FldM64, forms::FLD_M64, 0x30D, F64, false);

/// FLD st(i): pushes a copy of stack slot i (an empty source pushes the
/// indefinite, matching masked hardware).
#[derive(Clone, Copy, Debug)]
pub struct FldSti;

impl SemanticProvider for FldSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x30E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FLD_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let source = out.read_operand(1, U80)?;
        let value = unpack_st(out, source)?;
        push_st(out, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x30E, context))
    }
}

macro_rules! x87_load_const {
    ($name:ident, $form:expr, $rule:expr, $bits:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let value = const_f64(out, $bits)?;
                push_st(out, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_load_const!(Fld1, forms::FLD1, 0x30F, 0x3FF0_0000_0000_0000);
x87_load_const!(Fldz, forms::FLDZ, 0x310, 0x0000_0000_0000_0000);

// ---------------------------------------------------------------------------
// FST/FSTP: store ST(0) to memory or st(i), with or without a pop
// ---------------------------------------------------------------------------

/// FSTP st(i): stores ST(0) into the destination slot (relative to the
/// pre-pop stack), then pops.
#[derive(Clone, Copy, Debug)]
pub struct FstpSti;

impl SemanticProvider for FstpSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x311)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSTP_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = read_st(out, 0)?;
        let stored = unpack_st(out, top)?;
        let destination = operand_st_index(insn, 0)?;
        pop_st(out)?;
        if destination >= 1 {
            let packed = pack_st(out, stored)?;
            write_st(out, destination - 1, packed)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(0x311, context))
    }
}

macro_rules! x87_store {
    ($name:ident, $form:expr, $rule:expr, $dst_ty:expr, $convert:expr, $pop:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let top = read_st(out, 0)?;
                let stored = unpack_st(out, top)?;
                let value = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F32, &[stored])?
                } else {
                    stored
                };
                out.write_operand(0, value)?;
                if $pop {
                    pop_st(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_store!(FstM32, forms::FST_M32, 0x312, F32, true, false);
x87_store!(FstM64, forms::FST_M64, 0x313, F64, false, false);
x87_store!(FstpM32, forms::FSTP_M32, 0x314, F32, true, true);
x87_store!(FstpM64, forms::FSTP_M64, 0x315, F64, false, true);

// ---------------------------------------------------------------------------
// Arithmetic: two-stack-register and memory forms
// ---------------------------------------------------------------------------

/// Emits `left op right` (or `right op left` for the reversed R forms) as f64.
fn float_op(
    out: &mut dyn SemanticBuilder,
    op: FloatingOp,
    reversed: bool,
    left: ValueId,
    right: ValueId,
) -> Result<ValueId, SemanticError> {
    let (a, b) = if reversed { (right, left) } else { (left, right) };
    out.emit(SemanticOp::Float(op), F64, &[a, b])
}

/// Two-register arithmetic. Operand 0 is the read-write destination (st(0)
/// for the D8 encodings, st(i) for the DC encodings); operand 1 is the source.
macro_rules! x87_arith_st {
    ($name:ident, $form:expr, $rule:expr, $op:expr, $reversed:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let dst = out.read_operand(0, U80)?;
                let src = out.read_operand(1, U80)?;
                let dst_value = unpack_st(out, dst)?;
                let src_value = unpack_st(out, src)?;
                let result = float_op(out, $op, $reversed, dst_value, src_value)?;
                let packed = pack_st(out, result)?;
                out.write_operand(0, packed)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

/// Memory arithmetic: ST(0) combined with a memory operand.
macro_rules! x87_arith_mem {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $convert:expr, $op:expr, $reversed:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let dst = out.read_operand(0, U80)?;
                let source = out.read_operand(1, $src_ty)?;
                let src = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[source])?
                } else {
                    source
                };
                let dst_value = unpack_st(out, dst)?;
                let result = float_op(out, $op, $reversed, dst_value, src)?;
                let packed = pack_st(out, result)?;
                out.write_operand(0, packed)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_arith_st!(FaddSt0Sti, forms::FADD_ST0_STI, 0x316, FloatingOp::Add, false);
x87_arith_st!(FaddStiSt0, forms::FADD_STI_ST0, 0x317, FloatingOp::Add, false);
x87_arith_mem!(FaddM32, forms::FADD_M32, 0x318, F32, true, FloatingOp::Add, false);
x87_arith_mem!(FaddM64, forms::FADD_M64, 0x319, F64, false, FloatingOp::Add, false);

x87_arith_st!(FsubSt0Sti, forms::FSUB_ST0_STI, 0x31A, FloatingOp::Sub, false);
x87_arith_st!(FsubStiSt0, forms::FSUB_STI_ST0, 0x31B, FloatingOp::Sub, false);
x87_arith_mem!(FsubM32, forms::FSUB_M32, 0x31C, F32, true, FloatingOp::Sub, false);
x87_arith_mem!(FsubM64, forms::FSUB_M64, 0x31D, F64, false, FloatingOp::Sub, false);
x87_arith_st!(FsubrSt0Sti, forms::FSUBR_ST0_STI, 0x31E, FloatingOp::Sub, true);
x87_arith_st!(FsubrStiSt0, forms::FSUBR_STI_ST0, 0x31F, FloatingOp::Sub, true);
x87_arith_mem!(FsubrM32, forms::FSUBR_M32, 0x320, F32, true, FloatingOp::Sub, true);
x87_arith_mem!(FsubrM64, forms::FSUBR_M64, 0x321, F64, false, FloatingOp::Sub, true);

x87_arith_st!(FmulSt0Sti, forms::FMUL_ST0_STI, 0x322, FloatingOp::Mul, false);
x87_arith_st!(FmulStiSt0, forms::FMUL_STI_ST0, 0x323, FloatingOp::Mul, false);
x87_arith_mem!(FmulM32, forms::FMUL_M32, 0x324, F32, true, FloatingOp::Mul, false);
x87_arith_mem!(FmulM64, forms::FMUL_M64, 0x325, F64, false, FloatingOp::Mul, false);

x87_arith_st!(FdivSt0Sti, forms::FDIV_ST0_STI, 0x326, FloatingOp::Div, false);
x87_arith_st!(FdivStiSt0, forms::FDIV_STI_ST0, 0x327, FloatingOp::Div, false);
x87_arith_mem!(FdivM32, forms::FDIV_M32, 0x328, F32, true, FloatingOp::Div, false);
x87_arith_mem!(FdivM64, forms::FDIV_M64, 0x329, F64, false, FloatingOp::Div, false);
x87_arith_st!(FdivrSt0Sti, forms::FDIVR_ST0_STI, 0x32A, FloatingOp::Div, true);
x87_arith_st!(FdivrStiSt0, forms::FDIVR_STI_ST0, 0x32B, FloatingOp::Div, true);
x87_arith_mem!(FdivrM32, forms::FDIVR_M32, 0x32C, F32, true, FloatingOp::Div, true);
x87_arith_mem!(FdivrM64, forms::FDIVR_M64, 0x32D, F64, false, FloatingOp::Div, true);

// ---------------------------------------------------------------------------
// FCOMI/FUCOMI: compare ST(0) with ST(i) into ZF/PF/CF
// ---------------------------------------------------------------------------

macro_rules! x87_comi {
    ($name:ident, $form:expr, $rule:expr, $pop:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U80)?;
                let right = out.read_operand(1, U80)?;
                let left_value = unpack_st(out, left)?;
                let right_value = unpack_st(out, right)?;
                let flags = out.emit(
                    SemanticOp::Float(FloatingOp::Compare),
                    U64,
                    &[left_value, right_value],
                )?;
                write_zf_cf_pf_packed(out, flags)?;
                if $pop {
                    pop_st(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_comi!(FucomiSt0Sti, forms::FUCOMI_ST0_STI, 0x32E, false);
x87_comi!(FucomipSt0Sti, forms::FUCOMIP_ST0_STI, 0x32F, true);
x87_comi!(FcomiSt0Sti, forms::FCOMI_ST0_STI, 0x330, false);
x87_comi!(FcomipSt0Sti, forms::FCOMIP_ST0_STI, 0x331, true);

/// FLD m80. The current x87 data model stores an f64 payload plus a 16-bit
/// validity tag rather than an IEEE 754 extended-precision value. Preserve
/// the low 64 memory bits as the payload and discard the high exponent/sign
/// word for now; replacing this lossy bridge is explicit x87-model debt.
#[derive(Clone, Copy, Debug)]
pub struct FldM80;

impl SemanticProvider for FldM80 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1305)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FLD_M80
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let source = out.read_operand(1, U80)?;
        let zero = const_u64(out, 0)?;
        let payload = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[source, zero])?;
        push_st(out, payload)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1305, context))
    }
}

// ---------------------------------------------------------------------------
// FSTSW AX: store the FPU status word into AX
// ---------------------------------------------------------------------------

/// FNSTSW/FSTSW AX (`DF E0`): copies the 16-bit status word — TOP plus the
/// C0/C2/C3 condition codes left by FCOM-family compares — into AX. The AX
/// write preserves the upper 48 bits of RAX. Exception/summary flags read as
/// 0 in the masked-exceptions model; FSTSW m16 is not mapped yet.
#[derive(Clone, Copy, Debug)]
pub struct FstswAx;

impl SemanticProvider for FstswAx {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x332)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSTSW_AX
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let status = out.read_register(register_id::X87_SW, U16)?;
        out.write_operand(0, status)?;
        fall_through(out, insn)?;
        Ok(receipt(0x332, context))
    }
}

// ---------------------------------------------------------------------------
// Extended x87 Constants: FLDPI, FLDL2E, FLDL2T, FLDLG2, FLDLN2
// ---------------------------------------------------------------------------

x87_load_const!(Fldpi, forms::FLDPI, 0x333, 0x4009_21FB_5444_2D18);
x87_load_const!(Fldl2e, forms::FLDL2E, 0x334, 0x3FF7_1547_652B_82FE);
x87_load_const!(Fldl2t, forms::FLDL2T, 0x335, 0x400A_934F_0979_A371);
x87_load_const!(Fldlg2, forms::FLDLG2, 0x336, 0x3FD3_4413_509F_79FF);
x87_load_const!(Fldln2, forms::FLDLN2, 0x337, 0x3FE6_2E42_FEFA_39EF);

// ---------------------------------------------------------------------------
// FST st(i) and FNOP
// ---------------------------------------------------------------------------

/// FST st(i): stores ST(0) into ST(i) without popping.
#[derive(Clone, Copy, Debug)]
pub struct FstSti;

impl SemanticProvider for FstSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x338)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FST_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = read_st(out, 0)?;
        let stored = unpack_st(out, top)?;
        let destination = operand_st_index(insn, 0)?;
        let packed = pack_st(out, stored)?;
        write_st(out, destination, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x338, context))
    }
}

/// FNOP: No-operation (alias for FST st(0)).
#[derive(Clone, Copy, Debug)]
pub struct Fnop;

impl SemanticProvider for Fnop {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x339)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FNOP
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x339, context))
    }
}

// ---------------------------------------------------------------------------
// FSTSW m16, FLDCW m16, FNSTCW m16
// ---------------------------------------------------------------------------

/// FNSTSW/FSTSW m16: stores the 16-bit status word into memory.
#[derive(Clone, Copy, Debug)]
pub struct FstswM16;

impl SemanticProvider for FstswM16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x33A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSTSW_M16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let status = out.read_register(register_id::X87_SW, U16)?;
        out.write_operand(0, status)?;
        fall_through(out, insn)?;
        Ok(receipt(0x33A, context))
    }
}

/// FLDCW m16: loads the 16-bit FPU control word from memory.
#[derive(Clone, Copy, Debug)]
pub struct FldcwM16;

impl SemanticProvider for FldcwM16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x33B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FLDCW_M16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U16)?;
        out.write_register(register_id::X87_CW, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x33B, context))
    }
}

/// FNSTCW/FSTCW m16: stores the 16-bit FPU control word into memory.
#[derive(Clone, Copy, Debug)]
pub struct FnstcwM16;

impl SemanticProvider for FnstcwM16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x33C)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FNSTCW_M16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let cw = out.read_register(register_id::X87_CW, U16)?;
        out.write_operand(0, cw)?;
        fall_through(out, insn)?;
        Ok(receipt(0x33C, context))
    }
}

// ---------------------------------------------------------------------------
// FNCLEX, FTST, FXAM, FDECSTP, FINCSTP, FFREE
// ---------------------------------------------------------------------------

/// FNCLEX/FCLEX: clears floating-point exception flags in X87_SW.
#[derive(Clone, Copy, Debug)]
pub struct Fnclex;

impl SemanticProvider for Fnclex {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x33D)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FNCLEX
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let old = out.read_register(register_id::X87_SW, U16)?;
        let mask = const_u16(out, !0x80FF)?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[old, mask])?;
        out.write_register(register_id::X87_SW, cleared)?;
        fall_through(out, insn)?;
        Ok(receipt(0x33D, context))
    }
}

/// FTST: tests ST(0) against 0.0, updating condition codes C0/C2/C3 in X87_SW.
#[derive(Clone, Copy, Debug)]
pub struct Ftst;

impl SemanticProvider for Ftst {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x33E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FTST
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = read_st(out, 0)?;
        let top_val = unpack_st(out, top)?;
        let zero = const_f64(out, 0)?;
        let flags = out.emit(SemanticOp::Float(FloatingOp::Compare), U64, &[top_val, zero])?;
        write_fcom_condition_codes(out, flags, 0)?;
        fall_through(out, insn)?;
        Ok(receipt(0x33E, context))
    }
}

/// FXAM: examines ST(0), setting condition codes C0/C1/C2/C3 in X87_SW.
#[derive(Clone, Copy, Debug)]
pub struct Fxam;

impl SemanticProvider for Fxam {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x33F)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FXAM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let raw = read_st(out, 0)?;
        let sixty_four = const_u64(out, 64)?;
        let zero_u64 = const_u64(out, 0)?;
        let tag = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[raw, sixty_four])?;
        let payload = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[raw, zero_u64])?;

        let empty_tag = const_u16(out, EMPTY_TAG)?;
        let is_empty = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[tag, empty_tag])?;

        let sixty_three = const_u64(out, 63)?;
        let sign_bit = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[payload, sixty_three],
        )?;
        let one_u64 = const_u64(out, 1)?;
        let sign = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sign_bit, one_u64])?;
        let sign_u16 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[sign, zero_u64])?;
        let c1_shift = const_u16(out, SW_C1_BIT)?;
        let c1 = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U16,
            &[sign_u16, c1_shift],
        )?;

        let fifty_two = const_u64(out, 52)?;
        let exp_shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[payload, fifty_two],
        )?;
        let exp_mask = const_u64(out, 0x7FF)?;
        let exp = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[exp_shifted, exp_mask])?;

        let mant_mask = const_u64(out, 0x000F_FFFF_FFFF_FFFF)?;
        let mant = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[payload, mant_mask])?;

        let exp_all_ones = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[exp, exp_mask])?;
        let exp_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[exp, zero_u64])?;
        let mant_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[mant, zero_u64])?;
        let mant_non_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[mant_zero])?;

        let is_nan = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U1,
            &[exp_all_ones, mant_non_zero],
        )?;
        let is_inf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[exp_all_ones, mant_zero])?;
        let is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[exp_zero, mant_zero])?;
        let is_denorm = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[exp_zero, mant_non_zero])?;

        let c_empty = const_u16(out, (1 << SW_C3_BIT) | (1 << SW_C0_BIT))?;
        let c_nan = const_u16(out, 1 << SW_C0_BIT)?;
        let c_inf = const_u16(out, (1 << SW_C2_BIT) | (1 << SW_C0_BIT))?;
        let c_zero = const_u16(out, 1 << SW_C3_BIT)?;
        let c_denorm = const_u16(out, (1 << SW_C3_BIT) | (1 << SW_C2_BIT))?;
        let c_norm = const_u16(out, 1 << SW_C2_BIT)?;

        let cc = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Select),
            U16,
            &[is_denorm, c_denorm, c_norm],
        )?;
        let cc = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U16, &[is_zero, c_zero, cc])?;
        let cc = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U16, &[is_inf, c_inf, cc])?;
        let cc = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U16, &[is_nan, c_nan, cc])?;
        let cc = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Select),
            U16,
            &[is_empty, c_empty, cc],
        )?;
        let full_codes = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[cc, c1])?;

        let old = out.read_register(register_id::X87_SW, U16)?;
        let clear_mask = const_u16(
            out,
            !((1 << SW_C0_BIT) | (1 << SW_C1_BIT) | (1 << SW_C2_BIT) | (1 << SW_C3_BIT)),
        )?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[old, clear_mask])?;
        let merged = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[cleared, full_codes])?;
        out.write_register(register_id::X87_SW, merged)?;
        fall_through(out, insn)?;
        Ok(receipt(0x33F, context))
    }
}

/// FDECSTP: decrements TOP modulo 8 in X87_SW.
#[derive(Clone, Copy, Debug)]
pub struct Fdecstp;

impl SemanticProvider for Fdecstp {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x340)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FDECSTP
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        sw_adjust_top(out, -1)?;
        fall_through(out, insn)?;
        Ok(receipt(0x340, context))
    }
}

/// FINCSTP: increments TOP modulo 8 in X87_SW.
#[derive(Clone, Copy, Debug)]
pub struct Fincstp;

impl SemanticProvider for Fincstp {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x341)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FINCSTP
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        sw_adjust_top(out, 1)?;
        fall_through(out, insn)?;
        Ok(receipt(0x341, context))
    }
}

/// FFREE st(i): marks stack register st(i) empty.
#[derive(Clone, Copy, Debug)]
pub struct FfreeSti;

impl SemanticProvider for FfreeSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x342)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FFREE_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let index = operand_st_index(insn, 0)?;
        let empty = empty_slot(out)?;
        write_st(out, index, empty)?;
        fall_through(out, insn)?;
        Ok(receipt(0x342, context))
    }
}

// ---------------------------------------------------------------------------
// FRNDINT & FSINCOS
// ---------------------------------------------------------------------------

/// FRNDINT: rounds ST(0) to nearest integer.
#[derive(Clone, Copy, Debug)]
pub struct Frndint;

impl SemanticProvider for Frndint {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x343)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FRNDINT
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = read_st(out, 0)?;
        let val = unpack_st(out, top)?;
        let cw = out.read_register(register_id::X87_CW, U16)?;
        let ten = const_u16(out, 10)?;
        let rc = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U16, &[cw, ten])?;
        let three = const_u16(out, 0x3)?;
        let mode = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[rc, three])?;
        let mode_u32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[mode])?;
        let rounded = out.emit(SemanticOp::Float(FloatingOp::Round), F64, &[val, mode_u32])?;
        let packed = pack_st(out, rounded)?;
        write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x343, context))
    }
}

/// FSINCOS: computes sin and cos of ST(0), stores sin into ST(0) then pushes cos.
#[derive(Clone, Copy, Debug)]
pub struct Fsincos;

impl SemanticProvider for Fsincos {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x344)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSINCOS
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = read_st(out, 0)?;
        let val = unpack_st(out, top)?;
        let sin = out.emit(SemanticOp::Float(FloatingOp::Sin), F64, &[val])?;
        let cos = out.emit(SemanticOp::Float(FloatingOp::Cos), F64, &[val])?;
        let packed_sin = pack_st(out, sin)?;
        write_st(out, 0, packed_sin)?;
        push_st(out, cos)?;
        let old = out.read_register(register_id::X87_SW, U16)?;
        let clear_c2 = const_u16(out, !(1 << SW_C2_BIT))?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[old, clear_c2])?;
        out.write_register(register_id::X87_SW, cleared)?;
        fall_through(out, insn)?;
        Ok(receipt(0x344, context))
    }
}

// ---------------------------------------------------------------------------
// FCMOVcc: conditional move ST(0) <- ST(i) based on EFLAGS
// ---------------------------------------------------------------------------

fn read_flag_bit(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let rflags = out.read_register(register_id::RFLAGS, U64)?;
    let bit_offset = const_u64(out, u64::from(bit))?;
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[rflags, bit_offset],
    )?;
    let zero = const_u64(out, 0)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U1, &[shifted, zero])
}

fn read_flag_not_bit(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let bit_val = read_flag_bit(out, bit)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[bit_val])
}

fn cond_be(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    let cf = read_flag_bit(out, rflags::CF_BIT)?;
    let zf = read_flag_bit(out, rflags::ZF_BIT)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf])
}

fn cond_nbe(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    let be = cond_be(out)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[be])
}

macro_rules! x87_cmov {
    ($name:ident, $form:expr, $rule:expr, $cond_fn:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let cond = $cond_fn(out)?;
                let dest = out.read_operand(0, U80)?;
                let src = out.read_operand(1, U80)?;
                let selected = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    U80,
                    &[cond, src, dest],
                )?;
                out.write_operand(0, selected)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_cmov!(
    FcmovbSt0Sti,
    forms::FCMOVB_ST0_STI,
    0x345,
    |out: &mut dyn SemanticBuilder| read_flag_bit(out, rflags::CF_BIT)
);
x87_cmov!(
    FcmoveSt0Sti,
    forms::FCMOVE_ST0_STI,
    0x346,
    |out: &mut dyn SemanticBuilder| read_flag_bit(out, rflags::ZF_BIT)
);
x87_cmov!(FcmovbeSt0Sti, forms::FCMOVBE_ST0_STI, 0x347, cond_be);
x87_cmov!(
    FcmovuSt0Sti,
    forms::FCMOVU_ST0_STI,
    0x348,
    |out: &mut dyn SemanticBuilder| read_flag_bit(out, rflags::PF_BIT)
);
x87_cmov!(
    FcmovnbSt0Sti,
    forms::FCMOVNB_ST0_STI,
    0x349,
    |out: &mut dyn SemanticBuilder| read_flag_not_bit(out, rflags::CF_BIT)
);
x87_cmov!(
    FcmovneSt0Sti,
    forms::FCMOVNE_ST0_STI,
    0x34A,
    |out: &mut dyn SemanticBuilder| read_flag_not_bit(out, rflags::ZF_BIT)
);
x87_cmov!(FcmovnbeSt0Sti, forms::FCMOVNBE_ST0_STI, 0x34B, cond_nbe);
x87_cmov!(
    FcmovnuSt0Sti,
    forms::FCMOVNU_ST0_STI,
    0x34C,
    |out: &mut dyn SemanticBuilder| read_flag_not_bit(out, rflags::PF_BIT)
);
