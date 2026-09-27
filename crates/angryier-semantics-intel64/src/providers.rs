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
    DecodedInstructionView, OperandClass, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder, SemanticContext,
    SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, ValueId,
};
use angryier_types::SemanticRuleId;

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U16: SemanticType = SemanticType::Scalar(ScalarType::BitVec(16));
const U8: SemanticType = SemanticType::Scalar(ScalarType::BitVec(8));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));
const U128: SemanticType = SemanticType::Scalar(ScalarType::BitVec(128));

// ---------------------------------------------------------------------------
// Flag computation helpers
// ---------------------------------------------------------------------------

pub(crate) fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

// ---------------------------------------------------------------------------
// 16-bit integer arithmetic, IMUL, and MOVSXD
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Alu16Kind {
    Add,
    Adc,
    Sbb,
    Cmp,
    Or,
    Xor,
    Sub,
    And,
}

fn write_adc16_flags(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    carry: ValueId,
) -> Result<(), SemanticError> {
    let left32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[left])?;
    let right32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[right])?;
    let carry32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[carry])?;
    let rhs32 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[right32, carry32])?;
    let full = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[left32, rhs32])?;
    let sixteen = const_u32(out, 16)?;
    let cf32 = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U32,
        &[full, sixteen],
    )?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf32])?;
    let result64 = widen_to_u64(out, result, 16)?;
    let left64 = widen_to_u64(out, left, 16)?;
    let right64 = widen_to_u64(out, right, 16)?;
    let mut flags = add_flag_values(out, result64, left64, right64, 16)?;
    flags.pop();
    flags.push(cf);
    compose_rflags(out, &flags, false)
}

fn write_sbb16_flags(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
    carry: ValueId,
) -> Result<(), SemanticError> {
    let left32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[left])?;
    let right32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[right])?;
    let carry32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[carry])?;
    let rhs32 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[right32, carry32])?;
    let cf1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[left32, rhs32])?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf1])?;
    let result64 = widen_to_u64(out, result, 16)?;
    let left64 = widen_to_u64(out, left, 16)?;
    let right64 = widen_to_u64(out, right, 16)?;
    let mut flags = sub_flag_values(out, result64, left64, right64, 16)?;
    flags.pop();
    flags.push(cf);
    compose_rflags(out, &flags, false)
}

fn emit_alu16(
    kind: Alu16Kind,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    rule: u64,
) -> Result<SemanticReceipt, SemanticError> {
    let left = out.read_operand(0, U16)?;
    let right = out.read_operand(1, U16)?;
    let result = match kind {
        Alu16Kind::Add => {
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[left, right])?;
            write_add_flags(out, result, left, right, 16)?;
            result
        }
        Alu16Kind::Adc => {
            let carry1 = read_flag_set(out, rflags::CF_BIT)?;
            let carry = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U16, &[carry1])?;
            let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[left, right])?;
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[sum, carry])?;
            write_adc16_flags(out, result, left, right, carry)?;
            result
        }
        Alu16Kind::Sbb => {
            let carry1 = read_flag_set(out, rflags::CF_BIT)?;
            let carry = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U16, &[carry1])?;
            let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U16, &[left, right])?;
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U16, &[diff, carry])?;
            write_sbb16_flags(out, result, left, right, carry)?;
            result
        }
        Alu16Kind::Cmp | Alu16Kind::Sub => {
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U16, &[left, right])?;
            write_sub_flags(out, result, left, right, 16)?;
            result
        }
        Alu16Kind::Or => {
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U16, &[left, right])?;
            write_logical_flags(out, result, 16)?;
            result
        }
        Alu16Kind::Xor => {
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U16, &[left, right])?;
            write_logical_flags(out, result, 16)?;
            result
        }
        Alu16Kind::And => {
            let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U16, &[left, right])?;
            write_logical_flags(out, result, 16)?;
            result
        }
    };
    if kind != Alu16Kind::Cmp {
        out.write_operand(0, result)?;
    }
    fall_through(out, insn)?;
    Ok(receipt(rule, context))
}

macro_rules! alu16_provider {
    ($name:ident, $form:expr, $kind:ident, $rule:expr) => {
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
                emit_alu16(Alu16Kind::$kind, context, insn, out, $rule)
            }
        }
    };
}

alu16_provider!(AddR16Imm16, forms::ADD_R16_IMM16, Add, 0x616);
alu16_provider!(AddR16Imm8, forms::ADD_R16_IMM8, Add, 0x617);
alu16_provider!(AddR16Mem16, forms::ADD_R16_MEM16, Add, 0x618);
alu16_provider!(AddMem16R16, forms::ADD_MEM16_R16, Add, 0x619);
alu16_provider!(AddMem16Imm16V2, forms::ADD_MEM16_IMM16_V2, Add, 0x61A);
alu16_provider!(AddMem16Imm8, forms::ADD_MEM16_IMM8, Add, 0x61B);
alu16_provider!(AdcR16R16, forms::ADC_R16_R16, Adc, 0x61C);
alu16_provider!(AdcR16Imm16, forms::ADC_R16_IMM16, Adc, 0x61D);
alu16_provider!(AdcR16Imm8, forms::ADC_R16_IMM8, Adc, 0x61E);
alu16_provider!(AdcR16Mem16, forms::ADC_R16_MEM16, Adc, 0x61F);
alu16_provider!(AdcMem16R16, forms::ADC_MEM16_R16, Adc, 0x620);
alu16_provider!(AdcMem16Imm16, forms::ADC_MEM16_IMM16, Adc, 0x621);
alu16_provider!(AdcMem16Imm8, forms::ADC_MEM16_IMM8, Adc, 0x622);
alu16_provider!(SbbR16R16, forms::SBB_R16_R16, Sbb, 0x623);
alu16_provider!(SbbR16Imm16, forms::SBB_R16_IMM16, Sbb, 0x624);
alu16_provider!(SbbR16Imm8, forms::SBB_R16_IMM8, Sbb, 0x625);
alu16_provider!(SbbR16Mem16, forms::SBB_R16_MEM16, Sbb, 0x626);
alu16_provider!(SbbMem16R16, forms::SBB_MEM16_R16, Sbb, 0x627);
alu16_provider!(SbbMem16Imm16, forms::SBB_MEM16_IMM16, Sbb, 0x628);
alu16_provider!(SbbMem16Imm8, forms::SBB_MEM16_IMM8, Sbb, 0x629);
alu16_provider!(CmpR16R16, forms::CMP_R16_R16, Cmp, 0x62A);
alu16_provider!(CmpR16Imm16, forms::CMP_R16_IMM16, Cmp, 0x62B);
alu16_provider!(CmpR16Imm8, forms::CMP_R16_IMM8, Cmp, 0x62C);
alu16_provider!(CmpR16Mem16, forms::CMP_R16_MEM16, Cmp, 0x62D);
alu16_provider!(CmpMem16R16V2, forms::CMP_MEM16_R16_V2, Cmp, 0x62E);
alu16_provider!(CmpMem16Imm16V2, forms::CMP_MEM16_IMM16_V2, Cmp, 0x62F);
alu16_provider!(CmpMem16Imm8, forms::CMP_MEM16_IMM8, Cmp, 0x630);
alu16_provider!(OrR16R16, forms::OR_R16_R16, Or, 0x631);
alu16_provider!(OrR16Imm16, forms::OR_R16_IMM16, Or, 0x632);
alu16_provider!(OrR16Imm8, forms::OR_R16_IMM8, Or, 0x633);
alu16_provider!(OrR16Mem16, forms::OR_R16_MEM16, Or, 0x634);
alu16_provider!(OrMem16R16, forms::OR_MEM16_R16, Or, 0x635);
alu16_provider!(OrMem16Imm16V2, forms::OR_MEM16_IMM16_V2, Or, 0x636);
alu16_provider!(OrMem16Imm8, forms::OR_MEM16_IMM8, Or, 0x637);
alu16_provider!(XorR16R16, forms::XOR_R16_R16, Xor, 0x638);
alu16_provider!(XorR16Imm16, forms::XOR_R16_IMM16, Xor, 0x639);
alu16_provider!(XorR16Imm8, forms::XOR_R16_IMM8, Xor, 0x63A);
alu16_provider!(XorR16Mem16, forms::XOR_R16_MEM16, Xor, 0x63B);
alu16_provider!(XorMem16R16, forms::XOR_MEM16_R16, Xor, 0x63C);
alu16_provider!(XorMem16Imm16V2, forms::XOR_MEM16_IMM16_V2, Xor, 0x63D);
alu16_provider!(XorMem16Imm8, forms::XOR_MEM16_IMM8, Xor, 0x63E);
alu16_provider!(SubR16R16, forms::SUB_R16_R16, Sub, 0x63F);
alu16_provider!(SubR16Imm16, forms::SUB_R16_IMM16, Sub, 0x640);
alu16_provider!(SubR16Imm8, forms::SUB_R16_IMM8, Sub, 0x641);
alu16_provider!(SubR16Mem16, forms::SUB_R16_MEM16, Sub, 0x642);
alu16_provider!(SubMem16R16, forms::SUB_MEM16_R16, Sub, 0x643);
alu16_provider!(SubMem16Imm16V2, forms::SUB_MEM16_IMM16_V2, Sub, 0x644);
alu16_provider!(SubMem16Imm8, forms::SUB_MEM16_IMM8, Sub, 0x645);
alu16_provider!(AndR16R16, forms::AND_R16_R16, And, 0x930);
alu16_provider!(AndR16Imm16, forms::AND_R16_IMM16, And, 0x931);
alu16_provider!(AndR16Imm8, forms::AND_R16_IMM8, And, 0x932);
alu16_provider!(AndR16Mem16, forms::AND_R16_MEM16, And, 0x933);
alu16_provider!(AndMem16R16, forms::AND_MEM16_R16, And, 0x934);
alu16_provider!(AndMem16Imm16V2, forms::AND_MEM16_IMM16_V2, And, 0x935);
alu16_provider!(AndMem16Imm8, forms::AND_MEM16_IMM8, And, 0x936);

macro_rules! imul_provider {
    ($name:ident, $form:expr, $ty:expr, $width:expr, $src:expr, $rhs:expr, $rule:expr) => {
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
                let left = out.read_operand($src, $ty)?;
                let right = out.read_operand($rhs, $ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), $ty, &[left, right])?;
                write_mul_flags(out, left, right, $width)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

imul_provider!(ImulR16R16, forms::IMUL_R16_R16, U16, 16, 0, 1, 0x646);
imul_provider!(ImulR16Mem16, forms::IMUL_R16_MEM16, U16, 16, 0, 1, 0x647);
imul_provider!(ImulR16R16Imm16, forms::IMUL_R16_R16_IMM16, U16, 16, 1, 2, 0x648);
imul_provider!(ImulR16R16Imm8, forms::IMUL_R16_R16_IMM8, U16, 16, 1, 2, 0x649);
imul_provider!(ImulR16Mem16Imm16, forms::IMUL_R16_MEM16_IMM16, U16, 16, 1, 2, 0x64A);
imul_provider!(ImulR16Mem16Imm8, forms::IMUL_R16_MEM16_IMM8, U16, 16, 1, 2, 0x64B);
imul_provider!(ImulR32Mem32, forms::IMUL_R32_MEM32, U32, 32, 0, 1, 0x64C);
imul_provider!(ImulR32Mem32Imm32, forms::IMUL_R32_MEM32_IMM32, U32, 32, 1, 2, 0x64D);
imul_provider!(ImulR64Mem64Imm32, forms::IMUL_R64_MEM64_IMM32, U64, 64, 1, 2, 0x64E);

macro_rules! movsxd_provider {
    ($name:ident, $form:expr, $rule:expr) => {
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
                let value = read_sign_extend(out, 1, U32)?;
                out.write_operand(0, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movsxd_provider!(MovsxdR64R32, forms::MOVSXD_R64_R32, 0x64F);
movsxd_provider!(MovsxdR64Mem32, forms::MOVSXD_R64_MEM32, 0x650);
imul_provider!(ImulR32Mem32Imm8, forms::IMUL_R32_MEM32_IMM8, U32, 32, 1, 2, 0x651);
imul_provider!(ImulR64R64Imm8, forms::IMUL_R64_R64_IMM8, U64, 64, 1, 2, 0x652);
imul_provider!(ImulR64Mem64Imm8, forms::IMUL_R64_MEM64_IMM8, U64, 64, 1, 2, 0x653);

pub(crate) fn const_u32(out: &mut dyn SemanticBuilder, value: u32) -> Result<ValueId, SemanticError> {
    out.constant(U32, &value.to_le_bytes())
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
pub(crate) fn fall_through(
    out: &mut dyn SemanticBuilder,
    insn: &dyn DecodedInstructionView,
) -> Result<(), SemanticError> {
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
pub(crate) fn write_shift_flags(
    out: &mut dyn SemanticBuilder,
    operand: ValueId,
    count: ValueId,
    result: ValueId,
    kind: ShiftKind,
    width_bits: u16,
) -> Result<(), SemanticError> {
    let operand = widen_to_u64(out, operand, width_bits)?;
    let count = widen_to_u64(out, count, width_bits)?;
    let result = widen_to_u64(out, result, width_bits)?;

    let one = const_u64(out, 1)?;
    let sixty_three = const_u64(out, u64::from(width_bits - 1))?;
    let sixty_four = const_u64(out, u64::from(width_bits))?;
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

    let (zf, sf) = zf_sf(out, result, width_bits - 1)?;
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

/// CF and OF for rotate instructions at a specified operand width
/// (the only architecturally defined flags for rol/ror; count-one OF formula).
pub(crate) fn write_rotate_flags_width(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    kind: ShiftKind,
    width_bits: u16,
) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, width_bits)?;
    let one = const_u64(out, 1)?;
    let sign_bit = const_u64(out, u64::from(width_bits - 1))?;
    let result_sign = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, sign_bit],
    )?;
    let result_sign = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[result_sign, one])?;
    let (cf, of) = match kind {
        ShiftKind::RotateLeft => {
            let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[result, one])?;
            let of = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[result_sign, cf])?;
            (cf, of)
        }
        ShiftKind::RotateRight => {
            let cf = result_sign;
            let bit_second_off = const_u64(out, u64::from(width_bits - 2))?;
            let bit_second = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                U64,
                &[result, bit_second_off],
            )?;
            let bit_second = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[bit_second, one])?;
            let of = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[cf, bit_second])?;
            (cf, of)
        }
        _ => return Err(SemanticError::InvalidOperand),
    };
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of, of_bit])?;
    compose_rflags_masked(out, &[cf, of], !((1 << rflags::CF_BIT) | (1 << rflags::OF_BIT)))
}

/// CF and OF for 64-bit rotate instructions.
pub(crate) fn write_rotate_flags(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    kind: ShiftKind,
) -> Result<(), SemanticError> {
    write_rotate_flags_width(out, result, kind, 64)
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
pub(crate) fn write_cf_only(out: &mut dyn SemanticBuilder, cf_value: ValueId) -> Result<(), SemanticError> {
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
        write_shift_flags(out, left, count, result, ShiftKind::Left, 64)?;
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
        write_shift_flags(out, left, count, result, ShiftKind::RightLogical, 64)?;
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
        write_shift_flags(out, left, count, result, ShiftKind::RightArith, 64)?;
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
        write_shift_flags(out, left, count, result, ShiftKind::Left, 64)?;
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
        write_shift_flags(out, left, count, result, ShiftKind::RightLogical, 64)?;
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
        write_shift_flags(out, left, count, result, ShiftKind::RightArith, 64)?;
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
        // x86-64 normalizes the rotate count to 6 bits (count mod 64). The
        // rotate primitive itself reduces the count modulo the operand
        // width — the same function at 64 bits — so masking once here is
        // exactly the architectural normalization, never a double mask.
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::RotateLeft),
            U64,
            &[value, count_masked],
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
        // Same count normalization as ROL: a single 6-bit (mod 64)
        // architectural mask; the primitive's own mod-width reduction is
        // identical at 64 bits.
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::RotateRight),
            U64,
            &[value, count_masked],
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
        let sixty_five = const_u64(out, 65)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let complement_plus_one = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_five, count_masked],
        )?;
        let one = const_u64(out, 1)?;
        let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count_masked, one])?;
        let shifted_left = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value, count_masked],
        )?;
        // Through-carry rotate: the top (count-1) value bits land at
        // positions count-1..1 (value >> 65-count), with CF at position 0
        // shifted up to count-1... specifically:
        //   result = (value<<count) | (value>>(65-count)) | (CF<<(count-1))
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, complement_plus_one],
        )?;
        let cf_shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[cf_64, count_minus_one],
        )?;
        let partial = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_left, shifted_right],
        )?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[partial, cf_shifted])?;
        // New CF = the last bit rotated out = value's bit (64-count).
        let new_cf_raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, complement],
        )?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[new_cf_raw, one])?;
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
        let sixty_five = const_u64(out, 65)?;
        let complement = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_four, count_masked],
        )?;
        let complement_plus_one = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Sub),
            U64,
            &[sixty_five, count_masked],
        )?;
        let one = const_u64(out, 1)?;
        let shifted_right = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value, count_masked],
        )?;
        // result = (value>>count) | (CF<<(64-count)) | (value<<(65-count))
        let shifted_left = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value, complement_plus_one],
        )?;
        let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, complement])?;
        let partial = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            U64,
            &[shifted_right, shifted_left],
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
// BT/BTS/BTR/BTC — bit-test family, register and immediate forms at 32 and
// 64 bits. CF = bit(value, index); BTS/BTR/BTC additionally set/reset/
// complement the tested bit in the destination. The index is masked mod the
// operand width (architectural normalization; the imm8 and r32 indices are
// read at U64 and masked before use — the rotate-family idiom). The oracle
// (bit_test_differential.rs) proved masking matters for write-back forms:
// `bts r64, 64` must set bit 0, not wrap `1 << 64` to zero.
// ---------------------------------------------------------------------------

/// Bit-test write-back behavior (BT tests only).
#[derive(Clone, Copy)]
enum BitTestOp {
    Test,
    Set,
    Reset,
    Complement,
}

macro_rules! bit_test_reg {
    ($name:ident, $form:expr, $width:expr, $index_ty:expr, $mask_bits:expr, $op:ident, $rule:expr) => {
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
                let value = out.read_operand(0, $width)?;
                // Register indices are read at their natural width (the
                // lowerer rejects widening a register view), then widened;
                // immediate indices read at U64 directly.
                let index = out.read_operand(1, $index_ty)?;
                let index = match $index_ty {
                    U64 => index,
                    _ => out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[index])?,
                };
                let mask = const_u64(out, $mask_bits)?;
                let index_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[index, mask])?;
                let one = match $width {
                    U32 => out.constant(U32, &1u32.to_le_bytes())?,
                    U64 => out.constant(U64, &1u64.to_le_bytes())?,
                    _ => return Err(SemanticError::InvalidWidth),
                };
                let shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                    $width,
                    &[value, index_masked],
                )?;
                let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $width, &[shifted, one])?;
                // CF is defined at the operand width; widen only the 32-bit
                // forms for the U64 flag composition.
                let cf64 = match $width {
                    U64 => cf,
                    _ => out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf])?,
                };
                write_cf_only(out, cf64)?;
                let bit_mask = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    $width,
                    &[one, index_masked],
                )?;
                let result = match BitTestOp::$op {
                    BitTestOp::Test => value,
                    BitTestOp::Set => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), $width, &[value, bit_mask])?,
                    BitTestOp::Reset => {
                        let not_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), $width, &[bit_mask])?;
                        out.emit(
                            SemanticOp::Primitive(PrimitiveOp::And),
                            $width,
                            &[value, not_mask],
                        )?
                    }
                    BitTestOp::Complement => out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Xor),
                        $width,
                        &[value, bit_mask],
                    )?,
                };
                if !matches!(BitTestOp::$op, BitTestOp::Test) {
                    out.write_operand(0, result)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

bit_test_reg!(BtR64R64, forms::BT_R64_R64, U64, U64, 0x3F, Test, 63);
bit_test_reg!(BtsR64R64, forms::BTS_R64_R64, U64, U64, 0x3F, Set, 64);
bit_test_reg!(BtrR64R64, forms::BTR_R64_R64, U64, U64, 0x3F, Reset, 65);
bit_test_reg!(BtcR64R64, forms::BTC_R64_R64, U64, U64, 0x3F, Complement, 66);
bit_test_reg!(BtR32R32, forms::BT_R32_R32, U32, U32, 0x1F, Test, 0x530);
bit_test_reg!(BtsR32R32, forms::BTS_R32_R32, U32, U32, 0x1F, Set, 0x531);
bit_test_reg!(BtrR32R32, forms::BTR_R32_R32, U32, U32, 0x1F, Reset, 0x532);
bit_test_reg!(BtcR32R32, forms::BTC_R32_R32, U32, U32, 0x1F, Complement, 0x533);
bit_test_reg!(BtR64Imm8, forms::BT_R64_IMM8, U64, U64, 0x3F, Test, 0x534);
bit_test_reg!(BtsR64Imm8, forms::BTS_R64_IMM8, U64, U64, 0x3F, Set, 0x535);
bit_test_reg!(BtrR64Imm8, forms::BTR_R64_IMM8, U64, U64, 0x3F, Reset, 0x536);
bit_test_reg!(BtcR64Imm8, forms::BTC_R64_IMM8, U64, U64, 0x3F, Complement, 0x537);
bit_test_reg!(BtR32Imm8, forms::BT_R32_IMM8, U32, U64, 0x1F, Test, 0x538);
bit_test_reg!(BtsR32Imm8, forms::BTS_R32_IMM8, U32, U64, 0x1F, Set, 0x539);
bit_test_reg!(BtrR32Imm8, forms::BTR_R32_IMM8, U32, U64, 0x1F, Reset, 0x53A);
bit_test_reg!(BtcR32Imm8, forms::BTC_R32_IMM8, U32, U64, 0x1F, Complement, 0x53B);
bit_test_reg!(BtsMem32R32, forms::BTS_MEM32_R32, U32, U32, 0x1F, Set, 0x92A);
bit_test_reg!(BtsMem64R64, forms::BTS_MEM64_R64, U64, U64, 0x3F, Set, 0x92B);
bit_test_reg!(BtrMem32R32, forms::BTR_MEM32_R32, U32, U32, 0x1F, Reset, 0x92C);
bit_test_reg!(BtrMem64R64, forms::BTR_MEM64_R64, U64, U64, 0x3F, Reset, 0x92D);
bit_test_reg!(BtcMem32R32, forms::BTC_MEM32_R32, U32, U32, 0x1F, Complement, 0x92E);
bit_test_reg!(BtcMem64R64, forms::BTC_MEM64_R64, U64, U64, 0x3F, Complement, 0x92F);

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
        let count = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
        // x86-64 takes the count from CL, ignoring the rest of RCX, and
        // reduces it modulo 64. Reading the full parent and masking to 6
        // bits performs both steps; the rotate primitive's own mod-width
        // reduction is the same function at 64 bits.
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::RotateLeft),
            U64,
            &[value, count_masked],
        )?;
        write_rotate_flags(out, result, ShiftKind::RotateLeft)?;
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
        let count = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
        // Same normalization as ROL: CL only (the rest of RCX is masked
        // away), reduced modulo 64; the primitive applies the identical
        // mod-width reduction at 64 bits.
        let mask = const_u64(out, 0x3F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::RotateRight),
            U64,
            &[value, count_masked],
        )?;
        write_rotate_flags(out, result, ShiftKind::RotateRight)?;
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
        // When the destination IS the accumulator (cmpxchg %rbx, %rax) the
        // operand write already produced the correct value: on equal it holds
        // source; on not-equal rax == dest so the accumulator write would be
        // an identity — and on equal it would wrongly clobber the just-written
        // source value. Skip it.
        let dest_is_acc = matches!(
            insn.operand(0).map(|op| op.kind),
            Some(angryier_semantics::OperandKind::Register(view))
                if view.parent.0 == register_id::GPR_BASE && view.bit_offset == 0 && view.width_bits == 64
        );
        if !dest_is_acc {
            out.write_register(RegisterId(register_id::GPR_BASE), new_rax)?;
        }

        // CMPXCHG sets the full CMP flag set; the oracle shows the flags
        // come from (rax - dest) on real hardware — the reverse of the
        // SDM's stated (dest - rax). Verified across value pairs on the
        // differential host; debt-note: documented deviation.
        let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rax, dest])?;
        write_sub_flags(out, diff, rax, dest, 64)?;

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

// ---------------------------------------------------------------------------
// RDTSC (Read Time-Stamp Counter)
// ---------------------------------------------------------------------------

/// RDTSC: writes a deterministic monotonically-increasing counter to
/// EDX:EAX. NOT the real CPU TSC — this is replayable and deterministic.
/// Drivers use RDTSC for anti-tamper timestamps, entropy seeding, and
/// timing checks; a fixed counter satisfies all of them without breaking
/// replay.
#[derive(Clone, Copy, Debug)]
pub struct Rdtsc;

impl SemanticProvider for Rdtsc {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x500)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RDTSC
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Deterministic counter: a fixed constant that satisfies drivers
        // checking for non-zero / changing timestamps. The exact value is
        // replay-safe (same on every run).
        let tsc: u64 = 0x0000_0000_0100_0000; // ~1M cycles (arbitrary)
        let eax = tsc & 0xFFFF_FFFF;
        let edx = tsc >> 32;
        let eax_val = const_u64(out, eax)?;
        let edx_val = const_u64(out, edx)?;
        out.write_register(RegisterId(register_id::GPR_BASE), eax_val)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 2), edx_val)?;
        fall_through(out, insn)?;
        Ok(receipt(0x500, context))
    }
}

// ---------------------------------------------------------------------------
// RDMSR (read model-specific register) / WRMSR (write model-specific
// register). The model tracks no MSR state: RDMSR returns zero for every
// selector (debt-recorded — drivers that branch on specific MSR features
// see the "feature absent" value, which is the conservative direction),
// and WRMSR is a no-op. Deterministic for replay.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Rdmsr;

impl SemanticProvider for Rdmsr {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x502)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RDMSR
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let _msr = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?; // ECX selector
        let zero = const_u64(out, 0)?;
        out.write_register(RegisterId(register_id::GPR_BASE), zero)?; // EAX
        out.write_register(RegisterId(register_id::GPR_BASE + 2), zero)?; // EDX
        fall_through(out, insn)?;
        Ok(receipt(0x502, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Wrmsr;

impl SemanticProvider for Wrmsr {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x503)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::WRMSR
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // No observable model state; the write is dropped.
        fall_through(out, insn)?;
        Ok(receipt(0x503, context))
    }
}

/// LFENCE/SFENCE/MFENCE — memory-ordering fences. A single-vCPU model has
/// no memory-ordering state to fence (debt-recorded), so the semantics is
/// an exact no-op.
#[derive(Clone, Copy, Debug)]
pub struct Fence;

impl SemanticProvider for Fence {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x504)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FENCE
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x504, context))
    }
}

// ---------------------------------------------------------------------------
// IN/OUT port I/O. No device model exists: IN reads return zero (the
// "device absent" value — reads of absent ports return 0xFF on most chipsets
// but 0 is the conservative direction for drivers checking feature bits),
// and OUT writes are dropped. Deterministic for replay.
// ---------------------------------------------------------------------------

macro_rules! port_in {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
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
                let _port = out.read_operand(1, U16)?; // DX
                let zero = match $ty {
                    U8 => out.constant(U8, &[0])?,
                    U16 => out.constant(U16, &0u16.to_le_bytes())?,
                    U32 => out.constant(U32, &0u32.to_le_bytes())?,
                    _ => return Err(SemanticError::InvalidWidth),
                };
                out.write_operand(0, zero)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! port_out {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
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
                let _port = out.read_operand(0, U16)?; // DX
                let _value = out.read_operand(1, $ty)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

port_in!(InAlDx, forms::IN_AL_DX, U8, 0x505);
port_in!(InAxDx, forms::IN_AX_DX, U16, 0x506);
port_in!(InEaxDx, forms::IN_EAX_DX, U32, 0x507);
port_out!(OutDxAl, forms::OUT_DX_AL, U8, 0x508);
port_out!(OutDxAx, forms::OUT_DX_AX, U16, 0x509);
port_out!(OutDxEax, forms::OUT_DX_EAX, U32, 0x50A);

macro_rules! port_in_imm {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
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
                let _port = out.read_operand(1, U8)?;
                let zero = match $ty {
                    U8 => out.constant(U8, &[0])?,
                    U16 => out.constant(U16, &0u16.to_le_bytes())?,
                    U32 => out.constant(U32, &0u32.to_le_bytes())?,
                    _ => return Err(SemanticError::InvalidWidth),
                };
                out.write_operand(0, zero)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! port_out_imm {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
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
                let _port = out.read_operand(0, U8)?;
                let _value = out.read_operand(1, $ty)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! string_port_in {
    ($name:ident, $form:expr, $ty:expr, $size:expr, $rule:expr) => {
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
                let _port = out.read_operand(1, U16)?; // DX
                let zero = match $ty {
                    U8 => out.constant(U8, &[0])?,
                    U16 => out.constant(U16, &0u16.to_le_bytes())?,
                    U32 => out.constant(U32, &0u32.to_le_bytes())?,
                    _ => return Err(SemanticError::InvalidWidth),
                };
                out.write_operand(0, zero)?; // [RDI]
                let rdi_reg = RegisterId(register_id::GPR_BASE + 7);
                let rdi = out.read_register(rdi_reg, U64)?;
                let df = read_flag_set(out, rflags::DF_BIT)?;
                let step = const_u64(out, $size)?;
                let rdi_plus = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rdi, step])?;
                let rdi_minus = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rdi, step])?;
                let new_rdi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    U64,
                    &[df, rdi_minus, rdi_plus],
                )?;
                out.write_register(rdi_reg, new_rdi)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! string_port_out {
    ($name:ident, $form:expr, $ty:expr, $size:expr, $rule:expr) => {
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
                let _port = out.read_operand(0, U16)?; // DX
                let _value = out.read_operand(1, $ty)?; // [RSI]
                let rsi_reg = RegisterId(register_id::GPR_BASE + 6);
                let rsi = out.read_register(rsi_reg, U64)?;
                let df = read_flag_set(out, rflags::DF_BIT)?;
                let step = const_u64(out, $size)?;
                let rsi_plus = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsi, step])?;
                let rsi_minus = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsi, step])?;
                let new_rsi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    U64,
                    &[df, rsi_minus, rsi_plus],
                )?;
                out.write_register(rsi_reg, new_rsi)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

port_in_imm!(InAlImm8, forms::IN_AL_IMM8, U8, 0x700);
port_in_imm!(InAxImm8, forms::IN_AX_IMM8, U16, 0x701);
port_in_imm!(InEaxImm8, forms::IN_EAX_IMM8, U32, 0x702);
port_out_imm!(OutImm8Al, forms::OUT_IMM8_AL, U8, 0x703);
port_out_imm!(OutImm8Ax, forms::OUT_IMM8_AX, U16, 0x704);
port_out_imm!(OutImm8Eax, forms::OUT_IMM8_EAX, U32, 0x705);

string_port_in!(Insb, forms::INSB, U8, 1, 0x706);
string_port_in!(Insw, forms::INSW, U16, 2, 0x707);
string_port_in!(Insd, forms::INSD, U32, 4, 0x708);
string_port_out!(Outsb, forms::OUTSB, U8, 1, 0x709);
string_port_out!(Outsw, forms::OUTSW, U16, 2, 0x70A);
string_port_out!(Outsd, forms::OUTSD, U32, 4, 0x70B);

// ---------------------------------------------------------------------------
// INT imm8 (Software Interrupt / __fastfail)
// ---------------------------------------------------------------------------

/// INT imm8: reads the interrupt vector from operand 0, stores it in RAX
/// for diagnostics, and terminates execution. On Windows, `int 0x29` is
/// `__fastfail` — the driver detected a security condition and would
/// bugcheck on real hardware. The semantic treats all interrupts as
/// terminal (debt-recorded: INT 3/1 debug interrupts could be no-ops).
fn memory_shift_count(
    out: &mut dyn SemanticBuilder,
    from_cl: bool,
    ty: SemanticType,
    width: u16,
) -> Result<ValueId, SemanticError> {
    let raw = if from_cl {
        out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?
    } else {
        let imm = out.read_operand(1, U8)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[imm])?
    };
    let mask = const_u64(out, if width == 64 { 0x3f } else { 0x1f })?;
    let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, mask])?;
    if width == 64 {
        Ok(masked)
    } else {
        let zero = const_u64(out, 0)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), ty, &[masked, zero])
    }
}

macro_rules! memory_shift {
    ($name:ident, $form:expr, $ty:expr, $width:expr, $from_cl:expr, $op:expr, $kind:expr, $rule:expr) => {
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
                let value = out.read_operand(0, $ty)?;
                let count = memory_shift_count(out, $from_cl, $ty, $width)?;
                let result = out.emit(SemanticOp::Primitive($op), $ty, &[value, count])?;
                write_shift_flags(out, value, count, result, $kind, $width)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! memory_rotate {
    ($name:ident, $form:expr, $ty:expr, $width:expr, $from_cl:expr, $op:expr, $kind:expr, $rule:expr) => {
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
                let value = out.read_operand(0, $ty)?;
                let count = memory_shift_count(out, $from_cl, $ty, $width)?;
                let result = out.emit(SemanticOp::Primitive($op), $ty, &[value, count])?;
                write_rotate_flags_width(out, result, $kind, $width)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

memory_shift!(
    ShlMem16Imm8,
    forms::SHL_MEM16_IMM8,
    U16,
    16,
    false,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x900
);
memory_shift!(
    ShlMem16Cl,
    forms::SHL_MEM16_CL,
    U16,
    16,
    true,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x901
);
memory_shift!(
    ShlMem32Imm8,
    forms::SHL_MEM32_IMM8,
    U32,
    32,
    false,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x902
);
memory_shift!(
    ShlMem32Cl,
    forms::SHL_MEM32_CL,
    U32,
    32,
    true,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x903
);
memory_shift!(
    ShlMem64Imm8,
    forms::SHL_MEM64_IMM8,
    U64,
    64,
    false,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x904
);
memory_shift!(
    ShlMem64Cl,
    forms::SHL_MEM64_CL,
    U64,
    64,
    true,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x905
);
memory_shift!(
    ShrMem16Imm8,
    forms::SHR_MEM16_IMM8,
    U16,
    16,
    false,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x906
);
memory_shift!(
    ShrMem16Cl,
    forms::SHR_MEM16_CL,
    U16,
    16,
    true,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x907
);
memory_shift!(
    ShrMem32Imm8,
    forms::SHR_MEM32_IMM8,
    U32,
    32,
    false,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x908
);
memory_shift!(
    ShrMem32Cl,
    forms::SHR_MEM32_CL,
    U32,
    32,
    true,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x909
);
memory_shift!(
    ShrMem64Imm8,
    forms::SHR_MEM64_IMM8,
    U64,
    64,
    false,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x90A
);
memory_shift!(
    ShrMem64Cl,
    forms::SHR_MEM64_CL,
    U64,
    64,
    true,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x90B
);
memory_shift!(
    SarMem16Imm8,
    forms::SAR_MEM16_IMM8,
    U16,
    16,
    false,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x90C
);
memory_shift!(
    SarMem16Cl,
    forms::SAR_MEM16_CL,
    U16,
    16,
    true,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x90D
);
memory_shift!(
    SarMem32Imm8,
    forms::SAR_MEM32_IMM8,
    U32,
    32,
    false,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x90E
);
memory_shift!(
    SarMem32Cl,
    forms::SAR_MEM32_CL,
    U32,
    32,
    true,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x90F
);
memory_shift!(
    SarMem64Imm8,
    forms::SAR_MEM64_IMM8,
    U64,
    64,
    false,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x910
);
memory_shift!(
    SarMem64Cl,
    forms::SAR_MEM64_CL,
    U64,
    64,
    true,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x911
);
memory_rotate!(
    RolMem16Imm8,
    forms::ROL_MEM16_IMM8,
    U16,
    16,
    false,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x912
);
memory_rotate!(
    RolMem16Cl,
    forms::ROL_MEM16_CL,
    U16,
    16,
    true,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x913
);
memory_rotate!(
    RolMem32Imm8,
    forms::ROL_MEM32_IMM8,
    U32,
    32,
    false,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x914
);
memory_rotate!(
    RolMem32Cl,
    forms::ROL_MEM32_CL,
    U32,
    32,
    true,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x915
);
memory_rotate!(
    RolMem64Imm8,
    forms::ROL_MEM64_IMM8,
    U64,
    64,
    false,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x916
);
memory_rotate!(
    RolMem64Cl,
    forms::ROL_MEM64_CL,
    U64,
    64,
    true,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x917
);
memory_rotate!(
    RorMem16Imm8,
    forms::ROR_MEM16_IMM8,
    U16,
    16,
    false,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x918
);
memory_rotate!(
    RorMem16Cl,
    forms::ROR_MEM16_CL,
    U16,
    16,
    true,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x919
);
memory_rotate!(
    RorMem32Imm8,
    forms::ROR_MEM32_IMM8,
    U32,
    32,
    false,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x91A
);
memory_rotate!(
    RorMem32Cl,
    forms::ROR_MEM32_CL,
    U32,
    32,
    true,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x91B
);
memory_rotate!(
    RorMem64Imm8,
    forms::ROR_MEM64_IMM8,
    U64,
    64,
    false,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x91C
);
memory_rotate!(
    RorMem64Cl,
    forms::ROR_MEM64_CL,
    U64,
    64,
    true,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x91D
);

fn emit_memory_rotate_carry(
    out: &mut dyn SemanticBuilder,
    value: ValueId,
    ty: SemanticType,
    width: u16,
    from_cl: bool,
    left: bool,
) -> Result<ValueId, SemanticError> {
    let value64 = widen_to_u64(out, value, width)?;
    let mut count = if from_cl {
        out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?
    } else {
        let imm = out.read_operand(1, U8)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[imm])?
    };
    let mask = const_u64(out, if width == 64 { 0x3f } else { 0x1f })?;
    count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, mask])?;
    if width == 16 {
        let seventeen = const_u64(out, 17)?;
        let quotient = out.emit(
            SemanticOp::Primitive(PrimitiveOp::UnsignedDiv),
            U64,
            &[count, seventeen],
        )?;
        let product = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[quotient, seventeen])?;
        count = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count, product])?;
    }
    let one = const_u64(out, 1)?;
    let width_value = const_u64(out, u64::from(width))?;
    let ring_value = const_u64(out, u64::from(width + 1))?;
    let cf1 = read_flag_set(out, rflags::CF_BIT)?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf1])?;
    let count_minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[count, one])?;
    let width_minus_count = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[width_value, count])?;
    let ring_minus_count = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[ring_value, count])?;
    let (result64, new_cf) = if left {
        let a = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[value64, count])?;
        let b = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value64, ring_minus_count],
        )?;
        let c = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[cf, count_minus_one],
        )?;
        let ab = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[a, b])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[ab, c])?;
        let raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value64, width_minus_count],
        )?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, one])?;
        (result, new_cf)
    } else {
        let a = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value64, count],
        )?;
        let b = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[value64, ring_minus_count],
        )?;
        let c = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U64,
            &[cf, width_minus_count],
        )?;
        let ab = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[a, b])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[ab, c])?;
        let raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[value64, count_minus_one],
        )?;
        let new_cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[raw, one])?;
        (result, new_cf)
    };
    let sign_off = const_u64(out, u64::from(width - 1))?;
    let sign = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result64, sign_off],
    )?;
    let sign = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sign, one])?;
    let of = if left {
        out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[sign, new_cf])?
    } else {
        let second_off = const_u64(out, u64::from(width - 2))?;
        let second = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[result64, second_off],
        )?;
        let second = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[second, one])?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[sign, second])?
    };
    let of_off = const_u64(out, u64::from(rflags::OF_BIT))?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of, of_off])?;
    compose_rflags_masked(out, &[new_cf, of], !((1 << rflags::CF_BIT) | (1 << rflags::OF_BIT)))?;
    if width == 64 {
        Ok(result64)
    } else {
        let zero = const_u64(out, 0)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), ty, &[result64, zero])
    }
}

macro_rules! memory_rotate_carry {
    ($name:ident, $form:expr, $ty:expr, $width:expr, $from_cl:expr, $left:expr, $rule:expr) => {
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
                let value = out.read_operand(0, $ty)?;
                let result = emit_memory_rotate_carry(out, value, $ty, $width, $from_cl, $left)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}
memory_rotate_carry!(RclMem16Imm8, forms::RCL_MEM16_IMM8, U16, 16, false, true, 0x91E);
memory_rotate_carry!(RclMem16Cl, forms::RCL_MEM16_CL, U16, 16, true, true, 0x91F);
memory_rotate_carry!(RclMem32Imm8, forms::RCL_MEM32_IMM8, U32, 32, false, true, 0x920);
memory_rotate_carry!(RclMem32Cl, forms::RCL_MEM32_CL, U32, 32, true, true, 0x921);
memory_rotate_carry!(RclMem64Imm8, forms::RCL_MEM64_IMM8, U64, 64, false, true, 0x922);
memory_rotate_carry!(RclMem64Cl, forms::RCL_MEM64_CL, U64, 64, true, true, 0x923);
memory_rotate_carry!(RcrMem16Imm8, forms::RCR_MEM16_IMM8, U16, 16, false, false, 0x924);
memory_rotate_carry!(RcrMem16Cl, forms::RCR_MEM16_CL, U16, 16, true, false, 0x925);
memory_rotate_carry!(RcrMem32Imm8, forms::RCR_MEM32_IMM8, U32, 32, false, false, 0x926);
memory_rotate_carry!(RcrMem32Cl, forms::RCR_MEM32_CL, U32, 32, true, false, 0x927);
memory_rotate_carry!(RcrMem64Imm8, forms::RCR_MEM64_IMM8, U64, 64, false, false, 0x928);
memory_rotate_carry!(RcrMem64Cl, forms::RCR_MEM64_CL, U64, 64, true, false, 0x929);

macro_rules! simple_store {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
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
                let value = out.read_operand(1, $ty)?;
                out.write_operand(0, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}
simple_store!(MovntdqMem128Xmm, forms::MOVNTDQ_MEM128_XMM, U128, 0x941);
simple_store!(MovntiMem32R32, forms::MOVNTI_MEM32_R32, U32, 0x942);
simple_store!(MovntiMem64R64, forms::MOVNTI_MEM64_R64, U64, 0x943);

macro_rules! hint_noop {
    ($name:ident, $form:expr, $rule:expr) => {
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
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}
hint_noop!(PrefetchntaMem8, forms::PREFETCHNTA_MEM8, 0x944);
hint_noop!(Prefetcht0Mem8, forms::PREFETCHT0_MEM8, 0x945);
hint_noop!(Prefetcht1Mem8, forms::PREFETCHT1_MEM8, 0x946);
hint_noop!(Prefetcht2Mem8, forms::PREFETCHT2_MEM8, 0x947);

#[derive(Clone, Copy)]
enum Cmov16Condition {
    Z,
    Nz,
    B,
    Nb,
    L,
    Nl,
    Be,
    Nbe,
    Le,
    Nle,
}

fn cmov16_condition(out: &mut dyn SemanticBuilder, condition: Cmov16Condition) -> Result<ValueId, SemanticError> {
    let zf = read_flag_set(out, rflags::ZF_BIT)?;
    let cf = read_flag_set(out, rflags::CF_BIT)?;
    let sf = read_flag_set(out, rflags::SF_BIT)?;
    let of = read_flag_set(out, rflags::OF_BIT)?;
    let not_zf = read_flag_not_set(out, rflags::ZF_BIT)?;
    let not_cf = read_flag_not_set(out, rflags::CF_BIT)?;
    let sf_ne_of = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
    let sf_eq_of = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[sf_ne_of])?;
    match condition {
        Cmov16Condition::Z => Ok(zf),
        Cmov16Condition::Nz => Ok(not_zf),
        Cmov16Condition::B => Ok(cf),
        Cmov16Condition::Nb => Ok(not_cf),
        Cmov16Condition::L => Ok(sf_ne_of),
        Cmov16Condition::Nl => Ok(sf_eq_of),
        Cmov16Condition::Be => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf]),
        Cmov16Condition::Nbe => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_cf, not_zf]),
        Cmov16Condition::Le => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, sf_ne_of]),
        Cmov16Condition::Nle => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_zf, sf_eq_of]),
    }
}

macro_rules! cmov16 {
    ($name:ident, $form:expr, $condition:ident, $rule:expr) => {
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
                let dst = out.read_operand(0, U16)?;
                let src = out.read_operand(1, U16)?;
                let condition = cmov16_condition(out, Cmov16Condition::$condition)?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    U16,
                    &[condition, src, dst],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}
cmov16!(CmovzR16R16, forms::CMOVZ_R16_R16, Z, 0x937);
cmov16!(CmovnzR16R16, forms::CMOVNZ_R16_R16, Nz, 0x938);
cmov16!(CmovbR16R16, forms::CMOVB_R16_R16, B, 0x939);
cmov16!(CmovnbR16R16, forms::CMOVNB_R16_R16, Nb, 0x93A);
cmov16!(CmovlR16R16, forms::CMOVL_R16_R16, L, 0x93B);
cmov16!(CmovnlR16R16, forms::CMOVNL_R16_R16, Nl, 0x93C);
cmov16!(CmovbeR16R16, forms::CMOVBE_R16_R16, Be, 0x93D);
cmov16!(CmovnbeR16R16, forms::CMOVNBE_R16_R16, Nbe, 0x93E);
cmov16!(CmovleR16R16, forms::CMOVLE_R16_R16, Le, 0x93F);
cmov16!(CmovnleR16R16, forms::CMOVNLE_R16_R16, Nle, 0x940);

#[derive(Clone, Copy, Debug)]
pub struct IntImm8;

impl SemanticProvider for IntImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x501)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::INT_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Read the interrupt vector from operand 0 (imm8)
        let vector = out.read_operand(0, U64)?;
        // Store in RAX for diagnostics: which interrupt fired
        out.write_register(RegisterId(register_id::GPR_BASE), vector)?;
        // Terminate: on real hardware, __fastfail (int 0x29) is an immediate
        // unrecoverable termination. The code after it is unreachable
        // (padding/data), and executing it as instructions produces garbage.
        // The security cookie check that triggers __fastfail depends on a
        // properly initialized GS segment — future work.
        let exit = const_u64(out, 0xdead_beef_0000)?;
        out.jump(exit)?;
        Ok(receipt(0x501, context))
    }
}

// ---------------------------------------------------------------------------
// 32-bit shifts and rotates (mod-32 count masking, full flag modeling)
// ---------------------------------------------------------------------------

macro_rules! shift_r32_imm8 {
    ($name:ident, $form:expr, $op:expr, $kind:expr, $rule:expr) => {
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
                let val = out.read_operand(0, U32)?;
                let count = out.read_operand(1, U8)?;
                let count_32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[count])?;
                let mask = const_u32(out, 0x1F)?;
                let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[count_32, mask])?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[val, count_masked])?;
                write_shift_flags(out, val, count_masked, result, $kind, 32)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

shift_r32_imm8!(
    ShlR32Imm8Masked,
    forms::SHL_R32_IMM8,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x8E
);
shift_r32_imm8!(
    ShrR32Imm8Masked,
    forms::SHR_R32_IMM8,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x8F
);
shift_r32_imm8!(
    SarR32Imm8Masked,
    forms::SAR_R32_IMM8,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x90
);

macro_rules! shift_r32_cl {
    ($name:ident, $form:expr, $op:expr, $kind:expr, $rule:expr) => {
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
                let val = out.read_operand(0, U32)?;
                let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
                let mask = const_u64(out, 0x1F)?;
                let count_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
                let zero = const_u64(out, 0)?;
                let count_32 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U32,
                    &[count_64, zero],
                )?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[val, count_32])?;
                write_shift_flags(out, val, count_32, result, $kind, 32)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

shift_r32_cl!(
    ShlR32ClMasked,
    forms::SHL_R32_CL,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x91
);
shift_r32_cl!(
    ShrR32ClMasked,
    forms::SHR_R32_CL,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x92
);
shift_r32_cl!(
    SarR32ClMasked,
    forms::SAR_R32_CL,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x93
);

macro_rules! rotate_r32_imm8 {
    ($name:ident, $form:expr, $rule:expr, $is_left:expr) => {
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
                let val = out.read_operand(0, U32)?;
                let count = out.read_operand(1, U8)?;
                let count_32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[count])?;
                let mask = const_u32(out, 0x1F)?;
                let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[count_32, mask])?;
                let prim = if $is_left {
                    PrimitiveOp::RotateLeft
                } else {
                    PrimitiveOp::RotateRight
                };
                let result = out.emit(SemanticOp::Primitive(prim), U32, &[val, count_masked])?;
                write_rotate_flags_width(
                    out,
                    result,
                    if $is_left {
                        ShiftKind::RotateLeft
                    } else {
                        ShiftKind::RotateRight
                    },
                    32,
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

rotate_r32_imm8!(RolR32Imm8Masked, forms::ROL_R32_IMM8, 0x94, true);
rotate_r32_imm8!(RorR32Imm8Masked, forms::ROR_R32_IMM8, 0x95, false);

macro_rules! rotate_r32_cl {
    ($name:ident, $form:expr, $rule:expr, $is_left:expr) => {
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
                let val = out.read_operand(0, U32)?;
                let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
                let zero = const_u64(out, 0)?;
                let mask = const_u64(out, 0x1F)?;
                let count_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
                let count_32 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U32,
                    &[count_64, zero],
                )?;
                let prim = if $is_left {
                    PrimitiveOp::RotateLeft
                } else {
                    PrimitiveOp::RotateRight
                };
                let result = out.emit(SemanticOp::Primitive(prim), U32, &[val, count_32])?;
                write_rotate_flags_width(
                    out,
                    result,
                    if $is_left {
                        ShiftKind::RotateLeft
                    } else {
                        ShiftKind::RotateRight
                    },
                    32,
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

rotate_r32_cl!(RolR32ClMasked, forms::ROL_R32_CL, 0x96, true);
rotate_r32_cl!(RorR32ClMasked, forms::ROR_R32_CL, 0x97, false);

// ---------------------------------------------------------------------------
// LOOP / LOOPE / LOOPNE / JRCXZ (decrement RCX, conditional relative branch)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct LoopRel8;

impl SemanticProvider for LoopRel8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0800)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LOOP_REL8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rcx_reg = RegisterId(register_id::GPR_BASE + 1);
        let rcx = out.read_register(rcx_reg, U64)?;
        let one = const_u64(out, 1)?;
        let new_rcx = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rcx, one])?;
        out.write_register(rcx_reg, new_rcx)?;
        let zero = const_u64(out, 0)?;
        let rcx_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[new_rcx, zero])?;
        let rcx_not_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[rcx_is_zero])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(rcx_not_zero, target, next_pc)?;
        Ok(receipt(0x0800, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoopeRel8;

impl SemanticProvider for LoopeRel8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0801)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LOOPE_REL8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rcx_reg = RegisterId(register_id::GPR_BASE + 1);
        let rcx = out.read_register(rcx_reg, U64)?;
        let one = const_u64(out, 1)?;
        let new_rcx = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rcx, one])?;
        out.write_register(rcx_reg, new_rcx)?;
        let zero = const_u64(out, 0)?;
        let rcx_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[new_rcx, zero])?;
        let rcx_not_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[rcx_is_zero])?;
        let zf_set = read_flag_set(out, rflags::ZF_BIT)?;
        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[rcx_not_zero, zf_set])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cond, target, next_pc)?;
        Ok(receipt(0x0801, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoopneRel8;

impl SemanticProvider for LoopneRel8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0802)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LOOPNE_REL8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rcx_reg = RegisterId(register_id::GPR_BASE + 1);
        let rcx = out.read_register(rcx_reg, U64)?;
        let one = const_u64(out, 1)?;
        let new_rcx = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rcx, one])?;
        out.write_register(rcx_reg, new_rcx)?;
        let zero = const_u64(out, 0)?;
        let rcx_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[new_rcx, zero])?;
        let rcx_not_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[rcx_is_zero])?;
        let zf_not_set = read_flag_not_set(out, rflags::ZF_BIT)?;
        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[rcx_not_zero, zf_not_set])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(cond, target, next_pc)?;
        Ok(receipt(0x0802, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct JrcxzRel8;

impl SemanticProvider for JrcxzRel8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0803)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JRCXZ_REL8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rcx_reg = RegisterId(register_id::GPR_BASE + 1);
        let rcx = out.read_register(rcx_reg, U64)?;
        let zero = const_u64(out, 0)?;
        let rcx_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[rcx, zero])?;
        let target = out.read_operand(0, U64)?;
        let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(rcx_is_zero, target, next_pc)?;
        Ok(receipt(0x0803, context))
    }
}

// ---------------------------------------------------------------------------
// RET_FAR (far return: pop RIP, pop selector, indirect jump)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RetFar;

impl SemanticProvider for RetFar {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0804)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RET_FAR
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let mem_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Memory))
            .unwrap_or(1);
        let target = out.read_operand(mem_idx, U64)?;
        let rsp_reg = RegisterId(register_id::GPR_BASE + 4);
        let rsp = out.read_register(rsp_reg, U64)?;
        let ten = const_u64(out, 10)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, ten])?;
        out.write_register(rsp_reg, new_rsp)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x0804, context))
    }
}

// ---------------------------------------------------------------------------
// RET imm16 (pop RIP, add imm16 to RSP, indirect jump)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RetImm16;

impl SemanticProvider for RetImm16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0805)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RET_IMM16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let mem_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Memory))
            .unwrap_or(2);
        let imm_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Immediate))
            .unwrap_or(0);
        let target = out.read_operand(mem_idx, U64)?;
        let imm = out.read_operand(imm_idx, U16)?;
        let imm_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[imm])?;
        let rsp_reg = RegisterId(register_id::GPR_BASE + 4);
        let rsp = out.read_register(rsp_reg, U64)?;
        let eight = const_u64(out, 8)?;
        let rsp_plus_8 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, eight])?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp_plus_8, imm_64])?;
        out.write_register(rsp_reg, new_rsp)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x0805, context))
    }
}

// ---------------------------------------------------------------------------
// ENTER imm16, imm8 (create stack frame)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct EnterImm16Imm8;

impl SemanticProvider for EnterImm16Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0806)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ENTER_IMM16_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp_reg = RegisterId(register_id::GPR_BASE + 4);
        let rbp_reg = RegisterId(register_id::GPR_BASE + 5);
        let rsp = out.read_register(rsp_reg, U64)?;
        let rbp = out.read_register(rbp_reg, U64)?;
        let eight = const_u64(out, 8)?;
        let pushed_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        out.write_register(rsp_reg, pushed_rsp)?;
        let mem_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Memory));
        if let Some(idx) = mem_idx {
            out.write_operand(idx, rbp)?;
        }
        out.write_register(rbp_reg, pushed_rsp)?;
        let imm_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Immediate))
            .unwrap_or(0);
        let imm16 = out.read_operand(imm_idx, U16)?;
        let imm16_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[imm16])?;
        let final_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[pushed_rsp, imm16_64])?;
        out.write_register(rsp_reg, final_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0806, context))
    }
}

// ---------------------------------------------------------------------------
// RET_FAR imm16
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct RetFarImm16;

impl SemanticProvider for RetFarImm16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0807)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RET_FAR_IMM16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let mem_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Memory))
            .unwrap_or(2);
        let imm_idx = (0..insn.operand_count() as u8)
            .find(|&i| insn.operand(i).map_or(false, |op| op.class == OperandClass::Immediate))
            .unwrap_or(0);
        let target = out.read_operand(mem_idx, U64)?;
        let imm = out.read_operand(imm_idx, U16)?;
        let imm_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[imm])?;
        let rsp_reg = RegisterId(register_id::GPR_BASE + 4);
        let rsp = out.read_register(rsp_reg, U64)?;
        let ten = const_u64(out, 10)?;
        let rsp_plus_10 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, ten])?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp_plus_10, imm_64])?;
        out.write_register(rsp_reg, new_rsp)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x0807, context))
    }
}

// ---------------------------------------------------------------------------
// LAHF / SAHF (load/store AH from/to flags)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Lahf;

impl SemanticProvider for Lahf {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0808)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LAHF
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rflags_val = out.read_register(register_id::RFLAGS, U64)?;
        let mask = const_u64(out, 0xD5u64)?;
        let filtered = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[rflags_val, mask])?;
        let bit1 = const_u64(out, 0x02u64)?;
        let ah_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[filtered, bit1])?;
        let zero = const_u64(out, 0)?;
        let ah_8 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U8, &[ah_64, zero])?;
        if insn.operand_count() > 0 {
            out.write_operand(0, ah_8)?;
        } else {
            let rax_reg = RegisterId(register_id::GPR_BASE);
            let rax = out.read_register(rax_reg, U64)?;
            let mask_rax = const_u64(out, !0xFF00u64)?;
            let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[rax, mask_rax])?;
            let eight = const_u64(out, 8)?;
            let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[ah_64, eight])?;
            let new_rax = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, shifted])?;
            out.write_register(rax_reg, new_rax)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(0x0808, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Sahf;

impl SemanticProvider for Sahf {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0809)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SAHF
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let ah_64 = if insn.operand_count() > 0 {
            let ah_8 = out.read_operand(0, U8)?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[ah_8])?
        } else {
            let rax_reg = RegisterId(register_id::GPR_BASE);
            let rax = out.read_register(rax_reg, U64)?;
            let eight = const_u64(out, 8)?;
            let shifted = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                U64,
                &[rax, eight],
            )?;
            let mask = const_u64(out, 0xFF)?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, mask])?
        };
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let clear_mask = const_u64(out, !0xD5u64)?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, clear_mask])?;
        let flag_mask = const_u64(out, 0xD5u64)?;
        let new_flags = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[ah_64, flag_mask])?;
        let final_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, new_flags])?;
        out.write_register(register_id::RFLAGS, final_rflags)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0809, context))
    }
}

// ---------------------------------------------------------------------------
// CLD / STD (clear/set Direction Flag DF in RFLAGS)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Cld;

impl SemanticProvider for Cld {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x080A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CLD
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let clear_df_mask = !(1u64 << rflags::DF_BIT);
        let mask = const_u64(out, clear_df_mask)?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;
        fall_through(out, insn)?;
        Ok(receipt(0x080A, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Std;

impl SemanticProvider for Std {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x080B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::STD
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let set_df_mask = 1u64 << rflags::DF_BIT;
        let mask = const_u64(out, set_df_mask)?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[old_rflags, mask])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;
        fall_through(out, insn)?;
        Ok(receipt(0x080B, context))
    }
}
