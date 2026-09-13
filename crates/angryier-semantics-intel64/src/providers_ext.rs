#![forbid(unsafe_code)]

//! Extended handwritten Intel 64 semantic providers.
//!
//! This module contains the Phase 4 expansion forms: additional register
//! aliasing, 32-bit arithmetic, conditional moves/sets/branches, bit
//! manipulation, shifts, memory operations, immediate arithmetic, and
//! NOP/HLT/UD2 variants.
//!
//! All forms here use only `PrimitiveOp` operations that are already
//! supported by the IR lowerer and concrete interpreter, so they work
//! end-to-end through the full pipeline.

use angryier_arch::OperandKind;
use crate::{forms, rflags, rule_id};
use angryier_arch_intel64::register_id;
use angryier_semantics::{
    DecodedInstructionView, FloatFormat, FloatingOp, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder,
    SemanticContext, SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType,
    SideEffect, ValueId, VectorOp,
};
use angryier_types::SemanticRuleId;

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U16: SemanticType = SemanticType::Scalar(ScalarType::BitVec(16));
const U8: SemanticType = SemanticType::Scalar(ScalarType::BitVec(8));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));
const F32: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F32));
const F64: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F64));
const F32X4: SemanticType = SemanticType::Vector { lanes: 4, lane: ScalarType::Float(FloatFormat::F32) };
const F64X2: SemanticType = SemanticType::Vector { lanes: 2, lane: ScalarType::Float(FloatFormat::F64) };
const I8X16: SemanticType = SemanticType::Vector { lanes: 16, lane: ScalarType::BitVec(8) };
const I16X8: SemanticType = SemanticType::Vector { lanes: 8, lane: ScalarType::BitVec(16) };
const I32X4: SemanticType = SemanticType::Vector { lanes: 4, lane: ScalarType::BitVec(32) };
const I64X2: SemanticType = SemanticType::Vector { lanes: 2, lane: ScalarType::BitVec(64) };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

fn const_u32(out: &mut dyn SemanticBuilder, value: u32) -> Result<ValueId, SemanticError> {
    out.constant(U32, &value.to_le_bytes())
}

/// Creates a vector constant with a uniform lane value.
/// `lane_bytes` is the byte width of each lane; `lanes` is the lane count.
fn vec_const_uniform(
    out: &mut dyn SemanticBuilder,
    ty: SemanticType,
    lane_value: u64,
    lane_bytes: usize,
    lanes: usize,
) -> Result<ValueId, SemanticError> {
    let lane = lane_value.to_le_bytes();
    let mut bytes = Vec::with_capacity(lane_bytes * lanes);
    for _ in 0..lanes {
        bytes.extend_from_slice(&lane[..lane_bytes]);
    }
    out.constant(ty, &bytes)
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

/// Write ZF, SF for a 32-bit result, preserving CF.
fn write_zf_sf_32_preserve_cf(out: &mut dyn SemanticBuilder, result: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u64(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[result, thirty_one])?;
    let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
    let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;

    // Preserve CF, clear ZF+SF, then set new ZF+SF
    let preserve_cf_mask = const_u64(out, !((1u64 << rflags::ZF_BIT) | (1u64 << rflags::SF_BIT)))?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, preserve_cf_mask])?;
    let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, sf_shifted])?;

    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Write ZF, SF, CF for a 32-bit addition.
fn write_add_flags_32(out: &mut dyn SemanticBuilder, result: ValueId, left: ValueId, _right: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u32(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[result, thirty_one])?;
    let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
    let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;

    let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[result, left])?;
    let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
    let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, cf_bit])?;

    let mask = const_u64(out, rflags::CORPUS_FLAG_MASK)?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    let with_sf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, sf_shifted])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_sf, cf_shifted])?;

    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Write ZF, SF, CF for a 32-bit subtraction.
fn write_sub_flags_32(out: &mut dyn SemanticBuilder, result: ValueId, left: ValueId, right: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u32(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[result, thirty_one])?;
    let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
    let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;

    let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[left, right])?;
    let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
    let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, cf_bit])?;

    let mask = const_u64(out, rflags::CORPUS_FLAG_MASK)?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    let with_sf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, sf_shifted])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_sf, cf_shifted])?;

    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Write ZF, SF for a 32-bit logical result, CF=0.
fn write_logical_flags_32(out: &mut dyn SemanticBuilder, result: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u32(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[result, thirty_one])?;
    let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
    let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;

    let mask = const_u64(out, rflags::CORPUS_FLAG_MASK)?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, sf_shifted])?;

    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

fn read_flag_set(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let rflags = out.read_register(register_id::RFLAGS, U64)?;
    let bit_val = const_u64(out, u64::from(bit))?;
    let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[rflags, bit_val])?;
    let one = const_u64(out, 1)?;
    let flag_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[flag_64, one])
}

fn read_flag_not_set(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let rflags = out.read_register(register_id::RFLAGS, U64)?;
    let bit_val = const_u64(out, u64::from(bit))?;
    let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[rflags, bit_val])?;
    let one = const_u64(out, 1)?;
    let flag_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
    let zero = const_u64(out, 0)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[flag_64, zero])
}

/// Writes ZF from a 1-bit condition value (1 = set ZF, 0 = clear ZF).
fn write_zf_from_cond(out: &mut dyn SemanticBuilder, cond: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zf_clear_mask = !(1u64 << rflags::ZF_BIT);
    let mask = out.constant(U64, &zf_clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cond])?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Writes ZF and CF from 1-bit condition values in a single RFLAGS update.
fn write_zf_cf_from_cond(
    out: &mut dyn SemanticBuilder,
    zf_cond: ValueId,
    cf_cond: ValueId,
) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let clear_mask = !((1u64 << rflags::ZF_BIT) | (1u64 << rflags::CF_BIT));
    let mask = out.constant(U64, &clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;

    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_cond])?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_cond])?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, cf_bit])?;

    let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, cf_shifted])?;
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Register aliasing / partial writes
// ---------------------------------------------------------------------------

macro_rules! mov_reg_reg {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let src = out.read_operand(1, $ty)?;
                out.write_operand(0, src)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_reg_reg!(MovR16R16, forms::MOV_R16_R16, U16, 0x5E);
mov_reg_reg!(MovR32Imm32, forms::MOV_R32_IMM32, U32, 0x63);
mov_reg_reg!(MovR16Imm16, forms::MOV_R16_IMM16, U16, 0x64);
mov_reg_reg!(MovR8Imm8, forms::MOV_R8_IMM8, U8, 0x65);

macro_rules! movzx {
    ($name:ident, $form:expr, $src_ty:expr, $dst_ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let src = out.read_operand(1, $src_ty)?;
                let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), $dst_ty, &[src])?;
                out.write_operand(0, extended)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movzx!(MovzxR32R16, forms::MOVZX_R32_R16, U16, U32, 0x5F);
movzx!(MovzxR32R8, forms::MOVZX_R32_R8, U8, U32, 0x61);

macro_rules! movsx {
    ($name:ident, $form:expr, $src_ty:expr, $dst_ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let src = out.read_operand(1, $src_ty)?;
                let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), $dst_ty, &[src])?;
                out.write_operand(0, extended)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movsx!(MovsxR32R16, forms::MOVSX_R32_R16, U16, U32, 0x60);
movsx!(MovsxR32R8, forms::MOVSX_R32_R8, U8, U32, 0x62);

// ---------------------------------------------------------------------------
// 32-bit arithmetic
// ---------------------------------------------------------------------------

macro_rules! arith_r32_r32 {
    ($name:ident, $form:expr, $op:expr, $rule:expr, $write_flags:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U32)?;
                let right = out.read_operand(1, U32)?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[left, right])?;
                $write_flags(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

arith_r32_r32!(AddR32R32, forms::ADD_R32_R32, PrimitiveOp::Add, 0x66, write_add_flags_32);
arith_r32_r32!(SubR32R32, forms::SUB_R32_R32, PrimitiveOp::Sub, 0x67, write_sub_flags_32);

macro_rules! logical_r32_r32 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U32)?;
                let right = out.read_operand(1, U32)?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[left, right])?;
                write_logical_flags_32(out, result)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logical_r32_r32!(XorR32R32, forms::XOR_R32_R32, PrimitiveOp::Xor, 0x68);
logical_r32_r32!(AndR32R32, forms::AND_R32_R32, PrimitiveOp::And, 0x69);
logical_r32_r32!(OrR32R32, forms::OR_R32_R32, PrimitiveOp::Or, 0x6A);

// CMP r32, r32 — flags only, no register write
#[derive(Clone, Copy, Debug)]
pub struct CmpR32R32;

impl SemanticProvider for CmpR32R32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x6B) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::CMP_R32_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U32)?;
        let right = out.read_operand(1, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[left, right])?;
        write_sub_flags_32(out, result, left, right)?;
        fall_through(out, insn)?;
        Ok(receipt(0x6B, context))
    }
}

// INC/DEC/NEG/NOT r32

// INC r32 — preserves CF, writes ZF/SF
#[derive(Clone, Copy, Debug)]
pub struct IncR32;
impl SemanticProvider for IncR32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x6C) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::INC_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U32)?;
        let one = const_u32(out, 1)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[operand, one])?;
        write_zf_sf_32_preserve_cf(out, result)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x6C, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DecR32;
impl SemanticProvider for DecR32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x6D) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::DEC_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U32)?;
        let one = const_u32(out, 1)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[operand, one])?;
        write_zf_sf_32_preserve_cf(out, result)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x6D, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NegR32;
impl SemanticProvider for NegR32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x6E) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::NEG_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U32)?;
        let zero = const_u32(out, 0)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[zero, operand])?;
        // CF = (operand != 0)
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
        let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
        let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
        let thirty_one = const_u64(out, 31)?;
        let one = const_u64(out, 1)?;

        let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
        let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
        let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

        let sf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[result, thirty_one])?;
        let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
        let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;

        let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[zero, operand])?;
        let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
        let cf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, cf_bit])?;

        let mask = const_u64(out, rflags::CORPUS_FLAG_MASK)?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
        let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
        let with_sf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, sf_shifted])?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_sf, cf_shifted])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;

        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x6E, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NotR32;
impl SemanticProvider for NotR32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x6F) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::NOT_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U32, &[operand])?;
        // NOT does not modify flags
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x6F, context))
    }
}

// ---------------------------------------------------------------------------
// Additional CMOVcc
// ---------------------------------------------------------------------------

macro_rules! cmovcc_r64 {
    ($name:ident, $form:expr, $rule:expr, $flag_fn:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let dst = out.read_operand(0, U64)?;
                let src = out.read_operand(1, U64)?;
                let cond = $flag_fn(out)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[cond, src, dst])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmovcc_r64!(CmovaR64R64, forms::CMOVA_R64_R64, 0x70, |out: &mut dyn SemanticBuilder| {
    // CMOVA: CF=0 AND ZF=0
    let cf_clear = read_flag_not_set(out, rflags::CF_BIT)?;
    let zf_clear = read_flag_not_set(out, rflags::ZF_BIT)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[cf_clear, zf_clear])
});
cmovcc_r64!(CmovbR64R64, forms::CMOVB_R64_R64, 0x71, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::CF_BIT) });
cmovcc_r64!(CmovbeR64R64, forms::CMOVBE_R64_R64, 0x72, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::ZF_BIT) });
cmovcc_r64!(CmovaeR64R64, forms::CMOVAE_R64_R64, 0x73, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) });
cmovcc_r64!(CmovsR64R64, forms::CMOVS_R64_R64, 0x74, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::SF_BIT) });
cmovcc_r64!(CmovnsR64R64, forms::CMOVNS_R64_R64, 0x75, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::SF_BIT) });
cmovcc_r64!(CmovcR64R64, forms::CMOVC_R64_R64, 0x76, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::CF_BIT) });
cmovcc_r64!(CmovncR64R64, forms::CMOVNC_R64_R64, 0x77, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) });
cmovcc_r64!(CmovleR64R64, forms::CMOVLE_R64_R64, 0x78, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::ZF_BIT) });
cmovcc_r64!(CmovgR64R64, forms::CMOVG_R64_R64, 0x79, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::ZF_BIT) });

// ---------------------------------------------------------------------------
// Additional SETcc
// ---------------------------------------------------------------------------

macro_rules! setcc_r8 {
    ($name:ident, $form:expr, $rule:expr, $flag_fn:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let cond = $flag_fn(out)?;
                let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cond])?;
                out.write_operand(0, extended)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

setcc_r8!(SetaR8, forms::SETA_R8, 0x7A, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) });
setcc_r8!(SetbR8, forms::SETB_R8, 0x7B, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::CF_BIT) });
setcc_r8!(SetbeR8, forms::SETBE_R8, 0x7C, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::ZF_BIT) });
setcc_r8!(SetaeR8, forms::SETAE_R8, 0x7D, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) });
setcc_r8!(SetsR8, forms::SETS_R8, 0x7E, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::SF_BIT) });
setcc_r8!(SetnsR8, forms::SETNS_R8, 0x7F, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::SF_BIT) });
setcc_r8!(SetcR8, forms::SETC_R8, 0x80, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::CF_BIT) });
setcc_r8!(SetncR8, forms::SETNC_R8, 0x81, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) });
setcc_r8!(SetleR8, forms::SETLE_R8, 0x82, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::ZF_BIT) });
setcc_r8!(SetgR8, forms::SETG_R8, 0x83, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::ZF_BIT) });

// ---------------------------------------------------------------------------
// Additional conditional branches
// ---------------------------------------------------------------------------

macro_rules! jcc_rel32 {
    ($name:ident, $form:expr, $rule:expr, $flag_fn:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let cond = $flag_fn(out)?;
                let target = out.read_operand(0, U64)?;
                let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
                out.branch(cond, target, next_pc)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

jcc_rel32!(JoRel32, forms::JO_REL32, 0x84, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::OF_BIT) });
jcc_rel32!(JnoRel32, forms::JNO_REL32, 0x85, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::OF_BIT) });
jcc_rel32!(JpeRel32, forms::JPE_REL32, 0x86, |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::PF_BIT) });
jcc_rel32!(JpoRel32, forms::JPO_REL32, 0x87, |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::PF_BIT) });

// ---------------------------------------------------------------------------
// Bit manipulation (using existing primitives — concrete-only approximation)
// ---------------------------------------------------------------------------

// BSWAP r64 — byte-swap, expressible as a series of shifts and masks
#[derive(Clone, Copy, Debug)]
pub struct BswapR64;

impl SemanticProvider for BswapR64 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x8D) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::BSWAP_R64 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let val = out.read_operand(0, U64)?;
        // BSWAP: reverse bytes. Extract byte i from position i*8, place at (7-i)*8.
        let mask_ff = const_u64(out, 0xFF)?;
        let mut result = const_u64(out, 0)?;

        for i in 0..8u64 {
            let src_shift = i * 8;
            let dst_shift = (7 - i) * 8;
            let bs = const_u64(out, src_shift)?;
            let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U64, &[val, bs])?;
            let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[byte, mask_ff])?;
            let ds = const_u64(out, dst_shift)?;
            let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[masked, ds])?;
            result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[result, shifted])?;
        }

        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x8D, context))
    }
}

// ---------------------------------------------------------------------------
// Bit scan / popcount (using new IR primitives)
// ---------------------------------------------------------------------------

/// BSF r64, r64: bit scan forward. dest = index of least significant set bit.
/// ZF=1 if source is 0 (dest undefined). ZF=0 if source != 0.
#[derive(Clone, Copy, Debug)]
pub struct BsfR64R64;
impl SemanticProvider for BsfR64R64 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x88) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::BSF_R64_R64 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let zero = const_u64(out, 0)?;
        let src_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
        // CTZ returns 64 when input is 0, but BSF leaves dest undefined in that case.
        // We write CTZ unconditionally; when src=0 the value is architecturally undefined.
        let ctz = out.emit(SemanticOp::Primitive(PrimitiveOp::CountTrailingZeros), U64, &[src])?;
        out.write_operand(0, ctz)?;
        // ZF = (src == 0)
        write_zf_from_cond(out, src_is_zero)?;
        fall_through(out, insn)?;
        Ok(receipt(0x88, context))
    }
}

/// BSR r64, r64: bit scan reverse. dest = index of most significant set bit.
/// ZF=1 if source is 0 (dest undefined). ZF=0 if source != 0.
#[derive(Clone, Copy, Debug)]
pub struct BsrR64R64;
impl SemanticProvider for BsrR64R64 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x89) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::BSR_R64_R64 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let zero = const_u64(out, 0)?;
        let src_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
        // CLZ returns 64 when input is 0. BSR result = (63 - CLZ) when src != 0.
        let clz = out.emit(SemanticOp::Primitive(PrimitiveOp::CountLeadingZeros), U64, &[src])?;
        let width_minus_one = const_u64(out, 63)?;
        let bsr_result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[width_minus_one, clz])?;
        out.write_operand(0, bsr_result)?;
        write_zf_from_cond(out, src_is_zero)?;
        fall_through(out, insn)?;
        Ok(receipt(0x89, context))
    }
}

/// POPCNT r64, r64: dest = number of set bits in src. ZF = (result == 0).
#[derive(Clone, Copy, Debug)]
pub struct PopcntR64R64;
impl SemanticProvider for PopcntR64R64 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x8A) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::POPCNT_R64_R64 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let count = out.emit(SemanticOp::Primitive(PrimitiveOp::Popcount), U64, &[src])?;
        out.write_operand(0, count)?;
        // ZF = (count == 0)
        let zero = const_u64(out, 0)?;
        let zf_cond = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[count, zero])?;
        write_zf_from_cond(out, zf_cond)?;
        fall_through(out, insn)?;
        Ok(receipt(0x8A, context))
    }
}

/// TZCNT r64, r64: dest = count of trailing zeros. Returns 64 if src=0.
/// ZF = (src == 0). CF = (src == 0).
#[derive(Clone, Copy, Debug)]
pub struct TzcntR64R64;
impl SemanticProvider for TzcntR64R64 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x8B) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::TZCNT_R64_R64 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let zero = const_u64(out, 0)?;
        let src_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
        let ctz = out.emit(SemanticOp::Primitive(PrimitiveOp::CountTrailingZeros), U64, &[src])?;
        out.write_operand(0, ctz)?;
        // ZF = (src == 0), CF = (src == 0)
        write_zf_cf_from_cond(out, src_is_zero, src_is_zero)?;
        fall_through(out, insn)?;
        Ok(receipt(0x8B, context))
    }
}

/// LZCNT r64, r64: dest = count of leading zeros. Returns 64 if src=0.
/// ZF = (result == 0). CF = (src == 0).
#[derive(Clone, Copy, Debug)]
pub struct LzcntR64R64;
impl SemanticProvider for LzcntR64R64 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x8C) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::LZCNT_R64_R64 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let zero = const_u64(out, 0)?;
        let src_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
        let clz = out.emit(SemanticOp::Primitive(PrimitiveOp::CountLeadingZeros), U64, &[src])?;
        out.write_operand(0, clz)?;
        // ZF = (result == 0), CF = (src == 0)
        let result_is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[clz, zero])?;
        write_zf_cf_from_cond(out, result_is_zero, src_is_zero)?;
        fall_through(out, insn)?;
        Ok(receipt(0x8C, context))
    }
}

// ---------------------------------------------------------------------------
// 32-bit shifts
// ---------------------------------------------------------------------------

macro_rules! shift_r32_imm8 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let val = out.read_operand(0, U32)?;
                let count = out.read_operand(1, U8)?;
                let count_32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[count])?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[val, count_32])?;
                write_zf_sf_32_preserve_cf(out, result)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

shift_r32_imm8!(ShlR32Imm8, forms::SHL_R32_IMM8, PrimitiveOp::ShiftLeft, 0x8E);
shift_r32_imm8!(ShrR32Imm8, forms::SHR_R32_IMM8, PrimitiveOp::LogicalShiftRight, 0x8F);
shift_r32_imm8!(SarR32Imm8, forms::SAR_R32_IMM8, PrimitiveOp::ArithmeticShiftRight, 0x90);

macro_rules! shift_r32_cl {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let val = out.read_operand(0, U32)?;
                let count = out.read_operand(1, U8)?;
                let count_32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[count])?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[val, count_32])?;
                write_zf_sf_32_preserve_cf(out, result)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

shift_r32_cl!(ShlR32Cl, forms::SHL_R32_CL, PrimitiveOp::ShiftLeft, 0x91);
shift_r32_cl!(ShrR32Cl, forms::SHR_R32_CL, PrimitiveOp::LogicalShiftRight, 0x92);
shift_r32_cl!(SarR32Cl, forms::SAR_R32_CL, PrimitiveOp::ArithmeticShiftRight, 0x93);

// ---------------------------------------------------------------------------
// 32-bit rotates (simplified — no CF)
// ---------------------------------------------------------------------------

macro_rules! rotate_r32_imm8 {
    ($name:ident, $form:expr, $rule:expr, $is_left:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let val = out.read_operand(0, U32)?;
                let count = out.read_operand(1, U8)?;
                let count_32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[count])?;
                let thirty_two = const_u32(out, 32)?;
                let effective = out.emit(SemanticOp::Primitive(PrimitiveOp::UnsignedDiv), U32, &[count_32, thirty_two])?;
                let shifted = if $is_left {
                    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[val, effective])?
                } else {
                    out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U32, &[val, effective])?
                };
                let complement = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[thirty_two, effective])?;
                let other = if $is_left {
                    out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U32, &[val, complement])?
                } else {
                    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[val, complement])?
                };
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[shifted, other])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

rotate_r32_imm8!(RolR32Imm8, forms::ROL_R32_IMM8, 0x94, true);
rotate_r32_imm8!(RorR32Imm8, forms::ROR_R32_IMM8, 0x95, false);

// ---------------------------------------------------------------------------
// 32-bit memory operations
// ---------------------------------------------------------------------------

macro_rules! mov_reg_mem_32 {
    ($name:ident, $form:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let val = out.read_operand(1, U32)?;
                out.write_operand(0, val)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_reg_mem_32!(MovR32Mem32, forms::MOV_R32_MEM32, 0x96);
mov_reg_mem_32!(MovR8Mem8, forms::MOV_R8_MEM8, 0x9B);

macro_rules! mov_mem_reg_32 {
    ($name:ident, $form:expr, $rule:expr, $ty:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let val = out.read_operand(0, $ty)?;
                out.write_operand(1, val)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_mem_reg_32!(MovMem32R32, forms::MOV_MEM32_R32, 0x97, U32);
mov_mem_reg_32!(MovMem8R8, forms::MOV_MEM8_R8, 0x9C, U8);

macro_rules! arith_r32_mem32 {
    ($name:ident, $form:expr, $op:expr, $rule:expr, $flags_fn:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U32)?;
                let right = out.read_operand(1, U32)?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[left, right])?;
                $flags_fn(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

arith_r32_mem32!(AddR32Mem32, forms::ADD_R32_MEM32, PrimitiveOp::Add, 0x98, write_add_flags_32);
arith_r32_mem32!(SubR32Mem32, forms::SUB_R32_MEM32, PrimitiveOp::Sub, 0x99, write_sub_flags_32);

#[derive(Clone, Copy, Debug)]
pub struct CmpR32Mem32;
impl SemanticProvider for CmpR32Mem32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x9A) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::CMP_R32_MEM32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U32)?;
        let right = out.read_operand(1, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[left, right])?;
        write_sub_flags_32(out, result, left, right)?;
        fall_through(out, insn)?;
        Ok(receipt(0x9A, context))
    }
}

// 8-bit memory arithmetic
macro_rules! arith_r8_mem8 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U8)?;
                let right = out.read_operand(1, U8)?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[left, right])?;
                // Simplified: no flags for 8-bit memory ops in this pass
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

arith_r8_mem8!(AddR8Mem8, forms::ADD_R8_MEM8, PrimitiveOp::Add, 0x9D);
arith_r8_mem8!(SubR8Mem8, forms::SUB_R8_MEM8, PrimitiveOp::Sub, 0x9E);

#[derive(Clone, Copy, Debug)]
pub struct CmpR8Mem8;
impl SemanticProvider for CmpR8Mem8 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0x9F) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::CMP_R8_MEM8 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U8)?;
        let right = out.read_operand(1, U8)?;
        let _result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[left, right])?;
        // Simplified: no flags for 8-bit cmp in this pass
        fall_through(out, insn)?;
        Ok(receipt(0x9F, context))
    }
}

// ---------------------------------------------------------------------------
// Immediate arithmetic
// ---------------------------------------------------------------------------

macro_rules! arith_r32_imm {
    ($name:ident, $form:expr, $op:expr, $rule:expr, $flags_fn:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U32)?;
                let right = out.read_operand(1, U32)?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[left, right])?;
                $flags_fn(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

arith_r32_imm!(AddR32Imm8, forms::ADD_R32_IMM8, PrimitiveOp::Add, 0xA0, write_add_flags_32);
arith_r32_imm!(SubR32Imm8, forms::SUB_R32_IMM8, PrimitiveOp::Sub, 0xA1, write_sub_flags_32);

#[derive(Clone, Copy, Debug)]
pub struct CmpR32Imm8;
impl SemanticProvider for CmpR32Imm8 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xA2) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::CMP_R32_IMM8 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U32)?;
        let right = out.read_operand(1, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[left, right])?;
        write_sub_flags_32(out, result, left, right)?;
        fall_through(out, insn)?;
        Ok(receipt(0xA2, context))
    }
}

macro_rules! logical_r64_imm {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U64)?;
                let right = out.read_operand(1, U64)?;
                let result = out.emit(SemanticOp::Primitive($op), U64, &[left, right])?;
                // Simplified: ZF only for logical imm
                let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
                let zero = const_u64(out, 0)?;
                let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;

                let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
                let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
                let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

                let preserve_mask = const_u64(out, !(1u64 << rflags::ZF_BIT))?;
                let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, preserve_mask])?;
                let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
                out.write_register(register_id::RFLAGS, new_rflags)?;

                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logical_r64_imm!(AndR64Imm32, forms::AND_R64_IMM32, PrimitiveOp::And, 0xA3);
logical_r64_imm!(OrR64Imm32, forms::OR_R64_IMM32, PrimitiveOp::Or, 0xA4);
logical_r64_imm!(XorR64Imm32, forms::XOR_R64_IMM32, PrimitiveOp::Xor, 0xA5);

#[derive(Clone, Copy, Debug)]
pub struct TestR64Imm32;
impl SemanticProvider for TestR64Imm32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xA6) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::TEST_R64_IMM32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U64)?;
        let right = out.read_operand(1, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[left, right])?;
        // ZF only
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let zero = const_u64(out, 0)?;
        let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;

        let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
        let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
        let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

        let preserve_mask = const_u64(out, !(1u64 << rflags::ZF_BIT))?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, preserve_mask])?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;

        fall_through(out, insn)?;
        Ok(receipt(0xA6, context))
    }
}

macro_rules! logical_r32_imm {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U32)?;
                let right = out.read_operand(1, U32)?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[left, right])?;
                write_logical_flags_32(out, result)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logical_r32_imm!(AndR32Imm32, forms::AND_R32_IMM32, PrimitiveOp::And, 0xA7);
logical_r32_imm!(OrR32Imm32, forms::OR_R32_IMM32, PrimitiveOp::Or, 0xA8);
logical_r32_imm!(XorR32Imm32, forms::XOR_R32_IMM32, PrimitiveOp::Xor, 0xA9);

#[derive(Clone, Copy, Debug)]
pub struct TestR32Imm32;
impl SemanticProvider for TestR32Imm32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xAA) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::TEST_R32_IMM32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U32)?;
        let right = out.read_operand(1, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[left, right])?;
        write_logical_flags_32(out, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAA, context))
    }
}

// ---------------------------------------------------------------------------
// NOP variants
// ---------------------------------------------------------------------------

macro_rules! nop_n {
    ($name:ident, $form:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

nop_n!(Nop3, forms::NOP3, 0xB8);
nop_n!(Nop4, forms::NOP4, 0xB9);
nop_n!(Nop5, forms::NOP5, 0xBA);
nop_n!(Nop6, forms::NOP6, 0xBB);
nop_n!(Nop7, forms::NOP7, 0xBC);
nop_n!(Nop8, forms::NOP8, 0xBD);
nop_n!(Nop9, forms::NOP9, 0xBE);

// ---------------------------------------------------------------------------
// HLT / UD2
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Hlt;

impl SemanticProvider for Hlt {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xBF) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::HLT }
    fn emit(&self, context: &SemanticContext, _insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        // HLT: raise exception vector 0
        out.side_effect(SideEffect::RaiseException(0), &[])?;
        Ok(receipt(0xBF, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ud2;

impl SemanticProvider for Ud2 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC0) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::UD2 }
    fn emit(&self, context: &SemanticContext, _insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        // UD2: raise exception vector 6 (undefined instruction)
        out.side_effect(SideEffect::RaiseException(6), &[])?;
        Ok(receipt(0xC0, context))
    }
}

// ---------------------------------------------------------------------------
// LEA r32, [m]
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct LeaR32Mem;

impl SemanticProvider for LeaR32Mem {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xB6) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::LEA_R32_MEM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let addr = out.read_operand(1, U32)?;
        out.write_operand(0, addr)?;
        fall_through(out, insn)?;
        Ok(receipt(0xB6, context))
    }
}

// ---------------------------------------------------------------------------
// MOVQ XMM, XMM — scalar 64-bit move via integer path
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MovqXmmXmm;

impl SemanticProvider for MovqXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xB7) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::MOVQ_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        out.write_operand(0, src)?;
        fall_through(out, insn)?;
        Ok(receipt(0xB7, context))
    }
}

// ---------------------------------------------------------------------------
// 32-bit stack operations
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PushR32;

impl SemanticProvider for PushR32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xAD) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PUSH_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let value = out.read_operand(0, U32)?;
        let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[value])?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        out.side_effect(SideEffect::MemoryWrite, &[new_rsp, extended])?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAD, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PopR32;

impl SemanticProvider for PopR32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xAE) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::POP_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        // The semantic IR does not provide a value-producing load from a
        // computed address yet. Emit the memory read side effect and
        // increment RSP to model the stack pop.
        out.side_effect(SideEffect::MemoryRead, &[rsp])?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, eight])?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAE, context))
    }
}

// ---------------------------------------------------------------------------
// XADD r32, r32
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct XaddR32R32;

impl SemanticProvider for XaddR32R32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xAB) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::XADD_R32_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, U32)?;
        let src = out.read_operand(1, U32)?;
        let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[dst, src])?;
        write_add_flags_32(out, sum, dst, src)?;
        // XADD: dest = dest + src, src = old dest
        out.write_operand(0, sum)?;
        out.write_operand(1, dst)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAB, context))
    }
}

// ---------------------------------------------------------------------------
// CMPXCHG r32, r32
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CmpxchgR32R32;

impl SemanticProvider for CmpxchgR32R32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xAC) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::CMPXCHG_R32_R32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        // CMPXCHG r32, r32: compare EAX with dest, if equal ZF=1 and dest=src, else ZF=0 and EAX=dest
        // For this semantic we use operand 0 = dest, operand 1 = src
        let dest = out.read_operand(0, U32)?;
        let src = out.read_operand(1, U32)?;
        let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[dest, src])?;
        let new_dest = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U32, &[eq, src, dest])?;
        // ZF = eq
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
        let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[eq])?;
        let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;
        let preserve_mask = const_u64(out, !(1u64 << rflags::ZF_BIT))?;
        let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, preserve_mask])?;
        let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
        out.write_register(register_id::RFLAGS, new_rflags)?;
        out.write_operand(0, new_dest)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAC, context))
    }
}

// ---------------------------------------------------------------------------
// IMUL r64, r64, imm32 — three-operand multiply
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ImulR64R64Imm32;

impl SemanticProvider for ImulR64R64Imm32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xAF) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::IMUL_R64_R64_IMM32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let imm = out.read_operand(2, U64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[src, imm])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAF, context))
    }
}

// ---------------------------------------------------------------------------
// 32-bit multiply/divide
// ---------------------------------------------------------------------------

macro_rules! muldiv_r32 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let left = out.read_operand(0, U32)?;
                let right = out.read_operand(1, U32)?;
                let result = out.emit(SemanticOp::Primitive($op), U32, &[left, right])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

muldiv_r32!(ImulR32R32, forms::IMUL_R32_R32, PrimitiveOp::Mul, 0xB0);
muldiv_r32!(MulR32R32, forms::MUL_R32_R32, PrimitiveOp::Mul, 0xB3);
muldiv_r32!(DivR32R32, forms::DIV_R32_R32, PrimitiveOp::UnsignedDiv, 0xB4);
muldiv_r32!(IdivR32R32, forms::IDIV_R32_R32, PrimitiveOp::SignedDiv, 0xB5);

#[derive(Clone, Copy, Debug)]
pub struct ImulR32R32Imm8;
impl SemanticProvider for ImulR32R32Imm8 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xB1) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::IMUL_R32_R32_IMM8 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U32)?;
        let imm = out.read_operand(2, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U32, &[src, imm])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xB1, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ImulR32R32Imm32;
impl SemanticProvider for ImulR32R32Imm32 {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xB2) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::IMUL_R32_R32_IMM32 }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U32)?;
        let imm = out.read_operand(2, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U32, &[src, imm])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xB2, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE scalar float providers
// ---------------------------------------------------------------------------

/// ADDSS xmm, xmm: scalar single-precision add on lane 0.
/// Simplified: treats the XMM as a single f32 (upper lanes not modeled).
#[derive(Clone, Copy, Debug)]
pub struct AddssXmmXmm;

impl SemanticProvider for AddssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC1) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADDSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32)?;
        let src = out.read_operand(1, F32)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Add), F32, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC1, context))
    }
}

/// SUBSS xmm, xmm: scalar single-precision subtract on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct SubssXmmXmm;

impl SemanticProvider for SubssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC2) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUBSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32)?;
        let src = out.read_operand(1, F32)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Sub), F32, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC2, context))
    }
}

/// MULSS xmm, xmm: scalar single-precision multiply on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct MulssXmmXmm;

impl SemanticProvider for MulssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC3) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MULSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32)?;
        let src = out.read_operand(1, F32)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Mul), F32, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC3, context))
    }
}

/// DIVSS xmm, xmm: scalar single-precision divide on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct DivssXmmXmm;

impl SemanticProvider for DivssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC4) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIVSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32)?;
        let src = out.read_operand(1, F32)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Div), F32, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC4, context))
    }
}

/// SQRTSS xmm, xmm: scalar single-precision square root on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct SqrtssXmmXmm;

impl SemanticProvider for SqrtssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC5) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SQRTSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, F32)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Sqrt), F32, &[src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC5, context))
    }
}

/// ADDSD xmm, xmm: scalar double-precision add on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct AddsdXmmXmm;

impl SemanticProvider for AddsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC6) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADDSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64)?;
        let src = out.read_operand(1, F64)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Add), F64, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC6, context))
    }
}

/// SUBSD xmm, xmm: scalar double-precision subtract on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct SubsdXmmXmm;

impl SemanticProvider for SubsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC7) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUBSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64)?;
        let src = out.read_operand(1, F64)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Sub), F64, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC7, context))
    }
}

/// MULSD xmm, xmm: scalar double-precision multiply on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct MulsdXmmXmm;

impl SemanticProvider for MulsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC8) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MULSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64)?;
        let src = out.read_operand(1, F64)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Mul), F64, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC8, context))
    }
}

/// DIVSD xmm, xmm: scalar double-precision divide on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct DivsdXmmXmm;

impl SemanticProvider for DivsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xC9) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIVSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64)?;
        let src = out.read_operand(1, F64)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Div), F64, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xC9, context))
    }
}

/// SQRTSD xmm, xmm: scalar double-precision square root on lane 0.
#[derive(Clone, Copy, Debug)]
pub struct SqrtsdXmmXmm;

impl SemanticProvider for SqrtsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xCA) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SQRTSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, F64)?;
        let result = out.emit(SemanticOp::Float(FloatingOp::Sqrt), F64, &[src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCA, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE packed float providers
// ---------------------------------------------------------------------------

/// ADDPS xmm, xmm: packed single-precision add (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct AddpsXmmXmm;

impl SemanticProvider for AddpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xCB) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADDPS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Add)), F32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCB, context))
    }
}

/// SUBPS xmm, xmm: packed single-precision subtract (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct SubpsXmmXmm;

impl SemanticProvider for SubpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xCC) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUBPS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Sub)), F32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCC, context))
    }
}

/// MULPS xmm, xmm: packed single-precision multiply (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct MulpsXmmXmm;

impl SemanticProvider for MulpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xCD) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MULPS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Mul)), F32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCD, context))
    }
}

/// DIVPS xmm, xmm: packed single-precision divide (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct DivpsXmmXmm;

impl SemanticProvider for DivpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xCE) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIVPS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Div)), F32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCE, context))
    }
}

/// ADDPD xmm, xmm: packed double-precision add (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct AddpdXmmXmm;

impl SemanticProvider for AddpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xCF) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADDPD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Add)), F64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCF, context))
    }
}

/// SUBPD xmm, xmm: packed double-precision subtract (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct SubpdXmmXmm;

impl SemanticProvider for SubpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD0) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUBPD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Sub)), F64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD0, context))
    }
}

/// MULPD xmm, xmm: packed double-precision multiply (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct MulpdXmmXmm;

impl SemanticProvider for MulpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD1) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MULPD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Mul)), F64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD1, context))
    }
}

/// DIVPD xmm, xmm: packed double-precision divide (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct DivpdXmmXmm;

impl SemanticProvider for DivpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD2) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIVPD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Div)), F64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD2, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed integer providers
// ---------------------------------------------------------------------------

/// PADDB xmm, xmm: packed byte add (16x8 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PaddbXmmXmm;

impl SemanticProvider for PaddbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD3) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PADDB_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD3, context))
    }
}

/// PSUBB xmm, xmm: packed byte subtract (16x8 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubbXmmXmm;

impl SemanticProvider for PsubbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD4) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PSUBB_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD4, context))
    }
}

/// PADDW xmm, xmm: packed word add (8x16 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PaddwXmmXmm;

impl SemanticProvider for PaddwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD5) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PADDW_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)), I16X8, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD5, context))
    }
}

/// PSUBW xmm, xmm: packed word subtract (8x16 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubwXmmXmm;

impl SemanticProvider for PsubwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD6) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PSUBW_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)), I16X8, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD6, context))
    }
}

/// PMULLW xmm, xmm: packed word multiply low (8x16 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PmullwXmmXmm;

impl SemanticProvider for PmullwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD7) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PMULLW_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Mul)), I16X8, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD7, context))
    }
}

/// PADDD xmm, xmm: packed dword add (4x32 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PadddXmmXmm;

impl SemanticProvider for PadddXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD8) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PADDD_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)), I32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD8, context))
    }
}

/// PSUBD xmm, xmm: packed dword subtract (4x32 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubdXmmXmm;

impl SemanticProvider for PsubdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xD9) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PSUBD_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)), I32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD9, context))
    }
}

/// PMULLD xmm, xmm: packed dword multiply low (4x32 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PmulldXmmXmm;

impl SemanticProvider for PmulldXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xDA) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PMULLD_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Mul)), I32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDA, context))
    }
}

/// PADDQ xmm, xmm: packed qword add (2x64 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PaddqXmmXmm;

impl SemanticProvider for PaddqXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xDB) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PADDQ_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I64X2)?;
        let src = out.read_operand(1, I64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)), I64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDB, context))
    }
}

/// PSUBQ xmm, xmm: packed qword subtract (2x64 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubqXmmXmm;

impl SemanticProvider for PsubqXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xDC) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PSUBQ_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I64X2)?;
        let src = out.read_operand(1, I64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)), I64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDC, context))
    }
}

/// PAND xmm, xmm: packed bitwise AND (full 128-bit).
#[derive(Clone, Copy, Debug)]
pub struct PandXmmXmm;

impl SemanticProvider for PandXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xDD) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PAND_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDD, context))
    }
}

/// POR xmm, xmm: packed bitwise OR (full 128-bit).
#[derive(Clone, Copy, Debug)]
pub struct PorXmmXmm;

impl SemanticProvider for PorXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xDE) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::POR_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Or)), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDE, context))
    }
}

/// PXOR xmm, xmm: packed bitwise XOR (full 128-bit).
#[derive(Clone, Copy, Debug)]
pub struct PxorXmmXmm;

impl SemanticProvider for PxorXmmXmm {
    fn rule_id(&self) -> SemanticRuleId { rule_id(0xDF) }
    fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == forms::PXOR_XMM_XMM }
    fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDF, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shift providers (imm8)
// ---------------------------------------------------------------------------

macro_rules! packed_shift_imm8 {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $lane_bytes:expr, $lanes:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let dst = out.read_operand(0, $ty)?;
                // Extract the immediate shift count from the decoded instruction
                let count = insn.operand(1)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let count_vec = vec_const_uniform(out, $ty, count, $lane_bytes, $lanes)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise($op)), $ty, &[dst, count_vec])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_shift_imm8!(PsllwXmmImm8, forms::PSLLW_XMM_IMM8, PrimitiveOp::ShiftLeft, I16X8, 2, 8, 0xE0);
packed_shift_imm8!(PsrlwXmmImm8, forms::PSRLW_XMM_IMM8, PrimitiveOp::LogicalShiftRight, I16X8, 2, 8, 0xE1);
packed_shift_imm8!(PsrawXmmImm8, forms::PSRAW_XMM_IMM8, PrimitiveOp::ArithmeticShiftRight, I16X8, 2, 8, 0xE2);
packed_shift_imm8!(PslldXmmImm8, forms::PSLLD_XMM_IMM8, PrimitiveOp::ShiftLeft, I32X4, 4, 4, 0xE3);
packed_shift_imm8!(PsrldXmmImm8, forms::PSRLD_XMM_IMM8, PrimitiveOp::LogicalShiftRight, I32X4, 4, 4, 0xE4);
packed_shift_imm8!(PsradXmmImm8, forms::PSRAD_XMM_IMM8, PrimitiveOp::ArithmeticShiftRight, I32X4, 4, 4, 0xE5);
packed_shift_imm8!(PsllqXmmImm8, forms::PSLLQ_XMM_IMM8, PrimitiveOp::ShiftLeft, I64X2, 8, 2, 0xE6);
packed_shift_imm8!(PsrlqXmmImm8, forms::PSRLQ_XMM_IMM8, PrimitiveOp::LogicalShiftRight, I64X2, 8, 2, 0xE7);

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed compare providers
// ---------------------------------------------------------------------------

macro_rules! packed_cmp {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise($op)), $ty, &[dst, src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_cmp!(PcmpeqbXmmXmm, forms::PCMPEQB_XMM_XMM, PrimitiveOp::MaskEq, I8X16, 0xE8);
packed_cmp!(PcmpeqwXmmXmm, forms::PCMPEQW_XMM_XMM, PrimitiveOp::MaskEq, I16X8, 0xE9);
packed_cmp!(PcmpeqdXmmXmm, forms::PCMPEQD_XMM_XMM, PrimitiveOp::MaskEq, I32X4, 0xEA);
packed_cmp!(PcmpgtbXmmXmm, forms::PCMPGTB_XMM_XMM, PrimitiveOp::MaskSgt, I8X16, 0xEB);
packed_cmp!(PcmpgtwXmmXmm, forms::PCMPGTW_XMM_XMM, PrimitiveOp::MaskSgt, I16X8, 0xEC);
packed_cmp!(PcmpgtdXmmXmm, forms::PCMPGTD_XMM_XMM, PrimitiveOp::MaskSgt, I32X4, 0xED);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4 packed min/max providers
// ---------------------------------------------------------------------------

macro_rules! packed_minmax {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId { rule_id($rule) }
            fn origin(&self) -> SemanticOrigin { SemanticOrigin::HandwrittenOverride }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool { insn.form_id() == $form }
            fn emit(&self, context: &SemanticContext, insn: &dyn DecodedInstructionView, out: &mut dyn SemanticBuilder) -> Result<SemanticReceipt, SemanticError> {
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise($op)), $ty, &[dst, src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// Signed max
packed_minmax!(PmaxsbXmmXmm, forms::PMAXSB_XMM_XMM, PrimitiveOp::MaxS, I8X16, 0xEE);
packed_minmax!(PmaxswXmmXmm, forms::PMAXSW_XMM_XMM, PrimitiveOp::MaxS, I16X8, 0xEF);
packed_minmax!(PmaxsdXmmXmm, forms::PMAXSD_XMM_XMM, PrimitiveOp::MaxS, I32X4, 0xF0);
// Unsigned max
packed_minmax!(PmaxubXmmXmm, forms::PMAXUB_XMM_XMM, PrimitiveOp::MaxU, I8X16, 0xF1);
packed_minmax!(PmaxuwXmmXmm, forms::PMAXUW_XMM_XMM, PrimitiveOp::MaxU, I16X8, 0xF2);
packed_minmax!(PmaxudXmmXmm, forms::PMAXUD_XMM_XMM, PrimitiveOp::MaxU, I32X4, 0xF3);
// Signed min
packed_minmax!(PminsbXmmXmm, forms::PMINSB_XMM_XMM, PrimitiveOp::MinS, I8X16, 0xF4);
packed_minmax!(PminswXmmXmm, forms::PMINSW_XMM_XMM, PrimitiveOp::MinS, I16X8, 0xF5);
packed_minmax!(PminsdXmmXmm, forms::PMINSD_XMM_XMM, PrimitiveOp::MinS, I32X4, 0xF6);
// Unsigned min
packed_minmax!(PminubXmmXmm, forms::PMINUB_XMM_XMM, PrimitiveOp::MinU, I8X16, 0xF7);
packed_minmax!(PminuwXmmXmm, forms::PMINUW_XMM_XMM, PrimitiveOp::MinU, I16X8, 0xF8);
packed_minmax!(PminudXmmXmm, forms::PMINUD_XMM_XMM, PrimitiveOp::MinU, I32X4, 0xF9);
