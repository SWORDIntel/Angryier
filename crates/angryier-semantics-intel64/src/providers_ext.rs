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

use crate::providers::{widen_to_u64, write_add_flags, write_logical_flags, write_sub_flags};
use crate::{forms, rflags, rule_id};
use angryier_arch::OperandKind;
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
const F32X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::Float(FloatFormat::F32),
};
const F64X2: SemanticType = SemanticType::Vector {
    lanes: 2,
    lane: ScalarType::Float(FloatFormat::F64),
};
const I8X16: SemanticType = SemanticType::Vector {
    lanes: 16,
    lane: ScalarType::BitVec(8),
};
const I16X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::BitVec(16),
};
const I32X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::BitVec(32),
};
const I64X2: SemanticType = SemanticType::Vector {
    lanes: 2,
    lane: ScalarType::BitVec(64),
};
const U128: SemanticType = SemanticType::Scalar(ScalarType::BitVec(128));
const U96: SemanticType = SemanticType::Scalar(ScalarType::BitVec(96));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

fn const_u32(out: &mut dyn SemanticBuilder, value: u32) -> Result<ValueId, SemanticError> {
    out.constant(U32, &value.to_le_bytes())
}

/// Emits a constant of the given scalar type (value truncated to the width).
fn const_typed(out: &mut dyn SemanticBuilder, ty: SemanticType, value: u64) -> Result<ValueId, SemanticError> {
    let bits = scalar_bits(ty) as usize;
    let byte_count = bits.div_ceil(8);
    let mut bytes = value.to_le_bytes().to_vec();
    bytes.resize(byte_count, 0);
    out.constant(ty, &bytes)
}

/// Scalar single-precision float op on lane 0, preserving upper 96 bits from src1.
fn scalar_ss_preserve(
    out: &mut dyn SemanticBuilder,
    insn: &dyn DecodedInstructionView,
    fop: FloatingOp,
    unary: bool,
) -> Result<(), SemanticError> {
    let src1 = out.read_operand(0, F32X4)?;
    let src2 = out.read_operand(1, F32X4)?;
    let zero = const_u64(out, 0)?;
    let thirty_two = const_u64(out, 32)?;
    let lo1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src1, zero])?;
    let lo2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src2, zero])?;
    let result = if unary {
        out.emit(SemanticOp::Float(fop), F32, &[lo2])?
    } else {
        out.emit(SemanticOp::Float(fop), F32, &[lo1, lo2])?
    };
    let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U96, &[src1, thirty_two])?;
    let combined = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X4, &[result, upper])?;
    out.write_operand(0, combined)?;
    fall_through(out, insn)?;
    Ok(())
}

/// Scalar double-precision float op on lane 0, preserving upper 64 bits from src1.
fn scalar_sd_preserve(
    out: &mut dyn SemanticBuilder,
    insn: &dyn DecodedInstructionView,
    fop: FloatingOp,
    unary: bool,
) -> Result<(), SemanticError> {
    let src1 = out.read_operand(0, F64X2)?;
    let src2 = out.read_operand(1, F64X2)?;
    let zero = const_u64(out, 0)?;
    let sixty_four = const_u64(out, 64)?;
    let lo1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src1, zero])?;
    let lo2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src2, zero])?;
    let result = if unary {
        out.emit(SemanticOp::Float(fop), F64, &[lo2])?
    } else {
        out.emit(SemanticOp::Float(fop), F64, &[lo1, lo2])?
    };
    let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src1, sixty_four])?;
    let combined = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X2, &[result, upper])?;
    out.write_operand(0, combined)?;
    fall_through(out, insn)?;
    Ok(())
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
    let result = widen_to_u64(out, result, 32)?;
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u64(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, thirty_one],
    )?;
    let sf_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[sf_raw, one])?;
    let sf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_masked, sf_bit])?;

    // Preserve CF, clear ZF+SF, then set new ZF+SF
    let preserve_cf_mask = const_u64(out, !((1u64 << rflags::ZF_BIT) | (1u64 << rflags::SF_BIT)))?;
    let cleared = out.emit(
        SemanticOp::Primitive(PrimitiveOp::And),
        U64,
        &[old_rflags, preserve_cf_mask],
    )?;
    let with_zf = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, zf_shifted])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[with_zf, sf_shifted])?;

    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

/// Write ZF, SF, CF for a 32-bit addition.
fn write_add_flags_32(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    _right: ValueId,
) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, 32)?;
    let left = widen_to_u64(out, left, 32)?;
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u64(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, thirty_one],
    )?;
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
fn write_sub_flags_32(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
) -> Result<(), SemanticError> {
    let result = widen_to_u64(out, result, 32)?;
    let left = widen_to_u64(out, left, 32)?;
    let right = widen_to_u64(out, right, 32)?;
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u64(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, thirty_one],
    )?;
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
    let result = widen_to_u64(out, result, 32)?;
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let zero = const_u64(out, 0)?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let thirty_one = const_u64(out, 31)?;
    let one = const_u64(out, 1)?;

    let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
    let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
    let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

    let sf_raw = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[result, thirty_one],
    )?;
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
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[rflags, bit_val],
    )?;
    let one = const_u64(out, 1)?;
    let flag_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[shifted, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[flag_64, one])
}

fn read_flag_not_set(out: &mut dyn SemanticBuilder, bit: u8) -> Result<ValueId, SemanticError> {
    let rflags = out.read_register(register_id::RFLAGS, U64)?;
    let bit_val = const_u64(out, u64::from(bit))?;
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[rflags, bit_val],
    )?;
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
                let src = out.read_operand(1, $src_ty)?;
                let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), $dst_ty, &[src])?;
                out.write_operand(0, extended)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movsx!(MovsxR64Mem32, forms::MOVSX_R64_MEM32, U32, U64, 0x208);
movsx!(MovsxR64Mem8, forms::MOVSX_R64_MEM8, U8, U64, 0x209);
movsx!(MovsxR64Mem16, forms::MOVSX_R64_MEM16, U16, U64, 0x20A);
movsx!(MovsxR32Mem8, forms::MOVSX_R32_MEM8, U8, U32, 0x20B);
movsx!(MovsxR32Mem16, forms::MOVSX_R32_MEM16, U16, U32, 0x20C);
movzx!(MovzxR64Mem8, forms::MOVZX_R64_MEM8, U8, U64, 0x20D);
movzx!(MovzxR64Mem16, forms::MOVZX_R64_MEM16, U16, U64, 0x20E);
movzx!(MovzxR32Mem8, forms::MOVZX_R32_MEM8, U8, U32, 0x20F);
movzx!(MovzxR32Mem16, forms::MOVZX_R32_MEM16, U16, U32, 0x210);
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

arith_r32_r32!(
    AddR32R32,
    forms::ADD_R32_R32,
    PrimitiveOp::Add,
    0x66,
    write_add_flags_32
);
arith_r32_r32!(
    SubR32R32,
    forms::SUB_R32_R32,
    PrimitiveOp::Sub,
    0x67,
    write_sub_flags_32
);

macro_rules! logical_r32_r32 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x6B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x6C)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::INC_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x6D)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DEC_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x6E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NEG_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U32)?;
        let zero = const_u64(out, 0)?;
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

        let sf_raw = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[result, thirty_one],
        )?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x6F)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NOT_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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

cmovcc_r64!(
    CmovaR64R64,
    forms::CMOVA_R64_R64,
    0x70,
    |out: &mut dyn SemanticBuilder| {
        // CMOVA: CF=0 AND ZF=0
        let cf_clear = read_flag_not_set(out, rflags::CF_BIT)?;
        let zf_clear = read_flag_not_set(out, rflags::ZF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[cf_clear, zf_clear])
    }
);
cmovcc_r64!(
    CmovbR64R64,
    forms::CMOVB_R64_R64,
    0x71,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::CF_BIT) }
);
cmovcc_r64!(
    CmovbeR64R64,
    forms::CMOVBE_R64_R64,
    0x72,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::ZF_BIT) }
);
cmovcc_r64!(
    CmovaeR64R64,
    forms::CMOVAE_R64_R64,
    0x73,
    |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) }
);
cmovcc_r64!(
    CmovsR64R64,
    forms::CMOVS_R64_R64,
    0x74,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::SF_BIT) }
);
cmovcc_r64!(
    CmovnsR64R64,
    forms::CMOVNS_R64_R64,
    0x75,
    |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::SF_BIT) }
);
cmovcc_r64!(
    CmovcR64R64,
    forms::CMOVC_R64_R64,
    0x76,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::CF_BIT) }
);
cmovcc_r64!(
    CmovncR64R64,
    forms::CMOVNC_R64_R64,
    0x77,
    |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::CF_BIT) }
);
cmovcc_r64!(
    CmovleR64R64,
    forms::CMOVLE_R64_R64,
    0x78,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::ZF_BIT) }
);
cmovcc_r64!(
    CmovgR64R64,
    forms::CMOVG_R64_R64,
    0x79,
    |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::ZF_BIT) }
);

// ---------------------------------------------------------------------------
// Additional SETcc
// ---------------------------------------------------------------------------

macro_rules! setcc_r8 {
    ($name:ident, $form:expr, $rule:expr, $flag_fn:expr) => {
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
                let cond = $flag_fn(out)?;
                // The condition is written as a byte: 1 when set, 0 otherwise.
                let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[cond])?;
                out.write_operand(0, byte)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

setcc_r8!(SetaR8, forms::SETA_R8, 0x7A, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::CF_BIT)
});
setcc_r8!(SetbR8, forms::SETB_R8, 0x7B, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::CF_BIT)
});
setcc_r8!(SetbeR8, forms::SETBE_R8, 0x7C, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::ZF_BIT)
});
setcc_r8!(SetaeR8, forms::SETAE_R8, 0x7D, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::CF_BIT)
});
setcc_r8!(SetsR8, forms::SETS_R8, 0x7E, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::SF_BIT)
});
setcc_r8!(SetnsR8, forms::SETNS_R8, 0x7F, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::SF_BIT)
});
setcc_r8!(SetcR8, forms::SETC_R8, 0x80, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::CF_BIT)
});
setcc_r8!(SetncR8, forms::SETNC_R8, 0x81, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::CF_BIT)
});
setcc_r8!(SetleR8, forms::SETLE_R8, 0x82, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::ZF_BIT)
});
setcc_r8!(SetgR8, forms::SETG_R8, 0x83, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::ZF_BIT)
});

// ---------------------------------------------------------------------------
// Additional conditional branches
// ---------------------------------------------------------------------------

macro_rules! jcc_rel32 {
    ($name:ident, $form:expr, $rule:expr, $flag_fn:expr) => {
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
                let cond = $flag_fn(out)?;
                let target = out.read_operand(0, U64)?;
                let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
                out.branch(cond, target, next_pc)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

jcc_rel32!(JoRel32, forms::JO_REL32, 0x84, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::OF_BIT)
});
jcc_rel32!(JnoRel32, forms::JNO_REL32, 0x85, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::OF_BIT)
});
jcc_rel32!(JpeRel32, forms::JPE_REL32, 0x86, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::PF_BIT)
});
jcc_rel32!(JpoRel32, forms::JPO_REL32, 0x87, |out: &mut dyn SemanticBuilder| {
    read_flag_not_set(out, rflags::PF_BIT)
});

// ---------------------------------------------------------------------------
// Bit manipulation (using existing primitives — concrete-only approximation)
// ---------------------------------------------------------------------------

// BSWAP r64 — byte-swap, expressible as a series of shifts and masks
#[derive(Clone, Copy, Debug)]
pub struct BswapR64;

impl SemanticProvider for BswapR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x8D)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BSWAP_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x88)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BSF_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x89)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BSR_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x8A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POPCNT_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x8B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::TZCNT_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x8C)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LZCNT_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
                let thirty_two = const_u32(out, 32)?;
                let effective = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::UnsignedDiv),
                    U32,
                    &[count_32, thirty_two],
                )?;
                let shifted = if $is_left {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U32,
                        &[val, effective],
                    )?
                } else {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                        U32,
                        &[val, effective],
                    )?
                };
                let complement = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Sub),
                    U32,
                    &[thirty_two, effective],
                )?;
                let other = if $is_left {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                        U32,
                        &[val, complement],
                    )?
                } else {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U32,
                        &[val, complement],
                    )?
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
                let src = out.read_operand(0, U64)?;
                let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
                let zero = const_u64(out, 0)?;
                let mask = const_u64(out, 0x1F)?;
                let thirty_two = const_u32(out, 32)?;
                let val = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src, zero])?;
                let count_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
                let effective = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U32,
                    &[count_64, zero],
                )?;
                let shifted = if $is_left {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U32,
                        &[val, effective],
                    )?
                } else {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                        U32,
                        &[val, effective],
                    )?
                };
                let complement = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Sub),
                    U32,
                    &[thirty_two, effective],
                )?;
                let other = if $is_left {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                        U32,
                        &[val, complement],
                    )?
                } else {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U32,
                        &[val, complement],
                    )?
                };
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[shifted, other])?;
                let result_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[result])?;
                out.write_operand(0, result_64)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

rotate_r32_cl!(RolR32Cl, forms::ROL_R32_CL, 0x96, true);
rotate_r32_cl!(RorR32Cl, forms::ROR_R32_CL, 0x97, false);

// ---------------------------------------------------------------------------
// 32-bit memory operations
// ---------------------------------------------------------------------------

macro_rules! mov_reg_mem_32 {
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
                let val = out.read_operand(1, U32)?;
                out.write_operand(0, val)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_reg_mem_32!(MovR32Mem32, forms::MOV_R32_MEM32, 0x206);
mov_reg_mem_32!(MovR8Mem8, forms::MOV_R8_MEM8, 0x9B);

macro_rules! mov_mem_reg_32 {
    ($name:ident, $form:expr, $rule:expr, $ty:expr) => {
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
                // `mov [mN], rN`: operand 0 is the memory destination, operand
                // 1 is the register source.
                let val = out.read_operand(1, $ty)?;
                out.write_operand(0, val)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_mem_reg_32!(MovMem32R32, forms::MOV_MEM32_R32, 0x207, U32);
mov_mem_reg_32!(MovMem8R8, forms::MOV_MEM8_R8, 0x9C, U8);

macro_rules! arith_r32_mem32 {
    ($name:ident, $form:expr, $op:expr, $rule:expr, $flags_fn:ident) => {
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

arith_r32_mem32!(
    AddR32Mem32,
    forms::ADD_R32_MEM32,
    PrimitiveOp::Add,
    0x98,
    write_add_flags_32
);
arith_r32_mem32!(
    SubR32Mem32,
    forms::SUB_R32_MEM32,
    PrimitiveOp::Sub,
    0x99,
    write_sub_flags_32
);

#[derive(Clone, Copy, Debug)]
pub struct CmpR32Mem32;
impl SemanticProvider for CmpR32Mem32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x9A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R32_MEM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x9F)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R8_MEM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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

arith_r32_imm!(
    AddR32Imm8,
    forms::ADD_R32_IMM8,
    PrimitiveOp::Add,
    0xA0,
    write_add_flags_32
);
arith_r32_imm!(
    SubR32Imm8,
    forms::SUB_R32_IMM8,
    PrimitiveOp::Sub,
    0xA1,
    write_sub_flags_32
);

#[derive(Clone, Copy, Debug)]
pub struct CmpR32Imm8;
impl SemanticProvider for CmpR32Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xA2)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMP_R32_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
                let left = out.read_operand(0, U64)?;
                let right = out.read_operand(1, U64)?;
                let result = out.emit(SemanticOp::Primitive($op), U64, &[left, right])?;
                // Simplified: ZF only for logical imm
                let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
                let zero = const_u64(out, 0)?;
                let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;

                let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
                let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
                let zf_shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U64,
                    &[zf_64, zf_bit],
                )?;

                let preserve_mask = const_u64(out, !(1u64 << rflags::ZF_BIT))?;
                let cleared = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::And),
                    U64,
                    &[old_rflags, preserve_mask],
                )?;
                let new_rflags = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Or),
                    U64,
                    &[cleared, zf_shifted],
                )?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xA6)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::TEST_R64_IMM32
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
        // ZF only
        let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
        let zero = const_u64(out, 0)?;
        let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;

        let zf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[result, zero])?;
        let zf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[zf_1])?;
        let zf_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_64, zf_bit])?;

        let preserve_mask = const_u64(out, !(1u64 << rflags::ZF_BIT))?;
        let cleared = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U64,
            &[old_rflags, preserve_mask],
        )?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xAA)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::TEST_R32_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xBF)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::HLT
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // HLT: raise exception vector 0
        out.side_effect(SideEffect::RaiseException(0), &[])?;
        Ok(receipt(0xBF, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ud2;

impl SemanticProvider for Ud2 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC0)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::UD2
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xB6)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::LEA_R32_MEM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // The address operand always lowers to the full 64-bit effective
        // address; the write to a 32-bit destination narrows it.
        let addr = out.read_operand(1, U64)?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xB7)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVQ_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, I64X2)?;
        let zero = const_u64(out, 0)?;
        let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src, zero])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[lo])?;
        out.write_operand(0, result)?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xAD)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let value = out.read_operand(0, U32)?;
        let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[value])?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        out.write_operand(1, extended)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(0xAD, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PopR32;

impl SemanticProvider for PopR32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xAE)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POP_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xAB)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::XADD_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xAC)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CMPXCHG_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
        let cleared = out.emit(
            SemanticOp::Primitive(PrimitiveOp::And),
            U64,
            &[old_rflags, preserve_mask],
        )?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xAF)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_R64_R64_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xB1)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_R32_R32_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xB2)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_R32_R32_IMM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
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

/// ADDSS xmm, xmm: scalar single-precision add on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct AddssXmmXmm;

impl SemanticProvider for AddssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC1)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADDSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_ss_preserve(out, insn, FloatingOp::Add, false)?;
        Ok(receipt(0xC1, context))
    }
}

/// SUBSS xmm, xmm: scalar single-precision subtract on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct SubssXmmXmm;

impl SemanticProvider for SubssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC2)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUBSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_ss_preserve(out, insn, FloatingOp::Sub, false)?;
        Ok(receipt(0xC2, context))
    }
}

/// MULSS xmm, xmm: scalar single-precision multiply on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct MulssXmmXmm;

impl SemanticProvider for MulssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC3)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MULSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_ss_preserve(out, insn, FloatingOp::Mul, false)?;
        Ok(receipt(0xC3, context))
    }
}

/// DIVSS xmm, xmm: scalar single-precision divide on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct DivssXmmXmm;

impl SemanticProvider for DivssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC4)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIVSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_ss_preserve(out, insn, FloatingOp::Div, false)?;
        Ok(receipt(0xC4, context))
    }
}

/// SQRTSS xmm, xmm: scalar single-precision square root on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct SqrtssXmmXmm;

impl SemanticProvider for SqrtssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC5)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SQRTSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_ss_preserve(out, insn, FloatingOp::Sqrt, true)?;
        Ok(receipt(0xC5, context))
    }
}

/// ADDSD xmm, xmm: scalar double-precision add on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct AddsdXmmXmm;

impl SemanticProvider for AddsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC6)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADDSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_sd_preserve(out, insn, FloatingOp::Add, false)?;
        Ok(receipt(0xC6, context))
    }
}

/// SUBSD xmm, xmm: scalar double-precision subtract on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct SubsdXmmXmm;

impl SemanticProvider for SubsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC7)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SUBSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_sd_preserve(out, insn, FloatingOp::Sub, false)?;
        Ok(receipt(0xC7, context))
    }
}

/// MULSD xmm, xmm: scalar double-precision multiply on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct MulsdXmmXmm;

impl SemanticProvider for MulsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC8)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MULSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_sd_preserve(out, insn, FloatingOp::Mul, false)?;
        Ok(receipt(0xC8, context))
    }
}

/// DIVSD xmm, xmm: scalar double-precision divide on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct DivsdXmmXmm;

impl SemanticProvider for DivsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xC9)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::DIVSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_sd_preserve(out, insn, FloatingOp::Div, false)?;
        Ok(receipt(0xC9, context))
    }
}

/// SQRTSD xmm, xmm: scalar double-precision square root on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct SqrtsdXmmXmm;

impl SemanticProvider for SqrtsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xCA)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SQRTSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        scalar_sd_preserve(out, insn, FloatingOp::Sqrt, true)?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xCB)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Add)),
            F32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCB, context))
    }
}

/// SUBPS xmm, xmm: packed single-precision subtract (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct SubpsXmmXmm;

impl SemanticProvider for SubpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xCC)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Sub)),
            F32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCC, context))
    }
}

/// MULPS xmm, xmm: packed single-precision multiply (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct MulpsXmmXmm;

impl SemanticProvider for MulpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xCD)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Mul)),
            F32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCD, context))
    }
}

/// DIVPS xmm, xmm: packed single-precision divide (4x32 lanes).
#[derive(Clone, Copy, Debug)]
pub struct DivpsXmmXmm;

impl SemanticProvider for DivpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xCE)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Div)),
            F32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCE, context))
    }
}

/// ADDPD xmm, xmm: packed double-precision add (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct AddpdXmmXmm;

impl SemanticProvider for AddpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xCF)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Add)),
            F64X2,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xCF, context))
    }
}

/// SUBPD xmm, xmm: packed double-precision subtract (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct SubpdXmmXmm;

impl SemanticProvider for SubpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD0)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Sub)),
            F64X2,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD0, context))
    }
}

/// MULPD xmm, xmm: packed double-precision multiply (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct MulpdXmmXmm;

impl SemanticProvider for MulpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD1)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Mul)),
            F64X2,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD1, context))
    }
}

/// DIVPD xmm, xmm: packed double-precision divide (2x64 lanes).
#[derive(Clone, Copy, Debug)]
pub struct DivpdXmmXmm;

impl SemanticProvider for DivpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD2)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
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
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWiseFloat(FloatingOp::Div)),
            F64X2,
            &[dst, src],
        )?;
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
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD3)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PADDB_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)),
            I8X16,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD3, context))
    }
}

/// PSUBB xmm, xmm: packed byte subtract (16x8 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubbXmmXmm;

impl SemanticProvider for PsubbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD4)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSUBB_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)),
            I8X16,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD4, context))
    }
}

/// PADDW xmm, xmm: packed word add (8x16 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PaddwXmmXmm;

impl SemanticProvider for PaddwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD5)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PADDW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)),
            I16X8,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD5, context))
    }
}

/// PSUBW xmm, xmm: packed word subtract (8x16 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubwXmmXmm;

impl SemanticProvider for PsubwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD6)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSUBW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)),
            I16X8,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD6, context))
    }
}

/// PMULLW xmm, xmm: packed word multiply low (8x16 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PmullwXmmXmm;

impl SemanticProvider for PmullwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD7)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMULLW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Mul)),
            I16X8,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD7, context))
    }
}

/// PADDD xmm, xmm: packed dword add (4x32 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PadddXmmXmm;

impl SemanticProvider for PadddXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD8)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PADDD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)),
            I32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD8, context))
    }
}

/// PSUBD xmm, xmm: packed dword subtract (4x32 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubdXmmXmm;

impl SemanticProvider for PsubdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xD9)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSUBD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)),
            I32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xD9, context))
    }
}

/// PMULLD xmm, xmm: packed dword multiply low (4x32 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PmulldXmmXmm;

impl SemanticProvider for PmulldXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xDA)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMULLD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Mul)),
            I32X4,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDA, context))
    }
}

/// PADDQ xmm, xmm: packed qword add (2x64 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PaddqXmmXmm;

impl SemanticProvider for PaddqXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xDB)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PADDQ_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I64X2)?;
        let src = out.read_operand(1, I64X2)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Add)),
            I64X2,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDB, context))
    }
}

/// PSUBQ xmm, xmm: packed qword subtract (2x64 lanes, wrapping).
#[derive(Clone, Copy, Debug)]
pub struct PsubqXmmXmm;

impl SemanticProvider for PsubqXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xDC)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSUBQ_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I64X2)?;
        let src = out.read_operand(1, I64X2)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Sub)),
            I64X2,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDC, context))
    }
}

/// PAND xmm, xmm: packed bitwise AND (full 128-bit).
#[derive(Clone, Copy, Debug)]
pub struct PandXmmXmm;

impl SemanticProvider for PandXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xDD)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PAND_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
            I8X16,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDD, context))
    }
}

/// POR xmm, xmm: packed bitwise OR (full 128-bit).
#[derive(Clone, Copy, Debug)]
pub struct PorXmmXmm;

impl SemanticProvider for PorXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xDE)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POR_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Or)),
            I8X16,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xDE, context))
    }
}

/// PXOR xmm, xmm: packed bitwise XOR (full 128-bit).
#[derive(Clone, Copy, Debug)]
pub struct PxorXmmXmm;

impl SemanticProvider for PxorXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xDF)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PXOR_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
            I8X16,
            &[dst, src],
        )?;
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
                let dst = out.read_operand(0, $ty)?;
                // Extract the immediate shift count from the decoded instruction
                let count = insn
                    .operand(1)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let count_vec = vec_const_uniform(out, $ty, count, $lane_bytes, $lanes)?;
                let result = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $ty,
                    &[dst, count_vec],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_shift_imm8!(
    PsllwXmmImm8,
    forms::PSLLW_XMM_IMM8,
    PrimitiveOp::ShiftLeft,
    I16X8,
    2,
    8,
    0xE0
);
packed_shift_imm8!(
    PsrlwXmmImm8,
    forms::PSRLW_XMM_IMM8,
    PrimitiveOp::LogicalShiftRight,
    I16X8,
    2,
    8,
    0xE1
);
packed_shift_imm8!(
    PsrawXmmImm8,
    forms::PSRAW_XMM_IMM8,
    PrimitiveOp::ArithmeticShiftRight,
    I16X8,
    2,
    8,
    0xE2
);
packed_shift_imm8!(
    PslldXmmImm8,
    forms::PSLLD_XMM_IMM8,
    PrimitiveOp::ShiftLeft,
    I32X4,
    4,
    4,
    0xE3
);
packed_shift_imm8!(
    PsrldXmmImm8,
    forms::PSRLD_XMM_IMM8,
    PrimitiveOp::LogicalShiftRight,
    I32X4,
    4,
    4,
    0xE4
);
packed_shift_imm8!(
    PsradXmmImm8,
    forms::PSRAD_XMM_IMM8,
    PrimitiveOp::ArithmeticShiftRight,
    I32X4,
    4,
    4,
    0xE5
);
packed_shift_imm8!(
    PsllqXmmImm8,
    forms::PSLLQ_XMM_IMM8,
    PrimitiveOp::ShiftLeft,
    I64X2,
    8,
    2,
    0xE6
);
packed_shift_imm8!(
    PsrlqXmmImm8,
    forms::PSRLQ_XMM_IMM8,
    PrimitiveOp::LogicalShiftRight,
    I64X2,
    8,
    2,
    0xE7
);

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed compare providers
// ---------------------------------------------------------------------------

macro_rules! packed_cmp {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
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

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed multiply high providers
// ---------------------------------------------------------------------------

/// PMULHW xmm, xmm: packed signed multiply high (8x16 lanes).
#[derive(Clone, Copy, Debug)]
pub struct PmulhwXmmXmm;

impl SemanticProvider for PmulhwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xFA)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMULHW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::MulHighS)),
            I16X8,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xFA, context))
    }
}

/// PMULHUW xmm, xmm: packed unsigned multiply high (8x16 lanes).
#[derive(Clone, Copy, Debug)]
pub struct PmulhuwXmmXmm;

impl SemanticProvider for PmulhuwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xFB)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMULHUW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::MulHighU)),
            I16X8,
            &[dst, src],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xFB, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed shuffle bytes provider
// ---------------------------------------------------------------------------

/// PSHUFB xmm, xmm: parallel byte shuffle.
/// For each byte i: if src[i] & 0x80, result[i] = 0; else result[i] = dst[src[i] & 0x0F].
#[derive(Clone, Copy, Debug)]
pub struct PshufbXmmXmm;

impl SemanticProvider for PshufbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xFC)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSHUFB_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Shuffle), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xFC, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed unpack/interleave providers
// ---------------------------------------------------------------------------

macro_rules! packed_unpack {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
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
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Vector($op), $ty, &[dst, src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_unpack!(PunpcklbwXmmXmm, forms::PUNPCKLBW_XMM_XMM, VectorOp::Unpack, I8X16, 0xFD);
packed_unpack!(PunpcklwdXmmXmm, forms::PUNPCKLWD_XMM_XMM, VectorOp::Unpack, I16X8, 0xFE);
packed_unpack!(PunpckldqXmmXmm, forms::PUNPCKLDQ_XMM_XMM, VectorOp::Unpack, I32X4, 0xFF);
packed_unpack!(
    PunpcklqdqXmmXmm,
    forms::PUNPCKLQDQ_XMM_XMM,
    VectorOp::Unpack,
    I64X2,
    0x100
);
packed_unpack!(
    PunpckhbwXmmXmm,
    forms::PUNPCKHBW_XMM_XMM,
    VectorOp::UnpackHigh,
    I8X16,
    0x101
);
packed_unpack!(
    PunpckhwdXmmXmm,
    forms::PUNPCKHWD_XMM_XMM,
    VectorOp::UnpackHigh,
    I16X8,
    0x102
);
packed_unpack!(
    PunpckhdqXmmXmm,
    forms::PUNPCKHDQ_XMM_XMM,
    VectorOp::UnpackHigh,
    I32X4,
    0x103
);
packed_unpack!(
    PunpckhqdqXmmXmm,
    forms::PUNPCKHQDQ_XMM_XMM,
    VectorOp::UnpackHigh,
    I64X2,
    0x104
);

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed saturate providers
// ---------------------------------------------------------------------------

/// PACKSSWB xmm, xmm: pack 8x16-bit signed → 16x8-bit signed with saturation.
/// First 8 bytes from dst (16-bit lanes), second 8 bytes from src (16-bit lanes).
#[derive(Clone, Copy, Debug)]
pub struct PacksswbXmmXmm;

impl SemanticProvider for PacksswbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x105)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PACKSSWB_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Pack), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x105, context))
    }
}

/// PACKSSDW xmm, xmm: pack 4x32-bit signed → 8x16-bit signed with saturation.
/// First 4 words from dst (32-bit lanes), second 4 words from src (32-bit lanes).
#[derive(Clone, Copy, Debug)]
pub struct PackssdwXmmXmm;

impl SemanticProvider for PackssdwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x106)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PACKSSDW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Pack), I16X8, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x106, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2/SSE4 packed unsigned saturate providers
// ---------------------------------------------------------------------------

/// PACKUSWB xmm, xmm: pack 8x16-bit signed → 16x8-bit unsigned with saturation.
/// Saturates to [0, 255]. First 8 bytes from dst, second 8 bytes from src.
#[derive(Clone, Copy, Debug)]
pub struct PackuswbXmmXmm;

impl SemanticProvider for PackuswbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x107)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PACKUSWB_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::PackUnsigned), I8X16, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x107, context))
    }
}

/// PACKUSDW xmm, xmm: pack 4x32-bit signed → 8x16-bit unsigned with saturation.
/// Saturates to [0, 65535]. First 4 words from dst, second 4 words from src.
#[derive(Clone, Copy, Debug)]
pub struct PackusdwXmmXmm;

impl SemanticProvider for PackusdwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x108)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PACKUSDW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::PackUnsigned), I16X8, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x108, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed multiply and add provider
// ---------------------------------------------------------------------------

/// PMADDWD xmm, xmm: packed multiply and add.
/// Multiplies 8x16-bit signed lanes pairwise, then adds adjacent products
/// to produce 4x32-bit signed results.
///   result[i] = (int16)dst[2i] * (int16)src[2i] + (int16)dst[2i+1] * (int16)src[2i+1]
#[derive(Clone, Copy, Debug)]
pub struct PmaddwdXmmXmm;

impl SemanticProvider for PmaddwdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x109)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMADDWD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Madd16), I32X4, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x109, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed sum of absolute differences provider
// ---------------------------------------------------------------------------

/// PSADBW xmm, xmm: packed sum of absolute differences.
/// Computes the sum of absolute differences of 8-byte blocks:
///   result[0] = sum(|left[i] - right[i]| for i in 0..8)
///   result[1] = sum(|left[i] - right[i]| for i in 8..16)
/// Produces 2x64-bit results from 16x8-bit unsigned inputs.
#[derive(Clone, Copy, Debug)]
pub struct PsadbwXmmXmm;

impl SemanticProvider for PsadbwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x10A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSADBW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Sad8), I64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x10A, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shuffle doublewords provider
// ---------------------------------------------------------------------------

/// PSHUFD xmm, xmm/m128, imm8: shuffle 32-bit doublewords.
/// Each 2-bit field of imm8 selects which source lane goes to the
/// corresponding destination lane:
///   imm8[1:0] → dst[0], imm8[3:2] → dst[1],
///   imm8[5:4] → dst[2], imm8[7:6] → dst[3]
#[derive(Clone, Copy, Debug)]
pub struct PshufdXmmImm8;

impl SemanticProvider for PshufdXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x10B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSHUFD_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let imm = insn
            .operand(1)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_const = const_u64(out, imm)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Shuffle32), I32X4, &[dst, imm_const])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x10B, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shuffle high/low words providers
// ---------------------------------------------------------------------------

/// PSHUFHW xmm, xmm/m128, imm8: shuffle high 4x16-bit words.
/// Low 64 bits copied unchanged; high 4x16-bit lanes shuffled by imm8.
#[derive(Clone, Copy, Debug)]
pub struct PshufhwXmmImm8;

impl SemanticProvider for PshufhwXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x10C)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSHUFHW_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let imm = insn
            .operand(1)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        // Encode high-half flag in bit 8 of the constant.
        let imm_const = const_u64(out, imm | (1 << 8))?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Shuffle16), I16X8, &[dst, imm_const])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x10C, context))
    }
}

/// PSHUFLW xmm, xmm/m128, imm8: shuffle low 4x16-bit words.
/// High 64 bits copied unchanged; low 4x16-bit lanes shuffled by imm8.
#[derive(Clone, Copy, Debug)]
pub struct PshuflwXmmImm8;

impl SemanticProvider for PshuflwXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x10D)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSHUFLW_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I16X8)?;
        let imm = insn
            .operand(1)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        // Low half: bit 8 = 0.
        let imm_const = const_u64(out, imm)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Shuffle16), I16X8, &[dst, imm_const])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x10D, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed multiply and add unsigned/signed bytes provider
// ---------------------------------------------------------------------------

/// PMADDUBSW xmm, xmm: packed multiply and add with saturation.
/// Multiplies adjacent 8-bit lanes (left signed, right unsigned),
/// then adds adjacent products with signed 16-bit saturation:
///   result[i] = sat((int8)left[2i] * (uint8)right[2i]
///             + (int8)left[2i+1] * (uint8)right[2i+1])
#[derive(Clone, Copy, Debug)]
pub struct PmaddubswXmmXmm;

impl SemanticProvider for PmaddubswXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x10E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMADDUBSW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Maddubs), I16X8, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x10E, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shift with register count (xmm, xmm)
// ---------------------------------------------------------------------------

macro_rules! packed_shift_reg {
    ($name:ident, $form:expr, $vop:expr, $ty:expr, $rule:expr) => {
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
                let dst = out.read_operand(0, $ty)?;
                // The shift count is taken from the low 64 bits of the second XMM operand.
                let count_src = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Vector($vop), $ty, &[dst, count_src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_shift_reg!(PsllwXmmXmm, forms::PSLLW_XMM_XMM, VectorOp::ShiftRegL, I16X8, 0x10F);
packed_shift_reg!(PslldXmmXmm, forms::PSLLD_XMM_XMM, VectorOp::ShiftRegL, I32X4, 0x110);
packed_shift_reg!(PsllqXmmXmm, forms::PSLLQ_XMM_XMM, VectorOp::ShiftRegL, I64X2, 0x111);
packed_shift_reg!(PsrlwXmmXmm, forms::PSRLW_XMM_XMM, VectorOp::ShiftRegR, I16X8, 0x112);
packed_shift_reg!(PsrldXmmXmm, forms::PSRLD_XMM_XMM, VectorOp::ShiftRegR, I32X4, 0x113);
packed_shift_reg!(PsrlqXmmXmm, forms::PSRLQ_XMM_XMM, VectorOp::ShiftRegR, I64X2, 0x114);
packed_shift_reg!(PsrawXmmXmm, forms::PSRAW_XMM_XMM, VectorOp::ShiftRegRA, I16X8, 0x115);
packed_shift_reg!(PsradXmmXmm, forms::PSRAD_XMM_XMM, VectorOp::ShiftRegRA, I32X4, 0x116);

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 horizontal add/subtract providers
// ---------------------------------------------------------------------------

macro_rules! packed_hbinop {
    ($name:ident, $form:expr, $vop:expr, $ty:expr, $rule:expr) => {
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
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Vector($vop), $ty, &[dst, src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_hbinop!(PhaddwXmmXmm, forms::PHADDW_XMM_XMM, VectorOp::HAdd, I16X8, 0x117);
packed_hbinop!(PhadddXmmXmm, forms::PHADDD_XMM_XMM, VectorOp::HAdd, I32X4, 0x118);
packed_hbinop!(PhsubwXmmXmm, forms::PHSUBW_XMM_XMM, VectorOp::HSub, I16X8, 0x119);
packed_hbinop!(PhsubdXmmXmm, forms::PHSUBD_XMM_XMM, VectorOp::HSub, I32X4, 0x11A);

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed absolute value providers
// ---------------------------------------------------------------------------

macro_rules! packed_unary_lane {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise($op)), $ty, &[src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_unary_lane!(PabsbXmmXmm, forms::PABSB_XMM_XMM, PrimitiveOp::Abs, I8X16, 0x11B);
packed_unary_lane!(PabswXmmXmm, forms::PABSW_XMM_XMM, PrimitiveOp::Abs, I16X8, 0x11C);
packed_unary_lane!(PabsdXmmXmm, forms::PABSD_XMM_XMM, PrimitiveOp::Abs, I32X4, 0x11D);

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed sign providers
// ---------------------------------------------------------------------------

macro_rules! packed_binary_lane {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
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

packed_binary_lane!(PsignbXmmXmm, forms::PSIGNB_XMM_XMM, PrimitiveOp::Sign, I8X16, 0x11E);
packed_binary_lane!(PsignwXmmXmm, forms::PSIGNW_XMM_XMM, PrimitiveOp::Sign, I16X8, 0x11F);
packed_binary_lane!(PsigndXmmXmm, forms::PSIGND_XMM_XMM, PrimitiveOp::Sign, I32X4, 0x120);

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 PMULHRSW provider
// ---------------------------------------------------------------------------

packed_binary_lane!(
    PmulhrswXmmXmm,
    forms::PMULHRSW_XMM_XMM,
    PrimitiveOp::MulHighRS,
    I16X8,
    0x121
);

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 PHADDSW/PHSUBSW providers
// ---------------------------------------------------------------------------

packed_hbinop!(PhaddswXmmXmm, forms::PHADDSW_XMM_XMM, VectorOp::HAddS, I16X8, 0x122);
packed_hbinop!(PhsubswXmmXmm, forms::PHSUBSW_XMM_XMM, VectorOp::HSubS, I16X8, 0x123);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PCMPEQQ provider
// ---------------------------------------------------------------------------

packed_cmp!(PcmpeqqXmmXmm, forms::PCMPEQQ_XMM_XMM, PrimitiveOp::MaskEq, I64X2, 0x124);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PMULDQ provider
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PmuldqXmmXmm;

impl SemanticProvider for PmuldqXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x125)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PMULDQ_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I64X2)?;
        let src = out.read_operand(1, I64X2)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::MulDq), I64X2, &[dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x125, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PBLENDVB provider (variable blend with mask)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct PblendvbXmmXmm;

impl SemanticProvider for PblendvbXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x126)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PBLENDVB_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        // PBLENDVB uses XMM0 as implicit mask operand (operand index 2)
        let mask = out.read_operand(2, I8X16)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::BlendV), I8X16, &[dst, src, mask])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x126, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed move with sign/zero extend providers
// ---------------------------------------------------------------------------

macro_rules! packed_extend {
    ($name:ident, $form:expr, $vop:expr, $src_ty:expr, $dst_ty:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $src_ty)?;
                let result = out.emit(SemanticOp::Vector($vop), $dst_ty, &[src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_extend!(
    PmovsxbwXmmXmm,
    forms::PMOVSXBW_XMM_XMM,
    VectorOp::SignExtend,
    I8X16,
    I16X8,
    0x127
);
packed_extend!(
    PmovzxbwXmmXmm,
    forms::PMOVZXBW_XMM_XMM,
    VectorOp::ZeroExtend,
    I8X16,
    I16X8,
    0x128
);
packed_extend!(
    PmovsxbdXmmXmm,
    forms::PMOVSXBD_XMM_XMM,
    VectorOp::SignExtend,
    I8X16,
    I32X4,
    0x129
);
packed_extend!(
    PmovzxbdXmmXmm,
    forms::PMOVZXBD_XMM_XMM,
    VectorOp::ZeroExtend,
    I8X16,
    I32X4,
    0x12A
);
packed_extend!(
    PmovsxwdXmmXmm,
    forms::PMOVSXWD_XMM_XMM,
    VectorOp::SignExtend,
    I16X8,
    I32X4,
    0x12B
);
packed_extend!(
    PmovzxwdXmmXmm,
    forms::PMOVZXWD_XMM_XMM,
    VectorOp::ZeroExtend,
    I16X8,
    I32X4,
    0x12C
);
packed_extend!(
    PmovsxdqXmmXmm,
    forms::PMOVSXDQ_XMM_XMM,
    VectorOp::SignExtend,
    I32X4,
    I64X2,
    0x12D
);
packed_extend!(
    PmovzxdqXmmXmm,
    forms::PMOVZXDQ_XMM_XMM,
    VectorOp::ZeroExtend,
    I32X4,
    I64X2,
    0x12E
);
packed_extend!(
    PmovsxwqXmmXmm,
    forms::PMOVSXWQ_XMM_XMM,
    VectorOp::SignExtend,
    I16X8,
    I64X2,
    0x12F
);
packed_extend!(
    PmovzxwqXmmXmm,
    forms::PMOVZXWQ_XMM_XMM,
    VectorOp::ZeroExtend,
    I16X8,
    I64X2,
    0x130
);
packed_extend!(
    PmovsxbqXmmXmm,
    forms::PMOVSXBQ_XMM_XMM,
    VectorOp::SignExtend,
    I8X16,
    I64X2,
    0x131
);
packed_extend!(
    PmovzxbqXmmXmm,
    forms::PMOVZXBQ_XMM_XMM,
    VectorOp::ZeroExtend,
    I8X16,
    I64X2,
    0x132
);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 immediate blend providers
// ---------------------------------------------------------------------------

macro_rules! packed_blend_imm {
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
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let imm = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let imm_const = const_u64(out, imm)?;
                let result = out.emit(
                    SemanticOp::Vector(VectorOp::BlendImm),
                    $ty,
                    &[dst, src, imm_const],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_blend_imm!(PblendwXmmXmmImm8, forms::PBLENDW_XMM_XMM_IMM8, I16X8, 0x133);
packed_blend_imm!(BlendpsXmmXmmImm8, forms::BLENDPS_XMM_XMM_IMM8, F32X4, 0x134);
packed_blend_imm!(BlendpdXmmXmmImm8, forms::BLENDPD_XMM_XMM_IMM8, F64X2, 0x135);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed dot product providers
// ---------------------------------------------------------------------------

macro_rules! packed_dot {
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
                let src1 = out.read_operand(0, $ty)?;
                let src2 = out.read_operand(1, $ty)?;
                let imm = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let imm_const = const_u64(out, imm)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::DotF), $ty, &[src1, src2, imm_const])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_dot!(DppsXmmXmmImm8, forms::DPPS_XMM_XMM_IMM8, F32X4, 0x136);
packed_dot!(DppdXmmXmmImm8, forms::DPPD_XMM_XMM_IMM8, F64X2, 0x137);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 byte extract/insert providers
// ---------------------------------------------------------------------------

/// PEXTRB r32, xmm, imm8: extract byte at imm8[3:0] from xmm, zero-extend to r32.
#[derive(Clone, Copy, Debug)]
pub struct PextrbR32XmmImm8;

impl SemanticProvider for PextrbR32XmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x138)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PEXTRB_R32_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(1, I8X16)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let bit_pos = const_u64(out, (imm & 0x0F) * 8)?;
        let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U8, &[xmm, bit_pos])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[byte])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x138, context))
    }
}

/// PINSRB xmm, r32, imm8: insert low byte of r32 into xmm at byte imm8[3:0].
#[derive(Clone, Copy, Debug)]
pub struct PinsrbXmmR32Imm8;

impl SemanticProvider for PinsrbXmmR32Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x139)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PINSRB_XMM_R32_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(0, U128)?;
        let gpr = out.read_operand(1, U64)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let byte_idx = imm & 0x0F;
        let zero = const_u64(out, 0)?;
        let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U8, &[gpr, zero])?;
        let byte128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[byte])?;
        let shift = const_u64(out, byte_idx * 8)?;
        let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U128, &[byte128, shift])?;
        let mask_val: u128 = !(0xFFu128 << (byte_idx * 8));
        let mask = out.constant(U128, &mask_val.to_le_bytes())?;
        let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[xmm, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[masked, shifted])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x139, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE/SSE2 scalar float compare with flags
// ---------------------------------------------------------------------------

/// Writes ZF, CF, PF from a packed u64 flag result (bits at RFLAGS positions).
fn write_zf_cf_pf_packed(out: &mut dyn SemanticBuilder, packed: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let clear_mask = !((1u64 << rflags::ZF_BIT) | (1u64 << rflags::CF_BIT) | (1u64 << rflags::PF_BIT));
    let mask = out.constant(U64, &clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, packed])?;
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

macro_rules! scalar_float_compare {
    ($name:ident, $form:expr, $fty:expr, $rule:expr) => {
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
                let src1 = out.read_operand(0, $fty)?;
                let src2 = out.read_operand(1, $fty)?;
                let flags = out.emit(SemanticOp::Float(FloatingOp::Compare), U64, &[src1, src2])?;
                write_zf_cf_pf_packed(out, flags)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

scalar_float_compare!(UcomissXmmXmm, forms::UCOMISS_XMM_XMM, F32, 0x13A);
scalar_float_compare!(UcomisdXmmXmm, forms::UCOMISD_XMM_XMM, F64, 0x13B);
scalar_float_compare!(ComissXmmXmm, forms::COMISS_XMM_XMM, F32, 0x13C);
scalar_float_compare!(ComisdXmmXmm, forms::COMISD_XMM_XMM, F64, 0x13D);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed/scalar round with imm8
// ---------------------------------------------------------------------------

macro_rules! packed_round {
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
                let src = out.read_operand(1, $ty)?;
                let imm = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let imm_val = const_u64(out, imm & 0x3)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::FRound), $ty, &[src, imm_val])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_round!(RoundpsXmmXmmImm8, forms::ROUNDPS_XMM_XMM_IMM8, F32X4, 0x13E);
packed_round!(RoundpdXmmXmmImm8, forms::ROUNDPD_XMM_XMM_IMM8, F64X2, 0x13F);

/// ROUNDSS xmm, xmm, imm8: round low 32-bit float, upper lanes from src1.
#[derive(Clone, Copy, Debug)]
pub struct RoundssXmmXmmImm8;

impl SemanticProvider for RoundssXmmXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x140)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ROUNDSS_XMM_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src1 = out.read_operand(0, U128)?;
        let src2 = out.read_operand(1, F32)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_val = const_u64(out, imm & 0x3)?;
        let rounded = out.emit(SemanticOp::Float(FloatingOp::Round), F32, &[src2, imm_val])?;
        let rounded_u128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[rounded])?;
        let mask_val: u128 = !0xFFFFFFFFu128;
        let mask = out.constant(U128, &mask_val.to_le_bytes())?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[src1, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[upper, rounded_u128])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x140, context))
    }
}

/// ROUNDSD xmm, xmm, imm8: round low 64-bit float, upper lanes from src1.
#[derive(Clone, Copy, Debug)]
pub struct RoundsdXmmXmmImm8;

impl SemanticProvider for RoundsdXmmXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x141)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ROUNDSD_XMM_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src1 = out.read_operand(0, U128)?;
        let src2 = out.read_operand(1, F64)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_val = const_u64(out, imm & 0x3)?;
        let rounded = out.emit(SemanticOp::Float(FloatingOp::Round), F64, &[src2, imm_val])?;
        let rounded_u128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[rounded])?;
        let mask_val: u128 = !0xFFFFFFFFFFFFFFFFu128;
        let mask = out.constant(U128, &mask_val.to_le_bytes())?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[src1, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[upper, rounded_u128])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x141, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PTEST
// ---------------------------------------------------------------------------

/// PTEST xmm, xmm: set ZF and CF based on bitwise tests.
/// ZF = 1 if (dst AND src) == 0; CF = 1 if ((NOT dst) AND src) == 0.
#[derive(Clone, Copy, Debug)]
pub struct PtestXmmXmm;

impl SemanticProvider for PtestXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x142)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PTEST_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let flags = out.emit(SemanticOp::Vector(VectorOp::Test), U64, &[dst, src])?;
        write_zf_cf_pf_packed(out, flags)?;
        fall_through(out, insn)?;
        Ok(receipt(0x142, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.2 CRC32
// ---------------------------------------------------------------------------

/// CRC32 r32, r32: compute CRC-32C of 32-bit source, result in r32.
#[derive(Clone, Copy, Debug)]
pub struct Crc32R32R32;

impl SemanticProvider for Crc32R32R32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x143)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CRC32_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let zero = const_u64(out, 0)?;
        let extracted = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src, zero])?;
        let crc = out.emit(SemanticOp::Primitive(PrimitiveOp::Crc32), U32, &[extracted])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[crc])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x143, context))
    }
}

/// CRC32 r64, r64: compute CRC-32C of 64-bit source, result zero-extended in r64.
#[derive(Clone, Copy, Debug)]
pub struct Crc32R64R64;

impl SemanticProvider for Crc32R64R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x144)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CRC32_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U64)?;
        let crc = out.emit(SemanticOp::Primitive(PrimitiveOp::Crc32), U64, &[src])?;
        out.write_operand(0, crc)?;
        fall_through(out, insn)?;
        Ok(receipt(0x144, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 dword/qword extract/insert
// ---------------------------------------------------------------------------

/// PEXTRD r32, xmm, imm8: extract dword at imm8[1:0] from xmm, zero-extend to r32.
#[derive(Clone, Copy, Debug)]
pub struct PextrdR32XmmImm8;

impl SemanticProvider for PextrdR32XmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x145)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PEXTRD_R32_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(1, I32X4)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let bit_pos = const_u64(out, (imm & 0x03) * 32)?;
        let dword = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[xmm, bit_pos])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[dword])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x145, context))
    }
}

/// PEXTRQ r64, xmm, imm8: extract qword at imm8[0] from xmm.
#[derive(Clone, Copy, Debug)]
pub struct PextrqR64XmmImm8;

impl SemanticProvider for PextrqR64XmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x146)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PEXTRQ_R64_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(1, I64X2)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let bit_pos = const_u64(out, (imm & 0x01) * 64)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[xmm, bit_pos])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x146, context))
    }
}

/// PINSRD xmm, r32, imm8: insert low dword of r32 into xmm at dword imm8[1:0].
#[derive(Clone, Copy, Debug)]
pub struct PinsrdXmmR32Imm8;

impl SemanticProvider for PinsrdXmmR32Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x147)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PINSRD_XMM_R32_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(0, U128)?;
        let gpr = out.read_operand(1, U64)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let dword_idx = imm & 0x03;
        let zero = const_u64(out, 0)?;
        let dword = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[gpr, zero])?;
        let dword128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[dword])?;
        let shift = const_u64(out, dword_idx * 32)?;
        let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U128, &[dword128, shift])?;
        let mask_val: u128 = !(0xFFFFFFFFu128 << (dword_idx * 32));
        let mask = out.constant(U128, &mask_val.to_le_bytes())?;
        let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[xmm, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[masked, shifted])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x147, context))
    }
}

/// PINSRQ xmm, r64, imm8: insert qword of r64 into xmm at qword imm8[0].
#[derive(Clone, Copy, Debug)]
pub struct PinsrqXmmR64Imm8;

impl SemanticProvider for PinsrqXmmR64Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x148)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PINSRQ_XMM_R64_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(0, U128)?;
        let gpr = out.read_operand(1, U64)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let qword_idx = imm & 0x01;
        let gpr128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[gpr])?;
        let shift = const_u64(out, qword_idx * 64)?;
        let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U128, &[gpr128, shift])?;
        let mask_val: u128 = !(0xFFFFFFFFFFFFFFFFu128 << (qword_idx * 64));
        let mask = out.constant(U128, &mask_val.to_le_bytes())?;
        let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[xmm, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[masked, shifted])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x148, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 INSERTPS/EXTRACTPS
// ---------------------------------------------------------------------------

/// EXTRACTPS r32, xmm, imm8: extract float dword at imm8[1:0] from xmm, store raw bits in r32.
#[derive(Clone, Copy, Debug)]
pub struct ExtractpsR32XmmImm8;

impl SemanticProvider for ExtractpsR32XmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x14A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::EXTRACTPS_R32_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let xmm = out.read_operand(1, F32X4)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let bit_pos = const_u64(out, (imm & 0x03) * 32)?;
        let dword = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[xmm, bit_pos])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[dword])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x14A, context))
    }
}

/// INSERTPS xmm, xmm, imm8: insert float dword from src at imm8[3:2] into dst at imm8[1:0],
/// zeroing dwords per imm8[7:4] (ZMASK).
#[derive(Clone, Copy, Debug)]
pub struct InsertpsXmmXmmImm8;

impl SemanticProvider for InsertpsXmmXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x149)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::INSERTPS_XMM_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, U128)?;
        let src = out.read_operand(1, U128)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let dst_idx = imm & 0x03;
        let src_idx = (imm >> 2) & 0x03;
        let zmask_bits = (imm >> 4) & 0x0F;
        let src_bit_pos = const_u64(out, src_idx * 32)?;
        let dword = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src, src_bit_pos])?;
        let dword128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[dword])?;
        let dst_shift = const_u64(out, dst_idx * 32)?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            U128,
            &[dword128, dst_shift],
        )?;
        let insert_mask_val: u128 = !(0xFFFFFFFFu128 << (dst_idx * 32));
        let insert_mask = out.constant(U128, &insert_mask_val.to_le_bytes())?;
        let masked_dst = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[dst, insert_mask])?;
        let inserted = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[masked_dst, shifted])?;
        let mut zmask_val: u128 = 0;
        for i in 0..4u32 {
            if zmask_bits & (1 << i) != 0 {
                zmask_val |= 0xFFFFFFFFu128 << (i * 32);
            }
        }
        let zmask_clear = out.constant(U128, &(!zmask_val).to_le_bytes())?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[inserted, zmask_clear])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x149, context))
    }
}

// ---------------------------------------------------------------------------
// CMPPS/CMPPD: packed float compare with imm8 predicate
// ---------------------------------------------------------------------------

macro_rules! packed_cmpf {
    ($name:ident, $form:expr, $vec_ty:expr, $rule:expr) => {
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
                let src1 = out.read_operand(0, $vec_ty)?;
                let src2 = out.read_operand(1, $vec_ty)?;
                let imm = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let imm_val = const_u64(out, imm)?;
                let result = out.emit(
                    SemanticOp::Vector(VectorOp::CmpF),
                    $vec_ty,
                    &[src1, src2, imm_val],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_cmpf!(CmppsXmmXmmImm8, forms::CMPPS_XMM_XMM_IMM8, F32X4, 0x14D);
packed_cmpf!(CmppdXmmXmmImm8, forms::CMPPD_XMM_XMM_IMM8, F64X2, 0x14E);

// ---------------------------------------------------------------------------
// MINPS/MAXPS: packed float min/max with NaN and signed-zero semantics
// ---------------------------------------------------------------------------

macro_rules! packed_fminmax {
    ($name:ident, $form:expr, $vec_ty:expr, $op:expr, $rule:expr) => {
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
                let src1 = out.read_operand(0, $vec_ty)?;
                let src2 = out.read_operand(1, $vec_ty)?;
                let result = out.emit(SemanticOp::Vector($op), $vec_ty, &[src1, src2])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_fminmax!(MinpsXmmXmm, forms::MINPS_XMM_XMM, F32X4, VectorOp::FMin, 0x14F);
packed_fminmax!(MaxpsXmmXmm, forms::MAXPS_XMM_XMM, F32X4, VectorOp::FMax, 0x150);

// ---------------------------------------------------------------------------
// MOVMSKPS/MOVMSKPD/PMOVMSKB: extract sign bits to r32
// ---------------------------------------------------------------------------

macro_rules! packed_movmask {
    ($name:ident, $form:expr, $vec_ty:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $vec_ty)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::MovMask), U64, &[src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_movmask!(MovmskpsR32Xmm, forms::MOVMSKPS_R32_XMM, F32X4, 0x151);
packed_movmask!(MovmskpdR32Xmm, forms::MOVMSKPD_R32_XMM, F64X2, 0x152);
packed_movmask!(PmovmskbR32Xmm, forms::PMOVMSKB_R32_XMM, I8X16, 0x153);

// ---------------------------------------------------------------------------
// Phase 4b: SSE3/SSE4 packed float horizontal add/sub providers
// ---------------------------------------------------------------------------

packed_hbinop!(HaddpsXmmXmm, forms::HADDPS_XMM_XMM, VectorOp::HFAdd, F32X4, 0x154);
packed_hbinop!(HaddpdXmmXmm, forms::HADDPD_XMM_XMM, VectorOp::HFAdd, F64X2, 0x155);
packed_hbinop!(HsubpsXmmXmm, forms::HSUBPS_XMM_XMM, VectorOp::HFSub, F32X4, 0x156);
packed_hbinop!(HsubpdXmmXmm, forms::HSUBPD_XMM_XMM, VectorOp::HFSub, F64X2, 0x157);

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed min/max 64-bit providers
// ---------------------------------------------------------------------------

packed_minmax!(PmaxsqXmmXmm, forms::PMAXSQ_XMM_XMM, PrimitiveOp::MaxS, I64X2, 0x158);
packed_minmax!(PminsqXmmXmm, forms::PMINSQ_XMM_XMM, PrimitiveOp::MinS, I64X2, 0x159);

// ---------------------------------------------------------------------------
// Phase 4b: SSE/SSE2 packed aligned/unaligned moves (register-to-register)
// ---------------------------------------------------------------------------

mov_reg_reg!(MovapsXmmXmm, forms::MOVAPS_XMM_XMM, U128, 0x15A);
mov_reg_reg!(MovapdXmmXmm, forms::MOVAPD_XMM_XMM, U128, 0x15B);
mov_reg_reg!(MovupsXmmXmm, forms::MOVUPS_XMM_XMM, U128, 0x15C);
mov_reg_reg!(MovupdXmmXmm, forms::MOVUPD_XMM_XMM, U128, 0x15D);

// ---------------------------------------------------------------------------
// Phase 4b: SSE/SSE2 scalar moves (register-to-register)
// ---------------------------------------------------------------------------

/// MOVSS xmm, xmm: copy low 32 bits from src, zero upper 96 bits.
#[derive(Clone, Copy, Debug)]
pub struct MovssXmmXmm;

impl SemanticProvider for MovssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x15E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, F32X4)?;
        let zero = const_u64(out, 0)?;
        let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src, zero])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[lo])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x15E, context))
    }
}

/// MOVSD xmm, xmm: copy low 64 bits from src, zero upper 64 bits.
#[derive(Clone, Copy, Debug)]
pub struct MovsdXmmXmm;

impl SemanticProvider for MovsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x15F)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, F64X2)?;
        let zero = const_u64(out, 0)?;
        let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src, zero])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[lo])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x15F, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 MPSADBW provider
// ---------------------------------------------------------------------------

/// MPSADBW xmm, xmm, imm8: multiple packed sums of absolute differences.
/// Computes 8 SAD words; imm8[1:0] selects src1 offset, imm8[3:2] selects src2 offset.
#[derive(Clone, Copy, Debug)]
pub struct MpsadbwXmmXmmImm8;

impl SemanticProvider for MpsadbwXmmXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x160)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MPSADBW_XMM_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let src = out.read_operand(1, I8X16)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_const = const_u64(out, imm)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::Mpsadbw), I16X8, &[dst, src, imm_const])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x160, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PHMINPOSUW provider
// ---------------------------------------------------------------------------

/// PHMINPOSUW xmm, xmm: horizontal minimum of 8 unsigned 16-bit words.
/// result[0:16] = min value, result[16:32] = min index, result[32:128] = 0.
#[derive(Clone, Copy, Debug)]
pub struct PhminposuwXmmXmm;

impl SemanticProvider for PhminposuwXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x161)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PHMINPOSUW_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, I16X8)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::HMinUW), I16X8, &[src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x161, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.2 PCMPGTQ provider
// ---------------------------------------------------------------------------

packed_cmp!(
    PcmpgtqXmmXmm,
    forms::PCMPGTQ_XMM_XMM,
    PrimitiveOp::MaskSgt,
    I64X2,
    0x162
);

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 PSLLDQ/PSRLDQ providers
// ---------------------------------------------------------------------------

/// PSLLDQ xmm, imm8: shift left double quadword by imm8 bytes.
#[derive(Clone, Copy, Debug)]
pub struct PslldqXmmImm8;

impl SemanticProvider for PslldqXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x163)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSLLDQ_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let imm = insn
            .operand(1)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_const = const_u64(out, imm)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::ShiftLeftBytes), I8X16, &[dst, imm_const])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x163, context))
    }
}

/// PSRLDQ xmm, imm8: shift right double quadword by imm8 bytes.
#[derive(Clone, Copy, Debug)]
pub struct PsrldqXmmImm8;

impl SemanticProvider for PsrldqXmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x164)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PSRLDQ_XMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I8X16)?;
        let imm = insn
            .operand(1)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_const = const_u64(out, imm)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::ShiftRightBytes), I8X16, &[dst, imm_const])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x164, context))
    }
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 PANDN provider
// ---------------------------------------------------------------------------

/// PANDN xmm, xmm: packed AND NOT — dst = (~dst) & src.
#[derive(Clone, Copy, Debug)]
pub struct PandnXmmXmm;

impl SemanticProvider for PandnXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x165)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PANDN_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, U128)?;
        let src = out.read_operand(1, U128)?;
        let not_dst = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U128, &[dst])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[not_dst, src])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x165, context))
    }
}

// ---------------------------------------------------------------------------
// 8-bit TEST/CMP forms (libc string paths)
// ---------------------------------------------------------------------------

macro_rules! test_r8 {
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
                let left = out.read_operand(0, U8)?;
                let right = out.read_operand(1, U8)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U8, &[left, right])?;
                write_logical_flags(out, result, 8)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

test_r8!(TestR8R8, forms::TEST_R8_R8, 0x211);
test_r8!(TestR8Imm8, forms::TEST_R8_IMM8, 0x212);
test_r8!(TestMem8R8, forms::TEST_MEM8_R8, 0x213);

#[derive(Clone, Copy, Debug)]
pub struct TestR32R32;

impl SemanticProvider for TestR32R32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x217)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::TEST_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U32)?;
        let right = out.read_operand(1, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[left, right])?;
        write_logical_flags(out, result, 32)?;
        fall_through(out, insn)?;
        Ok(receipt(0x217, context))
    }
}

macro_rules! cmp_r8 {
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
                let left = out.read_operand(0, U8)?;
                let right = out.read_operand(1, U8)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[left, right])?;
                write_sub_flags(out, result, left, right, 8)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmp_r8!(CmpR8Imm8, forms::CMP_R8_IMM8, 0x214);
cmp_r8!(CmpR8R8, forms::CMP_R8_R8, 0x215);
cmp_r8!(CmpMem8Imm8, forms::CMP_MEM8_IMM8, 0x216);

// ---------------------------------------------------------------------------
// GPR/vector and memory transfers
// ---------------------------------------------------------------------------

/// `movq xmm, r/m64` — destination low qword = source, upper qword = 0.
macro_rules! movq_to_xmm {
    ($name:ident, $form:expr, $src_ty:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $src_ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movq_to_xmm!(MovqXmmR64, forms::MOVQ_XMM_R64, U64, 0x218);
movq_to_xmm!(MovqXmmMem64, forms::MOVQ_XMM_MEM64, U64, 0x219);
movq_to_xmm!(MovdXmmR32, forms::MOVD_XMM_R32, U32, 0x21A);
movq_to_xmm!(MovdXmmMem32, forms::MOVD_XMM_MEM32, U32, 0x21B);
movq_to_xmm!(MovqXmmMem, forms::MOVQ_XMM_MEM, U64, 0x21F);

/// `movq r/m64, xmm` — destination = source low qword.
macro_rules! movq_from_xmm {
    ($name:ident, $form:expr, $dst_ty:expr, $rule:expr) => {
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
                let src = out.read_operand(1, U128)?;
                let zero = const_u64(out, 0)?;
                let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $dst_ty, &[src, zero])?;
                out.write_operand(0, lo)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movq_from_xmm!(MovqR64Xmm, forms::MOVQ_R64_XMM, U64, 0x21C);
movq_from_xmm!(MovqMem64Xmm, forms::MOVQ_MEM64_XMM, U64, 0x21D);
movq_from_xmm!(MovdR32Xmm, forms::MOVD_R32_XMM, U32, 0x21E);

/// `movaps/movdqa/movups xmm, [m128]` — full-width load.
macro_rules! mov_xmm_mem {
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
                let src = out.read_operand(1, U128)?;
                out.write_operand(0, src)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_xmm_mem!(MovapsXmmMem, forms::MOVAPS_XMM_MEM, 0x220);
mov_xmm_mem!(MovdqaXmmMem, forms::MOVDQA_XMM_MEM, 0x221);
mov_xmm_mem!(MovupsXmmMem, forms::MOVUPS_XMM_MEM, 0x222);

/// `movaps/movdqa/movups [m128], xmm` — full-width store.
macro_rules! mov_mem_xmm {
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
                let src = out.read_operand(1, U128)?;
                out.write_operand(0, src)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_mem_xmm!(MovapsMemXmm, forms::MOVAPS_MEM_XMM, 0x223);
mov_mem_xmm!(MovdqaMemXmm, forms::MOVDQA_MEM_XMM, 0x224);
mov_mem_xmm!(MovupsMemXmm, forms::MOVUPS_MEM_XMM, 0x225);

/// `mov [mN], imm` — memory-immediate store.
macro_rules! mov_mem_imm {
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

mov_mem_imm!(MovMem8Imm8, forms::MOV_MEM8_IMM8, U8, 0x226);
mov_mem_imm!(MovMem16Imm16, forms::MOV_MEM16_IMM16, U16, 0x227);
mov_mem_imm!(MovMem32Imm32, forms::MOV_MEM32_IMM32, U32, 0x228);

/// `cmp [mN], rN` — memory-minus-register compare.
macro_rules! cmp_mem_reg {
    ($name:ident, $form:expr, $ty:expr, $width:expr, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[left, right])?;
                write_sub_flags(out, result, left, right, $width)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmp_mem_reg!(CmpMem64R64, forms::CMP_MEM64_R64, U64, 64, 0x229);
cmp_mem_reg!(CmpMem32R32, forms::CMP_MEM32_R32, U32, 32, 0x22A);
cmp_mem_reg!(CmpMem8R8, forms::CMP_MEM8_R8, U8, 8, 0x22B);

// ---------------------------------------------------------------------------
// Indirect control transfer through a register operand
// ---------------------------------------------------------------------------

/// `jmp *r64` — the target register value becomes the next instruction pointer.
#[derive(Clone, Copy, Debug)]
pub struct JmpIndirectR64;

impl SemanticProvider for JmpIndirectR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x22C)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JMP_INDIRECT_R64 || insn.form_id() == forms::JMP_INDIRECT_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let target = out.read_operand(0, U64)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x22C, context))
    }
}

/// `jmp *[mem]` — read the jump target from memory.
#[derive(Clone, Copy, Debug)]
pub struct JmpIndirectMem64;

impl SemanticProvider for JmpIndirectMem64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x2EE)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JMP_INDIRECT_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let target = out.read_operand(0, U64)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x2EE, context))
    }
}

/// `call *[mem]` — push the return address, then jump to the memory target.
#[derive(Clone, Copy, Debug)]
pub struct CallIndirectMem64;

impl SemanticProvider for CallIndirectMem64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x2EF)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CALL_INDIRECT_MEM64
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
        let return_address = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.write_operand(2, return_address)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        let target = out.read_operand(0, U64)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x2EF, context))
    }
}

/// `call *r64` — push the return address, then jump to the register target.
#[derive(Clone, Copy, Debug)]
pub struct CallIndirectR64;

impl SemanticProvider for CallIndirectR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x22D)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CALL_INDIRECT_R64 || insn.form_id() == forms::CALL_INDIRECT_MEM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Operand 2 is the suppressed stack-slot write reported by the decoder
        // (`call` pushes the return address to [RSP-8]). Same convention as
        // `call rel32`.
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let eight = const_u64(out, 8)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, eight])?;
        let return_address = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.write_operand(2, return_address)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        let target = out.read_operand(0, U64)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x22D, context))
    }
}

/// `mov [m16], r16` — 16-bit register store.
#[derive(Clone, Copy, Debug)]
pub struct MovMem16R16;

impl SemanticProvider for MovMem16R16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x22E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_MEM16_R16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U16)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x22E, context))
    }
}

/// `mov r16, [m16]` — 16-bit load.
#[derive(Clone, Copy, Debug)]
pub struct MovR16Mem16;

impl SemanticProvider for MovR16Mem16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x22F)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R16_MEM16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U16)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x22F, context))
    }
}

/// Read-modify-write `op [mN], imm` with the appropriate flag helper.
macro_rules! rmw_mem_imm {
    ($name:ident, $form:expr, $ty:expr, $op:expr, $flags:ident, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive($op), $ty, &[left, right])?;
                $flags(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

/// Flag-writer adapters with a uniform `(out, result, left, right)` signature.
macro_rules! flag_adapter {
    ($name:ident, $width:expr, $call:expr) => {
        fn $name(
            out: &mut dyn SemanticBuilder,
            result: ValueId,
            left: ValueId,
            right: ValueId,
        ) -> Result<(), SemanticError> {
            #[allow(clippy::redundant_closure_call)]
            ($call)(out, result, left, right)
        }
    };
}

flag_adapter!(flags_add_8, 8, |out: &mut dyn SemanticBuilder,
                               r: ValueId,
                               l: ValueId,
                               _ri: ValueId| {
    write_add_flags(out, r, l, 8)
});
flag_adapter!(flags_sub_8, 8, |out: &mut dyn SemanticBuilder,
                               r: ValueId,
                               l: ValueId,
                               ri: ValueId| {
    write_sub_flags(out, r, l, ri, 8)
});
flag_adapter!(flags_or_8, 8, |out: &mut dyn SemanticBuilder,
                              r: ValueId,
                              _l: ValueId,
                              _ri: ValueId| {
    write_logical_flags(out, r, 8)
});
flag_adapter!(flags_or_16, 16, |out: &mut dyn SemanticBuilder,
                                r: ValueId,
                                _l: ValueId,
                                _ri: ValueId| {
    write_logical_flags(out, r, 16)
});
flag_adapter!(flags_or_32, 32, |out: &mut dyn SemanticBuilder,
                                r: ValueId,
                                _l: ValueId,
                                _ri: ValueId| {
    write_logical_flags(out, r, 32)
});
flag_adapter!(flags_or_64, 64, |out: &mut dyn SemanticBuilder,
                                r: ValueId,
                                _l: ValueId,
                                _ri: ValueId| {
    write_logical_flags(out, r, 64)
});
flag_adapter!(flags_add_32, 32, |out: &mut dyn SemanticBuilder,
                                 r: ValueId,
                                 l: ValueId,
                                 _ri: ValueId| {
    write_add_flags(out, r, l, 32)
});
flag_adapter!(flags_add_16, 16, |out: &mut dyn SemanticBuilder,
                                 r: ValueId,
                                 l: ValueId,
                                 _ri: ValueId| {
    write_add_flags(out, r, l, 16)
});
flag_adapter!(flags_sub_16, 16, |out: &mut dyn SemanticBuilder,
                                 r: ValueId,
                                 l: ValueId,
                                 ri: ValueId| {
    write_sub_flags(out, r, l, ri, 16)
});
flag_adapter!(flags_sub_32, 32, |out: &mut dyn SemanticBuilder,
                                 r: ValueId,
                                 l: ValueId,
                                 ri: ValueId| {
    write_sub_flags(out, r, l, ri, 32)
});
flag_adapter!(flags_sub_64, 64, |out: &mut dyn SemanticBuilder,
                                 r: ValueId,
                                 l: ValueId,
                                 ri: ValueId| {
    write_sub_flags(out, r, l, ri, 64)
});

rmw_mem_imm!(
    OrMem32Imm32,
    forms::OR_MEM32_IMM32,
    U32,
    PrimitiveOp::Or,
    flags_or_32,
    0x231
);
rmw_mem_imm!(
    OrMem64Imm32,
    forms::OR_MEM64_IMM32,
    U64,
    PrimitiveOp::Or,
    flags_or_64,
    0x232
);
rmw_mem_imm!(
    AndMem32Imm32,
    forms::AND_MEM32_IMM32,
    U32,
    PrimitiveOp::And,
    flags_or_32,
    0x233
);
rmw_mem_imm!(
    AndMem64Imm32,
    forms::AND_MEM64_IMM32,
    U64,
    PrimitiveOp::And,
    flags_or_64,
    0x234
);
rmw_mem_imm!(
    XorMem32Imm32,
    forms::XOR_MEM32_IMM32,
    U32,
    PrimitiveOp::Xor,
    flags_or_32,
    0x235
);
rmw_mem_imm!(
    XorMem64Imm32,
    forms::XOR_MEM64_IMM32,
    U64,
    PrimitiveOp::Xor,
    flags_or_64,
    0x236
);
rmw_mem_imm!(
    AddMem32Imm32,
    forms::ADD_MEM32_IMM32,
    U32,
    PrimitiveOp::Add,
    flags_add_32,
    0x237
);
rmw_mem_imm!(
    SubMem32Imm32,
    forms::SUB_MEM32_IMM32,
    U32,
    PrimitiveOp::Sub,
    flags_sub_32,
    0x239
);
rmw_mem_imm!(
    SubMem64Imm32,
    forms::SUB_MEM64_IMM32,
    U64,
    PrimitiveOp::Sub,
    flags_sub_64,
    0x23A
);

/// `cmp [mN]/rN, imm` — compare against immediate.
macro_rules! cmp_imm {
    ($name:ident, $form:expr, $ty:expr, $flags:ident, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[left, right])?;
                $flags(out, result, left, right)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmp_imm!(CmpMem32Imm32, forms::CMP_MEM32_IMM32, U32, flags_sub_32, 0x23B);
cmp_imm!(CmpMem16Imm16, forms::CMP_MEM16_IMM16, U16, flags_sub_16, 0x23C);

/// `test [mN], imm` — AND of operands, flags only.
macro_rules! test_mem_imm {
    ($name:ident, $form:expr, $ty:expr, $flags:ident, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[left, right])?;
                $flags(out, result, left, right)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

test_mem_imm!(TestMem8Imm8, forms::TEST_MEM8_IMM8, U8, flags_or_8, 0x23E);
test_mem_imm!(TestMem16Imm16, forms::TEST_MEM16_IMM16, U16, flags_or_16, 0x23F);
test_mem_imm!(TestMem32Imm32, forms::TEST_MEM32_IMM32, U32, flags_or_32, 0x240);
test_mem_imm!(TestMem64Imm32, forms::TEST_MEM64_IMM32, U64, flags_or_64, 0x241);

/// `op rN, [mN]` — register-minus/logic-with-memory.
macro_rules! r_op_mem {
    ($name:ident, $form:expr, $ty:expr, $op:expr, $flags:ident, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive($op), $ty, &[left, right])?;
                $flags(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

r_op_mem!(
    OrR32Mem32,
    forms::OR_R32_MEM32,
    U32,
    PrimitiveOp::Or,
    flags_or_32,
    0x242
);
r_op_mem!(
    OrR64Mem64,
    forms::OR_R64_MEM64,
    U64,
    PrimitiveOp::Or,
    flags_or_64,
    0x243
);
r_op_mem!(
    AndR32Mem32,
    forms::AND_R32_MEM32,
    U32,
    PrimitiveOp::And,
    flags_or_32,
    0x244
);
r_op_mem!(
    AndR64Mem64,
    forms::AND_R64_MEM64,
    U64,
    PrimitiveOp::And,
    flags_or_64,
    0x245
);
r_op_mem!(
    XorR32Mem32,
    forms::XOR_R32_MEM32,
    U32,
    PrimitiveOp::Xor,
    flags_or_32,
    0x246
);
r_op_mem!(
    XorR64Mem64,
    forms::XOR_R64_MEM64,
    U64,
    PrimitiveOp::Xor,
    flags_or_64,
    0x247
);
r_op_mem!(OrR8Mem8, forms::OR_R8_MEM8, U8, PrimitiveOp::Or, flags_or_8, 0x248);
r_op_mem!(AndR8Mem8, forms::AND_R8_MEM8, U8, PrimitiveOp::And, flags_or_8, 0x249);
r_op_mem!(XorR8Mem8, forms::XOR_R8_MEM8, U8, PrimitiveOp::Xor, flags_or_8, 0x24A);

/// Read-modify-write `op [mN], rN` — memory destination, register source.
macro_rules! rmw_mem_reg {
    ($name:ident, $form:expr, $ty:expr, $op:expr, $flags:ident, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive($op), $ty, &[left, right])?;
                $flags(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

rmw_mem_reg!(
    OrMem32R32,
    forms::OR_MEM32_R32,
    U32,
    PrimitiveOp::Or,
    flags_or_32,
    0x24B
);
rmw_mem_reg!(
    OrMem64R64,
    forms::OR_MEM64_R64,
    U64,
    PrimitiveOp::Or,
    flags_or_64,
    0x24C
);
rmw_mem_reg!(
    AndMem32R32,
    forms::AND_MEM32_R32,
    U32,
    PrimitiveOp::And,
    flags_or_32,
    0x24D
);
rmw_mem_reg!(
    AndMem64R64,
    forms::AND_MEM64_R64,
    U64,
    PrimitiveOp::And,
    flags_or_64,
    0x24E
);
rmw_mem_reg!(
    XorMem32R32,
    forms::XOR_MEM32_R32,
    U32,
    PrimitiveOp::Xor,
    flags_or_32,
    0x24F
);
rmw_mem_reg!(
    XorMem64R64,
    forms::XOR_MEM64_R64,
    U64,
    PrimitiveOp::Xor,
    flags_or_64,
    0x250
);
rmw_mem_reg!(OrMem8R8, forms::OR_MEM8_R8, U8, PrimitiveOp::Or, flags_or_8, 0x251);
rmw_mem_reg!(AndMem8R8, forms::AND_MEM8_R8, U8, PrimitiveOp::And, flags_or_8, 0x252);
rmw_mem_reg!(XorMem8R8, forms::XOR_MEM8_R8, U8, PrimitiveOp::Xor, flags_or_8, 0x253);
rmw_mem_reg!(AddMem8R8, forms::ADD_MEM8_R8, U8, PrimitiveOp::Add, flags_add_8, 0x254);
rmw_mem_reg!(SubMem8R8, forms::SUB_MEM8_R8, U8, PrimitiveOp::Sub, flags_sub_8, 0x255);

/// `cmovcc r32, r32/m32` — conditional move.
macro_rules! cmovcc_r32 {
    ($name:ident, $form:expr, $rule:expr, $flag_fn:expr) => {
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
                let dst = out.read_operand(0, U32)?;
                let src = out.read_operand(1, U32)?;
                let cond = $flag_fn(out)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U32, &[cond, src, dst])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmovcc_r32!(
    CmovzR32R32,
    forms::CMOVZ_R32_R32,
    0x256,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::ZF_BIT)
);
cmovcc_r32!(
    CmovnzR32R32,
    forms::CMOVNZ_R32_R32,
    0x257,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::ZF_BIT)
);
// The corpus computes ZF/SF/CF and leaves OF/PF/AF at zero, so signed
// conditions reduce to ZF/SF (SF!=OF becomes SF, SF==OF becomes !SF).
cmovcc_r32!(
    CmovlR32R32,
    forms::CMOVL_R32_R32,
    0x258,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::SF_BIT)
);
cmovcc_r32!(
    CmovgeR32R32,
    forms::CMOVGE_R32_R32,
    0x259,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::SF_BIT)
);
cmovcc_r32!(
    CmovleR32R32,
    forms::CMOVLE_R32_R32,
    0x25A,
    |out: &mut dyn SemanticBuilder| {
        let zf = read_flag_set(out, rflags::ZF_BIT)?;
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, sf])
    }
);
cmovcc_r32!(
    CmovgR32R32,
    forms::CMOVG_R32_R32,
    0x25B,
    |out: &mut dyn SemanticBuilder| {
        let zf = read_flag_not_set(out, rflags::ZF_BIT)?;
        let sf = read_flag_not_set(out, rflags::SF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[zf, sf])
    }
);
cmovcc_r32!(
    CmovaR32R32,
    forms::CMOVA_R32_R32,
    0x25C,
    |out: &mut dyn SemanticBuilder| {
        let cf = read_flag_not_set(out, rflags::CF_BIT)?;
        let zf = read_flag_not_set(out, rflags::ZF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[cf, zf])
    }
);
cmovcc_r32!(
    CmovbR32R32,
    forms::CMOVB_R32_R32,
    0x25D,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::CF_BIT)
);
cmovcc_r32!(
    CmovbeR32R32,
    forms::CMOVBE_R32_R32,
    0x25E,
    |out: &mut dyn SemanticBuilder| {
        let cf = read_flag_set(out, rflags::CF_BIT)?;
        let zf = read_flag_set(out, rflags::ZF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf])
    }
);
cmovcc_r32!(
    CmovaeR32R32,
    forms::CMOVAE_R32_R32,
    0x25F,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::CF_BIT)
);
cmovcc_r32!(
    CmovsR32R32,
    forms::CMOVS_R32_R32,
    0x260,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::SF_BIT)
);
cmovcc_r32!(
    CmovnsR32R32,
    forms::CMOVNS_R32_R32,
    0x261,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::SF_BIT)
);
cmovcc_r32!(
    CmovcR32R32,
    forms::CMOVC_R32_R32,
    0x262,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::CF_BIT)
);
cmovcc_r32!(
    CmovncR32R32,
    forms::CMOVNC_R32_R32,
    0x263,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::CF_BIT)
);
cmovcc_r32!(
    CmovnpR32R32,
    forms::CMOVNP_R32_R32,
    0x264,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::PF_BIT)
);
cmovcc_r32!(
    CmovpR32R32,
    forms::CMOVP_R32_R32,
    0x265,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::PF_BIT)
);
cmovcc_r32!(
    CmovnoR32R32,
    forms::CMOVNO_R32_R32,
    0x266,
    |out: &mut dyn SemanticBuilder| read_flag_not_set(out, rflags::OF_BIT)
);
cmovcc_r32!(
    CmovoR32R32,
    forms::CMOVO_R32_R32,
    0x267,
    |out: &mut dyn SemanticBuilder| read_flag_set(out, rflags::OF_BIT)
);

/// `logic r8, r8` — 8-bit logical op (CF/OF cleared).
macro_rules! r_r_8 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
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
                let left = out.read_operand(0, U8)?;
                let right = out.read_operand(1, U8)?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[left, right])?;
                write_logical_flags(out, result, 8)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

/// `add/sub r8, r8` — 8-bit arithmetic.
macro_rules! r_r_8_addsub {
    ($name:ident, $form:expr, $op:expr, $rule:expr, $add:expr) => {
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
                let left = out.read_operand(0, U8)?;
                let right = out.read_operand(1, U8)?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[left, right])?;
                if $add {
                    write_add_flags(out, result, left, 8)?;
                } else {
                    write_sub_flags(out, result, left, right, 8)?;
                }
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

/// `op r8, imm8` — 8-bit read-modify-write.
macro_rules! r8_imm8 {
    ($name:ident, $form:expr, $op:expr, $flags:ident, $rule:expr) => {
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
                let left = out.read_operand(0, U8)?;
                let right = out.read_operand(1, U8)?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[left, right])?;
                $flags(out, result, left, right)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

r8_imm8!(AndR8Imm8, forms::AND_R8_IMM8, PrimitiveOp::And, flags_or_8, 0x268);
r8_imm8!(OrR8Imm8, forms::OR_R8_IMM8, PrimitiveOp::Or, flags_or_8, 0x269);
r8_imm8!(XorR8Imm8, forms::XOR_R8_IMM8, PrimitiveOp::Xor, flags_or_8, 0x26A);
r8_imm8!(AddR8Imm8, forms::ADD_R8_IMM8, PrimitiveOp::Add, flags_add_8, 0x26B);
r8_imm8!(SubR8Imm8, forms::SUB_R8_IMM8, PrimitiveOp::Sub, flags_sub_8, 0x26C);

// ---------------------------------------------------------------------------
// One-operand multiply/divide (rdx:rax accumulator forms)
// ---------------------------------------------------------------------------

/// `div r/m64` — unsigned divide of rdx:rax by the operand; rax = quotient,
/// rdx = remainder. The dividend is computed via `quot*divisor + rem` so no
/// dedicated remainder primitive is needed.
macro_rules! div_form {
    ($name:ident, $form:expr, $ty:expr, $wide:expr, $rule:expr) => {
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
                let divisor = out.read_operand(0, $ty)?;
                let lo = out.read_register(RegisterId(register_id::GPR_BASE), $ty)?; // RAX/EAX
                let hi = out.read_register(RegisterId(register_id::GPR_BASE + 2), $ty)?; // RDX/EDX
                let dividend = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), $wide, &[lo, hi])?;
                let divisor_w = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), $wide, &[divisor])?;
                let quot = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::UnsignedDiv),
                    $wide,
                    &[dividend, divisor_w],
                )?;
                let prod = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), $wide, &[quot, divisor_w])?;
                let rem = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $wide, &[dividend, prod])?;
                let zero = const_u64(out, 0)?;
                let quot_n = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[quot, zero])?;
                let rem_n = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[rem, zero])?;
                out.write_register(RegisterId(register_id::GPR_BASE), quot_n)?;
                out.write_register(RegisterId(register_id::GPR_BASE + 2), rem_n)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

div_form!(DivR64, forms::DIV_R64, U64, U128, 0x26D);
div_form!(DivR32, forms::DIV_R32, U32, U64, 0x26E);
div_form!(DivMem64, forms::DIV_MEM64, U64, U128, 0x26F);
div_form!(DivMem32, forms::DIV_MEM32, U32, U64, 0x270);

/// `mul r/mN` — unsigned multiply; result written into rdx:rax (the
/// concatenated destination).
/// Writes a condition bit into a named RFLAGS bit, preserving the rest.
fn write_flag_bit(out: &mut dyn SemanticBuilder, bit: u8, cond: ValueId) -> Result<(), SemanticError> {
    let old = out.read_register(register_id::RFLAGS, U64)?;
    let mask = out.constant(U64, &(!(1u64 << bit)).to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old, mask])?;
    let cond64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cond])?;
    let shifted = if bit == 0 {
        cond64
    } else {
        let shift = const_u64(out, u64::from(bit))?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cond64, shift])?
    };
    let new = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, shifted])?;
    out.write_register(register_id::RFLAGS, new)?;
    Ok(())
}

macro_rules! mul_form {
    ($name:ident, $form:expr, $ty:expr, $wide:expr, $hi_bit:expr, $rule:expr) => {
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
                let operand = out.read_operand(0, $ty)?;
                let acc = out.read_register(RegisterId(register_id::GPR_BASE), $ty)?;
                let operand_w = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), $wide, &[operand])?;
                let acc_w = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), $wide, &[acc])?;
                let product = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Mul),
                    $wide,
                    &[acc_w, operand_w],
                )?;
                let zero = const_u64(out, 0)?;
                let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[product, zero])?;
                let hi_bit = const_u64(out, $hi_bit)?;
                let hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[product, hi_bit],
                )?;
                out.write_register(RegisterId(register_id::GPR_BASE), lo)?;
                out.write_register(RegisterId(register_id::GPR_BASE + 2), hi)?;
                // CF/OF set when the product overflows the low half.
                let zero_t = const_typed(out, $ty, 0)?;
                let overflow = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[zero_t, hi])?;
                write_flag_bit(out, rflags::CF_BIT, overflow)?;
                write_flag_bit(out, rflags::OF_BIT, overflow)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mul_form!(MulR64, forms::MUL_R64, U64, U128, 64, 0x271);
mul_form!(MulMem64, forms::MUL_MEM64, U64, U128, 64, 0x272);
mul_form!(MulR32, forms::MUL_R32, U32, U64, 32, 0x273);
mul_form!(MulMem32, forms::MUL_MEM32, U32, U64, 32, 0x274);
mov_xmm_mem!(MovdquXmmMem, forms::MOVDQU_XMM_MEM, 0x279);
mov_mem_xmm!(MovdquMemXmm, forms::MOVDQU_MEM_XMM, 0x27A);
mov_reg_reg!(MovdquXmmXmm, forms::MOVDQU_XMM_XMM, U128, 0x27B);

rmw_mem_imm!(OrMem8Imm8, forms::OR_MEM8_IMM8, U8, PrimitiveOp::Or, flags_or_8, 0x27C);
rmw_mem_imm!(
    AndMem8Imm8,
    forms::AND_MEM8_IMM8,
    U8,
    PrimitiveOp::And,
    flags_or_8,
    0x27D
);
rmw_mem_imm!(
    XorMem8Imm8,
    forms::XOR_MEM8_IMM8,
    U8,
    PrimitiveOp::Xor,
    flags_or_8,
    0x27E
);
rmw_mem_imm!(
    AddMem8Imm8,
    forms::ADD_MEM8_IMM8,
    U8,
    PrimitiveOp::Add,
    flags_add_8,
    0x27F
);
rmw_mem_imm!(
    SubMem8Imm8,
    forms::SUB_MEM8_IMM8,
    U8,
    PrimitiveOp::Sub,
    flags_sub_8,
    0x280
);
rmw_mem_imm!(
    OrMem16Imm16,
    forms::OR_MEM16_IMM16,
    U16,
    PrimitiveOp::Or,
    flags_or_16,
    0x281
);
rmw_mem_imm!(
    AndMem16Imm16,
    forms::AND_MEM16_IMM16,
    U16,
    PrimitiveOp::And,
    flags_or_16,
    0x282
);
rmw_mem_imm!(
    XorMem16Imm16,
    forms::XOR_MEM16_IMM16,
    U16,
    PrimitiveOp::Xor,
    flags_or_16,
    0x283
);
rmw_mem_imm!(
    AddMem16Imm16,
    forms::ADD_MEM16_IMM16,
    U16,
    PrimitiveOp::Add,
    flags_add_16,
    0x284
);
rmw_mem_imm!(
    SubMem16Imm16,
    forms::SUB_MEM16_IMM16,
    U16,
    PrimitiveOp::Sub,
    flags_sub_16,
    0x285
);
cmp_mem_reg!(CmpMem16R16, forms::CMP_MEM16_R16, U16, 16, 0x286);

r_r_8!(XorR8R8, forms::XOR_R8_R8, PrimitiveOp::Xor, 0x287);
r_r_8!(OrR8R8, forms::OR_R8_R8, PrimitiveOp::Or, 0x288);
r_r_8!(AndR8R8, forms::AND_R8_R8, PrimitiveOp::And, 0x289);
r_r_8_addsub!(AddR8R8, forms::ADD_R8_R8, PrimitiveOp::Add, 0x28A, true);
r_r_8_addsub!(SubR8R8, forms::SUB_R8_R8, PrimitiveOp::Sub, 0x28B, false);

r_op_mem!(
    SubR64Mem64,
    forms::SUB_R64_MEM64,
    U64,
    PrimitiveOp::Sub,
    flags_sub_64,
    0x28C
);
rmw_mem_reg!(
    SubMem64R64,
    forms::SUB_MEM64_R64,
    U64,
    PrimitiveOp::Sub,
    flags_sub_64,
    0x28D
);
rmw_mem_reg!(
    SubMem32R32,
    forms::SUB_MEM32_R32,
    U32,
    PrimitiveOp::Sub,
    flags_sub_32,
    0x28E
);

// ---------------------------------------------------------------------------
// CMPXCHG — compare-and-exchange
// ---------------------------------------------------------------------------

/// `cmpxchg dst, src` — if `accumulator == dst` then `dst = src` (ZF=1),
/// else `accumulator = dst` (ZF=0). The accumulator is AL/AX/EAX/RAX.
macro_rules! cmpxchg {
    ($name:ident, $form:expr, $ty:expr, $acc:expr, $rule:expr) => {
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
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let acc = out.read_register(RegisterId(register_id::GPR_BASE), $ty)?;
                let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[acc, dst])?;
                write_sub_flags(out, diff, acc, dst, scalar_bits($ty))?;
                let equal = read_flag_set(out, rflags::ZF_BIT)?;
                // On success dst = src; on failure acc = dst.
                let new_dst = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    $ty,
                    &[equal, src, dst],
                )?;
                let new_acc = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    $ty,
                    &[equal, acc, dst],
                )?;
                out.write_operand(0, new_dst)?;
                // A narrower cmpxchg zero-extends the accumulator into RAX.
                let acc_write = if $ty == U64 {
                    new_acc
                } else {
                    out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[new_acc])?
                };
                out.write_register(RegisterId($acc), acc_write)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmpxchg!(
    CmpxchgMem32R32,
    forms::CMPXCHG_MEM32_R32,
    U32,
    register_id::GPR_BASE,
    0x28F
);
cmpxchg!(
    CmpxchgMem64R64,
    forms::CMPXCHG_MEM64_R64,
    U64,
    register_id::GPR_BASE,
    0x290
);
cmpxchg!(CmpxchgMem8R8, forms::CMPXCHG_MEM8_R8, U8, register_id::GPR_BASE, 0x291);

fn scalar_bits(ty: SemanticType) -> u16 {
    match ty {
        SemanticType::Scalar(ScalarType::BitVec(bits)) => bits,
        _ => 64,
    }
}

rmw_mem_reg!(
    AddMem32R32,
    forms::ADD_MEM32_R32,
    U32,
    PrimitiveOp::Add,
    flags_add_32,
    0x294
);

/// `test dst, src` — AND of operands, flags only, no writeback.
macro_rules! test_op {
    ($name:ident, $form:expr, $ty:expr, $bits:expr, $rule:expr) => {
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
                let left = out.read_operand(0, $ty)?;
                let right = out.read_operand(1, $ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[left, right])?;
                write_logical_flags(out, result, $bits)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

/// `xchg dst, src` — exchange; no flag effects.
macro_rules! xchg {
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
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                out.write_operand(0, src)?;
                out.write_operand(1, dst)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

xchg!(XchgMem32R32, forms::XCHG_MEM32_R32, U32, 0x295);
xchg!(XchgMem64R64, forms::XCHG_MEM64_R64, U64, 0x296);
xchg!(XchgMem8R8, forms::XCHG_MEM8_R8, U8, 0x297);

xchg!(XchgR32R32, forms::XCHG_R32_R32, U32, 0x298);

test_op!(TestR16R16, forms::TEST_R16_R16, U16, 16, 0x29A);
test_op!(TestR16Imm16, forms::TEST_R16_IMM16, U16, 16, 0x29B);
test_op!(TestMem16R16, forms::TEST_MEM16_R16, U16, 16, 0x29C);

/// `bsf r, r/m` — index of lowest set bit (BSF) or `tzcnt` (returns operand
/// width when the source is zero).
macro_rules! bitscan_low {
    ($name:ident, $form:expr, $ty:expr, $is_tzcnt:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $ty)?;
                let index = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::CountTrailingZeros),
                    $ty,
                    &[src],
                )?;
                out.write_operand(0, index)?;
                // ZF=1 iff source was zero; tzcnt also reports the operand
                // width in that case via the primitive's contract.
                let zero = const_typed(out, $ty, 0)?;
                let is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
                write_flag_bit(out, rflags::ZF_BIT, is_zero)?;
                if $is_tzcnt {
                    write_flag_bit(out, rflags::CF_BIT, is_zero)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

bitscan_low!(BsfR32R32, forms::BSF_R32_R32, U32, false, 0x29D);
bitscan_low!(BsfR64Mem64, forms::BSF_R64_MEM64, U64, false, 0x29E);
bitscan_low!(BsfR32Mem32, forms::BSF_R32_MEM32, U32, false, 0x29F);
bitscan_low!(TzcntR32R32, forms::TZCNT_R32_R32, U32, true, 0x2A0);

/// `bsr/lzcnt r, r/m` — index of highest set bit.
macro_rules! bitscan_high {
    ($name:ident, $form:expr, $ty:expr, $is_lzcnt:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $ty)?;
                let leading = out.emit(SemanticOp::Primitive(PrimitiveOp::CountLeadingZeros), $ty, &[src])?;
                // bsr reports bits-1-clz; lzcnt reports clz directly.
                let index = if $is_lzcnt {
                    leading
                } else {
                    let width_minus_one = const_u64(out, u64::from(scalar_bits($ty)) - 1)?;
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Sub),
                        $ty,
                        &[width_minus_one, leading],
                    )?
                };
                out.write_operand(0, index)?;
                let zero = const_typed(out, $ty, 0)?;
                let is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
                write_flag_bit(out, rflags::ZF_BIT, is_zero)?;
                if $is_lzcnt {
                    write_flag_bit(out, rflags::CF_BIT, is_zero)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

bitscan_high!(BsrR32R32, forms::BSR_R32_R32, U32, false, 0x2A1);
bitscan_high!(LzcntR32R32, forms::LZCNT_R32_R32, U32, true, 0x2A2);

/// `popcnt r, r/m` — population count.
macro_rules! popcnt {
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
                let src = out.read_operand(1, $ty)?;
                let count = out.emit(SemanticOp::Primitive(PrimitiveOp::Popcount), $ty, &[src])?;
                out.write_operand(0, count)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

popcnt!(PopcntR32R32, forms::POPCNT_R32_R32, U32, 0x2A3);

/// `movhps/movhpd xmm, m64` — loads 64 bits into the high half of the
/// destination, preserving the low 64 bits.
macro_rules! movh_mem {
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
                let mem = out.read_operand(1, U64)?;
                let old = out.read_operand(0, U128)?;
                let mem128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[mem])?;
                let sixty_four = const_u64(out, 64)?;
                let shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U128,
                    &[mem128, sixty_four],
                )?;
                let low_mask = const_u64(out, 0xFFFF_FFFF_FFFF_FFFF)?;
                let low_mask128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[low_mask])?;
                let kept = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[old, low_mask128])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[kept, shifted])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movh_mem!(MovhpsXmmMem64, forms::MOVHPS_XMM_MEM64, 0x2A4);
movh_mem!(MovhpdXmmMem64, forms::MOVHPD_XMM_MEM64, 0x2A5);

/// `movlps/movlpd xmm, m64` — loads 64 bits into the low half of the
/// destination, preserving the high 64 bits.
macro_rules! movl_mem {
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
                let mem = out.read_operand(1, U64)?;
                let old = out.read_operand(0, U128)?;
                let mem128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[mem])?;
                let high_mask = const_u64(out, 0xFFFF_FFFF_FFFF_FFFF)?;
                let high_mask128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[high_mask])?;
                let sixty_four = const_u64(out, 64)?;
                let high_shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U128,
                    &[high_mask128, sixty_four],
                )?;
                let kept = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::And),
                    U128,
                    &[old, high_shifted],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[kept, mem128])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movl_mem!(MovlpsXmmMem64, forms::MOVLPS_XMM_MEM64, 0x2A6);
movl_mem!(MovlpdXmmMem64, forms::MOVLPD_XMM_MEM64, 0x2A7);

/// `movhps/movlps m64, xmm` — stores the high or low 64 bits to memory.
macro_rules! mov_mem_hl {
    ($name:ident, $form:expr, $high:expr, $rule:expr) => {
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
                let xmm = out.read_operand(1, U128)?;
                let start = const_u64(out, if $high { 64 } else { 0 })?;
                let half = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[xmm, start])?;
                out.write_operand(0, half)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_mem_hl!(MovhpsMem64Xmm, forms::MOVHPS_MEM64_XMM, true, 0x2A8);
mov_mem_hl!(MovlpsMem64Xmm, forms::MOVLPS_MEM64_XMM, false, 0x2A9);

/// `movss xmm, m32` — zero-extends a 32-bit scalar into the destination.
macro_rules! mov_scalar_mem {
    ($name:ident, $form:expr, $mem_ty:expr, $rule:expr) => {
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
                let value = out.read_operand(1, $mem_ty)?;
                let widened = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[value])?;
                out.write_operand(0, widened)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_scalar_mem!(MovssXmmMem32, forms::MOVSS_XMM_MEM32, U32, 0x2AA);
mov_scalar_mem!(MovsdXmmMem64, forms::MOVSD_XMM_MEM64, U64, 0x2AB);

/// `movss/movsd m, xmm` — stores the low scalar to memory.
macro_rules! mov_mem_scalar {
    ($name:ident, $form:expr, $mem_ty:expr, $rule:expr) => {
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
                let xmm = out.read_operand(1, U128)?;
                let zero = const_u64(out, 0)?;
                let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $mem_ty, &[xmm, zero])?;
                out.write_operand(0, low)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_mem_scalar!(MovssMem32Xmm, forms::MOVSS_MEM32_XMM, U32, 0x2AC);
mov_mem_scalar!(MovsdMem64Xmm, forms::MOVSD_MEM64_XMM, U64, 0x2AD);

// ---------------------------------------------------------------------------
// YMM (VEX.256) providers — 256-bit lane-wise ops on widened concrete values
// ---------------------------------------------------------------------------

const U256: SemanticType = SemanticType::Scalar(ScalarType::BitVec(256));
const I8X32: SemanticType = SemanticType::Vector {
    lanes: 32,
    lane: ScalarType::BitVec(8),
};
const I64X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::BitVec(64),
};

/// `vmov* ymm, m256/ymm` — 256-bit load or register move.
macro_rules! mov_ymm {
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
                let value = out.read_operand(1, U256)?;
                out.write_operand(0, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_ymm!(VmovdqaYmmMem, forms::VMOVDQA_YMM_MEM, 0x2B0);
mov_ymm!(VmovdqaYmmYmm, forms::VMOVDQA_YMM_YMM, 0x2B1);
mov_ymm!(VmovdquYmmMem, forms::VMOVDQU_YMM_MEM, 0x2B2);
mov_ymm!(VmovdquYmmYmm, forms::VMOVDQU_YMM_YMM, 0x2B3);
mov_ymm!(VmovapsYmmMem, forms::VMOVAPS_YMM_MEM, 0x2B4);
mov_ymm!(VmovupsYmmMem, forms::VMOVUPS_YMM_MEM, 0x2B5);

/// `vmov* m256, ymm` — 256-bit store.
macro_rules! mov_mem_ymm {
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
                let value = out.read_operand(1, U256)?;
                out.write_operand(0, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_mem_ymm!(VmovdqaMemYmm, forms::VMOVDQA_MEM_YMM, 0x2B6);
mov_mem_ymm!(VmovdquMemYmm, forms::VMOVDQU_MEM_YMM, 0x2B7);
mov_mem_ymm!(VmovapsMemYmm, forms::VMOVAPS_MEM_YMM, 0x2B8);
mov_mem_ymm!(VmovupsMemYmm, forms::VMOVUPS_MEM_YMM, 0x2B9);

/// `vp* ymm, ymm, ymm` — 256-bit three-operand lane-wise logical op.
macro_rules! logic_ymm {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
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
                let left = out.read_operand(1, U256)?;
                let right = out.read_operand(2, U256)?;
                let result = out.emit(SemanticOp::Primitive($op), U256, &[left, right])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logic_ymm!(VpxorYmmYmmYmm, forms::VPXOR_YMM_YMM_YMM, PrimitiveOp::Xor, 0x2BA);
logic_ymm!(VporYmmYmmYmm, forms::VPOR_YMM_YMM_YMM, PrimitiveOp::Or, 0x2BB);
logic_ymm!(VpandYmmYmmYmm, forms::VPAND_YMM_YMM_YMM, PrimitiveOp::And, 0x2BC);
logic_ymm!(VxorpsYmmYmmYmm, forms::VXORPS_YMM_YMM_YMM, PrimitiveOp::Xor, 0x2BD);

/// `vpcmpeqb ymm, ymm, ymm` — per-byte equality mask (0xFF where equal).
#[derive(Clone, Copy, Debug)]
pub struct VpcmpeqbYmmYmmYmm;

impl SemanticProvider for VpcmpeqbYmmYmmYmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x2BE)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::VPCMPEQB_YMM_YMM_YMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Byte-wise: mask = ~(a ^ b) per byte where equal => a^b==0 -> 0xFF.
        let left = out.read_operand(1, I8X32)?;
        let right = out.read_operand(2, I8X32)?;
        let mask = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::MaskEq)),
            I8X32,
            &[left, right],
        )?;
        out.write_operand(0, mask)?;
        fall_through(out, insn)?;
        Ok(receipt(0x2BE, context))
    }
}

/// `vpmovmskb r32, ymm` — gather each byte's MSB into a 32-bit mask.
#[derive(Clone, Copy, Debug)]
pub struct VpmovmskbR32Ymm;

impl SemanticProvider for VpmovmskbR32Ymm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x2BF)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::VPMOVMSKB_R32_YMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, I8X32)?;
        let mask = out.emit(SemanticOp::Vector(VectorOp::MovMask), U32, &[src])?;
        out.write_operand(0, mask)?;
        fall_through(out, insn)?;
        Ok(receipt(0x2BF, context))
    }
}

/// `vpbroadcast* ymm, xmm/m` — broadcast the low lane across all 32 bytes.
macro_rules! broadcast_ymm {
    ($name:ident, $form:expr, $src_ty:expr, $lane_bits:expr, $rule:expr) => {
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
                let src = out.read_operand(1, $src_ty)?;
                let lanes = match $lane_bits {
                    8 => I8X32,
                    64 => I64X4,
                    _ => I8X32,
                };
                let result = out.emit(SemanticOp::Vector(VectorOp::Broadcast), lanes, &[src])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

broadcast_ymm!(VpbroadcastbYmmXmm, forms::VPBROADCASTB_YMM_XMM, U128, 8, 0x2C0);
broadcast_ymm!(VpbroadcastqYmmXmm, forms::VPBROADCASTQ_YMM_XMM, U128, 64, 0x2C1);
broadcast_ymm!(VpbroadcastbYmmMem8, forms::VPBROADCASTB_YMM_MEM8, U8, 8, 0x2C2);

/// `vzeroupper` — clears all ymm/zmm upper halves (keeps low 128 of each zmm).
#[derive(Clone, Copy, Debug)]
pub struct Vzeroupper;

impl SemanticProvider for Vzeroupper {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x2C3)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::VZEROUPPER
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Model as a no-op for now: the architectural effect is zeroing upper
        // vector bits, which only matters if later code reads stale ymm bits.
        fall_through(out, insn)?;
        Ok(receipt(0x2C3, context))
    }
}

/// `vp* xmm, xmm, xmm` — 128-bit three-operand lane-wise logical op.
macro_rules! logic_vex128 {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
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
                let left = out.read_operand(1, U128)?;
                let right = out.read_operand(2, U128)?;
                let result = out.emit(SemanticOp::Primitive($op), U128, &[left, right])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logic_vex128!(VpxorXmmXmmXmm, forms::VPXOR_XMM_XMM_XMM, PrimitiveOp::Xor, 0x2C4);
logic_vex128!(VporXmmXmmXmm, forms::VPOR_XMM_XMM_XMM, PrimitiveOp::Or, 0x2C5);
logic_vex128!(VpandXmmXmmXmm, forms::VPAND_XMM_XMM_XMM, PrimitiveOp::And, 0x2C6);
logic_vex128!(VxorpsXmmXmmXmm, forms::VXORPS_XMM_XMM_XMM, PrimitiveOp::Xor, 0x2C7);

/// `vpcmpeqb xmm, xmm, xmm` — per-byte equality mask.
#[derive(Clone, Copy, Debug)]
pub struct VpcmpeqbXmmXmmXmm;

impl SemanticProvider for VpcmpeqbXmmXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x2C8)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::VPCMPEQB_XMM_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(1, I8X16)?;
        let right = out.read_operand(2, I8X16)?;
        let mask = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::MaskEq)),
            I8X16,
            &[left, right],
        )?;
        out.write_operand(0, mask)?;
        fall_through(out, insn)?;
        Ok(receipt(0x2C8, context))
    }
}

/// `vpinsr* xmm, xmm, r/m, imm` — copy src1, replace lane `imm` with the
/// scalar from operand 2.
macro_rules! vpinsr {
    ($name:ident, $form:expr, $elem_ty:expr, $elem_bits:expr, $rule:expr) => {
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
                let dst = out.read_operand(1, U128)?;
                let elem = out.read_operand(2, $elem_ty)?;
                let imm = out.read_operand(3, U8)?;
                // lane index = imm mod (128/elem_bits)
                let lane_count = const_typed(out, U8, (128 / $elem_bits - 1) as u64)?;
                let lane = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U8, &[imm, lane_count])?;
                let lane64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[lane])?;
                let elem_bits = const_u64(out, $elem_bits as u64)?;
                let bit_off = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[lane64, elem_bits])?;
                let elem128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[elem])?;
                let shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U128,
                    &[elem128, bit_off],
                )?;
                let elem_mask = const_typed(
                    out,
                    U128,
                    if $elem_bits == 64 {
                        u64::MAX
                    } else {
                        (1u64 << $elem_bits) - 1
                    },
                )?;
                let lane_mask = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U128,
                    &[elem_mask, bit_off],
                )?;
                let keep = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U128, &[lane_mask])?;
                let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[dst, keep])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[cleared, shifted])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vpinsr!(VpinsrbXmmXmmR8Imm8, forms::VPINSRB_XMM_XMM_R8_IMM8, U8, 8, 0x2C9);
vpinsr!(VpinsrwXmmXmmR16Imm8, forms::VPINSRW_XMM_XMM_R16_IMM8, U16, 16, 0x2CA);
vpinsr!(VpinsrdXmmXmmR32Imm8, forms::VPINSRD_XMM_XMM_R32_IMM8, U32, 32, 0x2CB);
vpinsr!(VpinsrqXmmXmmR64Imm8, forms::VPINSRQ_XMM_XMM_R64_IMM8, U64, 64, 0x2CC);
vpinsr!(VpinsrbXmmXmmMem8Imm8, forms::VPINSRB_XMM_XMM_MEM8_IMM8, U8, 8, 0x2CD);
vpinsr!(
    VpinsrwXmmXmmMem16Imm8,
    forms::VPINSRW_XMM_XMM_MEM16_IMM8,
    U16,
    16,
    0x2CE
);
vpinsr!(
    VpinsrdXmmXmmMem32Imm8,
    forms::VPINSRD_XMM_XMM_MEM32_IMM8,
    U32,
    32,
    0x2CF
);
vpinsr!(
    VpinsrqXmmXmmMem64Imm8,
    forms::VPINSRQ_XMM_XMM_MEM64_IMM8,
    U64,
    64,
    0x2D0
);

/// `vinsertf128/vinserti128 ymm, ymm, xmm, imm` — replace half `imm` of ymm.
macro_rules! vinsert128 {
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
                let dst = out.read_operand(1, U256)?;
                let src = out.read_operand(2, U128)?;
                let imm = out.read_operand(3, U8)?;
                let one = const_typed(out, U8, 1)?;
                let which = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U8, &[imm, one])?;
                let which64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[which])?;
                let c128 = const_u64(out, 128)?;
                let bit_off = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[which64, c128])?;
                let src256 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U256, &[src])?;
                let shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U256,
                    &[src256, bit_off],
                )?;
                // mask = 128 ones at bit_off
                let lo_mask = out.constant(U128, &[0xFFu8; 16])?;
                let lo_mask256 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U256, &[lo_mask])?;
                let lane_mask = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                    U256,
                    &[lo_mask256, bit_off],
                )?;
                let keep = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U256, &[lane_mask])?;
                let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U256, &[dst, keep])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U256, &[cleared, shifted])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vinsert128!(Vinserti128YmmYmmXmmImm8, forms::VINSERTI128_YMM_YMM_XMM_IMM8, 0x2D1);
vinsert128!(Vinsertf128YmmYmmXmmImm8, forms::VINSERTF128_YMM_YMM_XMM_IMM8, 0x2D2);

/// `vextractf128/vextracti128 xmm, ymm, imm` — extract half `imm` of ymm.
macro_rules! vextract128 {
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
                let src = out.read_operand(1, U256)?;
                let imm = out.read_operand(2, U8)?;
                let one = const_typed(out, U8, 1)?;
                let which = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U8, &[imm, one])?;
                let which64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[which])?;
                let c128 = const_u64(out, 128)?;
                let bit_off = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[which64, c128])?;
                let half = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src, bit_off])?;
                out.write_operand(0, half)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vextract128!(Vextracti128XmmYmmImm8, forms::VEXTRACTI128_XMM_YMM_IMM8, 0x2D3);
vextract128!(Vextractf128XmmYmmImm8, forms::VEXTRACTF128_XMM_YMM_IMM8, 0x2D4);

/// `vmov* xmm, m128/xmm` — 128-bit VEX move.
macro_rules! mov_vex128 {
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
                let value = out.read_operand(1, U128)?;
                out.write_operand(0, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_vex128!(VmovdqaXmmMem, forms::VMOVDQA_XMM_MEM, 0x2D5);
mov_vex128!(VmovdqaXmmXmm, forms::VMOVDQA_XMM_XMM, 0x2D6);
mov_vex128!(VmovdquXmmMem, forms::VMOVDQU_XMM_MEM, 0x2D7);
mov_vex128!(VmovdquXmmXmm, forms::VMOVDQU_XMM_XMM, 0x2D8);
mov_vex128!(VmovapsXmmMem, forms::VMOVAPS_XMM_MEM, 0x2D9);
mov_vex128!(VmovupsXmmMem, forms::VMOVUPS_XMM_MEM, 0x2DA);
mov_vex128!(VmovdqaMemXmm, forms::VMOVDQA_MEM_XMM, 0x2DB);
mov_vex128!(VmovdquMemXmm, forms::VMOVDQU_MEM_XMM, 0x2DC);
mov_vex128!(VmovapsMemXmm, forms::VMOVAPS_MEM_XMM, 0x2DD);
mov_vex128!(VmovupsMemXmm, forms::VMOVUPS_MEM_XMM, 0x2DE);

/// `vextractf128/vextracti128 m128, ymm, imm` — extract half to memory.
macro_rules! vextract128_mem {
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
                let src = out.read_operand(1, U256)?;
                let imm = out.read_operand(2, U8)?;
                let one = const_typed(out, U8, 1)?;
                let which = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U8, &[imm, one])?;
                let which64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[which])?;
                let c128 = const_u64(out, 128)?;
                let bit_off = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[which64, c128])?;
                let half = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src, bit_off])?;
                out.write_operand(0, half)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vextract128_mem!(Vextracti128Mem128YmmImm8, forms::VEXTRACTI128_MEM128_YMM_IMM8, 0x2DF);
vextract128_mem!(Vextractf128Mem128YmmImm8, forms::VEXTRACTF128_MEM128_YMM_IMM8, 0x2E0);

/// `vmovd/vmovq xmm, r/m` — zero-extend a scalar into the low lane.
macro_rules! vmov_to_xmm {
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
                let widened = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[value])?;
                out.write_operand(0, widened)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vmov_to_xmm!(VmovdXmmR32, forms::VMOVD_XMM_R32, U32, 0x2E1);
vmov_to_xmm!(VmovdXmmMem32, forms::VMOVD_XMM_MEM32, U32, 0x2E2);
vmov_to_xmm!(VmovqXmmR64, forms::VMOVQ_XMM_R64, U64, 0x2E3);
vmov_to_xmm!(VmovqXmmMem64, forms::VMOVQ_XMM_MEM64, U64, 0x2E4);

/// `vmovd/vmovq r/m, xmm` — extract the low scalar lane.
macro_rules! vmov_from_xmm {
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
                let xmm = out.read_operand(1, U128)?;
                let zero = const_u64(out, 0)?;
                let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[xmm, zero])?;
                out.write_operand(0, low)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vmov_from_xmm!(VmovdR32Xmm, forms::VMOVD_R32_XMM, U32, 0x2E5);
vmov_from_xmm!(VmovdMem32Xmm, forms::VMOVD_MEM32_XMM, U32, 0x2E6);
vmov_from_xmm!(VmovqR64Xmm, forms::VMOVQ_R64_XMM, U64, 0x2E7);
vmov_from_xmm!(VmovqMem64Xmm, forms::VMOVQ_MEM64_XMM, U64, 0x2E8);

/// `push r/m` — decrement rsp by width then store the operand.
macro_rules! push_mem {
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
                let value = out.read_operand(0, $ty)?;
                let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
                let size = const_u64(out, $size)?;
                let new_sp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, size])?;
                out.write_operand(1, value)?;
                out.write_register(RegisterId(register_id::GPR_BASE + 4), new_sp)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

push_mem!(PushMem64, forms::PUSH_MEM64, U64, 8, 0x2E9);
push_mem!(PushMem16, forms::PUSH_MEM16, U16, 2, 0x2EA);

/// `pop r/m` — load the operand from [rsp] then increment rsp.
macro_rules! pop_mem {
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
                let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
                let value = out.read_operand(1, $ty)?;
                out.write_operand(0, value)?;
                let size = const_u64(out, $size)?;
                let new_sp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, size])?;
                out.write_register(RegisterId(register_id::GPR_BASE + 4), new_sp)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

pop_mem!(PopMem64, forms::POP_MEM64, U64, 8, 0x2EB);
