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

use crate::providers::{
    ShiftKind, add_flag_values, compose_rflags, emit_memory_rotate_carry, sub_flag_values, widen_to_u64,
    write_add_flags, write_add_flags_preserve_cf, write_logical_flags, write_mul_flags, write_rotate_flags_width_count,
    write_shift_flags, write_sub_flags, write_sub_flags_preserve_cf,
};
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
    right: ValueId,
) -> Result<(), SemanticError> {
    write_add_flags(out, result, left, right, 32)
}

fn write_sub_flags_32(
    out: &mut dyn SemanticBuilder,
    result: ValueId,
    left: ValueId,
    right: ValueId,
) -> Result<(), SemanticError> {
    write_sub_flags(out, result, left, right, 32)
}

/// Write ZF, SF for a 32-bit logical result, CF=0.
fn write_logical_flags_32(out: &mut dyn SemanticBuilder, result: ValueId) -> Result<(), SemanticError> {
    write_logical_flags(out, result, 32)
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
// CQO: rdx = sign extension of rax's top bit (op0=rdx write, op1=rax read,
// both suppressed).
#[derive(Clone, Copy, Debug)]
pub struct Cqo;

impl SemanticProvider for Cqo {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x301)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CQO
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rax = out.read_operand(1, U64)?;
        let sixty_three = const_u64(out, 63)?;
        let rdx = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U64,
            &[rax, sixty_three],
        )?;
        out.write_operand(0, rdx)?;
        fall_through(out, insn)?;
        Ok(receipt(0x301, context))
    }
}

// One-operand IMUL: rdx:rax = rax * r/m64 signed, CF/OF from the product's
// high half. op0=r/m64 read, op1=rax read/write, op2=rdx write, op3=rflags.
#[derive(Clone, Copy, Debug)]
pub struct Imul1R64;

impl SemanticProvider for Imul1R64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x302)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_1OP_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let right = out.read_operand(0, U64)?;
        let rax = out.read_operand(1, U64)?;
        write_mul_flags(out, rax, right, 64)?;
        let u128_ty = SemanticType::Scalar(ScalarType::BitVec(128));
        let rax2 = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), u128_ty, &[rax])?;
        let right2 = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), u128_ty, &[right])?;
        let product = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), u128_ty, &[rax2, right2])?;
        let zero = const_u64(out, 0)?;
        let sixty_four = const_u64(out, 64)?;
        let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[product, zero])?;
        let hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[product, sixty_four])?;
        out.write_operand(1, lo)?;
        out.write_operand(2, hi)?;
        fall_through(out, insn)?;
        Ok(receipt(0x302, context))
    }
}

movsx!(MovsxR64R16, forms::MOVSX_R64_R16, U16, U64, 0x230);
movzx!(MovzxR64R16, forms::MOVZX_R64_R16, U16, U64, 0x300);
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
        write_add_flags_preserve_cf(out, result, operand, one, 32)?;
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
        write_sub_flags_preserve_cf(out, result, operand, one, 32)?;
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
        let zero = const_u32(out, 0)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[zero, operand])?;
        write_sub_flags_32(out, result, zero, operand)?;
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
    |out: &mut dyn SemanticBuilder| {
        // BE: CF=1 OR ZF=1.
        let cf = read_flag_set(out, rflags::CF_BIT)?;
        let zf = read_flag_set(out, rflags::ZF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf])
    }
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
    |out: &mut dyn SemanticBuilder| {
        // LE: ZF=1 OR SF != OF.
        let zf = read_flag_set(out, rflags::ZF_BIT)?;
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        let of = read_flag_set(out, rflags::OF_BIT)?;
        let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, ne])
    }
);
cmovcc_r64!(
    CmovgR64R64,
    forms::CMOVG_R64_R64,
    0x79,
    |out: &mut dyn SemanticBuilder| {
        // G: ZF=0 AND SF == OF.
        let not_zf = read_flag_not_set(out, rflags::ZF_BIT)?;
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        let of = read_flag_set(out, rflags::OF_BIT)?;
        let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
        let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[ne])?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_zf, eq])
    }
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
    // A: CF=0 AND ZF=0.
    let not_cf = read_flag_not_set(out, rflags::CF_BIT)?;
    let not_zf = read_flag_not_set(out, rflags::ZF_BIT)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_cf, not_zf])
});
setcc_r8!(SetbR8, forms::SETB_R8, 0x7B, |out: &mut dyn SemanticBuilder| {
    read_flag_set(out, rflags::CF_BIT)
});
setcc_r8!(SetbeR8, forms::SETBE_R8, 0x7C, |out: &mut dyn SemanticBuilder| {
    // BE: CF=1 OR ZF=1.
    let cf = read_flag_set(out, rflags::CF_BIT)?;
    let zf = read_flag_set(out, rflags::ZF_BIT)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf])
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
    // LE: ZF=1 OR SF != OF.
    let zf = read_flag_set(out, rflags::ZF_BIT)?;
    let sf = read_flag_set(out, rflags::SF_BIT)?;
    let of = read_flag_set(out, rflags::OF_BIT)?;
    let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, ne])
});
setcc_r8!(SetgR8, forms::SETG_R8, 0x83, |out: &mut dyn SemanticBuilder| {
    // G: ZF=0 AND SF == OF.
    let not_zf = read_flag_not_set(out, rflags::ZF_BIT)?;
    let sf = read_flag_set(out, rflags::SF_BIT)?;
    let of = read_flag_set(out, rflags::OF_BIT)?;
    let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
    let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[ne])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_zf, eq])
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
pub struct BswapR32;

impl SemanticProvider for BswapR32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x30A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BSWAP_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let val = out.read_operand(0, U32)?;
        let mask_ff = const_typed(out, U32, 0xFF)?;
        let mut result = const_typed(out, U32, 0)?;

        for i in 0..4u64 {
            let src_shift = i * 8;
            let dst_shift = (3 - i) * 8;
            let bs = const_typed(out, U32, src_shift)?;
            let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), U32, &[val, bs])?;
            let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[byte, mask_ff])?;
            let ds = const_typed(out, U32, dst_shift)?;
            let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[masked, ds])?;
            result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[result, shifted])?;
        }

        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x30A, context))
    }
}

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

/// Emits a 32-bit rotate: the count is normalized the x86 way — masked to 5
/// bits (count mod 32), which for a 32-bit operand is exactly the rotate
/// primitive's own mod-width reduction — and the rotation itself is the
/// single `RotateLeft`/`RotateRight` primitive (no shl/lshr/or expansion).
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
                // x86 masks rotate counts to 5 bits for 32-bit operands
                // (count mod 32 — the operand-size quirk that also governs
                // 8/16-bit rotates); the primitive then reduces modulo the
                // 32-bit width, the same function, so there is no double
                // masking and no under-masking.
                let mask = const_u32(out, 0x1F)?;
                let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[count_32, mask])?;
                let prim = if $is_left {
                    PrimitiveOp::RotateLeft
                } else {
                    PrimitiveOp::RotateRight
                };
                let result = out.emit(SemanticOp::Primitive(prim), U32, &[val, count_masked])?;
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
                let val = out.read_operand(0, U32)?;
                let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
                let zero = const_u64(out, 0)?;
                // CL only (the rest of RCX is masked away), reduced modulo
                // 32 — the x86 normalization for 32-bit operands; the
                // primitive's mod-width reduction is identical.
                let mask = const_u64(out, 0x1F)?;
                let count_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
                let effective = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U32,
                    &[count_64, zero],
                )?;
                let prim = if $is_left {
                    PrimitiveOp::RotateLeft
                } else {
                    PrimitiveOp::RotateRight
                };
                let result = out.emit(SemanticOp::Primitive(prim), U32, &[val, effective])?;
                // A 32-bit destination zero-extends its parent register;
                // the operand write's view kind performs that widening.
                out.write_operand(0, result)?;
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
                write_logical_flags(out, result, 64)?;
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
        write_logical_flags(out, result, 64)?;

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
        // CMPXCHG r32, r32: compare EAX with dest; if equal ZF=1 and
        // dest=src, else ZF=0 and EAX=dest. Flags come from (eax - dest)
        // per the oracle (see the R64 provider's debt note).
        let dest = out.read_operand(0, U32)?;
        let src = out.read_operand(1, U32)?;
        let eax = out.read_register(RegisterId(register_id::GPR_BASE), U32)?;
        let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[dest, eax])?;
        let new_dest = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U32, &[eq, src, dest])?;
        let new_eax = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U32, &[eq, eax, dest])?;
        let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[eax, dest])?;
        write_sub_flags(out, diff, eax, dest, 32)?;
        out.write_operand(0, new_dest)?;
        let dest_is_acc = matches!(
            insn.operand(0).map(|op| op.kind),
            Some(angryier_semantics::OperandKind::Register(view))
                if view.parent.0 == register_id::GPR_BASE && view.bit_offset == 0 && view.width_bits == 32
        );
        if !dest_is_acc {
            out.write_register(RegisterId(register_id::GPR_BASE), new_eax)?;
        }
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

#[derive(Clone, Copy, Debug)]
pub struct ImulR32R32;
impl SemanticProvider for ImulR32R32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0xB0)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IMUL_R32_R32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U32)?;
        let right = out.read_operand(1, U32)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U32, &[left, right])?;
        write_mul_flags(out, left, right, 32)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0xB0, context))
    }
}
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
// xorps/xorpd xmm, xmm/m128 — packed bitwise XOR. Lane-wise byte XOR is the
// bitwise XOR regardless of the interpreted element type (float vs double
// vs integer), so the PXOR shape carries the whole family.
// ---------------------------------------------------------------------------

macro_rules! xor_packed {
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
                let dst = out.read_operand(0, I8X16)?;
                let src = out.read_operand(1, I8X16)?;
                let result = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I8X16,
                    &[dst, src],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

xor_packed!(XorpsXmmXmm, forms::XORPS_XMM_XMM, 0x2EC);
xor_packed!(XorpsXmmMem128, forms::XORPS_XMM_MEM128, 0x2ED);
xor_packed!(XorpdXmmXmm, forms::XORPD_XMM_XMM, 0x2F0);
xor_packed!(XorpdXmmMem128, forms::XORPD_XMM_MEM128, 0x2F1);

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
        let dst = out.read_operand(1, I32X4)?;
        let imm = insn
            .operand(2)
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
        let dst = out.read_operand(1, I16X8)?;
        let imm = insn
            .operand(2)
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

/// BLENDVPS xmm, xmm, <xmm0>: variable blend of single-precision float dwords per sign bit of XMM0.
#[derive(Clone, Copy, Debug)]
pub struct BlendvpsXmmXmm;

impl SemanticProvider for BlendvpsXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0D00)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BLENDVPS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I32X4)?;
        let src = out.read_operand(1, I32X4)?;
        let mask = if insn.operand(2).is_some() {
            out.read_operand(2, I32X4)?
        } else {
            out.read_register(RegisterId(register_id::ZMM_BASE), I32X4)?
        };
        let count_val = 31u128 | (31u128 << 32) | (31u128 << 64) | (31u128 << 96);
        let count = out.constant(I32X4, &count_val.to_le_bytes())?;
        let mask_dwords = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::ArithmeticShiftRight)),
            I32X4,
            &[mask, count],
        )?;
        let diff = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
            I32X4,
            &[dst, src],
        )?;
        let diff_masked = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
            I32X4,
            &[diff, mask_dwords],
        )?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
            I32X4,
            &[dst, diff_masked],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0D00, context))
    }
}

/// BLENDVPD xmm, xmm, <xmm0>: variable blend of double-precision float qwords per sign bit of XMM0.
#[derive(Clone, Copy, Debug)]
pub struct BlendvpdXmmXmm;

impl SemanticProvider for BlendvpdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0D01)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::BLENDVPD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, I64X2)?;
        let src = out.read_operand(1, I64X2)?;
        let mask = if insn.operand(2).is_some() {
            out.read_operand(2, I64X2)?
        } else {
            out.read_register(RegisterId(register_id::ZMM_BASE), I64X2)?
        };
        let count_val = 63u128 | (63u128 << 64);
        let count = out.constant(I64X2, &count_val.to_le_bytes())?;
        let mask_qwords = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::ArithmeticShiftRight)),
            I64X2,
            &[mask, count],
        )?;
        let diff = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
            I64X2,
            &[dst, src],
        )?;
        let diff_masked = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
            I64X2,
            &[diff, mask_qwords],
        )?;
        let result = out.emit(
            SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
            I64X2,
            &[dst, diff_masked],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0D01, context))
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
        let gpr = out.read_operand(1, U32)?;
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
        let dst = out.read_operand(0, U32)?;
        let src = out.read_operand(1, U32)?;
        let crc = out.emit(SemanticOp::Primitive(PrimitiveOp::Crc32), U32, &[dst, src])?;
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
        let dst = out.read_operand(0, U64)?;
        let zero = const_u64(out, 0)?;
        let dst32 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[dst, zero])?;
        let src = out.read_operand(1, U64)?;
        let crc = out.emit(SemanticOp::Primitive(PrimitiveOp::Crc32), U32, &[dst32, src])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[crc])?;
        out.write_operand(0, result)?;
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
        // PINSRD's source is a 32-bit register; reading it at U64 would
        // mismatch the decoded operand width.
        let dword = out.read_operand(1, U32)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let dword_idx = imm & 0x03;
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
mov_xmm_mem!(MovntdqaXmmMem, forms::MOVNTDQA_XMM_MEM, 0x0D02);

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
                               ri: ValueId| {
    write_add_flags(out, r, l, ri, 8)
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
                                 ri: ValueId| {
    write_add_flags(out, r, l, ri, 32)
});
flag_adapter!(flags_add_16, 16, |out: &mut dyn SemanticBuilder,
                                 r: ValueId,
                                 l: ValueId,
                                 ri: ValueId| {
    write_add_flags(out, r, l, ri, 16)
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
cmovcc_r32!(
    CmovlR32R32,
    forms::CMOVL_R32_R32,
    0x258,
    |out: &mut dyn SemanticBuilder| {
        // L: SF != OF.
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        let of = read_flag_set(out, rflags::OF_BIT)?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])
    }
);
cmovcc_r32!(
    CmovgeR32R32,
    forms::CMOVGE_R32_R32,
    0x259,
    |out: &mut dyn SemanticBuilder| {
        // GE: SF == OF.
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        let of = read_flag_set(out, rflags::OF_BIT)?;
        let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[ne])
    }
);
cmovcc_r32!(
    CmovleR32R32,
    forms::CMOVLE_R32_R32,
    0x25A,
    |out: &mut dyn SemanticBuilder| {
        // LE: ZF=1 OR SF != OF.
        let zf = read_flag_set(out, rflags::ZF_BIT)?;
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        let of = read_flag_set(out, rflags::OF_BIT)?;
        let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, ne])
    }
);
cmovcc_r32!(
    CmovgR32R32,
    forms::CMOVG_R32_R32,
    0x25B,
    |out: &mut dyn SemanticBuilder| {
        // G: ZF=0 AND SF == OF.
        let not_zf = read_flag_not_set(out, rflags::ZF_BIT)?;
        let sf = read_flag_set(out, rflags::SF_BIT)?;
        let of = read_flag_set(out, rflags::OF_BIT)?;
        let ne = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
        let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[ne])?;
        out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_zf, eq])
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
                    write_add_flags(out, result, left, right, 8)?;
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
                // 32-bit results write back zero-extended (x86 semantics);
                // the interpreter rejects a 4-byte write to an 8-byte GPR.
                let (quot_w, rem_w) = match $ty {
                    U32 => {
                        let q = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[quot_n])?;
                        let r = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[rem_n])?;
                        (q, r)
                    }
                    _ => (quot_n, rem_n),
                };
                out.write_register(RegisterId(register_id::GPR_BASE), quot_w)?;
                out.write_register(RegisterId(register_id::GPR_BASE + 2), rem_w)?;
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

/// `idiv r/mN` — signed divide; rdx:rax dividend, truncating quotient in
/// rax, dividend-signed remainder in rdx.
macro_rules! idiv_form {
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
                let divisor_w = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), $wide, &[divisor])?;
                let quot = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::SignedDiv),
                    $wide,
                    &[dividend, divisor_w],
                )?;
                let prod = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), $wide, &[quot, divisor_w])?;
                let rem = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $wide, &[dividend, prod])?;
                let zero = const_u64(out, 0)?;
                let quot_n = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[quot, zero])?;
                let rem_n = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[rem, zero])?;
                // 32-bit results write back zero-extended (x86 semantics);
                // the interpreter rejects a 4-byte write to an 8-byte GPR.
                let (quot_w, rem_w) = match $ty {
                    U32 => {
                        let q = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[quot_n])?;
                        let r = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[rem_n])?;
                        (q, r)
                    }
                    _ => (quot_n, rem_n),
                };
                out.write_register(RegisterId(register_id::GPR_BASE), quot_w)?;
                out.write_register(RegisterId(register_id::GPR_BASE + 2), rem_w)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

idiv_form!(IdivR64, forms::IDIV_R64, U64, U128, 0x303);

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
                // Compute equality BEFORE writing flags: a subsequent
                // RFLAGS read would be bound by the lowerer to the
                // pre-write value (stale), breaking the Select.
                let equal = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[dst, acc])?;
                let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[acc, dst])?;
                write_sub_flags(out, diff, acc, dst, scalar_bits($ty))?;
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

/// `movhlps xmm1, xmm2` — dest[63:0] = src[127:64]; dest[127:64] unchanged.
/// `movlhps xmm1, xmm2` — dest[127:64] = src[63:0]; dest[63:0] unchanged.
macro_rules! mov_lane_reg {
    ($name:ident, $form:expr, $high_to_low:expr, $rule:expr) => {
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
                let old = out.read_operand(0, U128)?;
                let src = out.read_operand(1, U128)?;
                let start = const_u64(out, if $high_to_low { 64 } else { 0 })?;
                let lane = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src, start])?;
                let lane128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[lane])?;
                let low_mask = const_u64(out, 0xFFFF_FFFF_FFFF_FFFF)?;
                let low_mask128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[low_mask])?;
                let sixty_four = const_u64(out, 64)?;
                let (kept, placed) = if $high_to_low {
                    // MOVHLPS: dest[63:0] = src[127:64], dest[127:64]
                    // unchanged — keep the destination's HIGH half and let
                    // the extracted source high half replace the low half.
                    let high_mask = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U128,
                        &[low_mask128, sixty_four],
                    )?;
                    let kept = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[old, high_mask])?;
                    (kept, lane128)
                } else {
                    // Keep the destination's low half; the extracted source
                    // low half lands in the high half.
                    let high_mask = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U128,
                        &[low_mask128, sixty_four],
                    )?;
                    let kept = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[old, high_mask])?;
                    let placed = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
                        U128,
                        &[lane128, sixty_four],
                    )?;
                    (kept, placed)
                };
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U128, &[kept, placed])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_lane_reg!(MovhlpsXmmXmm, forms::MOVHLPS_XMM_XMM, true, 0x2AE);
mov_lane_reg!(MovlhpsXmmXmm, forms::MOVLHPS_XMM_XMM, false, 0x2AF);

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
const F32X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::Float(FloatFormat::F32),
};
#[allow(dead_code)]
const I64X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::BitVec(64),
};
const F64X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::Float(FloatFormat::F64),
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

/// VEX.256 packed single-precision arithmetic, with a register or memory
/// third operand represented uniformly by the decoder.
macro_rules! packed_float_ymm {
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
                let left = out.read_operand(1, F32X8)?;
                let right = out.read_operand(2, F32X8)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32X4, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32X4, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[right, high_offset],
                )?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_low, right_low],
                )?;
                let high = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_high, right_high],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X8, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_float_ymm!(VaddpsYmmYmmYmm, forms::VADDPS_YMM_YMM_YMM, FloatingOp::Add, 0x600);
packed_float_ymm!(VaddpsYmmYmmMem, forms::VADDPS_YMM_YMM_MEM, FloatingOp::Add, 0x601);
packed_float_ymm!(VsubpsYmmYmmYmm, forms::VSUBPS_YMM_YMM_YMM, FloatingOp::Sub, 0x602);
packed_float_ymm!(VsubpsYmmYmmMem, forms::VSUBPS_YMM_YMM_MEM, FloatingOp::Sub, 0x603);
packed_float_ymm!(VmulpsYmmYmmYmm, forms::VMULPS_YMM_YMM_YMM, FloatingOp::Mul, 0x604);
packed_float_ymm!(VmulpsYmmYmmMem, forms::VMULPS_YMM_YMM_MEM, FloatingOp::Mul, 0x605);
packed_float_ymm!(VdivpsYmmYmmYmm, forms::VDIVPS_YMM_YMM_YMM, FloatingOp::Div, 0x606);
packed_float_ymm!(VdivpsYmmYmmMem, forms::VDIVPS_YMM_YMM_MEM, FloatingOp::Div, 0x607);

macro_rules! scalar_float_xmm {
    ($name:ident, $form:expr, $op:expr, $memory:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, F32X4)?;
                let zero = const_u64(out, 0)?;
                let thirty_two = const_u64(out, 32)?;
                let left = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src1, zero])?;
                let right = if $memory {
                    out.read_operand(2, F32)?
                } else {
                    let src2 = out.read_operand(2, F32X4)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src2, zero])?
                };
                let low = out.emit(SemanticOp::Float($op), F32, &[left, right])?;
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U96,
                    &[src1, thirty_two],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X4, &[low, upper])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

scalar_float_xmm!(
    VaddssXmmXmmXmm,
    forms::VADDSS_XMM_XMM_XMM,
    FloatingOp::Add,
    false,
    0x608
);
scalar_float_xmm!(
    VaddssXmmXmmMem32,
    forms::VADDSS_XMM_XMM_MEM32,
    FloatingOp::Add,
    true,
    0x609
);
scalar_float_xmm!(
    VsubssXmmXmmXmm,
    forms::VSUBSS_XMM_XMM_XMM,
    FloatingOp::Sub,
    false,
    0x60A
);
scalar_float_xmm!(
    VsubssXmmXmmMem32,
    forms::VSUBSS_XMM_XMM_MEM32,
    FloatingOp::Sub,
    true,
    0x60B
);
scalar_float_xmm!(
    VmulssXmmXmmXmm,
    forms::VMULSS_XMM_XMM_XMM,
    FloatingOp::Mul,
    false,
    0x60C
);
scalar_float_xmm!(
    VmulssXmmXmmMem32,
    forms::VMULSS_XMM_XMM_MEM32,
    FloatingOp::Mul,
    true,
    0x60D
);
scalar_float_xmm!(
    VdivssXmmXmmXmm,
    forms::VDIVSS_XMM_XMM_XMM,
    FloatingOp::Div,
    false,
    0x60E
);
scalar_float_xmm!(
    VdivssXmmXmmMem32,
    forms::VDIVSS_XMM_XMM_MEM32,
    FloatingOp::Div,
    true,
    0x60F
);

macro_rules! logic_ps_ymm {
    ($name:ident, $form:expr, $op:ident, $rule:expr) => {
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
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[right, high_offset],
                )?;
                let low = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::$op),
                    U128,
                    &[left_low, right_low],
                )?;
                let high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::$op),
                    U128,
                    &[left_high, right_high],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logic_ps_ymm!(VandpsYmmYmmYmm, forms::VANDPS_YMM_YMM_YMM, And, 0x610);
logic_ps_ymm!(VandpsYmmYmmMem, forms::VANDPS_YMM_YMM_MEM, And, 0x611);
logic_ps_ymm!(VorpsYmmYmmYmm, forms::VORPS_YMM_YMM_YMM, Or, 0x614);
logic_ps_ymm!(VorpsYmmYmmMem, forms::VORPS_YMM_YMM_MEM, Or, 0x615);

macro_rules! andn_ps_ymm {
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
                let left = out.read_operand(1, U256)?;
                let right = out.read_operand(2, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[right, high_offset],
                )?;
                let inverted_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U128, &[left_low])?;
                let inverted_high = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U128, &[left_high])?;
                let low = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::And),
                    U128,
                    &[inverted_low, right_low],
                )?;
                let high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::And),
                    U128,
                    &[inverted_high, right_high],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

andn_ps_ymm!(VandnpsYmmYmmYmm, forms::VANDNPS_YMM_YMM_YMM, 0x612);
andn_ps_ymm!(VandnpsYmmYmmMem, forms::VANDNPS_YMM_YMM_MEM, 0x613);

/// VEX.256 packed double-precision arithmetic.
macro_rules! packed_double_ymm {
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
                let left = out.read_operand(1, F64X4)?;
                let right = out.read_operand(2, F64X4)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64X2, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64X2, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[right, high_offset],
                )?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_low, right_low],
                )?;
                let high = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_high, right_high],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X4, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_double_ymm!(VaddpdYmmYmmYmm, forms::VADDPD_YMM_YMM_YMM, FloatingOp::Add, 0x1410);
packed_double_ymm!(VaddpdYmmYmmMem, forms::VADDPD_YMM_YMM_MEM, FloatingOp::Add, 0x1411);
packed_double_ymm!(VsubpdYmmYmmYmm, forms::VSUBPD_YMM_YMM_YMM, FloatingOp::Sub, 0x1412);
packed_double_ymm!(VsubpdYmmYmmMem, forms::VSUBPD_YMM_YMM_MEM, FloatingOp::Sub, 0x1413);
packed_double_ymm!(VmulpdYmmYmmYmm, forms::VMULPD_YMM_YMM_YMM, FloatingOp::Mul, 0x1414);
packed_double_ymm!(VmulpdYmmYmmMem, forms::VMULPD_YMM_YMM_MEM, FloatingOp::Mul, 0x1415);
packed_double_ymm!(VdivpdYmmYmmYmm, forms::VDIVPD_YMM_YMM_YMM, FloatingOp::Div, 0x1416);
packed_double_ymm!(VdivpdYmmYmmMem, forms::VDIVPD_YMM_YMM_MEM, FloatingOp::Div, 0x1417);

macro_rules! scalar_double_xmm {
    ($name:ident, $form:expr, $op:expr, $memory:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, F64X2)?;
                let zero = const_u64(out, 0)?;
                let sixty_four = const_u64(out, 64)?;
                let left = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src1, zero])?;
                let right = if $memory {
                    out.read_operand(2, F64)?
                } else {
                    let src2 = out.read_operand(2, F64X2)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src2, zero])?
                };
                let low = out.emit(SemanticOp::Float($op), F64, &[left, right])?;
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, sixty_four],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X2, &[low, upper])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

scalar_double_xmm!(
    VaddsdXmmXmmXmm,
    forms::VADDSD_XMM_XMM_XMM,
    FloatingOp::Add,
    false,
    0x1418
);
scalar_double_xmm!(
    VaddsdXmmXmmMem64,
    forms::VADDSD_XMM_XMM_MEM64,
    FloatingOp::Add,
    true,
    0x1419
);
scalar_double_xmm!(
    VsubsdXmmXmmXmm,
    forms::VSUBSD_XMM_XMM_XMM,
    FloatingOp::Sub,
    false,
    0x141A
);
scalar_double_xmm!(
    VsubsdXmmXmmMem64,
    forms::VSUBSD_XMM_XMM_MEM64,
    FloatingOp::Sub,
    true,
    0x141B
);
scalar_double_xmm!(
    VmulsdXmmXmmXmm,
    forms::VMULSD_XMM_XMM_XMM,
    FloatingOp::Mul,
    false,
    0x141C
);
scalar_double_xmm!(
    VmulsdXmmXmmMem64,
    forms::VMULSD_XMM_XMM_MEM64,
    FloatingOp::Mul,
    true,
    0x141D
);
scalar_double_xmm!(
    VdivsdXmmXmmXmm,
    forms::VDIVSD_XMM_XMM_XMM,
    FloatingOp::Div,
    false,
    0x141E
);
scalar_double_xmm!(
    VdivsdXmmXmmMem64,
    forms::VDIVSD_XMM_XMM_MEM64,
    FloatingOp::Div,
    true,
    0x141F
);

logic_ps_ymm!(VandpdYmmYmmYmm, forms::VANDPD_YMM_YMM_YMM, And, 0x1420);
logic_ps_ymm!(VandpdYmmYmmMem, forms::VANDPD_YMM_YMM_MEM, And, 0x1421);
andn_ps_ymm!(VandnpdYmmYmmYmm, forms::VANDNPD_YMM_YMM_YMM, 0x1422);
andn_ps_ymm!(VandnpdYmmYmmMem, forms::VANDNPD_YMM_YMM_MEM, 0x1423);
logic_ps_ymm!(VorpdYmmYmmYmm, forms::VORPD_YMM_YMM_YMM, Or, 0x1424);
logic_ps_ymm!(VorpdYmmYmmMem, forms::VORPD_YMM_YMM_MEM, Or, 0x1425);
logic_ps_ymm!(VxorpdYmmYmmYmm, forms::VXORPD_YMM_YMM_YMM, Xor, 0x1426);
logic_ps_ymm!(VxorpdYmmYmmMem, forms::VXORPD_YMM_YMM_MEM, Xor, 0x1427);

// ---------------------------------------------------------------------------
// AVX conversion, blend, and permutation providers (0x1428..0x1439)
// ---------------------------------------------------------------------------

/// VCVTSS2SD xmm1, xmm2, xmm3/m32: convert scalar single to double, upper 64 bits from xmm2.
macro_rules! vcvt_ss2sd {
    ($name:ident, $form:expr, $memory:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, F64X2)?;
                let zero = const_u64(out, 0)?;
                let sixty_four = const_u64(out, 64)?;
                let src2 = if $memory {
                    out.read_operand(2, F32)?
                } else {
                    let v = out.read_operand(2, F32X4)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[v, zero])?
                };
                let converted = out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[src2])?;
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, sixty_four],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F64X2,
                    &[converted, upper],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vcvt_ss2sd!(Vcvtss2sdXmmXmmXmm, forms::VCVTSS2SD_XMM_XMM_XMM, false, 0x1428);
vcvt_ss2sd!(Vcvtss2sdXmmXmmMem32, forms::VCVTSS2SD_XMM_XMM_MEM32, true, 0x1429);

/// VCVTSD2SS xmm1, xmm2, xmm3/m64: convert scalar double to single, upper 96 bits from xmm2.
macro_rules! vcvt_sd2ss {
    ($name:ident, $form:expr, $memory:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, F32X4)?;
                let zero = const_u64(out, 0)?;
                let thirty_two = const_u64(out, 32)?;
                let src2 = if $memory {
                    out.read_operand(2, F64)?
                } else {
                    let v = out.read_operand(2, F64X2)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[v, zero])?
                };
                let converted = out.emit(SemanticOp::Float(FloatingOp::Convert), F32, &[src2])?;
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U96,
                    &[src1, thirty_two],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F32X4,
                    &[converted, upper],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vcvt_sd2ss!(Vcvtsd2ssXmmXmmXmm, forms::VCVTSD2SS_XMM_XMM_XMM, false, 0x142A);
vcvt_sd2ss!(Vcvtsd2ssXmmXmmMem64, forms::VCVTSD2SS_XMM_XMM_MEM64, true, 0x142B);

/// VBLENDPS ymm1, ymm2, ymm3/m256, imm8: conditional blend of 8 single-precision floats based on imm8 bits.
macro_rules! vblend_ps {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let imm = insn
                    .operand(3)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0) as u8;
                let mut mask_bytes = [0u8; 32];
                for i in 0..8 {
                    if (imm >> i) & 1 == 1 {
                        mask_bytes[i * 4..i * 4 + 4].fill(0xFF);
                    }
                }
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src1_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src1, zero])?;
                let src1_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[src1, high_offset],
                )?;
                let src2_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src2, zero])?;
                let src2_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[src2, high_offset],
                )?;
                let mask_lo = out.constant(U128, &mask_bytes[..16])?;
                let mask_hi = out.constant(U128, &mask_bytes[16..])?;
                let diff_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U128, &[src1_lo, src2_lo])?;
                let diff_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U128, &[src1_hi, src2_hi])?;
                let diff_masked_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[diff_lo, mask_lo])?;
                let diff_masked_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[diff_hi, mask_hi])?;
                let res_lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Xor),
                    U128,
                    &[src1_lo, diff_masked_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Xor),
                    U128,
                    &[src1_hi, diff_masked_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U256,
                    &[res_lo, res_hi],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vblend_ps!(VblendpsYmmYmmYmmImm8, forms::VBLENDPS_YMM_YMM_YMM_IMM8, 0x142C);
vblend_ps!(VblendpsYmmYmmMemImm8, forms::VBLENDPS_YMM_YMM_MEM_IMM8, 0x142D);

/// VBLENDPD ymm1, ymm2, ymm3/m256, imm8: conditional blend of 4 double-precision floats based on imm8 bits.
macro_rules! vblend_pd {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let imm = insn
                    .operand(3)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0) as u8;
                let mut mask_bytes = [0u8; 32];
                for i in 0..4 {
                    if (imm >> i) & 1 == 1 {
                        mask_bytes[i * 8..i * 8 + 8].fill(0xFF);
                    }
                }
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src1_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src1, zero])?;
                let src1_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[src1, high_offset],
                )?;
                let src2_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src2, zero])?;
                let src2_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[src2, high_offset],
                )?;
                let mask_lo = out.constant(U128, &mask_bytes[..16])?;
                let mask_hi = out.constant(U128, &mask_bytes[16..])?;
                let diff_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U128, &[src1_lo, src2_lo])?;
                let diff_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U128, &[src1_hi, src2_hi])?;
                let diff_masked_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[diff_lo, mask_lo])?;
                let diff_masked_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U128, &[diff_hi, mask_hi])?;
                let res_lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Xor),
                    U128,
                    &[src1_lo, diff_masked_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Xor),
                    U128,
                    &[src1_hi, diff_masked_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U256,
                    &[res_lo, res_hi],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vblend_pd!(VblendpdYmmYmmYmmImm8, forms::VBLENDPD_YMM_YMM_YMM_IMM8, 0x142E);
vblend_pd!(VblendpdYmmYmmMemImm8, forms::VBLENDPD_YMM_YMM_MEM_IMM8, 0x142F);

/// VBLENDVPS ymm1, ymm2, ymm3/m256, ymm4: variable blend of 8 single-precision floats based on mask sign bits.
macro_rules! vblendv_ps {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let mask_ymm = out.read_operand(3, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src1_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I32X4, &[src1, zero])?;
                let src1_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I32X4,
                    &[src1, high_offset],
                )?;
                let src2_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I32X4, &[src2, zero])?;
                let src2_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I32X4,
                    &[src2, high_offset],
                )?;
                let mask_lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I32X4,
                    &[mask_ymm, zero],
                )?;
                let mask_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I32X4,
                    &[mask_ymm, high_offset],
                )?;
                let count_val = 31u128 | (31u128 << 32) | (31u128 << 64) | (31u128 << 96);
                let count = out.constant(I32X4, &count_val.to_le_bytes())?;
                let mask_dwords_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::ArithmeticShiftRight)),
                    I32X4,
                    &[mask_lo, count],
                )?;
                let mask_dwords_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::ArithmeticShiftRight)),
                    I32X4,
                    &[mask_hi, count],
                )?;
                let diff_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I32X4,
                    &[src1_lo, src2_lo],
                )?;
                let diff_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I32X4,
                    &[src1_hi, src2_hi],
                )?;
                let diff_masked_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
                    I32X4,
                    &[diff_lo, mask_dwords_lo],
                )?;
                let diff_masked_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
                    I32X4,
                    &[diff_hi, mask_dwords_hi],
                )?;
                let res_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I32X4,
                    &[src1_lo, diff_masked_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I32X4,
                    &[src1_hi, diff_masked_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U256,
                    &[res_lo, res_hi],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vblendv_ps!(VblendvpsYmmYmmYmmYmm, forms::VBLENDVPS_YMM_YMM_YMM_YMM, 0x1430);
vblendv_ps!(VblendvpsYmmYmmMemYmm, forms::VBLENDVPS_YMM_YMM_MEM_YMM, 0x1431);

/// VBLENDVPD ymm1, ymm2, ymm3/m256, ymm4: variable blend of 4 double-precision floats based on mask sign bits.
macro_rules! vblendv_pd {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let mask_ymm = out.read_operand(3, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src1_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I64X2, &[src1, zero])?;
                let src1_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I64X2,
                    &[src1, high_offset],
                )?;
                let src2_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I64X2, &[src2, zero])?;
                let src2_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I64X2,
                    &[src2, high_offset],
                )?;
                let mask_lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I64X2,
                    &[mask_ymm, zero],
                )?;
                let mask_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I64X2,
                    &[mask_ymm, high_offset],
                )?;
                let count_val = 63u128 | (63u128 << 64);
                let count = out.constant(I64X2, &count_val.to_le_bytes())?;
                let mask_qwords_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::ArithmeticShiftRight)),
                    I64X2,
                    &[mask_lo, count],
                )?;
                let mask_qwords_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::ArithmeticShiftRight)),
                    I64X2,
                    &[mask_hi, count],
                )?;
                let diff_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I64X2,
                    &[src1_lo, src2_lo],
                )?;
                let diff_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I64X2,
                    &[src1_hi, src2_hi],
                )?;
                let diff_masked_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
                    I64X2,
                    &[diff_lo, mask_qwords_lo],
                )?;
                let diff_masked_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::And)),
                    I64X2,
                    &[diff_hi, mask_qwords_hi],
                )?;
                let res_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I64X2,
                    &[src1_lo, diff_masked_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise(PrimitiveOp::Xor)),
                    I64X2,
                    &[src1_hi, diff_masked_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U256,
                    &[res_lo, res_hi],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vblendv_pd!(VblendvpdYmmYmmYmmYmm, forms::VBLENDVPD_YMM_YMM_YMM_YMM, 0x1432);
vblendv_pd!(VblendvpdYmmYmmMemYmm, forms::VBLENDVPD_YMM_YMM_MEM_YMM, 0x1433);

/// VPERM2F128 ymm1, ymm2, ymm3/m256, imm8: permute 128-bit floating-point fields.
macro_rules! vperm2f128 {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let imm = insn
                    .operand(3)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0) as u8;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src1_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src1, zero])?;
                let src1_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[src1, high_offset],
                )?;
                let src2_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U128, &[src2, zero])?;
                let src2_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U128,
                    &[src2, high_offset],
                )?;
                let zero_128 = out.constant(U128, &[0u8; 16])?;

                let lo_part = if (imm & 0x08) != 0 {
                    zero_128
                } else {
                    match imm & 0x03 {
                        0 => src1_lo,
                        1 => src1_hi,
                        2 => src2_lo,
                        _ => src2_hi,
                    }
                };
                let hi_part = if (imm & 0x80) != 0 {
                    zero_128
                } else {
                    match (imm >> 4) & 0x03 {
                        0 => src1_lo,
                        1 => src1_hi,
                        2 => src2_lo,
                        _ => src2_hi,
                    }
                };
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U256,
                    &[lo_part, hi_part],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vperm2f128!(Vperm2f128YmmYmmYmmImm8, forms::VPERM2F128_YMM_YMM_YMM_IMM8, 0x1434);
vperm2f128!(Vperm2f128YmmYmmMemImm8, forms::VPERM2F128_YMM_YMM_MEM_IMM8, 0x1435);

/// VPERMILPS ymm1, ymm2/m256, imm8: in-lane permute of single-precision floats within 128-bit halves.
macro_rules! vpermil_ps {
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
                let imm = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let imm_const = const_u64(out, imm)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I32X4, &[src, zero])?;
                let src_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I32X4,
                    &[src, high_offset],
                )?;
                let lo = out.emit(
                    SemanticOp::Vector(VectorOp::Shuffle32),
                    I32X4,
                    &[src_lo, imm_const],
                )?;
                let hi = out.emit(
                    SemanticOp::Vector(VectorOp::Shuffle32),
                    I32X4,
                    &[src_hi, imm_const],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[lo, hi])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vpermil_ps!(VpermilpsYmmYmmImm8, forms::VPERMILPS_YMM_YMM_IMM8, 0x1436);
vpermil_ps!(VpermilpsYmmMemImm8, forms::VPERMILPS_YMM_MEM_IMM8, 0x1437);

/// VPERMILPD ymm1, ymm2/m256, imm8: in-lane permute of double-precision floats within 128-bit halves.
macro_rules! vpermil_pd {
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
                let imm = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0) as u8;
                let zero = const_u64(out, 0)?;
                let sixty_four = const_u64(out, 64)?;
                let one_twenty_eight = const_u64(out, 128)?;
                let one_ninety_two = const_u64(out, 192)?;

                let q0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src, zero])?;
                let q1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src, sixty_four],
                )?;
                let q2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src, one_twenty_eight],
                )?;
                let q3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src, one_ninety_two],
                )?;

                let lo_q0 = if (imm & 1) == 0 { q0 } else { q1 };
                let lo_q1 = if (imm & 2) == 0 { q0 } else { q1 };
                let hi_q0 = if (imm & 4) == 0 { q2 } else { q3 };
                let hi_q1 = if (imm & 8) == 0 { q2 } else { q3 };

                let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[lo_q0, lo_q1])?;
                let high = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[hi_q0, hi_q1])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vpermil_pd!(VpermilpdYmmYmmImm8, forms::VPERMILPD_YMM_YMM_IMM8, 0x1438);
vpermil_pd!(VpermilpdYmmMemImm8, forms::VPERMILPD_YMM_MEM_IMM8, 0x1439);

/// VSHUFPS ymm1, ymm2, ymm3/m256, imm8: shuffle single-precision floats within 128-bit halves.
macro_rules! vshuf_ps {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let imm = insn
                    .operand(3)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0) as u8;

                let c0 = const_u64(out, 0)?;
                let c32 = const_u64(out, 32)?;
                let c64 = const_u64(out, 64)?;
                let c96 = const_u64(out, 96)?;
                let c128 = const_u64(out, 128)?;
                let c160 = const_u64(out, 160)?;
                let c192 = const_u64(out, 192)?;
                let c224 = const_u64(out, 224)?;

                let s1_d0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c0])?;
                let s1_d1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c32])?;
                let s1_d2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c64])?;
                let s1_d3 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c96])?;
                let s1_d4 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c128])?;
                let s1_d5 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c160])?;
                let s1_d6 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c192])?;
                let s1_d7 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src1, c224])?;

                let s2_d0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c0])?;
                let s2_d1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c32])?;
                let s2_d2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c64])?;
                let s2_d3 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c96])?;
                let s2_d4 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c128])?;
                let s2_d5 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c160])?;
                let s2_d6 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c192])?;
                let s2_d7 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src2, c224])?;

                let sel1_lo = |sel: u8| match sel & 3 {
                    0 => s1_d0,
                    1 => s1_d1,
                    2 => s1_d2,
                    _ => s1_d3,
                };
                let sel2_lo = |sel: u8| match sel & 3 {
                    0 => s2_d0,
                    1 => s2_d1,
                    2 => s2_d2,
                    _ => s2_d3,
                };
                let sel1_hi = |sel: u8| match sel & 3 {
                    0 => s1_d4,
                    1 => s1_d5,
                    2 => s1_d6,
                    _ => s1_d7,
                };
                let sel2_hi = |sel: u8| match sel & 3 {
                    0 => s2_d4,
                    1 => s2_d5,
                    2 => s2_d6,
                    _ => s2_d7,
                };

                let lo_0 = sel1_lo(imm);
                let lo_1 = sel1_lo(imm >> 2);
                let lo_2 = sel2_lo(imm >> 4);
                let lo_3 = sel2_lo(imm >> 6);

                let hi_0 = sel1_hi(imm);
                let hi_1 = sel1_hi(imm >> 2);
                let hi_2 = sel2_hi(imm >> 4);
                let hi_3 = sel2_hi(imm >> 6);

                let lo_q0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[lo_0, lo_1])?;
                let lo_q1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[lo_2, lo_3])?;
                let hi_q0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[hi_0, hi_1])?;
                let hi_q1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[hi_2, hi_3])?;

                let lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[lo_q0, lo_q1])?;
                let hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[hi_q0, hi_q1])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[lo, hi])?;

                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vshuf_ps!(VshufpsYmmYmmYmmImm8, forms::VSHUFPS_YMM_YMM_YMM_IMM8, 0x143A);
vshuf_ps!(VshufpsYmmYmmMemImm8, forms::VSHUFPS_YMM_YMM_MEM_IMM8, 0x143B);

/// VSHUFPD ymm1, ymm2, ymm3/m256, imm8: shuffle double-precision floats within 128-bit halves.
macro_rules! vshuf_pd {
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
                let src1 = out.read_operand(1, U256)?;
                let src2 = out.read_operand(2, U256)?;
                let imm = insn
                    .operand(3)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0) as u8;

                let zero = const_u64(out, 0)?;
                let sixty_four = const_u64(out, 64)?;
                let one_twenty_eight = const_u64(out, 128)?;
                let one_ninety_two = const_u64(out, 192)?;

                let s1_q0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src1, zero])?;
                let s1_q1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, sixty_four],
                )?;
                let s1_q2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, one_twenty_eight],
                )?;
                let s1_q3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, one_ninety_two],
                )?;

                let s2_q0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src2, zero])?;
                let s2_q1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src2, sixty_four],
                )?;
                let s2_q2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src2, one_twenty_eight],
                )?;
                let s2_q3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src2, one_ninety_two],
                )?;

                let out_q0 = if (imm & 1) == 0 { s1_q0 } else { s1_q1 };
                let out_q1 = if (imm & 2) == 0 { s2_q0 } else { s2_q1 };
                let out_q2 = if (imm & 4) == 0 { s1_q2 } else { s1_q3 };
                let out_q3 = if (imm & 8) == 0 { s2_q2 } else { s2_q3 };

                let low = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U128,
                    &[out_q0, out_q1],
                )?;
                let high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    U128,
                    &[out_q2, out_q3],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;

                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vshuf_pd!(VshufpdYmmYmmYmmImm8, forms::VSHUFPD_YMM_YMM_YMM_IMM8, 0x143C);
vshuf_pd!(VshufpdYmmYmmMemImm8, forms::VSHUFPD_YMM_YMM_MEM_IMM8, 0x143D);

/// VEX.256 packed unpack (interleave) operations within 128-bit halves.
macro_rules! vunpck_ymm {
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
                let left = out.read_operand(1, U256)?;
                let right = out.read_operand(2, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[right, high_offset],
                )?;
                let low = out.emit(SemanticOp::Vector($op), $ty, &[left_low, right_low])?;
                let high = out.emit(SemanticOp::Vector($op), $ty, &[left_high, right_high])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

vunpck_ymm!(
    VunpcklpsYmmYmmYmm,
    forms::VUNPCKLPS_YMM_YMM_YMM,
    VectorOp::Unpack,
    I32X4,
    0x143E
);
vunpck_ymm!(
    VunpcklpsYmmYmmMem,
    forms::VUNPCKLPS_YMM_YMM_MEM,
    VectorOp::Unpack,
    I32X4,
    0x143F
);
vunpck_ymm!(
    VunpckhpsYmmYmmYmm,
    forms::VUNPCKHPS_YMM_YMM_YMM,
    VectorOp::UnpackHigh,
    I32X4,
    0x1440
);
vunpck_ymm!(
    VunpckhpsYmmYmmMem,
    forms::VUNPCKHPS_YMM_YMM_MEM,
    VectorOp::UnpackHigh,
    I32X4,
    0x1441
);
vunpck_ymm!(
    VunpcklpdYmmYmmYmm,
    forms::VUNPCKLPD_YMM_YMM_YMM,
    VectorOp::Unpack,
    I64X2,
    0x1442
);
vunpck_ymm!(
    VunpcklpdYmmYmmMem,
    forms::VUNPCKLPD_YMM_YMM_MEM,
    VectorOp::Unpack,
    I64X2,
    0x1443
);
vunpck_ymm!(
    VunpckhpdYmmYmmYmm,
    forms::VUNPCKHPD_YMM_YMM_YMM,
    VectorOp::UnpackHigh,
    I64X2,
    0x1444
);
vunpck_ymm!(
    VunpckhpdYmmYmmMem,
    forms::VUNPCKHPD_YMM_YMM_MEM,
    VectorOp::UnpackHigh,
    I64X2,
    0x1445
);

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

fn broadcast_u8_to_u256(out: &mut dyn SemanticBuilder, byte_val: ValueId) -> Result<ValueId, SemanticError> {
    let u16_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U16, &[byte_val, byte_val])?;
    let u32_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U32, &[u16_val, u16_val])?;
    let u64_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[u32_val, u32_val])?;
    let u128_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[u64_val, u64_val])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[u128_val, u128_val])
}

fn broadcast_u16_to_u256(out: &mut dyn SemanticBuilder, word_val: ValueId) -> Result<ValueId, SemanticError> {
    let u32_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U32, &[word_val, word_val])?;
    let u64_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[u32_val, u32_val])?;
    let u128_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[u64_val, u64_val])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[u128_val, u128_val])
}

fn broadcast_u32_to_u256(out: &mut dyn SemanticBuilder, dword_val: ValueId) -> Result<ValueId, SemanticError> {
    let u64_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U64, &[dword_val, dword_val])?;
    let u128_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U128, &[u64_val, u64_val])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[u128_val, u128_val])
}

fn broadcast_u64_to_u256(out: &mut dyn SemanticBuilder, qword_val: ValueId) -> Result<ValueId, SemanticError> {
    let u128_val = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Concat),
        U128,
        &[qword_val, qword_val],
    )?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[u128_val, u128_val])
}

/// `vpbroadcast* ymm, xmm/r/m` — broadcast the low lane across all 32 bytes.
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
                let zero = const_u64(out, 0)?;
                let result = match $lane_bits {
                    8 => {
                        let b = if $src_ty == U8 {
                            src
                        } else {
                            out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U8, &[src, zero])?
                        };
                        broadcast_u8_to_u256(out, b)?
                    }
                    16 => {
                        let w = if $src_ty == U16 {
                            src
                        } else {
                            out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[src, zero])?
                        };
                        broadcast_u16_to_u256(out, w)?
                    }
                    32 => {
                        let d = if $src_ty == U32 {
                            src
                        } else {
                            out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[src, zero])?
                        };
                        broadcast_u32_to_u256(out, d)?
                    }
                    64 => {
                        let q = if $src_ty == U64 {
                            src
                        } else {
                            out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[src, zero])?
                        };
                        broadcast_u64_to_u256(out, q)?
                    }
                    _ => return Err(SemanticError::InvalidWidth),
                };
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
broadcast_ymm!(VpbroadcastwYmmXmm, forms::VPBROADCASTW_YMM_XMM, U128, 16, 0x0B38);
broadcast_ymm!(VpbroadcastdYmmXmm, forms::VPBROADCASTD_YMM_XMM, U128, 32, 0x0B39);
broadcast_ymm!(VpbroadcastbYmmR32, forms::VPBROADCASTB_YMM_R32, U32, 8, 0x0B3A);
broadcast_ymm!(VpbroadcastwYmmR32, forms::VPBROADCASTW_YMM_R32, U32, 16, 0x0B3B);
broadcast_ymm!(VpbroadcastdYmmR32, forms::VPBROADCASTD_YMM_R32, U32, 32, 0x0B3C);
broadcast_ymm!(VpbroadcastqYmmR64, forms::VPBROADCASTQ_YMM_R64, U64, 64, 0x0B3D);

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

// ---------------------------------------------------------------------------
// ADD r16, r16
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AddR16R16;

impl SemanticProvider for AddR16R16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x304)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::ADD_R16_R16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U16)?;
        let right = out.read_operand(1, U16)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[left, right])?;
        write_add_flags(out, result, left, right, 16)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x304, context))
    }
}

// ---------------------------------------------------------------------------
// INC/DEC r8 — CF preserved, other arithmetic flags at 8-bit width
// ---------------------------------------------------------------------------

macro_rules! incdec_r8 {
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
                let operand = out.read_operand(0, U8)?;
                let one = const_typed(out, U8, 1)?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[operand, one])?;
                if $op == PrimitiveOp::Add {
                    write_add_flags_preserve_cf(out, result, operand, one, 8)?;
                } else {
                    write_sub_flags_preserve_cf(out, result, operand, one, 8)?;
                }
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

incdec_r8!(IncR8, forms::INC_R8, PrimitiveOp::Add, 0x305);
incdec_r8!(DecR8, forms::DEC_R8, PrimitiveOp::Sub, 0x306);

/// INC/DEC with a memory operand (driver refcount shapes). Semantically
/// identical to the register forms — read operand 0, ±1, write back, with
/// the CF-preserving flag policy. LOCK-prefixed encodings share these
/// forms (single-vCPU RMW; ordering semantics debt-recorded).
macro_rules! incdec_mem {
    ($name:ident, $form:expr, $op:expr, $rule:expr, $ty:expr, $width:expr) => {
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
                let one = const_typed(out, $ty, 1)?;
                let result = out.emit(SemanticOp::Primitive($op), $ty, &[operand, one])?;
                if $op == PrimitiveOp::Add {
                    write_add_flags_preserve_cf(out, result, operand, one, $width)?;
                } else {
                    write_sub_flags_preserve_cf(out, result, operand, one, $width)?;
                }
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

incdec_mem!(IncMem8, forms::INC_MEM8, PrimitiveOp::Add, 0x540, U8, 8);
incdec_mem!(IncMem16, forms::INC_MEM16, PrimitiveOp::Add, 0x541, U16, 16);
incdec_mem!(IncMem32, forms::INC_MEM32, PrimitiveOp::Add, 0x542, U32, 32);
incdec_mem!(IncMem64, forms::INC_MEM64, PrimitiveOp::Add, 0x543, U64, 64);
incdec_mem!(DecMem8, forms::DEC_MEM8, PrimitiveOp::Sub, 0x544, U8, 8);
incdec_mem!(DecMem16, forms::DEC_MEM16, PrimitiveOp::Sub, 0x545, U16, 16);
incdec_mem!(DecMem32, forms::DEC_MEM32, PrimitiveOp::Sub, 0x546, U32, 32);
incdec_mem!(DecMem64, forms::DEC_MEM64, PrimitiveOp::Sub, 0x547, U64, 64);

// ---------------------------------------------------------------------------
// NEG/NOT r8
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct NegR8;

impl SemanticProvider for NegR8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x307)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NEG_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U8)?;
        let zero = const_typed(out, U8, 0)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[zero, operand])?;
        write_sub_flags(out, result, zero, operand, 8)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x307, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct NotR8;

impl SemanticProvider for NotR8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x308)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::NOT_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U8)?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U8, &[operand])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x308, context))
    }
}

// ---------------------------------------------------------------------------
// SHL r8, imm8
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct ShlR8Imm8;

impl SemanticProvider for ShlR8Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x309)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SHL_R8_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(0, U8)?;
        let count = out.read_operand(1, U8)?;
        let mask = const_typed(out, U8, 0x1F)?;
        let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U8, &[count, mask])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U8, &[left, count_masked])?;
        write_shift_flags(out, left, count_masked, result, crate::providers::ShiftKind::Left, 8)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x309, context))
    }
}

// ---------------------------------------------------------------------------
// Extended x87 FPU family
// ---------------------------------------------------------------------------

const U80: SemanticType = SemanticType::Scalar(ScalarType::BitVec(80));
const INDEFINITE_F64: u64 = 0xFFF8_0000_0000_0000;
const EMPTY_TAG: u16 = 0xFFFF;

fn const_u16(out: &mut dyn SemanticBuilder, value: u16) -> Result<ValueId, SemanticError> {
    out.constant(U16, &value.to_le_bytes())
}

fn const_f64(out: &mut dyn SemanticBuilder, bits: u64) -> Result<ValueId, SemanticError> {
    out.constant(F64, &bits.to_le_bytes())
}

fn x87_reg(index: u32) -> RegisterId {
    RegisterId(angryier_arch_intel64::register_id::X87_BASE + index)
}

fn x87_read_st(out: &mut dyn SemanticBuilder, index: u32) -> Result<ValueId, SemanticError> {
    out.read_register(x87_reg(index), U80)
}

fn x87_write_st(out: &mut dyn SemanticBuilder, index: u32, value: ValueId) -> Result<(), SemanticError> {
    out.write_register(x87_reg(index), value)?;
    Ok(())
}

fn x87_pack_st(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<ValueId, SemanticError> {
    let zero_tag = const_u16(out, 0)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U80, &[value, zero_tag])
}

fn x87_unpack_st(out: &mut dyn SemanticBuilder, raw: ValueId) -> Result<ValueId, SemanticError> {
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

fn x87_empty_slot(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    let mut bytes = [0u8; 10];
    bytes[8..].copy_from_slice(&EMPTY_TAG.to_le_bytes());
    out.constant(U80, &bytes)
}

fn x87_push_st(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<(), SemanticError> {
    let bottom = x87_read_st(out, u32::from(angryier_arch_intel64::X87_COUNT) - 1)?;
    let sixty_four = const_u64(out, 64)?;
    let bottom_tag = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[bottom, sixty_four])?;
    let empty_tag = const_u16(out, EMPTY_TAG)?;
    let has_room = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[bottom_tag, empty_tag])?;
    let indefinite = const_f64(out, INDEFINITE_F64)?;
    let pushed = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        F64,
        &[has_room, value, indefinite],
    )?;

    let mut sources = Vec::with_capacity(7);
    for index in 0..(angryier_arch_intel64::X87_COUNT - 1) {
        sources.push(x87_read_st(out, u32::from(index))?);
    }
    let packed = x87_pack_st(out, pushed)?;
    for index in 0..(angryier_arch_intel64::X87_COUNT - 1) {
        x87_write_st(out, u32::from(index + 1), sources[usize::from(index)])?;
    }
    x87_write_st(out, 0, packed)?;
    crate::x87::sw_adjust_top(out, -1)?;
    Ok(())
}

fn x87_pop_st_regs(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    let mut sources = Vec::with_capacity(7);
    for index in 1..angryier_arch_intel64::X87_COUNT {
        sources.push(x87_read_st(out, u32::from(index))?);
    }
    let empty = x87_empty_slot(out)?;
    for index in 0..(angryier_arch_intel64::X87_COUNT - 1) {
        x87_write_st(out, u32::from(index), sources[usize::from(index)])?;
    }
    x87_write_st(out, u32::from(angryier_arch_intel64::X87_COUNT) - 1, empty)?;
    Ok(())
}

fn x87_pop_st(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    x87_pop_st_regs(out)?;
    crate::x87::sw_adjust_top(out, 1)?;
    Ok(())
}

fn x87_pop2_st_regs(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    let mut sources = Vec::with_capacity(6);
    for index in 2..angryier_arch_intel64::X87_COUNT {
        sources.push(x87_read_st(out, u32::from(index))?);
    }
    let empty = x87_empty_slot(out)?;
    for index in 0..(angryier_arch_intel64::X87_COUNT - 2) {
        x87_write_st(out, u32::from(index), sources[usize::from(index)])?;
    }
    x87_write_st(out, u32::from(angryier_arch_intel64::X87_COUNT) - 2, empty)?;
    x87_write_st(out, u32::from(angryier_arch_intel64::X87_COUNT) - 1, empty)?;
    Ok(())
}

#[allow(dead_code)]
fn x87_pop2_st(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    x87_pop2_st_regs(out)?;
    crate::x87::sw_adjust_top(out, 2)?;
    Ok(())
}

fn x87_operand_st_index(insn: &dyn DecodedInstructionView, index: u8) -> Result<u32, SemanticError> {
    match insn.operand(index).map(|operand| operand.kind) {
        Some(OperandKind::Register(view)) if view.parent.0 >= angryier_arch_intel64::register_id::X87_BASE => {
            Ok(view.parent.0 - angryier_arch_intel64::register_id::X87_BASE)
        }
        _ => Err(SemanticError::InvalidOperand),
    }
}

fn x87_float_op(
    out: &mut dyn SemanticBuilder,
    op: FloatingOp,
    reversed: bool,
    left: ValueId,
    right: ValueId,
) -> Result<ValueId, SemanticError> {
    let (a, b) = if reversed { (right, left) } else { (left, right) };
    out.emit(SemanticOp::Float(op), F64, &[a, b])
}

fn int_to_f64(out: &mut dyn SemanticBuilder, val: ValueId, src_ty: SemanticType) -> Result<ValueId, SemanticError> {
    let s64 = if src_ty == U64 {
        val
    } else {
        out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[val])?
    };
    let zero64 = const_u64(out, 0)?;
    let is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[s64, zero64])?;
    let is_neg = out.emit(SemanticOp::Primitive(PrimitiveOp::Slt), U1, &[s64, zero64])?;
    let sign_mask = const_u64(out, 1u64 << 63)?;
    let sign_bit = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[is_neg, sign_mask, zero64],
    )?;
    let neg_s64 = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[zero64, s64])?;
    let mag = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[is_neg, neg_s64, s64])?;

    let clz = out.emit(SemanticOp::Primitive(PrimitiveOp::CountLeadingZeros), U64, &[mag])?;
    let sixty_three = const_u64(out, 63)?;
    let p = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[sixty_three, clz])?;

    let exp_bias = const_u64(out, 1023)?;
    let exp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[p, exp_bias])?;
    let fifty_two = const_u64(out, 52)?;
    let exp_shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[exp, fifty_two])?;

    let p_ge_52 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ule), U1, &[fifty_two, p])?;
    let diff_right = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[p, fifty_two])?;
    let diff_left = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[fifty_two, p])?;
    let diff_r_guarded = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[p_ge_52, diff_right, zero64],
    )?;
    let diff_l_guarded = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[p_ge_52, zero64, diff_left],
    )?;

    let shifted_r = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[mag, diff_r_guarded],
    )?;
    let shifted_l = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
        U64,
        &[mag, diff_l_guarded],
    )?;
    let aligned = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[p_ge_52, shifted_r, shifted_l],
    )?;

    let one64 = const_u64(out, 1)?;
    let p_gt_52 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[fifty_two, p])?;
    let shift_minus_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[diff_r_guarded, one64])?;
    let round_mask = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
        U64,
        &[one64, shift_minus_1],
    )?;
    let sticky_mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[round_mask, one64])?;
    let round_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[mag, round_mask])?;
    let sticky_bits = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[mag, sticky_mask])?;
    let has_round = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[zero64, round_bit])?;
    let has_sticky = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[zero64, sticky_bits])?;
    let lsb = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U1, &[aligned, zero64])?;
    let sticky_or_lsb = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[has_sticky, lsb])?;
    let should_round_up = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[has_round, sticky_or_lsb])?;
    let round_up_active = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[p_gt_52, should_round_up])?;
    let rounded_aligned = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[aligned, one64])?;
    let final_aligned = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[round_up_active, rounded_aligned, aligned],
    )?;

    let mantissa_mask = const_u64(out, 0x000F_FFFF_FFFF_FFFF)?;
    let mantissa = out.emit(
        SemanticOp::Primitive(PrimitiveOp::And),
        U64,
        &[final_aligned, mantissa_mask],
    )?;

    let exp_or_mant = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[exp_shifted, mantissa])?;
    let full_bits = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[sign_bit, exp_or_mant])?;

    let non_zero_f64 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[full_bits, zero64])?;
    let zero_f64 = const_f64(out, 0)?;
    out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        F64,
        &[is_zero, zero_f64, non_zero_f64],
    )
}

fn f64_to_int(out: &mut dyn SemanticBuilder, f: ValueId, dst_ty: SemanticType) -> Result<ValueId, SemanticError> {
    let mode = const_u64(out, 0)?; // Round to nearest even
    let rounded = out.emit(SemanticOp::Float(FloatingOp::Round), F64, &[f, mode])?;
    let zero64 = const_u64(out, 0)?;
    let bits = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[rounded, zero64])?;

    let fifty_two = const_u64(out, 52)?;
    let exp_shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[bits, fifty_two],
    )?;
    let mask_7ff = const_u64(out, 0x7FF)?;
    let exp = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[exp_shifted, mask_7ff])?;

    let exp_bias = const_u64(out, 1023)?;
    let is_underflow = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[exp, exp_bias])?;

    let mantissa_mask = const_u64(out, 0x000F_FFFF_FFFF_FFFF)?;
    let mantissa_low = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[bits, mantissa_mask])?;
    let implicit_one = const_u64(out, 0x0010_0000_0000_0000)?;
    let mantissa = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Or),
        U64,
        &[mantissa_low, implicit_one],
    )?;

    let shift = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[exp, exp_bias])?;
    let shift_le_52 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ule), U1, &[shift, fifty_two])?;
    let diff_r = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[fifty_two, shift])?;
    let diff_l = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[shift, fifty_two])?;
    let diff_r_guarded = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[shift_le_52, diff_r, zero64],
    )?;
    let diff_l_guarded = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[shift_le_52, zero64, diff_l],
    )?;
    let val_r = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[mantissa, diff_r_guarded],
    )?;
    let val_l = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
        U64,
        &[mantissa, diff_l_guarded],
    )?;
    let mag = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[shift_le_52, val_r, val_l],
    )?;
    let mag_with_zero = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[is_underflow, zero64, mag],
    )?;

    let sixty_three = const_u64(out, 63)?;
    let sign_bit = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[bits, sixty_three],
    )?;
    let one64 = const_u64(out, 1)?;
    let is_neg = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[sign_bit, one64])?;
    let neg_mag = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[zero64, mag_with_zero])?;
    let val_u64 = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        U64,
        &[is_neg, neg_mag, mag_with_zero],
    )?;

    if dst_ty == U64 {
        Ok(val_u64)
    } else {
        out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), dst_ty, &[val_u64, zero64])
    }
}

// ---------------------------------------------------------------------------
// FCOM / FCOMP / FCOMPP
// FCOM compares ST(0) with the source and reports the result in the FPU
// status-word condition codes: C0=CF (bit 8), C2=PF (bit 10), C3=ZF (bit 14).
// Unordered comparisons (NaN or an empty stack slot, which reads as the real
// indefinite) set C0=C2=C3=1, matching masked hardware. FCOMP pops ST(0)
// once; FCOMPP pops ST(0) twice.
// ---------------------------------------------------------------------------

macro_rules! x87_com {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $convert:expr, $pop:expr) => {
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
                let top = out.read_operand(0, U80)?;
                let source = out.read_operand(1, $src_ty)?;
                let top_value = x87_unpack_st(out, top)?;
                let src_value = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[source])?
                } else if $src_ty == U80 {
                    x87_unpack_st(out, source)?
                } else {
                    source
                };
                let flags = out.emit(
                    SemanticOp::Float(FloatingOp::Compare),
                    U64,
                    &[top_value, src_value],
                )?;
                let pop_delta: i32 = if $pop { 1 } else { 0 };
                crate::x87::write_fcom_condition_codes(out, flags, pop_delta)?;
                if $pop {
                    x87_pop_st_regs(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_com!(FcomSti, forms::FCOM_STI, 0x0A00, U80, false, false);
x87_com!(FcomM32, forms::FCOM_M32, 0x0A01, F32, true, false);
x87_com!(FcomM64, forms::FCOM_M64, 0x0A02, F64, false, false);
x87_com!(FcompSti, forms::FCOMP_STI, 0x0A03, U80, false, true);
x87_com!(FcompM32, forms::FCOMP_M32, 0x0A04, F32, true, true);
x87_com!(FcompM64, forms::FCOMP_M64, 0x0A05, F64, false, true);

#[derive(Clone, Copy, Debug)]
pub struct Fcompp;

impl SemanticProvider for Fcompp {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0A06)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FCOMPP
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = out.read_operand(0, U80)?;
        let source = out.read_operand(1, U80)?;
        let top_value = x87_unpack_st(out, top)?;
        let src_value = x87_unpack_st(out, source)?;
        let flags = out.emit(SemanticOp::Float(FloatingOp::Compare), U64, &[top_value, src_value])?;
        crate::x87::write_fcom_condition_codes(out, flags, 2)?;
        x87_pop2_st_regs(out)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0A06, context))
    }
}

// ---------------------------------------------------------------------------
// Integer arithmetic: FIADD / FISUB / FISUBR / FIMUL / FIDIV / FIDIVR
// ---------------------------------------------------------------------------

macro_rules! x87_int_arith {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $op:expr, $reversed:expr) => {
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
                let dst = x87_read_st(out, 0)?;
                let source = out.read_operand(1, $src_ty)?;
                let src_val = int_to_f64(out, source, $src_ty)?;
                let dst_val = x87_unpack_st(out, dst)?;
                let result = x87_float_op(out, $op, $reversed, dst_val, src_val)?;
                let packed = x87_pack_st(out, result)?;
                x87_write_st(out, 0, packed)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_int_arith!(FiaddM16, forms::FIADD_M16, 0x0A07, U16, FloatingOp::Add, false);
x87_int_arith!(FiaddM32, forms::FIADD_M32, 0x0A08, U32, FloatingOp::Add, false);
x87_int_arith!(FisubM16, forms::FISUB_M16, 0x0A09, U16, FloatingOp::Sub, false);
x87_int_arith!(FisubM32, forms::FISUB_M32, 0x0A0A, U32, FloatingOp::Sub, false);
x87_int_arith!(FisubrM16, forms::FISUBR_M16, 0x0A0B, U16, FloatingOp::Sub, true);
x87_int_arith!(FisubrM32, forms::FISUBR_M32, 0x0A0C, U32, FloatingOp::Sub, true);
x87_int_arith!(FimulM16, forms::FIMUL_M16, 0x0A0D, U16, FloatingOp::Mul, false);
x87_int_arith!(FimulM32, forms::FIMUL_M32, 0x0A0E, U32, FloatingOp::Mul, false);
x87_int_arith!(FidivM16, forms::FIDIV_M16, 0x0A0F, U16, FloatingOp::Div, false);
x87_int_arith!(FidivM32, forms::FIDIV_M32, 0x0A10, U32, FloatingOp::Div, false);
x87_int_arith!(FidivrM16, forms::FIDIVR_M16, 0x0A11, U16, FloatingOp::Div, true);
x87_int_arith!(FidivrM32, forms::FIDIVR_M32, 0x0A12, U32, FloatingOp::Div, true);

// ---------------------------------------------------------------------------
// Integer compare: FICOM / FICOMP
// Like FCOM, but the source is an integer memory operand converted to f64;
// the result lands in the status-word condition codes C0/C2/C3.
// ---------------------------------------------------------------------------

macro_rules! x87_int_com {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $pop:expr) => {
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
                let top = out.read_operand(0, U80)?;
                let source = out.read_operand(1, $src_ty)?;
                let top_value = x87_unpack_st(out, top)?;
                let src_value = int_to_f64(out, source, $src_ty)?;
                let flags = out.emit(
                    SemanticOp::Float(FloatingOp::Compare),
                    U64,
                    &[top_value, src_value],
                )?;
                let pop_delta: i32 = if $pop { 1 } else { 0 };
                crate::x87::write_fcom_condition_codes(out, flags, pop_delta)?;
                if $pop {
                    x87_pop_st_regs(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_int_com!(FicomM16, forms::FICOM_M16, 0x0A13, U16, false);
x87_int_com!(FicomM32, forms::FICOM_M32, 0x0A14, U32, false);
x87_int_com!(FicompM16, forms::FICOMP_M16, 0x0A15, U16, true);
x87_int_com!(FicompM32, forms::FICOMP_M32, 0x0A16, U32, true);

// ---------------------------------------------------------------------------
// Integer load and store: FILD / FIST / FISTP
// ---------------------------------------------------------------------------

macro_rules! x87_fild {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr) => {
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
                let f = int_to_f64(out, source, $src_ty)?;
                x87_push_st(out, f)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_fild!(FildM16, forms::FILD_M16, 0x0A17, U16);
x87_fild!(FildM32, forms::FILD_M32, 0x0A18, U32);
x87_fild!(FildM64, forms::FILD_M64, 0x0A19, U64);

macro_rules! x87_fist {
    ($name:ident, $form:expr, $rule:expr, $dst_ty:expr, $pop:expr) => {
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
                let top = x87_read_st(out, 0)?;
                let f = x87_unpack_st(out, top)?;
                let int_val = f64_to_int(out, f, $dst_ty)?;
                out.write_operand(0, int_val)?;
                if $pop {
                    x87_pop_st(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_fist!(FistM16, forms::FIST_M16, 0x0A1A, U16, false);
x87_fist!(FistM32, forms::FIST_M32, 0x0A1B, U32, false);
x87_fist!(FistpM16, forms::FISTP_M16, 0x0A1C, U16, true);
x87_fist!(FistpM32, forms::FISTP_M32, 0x0A1D, U32, true);
x87_fist!(FistpM64, forms::FISTP_M64, 0x0A1E, U64, true);

// ---------------------------------------------------------------------------
// Sign, Square Root, and Exchange: FABS / FCHS / FSQRT / FXCH
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Fabs;

impl SemanticProvider for Fabs {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0A1F)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FABS
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let zero64 = const_u64(out, 0)?;
        let bits = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[f, zero64])?;
        let mask = const_u64(out, 0x7FFF_FFFF_FFFF_FFFF)?;
        let abs_bits = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[bits, mask])?;
        let abs_f = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[abs_bits, zero64])?;
        let packed = x87_pack_st(out, abs_f)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0A1F, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fchs;

impl SemanticProvider for Fchs {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0A20)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FCHS
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let zero64 = const_u64(out, 0)?;
        let bits = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[f, zero64])?;
        let mask = const_u64(out, 1u64 << 63)?;
        let chs_bits = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[bits, mask])?;
        let chs_f = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[chs_bits, zero64])?;
        let packed = x87_pack_st(out, chs_f)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0A20, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fsqrt;

impl SemanticProvider for Fsqrt {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0A21)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSQRT
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Sqrt), F64, &[f])?;
        let packed = x87_pack_st(out, res)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0A21, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fxch;

impl SemanticProvider for Fxch {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0A22)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FXCH
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let st0 = x87_read_st(out, 0)?;
        let st1 = x87_read_st(out, 1)?;
        x87_write_st(out, 0, st1)?;
        x87_write_st(out, 1, st0)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0A22, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FxchSti;

impl SemanticProvider for FxchSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0A23)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FXCH_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let idx0 = x87_operand_st_index(insn, 0).ok();
        let idx1 = x87_operand_st_index(insn, 1).ok();
        let index = match (idx0, idx1) {
            (Some(0), Some(i)) | (Some(i), Some(0)) => i,
            (Some(i), _) => i,
            (None, Some(i)) => i,
            (None, None) => 1,
        };
        let st0 = x87_read_st(out, 0)?;
        let sti = x87_read_st(out, index)?;
        x87_write_st(out, 0, sti)?;
        x87_write_st(out, index, st0)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0A23, context))
    }
}

// ---------------------------------------------------------------------------
// Scalar SSE floating-point conversion and min/max providers (0x0E00..0x0EFF)
// ---------------------------------------------------------------------------

/// CVTSS2SD xmm, xmm: convert scalar single to scalar double on lane 0, preserving upper 64 bits.
#[derive(Clone, Copy, Debug)]
pub struct Cvtss2sdXmmXmm;

impl SemanticProvider for Cvtss2sdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0E00)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CVTSS2SD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F32X4)?;
        let zero = const_u64(out, 0)?;
        let sixty_four = const_u64(out, 64)?;
        let lo2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src, zero])?;
        let converted = out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[lo2])?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[dst, sixty_four])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X2, &[converted, upper])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0E00, context))
    }
}

/// CVTSD2SS xmm, xmm: convert scalar double to scalar single on lane 0, preserving upper 96 bits.
#[derive(Clone, Copy, Debug)]
pub struct Cvtsd2ssXmmXmm;

impl SemanticProvider for Cvtsd2ssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0E01)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CVTSD2SS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F64X2)?;
        let zero = const_u64(out, 0)?;
        let thirty_two = const_u64(out, 32)?;
        let lo2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src, zero])?;
        let converted = out.emit(SemanticOp::Float(FloatingOp::Convert), F32, &[lo2])?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U96, &[dst, thirty_two])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X4, &[converted, upper])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0E01, context))
    }
}

/// MAXSS xmm, xmm: scalar single-precision max on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct MaxssXmmXmm;

impl SemanticProvider for MaxssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0E02)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MAXSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F32X4)?;
        let zero = const_u64(out, 0)?;
        let thirty_two = const_u64(out, 32)?;
        let vec_max = out.emit(SemanticOp::Vector(VectorOp::FMax), F32X4, &[dst, src])?;
        let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[vec_max, zero])?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U96, &[dst, thirty_two])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X4, &[low, upper])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0E02, context))
    }
}

/// MAXSD xmm, xmm: scalar double-precision max on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct MaxsdXmmXmm;

impl SemanticProvider for MaxsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0E03)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MAXSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F64X2)?;
        let zero = const_u64(out, 0)?;
        let sixty_four = const_u64(out, 64)?;
        let vec_max = out.emit(SemanticOp::Vector(VectorOp::FMax), F64X2, &[dst, src])?;
        let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[vec_max, zero])?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[dst, sixty_four])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X2, &[low, upper])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0E03, context))
    }
}

/// MINSS xmm, xmm: scalar single-precision min on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct MinssXmmXmm;

impl SemanticProvider for MinssXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0E04)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MINSS_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F32X4)?;
        let src = out.read_operand(1, F32X4)?;
        let zero = const_u64(out, 0)?;
        let thirty_two = const_u64(out, 32)?;
        let vec_min = out.emit(SemanticOp::Vector(VectorOp::FMin), F32X4, &[dst, src])?;
        let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[vec_min, zero])?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U96, &[dst, thirty_two])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X4, &[low, upper])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0E04, context))
    }
}

/// MINSD xmm, xmm: scalar double-precision min on lane 0, preserving upper lanes.
#[derive(Clone, Copy, Debug)]
pub struct MinsdXmmXmm;

impl SemanticProvider for MinsdXmmXmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0E05)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MINSD_XMM_XMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let dst = out.read_operand(0, F64X2)?;
        let src = out.read_operand(1, F64X2)?;
        let zero = const_u64(out, 0)?;
        let sixty_four = const_u64(out, 64)?;
        let vec_min = out.emit(SemanticOp::Vector(VectorOp::FMin), F64X2, &[dst, src])?;
        let low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[vec_min, zero])?;
        let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[dst, sixty_four])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X2, &[low, upper])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0E05, context))
    }
}

// ---------------------------------------------------------------------------
// Tail census batch (0x0B00..0x0BFF): XADD, CMPXCHG, SETcc mem, TEST mem,
// CLFLUSH, MOVBE, CRC32, JMP_FAR
// ---------------------------------------------------------------------------

fn bswap_value(
    out: &mut dyn SemanticBuilder,
    val: ValueId,
    ty: SemanticType,
    byte_count: usize,
) -> Result<ValueId, SemanticError> {
    let mask_ff = const_typed(out, ty, 0xFF)?;
    let mut result = const_typed(out, ty, 0)?;
    for i in 0..byte_count {
        let src_shift = (i * 8) as u64;
        let dst_shift = ((byte_count - 1 - i) * 8) as u64;
        let bs = const_typed(out, ty, src_shift)?;
        let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight), ty, &[val, bs])?;
        let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[byte, mask_ff])?;
        let ds = const_typed(out, ty, dst_shift)?;
        let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), ty, &[masked, ds])?;
        result = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), ty, &[result, shifted])?;
    }
    Ok(result)
}

macro_rules! xadd_op {
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
                let dst = out.read_operand(0, $ty)?;
                let src = out.read_operand(1, $ty)?;
                let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), $ty, &[dst, src])?;
                write_add_flags(out, sum, dst, src, $bits)?;
                out.write_operand(0, sum)?;
                out.write_operand(1, dst)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

xadd_op!(XaddMem32R32, forms::XADD_MEM32_R32, U32, 32, 0x0C00);
xadd_op!(XaddMem64R64, forms::XADD_MEM64_R64, U64, 64, 0x0C01);
xadd_op!(XaddMem16R16, forms::XADD_MEM16_R16, U16, 16, 0x0C02);
xadd_op!(XaddMem8R8, forms::XADD_MEM8_R8, U8, 8, 0x0C03);
xadd_op!(XaddR16R16, forms::XADD_R16_R16, U16, 16, 0x0C04);
xadd_op!(XaddR8R8, forms::XADD_R8_R8, U8, 8, 0x0C05);

macro_rules! cmpxchg_narrow {
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
                let acc = out.read_register(RegisterId(register_id::GPR_BASE), $ty)?;
                // Compute equality BEFORE writing flags: a subsequent
                // RFLAGS read would be bound by the lowerer to the
                // pre-write value (stale), breaking the Select.
                let equal = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[dst, acc])?;
                let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[acc, dst])?;
                write_sub_flags(out, diff, acc, dst, scalar_bits($ty))?;
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
                let full_rax = out.read_register(RegisterId(register_id::GPR_BASE), U64)?;
                let mask = if $ty == U16 {
                    const_u64(out, 0xFFFF_FFFF_FFFF_0000u64)?
                } else {
                    const_u64(out, 0xFFFF_FFFF_FFFF_FF00u64)?
                };
                let upper = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[full_rax, mask])?;
                let ext = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[new_acc])?;
                let acc_write = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[upper, ext])?;
                out.write_register(RegisterId(register_id::GPR_BASE), acc_write)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

cmpxchg_narrow!(CmpxchgMem16R16, forms::CMPXCHG_MEM16_R16, U16, 0x0C06);
cmpxchg_narrow!(CmpxchgR16R16, forms::CMPXCHG_R16_R16, U16, 0x0C07);
cmpxchg_narrow!(CmpxchgR8R8, forms::CMPXCHG_R8_R8, U8, 0x0C08);

#[derive(Clone, Copy)]
enum SetccCondition {
    Z,
    Nz,
    B,
    Ae,
    Be,
    A,
    L,
    Ge,
    Le,
    G,
    S,
    Ns,
    O,
    No,
    P,
    Np,
}

fn eval_setcc_condition(out: &mut dyn SemanticBuilder, condition: SetccCondition) -> Result<ValueId, SemanticError> {
    let zf = read_flag_set(out, rflags::ZF_BIT)?;
    let cf = read_flag_set(out, rflags::CF_BIT)?;
    let sf = read_flag_set(out, rflags::SF_BIT)?;
    let of = read_flag_set(out, rflags::OF_BIT)?;
    let pf = read_flag_set(out, rflags::PF_BIT)?;
    let not_zf = read_flag_not_set(out, rflags::ZF_BIT)?;
    let not_cf = read_flag_not_set(out, rflags::CF_BIT)?;
    let not_sf = read_flag_not_set(out, rflags::SF_BIT)?;
    let not_of = read_flag_not_set(out, rflags::OF_BIT)?;
    let not_pf = read_flag_not_set(out, rflags::PF_BIT)?;
    let sf_ne_of = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
    let sf_eq_of = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[sf_ne_of])?;
    match condition {
        SetccCondition::Z => Ok(zf),
        SetccCondition::Nz => Ok(not_zf),
        SetccCondition::B => Ok(cf),
        SetccCondition::Ae => Ok(not_cf),
        SetccCondition::Be => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf]),
        SetccCondition::A => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_cf, not_zf]),
        SetccCondition::L => Ok(sf_ne_of),
        SetccCondition::Ge => Ok(sf_eq_of),
        SetccCondition::Le => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, sf_ne_of]),
        SetccCondition::G => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[not_zf, sf_eq_of]),
        SetccCondition::S => Ok(sf),
        SetccCondition::Ns => Ok(not_sf),
        SetccCondition::O => Ok(of),
        SetccCondition::No => Ok(not_of),
        SetccCondition::P => Ok(pf),
        SetccCondition::Np => Ok(not_pf),
    }
}

macro_rules! setcc_mem {
    ($name:ident, $form:expr, $condition:expr, $rule:expr) => {
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
                let cond = eval_setcc_condition(out, $condition)?;
                let byte = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[cond])?;
                out.write_operand(0, byte)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

setcc_mem!(SetzMem8, forms::SETZ_MEM8, SetccCondition::Z, 0x0C10);
setcc_mem!(SetnzMem8, forms::SETNZ_MEM8, SetccCondition::Nz, 0x0C11);
setcc_mem!(SetbMem8, forms::SETB_MEM8, SetccCondition::B, 0x0C12);
setcc_mem!(SetaeMem8, forms::SETAE_MEM8, SetccCondition::Ae, 0x0C13);
setcc_mem!(SetbeMem8, forms::SETBE_MEM8, SetccCondition::Be, 0x0C14);
setcc_mem!(SetaMem8, forms::SETA_MEM8, SetccCondition::A, 0x0C15);
setcc_mem!(SetlMem8, forms::SETL_MEM8, SetccCondition::L, 0x0C16);
setcc_mem!(SetgeMem8, forms::SETGE_MEM8, SetccCondition::Ge, 0x0C17);
setcc_mem!(SetleMem8, forms::SETLE_MEM8, SetccCondition::Le, 0x0C18);
setcc_mem!(SetgMem8, forms::SETG_MEM8, SetccCondition::G, 0x0C19);
setcc_mem!(SetsMem8, forms::SETS_MEM8, SetccCondition::S, 0x0C1A);
setcc_mem!(SetnsMem8, forms::SETNS_MEM8, SetccCondition::Ns, 0x0C1B);
setcc_mem!(SetoR8, forms::SETO_R8, SetccCondition::O, 0x0C1C);
setcc_mem!(SetoMem8, forms::SETO_MEM8, SetccCondition::O, 0x0C1D);
setcc_mem!(SetnoR8, forms::SETNO_R8, SetccCondition::No, 0x0C1E);
setcc_mem!(SetnoMem8, forms::SETNO_MEM8, SetccCondition::No, 0x0C1F);
setcc_mem!(SetpR8, forms::SETP_R8, SetccCondition::P, 0x0C20);
setcc_mem!(SetpMem8, forms::SETP_MEM8, SetccCondition::P, 0x0C21);
setcc_mem!(SetnpR8, forms::SETNP_R8, SetccCondition::Np, 0x0C22);
setcc_mem!(SetnpMem8, forms::SETNP_MEM8, SetccCondition::Np, 0x0C23);

test_op!(TestMem32R32, forms::TEST_MEM32_R32, U32, 32, 0x0C24);
test_op!(TestMem64R64, forms::TEST_MEM64_R64, U64, 64, 0x0C25);
test_op!(TestR32Mem32, forms::TEST_R32_MEM32, U32, 32, 0x0C26);
test_op!(TestR64Mem64, forms::TEST_R64_MEM64, U64, 64, 0x0C27);

#[derive(Clone, Copy, Debug)]
pub struct ClflushMem;

impl SemanticProvider for ClflushMem {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0C30)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CLFLUSH_MEM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let _ = out.read_operand(0, U8)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0C30, context))
    }
}

macro_rules! movbe_op {
    ($name:ident, $form:expr, $ty:expr, $bytes:expr, $rule:expr) => {
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
                let swapped = bswap_value(out, src, $ty, $bytes)?;
                out.write_operand(0, swapped)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

movbe_op!(MovbeR16Mem16, forms::MOVBE_R16_MEM16, U16, 2, 0x0C40);
movbe_op!(MovbeR32Mem32, forms::MOVBE_R32_MEM32, U32, 4, 0x0C41);
movbe_op!(MovbeR64Mem64, forms::MOVBE_R64_MEM64, U64, 8, 0x0C42);
movbe_op!(MovbeMem16R16, forms::MOVBE_MEM16_R16, U16, 2, 0x0C43);
movbe_op!(MovbeMem32R32, forms::MOVBE_MEM32_R32, U32, 4, 0x0C44);
movbe_op!(MovbeMem64R64, forms::MOVBE_MEM64_R64, U64, 8, 0x0C45);

macro_rules! crc32_r32_op {
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
                let dst = out.read_operand(0, U32)?;
                let src = out.read_operand(1, $src_ty)?;
                let crc = out.emit(SemanticOp::Primitive(PrimitiveOp::Crc32), U32, &[dst, src])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[crc])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! crc32_r64_op {
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
                let dst = out.read_operand(0, U64)?;
                let zero = const_u64(out, 0)?;
                let dst32 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[dst, zero])?;
                let src = out.read_operand(1, $src_ty)?;
                let crc = out.emit(SemanticOp::Primitive(PrimitiveOp::Crc32), U32, &[dst32, src])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[crc])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

crc32_r32_op!(Crc32R32Mem32, forms::CRC32_R32_MEM32, U32, 0x0C50);
crc32_r64_op!(Crc32R64Mem64, forms::CRC32_R64_MEM64, U64, 0x0C51);
crc32_r32_op!(Crc32R32R8, forms::CRC32_R32_R8, U8, 0x0C52);
crc32_r32_op!(Crc32R32Mem8, forms::CRC32_R32_MEM8, U8, 0x0C53);
crc32_r64_op!(Crc32R64R8, forms::CRC32_R64_R8, U8, 0x0C54);
crc32_r64_op!(Crc32R64Mem8, forms::CRC32_R64_MEM8, U8, 0x0C55);

#[derive(Clone, Copy, Debug)]
pub struct JmpFarMem;

impl SemanticProvider for JmpFarMem {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0C60)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JMP_FAR_MEM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let target = out.read_operand(0, U64)?;
        out.jump_indirect(target)?;
        Ok(receipt(0x0C60, context))
    }
}

// ---------------------------------------------------------------------------
// AVX-256 (VEX) Integer Family (0x0A00..0x0AFF / Rule 0x0B00..0x0BFF)
// ---------------------------------------------------------------------------

macro_rules! packed_int_ymm {
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
                let left = out.read_operand(1, U256)?;
                let right = out.read_operand(2, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[right, high_offset],
                )?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $ty,
                    &[left_low, right_low],
                )?;
                let high = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $ty,
                    &[left_high, right_high],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// 1. Packed Add / Sub
packed_int_ymm!(
    VpaddbYmmYmmYmm,
    forms::VPADDB_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I8X16,
    0x0B00
);

// ---------------------------------------------------------------------------
// Privileged control/debug register moves
// ---------------------------------------------------------------------------

fn system_register_selector(insn: &dyn DecodedInstructionView) -> Result<u64, SemanticError> {
    match insn.operand(1).map(|operand| operand.kind) {
        Some(OperandKind::Immediate(immediate)) => Ok(immediate.value),
        _ => Err(SemanticError::InvalidOperand),
    }
}

/// Deterministic CR reads. These fixed values are semantic debt until the
/// execution state grows explicit control-register state.
#[derive(Debug)]
pub struct MovR64Cr;

impl SemanticProvider for MovR64Cr {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1100)
    }

    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }

    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R64_CR
    }

    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = match system_register_selector(insn)? {
            0 => 0x8001_0033,
            2 | 3 | 8 => 0,
            4 => 0x0000_06F8,
            _ => 0,
        };
        let value = const_u64(out, value)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1100, context))
    }
}

#[derive(Debug)]
pub struct MovCrR64;

impl SemanticProvider for MovCrR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1101)
    }

    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }

    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_CR_R64
    }

    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x1101, context))
    }
}

#[derive(Debug)]
pub struct MovR64Dr;

impl SemanticProvider for MovR64Dr {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1102)
    }

    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }

    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_R64_DR
    }

    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let zero = const_u64(out, 0)?;
        out.write_operand(0, zero)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1102, context))
    }
}

#[derive(Debug)]
pub struct MovDrR64;

impl SemanticProvider for MovDrR64 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1103)
    }

    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }

    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOV_DR_R64
    }

    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x1103, context))
    }
}
packed_int_ymm!(
    VpaddwYmmYmmYmm,
    forms::VPADDW_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I16X8,
    0x0B01
);
packed_int_ymm!(
    VpadddYmmYmmYmm,
    forms::VPADDD_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I32X4,
    0x0B02
);
packed_int_ymm!(
    VpaddqYmmYmmYmm,
    forms::VPADDQ_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I64X2,
    0x0B03
);
packed_int_ymm!(
    VpsubbYmmYmmYmm,
    forms::VPSUBB_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I8X16,
    0x0B04
);
packed_int_ymm!(
    VpsubwYmmYmmYmm,
    forms::VPSUBW_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I16X8,
    0x0B05
);
packed_int_ymm!(
    VpsubdYmmYmmYmm,
    forms::VPSUBD_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I32X4,
    0x0B06
);
packed_int_ymm!(
    VpsubqYmmYmmYmm,
    forms::VPSUBQ_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I64X2,
    0x0B07
);

// 2. Packed Comparisons
packed_int_ymm!(
    VpcmpeqwYmmYmmYmm,
    forms::VPCMPEQW_YMM_YMM_YMM,
    PrimitiveOp::MaskEq,
    I16X8,
    0x0B08
);
packed_int_ymm!(
    VpcmpeqdYmmYmmYmm,
    forms::VPCMPEQD_YMM_YMM_YMM,
    PrimitiveOp::MaskEq,
    I32X4,
    0x0B09
);
packed_int_ymm!(
    VpcmpeqqYmmYmmYmm,
    forms::VPCMPEQQ_YMM_YMM_YMM,
    PrimitiveOp::MaskEq,
    I64X2,
    0x0B0A
);
packed_int_ymm!(
    VpcmpgtbYmmYmmYmm,
    forms::VPCMPGTB_YMM_YMM_YMM,
    PrimitiveOp::MaskSgt,
    I8X16,
    0x0B0B
);
packed_int_ymm!(
    VpcmpgtwYmmYmmYmm,
    forms::VPCMPGTW_YMM_YMM_YMM,
    PrimitiveOp::MaskSgt,
    I16X8,
    0x0B0C
);
packed_int_ymm!(
    VpcmpgtdYmmYmmYmm,
    forms::VPCMPGTD_YMM_YMM_YMM,
    PrimitiveOp::MaskSgt,
    I32X4,
    0x0B0D
);
packed_int_ymm!(
    VpcmpgtqYmmYmmYmm,
    forms::VPCMPGTQ_YMM_YMM_YMM,
    PrimitiveOp::MaskSgt,
    I64X2,
    0x0B0E
);

// 3. Multiplies
packed_int_ymm!(
    VpmullwYmmYmmYmm,
    forms::VPMULLW_YMM_YMM_YMM,
    PrimitiveOp::Mul,
    I16X8,
    0x0B0F
);
packed_int_ymm!(
    VpmulhwYmmYmmYmm,
    forms::VPMULHW_YMM_YMM_YMM,
    PrimitiveOp::MulHighS,
    I16X8,
    0x0B10
);

macro_rules! packed_madd_ymm {
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
                let left = out.read_operand(1, U256)?;
                let right = out.read_operand(2, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I16X8, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I16X8,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I16X8, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    I16X8,
                    &[right, high_offset],
                )?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::Madd16),
                    I32X4,
                    &[left_low, right_low],
                )?;
                let high = out.emit(
                    SemanticOp::Vector(VectorOp::Madd16),
                    I32X4,
                    &[left_high, right_high],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_madd_ymm!(VpmaddwdYmmYmmYmm, forms::VPMADDWD_YMM_YMM_YMM, 0x0B11);

// 4. Shifts by immediate
macro_rules! packed_shift_imm8_ymm {
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
                let src = out.read_operand(1, U256)?;
                let count = insn
                    .operand(2)
                    .and_then(|op| match op.kind {
                        OperandKind::Immediate(imm) => Some(imm.value),
                        _ => None,
                    })
                    .unwrap_or(0);
                let count_vec = vec_const_uniform(out, $ty, count, $lane_bytes, $lanes)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[src, zero])?;
                let src_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[src, high_offset],
                )?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $ty,
                    &[src_low, count_vec],
                )?;
                let high = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $ty,
                    &[src_high, count_vec],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_shift_imm8_ymm!(
    VpsllwYmmYmmImm8,
    forms::VPSLLW_YMM_YMM_IMM8,
    PrimitiveOp::ShiftLeft,
    I16X8,
    2,
    8,
    0x0B12
);
packed_shift_imm8_ymm!(
    VpslldYmmYmmImm8,
    forms::VPSLLD_YMM_YMM_IMM8,
    PrimitiveOp::ShiftLeft,
    I32X4,
    4,
    4,
    0x0B13
);
packed_shift_imm8_ymm!(
    VpsllqYmmYmmImm8,
    forms::VPSLLQ_YMM_YMM_IMM8,
    PrimitiveOp::ShiftLeft,
    I64X2,
    8,
    2,
    0x0B14
);
packed_shift_imm8_ymm!(
    VpsrlwYmmYmmImm8,
    forms::VPSRLW_YMM_YMM_IMM8,
    PrimitiveOp::LogicalShiftRight,
    I16X8,
    2,
    8,
    0x0B15
);
packed_shift_imm8_ymm!(
    VpsrldYmmYmmImm8,
    forms::VPSRLD_YMM_YMM_IMM8,
    PrimitiveOp::LogicalShiftRight,
    I32X4,
    4,
    4,
    0x0B16
);
packed_shift_imm8_ymm!(
    VpsrlqYmmYmmImm8,
    forms::VPSRLQ_YMM_YMM_IMM8,
    PrimitiveOp::LogicalShiftRight,
    I64X2,
    8,
    2,
    0x0B17
);
packed_shift_imm8_ymm!(
    VpsrawYmmYmmImm8,
    forms::VPSRAW_YMM_YMM_IMM8,
    PrimitiveOp::ArithmeticShiftRight,
    I16X8,
    2,
    8,
    0x0B18
);
packed_shift_imm8_ymm!(
    VpsradYmmYmmImm8,
    forms::VPSRAD_YMM_YMM_IMM8,
    PrimitiveOp::ArithmeticShiftRight,
    I32X4,
    4,
    4,
    0x0B19
);

// 5. Shifts by XMM register count
macro_rules! packed_shift_reg_ymm {
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
                let src = out.read_operand(1, U256)?;
                let count_src = out.read_operand(2, $ty)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let src_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[src, zero])?;
                let src_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[src, high_offset],
                )?;
                let low = out.emit(SemanticOp::Vector($vop), $ty, &[src_low, count_src])?;
                let high = out.emit(SemanticOp::Vector($vop), $ty, &[src_high, count_src])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_shift_reg_ymm!(
    VpsllwYmmYmmXmm,
    forms::VPSLLW_YMM_YMM_XMM,
    VectorOp::ShiftRegL,
    I16X8,
    0x0B1A
);
packed_shift_reg_ymm!(
    VpslldYmmYmmXmm,
    forms::VPSLLD_YMM_YMM_XMM,
    VectorOp::ShiftRegL,
    I32X4,
    0x0B1B
);
packed_shift_reg_ymm!(
    VpsllqYmmYmmXmm,
    forms::VPSLLQ_YMM_YMM_XMM,
    VectorOp::ShiftRegL,
    I64X2,
    0x0B1C
);
packed_shift_reg_ymm!(
    VpsrlwYmmYmmXmm,
    forms::VPSRLW_YMM_YMM_XMM,
    VectorOp::ShiftRegR,
    I16X8,
    0x0B1D
);
packed_shift_reg_ymm!(
    VpsrldYmmYmmXmm,
    forms::VPSRLD_YMM_YMM_XMM,
    VectorOp::ShiftRegR,
    I32X4,
    0x0B1E
);
packed_shift_reg_ymm!(
    VpsrlqYmmYmmXmm,
    forms::VPSRLQ_YMM_YMM_XMM,
    VectorOp::ShiftRegR,
    I64X2,
    0x0B1F
);
packed_shift_reg_ymm!(
    VpsrawYmmYmmXmm,
    forms::VPSRAW_YMM_YMM_XMM,
    VectorOp::ShiftRegRA,
    I16X8,
    0x0B20
);
packed_shift_reg_ymm!(
    VpsradYmmYmmXmm,
    forms::VPSRAD_YMM_YMM_XMM,
    VectorOp::ShiftRegRA,
    I32X4,
    0x0B21
);

// 6. Shuffles
#[derive(Clone, Copy, Debug)]
pub struct VpshufdYmmYmmImm8;

impl SemanticProvider for VpshufdYmmYmmImm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0B22)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::VPSHUFD_YMM_YMM_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src = out.read_operand(1, U256)?;
        let imm = insn
            .operand(2)
            .and_then(|op| match op.kind {
                OperandKind::Immediate(imm) => Some(imm.value),
                _ => None,
            })
            .unwrap_or(0);
        let imm_const = const_u64(out, imm)?;
        let zero = const_u64(out, 0)?;
        let high_offset = const_u64(out, 128)?;
        let src_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I32X4, &[src, zero])?;
        let src_high = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I32X4, &[src, high_offset])?;
        let low = out.emit(SemanticOp::Vector(VectorOp::Shuffle32), I32X4, &[src_low, imm_const])?;
        let high = out.emit(SemanticOp::Vector(VectorOp::Shuffle32), I32X4, &[src_high, imm_const])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0B22, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct VpshufbYmmYmmYmm;

impl SemanticProvider for VpshufbYmmYmmYmm {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x0B23)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::VPSHUFB_YMM_YMM_YMM
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let left = out.read_operand(1, U256)?;
        let right = out.read_operand(2, U256)?;
        let zero = const_u64(out, 0)?;
        let high_offset = const_u64(out, 128)?;
        let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I8X16, &[left, zero])?;
        let left_high = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I8X16, &[left, high_offset])?;
        let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), I8X16, &[right, zero])?;
        let right_high = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Extract),
            I8X16,
            &[right, high_offset],
        )?;
        let low = out.emit(SemanticOp::Vector(VectorOp::Shuffle), I8X16, &[left_low, right_low])?;
        let high = out.emit(SemanticOp::Vector(VectorOp::Shuffle), I8X16, &[left_high, right_high])?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x0B23, context))
    }
}

// 7. Unpacks (low and high)
macro_rules! packed_unpack_ymm {
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
                let left = out.read_operand(1, U256)?;
                let right = out.read_operand(2, U256)?;
                let zero = const_u64(out, 0)?;
                let high_offset = const_u64(out, 128)?;
                let left_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[left, zero])?;
                let left_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[left, high_offset],
                )?;
                let right_low = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $ty, &[right, zero])?;
                let right_high = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $ty,
                    &[right, high_offset],
                )?;
                let low = out.emit(SemanticOp::Vector($op), $ty, &[left_low, right_low])?;
                let high = out.emit(SemanticOp::Vector($op), $ty, &[left_high, right_high])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U256, &[low, high])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_unpack_ymm!(
    VpunpcklbwYmmYmmYmm,
    forms::VPUNPCKLBW_YMM_YMM_YMM,
    VectorOp::Unpack,
    I8X16,
    0x0B24
);
packed_unpack_ymm!(
    VpunpcklwdYmmYmmYmm,
    forms::VPUNPCKLWD_YMM_YMM_YMM,
    VectorOp::Unpack,
    I16X8,
    0x0B25
);
packed_unpack_ymm!(
    VpunpckldqYmmYmmYmm,
    forms::VPUNPCKLDQ_YMM_YMM_YMM,
    VectorOp::Unpack,
    I32X4,
    0x0B26
);
packed_unpack_ymm!(
    VpunpcklqdqYmmYmmYmm,
    forms::VPUNPCKLQDQ_YMM_YMM_YMM,
    VectorOp::Unpack,
    I64X2,
    0x0B27
);
packed_unpack_ymm!(
    VpunpckhbwYmmYmmYmm,
    forms::VPUNPCKHBW_YMM_YMM_YMM,
    VectorOp::UnpackHigh,
    I8X16,
    0x0B28
);
packed_unpack_ymm!(
    VpunpckhwdYmmYmmYmm,
    forms::VPUNPCKHWD_YMM_YMM_YMM,
    VectorOp::UnpackHigh,
    I16X8,
    0x0B29
);
packed_unpack_ymm!(
    VpunpckhdqYmmYmmYmm,
    forms::VPUNPCKHDQ_YMM_YMM_YMM,
    VectorOp::UnpackHigh,
    I32X4,
    0x0B2A
);
packed_unpack_ymm!(
    VpunpckhqdqYmmYmmYmm,
    forms::VPUNPCKHQDQ_YMM_YMM_YMM,
    VectorOp::UnpackHigh,
    I64X2,
    0x0B2B
);

// 8. Min / Max
packed_int_ymm!(
    VpminubYmmYmmYmm,
    forms::VPMINUB_YMM_YMM_YMM,
    PrimitiveOp::MinU,
    I8X16,
    0x0B2C
);
packed_int_ymm!(
    VpminsbYmmYmmYmm,
    forms::VPMINSB_YMM_YMM_YMM,
    PrimitiveOp::MinS,
    I8X16,
    0x0B2D
);
packed_int_ymm!(
    VpminuwYmmYmmYmm,
    forms::VPMINUW_YMM_YMM_YMM,
    PrimitiveOp::MinU,
    I16X8,
    0x0B2E
);
packed_int_ymm!(
    VpminswYmmYmmYmm,
    forms::VPMINSW_YMM_YMM_YMM,
    PrimitiveOp::MinS,
    I16X8,
    0x0B2F
);
packed_int_ymm!(
    VpminudYmmYmmYmm,
    forms::VPMINUD_YMM_YMM_YMM,
    PrimitiveOp::MinU,
    I32X4,
    0x0B30
);
packed_int_ymm!(
    VpminsdYmmYmmYmm,
    forms::VPMINSD_YMM_YMM_YMM,
    PrimitiveOp::MinS,
    I32X4,
    0x0B31
);
packed_int_ymm!(
    VpmaxubYmmYmmYmm,
    forms::VPMAXUB_YMM_YMM_YMM,
    PrimitiveOp::MaxU,
    I8X16,
    0x0B32
);
packed_int_ymm!(
    VpmaxsbYmmYmmYmm,
    forms::VPMAXSB_YMM_YMM_YMM,
    PrimitiveOp::MaxS,
    I8X16,
    0x0B33
);
packed_int_ymm!(
    VpmaxuwYmmYmmYmm,
    forms::VPMAXUW_YMM_YMM_YMM,
    PrimitiveOp::MaxU,
    I16X8,
    0x0B34
);
packed_int_ymm!(
    VpmaxswYmmYmmYmm,
    forms::VPMAXSW_YMM_YMM_YMM,
    PrimitiveOp::MaxS,
    I16X8,
    0x0B35
);
packed_int_ymm!(
    VpmaxudYmmYmmYmm,
    forms::VPMAXUD_YMM_YMM_YMM,
    PrimitiveOp::MaxU,
    I32X4,
    0x0B36
);
packed_int_ymm!(
    VpmaxsdYmmYmmYmm,
    forms::VPMAXSD_YMM_YMM_YMM,
    PrimitiveOp::MaxS,
    I32X4,
    0x0B37
);

// ---------------------------------------------------------------------------
// Census-tail completion (0x0E80..0x0EA0): 8-bit shifts/rotates (CL + mem
// imm8), ADC/SBB r8/m8 imm8, ADD mem32-r32, MOVSXD r32, BTS/BTR/BTC
// mem-imm8. These close the last unmapped decode shapes the census reports
// (dead-code paths in the corpus — the execution sweep was already clean).
// ---------------------------------------------------------------------------

fn write_adc8_flags(
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
    let eight = const_u32(out, 8)?;
    let cf32 = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U32,
        &[full, eight],
    )?;
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf32])?;
    let result64 = widen_to_u64(out, result, 8)?;
    let left64 = widen_to_u64(out, left, 8)?;
    let right64 = widen_to_u64(out, right, 8)?;
    let mut flags = add_flag_values(out, result64, left64, right64, 8)?;
    flags.pop();
    flags.push(cf);
    compose_rflags(out, &flags, false)
}

fn write_sbb8_flags(
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
    let result64 = widen_to_u64(out, result, 8)?;
    let left64 = widen_to_u64(out, left, 8)?;
    let right64 = widen_to_u64(out, right, 8)?;
    let mut flags = sub_flag_values(out, result64, left64, right64, 8)?;
    flags.pop();
    flags.push(cf);
    compose_rflags(out, &flags, false)
}

macro_rules! adc_sbb_r8 {
    ($name:ident, $form:expr, $is_adc:expr, $rule:expr) => {
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
                let dest = out.read_operand(0, U8)?;
                let src = out.read_operand(1, U8)?;
                let carry1 = read_flag_set(out, rflags::CF_BIT)?;
                let carry = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[carry1])?;
                let result = if $is_adc {
                    let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U8, &[dest, src])?;
                    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U8, &[sum, carry])?;
                    write_adc8_flags(out, result, dest, src, carry)?;
                    result
                } else {
                    let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[dest, src])?;
                    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[diff, carry])?;
                    write_sbb8_flags(out, result, dest, src, carry)?;
                    result
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

adc_sbb_r8!(AdcR8Imm8, forms::ADC_R8_IMM8, true, 0x1200);
adc_sbb_r8!(AdcMem8Imm8, forms::ADC_MEM8_IMM8, true, 0x1201);
adc_sbb_r8!(SbbR8Imm8, forms::SBB_R8_IMM8, false, 0x1202);
adc_sbb_r8!(SbbMem8Imm8, forms::SBB_MEM8_IMM8, false, 0x1203);

/// MOVSXD r32, r/m32 — the 32-bit destination form is a plain move.
#[derive(Clone, Copy, Debug)]
pub struct MovsxdR32Mem32;

impl SemanticProvider for MovsxdR32Mem32 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1205)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::MOVSXD_R32_MEM32
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(1, U32)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1205, context))
    }
}

macro_rules! shift_cl_r8 {
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
                let value = out.read_operand(0, U8)?;
                let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
                let mask = const_u64(out, 0x1F)?;
                let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[value, count])?;
                write_shift_flags(out, value, count, result, $kind, 8)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! rotate_cl_r8 {
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
                let value = out.read_operand(0, U8)?;
                let cl = out.read_register(RegisterId(register_id::GPR_BASE + 1), U64)?;
                let mask = const_u64(out, 0x1F)?;
                let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cl, mask])?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[value, count])?;
                // The zero-count guard wants the count at the operand width.
                let zero64 = const_u64(out, 0)?;
                let count8 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U8, &[count, zero64])?;
                write_rotate_flags_width_count(out, result, $kind, 8, Some(count8))?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! rotate_carry_cl_r8 {
    ($name:ident, $form:expr, $left:expr, $rule:expr) => {
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
                let value = out.read_operand(0, U8)?;
                let result = emit_memory_rotate_carry(out, value, U8, 8, true, $left)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

shift_cl_r8!(
    ShlR8Cl,
    forms::SHL_R8_CL,
    PrimitiveOp::ShiftLeft,
    ShiftKind::Left,
    0x1206
);
shift_cl_r8!(
    ShrR8Cl,
    forms::SHR_R8_CL,
    PrimitiveOp::LogicalShiftRight,
    ShiftKind::RightLogical,
    0x1207
);
shift_cl_r8!(
    SarR8Cl,
    forms::SAR_R8_CL,
    PrimitiveOp::ArithmeticShiftRight,
    ShiftKind::RightArith,
    0x1208
);
rotate_cl_r8!(
    RolR8Cl,
    forms::ROL_R8_CL,
    PrimitiveOp::RotateLeft,
    ShiftKind::RotateLeft,
    0x1209
);
rotate_cl_r8!(
    RorR8Cl,
    forms::ROR_R8_CL,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x120A
);
// RCL/RCR r8, CL: rotate through CF (carry-aware helper).
rotate_carry_cl_r8!(RclR8Cl, forms::RCL_R8_CL, true, 0x120B);
rotate_carry_cl_r8!(RcrR8Cl, forms::RCR_R8_CL, false, 0x120C);

// 8-bit memory shifts/rotates (imm8 and CL) via the round-5 macros.

/// ADC/SBB r8, r8 and r/m8, r8 (the census's `10 /r` / `18 /r` shapes).
macro_rules! adc_sbb_r8_r8 {
    ($name:ident, $form:expr, $is_adc:expr, $rule:expr) => {
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
                let dest = out.read_operand(0, U8)?;
                let src = out.read_operand(1, U8)?;
                let carry1 = read_flag_set(out, rflags::CF_BIT)?;
                let carry = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U8, &[carry1])?;
                let result = if $is_adc {
                    let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U8, &[dest, src])?;
                    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U8, &[sum, carry])?;
                    write_adc8_flags(out, result, dest, src, carry)?;
                    result
                } else {
                    let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[dest, src])?;
                    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U8, &[diff, carry])?;
                    write_sbb8_flags(out, result, dest, src, carry)?;
                    result
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

adc_sbb_r8_r8!(AdcR8R8, forms::ADC_R8_R8, true, 0x1221);
adc_sbb_r8_r8!(AdcMem8R8, forms::ADC_MEM8_R8, true, 0x1222);
adc_sbb_r8_r8!(SbbR8R8, forms::SBB_R8_R8, false, 0x1223);
adc_sbb_r8_r8!(SbbMem8R8, forms::SBB_MEM8_R8, false, 0x1224);

/// FWAIT (0x9B) and CLTS (0x0F 06): no-ops in the single-vCPU model.
#[derive(Clone, Copy, Debug)]
pub struct Fwait;

impl SemanticProvider for Fwait {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1226)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FWAIT
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x1226, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Clts;

impl SemanticProvider for Clts {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1227)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::CLTS
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x1227, context))
    }
}

/// INC r16 (`66 FF /0` — the deeper AMD-style drivers hit this).
#[derive(Clone, Copy, Debug)]
pub struct IncR16;
impl SemanticProvider for IncR16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x122A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::INC_R16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let operand = out.read_operand(0, U16)?;
        let one = out.constant(U16, &1u16.to_le_bytes())?;
        let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U16, &[operand, one])?;
        write_add_flags_preserve_cf(out, result, operand, one, 16)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x122A, context))
    }
}

cmovcc_r64!(
    CmovOR64R64,
    forms::CMOVO_R64_R64,
    0x122B,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::OF_BIT) }
);
cmovcc_r64!(
    CmovNoR64R64,
    forms::CMOVNO_R64_R64,
    0x122C,
    |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::OF_BIT) }
);
cmovcc_r64!(
    CmovPR64R64,
    forms::CMOVP_R64_R64,
    0x122D,
    |out: &mut dyn SemanticBuilder| { read_flag_set(out, rflags::PF_BIT) }
);
cmovcc_r64!(
    CmovNpR64R64,
    forms::CMOVNP_R64_R64,
    0x122E,
    |out: &mut dyn SemanticBuilder| { read_flag_not_set(out, rflags::PF_BIT) }
);

// ---------------------------------------------------------------------------
// Restored census-tail providers (the forms survived in lib.rs/registry; the
// implementations were re-created after a workspace revert): Sreg moves,
// FLD m80 (in x87.rs), IRETD, PUSH r16, XCHG r8, ROR/RCR r8 imm8,
// ADC/SBB r8-m8 and r32-imm32.
// ---------------------------------------------------------------------------

macro_rules! mov_sreg_read {
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
                // The engine has no segment state: reads return zero.
                let zero = const_typed(out, $ty, 0)?;
                out.write_operand(0, zero)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! mov_sreg_write {
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
                // Segment writes are dropped (no segment state).
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mov_sreg_read!(MovR16Sreg, forms::MOV_R16_SREG, U16, 0x1310);
mov_sreg_read!(MovR32Sreg, forms::MOV_R32_SREG, U32, 0x1311);
mov_sreg_read!(MovR64Sreg, forms::MOV_R64_SREG, U64, 0x1312);
mov_sreg_read!(MovMem16Sreg, forms::MOV_MEM16_SREG, U16, 0x1313);
mov_sreg_write!(MovSregR16, forms::MOV_SREG_R16, 0x1314);
mov_sreg_write!(MovSregMem16, forms::MOV_SREG_MEM16, 0x1315);

/// IRETD (0xCF): legacy 32-bit interrupt return; the engine models kernel
/// drivers where this appears in legacy exception paths — no-op fall-through
/// (debt-recorded).
#[derive(Clone, Copy, Debug)]
pub struct Iretd;
impl SemanticProvider for Iretd {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1316)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::IRETD
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        fall_through(out, insn)?;
        Ok(receipt(0x1316, context))
    }
}

/// PUSH r16 (66 50-57): 2-byte stack push.
#[derive(Clone, Copy, Debug)]
pub struct PushR16;
impl SemanticProvider for PushR16 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1317)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH_R16
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let rsp = out.read_register(RegisterId(register_id::GPR_BASE + 4), U64)?;
        let value = out.read_operand(0, U16)?;
        let two = const_u64(out, 2)?;
        let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, two])?;
        // The decoded stack operand is relative to the pre-instruction RSP
        // (PUSH_R64 pattern); the store lands at the post-decrement pointer.
        out.write_operand(1, value)?;
        out.write_register(RegisterId(register_id::GPR_BASE + 4), new_rsp)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1317, context))
    }
}

/// XCHG r8, r8 (86 /r): swap, no flags.
#[derive(Clone, Copy, Debug)]
pub struct XchgR8R8;
impl SemanticProvider for XchgR8R8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1318)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::XCHG_R8_R8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let a = out.read_operand(0, U8)?;
        let b = out.read_operand(1, U8)?;
        out.write_operand(0, b)?;
        out.write_operand(1, a)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1318, context))
    }
}

macro_rules! rotate_r8_imm {
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
                let value = out.read_operand(0, U8)?;
                let count = out.read_operand(1, U8)?;
                let count64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[count])?;
                let mask = const_u64(out, 0x1F)?;
                let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count64, mask])?;
                let result = out.emit(SemanticOp::Primitive($op), U8, &[value, count_masked])?;
                // The zero-count guard wants the count at the operand width.
                let zero64 = const_u64(out, 0)?;
                let count8 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U8,
                    &[count_masked, zero64],
                )?;
                write_rotate_flags_width_count(out, result, $kind, 8, Some(count8))?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

rotate_r8_imm!(
    RorR8Imm8,
    forms::ROR_R8_IMM8,
    PrimitiveOp::RotateRight,
    ShiftKind::RotateRight,
    0x1319
);

/// RCR r8, imm8: rotate through CF (carry-aware helper).
#[derive(Clone, Copy, Debug)]
pub struct RcrR8Imm8;
impl SemanticProvider for RcrR8Imm8 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x131A)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::RCR_R8_IMM8
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let value = out.read_operand(0, U8)?;
        let result = emit_memory_rotate_carry(out, value, U8, 8, false, false)?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(0x131A, context))
    }
}

adc_sbb_r8_r8!(AdcR8Mem8, forms::ADC_R8_MEM8, true, 0x131B);
adc_sbb_r8_r8!(SbbR8Mem8, forms::SBB_R8_MEM8, false, 0x131C);

/// ADC/SBB r32, imm32 (the census's `15`/`1d` EAX-imm32 shapes).
macro_rules! adc_sbb_r32_imm {
    ($name:ident, $form:expr, $is_adc:expr, $rule:expr) => {
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
                let dest = out.read_operand(0, U32)?;
                let src = out.read_operand(1, U32)?;
                let carry1 = read_flag_set(out, rflags::CF_BIT)?;
                let carry = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[carry1])?;
                let dest64 = widen_to_u64(out, dest, 32)?;
                let src64 = widen_to_u64(out, src, 32)?;
                let carry64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[carry])?;
                let rhs64 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[src64, carry64])?;
                let result = if $is_adc {
                    let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[dest, src])?;
                    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[sum, carry])?;
                    let full = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[dest64, rhs64])?;
                    let thirty_two = const_u64(out, 32)?;
                    let cf32 = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                        U64,
                        &[full, thirty_two],
                    )?;
                    let one = const_u64(out, 1)?;
                    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[cf32, one])?;
                    let result64 = widen_to_u64(out, result, 32)?;
                    let mut flags = add_flag_values(out, result64, dest64, src64, 32)?;
                    flags.pop();
                    flags.push(cf);
                    compose_rflags(out, &flags, false)?;
                    result
                } else {
                    let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[dest, src])?;
                    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[diff, carry])?;
                    let cf1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[dest64, rhs64])?;
                    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf1])?;
                    let result64 = widen_to_u64(out, result, 32)?;
                    let mut flags = sub_flag_values(out, result64, dest64, src64, 32)?;
                    flags.pop();
                    flags.push(cf);
                    compose_rflags(out, &flags, false)?;
                    result
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

adc_sbb_r32_imm!(AdcR32Imm32, forms::ADC_R32_IMM32, true, 0x1500);
adc_sbb_r32_imm!(SbbR32Imm32, forms::SBB_R32_IMM32, false, 0x1501);

// ---------------------------------------------------------------------------
// x87 Transcendental Family: FSIN / FCOS / FPTAN / FPATAN / F2XM1 / FYL2X / FYL2XP1 / FSCALE
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct Fsin;

impl SemanticProvider for Fsin {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1400)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSIN
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Sin), F64, &[f])?;
        let packed = x87_pack_st(out, res)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1400, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fcos;

impl SemanticProvider for Fcos {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1401)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FCOS
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Cos), F64, &[f])?;
        let packed = x87_pack_st(out, res)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1401, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fptan;

impl SemanticProvider for Fptan {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1402)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FPTAN
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let tan_val = out.emit(SemanticOp::Float(FloatingOp::Tan), F64, &[f])?;
        let packed = x87_pack_st(out, tan_val)?;
        x87_write_st(out, 0, packed)?;
        let one = const_f64(out, 0x3FF0_0000_0000_0000)?;
        x87_push_st(out, one)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1402, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fpatan;

impl SemanticProvider for Fpatan {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1403)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FPATAN
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let st0 = x87_read_st(out, 0)?;
        let st1 = x87_read_st(out, 1)?;
        let x = x87_unpack_st(out, st0)?;
        let y = x87_unpack_st(out, st1)?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Atan2), F64, &[y, x])?;
        let packed = x87_pack_st(out, res)?;
        x87_pop_st(out)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1403, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct F2xm1;

impl SemanticProvider for F2xm1 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1404)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::F2XM1
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = x87_read_st(out, 0)?;
        let f = x87_unpack_st(out, top)?;
        let exp2 = out.emit(SemanticOp::Float(FloatingOp::Exp2), F64, &[f])?;
        let one = const_f64(out, 0x3FF0_0000_0000_0000)?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Sub), F64, &[exp2, one])?;
        let packed = x87_pack_st(out, res)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1404, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fyl2x;

impl SemanticProvider for Fyl2x {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1405)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FYL2X
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let st0 = x87_read_st(out, 0)?;
        let st1 = x87_read_st(out, 1)?;
        let x = x87_unpack_st(out, st0)?;
        let y = x87_unpack_st(out, st1)?;
        let log2_x = out.emit(SemanticOp::Float(FloatingOp::Log2), F64, &[x])?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Mul), F64, &[y, log2_x])?;
        let packed = x87_pack_st(out, res)?;
        x87_pop_st(out)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1405, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fyl2xp1;

impl SemanticProvider for Fyl2xp1 {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1406)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FYL2XP1
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let st0 = x87_read_st(out, 0)?;
        let st1 = x87_read_st(out, 1)?;
        let x = x87_unpack_st(out, st0)?;
        let y = x87_unpack_st(out, st1)?;
        let one = const_f64(out, 0x3FF0_0000_0000_0000)?;
        let x_p1 = out.emit(SemanticOp::Float(FloatingOp::Add), F64, &[x, one])?;
        let log2_val = out.emit(SemanticOp::Float(FloatingOp::Log2), F64, &[x_p1])?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Mul), F64, &[y, log2_val])?;
        let packed = x87_pack_st(out, res)?;
        x87_pop_st(out)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1406, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Fscale;

impl SemanticProvider for Fscale {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x1407)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSCALE
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let st0 = x87_read_st(out, 0)?;
        let st1 = x87_read_st(out, 1)?;
        let val = x87_unpack_st(out, st0)?;
        let scale = x87_unpack_st(out, st1)?;
        let res = out.emit(SemanticOp::Float(FloatingOp::Scale), F64, &[val, scale])?;
        let packed = x87_pack_st(out, res)?;
        x87_write_st(out, 0, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(0x1407, context))
    }
}
