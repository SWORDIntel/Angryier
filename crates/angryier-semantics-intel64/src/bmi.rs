#![forbid(unsafe_code)]

//! BMI1 and BMI2 (Bit Manipulation Instruction Sets 1 & 2) semantic providers.
//!
//! Covers:
//! - BMI1: ANDN, BEXTR, BLSI, BLSMSK, BLSR
//! - BMI2: BZHI, MULX, RORX, SARX, SHLX, SHRX

use crate::providers::{compose_rflags, fall_through, receipt, widen_to_u64, zf_sf};
use crate::{forms, rflags, rule_id};
use angryier_arch_intel64::register_id;
use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder, SemanticContext, SemanticError,
    SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, ValueId,
};
use angryier_types::SemanticRuleId;

const U128: SemanticType = SemanticType::Scalar(ScalarType::BitVec(128));
const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));

fn const_u32(out: &mut dyn SemanticBuilder, val: u32) -> Result<ValueId, SemanticError> {
    out.constant(U32, &val.to_le_bytes())
}

fn const_u64(out: &mut dyn SemanticBuilder, val: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &val.to_le_bytes())
}

fn const_u128(out: &mut dyn SemanticBuilder, val: u128) -> Result<ValueId, SemanticError> {
    out.constant(U128, &val.to_le_bytes())
}

fn shift_cf(out: &mut dyn SemanticBuilder, cf_1: ValueId) -> Result<ValueId, SemanticError> {
    let cf_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[cf_1])?;
    let cf_bit = const_u64(out, u64::from(rflags::CF_BIT))?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[cf_64, cf_bit])
}

// ---------------------------------------------------------------------------
// ANDN: dest = (!src1) & src2
// Flags: ZF, SF from result; CF=0, OF=0.
// ---------------------------------------------------------------------------

macro_rules! define_andn {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr) => {
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
                let src1 = out.read_operand(1, $ty)?;
                let src2 = out.read_operand(2, $ty)?;
                let not_src1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), $ty, &[src1])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[not_src1, src2])?;
                let res_u64 = widen_to_u64(out, result, $width)?;
                let (zf, sf) = zf_sf(out, res_u64, $width - 1)?;
                compose_rflags(out, &[zf, sf], false)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_andn!(AndnR32R32R32, forms::ANDN_R32_R32_R32, 0x1450, U32, 32);
define_andn!(AndnR32R32M32, forms::ANDN_R32_R32_MEM32, 0x1451, U32, 32);
define_andn!(AndnR64R64R64, forms::ANDN_R64_R64_R64, 0x1452, U64, 64);
define_andn!(AndnR64R64M64, forms::ANDN_R64_R64_MEM64, 0x1453, U64, 64);

// ---------------------------------------------------------------------------
// BEXTR: Bit Field Extract
// dest = (src >> control[7:0]) & ((1 << control[15:8]) - 1)
// Flags: ZF = (dest == 0), CF=0, OF=0.
// ---------------------------------------------------------------------------

macro_rules! define_bextr {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let control = out.read_operand(2, $ty)?;
                let mask_ff = $const_fn(out, 0xFF)?;
                let start = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[control, mask_ff])?;
                let eight = $const_fn(out, 8)?;
                let len_raw = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                    $ty,
                    &[control, eight],
                )?;
                let len = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[len_raw, mask_ff])?;

                let shifted = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                    $ty,
                    &[src, start],
                )?;
                let one = $const_fn(out, 1)?;
                let one_shl = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), $ty, &[one, len])?;
                let mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[one_shl, one])?;
                let extracted = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[shifted, mask])?;

                // If start >= width, result is 0
                let width_val = $const_fn(out, $width)?;
                let start_ge_width = out.emit(SemanticOp::Primitive(PrimitiveOp::Ule), U1, &[width_val, start])?;
                let zero = $const_fn(out, 0)?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    $ty,
                    &[start_ge_width, zero, extracted],
                )?;

                let res_u64 = widen_to_u64(out, result, $width)?;
                let (zf, _) = zf_sf(out, res_u64, $width - 1)?;
                compose_rflags(out, &[zf], false)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_bextr!(BextrR32R32R32, forms::BEXTR_R32_R32_R32, 0x1454, U32, 32, const_u32);
define_bextr!(BextrR32M32R32, forms::BEXTR_R32_MEM32_R32, 0x1455, U32, 32, const_u32);
define_bextr!(BextrR64R64R64, forms::BEXTR_R64_R64_R64, 0x1456, U64, 64, const_u64);
define_bextr!(BextrR64M64R64, forms::BEXTR_R64_MEM64_R64, 0x1457, U64, 64, const_u64);

// ---------------------------------------------------------------------------
// BLSI: Extract Lowest Set Isolated Bit ((-src) & src)
// Flags: CF = (src != 0), ZF = (dest == 0), SF = dest[width-1], OF=0.
// ---------------------------------------------------------------------------

macro_rules! define_blsi {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let zero = $const_fn(out, 0)?;
                let neg_src = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[zero, src])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[neg_src, src])?;

                let res_u64 = widen_to_u64(out, result, $width)?;
                let (zf, sf) = zf_sf(out, res_u64, $width - 1)?;
                let src_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
                let one_u1 = out.constant(U1, &[1])?;
                let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[src_zero, one_u1])?; // CF = src != 0
                let cf = shift_cf(out, cf_1)?;
                compose_rflags(out, &[zf, sf, cf], false)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_blsi!(BlsiR32R32, forms::BLSI_R32_R32, 0x1458, U32, 32, const_u32);
define_blsi!(BlsiR32M32, forms::BLSI_R32_MEM32, 0x1459, U32, 32, const_u32);
define_blsi!(BlsiR64R64, forms::BLSI_R64_R64, 0x145A, U64, 64, const_u64);
define_blsi!(BlsiR64M64, forms::BLSI_R64_MEM64, 0x145B, U64, 64, const_u64);

// ---------------------------------------------------------------------------
// BLSMSK: Get Mask Up to Lowest Set Bit ((src - 1) ^ src)
// Flags: CF = (src == 0), ZF = 0, SF = dest[width-1], OF=0.
// ---------------------------------------------------------------------------

macro_rules! define_blsmsk {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let one = $const_fn(out, 1)?;
                let src_m1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[src, one])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), $ty, &[src_m1, src])?;

                let res_u64 = widen_to_u64(out, result, $width)?;
                let (_, sf) = zf_sf(out, res_u64, $width - 1)?;
                let zero = $const_fn(out, 0)?;
                let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
                let cf = shift_cf(out, cf_1)?;
                compose_rflags(out, &[sf, cf], false)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_blsmsk!(BlsmskR32R32, forms::BLSMSK_R32_R32, 0x145C, U32, 32, const_u32);
define_blsmsk!(BlsmskR32M32, forms::BLSMSK_R32_MEM32, 0x145D, U32, 32, const_u32);
define_blsmsk!(BlsmskR64R64, forms::BLSMSK_R64_R64, 0x145E, U64, 64, const_u64);
define_blsmsk!(BlsmskR64M64, forms::BLSMSK_R64_MEM64, 0x145F, U64, 64, const_u64);

// ---------------------------------------------------------------------------
// BLSR: Reset Lowest Set Bit ((src - 1) & src)
// Flags: CF = (src == 0), ZF = (dest == 0), SF = dest[width-1], OF=0.
// ---------------------------------------------------------------------------

macro_rules! define_blsr {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let one = $const_fn(out, 1)?;
                let src_m1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[src, one])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[src_m1, src])?;

                let res_u64 = widen_to_u64(out, result, $width)?;
                let (zf, sf) = zf_sf(out, res_u64, $width - 1)?;
                let zero = $const_fn(out, 0)?;
                let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[src, zero])?;
                let cf = shift_cf(out, cf_1)?;
                compose_rflags(out, &[zf, sf, cf], false)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_blsr!(BlsrR32R32, forms::BLSR_R32_R32, 0x1460, U32, 32, const_u32);
define_blsr!(BlsrR32M32, forms::BLSR_R32_MEM32, 0x1461, U32, 32, const_u32);
define_blsr!(BlsrR64R64, forms::BLSR_R64_R64, 0x1462, U64, 64, const_u64);
define_blsr!(BlsrR64M64, forms::BLSR_R64_MEM64, 0x1463, U64, 64, const_u64);

// ---------------------------------------------------------------------------
// BZHI: Zero High Bits Starting from Specified Bit Position
// Flags: CF = (index >= width), ZF = (dest == 0), SF = dest[width-1], OF=0.
// ---------------------------------------------------------------------------

macro_rules! define_bzhi {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let index_reg = out.read_operand(2, $ty)?;
                let mask_ff = $const_fn(out, 0xFF)?;
                let idx = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::And),
                    $ty,
                    &[index_reg, mask_ff],
                )?;

                let width_val = $const_fn(out, $width)?;
                let cf_1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Ule), U1, &[width_val, idx])?;
                let cf = shift_cf(out, cf_1)?;

                let one = $const_fn(out, 1)?;
                let shl = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), $ty, &[one, idx])?;
                let mask = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), $ty, &[shl, one])?;
                let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[src, mask])?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Select),
                    $ty,
                    &[cf_1, src, masked],
                )?;

                let res_u64 = widen_to_u64(out, result, $width)?;
                let (zf, sf) = zf_sf(out, res_u64, $width - 1)?;
                compose_rflags(out, &[zf, sf, cf], false)?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_bzhi!(BzhiR32R32R32, forms::BZHI_R32_R32_R32, 0x1464, U32, 32, const_u32);
define_bzhi!(BzhiR32M32R32, forms::BZHI_R32_MEM32_R32, 0x1465, U32, 32, const_u32);
define_bzhi!(BzhiR64R64R64, forms::BZHI_R64_R64_R64, 0x1466, U64, 64, const_u64);
define_bzhi!(BzhiR64M64R64, forms::BZHI_R64_MEM64_R64, 0x1467, U64, 64, const_u64);

// ---------------------------------------------------------------------------
// MULX: Unsigned Multiply Without Affecting Flags
// (EDX/RDX * src) -> (dest_hi, dest_lo)
// ---------------------------------------------------------------------------

macro_rules! define_mulx32 {
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
                let edx = out.read_register(RegisterId(register_id::GPR_BASE + 2), U32)?;
                let src = out.read_operand(2, U32)?;
                let edx_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[edx])?;
                let src_64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[src])?;
                let prod = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[edx_64, src_64])?;

                let thirty_two = const_u64(out, 32)?;
                let hi_64 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                    U64,
                    &[prod, thirty_two],
                )?;
                let zero = const_u64(out, 0)?;
                let dest_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[prod, zero])?;
                let dest_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[hi_64, zero])?;

                out.write_operand(0, dest_hi)?;
                out.write_operand(1, dest_lo)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_mulx32!(MulxR32R32R32, forms::MULX_R32_R32_R32, 0x1468);
define_mulx32!(MulxR32R32M32, forms::MULX_R32_R32_MEM32, 0x1469);

macro_rules! define_mulx64 {
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
                let rdx = out.read_register(RegisterId(register_id::GPR_BASE + 2), U64)?;
                let src = out.read_operand(2, U64)?;
                let rdx_128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[rdx])?;
                let src_128 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U128, &[src])?;
                let prod = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U128, &[rdx_128, src_128])?;

                let sixty_four = const_u128(out, 64)?;
                let hi_128 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                    U128,
                    &[prod, sixty_four],
                )?;
                let zero = const_u64(out, 0)?;
                let dest_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[prod, zero])?;
                let dest_hi = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U64, &[hi_128, zero])?;

                out.write_operand(0, dest_hi)?;
                out.write_operand(1, dest_lo)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_mulx64!(MulxR64R64R64, forms::MULX_R64_R64_R64, 0x146A);
define_mulx64!(MulxR64R64M64, forms::MULX_R64_R64_MEM64, 0x146B);

// ---------------------------------------------------------------------------
// RORX: Rotate Right Logical Without Flags
// ---------------------------------------------------------------------------

macro_rules! define_rorx {
    ($name:ident, $form:expr, $rule:expr, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let imm = out.read_operand(2, $ty)?;
                let mask = $const_fn(out, $width - 1)?;
                let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[imm, mask])?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::RotateRight),
                    $ty,
                    &[src, count],
                )?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_rorx!(RorxR32R32Imm8, forms::RORX_R32_R32_IMM8, 0x146C, U32, 32, const_u32);
define_rorx!(RorxR32M32Imm8, forms::RORX_R32_MEM32_IMM8, 0x146D, U32, 32, const_u32);
define_rorx!(RorxR64R64Imm8, forms::RORX_R64_R64_IMM8, 0x146E, U64, 64, const_u64);
define_rorx!(RorxR64M64Imm8, forms::RORX_R64_MEM64_IMM8, 0x146F, U64, 64, const_u64);

// ---------------------------------------------------------------------------
// SARX, SHLX, SHRX: Shift Without Flags
// ---------------------------------------------------------------------------

macro_rules! define_shiftx {
    ($name:ident, $form:expr, $rule:expr, $op:ident, $ty:ident, $width:expr, $const_fn:ident) => {
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
                let count = out.read_operand(2, $ty)?;
                let mask = $const_fn(out, $width - 1)?;
                let masked_count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[count, mask])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::$op), $ty, &[src, masked_count])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

define_shiftx!(
    SarxR32R32R32,
    forms::SARX_R32_R32_R32,
    0x1470,
    ArithmeticShiftRight,
    U32,
    32,
    const_u32
);
define_shiftx!(
    SarxR32M32R32,
    forms::SARX_R32_MEM32_R32,
    0x1471,
    ArithmeticShiftRight,
    U32,
    32,
    const_u32
);
define_shiftx!(
    SarxR64R64R64,
    forms::SARX_R64_R64_R64,
    0x1472,
    ArithmeticShiftRight,
    U64,
    64,
    const_u64
);
define_shiftx!(
    SarxR64M64R64,
    forms::SARX_R64_MEM64_R64,
    0x1473,
    ArithmeticShiftRight,
    U64,
    64,
    const_u64
);

define_shiftx!(
    ShlxR32R32R32,
    forms::SHLX_R32_R32_R32,
    0x1474,
    ShiftLeft,
    U32,
    32,
    const_u32
);
define_shiftx!(
    ShlxR32M32R32,
    forms::SHLX_R32_MEM32_R32,
    0x1475,
    ShiftLeft,
    U32,
    32,
    const_u32
);
define_shiftx!(
    ShlxR64R64R64,
    forms::SHLX_R64_R64_R64,
    0x1476,
    ShiftLeft,
    U64,
    64,
    const_u64
);
define_shiftx!(
    ShlxR64M64R64,
    forms::SHLX_R64_MEM64_R64,
    0x1477,
    ShiftLeft,
    U64,
    64,
    const_u64
);

define_shiftx!(
    ShrxR32R32R32,
    forms::SHRX_R32_R32_R32,
    0x1478,
    LogicalShiftRight,
    U32,
    32,
    const_u32
);
define_shiftx!(
    ShrxR32M32R32,
    forms::SHRX_R32_MEM32_R32,
    0x1479,
    LogicalShiftRight,
    U32,
    32,
    const_u32
);
define_shiftx!(
    ShrxR64R64R64,
    forms::SHRX_R64_R64_R64,
    0x147A,
    LogicalShiftRight,
    U64,
    64,
    const_u64
);
define_shiftx!(
    ShrxR64M64R64,
    forms::SHRX_R64_MEM64_R64,
    0x147B,
    LogicalShiftRight,
    U64,
    64,
    const_u64
);

/// Returns all 44 BMI1 & BMI2 semantic providers.
pub fn bmi_providers() -> Vec<Box<dyn SemanticProvider>> {
    vec![
        // BMI1 (20)
        Box::new(AndnR32R32R32),
        Box::new(AndnR32R32M32),
        Box::new(AndnR64R64R64),
        Box::new(AndnR64R64M64),
        Box::new(BextrR32R32R32),
        Box::new(BextrR32M32R32),
        Box::new(BextrR64R64R64),
        Box::new(BextrR64M64R64),
        Box::new(BlsiR32R32),
        Box::new(BlsiR32M32),
        Box::new(BlsiR64R64),
        Box::new(BlsiR64M64),
        Box::new(BlsmskR32R32),
        Box::new(BlsmskR32M32),
        Box::new(BlsmskR64R64),
        Box::new(BlsmskR64M64),
        Box::new(BlsrR32R32),
        Box::new(BlsrR32M32),
        Box::new(BlsrR64R64),
        Box::new(BlsrR64M64),
        // BMI2 (24)
        Box::new(BzhiR32R32R32),
        Box::new(BzhiR32M32R32),
        Box::new(BzhiR64R64R64),
        Box::new(BzhiR64M64R64),
        Box::new(MulxR32R32R32),
        Box::new(MulxR32R32M32),
        Box::new(MulxR64R64R64),
        Box::new(MulxR64R64M64),
        Box::new(RorxR32R32Imm8),
        Box::new(RorxR32M32Imm8),
        Box::new(RorxR64R64Imm8),
        Box::new(RorxR64M64Imm8),
        Box::new(SarxR32R32R32),
        Box::new(SarxR32M32R32),
        Box::new(SarxR64R64R64),
        Box::new(SarxR64M64R64),
        Box::new(ShlxR32R32R32),
        Box::new(ShlxR32M32R32),
        Box::new(ShlxR64R64R64),
        Box::new(ShlxR64M64R64),
        Box::new(ShrxR32R32R32),
        Box::new(ShrxR32M32R32),
        Box::new(ShrxR64R64R64),
        Box::new(ShrxR64M64R64),
    ]
}
