//! Scalar FP arithmetic providers (FADD/FSUB/FMUL/FDIV/FNEG/FSQRT/FABS/FCMP,
//! S and D). FCMP composes A64 NZCV from the IR FCompareFlags word
//! (CF=bit0, PF=bit2, ZF=bit6); NaN handling is a documented phase-1 debt.

use std::sync::Arc;

use angryier_semantics::{
    DecodedInstructionView, FloatFormat, FloatingOp, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext,
    SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType,
};
use angryier_types::SemanticRuleId;

use crate::providers::{const_ty, read_operand_typed};
use crate::rule_id;

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));

fn float_ty(double: bool) -> SemanticType {
    SemanticType::Scalar(ScalarType::Float(if double {
        FloatFormat::F64
    } else {
        FloatFormat::F32
    }))
}

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next = out.constant(U64, &insn.address().wrapping_add(4).to_le_bytes())?;
    out.jump(next)?;
    Ok(())
}

fn receipt(offset: u64, context: &SemanticContext) -> SemanticReceipt {
    SemanticReceipt {
        rule_id: rule_id(offset),
        origin: SemanticOrigin::HandwrittenOverride,
        semantic_version: context.semantic_version,
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FpBinaryProvider {
    pub form: u32,
    pub rule: u64,
    pub op: FloatingOp,
}

impl SemanticProvider for FpBinaryProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let double = insn.operand(0).map(|o| o.width_bits == 64).unwrap_or(false);
        let ty = float_ty(double);
        let left = read_operand_typed(out, insn, 1, ty)?;
        let right = read_operand_typed(out, insn, 2, ty)?;
        let result = out.emit(SemanticOp::Float(self.op), ty, &[left, right])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FpUnaryProvider {
    pub form: u32,
    pub rule: u64,
    pub op: FloatingOp,
}

impl SemanticProvider for FpUnaryProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let double = insn.operand(0).map(|o| o.width_bits == 64).unwrap_or(false);
        let ty = float_ty(double);
        let value = read_operand_typed(out, insn, 1, ty)?;
        let result = out.emit(SemanticOp::Float(self.op), ty, &[value])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FcmpProvider {
    pub form: u32,
    pub rule: u64,
}

impl SemanticProvider for FcmpProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let double = insn.operand(0).map(|o| o.width_bits == 64).unwrap_or(false);
        let ty = float_ty(double);
        let left = read_operand_typed(out, insn, 0, ty)?;
        let right = read_operand_typed(out, insn, 1, ty)?;
        let flags = out.emit(SemanticOp::Float(FloatingOp::Compare), U64, &[left, right])?;

        // FCompareFlags layout: CF=bit0, ZF=bit6.
        let one = const_ty(out, U64, 1)?;
        let six = const_ty(out, U64, 6)?;
        let zf_shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[flags, six],
        )?;
        let zf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[zf_shifted, one])?;
        let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[flags, one])?;
        // N = CF & !ZF (left < right), C = CF, V = 0, Z = ZF.
        let zf_u1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[zf, one])?;
        let cf_u1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[cf, one])?;
        let not_z = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[zf_u1])?;
        let n_u1 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[cf_u1, not_z])?;
        let zero_u1 = const_ty(out, U1, 0)?;
        let n32 = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ZeroExtend),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[n_u1],
        )?;
        let z32 = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ZeroExtend),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[zf_u1],
        )?;
        let c32 = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ZeroExtend),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[cf_u1],
        )?;
        let v32 = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ZeroExtend),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[zero_u1],
        )?;
        let amt31 = const_ty(out, SemanticType::Scalar(ScalarType::BitVec(32)), 31)?;
        let amt30 = const_ty(out, SemanticType::Scalar(ScalarType::BitVec(32)), 30)?;
        let amt29 = const_ty(out, SemanticType::Scalar(ScalarType::BitVec(32)), 29)?;
        let n_sh = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[n32, amt31],
        )?;
        let z_sh = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[z32, amt30],
        )?;
        let c_sh = out.emit(
            SemanticOp::Primitive(PrimitiveOp::ShiftLeft),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[c32, amt29],
        )?;
        let _ = v32;
        let nz = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[n_sh, z_sh],
        )?;
        let nzc = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Or),
            SemanticType::Scalar(ScalarType::BitVec(32)),
            &[nz, c_sh],
        )?;
        out.write_register(angryier_arch_arm64::regs::register_id::NZCV, nzc)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FpImmProvider {
    pub form: u32,
    pub rule: u64,
}

impl SemanticProvider for FpImmProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let width = insn.operand(0).map(|o| o.width_bits).unwrap_or(32);
        let ty = SemanticType::Scalar(ScalarType::BitVec(width));
        let value = insn
            .operand(1)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let constant = out.constant(ty, &value.to_le_bytes()[..usize::from(width).div_ceil(8)])?;
        out.write_operand(0, constant)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FpMoveProvider {
    pub form: u32,
    pub rule: u64,
}

impl SemanticProvider for FpMoveProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let width = insn.operand(0).map(|o| o.width_bits).unwrap_or(32);
        let ty = SemanticType::Scalar(ScalarType::BitVec(width));
        let value = read_operand_typed(out, insn, 1, ty)?;
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FcvtProvider {
    pub form: u32,
    pub rule: u64,
    pub to_double: bool,
}

impl SemanticProvider for FcvtProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src_ty = if self.to_double {
            SemanticType::Scalar(ScalarType::Float(FloatFormat::F32))
        } else {
            SemanticType::Scalar(ScalarType::Float(FloatFormat::F64))
        };
        let dst_ty = if self.to_double {
            SemanticType::Scalar(ScalarType::Float(FloatFormat::F64))
        } else {
            SemanticType::Scalar(ScalarType::Float(FloatFormat::F32))
        };
        let value = read_operand_typed(out, insn, 1, src_ty)?;
        let converted = out.emit(SemanticOp::Float(FloatingOp::Convert), dst_ty, &[value])?;
        out.write_operand(0, converted)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FcselProvider {
    pub form: u32,
    pub rule: u64,
}

impl SemanticProvider for FcselProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let double = insn.operand(0).map(|o| o.width_bits == 64).unwrap_or(false);
        let ty = float_ty(double);
        let cond = insn
            .operand(3)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value as u8,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let nzcv = out.read_register(angryier_arch_arm64::regs::register_id::NZCV, U32)?;
        // A64 ConditionHolds treats both AL and NV as unconditional here.
        let condition = if cond == 14 || cond == 15 {
            out.constant(SemanticType::Scalar(ScalarType::BitVec(1)), &[1])?
        } else {
            crate::providers::condition_value(out, cond, nzcv)?
        };
        let rn = read_operand_typed(out, insn, 1, ty)?;
        let rm = read_operand_typed(out, insn, 2, ty)?;
        let selected = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), ty, &[condition, rn, rm])?;
        out.write_operand(0, selected)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FcvtzProvider {
    pub form: u32,
    pub rule: u64,
    pub unsigned: bool,
}

impl SemanticProvider for FcvtzProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let src_width = insn.operand(1).map(|o| o.width_bits).unwrap_or(32);
        let dst_width = insn.operand(0).map(|o| o.width_bits).unwrap_or(32);
        let src_ty = SemanticType::Scalar(ScalarType::Float(if src_width == 64 {
            FloatFormat::F64
        } else {
            FloatFormat::F32
        }));
        let dst_ty = SemanticType::Scalar(ScalarType::BitVec(dst_width));
        let value = read_operand_typed(out, insn, 1, src_ty)?;
        let op = if self.unsigned {
            FloatingOp::ToIntUnsigned
        } else {
            FloatingOp::ToIntSigned
        };
        let converted = out.emit(SemanticOp::Float(op), dst_ty, &[value])?;
        // Register 31 is WZR/XZR for these forms, never SP.
        let destination = insn.operand(0).ok_or(SemanticError::InvalidOperand)?;
        if !matches!(destination.kind, angryier_semantics::OperandKind::Register(view)
            if view.parent == angryier_arch_arm64::regs::register_id::ZR)
        {
            out.write_operand(0, converted)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

pub(crate) fn register_scvtf(providers: &mut Vec<(u32, Arc<dyn SemanticProvider>)>, next_rule: &mut u64) {
    use angryier_arch_arm64::forms_fp::*;
    for (form, vector_lane_bits) in [
        (SCVTF_S_W, None),
        (SCVTF_D_W, None),
        (SCVTF_S_X, None),
        (SCVTF_D_X, None),
        (SCVTF_S_S, None),
        (SCVTF_D_D, None),
        (SCVTF_V2S, Some(32)),
        (SCVTF_V4S, Some(32)),
        (SCVTF_V2D, Some(64)),
    ] {
        providers.push((
            form,
            Arc::new(ScvtfProvider {
                form,
                rule: *next_rule,
                vector_lane_bits,
            }),
        ));
        *next_rule += 1;
    }
}

#[derive(Clone, Copy, Debug)]
struct ScvtfProvider {
    form: u32,
    rule: u64,
    vector_lane_bits: Option<u16>,
}

impl SemanticProvider for ScvtfProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let destination = insn.operand(0).ok_or(SemanticError::InvalidOperand)?;
        let source = insn.operand(1).ok_or(SemanticError::InvalidOperand)?;
        let bits = self.vector_lane_bits.unwrap_or(source.width_bits);
        let source_ty = SemanticType::Scalar(ScalarType::BitVec(source.width_bits));
        let value = if matches!(source.kind, angryier_semantics::OperandKind::Register(view)
            if view.parent == angryier_arch_arm64::regs::register_id::ZR)
        {
            out.constant(source_ty, &0u64.to_le_bytes()[..usize::from(source.width_bits / 8)])?
        } else {
            read_operand_typed(out, insn, 1, source_ty)?
        };
        let converted = if self.vector_lane_bits.is_some() {
            let lanes = destination.width_bits / bits;
            let mut result = None;
            for lane in 0..lanes {
                let offset = out.constant(U64, &u64::from(lane * bits).to_le_bytes())?;
                let input = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    SemanticType::Scalar(ScalarType::BitVec(bits)),
                    &[value, offset],
                )?;
                let converted = out.emit(
                    SemanticOp::Float(FloatingOp::FromIntSigned),
                    float_ty(bits == 64),
                    &[input],
                )?;
                result = Some(if let Some(previous) = result {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Concat),
                        SemanticType::Scalar(ScalarType::BitVec((lane + 1) * bits)),
                        &[previous, converted],
                    )?
                } else {
                    converted
                });
            }
            result.ok_or(SemanticError::InvalidOperand)?
        } else {
            out.emit(
                SemanticOp::Float(FloatingOp::FromIntSigned),
                float_ty(destination.width_bits == 64),
                &[value],
            )?
        };
        out.write_operand(0, converted)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

pub(crate) fn register(providers: &mut Vec<(u32, Arc<dyn SemanticProvider>)>, next_rule: &mut u64) {
    use angryier_arch_arm64::forms_fp::*;
    macro_rules! push {
        ($form:expr, $provider:expr) => {{
            providers.push(($form, $provider));
            *next_rule += 1;
        }};
    }
    macro_rules! rule {
        () => {
            *next_rule
        };
    }
    for (s_form, d_form, op) in [
        (FADD_S, FADD_D, FloatingOp::Add),
        (FSUB_S, FSUB_D, FloatingOp::Sub),
        (FMUL_S, FMUL_D, FloatingOp::Mul),
        (FDIV_S, FDIV_D, FloatingOp::Div),
    ] {
        push!(
            s_form,
            Arc::new(FpBinaryProvider {
                form: s_form,
                rule: rule!(),
                op
            })
        );
        push!(
            d_form,
            Arc::new(FpBinaryProvider {
                form: d_form,
                rule: rule!(),
                op
            })
        );
    }
    for (s_form, d_form, op) in [
        (FNEG_S, FNEG_D, FloatingOp::Neg),
        (FSQRT_S, FSQRT_D, FloatingOp::Sqrt),
        (FABS_S, FABS_D, FloatingOp::Abs),
    ] {
        push!(
            s_form,
            Arc::new(FpUnaryProvider {
                form: s_form,
                rule: rule!(),
                op
            })
        );
        push!(
            d_form,
            Arc::new(FpUnaryProvider {
                form: d_form,
                rule: rule!(),
                op
            })
        );
    }
    push!(
        FCMP_S,
        Arc::new(FcmpProvider {
            form: FCMP_S,
            rule: rule!()
        })
    );
    push!(
        FCMP_D,
        Arc::new(FcmpProvider {
            form: FCMP_D,
            rule: rule!()
        })
    );
    for form in [FMOV_S_W, FMOV_W_S, FMOV_D_X, FMOV_X_D] {
        push!(form, Arc::new(FpMoveProvider { form, rule: rule!() }));
    }
    for form in [FMOV_IS, FMOV_ID] {
        push!(form, Arc::new(FpImmProvider { form, rule: rule!() }));
    }
    push!(
        FCVT_D_S,
        Arc::new(FcvtProvider {
            form: FCVT_D_S,
            rule: rule!(),
            to_double: true
        })
    );
    push!(
        FCVT_S_D,
        Arc::new(FcvtProvider {
            form: FCVT_S_D,
            rule: rule!(),
            to_double: false
        })
    );
    push!(
        FCSEL_S,
        Arc::new(FcselProvider {
            form: FCSEL_S,
            rule: rule!()
        })
    );
    push!(
        FCSEL_D,
        Arc::new(FcselProvider {
            form: FCSEL_D,
            rule: rule!()
        })
    );
    for (form, unsigned) in [
        (FCVTZS_W_S, false),
        (FCVTZS_W_D, false),
        (FCVTZS_X_S, false),
        (FCVTZS_X_D, false),
        (FCVTZU_W_S, true),
        (FCVTZU_W_D, true),
        (FCVTZU_X_S, true),
        (FCVTZU_X_D, true),
    ] {
        push!(
            form,
            Arc::new(FcvtzProvider {
                form,
                rule: rule!(),
                unsigned
            })
        );
    }
}
