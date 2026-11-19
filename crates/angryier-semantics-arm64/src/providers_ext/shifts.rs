//! Variable-shift (LSLV/LSRV/ASRV/RORV) semantic providers — owned by a
//! parallel work stream.

use std::sync::Arc;

use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext, SemanticError, SemanticOp,
    SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, ValueId,
};
use angryier_types::SemanticRuleId;

use crate::rule_id;

// The form ids live in `angryier-arch-arm64::forms_shifts`, which is
// `pub(crate)` and therefore not re-exported to this crate. Re-derive them
// from the public `FORM_BASE` and the 0x130..=0x137 offsets assigned to the
// shifts extension group.
const LSLV_W: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x130;
const LSLV_X: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x131;
const LSRV_W: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x132;
const LSRV_X: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x133;
const ASRV_W: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x134;
const ASRV_X: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x135;
const RORV_W: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x136;
const RORV_X: u32 = angryier_arch_arm64::forms::FORM_BASE + 0x137;

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

fn receipt(offset: u64, context: &SemanticContext) -> SemanticReceipt {
    SemanticReceipt {
        rule_id: rule_id(offset),
        origin: SemanticOrigin::HandwrittenOverride,
        semantic_version: context.semantic_version,
    }
}

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
    out.jump(next_pc)?;
    Ok(())
}

fn read_operand_typed(
    out: &mut dyn SemanticBuilder,
    insn: &dyn DecodedInstructionView,
    index: u8,
    ty: SemanticType,
) -> Result<ValueId, SemanticError> {
    let _ = insn;
    out.read_operand(index, ty)
}

/// Variable-shift register provider: `Rd = op(Rn, Rm)` at the destination's
/// operand width. The shift amount is the low 5 (W) / 6 (X) bits of `Rm`, which
/// the lowering layer derives from the operand-width read of the Rm register.
#[derive(Clone, Copy, Debug)]
pub struct ShiftProvider {
    pub form: u32,
    pub rule: u64,
    pub op: PrimitiveOp,
}

impl SemanticProvider for ShiftProvider {
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
        let width = insn.operand(0).map(|o| o.width_bits).unwrap_or(64);
        let ty = SemanticType::Scalar(ScalarType::BitVec(width));
        let value = read_operand_typed(out, insn, 1, ty)?;
        let amount = read_operand_typed(out, insn, 2, ty)?;
        let result = out.emit(SemanticOp::Primitive(self.op), ty, &[value, amount])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

pub(crate) fn register(providers: &mut Vec<(u32, Arc<dyn SemanticProvider>)>, next_rule: &mut u64) {
    for (form, op) in [
        (LSLV_W, PrimitiveOp::ShiftLeft),
        (LSLV_X, PrimitiveOp::ShiftLeft),
        (LSRV_W, PrimitiveOp::LogicalShiftRight),
        (LSRV_X, PrimitiveOp::LogicalShiftRight),
        (ASRV_W, PrimitiveOp::ArithmeticShiftRight),
        (ASRV_X, PrimitiveOp::ArithmeticShiftRight),
        (RORV_W, PrimitiveOp::RotateRight),
        (RORV_X, PrimitiveOp::RotateRight),
    ] {
        providers.push((
            form,
            Arc::new(ShiftProvider {
                form,
                rule: *next_rule,
                op,
            }),
        ));
        *next_rule += 1;
    }
}
