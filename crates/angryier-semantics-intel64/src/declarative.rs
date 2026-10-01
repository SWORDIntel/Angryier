//! Declarative provider — interprets `SemanticPattern`s emitted by the
//! semantic generator (`angryier-semantics-gen`) into real `SemanticOp`
//! sequences. Generated providers flow through the same IR lowering,
//! interpreters, sealing, and hardware differential oracle as handwritten
//! providers — the generator emits `DeclarativeGenerated` origins, and the
//! oracle is the single validation gate for both.

use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext, SemanticError, SemanticOp,
    SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, VectorOp,
};
use angryier_semantics_gen::{FlagPolicy, SemanticPattern, ShiftPattern};
use angryier_types::SemanticRuleId;

use crate::providers::{
    ShiftKind, fall_through, widen_to_u64, write_add_flags, write_add_flags_preserve_cf, write_logical_flags,
    write_rotate_flags_width_count, write_shift_flags, write_sub_flags, write_sub_flags_preserve_cf,
};
use crate::rule_id;

/// A semantic provider produced by the generator from a declarative pattern.
#[derive(Clone, Debug)]
pub struct DeclarativeProvider {
    /// The instruction form this provider implements.
    pub form_id: u32,
    /// Rule-id offset (generated rules allocate from the 0x10000 band).
    pub rule_offset: u64,
    /// The declarative pattern to interpret.
    pub pattern: SemanticPattern,
}

impl SemanticProvider for DeclarativeProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule_offset)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::DeclarativeGenerated
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == self.form_id
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        emit_pattern(&self.pattern, out, insn)?;
        fall_through(out, insn)?;
        Ok(SemanticReceipt {
            rule_id: rule_id(self.rule_offset),
            semantic_version: context.semantic_version,
            origin: SemanticOrigin::DeclarativeGenerated,
        })
    }
}

fn scalar(bits: u16) -> SemanticType {
    SemanticType::Scalar(ScalarType::BitVec(bits))
}

fn vector(lanes: u16, lane_bits: u16) -> SemanticType {
    SemanticType::Vector {
        lanes,
        lane: ScalarType::BitVec(lane_bits),
    }
}

fn emit_pattern(
    pattern: &SemanticPattern,
    out: &mut dyn SemanticBuilder,
    _insn: &dyn DecodedInstructionView,
) -> Result<(), SemanticError> {
    match pattern {
        SemanticPattern::BinaryAlu { op, width_bits, flags } => {
            let ty = scalar(*width_bits);
            let left = out.read_operand(0, ty)?;
            let right = out.read_operand(1, ty)?;
            let result = out.emit(SemanticOp::Primitive(*op), ty, &[left, right])?;
            match flags {
                FlagPolicy::None => {}
                FlagPolicy::Arithmetic => match op {
                    PrimitiveOp::Add => write_add_flags(out, result, left, right, *width_bits)?,
                    PrimitiveOp::Sub => write_sub_flags(out, result, left, right, *width_bits)?,
                    PrimitiveOp::And | PrimitiveOp::Or | PrimitiveOp::Xor => {
                        write_logical_flags(out, result, *width_bits)?
                    }
                    _ => write_logical_flags(out, result, *width_bits)?,
                },
                FlagPolicy::Logical => write_logical_flags(out, result, *width_bits)?,
                FlagPolicy::PreserveCf => match op {
                    PrimitiveOp::Add => write_add_flags_preserve_cf(out, result, left, right, *width_bits)?,
                    PrimitiveOp::Sub => write_sub_flags_preserve_cf(out, result, left, right, *width_bits)?,
                    _ => write_logical_flags(out, result, *width_bits)?,
                },
            }
            out.write_operand(0, result)?;
        }
        SemanticPattern::PackedLane { op, lanes, lane_bits } => {
            let ty = vector(*lanes, *lane_bits);
            let dst = out.read_operand(0, ty)?;
            let src = out.read_operand(1, ty)?;
            let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(*op)), ty, &[dst, src])?;
            out.write_operand(0, result)?;
        }
        SemanticPattern::Extend {
            src_bits,
            dst_bits,
            signed,
        } => {
            let src = out.read_operand(1, scalar(*src_bits))?;
            let op = if *signed {
                PrimitiveOp::SignExtend
            } else {
                PrimitiveOp::ZeroExtend
            };
            let result = out.emit(SemanticOp::Primitive(op), scalar(*dst_bits), &[src])?;
            out.write_operand(0, result)?;
        }
        SemanticPattern::UnaryAlu { negate, width_bits } => {
            let ty = scalar(*width_bits);
            let operand = out.read_operand(0, ty)?;
            if *negate {
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), ty, &[operand])?;
                out.write_operand(0, result)?;
            } else {
                let zero = out.constant(ty, &0u64.to_le_bytes()[..usize::from(*width_bits).div_ceil(8)])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), ty, &[zero, operand])?;
                write_sub_flags(out, result, zero, operand, *width_bits)?;
                out.write_operand(0, result)?;
            }
        }
        SemanticPattern::Shift { kind, width_bits } => {
            let ty = scalar(*width_bits);
            let left = out.read_operand(0, ty)?;
            let count = out.read_operand(1, ty)?;
            let mask_bits = if *width_bits == 64 { 0x3Fu64 } else { 0x1Fu64 };
            let mask = out.constant(ty, &mask_bits.to_le_bytes()[..usize::from(*width_bits).div_ceil(8)])?;
            let count_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[count, mask])?;
            let (prim, shift_kind) = match kind {
                ShiftPattern::Left => (PrimitiveOp::ShiftLeft, ShiftKind::Left),
                ShiftPattern::RightLogical => (PrimitiveOp::LogicalShiftRight, ShiftKind::RightLogical),
                ShiftPattern::RightArithmetic => (PrimitiveOp::ArithmeticShiftRight, ShiftKind::RightArith),
                ShiftPattern::RotateLeft => (PrimitiveOp::RotateLeft, ShiftKind::RotateLeft),
                ShiftPattern::RotateRight => (PrimitiveOp::RotateRight, ShiftKind::RotateRight),
            };
            let result = out.emit(SemanticOp::Primitive(prim), ty, &[left, count_masked])?;
            match kind {
                ShiftPattern::RotateLeft | ShiftPattern::RotateRight => {
                    let count64 = widen_to_u64(out, count_masked, *width_bits)?;
                    write_rotate_flags_width_count(out, result, shift_kind, *width_bits, Some(count64))?;
                }
                _ => write_shift_flags(out, left, count_masked, result, shift_kind, *width_bits)?,
            }
            out.write_operand(0, result)?;
        }
    }
    Ok(())
}

/// First rule-offset in the generated band (handwritten corpus uses
/// 0x0000-0x0FFF style offsets; generated rules start at 0x10000 so the two
/// spaces never collide).
pub const GENERATED_RULE_BASE: u64 = 0x10000;

/// Builds generated providers for `(form_id, pattern)` pairs; rule offsets
/// are assigned sequentially from [`GENERATED_RULE_BASE`].
pub fn generated_providers(defs: &[(u32, SemanticPattern)]) -> Vec<DeclarativeProvider> {
    defs.iter()
        .enumerate()
        .map(|(index, (form_id, pattern))| DeclarativeProvider {
            form_id: *form_id,
            rule_offset: GENERATED_RULE_BASE + index as u64,
            pattern: pattern.clone(),
        })
        .collect()
}
