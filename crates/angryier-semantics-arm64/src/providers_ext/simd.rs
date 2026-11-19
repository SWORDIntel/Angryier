//! simd providers — FP/SIMD memory semantics for the ARM64 backend.
//!
//! Loads and stores reuse the core `LoadProvider`/`StoreProvider`/
//! `IndexedLoadStoreProvider` machinery (width-generic, FP register views), so
//! no new IR operations are introduced. Only the PC-relative literal load and
//! the S/D pair forms (which must distinguish offset/post/pre access
//! addressing) need local providers.

use std::sync::Arc;

use angryier_arch_arm64::forms::FORM_BASE;
use angryier_semantics::{
    DecodedInstructionView, FloatFormat, MemoryBase, OperandKind, PrimitiveOp, ScalarType, SemanticBuilder,
    SemanticContext, SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType,
    SideEffect, ValueId, VectorOp,
};
use angryier_types::SemanticRuleId;

use crate::{IndexedLoadStoreProvider, LoadProvider, StoreProvider, rule_id};

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));

const LDR_S: u32 = FORM_BASE + 0x190;
const LDR_D: u32 = FORM_BASE + 0x191;
const LDR_Q: u32 = FORM_BASE + 0x192;
const STR_S: u32 = FORM_BASE + 0x193;
const STR_D: u32 = FORM_BASE + 0x194;
const STR_Q: u32 = FORM_BASE + 0x195;
const LDUR_S: u32 = FORM_BASE + 0x196;
const LDUR_D: u32 = FORM_BASE + 0x197;
const LDUR_Q: u32 = FORM_BASE + 0x198;
const STUR_S: u32 = FORM_BASE + 0x199;
const STUR_D: u32 = FORM_BASE + 0x19A;
const STUR_Q: u32 = FORM_BASE + 0x19B;
const LDR_S_LIT: u32 = FORM_BASE + 0x19C;
const LDR_D_LIT: u32 = FORM_BASE + 0x19D;
const LDR_S_REG: u32 = FORM_BASE + 0x19E;
const LDR_D_REG: u32 = FORM_BASE + 0x19F;
const LDR_Q_REG: u32 = FORM_BASE + 0x1A0;
const STR_S_REG: u32 = FORM_BASE + 0x1A1;
const STR_D_REG: u32 = FORM_BASE + 0x1A2;
const STR_Q_REG: u32 = FORM_BASE + 0x1A3;
const LDP_S: u32 = FORM_BASE + 0x1A4;
const LDP_Q: u32 = FORM_BASE + 0x1B0;
const STP_Q: u32 = FORM_BASE + 0x1B1;
const LDAR_B: u32 = FORM_BASE + 0x1B2;
const LDAR_H: u32 = FORM_BASE + 0x1B3;
const LDAR_X: u32 = FORM_BASE + 0x1B4;
const STLR_B: u32 = FORM_BASE + 0x1B5;
const STLR_H: u32 = FORM_BASE + 0x1B6;
const STLR_X: u32 = FORM_BASE + 0x1B7;
const LDAR_W: u32 = FORM_BASE + 0x1B8;
const STLR_W: u32 = FORM_BASE + 0x1B9;
const MOV_V: u32 = FORM_BASE + 0x1C0;
const ADD_V16B: u32 = FORM_BASE + 0x1C1;
const ADD_V8H: u32 = FORM_BASE + 0x1C2;
const ADD_V4S: u32 = FORM_BASE + 0x1C3;
const ADD_V2D: u32 = FORM_BASE + 0x1C4;
const SUB_V8H: u32 = FORM_BASE + 0x1C6;
const SUB_V4S: u32 = FORM_BASE + 0x1C7;
const SUB_V2D: u32 = FORM_BASE + 0x1C8;
const AND_V16B: u32 = FORM_BASE + 0x1C9;
const ORR_V16B: u32 = FORM_BASE + 0x1CA;
const EOR_V16B: u32 = FORM_BASE + 0x1CB;
const FADD_V2S: u32 = FORM_BASE + 0x1CC;
const FADD_V4S: u32 = FORM_BASE + 0x1CD;
const FADD_V2D: u32 = FORM_BASE + 0x1CE;
const FSUB_V2D: u32 = FORM_BASE + 0x1D0;
const FMUL_V4S: u32 = FORM_BASE + 0x1D1;
const FDIV_V4S: u32 = FORM_BASE + 0x1D3;
const LDP_D: u32 = FORM_BASE + 0x1A5;
const STP_S: u32 = FORM_BASE + 0x1A6;
const STP_D: u32 = FORM_BASE + 0x1A7;
const LDR_S_POST: u32 = FORM_BASE + 0x1A8;
const LDR_D_POST: u32 = FORM_BASE + 0x1A9;
const STR_S_POST: u32 = FORM_BASE + 0x1AA;
const STR_D_POST: u32 = FORM_BASE + 0x1AB;
const LDR_S_PRE: u32 = FORM_BASE + 0x1AC;
const LDR_D_PRE: u32 = FORM_BASE + 0x1AD;
const STR_S_PRE: u32 = FORM_BASE + 0x1AE;
const STR_D_PRE: u32 = FORM_BASE + 0x1AF;

fn take_rule(next_rule: &mut u64) -> u64 {
    let rule = *next_rule;
    *next_rule += 1;
    rule
}

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
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

pub(crate) fn register_dup(providers: &mut Vec<(u32, Arc<dyn SemanticProvider>)>, next_rule: &mut u64) {
    use angryier_arch_arm64::forms_simd as copy_forms;
    for (form, gpr_lane_bits) in [
        (copy_forms::DUP_ELEMENT, None),
        (copy_forms::DUP_SCALAR, None),
        (copy_forms::DUP_GPR_B, Some(8)),
        (copy_forms::DUP_GPR_H, Some(16)),
        (copy_forms::DUP_GPR_S, Some(32)),
        (copy_forms::DUP_GPR_D, Some(64)),
    ] {
        providers.push((
            form,
            Arc::new(DupProvider {
                form,
                rule: take_rule_inc(next_rule),
                gpr_lane_bits,
            }),
        ));
    }
}

#[derive(Clone, Copy, Debug)]
struct DupProvider {
    form: u32,
    rule: u64,
    gpr_lane_bits: Option<u16>,
}

impl SemanticProvider for DupProvider {
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
        let lane_bits = self.gpr_lane_bits.unwrap_or(source.width_bits);
        if !matches!(lane_bits, 8 | 16 | 32 | 64) || destination.width_bits < lane_bits {
            return Err(SemanticError::InvalidOperand);
        }
        let source_ty = SemanticType::Scalar(ScalarType::BitVec(source.width_bits));
        let mut value = if matches!(source.kind, OperandKind::Register(view)
            if view.parent == angryier_arch_arm64::regs::register_id::ZR)
        {
            out.constant(source_ty, &0u64.to_le_bytes()[..usize::from(source.width_bits / 8)])?
        } else {
            crate::providers::read_operand_typed(out, insn, 1, source_ty)?
        };
        if source.width_bits > lane_bits {
            let zero = const_u64(out, 0)?;
            value = out.emit(
                SemanticOp::Primitive(PrimitiveOp::Extract),
                SemanticType::Scalar(ScalarType::BitVec(lane_bits)),
                &[value, zero],
            )?;
        }
        let mut width = lane_bits;
        while width < destination.width_bits {
            width *= 2;
            value = out.emit(
                SemanticOp::Primitive(PrimitiveOp::Concat),
                SemanticType::Scalar(ScalarType::BitVec(width)),
                &[value, value],
            )?;
        }
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

pub(crate) fn register(providers: &mut Vec<(u32, Arc<dyn SemanticProvider>)>, next_rule: &mut u64) {
    // Scaled, unscaled, and register-offset loads/stores reuse the core width-
    // generic Load/Store machinery with the decoded FP register views.
    for (form, width) in [
        (LDR_S, 32u16),
        (LDR_D, 64u16),
        (LDR_Q, 128u16),
        (LDUR_S, 32u16),
        (LDUR_D, 64u16),
        (LDUR_Q, 128u16),
        (LDR_S_REG, 32u16),
        (LDR_D_REG, 64u16),
        (LDR_Q_REG, 128u16),
    ] {
        providers.push((
            form,
            Arc::new(LoadProvider {
                form,
                rule: take_rule(next_rule),
                width,
                sign_extend: false,
            }),
        ));
    }
    for (form, width) in [
        (STR_S, 32u16),
        (STR_D, 64u16),
        (STR_Q, 128u16),
        (STUR_S, 32u16),
        (STUR_D, 64u16),
        (STUR_Q, 128u16),
        (STR_S_REG, 32u16),
        (STR_D_REG, 64u16),
        (STR_Q_REG, 128u16),
    ] {
        providers.push((
            form,
            Arc::new(StoreProvider {
                form,
                rule: take_rule(next_rule),
                width,
            }),
        ));
    }

    // SIMD lane-wise arithmetic.
    {
        use angryier_semantics::{FloatingOp, PrimitiveOp};
        for (form, op, lanes, lane_bits) in [
            (MOV_V, PrimitiveOp::Or, 16u16, 8u16),
            (ADD_V16B, PrimitiveOp::Add, 16, 8),
            (ADD_V8H, PrimitiveOp::Add, 8, 16),
            (ADD_V4S, PrimitiveOp::Add, 4, 32),
            (ADD_V2D, PrimitiveOp::Add, 2, 64),
            (SUB_V8H, PrimitiveOp::Sub, 8, 16),
            (SUB_V4S, PrimitiveOp::Sub, 4, 32),
            (SUB_V2D, PrimitiveOp::Sub, 2, 64),
            (AND_V16B, PrimitiveOp::And, 16, 8),
            (ORR_V16B, PrimitiveOp::Or, 16, 8),
            (EOR_V16B, PrimitiveOp::Xor, 16, 8),
        ] {
            providers.push((
                form,
                Arc::new(SimdLaneProvider {
                    form,
                    rule: take_rule_inc(next_rule),
                    op,
                    lanes,
                    lane_bits,
                }),
            ));
        }
        for (form, op, lanes, lane_bits) in [
            (FADD_V2S, FloatingOp::Add, 2u16, 32u16),
            (FADD_V4S, FloatingOp::Add, 4, 32),
            (FADD_V2D, FloatingOp::Add, 2, 64),
            (FSUB_V2D, FloatingOp::Sub, 2, 64),
            (FMUL_V4S, FloatingOp::Mul, 4, 32),
            (FDIV_V4S, FloatingOp::Div, 4, 32),
        ] {
            providers.push((
                form,
                Arc::new(SimdLaneFloatProvider {
                    form,
                    rule: take_rule_inc(next_rule),
                    op,
                    lanes,
                    lane_bits,
                }),
            ));
        }
    }

    // LDAR/STLR (acquire/release single accesses; ordering is documented
    // debt — they execute as plain loads/stores).
    for (form, width) in [(LDAR_B, 8u16), (LDAR_H, 16u16), (LDAR_W, 32u16), (LDAR_X, 64u16)] {
        providers.push((
            form,
            Arc::new(LoadProvider {
                form,
                rule: take_rule(next_rule),
                width,
                sign_extend: false,
            }),
        ));
    }
    for (form, width) in [(STLR_B, 8u16), (STLR_H, 16u16), (STLR_W, 32u16), (STLR_X, 64u16)] {
        providers.push((
            form,
            Arc::new(StoreProvider {
                form,
                rule: take_rule(next_rule),
                width,
            }),
        ));
    }

    // PC-relative literal loads.
    for (form, width) in [(LDR_S_LIT, 32u16), (LDR_D_LIT, 64u16)] {
        providers.push((
            form,
            Arc::new(LiteralLoadProvider {
                form,
                rule: take_rule(next_rule),
                width,
            }),
        ));
    }

    // S/D/Q pairs (offset/post/pre addressing encoded in the operands).
    for (form, width, load) in [
        (LDP_S, 32u16, true),
        (LDP_D, 64u16, true),
        (LDP_Q, 128u16, true),
        (STP_S, 32u16, false),
        (STP_D, 64u16, false),
        (STP_Q, 128u16, false),
    ] {
        providers.push((
            form,
            Arc::new(FpPairProvider {
                form,
                rule: take_rule(next_rule),
                width,
                load,
            }),
        ));
    }

    // Indexed (post/pre) single loads/stores reuse the core provider.
    for (form, width, load, pre_index) in [
        (LDR_S_POST, 32u16, true, false),
        (LDR_D_POST, 64u16, true, false),
        (STR_S_POST, 32u16, false, false),
        (STR_D_POST, 64u16, false, false),
        (LDR_S_PRE, 32u16, true, true),
        (LDR_D_PRE, 64u16, true, true),
        (STR_S_PRE, 32u16, false, true),
        (STR_D_PRE, 64u16, false, true),
    ] {
        providers.push((
            form,
            Arc::new(IndexedLoadStoreProvider {
                form,
                rule: take_rule(next_rule),
                width,
                load,
                pre_index,
            }),
        ));
    }
}

/// Loads a scalar FP value from a PC-relative address. The decoder stores the
/// `imm19 << 2` byte displacement in the memory operand; the target is the
/// instruction address plus that displacement.
#[derive(Clone, Copy, Debug)]
pub struct LiteralLoadProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
}

impl SemanticProvider for LiteralLoadProvider {
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
        let displacement = insn
            .operand(1)
            .map(|o| match o.kind {
                OperandKind::Memory(mem) => mem.displacement,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let target = const_u64(out, insn.address().wrapping_add(displacement as u64))?;
        let ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        let loaded = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), ty, &[target])?;
        out.write_operand(0, loaded)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

/// Emits two S/D loads or stores with stride `width / 8` bytes. The decoded
/// memory operand carries the pair offset (base + displacement); a mode tag in
/// operand 4 selects the access address (offset = base+disp, post = base,
/// pre = base+disp) and operand 3 signals the base write-back.
#[derive(Clone, Copy, Debug)]
pub struct FpPairProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
    pub load: bool,
}

impl SemanticProvider for FpPairProvider {
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
        let operand = insn.operand(2).ok_or(SemanticError::InvalidOperand)?;
        let (base_parent, displacement) = match operand.kind {
            OperandKind::Memory(mem) => match mem.base {
                Some(MemoryBase::Register(view)) => (view.parent, mem.displacement),
                _ => return Err(SemanticError::InvalidOperand),
            },
            _ => return Err(SemanticError::InvalidOperand),
        };
        // Mode tag: absent = offset (0), operand 4 = 1 (post) or 2 (pre).
        let mode = insn
            .operand(4)
            .map(|o| match o.kind {
                OperandKind::Immediate(imm) => imm.value,
                _ => 0,
            })
            .unwrap_or(0);

        let base = out.read_register(base_parent, U64)?;
        let disp = const_u64(out, displacement as u64)?;
        let access = if mode == 1 {
            base
        } else {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[base, disp])?
        };
        let stride = const_u64(out, u64::from(self.width) / 8)?;
        let second_addr = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[access, stride])?;

        let ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        if self.load {
            let first = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), ty, &[access])?;
            let second = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), ty, &[second_addr])?;
            out.write_operand(0, first)?;
            out.write_operand(1, second)?;
        } else {
            let first = out.read_operand(0, ty)?;
            let second = out.read_operand(1, ty)?;
            out.side_effect(SideEffect::MemoryWrite, &[access, first])?;
            out.side_effect(SideEffect::MemoryWrite, &[second_addr, second])?;
        }

        if insn.operand(3).is_some() {
            let new_base = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[base, disp])?;
            out.write_register(base_parent, new_base)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// SIMD lane-wise arithmetic (third wave)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SimdLaneProvider {
    pub form: u32,
    pub rule: u64,
    pub op: angryier_semantics::PrimitiveOp,
    pub lanes: u16,
    pub lane_bits: u16,
}

impl angryier_semantics::SemanticProvider for SimdLaneProvider {
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
        let ty = SemanticType::Vector {
            lanes: self.lanes,
            lane: ScalarType::BitVec(self.lane_bits),
        };
        let left = out.read_operand(1, ty)?;
        let right = out.read_operand(2, ty)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise(self.op)), ty, &[left, right])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SimdLaneFloatProvider {
    pub form: u32,
    pub rule: u64,
    pub op: angryier_semantics::FloatingOp,
    pub lanes: u16,
    pub lane_bits: u16,
}

impl angryier_semantics::SemanticProvider for SimdLaneFloatProvider {
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
        let ty = SemanticType::Vector {
            lanes: self.lanes,
            lane: ScalarType::Float(if self.lane_bits == 32 {
                FloatFormat::F32
            } else {
                FloatFormat::F64
            }),
        };
        let left = out.read_operand(1, ty)?;
        let right = out.read_operand(2, ty)?;
        let result = out.emit(SemanticOp::Vector(VectorOp::LaneWiseFloat(self.op)), ty, &[left, right])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

fn take_rule_inc(next_rule: &mut u64) -> u64 {
    let rule = *next_rule;
    *next_rule += 1;
    rule
}
