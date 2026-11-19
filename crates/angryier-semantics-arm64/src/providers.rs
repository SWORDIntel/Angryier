//! Handwritten A64 semantic providers for the phase-1 integer subset.
//!
//! NZCV model: a single 32-bit `NZCV` register (id 33) holding N/Z/C/V in
//! bits 31/30/29/28. `ADDS`/`SUBS`/`ANDS` compute and write the full NZCV
//! value; conditional branches read the relevant bits.

use angryier_arch_arm64::{forms, regs::register_id};
use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext, SemanticError, SemanticOp,
    SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, SideEffect, ValueId,
};
use angryier_types::SemanticRuleId;

use crate::rule_id;

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

pub(crate) fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

pub(crate) fn const_ty(out: &mut dyn SemanticBuilder, ty: SemanticType, value: u64) -> Result<ValueId, SemanticError> {
    let width = match ty {
        SemanticType::Scalar(ScalarType::BitVec(w)) => usize::from(w).div_ceil(8),
        _ => return Err(SemanticError::UnsupportedType(ty)),
    };
    out.constant(ty, &value.to_le_bytes()[..width])
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

fn read_nzcv(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    out.read_register(register_id::NZCV, U32)
}

fn write_nzcv(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<(), SemanticError> {
    out.write_register(register_id::NZCV, value)?;
    Ok(())
}

/// Extracts flag bit `n` (31=N, 30=Z, 29=C, 28=V) from a packed NZCV value
/// as a 1-bit value.
fn flag_bit(out: &mut dyn SemanticBuilder, nzcv: ValueId, bit: u64) -> Result<ValueId, SemanticError> {
    let amount = const_ty(out, U32, bit)?;
    let shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U32,
        &[nzcv, amount],
    )?;
    let one = const_ty(out, U32, 1)?;
    let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[shifted, one])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[masked, one])
}

fn pack_nzcv(
    out: &mut dyn SemanticBuilder,
    n: ValueId,
    z: ValueId,
    c: ValueId,
    v: ValueId,
) -> Result<ValueId, SemanticError> {
    // Widen each 1-bit flag to 32 bits, then shift into NZCV bit positions.
    let n32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[n])?;
    let z32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[z])?;
    let c32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[c])?;
    let v32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[v])?;
    let amt31 = const_ty(out, U32, 31)?;
    let amt30 = const_ty(out, U32, 30)?;
    let amt29 = const_ty(out, U32, 29)?;
    let amt28 = const_ty(out, U32, 28)?;
    let n_sh = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[n32, amt31])?;
    let z_sh = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[z32, amt30])?;
    let c_sh = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[c32, amt29])?;
    let v_sh = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[v32, amt28])?;
    let nz = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[n_sh, z_sh])?;
    let nzc = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[nz, c_sh])?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[nzc, v_sh])
}

/// Computes packed NZCV for an add: N/Z from result, C = carry-out, V = signed overflow.
fn nzcv_add(
    out: &mut dyn SemanticBuilder,
    width: u16,
    a: ValueId,
    b: ValueId,
    res: ValueId,
) -> Result<ValueId, SemanticError> {
    let ty = SemanticType::Scalar(ScalarType::BitVec(width));
    let zero = const_ty(out, ty, 0)?;
    let one = const_ty(out, ty, 1)?;
    let sign_amt = const_ty(out, ty, u64::from(width - 1))?;
    let n = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
        ty,
        &[res, sign_amt],
    )?;
    let n_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[n, one])?;
    let n_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[n_masked, one])?;
    let z_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[res, zero])?;
    let c_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[res, a])?;
    let axb = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, b])?;
    let not_axb = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), ty, &[axb])?;
    let axr = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, res])?;
    let v_full = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[not_axb, axr])?;
    let v_shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        ty,
        &[v_full, sign_amt],
    )?;
    let v_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[v_shifted, one])?;
    let v_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[v_masked, one])?;
    pack_nzcv(out, n_bit, z_bit, c_bit, v_bit)
}

/// Computes packed NZCV for a subtract: C = a >=_u b, V = (a ^ b) & (a ^ res) sign.
fn nzcv_sub(
    out: &mut dyn SemanticBuilder,
    width: u16,
    a: ValueId,
    b: ValueId,
    res: ValueId,
) -> Result<ValueId, SemanticError> {
    let ty = SemanticType::Scalar(ScalarType::BitVec(width));
    let zero = const_ty(out, ty, 0)?;
    let one = const_ty(out, ty, 1)?;
    let sign_amt = const_ty(out, ty, u64::from(width - 1))?;
    let n = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
        ty,
        &[res, sign_amt],
    )?;
    let n_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[n, one])?;
    let n_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[n_masked, one])?;
    let z_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[res, zero])?;
    let lt = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[a, b])?;
    let c_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[lt])?;
    let axb = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, b])?;
    let axr = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, res])?;
    let v_full = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[axb, axr])?;
    let v_shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        ty,
        &[v_full, sign_amt],
    )?;
    let v_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[v_shifted, one])?;
    let v_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[v_masked, one])?;
    pack_nzcv(out, n_bit, z_bit, c_bit, v_bit)
}

/// ANDS flags: N/Z from result, C/V cleared.
fn nzcv_logical(out: &mut dyn SemanticBuilder, width: u16, res: ValueId) -> Result<ValueId, SemanticError> {
    let ty = SemanticType::Scalar(ScalarType::BitVec(width));
    let zero = const_ty(out, ty, 0)?;
    let one = const_ty(out, ty, 1)?;
    let sign_amt = const_ty(out, ty, u64::from(width - 1))?;
    let n = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
        ty,
        &[res, sign_amt],
    )?;
    let n_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[n, one])?;
    let n_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[n_masked, one])?;
    let z_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[res, zero])?;
    let clear = const_ty(out, U1, 0)?;
    pack_nzcv(out, n_bit, z_bit, clear, clear)
}

/// Condition evaluation per ARM condition codes (0..=13). All composed
/// values are 1-bit.
pub(crate) fn condition_value(
    out: &mut dyn SemanticBuilder,
    cond: u8,
    nzcv: ValueId,
) -> Result<ValueId, SemanticError> {
    fn flag(o: &mut dyn SemanticBuilder, n: ValueId, bit: u64) -> Result<ValueId, SemanticError> {
        flag_bit(o, n, bit)
    }
    fn not(o: &mut dyn SemanticBuilder, v: ValueId) -> Result<ValueId, SemanticError> {
        o.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[v])
    }
    fn and(o: &mut dyn SemanticBuilder, a: ValueId, b: ValueId) -> Result<ValueId, SemanticError> {
        o.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[a, b])
    }
    fn or(o: &mut dyn SemanticBuilder, a: ValueId, b: ValueId) -> Result<ValueId, SemanticError> {
        o.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[a, b])
    }
    fn eq(o: &mut dyn SemanticBuilder, a: ValueId, b: ValueId) -> Result<ValueId, SemanticError> {
        o.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[a, b])
    }
    // Materialize each flag once, then compose.
    let n_f = flag(out, nzcv, 31)?;
    let z_f = flag(out, nzcv, 30)?;
    let c_f = flag(out, nzcv, 29)?;
    let v_f = flag(out, nzcv, 28)?;
    let not_z = not(out, z_f)?;
    let not_c = not(out, c_f)?;
    let not_n = not(out, n_f)?;
    let not_v = not(out, v_f)?;
    let n_eq_v = eq(out, n_f, v_f)?;
    let n_ne_v = not(out, n_eq_v)?;
    let c_and_not_z = and(out, c_f, not_z)?;
    let not_c_or_z = or(out, not_c, z_f)?;
    let not_z_and_n_eq_v = and(out, not_z, n_eq_v)?;
    let z_or_n_ne_v = or(out, z_f, n_ne_v)?;
    match cond {
        0b0000 => Ok(z_f),              // EQ: Z
        0b0001 => Ok(not_z),            // NE: !Z
        0b0010 => Ok(c_f),              // CS/HS: C
        0b0011 => Ok(not_c),            // CC/LO: !C
        0b0100 => Ok(n_f),              // MI: N
        0b0101 => Ok(not_n),            // PL: !N
        0b0110 => Ok(v_f),              // VS: V
        0b0111 => Ok(not_v),            // VC: !V
        0b1000 => Ok(c_and_not_z),      // HI: C && !Z
        0b1001 => Ok(not_c_or_z),       // LS: !C || Z
        0b1010 => Ok(n_eq_v),           // GE: N == V
        0b1011 => Ok(n_ne_v),           // LT: N != V
        0b1100 => Ok(not_z_and_n_eq_v), // GT: !Z && N==V
        0b1101 => Ok(z_or_n_ne_v),      // LE: Z || N!=V
        _ => Err(SemanticError::InvalidSemanticDefinition),
    }
}

/// Reads a decoded register operand at its operand width. The lowering
/// layer narrows register reads to the decoded view width, so the semantic
/// read must carry the operand-width type (a 64-bit read of a 32-bit W
/// operand would fail the operand-type check).
pub(crate) fn read_operand_typed(
    out: &mut dyn SemanticBuilder,
    insn: &dyn DecodedInstructionView,
    index: u8,
    ty: SemanticType,
) -> Result<ValueId, SemanticError> {
    let _ = insn;
    out.read_operand(index, ty)
}

// ---------------------------------------------------------------------------
// Branch providers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BranchImmProvider {
    pub form: u32,
    pub rule: u64,
    pub link: bool,
}

impl SemanticProvider for BranchImmProvider {
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
        let target = const_u64(out, insn.address().wrapping_add_signed(0))?;
        let _ = target;
        // The relative branch operand carries the displacement; the decoder
        // emits it as operand 0 of class RelativeBranch. The semantic target
        // is computed by the lowering layer from that operand; here we record
        // the control transfer plus the link write.
        let displacement = insn
            .operand(0)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::RelativeBranch(op) => op.displacement,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let target = const_u64(out, insn.address().wrapping_add(displacement as u64))?;
        if self.link {
            let next = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
            out.write_register(register_id::X30, next)?;
        }
        out.jump(target)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BCondProvider {
    pub cond: u8,
    pub rule: u64,
}

impl SemanticProvider for BCondProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(self.rule)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::B_COND_BASE + u32::from(self.cond)
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let nzcv = read_nzcv(out)?;
        let condition = condition_value(out, self.cond, nzcv)?;
        let displacement = insn
            .operand(0)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::RelativeBranch(op) => op.displacement,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let taken = const_u64(out, insn.address().wrapping_add(displacement as u64))?;
        let not_taken = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(condition, taken, not_taken)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CbzProvider {
    pub form: u32,
    pub rule: u64,
    pub nonzero: bool,
}

impl SemanticProvider for CbzProvider {
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
        let operand_width = insn.operand(0).map(|o| o.width_bits).unwrap_or(64);
        let ty = SemanticType::Scalar(ScalarType::BitVec(operand_width));
        let value = read_operand_typed(out, insn, 0, ty)?;
        let zero = const_ty(out, ty, 0)?;
        let is_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[value, zero])?;
        let condition = if self.nonzero {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[is_zero])?
        } else {
            is_zero
        };
        let displacement = insn
            .operand(1)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::RelativeBranch(op) => op.displacement,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let taken = const_u64(out, insn.address().wrapping_add(displacement as u64))?;
        let not_taken = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(condition, taken, not_taken)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TbzProvider {
    pub form: u32,
    pub rule: u64,
    pub nonzero: bool,
}

impl SemanticProvider for TbzProvider {
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
        let width = insn
            .operand(0)
            .map(|operand| operand.width_bits)
            .ok_or(SemanticError::InvalidOperand)?;
        let ty = SemanticType::Scalar(ScalarType::BitVec(width));
        let value = read_operand_typed(out, insn, 0, ty)?;
        let bit_index = insn
            .operand(1)
            .and_then(|operand| match operand.kind {
                angryier_semantics::OperandKind::Immediate(immediate) => Some(immediate.value),
                _ => None,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        if bit_index >= u64::from(width) {
            return Err(SemanticError::InvalidOperand);
        }
        let amount = const_ty(out, ty, bit_index)?;
        let shifted = out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            ty,
            &[value, amount],
        )?;
        let one = const_ty(out, ty, 1)?;
        let low = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[shifted, one])?;
        let zero = const_ty(out, ty, 0)?;
        let one = const_ty(out, ty, 1)?;
        let condition = if self.nonzero {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[low, one])?
        } else {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[low, zero])?
        };
        let displacement = insn
            .operand(2)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::RelativeBranch(op) => op.displacement,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let taken = const_u64(out, insn.address().wrapping_add(displacement as u64))?;
        let not_taken = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
        out.branch(condition, taken, not_taken)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IndirectBranchProvider {
    pub form: u32,
    pub rule: u64,
    pub link: bool,
}

impl SemanticProvider for IndirectBranchProvider {
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
        let target = out.read_operand(0, U64)?;
        if self.link {
            let next = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
            out.write_register(register_id::X30, next)?;
        }
        out.jump_indirect(target)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// PC-relative and wide-immediate providers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AdrProvider {
    pub form: u32,
    pub rule: u64,
    pub page: bool,
}

impl SemanticProvider for AdrProvider {
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
        let imm = insn
            .operand(1)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value as i64,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let base = if self.page {
            insn.address() & !0xFFF
        } else {
            insn.address()
        };
        let target = const_u64(out, base.wrapping_add(imm as u64))?;
        out.write_operand(0, target)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WideImmProvider {
    pub form: u32,
    pub rule: u64,
    /// 0 = MOVZ, 1 = MOVN, 2 = MOVK.
    pub kind: u8,
}

impl SemanticProvider for WideImmProvider {
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
        let imm16 = insn
            .operand(1)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let hw = insn
            .operand(2)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let width = insn.operand(0).map(|o| o.width_bits).unwrap_or(64);
        let ty = SemanticType::Scalar(ScalarType::BitVec(width));
        let imm = const_ty(out, ty, imm16)?;
        let amount = const_ty(out, ty, hw * 16)?;
        let shifted = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), ty, &[imm, amount])?;
        let value = match self.kind {
            0 => shifted,
            1 => out.emit(SemanticOp::Primitive(PrimitiveOp::Not), ty, &[shifted])?,
            _ => {
                let old = read_operand_typed(out, insn, 0, ty)?;
                let mask = const_ty(out, ty, 0xFFFF << (hw * 16))?;
                let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[old, mask])?;
                out.emit(SemanticOp::Primitive(PrimitiveOp::Or), ty, &[cleared, shifted])?
            }
        };
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// ALU providers (macro-generated for the add/sub/logical families)
// ---------------------------------------------------------------------------

/// Family descriptor: base form ids for the eight size/flag variants.
#[derive(Clone, Copy, Debug)]
pub struct AluFamily {
    pub forms_w_imm: [u32; 2], // [plain, with-flags]
    pub forms_x_imm: [u32; 2],
    pub forms_w_reg: [u32; 2],
    pub forms_x_reg: [u32; 2],
    pub op: PrimitiveOp,
}

pub fn alu_form(family: &AluFamily, imm: bool, width: u64, flags: bool) -> u32 {
    let idx = usize::from(flags);
    match (imm, width) {
        (true, 32) => family.forms_w_imm[idx],
        (true, _) => family.forms_x_imm[idx],
        (false, 32) => family.forms_w_reg[idx],
        (false, _) => family.forms_x_reg[idx],
    }
}

#[derive(Clone, Copy, Debug)]
pub struct AluProvider {
    pub form: u32,
    pub rule: u64,
    pub op: PrimitiveOp,
    pub flags: bool,
    /// ADD family: carry/overflow computed as addition (true); SUB family: subtraction.
    pub subtract: bool,
    pub imm: bool,
}

impl SemanticProvider for AluProvider {
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
        let left = read_operand_typed(out, insn, 1, ty)?;
        let right = if self.imm {
            read_operand_typed(out, insn, 2, ty)?
        } else {
            // shifted-register: operand 2 = Rm, operand 3 = shift amount, operand 4 = shift kind.
            let rm = read_operand_typed(out, insn, 2, ty)?;
            let amount = insn
                .operand(3)
                .map(|o| match o.kind {
                    angryier_semantics::OperandKind::Immediate(op) => op.value,
                    _ => 0,
                })
                .ok_or(SemanticError::InvalidOperand)?;
            let kind = insn
                .operand(4)
                .map(|o| match o.kind {
                    angryier_semantics::OperandKind::Immediate(op) => op.value,
                    _ => 0,
                })
                .ok_or(SemanticError::InvalidOperand)?;
            let shift_op = match kind {
                0 => PrimitiveOp::ShiftLeft,
                1 => PrimitiveOp::LogicalShiftRight,
                2 => PrimitiveOp::ArithmeticShiftRight,
                _ => PrimitiveOp::ShiftLeft,
            };
            let amount_value = const_ty(out, ty, amount)?;
            out.emit(SemanticOp::Primitive(shift_op), ty, &[rm, amount_value])?
        };
        let result = out.emit(SemanticOp::Primitive(self.op), ty, &[left, right])?;
        if self.flags {
            let nzcv = if self.subtract {
                nzcv_sub(out, width, left, right, result)?
            } else {
                nzcv_add(out, width, left, right, result)?
            };
            write_nzcv(out, nzcv)?;
        }
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Logical families (AND/ORR/EOR/ANDS, immediate and shifted-register)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct LogicalProvider {
    pub form: u32,
    pub rule: u64,
    pub op: PrimitiveOp,
    pub flags: bool,
    pub imm: bool,
}

impl SemanticProvider for LogicalProvider {
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
        let left = read_operand_typed(out, insn, 1, ty)?;
        let right = if self.imm {
            read_operand_typed(out, insn, 2, ty)?
        } else {
            let rm = read_operand_typed(out, insn, 2, ty)?;
            let amount = insn
                .operand(3)
                .map(|o| match o.kind {
                    angryier_semantics::OperandKind::Immediate(op) => op.value,
                    _ => 0,
                })
                .ok_or(SemanticError::InvalidOperand)?;
            let kind = insn
                .operand(4)
                .map(|o| match o.kind {
                    angryier_semantics::OperandKind::Immediate(op) => op.value,
                    _ => 0,
                })
                .ok_or(SemanticError::InvalidOperand)?;
            let shift_op = match kind {
                0 => PrimitiveOp::ShiftLeft,
                1 => PrimitiveOp::LogicalShiftRight,
                2 => PrimitiveOp::ArithmeticShiftRight,
                _ => PrimitiveOp::ShiftLeft,
            };
            let amount_value = const_ty(out, ty, amount)?;
            out.emit(SemanticOp::Primitive(shift_op), ty, &[rm, amount_value])?
        };
        let result = out.emit(SemanticOp::Primitive(self.op), ty, &[left, right])?;
        if self.flags {
            let nzcv = nzcv_logical(out, width, result)?;
            write_nzcv(out, nzcv)?;
        }
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Conditional select
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CselProvider {
    pub form: u32,
    pub rule: u64,
    /// 0 = CSEL, 1 = CSINC, 2 = CSINV, 3 = CSNEG.
    pub kind: u8,
}

impl SemanticProvider for CselProvider {
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
        let cond = insn
            .operand(3)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value as u8,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let nzcv = read_nzcv(out)?;
        let condition = condition_value(out, cond, nzcv)?;
        let rn = read_operand_typed(out, insn, 1, ty)?;
        let rm = read_operand_typed(out, insn, 2, ty)?;
        let one = const_ty(out, ty, 1)?;
        let incremented = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[rm, one])?;
        let inverted = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), ty, &[rm])?;
        let zero = const_ty(out, ty, 0)?;
        let negated = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), ty, &[zero, rm])?;
        let else_value = match self.kind {
            1 => incremented,
            2 => inverted,
            3 => negated,
            _ => rm,
        };
        let result = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Select),
            ty,
            &[condition, rn, else_value],
        )?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Multiply-accumulate
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MaddProvider {
    pub form: u32,
    pub rule: u64,
    pub subtract: bool,
}

impl SemanticProvider for MaddProvider {
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
        let rn = read_operand_typed(out, insn, 1, ty)?;
        let rm = read_operand_typed(out, insn, 2, ty)?;
        let ra = read_operand_typed(out, insn, 3, ty)?;
        let product = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), ty, &[rn, rm])?;
        let result = if self.subtract {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), ty, &[ra, product])?
        } else {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[ra, product])?
        };
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Bitfield move (UBFM/SBFM)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct BfmProvider {
    pub form: u32,
    pub rule: u64,
    pub signed: bool,
}

impl SemanticProvider for BfmProvider {
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
        let src = read_operand_typed(out, insn, 1, ty)?;
        let immr = insn
            .operand(2)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let imms = insn
            .operand(3)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let width_u = u64::from(width);
        if self.signed {
            // SBFM: Rd = SignExtend(Rn[imms:immr]) = ASR(Rn << (W-1-imms), immr + W-1-imms)
            let left_amount = const_ty(out, ty, width_u - 1 - imms)?;
            let left = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), ty, &[src, left_amount])?;
            let right_amount = const_ty(out, ty, immr + width_u - 1 - imms)?;
            let shifted = out.emit(
                SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
                ty,
                &[left, right_amount],
            )?;
            out.write_operand(0, shifted)?;
        } else if imms + 1 == width_u {
            // LSR alias.
            let shift_amount = const_ty(out, ty, immr)?;
            let shifted = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                ty,
                &[src, shift_amount],
            )?;
            out.write_operand(0, shifted)?;
        } else {
            // UBFM: Rd = (Rn >> immr) & ((1 << (imms+1)) - 1)
            let shift_amount = const_ty(out, ty, immr)?;
            let shifted = out.emit(
                SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
                ty,
                &[src, shift_amount],
            )?;
            let mask = (1u64 << (imms + 1)) - 1;
            let mask_value = const_ty(out, ty, mask)?;
            let masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[shifted, mask_value])?;
            out.write_operand(0, masked)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Loads and stores
// ---------------------------------------------------------------------------

/// Computes the effective address from the decoded memory operand:
/// base + index*scale + displacement.
fn effective_address(
    out: &mut dyn SemanticBuilder,
    insn: &dyn DecodedInstructionView,
    mem_index: u8,
) -> Result<ValueId, SemanticError> {
    let operand = insn.operand(mem_index).ok_or(SemanticError::InvalidOperand)?;
    let (base, index, scale, displacement) = match operand.kind {
        angryier_semantics::OperandKind::Memory(mem) => (mem.base, mem.index, u64::from(mem.scale), mem.displacement),
        _ => return Err(SemanticError::InvalidOperand),
    };
    let mut addr = match base {
        Some(angryier_semantics::MemoryBase::Register(view)) => out.read_register(view.parent, U64)?,
        _ => const_u64(out, 0)?,
    };
    let index_value = match index {
        Some(angryier_semantics::MemoryIndex::Register(view)) => Some(out.read_register(view.parent, U64)?),
        Some(angryier_semantics::MemoryIndex::ExtendedRegister { register, extension }) => {
            use angryier_semantics::MemoryIndexExtension;
            Some(match extension {
                MemoryIndexExtension::Uxtw => {
                    let value = out.read_register(register.parent, U32)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[value])?
                }
                MemoryIndexExtension::Sxtw => {
                    let value = out.read_register(register.parent, U32)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[value])?
                }
                MemoryIndexExtension::Uxtx | MemoryIndexExtension::Sxtx => out.read_register(register.parent, U64)?,
            })
        }
        Some(angryier_semantics::MemoryIndex::Vsib { .. }) => return Err(SemanticError::InvalidOperand),
        None => None,
    };
    if let Some(index_value) = index_value {
        let scaled = if scale > 1 {
            let scale_value = const_u64(out, scale)?;
            out.emit(
                SemanticOp::Primitive(PrimitiveOp::Mul),
                U64,
                &[index_value, scale_value],
            )?
        } else {
            index_value
        };
        addr = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[addr, scaled])?;
    }
    if displacement != 0 {
        let disp = const_u64(out, displacement as u64)?;
        let current = addr;
        addr = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[current, disp])?;
    }
    Ok(addr)
}

#[derive(Clone, Copy, Debug)]
pub struct LoadProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
    pub sign_extend: bool,
}

impl SemanticProvider for LoadProvider {
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
        let addr = effective_address(out, insn, 1)?;
        let load_ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        let loaded = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), load_ty, &[addr])?;
        let value = if self.sign_extend && self.width < 64 {
            out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[loaded])?
        } else {
            loaded
        };
        out.write_operand(0, value)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StoreProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
}

impl SemanticProvider for StoreProvider {
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
        let addr = effective_address(out, insn, 1)?;
        let store_ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        let data = read_operand_typed(out, insn, 0, store_ty)?;
        out.side_effect(SideEffect::MemoryWrite, &[addr, data])?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct LoadPairProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
}

impl SemanticProvider for LoadPairProvider {
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
        let addr = effective_address(out, insn, 2)?;
        let ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        let first = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), ty, &[addr])?;
        let stride = const_u64(out, u64::from(self.width) / 8)?;
        let first_addr = addr;
        let second_addr = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[first_addr, stride])?;
        let second = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), ty, &[second_addr])?;
        out.write_operand(0, first)?;
        out.write_operand(1, second)?;
        if insn.operand(3).is_some() {
            let operand = insn.operand(2).ok_or(SemanticError::InvalidOperand)?;
            if let angryier_semantics::OperandKind::Memory(mem) = operand.kind
                && let Some(angryier_semantics::MemoryBase::Register(view)) = mem.base
            {
                let old_base = out.read_register(view.parent, U64)?;
                let displacement = insn
                    .operand(4)
                    .and_then(|operand| match operand.kind {
                        angryier_semantics::OperandKind::Immediate(immediate) => Some(immediate.value),
                        _ => None,
                    })
                    .ok_or(SemanticError::InvalidOperand)?;
                let disp = const_u64(out, displacement)?;
                let new_base = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[old_base, disp])?;
                out.write_register(view.parent, new_base)?;
            }
        }
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StorePairProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
}

impl SemanticProvider for StorePairProvider {
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
        let addr = effective_address(out, insn, 2)?;
        let ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        let first = read_operand_typed(out, insn, 0, ty)?;
        let second = read_operand_typed(out, insn, 1, ty)?;
        let stride = const_u64(out, u64::from(self.width) / 8)?;
        let first_addr = addr;
        let second_addr = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[first_addr, stride])?;
        out.side_effect(SideEffect::MemoryWrite, &[first_addr, first])?;
        out.side_effect(SideEffect::MemoryWrite, &[second_addr, second])?;
        if insn.operand(3).is_some() {
            let operand = insn.operand(2).ok_or(SemanticError::InvalidOperand)?;
            if let angryier_semantics::OperandKind::Memory(mem) = operand.kind
                && let Some(angryier_semantics::MemoryBase::Register(view)) = mem.base
            {
                let old_base = out.read_register(view.parent, U64)?;
                let displacement = insn
                    .operand(4)
                    .and_then(|operand| match operand.kind {
                        angryier_semantics::OperandKind::Immediate(immediate) => Some(immediate.value),
                        _ => None,
                    })
                    .ok_or(SemanticError::InvalidOperand)?;
                let disp = const_u64(out, displacement)?;
                let new_base = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[old_base, disp])?;
                out.write_register(view.parent, new_base)?;
            }
        }
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// NOP/HINT/SVC
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct NoopProvider {
    pub form: u32,
    pub rule: u64,
}

impl SemanticProvider for NoopProvider {
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
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SvcProvider;

impl SemanticProvider for SvcProvider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x102)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::SVC
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let imm = insn
            .operand(0)
            .map(|o| match o.kind {
                angryier_semantics::OperandKind::Immediate(op) => op.value,
                _ => 0,
            })
            .ok_or(SemanticError::InvalidOperand)?;
        let imm_value = const_u64(out, imm)?;
        out.side_effect(SideEffect::RaiseException(imm as u32), &[imm_value])?;
        Ok(receipt(0x102, context))
    }
}

// ---------------------------------------------------------------------------
// Add/subtract with carry (ADC/ADCS/SBC/SBCS)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct AdcProvider {
    pub form: u32,
    pub rule: u64,
    pub subtract: bool,
    pub flags: bool,
}

impl SemanticProvider for AdcProvider {
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
        let a = read_operand_typed(out, insn, 1, ty)?;
        let b = read_operand_typed(out, insn, 2, ty)?;
        let nzcv = read_nzcv(out)?;
        let carry = flag_bit(out, nzcv, 29)?; // C flag, 1-bit
        let carry_wide = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), ty, &[carry])?;
        let one = const_ty(out, ty, 1)?;
        let (stage, result) = if self.subtract {
            // SBC: a - b - 1 + C
            let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), ty, &[a, b])?;
            let minus_one = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), ty, &[diff, one])?;
            let res = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[minus_one, carry_wide])?;
            (diff, res)
        } else {
            // ADC: a + b + C
            let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[a, b])?;
            let res = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[sum, carry_wide])?;
            (sum, res)
        };
        if self.flags {
            let packed = if self.subtract {
                nzcv_sbc(out, width, a, b, carry, stage, result)?
            } else {
                nzcv_adc(out, width, a, b, carry, stage, result)?
            };
            write_nzcv(out, packed)?;
        }
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

/// NZCV for add-with-carry: N/Z from the result; C = carry out of either
/// stage; V = overflow of either stage.
fn nzcv_adc(
    out: &mut dyn SemanticBuilder,
    width: u16,
    a: ValueId,
    _b: ValueId,
    carry: ValueId,
    stage: ValueId,
    res: ValueId,
) -> Result<ValueId, SemanticError> {
    let ty = SemanticType::Scalar(ScalarType::BitVec(width));
    let one = const_ty(out, ty, 1)?;
    let max = const_ty(out, ty, u64::MAX >> (64 - u64::from(width)))?;
    let sign_amt = const_ty(out, ty, u64::from(width - 1))?;
    let n = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
        ty,
        &[res, sign_amt],
    )?;
    let n_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[n, one])?;
    let n_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[n_masked, one])?;
    let zero_val = const_ty(out, ty, 0)?;
    let z_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[res, zero_val])?;
    let stage_overflow = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[stage, a])?;
    let stage_max = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[stage, max])?;
    let carry_and_max = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[carry, stage_max])?;
    let c_bit = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Or),
        U1,
        &[stage_overflow, carry_and_max],
    )?;
    // V: overflow of (a+b) and of (stage+C) both use the sign rule on the
    // add operands; combine the two stages.
    let axb = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, stage])?;
    let axr = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, res])?;
    let v_full = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[axb, axr])?;
    let v_shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        ty,
        &[v_full, sign_amt],
    )?;
    let v_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[v_shifted, one])?;
    let v_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[v_masked, one])?;
    pack_nzcv(out, n_bit, z_bit, c_bit, v_bit)
}

/// NZCV for subtract-with-carry: N/Z from the result; C = no borrow from
/// either stage; V = overflow of either stage.
fn nzcv_sbc(
    out: &mut dyn SemanticBuilder,
    width: u16,
    a: ValueId,
    b: ValueId,
    carry: ValueId,
    _stage: ValueId,
    res: ValueId,
) -> Result<ValueId, SemanticError> {
    let ty = SemanticType::Scalar(ScalarType::BitVec(width));
    let one = const_ty(out, ty, 1)?;
    let zero = const_ty(out, ty, 0)?;
    let sign_amt = const_ty(out, ty, u64::from(width - 1))?;
    let n = out.emit(
        SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
        ty,
        &[res, sign_amt],
    )?;
    let n_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[n, one])?;
    let n_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[n_masked, one])?;
    let z_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[res, zero])?;
    // C = (a >=_u b) AND NOT(a == b AND C_in == 0)
    let lt = out.emit(SemanticOp::Primitive(PrimitiveOp::Ult), U1, &[a, b])?;
    let no_borrow = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[lt])?;
    let eq = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[a, b])?;
    let carry_zero = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[carry])?;
    let borrow_in = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[eq, carry_zero])?;
    let not_borrow_in = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U1, &[borrow_in])?;
    let c_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[no_borrow, not_borrow_in])?;
    // V = (a ^ b) & (a ^ res) sign bit (two-stage, reuse the full-diff rule).
    let axb = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, b])?;
    let axr = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), ty, &[a, res])?;
    let v_full = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[axb, axr])?;
    let v_shifted = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        ty,
        &[v_full, sign_amt],
    )?;
    let v_masked = out.emit(SemanticOp::Primitive(PrimitiveOp::And), ty, &[v_shifted, one])?;
    let v_bit = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[v_masked, one])?;
    pack_nzcv(out, n_bit, z_bit, c_bit, v_bit)
}

// ---------------------------------------------------------------------------
// Conditional compare (CCMN/CCMP) — phase 1: unconditional flag computation;
// the conditional-Z rule is documented debt.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct CcProvider {
    pub form: u32,
    pub rule: u64,
    pub add: bool,
}

impl SemanticProvider for CcProvider {
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
        let a = read_operand_typed(out, insn, 0, ty)?;
        let b = read_operand_typed(out, insn, 1, ty)?;
        let packed = if self.add {
            let sum = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[a, b])?;
            nzcv_add(out, width, a, b, sum)?
        } else {
            let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), ty, &[a, b])?;
            nzcv_sub(out, width, a, b, diff)?
        };
        write_nzcv(out, packed)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Divide (UDIV/SDIV)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct DivProvider {
    pub form: u32,
    pub rule: u64,
    pub signed: bool,
}

impl SemanticProvider for DivProvider {
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
        let a = read_operand_typed(out, insn, 1, ty)?;
        let b = read_operand_typed(out, insn, 2, ty)?;
        let op = if self.signed {
            PrimitiveOp::SignedDiv
        } else {
            PrimitiveOp::UnsignedDiv
        };
        let result = out.emit(SemanticOp::Primitive(op), ty, &[a, b])?;
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Multiply-long (UMULL/SMULL/UMADDL/UMSUBL/SMADDL/SMSUBL)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct MulLongProvider {
    pub form: u32,
    pub rule: u64,
    pub signed: bool,
    /// None = plain long multiply; Some(true) = add, Some(false) = subtract.
    pub accumulate: Option<bool>,
}

impl SemanticProvider for MulLongProvider {
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
        let w_ty = SemanticType::Scalar(ScalarType::BitVec(32));
        let rn = read_operand_typed(out, insn, 1, w_ty)?;
        let rm = read_operand_typed(out, insn, 2, w_ty)?;
        let widen = if self.signed {
            PrimitiveOp::SignExtend
        } else {
            PrimitiveOp::ZeroExtend
        };
        let rn_wide = out.emit(SemanticOp::Primitive(widen), U64, &[rn])?;
        let rm_wide = out.emit(SemanticOp::Primitive(widen), U64, &[rm])?;
        let product = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[rn_wide, rm_wide])?;
        let result = match self.accumulate {
            Some(true) => {
                let ra = read_operand_typed(out, insn, 3, U64)?;
                out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[ra, product])?
            }
            Some(false) => {
                let ra = read_operand_typed(out, insn, 3, U64)?;
                out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[ra, product])?
            }
            None => product,
        };
        out.write_operand(0, result)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Indexed single loads/stores (post/pre-index with write-back)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct IndexedLoadStoreProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
    pub load: bool,
    pub pre_index: bool,
}

impl SemanticProvider for IndexedLoadStoreProvider {
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
        let operand = insn.operand(1).ok_or(SemanticError::InvalidOperand)?;
        let (base_view_id, displacement) = match operand.kind {
            angryier_semantics::OperandKind::Memory(mem) => match mem.base {
                Some(angryier_semantics::MemoryBase::Register(view)) => (view.parent, mem.displacement),
                _ => return Err(SemanticError::InvalidOperand),
            },
            _ => return Err(SemanticError::InvalidOperand),
        };
        let base = out.read_register(base_view_id, U64)?;
        let disp = const_u64(out, displacement as u64)?;
        let effective = if self.pre_index {
            out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[base, disp])?
        } else {
            base
        };
        let ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        if self.load {
            let loaded = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), ty, &[effective])?;
            out.write_operand(0, loaded)?;
        } else {
            let data = read_operand_typed(out, insn, 0, ty)?;
            out.side_effect(SideEffect::MemoryWrite, &[effective, data])?;
        }
        let new_base = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[base, disp])?;
        out.write_register(base_view_id, new_base)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}

// ---------------------------------------------------------------------------
// Sign-extending unscaled loads (LDURSB/LDURSH/LDURSW)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct SignExtUnscaledLoadProvider {
    pub form: u32,
    pub rule: u64,
    pub width: u16,
}

impl SemanticProvider for SignExtUnscaledLoadProvider {
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
        let addr = effective_address(out, insn, 1)?;
        let load_ty = SemanticType::Scalar(ScalarType::BitVec(self.width));
        let loaded = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), load_ty, &[addr])?;
        let extended = out.emit(SemanticOp::Primitive(PrimitiveOp::SignExtend), U64, &[loaded])?;
        out.write_operand(0, extended)?;
        fall_through(out, insn)?;
        Ok(receipt(self.rule, context))
    }
}
