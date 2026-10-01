#![forbid(unsafe_code)]

//! Advanced Performance Extensions (APX) semantic providers.
//!
//! Covers:
//! - JMPABS (64-bit direct absolute jump)
//! - PUSH2 / PUSH2P (push register pair onto stack)
//! - POP2 / POP2P (pop register pair from stack)
//! - CCMPcc (conditional compare with DFV flags) across 16 condition codes
//! - CTESTcc (conditional test with DFV flags) across 16 condition codes
//! - CFCMOVcc (conditional faulting conditional move)
//! - APX NDD (non-destructive 3-operand destination) integer ALU + shifts
//! - APX NF (no-flags) suppression support across all NDD operations

use angryier_arch_intel64::register_id;
use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder, SemanticContext, SemanticError,
    SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, SideEffect, ValueId,
};
use angryier_types::SemanticRuleId;
use std::sync::Arc;

use crate::providers::{
    ShiftKind, compose_rflags, const_u64, pf_flag, read_flag_not_set, read_flag_set, sub_flag_values, write_add_flags,
    write_logical_flags, write_shift_flags, write_sub_flags, zf_sf,
};
use crate::{forms, rflags};

pub const APX_RULE_BASE: u64 = 0x2A00;

pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(APX_RULE_BASE + offset)
}

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U8: SemanticType = SemanticType::Scalar(ScalarType::BitVec(8));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = out.constant(
        U64,
        &insn.address().wrapping_add(u64::from(insn.length())).to_le_bytes(),
    )?;
    out.jump(next_pc)?;
    Ok(())
}

fn receipt(rule_id: SemanticRuleId, context: &SemanticContext) -> SemanticReceipt {
    SemanticReceipt {
        rule_id,
        origin: SemanticOrigin::HandwrittenOverride,
        semantic_version: context.semantic_version,
    }
}

// ---------------------------------------------------------------------------
// 1. JMPABS
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub struct JmpabsImm64Provider;

impl SemanticProvider for JmpabsImm64Provider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x00)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::JMPABS_IMM64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        _insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        // Operand 0 of JMPABS is a FarPointer operand; `read_operand(0, U64)`
        // resolves it to the 64-bit target constant through the FarPointer
        // lowering arm in the lowerer. This provider depends on that arm:
        // without it the read cannot produce the absolute target.
        let target = out.read_operand(0, U64)?;
        out.jump(target)?;
        Ok(receipt(self.rule_id(), context))
    }
}

// ---------------------------------------------------------------------------
// 2. PUSH2 / PUSH2P
// ---------------------------------------------------------------------------

/// PUSH2/PUSH2P effect sequence (decoded operand 2 is the SUPPRESSED STACK
/// MEMORY operand — a register-pair push has no third architectural result,
/// so it must never be written):
///   new_rsp      = rsp - 16
///   [new_rsp+8]  = src1      (side_effect(MemoryWrite) with inputs
///                             [address, value] lowers to a real store)
///   [new_rsp+0]  = src2      (real store)
///   rsp          = new_rsp
fn emit_push2(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(0, U64)?;
    let src2 = out.read_operand(1, U64)?;
    let rsp_reg = RegisterId(register_id::GPR_BASE + 4);
    let rsp = out.read_register(rsp_reg, U64)?;
    let sixteen = const_u64(out, 16)?;
    let eight = const_u64(out, 8)?;
    let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[rsp, sixteen])?;
    let addr1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[new_rsp, eight])?;
    out.side_effect(SideEffect::MemoryWrite, &[addr1, src1])?;
    out.side_effect(SideEffect::MemoryWrite, &[new_rsp, src2])?;
    out.write_register(rsp_reg, new_rsp)?;
    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

#[derive(Clone, Copy, Debug)]
pub struct Push2R64R64Provider;

impl SemanticProvider for Push2R64R64Provider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x01)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH2_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        emit_push2(self.rule_id(), context, insn, out)
    }
}

/// PUSH2P is the EVEX operand-size-promoted (P suffix) encoding of PUSH2;
/// in 64-bit mode the promotion is a no-op, so both forms share emit_push2.
#[derive(Clone, Copy, Debug)]
pub struct Push2pR64R64Provider;

impl SemanticProvider for Push2pR64R64Provider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x02)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::PUSH2P_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        emit_push2(self.rule_id(), context, insn, out)
    }
}

// ---------------------------------------------------------------------------
// 3. POP2 / POP2P
// ---------------------------------------------------------------------------

/// POP2/POP2P effect sequence (operand_count() is always 3 for these forms;
/// there is no fallback path):
///   slot1   = load [rsp+0]  — decoded operand 2 is a suppressed READ memory
///                             operand at [rsp+0]; read_operand lowers it to a
///                             real load of the first stack slot
///   slot2   = load [rsp+8]  — materialized via PrimitiveOp::Load (real load)
///   dst0    = slot1
///   dst1    = slot2
///   rsp     = rsp + 16
fn emit_pop2(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
) -> Result<SemanticReceipt, SemanticError> {
    let rsp_reg = RegisterId(register_id::GPR_BASE + 4);
    let rsp = out.read_register(rsp_reg, U64)?;
    let eight = const_u64(out, 8)?;
    let sixteen = const_u64(out, 16)?;
    let slot1 = out.read_operand(2, U64)?;
    let addr2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, eight])?;
    let slot2 = out.emit(SemanticOp::Primitive(PrimitiveOp::Load), U64, &[addr2])?;
    out.write_operand(0, slot2)?;
    out.write_operand(1, slot1)?;
    let new_rsp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[rsp, sixteen])?;
    out.write_register(rsp_reg, new_rsp)?;
    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

#[derive(Clone, Copy, Debug)]
pub struct Pop2R64R64Provider;

impl SemanticProvider for Pop2R64R64Provider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x03)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POP2_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        emit_pop2(self.rule_id(), context, insn, out)
    }
}

/// POP2P is the EVEX operand-size-promoted (P suffix) encoding of POP2;
/// in 64-bit mode the promotion is a no-op, so both forms share emit_pop2.
#[derive(Clone, Copy, Debug)]
pub struct Pop2pR64R64Provider;

impl SemanticProvider for Pop2pR64R64Provider {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x04)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::POP2P_R64_R64
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        emit_pop2(self.rule_id(), context, insn, out)
    }
}

// ---------------------------------------------------------------------------
// 4. Condition Code Helpers for CCMPcc / CTESTcc / CFCMOVcc
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionCode {
    O,
    No,
    B,
    Nb,
    Z,
    Nz,
    Be,
    Nbe,
    S,
    Ns,
    T,
    F,
    L,
    Nl,
    Le,
    Nle,
}

fn eval_condition(out: &mut dyn SemanticBuilder, cc: ConditionCode) -> Result<ValueId, SemanticError> {
    match cc {
        ConditionCode::O => read_flag_set(out, rflags::OF_BIT),
        ConditionCode::No => read_flag_not_set(out, rflags::OF_BIT),
        ConditionCode::B => read_flag_set(out, rflags::CF_BIT),
        ConditionCode::Nb => read_flag_not_set(out, rflags::CF_BIT),
        ConditionCode::Z => read_flag_set(out, rflags::ZF_BIT),
        ConditionCode::Nz => read_flag_not_set(out, rflags::ZF_BIT),
        ConditionCode::Be => {
            let cf = read_flag_set(out, rflags::CF_BIT)?;
            let zf = read_flag_set(out, rflags::ZF_BIT)?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[cf, zf])
        }
        ConditionCode::Nbe => {
            let cf_clear = read_flag_not_set(out, rflags::CF_BIT)?;
            let zf_clear = read_flag_not_set(out, rflags::ZF_BIT)?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[cf_clear, zf_clear])
        }
        ConditionCode::S => read_flag_set(out, rflags::SF_BIT),
        ConditionCode::Ns => read_flag_not_set(out, rflags::SF_BIT),
        ConditionCode::T => out.constant(U1, &[1]),
        ConditionCode::F => out.constant(U1, &[0]),
        ConditionCode::L => {
            let sf = read_flag_set(out, rflags::SF_BIT)?;
            let of = read_flag_set(out, rflags::OF_BIT)?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])
        }
        ConditionCode::Nl => {
            let sf = read_flag_set(out, rflags::SF_BIT)?;
            let of = read_flag_set(out, rflags::OF_BIT)?;
            let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
            let one = out.constant(U1, &[1])?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[diff, one])
        }
        ConditionCode::Le => {
            let zf = read_flag_set(out, rflags::ZF_BIT)?;
            let sf = read_flag_set(out, rflags::SF_BIT)?;
            let of = read_flag_set(out, rflags::OF_BIT)?;
            let lt = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U1, &[zf, lt])
        }
        ConditionCode::Nle => {
            let zf_clear = read_flag_not_set(out, rflags::ZF_BIT)?;
            let sf = read_flag_set(out, rflags::SF_BIT)?;
            let of = read_flag_set(out, rflags::OF_BIT)?;
            let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[sf, of])?;
            let one = out.constant(U1, &[1])?;
            let ge = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U1, &[diff, one])?;
            out.emit(SemanticOp::Primitive(PrimitiveOp::And), U1, &[zf_clear, ge])
        }
    }
}

/// Expands the 4-bit DFV immediate into RFLAGS-positioned flag values.
/// DFV encoding: bit0=CF, bit1=ZF, bit2=SF, bit3=OF; PF and AF are
/// architecturally zero. Each extracted bit is shifted into its RFLAGS bit
/// position so the values compose correctly in `compose_rflags` (which ORs
/// them straight into RFLAGS): CF=bit0 (raw 0/1 already in position),
/// ZF -> bit 6, SF -> bit 7, OF -> bit 11.
/// Return order matches `sub_flag_values`: [zf, sf, pf, af, of, cf].
fn dfv_flags(out: &mut dyn SemanticBuilder, dfv_raw: ValueId) -> Result<[ValueId; 6], SemanticError> {
    let dfv = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[dfv_raw])?;
    let zero_64 = const_u64(out, 0)?;
    let one_64 = const_u64(out, 1)?;
    let two_64 = const_u64(out, 2)?;
    let three_64 = const_u64(out, 3)?;

    // DFV bit 0: CF (RFLAGS bit 0, so raw 0/1 is already positioned)
    let cf = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[dfv, one_64])?;
    // DFV bit 1: ZF -> RFLAGS bit 6
    let s1 = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[dfv, one_64],
    )?;
    let zf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[s1, one_64])?;
    let zf_bit = const_u64(out, u64::from(rflags::ZF_BIT))?;
    let zf = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[zf_raw, zf_bit])?;
    // DFV bit 2: SF -> RFLAGS bit 7
    let s2 = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[dfv, two_64],
    )?;
    let sf_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[s2, one_64])?;
    let sf_bit = const_u64(out, u64::from(rflags::SF_BIT))?;
    let sf = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[sf_raw, sf_bit])?;
    // DFV bit 3: OF -> RFLAGS bit 11
    let s3 = out.emit(
        SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
        U64,
        &[dfv, three_64],
    )?;
    let of_raw = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[s3, one_64])?;
    let of_bit = const_u64(out, u64::from(rflags::OF_BIT))?;
    let of = out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[of_raw, of_bit])?;
    let pf = zero_64;
    let af = zero_64;

    Ok([zf, sf, pf, af, of, cf])
}

fn select_flags(
    out: &mut dyn SemanticBuilder,
    cond: ValueId,
    calc: &[ValueId; 6],
    dfv: &[ValueId; 6],
) -> Result<[ValueId; 6], SemanticError> {
    let mut selected = [0u32; 6];
    for i in 0..6 {
        selected[i] = out.emit(
            SemanticOp::Primitive(PrimitiveOp::Select),
            U64,
            &[cond, calc[i], dfv[i]],
        )?;
    }
    Ok(selected)
}

// ---------------------------------------------------------------------------
// 5. CCMPcc Providers
// ---------------------------------------------------------------------------

fn emit_ccmp(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    cc: ConditionCode,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(0, U64)?;
    let src2 = out.read_operand(1, U64)?;
    let dfv_op = if insn.operand_count() > 2 {
        out.read_operand(2, U8)?
    } else {
        out.constant(U8, &[0])?
    };

    let cond = eval_condition(out, cc)?;
    let diff = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[src1, src2])?;
    let sub_flags = sub_flag_values(out, diff, src1, src2, 64)?;
    // sub_flag_values returns [zf, sf, pf, af, of, cf], each value already
    // shifted to its RFLAGS bit position (CF is raw 0/1, which IS bit 0).
    // The 1:1 copy preserves that order; compose_rflags only ORs values into
    // RFLAGS, so the array index order is cosmetic — what must (and does)
    // match is the per-element RFLAGS bit positioning of calc_flags and
    // dfv_flags above.
    let calc_flags: [ValueId; 6] = [
        sub_flags[0],
        sub_flags[1],
        sub_flags[2],
        sub_flags[3],
        sub_flags[4],
        sub_flags[5],
    ];

    let dfv = dfv_flags(out, dfv_op)?;
    let selected = select_flags(out, cond, &calc_flags, &dfv)?;
    compose_rflags(out, &selected, false)?;
    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

macro_rules! ccmp_provider {
    ($name:ident, $form:ident, $offset:expr, $cc:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($offset)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == forms::$form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                emit_ccmp(self.rule_id(), context, insn, out, ConditionCode::$cc)
            }
        }
    };
}

ccmp_provider!(CcmpoR64R64Provider, CCMPO_R64_R64, 0x05, O);
ccmp_provider!(CcmpnoR64R64Provider, CCMPNO_R64_R64, 0x06, No);
ccmp_provider!(CcmpbR64R64Provider, CCMPB_R64_R64, 0x07, B);
ccmp_provider!(CcmpnbR64R64Provider, CCMPNB_R64_R64, 0x08, Nb);
ccmp_provider!(CcmpzR64R64Provider, CCMPZ_R64_R64, 0x09, Z);
ccmp_provider!(CcmpnzR64R64Provider, CCMPNZ_R64_R64, 0x0A, Nz);
ccmp_provider!(CcmpbeR64R64Provider, CCMPBE_R64_R64, 0x0B, Be);
ccmp_provider!(CcmpnbeR64R64Provider, CCMPNBE_R64_R64, 0x0C, Nbe);
ccmp_provider!(CcmpsR64R64Provider, CCMPS_R64_R64, 0x0D, S);
ccmp_provider!(CcmpnsR64R64Provider, CCMPNS_R64_R64, 0x0E, Ns);
ccmp_provider!(CcmptR64R64Provider, CCMPT_R64_R64, 0x0F, T);
ccmp_provider!(CcmpfR64R64Provider, CCMPF_R64_R64, 0x10, F);
ccmp_provider!(CcmplR64R64Provider, CCMPL_R64_R64, 0x11, L);
ccmp_provider!(CcmpnlR64R64Provider, CCMPNL_R64_R64, 0x12, Nl);
ccmp_provider!(CcmpleR64R64Provider, CCMPLE_R64_R64, 0x13, Le);
ccmp_provider!(CcmpnleR64R64Provider, CCMPNLE_R64_R64, 0x14, Nle);

// ---------------------------------------------------------------------------
// 6. CTESTcc Providers
// ---------------------------------------------------------------------------

fn emit_ctest(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    cc: ConditionCode,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(0, U64)?;
    let src2 = out.read_operand(1, U64)?;
    let dfv_op = if insn.operand_count() > 2 {
        out.read_operand(2, U8)?
    } else {
        out.constant(U8, &[0])?
    };

    let cond = eval_condition(out, cc)?;
    let and_val = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[src1, src2])?;
    let (zf, sf) = zf_sf(out, and_val, 63)?;
    let pf = pf_flag(out, and_val)?;
    let zero = const_u64(out, 0)?;
    // TEST semantics: CF and OF are cleared unconditionally (AF zeroed per
    // corpus convention), so calc_flags zero those entries. Correct per ISA.
    let calc_flags: [ValueId; 6] = [zf, sf, pf, zero, zero, zero];

    let dfv = dfv_flags(out, dfv_op)?;
    let selected = select_flags(out, cond, &calc_flags, &dfv)?;
    compose_rflags(out, &selected, false)?;
    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

macro_rules! ctest_provider {
    ($name:ident, $form:ident, $offset:expr, $cc:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($offset)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == forms::$form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                emit_ctest(self.rule_id(), context, insn, out, ConditionCode::$cc)
            }
        }
    };
}

ctest_provider!(CtestoR64R64Provider, CTESTO_R64_R64, 0x15, O);
ctest_provider!(CtestnoR64R64Provider, CTESTNO_R64_R64, 0x16, No);
ctest_provider!(CtestbR64R64Provider, CTESTB_R64_R64, 0x17, B);
ctest_provider!(CtestnbR64R64Provider, CTESTNB_R64_R64, 0x18, Nb);
ctest_provider!(CtestzR64R64Provider, CTESTZ_R64_R64, 0x19, Z);
ctest_provider!(CtestnzR64R64Provider, CTESTNZ_R64_R64, 0x1A, Nz);
ctest_provider!(CtestbeR64R64Provider, CTESTBE_R64_R64, 0x1B, Be);
ctest_provider!(CtestnbeR64R64Provider, CTESTNBE_R64_R64, 0x1C, Nbe);
ctest_provider!(CtestsR64R64Provider, CTESTS_R64_R64, 0x1D, S);
ctest_provider!(CtestnsR64R64Provider, CTESTNS_R64_R64, 0x1E, Ns);
ctest_provider!(CtesttR64R64Provider, CTESTT_R64_R64, 0x1F, T);
ctest_provider!(CtestfR64R64Provider, CTESTF_R64_R64, 0x20, F);
ctest_provider!(CtestlR64R64Provider, CTESTL_R64_R64, 0x21, L);
ctest_provider!(CtestnlR64R64Provider, CTESTNL_R64_R64, 0x22, Nl);
ctest_provider!(CtestleR64R64Provider, CTESTLE_R64_R64, 0x23, Le);
ctest_provider!(CtestnleR64R64Provider, CTESTNLE_R64_R64, 0x24, Nle);

// ---------------------------------------------------------------------------
// 7. APX NDD (Non-Destructive Destination) Providers with NF
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NddOp {
    Add,
    Sub,
    And,
    Or,
    Xor,
}

fn emit_ndd_alu64(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    op: NddOp,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(1, U64)?;
    let src2 = out.read_operand(2, U64)?;

    let result = match op {
        NddOp::Add => out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[src1, src2])?,
        NddOp::Sub => out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[src1, src2])?,
        NddOp::And => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[src1, src2])?,
        NddOp::Or => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[src1, src2])?,
        NddOp::Xor => out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[src1, src2])?,
    };

    out.write_operand(0, result)?;

    if !insn.is_no_flags() {
        match op {
            NddOp::Add => write_add_flags(out, result, src1, src2, 64)?,
            NddOp::Sub => write_sub_flags(out, result, src1, src2, 64)?,
            NddOp::And | NddOp::Or | NddOp::Xor => write_logical_flags(out, result, 64)?,
        }
    }

    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

fn emit_ndd_alu32(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    op: NddOp,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(1, U32)?;
    let src2 = out.read_operand(2, U32)?;

    let result = match op {
        NddOp::Add => out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U32, &[src1, src2])?,
        NddOp::Sub => out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U32, &[src1, src2])?,
        NddOp::And => out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[src1, src2])?,
        NddOp::Or => out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U32, &[src1, src2])?,
        NddOp::Xor => out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U32, &[src1, src2])?,
    };

    // 32-bit ALU ops zero-extend the result into the full 64-bit destination
    // register; the explicit ZeroExtend keeps the promoted write explicit
    // (equivalent to the legacy r32 corpus providers, where write_operand
    // narrows the narrow-width result at the register write).
    let result64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[result])?;
    out.write_operand(0, result64)?;

    if !insn.is_no_flags() {
        match op {
            NddOp::Add => write_add_flags(out, result, src1, src2, 32)?,
            NddOp::Sub => write_sub_flags(out, result, src1, src2, 32)?,
            NddOp::And | NddOp::Or | NddOp::Xor => write_logical_flags(out, result, 32)?,
        }
    }

    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

macro_rules! ndd_alu_provider {
    ($name:ident, $form:ident, $offset:expr, $fn_emit:ident, $op:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($offset)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == forms::$form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                $fn_emit(self.rule_id(), context, insn, out, NddOp::$op)
            }
        }
    };
}

ndd_alu_provider!(AddR64R64R64NddProvider, ADD_R64_R64_R64_NDD, 0x25, emit_ndd_alu64, Add);
ndd_alu_provider!(SubR64R64R64NddProvider, SUB_R64_R64_R64_NDD, 0x26, emit_ndd_alu64, Sub);
ndd_alu_provider!(AndR64R64R64NddProvider, AND_R64_R64_R64_NDD, 0x27, emit_ndd_alu64, And);
ndd_alu_provider!(OrR64R64R64NddProvider, OR_R64_R64_R64_NDD, 0x28, emit_ndd_alu64, Or);
ndd_alu_provider!(XorR64R64R64NddProvider, XOR_R64_R64_R64_NDD, 0x29, emit_ndd_alu64, Xor);

ndd_alu_provider!(AddR32R32R32NddProvider, ADD_R32_R32_R32_NDD, 0x2A, emit_ndd_alu32, Add);
ndd_alu_provider!(SubR32R32R32NddProvider, SUB_R32_R32_R32_NDD, 0x2B, emit_ndd_alu32, Sub);
ndd_alu_provider!(AndR32R32R32NddProvider, AND_R32_R32_R32_NDD, 0x2C, emit_ndd_alu32, And);
ndd_alu_provider!(OrR32R32R32NddProvider, OR_R32_R32_R32_NDD, 0x2D, emit_ndd_alu32, Or);
ndd_alu_provider!(XorR32R32R32NddProvider, XOR_R32_R32_R32_NDD, 0x2E, emit_ndd_alu32, Xor);

// NDD shifts
fn emit_ndd_shift64(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    kind: ShiftKind,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(1, U64)?;
    let count8 = out.read_operand(2, U8)?;
    let count64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[count8])?;
    // 64-bit shifts mask the count to 6 bits (0x3F), per ISA.
    let mask = const_u64(out, 0x3F)?;
    let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count64, mask])?;

    let result = match kind {
        ShiftKind::Left => out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U64, &[src1, count])?,
        ShiftKind::RightLogical => out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U64,
            &[src1, count],
        )?,
        ShiftKind::RightArith => out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U64,
            &[src1, count],
        )?,
        _ => return Err(SemanticError::InvalidSemanticDefinition),
    };

    out.write_operand(0, result)?;

    if !insn.is_no_flags() {
        write_shift_flags(out, src1, count, result, kind, 64)?;
    }

    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

fn emit_ndd_shift32(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    kind: ShiftKind,
) -> Result<SemanticReceipt, SemanticError> {
    let src1 = out.read_operand(1, U32)?;
    let count8 = out.read_operand(2, U8)?;
    let count32 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U32, &[count8])?;
    // 32-bit shifts mask the count to 5 bits (0x1F), per ISA.
    let mask = out.constant(U32, &0x1Fu32.to_le_bytes())?;
    let count = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[count32, mask])?;

    let result = match kind {
        ShiftKind::Left => out.emit(SemanticOp::Primitive(PrimitiveOp::ShiftLeft), U32, &[src1, count])?,
        ShiftKind::RightLogical => out.emit(
            SemanticOp::Primitive(PrimitiveOp::LogicalShiftRight),
            U32,
            &[src1, count],
        )?,
        ShiftKind::RightArith => out.emit(
            SemanticOp::Primitive(PrimitiveOp::ArithmeticShiftRight),
            U32,
            &[src1, count],
        )?,
        _ => return Err(SemanticError::InvalidSemanticDefinition),
    };

    let result64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[result])?;
    out.write_operand(0, result64)?;

    if !insn.is_no_flags() {
        write_shift_flags(out, src1, count, result, kind, 32)?;
    }

    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

macro_rules! ndd_shift_provider {
    ($name:ident, $form:ident, $offset:expr, $fn_emit:ident, $kind:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($offset)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == forms::$form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                $fn_emit(self.rule_id(), context, insn, out, ShiftKind::$kind)
            }
        }
    };
}

ndd_shift_provider!(
    ShlR64R64Imm8NddProvider,
    SHL_R64_R64_IMM8_NDD,
    0x2F,
    emit_ndd_shift64,
    Left
);
ndd_shift_provider!(
    ShrR64R64Imm8NddProvider,
    SHR_R64_R64_IMM8_NDD,
    0x30,
    emit_ndd_shift64,
    RightLogical
);
ndd_shift_provider!(
    SarR64R64Imm8NddProvider,
    SAR_R64_R64_IMM8_NDD,
    0x31,
    emit_ndd_shift64,
    RightArith
);

ndd_shift_provider!(
    ShlR32R32Imm8NddProvider,
    SHL_R32_R32_IMM8_NDD,
    0x32,
    emit_ndd_shift32,
    Left
);
ndd_shift_provider!(
    ShrR32R32Imm8NddProvider,
    SHR_R32_R32_IMM8_NDD,
    0x33,
    emit_ndd_shift32,
    RightLogical
);
ndd_shift_provider!(
    SarR32R32Imm8NddProvider,
    SAR_R32_R32_IMM8_NDD,
    0x34,
    emit_ndd_shift32,
    RightArith
);

// ---------------------------------------------------------------------------
// 8. CFCMOVcc Providers
// ---------------------------------------------------------------------------

/// CFCMOVcc raises #UD when the condition is false on real hardware; the
/// fault is not modeled — this is a non-faulting approximation (plain
/// conditional Select between src and dst).
fn emit_cfcmov(
    rule_id: SemanticRuleId,
    context: &SemanticContext,
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    cc: ConditionCode,
) -> Result<SemanticReceipt, SemanticError> {
    let dst = out.read_operand(0, U64)?;
    let src = out.read_operand(1, U64)?;
    let cond = eval_condition(out, cc)?;
    let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Select), U64, &[cond, src, dst])?;
    out.write_operand(0, result)?;
    fall_through(out, insn)?;
    Ok(receipt(rule_id, context))
}

macro_rules! cfcmov_provider {
    ($name:ident, $form:ident, $offset:expr, $cc:ident) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($offset)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == forms::$form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                emit_cfcmov(self.rule_id(), context, insn, out, ConditionCode::$cc)
            }
        }
    };
}

cfcmov_provider!(CfcmovzR64R64Provider, CFCMOVZ_R64_R64, 0x35, Z);
cfcmov_provider!(CfcmovnzR64R64Provider, CFCMOVNZ_R64_R64, 0x36, Nz);
cfcmov_provider!(CfcmovbR64R64Provider, CFCMOVB_R64_R64, 0x37, B);
cfcmov_provider!(CfcmovnbR64R64Provider, CFCMOVNB_R64_R64, 0x38, Nb);
cfcmov_provider!(CfcmovlR64R64Provider, CFCMOVL_R64_R64, 0x39, L);
cfcmov_provider!(CfcmovnlR64R64Provider, CFCMOVNL_R64_R64, 0x3A, Nl);
cfcmov_provider!(CfcmovleR64R64Provider, CFCMOVLE_R64_R64, 0x3B, Le);
cfcmov_provider!(CfcmovnleR64R64Provider, CFCMOVNLE_R64_R64, 0x3C, Nle);

// ---------------------------------------------------------------------------
// Provider Registry
// ---------------------------------------------------------------------------

pub fn providers() -> Vec<Arc<dyn SemanticProvider>> {
    vec![
        // JMPABS
        Arc::new(JmpabsImm64Provider),
        // PUSH2 / POP2
        Arc::new(Push2R64R64Provider),
        Arc::new(Push2pR64R64Provider),
        Arc::new(Pop2R64R64Provider),
        Arc::new(Pop2pR64R64Provider),
        // CCMPcc (16 condition codes)
        Arc::new(CcmpoR64R64Provider),
        Arc::new(CcmpnoR64R64Provider),
        Arc::new(CcmpbR64R64Provider),
        Arc::new(CcmpnbR64R64Provider),
        Arc::new(CcmpzR64R64Provider),
        Arc::new(CcmpnzR64R64Provider),
        Arc::new(CcmpbeR64R64Provider),
        Arc::new(CcmpnbeR64R64Provider),
        Arc::new(CcmpsR64R64Provider),
        Arc::new(CcmpnsR64R64Provider),
        Arc::new(CcmptR64R64Provider),
        Arc::new(CcmpfR64R64Provider),
        Arc::new(CcmplR64R64Provider),
        Arc::new(CcmpnlR64R64Provider),
        Arc::new(CcmpleR64R64Provider),
        Arc::new(CcmpnleR64R64Provider),
        // CTESTcc (16 condition codes)
        Arc::new(CtestoR64R64Provider),
        Arc::new(CtestnoR64R64Provider),
        Arc::new(CtestbR64R64Provider),
        Arc::new(CtestnbR64R64Provider),
        Arc::new(CtestzR64R64Provider),
        Arc::new(CtestnzR64R64Provider),
        Arc::new(CtestbeR64R64Provider),
        Arc::new(CtestnbeR64R64Provider),
        Arc::new(CtestsR64R64Provider),
        Arc::new(CtestnsR64R64Provider),
        Arc::new(CtesttR64R64Provider),
        Arc::new(CtestfR64R64Provider),
        Arc::new(CtestlR64R64Provider),
        Arc::new(CtestnlR64R64Provider),
        Arc::new(CtestleR64R64Provider),
        Arc::new(CtestnleR64R64Provider),
        // APX NDD ALU (64-bit)
        Arc::new(AddR64R64R64NddProvider),
        Arc::new(SubR64R64R64NddProvider),
        Arc::new(AndR64R64R64NddProvider),
        Arc::new(OrR64R64R64NddProvider),
        Arc::new(XorR64R64R64NddProvider),
        // APX NDD ALU (32-bit)
        Arc::new(AddR32R32R32NddProvider),
        Arc::new(SubR32R32R32NddProvider),
        Arc::new(AndR32R32R32NddProvider),
        Arc::new(OrR32R32R32NddProvider),
        Arc::new(XorR32R32R32NddProvider),
        // APX NDD Shifts (64-bit and 32-bit)
        Arc::new(ShlR64R64Imm8NddProvider),
        Arc::new(ShrR64R64Imm8NddProvider),
        Arc::new(SarR64R64Imm8NddProvider),
        Arc::new(ShlR32R32Imm8NddProvider),
        Arc::new(ShrR32R32Imm8NddProvider),
        Arc::new(SarR32R32Imm8NddProvider),
        // CFCMOVcc (8 conditions)
        Arc::new(CfcmovzR64R64Provider),
        Arc::new(CfcmovnzR64R64Provider),
        Arc::new(CfcmovbR64R64Provider),
        Arc::new(CfcmovnbR64R64Provider),
        Arc::new(CfcmovlR64R64Provider),
        Arc::new(CfcmovnlR64R64Provider),
        Arc::new(CfcmovleR64R64Provider),
        Arc::new(CfcmovnleR64R64Provider),
    ]
}
