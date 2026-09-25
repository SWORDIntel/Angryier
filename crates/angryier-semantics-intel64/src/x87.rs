#![forbid(unsafe_code)]

//! x87 FPU semantic family (first slice).
//!
//! State model: the eight x87 stack registers exist as 80-bit parents
//! (`X87_BASE..X87_BASE+7`) in the Intel 64 register file, and each slot holds
//! a 64-bit float payload in its low bits plus a 16-bit tag in its high bits:
//! `0x0000` marks a valid payload and `0xFFFF` marks an empty slot. The tag
//! word is therefore modeled inside the data plane — no extra architectural
//! state is required. The FPU status word (TOP and exception flags) has no
//! register in the file, so the stack pointer is modeled *logically*: pushes
//! and pops rotate the register contents, keeping logical ST(i) in physical
//! register i. This is observationally equivalent to hardware TOP renaming for
//! every instruction in this slice.
//!
//! Empty-slot reads produce the x87 QNaN real indefinite
//! (`0xFFF8_0000_0000_0000`), matching hardware with masked exceptions (the
//! masked state `fninit` establishes). Pushing onto a full stack likewise
//! loads the indefinite, matching masked hardware stack-overflow behavior.
//! `FSTSW`/`FSTCW` and FPU state dumps read the status word and are not
//! modeled here.
//!
//! Arithmetic runs on the f64 payload, following the SSE scalar-float
//! precedent: the concrete interpreter has no f80 arithmetic, and every
//! modeled operand crosses the f64 boundary exactly (memory forms are f32/f64,
//! and results are stored back through the same rounding the CPU applies).

use crate::{forms, rflags, rule_id};
use angryier_arch_intel64::X87_COUNT;
use angryier_arch_intel64::register_id;
use angryier_arch_intel64::register_id::X87_BASE;
use angryier_semantics::{
    DecodedInstructionView, FloatFormat, FloatingOp, PrimitiveOp, RegisterId, ScalarType, SemanticBuilder,
    SemanticContext, SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType,
    ValueId,
};
use angryier_types::SemanticRuleId;

const U80: SemanticType = SemanticType::Scalar(ScalarType::BitVec(80));
const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));
const U16: SemanticType = SemanticType::Scalar(ScalarType::BitVec(16));
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));
const F32: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F32));
const F64: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F64));

/// x87 m64 real indefinite: stored by masked FST/FSTP on an empty source.
const INDEFINITE_F64: u64 = 0xFFF8_0000_0000_0000;
/// High 16 bits of an 80-bit stack slot carrying the empty tag.
const EMPTY_TAG: u16 = 0xFFFF;

fn const_u16(out: &mut dyn SemanticBuilder, value: u16) -> Result<ValueId, SemanticError> {
    out.constant(U16, &value.to_le_bytes())
}

fn const_u64(out: &mut dyn SemanticBuilder, value: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &value.to_le_bytes())
}

fn const_f64(out: &mut dyn SemanticBuilder, bits: u64) -> Result<ValueId, SemanticError> {
    out.constant(F64, &bits.to_le_bytes())
}

fn st_reg(index: u32) -> RegisterId {
    RegisterId(X87_BASE + index)
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

/// Reads the raw 80-bit content of stack slot `index`.
fn read_st(out: &mut dyn SemanticBuilder, index: u32) -> Result<ValueId, SemanticError> {
    out.read_register(st_reg(index), U80)
}

/// Writes the raw 80-bit content of stack slot `index`.
fn write_st(out: &mut dyn SemanticBuilder, index: u32, value: ValueId) -> Result<(), SemanticError> {
    out.write_register(st_reg(index), value)?;
    Ok(())
}

/// Unpacks a stack slot into an f64 payload; an empty tag yields the x87
/// real indefinite (masked hardware behavior for empty-slot reads).
fn unpack_st(out: &mut dyn SemanticBuilder, raw: ValueId) -> Result<ValueId, SemanticError> {
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

/// Packs an f64 payload into the 80-bit stack-slot representation.
fn pack_st(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<ValueId, SemanticError> {
    let zero_tag = const_u16(out, 0)?;
    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), U80, &[value, zero_tag])
}

/// The 80-bit empty-slot constant.
fn empty_slot(out: &mut dyn SemanticBuilder) -> Result<ValueId, SemanticError> {
    let mut bytes = [0u8; 10];
    bytes[8..].copy_from_slice(&EMPTY_TAG.to_le_bytes());
    out.constant(U80, &bytes)
}

/// Pushes `value` (an f64) onto the logical stack: slots rotate up and the
/// new payload lands in ST(0). Pushing onto a full stack (ST(7) valid) loads
/// the indefinite instead of the value, matching masked hardware overflow.
fn push_st(out: &mut dyn SemanticBuilder, value: ValueId) -> Result<(), SemanticError> {
    let bottom = read_st(out, u32::from(X87_COUNT) - 1)?;
    let sixty_four = const_u64(out, 64)?;
    let bottom_tag = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U16, &[bottom, sixty_four])?;
    // The bottom slot carries the empty tag exactly when the stack has room.
    let empty_tag = const_u16(out, EMPTY_TAG)?;
    let has_room = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[bottom_tag, empty_tag])?;
    let indefinite = const_f64(out, INDEFINITE_F64)?;
    let pushed = out.emit(
        SemanticOp::Primitive(PrimitiveOp::Select),
        F64,
        &[has_room, value, indefinite],
    )?;

    let mut sources = Vec::with_capacity(7);
    for index in 0..(X87_COUNT - 1) {
        sources.push(read_st(out, u32::from(index))?);
    }
    let packed = pack_st(out, pushed)?;
    for index in 0..(X87_COUNT - 1) {
        write_st(out, u32::from(index + 1), sources[usize::from(index)])?;
    }
    write_st(out, 0, packed)?;
    Ok(())
}

/// Pops the logical stack: slots rotate down and the bottom slot becomes
/// empty. The FSTP st(i) destination write is the caller's responsibility
/// (the stored value lands in slot i-1 of the post-pop stack).
fn pop_st(out: &mut dyn SemanticBuilder) -> Result<(), SemanticError> {
    let mut sources = Vec::with_capacity(7);
    for index in 1..X87_COUNT {
        sources.push(read_st(out, u32::from(index))?);
    }
    let empty = empty_slot(out)?;
    for index in 0..(X87_COUNT - 1) {
        write_st(out, u32::from(index), sources[usize::from(index)])?;
    }
    write_st(out, u32::from(X87_COUNT) - 1, empty)?;
    Ok(())
}

/// Index of the x87 register named by the operand (parent id minus X87_BASE).
fn operand_st_index(insn: &dyn DecodedInstructionView, index: u8) -> Result<u32, SemanticError> {
    match insn.operand(index).map(|operand| operand.kind) {
        Some(angryier_arch::OperandKind::Register(view)) if view.parent.0 >= X87_BASE => Ok(view.parent.0 - X87_BASE),
        _ => Err(SemanticError::InvalidOperand),
    }
}

/// Merges a packed ZF/CF/PF flag word into RFLAGS (bits at RFLAGS positions).
fn write_zf_cf_pf_packed(out: &mut dyn SemanticBuilder, packed: ValueId) -> Result<(), SemanticError> {
    let old_rflags = out.read_register(register_id::RFLAGS, U64)?;
    let clear_mask = !((1u64 << rflags::ZF_BIT) | (1u64 << rflags::CF_BIT) | (1u64 << rflags::PF_BIT));
    let mask = out.constant(U64, &clear_mask.to_le_bytes())?;
    let cleared = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[old_rflags, mask])?;
    let new_rflags = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[cleared, packed])?;
    out.write_register(register_id::RFLAGS, new_rflags)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// FINIT
// ---------------------------------------------------------------------------

/// FNINIT: marks every stack slot empty. The tag-in-data-plane analog of the
/// hardware tag-word reset; exceptions are masked (the masked-state model).
#[derive(Clone, Copy, Debug)]
pub struct Finit;

impl SemanticProvider for Finit {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x30B)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FINIT
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let empty = empty_slot(out)?;
        for index in 0..X87_COUNT {
            write_st(out, u32::from(index), empty)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(0x30B, context))
    }
}

// ---------------------------------------------------------------------------
// FLD: push from memory, st(i), or a constant
// ---------------------------------------------------------------------------

macro_rules! x87_load {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $convert:expr) => {
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
                let value = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[source])?
                } else {
                    source
                };
                push_st(out, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_load!(FldM32, forms::FLD_M32, 0x30C, F32, true);
x87_load!(FldM64, forms::FLD_M64, 0x30D, F64, false);

/// FLD st(i): pushes a copy of stack slot i (an empty source pushes the
/// indefinite, matching masked hardware).
#[derive(Clone, Copy, Debug)]
pub struct FldSti;

impl SemanticProvider for FldSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x30E)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FLD_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let source = out.read_operand(1, U80)?;
        let value = unpack_st(out, source)?;
        push_st(out, value)?;
        fall_through(out, insn)?;
        Ok(receipt(0x30E, context))
    }
}

macro_rules! x87_load_const {
    ($name:ident, $form:expr, $rule:expr, $bits:expr) => {
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
                let value = const_f64(out, $bits)?;
                push_st(out, value)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_load_const!(Fld1, forms::FLD1, 0x30F, 0x3FF0_0000_0000_0000);
x87_load_const!(Fldz, forms::FLDZ, 0x310, 0x0000_0000_0000_0000);

// ---------------------------------------------------------------------------
// FST/FSTP: store ST(0) to memory or st(i), with or without a pop
// ---------------------------------------------------------------------------

/// FSTP st(i): stores ST(0) into the destination slot (relative to the
/// pre-pop stack), then pops.
#[derive(Clone, Copy, Debug)]
pub struct FstpSti;

impl SemanticProvider for FstpSti {
    fn rule_id(&self) -> SemanticRuleId {
        rule_id(0x311)
    }
    fn origin(&self) -> SemanticOrigin {
        SemanticOrigin::HandwrittenOverride
    }
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
        insn.form_id() == forms::FSTP_STI
    }
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError> {
        let top = read_st(out, 0)?;
        let stored = unpack_st(out, top)?;
        let destination = operand_st_index(insn, 0)?;
        pop_st(out)?;
        if destination >= 1 {
            let packed = pack_st(out, stored)?;
            write_st(out, destination - 1, packed)?;
        }
        fall_through(out, insn)?;
        Ok(receipt(0x311, context))
    }
}

macro_rules! x87_store {
    ($name:ident, $form:expr, $rule:expr, $dst_ty:expr, $convert:expr, $pop:expr) => {
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
                let top = read_st(out, 0)?;
                let stored = unpack_st(out, top)?;
                let value = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F32, &[stored])?
                } else {
                    stored
                };
                out.write_operand(0, value)?;
                if $pop {
                    pop_st(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_store!(FstM32, forms::FST_M32, 0x312, F32, true, false);
x87_store!(FstM64, forms::FST_M64, 0x313, F64, false, false);
x87_store!(FstpM32, forms::FSTP_M32, 0x314, F32, true, true);
x87_store!(FstpM64, forms::FSTP_M64, 0x315, F64, false, true);

// ---------------------------------------------------------------------------
// Arithmetic: two-stack-register and memory forms
// ---------------------------------------------------------------------------

/// Emits `left op right` (or `right op left` for the reversed R forms) as f64.
fn float_op(
    out: &mut dyn SemanticBuilder,
    op: FloatingOp,
    reversed: bool,
    left: ValueId,
    right: ValueId,
) -> Result<ValueId, SemanticError> {
    let (a, b) = if reversed { (right, left) } else { (left, right) };
    out.emit(SemanticOp::Float(op), F64, &[a, b])
}

/// Two-register arithmetic. Operand 0 is the read-write destination (st(0)
/// for the D8 encodings, st(i) for the DC encodings); operand 1 is the source.
macro_rules! x87_arith_st {
    ($name:ident, $form:expr, $rule:expr, $op:expr, $reversed:expr) => {
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
                let dst = out.read_operand(0, U80)?;
                let src = out.read_operand(1, U80)?;
                let dst_value = unpack_st(out, dst)?;
                let src_value = unpack_st(out, src)?;
                let result = float_op(out, $op, $reversed, dst_value, src_value)?;
                let packed = pack_st(out, result)?;
                out.write_operand(0, packed)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

/// Memory arithmetic: ST(0) combined with a memory operand.
macro_rules! x87_arith_mem {
    ($name:ident, $form:expr, $rule:expr, $src_ty:expr, $convert:expr, $op:expr, $reversed:expr) => {
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
                let dst = out.read_operand(0, U80)?;
                let source = out.read_operand(1, $src_ty)?;
                let src = if $convert {
                    out.emit(SemanticOp::Float(FloatingOp::Convert), F64, &[source])?
                } else {
                    source
                };
                let dst_value = unpack_st(out, dst)?;
                let result = float_op(out, $op, $reversed, dst_value, src)?;
                let packed = pack_st(out, result)?;
                out.write_operand(0, packed)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_arith_st!(FaddSt0Sti, forms::FADD_ST0_STI, 0x316, FloatingOp::Add, false);
x87_arith_st!(FaddStiSt0, forms::FADD_STI_ST0, 0x317, FloatingOp::Add, false);
x87_arith_mem!(FaddM32, forms::FADD_M32, 0x318, F32, true, FloatingOp::Add, false);
x87_arith_mem!(FaddM64, forms::FADD_M64, 0x319, F64, false, FloatingOp::Add, false);

x87_arith_st!(FsubSt0Sti, forms::FSUB_ST0_STI, 0x31A, FloatingOp::Sub, false);
x87_arith_st!(FsubStiSt0, forms::FSUB_STI_ST0, 0x31B, FloatingOp::Sub, false);
x87_arith_mem!(FsubM32, forms::FSUB_M32, 0x31C, F32, true, FloatingOp::Sub, false);
x87_arith_mem!(FsubM64, forms::FSUB_M64, 0x31D, F64, false, FloatingOp::Sub, false);
x87_arith_st!(FsubrSt0Sti, forms::FSUBR_ST0_STI, 0x31E, FloatingOp::Sub, true);
x87_arith_st!(FsubrStiSt0, forms::FSUBR_STI_ST0, 0x31F, FloatingOp::Sub, true);
x87_arith_mem!(FsubrM32, forms::FSUBR_M32, 0x320, F32, true, FloatingOp::Sub, true);
x87_arith_mem!(FsubrM64, forms::FSUBR_M64, 0x321, F64, false, FloatingOp::Sub, true);

x87_arith_st!(FmulSt0Sti, forms::FMUL_ST0_STI, 0x322, FloatingOp::Mul, false);
x87_arith_st!(FmulStiSt0, forms::FMUL_STI_ST0, 0x323, FloatingOp::Mul, false);
x87_arith_mem!(FmulM32, forms::FMUL_M32, 0x324, F32, true, FloatingOp::Mul, false);
x87_arith_mem!(FmulM64, forms::FMUL_M64, 0x325, F64, false, FloatingOp::Mul, false);

x87_arith_st!(FdivSt0Sti, forms::FDIV_ST0_STI, 0x326, FloatingOp::Div, false);
x87_arith_st!(FdivStiSt0, forms::FDIV_STI_ST0, 0x327, FloatingOp::Div, false);
x87_arith_mem!(FdivM32, forms::FDIV_M32, 0x328, F32, true, FloatingOp::Div, false);
x87_arith_mem!(FdivM64, forms::FDIV_M64, 0x329, F64, false, FloatingOp::Div, false);
x87_arith_st!(FdivrSt0Sti, forms::FDIVR_ST0_STI, 0x32A, FloatingOp::Div, true);
x87_arith_st!(FdivrStiSt0, forms::FDIVR_STI_ST0, 0x32B, FloatingOp::Div, true);
x87_arith_mem!(FdivrM32, forms::FDIVR_M32, 0x32C, F32, true, FloatingOp::Div, true);
x87_arith_mem!(FdivrM64, forms::FDIVR_M64, 0x32D, F64, false, FloatingOp::Div, true);

// ---------------------------------------------------------------------------
// FCOMI/FUCOMI: compare ST(0) with ST(i) into ZF/PF/CF
// ---------------------------------------------------------------------------

macro_rules! x87_comi {
    ($name:ident, $form:expr, $rule:expr, $pop:expr) => {
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
                let left = out.read_operand(0, U80)?;
                let right = out.read_operand(1, U80)?;
                let left_value = unpack_st(out, left)?;
                let right_value = unpack_st(out, right)?;
                let flags = out.emit(
                    SemanticOp::Float(FloatingOp::Compare),
                    U64,
                    &[left_value, right_value],
                )?;
                write_zf_cf_pf_packed(out, flags)?;
                if $pop {
                    pop_st(out)?;
                }
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

x87_comi!(FucomiSt0Sti, forms::FUCOMI_ST0_STI, 0x32E, false);
x87_comi!(FucomipSt0Sti, forms::FUCOMIP_ST0_STI, 0x32F, true);
x87_comi!(FcomiSt0Sti, forms::FCOMI_ST0_STI, 0x330, false);
x87_comi!(FcomipSt0Sti, forms::FCOMIP_ST0_STI, 0x331, true);
