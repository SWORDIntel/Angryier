#![forbid(unsafe_code)]

//! Control-flow Enforcement Technology (CET) semantic providers.
//!
//! Covers shadow stack operations:
//! - INCSSPD / INCSSPQ (increment shadow stack pointer)
//! - RDSSPD / RDSSPQ (read shadow stack pointer)
//! - SAVEPREVSSP (save previous shadow stack pointer)
//! - RSTORSSP (restore shadow stack pointer)
//! - SETSSBSY / CLRSSBSY (shadow stack busy flag management)
//! - WRSSD / WRSSQ (write to shadow stack)
//! - WRUSSD / WRUSSQ (write to user shadow stack)

use angryier_arch_intel64::register_id;
use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext, SemanticError, SemanticOp,
    SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, SideEffect,
};
use angryier_types::SemanticRuleId;
use std::sync::Arc;

use crate::{forms, rule_id};

const U32: SemanticType = SemanticType::Scalar(ScalarType::BitVec(32));
const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = out.constant(
        U64,
        &insn.address().wrapping_add(u64::from(insn.length())).to_le_bytes(),
    )?;
    out.jump(next_pc)?;
    Ok(())
}

macro_rules! cet_provider {
    ($name:ident, $rule_offset:expr, $form_id:expr, $body:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule_offset)
            }

            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }

            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form_id
            }

            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let _ = (context, insn);
                #[allow(clippy::redundant_closure_call)]
                $body(out, insn)?;
                fall_through(out, insn)?;
                Ok(SemanticReceipt {
                    rule_id: self.rule_id(),
                    origin: self.origin(),
                    semantic_version: context.semantic_version,
                })
            }
        }
    };
}

// ---------------------------------------------------------------------------
// 1. RDSSPD / RDSSPQ: Read Shadow Stack Pointer
// ---------------------------------------------------------------------------

cet_provider!(
    RdsspdR32Provider,
    0x1900,
    forms::RDSSPD_R32,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let ssp = out.read_register(register_id::SSP, U64)?;
        let zero = out.constant(U64, &0u64.to_le_bytes())?;
        let ssp32 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), U32, &[ssp, zero])?;
        out.write_operand(0, ssp32)?;
        Ok::<(), SemanticError>(())
    }
);

cet_provider!(
    RdsspqR64Provider,
    0x1901,
    forms::RDSSPQ_R64,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let ssp = out.read_register(register_id::SSP, U64)?;
        out.write_operand(0, ssp)?;
        Ok::<(), SemanticError>(())
    }
);

// ---------------------------------------------------------------------------
// 2. INCSSPD / INCSSPQ: Increment Shadow Stack Pointer
// ---------------------------------------------------------------------------

cet_provider!(
    IncsspdR32Provider,
    0x1902,
    forms::INCSSPD_R32,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let count32 = out.read_operand(0, U32)?;
        let ff = out.constant(U32, &0xFFu32.to_le_bytes())?;
        let count8 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U32, &[count32, ff])?;
        let count64 = out.emit(SemanticOp::Primitive(PrimitiveOp::ZeroExtend), U64, &[count8])?;
        let four = out.constant(U64, &4u64.to_le_bytes())?;
        let delta = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[count64, four])?;
        let ssp = out.read_register(register_id::SSP, U64)?;
        let new_ssp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[ssp, delta])?;
        out.write_register(register_id::SSP, new_ssp)?;
        Ok::<(), SemanticError>(())
    }
);

cet_provider!(
    IncsspqR64Provider,
    0x1903,
    forms::INCSSPQ_R64,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let count = out.read_operand(0, U64)?;
        let ff = out.constant(U64, &0xFFu64.to_le_bytes())?;
        let count_byte = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[count, ff])?;
        let eight = out.constant(U64, &8u64.to_le_bytes())?;
        let delta = out.emit(SemanticOp::Primitive(PrimitiveOp::Mul), U64, &[count_byte, eight])?;
        let ssp = out.read_register(register_id::SSP, U64)?;
        let new_ssp = out.emit(SemanticOp::Primitive(PrimitiveOp::Add), U64, &[ssp, delta])?;
        out.write_register(register_id::SSP, new_ssp)?;
        Ok::<(), SemanticError>(())
    }
);

// ---------------------------------------------------------------------------
// 3. SAVEPREVSSP: Push current SSP to shadow stack
// ---------------------------------------------------------------------------

cet_provider!(
    SaveprevsspProvider,
    0x1904,
    forms::SAVEPREVSSP,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let ssp = out.read_register(register_id::SSP, U64)?;
        let eight = out.constant(U64, &8u64.to_le_bytes())?;
        let new_ssp = out.emit(SemanticOp::Primitive(PrimitiveOp::Sub), U64, &[ssp, eight])?;
        out.write_register(register_id::SSP, new_ssp)?;
        let one = out.constant(U64, &1u64.to_le_bytes())?;
        let token = out.emit(SemanticOp::Primitive(PrimitiveOp::Or), U64, &[ssp, one])?;
        out.side_effect(SideEffect::MemoryWrite, &[new_ssp, token])?;
        Ok::<(), SemanticError>(())
    }
);

// ---------------------------------------------------------------------------
// 4. RSTORSSP: Restore SSP from restore token
// ---------------------------------------------------------------------------

cet_provider!(
    RstorsspMem64Provider,
    0x1905,
    forms::RSTORSSP_MEM64,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let token = out.read_operand(0, U64)?;
        let mask = out.constant(U64, &(!7u64).to_le_bytes())?;
        let new_ssp = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[token, mask])?;
        out.write_register(register_id::SSP, new_ssp)?;
        Ok::<(), SemanticError>(())
    }
);

// ---------------------------------------------------------------------------
// 5. SETSSBSY / CLRSSBSY: Busy flag management
// ---------------------------------------------------------------------------

cet_provider!(
    SetssbsyProvider,
    0x1906,
    forms::SETSSBSY,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

cet_provider!(
    ClrssbsyMem64Provider,
    0x1907,
    forms::CLRSSBSY_MEM64,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

// ---------------------------------------------------------------------------
// 6. WRSSD / WRSSQ / WRUSSD / WRUSSQ: Shadow stack writes
// ---------------------------------------------------------------------------

cet_provider!(
    WrssdMem32R32Provider,
    0x1908,
    forms::WRSSD_MEM32_R32,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, U32)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

cet_provider!(
    WrssqMem64R64Provider,
    0x1909,
    forms::WRSSQ_MEM64_R64,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, U64)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

cet_provider!(
    WrussdMem32R32Provider,
    0x190A,
    forms::WRUSSD_MEM32_R32,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, U32)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

cet_provider!(
    WrussqMem64R64Provider,
    0x190B,
    forms::WRUSSQ_MEM64_R64,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, U64)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

pub fn providers() -> Vec<Arc<dyn SemanticProvider>> {
    vec![
        Arc::new(RdsspdR32Provider),
        Arc::new(RdsspqR64Provider),
        Arc::new(IncsspdR32Provider),
        Arc::new(IncsspqR64Provider),
        Arc::new(SaveprevsspProvider),
        Arc::new(RstorsspMem64Provider),
        Arc::new(SetssbsyProvider),
        Arc::new(ClrssbsyMem64Provider),
        Arc::new(WrssdMem32R32Provider),
        Arc::new(WrssqMem64R64Provider),
        Arc::new(WrussdMem32R32Provider),
        Arc::new(WrussqMem64R64Provider),
    ]
}
