#![forbid(unsafe_code)]

//! End-to-end execution tests for Intel CET shadow stack instructions.
//!
//! Validates the pipeline:
//! byte encoding -> decode -> provider_for_form -> emit -> seal -> lower -> ConcreteInterpreter

use angryier_semantics_intel64::cet;

use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, SemanticProvider, TileRepresentation,
    VectorRepresentation,
};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use angryier_types::{
    BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, ObjectId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};

const CODE_BASE: u64 = 0x400000;
const DATA_BASE: u64 = 0x500000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(1);

const RAX: u32 = register_id::GPR_BASE;
const RCX: u32 = register_id::GPR_BASE + 1;
const SSP: u32 = register_id::SSP.0;

type BoxError = Box<dyn std::error::Error>;

fn context() -> SemanticContext {
    SemanticContext {
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        fidelity: FidelityProfile::Prove,
        vector_representation: VectorRepresentation::HybridLazy,
        tile_representation: TileRepresentation::LazyChunked,
        floating_point_policy: FloatingPointPolicy::SmtFpPreferred,
    }
}

fn create_state(
    code: &[u8],
    mem_data: Option<&[u8]>,
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    let reg_file = Intel64RegisterFile::canonical();
    let registers = PersistentRegisters::from_widths(
        reg_file
            .architectural_registers
            .iter()
            .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
    )
    .map_err(|e| format!("registers: {e:?}"))?;

    let memory = PersistentMemory::new(vec![
        MemoryRegion {
            object: ObjectId(1),
            base: CODE_BASE,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: true,
        },
        MemoryRegion {
            object: ObjectId(2),
            base: DATA_BASE,
            size: 0x2000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;

    let code_bytes: Vec<ByteValue> = code.iter().map(|b| ByteValue::Concrete(*b)).collect();
    let mut memory = memory
        .write(CODE_BASE, &code_bytes)
        .map_err(|e| format!("load code: {e:?}"))?;

    if let Some(data) = mem_data {
        let data_bytes: Vec<ByteValue> = data.iter().map(|b| ByteValue::Concrete(*b)).collect();
        memory = memory
            .write(DATA_BASE, &data_bytes)
            .map_err(|e| format!("load data: {e:?}"))?;
    }

    Ok(ExecutionState {
        id: StateId(1),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    })
}

struct CetCase<'a> {
    code: &'a [u8],
    provider: &'a dyn SemanticProvider,
    rax: Option<u64>,
    rcx: Option<u64>,
    ssp: Option<u64>,
    mem_data: Option<&'a [u8]>,
}

fn run_cet(case: CetCase<'_>) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    let decoder = XedDecoder::new();
    let decoded = decoder
        .decode(CODE_BASE, case.code)
        .map_err(|e| format!("decode: {e:?}"))?;

    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    case.provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|e| format!("emit: {e:?}"))?;

    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|e| format!("seal: {e:?}"))?;

    let mut state = create_state(case.code, case.mem_data)?;
    if let Some(v) = case.rax {
        state
            .registers
            .write_in_place(RAX, &v.to_le_bytes())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(v) = case.rcx {
        state
            .registers
            .write_in_place(RCX, &v.to_le_bytes())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(v) = case.ssp {
        state
            .registers
            .write_in_place(SSP, &v.to_le_bytes())
            .map_err(|e| format!("{e:?}"))?;
    }

    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(1),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))
            .map_err(|e| format!("{e:?}"))?,
    };
    let ir_block = BasicSemanticLowerer
        .lower_with_decode(&sealed, &key, &decoded)
        .map_err(|e| format!("lower: {e:?}"))?;

    let (final_state, outcome) = ConcreteInterpreter::new()
        .execute_block(&state, &ir_block, ExecutionMode::Concrete)
        .map_err(|e| format!("execute: {e:?}"))?;

    match outcome {
        ExecutionOutcome::Continue { next_pc, .. } => {
            assert_eq!(next_pc, CODE_BASE + u64::from(decoded.length));
        }
        other => return Err(format!("unexpected outcome: {other:?}").into()),
    }

    Ok(final_state)
}

#[test]
fn test_cet_registry_conformance() {
    let providers = cet::providers();
    assert_eq!(providers.len(), 12);
    for provider in &providers {
        let rule = provider.rule_id().0;
        assert!(
            (0x2900..=0x2920).contains(&rule),
            "CET rule ID {:#x} out of expected band 0x2900..0x2920",
            rule
        );
    }
}

#[test]
fn test_cet_rdsspd_and_rdsspq() -> Result<(), BoxError> {
    // 1. rdsspd %eax: reads lower 32 bits of SSP, zero-extends to rax
    let state = run_cet(CetCase {
        code: &[0xf3, 0x0f, 0x1e, 0xc8],
        provider: &cet::RdsspdR32Provider,
        rax: Some(0xDEAD_BEEF_CAFE_BABE),
        rcx: None,
        ssp: Some(0x1234_5678_9ABC_DEF0),
        mem_data: None,
    })?;
    let rax_val = u64::from_le_bytes(state.registers.read(RAX).map_err(|e| format!("{e:?}"))?[..8].try_into()?);
    assert_eq!(rax_val, 0x9ABC_DEF0);

    // 2. rdsspq %rax: reads full 64 bits of SSP into rax
    let state = run_cet(CetCase {
        code: &[0xf3, 0x48, 0x0f, 0x1e, 0xc8],
        provider: &cet::RdsspqR64Provider,
        rax: None,
        rcx: None,
        ssp: Some(0x1234_5678_9ABC_DEF0),
        mem_data: None,
    })?;
    let rax_val = u64::from_le_bytes(state.registers.read(RAX).map_err(|e| format!("{e:?}"))?[..8].try_into()?);
    assert_eq!(rax_val, 0x1234_5678_9ABC_DEF0);

    Ok(())
}

#[test]
fn test_cet_incsspd_and_incsspq() -> Result<(), BoxError> {
    // 1. incsspd %eax: SSP := SSP + (eax * 4)
    let state = run_cet(CetCase {
        code: &[0xf3, 0x0f, 0xae, 0xe8],
        provider: &cet::IncsspdR32Provider,
        rax: Some(5),
        rcx: None,
        ssp: Some(0x1000),
        mem_data: None,
    })?;
    let ssp_val = u64::from_le_bytes(state.registers.read(SSP).map_err(|e| format!("{e:?}"))?[..8].try_into()?);
    assert_eq!(ssp_val, 0x1000 + 5 * 4);

    // 2. incsspq %rax: SSP := SSP + (rax * 8)
    let state = run_cet(CetCase {
        code: &[0xf3, 0x48, 0x0f, 0xae, 0xe8],
        provider: &cet::IncsspqR64Provider,
        rax: Some(3),
        rcx: None,
        ssp: Some(0x2000),
        mem_data: None,
    })?;
    let ssp_val = u64::from_le_bytes(state.registers.read(SSP).map_err(|e| format!("{e:?}"))?[..8].try_into()?);
    assert_eq!(ssp_val, 0x2000 + 3 * 8);

    Ok(())
}

#[test]
fn test_cet_saveprevssp_and_rstorssp() -> Result<(), BoxError> {
    // 1. saveprevssp: ssp := ssp - 8; [ssp] := old_ssp | 1
    let state = run_cet(CetCase {
        code: &[0xf3, 0x0f, 0x01, 0xea],
        provider: &cet::SaveprevsspProvider,
        rax: None,
        rcx: None,
        ssp: Some(DATA_BASE + 0x100),
        mem_data: None,
    })?;
    let ssp_val = u64::from_le_bytes(state.registers.read(SSP).map_err(|e| format!("{e:?}"))?[..8].try_into()?);
    assert_eq!(ssp_val, DATA_BASE + 0x100 - 8);

    // 2. rstorssp (%rax): SSP := token & ~7
    let mut mem = [0u8; 64];
    let token = 0x5000_1234_5678_9001u64; // bit 0 set (restore token)
    mem[..8].copy_from_slice(&token.to_le_bytes());

    let state = run_cet(CetCase {
        code: &[0xf3, 0x0f, 0x01, 0x28], // rstorssp (%rax)
        provider: &cet::RstorsspMem64Provider,
        rax: Some(DATA_BASE),
        rcx: None,
        ssp: Some(0),
        mem_data: Some(&mem),
    })?;
    let ssp_val = u64::from_le_bytes(state.registers.read(SSP).map_err(|e| format!("{e:?}"))?[..8].try_into()?);
    assert_eq!(ssp_val, token & !7);

    Ok(())
}

#[test]
fn test_cet_setssbsy_and_clrssbsy() -> Result<(), BoxError> {
    // setssbsy and clrssbsy should execute cleanly without error
    let _state = run_cet(CetCase {
        code: &[0xf3, 0x0f, 0x01, 0xe8], // setssbsy
        provider: &cet::SetssbsyProvider,
        rax: Some(DATA_BASE),
        rcx: None,
        ssp: None,
        mem_data: None,
    })?;

    let _state = run_cet(CetCase {
        code: &[0xf3, 0x0f, 0xae, 0x30], // clrssbsy (%rax)
        provider: &cet::ClrssbsyMem64Provider,
        rax: Some(DATA_BASE),
        rcx: None,
        ssp: None,
        mem_data: None,
    })?;

    Ok(())
}

#[test]
fn test_cet_wrssd_and_wrssq() -> Result<(), BoxError> {
    // 1. wrssd %eax, (%rcx)
    let state = run_cet(CetCase {
        code: &[0x0f, 0x38, 0xf6, 0x01],
        provider: &cet::WrssdMem32R32Provider,
        rax: Some(0x1234_5678),
        rcx: Some(DATA_BASE),
        ssp: None,
        mem_data: Some(&[0u8; 16]),
    })?;
    let mut stored = [ByteValue::Concrete(0); 4];
    state
        .memory
        .read_into(DATA_BASE, &mut stored)
        .map_err(|e| format!("{e:?}"))?;
    let stored_val = u32::from_le_bytes(stored.map(|b| match b {
        ByteValue::Concrete(x) => x,
        _ => 0,
    }));
    assert_eq!(stored_val, 0x1234_5678);

    // 2. wrssq %rax, (%rcx)
    let state = run_cet(CetCase {
        code: &[0x48, 0x0f, 0x38, 0xf6, 0x01],
        provider: &cet::WrssqMem64R64Provider,
        rax: Some(0xDEAD_BEEF_CAFE_BABE),
        rcx: Some(DATA_BASE),
        ssp: None,
        mem_data: Some(&[0u8; 16]),
    })?;
    let mut stored = [ByteValue::Concrete(0); 8];
    state
        .memory
        .read_into(DATA_BASE, &mut stored)
        .map_err(|e| format!("{e:?}"))?;
    let stored_val = u64::from_le_bytes(stored.map(|b| match b {
        ByteValue::Concrete(x) => x,
        _ => 0,
    }));
    assert_eq!(stored_val, 0xDEAD_BEEF_CAFE_BABE);

    Ok(())
}
