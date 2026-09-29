#![forbid(unsafe_code)]

#[path = "../src/amx.rs"]
mod amx;

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
const TMM0: u32 = register_id::TILE_BASE;
const TMM1: u32 = register_id::TILE_BASE + 1;
const TMM2: u32 = register_id::TILE_BASE + 2;
const TILECFG: u32 = register_id::TILECFG.0;

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

struct AmxCase<'a> {
    code: &'a [u8],
    provider: &'a dyn SemanticProvider,
    tmm0: Option<&'a [u8; 1024]>,
    tmm1: Option<&'a [u8; 1024]>,
    tmm2: Option<&'a [u8; 1024]>,
    tilecfg: Option<&'a [u8; 64]>,
    rax: Option<u64>,
    rcx: Option<u64>,
    mem_data: Option<&'a [u8]>,
}

fn run_amx(case: AmxCase<'_>) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
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
    if let Some(v) = case.tmm0 {
        state
            .registers
            .write_in_place(TMM0, v.as_slice())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(v) = case.tmm1 {
        state
            .registers
            .write_in_place(TMM1, v.as_slice())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(v) = case.tmm2 {
        state
            .registers
            .write_in_place(TMM2, v.as_slice())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(v) = case.tilecfg {
        state
            .registers
            .write_in_place(TILECFG, v.as_slice())
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
fn test_amx_registry_conformance() {
    let providers = amx::providers();
    assert_eq!(providers.len(), 13);
    for provider in &providers {
        let rule_id = provider.rule_id().0;
        assert!(
            (0x2800..=0x2820).contains(&rule_id),
            "rule id {rule_id:#x} out of range 0x2800..0x2820"
        );
    }
}

#[test]
fn test_amx_tilezero_and_tilerelease() -> Result<(), BoxError> {
    // 1. tilezero %tmm0
    let initial_tmm0 = [0xAAu8; 1024];
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x7b, 0x49, 0xc0], // tilezero %tmm0
        provider: &amx::TilezeroTmmProvider,
        tmm0: Some(&initial_tmm0),
        tmm1: None,
        tmm2: None,
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;
    let tmm0_val = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    assert_eq!(tmm0_val.len(), 1024);
    assert!(tmm0_val.iter().all(|&b| b == 0));

    // 2. tilerelease
    let initial_cfg = [0x55u8; 64];
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x78, 0x49, 0xc0], // tilerelease
        provider: &amx::TilereleaseProvider,
        tmm0: None,
        tmm1: None,
        tmm2: None,
        tilecfg: Some(&initial_cfg),
        rax: None,
        rcx: None,
        mem_data: None,
    })?;
    let cfg_val = state.registers.read(TILECFG).map_err(|e| format!("{e:?}"))?;
    assert_eq!(cfg_val.len(), 64);
    assert!(cfg_val.iter().all(|&b| b == 0));

    Ok(())
}

#[test]
fn test_amx_ldtilecfg_and_sttilecfg() -> Result<(), BoxError> {
    // 1. ldtilecfg (%rax)
    let mut cfg_data = [0u8; 64];
    cfg_data[0] = 1; // palette_id = 1
    cfg_data[48] = 8; // rows for tmm0 = 8
    cfg_data[16] = 32; // bytes_per_row for tmm0 = 32
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x78, 0x49, 0x00], // ldtilecfg (%rax)
        provider: &amx::LdtilecfgMemProvider,
        tmm0: None,
        tmm1: None,
        tmm2: None,
        tilecfg: None,
        rax: Some(DATA_BASE),
        rcx: None,
        mem_data: Some(&cfg_data),
    })?;
    let read_cfg = state.registers.read(TILECFG).map_err(|e| format!("{e:?}"))?;
    assert_eq!(&read_cfg[..64], &cfg_data[..]);

    // 2. sttilecfg (%rax)
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x79, 0x49, 0x00], // sttilecfg (%rax)
        provider: &amx::SttilecfgMemProvider,
        tmm0: None,
        tmm1: None,
        tmm2: None,
        tilecfg: Some(&cfg_data),
        rax: Some(DATA_BASE),
        rcx: None,
        mem_data: Some(&[0u8; 64]),
    })?;
    let mut stored = [ByteValue::Concrete(0); 64];
    state
        .memory
        .read_into(DATA_BASE, &mut stored)
        .map_err(|e| format!("{e:?}"))?;
    let stored_bytes: Vec<u8> = stored
        .iter()
        .map(|b| match b {
            ByteValue::Concrete(x) => *x,
            _ => 0,
        })
        .collect();
    assert_eq!(&stored_bytes[..64], &cfg_data[..]);

    Ok(())
}

#[test]
fn test_amx_tileloadd_and_tilestored() -> Result<(), BoxError> {
    // 1. tileloadd (%rax,%rcx,1), %tmm0
    let mut tile_data = vec![0x42u8; 1024];
    tile_data[0] = 0x11;
    tile_data[1023] = 0x99;
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x7b, 0x4b, 0x04, 0x08], // tileloadd (%rax,%rcx,1), %tmm0
        provider: &amx::TileloaddTmmMemProvider,
        tmm0: None,
        tmm1: None,
        tmm2: None,
        tilecfg: None,
        rax: Some(DATA_BASE),
        rcx: Some(0),
        mem_data: Some(&tile_data),
    })?;
    let tmm0_val = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    assert_eq!(&tmm0_val[..1024], tile_data.as_slice());

    // 2. tilestored %tmm0, (%rax,%rcx,1)
    let mut initial_tmm0 = [0x77u8; 1024];
    initial_tmm0[0] = 0xAA;
    initial_tmm0[512] = 0xBB;
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x7a, 0x4b, 0x04, 0x08], // tilestored %tmm0, (%rax,%rcx,1)
        provider: &amx::TilestoredMemTmmProvider,
        tmm0: Some(&initial_tmm0),
        tmm1: None,
        tmm2: None,
        tilecfg: None,
        rax: Some(DATA_BASE),
        rcx: Some(0),
        mem_data: Some(&vec![0u8; 1024]),
    })?;
    let mut stored = vec![ByteValue::Concrete(0); 1024];
    state
        .memory
        .read_into(DATA_BASE, &mut stored)
        .map_err(|e| format!("{e:?}"))?;
    let stored_bytes: Vec<u8> = stored
        .iter()
        .map(|b| match b {
            ByteValue::Concrete(x) => *x,
            _ => 0,
        })
        .collect();
    assert_eq!(&stored_bytes[..1024], initial_tmm0.as_slice());

    Ok(())
}

#[test]
fn test_amx_int8_tdpbssd() -> Result<(), BoxError> {
    // tdpbssd %tmm2, %tmm1, %tmm0
    // dst: tmm0, src1: tmm1, src2: tmm2
    let mut tmm0 = [0u8; 1024];
    let mut tmm1 = [0u8; 1024];
    let mut tmm2 = [0u8; 1024];

    // Seed destination dword [0, 0] with 100
    tmm0[0..4].copy_from_slice(&100i32.to_le_bytes());

    // src1 row 0: [2, 3, 4, 5, 0, ...]
    tmm1[0] = 2;
    tmm1[1] = 3;
    tmm1[2] = 4;
    tmm1[3] = 5;

    // src2 row 0 (which is k=0 for col n=0): [1, 2, 3, 4, 0, ...]
    tmm2[0] = 1;
    tmm2[1] = 2;
    tmm2[2] = 3;
    tmm2[3] = 4;

    // Dot product: 2*1 + 3*2 + 4*3 + 5*4 = 2 + 6 + 12 + 20 = 40
    // Expected result: 100 + 40 = 140
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x6b, 0x5e, 0xc1], // tdpbssd %tmm2, %tmm1, %tmm0
        provider: &amx::TdpbssdTmmTmmTmmProvider,
        tmm0: Some(&tmm0),
        tmm1: Some(&tmm1),
        tmm2: Some(&tmm2),
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;

    let res = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    let dword0 = i32::from_le_bytes([res[0], res[1], res[2], res[3]]);
    assert_eq!(dword0, 140);

    Ok(())
}

#[test]
fn test_amx_int8_tdpbsud_tdpbusd_tdpbuud() -> Result<(), BoxError> {
    let tmm0 = [0u8; 1024];
    let mut tmm1 = [0u8; 1024];
    let mut tmm2 = [0u8; 1024];

    // src1: signed -2, -3, 4, 5
    tmm1[0] = (-2i8) as u8;
    tmm1[1] = (-3i8) as u8;
    tmm1[2] = 4;
    tmm1[3] = 5;

    // src2: unsigned 10, 20, 30, 40
    tmm2[0] = 10;
    tmm2[1] = 20;
    tmm2[2] = 30;
    tmm2[3] = 40;

    // tdpbsud: signed x unsigned:
    // (-2)*10 + (-3)*20 + 4*30 + 5*40 = -20 - 60 + 120 + 200 = 240
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x6a, 0x5e, 0xc1], // tdpbsud %tmm2, %tmm1, %tmm0
        provider: &amx::TdpbsudTmmTmmTmmProvider,
        tmm0: Some(&tmm0),
        tmm1: Some(&tmm1),
        tmm2: Some(&tmm2),
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;
    let res = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    let dword0 = i32::from_le_bytes([res[0], res[1], res[2], res[3]]);
    assert_eq!(dword0, 240);

    // tdpbusd: unsigned x signed:
    // swap roles: src1 unsigned (10,20,30,40), src2 signed (-2,-3,4,5)
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x69, 0x5e, 0xc1], // tdpbusd %tmm2, %tmm1, %tmm0
        provider: &amx::TdpbusdTmmTmmTmmProvider,
        tmm0: Some(&tmm0),
        tmm1: Some(&tmm2),
        tmm2: Some(&tmm1),
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;
    let res = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    let dword0 = i32::from_le_bytes([res[0], res[1], res[2], res[3]]);
    assert_eq!(dword0, 240);

    // tdpbuud: unsigned x unsigned:
    // src1 (2, 3, 4, 5) x src2 (10, 20, 30, 40)
    // 2*10 + 3*20 + 4*30 + 5*40 = 20 + 60 + 120 + 200 = 400
    tmm1[0] = 2;
    tmm1[1] = 3;
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x68, 0x5e, 0xc1], // tdpbuud %tmm2, %tmm1, %tmm0
        provider: &amx::TdpbuudTmmTmmTmmProvider,
        tmm0: Some(&tmm0),
        tmm1: Some(&tmm1),
        tmm2: Some(&tmm2),
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;
    let res = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    let dword0 = i32::from_le_bytes([res[0], res[1], res[2], res[3]]);
    assert_eq!(dword0, 400);

    Ok(())
}

#[test]
fn test_amx_bf16_tdpbf16ps() -> Result<(), BoxError> {
    // tdpbf16ps %tmm2, %tmm1, %tmm0
    let mut tmm0 = [0u8; 1024];
    let mut tmm1 = [0u8; 1024];
    let mut tmm2 = [0u8; 1024];

    // Seed destination dword [0, 0] with 5.0f32
    tmm0[0..4].copy_from_slice(&5.0f32.to_le_bytes());

    // BF16 values:
    // 1.0f32 is 0x3F800000 -> bf16 is 0x3F80
    // 2.0f32 is 0x40000000 -> bf16 is 0x4000
    // 3.0f32 is 0x40400000 -> bf16 is 0x4040
    // 4.0f32 is 0x40800000 -> bf16 is 0x4080

    // src1 pair: [1.0, 2.0]
    tmm1[0..2].copy_from_slice(&0x3F80u16.to_le_bytes());
    tmm1[2..4].copy_from_slice(&0x4000u16.to_le_bytes());

    // src2 pair: [3.0, 4.0]
    tmm2[0..2].copy_from_slice(&0x4040u16.to_le_bytes());
    tmm2[2..4].copy_from_slice(&0x4080u16.to_le_bytes());

    // Expected: 5.0 + 1.0*3.0 + 2.0*4.0 = 5.0 + 3.0 + 8.0 = 16.0f32
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x6a, 0x5c, 0xc1], // tdpbf16ps %tmm2, %tmm1, %tmm0
        provider: &amx::Tdpbf16psTmmTmmTmmProvider,
        tmm0: Some(&tmm0),
        tmm1: Some(&tmm1),
        tmm2: Some(&tmm2),
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;

    let res = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    let f0 = f32::from_le_bytes([res[0], res[1], res[2], res[3]]);
    assert_eq!(f0, 16.0f32);

    Ok(())
}

#[test]
fn test_amx_fp16_tdpfp16ps() -> Result<(), BoxError> {
    // tdpfp16ps %tmm2, %tmm1, %tmm0
    let mut tmm0 = [0u8; 1024];
    let mut tmm1 = [0u8; 1024];
    let mut tmm2 = [0u8; 1024];

    // Seed destination dword [0, 0] with 10.0f32
    tmm0[0..4].copy_from_slice(&10.0f32.to_le_bytes());

    // IEEE FP16 values:
    // 1.0f16 is 0x3C00
    // 2.0f16 is 0x4000
    // 3.0f16 is 0x4200
    // 4.0f16 is 0x4400

    // src1 pair: [1.0, 2.0]
    tmm1[0..2].copy_from_slice(&0x3C00u16.to_le_bytes());
    tmm1[2..4].copy_from_slice(&0x4000u16.to_le_bytes());

    // src2 pair: [3.0, 4.0]
    tmm2[0..2].copy_from_slice(&0x4200u16.to_le_bytes());
    tmm2[2..4].copy_from_slice(&0x4400u16.to_le_bytes());

    // Expected: 10.0 + 1.0*3.0 + 2.0*4.0 = 10.0 + 3.0 + 8.0 = 21.0f32
    let state = run_amx(AmxCase {
        code: &[0xc4, 0xe2, 0x6b, 0x5c, 0xc1], // tdpfp16ps %tmm2, %tmm1, %tmm0
        provider: &amx::Tdpfp16psTmmTmmTmmProvider,
        tmm0: Some(&tmm0),
        tmm1: Some(&tmm1),
        tmm2: Some(&tmm2),
        tilecfg: None,
        rax: None,
        rcx: None,
        mem_data: None,
    })?;

    let res = state.registers.read(TMM0).map_err(|e| format!("{e:?}"))?;
    let f0 = f32::from_le_bytes([res[0], res[1], res[2], res[3]]);
    assert_eq!(f0, 21.0f32);

    Ok(())
}
