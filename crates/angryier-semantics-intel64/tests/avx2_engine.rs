#![forbid(unsafe_code)]

//! Engine-side validation for the AVX-256 (VEX) integer family.
//!
//! The differential host (Ivy Bridge) has no AVX2, so these forms cannot be
//! checked against hardware; the semantics are validated through the full
//! pipeline instead: decode -> provider_for_form -> emit -> seal ->
//! lower_with_decode -> ConcreteInterpreter::execute_block, with the YMM
//! register contents checked byte-for-byte against the expected lane math.

use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use angryier_types::{
    BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, ObjectId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};

const CODE_BASE: u64 = 0x400000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(1);
const ZMM0: u32 = register_id::ZMM_BASE;
const ZMM1: u32 = register_id::ZMM_BASE + 1;

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

fn create_state(code: &[u8]) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    let reg_file = Intel64RegisterFile::canonical();
    let registers = PersistentRegisters::from_widths(
        reg_file
            .architectural_registers
            .iter()
            .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
    )
    .map_err(|e| format!("registers: {e:?}"))?;

    let memory = PersistentMemory::new(vec![MemoryRegion {
        object: ObjectId(1),
        base: CODE_BASE,
        size: 0x1000,
        readable: true,
        writable: true,
        executable: true,
    }])?;
    let bytes: Vec<ByteValue> = code.iter().map(|b| ByteValue::Concrete(*b)).collect();
    let memory = memory
        .write(CODE_BASE, &bytes)
        .map_err(|e| format!("load code: {e:?}"))?;

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

fn run_avx2(
    code: &[u8],
    form_id: u32,
    src0: &[u8],
    src1: &[u8],
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    let decoder = XedDecoder::new();
    let decoded = decoder.decode(CODE_BASE, code).map_err(|e| format!("decode: {e:?}"))?;
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let provider = registry
        .provider_for_form(form_id)
        .ok_or_else(|| format!("no provider for form {form_id:#x}"))?;
    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|e| format!("emit: {e:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|e| format!("seal: {e:?}"))?;

    let mut state = create_state(code)?;
    // The register file holds 64-byte ZMM parents; pad the 32-byte seeds.
    let mut seed0 = [0u8; 64];
    seed0[..src0.len().min(64)].copy_from_slice(&src0[..src0.len().min(64)]);
    let mut seed1 = [0u8; 64];
    seed1[..src1.len().min(64)].copy_from_slice(&src1[..src1.len().min(64)]);
    // write() is copy-on-write and returns the new state; write_in_place
    // mutates (the registers are uniquely owned here).
    state
        .registers
        .write_in_place(ZMM0, &seed0)
        .map_err(|e| format!("seed ymm0: {e:?}"))?;
    state
        .registers
        .write_in_place(ZMM1, &seed1)
        .map_err(|e| format!("seed ymm1: {e:?}"))?;

    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(1),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))
            .map_err(|e| format!("code guards: {e:?}"))?,
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
        other => return Err(format!("unexpected outcome {other:?}").into()),
    }
    Ok(final_state)
}

fn read_ymm(state: &ExecutionState<PersistentRegisters, PersistentMemory>, reg: u32) -> Result<Vec<u8>, BoxError> {
    let bytes = state.registers.read(reg).map_err(|e| format!("read reg: {e:?}"))?;
    Ok(bytes[..32].to_vec())
}

/// Seeded 8-lane u32 data for the dword tests.
fn dword_lanes(values: &[u32; 8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    for v in values {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

fn u32_lanes(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap_or([0; 4])))
        .collect()
}

#[test]
fn avx2_add_sub_ymm() -> Result<(), BoxError> {
    // vpaddd ymm0, ymm0, ymm1: c5 fd fe c1
    let a = dword_lanes(&[1, 2, 3, 4, 0x7FFF_FFFF, 0xFFFF_FFFF, 0x8000_0000, 100]);
    let b = dword_lanes(&[10, 20, 30, 40, 1, 1, 0x8000_0000, 0xFFFF_FFFF]);
    let state = run_avx2(&[0xc5, 0xfd, 0xfe, 0xc1], forms::VPADDD_YMM_YMM_YMM, &a, &b)?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    let expected = [11u32, 22, 33, 44, 0x8000_0000, 0, 0, 99];
    assert_eq!(got, expected.to_vec(), "vpaddd lanes");

    // vpsubq ymm0, ymm0, ymm1: c5 fd fb c1
    let a64 = [0x0000_0001_0000_0000u64, 0, 5, 0xFFFF_FFFF_FFFF_FFFF];
    let b64 = [1u64, 1, 2, 0xFFFF_FFFF_FFFF_FFFF];
    let mut a = Vec::new();
    let mut b = Vec::new();
    for v in a64 {
        a.extend_from_slice(&v.to_le_bytes());
    }
    for v in b64 {
        b.extend_from_slice(&v.to_le_bytes());
    }
    let state = run_avx2(&[0xc5, 0xfd, 0xfb, 0xc1], forms::VPSUBQ_YMM_YMM_YMM, &a, &b)?;
    let got = read_ymm(&state, ZMM0)?;
    let mut expected = Vec::new();
    for v in [0x0000_0000_FFFF_FFFFu64, 0xFFFF_FFFF_FFFF_FFFF, 3, 0] {
        expected.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(got, expected, "vpsubq lanes");
    Ok(())
}

#[test]
fn avx2_compare_ymm() -> Result<(), BoxError> {
    // vpcmpeqd ymm0, ymm0, ymm1: c5 f5 76 c1
    let a = dword_lanes(&[7, 7, 1, 2, 3, 4, 5, 6]);
    let b = dword_lanes(&[7, 8, 1, 2, 3, 4, 5, 6]);
    let state = run_avx2(&[0xc5, 0xfd, 0x76, 0xc1], forms::VPCMPEQD_YMM_YMM_YMM, &a, &b)?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    let expected = [
        0xFFFF_FFFFu32,
        0,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
        0xFFFF_FFFF,
    ];
    assert_eq!(got, expected.to_vec(), "vpcmpeqd lanes");

    // vpcmpgtd ymm0, ymm0, ymm1: c5 f5 66 c1 (signed: a > b)
    let a = dword_lanes(&[5, 0x8000_0000, 3, 3, 0, 0, 0x7FFF_FFFF, 1]);
    let b = dword_lanes(&[1, 1, 3, 4, 0xFFFF_FFFF, 0, 0x7FFF_FFFF, 2]);
    let state = run_avx2(&[0xc5, 0xfd, 0x66, 0xc1], forms::VPCMPGTD_YMM_YMM_YMM, &a, &b)?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    // signed compares: 5>1 -> -1; 0x80000000(-2^31) > 1 -> no; 3>3 -> no;
    // 3>4 -> no; 0 > -1(0xFFFFFFFF) -> yes; 0>0 no; 0x7fffffff>0x7fffffff no; 1>2 no.
    let expected = [0xFFFF_FFFFu32, 0, 0, 0, 0xFFFF_FFFF, 0, 0, 0];
    assert_eq!(got, expected.to_vec(), "vpcmpgtd lanes");
    Ok(())
}

#[test]
fn avx2_shifts_ymm() -> Result<(), BoxError> {
    // vpslld ymm0, ymm0, imm8(1): c5 fd 72 f0 01
    let a = dword_lanes(&[1, 0x8000_0000, 0x7FFF_FFFF, 0, 2, 0xFFFF_FFFF, 0x4000_0000, 1]);
    let state = run_avx2(
        &[0xc5, 0xfd, 0x72, 0xf0, 0x01],
        forms::VPSLLD_YMM_YMM_IMM8,
        &a,
        &[0; 32],
    )?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    let expected = [2u32, 0, 0xFFFF_FFFE, 0, 4, 0xFFFF_FFFE, 0x8000_0000, 2];
    assert_eq!(got, expected.to_vec(), "vpslld imm8=1 lanes");

    // vpsrld ymm0, ymm0, imm8(31): c5 fd 72 d0 1f
    let a = dword_lanes(&[0x8000_0000, 0xFFFF_FFFF, 0x4000_0000, 1, 2, 3, 4, 5]);
    let state = run_avx2(
        &[0xc5, 0xfd, 0x72, 0xd0, 0x1f],
        forms::VPSRLD_YMM_YMM_IMM8,
        &a,
        &[0; 32],
    )?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    let expected = [1u32, 1, 0, 0, 0, 0, 0, 0];
    assert_eq!(got, expected.to_vec(), "vpsrld imm8=31 lanes");

    // vpsllq ymm0, ymm0, imm8(1): c5 fd 73 f0 01
    let a64 = [1u64, 0x8000_0000_0000_0000, 0x7FFF_FFFF_FFFF_FFFF, 0];
    let mut a = Vec::new();
    for v in a64 {
        a.extend_from_slice(&v.to_le_bytes());
    }
    let state = run_avx2(
        &[0xc5, 0xfd, 0x73, 0xf0, 0x01],
        forms::VPSLLQ_YMM_YMM_IMM8,
        &a,
        &[0; 32],
    )?;
    let got = read_ymm(&state, ZMM0)?;
    let mut expected = Vec::new();
    for v in [2u64, 0, 0xFFFF_FFFF_FFFF_FFFE, 0] {
        expected.extend_from_slice(&v.to_le_bytes());
    }
    assert_eq!(got, expected, "vpsllq imm8=1 lanes");
    Ok(())
}

#[test]
fn avx2_min_max_broadcast_ymm() -> Result<(), BoxError> {
    // vpmaxud ymm0, ymm0, ymm1: c4 e2 75 3f c1
    let a = dword_lanes(&[1, 0xFFFF_FFFF, 3, 4, 5, 6, 7, 8]);
    let b = dword_lanes(&[2, 1, 0xFFFF_FFFF, 4, 0, 6, 7, 0x8000_0000]);
    let state = run_avx2(&[0xc4, 0xe2, 0x7d, 0x3f, 0xc1], forms::VPMAXUD_YMM_YMM_YMM, &a, &b)?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    let expected = [2u32, 0xFFFF_FFFF, 0xFFFF_FFFF, 4, 5, 6, 7, 0x8000_0000];
    assert_eq!(got, expected.to_vec(), "vpmaxud lanes");

    // vpbroadcastd ymm0, xmm1: c4 e2 7d 58 c1 — all 8 lanes = xmm1[0]
    let xmm1 = dword_lanes(&[0xDEAD_BEEF, 0, 0, 0, 0, 0, 0, 0]);
    let state = run_avx2(
        &[0xc4, 0xe2, 0x7d, 0x58, 0xc1],
        forms::VPBROADCASTD_YMM_XMM,
        &[0; 32],
        &xmm1,
    )?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    assert!(got.iter().all(|&v| v == 0xDEAD_BEEF), "vpbroadcastd all lanes");
    Ok(())
}

#[test]
fn avx2_unpack_lane_semantics() -> Result<(), BoxError> {
    // vpunpckldq ymm0, ymm0, ymm1: c5 f5 62 c1 — per-128-bit lane unpack
    let a = dword_lanes(&[
        0x1111_1111,
        0x2222_2222,
        0x3333_3333,
        0x4444_4444,
        0x5555_5555,
        0x6666_6666,
        0x7777_7777,
        0x8888_8888,
    ]);
    let b = dword_lanes(&[
        0xAAAA_AAAA,
        0xBBBB_BBBB,
        0xCCCC_CCCC,
        0xDDDD_DDDD,
        0xEEEE_EEEE,
        0xFFFF_FFFF,
        0x1212_1212,
        0x3434_3434,
    ]);
    let state = run_avx2(&[0xc5, 0xfd, 0x62, 0xc1], forms::VPUNPCKLDQ_YMM_YMM_YMM, &a, &b)?;
    let got = u32_lanes(&read_ymm(&state, ZMM0)?);
    // lane 0: a[0], b[0], a[1], b[1]; lane 1: a[4], b[4], a[5], b[5]
    let expected = [
        0x1111_1111,
        0xAAAA_AAAA,
        0x2222_2222,
        0xBBBB_BBBB,
        0x5555_5555,
        0xEEEE_EEEE,
        0x6666_6666,
        0xFFFF_FFFF,
    ];
    assert_eq!(got, expected.to_vec(), "vpunpckldq per-lane unpack");
    Ok(())
}
