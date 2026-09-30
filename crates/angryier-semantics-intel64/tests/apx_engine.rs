#![forbid(unsafe_code)]

//! End-to-end execution tests for Intel APX (Advanced Performance Extensions).
//!
//! Validates the pipeline:
//! byte encoding -> decode -> provider emit -> seal -> lower -> ConcreteInterpreter
//!
//! Ground-truth semantics under test:
//! 1. JMPABS imm64                — next pc = imm64
//! 2. PUSH2 / PUSH2P              — RSP := R-16; [R-8] := src1; [R-16] := src2
//!    (Intel SDM: [new_rsp+8] = src1, [new_rsp] = src2)
//! 3. POP2 / POP2P                — src1 := [R]; src2 := [R+8]; RSP := R+16
//! 4. CCMPZ w64                   — cond true  -> RFLAGS = cmp(src1, src2) flags
//!    cond false -> RFLAGS = DFV-derived
//!    (CF=bit0, ZF=bit1, SF=bit2, OF=bit3, PF=AF=0)
//! 5. CTESTZ w64                  — RFLAGS ZF/SF/PF from AND(src1, src2); CF=OF=AF=0
//! 6. NDD ADD (NF / non-NF)       — dst := src1 + src2; NF preserves RFLAGS
//! 7. NDD SHL imm8                — dst := src1 << (count & 0x3F)
//! 8. CFCMOVZ                     — ZF=1 -> dst := src; ZF=0 -> dst unchanged

use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, DecodedInstructionView, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext,
    SemanticProvider, TileRepresentation, VectorRepresentation,
};
use angryier_semantics_intel64::apx;
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
const RDX: u32 = register_id::GPR_BASE + 2;
const RSP: u32 = register_id::GPR_BASE + 4;
const R9: u32 = register_id::GPR_BASE + 9;
const R15: u32 = register_id::GPR_BASE + 15;
const R16: u32 = register_id::GPR_BASE + 16;
const R17: u32 = register_id::GPR_BASE + 17;
const RFLAGS: u32 = register_id::RFLAGS.0;

/// The stack pointer value PUSH2/PUSH2P cases are seeded with. Stores land at
/// R-16..R, so the seed keeps every touched address inside the data region.
const PUSH_STACK_TOP: u64 = DATA_BASE + 0x100;

/// Sentinel stored at the old stack top [R] in the PUSH2 tests: neither store
/// of the pair may touch it.
const OLD_TOP_SENTINEL: u64 = 0x5555_5555_5555_5555;

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

struct ApxCase<'a> {
    code: &'a [u8],
    provider: &'a dyn SemanticProvider,
    rax: Option<u64>,
    rcx: Option<u64>,
    rdx: Option<u64>,
    r9: Option<u64>,
    r15: Option<u64>,
    r16: Option<u64>,
    r17: Option<u64>,
    rsp: Option<u64>,
    rflags: Option<u64>,
    mem_data: Option<&'a [u8]>,
    /// Asserted next pc. `None` asserts the architectural fall-through.
    next_pc: Option<u64>,
}

impl<'a> ApxCase<'a> {
    fn new(code: &'a [u8], provider: &'a dyn SemanticProvider) -> Self {
        Self {
            code,
            provider,
            rax: None,
            rcx: None,
            rdx: None,
            r9: None,
            r15: None,
            r16: None,
            r17: None,
            rsp: None,
            rflags: None,
            mem_data: None,
            next_pc: None,
        }
    }
}

fn run_apx(case: ApxCase<'_>) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
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
    for (id, value) in [
        (RAX, case.rax),
        (RCX, case.rcx),
        (RDX, case.rdx),
        (R9, case.r9),
        (R15, case.r15),
        (R16, case.r16),
        (R17, case.r17),
        (RSP, case.rsp),
        (RFLAGS, case.rflags),
    ] {
        if let Some(v) = value {
            state
                .registers
                .write_in_place(id, &v.to_le_bytes())
                .map_err(|e| format!("{e:?}"))?;
        }
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

    let expected_pc = case.next_pc.unwrap_or(CODE_BASE + u64::from(decoded.length));
    match outcome {
        ExecutionOutcome::Continue { next_pc, .. } => {
            assert_eq!(next_pc, expected_pc, "unexpected next pc");
        }
        other => return Err(format!("unexpected outcome: {other:?}").into()),
    }

    Ok(final_state)
}

fn read_gpr(state: &ExecutionState<PersistentRegisters, PersistentMemory>, id: u32) -> Result<u64, BoxError> {
    let bytes = state.registers.read(id).map_err(|e| format!("{e:?}"))?;
    Ok(u64::from_le_bytes(bytes[..8].try_into()?))
}

fn read_qword(state: &ExecutionState<PersistentRegisters, PersistentMemory>, address: u64) -> Result<u64, BoxError> {
    let mut bytes = [ByteValue::Concrete(0); 8];
    state
        .memory
        .read_into(address, &mut bytes)
        .map_err(|e| format!("{e:?}"))?;
    Ok(u64::from_le_bytes(bytes.map(|b| match b {
        ByteValue::Concrete(x) => x,
        _ => 0,
    })))
}

/// 0x108 bytes of zeroed stack image whose qword at offset 0x100 (address
/// DATA_BASE + 0x100 = the PUSH2 seed RSP) holds the old-top sentinel.
fn push_stack_image() -> Vec<u8> {
    let mut image = vec![0u8; 0x108];
    image[0x100..0x108].copy_from_slice(&OLD_TOP_SENTINEL.to_le_bytes());
    image
}

// ---------------------------------------------------------------------------
// Registry conformance
// ---------------------------------------------------------------------------

#[test]
fn test_apx_registry_conformance() {
    let providers = apx::providers();
    assert_eq!(providers.len(), 61, "expected the full APX provider set");
    let mut seen = std::collections::BTreeSet::new();
    for provider in &providers {
        let rule = provider.rule_id().0;
        assert!(
            (0x2A00..=0x2A40).contains(&rule),
            "APX rule ID {:#x} out of expected band 0x2A00..=0x2A40",
            rule
        );
        assert!(seen.insert(rule), "duplicate APX rule id {rule:#x}");
    }
}

// ---------------------------------------------------------------------------
// 1. JMPABS imm64
// ---------------------------------------------------------------------------

#[test]
fn test_apx_jmpabs_imm64() -> Result<(), BoxError> {
    // jmpabs 0x1122334455667788
    let _state = run_apx(ApxCase {
        next_pc: Some(0x1122_3344_5566_7788),
        ..ApxCase::new(
            &[0xd5, 0x00, 0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
            &apx::JmpabsImm64Provider,
        )
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. PUSH2 / PUSH2P
// ---------------------------------------------------------------------------

/// Intel SDM PUSH2 semantics: RSP := RSP - 16; Mem[RSP+8] := src1;
/// Mem[RSP] := src2. With pre-instruction stack pointer R this is
/// [R-8] = src1 and [R-16] = src2, and the old top [R] is untouched.
fn assert_push2_state(state: &ExecutionState<PersistentRegisters, PersistentMemory>) -> Result<(), BoxError> {
    assert_eq!(read_gpr(state, RSP)?, PUSH_STACK_TOP - 16, "RSP := R - 16");
    assert_eq!(
        read_qword(state, PUSH_STACK_TOP - 8)?,
        0xAAAA_AAA1,
        "[R-8] must hold src1 (r15)"
    );
    assert_eq!(
        read_qword(state, PUSH_STACK_TOP - 16)?,
        0xBBBB_BBB2,
        "[R-16] must hold src2 (rcx)"
    );
    assert_eq!(
        read_qword(state, PUSH_STACK_TOP)?,
        OLD_TOP_SENTINEL,
        "the pre-push old top [R] must be untouched"
    );
    Ok(())
}

#[test]
fn test_apx_push2() -> Result<(), BoxError> {
    // push2 %r15, %rcx
    let image = push_stack_image();
    let state = run_apx(ApxCase {
        r15: Some(0xAAAA_AAA1),
        rcx: Some(0xBBBB_BBB2),
        rsp: Some(PUSH_STACK_TOP),
        mem_data: Some(&image),
        ..ApxCase::new(&[0x62, 0xf4, 0x04, 0x18, 0xff, 0xf1], &apx::Push2R64R64Provider)
    })?;
    assert_push2_state(&state)
}

#[test]
fn test_apx_push2p_same_semantics_in_64bit() -> Result<(), BoxError> {
    // push2p %r15, %rcx — identical semantics to PUSH2 in 64-bit mode
    let image = push_stack_image();
    let state = run_apx(ApxCase {
        r15: Some(0xAAAA_AAA1),
        rcx: Some(0xBBBB_BBB2),
        rsp: Some(PUSH_STACK_TOP),
        mem_data: Some(&image),
        ..ApxCase::new(&[0x62, 0xf4, 0x84, 0x18, 0xff, 0xf1], &apx::Push2pR64R64Provider)
    })?;
    assert_push2_state(&state)
}

// ---------------------------------------------------------------------------
// 3. POP2 / POP2P
// ---------------------------------------------------------------------------

const POP_V1: u64 = 0x1122_3344_5566_7788;
const POP_V2: u64 = 0x99AA_BBCC_DDEE_FF00;
const POP_R15_SEED: u64 = 0xDEAD_0000_0000_0001;
const POP_RCX_SEED: u64 = 0xDEAD_0000_0000_0002;

/// Intel SDM POP2 semantics: src1 := Mem[RSP]; src2 := Mem[RSP+8];
/// RSP := RSP + 16. Memory is left unchanged.
fn assert_pop2_state(state: &ExecutionState<PersistentRegisters, PersistentMemory>) -> Result<(), BoxError> {
    assert_eq!(read_gpr(state, R15)?, POP_V1, "r15 := [R]");
    assert_eq!(read_gpr(state, RCX)?, POP_V2, "rcx := [R+8]");
    assert_eq!(read_gpr(state, RSP)?, DATA_BASE + 16, "RSP := R + 16");
    assert_eq!(read_qword(state, DATA_BASE)?, POP_V1, "stack qword [R] preserved");
    assert_eq!(read_qword(state, DATA_BASE + 8)?, POP_V2, "stack qword [R+8] preserved");
    Ok(())
}

#[test]
fn test_apx_pop2() -> Result<(), BoxError> {
    // pop2 %r15, %rcx — seed RSP = R with [R] = V1 and [R+8] = V2
    let mut image = [0u8; 16];
    image[..8].copy_from_slice(&POP_V1.to_le_bytes());
    image[8..].copy_from_slice(&POP_V2.to_le_bytes());
    let state = run_apx(ApxCase {
        r15: Some(POP_R15_SEED),
        rcx: Some(POP_RCX_SEED),
        rsp: Some(DATA_BASE),
        mem_data: Some(&image),
        ..ApxCase::new(&[0x62, 0xf4, 0x04, 0x18, 0x8f, 0xc1], &apx::Pop2R64R64Provider)
    })?;
    assert_pop2_state(&state)
}

#[test]
fn test_apx_pop2p_same_semantics_in_64bit() -> Result<(), BoxError> {
    // pop2p %r15, %rcx — identical semantics to POP2 in 64-bit mode
    let mut image = [0u8; 16];
    image[..8].copy_from_slice(&POP_V1.to_le_bytes());
    image[8..].copy_from_slice(&POP_V2.to_le_bytes());
    let state = run_apx(ApxCase {
        r15: Some(POP_R15_SEED),
        rcx: Some(POP_RCX_SEED),
        rsp: Some(DATA_BASE),
        mem_data: Some(&image),
        ..ApxCase::new(&[0x62, 0xf4, 0x84, 0x18, 0x8f, 0xc1], &apx::Pop2pR64R64Provider)
    })?;
    assert_pop2_state(&state)
}

// ---------------------------------------------------------------------------
// 4. CCMPZ w64
// ---------------------------------------------------------------------------

#[test]
fn test_apx_ccmpz_cond_true_uses_cmp_flags() -> Result<(), BoxError> {
    // ccmpz %rax, %rcx, DFV=0 with seeded ZF=1: RFLAGS := cmp(rax, rcx) flags.
    // cmp(0x1234, 0x1234): ZF=1, PF=1 (even parity of 0x00), CF=SF=OF=AF=0
    // -> 0x44. The seeded AF|CF bits (0x10|0x01) must be cleared.
    let state = run_apx(ApxCase {
        rax: Some(0x1234),
        rcx: Some(0x1234),
        rflags: Some(0x51), // ZF (cond true) | AF | CF
        ..ApxCase::new(&[0x62, 0xf4, 0x84, 0x04, 0x39, 0xc8], &apx::CcmpzR64R64Provider)
    })?;
    assert_eq!(read_gpr(&state, RFLAGS)?, 0x44, "RFLAGS := ZF|PF from cmp");
    Ok(())
}

#[test]
fn test_apx_ccmpz_cond_false_uses_dfv() -> Result<(), BoxError> {
    // ccmpz %rax, %rcx, DFV=8 with seeded ZF=0: condition false, so RFLAGS is
    // the DFV-derived value: CF=DFV bit0=0, ZF=bit1=0, SF=bit2=0, OF=bit3=1,
    // PF=AF=0. Exactly the OF bit set; every seeded corpus flag cleared.
    let state = run_apx(ApxCase {
        rax: Some(0x1234),
        rcx: Some(0x4321),
        rflags: Some(0x95), // CF|PF|AF|SF sentinel, ZF clear -> cond false
        ..ApxCase::new(&[0x62, 0xf4, 0xc4, 0x04, 0x39, 0xc8], &apx::CcmpzR64R64Provider)
    })?;
    assert_eq!(
        read_gpr(&state, RFLAGS)?,
        1 << 11,
        "cond false: RFLAGS = DFV(8) -> exactly OF set, all other flags cleared"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 5. CTESTZ w64
// ---------------------------------------------------------------------------

#[test]
fn test_apx_ctestz_writes_and_flags() -> Result<(), BoxError> {
    // ctestz %rax, %rcx, DFV=0 with seeded ZF=1: RFLAGS ZF/SF/PF from
    // AND(rax, rcx) = 0xFF00 & 0x0FF0 = 0x0F00 -> ZF=0, SF=0, PF=1 (even
    // parity of 0x00); CF=OF=AF=0. Seeded OF|SF|ZF|CF must all be cleared.
    let state = run_apx(ApxCase {
        rax: Some(0x0000_0000_0000_FF00),
        rcx: Some(0x0000_0000_0000_0FF0),
        rflags: Some(0x8C1), // OF|SF|ZF|CF
        ..ApxCase::new(&[0x62, 0xf4, 0x84, 0x04, 0x85, 0xc8], &apx::CtestzR64R64Provider)
    })?;
    assert_eq!(
        read_gpr(&state, RFLAGS)?,
        0x04,
        "RFLAGS := PF from AND, CF=OF=ZF=SF=AF=0"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. NDD ADD (NF / non-NF)
// ---------------------------------------------------------------------------

#[test]
fn test_apx_ndd_add_nf_preserves_flags() -> Result<(), BoxError> {
    // add %r16, %r17, %r9 {NF}: r16 := r17 + r9 with RFLAGS unchanged.
    let decoder = XedDecoder::new();
    let decoded = decoder
        .decode(CODE_BASE, &[0x62, 0x7c, 0xfc, 0x14, 0x01, 0xc9])
        .map_err(|e| format!("decode: {e:?}"))?;
    assert!(
        decoded.is_no_flags(),
        "NF encoding must decode with the NF attribute set"
    );

    let state = run_apx(ApxCase {
        r16: Some(0x0BAD_0000_0000_0000),
        r17: Some(0x1111),
        r9: Some(0x2222),
        rflags: Some(0x1), // CF sentinel
        ..ApxCase::new(&[0x62, 0x7c, 0xfc, 0x14, 0x01, 0xc9], &apx::AddR64R64R64NddProvider)
    })?;
    assert_eq!(read_gpr(&state, R16)?, 0x3333, "r16 := r17 + r9");
    assert_eq!(read_gpr(&state, RFLAGS)?, 0x1, "NF: RFLAGS sentinel preserved");
    Ok(())
}

#[test]
fn test_apx_ndd_add_without_nf_updates_flags() -> Result<(), BoxError> {
    // add %r16, %r17, %r9 without NF: same destination write, but the flags
    // must now be recomputed from the addition. Encoding note: the non-NF
    // sibling of the NF bytes 62 7c fc 14 01 c9 is 62 7c fc 10 01 c9 (EVEX
    // P2 byte 0x10 vs 0x14; the 0x04 variant from the working notes does not
    // decode). Verified via the XED decode: same iclass/operands as the NF
    // form (r16 <-, r17 ->, r9 ->) with the NF attribute clear.
    // add(0x1111, 0x2222) = 0x3333 -> ZF=SF=OF=AF=CF=0, PF=1 -> RFLAGS = 0x04;
    // the seeded CF sentinel must be cleared.
    let decoder = XedDecoder::new();
    let decoded = decoder
        .decode(CODE_BASE, &[0x62, 0x7c, 0xfc, 0x10, 0x01, 0xc9])
        .map_err(|e| format!("decode: {e:?}"))?;
    assert!(
        !decoded.is_no_flags(),
        "non-NF encoding must decode without the NF attribute"
    );

    let state = run_apx(ApxCase {
        r16: Some(0x0BAD_0000_0000_0000),
        r17: Some(0x1111),
        r9: Some(0x2222),
        rflags: Some(0x1), // CF sentinel
        ..ApxCase::new(&[0x62, 0x7c, 0xfc, 0x10, 0x01, 0xc9], &apx::AddR64R64R64NddProvider)
    })?;
    assert_eq!(read_gpr(&state, R16)?, 0x3333, "r16 := r17 + r9");
    assert_eq!(
        read_gpr(&state, RFLAGS)?,
        0x04,
        "non-NF: RFLAGS := PF from add (CF sentinel cleared)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 7. NDD SHL imm8
// ---------------------------------------------------------------------------

#[test]
fn test_apx_ndd_shl_imm8() -> Result<(), BoxError> {
    // shl %r16, %r17, 3: r16 := r17 << 3 (count masked mod 64).
    let state = run_apx(ApxCase {
        r16: Some(0x0BAD_0000_0000_0000),
        r17: Some(0x1234),
        ..ApxCase::new(
            &[0x62, 0xfc, 0xfc, 0x10, 0xc1, 0xe1, 0x03],
            &apx::ShlR64R64Imm8NddProvider,
        )
    })?;
    assert_eq!(read_gpr(&state, R16)?, 0x91A0, "r16 := r17 << 3");
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. CFCMOVZ
// ---------------------------------------------------------------------------

#[test]
fn test_apx_cfcmovz_cond_true_moves_src() -> Result<(), BoxError> {
    // cfcmovz %rdx, %rax with ZF=1: rdx := rax.
    let state = run_apx(ApxCase {
        rdx: Some(0xDEAD),
        rax: Some(0x1234),
        rflags: Some(1 << 6), // ZF set
        ..ApxCase::new(&[0x62, 0xf4, 0xfc, 0x08, 0x44, 0xd0], &apx::CfcmovzR64R64Provider)
    })?;
    assert_eq!(read_gpr(&state, RDX)?, 0x1234, "ZF=1: rdx := rax");
    Ok(())
}

#[test]
fn test_apx_cfcmovz_cond_false_keeps_dst() -> Result<(), BoxError> {
    // cfcmovz %rdx, %rax with ZF=0: rdx unchanged.
    let state = run_apx(ApxCase {
        rdx: Some(0xDEAD),
        rax: Some(0x1234),
        rflags: Some(0x1), // ZF clear
        ..ApxCase::new(&[0x62, 0xf4, 0xfc, 0x08, 0x44, 0xd0], &apx::CfcmovzR64R64Provider)
    })?;
    assert_eq!(read_gpr(&state, RDX)?, 0xDEAD, "ZF=0: rdx unchanged");
    Ok(())
}
