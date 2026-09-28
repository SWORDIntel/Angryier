#![forbid(unsafe_code)]

//! Concrete execution engine tests for BMI1 and BMI2 instruction sets.
//!
//! Covers:
//! - BMI1: ANDN, BEXTR, BLSI, BLSMSK, BLSR
//! - BMI2: BZHI, MULX, RORX, SARX, SHLX, SHRX

use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::{Intel64CorpusRegistry, forms, rflags};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use angryier_types::{
    BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, ObjectId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};

const CODE_BASE: u64 = 0x400000;
const SCRATCH: u64 = 0x500000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(7);

type BoxError = Box<dyn std::error::Error>;
type EngineState = ExecutionState<PersistentRegisters, PersistentMemory>;

const RAX: u32 = register_id::GPR_BASE;
const RCX: u32 = register_id::GPR_BASE + 1;
const RDX: u32 = register_id::GPR_BASE + 2;
const RBX: u32 = register_id::GPR_BASE + 3;
const RSI: u32 = register_id::GPR_BASE + 6;
const RDI: u32 = register_id::GPR_BASE + 7;
const RFLAGS: u32 = register_id::RFLAGS.0;

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

fn create_state(code: &[u8]) -> Result<EngineState, BoxError> {
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
            base: SCRATCH,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;
    let code_bytes: Vec<ByteValue> = code.iter().copied().map(ByteValue::Concrete).collect();
    let memory = memory
        .write(CODE_BASE, &code_bytes)
        .map_err(|e| format!("code load: {e:?}"))?;
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

fn execute_one(code: &[u8], form: u32, state: &EngineState) -> Result<EngineState, BoxError> {
    let decoded = XedDecoder::new()
        .decode(CODE_BASE, code)
        .map_err(|e| format!("decode: {e:?}"))?;
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let provider = registry
        .provider_for_form(form)
        .ok_or_else(|| format!("no provider for form {form:#x}"))?;
    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|e| format!("emit: {e:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|e| format!("seal: {e:?}"))?;
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
    let (after, outcome) = ConcreteInterpreter::new()
        .execute_block(state, &ir_block, ExecutionMode::Concrete)
        .map_err(|e| format!("execute: {e:?}"))?;
    match outcome {
        ExecutionOutcome::Continue { .. } => Ok(after),
        other => Err(format!("unexpected outcome: {other:?}").into()),
    }
}

fn read_reg(state: &EngineState, reg: u32) -> Result<u64, BoxError> {
    let raw = state.registers.read(reg)?;
    Ok(u64::from_le_bytes(raw[..8].try_into()?))
}

fn write_reg(state: &mut EngineState, reg: u32, val: u64) -> Result<(), BoxError> {
    state.registers.write_in_place(reg, &val.to_le_bytes())?;
    Ok(())
}

#[test]
fn test_andn() -> Result<(), BoxError> {
    // andn %edx, %esi, %edi (dest = !src1 & src2)
    // VEX.LZ.0F38.W0 F2 /r: C4 E2 48 F2 FA
    let code_32 = &[0xC4, 0xE2, 0x48, 0xF2, 0xFA];
    let mut state = create_state(code_32)?;
    write_reg(&mut state, RSI, 0b1010_1010)?; // src1
    write_reg(&mut state, RDX, 0b1111_0000)?; // src2
    write_reg(&mut state, RFLAGS, 0x08D5)?; // CF=1, OF=1
    let after = execute_one(code_32, forms::ANDN_R32_R32_R32, &state)?;
    // (!0b1010_1010) & 0b1111_0000 = 0b0101_0101 & 0b1111_0000 = 0b0101_0000 (0x50)
    assert_eq!(read_reg(&after, RDI)?, 0x50);
    let rflags_val = read_reg(&after, RFLAGS)?;
    // CF=0, OF=0, ZF=0, SF=0
    assert_eq!(rflags_val & (1 << rflags::CF_BIT), 0);
    assert_eq!(rflags_val & (1 << rflags::OF_BIT), 0);
    assert_eq!(rflags_val & (1 << rflags::ZF_BIT), 0);

    // 64-bit: andn %rdx, %rsi, %rdi
    // VEX.LZ.0F38.W1 F2 /r: C4 E2 C8 F2 FA
    let code_64 = &[0xC4, 0xE2, 0xC8, 0xF2, 0xFA];
    let mut state64 = create_state(code_64)?;
    write_reg(&mut state64, RSI, 0xFFFF_0000_0000_0000)?;
    write_reg(&mut state64, RDX, 0xFFFF_FFFF_0000_0000)?;
    let after64 = execute_one(code_64, forms::ANDN_R64_R64_R64, &state64)?;
    assert_eq!(read_reg(&after64, RDI)?, 0x0000_FFFF_0000_0000);
    Ok(())
}

#[test]
fn test_bextr() -> Result<(), BoxError> {
    // bextr %edx, %esi, %edi (src=ESI, control=EDX: start=EDX[7:0], len=EDX[15:8])
    // VEX.LZ.0F38.W0 F7 /r: C4 E2 68 F7 FE
    let code_32 = &[0xC4, 0xE2, 0x68, 0xF7, 0xFE];
    let mut state = create_state(code_32)?;
    write_reg(&mut state, RSI, 0x1234_5678)?; // src
    write_reg(&mut state, RDX, 0x0804)?; // start=4, len=8 -> bits 4..12 of 0x1234_5678 -> 0x67
    let after = execute_one(code_32, forms::BEXTR_R32_R32_R32, &state)?;
    assert_eq!(read_reg(&after, RDI)?, 0x67);
    Ok(())
}

#[test]
fn test_blsi_blsmsk_blsr() -> Result<(), BoxError> {
    // blsi %esi, %ecx: dest = (-src) & src (isolates lowest set bit)
    // VEX.LZ.0F38.W0 F3 /3: C4 E2 70 F3 DE (dest=RCX)
    let code_blsi = &[0xC4, 0xE2, 0x70, 0xF3, 0xDE];
    let mut state = create_state(code_blsi)?;
    write_reg(&mut state, RSI, 0x0010_2000)?;
    let after_blsi = execute_one(code_blsi, forms::BLSI_R32_R32, &state)?;
    assert_eq!(read_reg(&after_blsi, RCX)?, 0x0000_2000);
    let rf = read_reg(&after_blsi, RFLAGS)?;
    assert_ne!(rf & (1 << rflags::CF_BIT), 0); // CF = (src != 0)
    assert_eq!(rf & (1 << rflags::ZF_BIT), 0); // ZF = 0

    // blsmsk %esi, %ecx: dest = (src - 1) ^ src (masks lowest set bit and all below)
    // VEX.LZ.0F38.W0 F3 /2: C4 E2 70 F3 D6 (dest=RCX)
    let code_blsmsk = &[0xC4, 0xE2, 0x70, 0xF3, 0xD6];
    let mut state_mask = create_state(code_blsmsk)?;
    write_reg(&mut state_mask, RSI, 0x0010_2000)?;
    let after_mask = execute_one(code_blsmsk, forms::BLSMSK_R32_R32, &state_mask)?;
    assert_eq!(read_reg(&after_mask, RCX)?, 0x0000_3FFF);

    // blsr %esi, %ecx: dest = (src - 1) & src (resets lowest set bit)
    // VEX.LZ.0F38.W0 F3 /1: C4 E2 70 F3 CE (dest=RCX)
    let code_blsr = &[0xC4, 0xE2, 0x70, 0xF3, 0xCE];
    let mut state_blsr = create_state(code_blsr)?;
    write_reg(&mut state_blsr, RSI, 0x0010_2000)?;
    let after_blsr = execute_one(code_blsr, forms::BLSR_R32_R32, &state_blsr)?;
    assert_eq!(read_reg(&after_blsr, RCX)?, 0x0010_0000);
    Ok(())
}

#[test]
fn test_bzhi() -> Result<(), BoxError> {
    // bzhi %edx, %esi, %edi (zero bits above index in EDX)
    // VEX.LZ.0F38.W0 F5 /r: C4 E2 68 F5 FE
    let code_32 = &[0xC4, 0xE2, 0x68, 0xF5, 0xFE];
    let mut state = create_state(code_32)?;
    write_reg(&mut state, RSI, 0xFFFF_FFFF)?;
    write_reg(&mut state, RDX, 12)?; // index = 12 -> mask is (1 << 12) - 1 = 0xFFF
    let after = execute_one(code_32, forms::BZHI_R32_R32_R32, &state)?;
    assert_eq!(read_reg(&after, RDI)?, 0xFFF);
    let rf = read_reg(&after, RFLAGS)?;
    assert_eq!(rf & (1 << rflags::CF_BIT), 0); // index < 32 -> CF=0

    // Test index >= 32
    let mut state_high = create_state(code_32)?;
    write_reg(&mut state_high, RSI, 0x1234_5678)?;
    write_reg(&mut state_high, RDX, 40)?; // index >= 32
    let after_high = execute_one(code_32, forms::BZHI_R32_R32_R32, &state_high)?;
    assert_eq!(read_reg(&after_high, RDI)?, 0x1234_5678);
    let rf_high = read_reg(&after_high, RFLAGS)?;
    assert_ne!(rf_high & (1 << rflags::CF_BIT), 0); // index >= 32 -> CF=1
    Ok(())
}

#[test]
fn test_mulx() -> Result<(), BoxError> {
    // mulx %ecx, %ebx, %eax (EDX * ECX -> EBX:EAX)
    // VEX.LZ.F2.0F38.W0 F6 /r: C4 E2 7B F6 D9 (dest_hi=EBX, dest_lo=EAX, src=ECX, implicit=EDX)
    let code_mulx = &[0xC4, 0xE2, 0x7B, 0xF6, 0xD9];
    let mut state = create_state(code_mulx)?;
    write_reg(&mut state, RDX, 0x1000_0000)?; // EDX
    write_reg(&mut state, RCX, 0x0000_0020)?; // ECX
    write_reg(&mut state, RFLAGS, 0x0246)?; // Seed flags to verify they are unaffected
    let after = execute_one(code_mulx, forms::MULX_R32_R32_R32, &state)?;
    // product = 0x1000_0000 * 0x20 = 0x2_0000_0000
    // dest_hi (EBX) = 2, dest_lo (EAX) = 0
    assert_eq!(read_reg(&after, RBX)?, 2);
    assert_eq!(read_reg(&after, RAX)?, 0);
    assert_eq!(read_reg(&after, RFLAGS)?, 0x0246); // Flags must remain completely unchanged
    Ok(())
}

#[test]
fn test_rorx() -> Result<(), BoxError> {
    // rorx $4, %esi, %edi (EDI = ESI.rotate_right(4))
    // VEX.LZ.F2.0F3A.W0 F0 /r ib: C4 E3 7B F0 FE 04
    let code_rorx = &[0xC4, 0xE3, 0x7B, 0xF0, 0xFE, 0x04];
    let mut state = create_state(code_rorx)?;
    write_reg(&mut state, RSI, 0x1234_5678)?;
    write_reg(&mut state, RFLAGS, 0x0246)?;
    let after = execute_one(code_rorx, forms::RORX_R32_R32_IMM8, &state)?;
    assert_eq!(read_reg(&after, RDI)?, 0x8123_4567);
    assert_eq!(read_reg(&after, RFLAGS)?, 0x0246); // Flags unaffected
    Ok(())
}

#[test]
fn test_shifts_sarx_shlx_shrx() -> Result<(), BoxError> {
    // sarx %edx, %esi, %edi (EDI = ESI.sar(EDX & 31))
    // VEX.LZ.F3.0F38.W0 F7 /r: C4 E2 6A F7 FE
    let code_sarx = &[0xC4, 0xE2, 0x6A, 0xF7, 0xFE];
    let mut state_sarx = create_state(code_sarx)?;
    write_reg(&mut state_sarx, RSI, 0x8000_0000)?;
    write_reg(&mut state_sarx, RDX, 4)?;
    write_reg(&mut state_sarx, RFLAGS, 0x0246)?;
    let after_sarx = execute_one(code_sarx, forms::SARX_R32_R32_R32, &state_sarx)?;
    assert_eq!(read_reg(&after_sarx, RDI)?, 0xF800_0000);
    assert_eq!(read_reg(&after_sarx, RFLAGS)?, 0x0246);

    // shlx %edx, %esi, %edi (EDI = ESI << (EDX & 31))
    // VEX.LZ.66.0F38.W0 F7 /r: C4 E2 69 F7 FE
    let code_shlx = &[0xC4, 0xE2, 0x69, 0xF7, 0xFE];
    let mut state_shlx = create_state(code_shlx)?;
    write_reg(&mut state_shlx, RSI, 0x0000_0001)?;
    write_reg(&mut state_shlx, RDX, 8)?;
    let after_shlx = execute_one(code_shlx, forms::SHLX_R32_R32_R32, &state_shlx)?;
    assert_eq!(read_reg(&after_shlx, RDI)?, 0x0000_0100);

    // shrx %edx, %esi, %edi (EDI = ESI >> (EDX & 31))
    // VEX.LZ.F2.0F38.W0 F7 /r: C4 E2 6B F7 FE
    let code_shrx = &[0xC4, 0xE2, 0x6B, 0xF7, 0xFE];
    let mut state_shrx = create_state(code_shrx)?;
    write_reg(&mut state_shrx, RSI, 0x8000_0000)?;
    write_reg(&mut state_shrx, RDX, 4)?;
    let after_shrx = execute_one(code_shrx, forms::SHRX_R32_R32_R32, &state_shrx)?;
    assert_eq!(read_reg(&after_shrx, RDI)?, 0x0800_0000);
    Ok(())
}
