#![forbid(unsafe_code)]

//! Engine-only coverage for the final census-tail forms.

use angryier_arch_intel64::{Intel64RegisterFile, X87_COUNT, register_id};
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
const SCRATCH: u64 = 0x500000;
const STACK_TOP: u64 = 0x600000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(1);
const RSP: u32 = register_id::GPR_BASE + 4;

type BoxError = Box<dyn std::error::Error>;
type EngineState = ExecutionState<PersistentRegisters, PersistentMemory>;

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
    .map_err(|error| format!("registers: {error:?}"))?;
    let memory = PersistentMemory::new(vec![MemoryRegion {
        object: ObjectId(1),
        base: CODE_BASE,
        size: 0x300000,
        readable: true,
        writable: true,
        executable: true,
    }])?;
    let code_bytes: Vec<ByteValue> = code.iter().copied().map(ByteValue::Concrete).collect();
    let memory = memory.write(CODE_BASE, &code_bytes)?;
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

fn execute(
    code: &[u8],
    form: u32,
    register_seeds: &[(u32, u64)],
    memory_seeds: &[(u64, &[u8])],
) -> Result<EngineState, BoxError> {
    let decoded = XedDecoder::new()
        .decode(CODE_BASE, code)
        .map_err(|error| format!("decode: {error:?}"))?;
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let provider = registry
        .provider_for_form(form)
        .ok_or_else(|| format!("no provider for form {form:#x}"))?;
    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|error| format!("emit: {error:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|error| format!("seal: {error:?}"))?;

    let mut state = create_state(code)?;
    for (register, value) in register_seeds {
        state.registers.write_in_place(*register, &value.to_le_bytes())?;
    }
    for (address, bytes) in memory_seeds {
        let values: Vec<ByteValue> = bytes.iter().copied().map(ByteValue::Concrete).collect();
        state.memory = state.memory.write(*address, &values)?;
    }
    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(1),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))?,
    };
    let ir = BasicSemanticLowerer.lower_with_decode(&sealed, &key, &decoded)?;
    let (state, outcome) = ConcreteInterpreter::new().execute_block(&state, &ir, ExecutionMode::Concrete)?;
    match outcome {
        ExecutionOutcome::Continue { next_pc, .. } => {
            assert_eq!(next_pc, CODE_BASE + u64::from(decoded.length));
        }
        other => return Err(format!("unexpected outcome: {other:?}").into()),
    }
    Ok(state)
}

fn read_u64(state: &EngineState, register: u32) -> Result<u64, BoxError> {
    let bytes = state.registers.read(register)?;
    Ok(u64::from_le_bytes(bytes[..8].try_into()?))
}

fn read_memory(state: &EngineState, address: u64, len: usize) -> Result<Vec<u8>, BoxError> {
    state
        .memory
        .read(address, len)?
        .iter()
        .map(|byte| match byte {
            ByteValue::Concrete(value) => Ok(*value),
            ByteValue::Symbolic(_) => Err("unexpected symbolic byte".into()),
        })
        .collect()
}

#[test]
fn segment_moves_and_iretd_execute() -> Result<(), BoxError> {
    let rax = register_id::GPR_BASE;
    let state = execute(&[0x48, 0x8c, 0xd0], forms::MOV_R64_SREG, &[(rax, u64::MAX)], &[])?;
    assert_eq!(read_u64(&state, rax)?, 0);

    let seed = 0x1122_3344_5566_7788;
    let state = execute(&[0x66, 0x8c, 0xd0], forms::MOV_R16_SREG, &[(rax, seed)], &[])?;
    assert_eq!(read_u64(&state, rax)?, seed & !0xffff);

    let state = execute(&[0x8c, 0xd0], forms::MOV_R32_SREG, &[(rax, seed)], &[])?;
    assert_eq!(read_u64(&state, rax)?, 0);

    let state = execute(&[0x8e, 0xd0], forms::MOV_SREG_R16, &[(rax, seed)], &[])?;
    assert_eq!(read_u64(&state, rax)?, seed);

    let rcx = register_id::GPR_BASE + 1;
    let state = execute(
        &[0x8c, 0x11],
        forms::MOV_MEM16_SREG,
        &[(rcx, SCRATCH)],
        &[(SCRATCH, &[0xaa, 0xbb])],
    )?;
    assert_eq!(read_memory(&state, SCRATCH, 2)?, vec![0, 0]);

    let state = execute(&[0xcf], forms::IRETD, &[], &[])?;
    assert_eq!(read_u64(&state, register_id::RFLAGS.0)?, 0);
    Ok(())
}

#[test]
fn stack_exchange_and_rotate_forms_execute() -> Result<(), BoxError> {
    let rdx = register_id::GPR_BASE + 2;
    let state = execute(&[0x66, 0x52], forms::PUSH_R16, &[(rdx, 0x1122), (RSP, STACK_TOP)], &[])?;
    assert_eq!(read_u64(&state, RSP)?, STACK_TOP - 2);
    assert_eq!(read_memory(&state, STACK_TOP - 2, 2)?, vec![0x22, 0x11]);

    let rcx = register_id::GPR_BASE + 1;
    let popped = 0x8877_6655_4433_2211u64;
    let state = execute(
        &[0x8f, 0x01],
        forms::POP_MEM64,
        &[(rcx, SCRATCH), (RSP, STACK_TOP)],
        &[(STACK_TOP, &popped.to_le_bytes())],
    )?;
    assert_eq!(read_u64(&state, RSP)?, STACK_TOP + 8);
    assert_eq!(read_memory(&state, SCRATCH, 8)?, popped.to_le_bytes());

    let rbp = register_id::GPR_BASE + 5;
    let rsi = register_id::GPR_BASE + 6;
    let state = execute(&[0x40, 0x86, 0xf5], forms::XCHG_R8_R8, &[(rbp, 0x11), (rsi, 0x22)], &[])?;
    assert_eq!(read_u64(&state, rbp)? & 0xff, 0x22);
    assert_eq!(read_u64(&state, rsi)? & 0xff, 0x11);

    let rbx = register_id::GPR_BASE + 3;
    let state = execute(&[0xd0, 0xcb], forms::ROR_R8_IMM8, &[(rbx, 0x81)], &[])?;
    assert_eq!(read_u64(&state, rbx)? & 0xff, 0xc0);

    let flags = 0x8d5;
    let state = execute(
        &[0xc0, 0xde, 0x00],
        forms::RCR_R8_IMM8,
        &[(rdx, 0x8100), (register_id::RFLAGS.0, flags)],
        &[],
    )?;
    assert_eq!(read_u64(&state, rdx)?, 0x8100);
    assert_eq!(read_u64(&state, register_id::RFLAGS.0)?, flags);
    Ok(())
}

#[test]
fn fld_m80_preserves_low_payload_bits() -> Result<(), BoxError> {
    let rcx = register_id::GPR_BASE + 1;
    let source = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x34, 0x12];
    let mut state = create_state(&[0xdb, 0x29])?;
    state.registers.write_in_place(rcx, &SCRATCH.to_le_bytes())?;
    for index in 0..X87_COUNT {
        let mut empty = [0u8; 10];
        empty[8..].copy_from_slice(&u16::MAX.to_le_bytes());
        state
            .registers
            .write_in_place(register_id::X87_BASE + u32::from(index), &empty)?;
    }
    let source_bytes: Vec<ByteValue> = source.iter().copied().map(ByteValue::Concrete).collect();
    state.memory = state.memory.write(SCRATCH, &source_bytes)?;

    let decoded = XedDecoder::new().decode(CODE_BASE, &[0xdb, 0x29])?;
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let provider = registry
        .provider_for_form(forms::FLD_M80)
        .ok_or("missing FLD m80 provider")?;
    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|error| format!("emit: {error:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|error| format!("seal: {error:?}"))?;
    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(1),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))?,
    };
    let ir = BasicSemanticLowerer.lower_with_decode(&sealed, &key, &decoded)?;
    let (state, outcome) = ConcreteInterpreter::new().execute_block(&state, &ir, ExecutionMode::Concrete)?;
    assert!(matches!(outcome, ExecutionOutcome::Continue { .. }));
    let st0 = state.registers.read(register_id::X87_BASE)?;
    assert_eq!(&st0[..8], &source[..8]);
    assert_eq!(&st0[8..10], &[0, 0]);
    Ok(())
}
