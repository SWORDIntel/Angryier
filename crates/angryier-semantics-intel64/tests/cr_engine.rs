#![forbid(unsafe_code)]

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

fn execute(
    code: &[u8],
    form: u32,
    rax: u64,
    rflags: u64,
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
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
        size: 0x1000,
        readable: true,
        writable: true,
        executable: true,
    }])?;
    let code_bytes: Vec<ByteValue> = code.iter().copied().map(ByteValue::Concrete).collect();
    let memory = memory.write(CODE_BASE, &code_bytes)?;
    let mut state = ExecutionState {
        id: StateId(1),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    };
    state
        .registers
        .write_in_place(register_id::GPR_BASE, &rax.to_le_bytes())?;
    state
        .registers
        .write_in_place(register_id::RFLAGS.0, &rflags.to_le_bytes())?;

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
    Ok(state)
}

fn read_u64(state: &ExecutionState<PersistentRegisters, PersistentMemory>, register: u32) -> Result<u64, BoxError> {
    let bytes = state.registers.read(register)?;
    let array: [u8; 8] = bytes[..8].try_into()?;
    Ok(u64::from_le_bytes(array))
}

#[test]
fn control_and_debug_moves_execute() -> Result<(), BoxError> {
    // REX.R selects CR8; the ModRM r/m field selects RAX.
    let state = execute(&[0x44, 0x0f, 0x20, 0xc0], forms::MOV_R64_CR, u64::MAX, 0x202)?;
    assert_eq!(read_u64(&state, register_id::GPR_BASE)?, 0);

    let state = execute(&[0x0f, 0x20, 0xc0], forms::MOV_R64_CR, 0, 0x202)?;
    assert_eq!(read_u64(&state, register_id::GPR_BASE)?, 0x8001_0033);

    let state = execute(&[0x0f, 0x22, 0xc0], forms::MOV_CR_R64, 0x1234, 0x8d5)?;
    assert_eq!(read_u64(&state, register_id::RFLAGS.0)?, 0x8d5);

    let state = execute(&[0x0f, 0x21, 0xc0], forms::MOV_R64_DR, u64::MAX, 0x202)?;
    assert_eq!(read_u64(&state, register_id::GPR_BASE)?, 0);
    Ok(())
}
