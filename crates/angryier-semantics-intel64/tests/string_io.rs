#![forbid(unsafe_code)]

//! Tests for string port I/O and immediate-port I/O instruction forms:
//! INSB / INSW / INSD, OUTSB / OUTSW / OUTSD,
//! IN AL/AX/EAX imm8, and OUT imm8 AL/AX/EAX.
//!
//! Validates engine-side execution:
//! decode -> provider_for_form -> emit -> seal -> lower_with_decode -> execute_block.

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
const DATA_BASE: u64 = 0x500000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(1);

const RAX: u32 = register_id::GPR_BASE;
const RDX: u32 = register_id::GPR_BASE + 2;
const RSI: u32 = register_id::GPR_BASE + 6;
const RDI: u32 = register_id::GPR_BASE + 7;
const RFLAGS: u32 = register_id::RFLAGS.0;

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
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;

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

fn run_single_instruction(
    code: &[u8],
    form_id: u32,
    configure: impl FnOnce(
        ExecutionState<PersistentRegisters, PersistentMemory>,
    ) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError>,
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

    let initial_state = create_state(code)?;
    let state = configure(initial_state)?;

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

fn read_reg_u64(state: &ExecutionState<PersistentRegisters, PersistentMemory>, reg: u32) -> Result<u64, BoxError> {
    let bytes = state.registers.read(reg).map_err(|e| format!("read reg: {e:?}"))?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Ok(u64::from_le_bytes(buf))
}

fn write_reg_u64(
    mut state: ExecutionState<PersistentRegisters, PersistentMemory>,
    reg: u32,
    val: u64,
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    state.registers = state
        .registers
        .write(reg, &val.to_le_bytes())
        .map_err(|e| format!("write reg: {e:?}"))?;
    Ok(state)
}

// ---------------------------------------------------------------------------
// Immediate Port I/O Tests
// ---------------------------------------------------------------------------

#[test]
fn test_in_al_imm8() -> Result<(), BoxError> {
    // IN AL, 0x10 -> opcode E4 10
    let code = [0xE4, 0x10];
    let state = run_single_instruction(&code, forms::IN_AL_IMM8, |s| {
        // Seed RAX with non-zero
        write_reg_u64(s, RAX, 0x1234_5678_9ABC_DEFF)
    })?;
    let rax = read_reg_u64(&state, RAX)?;
    // AL (low byte) must be 0; upper bytes preserved
    assert_eq!(rax & 0xFF, 0, "AL should be zeroed");
    assert_eq!(rax & !0xFF, 0x1234_5678_9ABC_DE00, "upper bytes preserved");
    Ok(())
}

#[test]
fn test_in_ax_imm8() -> Result<(), BoxError> {
    // IN AX, 0x10 -> opcode 66 E5 10
    let code = [0x66, 0xE5, 0x10];
    let state = run_single_instruction(&code, forms::IN_AX_IMM8, |s| {
        write_reg_u64(s, RAX, 0x1234_5678_9ABC_FFFF)
    })?;
    let rax = read_reg_u64(&state, RAX)?;
    // AX (low 16 bits) must be 0; upper bytes preserved
    assert_eq!(rax & 0xFFFF, 0, "AX should be zeroed");
    assert_eq!(rax & !0xFFFF, 0x1234_5678_9ABC_0000, "upper bytes preserved");
    Ok(())
}

#[test]
fn test_in_eax_imm8() -> Result<(), BoxError> {
    // IN EAX, 0x10 -> opcode E5 10
    let code = [0xE5, 0x10];
    let state = run_single_instruction(&code, forms::IN_EAX_IMM8, |s| {
        write_reg_u64(s, RAX, 0xFFFF_FFFF_FFFF_FFFF)
    })?;
    let rax = read_reg_u64(&state, RAX)?;
    // 32-bit register write zero-extends into 64-bit parent
    assert_eq!(rax, 0, "EAX zero-extends into RAX");
    Ok(())
}

#[test]
fn test_out_imm8_al() -> Result<(), BoxError> {
    // OUT 0x10, AL -> opcode E6 10
    let code = [0xE6, 0x10];
    let state = run_single_instruction(&code, forms::OUT_IMM8_AL, |s| write_reg_u64(s, RAX, 0x42))?;
    // Value dropped, RAX unchanged
    assert_eq!(read_reg_u64(&state, RAX)?, 0x42);
    Ok(())
}

#[test]
fn test_out_imm8_ax() -> Result<(), BoxError> {
    // OUT 0x10, AX -> opcode 66 E7 10
    let code = [0x66, 0xE7, 0x10];
    let state = run_single_instruction(&code, forms::OUT_IMM8_AX, |s| write_reg_u64(s, RAX, 0x1234))?;
    assert_eq!(read_reg_u64(&state, RAX)?, 0x1234);
    Ok(())
}

#[test]
fn test_out_imm8_eax() -> Result<(), BoxError> {
    // OUT 0x10, EAX -> opcode E7 10
    let code = [0xE7, 0x10];
    let state = run_single_instruction(&code, forms::OUT_IMM8_EAX, |s| write_reg_u64(s, RAX, 0x1234_5678))?;
    assert_eq!(read_reg_u64(&state, RAX)?, 0x1234_5678);
    Ok(())
}

// ---------------------------------------------------------------------------
// String Port I/O Tests (INSB, INSW, INSD, OUTSB, OUTSW, OUTSD)
// ---------------------------------------------------------------------------

#[test]
fn test_insb_forward() -> Result<(), BoxError> {
    // INSB -> opcode 6C
    let code = [0x6C];
    let rdi_init = DATA_BASE + 0x10;
    let state = run_single_instruction(&code, forms::INSB, |mut s| {
        s.memory = s
            .memory
            .write(rdi_init, &[ByteValue::Concrete(0xAA)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RDI, rdi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 0) // DF = 0
    })?;

    // RDI should advance by 1
    assert_eq!(read_reg_u64(&state, RDI)?, rdi_init + 1, "RDI must advance by 1");
    // Memory at rdi_init must be 0
    let mut buf = [ByteValue::Concrete(0xFF)];
    state
        .memory
        .read_into(rdi_init, &mut buf)
        .map_err(|e| format!("read mem: {e:?}"))?;
    assert_eq!(buf[0], ByteValue::Concrete(0), "[RDI] must be zeroed");
    Ok(())
}

#[test]
fn test_insb_backward() -> Result<(), BoxError> {
    // INSB -> opcode 6C with DF = 1
    let code = [0x6C];
    let rdi_init = DATA_BASE + 0x10;
    let state = run_single_instruction(&code, forms::INSB, |mut s| {
        s.memory = s
            .memory
            .write(rdi_init, &[ByteValue::Concrete(0xBB)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RDI, rdi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 1 << rflags::DF_BIT) // DF = 1
    })?;

    // RDI should decrement by 1
    assert_eq!(
        read_reg_u64(&state, RDI)?,
        rdi_init - 1,
        "RDI must decrement by 1 with DF=1"
    );
    let mut buf = [ByteValue::Concrete(0xFF)];
    state
        .memory
        .read_into(rdi_init, &mut buf)
        .map_err(|e| format!("read mem: {e:?}"))?;
    assert_eq!(buf[0], ByteValue::Concrete(0), "[RDI] must be zeroed");
    Ok(())
}

#[test]
fn test_insw_forward() -> Result<(), BoxError> {
    // INSW -> opcode 66 6D
    let code = [0x66, 0x6D];
    let rdi_init = DATA_BASE + 0x20;
    let state = run_single_instruction(&code, forms::INSW, |mut s| {
        s.memory = s
            .memory
            .write(rdi_init, &[ByteValue::Concrete(0x11), ByteValue::Concrete(0x22)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RDI, rdi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 0)
    })?;

    assert_eq!(read_reg_u64(&state, RDI)?, rdi_init + 2, "RDI must advance by 2");
    let mut buf = [ByteValue::Concrete(0xFF); 2];
    state
        .memory
        .read_into(rdi_init, &mut buf)
        .map_err(|e| format!("read mem: {e:?}"))?;
    assert_eq!(
        buf,
        [ByteValue::Concrete(0), ByteValue::Concrete(0)],
        "[RDI] 2 bytes zeroed"
    );
    Ok(())
}

#[test]
fn test_insw_backward() -> Result<(), BoxError> {
    // INSW -> opcode 66 6D with DF = 1
    let code = [0x66, 0x6D];
    let rdi_init = DATA_BASE + 0x20;
    let state = run_single_instruction(&code, forms::INSW, |mut s| {
        s.memory = s
            .memory
            .write(rdi_init, &[ByteValue::Concrete(0x11), ByteValue::Concrete(0x22)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RDI, rdi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 1 << rflags::DF_BIT)
    })?;

    assert_eq!(
        read_reg_u64(&state, RDI)?,
        rdi_init - 2,
        "RDI must decrement by 2 with DF=1"
    );
    let mut buf = [ByteValue::Concrete(0xFF); 2];
    state
        .memory
        .read_into(rdi_init, &mut buf)
        .map_err(|e| format!("read mem: {e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0), ByteValue::Concrete(0)]);
    Ok(())
}

#[test]
fn test_insd_forward() -> Result<(), BoxError> {
    // INSD -> opcode 6D
    let code = [0x6D];
    let rdi_init = DATA_BASE + 0x30;
    let state = run_single_instruction(&code, forms::INSD, |mut s| {
        s.memory = s
            .memory
            .write(rdi_init, &[ByteValue::Concrete(0xFF); 4])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RDI, rdi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 0)
    })?;

    assert_eq!(read_reg_u64(&state, RDI)?, rdi_init + 4, "RDI must advance by 4");
    let mut buf = [ByteValue::Concrete(0xFF); 4];
    state
        .memory
        .read_into(rdi_init, &mut buf)
        .map_err(|e| format!("read mem: {e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0); 4], "[RDI] 4 bytes zeroed");
    Ok(())
}

#[test]
fn test_insd_backward() -> Result<(), BoxError> {
    // INSD -> opcode 6D with DF = 1
    let code = [0x6D];
    let rdi_init = DATA_BASE + 0x30;
    let state = run_single_instruction(&code, forms::INSD, |mut s| {
        s.memory = s
            .memory
            .write(rdi_init, &[ByteValue::Concrete(0xFF); 4])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RDI, rdi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 1 << rflags::DF_BIT)
    })?;

    assert_eq!(
        read_reg_u64(&state, RDI)?,
        rdi_init - 4,
        "RDI must decrement by 4 with DF=1"
    );
    let mut buf = [ByteValue::Concrete(0xFF); 4];
    state
        .memory
        .read_into(rdi_init, &mut buf)
        .map_err(|e| format!("read mem: {e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0); 4]);
    Ok(())
}

#[test]
fn test_outsb_forward() -> Result<(), BoxError> {
    // OUTSB -> opcode 6E
    let code = [0x6E];
    let rsi_init = DATA_BASE + 0x40;
    let state = run_single_instruction(&code, forms::OUTSB, |mut s| {
        s.memory = s
            .memory
            .write(rsi_init, &[ByteValue::Concrete(0x55)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RSI, rsi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 0)
    })?;

    assert_eq!(read_reg_u64(&state, RSI)?, rsi_init + 1, "RSI must advance by 1");
    Ok(())
}

#[test]
fn test_outsb_backward() -> Result<(), BoxError> {
    // OUTSB -> opcode 6E with DF = 1
    let code = [0x6E];
    let rsi_init = DATA_BASE + 0x40;
    let state = run_single_instruction(&code, forms::OUTSB, |mut s| {
        s.memory = s
            .memory
            .write(rsi_init, &[ByteValue::Concrete(0x55)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RSI, rsi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 1 << rflags::DF_BIT)
    })?;

    assert_eq!(
        read_reg_u64(&state, RSI)?,
        rsi_init - 1,
        "RSI must decrement by 1 with DF=1"
    );
    Ok(())
}

#[test]
fn test_outsw_forward() -> Result<(), BoxError> {
    // OUTSW -> opcode 66 6F
    let code = [0x66, 0x6F];
    let rsi_init = DATA_BASE + 0x50;
    let state = run_single_instruction(&code, forms::OUTSW, |mut s| {
        s.memory = s
            .memory
            .write(rsi_init, &[ByteValue::Concrete(0x55), ByteValue::Concrete(0x66)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RSI, rsi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 0)
    })?;

    assert_eq!(read_reg_u64(&state, RSI)?, rsi_init + 2, "RSI must advance by 2");
    Ok(())
}

#[test]
fn test_outsw_backward() -> Result<(), BoxError> {
    // OUTSW -> opcode 66 6F with DF = 1
    let code = [0x66, 0x6F];
    let rsi_init = DATA_BASE + 0x50;
    let state = run_single_instruction(&code, forms::OUTSW, |mut s| {
        s.memory = s
            .memory
            .write(rsi_init, &[ByteValue::Concrete(0x55), ByteValue::Concrete(0x66)])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RSI, rsi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 1 << rflags::DF_BIT)
    })?;

    assert_eq!(
        read_reg_u64(&state, RSI)?,
        rsi_init - 2,
        "RSI must decrement by 2 with DF=1"
    );
    Ok(())
}

#[test]
fn test_outsd_forward() -> Result<(), BoxError> {
    // OUTSD -> opcode 6F
    let code = [0x6F];
    let rsi_init = DATA_BASE + 0x60;
    let state = run_single_instruction(&code, forms::OUTSD, |mut s| {
        s.memory = s
            .memory
            .write(rsi_init, &[ByteValue::Concrete(0x77); 4])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RSI, rsi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 0)
    })?;

    assert_eq!(read_reg_u64(&state, RSI)?, rsi_init + 4, "RSI must advance by 4");
    Ok(())
}

#[test]
fn test_outsd_backward() -> Result<(), BoxError> {
    // OUTSD -> opcode 6F with DF = 1
    let code = [0x6F];
    let rsi_init = DATA_BASE + 0x60;
    let state = run_single_instruction(&code, forms::OUTSD, |mut s| {
        s.memory = s
            .memory
            .write(rsi_init, &[ByteValue::Concrete(0x77); 4])
            .map_err(|e| format!("seed mem: {e:?}"))?;
        s = write_reg_u64(s, RSI, rsi_init)?;
        s = write_reg_u64(s, RDX, 0x80)?;
        write_reg_u64(s, RFLAGS, 1 << rflags::DF_BIT)
    })?;

    assert_eq!(
        read_reg_u64(&state, RSI)?,
        rsi_init - 4,
        "RSI must decrement by 4 with DF=1"
    );
    Ok(())
}
