#![forbid(unsafe_code)]

//! End-to-end integration tests: decode -> provider -> seal -> lower -> execute.
//!
//! These tests exercise the full Phase 4 pipeline for the handwritten corpus,
//! verifying that semantic blocks produced by the corpus providers can be
//! lowered to AngryIR and executed by the concrete interpreter.

use angryier_arch::{
    AccessKind, DecodedInstruction, InstructionModifiers, Operand, OperandKind, OperandVisibility, RegisterId,
    RegisterView, RelativeBranchOperand,
};
use angryier_arch_intel64::register_id;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{MemoryError, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, SemanticRegistry, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterError, RegisterState,
    StateOwnership,
};
use angryier_types::{BlockId, FidelityProfile, ImageId, ObjectId, SemanticVersion, StateId, TargetProfileId};

// Intel 64 GPRs are indexed from GPR_BASE. RAX=0, RCX=1, RDX=2, RBX=3, etc.
const RAX: u32 = register_id::GPR_BASE;
const RCX: u32 = register_id::GPR_BASE + 1;
const RFLAGS: u32 = register_id::RFLAGS.0;

type TestError = angryier_execution::ConcreteExecutionError<RegisterError, MemoryError>;

const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(3);
const BLOCK_ADDR: u64 = 0x1000;

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

fn reg_operand(index: u8, reg: u32, access: AccessKind) -> Operand {
    Operand {
        index,
        width_bits: 64,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(RegisterView::full(RegisterId(reg), 64)),
    }
}

fn rel32_operand(index: u8, displacement: i64) -> Operand {
    Operand {
        index,
        width_bits: 32,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::RelativeBranch(RelativeBranchOperand {
            displacement,
            displacement_width_bits: 32,
        }),
    }
}

fn imm_operand(index: u8, value: u64, width: u16) -> Operand {
    Operand {
        index,
        width_bits: width,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Immediate(angryier_arch::ImmediateOperand { value, signed: false }),
    }
}

fn make_decoded(form: u32, operands: Vec<Operand>) -> DecodedInstruction {
    DecodedInstruction {
        address: BLOCK_ADDR,
        length: 3,
        form_id: form,
        features: vec![],
        operands,
        modifiers: InstructionModifiers::default(),
    }
}

fn validity_key(decoded: &DecodedInstruction, memory: &PersistentMemory) -> Result<BlockValidityKey, MemoryError> {
    Ok(BlockValidityKey {
        image: ImageId(1),
        block: BlockId(2),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: memory.code_version_guards_for_range(BLOCK_ADDR, 1)?,
    })
}

fn make_state() -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, Box<dyn std::error::Error>> {
    let memory = PersistentMemory::new(vec![
        MemoryRegion {
            object: ObjectId(1),
            base: 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: true,
        },
        MemoryRegion {
            object: ObjectId(2),
            base: 0x3000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;
    Ok(ExecutionState {
        id: StateId(7),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers: PersistentRegisters::from_widths([(RAX, 8), (RCX, 8), (RFLAGS, 8)])?,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    })
}

/// Returns a new state with the given register set to `value`.
fn with_reg(
    state: &ExecutionState<PersistentRegisters, PersistentMemory>,
    reg: u32,
    value: u64,
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, Box<dyn std::error::Error>> {
    Ok(ExecutionState {
        id: state.id,
        parent: state.parent,
        target_profile: state.target_profile,
        registers: state.registers.write(reg, &value.to_le_bytes())?,
        memory: state.memory.clone(),
        constraints: state.constraints.clone(),
        ownership: state.ownership,
        fidelity: state.fidelity.clone(),
    })
}

fn read_reg(
    state: &ExecutionState<PersistentRegisters, PersistentMemory>,
    reg: u32,
) -> Result<u64, Box<dyn std::error::Error>> {
    let bytes = state.registers.read(reg)?;
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(buffer))
}

/// Full pipeline: decode -> provider emit -> seal -> lower -> execute.
fn run_pipeline(
    decoded: &DecodedInstruction,
    initial: &ExecutionState<PersistentRegisters, PersistentMemory>,
) -> Result<(ExecutionState<PersistentRegisters, PersistentMemory>, ExecutionOutcome), TestError> {
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let resolution = registry
        .resolve(decoded, SEMANTIC_VERSION)
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;

    let provider = registry
        .providers()
        .iter()
        .find(|p| p.rule_id() == resolution.rule_id)
        .ok_or(angryier_execution::ConcreteExecutionError::TypeMismatch)?;

    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    let ctx = context();
    provider
        .emit(&ctx, decoded, &mut builder)
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let sealed = builder
        .seal(
            angryier_types::ContentIdentitySchemaVersion(1),
            angryier_types::SemanticFingerprintSchemaVersion(1),
        )
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let key = validity_key(decoded, &initial.memory)
        .map_err(|_| angryier_execution::ConcreteExecutionError::InvalidAddress)?;
    let lowerer = BasicSemanticLowerer;
    let ir_block = lowerer
        .lower_with_decode(&sealed, &key, decoded)
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let interpreter = ConcreteInterpreter::new();
    interpreter.execute_block(initial, &ir_block, ExecutionMode::Concrete)
}

const ZF_BIT: u64 = 1 << 6;
const SF_BIT: u64 = 1 << 7;
const CF_BIT: u64 = 1 << 0;

#[test]
fn mov_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RCX, 0xDEADBEEF)?;

    let decoded = make_decoded(
        forms::MOV_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xDEADBEEF);
    assert_eq!(read_reg(&executed, RCX)?, 0xDEADBEEF);
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn add_r64_r64_executes_and_sets_flags() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 10)?, RCX, 32)?, RFLAGS, 0)?;

    let decoded = make_decoded(
        forms::ADD_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 42);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear");
    assert_eq!(rflags & SF_BIT, 0, "SF should be clear");
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn add_r64_r64_sets_zf_on_zero_result() -> Result<(), Box<dyn std::error::Error>> {
    // u64::MAX + 1 = 0 (wrapping), with carry
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, u64::MAX)?, RCX, 1)?, RFLAGS, 0)?;

    let decoded = make_decoded(
        forms::ADD_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & ZF_BIT, 0, "ZF should be set");
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (carry out)");
    Ok(())
}

#[test]
fn add_r64_r64_sets_cf_on_carry() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, u64::MAX)?, RCX, 1)?, RFLAGS, 0)?;

    let decoded = make_decoded(
        forms::ADD_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set");
    Ok(())
}

#[test]
fn sub_r64_r64_executes_and_sets_borrow() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 5)?, RCX, 10)?, RFLAGS, 0)?;

    let decoded = make_decoded(
        forms::SUB_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, (-5i64 as u64));
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF (borrow) should be set");
    assert_ne!(rflags & SF_BIT, 0, "SF should be set");
    Ok(())
}

#[test]
fn xor_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0xFF00)?, RCX, 0x0FF0)?;

    let decoded = make_decoded(
        forms::XOR_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xF0F0);
    Ok(())
}

#[test]
fn and_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0xFF00)?, RCX, 0xF0F0)?;

    let decoded = make_decoded(
        forms::AND_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xF000);
    Ok(())
}

#[test]
fn or_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0xFF00)?, RCX, 0x0FF0)?;

    let decoded = make_decoded(
        forms::OR_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xFFF0);
    Ok(())
}

#[test]
fn cmp_r64_r64_does_not_write_register() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 10)?, RCX, 10)?, RFLAGS, 0)?;

    let decoded = make_decoded(
        forms::CMP_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Read),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 10, "RAX should be unchanged by CMP");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & ZF_BIT, 0, "ZF should be set (10 - 10 == 0)");
    Ok(())
}

#[test]
fn jmp_rel32_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = make_state()?;
    let decoded = make_decoded(forms::JMP_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3 + 0x100,
        }
    );
    Ok(())
}

#[test]
fn jz_rel32_taken_when_zf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, ZF_BIT)?;
    let decoded = make_decoded(forms::JZ_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3 + 0x100,
        }
    );
    Ok(())
}

#[test]
fn jz_rel32_not_taken_when_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::JZ_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn jnz_rel32_taken_when_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::JNZ_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3 + 0x100,
        }
    );
    Ok(())
}

#[test]
fn jnz_rel32_not_taken_when_zf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, ZF_BIT)?;
    let decoded = make_decoded(forms::JNZ_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn mov_r64_imm64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = make_state()?;
    let decoded = make_decoded(
        forms::MOV_R64_IMM64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            imm_operand(1, 0xDEADBEEFCAFEBABE, 64),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xDEADBEEFCAFEBABE);
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn add_r64_imm32_sign_extends_and_adds() -> Result<(), Box<dyn std::error::Error>> {
    // imm32 = 0xFFFFFFFF sign-extends to -1 as i64; 10 + (-1) = 9 (with carry out)
    let initial = with_reg(&with_reg(&make_state()?, RAX, 10)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::ADD_R64_IMM32,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            imm_operand(1, 0xFFFFFFFF, 32),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 9);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear");
    assert_ne!(
        rflags & CF_BIT,
        0,
        "CF should be set (carry out from unsigned addition)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn shl_r64_cl_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0x1)?, RCX, 4)?;
    let decoded = make_decoded(forms::SHL_R64_CL, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x10);
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn neg_r64_executes_and_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 5)?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::NEG_R64, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, (-5i64 as u64));
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (operand != 0)");
    assert_ne!(rflags & SF_BIT, 0, "SF should be set (negative result)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn neg_r64_zero_does_not_set_cf() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0)?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::NEG_R64, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (operand == 0)");
    assert_ne!(rflags & ZF_BIT, 0, "ZF should be set (result == 0)");
    Ok(())
}

#[test]
fn not_r64_executes_no_flags() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0x0F0F0F0F0F0F0F0F)?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::NOT_R64, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xF0F0F0F0F0F0F0F0);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags, 0, "NOT should not modify any flags");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn jc_rel32_taken_when_cf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(forms::JC_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3 + 0x100,
        }
    );
    Ok(())
}

#[test]
fn jc_rel32_not_taken_when_cf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::JC_REL32, vec![rel32_operand(0, 0x100)]);

    let (_, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn nop_executes_and_falls_through() -> Result<(), Box<dyn std::error::Error>> {
    let initial = make_state()?;
    let decoded = make_decoded(forms::NOP, vec![]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    // NOP should not modify any registers
    assert_eq!(read_reg(&executed, RAX)?, 0);
    assert_eq!(read_reg(&executed, RFLAGS)?, 0);
    Ok(())
}

#[test]
fn inc_r64_preserves_cf() -> Result<(), Box<dyn std::error::Error>> {
    // Start with CF set; INC should preserve it
    let initial = with_reg(&with_reg(&make_state()?, RAX, 5)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(forms::INC_R64, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 6);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be preserved (still set)");
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn dec_r64_sets_zf_on_zero() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&make_state()?, RAX, 1)?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::DEC_R64, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0);
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & ZF_BIT, 0, "ZF should be set (result == 0)");
    Ok(())
}

#[test]
fn bt_r64_r64_sets_cf_from_bit() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1000 (bit 3 set), RCX = 3 -> CF should be 1
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1000)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::BT_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::Read), imm_operand(1, 3, 64)],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    // BT does not modify operand 0
    assert_eq!(read_reg(&executed, RAX)?, 0b1000, "BT should not modify RAX");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (bit 3 of 0b1000 is 1)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn bt_r64_r64_clears_cf_when_bit_zero() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1000 (bit 1 clear), RCX = 1 -> CF should be 0
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1000)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::BT_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::Read), imm_operand(1, 1, 64)],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0b1000, "BT should not modify RAX");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (bit 1 of 0b1000 is 0)");
    Ok(())
}

#[test]
fn bts_r64_r64_sets_bit_and_cf() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1000 (bit 3 set), RCX = 1 -> CF=0, then set bit 1 -> RAX = 0b1010
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1000)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::BTS_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite), imm_operand(1, 1, 64)],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0b1010, "BTS should set bit 1");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (bit 1 was 0)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn bts_r64_r64_preserves_already_set_bit() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1000 (bit 3 set), RCX = 3 -> CF=1, bit already set -> RAX unchanged
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1000)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::BTS_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite), imm_operand(1, 3, 64)],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0b1000, "BTS should keep bit 3 set");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (bit 3 was 1)");
    Ok(())
}

#[test]
fn btr_r64_r64_clears_bit_and_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1010 (bits 1 and 3 set), RCX = 1 -> CF=1, then clear bit 1 -> RAX = 0b1000
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1010)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::BTR_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite), imm_operand(1, 1, 64)],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0b1000, "BTR should clear bit 1");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (bit 1 was 1)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn btr_r64_r64_clears_cf_when_bit_already_zero() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1000 (bit 1 clear), RCX = 1 -> CF=0, bit already clear -> RAX unchanged
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1000)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::BTR_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite), imm_operand(1, 1, 64)],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0b1000, "BTR should keep bit 1 clear");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (bit 1 was 0)");
    Ok(())
}

#[test]
fn btc_r64_r64_complements_bit_and_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1000 (bit 3 set, bit 1 clear), RCX = 1 -> CF=0, complement bit 1 -> RAX = 0b1010
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1000)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::BTC_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite), imm_operand(1, 1, 64)],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0b1010, "BTC should complement bit 1");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (bit 1 was 0)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn btc_r64_r64_complements_set_bit_and_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 0b1010 (bit 1 set), RCX = 1 -> CF=1, complement bit 1 -> RAX = 0b1000
    let initial = with_reg(&with_reg(&make_state()?, RAX, 0b1010)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::BTC_R64_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite), imm_operand(1, 1, 64)],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0b1000,
        "BTC should complement bit 1 (clear it)"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (bit 1 was 1)");
    Ok(())
}

#[test]
fn cmovz_r64_r64_moves_when_zf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        ZF_BIT,
    )?;
    let decoded = make_decoded(
        forms::CMOVZ_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x2222, "CMOVZ should move src when ZF=1");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovz_r64_r64_keeps_dest_when_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        0,
    )?;
    let decoded = make_decoded(
        forms::CMOVZ_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x1111, "CMOVZ should keep dest when ZF=0");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovnz_r64_r64_moves_when_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        0,
    )?;
    let decoded = make_decoded(
        forms::CMOVNZ_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x2222, "CMOVNZ should move src when ZF=0");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovnz_r64_r64_keeps_dest_when_zf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        ZF_BIT,
    )?;
    let decoded = make_decoded(
        forms::CMOVNZ_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x1111, "CMOVNZ should keep dest when ZF=1");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovl_r64_r64_moves_when_sf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        SF_BIT,
    )?;
    let decoded = make_decoded(
        forms::CMOVL_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x2222, "CMOVL should move src when SF=1");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovl_r64_r64_keeps_dest_when_sf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        0,
    )?;
    let decoded = make_decoded(
        forms::CMOVL_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x1111, "CMOVL should keep dest when SF=0");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovge_r64_r64_moves_when_sf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        0,
    )?;
    let decoded = make_decoded(
        forms::CMOVGE_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x2222, "CMOVGE should move src when SF=0");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmovge_r64_r64_keeps_dest_when_sf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x1111)?, RCX, 0x2222)?,
        RFLAGS,
        SF_BIT,
    )?;
    let decoded = make_decoded(
        forms::CMOVGE_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x1111, "CMOVGE should keep dest when SF=1");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn rol_r64_cl_executes_and_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    // ROL 0x8000000000000000 by 1: high bit wraps to bit 0, CF=1
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, 0x8000000000000000)?, RCX, 1)?,
        RFLAGS,
        0,
    )?;
    let decoded = make_decoded(
        forms::ROL_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x1, "ROL should wrap high bit to bit 0");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (rotated-out bit was 1)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn rol_r64_cl_preserves_value_when_cf_clear() -> Result<(), Box<dyn std::error::Error>> {
    // ROL 0x1 by 4: 0x1 << 4 = 0x10, no wrap, CF=0
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x1)?, RCX, 4)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::ROL_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x10, "ROL 0x1 by 4 should give 0x10");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (no high bit rotated out)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn ror_r64_cl_executes_and_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    // ROR 0x3 by 1: bit 0 wraps to bit 63, result=0x8000000000000001, CF=1
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x3)?, RCX, 1)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::ROR_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x8000000000000001,
        "ROR should wrap bit 0 to bit 63"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (rotated-out bit was 1)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn ror_r64_cl_no_wrap_when_low_bits_clear() -> Result<(), Box<dyn std::error::Error>> {
    // ROR 0x10 by 4: 0x10 >> 4 = 0x1, CF=0
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x10)?, RCX, 4)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::ROR_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x1, "ROR 0x10 by 4 should give 0x1");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (rotated-out bit was 0)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn rcl_r64_cl_inserts_cf_into_result() -> Result<(), Box<dyn std::error::Error>> {
    // RCL 0x1 by 1 with CF=1: old CF goes to bit 0, bit 0 goes to new CF
    // shifted_left = 0x1 << 1 = 0x2
    // shifted_right = 0x1 >> 63 = 0
    // cf_shifted = 1 << 0 = 1 (old CF inserted at bit 0)
    // result = 0x2 | 1 = 0x3
    // new_cf = 0 & 1 = 0
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x1)?, RCX, 1)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::RCL_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x3, "RCL should insert old CF at bit 0");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "new CF should be clear (bit 0 was 1, shifted out)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn rcl_r64_cl_cf_clear_no_insert() -> Result<(), Box<dyn std::error::Error>> {
    // RCL 0x1 by 1 with CF=0: old CF=0 goes to bit 0, result=0x2, new CF=0
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x1)?, RCX, 1)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::RCL_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x2, "RCL with CF=0 should just shift left");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "new CF should be clear");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn rcr_r64_cl_inserts_cf_into_result() -> Result<(), Box<dyn std::error::Error>> {
    // RCR 0x1 by 1 with CF=1: old CF goes to bit 63, bit 0 goes to new CF
    // shifted_right = 0x1 >> 1 = 0
    // shifted_left = 0x1 << 63 = 0x8000000000000000 (masked out by bit_mask)
    // cf_shifted = 1 << 63 = 0x8000000000000000 (old CF inserted at bit 63)
    // result = 0 | 0x8000000000000000 = 0x8000000000000000
    // new_cf = (0x1 >> 0) & 1 = 1
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x1)?, RCX, 1)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::RCR_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x8000000000000000,
        "RCR should insert old CF at bit 63"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "new CF should be set (bit 0 was 1, rotated out)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn rcr_r64_cl_cf_clear_no_insert() -> Result<(), Box<dyn std::error::Error>> {
    // RCR 0x1 by 1 with CF=0: old CF=0 goes to bit 63, result=0, new CF=1
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 0x1)?, RCX, 1)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::RCR_R64_CL,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0,
        "RCR with CF=0 should shift bit 0 out to CF"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "new CF should be set (bit 0 was 1, rotated out)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn mov_r32_r32_zero_extends() -> Result<(), Box<dyn std::error::Error>> {
    // Source has upper 32 bits set; MOV r32, r32 should zero-extend (clear upper 32)
    let initial = with_reg(&make_state()?, RCX, 0xFFFF_FFFF_FFFF_FFFF)?;
    let decoded = make_decoded(
        forms::MOV_R32_R32,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_FFFF_FFFF,
        "upper 32 bits should be zero-extended"
    );
    assert_eq!(
        read_reg(&executed, RCX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "source should be unchanged"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn mov_r8_r8_zero_extends() -> Result<(), Box<dyn std::error::Error>> {
    // Source has upper 56 bits set; MOV r8, r8 should zero-extend (clear upper 56)
    let initial = with_reg(&make_state()?, RCX, 0xFFFF_FFFF_FFFF_FFFF)?;
    let decoded = make_decoded(
        forms::MOV_R8_R8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_0000_00FF,
        "upper 56 bits should be zero-extended"
    );
    assert_eq!(
        read_reg(&executed, RCX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "source should be unchanged"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn movzx_r64_r32_zero_extends() -> Result<(), Box<dyn std::error::Error>> {
    // Source has upper 32 bits set; MOVZX should zero-extend lower 32 bits
    let initial = with_reg(&make_state()?, RCX, 0xFFFF_FFFF_FFFF_FFFF)?;
    let decoded = make_decoded(
        forms::MOVZX_R64_R32,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_FFFF_FFFF,
        "MOVZX should zero-extend 32-bit source"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn movsx_r64_r32_sign_extends_negative() -> Result<(), Box<dyn std::error::Error>> {
    // Source lower 32 bits = 0xFFFFFFFF (negative as int32); MOVSX should sign-extend to 0xFFFFFFFFFFFFFFFF
    let initial = with_reg(&make_state()?, RCX, 0x0000_0000_FFFF_FFFF)?;
    let decoded = make_decoded(
        forms::MOVSX_R64_R32,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "MOVSX should sign-extend negative 32-bit value"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn movsx_r64_r32_sign_extends_positive() -> Result<(), Box<dyn std::error::Error>> {
    // Source lower 32 bits = 0x7FFFFFFF (positive as int32); MOVSX should keep upper 32 bits clear
    let initial = with_reg(&make_state()?, RCX, 0xFFFF_FFFF_7FFF_FFFF)?;
    let decoded = make_decoded(
        forms::MOVSX_R64_R32,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_7FFF_FFFF,
        "MOVSX should sign-extend positive 32-bit value (upper bits clear)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn movzx_r64_r8_zero_extends() -> Result<(), Box<dyn std::error::Error>> {
    // Source has upper 56 bits set; MOVZX r64, r8 should zero-extend lower 8 bits
    let initial = with_reg(&make_state()?, RCX, 0xFFFF_FFFF_FFFF_FFFF)?;
    let decoded = make_decoded(
        forms::MOVZX_R64_R8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_0000_00FF,
        "MOVZX should zero-extend 8-bit source"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn movsx_r64_r8_sign_extends_negative() -> Result<(), Box<dyn std::error::Error>> {
    // Source lower 8 bits = 0xFF (negative as int8); MOVSX should sign-extend to 0xFFFFFFFFFFFFFFFF
    let initial = with_reg(&make_state()?, RCX, 0x0000_0000_0000_00FF)?;
    let decoded = make_decoded(
        forms::MOVSX_R64_R8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "MOVSX should sign-extend negative 8-bit value"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn movsx_r64_r8_sign_extends_positive() -> Result<(), Box<dyn std::error::Error>> {
    // Source lower 8 bits = 0x7F (positive as int8); MOVSX should keep upper 56 bits clear
    let initial = with_reg(&make_state()?, RCX, 0xFFFF_FFFF_FFFF_FF7F)?;
    let decoded = make_decoded(
        forms::MOVSX_R64_R8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_0000_007F,
        "MOVSX should sign-extend positive 8-bit value (upper bits clear)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn clc_clears_carry_flag() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(forms::CLC, vec![]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CLC should clear CF");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn stc_sets_carry_flag() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::STC, vec![]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "STC should set CF");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmc_complements_set_carry_flag() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(forms::CMC, vec![]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CMC should clear CF when it was set");
    Ok(())
}

#[test]
fn cmc_complements_clear_carry_flag() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::CMC, vec![]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CMC should set CF when it was clear");
    Ok(())
}

#[test]
fn setz_r8_sets_one_when_zf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, ZF_BIT)?;
    let decoded = make_decoded(forms::SETZ_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 1, "SETZ should write 1 when ZF=1");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn setz_r8_sets_zero_when_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::SETZ_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "SETZ should write 0 when ZF=0");
    Ok(())
}

#[test]
fn setnz_r8_sets_one_when_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::SETNZ_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 1, "SETNZ should write 1 when ZF=0");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn setnz_r8_sets_zero_when_zf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, ZF_BIT)?;
    let decoded = make_decoded(forms::SETNZ_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "SETNZ should write 0 when ZF=1");
    Ok(())
}

#[test]
fn setl_r8_sets_one_when_sf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, SF_BIT)?;
    let decoded = make_decoded(forms::SETL_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 1, "SETL should write 1 when SF=1");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn setl_r8_sets_zero_when_sf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::SETL_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "SETL should write 0 when SF=0");
    Ok(())
}

#[test]
fn setge_r8_sets_one_when_sf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, 0)?;
    let decoded = make_decoded(forms::SETGE_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 1, "SETGE should write 1 when SF=0");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn setge_r8_sets_zero_when_sf_set() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RFLAGS, SF_BIT)?;
    let decoded = make_decoded(forms::SETGE_R8, vec![reg_operand(0, RAX, AccessKind::Write)]);

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "SETGE should write 0 when SF=1");
    Ok(())
}

#[test]
fn adc_r64_r64_without_carry() -> Result<(), Box<dyn std::error::Error>> {
    // CF=0: 10 + 32 = 42, no carry
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 10)?, RCX, 32)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::ADC_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 42, "ADC with CF=0 should add operands");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (no carry)");
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn adc_r64_r64_with_carry() -> Result<(), Box<dyn std::error::Error>> {
    // CF=1: 10 + 32 + 1 = 43
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 10)?, RCX, 32)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::ADC_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        43,
        "ADC with CF=1 should add operands plus carry"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (no carry out)");
    Ok(())
}

#[test]
fn adc_r64_r64_carry_out() -> Result<(), Box<dyn std::error::Error>> {
    // CF=1: u64::MAX + 0 + 1 = 0 (wrapping), with carry out
    let initial = with_reg(
        &with_reg(&with_reg(&make_state()?, RAX, u64::MAX)?, RCX, 0)?,
        RFLAGS,
        CF_BIT,
    )?;
    let decoded = make_decoded(
        forms::ADC_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "ADC should wrap to 0");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (carry out)");
    assert_ne!(rflags & ZF_BIT, 0, "ZF should be set (result == 0)");
    Ok(())
}

#[test]
fn sbb_r64_r64_without_borrow() -> Result<(), Box<dyn std::error::Error>> {
    // CF=0: 42 - 10 = 32, no borrow
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 42)?, RCX, 10)?, RFLAGS, 0)?;
    let decoded = make_decoded(
        forms::SBB_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 32, "SBB with CF=0 should subtract operands");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (no borrow)");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn sbb_r64_r64_with_borrow() -> Result<(), Box<dyn std::error::Error>> {
    // CF=1: 42 - 10 - 1 = 31
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 42)?, RCX, 10)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::SBB_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        31,
        "SBB with CF=1 should subtract operands minus borrow"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear (no borrow out)");
    Ok(())
}

#[test]
fn sbb_r64_r64_borrow_out() -> Result<(), Box<dyn std::error::Error>> {
    // CF=1: 5 - 10 - 1 = -6 (wrapping), with borrow
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 5)?, RCX, 10)?, RFLAGS, CF_BIT)?;
    let decoded = make_decoded(
        forms::SBB_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, (-6i64 as u64), "SBB should wrap to -6");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & CF_BIT, 0, "CF should be set (borrow out)");
    assert_ne!(rflags & SF_BIT, 0, "SF should be set (negative result)");
    Ok(())
}

// ===========================================================================
// Phase 4c: sign extension, CWD/CDQ, CMPXCHG, NOP2
// ===========================================================================

const RDX: u32 = register_id::GPR_BASE + 2;

/// Like `make_state` but also initializes RDX (needed for CMPXCHG tests).
fn make_state_with_rdx() -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, Box<dyn std::error::Error>> {
    let memory = PersistentMemory::new(vec![
        MemoryRegion {
            object: ObjectId(1),
            base: 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: true,
        },
        MemoryRegion {
            object: ObjectId(2),
            base: 0x3000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;
    Ok(ExecutionState {
        id: StateId(7),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers: PersistentRegisters::from_widths([(RAX, 8), (RCX, 8), (RDX, 8), (RFLAGS, 8)])?,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    })
}

#[test]
fn cbw_sign_extends_negative_8bit() -> Result<(), Box<dyn std::error::Error>> {
    // AL = 0xFF (negative as int8); CBW should sign-extend to 0xFFFF...FFFF
    let initial = with_reg(&make_state()?, RAX, 0xFF)?;
    let decoded = make_decoded(forms::CBW, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "CBW should sign-extend negative 8-bit value"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cbw_sign_extends_positive_8bit() -> Result<(), Box<dyn std::error::Error>> {
    // AL = 0x7F (positive as int8); CBW should keep upper bits clear
    let initial = with_reg(&make_state()?, RAX, 0x7F)?;
    let decoded = make_decoded(forms::CBW, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_0000_007F,
        "CBW should sign-extend positive 8-bit value (upper bits clear)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cwde_sign_extends_negative_16bit() -> Result<(), Box<dyn std::error::Error>> {
    // AX = 0x8000 (negative as int16); CWDE should sign-extend to 0xFFFFFFFFFFFF8000
    let initial = with_reg(&make_state()?, RAX, 0x8000)?;
    let decoded = make_decoded(forms::CWDE, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0xFFFF_FFFF_FFFF_8000,
        "CWDE should sign-extend negative 16-bit value (upper bits set, lower 16 preserved)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cwde_sign_extends_positive_16bit() -> Result<(), Box<dyn std::error::Error>> {
    // AX = 0x7FFF (positive as int16); CWDE should keep upper bits clear
    let initial = with_reg(&make_state()?, RAX, 0x7FFF)?;
    let decoded = make_decoded(forms::CWDE, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_0000_7FFF,
        "CWDE should sign-extend positive 16-bit value (upper bits clear)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cdqe_sign_extends_negative_32bit() -> Result<(), Box<dyn std::error::Error>> {
    // EAX = 0x80000000 (negative as int32); CDQE should sign-extend to 0xFFFFFFFF80000000
    let initial = with_reg(&make_state()?, RAX, 0x8000_0000)?;
    let decoded = make_decoded(forms::CDQE, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0xFFFF_FFFF_8000_0000,
        "CDQE should sign-extend negative 32-bit value (upper bits set, lower 32 preserved)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cdqe_sign_extends_positive_32bit() -> Result<(), Box<dyn std::error::Error>> {
    // EAX = 0x7FFFFFFF (positive as int32); CDQE should keep upper bits clear
    let initial = with_reg(&make_state()?, RAX, 0x7FFF_FFFF)?;
    let decoded = make_decoded(forms::CDQE, vec![reg_operand(0, RAX, AccessKind::ReadWrite)]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RAX)?,
        0x0000_0000_7FFF_FFFF,
        "CDQE should sign-extend positive 32-bit value (upper bits clear)"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cwd_sign_extends_negative_16bit() -> Result<(), Box<dyn std::error::Error>> {
    // AX = 0x8000 (negative); CWD should set DX to 0xFFFF...FFFF (sign bits)
    let initial = with_reg(&make_state_with_rdx()?, RAX, 0x8000)?;
    let decoded = make_decoded(
        forms::CWD,
        vec![
            reg_operand(0, RAX, AccessKind::Read),
            reg_operand(1, RDX, AccessKind::Write),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RDX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "CWD should set DX to all 1s for negative AX"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cwd_sign_extends_positive_16bit() -> Result<(), Box<dyn std::error::Error>> {
    // AX = 0x7FFF (positive); CWD should set DX to 0
    let initial = with_reg(&make_state_with_rdx()?, RAX, 0x7FFF)?;
    let decoded = make_decoded(
        forms::CWD,
        vec![
            reg_operand(0, RAX, AccessKind::Read),
            reg_operand(1, RDX, AccessKind::Write),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RDX)?,
        0x0000_0000_0000_0000,
        "CWD should set DX to 0 for positive AX"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cdq_sign_extends_negative_32bit() -> Result<(), Box<dyn std::error::Error>> {
    // EAX = 0x80000000 (negative); CDQ should set EDX to 0xFFFF...FFFF (sign bits)
    let initial = with_reg(&make_state_with_rdx()?, RAX, 0x8000_0000)?;
    let decoded = make_decoded(
        forms::CDQ,
        vec![
            reg_operand(0, RAX, AccessKind::Read),
            reg_operand(1, RDX, AccessKind::Write),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RDX)?,
        0xFFFF_FFFF_FFFF_FFFF,
        "CDQ should set EDX to all 1s for negative EAX"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cdq_sign_extends_positive_32bit() -> Result<(), Box<dyn std::error::Error>> {
    // EAX = 0x7FFFFFFF (positive); CDQ should set EDX to 0
    let initial = with_reg(&make_state_with_rdx()?, RAX, 0x7FFF_FFFF)?;
    let decoded = make_decoded(
        forms::CDQ,
        vec![
            reg_operand(0, RAX, AccessKind::Read),
            reg_operand(1, RDX, AccessKind::Write),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RDX)?,
        0x0000_0000_0000_0000,
        "CDQ should set EDX to 0 for positive EAX"
    );
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmpxchg_equal_swaps_source_into_dest() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 42, dest (RCX) = 42, source (RDX) = 99
    // Equal: dest <- source (99), RAX unchanged (42), ZF set
    let initial = with_reg(
        &with_reg(&with_reg(&make_state_with_rdx()?, RAX, 42)?, RCX, 42)?,
        RDX,
        99,
    )?;
    let decoded = make_decoded(
        forms::CMPXCHG_R64_R64,
        vec![
            reg_operand(0, RCX, AccessKind::ReadWrite),
            reg_operand(1, RDX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RCX)?,
        99,
        "CMPXCHG equal: dest should get source value"
    );
    assert_eq!(read_reg(&executed, RAX)?, 42, "CMPXCHG equal: RAX should be unchanged");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_ne!(rflags & ZF_BIT, 0, "CMPXCHG equal: ZF should be set");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmpxchg_not_equal_loads_dest_into_rax() -> Result<(), Box<dyn std::error::Error>> {
    // RAX = 42, dest (RCX) = 77, source (RDX) = 99
    // Not equal: dest unchanged (77), RAX <- dest (77), ZF clear
    let initial = with_reg(
        &with_reg(&with_reg(&make_state_with_rdx()?, RAX, 42)?, RCX, 77)?,
        RDX,
        99,
    )?;
    let decoded = make_decoded(
        forms::CMPXCHG_R64_R64,
        vec![
            reg_operand(0, RCX, AccessKind::ReadWrite),
            reg_operand(1, RDX, AccessKind::Read),
        ],
    );

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(
        read_reg(&executed, RCX)?,
        77,
        "CMPXCHG not equal: dest should be unchanged"
    );
    assert_eq!(
        read_reg(&executed, RAX)?,
        77,
        "CMPXCHG not equal: RAX should get dest value"
    );
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "CMPXCHG not equal: ZF should be clear");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn nop2_falls_through() -> Result<(), Box<dyn std::error::Error>> {
    let initial = make_state()?;
    let decoded = make_decoded(forms::NOP2, vec![]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "NOP2 should not modify any registers");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Phase 4a expansion integration tests
// Only 64-bit forms are tested end-to-end here. 32-bit forms seal correctly
// (verified in the unit test suite) but the lowerer does not yet support
// partial-register reads/writes, so they cannot execute through the concrete
// interpreter.
// ---------------------------------------------------------------------------

#[test]
fn bswap_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RAX, 0x0102030405060708)?;

    let decoded = make_decoded(
        forms::BSWAP_R64,
        vec![reg_operand(0, RAX, AccessKind::ReadWrite)],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x0807060504030201);
    Ok(())
}

#[test]
fn and_r64_imm32_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RAX, 0xFF)?;

    let decoded = make_decoded(
        forms::AND_R64_IMM32,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            imm_operand(1, 0x0F, 64),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0x0F);
    Ok(())
}

#[test]
fn xor_r64_imm32_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RAX, 0xFF)?;

    let decoded = make_decoded(
        forms::XOR_R64_IMM32,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            imm_operand(1, 0x0F, 64),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xF0);
    Ok(())
}

#[test]
fn or_r64_imm32_executes() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RAX, 0xF0)?;

    let decoded = make_decoded(
        forms::OR_R64_IMM32,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            imm_operand(1, 0x0F, 64),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0xFF);
    Ok(())
}

#[test]
fn test_r64_imm32_sets_zf_when_zero() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RAX, 0x100)?;

    let decoded = make_decoded(
        forms::TEST_R64_IMM32,
        vec![
            reg_operand(0, RAX, AccessKind::Read),
            imm_operand(1, 0xFF, 64),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, ZF_BIT, "ZF should be set when AND result is zero");
    assert_eq!(read_reg(&executed, RAX)?, 0x100, "TEST should not modify register");
    Ok(())
}

#[test]
fn nop3_falls_through() -> Result<(), Box<dyn std::error::Error>> {
    let initial = make_state()?;
    let decoded = make_decoded(forms::NOP3, vec![]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "NOP3 should not modify any registers");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn nop9_falls_through() -> Result<(), Box<dyn std::error::Error>> {
    let initial = make_state()?;
    let decoded = make_decoded(forms::NOP9, vec![]);

    let (executed, outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "NOP9 should not modify any registers");
    assert_eq!(
        outcome,
        ExecutionOutcome::Continue {
            state: StateId(7),
            next_pc: BLOCK_ADDR + 3,
        }
    );
    Ok(())
}

#[test]
fn cmova_r64_r64_taken_when_cf_and_zf_clear() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&with_reg(&with_reg(&make_state()?, RAX, 10)?, RCX, 99)?, RFLAGS, 0)?;

    let decoded = make_decoded(
        forms::CMOVA_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::ReadWrite),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 99, "CMOVA should take src when CF=0 and ZF=0");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: bit-scan / popcount integration tests
// ---------------------------------------------------------------------------

#[test]
fn popcnt_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    // 0xB = 0b1011 -> 3 set bits
    let initial = with_reg(&make_state()?, RCX, 0xB)?;

    let decoded = make_decoded(
        forms::POPCNT_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 3, "POPCNT of 0xB should be 3");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear when result is nonzero");
    Ok(())
}

#[test]
fn popcnt_r64_r64_sets_zf_when_zero() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RCX, 0)?;

    let decoded = make_decoded(
        forms::POPCNT_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 0, "POPCNT of 0 should be 0");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, ZF_BIT, "ZF should be set when result is zero");
    Ok(())
}

#[test]
fn bsf_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    // 0x10 = 0b10000 -> least significant set bit at index 4
    let initial = with_reg(&make_state()?, RCX, 0x10)?;

    let decoded = make_decoded(
        forms::BSF_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 4, "BSF of 0x10 should be 4");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear when source is nonzero");
    Ok(())
}

#[test]
fn bsr_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    // 0x10 = 0b10000 -> most significant set bit at index 4
    let initial = with_reg(&make_state()?, RCX, 0x10)?;

    let decoded = make_decoded(
        forms::BSR_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 4, "BSR of 0x10 should be 4");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear when source is nonzero");
    Ok(())
}

#[test]
fn tzcnt_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    // 0x10 = 0b10000 -> 4 trailing zeros
    let initial = with_reg(&make_state()?, RCX, 0x10)?;

    let decoded = make_decoded(
        forms::TZCNT_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 4, "TZCNT of 0x10 should be 4");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear when source is nonzero");
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear when source is nonzero");
    Ok(())
}

#[test]
fn tzcnt_r64_r64_when_source_zero() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RCX, 0)?;

    let decoded = make_decoded(
        forms::TZCNT_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 64, "TZCNT of 0 should be 64");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, ZF_BIT, "ZF should be set when source is zero");
    assert_eq!(rflags & CF_BIT, CF_BIT, "CF should be set when source is zero");
    Ok(())
}

#[test]
fn lzcnt_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    // 0x10 = 0b10000 -> 59 leading zeros (64 - 5)
    let initial = with_reg(&make_state()?, RCX, 0x10)?;

    let decoded = make_decoded(
        forms::LZCNT_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 59, "LZCNT of 0x10 should be 59");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & ZF_BIT, 0, "ZF should be clear when result is nonzero");
    assert_eq!(rflags & CF_BIT, 0, "CF should be clear when source is nonzero");
    Ok(())
}

#[test]
fn lzcnt_r64_r64_when_source_zero() -> Result<(), Box<dyn std::error::Error>> {
    let initial = with_reg(&make_state()?, RCX, 0)?;

    let decoded = make_decoded(
        forms::LZCNT_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    assert_eq!(read_reg(&executed, RAX)?, 64, "LZCNT of 0 should be 64");
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & CF_BIT, CF_BIT, "CF should be set when source is zero");
    Ok(())
}
