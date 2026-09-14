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

// ---------------------------------------------------------------------------
// Phase 4b: SSE float integration tests
// ---------------------------------------------------------------------------

const XMM0: u32 = register_id::ZMM_BASE;
const XMM1: u32 = register_id::ZMM_BASE + 1;
const XMM2: u32 = register_id::ZMM_BASE + 2;

fn make_float_state(reg_widths: &[(u32, usize)]) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, Box<dyn std::error::Error>> {
    let memory = PersistentMemory::new(vec![
        MemoryRegion {
            object: ObjectId(1),
            base: 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: true,
        },
    ])?;
    let widths: Vec<(u32, usize)> = reg_widths.to_vec();
    Ok(ExecutionState {
        id: StateId(7),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers: PersistentRegisters::from_widths(widths)?,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    })
}

fn with_bytes(
    state: &ExecutionState<PersistentRegisters, PersistentMemory>,
    reg: u32,
    bytes: &[u8],
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, Box<dyn std::error::Error>> {
    Ok(ExecutionState {
        id: state.id,
        parent: state.parent,
        target_profile: state.target_profile,
        registers: state.registers.write(reg, bytes)?,
        memory: state.memory.clone(),
        constraints: state.constraints.clone(),
        ownership: state.ownership,
        fidelity: state.fidelity.clone(),
    })
}

fn read_bytes(
    state: &ExecutionState<PersistentRegisters, PersistentMemory>,
    reg: u32,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(state.registers.read(reg)?)
}

fn xmm_operand(index: u8, reg: u32, width_bits: u16, access: AccessKind) -> Operand {
    Operand {
        index,
        width_bits,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(RegisterView::full(RegisterId(reg), width_bits)),
    }
}

#[test]
fn addss_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4)])?;
    let initial = with_bytes(&state, XMM0, &1.5f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &2.5f32.to_le_bytes())?;

    let decoded = make_decoded(
        forms::ADDSS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[..4]);
    let result = f32::from_le_bytes(buf);
    assert!((result - 4.0).abs() < f32::EPSILON, "1.5 + 2.5 should be 4.0, got {result}");
    Ok(())
}

#[test]
fn subss_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4)])?;
    let initial = with_bytes(&state, XMM0, &5.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &1.5f32.to_le_bytes())?;

    let decoded = make_decoded(
        forms::SUBSS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[..4]);
    let result = f32::from_le_bytes(buf);
    assert!((result - 3.5).abs() < f32::EPSILON, "5.0 - 1.5 should be 3.5, got {result}");
    Ok(())
}

#[test]
fn mulss_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4)])?;
    let initial = with_bytes(&state, XMM0, &3.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &4.0f32.to_le_bytes())?;

    let decoded = make_decoded(
        forms::MULSS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[..4]);
    let result = f32::from_le_bytes(buf);
    assert!((result - 12.0).abs() < f32::EPSILON, "3.0 * 4.0 should be 12.0, got {result}");
    Ok(())
}

#[test]
fn divss_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4)])?;
    let initial = with_bytes(&state, XMM0, &10.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &4.0f32.to_le_bytes())?;

    let decoded = make_decoded(
        forms::DIVSS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[..4]);
    let result = f32::from_le_bytes(buf);
    assert!((result - 2.5).abs() < f32::EPSILON, "10.0 / 4.0 should be 2.5, got {result}");
    Ok(())
}

#[test]
fn sqrtss_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4)])?;
    let initial = with_bytes(&state, XMM1, &16.0f32.to_le_bytes())?;

    let decoded = make_decoded(
        forms::SQRTSS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[..4]);
    let result = f32::from_le_bytes(buf);
    assert!((result - 4.0).abs() < f32::EPSILON, "sqrt(16.0) should be 4.0, got {result}");
    Ok(())
}

#[test]
fn addsd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 8), (XMM1, 8)])?;
    let initial = with_bytes(&state, XMM0, &1.25f64.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &2.75f64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::ADDSD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 64, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 64, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let result = f64::from_le_bytes(buf);
    assert!((result - 4.0).abs() < f64::EPSILON, "1.25 + 2.75 should be 4.0, got {result}");
    Ok(())
}

#[test]
fn sqrtsd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 8), (XMM1, 8)])?;
    let initial = with_bytes(&state, XMM1, &64.0f64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::SQRTSD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 64, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 64, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    let result = f64::from_le_bytes(buf);
    assert!((result - 8.0).abs() < f64::EPSILON, "sqrt(64.0) should be 8.0, got {result}");
    Ok(())
}

#[test]
fn addps_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // [1.0, 2.0, 3.0, 4.0] + [10.0, 20.0, 30.0, 40.0] = [11.0, 22.0, 33.0, 44.0]
    let mut left_bytes = Vec::new();
    for v in [1.0f32, 2.0, 3.0, 4.0] {
        left_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut right_bytes = Vec::new();
    for v in [10.0f32, 20.0, 30.0, 40.0] {
        right_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::ADDPS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let results: Vec<f32> = (0..4)
        .map(|i| {
            let mut buf = [0u8; 4];
            buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
            f32::from_le_bytes(buf)
        })
        .collect();
    assert!((results[0] - 11.0).abs() < f32::EPSILON, "lane 0: 1+10=11, got {}", results[0]);
    assert!((results[1] - 22.0).abs() < f32::EPSILON, "lane 1: 2+20=22, got {}", results[1]);
    assert!((results[2] - 33.0).abs() < f32::EPSILON, "lane 2: 3+30=33, got {}", results[2]);
    assert!((results[3] - 44.0).abs() < f32::EPSILON, "lane 3: 4+40=44, got {}", results[3]);
    Ok(())
}

#[test]
fn mulpd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // [1.5, 2.5] * [3.0, 4.0] = [4.5, 10.0]
    let mut left_bytes = Vec::new();
    for v in [1.5f64, 2.5] {
        left_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut right_bytes = Vec::new();
    for v in [3.0f64, 4.0] {
        right_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::MULPD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let mut buf0 = [0u8; 8];
    buf0.copy_from_slice(&bytes[..8]);
    let mut buf1 = [0u8; 8];
    buf1.copy_from_slice(&bytes[8..16]);
    let r0 = f64::from_le_bytes(buf0);
    let r1 = f64::from_le_bytes(buf1);
    assert!((r0 - 4.5).abs() < f64::EPSILON, "lane 0: 1.5*3.0=4.5, got {r0}");
    assert!((r1 - 10.0).abs() < f64::EPSILON, "lane 1: 2.5*4.0=10.0, got {r1}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed integer integration tests
// ---------------------------------------------------------------------------

#[test]
fn paddb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 16x8-bit: [1,2,3,...,16] + [10,10,...,10] = [11,12,13,...,26]
    let left: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
    let right: [u8; 16] = [10; 16];
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PADDB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let expected = ((i + 1) + 10) as u8;
        assert_eq!(byte, expected, "lane {i}: {} + 10 = {}, got {}", i + 1, expected, byte);
    }
    Ok(())
}

#[test]
fn psubb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let left: [u8; 16] = core::array::from_fn(|i| (i + 20) as u8);
    let right: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PSUBB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let expected = ((i + 20) - (i + 1)) as u8;
        assert_eq!(byte, expected, "lane {i}: {} - {} = {}, got {}", i + 20, i + 1, expected, byte);
    }
    Ok(())
}

#[test]
fn paddw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 8x16-bit: [100,200,...,800] + [1000,1000,...,1000] = [1100,1200,...,1800]
    let mut left = Vec::new();
    for i in 0..8u16 {
        left.extend_from_slice(&((i + 1) * 100).to_le_bytes());
    }
    let mut right = Vec::new();
    for _ in 0..8 {
        right.extend_from_slice(&1000u16.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PADDW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for i in 0..8 {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        let expected = ((i as u16 + 1) * 100) + 1000;
        assert_eq!(result, expected, "lane {i}: {} + 1000 = {}, got {}", (i + 1) * 100, expected, result);
    }
    Ok(())
}

#[test]
fn pmullw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 8x16-bit: [1,2,3,...,8] * [2,2,...,2] = [2,4,6,...,16]
    let mut left = Vec::new();
    for i in 0..8u16 {
        left.extend_from_slice(&(i + 1).to_le_bytes());
    }
    let mut right = Vec::new();
    for _ in 0..8 {
        right.extend_from_slice(&2u16.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PMULLW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for i in 0..8 {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        let expected = (i as u16 + 1) * 2;
        assert_eq!(result, expected, "lane {i}: {} * 2 = {}, got {}", i + 1, expected, result);
    }
    Ok(())
}

#[test]
fn paddd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 4x32-bit: [1,2,3,4] + [100,200,300,400] = [101,202,303,404]
    let mut left = Vec::new();
    for v in [1u32, 2, 3, 4] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let mut right = Vec::new();
    for v in [100u32, 200, 300, 400] {
        right.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PADDD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [101u32, 202, 303, 404];
    for i in 0..4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, expected[i], "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn psubd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 4x32-bit: [1000,2000,3000,4000] - [100,200,300,400] = [900,1800,2700,3600]
    let mut left = Vec::new();
    for v in [1000u32, 2000, 3000, 4000] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let mut right = Vec::new();
    for v in [100u32, 200, 300, 400] {
        right.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PSUBD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [900u32, 1800, 2700, 3600];
    for i in 0..4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, expected[i], "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn paddq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 2x64-bit: [100, 200] + [1000, 2000] = [1100, 2200]
    let mut left = Vec::new();
    for v in [100u64, 200] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let mut right = Vec::new();
    for v in [1000u64, 2000] {
        right.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PADDQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [1100u64, 2200];
    for i in 0..2 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, expected[i], "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn pand_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 0xFF00 & 0xF0F0 = 0xF000
    let left: [u8; 16] = [0xFF; 16];
    let right: [u8; 16] = [0xF0; 16];
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PAND_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        assert_eq!(byte, 0xF0, "lane {i}: 0xFF & 0xF0 = 0xF0, got {:#x}", byte);
    }
    Ok(())
}

#[test]
fn por_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 0x0F | 0xF0 = 0xFF
    let left: [u8; 16] = [0x0F; 16];
    let right: [u8; 16] = [0xF0; 16];
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::POR_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        assert_eq!(byte, 0xFF, "lane {i}: 0x0F | 0xF0 = 0xFF, got {:#x}", byte);
    }
    Ok(())
}

#[test]
fn pxor_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 0xFF ^ 0x0F = 0xF0
    let left: [u8; 16] = [0xFF; 16];
    let right: [u8; 16] = [0x0F; 16];
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PXOR_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        assert_eq!(byte, 0xF0, "lane {i}: 0xFF ^ 0x0F = 0xF0, got {:#x}", byte);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shift integration tests
// ---------------------------------------------------------------------------

fn imm8_operand(index: u8, value: u64) -> Operand {
    Operand {
        index,
        width_bits: 8,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Immediate(angryier_arch::ImmediateOperand { value, signed: false }),
    }
}

fn cast_i8_bytes(values: &[i8]) -> Vec<u8> {
    values.iter().map(|&v| v as u8).collect()
}

fn cast_i32_bytes(values: &[i32]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(values.len() * 4);
    for &v in values {
        bytes.extend_from_slice(&v.to_le_bytes());
    }
    bytes
}

#[test]
fn psllw_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // 8x16-bit: [1,2,3,...,8] << 2 = [4,8,12,...,32]
    let mut left = Vec::new();
    for v in [1u16, 2, 3, 4, 5, 6, 7, 8] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;

    let decoded = make_decoded(
        forms::PSLLW_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 2),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [4u16, 8, 12, 16, 20, 24, 28, 32];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn psrlw_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // 8x16-bit: [256,512,...,2048] >> 2 = [64,128,...,512]
    let mut left = Vec::new();
    for v in [256u16, 512, 768, 1024, 1280, 1536, 1792, 2048] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;

    let decoded = make_decoded(
        forms::PSRLW_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 2),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [64u16, 128, 192, 256, 320, 384, 448, 512];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn psraw_xmm_imm8_preserves_sign() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // 8x16-bit: [0xFF00, 0x8000, 0x4000, ...] >> 4 — sign-extended for negative values
    let mut left = Vec::new();
    for v in [0xFF00u16, 0x8000, 0x4000, 0x0001, 0xFFE0, 0x8001, 0x7FFF, 0x0000] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;

    let decoded = make_decoded(
        forms::PSRAW_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 4),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    // 0xFF00 >> 4 (arithmetic) = 0xFFF0
    // 0x8000 >> 4 (arithmetic) = 0xF800
    // 0x4000 >> 4 (arithmetic) = 0x0400
    // 0x0001 >> 4 = 0x0000
    // 0xFFE0 >> 4 (arithmetic) = 0xFFFE
    // 0x8001 >> 4 (arithmetic) = 0xF800
    // 0x7FFF >> 4 = 0x07FF
    // 0x0000 >> 4 = 0x0000
    let expected = [0xFFF0u16, 0xF800, 0x0400, 0x0000, 0xFFFE, 0xF800, 0x07FF, 0x0000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#06x}, expected {exp:#06x}");
    }
    Ok(())
}

#[test]
fn pslld_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // 4x32-bit: [1,2,3,4] << 3 = [8,16,24,32]
    let mut left = Vec::new();
    for v in [1u32, 2, 3, 4] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;

    let decoded = make_decoded(
        forms::PSLLD_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 3),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [8u32, 16, 24, 32];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn psrlq_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // 2x64-bit: [0x100, 0x200] >> 4 = [0x10, 0x20]
    let mut left = Vec::new();
    for v in [0x100u64, 0x200] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;

    let decoded = make_decoded(
        forms::PSRLQ_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 4),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [0x10u64, 0x20];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed compare integration tests
// ---------------------------------------------------------------------------

#[test]
fn pcmpeqb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 16x8-bit: [1,2,3,...,16] vs [1,99,3,99,...] -> [0xFF, 0, 0xFF, 0, ...]
    let left: [u8; 16] = core::array::from_fn(|i| (i + 1) as u8);
    let mut right = [0u8; 16];
    for (i, v) in right.iter_mut().enumerate() {
        *v = if i % 2 == 0 { (i + 1) as u8 } else { 99 };
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PCMPEQB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let expected = if i % 2 == 0 { 0xFF } else { 0x00 };
        assert_eq!(byte, expected, "lane {i}: got {:#x}", byte);
    }
    Ok(())
}

#[test]
fn pcmpeqd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 4x32-bit: [100, 200, 300, 400] vs [100, 999, 300, 999] -> [0xFFFFFFFF, 0, 0xFFFFFFFF, 0]
    let mut left = Vec::new();
    for v in [100u32, 200, 300, 400] {
        left.extend_from_slice(&v.to_le_bytes());
    }
    let mut right = Vec::new();
    for v in [100u32, 999, 300, 999] {
        right.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PCMPEQD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [0xFFFFFFFFu32, 0, 0xFFFFFFFF, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}");
    }
    Ok(())
}

#[test]
fn pcmpgtb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 16x8-bit signed: [10, -5, 100, -100, ...] > [5, 0, 50, 0, ...]
    let left: [i8; 16] = [10, -5, 100, -100, 20, -20, 50, -50, 1, -1, 2, -2, 3, -3, 4, -4];
    let right: [i8; 16] = [5, 0, 50, 0, 10, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM0, &cast_i8_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &cast_i8_bytes(&right))?;

    let decoded = make_decoded(
        forms::PCMPGTB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let l = left[i];
        let r = right[i];
        let expected = if l > r { 0xFF } else { 0x00 };
        assert_eq!(byte, expected, "lane {i}: {l} > {r} = {}, got {:#x}", l > r, byte);
    }
    Ok(())
}

#[test]
fn pcmpgtd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 4x32-bit signed: [100, -100, 1000, -1000] > [50, 0, 500, 0]
    let left: [i32; 4] = [100, -100, 1000, -1000];
    let right: [i32; 4] = [50, 0, 500, 0];
    let initial = with_bytes(&state, XMM0, &cast_i32_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &cast_i32_bytes(&right))?;

    let decoded = make_decoded(
        forms::PCMPGTD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [0xFFFFFFFFu32, 0, 0xFFFFFFFF, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4 packed min/max integration tests
// ---------------------------------------------------------------------------

#[test]
fn pmaxsb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 16x8-bit signed: max([10, -5, 100, ...], [5, 0, 50, ...]) = [10, 0, 100, ...]
    let left: [i8; 16] = [10, -5, 100, -100, 20, -20, 50, -50, 1, -1, 2, -2, 3, -3, 4, -4];
    let right: [i8; 16] = [5, 0, 50, 0, 10, 0, 25, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM0, &cast_i8_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &cast_i8_bytes(&right))?;

    let decoded = make_decoded(
        forms::PMAXSB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let l = left[i];
        let r = right[i];
        let expected = l.max(r) as u8;
        assert_eq!(byte, expected, "lane {i}: max({l}, {r}) = {}, got {:#x}", l.max(r), byte);
    }
    Ok(())
}

#[test]
fn pmaxub_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 16x8-bit unsigned: max([10, 200, ...], [50, 100, ...]) = [50, 200, ...]
    let left: [u8; 16] = [10, 200, 30, 250, 20, 220, 50, 150, 1, 100, 2, 200, 3, 180, 4, 90];
    let right: [u8; 16] = [50, 100, 70, 80, 60, 120, 25, 200, 0, 50, 0, 100, 0, 50, 0, 50];
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PMAXUB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let expected = left[i].max(right[i]);
        assert_eq!(byte, expected, "lane {i}: max({}, {}) = {}, got {:#x}", left[i], right[i], expected, byte);
    }
    Ok(())
}

#[test]
fn pminsd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 4x32-bit signed: min([100, -100, 1000, -1000], [50, 0, 500, 0]) = [50, -100, 500, -1000]
    let left: [i32; 4] = [100, -100, 1000, -1000];
    let right: [i32; 4] = [50, 0, 500, 0];
    let initial = with_bytes(&state, XMM0, &cast_i32_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &cast_i32_bytes(&right))?;

    let decoded = make_decoded(
        forms::PMINSD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [50i32, -100, 500, -1000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = i32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}");
    }
    Ok(())
}

#[test]
fn pminuw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 8x16-bit unsigned: min([100, 200, ...], [50, 300, ...]) = [50, 200, ...]
    let left: [u16; 8] = [100, 200, 300, 400, 500, 600, 700, 800];
    let right: [u16; 8] = [50, 300, 250, 500, 400, 700, 600, 900];
    let mut left_bytes = Vec::new();
    for v in left {
        left_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut right_bytes = Vec::new();
    for v in right {
        right_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PMINUW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &exp) in left.iter().zip(right.iter()).map(|(l, r)| l.min(r)).enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed multiply high integration tests
// ---------------------------------------------------------------------------

#[test]
fn pmulhw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 8x16-bit signed: high 16 of (l * r) for each lane
    // [100, 200, -100, 300, ...] * [1000, 100, 200, 50, ...]
    // 100*1000 = 100000 = 0x186A0, high 16 bits = 0x0001
    // 200*100 = 20000 = 0x4E20, high 16 bits = 0x0000
    // -100*200 = -20000 = 0xFFFFB1E0, high 16 bits = 0xFFFF
    // 300*50 = 15000 = 0x3A98, high 16 bits = 0x0000
    let left: [i16; 8] = [100, 200, -100, 300, 1, -1, 2, -2];
    let right: [i16; 8] = [1000, 100, 200, 50, 100, 100, 100, 100];
    let mut left_bytes = Vec::new();
    for v in left {
        left_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut right_bytes = Vec::new();
    for v in right {
        right_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PMULHW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, (&l, &r)) in left.iter().zip(right.iter()).enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = i16::from_le_bytes(buf);
        let expected = (((i32::from(l) * i32::from(r)) >> 16) & 0xFFFF) as i16;
        assert_eq!(result, expected, "lane {i}: {l} * {r} high = {expected}, got {result}");
    }
    Ok(())
}

#[test]
fn pmulhuw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // 8x16-bit unsigned: high 16 of (l * r) for each lane
    // [100, 200, 40000, 300, ...] * [1000, 100, 1000, 50, ...]
    // 100*1000 = 100000, high 16 = 1
    // 200*100 = 20000, high 16 = 0
    // 40000*1000 = 40000000 = 0x2625A00, high 16 = 0x0262 = 610
    // 300*50 = 15000, high 16 = 0
    let left: [u16; 8] = [100, 200, 40000, 300, 1, 2, 3, 4];
    let right: [u16; 8] = [1000, 100, 1000, 50, 100, 100, 100, 100];
    let mut left_bytes = Vec::new();
    for v in left {
        left_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let mut right_bytes = Vec::new();
    for v in right {
        right_bytes.extend_from_slice(&v.to_le_bytes());
    }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PMULHUW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, (&l, &r)) in left.iter().zip(right.iter()).enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        let expected = ((u32::from(l) * u32::from(r)) >> 16) as u16;
        assert_eq!(result, expected, "lane {i}: {l} * {r} high = {expected}, got {result}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed shuffle bytes integration tests
// ---------------------------------------------------------------------------

#[test]
fn pshufb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // Data: [0x00, 0x01, 0x02, ..., 0x0F]
    // Control: [0x0F, 0x0E, 0x0D, ..., 0x00] — reverse
    let data: [u8; 16] = core::array::from_fn(|i| i as u8);
    let control: [u8; 16] = core::array::from_fn(|i| (15 - i) as u8);
    let initial = with_bytes(&state, XMM0, &data)?;
    let initial = with_bytes(&initial, XMM1, &control)?;

    let decoded = make_decoded(
        forms::PSHUFB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    // Result should be reversed: [0x0F, 0x0E, ..., 0x00]
    for (i, &byte) in bytes.iter().enumerate() {
        let expected = (15 - i) as u8;
        assert_eq!(byte, expected, "lane {i}: got {:#x}, expected {expected:#x}", byte);
    }
    Ok(())
}

#[test]
fn pshufb_xmm_xmm_zeroes_on_high_bit() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // Data: [0x00, 0x01, ..., 0x0F]
    // Control: [0x00, 0x80, 0x01, 0x80, 0x02, 0x80, ...] — alternating select and zero
    let data: [u8; 16] = core::array::from_fn(|i| i as u8);
    let control: [u8; 16] = core::array::from_fn(|i| if i % 2 == 0 { i as u8 } else { 0x80 });
    let initial = with_bytes(&state, XMM0, &data)?;
    let initial = with_bytes(&initial, XMM1, &control)?;

    let decoded = make_decoded(
        forms::PSHUFB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for (i, &byte) in bytes.iter().enumerate() {
        let expected = if i % 2 == 0 { data[i] } else { 0 };
        assert_eq!(byte, expected, "lane {i}: got {:#x}, expected {expected:#x}", byte);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed unpack/interleave integration tests
// ---------------------------------------------------------------------------

#[test]
fn punpcklbw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PUNPCKLBW: interleave low 8 bytes from each operand
    // dst  = [0,1,2,3,4,5,6,7,8,9,A,B,C,D,E,F]
    // src  = [0x10,0x11,...,0x1F]
    // result = [dst[0], src[0], dst[1], src[1], ..., dst[7], src[7]]
    let left: [u8; 16] = core::array::from_fn(|i| i as u8);
    let right: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PUNPCKLBW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for i in 0..8 {
        assert_eq!(bytes[2 * i], left[i], "lane {i} lo: got {:#x}", bytes[2 * i]);
        assert_eq!(bytes[2 * i + 1], right[i], "lane {i} hi: got {:#x}", bytes[2 * i + 1]);
    }
    Ok(())
}

#[test]
fn punpcklwd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PUNPCKLWD: interleave low 4 words from each operand
    let left: [u16; 8] = [100, 200, 300, 400, 500, 600, 700, 800];
    let right: [u16; 8] = [1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000];
    let mut left_bytes = Vec::new();
    for v in left { left_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut right_bytes = Vec::new();
    for v in right { right_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PUNPCKLWD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for i in 0..4 {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[(2 * i) * 2..(2 * i + 1) * 2]);
        let lo = u16::from_le_bytes(buf);
        buf.copy_from_slice(&bytes[(2 * i + 1) * 2..(2 * i + 2) * 2]);
        let hi = u16::from_le_bytes(buf);
        assert_eq!(lo, left[i], "lane {i} lo: got {lo}");
        assert_eq!(hi, right[i], "lane {i} hi: got {hi}");
    }
    Ok(())
}

#[test]
fn punpckhbw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PUNPCKHBW: interleave high 8 bytes from each operand
    let left: [u8; 16] = core::array::from_fn(|i| i as u8);
    let right: [u8; 16] = core::array::from_fn(|i| 0x10 + i as u8);
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PUNPCKHBW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    for i in 0..8 {
        assert_eq!(bytes[2 * i], left[8 + i], "lane {i} lo: got {:#x}", bytes[2 * i]);
        assert_eq!(bytes[2 * i + 1], right[8 + i], "lane {i} hi: got {:#x}", bytes[2 * i + 1]);
    }
    Ok(())
}

#[test]
fn punpckldq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PUNPCKLDQ: interleave low 2 dwords from each operand
    let left: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
    let right: [u32; 4] = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];
    let mut left_bytes = Vec::new();
    for v in left { left_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut right_bytes = Vec::new();
    for v in right { right_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PUNPCKLDQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [left[0], right[0], left[1], right[1]];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn punpcklqdq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PUNPCKLQDQ: interleave low 1 qword from each operand
    let left: [u64; 2] = [0x1111111111111111, 0x2222222222222222];
    let right: [u64; 2] = [0xAAAAAAAAAAAAAAAA, 0xBBBBBBBBBBBBBBBB];
    let mut left_bytes = Vec::new();
    for v in left { left_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut right_bytes = Vec::new();
    for v in right { right_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PUNPCKLQDQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected = [left[0], right[0]];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed saturate integration tests
// ---------------------------------------------------------------------------

#[test]
fn packsswb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PACKSSWB: 8x16-bit signed → 16x8-bit signed, saturate to [-128, 127]
    // dst = [100, 200, -100, -200, 50, -50, 0, 127]
    // src = [128, -129, 255, -256, 0, 1, -1, 100]
    // Expected: [100, 127, -100, -128, 50, -50, 0, 127, 127, -128, 127, -128, 0, 1, -1, 100]
    let left: [i16; 8] = [100, 200, -100, -200, 50, -50, 0, 127];
    let right: [i16; 8] = [128, -129, 255, -256, 0, 1, -1, 100];
    let mut left_bytes = Vec::new();
    for v in left { left_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut right_bytes = Vec::new();
    for v in right { right_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PACKSSWB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i8; 16] = [
        100, 127, -100, -128, 50, -50, 0, 127,
        127, -128, 127, -128, 0, 1, -1, 100,
    ];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(bytes[i] as i8, exp, "lane {i}: got {:#x}, expected {exp}", bytes[i]);
    }
    Ok(())
}

#[test]
fn packssdw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PACKSSDW: 4x32-bit signed → 8x16-bit signed, saturate to [-32768, 32767]
    // dst = [100, 40000, -100, -40000]
    // src = [32767, 32768, -32768, -32769]
    // Expected: [100, 32767, -100, -32768, 32767, 32767, -32768, -32768]
    let left: [i32; 4] = [100, 40000, -100, -40000];
    let right: [i32; 4] = [32767, 32768, -32768, -32769];
    let initial = with_bytes(&state, XMM0, &cast_i32_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &cast_i32_bytes(&right))?;

    let decoded = make_decoded(
        forms::PACKSSDW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [100, 32767, -100, -32768, 32767, 32767, -32768, -32768];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = i16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2/SSE4 packed unsigned saturate integration tests
// ---------------------------------------------------------------------------

#[test]
fn packuswb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PACKUSWB: 8x16-bit signed → 16x8-bit unsigned, saturate to [0, 255]
    // dst = [100, 200, -100, 300, 50, -50, 0, 255]
    // src = [256, -1, 128, -200, 0, 1, 100, 200]
    // Expected: [100, 200, 0, 255, 50, 0, 0, 255, 255, 0, 128, 0, 0, 1, 100, 200]
    let left: [i16; 8] = [100, 200, -100, 300, 50, -50, 0, 255];
    let right: [i16; 8] = [256, -1, 128, -200, 0, 1, 100, 200];
    let mut left_bytes = Vec::new();
    for v in left { left_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut right_bytes = Vec::new();
    for v in right { right_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PACKUSWB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u8; 16] = [
        100, 200, 0, 255, 50, 0, 0, 255,
        255, 0, 128, 0, 0, 1, 100, 200,
    ];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(bytes[i], exp, "lane {i}: got {:#x}, expected {exp:#x}", bytes[i]);
    }
    Ok(())
}

#[test]
fn packusdw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PACKUSDW: 4x32-bit signed → 8x16-bit unsigned, saturate to [0, 65535]
    // dst = [100, 70000, -100, -1]
    // src = [65535, 65536, 0, -1000]
    // Expected: [100, 65535, 0, 0, 65535, 65535, 0, 0]
    let left: [i32; 4] = [100, 70000, -100, -1];
    let right: [i32; 4] = [65535, 65536, 0, -1000];
    let initial = with_bytes(&state, XMM0, &cast_i32_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &cast_i32_bytes(&right))?;

    let decoded = make_decoded(
        forms::PACKUSDW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [100, 65535, 0, 0, 65535, 65535, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed multiply and add integration test
// ---------------------------------------------------------------------------

#[test]
fn pmaddwd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMADDWD: 8x16-bit signed → 4x32-bit signed
    //   result[i] = left[2i] * right[2i] + left[2i+1] * right[2i+1]
    // left  = [1, 2, 3, 4, -1, -2, 100, 200]
    // right = [10, 20, 30, 40, -10, -20, 1, 2]
    // result[0] = 1*10 + 2*20 = 10 + 40 = 50
    // result[1] = 3*30 + 4*40 = 90 + 160 = 250
    // result[2] = -1*-10 + -2*-20 = 10 + 40 = 50
    // result[3] = 100*1 + 200*2 = 100 + 400 = 500
    let left: [i16; 8] = [1, 2, 3, 4, -1, -2, 100, 200];
    let right: [i16; 8] = [10, 20, 30, 40, -10, -20, 1, 2];
    let mut left_bytes = Vec::new();
    for v in left { left_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut right_bytes = Vec::new();
    for v in right { right_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &left_bytes)?;
    let initial = with_bytes(&initial, XMM1, &right_bytes)?;

    let decoded = make_decoded(
        forms::PMADDWD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [50, 250, 50, 500];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = i32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed sum of absolute differences integration test
// ---------------------------------------------------------------------------

#[test]
fn psadbw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSADBW: 16x8-bit unsigned → 2x64-bit
    //   result[0] = sum(|left[i] - right[i]| for i in 0..8)
    //   result[1] = sum(|left[i] - right[i]| for i in 8..16)
    // left  = [10, 20, 30, 40, 50, 60, 70, 80, 100, 200, 0, 0, 0, 0, 0, 0]
    // right = [5, 10, 15, 20, 25, 30, 35, 40, 50, 100, 0, 0, 0, 0, 0, 0]
    // block 0: |10-5|+|20-10|+|30-15|+|40-20|+|50-25|+|60-30|+|70-35|+|80-40|
    //        = 5+10+15+20+25+30+35+40 = 180
    // block 1: |100-50|+|200-100|+0+0+0+0+0+0 = 50+100 = 150
    let left: [u8; 16] = [10, 20, 30, 40, 50, 60, 70, 80, 100, 200, 0, 0, 0, 0, 0, 0];
    let right: [u8; 16] = [5, 10, 15, 20, 25, 30, 35, 40, 50, 100, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM0, &left)?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PSADBW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    // Block 0 (low 64 bits): 180
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[0..8]);
    let result0 = u64::from_le_bytes(buf);
    assert_eq!(result0, 180, "block 0: got {result0}, expected 180");
    // Block 1 (high 64 bits): 150
    buf.copy_from_slice(&bytes[8..16]);
    let result1 = u64::from_le_bytes(buf);
    assert_eq!(result1, 150, "block 1: got {result1}, expected 150");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shuffle doublewords integration test
// ---------------------------------------------------------------------------

#[test]
fn pshufd_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // PSHUFD: 4x32-bit → 4x32-bit, lane shuffle by imm8
    // src = [0x11111111, 0x22222222, 0x33333333, 0x44444444]
    // imm8 = 0x1B = 00 01 10 11 → dst[0]=src[3], dst[1]=src[2], dst[2]=src[1], dst[3]=src[0]
    // Expected: [0x44444444, 0x33333333, 0x22222222, 0x11111111]
    let src: [u32; 4] = [0x11111111, 0x22222222, 0x33333333, 0x44444444];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &src_bytes)?;

    let decoded = make_decoded(
        forms::PSHUFD_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 0x1B),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [0x44444444, 0x33333333, 0x22222222, 0x11111111];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shuffle high/low words integration tests
// ---------------------------------------------------------------------------

#[test]
fn pshufhw_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // PSHUFHW: shuffle high 4x16-bit lanes, low 64 bits unchanged
    // src = [0x0001, 0x0002, 0x0003, 0x0004, 0x1001, 0x2002, 0x3003, 0x4004]
    // imm8 = 0x1B = 00 01 10 11 → dst[4]=src[7], dst[5]=src[6], dst[6]=src[5], dst[7]=src[4]
    // Expected: [0x0001, 0x0002, 0x0003, 0x0004, 0x4004, 0x3003, 0x2002, 0x1001]
    let src: [u16; 8] = [0x0001, 0x0002, 0x0003, 0x0004, 0x1001, 0x2002, 0x3003, 0x4004];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &src_bytes)?;

    let decoded = make_decoded(
        forms::PSHUFHW_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 0x1B),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [0x0001, 0x0002, 0x0003, 0x0004, 0x4004, 0x3003, 0x2002, 0x1001];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pshuflw_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16)])?;
    // PSHUFLW: shuffle low 4x16-bit lanes, high 64 bits unchanged
    // src = [0x0001, 0x0002, 0x0003, 0x0004, 0x1001, 0x2002, 0x3003, 0x4004]
    // imm8 = 0x1B = 00 01 10 11 → dst[0]=src[3], dst[1]=src[2], dst[2]=src[1], dst[3]=src[0]
    // Expected: [0x0004, 0x0003, 0x0002, 0x0001, 0x1001, 0x2002, 0x3003, 0x4004]
    let src: [u16; 8] = [0x0001, 0x0002, 0x0003, 0x0004, 0x1001, 0x2002, 0x3003, 0x4004];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &src_bytes)?;

    let decoded = make_decoded(
        forms::PSHUFLW_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            imm8_operand(1, 0x1B),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [0x0004, 0x0003, 0x0002, 0x0001, 0x1001, 0x2002, 0x3003, 0x4004];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed multiply and add unsigned/signed bytes integration test
// ---------------------------------------------------------------------------

#[test]
fn pmaddubsw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMADDUBSW: 16x8-bit → 8x16-bit signed with saturation
    //   result[i] = sat((int8)left[2i] * (uint8)right[2i]
    //             + (int8)left[2i+1] * (uint8)right[2i+1])
    // left  (signed)   = [1, 2, 3, 4, -1, -2, 100, 100, 0, 0, 0, 0, 0, 0, 0, 0]
    // right (unsigned) = [10, 20, 30, 40, 10, 20, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    // result[0] = 1*10 + 2*20 = 10 + 40 = 50
    // result[1] = 3*30 + 4*40 = 90 + 160 = 250
    // result[2] = -1*10 + -2*20 = -10 + -40 = -50
    // result[3] = 100*1 + 100*1 = 200
    // result[4..7] = 0
    let left: [i8; 16] = [1, 2, 3, 4, -1, -2, 100, 100, 0, 0, 0, 0, 0, 0, 0, 0];
    let right: [u8; 16] = [10, 20, 30, 40, 10, 20, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM0, &cast_i8_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PMADDUBSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [50, 250, -50, 200, 0, 0, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = i16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn pmaddubsw_xmm_xmm_saturates() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // Saturation test: large products should saturate to [-32768, 32767]
    // left  (signed)   = [-128, -128, 127, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    // right (unsigned) = [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    // result[0] = sat(-128*255 + -128*255) = sat(-65280) = -32768
    // result[1] = sat(127*255 + 127*255) = sat(64770) = 32767
    let left: [i8; 16] = [-128, -128, 127, 127, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let right: [u8; 16] = [255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM0, &cast_i8_bytes(&left))?;
    let initial = with_bytes(&initial, XMM1, &right)?;

    let decoded = make_decoded(
        forms::PMADDUBSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;

    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [-32768, 32767, 0, 0, 0, 0, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = i16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE2 packed shift with register count integration tests
// ---------------------------------------------------------------------------

#[test]
fn psllw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSLLW: 8x16-bit logical left shift by count in low 64 bits of XMM1
    // src = [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008]
    // count = 4
    // expected = [0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x0070, 0x0080]
    let src: [u16; 8] = [0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&4u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSLLW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [0x0010, 0x0020, 0x0030, 0x0040, 0x0050, 0x0060, 0x0070, 0x0080];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(u16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psllw_xmm_xmm_overflow_clears() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSLLW with count >= 16 should clear all lanes
    let src: [u16; 8] = [0xFFFF; 8];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&20u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSLLW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    for i in 0..8 {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(u16::from_le_bytes(buf), 0, "lane {i} should be 0");
    }
    Ok(())
}

#[test]
fn pslld_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSLLD: 4x32-bit logical left shift by count in low 64 bits of XMM1
    let src: [u32; 4] = [0x00000001, 0x00000002, 0x00000003, 0x00000004];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&8u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSLLD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [0x00000100, 0x00000200, 0x00000300, 0x00000400];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(u32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psllq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSLLQ: 2x64-bit logical left shift by count in low 64 bits of XMM1
    let src: [u64; 2] = [0x0000000000000001, 0x0000000000000002];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&16u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSLLQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0x0000000000010000, 0x0000000000020000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        assert_eq!(u64::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psrlw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSRLW: 8x16-bit logical right shift by count in low 64 bits of XMM1
    let src: [u16; 8] = [0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&4u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSRLW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [0x0100, 0x0200, 0x0300, 0x0400, 0x0500, 0x0600, 0x0700, 0x0800];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(u16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psrld_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSRLD: 4x32-bit logical right shift by count in low 64 bits of XMM1
    let src: [u32; 4] = [0x00000100, 0x00000200, 0x00000300, 0x00000400];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&8u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSRLD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [0x00000001, 0x00000002, 0x00000003, 0x00000004];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(u32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psrlq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSRLQ: 2x64-bit logical right shift by count in low 64 bits of XMM1
    let src: [u64; 2] = [0x0000000000010000, 0x0000000000020000];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&16u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSRLQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0x0000000000000001, 0x0000000000000002];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        assert_eq!(u64::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psraw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSRAW: 8x16-bit arithmetic right shift by count in low 64 bits of XMM1
    // Sign bit is preserved.
    let src: [i16; 8] = [-16, -32, -48, -64, 16, 32, 48, 64];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&2u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSRAW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [-4, -8, -12, -16, 4, 8, 12, 16];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psrad_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSRAD: 4x32-bit arithmetic right shift by count in low 64 bits of XMM1
    let src: [i32; 4] = [-256, -512, 256, 512];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&4u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSRAD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [-16, -32, 16, 32];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(i32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psraw_xmm_xmm_saturates_to_sign() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSRAW with count >= 16 should sign-extend (negative → -1, positive → 0)
    let src: [i16; 8] = [-1, -100, 1, 100, -32768, 32767, 0, -1];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut count_bytes = [0u8; 16];
    count_bytes[0..4].copy_from_slice(&20u32.to_le_bytes());
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &count_bytes)?;

    let decoded = make_decoded(
        forms::PSRAW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [-1, -1, 0, 0, -1, 0, 0, -1];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 horizontal add/subtract integration tests
// ---------------------------------------------------------------------------

#[test]
fn phaddw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHADDW: horizontally add adjacent 16-bit lanes from two sources
    // src1 = [1, 2, 3, 4, 5, 6, 7, 8]
    // src2 = [10, 20, 30, 40, 50, 60, 70, 80]
    // result[0..3] = [1+2, 3+4, 5+6, 7+8] = [3, 7, 11, 15]
    // result[4..7] = [10+20, 30+40, 50+60, 70+80] = [30, 70, 110, 150]
    let src1: [i16; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let src2: [i16; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHADDW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [3, 7, 11, 15, 30, 70, 110, 150];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn phaddd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHADDD: horizontally add adjacent 32-bit lanes from two sources
    // src1 = [1, 2, 3, 4]
    // src2 = [10, 20, 30, 40]
    // result[0..1] = [1+2, 3+4] = [3, 7]
    // result[2..3] = [10+20, 30+40] = [30, 70]
    let src1: [i32; 4] = [1, 2, 3, 4];
    let src2: [i32; 4] = [10, 20, 30, 40];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHADDD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [3, 7, 30, 70];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(i32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn phsubw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHSUBW: horizontally subtract adjacent 16-bit lanes from two sources
    // src1 = [10, 1, 30, 3, 50, 5, 70, 7]
    // src2 = [100, 10, 200, 20, 300, 30, 400, 40]
    // result[0..3] = [10-1, 30-3, 50-5, 70-7] = [9, 27, 45, 63]
    // result[4..7] = [100-10, 200-20, 300-30, 400-40] = [90, 180, 270, 360]
    let src1: [i16; 8] = [10, 1, 30, 3, 50, 5, 70, 7];
    let src2: [i16; 8] = [100, 10, 200, 20, 300, 30, 400, 40];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHSUBW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [9, 27, 45, 63, 90, 180, 270, 360];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn phsubd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHSUBD: horizontally subtract adjacent 32-bit lanes from two sources
    // src1 = [100, 1, 300, 3]
    // src2 = [1000, 10, 2000, 20]
    // result[0..1] = [100-1, 300-3] = [99, 297]
    // result[2..3] = [1000-10, 2000-20] = [990, 1980]
    let src1: [i32; 4] = [100, 1, 300, 3];
    let src2: [i32; 4] = [1000, 10, 2000, 20];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHSUBD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [99, 297, 990, 1980];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(i32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed absolute value integration tests
// ---------------------------------------------------------------------------

#[test]
fn pabsb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PABSB: per-lane signed absolute value (8-bit)
    let src: [i8; 16] = [-1, 2, -3, 4, -5, 6, -127, 127, 0, -1, 100, -100, 0, 0, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PABSB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u8; 16] = [1, 2, 3, 4, 5, 6, 127, 127, 0, 1, 100, 100, 0, 0, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(bytes[i], exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn pabsw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PABSW: per-lane signed absolute value (16-bit)
    let src: [i16; 8] = [-1, 2, -3, 4, -32768, 32767, 0, -100];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PABSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    // Note: i16::MIN.abs() overflows to i16::MIN (0x8000), but wrapping_abs gives 0x8000
    // Intel PABSW: -32768 → 0x8000 (32768, which is -32768 as i16 but 0x8000 as u16)
    let expected: [u16; 8] = [1, 2, 3, 4, 0x8000, 32767, 0, 100];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(u16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn pabsd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PABSD: per-lane signed absolute value (32-bit)
    let src: [i32; 4] = [-1, 2, -3, 4];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PABSD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [1, 2, 3, 4];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(u32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 packed sign integration tests
// ---------------------------------------------------------------------------

#[test]
fn psignb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSIGNB: per-lane sign application (8-bit)
    // result[i] = src1[i] * sign(src2[i])
    let src1: [i8; 16] = [5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5];
    let src2: [i8; 16] = [1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1, -1, 0, 1];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PSIGNB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i8; 16] = [5, -5, 0, 5, -5, 0, 5, -5, 0, 5, -5, 0, 5, -5, 0, 5];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(bytes[i] as i8, exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psignw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSIGNW: per-lane sign application (16-bit)
    let src1: [i16; 8] = [100, 100, 100, 100, 100, 100, 100, 100];
    let src2: [i16; 8] = [1, -1, 0, 1, -1, 0, 1, -1];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PSIGNW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [100, -100, 0, 100, -100, 0, 100, -100];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn psignd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PSIGND: per-lane sign application (32-bit)
    let src1: [i32; 4] = [1000, 1000, 1000, 1000];
    let src2: [i32; 4] = [1, -1, 0, 1];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PSIGND_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [1000, -1000, 0, 1000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        assert_eq!(i32::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 PMULHRSW integration test
// ---------------------------------------------------------------------------

#[test]
fn pmulhrsw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMULHRSW: packed multiply high with round and scale
    //   result[i] = ((int16)src1[i] * (int16)src2[i] + 0x4000) >> 15
    // Test: 2 * 3 = 6, (6 + 16384) >> 15 = 0 (6 is too small to round up)
    // Test: 100 * 200 = 20000, (20000 + 16384) >> 15 = 1
    // Test: 1000 * 1000 = 1000000, (1000000 + 16384) >> 15 = 30
    // Test: -100 * 200 = -20000, (-20000 + 16384) >> 15 = -1
    let src1: [i16; 8] = [2, 100, 1000, -100, 0, 0, 0, 0];
    let src2: [i16; 8] = [3, 200, 1000, 200, 0, 0, 0, 0];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PMULHRSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [0, 1, 31, -1, 0, 0, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSSE3 PHADDSW/PHSUBSW integration tests
// ---------------------------------------------------------------------------

#[test]
fn phaddsw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHADDSW: horizontally add adjacent pairs of lanes with saturation
    // src1 = [1, 2, 3, 4, 5, 6, 7, 8]
    // src2 = [10, 20, 30, 40, 50, 60, 70, 80]
    // result[0..3] = [1+2, 3+4, 5+6, 7+8] = [3, 7, 11, 15]
    // result[4..7] = [10+20, 30+40, 50+60, 70+80] = [30, 70, 110, 150]
    let src1: [i16; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let src2: [i16; 8] = [10, 20, 30, 40, 50, 60, 70, 80];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHADDSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [3, 7, 11, 15, 30, 70, 110, 150];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn phaddsw_xmm_xmm_saturates() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHADDSW saturation: 30000 + 30000 = 60000 → saturate to 32767
    let src1: [i16; 8] = [30000, 30000, -30000, -30000, 0, 0, 0, 0];
    let src2: [i16; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHADDSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [32767, -32768, 0, 0, 0, 0, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn phsubsw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHSUBSW: horizontally subtract adjacent pairs of lanes with saturation
    // src1 = [10, 1, 30, 3, 50, 5, 70, 7]
    // src2 = [100, 10, 200, 20, 300, 30, 400, 40]
    // result[0..3] = [10-1, 30-3, 50-5, 70-7] = [9, 27, 45, 63]
    // result[4..7] = [100-10, 200-20, 300-30, 400-40] = [90, 180, 270, 360]
    let src1: [i16; 8] = [10, 1, 30, 3, 50, 5, 70, 7];
    let src2: [i16; 8] = [100, 10, 200, 20, 300, 30, 400, 40];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHSUBSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [9, 27, 45, 63, 90, 180, 270, 360];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

#[test]
fn phsubsw_xmm_xmm_saturates() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PHSUBSW saturation: -30000 - 30000 = -60000 → saturate to -32768
    let src1: [i16; 8] = [-30000, 30000, 0, 0, 0, 0, 0, 0];
    let src2: [i16; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PHSUBSW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [-32768, 0, 0, 0, 0, 0, 0, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        assert_eq!(i16::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PCMPEQQ integration test
// ---------------------------------------------------------------------------

#[test]
fn pcmpeqq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PCMPEQQ: per-lane 64-bit equality mask
    let src1: [u64; 2] = [0x123456789ABCDEF0, 0xFFFFFFFFFFFFFFFF];
    let src2: [u64; 2] = [0x123456789ABCDEF0, 0x0000000000000000];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PCMPEQQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0xFFFFFFFFFFFFFFFF, 0x0000000000000000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        assert_eq!(u64::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PMULDQ integration test
// ---------------------------------------------------------------------------

#[test]
fn pmuldq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMULDQ: per 64-bit lane, take low 32 bits as signed, multiply to 64-bit
    // src1 = [0x0000000A_FFFFFFFF, 0x00000064_00000005]
    //   lane0: low32 = 0xFFFFFFFF = -1 (signed), lane1: low32 = 0x00000005 = 5
    // src2 = [0x00000003_00000002, 0x00000064_00000006]
    //   lane0: low32 = 0x00000002 = 2, lane1: low32 = 0x00000006 = 6
    // result[0] = -1 * 2 = -2 (0xFFFFFFFFFFFFFFFE)
    // result[1] = 5 * 6 = 30 (0x000000000000001E)
    let src1: [u64; 2] = [0x0000000AFFFFFFFF, 0x0000006400000005];
    let src2: [u64; 2] = [0x0000000300000002, 0x0000006400000006];
    let mut bytes1 = Vec::new();
    for v in src1 { bytes1.extend_from_slice(&v.to_le_bytes()); }
    let mut bytes2 = Vec::new();
    for v in src2 { bytes2.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &bytes1)?;
    let initial = with_bytes(&initial, XMM1, &bytes2)?;

    let decoded = make_decoded(
        forms::PMULDQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0xFFFFFFFFFFFFFFFE, 0x000000000000001E];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        assert_eq!(u64::from_le_bytes(buf), exp, "lane {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PBLENDVB integration test
// ---------------------------------------------------------------------------

#[test]
fn pblendvb_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16), (XMM2, 16)])?;
    // PBLENDVB: per-byte variable blend
    //   result[i] = if mask[i] & 0x80 != 0 { src[i] } else { dst[i] }
    let dst: [u8; 16] = [0xAA; 16];
    let src: [u8; 16] = [0xBB; 16];
    // mask: alternating bytes with bit 7 set/clear
    let mask: [u8; 16] = [0x80, 0x00, 0xFF, 0x00, 0x80, 0x00, 0xFF, 0x00,
                          0x80, 0x00, 0xFF, 0x00, 0x80, 0x00, 0xFF, 0x00];
    let initial = with_bytes(&state, XMM0, &dst)?;
    let initial = with_bytes(&initial, XMM1, &src)?;
    let initial = with_bytes(&initial, XMM2, &mask)?;

    let decoded = make_decoded(
        forms::PBLENDVB_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            xmm_operand(2, XMM2, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u8; 16] = [0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA,
                             0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB, 0xAA];
    for (i, &exp) in expected.iter().enumerate() {
        assert_eq!(bytes[i], exp, "byte {i}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed move with sign/zero extend integration tests
// ---------------------------------------------------------------------------

#[test]
fn pmovsxbw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVSXBW: sign-extend low 8 bytes to 8 words
    // src = [0x7F, 0x80, 0xFF, 0x00, 0x01, 0x02, 0x7E, 0xFE, ...]
    let src: [i8; 16] = [0x7F, -0x80, -1, 0, 1, 2, 0x7E, -2, 0, 0, 0, 0, 0, 0, 0, 0];
    let src_bytes: Vec<u8> = src.iter().map(|&v| v as u8).collect();
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVSXBW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i16; 8] = [0x7F, -0x80, -1, 0, 1, 2, 0x7E, -2];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = i16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovzxbw_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVZXBW: zero-extend low 8 bytes to 8 words
    let src: [u8; 16] = [0x7F, 0x80, 0xFF, 0x00, 0x01, 0x02, 0x7E, 0xFE, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM1, &src)?;

    let decoded = make_decoded(
        forms::PMOVZXBW_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [0x007F, 0x0080, 0x00FF, 0x0000, 0x0001, 0x0002, 0x007E, 0x00FE];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovsxbd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVSXBD: sign-extend low 4 bytes to 4 dwords
    let src: [i8; 16] = [0x7F, -0x80, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let src_bytes: Vec<u8> = src.iter().map(|&v| v as u8).collect();
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVSXBD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [0x7F, -0x80, -1, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = i32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovzxbd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [u8; 16] = [0x7F, 0x80, 0xFF, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM1, &src)?;

    let decoded = make_decoded(
        forms::PMOVZXBD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [0x0000007F, 0x00000080, 0x000000FF, 0x00000000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovsxwd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVSXWD: sign-extend low 4 words to 4 dwords
    let src: [i16; 8] = [0x7FFF, -0x8000, -1, 0, 0, 0, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVSXWD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i32; 4] = [0x7FFF, -0x8000, -1, 0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = i32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovzxwd_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [u16; 8] = [0x7FFF, 0x8000, 0xFFFF, 0x0000, 0, 0, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVZXWD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [0x00007FFF, 0x00008000, 0x0000FFFF, 0x00000000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovsxdq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVSXDQ: sign-extend low 2 dwords to 2 qwords
    let src: [i32; 4] = [0x7FFFFFFF, -0x80000000, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVSXDQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i64; 2] = [0x7FFFFFFF, -0x80000000_i64];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = i64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovzxdq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [u32; 4] = [0x7FFFFFFF, 0x80000000, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVZXDQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0x000000007FFFFFFF, 0x0000000080000000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovsxwq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVSXWQ: sign-extend low 2 words to 2 qwords
    let src: [i16; 8] = [0x7FFF, -0x8000, 0, 0, 0, 0, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVSXWQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i64; 2] = [0x7FFF, -0x8000_i64];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = i64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovzxwq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [u16; 8] = [0x7FFF, 0x8000, 0, 0, 0, 0, 0, 0];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVZXWQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0x0000000000007FFF, 0x0000000000008000];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovsxbq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PMOVSXBQ: sign-extend low 2 bytes to 2 qwords
    let src: [i8; 16] = [0x7F, -0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let src_bytes: Vec<u8> = src.iter().map(|&v| v as u8).collect();
    let initial = with_bytes(&state, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PMOVSXBQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [i64; 2] = [0x7F, -0x80_i64];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = i64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn pmovzxbq_xmm_xmm_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [u8; 16] = [0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM1, &src)?;

    let decoded = make_decoded(
        forms::PMOVZXBQ_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Write),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0x000000000000007F, 0x0000000000000080];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 immediate blend integration tests
// ---------------------------------------------------------------------------

#[test]
fn pblendw_xmm_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // PBLENDW: blend 8x16-bit lanes by imm8 (bit set → src, clear → dst)
    // imm8 = 0xAA = 10101010 → lanes 1,3,5,7 from src, lanes 0,2,4,6 from dst
    let dst: [u16; 8] = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888];
    let src: [u16; 8] = [0xAAAA, 0xBBBB, 0xCCCC, 0xDDDD, 0xEEEE, 0xFFFF, 0x0000, 0x1111];
    let mut dst_bytes = Vec::new();
    for v in dst { dst_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &dst_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::PBLENDW_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0xAA),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u16; 8] = [0x1111, 0xBBBB, 0x3333, 0xDDDD, 0x5555, 0xFFFF, 0x7777, 0x1111];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[i * 2..(i + 1) * 2]);
        let result = u16::from_le_bytes(buf);
        assert_eq!(result, exp, "lane {i}: got {result:#x}, expected {exp:#x}");
    }
    Ok(())
}

#[test]
fn blendps_xmm_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // BLENDPS: blend 4x32-bit float lanes by imm8 (bit set → src, clear → dst)
    // imm8 = 0x5 = 0101 → lanes 0,2 from src, lanes 1,3 from dst
    let dst: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
    let src: [f32; 4] = [10.0, 20.0, 30.0, 40.0];
    let mut dst_bytes = Vec::new();
    for v in dst { dst_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &dst_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::BLENDPS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0x5),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f32; 4] = [10.0, 2.0, 30.0, 4.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-6, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn blendpd_xmm_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // BLENDPD: blend 2x64-bit float lanes by imm8 (bit set → src, clear → dst)
    // imm8 = 0x2 = 10 → lane 0 from dst, lane 1 from src
    let dst: [f64; 2] = [1.0, 2.0];
    let src: [f64; 2] = [10.0, 20.0];
    let mut dst_bytes = Vec::new();
    for v in dst { dst_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &dst_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::BLENDPD_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0x2),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f64; 2] = [1.0, 20.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = f64::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-12, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed dot product integration tests
// ---------------------------------------------------------------------------

#[test]
fn dpps_xmm_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // DPPS: dot product of 4x32-bit floats with selection/broadcast by imm8
    // imm8 = 0xFF: multiply all 4 lanes, sum, broadcast to all 4 output lanes
    // src1 = [1.0, 2.0, 3.0, 4.0], src2 = [5.0, 6.0, 7.0, 8.0]
    // dot = 1*5 + 2*6 + 3*7 + 4*8 = 5+12+21+32 = 70.0
    let src1: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
    let src2: [f32; 4] = [5.0, 6.0, 7.0, 8.0];
    let mut s1_bytes = Vec::new();
    for v in src1 { s1_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut s2_bytes = Vec::new();
    for v in src2 { s2_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &s1_bytes)?;
    let initial = with_bytes(&initial, XMM1, &s2_bytes)?;

    let decoded = make_decoded(
        forms::DPPS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0xFF),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let dot: f32 = 70.0;
    for i in 0..4 {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - dot).abs() < 1e-4, "lane {i}: got {result}, expected {dot}");
    }
    Ok(())
}

#[test]
fn dppd_xmm_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // DPPD: dot product of 2x64-bit floats with selection/broadcast by imm8
    // imm8 = 0xFF: multiply both lanes, sum, broadcast to both output lanes
    // src1 = [1.0, 2.0], src2 = [3.0, 4.0]
    // dot = 1*3 + 2*4 = 3+8 = 11.0
    let src1: [f64; 2] = [1.0, 2.0];
    let src2: [f64; 2] = [3.0, 4.0];
    let mut s1_bytes = Vec::new();
    for v in src1 { s1_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut s2_bytes = Vec::new();
    for v in src2 { s2_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &s1_bytes)?;
    let initial = with_bytes(&initial, XMM1, &s2_bytes)?;

    let decoded = make_decoded(
        forms::DPPD_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0xFF),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let dot: f64 = 11.0;
    for i in 0..2 {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = f64::from_le_bytes(buf);
        assert!((result - dot).abs() < 1e-10, "lane {i}: got {result}, expected {dot}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 byte extract/insert integration tests
// ---------------------------------------------------------------------------

#[test]
fn pinsrb_xmm_r32_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // PINSRB: insert low byte of RAX into XMM0 at byte index 2
    // XMM0 initial = all zeros, RAX = 0xAB
    // Expected: XMM0[2] = 0xAB, rest = 0
    let xmm_init = [0u8; 16];
    let initial = with_bytes(&state, XMM0, &xmm_init)?;
    let initial = with_bytes(&initial, RAX, &0xAB_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PINSRB_XMM_R32_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            reg_operand(1, RAX, AccessKind::Read),
            imm8_operand(2, 2),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    assert_eq!(bytes[2], 0xAB, "byte 2: got {:#x}, expected 0xAB", bytes[2]);
    for (i, &b) in bytes.iter().enumerate() {
        if i != 2 {
            assert_eq!(b, 0, "byte {i}: got {b:#x}, expected 0");
        }
    }
    Ok(())
}

#[test]
fn pinsrb_preserves_other_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // PINSRB: insert byte at index 5, verify other bytes preserved
    let xmm_init: [u8; 16] = [0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                              0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F];
    let initial = with_bytes(&state, XMM0, &xmm_init)?;
    let initial = with_bytes(&initial, RAX, &0xFF_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PINSRB_XMM_R32_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            reg_operand(1, RAX, AccessKind::Read),
            imm8_operand(2, 5),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let mut expected = xmm_init;
    expected[5] = 0xFF;
    for (i, (&got, &exp)) in bytes.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, exp, "byte {i}: got {got:#x}, expected {exp:#x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE/SSE2 scalar float compare with flags integration tests
// ---------------------------------------------------------------------------

#[test]
fn ucomiss_greater_than_sets_no_flags() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &5.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &3.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::UCOMISS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::Read),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 0, "ZF/CF/PF should all be 0 when src1 > src2");
    Ok(())
}

#[test]
fn ucomiss_less_than_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &2.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &5.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::UCOMISS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::Read),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 1, "CF should be set when src1 < src2");
    Ok(())
}

#[test]
fn ucomiss_equal_sets_zf() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &3.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &3.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::UCOMISS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::Read),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 0x40, "ZF should be set when src1 == src2");
    Ok(())
}

#[test]
fn ucomiss_nan_sets_zf_cf_pf() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &f32::NAN.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &3.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::UCOMISS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::Read),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 0x45, "ZF/CF/PF should all be set for NaN");
    Ok(())
}

#[test]
fn ucomisd_less_than_sets_cf() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 8), (XMM1, 8), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &1.0f64.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &2.0f64.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::UCOMISD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 64, AccessKind::Read),
            xmm_operand(1, XMM1, 64, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 1, "CF should be set when src1 < src2");
    Ok(())
}

#[test]
fn comiss_greater_than_sets_no_flags() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 4), (XMM1, 4), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &10.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &3.0f32.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::COMISS_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 32, AccessKind::Read),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 0, "ZF/CF/PF should all be 0 when src1 > src2");
    Ok(())
}

#[test]
fn comisd_equal_sets_zf() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 8), (XMM1, 8), (RFLAGS, 8)])?;
    let initial = with_bytes(&state, XMM0, &7.0f64.to_le_bytes())?;
    let initial = with_bytes(&initial, XMM1, &7.0f64.to_le_bytes())?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::COMISD_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 64, AccessKind::Read),
            xmm_operand(1, XMM1, 64, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x45, 0x40, "ZF should be set when src1 == src2");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 packed/scalar round with imm8 integration tests
// ---------------------------------------------------------------------------

#[test]
fn roundps_xmm_xmm_imm8_round_nearest() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // ROUNDPS: round 4x32-bit floats, imm8=0 (nearest)
    let src: [f32; 4] = [1.4, 2.5, 3.6, -0.5];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::ROUNDPS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f32; 4] = [1.0, 3.0, 4.0, -1.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-6, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn roundps_xmm_xmm_imm8_round_truncate() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [f32; 4] = [1.9, 2.1, -3.8, -4.2];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::ROUNDPS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 3),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f32; 4] = [1.0, 2.0, -3.0, -4.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-6, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn roundpd_xmm_xmm_imm8_round_down() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    let src: [f64; 2] = [1.9, -2.1];
    let mut src_bytes = Vec::new();
    for v in src { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &src_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::ROUNDPD_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 1),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f64; 2] = [1.0, -3.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = f64::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-10, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn roundss_xmm_xmm_imm8_preserves_upper() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 4)])?;
    // ROUNDSS: round low 32-bit float, upper lanes from src1
    // src1 = [1.7, 10.0, 20.0, 30.0], src2 = [2.3, ...]
    // imm8 = 0 (nearest) → low = 2.0, upper = [10.0, 20.0, 30.0]
    let src1: [f32; 4] = [1.7, 10.0, 20.0, 30.0];
    let mut s1_bytes = Vec::new();
    for v in src1 { s1_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &s1_bytes)?;
    let initial = with_bytes(&initial, XMM1, &2.3f32.to_le_bytes())?;

    let decoded = make_decoded(
        forms::ROUNDSS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 32, AccessKind::Read),
            imm8_operand(2, 0),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f32; 4] = [2.0, 10.0, 20.0, 30.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-6, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn roundsd_xmm_xmm_imm8_preserves_upper() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 8)])?;
    // ROUNDSD: round low 64-bit float, upper lane from src1
    // src1 = [1.3, 50.0], src2 = [2.6]
    // imm8 = 0 (nearest) → low = 3.0, upper = 50.0
    let src1: [f64; 2] = [1.3, 50.0];
    let mut s1_bytes = Vec::new();
    for v in src1 { s1_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &s1_bytes)?;
    let initial = with_bytes(&initial, XMM1, &2.6f64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::ROUNDSD_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 64, AccessKind::Read),
            imm8_operand(2, 0),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f64; 2] = [3.0, 50.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = f64::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-10, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 PTEST integration tests
// ---------------------------------------------------------------------------

#[test]
fn ptest_sets_zf_when_and_is_zero() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16), (RFLAGS, 8)])?;
    // PTEST: ZF=1 if (dst AND src) == 0, CF=1 if ((NOT dst) AND src) == 0
    // dst = 0xFF00, src = 0x00FF → AND = 0 → ZF=1
    // NOT dst = 0x00FF, NOT dst AND src = 0x00FF → CF=0
    let dst: [u8; 16] = [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let src: [u8; 16] = [0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let initial = with_bytes(&state, XMM0, &dst)?;
    let initial = with_bytes(&initial, XMM1, &src)?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PTEST_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Read),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x41, 0x40, "ZF should be set, CF should be clear");
    Ok(())
}

#[test]
fn ptest_sets_cf_when_not_dst_and_src_is_zero() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16), (RFLAGS, 8)])?;
    // dst = 0xFFFF, src = 0xFFFF → AND = 0xFFFF → ZF=0
    // NOT dst = 0x0000, NOT dst AND src = 0 → CF=1
    let dst: [u8; 16] = [0xFF; 16];
    let src: [u8; 16] = [0xFF; 16];
    let initial = with_bytes(&state, XMM0, &dst)?;
    let initial = with_bytes(&initial, XMM1, &src)?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PTEST_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Read),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x41, 0x01, "ZF should be clear, CF should be set");
    Ok(())
}

#[test]
fn ptest_sets_both_zf_and_cf_when_src_zero() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16), (RFLAGS, 8)])?;
    // dst = anything, src = 0 → AND = 0 → ZF=1; NOT dst AND 0 = 0 → CF=1
    let dst: [u8; 16] = [0xAB; 16];
    let src: [u8; 16] = [0; 16];
    let initial = with_bytes(&state, XMM0, &dst)?;
    let initial = with_bytes(&initial, XMM1, &src)?;
    let initial = with_bytes(&initial, RFLAGS, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PTEST_XMM_XMM,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::Read),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let rflags = read_reg(&executed, RFLAGS)?;
    assert_eq!(rflags & 0x41, 0x41, "ZF and CF should both be set");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.2 CRC32 integration tests
// ---------------------------------------------------------------------------

#[test]
fn crc32_r32_r32_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(RAX, 8), (RCX, 8)])?;
    let initial = with_bytes(&state, RAX, &0u64.to_le_bytes())?;
    let initial = with_bytes(&initial, RCX, &0x00000001_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::CRC32_R32_R32,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 0xDD45AAB8, "CRC32C of 0x00000001");
    Ok(())
}

#[test]
fn crc32_r32_r32_known_value() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(RAX, 8), (RCX, 8)])?;
    let initial = with_bytes(&state, RAX, &0u64.to_le_bytes())?;
    let initial = with_bytes(&initial, RCX, &0x12345678_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::CRC32_R32_R32,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 0xFA745634, "CRC32C of 0x12345678");
    Ok(())
}

#[test]
fn crc32_r64_r64_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(RAX, 8), (RCX, 8)])?;
    let initial = with_bytes(&state, RAX, &0u64.to_le_bytes())?;
    let initial = with_bytes(&initial, RCX, &0x0000000000000001_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::CRC32_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 0x493C7D27, "CRC32C of 0x0000000000000001");
    Ok(())
}

#[test]
fn crc32_r64_r64_known_value() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(RAX, 8), (RCX, 8)])?;
    let initial = with_bytes(&state, RAX, &0u64.to_le_bytes())?;
    let initial = with_bytes(&initial, RCX, &0x0123456789ABCDEF_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::CRC32_R64_R64,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            reg_operand(1, RCX, AccessKind::Read),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 0xE9986AA9, "CRC32C of 0x0123456789ABCDEF");
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 dword/qword extract/insert integration tests
// ---------------------------------------------------------------------------

#[test]
fn pextrd_r32_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // PEXTRD: extract dword at index 1 from XMM0
    // XMM0 = [0x11112222, 0x33334444, 0x55556666, 0x77778888]
    let xmm_init: [u32; 4] = [0x11112222, 0x33334444, 0x55556666, 0x77778888];
    let mut xmm_bytes = Vec::new();
    for v in xmm_init { xmm_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &xmm_bytes)?;
    let initial = with_bytes(&initial, RAX, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PEXTRD_R32_XMM_IMM8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            xmm_operand(1, XMM0, 128, AccessKind::Read),
            imm8_operand(2, 1),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 0x33334444, "dword at index 1");
    Ok(())
}

#[test]
fn pextrq_r64_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // PEXTRQ: extract qword at index 1 from XMM0
    // XMM0 = [0x1111222233334444, 0x5555666677778888]
    let xmm_init: [u64; 2] = [0x1111222233334444, 0x5555666677778888];
    let mut xmm_bytes = Vec::new();
    for v in xmm_init { xmm_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &xmm_bytes)?;
    let initial = with_bytes(&initial, RAX, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PEXTRQ_R64_XMM_IMM8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            xmm_operand(1, XMM0, 128, AccessKind::Read),
            imm8_operand(2, 1),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 0x5555666677778888, "qword at index 1");
    Ok(())
}

#[test]
fn pinsrd_xmm_r32_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // PINSRD: insert dword from RAX into XMM0 at index 2
    // XMM0 = [0x11112222, 0x33334444, 0x55556666, 0x77778888]
    // RAX = 0xDEADBEEF
    // Expected: XMM0[2] = 0xDEADBEEF, rest unchanged
    let xmm_init: [u32; 4] = [0x11112222, 0x33334444, 0x55556666, 0x77778888];
    let mut xmm_bytes = Vec::new();
    for v in xmm_init { xmm_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &xmm_bytes)?;
    let initial = with_bytes(&initial, RAX, &0xDEADBEEF_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PINSRD_XMM_R32_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            reg_operand(1, RAX, AccessKind::Read),
            imm8_operand(2, 2),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u32; 4] = [0x11112222, 0x33334444, 0xDEADBEEF, 0x77778888];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = u32::from_le_bytes(buf);
        assert_eq!(result, exp, "dword {i}: got {result:#010x}, expected {exp:#010x}");
    }
    Ok(())
}

#[test]
fn pinsrq_xmm_r64_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // PINSRQ: insert qword from RAX into XMM0 at index 0
    // XMM0 = [0x1111222233334444, 0x5555666677778888]
    // RAX = 0xDEADBEEFCAFEBABE
    // Expected: XMM0[0] = 0xDEADBEEFCAFEBABE, XMM0[1] = 0x5555666677778888
    let xmm_init: [u64; 2] = [0x1111222233334444, 0x5555666677778888];
    let mut xmm_bytes = Vec::new();
    for v in xmm_init { xmm_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &xmm_bytes)?;
    let initial = with_bytes(&initial, RAX, &0xDEADBEEFCAFEBABE_u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::PINSRQ_XMM_R64_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            reg_operand(1, RAX, AccessKind::Read),
            imm8_operand(2, 0),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [u64; 2] = [0xDEADBEEFCAFEBABE, 0x5555666677778888];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        let result = u64::from_le_bytes(buf);
        assert_eq!(result, exp, "qword {i}: got {result:#018x}, expected {exp:#018x}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Phase 4b: SSE4.1 INSERTPS/EXTRACTPS integration tests
// ---------------------------------------------------------------------------

#[test]
fn extractps_r32_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (RAX, 8)])?;
    // EXTRACTPS: extract float dword at index 2 from XMM0, store raw bits in RAX
    // XMM0 = [1.0, 2.0, 3.0, 4.0]
    let xmm_init: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
    let mut xmm_bytes = Vec::new();
    for v in xmm_init { xmm_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &xmm_bytes)?;
    let initial = with_bytes(&initial, RAX, &0u64.to_le_bytes())?;

    let decoded = make_decoded(
        forms::EXTRACTPS_R32_XMM_IMM8,
        vec![
            reg_operand(0, RAX, AccessKind::Write),
            xmm_operand(1, XMM0, 128, AccessKind::Read),
            imm8_operand(2, 2),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let result = read_reg(&executed, RAX)?;
    assert_eq!(result, 3.0f32.to_bits() as u64, "extracted float bits for 3.0f");
    Ok(())
}

#[test]
fn insertps_xmm_xmm_imm8_executes() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // INSERTPS: insert dword from src (XMM1) at src_idx=1 into dst (XMM0) at dst_idx=2
    // imm8 = (src_idx << 2) | dst_idx = (1 << 2) | 2 = 0x06
    // XMM0 = [10.0, 20.0, 30.0, 40.0], XMM1 = [1.0, 2.0, 3.0, 4.0]
    // Expected: XMM0[2] = XMM1[1] = 2.0, rest unchanged
    let dst_init: [f32; 4] = [10.0, 20.0, 30.0, 40.0];
    let src_init: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
    let mut dst_bytes = Vec::new();
    for v in dst_init { dst_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut src_bytes = Vec::new();
    for v in src_init { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &dst_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::INSERTPS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0x06),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f32; 4] = [10.0, 20.0, 2.0, 40.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-6, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}

#[test]
fn insertps_zmask_zeroes_dwords() -> Result<(), Box<dyn std::error::Error>> {
    let state = make_float_state(&[(XMM0, 16), (XMM1, 16)])?;
    // INSERTPS with ZMASK: insert dword from src at src_idx=0 into dst at dst_idx=0
    // ZMASK = 0b1010 → zero out dwords 1 and 3
    // imm8 = (zmask << 4) | (src_idx << 2) | dst_idx = (0b1010 << 4) | 0 = 0xA0
    // XMM0 = [10.0, 20.0, 30.0, 40.0], XMM1 = [1.0, 2.0, 3.0, 4.0]
    // Expected: XMM0[0] = 1.0, XMM0[1] = 0.0, XMM0[2] = 30.0, XMM0[3] = 0.0
    let dst_init: [f32; 4] = [10.0, 20.0, 30.0, 40.0];
    let src_init: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
    let mut dst_bytes = Vec::new();
    for v in dst_init { dst_bytes.extend_from_slice(&v.to_le_bytes()); }
    let mut src_bytes = Vec::new();
    for v in src_init { src_bytes.extend_from_slice(&v.to_le_bytes()); }
    let initial = with_bytes(&state, XMM0, &dst_bytes)?;
    let initial = with_bytes(&initial, XMM1, &src_bytes)?;

    let decoded = make_decoded(
        forms::INSERTPS_XMM_XMM_IMM8,
        vec![
            xmm_operand(0, XMM0, 128, AccessKind::ReadWrite),
            xmm_operand(1, XMM1, 128, AccessKind::Read),
            imm8_operand(2, 0xA0),
        ],
    );

    let (executed, _outcome) = run_pipeline(&decoded, &initial)?;
    let bytes = read_bytes(&executed, XMM0)?;
    let expected: [f32; 4] = [1.0, 0.0, 30.0, 0.0];
    for (i, &exp) in expected.iter().enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[i * 4..(i + 1) * 4]);
        let result = f32::from_le_bytes(buf);
        assert!((result - exp).abs() < 1e-6, "lane {i}: got {result}, expected {exp}");
    }
    Ok(())
}
