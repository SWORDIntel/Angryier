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
