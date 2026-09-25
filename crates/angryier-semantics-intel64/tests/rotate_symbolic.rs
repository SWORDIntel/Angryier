#![forbid(unsafe_code)]

//! Symbolic/concolic differential for the rewired ROL/ROR providers.
//!
//! The handwritten rotate forms emit `PrimitiveOp::RotateLeft/Right`
//! directly (no shl/lshr/or decomposition), so the symbolic image of a
//! rotate is one rotate node over the value operand. These tests lower
//! each rewired form through the real provider -> seal -> lower pipeline
//! and check:
//!
//! - the symbolic evaluator over a symbolic value register produces a
//!   single rotate node (structural: no `Or`/`Shl`/`LShr` anywhere in the
//!   result's expression DAG);
//! - the rotate-count masking is x86's (count mod 64 for 64-bit operands,
//!   count mod 32 for 32-bit operands), agreed three ways: the concrete
//!   interpreter, the concolic shadow over a symbolic-count register, and
//!   `u64/u32::rotate_*` as the reference — including counts above the
//!   width and a zero masked count.

use std::collections::{BTreeMap, HashSet};

use angryier_arch::{
    AccessKind, DecodedInstruction, InstructionModifiers, Operand, OperandKind, OperandVisibility, RegisterId,
    RegisterView, RegisterWriteBehavior,
};
use angryier_arch_intel64::register_id;
use angryier_execution::{
    ConcolicEvaluator, ConcolicImage, ConcreteInterpreter, ExecutionEngine, ExecutionMode, SymbolicEvaluator,
    constant_value,
};
use angryier_expr::{ExprArena, ExprOp, ShardedExprArena};
use angryier_ir::{BasicSemanticLowerer, IrBlock, IrType};
use angryier_memory::{MemoryError, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterError, RegisterState,
    StateOwnership,
};
use angryier_types::{
    BlockId, ExpressionNormalizationVersion, FidelityProfile, ImageId, ObjectId, SemanticVersion, StateId,
    TargetProfileId,
};

const RAX: u32 = register_id::GPR_BASE;
const RCX: u32 = register_id::GPR_BASE + 1;
const RFLAGS: u32 = register_id::RFLAGS.0;

const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(3);
const BLOCK_ADDR: u64 = 0x1000;

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

fn r64_operand(index: u8, reg: u32, access: AccessKind) -> Operand {
    Operand {
        index,
        width_bits: 64,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(RegisterView::full(RegisterId(reg), 64)),
    }
}

/// A 32-bit dword view shaped like a real decode of `%eax`: the write
/// zero-extends the parent register.
fn r32_operand(index: u8, reg: u32, access: AccessKind) -> Operand {
    Operand {
        index,
        width_bits: 32,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(RegisterView::partial(
            RegisterId(reg),
            0,
            32,
            RegisterWriteBehavior::ZeroExtendParent,
        )),
    }
}

fn imm8_operand(index: u8, value: u64) -> Operand {
    Operand {
        index,
        width_bits: 8,
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

fn make_memory() -> Result<PersistentMemory, MemoryError> {
    PersistentMemory::new(vec![MemoryRegion {
        object: ObjectId(1),
        base: BLOCK_ADDR,
        size: 0x1000,
        readable: true,
        writable: true,
        executable: true,
    }])
}

/// Emits and lowers one rotate form; the decoded shape mirrors a real XED
/// decode (a full 64-bit view, or a zero-extending 32-bit view plus imm8).
fn lower_form(form: u32, is_32bit: bool, imm_count: Option<u64>) -> Result<IrBlock, BoxError> {
    let mut operands = vec![if is_32bit {
        r32_operand(0, RAX, AccessKind::ReadWrite)
    } else {
        r64_operand(0, RAX, AccessKind::ReadWrite)
    }];
    match imm_count {
        Some(count) => operands.push(imm8_operand(1, count)),
        None => operands.push(r64_operand(1, RCX, AccessKind::Read)),
    }
    let decoded = make_decoded(form, operands);
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let provider = registry.provider_for_form(form).ok_or("no provider for form")?;
    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|e| format!("emit: {e:?}"))?;
    let sealed = builder
        .seal(
            angryier_types::ContentIdentitySchemaVersion(1),
            angryier_types::SemanticFingerprintSchemaVersion(1),
        )
        .map_err(|e| format!("seal: {e:?}"))?;
    let memory = make_memory()?;
    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(2),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: memory.code_version_guards_for_range(BLOCK_ADDR, 1)?,
    };
    Ok(BasicSemanticLowerer
        .lower_with_decode(&sealed, &key, &decoded)
        .map_err(|e| format!("lower: {e:?}"))?)
}

/// Every rewired handwritten rotate form.
const R64_FORMS: [(u32, bool, &str); 4] = [
    (forms::ROL_R64_IMM8, false, "rolq_imm8"),
    (forms::ROR_R64_IMM8, false, "rorq_imm8"),
    (forms::ROL_R64_CL, false, "rolq_cl"),
    (forms::ROR_R64_CL, false, "rorq_cl"),
];
const R32_FORMS: [(u32, bool, &str); 4] = [
    (forms::ROL_R32_IMM8, true, "roll_imm8"),
    (forms::ROR_R32_IMM8, true, "rorl_imm8"),
    (forms::ROL_R32_CL, true, "roll_cl"),
    (forms::ROR_R32_CL, true, "rorl_cl"),
];

/// Collects the operator multiset of the expression DAG rooted at `root`.
fn collect_ops(
    arena: &dyn ExprArena<Error = angryier_expr::ExprArenaError>,
    root: angryier_types::ExprId,
) -> Vec<ExprOp> {
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    let mut ops = Vec::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(node) = arena.get(id) {
            stack.extend(node.operands.iter().copied());
            ops.push(node.op);
        }
    }
    ops
}

#[test]
fn rotate_providers_symbolize_to_a_single_rotate_node() -> Result<(), BoxError> {
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    for (form, is_32bit, name) in R64_FORMS.iter().chain(R32_FORMS.iter()) {
        let block = lower_form(*form, *is_32bit, None)?;
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.mark_register(RAX, IrType::Bits(64))?;
        evaluator.mark_register(RCX, IrType::Bits(64))?;
        evaluator.eval_block(&block)?;

        let written = evaluator
            .register_value(RAX)
            .ok_or(format!("{name}: no symbolic value written back"))?;
        let ops = collect_ops(&arena, written);
        let expected_rotate = if name.starts_with("rol") {
            ExprOp::RotL
        } else {
            ExprOp::RotR
        };
        assert_eq!(
            ops.iter()
                .filter(|op| **op == ExprOp::RotL || **op == ExprOp::RotR)
                .count(),
            1,
            "{name}: expected exactly one rotate node, got {ops:?}"
        );
        assert!(
            ops.contains(&expected_rotate),
            "{name}: expected {expected_rotate:?} in the result expression"
        );
        // The old decomposition's signature must be gone: no glued shifts,
        // no wide `or` recombining the halves.
        for ban in [ExprOp::Or, ExprOp::Shl, ExprOp::LShr] {
            assert!(
                !ops.contains(&ban),
                "{name}: rotate still decomposes ({ban:?} present in {ops:?})"
            );
        }
    }
    Ok(())
}

/// A register image for the concolic shadow: concrete values, and the
/// register widths they imply.
struct RegisterImage(BTreeMap<u32, u64>);

impl ConcolicImage for RegisterImage {
    fn read_register(&self, register: u32) -> Option<Vec<u8>> {
        self.0.get(&register).map(|value| value.to_le_bytes().to_vec())
    }

    fn read_bytes(&self, _address: u64, _length: usize) -> Option<Vec<angryier_memory::ByteValue>> {
        None
    }
}

fn concrete_run(
    block: &IrBlock,
    rax: u64,
    rcx: u64,
) -> Result<u64, angryier_execution::ConcreteExecutionError<RegisterError, MemoryError>> {
    let memory = make_memory().map_err(|_| angryier_execution::ConcreteExecutionError::InvalidAddress)?;
    let registers = PersistentRegisters::from_widths([(RAX, 8), (RCX, 8), (RFLAGS, 8)])
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let registers = registers
        .write(RAX, &rax.to_le_bytes())
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let registers = registers
        .write(RCX, &rcx.to_le_bytes())
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let state = ExecutionState {
        id: StateId(7),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    };
    let (executed, _outcome) = ConcreteInterpreter::new().execute_block(&state, block, ExecutionMode::Concrete)?;
    let bytes = executed
        .registers
        .read(RAX)
        .map_err(|_| angryier_execution::ConcreteExecutionError::TypeMismatch)?;
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(&bytes);
    Ok(u64::from_le_bytes(buffer))
}

/// Counts that pin the masking: in-width, boundary, above-width (33/65 are
/// 1-bit rotates past the width; 64/32 mask to zero), and the imm8 maximum.
const COUNTS: [u64; 10] = [0, 1, 5, 31, 32, 33, 63, 64, 65, 255];

#[test]
fn rotate_count_masking_agrees_concrete_concolic_and_reference() -> Result<(), BoxError> {
    let value64: u64 = 0xdead_beef_cafe_f00d;
    let value32: u32 = 0x8000_0001;
    // A dirty RCX upper half proves only CL feeds the count.
    let dirty_rcx = |count: u64| 0xaabb_ccdd_0000_0000 | count;

    for (form, is_32bit, name) in R64_FORMS.iter().chain(R32_FORMS.iter()) {
        for &count in &COUNTS {
            let imm_form = name.ends_with("imm8");
            let block = lower_form(*form, *is_32bit, imm_form.then_some(count))?;

            let right = name.starts_with("ror");
            let (seed_rax, seed_rcx, expected) = if *is_32bit {
                // Dirty parent upper half: the 32-bit write zero-extends.
                let seed = 0xffff_ffff_0000_0000 | u64::from(value32);
                let masked = (count % 32) as u32;
                let rotated = if right {
                    value32.rotate_right(masked)
                } else {
                    value32.rotate_left(masked)
                };
                (seed, dirty_rcx(count), u64::from(rotated))
            } else {
                let masked = (count % 64) as u32;
                let rotated = if right {
                    value64.rotate_right(masked)
                } else {
                    value64.rotate_left(masked)
                };
                (value64, dirty_rcx(count), rotated)
            };

            let concrete =
                concrete_run(&block, seed_rax, seed_rcx).map_err(|e| format!("{name} count {count}: {e:?}"))?;
            assert_eq!(
                concrete, expected,
                "{name}: concrete interpreter disagrees at count {count}"
            );

            // The image drives the shadow's concrete side (like the
            // execution crate's concolic differential); symbolic-operand
            // behavior is covered by the structural test above.
            let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
            let mut concolic = ConcolicEvaluator::new(&arena);
            let image = RegisterImage(BTreeMap::from([(RAX, seed_rax), (RCX, seed_rcx), (RFLAGS, 0)]));
            concolic.eval_block(&image, &block)?;
            let shadow = concolic
                .register_concretes()
                .get(&RAX)
                .copied()
                .ok_or(format!("{name}: no concolic shadow for rax"))?;
            assert_eq!(
                shadow,
                Some(u128::from(expected)),
                "{name}: concolic shadow disagrees at count {count}"
            );
        }
    }

    // The immediate count also flows as a folded constant into the symbolic
    // rotate node: `rol r64, 66` rotates by 2.
    let block = lower_form(forms::ROL_R64_IMM8, false, Some(66))?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let mut evaluator = SymbolicEvaluator::new(&arena);
    let value_symbol = evaluator.mark_register(RAX, IrType::Bits(64))?;
    evaluator.eval_block(&block)?;
    let written = evaluator.register_value(RAX).ok_or("rolq_imm8: no value")?;
    let node = arena.get(written).ok_or("rolq_imm8: no node")?;
    assert_eq!(node.op, ExprOp::RotL);
    assert_eq!(node.operands.first(), Some(&value_symbol));
    assert_eq!(
        constant_value(&arena, node.operands[1]),
        Ok(66 % 64),
        "the symbolic count operand must fold to the mod-64 masked constant"
    );
    Ok(())
}
