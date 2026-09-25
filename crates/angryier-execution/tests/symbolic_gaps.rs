//! Regression tests for the symbolic-evaluator gaps surfaced by the concolic
//! speed benchmark on real gcc -O2 code (docs/ROADMAP.md §2):
//!
//! - `ZExt 64→32` unsupported — a degenerate extension whose source
//!   *expression* is wider than the target must truncate (Extract low bits);
//!   equal widths are identity;
//! - 32-bit induction-variable init producing width-mismatched
//!   `SortMismatch(Ult)` — a register tracked at parent width and compared
//!   through a 32-bit view must compare the view's low bits;
//! - `RotL`/`RotR` unsupported symbolically — end-to-end rotate support with
//!   x86 count-mod-width masking.
//!
//! Where feasible the symbolic result is checked differentially against the
//! concrete machine semantics (native sub-register views and
//! `u64::rotate_left/right` with masked counts).

use std::collections::BTreeMap;

use angryier_execution::{
    ConcolicEvaluator, ConcolicImage, SymbolicEvalError, SymbolicEvaluator, SymbolicStateSnapshot, constant_value,
};
use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
use angryier_ir::{IrBlock, IrBlockKey, IrInstruction, IrOp, IrPrimitive, IrType, IrValueId, RegisterWriteKind};
use angryier_memory::ByteValue;
use angryier_types::{BlockId, ContentId, ExprId, ExpressionNormalizationVersion, ImageId, TargetProfileId};

fn arena() -> ShardedExprArena {
    ShardedExprArena::new(ExpressionNormalizationVersion(1))
}

fn bits(width: u16) -> IrType {
    IrType::Bits(width)
}

fn block(instructions: Vec<IrInstruction>) -> IrBlock {
    IrBlock {
        key: IrBlockKey {
            image: ImageId(1),
            block: BlockId(0),
            address: 0x1000,
            semantic_content: ContentId::default(),
            target_profile: TargetProfileId(1),
            code_versions: Vec::new(),
        },
        instructions,
    }
}

fn read_register(result: u32, register: u32, width: u16) -> IrInstruction {
    IrInstruction {
        result: Some(IrValueId(result)),
        op: IrOp::ReadRegister {
            register,
            ty: bits(width),
        },
    }
}

fn constant(result: u32, width: u16, value: u64) -> IrInstruction {
    let byte_width = usize::from(width).div_ceil(8);
    IrInstruction {
        result: Some(IrValueId(result)),
        op: IrOp::Constant {
            ty: bits(width),
            bytes_le: value.to_le_bytes()[..byte_width].to_vec(),
        },
    }
}

fn primitive(result: u32, op: IrPrimitive, width: u16, inputs: &[u32]) -> IrInstruction {
    IrInstruction {
        result: Some(IrValueId(result)),
        op: IrOp::Primitive {
            op,
            ty: bits(width),
            inputs: inputs.iter().map(|id| IrValueId(*id)).collect(),
        },
    }
}

fn expr_ref(result: u32, expression: ExprId, width: u16) -> IrInstruction {
    IrInstruction {
        result: Some(IrValueId(result)),
        op: IrOp::ExprRef {
            expression,
            ty: bits(width),
        },
    }
}

fn write_register(register: u32, value: u32) -> IrInstruction {
    IrInstruction {
        result: None,
        op: IrOp::WriteRegister {
            register,
            value: IrValueId(value),
            kind: RegisterWriteKind::ReplaceParent,
        },
    }
}

/// A `cmp view, imm; jcc` shaped block: comparison, then Branch.
fn compare_block(register: u32, view_width: u16, bound: u64, op: IrPrimitive) -> IrBlock {
    block(vec![
        read_register(0, register, view_width),
        constant(1, view_width, bound),
        primitive(2, op, 1, &[0, 1]),
        IrInstruction {
            result: None,
            op: IrOp::Branch {
                condition: IrValueId(2),
                taken: 0x2000,
                not_taken: 0x3000,
            },
        },
    ])
}

/// Hand-built expected expression helpers, interned in the same arena so
/// hash-consing makes structural equality an ExprId comparison.
struct Builder<'a> {
    arena: &'a ShardedExprArena,
}

impl Builder<'_> {
    fn intern(&self, node: ExprNode) -> Result<ExprId, String> {
        self.arena.intern(node).map_err(|error| format!("{error:?}"))
    }

    fn constant(&self, width: u16, value: u64) -> Result<ExprId, String> {
        let byte_width = usize::from(width).div_ceil(8);
        self.intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: value.to_le_bytes()[..byte_width].to_vec(),
        })
    }

    fn extract_low(&self, expr: ExprId, width: u16) -> Result<ExprId, String> {
        let mut immediate = Vec::with_capacity(4);
        immediate.extend_from_slice(&0u16.to_le_bytes());
        immediate.extend_from_slice(&width.to_le_bytes());
        self.intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Extract,
            operands: vec![expr],
            immediate,
        })
    }

    fn extend(&self, expr: ExprId, width: u16, op: ExprOp) -> Result<ExprId, String> {
        self.intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op,
            operands: vec![expr],
            immediate: Vec::new(),
        })
    }

    fn bool_op(&self, op: ExprOp, left: ExprId, right: ExprId) -> Result<ExprId, String> {
        self.intern(ExprNode {
            sort: ExprSort::Bool,
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
    }

    /// The 1-bit branch value comparisons materialize: `ite(cond, 1, 0)`.
    fn branch_value(&self, condition: ExprId) -> Result<ExprId, String> {
        let one = self.constant(1, 1)?;
        let zero = self.constant(1, 0)?;
        self.intern(ExprNode {
            sort: ExprSort::BitVec(1),
            op: ExprOp::Ite,
            operands: vec![condition, one, zero],
            immediate: Vec::new(),
        })
    }
}

fn concrete_snapshot(register: u32, value: u64) -> SymbolicStateSnapshot {
    SymbolicStateSnapshot {
        concrete_registers: BTreeMap::from([(register, value)]),
        ..SymbolicStateSnapshot::default()
    }
}

// ---------------------------------------------------------------------------
// Gap 1: ZExt with degenerate expression widths
// ---------------------------------------------------------------------------

#[test]
fn zext_to_equal_expression_width_is_identity() -> Result<(), Box<dyn std::error::Error>> {
    let arena = arena();
    let mut evaluator = SymbolicEvaluator::new(&arena);
    let symbol = evaluator.mark_register(0, bits(64))?;

    let summary = evaluator.eval_block(&block(vec![
        expr_ref(0, symbol, 64),
        primitive(1, IrPrimitive::ZExt, 64, &[0]),
        write_register(1, 1),
    ]))?;
    let _ = summary;
    assert_eq!(evaluator.register_value(1), Some(symbol));
    Ok(())
}

#[test]
fn zext_to_narrower_expression_width_truncates_low_bits() -> Result<(), Box<dyn std::error::Error>> {
    // The IR type may declare a 32-bit view while the operand's expression
    // carries the parent's 64 bits (how the 32-bit count forms lower); the
    // extension degenerates to taking the low bits.
    let arena = arena();
    let mut evaluator = SymbolicEvaluator::new(&arena);
    let symbol = evaluator.mark_register(0, bits(64))?;

    evaluator.eval_block(&block(vec![
        expr_ref(0, symbol, 32),
        primitive(1, IrPrimitive::ZExt, 32, &[0]),
        write_register(1, 1),
    ]))?;

    let builder = Builder { arena: &arena };
    let expected = builder.extract_low(symbol, 32)?;
    assert_eq!(evaluator.register_value(1), Some(expected));
    Ok(())
}

#[test]
fn degenerate_zext_fold_matches_native_subregister_view() -> Result<(), Box<dyn std::error::Error>> {
    // Differential: the concrete value 0x1234_5678_89AB_CDEF read through a
    // 64-bit-tracked register and degenerately extended to 32 bits must fold
    // to eax's native view 0x89ABCDEF.
    let arena = arena();
    let mut evaluator = SymbolicEvaluator::new(&arena);
    evaluator.restore(&concrete_snapshot(0, 0x1234_5678_89AB_CDEF));

    evaluator.eval_block(&block(vec![
        read_register(0, 0, 64),
        primitive(1, IrPrimitive::ZExt, 32, &[0]),
        write_register(1, 1),
    ]))?;

    let folded = evaluator
        .register_value(1)
        .ok_or(SymbolicEvalError::UnsupportedOperation("no value".into()))?;
    assert_eq!(constant_value(&arena, folded), Ok(0x89AB_CDEF));
    Ok(())
}

// ---------------------------------------------------------------------------
// Gap 2: 32-bit view comparisons must stay well-sorted
// ---------------------------------------------------------------------------

#[test]
fn thirty_two_bit_view_ult_compares_the_low_bits() -> Result<(), Box<dyn std::error::Error>> {
    // An induction variable tracked at the parent (64-bit) width, read
    // through its 32-bit view, then compared: previously this interned a
    // width-mismatched Ult (SortMismatch) because the register file handed
    // out the 64-bit expression for the 32-bit read.
    let arena = arena();
    let mut evaluator = SymbolicEvaluator::new(&arena);
    let symbol = evaluator.mark_register(0, bits(64))?;

    let summary = evaluator.eval_block(&compare_block(0, 32, 10, IrPrimitive::Ult))?;
    let branch = summary
        .branch
        .ok_or(SymbolicEvalError::UnsupportedOperation("no branch".into()))?;

    let builder = Builder { arena: &arena };
    let view = builder.extract_low(symbol, 32)?;
    let bound = builder.constant(32, 10)?;
    let expected = builder.branch_value(builder.bool_op(ExprOp::Ult, view, bound)?)?;
    assert_eq!(branch.condition, expected);
    Ok(())
}

#[test]
fn thirty_two_bit_view_comparison_folds_like_the_machine() -> Result<(), Box<dyn std::error::Error>> {
    // Differential, both directions: 0x1_0000_0005 read as eax is 5, so
    // `5 < 10` folds true and `5 < 3` folds false — exactly what the
    // concrete interpreter computes for the same masked values.
    for (value, bound, taken) in [(0x1_0000_0005u64, 10u64, true), (0x1_0000_0005, 3, false)] {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.restore(&concrete_snapshot(0, value));

        let summary = evaluator.eval_block(&compare_block(0, 32, bound, IrPrimitive::Ult))?;
        let branch = summary
            .branch
            .ok_or(SymbolicEvalError::UnsupportedOperation("no branch".into()))?;
        assert_eq!(
            arena
                .get(branch.condition)
                .map(|node| (node.op, node.immediate.clone())),
            Some((ExprOp::Constant, vec![u8::from(taken)])),
            "value {value:#x} vs bound {bound}"
        );
    }
    Ok(())
}

#[test]
fn comparison_widens_mismatched_expression_widths() -> Result<(), Box<dyn std::error::Error>> {
    // Expressions whose widths drift without a register read in between
    // (ExprRef carries an externally built expression): the comparison
    // itself must coerce before interning. Unsigned comparisons zero-widen
    // the narrower side; signed comparisons sign-widen it.
    let arena = arena();
    let builder = Builder { arena: &arena };
    let symbol64 = builder.intern(ExprNode {
        sort: ExprSort::BitVec(64),
        op: ExprOp::Symbol,
        operands: Vec::new(),
        immediate: 1u64.to_le_bytes().to_vec(),
    })?;
    let symbol32 = builder.intern(ExprNode {
        sort: ExprSort::BitVec(32),
        op: ExprOp::Symbol,
        operands: Vec::new(),
        immediate: 2u64.to_le_bytes().to_vec(),
    })?;

    // Ult(sym64, const32): the constant zero-widens to 64 bits.
    let mut evaluator = SymbolicEvaluator::new(&arena);
    let summary = evaluator.eval_block(&block(vec![
        expr_ref(0, symbol64, 64),
        constant(1, 32, 10),
        primitive(2, IrPrimitive::Ult, 1, &[0, 1]),
        IrInstruction {
            result: None,
            op: IrOp::Branch {
                condition: IrValueId(2),
                taken: 0x2000,
                not_taken: 0x3000,
            },
        },
    ]))?;
    let branch = summary
        .branch
        .ok_or(SymbolicEvalError::UnsupportedOperation("no branch".into()))?;
    let expected = builder.branch_value(builder.bool_op(
        ExprOp::Ult,
        symbol64,
        builder.extend(builder.constant(32, 10)?, 64, ExprOp::ZExt)?,
    )?)?;
    assert_eq!(branch.condition, expected);

    // Slt(sym32, const64): the symbol sign-widens to 64 bits.
    let mut evaluator = SymbolicEvaluator::new(&arena);
    let summary = evaluator.eval_block(&block(vec![
        expr_ref(0, symbol32, 32),
        constant(1, 64, u64::MAX),
        primitive(2, IrPrimitive::Slt, 1, &[0, 1]),
        IrInstruction {
            result: None,
            op: IrOp::Branch {
                condition: IrValueId(2),
                taken: 0x2000,
                not_taken: 0x3000,
            },
        },
    ]))?;
    let branch = summary
        .branch
        .ok_or(SymbolicEvalError::UnsupportedOperation("no branch".into()))?;
    let expected = builder.branch_value(builder.bool_op(
        ExprOp::Slt,
        builder.extend(symbol32, 64, ExprOp::SExt)?,
        builder.constant(64, u64::MAX)?,
    )?)?;
    assert_eq!(branch.condition, expected);
    Ok(())
}

// ---------------------------------------------------------------------------
// Gap 3: RotL/RotR
// ---------------------------------------------------------------------------

fn rotate_block(op: IrPrimitive, value_register: u32, count_register: u32, count_width: u16) -> IrBlock {
    block(vec![
        read_register(0, value_register, 64),
        read_register(1, count_register, count_width),
        primitive(2, op, 64, &[0, 1]),
        write_register(2, 2),
    ])
}

#[test]
fn rotate_primitives_evaluate_symbolically() -> Result<(), Box<dyn std::error::Error>> {
    // A CL-shaped 8-bit count must be zero-extended to the operand width so
    // the rotate node is well-sorted; the count-mod-width masking is the
    // rotate op's own semantics.
    let arena = arena();
    let builder = Builder { arena: &arena };

    for op in [IrPrimitive::RotL, IrPrimitive::RotR] {
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let value_symbol = evaluator.mark_register(0, bits(64))?;
        let count_symbol = evaluator.mark_register(1, bits(8))?;
        evaluator.eval_block(&rotate_block(op, 0, 1, 8))?;

        let expression_op = if op == IrPrimitive::RotL {
            ExprOp::RotL
        } else {
            ExprOp::RotR
        };
        let expected = builder.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: expression_op,
            operands: vec![value_symbol, builder.extend(count_symbol, 64, ExprOp::ZExt)?],
            immediate: Vec::new(),
        })?;
        assert_eq!(evaluator.register_value(2), Some(expected), "{op:?}");
    }
    Ok(())
}

#[test]
fn rotate_count_masks_modulo_width_symbolically() -> Result<(), Box<dyn std::error::Error>> {
    // Differential: `rol r64, 66` rotates by 66 mod 64 = 2, exactly what the
    // concrete interpreter computes (`shift % output_bits`).
    let value: u64 = 0xF0;
    for (op, expected) in [
        (IrPrimitive::RotL, value.rotate_left(66 % 64)),
        (IrPrimitive::RotR, value.rotate_right(66 % 64)),
    ] {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.restore(&concrete_snapshot(0, value));

        // The immediate count arrives imm8-shaped, as the lowering emits it.
        evaluator.eval_block(&block(vec![
            read_register(0, 0, 64),
            constant(1, 8, 66),
            primitive(2, op, 64, &[0, 1]),
            write_register(2, 2),
        ]))?;

        let rotated = evaluator
            .register_value(2)
            .ok_or(SymbolicEvalError::UnsupportedOperation("no value".into()))?;
        assert_eq!(constant_value(&arena, rotated), Ok(expected), "{op:?}");
    }
    Ok(())
}

struct RegisterImage(BTreeMap<u32, u64>);

impl ConcolicImage for RegisterImage {
    fn read_register(&self, register: u32) -> Option<Vec<u8>> {
        self.0.get(&register).map(|value| value.to_le_bytes().to_vec())
    }

    fn read_bytes(&self, _address: u64, _length: usize) -> Option<Vec<angryier_memory::ByteValue>> {
        None
    }
}

#[test]
fn concolic_rotate_folds_like_the_machine() -> Result<(), Box<dyn std::error::Error>> {
    // Concolic differential with a symbolic-width count in CL: the shadow
    // folds through the same count-mod-width semantics the concrete
    // interpreter applies.
    let value: u64 = 0xF0;
    let count: u64 = 70; // CL value; 70 mod 64 = 6
    for (op, expected) in [
        (IrPrimitive::RotL, u128::from(value.rotate_left((count % 64) as u32))),
        (IrPrimitive::RotR, u128::from(value.rotate_right((count % 64) as u32))),
    ] {
        let arena = arena();
        let mut evaluator = ConcolicEvaluator::new(&arena);
        let image = RegisterImage(BTreeMap::from([(0u32, value), (1u32, count)]));
        evaluator.eval_block(&image, &rotate_block(op, 0, 1, 8))?;
        assert_eq!(evaluator.register_concretes().get(&2), Some(&Some(expected)), "{op:?}");
    }
    Ok(())
}

#[test]
fn rotate_of_symbol_does_not_fold() -> Result<(), Box<dyn std::error::Error>> {
    // The rotate node survives over a symbolic value (no spurious fold), and
    // its dependency tracks the value symbol.
    let arena = arena();
    let mut evaluator = SymbolicEvaluator::new(&arena);
    evaluator.mark_register(0, bits(64))?;

    evaluator.eval_block(&block(vec![
        read_register(0, 0, 64),
        constant(1, 8, 3),
        primitive(2, IrPrimitive::RotL, 64, &[0, 1]),
        write_register(2, 2),
    ]))?;

    let rotated = evaluator
        .register_value(2)
        .ok_or(SymbolicEvalError::UnsupportedOperation("no value".into()))?;
    let node = arena
        .get(rotated)
        .ok_or(SymbolicEvalError::UnsupportedOperation("no node".into()))?;
    assert_eq!(node.op, ExprOp::RotL);
    let summary = arena
        .dependency_summary(rotated)
        .ok_or(SymbolicEvalError::UnsupportedOperation("no dependency".into()))?;
    assert_eq!(summary.symbolic_sources.len(), 1);
    Ok(())
}

// ── Concolic concrete-first fast path (QSYM-style block skipping) ─────────
//
// The fast path walks a block with concrete values only and falls back to
// the full symbolic walk on the first sign of input influence. These tests
// pin the three contracts that make the skip safe:
// 1. committed state is indistinguishable from the full walk's fold
//    (written registers keep expression+concrete shadow entries);
// 2. concrete stores land as fresh concrete shadow bytes — a later load
//    must never observe a stale shadow byte the concrete engine already
//    overwrote (including overwriting a marked input byte, which the full
//    walk's constant-store path also does);
// 3. an aborted fast walk leaves no partial state behind.

/// Image with registers AND memory for store/load fast-path coverage.
struct MemoryImage {
    registers: BTreeMap<u32, u64>,
    memory: BTreeMap<u64, u8>,
}

impl ConcolicImage for MemoryImage {
    fn read_register(&self, register: u32) -> Option<Vec<u8>> {
        self.registers.get(&register).map(|value| value.to_le_bytes().to_vec())
    }

    fn read_bytes(&self, address: u64, length: usize) -> Option<Vec<ByteValue>> {
        let mut out = Vec::with_capacity(length);
        for offset in 0..length {
            out.push(ByteValue::Concrete(*self.memory.get(&(address + offset as u64))?));
        }
        Some(out)
    }
}

#[test]
fn concrete_fast_path_commits_memory_and_serves_fresh_loads() -> Result<(), Box<dyn std::error::Error>> {
    let arena = arena();
    let mut evaluator = ConcolicEvaluator::new(&arena);
    // One marked input byte at the store target: the store must overwrite
    // it with a concrete shadow byte exactly like the full walk's
    // constant-store path, and the later load must see the stored value,
    // never the symbol underneath and never the image's zero.
    evaluator.mark_memory(0x1000, 1)?;
    let image = MemoryImage {
        registers: BTreeMap::from([(0u32, 0x1000u64)]),
        memory: BTreeMap::from([(0x1000u64, 0u8)]),
    };

    // [r0] = 0x1122334455667788 — every input concrete, fast path taken.
    evaluator.eval_block(
        &image,
        &block(vec![
            read_register(0, 0, 64),
            constant(1, 64, 0x1122_3344_5566_7788),
            IrInstruction {
                result: None,
                op: IrOp::Store {
                    address: IrValueId(0),
                    value: IrValueId(1),
                },
            },
        ]),
    )?;

    // r1 = [r0] — the fast-path load must fold the freshly committed
    // concrete shadow bytes, not the image's zero byte.
    evaluator.eval_block(
        &image,
        &block(vec![
            read_register(0, 0, 64),
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Load {
                    address: IrValueId(0),
                    ty: IrType::Bits(64),
                },
            },
            write_register(1, 1),
        ]),
    )?;

    assert_eq!(
        evaluator.register_concretes().get(&1),
        Some(&Some(0x1122_3344_5566_7788)),
        "load after fast-path store must observe the stored value"
    );
    // The store also committed concrete bytes over the marked input byte.
    assert_eq!(
        evaluator.shadow_memory().get(&0x1000),
        Some(&ByteValue::Concrete(0x88)),
        "fast-path store must overwrite the symbolic input byte concretely"
    );
    Ok(())
}

#[test]
fn concrete_fast_path_falls_back_cleanly_on_symbolic_registers() -> Result<(), Box<dyn std::error::Error>> {
    let arena = arena();
    let mut evaluator = ConcolicEvaluator::new(&arena);
    evaluator.mark_register(0, bits(64))?;
    let image = MemoryImage {
        registers: BTreeMap::from([(0u32, 41u64), (3u32, 0u64)]),
        memory: BTreeMap::new(),
    };

    // Uninfluenced block first: r3 = 7 commits through the fast path.
    evaluator.eval_block(&image, &block(vec![constant(0, 64, 7), write_register(3, 0)]))?;
    assert_eq!(evaluator.register_concretes().get(&3), Some(&Some(7)));

    // Influenced block: r2 = r0 + 1 — the fast walk aborts at the symbolic
    // read of r0 and the full walk builds the expression.
    evaluator.eval_block(
        &image,
        &block(vec![
            read_register(0, 0, 64),
            constant(1, 64, 1),
            primitive(2, IrPrimitive::Add, 64, &[0, 1]),
            write_register(2, 2),
        ]),
    )?;
    assert_eq!(
        evaluator.register_concretes().get(&2),
        Some(&None),
        "r2 must carry the symbolic Add expression"
    );
    let added = evaluator
        .register_value(2)
        .ok_or(SymbolicEvalError::UnsupportedOperation("no r2 value".into()))?;
    let node = arena
        .get(added)
        .ok_or(SymbolicEvalError::UnsupportedOperation("no node".into()))?;
    assert_eq!(node.op, ExprOp::Add, "full walk must have built the Add node");

    // The aborted fast walk must not have disturbed the earlier commit.
    assert_eq!(
        evaluator.register_concretes().get(&3),
        Some(&Some(7)),
        "fallback must leave prior fast-path state untouched"
    );
    Ok(())
}

#[test]
fn concrete_fast_path_skips_branch_constraints_for_concrete_conditions() -> Result<(), Box<dyn std::error::Error>> {
    let arena = arena();
    let mut evaluator = ConcolicEvaluator::new(&arena);
    let image = MemoryImage {
        registers: BTreeMap::from([(0u32, 5u64)]),
        memory: BTreeMap::new(),
    };

    // cmp r0, 10; jcc — r0 is concrete, so the block takes the fast path
    // and records no branch (a concrete condition cannot be inverted).
    let summary = evaluator.eval_block(&image, &compare_block(0, 64, 10, IrPrimitive::Ult))?;
    assert!(summary.branch.is_none(), "concrete branch must not record a constraint");

    // The mirror case with a symbolic register still records.
    let mut symbolic = ConcolicEvaluator::new(&arena);
    symbolic.mark_register(0, bits(64))?;
    let summary = symbolic.eval_block(&image, &compare_block(0, 64, 10, IrPrimitive::Ult))?;
    assert!(
        summary.branch.is_some(),
        "symbolic branch must still record a constraint"
    );
    Ok(())
}
