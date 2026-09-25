//! Round-trip proofs for the symbolic rotate ops through the native Z3 FFI
//! backend (the `RotL`/`RotR` leg of the roadmap's symbolic-evaluator gaps).
//!
//! Each case fixes a concrete input through path constraints and asks Z3 to
//! prove the translated rotation equal to the value the concrete interpreter
//! computes (`u64::rotate_left/right` with the count taken modulo the
//! operand width — x86 rotate semantics). Both the constant-count path
//! (`Z3_mk_rotate_left`, an indexed numeral amount) and the symbolic-count
//! path (`Z3_mk_ext_rotate_left`, with the 8-bit CL-shaped count
//! zero-extended to the operand width) are exercised, in both directions,
//! with a matching `Sat` and a mismatching `Unsat`.

use std::sync::Arc;
use std::time::Duration;

use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprReader, ExprSort, ShardedExprArena};
use angryier_solver::{CanonicalConstraint, SolverBackend, SolverQuery};
use angryier_solver_z3_ffi::Z3FfiBridge;
use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, ExpressionNormalizationVersion,
    SolverOutcomeKind, SolverQueryId, TargetProfileId,
};

const TIMEOUT: Duration = Duration::from_secs(30);

fn make_arena() -> Arc<ShardedExprArena> {
    Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)))
}

fn intern(arena: &ShardedExprArena, node: ExprNode) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena.intern(node).map_err(Into::into)
}

fn make_symbol(arena: &ShardedExprArena, width: u16, sym_id: u64) -> Result<ExprId, Box<dyn std::error::Error>> {
    intern(
        arena,
        ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: sym_id.to_le_bytes().to_vec(),
        },
    )
}

fn make_const(arena: &ShardedExprArena, width: u16, value: u128) -> Result<ExprId, Box<dyn std::error::Error>> {
    let byte_width = usize::from(width).div_ceil(8);
    intern(
        arena,
        ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: value.to_le_bytes()[..byte_width].to_vec(),
        },
    )
}

fn make_rotate(
    arena: &ShardedExprArena,
    op: ExprOp,
    value: ExprId,
    count: ExprId,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    intern(
        arena,
        ExprNode {
            sort: ExprSort::BitVec(64),
            op,
            operands: vec![value, count],
            immediate: Vec::new(),
        },
    )
}

fn make_eq(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> Result<ExprId, Box<dyn std::error::Error>> {
    intern(
        arena,
        ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![left, right],
            immediate: Vec::new(),
        },
    )
}

fn make_query(
    arena: &ShardedExprArena,
    predicate: ExprId,
    constraints: &[(ConstraintId, ExprId)],
) -> Result<SolverQuery, Box<dyn std::error::Error>> {
    let canonical_constraints: Vec<_> = constraints
        .iter()
        .map(|(cid, eid)| CanonicalConstraint {
            id: *cid,
            key: arena
                .dependency_summary(*eid)
                .map(|s| s.key)
                .unwrap_or(DependencyKey([0; 32])),
            expr: *eid,
        })
        .collect();
    let pred_key = arena
        .dependency_summary(predicate)
        .map(|s| s.key)
        .ok_or("predicate must have a dependency summary")?;
    Ok(SolverQuery::canonical(
        SolverQueryId(1),
        &canonical_constraints,
        predicate,
        pred_key,
        TargetProfileId(1),
        ConstraintCanonicalizationVersion(1),
        TIMEOUT,
    )?)
}

fn solve(arena: &Arc<ShardedExprArena>, query: &SolverQuery) -> Result<SolverOutcomeKind, Box<dyn std::error::Error>> {
    let mut bridge = Z3FfiBridge::new(arena.clone() as Arc<dyn ExprReader>)?;
    Ok(bridge.solve(query).outcome)
}

/// One rotate proof: `rot(value, count)` under Z3 must equal the concrete
/// interpreter's `u64::rotate_*(count % 64)`, and must be provably unequal
/// to a corrupted expectation.
fn check_rotate_case(op: ExprOp, value: u64, count: u64) -> Result<(), Box<dyn std::error::Error>> {
    let expected = if op == ExprOp::RotL {
        value.rotate_left(u32::try_from(count % 64)?)
    } else {
        value.rotate_right(u32::try_from(count % 64)?)
    };
    let corrupted = expected.rotate_left(4);

    for (claimed, outcome) in [
        (expected, SolverOutcomeKind::Sat),
        (corrupted, SolverOutcomeKind::Unsat),
    ] {
        let arena = make_arena();
        let value_symbol = make_symbol(&arena, 64, 1)?;
        let count_symbol = make_symbol(&arena, 8, 2)?;
        let rotated = make_rotate(&arena, op, value_symbol, count_symbol)?;
        let claim = make_eq(&arena, rotated, make_const(&arena, 64, u128::from(claimed))?)?;
        let query = make_query(
            &arena,
            claim,
            &[
                (
                    ConstraintId(0),
                    make_eq(&arena, value_symbol, make_const(&arena, 64, u128::from(value))?)?,
                ),
                (
                    ConstraintId(1),
                    make_eq(&arena, count_symbol, make_const(&arena, 8, u128::from(count))?)?,
                ),
            ],
        )?;
        assert_eq!(solve(&arena, &query)?, outcome, "{op:?} claim {claimed:#x}");
    }
    Ok(())
}

#[test]
fn z3_translates_symbolic_rotate_left() -> Result<(), Box<dyn std::error::Error>> {
    // Counts below and above the width both exercise the modulo masking.
    check_rotate_case(ExprOp::RotL, 0x0000_0000_0000_00F0, 6)?;
    check_rotate_case(ExprOp::RotL, 0x1234_5678_9ABC_DEF0, 70)?;
    // A count that reduces to zero must be the identity rotation.
    check_rotate_case(ExprOp::RotL, 0x1234_5678_9ABC_DEF0, 64)?;
    Ok(())
}

#[test]
fn z3_translates_symbolic_rotate_right() -> Result<(), Box<dyn std::error::Error>> {
    check_rotate_case(ExprOp::RotR, 0x0000_0000_0000_00F0, 6)?;
    check_rotate_case(ExprOp::RotR, 0x1234_5678_9ABC_DEF0, 70)?;
    check_rotate_case(ExprOp::RotR, 0x1234_5678_9ABC_DEF0, 64)?;
    Ok(())
}

#[test]
fn z3_translates_constant_count_rotate() -> Result<(), Box<dyn std::error::Error>> {
    // A constant count goes through the indexed numeral rotate; the value
    // stays symbolic so the rotate node survives arena folding.
    let value = 0x0F0F_0F0F_0F0F_0F0Fu64;
    let count = 9u64;
    let expected = value.rotate_left(u32::try_from(count)?);
    let corrupted = value.rotate_left(u32::try_from(count + 1)?);

    for (claimed, outcome) in [
        (expected, SolverOutcomeKind::Sat),
        (corrupted, SolverOutcomeKind::Unsat),
    ] {
        let arena = make_arena();
        let value_symbol = make_symbol(&arena, 64, 1)?;
        let rotated = make_rotate(
            &arena,
            ExprOp::RotL,
            value_symbol,
            make_const(&arena, 8, u128::from(count))?,
        )?;
        let claim = make_eq(&arena, rotated, make_const(&arena, 64, u128::from(claimed))?)?;
        let query = make_query(
            &arena,
            claim,
            &[(
                ConstraintId(0),
                make_eq(&arena, value_symbol, make_const(&arena, 64, u128::from(value))?)?,
            )],
        )?;
        assert_eq!(solve(&arena, &query)?, outcome, "claim {claimed:#x}");
    }
    Ok(())
}
