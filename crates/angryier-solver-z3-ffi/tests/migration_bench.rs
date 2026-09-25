//! Gate B solver measurement: the migration cost of an incremental Z3
//! solver context at path depth 500.
//!
//! Incremental contexts want states pinned to the worker that built them
//! (scopes accumulate learned state per path constraint); work stealing wants
//! states free to move. This benchmark prices the steal for a stolen state
//! landing on a worker whose context shares nothing (cold rebuild), shares
//! half the path (partial-prefix migration), or shares the whole prefix
//! (warm incremental), plus the resident-set cost of a context holding the
//! full 500-constraint chain.

use std::sync::Arc;
use std::time::Instant;

use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprReader, ExprSort, ShardedExprArena};
use angryier_solver::{CanonicalConstraint, SolverBackend, SolverQuery};
use angryier_solver_z3_ffi::Z3FfiBridge;
use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, ExpressionNormalizationVersion,
    SolverOutcomeKind, SolverQueryId, TargetProfileId,
};
use core::time::Duration;

/// Depth of the measured path; 100 and 250 are swept alongside it so the
/// trend is visible.
const DEPTHS: [usize; 3] = [100, 250, 500];

fn make_arena() -> Arc<ShardedExprArena> {
    Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)))
}

fn make_symbol(arena: &ShardedExprArena, width: u16, sym_id: u64) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: sym_id.to_le_bytes().to_vec(),
        })
        .map_err(Into::into)
}

fn make_const(arena: &ShardedExprArena, width: u16, value: u128) -> Result<ExprId, Box<dyn std::error::Error>> {
    let byte_width = usize::from(width).div_ceil(8);
    let immediate = value.to_le_bytes()[..byte_width].to_vec();
    arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate,
        })
        .map_err(Into::into)
}

fn make_binop(
    arena: &ShardedExprArena,
    op: ExprOp,
    width: u16,
    left: ExprId,
    right: ExprId,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

fn make_eq(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

fn make_ult(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Ult,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

fn make_query(
    predicate: ExprId,
    constraints: &[(ConstraintId, ExprId)],
    arena: &ShardedExprArena,
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
        Duration::from_secs(60),
    )?)
}

/// A linked constraint chain over four 64-bit symbols: even positions fold
/// an `Ult` comparison over the running symbol, odd positions chain
/// `x_i + k == x_{i+1} + k`. The equalities are satisfied with all symbols
/// equal and the bounds stay far above any achievable value, so the chain is
/// Sat at every depth.
struct PathChain {
    constraints: Vec<(ConstraintId, ExprId)>,
    predicate: ExprId,
    /// A second, also-Sat predicate over a different symbol — the warm
    /// incremental re-solve changes only the predicate.
    alt_predicate: ExprId,
}

fn build_chain(arena: &ShardedExprArena, depth: usize) -> Result<PathChain, Box<dyn std::error::Error>> {
    let symbols: Vec<ExprId> = (0..4u64)
        .map(|index| make_symbol(arena, 64, index + 1))
        .collect::<Result<_, _>>()?;
    let mut constraints = Vec::with_capacity(depth);
    for step in 0..depth {
        let value = symbols[step % symbols.len()];
        let next = symbols[(step + 1) % symbols.len()];
        let tag = u128::try_from(step)? + 1;
        let constraint = if step % 2 == 0 {
            let bound = make_const(arena, 64, (1u128 << 40) + tag)?;
            make_ult(arena, value, bound)?
        } else {
            let offset = make_const(arena, 64, tag)?;
            let left = make_binop(arena, ExprOp::Add, 64, value, offset)?;
            let right = make_binop(arena, ExprOp::Add, 64, next, offset)?;
            make_eq(arena, left, right)?
        };
        let id = ConstraintId(u64::try_from(step)?);
        constraints.push((id, constraint));
    }
    let zero = make_const(arena, 64, 0)?;
    let predicate = make_ult(arena, zero, symbols[0])?;
    let ceiling = make_const(arena, 64, 1u128 << 50)?;
    let alt_predicate = make_ult(arena, symbols[1], ceiling)?;
    Ok(PathChain {
        constraints,
        predicate,
        alt_predicate,
    })
}

/// Resident set size in bytes: the second `/proc/self/statm` field is the
/// resident page count.
fn resident_bytes() -> Result<u64, Box<dyn std::error::Error>> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let field = statm.split_whitespace().nth(1).ok_or("statm missing fields")?;
    let resident_pages: u64 = field.parse()?;
    Ok(resident_pages * 4096)
}

/// The migration benchmark: for each depth, a worker receives the same
/// stolen state three ways — cold (no context), partial-prefix (half the
/// path already loaded), and warm (full prefix shared) — and the solve wall
/// times are compared.
#[test]
#[ignore = "Gate B measurement — run explicitly with --ignored"]
fn gate_b_solver_migration_depth_500() -> Result<(), Box<dyn std::error::Error>> {
    let arena = make_arena();
    let chain = build_chain(&arena, *DEPTHS.last().ok_or("empty depth sweep")?)?;
    let reader: Arc<dyn ExprReader> = arena.clone();

    let mut ctx_rss_delta = 0u64;
    for &depth in &DEPTHS {
        let half = depth / 2;
        let prefix = &chain.constraints[..half];
        let full = &chain.constraints[..depth];
        let q_prefix = make_query(chain.predicate, prefix, &arena)?;
        let q_full = make_query(chain.predicate, full, &arena)?;
        let q_warm = make_query(chain.alt_predicate, full, &arena)?;

        // Cold rebuild: a fresh context pays for translation plus all 500
        // pushes — what a stolen state costs a worker with no context.
        let rss_before = resident_bytes()?;
        let cold_started = Instant::now();
        let mut bridge = Z3FfiBridge::new(reader.clone())?;
        let cold_result = bridge.solve(&q_full);
        let cold = cold_started.elapsed();
        let rss_after = resident_bytes()?;
        assert_eq!(cold_result.outcome, SolverOutcomeKind::Sat, "cold rebuild must be Sat");

        // Partial-prefix migration: a second context already holds the first
        // half of the path; the steal pops nothing and pushes the suffix.
        let mut partial_bridge = Z3FfiBridge::new(reader.clone())?;
        let warmup = partial_bridge.solve(&q_prefix);
        assert_eq!(warmup.outcome, SolverOutcomeKind::Sat, "prefix load must be Sat");
        let partial_started = Instant::now();
        let partial_result = partial_bridge.solve(&q_full);
        let partial = partial_started.elapsed();
        assert_eq!(
            partial_result.outcome,
            SolverOutcomeKind::Sat,
            "partial migration must be Sat"
        );

        // Warm incremental: the full prefix is shared; only the predicate
        // changes inside a transient scope.
        let warm_started = Instant::now();
        let warm_result = partial_bridge.solve(&q_warm);
        let warm = warm_started.elapsed();
        assert_eq!(warm_result.outcome, SolverOutcomeKind::Sat, "warm re-solve must be Sat");

        assert!(
            !cold.is_zero() && !partial.is_zero() && !warm.is_zero(),
            "timings must be non-zero"
        );

        // Bridge + full-context RSS is captured at the measured depth only,
        // while the cold context is still live.
        if depth == DEPTHS[DEPTHS.len() - 1] {
            ctx_rss_delta = rss_after.saturating_sub(rss_before);
        }
        let ratio = cold.as_secs_f64() / warm.as_secs_f64().max(1e-9);
        let mut line = format!(
            "GATE-B solver: depth {depth} cold={:.1}ms partial={:.1}ms warm={:.1}ms (cold/warm ratio {:.1})",
            cold.as_secs_f64() * 1000.0,
            partial.as_secs_f64() * 1000.0,
            warm.as_secs_f64() * 1000.0,
            ratio
        );
        if depth == DEPTHS[DEPTHS.len() - 1] {
            line.push_str(&format!(
                ", ctx RSS +{:.2} MB ({} KB)",
                ctx_rss_delta as f64 / (1024.0 * 1024.0),
                ctx_rss_delta / 1024
            ));
        }
        println!("{line}");
    }
    assert!(ctx_rss_delta > 0, "a 500-constraint context must grow the resident set");
    Ok(())
}
