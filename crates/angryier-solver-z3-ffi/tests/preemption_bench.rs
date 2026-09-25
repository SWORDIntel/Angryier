//! Gate C preemption measurement: what cancellation at a wall-clock budget
//! buys on a query family Z3 grinds on.
//!
//! `InMemoryPortfolioRouter::should_preempt` decides *when* to give up on a
//! backend; the Z3 FFI bridge's cancellation paths — the per-query timeout
//! it forwards into Z3's soft-limit machinery, and `Z3FfiBridge::interrupt()`
//! — are *how* a grindy check is stopped. This benchmark prices both on a
//! semiprime factoring family — `2 <= a < 2^32 ∧ 2 <= b < 2^32 ∧ a*b == N`
//! — which forces Z3 to factor N with no 64-bit wraparound escape:
//!
//! - uninterrupted wall time (the cost the budget is defending against);
//! - budget-N arms (10/50/100/500 ms): the check is cancelled at N ms and
//!   must return promptly with `Unknown` — never a wrong `Sat`/`Unsat`;
//! - throughput-at-budget: queries per second completed when every query
//!   runs under an N-ms budget;
//! - a pre-armed `interrupt()`: the cancellation flag's effect on the next
//!   check (prompt `Unknown`, never a fabricated answer).

use std::sync::Arc;
use std::time::Instant;

use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprReader, ExprSort, ShardedExprArena};
use angryier_solver::SolverBackend;
use angryier_solver::{CanonicalConstraint, SolverQuery};
use angryier_solver_z3_ffi::Z3FfiBridge;
use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, ExpressionNormalizationVersion,
    SolverOutcomeKind, SolverQueryId, TargetProfileId,
};
use core::time::Duration;

/// Wall-clock budgets swept for the cancellation arms, in milliseconds.
const BUDGETS_MS: [u64; 4] = [10, 50, 100, 500];

/// Repetitions per budget arm for the throughput figure.
const REPS: usize = 3;

/// Hard ceiling for the uninterrupted arm; if Z3 hits it the family is
/// grindy enough to measure budgets against (the floor is then the ceiling).
const FULL_ARM_CEILING: Duration = Duration::from_secs(20);

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

fn make_query(
    predicate: ExprId,
    constraints: &[(ConstraintId, ExprId)],
    arena: &ShardedExprArena,
    timeout: Duration,
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
        timeout,
    )?)
}

// ---------------------------------------------------------------------------
// Deterministic primality (Miller-Rabin, fixed bases valid for all u64)
// ---------------------------------------------------------------------------

fn mul_mod(left: u64, right: u64, modulus: u64) -> u64 {
    (u128::from(left) * u128::from(right) % u128::from(modulus)) as u64
}

fn pow_mod(mut base: u64, mut exponent: u64, modulus: u64) -> u64 {
    let mut result = 1u64 % modulus;
    while exponent > 0 {
        if !exponent.is_multiple_of(2) {
            result = mul_mod(result, base, modulus);
        }
        base = mul_mod(base, base, modulus);
        exponent >>= 1;
    }
    result
}

fn is_prime_u64(n: u64) -> bool {
    if n < 2 {
        return false;
    }
    for known in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        if n.is_multiple_of(known) {
            return n == known;
        }
    }
    let mut d = n - 1;
    let mut r: i32 = 0;
    while d.is_multiple_of(2) {
        d /= 2;
        r += 1;
    }
    for a in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37] {
        let mut x = pow_mod(a, d, n);
        if x == 1 || x == n - 1 {
            continue;
        }
        let mut composite = true;
        for _ in 0..r.saturating_sub(1) {
            x = mul_mod(x, x, n);
            if x == n - 1 {
                composite = false;
                break;
            }
        }
        if composite {
            return false;
        }
    }
    true
}

/// Largest prime strictly below `limit` (deterministic downward search).
fn largest_prime_below(limit: u64) -> Option<u64> {
    let mut candidate = limit.saturating_sub(1) | 1;
    while candidate >= 3 {
        if is_prime_u64(candidate) {
            return Some(candidate);
        }
        candidate -= 2;
    }
    None
}

/// The pathological family: `2 <= a < 2^32 ∧ 2 <= b < 2^32 ∧ a*b == N`
/// with N a semiprime of two primes just under `2^prime_bits` — genuine
/// factoring, no modular wraparound escape, Sat exactly at the factor pair.
struct FactoringFamily {
    predicate: ExprId,
    constraints: Vec<(ConstraintId, ExprId)>,
    trivial_predicate: ExprId,
    /// ExprIds of the two factor symbols — model entries are keyed by them.
    factor_a: ExprId,
    factor_b: ExprId,
    semiprime: u128,
    semiprime_bits: u32,
}

fn build_family(arena: &ShardedExprArena, prime_bits: u32) -> Result<FactoringFamily, Box<dyn std::error::Error>> {
    let limit = 1u64.checked_shl(prime_bits).ok_or("prime_bits too large")?;
    let p = largest_prime_below(limit).ok_or("no prime below limit")?;
    let q = largest_prime_below(p / 2).ok_or("no second prime")?;
    let n = u128::from(p) * u128::from(q);
    let semiprime_bits = 127 - n.leading_zeros();

    let a = make_symbol(arena, 64, 1)?;
    let b = make_symbol(arena, 64, 2)?;
    let two = make_const(arena, 64, 2)?;
    let shard_limit = make_const(arena, 64, 1u128 << 32)?;
    let a_lower = make_ult(arena, two, a)?;
    let a_upper = make_ult(arena, a, shard_limit)?;
    let b_lower = make_ult(arena, two, b)?;
    let b_upper = make_ult(arena, b, shard_limit)?;
    let product = make_binop(arena, ExprOp::Mul, 64, a, b)?;
    let target = make_const(arena, 64, n)?;
    let predicate = make_eq(arena, product, target)?;
    // Trivially-Sat predicate (a < 11 with a >= 2 already implied by nothing
    // here — used unconstrained, still cheap and Sat) for the pre-armed arm.
    let eleven = make_const(arena, 64, 11)?;
    let trivial_predicate = make_ult(arena, a, eleven)?;
    Ok(FactoringFamily {
        predicate,
        constraints: vec![
            (ConstraintId(0), a_lower),
            (ConstraintId(1), a_upper),
            (ConstraintId(2), b_lower),
            (ConstraintId(3), b_upper),
        ],
        trivial_predicate,
        factor_a: a,
        factor_b: b,
        semiprime: n,
        semiprime_bits,
    })
}

/// Default factor size for the family; override with
/// `ANGRYIER_BENCH_PRIME_BITS` to retune difficulty. Z3's sensitivity is
/// erratic on bvmul factoring (measured: 17-bit primes -> 33-bit N, Sat in
/// ~16s; 16-bit -> >20s; 20+-bit -> >20s), so the default is pinned to a
/// size that grinds well past every budget yet still finishes under the
/// ceiling with a model.
const DEFAULT_PRIME_BITS: u32 = 17;

fn prime_bits_from_env() -> u32 {
    std::env::var("ANGRYIER_BENCH_PRIME_BITS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|bits| (16..=33).contains(bits))
        .unwrap_or(DEFAULT_PRIME_BITS)
}

/// The preemption benchmark.
#[test]
#[ignore = "Gate C measurement — run explicitly with --ignored"]
fn gate_c_preemption_cancellation_budgets() -> Result<(), Box<dyn std::error::Error>> {
    let arena = make_arena();
    let family = build_family(&arena, prime_bits_from_env())?;
    let reader: Arc<dyn ExprReader> = arena.clone();
    println!(
        "GATE-C preemption: family=semiprime factoring ({}-bit N), budgets={}ms reps={}",
        family.semiprime_bits,
        BUDGETS_MS.iter().map(u64::to_string).collect::<Vec<_>>().join("/"),
        REPS
    );

    // Arm 1: uninterrupted wall time — the cost the budget defends against.
    let query_full = make_query(family.predicate, &family.constraints, &arena, FULL_ARM_CEILING)?;
    let mut bridge = Z3FfiBridge::new(reader.clone())?;
    let started = Instant::now();
    let full = bridge.solve(&query_full);
    let full_wall = started.elapsed();
    println!(
        "GATE-C preemption: uninterrupted outcome={:?} wall={:.0}ms (ceiling {}ms)",
        full.outcome,
        full_wall.as_secs_f64() * 1000.0,
        FULL_ARM_CEILING.as_millis()
    );
    assert_ne!(full.outcome, SolverOutcomeKind::Unsat, "factoring a semiprime is Sat");
    if full.outcome == SolverOutcomeKind::Sat {
        // The model must be a genuine factorization — the ground truth the
        // cancelled arms are compared against.
        let value_of = |symbol_key: u64| -> Option<u64> {
            full.model
                .iter()
                .find(|(key, _)| *key == symbol_key)
                .and_then(|(_, bytes)| bytes.first_chunk::<8>())
                .map(|chunk| u64::from_le_bytes(*chunk))
        };
        let (factor_a, factor_b) = (
            value_of(u64::from(family.factor_a.0)),
            value_of(u64::from(family.factor_b.0)),
        );
        if let (Some(a), Some(b)) = (factor_a, factor_b) {
            assert_eq!(
                u128::from(a).saturating_mul(u128::from(b)),
                family.semiprime,
                "Sat model must multiply back to N"
            );
            println!(
                "GATE-C preemption: verified ground truth Sat: {a} * {b} == N ({}-bit)",
                family.semiprime_bits
            );
        } else {
            return Err("Sat model must expose both factor symbols".into());
        }
    }
    let full_floor = if full.outcome == SolverOutcomeKind::Sat {
        full_wall
    } else {
        FULL_ARM_CEILING
    };
    assert!(
        full_floor >= Duration::from_millis(1000),
        "family must grind for >= 1s uninterrupted, got {:.0}ms — retune prime bits",
        full_floor.as_secs_f64() * 1000.0
    );

    // Budget arms: cancellation at N ms must be prompt and must never
    // fabricate a decision.
    let mut overhead_estimate = Duration::ZERO;
    for (index, &budget_ms) in BUDGETS_MS.iter().enumerate() {
        let budget = Duration::from_millis(budget_ms);
        let budgeted_query = make_query(family.predicate, &family.constraints, &arena, budget)?;
        let mut walls = Vec::with_capacity(REPS);
        let mut outcomes = Vec::with_capacity(REPS);
        let arm_started = Instant::now();
        for _ in 0..REPS {
            // A fresh context per rep: the budget pays its own translation,
            // which is what a preempted-and-restarted query costs.
            let mut budget_bridge = Z3FfiBridge::new(reader.clone())?;
            let rep_started = Instant::now();
            let result = budget_bridge.solve(&budgeted_query);
            walls.push(rep_started.elapsed());
            outcomes.push(result.outcome);
        }
        let total = arm_started.elapsed();
        let mean = walls
            .iter()
            .try_fold(Duration::ZERO, |sum: Duration, wall| {
                sum.checked_add(*wall).ok_or("duration overflow")
            })
            .map(|sum| sum / walls.len() as u32)?;
        if index == 0 {
            // The smallest budget aborts its check almost immediately, so
            // its wall time bounds translation + setup overhead.
            overhead_estimate = mean.saturating_sub(budget);
        }
        let prompt_limit = budget
            .checked_add(overhead_estimate)
            .and_then(|d| d.checked_add(overhead_estimate))
            .and_then(|d| d.checked_add(overhead_estimate))
            .and_then(|d| d.checked_add(Duration::from_millis(500)))
            .ok_or("duration overflow")?;
        for (outcome, wall) in outcomes.iter().zip(walls.iter()) {
            assert_eq!(
                outcome,
                &SolverOutcomeKind::Unknown,
                "a check cancelled at {budget_ms}ms must return Unknown, never a fabricated Sat/Unsat"
            );
            assert!(
                wall <= &prompt_limit,
                "cancelled check at {budget_ms}ms took {wall:.0?} (limit {prompt_limit:.0?}) — not prompt"
            );
        }
        let qps = REPS as f64 / total.as_secs_f64().max(1e-9);
        println!(
            "GATE-C preemption: budget={budget_ms}ms outcome=Unknown wall_mean={:.0}ms overhead~{:.0}ms throughput={qps:.2} q/s ({} reps in {:.0}ms)",
            mean.as_secs_f64() * 1000.0,
            overhead_estimate.as_secs_f64() * 1000.0,
            REPS,
            total.as_secs_f64() * 1000.0
        );
    }

    // Pre-armed interrupt: the flag must stop the NEXT check with Unknown
    // (never a fabricated answer), promptly.
    let trivial_query = make_query(family.trivial_predicate, &[], &arena, FULL_ARM_CEILING)?;
    let mut prearm_bridge = Z3FfiBridge::new(reader.clone())?;
    prearm_bridge.interrupt();
    let prearm_started = Instant::now();
    let prearm = prearm_bridge.solve(&trivial_query);
    let prearm_wall = prearm_started.elapsed();
    println!(
        "GATE-C preemption: prearmed interrupt() outcome={:?} wall={:.2}ms (next-check cancellation {})",
        prearm.outcome,
        prearm_wall.as_secs_f64() * 1000.0,
        if prearm.outcome == SolverOutcomeKind::Unknown {
            "effective"
        } else {
            "consumed before check"
        }
    );
    assert_ne!(
        prearm.outcome,
        SolverOutcomeKind::Unsat,
        "interrupt must never fabricate Unsat"
    );
    Ok(())
}
