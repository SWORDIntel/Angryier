//! Gate C proof: true mid-flight cancellation of an in-flight Z3 check.
//!
//! `tests/preemption_bench.rs` measured two things: the per-query *soft*
//! timeout (Z3's `timeout` solver param) cancels a grindy check promptly
//! with `Unknown`, but a *pre-armed* `interrupt()` flag is consumed by the
//! API calls that precede the check — so interrupting a check that is
//! already running was not expressible. `Z3FfiBridge::solve_with_deadline`
//! closes that gap: it arms a watchdog thread around the
//! `Z3_solver_check_assumptions` call itself (after all translation and
//! pushes), which fires `Z3_interrupt` mid-check when the deadline expires.
//!
//! This test proves, on the same semiprime-factoring family the bench used:
//!
//! - **unarmed**: a deadline longer than the solve returns the correct
//!   `Sat` with a model whose factors multiply back to N, and retiring the
//!   unfired watchdog does not stall (wall time stays under the deadline);
//! - **armed**: a short deadline (default 75 ms) with the soft timeout set
//!   far away (30 s) returns `Unknown` within deadline + slack — the only
//!   mechanism that could have cancelled the check is the watchdog, so the
//!   interrupt provably landed *during* the check — never a fabricated
//!   `Sat`/`Unsat`;
//! - **composition**: with the soft timeout *earlier* than the hard
//!   deadline, the soft limit fires first, the watchdog retires unfired,
//!   and the persistent context stays usable afterwards (a follow-up
//!   trivial query solves to `Sat` through the plain `solve` path).

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

/// Hard deadline for the unarmed (ground-truth) arm — must exceed the
/// uninterrupted solve so the watchdog retires without firing.
const UNARMED_DEADLINE: Duration = Duration::from_secs(30);

/// Soft timeout installed on every factoring query in the armed arm — far
/// beyond every hard deadline used, so any cancellation observed there is
/// attributable to the watchdog alone.
const SOFT_BACKSTOP: Duration = Duration::from_secs(30);

/// Mid-flight deadline for the armed reps (50–100 ms band).
const ARMED_DEADLINE: Duration = Duration::from_millis(75);

/// Repetitions of the armed arm.
const ARMED_REPS: usize = 3;

/// Soft-limit composition arm budget: the query's soft timeout, set earlier
/// than the hard deadline so the soft limit must win.
const SOFT_BUDGET: Duration = Duration::from_millis(100);

/// Generous promptness slack allowed on top of a deadline / soft budget.
const SLACK: Duration = Duration::from_secs(2);

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
    /// Trivially-Sat predicate (a < 11) for the post-cancellation recovery
    /// probe — solved through the plain `solve` path.
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
/// `ANGRYIER_CANCEL_PRIME_BITS` to retune difficulty (16..=33). Pinned to
/// 17-bit primes (33-bit N) — the size the preemption bench measured as
/// grinding well past every deadline yet finishing under the unarmed
/// ceiling with a model (~16 s uninterrupted).
const DEFAULT_PRIME_BITS: u32 = 17;

fn prime_bits_from_env() -> u32 {
    std::env::var("ANGRYIER_CANCEL_PRIME_BITS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|bits| (16..=33).contains(bits))
        .unwrap_or(DEFAULT_PRIME_BITS)
}

/// The mid-flight cancellation proof.
#[test]
#[ignore = "Gate C proof — run explicitly with --release --ignored --nocapture"]
fn mid_flight_deadline_interrupts_in_flight_check() -> Result<(), Box<dyn std::error::Error>> {
    let arena = make_arena();
    let family = build_family(&arena, prime_bits_from_env())?;
    let reader: Arc<dyn ExprReader> = arena.clone();
    println!(
        "GATE-C cancellation: family=semiprime factoring ({}-bit N), prime_bits={} (env ANGRYIER_CANCEL_PRIME_BITS)",
        family.semiprime_bits,
        prime_bits_from_env()
    );

    // Arm 1 — unarmed: a deadline longer than the solve must not disturb it.
    // The soft timeout matches the hard deadline, both far beyond the solve,
    // so the watchdog retires unfired and the model must be genuine.
    let query_full = make_query(family.predicate, &family.constraints, &arena, UNARMED_DEADLINE)?;
    let mut bridge = Z3FfiBridge::new(reader.clone())?;
    let started = Instant::now();
    let full = bridge.solve_with_deadline(&query_full, UNARMED_DEADLINE);
    let full_wall = started.elapsed();
    println!(
        "GATE-C cancellation: unarmed deadline={}ms outcome={:?} wall={:.0}ms (watchdog retired unfired; retire did not block)",
        UNARMED_DEADLINE.as_millis(),
        full.outcome,
        full_wall.as_secs_f64() * 1000.0
    );
    assert_eq!(
        full.outcome,
        SolverOutcomeKind::Sat,
        "a deadline longer than the solve must return the correct Sat"
    );
    assert!(
        full_wall < UNARMED_DEADLINE,
        "retiring an unfired watchdog must not wait out the deadline (wall {full_wall:.0?})"
    );
    // Ground truth: the model must be a genuine factorization of N.
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
    let (Some(a), Some(b)) = (factor_a, factor_b) else {
        return Err("Sat model must expose both factor symbols".into());
    };
    assert_eq!(
        u128::from(a).saturating_mul(u128::from(b)),
        family.semiprime,
        "Sat model must multiply back to N"
    );
    println!("GATE-C cancellation: unarmed verified ground truth: {a} * {b} == N");
    // The family must grind: a short deadline can only land mid-flight if
    // the check cannot possibly finish before it.
    assert!(
        full_wall >= Duration::from_secs(1),
        "family must grind for >= 1s uninterrupted, got {full_wall:.0?} — retune prime bits"
    );

    // Arm 2 — armed: short hard deadline, soft timeout parked at 30 s. The
    // only thing that can cancel the check is the watchdog firing
    // Z3_interrupt mid-flight; the result must be Unknown, promptly.
    for rep in 1..=ARMED_REPS {
        // A fresh bridge per rep: the deadline pays its own translation,
        // which is what a cancelled-and-restarted query costs.
        let query = make_query(family.predicate, &family.constraints, &arena, SOFT_BACKSTOP)?;
        let mut armed_bridge = Z3FfiBridge::new(reader.clone())?;
        let started = Instant::now();
        let result = armed_bridge.solve_with_deadline(&query, ARMED_DEADLINE);
        let wall = started.elapsed();
        println!(
            "GATE-C cancellation: armed rep={}/{} deadline={}ms soft_timeout={}ms outcome={:?} wall={:.0}ms (soft limit parked far away — only the mid-flight interrupt could cancel)",
            rep,
            ARMED_REPS,
            ARMED_DEADLINE.as_millis(),
            SOFT_BACKSTOP.as_millis(),
            result.outcome,
            wall.as_secs_f64() * 1000.0
        );
        assert_eq!(
            result.outcome,
            SolverOutcomeKind::Unknown,
            "a check cancelled mid-flight at {}ms must return Unknown, never a fabricated Sat/Unsat",
            ARMED_DEADLINE.as_millis()
        );
        let prompt_limit = ARMED_DEADLINE.checked_add(SLACK).ok_or("duration overflow")?;
        assert!(
            wall <= prompt_limit,
            "mid-flight cancellation at {ARMED_DEADLINE:.0?} took {wall:.0?} (limit {prompt_limit:.0?}) — not prompt"
        );
        assert!(
            wall >= ARMED_DEADLINE,
            "Unknown returned before the deadline elapsed ({wall:.0?} < {ARMED_DEADLINE:.0?}) — cancellation did not come from this watchdog"
        );
    }

    // Arm 3 — composition: soft timeout earlier than the hard deadline. The
    // soft limit must win, the watchdog must retire unfired, and the
    // persistent context must stay usable for later queries.
    let soft_query = make_query(family.predicate, &family.constraints, &arena, SOFT_BUDGET)?;
    let mut soft_bridge = Z3FfiBridge::new(reader.clone())?;
    for rep in 1..=2 {
        let started = Instant::now();
        let result = soft_bridge.solve_with_deadline(&soft_query, UNARMED_DEADLINE);
        let wall = started.elapsed();
        println!(
            "GATE-C cancellation: softlimit rep={} timeout={}ms deadline={}ms outcome={:?} wall={:.0}ms (soft limit fired first; watchdog retired unfired)",
            rep,
            SOFT_BUDGET.as_millis(),
            UNARMED_DEADLINE.as_millis(),
            result.outcome,
            wall.as_secs_f64() * 1000.0
        );
        assert_eq!(
            result.outcome,
            SolverOutcomeKind::Unknown,
            "the earlier soft limit must cancel the check with Unknown"
        );
        let prompt_limit = SOFT_BUDGET.checked_add(SLACK).ok_or("duration overflow")?;
        assert!(
            wall <= prompt_limit,
            "soft-limit cancellation at {SOFT_BUDGET:.0?} took {wall:.0?} (limit {prompt_limit:.0?}) — not prompt"
        );
    }

    // Recovery: after cancelled checks, the plain (non-cancellable) solve
    // path on the same bridge must answer a trivial query correctly — the
    // cancelled context neither fabricates answers nor stays poisoned.
    let trivial_query = make_query(family.trivial_predicate, &[], &arena, SOFT_BACKSTOP)?;
    let recovery = soft_bridge.solve(&trivial_query);
    println!(
        "GATE-C cancellation: recovery after cancelled checks: trivial query via plain solve outcome={:?}",
        recovery.outcome
    );
    assert_ne!(
        recovery.outcome,
        SolverOutcomeKind::Unsat,
        "recovery probe must never fabricate Unsat"
    );
    assert_eq!(
        recovery.outcome,
        SolverOutcomeKind::Sat,
        "the persistent context must remain correctly usable after cancelled checks"
    );
    Ok(())
}
