//! Incremental prefix-reuse benchmark: per-query cost of a persistent Z3
//! bridge under a growing constraint path, shaped after the kernel-campaign
//! query family (deep concatenated bitvector chains + interval bounds +
//! region-bound disjunctions + an Itê predicate per query).
//!
//! Three scenarios separate the possible cost sources:
//!
//! - **growing prefix** (the campaign shape): query t asserts constraints
//!   `[0..t]` plus a fresh Itê predicate. If scope reuse works, per-query
//!   cost stays flat as t grows (each query pushes exactly one scope and
//!   translates only the new nodes); if reuse is defeated, every query
//!   re-translates and re-asserts a growing suffix and the cost grows
//!   linearly with t.
//! - **fixed prefix, fresh predicate**: the constraint set stops growing and
//!   only the predicate changes. Isolates predicate-translation cost (a
//!   per-query translate cache re-builds every shared subtree each time; a
//!   persistent one pays only for genuinely new nodes).
//! - **identical query repeated** (control): everything shared. Flat in any
//!   implementation; measures the floor.
//!
//! The measured sweeps are `#[ignore]`d (run with `--ignored
//! --nocapture`); the regression test that asserts prefix reuse structurally
//! (not by timing) runs in CI.

use std::sync::Arc;
use std::time::Instant;

use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprReader, ExprSort, ShardedExprArena};
use angryier_solver::{CanonicalConstraint, SolverBackend, SolverQuery};
use angryier_solver_z3_ffi::Z3FfiBridge;
use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, ExprId, ExpressionNormalizationVersion, SolverOutcomeKind,
    SolverQueryId, TargetProfileId,
};
use core::time::Duration;

/// Number of rotating register symbols (kernel campaigns touch a handful of
/// GPRs per block; symbols recur across constraints, giving cross-constraint
/// DAG sharing).
const REGISTERS: u64 = 8;
/// Deep-chain rounds per step: each round is extract / add / xor / concat,
/// optionally a rotate — deep concatenated exprs like the kernel's.
const CHAIN_ROUNDS: usize = 10;

// ---------------------------------------------------------------------------
// Expression builders
// ---------------------------------------------------------------------------

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

fn make_cmp(
    arena: &ShardedExprArena,
    op: ExprOp,
    left: ExprId,
    right: ExprId,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::Bool,
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

fn make_bool_op(
    arena: &ShardedExprArena,
    op: ExprOp,
    left: ExprId,
    right: ExprId,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::Bool,
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

fn make_extract(
    arena: &ShardedExprArena,
    value: ExprId,
    start: u16,
    width: u16,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    let mut immediate = Vec::with_capacity(4);
    immediate.extend_from_slice(&start.to_le_bytes());
    immediate.extend_from_slice(&width.to_le_bytes());
    arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Extract,
            operands: vec![value],
            immediate,
        })
        .map_err(Into::into)
}

fn make_ite(
    arena: &ShardedExprArena,
    width: u16,
    cond: ExprId,
    then_val: ExprId,
    else_val: ExprId,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(width),
            op: ExprOp::Ite,
            operands: vec![cond, then_val, else_val],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

/// A deep "kernel-shaped" chain over `seed`: CHAIN_ROUNDS rounds of
/// extract→alu→concat with per-step constants, every third round closing
/// with a rotate. ~7 nodes per round.
fn deep_chain(arena: &ShardedExprArena, seed: ExprId, step: usize) -> Result<ExprId, Box<dyn std::error::Error>> {
    let mut acc = seed;
    for round in 0..CHAIN_ROUNDS {
        let salt = (step * 131 + round * 17) as u128;
        let lo = make_extract(arena, acc, 0, 32)?;
        let hi = make_extract(arena, acc, 32, 32)?;
        let lo2 = make_binop(arena, ExprOp::Add, 32, lo, make_const(arena, 32, salt & 0xff)?)?;
        let hi2 = make_binop(arena, ExprOp::Xor, 32, hi, make_const(arena, 32, (salt >> 8) & 0xff)?)?;
        let joined = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Concat,
            operands: vec![lo2, hi2],
            immediate: Vec::new(),
        })?;
        acc = if round % 3 == 2 {
            let amount = ((salt >> 16) % 64) as u128;
            make_binop(arena, ExprOp::RotL, 64, joined, make_const(arena, 8, amount)?)?
        } else {
            make_binop(arena, ExprOp::Shl, 64, joined, make_const(arena, 64, (salt >> 16) % 4)?)?
        };
    }
    Ok(acc)
}

/// One campaign step's path constraint, alternating shapes. Every shape is
/// GROUNDED in the concrete register state (`reg_vals`): each constraint
/// evaluates true under it, exactly like real path constraints (which held
/// at the concrete execution), so every prefix stays Sat:
/// - step % 4 == 0: interval bound `chain < eval(chain) + 1`
/// - step % 4 == 1: eq pin `chain == eval(chain)` (the kernel's
///   "deep concatenated expr == immediate" branch shape)
/// - step % 4 == 2: region-bound disjunction over a two-region map, one
///   region containing the concrete address
/// - step % 4 == 3: shifted bound `chain >> 3 < eval + 1`
fn step_constraint(
    arena: &ShardedExprArena,
    regs: &[ExprId],
    reg_vals: &[u64],
    step: usize,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    let seed = regs[step % regs.len()];
    let chain = deep_chain(arena, seed, step)?;
    let concrete = eval(arena, chain, reg_vals)?;
    match step % 4 {
        0 => {
            let ceiling = make_const(arena, 64, u128::from(concrete.wrapping_add(1)))?;
            make_cmp(arena, ExprOp::Ult, chain, ceiling)
        }
        1 => {
            let pinned = make_const(arena, 64, u128::from(concrete))?;
            make_eq(arena, chain, pinned)
        }
        2 => {
            // (base <= addr < base+size) OR (base2 <= addr < ...) — the
            // driver-mode six-region map compressed to two, with the second
            // region containing the concrete address.
            let addr_seed = regs[(step + 3) % regs.len()];
            let addr = make_binop(arena, ExprOp::Add, 64, addr_seed, make_const(arena, 64, 0x1000)?)?;
            let addr_val = eval(arena, addr, reg_vals)?;
            let base2 = addr_val & !0xfffu64; // 4 KiB-aligned region containing addr_val
            let region = |base: u128, size: u128| -> Result<ExprId, Box<dyn std::error::Error>> {
                let lo = make_cmp(arena, ExprOp::Ule, make_const(arena, 64, base)?, addr)?;
                let hi = make_cmp(arena, ExprOp::Ult, addr, make_const(arena, 64, base + size)?)?;
                make_bool_op(arena, ExprOp::And, lo, hi)
            };
            let r1 = region(0x0040_0000, 0x0010_0000)?;
            let r2 = region(u128::from(base2), 0x1000)?;
            make_bool_op(arena, ExprOp::Or, r1, r2)
        }
        _ => {
            let shifted = make_binop(arena, ExprOp::LShr, 64, chain, make_const(arena, 64, 3)?)?;
            let shifted_val = eval(arena, shifted, reg_vals)?;
            make_cmp(
                arena,
                ExprOp::Ult,
                shifted,
                make_const(arena, 64, u128::from(shifted_val + 1))?,
            )
        }
    }
}

/// The per-query Itê predicate: `ite(chain_t < K_t, free, C_t) == reg`,
/// sharing the step-t deep chain with the step-t constraint (DAG sharing
/// between predicate and prefix, as in the campaign). `K_t` is grounded so
/// the condition is true at the concrete state, leaving `free == reg` as
/// the satisfiable witness path.
fn step_predicate(
    arena: &ShardedExprArena,
    regs: &[ExprId],
    reg_vals: &[u64],
    free: ExprId,
    step: usize,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    let seed = regs[step % regs.len()];
    let chain = deep_chain(arena, seed, step);
    // The arena hash-conses, so this is the SAME ExprId the step-t
    // constraint uses — the sharing is structural, not incidental.
    let chain = chain?;
    let concrete = eval(arena, chain, reg_vals)?;
    let cond = make_cmp(
        arena,
        ExprOp::Ult,
        chain,
        make_const(arena, 64, u128::from(concrete.wrapping_add(1)))?,
    )?;
    let then_val = free;
    let else_val = make_const(arena, 64, 0xdead_0000 + step as u128)?;
    let ite = make_ite(arena, 64, cond, then_val, else_val)?;
    make_eq(arena, ite, regs[(step + 1) % regs.len()])
}

/// Tiny concrete evaluator for the op subset the generator uses (64-bit
/// bitvector arithmetic + bool combinators + Itê), so every generated
/// constraint can be grounded true at a fixed concrete register state —
/// real path constraints are exactly that (they held at the executed
/// state), which keeps every prefix satisfiable by construction.
fn eval(arena: &ShardedExprArena, root: ExprId, reg_vals: &[u64]) -> Result<u64, Box<dyn std::error::Error>> {
    /// Evaluate to either a 64-bit value or a bool.
    fn eval_inner(arena: &ShardedExprArena, id: ExprId, reg_vals: &[u64]) -> Result<u128, Box<dyn std::error::Error>> {
        let node = arena.get(id).ok_or("eval: unknown id")?;
        Ok(match node.op {
            ExprOp::Constant => {
                let mut buf = [0u8; 16];
                let len = node.immediate.len().min(16);
                buf[..len].copy_from_slice(&node.immediate[..len]);
                u128::from_le_bytes(buf)
            }
            ExprOp::Symbol => {
                let mut buf = [0u8; 8];
                let len = node.immediate.len().min(8);
                buf[..len].copy_from_slice(&node.immediate[..len]);
                let sym = u64::from_le_bytes(buf);
                u128::from(
                    *reg_vals
                        .get((sym as usize).wrapping_sub(1))
                        .ok_or("eval: unknown register symbol")?,
                )
            }
            ExprOp::Add | ExprOp::Sub | ExprOp::Xor | ExprOp::Shl | ExprOp::LShr | ExprOp::AShr => {
                let l = eval_inner(arena, node.operands[0], reg_vals)? as u64;
                let r = eval_inner(arena, node.operands[1], reg_vals)? as u64;
                u128::from(match node.op {
                    ExprOp::Add => l.wrapping_add(r),
                    ExprOp::Sub => l.wrapping_sub(r),
                    ExprOp::Xor => l ^ r,
                    ExprOp::Shl => l.wrapping_shl(r as u32),
                    ExprOp::LShr => l.wrapping_shr(r as u32),
                    _ => l.wrapping_shr(r as u32),
                })
            }
            ExprOp::RotL | ExprOp::RotR => {
                let v = eval_inner(arena, node.operands[0], reg_vals)? as u64;
                let amount = (eval_inner(arena, node.operands[1], reg_vals)? % 64) as u32;
                u128::from(if node.op == ExprOp::RotL {
                    v.rotate_left(amount)
                } else {
                    v.rotate_right(amount)
                })
            }
            ExprOp::Concat => {
                let lo = eval_inner(arena, node.operands[0], reg_vals)? as u64;
                let hi = eval_inner(arena, node.operands[1], reg_vals)? as u64;
                u128::from((hi << 32) | (lo & 0xffff_ffff))
            }
            ExprOp::Extract => {
                let v = eval_inner(arena, node.operands[0], reg_vals)? as u64;
                let start = u16::from_le_bytes([node.immediate[0], node.immediate[1]]);
                let width = u16::from_le_bytes([node.immediate[2], node.immediate[3]]);
                u128::from((v >> start) & ((1u64 << width) - 1))
            }
            ExprOp::Eq | ExprOp::Ult | ExprOp::Ule | ExprOp::Slt | ExprOp::Sle | ExprOp::And | ExprOp::Or => {
                let l = eval_inner(arena, node.operands[0], reg_vals)?;
                let r = eval_inner(arena, node.operands[1], reg_vals)?;
                let truth = match node.op {
                    ExprOp::Eq => l == r,
                    ExprOp::Ult => l < r,
                    ExprOp::Ule => l <= r,
                    ExprOp::Slt => (l as i64) < (r as i64),
                    ExprOp::Sle => (l as i64) <= (r as i64),
                    ExprOp::And => l == 1 && r == 1,
                    _ => l == 1 || r == 1,
                };
                u128::from(truth)
            }
            ExprOp::Ite => {
                let cond = eval_inner(arena, node.operands[0], reg_vals)?;
                if cond == 1 {
                    eval_inner(arena, node.operands[1], reg_vals)?
                } else {
                    eval_inner(arena, node.operands[2], reg_vals)?
                }
            }
            _ => return Err("eval: unsupported op".into()),
        })
    }
    Ok(eval_inner(arena, root, reg_vals)? as u64)
}

fn make_query(
    predicate: ExprId,
    constraints: &[(ConstraintId, ExprId)],
    arena: &ShardedExprArena,
    query_id: u64,
) -> Result<SolverQuery, Box<dyn std::error::Error>> {
    let mut canonical_constraints = Vec::with_capacity(constraints.len());
    for (cid, eid) in constraints {
        let key = arena
            .dependency_summary(*eid)
            .map(|s| s.key)
            .ok_or("constraint must have a dependency summary")?;
        canonical_constraints.push(CanonicalConstraint {
            id: *cid,
            key,
            expr: *eid,
        });
    }
    let pred_key = arena
        .dependency_summary(predicate)
        .map(|s| s.key)
        .ok_or("predicate must have a dependency summary")?;
    Ok(SolverQuery::canonical(
        SolverQueryId(query_id),
        &canonical_constraints,
        predicate,
        pred_key,
        TargetProfileId(1),
        ConstraintCanonicalizationVersion(1),
        Duration::from_secs(60),
    )?)
}

// ---------------------------------------------------------------------------
// Measurement scaffolding
// ---------------------------------------------------------------------------

struct Campaign {
    arena: Arc<ShardedExprArena>,
    regs: Vec<ExprId>,
    reg_vals: Vec<u64>,
    free: ExprId,
    constraints: Vec<(ConstraintId, ExprId)>,
}

fn build_campaign(steps: usize) -> Result<Campaign, Box<dyn std::error::Error>> {
    let arena = make_arena();
    let regs: Vec<ExprId> = (0..REGISTERS)
        .map(|i| make_symbol(&arena, 64, i + 1))
        .collect::<Result<_, _>>()?;
    // Fixed concrete register state (a small LCG): every generated
    // constraint evaluates true under it, so every prefix is Sat.
    let mut state = 0x2545_f491_4f6c_dd1du64;
    let reg_vals: Vec<u64> = (0..REGISTERS)
        .map(|_| {
            state = state
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            state ^ (state >> 29)
        })
        .collect();
    // The solver-assisted concretization free variable (u64::MAX immediate,
    // hash-consed across queries, exactly as the runtime does).
    let free = make_symbol(&arena, 64, u64::MAX)?;
    let mut constraints = Vec::with_capacity(steps);
    for step in 0..steps {
        let expr = step_constraint(&arena, &regs, &reg_vals, step)?;
        constraints.push((ConstraintId(step as u64), expr));
    }
    Ok(Campaign {
        arena,
        regs,
        reg_vals,
        free,
        constraints,
    })
}

fn median(samples: &[f64]) -> f64 {
    let mut sorted = samples.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).expect("no NaN timings"));
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    }
}

/// Print the per-query-cost curve: median ms per prefix-length bucket.
fn report_curve(label: &str, samples: &[f64], bucket: usize) {
    println!("curve [{label}] (median ms per {bucket}-query bucket):");
    let mut buckets = Vec::new();
    for chunk in samples.chunks(bucket) {
        buckets.push(median(chunk));
    }
    for (i, ms) in buckets.iter().enumerate() {
        let lo = i * bucket + 1;
        let hi = (i + 1) * bucket;
        println!("  [{lo:>4}..{hi:>4}] {ms:8.3} ms  {}", "#".repeat((ms * 4.0) as usize));
    }
    let first = buckets.first().copied().unwrap_or(f64::MAX);
    let last = buckets.last().copied().unwrap_or(0.0);
    println!(
        "curve [{label}]: first bucket {first:.3} ms, last bucket {last:.3} ms, growth x{:.2}",
        if first > 0.0 { last / first } else { f64::INFINITY }
    );
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Scenario A — the campaign shape: query t has constraints [0..=t] and a
/// fresh Itê predicate. Returns per-query wall times in ms.
fn growing_prefix_run(
    bridge: &mut Z3FfiBridge,
    camp: &Campaign,
    steps: usize,
) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
    let mut samples = Vec::with_capacity(steps);
    for step in 0..steps {
        let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, step)?;
        let query = make_query(predicate, &camp.constraints[..step + 1], &camp.arena, step as u64)?;
        let started = Instant::now();
        let result = bridge.solve(&query);
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(
            result.outcome,
            SolverOutcomeKind::Sat,
            "step {step} must stay Sat (synthetic chain is satisfiable at every depth)"
        );
        samples.push(elapsed);
    }
    Ok(samples)
}

/// Scenario B — fixed full prefix, fresh predicate per query.
fn fixed_prefix_run(
    bridge: &mut Z3FfiBridge,
    camp: &Campaign,
    steps: usize,
) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
    // Warm the full prefix once.
    let warm_predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, 0)?;
    let warm = make_query(warm_predicate, &camp.constraints, &camp.arena, 0)?;
    assert_eq!(bridge.solve(&warm).outcome, SolverOutcomeKind::Sat);
    let mut samples = Vec::with_capacity(steps);
    for step in 0..steps {
        let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, step)?;
        let query = make_query(predicate, &camp.constraints, &camp.arena, 1 + step as u64)?;
        let started = Instant::now();
        let result = bridge.solve(&query);
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(result.outcome, SolverOutcomeKind::Sat, "step {step} must stay Sat");
        samples.push(elapsed);
    }
    Ok(samples)
}

/// Scenario C — identical query repeated (control / floor).
fn identical_query_run(
    bridge: &mut Z3FfiBridge,
    camp: &Campaign,
    steps: usize,
) -> Result<Vec<f64>, Box<dyn std::error::Error>> {
    let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, steps / 2)?;
    let query = make_query(predicate, &camp.constraints, &camp.arena, 2)?;
    let mut samples = Vec::with_capacity(steps);
    for _ in 0..steps {
        let started = Instant::now();
        let result = bridge.solve(&query);
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        samples.push(elapsed);
    }
    Ok(samples)
}

/// The measured sweep: 200 growing-prefix queries plus the two controls.
#[test]
#[ignore = "prefix-reuse measurement — run explicitly with --ignored --nocapture"]
fn incremental_prefix_growth_curve() -> Result<(), Box<dyn std::error::Error>> {
    const STEPS: usize = 200;
    let camp = build_campaign(STEPS)?;
    let reader: Arc<dyn ExprReader> = camp.arena.clone();
    let mut bridge = Z3FfiBridge::new(reader)?;

    let started = Instant::now();
    let growing = growing_prefix_run(&mut bridge, &camp, STEPS)?;
    let growing_wall = started.elapsed();

    let fixed = fixed_prefix_run(&mut bridge, &camp, 60)?;
    let identical = identical_query_run(&mut bridge, &camp, 60)?;

    println!("\n=== incremental reuse benchmark ({STEPS} growing-prefix queries) ===");
    report_curve("growing prefix", &growing, 20);
    report_curve("fixed prefix + fresh predicate", &fixed, 20);
    report_curve("identical query (control)", &identical, 20);
    println!(
        "growing-prefix total wall: {:.1} s; mean {:.3} ms/query; final-query {:.3} ms",
        growing_wall.as_secs_f64(),
        growing.iter().sum::<f64>() / growing.len() as f64,
        growing[STEPS - 1]
    );
    println!(
        "campaign shape: {} constraints, {} chain nodes/constraint, Itê predicate per query",
        STEPS,
        CHAIN_ROUNDS * 7
    );
    Ok(())
}

/// Smoke variant that runs in CI (small, fast) so the generator itself is
/// always exercised: correctness of outcomes across a growing prefix.
#[test]
fn incremental_campaign_stays_correct_at_small_depth() -> Result<(), Box<dyn std::error::Error>> {
    const STEPS: usize = 24;
    let camp = build_campaign(STEPS)?;
    let reader: Arc<dyn ExprReader> = camp.arena.clone();
    let mut bridge = Z3FfiBridge::new(reader)?;
    let samples = growing_prefix_run(&mut bridge, &camp, STEPS)?;
    assert!(samples.iter().all(|&ms| ms >= 0.0));
    // Every query must also extract a model value for the free symbol.
    let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, STEPS - 1)?;
    let query = make_query(predicate, &camp.constraints, &camp.arena, STEPS as u64)?;
    let result = bridge.solve(&query);
    assert_eq!(result.outcome, SolverOutcomeKind::Sat);
    assert!(
        result.model.iter().any(|(sym, _)| *sym == u64::from(camp.free.0)),
        "the concretization free symbol must appear in the model"
    );
    Ok(())
}

/// Structural prefix-reuse regression (no timing, no flakiness): on an
/// append-only constraint path, every query past the first must share the
/// ENTIRE previous prefix, pop nothing, and push exactly one scope —
/// regardless of where each new constraint's canonical key would sort.
/// This is the invariant whose absence made per-query cost grow linearly
/// with path length.
#[test]
fn growing_path_shares_full_prefix_every_query() -> Result<(), Box<dyn std::error::Error>> {
    const STEPS: usize = 40;
    let camp = build_campaign(STEPS)?;
    let reader: Arc<dyn ExprReader> = camp.arena.clone();
    let mut bridge = Z3FfiBridge::new(reader)?;
    for step in 0..STEPS {
        let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, step)?;
        let query = make_query(predicate, &camp.constraints[..step + 1], &camp.arena, step as u64)?;
        let result = bridge.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        let stats = bridge.last_incremental_stats();
        assert_eq!(
            stats.shared_prefix, step,
            "query {step} must share all {step} previously-asserted scopes"
        );
        assert_eq!(stats.popped, 0, "an append-only path must never pop");
        assert_eq!(stats.pushed, 1, "an append-only path pushes exactly one new scope");
    }
    // A shorter query (path truncation) must pop the suffix and reuse the
    // remaining prefix.
    let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, 10)?;
    let query = make_query(predicate, &camp.constraints[..11], &camp.arena, 99)?;
    assert_eq!(bridge.solve(&query).outcome, SolverOutcomeKind::Sat);
    let stats = bridge.last_incremental_stats();
    assert_eq!(stats.shared_prefix, 11);
    assert_eq!(stats.popped, STEPS - 11);
    assert_eq!(stats.pushed, 0);
    Ok(())
}

/// Does re-installing a DIFFERENT `timeout` solver param per query disturb
/// the persistent solver's incremental state? Arm A repeats an identical
/// query with a constant timeout; arm B alternates between two timeouts
/// (neither trips). If arm B is markedly slower, per-query param updates
/// force solver resets and `ANGRYIER_Z3_FFI_NO_SOLVER_TIMEOUT=1` is the
/// mitigation.
#[test]
#[ignore = "timeout-churn measurement — run explicitly with --ignored --nocapture"]
fn timeout_param_churn_effect() -> Result<(), Box<dyn std::error::Error>> {
    const PREFIX: usize = 120;
    const REPS: usize = 40;
    let camp = build_campaign(PREFIX)?;
    let reader: Arc<dyn ExprReader> = camp.arena.clone();
    let mut bridge = Z3FfiBridge::new(reader)?;
    let predicate = step_predicate(&camp.arena, &camp.regs, &camp.reg_vals, camp.free, PREFIX - 1)?;
    let constraints = &camp.constraints[..PREFIX];

    let query_with_timeout = |timeout: Duration| -> Result<SolverQuery, Box<dyn std::error::Error>> {
        let mut canonical = Vec::with_capacity(constraints.len());
        for (cid, eid) in constraints {
            canonical.push(CanonicalConstraint {
                id: *cid,
                key: camp
                    .arena
                    .dependency_summary(*eid)
                    .map(|s| s.key)
                    .ok_or("constraint must have a dependency summary")?,
                expr: *eid,
            });
        }
        let pred_key = camp
            .arena
            .dependency_summary(predicate)
            .map(|s| s.key)
            .ok_or("predicate must have a dependency summary")?;
        Ok(SolverQuery::canonical(
            SolverQueryId(7),
            &canonical,
            predicate,
            pred_key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            timeout,
        )?)
    };

    let mut arm_a = Vec::with_capacity(REPS);
    for _ in 0..REPS {
        let q = query_with_timeout(Duration::from_secs(60))?;
        let started = Instant::now();
        assert_eq!(bridge.solve(&q).outcome, SolverOutcomeKind::Sat);
        arm_a.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    let mut arm_b = Vec::with_capacity(REPS);
    for rep in 0..REPS {
        let timeout = if rep % 2 == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_secs(59)
        };
        let q = query_with_timeout(timeout)?;
        let started = Instant::now();
        assert_eq!(bridge.solve(&q).outcome, SolverOutcomeKind::Sat);
        arm_b.push(started.elapsed().as_secs_f64() * 1000.0);
    }
    println!(
        "\n=== timeout param churn (identical queries, prefix {PREFIX}) ===\n\
         constant timeout : median {:.3} ms  (min {:.3}, max {:.3})\n\
         alternating      : median {:.3} ms  (min {:.3}, max {:.3})\n\
         ratio            : {:.2}x",
        median(&arm_a),
        arm_a.iter().cloned().fold(f64::INFINITY, f64::min),
        arm_a.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        median(&arm_b),
        arm_b.iter().cloned().fold(f64::INFINITY, f64::min),
        arm_b.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
        median(&arm_b) / median(&arm_a),
    );
    Ok(())
}
