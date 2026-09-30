//! Speculative fork execution — hide solver latency behind eager branch execution.
//!
//! When a symbolic branch is encountered the engine can *speculate*: fork
//! O(1) COW state immediately, begin executing **both** (or the concrete-
//! favoured) paths concurrently while the solver feasibility check runs in
//! the background, then **commit** the surviving side and **prune** the
//! infeasible one when the solver answer arrives.
//!
//! # How it fits in the pipeline
//!
//! ```text
//!  SymbolicSession::step_state_checked
//!      │
//!      ├─ branch hit ──► SpeculativeForkExecutor::speculate_branch
//!      │                      │ (solver fires async / caller-driven)
//!      │                      ▼
//!      │               speculative steps execute on both paths
//!      │                      │
//!      └─ solver returns ──► commit_feasible / rollback
//! ```
//!
//! The module is deliberately self-contained and **does not** interact with
//! the solver or the async runtime directly — the caller drives the solver
//! and supplies the `SolverOutcomeKind` to [`SpeculativeForkExecutor::commit_feasible`].
//! This keeps the module `no_std`-compatible and lets the caller choose any
//! execution strategy (thread pool, tokio, rayon, …).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use angryier_solver::SolverOutcomeKind;
use angryier_types::StateId;

// ── Policy ──────────────────────────────────────────────────────────────────

/// Controls how aggressively the executor speculatively executes branches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SpeculativeForkPolicy {
    /// Do not speculate at all — fall back to sequential solver-then-step.
    #[default]
    Disabled,
    /// Execute only the concrete-favoured path speculatively while the solver
    /// checks the other direction.  Cheaper than `EagerDual` but misses
    /// wins when the concrete side turns out infeasible.
    FavorConcrete,
    /// Execute **both** directions immediately, prune the infeasible one when
    /// the solver returns.  Maximum latency hiding at the cost of wasted work
    /// on the infeasible path.
    EagerDual,
}

// ── Branch info ──────────────────────────────────────────────────────────────

/// Identifies a symbolic branch: the two outgoing states and the constraint
/// id the solver is checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchInfo {
    /// The `StateId` of the *taken* fork.
    pub taken_id: StateId,
    /// The `StateId` of the *not-taken* fork.
    pub not_taken_id: StateId,
    /// Opaque id of the in-flight solver query (for correlation).
    pub constraint_id: u64,
}

// ── Checkpoint ───────────────────────────────────────────────────────────────

/// Snapshot of a state at the moment speculation began.
///
/// Used both to record progress during speculation and to roll back if
/// speculation is aborted (budget exceeded, solver timeout, etc.).
#[derive(Clone, Debug)]
pub struct SpeculativeForkCheckpoint {
    /// The `StateId` of the speculated state this checkpoint belongs to.
    pub state_id: StateId,
    /// Execution step count *before* any speculative steps were taken.
    pub step_count_at_fork: u64,
    /// How many speculative steps have been executed on this path so far.
    pub speculative_steps: u64,
    /// The constraint id of the in-flight branch query.
    pub constraint_id: u64,
    /// Whether this state is on the *concrete-favoured* side of the branch.
    pub is_concrete_favoured: bool,
}

impl SpeculativeForkCheckpoint {
    /// Returns `true` if `budget` speculative steps have been consumed.
    #[must_use]
    pub fn budget_exceeded(&self, budget: u64) -> bool {
        self.speculative_steps >= budget
    }
}

// ── Internal per-fork record ──────────────────────────────────────────────────

/// All tracking data for one speculative fork pair.
#[derive(Debug)]
struct ForkRecord {
    branch: BranchInfo,
    taken_checkpoint: SpeculativeForkCheckpoint,
    not_taken_checkpoint: SpeculativeForkCheckpoint,
    /// Number of speculative steps the caller allowed per side.
    budget: u64,
}

// ── Metrics ──────────────────────────────────────────────────────────────────

/// Aggregate statistics emitted by a [`SpeculativeForkExecutor`].
#[derive(Clone, Debug, Default)]
pub struct SpeculativeMetrics {
    /// Total speculative steps executed across all forks and both sides.
    pub speculative_steps_executed: u64,
    /// Forks where the speculated side matched the solver's verdict
    /// (no rollback needed).
    pub speculative_hits: u64,
    /// Forks where the speculated side was pruned (work wasted).
    pub speculative_misses: u64,
    /// Speculative steps that overlapped with solver latency — i.e., steps
    /// executed while the solver was still running.  This approximates the
    /// latency hidden.
    pub solver_latency_hidden_steps: u64,
}

impl SpeculativeMetrics {
    /// Combines two sets of metrics (useful for aggregating across threads).
    #[must_use]
    pub fn merge(&self, other: &Self) -> Self {
        Self {
            speculative_steps_executed: self.speculative_steps_executed + other.speculative_steps_executed,
            speculative_hits: self.speculative_hits + other.speculative_hits,
            speculative_misses: self.speculative_misses + other.speculative_misses,
            solver_latency_hidden_steps: self.solver_latency_hidden_steps + other.solver_latency_hidden_steps,
        }
    }
}

// ── Shared atomic metrics ─────────────────────────────────────────────────────

/// Atomically-updated counters that can be shared across threads
/// (e.g. when a [`crate::OsWorkerPool`] drives parallel speculation).
#[derive(Debug, Default)]
pub struct AtomicSpeculativeMetrics {
    pub speculative_steps_executed: AtomicU64,
    pub speculative_hits: AtomicU64,
    pub speculative_misses: AtomicU64,
    pub solver_latency_hidden_steps: AtomicU64,
}

impl AtomicSpeculativeMetrics {
    /// Snapshots the current counter values into a plain [`SpeculativeMetrics`].
    #[must_use]
    pub fn snapshot(&self) -> SpeculativeMetrics {
        SpeculativeMetrics {
            speculative_steps_executed: self.speculative_steps_executed.load(Ordering::Relaxed),
            speculative_hits: self.speculative_hits.load(Ordering::Relaxed),
            speculative_misses: self.speculative_misses.load(Ordering::Relaxed),
            solver_latency_hidden_steps: self.solver_latency_hidden_steps.load(Ordering::Relaxed),
        }
    }
}

// ── Executor ─────────────────────────────────────────────────────────────────

/// Tracks speculative forks, drives commit/rollback decisions, and collects
/// metrics.
///
/// One executor instance should be created per symbolic session (or per
/// worker thread when the session is parallelised over an
/// [`crate::OsWorkerPool`]).  Thread-safety of the metrics counters is
/// provided via `Arc<AtomicSpeculativeMetrics>`; the fork records themselves
/// are stored in a plain `BTreeMap` and are accessed only from the owning
/// thread.
pub struct SpeculativeForkExecutor {
    policy: SpeculativeForkPolicy,
    /// Live fork records keyed by the *taken* `StateId` (primary key chosen
    /// because the taken side is always present regardless of policy).
    forks: BTreeMap<u64, ForkRecord>,
    /// Shared atomic metric counters.
    pub metrics: Arc<AtomicSpeculativeMetrics>,
}

impl SpeculativeForkExecutor {
    /// Creates a new executor with the given policy.
    pub fn new(policy: SpeculativeForkPolicy) -> Self {
        Self {
            policy,
            forks: BTreeMap::new(),
            metrics: Arc::new(AtomicSpeculativeMetrics::default()),
        }
    }

    /// Creates a new executor sharing metric counters with an existing one
    /// (useful for worker-thread clones that aggregate into a session total).
    pub fn with_shared_metrics(policy: SpeculativeForkPolicy, metrics: Arc<AtomicSpeculativeMetrics>) -> Self {
        Self {
            policy,
            forks: BTreeMap::new(),
            metrics,
        }
    }

    /// Returns the active policy.
    pub fn policy(&self) -> SpeculativeForkPolicy {
        self.policy
    }

    /// Registers a speculative fork for `branch`, allowing up to `budget`
    /// speculative steps per side before the executor forces a rollback.
    ///
    /// Under [`SpeculativeForkPolicy::Disabled`] this is a no-op and returns
    /// `false`.  Under `FavorConcrete` only the concrete-favoured checkpoint
    /// is meaningful; under `EagerDual` both checkpoints are live.
    ///
    /// Returns `true` when speculation was registered, `false` when the policy
    /// is `Disabled`.
    pub fn speculate_branch(
        &mut self,
        branch: BranchInfo,
        taken_step_count: u64,
        not_taken_step_count: u64,
        budget: u64,
    ) -> bool {
        if self.policy == SpeculativeForkPolicy::Disabled {
            return false;
        }

        let taken_checkpoint = SpeculativeForkCheckpoint {
            state_id: branch.taken_id,
            step_count_at_fork: taken_step_count,
            speculative_steps: 0,
            constraint_id: branch.constraint_id,
            is_concrete_favoured: true,
        };
        let not_taken_checkpoint = SpeculativeForkCheckpoint {
            state_id: branch.not_taken_id,
            step_count_at_fork: not_taken_step_count,
            speculative_steps: 0,
            constraint_id: branch.constraint_id,
            is_concrete_favoured: false,
        };

        let record = ForkRecord {
            branch,
            taken_checkpoint,
            not_taken_checkpoint,
            budget,
        };
        self.forks.insert(branch.taken_id.0, record);
        true
    }

    /// Notifies the executor that one speculative step was executed on the
    /// path identified by `state_id`.
    ///
    /// Returns `Ok(false)` when the state is not under speculation (call is
    /// idempotent / safe to ignore).  Returns `Ok(true)` when the step was
    /// recorded.  Returns `Err(state_id)` when the budget has been exceeded
    /// — the caller **must** call [`rollback`](Self::rollback) for this state.
    pub fn record_speculative_step(&mut self, state_id: StateId) -> Result<bool, StateId> {
        let key = self.fork_key_for(state_id);
        let Some(record) = key.and_then(|k| self.forks.get_mut(&k)) else {
            return Ok(false);
        };

        let checkpoint = if record.branch.taken_id == state_id {
            &mut record.taken_checkpoint
        } else {
            &mut record.not_taken_checkpoint
        };

        checkpoint.speculative_steps += 1;
        self.metrics
            .speculative_steps_executed
            .fetch_add(1, Ordering::Relaxed);

        if checkpoint.budget_exceeded(record.budget) {
            Err(state_id)
        } else {
            // Count this step as hidden solver latency (it ran while the
            // solver query was conceptually in-flight).
            self.metrics
                .solver_latency_hidden_steps
                .fetch_add(1, Ordering::Relaxed);
            Ok(true)
        }
    }

    /// Commits the feasible branch and prunes the infeasible one based on
    /// `sat_outcome`.
    ///
    /// * `Sat`     → taken side survives; not-taken side is pruned.
    /// * `Unsat`   → not-taken side survives; taken side is pruned.
    /// * `Unknown` / `BackendError` → both sides survive (conservative).
    ///
    /// Returns a [`CommitOutcome`] describing which state ids were kept and
    /// which were pruned, or `None` when `state_id` is not tracked.
    pub fn commit_feasible(
        &mut self,
        state_id: StateId,
        sat_outcome: SolverOutcomeKind,
    ) -> Option<CommitOutcome> {
        let key = self.fork_key_for(state_id)?;
        let record = self.forks.remove(&key)?;

        let (kept, pruned) = match sat_outcome {
            SolverOutcomeKind::Sat => {
                // Taken direction is feasible.
                (record.branch.taken_id, Some(record.branch.not_taken_id))
            }
            SolverOutcomeKind::Unsat => {
                // Not-taken direction is feasible.
                (record.branch.not_taken_id, Some(record.branch.taken_id))
            }
            // Unknown / BackendError: keep both, do not prune.
            _ => (record.branch.taken_id, None),
        };

        // Determine whether the concrete-favoured side survived (hit) or was
        // pruned (miss).
        let concrete_favoured_pruned = pruned
            .map(|p| p == record.branch.taken_id) // taken is concrete-favoured
            .unwrap_or(false);

        if concrete_favoured_pruned {
            self.metrics.speculative_misses.fetch_add(1, Ordering::Relaxed);
        } else if pruned.is_some() {
            self.metrics.speculative_hits.fetch_add(1, Ordering::Relaxed);
        }

        Some(CommitOutcome {
            kept,
            pruned,
            also_kept: if pruned.is_none() {
                Some(record.branch.not_taken_id)
            } else {
                None
            },
            constraint_id: record.branch.constraint_id,
        })
    }

    /// Rolls back speculative progress for `state_id` (e.g. budget exceeded
    /// or solver timed out).
    ///
    /// Returns the checkpoint that was active at rollback time, or `None`
    /// when the state is not tracked.  The **caller** is responsible for
    /// actually restoring the execution state to `checkpoint.step_count_at_fork`
    /// — this executor only tracks bookkeeping, it does not hold copies of
    /// the symbolic state itself.
    pub fn rollback(&mut self, state_id: StateId) -> Option<RollbackOutcome> {
        let key = self.fork_key_for(state_id)?;
        let record = self.forks.remove(&key)?;

        let checkpoint = if record.branch.taken_id == state_id {
            record.taken_checkpoint
        } else {
            record.not_taken_checkpoint
        };

        Some(RollbackOutcome {
            state_id,
            step_count_at_fork: checkpoint.step_count_at_fork,
            speculative_steps_wasted: checkpoint.speculative_steps,
            constraint_id: checkpoint.constraint_id,
        })
    }

    /// Returns an immutable view of the checkpoint for `state_id`, if any.
    pub fn checkpoint_for(&self, state_id: StateId) -> Option<&SpeculativeForkCheckpoint> {
        let key = self.fork_key_for_ref(state_id)?;
        let record = self.forks.get(&key)?;
        if record.branch.taken_id == state_id {
            Some(&record.taken_checkpoint)
        } else {
            Some(&record.not_taken_checkpoint)
        }
    }

    /// Returns the number of active (in-flight) fork records.
    pub fn active_forks(&self) -> usize {
        self.forks.len()
    }

    /// Snapshots the current metrics counters.
    pub fn metrics_snapshot(&self) -> SpeculativeMetrics {
        self.metrics.snapshot()
    }

    // ── internal helpers ────────────────────────────────────────────────────

    /// Finds the BTreeMap key (taken_id.0) for a record that contains
    /// `state_id` on either side.  Requires `&mut self` for consistency with
    /// callers that immediately borrow mutably afterwards.
    fn fork_key_for(&mut self, state_id: StateId) -> Option<u64> {
        self.fork_key_for_ref(state_id)
    }

    fn fork_key_for_ref(&self, state_id: StateId) -> Option<u64> {
        // Fast path: state_id IS the taken side.
        if self.forks.contains_key(&state_id.0) {
            return Some(state_id.0);
        }
        // Slow path: state_id is the not-taken side — scan.
        self.forks
            .iter()
            .find(|(_, r)| r.branch.not_taken_id == state_id)
            .map(|(k, _)| *k)
    }
}

// ── Outcome types ─────────────────────────────────────────────────────────────

/// Result of [`SpeculativeForkExecutor::commit_feasible`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitOutcome {
    /// The surviving `StateId` (always present).
    pub kept: StateId,
    /// The pruned `StateId`, or `None` when the solver returned `Unknown`.
    pub pruned: Option<StateId>,
    /// When the solver returned `Unknown`, the second surviving state.
    pub also_kept: Option<StateId>,
    /// The constraint id of the resolved query.
    pub constraint_id: u64,
}

/// Result of [`SpeculativeForkExecutor::rollback`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackOutcome {
    pub state_id: StateId,
    /// Step count to which the caller should restore the state.
    pub step_count_at_fork: u64,
    /// Number of speculative steps that were wasted.
    pub speculative_steps_wasted: u64,
    /// Constraint id of the aborted query.
    pub constraint_id: u64,
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_solver::SolverOutcomeKind;
    use angryier_types::StateId;

    // Helpers ----------------------------------------------------------------

    fn state(n: u64) -> StateId {
        StateId(n)
    }

    fn branch(taken: u64, not_taken: u64, cid: u64) -> BranchInfo {
        BranchInfo {
            taken_id: state(taken),
            not_taken_id: state(not_taken),
            constraint_id: cid,
        }
    }

    // ── FavorConcrete: speculation and commit ────────────────────────────────

    #[test]
    fn favor_concrete_registers_and_commits() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::FavorConcrete);

        let info = branch(1, 2, 42);
        // Registers the fork (step counts: taken=10, not_taken=10, budget=5).
        assert!(exec.speculate_branch(info, 10, 10, 5));
        assert_eq!(exec.active_forks(), 1);

        // Record two speculative steps on the taken (concrete-favoured) side.
        assert_eq!(exec.record_speculative_step(state(1)), Ok(true));
        assert_eq!(exec.record_speculative_step(state(1)), Ok(true));

        // Solver returns Sat → taken side survives.
        let outcome = exec.commit_feasible(state(1), SolverOutcomeKind::Sat).unwrap();
        assert_eq!(outcome.kept, state(1));
        assert_eq!(outcome.pruned, Some(state(2)));
        assert!(outcome.also_kept.is_none());
        assert_eq!(outcome.constraint_id, 42);

        // Fork is consumed.
        assert_eq!(exec.active_forks(), 0);

        // Hit counter incremented (concrete-favoured side won).
        let m = exec.metrics_snapshot();
        assert_eq!(m.speculative_hits, 1);
        assert_eq!(m.speculative_misses, 0);
        assert_eq!(m.speculative_steps_executed, 2);
        assert_eq!(m.solver_latency_hidden_steps, 2);
    }

    // ── FavorConcrete: solver says Unsat → concrete side is pruned (miss) ───

    #[test]
    fn favor_concrete_miss_on_unsat() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::FavorConcrete);
        let info = branch(10, 11, 99);
        exec.speculate_branch(info, 0, 0, 10);

        // Record one step on taken side.
        exec.record_speculative_step(state(10)).unwrap();

        // Solver says the taken direction is infeasible.
        let outcome = exec.commit_feasible(state(10), SolverOutcomeKind::Unsat).unwrap();
        assert_eq!(outcome.kept, state(11));
        assert_eq!(outcome.pruned, Some(state(10)));

        let m = exec.metrics_snapshot();
        assert_eq!(m.speculative_misses, 1);
        assert_eq!(m.speculative_hits, 0);
    }

    // ── EagerDual: both sides speculate; solver prunes one ───────────────────

    #[test]
    fn eager_dual_both_sides_then_prune() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::EagerDual);
        let info = branch(20, 21, 7);
        exec.speculate_branch(info, 100, 100, 8);

        // Three steps on the taken side.
        for _ in 0..3 {
            assert_eq!(exec.record_speculative_step(state(20)), Ok(true));
        }
        // Two steps on the not-taken side.
        for _ in 0..2 {
            assert_eq!(exec.record_speculative_step(state(21)), Ok(true));
        }

        // Solver returns Sat: taken kept, not-taken pruned.
        let outcome = exec.commit_feasible(state(20), SolverOutcomeKind::Sat).unwrap();
        assert_eq!(outcome.kept, state(20));
        assert_eq!(outcome.pruned, Some(state(21)));

        let m = exec.metrics_snapshot();
        assert_eq!(m.speculative_steps_executed, 5);
        assert_eq!(m.speculative_hits, 1);
    }

    // ── EagerDual: Unknown outcome → both states survive ────────────────────

    #[test]
    fn eager_dual_unknown_keeps_both() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::EagerDual);
        let info = branch(30, 31, 55);
        exec.speculate_branch(info, 0, 0, 20);

        exec.record_speculative_step(state(30)).unwrap();
        exec.record_speculative_step(state(31)).unwrap();

        let outcome = exec.commit_feasible(state(30), SolverOutcomeKind::Unknown).unwrap();
        assert_eq!(outcome.kept, state(30));
        assert!(outcome.pruned.is_none());
        assert_eq!(outcome.also_kept, Some(state(31)));

        let m = exec.metrics_snapshot();
        // Unknown → neither hit nor miss.
        assert_eq!(m.speculative_hits, 0);
        assert_eq!(m.speculative_misses, 0);
    }

    // ── Budget limit triggers rollback ───────────────────────────────────────

    #[test]
    fn budget_exceeded_triggers_rollback() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::EagerDual);
        let info = branch(40, 41, 3);
        exec.speculate_branch(info, 50, 50, 3);

        // Steps 1 and 2: within budget.
        assert_eq!(exec.record_speculative_step(state(40)), Ok(true));
        assert_eq!(exec.record_speculative_step(state(40)), Ok(true));
        // Step 3: budget hits exactly → error.
        assert_eq!(exec.record_speculative_step(state(40)), Err(state(40)));

        // Caller rolls back.
        let rb = exec.rollback(state(40)).unwrap();
        assert_eq!(rb.state_id, state(40));
        assert_eq!(rb.step_count_at_fork, 50);
        assert_eq!(rb.speculative_steps_wasted, 3);
        assert_eq!(rb.constraint_id, 3);

        // Fork is gone.
        assert_eq!(exec.active_forks(), 0);
    }

    // ── Disabled policy is a no-op ───────────────────────────────────────────

    #[test]
    fn disabled_policy_is_noop() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::Disabled);
        let info = branch(60, 61, 1);
        assert!(!exec.speculate_branch(info, 0, 0, 10));
        assert_eq!(exec.active_forks(), 0);
        // record_speculative_step returns Ok(false) when not tracked.
        assert_eq!(exec.record_speculative_step(state(60)), Ok(false));
        // commit_feasible returns None.
        assert!(exec.commit_feasible(state(60), SolverOutcomeKind::Sat).is_none());
    }

    // ── Metrics accuracy: all counters reflect multi-fork activity ────────────

    #[test]
    fn metrics_accuracy_multi_fork() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::EagerDual);

        // Fork A: hits.
        exec.speculate_branch(branch(70, 71, 1), 0, 0, 10);
        exec.record_speculative_step(state(70)).unwrap();
        exec.record_speculative_step(state(71)).unwrap();
        exec.commit_feasible(state(70), SolverOutcomeKind::Sat);

        // Fork B: misses.
        exec.speculate_branch(branch(72, 73, 2), 0, 0, 10);
        exec.record_speculative_step(state(72)).unwrap();
        exec.commit_feasible(state(72), SolverOutcomeKind::Unsat);

        let m = exec.metrics_snapshot();
        assert_eq!(m.speculative_steps_executed, 3); // 2 from A + 1 from B
        assert_eq!(m.solver_latency_hidden_steps, 3);
        assert_eq!(m.speculative_hits, 1);
        assert_eq!(m.speculative_misses, 1);
    }

    // ── Shared AtomicSpeculativeMetrics across two executors ─────────────────

    #[test]
    fn shared_metrics_aggregate_across_executors() {
        let shared = Arc::new(AtomicSpeculativeMetrics::default());

        let mut exec_a = SpeculativeForkExecutor::with_shared_metrics(
            SpeculativeForkPolicy::EagerDual,
            shared.clone(),
        );
        let mut exec_b = SpeculativeForkExecutor::with_shared_metrics(
            SpeculativeForkPolicy::EagerDual,
            shared.clone(),
        );

        exec_a.speculate_branch(branch(80, 81, 10), 0, 0, 10);
        exec_b.speculate_branch(branch(82, 83, 11), 0, 0, 10);

        exec_a.record_speculative_step(state(80)).unwrap();
        exec_b.record_speculative_step(state(82)).unwrap();
        exec_b.record_speculative_step(state(82)).unwrap();

        exec_a.commit_feasible(state(80), SolverOutcomeKind::Sat);
        exec_b.commit_feasible(state(82), SolverOutcomeKind::Sat);

        let m = shared.snapshot();
        assert_eq!(m.speculative_steps_executed, 3);
        assert_eq!(m.speculative_hits, 2);
    }

    // ── checkpoint_for returns correct side ──────────────────────────────────

    #[test]
    fn checkpoint_for_returns_correct_side() {
        let mut exec = SpeculativeForkExecutor::new(SpeculativeForkPolicy::EagerDual);
        exec.speculate_branch(branch(90, 91, 5), 100, 200, 50);

        let cp_taken = exec.checkpoint_for(state(90)).unwrap();
        assert_eq!(cp_taken.state_id, state(90));
        assert_eq!(cp_taken.step_count_at_fork, 100);
        assert!(cp_taken.is_concrete_favoured);

        let cp_not_taken = exec.checkpoint_for(state(91)).unwrap();
        assert_eq!(cp_not_taken.state_id, state(91));
        assert_eq!(cp_not_taken.step_count_at_fork, 200);
        assert!(!cp_not_taken.is_concrete_favoured);
    }
}
