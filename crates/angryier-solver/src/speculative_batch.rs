//! Speculative Constraint Batching.
//!
//! Provides batching, dependency cone slicing, and redundancy elimination
//! for speculative symbolic execution branches.

#![forbid(unsafe_code)]

use crate::{SolverBackend, SolverQuery, SolverResult};
use angryier_types::{DependencyKey, StateId};
use core::time::Duration;
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::Instant,
};

/// Identifier for a speculative branch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BranchId(pub u64);

/// A single speculative branch assertion with its dependency cone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeculativeAssertion {
    pub state_id: StateId,
    pub branch_id: BranchId,
    pub dependency_key: DependencyKey,
    pub query: SolverQuery,
    pub dependency_cone: BTreeSet<DependencyKey>,
    pub associated_tags: Vec<(StateId, BranchId, DependencyKey)>,
}

impl SpeculativeAssertion {
    /// Creates a new speculative assertion, populating its dependency cone
    /// from `dependency_key`, `query.predicate_key()`, and `query.constraint_keys()`.
    pub fn new(
        state_id: StateId,
        branch_id: BranchId,
        dependency_key: DependencyKey,
        query: SolverQuery,
    ) -> Self {
        let mut dependency_cone = BTreeSet::new();
        if dependency_key != DependencyKey::default() {
            dependency_cone.insert(dependency_key);
        }
        if query.predicate_key() != DependencyKey::default() {
            dependency_cone.insert(query.predicate_key());
        }
        for &key in query.constraint_keys() {
            if key != DependencyKey::default() {
                dependency_cone.insert(key);
            }
        }
        let tag = (state_id, branch_id, dependency_key);
        Self {
            state_id,
            branch_id,
            dependency_key,
            query,
            dependency_cone,
            associated_tags: vec![tag],
        }
    }

    /// Creates a speculative assertion with an explicitly specified dependency cone.
    pub fn with_cone(
        state_id: StateId,
        branch_id: BranchId,
        dependency_key: DependencyKey,
        query: SolverQuery,
        cone: impl IntoIterator<Item = DependencyKey>,
    ) -> Self {
        let mut dependency_cone: BTreeSet<DependencyKey> = cone.into_iter().collect();
        if dependency_key != DependencyKey::default() {
            dependency_cone.insert(dependency_key);
        }
        let tag = (state_id, branch_id, dependency_key);
        Self {
            state_id,
            branch_id,
            dependency_key,
            query,
            dependency_cone,
            associated_tags: vec![tag],
        }
    }

    /// Returns the identifying tag `(StateId, BranchId, DependencyKey)`.
    pub fn tag(&self) -> (StateId, BranchId, DependencyKey) {
        (self.state_id, self.branch_id, self.dependency_key)
    }

    /// Checks if this assertion is functionally identical to another assertion
    /// across concurrent speculative paths.
    pub fn is_identical_to(&self, other: &Self) -> bool {
        if self.dependency_key != DependencyKey::default()
            && self.dependency_key == other.dependency_key
        {
            return true;
        }
        self.query.canonical_key() == other.query.canonical_key()
    }
}

/// Accumulates speculative branch assertions, performs dependency cone slicing,
/// and eliminates redundancies across concurrent speculative paths.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpeculativeConstraintBatch {
    assertions: Vec<SpeculativeAssertion>,
}

impl SpeculativeConstraintBatch {
    /// Creates an empty batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a speculative assertion to the batch.
    pub fn add(&mut self, assertion: SpeculativeAssertion) {
        self.assertions.push(assertion);
    }

    /// Creates and adds an assertion tagged by `(StateId, BranchId, DependencyKey)`.
    pub fn add_assertion(
        &mut self,
        state_id: StateId,
        branch_id: BranchId,
        dependency_key: DependencyKey,
        query: SolverQuery,
    ) {
        self.add(SpeculativeAssertion::new(
            state_id,
            branch_id,
            dependency_key,
            query,
        ));
    }

    /// Number of assertions currently in the batch.
    pub fn len(&self) -> usize {
        self.assertions.len()
    }

    /// Returns `true` if the batch contains no assertions.
    pub fn is_empty(&self) -> bool {
        self.assertions.is_empty()
    }

    /// Returns a slice of the assertions in the batch.
    pub fn assertions(&self) -> &[SpeculativeAssertion] {
        &self.assertions
    }

    /// Consumes the batch and returns the assertions.
    pub fn into_assertions(self) -> Vec<SpeculativeAssertion> {
        self.assertions
    }

    /// Deduplicates identical assertions across concurrent speculative paths in-place.
    ///
    /// Preserves all `(StateId, BranchId, DependencyKey)` tags in `associated_tags`
    /// of the remaining unique assertion, so every waiter receives the result.
    /// Returns the number of eliminated duplicate queries.
    pub fn eliminate_redundancy(&mut self) -> usize {
        if self.assertions.len() <= 1 {
            return 0;
        }

        let mut unique: Vec<SpeculativeAssertion> = Vec::new();
        let mut query_key_to_idx: HashMap<DependencyKey, usize> = HashMap::new();
        let mut deduplicated_count = 0;

        for assertion in self.assertions.drain(..) {
            let query_key = assertion.query.canonical_key();

            let matched_idx = if query_key != DependencyKey::default() {
                query_key_to_idx.get(&query_key).copied()
            } else {
                None
            };

            if let Some(idx) = matched_idx {
                unique[idx].associated_tags.extend(assertion.associated_tags);
                unique[idx].dependency_cone.extend(assertion.dependency_cone);
                deduplicated_count += 1;
            } else {
                let new_idx = unique.len();
                if query_key != DependencyKey::default() {
                    query_key_to_idx.insert(query_key, new_idx);
                }
                unique.push(assertion);
            }
        }

        self.assertions = unique;
        deduplicated_count
    }

    /// Non-mutating redundancy elimination returning a new batch and count.
    pub fn deduplicate(&self) -> (Self, usize) {
        let mut cloned = self.clone();
        let removed = cloned.eliminate_redundancy();
        (cloned, removed)
    }

    /// Dependency Cone Slicing: partitions assertions into independent subsets
    /// based on disjoint `DependencyKey` sets using disjoint-set union.
    pub fn partition_dependency_cones(&self) -> Vec<SpeculativeConstraintBatch> {
        if self.assertions.is_empty() {
            return Vec::new();
        }
        let n = self.assertions.len();
        if n == 1 {
            return vec![self.clone()];
        }

        let mut parent: Vec<usize> = (0..n).collect();

        fn find(parent: &mut [usize], mut i: usize) -> usize {
            while parent[i] != i {
                parent[i] = parent[parent[i]];
                i = parent[i];
            }
            i
        }

        fn union(parent: &mut [usize], i: usize, j: usize) {
            let root_i = find(parent, i);
            let root_j = find(parent, j);
            if root_i != root_j {
                if root_i < root_j {
                    parent[root_j] = root_i;
                } else {
                    parent[root_i] = root_j;
                }
            }
        }

        let mut key_to_assertion: HashMap<DependencyKey, usize> = HashMap::new();

        for (idx, assertion) in self.assertions.iter().enumerate() {
            for key in &assertion.dependency_cone {
                if let Some(&prev_idx) = key_to_assertion.get(key) {
                    union(&mut parent, prev_idx, idx);
                } else {
                    key_to_assertion.insert(*key, idx);
                }
            }
        }

        let mut groups: HashMap<usize, Vec<SpeculativeAssertion>> = HashMap::new();
        for (idx, assertion) in self.assertions.iter().enumerate() {
            let root = find(&mut parent, idx);
            groups.entry(root).or_default().push(assertion.clone());
        }

        let mut sorted_roots: Vec<usize> = groups.keys().copied().collect();
        sorted_roots.sort_unstable();

        sorted_roots
            .into_iter()
            .map(|root| {
                let assertions = groups.remove(&root).unwrap_or_default();
                SpeculativeConstraintBatch { assertions }
            })
            .collect()
    }

    /// Builds a [`BatchSolvePlan`] by deduplicating redundancies and slicing
    /// into independent partitions.
    pub fn plan(&self) -> BatchSolvePlan {
        let total_batched = self.assertions.len();
        let mut deduplicated_batch = self.clone();
        let deduplicated_queries = deduplicated_batch.eliminate_redundancy();
        let partition_batches = deduplicated_batch.partition_dependency_cones();

        let partitions = partition_batches
            .into_iter()
            .enumerate()
            .map(|(id, b)| BatchPartition::new(id, b.into_assertions()))
            .collect();

        BatchSolvePlan::new(partitions, total_batched, deduplicated_queries)
    }
}

/// An independent partition of speculative queries within a [`BatchSolvePlan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchPartition {
    pub partition_id: usize,
    pub assertions: Vec<SpeculativeAssertion>,
    pub dependency_keys: BTreeSet<DependencyKey>,
}

impl BatchPartition {
    pub fn new(partition_id: usize, assertions: Vec<SpeculativeAssertion>) -> Self {
        let mut dependency_keys = BTreeSet::new();
        for assertion in &assertions {
            dependency_keys.extend(assertion.dependency_cone.iter().copied());
        }
        Self {
            partition_id,
            assertions,
            dependency_keys,
        }
    }

    pub fn len(&self) -> usize {
        self.assertions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.assertions.is_empty()
    }

    pub fn queries(&self) -> Vec<&SolverQuery> {
        self.assertions.iter().map(|a| &a.query).collect()
    }

    /// Verifies that this partition is disjoint in dependency keys from another.
    pub fn is_disjoint_from(&self, other: &Self) -> bool {
        self.dependency_keys.is_disjoint(&other.dependency_keys)
    }
}

/// Plan grouping independent sub-queries for solver evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSolvePlan {
    pub partitions: Vec<BatchPartition>,
    pub total_batched: usize,
    pub deduplicated_queries: usize,
}

impl BatchSolvePlan {
    pub fn new(
        partitions: Vec<BatchPartition>,
        total_batched: usize,
        deduplicated_queries: usize,
    ) -> Self {
        Self {
            partitions,
            total_batched,
            deduplicated_queries,
        }
    }

    pub fn partition_count(&self) -> usize {
        self.partitions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.partitions.is_empty()
    }

    pub fn partitions(&self) -> &[BatchPartition] {
        &self.partitions
    }

    pub fn total_unique_queries(&self) -> usize {
        self.partitions.iter().map(|p| p.assertions.len()).sum()
    }

    /// Evaluates all queries in the plan using the given backend and returns
    /// results mapped to each assertion.
    pub fn execute(&self, solver: &mut dyn SolverBackend) -> Vec<(SpeculativeAssertion, SolverResult)> {
        let mut results = Vec::new();
        for partition in &self.partitions {
            for assertion in &partition.assertions {
                let res = solver.solve(&assertion.query);
                results.push((assertion.clone(), res));
            }
        }
        results
    }
}

/// Configuration for [`SpeculativeBatchCoordinator`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BatchCoordinatorConfig {
    pub max_batch_size: usize,
    pub timeout: Duration,
    pub enable_background_worker: bool,
}

impl Default for BatchCoordinatorConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 16,
            timeout: Duration::from_millis(50),
            enable_background_worker: true,
        }
    }
}

impl BatchCoordinatorConfig {
    pub fn new(max_batch_size: usize, timeout: Duration) -> Self {
        Self {
            max_batch_size,
            timeout,
            enable_background_worker: true,
        }
    }
}

/// Metrics emitted by [`SpeculativeBatchCoordinator`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpeculativeBatchMetrics {
    pub total_batched: u64,
    pub independent_partitions: u64,
    pub deduplicated_queries: u64,
    pub amortized_solve_time_us: u64,
}

/// Handle allowing an individual branch to wait for its solver result.
#[derive(Debug)]
pub struct BranchWaiter {
    pub state_id: StateId,
    pub branch_id: BranchId,
    pub receiver: mpsc::Receiver<SolverResult>,
}

impl BranchWaiter {
    /// Blocks until the solver result is available.
    pub fn wait(self) -> Result<SolverResult, mpsc::RecvError> {
        self.receiver.recv()
    }

    /// Blocks until the solver result is available or `timeout` elapses.
    pub fn wait_timeout(self, timeout: Duration) -> Result<SolverResult, mpsc::RecvTimeoutError> {
        self.receiver.recv_timeout(timeout)
    }

    /// Non-blocking check for the solver result.
    pub fn try_wait(&self) -> Result<SolverResult, mpsc::TryRecvError> {
        self.receiver.try_recv()
    }
}

struct QueuedItem {
    assertion: SpeculativeAssertion,
    responder: mpsc::Sender<SolverResult>,
    queued_at: Instant,
}

struct CoordinatorState {
    queue: Vec<QueuedItem>,
    metrics: SpeculativeBatchMetrics,
    total_solve_time: Duration,
    total_solved_queries: u64,
}

/// Manages a queue of speculative branch queries, triggers batch evaluation
/// when `max_batch_size` or timeout elapses, dispatches to the solver portfolio,
/// and distributes results back to individual branch waiters.
pub struct SpeculativeBatchCoordinator {
    solver: Arc<Mutex<Box<dyn SolverBackend>>>,
    config: BatchCoordinatorConfig,
    state: Arc<Mutex<CoordinatorState>>,
    cond: Arc<Condvar>,
    shutdown: Arc<AtomicBool>,
    worker_handle: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl SpeculativeBatchCoordinator {
    /// Creates a new coordinator backed by `solver` and `config`.
    pub fn new(solver: Box<dyn SolverBackend>, config: BatchCoordinatorConfig) -> Self {
        let state = Arc::new(Mutex::new(CoordinatorState {
            queue: Vec::new(),
            metrics: SpeculativeBatchMetrics::default(),
            total_solve_time: Duration::ZERO,
            total_solved_queries: 0,
        }));
        let cond = Arc::new(Condvar::new());
        let shutdown = Arc::new(AtomicBool::new(false));
        let solver = Arc::new(Mutex::new(solver));

        let worker_handle = if config.enable_background_worker {
            let state_clone = Arc::clone(&state);
            let cond_clone = Arc::clone(&cond);
            let shutdown_clone = Arc::clone(&shutdown);
            let solver_clone = Arc::clone(&solver);
            let timeout = config.timeout;

            let handle = std::thread::spawn(move || {
                while !shutdown_clone.load(Ordering::Acquire) {
                    let mut guard = match state_clone.lock() {
                        Ok(g) => g,
                        Err(poisoned) => poisoned.into_inner(),
                    };

                    if guard.queue.is_empty() {
                        let wait_step = Duration::from_millis(50).min(timeout);
                        guard = match cond_clone.wait_timeout(guard, wait_step) {
                            Ok((g, _)) => g,
                            Err(poisoned) => poisoned.into_inner().0,
                        };
                    } else {
                        let oldest_age = guard
                            .queue
                            .first()
                            .map(|item| item.queued_at.elapsed())
                            .unwrap_or(Duration::ZERO);

                        if oldest_age >= timeout {
                            let items = std::mem::take(&mut guard.queue);
                            drop(guard);
                            Self::evaluate_items(&solver_clone, &state_clone, items);
                            continue;
                        } else {
                            let remaining = timeout.saturating_sub(oldest_age);
                            guard = match cond_clone.wait_timeout(guard, remaining) {
                                Ok((g, _)) => g,
                                Err(poisoned) => poisoned.into_inner().0,
                            };
                        }
                    }

                    if !guard.queue.is_empty() {
                        let oldest_age = guard
                            .queue
                            .first()
                            .map(|item| item.queued_at.elapsed())
                            .unwrap_or(Duration::ZERO);
                        if oldest_age >= timeout {
                            let items = std::mem::take(&mut guard.queue);
                            drop(guard);
                            Self::evaluate_items(&solver_clone, &state_clone, items);
                        }
                    }
                }
            });
            Some(handle)
        } else {
            None
        };

        Self {
            solver,
            config,
            state,
            cond,
            shutdown,
            worker_handle: Mutex::new(worker_handle),
        }
    }

    /// Enqueues a speculative assertion and returns a waiter for its result.
    ///
    /// Triggers evaluation immediately if queue size reaches `max_batch_size`.
    pub fn submit(&self, assertion: SpeculativeAssertion) -> BranchWaiter {
        let (tx, rx) = mpsc::channel();
        let state_id = assertion.state_id;
        let branch_id = assertion.branch_id;
        let waiter = BranchWaiter {
            state_id,
            branch_id,
            receiver: rx,
        };

        let should_trigger = {
            let mut guard = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            guard.queue.push(QueuedItem {
                assertion,
                responder: tx,
                queued_at: Instant::now(),
            });
            guard.queue.len() >= self.config.max_batch_size
        };

        if should_trigger {
            self.trigger_batch();
        } else {
            self.cond.notify_one();
        }

        waiter
    }

    /// Enqueues a speculative query tagged by `(StateId, BranchId, DependencyKey)`.
    pub fn submit_query(
        &self,
        state_id: StateId,
        branch_id: BranchId,
        dependency_key: DependencyKey,
        query: SolverQuery,
    ) -> BranchWaiter {
        self.submit(SpeculativeAssertion::new(
            state_id,
            branch_id,
            dependency_key,
            query,
        ))
    }

    /// Triggers immediate evaluation of all currently queued items.
    pub fn trigger_batch(&self) {
        let items = {
            let mut guard = match self.state.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            if guard.queue.is_empty() {
                return;
            }
            std::mem::take(&mut guard.queue)
        };
        Self::evaluate_items(&self.solver, &self.state, items);
    }

    /// Flushes all queued queries immediately.
    pub fn flush(&self) {
        self.trigger_batch();
    }

    /// Current number of items waiting in queue.
    pub fn queue_len(&self) -> usize {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.queue.len()
    }

    /// Returns a snapshot of the coordinator's current metrics.
    pub fn metrics(&self) -> SpeculativeBatchMetrics {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.metrics
    }

    pub fn total_batched(&self) -> u64 {
        self.metrics().total_batched
    }

    pub fn independent_partitions(&self) -> u64 {
        self.metrics().independent_partitions
    }

    pub fn deduplicated_queries(&self) -> u64 {
        self.metrics().deduplicated_queries
    }

    pub fn amortized_solve_time_us(&self) -> u64 {
        self.metrics().amortized_solve_time_us
    }

    fn evaluate_items(
        solver_mutex: &Arc<Mutex<Box<dyn SolverBackend>>>,
        state_mutex: &Arc<Mutex<CoordinatorState>>,
        items: Vec<QueuedItem>,
    ) {
        if items.is_empty() {
            return;
        }

        let mut batch = SpeculativeConstraintBatch::new();
        let mut responders_by_tag: HashMap<
            (StateId, BranchId, DependencyKey),
            Vec<mpsc::Sender<SolverResult>>,
        > = HashMap::new();

        for item in items {
            let tag = item.assertion.tag();
            responders_by_tag.entry(tag).or_default().push(item.responder);
            batch.add(item.assertion);
        }

        let plan = batch.plan();

        let start = Instant::now();
        let mut solver = match solver_mutex.lock() {
            Ok(s) => s,
            Err(p) => p.into_inner(),
        };

        let mut results_by_tag: HashMap<(StateId, BranchId, DependencyKey), SolverResult> =
            HashMap::new();

        for partition in &plan.partitions {
            for assertion in &partition.assertions {
                let res = solver.solve(&assertion.query);
                for &tag in &assertion.associated_tags {
                    results_by_tag.insert(tag, res.clone());
                }
            }
        }
        let elapsed = start.elapsed();
        drop(solver);

        for (tag, senders) in responders_by_tag {
            if let Some(result) = results_by_tag.get(&tag) {
                for sender in senders {
                    let _ = sender.send(result.clone());
                }
            }
        }

        let mut state_guard = match state_mutex.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state_guard.metrics.total_batched += plan.total_batched as u64;
        state_guard.metrics.independent_partitions += plan.partitions.len() as u64;
        state_guard.metrics.deduplicated_queries += plan.deduplicated_queries as u64;
        state_guard.total_solve_time += elapsed;
        state_guard.total_solved_queries += plan.total_batched as u64;
        state_guard.metrics.amortized_solve_time_us =
            (state_guard.total_solve_time.as_micros() as u64)
                .checked_div(state_guard.total_solved_queries)
                .unwrap_or(0);
    }
}

impl Drop for SpeculativeBatchCoordinator {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        self.cond.notify_all();
        if let Ok(mut handle) = self.worker_handle.lock()
            && let Some(h) = handle.take()
        {
            let _ = h.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CanonicalConstraint, MockSolverBackend, SolverOutcomeKind};
    use angryier_types::{
        ConstraintCanonicalizationVersion, ConstraintId, ExprId, SolverQueryId, TargetProfileId,
    };

    fn key(byte: u8) -> DependencyKey {
        let mut arr = [0u8; 32];
        arr[0] = byte;
        DependencyKey(arr)
    }

    fn make_test_query(id: u64, key_byte: u8) -> Result<SolverQuery, Box<dyn std::error::Error>> {
        let q = SolverQuery::canonical(
            SolverQueryId(id),
            &[],
            ExprId(id as u32),
            key(key_byte),
            TargetProfileId(0),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )?;
        Ok(q)
    }

    fn make_test_query_with_constraints(
        id: u64,
        pred_byte: u8,
        constraint_bytes: &[u8],
    ) -> Result<SolverQuery, Box<dyn std::error::Error>> {
        let constraints: Vec<CanonicalConstraint> = constraint_bytes
            .iter()
            .enumerate()
            .map(|(idx, &b)| CanonicalConstraint {
                id: ConstraintId(idx as u64 + 1),
                key: key(b),
                expr: ExprId((idx + 1) as u32),
            })
            .collect();

        let q = SolverQuery::canonical(
            SolverQueryId(id),
            &constraints,
            ExprId(id as u32),
            key(pred_byte),
            TargetProfileId(0),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )?;
        Ok(q)
    }

    #[test]
    fn test_disjoint_dependency_cone_partitioning() -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = SpeculativeConstraintBatch::new();

        // Assertion 1: cone touches {key(10), key(20)}
        let q1 = make_test_query_with_constraints(1, 10, &[20])?;
        batch.add_assertion(StateId(1), BranchId(0), key(10), q1);

        // Assertion 2: cone touches {key(20), key(30)} - overlaps with Assertion 1 on key(20)!
        let q2 = make_test_query_with_constraints(2, 20, &[30])?;
        batch.add_assertion(StateId(1), BranchId(1), key(20), q2);

        // Assertion 3: cone touches {key(40), key(50)} - completely disjoint from {key(10), key(20), key(30)}
        let q3 = make_test_query_with_constraints(3, 40, &[50])?;
        batch.add_assertion(StateId(2), BranchId(0), key(40), q3);

        // Assertion 4: cone touches {key(60)} - disjoint from all others
        let q4 = make_test_query(4, 60)?;
        batch.add_assertion(StateId(3), BranchId(0), key(60), q4);

        let partitions = batch.partition_dependency_cones();
        assert_eq!(partitions.len(), 3, "should slice into 3 independent partitions");

        // Partition 0 contains assertions 1 and 2
        assert_eq!(partitions[0].len(), 2);
        // Partition 1 contains assertion 3
        assert_eq!(partitions[1].len(), 1);
        // Partition 2 contains assertion 4
        assert_eq!(partitions[2].len(), 1);

        // Verify pairwise disjointness of dependency keys
        let plan = batch.plan();
        assert_eq!(plan.partition_count(), 3);
        assert!(plan.partitions[0].is_disjoint_from(&plan.partitions[1]));
        assert!(plan.partitions[0].is_disjoint_from(&plan.partitions[2]));
        assert!(plan.partitions[1].is_disjoint_from(&plan.partitions[2]));
        Ok(())
    }

    #[test]
    fn test_duplicate_deduplication() -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = SpeculativeConstraintBatch::new();

        let q1 = make_test_query(1, 10)?;
        let q2 = make_test_query(2, 20)?;

        // Add assertion on Path A: State 1, Branch 0
        batch.add_assertion(StateId(1), BranchId(0), key(10), q1.clone());

        // Add identical assertion on Path B: State 2, Branch 1 (concurrent speculative path!)
        batch.add_assertion(StateId(2), BranchId(1), key(10), q1.clone());

        // Add third identical assertion on Path C: State 3, Branch 0
        batch.add_assertion(StateId(3), BranchId(0), key(10), q1);

        // Add distinct assertion
        batch.add_assertion(StateId(4), BranchId(0), key(20), q2);

        assert_eq!(batch.len(), 4);

        let plan = batch.plan();
        assert_eq!(plan.total_batched, 4);
        assert_eq!(plan.deduplicated_queries, 2, "2 identical assertions should be deduplicated");
        assert_eq!(plan.total_unique_queries(), 2, "only 2 unique queries remain");

        // Check that the merged assertion retained all 3 associated tags
        let first_partition_assertions = &plan.partitions[0].assertions;
        let deduplicated_assertion = first_partition_assertions
            .iter()
            .find(|a| a.dependency_key == key(10))
            .ok_or("assertion present")?;
        assert_eq!(deduplicated_assertion.associated_tags.len(), 3);
        assert!(deduplicated_assertion.associated_tags.contains(&(StateId(1), BranchId(0), key(10))));
        assert!(deduplicated_assertion.associated_tags.contains(&(StateId(2), BranchId(1), key(10))));
        assert!(deduplicated_assertion.associated_tags.contains(&(StateId(3), BranchId(0), key(10))));
        Ok(())
    }

    #[test]
    fn test_end_to_end_batch_coordination_by_size() -> Result<(), Box<dyn std::error::Error>> {
        let mock_backend = MockSolverBackend::new("mock", SolverOutcomeKind::Sat);
        let config = BatchCoordinatorConfig {
            max_batch_size: 3,
            timeout: Duration::from_millis(500),
            enable_background_worker: false, // test manual/size triggering deterministically
        };
        let coordinator = SpeculativeBatchCoordinator::new(Box::new(mock_backend), config);

        let q1 = make_test_query(1, 1)?;
        let q2 = make_test_query(2, 2)?;
        let q3 = make_test_query(3, 3)?;

        let w1 = coordinator.submit_query(StateId(1), BranchId(0), key(1), q1);
        let w2 = coordinator.submit_query(StateId(2), BranchId(0), key(2), q2);
        assert_eq!(coordinator.queue_len(), 2);

        // Third submission hits max_batch_size (3) and triggers batch evaluation!
        let w3 = coordinator.submit_query(StateId(3), BranchId(0), key(3), q3);
        assert_eq!(coordinator.queue_len(), 0, "queue should be drained after trigger");

        let res1 = w1.wait()?;
        let res2 = w2.wait()?;
        let res3 = w3.wait()?;

        assert_eq!(res1.outcome, SolverOutcomeKind::Sat);
        assert_eq!(res2.outcome, SolverOutcomeKind::Sat);
        assert_eq!(res3.outcome, SolverOutcomeKind::Sat);

        let metrics = coordinator.metrics();
        assert_eq!(metrics.total_batched, 3);
        assert_eq!(metrics.independent_partitions, 3);
        assert_eq!(metrics.deduplicated_queries, 0);
        Ok(())
    }

    #[test]
    fn test_end_to_end_batch_coordination_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let mock_backend = MockSolverBackend::new("mock", SolverOutcomeKind::Sat);
        let config = BatchCoordinatorConfig {
            max_batch_size: 10, // will not reach max size
            timeout: Duration::from_millis(30),
            enable_background_worker: true, // background worker triggers on timeout
        };
        let coordinator = SpeculativeBatchCoordinator::new(Box::new(mock_backend), config);

        let q1 = make_test_query(1, 1)?;
        let w1 = coordinator.submit_query(StateId(1), BranchId(0), key(1), q1);

        // Wait up to 1 second for timeout trigger to fire
        let res = w1.wait_timeout(Duration::from_secs(1))?;
        assert_eq!(res.outcome, SolverOutcomeKind::Sat);
        assert_eq!(coordinator.total_batched(), 1);
        Ok(())
    }

    #[test]
    fn test_end_to_end_coordination_with_deduplication() -> Result<(), Box<dyn std::error::Error>> {
        let mock_backend = MockSolverBackend::new("mock", SolverOutcomeKind::Sat);
        let config = BatchCoordinatorConfig {
            max_batch_size: 2,
            timeout: Duration::from_secs(1),
            enable_background_worker: false,
        };
        let coordinator = SpeculativeBatchCoordinator::new(Box::new(mock_backend), config);

        let q1 = make_test_query(1, 42)?;

        // Path 1 and Path 2 submit identical queries
        let w1 = coordinator.submit_query(StateId(1), BranchId(0), key(42), q1.clone());
        let w2 = coordinator.submit_query(StateId(2), BranchId(1), key(42), q1);

        // 2 items submitted reaches max_batch_size = 2
        let res1 = w1.wait()?;
        let res2 = w2.wait()?;

        assert_eq!(res1.outcome, SolverOutcomeKind::Sat);
        assert_eq!(res2.outcome, SolverOutcomeKind::Sat);

        let metrics = coordinator.metrics();
        assert_eq!(metrics.total_batched, 2);
        assert_eq!(metrics.deduplicated_queries, 1);
        assert_eq!(metrics.independent_partitions, 1);
        Ok(())
    }
}
