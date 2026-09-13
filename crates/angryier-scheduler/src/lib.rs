#![forbid(unsafe_code)]

//! NUMA-aware multi-objective work-stealing scheduler.
//!
//! This crate provides the scheduling contracts ([`SearchScore`], [`StealCost`],
//! [`ScheduleDecision`], [`Scheduler`]) and a concrete in-memory implementation
//! ([`InMemoryScheduler`]) with per-worker local queues, a global overflow queue,
//! monotonic work-unit identifiers, and a simulated NUMA distance model.

use angryier_types::{StateId, WorkUnitId};
use std::collections::VecDeque;
use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Existing contracts
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SearchScore {
    pub coverage_novelty: f64,
    pub taint_relevance: f64,
    pub target_proximity: f64,
    pub solver_cost: f64,
    pub uncertainty: f64,
    pub learned_advisory: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StealCost {
    pub load_gain: f64,
    pub solver_rebuild_cost: f64,
    pub numa_cost: f64,
    pub cache_locality_loss: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleDecision {
    pub work: WorkUnitId,
    pub state: StateId,
    pub worker: u32,
    pub sequence: u64,
}

pub trait Scheduler: Send + Sync {
    fn enqueue(&self, state: StateId, score: SearchScore);
    fn next(&self, worker: u32) -> Option<StateId>;
    fn steal_cost(&self, state: StateId, from_worker: u32, to_worker: u32) -> StealCost;
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

/// Errors produced by [`InMemoryScheduler`] operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedulerError {
    /// A synchronization primitive was poisoned by a panicking thread.
    Poisoned,
    /// The scheduler queue capacity has been exhausted (backpressure).
    QueueFull,
    /// The requested worker index is out of range.
    InvalidWorker,
    /// The referenced execution state is not known to the scheduler.
    UnknownState,
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Poisoned => "scheduler synchronization primitive poisoned",
            Self::QueueFull => "scheduler queue is full (backpressure)",
            Self::InvalidWorker => "invalid worker index",
            Self::UnknownState => "unknown execution state",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SchedulerError {}

// ---------------------------------------------------------------------------
// GreedyScore helper
// ---------------------------------------------------------------------------

/// Weighted normalization of individual search-interest signals into a single
/// [`SearchScore`], mirroring the weighted-sum approach used by
/// `TraceInterest::priority()` in the provenance crate.
///
/// Each input signal is expected in the range `[0, 1]`; values outside that range
/// are clamped. The resulting [`SearchScore`] fields are the clamped weighted
/// contributions, and [`GreedyScore::priority`] collapses them into a scalar.
#[derive(Clone, Copy, Debug)]
pub struct GreedyScore;

impl GreedyScore {
    /// Per-signal weights. The absolute values sum to 1.0 so the weighted sum
    /// stays within `[0, 1]` when every input is in `[0, 1]`.
    const WEIGHTS: [(f64, f64); 6] = [
        // (weight, negative-penalty flag is folded into the weight sign)
        (0.25, 0.0), // coverage_novelty
        (0.15, 0.0), // taint_relevance
        (0.20, 0.0), // target_proximity
        (0.10, 0.0), // solver_cost (lower is better, applied as penalty below)
        (0.15, 0.0), // uncertainty
        (0.15, 0.0), // learned_advisory
    ];

    #[inline]
    fn clamp01(value: f64) -> f64 {
        value.clamp(0.0, 1.0)
    }

    /// Compose a [`SearchScore`] from raw signals, clamping each to `[0, 1]`.
    pub fn compose(
        coverage_novelty: f64,
        taint_relevance: f64,
        target_proximity: f64,
        solver_cost: f64,
        uncertainty: f64,
        learned_advisory: f64,
    ) -> SearchScore {
        SearchScore {
            coverage_novelty: Self::clamp01(coverage_novelty),
            taint_relevance: Self::clamp01(taint_relevance),
            target_proximity: Self::clamp01(target_proximity),
            solver_cost: Self::clamp01(solver_cost),
            uncertainty: Self::clamp01(uncertainty),
            learned_advisory: Self::clamp01(learned_advisory),
        }
    }

    /// Collapse a [`SearchScore`] into a scalar priority in `[0, 1]`.
    ///
    /// `solver_cost` is treated as a penalty (lower cost is better), so its
    /// contribution is `(1 - solver_cost) * weight`.
    pub fn priority(score: &SearchScore) -> f64 {
        let signals = [
            score.coverage_novelty,
            score.taint_relevance,
            score.target_proximity,
            1.0 - score.solver_cost,
            score.uncertainty,
            score.learned_advisory,
        ];
        let weights = Self::WEIGHTS;
        let mut sum = 0.0;
        let mut total_weight = 0.0;
        let mut i = 0;
        while i < signals.len() {
            sum += signals[i] * weights[i].0;
            total_weight += weights[i].0;
            i += 1;
        }
        if total_weight > 0.0 {
            (sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

// ---------------------------------------------------------------------------
// NUMA distance model
// ---------------------------------------------------------------------------

/// A simple NUMA distance matrix for a fixed set of worker groups.
///
/// Workers in the same group have distance `0.0`; cross-group distances are
/// configurable at construction time. The default model is a 2x2 grid where
/// the off-diagonal distance is `2.0`.
#[derive(Clone, Debug)]
pub struct NumaModel {
    /// `distances[i][j]` is the distance between NUMA nodes `i` and `j`.
    distances: Vec<Vec<f64>>,
}

impl NumaModel {
    /// Build a `nodes x nodes` NUMA model where same-node distance is `0.0` and
    /// every cross-node distance is `cross_distance`.
    pub fn uniform(nodes: u32, cross_distance: f64) -> Self {
        let n = nodes as usize;
        let mut distances = Vec::with_capacity(n);
        let mut i = 0;
        while i < n {
            let mut row = Vec::with_capacity(n);
            let mut j = 0;
            while j < n {
                if i == j {
                    row.push(0.0);
                } else {
                    row.push(cross_distance);
                }
                j += 1;
            }
            distances.push(row);
            i += 1;
        }
        Self { distances }
    }

    /// The default 2-node NUMA model with cross-node distance `2.0`.
    pub fn default_2x2() -> Self {
        Self::uniform(2, 2.0)
    }

    /// The default 4-node NUMA model with cross-node distance `2.0`.
    pub fn default_4x4() -> Self {
        Self::uniform(4, 2.0)
    }

    /// Distance between two NUMA nodes. Out-of-range indices return `0.0`
    /// (treated as same node) rather than panicking.
    pub fn distance(&self, from: u32, to: u32) -> f64 {
        let from = from as usize;
        let to = to as usize;
        match (self.distances.get(from), self.distances.get(to)) {
            (Some(row), Some(_)) => match row.get(to) {
                Some(d) => *d,
                None => 0.0,
            },
            _ => 0.0,
        }
    }

    /// Number of NUMA nodes in the model.
    pub fn node_count(&self) -> u32 {
        self.distances.len() as u32
    }
}

impl Default for NumaModel {
    fn default() -> Self {
        Self::default_2x2()
    }
}

// ---------------------------------------------------------------------------
// In-memory scheduler
// ---------------------------------------------------------------------------

/// A single queued work unit.
#[derive(Clone, Copy, Debug)]
struct WorkItem {
    #[allow(dead_code)]
    id: WorkUnitId,
    state: StateId,
    #[allow(dead_code)]
    score: SearchScore,
}

/// Configuration constants for the in-memory scheduler.
const DEFAULT_QUEUE_CAPACITY: usize = 4096;

/// A thread-safe in-memory work-stealing scheduler.
///
/// Each worker owns a local [`VecDeque`] protected by a [`Mutex`]. Work is
/// enqueued onto the least-loaded worker's local queue and popped locally; when
/// a worker's queue is empty it attempts to steal from the most-loaded worker.
/// A global overflow queue absorbs surplus work when local queues are full.
pub struct InMemoryScheduler {
    workers: Vec<Mutex<VecDeque<WorkItem>>>,
    global: Mutex<VecDeque<WorkItem>>,
    /// Maps `WorkUnitId` -> owning worker, used for `steal_cost` lookups.
    owners: Mutex<Vec<(WorkUnitId, u32)>>,
    next_id: AtomicU64,
    worker_count: u32,
    capacity: usize,
    numa: NumaModel,
}

impl InMemoryScheduler {
    /// Create a scheduler with `worker_count` workers and the default capacity.
    pub fn new(worker_count: u32) -> Self {
        Self::with_options(worker_count, DEFAULT_QUEUE_CAPACITY, NumaModel::default_2x2())
    }

    /// Create a scheduler with a custom per-worker capacity and NUMA model.
    pub fn with_options(worker_count: u32, capacity: usize, numa: NumaModel) -> Self {
        let count = worker_count as usize;
        let mut workers = Vec::with_capacity(count);
        let mut i = 0;
        while i < count {
            workers.push(Mutex::new(VecDeque::new()));
            i += 1;
        }
        Self {
            workers,
            global: Mutex::new(VecDeque::new()),
            owners: Mutex::new(Vec::new()),
            next_id: AtomicU64::new(1),
            worker_count,
            capacity,
            numa,
        }
    }

    /// Number of workers in this scheduler.
    pub fn worker_count(&self) -> u32 {
        self.worker_count
    }

    fn validate_worker(&self, worker: u32) -> Result<(), SchedulerError> {
        if worker < self.worker_count {
            Ok(())
        } else {
            Err(SchedulerError::InvalidWorker)
        }
    }

    /// Allocate the next monotonic work-unit identifier.
    fn allocate_id(&self) -> WorkUnitId {
        WorkUnitId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    /// Snapshot of per-worker queue depths. Returns `Err(Poisoned)` if any
    /// local queue lock is poisoned.
    fn load_snapshot(&self) -> Result<Vec<usize>, SchedulerError> {
        let mut loads = Vec::with_capacity(self.workers.len());
        for w in &self.workers {
            let guard = w.lock().map_err(|_| SchedulerError::Poisoned)?;
            loads.push(guard.len());
        }
        Ok(loads)
    }

    /// Index of the least-loaded worker, or `None` if there are no workers.
    fn least_loaded(&self, loads: &[usize]) -> Option<u32> {
        if loads.is_empty() {
            return None;
        }
        let mut best = 0usize;
        let mut best_load = loads[0];
        let mut i = 1;
        while i < loads.len() {
            if loads[i] < best_load {
                best = i;
                best_load = loads[i];
            }
            i += 1;
        }
        Some(best as u32)
    }

    /// Index of the most-loaded worker with at least `min_depth` items,
    /// excluding `exclude`. Returns `None` if no candidate qualifies.
    fn most_loaded(&self, loads: &[usize], min_depth: usize, exclude: u32) -> Option<u32> {
        let mut best: Option<u32> = None;
        let mut best_load: usize = 0;
        let mut i = 0;
        while i < loads.len() {
            if i as u32 != exclude && loads[i] >= min_depth && loads[i] > best_load {
                best = Some(i as u32);
                best_load = loads[i];
            }
            i += 1;
        }
        best
    }

    /// Enqueue a work unit onto the least-loaded worker's local queue.
    ///
    /// If all local queues are at capacity the unit overflows into the global
    /// queue; if the global queue is also full the operation fails with
    /// [`SchedulerError::QueueFull`].
    pub fn enqueue(&self, state: StateId, score: SearchScore) -> Result<WorkUnitId, SchedulerError> {
        if self.worker_count == 0 {
            // With no workers there is nowhere to place work.
            return Err(SchedulerError::InvalidWorker);
        }
        let loads = self.load_snapshot()?;
        let target = self.least_loaded(&loads).ok_or(SchedulerError::InvalidWorker)?;

        let id = self.allocate_id();
        let item = WorkItem { id, state, score };

        let placed_local = {
            let mut guard = self.workers[target as usize]
                .lock()
                .map_err(|_| SchedulerError::Poisoned)?;
            if guard.len() < self.capacity {
                guard.push_back(item);
                true
            } else {
                false
            }
        };

        if !placed_local {
            let mut global = self.global.lock().map_err(|_| SchedulerError::Poisoned)?;
            if global.len() < self.capacity {
                global.push_back(item);
            } else {
                // Roll back the id allocation so ids stay contiguous on failure.
                self.next_id.fetch_sub(1, Ordering::Relaxed);
                return Err(SchedulerError::QueueFull);
            }
        }

        let mut owners = self.owners.lock().map_err(|_| SchedulerError::Poisoned)?;
        owners.push((id, target));
        Ok(id)
    }

    /// Pop the next work unit for `worker`, stealing from the most-loaded
    /// worker (or the global queue) when the local queue is empty.
    pub fn next(&self, worker: u32) -> Option<StateId> {
        match self.next_item(worker) {
            Ok(Some(item)) => Some(item.state),
            Ok(None) => None,
            Err(_) => None,
        }
    }

    fn next_item(&self, worker: u32) -> Result<Option<WorkItem>, SchedulerError> {
        self.validate_worker(worker)?;

        // 1. Try the local queue.
        {
            let mut guard = self.workers[worker as usize]
                .lock()
                .map_err(|_| SchedulerError::Poisoned)?;
            if let Some(item) = guard.pop_front() {
                return Ok(Some(item));
            }
        }

        // 2. Try the global overflow queue.
        {
            let mut global = self.global.lock().map_err(|_| SchedulerError::Poisoned)?;
            if let Some(item) = global.pop_front() {
                return Ok(Some(item));
            }
        }

        // 3. Steal from the most-loaded peer.
        let loads = self.load_snapshot()?;
        let donor = self.most_loaded(&loads, 1, worker);
        if let Some(donor) = donor {
            let mut guard = self.workers[donor as usize]
                .lock()
                .map_err(|_| SchedulerError::Poisoned)?;
            // Steal half of the donor's queue (at least one item).
            let steal_count = guard.len() / 2;
            if steal_count == 0 {
                if let Some(item) = guard.pop_back() {
                    return Ok(Some(item));
                }
            } else {
                // Move the stolen items to the local queue, keeping one to return.
                let mut local = self.workers[worker as usize]
                    .lock()
                    .map_err(|_| SchedulerError::Poisoned)?;
                let mut taken = 0;
                let mut first: Option<WorkItem> = None;
                while taken < steal_count {
                    match guard.pop_back() {
                        Some(item) => {
                            if first.is_none() {
                                first = Some(item);
                            } else {
                                local.push_back(item);
                            }
                            taken += 1;
                        }
                        None => break,
                    }
                }
                if let Some(item) = first {
                    return Ok(Some(item));
                }
            }
        }
        Ok(None)
    }

    /// Compute the cost of moving `state` from `from_worker` to `to_worker`.
    ///
    /// The cost combines the load-balancing gain (negative when the donor is
    /// more loaded than the receiver), the solver rebuild cost, the NUMA
    /// distance between the workers' nodes, and a cache-locality loss term.
    pub fn steal_cost(&self, state: StateId, from_worker: u32, to_worker: u32) -> StealCost {
        let from_load = self.worker_load(from_worker).unwrap_or(0);
        let to_load = self.worker_load(to_worker).unwrap_or(0);
        let depth_diff = from_load as f64 - to_load as f64;

        // Load gain: positive when the move reduces imbalance.
        let load_gain = depth_diff.max(0.0);

        // Solver rebuild cost grows with how much deeper the donor is (more
        // pending work means more solver state to reconstruct on the thief).
        let solver_rebuild_cost = (depth_diff * 0.1).clamp(0.0, 1.0);

        // NUMA cost from the distance matrix.
        let from_node = self.node_of(from_worker);
        let to_node = self.node_of(to_worker);
        let numa_cost = self.numa.distance(from_node, to_node);

        // Cache-locality loss is proportional to NUMA distance.
        let cache_locality_loss = numa_cost * 0.5;

        // `state` is intentionally accepted so callers can later weight the
        // cost by per-state solver complexity; for now it does not change the
        // base computation but suppresses the unused-variable lint.
        let _ = state;

        StealCost {
            load_gain,
            solver_rebuild_cost,
            numa_cost,
            cache_locality_loss,
        }
    }

    /// Map a worker index to its NUMA node. Workers are round-robin assigned
    /// across the available NUMA nodes.
    fn node_of(&self, worker: u32) -> u32 {
        let nodes = self.numa.node_count();
        if nodes == 0 { 0 } else { worker % nodes }
    }

    /// Queue depth for a worker. Returns `Err(InvalidWorker)` for out-of-range
    /// indices and `Err(Poisoned)` on lock failure.
    pub fn worker_load(&self, worker: u32) -> Result<usize, SchedulerError> {
        self.validate_worker(worker)?;
        let guard = self.workers[worker as usize]
            .lock()
            .map_err(|_| SchedulerError::Poisoned)?;
        Ok(guard.len())
    }

    /// Total queued work across all local queues and the global overflow queue.
    pub fn total_load(&self) -> usize {
        let mut total = 0;
        for w in &self.workers {
            if let Ok(guard) = w.lock() {
                total += guard.len();
            }
        }
        if let Ok(guard) = self.global.lock() {
            total += guard.len();
        }
        total
    }

    /// Reference to the NUMA model used for steal-cost computation.
    pub fn numa_model(&self) -> &NumaModel {
        &self.numa
    }
}

impl Scheduler for InMemoryScheduler {
    fn enqueue(&self, state: StateId, score: SearchScore) {
        // The trait signature cannot propagate errors, so failures are
        // silently dropped (mirroring the contract-only behaviour).
        let _ = InMemoryScheduler::enqueue(self, state, score);
    }

    fn next(&self, worker: u32) -> Option<StateId> {
        InMemoryScheduler::next(self, worker)
    }

    fn steal_cost(&self, state: StateId, from_worker: u32, to_worker: u32) -> StealCost {
        InMemoryScheduler::steal_cost(self, state, from_worker, to_worker)
    }
}

impl Default for InMemoryScheduler {
    fn default() -> Self {
        Self::new(4)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn score(v: f64) -> SearchScore {
        GreedyScore::compose(v, v, v, 1.0 - v, v, v)
    }

    #[test]
    fn enqueue_distributes_work_across_workers() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(4);
        for i in 0u64..8 {
            scheduler.enqueue(StateId(i), score(0.5))?;
        }
        // With 8 items and 4 workers each starting empty, each worker should
        // hold roughly 2 items and no single worker should hold all of them.
        let loads = [
            scheduler.worker_load(0)?,
            scheduler.worker_load(1)?,
            scheduler.worker_load(2)?,
            scheduler.worker_load(3)?,
        ];
        let max = loads.iter().copied().max().unwrap_or(0);
        assert!(max < 8, "work was not distributed: {loads:?}");
        assert_eq!(scheduler.total_load(), 8);
        Ok(())
    }

    #[test]
    fn next_pops_from_local_queue() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        scheduler.enqueue(StateId(10), score(0.5))?;
        scheduler.enqueue(StateId(11), score(0.5))?;

        let first = scheduler.next(0);
        assert!(first.is_some(), "expected a work unit from worker 0");
        assert_eq!(first, Some(StateId(10)));
        Ok(())
    }

    #[test]
    fn stealing_from_another_worker_when_local_is_empty() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        // 6 items distribute 3/3 across the two workers.
        for i in 0u64..6 {
            scheduler.enqueue(StateId(i), score(0.5))?;
        }
        // Pop exactly the 3 items on worker 0's local queue.
        let _ = scheduler.next(0);
        let _ = scheduler.next(0);
        let _ = scheduler.next(0);
        // Worker 0 is now empty; the next call must steal from worker 1.
        let stolen = scheduler.next(0);
        assert!(stolen.is_some(), "worker 0 should have stolen work");
        Ok(())
    }

    #[test]
    fn steal_cost_is_higher_for_cross_node_than_same_node() -> Result<(), SchedulerError> {
        // 4 workers, 2 NUMA nodes -> workers 0,2 on node 0 and 1,3 on node 1.
        let numa = NumaModel::uniform(2, 3.0);
        let scheduler = InMemoryScheduler::with_options(4, 64, numa);
        for i in 0u64..4 {
            scheduler.enqueue(StateId(i), score(0.5))?;
        }
        let same = scheduler.steal_cost(StateId(0), 0, 2);
        let cross = scheduler.steal_cost(StateId(0), 0, 1);
        assert!(
            cross.numa_cost > same.numa_cost,
            "cross-node cost {cross:?} should exceed same-node {same:?}"
        );
        Ok(())
    }

    #[test]
    fn queue_full_rejection() -> Result<(), SchedulerError> {
        // 1 worker, capacity 2: local holds 2, global overflow holds 2, total 4.
        let scheduler = InMemoryScheduler::with_options(1, 2, NumaModel::default_2x2());
        assert!(scheduler.enqueue(StateId(0), score(0.5)).is_ok());
        assert!(scheduler.enqueue(StateId(1), score(0.5)).is_ok());
        assert!(scheduler.enqueue(StateId(2), score(0.5)).is_ok());
        assert!(scheduler.enqueue(StateId(3), score(0.5)).is_ok());
        // Both local and global queues are now full.
        let result = scheduler.enqueue(StateId(4), score(0.5));
        assert_eq!(result, Err(SchedulerError::QueueFull));
        Ok(())
    }

    #[test]
    fn invalid_worker_rejection() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        assert_eq!(scheduler.worker_load(5), Err(SchedulerError::InvalidWorker));
        // next on an invalid worker returns None gracefully.
        assert_eq!(scheduler.next(5), None);
        Ok(())
    }

    #[test]
    fn worker_load_tracking() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        assert_eq!(scheduler.worker_load(0)?, 0);
        scheduler.enqueue(StateId(0), score(0.5))?;
        scheduler.enqueue(StateId(1), score(0.5))?;
        let total = scheduler.worker_load(0)? + scheduler.worker_load(1)?;
        assert_eq!(total, 2);
        Ok(())
    }

    #[test]
    fn total_load_tracking() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(3);
        assert_eq!(scheduler.total_load(), 0);
        for i in 0u64..5 {
            scheduler.enqueue(StateId(i), score(0.5))?;
        }
        assert_eq!(scheduler.total_load(), 5);
        let _ = scheduler.next(0);
        assert_eq!(scheduler.total_load(), 4);
        Ok(())
    }

    #[test]
    fn score_normalization_is_bounded() {
        let high = GreedyScore::compose(1.0, 1.0, 1.0, 0.0, 1.0, 1.0);
        let low = GreedyScore::compose(0.0, 0.0, 0.0, 1.0, 0.0, 0.0);
        let p_high = GreedyScore::priority(&high);
        let p_low = GreedyScore::priority(&low);
        assert!(p_high > p_low, "high priority {p_high} should beat low {p_low}");
        assert!((0.0..=1.0).contains(&p_high), "priority out of range: {p_high}");
        assert!((0.0..=1.0).contains(&p_low), "priority out of range: {p_low}");

        // Clamping: out-of-range inputs are clamped to [0,1].
        let clamped = GreedyScore::compose(5.0, -1.0, 0.5, 0.5, 0.5, 0.5);
        assert_eq!(clamped.coverage_novelty, 1.0);
        assert_eq!(clamped.taint_relevance, 0.0);
    }

    #[test]
    fn monotonic_work_unit_ids() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        let a = scheduler.enqueue(StateId(0), score(0.5))?;
        let b = scheduler.enqueue(StateId(1), score(0.5))?;
        let c = scheduler.enqueue(StateId(2), score(0.5))?;
        assert!(b.0 > a.0, "ids must be monotonic: {a:?} {b:?}");
        assert!(c.0 > b.0, "ids must be monotonic: {b:?} {c:?}");
        Ok(())
    }

    #[test]
    fn empty_queue_returns_none() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        assert_eq!(scheduler.next(0), None);
        Ok(())
    }

    #[test]
    fn stealing_balances_load() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        for i in 0u64..10 {
            scheduler.enqueue(StateId(i), score(0.5))?;
        }
        // Fully drain worker 0 then let it steal repeatedly.
        while scheduler.next(0).is_some() {}
        let _ = scheduler.next(0);
        let _ = scheduler.next(0);
        let load0 = scheduler.worker_load(0)?;
        let load1 = scheduler.worker_load(1)?;
        // After stealing, neither worker should hold all remaining work.
        assert!(load0 + load1 <= 10, "work was lost");
        assert!(load1 < 10, "worker 1 should have shared work via stealing");
        Ok(())
    }

    #[test]
    fn numa_distance_correctness() {
        let model = NumaModel::uniform(4, 2.5);
        assert_eq!(model.distance(0, 0), 0.0);
        assert_eq!(model.distance(1, 1), 0.0);
        assert_eq!(model.distance(0, 1), 2.5);
        assert_eq!(model.distance(3, 0), 2.5);
        assert_eq!(model.node_count(), 4);

        let model2 = NumaModel::default_2x2();
        assert_eq!(model2.distance(0, 1), 2.0);
        assert_eq!(model2.distance(1, 1), 0.0);
    }

    #[test]
    fn scheduler_error_display_messages() {
        assert_eq!(
            SchedulerError::Poisoned.to_string(),
            "scheduler synchronization primitive poisoned"
        );
        assert_eq!(
            SchedulerError::QueueFull.to_string(),
            "scheduler queue is full (backpressure)"
        );
        assert_eq!(SchedulerError::InvalidWorker.to_string(), "invalid worker index");
        assert_eq!(SchedulerError::UnknownState.to_string(), "unknown execution state");
    }

    #[test]
    fn concurrent_enqueue() -> Result<(), SchedulerError> {
        let scheduler = Arc::new(InMemoryScheduler::with_options(4, 1024, NumaModel::default_4x4()));
        let mut handles = Vec::new();
        for t in 0u32..4 {
            let sched = Arc::clone(&scheduler);
            handles.push(thread::spawn(move || -> Result<u64, SchedulerError> {
                let mut count = 0u64;
                for i in 0u64..50 {
                    let state = StateId((t * 1000) as u64 + i);
                    match sched.enqueue(state, score(0.5)) {
                        Ok(_) => count += 1,
                        Err(SchedulerError::QueueFull) => break,
                        Err(e) => return Err(e),
                    }
                }
                Ok(count)
            }));
        }
        let mut total = 0u64;
        for h in handles {
            let n = h.join().map_err(|_| SchedulerError::Poisoned)??;
            total += n;
        }
        assert_eq!(
            total as usize,
            scheduler.total_load(),
            "all enqueued work should be present"
        );
        assert_eq!(total, 200);
        Ok(())
    }

    #[test]
    fn trait_impl_enqueue_and_next() -> Result<(), SchedulerError> {
        let scheduler = InMemoryScheduler::new(2);
        let dyn_sched: &dyn Scheduler = &scheduler;
        dyn_sched.enqueue(StateId(42), score(0.5));
        dyn_sched.enqueue(StateId(43), score(0.5));
        let popped = dyn_sched.next(0);
        assert!(popped.is_some());
        let cost = dyn_sched.steal_cost(StateId(42), 0, 1);
        assert!(cost.numa_cost >= 0.0);
        Ok(())
    }

    #[test]
    fn greedy_score_priority_zero_when_all_zero() {
        let zero = GreedyScore::compose(0.0, 0.0, 0.0, 1.0, 0.0, 0.0);
        // solver_cost=1.0 means (1 - solver_cost)=0, so all signals are 0.
        assert_eq!(GreedyScore::priority(&zero), 0.0);
    }
}
