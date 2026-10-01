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
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
            let mut stolen = Vec::new();
            {
                let mut guard = self.workers[donor as usize]
                    .lock()
                    .map_err(|_| SchedulerError::Poisoned)?;
                let steal_count = guard.len() / 2;
                if steal_count == 0 {
                    return Ok(guard.pop_back());
                }
                for _ in 0..steal_count {
                    if let Some(item) = guard.pop_back() {
                        stolen.push(item);
                    }
                }
            } // donor guard dropped here

            if let Some(first) = stolen.pop() {
                let mut local = self.workers[worker as usize]
                    .lock()
                    .map_err(|_| SchedulerError::Poisoned)?;
                local.extend(stolen);
                return Ok(Some(first));
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
// Memory-pressure monitor
// ---------------------------------------------------------------------------

/// Reads system memory availability.
///
/// On Linux, this parses `/proc/meminfo` to obtain `MemAvailable`. On all
/// other platforms it returns `None` (no-op sentinel), which causes callers
/// to skip pressure-throttling entirely.
pub struct MemoryPressureMonitor;

impl MemoryPressureMonitor {
    /// Returns the number of bytes currently available to user-space, or
    /// `None` if the information cannot be obtained (non-Linux, parse error,
    /// or I/O failure).
    pub fn available_bytes() -> Option<u64> {
        #[cfg(target_os = "linux")]
        {
            use std::fs;
            let content = fs::read_to_string("/proc/meminfo").ok()?;
            for line in content.lines() {
                // Lines look like: "MemAvailable:   12345678 kB"
                if let Some(rest) = line.strip_prefix("MemAvailable:") {
                    let rest = rest.trim();
                    // strip optional " kB" suffix
                    let kb_str = rest.strip_suffix(" kB").unwrap_or(rest).trim();
                    let kb: u64 = kb_str.parse().ok()?;
                    return kb.checked_mul(1024);
                }
            }
            None
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// Returns `true` when available memory is below `threshold_bytes`.
    /// On non-Linux platforms this always returns `false` (never throttle).
    pub fn is_under_pressure(threshold_bytes: u64) -> bool {
        match Self::available_bytes() {
            Some(avail) => avail < threshold_bytes,
            None => false,
        }
    }
}

/// Default memory-pressure threshold: 512 MiB.
pub const DEFAULT_PRESSURE_THRESHOLD_BYTES: u64 = 512 * 1024 * 1024;

// ---------------------------------------------------------------------------
// OS-thread worker pool with NUMA groups and memory-pressure stealing
// ---------------------------------------------------------------------------

/// Statistics reported when an [`OsWorkerPool`] run finishes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PoolStats {
    /// Work units ever enqueued (seed units plus children pushed by handlers).
    pub produced: u64,
    /// Work units fully processed.
    pub completed: u64,
    /// Units completed per worker — load-balance instrumentation for Gate B.
    pub per_worker_completed: Vec<u64>,
    /// Wall time of the parallel run.
    pub elapsed: Duration,
    /// Steals from a peer in the same NUMA group.
    pub same_numa_steals: u64,
    /// Steals from a peer in a different NUMA group.
    pub cross_numa_steals: u64,
    /// Number of times a worker paused/yielded before stealing due to memory pressure.
    pub pressure_throttle_events: u64,
}

/// Backwards compatibility alias for [`PoolStats`].
pub type NumaPoolStats = PoolStats;

/// A pool of OS threads over worker-local deques with NUMA-group-aware work
/// stealing and memory-pressure throttling.
///
/// ### Steal order
/// 1. Own deque (LIFO).
/// 2. Most-loaded peer in the **same** NUMA group (FIFO steal).
/// 3. Most-loaded peer in a **different** NUMA group (FIFO steal, counted as
///    cross-NUMA steal; yields before stealing when under memory pressure).
/// 4. Global overflow queue.
///
/// ### NUMA groups
/// Workers are partitioned into groups by the `numa_groups` parameter.
/// Each element of the outer `Vec` is a NUMA group; each element of the inner
/// `Vec` is a worker index belonging to that group. Workers not listed in any
/// group are implicitly placed into group 0 (the default group).
pub struct OsWorkerPool<T: Send> {
    queues: Vec<Mutex<VecDeque<T>>>,
    global: Mutex<VecDeque<T>>,
    produced: AtomicU64,
    completed: AtomicU64,
    inflight: AtomicU64,
    per_worker: Vec<AtomicU64>,
    worker_count: u32,
    /// `group_of[worker_index]` = NUMA group index for that worker.
    group_of: Vec<usize>,
    /// `group_members[group_index]` = sorted list of worker indices in that group.
    group_members: Vec<Vec<usize>>,
    same_numa_steals: AtomicU64,
    cross_numa_steals: AtomicU64,
    pressure_throttle_events: AtomicU64,
    pressure_threshold: u64,
}

impl<T: Send> OsWorkerPool<T> {
    /// Creates a pool with `worker_count` worker deques in a single NUMA group
    /// and default memory-pressure threshold (512 MiB).
    pub fn new(worker_count: u32) -> Self {
        let count = worker_count.max(1) as usize;
        let all: Vec<usize> = (0..count).collect();
        Self::with_options(worker_count, vec![all], DEFAULT_PRESSURE_THRESHOLD_BYTES)
    }

    /// Convenience constructor: all workers in one group, default pressure threshold.
    pub fn single_group(worker_count: u32) -> Self {
        Self::new(worker_count)
    }

    /// Creates a pool with configurable NUMA groups and default memory-pressure threshold.
    pub fn with_numa_groups(worker_count: u32, numa_groups: Vec<Vec<usize>>) -> Self {
        Self::with_options(worker_count, numa_groups, DEFAULT_PRESSURE_THRESHOLD_BYTES)
    }

    /// Creates a NUMA-aware pool with configurable NUMA groups and memory-pressure threshold.
    ///
    /// # Parameters
    /// - `worker_count`: total number of workers.
    /// - `numa_groups`: partition of worker indices by NUMA group. Workers
    ///   missing from the partition are placed in group 0.
    /// - `pressure_threshold`: available-memory threshold in bytes below which
    ///   cross-group stealing is throttled. Use
    ///   [`DEFAULT_PRESSURE_THRESHOLD_BYTES`] for the default 512 MiB.
    pub fn with_options(
        worker_count: u32,
        numa_groups: Vec<Vec<usize>>,
        pressure_threshold: u64,
    ) -> Self {
        let count = worker_count.max(1) as usize;

        let mut group_of = vec![0usize; count];
        let mut assigned = vec![false; count];
        let mut group_members: Vec<Vec<usize>> = if numa_groups.is_empty() {
            vec![(0..count).collect()]
        } else {
            let mut members: Vec<Vec<usize>> = (0..numa_groups.len()).map(|_| vec![]).collect();
            for (gidx, workers) in numa_groups.iter().enumerate() {
                for &w in workers {
                    if w < count && !assigned[w] {
                        group_of[w] = gidx;
                        members[gidx].push(w);
                        assigned[w] = true;
                    }
                }
            }
            // Workers not mentioned in any group fall into group 0.
            for w in 0..count {
                if !assigned[w] {
                    group_of[w] = 0;
                    members[0].push(w);
                    assigned[w] = true;
                }
            }
            members
        };

        for g in &mut group_members {
            g.sort_unstable();
        }

        let mut queues = Vec::with_capacity(count);
        let mut per_worker = Vec::with_capacity(count);
        for _ in 0..count {
            queues.push(Mutex::new(VecDeque::new()));
            per_worker.push(AtomicU64::new(0));
        }

        Self {
            queues,
            global: Mutex::new(VecDeque::new()),
            produced: AtomicU64::new(0),
            completed: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            per_worker,
            worker_count: worker_count.max(1),
            group_of,
            group_members,
            same_numa_steals: AtomicU64::new(0),
            cross_numa_steals: AtomicU64::new(0),
            pressure_throttle_events: AtomicU64::new(0),
            pressure_threshold,
        }
    }

    /// Returns the NUMA group index for the given worker.
    pub fn group_of(&self, worker: usize) -> usize {
        self.group_of.get(worker).copied().unwrap_or(0)
    }

    /// Returns a slice of all members in `group`.
    pub fn group_members(&self, group: usize) -> &[usize] {
        self.group_members.get(group).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Number of NUMA groups.
    pub fn group_count(&self) -> usize {
        self.group_members.len()
    }

    /// Enqueues a unit on `worker`'s deque (or the global overflow queue when
    /// the local deque is at capacity).
    pub fn push(&self, worker: u32, item: T) {
        let index = usize::try_from(worker).unwrap_or(0) % self.queues.len();
        if let Ok(mut queue) = self.queues[index].lock() {
            queue.push_back(item);
        } else if let Ok(mut global) = self.global.lock() {
            global.push_back(item);
        }
        self.produced.fetch_add(1, Ordering::Relaxed);
    }

    fn peek_load(&self, peer: usize) -> usize {
        self.queues
            .get(peer)
            .and_then(|q| q.lock().ok())
            .map(|g| g.len())
            .unwrap_or(0)
    }

    fn steal_from(&self, peer: usize) -> Option<T> {
        let mut guard = self.queues.get(peer)?.lock().ok()?;
        guard.pop_front()
    }

    fn most_loaded_in(&self, candidates: &[usize], self_idx: usize) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_load = 0usize;
        for &peer in candidates {
            if peer == self_idx {
                continue;
            }
            let load = self.peek_load(peer);
            if load > best_load {
                best_load = load;
                best = Some(peer);
            }
        }
        if best_load == 0 { None } else { best }
    }

    /// Pops the next unit for `worker`:
    /// 1. Own deque (LIFO).
    /// 2. Most-loaded peer in the same NUMA group (FIFO steal).
    /// 3. Most-loaded peer in another NUMA group (FIFO steal; yields if under memory pressure).
    /// 4. Global overflow queue.
    pub fn next(&self, worker: u32) -> Option<T> {
        let idx = usize::try_from(worker).unwrap_or(0) % self.queues.len();

        // 1. Own deque (LIFO).
        if let Ok(mut q) = self.queues[idx].lock()
            && let Some(item) = q.pop_back()
        {
            self.inflight.fetch_add(1, Ordering::Relaxed);
            return Some(item);
        }

        let my_group = self.group_of.get(idx).copied().unwrap_or(0);

        // 2. Same-NUMA-group peer (FIFO steal).
        let same_group = self.group_members.get(my_group).map(|v| v.as_slice()).unwrap_or(&[]);
        if let Some(peer) = self.most_loaded_in(same_group, idx)
            && let Some(item) = self.steal_from(peer)
        {
            self.same_numa_steals.fetch_add(1, Ordering::Relaxed);
            self.inflight.fetch_add(1, Ordering::Relaxed);
            return Some(item);
        }

        // 3. Cross-NUMA-group peer — throttle under memory pressure.
        let cross_candidates: Vec<usize> = (0..self.queues.len())
            .filter(|&w| self.group_of.get(w).copied().unwrap_or(0) != my_group)
            .collect();

        if !cross_candidates.is_empty()
            && let Some(peer) = self.most_loaded_in(&cross_candidates, idx)
        {
            if MemoryPressureMonitor::is_under_pressure(self.pressure_threshold) {
                self.pressure_throttle_events.fetch_add(1, Ordering::Relaxed);
                std::thread::yield_now();
            }
            if let Some(item) = self.steal_from(peer) {
                self.cross_numa_steals.fetch_add(1, Ordering::Relaxed);
                self.inflight.fetch_add(1, Ordering::Relaxed);
                return Some(item);
            }
        }

        // 4. Global overflow queue.
        if let Ok(mut global) = self.global.lock()
            && let Some(item) = global.pop_front()
        {
            self.inflight.fetch_add(1, Ordering::Relaxed);
            return Some(item);
        }

        None
    }

    /// True when the run has finished: every produced unit completed and no
    /// worker holds an in-flight unit.
    fn finished(&self) -> bool {
        self.produced.load(Ordering::Relaxed) == self.completed.load(Ordering::Relaxed)
            && self.inflight.load(Ordering::Relaxed) == 0
    }

    /// Number of workers in this pool.
    pub fn worker_count(&self) -> u32 {
        self.worker_count
    }

    /// Snapshot of steal counters: `(same_numa_steals, cross_numa_steals, pressure_throttle_events)`.
    pub fn steal_counts(&self) -> (u64, u64, u64) {
        (
            self.same_numa_steals.load(Ordering::Relaxed),
            self.cross_numa_steals.load(Ordering::Relaxed),
            self.pressure_throttle_events.load(Ordering::Relaxed),
        )
    }
}

impl<T: Send + 'static> OsWorkerPool<T> {
    /// Runs `handler` on `worker_count` OS threads until the pool drains.
    /// The handler receives the worker index, the unit, and a callback for
    /// pushing follow-up units (children) onto this worker's deque.
    pub fn run<H>(self: &Arc<Self>, handler: H) -> PoolStats
    where
        H: Fn(u32, T, &dyn Fn(T)) + Send + Sync,
    {
        let started = Instant::now();
        let pool = Arc::clone(self);
        std::thread::scope(|scope| {
            for worker in 0..self.worker_count {
                let pool = Arc::clone(&pool);
                let handler = &handler;
                scope.spawn(move || loop {
                    match pool.next(worker) {
                        Some(item) => {
                            let pool2 = Arc::clone(&pool);
                            let enqueue = move |child: T| pool2.push(worker, child);
                            handler(worker, item, &enqueue);
                            pool.completed.fetch_add(1, Ordering::Relaxed);
                            pool.per_worker[usize::try_from(worker).unwrap_or(0)]
                                .fetch_add(1, Ordering::Relaxed);
                            pool.inflight.fetch_sub(1, Ordering::Relaxed);
                        }
                        None => {
                            if pool.finished() {
                                return;
                            }
                            std::thread::yield_now();
                        }
                    }
                });
            }
        });
        PoolStats {
            produced: self.produced.load(Ordering::Relaxed),
            completed: self.completed.load(Ordering::Relaxed),
            per_worker_completed: self
                .per_worker
                .iter()
                .map(|counter| counter.load(Ordering::Relaxed))
                .collect(),
            elapsed: started.elapsed(),
            same_numa_steals: self.same_numa_steals.load(Ordering::Relaxed),
            cross_numa_steals: self.cross_numa_steals.load(Ordering::Relaxed),
            pressure_throttle_events: self.pressure_throttle_events.load(Ordering::Relaxed),
        }
    }
}

/// Backwards compatibility alias for [`OsWorkerPool`].
pub type NumaOsWorkerPool<T> = OsWorkerPool<T>;

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

        // -----------------------------------------------------------------------
    // OsWorkerPool: group assignment tests
    // -----------------------------------------------------------------------

    /// Verify that `group_of` and `group_members` reflect the supplied partition.
    #[test]
    fn numa_group_assignment_two_groups() {
        // 4 workers split 0-1 into group 0 and 2-3 into group 1.
        let pool: OsWorkerPool<u32> = OsWorkerPool::with_options(
            4,
            vec![vec![0, 1], vec![2, 3]],
            DEFAULT_PRESSURE_THRESHOLD_BYTES,
        );

        assert_eq!(pool.group_count(), 2);

        // group_of checks
        assert_eq!(pool.group_of(0), 0);
        assert_eq!(pool.group_of(1), 0);
        assert_eq!(pool.group_of(2), 1);
        assert_eq!(pool.group_of(3), 1);

        // group_members checks (sorted)
        assert_eq!(pool.group_members(0), &[0usize, 1]);
        assert_eq!(pool.group_members(1), &[2usize, 3]);
    }

    /// Workers not listed in any group fall into group 0.
    #[test]
    fn numa_group_unmentioned_workers_fall_into_group_zero() {
        // Explicitly list workers 1 and 3 in group 1; workers 0 and 2 are not
        // mentioned and must land in group 0.
        let pool: OsWorkerPool<u32> = OsWorkerPool::with_options(
            4,
            vec![vec![], vec![1, 3]],
            DEFAULT_PRESSURE_THRESHOLD_BYTES,
        );

        assert_eq!(pool.group_of(0), 0, "worker 0 should fall into group 0");
        assert_eq!(pool.group_of(1), 1);
        assert_eq!(pool.group_of(2), 0, "worker 2 should fall into group 0");
        assert_eq!(pool.group_of(3), 1);

        // group 0 should contain workers 0 and 2
        let mut g0: Vec<usize> = pool.group_members(0).to_vec();
        g0.sort_unstable();
        assert_eq!(g0, vec![0usize, 2]);
    }

    /// Single-group convenience constructor puts all workers in group 0.
    #[test]
    fn numa_single_group_constructor() {
        let pool: OsWorkerPool<u32> = OsWorkerPool::single_group(4);
        assert_eq!(pool.group_count(), 1);
        for w in 0..4 {
            assert_eq!(pool.group_of(w), 0);
        }
        // All 4 workers are in group 0.
        let mut members = pool.group_members(0).to_vec();
        members.sort_unstable();
        assert_eq!(members, vec![0usize, 1, 2, 3]);
    }

    // -----------------------------------------------------------------------
    // OsWorkerPool: steal-counter tests
    // -----------------------------------------------------------------------

    /// Force a same-NUMA steal by pre-loading a peer in the same group and
    /// draining the stealing worker's own queue.
    #[test]
    fn same_numa_steal_counter_increments() {
        // 2 workers, both in group 0 — same NUMA.
        let pool = Arc::new(OsWorkerPool::<u32>::with_options(
            2,
            vec![vec![0, 1]],
            DEFAULT_PRESSURE_THRESHOLD_BYTES,
        ));

        // Load work only onto worker 1.
        pool.push(1, 100u32);
        pool.push(1, 101u32);
        pool.push(1, 102u32);

        // Worker 0 has an empty local queue -> will steal from worker 1 (same group).
        let stats = pool.run(|_worker, _item, _push| {});

        assert!(
            stats.same_numa_steals >= 1,
            "expected >=1 same-NUMA steal, got {}",
            stats.same_numa_steals
        );
        assert_eq!(
            stats.cross_numa_steals, 0,
            "no cross-NUMA steals expected in a single-group pool"
        );
        assert_eq!(stats.completed, stats.produced, "all work must complete");
    }

    /// Force a cross-NUMA steal by putting the donor in a different group.
    ///
    /// We call `next(0)` directly (rather than `run`) so worker 0 is the sole
    /// consumer. Worker 0 has an empty local queue, no same-group peers, and
    /// therefore must steal cross-NUMA from worker 1.
    #[test]
    fn cross_numa_steal_counter_increments() {
        // Worker 0 in group 0, worker 1 in group 1 — different NUMA nodes.
        // pressure_threshold = 0 -> is_under_pressure(0) is always false.
        let pool = OsWorkerPool::<u32>::with_options(
            2,
            vec![vec![0], vec![1]],
            0,
        );

        // Load work only onto worker 1 (group 1).
        pool.push(1, 200u32);
        pool.push(1, 201u32);
        pool.push(1, 202u32);

        // Drain via worker 0 only — it has no local items and no same-group peers,
        // so every successful pop is a cross-NUMA steal.
        let mut popped = 0u32;
        while pool.next(0).is_some() {
            popped += 1;
        }

        let (same, cross, _throttle) = pool.steal_counts();
        assert!(popped >= 1, "worker 0 should have stolen at least one item");
        assert!(
            cross >= 1,
            "expected >=1 cross-NUMA steal, got {cross}"
        );
        assert_eq!(same, 0, "no same-NUMA steals expected");
    }

    /// Under memory pressure, cross-NUMA stealing records a throttle event.
    #[test]
    #[cfg(target_os = "linux")]
    fn memory_pressure_throttling_increments_counter() {
        // Worker 0 in group 0, worker 1 in group 1.
        // Set threshold to u64::MAX so is_under_pressure is guaranteed true on Linux.
        let pool = OsWorkerPool::<u32>::with_options(
            2,
            vec![vec![0], vec![1]],
            u64::MAX,
        );

        pool.push(1, 300u32);

        // Worker 0 steals cross-NUMA from worker 1 under pressure.
        let item = pool.next(0);
        assert_eq!(item, Some(300u32));

        let (_same, cross, throttle) = pool.steal_counts();
        assert_eq!(cross, 1);
        assert!(
            throttle >= 1,
            "expected >=1 pressure throttle event, got {throttle}"
        );
    }

    // -----------------------------------------------------------------------
    // MemoryPressureMonitor tests
    // -----------------------------------------------------------------------

    /// On Linux the monitor must parse /proc/meminfo and return a positive byte
    /// count; on other platforms it returns None.
    #[test]
    fn memory_pressure_monitor_available_bytes() {
        let result = MemoryPressureMonitor::available_bytes();

        #[cfg(target_os = "linux")]
        {
            if let Some(bytes) = result {
                assert!(bytes > 0, "available bytes should be positive");
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            assert!(
                result.is_none(),
                "on non-Linux platforms available_bytes() must return None"
            );
        }
    }

    /// `is_under_pressure` must return `false` when the threshold is zero
    /// (available >= 0 is always true), and `true` only when available < threshold.
    #[test]
    fn memory_pressure_is_under_pressure_threshold_zero() {
        // A threshold of 0 means "never throttle": available bytes >= 0 always.
        assert!(
            !MemoryPressureMonitor::is_under_pressure(0),
            "zero threshold should never report pressure"
        );
    }

    /// `is_under_pressure` with a very large threshold should report pressure
    /// on Linux (unless the machine has exabytes of RAM).
    #[test]
    #[cfg(target_os = "linux")]
    fn memory_pressure_is_under_pressure_very_high_threshold() {
        // u64::MAX bytes — no machine has this much RAM.
        assert!(
            MemoryPressureMonitor::is_under_pressure(u64::MAX),
            "u64::MAX threshold should always report pressure on Linux"
        );
    }
}
