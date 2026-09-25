#![forbid(unsafe_code)]

pub mod alpha;

pub use alpha::{AlphaKey, AlphaReuseConfig, AlphaReuseStats, alpha_key};
use angryier_expr::ExprReader;
pub use angryier_types::SolverOutcomeKind;
use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, SolverQueryId, TargetProfileId,
};
use core::time::Duration;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalConstraint {
    pub id: ConstraintId,
    pub key: DependencyKey,
    pub expr: ExprId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolverQueryError {
    DuplicateConstraintId(ConstraintId),
    ZeroTimeout,
    CanonicalIdentityMismatch,
}

impl core::fmt::Display for SolverQueryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateConstraintId(id) => write!(formatter, "duplicate constraint id: {}", id.0),
            Self::ZeroTimeout => formatter.write_str("solver query timeout must be non-zero"),
            Self::CanonicalIdentityMismatch => formatter.write_str("solver query canonical identity mismatch"),
        }
    }
}

impl std::error::Error for SolverQueryError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverQuery {
    id: SolverQueryId,
    path_constraints: Vec<ConstraintId>,
    predicate: ExprId,
    constraint_keys: Vec<DependencyKey>,
    constraint_expressions: Vec<(ConstraintId, ExprId)>,
    predicate_key: DependencyKey,
    target_profile: TargetProfileId,
    canonicalization_version: ConstraintCanonicalizationVersion,
    canonical_key: DependencyKey,
    timeout: Duration,
}

impl SolverQuery {
    pub fn canonical(
        id: SolverQueryId,
        constraints: &[CanonicalConstraint],
        predicate: ExprId,
        predicate_key: DependencyKey,
        target_profile: TargetProfileId,
        canonicalization_version: ConstraintCanonicalizationVersion,
        timeout: Duration,
    ) -> Result<Self, SolverQueryError> {
        if timeout.is_zero() {
            return Err(SolverQueryError::ZeroTimeout);
        }
        let mut seen_ids = BTreeSet::new();
        for constraint in constraints {
            if !seen_ids.insert(constraint.id) {
                return Err(SolverQueryError::DuplicateConstraintId(constraint.id));
            }
        }
        let mut constraint_keys: Vec<_> = constraints.iter().map(|constraint| constraint.key).collect();
        constraint_keys.sort_unstable();
        constraint_keys.dedup();
        let canonical_key = derive_query_key(
            &constraint_keys,
            predicate_key,
            target_profile,
            canonicalization_version,
        );
        Ok(Self {
            id,
            path_constraints: constraints.iter().map(|constraint| constraint.id).collect(),
            predicate,
            constraint_keys,
            constraint_expressions: constraints
                .iter()
                .map(|constraint| (constraint.id, constraint.expr))
                .collect(),
            predicate_key,
            target_profile,
            canonicalization_version,
            canonical_key,
            timeout,
        })
    }

    pub fn validate_identity(&self) -> Result<(), SolverQueryError> {
        let expected = derive_query_key(
            &self.constraint_keys,
            self.predicate_key,
            self.target_profile,
            self.canonicalization_version,
        );
        if expected != self.canonical_key {
            return Err(SolverQueryError::CanonicalIdentityMismatch);
        }
        Ok(())
    }

    pub fn id(&self) -> SolverQueryId {
        self.id
    }

    pub fn path_constraints(&self) -> &[ConstraintId] {
        &self.path_constraints
    }

    pub fn predicate(&self) -> ExprId {
        self.predicate
    }

    pub fn constraint_keys(&self) -> &[DependencyKey] {
        &self.constraint_keys
    }

    pub fn constraint_expressions(&self) -> &[(ConstraintId, ExprId)] {
        &self.constraint_expressions
    }

    pub fn predicate_key(&self) -> DependencyKey {
        self.predicate_key
    }

    pub fn target_profile(&self) -> TargetProfileId {
        self.target_profile
    }

    pub fn canonicalization_version(&self) -> ConstraintCanonicalizationVersion {
        self.canonicalization_version
    }

    pub fn canonical_key(&self) -> DependencyKey {
        self.canonical_key
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverResult {
    pub outcome: SolverOutcomeKind,
    pub model: Vec<(u64, Vec<u8>)>,
    pub unsat_core: Vec<ConstraintId>,
    pub elapsed: Duration,
}

pub trait SolverBackend: Send {
    fn name(&self) -> &'static str;
    fn solve(&mut self, query: &SolverQuery) -> SolverResult;
    fn solve_batch(&mut self, shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult>;

    fn as_cancellable_mut(&mut self) -> Option<&mut dyn CancellableSolverBackend> {
        None
    }
}

pub trait SolverRouter: Send + Sync {
    fn rank_backends(&self, query: &SolverQuery) -> Vec<&'static str>;
    fn should_preempt(&self, query: &SolverQuery, elapsed: Duration) -> bool;
    fn record_outcome(&self, _backend: &'static str, _outcome: SolverOutcomeKind, _elapsed: Duration) {}
}

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

pub trait CancellableSolverBackend: SolverBackend {
    fn solve_cancellable(&mut self, query: &SolverQuery, cancellation: &CancellationToken) -> SolverResult;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SolverCacheStats {
    pub hits: u64,
    pub misses: u64,
    pub entries: u64,
    /// Entries evicted to make room for a higher-value admission.
    pub evictions: u64,
    /// Inserts refused because the shard was full of higher-value entries.
    pub rejected_capacity: u64,
    /// Inserts refused because the byte budget was exhausted.
    pub rejected_budget: u64,
    /// Estimated bytes currently stored (sum of per-entry estimates).
    pub stored_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheAdmission {
    Stored,
    RejectedTransient,
    RejectedCapacity,
    RejectedBudget,
}

/// Bounded, value-aware admission policy for [`InMemorySolverCache`].
///
/// Every Sat/Unsat result used to be admitted; under adversarial or simply
/// long-running workloads that grows without bound. The policy bounds the
/// cache two ways — per-shard entry caps and a global byte budget — and
/// admits by *estimated reuse value*: a small count sketch of seen canonical
/// keys predicts which queries repeat, so under pressure a key seen more
/// than once is stored (or evicts a lower-value entry) while one-shot keys
/// are rejected with observable counters. All decisions are deterministic
/// functions of the observed key sequence (fixed sketch hashes, FIFO among
/// equal scores) — no time-based input, so admissions replay identically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheAdmissionPolicy {
    /// Maximum stored entries per shard.
    pub max_entries_per_shard: usize,
    /// Total estimated bytes admitted across all shards.
    pub byte_budget: u64,
}

impl Default for CacheAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_entries_per_shard: 8192,
            byte_budget: 1 << 30,
        }
    }
}

/// Estimated heap footprint of one cached result: key + entry overhead,
/// model bytes and unsat-core ids. Deterministic in the result's contents.
fn estimate_entry_bytes(result: &SolverResult) -> u64 {
    let model_bytes: u64 = result
        .model
        .iter()
        .map(|(_, value)| u64::try_from(value.len()).unwrap_or(u64::MAX))
        .fold(0u64, |sum, len| sum.saturating_add(len.saturating_add(16)));
    let core_bytes = result.unsat_core.len().saturating_mul(8).try_into().unwrap_or(u64::MAX);
    // 32-byte key + entry header (Arc, score, bytes, seq) + vec overhead.
    96u64.saturating_add(model_bytes).saturating_add(core_bytes)
}

/// Per-shard count sketch over canonical keys: two saturating counters per
/// key (two independent hash probes, estimate = min). Collisions overcount —
/// deterministic for a given key sequence, and conservative for admission
/// (an overcounted one-shot can at worst be admitted like today).
struct SeenSketch {
    counters: [u16; SEEN_COUNTERS_PER_SHARD],
}

impl Default for SeenSketch {
    fn default() -> Self {
        Self {
            counters: [0; SEEN_COUNTERS_PER_SHARD],
        }
    }
}

const SEEN_COUNTERS_PER_SHARD: usize = 4096;

fn fnv1a(key: &DependencyKey, seed: u64) -> u64 {
    let mut hash = 0xcbf29ce484222325u64 ^ seed;
    for byte in key.0 {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

impl SeenSketch {
    fn probes(key: &DependencyKey) -> (usize, usize) {
        let first = (fnv1a(key, 0) % SEEN_COUNTERS_PER_SHARD as u64) as usize;
        let second = (fnv1a(key, 0x9e3779b97f4a7c15) % SEEN_COUNTERS_PER_SHARD as u64) as usize;
        (first, second)
    }

    fn record(&mut self, key: &DependencyKey) {
        let (first, second) = Self::probes(key);
        self.counters[first] = self.counters[first].saturating_add(1);
        self.counters[second] = self.counters[second].saturating_add(1);
    }

    fn estimate(&self, key: &DependencyKey) -> u32 {
        let (first, second) = Self::probes(key);
        u32::from(self.counters[first]).min(u32::from(self.counters[second]))
    }
}

/// One shard: the entry map plus the seen-key sketch guarding it.
#[derive(Default)]
struct CacheShard {
    entries: HashMap<DependencyKey, CacheEntry>,
    seen: SeenSketch,
}

#[derive(Clone)]
struct CacheEntry {
    result: Arc<SolverResult>,
    /// Seen-sketch estimate at admission time (reuse-value score).
    score: u32,
    /// Estimated byte footprint at admission time.
    bytes: u64,
    /// Admission sequence number; strictly increasing, so (score, seq)
    /// totally orders entries and eviction is deterministic (FIFO among
    /// equal scores).
    seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SolverCacheError {
    InvalidQuery(SolverQueryError),
    LockPoisoned,
}

impl core::fmt::Display for SolverCacheError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidQuery(error) => write!(formatter, "invalid solver query: {error}"),
            Self::LockPoisoned => formatter.write_str("solver cache lock was poisoned"),
        }
    }
}

impl std::error::Error for SolverCacheError {}

const SHARD_COUNT: usize = 16;
const ALPHA_CANDIDATES_MAX: usize = 8;
const ALPHA_BUCKETS_MAX: usize = 1 << 16;

#[derive(Default)]
pub struct InMemorySolverCache {
    shards: [Mutex<CacheShard>; SHARD_COUNT],
    policy: CacheAdmissionPolicy,
    seq_counter: AtomicU64,
    total_bytes: AtomicU64,
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
    rejected_capacity: AtomicU64,
    rejected_budget: AtomicU64,
    /// Alpha key -> exact canonical keys of admitted entries (validation
    /// tier; see [`alpha`]). Never holds a shard lock while locked.
    alpha_index: Mutex<HashMap<AlphaKey, Vec<DependencyKey>>>,
    alpha_proposals: AtomicU64,
    alpha_confirmations: AtomicU64,
    alpha_contradictions: AtomicU64,
    alpha_suppressed_reuses: AtomicU64,
}

fn shard_index(key: &DependencyKey) -> usize {
    usize::from(key.0[0]) % SHARD_COUNT
}

impl InMemorySolverCache {
    /// Cache with the default (generous, effectively unbounded for typical
    /// workloads) admission policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Cache with an explicit bounded admission policy.
    pub fn with_policy(policy: CacheAdmissionPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn policy(&self) -> CacheAdmissionPolicy {
        self.policy
    }

    pub fn lookup(&self, query: &SolverQuery) -> Result<Option<Arc<SolverResult>>, SolverCacheError> {
        query.validate_identity().map_err(SolverCacheError::InvalidQuery)?;
        let key = query.canonical_key();
        let index = shard_index(&key);
        let mut shard = self.shards[index].lock().map_err(|_| SolverCacheError::LockPoisoned)?;
        let result = shard.entries.get(&key).cloned().map(|entry| entry.result);
        // Every lookup is reuse-predictor evidence, hit or miss.
        shard.seen.record(&key);
        drop(shard);
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    pub fn insert(&self, query: &SolverQuery, result: SolverResult) -> Result<CacheAdmission, SolverCacheError> {
        self.insert_with_alpha(query, None, result)
    }

    /// Inserts with an optional alpha key: on admission the exact key is
    /// also indexed under the alpha key so later alpha-equivalent queries
    /// can propose it as a reuse candidate.
    pub fn insert_with_alpha(
        &self,
        query: &SolverQuery,
        alpha: Option<AlphaKey>,
        result: SolverResult,
    ) -> Result<CacheAdmission, SolverCacheError> {
        query.validate_identity().map_err(SolverCacheError::InvalidQuery)?;
        if !matches!(result.outcome, SolverOutcomeKind::Sat | SolverOutcomeKind::Unsat) {
            return Ok(CacheAdmission::RejectedTransient);
        }
        let key = query.canonical_key();
        let index = shard_index(&key);
        let admission = {
            let mut shard = self.shards[index].lock().map_err(|_| SolverCacheError::LockPoisoned)?;
            self.admit_locked(&key, result, &mut shard)
        };
        if admission == Ok(CacheAdmission::Stored)
            && let Some(alpha) = alpha
            && let Ok(mut alpha_index) = self.alpha_index.lock()
        {
            Self::index_alpha_locked(&mut alpha_index, alpha, key);
        }
        admission
    }

    /// Admission decision under a held shard lock. Value-aware: the
    /// seen-sketch score decides whether a full shard evicts its minimum
    /// (score, seq) entry for the newcomer or rejects it; the byte budget
    /// rejects what does not fit after any eviction.
    fn admit_locked(
        &self,
        key: &DependencyKey,
        result: SolverResult,
        shard: &mut CacheShard,
    ) -> Result<CacheAdmission, SolverCacheError> {
        let bytes = estimate_entry_bytes(&result);
        let score = shard.seen.estimate(key);
        if let Some(entry) = shard.entries.get_mut(key) {
            // Refresh an admitted key: newest result, best-known score.
            self.total_bytes.fetch_sub(entry.bytes, Ordering::Relaxed);
            self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
            entry.result = Arc::new(result);
            entry.score = entry.score.max(score);
            entry.bytes = bytes;
            entry.seq = self.seq_counter.fetch_add(1, Ordering::Relaxed);
            return Ok(CacheAdmission::Stored);
        }
        // The eviction victim: minimum (score, seq) — the least valuable,
        // oldest among equals. seq is unique, so the choice is deterministic.
        let minimum = shard
            .entries
            .iter()
            .min_by_key(|(_, entry)| (entry.score, entry.seq))
            .map(|(entry_key, entry)| (*entry_key, entry.score, entry.bytes));
        if shard.entries.len() >= self.policy.max_entries_per_shard {
            match minimum {
                // Strictly more valuable than the victim: evict it. Equal
                // value does not churn a stable shard — reject instead, so
                // repeated keys beat one-shots and admission replays.
                Some((min_key, min_score, min_bytes)) if score > min_score => {
                    if shard.entries.remove(&min_key).is_some() {
                        self.total_bytes.fetch_sub(min_bytes, Ordering::Relaxed);
                        self.evictions.fetch_add(1, Ordering::Relaxed);
                    }
                }
                // Shard full of equal or more valuable entries (or cap 0).
                _ => {
                    self.rejected_capacity.fetch_add(1, Ordering::Relaxed);
                    return Ok(CacheAdmission::RejectedCapacity);
                }
            }
        }
        if self.total_bytes.load(Ordering::Relaxed).saturating_add(bytes) > self.policy.byte_budget {
            // One eviction attempt, same strict rule as the capacity path.
            if let Some((min_key, min_score, min_bytes)) = minimum
                && score > min_score
                && shard.entries.remove(&min_key).is_some()
            {
                self.total_bytes.fetch_sub(min_bytes, Ordering::Relaxed);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
            if self.total_bytes.load(Ordering::Relaxed).saturating_add(bytes) > self.policy.byte_budget {
                self.rejected_budget.fetch_add(1, Ordering::Relaxed);
                return Ok(CacheAdmission::RejectedBudget);
            }
        }
        self.total_bytes.fetch_add(bytes, Ordering::Relaxed);
        let seq = self.seq_counter.fetch_add(1, Ordering::Relaxed);
        shard.entries.insert(
            *key,
            CacheEntry {
                result: Arc::new(result),
                score,
                bytes,
                seq,
            },
        );
        Ok(CacheAdmission::Stored)
    }

    fn index_alpha_locked(
        alpha_index: &mut HashMap<AlphaKey, Vec<DependencyKey>>,
        alpha: AlphaKey,
        key: DependencyKey,
    ) {
        if let Some(bucket) = alpha_index.get_mut(&alpha) {
            if !bucket.contains(&key) && bucket.len() < ALPHA_CANDIDATES_MAX {
                bucket.push(key);
            }
            return;
        }
        if alpha_index.len() >= ALPHA_BUCKETS_MAX {
            return;
        }
        alpha_index.insert(alpha, vec![key]);
    }

    /// Proposes reuse candidates for an alpha key: admitted results whose
    /// queries were alpha-equivalent, ordered by exact key for replayable
    /// candidate selection. Presence is verified per exact key, so evicted
    /// entries simply stop being proposed.
    pub fn propose_alpha(&self, alpha: AlphaKey) -> Result<Vec<(DependencyKey, Arc<SolverResult>)>, SolverCacheError> {
        self.alpha_proposals.fetch_add(1, Ordering::Relaxed);
        let candidates: Vec<DependencyKey> = self
            .alpha_index
            .lock()
            .map_err(|_| SolverCacheError::LockPoisoned)?
            .get(&alpha)
            .cloned()
            .unwrap_or_default();
        let mut proposals = Vec::with_capacity(candidates.len());
        for key in candidates {
            let index = shard_index(&key);
            if let Ok(shard) = self.shards[index].lock()
                && let Some(entry) = shard.entries.get(&key)
            {
                proposals.push((key, Arc::clone(&entry.result)));
            }
        }
        proposals.sort_by_key(|(left, _)| left.0);
        Ok(proposals)
    }

    /// Records that a confirmatory exact solve agreed with an alpha proposal.
    pub fn record_alpha_confirmation(&self) {
        self.alpha_confirmations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records that a confirmatory exact solve disagreed with an alpha
    /// proposal — a would-be poisoning had suppression been enabled.
    pub fn record_alpha_contradiction(&self) {
        self.alpha_contradictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a query answered from an alpha proposal without a
    /// confirming solve (only possible with the experimental suppression
    /// flag enabled).
    pub fn record_alpha_suppressed_reuse(&self) {
        self.alpha_suppressed_reuses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn alpha_stats(&self) -> Result<AlphaReuseStats, SolverCacheError> {
        let (indexed_buckets, indexed_candidates) = self
            .alpha_index
            .lock()
            .map_err(|_| SolverCacheError::LockPoisoned)
            .map(|index| {
                let buckets = u64::try_from(index.len()).unwrap_or(u64::MAX);
                let candidates: u64 = index.values().map(Vec::len).fold(0u64, |sum, len| {
                    sum.saturating_add(u64::try_from(len).unwrap_or(u64::MAX))
                });
                (buckets, candidates)
            })?;
        Ok(AlphaReuseStats {
            proposals: self.alpha_proposals.load(Ordering::Relaxed),
            confirmations: self.alpha_confirmations.load(Ordering::Relaxed),
            contradictions: self.alpha_contradictions.load(Ordering::Relaxed),
            suppressed_reuses: self.alpha_suppressed_reuses.load(Ordering::Relaxed),
            indexed_buckets,
            indexed_candidates,
        })
    }

    pub fn stats(&self) -> Result<SolverCacheStats, SolverCacheError> {
        let mut entries: u64 = 0;
        for shard in &self.shards {
            let len = shard.lock().map_err(|_| SolverCacheError::LockPoisoned)?.entries.len();
            entries = entries.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        }
        Ok(SolverCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries,
            evictions: self.evictions.load(Ordering::Relaxed),
            rejected_capacity: self.rejected_capacity.load(Ordering::Relaxed),
            rejected_budget: self.rejected_budget.load(Ordering::Relaxed),
            stored_bytes: self.total_bytes.load(Ordering::Relaxed),
        })
    }

    /// Returns the entry count for each shard, useful for verifying distribution.
    pub fn shard_lens(&self) -> Result<Vec<u64>, SolverCacheError> {
        let mut lens = Vec::with_capacity(SHARD_COUNT);
        for shard in &self.shards {
            let len = shard.lock().map_err(|_| SolverCacheError::LockPoisoned)?.entries.len();
            lens.push(u64::try_from(len).unwrap_or(u64::MAX));
        }
        Ok(lens)
    }
}

fn derive_query_key(
    constraint_keys: &[DependencyKey],
    predicate_key: DependencyKey,
    target_profile: TargetProfileId,
    version: ConstraintCanonicalizationVersion,
) -> DependencyKey {
    let mut normalized_constraints = constraint_keys.to_vec();
    normalized_constraints.sort_unstable();
    normalized_constraints.dedup();

    let mut hasher = Sha256::new();
    hasher.update(b"ANGRYIER\0SOLVER-QUERY\0");
    hasher.update(version.0.to_le_bytes());
    hasher.update(target_profile.0.to_le_bytes());
    hasher.update((normalized_constraints.len() as u64).to_le_bytes());
    for key in normalized_constraints {
        hasher.update(key.0);
    }
    hasher.update(predicate_key.0);
    DependencyKey(hasher.finalize().into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConstraintScale {
    Small,
    Medium,
    Large,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PredicateComplexity {
    Simple,
    Moderate,
    Complex,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TimeoutCategory {
    Short,
    Standard,
    Long,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QueryShape {
    pub constraint_scale: ConstraintScale,
    pub predicate_complexity: PredicateComplexity,
    pub timeout_category: TimeoutCategory,
    pub constraint_count: usize,
}

impl QueryShape {
    pub fn classify(query: &SolverQuery) -> Self {
        let constraint_count = query.constraint_keys().len();
        let constraint_scale = if constraint_count <= 4 {
            ConstraintScale::Small
        } else if constraint_count <= 16 {
            ConstraintScale::Medium
        } else {
            ConstraintScale::Large
        };

        let timeout = query.timeout();
        let timeout_category = if timeout < Duration::from_millis(500) {
            TimeoutCategory::Short
        } else if timeout <= Duration::from_secs(5) {
            TimeoutCategory::Standard
        } else {
            TimeoutCategory::Long
        };

        let pred_bytes = &query.predicate_key().0;
        let sum_pred_bytes: usize = pred_bytes.iter().map(|&b| b as usize).sum();
        let avg_pred_byte = sum_pred_bytes / 32;
        let complexity_score = avg_pred_byte.saturating_add(constraint_count.saturating_mul(10));

        let predicate_complexity = if complexity_score < 70 {
            PredicateComplexity::Simple
        } else if complexity_score < 180 {
            PredicateComplexity::Moderate
        } else {
            PredicateComplexity::Complex
        };

        Self {
            constraint_scale,
            predicate_complexity,
            timeout_category,
            constraint_count,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PreferredBackendHints {
    pub preferred_for_small_query: Option<&'static str>,
    pub preferred_for_large_query: Option<&'static str>,
    pub preferred_for_simple_predicate: Option<&'static str>,
    pub preferred_for_complex_predicate: Option<&'static str>,
    pub preferred_for_short_timeout: Option<&'static str>,
    pub preferred_for_long_timeout: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackendStats {
    pub sat_count: u64,
    pub unsat_count: u64,
    pub unknown_count: u64,
    pub timeout_count: u64,
    pub backend_error_count: u64,
    pub resource_limit_count: u64,
    pub total_elapsed: Duration,
    pub total_queries: u64,
}

impl BackendStats {
    pub fn average_elapsed(&self) -> Duration {
        if self.total_queries > 0 {
            let micros = self.total_elapsed.as_micros();
            let avg_micros = u64::try_from(micros / u128::from(self.total_queries)).unwrap_or(u64::MAX);
            Duration::from_micros(avg_micros)
        } else {
            Duration::ZERO
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CrossCheckPolicy {
    pub sample_rate: f64,
}

impl Default for CrossCheckPolicy {
    fn default() -> Self {
        Self { sample_rate: 0.10 }
    }
}

impl CrossCheckPolicy {
    pub const fn new(sample_rate: f64) -> Self {
        Self { sample_rate }
    }

    pub fn should_cross_check(&self, query: &SolverQuery) -> bool {
        if self.sample_rate <= 0.0 {
            return false;
        }
        if self.sample_rate >= 1.0 {
            return true;
        }
        let mut hasher = Sha256::new();
        hasher.update(b"ANGRYIER\0CROSS-CHECK\0");
        hasher.update(query.canonical_key().0);
        hasher.update(query.id().0.to_le_bytes());
        let digest = hasher.finalize();
        let val = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        let fraction = f64::from(val) / f64::from(u32::MAX);
        fraction < self.sample_rate
    }
}

pub struct MockSolverBackend {
    name: &'static str,
    outcome: SolverOutcomeKind,
    delay: Duration,
    call_count: usize,
}

impl MockSolverBackend {
    pub fn new(name: &'static str, outcome: SolverOutcomeKind) -> Self {
        Self {
            name,
            outcome,
            delay: Duration::ZERO,
            call_count: 0,
        }
    }

    pub fn with_delay(name: &'static str, outcome: SolverOutcomeKind, delay: Duration) -> Self {
        Self {
            name,
            outcome,
            delay,
            call_count: 0,
        }
    }

    pub fn call_count(&self) -> usize {
        self.call_count
    }
}

impl SolverBackend for MockSolverBackend {
    fn name(&self) -> &'static str {
        self.name
    }

    fn solve(&mut self, _query: &SolverQuery) -> SolverResult {
        self.call_count = self.call_count.saturating_add(1);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        SolverResult {
            outcome: self.outcome,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed: self.delay,
        }
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve(query)).collect()
    }
}

pub struct MockCancellableSolverBackend {
    name: &'static str,
    outcome: SolverOutcomeKind,
    delay: Duration,
    call_count: usize,
    cancelled_count: usize,
}

impl MockCancellableSolverBackend {
    pub fn new(name: &'static str, outcome: SolverOutcomeKind, delay: Duration) -> Self {
        Self {
            name,
            outcome,
            delay,
            call_count: 0,
            cancelled_count: 0,
        }
    }

    pub fn call_count(&self) -> usize {
        self.call_count
    }

    pub fn cancelled_count(&self) -> usize {
        self.cancelled_count
    }
}

impl SolverBackend for MockCancellableSolverBackend {
    fn name(&self) -> &'static str {
        self.name
    }

    fn solve(&mut self, _query: &SolverQuery) -> SolverResult {
        self.call_count = self.call_count.saturating_add(1);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        SolverResult {
            outcome: self.outcome,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed: self.delay,
        }
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve(query)).collect()
    }

    fn as_cancellable_mut(&mut self) -> Option<&mut dyn CancellableSolverBackend> {
        Some(self)
    }
}

impl CancellableSolverBackend for MockCancellableSolverBackend {
    fn solve_cancellable(&mut self, query: &SolverQuery, cancellation: &CancellationToken) -> SolverResult {
        self.call_count = self.call_count.saturating_add(1);
        let start = Instant::now();
        let step = Duration::from_millis(1);
        while start.elapsed() < self.delay {
            if cancellation.is_cancelled() {
                self.cancelled_count = self.cancelled_count.saturating_add(1);
                return SolverResult {
                    outcome: SolverOutcomeKind::Timeout,
                    model: Vec::new(),
                    unsat_core: Vec::new(),
                    elapsed: start.elapsed(),
                };
            }
            std::thread::sleep(step);
        }
        self.solve(query)
    }
}

pub struct InMemoryPortfolioRouter {
    backend_names: Vec<&'static str>,
    preempt_threshold: Duration,
    hints: PreferredBackendHints,
    history: Mutex<HashMap<&'static str, BackendStats>>,
}

impl InMemoryPortfolioRouter {
    pub fn new(backend_names: Vec<&'static str>, preempt_threshold: Duration) -> Self {
        Self {
            backend_names,
            preempt_threshold,
            hints: PreferredBackendHints::default(),
            history: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_hints(
        backend_names: Vec<&'static str>,
        preempt_threshold: Duration,
        hints: Option<PreferredBackendHints>,
    ) -> Self {
        Self {
            backend_names,
            preempt_threshold,
            hints: hints.unwrap_or_default(),
            history: Mutex::new(HashMap::new()),
        }
    }

    pub fn new_with_hints(
        backend_names: Vec<&'static str>,
        preempt_threshold: Duration,
        hints: Option<PreferredBackendHints>,
    ) -> Self {
        Self::with_hints(backend_names, preempt_threshold, hints)
    }

    pub fn record_outcome(&self, backend: &'static str, outcome: SolverOutcomeKind, elapsed: Duration) {
        if let Ok(mut map) = self.history.lock() {
            let entry = map.entry(backend).or_default();
            entry.total_queries = entry.total_queries.saturating_add(1);
            entry.total_elapsed = entry.total_elapsed.saturating_add(elapsed);
            match outcome {
                SolverOutcomeKind::Sat => entry.sat_count = entry.sat_count.saturating_add(1),
                SolverOutcomeKind::Unsat => entry.unsat_count = entry.unsat_count.saturating_add(1),
                SolverOutcomeKind::Unknown => entry.unknown_count = entry.unknown_count.saturating_add(1),
                SolverOutcomeKind::Timeout => entry.timeout_count = entry.timeout_count.saturating_add(1),
                SolverOutcomeKind::ResourceLimit => {
                    entry.resource_limit_count = entry.resource_limit_count.saturating_add(1);
                }
                SolverOutcomeKind::BackendError => {
                    entry.backend_error_count = entry.backend_error_count.saturating_add(1);
                }
            }
        }
    }

    pub fn stats_for(&self, backend: &'static str) -> Option<BackendStats> {
        self.history.lock().ok().and_then(|map| map.get(backend).copied())
    }

    pub fn hints(&self) -> &PreferredBackendHints {
        &self.hints
    }
}

impl Default for InMemoryPortfolioRouter {
    fn default() -> Self {
        Self {
            backend_names: Vec::new(),
            preempt_threshold: Duration::from_secs(30),
            hints: PreferredBackendHints::default(),
            history: Mutex::new(HashMap::new()),
        }
    }
}

impl SolverRouter for InMemoryPortfolioRouter {
    fn rank_backends(&self, query: &SolverQuery) -> Vec<&'static str> {
        if self.backend_names.is_empty() {
            return Vec::new();
        }

        let shape = QueryShape::classify(query);
        let history = self.history.lock().ok();

        let mut scored: Vec<(&'static str, i64, usize)> = self
            .backend_names
            .iter()
            .enumerate()
            .map(|(index, &name)| {
                let mut score: i64 = 1000;

                // 1. Preferred backend hints
                if let Some(preferred) = self.hints.preferred_for_small_query
                    && shape.constraint_scale == ConstraintScale::Small
                {
                    if preferred == name {
                        score = score.saturating_add(500);
                    } else {
                        score = score.saturating_sub(100);
                    }
                }
                if let Some(preferred) = self.hints.preferred_for_large_query
                    && shape.constraint_scale == ConstraintScale::Large
                {
                    if preferred == name {
                        score = score.saturating_add(500);
                    } else {
                        score = score.saturating_sub(100);
                    }
                }
                if let Some(preferred) = self.hints.preferred_for_simple_predicate
                    && shape.predicate_complexity == PredicateComplexity::Simple
                {
                    if preferred == name {
                        score = score.saturating_add(500);
                    } else {
                        score = score.saturating_sub(100);
                    }
                }
                if let Some(preferred) = self.hints.preferred_for_complex_predicate
                    && shape.predicate_complexity == PredicateComplexity::Complex
                {
                    if preferred == name {
                        score = score.saturating_add(500);
                    } else {
                        score = score.saturating_sub(100);
                    }
                }
                if let Some(preferred) = self.hints.preferred_for_short_timeout
                    && shape.timeout_category == TimeoutCategory::Short
                {
                    if preferred == name {
                        score = score.saturating_add(500);
                    } else {
                        score = score.saturating_sub(100);
                    }
                }
                if let Some(preferred) = self.hints.preferred_for_long_timeout
                    && shape.timeout_category == TimeoutCategory::Long
                {
                    if preferred == name {
                        score = score.saturating_add(500);
                    } else {
                        score = score.saturating_sub(100);
                    }
                }

                // 2. Default domain heuristic for well-known backends: "bitwuzla" vs "z3"
                if name == "bitwuzla" {
                    if shape.constraint_scale == ConstraintScale::Small {
                        score = score.saturating_add(300);
                    }
                    if shape.predicate_complexity == PredicateComplexity::Simple {
                        score = score.saturating_add(300);
                    }
                    if shape.timeout_category == TimeoutCategory::Short {
                        score = score.saturating_add(150);
                    }
                } else if name == "z3" {
                    if shape.constraint_scale == ConstraintScale::Large {
                        score = score.saturating_add(300);
                    } else if shape.constraint_scale == ConstraintScale::Medium {
                        score = score.saturating_add(100);
                    }
                    if shape.predicate_complexity == PredicateComplexity::Complex {
                        score = score.saturating_add(300);
                    } else if shape.predicate_complexity == PredicateComplexity::Moderate {
                        score = score.saturating_add(100);
                    }
                    if shape.timeout_category == TimeoutCategory::Long {
                        score = score.saturating_add(150);
                    }
                }

                // 3. Historical performance adjustments
                if let Some(ref map) = history
                    && let Some(stats) = map.get(name)
                {
                    let successes = stats.sat_count.saturating_add(stats.unsat_count);
                    score = score.saturating_add((successes.min(50) as i64).saturating_mul(10));
                    score = score.saturating_sub((stats.backend_error_count.min(50) as i64).saturating_mul(400));
                    score = score.saturating_sub((stats.timeout_count.min(50) as i64).saturating_mul(150));
                    score = score.saturating_sub((stats.unknown_count.min(50) as i64).saturating_mul(30));

                    if stats.total_queries > 0 {
                        let avg_ms = (stats.total_elapsed.as_millis() / u128::from(stats.total_queries)).min(200);
                        score = score.saturating_sub(avg_ms as i64);
                    }
                }

                (name, score, index)
            })
            .collect();

        scored.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2)));
        scored.into_iter().map(|(name, _, _)| name).collect()
    }

    fn should_preempt(&self, query: &SolverQuery, elapsed: Duration) -> bool {
        elapsed > self.preempt_threshold || elapsed >= query.timeout()
    }

    fn record_outcome(&self, backend: &'static str, outcome: SolverOutcomeKind, elapsed: Duration) {
        InMemoryPortfolioRouter::record_outcome(self, backend, outcome, elapsed);
    }
}

pub struct BatchSolver {
    backends: Vec<Box<dyn SolverBackend>>,
    router: Box<dyn SolverRouter>,
    cross_check: CrossCheckPolicy,
    cross_checks_performed: u64,
    cross_check_disagreements: u64,
}

impl BatchSolver {
    pub fn new(backends: Vec<Box<dyn SolverBackend>>, router: Box<dyn SolverRouter>) -> Self {
        Self {
            backends,
            router,
            cross_check: CrossCheckPolicy::default(),
            cross_checks_performed: 0,
            cross_check_disagreements: 0,
        }
    }

    pub fn with_cross_check(mut self, cross_check: CrossCheckPolicy) -> Self {
        self.cross_check = cross_check;
        self
    }

    pub fn set_cross_check_policy(&mut self, cross_check: CrossCheckPolicy) {
        self.cross_check = cross_check;
    }

    pub fn cross_check_policy(&self) -> &CrossCheckPolicy {
        &self.cross_check
    }

    pub fn cross_checks_performed(&self) -> u64 {
        self.cross_checks_performed
    }

    pub fn cross_check_disagreements(&self) -> u64 {
        self.cross_check_disagreements
    }

    pub fn solve_query(&mut self, query: &SolverQuery) -> SolverResult {
        if let Some(backend) = self.backends.first_mut() {
            let name = backend.name();
            let result = backend.solve(query);
            self.router.record_outcome(name, result.outcome, result.elapsed);
            return result;
        }
        SolverResult {
            outcome: SolverOutcomeKind::BackendError,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed: Duration::ZERO,
        }
    }

    pub fn solve_with_fallback(&mut self, query: &SolverQuery) -> SolverResult {
        self.solve_fallback_internal(query, None)
    }

    pub fn solve_with_timeout(&mut self, query: &SolverQuery, timeout: Duration) -> SolverResult {
        let start = Instant::now();
        let cancellation = CancellationToken::default();
        let finished = Arc::new(AtomicBool::new(false));

        let finished_watcher = Arc::clone(&finished);
        let cancellation_watcher = cancellation.clone();
        let watcher = std::thread::spawn(move || {
            let sleep_step = Duration::from_millis(1).min(timeout);
            let timer_start = Instant::now();
            while timer_start.elapsed() < timeout {
                if finished_watcher.load(Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(sleep_step);
            }
            if !finished_watcher.load(Ordering::Relaxed) {
                cancellation_watcher.cancel();
            }
        });

        let result = self.solve_fallback_internal(query, Some(&cancellation));
        finished.store(true, Ordering::Relaxed);
        let _ = watcher.join();

        let elapsed = start.elapsed();
        if elapsed >= timeout || cancellation.is_cancelled() || result.outcome == SolverOutcomeKind::Timeout {
            SolverResult {
                outcome: SolverOutcomeKind::Timeout,
                model: Vec::new(),
                unsat_core: Vec::new(),
                elapsed,
            }
        } else {
            result
        }
    }

    fn solve_fallback_internal(
        &mut self,
        query: &SolverQuery,
        cancellation: Option<&CancellationToken>,
    ) -> SolverResult {
        let ranked = self.router.rank_backends(query);

        // Check cross-check policy if we have at least 2 backends
        if self.cross_check.should_cross_check(query) && self.backends.len() >= 2 {
            self.cross_checks_performed = self.cross_checks_performed.saturating_add(1);

            let mut first_idx = None;
            let mut second_idx = None;
            for name in &ranked {
                if let Some(pos) = self.backends.iter().position(|b| b.name() == *name) {
                    if first_idx.is_none() {
                        first_idx = Some(pos);
                    } else if second_idx.is_none() && Some(pos) != first_idx {
                        second_idx = Some(pos);
                        break;
                    }
                }
            }
            if first_idx.is_none() && !self.backends.is_empty() {
                first_idx = Some(0);
            }
            if second_idx.is_none() && self.backends.len() > 1 {
                second_idx = Some(if first_idx == Some(0) { 1 } else { 0 });
            }

            if let (Some(idx1), Some(idx2)) = (first_idx, second_idx) {
                let (name1, res1) = {
                    let b1 = &mut self.backends[idx1];
                    let name = b1.name();
                    let res = if let Some(token) = cancellation
                        && let Some(cancellable) = b1.as_cancellable_mut()
                    {
                        cancellable.solve_cancellable(query, token)
                    } else {
                        b1.solve(query)
                    };
                    (name, res)
                };
                self.router.record_outcome(name1, res1.outcome, res1.elapsed);

                let (name2, res2) = {
                    let b2 = &mut self.backends[idx2];
                    let name = b2.name();
                    let res = if let Some(token) = cancellation
                        && let Some(cancellable) = b2.as_cancellable_mut()
                    {
                        cancellable.solve_cancellable(query, token)
                    } else {
                        b2.solve(query)
                    };
                    (name, res)
                };
                self.router.record_outcome(name2, res2.outcome, res2.elapsed);

                let disagreement = res1.outcome != res2.outcome;
                if disagreement {
                    self.cross_check_disagreements = self.cross_check_disagreements.saturating_add(1);
                    eprintln!(
                        "[WARN] solver cross-check disagreement: backend '{}' outcome {:?} != backend '{}' outcome {:?}",
                        name1, res1.outcome, name2, res2.outcome
                    );
                    // Prefer Z3 result if one of the backends is z3
                    if name1 == "z3" {
                        return res1;
                    }
                    if name2 == "z3" {
                        return res2;
                    }
                    // Otherwise prefer non-error result
                    if res1.outcome == SolverOutcomeKind::BackendError
                        && res2.outcome != SolverOutcomeKind::BackendError
                    {
                        return res2;
                    }
                }
                return res1;
            }
        }

        for name in ranked {
            if let Some(backend) = self.backends.iter_mut().find(|backend| backend.name() == name) {
                let result = if let Some(token) = cancellation
                    && let Some(cancellable) = backend.as_cancellable_mut()
                {
                    cancellable.solve_cancellable(query, token)
                } else {
                    backend.solve(query)
                };
                self.router.record_outcome(name, result.outcome, result.elapsed);
                if result.outcome != SolverOutcomeKind::BackendError {
                    return result;
                }
            }
        }

        SolverResult {
            outcome: SolverOutcomeKind::BackendError,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed: Duration::ZERO,
        }
    }

    pub fn solve_batch_parallel(&mut self, queries: &[SolverQuery]) -> Vec<SolverResult> {
        queries.iter().map(|query| self.solve_query(query)).collect()
    }

    pub fn solve_with_cache(
        &mut self,
        query: &SolverQuery,
        cache: &InMemorySolverCache,
    ) -> Result<(Arc<SolverResult>, bool), SolverCacheError> {
        if let Some(cached) = cache.lookup(query)? {
            return Ok((cached, true));
        }
        let result = self.solve_query(query);
        cache.insert(query, result.clone())?;
        Ok((Arc::new(result), false))
    }
}

/// `BatchSolver` is usable anywhere a `SolverBackend` is expected, so
/// execution-plane callers (for example the runtime's branch solver) get
/// portfolio routing and fallback without depending on the router directly.
impl SolverBackend for BatchSolver {
    fn name(&self) -> &'static str {
        "batch"
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        self.solve_with_fallback(query)
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve_with_fallback(query)).collect()
    }
}

// ---------------------------------------------------------------------------
// Caching backend wrapper with UNSAT-core reuse
// ---------------------------------------------------------------------------

/// A [`SolverBackend`] wrapper adding exact query reuse and UNSAT-core reuse.
///
/// Exact reuse: a solved query's canonical key maps to its `Sat`/`Unsat`
/// result in the shared [`InMemorySolverCache`] — identical queries (same
/// constraint slice, predicate, profile, canonicalization version) hit
/// without a solver call.
///
/// UNSAT-core reuse: when a backend reports an unsatisfiable core — the
/// minimal conflicting constraint set — its key-set is indexed. A later
/// query whose constraint+predicate keys *contain* a recorded core is
/// unsatisfiable by superset and returns `Unsat` without a solver call.
/// (Backends that don't extract cores simply never populate the index; the
/// Z3 FFI's core extraction is future work.)
///
/// Alpha-equivalence reuse (optional, [`Self::with_alpha_reuse`]): the
/// cache's alpha index proposes results from alpha-equivalent queries —
/// identical modulo symbol renaming. By default every proposal is confirmed
/// by an exact backend solve before it is trusted (confirmations and
/// contradictions are counted on the cache); answering directly from an
/// unconfirmed proposal requires the experimental
/// `AlphaReuseConfig::suppress_without_confirmation` flag and stays off by
/// default.
pub struct CachingSolverBackend {
    inner: Box<dyn SolverBackend>,
    cache: Arc<InMemorySolverCache>,
    unsat_cores: Mutex<Vec<BTreeSet<DependencyKey>>>,
    alpha: Option<AlphaReuseEngine>,
}

/// Reader + policy driving the alpha tier of [`CachingSolverBackend`].
struct AlphaReuseEngine {
    reader: Arc<dyn ExprReader>,
    config: AlphaReuseConfig,
}

impl CachingSolverBackend {
    /// Wraps `inner` with the shared `cache`.
    pub fn new(inner: Box<dyn SolverBackend>, cache: Arc<InMemorySolverCache>) -> Self {
        Self {
            inner,
            cache,
            unsat_cores: Mutex::new(Vec::new()),
            alpha: None,
        }
    }

    /// Wraps `inner` with the shared `cache` and the alpha-equivalence
    /// experiment enabled (see [`AlphaReuseConfig`]).
    pub fn with_alpha_reuse(
        inner: Box<dyn SolverBackend>,
        cache: Arc<InMemorySolverCache>,
        reader: Arc<dyn ExprReader>,
        config: AlphaReuseConfig,
    ) -> Self {
        Self {
            alpha: Some(AlphaReuseEngine { reader, config }),
            ..Self::new(inner, cache)
        }
    }

    /// The active alpha configuration, if the tier is enabled.
    pub fn alpha_config(&self) -> Option<AlphaReuseConfig> {
        self.alpha.as_ref().map(|engine| engine.config)
    }

    /// Number of UNSAT cores indexed so far (instrumentation).
    pub fn indexed_core_count(&self) -> usize {
        self.unsat_cores.lock().map(|cores| cores.len()).unwrap_or(0)
    }

    /// The query's dependency-key set: constraint keys plus the predicate key.
    fn query_keys(query: &SolverQuery) -> BTreeSet<DependencyKey> {
        let mut keys: BTreeSet<DependencyKey> = query.constraint_keys().iter().copied().collect();
        keys.insert(query.predicate_key());
        keys
    }

    /// Result borrowed from the cache/core index (avoids double lookup).
    fn cached_result(&self, query: &SolverQuery) -> Option<SolverResult> {
        if let Ok(Some(result)) = self.cache.lookup(query) {
            return Some(SolverResult {
                outcome: result.outcome,
                model: result.model.clone(),
                unsat_core: result.unsat_core.clone(),
                elapsed: Duration::ZERO,
            });
        }
        let keys = Self::query_keys(query);
        let cores = self.unsat_cores.lock().ok()?;
        for core in cores.iter() {
            if core.is_subset(&keys) {
                return Some(SolverResult {
                    outcome: SolverOutcomeKind::Unsat,
                    model: Vec::new(),
                    unsat_core: Vec::new(),
                    elapsed: Duration::ZERO,
                });
            }
        }
        None
    }

    /// Indexes a reported UNSAT core for superset reuse.
    fn index_unsat_core(&self, query: &SolverQuery, result: &SolverResult) {
        if result.outcome != SolverOutcomeKind::Unsat || result.unsat_core.is_empty() {
            return;
        }
        let core_keys: Option<BTreeSet<DependencyKey>> = result
            .unsat_core
            .iter()
            .map(|id| {
                query
                    .constraint_expressions()
                    .iter()
                    .find(|(constraint_id, _)| constraint_id == id)
                    .and_then(|_| {
                        query
                            .constraint_keys()
                            .get(query.constraint_expressions().iter().position(|(cid, _)| cid == id)?)
                    })
                    .copied()
            })
            .collect();
        if let Some(core_keys) = core_keys
            && let Ok(mut cores) = self.unsat_cores.lock()
        {
            cores.push(core_keys);
        }
    }

    /// Outcome-only view of a result reused across a symbol renaming: the
    /// model and unsat core are keyed by the *other* query's symbol and
    /// constraint identities and must not leak.
    fn renaming_reuse_result(outcome: SolverOutcomeKind) -> SolverResult {
        SolverResult {
            outcome,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed: Duration::ZERO,
        }
    }
}

impl SolverBackend for CachingSolverBackend {
    fn name(&self) -> &'static str {
        self.inner.name()
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        if let Some(result) = self.cached_result(query) {
            return result;
        }
        let query_alpha = self
            .alpha
            .as_ref()
            .filter(|engine| engine.config.enabled)
            .and_then(|engine| alpha_key(engine.reader.as_ref(), query));
        if let Some(alpha) = query_alpha
            && let Ok(candidates) = self.cache.propose_alpha(alpha)
            && let Some((_, proposed)) = candidates.first()
        {
            if self
                .alpha
                .as_ref()
                .is_some_and(|engine| engine.config.suppress_without_confirmation)
            {
                // EXPERIMENTAL (flag defaults to off): answer without the
                // confirming solve. A poisoned index would answer wrongly.
                self.cache.record_alpha_suppressed_reuse();
                return Self::renaming_reuse_result(proposed.outcome);
            }
            // Validation mode: the alpha hit MUST be confirmed by an exact
            // solve before it is trusted. The exact answer is what callers
            // see either way; the counters record whether the alpha tier
            // would have been right.
            let result = self.inner.solve(query);
            self.index_unsat_core(query, &result);
            if result.outcome == proposed.outcome {
                self.cache.record_alpha_confirmation();
            } else {
                self.cache.record_alpha_contradiction();
                eprintln!(
                    "[WARN] alpha-reuse contradiction: proposal {:?} != exact {:?} for canonical key {:?}",
                    proposed.outcome,
                    result.outcome,
                    query.canonical_key()
                );
            }
            let _ = self.cache.insert_with_alpha(query, Some(alpha), result.clone());
            return result;
        }
        let result = self.inner.solve(query);
        self.index_unsat_core(query, &result);
        let _ = self.cache.insert_with_alpha(query, query_alpha, result.clone());
        result
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve(query)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_expr::{ExprArena, ShardedExprArena};

    fn constraint(id: u64, byte: u8) -> CanonicalConstraint {
        CanonicalConstraint {
            id: ConstraintId(id),
            key: DependencyKey([byte; 32]),
            expr: ExprId(u32::try_from(id).unwrap_or(0)),
        }
    }

    fn query(constraints: &[CanonicalConstraint]) -> Result<SolverQuery, SolverQueryError> {
        SolverQuery::canonical(
            SolverQueryId(1),
            constraints,
            ExprId(2),
            DependencyKey([3; 32]),
            TargetProfileId(4),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(1),
        )
    }

    fn result(outcome: SolverOutcomeKind) -> SolverResult {
        SolverResult {
            outcome,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed: Duration::from_millis(5),
        }
    }

    #[test]
    fn conjunction_order_does_not_change_canonical_identity() -> Result<(), SolverQueryError> {
        let first = query(&[constraint(1, 10), constraint(2, 20)])?;
        let reordered = query(&[constraint(2, 20), constraint(1, 10)])?;

        assert_eq!(first.canonical_key, reordered.canonical_key);
        assert_ne!(first.path_constraints, reordered.path_constraints);
        Ok(())
    }

    #[test]
    fn exact_cache_reuses_only_stable_outcomes() -> Result<(), SolverCacheError> {
        let query = query(&[constraint(1, 10)]).map_err(SolverCacheError::InvalidQuery)?;
        let cache = InMemorySolverCache::default();

        assert_eq!(cache.lookup(&query)?, None);
        assert_eq!(
            cache.insert(&query, result(SolverOutcomeKind::Timeout))?,
            CacheAdmission::RejectedTransient
        );
        assert_eq!(cache.lookup(&query)?, None);
        assert_eq!(
            cache.insert(&query, result(SolverOutcomeKind::Unsat))?,
            CacheAdmission::Stored
        );
        let cached = cache.lookup(&query)?;
        assert!(cached.is_some());
        if let Some(cached) = cached {
            assert_eq!(*cached, result(SolverOutcomeKind::Unsat));
        }
        assert_eq!(
            cache.stats()?,
            SolverCacheStats {
                hits: 1,
                misses: 2,
                entries: 1,
                stored_bytes: 96,
                ..SolverCacheStats::default()
            }
        );
        Ok(())
    }

    #[test]
    fn tampered_identity_fails_closed() -> Result<(), SolverCacheError> {
        let mut query = query(&[]).map_err(SolverCacheError::InvalidQuery)?;
        query.canonical_key = DependencyKey([0xff; 32]);
        let cache = InMemorySolverCache::default();

        assert_eq!(
            cache.lookup(&query),
            Err(SolverCacheError::InvalidQuery(
                SolverQueryError::CanonicalIdentityMismatch
            ))
        );
        Ok(())
    }

    #[test]
    fn cancellation_token_is_shared() {
        let first = CancellationToken::default();
        let second = first.clone();

        assert!(!second.is_cancelled());
        first.cancel();
        assert!(second.is_cancelled());
    }

    #[test]
    fn mock_solver_backend_returns_configured_outcome() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let mut backend = MockSolverBackend::new("mock-sat", SolverOutcomeKind::Sat);
        let result = backend.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        assert!(result.model.is_empty());
        assert!(result.unsat_core.is_empty());
        assert_eq!(result.elapsed, Duration::ZERO);
        assert_eq!(backend.name(), "mock-sat");
        Ok(())
    }

    #[test]
    fn mock_solver_backend_solve_batch_returns_results_for_all_queries() -> Result<(), SolverQueryError> {
        let first = query(&[constraint(1, 10)])?;
        let second = query(&[constraint(2, 20)])?;
        let mut backend = MockSolverBackend::new("mock-unsat", SolverOutcomeKind::Unsat);
        let results = backend.solve_batch(&[], &[first, second]);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].outcome, SolverOutcomeKind::Unsat);
        assert_eq!(results[1].outcome, SolverOutcomeKind::Unsat);
        Ok(())
    }

    #[test]
    fn portfolio_router_ranks_backends_in_order() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let router = InMemoryPortfolioRouter::new(vec!["z3", "cvc5", "boolector"], Duration::from_secs(30));
        let ranked = router.rank_backends(&query);
        assert_eq!(ranked, vec!["z3", "cvc5", "boolector"]);
        Ok(())
    }

    #[test]
    fn portfolio_router_should_preempt_returns_true_past_threshold() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let router = InMemoryPortfolioRouter::new(vec!["z3"], Duration::from_millis(100));
        assert!(router.should_preempt(&query, Duration::from_millis(200)));
        Ok(())
    }

    #[test]
    fn portfolio_router_should_preempt_returns_false_under_threshold() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let router = InMemoryPortfolioRouter::new(vec!["z3"], Duration::from_millis(100));
        assert!(!router.should_preempt(&query, Duration::from_millis(50)));
        Ok(())
    }

    #[test]
    fn portfolio_router_default_has_empty_backend_list() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let router = InMemoryPortfolioRouter::default();
        let ranked = router.rank_backends(&query);
        assert!(ranked.is_empty());
        Ok(())
    }

    #[test]
    fn batch_solver_solve_query_routes_to_first_backend() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let backends: Vec<Box<dyn SolverBackend>> = vec![
            Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::Sat)),
            Box::new(MockSolverBackend::new("secondary", SolverOutcomeKind::Unsat)),
        ];
        let router = Box::new(InMemoryPortfolioRouter::new(
            vec!["primary", "secondary"],
            Duration::from_secs(30),
        ));
        let mut solver = BatchSolver::new(backends, router);
        let result = solver.solve_query(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        Ok(())
    }

    #[test]
    fn batch_solver_solve_with_fallback_tries_second_backend_if_first_errors() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let backends: Vec<Box<dyn SolverBackend>> = vec![
            Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::BackendError)),
            Box::new(MockSolverBackend::new("secondary", SolverOutcomeKind::Sat)),
        ];
        let router = Box::new(InMemoryPortfolioRouter::new(
            vec!["primary", "secondary"],
            Duration::from_secs(30),
        ));
        let mut solver = BatchSolver::new(backends, router);
        let result = solver.solve_with_fallback(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        Ok(())
    }

    #[test]
    fn batch_solver_solve_with_fallback_returns_first_non_error_result() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let backends: Vec<Box<dyn SolverBackend>> = vec![
            Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::Unsat)),
            Box::new(MockSolverBackend::new("secondary", SolverOutcomeKind::Sat)),
        ];
        let router = Box::new(InMemoryPortfolioRouter::new(
            vec!["primary", "secondary"],
            Duration::from_secs(30),
        ));
        let mut solver = BatchSolver::new(backends, router);
        let result = solver.solve_with_fallback(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Unsat);
        Ok(())
    }

    #[test]
    fn batch_solver_is_usable_as_a_solver_backend() -> Result<(), SolverQueryError> {
        let query = query(&[constraint(1, 10)])?;
        let backends: Vec<Box<dyn SolverBackend>> = vec![
            Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::BackendError)),
            Box::new(MockSolverBackend::new("secondary", SolverOutcomeKind::Sat)),
        ];
        let router = Box::new(InMemoryPortfolioRouter::new(
            vec!["primary", "secondary"],
            Duration::from_secs(30),
        ));
        let mut solver = BatchSolver::new(backends, router);

        // The trait path must behave like `solve_with_fallback` so callers
        // that only know `SolverBackend` get portfolio routing.
        let backend: &mut dyn SolverBackend = &mut solver;
        assert_eq!(backend.name(), "batch");
        assert_eq!(backend.solve(&query).outcome, SolverOutcomeKind::Sat);

        let results = backend.solve_batch(&[], &[query]);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].outcome, SolverOutcomeKind::Sat);
        Ok(())
    }

    #[test]
    fn batch_solver_solve_batch_parallel_returns_results_for_all() -> Result<(), SolverQueryError> {
        let first = query(&[constraint(1, 10)])?;
        let second = query(&[constraint(2, 20)])?;
        let third = query(&[constraint(3, 30)])?;
        let backends: Vec<Box<dyn SolverBackend>> =
            vec![Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::Sat))];
        let router = Box::new(InMemoryPortfolioRouter::new(vec!["primary"], Duration::from_secs(30)));
        let mut solver = BatchSolver::new(backends, router);
        let results = solver.solve_batch_parallel(&[first, second, third]);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].outcome, SolverOutcomeKind::Sat);
        assert_eq!(results[1].outcome, SolverOutcomeKind::Sat);
        assert_eq!(results[2].outcome, SolverOutcomeKind::Sat);
        Ok(())
    }

    #[test]
    fn batch_solver_solve_with_cache_returns_cached_result_on_hit() -> Result<(), SolverCacheError> {
        let query = query(&[constraint(1, 10)]).map_err(SolverCacheError::InvalidQuery)?;
        let cache = InMemorySolverCache::default();
        assert!(cache.insert(&query, result(SolverOutcomeKind::Sat)).is_ok());
        let backends: Vec<Box<dyn SolverBackend>> =
            vec![Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::Unsat))];
        let router = Box::new(InMemoryPortfolioRouter::new(vec!["primary"], Duration::from_secs(30)));
        let mut solver = BatchSolver::new(backends, router);
        let outcome = solver.solve_with_cache(&query, &cache);
        assert!(outcome.is_ok());
        if let Ok((solver_result, hit)) = outcome {
            assert!(hit);
            assert_eq!(solver_result.outcome, SolverOutcomeKind::Sat);
        }
        Ok(())
    }

    #[test]
    fn batch_solver_solve_with_cache_solves_and_stores_on_miss() -> Result<(), SolverCacheError> {
        let query = query(&[constraint(1, 10)]).map_err(SolverCacheError::InvalidQuery)?;
        let cache = InMemorySolverCache::default();
        let backends: Vec<Box<dyn SolverBackend>> =
            vec![Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::Sat))];
        let router = Box::new(InMemoryPortfolioRouter::new(vec!["primary"], Duration::from_secs(30)));
        let mut solver = BatchSolver::new(backends, router);
        let outcome = solver.solve_with_cache(&query, &cache);
        assert!(outcome.is_ok());
        if let Ok((solver_result, hit)) = outcome {
            assert!(!hit);
            assert_eq!(solver_result.outcome, SolverOutcomeKind::Sat);
        }
        let lookup = cache.lookup(&query)?;
        assert!(lookup.is_some());
        if let Some(cached) = lookup {
            assert_eq!(cached.outcome, SolverOutcomeKind::Sat);
        }
        Ok(())
    }

    #[test]
    fn batch_solver_solve_with_cache_returns_true_on_hit_false_on_miss() -> Result<(), SolverCacheError> {
        let query = query(&[constraint(1, 10)]).map_err(SolverCacheError::InvalidQuery)?;
        let cache = InMemorySolverCache::default();
        let backends: Vec<Box<dyn SolverBackend>> =
            vec![Box::new(MockSolverBackend::new("primary", SolverOutcomeKind::Sat))];
        let router = Box::new(InMemoryPortfolioRouter::new(vec!["primary"], Duration::from_secs(30)));
        let mut solver = BatchSolver::new(backends, router);

        let miss_outcome = solver.solve_with_cache(&query, &cache);
        assert!(miss_outcome.is_ok());
        if let Ok((_, hit)) = miss_outcome {
            assert!(!hit);
        }

        let hit_outcome = solver.solve_with_cache(&query, &cache);
        assert!(hit_outcome.is_ok());
        if let Ok((_, hit)) = hit_outcome {
            assert!(hit);
        }
        Ok(())
    }

    #[test]
    fn sharded_cache_distributes_entries() -> Result<(), SolverCacheError> {
        let cache = InMemorySolverCache::default();
        let mut expected = [0u64; SHARD_COUNT];
        for i in 1..=32u64 {
            let q = query(&[constraint(i, (i as u8).wrapping_mul(17))]).map_err(SolverCacheError::InvalidQuery)?;
            let idx = usize::from(q.canonical_key().0[0]) % SHARD_COUNT;
            cache.insert(&q, result(SolverOutcomeKind::Sat))?;
            expected[idx] += 1;
        }
        let lens = cache.shard_lens()?;
        assert_eq!(lens, expected.to_vec());
        let occupied = expected.iter().filter(|&&count| count > 0).count();
        assert!(occupied > 1, "entries should span multiple shards, got {occupied}");
        Ok(())
    }

    #[test]
    fn sharded_cache_lookup_returns_arc() -> Result<(), SolverCacheError> {
        let query = query(&[constraint(1, 10)]).map_err(SolverCacheError::InvalidQuery)?;
        let cache = InMemorySolverCache::default();
        cache.insert(&query, result(SolverOutcomeKind::Unsat))?;
        let cached = cache.lookup(&query)?;
        assert!(cached.is_some());
        if let Some(cached) = cached {
            assert_eq!(*cached, result(SolverOutcomeKind::Unsat));
            let cloned: Arc<SolverResult> = Arc::clone(&cached);
            assert_eq!(*cloned, *cached);
        }
        Ok(())
    }

    #[test]
    fn sharded_cache_stats_aggregate_across_shards() -> Result<(), SolverCacheError> {
        let cache = InMemorySolverCache::default();
        let mut total_entries = 0u64;
        for i in 1..=16u64 {
            let q = query(&[constraint(i, (i as u8).wrapping_mul(13))]).map_err(SolverCacheError::InvalidQuery)?;
            cache.insert(&q, result(SolverOutcomeKind::Sat))?;
            total_entries += 1;
        }
        let stats = cache.stats()?;
        assert_eq!(stats.entries, total_entries);
        let lens = cache.shard_lens()?;
        let summed: u64 = lens.iter().sum();
        assert_eq!(summed, total_entries);
        Ok(())
    }

    /// Exact query reuse: the second identical query is a cache hit — the
    /// inner backend is invoked once.
    #[test]
    fn caching_backend_reuses_exact_queries() -> Result<(), Box<dyn std::error::Error>> {
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = CountingBackend {
            outcome: SolverOutcomeKind::Sat,
            calls: Arc::clone(&calls),
        };
        let mut backend = CachingSolverBackend::new(Box::new(inner), Arc::clone(&cache));
        let query = query_with_key([1; 32], [2; 32])?;
        let first = backend.solve(&query);
        let second = backend.solve(&query);
        assert_eq!(first.outcome, SolverOutcomeKind::Sat);
        assert_eq!(second.outcome, SolverOutcomeKind::Sat);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "second query hit the cache");
        let stats = cache.stats()?;
        assert_eq!(stats.hits, 1);
        Ok(())
    }

    /// UNSAT-core reuse: a query whose constraint keys contain a recorded
    /// core returns Unsat without invoking the backend.
    #[test]
    fn caching_backend_reuses_unsat_cores() -> Result<(), Box<dyn std::error::Error>> {
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = CoreReportingBackend {
            calls: Arc::clone(&calls),
        };
        let mut backend = CachingSolverBackend::new(Box::new(inner), Arc::clone(&cache));

        // First query: backend reports Unsat with core {ConstraintId(0)}.
        let first = backend.solve(&query_with_key([7; 32], [8; 32])?);
        assert_eq!(first.outcome, SolverOutcomeKind::Unsat);
        assert_eq!(backend.indexed_core_count(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // Second query: same constraint set (superset of the core) — early
        // Unsat from the index, no backend call. NOTE: the canonical key
        // differs (different predicate key), so this is not an exact-reuse
        // hit — it exercises the core-subset path.
        let second = backend.solve(&query_with_key([7; 32], [9; 32])?);
        assert_eq!(second.outcome, SolverOutcomeKind::Unsat);
        assert_eq!(calls.load(Ordering::Relaxed), 1, "core reuse skipped the backend");
        Ok(())
    }

    struct CountingBackend {
        outcome: SolverOutcomeKind,
        calls: Arc<AtomicU64>,
    }

    impl SolverBackend for CountingBackend {
        fn name(&self) -> &'static str {
            "counting"
        }
        fn solve(&mut self, _query: &SolverQuery) -> SolverResult {
            self.calls.fetch_add(1, Ordering::Relaxed);
            SolverResult {
                outcome: self.outcome,
                model: Vec::new(),
                unsat_core: Vec::new(),
                elapsed: Duration::ZERO,
            }
        }
        fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
            predicates.iter().map(|q| self.solve(q)).collect()
        }
    }

    struct CoreReportingBackend {
        calls: Arc<AtomicU64>,
    }

    impl SolverBackend for CoreReportingBackend {
        fn name(&self) -> &'static str {
            "core-reporter"
        }
        fn solve(&mut self, _query: &SolverQuery) -> SolverResult {
            self.calls.fetch_add(1, Ordering::Relaxed);
            SolverResult {
                outcome: SolverOutcomeKind::Unsat,
                model: Vec::new(),
                unsat_core: vec![ConstraintId(0)],
                elapsed: Duration::ZERO,
            }
        }
        fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
            predicates.iter().map(|q| self.solve(q)).collect()
        }
    }

    fn query_with_key(
        constraint_key: [u8; 32],
        predicate_key: [u8; 32],
    ) -> Result<SolverQuery, Box<dyn std::error::Error>> {
        let constraint = CanonicalConstraint {
            id: ConstraintId(0),
            key: DependencyKey(constraint_key),
            expr: ExprId(0),
        };
        SolverQuery::canonical(
            SolverQueryId(1),
            &[constraint],
            ExprId(0),
            DependencyKey(predicate_key),
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )
        .map_err(|e| -> Box<dyn std::error::Error> { format!("{e:?}").into() })
    }

    // -----------------------------------------------------------------------
    // Bounded, value-aware admission
    // -----------------------------------------------------------------------

    /// Deterministic distinct queries that all land in the same cache shard,
    /// with pairwise sketch-probe-disjoint canonical keys so admission tests
    /// reason about exact seen counts (no counter collisions).
    fn same_shard_probe_disjoint_queries(count: usize) -> Result<Vec<SolverQuery>, Box<dyn std::error::Error>> {
        let mut buckets: Vec<Vec<SolverQuery>> = vec![Vec::new(); SHARD_COUNT];
        let mut used_probes: Vec<(usize, usize)> = Vec::new();
        let mut seed: u64 = 1;
        while buckets.iter().map(Vec::len).max().unwrap_or(0) < count {
            if seed > 200_000 {
                return Err("same-shard query search did not converge".into());
            }
            // Full-width constraint keys (a repeated byte gives only 256
            // distinct canonical keys — not enough for a 44-key shard).
            let mut hasher = Sha256::new();
            hasher.update(seed.to_le_bytes());
            let key: [u8; 32] = hasher.finalize().into();
            let varied = CanonicalConstraint {
                id: ConstraintId(seed),
                key: DependencyKey(key),
                expr: ExprId(u32::try_from(seed).unwrap_or(0)),
            };
            let q = query(&[varied]).map_err(|e| -> Box<dyn std::error::Error> { format!("{e:?}").into() })?;
            let index = shard_index(&q.canonical_key());
            let probes = SeenSketch::probes(&q.canonical_key());
            if !buckets[index]
                .iter()
                .any(|other| other.canonical_key() == q.canonical_key())
                && !used_probes.contains(&probes)
            {
                used_probes.push(probes);
                buckets[index].push(q);
            }
            seed += 1;
        }
        let fullest = buckets
            .into_iter()
            .max_by_key(|bucket| bucket.len())
            .unwrap_or_default();
        Ok(fullest)
    }

    #[test]
    fn admission_never_admits_transient_outcomes() -> Result<(), SolverCacheError> {
        let q = query(&[constraint(1, 10)]).map_err(SolverCacheError::InvalidQuery)?;
        let cache = InMemorySolverCache::default();
        for outcome in [
            SolverOutcomeKind::Unknown,
            SolverOutcomeKind::Timeout,
            SolverOutcomeKind::ResourceLimit,
            SolverOutcomeKind::BackendError,
        ] {
            assert_eq!(cache.insert(&q, result(outcome))?, CacheAdmission::RejectedTransient);
            assert_eq!(cache.lookup(&q)?, None, "{outcome:?} must never be cached");
        }
        let stats = cache.stats()?;
        assert_eq!(stats.entries, 0);
        assert_eq!(stats.rejected_capacity + stats.rejected_budget, 0);
        Ok(())
    }

    #[test]
    fn repeated_keys_win_admission_under_shard_pressure() -> Result<(), Box<dyn std::error::Error>> {
        let queries = same_shard_probe_disjoint_queries(2)?;
        let [hot, cold] = [&queries[0], &queries[1]];
        let cache = InMemorySolverCache::with_policy(CacheAdmissionPolicy {
            max_entries_per_shard: 1,
            byte_budget: 1 << 30,
        });

        // First sighting of `hot`: admitted into the empty shard.
        assert_eq!(cache.lookup(hot)?, None);
        assert_eq!(
            cache.insert(hot, result(SolverOutcomeKind::Sat))?,
            CacheAdmission::Stored
        );

        // One-shot `cold`: the shard is full of an equal-score entry, and an
        // equal score does not justify evicting — rejected, observable.
        assert_eq!(cache.lookup(cold)?, None);
        assert_eq!(
            cache.insert(cold, result(SolverOutcomeKind::Unsat))?,
            CacheAdmission::RejectedCapacity
        );

        // Second sighting of `cold`: its estimated reuse value now exceeds
        // the stored one-shot's, so it is admitted and evicts `hot`.
        assert_eq!(cache.lookup(cold)?, None);
        assert_eq!(
            cache.insert(cold, result(SolverOutcomeKind::Unsat))?,
            CacheAdmission::Stored
        );

        let stats = cache.stats()?;
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.rejected_capacity, 1);
        assert_eq!(stats.evictions, 1);
        assert_eq!(cache.lookup(hot)?, None, "evicted key must miss");
        assert!(cache.lookup(cold)?.is_some(), "twice-seen key must hit");
        Ok(())
    }

    #[test]
    fn byte_budget_rejects_what_does_not_fit() -> Result<(), Box<dyn std::error::Error>> {
        let queries = same_shard_probe_disjoint_queries(2)?;
        let [valuable, oversized] = [&queries[0], &queries[1]];
        // Exactly one empty-model entry (estimated at 96 bytes) fits.
        let cache = InMemorySolverCache::with_policy(CacheAdmissionPolicy {
            max_entries_per_shard: 8192,
            byte_budget: 96,
        });

        // `valuable` is asked for twice before admission (score 2).
        assert_eq!(cache.lookup(valuable)?, None);
        assert_eq!(cache.lookup(valuable)?, None);
        assert_eq!(
            cache.insert(valuable, result(SolverOutcomeKind::Sat))?,
            CacheAdmission::Stored
        );

        // `oversized` is a one-shot (score 1): evicting the more valuable
        // entry is not allowed, and 96 + 96 > 96 — rejected on budget.
        assert_eq!(cache.lookup(oversized)?, None);
        assert_eq!(
            cache.insert(oversized, result(SolverOutcomeKind::Unsat))?,
            CacheAdmission::RejectedBudget
        );

        let stats = cache.stats()?;
        assert_eq!(stats.entries, 1);
        assert_eq!(stats.rejected_budget, 1);
        assert_eq!(stats.stored_bytes, 96);
        assert!(cache.lookup(valuable)?.is_some());
        assert_eq!(cache.lookup(oversized)?, None);
        Ok(())
    }

    #[test]
    fn eviction_order_is_deterministic_and_replayable() -> Result<(), Box<dyn std::error::Error>> {
        let queries = same_shard_probe_disjoint_queries(3)?;
        let run = |cache: &InMemorySolverCache| -> Result<Vec<bool>, SolverCacheError> {
            for q in &queries {
                cache.lookup(q)?;
            }
            // The third query is seen twice, so it outranks the one-shot
            // stored under equal scores and evicts the OLDEST of them.
            cache.lookup(&queries[2])?;
            for q in &queries {
                let admission = cache.insert(q, result(SolverOutcomeKind::Sat))?;
                let _ = admission;
            }
            queries.iter().map(|q| Ok(cache.lookup(q)?.is_some())).collect()
        };
        let policy = CacheAdmissionPolicy {
            max_entries_per_shard: 2,
            byte_budget: 1 << 30,
        };
        let first = InMemorySolverCache::with_policy(policy);
        let second = InMemorySolverCache::with_policy(policy);
        let survivors_first = run(&first)?;
        let survivors_second = run(&second)?;
        assert_eq!(survivors_first, survivors_second, "admissions must replay identically");
        assert_eq!(
            survivors_first,
            vec![false, true, true],
            "oldest equal-score entry is evicted"
        );
        assert_eq!(first.stats()?, second.stats()?);
        assert_eq!(first.stats()?.evictions, 1);
        Ok(())
    }

    /// Hit-rate on a repeated-key workload before and after bounding: the
    /// bounded cache must keep the hot keys resident (value-aware admission
    /// rejects the cold flood) and match the unbounded hit count.
    #[test]
    fn value_aware_bounding_preserves_hot_hit_rate() -> Result<(), Box<dyn std::error::Error>> {
        let queries = same_shard_probe_disjoint_queries(44)?;
        let (hot, cold) = queries.split_at(4);
        let workload = |cache: &InMemorySolverCache| -> Result<u64, SolverCacheError> {
            let hits_before = cache.stats()?.hits;
            for _round in 0..6 {
                for q in hot {
                    if cache.lookup(q)?.is_none() {
                        cache.insert(q, result(SolverOutcomeKind::Sat))?;
                    }
                }
            }
            for q in cold {
                if cache.lookup(q)?.is_none() {
                    cache.insert(q, result(SolverOutcomeKind::Sat))?;
                }
            }
            for q in hot {
                let _ = cache.lookup(q)?;
            }
            Ok(cache.stats()?.hits - hits_before)
        };
        let unbounded = InMemorySolverCache::default();
        let unbounded_hits = workload(&unbounded)?;
        let bounded = InMemorySolverCache::with_policy(CacheAdmissionPolicy {
            max_entries_per_shard: 4,
            byte_budget: 1 << 30,
        });
        let bounded_hits = workload(&bounded)?;

        let bounded_stats = bounded.stats()?;
        let total: u64 = 4 * 6 + 40 + 4;
        println!(
            "admission: hit-rate repeated-key workload unbounded {}/{} = {:.2}, bounded(cap 4/shard) {}/{} = {:.2}, rejected {} cold, evicted {}",
            unbounded_hits,
            total,
            unbounded_hits as f64 / total as f64,
            bounded_hits,
            total,
            bounded_hits as f64 / total as f64,
            bounded_stats.rejected_capacity,
            bounded_stats.evictions
        );
        assert_eq!(bounded_hits, unbounded_hits, "hot-key hits must survive bounding");
        assert_eq!(bounded_stats.entries, 4, "cold flood must not be admitted");
        assert_eq!(bounded_stats.rejected_capacity, 40, "every cold one-shot is rejected");
        assert_eq!(bounded_stats.evictions, 0, "no hot entry is evicted");
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Alpha-equivalence tier (Gate C experiment)
    // -----------------------------------------------------------------------

    fn expr_arena() -> Arc<ShardedExprArena> {
        Arc::new(ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1)))
    }

    fn expr_symbol(arena: &ShardedExprArena, sym_id: u64) -> Result<ExprId, Box<dyn std::error::Error>> {
        arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::BitVec(64),
                op: angryier_expr::ExprOp::Symbol,
                operands: Vec::new(),
                immediate: sym_id.to_le_bytes().to_vec(),
            })
            .map_err(Into::into)
    }

    fn expr_const(arena: &ShardedExprArena, width: u16, value: u128) -> Result<ExprId, Box<dyn std::error::Error>> {
        let byte_width = usize::from(width).div_ceil(8);
        let immediate = value.to_le_bytes()[..byte_width].to_vec();
        arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::BitVec(width),
                op: angryier_expr::ExprOp::Constant,
                operands: Vec::new(),
                immediate,
            })
            .map_err(Into::into)
    }

    fn expr_binop(
        arena: &ShardedExprArena,
        op: angryier_expr::ExprOp,
        width: u16,
        left: ExprId,
        right: ExprId,
    ) -> Result<ExprId, Box<dyn std::error::Error>> {
        arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::BitVec(width),
                op,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .map_err(Into::into)
    }

    fn expr_bool_op(
        arena: &ShardedExprArena,
        op: angryier_expr::ExprOp,
        left: ExprId,
        right: ExprId,
    ) -> Result<ExprId, Box<dyn std::error::Error>> {
        arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::Bool,
                op,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .map_err(Into::into)
    }

    fn expr_query(
        arena: &ShardedExprArena,
        predicate: ExprId,
        constraints: &[(u64, ExprId)],
    ) -> Result<SolverQuery, Box<dyn std::error::Error>> {
        let canonical: Vec<_> = constraints
            .iter()
            .map(|(cid, eid)| CanonicalConstraint {
                id: ConstraintId(*cid),
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
            &canonical,
            predicate,
            pred_key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )?)
    }

    /// Family template: `x * y + k == 10` with `x > 2`, `y > 2` — copies
    /// differ by symbol renaming (`symbol_offset`) and constant (`k`).
    fn template_query(
        arena: &ShardedExprArena,
        symbol_offset: u64,
        constant: u128,
    ) -> Result<SolverQuery, Box<dyn std::error::Error>> {
        let x = expr_symbol(arena, 100 + symbol_offset)?;
        let y = expr_symbol(arena, 200 + symbol_offset)?;
        let two = expr_const(arena, 64, 2)?;
        let bound_x = expr_bool_op(arena, angryier_expr::ExprOp::Ult, two, x)?;
        let bound_y = expr_bool_op(arena, angryier_expr::ExprOp::Ult, two, y)?;
        let product = expr_binop(arena, angryier_expr::ExprOp::Mul, 64, x, y)?;
        let sum = expr_binop(
            arena,
            angryier_expr::ExprOp::Add,
            64,
            product,
            expr_const(arena, 64, constant)?,
        )?;
        let ten = expr_const(arena, 64, 10)?;
        let predicate = expr_bool_op(arena, angryier_expr::ExprOp::Eq, sum, ten)?;
        expr_query(arena, predicate, &[(0, bound_x), (1, bound_y)])
    }

    #[test]
    fn alpha_key_ignores_renaming_but_not_structure() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();

        let base = template_query(&arena, 0, 3)?;
        let renamed = template_query(&arena, 5, 3)?;
        assert_ne!(base.canonical_key(), renamed.canonical_key(), "exact keys differ");
        assert_eq!(alpha_key(reader.as_ref(), &base), alpha_key(reader.as_ref(), &renamed));

        // Poisoning cases: constant, operator, symbol multiplicity, width.
        let poisoned_constant = template_query(&arena, 0, 4)?;
        assert_ne!(
            alpha_key(reader.as_ref(), &base),
            alpha_key(reader.as_ref(), &poisoned_constant),
            "different constants must not conflate"
        );

        let x = expr_symbol(&arena, 300)?;
        let y = expr_symbol(&arena, 301)?;
        let four = expr_const(&arena, 64, 4)?;
        let xx = expr_binop(&arena, angryier_expr::ExprOp::Mul, 64, x, x)?;
        let xy = expr_binop(&arena, angryier_expr::ExprOp::Mul, 64, x, y)?;
        let x_plus_y = expr_binop(&arena, angryier_expr::ExprOp::Add, 64, x, y)?;
        let q_xx = expr_query(&arena, expr_bool_op(&arena, angryier_expr::ExprOp::Eq, xx, four)?, &[])?;
        let q_xy = expr_query(&arena, expr_bool_op(&arena, angryier_expr::ExprOp::Eq, xy, four)?, &[])?;
        assert_ne!(
            alpha_key(reader.as_ref(), &q_xx),
            alpha_key(reader.as_ref(), &q_xy),
            "x*x and x*y are not alpha-equivalent"
        );

        let yx = expr_binop(&arena, angryier_expr::ExprOp::Add, 64, y, x)?;
        let q_xy_eq = expr_query(
            &arena,
            expr_bool_op(&arena, angryier_expr::ExprOp::Eq, x_plus_y, four)?,
            &[],
        )?;
        let q_yx_eq = expr_query(&arena, expr_bool_op(&arena, angryier_expr::ExprOp::Eq, yx, four)?, &[])?;
        assert_eq!(
            alpha_key(reader.as_ref(), &q_xy_eq),
            alpha_key(reader.as_ref(), &q_yx_eq),
            "commutative operand order is canonicalized"
        );

        let x32 = expr_symbol(&arena, 302)?;
        // Re-intern as 32-bit by building the same shape with a 32-bit symbol.
        let sym32 = arena.intern(angryier_expr::ExprNode {
            sort: angryier_expr::ExprSort::BitVec(32),
            op: angryier_expr::ExprOp::Symbol,
            operands: Vec::new(),
            immediate: 302u64.to_le_bytes().to_vec(),
        })?;
        let _ = x32;
        let four32 = expr_const(&arena, 32, 4)?;
        let sum32 = expr_binop(&arena, angryier_expr::ExprOp::Add, 32, sym32, sym32)?;
        let q_32 = expr_query(
            &arena,
            expr_bool_op(&arena, angryier_expr::ExprOp::Eq, sum32, four32)?,
            &[],
        )?;
        let sum64 = expr_binop(&arena, angryier_expr::ExprOp::Add, 64, x, x)?;
        let q_64 = expr_query(
            &arena,
            expr_bool_op(&arena, angryier_expr::ExprOp::Eq, sum64, four)?,
            &[],
        )?;
        assert_ne!(
            alpha_key(reader.as_ref(), &q_32),
            alpha_key(reader.as_ref(), &q_64),
            "widths must not conflate"
        );
        Ok(())
    }

    #[test]
    fn alpha_index_proposes_only_admitted_candidates() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let q = template_query(&arena, 0, 3)?;
        let key = alpha_key(reader.as_ref(), &q).ok_or("alpha key")?;
        let cache = InMemorySolverCache::default();

        assert!(cache.propose_alpha(key)?.is_empty(), "nothing indexed yet");
        assert_eq!(
            cache.insert_with_alpha(&q, Some(key), result(SolverOutcomeKind::Sat))?,
            CacheAdmission::Stored
        );
        let proposals = cache.propose_alpha(key)?;
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0].0, q.canonical_key());
        assert_eq!(proposals[0].1.outcome, SolverOutcomeKind::Sat);
        let stats = cache.alpha_stats()?;
        assert_eq!(stats.proposals, 2, "one empty consultation plus one hit");
        assert_eq!(stats.indexed_buckets, 1);
        assert_eq!(stats.indexed_candidates, 1);
        Ok(())
    }

    #[test]
    fn caching_backend_confirms_alpha_hits_with_exact_solve() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = CountingBackend {
            outcome: SolverOutcomeKind::Sat,
            calls: Arc::clone(&calls),
        };
        let mut backend = CachingSolverBackend::with_alpha_reuse(
            Box::new(inner),
            Arc::clone(&cache),
            reader,
            AlphaReuseConfig {
                enabled: true,
                suppress_without_confirmation: false,
            },
        );

        let base = template_query(&arena, 0, 3)?;
        let renamed = template_query(&arena, 9, 3)?;
        assert_eq!(backend.solve(&base).outcome, SolverOutcomeKind::Sat);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // The renamed query alpha-hits, but validation mode still confirms
        // with an exact solve before trusting it.
        let outcome = backend.solve(&renamed);
        assert_eq!(outcome.outcome, SolverOutcomeKind::Sat);
        assert_eq!(
            calls.load(Ordering::Relaxed),
            2,
            "alpha hit was confirmed by an exact solve"
        );

        let stats = cache.alpha_stats()?;
        assert_eq!(stats.proposals, 2, "one empty consultation plus one proposal");
        assert_eq!(stats.confirmations, 1);
        assert_eq!(stats.contradictions, 0);
        assert_eq!(stats.suppressed_reuses, 0);

        // The confirmed query is now exactly cached — no further solves.
        let again = backend.solve(&renamed);
        assert_eq!(again.outcome, SolverOutcomeKind::Sat);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        Ok(())
    }

    /// A disagreeing backend (different true answers for the same alpha
    /// class, i.e. what a poisoned index would look like): the contradiction
    /// is counted and the exact answer is what callers see.
    struct OutcomeByQueryBackend {
        calls: Arc<AtomicU64>,
    }

    impl SolverBackend for OutcomeByQueryBackend {
        fn name(&self) -> &'static str {
            "outcome-by-query"
        }
        fn solve(&mut self, query: &SolverQuery) -> SolverResult {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let outcome = if query.canonical_key().0[31].is_multiple_of(2) {
                SolverOutcomeKind::Sat
            } else {
                SolverOutcomeKind::Unsat
            };
            SolverResult {
                outcome,
                model: Vec::new(),
                unsat_core: Vec::new(),
                elapsed: Duration::ZERO,
            }
        }
        fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
            predicates.iter().map(|q| self.solve(q)).collect()
        }
    }

    #[test]
    fn caching_backend_counts_alpha_contradictions() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = OutcomeByQueryBackend {
            calls: Arc::clone(&calls),
        };
        let mut backend = CachingSolverBackend::with_alpha_reuse(
            Box::new(inner),
            Arc::clone(&cache),
            reader,
            AlphaReuseConfig {
                enabled: true,
                suppress_without_confirmation: false,
            },
        );

        let base = template_query(&arena, 0, 3)?;
        let renamed = template_query(&arena, 9, 3)?;
        let base_outcome = backend.solve(&base).outcome;
        let renamed_outcome = backend.solve(&renamed).outcome;
        assert_eq!(calls.load(Ordering::Relaxed), 2, "both queries solved exactly");

        let stats = cache.alpha_stats()?;
        assert_eq!(stats.proposals, 2, "one empty consultation plus one proposal");
        assert_eq!(stats.contradictions, 1, "the disagreeing proposal is recorded");
        assert_eq!(stats.confirmations, 0);
        // Callers always see the exact backend answer for each query.
        let expected_base = if base.canonical_key().0[31].is_multiple_of(2) {
            SolverOutcomeKind::Sat
        } else {
            SolverOutcomeKind::Unsat
        };
        let expected_renamed = if renamed.canonical_key().0[31].is_multiple_of(2) {
            SolverOutcomeKind::Sat
        } else {
            SolverOutcomeKind::Unsat
        };
        assert_eq!(base_outcome, expected_base);
        assert_eq!(renamed_outcome, expected_renamed);
        assert_ne!(base_outcome, renamed_outcome, "the family genuinely disagrees");
        Ok(())
    }

    #[test]
    fn alpha_reuse_defaults_to_no_suppression() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = CountingBackend {
            outcome: SolverOutcomeKind::Sat,
            calls: Arc::clone(&calls),
        };

        // Default construction: no alpha engine at all.
        let plain = CachingSolverBackend::new(Box::new(inner), Arc::clone(&cache));
        assert_eq!(plain.alpha_config(), None);

        // Default config: alpha disabled — behavior identical to plain.
        let disabled = CachingSolverBackend::with_alpha_reuse(
            Box::new(CountingBackend {
                outcome: SolverOutcomeKind::Sat,
                calls: Arc::clone(&calls),
            }),
            Arc::clone(&cache),
            reader,
            AlphaReuseConfig::default(),
        );
        assert_eq!(
            disabled.alpha_config(),
            Some(AlphaReuseConfig {
                enabled: false,
                suppress_without_confirmation: false
            })
        );
        let base = template_query(&arena, 0, 3)?;
        let renamed = template_query(&arena, 9, 3)?;
        let mut disabled = disabled;
        disabled.solve(&base);
        disabled.solve(&renamed);
        // One call from `plain`, zero for the exactly-cached base, one for
        // the renamed query — the disabled tier consults nothing.
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        let stats = cache.alpha_stats()?;
        assert_eq!(stats.proposals, 0, "disabled tier never consults the index");
        assert_eq!(stats.indexed_buckets, 0);
        Ok(())
    }

    #[test]
    fn suppression_flag_answers_without_solving_when_enabled() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = CountingBackend {
            outcome: SolverOutcomeKind::Sat,
            calls: Arc::clone(&calls),
        };
        let mut backend = CachingSolverBackend::with_alpha_reuse(
            Box::new(inner),
            Arc::clone(&cache),
            reader,
            AlphaReuseConfig {
                enabled: true,
                suppress_without_confirmation: true,
            },
        );

        let base = template_query(&arena, 0, 3)?;
        let renamed = template_query(&arena, 9, 3)?;
        assert_eq!(backend.solve(&base).outcome, SolverOutcomeKind::Sat);
        assert_eq!(calls.load(Ordering::Relaxed), 1);

        // Suppression on: the renamed query is answered from the proposal
        // alone — no second solve, outcome-only result (model dropped).
        let outcome = backend.solve(&renamed);
        assert_eq!(outcome.outcome, SolverOutcomeKind::Sat);
        assert!(outcome.model.is_empty());
        assert_eq!(calls.load(Ordering::Relaxed), 1, "no confirmatory solve happened");
        let stats = cache.alpha_stats()?;
        assert_eq!(stats.suppressed_reuses, 1);
        assert_eq!(stats.confirmations, 0);
        Ok(())
    }

    /// Gate C alpha-equivalence experiment: renamed families must alpha-hit
    /// and confirm; poisoned (constant-mutated) families must never conflate.
    #[test]
    #[ignore = "Gate C alpha-equivalence experiment — run explicitly with --ignored"]
    fn alpha_families_validation_experiment() -> Result<(), Box<dyn std::error::Error>> {
        let arena = expr_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let cache = Arc::new(InMemorySolverCache::default());
        let calls = Arc::new(AtomicU64::new(0));
        let inner = CountingBackend {
            outcome: SolverOutcomeKind::Sat,
            calls: Arc::clone(&calls),
        };
        let mut backend = CachingSolverBackend::with_alpha_reuse(
            Box::new(inner),
            Arc::clone(&cache),
            reader,
            AlphaReuseConfig {
                enabled: true,
                suppress_without_confirmation: false,
            },
        );

        // Family R: 8 copies identical up to symbol renaming.
        let renamed_family: Vec<_> = (0..8u64)
            .map(|offset| template_query(&arena, offset * 7, 3))
            .collect::<Result<_, _>>()?;
        for query in &renamed_family {
            assert_eq!(backend.solve(query).outcome, SolverOutcomeKind::Sat);
        }
        // One solve per family member: the first stores, the rest confirm.
        assert_eq!(calls.load(Ordering::Relaxed), 8);

        // Family P: same shape, one constant mutated per member — must not
        // conflate with R or with each other.
        let poisoned_family: Vec<_> = (0..8u128)
            .map(|member| template_query(&arena, 1000 + u64::try_from(member)?, member + 20))
            .collect::<Result<_, _>>()?;
        let renamed_alpha = alpha_key(arena.as_ref(), renamed_family.first().ok_or("family")?);
        for query in &poisoned_family {
            let key = alpha_key(arena.as_ref(), query).ok_or("alpha key")?;
            assert_ne!(key, renamed_alpha.ok_or("alpha key")?);
            assert_eq!(backend.solve(query).outcome, SolverOutcomeKind::Sat);
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            16,
            "every poisoned member solved exactly"
        );

        let stats = cache.alpha_stats()?;
        println!(
            "GATE-C alpha: family(8 renamed) confirmations={} contradictions={} proposals={} suppressed={} indexed_buckets={}",
            stats.confirmations, stats.contradictions, stats.proposals, stats.suppressed_reuses, stats.indexed_buckets
        );
        assert_eq!(stats.confirmations, 7, "7 renamed copies confirmed the stored result");
        assert_eq!(stats.contradictions, 0, "no poisoned member was conflated");
        assert_eq!(stats.suppressed_reuses, 0, "validation mode never suppresses");
        let stats = cache.stats()?;
        println!(
            "GATE-C alpha: exact cache entries={} hits={} misses={}",
            stats.entries, stats.hits, stats.misses
        );
        Ok(())
    }
}
