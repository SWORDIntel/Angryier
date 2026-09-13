#![forbid(unsafe_code)]

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
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheAdmission {
    Stored,
    RejectedTransient,
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

#[derive(Default)]
pub struct InMemorySolverCache {
    shards: [Mutex<HashMap<DependencyKey, Arc<SolverResult>>>; SHARD_COUNT],
    hits: AtomicU64,
    misses: AtomicU64,
}

fn shard_index(key: &DependencyKey) -> usize {
    usize::from(key.0[0]) % SHARD_COUNT
}

impl InMemorySolverCache {
    pub fn lookup(&self, query: &SolverQuery) -> Result<Option<Arc<SolverResult>>, SolverCacheError> {
        query.validate_identity().map_err(SolverCacheError::InvalidQuery)?;
        let key = query.canonical_key();
        let index = shard_index(&key);
        let result = self.shards[index]
            .lock()
            .map_err(|_| SolverCacheError::LockPoisoned)?
            .get(&key)
            .cloned();
        if result.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        Ok(result)
    }

    pub fn insert(&self, query: &SolverQuery, result: SolverResult) -> Result<CacheAdmission, SolverCacheError> {
        query.validate_identity().map_err(SolverCacheError::InvalidQuery)?;
        if !matches!(result.outcome, SolverOutcomeKind::Sat | SolverOutcomeKind::Unsat) {
            return Ok(CacheAdmission::RejectedTransient);
        }
        let key = query.canonical_key();
        let index = shard_index(&key);
        self.shards[index]
            .lock()
            .map_err(|_| SolverCacheError::LockPoisoned)?
            .insert(key, Arc::new(result));
        Ok(CacheAdmission::Stored)
    }

    pub fn stats(&self) -> Result<SolverCacheStats, SolverCacheError> {
        let mut entries: u64 = 0;
        for shard in &self.shards {
            let len = shard.lock().map_err(|_| SolverCacheError::LockPoisoned)?.len();
            entries = entries.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        }
        Ok(SolverCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries,
        })
    }

    /// Returns the entry count for each shard, useful for verifying distribution.
    pub fn shard_lens(&self) -> Result<Vec<u64>, SolverCacheError> {
        let mut lens = Vec::with_capacity(SHARD_COUNT);
        for shard in &self.shards {
            let len = shard.lock().map_err(|_| SolverCacheError::LockPoisoned)?.len();
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

#[cfg(test)]
mod tests {
    use super::*;

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
                entries: 1
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
}
