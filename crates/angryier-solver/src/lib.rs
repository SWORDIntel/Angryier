#![forbid(unsafe_code)]

use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, SolverOutcomeKind, SolverQueryId,
    TargetProfileId,
};
use core::time::Duration;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CanonicalConstraint {
    pub id: ConstraintId,
    pub key: DependencyKey,
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
}

pub trait SolverRouter: Send + Sync {
    fn rank_backends(&self, query: &SolverQuery) -> Vec<&'static str>;
    fn should_preempt(&self, query: &SolverQuery, elapsed: Duration) -> bool;
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

#[derive(Default)]
pub struct InMemorySolverCache {
    entries: Mutex<HashMap<DependencyKey, SolverResult>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl InMemorySolverCache {
    pub fn lookup(&self, query: &SolverQuery) -> Result<Option<SolverResult>, SolverCacheError> {
        query.validate_identity().map_err(SolverCacheError::InvalidQuery)?;
        let result = self
            .entries
            .lock()
            .map_err(|_| SolverCacheError::LockPoisoned)?
            .get(&query.canonical_key())
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
        self.entries
            .lock()
            .map_err(|_| SolverCacheError::LockPoisoned)?
            .insert(query.canonical_key(), result);
        Ok(CacheAdmission::Stored)
    }

    pub fn stats(&self) -> Result<SolverCacheStats, SolverCacheError> {
        let entries = self.entries.lock().map_err(|_| SolverCacheError::LockPoisoned)?.len();
        Ok(SolverCacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            entries: u64::try_from(entries).unwrap_or(u64::MAX),
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    fn constraint(id: u64, byte: u8) -> CanonicalConstraint {
        CanonicalConstraint {
            id: ConstraintId(id),
            key: DependencyKey([byte; 32]),
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
        assert_eq!(cache.lookup(&query)?, Some(result(SolverOutcomeKind::Unsat)));
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
}
