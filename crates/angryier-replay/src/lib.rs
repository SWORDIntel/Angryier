#![forbid(unsafe_code)]

//! Deterministic replay capsule contracts and a concrete in-memory engine.
//!
//! A [`ReplayCapsule`] captures the identity frame required to reproduce an
//! analysis run: schema version, binary [`AnalysisContext`], semantic
//! identity, code-page guards, environment key, and scheduler seed. The
//! [`BasicReplayValidator`] enforces that a capsule is internally consistent
//! with a known-good frame, the [`ReplayCapsuleStore`] persists capsules for
//! retrieval, and the [`BasicReplayEngine`] ties validation and storage
//! together to produce a [`ReplayResult`].

use angryier_types::{
    AnalysisContext, CodeVersionGuard, ContentId, DependencyKey, ReplayCapsuleId, ReplaySchemaVersion, SemanticVersion,
    StateId,
};
use core::fmt;
use std::collections::BTreeMap;
use std::sync::RwLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayCapsule {
    pub id: ReplayCapsuleId,
    pub schema: ReplaySchemaVersion,
    pub context: AnalysisContext,
    pub initial_state: StateId,
    pub semantic_version: SemanticVersion,
    pub semantic_content: ContentId,
    pub code_versions: Vec<CodeVersionGuard>,
    pub environment_key: DependencyKey,
    pub scheduler_seed: u64,
}

/// Failures that can occur while validating, storing, or replaying a capsule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    SchemaMismatch,
    BinaryMismatch,
    SemanticMismatch,
    CodeVersionMismatch,
    EnvironmentMismatch,
    SchedulerMismatch,
    /// A synchronization primitive was poisoned by a panicking thread.
    Poisoned,
    /// A capsule with the same id has already been published.
    DuplicateCapsule,
    /// No capsule is registered for the requested id.
    UnknownCapsule,
}

impl fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SchemaMismatch => "replay schema version mismatch",
            Self::BinaryMismatch => "binary analysis context mismatch",
            Self::SemanticMismatch => "semantic version mismatch",
            Self::CodeVersionMismatch => "code-version guard set is empty or unsorted",
            Self::EnvironmentMismatch => "environment dependency key is zero",
            Self::SchedulerMismatch => "scheduler seed is non-deterministic",
            Self::Poisoned => "replay store synchronization primitive poisoned",
            Self::DuplicateCapsule => "replay capsule already published",
            Self::UnknownCapsule => "unknown replay capsule",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReplayError {}

pub trait ReplayValidator: Send + Sync {
    fn validate(&self, capsule: &ReplayCapsule) -> Result<(), ReplayError>;
}

pub trait ReplayEngine: Send + Sync {
    type Output;
    fn replay(&self, capsule: &ReplayCapsule) -> Result<Self::Output, ReplayError>;
}

/// Outcome of a [`BasicReplayEngine::replay`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayStatus {
    /// The capsule passed validation only; no replay log was produced.
    Validated,
    /// The capsule was validated and a replay log entry was produced.
    Replayed,
}

/// A single replay log entry recording that a capsule was replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayLogEntry {
    pub capsule_id: ReplayCapsuleId,
    pub sequence: u64,
}

/// The result of replaying a capsule through a [`BasicReplayEngine`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplayResult {
    pub capsule_id: ReplayCapsuleId,
    pub initial_state: StateId,
    pub status: ReplayStatus,
    pub sequence: u64,
}

/// A validator that compares a capsule against a fixed expected identity frame.
///
/// The expected frame is the schema version, binary [`AnalysisContext`], and
/// the set of [`SemanticVersion`]s that the replay host considers admissible.
pub struct BasicReplayValidator {
    expected_schema: ReplaySchemaVersion,
    expected_context: AnalysisContext,
    known_semantic_versions: BTreeMap<SemanticVersion, ()>,
}

impl BasicReplayValidator {
    /// Construct a new validator from an expected frame and admissible versions.
    pub fn new(expected_schema: ReplaySchemaVersion, expected_context: AnalysisContext) -> Self {
        Self {
            expected_schema,
            expected_context,
            known_semantic_versions: BTreeMap::new(),
        }
    }

    /// Register an admissible semantic version with the validator.
    pub fn admit(&mut self, version: SemanticVersion) {
        self.known_semantic_versions.insert(version, ());
    }

    /// Register a batch of admissible semantic versions.
    pub fn admit_many(&mut self, versions: impl IntoIterator<Item = SemanticVersion>) {
        for version in versions {
            self.known_semantic_versions.insert(version, ());
        }
    }

    fn is_sorted_and_nonempty(versions: &[CodeVersionGuard]) -> bool {
        if versions.is_empty() {
            return false;
        }
        versions.windows(2).all(|window| window[0].page <= window[1].page)
    }
}

impl ReplayValidator for BasicReplayValidator {
    fn validate(&self, capsule: &ReplayCapsule) -> Result<(), ReplayError> {
        if capsule.schema != self.expected_schema {
            return Err(ReplayError::SchemaMismatch);
        }
        if capsule.context != self.expected_context {
            return Err(ReplayError::BinaryMismatch);
        }
        if !self.known_semantic_versions.contains_key(&capsule.semantic_version) {
            return Err(ReplayError::SemanticMismatch);
        }
        if !Self::is_sorted_and_nonempty(&capsule.code_versions) {
            return Err(ReplayError::CodeVersionMismatch);
        }
        if capsule.environment_key == DependencyKey([0u8; 32]) {
            return Err(ReplayError::EnvironmentMismatch);
        }
        if capsule.scheduler_seed == 0 {
            return Err(ReplayError::SchedulerMismatch);
        }
        Ok(())
    }
}

/// An in-memory store of published replay capsules keyed by id.
#[derive(Debug, Default)]
pub struct ReplayCapsuleStore {
    capsules: RwLock<BTreeMap<ReplayCapsuleId, ReplayCapsule>>,
}

impl ReplayCapsuleStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish a capsule. Rejects duplicate ids.
    pub fn publish(&self, capsule: ReplayCapsule) -> Result<ReplayCapsuleId, ReplayError> {
        let mut capsules = self.capsules.write().map_err(|_| ReplayError::Poisoned)?;
        if capsules.contains_key(&capsule.id) {
            return Err(ReplayError::DuplicateCapsule);
        }
        let id = capsule.id;
        capsules.insert(id, capsule);
        Ok(id)
    }

    /// Retrieve a capsule by id.
    pub fn retrieve(&self, id: ReplayCapsuleId) -> Result<ReplayCapsule, ReplayError> {
        let capsules = self.capsules.read().map_err(|_| ReplayError::Poisoned)?;
        capsules.get(&id).cloned().ok_or(ReplayError::UnknownCapsule)
    }

    /// Returns true if a capsule with the given id is present.
    pub fn contains(&self, id: ReplayCapsuleId) -> bool {
        match self.capsules.read() {
            Ok(capsules) => capsules.contains_key(&id),
            Err(_) => false,
        }
    }
}

/// A concrete replay engine that validates capsules, stores them, and
/// produces a [`ReplayResult`] with a monotonic sequence number.
pub struct BasicReplayEngine {
    store: ReplayCapsuleStore,
    validator: BasicReplayValidator,
    sequence: RwLock<u64>,
}

impl BasicReplayEngine {
    pub fn new(validator: BasicReplayValidator) -> Self {
        Self {
            store: ReplayCapsuleStore::new(),
            validator,
            sequence: RwLock::new(0),
        }
    }

    /// Publish a capsule directly through the engine's store.
    pub fn publish(&self, capsule: ReplayCapsule) -> Result<ReplayCapsuleId, ReplayError> {
        self.store.publish(capsule)
    }

    /// Retrieve a capsule from the engine's store.
    pub fn retrieve(&self, id: ReplayCapsuleId) -> Result<ReplayCapsule, ReplayError> {
        self.store.retrieve(id)
    }

    /// Returns true if the engine's store contains the given id.
    pub fn contains(&self, id: ReplayCapsuleId) -> bool {
        self.store.contains(id)
    }

    fn next_sequence(&self) -> Result<u64, ReplayError> {
        let mut sequence = self.sequence.write().map_err(|_| ReplayError::Poisoned)?;
        *sequence = sequence.checked_add(1).ok_or(ReplayError::Poisoned)?;
        Ok(*sequence)
    }
}

impl ReplayEngine for BasicReplayEngine {
    type Output = ReplayResult;

    fn replay(&self, capsule: &ReplayCapsule) -> Result<Self::Output, ReplayError> {
        self.validator.validate(capsule)?;
        let sequence = self.next_sequence()?;
        Ok(ReplayResult {
            capsule_id: capsule.id,
            initial_state: capsule.initial_state,
            status: ReplayStatus::Replayed,
            sequence,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_types::{
        CodePageId, CodePageVersion, FidelityProfile, RetentionProfile, RunId, SecurityContext, TargetProfileId,
    };

    fn context() -> AnalysisContext {
        AnalysisContext {
            run_id: RunId(1),
            target_profile: TargetProfileId(2),
            fidelity: FidelityProfile::Prove,
            retention: RetentionProfile::Forensic,
            security: SecurityContext {
                classification: 0,
                compartment: 0,
            },
        }
    }

    fn content(byte: u8) -> ContentId {
        ContentId([byte; 32])
    }

    fn env_key(byte: u8) -> DependencyKey {
        DependencyKey([byte; 32])
    }

    fn code_versions() -> Vec<CodeVersionGuard> {
        vec![
            CodeVersionGuard {
                page: CodePageId(1),
                version: CodePageVersion(0),
            },
            CodeVersionGuard {
                page: CodePageId(2),
                version: CodePageVersion(0),
            },
        ]
    }

    fn valid_capsule() -> ReplayCapsule {
        ReplayCapsule {
            id: ReplayCapsuleId(1),
            schema: ReplaySchemaVersion(1),
            context: context(),
            initial_state: StateId(7),
            semantic_version: SemanticVersion(1),
            semantic_content: content(1),
            code_versions: code_versions(),
            environment_key: env_key(1),
            scheduler_seed: 42,
        }
    }

    fn validator() -> BasicReplayValidator {
        let mut validator = BasicReplayValidator::new(ReplaySchemaVersion(1), context());
        validator.admit(SemanticVersion(1));
        validator
    }

    #[test]
    fn valid_capsule_validates_successfully() {
        let validator = validator();
        let capsule = valid_capsule();
        assert_eq!(validator.validate(&capsule), Ok(()));
    }

    #[test]
    fn schema_mismatch_is_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.schema = ReplaySchemaVersion(2);
        assert_eq!(validator.validate(&capsule), Err(ReplayError::SchemaMismatch));
    }

    #[test]
    fn binary_mismatch_is_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.context = AnalysisContext {
            run_id: RunId(99),
            target_profile: TargetProfileId(2),
            fidelity: FidelityProfile::Prove,
            retention: RetentionProfile::Forensic,
            security: SecurityContext {
                classification: 0,
                compartment: 0,
            },
        };
        assert_eq!(validator.validate(&capsule), Err(ReplayError::BinaryMismatch));
    }

    #[test]
    fn semantic_mismatch_is_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.semantic_version = SemanticVersion(99);
        assert_eq!(validator.validate(&capsule), Err(ReplayError::SemanticMismatch));
    }

    #[test]
    fn empty_code_versions_are_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.code_versions = Vec::new();
        assert_eq!(validator.validate(&capsule), Err(ReplayError::CodeVersionMismatch));
    }

    #[test]
    fn unsorted_code_versions_are_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.code_versions = vec![
            CodeVersionGuard {
                page: CodePageId(2),
                version: CodePageVersion(0),
            },
            CodeVersionGuard {
                page: CodePageId(1),
                version: CodePageVersion(0),
            },
        ];
        assert_eq!(validator.validate(&capsule), Err(ReplayError::CodeVersionMismatch));
    }

    #[test]
    fn zero_environment_key_is_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.environment_key = DependencyKey([0u8; 32]);
        assert_eq!(validator.validate(&capsule), Err(ReplayError::EnvironmentMismatch));
    }

    #[test]
    fn zero_scheduler_seed_is_rejected() {
        let validator = validator();
        let mut capsule = valid_capsule();
        capsule.scheduler_seed = 0;
        assert_eq!(validator.validate(&capsule), Err(ReplayError::SchedulerMismatch));
    }

    #[test]
    fn store_publish_and_retrieve_round_trips() {
        let store = ReplayCapsuleStore::new();
        let capsule = valid_capsule();
        let id = store.publish(capsule.clone());
        assert_eq!(id, Ok(capsule.id));
        assert!(store.contains(capsule.id));
        assert_eq!(store.retrieve(capsule.id), Ok(capsule));
    }

    #[test]
    fn store_rejects_duplicate_capsule_ids() {
        let store = ReplayCapsuleStore::new();
        let capsule = valid_capsule();
        assert_eq!(store.publish(capsule.clone()), Ok(capsule.id));
        assert_eq!(store.publish(capsule), Err(ReplayError::DuplicateCapsule));
    }

    #[test]
    fn store_rejects_unknown_id_retrieval() {
        let store = ReplayCapsuleStore::new();
        assert_eq!(store.retrieve(ReplayCapsuleId(123)), Err(ReplayError::UnknownCapsule));
    }

    #[test]
    fn engine_replay_produces_correct_result() {
        let engine = BasicReplayEngine::new(validator());
        let capsule = valid_capsule();
        let expected = ReplayResult {
            capsule_id: capsule.id,
            initial_state: capsule.initial_state,
            status: ReplayStatus::Replayed,
            sequence: 1,
        };
        assert_eq!(engine.replay(&capsule), Ok(expected));
    }

    #[test]
    fn engine_rejects_invalid_capsule() {
        let engine = BasicReplayEngine::new(validator());
        let mut capsule = valid_capsule();
        capsule.scheduler_seed = 0;
        assert_eq!(engine.replay(&capsule), Err(ReplayError::SchedulerMismatch));
    }

    #[test]
    fn engine_sequence_advances_monotonically() -> Result<(), ReplayError> {
        let engine = BasicReplayEngine::new(validator());
        let capsule = valid_capsule();
        let first = engine.replay(&capsule)?;
        let second = engine.replay(&capsule)?;
        assert_eq!(first.sequence, 1);
        assert_eq!(second.sequence, 2);
        Ok(())
    }

    #[test]
    fn display_covers_all_error_variants() {
        let errors = [
            ReplayError::SchemaMismatch,
            ReplayError::BinaryMismatch,
            ReplayError::SemanticMismatch,
            ReplayError::CodeVersionMismatch,
            ReplayError::EnvironmentMismatch,
            ReplayError::SchedulerMismatch,
            ReplayError::Poisoned,
            ReplayError::DuplicateCapsule,
            ReplayError::UnknownCapsule,
        ];
        for error in errors {
            let rendered = format!("{error}");
            assert!(!rendered.is_empty());
        }
    }
}
