#![forbid(unsafe_code)]

//! Deterministic replay capsule contracts and a concrete in-memory engine.
//!
//! A [`ReplayCapsule`] captures the identity frame required to reproduce an
//! analysis run: schema version, binary [`AnalysisContext`], semantic
//! identity, code-page guards, environment key, and scheduler seed. Schema
//! version 2 extends the frame with the concrete inputs that drove the run
//! ([`RecordedInputs`]) and the observable outcome checkpoints it must
//! reproduce ([`ExpectedCheckpoints`]) — image hash, input registers/stdin,
//! exit code, and captured `write` output. Version 1 capsules (no recorded
//! payload) still validate against version 1 frames. The
//! [`BasicReplayValidator`] enforces that a capsule is internally consistent
//! with a known-good frame — either a full analysis context or a replay
//! host's image hash, semantic version, and target profile — the
//! [`ReplayCapsuleStore`] persists capsules for retrieval, and the
//! [`BasicReplayEngine`] ties validation and storage together to produce a
//! [`ReplayResult`].

use angryier_types::{
    AnalysisContext, CodePageId, CodePageVersion, CodeVersionGuard, ContentDomain, ContentId,
    ContentIdentitySchemaVersion, DependencyKey, ReplayCapsuleId, ReplaySchemaVersion, RunId, SecurityContext,
    SemanticVersion, StateId, TargetProfileId,
};
use core::fmt;
use std::collections::BTreeMap;
use std::sync::RwLock;

/// Capsule schema of the original identity frame: no recorded inputs or
/// expected checkpoints (those fields are empty/default on version 1
/// capsules and are neither stored nor checked).
pub const REPLAY_SCHEMA_V1: ReplaySchemaVersion = ReplaySchemaVersion(1);
/// Capsule schema that records the run payload: image hash, concrete inputs,
/// and expected outcome checkpoints (exit code, captured `write` output).
pub const REPLAY_SCHEMA_V2: ReplaySchemaVersion = ReplaySchemaVersion(2);

/// Domain-separated content identity over the replay-capsule domain; the
/// building block for capsule image hashes and environment keys.
pub fn capsule_domain_id(canonical_bytes: &[u8]) -> ContentId {
    ContentId::derive(
        ContentDomain::ReplayCapsule,
        ContentIdentitySchemaVersion(1),
        canonical_bytes,
    )
}

/// Image identity recorded in capsules: a domain-separated content id of the
/// loaded image bytes. A replay host recomputes it from its own image bytes
/// and rejects the capsule on any mismatch.
pub fn image_hash(image_bytes: &[u8]) -> ContentId {
    capsule_domain_id(image_bytes)
}

/// Concrete inputs recorded for deterministic replay (schema v2): register
/// values applied before execution (sorted by register id, last write wins)
/// and the stdin bytes served by the `read(0)` model.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecordedInputs {
    pub registers: Vec<(u32, u64)>,
    pub stdin: Vec<u8>,
}

/// Observable outcome checkpoints recorded at record time and re-asserted at
/// replay time (schema v2). A replay whose exit code or captured `write`
/// output drifts from these checkpoints is rejected, not best-effort.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExpectedCheckpoints {
    pub exit_code: Option<u64>,
    pub write_output: Vec<u8>,
}

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
    // --- schema v2 extension: recorded run payload -------------------------
    /// Identity of the image the run executed (see [`image_hash`]). Zero on
    /// version 1 capsules.
    pub image_hash: ContentId,
    /// The concrete inputs that drove the run. Empty on version 1 capsules.
    pub inputs: RecordedInputs,
    /// The outcome the run must reproduce. Empty on version 1 capsules.
    pub expected: ExpectedCheckpoints,
}

impl ReplayCapsule {
    /// Returns `true` when the capsule carries a recorded run payload that
    /// only schema version 2 covers.
    fn has_recorded_payload(&self) -> bool {
        !self.inputs.registers.is_empty()
            || !self.inputs.stdin.is_empty()
            || self.expected.exit_code.is_some()
            || !self.expected.write_output.is_empty()
    }
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
    /// The capsule's image hash does not match the replay host's image.
    ImageMismatch,
    /// The capsule's recorded payload does not match its schema version
    /// (version 2 mandates inputs and an exit-code checkpoint; version 1
    /// cannot carry any recorded payload).
    CapsuleIncomplete,
    /// A re-executed run drifted from the capsule's expected checkpoints.
    CheckpointMismatch,
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
            Self::ImageMismatch => "capsule image hash mismatch",
            Self::CapsuleIncomplete => "capsule payload is not covered by its schema version",
            Self::CheckpointMismatch => "replayed outcome does not match capsule checkpoints",
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
/// Two frames are supported. `new` pins the full analysis context — the
/// original ledger frame, where replay happens within the same recorded run.
/// `for_replay_host` pins the replay HOST frame instead: the exact image
/// hash, target profile, and admissible [`SemanticVersion`]s of the runtime
/// that intends to re-execute the capsule; run-scoped context fields (run id,
/// fidelity, retention, security) legitimately differ between record and
/// replay, so only the target profile is compared.
pub struct BasicReplayValidator {
    expected_schema: ReplaySchemaVersion,
    /// When set, the capsule's full analysis context must equal this frame;
    /// otherwise only `host_target_profile` is compared.
    expected_context: Option<AnalysisContext>,
    host_target_profile: TargetProfileId,
    /// When set, the capsule's image hash must equal this hash.
    expected_image_hash: Option<ContentId>,
    known_semantic_versions: BTreeMap<SemanticVersion, ()>,
}

impl BasicReplayValidator {
    /// Construct a new validator from an expected full frame and admissible versions.
    pub fn new(expected_schema: ReplaySchemaVersion, expected_context: AnalysisContext) -> Self {
        Self {
            expected_schema,
            host_target_profile: expected_context.target_profile,
            expected_context: Some(expected_context),
            expected_image_hash: None,
            known_semantic_versions: BTreeMap::new(),
        }
    }

    /// Construct a validator for a replay HOST: the exact image the host will
    /// re-execute, its target profile, and the schema it understands.
    pub fn for_replay_host(
        expected_schema: ReplaySchemaVersion,
        host_target_profile: TargetProfileId,
        host_image_hash: ContentId,
    ) -> Self {
        Self {
            expected_schema,
            host_target_profile,
            expected_context: None,
            expected_image_hash: Some(host_image_hash),
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
        match self.expected_context {
            Some(expected) if capsule.context != expected => return Err(ReplayError::BinaryMismatch),
            None if capsule.context.target_profile != self.host_target_profile => {
                return Err(ReplayError::BinaryMismatch);
            }
            _ => {}
        }
        if let Some(expected_hash) = self.expected_image_hash
            && capsule.image_hash != expected_hash
        {
            return Err(ReplayError::ImageMismatch);
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
        if capsule.schema.0 >= REPLAY_SCHEMA_V2.0 {
            let has_inputs = !capsule.inputs.registers.is_empty() || !capsule.inputs.stdin.is_empty();
            if !has_inputs || capsule.expected.exit_code.is_none() {
                return Err(ReplayError::CapsuleIncomplete);
            }
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

/// Durable capsule backend: one binary file per capsule under `dir`.
/// The on-disk layout is a fixed little-endian record — schema, identity,
/// environment key, scheduler seed, analysis context, and the sorted
/// code-version guards — so capsules survive process restarts. Schema
/// version 2 files append the recorded-run extension (image hash, inputs,
/// expected checkpoints) after the guard array; version 1 files keep the
/// original byte layout and parse exactly as before.
pub struct FileReplayStore {
    dir: std::path::PathBuf,
}

impl FileReplayStore {
    pub fn new(dir: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    fn path(&self, id: ReplayCapsuleId) -> std::path::PathBuf {
        self.dir.join(format!("{:016x}.capsule", id.0))
    }

    pub fn publish(&self, capsule: &ReplayCapsule) -> Result<(), ReplayError> {
        let path = self.path(capsule.id);
        if path.exists() {
            return Err(ReplayError::DuplicateCapsule);
        }
        // Version 1 files cannot carry a recorded payload; refuse rather
        // than silently dropping it.
        if capsule.schema.0 < REPLAY_SCHEMA_V2.0 && capsule.has_recorded_payload() {
            return Err(ReplayError::CapsuleIncomplete);
        }
        let mut buf = Vec::with_capacity(160);
        buf.extend_from_slice(&capsule.schema.0.to_le_bytes());
        buf.extend_from_slice(&capsule.id.0.to_le_bytes());
        buf.extend_from_slice(&capsule.initial_state.0.to_le_bytes());
        buf.extend_from_slice(&capsule.semantic_version.0.to_le_bytes());
        buf.extend_from_slice(&capsule.semantic_content.0);
        buf.extend_from_slice(&capsule.environment_key.0);
        buf.extend_from_slice(&capsule.scheduler_seed.to_le_bytes());
        let ctx = &capsule.context;
        buf.extend_from_slice(&ctx.run_id.0.to_le_bytes());
        buf.extend_from_slice(&ctx.target_profile.0.to_le_bytes());
        buf.push(match ctx.fidelity {
            angryier_types::FidelityProfile::Prove => 0,
            angryier_types::FidelityProfile::Explore => 1,
            angryier_types::FidelityProfile::Hunt => 2,
        });
        buf.push(match ctx.retention {
            angryier_types::RetentionProfile::Forensic => 0,
            angryier_types::RetentionProfile::Research => 1,
            angryier_types::RetentionProfile::Benchmark => 2,
            angryier_types::RetentionProfile::Disposable => 3,
        });
        buf.extend_from_slice(&ctx.security.classification.to_le_bytes());
        buf.extend_from_slice(&ctx.security.compartment.to_le_bytes());
        buf.extend_from_slice(&(capsule.code_versions.len() as u64).to_le_bytes());
        for g in &capsule.code_versions {
            buf.extend_from_slice(&g.page.0.to_le_bytes());
            buf.extend_from_slice(&g.version.0.to_le_bytes());
        }
        if capsule.schema.0 >= REPLAY_SCHEMA_V2.0 {
            buf.extend_from_slice(&capsule.image_hash.0);
            buf.extend_from_slice(&(capsule.inputs.registers.len() as u64).to_le_bytes());
            for (register, value) in &capsule.inputs.registers {
                buf.extend_from_slice(&register.to_le_bytes());
                buf.extend_from_slice(&value.to_le_bytes());
            }
            buf.extend_from_slice(&(capsule.inputs.stdin.len() as u64).to_le_bytes());
            buf.extend_from_slice(&capsule.inputs.stdin);
            match capsule.expected.exit_code {
                Some(code) => {
                    buf.push(1);
                    buf.extend_from_slice(&code.to_le_bytes());
                }
                None => buf.push(0),
            }
            buf.extend_from_slice(&(capsule.expected.write_output.len() as u64).to_le_bytes());
            buf.extend_from_slice(&capsule.expected.write_output);
        }
        std::fs::write(&path, &buf).map_err(|_| ReplayError::Poisoned)?;
        Ok(())
    }

    pub fn retrieve(&self, id: ReplayCapsuleId) -> Result<ReplayCapsule, ReplayError> {
        let bytes = std::fs::read(self.path(id)).map_err(|_| ReplayError::UnknownCapsule)?;
        let mut off = 0usize;
        let mut take = |n: usize| -> Result<&[u8], ReplayError> {
            let s = bytes.get(off..off + n).ok_or(ReplayError::BinaryMismatch)?;
            off += n;
            Ok(s)
        };
        let u64_at = |s: &[u8]| u64::from_le_bytes(s.try_into().unwrap_or([0; 8]));
        let u32_at = |s: &[u8]| u32::from_le_bytes(s.try_into().unwrap_or([0; 4]));
        let schema = ReplaySchemaVersion(u64_at(take(8)?));
        let cid = ReplayCapsuleId(u64_at(take(8)?));
        let state = StateId(u64_at(take(8)?));
        let sem = SemanticVersion(u64_at(take(8)?));
        let mut content = [0u8; 32];
        content.copy_from_slice(take(32)?);
        let mut env = [0u8; 32];
        env.copy_from_slice(take(32)?);
        let seed = u64_at(take(8)?);
        let run = u64_at(take(8)?);
        let profile = u64_at(take(8)?);
        let fidelity = match take(1)?[0] {
            0 => angryier_types::FidelityProfile::Prove,
            1 => angryier_types::FidelityProfile::Explore,
            _ => angryier_types::FidelityProfile::Hunt,
        };
        let retention = match take(1)?[0] {
            0 => angryier_types::RetentionProfile::Forensic,
            1 => angryier_types::RetentionProfile::Research,
            2 => angryier_types::RetentionProfile::Benchmark,
            _ => angryier_types::RetentionProfile::Disposable,
        };
        let classification = u32::from_le_bytes(take(4)?.try_into().unwrap_or([0; 4]));
        let compartment = u32::from_le_bytes(take(4)?.try_into().unwrap_or([0; 4]));
        let guard_count = u64_at(take(8)?) as usize;
        let mut guards = Vec::new();
        for _ in 0..guard_count {
            let page = CodePageId(u64_at(take(8)?));
            let version = CodePageVersion(u64_at(take(8)?));
            guards.push(CodeVersionGuard { page, version });
        }
        // Recorded-run extension, present only on schema version 2+ files.
        // Version 1 files end at the guard array and decode with the empty
        // (default) extension.
        let mut image_hash = ContentId([0u8; 32]);
        let mut inputs = RecordedInputs::default();
        let mut expected = ExpectedCheckpoints::default();
        if schema.0 >= REPLAY_SCHEMA_V2.0 {
            let mut hash = [0u8; 32];
            hash.copy_from_slice(take(32)?);
            image_hash = ContentId(hash);
            let register_count = u64_at(take(8)?);
            for _ in 0..register_count {
                let register = u32_at(take(4)?);
                let value = u64_at(take(8)?);
                inputs.registers.push((register, value));
            }
            let stdin_len = u64_at(take(8)?) as usize;
            inputs.stdin = take(stdin_len)?.to_vec();
            let has_exit_code = take(1)?[0] != 0;
            expected.exit_code = if has_exit_code { Some(u64_at(take(8)?)) } else { None };
            let output_len = u64_at(take(8)?) as usize;
            expected.write_output = take(output_len)?.to_vec();
        }
        Ok(ReplayCapsule {
            id: cid,
            schema,
            context: AnalysisContext {
                run_id: RunId(run),
                target_profile: TargetProfileId(profile),
                fidelity,
                retention,
                security: SecurityContext {
                    classification,
                    compartment,
                },
            },
            initial_state: state,
            semantic_version: sem,
            semantic_content: ContentId(content),
            code_versions: guards,
            environment_key: DependencyKey(env),
            scheduler_seed: seed,
            image_hash,
            inputs,
            expected,
        })
    }

    pub fn contains(&self, id: ReplayCapsuleId) -> bool {
        self.path(id).exists()
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
            image_hash: ContentId::default(),
            inputs: RecordedInputs::default(),
            expected: ExpectedCheckpoints::default(),
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
            ReplayError::ImageMismatch,
            ReplayError::CapsuleIncomplete,
            ReplayError::CheckpointMismatch,
            ReplayError::Poisoned,
            ReplayError::DuplicateCapsule,
            ReplayError::UnknownCapsule,
        ];
        for error in errors {
            let rendered = format!("{error}");
            assert!(!rendered.is_empty());
        }
    }

    /// The version 2 frame: a capsule carrying recorded inputs and
    /// checkpoints validates against a replay host whose image hash,
    /// target profile, and semantic version all match.
    #[test]
    fn v2_capsule_validates_against_matching_replay_host() {
        let mut capsule = valid_capsule();
        capsule.schema = REPLAY_SCHEMA_V2;
        capsule.image_hash = image_hash(b"fixture-elf-bytes");
        capsule.inputs = RecordedInputs {
            registers: vec![(0, 42)],
            stdin: Vec::new(),
        };
        capsule.expected = ExpectedCheckpoints {
            exit_code: Some(0),
            write_output: b"OK".to_vec(),
        };
        let mut host = BasicReplayValidator::for_replay_host(
            REPLAY_SCHEMA_V2,
            TargetProfileId(2),
            image_hash(b"fixture-elf-bytes"),
        );
        host.admit(SemanticVersion(1));
        assert_eq!(host.validate(&capsule), Ok(()));
    }

    /// A different host image must be rejected by hash, fail-closed.
    #[test]
    fn v2_capsule_with_wrong_image_hash_is_rejected() {
        let mut capsule = valid_capsule();
        capsule.schema = REPLAY_SCHEMA_V2;
        capsule.image_hash = image_hash(b"fixture-elf-bytes");
        capsule.inputs = RecordedInputs {
            registers: vec![(0, 42)],
            stdin: Vec::new(),
        };
        capsule.expected.exit_code = Some(0);
        let mut host =
            BasicReplayValidator::for_replay_host(REPLAY_SCHEMA_V2, TargetProfileId(2), image_hash(b"other-elf-bytes"));
        host.admit(SemanticVersion(1));
        assert_eq!(host.validate(&capsule), Err(ReplayError::ImageMismatch));
    }

    /// Host-frame target-profile mismatch keeps the BinaryMismatch class.
    #[test]
    fn v2_capsule_with_wrong_target_profile_is_rejected() {
        let mut capsule = valid_capsule();
        capsule.schema = REPLAY_SCHEMA_V2;
        capsule.image_hash = image_hash(b"fixture-elf-bytes");
        capsule.inputs = RecordedInputs {
            registers: vec![(0, 42)],
            stdin: Vec::new(),
        };
        capsule.expected.exit_code = Some(0);
        let mut host = BasicReplayValidator::for_replay_host(
            REPLAY_SCHEMA_V2,
            TargetProfileId(99),
            image_hash(b"fixture-elf-bytes"),
        );
        host.admit(SemanticVersion(1));
        assert_eq!(host.validate(&capsule), Err(ReplayError::BinaryMismatch));
    }

    /// Version 2 mandates the recorded payload: no inputs or no exit-code
    /// checkpoint means the capsule cannot be replayed.
    #[test]
    fn v2_capsule_without_recorded_payload_is_rejected() {
        let mut capsule = valid_capsule();
        capsule.schema = REPLAY_SCHEMA_V2;
        capsule.image_hash = image_hash(b"fixture-elf-bytes");
        // No inputs, no checkpoints.
        let mut host = BasicReplayValidator::for_replay_host(
            REPLAY_SCHEMA_V2,
            TargetProfileId(2),
            image_hash(b"fixture-elf-bytes"),
        );
        host.admit(SemanticVersion(1));
        assert_eq!(host.validate(&capsule), Err(ReplayError::CapsuleIncomplete));

        // Inputs but no exit-code checkpoint is equally incomplete.
        capsule.inputs = RecordedInputs {
            registers: vec![(0, 42)],
            stdin: Vec::new(),
        };
        assert_eq!(host.validate(&capsule), Err(ReplayError::CapsuleIncomplete));
    }
}

#[cfg(test)]
mod file_store_tests {
    use super::*;

    fn capsule(id: u64) -> ReplayCapsule {
        ReplayCapsule {
            id: ReplayCapsuleId(id),
            schema: ReplaySchemaVersion(1),
            context: AnalysisContext {
                run_id: RunId(7),
                target_profile: TargetProfileId(1),
                fidelity: angryier_types::FidelityProfile::Prove,
                retention: angryier_types::RetentionProfile::Forensic,
                security: SecurityContext {
                    classification: 3,
                    compartment: 9,
                },
            },
            initial_state: StateId(4),
            semantic_version: SemanticVersion(11),
            semantic_content: ContentId([0xAB; 32]),
            code_versions: vec![
                CodeVersionGuard {
                    page: CodePageId(5),
                    version: CodePageVersion(2),
                },
                CodeVersionGuard {
                    page: CodePageId(9),
                    version: CodePageVersion(1),
                },
            ],
            environment_key: DependencyKey([0xCD; 32]),
            scheduler_seed: 42,
            image_hash: ContentId::default(),
            inputs: RecordedInputs::default(),
            expected: ExpectedCheckpoints::default(),
        }
    }

    fn v2_capsule(id: u64) -> ReplayCapsule {
        ReplayCapsule {
            schema: REPLAY_SCHEMA_V2,
            image_hash: image_hash(b"v2-fixture-elf"),
            inputs: RecordedInputs {
                registers: vec![(0, 42), (1, 7)],
                stdin: b"stdin-bytes".to_vec(),
            },
            expected: ExpectedCheckpoints {
                exit_code: Some(1),
                write_output: b"NO".to_vec(),
            },
            ..capsule(id)
        }
    }

    fn store(tag: &str) -> Option<FileReplayStore> {
        let dir = std::env::temp_dir().join(format!("replay-{tag}-{}", std::process::id()));
        match FileReplayStore::new(&dir) {
            Ok(store) => Some(store),
            Err(e) => {
                eprintln!("skip: {e}");
                None
            }
        }
    }

    #[test]
    fn file_store_round_trip() {
        let Some(store) = store("v1") else {
            return;
        };
        let cap = capsule(1);
        assert!(store.publish(&cap).is_ok());
        assert!(store.contains(ReplayCapsuleId(1)));
        let back = store.retrieve(ReplayCapsuleId(1));
        assert_eq!(back, Ok(cap));
        // Duplicate rejected.
        assert_eq!(store.publish(&capsule(1)), Err(ReplayError::DuplicateCapsule));
        let _ = std::fs::remove_dir_all(store.dir);
    }

    #[test]
    fn file_store_round_trips_v2_payload() {
        let Some(store) = store("v2") else {
            return;
        };
        let cap = v2_capsule(2);
        assert!(store.publish(&cap).is_ok());
        assert_eq!(store.retrieve(ReplayCapsuleId(2)), Ok(cap));
        let _ = std::fs::remove_dir_all(store.dir);
    }

    /// Version 1 files cannot durably carry a recorded payload; publishing
    /// one is refused instead of silently dropping the payload.
    #[test]
    fn file_store_refuses_v1_capsule_with_payload() {
        let Some(store) = store("v1-payload") else {
            return;
        };
        let mut cap = capsule(3);
        cap.expected.exit_code = Some(0);
        assert_eq!(store.publish(&cap), Err(ReplayError::CapsuleIncomplete));
        assert!(!store.contains(ReplayCapsuleId(3)));
        let _ = std::fs::remove_dir_all(store.dir);
    }

    /// A file written by the pre-v2 store (the exact original byte layout)
    /// still parses and still validates against a version 1 frame.
    #[test]
    fn legacy_v1_file_round_trips_and_validates() {
        let Some(store) = store("legacy") else {
            return;
        };
        // Hand-assembled bytes exactly as the original publish wrote them:
        // schema, id, state, semantic version, content, env key, seed,
        // context (run, profile, fidelity, retention, classification,
        // compartment), then the guard array.
        let mut buf = Vec::new();
        buf.extend_from_slice(&1u64.to_le_bytes()); // schema v1
        buf.extend_from_slice(&9u64.to_le_bytes()); // id
        buf.extend_from_slice(&4u64.to_le_bytes()); // initial_state
        buf.extend_from_slice(&11u64.to_le_bytes()); // semantic_version
        buf.extend_from_slice(&[0xAB; 32]); // semantic_content
        buf.extend_from_slice(&[0xCD; 32]); // environment_key
        buf.extend_from_slice(&42u64.to_le_bytes()); // scheduler_seed
        buf.extend_from_slice(&7u64.to_le_bytes()); // run_id
        buf.extend_from_slice(&1u64.to_le_bytes()); // target_profile
        buf.push(0); // fidelity = Prove
        buf.push(0); // retention = Forensic
        buf.extend_from_slice(&3u32.to_le_bytes()); // classification
        buf.extend_from_slice(&9u32.to_le_bytes()); // compartment
        buf.extend_from_slice(&2u64.to_le_bytes()); // guard count
        buf.extend_from_slice(&5u64.to_le_bytes()); // page
        buf.extend_from_slice(&2u64.to_le_bytes()); // version
        buf.extend_from_slice(&9u64.to_le_bytes()); // page
        buf.extend_from_slice(&1u64.to_le_bytes()); // version
        std::fs::write(store.path(ReplayCapsuleId(9)), &buf).ok();

        // Decodes to the v1 capsule with the empty (default) extension.
        let expected = capsule(9);
        assert_eq!(store.retrieve(ReplayCapsuleId(9)), Ok(expected.clone()));

        // And still validates under a version 1 full frame.
        let mut validator = BasicReplayValidator::new(REPLAY_SCHEMA_V1, expected.context);
        validator.admit(SemanticVersion(11));
        assert_eq!(validator.validate(&expected), Ok(()));
        let _ = std::fs::remove_dir_all(store.dir);
    }
}
