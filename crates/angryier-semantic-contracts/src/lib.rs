#![forbid(unsafe_code)]

//! Cross-plane contracts for sealed semantic identity and post-seal transformations.
//! This crate defines policy/data boundaries only; it performs no optimization itself.

use angryier_semantics::{FidelityProfile, SemanticVersion};
use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContentId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SemanticFingerprint(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvidenceDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransformationId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceLevel {
    Verified,
    SolverChecked,
    DifferentiallyTested,
    Composite,
    Advisory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransformationContract {
    pub preserves_values: bool,
    pub preserves_architectural_side_effects: bool,
    pub preserves_exception_behavior: bool,
    pub preserves_memory_ordering: bool,
    pub preserves_floating_point_behavior: bool,
    pub preserves_masking_behavior: bool,
    pub preserves_target_feature_semantics: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EquivalenceEvidence {
    pub level: EvidenceLevel,
    pub evidence_digest: EvidenceDigest,
}

pub trait SealedSemanticBlock: Debug + Send + Sync {
    fn content_id(&self) -> ContentId;
    fn semantic_fingerprint(&self) -> SemanticFingerprint;
    fn semantic_version(&self) -> SemanticVersion;
}

pub trait DerivedSemanticBlock: SealedSemanticBlock {
    fn parent_content_id(&self) -> ContentId;
    fn transformation_id(&self) -> TransformationId;
    fn contract(&self) -> TransformationContract;
    fn evidence(&self) -> EquivalenceEvidence;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformationError {
    SourceNotSealed,
    InvalidContract,
    MissingEvidence,
    InsufficientEvidence,
    SemanticVersionMismatch,
    ContentIdentityConflict,
    ValidationFailed,
}

/// A post-seal semantic transformation never mutates `Source` in place.
/// It produces a distinct sealed `Output` with explicit derivation metadata.
pub trait SemanticTransformation: Debug + Send + Sync {
    type Source: SealedSemanticBlock;
    type Output: DerivedSemanticBlock;

    fn id(&self) -> TransformationId;
    fn contract(&self) -> TransformationContract;

    fn derive(&self, source: &Self::Source) -> Result<Self::Output, TransformationError>;
}

/// Policy boundary for deciding whether equivalence evidence is sufficient
/// for a particular fidelity profile.
pub trait TransformationAcceptancePolicy: Debug + Send + Sync {
    fn accepts(
        &self,
        profile: FidelityProfile,
        contract: &TransformationContract,
        evidence: &EquivalenceEvidence,
    ) -> bool;
}

/// Execution artifacts remain bound to the exact sealed semantic source.
pub trait ExecutionArtifactSemanticBinding: Debug + Send + Sync {
    fn source_content_id(&self) -> ContentId;
    fn source_semantic_version(&self) -> SemanticVersion;
}
