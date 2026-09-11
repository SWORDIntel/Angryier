#![forbid(unsafe_code)]

//! Canonical cross-crate identity, version, policy, and small value types.
//! This crate owns identifiers that must remain stable across execution, replay,
//! provenance, persistence, and future distribution boundaries.

use sha2::{Digest, Sha256};

pub type Address = u64;

macro_rules! id64 {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(pub u64);
        )+
    };
}

macro_rules! version64 {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(pub u64);
        )+
    };
}

id64!(
    RunId,
    ImageId,
    ModuleId,
    BlockId,
    StateId,
    ConstraintId,
    CodePageId,
    SummaryId,
    ProvenanceNodeId,
    ReplayCapsuleId,
    TargetProfileId,
    SemanticRuleId,
    WorkUnitId,
    TaintId,
    ObjectId,
    EnvironmentModelId,
    SolverQueryId,
    LedgerEpoch,
    ProvenanceSeq,
);

version64!(
    SemanticVersion,
    ContentIdentitySchemaVersion,
    SemanticFingerprintSchemaVersion,
    ExpressionNormalizationVersion,
    ConstraintCanonicalizationVersion,
    EnvironmentModelVersion,
    SummarySchemaVersion,
    ProvenanceSchemaVersion,
    ReplaySchemaVersion,
    EmbeddingModelVersion,
    EmbeddingSchemaVersion,
    KnowledgeSchemaVersion,
    CodePageVersion,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(pub u32);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentDomain {
    SemanticBlock,
    ExecutionIr,
    SolverQuery,
    StateSnapshot,
    ReplayCapsule,
    KnowledgeArtifact,
}

impl ContentDomain {
    const fn tag(self) -> [u8; 4] {
        match self {
            Self::SemanticBlock => *b"SEMA",
            Self::ExecutionIr => *b"EXIR",
            Self::SolverQuery => *b"SOLV",
            Self::StateSnapshot => *b"STAT",
            Self::ReplayCapsule => *b"RPLY",
            Self::KnowledgeArtifact => *b"KNOW",
        }
    }
}

impl ContentId {
    /// Derives an authoritative identity from an already-canonical byte stream.
    ///
    /// The fixed prefix, artifact domain, schema version, and payload length are
    /// included to prevent cross-domain and ambiguous-concatenation reuse.
    pub fn derive(domain: ContentDomain, schema: ContentIdentitySchemaVersion, canonical_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ANGRYIER\0CONTENT\0");
        hasher.update(domain.tag());
        hasher.update(schema.0.to_le_bytes());
        hasher.update((canonical_bytes.len() as u64).to_le_bytes());
        hasher.update(canonical_bytes);
        Self(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticFingerprint(pub [u8; 32]);

impl SemanticFingerprint {
    /// Derives a retrieval/candidate fingerprint from normalized semantic bytes.
    /// A match is advisory and never substitutes for an exact `ContentId`.
    pub fn derive(schema: SemanticFingerprintSchemaVersion, normalized_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ANGRYIER\0SEMANTIC-FINGERPRINT\0");
        hasher.update(schema.0.to_le_bytes());
        hasher.update((normalized_bytes.len() as u64).to_le_bytes());
        hasher.update(normalized_bytes);
        Self(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DependencyKey(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FidelityProfile {
    Prove,
    Explore,
    Hunt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnalysisDebtKind {
    Modelled,
    Summary,
    Concretized,
    Assumed,
    Unsupported,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolverOutcomeKind {
    Sat,
    Unsat,
    Unknown,
    Timeout,
    ResourceLimit,
    BackendError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RetentionProfile {
    Forensic,
    Research,
    Benchmark,
    Disposable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProvenanceTier {
    Tier0,
    Tier1,
    Tier2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodeVersionGuard {
    pub page: CodePageId,
    pub version: CodePageVersion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SecurityContext {
    pub classification: u32,
    pub compartment: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AnalysisContext {
    pub run_id: RunId,
    pub target_profile: TargetProfileId,
    pub fidelity: FidelityProfile,
    pub retention: RetentionProfile,
    pub security: SecurityContext,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_identity_is_deterministic_and_domain_separated() {
        let schema = ContentIdentitySchemaVersion(1);
        let first = ContentId::derive(ContentDomain::SemanticBlock, schema, b"canonical");
        let repeated = ContentId::derive(ContentDomain::SemanticBlock, schema, b"canonical");
        let other_domain = ContentId::derive(ContentDomain::ExecutionIr, schema, b"canonical");
        let other_schema = ContentId::derive(
            ContentDomain::SemanticBlock,
            ContentIdentitySchemaVersion(2),
            b"canonical",
        );
        let other_payload = ContentId::derive(ContentDomain::SemanticBlock, schema, b"canonical!");

        assert_eq!(first, repeated);
        assert_ne!(first, other_domain);
        assert_ne!(first, other_schema);
        assert_ne!(first, other_payload);
    }

    #[test]
    fn semantic_fingerprint_has_an_independent_identity_domain() {
        let bytes = b"canonical semantics";
        let content = ContentId::derive(ContentDomain::SemanticBlock, ContentIdentitySchemaVersion(1), bytes);
        let fingerprint = SemanticFingerprint::derive(SemanticFingerprintSchemaVersion(1), bytes);

        assert_ne!(content.0, fingerprint.0);
    }

    #[test]
    fn payload_length_is_part_of_the_identity_frame() {
        let schema = ContentIdentitySchemaVersion(1);
        let joined = ContentId::derive(ContentDomain::KnowledgeArtifact, schema, b"ab");
        let split_framing = ContentId::derive(ContentDomain::KnowledgeArtifact, schema, b"a\0b");

        assert_ne!(joined, split_framing);
    }
}
