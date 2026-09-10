#![forbid(unsafe_code)]

//! Canonical cross-crate identity, version, policy, and small value types.
//! This crate owns identifiers that must remain stable across execution, replay,
//! provenance, persistence, and future distribution boundaries.

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticFingerprint(pub [u8; 32]);

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
