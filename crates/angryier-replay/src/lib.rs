#![forbid(unsafe_code)]

use angryier_types::{
    AnalysisContext, CodeVersionGuard, ContentId, DependencyKey, ReplayCapsuleId, ReplaySchemaVersion, SemanticVersion,
    StateId,
};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayError {
    SchemaMismatch,
    BinaryMismatch,
    SemanticMismatch,
    CodeVersionMismatch,
    EnvironmentMismatch,
    SchedulerMismatch,
}

pub trait ReplayValidator: Send + Sync {
    fn validate(&self, capsule: &ReplayCapsule) -> Result<(), ReplayError>;
}
pub trait ReplayEngine: Send + Sync {
    type Output;
    fn replay(&self, capsule: &ReplayCapsule) -> Result<Self::Output, ReplayError>;
}
