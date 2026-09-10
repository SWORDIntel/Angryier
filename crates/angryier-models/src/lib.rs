#![forbid(unsafe_code)]

use angryier_types::{DependencyKey, EnvironmentModelId, EnvironmentModelVersion, FidelityProfile, SummaryId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SummaryPrecision {
    ExactValidated,
    Approximate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelKey {
    pub id: EnvironmentModelId,
    pub version: EnvironmentModelVersion,
    pub dependency: DependencyKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSummary {
    pub id: SummaryId,
    pub precision: SummaryPrecision,
    pub dependency: DependencyKey,
    pub payload: Vec<u8>,
}

pub trait EnvironmentModel: Send + Sync {
    type State;
    type Error;
    fn key(&self) -> ModelKey;
    fn apply(&self, state: &Self::State, operation: u64, profile: FidelityProfile) -> Result<Self::State, Self::Error>;
}
pub trait SummaryProvider: Send + Sync {
    fn lookup(&self, dependency: DependencyKey) -> Option<FunctionSummary>;
}
