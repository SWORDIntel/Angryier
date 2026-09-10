#![forbid(unsafe_code)]

//! Top-level engine orchestration contracts. This crate coordinates subsystems but
//! must not own decoder, solver, database, or JIT implementation details.

pub use angryier_types::{AnalysisContext, FidelityProfile, RunId, TargetProfileId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineMode {
    Normal,
    DeterministicRecord,
    DeterministicReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    pub mode: EngineMode,
    pub context: AnalysisContext,
}

pub trait EngineSubsystem: Send + Sync {
    fn name(&self) -> &'static str;
    fn ready(&self) -> bool;
}

pub trait EngineControl: Send + Sync {
    type Error;
    fn start(&self, config: EngineConfig) -> Result<(), Self::Error>;
    fn stop(&self) -> Result<(), Self::Error>;
}
