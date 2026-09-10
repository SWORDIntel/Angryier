#![forbid(unsafe_code)]

use angryier_types::{FidelityProfile, RunId};

#[derive(Clone, Debug, PartialEq)]
pub struct BenchmarkRecord {
    pub run: RunId,
    pub case: &'static str,
    pub fidelity: FidelityProfile,
    pub wall_seconds: f64,
    pub states: u64,
    pub solver_queries: u64,
    pub coverage_units: u64,
    pub replay_verified: bool,
    pub semantic_verified: bool,
}

pub trait BenchmarkSink: Send + Sync {
    type Error;
    fn record(&self, result: &BenchmarkRecord) -> Result<(), Self::Error>;
}
