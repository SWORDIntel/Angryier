#![forbid(unsafe_code)]

use angryier_types::{ContentId, ProvenanceNodeId, ProvenanceSeq, ProvenanceTier, StateId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProvenanceEventKind {
    StateFork,
    ConstraintAdded,
    ConstraintRemoved,
    Branch,
    MemoryEffect,
    RegisterEffect,
    SolverQuery,
    SolverResult,
    ModelUse,
    SummaryUse,
    Concretization,
    Approximation,
    JitInvalidation,
    ReplayCheckpoint,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TraceInterest {
    pub novelty: f32,
    pub coverage: f32,
    pub symbolic_depth: f32,
    pub taint_relevance: f32,
    pub solver_cost: f32,
    pub semantic_uncertainty: f32,
    pub approximation: f32,
    pub crash_proximity: f32,
    pub target_proximity: f32,
    pub repetition: f32,
    pub event_rate: f32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceEvent {
    pub id: ProvenanceNodeId,
    pub sequence: ProvenanceSeq,
    pub state: StateId,
    pub tier: ProvenanceTier,
    pub kind: ProvenanceEventKind,
    pub semantic_content: Option<ContentId>,
    pub parents: Vec<ProvenanceNodeId>,
}

pub trait ProvenanceSink: Send + Sync {
    type Error;
    fn publish(&self, events: &[ProvenanceEvent]) -> Result<(), Self::Error>;
}
pub trait TraceGovernor: Send + Sync {
    fn choose_tier(&self, interest: TraceInterest, current: ProvenanceTier) -> ProvenanceTier;
}
