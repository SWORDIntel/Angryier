#![forbid(unsafe_code)]

use angryier_types::{StateId, WorkUnitId};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SearchScore {
    pub coverage_novelty: f64,
    pub taint_relevance: f64,
    pub target_proximity: f64,
    pub solver_cost: f64,
    pub uncertainty: f64,
    pub learned_advisory: f64,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StealCost {
    pub load_gain: f64,
    pub solver_rebuild_cost: f64,
    pub numa_cost: f64,
    pub cache_locality_loss: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScheduleDecision {
    pub work: WorkUnitId,
    pub state: StateId,
    pub worker: u32,
    pub sequence: u64,
}

pub trait Scheduler: Send + Sync {
    fn enqueue(&self, state: StateId, score: SearchScore);
    fn next(&self, worker: u32) -> Option<StateId>;
    fn steal_cost(&self, state: StateId, from_worker: u32, to_worker: u32) -> StealCost;
}
