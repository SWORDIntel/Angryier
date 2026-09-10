#![forbid(unsafe_code)]

use angryier_types::{ConstraintId, DependencyKey, ExprId, SolverOutcomeKind, SolverQueryId};
use core::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverQuery {
    pub id: SolverQueryId,
    pub path_constraints: Vec<ConstraintId>,
    pub predicate: ExprId,
    pub canonical_key: DependencyKey,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolverResult {
    pub outcome: SolverOutcomeKind,
    pub model: Vec<(u64, Vec<u8>)>,
    pub unsat_core: Vec<ConstraintId>,
    pub elapsed: Duration,
}

pub trait SolverBackend: Send {
    fn name(&self) -> &'static str;
    fn solve(&mut self, query: &SolverQuery) -> SolverResult;
    fn solve_batch(&mut self, shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult>;
}

pub trait SolverRouter: Send + Sync {
    fn rank_backends(&self, query: &SolverQuery) -> Vec<&'static str>;
    fn should_preempt(&self, query: &SolverQuery, elapsed: Duration) -> bool;
}
