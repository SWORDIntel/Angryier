#![forbid(unsafe_code)]

use angryier_solver::{SolverBackend, SolverQuery, SolverResult};
use angryier_types::{ConstraintId, SolverOutcomeKind};
use core::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitwuzlaAdapterError {
    NotLinked,
    ContextCreationFailed,
    TranslationFailed,
}

pub trait BitwuzlaNativeBridge: Send {
    fn solve_bitwuzla(&mut self, query: &SolverQuery) -> Result<SolverResult, BitwuzlaAdapterError>;

    fn solve_bitwuzla_batch(
        &mut self,
        _shared: &[ConstraintId],
        queries: &[SolverQuery],
    ) -> Vec<Result<SolverResult, BitwuzlaAdapterError>> {
        queries.iter().map(|query| self.solve_bitwuzla(query)).collect()
    }
}

#[derive(Debug)]
pub struct BitwuzlaBackend<Bridge> {
    bridge: Bridge,
}

impl<Bridge> BitwuzlaBackend<Bridge> {
    pub fn new(bridge: Bridge) -> Self {
        Self { bridge }
    }

    pub fn into_inner(self) -> Bridge {
        self.bridge
    }
}

impl<Bridge: BitwuzlaNativeBridge> SolverBackend for BitwuzlaBackend<Bridge> {
    fn name(&self) -> &'static str {
        "bitwuzla"
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        if query.validate_identity().is_err() {
            return backend_error();
        }
        self.bridge.solve_bitwuzla(query).unwrap_or_else(|_| backend_error())
    }

    fn solve_batch(&mut self, shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        if predicates.iter().any(|query| query.validate_identity().is_err()) {
            return predicates.iter().map(|_| backend_error()).collect();
        }
        self.bridge
            .solve_bitwuzla_batch(shared, predicates)
            .into_iter()
            .map(|result| result.unwrap_or_else(|_| backend_error()))
            .collect()
    }
}

fn backend_error() -> SolverResult {
    SolverResult {
        outcome: SolverOutcomeKind::BackendError,
        model: Vec::new(),
        unsat_core: Vec::new(),
        elapsed: Duration::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_solver::{CanonicalConstraint, SolverQuery};
    use angryier_types::{ConstraintCanonicalizationVersion, DependencyKey, ExprId, SolverQueryId, TargetProfileId};

    struct UnlinkedBridge;

    impl BitwuzlaNativeBridge for UnlinkedBridge {
        fn solve_bitwuzla(&mut self, _query: &SolverQuery) -> Result<SolverResult, BitwuzlaAdapterError> {
            Err(BitwuzlaAdapterError::NotLinked)
        }
    }

    #[test]
    fn native_failures_are_never_reported_as_unsat() -> Result<(), Box<dyn std::error::Error>> {
        let query = SolverQuery::canonical(
            SolverQueryId(1),
            &[CanonicalConstraint {
                id: ConstraintId(2),
                key: DependencyKey([3; 32]),
            }],
            ExprId(4),
            DependencyKey([5; 32]),
            TargetProfileId(6),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(1),
        )?;
        let mut backend = BitwuzlaBackend::new(UnlinkedBridge);

        assert_eq!(backend.name(), "bitwuzla");
        assert_eq!(backend.solve(&query).outcome, SolverOutcomeKind::BackendError);
        Ok(())
    }
}
