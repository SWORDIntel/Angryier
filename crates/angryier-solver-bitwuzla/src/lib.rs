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

// ---------------------------------------------------------------------------
// Native FFI wiring (behind the `ffi` Cargo feature)
// ---------------------------------------------------------------------------
// When the `ffi` feature is enabled, this crate depends on
// `angryier-solver-bitwuzla-ffi` and exposes a constructor that wraps the
// native Bitwuzla FFI bridge in the safe `BitwuzlaBackend` adapter. The safe
// adapter validates query identity and converts native failures to
// `BackendError`, so callers never observe a false `Unsat` from a native
// translation/linking failure.

#[cfg(feature = "ffi")]
pub use angryier_solver_bitwuzla_ffi::{BitwuzlaFfiBridge, BitwuzlaFfiError};

#[cfg(feature = "ffi")]
use angryier_expr::ExprReader;
#[cfg(feature = "ffi")]
use std::sync::Arc;

#[cfg(feature = "ffi")]
impl BitwuzlaNativeBridge for BitwuzlaFfiBridge {
    fn solve_bitwuzla(&mut self, query: &SolverQuery) -> Result<SolverResult, BitwuzlaAdapterError> {
        let result = angryier_solver::SolverBackend::solve(self, query);
        if result.outcome == SolverOutcomeKind::BackendError {
            Err(BitwuzlaAdapterError::TranslationFailed)
        } else {
            Ok(result)
        }
    }

    fn solve_bitwuzla_batch(
        &mut self,
        shared: &[ConstraintId],
        queries: &[SolverQuery],
    ) -> Vec<Result<SolverResult, BitwuzlaAdapterError>> {
        angryier_solver::SolverBackend::solve_batch(self, shared, queries)
            .into_iter()
            .map(|result| {
                if result.outcome == SolverOutcomeKind::BackendError {
                    Err(BitwuzlaAdapterError::TranslationFailed)
                } else {
                    Ok(result)
                }
            })
            .collect()
    }
}

#[cfg(feature = "ffi")]
impl BitwuzlaBackend<BitwuzlaFfiBridge> {
    /// Creates a `BitwuzlaBackend` backed by the native Bitwuzla FFI bridge.
    ///
    /// Requires the `ffi` Cargo feature. `bitwuzla-sys` vendors and builds
    /// Bitwuzla from source, so no system installation is required.
    pub fn native_ffi(reader: Arc<dyn ExprReader>) -> Result<Self, BitwuzlaFfiError> {
        let bridge = BitwuzlaFfiBridge::new(reader)?;
        Ok(BitwuzlaBackend::new(bridge))
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
                expr: ExprId(4),
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

#[cfg(all(test, feature = "ffi"))]
mod ffi_tests {
    use super::*;
    use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
    use angryier_solver::{CanonicalConstraint, SolverQuery};
    use angryier_types::{
        ConstraintCanonicalizationVersion, DependencyKey, ExprId, ExpressionNormalizationVersion, SolverQueryId,
        TargetProfileId,
    };

    fn make_arena() -> Arc<ShardedExprArena> {
        Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)))
    }

    fn make_symbol(arena: &ShardedExprArena, width: u16, sym_id: u64) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: sym_id.to_le_bytes().to_vec(),
            })
            .unwrap_or(ExprId(0))
    }

    fn make_const(arena: &ShardedExprArena, width: u16, value: u128) -> ExprId {
        let byte_width = usize::from(width).div_ceil(8);
        let immediate = value.to_le_bytes()[..byte_width].to_vec();
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate,
            })
            .unwrap_or(ExprId(0))
    }

    fn make_binop(arena: &ShardedExprArena, op: ExprOp, width: u16, left: ExprId, right: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .unwrap_or(ExprId(0))
    }

    fn make_eq(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .unwrap_or(ExprId(0))
    }

    #[test]
    fn native_ffi_backend_solves_sat() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let three = make_const(&arena, 64, 3);
        let five = make_const(&arena, 64, 5);
        let x_plus_3 = make_binop(&arena, ExprOp::Add, 64, x, three);
        let predicate = make_eq(&arena, x_plus_3, five);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut backend = BitwuzlaBackend::native_ffi(reader)?;

        let summary = arena.dependency_summary(predicate);
        let key = summary.map(|s| s.key).unwrap_or(DependencyKey([0; 32]));
        let query = SolverQuery::canonical(
            SolverQueryId(1),
            &[CanonicalConstraint {
                id: ConstraintId(0),
                key: DependencyKey([1; 32]),
                expr: predicate,
            }],
            predicate,
            key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(10),
        )?;
        let result = backend.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        assert_eq!(backend.name(), "bitwuzla");
        Ok(())
    }

    #[test]
    fn native_ffi_backend_solves_unsat() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let two = make_const(&arena, 64, 2);
        let five = make_const(&arena, 64, 5);
        let eq_two = make_eq(&arena, x, two);
        let eq_five = make_eq(&arena, x, five);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut backend = BitwuzlaBackend::native_ffi(reader)?;

        let summary = arena.dependency_summary(eq_two);
        let key = summary.map(|s| s.key).unwrap_or(DependencyKey([0; 32]));
        let query = SolverQuery::canonical(
            SolverQueryId(1),
            &[CanonicalConstraint {
                id: ConstraintId(0),
                key: DependencyKey([1; 32]),
                expr: eq_five,
            }],
            eq_two,
            key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(10),
        )?;
        let result = backend.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Unsat);
        Ok(())
    }
}
