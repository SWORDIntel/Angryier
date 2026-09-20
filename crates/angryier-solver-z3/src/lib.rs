#![forbid(unsafe_code)]

use angryier_solver::{SolverBackend, SolverQuery, SolverResult};
use angryier_types::{ConstraintId, SolverOutcomeKind};
use core::time::Duration;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Z3AdapterError {
    NotLinked,
    ContextCreationFailed,
    TranslationFailed,
}

pub trait Z3NativeBridge: Send {
    fn solve_z3(&mut self, query: &SolverQuery) -> Result<SolverResult, Z3AdapterError>;

    fn solve_z3_batch(
        &mut self,
        _shared: &[ConstraintId],
        queries: &[SolverQuery],
    ) -> Vec<Result<SolverResult, Z3AdapterError>> {
        queries.iter().map(|query| self.solve_z3(query)).collect()
    }
}

#[derive(Debug)]
pub struct Z3Backend<Bridge> {
    bridge: Bridge,
}

impl<Bridge> Z3Backend<Bridge> {
    pub fn new(bridge: Bridge) -> Self {
        Self { bridge }
    }

    pub fn into_inner(self) -> Bridge {
        self.bridge
    }
}

impl<Bridge: Z3NativeBridge> SolverBackend for Z3Backend<Bridge> {
    fn name(&self) -> &'static str {
        "z3"
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        if query.validate_identity().is_err() {
            return backend_error();
        }
        self.bridge.solve_z3(query).unwrap_or_else(|_| backend_error())
    }

    fn solve_batch(&mut self, shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        if predicates.iter().any(|query| query.validate_identity().is_err()) {
            return predicates.iter().map(|_| backend_error()).collect();
        }
        self.bridge
            .solve_z3_batch(shared, predicates)
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
// `angryier-solver-z3-ffi` and exposes a constructor that wraps the native Z3
// FFI bridge in the safe `Z3Backend` adapter. The safe adapter validates
// query identity and converts native failures to `BackendError`, so callers
// never observe a false `Unsat` from a native translation/linking failure.

#[cfg(feature = "ffi")]
pub use angryier_solver_z3_ffi::{Z3FfiBridge, Z3FfiError};

#[cfg(feature = "ffi")]
use angryier_expr::ExprReader;
#[cfg(feature = "ffi")]
use std::sync::Arc;

#[cfg(feature = "ffi")]
impl Z3NativeBridge for Z3FfiBridge {
    fn solve_z3(&mut self, query: &SolverQuery) -> Result<SolverResult, Z3AdapterError> {
        let result = angryier_solver::SolverBackend::solve(self, query);
        if result.outcome == SolverOutcomeKind::BackendError {
            Err(Z3AdapterError::TranslationFailed)
        } else {
            Ok(result)
        }
    }

    fn solve_z3_batch(
        &mut self,
        shared: &[ConstraintId],
        queries: &[SolverQuery],
    ) -> Vec<Result<SolverResult, Z3AdapterError>> {
        angryier_solver::SolverBackend::solve_batch(self, shared, queries)
            .into_iter()
            .map(|result| {
                if result.outcome == SolverOutcomeKind::BackendError {
                    Err(Z3AdapterError::TranslationFailed)
                } else {
                    Ok(result)
                }
            })
            .collect()
    }
}

#[cfg(feature = "ffi")]
impl Z3Backend<Z3FfiBridge> {
    /// Creates a `Z3Backend` backed by the native Z3 FFI bridge.
    ///
    /// Requires the `ffi` Cargo feature and a system-installed `libz3`.
    pub fn native_ffi(reader: Arc<dyn ExprReader>) -> Result<Self, Z3FfiError> {
        let bridge = Z3FfiBridge::new(reader)?;
        Ok(Z3Backend::new(bridge))
    }

    /// Interrupts an in-progress  on the underlying context — the
    /// driver can cancel a runaway query from another thread; the query
    /// returns UNKNOWN rather than a wrong answer.
    pub fn interrupt(&self) {
        self.bridge.interrupt();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_solver::{CanonicalConstraint, SolverQuery};
    use angryier_types::{ConstraintCanonicalizationVersion, DependencyKey, ExprId, SolverQueryId, TargetProfileId};

    struct UnlinkedBridge;

    impl Z3NativeBridge for UnlinkedBridge {
        fn solve_z3(&mut self, _query: &SolverQuery) -> Result<SolverResult, Z3AdapterError> {
            Err(Z3AdapterError::NotLinked)
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
        let mut backend = Z3Backend::new(UnlinkedBridge);

        assert_eq!(backend.name(), "z3");
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
        let mut backend = Z3Backend::native_ffi(reader)?;

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
        assert_eq!(backend.name(), "z3");
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
        let mut backend = Z3Backend::native_ffi(reader)?;

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
