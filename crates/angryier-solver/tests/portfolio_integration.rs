#![forbid(unsafe_code)]

use angryier_solver::{
    BatchSolver, CanonicalConstraint, ConstraintScale, CrossCheckPolicy, InMemoryPortfolioRouter,
    MockCancellableSolverBackend, MockSolverBackend, PredicateComplexity, PreferredBackendHints, QueryShape,
    SolverBackend, SolverOutcomeKind, SolverQuery, SolverRouter, TimeoutCategory,
};
use angryier_types::{
    ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, SolverQueryId, TargetProfileId,
};
use core::time::Duration;

fn make_constraint(id: u64, byte: u8) -> CanonicalConstraint {
    CanonicalConstraint {
        id: ConstraintId(id),
        key: DependencyKey([byte; 32]),
        expr: ExprId(u32::try_from(id).unwrap_or(0)),
    }
}

fn make_query(
    id: u64,
    constraints: &[CanonicalConstraint],
    pred_byte: u8,
    timeout: Duration,
) -> Result<SolverQuery, Box<dyn std::error::Error>> {
    let q = SolverQuery::canonical(
        SolverQueryId(id),
        constraints,
        ExprId(100),
        DependencyKey([pred_byte; 32]),
        TargetProfileId(1),
        ConstraintCanonicalizationVersion(1),
        timeout,
    )?;
    Ok(q)
}

#[test]
fn test_query_shape_classification() -> Result<(), Box<dyn std::error::Error>> {
    let small_c = vec![make_constraint(1, 10)];
    let q_small = make_query(1, &small_c, 3, Duration::from_millis(100))?;
    let shape_small = QueryShape::classify(&q_small);
    assert_eq!(shape_small.constraint_scale, ConstraintScale::Small);
    assert_eq!(shape_small.predicate_complexity, PredicateComplexity::Simple);
    assert_eq!(shape_small.timeout_category, TimeoutCategory::Short);

    let mut large_c = Vec::new();
    for i in 1..=20u64 {
        large_c.push(make_constraint(i, (i as u8).wrapping_mul(7)));
    }
    let q_large = make_query(2, &large_c, 200, Duration::from_secs(10))?;
    let shape_large = QueryShape::classify(&q_large);
    assert_eq!(shape_large.constraint_scale, ConstraintScale::Large);
    assert_eq!(shape_large.predicate_complexity, PredicateComplexity::Complex);
    assert_eq!(shape_large.timeout_category, TimeoutCategory::Long);
    Ok(())
}

#[test]
fn test_per_query_routing_sends_different_queries_based_on_shape() -> Result<(), Box<dyn std::error::Error>> {
    let small_c = vec![make_constraint(1, 10)];
    let q_small = make_query(1, &small_c, 3, Duration::from_millis(100))?;

    let mut large_c = Vec::new();
    for i in 1..=20u64 {
        large_c.push(make_constraint(i, (i as u8).wrapping_mul(7)));
    }
    let q_large = make_query(2, &large_c, 200, Duration::from_secs(10))?;

    let router = InMemoryPortfolioRouter::new(vec!["bitwuzla", "z3"], Duration::from_secs(30));

    let ranked_small = router.rank_backends(&q_small);
    assert_eq!(
        ranked_small,
        vec!["bitwuzla", "z3"],
        "small bitvector query should rank bitwuzla ahead of z3"
    );

    let ranked_large = router.rank_backends(&q_large);
    assert_eq!(
        ranked_large,
        vec!["z3", "bitwuzla"],
        "large complex query should rank z3 ahead of bitwuzla"
    );

    // Verify routing through BatchSolver
    let backends: Vec<Box<dyn SolverBackend>> = vec![
        Box::new(MockSolverBackend::new("bitwuzla", SolverOutcomeKind::Sat)),
        Box::new(MockSolverBackend::new("z3", SolverOutcomeKind::Unsat)),
    ];
    let mut solver = BatchSolver::new(backends, Box::new(router)).with_cross_check(CrossCheckPolicy::new(0.0));

    let res_small = solver.solve_with_fallback(&q_small);
    assert_eq!(res_small.outcome, SolverOutcomeKind::Sat);

    let res_large = solver.solve_with_fallback(&q_large);
    assert_eq!(res_large.outcome, SolverOutcomeKind::Unsat);

    Ok(())
}

#[test]
fn test_per_query_routing_with_custom_hints() -> Result<(), Box<dyn std::error::Error>> {
    let small_c = vec![make_constraint(1, 10)];
    let q_small = make_query(1, &small_c, 3, Duration::from_millis(100))?;

    let mut large_c = Vec::new();
    for i in 1..=20u64 {
        large_c.push(make_constraint(i, (i as u8).wrapping_mul(7)));
    }
    let q_large = make_query(2, &large_c, 200, Duration::from_secs(10))?;

    let hints = PreferredBackendHints {
        preferred_for_small_query: Some("backend_alpha"),
        preferred_for_large_query: Some("backend_beta"),
        ..Default::default()
    };
    let router = InMemoryPortfolioRouter::new_with_hints(
        vec!["backend_alpha", "backend_beta"],
        Duration::from_secs(30),
        Some(hints),
    );

    let ranked_small = router.rank_backends(&q_small);
    assert_eq!(ranked_small, vec!["backend_alpha", "backend_beta"]);

    let ranked_large = router.rank_backends(&q_large);
    assert_eq!(ranked_large, vec!["backend_beta", "backend_alpha"]);

    Ok(())
}

#[test]
fn test_cross_check_policy_routes_to_both_backends() -> Result<(), Box<dyn std::error::Error>> {
    let q = make_query(1, &[make_constraint(1, 10)], 3, Duration::from_secs(1))?;

    let backends: Vec<Box<dyn SolverBackend>> = vec![
        Box::new(MockSolverBackend::new("bitwuzla", SolverOutcomeKind::Unsat)),
        Box::new(MockSolverBackend::new("z3", SolverOutcomeKind::Sat)),
    ];
    let router = Box::new(InMemoryPortfolioRouter::new(
        vec!["bitwuzla", "z3"],
        Duration::from_secs(30),
    ));

    let mut solver = BatchSolver::new(backends, router).with_cross_check(CrossCheckPolicy::new(1.0));

    let res = solver.solve_with_fallback(&q);
    assert_eq!(solver.cross_checks_performed(), 1);
    assert_eq!(solver.cross_check_disagreements(), 1);
    // When bitwuzla (Unsat) and z3 (Sat) disagree, cross-check policy prefers Z3
    assert_eq!(res.outcome, SolverOutcomeKind::Sat);

    Ok(())
}

#[test]
fn test_cross_check_disabled_routes_only_to_first() -> Result<(), Box<dyn std::error::Error>> {
    let q = make_query(1, &[make_constraint(1, 10)], 3, Duration::from_secs(1))?;

    let backends: Vec<Box<dyn SolverBackend>> = vec![
        Box::new(MockSolverBackend::new("bitwuzla", SolverOutcomeKind::Sat)),
        Box::new(MockSolverBackend::new("z3", SolverOutcomeKind::Unsat)),
    ];
    let router = Box::new(InMemoryPortfolioRouter::new(
        vec!["bitwuzla", "z3"],
        Duration::from_secs(30),
    ));

    let mut solver = BatchSolver::new(backends, router).with_cross_check(CrossCheckPolicy::new(0.0));

    let res = solver.solve_with_fallback(&q);
    assert_eq!(solver.cross_checks_performed(), 0);
    assert_eq!(solver.cross_check_disagreements(), 0);
    assert_eq!(res.outcome, SolverOutcomeKind::Sat);

    Ok(())
}

#[test]
fn test_timeout_enforcement_returns_timeout_for_slow_mock() -> Result<(), Box<dyn std::error::Error>> {
    let q = make_query(1, &[make_constraint(1, 10)], 3, Duration::from_millis(50))?;

    let backends: Vec<Box<dyn SolverBackend>> = vec![Box::new(MockSolverBackend::with_delay(
        "slow_backend",
        SolverOutcomeKind::Sat,
        Duration::from_millis(50),
    ))];
    let router = Box::new(InMemoryPortfolioRouter::new(
        vec!["slow_backend"],
        Duration::from_secs(30),
    ));

    let mut solver = BatchSolver::new(backends, router);
    let result = solver.solve_with_timeout(&q, Duration::from_millis(10));
    assert_eq!(result.outcome, SolverOutcomeKind::Timeout);

    Ok(())
}

#[test]
fn test_timeout_enforcement_succeeds_when_within_deadline() -> Result<(), Box<dyn std::error::Error>> {
    let q = make_query(1, &[make_constraint(1, 10)], 3, Duration::from_secs(1))?;

    let backends: Vec<Box<dyn SolverBackend>> =
        vec![Box::new(MockSolverBackend::new("fast_backend", SolverOutcomeKind::Sat))];
    let router = Box::new(InMemoryPortfolioRouter::new(
        vec!["fast_backend"],
        Duration::from_secs(30),
    ));

    let mut solver = BatchSolver::new(backends, router);
    let result = solver.solve_with_timeout(&q, Duration::from_secs(1));
    assert_eq!(result.outcome, SolverOutcomeKind::Sat);

    Ok(())
}

#[test]
fn test_timeout_enforcement_with_cancellable_preemption() -> Result<(), Box<dyn std::error::Error>> {
    let q = make_query(1, &[make_constraint(1, 10)], 3, Duration::from_millis(50))?;

    let cancellable = MockCancellableSolverBackend::new(
        "cancellable_backend",
        SolverOutcomeKind::Sat,
        Duration::from_millis(200),
    );
    let backends: Vec<Box<dyn SolverBackend>> = vec![Box::new(cancellable)];
    let router = Box::new(InMemoryPortfolioRouter::new(
        vec!["cancellable_backend"],
        Duration::from_secs(30),
    ));

    let mut solver = BatchSolver::new(backends, router);
    let result = solver.solve_with_timeout(&q, Duration::from_millis(15));
    assert_eq!(result.outcome, SolverOutcomeKind::Timeout);

    Ok(())
}

#[test]
fn test_history_tracking_influences_routing_after_observed_outcomes() -> Result<(), Box<dyn std::error::Error>> {
    let q = make_query(1, &[make_constraint(1, 10)], 3, Duration::from_secs(1))?;

    let router = InMemoryPortfolioRouter::new(vec!["backend_a", "backend_b"], Duration::from_secs(30));

    // Initially both backends have score 1000, tie breaker keeps backend_a first
    let initial_ranking = router.rank_backends(&q);
    assert_eq!(initial_ranking, vec!["backend_a", "backend_b"]);

    // Record repeated backend errors on backend_a and successes on backend_b
    router.record_outcome("backend_a", SolverOutcomeKind::BackendError, Duration::from_millis(20));
    router.record_outcome("backend_b", SolverOutcomeKind::Sat, Duration::from_millis(5));

    // History tracking should now rank backend_b ahead of backend_a
    let updated_ranking = router.rank_backends(&q);
    assert_eq!(updated_ranking, vec!["backend_b", "backend_a"]);

    // Verify stats were correctly recorded
    let stats_a = router.stats_for("backend_a");
    assert!(stats_a.is_some());
    if let Some(stats) = stats_a {
        assert_eq!(stats.backend_error_count, 1);
        assert_eq!(stats.total_queries, 1);
    }

    let stats_b = router.stats_for("backend_b");
    assert!(stats_b.is_some());
    if let Some(stats) = stats_b {
        assert_eq!(stats.sat_count, 1);
        assert_eq!(stats.total_queries, 1);
    }

    // Verify end-to-end integration via BatchSolver
    let backends: Vec<Box<dyn SolverBackend>> = vec![
        Box::new(MockSolverBackend::new("backend_a", SolverOutcomeKind::BackendError)),
        Box::new(MockSolverBackend::new("backend_b", SolverOutcomeKind::Sat)),
    ];
    let mut solver = BatchSolver::new(backends, Box::new(router)).with_cross_check(CrossCheckPolicy::new(0.0));

    // First query: router starts with backend_b ranked first due to prior history
    let res = solver.solve_with_fallback(&q);
    assert_eq!(res.outcome, SolverOutcomeKind::Sat);

    Ok(())
}

#[cfg(feature = "ffi")]
#[test]
fn test_real_ffi_portfolio_batch_solver() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
    use angryier_solver_bitwuzla::BitwuzlaBackend;
    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;
    use std::sync::Arc;

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));

    // Create x + 3 == 5
    let x = arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: 1u64.to_le_bytes().to_vec(),
        })
        .unwrap_or(ExprId(0));

    let three = arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: 3u64.to_le_bytes().to_vec(),
        })
        .unwrap_or(ExprId(0));

    let five = arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: 5u64.to_le_bytes().to_vec(),
        })
        .unwrap_or(ExprId(0));

    let x_plus_3 = arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![x, three],
            immediate: Vec::new(),
        })
        .unwrap_or(ExprId(0));

    let predicate = arena
        .intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![x_plus_3, five],
            immediate: Vec::new(),
        })
        .unwrap_or(ExprId(0));

    let summary = arena.dependency_summary(predicate);
    let pred_key = summary.map(|s| s.key).unwrap_or(DependencyKey([1; 32]));

    let query = SolverQuery::canonical(
        SolverQueryId(42),
        &[CanonicalConstraint {
            id: ConstraintId(1),
            key: DependencyKey([10; 32]),
            expr: predicate,
        }],
        predicate,
        pred_key,
        TargetProfileId(1),
        ConstraintCanonicalizationVersion(1),
        Duration::from_secs(10),
    )?;

    let z3_backend = Z3Backend::native_ffi(arena.clone())?;
    let bitwuzla_backend = BitwuzlaBackend::native_ffi(arena.clone())?;

    let backends: Vec<Box<dyn SolverBackend>> = vec![Box::new(bitwuzla_backend), Box::new(z3_backend)];
    let router = InMemoryPortfolioRouter::new(vec!["bitwuzla", "z3"], Duration::from_secs(30));

    let mut solver = BatchSolver::new(backends, Box::new(router)).with_cross_check(CrossCheckPolicy::new(1.0));

    let result = solver.solve_with_fallback(&query);
    assert_eq!(result.outcome, SolverOutcomeKind::Sat);
    assert_eq!(solver.cross_checks_performed(), 1);
    assert_eq!(solver.cross_check_disagreements(), 0);

    Ok(())
}
