use angryier_provenance::sustained::{
    BranchEvidence, Completion, DebtKind, DynamicBlock, EdgeBasis, EvidenceBuilder, EvidenceError, EvidenceLimits,
    EvidenceScope, FailureReason, FlowEdge, PathDisposition, PathEvidence, PendingReason, PendingWork,
    ReplayVerification, ScopeClosure, SemanticDebt, SolverDisposition, WitnessEvidence,
};
use angryier_types::FidelityProfile;

fn d(byte: u8) -> [u8; 32] {
    [byte; 32]
}
fn scope() -> EvidenceScope {
    EvidenceScope {
        campaign_digest: d(1),
        contract_epoch: 3,
        bounds_digest: d(2),
        fidelity: FidelityProfile::Explore,
    }
}
fn limits() -> EvidenceLimits {
    EvidenceLimits {
        max_paths: 8,
        max_frontier: 8,
        max_items_per_path: 16,
        max_bytes: 32_000,
    }
}
fn path(id: u8) -> PathEvidence {
    PathEvidence {
        path_id: d(id),
        provenance_digest: d(9),
        fidelity: FidelityProfile::Explore,
        blocks: vec![DynamicBlock {
            pc: 0x100,
            visit_index: 0,
        }],
        edges: vec![],
        branches: vec![],
        witness: None,
        semantic_debt: vec![],
        disposition: PathDisposition::Terminal,
    }
}
fn branch(disposition: SolverDisposition) -> BranchEvidence {
    BranchEvidence {
        pc: 0x100,
        visit_index: 0,
        predicate_digest: d(3),
        query_digest: d(4),
        result_digest: Some(d(5)),
        tested_target: Some(0x300),
        disposition,
    }
}

#[test]
fn observed_edge_is_not_a_solver_proof() -> Result<(), EvidenceError> {
    let mut evidence = EvidenceBuilder::new(scope(), limits())?;
    let mut observed = path(10);
    observed.edges.push(FlowEdge {
        from_pc: 0x100,
        to_pc: 0x200,
        basis: EdgeBasis::Observed { trace_digest: d(6) },
    });
    observed.witness = Some(WitnessEvidence {
        input_digest: d(7),
        replay_input_provenance: None,
        replay_trace: vec![],
        replay: ReplayVerification::NotChecked,
    });
    evidence.add_path(observed)?;
    assert_eq!(evidence.report().summary.observed_edges, 1);
    assert_eq!(evidence.report().summary.infeasible_edges, 0);
    assert_eq!(evidence.report().summary.replay_verified_witnesses, 0);

    let mut false_proof = path(11);
    false_proof.edges.push(FlowEdge {
        from_pc: 0x100,
        to_pc: 0x300,
        basis: EdgeBasis::SolverInfeasible {
            predicate_digest: d(3),
            query_digest: d(4),
            result_digest: d(5),
        },
    });
    assert_eq!(
        evidence.add_path(false_proof.clone()),
        Err(EvidenceError::Invalid("edge evidence"))
    );
    false_proof.branches.push(branch(SolverDisposition::Sat));
    assert_eq!(
        evidence.add_path(false_proof.clone()),
        Err(EvidenceError::Invalid("edge evidence"))
    );
    false_proof.branches[0].disposition = SolverDisposition::Unsat;
    false_proof.branches[0].tested_target = Some(0x400);
    assert_eq!(
        evidence.add_path(false_proof.clone()),
        Err(EvidenceError::Invalid("edge evidence"))
    );
    false_proof.branches[0].tested_target = Some(0x300);
    evidence.add_path(false_proof)?;
    assert_eq!(evidence.report().summary.infeasible_edges, 1);
    assert_eq!(evidence.report().summary.observed_edges, 1);

    let mut contradictory = path(12);
    contradictory.branches.push(branch(SolverDisposition::Unsat));
    contradictory.edges.extend([
        FlowEdge {
            from_pc: 0x100,
            to_pc: 0x300,
            basis: EdgeBasis::Observed { trace_digest: d(6) },
        },
        FlowEdge {
            from_pc: 0x100,
            to_pc: 0x300,
            basis: EdgeBasis::SolverInfeasible {
                predicate_digest: d(3),
                query_digest: d(4),
                result_digest: d(5),
            },
        },
    ]);
    assert_eq!(
        evidence.add_path(contradictory),
        Err(EvidenceError::Invalid("observed edge cannot be infeasible"))
    );
    Ok(())
}

#[test]
fn unknown_timeout_and_deferred_frontier_never_complete() -> Result<(), EvidenceError> {
    for (reason, disposition, expected) in [
        (PendingReason::Unknown, SolverDisposition::Unknown, Completion::Blocked),
        (PendingReason::Timeout, SolverDisposition::Timeout, Completion::Blocked),
        (
            PendingReason::Deferred,
            SolverDisposition::NotQueried,
            Completion::Partial,
        ),
    ] {
        let mut evidence = EvidenceBuilder::new(scope(), limits())?;
        let mut unresolved = path(10);
        unresolved.disposition = PathDisposition::Pending(reason);
        unresolved.branches.push(branch(disposition));
        evidence.add_path(unresolved)?;
        evidence.add_frontier(PendingWork { path_id: d(10), reason })?;
        assert_eq!(evidence.report().summary.completion, expected);
        assert_eq!(evidence.report().frontier.len(), 1);
        assert_eq!(evidence.report().summary.pending_paths, 1);
        assert_eq!(
            evidence.close_owned_scope(ScopeClosure {
                owned_work_units: 1,
                resolved_work_units: 1
            }),
            Err(EvidenceError::Invalid("owned scope not fully resolved"))
        );
    }
    Ok(())
}

#[test]
fn unresolved_solver_cannot_be_labeled_terminal_or_infeasible() -> Result<(), EvidenceError> {
    for disposition in [
        SolverDisposition::Unknown,
        SolverDisposition::Timeout,
        SolverDisposition::ResourceLimit,
        SolverDisposition::BackendError,
    ] {
        let mut evidence = EvidenceBuilder::new(scope(), limits())?;
        let mut misleading = path(10);
        misleading.branches.push(branch(disposition));
        assert_eq!(
            evidence.add_path(misleading),
            Err(EvidenceError::Invalid("unresolved solver on resolved path"))
        );
    }
    let mut evidence = EvidenceBuilder::new(scope(), limits())?;
    let mut misleading = path(10);
    misleading.disposition = PathDisposition::SolverInfeasible;
    assert_eq!(
        evidence.add_path(misleading),
        Err(EvidenceError::Invalid("infeasibility without UNSAT"))
    );
    Ok(())
}

#[test]
fn repeated_pc_paths_are_distinct_but_duplicate_ids_fail() -> Result<(), EvidenceError> {
    let mut evidence = EvidenceBuilder::new(scope(), limits())?;
    evidence.add_path(path(10))?;
    let mut second = path(11);
    second.blocks[0].visit_index = 1;
    evidence.add_path(second)?;
    assert_eq!(evidence.add_path(path(10)), Err(EvidenceError::DuplicatePath));
    assert_eq!(evidence.report().paths.len(), 2);
    assert_eq!(evidence.report().summary.dynamic_blocks, 2);
    Ok(())
}

#[test]
fn scoped_completion_requires_explicit_drained_ownership() -> Result<(), EvidenceError> {
    let mut evidence = EvidenceBuilder::new(scope(), limits())?;
    let mut terminal = path(10);
    terminal.witness = Some(WitnessEvidence {
        input_digest: d(7),
        replay_input_provenance: Some(d(7)),
        replay_trace: terminal.blocks.clone(),
        replay: ReplayVerification::Verified { trace_digest: d(8) },
    });
    terminal.semantic_debt.push(SemanticDebt {
        pc: 0x100,
        kind: DebtKind::ExternalModel,
    });
    evidence.add_path(terminal)?;
    assert_eq!(evidence.report().summary.completion, Completion::Partial);
    assert_eq!(
        evidence.close_owned_scope(ScopeClosure {
            owned_work_units: 2,
            resolved_work_units: 1
        }),
        Err(EvidenceError::Invalid("owned scope not fully resolved"))
    );
    evidence.close_owned_scope(ScopeClosure {
        owned_work_units: 1,
        resolved_work_units: 1,
    })?;
    let summary = evidence.report().summary;
    assert_eq!(summary.completion, Completion::CompleteWithinDeclaredBounds);
    assert_eq!(summary.scope, scope());
    assert_eq!(summary.replay_verified_witnesses, 1);
    assert_eq!(summary.semantic_debt_records, 1);
    assert_eq!(evidence.add_path(path(11)), Err(EvidenceError::Closed));
    Ok(())
}

#[test]
fn exhausted_evidence_fails_closed_without_dropping_existing_records() -> Result<(), EvidenceError> {
    let mut small = limits();
    small.max_paths = 1;
    let mut evidence = EvidenceBuilder::new(scope(), small)?;
    evidence.add_path(path(10))?;
    assert_eq!(evidence.add_path(path(11)), Err(EvidenceError::Exhausted));
    assert_eq!(evidence.report().paths.len(), 1);
    assert_eq!(evidence.report().summary.storage_rejections, 1);
    assert_eq!(evidence.report().summary.completion, Completion::Failed);
    assert!(
        evidence
            .close_owned_scope(ScopeClosure {
                owned_work_units: 1,
                resolved_work_units: 1
            })
            .is_err()
    );

    let mut tiny = limits();
    tiny.max_bytes = 1;
    let mut evidence = EvidenceBuilder::new(scope(), tiny)?;
    assert_eq!(
        evidence.add_frontier(PendingWork {
            path_id: d(10),
            reason: PendingReason::Deferred
        }),
        Err(EvidenceError::Exhausted)
    );
    assert_eq!(evidence.report().summary.completion, Completion::Failed);
    Ok(())
}

#[test]
fn pending_path_without_retained_frontier_is_failed() -> Result<(), EvidenceError> {
    let mut evidence = EvidenceBuilder::new(scope(), limits())?;
    let mut pending = path(10);
    pending.disposition = PathDisposition::Pending(PendingReason::Deferred);
    evidence.add_path(pending)?;
    assert_eq!(evidence.report().summary.completion, Completion::Failed);
    evidence.add_frontier(PendingWork {
        path_id: d(10),
        reason: PendingReason::Deferred,
    })?;
    assert_eq!(evidence.report().summary.completion, Completion::Partial);
    Ok(())
}

#[test]
fn failed_path_does_not_complete() -> Result<(), EvidenceError> {
    let mut evidence = EvidenceBuilder::new(scope(), limits())?;
    let mut failed = path(10);
    failed.disposition = PathDisposition::Failed(FailureReason::Replay);
    evidence.add_path(failed)?;
    assert_eq!(evidence.report().summary.completion, Completion::Failed);
    Ok(())
}
