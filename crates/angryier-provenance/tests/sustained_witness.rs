use angryier_provenance::sustained::{
    BranchEvidence, DebtKind, DynamicBlock, EdgeBasis, EvidenceBuilder, EvidenceError, EvidenceLimits, EvidenceScope,
    FlowEdge, PathDisposition, PathEvidence, PendingReason, PendingWork, ReplayVerification, SemanticDebt,
    SolverDisposition, WitnessEvidence,
};
use angryier_types::FidelityProfile;

fn d(byte: u8) -> [u8; 32] {
    [byte; 32]
}
fn builder() -> Result<EvidenceBuilder, EvidenceError> {
    EvidenceBuilder::new(
        EvidenceScope {
            campaign_digest: d(1),
            contract_epoch: 1,
            bounds_digest: d(2),
            fidelity: FidelityProfile::Explore,
        },
        EvidenceLimits {
            max_paths: 8,
            max_frontier: 8,
            max_items_per_path: 40,
            max_bytes: 32_000,
        },
    )
}
fn path(id: u8, disposition: PathDisposition) -> PathEvidence {
    PathEvidence {
        path_id: d(id),
        provenance_digest: d(3),
        fidelity: FidelityProfile::Explore,
        blocks: vec![
            DynamicBlock {
                pc: 0x100,
                visit_index: 0,
            },
            DynamicBlock {
                pc: 0x100,
                visit_index: 1,
            },
        ],
        edges: vec![],
        branches: vec![],
        witness: None,
        semantic_debt: vec![],
        disposition,
    }
}

#[test]
fn sat_and_forged_replay_are_not_verified_witnesses() -> Result<(), EvidenceError> {
    let mut evidence = builder()?;
    let mut candidate = path(10, PathDisposition::Terminal);
    candidate.branches.push(BranchEvidence {
        pc: 0x100,
        visit_index: 1,
        predicate_digest: d(4),
        query_digest: d(5),
        result_digest: Some(d(6)),
        tested_target: Some(0x200),
        disposition: SolverDisposition::Sat,
    });
    candidate.witness = Some(WitnessEvidence {
        input_digest: d(7),
        replay_input_provenance: None,
        replay_trace: vec![],
        replay: ReplayVerification::NotChecked,
    });
    evidence.add_path(candidate.clone())?;
    assert_eq!(evidence.report().summary.replay_verified_witnesses, 0);
    candidate.path_id = d(11);
    candidate
        .witness
        .as_mut()
        .ok_or(EvidenceError::Invalid("witness evidence"))?
        .replay = ReplayVerification::Verified { trace_digest: d(8) };
    assert_eq!(
        evidence.add_path(candidate.clone()),
        Err(EvidenceError::Invalid("witness evidence"))
    );
    candidate
        .witness
        .as_mut()
        .ok_or(EvidenceError::Invalid("witness evidence"))?
        .replay_input_provenance = Some(d(9));
    assert_eq!(
        evidence.add_path(candidate.clone()),
        Err(EvidenceError::Invalid("witness evidence"))
    );
    candidate
        .witness
        .as_mut()
        .ok_or(EvidenceError::Invalid("witness evidence"))?
        .replay_trace = vec![candidate.blocks[0]];
    assert_eq!(
        evidence.add_path(candidate.clone()),
        Err(EvidenceError::Invalid("witness evidence"))
    );
    candidate
        .witness
        .as_mut()
        .ok_or(EvidenceError::Invalid("witness evidence"))?
        .replay_trace = candidate.blocks.clone();
    evidence.add_path(candidate)?;
    assert_eq!(evidence.report().summary.replay_verified_witnesses, 1);
    Ok(())
}

#[test]
fn cumulative_flow_preserves_paths_visits_dispositions_and_evidence() -> Result<(), EvidenceError> {
    let mut evidence = builder()?;
    let mut observed = path(10, PathDisposition::Terminal);
    observed.edges.push(FlowEdge {
        from_pc: 0x100,
        to_pc: 0x200,
        basis: EdgeBasis::Observed { trace_digest: d(8) },
    });
    observed.semantic_debt.push(SemanticDebt {
        pc: 0x100,
        kind: DebtKind::ExternalModel,
    });
    evidence.add_path(observed)?;
    let mut pending = path(11, PathDisposition::Pending(PendingReason::Unknown));
    pending.edges.push(FlowEdge {
        from_pc: 0x100,
        to_pc: 0x200,
        basis: EdgeBasis::StaticInference { analysis_digest: d(9) },
    });
    pending.branches.push(BranchEvidence {
        pc: 0x100,
        visit_index: 1,
        predicate_digest: d(4),
        query_digest: d(5),
        result_digest: Some(d(6)),
        tested_target: Some(0x200),
        disposition: SolverDisposition::Unknown,
    });
    evidence.add_path(pending)?;
    evidence.add_frontier(PendingWork {
        path_id: d(11),
        reason: PendingReason::Unknown,
    })?;
    let mut infeasible = path(12, PathDisposition::SolverInfeasible);
    infeasible.branches.push(BranchEvidence {
        pc: 0x100,
        visit_index: 1,
        predicate_digest: d(4),
        query_digest: d(5),
        result_digest: Some(d(6)),
        tested_target: Some(0x200),
        disposition: SolverDisposition::Unsat,
    });
    infeasible.edges.push(FlowEdge {
        from_pc: 0x100,
        to_pc: 0x200,
        basis: EdgeBasis::SolverInfeasible {
            predicate_digest: d(4),
            query_digest: d(5),
            result_digest: d(6),
        },
    });
    evidence.add_path(infeasible)?;
    let graph = evidence.flow_graph(12, 4096)?;
    assert_eq!(graph.blocks.len(), 6);
    assert_eq!(graph.edges.len(), 3);
    assert_eq!(
        graph.edges.iter().map(|e| e.from_visit_index).collect::<Vec<_>>(),
        vec![None, None, Some(1)]
    );
    assert_eq!(
        graph.edges.iter().map(|e| e.path_id).collect::<Vec<_>>(),
        vec![d(10), d(11), d(12)]
    );
    assert_eq!(graph.summary.observed_edges, 1);
    assert_eq!(graph.summary.inferred_edges, 1);
    assert_eq!(graph.summary.infeasible_edges, 1);
    assert_eq!(graph.summary.semantic_debt_records, 1);
    assert_eq!(graph.paths[1].branches[0].disposition, SolverDisposition::Unknown);
    assert_eq!(graph.paths[2].branches[0].query_digest, d(5));
    assert_eq!(evidence.flow_graph(11, 4096).err(), Some(EvidenceError::Exhausted));
    assert_eq!(evidence.flow_graph(12, 1).err(), Some(EvidenceError::Exhausted));
    assert_eq!(evidence.report().paths.len(), 3);
    Ok(())
}
