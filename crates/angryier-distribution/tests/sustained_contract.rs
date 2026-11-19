use angryier_distribution::contracts::{
    BranchDecision, BranchPoint, CampaignArtifacts, CampaignManifest, CampaignSpec, ContractError, Digest,
    ExplorationLimits, NamedArtifact, NamedDigest, Successor, WorkUnit, validate_owned, validate_split,
};
use angryier_types::FidelityProfile;

fn artifacts<'a>() -> CampaignArtifacts<'a> {
    CampaignArtifacts {
        binary: b"binary",
        semantic_profile: b"semantic profile",
        script: b"lua script",
        policy: b"search policy",
        solver_policy: b"solver policy",
        inputs: vec![NamedArtifact {
            name: "stdin",
            bytes: b"seeded stdin",
        }],
        stubs: vec![NamedArtifact {
            name: "load_mem:1000",
            bytes: b"stub bytes",
        }],
    }
}

fn manifest() -> Result<CampaignManifest, ContractError> {
    let bytes = artifacts();
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(bytes.binary),
        architecture: "x86_64".into(),
        entry_pc: 0x1000,
        semantic_version: "engine-1".into(),
        semantic_profile_digest: Digest::of(bytes.semantic_profile),
        script_digest: Digest::of(bytes.script),
        policy_digest: Digest::of(bytes.policy),
        inputs: vec![NamedDigest {
            name: "stdin".into(),
            digest: Digest::of(bytes.inputs[0].bytes),
        }],
        stubs: vec![NamedDigest {
            name: "load_mem:1000".into(),
            digest: Digest::of(bytes.stubs[0].bytes),
        }],
        solver_version: "solver-1".into(),
        solver_policy_digest: Digest::of(bytes.solver_policy),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 10_000,
            max_path_steps: 1_000,
            max_active_states: 64,
            max_path_depth: 10_000,
            max_loop_visits: 10_000,
            max_solver_millis: 10_000,
            max_wall_millis: 10_000,
            max_ram_bytes: 1_000_000,
            max_disk_bytes: 1_000_000,
            max_trace_bytes: 1_000_000,
        },
    })
}

fn fork(pc: u64, visit: u64) -> BranchPoint {
    BranchPoint {
        branch_pc: pc,
        visit_index: visit,
        false_target: 0x10,
        true_target: 0x20,
        prefix_constraints: visit,
        trace_digest: Digest::of(&visit.to_le_bytes()),
        predicate_digest: Digest::of(&[pc.to_le_bytes(), visit.to_le_bytes()].concat()),
    }
}

#[test]
fn pin_all_artifacts_and_reject_changed_or_missing_inputs() -> Result<(), ContractError> {
    let m = manifest()?;
    assert_eq!(m.validate_artifacts(&artifacts()), Ok(()));
    let mut changed = artifacts();
    changed.binary = b"different binary";
    assert_eq!(m.validate_artifacts(&changed), Err(ContractError::Mismatch("binary")));
    changed = artifacts();
    changed.inputs.clear();
    assert_eq!(m.validate_artifacts(&changed), Err(ContractError::Missing("inputs")));
    changed = artifacts();
    changed.stubs[0].bytes = b"changed stub";
    assert_eq!(m.validate_artifacts(&changed), Err(ContractError::Mismatch("stubs")));
    changed = artifacts();
    changed.solver_policy = b"new model";
    assert_eq!(
        m.validate_artifacts(&changed),
        Err(ContractError::Mismatch("solver policy"))
    );
    Ok(())
}

#[test]
fn empty_named_seed_is_present_when_its_digest_matches() -> Result<(), ContractError> {
    let mut spec = manifest()?.spec;
    spec.inputs[0].digest = Digest::of(b"");
    let manifest = CampaignManifest::seal(spec)?;
    let mut bytes = artifacts();
    bytes.inputs[0].bytes = b"";
    assert_eq!(manifest.validate_artifacts(&bytes), Ok(()));
    Ok(())
}

#[test]
fn manifest_identity_is_sealed_and_versioned() -> Result<(), ContractError> {
    let m = manifest()?;
    let mut altered = m.clone();
    altered.spec.limits.max_path_depth += 1;
    assert_eq!(altered.validate(), Err(ContractError::Mismatch("campaign digest")));
    altered = m.clone();
    altered.schema_version += 1;
    assert_eq!(altered.validate(), Err(ContractError::UnsupportedVersion));
    altered = m.clone();
    altered.spec.semantic_version = "new semantics".into();
    altered = CampaignManifest::seal(altered.spec)?;
    assert_eq!(
        altered.validate_resume(&m),
        Err(ContractError::Mismatch("campaign identity"))
    );
    let mut incomplete = m.spec;
    incomplete.inputs.push(incomplete.inputs[0].clone());
    assert!(matches!(
        CampaignManifest::seal(incomplete),
        Err(ContractError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn deep_repeated_branch_site_has_full_prefix_and_prefix_free_frontier() -> Result<(), ContractError> {
    let m = manifest()?;
    let mut current = WorkUnit::root(&m, 8)?;
    let mut owned = Vec::new();
    for visit in 0..100 {
        let (false_child, true_child) = current.split(&m, 8, fork(0x1000, visit), &owned)?;
        validate_split(&current, &false_child, &true_child, &m, 8)?;
        assert_eq!(false_child.prefix.last().map(BranchDecision::target), Some(0x10));
        assert_eq!(true_child.prefix.last().map(BranchDecision::target), Some(0x20));
        owned.push(true_child);
        current = false_child;
    }
    assert_eq!(current.prefix.len(), 100);
    assert_eq!(current.prefix[0].branch.visit_index, 0);
    assert_eq!(current.prefix[99].branch.visit_index, 99);
    owned.push(current);
    validate_owned(&owned, &m, 8)?;
    Ok(())
}

#[test]
fn reject_overlap_ambiguous_context_and_false_splits() -> Result<(), ContractError> {
    let m = manifest()?;
    let root = WorkUnit::root(&m, 2)?;
    let (left, right) = root.split(&m, 2, fork(0x1000, 0), &[])?;
    assert_eq!(validate_owned(&[left.clone(), right.clone()], &m, 2), Ok(()));
    assert_eq!(
        validate_owned(&[root.clone(), left.clone()], &m, 2),
        Err(ContractError::Overlap)
    );
    assert_eq!(
        root.split(&m, 2, fork(0x1000, 0), std::slice::from_ref(&left)),
        Err(ContractError::Overlap)
    );
    assert_eq!(
        validate_split(&root, &left, &left, &m, 2),
        Err(ContractError::Invalid(
            "split must cover parent with complementary fork edges"
        ))
    );
    let mut forged = right.clone();
    forged.prefix[0].branch.trace_digest = Digest::of(b"different replay context");
    assert_eq!(
        validate_owned(&[left.clone(), forged.clone()], &m, 2),
        Err(ContractError::UnprovenDisjointness)
    );
    assert_eq!(
        validate_split(&root, &left, &forged, &m, 2),
        Err(ContractError::Invalid(
            "split must cover parent with complementary fork edges"
        ))
    );
    let mut duplicate_visit = left;
    duplicate_visit.prefix.push(BranchDecision {
        branch: fork(0x1000, 0),
        successor: Successor::False,
    });
    assert!(matches!(
        duplicate_visit.validate(&m, 2),
        Err(ContractError::Invalid(_))
    ));
    Ok(())
}

#[test]
fn reject_mismatched_campaign_version_epoch_and_malformed_prefix() -> Result<(), ContractError> {
    let m = manifest()?;
    let root = WorkUnit::root(&m, 5)?;
    assert_eq!(root.validate(&m, 6), Err(ContractError::StaleEpoch));
    let mut wrong = root.clone();
    wrong.schema_version = 2;
    assert_eq!(wrong.validate(&m, 5), Err(ContractError::UnsupportedVersion));
    wrong = root.clone();
    wrong.campaign_digest = Digest::of(b"other campaign");
    assert_eq!(wrong.validate(&m, 5), Err(ContractError::Mismatch("work campaign")));
    let mut bad = root.clone();
    bad.prefix.push(BranchDecision {
        branch: fork(0x1000, 0),
        successor: Successor::True,
    });
    bad.prefix[0].branch.predicate_digest = Digest::default();
    assert_eq!(
        bad.validate(&m, 5),
        Err(ContractError::Missing("branch replay context"))
    );
    assert!(matches!(WorkUnit::root(&m, 0), Err(ContractError::Invalid(_))));
    assert_eq!(root.split(&m, 6, fork(0x1000, 0), &[]), Err(ContractError::StaleEpoch));
    Ok(())
}

#[test]
fn reject_prefix_beyond_declared_depth_without_truncating_it() -> Result<(), ContractError> {
    let mut spec = manifest()?.spec;
    spec.limits.max_path_depth = 1;
    let m = CampaignManifest::seal(spec)?;
    let root = WorkUnit::root(&m, 1)?;
    let (first, _) = root.split(&m, 1, fork(0x1000, 0), &[])?;
    assert_eq!(first.prefix.len(), 1);
    assert_eq!(
        first.split(&m, 1, fork(0x1000, 1), &[]),
        Err(ContractError::Invalid("prefix exceeds declared depth"))
    );
    Ok(())
}
