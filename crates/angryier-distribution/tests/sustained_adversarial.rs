//! Independent adversarial checks of campaign pinning and prefix ownership.
use angryier_distribution::contracts::{
    BranchPoint, CampaignArtifacts, CampaignManifest, CampaignSpec, ContractError, Digest, ExplorationLimits,
    NamedArtifact, NamedDigest, WorkUnit, validate_owned,
};
use angryier_types::FidelityProfile;

fn manifest() -> Result<CampaignManifest, ContractError> {
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(b"binary"),
        architecture: "x86_64".into(),
        entry_pc: 0x1000,
        semantic_version: "engine-1".into(),
        semantic_profile_digest: Digest::of(b"profile"),
        script_digest: Digest::of(b"script"),
        policy_digest: Digest::of(b"policy"),
        inputs: vec![NamedDigest {
            name: "stdin".into(),
            digest: Digest::of(b"input"),
        }],
        stubs: vec![NamedDigest {
            name: "stub".into(),
            digest: Digest::of(b"stub bytes"),
        }],
        solver_version: "z3".into(),
        solver_policy_digest: Digest::of(b"solver"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 100_000,
            max_path_steps: 100_000,
            max_active_states: 2,
            max_path_depth: 128,
            max_loop_visits: 100_000,
            max_solver_millis: 10_000,
            max_wall_millis: 10_000,
            max_ram_bytes: 1_000_000,
            max_disk_bytes: 1_000_000,
            max_trace_bytes: 1_000_000,
        },
    })
}

fn branch(visit: u64) -> BranchPoint {
    BranchPoint {
        branch_pc: 0x1002,
        visit_index: visit,
        false_target: 0x1004,
        true_target: 0x1008,
        prefix_constraints: visit,
        trace_digest: Digest::of(&visit.to_le_bytes()),
        predicate_digest: Digest::of(b"predicate"),
    }
}

#[test]
fn long_dynamic_prefix_stays_disjoint_and_forged_context_does_not_prove_disjointness() -> Result<(), ContractError> {
    let manifest = manifest()?;
    let mut current = WorkUnit::root(&manifest, 1)?;
    let mut siblings = Vec::new();
    for visit in 0..65 {
        let (left, right) = current.split(&manifest, 1, branch(visit), &siblings)?;
        siblings.push(right);
        current = left;
    }
    assert_eq!(current.prefix.len(), 65);
    assert_eq!(current.prefix[64].branch.visit_index, 64);
    let mut owned = siblings.clone();
    owned.push(current.clone());
    assert_eq!(validate_owned(&owned, &manifest, 1), Ok(()));
    assert_eq!(
        validate_owned(&[current.clone(), current.clone()], &manifest, 1),
        Err(ContractError::Overlap)
    );
    let ancestor = WorkUnit::root(&manifest, 1)?;
    assert_eq!(
        validate_owned(&[ancestor, current], &manifest, 1),
        Err(ContractError::Overlap)
    );
    let mut forged = siblings[0].clone();
    forged.prefix[0].branch.trace_digest = Digest::of(b"different trace");
    assert_eq!(
        validate_owned(
            &[
                owned.last().ok_or(ContractError::Missing("owned leaf"))?.clone(),
                forged
            ],
            &manifest,
            1
        ),
        Err(ContractError::UnprovenDisjointness)
    );
    Ok(())
}

#[test]
fn all_immutable_manifest_fields_change_identity_and_bytes_are_checked_on_resume() -> Result<(), ContractError> {
    let original = manifest()?;
    let mut variants = Vec::new();
    let mut changed = original.spec.clone();
    changed.binary_digest = Digest::of(b"new binary");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.architecture = "arm64".into();
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.entry_pc += 1;
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.semantic_version.push('2');
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.semantic_profile_digest = Digest::of(b"new profile");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.script_digest = Digest::of(b"new script");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.policy_digest = Digest::of(b"new policy");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.inputs[0].digest = Digest::of(b"new input");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.stubs[0].digest = Digest::of(b"new stub");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.solver_version.push('2');
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.solver_policy_digest = Digest::of(b"new solver");
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.fidelity = FidelityProfile::Explore;
    variants.push(changed);
    let mut changed = original.spec.clone();
    changed.limits.max_trace_bytes -= 1;
    variants.push(changed);
    for spec in variants {
        let next = CampaignManifest::seal(spec)?;
        assert_eq!(
            next.validate_resume(&original),
            Err(ContractError::Mismatch("campaign identity"))
        );
    }
    let pinned = CampaignArtifacts {
        binary: b"binary",
        semantic_profile: b"profile",
        script: b"script",
        policy: b"policy",
        solver_policy: b"solver",
        inputs: vec![NamedArtifact {
            name: "stdin",
            bytes: b"input",
        }],
        stubs: vec![NamedArtifact {
            name: "stub",
            bytes: b"stub bytes",
        }],
    };
    assert_eq!(original.validate_artifacts(&pinned), Ok(()));
    let mut missing = pinned.clone();
    missing.inputs.clear();
    assert_eq!(
        original.validate_artifacts(&missing),
        Err(ContractError::Missing("inputs"))
    );
    let mut altered = pinned;
    altered.stubs[0].bytes = b"wrong";
    assert_eq!(
        original.validate_artifacts(&altered),
        Err(ContractError::Mismatch("stubs"))
    );
    Ok(())
}
