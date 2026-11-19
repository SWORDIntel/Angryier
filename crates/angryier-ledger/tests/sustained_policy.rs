use angryier_distribution::contracts::{BranchPoint, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_ledger::sustained::{ChildDisposition, ReplayDescriptor, SustainedLedger};
use angryier_types::FidelityProfile;
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn manifest() -> Result<CampaignManifest, Box<dyn std::error::Error>> {
    Ok(CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(b"binary"),
        architecture: "x86_64".into(),
        entry_pc: 0x1000,
        semantic_version: "1".into(),
        semantic_profile_digest: Digest::of(b"semantics"),
        script_digest: Digest::of(b"script"),
        policy_digest: Digest::of(b"ranked"),
        inputs: vec![],
        stubs: vec![],
        solver_version: "solver".into(),
        solver_policy_digest: Digest::of(b"solver-policy"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 100,
            max_path_steps: 100,
            max_active_states: 2,
            max_path_depth: 10,
            max_loop_visits: 10,
            max_solver_millis: 100,
            max_wall_millis: 100,
            max_ram_bytes: 100000,
            max_disk_bytes: 100000,
            max_trace_bytes: 10000,
        },
    })?)
}

#[test]
fn ranked_reservation_is_exact_fenced_and_recovers_in_same_order() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-ledger-policy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir)?;
    let path: PathBuf = dir.join("frontier.snap");
    let m = manifest()?;
    let owner = Digest::of(b"owner");
    let mut ledger = SustainedLedger::initialize(
        &path,
        m.clone(),
        1,
        ReplayDescriptor {
            initial_state_digest: Digest::of(b"root"),
        },
    )?;
    let root = ledger
        .reserve()?
        .ok_or_else(|| io::Error::other("initial frontier reservation was unavailable"))?;
    let point = BranchPoint {
        branch_pc: 0x1001,
        visit_index: 0,
        false_target: 0x1010,
        true_target: 0x1020,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"trace"),
        predicate_digest: Digest::of(b"predicate"),
    };
    let (false_child, true_child) = root.unit.split(&m, 1, point, &[])?;
    assert!(
        ledger
            .finish(&root, angryier_ledger::sustained::Status::Excluded, "no policy proof")
            .is_err()
    );
    assert!(
        ledger
            .split(
                &root,
                false_child.clone(),
                true_child.clone(),
                ChildDisposition::Excluded("no proof".into()),
                ChildDisposition::Queued
            )
            .is_err()
    );
    ledger.split(
        &root,
        false_child.clone(),
        true_child.clone(),
        ChildDisposition::Queued,
        ChildDisposition::Queued,
    )?;
    assert_eq!(
        ledger
            .reserve_by_rank_fenced(owner, &[0x1020], &[0x1010])?
            .ok_or_else(|| io::Error::other("ranked reservation was unavailable"))?
            .reservation
            .unit,
        true_child
    );
    drop(ledger);
    let mut recovered = SustainedLedger::open(&path, m)?;
    assert_eq!(recovered.report().queued, 2);
    let first = recovered
        .reserve_by_rank_fenced(owner, &[0x1020], &[0x1010])?
        .ok_or_else(|| io::Error::other("recovered ranked reservation was unavailable"))?;
    assert_eq!(first.reservation.unit, true_child);
    recovered.revoke_fenced(&first)?;
    assert_eq!(
        recovered
            .reserve()?
            .ok_or_else(|| io::Error::other("FIFO reservation was unavailable"))?
            .unit,
        false_child,
        "legacy FIFO unchanged"
    );
    drop(recovered);
    fs::remove_dir_all(&dir)?;
    Ok(())
}
