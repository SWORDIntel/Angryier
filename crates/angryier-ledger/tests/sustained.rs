use angryier_distribution::contracts::{BranchPoint, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_ledger::sustained::{ChildDisposition, Error, ReplayDescriptor, Status, SustainedLedger};
use angryier_types::FidelityProfile;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static ID: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "angryier-frontier-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let path = dir.join("frontier.snap");
        Ok(Self { dir, path })
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn manifest() -> Result<CampaignManifest, angryier_distribution::contracts::ContractError> {
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(b"binary"),
        architecture: "x86_64".into(),
        entry_pc: 0x1000,
        semantic_version: "engine-v1".into(),
        semantic_profile_digest: Digest::of(b"semantics"),
        script_digest: Digest::of(b"script"),
        policy_digest: Digest::of(b"policy"),
        inputs: vec![],
        stubs: vec![],
        solver_version: "solver-v1".into(),
        solver_policy_digest: Digest::of(b"solver-policy"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 100,
            max_path_steps: 100,
            max_active_states: 10,
            max_path_depth: 100,
            max_loop_visits: 100,
            max_solver_millis: 100,
            max_wall_millis: 100,
            max_ram_bytes: 10000,
            max_disk_bytes: 10000,
            max_trace_bytes: 10000,
        },
    })
}
fn seed() -> ReplayDescriptor {
    ReplayDescriptor {
        initial_state_digest: Digest::of(b"initial-state"),
    }
}
fn fork() -> BranchPoint {
    BranchPoint {
        branch_pc: 0x1100,
        visit_index: 0,
        false_target: 0x1102,
        true_target: 0x1120,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"full trace"),
        predicate_digest: Digest::of(b"predicate"),
    }
}

#[test]
fn interruption_requeues_and_fences_reservation() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let old = ledger.reserve()?.ok_or("root missing")?;
    assert_eq!(ledger.report().active, 1);
    drop(ledger); // simulated crash between reserve and finish
    let mut resumed = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(resumed.report().queued, 1);
    let fresh = resumed.reserve()?.ok_or("root missing after recovery")?;
    assert_eq!(fresh.replay, seed());
    assert_ne!(old.attempt, fresh.attempt);
    assert!(matches!(
        resumed.finish(&old, Status::Completed, "stale"),
        Err(Error::StaleReservation)
    ));
    resumed.finish(&fresh, Status::Completed, "replay verified")?;
    drop(resumed);
    let resumed = SustainedLedger::open(&f.path, m)?;
    assert_eq!(resumed.report().completed, 1);
    assert!(resumed.report().complete_within_declared_bounds);
    assert_eq!(resumed.records()[0].replay, seed());
    Ok(())
}

#[test]
fn split_publishes_both_children_and_parent_retirement_together() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root missing")?;
    let (left, right) = root.unit.split(&m, 1, fork(), &[])?;
    ledger.split(
        &root,
        left.clone(),
        right.clone(),
        ChildDisposition::Deferred("budget".into()),
        ChildDisposition::Unknown("solver unknown".into()),
    )?;
    assert!(matches!(
        ledger.split(&root, left, right, ChildDisposition::Queued, ChildDisposition::Queued),
        Err(Error::StaleReservation)
    ));
    drop(ledger);
    let resumed = SustainedLedger::open(&f.path, m)?;
    let report = resumed.report();
    assert_eq!((report.retired_splits, report.deferred, report.unknown), (1, 1, 1));
    assert!(!report.complete_within_declared_bounds);
    assert_eq!(resumed.records().len(), 3);
    assert_eq!(resumed.records()[1].replay, seed());
    Ok(())
}

#[test]
fn deferred_and_unknown_require_explicit_requeue_and_finish() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root missing")?;
    let (left, right) = root.unit.split(&m, 1, fork(), &[])?;
    ledger.split(
        &root,
        left.clone(),
        right.clone(),
        ChildDisposition::Deferred("budget".into()),
        ChildDisposition::Unknown("solver".into()),
    )?;
    assert!(ledger.reserve()?.is_none());
    ledger.requeue(&left)?;
    let reserved = ledger.reserve()?.ok_or("deferred child missing")?;
    ledger.finish(&reserved, Status::Completed, "replay verified")?;
    assert!(!ledger.report().complete_within_declared_bounds);
    ledger.requeue(&right)?;
    let reserved = ledger.reserve()?.ok_or("unknown child missing")?;
    ledger.finish(&reserved, Status::Infeasible, "solver unsat")?;
    assert!(ledger.report().complete_within_declared_bounds);
    drop(ledger);
    assert!(
        SustainedLedger::open(&f.path, m)?
            .report()
            .complete_within_declared_bounds
    );
    Ok(())
}

#[test]
fn orphan_temp_does_not_override_previous_atomic_snapshot() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let active = ledger.reserve()?.ok_or("root missing")?;
    let abandoned = f.path.with_extension("frontier.orphan.tmp");
    fs::write(abandoned, b"torn publication before rename")?;
    drop(ledger);
    let mut ledger = SustainedLedger::open(&f.path, m)?;
    assert_eq!(ledger.report().queued, 1);
    let fresh = ledger.reserve()?.ok_or("root missing")?;
    assert!(fresh.attempt > active.attempt);
    Ok(())
}

#[test]
fn declared_disk_limit_fails_before_publication() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let mut spec = manifest()?.spec;
    spec.limits.max_disk_bytes = 100;
    let m = CampaignManifest::seal(spec)?;
    assert!(matches!(
        SustainedLedger::initialize(&f.path, m, 1, seed()),
        Err(Error::LimitExceeded)
    ));
    assert!(!f.path.exists());
    Ok(())
}

#[test]
fn disk_ceiling_cannot_partially_publish_a_split() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let mut spec = manifest()?.spec;
    // Budget includes the WAL base frame plus the durable recovery-requeue
    // fence written when reopening with an interrupted active reservation.
    spec.limits.max_disk_bytes = 800;
    let m = CampaignManifest::seal(spec)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root missing")?;
    let before = fs::read(&f.path)?;
    let (left, right) = root.unit.split(&m, 1, fork(), &[])?;
    assert!(matches!(
        ledger.split(&root, left, right, ChildDisposition::Queued, ChildDisposition::Queued),
        Err(Error::LimitExceeded)
    ));
    assert_eq!(fs::read(&f.path)?, before);
    assert_eq!((ledger.report().active, ledger.records().len()), (1, 1));
    drop(ledger);
    assert_eq!(SustainedLedger::open(&f.path, m)?.report().queued, 1);
    Ok(())
}

#[test]
fn invalid_split_preserves_parent_and_duplicate_child_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root missing")?;
    let (left, right) = root.unit.split(&m, 1, fork(), &[])?;
    assert!(
        ledger
            .split(
                &root,
                left.clone(),
                left.clone(),
                ChildDisposition::Queued,
                ChildDisposition::Queued
            )
            .is_err()
    );
    assert_eq!(ledger.records().len(), 1);
    ledger.split(
        &root,
        left.clone(),
        right,
        ChildDisposition::Queued,
        ChildDisposition::Queued,
    )?;
    let child = ledger.reserve()?.ok_or("child missing")?;
    // A repeated site without increasing visit index cannot create valid descendants.
    assert!(child.unit.split(&m, 1, fork(), &[]).is_err());
    assert_eq!(ledger.report().active, 1);
    drop(ledger);
    assert_eq!(SustainedLedger::open(&f.path, m)?.records().len(), 3);
    Ok(())
}

#[test]
fn mismatch_checksum_and_torn_snapshot_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    drop(SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?);
    let mut other = m.clone().spec;
    other.policy_digest = Digest::of(b"changed policy");
    let changed = CampaignManifest::seal(other)?;
    assert!(matches!(
        SustainedLedger::open(&f.path, changed),
        Err(Error::MismatchedCampaign)
    ));
    let mut bytes = fs::read(&f.path)?;
    bytes[54] ^= 0x80;
    fs::write(&f.path, &bytes)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));
    fs::write(&f.path, &bytes[..bytes.len() / 2])?;
    assert!(matches!(SustainedLedger::open(&f.path, m), Err(Error::Corrupt)));
    Ok(())
}

#[test]
fn failed_publication_does_not_claim_completion_or_change_disk() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("root missing")?;
    let before = fs::read(&f.path)?;
    assert!(matches!(
        ledger.finish(&reservation, Status::Completed, &"x".repeat(4097)),
        Err(Error::InvalidTransition)
    ));
    assert_eq!(fs::read(&f.path)?, before);
    assert!(!ledger.report().complete_within_declared_bounds);
    drop(ledger);
    assert_eq!(SustainedLedger::open(&f.path, m)?.report().queued, 1);
    Ok(())
}

#[test]
fn second_writer_is_rejected_while_first_holds_lock() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest()?;
    let ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Io(_))));
    drop(ledger);
    assert!(SustainedLedger::open(&f.path, m).is_ok());
    Ok(())
}

/// Removes only the files its relative-path test owns in the test binary's
/// working directory. Names embed the process id and a per-process counter, so
/// parallel tests can never collide or delete each other's files.
struct RelativeCleanup {
    path: PathBuf,
}
impl Drop for RelativeCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(self.path.with_extension("frontier.lock"));
        let _ = fs::remove_file(format!("{}.wal", self.path.display()));
    }
}

#[test]
fn bare_relative_ledger_path_syncs_working_directory() -> Result<(), Box<dyn std::error::Error>> {
    // Regression: initialize() must survive a bare relative filename. Its
    // parent component is empty (not None), so sync_parent opens '' and the
    // checkpoint creation fails with ENOENT unless it fsyncs '.'.
    let name = format!(
        "angryier-relative-{}-{}.snap",
        std::process::id(),
        ID.fetch_add(1, Ordering::Relaxed)
    );
    let path = PathBuf::from(&name);
    let cleanup = RelativeCleanup { path: path.clone() };
    let m = manifest()?;
    let ledger = SustainedLedger::initialize(&path, m.clone(), 1, seed())?;
    assert!(path.exists());
    drop(ledger);
    let resumed = SustainedLedger::open(&path, m)?;
    assert_eq!(resumed.report().queued, 1);
    drop(resumed);
    drop(cleanup);
    Ok(())
}
