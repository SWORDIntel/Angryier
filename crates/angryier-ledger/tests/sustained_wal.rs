//! Durability and recovery tests for the append-only WAL sidecar: startup and
//! reopen replay, active-grant fence invalidation, atomic split plus evidence,
//! torn-tail tolerance versus interior corruption rejection, manifest and
//! generation mismatch, sealed file budget fail-closed behavior, monotonic
//! sequences, and legacy snapshot migration.
use angryier_distribution::contracts::{
    BranchPoint, CampaignManifest, CampaignSpec, Digest, ExplorationLimits, Successor,
};
use angryier_ledger::{
    evidence::{
        BranchEvidence, DynamicBlock, EdgeBasis, EvidenceDelta, FlowEdge, PathDisposition, PathEvidence, PendingReason,
        ReplayVerification, SolverDisposition, WitnessEvidence,
    },
    sustained::{
        ChildDisposition, Error, Record, ReplayDescriptor, Reservation, Status, SustainedLedger, work_path_id,
    },
};
use angryier_types::FidelityProfile;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Instant,
};

static ID: AtomicU64 = AtomicU64::new(0);
struct Fixture {
    dir: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "angryier-wal-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let path = dir.join("frontier.snap");
        Ok(Self { dir, path })
    }
    fn wal_path(&self) -> PathBuf {
        self.path.with_extension("snap.wal")
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
fn manifest(max_disk_bytes: u64) -> Result<CampaignManifest, Box<dyn std::error::Error>> {
    Ok(CampaignManifest::seal(CampaignSpec {
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
            max_disk_bytes,
            max_trace_bytes: 10000,
        },
    })?)
}
fn seed() -> ReplayDescriptor {
    ReplayDescriptor {
        initial_state_digest: Digest::of(b"seed"),
    }
}
fn delta(reservation: &Reservation, disposition: PathDisposition) -> EvidenceDelta {
    let blocks = vec![
        DynamicBlock {
            pc: 0x1000,
            visit_index: 0,
        },
        DynamicBlock {
            pc: 0x1010,
            visit_index: 0,
        },
    ];
    EvidenceDelta {
        sequence: 1,
        path: PathEvidence {
            path_id: work_path_id(&reservation.unit, &reservation.replay).0,
            provenance_digest: Digest::of(b"provenance").0,
            fidelity: FidelityProfile::Prove,
            blocks: blocks.clone(),
            edges: vec![FlowEdge {
                from_pc: 0x1000,
                to_pc: 0x1010,
                basis: EdgeBasis::Observed {
                    trace_digest: Digest::of(b"trace").0,
                },
            }],
            branches: vec![],
            witness: Some(WitnessEvidence {
                input_digest: Digest::of(b"input").0,
                replay_input_provenance: Some(Digest::of(b"pinned-input").0),
                replay_trace: blocks,
                replay: ReplayVerification::Verified {
                    trace_digest: Digest::of(b"verified-replay").0,
                },
            }),
            semantic_debt: vec![],
            disposition,
        },
    }
}
fn terminal(reservation: &Reservation) -> EvidenceDelta {
    delta(reservation, PathDisposition::Terminal)
}
/// Durable state bytes in the WAL (base frame plus transactions).
fn logical(path: &std::path::Path) -> u64 {
    fs::metadata(path.with_extension("snap.wal")).map_or(0, |m| m.len()) - 116
}
/// Frame extents in a WAL file: (start, end) with end including the checksum.
fn wal_frames(bytes: &[u8]) -> Result<Vec<(usize, usize)>, Box<dyn std::error::Error>> {
    let mut frames = Vec::new();
    let mut pos = 116usize; // ANGFRWAL header
    while pos < bytes.len() {
        // kind(1) + generation(8) + seq(8) + payload_len(4)
        let payload_len = u32::from_le_bytes(bytes[pos + 17..pos + 21].try_into()?) as usize;
        let end = pos + 21 + payload_len + 32;
        frames.push((pos, end));
        pos = end;
    }
    Ok(frames)
}
fn rechecksum_header(bytes: &mut [u8]) {
    let digest = Digest::of(&bytes[..84]);
    bytes[84..116].copy_from_slice(&digest.0);
}

#[test]
fn wal_startup_reopen_replays_records_and_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    assert_eq!(ledger.durable_sequence(), None);
    assert!(!f.wal_path().exists());
    let reservation = ledger.reserve()?.ok_or("root")?;
    assert_eq!(ledger.durable_sequence(), Some(1));
    assert!(f.wal_path().exists());
    ledger.commit_outcome(&reservation, Status::Completed, "replayed", terminal(&reservation))?;
    assert_eq!(ledger.durable_sequence(), Some(2));
    let wal_len = fs::metadata(f.wal_path())?.len();
    drop(ledger);

    let reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert!(reopened.report().complete_within_declared_bounds);
    assert_eq!(reopened.read_snapshot().0.len(), 1);
    assert_eq!(reopened.read_snapshot().1.len(), 1);
    assert_eq!(reopened.read_snapshot().1[0].delta, terminal(&reservation));
    assert_eq!(reopened.durable_sequence(), Some(2));
    drop(reopened);
    // A reopen without transitions appends nothing.
    let again = SustainedLedger::open(&f.path, m)?;
    assert_eq!(fs::metadata(f.wal_path())?.len(), wal_len);
    assert_eq!(again.durable_sequence(), Some(2));
    Ok(())
}

#[test]
fn active_grant_fence_is_invalidated_by_recovery_requeue() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let alice = Digest::of(b"alice");
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let first = ledger.reserve_fenced(alice)?.ok_or("root")?;
    drop(ledger); // crash between fenced reserve and finish

    let mut resumed = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(resumed.report().queued, 1);
    assert!(matches!(
        resumed.commit_outcome_fenced(&first, Status::Completed, "stale", terminal(&first.reservation)),
        Err(Error::StaleReservation)
    ));
    let second = resumed.reserve_fenced(alice)?.ok_or("recovered root")?;
    assert!(second.ownership_epoch > first.ownership_epoch);
    assert!(second.reservation.attempt > first.reservation.attempt);
    resumed.commit_outcome_fenced(&second, Status::Completed, "replayed", terminal(&second.reservation))?;
    drop(resumed);
    assert!(
        SustainedLedger::open(&f.path, m)?
            .report()
            .complete_within_declared_bounds
    );
    Ok(())
}

#[test]
fn atomic_split_with_two_events_and_torn_tail_discards_whole_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let owner = Digest::of(b"owner");
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let grant = ledger.reserve_fenced(owner)?.ok_or("missing root")?;
    let root = &grant.reservation;
    let fork = BranchPoint {
        branch_pc: 0x1010,
        visit_index: 0,
        false_target: 0x1012,
        true_target: 0x1020,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"observed fork trace"),
        predicate_digest: Digest::of(b"fork predicate"),
    };
    let (left, right) = root.unit.split(&m, 1, fork.clone(), &[])?;
    let unsat = BranchEvidence {
        pc: fork.branch_pc,
        visit_index: fork.visit_index,
        predicate_digest: fork.predicate_digest.0,
        query_digest: Digest::of(b"false query").0,
        result_digest: Some(Digest::of(b"false UNSAT").0),
        tested_target: Some(fork.false_target),
        disposition: SolverDisposition::Unsat,
    };
    let sat = BranchEvidence {
        tested_target: Some(fork.true_target),
        query_digest: Digest::of(b"true query").0,
        result_digest: Some(Digest::of(b"true SAT").0),
        disposition: SolverDisposition::Sat,
        ..unsat
    };
    let mut parent = delta(root, PathDisposition::Pending(PendingReason::Queued));
    parent.path.provenance_digest = fork.trace_digest.0;
    parent.path.branches = vec![unsat, sat];
    let mut child = parent.clone();
    child.path.path_id = work_path_id(&left, &root.replay).0;
    child.path.disposition = PathDisposition::SolverInfeasible;
    child.path.witness = None;
    child.path.branches = vec![unsat];
    child.path.edges.push(FlowEdge {
        from_pc: fork.branch_pc,
        to_pc: fork.false_target,
        basis: EdgeBasis::SolverInfeasible {
            predicate_digest: unsat.predicate_digest,
            query_digest: unsat.query_digest,
            result_digest: unsat.result_digest.ok_or("result")?,
        },
    });
    ledger.split_with_proofs_fenced(
        &grant,
        left.clone(),
        right.clone(),
        ChildDisposition::Infeasible("solver UNSAT".into()),
        ChildDisposition::Queued,
        angryier_ledger::sustained::SplitProofs {
            delta: parent.clone(),
            child_proofs: [Some(child.clone()), None],
        },
    )?;
    // One WAL frame holds the parent retirement, both children, and both events.
    assert_eq!(ledger.durable_sequence(), Some(2));
    assert_eq!(ledger.read_snapshot().1.len(), 2);
    drop(ledger);

    let reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(reopened.records().len(), 3);
    assert_eq!(reopened.read_snapshot().1.len(), 2);
    assert_eq!(
        (
            reopened.report().retired_splits,
            reopened.report().infeasible,
            reopened.report().queued
        ),
        (1, 1, 1)
    );
    assert_eq!(reopened.read_snapshot().1[1].delta, child);
    drop(reopened);

    // A torn final append of the split frame discards the WHOLE transaction:
    // no parent retirement, no children, no evidence.
    let wal = fs::read(f.wal_path())?;
    let frames = wal_frames(&wal)?;
    let split_frame = *frames.last().ok_or("split frame")?;
    fs::write(f.wal_path(), &wal[..split_frame.0 + 12])?;
    let reopened = SustainedLedger::open(&f.path, m)?;
    assert_eq!(reopened.records().len(), 1);
    assert!(reopened.read_snapshot().1.is_empty());
    assert_eq!(
        reopened.report().queued,
        1,
        "interrupted active root is durably requeued"
    );
    assert_eq!(
        reopened.durable_sequence(),
        Some(2),
        "requeue fence is a new durable transaction"
    );
    Ok(())
}

#[test]
fn torn_final_append_truncates_but_interior_corruption_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    // Torn final frame: tolerated by truncation to the last valid frame.
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    ledger.reserve()?.ok_or("root")?;
    drop(ledger);
    let wal = fs::read(f.wal_path())?;
    let frames = wal_frames(&wal)?;
    assert_eq!(frames.len(), 2); // base + reserve
    let torn_at = frames[1].0 + 8;
    fs::write(f.wal_path(), &wal[..torn_at])?;
    let reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(reopened.records()[0].attempt, 0, "torn reserve was never acknowledged");
    assert_eq!(reopened.report().queued, 1);
    assert_eq!(logical(&f.path), frames[1].0 as u64 - 116);
    drop(reopened);

    // Interior corruption of a complete frame: rejected, never silently skipped.
    fs::write(f.wal_path(), &wal)?;
    let mut interior = wal.clone();
    interior[frames[1].0 + 21] ^= 1;
    fs::write(f.wal_path(), interior)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));

    // A complete final frame with a bad checksum is corruption too, not a torn append.
    let mut checksummed = wal.clone();
    checksummed[frames[1].1 - 1] ^= 1;
    fs::write(f.wal_path(), checksummed)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));

    // A complete final frame whose payload was edited (checksum now bad): rejected.
    let mut edited = wal;
    edited[frames[1].0 + 25] ^= 0x80;
    fs::write(f.wal_path(), edited)?;
    assert!(matches!(SustainedLedger::open(&f.path, m), Err(Error::Corrupt)));
    Ok(())
}

/// A corrupted payload_len on an *interior* frame that points past EOF has the
/// same shape as a torn final append, but acknowledged frames remain behind it.
/// Recovery must fail closed without truncating them. When no valid later frame
/// exists, a corrupted final frame length cannot be told apart from a torn
/// unsynced tail, so the bounded probe still permits that truncation (the real
/// torn-tail cases are exercised above and in the migration crash test).
#[test]
fn interior_length_past_eof_rejects_without_truncation() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("root")?;
    ledger.commit_outcome(&reservation, Status::Completed, "done", terminal(&reservation))?;
    assert_eq!(ledger.durable_sequence(), Some(2));
    drop(ledger);

    let wal = fs::read(f.wal_path())?;
    let frames = wal_frames(&wal)?;
    assert_eq!(frames.len(), 3); // base + reserve + outcome
    // Corrupt the interior reserve frame's payload_len to run past EOF while
    // the acknowledged outcome frame behind it stays fully intact.
    let mut corrupted = wal;
    corrupted[frames[1].0 + 17..frames[1].0 + 21].copy_from_slice(&u32::MAX.to_le_bytes());
    fs::write(f.wal_path(), &corrupted)?;
    assert!(
        matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)),
        "interior length corruption must fail closed"
    );
    assert_eq!(
        fs::read(f.wal_path())?,
        corrupted,
        "rejection must not truncate acknowledged later frames"
    );
    Ok(())
}

#[test]
fn mismatched_manifest_generation_and_anchor_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    ledger.reserve()?.ok_or("root")?;
    drop(ledger);
    let snap_original = fs::read(&f.path)?;
    let wal_original = fs::read(f.wal_path())?;

    // Different campaign: rejected at the tombstone before any replay.
    let mut spec = m.clone().spec;
    spec.policy_digest = Digest::of(b"changed policy");
    let changed = CampaignManifest::seal(spec)?;
    assert!(matches!(
        SustainedLedger::open(&f.path, changed),
        Err(Error::MismatchedCampaign)
    ));

    // WAL header with a different manifest: rejected even with a valid checksum.
    let mut wal = wal_original.clone();
    wal[20] ^= 1; // manifest digest byte
    rechecksum_header(&mut wal);
    fs::write(f.wal_path(), &wal)?;
    assert!(matches!(
        SustainedLedger::open(&f.path, m.clone()),
        Err(Error::MismatchedCampaign)
    ));
    fs::write(f.wal_path(), &wal_original)?;

    // Tombstone generation corruption: rejected.
    let mut snap = snap_original.clone();
    snap[12] ^= 1; // generation byte
    let digest = Digest::of(&snap[..52]);
    snap[52..84].copy_from_slice(&digest.0);
    fs::write(&f.path, snap)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));
    fs::write(&f.path, &snap_original)?;

    // Rollback: a restored base checkpoint whose hash no longer matches the WAL
    // anchor fails closed instead of accepting stale state.
    let frames = wal_frames(&wal_original)?;
    let base = wal_original[frames[0].0 + 21..frames[0].1 - 32].to_vec();
    fs::write(&f.path, &base)?;
    let mut wal = wal_original;
    wal[52] ^= 1; // anchor byte
    rechecksum_header(&mut wal);
    fs::write(f.wal_path(), wal)?;
    assert!(matches!(SustainedLedger::open(&f.path, m), Err(Error::Corrupt)));
    Ok(())
}

#[test]
fn sealed_budget_is_enforced_and_full_wal_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    let probe = Fixture::new()?;
    let big = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&probe.path, big.clone(), 1, seed())?;
    let fork = BranchPoint {
        branch_pc: 0x1100,
        visit_index: 0,
        false_target: 0x1102,
        true_target: 0x1120,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"trace"),
        predicate_digest: Digest::of(b"predicate"),
    };
    let root = ledger.reserve()?.ok_or("probe root")?;
    let (left, right) = root.unit.split(&big, 1, fork.clone(), &[])?;
    ledger.split(&root, left, right, ChildDisposition::Queued, ChildDisposition::Queued)?;
    ledger.reserve()?.ok_or("probe child")?;
    let reserved_logical = logical(&probe.path);
    let reserved_store = fs::metadata(probe.wal_path())?.len() + fs::metadata(&probe.path)?.len();
    drop(ledger);

    let requeue_probe = Fixture::new()?;
    let mut ledger = SustainedLedger::initialize(&requeue_probe.path, big.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("probe root")?;
    let (left, right) = root.unit.split(&big, 1, fork.clone(), &[])?;
    ledger.split(&root, left, right, ChildDisposition::Queued, ChildDisposition::Queued)?;
    ledger.reserve()?.ok_or("probe child")?;
    drop(ledger);
    let _ = SustainedLedger::open(&requeue_probe.path, big)?; // appends the recovery requeue
    let margin = logical(&requeue_probe.path) - reserved_logical;
    assert_eq!(reserved_store, reserved_logical + 116 + 84);
    assert!(margin > 0);

    // A budget that exactly fits the active child cannot fit its recovery
    // requeue: open fails closed rather than publishing a stale fence.
    let f = Fixture::new()?;
    let m = manifest(reserved_store)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root")?;
    let (left, right) = root.unit.split(&m, 1, fork.clone(), &[])?;
    ledger.split(&root, left, right, ChildDisposition::Queued, ChildDisposition::Queued)?;
    ledger.reserve()?.ok_or("child")?;
    drop(ledger);
    assert!(matches!(SustainedLedger::open(&f.path, m), Err(Error::LimitExceeded)));

    // One requeue frame of headroom recovers normally.
    let f = Fixture::new()?;
    let m = manifest(reserved_store + margin)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root")?;
    let (left, right) = root.unit.split(&m, 1, fork, &[])?;
    ledger.split(&root, left, right, ChildDisposition::Queued, ChildDisposition::Queued)?;
    ledger.reserve()?.ok_or("child")?;
    drop(ledger);
    let recovered = SustainedLedger::open(&f.path, m)?;
    assert_eq!(recovered.report().queued, 2);
    assert_eq!(recovered.records()[1].attempt, 2);
    Ok(())
}

#[test]
fn sequences_are_monotonic_across_transactions_and_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let owner = Digest::of(b"owner");
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    assert_eq!(ledger.durable_sequence(), None);
    let grant = ledger.reserve_fenced(owner)?.ok_or("root")?;
    assert_eq!(ledger.durable_sequence(), Some(1));
    let fork = BranchPoint {
        branch_pc: 0x1100,
        visit_index: 0,
        false_target: 0x1102,
        true_target: 0x1120,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"trace"),
        predicate_digest: Digest::of(b"predicate"),
    };
    let (left, right) = grant.reservation.unit.split(&m, 1, fork, &[])?;
    ledger.split(
        &grant.reservation,
        left,
        right,
        ChildDisposition::Queued,
        ChildDisposition::Queued,
    )?;
    assert_eq!(ledger.durable_sequence(), Some(2));
    let second = ledger.reserve_fenced(owner)?.ok_or("child")?;
    assert_eq!(ledger.durable_sequence(), Some(3));
    ledger.revoke_fenced(&second)?;
    assert_eq!(ledger.durable_sequence(), Some(4));
    drop(ledger);

    let mut reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(reopened.durable_sequence(), Some(4));
    let third = reopened.reserve()?.ok_or("requeued child")?;
    assert_eq!(reopened.durable_sequence(), Some(5));
    assert!(third.attempt > second.reservation.attempt);
    reopened.finish(&third, Status::Failed, "monotonic probe")?;
    assert_eq!(reopened.durable_sequence(), Some(6));
    drop(reopened);
    assert_eq!(SustainedLedger::open(&f.path, m)?.durable_sequence(), Some(6));
    Ok(())
}

/// A hand-built ANGFRNT1 (legacy, no owner fence byte, no evidence section)
/// snapshot still opens, and its first transition migrates to the WAL.
#[test]
fn legacy_snapshot_only_ledger_migrates_and_old_binaries_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut payload = Vec::new();
    payload.extend_from_slice(b"ANGFRNT1");
    payload.extend_from_slice(&m.campaign_digest.0);
    payload.extend_from_slice(&1u64.to_le_bytes()); // epoch
    payload.extend_from_slice(&1u32.to_le_bytes()); // one record
    payload.extend_from_slice(&1u32.to_le_bytes()); // schema version
    payload.extend_from_slice(&m.campaign_digest.0);
    payload.extend_from_slice(&1u64.to_le_bytes()); // contract epoch
    payload.extend_from_slice(&0u32.to_le_bytes()); // prefix depth
    payload.extend_from_slice(&seed().initial_state_digest.0);
    payload.push(0); // queued
    payload.push(0); // not retired
    payload.extend_from_slice(&0u64.to_le_bytes()); // attempt
    payload.extend_from_slice(&0u32.to_le_bytes()); // reason length
    payload.extend_from_slice(&Digest::of(&payload).0);
    fs::write(&f.path, payload)?;

    let mut ledger = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(ledger.report().queued, 1);
    assert_eq!(ledger.durable_sequence(), None);
    assert!(!f.wal_path().exists(), "no WAL until the first transition");
    ledger.reserve()?.ok_or("legacy root")?;
    assert!(f.wal_path().exists());
    // The checkpoint is now a tombstone: a pre-WAL binary reading the snapshot
    // sees unknown magic and fails closed instead of accepting stale state.
    let snapshot = fs::read(&f.path)?;
    assert_eq!(&snapshot[..8], b"ANGFRNT9");
    drop(ledger);
    let resumed = SustainedLedger::open(&f.path, m)?;
    assert_eq!(
        resumed.report().queued,
        1,
        "interrupted legacy active was durably requeued"
    );
    assert_eq!(resumed.records()[0].attempt, 2);
    Ok(())
}

#[test]
fn migration_crash_boundaries_never_acknowledge_before_tombstone() -> Result<(), Box<dyn std::error::Error>> {
    let m = manifest(10000)?;
    let f = Fixture::new()?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let old_snapshot = fs::read(&f.path)?;
    ledger.reserve()?.ok_or("root")?;
    let committed_wal = fs::read(f.wal_path())?;
    let frames = wal_frames(&committed_wal)?;
    assert_eq!(frames.len(), 2);
    drop(ledger);

    // A crash during WAL creation leaves the old checkpoint available; no
    // transaction was acknowledged. Torn creation may be removed and retried.
    fs::write(&f.path, &old_snapshot)?;
    fs::write(f.wal_path(), &committed_wal[..32])?;
    let mut reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(reopened.durable_sequence(), None);
    assert_eq!(reopened.records()[0].attempt, 0);
    assert_eq!(fs::read(&f.path)?, old_snapshot);
    drop(reopened);

    // Base WAL fsync precedes tombstone: replay finds no acknowledged work and
    // completes migration before returning, disabling old-binary snapshot reads.
    fs::write(f.wal_path(), &committed_wal[..frames[0].1])?;
    reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(reopened.durable_sequence(), Some(0));
    assert_eq!(reopened.records()[0].attempt, 0);
    assert_eq!(&fs::read(&f.path)?[..8], b"ANGFRNT9");
    drop(reopened);

    // A torn first append after the tombstone is discarded atomically.
    fs::write(f.wal_path(), &committed_wal[..frames[1].0 + 21 + 4])?;
    reopened = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(reopened.durable_sequence(), Some(0));
    assert_eq!(reopened.records()[0].attempt, 0);
    assert_eq!(fs::metadata(f.wal_path())?.len(), frames[0].1 as u64);
    drop(reopened);

    // Complete first frame is replayed and the interrupted grant is fenced.
    fs::write(f.wal_path(), &committed_wal)?;
    reopened = SustainedLedger::open(&f.path, m)?;
    assert_eq!(reopened.records()[0].attempt, 2);
    assert_eq!(reopened.report().queued, 1);
    assert_eq!(&fs::read(&f.path)?[..8], b"ANGFRNT9");
    drop(reopened);

    // A complete last frame with a bad checksum is tampering/corruption,
    // not an interrupted append to be silently discarded.
    let mut tampered = committed_wal;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x40;
    fs::write(f.wal_path(), tampered)?;
    assert!(matches!(
        SustainedLedger::open(&f.path, manifest(10000)?),
        Err(Error::Corrupt)
    ));
    Ok(())
}

#[test]
fn physical_budget_includes_header_base_checkpoint_and_tombstone() -> Result<(), Box<dyn std::error::Error>> {
    let probe = Fixture::new()?;
    let mut ledger = SustainedLedger::initialize(&probe.path, manifest(10000)?, 1, seed())?;
    let snapshot_len = fs::metadata(&probe.path)?.len();
    ledger.reserve()?.ok_or("root")?;
    let store_len = fs::metadata(probe.wal_path())?.len() + fs::metadata(&probe.path)?.len();
    drop(ledger);
    let base_only = store_len - (53 + 4 + 8 + 1); // reserve frame envelope plus payload
    let migration_peak = store_len + snapshot_len - 84;
    assert!(base_only >= 116 + snapshot_len + 53 + 84);
    for budget in [snapshot_len - 1, base_only - 1, migration_peak - 1] {
        let f = Fixture::new()?;
        let m = manifest(budget)?;
        if budget < snapshot_len {
            assert!(matches!(
                SustainedLedger::initialize(&f.path, m, 1, seed()),
                Err(Error::LimitExceeded)
            ));
        } else {
            let mut ledger = SustainedLedger::initialize(&f.path, m, 1, seed())?;
            assert!(matches!(ledger.reserve(), Err(Error::LimitExceeded)));
            assert!(!f.wal_path().exists());
            assert_eq!(&fs::read(&f.path)?[..8], b"ANGFRNT3");
        }
    }
    let f = Fixture::new()?;
    let m = manifest(migration_peak)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m, 1, seed())?;
    ledger.reserve()?.ok_or("exact migration peak fits")?;
    assert_eq!(
        fs::metadata(f.wal_path())?.len() + fs::metadata(&f.path)?.len(),
        store_len
    );
    Ok(())
}

#[test]
fn same_stem_wal_paths_are_distinct_and_old_sidecar_is_not_ignored() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let other = f.dir.join("frontier.other");
    let m = manifest(10000)?;
    // Same-stem ledgers share the legacy lock; operate sequentially so a
    // migration cannot race with an old reader holding that lock.
    drop(SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?);
    let mut second = SustainedLedger::initialize(&other, m.clone(), 1, seed())?;
    second.reserve()?.ok_or("second")?;
    drop(second);
    let mut first = SustainedLedger::open(&f.path, m.clone())?;
    first.reserve()?.ok_or("first")?;
    drop(first);
    assert_ne!(f.wal_path(), other.with_extension("other.wal"));
    assert!(other.with_extension("other.wal").exists());
    assert_eq!(SustainedLedger::open(&f.path, m.clone())?.records()[0].attempt, 2);
    assert_eq!(SustainedLedger::open(&other, m.clone())?.records()[0].attempt, 2);
    // Without its own WAL, a legacy same-stem sidecar must not silently be
    // skipped and admit the old snapshot as authoritative.
    let old = f.dir.join("frontier.legacy");
    let initial = SustainedLedger::initialize(&old, m.clone(), 1, seed());
    assert!(matches!(initial, Err(Error::AlreadyExists)));
    Ok(())
}

// Build a checksummed legacy checkpoint to test structural validation on open,
// independently of the WAL transaction writer's valid-state guarantees.
fn write_graph_checkpoint(
    f: &Fixture,
    m: &CampaignManifest,
    records: &[Record],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ANGFRNT3");
    bytes.extend_from_slice(&m.campaign_digest.0);
    bytes.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for record in records {
        bytes.extend_from_slice(&record.unit.schema_version.to_le_bytes());
        bytes.extend_from_slice(&record.unit.campaign_digest.0);
        bytes.extend_from_slice(&record.unit.contract_epoch.to_le_bytes());
        bytes.extend_from_slice(&(record.unit.prefix.len() as u32).to_le_bytes());
        for decision in &record.unit.prefix {
            let branch = &decision.branch;
            for value in [
                branch.branch_pc,
                branch.visit_index,
                branch.false_target,
                branch.true_target,
                branch.prefix_constraints,
            ] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&branch.trace_digest.0);
            bytes.extend_from_slice(&branch.predicate_digest.0);
            bytes.push(u8::from(decision.successor == Successor::True));
        }
        bytes.extend_from_slice(&record.replay.initial_state_digest.0);
        bytes.push(match record.status {
            Status::Queued => 0,
            Status::Active => 1,
            Status::Deferred => 2,
            Status::Completed => 3,
            Status::Infeasible => 4,
            Status::Unknown => 5,
            Status::Excluded => 6,
            Status::Failed => 7,
        });
        bytes.push(u8::from(record.retired));
        bytes.extend_from_slice(&record.attempt.to_le_bytes());
        bytes.push(u8::from(record.owner_id.is_some()));
        if let Some(owner) = record.owner_id {
            bytes.extend_from_slice(&owner.0);
        }
        bytes.extend_from_slice(&(record.reason.len() as u32).to_le_bytes());
        bytes.extend_from_slice(record.reason.as_bytes());
    }
    bytes.extend_from_slice(&angryier_ledger::evidence::SCHEMA_VERSION.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&Digest::of(&bytes).0);
    fs::write(&f.path, bytes)?;
    Ok(())
}

#[test]
fn malformed_record_graphs_fail_closed_on_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let m = manifest(100_000)?;
    let f = Fixture::new()?;
    let ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let mut root = ledger.records()[0].clone();
    drop(ledger);
    let fork = |pc| BranchPoint {
        branch_pc: pc,
        visit_index: 0,
        false_target: pc + 1,
        true_target: pc + 2,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"same-trace"),
        predicate_digest: Digest::of(b"same-predicate"),
    };
    let (false_unit, true_unit) = root.unit.split(&m, 1, fork(0x1100), &[])?;
    let (grandfalse, grandtrue) = false_unit.split(&m, 1, fork(0x1200), &[])?;
    root.retired = true;
    root.status = Status::Completed;
    let mut left = root.clone();
    left.unit = false_unit;
    let mut right = root.clone();
    right.unit = true_unit;
    right.retired = false;
    right.status = Status::Queued;
    let mut grandleft = right.clone();
    grandleft.unit = grandfalse;
    let mut grandright = right.clone();
    grandright.unit = grandtrue;
    let valid = vec![root, left, right, grandleft, grandright];
    write_graph_checkpoint(&f, &m, &valid)?;
    assert_eq!(SustainedLedger::open(&f.path, m.clone())?.records().len(), 5);
    let mut reordered = valid.clone();
    reordered.swap(1, 4);
    write_graph_checkpoint(&f, &m, &reordered)?;
    assert_eq!(SustainedLedger::open(&f.path, m.clone())?.records().len(), 5);

    let mut cases = Vec::new();
    let mut unsplit_root = valid.clone();
    unsplit_root[0].retired = false;
    unsplit_root[0].status = Status::Queued;
    cases.push(("unretired root with descendants", unsplit_root));
    let mut duplicate = valid.clone();
    duplicate[4] = duplicate[3].clone();
    cases.push(("duplicate exact prefix", duplicate));
    let mut missing_parent = valid.clone();
    missing_parent.remove(1);
    cases.push(("missing intermediate parent", missing_parent));
    let mut leaf_with_child = valid.clone();
    leaf_with_child[1].retired = false;
    leaf_with_child[1].status = Status::Queued;
    cases.push(("unretired parent with descendants", leaf_with_child));
    let mut missing_sibling = valid.clone();
    missing_sibling.remove(2);
    cases.push(("retired parent missing one child", missing_sibling));
    let mut wrong_branch = valid.clone();
    wrong_branch[2].unit.prefix[0].branch.branch_pc += 1;
    cases.push(("same-digest distinct fork context", wrong_branch));
    let mut wrong_replay = valid.clone();
    wrong_replay[4].replay.initial_state_digest = Digest::of(b"other seed");
    cases.push(("child replay differs", wrong_replay));
    for (name, records) in cases {
        write_graph_checkpoint(&f, &m, &records)?;
        assert!(
            matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)),
            "{name}"
        );
    }
    Ok(())
}

/// Bounded scale: >10001 accepted evidence events and >10001 work records in a
/// single durable ledger, replayed on reopen. Binary breadth-first splitting
/// keeps prefix depth logarithmic in the record count.
/// Run with: cargo test -p angryier-ledger --release --test sustained_wal -- --ignored
#[test]
#[ignore = "scale test; run in release mode"]
fn scale_test_10001_records_and_events() -> Result<(), Box<dyn std::error::Error>> {
    const SPLITS: u64 = 10001;
    let f = Fixture::new()?;
    let m = manifest(64 * 1024 * 1024)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    for depth in 0..SPLITS {
        let reservation = ledger.reserve()?.ok_or("frontier leaf")?;
        let fork = BranchPoint {
            branch_pc: 0x1100 + depth,
            visit_index: 0,
            false_target: 0x2000 + depth,
            true_target: 0x3000 + depth,
            prefix_constraints: 0,
            trace_digest: Digest::of(format!("trace-{depth}").as_bytes()),
            predicate_digest: Digest::of(format!("predicate-{depth}").as_bytes()),
        };
        let (left, right) = reservation.unit.split(&m, 1, fork, &[])?;
        ledger.split_with_evidence(
            &reservation,
            left,
            right,
            ChildDisposition::Queued,
            ChildDisposition::Queued,
            delta(&reservation, PathDisposition::Pending(PendingReason::Queued)),
        )?;
    }
    assert_eq!(ledger.records().len(), 1 + 2 * SPLITS as usize);
    assert_eq!(ledger.read_snapshot().1.len(), SPLITS as usize);
    assert_eq!(ledger.durable_sequence(), Some(2 * SPLITS));
    assert!(
        ledger.durable_wal_bytes() < 1 << 30,
        "aggregate durable store within 1 GiB"
    );
    drop(ledger);

    let start = Instant::now();
    let reopened = SustainedLedger::open(&f.path, m)?;
    eprintln!(
        "reopen {} records and {} events: {:?}",
        1 + 2 * SPLITS,
        SPLITS,
        start.elapsed()
    );
    assert_eq!(reopened.records().len(), 1 + 2 * SPLITS as usize);
    assert_eq!(reopened.read_snapshot().1.len(), SPLITS as usize);
    assert_eq!(reopened.report().retired_splits, SPLITS as usize);
    assert_eq!(reopened.report().queued, SPLITS as usize + 1);
    assert_eq!(reopened.cumulative_evidence().count(), SPLITS as usize);
    assert!(reopened.durable_wal_bytes() < 1 << 30);
    Ok(())
}
