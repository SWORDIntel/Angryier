use angryier_distribution::contracts::{BranchPoint, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_ledger::{
    evidence::{
        BranchEvidence, DynamicBlock, EdgeBasis, EvidenceDelta, FlowEdge, PathDisposition, PathEvidence, PendingReason,
        ReplayVerification, SolverDisposition, WitnessEvidence,
    },
    sustained::{ChildDisposition, Error, ReplayDescriptor, Reservation, Status, SustainedLedger, work_path_id},
};
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
            "angryier-evidence-{}-{}",
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
/// ANGFRWAL header prefix (magic, version, generation, digests, checksum).
const WAL_HEADER: u64 = 116;
/// ANGFRNT9 tombstone length; after the first WAL transition the checkpoint
/// shrinks to this size but the physical budget keeps accounting for it.
const TOMBSTONE: u64 = 84;
fn wal_path(path: &std::path::Path) -> PathBuf {
    // Physical sidecar suffix `<checkpoint>.wal`, matching `wal::suffix_path`;
    // `with_extension` would replace the checkpoint extension instead.
    let mut name = path.as_os_str().to_os_string();
    name.push(".wal");
    PathBuf::from(name)
}
/// Logical durable WAL bytes: physical file size minus the ANGFRWAL header.
fn wal_logical(path: &std::path::Path) -> u64 {
    fs::metadata(wal_path(path)).map_or(0, |m| m.len().saturating_sub(WAL_HEADER))
}
/// Frame extents in a WAL file: (start, end) with end including the checksum.
fn wal_frames(bytes: &[u8]) -> Result<Vec<(usize, usize)>, Box<dyn std::error::Error>> {
    let mut frames = Vec::new();
    let mut pos = WAL_HEADER as usize; // ANGFRWAL header
    while pos < bytes.len() {
        // kind(1) + generation(8) + seq(8) + payload_len(4)
        let payload_len = u32::from_le_bytes(bytes[pos + 17..pos + 21].try_into()?) as usize;
        let end = pos + 21 + payload_len + 32;
        frames.push((pos, end));
        pos = end;
    }
    Ok(frames)
}
fn frame_at(frames: &[(usize, usize)], pos: usize) -> Result<(usize, usize), Box<dyn std::error::Error>> {
    frames
        .iter()
        .find(|(start, end)| pos >= *start && pos < *end)
        .copied()
        .ok_or_else(|| "offset outside all frames".into())
}
fn rechecksum_frame(bytes: &mut [u8], frame: (usize, usize)) {
    let end = frame.1;
    let digest = Digest::of(&bytes[frame.0..end - 32]);
    bytes[end - 32..end].copy_from_slice(&digest.0);
}

#[test]
fn atomic_completion_and_recovery_preserve_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("missing work")?;
    let prior = fs::read(&f.path)?;
    let mut invalid = terminal(&reservation);
    invalid.path.witness.as_mut().ok_or("witness")?.replay = ReplayVerification::Verified { trace_digest: [0; 32] };
    assert!(matches!(
        ledger.commit_outcome(&reservation, Status::Completed, "replayed", invalid),
        Err(Error::InvalidTransition)
    ));
    assert_eq!(fs::read(&f.path)?, prior);
    assert!(ledger.read_snapshot().1.is_empty());
    ledger.commit_outcome(&reservation, Status::Completed, "replayed", terminal(&reservation))?;
    ledger.commit_outcome(&reservation, Status::Completed, "replayed", terminal(&reservation))?;
    let mut different = terminal(&reservation);
    different.path.provenance_digest = Digest::of(b"different").0;
    assert!(matches!(
        ledger.commit_outcome(&reservation, Status::Completed, "replayed", different),
        Err(Error::InvalidTransition)
    ));
    drop(ledger);
    let ledger = SustainedLedger::open(&f.path, m)?;
    assert!(ledger.report().complete_within_declared_bounds);
    let (records, evidence) = ledger.read_snapshot();
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].replay_digest, records[0].replay.initial_state_digest);
    assert_eq!(evidence[0].delta, terminal(&reservation));
    Ok(())
}

#[test]
fn failed_publish_keeps_work_active_and_evidence_absent() -> Result<(), Box<dyn std::error::Error>> {
    // Derive the sealed budget from the probe's measured physical sizes. The
    // first reserve preflights checkpoint + WAL (header, base frame, reserve
    // frame); recovery on reopen must additionally fit the durable requeue
    // fence, while the far larger evidence-bearing outcome frame must not.
    // Probe A: checkpoint size, the WAL after one reserve, and the requeue
    // fence a reopen appends for the interrupted active reservation.
    let probe = Fixture::new()?;
    let mut ledger = SustainedLedger::initialize(&probe.path, manifest(10000)?, 1, seed())?;
    let checkpoint = fs::metadata(&probe.path)?.len();
    ledger.reserve()?.ok_or("probe reservation")?;
    let after_reserve_wal = fs::metadata(wal_path(&probe.path))?.len();
    drop(ledger);
    let reopened = SustainedLedger::open(&probe.path, manifest(10000)?)?;
    let requeue_frame = fs::metadata(wal_path(&probe.path))?.len() - after_reserve_wal;
    drop(reopened);
    // Probe B: the evidence-bearing outcome frame appended by commit_outcome.
    let outcome = Fixture::new()?;
    let mut ledger = SustainedLedger::initialize(&outcome.path, manifest(10000)?, 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("outcome probe reservation")?;
    let before_outcome = fs::metadata(wal_path(&outcome.path))?.len();
    ledger.commit_outcome(&reservation, Status::Completed, "replayed", terminal(&reservation))?;
    let outcome_frame = fs::metadata(wal_path(&outcome.path))?.len() - before_outcome;
    drop(ledger);
    let reserve_fence = checkpoint.max(TOMBSTONE);
    assert!(
        outcome_frame + TOMBSTONE > reserve_fence.max(requeue_frame + TOMBSTONE),
        "evidence frame ({outcome_frame}) must exceed the reserve/requeue fence"
    );
    let budget = after_reserve_wal + reserve_fence.max(requeue_frame + TOMBSTONE);

    let f = Fixture::new()?;
    let m = manifest(budget)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("missing work")?;
    let prior = fs::read(&f.path)?;
    assert!(matches!(
        ledger.commit_outcome(&reservation, Status::Completed, "replayed", terminal(&reservation)),
        Err(Error::LimitExceeded)
    ));
    assert_eq!(ledger.report().active, 1);
    assert!(ledger.read_snapshot().1.is_empty());
    assert_eq!(fs::read(&f.path)?, prior);
    drop(ledger);
    assert_eq!(SustainedLedger::open(&f.path, m)?.report().queued, 1);
    Ok(())
}

#[test]
fn torn_or_corrupt_evidence_is_not_accepted() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("missing work")?;
    ledger.commit_outcome(&reservation, Status::Completed, "replayed", terminal(&reservation))?;
    drop(ledger);
    // The checkpoint is tombstoned once the WAL exists; corrupting it fails closed.
    let snapshot = fs::read(&f.path)?;
    fs::write(&f.path, &snapshot[..snapshot.len() - 12])?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));
    fs::write(&f.path, &snapshot)?;
    let mut damaged = snapshot.clone();
    let position = damaged.len() - 33;
    damaged[position] ^= 1;
    fs::write(&f.path, damaged)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));
    fs::write(&f.path, &snapshot)?;

    // A complete WAL frame whose checksum fails is rejected, and a complete
    // frame with a forged payload and a fixed frame checksum is still rejected
    // by semantic replay validation.
    let mut wal = fs::read(wal_path(&f.path))?;
    let frames = wal_frames(&wal)?;
    let outcome = *frames.last().ok_or("outcome frame")?;
    let id = work_path_id(&reservation.unit, &reservation.replay).0;
    let offset = wal.windows(32).position(|window| window == id).ok_or("path identity")?;
    assert!(offset >= outcome.0 && offset < outcome.1);
    wal[offset] ^= 1;
    rechecksum_frame(&mut wal, outcome);
    fs::write(wal_path(&f.path), &wal)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));

    let mut wal = fs::read(wal_path(&f.path))?;
    wal[offset] ^= 1;
    // Forged status: an infeasible record with a terminal path is inconsistent.
    let status_at = outcome.0 + 21 + 4 + 8;
    wal[status_at] = 4;
    rechecksum_frame(&mut wal, outcome);
    fs::write(wal_path(&f.path), wal)?;
    assert!(matches!(SustainedLedger::open(&f.path, m), Err(Error::Corrupt)));
    Ok(())
}

#[test]
fn owner_fence_survives_reopen_and_rejects_stale_grants() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let alice = Digest::of(b"alice");
    let bob = Digest::of(b"bob");
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let first = ledger.reserve_fenced(alice)?.ok_or("missing work")?;
    let forged = angryier_ledger::sustained::FencedReservation {
        owner_id: bob,
        ..first.clone()
    };
    assert!(matches!(
        ledger.commit_outcome_fenced(&forged, Status::Completed, "forged", terminal(&first.reservation)),
        Err(Error::StaleReservation)
    ));
    ledger.revoke_fenced(&first)?;
    assert!(matches!(
        ledger.commit_outcome_fenced(&first, Status::Completed, "stale", terminal(&first.reservation)),
        Err(Error::StaleReservation)
    ));
    let second = ledger.reserve_fenced(bob)?.ok_or("missing replacement")?;
    assert!(second.ownership_epoch > first.ownership_epoch);
    drop(ledger);
    let mut resumed = SustainedLedger::open(&f.path, m)?;
    assert!(matches!(
        resumed.commit_outcome_fenced(&second, Status::Completed, "stale", terminal(&second.reservation)),
        Err(Error::StaleReservation)
    ));
    let third = resumed.reserve_fenced(alice)?.ok_or("missing recovered work")?;
    assert!(third.ownership_epoch > second.ownership_epoch);
    resumed.commit_outcome_fenced(&third, Status::Completed, "replayed", terminal(&third.reservation))?;
    assert_eq!(resumed.read_snapshot().1.len(), 1);
    Ok(())
}

#[test]
fn split_commits_parent_evidence_with_both_children() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("missing root")?;
    let fork = BranchPoint {
        branch_pc: 0x1000,
        visit_index: 0,
        false_target: 0x1002,
        true_target: 0x1020,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"branch trace"),
        predicate_digest: Digest::of(b"branch predicate"),
    };
    let (left, right) = root.unit.split(&m, 1, fork, &[])?;
    let prior = fs::read(&f.path)?;
    assert!(matches!(
        ledger.split_with_evidence(
            &root,
            left.clone(),
            right.clone(),
            ChildDisposition::Queued,
            ChildDisposition::Deferred("budget".into()),
            delta(&root, PathDisposition::SolverInfeasible)
        ),
        Err(Error::InvalidTransition)
    ));
    assert_eq!(fs::read(&f.path)?, prior);
    assert_eq!(ledger.read_snapshot().0.len(), 1);
    ledger.split_with_evidence(
        &root,
        left,
        right,
        ChildDisposition::Queued,
        ChildDisposition::Deferred("budget".into()),
        delta(&root, PathDisposition::Pending(PendingReason::Queued)),
    )?;
    drop(ledger);
    let ledger = SustainedLedger::open(&f.path, m)?;
    let (records, evidence) = ledger.read_snapshot();
    assert_eq!(records.len(), 3);
    assert!(records[0].retired);
    assert_eq!(evidence.len(), 1);
    assert_eq!(evidence[0].status, Status::Completed);
    assert_eq!(evidence[0].work_index, 0);
    assert_eq!((ledger.report().queued, ledger.report().deferred), (1, 1));
    Ok(())
}

#[test]
fn split_unsat_proof_is_atomic_and_rechecked_on_recovery() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let grant = ledger.reserve_fenced(Digest::of(b"owner"))?.ok_or("missing root")?;
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
    let before = fs::read(&f.path)?;
    let publish = |ledger: &mut SustainedLedger, proof: Option<EvidenceDelta>| {
        ledger.split_with_proofs_fenced(
            &grant,
            left.clone(),
            right.clone(),
            ChildDisposition::Infeasible("solver UNSAT".into()),
            ChildDisposition::Queued,
            angryier_ledger::sustained::SplitProofs {
                delta: parent.clone(),
                child_proofs: [proof, None],
            },
        )
    };
    assert!(matches!(publish(&mut ledger, None), Err(Error::InvalidTransition)));
    let mut wrong = child.clone();
    wrong.path.path_id = work_path_id(&right, &root.replay).0;
    assert!(matches!(
        publish(&mut ledger, Some(wrong)),
        Err(Error::InvalidTransition)
    ));
    let mut wrong = child.clone();
    wrong.sequence += 1;
    assert!(matches!(
        publish(&mut ledger, Some(wrong)),
        Err(Error::InvalidTransition)
    ));
    let mut wrong = child.clone();
    wrong.path.disposition = PathDisposition::Terminal;
    assert!(matches!(
        publish(&mut ledger, Some(wrong)),
        Err(Error::InvalidTransition)
    ));
    let mut wrong = child.clone();
    wrong.path.edges[0].to_pc = fork.true_target;
    assert!(matches!(
        publish(&mut ledger, Some(wrong)),
        Err(Error::InvalidTransition)
    ));
    assert_eq!(fs::read(&f.path)?, before);
    assert_eq!(ledger.read_snapshot().0.len(), 1);
    assert!(!ledger.report().complete_within_declared_bounds);
    publish(&mut ledger, Some(child.clone()))?;
    assert_eq!(ledger.read_snapshot().1.len(), 2);
    assert_eq!(ledger.report().infeasible, 1);
    drop(ledger);
    let ledger = SustainedLedger::open(&f.path, m.clone())?;
    assert_eq!(ledger.read_snapshot().1[1].delta, child);
    drop(ledger);
    let original = fs::read(wal_path(&f.path))?;
    let proof_result = unsat.result_digest.ok_or("result")?;
    let pos = original
        .windows(32)
        .rposition(|w| w == proof_result)
        .ok_or("proof result")?;
    let frames = wal_frames(&original)?;
    let frame = frame_at(&frames, pos)?;
    let mut forged = original.clone();
    forged[pos] ^= 1;
    rechecksum_frame(&mut forged, frame);
    fs::write(wal_path(&f.path), forged)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));
    fs::write(wal_path(&f.path), original)?;
    assert_eq!(SustainedLedger::open(&f.path, m)?.report().infeasible, 1);
    Ok(())
}

#[test]
fn retry_of_same_path_keeps_history_and_latest_disposition() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let first = ledger.reserve()?.ok_or("root")?;
    ledger.commit_outcome(
        &first,
        Status::Unknown,
        "solver unknown",
        delta(&first, PathDisposition::Pending(PendingReason::Unknown)),
    )?;
    ledger.requeue(&first.unit)?;
    let second = ledger.reserve()?.ok_or("retry")?;
    assert!(second.attempt > first.attempt);
    assert!(matches!(
        ledger.commit_outcome(&second, Status::Completed, "replayed", terminal(&second)),
        Err(Error::InvalidTransition)
    )); // sequence must increase across attempts.
    let mut latest = terminal(&second);
    latest.sequence = 2;
    ledger.commit_outcome(&second, Status::Completed, "replayed", latest)?;
    drop(ledger);
    let ledger = SustainedLedger::open(&f.path, m)?;
    assert_eq!(ledger.read_snapshot().1.len(), 2);
    let cumulative: Vec<_> = ledger.cumulative_evidence().collect();
    assert_eq!(cumulative.len(), 1);
    assert_eq!(cumulative[0].status, Status::Completed);
    assert_eq!(cumulative[0].attempt, second.attempt);
    Ok(())
}

#[test]
fn rejects_duplicate_or_misbound_path_without_publishing() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let reservation = ledger.reserve()?.ok_or("root")?;
    let prior = fs::read(&f.path)?;
    let mut wrong = terminal(&reservation);
    wrong.path.path_id = Digest::of(b"other path").0;
    assert!(matches!(
        ledger.commit_outcome(&reservation, Status::Completed, "replayed", wrong),
        Err(Error::InvalidTransition)
    ));
    assert!(matches!(
        ledger.commit_outcome(&reservation, Status::Unknown, "unknown", terminal(&reservation)),
        Err(Error::InvalidTransition)
    ));
    let mut oversized = terminal(&reservation);
    oversized.path.blocks.resize(
        4097,
        DynamicBlock {
            pc: 0x1000,
            visit_index: 0,
        },
    );
    assert!(matches!(
        ledger.commit_outcome(&reservation, Status::Completed, "replayed", oversized),
        Err(Error::InvalidTransition)
    ));
    assert_eq!(fs::read(&f.path)?, prior);
    assert!(ledger.read_snapshot().1.is_empty());
    Ok(())
}

#[test]
fn rechecksummed_replay_and_duplicate_sequence_fail_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(10000)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let first = ledger.reserve()?.ok_or("root")?;
    ledger.commit_outcome(
        &first,
        Status::Unknown,
        "unknown",
        delta(&first, PathDisposition::Pending(PendingReason::Unknown)),
    )?;
    ledger.requeue(&first.unit)?;
    let second = ledger.reserve()?.ok_or("retry")?;
    let mut latest = terminal(&second);
    latest.sequence = 2;
    ledger.commit_outcome(&second, Status::Completed, "done", latest)?;
    drop(ledger);
    let original = fs::read(wal_path(&f.path))?;
    let frames = wal_frames(&original)?;
    let id = work_path_id(&first.unit, &first.replay).0;
    let offsets: Vec<_> = original
        .windows(32)
        .enumerate()
        .filter_map(|(i, window)| (window == id).then_some(i))
        .collect();
    assert_eq!(offsets.len(), 2);
    let mut forged = original.clone();
    let second = frame_at(&frames, offsets[1])?;
    forged[offsets[1] - 8..offsets[1]].copy_from_slice(&1u64.to_le_bytes());
    rechecksum_frame(&mut forged, second);
    fs::write(wal_path(&f.path), forged)?;
    assert!(matches!(SustainedLedger::open(&f.path, m.clone()), Err(Error::Corrupt)));

    let mut forged = original;
    let replay = first.replay.initial_state_digest.0;
    let replay_at = forged
        .windows(32)
        .rposition(|window| window == replay)
        .ok_or("replay")?;
    let frame = frame_at(&frames, replay_at)?;
    forged[replay_at] ^= 1;
    rechecksum_frame(&mut forged, frame);
    fs::write(wal_path(&f.path), forged)?;
    assert!(matches!(SustainedLedger::open(&f.path, m), Err(Error::Corrupt)));
    Ok(())
}

#[test]
fn disk_limit_rejects_split_and_evidence_as_one_unit() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new()?;
    let m = manifest(800)?;
    let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
    let root = ledger.reserve()?.ok_or("root")?;
    let fork = BranchPoint {
        branch_pc: 0x1000,
        visit_index: 0,
        false_target: 0x1002,
        true_target: 0x1020,
        prefix_constraints: 0,
        trace_digest: Digest::of(b"trace"),
        predicate_digest: Digest::of(b"predicate"),
    };
    let (left, right) = root.unit.split(&m, 1, fork, &[])?;
    let prior = fs::read(&f.path)?;
    assert!(matches!(
        ledger.split_with_evidence(
            &root,
            left,
            right,
            ChildDisposition::Queued,
            ChildDisposition::Queued,
            delta(&root, PathDisposition::Pending(PendingReason::Queued))
        ),
        Err(Error::LimitExceeded)
    ));
    assert_eq!(fs::read(&f.path)?, prior);
    assert_eq!(ledger.read_snapshot().0.len(), 1);
    assert!(ledger.read_snapshot().1.is_empty());
    drop(ledger);
    let resumed = SustainedLedger::open(&f.path, m)?;
    assert_eq!(resumed.report().queued, 1);
    assert!(resumed.read_snapshot().1.is_empty());
    Ok(())
}

#[test]
fn fenced_reservation_disk_limit_is_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let owner = Digest::of(b"fenced-owner");
    // Probe the physical size a first fenced reservation preflights: the whole
    // WAL (header + base frame + fenced reserve frame) plus the checkpoint it
    // replaces. One byte less than that exact sum must fail atomically.
    let probe = Fixture::new()?;
    let mut ledger = SustainedLedger::initialize(&probe.path, manifest(10000)?, 1, seed())?;
    let checkpoint = fs::metadata(&probe.path)?.len();
    ledger.reserve_fenced(owner)?.ok_or("fenced probe")?;
    let fenced_wal = fs::metadata(wal_path(&probe.path))?.len();
    drop(ledger);
    let fenced_logical = fenced_wal - WAL_HEADER;
    let first_txn_budget = fenced_wal + checkpoint.max(TOMBSTONE);
    let tight = first_txn_budget - 1;

    for ranked in [false, true] {
        let f = Fixture::new()?;
        let m = manifest(tight)?;
        let mut ledger = SustainedLedger::initialize(&f.path, m.clone(), 1, seed())?;
        let before = fs::read(&f.path)?;
        assert_eq!(before.len() as u64, checkpoint);
        let result = if ranked {
            ledger.reserve_by_rank_fenced(owner, &[], &[])
        } else {
            ledger.reserve_fenced(owner)
        };
        assert!(matches!(result, Err(Error::LimitExceeded)));
        assert_eq!(fs::read(&f.path)?, before);
        assert_eq!(ledger.records()[0].status, Status::Queued);
        assert_eq!(ledger.records()[0].attempt, 0);
        assert_eq!(ledger.records()[0].owner_id, None);
        drop(ledger);
        let recovered = SustainedLedger::open(&f.path, m)?;
        assert_eq!(recovered.records()[0].status, Status::Queued);
        assert_eq!(recovered.records()[0].attempt, 0);
        assert!(recovered.read_snapshot().1.is_empty());

        let success = Fixture::new()?;
        let mut ledger = SustainedLedger::initialize(&success.path, manifest(first_txn_budget)?, 1, seed())?;
        let grant = if ranked {
            ledger.reserve_by_rank_fenced(owner, &[], &[])?
        } else {
            ledger.reserve_fenced(owner)?
        }
        .ok_or("fenced reservation")?;
        assert_eq!(grant.ownership_epoch, 1);
        assert_eq!(ledger.records()[0].status, Status::Active);
        assert_eq!(ledger.records()[0].attempt, grant.reservation.attempt);
        assert_eq!(ledger.records()[0].owner_id, Some(owner));
        assert_eq!(wal_logical(&success.path), fenced_logical);
        assert_eq!(ledger.read_snapshot().1.len(), 0);
    }
    Ok(())
}
