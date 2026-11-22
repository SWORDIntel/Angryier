//! Durable, local-only ownership ledger. The replay descriptor requests root replay;
//! it does not claim to persist an execution-state snapshot or solver proof.
//!
//! Storage layout: an immutable ANGFRNT3 checkpoint (`frontier.snap`) plus a
//! checksummed, generation/sequence-bound append-only WAL sidecar
//! (`<checkpoint>.wal`, see [`wal`]). Each acknowledged transition is a single
//! bounded frame holding the exact changed record(s) and accepted evidence,
//! fsynced BEFORE the in-memory state moves; the whole-snapshot re-encode and
//! rename per transition is gone. Once a WAL exists, the checkpoint is replaced
//! by an ANGFRNT9 tombstone so pre-WAL binaries fail closed instead of
//! accepting stale state. Legacy snapshot-only ledgers open normally and
//! migrate on their first transition. No compaction is implemented yet: the WAL
//! grows monotonically and the writer fails closed at 1 GiB.
use crate::evidence::{self, AcceptedEvidence, EdgeBasis, EvidenceDelta, PathDisposition, SolverDisposition};
use crate::wal;
use angryier_distribution::contracts::{
    BranchDecision, BranchPoint, CampaignManifest, ContractError, Digest, Successor, WorkUnit, validate_split,
};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAGIC: &[u8; 8] = b"ANGFRNT3";
/// Aggregate durable store ceiling: checkpoint plus WAL, at most 1 GiB.
pub(crate) const MAX_STORE: usize = 1 << 30;
const MAX_RECORD: usize = 64 * 1024;
/// Target capacity: 65536 work records per durable ledger.
const MAX_UNITS: usize = 65536;
pub(crate) const MAX_REASON: usize = 4096;
const SPLIT_REASON: &str = "split into two recorded children";
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Contract(ContractError),
    Corrupt,
    MismatchedCampaign,
    AlreadyExists,
    NotFound,
    InvalidTransition,
    /// Verified evidence exceeded the per-event typed-evidence bound.
    EvidenceTooLarge {
        blocks: usize,
        edges: usize,
    },
    StaleReservation,
    LimitExceeded,
    Poisoned,
    /// Another process holds the ledger's exclusive writer lock.
    Locked,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Locked => write!(f, "ledger is locked by another process; one coordinator owns a ledger"),
            Self::EvidenceTooLarge { blocks, edges } => write!(
                f,
                "verified evidence exceeds the per-event bound ({blocks} blocks, {edges} edges)"
            ),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<ContractError> for Error {
    fn from(value: ContractError) -> Self {
        Self::Contract(value)
    }
}

/// A root-replay seed: the caller must retain the pinned inputs and verify each
/// complete ordered branch decision during replay, before accepting a result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReplayDescriptor {
    pub initial_state_digest: Digest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Queued,
    Active,
    Deferred,
    Completed,
    Infeasible,
    Unknown,
    Excluded,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub unit: WorkUnit,
    pub replay: ReplayDescriptor,
    pub status: Status,
    pub reason: String,
    /// Incremented on each reservation and on recovery of interrupted work.
    pub attempt: u64,
    /// Durable owner fence; absent for legacy local-only reservations.
    pub owner_id: Option<Digest>,
    /// A split parent owns no remaining subtree. It is not a completed leaf.
    pub retired: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub unit: WorkUnit,
    pub replay: ReplayDescriptor,
    pub attempt: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FencedReservation {
    pub reservation: Reservation,
    pub owner_id: Digest,
    /// Per-work grant generation, increased by reserve/revoke/recovery.
    pub ownership_epoch: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub queued: usize,
    pub active: usize,
    pub deferred: usize,
    pub completed: usize,
    pub infeasible: usize,
    pub unknown: usize,
    pub excluded: usize,
    pub failed: usize,
    pub retired_splits: usize,
    pub complete_within_declared_bounds: bool,
}

/// A single-process writer guarded by an OS advisory lock on a *stable* sidecar
/// inode (not the renamed snapshot). Other processes must use this API.
pub struct SustainedLedger {
    path: PathBuf,
    wal_path: PathBuf,
    _lock: File,
    manifest: CampaignManifest,
    epoch: u64,
    records: Vec<Record>,
    evidence: Vec<AcceptedEvidence>,
    /// Last accepted event index per path identity (O(1) cumulative lookup).
    latest: HashMap<[u8; 32], usize>,
    /// Last accepted event index per work record (O(1) monotonicity checks).
    latest_by_work: HashMap<u32, usize>,
    /// Append-only transaction tail; `None` until the first transition migrates
    /// a legacy snapshot-only ledger.
    wal: Option<wal::Wal>,
    /// Checkpoint bytes retained only while the ledger is still legacy (no WAL);
    /// consumed when the WAL is created.
    base_snapshot: Option<Vec<u8>>,
    /// The checkpoint file is already an ANGFRNT9 tombstone (WAL is the truth).
    snapshot_poisoned: bool,
    /// Lower bound on the first queued record, keeping reserve() near O(1).
    reserve_hint: usize,
    poisoned: bool,
}

impl SustainedLedger {
    /// Create a new campaign; never overwrite an existing or corrupt snapshot.
    pub fn initialize(
        path: impl AsRef<Path>,
        manifest: CampaignManifest,
        epoch: u64,
        replay: ReplayDescriptor,
    ) -> Result<Self, Error> {
        manifest.validate()?;
        let root = WorkUnit::root(&manifest, epoch)?;
        if replay.initial_state_digest == Digest::default() {
            return Err(Error::InvalidTransition);
        }
        let path = path.as_ref().to_path_buf();
        let lock = acquire_lock(&path)?;
        if wal::wal_path(&path).exists() || wal::legacy_wal_path(&path).is_some_and(|legacy| legacy.exists()) {
            return Err(Error::AlreadyExists);
        }
        let mut ledger = Self {
            wal_path: wal::wal_path(&path),
            path,
            _lock: lock,
            manifest,
            epoch,
            records: vec![Record {
                unit: root,
                replay,
                status: Status::Queued,
                reason: String::new(),
                attempt: 0,
                owner_id: None,
                retired: false,
            }],
            evidence: Vec::new(),
            latest: HashMap::new(),
            latest_by_work: HashMap::new(),
            wal: None,
            base_snapshot: None,
            snapshot_poisoned: false,
            reserve_hint: 0,
            poisoned: false,
        };
        let bytes = ledger.encode()?;
        if bytes.len() as u64 > ledger.manifest.spec.limits.max_disk_bytes {
            return Err(Error::LimitExceeded);
        }
        // Exclusive placeholder makes initialization race-safe, including with
        // writers that do not participate in our advisory lock.
        let mut slot = OpenOptions::new().write(true).create_new(true).open(&ledger.path)?;
        if let Err(err) = slot
            .write_all(&bytes)
            .and_then(|()| slot.sync_all())
            .and_then(|()| sync_parent(&ledger.path))
        {
            ledger.poisoned = true;
            return Err(Error::Io(err));
        }
        ledger.base_snapshot = Some(bytes);
        Ok(ledger)
    }

    /// Open only with the identical sealed campaign. Under the stable lock the
    /// WAL is replayed in order; interrupted active jobs are durably requeued
    /// with a fresh fence before this returns, invalidating old reservations.
    pub fn open(path: impl AsRef<Path>, manifest: CampaignManifest) -> Result<Self, Error> {
        manifest.validate()?;
        let path = path.as_ref().to_path_buf();
        let lock = acquire_lock(&path)?;
        let mut file = File::open(&path)?;
        let snapshot_len = file.metadata()?.len();
        if snapshot_len > (MAX_STORE as u64).min(manifest.spec.limits.max_disk_bytes) {
            return Err(Error::LimitExceeded);
        }
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let wal_path = wal::wal_path(&path);
        let wal_exists = wal_path.exists();
        if !wal_exists && wal::legacy_wal_path(&path).is_some_and(|legacy| legacy.exists()) {
            // An older build may have written this path. Do not ignore its
            // possibly accepted transactions and reopen a stale checkpoint.
            return Err(Error::Corrupt);
        }
        let (mut ledger, recovery) = if bytes.starts_with(wal::TOMBSTONE_MAGIC) {
            let (generation, wal_manifest) = wal::parse_tombstone(&bytes)?;
            if wal_manifest != manifest.campaign_digest {
                return Err(Error::MismatchedCampaign);
            }
            if !wal_exists {
                return Err(Error::Corrupt);
            }
            let recovery = wal::recover(&wal_path, &manifest, None)?;
            if recovery.header_torn {
                // Base unreachable without a valid checkpoint.
                return Err(Error::Corrupt);
            }
            if recovery.generation != generation {
                // Tombstone and WAL generation mismatch: fail closed.
                return Err(Error::Corrupt);
            }
            let (epoch, mut records, mut evidence) = decode(&recovery.base, &manifest)?;
            apply_txns(&mut records, &mut evidence, &recovery.txns)?;
            let ledger = Self {
                path,
                wal_path,
                _lock: lock,
                manifest,
                epoch,
                records,
                evidence,
                latest: HashMap::new(),
                latest_by_work: HashMap::new(),
                wal: None,
                base_snapshot: None,
                snapshot_poisoned: true,
                reserve_hint: 0,
                poisoned: false,
            };
            (ledger, Some(recovery))
        } else if bytes.starts_with(MAGIC) || bytes.starts_with(b"ANGFRNT1") {
            let (epoch, mut records, mut evidence) = decode(&bytes, &manifest)?;
            if wal_exists {
                let recovery = wal::recover(&wal_path, &manifest, Some(Digest::of(&bytes)))?;
                if recovery.header_torn {
                    // Torn first creation: nothing was ever acknowledged from
                    // this WAL, and the checkpoint is still the valid base.
                    fs::remove_file(&wal_path)?;
                    let ledger = Self {
                        path,
                        wal_path,
                        _lock: lock,
                        manifest,
                        epoch,
                        records,
                        evidence,
                        latest: HashMap::new(),
                        latest_by_work: HashMap::new(),
                        wal: None,
                        base_snapshot: Some(bytes),
                        snapshot_poisoned: false,
                        reserve_hint: 0,
                        poisoned: false,
                    };
                    (ledger, None)
                } else {
                    apply_txns(&mut records, &mut evidence, &recovery.txns)?;
                    let ledger = Self {
                        path,
                        wal_path,
                        _lock: lock,
                        manifest,
                        epoch,
                        records,
                        evidence,
                        latest: HashMap::new(),
                        latest_by_work: HashMap::new(),
                        wal: None,
                        base_snapshot: None,
                        snapshot_poisoned: false,
                        reserve_hint: 0,
                        poisoned: false,
                    };
                    (ledger, Some(recovery))
                }
            } else {
                // Legacy snapshot-only ledger: validate in place; the WAL is
                // created (and the checkpoint tombstoned) on the first durable
                // transition or recovery requeue.
                let ledger = Self {
                    path,
                    wal_path,
                    _lock: lock,
                    manifest,
                    epoch,
                    records,
                    evidence,
                    latest: HashMap::new(),
                    latest_by_work: HashMap::new(),
                    wal: None,
                    base_snapshot: Some(bytes),
                    snapshot_poisoned: false,
                    reserve_hint: 0,
                    poisoned: false,
                };
                (ledger, None)
            }
        } else {
            return Err(Error::Corrupt);
        };
        ledger.rebuild_evidence_indexes();
        ledger.validate_records()?;
        ledger.validate_evidence()?;
        let wal_bytes = recovery.as_ref().map_or(0, |r| wal::WAL_HEADER_LEN as u64 + r.logical);
        if snapshot_len
            .checked_add(wal_bytes)
            .is_none_or(|total| total > (MAX_STORE as u64).min(ledger.manifest.spec.limits.max_disk_bytes))
        {
            return Err(Error::LimitExceeded);
        }
        if let Some(ref recovered) = recovery
            && !ledger.snapshot_poisoned
        {
            // A completed base WAL may survive a crash before migration. Do not
            // append/requeue while an old reader can still accept the checkpoint.
            let tombstone = wal::tombstone_bytes(recovered.generation, ledger.manifest.campaign_digest);
            atomic_replace(&ledger.path, &tombstone)?;
            ledger.snapshot_poisoned = true;
        }
        if let Some(recovery) = recovery {
            if let Some(at) = recovery.truncate_at {
                // Tolerate only the torn final unsynced append: truncate to the
                // last valid frame and sync before any further append.
                let file = OpenOptions::new().write(true).open(&ledger.wal_path)?;
                file.set_len(at)?;
                file.sync_all()?;
            }
            ledger.wal = Some(wal::Wal::open_append(
                &ledger.wal_path,
                recovery.generation,
                recovery.last_seq,
                recovery.logical,
            )?);
        }
        ledger.requeue_interrupted()?;
        Ok(ledger)
    }

    pub fn manifest(&self) -> &CampaignManifest {
        &self.manifest
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    pub fn records(&self) -> &[Record] {
        &self.records
    }
    /// One coherent snapshot: ownership and accepted evidence share one WAL generation.
    pub fn read_snapshot(&self) -> (&[Record], &[AcceptedEvidence]) {
        (&self.records, &self.evidence)
    }
    /// Latest accepted disposition for each path; event history remains in read_snapshot.
    /// O(n) with a precomputed last index per path (no O(n^2) suffix scans).
    pub fn cumulative_evidence(&self) -> impl Iterator<Item = &AcceptedEvidence> {
        self.evidence
            .iter()
            .enumerate()
            .filter(|(index, event)| self.latest.get(&event.delta.path.path_id) == Some(index))
            .map(|(_, event)| event)
    }
    /// Last fsynced WAL transaction sequence; `None` before the first transition.
    pub fn durable_sequence(&self) -> Option<u64> {
        self.wal.as_ref().map(|wal| wal.seq)
    }
    /// Durable state bytes in the WAL (base frame plus transactions, header excluded).
    pub fn durable_wal_bytes(&self) -> u64 {
        self.wal.as_ref().map_or(0, |wal| wal.logical)
    }

    /// Reserve one queued unit; a stale attempt cannot later publish a result.
    pub fn reserve(&mut self) -> Result<Option<Reservation>, Error> {
        let len = self.records.len();
        if len == 0 {
            return Ok(None);
        }
        let hint = self.reserve_hint.min(len);
        let index = (hint..len)
            .chain(0..hint)
            .find(|&index| self.records[index].status == Status::Queued && !self.records[index].retired);
        match index {
            Some(index) => {
                self.reserve_hint = index + 1;
                self.reserve_index(Some(index), None)
            }
            None => Ok(None),
        }
    }

    /// Rank sealed, exact dynamic-prefix suffixes rather than insertion order.
    /// Only direct successor targets are known; no CFG reachability is inferred.
    pub fn reserve_by_rank(&mut self, find: &[u64], avoid: &[u64]) -> Result<Option<Reservation>, Error> {
        let index = self.ranked_index(find, avoid)?;
        self.reserve_index(index, None)
    }

    fn ranked_index(&self, find: &[u64], avoid: &[u64]) -> Result<Option<usize>, Error> {
        if find.windows(2).any(|w| w[0] >= w[1]) || avoid.windows(2).any(|w| w[0] >= w[1]) {
            return Err(Error::InvalidTransition);
        }
        let index = self
            .records
            .iter()
            .enumerate()
            .filter(|(_, r)| r.status == Status::Queued && !r.retired)
            .min_by_key(|(_, r)| {
                let last = r.unit.prefix.last();
                let target = last.map(|d| d.target());
                let class = if target.is_some_and(|t| find.binary_search(&t).is_ok()) {
                    0u8
                } else if target.is_some_and(|t| avoid.binary_search(&t).is_ok()) {
                    2
                } else {
                    1
                };
                (
                    class,
                    target.unwrap_or(u64::MAX),
                    last.map(|d| d.branch.predicate_digest.0).unwrap_or([0; 32]),
                    work_path_id(&r.unit, &r.replay).0,
                )
            })
            .map(|(index, _)| index);
        Ok(index)
    }

    fn reserve_index(&mut self, index: Option<usize>, owner_id: Option<Digest>) -> Result<Option<Reservation>, Error> {
        self.ensure_healthy()?;
        let Some(index) = index else { return Ok(None) };
        if self.records[index].status != Status::Queued || self.records[index].retired {
            return Err(Error::StaleReservation);
        }
        let attempt = self.records[index].attempt.checked_add(1).ok_or(Error::LimitExceeded)?;
        let reservation = Reservation {
            unit: self.records[index].unit.clone(),
            replay: self.records[index].replay.clone(),
            attempt,
        };
        self.append_txns(vec![wal::Txn::Reserve {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt,
            owner: owner_id,
        }])?;
        let record = &mut self.records[index];
        record.attempt = attempt;
        record.status = Status::Active;
        record.owner_id = owner_id;
        Ok(Some(reservation))
    }

    /// Defer an active unit with a reproducible replay descriptor and reason.
    pub fn defer(&mut self, reservation: &Reservation, reason: &str) -> Result<(), Error> {
        self.finish(reservation, Status::Deferred, reason)
    }

    /// Explicitly retry an unresolved leaf. The next reserve issues a new attempt.
    pub fn requeue(&mut self, unit: &WorkUnit) -> Result<(), Error> {
        self.ensure_healthy()?;
        let index = self
            .records
            .iter()
            .position(|r| &r.unit == unit)
            .ok_or(Error::NotFound)?;
        if self.records[index].retired
            || !matches!(
                self.records[index].status,
                Status::Deferred | Status::Unknown | Status::Failed
            )
        {
            return Err(Error::InvalidTransition);
        }
        let attempt = self.records[index].attempt;
        self.append_txns(vec![wal::Txn::Requeue {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt,
        }])?;
        let record = &mut self.records[index];
        record.status = Status::Queued;
        record.reason.clear();
        self.reserve_hint = self.reserve_hint.min(index);
        Ok(())
    }

    /// Record one accepted disposition. Unknown and failed remain incomplete.
    /// Queued and active are only entered through reserve/recovery.
    pub fn finish(&mut self, reservation: &Reservation, status: Status, reason: &str) -> Result<(), Error> {
        if !matches!(
            status,
            Status::Deferred
                | Status::Completed
                | Status::Infeasible
                | Status::Unknown
                // Exclusion requires an atomic split proof.
                | Status::Failed
        ) || reason.is_empty()
            || reason.len() > MAX_REASON
        {
            return Err(Error::InvalidTransition);
        }
        let index = self.active_index(reservation)?;
        self.append_txns(vec![wal::Txn::Finish {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt: reservation.attempt,
            status,
            reason: reason.to_owned(),
        }])?;
        let record = &mut self.records[index];
        record.status = status;
        record.owner_id = None;
        record.reason = reason.to_owned();
        Ok(())
    }

    /// Atomically replace a verified active parent by BOTH children, each with an
    /// explicit disposition. Parent and children commit in one fsynced WAL frame.
    pub fn split(
        &mut self,
        reservation: &Reservation,
        false_child: WorkUnit,
        true_child: WorkUnit,
        false_status: ChildDisposition,
        true_status: ChildDisposition,
    ) -> Result<(), Error> {
        if matches!(
            false_status,
            ChildDisposition::Infeasible(_) | ChildDisposition::Excluded(_)
        ) || matches!(
            true_status,
            ChildDisposition::Infeasible(_) | ChildDisposition::Excluded(_)
        ) {
            return Err(Error::InvalidTransition);
        }
        let (index, children) = self.prepare_split(reservation, false_child, true_child, false_status, true_status)?;
        self.append_txns(vec![wal::Txn::Split {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt: reservation.attempt,
            children: Box::new(children.clone()),
            parent_event: None,
            child_events: Box::new([None, None]),
        }])?;
        self.apply_split(index, children);
        Ok(())
    }

    /// Commit BOTH child dispositions and the observed parent path in one snapshot.
    pub fn split_with_evidence(
        &mut self,
        reservation: &Reservation,
        false_child: WorkUnit,
        true_child: WorkUnit,
        false_status: ChildDisposition,
        true_status: ChildDisposition,
        delta: EvidenceDelta,
    ) -> Result<(), Error> {
        self.split_with_proofs(
            reservation,
            false_child,
            true_child,
            false_status,
            true_status,
            SplitProofs {
                delta,
                child_proofs: [None, None],
            },
        )
    }

    /// Publish a fenced split, its observed parent path and each infeasible child
    /// query in the same bounded, checksummed and fsynced ownership snapshot.
    pub fn split_with_proofs_fenced(
        &mut self,
        grant: &FencedReservation,
        false_child: WorkUnit,
        true_child: WorkUnit,
        false_status: ChildDisposition,
        true_status: ChildDisposition,
        proofs: SplitProofs,
    ) -> Result<(), Error> {
        self.validate_fence(grant)?;
        self.split_with_proofs(
            &grant.reservation,
            false_child,
            true_child,
            false_status,
            true_status,
            proofs,
        )
    }

    fn split_with_proofs(
        &mut self,
        reservation: &Reservation,
        false_child: WorkUnit,
        true_child: WorkUnit,
        false_status: ChildDisposition,
        true_status: ChildDisposition,
        proofs: SplitProofs,
    ) -> Result<(), Error> {
        self.ensure_healthy()?;
        let (index, children) = self.prepare_split(reservation, false_child, true_child, false_status, true_status)?;
        let event = AcceptedEvidence {
            work_index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt: reservation.attempt,
            replay_digest: reservation.replay.initial_state_digest,
            status: Status::Completed,
            delta: proofs.delta,
        };
        let mut next_record = self.records[index].clone();
        next_record.retired = true;
        next_record.status = Status::Completed;
        next_record.owner_id = None;
        next_record.reason = SPLIT_REASON.into();
        self.check_new_evidence(&event, &next_record)?;
        if children
            .iter()
            .any(|r| matches!(r.status, Status::Infeasible | Status::Excluded))
        {
            for child in &children {
                let decision = child.unit.prefix.last().ok_or(Error::InvalidTransition)?;
                let matches: Vec<_> = event
                    .delta
                    .path
                    .branches
                    .iter()
                    .rev()
                    .take(2)
                    .filter(|branch| {
                        branch.pc == decision.branch.branch_pc
                            && branch.visit_index == decision.branch.visit_index
                            && branch.predicate_digest == decision.branch.predicate_digest.0
                            && branch.tested_target == Some(decision.target())
                    })
                    .collect();
                if matches.len() != 1
                    || !match child.status {
                        Status::Infeasible => matches[0].disposition == SolverDisposition::Unsat,
                        Status::Queued | Status::Deferred => matches[0].disposition == SolverDisposition::Sat,
                        Status::Unknown => !matches!(
                            matches[0].disposition,
                            SolverDisposition::Sat | SolverDisposition::Unsat
                        ),
                        Status::Excluded => matches[0].disposition == SolverDisposition::Sat,
                        Status::Failed => true,
                        Status::Active | Status::Completed => false,
                    }
                {
                    return Err(Error::InvalidTransition);
                }
            }
        }
        let mut child_events: [Option<AcceptedEvidence>; 2] = [None, None];
        for (offset, proof) in proofs.child_proofs.into_iter().enumerate() {
            if matches!(children[offset].status, Status::Infeasible | Status::Excluded) != proof.is_some() {
                return Err(Error::InvalidTransition);
            }
            if let Some(delta) = proof {
                let child_event = AcceptedEvidence {
                    work_index: u32::try_from(self.records.len() + offset).map_err(|_| Error::LimitExceeded)?,
                    attempt: 0, // No child reservation: proof belongs to the parent split.
                    replay_digest: reservation.replay.initial_state_digest,
                    status: children[offset].status,
                    delta,
                };
                self.validate_split_proof(&event, &child_event, &children[offset])?;
                child_events[offset] = Some(child_event);
            }
        }
        self.append_txns(vec![wal::Txn::Split {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt: reservation.attempt,
            children: Box::new(children.clone()),
            parent_event: Some(Box::new(event.clone())),
            child_events: Box::new(child_events.clone()),
        }])?;
        self.apply_split(index, children);
        self.note_evidence(event);
        for child in child_events.into_iter().flatten() {
            self.note_evidence(child);
        }
        Ok(())
    }

    /// Apply an already-durably-appended split: retire the parent, append both
    /// children. A parent is never retired without its durable children.
    fn apply_split(&mut self, index: usize, children: [Record; 2]) {
        let record = &mut self.records[index];
        record.retired = true;
        record.status = Status::Completed;
        record.owner_id = None;
        record.reason = SPLIT_REASON.into();
        self.records.push(children[0].clone());
        self.records.push(children[1].clone());
    }

    fn prepare_split(
        &self,
        reservation: &Reservation,
        false_child: WorkUnit,
        true_child: WorkUnit,
        false_status: ChildDisposition,
        true_status: ChildDisposition,
    ) -> Result<(usize, [Record; 2]), Error> {
        let index = self.active_index(reservation)?;
        validate_split(&reservation.unit, &false_child, &true_child, &self.manifest, self.epoch)?;
        if self.records.len() > MAX_UNITS - 2 {
            return Err(Error::LimitExceeded);
        }
        // The active parent is an owned leaf of the previously validated
        // frontier. Replacing it by the two children of the same verified fork
        // preserves prefix-free ownership without rebuilding the whole trie.
        let replay = self.records[index].replay.clone();
        let mut children = Vec::with_capacity(2);
        for (unit, disposition) in [(false_child, false_status), (true_child, true_status)] {
            let (status, reason) = disposition.parts()?;
            children.push(Record {
                unit,
                replay: replay.clone(),
                status,
                reason,
                attempt: 0,
                owner_id: None,
                retired: false,
            });
        }
        let children: [Record; 2] = children.try_into().map_err(|_| Error::InvalidTransition)?;
        Ok((index, children))
    }

    pub fn report(&self) -> Report {
        let mut result = Report::default();
        for record in &self.records {
            if record.retired {
                result.retired_splits += 1;
                continue;
            }
            let count = match record.status {
                Status::Queued => &mut result.queued,
                Status::Active => &mut result.active,
                Status::Deferred => &mut result.deferred,
                Status::Completed => &mut result.completed,
                Status::Infeasible => &mut result.infeasible,
                Status::Unknown => &mut result.unknown,
                Status::Excluded => &mut result.excluded,
                Status::Failed => &mut result.failed,
            };
            *count += 1;
        }
        result.complete_within_declared_bounds = !self.poisoned
            && result.completed + result.infeasible + result.excluded > 0
            && result.queued + result.active + result.deferred + result.unknown + result.failed == 0;
        result
    }

    fn active_index(&self, reservation: &Reservation) -> Result<usize, Error> {
        self.ensure_healthy()?;
        let index = self
            .records
            .iter()
            .position(|r| r.unit == reservation.unit)
            .ok_or(Error::NotFound)?;
        let record = &self.records[index];
        if record.attempt != reservation.attempt
            || record.replay != reservation.replay
            || record.status != Status::Active
            || record.retired
        {
            return Err(Error::StaleReservation);
        }
        Ok(index)
    }
    fn ensure_healthy(&self) -> Result<(), Error> {
        if self.poisoned { Err(Error::Poisoned) } else { Ok(()) }
    }

    /// Requeue every interrupted active record with a fresh durable fence.
    fn requeue_interrupted(&mut self) -> Result<(), Error> {
        let mut txns = Vec::new();
        let mut applied = Vec::new();
        for (index, record) in self.records.iter().enumerate() {
            if record.status == Status::Active {
                let attempt = record.attempt.checked_add(1).ok_or(Error::LimitExceeded)?;
                txns.push(wal::Txn::Requeue {
                    index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
                    attempt,
                });
                applied.push((index, attempt));
            }
        }
        if txns.is_empty() {
            return Ok(());
        }
        self.append_txns(txns)?;
        for (index, attempt) in applied {
            let record = &mut self.records[index];
            record.attempt = attempt;
            record.status = Status::Queued;
            record.owner_id = None;
            record.reason.clear();
            self.reserve_hint = self.reserve_hint.min(index);
        }
        Ok(())
    }

    fn note_evidence(&mut self, event: AcceptedEvidence) {
        let index = self.evidence.len();
        self.latest_by_work.insert(event.work_index, index);
        self.latest.insert(event.delta.path.path_id, index);
        self.evidence.push(event);
    }
    fn rebuild_evidence_indexes(&mut self) {
        self.latest.clear();
        self.latest_by_work.clear();
        for (index, event) in self.evidence.iter().enumerate() {
            self.latest_by_work.insert(event.work_index, index);
            self.latest.insert(event.delta.path.path_id, index);
        }
    }

    /// Append one bounded, versioned, checksummed WAL transaction set, fsynced
    /// BEFORE the caller mutates in-memory state. The first append creates the
    /// WAL from the checkpoint and tombstones the checkpoint so pre-WAL
    /// binaries fail closed. Failure to persist poisons this handle.
    fn append_txns(&mut self, txns: Vec<wal::Txn>) -> Result<(), Error> {
        self.ensure_healthy()?;
        if txns.is_empty() {
            return Ok(());
        }
        let mut encoded = Vec::with_capacity(txns.len());
        let mut extra: u64 = 0;
        for txn in &txns {
            let (kind, payload) = wal::encode_txn(txn)?;
            extra = extra
                .checked_add(53 + payload.len() as u64)
                .ok_or(Error::LimitExceeded)?;
            encoded.push((kind, payload));
        }
        if self.wal.is_none() {
            let base_len = self.base_snapshot.as_ref().map_or(0, |base| 53 + base.len() as u64);
            extra = extra.checked_add(base_len).ok_or(Error::LimitExceeded)?;
        }
        let logical: u64 = self.wal.as_ref().map_or(0, |wal| wal.logical);
        let checkpoint_bytes = if self.snapshot_poisoned {
            wal::TOMBSTONE_LEN as u64
        } else {
            self.base_snapshot
                .as_ref()
                .map_or(wal::TOMBSTONE_LEN as u64, |base| base.len() as u64)
                .max(wal::TOMBSTONE_LEN as u64)
        };
        let wal_total = logical
            .checked_add(extra)
            .and_then(|n| n.checked_add(wal::WAL_HEADER_LEN as u64));
        let budget = (MAX_STORE as u64).min(self.manifest.spec.limits.max_disk_bytes);
        if wal_total.is_none_or(|total| {
            total > wal::MAX_WAL_BYTES || total.checked_add(checkpoint_bytes).is_none_or(|sum| sum > budget)
        }) {
            return Err(Error::LimitExceeded);
        }
        let result = (|| -> Result<(), Error> {
            if self.wal.is_none() {
                let base = self.base_snapshot.take().ok_or(Error::Corrupt)?;
                let anchor = Digest::of(&base);
                let wal = wal::Wal::create(&self.wal_path, 1, self.manifest.campaign_digest, anchor, &base)?;
                sync_parent(&self.wal_path)?;
                self.wal = Some(wal);
            }
            if !self.snapshot_poisoned {
                let generation = self.wal.as_ref().map(|wal| wal.generation).ok_or(Error::Corrupt)?;
                let tombstone = wal::tombstone_bytes(generation, self.manifest.campaign_digest);
                atomic_replace(&self.path, &tombstone)?;
                self.snapshot_poisoned = true;
            }
            self.wal.as_mut().ok_or(Error::Corrupt)?.append_encoded(&encoded)?;
            Ok(())
        })();
        if let Err(err) = result {
            self.poisoned = true;
            return Err(err);
        }
        Ok(())
    }

    fn encode(&self) -> Result<Vec<u8>, Error> {
        encode(self.manifest.campaign_digest, self.epoch, &self.records, &self.evidence)
    }
    fn validate_records(&self) -> Result<(), Error> {
        #[derive(Default)]
        struct Node {
            record: Option<usize>,
            branch: Option<BranchPoint>,
            children: [Option<usize>; 2],
        }

        if self.records.is_empty() || self.records.len() > MAX_UNITS || self.epoch == 0 {
            return Err(Error::Corrupt);
        }
        if self.records[0].unit != WorkUnit::root(&self.manifest, self.epoch)? {
            return Err(Error::Corrupt);
        }
        let mut nodes = vec![Node::default()];
        for (i, record) in self.records.iter().enumerate() {
            record.unit.validate(&self.manifest, self.epoch)?;
            if record.replay.initial_state_digest == Digest::default()
                || record.reason.len() > MAX_REASON
                || (record.retired && record.status != Status::Completed)
                || (record.status == Status::Active && record.attempt == 0)
                || (record.owner_id.is_some()
                    && (record.status != Status::Active || record.owner_id == Some(Digest::default())))
            {
                return Err(Error::Corrupt);
            }
            let mut node = 0;
            for decision in &record.unit.prefix {
                let edge = match decision.successor {
                    Successor::False => 0,
                    Successor::True => 1,
                };
                if let Some(branch) = &nodes[node].branch {
                    if branch != &decision.branch {
                        return Err(Error::Corrupt);
                    }
                } else {
                    nodes[node].branch = Some(decision.branch.clone());
                }
                node = match nodes[node].children[edge] {
                    Some(child) => child,
                    None => {
                        if nodes.len() >= self.records.len() {
                            return Err(Error::Corrupt);
                        }
                        let child = nodes.len();
                        nodes[node].children[edge] = Some(child);
                        nodes.push(Node::default());
                        child
                    }
                };
            }
            if nodes[node].record.replace(i).is_some() {
                return Err(Error::Corrupt);
            }
        }
        // Every indexed prefix must have a record; only retired records may
        // fork, and their exact two children must cover the same branch.
        for node in &nodes {
            let parent = &self.records[node.record.ok_or(Error::Corrupt)?];
            if parent.retired {
                let false_index = nodes[node.children[0].ok_or(Error::Corrupt)?]
                    .record
                    .ok_or(Error::Corrupt)?;
                let true_index = nodes[node.children[1].ok_or(Error::Corrupt)?]
                    .record
                    .ok_or(Error::Corrupt)?;
                let false_child = &self.records[false_index];
                let true_child = &self.records[true_index];
                if false_child.replay != parent.replay
                    || true_child.replay != parent.replay
                    || validate_split(
                        &parent.unit,
                        &false_child.unit,
                        &true_child.unit,
                        &self.manifest,
                        self.epoch,
                    )
                    .is_err()
                {
                    return Err(Error::Corrupt);
                }
            } else if node.children.iter().any(Option::is_some) {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildDisposition {
    Queued,
    Deferred(String),
    Infeasible(String),
    Unknown(String),
    Excluded(String),
    Failed(String),
}

/// Evidence committed atomically with both children of a split.
pub struct SplitProofs {
    pub delta: EvidenceDelta,
    pub child_proofs: [Option<EvidenceDelta>; 2],
}

impl ChildDisposition {
    fn parts(self) -> Result<(Status, String), Error> {
        let (status, reason) = match self {
            Self::Queued => (Status::Queued, String::new()),
            Self::Deferred(s) => (Status::Deferred, s),
            Self::Infeasible(s) => (Status::Infeasible, s),
            Self::Unknown(s) => (Status::Unknown, s),
            Self::Excluded(s) => (Status::Excluded, s),
            Self::Failed(s) => (Status::Failed, s),
        };
        if reason.len() > MAX_REASON || (status != Status::Queued && reason.is_empty()) {
            return Err(Error::InvalidTransition);
        }
        Ok((status, reason))
    }
}

fn acquire_lock(path: &Path) -> Result<File, Error> {
    // Share the legacy lock during migration so an older process cannot keep
    // a snapshot-only ledger open while we begin accepting WAL transactions.
    let lock_path = path.with_extension("frontier.lock");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.try_lock().map_err(|error| match error {
        // A concurrent writer is an expected operator mistake, not a generic I/O fault.
        std::fs::TryLockError::WouldBlock => Error::Locked,
        std::fs::TryLockError::Error(inner) => Error::Io(inner),
    })?;
    Ok(lock)
}
fn sync_parent(path: &Path) -> std::io::Result<()> {
    // A bare relative filename ('campaign.ledger') has an empty parent
    // component, not None: fsync the working directory instead of opening ''.
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)?.sync_all()
}
fn atomic_replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let temp = wal::suffix_path(path, &format!(".{}.{}.tmp", std::process::id(), id));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn put_len(out: &mut Vec<u8>, n: usize) -> Result<(), Error> {
    out.extend_from_slice(&u32::try_from(n).map_err(|_| Error::LimitExceeded)?.to_le_bytes());
    Ok(())
}
fn encode(campaign: Digest, epoch: u64, records: &[Record], events: &[AcceptedEvidence]) -> Result<Vec<u8>, Error> {
    if records.is_empty() || records.len() > MAX_UNITS {
        return Err(Error::LimitExceeded);
    }
    let mut out = Vec::new();
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&campaign.0);
    put_u64(&mut out, epoch);
    put_len(&mut out, records.len())?;
    for record in records {
        encode_record(&mut out, record)?;
    }
    evidence::encode(events, &mut out)?;
    if out.len() + 32 > MAX_STORE {
        return Err(Error::LimitExceeded);
    }
    out.extend_from_slice(&Digest::of(&out).0);
    Ok(out)
}

/// One record exactly as it appears inside the snapshot and inside WAL frames.
pub(crate) fn encode_record(out: &mut Vec<u8>, record: &Record) -> Result<(), Error> {
    let start = out.len();
    out.extend_from_slice(&record.unit.schema_version.to_le_bytes());
    out.extend_from_slice(&record.unit.campaign_digest.0);
    put_u64(out, record.unit.contract_epoch);
    put_len(out, record.unit.prefix.len())?;
    for decision in &record.unit.prefix {
        let b = &decision.branch;
        for n in [
            b.branch_pc,
            b.visit_index,
            b.false_target,
            b.true_target,
            b.prefix_constraints,
        ] {
            put_u64(out, n);
        }
        out.extend_from_slice(&b.trace_digest.0);
        out.extend_from_slice(&b.predicate_digest.0);
        out.push(match decision.successor {
            Successor::False => 0,
            Successor::True => 1,
        });
    }
    out.extend_from_slice(&record.replay.initial_state_digest.0);
    out.push(match record.status {
        Status::Queued => 0,
        Status::Active => 1,
        Status::Deferred => 2,
        Status::Completed => 3,
        Status::Infeasible => 4,
        Status::Unknown => 5,
        Status::Excluded => 6,
        Status::Failed => 7,
    });
    out.push(u8::from(record.retired));
    put_u64(out, record.attempt);
    out.push(u8::from(record.owner_id.is_some()));
    if let Some(owner) = record.owner_id {
        out.extend_from_slice(&owner.0);
    }
    put_len(out, record.reason.len())?;
    out.extend_from_slice(record.reason.as_bytes());
    if record.reason.len() > MAX_REASON || out.len() - start > MAX_RECORD {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}
pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) pos: usize,
}
impl<'a> Cursor<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Corrupt)?;
        let bytes = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }
    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }
    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        Ok(u64::from_le_bytes(
            self.take(8)?.try_into().map_err(|_| Error::Corrupt)?,
        ))
    }
    pub(crate) fn digest(&mut self) -> Result<Digest, Error> {
        Ok(Digest(self.take(32)?.try_into().map_err(|_| Error::Corrupt)?))
    }
}
pub(crate) fn decode_record(c: &mut Cursor<'_>, legacy: bool, manifest: &CampaignManifest) -> Result<Record, Error> {
    let start = c.pos;
    let schema_version = c.u32()?;
    let campaign_digest = c.digest()?;
    let contract_epoch = c.u64()?;
    let depth = c.u32()? as usize;
    if depth > MAX_RECORD / 105 || depth as u64 > manifest.spec.limits.max_path_depth {
        return Err(Error::Corrupt);
    }
    let mut prefix = Vec::with_capacity(depth);
    for _ in 0..depth {
        let branch = BranchPoint {
            branch_pc: c.u64()?,
            visit_index: c.u64()?,
            false_target: c.u64()?,
            true_target: c.u64()?,
            prefix_constraints: c.u64()?,
            trace_digest: c.digest()?,
            predicate_digest: c.digest()?,
        };
        let successor = match c.u8()? {
            0 => Successor::False,
            1 => Successor::True,
            _ => return Err(Error::Corrupt),
        };
        prefix.push(BranchDecision { branch, successor });
    }
    let replay = ReplayDescriptor {
        initial_state_digest: c.digest()?,
    };
    let status = match c.u8()? {
        0 => Status::Queued,
        1 => Status::Active,
        2 => Status::Deferred,
        3 => Status::Completed,
        4 => Status::Infeasible,
        5 => Status::Unknown,
        6 => Status::Excluded,
        7 => Status::Failed,
        _ => return Err(Error::Corrupt),
    };
    let retired = match c.u8()? {
        0 => false,
        1 => true,
        _ => return Err(Error::Corrupt),
    };
    let attempt = c.u64()?;
    let owner_id = if legacy {
        None
    } else {
        match c.u8()? {
            0 => None,
            1 => Some(c.digest()?),
            _ => return Err(Error::Corrupt),
        }
    };
    let reason_len = c.u32()? as usize;
    if reason_len > MAX_REASON {
        return Err(Error::Corrupt);
    }
    let reason = String::from_utf8(c.take(reason_len)?.to_vec()).map_err(|_| Error::Corrupt)?;
    if c.pos - start > MAX_RECORD {
        return Err(Error::Corrupt);
    }
    Ok(Record {
        unit: WorkUnit {
            schema_version,
            campaign_digest,
            contract_epoch,
            prefix,
        },
        replay,
        status,
        reason,
        attempt,
        owner_id,
        retired,
    })
}
fn decode(bytes: &[u8], manifest: &CampaignManifest) -> Result<(u64, Vec<Record>, Vec<AcceptedEvidence>), Error> {
    if bytes.len() < 8 + 32 + 8 + 4 + 32 || bytes.len() > MAX_STORE {
        return Err(Error::Corrupt);
    }
    let (payload, checksum) = bytes.split_at(bytes.len() - 32);
    if Digest::of(payload).0.as_slice() != checksum {
        return Err(Error::Corrupt);
    }
    let mut c = Cursor { bytes: payload, pos: 0 };
    let header = c.take(8)?;
    let legacy = header == b"ANGFRNT1";
    if !legacy && header != MAGIC {
        return Err(Error::Corrupt);
    }
    if c.digest()? != manifest.campaign_digest {
        return Err(Error::MismatchedCampaign);
    }
    let epoch = c.u64()?;
    let count = c.u32()? as usize;
    if count == 0 || count > MAX_UNITS {
        return Err(Error::Corrupt);
    }
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(decode_record(&mut c, legacy, manifest)?);
    }
    let events = if legacy { Vec::new() } else { evidence::decode(&mut c)? };
    if c.pos != payload.len() {
        return Err(Error::Corrupt);
    }
    Ok((epoch, records, events))
}

/// Apply replayed transactions with structural bounds; full semantic validation
/// runs afterwards. Frames were validated at append time by the same version.
fn apply_txns(records: &mut Vec<Record>, evidence: &mut Vec<AcceptedEvidence>, txns: &[wal::Txn]) -> Result<(), Error> {
    for txn in txns {
        match txn {
            wal::Txn::Reserve { index, attempt, owner } => {
                let record = records.get_mut(*index as usize).ok_or(Error::Corrupt)?;
                record.attempt = *attempt;
                record.status = Status::Active;
                record.owner_id = *owner;
            }
            wal::Txn::Finish {
                index,
                attempt: _,
                status,
                reason,
            } => {
                let record = records.get_mut(*index as usize).ok_or(Error::Corrupt)?;
                record.status = *status;
                record.owner_id = None;
                record.reason = reason.clone();
            }
            wal::Txn::Outcome {
                index,
                attempt: _,
                status,
                reason,
                event,
            } => {
                if event.work_index != *index {
                    return Err(Error::Corrupt);
                }
                let record = records.get_mut(*index as usize).ok_or(Error::Corrupt)?;
                record.status = *status;
                record.owner_id = None;
                record.reason = reason.clone();
                evidence.push((**event).clone());
            }
            wal::Txn::Requeue { index, attempt } | wal::Txn::Revoke { index, attempt } => {
                let record = records.get_mut(*index as usize).ok_or(Error::Corrupt)?;
                record.attempt = *attempt;
                record.status = Status::Queued;
                record.owner_id = None;
                record.reason.clear();
            }
            wal::Txn::Split {
                index,
                attempt: _,
                children,
                parent_event,
                child_events,
            } => {
                let record = records.get_mut(*index as usize).ok_or(Error::Corrupt)?;
                record.retired = true;
                record.status = Status::Completed;
                record.owner_id = None;
                record.reason = SPLIT_REASON.into();
                records.push(children[0].clone());
                records.push(children[1].clone());
                if let Some(event) = parent_event {
                    evidence.push((**event).clone());
                }
                for event in child_events.iter().flatten() {
                    evidence.push(event.clone());
                }
            }
        }
    }
    Ok(())
}

impl SustainedLedger {
    /// Commit an accepted path and its disposition in the same durable WAL frame.
    pub fn commit_outcome(
        &mut self,
        reservation: &Reservation,
        status: Status,
        reason: &str,
        delta: EvidenceDelta,
    ) -> Result<(), Error> {
        self.ensure_healthy()?;
        if !matches!(
            status,
            Status::Deferred
                | Status::Completed
                | Status::Infeasible
                | Status::Unknown
                // Exclusion requires an atomic split proof.
                | Status::Failed
        ) || reason.is_empty()
            || reason.len() > MAX_REASON
        {
            return Err(Error::InvalidTransition);
        }
        let index = self
            .records
            .iter()
            .position(|r| r.unit == reservation.unit)
            .ok_or(Error::NotFound)?;
        let event = AcceptedEvidence {
            work_index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt: reservation.attempt,
            replay_digest: reservation.replay.initial_state_digest,
            status,
            delta,
        };
        if let Some(&prior) = self.latest_by_work.get(&event.work_index) {
            let old = &self.evidence[prior];
            if old.attempt == event.attempt && old.delta.sequence == event.delta.sequence {
                return if old == &event && self.records[index].status == status && self.records[index].reason == reason
                {
                    Ok(())
                } else {
                    Err(Error::InvalidTransition)
                };
            }
        }
        self.active_index(reservation)?;
        let mut next_record = self.records[index].clone();
        next_record.status = status;
        next_record.owner_id = None;
        next_record.reason = reason.to_owned();
        self.check_new_evidence(&event, &next_record)?;
        self.append_txns(vec![wal::Txn::Outcome {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt: reservation.attempt,
            status,
            reason: reason.to_owned(),
            event: Box::new(event.clone()),
        }])?;
        let record = &mut self.records[index];
        record.status = status;
        record.owner_id = None;
        record.reason = reason.to_owned();
        self.note_evidence(event);
        Ok(())
    }

    fn check_new_evidence(&self, event: &AcceptedEvidence, record: &Record) -> Result<(), Error> {
        if event.attempt == 0
            || event.attempt != record.attempt
            || event.replay_digest != record.replay.initial_state_digest
            || event.delta.path.path_id != work_path_id(&record.unit, &record.replay).0
            || event.status != record.status
        {
            return Err(Error::InvalidTransition);
        }
        evidence::validate_event(event, &self.manifest, self.epoch, record.retired)?;
        if let Some(&prior) = self.latest.get(&event.delta.path.path_id)
            && self.evidence[prior].work_index != event.work_index
        {
            return Err(Error::InvalidTransition);
        }
        if let Some(&prior) = self.latest_by_work.get(&event.work_index) {
            let old = &self.evidence[prior];
            if old.attempt >= event.attempt || old.delta.sequence >= event.delta.sequence {
                return Err(Error::InvalidTransition);
            }
        }
        Ok(())
    }

    fn validate_split_proof(
        &self,
        parent: &AcceptedEvidence,
        child: &AcceptedEvidence,
        record: &Record,
    ) -> Result<(), Error> {
        let path = &child.delta.path;
        let observed = &parent.delta.path;
        let decision = record.unit.prefix.last().ok_or(Error::InvalidTransition)?;
        let point = &decision.branch;
        let target = decision.target();
        let other_target = if decision.successor == Successor::True {
            point.false_target
        } else {
            point.true_target
        };
        let fork_queries = observed
            .branches
            .get(observed.branches.len().saturating_sub(2)..)
            .ok_or(Error::InvalidTransition)?;
        if fork_queries.len() != 2
            || [target, other_target].iter().any(|target| {
                fork_queries
                    .iter()
                    .filter(|branch| {
                        branch.pc == point.branch_pc
                            && branch.visit_index == point.visit_index
                            && branch.tested_target == Some(*target)
                            && branch.predicate_digest == point.predicate_digest.0
                    })
                    .count()
                    != 1
            })
        {
            return Err(Error::InvalidTransition);
        }
        let branch = fork_queries
            .iter()
            .find(|branch| branch.tested_target == Some(target))
            .ok_or(Error::InvalidTransition)?;
        let excluded = record.status == Status::Excluded;
        let policy_reason = format!(
            "excluded-by-policy:{}:{target:016x}",
            self.manifest
                .spec
                .policy_digest
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        );
        if child.attempt != 0
            || record.attempt != 0
            || !matches!(record.status, Status::Infeasible | Status::Excluded)
            || (excluded && record.reason != policy_reason)
            || parent.status != Status::Completed
            || child.status != record.status
            || child.replay_digest != parent.replay_digest
            || child.delta.sequence != parent.delta.sequence
            || path.path_id != work_path_id(&record.unit, &record.replay).0
            || path.disposition
                != if excluded {
                    PathDisposition::ExcludedByPolicy
                } else {
                    PathDisposition::SolverInfeasible
                }
            || path.provenance_digest != observed.provenance_digest
            || observed.provenance_digest != point.trace_digest.0
            || path.fidelity != observed.fidelity
            || path.blocks != observed.blocks
            || path.semantic_debt != observed.semantic_debt
            || path.witness.is_some()
            || branch.disposition
                != if excluded {
                    SolverDisposition::Sat
                } else {
                    SolverDisposition::Unsat
                }
            || branch.query_digest == [0; 32]
            || branch.result_digest.is_none()
            || path.branches.len() != observed.branches.len() - 1
            || path.branches[..path.branches.len() - 1] != observed.branches[..observed.branches.len() - 2]
            || path.branches.last() != Some(branch)
            || path.edges.len() != observed.edges.len() + usize::from(!excluded)
            || path.edges[..observed.edges.len()] != observed.edges
            || !excluded
                && !matches!(path.edges.last(), Some(edge) if edge.from_pc == point.branch_pc
                && edge.to_pc == target && matches!(edge.basis,
                    EdgeBasis::SolverInfeasible { predicate_digest, query_digest, result_digest }
                    if predicate_digest == branch.predicate_digest && query_digest == branch.query_digest
                        && Some(result_digest) == branch.result_digest))
            || evidence::validate_event(child, &self.manifest, self.epoch, false).is_err()
        {
            return Err(Error::InvalidTransition);
        }
        Ok(())
    }

    fn validate_evidence(&self) -> Result<(), Error> {
        let mut latest: HashMap<[u8; 32], usize> = HashMap::new();
        let mut by_work: HashMap<u32, usize> = HashMap::new();
        for (i, event) in self.evidence.iter().enumerate() {
            let record = self.records.get(event.work_index as usize).ok_or(Error::Corrupt)?;
            let split_child = event.attempt == 0 && matches!(record.status, Status::Infeasible | Status::Excluded);
            if (event.attempt == 0 && !split_child)
                || (record.status == Status::Excluded && !split_child)
                || event.attempt > record.attempt
                || event.replay_digest != record.replay.initial_state_digest
                || event.delta.path.path_id != work_path_id(&record.unit, &record.replay).0
                || evidence::validate_event(event, &self.manifest, self.epoch, record.retired).is_err()
                || latest
                    .get(&event.delta.path.path_id)
                    .is_some_and(|&prior| self.evidence[prior].work_index != event.work_index)
                || by_work.get(&event.work_index).is_some_and(|&prior| {
                    let old = &self.evidence[prior];
                    old.attempt >= event.attempt || old.delta.sequence >= event.delta.sequence
                })
            {
                return Err(Error::Corrupt);
            }
            if split_child {
                let parent = self
                    .records
                    .iter()
                    .enumerate()
                    .find(|(_, parent)| {
                        parent.retired
                            && parent.unit.prefix.len() + 1 == record.unit.prefix.len()
                            && record.unit.prefix.starts_with(&parent.unit.prefix)
                    })
                    .ok_or(Error::Corrupt)?;
                let parent_event = by_work
                    .get(&(parent.0 as u32))
                    .map(|&prior| &self.evidence[prior])
                    .ok_or(Error::Corrupt)?;
                if self.validate_split_proof(parent_event, event, record).is_err() {
                    return Err(Error::Corrupt);
                }
            } else if event.attempt == record.attempt
                && !record.retired
                && record.status != Status::Queued
                && record.status != event.status
            {
                return Err(Error::Corrupt);
            }
            latest.insert(event.delta.path.path_id, i);
            by_work.insert(event.work_index, i);
        }
        for (index, record) in self.records.iter().enumerate() {
            if matches!(record.status, Status::Infeasible | Status::Excluded)
                && record.attempt == 0
                && !by_work.contains_key(&(index as u32))
            {
                return Err(Error::Corrupt);
            }
        }
        Ok(())
    }
}

impl SustainedLedger {
    /// Grant local ownership with a durable owner identity and per-work attempt fence.
    pub fn reserve_fenced(&mut self, owner_id: Digest) -> Result<Option<FencedReservation>, Error> {
        self.reserve_fenced_with_rank(owner_id, None)
    }

    pub fn reserve_by_rank_fenced(
        &mut self,
        owner_id: Digest,
        find: &[u64],
        avoid: &[u64],
    ) -> Result<Option<FencedReservation>, Error> {
        self.reserve_fenced_with_rank(owner_id, Some((find, avoid)))
    }

    fn reserve_fenced_with_rank(
        &mut self,
        owner_id: Digest,
        rank: Option<(&[u64], &[u64])>,
    ) -> Result<Option<FencedReservation>, Error> {
        if owner_id == Digest::default() {
            return Err(Error::InvalidTransition);
        }
        let index = match rank {
            Some((find, avoid)) => self.ranked_index(find, avoid)?,
            None => self
                .records
                .iter()
                .position(|r| r.status == Status::Queued && !r.retired),
        };
        let Some(reservation) = self.reserve_index(index, Some(owner_id))? else {
            return Ok(None);
        };
        Ok(Some(FencedReservation {
            ownership_epoch: reservation.attempt,
            reservation,
            owner_id,
        }))
    }

    /// Revoke a grant and advance its generation even without a replacement.
    pub fn revoke_fenced(&mut self, grant: &FencedReservation) -> Result<(), Error> {
        let index = self.validate_fence(grant)?;
        let attempt = self.records[index].attempt.checked_add(1).ok_or(Error::LimitExceeded)?;
        self.append_txns(vec![wal::Txn::Revoke {
            index: u32::try_from(index).map_err(|_| Error::LimitExceeded)?,
            attempt,
        }])?;
        let record = &mut self.records[index];
        record.attempt = attempt;
        record.owner_id = None;
        record.status = Status::Queued;
        record.reason.clear();
        self.reserve_hint = self.reserve_hint.min(index);
        Ok(())
    }

    pub fn commit_outcome_fenced(
        &mut self,
        grant: &FencedReservation,
        status: Status,
        reason: &str,
        delta: EvidenceDelta,
    ) -> Result<(), Error> {
        self.validate_fence(grant)?;
        self.commit_outcome(&grant.reservation, status, reason, delta)
    }

    fn validate_fence(&self, grant: &FencedReservation) -> Result<usize, Error> {
        let index = self.active_index(&grant.reservation)?;
        let record = &self.records[index];
        if grant.owner_id == Digest::default()
            || record.owner_id != Some(grant.owner_id)
            || grant.ownership_epoch != record.attempt
        {
            return Err(Error::StaleReservation);
        }
        Ok(index)
    }
}

/// Exact path identity used by root replay and per-work evidence, not a PC.
pub fn work_path_id(unit: &WorkUnit, replay: &ReplayDescriptor) -> Digest {
    let mut bytes = Vec::with_capacity(72 + unit.prefix.len().saturating_mul(105));
    bytes.extend_from_slice(&unit.campaign_digest.0);
    bytes.extend_from_slice(&replay.initial_state_digest.0);
    bytes.extend_from_slice(&unit.contract_epoch.to_le_bytes());
    for decision in &unit.prefix {
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
    Digest::of(&bytes)
}
