//! Typed accepted flow evidence. Every event shares a checksum and atomic rename
//! with the exact owning work record; this module does not execute solver/replay.
use crate::sustained::{Cursor, Error, MAX_STORE, Status};
use angryier_distribution::contracts::{CampaignManifest, Digest};
pub use angryier_provenance::sustained::{
    BranchEvidence, DebtKind, DynamicBlock, EdgeBasis, EvidenceBuilder, EvidenceLimits, EvidenceScope, FailureReason,
    FlowEdge, PathDisposition, PathEvidence, PendingReason, ReplayVerification, SemanticDebt, SolverDisposition,
    WitnessEvidence,
};

pub const SCHEMA_VERSION: u32 = 3;
/// Target capacity: 65536 accepted evidence events per durable ledger.
pub const MAX_EVENTS: usize = 65536;
pub const MAX_ITEMS: usize = 4096;
pub const MAX_EVENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceDelta {
    /// Strictly increasing event number for a path across attempts.
    pub sequence: u64,
    pub path: PathEvidence,
}

impl EvidenceDelta {
    /// Validate the typed path against the sealed campaign's limits and fidelity.
    pub fn validate(&self, manifest: &CampaignManifest, epoch: u64) -> Result<(), Error> {
        if self.sequence == 0 {
            return Err(Error::InvalidTransition);
        }
        validate_path(&self.path, manifest, epoch)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedEvidence {
    /// Index of the immutable work ID in the ownership snapshot.
    pub work_index: u32,
    pub attempt: u64,
    pub replay_digest: Digest,
    pub status: Status,
    pub delta: EvidenceDelta,
}

pub(crate) fn validate_path(path: &PathEvidence, manifest: &CampaignManifest, epoch: u64) -> Result<(), Error> {
    let limits = &manifest.spec.limits;
    let mut bounds = Vec::with_capacity(80);
    for value in [
        limits.max_steps,
        limits.max_path_steps,
        limits.max_active_states,
        limits.max_path_depth,
        limits.max_loop_visits,
        limits.max_solver_millis,
        limits.max_wall_millis,
        limits.max_ram_bytes,
        limits.max_disk_bytes,
        limits.max_trace_bytes,
    ] {
        bounds.extend_from_slice(&value.to_le_bytes());
    }
    let mut builder = EvidenceBuilder::new(
        EvidenceScope {
            campaign_digest: manifest.campaign_digest.0,
            contract_epoch: epoch,
            bounds_digest: Digest::of(&bounds).0,
            fidelity: manifest.spec.fidelity,
        },
        EvidenceLimits {
            max_paths: 1,
            max_frontier: 1,
            max_items_per_path: MAX_ITEMS,
            max_bytes: MAX_EVENT_BYTES,
        },
    )
    .map_err(|_| Error::InvalidTransition)?;
    builder.add_path(path.clone()).map_err(|_| Error::InvalidTransition)
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}
fn put_digest(out: &mut Vec<u8>, digest: [u8; 32]) {
    out.extend_from_slice(&digest);
}
fn put_optional_digest(out: &mut Vec<u8>, value: Option<[u8; 32]>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        put_digest(out, value);
    }
}
fn put_optional_u64(out: &mut Vec<u8>, value: Option<u64>) {
    out.push(u8::from(value.is_some()));
    if let Some(value) = value {
        put_u64(out, value);
    }
}
fn optional_digest(c: &mut Cursor<'_>) -> Result<Option<[u8; 32]>, Error> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(c.digest()?.0)),
        _ => Err(Error::Corrupt),
    }
}
fn optional_u64(c: &mut Cursor<'_>) -> Result<Option<u64>, Error> {
    match c.u8()? {
        0 => Ok(None),
        1 => Ok(Some(c.u64()?)),
        _ => Err(Error::Corrupt),
    }
}
fn count(c: &mut Cursor<'_>) -> Result<usize, Error> {
    let count = c.u32()? as usize;
    if count > MAX_ITEMS {
        return Err(Error::Corrupt);
    }
    Ok(count)
}
fn blocks(out: &mut Vec<u8>, blocks: &[DynamicBlock]) -> Result<(), Error> {
    if blocks.len() > MAX_ITEMS {
        return Err(Error::LimitExceeded);
    }
    out.extend_from_slice(&(blocks.len() as u32).to_le_bytes());
    for block in blocks {
        put_u64(out, block.pc);
        put_u64(out, block.visit_index);
    }
    Ok(())
}
fn read_blocks(c: &mut Cursor<'_>) -> Result<Vec<DynamicBlock>, Error> {
    let size = count(c)?;
    let mut out = Vec::with_capacity(size);
    for _ in 0..size {
        out.push(DynamicBlock {
            pc: c.u64()?,
            visit_index: c.u64()?,
        });
    }
    Ok(out)
}
fn solver_byte(status: SolverDisposition) -> u8 {
    match status {
        SolverDisposition::NotQueried => 0,
        SolverDisposition::Sat => 1,
        SolverDisposition::Unsat => 2,
        SolverDisposition::Unknown => 3,
        SolverDisposition::Timeout => 4,
        SolverDisposition::ResourceLimit => 5,
        SolverDisposition::BackendError => 6,
    }
}
fn solver_status(tag: u8) -> Result<SolverDisposition, Error> {
    Ok(match tag {
        0 => SolverDisposition::NotQueried,
        1 => SolverDisposition::Sat,
        2 => SolverDisposition::Unsat,
        3 => SolverDisposition::Unknown,
        4 => SolverDisposition::Timeout,
        5 => SolverDisposition::ResourceLimit,
        6 => SolverDisposition::BackendError,
        _ => return Err(Error::Corrupt),
    })
}
fn pending_byte(reason: PendingReason) -> u8 {
    match reason {
        PendingReason::Queued => 0,
        PendingReason::Leased => 1,
        PendingReason::Deferred => 2,
        PendingReason::Unknown => 3,
        PendingReason::Timeout => 4,
        PendingReason::ResourceLimit => 5,
        PendingReason::ReplayMismatch => 6,
    }
}
fn pending_reason(tag: u8) -> Result<PendingReason, Error> {
    Ok(match tag {
        0 => PendingReason::Queued,
        1 => PendingReason::Leased,
        2 => PendingReason::Deferred,
        3 => PendingReason::Unknown,
        4 => PendingReason::Timeout,
        5 => PendingReason::ResourceLimit,
        6 => PendingReason::ReplayMismatch,
        _ => return Err(Error::Corrupt),
    })
}
fn failure_byte(reason: FailureReason) -> u8 {
    match reason {
        FailureReason::Execution => 0,
        FailureReason::Solver => 1,
        FailureReason::Replay => 2,
        FailureReason::Storage => 3,
    }
}
fn failure_reason(tag: u8) -> Result<FailureReason, Error> {
    Ok(match tag {
        0 => FailureReason::Execution,
        1 => FailureReason::Solver,
        2 => FailureReason::Replay,
        3 => FailureReason::Storage,
        _ => return Err(Error::Corrupt),
    })
}
fn encode_path(out: &mut Vec<u8>, path: &PathEvidence) -> Result<(), Error> {
    put_digest(out, path.path_id);
    put_digest(out, path.provenance_digest);
    out.push(match path.fidelity {
        angryier_types::FidelityProfile::Prove => 0,
        angryier_types::FidelityProfile::Explore => 1,
        angryier_types::FidelityProfile::Hunt => 2,
    });
    match path.disposition {
        PathDisposition::Terminal => out.push(0),
        PathDisposition::ExcludedByPolicy => out.push(1),
        PathDisposition::SolverInfeasible => out.push(2),
        PathDisposition::Pending(reason) => {
            out.push(3);
            out.push(pending_byte(reason));
        }
        PathDisposition::Failed(reason) => {
            out.push(4);
            out.push(failure_byte(reason));
        }
    }
    blocks(out, &path.blocks)?;
    if path.edges.len() > MAX_ITEMS {
        return Err(Error::LimitExceeded);
    }
    out.extend_from_slice(&(path.edges.len() as u32).to_le_bytes());
    for edge in &path.edges {
        put_u64(out, edge.from_pc);
        put_u64(out, edge.to_pc);
        match edge.basis {
            EdgeBasis::Observed { trace_digest } => {
                out.push(0);
                put_digest(out, trace_digest);
            }
            EdgeBasis::StaticInference { analysis_digest } => {
                out.push(1);
                put_digest(out, analysis_digest);
            }
            EdgeBasis::SolverInfeasible {
                predicate_digest,
                query_digest,
                result_digest,
            } => {
                out.push(2);
                for digest in [predicate_digest, query_digest, result_digest] {
                    put_digest(out, digest);
                }
            }
        }
    }
    if path.branches.len() > MAX_ITEMS {
        return Err(Error::LimitExceeded);
    }
    out.extend_from_slice(&(path.branches.len() as u32).to_le_bytes());
    for branch in &path.branches {
        put_u64(out, branch.pc);
        put_u64(out, branch.visit_index);
        put_digest(out, branch.predicate_digest);
        put_digest(out, branch.query_digest);
        put_optional_digest(out, branch.result_digest);
        put_optional_u64(out, branch.tested_target);
        out.push(solver_byte(branch.disposition));
    }
    out.push(u8::from(path.witness.is_some()));
    if let Some(witness) = &path.witness {
        put_digest(out, witness.input_digest);
        put_optional_digest(out, witness.replay_input_provenance);
        blocks(out, &witness.replay_trace)?;
        match witness.replay {
            ReplayVerification::NotChecked => out.push(0),
            ReplayVerification::Verified { trace_digest } => {
                out.push(1);
                put_digest(out, trace_digest);
            }
            ReplayVerification::Mismatch => out.push(2),
            ReplayVerification::Error => out.push(3),
        }
    }
    if path.semantic_debt.len() > MAX_ITEMS {
        return Err(Error::LimitExceeded);
    }
    out.extend_from_slice(&(path.semantic_debt.len() as u32).to_le_bytes());
    for debt in &path.semantic_debt {
        put_u64(out, debt.pc);
        out.push(match debt.kind {
            DebtKind::Approximation => 0,
            DebtKind::Concretization => 1,
            DebtKind::UnsupportedSemantics => 2,
            DebtKind::ExternalModel => 3,
            DebtKind::UnderconstrainedMemory => 4,
        });
    }
    Ok(())
}
fn decode_path(c: &mut Cursor<'_>) -> Result<PathEvidence, Error> {
    let path_id = c.digest()?.0;
    let provenance_digest = c.digest()?.0;
    let fidelity = match c.u8()? {
        0 => angryier_types::FidelityProfile::Prove,
        1 => angryier_types::FidelityProfile::Explore,
        2 => angryier_types::FidelityProfile::Hunt,
        _ => return Err(Error::Corrupt),
    };
    let disposition = match c.u8()? {
        0 => PathDisposition::Terminal,
        1 => PathDisposition::ExcludedByPolicy,
        2 => PathDisposition::SolverInfeasible,
        3 => PathDisposition::Pending(pending_reason(c.u8()?)?),
        4 => PathDisposition::Failed(failure_reason(c.u8()?)?),
        _ => return Err(Error::Corrupt),
    };
    let blocks = read_blocks(c)?;
    let edge_count = count(c)?;
    let mut edges = Vec::with_capacity(edge_count);
    for _ in 0..edge_count {
        let from_pc = c.u64()?;
        let to_pc = c.u64()?;
        let basis = match c.u8()? {
            0 => EdgeBasis::Observed {
                trace_digest: c.digest()?.0,
            },
            1 => EdgeBasis::StaticInference {
                analysis_digest: c.digest()?.0,
            },
            2 => EdgeBasis::SolverInfeasible {
                predicate_digest: c.digest()?.0,
                query_digest: c.digest()?.0,
                result_digest: c.digest()?.0,
            },
            _ => return Err(Error::Corrupt),
        };
        edges.push(FlowEdge { from_pc, to_pc, basis });
    }
    let branch_count = count(c)?;
    let mut branches = Vec::with_capacity(branch_count);
    for _ in 0..branch_count {
        branches.push(BranchEvidence {
            pc: c.u64()?,
            visit_index: c.u64()?,
            predicate_digest: c.digest()?.0,
            query_digest: c.digest()?.0,
            result_digest: optional_digest(c)?,
            tested_target: optional_u64(c)?,
            disposition: solver_status(c.u8()?)?,
        });
    }
    let witness = match c.u8()? {
        0 => None,
        1 => {
            let input_digest = c.digest()?.0;
            let replay_input_provenance = optional_digest(c)?;
            let replay_trace = read_blocks(c)?;
            let replay = match c.u8()? {
                0 => ReplayVerification::NotChecked,
                1 => ReplayVerification::Verified {
                    trace_digest: c.digest()?.0,
                },
                2 => ReplayVerification::Mismatch,
                3 => ReplayVerification::Error,
                _ => return Err(Error::Corrupt),
            };
            Some(WitnessEvidence {
                input_digest,
                replay_input_provenance,
                replay_trace,
                replay,
            })
        }
        _ => return Err(Error::Corrupt),
    };
    let debt_count = count(c)?;
    let mut semantic_debt = Vec::with_capacity(debt_count);
    for _ in 0..debt_count {
        let pc = c.u64()?;
        let kind = match c.u8()? {
            0 => DebtKind::Approximation,
            1 => DebtKind::Concretization,
            2 => DebtKind::UnsupportedSemantics,
            3 => DebtKind::ExternalModel,
            4 => DebtKind::UnderconstrainedMemory,
            _ => return Err(Error::Corrupt),
        };
        semantic_debt.push(SemanticDebt { pc, kind });
    }
    Ok(PathEvidence {
        path_id,
        provenance_digest,
        fidelity,
        blocks,
        edges,
        branches,
        witness,
        semantic_debt,
        disposition,
    })
}

pub(crate) fn status_byte(status: Status) -> u8 {
    match status {
        Status::Queued => 0,
        Status::Active => 1,
        Status::Deferred => 2,
        Status::Completed => 3,
        Status::Infeasible => 4,
        Status::Unknown => 5,
        Status::Excluded => 6,
        Status::Failed => 7,
    }
}
pub(crate) fn status_from_byte(tag: u8) -> Result<Status, Error> {
    Ok(match tag {
        2 => Status::Deferred,
        3 => Status::Completed,
        4 => Status::Infeasible,
        5 => Status::Unknown,
        6 => Status::Excluded,
        7 => Status::Failed,
        _ => return Err(Error::Corrupt),
    })
}

pub(crate) fn encode(events: &[AcceptedEvidence], out: &mut Vec<u8>) -> Result<(), Error> {
    if events.len() > MAX_EVENTS {
        return Err(Error::LimitExceeded);
    }
    out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    out.extend_from_slice(&(events.len() as u32).to_le_bytes());
    for event in events {
        encode_event(event, out)?;
        if out.len() + 32 > MAX_STORE {
            return Err(Error::LimitExceeded);
        }
    }
    Ok(())
}
pub(crate) fn decode(c: &mut Cursor<'_>) -> Result<Vec<AcceptedEvidence>, Error> {
    if c.u32()? != SCHEMA_VERSION {
        return Err(Error::Corrupt);
    }
    let count = c.u32()? as usize;
    if count > MAX_EVENTS {
        return Err(Error::Corrupt);
    }
    let mut events = Vec::with_capacity(count);
    for _ in 0..count {
        events.push(decode_event(c)?);
    }
    Ok(events)
}

/// One evidence event as it appears inside a snapshot section or a WAL frame.
pub(crate) fn encode_event(event: &AcceptedEvidence, out: &mut Vec<u8>) -> Result<(), Error> {
    let start = out.len();
    put_u64(out, event.work_index as u64);
    put_u64(out, event.attempt);
    put_digest(out, event.replay_digest.0);
    out.push(status_byte(event.status));
    put_u64(out, event.delta.sequence);
    encode_path(out, &event.delta.path)?;
    if out.len() - start > MAX_EVENT_BYTES {
        return Err(Error::LimitExceeded);
    }
    Ok(())
}
pub(crate) fn decode_event(c: &mut Cursor<'_>) -> Result<AcceptedEvidence, Error> {
    let start = c.pos;
    let work_index = u32::try_from(c.u64()?).map_err(|_| Error::Corrupt)?;
    let attempt = c.u64()?;
    let replay_digest = c.digest()?;
    let status = status_from_byte(c.u8()?)?;
    let sequence = c.u64()?;
    let path = decode_path(c)?;
    if c.pos - start > MAX_EVENT_BYTES {
        return Err(Error::Corrupt);
    }
    Ok(AcceptedEvidence {
        work_index,
        attempt,
        replay_digest,
        status,
        delta: EvidenceDelta { sequence, path },
    })
}

pub(crate) fn validate_event(
    event: &AcceptedEvidence,
    manifest: &CampaignManifest,
    epoch: u64,
    retired: bool,
) -> Result<(), Error> {
    if event.replay_digest == Digest::default() {
        return Err(Error::InvalidTransition);
    }
    event.delta.validate(manifest, epoch)?;
    let disposition = event.delta.path.disposition;
    let consistent = match event.status {
        Status::Completed => {
            matches!(disposition, PathDisposition::Terminal)
                || retired && matches!(disposition, PathDisposition::Pending(PendingReason::Queued))
        }
        Status::Infeasible => matches!(disposition, PathDisposition::SolverInfeasible),
        Status::Excluded => matches!(disposition, PathDisposition::ExcludedByPolicy),
        Status::Deferred | Status::Unknown => matches!(disposition, PathDisposition::Pending(_)),
        Status::Failed => matches!(disposition, PathDisposition::Failed(_) | PathDisposition::Pending(_)),
        Status::Queued | Status::Active => false,
    };
    if !consistent {
        return Err(Error::InvalidTransition);
    }
    validate_path(&event.delta.path, manifest, epoch)
}
