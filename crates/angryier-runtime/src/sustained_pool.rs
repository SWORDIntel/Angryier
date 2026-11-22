//! Native local workers execute fresh, disjoint symbolic roots; only the caller
//! of `run_pool` may reserve or publish ledger ownership and evidence.
use std::{
    collections::HashSet,
    thread,
    time::{Duration, Instant},
};

use angryier_arch::Decoder;
use angryier_distribution::contracts::{CampaignManifest, Digest, Successor, WorkUnit};
use angryier_ledger::{
    evidence::{DebtKind, EvidenceDelta, SemanticDebt},
    sustained::{ChildDisposition, FencedReservation, Report, Status, work_path_id},
};
use angryier_provenance::sustained::{
    PathDisposition, PathEvidence, PendingReason, ReplayVerification, SolverDisposition,
};
use angryier_solver::SolverBackend;

use crate::{
    SymbolicSession, SymbolicStepOutcome,
    sustained::{
        SustainedCampaign, SustainedError, branch_point, budget, observed_debt, observed_path, sustained_witness,
    },
};

/// Only `verify_remote` constructs the coordinator's independently replayed result.
pub struct VerifiedRemoteOutcome {
    outcome: AdvanceOutcome,
}

/// A worker's claimed result; decoding a wire result does not verify execution.
pub struct AdvanceOutcome {
    grant: FencedReservation,
    status: Status,
    reason: String,
    path: PathEvidence,
    split: Option<(WorkUnit, WorkUnit, ChildDisposition, ChildDisposition)>,
    steps: u64,
}

/// The accepted ledger snapshot, not merely this invocation's transient paths.
pub struct PoolRun {
    pub ledger: Report,
    pub accepted_path_ids: Vec<Digest>,
    pub worker_threads: HashSet<thread::ThreadId>,
    pub steps: u64,
    pub reason: Option<String>,
}

impl SustainedCampaign {
    /// The factory runs INSIDE each native worker and must create a fresh root,
    /// arena and solver there, then call `advance_sustained`. Never share a
    /// mutable session or a ledger with a worker. Only 1, 2 and 4 are supported.
    pub fn run_pool<F>(&mut self, workers: usize, timeout: Duration, factory: F) -> Result<PoolRun, SustainedError>
    where
        F: Fn(&FencedReservation, &CampaignManifest, Duration, u64) -> Result<AdvanceOutcome, SustainedError> + Sync,
    {
        if !matches!(workers, 1 | 2 | 4) {
            return Err(SustainedError::UnreplayableEnvironment(
                "pool supports only 1, 2 or 4 workers",
            ));
        }
        let manifest = self.ledger.manifest().clone();
        let deadline = timeout.min(Duration::from_millis(manifest.spec.limits.max_wall_millis));
        let start = Instant::now();
        let mut steps = 0u64;
        let mut worker_threads = HashSet::new();
        let mut reason = None;
        while start.elapsed() < deadline && steps < manifest.spec.limits.max_steps {
            let mut grants = Vec::new();
            for index in 0..workers {
                if steps + grants.len() as u64 >= manifest.spec.limits.max_steps {
                    break;
                }
                let owner = Digest::of(format!("angryier-local-worker-{index}").as_bytes());
                match self.ledger.reserve_fenced(owner) {
                    Ok(Some(grant)) => grants.push(grant),
                    Ok(None) => break,
                    Err(error) => {
                        for pending in &grants {
                            let _ = self.ledger.revoke_fenced(pending);
                        }
                        return Err(error.into());
                    }
                }
            }
            if grants.is_empty() {
                break;
            }
            let remaining = manifest.spec.limits.max_steps - steps;
            let per_grant = remaining / grants.len() as u64;
            let excess = remaining % grants.len() as u64;
            // A scoped thread constructs the non-Send symbolic root locally.
            // Joining all workers before admission keeps commit order equal to
            // durable reservation order, independent of solver finish order.
            let results = thread::scope(|scope| {
                let mut handles = Vec::new();
                for (index, grant) in grants.iter().cloned().enumerate() {
                    let budget = per_grant + u64::from((index as u64) < excess);
                    let factory = &factory;
                    let manifest = &manifest;
                    handles.push(scope.spawn(move || {
                        let id = thread::current().id();
                        (
                            id,
                            factory(&grant, manifest, deadline.saturating_sub(start.elapsed()), budget),
                        )
                    }));
                }
                handles.into_iter().map(|handle| handle.join()).collect::<Vec<_>>()
            });
            for (index, result) in results.into_iter().enumerate() {
                let grant = &grants[index];
                let (id, outcome) = match result {
                    Ok((id, Ok(outcome))) => (id, outcome),
                    Ok((_, Err(error))) => {
                        for pending in &grants[index..] {
                            self.ledger.revoke_fenced(pending)?;
                        }
                        return Err(error);
                    }
                    Err(_) => {
                        for pending in &grants[index..] {
                            self.ledger.revoke_fenced(pending)?;
                        }
                        return Err(SustainedError::UnreplayableEnvironment(
                            "worker panicked; grants revoked",
                        ));
                    }
                };
                worker_threads.insert(id);
                if outcome.grant != *grant
                    || outcome.steps > per_grant + u64::from((index as u64) < excess)
                    || outcome.path.path_id != work_path_id(&grant.reservation.unit, &grant.reservation.replay).0
                {
                    for pending in &grants[index..] {
                        self.ledger.revoke_fenced(pending)?;
                    }
                    return Err(SustainedError::Ledger(
                        angryier_ledger::sustained::Error::StaleReservation,
                    ));
                }
                let record = self
                    .ledger
                    .records()
                    .iter()
                    .find(|record| record.unit == grant.reservation.unit);
                if !record.is_some_and(|record| {
                    record.status == Status::Active
                        && !record.retired
                        && record.owner_id == Some(grant.owner_id)
                        && record.attempt == grant.ownership_epoch
                        && record.replay == grant.reservation.replay
                }) {
                    return Err(SustainedError::Ledger(
                        angryier_ledger::sustained::Error::StaleReservation,
                    ));
                }
                if outcome.split.as_ref().is_some_and(|(_, _, false_status, true_status)| {
                    matches!(false_status, ChildDisposition::Infeasible(_))
                        || matches!(true_status, ChildDisposition::Infeasible(_))
                }) {
                    // The ledger cannot atomically publish a split and the
                    // infeasible child's proof; do not claim a complete scope.
                    for pending in &grants[index..] {
                        self.ledger.revoke_fenced(pending)?;
                    }
                    return Err(SustainedError::UnreplayableEnvironment(
                        "pool cannot durably commit infeasible child evidence",
                    ));
                }
                let delta = EvidenceDelta {
                    sequence: grant.reservation.attempt,
                    path: outcome.path,
                };
                // Split is the one ledger API without a fenced variant. The
                // coordinator checks the fence above, then publishes both
                // children and parent evidence in its single-writer snapshot.
                let committed = if let Some((false_child, true_child, false_status, true_status)) = outcome.split {
                    self.ledger.split_with_evidence(
                        &grant.reservation,
                        false_child,
                        true_child,
                        false_status,
                        true_status,
                        delta,
                    )
                } else {
                    self.ledger
                        .commit_outcome_fenced(grant, outcome.status, &outcome.reason, delta)
                };
                if let Err(error) = committed {
                    // A failed fsync poisons the ledger; reopening recovers its
                    // active grants. Otherwise requeue every uncommitted grant.
                    for pending in &grants[index..] {
                        let _ = self.ledger.revoke_fenced(pending);
                    }
                    return Err(error.into());
                }
                steps += outcome.steps;
                if outcome.status != Status::Completed {
                    reason = Some(outcome.reason.to_owned());
                }
            }
        }
        let ledger = self.ledger.report();
        let mut accepted_path_ids: Vec<_> = self
            .ledger
            .cumulative_evidence()
            .map(|event| Digest(event.delta.path.path_id))
            .collect();
        accepted_path_ids.sort_by_key(|digest| digest.0);
        if !ledger.complete_within_declared_bounds && reason.is_none() {
            reason = Some("campaign has unresolved owned work".into());
        }
        Ok(PoolRun {
            ledger,
            accepted_path_ids,
            worker_threads,
            steps,
            reason,
        })
    }
}

impl<D: Decoder> SymbolicSession<'_, D> {
    /// Replay a fenced prefix from this fresh root, solve both successor
    /// directions, and return a result without touching the ledger.
    pub fn advance_sustained(
        &mut self,
        grant: &FencedReservation,
        manifest: &CampaignManifest,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
        step_budget: u64,
    ) -> Result<AdvanceOutcome, SustainedError> {
        if grant.reservation.unit.campaign_digest != manifest.campaign_digest
            || grant.reservation.unit.contract_epoch == 0
            || backend.name() != manifest.spec.solver_version
            || self.states.len() != 1
            || !self.dead.is_empty()
            || !self.pending_merges.is_empty()
        {
            return Err(SustainedError::UnreplayableEnvironment(
                "worker campaign, solver or fresh root mismatch",
            ));
        }
        let root = &self.states[0];
        if !root.process.trace.is_empty()
            || root.process.step_count != 0
            || root.process.terminated
            || root.process.pc().ok() != Some(manifest.spec.entry_pc)
            || !root.branch_history.is_empty()
            || !root.constraints.is_empty()
        {
            return Err(SustainedError::UnreplayableEnvironment(
                "worker root is not at fresh entry",
            ));
        }
        let initial = self.sustained_initial_digest()?;
        if grant.reservation.replay.initial_state_digest != initial {
            return Err(SustainedError::InitialStateMismatch);
        }
        let old_fork_policy = self.fork_on_symbolic;
        self.fork_on_symbolic = true;
        let result = self.advance_owned(grant, manifest, backend, timeout, step_budget, initial);
        self.fork_on_symbolic = old_fork_policy;
        result
    }

    fn advance_owned(
        &mut self,
        grant: &FencedReservation,
        manifest: &CampaignManifest,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
        step_budget: u64,
        initial: Digest,
    ) -> Result<AdvanceOutcome, SustainedError> {
        let limits = &manifest.spec.limits;
        let unit = &grant.reservation.unit;
        let start = Instant::now();
        let deadline = timeout.min(Duration::from_millis(limits.max_wall_millis));
        let mut solver_spent = Duration::ZERO;
        let mut steps = 0u64;
        let mut matched = 0usize;
        let mut branches = Vec::new();
        let root = self.states[0].clone();
        let mut owned_model = None;
        let mut step_debt = Vec::new();
        let debt_before = self.vector_debt_total;
        let retries_before = self.concretization_retries_total;
        let (mut status, mut disposition, mut reason, split) = loop {
            let state = &self.states[0];
            let pc = state.process.pc().ok();
            if start.elapsed() >= deadline {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::Timeout),
                    "wall timeout",
                    None,
                );
            }
            if steps >= step_budget || steps >= limits.max_path_steps {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::ResourceLimit),
                    "step budget",
                    None,
                );
            }
            if !budget(state, limits.max_trace_bytes) {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::ResourceLimit),
                    "trace/history byte budget",
                    None,
                );
            }
            let mapped = state
                .process
                .state
                .memory
                .regions()
                .iter()
                .try_fold(0u64, |sum, region| sum.checked_add(region.size));
            if mapped.is_none_or(|size| size.saturating_add(limits.max_trace_bytes) > limits.max_ram_bytes) {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::ResourceLimit),
                    "mapped state/trace RAM budget",
                    None,
                );
            }
            if pc.is_some_and(|pc| {
                state.process.trace.iter().filter(|&&v| v == pc).count() as u64 >= limits.max_loop_visits
            }) || state.branch_history.len() as u64 > limits.max_path_depth
            {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::ResourceLimit),
                    "loop/depth budget",
                    None,
                );
            }
            let vector_before_step = self.vector_debt_total;
            let retries_before_step = self.concretization_retries_total;
            let outcome = self.step_state(0);
            let site = pc.unwrap_or(manifest.spec.entry_pc);
            for _ in 0..self.vector_debt_total.saturating_sub(vector_before_step).min(4097) {
                step_debt.push(SemanticDebt {
                    pc: site,
                    kind: DebtKind::Approximation,
                });
            }
            for _ in 0..self
                .concretization_retries_total
                .saturating_sub(retries_before_step)
                .min(4097)
            {
                step_debt.push(SemanticDebt {
                    pc: site,
                    kind: DebtKind::Concretization,
                });
            }
            steps += 1;
            self.pending_merges.clear();
            let Ok(outcome) = outcome else {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::Unknown),
                    "execution failed; subtree retained",
                    None,
                );
            };
            if self.states.is_empty() {
                break (
                    Status::Deferred,
                    PathDisposition::Pending(PendingReason::Unknown),
                    "state disappeared without verified terminal",
                    None,
                );
            }
            let state = &self.states[0];
            let new_decision = state.branch_history.len() > matched;
            if matched < unit.prefix.len() {
                if !new_decision {
                    if outcome == SymbolicStepOutcome::Terminated {
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::ReplayMismatch),
                            "terminated before owned prefix",
                            None,
                        );
                    }
                    continue;
                }
                let expected = &unit.prefix[matched];
                let actual = state
                    .last_branch
                    .and_then(|decision| branch_point(self, state, decision));
                if actual.as_ref() != Some(&expected.branch) {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::ReplayMismatch),
                        "branch context mismatch on root replay",
                        None,
                    );
                }
                if !matches!(outcome, SymbolicStepOutcome::Branched { .. }) || self.states.len() != 2 {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::ReplayMismatch),
                        "owned edge not forked during replay",
                        None,
                    );
                }
                let chosen = usize::from(expected.successor == Successor::False);
                self.states.remove(1 - chosen);
                let state = &self.states[0];
                let Some(direction) = state.constraints.last().copied() else {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::Unknown),
                        "replay constraint unavailable",
                        None,
                    );
                };
                let remaining = deadline
                    .saturating_sub(start.elapsed())
                    .min(Duration::from_millis(limits.max_solver_millis).saturating_sub(solver_spent));
                let query_start = Instant::now();
                let (proof, model) = self.sustained_query_with_model(
                    state,
                    direction,
                    backend,
                    remaining,
                    expected.target(),
                    &expected.branch,
                );
                solver_spent += query_start.elapsed();
                if proof.disposition != SolverDisposition::Sat {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::Unknown),
                        "owned edge no longer solver-SAT on replay",
                        None,
                    );
                }
                branches.push(proof);
                owned_model = model;
                matched += 1;
                continue;
            }
            if new_decision {
                if state.branch_history.len() as u64 > limits.max_path_depth {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::ResourceLimit),
                        "branch depth budget",
                        None,
                    );
                }
                if !matches!(outcome, SymbolicStepOutcome::Branched { .. }) {
                    // The condition resolved concretely (constant fold or a
                    // recorded concrete value), so exactly one successor exists
                    // and no fork or complementary proof is needed. The
                    // decision is already recorded with its chosen successor;
                    // keep walking the single path.
                    continue;
                }
                if self.states.len() != 2 {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::Unknown),
                        "fork did not produce exactly two children",
                        None,
                    );
                }
                let Some(point) = state
                    .last_branch
                    .and_then(|decision| branch_point(self, state, decision))
                else {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::ReplayMismatch),
                        "fork context unavailable",
                        None,
                    );
                };
                let Ok((false_child, true_child)) = unit.split(manifest, unit.contract_epoch, point.clone(), &[])
                else {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::ResourceLimit),
                        "fork exceeds ownership/depth bound",
                        None,
                    );
                };
                let fork_proofs = branches.len();
                for (index, target) in [(1, point.false_target), (0, point.true_target)] {
                    let state = &self.states[index];
                    let Some(direction) = state.constraints.last().copied() else {
                        break;
                    };
                    let remaining = deadline
                        .saturating_sub(start.elapsed())
                        .min(Duration::from_millis(limits.max_solver_millis).saturating_sub(solver_spent));
                    if remaining.is_zero() {
                        break;
                    }
                    let query_start = Instant::now();
                    branches.push(self.sustained_query(state, direction, backend, remaining, target, &point));
                    solver_spent += query_start.elapsed();
                }
                if branches.len() != fork_proofs + 2 {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::Timeout),
                        "solver direction unavailable",
                        None,
                    );
                }
                let to_status = |proof: &angryier_provenance::sustained::BranchEvidence| match proof.disposition {
                    SolverDisposition::Sat if limits.max_active_states >= 2 => ChildDisposition::Queued,
                    SolverDisposition::Sat => {
                        ChildDisposition::Deferred("active state cap; replayable child retained".into())
                    }
                    SolverDisposition::Unsat => ChildDisposition::Infeasible("solver UNSAT at verified fork".into()),
                    _ => ChildDisposition::Unknown("solver UNKNOWN/timeout; child retained".into()),
                };
                let statuses = (to_status(&branches[fork_proofs]), to_status(&branches[fork_proofs + 1]));
                break (
                    Status::Completed,
                    PathDisposition::Pending(PendingReason::Queued),
                    "fork split into two durable children",
                    Some((false_child, true_child, statuses.0, statuses.1)),
                );
            }
            if outcome == SymbolicStepOutcome::Terminated {
                if !state.process.state.fidelity.entries.is_empty()
                    || self.vector_debt_total != debt_before
                    || self.concretization_retries_total != retries_before
                {
                    break (
                        Status::Deferred,
                        PathDisposition::Pending(PendingReason::Unknown),
                        "semantic debt or concretization prevents verified completion",
                        None,
                    );
                }
                break (
                    Status::Completed,
                    PathDisposition::Terminal,
                    "terminal path at owned prefix",
                    None,
                );
            }
        };
        let trace = self
            .states
            .first()
            .or_else(|| self.dead.first())
            .map(|state| state.process.trace.as_slice())
            .unwrap_or(&[]);
        let witness = if status == Status::Completed && split.is_none() && matched == unit.prefix.len() {
            owned_model.as_deref().and_then(|model| {
                sustained_witness::verify(
                    self,
                    &root,
                    unit,
                    manifest,
                    initial,
                    sustained_witness::WitnessReplayInputs {
                        model,
                        expected_trace: trace,
                    },
                    deadline.saturating_sub(start.elapsed()),
                )
            })
        } else {
            None
        };
        if status == Status::Completed
            && split.is_none()
            && !unit.prefix.is_empty()
            && !witness
                .as_ref()
                .is_some_and(|w| matches!(w.replay, ReplayVerification::Verified { .. }))
        {
            status = Status::Deferred;
            disposition = PathDisposition::Pending(PendingReason::ReplayMismatch);
            reason = "concrete root replay did not verify SAT model and exact dynamic trace";
        }
        let counted_debt = self
            .vector_debt_total
            .saturating_sub(debt_before)
            .saturating_add(self.concretization_retries_total.saturating_sub(retries_before));
        if step_debt.len() as u64 != counted_debt {
            return Err(SustainedError::UnreplayableEnvironment(
                "step debt exceeds bounded evidence",
            ));
        }
        let mut path = observed_path(unit, initial, trace, disposition, manifest.spec.fidelity, branches);
        path.witness = witness;
        if let Some(state) = self.states.first().or_else(|| self.dead.first()) {
            path.semantic_debt = observed_debt(state);
        }
        path.semantic_debt.extend(step_debt);
        Ok(AdvanceOutcome {
            grant: grant.clone(),
            status,
            reason: reason.into(),
            path,
            split,
            steps,
        })
    }
}

/// Bounded versioned wire payload for a leased subtree; the work identity is
/// separately authenticated by the transport envelope.
pub struct WireGrant {
    pub fence: FencedReservation,
    pub timeout: Duration,
    pub step_budget: u64,
}

const WIRE_LIMIT: usize = 64 * 1024;
const WIRE_GRANT_VERSION: u8 = 1;
const WIRE_OUTCOME_VERSION: u8 = 2;
const WIRE_DEBT_LIMIT: usize = 4096;

fn wire_error() -> SustainedError {
    SustainedError::UnreplayableEnvironment("malformed or unsupported worker payload")
}
fn put_string(out: &mut Vec<u8>, value: &str) -> Result<(), SustainedError> {
    if value.is_empty() || value.len() > 256 {
        return Err(wire_error());
    }
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
struct WireReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> WireReader<'a> {
    fn new(bytes: &'a [u8]) -> Result<Self, SustainedError> {
        if bytes.len() > WIRE_LIMIT {
            return Err(wire_error());
        }
        Ok(Self { bytes, offset: 0 })
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], SustainedError> {
        let end = self.offset.checked_add(n).ok_or_else(wire_error)?;
        let result = self.bytes.get(self.offset..end).ok_or_else(wire_error)?;
        self.offset = end;
        Ok(result)
    }
    fn u8(&mut self) -> Result<u8, SustainedError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, SustainedError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| wire_error())?))
    }
    fn u32(&mut self) -> Result<u32, SustainedError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| wire_error())?))
    }
    fn u64(&mut self) -> Result<u64, SustainedError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| wire_error())?))
    }
    fn digest(&mut self) -> Result<Digest, SustainedError> {
        Ok(Digest(self.take(32)?.try_into().map_err(|_| wire_error())?))
    }
    fn string(&mut self) -> Result<String, SustainedError> {
        let size = self.u16()? as usize;
        if size == 0 || size > 256 {
            return Err(wire_error());
        }
        String::from_utf8(self.take(size)?.to_vec()).map_err(|_| wire_error())
    }
    fn finish(&self) -> Result<(), SustainedError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(wire_error())
        }
    }
}
fn encode_fence(out: &mut Vec<u8>, grant: &FencedReservation) {
    out.extend_from_slice(&grant.reservation.replay.initial_state_digest.0);
    out.extend_from_slice(&grant.reservation.attempt.to_le_bytes());
    out.extend_from_slice(&grant.owner_id.0);
    out.extend_from_slice(&grant.ownership_epoch.to_le_bytes());
}
fn decode_fence(r: &mut WireReader<'_>, work: WorkUnit) -> Result<FencedReservation, SustainedError> {
    let initial_state_digest = r.digest()?;
    let attempt = r.u64()?;
    let owner_id = r.digest()?;
    let ownership_epoch = r.u64()?;
    if attempt == 0
        || attempt != ownership_epoch
        || owner_id == Digest::default()
        || initial_state_digest == Digest::default()
    {
        return Err(wire_error());
    }
    Ok(FencedReservation {
        reservation: angryier_ledger::sustained::Reservation {
            unit: work,
            replay: angryier_ledger::sustained::ReplayDescriptor { initial_state_digest },
            attempt,
        },
        owner_id,
        ownership_epoch,
    })
}
impl WireGrant {
    pub fn encode(&self) -> Result<Vec<u8>, SustainedError> {
        if self.timeout.is_zero() || self.step_budget == 0 {
            return Err(wire_error());
        }
        let millis = u64::try_from(self.timeout.as_millis()).map_err(|_| wire_error())?;
        let mut out = vec![WIRE_GRANT_VERSION];
        encode_fence(&mut out, &self.fence);
        out.extend_from_slice(&millis.to_le_bytes());
        out.extend_from_slice(&self.step_budget.to_le_bytes());
        Ok(out)
    }
    pub fn decode(work: WorkUnit, bytes: &[u8], manifest: &CampaignManifest) -> Result<Self, SustainedError> {
        work.validate(manifest, work.contract_epoch)?;
        let mut r = WireReader::new(bytes)?;
        if r.u8()? != WIRE_GRANT_VERSION {
            return Err(wire_error());
        }
        let fence = decode_fence(&mut r, work)?;
        let millis = r.u64()?;
        let step_budget = r.u64()?;
        r.finish()?;
        if millis == 0
            || millis > manifest.spec.limits.max_wall_millis
            || step_budget == 0
            || step_budget > manifest.spec.limits.max_steps
        {
            return Err(wire_error());
        }
        Ok(Self {
            fence,
            timeout: Duration::from_millis(millis),
            step_budget,
        })
    }
}

fn encode_child(out: &mut Vec<u8>, disposition: &ChildDisposition) -> Result<(), SustainedError> {
    match disposition {
        ChildDisposition::Queued => out.push(0),
        ChildDisposition::Deferred(reason) => {
            out.push(1);
            put_string(out, reason)?;
        }
        ChildDisposition::Unknown(reason) => {
            out.push(2);
            put_string(out, reason)?;
        }
        ChildDisposition::Infeasible(_) => {
            return Err(SustainedError::UnreplayableEnvironment(
                "remote split cannot durably commit infeasible child evidence",
            ));
        }
        ChildDisposition::Excluded(_) | ChildDisposition::Failed(_) => return Err(wire_error()),
    }
    Ok(())
}
fn decode_child(r: &mut WireReader<'_>) -> Result<ChildDisposition, SustainedError> {
    Ok(match r.u8()? {
        0 => ChildDisposition::Queued,
        1 => ChildDisposition::Deferred(r.string()?),
        2 => ChildDisposition::Unknown(r.string()?),
        _ => return Err(wire_error()),
    })
}
fn encode_disposition(out: &mut Vec<u8>, disposition: PathDisposition) -> Result<(), SustainedError> {
    match disposition {
        PathDisposition::Terminal => out.push(0),
        PathDisposition::Pending(reason) => {
            out.push(1);
            out.push(match reason {
                PendingReason::Queued => 0,
                PendingReason::Leased => 1,
                PendingReason::Deferred => 2,
                PendingReason::Unknown => 3,
                PendingReason::Timeout => 4,
                PendingReason::ResourceLimit => 5,
                PendingReason::ReplayMismatch => 6,
            });
        }
        _ => return Err(wire_error()),
    }
    Ok(())
}
fn decode_disposition(r: &mut WireReader<'_>) -> Result<PathDisposition, SustainedError> {
    Ok(match r.u8()? {
        0 => PathDisposition::Terminal,
        1 => PathDisposition::Pending(match r.u8()? {
            0 => PendingReason::Queued,
            1 => PendingReason::Leased,
            2 => PendingReason::Deferred,
            3 => PendingReason::Unknown,
            4 => PendingReason::Timeout,
            5 => PendingReason::ResourceLimit,
            6 => PendingReason::ReplayMismatch,
            _ => return Err(wire_error()),
        }),
        _ => return Err(wire_error()),
    })
}
fn solver_tag(disposition: SolverDisposition) -> u8 {
    match disposition {
        SolverDisposition::NotQueried => 0,
        SolverDisposition::Sat => 1,
        SolverDisposition::Unsat => 2,
        SolverDisposition::Unknown => 3,
        SolverDisposition::Timeout => 4,
        SolverDisposition::ResourceLimit => 5,
        SolverDisposition::BackendError => 6,
    }
}
fn decode_solver(tag: u8) -> Result<SolverDisposition, SustainedError> {
    Ok(match tag {
        0 => SolverDisposition::NotQueried,
        1 => SolverDisposition::Sat,
        2 => SolverDisposition::Unsat,
        3 => SolverDisposition::Unknown,
        4 => SolverDisposition::Timeout,
        5 => SolverDisposition::ResourceLimit,
        6 => SolverDisposition::BackendError,
        _ => return Err(wire_error()),
    })
}
fn debt_tag(kind: DebtKind) -> u8 {
    match kind {
        DebtKind::Approximation => 0,
        DebtKind::Concretization => 1,
        DebtKind::UnsupportedSemantics => 2,
        DebtKind::ExternalModel => 3,
        DebtKind::UnderconstrainedMemory => 4,
    }
}
fn decode_debt(tag: u8) -> Result<DebtKind, SustainedError> {
    Ok(match tag {
        0 => DebtKind::Approximation,
        1 => DebtKind::Concretization,
        2 => DebtKind::UnsupportedSemantics,
        3 => DebtKind::ExternalModel,
        4 => DebtKind::UnderconstrainedMemory,
        _ => return Err(wire_error()),
    })
}
fn encode_point(out: &mut Vec<u8>, p: &angryier_distribution::contracts::BranchPoint) {
    for n in [
        p.branch_pc,
        p.visit_index,
        p.false_target,
        p.true_target,
        p.prefix_constraints,
    ] {
        out.extend_from_slice(&n.to_le_bytes());
    }
    out.extend_from_slice(&p.trace_digest.0);
    out.extend_from_slice(&p.predicate_digest.0);
}
fn decode_point(r: &mut WireReader<'_>) -> Result<angryier_distribution::contracts::BranchPoint, SustainedError> {
    Ok(angryier_distribution::contracts::BranchPoint {
        branch_pc: r.u64()?,
        visit_index: r.u64()?,
        false_target: r.u64()?,
        true_target: r.u64()?,
        prefix_constraints: r.u64()?,
        trace_digest: r.digest()?,
        predicate_digest: r.digest()?,
    })
}

impl AdvanceOutcome {
    /// The coordinator independently re-derives verified witnesses; debt is
    /// preserved on the wire, while nonverified witnesses are rejected.
    pub fn encode_wire(&self) -> Result<Vec<u8>, SustainedError> {
        let trace: Vec<_> = self.path.blocks.iter().map(|block| block.pc).collect();
        let mut canonical = self.path.clone();
        canonical.witness = None; // Coordinator independently re-derives the verified model replay.
        let mut reconstructed = observed_path(
            &self.grant.reservation.unit,
            self.grant.reservation.replay.initial_state_digest,
            &trace,
            self.path.disposition,
            self.path.fidelity,
            self.path.branches.clone(),
        );
        reconstructed.semantic_debt = self.path.semantic_debt.clone();
        if self
            .path
            .witness
            .as_ref()
            .is_some_and(|w| !matches!(w.replay, ReplayVerification::Verified { .. }))
            || reconstructed != canonical
            || (self.status == Status::Completed
                && self.path.disposition == PathDisposition::Terminal
                && !self.path.semantic_debt.is_empty())
            || trace.len() > 4096
            || self.path.branches.len() > 256
            || self.path.semantic_debt.len() > WIRE_DEBT_LIMIT
        {
            return Err(wire_error());
        }
        let mut out = vec![WIRE_OUTCOME_VERSION];
        encode_fence(&mut out, &self.grant);
        out.extend_from_slice(&self.steps.to_le_bytes());
        out.push(match self.status {
            Status::Completed => 0,
            Status::Deferred => 1,
            Status::Unknown => 2,
            Status::Failed => 3,
            _ => return Err(wire_error()),
        });
        put_string(&mut out, &self.reason)?;
        encode_disposition(&mut out, self.path.disposition)?;
        out.extend_from_slice(&(trace.len() as u32).to_le_bytes());
        for pc in trace {
            out.extend_from_slice(&pc.to_le_bytes());
        }
        out.extend_from_slice(&(self.path.branches.len() as u32).to_le_bytes());
        for branch in &self.path.branches {
            out.extend_from_slice(&branch.pc.to_le_bytes());
            out.extend_from_slice(&branch.visit_index.to_le_bytes());
            out.extend_from_slice(&branch.predicate_digest);
            out.extend_from_slice(&branch.query_digest);
            out.push(u8::from(branch.result_digest.is_some()));
            if let Some(digest) = branch.result_digest {
                out.extend_from_slice(&digest);
            }
            out.push(u8::from(branch.tested_target.is_some()));
            if let Some(target) = branch.tested_target {
                out.extend_from_slice(&target.to_le_bytes());
            }
            out.push(solver_tag(branch.disposition));
        }
        out.extend_from_slice(&(self.path.semantic_debt.len() as u32).to_le_bytes());
        for debt in &self.path.semantic_debt {
            out.extend_from_slice(&debt.pc.to_le_bytes());
            out.push(debt_tag(debt.kind));
        }
        match &self.split {
            None => out.push(0),
            Some((false_child, true_child, false_status, true_status)) => {
                let point = false_child.prefix.last().ok_or_else(wire_error)?.branch.clone();
                let parent = &self.grant.reservation.unit;
                if false_child.campaign_digest != parent.campaign_digest
                    || true_child.campaign_digest != parent.campaign_digest
                    || false_child.contract_epoch != parent.contract_epoch
                    || true_child.contract_epoch != parent.contract_epoch
                    || false_child.prefix.len() != parent.prefix.len() + 1
                    || true_child.prefix.len() != parent.prefix.len() + 1
                    || !false_child.prefix.starts_with(&parent.prefix)
                    || !true_child.prefix.starts_with(&parent.prefix)
                    || false_child
                        .prefix
                        .last()
                        .is_none_or(|last| last.successor != Successor::False)
                    || true_child
                        .prefix
                        .last()
                        .is_none_or(|last| last.successor != Successor::True || last.branch != point)
                {
                    return Err(wire_error());
                }
                out.push(1);
                encode_point(&mut out, &point);
                encode_child(&mut out, false_status)?;
                encode_child(&mut out, true_status)?;
            }
        }
        if out.len() > WIRE_LIMIT {
            return Err(wire_error());
        }
        Ok(out)
    }

    pub fn decode_wire(work: WorkUnit, bytes: &[u8], manifest: &CampaignManifest) -> Result<Self, SustainedError> {
        work.validate(manifest, work.contract_epoch)?;
        let mut r = WireReader::new(bytes)?;
        let version = r.u8()?;
        if version != 1 && version != WIRE_OUTCOME_VERSION {
            return Err(wire_error());
        }
        let grant = decode_fence(&mut r, work)?;
        let steps = r.u64()?;
        if steps > manifest.spec.limits.max_steps {
            return Err(wire_error());
        }
        let status = match r.u8()? {
            0 => Status::Completed,
            1 => Status::Deferred,
            2 => Status::Unknown,
            3 => Status::Failed,
            _ => return Err(wire_error()),
        };
        let reason = r.string()?;
        let disposition = decode_disposition(&mut r)?;
        let count = r.u32()? as usize;
        if count > 4096 || count as u64 > manifest.spec.limits.max_path_steps {
            return Err(wire_error());
        }
        let mut trace = Vec::with_capacity(count);
        for _ in 0..count {
            trace.push(r.u64()?);
        }
        let count = r.u32()? as usize;
        if count > 256 {
            return Err(wire_error());
        }
        let mut branches = Vec::with_capacity(count);
        for _ in 0..count {
            let pc = r.u64()?;
            let visit_index = r.u64()?;
            let predicate_digest = r.digest()?.0;
            let query_digest = r.digest()?.0;
            let result_digest = match r.u8()? {
                0 => None,
                1 => Some(r.digest()?.0),
                _ => return Err(wire_error()),
            };
            let tested_target = match r.u8()? {
                0 => None,
                1 => Some(r.u64()?),
                _ => return Err(wire_error()),
            };
            let disposition = decode_solver(r.u8()?)?;
            branches.push(angryier_provenance::sustained::BranchEvidence {
                pc,
                visit_index,
                predicate_digest,
                query_digest,
                result_digest,
                tested_target,
                disposition,
            });
        }
        let semantic_debt = if version == WIRE_OUTCOME_VERSION {
            // Debt events repeat per executed step (approximation plus
            // concretization), so the manifest path-step bound must not cap the
            // record count: encode_wire and decode_wire share the
            // WIRE_DEBT_LIMIT hard cap inside the WIRE_LIMIT byte budget.
            let count = r.u32()? as usize;
            if count > WIRE_DEBT_LIMIT
                || count
                    .checked_mul(9)
                    .and_then(|bytes| bytes.checked_add(4))
                    .is_none_or(|bytes| bytes > WIRE_LIMIT)
            {
                return Err(wire_error());
            }
            let mut debt = Vec::with_capacity(count);
            for _ in 0..count {
                debt.push(SemanticDebt {
                    pc: r.u64()?,
                    kind: decode_debt(r.u8()?)?,
                });
            }
            debt
        } else {
            Vec::new()
        };
        let split = match r.u8()? {
            0 => None,
            1 => {
                let point = decode_point(&mut r)?;
                let (false_child, true_child) =
                    grant
                        .reservation
                        .unit
                        .split(manifest, grant.reservation.unit.contract_epoch, point, &[])?;
                Some((false_child, true_child, decode_child(&mut r)?, decode_child(&mut r)?))
            }
            _ => return Err(wire_error()),
        };
        r.finish()?;
        if split.is_some() {
            if status != Status::Completed || disposition != PathDisposition::Pending(PendingReason::Queued) {
                return Err(wire_error());
            }
        } else if status == Status::Completed {
            if disposition != PathDisposition::Terminal || !semantic_debt.is_empty() {
                return Err(wire_error());
            }
        } else if !matches!(disposition, PathDisposition::Pending(_)) {
            return Err(wire_error());
        }
        let mut path = observed_path(
            &grant.reservation.unit,
            grant.reservation.replay.initial_state_digest,
            &trace,
            disposition,
            manifest.spec.fidelity,
            branches,
        );
        path.semantic_debt = semantic_debt;
        Ok(Self {
            grant,
            status,
            reason,
            path,
            split,
            steps,
        })
    }
}

impl SustainedCampaign {
    /// A fresh coordinator-owned execution must reproduce every wire claim.
    /// Publish its independently derived evidence (including its verified
    /// concrete witness), never the worker's untrusted decoded path.
    pub fn verify_remote<D: Decoder>(
        &self,
        grant: &FencedReservation,
        claimed: &AdvanceOutcome,
        session: &mut SymbolicSession<'_, D>,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
        step_budget: u64,
    ) -> Result<VerifiedRemoteOutcome, SustainedError> {
        if claimed.grant != *grant {
            return Err(wire_error());
        }
        let verified = session.advance_sustained(grant, self.ledger.manifest(), backend, timeout, step_budget)?;
        if verified.grant != *grant
            || claimed.steps > step_budget
            || verified.steps > step_budget
            || claimed.steps != verified.steps
            || claimed.status != verified.status
            || claimed.reason != verified.reason
            || claimed.split != verified.split
        {
            return Err(wire_error());
        }
        let mut path = verified.path.clone();
        path.witness = None;
        if claimed.path != path {
            return Err(wire_error());
        }
        // Reject any independently observed shape that the bounded v2 codec
        // cannot represent, rather than silently losing evidence.
        verified.encode_wire()?;
        Ok(VerifiedRemoteOutcome { outcome: verified })
    }

    pub fn reserve_remote(&mut self, owner: Digest) -> Result<Option<FencedReservation>, SustainedError> {
        Ok(self.ledger.reserve_fenced(owner)?)
    }

    pub fn revoke_remote(&mut self, grant: &FencedReservation) -> Result<(), SustainedError> {
        Ok(self.ledger.revoke_fenced(grant)?)
    }

    /// Only the coordinator calls this; it checks the exact live grant before a
    /// single writer publishes parent and children with evidence atomically.
    pub fn commit_remote(
        &mut self,
        grant: &FencedReservation,
        verified: VerifiedRemoteOutcome,
        step_budget: u64,
    ) -> Result<u64, SustainedError> {
        let outcome = verified.outcome;
        if outcome.grant != *grant
            || outcome.steps > step_budget
            || outcome.path.path_id != work_path_id(&grant.reservation.unit, &grant.reservation.replay).0
            || grant.reservation.unit.campaign_digest != self.ledger.manifest().campaign_digest
            || grant.reservation.unit.contract_epoch != self.ledger.epoch()
        {
            return Err(SustainedError::Ledger(
                angryier_ledger::sustained::Error::StaleReservation,
            ));
        }
        let record = self
            .ledger
            .records()
            .iter()
            .find(|record| record.unit == grant.reservation.unit);
        if !record.is_some_and(|record| {
            record.status == Status::Active
                && !record.retired
                && record.owner_id == Some(grant.owner_id)
                && record.attempt == grant.ownership_epoch
                && record.replay == grant.reservation.replay
        }) {
            return Err(SustainedError::Ledger(
                angryier_ledger::sustained::Error::StaleReservation,
            ));
        }
        let delta = EvidenceDelta {
            sequence: grant.reservation.attempt,
            path: outcome.path,
        };
        if outcome.status == Status::Completed {
            let prefix = &grant.reservation.unit.prefix;
            if delta.path.branches.len() < prefix.len() {
                return Err(wire_error());
            }
            for (decision, proof) in prefix.iter().zip(&delta.path.branches) {
                let branch = &decision.branch;
                let observed = delta
                    .path
                    .blocks
                    .iter()
                    .enumerate()
                    .filter(|(_, block)| block.pc == branch.branch_pc)
                    .nth(branch.visit_index as usize);
                let Some((trace_end, _)) = observed else {
                    return Err(wire_error());
                };
                let mut bytes = Vec::with_capacity((trace_end + 1) * 8);
                for block in &delta.path.blocks[..=trace_end] {
                    bytes.extend_from_slice(&block.pc.to_le_bytes());
                }
                if Digest::of(&bytes) != branch.trace_digest
                    || proof.pc != branch.branch_pc
                    || proof.visit_index != branch.visit_index
                    || proof.predicate_digest != branch.predicate_digest.0
                    || proof.tested_target != Some(decision.target())
                    || proof.disposition != SolverDisposition::Sat
                {
                    return Err(wire_error());
                }
            }
        }
        if let Some((false_child, true_child, false_status, true_status)) = outcome.split {
            let point = &false_child.prefix.last().ok_or_else(wire_error)?.branch;
            if delta.path.provenance_digest != point.trace_digest.0
                || delta.path.branches.len() != grant.reservation.unit.prefix.len() + 2
                || [(point.false_target, &false_status), (point.true_target, &true_status)]
                    .iter()
                    .enumerate()
                    .any(|(index, (target, child_status))| {
                        let branch = &delta.path.branches[delta.path.branches.len() - 2 + index];
                        branch.pc != point.branch_pc
                            || branch.visit_index != point.visit_index
                            || branch.predicate_digest != point.predicate_digest.0
                            || branch.tested_target != Some(*target)
                            || match child_status {
                                ChildDisposition::Queued | ChildDisposition::Deferred(_) => {
                                    branch.disposition != SolverDisposition::Sat
                                }
                                ChildDisposition::Unknown(_) => {
                                    matches!(branch.disposition, SolverDisposition::Sat | SolverDisposition::Unsat)
                                }
                                _ => true,
                            }
                    })
            {
                return Err(wire_error());
            }
            if matches!(false_status, ChildDisposition::Infeasible(_))
                || matches!(true_status, ChildDisposition::Infeasible(_))
            {
                return Err(SustainedError::UnreplayableEnvironment(
                    "remote split cannot durably commit infeasible child evidence",
                ));
            }
            self.ledger.split_with_evidence(
                &grant.reservation,
                false_child,
                true_child,
                false_status,
                true_status,
                delta,
            )?;
        } else {
            self.ledger
                .commit_outcome_fenced(grant, outcome.status, &outcome.reason, delta)?;
        }
        Ok(outcome.steps)
    }
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use angryier_distribution::contracts::{CampaignSpec, ExplorationLimits};
    use angryier_types::FidelityProfile;

    fn fixture() -> (CampaignManifest, AdvanceOutcome) {
        let hash = Digest::of(b"wire-fixture");
        let manifest = CampaignManifest::seal(CampaignSpec {
            binary_digest: hash,
            architecture: "x86_64".into(),
            entry_pc: 0x1000,
            semantic_version: "1".into(),
            semantic_profile_digest: hash,
            script_digest: hash,
            policy_digest: hash,
            inputs: vec![],
            stubs: vec![],
            solver_version: "test".into(),
            solver_policy_digest: hash,
            fidelity: FidelityProfile::Prove,
            limits: ExplorationLimits {
                max_steps: 128,
                max_path_steps: 64,
                max_active_states: 2,
                max_path_depth: 64,
                max_loop_visits: 64,
                max_solver_millis: 10_000,
                max_wall_millis: 30_000,
                max_ram_bytes: 64 * 1024 * 1024,
                max_disk_bytes: 1024 * 1024,
                max_trace_bytes: 1024 * 1024,
            },
        })
        .unwrap();
        let unit = WorkUnit::root(&manifest, 1).unwrap();
        let grant = FencedReservation {
            reservation: angryier_ledger::sustained::Reservation {
                unit: unit.clone(),
                replay: angryier_ledger::sustained::ReplayDescriptor {
                    initial_state_digest: hash,
                },
                attempt: 1,
            },
            owner_id: hash,
            ownership_epoch: 1,
        };
        let mut path = observed_path(
            &unit,
            hash,
            &[0x1000, 0x1001],
            PathDisposition::Pending(PendingReason::Unknown),
            manifest.spec.fidelity,
            vec![],
        );
        path.semantic_debt = vec![
            SemanticDebt {
                pc: 0x1000,
                kind: DebtKind::UnsupportedSemantics,
            },
            SemanticDebt {
                pc: 0x1001,
                kind: DebtKind::Concretization,
            },
        ];
        (
            manifest,
            AdvanceOutcome {
                grant,
                status: Status::Deferred,
                reason: "semantic debt prevents verified completion".into(),
                path,
                split: None,
                steps: 2,
            },
        )
    }

    #[test]
    fn v2_deferred_debt_round_trip_and_v1_decode() {
        let (manifest, mut outcome) = fixture();
        for kind in [
            DebtKind::Approximation,
            DebtKind::Concretization,
            DebtKind::UnsupportedSemantics,
            DebtKind::ExternalModel,
            DebtKind::UnderconstrainedMemory,
        ] {
            outcome.path.semantic_debt.push(SemanticDebt { pc: 0x1000, kind });
        }
        let wire = outcome.encode_wire().unwrap();
        assert_eq!(wire[0], WIRE_OUTCOME_VERSION);
        let decoded = AdvanceOutcome::decode_wire(outcome.grant.reservation.unit.clone(), &wire, &manifest).unwrap();
        assert_eq!(decoded.path, outcome.path);
        assert_eq!(decoded.status, Status::Deferred);
        // Multiplicity is evidence: consecutive identical records can be real counters.
        outcome.path.semantic_debt.push(SemanticDebt {
            pc: 0x1000,
            kind: DebtKind::Approximation,
        });
        let repeated = outcome.encode_wire().unwrap();
        assert_eq!(
            AdvanceOutcome::decode_wire(outcome.grant.reservation.unit.clone(), &repeated, &manifest)
                .unwrap()
                .path
                .semantic_debt,
            outcome.path.semantic_debt
        );
        // The old layout has no debt count; only debt-free v1 outcomes can replay.
        let (_, mut old) = fixture();
        old.path.semantic_debt.clear();
        let mut v1 = old.encode_wire().unwrap();
        let debt_offset = v1.len() - 5; // empty debt count followed by the no-split tag
        v1.drain(debt_offset..debt_offset + 4);
        v1[0] = 1;
        assert!(
            AdvanceOutcome::decode_wire(old.grant.reservation.unit.clone(), &v1, &manifest)
                .unwrap()
                .path
                .semantic_debt
                .is_empty()
        );
    }

    #[test]
    fn rejects_malformed_and_tampered_debt() {
        let (manifest, outcome) = fixture();
        let work = outcome.grant.reservation.unit.clone();
        let wire = outcome.encode_wire().unwrap();
        let debt_offset = wire.len() - 1 - 4 - outcome.path.semantic_debt.len() * 9;
        let mut bad = wire.clone();
        bad[debt_offset + 4 + 8] = 255; // unknown debt kind
        assert!(AdvanceOutcome::decode_wire(work.clone(), &bad, &manifest).is_err());
        let mut bad = wire.clone();
        bad[debt_offset..debt_offset + 4].copy_from_slice(&65u32.to_le_bytes());
        assert!(AdvanceOutcome::decode_wire(work.clone(), &bad, &manifest).is_err());
        let mut bad = wire.clone();
        bad.pop(); // missing split marker
        assert!(AdvanceOutcome::decode_wire(work.clone(), &bad, &manifest).is_err());
        let mut bad = wire.clone();
        bad[debt_offset + 4] ^= 1; // valid encoding, false worker debt claim
        let claimed = AdvanceOutcome::decode_wire(work.clone(), &bad, &manifest).unwrap();
        assert_ne!(claimed.path, outcome.path, "independent replay must reject altered pc");
        let mut bad = wire.clone();
        bad[debt_offset + 4 + 8] = 3; // valid encoding, false worker kind
        let claimed = AdvanceOutcome::decode_wire(work, &bad, &manifest).unwrap();
        assert_ne!(
            claimed.path, outcome.path,
            "independent replay must reject altered kind"
        );
    }

    #[test]
    fn debt_cannot_verify_terminal_completion() {
        let (manifest, mut outcome) = fixture();
        outcome.status = Status::Completed;
        outcome.path.disposition = PathDisposition::Terminal;
        assert!(outcome.encode_wire().is_err());
        outcome.status = Status::Deferred;
        outcome.path.disposition = PathDisposition::Pending(PendingReason::Unknown);
        let mut wire = outcome.encode_wire().unwrap();
        let status_offset = 1 + 32 + 8 + 32 + 8 + 8;
        wire[status_offset] = 0;
        let disposition_offset = status_offset + 1 + 2 + outcome.reason.len();
        wire[disposition_offset] = 0;
        wire.remove(disposition_offset + 1); // terminal has no pending reason byte
        assert!(AdvanceOutcome::decode_wire(outcome.grant.reservation.unit, &wire, &manifest).is_err());
    }

    #[test]
    fn repeated_step_debt_above_max_path_steps_round_trips() {
        // The fixture manifest allows only 64 path steps, yet each step repeats
        // approximation and concretization debt events, so a legitimate deferred
        // outcome carries more debt records than steps. The shared bounded
        // count must round trip every record instead of revoking the grant.
        let (manifest, mut outcome) = fixture();
        for step in [0x1000u64, 0x1001] {
            for _ in 0..64 {
                outcome.path.semantic_debt.push(SemanticDebt {
                    pc: step,
                    kind: DebtKind::Approximation,
                });
                outcome.path.semantic_debt.push(SemanticDebt {
                    pc: step,
                    kind: DebtKind::Concretization,
                });
            }
        }
        assert!(outcome.path.semantic_debt.len() as u64 > manifest.spec.limits.max_path_steps);
        let wire = outcome.encode_wire().unwrap();
        assert_eq!(wire[0], WIRE_OUTCOME_VERSION);
        let decoded = AdvanceOutcome::decode_wire(outcome.grant.reservation.unit.clone(), &wire, &manifest).unwrap();
        assert_eq!(decoded.path, outcome.path);
        assert_eq!(decoded.status, Status::Deferred);
        assert_eq!(decoded.path.semantic_debt.len(), 258); // 2 fixture records plus 2 per step
    }

    #[test]
    fn debt_hard_cap_round_trips_and_oversized_is_rejected() {
        let (manifest, mut outcome) = fixture();
        outcome.path.semantic_debt.clear();
        for _ in 0..WIRE_DEBT_LIMIT {
            outcome.path.semantic_debt.push(SemanticDebt {
                pc: 0x1000,
                kind: DebtKind::Concretization,
            });
        }
        // Exactly the shared hard cap still round trips without dropping debt.
        let wire = outcome.encode_wire().unwrap();
        let decoded = AdvanceOutcome::decode_wire(outcome.grant.reservation.unit.clone(), &wire, &manifest).unwrap();
        assert_eq!(decoded.path, outcome.path);
        assert_eq!(decoded.path.semantic_debt.len(), WIRE_DEBT_LIMIT);
        // One record past the hard cap is rejected on encode...
        outcome.path.semantic_debt.push(SemanticDebt {
            pc: 0x1000,
            kind: DebtKind::Concretization,
        });
        assert!(outcome.encode_wire().is_err());
        // ...and on decode, even while the byte budget still fits WIRE_LIMIT.
        let debt_offset = wire.len() - 1 - 4 - WIRE_DEBT_LIMIT * 9;
        let mut oversized = wire.clone();
        oversized[debt_offset..debt_offset + 4].copy_from_slice(&(WIRE_DEBT_LIMIT as u32 + 1).to_le_bytes());
        assert!(AdvanceOutcome::decode_wire(outcome.grant.reservation.unit, &oversized, &manifest).is_err());
    }
}
