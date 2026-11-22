//! Opt-in, local-first exploration of exact dynamic branch-prefix subtrees.
//! A fresh pinned root is replayed for each reservation; unresolved work never
//! becomes a completed leaf or disappears when the in-memory state cap is hit.
use std::{
    collections::HashMap,
    mem::size_of,
    path::Path,
    time::{Duration, Instant},
};

use angryier_arch::Decoder;
use angryier_distribution::contracts::{
    BranchPoint, CampaignArtifacts, CampaignManifest, ContractError, Digest, Successor, WorkUnit,
};
use angryier_ledger::{
    evidence::{AcceptedEvidence, DebtKind, EvidenceDelta, SemanticDebt},
    sustained::{
        ChildDisposition, Error as LedgerError, ReplayDescriptor, Report as LedgerReport, Status, SustainedLedger,
    },
};
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_provenance::sustained::{
    BranchEvidence, DynamicBlock, EdgeBasis, EvidenceBuilder, EvidenceError, EvidenceLimits, EvidenceScope, FlowEdge,
    PathDisposition, PathEvidence, PendingReason, PendingWork, ScopeClosure, SolverDisposition,
};
use angryier_solver::{SolverBackend, SolverOutcomeKind, SolverQuery};
use angryier_types::{AnalysisDebtKind, ConstraintCanonicalizationVersion, ObjectId, SolverQueryId};
use sha2::{Digest as _, Sha256};

use crate::{SymbolicBranchDecision, SymbolicSession, SymbolicState, SymbolicStepOutcome, checked_path_constraints};

#[path = "sustained_witness.rs"]
pub(super) mod sustained_witness;

type SustainedQueryResult = (BranchEvidence, Option<Vec<(u64, Vec<u8>)>>);

#[derive(Debug)]
pub enum SustainedError {
    Contract(ContractError),
    Ledger(LedgerError),
    Evidence(EvidenceError),
    UnreplayableEnvironment(&'static str),
    InitialStateMismatch,
    ExclusionUnproven,
}
impl std::fmt::Display for SustainedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ledger(error) => write!(f, "{error}"),
            _ => write!(f, "{self:?}"),
        }
    }
}
impl std::error::Error for SustainedError {}
impl From<ContractError> for SustainedError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error)
    }
}
impl From<LedgerError> for SustainedError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}
impl From<EvidenceError> for SustainedError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

pub struct SustainedCampaign {
    pub(super) ledger: SustainedLedger,
}
impl SustainedCampaign {
    /// The caller must present the actual pinned artifacts on every resume.
    /// The root digest is independently checked by `run_sustained` before work.
    pub fn open(
        path: impl AsRef<Path>,
        manifest: CampaignManifest,
        artifacts: &CampaignArtifacts<'_>,
        initial_state_digest: Digest,
    ) -> Result<Self, SustainedError> {
        Self::validate(&manifest, artifacts, initial_state_digest)?;
        let path = path.as_ref();
        if path.exists() {
            Self::resume_existing(path, manifest, artifacts, initial_state_digest)
        } else {
            Self::start_new(path, manifest, artifacts, initial_state_digest)
        }
    }

    /// Create only a new ledger; initialization refuses existing snapshots under lock.
    pub fn start_new(
        path: impl AsRef<Path>,
        manifest: CampaignManifest,
        artifacts: &CampaignArtifacts<'_>,
        initial_state_digest: Digest,
    ) -> Result<Self, SustainedError> {
        Self::validate(&manifest, artifacts, initial_state_digest)?;
        let ledger = SustainedLedger::initialize(path, manifest, 1, ReplayDescriptor { initial_state_digest })?;
        Ok(Self { ledger })
    }

    /// Open only an existing ledger with matching sealed artifacts and root.
    pub fn resume_existing(
        path: impl AsRef<Path>,
        manifest: CampaignManifest,
        artifacts: &CampaignArtifacts<'_>,
        initial_state_digest: Digest,
    ) -> Result<Self, SustainedError> {
        Self::validate(&manifest, artifacts, initial_state_digest)?;
        let ledger = SustainedLedger::open(path, manifest)?;
        if ledger
            .records()
            .iter()
            .any(|r| r.replay.initial_state_digest != initial_state_digest)
        {
            return Err(SustainedError::InitialStateMismatch);
        }
        Ok(Self { ledger })
    }

    fn validate(
        manifest: &CampaignManifest,
        artifacts: &CampaignArtifacts<'_>,
        initial_state_digest: Digest,
    ) -> Result<(), SustainedError> {
        manifest.validate_artifacts(artifacts)?;
        if initial_state_digest == Digest::default() {
            return Err(SustainedError::InitialStateMismatch);
        }
        Ok(())
    }
    pub fn report(&self) -> LedgerReport {
        self.ledger.report()
    }

    /// Validate exclusion claims only when the ledger is complete. An
    /// unproven avoid address rejects the report without changing the ledger.
    pub fn checked_report(&self, avoid: &[u64]) -> Result<LedgerReport, SustainedError> {
        let report = self.report();
        if report.complete_within_declared_bounds
            && avoid.iter().any(|target| {
                !self.ledger.records().iter().any(|record| {
                    matches!(record.status, Status::Excluded | Status::Infeasible)
                        && record
                            .unit
                            .prefix
                            .last()
                            .is_some_and(|decision| decision.target() == *target)
                })
            })
        {
            return Err(SustainedError::ExclusionUnproven);
        }
        Ok(report)
    }
    /// Latest accepted disposition for each path, in ledger order. Distinct
    /// from the historical event stream retained in the ledger snapshot: only
    /// the most recently accepted evidence for a path is yielded, while every
    /// accepted event remains available there.
    pub fn cumulative_evidence(&self) -> impl Iterator<Item = &AcceptedEvidence> + '_ {
        self.ledger.cumulative_evidence()
    }
    /// Every durably accepted evidence event, including superseded retries.
    pub fn accepted_events(&self) -> &[AcceptedEvidence] {
        self.ledger.read_snapshot().1
    }
    pub fn retry_deferred(&mut self) -> Result<(), SustainedError> {
        let units: Vec<_> = self
            .ledger
            .records()
            .iter()
            .filter(|r| !r.retired && matches!(r.status, Status::Deferred | Status::Unknown | Status::Failed))
            .map(|r| r.unit.clone())
            .collect();
        for unit in units {
            self.ledger.requeue(&unit)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
pub struct SustainedRanking<'a> {
    pub find: &'a [u64],
    pub avoid: &'a [u64],
    pub exclude_avoid: bool,
}

pub struct SustainedRun {
    pub ledger: LedgerReport,
    pub evidence: EvidenceBuilder,
    /// Accepted retired parent paths; each fork's solver evidence remains durable.
    pub accepted_splits: Vec<PathEvidence>,
    pub steps: u64,
    pub reason: Option<String>,
}

fn report_limits(manifest: &CampaignManifest) -> EvidenceLimits {
    let limits = &manifest.spec.limits;
    EvidenceLimits {
        // Match the ledger's work-unit and accepted-event ceilings until both
        // are exported as public constants.
        max_paths: 65_536,
        max_frontier: 65_536,
        max_items_per_path: usize::try_from(limits.max_trace_bytes).unwrap_or(usize::MAX).max(1),
        max_bytes: usize::try_from(limits.max_ram_bytes.min(limits.max_disk_bytes))
            .unwrap_or(usize::MAX)
            .max(1),
    }
}

pub(super) fn scope(manifest: &CampaignManifest, epoch: u64) -> EvidenceScope {
    let l = &manifest.spec.limits;
    let mut bytes = Vec::with_capacity(80);
    for n in [
        l.max_steps,
        l.max_path_steps,
        l.max_active_states,
        l.max_path_depth,
        l.max_loop_visits,
        l.max_solver_millis,
        l.max_wall_millis,
        l.max_ram_bytes,
        l.max_disk_bytes,
        l.max_trace_bytes,
    ] {
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    EvidenceScope {
        campaign_digest: manifest.campaign_digest.0,
        contract_epoch: epoch,
        bounds_digest: Digest::of(&bytes).0,
        fidelity: manifest.spec.fidelity,
    }
}

fn trace_digest(trace: &[u64]) -> Digest {
    let mut bytes = Vec::with_capacity(trace.len().saturating_mul(8));
    for pc in trace {
        bytes.extend_from_slice(&pc.to_le_bytes());
    }
    Digest::of(&bytes)
}

pub(super) fn branch_point<D: Decoder>(
    session: &SymbolicSession<'_, D>,
    state: &SymbolicState,
    decision: SymbolicBranchDecision,
) -> Option<BranchPoint> {
    if !decision.visit_index_exact || decision.visit_index == 0 {
        return None;
    }
    let predicate_digest = Digest(session.arena.dependency_summary(decision.condition)?.key.0);
    let trace = &state.process.trace;
    let visits = trace.iter().filter(|&&pc| pc == decision.pc).count() as u64;
    if visits != decision.visit_index || trace.last() != Some(&decision.pc) {
        return None;
    }
    Some(BranchPoint {
        branch_pc: decision.pc,
        visit_index: decision.visit_index - 1,
        false_target: decision.not_taken,
        true_target: decision.taken,
        prefix_constraints: u64::try_from(decision.prefix_constraints).ok()?,
        trace_digest: trace_digest(trace),
        predicate_digest,
    })
}

fn path_id(unit: &WorkUnit, initial: Digest) -> Digest {
    let mut bytes = Vec::with_capacity(72 + unit.prefix.len().saturating_mul(180));
    bytes.extend_from_slice(&unit.campaign_digest.0);
    bytes.extend_from_slice(&initial.0);
    bytes.extend_from_slice(&unit.contract_epoch.to_le_bytes());
    for decision in &unit.prefix {
        let b = &decision.branch;
        for n in [
            b.branch_pc,
            b.visit_index,
            b.false_target,
            b.true_target,
            b.prefix_constraints,
        ] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        bytes.extend_from_slice(&b.trace_digest.0);
        bytes.extend_from_slice(&b.predicate_digest.0);
        bytes.push(u8::from(decision.successor == Successor::True));
    }
    Digest::of(&bytes)
}

pub(super) fn observed_path(
    unit: &WorkUnit,
    initial: Digest,
    trace: &[u64],
    disposition: PathDisposition,
    fidelity: angryier_types::FidelityProfile,
    branches: Vec<BranchEvidence>,
) -> PathEvidence {
    let digest = trace_digest(trace).0;
    let mut visits = std::collections::BTreeMap::new();
    let blocks = trace
        .iter()
        .map(|pc| {
            let visit = visits.entry(*pc).or_insert(0u64);
            let block = DynamicBlock {
                pc: *pc,
                visit_index: *visit,
            };
            *visit += 1;
            block
        })
        .collect();
    let edges = trace
        .windows(2)
        .map(|pair| FlowEdge {
            from_pc: pair[0],
            to_pc: pair[1],
            basis: EdgeBasis::Observed { trace_digest: digest },
        })
        .collect();
    PathEvidence {
        path_id: path_id(unit, initial).0,
        provenance_digest: digest,
        fidelity,
        blocks,
        edges,
        branches,
        witness: None,
        semantic_debt: Vec::new(),
        disposition,
    }
}

pub(super) fn observed_debt(state: &SymbolicState) -> Vec<SemanticDebt> {
    state
        .process
        .state
        .fidelity
        .entries
        .iter()
        .map(|entry| SemanticDebt {
            pc: entry.source,
            kind: match entry.kind {
                AnalysisDebtKind::Concretized => DebtKind::Concretization,
                AnalysisDebtKind::Unsupported => DebtKind::UnsupportedSemantics,
                AnalysisDebtKind::Modelled | AnalysisDebtKind::Summary => DebtKind::ExternalModel,
                AnalysisDebtKind::Assumed | AnalysisDebtKind::Timeout => DebtKind::Approximation,
            },
        })
        .collect()
}

pub(super) fn budget(state: &SymbolicState, limit: u64) -> bool {
    state
        .branch_history
        .len()
        .checked_mul(size_of::<SymbolicBranchDecision>())
        .and_then(|n| {
            state
                .process
                .trace
                .len()
                .checked_mul(size_of::<u64>())
                .and_then(|t| n.checked_add(t))
        })
        .and_then(|n| n.checked_add(size_of::<SymbolicBranchDecision>() + size_of::<u64>()))
        .and_then(|n| u64::try_from(n).ok())
        .is_some_and(|n| n <= limit)
}

// The only name-keyed hook permitted in a pinned PE64 root is the loader's
// return sentinel. Check its stack target and the complete import-stub layout
// before committing their descriptions to the root hash.
fn pinned_pe_loader_state(state: &SymbolicState) -> Result<bool, SustainedError> {
    let process = &state.process;
    if process.simproc_hooks.is_empty()
        && process.pe_import_stubs.is_empty()
        && !process
            .state
            .memory
            .regions()
            .iter()
            .any(|r| r.base == crate::PE_DRIVER_STUB_BASE)
    {
        return Ok(false);
    }
    let invalid = || SustainedError::UnreplayableEnvironment("unrecognized PE loader hooks or import stubs");
    let stub_region = process
        .state
        .memory
        .regions()
        .iter()
        .find(|r| r.base == crate::PE_DRIVER_STUB_BASE);
    if process.simproc_hooks.len() != 1
        || process.simproc_hooks.get(&crate::EXIT_HOOK).map(String::as_str) != Some("exit")
        || process.target_profile.0 != 1
        || !stub_region.is_some_and(|r| {
            r.object == ObjectId(5) && r.size == 0x0010_0000 && r.readable && !r.writable && r.executable
        })
        || !process.state.memory.regions().iter().any(|r| {
            r.object == ObjectId(6)
                && r.base == crate::PE_DRIVER_SCRATCH_BASE
                && r.size == 0x10000
                && r.readable
                && r.writable
                && !r.executable
        })
    {
        return Err(invalid());
    }
    let rsp = process
        .read_register(crate::register_id::GPR_BASE + 4)
        .map_err(|_| invalid())?;
    let sentinel = crate::EXIT_HOOK.to_le_bytes();
    for memory in [
        process.state.memory.read(rsp, 8),
        state.memory.memory.read_at_address(rsp, 8),
    ] {
        let found = memory.map_err(|_| invalid())?;
        if !found.iter().zip(sentinel).all(|(v, b)| *v == ByteValue::Concrete(b)) || found.len() != 8 {
            return Err(invalid());
        }
    }
    if process.pe_import_stubs.len() > 0x0010_0000 / 16 {
        return Err(invalid());
    }
    for (index, (&address, (dll, export))) in process.pe_import_stubs.iter().enumerate() {
        if address != crate::PE_DRIVER_STUB_BASE + index as u64 * 16
            || dll.is_empty()
            || dll.len() > 256
            || !dll
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
            || export.is_empty()
            || export.len() > 1024
            || !export.bytes().all(|b| b.is_ascii_graphic())
            || (export.starts_with('#') && export[1..].parse::<u16>().is_err())
        {
            return Err(invalid());
        }
        let expected: &[u8] = if dll.eq_ignore_ascii_case("kernel32.dll")
            && matches!(
                export.as_str(),
                "IsProcessorFeaturePresent" | "CreateThread" | "CloseHandle" | "SetEvent" | "ResetEvent"
            ) {
            &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3]
        } else {
            &[0xC3]
        };
        for found in [
            process.state.memory.read(address, 16),
            state.memory.memory.read_at_address(address, 16),
        ] {
            let found = found.map_err(|_| invalid())?;
            if found.len() != 16
                || !found
                    .iter()
                    .take(expected.len())
                    .zip(expected)
                    .all(|(v, &b)| *v == ByteValue::Concrete(b))
                || !found.iter().skip(expected.len()).all(|v| *v == ByteValue::Concrete(0))
            {
                return Err(invalid());
            }
        }
    }
    Ok(true)
}

impl<D: Decoder> SymbolicSession<'_, D> {
    /// Reproducible digest of the fresh root including mapped concrete and
    /// symbolic bytes. Oversized or mutable environments cannot be pinned.
    pub fn sustained_initial_digest(&self) -> Result<Digest, SustainedError> {
        let state = self
            .states
            .first()
            .ok_or(SustainedError::UnreplayableEnvironment("missing root"))?;
        let process = &state.process;
        if !process.stdin.is_empty()
            || !process.files.is_empty()
            || !process.open_fds.is_empty()
            || !process.symbolic_files.is_empty()
            || !process.symbolic_fds.is_empty()
            || !process.symbolic_fd_paths.is_empty()
            || process.kernel_pool.is_some()
            || process.jni_env.is_some()
            || !models_are_deterministic(process)
            || !process.redirects.is_empty()
            || self.uc_pin_fallback
            || !self.loop_summaries.is_empty()
            || !self.function_summaries.is_empty()
        {
            return Err(SustainedError::UnreplayableEnvironment(
                "mutable environment or hooks cannot be replayed",
            ));
        }
        let pe = pinned_pe_loader_state(state)?;
        let mut bytes = Vec::new();
        // A process carrying kernel models needs its own root domain: the
        // model set is part of the pinned environment, and old v1 ledgers must
        // not silently compare equal to a modeled root.
        let modeled = !process.simproc_instances.is_empty();
        bytes.extend_from_slice(match (pe, modeled) {
            (true, _) => b"ANGRYIER-SUSTAINED-ROOT-v2-PE".as_slice(),
            (false, false) => b"ANGRYIER-SUSTAINED-ROOT-v1".as_slice(),
            (false, true) => b"ANGRYIER-SUSTAINED-ROOT-v3-MODELED-ELF".as_slice(),
        });
        // Bind the deterministic model set: address and model identity, sorted
        // so install order cannot change the digest.
        if modeled {
            let mut bindings: Vec<(u64, String)> = process
                .simproc_instances
                .iter()
                .map(|(address, model)| (*address, model.name().to_owned()))
                .collect();
            bindings.sort();
            bytes.extend_from_slice(&(bindings.len() as u64).to_le_bytes());
            for (address, name) in &bindings {
                bytes.extend_from_slice(&address.to_le_bytes());
                bytes.extend_from_slice(&(name.len() as u64).to_le_bytes());
                bytes.extend_from_slice(name.as_bytes());
            }
        }
        for n in [
            process.entry,
            process.image_id.0,
            process.target_profile.0,
            process.program_break,
            process.heap_end,
            process.mmap_next,
        ] {
            bytes.extend_from_slice(&n.to_le_bytes());
        }
        for register in (0..16)
            .map(|i| crate::register_id::GPR_BASE + i)
            .chain([crate::register_id::RIP.0, crate::register_id::RFLAGS.0])
            .chain(
                [crate::register_id::FS_BASE.0, crate::register_id::GS_BASE.0]
                    .into_iter()
                    .filter(|_| pe),
            )
        {
            let value = match process.read_register(register) {
                Ok(value) => value,
                Err(_) if !pe => continue, // Preserve the legacy ELF v1 encoding.
                Err(_) => return Err(SustainedError::UnreplayableEnvironment("unreadable PE root register")),
            };
            bytes.extend_from_slice(&register.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for (register, value) in &state.concrete_registers {
            bytes.extend_from_slice(&register.to_le_bytes());
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for (register, (expr, kind)) in &state.registers {
            bytes.extend_from_slice(&register.to_le_bytes());
            bytes.extend_from_slice(&expr.0.to_le_bytes());
            bytes.extend_from_slice(format!("{kind:?}").as_bytes());
            let key = self
                .arena
                .dependency_summary(*expr)
                .ok_or(SustainedError::InitialStateMismatch)?
                .key;
            bytes.extend_from_slice(&key.0);
            bytes.push(0);
        }
        for binding in &state.symbols {
            bytes.extend_from_slice(&binding.register.to_le_bytes());
            bytes.extend_from_slice(&binding.width.to_le_bytes());
            bytes.extend_from_slice(&binding.expression.0.to_le_bytes());
        }
        for (expr, addr) in &state.replay_memory_symbols {
            bytes.extend_from_slice(&expr.0.to_le_bytes());
            bytes.extend_from_slice(&addr.to_le_bytes());
        }
        if !state.replay_stream_symbols.is_empty() || !state.memory.memory.symbolic_writes().is_empty() {
            return Err(SustainedError::UnreplayableEnvironment(
                "runtime stream/array memory cannot be pinned",
            ));
        }
        let prefix_len = bytes.len();
        let mut hash = Sha256::new();
        hash.update(&bytes);
        if pe {
            hash.update(crate::EXIT_HOOK.to_le_bytes());
            hash.update(b"exit");
            hash.update((process.pe_import_stubs.len() as u64).to_le_bytes());
            for (&address, (dll, export)) in &process.pe_import_stubs {
                hash.update(address.to_le_bytes());
                hash.update((dll.len() as u64).to_le_bytes());
                hash.update(dll.as_bytes());
                hash.update((export.len() as u64).to_le_bytes());
                hash.update(export.as_bytes());
            }
        }
        let mut mapped = 0u64;
        let mut region_headers = 0u64;
        let mut chunk = vec![ByteValue::Concrete(0); 4096];
        for region in process.state.memory.regions() {
            mapped = mapped
                .checked_add(region.size)
                .ok_or(SustainedError::InitialStateMismatch)?;
            region_headers += 19;
            // A PE image can occupy 512 MiB, plus the loader's fixed stack,
            // heap and model regions. ELF retains its previous 64 MiB bound.
            if region.size > if pe { 512 * 1024 * 1024 } else { 64 * 1024 * 1024 }
                || (pe && mapped > 576 * 1024 * 1024)
                || (!pe
                    && (prefix_len as u64)
                        .saturating_add(region_headers)
                        .saturating_add(mapped.saturating_mul(4))
                        > 64 * 1024 * 1024)
            {
                return Err(SustainedError::UnreplayableEnvironment(
                    "initial memory exceeds snapshot pinning limit",
                ));
            }
            hash.update(region.base.to_le_bytes());
            hash.update(region.size.to_le_bytes());
            hash.update([region.readable as u8, region.writable as u8, region.executable as u8]);
            let mut at = region.base;
            let end = region
                .base
                .checked_add(region.size)
                .ok_or(SustainedError::InitialStateMismatch)?;
            while at < end {
                let len = (end - at).min(chunk.len() as u64) as usize;
                for memory in [&process.state.memory, state.memory.memory.inner()] {
                    memory
                        .read_into(at, &mut chunk[..len])
                        .map_err(|_| SustainedError::InitialStateMismatch)?;
                    bytes.clear();
                    for &value in &chunk[..len] {
                        match value {
                            ByteValue::Concrete(n) => bytes.extend_from_slice(&[0, n]),
                            ByteValue::Symbolic(expr) => {
                                bytes.push(1);
                                bytes.extend_from_slice(&expr.0.to_le_bytes());
                            }
                        }
                    }
                    hash.update(&bytes);
                }
                at += len as u64;
            }
        }
        Ok(Digest(hash.finalize().into()))
    }

    pub(super) fn sustained_query(
        &self,
        state: &SymbolicState,
        direction: angryier_types::ExprId,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
        target: u64,
        point: &BranchPoint,
    ) -> BranchEvidence {
        self.sustained_query_with_model(state, direction, backend, timeout, target, point)
            .0
    }

    pub(super) fn sustained_query_with_model(
        &self,
        state: &SymbolicState,
        direction: angryier_types::ExprId,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
        target: u64,
        point: &BranchPoint,
    ) -> SustainedQueryResult {
        let key = self.arena.dependency_summary(direction).map(|s| s.key);
        let constraints = checked_path_constraints(
            self.arena,
            &state.constraints[..state.constraints.len().saturating_sub(1)],
        );
        let query = key.and_then(|key| {
            constraints.ok().and_then(|constraints| {
                SolverQuery::canonical(
                    SolverQueryId(0),
                    &constraints,
                    direction,
                    key,
                    state.process.target_profile,
                    ConstraintCanonicalizationVersion(1),
                    timeout,
                )
                .ok()
            })
        });
        let (query_digest, disposition, result_digest, model) = if let Some(query) = query {
            let query_digest = Digest(query.canonical_key().0);
            let started = Instant::now();
            let result = backend.solve(&query);
            let disposition = if started.elapsed() > timeout || result.elapsed > timeout {
                SolverDisposition::Timeout
            } else {
                match result.outcome {
                    SolverOutcomeKind::Sat => SolverDisposition::Sat,
                    SolverOutcomeKind::Unsat => SolverDisposition::Unsat,
                    _ => SolverDisposition::Unknown,
                }
            };
            let result_digest = matches!(disposition, SolverDisposition::Sat | SolverDisposition::Unsat).then(|| {
                let mut data = query_digest.0.to_vec();
                data.push(u8::from(disposition == SolverDisposition::Sat));
                Digest::of(&data).0
            });
            let model = (disposition == SolverDisposition::Sat).then(|| {
                let mut assignments = result.model;
                // Multi-register root seeds (for example `--symbolic-reg sysv`)
                // may leave an unused input symbol absent from all path
                // constraints; Z3 omits unconstrained symbols from its model.
                // Default only symbols absent from `state.constraints` so a
                // tampered/missing constrained symbol still fails verification.
                let mut constrained = std::collections::BTreeSet::new();
                let mut stack: Vec<angryier_types::ExprId> = state.constraints.clone();
                while let Some(id) = stack.pop() {
                    if !constrained.insert(id) {
                        continue;
                    }
                    if let Some(node) = self.arena.get(id) {
                        stack.extend(node.operands.iter().copied());
                    }
                }
                let present: std::collections::BTreeSet<u64> = assignments.iter().map(|(id, _)| *id).collect();
                for binding in &state.symbols {
                    let expr_id = u64::from(binding.expression.0);
                    if present.contains(&expr_id) || constrained.contains(&binding.expression) {
                        continue;
                    }
                    if let Some(&addr) = state.replay_memory_symbols.get(&binding.expression) {
                        if binding.width == 8 {
                            let fallback = state
                                .process
                                .state
                                .memory
                                .read(addr, 1)
                                .ok()
                                .and_then(|bytes| match bytes.first() {
                                    Some(ByteValue::Concrete(b)) => Some(*b),
                                    _ => None,
                                })
                                .unwrap_or(0);
                            assignments.push((expr_id, vec![fallback]));
                        }
                    } else if binding.width == 64
                        && (crate::register_id::GPR_BASE..crate::register_id::GPR_BASE + 16).contains(&binding.register)
                    {
                        let fallback = state.process.read_register(binding.register).unwrap_or(0);
                        assignments.push((expr_id, fallback.to_le_bytes().to_vec()));
                    }
                }
                assignments
            });
            (query_digest, disposition, result_digest, model)
        } else {
            (
                Digest::of(&point.trace_digest.0),
                SolverDisposition::Unknown,
                None,
                None,
            )
        };
        (
            BranchEvidence {
                pc: point.branch_pc,
                visit_index: point.visit_index,
                predicate_digest: point.predicate_digest.0,
                query_digest: query_digest.0,
                result_digest,
                tested_target: Some(target),
                disposition,
            },
            model,
        )
    }

    /// Execute a bounded batch of durably owned subtrees. Each reserved prefix
    /// is replayed from the same independently pinned root, with every dynamic
    /// branch site, visit, trace, predicate, constraint count and edge checked.
    pub fn run_sustained(
        &mut self,
        campaign: &mut SustainedCampaign,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<SustainedRun, SustainedError> {
        self.run_sustained_ranked(campaign, backend, timeout, None)
    }

    pub fn run_sustained_ranked(
        &mut self,
        campaign: &mut SustainedCampaign,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
        ranking: Option<SustainedRanking<'_>>,
    ) -> Result<SustainedRun, SustainedError> {
        let manifest = campaign.ledger.manifest().clone();
        if ranking.is_some_and(|rank| rank.exclude_avoid && rank.avoid.binary_search(&manifest.spec.entry_pc).is_ok()) {
            return Err(SustainedError::ExclusionUnproven);
        }
        if backend.name() != manifest.spec.solver_version {
            return Err(SustainedError::UnreplayableEnvironment(
                "solver backend differs from pinned campaign",
            ));
        }
        let limits = &manifest.spec.limits;
        if self.states.len() != 1 || !self.dead.is_empty() || !self.pending_merges.is_empty() {
            return Err(SustainedError::UnreplayableEnvironment(
                "requires one fresh root without merges or dead states",
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
            return Err(SustainedError::UnreplayableEnvironment("root is not at fresh entry"));
        }
        let initial = self.sustained_initial_digest()?;
        if campaign
            .ledger
            .records()
            .iter()
            .any(|r| r.replay.initial_state_digest != initial)
        {
            return Err(SustainedError::InitialStateMismatch);
        }
        let root = root.clone();
        let mut owner_bytes = b"angryier-local-sustained/v1".to_vec();
        owner_bytes.extend_from_slice(&manifest.campaign_digest.0);
        owner_bytes.extend_from_slice(&initial.0);
        let owner = Digest::of(&owner_bytes);
        let deadline = timeout.min(Duration::from_millis(limits.max_wall_millis));
        let start = Instant::now();
        let old_fork_policy = self.fork_on_symbolic;
        self.fork_on_symbolic = true;
        let result = (|| {
            let mut steps = 0u64;
            let mut solver_spent = Duration::ZERO;
            let mut reason = None;
            while let Some(grant) = match ranking {
                Some(rank) => campaign.ledger.reserve_by_rank_fenced(owner, rank.find, rank.avoid)?,
                None => campaign.ledger.reserve_fenced(owner)?,
            } {
                let reservation = &grant.reservation;
                self.states.clear();
                self.states.push(root.clone());
                self.dead.clear();
                self.pending_merges.clear();
                self.feasibility_memo.clear();
                let debt_before = self.vector_debt_total;
                let retries_before = self.concretization_retries_total;
                let mut step_debt = Vec::new();
                let mut path_steps = 0u64;
                let mut matched = 0usize;
                let mut branches = Vec::new();
                let mut owned_model = None;
                let (mut status, mut disposition, mut why, split) = loop {
                    let state = &self.states[0];
                    let pc = state.process.pc().ok();
                    if ranking.is_some_and(|rank| {
                        rank.exclude_avoid && pc.is_some_and(|pc| rank.avoid.binary_search(&pc).is_ok())
                    }) {
                        campaign.ledger.revoke_fenced(&grant)?;
                        return Err(SustainedError::ExclusionUnproven);
                    }
                    if start.elapsed() >= deadline {
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::Timeout),
                            "wall timeout",
                            None,
                        );
                    }
                    if steps >= limits.max_steps || path_steps >= limits.max_path_steps {
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
                        .try_fold(0u64, |size, region| size.checked_add(region.size));
                    if mapped.is_none_or(|n| n.saturating_add(limits.max_trace_bytes) > limits.max_ram_bytes) {
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::ResourceLimit),
                            "mapped state/trace RAM budget",
                            None,
                        );
                    }
                    if pc.is_some_and(|pc| {
                        state.process.trace.iter().filter(|&&v| v == pc).count() as u64 >= limits.max_loop_visits
                    }) {
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::ResourceLimit),
                            "loop visit budget",
                            None,
                        );
                    }
                    if state.branch_history.len() as u64 > limits.max_path_depth {
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::ResourceLimit),
                            "branch depth budget",
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
                    path_steps += 1;
                    self.pending_merges.clear(); // contract-owned prefixes must never merge
                    let outcome = match outcome {
                        Ok(outcome) => outcome,
                        Err(_) => {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::Unknown),
                                "execution failed; subtree retained",
                                None,
                            );
                        }
                    };
                    if self.states.is_empty() {
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::Unknown),
                            "state disappeared without a verified terminal",
                            None,
                        );
                    }
                    let state = &self.states[0];
                    let new_decision = state.branch_history.len() > matched;
                    if matched < reservation.unit.prefix.len() {
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
                        let expected = &reservation.unit.prefix[matched];
                        let actual = state.last_branch.and_then(|d| branch_point(self, state, d));
                        if actual.as_ref() != Some(&expected.branch) {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::ReplayMismatch),
                                "branch context mismatch on root replay",
                                None,
                            );
                        }
                        let chosen = match expected.successor {
                            Successor::True => 0,
                            Successor::False => 1,
                        };
                        if !matches!(outcome, SymbolicStepOutcome::Branched { .. }) || self.states.len() != 2 {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::ReplayMismatch),
                                "owned edge not forked during replay",
                                None,
                            );
                        }
                        let opposite = 1 - chosen;
                        self.states.remove(opposite);
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
                        if !matches!(outcome, SymbolicStepOutcome::Branched { .. }) || self.states.len() != 2 {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::Unknown),
                                "single-edge fork lacks complementary solver proof",
                                None,
                            );
                        }
                        let Some(point) = state.last_branch.and_then(|d| branch_point(self, state, d)) else {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::ReplayMismatch),
                                "fork context unavailable",
                                None,
                            );
                        };
                        let other_owned: Vec<_> = campaign
                            .ledger
                            .records()
                            .iter()
                            .filter(|r| !r.retired && r.unit != reservation.unit)
                            .map(|r| r.unit.clone())
                            .collect();
                        let Ok((false_child, true_child)) =
                            reservation
                                .unit
                                .split(&manifest, campaign.ledger.epoch(), point.clone(), &other_owned)
                        else {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::ResourceLimit),
                                "fork exceeds ownership/depth bound",
                                None,
                            );
                        };
                        let remaining = deadline
                            .saturating_sub(start.elapsed())
                            .min(Duration::from_millis(limits.max_solver_millis).saturating_sub(solver_spent));
                        if remaining.is_zero() {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::Timeout),
                                "no solver time remaining",
                                None,
                            );
                        }
                        let fork_proofs = branches.len();
                        for (index, target) in [(1, point.false_target), (0, point.true_target)] {
                            let state = &self.states[index];
                            let Some(direction) = state.constraints.last().copied() else {
                                break;
                            };
                            let query_start = Instant::now();
                            let remaining = deadline
                                .saturating_sub(start.elapsed())
                                .min(Duration::from_millis(limits.max_solver_millis).saturating_sub(solver_spent));
                            branches.push(self.sustained_query(state, direction, backend, remaining, target, &point));
                            solver_spent += query_start.elapsed();
                        }
                        if branches.len() != fork_proofs + 2 {
                            break (
                                Status::Deferred,
                                PathDisposition::Pending(PendingReason::Unknown),
                                "solver direction unavailable",
                                None,
                            );
                        }
                        let to_status = |branch: &BranchEvidence| match branch.disposition {
                            SolverDisposition::Sat if limits.max_active_states >= 2 => ChildDisposition::Queued,
                            SolverDisposition::Sat => {
                                ChildDisposition::Deferred("active state cap; replayable child retained".into())
                            }
                            SolverDisposition::Unsat => {
                                ChildDisposition::Infeasible("solver UNSAT at verified fork".into())
                            }
                            _ => ChildDisposition::Unknown("solver returned UNKNOWN/timeout; child retained".into()),
                        };
                        let policy_status = |branch: &BranchEvidence, target: u64| {
                            if ranking
                                .is_some_and(|rank| rank.exclude_avoid && rank.avoid.binary_search(&target).is_ok())
                            {
                                if branch.disposition == SolverDisposition::Unsat {
                                    return Ok(to_status(branch));
                                }
                                if branch.disposition != SolverDisposition::Sat || branch.result_digest.is_none() {
                                    return Err(SustainedError::ExclusionUnproven);
                                }
                                let digest: String = manifest
                                    .spec
                                    .policy_digest
                                    .0
                                    .iter()
                                    .map(|b| format!("{b:02x}"))
                                    .collect();
                                Ok(ChildDisposition::Excluded(format!(
                                    "excluded-by-policy:{digest}:{target:016x}"
                                )))
                            } else {
                                Ok(to_status(branch))
                            }
                        };
                        let (false_status, true_status) = match (
                            policy_status(&branches[fork_proofs], point.false_target),
                            policy_status(&branches[fork_proofs + 1], point.true_target),
                        ) {
                            (Ok(false_status), Ok(true_status)) => (false_status, true_status),
                            _ => {
                                campaign.ledger.revoke_fenced(&grant)?;
                                return Err(SustainedError::ExclusionUnproven);
                            }
                        };
                        let dispositions = (false_status, true_status);
                        break (
                            Status::Deferred,
                            PathDisposition::Pending(PendingReason::Queued),
                            "fork split into two durable children",
                            Some((false_child, true_child, dispositions)),
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
                let state = self.states.first().or_else(|| self.dead.first());
                let trace = state.map(|state| state.process.trace.as_slice()).unwrap_or(&[]);
                let witness = if status == Status::Completed && matched == reservation.unit.prefix.len() {
                    owned_model.as_deref().and_then(|model| {
                        sustained_witness::verify(
                            self,
                            &root,
                            &reservation.unit,
                            &manifest,
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
                    && owned_model.as_ref().is_some_and(|model| !model.is_empty())
                    && !witness.as_ref().is_some_and(|w| {
                        matches!(
                            w.replay,
                            angryier_provenance::sustained::ReplayVerification::Verified { .. }
                        )
                    })
                {
                    status = Status::Deferred;
                    disposition = PathDisposition::Pending(PendingReason::ReplayMismatch);
                    why = "concrete root replay did not verify SAT model and exact dynamic trace";
                }
                let mut path = observed_path(
                    &reservation.unit,
                    initial,
                    trace,
                    disposition,
                    manifest.spec.fidelity,
                    branches,
                );
                path.witness = witness;
                let counted_debt = self
                    .vector_debt_total
                    .saturating_sub(debt_before)
                    .saturating_add(self.concretization_retries_total.saturating_sub(retries_before));
                if step_debt.len() as u64 != counted_debt {
                    campaign.ledger.revoke_fenced(&grant)?;
                    return Err(SustainedError::UnreplayableEnvironment(
                        "step debt exceeds bounded evidence",
                    ));
                }
                if let Some(state) = state {
                    path.semantic_debt = observed_debt(state);
                }
                path.semantic_debt.extend(step_debt);
                let delta = EvidenceDelta {
                    sequence: reservation.attempt,
                    path,
                };
                if let Err(error) = delta.validate(&manifest, campaign.ledger.epoch()) {
                    campaign.ledger.revoke_fenced(&grant)?;
                    return Err(error.into());
                }
                let committed = if let Some((false_child, true_child, (false_status, true_status))) = split {
                    let proof_for = |child: &WorkUnit, status: &ChildDisposition| {
                        if !matches!(status, ChildDisposition::Infeasible(_) | ChildDisposition::Excluded(_)) {
                            return None;
                        }
                        let decision = child.prefix.last()?;
                        let branch = delta.path.branches.iter().rev().take(2).find(|branch| {
                            branch.pc == decision.branch.branch_pc
                                && branch.visit_index == decision.branch.visit_index
                                && branch.tested_target == Some(decision.target())
                                && branch.predicate_digest == decision.branch.predicate_digest.0
                                && branch.disposition
                                    == if matches!(status, ChildDisposition::Excluded(_)) {
                                        SolverDisposition::Sat
                                    } else {
                                        SolverDisposition::Unsat
                                    }
                        })?;
                        let mut path = delta.path.clone();
                        path.path_id = path_id(child, initial).0;
                        path.disposition = if matches!(status, ChildDisposition::Excluded(_)) {
                            PathDisposition::ExcludedByPolicy
                        } else {
                            PathDisposition::SolverInfeasible
                        };
                        path.witness = None;
                        path.branches.truncate(path.branches.len().saturating_sub(2));
                        path.branches.push(*branch);
                        if matches!(status, ChildDisposition::Infeasible(_)) {
                            path.edges.push(FlowEdge {
                                from_pc: branch.pc,
                                to_pc: decision.target(),
                                basis: EdgeBasis::SolverInfeasible {
                                    predicate_digest: branch.predicate_digest,
                                    query_digest: branch.query_digest,
                                    result_digest: branch.result_digest?,
                                },
                            });
                        }
                        Some(EvidenceDelta {
                            sequence: delta.sequence,
                            path,
                        })
                    };
                    let child_proofs = [
                        proof_for(&false_child, &false_status),
                        proof_for(&true_child, &true_status),
                    ];
                    if (matches!(false_status, ChildDisposition::Excluded(_)) && child_proofs[0].is_none())
                        || (matches!(true_status, ChildDisposition::Excluded(_)) && child_proofs[1].is_none())
                    {
                        campaign.ledger.revoke_fenced(&grant)?;
                        return Err(SustainedError::ExclusionUnproven);
                    }
                    campaign.ledger.split_with_proofs_fenced(
                        &grant,
                        false_child,
                        true_child,
                        false_status,
                        true_status,
                        angryier_ledger::sustained::SplitProofs { delta, child_proofs },
                    )
                } else {
                    campaign.ledger.commit_outcome_fenced(&grant, status, why, delta)
                };
                if let Err(error) = committed {
                    let _ = campaign.ledger.revoke_fenced(&grant);
                    return Err(error.into());
                }
                if status != Status::Completed {
                    reason = Some(why.to_owned());
                }
                if start.elapsed() >= deadline || steps >= limits.max_steps {
                    break;
                }
            }
            let mut report = campaign.report();
            if ranking.is_some_and(|rank| {
                rank.exclude_avoid
                    && report.complete_within_declared_bounds
                    && rank.avoid.iter().any(|target| {
                        !campaign.ledger.records().iter().any(|record| {
                            matches!(record.status, Status::Excluded | Status::Infeasible)
                                && record
                                    .unit
                                    .prefix
                                    .last()
                                    .is_some_and(|decision| decision.target() == *target)
                        })
                    })
            }) {
                return Err(SustainedError::ExclusionUnproven);
            }
            let mut evidence =
                EvidenceBuilder::new(scope(&manifest, campaign.ledger.epoch()), report_limits(&manifest))?;
            let mut accepted_splits = Vec::new();
            let (records, _) = campaign.ledger.read_snapshot();
            for event in campaign.ledger.cumulative_evidence() {
                let record = &records[event.work_index as usize];
                if record.retired {
                    accepted_splits.push(event.delta.path.clone());
                } else {
                    evidence.add_path(event.delta.path.clone())?;
                }
            }
            let path_dispositions: HashMap<_, _> = evidence
                .report()
                .paths
                .iter()
                .map(|path| (path.path_id, path.disposition))
                .collect();
            for record in records.iter().filter(|record| {
                !record.retired
                    && matches!(
                        record.status,
                        Status::Queued | Status::Active | Status::Unknown | Status::Deferred | Status::Failed
                    )
            }) {
                let path_id = path_id(&record.unit, initial).0;
                evidence.add_frontier(PendingWork {
                    path_id,
                    reason: if record.status == Status::Queued {
                        PendingReason::Queued
                    } else if let Some(&PathDisposition::Pending(reason)) = path_dispositions.get(&path_id) {
                        reason
                    } else if record.status == Status::Deferred {
                        PendingReason::Deferred
                    } else {
                        PendingReason::Unknown
                    },
                })?;
            }
            if report.complete_within_declared_bounds {
                let resolved = report.completed + report.infeasible + report.excluded;
                if evidence.report().paths.len() == resolved {
                    evidence.close_owned_scope(ScopeClosure {
                        owned_work_units: resolved as u64,
                        resolved_work_units: resolved as u64,
                    })?;
                    reason = None;
                } else {
                    report.complete_within_declared_bounds = false;
                    reason = Some("resolved leaf lacks accepted evidence".into());
                }
            } else if reason.is_none() {
                reason = Some("campaign has unresolved owned work".into());
            }
            Ok(SustainedRun {
                ledger: report,
                evidence,
                accepted_splits,
                steps,
                reason,
            })
        })();
        self.fork_on_symbolic = old_fork_policy;
        result
    }
}

#[cfg(all(test, feature = "xed", target_arch = "x86_64"))]
mod pe_root_tests {
    use super::*;
    use crate::Runtime;
    use angryier_expr::ShardedExprArena;
    use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

    fn driver_fixture() -> Vec<u8> {
        let mut pe = vec![0u8; 0x480];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[0xb0..0xb8].copy_from_slice(&0x1_4000_0000u64.to_le_bytes());
        pe[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
        pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
        pe[0x110..0x114].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[0x114..0x118].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
        pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes());
        pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[0x198..0x19c].copy_from_slice(&1u32.to_le_bytes());
        pe[0x19c..0x1a0].copy_from_slice(&0x200u32.to_le_bytes());
        pe[0x1ac..0x1b0].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        pe[0x1b0..0x1b8].copy_from_slice(b".rdata\0\0");
        pe[0x1b8..0x1bc].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x1bc..0x1c0].copy_from_slice(&0x2000u32.to_le_bytes());
        pe[0x1c0..0x1c4].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x1c4..0x1c8].copy_from_slice(&0x400u32.to_le_bytes());
        pe[0x1d4..0x1d8].copy_from_slice(&0x4000_0000u32.to_le_bytes());
        pe[0x200] = 0xc3;
        // Import descriptor, DLL, INT, IAT, hint/name for one export.
        pe[0x400..0x404].copy_from_slice(&0x2038u32.to_le_bytes());
        pe[0x40c..0x410].copy_from_slice(&0x2028u32.to_le_bytes());
        pe[0x410..0x414].copy_from_slice(&0x2048u32.to_le_bytes());
        pe[0x428..0x435].copy_from_slice(b"ntoskrnl.exe\0");
        pe[0x438..0x440].copy_from_slice(&0x2060u64.to_le_bytes());
        pe[0x448..0x450].copy_from_slice(&0x2060u64.to_le_bytes());
        pe[0x462..0x46b].copy_from_slice(b"DbgPrint\0");
        pe
    }

    #[test]
    fn pe_loader_root_pins_segment_bases() -> Result<(), Box<dyn std::error::Error>> {
        use angryier_state::SymbolicRegisterState;

        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let process = runtime.load_pe_driver(&driver_fixture())?;
        let mut session = SymbolicSession::new(&runtime, &arena, process);
        let pinned = session.sustained_initial_digest()?;
        for register in [crate::register_id::GS_BASE.0, crate::register_id::FS_BASE.0] {
            let original = session.states[0].process.read_register(register)?;
            session.states[0].process.write_register(register, original ^ 1)?;
            assert_ne!(session.sustained_initial_digest()?, pinned);
            session.states[0].process.write_register(register, original)?;
        }
        let registers = &mut session.states[0].process.state.registers;
        *registers = registers.write_symbolic(crate::register_id::GS_BASE.0, angryier_types::ExprId(1))?;
        assert!(matches!(
            session.sustained_initial_digest(),
            Err(SustainedError::UnreplayableEnvironment(_))
        ));
        Ok(())
    }

    #[test]
    fn pe_loader_root_pins_only_exact_exit_hook_and_stub_map() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let process = runtime.load_pe_driver(&driver_fixture())?;
        assert_eq!(process.pe_import_stubs.len(), 1);
        let mut session = SymbolicSession::new(&runtime, &arena, process);
        let pinned = session.sustained_initial_digest()?;
        assert_eq!(session.sustained_initial_digest()?, pinned);
        session.states[0]
            .process
            .simproc_hooks
            .insert(crate::EXIT_HOOK + 1, "exit".into());
        assert!(session.sustained_initial_digest().is_err());
        session.states[0].process.simproc_hooks.remove(&(crate::EXIT_HOOK + 1));
        session.states[0]
            .process
            .redirects
            .insert(crate::EXIT_HOOK, crate::PE_DRIVER_STUB_BASE);
        assert!(session.sustained_initial_digest().is_err());
        session.states[0].process.redirects.clear();
        session.states[0]
            .process
            .pe_import_stubs
            .get_mut(&crate::PE_DRIVER_STUB_BASE)
            .unwrap()
            .1 = "Other".into();
        assert_ne!(session.sustained_initial_digest()?, pinned);
        session.states[0]
            .process
            .pe_import_stubs
            .insert(crate::PE_DRIVER_STUB_BASE + 32, ("ntoskrnl.exe".into(), "Other".into()));
        assert!(session.sustained_initial_digest().is_err());
        Ok(())
    }

    #[test]
    fn pe_digest_distinguishes_both_memory_views() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let process = runtime.load_pe_driver(&driver_fixture())?;
        let mut session = SymbolicSession::new(&runtime, &arena, process);
        let original = session.sustained_initial_digest()?;
        let at = crate::PE_DRIVER_SCRATCH_BASE + 4095;
        let values = [
            ByteValue::Concrete(0xa5),
            ByteValue::Symbolic(angryier_types::ExprId(42)),
        ];
        let base = session.states[0].process.state.memory.clone();
        session.states[0].process.state.memory = base.write(at, &values)?;
        let process_only = session.sustained_initial_digest()?;
        session.states[0].process.state.memory = base;
        let view = &mut session.states[0].memory.memory;
        *view = view.write_at_address(at, &values)?;
        let symbolic_only = session.sustained_initial_digest()?;
        assert_ne!(process_only, original);
        assert_ne!(symbolic_only, original);
        assert_ne!(process_only, symbolic_only);
        Ok(())
    }

    #[test]
    fn pe_image_larger_than_legacy_snapshot_limit_is_streamed() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let mut image = driver_fixture();
        // 18 MiB of mapped .rdata plus fixed loader regions exceeds the
        // old 64 MiB serialized-snapshot cap; raw bytes remain tiny.
        image[0x1b8..0x1bc].copy_from_slice(&(18 * 1024 * 1024u32).to_le_bytes());
        let process = runtime.load_pe_driver(&image)?;
        let session = SymbolicSession::new(&runtime, &arena, process);
        assert_ne!(session.sustained_initial_digest()?.0, [0; 32]);
        Ok(())
    }

    #[test]
    fn pe_loader_root_rejects_modified_stub_and_sentinel() -> Result<(), Box<dyn std::error::Error>> {
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let process = runtime.load_pe_driver(&driver_fixture())?;
        let mut session = SymbolicSession::new(&runtime, &arena, process);
        let original = session.states[0].process.state.memory.clone();
        session.states[0].process.state.memory = original.load_concrete(crate::PE_DRIVER_STUB_BASE, &[0x90])?;
        assert!(session.sustained_initial_digest().is_err());
        session.states[0].process.state.memory = original;
        let rsp = session.states[0]
            .process
            .read_register(crate::register_id::GPR_BASE + 4)?;
        session.states[0].process.state.memory = session.states[0].process.state.memory.load_concrete(rsp, &[1])?;
        assert!(session.sustained_initial_digest().is_err());
        Ok(())
    }
}

/// True when every installed SimProcedure is one of the deterministic kernel
/// models, whose behaviour is a pure function of its slot address. Any other
/// hook makes the root unreplayable.
fn models_are_deterministic(process: &crate::Process) -> bool {
    process
        .simproc_instances
        .values()
        .all(|model| crate::kernel_models::DETERMINISTIC_MODEL_NAMES.contains(&model.name()))
}

#[cfg(test)]
mod cumulative_evidence_tests {
    use super::*;
    use angryier_distribution::contracts::{CampaignSpec, ExplorationLimits};
    use angryier_ledger::{
        evidence::{ReplayVerification, WitnessEvidence},
        sustained::{Reservation, work_path_id},
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
        fn new() -> std::io::Result<Self> {
            let dir = std::env::temp_dir().join(format!(
                "angryier-runtime-cumulative-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed),
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

    fn manifest() -> CampaignManifest {
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
        .expect("manifest")
    }

    fn artifacts() -> CampaignArtifacts<'static> {
        CampaignArtifacts {
            binary: b"binary",
            semantic_profile: b"semantics",
            script: b"script",
            policy: b"policy",
            solver_policy: b"solver-policy",
            inputs: vec![],
            stubs: vec![],
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

    #[test]
    fn report_retains_more_than_legacy_path_and_frontier_capacity() -> Result<(), SustainedError> {
        let mut spec = manifest().spec;
        spec.limits.max_ram_bytes = 2 * 1024 * 1024;
        spec.limits.max_disk_bytes = 3 * 1024 * 1024;
        let manifest = CampaignManifest::seal(spec)?;
        let limits = report_limits(&manifest);
        assert_eq!(limits.max_bytes, 2 * 1024 * 1024);
        let mut evidence = EvidenceBuilder::new(scope(&manifest, 1), limits)?;
        for index in 1..=4097u64 {
            let mut path_id = [0; 32];
            path_id[..8].copy_from_slice(&index.to_le_bytes());
            evidence.add_path(PathEvidence {
                path_id,
                provenance_digest: Digest::of(b"provenance").0,
                fidelity: FidelityProfile::Prove,
                blocks: vec![],
                edges: vec![],
                branches: vec![],
                witness: None,
                semantic_debt: vec![],
                disposition: PathDisposition::Pending(PendingReason::Timeout),
            })?;
        }
        let path_dispositions: HashMap<_, _> = evidence
            .report()
            .paths
            .iter()
            .map(|path| (path.path_id, path.disposition))
            .collect();
        for index in 1..=4097u64 {
            let mut path_id = [0; 32];
            path_id[..8].copy_from_slice(&index.to_le_bytes());
            let Some(&PathDisposition::Pending(reason)) = path_dispositions.get(&path_id) else {
                panic!("missing accepted pending path");
            };
            evidence.add_frontier(PendingWork { path_id, reason })?;
        }
        let report = evidence.report();
        assert_eq!(report.paths.len(), 4097);
        assert_eq!(report.frontier.len(), 4097);
        assert_eq!(report.frontier.last().unwrap().reason, PendingReason::Timeout);
        assert!(
            evidence
                .close_owned_scope(ScopeClosure {
                    owned_work_units: 4097,
                    resolved_work_units: 4097,
                })
                .is_err()
        );

        let mut spec = manifest.spec;
        spec.limits.max_ram_bytes = 1;
        let tight_manifest = CampaignManifest::seal(spec)?;
        let tight_limits = report_limits(&tight_manifest);
        assert_eq!(tight_limits.max_bytes, 1);
        let mut bounded = EvidenceBuilder::new(scope(&tight_manifest, 1), tight_limits)?;
        assert_eq!(
            bounded.add_frontier(PendingWork {
                path_id: Digest::of(b"pending").0,
                reason: PendingReason::Queued,
            }),
            Err(EvidenceError::Exhausted)
        );
        Ok(())
    }

    #[test]
    fn cumulative_evidence_exposes_latest_accepted_per_path() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let mut campaign = SustainedCampaign::open(&fixture.path, manifest(), &artifacts(), Digest::of(b"seed"))?;
        assert_eq!(campaign.cumulative_evidence().count(), 0);
        let first = campaign.ledger.reserve()?.ok_or("root")?;
        campaign.ledger.commit_outcome(
            &first,
            Status::Unknown,
            "solver unknown",
            delta(&first, PathDisposition::Pending(PendingReason::Unknown)),
        )?;
        campaign.ledger.requeue(&first.unit)?;
        let second = campaign.ledger.reserve()?.ok_or("retry")?;
        assert!(second.attempt > first.attempt);
        let mut latest = terminal(&second);
        latest.sequence = 2;
        campaign
            .ledger
            .commit_outcome(&second, Status::Completed, "replayed", latest)?;
        // Both events remain in the snapshot, but the borrowed iterator yields
        // only the latest accepted disposition for the single path.
        assert_eq!(campaign.ledger.read_snapshot().1.len(), 2);
        let accepted = campaign.accepted_events();
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].status, Status::Unknown);
        assert_eq!(accepted[1].status, Status::Completed);
        let cumulative: Vec<_> = campaign.cumulative_evidence().collect();
        assert_eq!(cumulative.len(), 1);
        assert_eq!(cumulative[0].status, Status::Completed);
        assert_eq!(cumulative[0].attempt, second.attempt);
        Ok(())
    }

    #[test]
    fn start_new_never_reopens_existing_ledger() -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let initial = Digest::of(b"seed");
        let first = SustainedCampaign::start_new(&fixture.path, manifest(), &artifacts(), initial)?;
        assert!(matches!(
            SustainedCampaign::start_new(&fixture.path, manifest(), &artifacts(), initial),
            Err(SustainedError::Ledger(_))
        ));
        drop(first);
        assert!(matches!(
            SustainedCampaign::start_new(&fixture.path, manifest(), &artifacts(), initial),
            Err(SustainedError::Ledger(LedgerError::AlreadyExists)) | Err(SustainedError::Ledger(LedgerError::Io(_)))
        ));
        assert!(SustainedCampaign::resume_existing(&fixture.path, manifest(), &artifacts(), initial).is_ok());
        Ok(())
    }
}
