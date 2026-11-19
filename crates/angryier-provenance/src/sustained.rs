//! Bounded local evidence for a single sustained-exploration ownership scope.
//!
//! These records describe observations and caller-supplied solver/replay evidence;
//! they do not execute a solver, prove a solver result, or persist a frontier.
//! The owner must retain pending work in its durable work ledger separately.

use std::collections::BTreeSet;
use std::mem::size_of;

use angryier_types::FidelityProfile;

/// Content identities supplied by the distribution contract / engine.
pub type Digest = [u8; 32];

pub const EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceScope {
    pub campaign_digest: Digest,
    pub contract_epoch: u64,
    /// Digest of the exact declared resource limits, not an assertion of unbounded coverage.
    pub bounds_digest: Digest,
    pub fidelity: FidelityProfile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceLimits {
    pub max_paths: usize,
    pub max_frontier: usize,
    pub max_items_per_path: usize,
    pub max_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EvidenceError {
    Invalid(&'static str),
    DuplicatePath,
    DuplicateFrontier,
    Exhausted,
    Closed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DynamicBlock {
    pub pc: u64,
    /// Exact zero-based dynamic visit of this block; repeated PCs are not merged.
    pub visit_index: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EdgeBasis {
    /// A trace established that this edge was traversed, NOT that an alternative is feasible.
    Observed { trace_digest: Digest },
    /// A static analysis proposed an edge, without a dynamic witness.
    StaticInference { analysis_digest: Digest },
    /// Must match an explicit UNSAT branch query in the same path record.
    SolverInfeasible {
        predicate_digest: Digest,
        query_digest: Digest,
        result_digest: Digest,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowEdge {
    pub from_pc: u64,
    pub to_pc: u64,
    pub basis: EdgeBasis,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolverDisposition {
    NotQueried,
    Sat,
    Unsat,
    Unknown,
    Timeout,
    ResourceLimit,
    BackendError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchEvidence {
    pub pc: u64,
    pub visit_index: u64,
    pub predicate_digest: Digest,
    pub query_digest: Digest,
    pub result_digest: Option<Digest>,
    /// The successor tested by this query, required for an UNSAT claim.
    pub tested_target: Option<u64>,
    pub disposition: SolverDisposition,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplayVerification {
    NotChecked,
    Verified { trace_digest: Digest },
    Mismatch,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessEvidence {
    pub input_digest: Digest,
    /// Digest of the pinned input artifact set used for a separate concrete replay.
    pub replay_input_provenance: Option<Digest>,
    /// Ordered, actual dynamic block visits from that replay, not a solver model.
    pub replay_trace: Vec<DynamicBlock>,
    pub replay: ReplayVerification,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DebtKind {
    Approximation,
    Concretization,
    UnsupportedSemantics,
    ExternalModel,
    UnderconstrainedMemory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SemanticDebt {
    pub pc: u64,
    pub kind: DebtKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PendingReason {
    Queued,
    Leased,
    Deferred,
    Unknown,
    Timeout,
    ResourceLimit,
    ReplayMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureReason {
    Execution,
    Solver,
    Replay,
    Storage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathDisposition {
    Terminal,
    ExcludedByPolicy,
    SolverInfeasible,
    Pending(PendingReason),
    Failed(FailureReason),
}

/// One dynamic path, keyed by contract path identity, never by PC or CFG edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathEvidence {
    pub path_id: Digest,
    pub provenance_digest: Digest,
    pub fidelity: FidelityProfile,
    pub blocks: Vec<DynamicBlock>,
    pub edges: Vec<FlowEdge>,
    pub branches: Vec<BranchEvidence>,
    pub witness: Option<WitnessEvidence>,
    pub semantic_debt: Vec<SemanticDebt>,
    pub disposition: PathDisposition,
}

/// The caller retains this work outside the report; a frontier record is NOT a terminal path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingWork {
    pub path_id: Digest,
    pub reason: PendingReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Completion {
    CompleteWithinDeclaredBounds,
    Partial,
    Blocked,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScopeClosure {
    /// Caller attestation of a drained owned subtree; this module cannot verify ownership.
    pub owned_work_units: u64,
    pub resolved_work_units: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvidenceSummary {
    pub schema_version: u32,
    pub scope: EvidenceScope,
    pub closure: Option<ScopeClosure>,
    pub completion: Completion,
    pub terminal_paths: usize,
    pub excluded_paths: usize,
    pub infeasible_paths: usize,
    pub pending_paths: usize,
    pub failed_paths: usize,
    pub retained_frontier: usize,
    pub observed_edges: usize,
    pub inferred_edges: usize,
    pub infeasible_edges: usize,
    pub dynamic_blocks: usize,
    pub replay_verified_witnesses: usize,
    pub semantic_debt_records: usize,
    /// Rejected evidence due to a storage bound; any positive value forces Failed.
    pub storage_rejections: usize,
}

pub struct EvidenceReport<'a> {
    pub summary: EvidenceSummary,
    pub paths: &'a [PathEvidence],
    pub frontier: &'a [PendingWork],
}

/// In-memory, fallible evidence sink. Does not claim durability or solver verification.
pub struct EvidenceBuilder {
    scope: EvidenceScope,
    limits: EvidenceLimits,
    paths: Vec<PathEvidence>,
    frontier: Vec<PendingWork>,
    path_ids: BTreeSet<Digest>,
    frontier_ids: BTreeSet<Digest>,
    bytes: usize,
    storage_rejections: usize,
    closure: Option<ScopeClosure>,
}

impl EvidenceBuilder {
    pub fn new(scope: EvidenceScope, limits: EvidenceLimits) -> Result<Self, EvidenceError> {
        if scope.campaign_digest == [0; 32] || scope.bounds_digest == [0; 32] || scope.contract_epoch == 0 {
            return Err(EvidenceError::Invalid("scope identity"));
        }
        if limits.max_paths == 0 || limits.max_frontier == 0 || limits.max_items_per_path == 0 || limits.max_bytes == 0
        {
            return Err(EvidenceError::Invalid("evidence limits"));
        }
        Ok(Self {
            scope,
            limits,
            paths: Vec::new(),
            frontier: Vec::new(),
            path_ids: BTreeSet::new(),
            frontier_ids: BTreeSet::new(),
            bytes: 0,
            storage_rejections: 0,
            closure: None,
        })
    }

    fn reserve_bytes(&mut self, additional: Option<usize>) -> Result<(), EvidenceError> {
        if !additional.is_some_and(|n| {
            self.bytes
                .checked_add(n)
                .is_some_and(|total| total <= self.limits.max_bytes)
        }) {
            self.storage_rejections = self.storage_rejections.saturating_add(1);
            return Err(EvidenceError::Exhausted);
        }
        Ok(())
    }

    pub fn add_path(&mut self, path: PathEvidence) -> Result<(), EvidenceError> {
        if self.closure.is_some() {
            return Err(EvidenceError::Closed);
        }
        if path.path_id == [0; 32] || path.provenance_digest == [0; 32] || path.fidelity != self.scope.fidelity {
            return Err(EvidenceError::Invalid("path identity or fidelity"));
        }
        if self.path_ids.contains(&path.path_id) {
            return Err(EvidenceError::DuplicatePath);
        }
        if path.branches.iter().any(|branch| {
            branch.predicate_digest == [0; 32]
                || branch.query_digest == [0; 32]
                || branch.result_digest == Some([0; 32])
                || (matches!(branch.disposition, SolverDisposition::Sat | SolverDisposition::Unsat)
                    && branch.result_digest.is_none())
                || (branch.disposition == SolverDisposition::Unsat && branch.tested_target.is_none())
        }) {
            return Err(EvidenceError::Invalid("branch solver evidence"));
        }
        for edge in &path.edges {
            let valid = match edge.basis {
                EdgeBasis::Observed { trace_digest } => trace_digest != [0; 32],
                EdgeBasis::StaticInference { analysis_digest } => analysis_digest != [0; 32],
                EdgeBasis::SolverInfeasible {
                    predicate_digest,
                    query_digest,
                    result_digest,
                } => {
                    predicate_digest != [0; 32]
                        && query_digest != [0; 32]
                        && result_digest != [0; 32]
                        && path.branches.iter().any(|branch| {
                            branch.pc == edge.from_pc
                                && branch.tested_target == Some(edge.to_pc)
                                && branch.predicate_digest == predicate_digest
                                && branch.query_digest == query_digest
                                && branch.result_digest == Some(result_digest)
                                && branch.disposition == SolverDisposition::Unsat
                        })
                }
            };
            if !valid {
                return Err(EvidenceError::Invalid("edge evidence"));
            }
            if matches!(edge.basis, EdgeBasis::SolverInfeasible { .. })
                && path.edges.iter().any(|other| {
                    other.from_pc == edge.from_pc
                        && other.to_pc == edge.to_pc
                        && matches!(other.basis, EdgeBasis::Observed { .. })
                })
            {
                return Err(EvidenceError::Invalid("observed edge cannot be infeasible"));
            }
        }
        if path.witness.as_ref().is_some_and(|witness| {
            witness.input_digest == [0; 32]
                || witness.replay_input_provenance == Some([0; 32])
                || matches!(witness.replay, ReplayVerification::Verified { trace_digest }
                    if trace_digest == [0; 32]
                        || witness.replay_input_provenance.is_none()
                        || witness.replay_trace.is_empty()
                        || witness.replay_trace != path.blocks)
        }) {
            return Err(EvidenceError::Invalid("witness evidence"));
        }
        if matches!(
            path.disposition,
            PathDisposition::Terminal | PathDisposition::ExcludedByPolicy | PathDisposition::SolverInfeasible
        ) && path.branches.iter().any(|branch| {
            matches!(
                branch.disposition,
                SolverDisposition::Unknown
                    | SolverDisposition::Timeout
                    | SolverDisposition::ResourceLimit
                    | SolverDisposition::BackendError
            )
        }) {
            return Err(EvidenceError::Invalid("unresolved solver on resolved path"));
        }
        if matches!(path.disposition, PathDisposition::SolverInfeasible)
            && !path
                .branches
                .iter()
                .any(|branch| branch.disposition == SolverDisposition::Unsat)
        {
            return Err(EvidenceError::Invalid("infeasibility without UNSAT"));
        }
        let items = path
            .blocks
            .len()
            .checked_add(path.edges.len())
            .and_then(|n| n.checked_add(path.branches.len()))
            .and_then(|n| n.checked_add(path.semantic_debt.len()))
            .and_then(|n| n.checked_add(path.witness.as_ref().map_or(0, |w| w.replay_trace.len())));
        let bytes = path
            .blocks
            .len()
            .checked_mul(size_of::<DynamicBlock>())
            .and_then(|n| {
                path.edges
                    .len()
                    .checked_mul(size_of::<FlowEdge>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                path.branches
                    .len()
                    .checked_mul(size_of::<BranchEvidence>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                path.semantic_debt
                    .len()
                    .checked_mul(size_of::<SemanticDebt>())
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| {
                path.witness.as_ref().map_or(Some(n), |w| {
                    w.replay_trace
                        .len()
                        .checked_mul(size_of::<DynamicBlock>())
                        .and_then(|m| n.checked_add(m))
                })
            })
            .and_then(|n| n.checked_add(size_of::<PathEvidence>() + size_of::<Digest>()));
        if self.paths.len() >= self.limits.max_paths || !items.is_some_and(|n| n <= self.limits.max_items_per_path) {
            self.storage_rejections = self.storage_rejections.saturating_add(1);
            return Err(EvidenceError::Exhausted);
        }
        self.reserve_bytes(bytes)?;
        self.paths.try_reserve(1).map_err(|_| {
            self.storage_rejections = self.storage_rejections.saturating_add(1);
            EvidenceError::Exhausted
        })?;
        self.bytes += bytes.ok_or(EvidenceError::Exhausted)?;
        self.path_ids.insert(path.path_id);
        self.paths.push(path);
        Ok(())
    }

    pub fn add_frontier(&mut self, work: PendingWork) -> Result<(), EvidenceError> {
        if self.closure.is_some() {
            return Err(EvidenceError::Closed);
        }
        if work.path_id == [0; 32] {
            return Err(EvidenceError::Invalid("frontier identity"));
        }
        if self.frontier_ids.contains(&work.path_id) {
            return Err(EvidenceError::DuplicateFrontier);
        }
        if self.frontier.len() >= self.limits.max_frontier {
            self.storage_rejections = self.storage_rejections.saturating_add(1);
            return Err(EvidenceError::Exhausted);
        }
        self.reserve_bytes(Some(size_of::<PendingWork>() + size_of::<Digest>()))?;
        self.frontier.try_reserve(1).map_err(|_| {
            self.storage_rejections = self.storage_rejections.saturating_add(1);
            EvidenceError::Exhausted
        })?;
        self.frontier_ids.insert(work.path_id);
        self.bytes += size_of::<PendingWork>() + size_of::<Digest>();
        self.frontier.push(work);
        Ok(())
    }

    /// Only a caller that has checked the entire owned subtree should close it.
    pub fn close_owned_scope(&mut self, closure: ScopeClosure) -> Result<(), EvidenceError> {
        if self.closure.is_some() {
            return Err(EvidenceError::Closed);
        }
        if closure.owned_work_units == 0
            || closure.owned_work_units != closure.resolved_work_units
            || self.storage_rejections != 0
            || !self.frontier.is_empty()
            || self.paths.is_empty()
            || self.paths.iter().any(|path| {
                matches!(
                    path.disposition,
                    PathDisposition::Pending(_) | PathDisposition::Failed(_)
                )
            })
        {
            return Err(EvidenceError::Invalid("owned scope not fully resolved"));
        }
        self.closure = Some(closure);
        Ok(())
    }

    pub fn report(&self) -> EvidenceReport<'_> {
        let mut summary = EvidenceSummary {
            schema_version: EVIDENCE_SCHEMA_VERSION,
            scope: self.scope,
            closure: self.closure,
            completion: Completion::Partial,
            terminal_paths: 0,
            excluded_paths: 0,
            infeasible_paths: 0,
            pending_paths: 0,
            failed_paths: 0,
            retained_frontier: self.frontier.len(),
            observed_edges: 0,
            inferred_edges: 0,
            infeasible_edges: 0,
            dynamic_blocks: 0,
            replay_verified_witnesses: 0,
            semantic_debt_records: 0,
            storage_rejections: self.storage_rejections,
        };
        for path in &self.paths {
            match path.disposition {
                PathDisposition::Terminal => summary.terminal_paths += 1,
                PathDisposition::ExcludedByPolicy => summary.excluded_paths += 1,
                PathDisposition::SolverInfeasible => summary.infeasible_paths += 1,
                PathDisposition::Pending(_) => summary.pending_paths += 1,
                PathDisposition::Failed(_) => summary.failed_paths += 1,
            }
            for edge in &path.edges {
                match edge.basis {
                    EdgeBasis::Observed { .. } => summary.observed_edges += 1,
                    EdgeBasis::StaticInference { .. } => summary.inferred_edges += 1,
                    EdgeBasis::SolverInfeasible { .. } => summary.infeasible_edges += 1,
                }
            }
            summary.dynamic_blocks += path.blocks.len();
            summary.semantic_debt_records += path.semantic_debt.len();
            if path
                .witness
                .as_ref()
                .is_some_and(|w| matches!(w.replay, ReplayVerification::Verified { .. }))
            {
                summary.replay_verified_witnesses += 1;
            }
        }
        summary.completion = if summary.storage_rejections > 0
            || summary.failed_paths > 0
            || self.paths.iter().any(|path| {
                matches!(path.disposition, PathDisposition::Pending(_)) && !self.frontier_ids.contains(&path.path_id)
            }) {
            Completion::Failed
        } else if self.frontier.iter().any(|work| {
            matches!(
                work.reason,
                PendingReason::Unknown
                    | PendingReason::Timeout
                    | PendingReason::ResourceLimit
                    | PendingReason::ReplayMismatch
            )
        }) || self.paths.iter().any(|path| {
            matches!(
                path.disposition,
                PathDisposition::Pending(
                    PendingReason::Unknown
                        | PendingReason::Timeout
                        | PendingReason::ResourceLimit
                        | PendingReason::ReplayMismatch
                )
            )
        }) {
            Completion::Blocked
        } else if self.closure.is_some() {
            Completion::CompleteWithinDeclaredBounds
        } else {
            Completion::Partial
        };
        EvidenceReport {
            summary,
            paths: &self.paths,
            frontier: &self.frontier,
        }
    }

    /// Bounded, path-attributed flow from accepted evidence. On resume, the
    /// caller must first authenticate persisted records; this sink is in memory.
    pub fn flow_graph(&self, max_items: usize, max_bytes: usize) -> Result<FlowGraph<'_>, EvidenceError> {
        let blocks = self.paths.iter().try_fold(0usize, |n, p| n.checked_add(p.blocks.len()));
        let edges = self.paths.iter().try_fold(0usize, |n, p| n.checked_add(p.edges.len()));
        let count = blocks
            .and_then(|n| edges.and_then(|m| n.checked_add(m)))
            .and_then(|n| n.checked_add(self.paths.len()))
            .ok_or(EvidenceError::Exhausted)?;
        let bytes = blocks
            .and_then(|n| n.checked_mul(size_of::<FlowBlock>()))
            .and_then(|n| {
                edges.and_then(|m| {
                    m.checked_mul(size_of::<FlowTransition>())
                        .and_then(|m| n.checked_add(m))
                })
            })
            .and_then(|n| {
                self.paths
                    .len()
                    .checked_mul(size_of::<&PathEvidence>())
                    .and_then(|m| n.checked_add(m))
            })
            .ok_or(EvidenceError::Exhausted)?;
        if count > max_items || bytes > max_bytes {
            return Err(EvidenceError::Exhausted);
        }
        let mut block_flow = Vec::new();
        let mut edge_flow = Vec::new();
        block_flow
            .try_reserve_exact(blocks.unwrap_or(0))
            .map_err(|_| EvidenceError::Exhausted)?;
        edge_flow
            .try_reserve_exact(edges.unwrap_or(0))
            .map_err(|_| EvidenceError::Exhausted)?;
        for path in &self.paths {
            for block in &path.blocks {
                block_flow.push(FlowBlock {
                    path_id: path.path_id,
                    block: *block,
                });
            }
            for edge in &path.edges {
                let from_visit_index = match edge.basis {
                    EdgeBasis::Observed { .. } => {
                        let mut visits = path.blocks.iter().filter(|block| block.pc == edge.from_pc);
                        let first = visits.next().map(|block| block.visit_index);
                        // No edge visit in the input: never guess the loop iteration.
                        if visits.next().is_none() { first } else { None }
                    }
                    EdgeBasis::StaticInference { .. } => None,
                    EdgeBasis::SolverInfeasible {
                        predicate_digest,
                        query_digest,
                        result_digest,
                    } => {
                        let mut matches = path.branches.iter().filter(|branch| {
                            branch.pc == edge.from_pc
                                && branch.tested_target == Some(edge.to_pc)
                                && branch.predicate_digest == predicate_digest
                                && branch.query_digest == query_digest
                                && branch.result_digest == Some(result_digest)
                                && branch.disposition == SolverDisposition::Unsat
                        });
                        let first = matches.next().map(|branch| branch.visit_index);
                        if matches.next().is_none() { first } else { None }
                    }
                };
                edge_flow.push(FlowTransition {
                    path_id: path.path_id,
                    from_visit_index,
                    edge: *edge,
                });
            }
        }
        block_flow.sort_by_key(|block| (block.block.pc, block.path_id, block.block.visit_index));
        edge_flow.sort_by_key(|edge| (edge.edge.from_pc, edge.edge.to_pc, edge.path_id, edge.from_visit_index));
        Ok(FlowGraph {
            blocks: block_flow,
            edges: edge_flow,
            paths: &self.paths,
            summary: self.report().summary,
        })
    }
}

/// Paths retain predicate/query/result, witness, debt and disposition; graph
/// entries retain each originating path even where their static PCs converge.
pub struct FlowGraph<'a> {
    pub blocks: Vec<FlowBlock>,
    pub edges: Vec<FlowTransition>,
    pub paths: &'a [PathEvidence],
    pub summary: EvidenceSummary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowBlock {
    pub path_id: Digest,
    pub block: DynamicBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowTransition {
    pub path_id: Digest,
    /// None means an inferred edge or ambiguous repeated source PC, not visit zero.
    pub from_visit_index: Option<u64>,
    pub edge: FlowEdge,
}
