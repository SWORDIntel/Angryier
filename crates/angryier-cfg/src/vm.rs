//! Opt-in VM-dispatch reconnaissance and context-sensitive transition graphs.
//!
//! Ordinary CFGs are keyed only by native PC, which aliases distinct virtual
//! instructions executed by the same VM handler. This module intentionally
//! separates three levels of evidence:
//!
//! * `inspect_native_cfg`: structural candidates, NOT confirmed VM instructions;
//! * `VmAnalysisSession`: observed/symbolically derived handler transitions,
//!   keyed by native PC, virtual PC, state context and executable image version;
//! * `projected_edges`: an explicitly observational virtual CFG projection.
//!
//! The caller must identify handler boundaries and supply trustworthy VPC and
//! context observations. Nothing here guesses a virtual PC from a jump target,
//! fabricates unobserved edges, executes untrusted code or claims full coverage.
//! The existing native CFG recovery remains unchanged.

use std::collections::{BTreeMap, BTreeSet};

use angryier_arch::RegisterId;
use angryier_types::Address;

use crate::themida::{BaseProvenance, DispatchKind, DispatchWindow};
use crate::vpc::{VpcBlock, identify_vpc_candidates};
use crate::{Cfg, EdgeKind};

/// A register-only VPC hypothesis; scores are heuristic, not probabilities.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmVpcCandidate {
    pub register: RegisterId,
    pub confidence: u8,
    pub table_base: Option<Address>,
}

/// Evidence at one native indirect-dispatch site.
#[derive(Clone, Debug)]
pub struct VmDispatchFinding {
    pub block_start: Address,
    pub dispatch_pc: Address,
    pub kind: DispatchKind,
    pub base: Option<(RegisterId, BaseProvenance)>,
    /// A candidate context register, not a proven VM_CONTEXT base.
    pub context_origin: Option<RegisterId>,
    pub vpc_candidates: Vec<VmVpcCandidate>,
}

/// A bounded static scan result. Indirect exits without recognized operands
/// remain unresolved rather than being silently promoted to VM sites.
#[derive(Clone, Debug, Default)]
pub struct VmDispatchReport {
    pub findings: Vec<VmDispatchFinding>,
    pub unresolved_indirect_blocks: usize,
    pub unclassified_indirect_blocks: usize,
}

/// Inspect only unresolved native indirect-jump exits. This does not mutate
/// the CFG or allow heuristic VM findings to become confirmed CFG edges.
pub fn inspect_native_cfg(cfg: &Cfg) -> VmDispatchReport {
    let blocks: Vec<VpcBlock<'_>> = cfg
        .blocks
        .values()
        .filter(|block| block.terminator == EdgeKind::IndirectJump)
        .map(|block| VpcBlock {
            native_pc: block.start,
            instructions: &block.instructions,
        })
        .collect();

    let mut candidate_map: BTreeMap<Address, Vec<VmVpcCandidate>> = BTreeMap::new();
    for candidate in identify_vpc_candidates(&blocks) {
        candidate_map
            .entry(candidate.native_pc)
            .or_default()
            .push(VmVpcCandidate {
                register: candidate.register,
                confidence: candidate.confidence,
                table_base: candidate.table_base,
            });
    }

    let mut report = VmDispatchReport {
        unresolved_indirect_blocks: blocks.len(),
        ..VmDispatchReport::default()
    };
    for block in blocks {
        let Some(site) = (DispatchWindow {
            instructions: block.instructions,
        })
        .classify() else {
            report.unclassified_indirect_blocks += 1;
            continue;
        };

        let origin = match site.base {
            Some((_, BaseProvenance::ContextRegister { source, .. }))
            | Some((_, BaseProvenance::DerivedFrom { source })) => Some(source),
            _ => None,
        };
        report.findings.push(VmDispatchFinding {
            block_start: block.native_pc,
            dispatch_pc: site.native_pc,
            kind: site.kind,
            base: site.base,
            context_origin: origin,
            vpc_candidates: candidate_map.remove(&block.native_pc).unwrap_or_default(),
        });
    }
    report
}

/// Exact replay/capture identity. The caller hashes the relevant VM state
/// and code bytes under a pinned interpretation and records their provenance.
/// The digests are not computed or authenticated by this module.
pub type VmDigest = [u8; 32];

/// Context-sensitive handler location, disambiguating two virtual instructions
/// executed at the same native PC, including different decryption/key states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VmNodeKey {
    pub native_pc: Address,
    pub virtual_pc: Address,
    pub state_digest: VmDigest,
    pub code_digest: VmDigest,
}

/// Where a particular transition came from. Even a symbolic result needs
/// independent validation before being represented as semantic equivalence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmTransitionSource {
    ObservedTrace,
    SymbolicCandidate,
    ValidatedReplay,
}

/// One handler-boundary transition. An observation is not a proof that these
/// are all possible successors; the full state and origin remain significant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmTransition {
    pub from: VmNodeKey,
    pub to: VmNodeKey,
    pub source: VmTransitionSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmAnalysisLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
}

impl Default for VmAnalysisLimits {
    fn default() -> Self {
        Self {
            max_nodes: 100_000,
            max_edges: 200_000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmAnalysisError {
    NodeBudgetExceeded { required: usize, limit: usize },
    EdgeBudgetExceeded { required: usize, limit: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmEdgeEvidence {
    pub observations: u64,
    pub sources: BTreeSet<VmTransitionSource>,
}

/// An aggregated observed edge in a VPC-aware graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmProjectedEdge {
    pub from: (Address, Address),
    pub to: (Address, Address),
    pub observations: u64,
}

/// Accumulates explicit VM transition evidence with fail-closed admission.
/// Budget rejection is atomic: an edge cannot leave orphan nodes behind.
/// The graph is observational even when no budget was exceeded.
pub struct VmAnalysisSession {
    limits: VmAnalysisLimits,
    nodes: BTreeSet<VmNodeKey>,
    edges: BTreeMap<(VmNodeKey, VmNodeKey), VmEdgeEvidence>,
    attempted: u64,
    rejected: u64,
}

impl VmAnalysisSession {
    pub fn new(limits: VmAnalysisLimits) -> Self {
        Self {
            limits,
            nodes: BTreeSet::new(),
            edges: BTreeMap::new(),
            attempted: 0,
            rejected: 0,
        }
    }

    /// Record evidence without modifying existing edges on admission failure.
    pub fn observe(&mut self, transition: VmTransition) -> Result<(), VmAnalysisError> {
        self.attempted = self.attempted.saturating_add(1);
        let key = (transition.from, transition.to);
        if let Some(edge) = self.edges.get_mut(&key) {
            edge.observations = edge.observations.saturating_add(1);
            edge.sources.insert(transition.source);
            return Ok(());
        }

        let new_nodes = usize::from(!self.nodes.contains(&transition.from))
            + usize::from(
                transition.to != transition.from && !self.nodes.contains(&transition.to),
            );
        let required_nodes = self.nodes.len().saturating_add(new_nodes);
        if required_nodes > self.limits.max_nodes {
            self.rejected = self.rejected.saturating_add(1);
            return Err(VmAnalysisError::NodeBudgetExceeded {
                required: required_nodes,
                limit: self.limits.max_nodes,
            });
        }
        let required_edges = self.edges.len().saturating_add(1);
        if required_edges > self.limits.max_edges {
            self.rejected = self.rejected.saturating_add(1);
            return Err(VmAnalysisError::EdgeBudgetExceeded {
                required: required_edges,
                limit: self.limits.max_edges,
            });
        }

        self.nodes.insert(transition.from);
        self.nodes.insert(transition.to);
        self.edges.insert(
            key,
            VmEdgeEvidence {
                observations: 1,
                sources: BTreeSet::from([transition.source]),
            },
        );
        Ok(())
    }

    pub fn nodes(&self) -> &BTreeSet<VmNodeKey> {
        &self.nodes
    }

    pub fn edges(&self) -> &BTreeMap<(VmNodeKey, VmNodeKey), VmEdgeEvidence> {
        &self.edges
    }

    pub fn attempted(&self) -> u64 {
        self.attempted
    }

    pub fn rejected(&self) -> u64 {
        self.rejected
    }

    /// Context-collapsed view for a downstream decompiler. This is a union of
    /// observed possibilities, not a complete CFG or an equivalence proof.
    pub fn projected_edges(&self) -> Vec<VmProjectedEdge> {
        let mut edges: BTreeMap<
            ((Address, Address), (Address, Address)),
            u64,
        > = BTreeMap::new();
        for ((from, to), evidence) in &self.edges {
            let location = (
                (from.native_pc, from.virtual_pc),
                (to.native_pc, to.virtual_pc),
            );
            let count = edges.entry(location).or_default();
            *count = count.saturating_add(evidence.observations);
        }
        edges
            .into_iter()
            .map(|((from, to), observations)| VmProjectedEdge {
                from,
                to,
                observations,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{
        AccessKind, DecodedInstruction, InstructionModifiers, MemoryBase, MemoryOperand,
        Operand, OperandKind, OperandVisibility, RegisterView,
    };
    use angryier_semantics_intel64::forms;
    use crate::{BasicBlock, CfgEdge};

    fn node(native_pc: u64, virtual_pc: u64, state: u8) -> VmNodeKey {
        VmNodeKey {
            native_pc,
            virtual_pc,
            state_digest: [state; 32],
            code_digest: [0xb7; 32],
        }
    }

    #[test]
    fn native_pc_does_not_alias_distinct_virtual_pcs_or_contexts() {
        let mut session = VmAnalysisSession::new(VmAnalysisLimits::default());
        let x = node(0x1000, 0x2000, 1);
        let y = node(0x1000, 0x2001, 1);
        let z = node(0x1000, 0x2000, 2);
        for (from, to) in [(x, y), (y, z), (z, x)] {
            assert_eq!(session.observe(VmTransition {
                from,
                to,
                source: VmTransitionSource::ObservedTrace,
            }), Ok(()));
        }
        assert_eq!(session.nodes().len(), 3);
        assert_eq!(session.edges().len(), 3);
        // Projection collapses only context, not VPC, and stays observational.
        assert_eq!(session.projected_edges().len(), 3);
    }

    #[test]
    fn duplicate_evidence_is_coalesced_without_losing_sources() {
        let mut session = VmAnalysisSession::new(VmAnalysisLimits::default());
        let from = node(0x1000, 0x2000, 1);
        let to = node(0x1100, 0x2005, 2);
        for source in [
            VmTransitionSource::ObservedTrace,
            VmTransitionSource::SymbolicCandidate,
            VmTransitionSource::ValidatedReplay,
        ] {
            assert_eq!(session.observe(VmTransition { from, to, source }), Ok(()));
        }
        let edge = &session.edges()[&(from, to)];
        assert_eq!(edge.observations, 3);
        assert_eq!(edge.sources.len(), 3);
        assert_eq!(session.projected_edges()[0].observations, 3);
    }

    #[test]
    fn budgets_reject_atomically_and_preserve_incompleteness() {
        let mut session = VmAnalysisSession::new(VmAnalysisLimits {
            max_nodes: 2,
            max_edges: 1,
        });
        let x = node(0x1000, 0x2000, 1);
        let y = node(0x1100, 0x2001, 1);
        let z = node(0x1200, 0x2002, 1);
        assert_eq!(session.observe(VmTransition {
            from: x,
            to: y,
            source: VmTransitionSource::ObservedTrace,
        }), Ok(()));
        assert_eq!(
            session.observe(VmTransition {
                from: y,
                to: z,
                source: VmTransitionSource::ObservedTrace,
            }),
            Err(VmAnalysisError::NodeBudgetExceeded { required: 3, limit: 2 })
        );
        assert_eq!(
            session.observe(VmTransition {
                from: y,
                to: x,
                source: VmTransitionSource::ObservedTrace,
            }),
            Err(VmAnalysisError::EdgeBudgetExceeded { required: 2, limit: 1 })
        );
        assert_eq!(session.nodes().len(), 2);
        assert_eq!(session.edges().len(), 1);
        assert_eq!(session.rejected(), 2);
        assert_eq!(session.attempted(), 3);
    }

    fn register(id: u32) -> RegisterView {
        RegisterView::full(RegisterId(id), 64)
    }

    fn register_operand(index: u8, id: u32, access: AccessKind) -> Operand {
        Operand {
            index,
            width_bits: 64,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Register(register(id)),
        }
    }

    #[test]
    fn structural_scan_separates_context_provenance_from_confirmed_vpc() {
        // MOV RBX,R14 / JMP [RBX+38h]: context-table shape, not proof
        // that R14 holds the VM context, and no VPC is identifiable here.
        let memory = Operand {
            index: 0,
            width_bits: 64,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Memory(MemoryOperand {
                memory_index: 0,
                address_width_bits: 64,
                segment: None,
                segment_base: None,
                base: Some(MemoryBase::Register(register(3))),
                index: None,
                scale: 1,
                displacement: 0x38,
                displacement_width_bits: 32,
            }),
        };
        let insns = vec![
            DecodedInstruction {
                address: 0x1000,
                length: 3,
                form_id: forms::MOV_R64_R64,
                features: Vec::new(),
                operands: vec![
                    register_operand(0, 3, AccessKind::Write),
                    register_operand(1, 14, AccessKind::Read),
                ],
                modifiers: InstructionModifiers::default(),
            },
            DecodedInstruction {
                address: 0x1003,
                length: 3,
                form_id: forms::JMP_INDIRECT_MEM64,
                features: Vec::new(),
                operands: vec![memory],
                modifiers: InstructionModifiers::default(),
            },
        ];
        let cfg = Cfg {
            entry: 0x1000,
            blocks: BTreeMap::from([(
                0x1000,
                BasicBlock {
                    start: 0x1000,
                    end: 0x1006,
                    instructions: insns,
                    terminator: EdgeKind::IndirectJump,
                },
            )]),
            edges: vec![CfgEdge {
                from: 0x1003,
                to: None,
                kind: EdgeKind::IndirectJump,
            }],
        };
        let report = inspect_native_cfg(&cfg);
        assert_eq!(report.unresolved_indirect_blocks, 1);
        assert_eq!(report.unclassified_indirect_blocks, 0);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].context_origin, Some(RegisterId(14)));
        assert_eq!(report.findings[0].kind, DispatchKind::ContextTable { disp: 0x38 });
        assert!(report.findings[0].vpc_candidates.is_empty());
    }
}
