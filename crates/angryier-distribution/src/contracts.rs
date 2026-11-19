//! Local-first, versioned ownership contract for sustained exploration.
//!
//! This module describes work, not execution or solver evidence. A split is a
//! structural partition of a *verified* binary fork; the caller must establish
//! satisfiability and durably publish both children before retiring the parent.

use std::collections::HashMap;
use std::fmt;

use angryier_types::FidelityProfile;
use sha2::{Digest as _, Sha256};

pub const CONTRACT_SCHEMA_VERSION: u32 = 1;

/// SHA-256 of artifact bytes, or a domain-separated canonical campaign record.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn matches(self, bytes: &[u8]) -> bool {
        self == Self::of(bytes)
    }

    fn present(self) -> bool {
        self != Self::default()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractError {
    UnsupportedVersion,
    Missing(&'static str),
    Invalid(&'static str),
    Mismatch(&'static str),
    StaleEpoch,
    Overlap,
    UnprovenDisjointness,
}

impl fmt::Display for ContractError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ContractError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedDigest {
    pub name: String,
    pub digest: Digest,
}

/// An artifact supplied by the local loader on create/resume, never a path-only pin.
#[derive(Clone, Copy, Debug)]
pub struct NamedArtifact<'a> {
    pub name: &'a str,
    pub bytes: &'a [u8],
}

/// Bytes that must be available unchanged before a campaign is accepted.
#[derive(Clone, Debug)]
pub struct CampaignArtifacts<'a> {
    pub binary: &'a [u8],
    pub semantic_profile: &'a [u8],
    pub script: &'a [u8],
    pub policy: &'a [u8],
    pub solver_policy: &'a [u8],
    pub inputs: Vec<NamedArtifact<'a>>,
    pub stubs: Vec<NamedArtifact<'a>>,
}

/// Immutable per-campaign resource ceilings; the chosen depth is a policy, not a contract truncation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplorationLimits {
    pub max_steps: u64,
    pub max_path_steps: u64,
    pub max_active_states: u64,
    pub max_path_depth: u64,
    pub max_loop_visits: u64,
    pub max_solver_millis: u64,
    pub max_wall_millis: u64,
    pub max_ram_bytes: u64,
    pub max_disk_bytes: u64,
    pub max_trace_bytes: u64,
}

impl ExplorationLimits {
    fn validate(&self) -> Result<(), ContractError> {
        if [
            self.max_steps,
            self.max_path_steps,
            self.max_active_states,
            self.max_path_depth,
            self.max_loop_visits,
            self.max_solver_millis,
            self.max_wall_millis,
            self.max_ram_bytes,
            self.max_disk_bytes,
            self.max_trace_bytes,
        ]
        .contains(&0)
        {
            return Err(ContractError::Invalid("limits must be positive"));
        }
        Ok(())
    }
}

/// All values contributing to campaign identity. Named artifacts are strictly sorted by name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignSpec {
    pub binary_digest: Digest,
    pub architecture: String,
    pub entry_pc: u64,
    pub semantic_version: String,
    pub semantic_profile_digest: Digest,
    pub script_digest: Digest,
    pub policy_digest: Digest,
    pub inputs: Vec<NamedDigest>,
    pub stubs: Vec<NamedDigest>,
    pub solver_version: String,
    pub solver_policy_digest: Digest,
    pub fidelity: FidelityProfile,
    pub limits: ExplorationLimits,
}

fn validate_named(entries: &[NamedDigest]) -> Result<(), ContractError> {
    let mut last: Option<&str> = None;
    for entry in entries {
        if entry.name.is_empty() || !entry.digest.present() || last.is_some_and(|prev| prev >= entry.name.as_str()) {
            return Err(ContractError::Invalid("named artifact order, name or digest"));
        }
        last = Some(&entry.name);
    }
    Ok(())
}

fn add_bytes(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

fn add_named(hash: &mut Sha256, entries: &[NamedDigest]) {
    hash.update((entries.len() as u64).to_le_bytes());
    for entry in entries {
        add_bytes(hash, entry.name.as_bytes());
        hash.update(entry.digest.0);
    }
}

impl CampaignSpec {
    fn validate(&self) -> Result<(), ContractError> {
        if self.architecture.is_empty() || self.semantic_version.is_empty() || self.solver_version.is_empty() {
            return Err(ContractError::Missing("architecture or semantic/solver version"));
        }
        if [
            self.binary_digest,
            self.semantic_profile_digest,
            self.script_digest,
            self.policy_digest,
            self.solver_policy_digest,
        ]
        .iter()
        .any(|digest| !digest.present())
        {
            return Err(ContractError::Missing("required artifact digest"));
        }
        validate_named(&self.inputs)?;
        validate_named(&self.stubs)?;
        self.limits.validate()
    }

    fn digest(&self) -> Digest {
        let mut hash = Sha256::new();
        hash.update(b"ANGRYIER\0SUSTAINED-CAMPAIGN\0");
        hash.update(CONTRACT_SCHEMA_VERSION.to_le_bytes());
        hash.update(self.binary_digest.0);
        add_bytes(&mut hash, self.architecture.as_bytes());
        hash.update(self.entry_pc.to_le_bytes());
        add_bytes(&mut hash, self.semantic_version.as_bytes());
        hash.update(self.semantic_profile_digest.0);
        hash.update(self.script_digest.0);
        hash.update(self.policy_digest.0);
        add_named(&mut hash, &self.inputs);
        add_named(&mut hash, &self.stubs);
        add_bytes(&mut hash, self.solver_version.as_bytes());
        hash.update(self.solver_policy_digest.0);
        hash.update([match self.fidelity {
            FidelityProfile::Prove => 0,
            FidelityProfile::Explore => 1,
            FidelityProfile::Hunt => 2,
        }]);
        for limit in [
            self.limits.max_steps,
            self.limits.max_path_steps,
            self.limits.max_active_states,
            self.limits.max_path_depth,
            self.limits.max_loop_visits,
            self.limits.max_solver_millis,
            self.limits.max_wall_millis,
            self.limits.max_ram_bytes,
            self.limits.max_disk_bytes,
            self.limits.max_trace_bytes,
        ] {
            hash.update(limit.to_le_bytes());
        }
        Digest(hash.finalize().into())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignManifest {
    pub schema_version: u32,
    pub campaign_digest: Digest,
    pub spec: CampaignSpec,
}

impl CampaignManifest {
    /// Seal an explicit, complete specification; zero is never an implicit/default limit.
    pub fn seal(spec: CampaignSpec) -> Result<Self, ContractError> {
        spec.validate()?;
        let campaign_digest = spec.digest();
        Ok(Self {
            schema_version: CONTRACT_SCHEMA_VERSION,
            campaign_digest,
            spec,
        })
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedVersion);
        }
        self.spec.validate()?;
        if self.campaign_digest != self.spec.digest() {
            return Err(ContractError::Mismatch("campaign digest"));
        }
        Ok(())
    }

    /// Reject a changed campaign even if the supplied record has a valid self-digest.
    pub fn validate_resume(&self, expected: &Self) -> Result<(), ContractError> {
        self.validate()?;
        expected.validate()?;
        if self.campaign_digest != expected.campaign_digest {
            return Err(ContractError::Mismatch("campaign identity"));
        }
        Ok(())
    }

    /// Check the actual bytes at the local boundary, including complete named input/stub sets.
    pub fn validate_artifacts(&self, artifacts: &CampaignArtifacts<'_>) -> Result<(), ContractError> {
        self.validate()?;
        for (name, actual, expected) in [
            ("binary", artifacts.binary, self.spec.binary_digest),
            (
                "semantic profile",
                artifacts.semantic_profile,
                self.spec.semantic_profile_digest,
            ),
            ("script", artifacts.script, self.spec.script_digest),
            ("policy", artifacts.policy, self.spec.policy_digest),
            ("solver policy", artifacts.solver_policy, self.spec.solver_policy_digest),
        ] {
            if actual.is_empty() {
                return Err(ContractError::Missing(name));
            }
            if !expected.matches(actual) {
                return Err(ContractError::Mismatch(name));
            }
        }
        check_named_bytes(&self.spec.inputs, &artifacts.inputs, "inputs")?;
        check_named_bytes(&self.spec.stubs, &artifacts.stubs, "stubs")
    }
}

fn check_named_bytes(
    expected: &[NamedDigest],
    actual: &[NamedArtifact<'_>],
    category: &'static str,
) -> Result<(), ContractError> {
    if actual.len() < expected.len() {
        return Err(ContractError::Missing(category));
    }
    if actual.len() != expected.len() {
        return Err(ContractError::Mismatch(category));
    }
    for (pin, bytes) in expected.iter().zip(actual) {
        if pin.name != bytes.name {
            return Err(ContractError::Mismatch(category));
        }
        if !pin.digest.matches(bytes.bytes) {
            return Err(ContractError::Mismatch(category));
        }
    }
    Ok(())
}

/// Exact dynamic fork site and symbolic replay context, before choosing an edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchPoint {
    pub branch_pc: u64,
    /// Zero-based exact visit number at this branch PC; never inferred from a truncated trace.
    pub visit_index: u64,
    pub false_target: u64,
    pub true_target: u64,
    pub prefix_constraints: u64,
    pub trace_digest: Digest,
    pub predicate_digest: Digest,
}

impl BranchPoint {
    fn validate(&self) -> Result<(), ContractError> {
        if !self.trace_digest.present() || !self.predicate_digest.present() {
            return Err(ContractError::Missing("branch replay context"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Successor {
    False,
    True,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchDecision {
    pub branch: BranchPoint,
    pub successor: Successor,
}

impl BranchDecision {
    pub fn target(&self) -> u64 {
        match self.successor {
            Successor::False => self.branch.false_target,
            Successor::True => self.branch.true_target,
        }
    }
}

fn validate_prefix(prefix: &[BranchDecision]) -> Result<(), ContractError> {
    let mut visits = HashMap::new();
    let mut previous_constraints = 0;
    for decision in prefix {
        decision.branch.validate()?;
        if visits
            .insert(decision.branch.branch_pc, decision.branch.visit_index)
            .is_some_and(|last| last >= decision.branch.visit_index)
        {
            return Err(ContractError::Invalid(
                "branch visit index must increase at repeated PC",
            ));
        }
        if decision.branch.prefix_constraints < previous_constraints {
            return Err(ContractError::Invalid("constraint prefix cannot decrease"));
        }
        previous_constraints = decision.branch.prefix_constraints;
    }
    Ok(())
}

/// Ownership of every path extending the entire ordered dynamic prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkUnit {
    pub schema_version: u32,
    pub campaign_digest: Digest,
    pub contract_epoch: u64,
    pub prefix: Vec<BranchDecision>,
}

impl WorkUnit {
    pub fn root(manifest: &CampaignManifest, contract_epoch: u64) -> Result<Self, ContractError> {
        manifest.validate()?;
        if contract_epoch == 0 {
            return Err(ContractError::Invalid("zero contract epoch"));
        }
        Ok(Self {
            schema_version: CONTRACT_SCHEMA_VERSION,
            campaign_digest: manifest.campaign_digest,
            contract_epoch,
            prefix: Vec::new(),
        })
    }

    pub fn validate(&self, manifest: &CampaignManifest, active_epoch: u64) -> Result<(), ContractError> {
        manifest.validate()?;
        if self.schema_version != CONTRACT_SCHEMA_VERSION {
            return Err(ContractError::UnsupportedVersion);
        }
        if self.campaign_digest != manifest.campaign_digest {
            return Err(ContractError::Mismatch("work campaign"));
        }
        if active_epoch == 0 || self.contract_epoch != active_epoch {
            return Err(ContractError::StaleEpoch);
        }
        if u64::try_from(self.prefix.len()).map_err(|_| ContractError::Invalid("prefix depth overflow"))?
            > manifest.spec.limits.max_path_depth
        {
            return Err(ContractError::Invalid("prefix exceeds declared depth"));
        }
        validate_prefix(&self.prefix)
    }

    /// Generate a binary partition, excluding other currently owned subtrees.
    /// This does not decide whether either child is feasible or publish a ledger transition.
    pub fn split(
        &self,
        manifest: &CampaignManifest,
        active_epoch: u64,
        fork: BranchPoint,
        other_owned: &[WorkUnit],
    ) -> Result<(Self, Self), ContractError> {
        self.validate(manifest, active_epoch)?;
        fork.validate()?;
        for other in other_owned {
            other.validate(manifest, active_epoch)?;
            check_disjoint(self, other)?;
        }
        let make_child = |successor| {
            let mut child = self.clone();
            child.prefix.push(BranchDecision {
                branch: fork.clone(),
                successor,
            });
            child
        };
        let children = (make_child(Successor::False), make_child(Successor::True));
        validate_split(self, &children.0, &children.1, manifest, active_epoch)?;
        for other in other_owned {
            check_disjoint(&children.0, other)?;
            check_disjoint(&children.1, other)?;
        }
        Ok(children)
    }
}

/// Validate a previously recorded split: both exactly one step below the parent,
/// with identical fork context and complementary edges (so the two cover the parent).
pub fn validate_split(
    parent: &WorkUnit,
    false_child: &WorkUnit,
    true_child: &WorkUnit,
    manifest: &CampaignManifest,
    active_epoch: u64,
) -> Result<(), ContractError> {
    for unit in [parent, false_child, true_child] {
        unit.validate(manifest, active_epoch)?;
    }
    let depth = parent.prefix.len();
    let false_edge = false_child
        .prefix
        .get(depth)
        .ok_or(ContractError::Invalid("missing false edge"))?;
    let true_edge = true_child
        .prefix
        .get(depth)
        .ok_or(ContractError::Invalid("missing true edge"))?;
    if false_child.prefix.len() != depth + 1
        || true_child.prefix.len() != depth + 1
        || false_child.prefix[..depth] != parent.prefix
        || true_child.prefix[..depth] != parent.prefix
        || false_edge.branch != true_edge.branch
        || false_edge.successor != Successor::False
        || true_edge.successor != Successor::True
    {
        return Err(ContractError::Invalid(
            "split must cover parent with complementary fork edges",
        ));
    }
    Ok(())
}

fn check_disjoint(a: &WorkUnit, b: &WorkUnit) -> Result<(), ContractError> {
    for (left, right) in a.prefix.iter().zip(&b.prefix) {
        if left != right {
            return if left.branch == right.branch && left.successor != right.successor {
                Ok(())
            } else {
                Err(ContractError::UnprovenDisjointness)
            };
        }
    }
    Err(ContractError::Overlap)
}

/// Node of the transient ownership trie. Every path through a node resolves
/// the *same* [`BranchPoint`] at this depth, so the only legal divergence is
/// the two successor slots of that one fork: opposite edges of the same branch.
#[derive(Default)]
struct OwnedTrieNode {
    /// Fork resolved at this depth; `None` while the node has no children.
    branch: Option<BranchPoint>,
    /// Children for [`Successor::False`] and [`Successor::True`].
    children: [Option<usize>; 2],
    /// A unit's prefix ends exactly here.
    terminal: bool,
}

/// Transient index of owned prefixes, linear in their total length.
struct OwnedTrie {
    nodes: Vec<OwnedTrieNode>,
}

impl OwnedTrie {
    fn new() -> Self {
        Self {
            nodes: vec![OwnedTrieNode::default()],
        }
    }

    /// Insert one validated prefix. Errors replicate the pairwise
    /// [`check_disjoint`] outcome against every previously inserted unit: the
    /// first divergence must be opposite successors of the same branch, and
    /// no path may be a prefix of another.
    fn insert(&mut self, prefix: &[BranchDecision]) -> Result<(), ContractError> {
        let mut node_index = 0usize;
        for decision in prefix {
            let slot = match decision.successor {
                Successor::False => 0,
                Successor::True => 1,
            };
            let (terminal, same_branch, child) = {
                let node = &self.nodes[node_index];
                (
                    node.terminal,
                    node.branch.as_ref() == Some(&decision.branch),
                    node.children[slot],
                )
            };
            if terminal {
                // A previously owned unit ends here: its prefix is an ancestor
                // of this one, so the two own overlapping path sets.
                return Err(ContractError::Overlap);
            }
            match child {
                Some(next) => {
                    if !same_branch {
                        return Err(ContractError::UnprovenDisjointness);
                    }
                    node_index = next;
                }
                None => {
                    // First unit on this edge. If the opposite edge is taken,
                    // this is a divergence, proven only by the same fork.
                    if self.nodes[node_index].children[1 - slot].is_some() && !same_branch {
                        return Err(ContractError::UnprovenDisjointness);
                    }
                    self.nodes[node_index].branch = Some(decision.branch.clone());
                    let next = self.nodes.len();
                    self.nodes[node_index].children[slot] = Some(next);
                    self.nodes.push(OwnedTrieNode::default());
                    node_index = next;
                }
            }
        }
        let end = &self.nodes[node_index];
        if end.terminal || end.children.iter().any(Option::is_some) {
            // Duplicate path, or this unit is an ancestor of an owned unit.
            return Err(ContractError::Overlap);
        }
        self.nodes[node_index].terminal = true;
        Ok(())
    }
}

/// Accept only prefix-free ownership whose first divergence proves opposite
/// outcomes of the *same* dynamic fork. Distinct context is not proof of disjointness.
///
/// Validation is linear in the total prefix length: a transient trie replaces
/// pairwise comparisons, so large owned frontiers stay feasible.
pub fn validate_owned(units: &[WorkUnit], manifest: &CampaignManifest, active_epoch: u64) -> Result<(), ContractError> {
    let mut trie = OwnedTrie::new();
    for unit in units {
        unit.validate(manifest, active_epoch)?;
        trie.insert(&unit.prefix)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    const EPOCH: u64 = 7;

    fn manifest() -> Result<CampaignManifest, ContractError> {
        CampaignManifest::seal(CampaignSpec {
            binary_digest: Digest::of(b"binary"),
            architecture: "x86_64".into(),
            entry_pc: 0x1000,
            semantic_version: "engine-1".into(),
            semantic_profile_digest: Digest::of(b"profile"),
            script_digest: Digest::of(b"script"),
            policy_digest: Digest::of(b"policy"),
            inputs: vec![NamedDigest {
                name: "stdin".into(),
                digest: Digest::of(b"input"),
            }],
            stubs: vec![NamedDigest {
                name: "stub".into(),
                digest: Digest::of(b"stub bytes"),
            }],
            solver_version: "z3".into(),
            solver_policy_digest: Digest::of(b"solver"),
            fidelity: FidelityProfile::Prove,
            limits: ExplorationLimits {
                max_steps: 100_000,
                max_path_steps: 100_000,
                max_active_states: 2,
                max_path_depth: 10_000,
                max_loop_visits: 100_000,
                max_solver_millis: 10_000,
                max_wall_millis: 10_000,
                max_ram_bytes: 1_000_000,
                max_disk_bytes: 1_000_000,
                max_trace_bytes: 1_000_000,
            },
        })
    }

    fn fork(pc: u64) -> BranchPoint {
        BranchPoint {
            branch_pc: pc,
            visit_index: 0,
            false_target: pc + 4,
            true_target: pc + 8,
            prefix_constraints: 0,
            trace_digest: Digest::of(&pc.to_le_bytes()),
            predicate_digest: Digest::of(&(pc ^ 0x5a5a).to_le_bytes()),
        }
    }

    fn decision(pc: u64, successor: Successor) -> BranchDecision {
        BranchDecision {
            branch: fork(pc),
            successor,
        }
    }

    fn unit(prefix: Vec<BranchDecision>, manifest: &CampaignManifest) -> WorkUnit {
        WorkUnit {
            schema_version: CONTRACT_SCHEMA_VERSION,
            campaign_digest: manifest.campaign_digest,
            contract_epoch: EPOCH,
            prefix,
        }
    }

    /// The former quadratic implementation, kept as the reference oracle.
    fn legacy_validate_owned(
        units: &[WorkUnit],
        manifest: &CampaignManifest,
        active_epoch: u64,
    ) -> Result<(), ContractError> {
        for (index, unit) in units.iter().enumerate() {
            unit.validate(manifest, active_epoch)?;
            for previous in &units[..index] {
                check_disjoint(previous, unit)?;
            }
        }
        Ok(())
    }

    /// Deterministic splitmix64 so randomized differentials reproduce.
    struct SplitMix(u64);

    impl SplitMix {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    #[test]
    fn trie_rejects_mismatched_fork_identities() -> Result<(), ContractError> {
        let m = manifest()?;
        let left = unit(vec![decision(0x2000, Successor::False)], &m);
        let right = unit(vec![decision(0x2000, Successor::True)], &m);
        assert_eq!(validate_owned(&[left.clone(), right.clone()], &m, EPOCH), Ok(()));
        // A third edge at the same node: same successor as `left`, but a
        // different fork (different PC) proves nothing.
        let different_pc = unit(vec![decision(0x2100, Successor::False)], &m);
        assert_eq!(
            validate_owned(&[left.clone(), right.clone(), different_pc], &m, EPOCH),
            Err(ContractError::UnprovenDisjointness)
        );
        // Same PC with a different visit index and replay digest is still a
        // different fork, not a proof of disjointness.
        let mut same_pc_other_visit = left.clone();
        same_pc_other_visit.prefix[0].branch.visit_index = 1;
        same_pc_other_visit.prefix[0].branch.trace_digest = Digest::of(b"other trace");
        assert_eq!(
            validate_owned(&[left.clone(), same_pc_other_visit], &m, EPOCH),
            Err(ContractError::UnprovenDisjointness)
        );
        // Mismatched fork buried below a shared two-decision prefix: only the
        // first divergence matters, and it must be opposite successors of the
        // same branch.
        let shared = || vec![decision(0x3000, Successor::False), decision(0x3008, Successor::True)];
        let deep_false = unit(
            {
                let mut prefix = shared();
                prefix.push(decision(0x3010, Successor::False));
                prefix
            },
            &m,
        );
        let deep_true = unit(
            {
                let mut prefix = shared();
                prefix.push(decision(0x3010, Successor::True));
                prefix
            },
            &m,
        );
        let deep_other_fork = unit(
            {
                let mut prefix = shared();
                prefix.push(decision(0x3020, Successor::False));
                prefix
            },
            &m,
        );
        assert_eq!(
            validate_owned(&[deep_false.clone(), deep_true.clone()], &m, EPOCH),
            Ok(())
        );
        assert_eq!(
            validate_owned(&[deep_false, deep_true, deep_other_fork], &m, EPOCH),
            Err(ContractError::UnprovenDisjointness)
        );
        // Opposite successor of a *different* fork is equally unproven.
        let right_other_fork = unit(vec![decision(0x2200, Successor::True)], &m);
        assert_eq!(
            validate_owned(&[left, right, right_other_fork], &m, EPOCH),
            Err(ContractError::UnprovenDisjointness)
        );
        Ok(())
    }

    #[test]
    fn trie_rejects_duplicate_paths_and_prefix_ancestry() -> Result<(), ContractError> {
        let m = manifest()?;
        let base = unit(
            vec![decision(0x4000, Successor::False), decision(0x4008, Successor::True)],
            &m,
        );
        let sibling = unit(
            vec![decision(0x4000, Successor::False), decision(0x4008, Successor::False)],
            &m,
        );
        assert_eq!(validate_owned(&[base.clone(), sibling.clone()], &m, EPOCH), Ok(()));
        // An exact duplicate is rejected even with a valid unit in between.
        assert_eq!(
            validate_owned(&[base.clone(), sibling, base.clone()], &m, EPOCH),
            Err(ContractError::Overlap)
        );
        let mut descendant = base.clone();
        descendant.prefix.push(decision(0x4010, Successor::False));
        // Ancestor-before-descendant and descendant-before-ancestor overlap.
        assert_eq!(
            validate_owned(&[base.clone(), descendant.clone()], &m, EPOCH),
            Err(ContractError::Overlap)
        );
        assert_eq!(
            validate_owned(&[descendant, base.clone()], &m, EPOCH),
            Err(ContractError::Overlap)
        );
        // The root owns every path, so it overlaps any other unit.
        let root = unit(Vec::new(), &m);
        assert_eq!(validate_owned(&[root, base], &m, EPOCH), Err(ContractError::Overlap));
        Ok(())
    }

    #[test]
    fn trie_matches_pairwise_oracle_on_randomized_ownership_sets() -> Result<(), ContractError> {
        let m = manifest()?;
        let mut rng = SplitMix(0x1CEB_00DA_BA5E_BA11);
        let branches: Vec<BranchPoint> = (0..6u64).map(|i| fork(0x5000 + i * 16)).collect();
        for round in 0..2000 {
            let unit_count = 1 + rng.below(14) as usize;
            let mut units: Vec<WorkUnit> = Vec::with_capacity(unit_count + 1);
            if rng.next().is_multiple_of(2) {
                // Valid family: one shared branch per depth, so first
                // divergences are real forks and many sets validate.
                let max_depth = 1 + rng.below(6);
                for _ in 0..unit_count {
                    let depth = rng.below(max_depth + 1) as usize;
                    let mut prefix = Vec::with_capacity(depth);
                    for branch in branches.iter().take(depth) {
                        prefix.push(BranchDecision {
                            branch: branch.clone(),
                            successor: if rng.next().is_multiple_of(2) {
                                Successor::False
                            } else {
                                Successor::True
                            },
                        });
                    }
                    units.push(unit(prefix, &m));
                }
            } else {
                for _ in 0..unit_count {
                    let depth = rng.below(6) as usize;
                    let mut prefix = Vec::with_capacity(depth);
                    for _ in 0..depth {
                        prefix.push(BranchDecision {
                            branch: branches[rng.below(branches.len() as u64) as usize].clone(),
                            successor: if rng.next().is_multiple_of(2) {
                                Successor::False
                            } else {
                                Successor::True
                            },
                        });
                    }
                    units.push(unit(prefix, &m));
                }
                // Inject an exact duplicate to exercise overlap paths.
                if rng.next().is_multiple_of(3) {
                    units.push(units[rng.below(units.len() as u64) as usize].clone());
                }
            }
            assert_eq!(
                validate_owned(&units, &m, EPOCH),
                legacy_validate_owned(&units, &m, EPOCH),
                "round {round}"
            );
        }
        Ok(())
    }

    #[test]
    fn trie_validates_over_ten_thousand_owned_prefixes() -> Result<(), ContractError> {
        let m = manifest()?;
        const DEPTH: usize = 14;
        const UNIT_COUNT: usize = 1 << DEPTH;
        let branches: Vec<BranchPoint> = (0..DEPTH as u64).map(|level| fork(0x6000 + level * 8)).collect();
        let mut units: Vec<WorkUnit> = Vec::with_capacity(UNIT_COUNT);
        for index in 0..UNIT_COUNT {
            let mut prefix = Vec::with_capacity(DEPTH);
            for (level, branch) in branches.iter().enumerate() {
                prefix.push(BranchDecision {
                    branch: branch.clone(),
                    successor: if (index >> level) & 1 == 0 {
                        Successor::False
                    } else {
                        Successor::True
                    },
                });
            }
            units.push(unit(prefix, &m));
        }
        // All leaves of a complete binary fork tree are pairwise provably
        // disjoint and none is a prefix of another.
        let started = Instant::now();
        assert_eq!(validate_owned(&units, &m, EPOCH), Ok(()));
        let elapsed = started.elapsed();
        let decisions: usize = units.iter().map(|u| u.prefix.len()).sum();
        println!("validate_owned: {UNIT_COUNT} units, {decisions} decisions in {elapsed:?}");
        assert!(elapsed.as_secs() < 10, "linear trie pass too slow: {elapsed:?}");
        Ok(())
    }
}
