#![forbid(unsafe_code)]

//! Cross-plane contracts for sealed semantic identity and post-seal transformations.
//! This crate defines policy/data boundaries only; it performs no optimization itself.

use angryier_types::{ContentId, FidelityProfile, SemanticFingerprint, SemanticVersion};
use core::fmt::{self, Debug, Display};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EvidenceDigest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransformationId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceLevel {
    Verified,
    SolverChecked,
    DifferentiallyTested,
    Composite,
    Advisory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransformationContract {
    pub preserves_values: bool,
    pub preserves_architectural_side_effects: bool,
    pub preserves_exception_behavior: bool,
    pub preserves_memory_ordering: bool,
    pub preserves_floating_point_behavior: bool,
    pub preserves_masking_behavior: bool,
    pub preserves_target_feature_semantics: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EquivalenceEvidence {
    pub level: EvidenceLevel,
    pub evidence_digest: EvidenceDigest,
}

pub trait SealedSemanticBlock: Debug + Send + Sync {
    fn content_id(&self) -> ContentId;
    fn semantic_fingerprint(&self) -> SemanticFingerprint;
    fn semantic_version(&self) -> SemanticVersion;
}

pub trait DerivedSemanticBlock: SealedSemanticBlock {
    fn parent_content_id(&self) -> ContentId;
    fn transformation_id(&self) -> TransformationId;
    fn contract(&self) -> TransformationContract;
    fn evidence(&self) -> EquivalenceEvidence;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransformationError {
    SourceNotSealed,
    InvalidContract,
    MissingEvidence,
    InsufficientEvidence,
    SemanticVersionMismatch,
    ContentIdentityConflict,
    ValidationFailed,
}

impl Display for TransformationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransformationError::SourceNotSealed => f.write_str("source block is not sealed"),
            TransformationError::InvalidContract => f.write_str("transformation contract is invalid"),
            TransformationError::MissingEvidence => f.write_str("equivalence evidence is missing"),
            TransformationError::InsufficientEvidence => {
                f.write_str("equivalence evidence is insufficient for the requested fidelity")
            }
            TransformationError::SemanticVersionMismatch => {
                f.write_str("semantic version mismatch between source and derived block")
            }
            TransformationError::ContentIdentityConflict => {
                f.write_str("content identity conflict detected during derivation")
            }
            TransformationError::ValidationFailed => f.write_str("transformation validation failed"),
        }
    }
}

pub trait SemanticTransformation: Debug + Send + Sync {
    type Source: SealedSemanticBlock;
    type Output: DerivedSemanticBlock;
    fn id(&self) -> TransformationId;
    fn contract(&self) -> TransformationContract;
    fn derive(&self, source: &Self::Source) -> Result<Self::Output, TransformationError>;
}

pub trait TransformationAcceptancePolicy: Debug + Send + Sync {
    fn accepts(
        &self,
        profile: FidelityProfile,
        contract: &TransformationContract,
        evidence: &EquivalenceEvidence,
    ) -> bool;
}

pub trait ExecutionArtifactSemanticBinding: Debug + Send + Sync {
    fn source_content_id(&self) -> ContentId;
    fn source_semantic_version(&self) -> SemanticVersion;
}

// ---------------------------------------------------------------------------
// In-memory concrete implementations
// ---------------------------------------------------------------------------

/// A simple in-memory [`SealedSemanticBlock`] carrying the three pieces of
/// sealed identity: content id, semantic fingerprint and semantic version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SimpleSealedBlock {
    content_id: ContentId,
    fingerprint: SemanticFingerprint,
    version: SemanticVersion,
}

impl SimpleSealedBlock {
    /// Creates a new `SimpleSealedBlock` from the sealed identity triple.
    pub fn new(content_id: ContentId, fingerprint: SemanticFingerprint, version: SemanticVersion) -> Self {
        Self {
            content_id,
            fingerprint,
            version,
        }
    }

    /// Convenience accessor mirroring the trait method for use without a
    /// trait upcast.
    pub fn fingerprint(&self) -> SemanticFingerprint {
        self.fingerprint
    }
}

impl SealedSemanticBlock for SimpleSealedBlock {
    fn content_id(&self) -> ContentId {
        self.content_id
    }

    fn semantic_fingerprint(&self) -> SemanticFingerprint {
        self.fingerprint
    }

    fn semantic_version(&self) -> SemanticVersion {
        self.version
    }
}

/// An in-memory [`DerivedSemanticBlock`] that records both its own sealed
/// identity and the lineage of the transformation that produced it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DerivedBlock {
    content_id: ContentId,
    fingerprint: SemanticFingerprint,
    version: SemanticVersion,
    parent_content_id: ContentId,
    transformation_id: TransformationId,
    contract: TransformationContract,
    evidence: EquivalenceEvidence,
}

impl DerivedBlock {
    /// Creates a new `DerivedBlock` from all constituent fields.
    pub fn new(
        content_id: ContentId,
        fingerprint: SemanticFingerprint,
        version: SemanticVersion,
        parent_content_id: ContentId,
        transformation_id: TransformationId,
        contract: TransformationContract,
        evidence: EquivalenceEvidence,
    ) -> Self {
        Self {
            content_id,
            fingerprint,
            version,
            parent_content_id,
            transformation_id,
            contract,
            evidence,
        }
    }
}

impl SealedSemanticBlock for DerivedBlock {
    fn content_id(&self) -> ContentId {
        self.content_id
    }

    fn semantic_fingerprint(&self) -> SemanticFingerprint {
        self.fingerprint
    }

    fn semantic_version(&self) -> SemanticVersion {
        self.version
    }
}

impl DerivedSemanticBlock for DerivedBlock {
    fn parent_content_id(&self) -> ContentId {
        self.parent_content_id
    }

    fn transformation_id(&self) -> TransformationId {
        self.transformation_id
    }

    fn contract(&self) -> TransformationContract {
        self.contract
    }

    fn evidence(&self) -> EquivalenceEvidence {
        self.evidence
    }
}

/// The identity transformation: it produces a [`DerivedBlock`] that mirrors
/// the sealed identity of its source. It is the canonical "no-op" derivation
/// used to validate the contract plumbing end-to-end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct IdentityTransformation;

impl IdentityTransformation {
    /// Builds a fully-preserving [`TransformationContract`].
    fn full_preservation_contract() -> TransformationContract {
        TransformationContract {
            preserves_values: true,
            preserves_architectural_side_effects: true,
            preserves_exception_behavior: true,
            preserves_memory_ordering: true,
            preserves_floating_point_behavior: true,
            preserves_masking_behavior: true,
            preserves_target_feature_semantics: true,
        }
    }

    /// A deterministic, non-zero evidence digest for the identity transform.
    fn identity_digest() -> EvidenceDigest {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x49; // 'I'
        bytes[1] = 0x44; // 'D'
        bytes[2] = 0x45; // 'E'
        bytes[3] = 0x4E; // 'N'
        bytes[4] = 0x54; // 'T'
        EvidenceDigest(bytes)
    }
}

impl SemanticTransformation for IdentityTransformation {
    type Source = SimpleSealedBlock;
    type Output = DerivedBlock;

    fn id(&self) -> TransformationId {
        TransformationId(1)
    }

    fn contract(&self) -> TransformationContract {
        Self::full_preservation_contract()
    }

    fn derive(&self, source: &Self::Source) -> Result<Self::Output, TransformationError> {
        let content_id = source.content_id();
        // An all-zero content id indicates the source was never sealed.
        if content_id.0 == [0u8; 32] {
            return Err(TransformationError::SourceNotSealed);
        }

        Ok(DerivedBlock::new(
            content_id,
            source.semantic_fingerprint(),
            source.semantic_version(),
            content_id,
            self.id(),
            self.contract(),
            EquivalenceEvidence {
                level: EvidenceLevel::Verified,
                evidence_digest: Self::identity_digest(),
            },
        ))
    }
}

/// A fidelity-driven acceptance policy that gates transformations on the
/// requested [`FidelityProfile`] combined with the contract and evidence.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FidelityAcceptancePolicy;

impl FidelityAcceptancePolicy {
    /// Returns `true` when every `preserves_*` flag in `contract` is set.
    fn fully_preserves(contract: &TransformationContract) -> bool {
        contract.preserves_values
            && contract.preserves_architectural_side_effects
            && contract.preserves_exception_behavior
            && contract.preserves_memory_ordering
            && contract.preserves_floating_point_behavior
            && contract.preserves_masking_behavior
            && contract.preserves_target_feature_semantics
    }
}

impl TransformationAcceptancePolicy for FidelityAcceptancePolicy {
    fn accepts(
        &self,
        profile: FidelityProfile,
        contract: &TransformationContract,
        evidence: &EquivalenceEvidence,
    ) -> bool {
        match profile {
            FidelityProfile::Prove => evidence.level == EvidenceLevel::Verified && Self::fully_preserves(contract),
            FidelityProfile::Explore => {
                let level_ok = matches!(evidence.level, EvidenceLevel::Verified | EvidenceLevel::SolverChecked);
                level_ok && Self::fully_preserves(contract)
            }
            FidelityProfile::Hunt => {
                // Hunt accepts any evidence level but still requires value
                // preservation as a hard floor.
                contract.preserves_values
            }
        }
    }
}

/// An in-memory [`ExecutionArtifactSemanticBinding`] tying an execution
/// artifact back to its source semantic identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ArtifactBinding {
    content_id: ContentId,
    version: SemanticVersion,
}

impl ArtifactBinding {
    /// Creates a new `ArtifactBinding`.
    pub fn new(content_id: ContentId, version: SemanticVersion) -> Self {
        Self { content_id, version }
    }
}

impl ExecutionArtifactSemanticBinding for ArtifactBinding {
    fn source_content_id(&self) -> ContentId {
        self.content_id
    }

    fn source_semantic_version(&self) -> SemanticVersion {
        self.version
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_types::{ContentId, SemanticFingerprint, SemanticVersion};

    /// Builds a non-zero `ContentId` from a seed byte.
    fn sealed_content_id(seed: u8) -> ContentId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        ContentId(bytes)
    }

    /// Builds a non-zero `SemanticFingerprint` from a seed byte.
    fn sealed_fingerprint(seed: u8) -> SemanticFingerprint {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        SemanticFingerprint(bytes)
    }

    fn full_contract() -> TransformationContract {
        TransformationContract {
            preserves_values: true,
            preserves_architectural_side_effects: true,
            preserves_exception_behavior: true,
            preserves_memory_ordering: true,
            preserves_floating_point_behavior: true,
            preserves_masking_behavior: true,
            preserves_target_feature_semantics: true,
        }
    }

    fn verified_evidence() -> EquivalenceEvidence {
        EquivalenceEvidence {
            level: EvidenceLevel::Verified,
            evidence_digest: EvidenceDigest([1u8; 32]),
        }
    }

    fn solver_checked_evidence() -> EquivalenceEvidence {
        EquivalenceEvidence {
            level: EvidenceLevel::SolverChecked,
            evidence_digest: EvidenceDigest([2u8; 32]),
        }
    }

    fn advisory_evidence() -> EquivalenceEvidence {
        EquivalenceEvidence {
            level: EvidenceLevel::Advisory,
            evidence_digest: EvidenceDigest([3u8; 32]),
        }
    }

    // 1. SealedBlock construction and trait methods.
    #[test]
    fn sealed_block_reports_identity() {
        let cid = sealed_content_id(7);
        let fp = sealed_fingerprint(9);
        let block = SimpleSealedBlock::new(cid, fp, SemanticVersion(3));
        assert_eq!(block.content_id(), cid);
        assert_eq!(block.semantic_fingerprint(), fp);
        assert_eq!(block.semantic_version(), SemanticVersion(3));
    }

    // 2. DerivedBlock construction and trait methods.
    #[test]
    fn derived_block_reports_lineage() {
        let cid = sealed_content_id(11);
        let parent = sealed_content_id(22);
        let fp = sealed_fingerprint(13);
        let contract = full_contract();
        let evidence = verified_evidence();
        let block = DerivedBlock::new(
            cid,
            fp,
            SemanticVersion(5),
            parent,
            TransformationId(42),
            contract,
            evidence,
        );

        // Inherited SealedSemanticBlock methods.
        assert_eq!(block.content_id(), cid);
        assert_eq!(block.semantic_fingerprint(), fp);
        assert_eq!(block.semantic_version(), SemanticVersion(5));
        // DerivedSemanticBlock methods.
        assert_eq!(block.parent_content_id(), parent);
        assert_eq!(block.transformation_id(), TransformationId(42));
        assert_eq!(block.contract(), contract);
        assert_eq!(block.evidence(), evidence);
    }

    // 3. IdentityTransformation derive succeeds for a valid source.
    #[test]
    fn identity_derive_succeeds_for_valid_source() {
        let cid = sealed_content_id(1);
        let fp = sealed_fingerprint(2);
        let source = SimpleSealedBlock::new(cid, fp, SemanticVersion(1));
        let transform = IdentityTransformation;
        let result = transform.derive(&source);
        assert!(result.is_ok());
        if let Ok(derived) = result {
            assert_eq!(derived.content_id(), cid);
            assert_eq!(derived.semantic_fingerprint(), fp);
            assert_eq!(derived.semantic_version(), SemanticVersion(1));
            assert_eq!(derived.parent_content_id(), cid);
            assert_eq!(derived.transformation_id(), TransformationId(1));
            assert_eq!(derived.evidence().level, EvidenceLevel::Verified);
            assert_ne!(derived.evidence().evidence_digest.0, [0u8; 32]);
        }
    }

    // 4. IdentityTransformation derive fails for an unsealed (all-zeros) source.
    #[test]
    fn identity_derive_fails_for_unsealed_source() {
        let source = SimpleSealedBlock::new(ContentId([0u8; 32]), sealed_fingerprint(2), SemanticVersion(1));
        let transform = IdentityTransformation;
        let result = transform.derive(&source);
        assert!(result.is_err());
        if let Err(err) = result {
            assert_eq!(err, TransformationError::SourceNotSealed);
        }
    }

    // 5. IdentityTransformation has the correct contract (all preserves true).
    #[test]
    fn identity_contract_preserves_everything() {
        let transform = IdentityTransformation;
        let contract = transform.contract();
        assert!(contract.preserves_values);
        assert!(contract.preserves_architectural_side_effects);
        assert!(contract.preserves_exception_behavior);
        assert!(contract.preserves_memory_ordering);
        assert!(contract.preserves_floating_point_behavior);
        assert!(contract.preserves_masking_behavior);
        assert!(contract.preserves_target_feature_semantics);
        assert_eq!(transform.id(), TransformationId(1));
    }

    // 6. FidelityAcceptancePolicy Prove accepts Verified + all-preserve.
    #[test]
    fn prove_accepts_verified_full_contract() {
        let policy = FidelityAcceptancePolicy;
        assert!(policy.accepts(FidelityProfile::Prove, &full_contract(), &verified_evidence()));
    }

    // 7. FidelityAcceptancePolicy Prove rejects SolverChecked.
    #[test]
    fn prove_rejects_solver_checked() {
        let policy = FidelityAcceptancePolicy;
        assert!(!policy.accepts(FidelityProfile::Prove, &full_contract(), &solver_checked_evidence()));
    }

    // 8. FidelityAcceptancePolicy Prove rejects missing preservation.
    #[test]
    fn prove_rejects_missing_preservation() {
        let policy = FidelityAcceptancePolicy;
        let mut contract = full_contract();
        contract.preserves_memory_ordering = false;
        assert!(!policy.accepts(FidelityProfile::Prove, &contract, &verified_evidence()));
    }

    // 9. FidelityAcceptancePolicy Explore accepts SolverChecked.
    #[test]
    fn explore_accepts_solver_checked() {
        let policy = FidelityAcceptancePolicy;
        assert!(policy.accepts(FidelityProfile::Explore, &full_contract(), &solver_checked_evidence()));
    }

    // 10. FidelityAcceptancePolicy Explore rejects Advisory.
    #[test]
    fn explore_rejects_advisory() {
        let policy = FidelityAcceptancePolicy;
        assert!(!policy.accepts(FidelityProfile::Explore, &full_contract(), &advisory_evidence()));
    }

    // 11. FidelityAcceptancePolicy Hunt accepts Advisory with preserves_values.
    #[test]
    fn hunt_accepts_advisory_with_preserves_values() {
        let policy = FidelityAcceptancePolicy;
        let mut contract = full_contract();
        contract.preserves_memory_ordering = false;
        contract.preserves_exception_behavior = false;
        // preserves_values still true.
        assert!(policy.accepts(FidelityProfile::Hunt, &contract, &advisory_evidence()));
    }

    // 12. FidelityAcceptancePolicy Hunt rejects when preserves_values is false.
    #[test]
    fn hunt_rejects_when_preserves_values_false() {
        let policy = FidelityAcceptancePolicy;
        let mut contract = full_contract();
        contract.preserves_values = false;
        assert!(!policy.accepts(FidelityProfile::Hunt, &contract, &verified_evidence()));
    }

    // 13. ArtifactBinding returns correct values.
    #[test]
    fn artifact_binding_reports_identity() {
        let cid = sealed_content_id(99);
        let binding = ArtifactBinding::new(cid, SemanticVersion(8));
        assert_eq!(binding.source_content_id(), cid);
        assert_eq!(binding.source_semantic_version(), SemanticVersion(8));
    }

    // 14. TransformationError Display is non-empty for every variant.
    #[test]
    fn transformation_error_display_is_non_empty() {
        let errors = [
            TransformationError::SourceNotSealed,
            TransformationError::InvalidContract,
            TransformationError::MissingEvidence,
            TransformationError::InsufficientEvidence,
            TransformationError::SemanticVersionMismatch,
            TransformationError::ContentIdentityConflict,
            TransformationError::ValidationFailed,
        ];
        for err in errors {
            let rendered = format!("{err}");
            assert!(!rendered.is_empty(), "error display must not be empty");
        }
    }

    // 15. End-to-end: IdentityTransformation output is accepted by Prove policy.
    #[test]
    fn identity_output_is_accepted_by_prove_policy() {
        let cid = sealed_content_id(5);
        let source = SimpleSealedBlock::new(cid, sealed_fingerprint(6), SemanticVersion(2));
        let transform = IdentityTransformation;
        let derived_result = transform.derive(&source);
        assert!(derived_result.is_ok());
        if let Ok(derived) = derived_result {
            let policy = FidelityAcceptancePolicy;
            assert!(policy.accepts(FidelityProfile::Prove, &derived.contract(), &derived.evidence()));
        }
    }
}
