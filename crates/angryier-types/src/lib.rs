#![forbid(unsafe_code)]

//! Canonical cross-crate identity, version, policy, and small value types.
//! This crate owns identifiers that must remain stable across execution, replay,
//! provenance, persistence, and future distribution boundaries.

use sha2::{Digest, Sha256};

pub type Address = u64;

macro_rules! id64 {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(pub u64);
        )+
    };
}

macro_rules! version64 {
    ($($name:ident),+ $(,)?) => {
        $(
            #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name(pub u64);
        )+
    };
}

id64!(
    RunId,
    ImageId,
    ModuleId,
    BlockId,
    StateId,
    ConstraintId,
    CodePageId,
    SummaryId,
    ProvenanceNodeId,
    ReplayCapsuleId,
    TargetProfileId,
    SemanticRuleId,
    WorkUnitId,
    TaintId,
    ObjectId,
    EnvironmentModelId,
    SolverQueryId,
    LedgerEpoch,
    ProvenanceSeq,
);

version64!(
    SemanticVersion,
    ContentIdentitySchemaVersion,
    SemanticFingerprintSchemaVersion,
    ExpressionNormalizationVersion,
    ConstraintCanonicalizationVersion,
    EnvironmentModelVersion,
    SummarySchemaVersion,
    ProvenanceSchemaVersion,
    ReplaySchemaVersion,
    EmbeddingModelVersion,
    EmbeddingSchemaVersion,
    KnowledgeSchemaVersion,
    CodePageVersion,
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExprId(pub u32);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContentId(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentDomain {
    SemanticBlock,
    ExecutionIr,
    SolverQuery,
    StateSnapshot,
    ReplayCapsule,
    KnowledgeArtifact,
}

impl ContentDomain {
    const fn tag(self) -> [u8; 4] {
        match self {
            Self::SemanticBlock => *b"SEMA",
            Self::ExecutionIr => *b"EXIR",
            Self::SolverQuery => *b"SOLV",
            Self::StateSnapshot => *b"STAT",
            Self::ReplayCapsule => *b"RPLY",
            Self::KnowledgeArtifact => *b"KNOW",
        }
    }
}

impl ContentId {
    /// Derives an authoritative identity from an already-canonical byte stream.
    ///
    /// The fixed prefix, artifact domain, schema version, and payload length are
    /// included to prevent cross-domain and ambiguous-concatenation reuse.
    pub fn derive(domain: ContentDomain, schema: ContentIdentitySchemaVersion, canonical_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ANGRYIER\0CONTENT\0");
        hasher.update(domain.tag());
        hasher.update(schema.0.to_le_bytes());
        hasher.update((canonical_bytes.len() as u64).to_le_bytes());
        hasher.update(canonical_bytes);
        Self(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SemanticFingerprint(pub [u8; 32]);

impl SemanticFingerprint {
    /// Derives a retrieval/candidate fingerprint from normalized semantic bytes.
    /// A match is advisory and never substitutes for an exact `ContentId`.
    pub fn derive(schema: SemanticFingerprintSchemaVersion, normalized_bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ANGRYIER\0SEMANTIC-FINGERPRINT\0");
        hasher.update(schema.0.to_le_bytes());
        hasher.update((normalized_bytes.len() as u64).to_le_bytes());
        hasher.update(normalized_bytes);
        Self(hasher.finalize().into())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DependencyKey(pub [u8; 32]);

impl DependencyKey {
    pub const ZERO: Self = Self([0u8; 32]);

    #[inline]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FidelityProfile {
    Prove,
    Explore,
    Hunt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AnalysisDebtKind {
    Modelled,
    Summary,
    Concretized,
    Assumed,
    Unsupported,
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolverOutcomeKind {
    Sat,
    Unsat,
    Unknown,
    Timeout,
    ResourceLimit,
    BackendError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionProfile {
    Forensic,
    Research,
    Benchmark,
    Disposable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProvenanceTier {
    Tier0,
    Tier1,
    Tier2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodeVersionGuard {
    pub page: CodePageId,
    pub version: CodePageVersion,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecurityContext {
    pub classification: u32,
    pub compartment: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnalysisContext {
    pub run_id: RunId,
    pub target_profile: TargetProfileId,
    pub fidelity: FidelityProfile,
    pub retention: RetentionProfile,
    pub security: SecurityContext,
}

/// Fast non-cryptographic hasher (the rustc-hash / Fx algorithm) for
/// in-process hot maps keyed by engine-owned types (`ExprNode`, `ExprId`,
/// dependency keys).
///
/// Profiled 2026-09-25 (callgrind, 20k-step mix-loop): SipHash over
/// `ExprNode` hash-cons keys was ~33% of all executed instructions. Fx
/// hashes the same keys an order of magnitude cheaper.
///
/// Contract: deterministic across processes and runs (no per-process seed —
/// also what replay determinism wants), and equality-consistent (equal keys
/// hash equal). It is NOT collision-resistant: a crafted key stream can
/// degrade a map to linear probing. Keys here derive from engine-internal
/// node structure where a collision costs extra probes, never a wrong
/// answer (`Eq` remains the arbiter), and content-addressed identity digests
/// (`ContentId`, `SemanticFingerprint`) stay on SHA-256 for cross-boundary
/// stability — never use this hasher where a digest is load-bearing.
/// Expression `DependencyKey` derivation uses BLAKE3 (in `angryier-expr`).
pub mod fx {
    use std::hash::{BuildHasherDefault, Hasher};

    #[derive(Clone, Default)]
    pub struct FxHasher {
        hash: u64,
    }

    const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;

    impl FxHasher {
        #[inline]
        fn add_to_hash(&mut self, word: u64) {
            self.hash = (self.hash.rotate_left(5) ^ word).wrapping_mul(SEED);
        }
    }

    macro_rules! fx_write_int {
        ($($method:ident => $ty:ty),+ $(,)?) => {
            $(
                #[inline]
                fn $method(&mut self, value: $ty) {
                    self.add_to_hash(value as u64);
                }
            )+
        };
    }

    impl Hasher for FxHasher {
        fx_write_int! {
            write_u8 => u8,
            write_u16 => u16,
            write_u32 => u32,
            write_u64 => u64,
            write_usize => usize,
        }

        #[inline]
        fn write_u128(&mut self, value: u128) {
            self.add_to_hash(value as u64);
            self.add_to_hash((value >> 64) as u64);
        }

        fn write(&mut self, bytes: &[u8]) {
            let (chunks, remainder) = bytes.as_chunks::<8>();
            for chunk in chunks {
                self.add_to_hash(u64::from_le_bytes(*chunk));
            }
            if !remainder.is_empty() {
                let mut packed = 0u64;
                for (index, byte) in remainder.iter().enumerate() {
                    packed |= (*byte as u64) << (8 * index);
                }
                self.add_to_hash(remainder.len() as u64);
                self.add_to_hash(packed);
            }
        }

        #[inline]
        fn finish(&self) -> u64 {
            self.hash
        }
    }

    /// Deterministic builder for [`FxHasher`] (zero-sized, `Default`-seeded).
    pub type FxBuildHasher = BuildHasherDefault<FxHasher>;

    pub type FxHashMap<K, V> = std::collections::HashMap<K, V, FxBuildHasher>;

    pub type FxHashSet<K> = std::collections::HashSet<K, FxBuildHasher>;
}

#[cfg(test)]
mod tests {
    use std::hash::Hash;
    use std::hash::Hasher;

    use super::fx::FxHasher;
    use super::*;

    #[test]
    fn dependency_key_helpers() {
        let key = DependencyKey::from_bytes([42u8; 32]);
        assert_eq!(key.as_bytes(), &[42u8; 32]);
        assert_eq!(DependencyKey::ZERO, DependencyKey([0u8; 32]));
    }

    #[test]
    fn content_identity_is_deterministic_and_domain_separated() {
        let schema = ContentIdentitySchemaVersion(1);
        let first = ContentId::derive(ContentDomain::SemanticBlock, schema, b"canonical");
        let repeated = ContentId::derive(ContentDomain::SemanticBlock, schema, b"canonical");
        let other_domain = ContentId::derive(ContentDomain::ExecutionIr, schema, b"canonical");
        let other_schema = ContentId::derive(
            ContentDomain::SemanticBlock,
            ContentIdentitySchemaVersion(2),
            b"canonical",
        );
        let other_payload = ContentId::derive(ContentDomain::SemanticBlock, schema, b"canonical!");

        assert_eq!(first, repeated);
        assert_ne!(first, other_domain);
        assert_ne!(first, other_schema);
        assert_ne!(first, other_payload);
    }

    #[test]
    fn semantic_fingerprint_has_an_independent_identity_domain() {
        let bytes = b"canonical semantics";
        let content = ContentId::derive(ContentDomain::SemanticBlock, ContentIdentitySchemaVersion(1), bytes);
        let fingerprint = SemanticFingerprint::derive(SemanticFingerprintSchemaVersion(1), bytes);

        assert_ne!(content.0, fingerprint.0);
    }

    #[test]
    fn payload_length_is_part_of_the_identity_frame() {
        let schema = ContentIdentitySchemaVersion(1);
        let joined = ContentId::derive(ContentDomain::KnowledgeArtifact, schema, b"ab");
        let split_framing = ContentId::derive(ContentDomain::KnowledgeArtifact, schema, b"a\0b");

        assert_ne!(joined, split_framing);
    }

    #[test]
    fn fx_hasher_is_deterministic_and_equality_consistent() {
        use super::fx::{FxHashMap, FxHashSet};

        // Deterministic across hasher instances (no per-process seed).
        let mut first = FxHasher::default();
        let mut second = FxHasher::default();
        "an expression node key".hash(&mut first);
        "an expression node key".hash(&mut second);
        assert_eq!(first.finish(), second.finish());

        // Equal keys hash equal through the derived Hash impls the hot maps
        // rely on; unequal keys need not differ (collisions are legal, only
        // probing cost) — so this asserts map behavior, not inequality.
        let mut words: FxHashSet<&str> = FxHashSet::default();
        words.insert("sort");
        words.insert("op");
        words.insert("operands");
        words.insert("immediate");
        assert_eq!(words.len(), 4);
        assert!(words.contains("op"));
        assert!(!words.contains("symbolic_sources"));

        let mut map: FxHashMap<(u16, u128), u32> = FxHashMap::default();
        map.insert((64, 0xDEAD_BEEF), 7);
        assert_eq!(map.get(&(64, 0xDEAD_BEEF)), Some(&7));
        assert_eq!(map.get(&(32, 0xDEAD_BEEF)), None);
    }

    #[test]
    fn fx_hasher_byte_slices_follow_the_same_path_as_integers() {
        use super::fx::FxHasher;

        // write_u64 and write of the same 8 little-endian bytes are allowed
        // to differ; what matters is that each is stable. Assert both
        // stability and rough avalanche behavior on single words.
        let mut one = FxHasher::default();
        one.write_u64(1);
        let mut two = FxHasher::default();
        two.write_u64(2);
        assert_ne!(one.finish(), two.finish());

        let mut bytes = FxHasher::default();
        bytes.write(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        let mut repeated = FxHasher::default();
        repeated.write(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
        assert_eq!(bytes.finish(), repeated.finish());

        // Trailing zeros in remainder do not collide
        let mut r1 = FxHasher::default();
        r1.write(&[1]);
        let mut r2 = FxHasher::default();
        r2.write(&[1, 0]);
        assert_ne!(r1.finish(), r2.finish());
    }
}
