# Shared Identity and Version Model

> **Status superseded (2026-09-24):** see [ROADMAP.md](../ROADMAP.md).

> **Implementation status:** Implemented. `angryier-types` owns all cross-plane IDs, versions, and identity types. `ContentId` and `SemanticFingerprint` are distinct newtypes with domain-separated identity frames.

---

## Identity-bearing objects

Identity-bearing objects use distinct newtypes. Cross-domain IDs must not be interchangeable primitive aliases in mature code.

Core identities include at least:

```text
RunId
ImageId
ModuleId
BlockId
StateId
ExprId
ConstraintId
CodePageId
SummaryId
ProvenanceNodeId
ReplayCapsuleId
TargetProfileId
SemanticRuleId
ContentId
SemanticFingerprint
DependencyKey
WorkUnitId
```

## Version domains

Version domains include:

```text
SemanticVersion
ContentIdentitySchemaVersion
SemanticFingerprintSchemaVersion
ExpressionNormalizationVersion
ConstraintCanonicalizationVersion
EnvironmentModelVersion
SummarySchemaVersion
ProvenanceSchemaVersion
ReplaySchemaVersion
EmbeddingModelVersion
EmbeddingSchemaVersion
KnowledgeSchemaVersion
CodePageVersion
LedgerEpoch
```

A cache key that omits a materially relevant version is a correctness defect.

## Architecture abstraction

The engine is ISA-neutral at its core.

Conceptually:

```rust
pub trait Architecture {
    type Register;
    type Feature;
    type Decoded;
    type RegisterFile;

    fn decode(&self, pc: u64, bytes: &[u8], profile: &TargetProfile)
        -> Result<Self::Decoded, DecodeError>;

    fn initial_registers(&self, profile: &TargetProfile) -> Self::RegisterFile;

    fn validate_target_features(
        &self,
        decoded: &Self::Decoded,
        profile: &TargetProfile,
    ) -> Result<(), FeatureError>;
}
```

This is an architectural boundary, not a requirement that every backend expose identical internal details.

### Intel 64 first

The first production backend is Intel 64. Validation scope includes modern Intel families such as:

```text
base Intel 64
SSE / SSE2 / SSE3 / SSSE3 / SSE4.x
AES-NI / SHA / BMI-class instructions
AVX
AVX2
AVX-512
AVX-VNNI
AVX10
AMX
CET
APX
future Intel extensions after explicit semantic validation
```

AMD-specific extensions, SVM behavior, and AMD-specific MSRs/system behavior are not part of the Intel 64 validation target.

### Host and target separation

```text
HostFeatures   = analyzer machine CPUID/XCR0/OS enablement
TargetFeatures = virtual target CPU profile and allowed feature set
```

Execution policy chooses acceleration:

```text
decode -> semantic truth -> execution policy

if host safely supports accelerated form:
    optional native/JIT specialization
else:
    software semantic path
```

Target support must never disappear because the host lacks a feature.

### Target profiles

Target profiles support:

- `native` convenience profile;
- named Intel microarchitecture profiles;
- custom CPUID/feature-set profiles;
- explicit XCR0/OS-state assumptions where relevant.

The profile identity participates in validity keys whenever feature availability changes semantics or legality.
