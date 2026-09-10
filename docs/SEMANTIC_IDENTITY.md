# Angryier Semantic Identity Contract

## Status

**Q30 — Locked C: dual semantic identity.**

A sealed semantic block carries two distinct identities with different trust roles:

```text
SealedSemanticBlock
    |
    +--> ContentId
    |      authoritative exact identity
    |
    +--> SemanticFingerprint
           normalized equivalence/retrieval identity
```

These identities must never be conflated.

## ContentId — authoritative identity

`ContentId` is computed from the canonical serialization of the sealed semantic block after normalization and validation.

It is the identity trusted by:

- replay capsules;
- JIT/block-cache validity;
- provenance references;
- exact cross-run reuse;
- deterministic cache keys;
- semantic derivation records;
- QIHSE exact-plane storage.

Two blocks may share a `ContentId` only when their canonical sealed representations are byte-for-byte identical under the same identity-schema version.

A post-seal semantic transformation never mutates the original block. It creates a new sealed block and therefore a new `ContentId`, with an explicit derivation edge to the parent.

## SemanticFingerprint — normalized candidate identity

`SemanticFingerprint` intentionally ignores selected representation artifacts that do not change meaning, subject to the fingerprint-schema rules.

Potentially normalized dimensions include:

- temporary/value numbering;
- canonical ordering of commutative operands where sound;
- normalized constant encoding;
- equivalent width/type encodings;
- normalized vector lane representation;
- normalized mask representation;
- normalized structural naming/IDs.

It must preserve semantically relevant distinctions, including:

- operand width and signedness where meaningful;
- floating-point format and rounding behavior;
- MXCSR-sensitive behavior;
- SAE/exception suppression;
- AVX-512 merge-vs-zero masking;
- architectural side effects;
- exception behavior;
- target-feature assumptions;
- memory ordering;
- privilege/system-state semantics where modeled.

The fingerprint is used for:

- alpha-equivalence candidates;
- semantic deduplication candidates;
- QIHSE/KEYSTONE cross-run retrieval;
- generalized solver-knowledge lookup;
- learned-fusion modality input;
- similarity and clustering;
- candidate summary reuse.

A fingerprint match is never proof of semantic identity.

## Validation flow

```text
sealed semantic block
        |
        +--> canonical serialization --> ContentId
        |
        +--> normalized semantic view --> SemanticFingerprint
                                      |
                                      v
                              candidate retrieval
                                      |
                                      v
                           exact validity checking
                                      |
                          +-----------+-----------+
                          |                       |
                        reuse                   reject
```

## Versioning

Both identity schemes are versioned independently:

```text
ContentIdentitySchemaVersion
SemanticFingerprintSchemaVersion
SemanticVersion
```

Changing canonical serialization rules, normalization rules, or fingerprint construction must not silently reinterpret prior identifiers.

Persistent QIHSE records must store the relevant schema versions with every identity.

## Required invariants

1. `ContentId` is computed only from a sealed semantic block.
2. Identical canonical sealed serialization yields the same `ContentId`.
3. Any semantically visible post-seal change yields a different `ContentId`.
4. `SemanticFingerprint` may collide or match across non-identical blocks; therefore it is advisory until exact checks pass.
5. Replay and JIT validity never trust `SemanticFingerprint` as an authoritative key.
6. Fingerprint normalization must not erase rounding, masking, exception, memory-ordering, or target-profile semantics.
7. Exact and similarity identities are stored as separate fields in provenance and QIHSE.
8. Derivation relationships between sealed semantic objects are retained explicitly.

## Rust boundary direction

The planned interface should expose distinct types rather than aliases that can be accidentally interchanged:

```rust
pub struct ContentId([u8; 32]);
pub struct SemanticFingerprint([u8; 32]);

pub trait SealedSemanticBlock {
    fn content_id(&self) -> ContentId;
    fn semantic_fingerprint(&self) -> SemanticFingerprint;
    fn semantic_version(&self) -> SemanticVersion;
}
```

The exact digest/fingerprint algorithms remain an implementation decision; the architectural requirement is the separation of authoritative exact identity from normalized candidate identity.

## Stress tests

The identity subsystem is not considered stable until tests demonstrate that:

- temporary renumbering can preserve `SemanticFingerprint` while changing no semantics;
- semantically relevant rounding/masking changes alter both the fingerprint and exact identity;
- canonical serialization is deterministic across process runs;
- schema-version changes invalidate reuse safely;
- a fingerprint collision cannot bypass exact validation;
- replay/JIT reject any block whose `ContentId` does not match the capsule/validity key.
