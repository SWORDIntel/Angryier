# Semantic Definition Architecture

> **Implementation status:** Implemented (contract + builder). `angryier-semantics` owns the typed semantic domains, provider/builder traits, and sealed block builder (561 lines). The semantic provider registry, value/effect definitions, and sealing pipeline are implemented. No actual Intel 64 semantic definitions exist yet — the handwritten corpus is the next implementation phase.

---

## Hybrid definition strategy

The semantic-definition strategy is hybrid.

```text
                    semantic source
                          |
          +---------------+----------------+
          |               |                |
          v               v                v
   declarative family   typed Rust       handwritten
      definitions       combinators       overrides
          |               |                |
          +---------------+----------------+
                          |
                    semantic compiler
                          |
                          v
               private rich semantic IR
                          |
               normalize / optimize / validate
                          |
                          v
                         SEAL
                          |
                          v
               immutable semantic block
```

### Why hybrid

Regular instruction families contain enormous repetition in widths, lanes, masks, source/destination forms, and feature tags. These should be declarative/generated.

Complex behavior should not force the declarative format to become a hidden general-purpose programming language. Typed Rust combinators and explicit overrides remain available for:

- AMX;
- complex AVX-512 masking/gather/scatter;
- difficult floating-point behavior;
- system/state instructions;
- CET/APX corner cases;
- x87/string/REP families where appropriate;
- semantics that resist clean declarative factoring.

### Provider resolution

A decoded form resolves to exactly one authoritative semantic provider. Registry order must never silently determine semantic priority. Multiple matching providers are a hard error.

Every emitted semantic definition yields a receipt containing at least rule identity, origin, and semantic version.

### Generator discipline

The generator is built **after** a representative handwritten corpus stabilizes the semantic and execution IRs.

Generated outputs must be:

- deterministic;
- readable;
- checked into the repository when appropriate;
- reproducible by CI;
- covered by a support manifest;
- test-generated from the same semantic source where useful.

Unsupported forms are explicit errors, never silent no-ops.

---

## Two-level IR architecture

Angryier uses two distinct IR levels.

### Rich Canonical Semantic IR

The rich IR exists to express architectural meaning without premature lowering into solver bitvectors or JIT-friendly micro-ops.

First-class domains include:

```text
BitVec(width)
Float(format)
Vector { width, lane/view metadata }
Opmask { lanes }
Tile { rows, columns/bytes-per-row, element/layout metadata }
```

It represents:

- explicit register reads/writes;
- explicit memory effects;
- architectural flags;
- exceptions/fault conditions;
- floating-point rounding and MXCSR-sensitive behavior;
- SAE and embedded rounding;
- AVX-512 merge/zero masking;
- upper-lane behavior;
- broadcasts/permutations/shuffles;
- AMX TILECFG and tile state;
- memory ordering where modeled;
- control transfers;
- feature/privilege assumptions where required.

### AngryIR execution IR

> **Implementation status:** Implemented. `angryier-ir` owns AngryIR types, lowering (`lower.rs`, 545 lines), and verification (`verify.rs`, 233 lines).

AngryIR is compact and hot-path oriented.

Requirements:

- SSA-like block temporaries;
- compact IDs and inline immediates;
- explicit widths/types;
- explicit register/memory effects;
- solver-independent representation;
- no decoder-specific objects;
- no database handles;
- no per-operand heap allocation in the normal path;
- structural vector/mask/tile operations retained where profitable;
- deterministic serialization where identity-bearing;
- block validity tied to exact semantic `ContentId` and code-page versions.

Rich semantics are truth; AngryIR is an execution artifact derived from that truth.

---

## Semantic block lifecycle and identity

### Two-stage lifecycle

```text
PRIVATE / MUTABLE
    |
    +-- construct
    +-- normalize
    +-- local optimize
    +-- validate
    |
    v
SEAL
    |
    +-- canonical serialization
    +-- exact ContentId
    +-- normalized SemanticFingerprint
    +-- semantic/schema version binding
    +-- provenance receipt
    |
    v
PUBLIC / IMMUTABLE
```

Only sealed blocks may enter:

- lowering;
- caches;
- JIT validity;
- replay capsules;
- provenance references;
- exact cross-run reuse;
- QIHSE exact-plane storage.

### Dual identity

Every sealed block has two identities.

**`ContentId`**

- authoritative exact identity;
- computed from canonical sealed serialization;
- trusted by replay, JIT, provenance, exact caches, and exact reuse.

**`SemanticFingerprint`**

- normalized semantic/structural candidate identity;
- may normalize irrelevant temporary numbering, safe commutative ordering, structural naming, and equivalent representation artifacts;
- used for candidate equivalence, clustering, generalized lookup, and learned-fusion input;
- never sufficient to authorize exact reuse.

Fingerprint normalization must preserve semantically relevant distinctions such as widths, signedness where meaningful, rounding, MXCSR behavior, SAE, mask merge/zero behavior, exceptions, memory ordering, architectural side effects, and target-feature assumptions.

See [Semantic Identity](../semantics/identity.md) for the full identity contract.

---

## Semantic transformation trust

A sealed semantic block is never modified in place.

```text
sealed block A
      |
 transformation pass
      |
      v
candidate block B
      |
      +-- declared transformation contract
      +-- structural/type/effect checks
      +-- equivalence evidence
      +-- parent derivation link
      |
      v
sealed block B
```

Transformation contracts explicitly state preservation claims such as:

```text
values
architectural side effects
exception behavior
memory ordering
floating-point behavior
masking behavior
target-feature semantics
```

### Evidence lattice

Equivalence evidence is layered rather than a single boolean:

```text
Structural
    -> SolverChecked
        -> DifferentiallyTested
            -> Composite
```

Different transformation classes may require different evidence. PROVE requires policy-sufficient evidence. EXPLORE/HUNT may permit explicitly weaker evidence, but such artifacts are marked and may not silently contaminate the authoritative semantic corpus.

Execution/JIT optimizations remain bound to the exact source `ContentId` even when their machine representation changes.

---

## Structured vector, mask, and AMX representation

Wide architectural state is represented structurally and lowered lazily.

### Vectors

Vectors use a hybrid packed/lane-aware representation:

- packed view for bitwise/reinterpretation-heavy operations;
- lane view for arithmetic, masks, taint, and partially symbolic data;
- lazy conversion between views;
- concrete lanes remain concrete;
- symbolic lanes reference compact expressions;
- view coherence is versioned/validated rather than protected by a global lock.

### AVX-512 opmasks

`k0..k7` are first-class mask state. Semantics distinguish:

- merge masking;
- zero masking;
- mask lane width;
- broadcasts;
- upper-lane clearing/preservation as required;
- embedded rounding and SAE.

### AMX

AMX state includes explicit TMM state and TILECFG.

Preferred representation:

```text
LazyChunked
```

with concrete backing and sparse/lazy symbolic chunks/cells.

Fallback:

```text
DenseCellFallback
```

may be selected when profiling demonstrates pathological translation/contention. Representation changes are policy transitions, not semantic approximations, and must be provenance-visible and differentially cross-checked.

---

## Floating-point model

Floating-point semantics use native SMT floating-point theories where appropriate, with a controlled bitvector lowering/fallback path.

The model must account for, where architecturally relevant:

- F16/BF16/F32/F64/F80 and newer formats as Intel extensions require;
- rounding modes;
- NaN/sNaN behavior;
- infinities;
- signed zero;
- denormals;
- DAZ/FTZ;
- MXCSR;
- exception flags;
- SAE;
- embedded rounding;
- conversion corner cases.

Bitvector fallback is explicit and validity-scoped. Cross-check corpora should compare SMT-FP and bitvector formulations where both apply.
