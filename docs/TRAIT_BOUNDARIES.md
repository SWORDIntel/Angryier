# Angryier Trait Boundaries

This document defines the concrete Rust ownership and interface boundaries implied by `Plan.md` and the frozen architecture. It is a contract document: crate existence reserves responsibility, but does not claim that a backend is implemented.

## Primary invariant

The dominant cross-plane failure mode is semantic/execution/provenance desynchronization during code mutation, lowering, cache/JIT reuse, solver reuse, or replay. Angryier therefore treats identity, validity, and publication boundaries as part of correctness rather than instrumentation.

The architecture enforces these separations:

1. **Shared identity is singular.** Cross-plane IDs, versions, dependency keys, fidelity and analysis context are owned by `angryier-types`.
2. **Decode is not semantics.** XED-specific ownership terminates in `angryier-decode-xed`.
3. **Construction is not publication.** Rich semantic blocks are private/mutable until sealing.
4. **Semantic truth is not execution representation.** `angryier-semantics` defines typed semantic construction; `angryier-ir` owns compact execution IR.
5. **Post-seal transforms are derivations, not mutation.** `angryier-semantic-contracts` owns exact identity, fingerprints and equivalence-evidence contracts.
6. **State is not solver state.** Persistent execution state stores engine-level expressions/constraints, never backend-native Z3/Bitwuzla objects.
7. **Execution publication is atomic.** `angryier-ledger` owns the epoch boundary coupling state, code versions, provenance and replay-visible metadata.
8. **Persistence is not execution.** QIHSE/KEYSTONE adapters are asynchronous knowledge-plane edges and never correctness prerequisites for a worker step.
9. **Similarity is not proof.** Fusion/vector retrieval may propose candidates; authoritative reuse validates exact compatibility/dependency keys.

---

# Ownership Map

```text
angryier-types
    |
    +-- angryier-arch
    |      +-- angryier-arch-intel64
    |             +-- angryier-decode-xed
    |
    +-- angryier-semantics
    |      +-- angryier-semantics-gen
    |
    +-- angryier-semantic-contracts
    |
    +-- angryier-ir
    +-- angryier-expr
    +-- angryier-memory
    +-- angryier-state
    +-- angryier-taint
    +-- angryier-execution
    +-- angryier-ledger
    +-- angryier-replay
    +-- angryier-solver
    |      +-- angryier-solver-z3
    |      +-- angryier-solver-bitwuzla
    +-- angryier-scheduler
    +-- angryier-provenance
    +-- angryier-knowledge
    +-- angryier-fusion
    +-- angryier-models
    +-- angryier-storage
    +-- angryier-telemetry
    +-- angryier-qihse
    +-- angryier-keystone
    +-- angryier-loader
    +-- angryier-fuzz
    +-- angryier-jit
    +-- angryier-plugins
    +-- angryier-distribution
    +-- angryier-bench
```

The CLI is an orchestration surface, not a source of engine truth.

---

# Canonical Shared Types

`angryier-types` is deliberately low-level. The following classes of values must not be independently redefined by higher crates:

```text
Address
RunId / ImageId / BlockId / StateId
ConstraintId / ExprId
CodePageId / CodePageVersion
SemanticRuleId / SemanticVersion
ContentId / SemanticFingerprint
TargetProfileId
ProvenanceNodeId / ProvenanceSeq
ReplayCapsuleId
DependencyKey
EnvironmentModelVersion
EmbeddingModelVersion
KnowledgeSchemaVersion
FidelityProfile
RetentionProfile
AnalysisContext
```

A type with the same conceptual name in two crates is an architectural defect unless it is intentionally architecture-local and cannot cross a plane boundary.

Backend-native handles, pointers, contexts, ASTs and database objects are explicitly excluded from this crate.

---

# Decode Boundary

`angryier-arch` owns the ISA-neutral decoder contract and normalized decoded-instruction shape. `angryier-arch-intel64` owns Intel 64 target profiles and architectural feature/state definitions. `angryier-decode-xed` adapts Intel XED into those internal forms.

```text
bytes + target profile
        |
        v
Intel XED
        |
        v
angryier-decode-xed
        |
  normalize/copy
        |
        v
DecodedInstruction
        |
        v
semantic provider resolution
```

XED-owned pointers, decoder-state lifetimes, opaque structs and allocator ownership do not cross the adapter boundary.

The adapter must fail explicitly if XED is unavailable; the scaffold must never fabricate successful decode results.

---

# Semantic Provider Boundary

`angryier-semantics` owns semantic construction and provider contracts:

```text
SemanticProvider
├── GeneratedSemanticFamily
├── RustSemanticCombinator
└── SemanticOverride
```

The registry resolves each decoded form to exactly one authoritative provider. Registration order never acts as semantic priority; ambiguity is an error.

Semantic providers can observe normalized instruction information and emit typed semantic values/effects. They cannot access:

- solver backend ASTs;
- JIT/compiler handles;
- mutable execution states;
- QIHSE/KEYSTONE handles;
- WAL/storage handles;
- scheduler queues.

That restriction is the primary impedance barrier between semantic truth and execution policy.

---

# Semantic Block Lifecycle

```text
PRIVATE / MUTABLE
    |
    +-- construct
    +-- normalize
    +-- optimize before publication
    +-- validate
    |
    v
SEAL
    |
    +-- canonical serialization
    +-- ContentId
    +-- SemanticFingerprint
    +-- semantic/schema version binding
    +-- validation receipt
    |
    v
PUBLIC / IMMUTABLE
    |
    +-- lowering
    +-- exact cache keys
    +-- JIT validity
    +-- provenance references
    +-- replay capsules
    +-- QIHSE exact-plane records
```

No execution, replay, provenance or knowledge component may observe a rich semantic block before sealing succeeds.

## Dual identity

`ContentId` is authoritative exact identity. `SemanticFingerprint` is a normalized candidate identity. Replay/JIT/exact-cache decisions may never substitute fingerprint equality for exact validity.

## Post-seal transformation

`angryier-semantic-contracts` defines immutable derivation:

```text
sealed A
  |
  +-- transformation contract
  +-- equivalence evidence
  v
sealed B
```

B receives a new `ContentId` and a parent/derivation edge. PROVE accepts a derived block only when the acceptance policy considers its evidence sufficient for every claimed preserved property.

---

# Typed Wide Semantics

The truth plane keeps structural domains for:

```text
Scalar(BitVec / Float)
Vector
Opmask
Tile
```

Locked representation policies include:

```text
VectorRepresentation::HybridLazy
TileRepresentation::LazyChunked
TileRepresentation::DenseCellFallback
FloatingPointPolicy::SmtFpPreferred
FloatingPointPolicy::ControlledBitVectorFallback
```

Lazy packed/lane/cell views are execution/solver representation choices, not semantic approximations. Any fallback between lazy AMX chunks and dense cells must preserve observable semantics and appear in provenance/benchmark telemetry.

---

# Two-Level IR Boundary

```text
DecodedInstruction
       |
       v
SemanticProvider
       |
       v
private rich semantic IR
       |
 normalize / validate / seal
       |
       v
sealed semantic block
       |
       v
SemanticLowerer
       |
       v
angryier-ir compact block
       |
       +--> interpreter
       +--> taint/symbolic hooks
       +--> specialized executor
       +--> profile-driven JIT
```

The compact execution block carries or is bound to:

- exact semantic `ContentId`;
- semantic version;
- target profile;
- code-page versions;
- image/block identity.

Virtual-address equality alone can never authorize reuse.

---

# State, Memory and Expression Boundaries

`angryier-state` owns persistent state roots and fidelity history. `angryier-memory` owns page-backed copy-on-write memory and sparse symbolic overlays. `angryier-expr` owns hash-consed expression DAGs and canonicalization. `angryier-taint` owns dataflow provenance and concrete→taint→symbolic promotion decisions.

The normal design direction is:

```text
immutable shared state roots
+ worker-owned current mutation context
+ COW memory/page deltas
+ compact ExprId references
+ worker-local caches
```

State must not embed solver contexts, backend ASTs, database sessions or JIT compiler objects.

Symbolic addresses are resolved through explicit profile-aware policy rather than hidden concretization.

---

# Solver Boundary

`angryier-solver` defines backend-neutral query/result structures, shared-context batch solving, routing and preemption. Z3 and Bitwuzla live behind adapter crates.

Required terminal/result classes remain distinct:

```text
SAT
UNSAT
UNKNOWN
TIMEOUT
RESOURCE_LIMIT
BACKEND_ERROR
```

UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR may never be silently promoted to UNSAT.

Each worker owns its incremental backend contexts. Persistent solver knowledge stores canonical engine-level facts, models/cores where portable, validity keys and telemetry—not live solver-native objects.

---

# Atomic Execution Ledger

`angryier-ledger` is the mandatory publication boundary for replay-visible execution mutations.

Conceptually coupled state:

```text
ExecutionState
CodePageVersions
block/JIT validity consequences
ProvenanceSequence
ReplayCheckpoint
SemanticVersion
SemanticContentId
```

A successful commit publishes one new epoch containing the entire mutation. Failure publishes none of it.

```text
begin(snapshot N)
    |
    +-- state mutation
    +-- code-page version change
    +-- invalidation consequence
    +-- provenance events
    +-- replay checkpoint
    +-- semantic identity refs
    |
commit
    |
    v
snapshot N+1 atomically visible
```

Required rejection classes include stale epoch, stale code version, semantic-version/content mismatch, provenance gap, replay mismatch and conflicting commit.

Atomicity must not be implemented as one global mutex. Independent state/version domains must remain independently committable where correctness permits.

---

# JIT and Self-Modifying Code

`angryier-jit` owns translated-code artifacts and isolation policy. Code-page writes advance version identity. Any block bound to an old page version becomes invalid without requiring address-based global flushing.

Trusted Angryier-generated translations may eventually execute in-process. Arbitrary/native target execution belongs in a restricted worker/sandbox boundary.

JIT is profile-driven and remains optional until end-to-end profiling demonstrates value.

---

# Provenance and Telemetry Boundary

`angryier-provenance` owns causal event structure and adaptive Tier 0/1/2 policy. `angryier-telemetry` owns operational metrics. `angryier-storage` owns local WAL/spill and retention lifecycle.

Correctness-critical Tier-1 events cannot be silently dropped. Under persistence backpressure, the transport may batch, spill locally, aggregate lower-value telemetry, or apply explicitly visible backpressure according to policy.

Workers must not synchronously wait on QIHSE or KEYSTONE during ordinary execution.

---

# Knowledge and Retrieval Boundary

`angryier-knowledge` owns exact/advisory validity semantics and dependency-aware invalidation. `angryier-qihse` and `angryier-keystone` are persistence/index adapters. `angryier-fusion` owns modality encoding and learned fusion.

```text
EXACT PLANE
ContentId + canonical artifact + dependency keys
            |
            +--> may authorize reuse after compatibility validation

ADVISORY PLANE
SemanticFingerprint / fused embeddings / similarity
            |
            +--> proposes candidates only
```

Every correctness-affecting cache hit validates the cryptographically backed dependency/compatibility envelope before reuse.

---

# Concurrency Rules

Locked concurrency model:

```text
immutable shared structures
+ worker-local mutable caches
+ worker-local solver contexts
+ NUMA-local worker groups
+ locality-aware work stealing
```

State migration cost includes solver-context rebuild, NUMA/cache locality and load-imbalance gain. The scheduler may use learned ranking only as advisory input layered over deterministic admissible policy.

Strict deterministic mode records/replays scheduler decisions, seeds, solver policy decisions and event ordering needed to reproduce emergent exploration behavior.

---

# Environment, Summary and State Import Boundaries

`angryier-models` owns environment models and exact/approximate function summaries. Every summary/model is dependency-keyed against relevant semantics, ABI/calling convention, target profile, referenced globals and environment versions.

`angryier-loader` owns the unified import abstraction for:

```text
static binary
snapshot
checkpoint
live-process capture
```

Imported state enters through the same internal state/profile/fidelity contracts rather than special execution paths.

---

# Fuzzing Boundary

`angryier-fuzz` is staged deliberately:

```text
Stage 1: seed sharing
Stage 2: seed + coverage exchange
Stage 3: bidirectional seeds / coverage / constraints / target hints / feedback
```

High-entropy mutated inputs are treated as an explicit cache-poisoning/canonicalization stress class. Fuzzer origin never weakens exact knowledge validation.

---

# Plugin and Future Distribution Boundaries

Internal extensibility uses stable Rust traits. A binary C ABI is deferred until an external plugin requirement justifies its compatibility burden.

`angryier-distribution` reserves serializable work/state/identity envelopes now, but multi-host scheduling is not implemented until single-host NUMA scaling is proven.

---

# Required Architecture Tests

Before broad semantic implementation, tests must demonstrate at least:

1. synthetic decode objects can exercise semantics without linking XED;
2. generated/combinator/override providers cannot ambiguously resolve a form;
3. unsealed semantics cannot enter lowering/cache/replay/knowledge;
4. canonical sealing is deterministic across process runs;
5. post-seal transforms create new immutable identities and derivation records;
6. semantic fingerprint collisions cannot authorize exact reuse;
7. code-page changes invalidate all dependent execution/JIT artifacts;
8. failed ledger commits expose no partial state/provenance/replay mutation;
9. independent state domains do not require a global execution lock;
10. lazy/dense AMX representations agree on the designated cross-check corpus;
11. SMT-FP and controlled bitvector fallback agree where both are applicable;
12. UNKNOWN/TIMEOUT/backend errors are never treated as UNSAT;
13. stale dependency keys cannot authorize solver/summary/cache reuse;
14. QIHSE/KEYSTONE loss cannot corrupt execution correctness;
15. WAL saturation is observable and recoverable;
16. deterministic mode can reproduce scheduler/exploration ordering;
17. high-entropy fuzzer near-misses cannot poison alpha-equivalence/subsumption reuse.

---

# Scaffold Status

The crate ownership and public contract boundaries above are present in the repository. Native XED integration, full Intel semantic coverage, concrete/symbolic execution internals, solver translation, NUMA scheduling, durable ledger/replay implementations, QIHSE/KEYSTONE SDK bindings, learned models, JIT and full hybrid-fuzzer adapters remain implementation work.

No placeholder backend is permitted to report success for an unimplemented capability.
