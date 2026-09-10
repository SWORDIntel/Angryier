# Angryier Implementation Plan

## Status

**Architecture frozen. Implementation planning begins here.**

`Plan.md` is the operational architectural baseline. This document defines implementation order and validation gates without weakening or reinterpreting any locked architectural decision.

The implementation sequence begins with foundational Execution Plane data structures, immediately followed by the Intel XED decode boundary. The rationale is simple: the decoder must target stable internal contracts rather than accidentally define them.

---

## Implementation Doctrine

1. Correctness contracts before optimization.
2. Stable internal identities before external adapters.
3. Deterministic single-thread behavior before multicore scheduling.
4. Concrete execution before symbolic promotion.
5. Exact cache validity before cross-run reuse.
6. Tier-1 provenance before deep tracing.
7. JIT only after profiling demonstrates a material need.
8. Bidirectional fuzzing only after deterministic replay and cache-validity invariants are hardened.
9. QIHSE/KEYSTONE integration must never become a synchronous execution dependency.
10. Every performance claim requires a matching correctness/replay result.

---

# Phase 0 — Build and Validation Skeleton

Create the workspace structure, CI, lints, test categories, benchmark schema, deterministic test seed handling, and feature gates.

Required outputs:

- workspace crate graph;
- `cargo fmt`, `clippy`, unit/integration tests;
- sanitizer/Miri-compatible test targets where applicable;
- deterministic test-seed plumbing;
- benchmark result schema;
- architecture invariant test harness;
- no hidden panics/unwraps in core crates.

**Exit gate:** CI can validate contract crates and deterministic test fixtures before engine behavior exists.

---

# Phase 1 — Foundational Execution Plane Data Structures

Implement stable internal types first.

Primary crates:

```text
angryier-core
angryier-ir
angryier-state
angryier-memory
angryier-expr
angryier-arch
angryier-arch-intel64
angryier-provenance
```

Core structures:

- stable IDs for image, block, state, expression, constraint, semantic content, target profile, provenance node, code page, and replay capsule;
- immutable/persistent state roots;
- page-based COW memory;
- concrete backing plus sparse symbolic overlay;
- register-state abstraction;
- target CPU profile model;
- expression arena/hash-consing interfaces;
- fidelity ledger;
- code-page version records;
- execution-ledger epoch model;
- deterministic serialization contracts for identity-bearing objects.

The initial state/memory implementation must be usable without XED, Z3, Bitwuzla, QIHSE, KEYSTONE, JIT, or fuzzing.

**Exit gate:** synthetic states can fork, mutate isolated pages/registers, preserve parent state, serialize deterministically, and reject stale ledger publication.

---

# Phase 2 — Intel XED Decode Boundary

Implement `angryier-decode-xed` only after internal decoded-form and target-feature types exist.

Responsibilities:

- XED initialization;
- Intel 64 instruction decode;
- normalized operand descriptors;
- form IDs;
- feature classification;
- instruction length/address;
- normalized register references;
- target-profile legality checks;
- conversion into XED-independent `DecodedInstructionView` data.

XED-owned pointers/lifetimes must terminate at the adapter boundary.

**Exit gate:** decode corpus round-trips deterministically into normalized internal forms, including representative scalar, SSE/AVX, AVX-512, AMX, CET/APX-capable forms where supported by the XED release in use.

---

# Phase 3 — Rich Semantic IR and Sealing

Implement private mutable semantic construction followed by immutable sealing.

Required components:

- typed semantic nodes;
- values/effects;
- explicit architectural side effects;
- scalar/FP/vector/opmask/tile domains;
- normalization;
- validation;
- canonical serialization;
- `ContentId` generation;
- `SemanticFingerprint` generation;
- semantic schema versions;
- derivation/provenance linkage.

Only sealed blocks may be lowered, cached, persisted, replayed, or used by JIT validity.

**Exit gate:** semantically identical canonical blocks receive stable exact identities across runs, while relevant rounding/masking/exception changes alter authoritative identity.

---

# Phase 4 — Handwritten Semantic Corpus

Before building the semantic generator, implement a deliberately small but structurally representative corpus.

Representative families should exercise:

- integer arithmetic/flags;
- load/store/addressing;
- control flow;
- shifts/rotates;
- SSE/AVX lane operations;
- AVX-512 opmask merge/zero semantics;
- floating point with rounding/MXCSR interactions;
- one or more AMX tile operations;
- exception/unsupported behavior.

The objective is to force the rich IR and execution IR contracts to stabilize before automation amplifies design mistakes.

**Exit gate:** corpus passes differential concrete tests and supports deterministic semantic sealing/lowering.

---

# Phase 5 — Compact Execution IR and Concrete Interpreter

Implement `AngryIR` as the compact execution representation downstream of sealed semantics.

Requirements:

- compact SSA-like temporaries;
- explicit register/memory effects;
- typed operations where structural preservation pays off;
- no solver types in IR;
- block validity keys including semantic `ContentId`, target profile, and code-page versions;
- deterministic interpretation;
- code-page invalidation handling.

**Exit gate:** handwritten semantic corpus executes concretely and matches native/reference behavior on the differential corpus.

---

# Phase 6 — Atomic Execution Ledger + Replay

Harden the state publication boundary before concurrency, cross-run knowledge, or bidirectional fuzzing.

Implement atomic coupling of:

```text
state mutation
code-page version changes
block/JIT invalidation consequences
Tier-1 provenance sequence
semantic identity references
replay checkpoint publication
```

Required failure tests:

- stale epoch;
- stale page version;
- semantic mismatch;
- provenance gap;
- replay mismatch;
- conflicting commit;
- injected failure between every internal commit step.

**Exit gate:** deterministic replay reproduces committed executions and rejects intentionally corrupted/stale capsules.

---

# Phase 7 — Expression DAG + Taint Promotion

Implement symbolic expression infrastructure without solver commitment leaking into the state model.

Requirements:

- arena-allocated `ExprId`;
- hash-consing;
- constant folding;
- cheap deterministic canonicalization;
- dependency summaries;
- taint/dataflow IDs;
- concrete -> tainted -> symbolic promotion;
- hybrid vector representation;
- lazy chunked AMX representation with dense-cell fallback.

**Exit gate:** mostly-concrete execution does not allocate symbolic ASTs unnecessarily, and vector/tile representation transitions are semantically equivalent on the corpus.

---

# Phase 8 — Solver Interface and Z3/Bitwuzla Backends

Implement the solver-neutral query model, then Z3 and Bitwuzla adapters.

Required result classes:

```text
SAT
UNSAT
UNKNOWN
TIMEOUT
RESOURCE_LIMIT
BACKEND_ERROR
```

Required capabilities:

- per-worker incremental contexts;
- shared-context batched satisfiability;
- model extraction;
- UNSAT-core support where backend permits;
- canonical query fingerprints;
- hard resource limits;
- adaptive preemption hooks;
- no backend AST in persistent engine state.

**Exit gate:** solver backends agree on the designated cross-check corpus, and timeout/error states can never be misclassified as UNSAT.

---

# Phase 9 — Constraint Reuse and Knowledge Validity

Implement exact reuse before approximate retrieval.

Order:

1. exact canonical query cache;
2. compatibility/dependency keys;
3. alpha-equivalence candidates;
4. validated UNSAT-core reuse;
5. implication/subsumption facts;
6. dependency-aware invalidation graph;
7. deeper offline canonicalization.

Every hit that can affect correctness must validate all required dependency keys before reuse.

**Exit gate:** deliberate fingerprint collisions, stale semantic versions, model changes, and fuzzer-generated near-miss constraints cannot authorize incorrect reuse.

---

# Phase 10 — Multicore / NUMA Scheduler

Introduce parallelism only after deterministic single-thread behavior is stable.

Implement:

- worker-local queues;
- work stealing;
- per-worker solver contexts/caches;
- NUMA-aware worker groups;
- state/solver/cache affinity metadata;
- multifactor steal cost;
- deterministic scheduler-record mode;
- scheduler-decision replay.

**Exit gate:** independent states scale across physical cores without a global execution lock, and deterministic mode can reproduce a recorded exploration ordering.

---

# Phase 11 — State Merge, Search, Summaries, Environment Models

Implement the higher-level exploration policies:

- multifactor state-merge cost model;
- composable multi-objective search;
- optional learned/advisory ranking hook;
- exact and approximate function summaries;
- dependency-keyed summary invalidation;
- layered syscall/libc/environment models;
- static/snapshot/checkpoint/live state-import abstraction.

**Exit gate:** PROVE refuses insufficiently justified approximations, while EXPLORE/HUNT record every policy relaxation in the fidelity ledger.

---

# Phase 12 — Provenance Transport, WAL, and QIHSE/KEYSTONE

Implement the knowledge-plane transport only after correctness-critical local provenance is stable.

Requirements:

- Tier-1 structural events never silently dropped;
- bounded priority-aware queues;
- worker-local batching;
- local WAL/spill under backpressure;
- Tier-2 flight recorder;
- semantic structural trace compression;
- quarantine/retention lifecycle;
- QIHSE exact-plane persistence;
- KEYSTONE indexing/ingestion/retrieval acceleration;
- dependency graph persistence;
- time-series telemetry;
- future GraphDB binding if required by the Rust SDK boundary.

**Exit gate:** forced database unavailability cannot corrupt execution correctness, and sustained backpressure is observable rather than silent.

---

# Phase 13 — Hybrid Fuzzing

Start conservatively.

Stage 1:

```text
seed sharing + coverage exchange
```

Stage 2 after replay/cache validation stress tests pass:

```text
bidirectional seeds
coverage
constraint hints
target hints
testcase feedback
```

High-entropy fuzz inputs must be a dedicated stress corpus for canonicalization and solver-cache poisoning resistance.

**Exit gate:** fuzzing cannot authorize an exact knowledge reuse without the same dependency validation required for non-fuzzed states.

---

# Phase 14 — Learned Fusion and Retrieval

Only after exact identity/reuse works reliably:

- modality-specific encoders;
- masked/gated fusion;
- default 1024-D representation;
- optional 384/2048/4096 profiles;
- multi-objective contrastive/self-supervised/exact-pair/behavioral/analyst-feedback training;
- calibrated fused retrieval score;
- modality contribution attribution;
- exact-validation status returned beside similarity results.

Similarity remains advisory.

**Exit gate:** retrieval quality is benchmarked independently of exact validity, and no learned score can bypass exact-plane checks.

---

# Phase 15 — JIT / Native Acceleration

JIT remains profile-driven rather than schedule-driven.

Potential progression:

```text
cold block -> compact interpreter
warm block -> specialized cached executor
hot block -> Cranelift/native translation
```

Trusted generated JIT may execute in-process under validity guards. Arbitrary/native target execution belongs in restricted worker/sandbox isolation.

**Exit gate:** JIT produces measurable end-to-end benefit on runtime-dominated workloads and aggressive invalidation stress cannot desynchronize state, provenance, code-page versions, or replay.

---

# Phase 16 — Distribution Boundary

Define wire/storage formats now, implement distributed execution only after single-host NUMA scaling is proven.

Serializable boundaries include:

- target profile;
- sealed semantics identity;
- state roots/deltas;
- expression/constraint identities;
- replay capsule;
- fidelity/provenance context;
- solver-knowledge validity keys;
- work-unit identity.

No distributed scheduler implementation is a near-term blocker.

---

# Critical Early Stress Tests

The first implementation cycle must deliberately attack the architecture's known failure modes:

- millions of dependency graph nodes with bounded metadata overhead;
- WAL saturation and recovery;
- page-version/JIT/provenance atomicity under injected failures;
- alpha-equivalence near misses from mutated fuzz inputs;
- canonicalization CPU amplification;
- solver-preemption oscillation;
- NUMA state migration versus solver-affinity cost;
- AMX lazy-chunk contention versus dense fallback;
- deterministic replay under scheduler nondeterminism;
- QIHSE/KEYSTONE unavailability;
- fingerprint collision and stale-dependency attacks against reuse.

---

# First Coding Milestone

The first implementation milestone is **not XED**. It is the minimal stable Execution Plane substrate required for XED to plug into:

```text
IDs + schemas
TargetProfile / HostFeatures
State root
Register state
COW memory
CodePageVersion
FidelityLedger
ExecutionLedger contract
Deterministic serialization
```

Immediately after that substrate passes its invariant tests, implement the XED adapter and feed normalized Intel 64 decode objects into the already-defined semantic boundary.
