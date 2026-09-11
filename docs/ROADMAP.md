# Angryier Implementation Roadmap

This roadmap is ordered around the primary technical objective: make Angryier materially faster and smarter than Python-heavy symbolic-execution systems on real analysis workloads.

The roadmap therefore prioritizes:

- native multicore execution;
- persistent/COW state economics;
- low-overhead immutable expression sharing;
- solver-context affinity and preemption;
- canonical solver-query reuse;
- exact and generalized UNSAT reuse;
- NUMA-aware work placement;
- search strategies that spend compute where it has the highest expected value;
- optional cumulative knowledge and similarity retrieval through QIHSE and KEYSTONE.

Enterprise-only hardening, elaborate governance machinery, process-isolation frameworks, and similar work do **not** block the core performance programme unless measurements or deployment requirements later prove they are necessary.

A phase advances only when its exit criteria are satisfied.

---

# Competitive Performance Mandate

The following are first-class design goals, not later polish.

## Multicore state ownership

A runnable state has one execution owner at a time. Workers may transfer ownership through scheduler queues, but normal execution does not require multiple workers to mutate the same state concurrently.

This is intended to avoid fine-grained locking while preserving cheap state migration.

## Hierarchical work queues

The scheduler should mature toward:

```text
worker-local deque
      ↓
NUMA-group queue
      ↓
global emergency queue
```

Stealing should prefer the cheapest locality boundary. Cross-NUMA migration should occur only when expected load-balancing gain exceeds solver rebuild, cache, memory-working-set, and NUMA costs.

## Solver affinity and preemption

Fork descendants should preferentially remain near solver contexts containing useful ancestor assertions. Solver work must be cancellable/preemptible so a pathological query does not monopolize a worker indefinitely.

## Canonical solver-query representation

Solver requests must have a solver-independent canonical identity suitable for:

- exact query deduplication;
- Z3/Bitwuzla cross-routing;
- sibling-state reuse;
- persistent reuse;
- alpha-equivalence experiments;
- UNSAT-core/subsumption reuse;
- offline replay and performance analysis.

## Shared immutable arenas

Expression nodes, sealed semantic blocks, decoded blocks, and other hot immutable objects should use compact IDs and arena/epoch-style lifetime strategies where measurements show `Arc`/atomic reference traffic becoming a scaling limit.

## Cache admission

Lookup and admission are separate decisions. Expensive persistent caches must reject low-value entries when storage/indexing cost exceeds expected recomputation savings.

## Scheduler performance instrumentation

Performance counters are part of the execution engine. At minimum measure:

- state fork cost;
- COW page creation;
- expression interning hit rate;
- expression allocation volume;
- solver query count and wall time;
- solver-context rebuild cost;
- exact/generalized cache hit classes;
- state steals and migrations;
- NUMA-local vs cross-NUMA steals;
- queue depth and worker utilization;
- target-discovery latency;
- provenance/telemetry overhead when enabled.

These metrics exist to improve scheduling and optimization, not merely for reporting.

---

# Phase 0 — Repository, Contracts, and Measurement Baseline

## Build

- Cargo workspace matching `ARCHITECTURE.md` crate boundaries.
- CI for formatting, clippy, unit tests, and benchmark smoke tests.
- Versioned JSON metrics schema.
- Reference benchmark harness capable of running Angryier and comparison engines under equivalent limits.
- Initial micro-binary corpus with source/build scripts.
- Architecture/semantics support-manifest schema.
- Performance counters for the hot-path boundaries listed above.

## Exit criteria

- reproducible benchmark command from a clean checkout;
- host CPU, microcode, kernel, compiler, solver, affinity, NUMA, build flags, and binary hashes recorded;
- baseline comparison runs detect meaningful regressions;
- benchmark results separate executor, solver, scheduler and persistence costs.

---

# Phase 1 — Loader + Intel 64 Decode + Handwritten Semantic Corpus

## Build

- ELF64 loader;
- PE32+ loader;
- architecture-neutral core trait;
- Intel 64 register/feature model;
- Intel XED FFI adapter;
- safe normalized XED metadata boundary;
- normalized `DecodedInstruction` representation owned by Angryier;
- representative handwritten semantic corpus;
- minimal AngryIR lowering;
- concrete interpreter;
- block cache keyed by image/address/code/semantic identity.

## Corpus requirements

The handwritten corpus must exercise:

- scalar integer and flags;
- partial-register semantics;
- branches;
- memory operations;
- shifts/rotates;
- scalar FP;
- packed SIMD;
- AVX upper-lane behavior;
- AVX-512 masking;
- gather/scatter and VSIB;
- representative AMX configuration/tile operations;
- representative APX modifiers.

## Exit criteria

- curated concrete blocks match reference/native results where applicable;
- unsupported forms fail explicitly;
- XED decode support is never conflated with semantic support;
- the semantic representation covers every semantic shape in the representative corpus.

---

# Phase 2 — Typed Values + Symbolic Expression Core

## Build

- compact `ExprId` arena;
- structural hashing/hash-consing;
- cheap hot-path canonicalization;
- deeper offline canonicalization;
- constant folding;
- dependency metadata;
- solver-independent expression fingerprints;
- bitvector, floating-point, vector, opmask and tile domains;
- lazy lane/tile symbolic materialization;
- symbolic register support;
- initial shared-immutable arena strategy with instrumentation for atomic/refcount overhead.

## Exit criteria

- identical subexpressions intern consistently;
- simplifier property tests preserve semantics;
- vector/mask/tile values round-trip through canonical representation;
- expression statistics expose allocation, reuse and contention costs;
- expression sharing does not introduce a global hot lock.

---

# Phase 3 — COW Memory + Persistent State

## Build

- page-based concrete backing;
- sparse symbolic overlays;
- symbolic/taint bitmap;
- copy-on-write page ownership;
- compact COW register file;
- persistent constraint lineage;
- state fork primitive;
- explicit worker/state ownership metadata;
- code-page versions for self-modifying-code/JIT invalidation;
- state/fidelity metadata slots.

## Exit criteria

- fork cost is close to O(1) in unchanged mapped-memory size;
- sibling states share unchanged pages;
- one symbolic byte does not materialize an entire page symbolically;
- state transfer between workers does not require deep copying;
- COW and state-fork costs are measurable under multicore pressure.

---

# Phase 4 — Solver Backends + Canonical Query Layer

## Build

- backend-independent solver trait;
- Z3 backend;
- Bitwuzla backend;
- per-worker incremental contexts;
- SAT/UNSAT/UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR outcomes;
- solver-independent canonical query representation;
- exact canonical query fingerprint;
- hard query timeouts;
- cancellation/preemption boundary;
- normalized local query cache;
- shared-context batched-query API;
- basic DFS/BFS exploration.

## Exit criteria

- branch feasibility agrees with reference expectations;
- satisfying inputs reproduce native paths;
- UNKNOWN/timeout is never silently converted to UNSAT;
- Z3 and Bitwuzla are interchangeable at the engine boundary for supported theories;
- canonical-equivalent queries obtain identical authoritative identities;
- solver time, rebuild time and executor time are separately measurable.

---

# Phase 5 — Native Multicore + NUMA Scheduler

This is a core competitive milestone, not optional scalability polish.

## Build

- fixed-size native worker pool;
- explicit single-worker mutable ownership of each runnable state;
- worker-local deques;
- NUMA-group queues;
- global emergency queue;
- locality-first work stealing;
- per-worker solver contexts and hot caches;
- solver-context affinity for fork descendants;
- scheduler policy trait;
- memory-working-set-aware migration cost;
- solver rebuild/cache/NUMA migration cost model;
- memory-pressure-aware stealing;
- deterministic single-thread baseline;
- scheduler performance instrumentation.

Steal decisions should approximate:

```text
steal benefit =
    expected load-balancing gain
    - solver rebuild cost
    - cache locality loss
    - state working-set migration cost
    - NUMA penalty
```

## Exit criteria

- deterministic single-thread results match Phase 4;
- bounded N-thread runs reach the same expected solution set;
- no global mutex exists on the normal execution/solver path;
- branch-parallel workloads scale usefully across physical cores;
- local steals outperform cross-NUMA steals where expected;
- solver-context affinity measurably reduces rebuild work on appropriate workloads;
- scheduler instrumentation identifies contention and poor migration decisions.

---

# Phase 6 — Concrete/Taint Fast Path + Symbolic Promotion

## Build

- cheap taint/dataflow domain;
- taint propagation through canonical semantics/AngryIR;
- concrete-to-symbolic promotion policy;
- concrete-only path with zero symbolic-node allocation where possible;
- PROVE / EXPLORE / HUNT profiles;
- per-state fidelity ledger.

## Exit criteria

- mostly concrete workloads create materially fewer symbolic nodes than always-symbolic execution;
- concrete/taint paths outperform equivalent always-symbolic execution;
- PROVE rejects unsupported approximation;
- EXPLORE/HUNT approximations remain explicitly identified.

---

# Phase 7 — Semantic Generator + Broad Intel 64 Coverage

## Build

- versioned semantic-definition schema;
- semantic compiler/generator;
- deterministic generated output;
- support manifest;
- generated form tests;
- handwritten override mechanism;
- CI regeneration/diff gate.

## Target families

```text
scalar Intel 64
SSE through SSE4.x
AES/SHA/BMI-class extensions
AVX
AVX2
AVX-512
AVX-VNNI
AVX10
AMX
CET
APX
```

## Exit criteria

- generated and handwritten semantics use one validation pipeline;
- families are advertised only after required forms pass validation;
- host feature absence never removes software target semantics;
- representative semantic families can be expanded without hand-writing every form.

---

# Phase 8 — Solver Reuse, Slicing, and Preemption

## Build

- dependency-driven constraint slicing;
- exact query reuse across sibling states;
- incremental-context reuse;
- solver cancellation/preemption;
- portfolio routing by query shape and historical performance;
- cross-check policies for selected queries;
- exact SAT/UNSAT/model cache;
- UNSAT-core reuse;
- alpha-equivalence experiments;
- implication/subsumption/generalized UNSAT experiments;
- cache-admission policy based on estimated future value.

A basic example of useful generalized reuse:

```text
A ∧ B ∧ C = UNSAT
```

may authorize skipping a solver call for compatible supersets such as:

```text
A ∧ B ∧ C ∧ D ∧ E
```

when the exact validity and implication conditions are satisfied.

## Exit criteria

- sliced and unsliced queries are equivalent on the correctness corpus;
- exact reuse never crosses a validity domain;
- generalized UNSAT reuse is independently validated;
- preemption reduces pathological solver wall time;
- cumulative reuse measurably reduces query count and total solver time;
- cache storage/lookup cost is below the recomputation cost it is intended to avoid.

---

# Phase 9 — Optional, Highly Recommended QIHSE + KEYSTONE Submodules

Angryier must remain fully usable without either repository. These integrations are optional because core symbolic execution must not depend on external persistence or retrieval systems.

They are nevertheless **highly recommended** for repeated analysis, large corpora, similarity searching, exact artifact lookup and cumulative knowledge.

## Intended Git submodules

```text
external/QIHSE
  https://github.com/SWORDIntel/QIHSE.git

external/KEYSTONE
  https://github.com/SWORDIntel/KEYSTONE.git
```

The existing adapter crates remain the Angryier-facing boundary:

```text
crates/angryier-qihse/
crates/angryier-keystone/
```

Core execution crates must not depend directly on submodule implementation details. Integrations should be Cargo-feature gated and removable from a minimal build.

## QIHSE role

Use QIHSE as the optional persistent knowledge and similarity/retrieval system, including where useful:

- semantic similarity search;
- constraint/path/function similarity;
- prior-analysis candidate retrieval;
- fused-vector / quantum-inspired similarity lookup;
- historical finding correlation;
- cross-run candidate discovery;
- graph/document/time-series knowledge where warranted.

Similarity is advisory. Exact identities and validity checks remain authoritative.

## KEYSTONE role

Use KEYSTONE as the optional ingestion/indexing/retrieval accelerator for:

- exact artifact lookup;
- ingestion pipelines;
- indexing canonical identities;
- fast candidate retrieval;
- metadata lookup;
- linking exact artifacts to QIHSE similarity candidates.

## Build

- optional `.gitmodules` entries when integration implementation begins;
- feature-gated adapter crates;
- asynchronous/batched execution-event bridge;
- local buffering/spooling fallback;
- exact validity-key lookup;
- similarity candidate API;
- persistence-disabled mode requiring neither repository.

## Exit criteria

- removing both submodules still leaves a functional Angryier engine;
- enabling them does not add synchronous database work to execution workers;
- exact prior-run artifacts can be found by validity key;
- similarity search returns useful candidates on repeated/correlated corpora;
- QIHSE/KEYSTONE candidate matches never bypass exact validation before correctness-affecting reuse.

---

# Phase 10 — Search Intelligence and State Economics

## Build

- composable search objective;
- coverage novelty;
- target distance;
- taint relevance;
- solver-cost estimate;
- uncertainty/fidelity signals;
- loop accounting;
- analyst-specified targets;
- multifactor state-merge cost model;
- learned ranking as an optional advisory layer;
- scheduler-performance history feeding ranking/routing decisions.

## Exit criteria

- search objectives can be benchmarked independently;
- learned ranking can be disabled;
- deterministic policies remain available;
- target-oriented corpora show reduced time-to-interest compared with baseline DFS/BFS where applicable;
- merge decisions reduce state count without causing solver-expression blowups that erase the gain.

---

# Phase 11 — Learned Fusion Retrieval

This phase is most useful when the optional QIHSE/KEYSTONE integrations are enabled, but the encoders themselves must remain separable from core execution.

## Build

Specialist encoders for:

- semantic/AngryIR structure;
- CFG/path topology;
- constraint DAGs;
- taint/dataflow;
- dynamic/memory behavior;
- solver profile;
- findings/context.

Then build:

- missing-modality masks;
- learned gated/attention-style fusion;
- default 1024-D fused representation;
- optional 384/2048/4096-D profiles;
- similarity retrieval through QIHSE where enabled;
- exact-validation stage after similarity retrieval.

## Exit criteria

- held-out retrieval quality beats simple structural baselines where claimed;
- similarity computation has bounded cost;
- approximate matches never bypass exact validation;
- retrieval produces measurable analysis benefit rather than only visually plausible neighbors.

---

# Phase 12 — Adaptive Provenance and Flight Recorder

Provenance is retained because it improves debugging and analyst insight, but implementation should remain proportional to measured value.

## Build

- Tier 0/1/2 event schema;
- Tier 1 structural provenance;
- per-worker circular flight recorder;
- Tier 2 triggers;
- structural repetition summarization;
- post-processing canonicalization/deduplication;
- bounded asynchronous transport.

## Exit criteria

- Tier 1 reconstructs state/constraint/finding lineage;
- configured interest events retain useful pre-trigger context;
- repetitive traces compress substantially;
- provenance overhead remains measurable and bounded.

---

# Phase 13 — JIT / Specialized Concrete Execution

## Build only if profiling justifies it

Potential maturity path:

```text
cold block -> compact interpreter
warm block -> specialized cached executor
hot block  -> native translation
```

Requirements:

- symbolic/taint transition hooks;
- memory permission checks;
- code-page version guards;
- targeted self-modifying-code invalidation;
- host-feature guards;
- software semantic fallback.

## Exit criteria

- JIT and interpreter are semantically equivalent on the differential suite;
- compile/cache overhead is exposed;
- end-to-end performance improves on concrete-heavy classes.

---

# Phase 14 — Hybrid Fuzzing + Environment Models

## Build

- versioned syscall/library/environment models;
- deterministic summary contracts;
- testcase import/export;
- coverage/seed exchange;
- constraint and target-hint exchange after simpler integration proves stable;
- bidirectional hybrid fuzzing interface.

## Exit criteria

- symbolic execution produces useful seeds for fuzzing;
- fuzzer discoveries can seed targeted symbolic exploration;
- hybrid operation beats either engine alone on at least one representative corpus before additional complexity is accepted.

---

# Phase 15 — API Stabilization, Packaging, and Optional Distribution Seam

## Build

- stable Rust library API;
- CLI documentation;
- optional PyO3 bindings;
- reproducible release builds;
- versioned support manifests;
- benchmark report generation;
- serialization boundaries for future multi-host work units.

Multi-host execution is not required for initial production readiness; only the serialization boundary is reserved.

---

# Production 1.0 Definition

Production 1.0 requires:

1. ELF64 and PE32+ loading for the declared scope;
2. Intel 64 XED decoding with explicit semantic-support manifest;
3. production semantic coverage for declared Intel extension families;
4. concrete/taint/concolic/symbolic execution;
5. COW state and sparse symbolic memory;
6. Z3 + Bitwuzla solver support;
7. canonical solver-query identities and exact reuse;
8. native multicore exploration with worker/state ownership and useful physical-core scaling;
9. NUMA-aware work placement where applicable;
10. solver affinity, timeout and preemption;
11. search policies demonstrably better than simple baselines on at least some target classes;
12. reproducible correctness and performance reports.

The following are **recommended but not mandatory for a minimal Production 1.0 engine**:

- QIHSE submodule integration;
- KEYSTONE submodule integration;
- persistent cross-run similarity search;
- learned-fusion retrieval;
- JIT;
- distributed execution;
- GUI;
- additional ISAs;
- AI-assisted search.

A recommended full-feature profile should enable QIHSE + KEYSTONE because cumulative exact lookup and similarity retrieval are expected to become increasingly valuable as the analysis corpus grows.

---

# Go / No-Go Gates

## Gate A — after Phase 4

Proceed only if symbolic results are correct and canonical solver identities are stable.

## Gate B — after Phase 5

Proceed only if branch-parallel workloads show useful multicore scaling. Otherwise investigate allocator contention, shared-object lifetime overhead, solver-context migration, queue policy, cache locality and NUMA placement before adding major features.

## Gate C — before generalized solver reuse

Do not allow alpha-equivalence, implication or subsumption results to suppress solver work until exact canonical-query reuse is proven correct.

## Gate D — before broad generated semantics

Do not build a giant semantic DSL until the handwritten corpus demonstrates the required semantic shapes.

## Gate E — before QIHSE/KEYSTONE become recommended in deployment defaults

They must show measurable value in exact lookup, similarity retrieval, repeated-analysis latency or analyst discovery without putting synchronous persistence on the execution hot path.

## Gate F — before learned fusion influences scheduling

Similarity retrieval must demonstrate useful precision/recall and remain advisory.

## Gate G — before JIT

JIT proceeds only if profiling shows concrete execution remains a material wall-time component.

## Gate H — before another ISA

Do not allow AArch64/RISC-V work to substitute for proving the Intel 64 performance, correctness and reuse thesis.
