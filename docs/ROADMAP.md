# Angryier Implementation Roadmap

This roadmap is ordered to establish semantic correctness and measurable execution first, then add scale, provenance, cumulative knowledge, generation, and advanced optimization.

A phase advances only when its exit criteria are satisfied.

---

# Phase 0 — Repository, Contracts, and Measurement Baseline

## Build

- Cargo workspace matching `ARCHITECTURE.md` crate boundaries.
- CI for formatting, clippy, unit tests, sanitizers where applicable, and benchmark smoke tests.
- Versioned JSON metrics schema.
- Reference benchmark harness capable of running Angryier and comparison engines under equivalent limits.
- Initial micro-binary corpus with source/build scripts.
- Architecture/semantics support-manifest schema.
- Decision-log enforcement: implementation PRs that change locked architecture must update `DESIGN_DECISIONS.md`.

## Exit criteria

- Reproducible benchmark command from a clean checkout.
- Host CPU, microcode, kernel, compiler, solver, affinity, NUMA, build flags, and binary hashes are recorded.
- Baseline comparison runs are reproducible enough to detect meaningful regressions.

---

# Phase 1 — Loader + Intel 64 Decode + Handwritten Semantic Corpus

## Build

- ELF64 loader.
- PE32+ loader.
- architecture-neutral core trait.
- Intel 64 register/feature model.
- Intel XED FFI adapter.
- normalized `DecodedInstruction` representation owned by Angryier.
- first canonical semantic representation.
- representative handwritten instruction-semantic corpus.
- minimal AngryIR lowering.
- concrete interpreter.
- block cache keyed by image/address/code/semantic identity.

## Corpus requirements

The handwritten set must exercise:

- scalar integer and flags;
- partial-register semantics;
- branches;
- memory operations;
- shifts/rotates;
- scalar FP;
- packed SIMD;
- AVX upper-lane behavior;
- AVX-512 masking;
- representative gather/scatter;
- representative AMX configuration/tile operation.

## Exit criteria

- curated concrete blocks match reference/native results where applicable.
- unsupported instruction forms fail explicitly.
- XED decode support is not conflated with semantic support.
- the semantic representation is expressive enough to cover every semantic shape in the representative corpus.

---

# Phase 2 — Typed Values + Symbolic Expression Core

## Build

- compact `ExprId` arena.
- structural hashing/hash-consing.
- canonicalization and constant folding.
- dependency metadata.
- solver-independent expression fingerprints.
- runtime domains for:
  - bitvectors;
  - floating point;
  - vectors;
  - opmasks;
  - tiles.
- lazy lane/tile symbolic materialization.
- symbolic register support.

## Exit criteria

- identical subexpressions intern consistently.
- simplifier property tests preserve semantics.
- structured vector/mask/tile values round-trip through the selected canonical representation.
- expression statistics are exposed in metrics.

---

# Phase 3 — COW Memory + Persistent State

## Build

- page-based concrete backing.
- sparse symbolic overlays.
- symbolic/taint bitmap.
- copy-on-write page ownership.
- compact COW register file.
- persistent constraint lineage.
- state fork primitive.
- state/fidelity metadata slots even before full provenance implementation.

## Exit criteria

- fork cost is close to O(1) in unchanged mapped-memory size.
- sibling states share unchanged pages.
- one symbolic byte does not materialize an entire page symbolically.
- state destruction is leak-free under stress.

---

# Phase 4 — Solver Backends + Exact Path Exploration

## Build

- backend-independent solver trait.
- Z3 backend.
- Bitwuzla backend.
- per-worker incremental context abstraction.
- SAT/UNSAT/UNKNOWN/model APIs.
- hard query timeouts.
- normalized local query cache.
- shared-context batched-query API.
- basic DFS/BFS exploration.

## Exit criteria

- branch feasibility agrees with reference expectations on the symbolic micro-corpus.
- generated satisfying inputs reproduce the target native path.
- UNKNOWN/timeout is never silently converted to UNSAT.
- Z3 and Bitwuzla are interchangeable at the engine boundary for supported theories.
- solver time and executor time are separately measurable.

---

# Phase 5 — Native Parallel Scheduler

## Build

- fixed-size worker pool.
- local deque + work stealing.
- per-worker solver contexts and hot caches.
- deterministic single-thread mode.
- scheduler policy trait.
- locality/affinity metadata.
- migration-cost estimate including solver rebuild, cache locality, and NUMA cost.
- scheduler telemetry.

## Exit criteria

- deterministic single-thread results match Phase 4.
- bounded N-thread tests reach the same solution set.
- no global mutex is present on the normal solver/execution path.
- branch-parallel workloads show useful scaling across physical cores.
- migrations and solver-context rebuild costs are observable.

---

# Phase 6 — Concrete/Taint Fast Path + Fidelity Profiles

## Build

- cheap taint/dataflow domain.
- taint propagation through canonical semantics/AngryIR.
- concrete-to-symbolic promotion policy.
- concrete-only path with zero symbolic-node allocation where possible.
- PROVE / EXPLORE / HUNT profiles.
- per-state fidelity ledger.
- explicit approximation/concretization events.

## Exit criteria

- mostly concrete workloads create materially fewer symbolic nodes than always-symbolic execution.
- PROVE rejects unsupported/approximate behavior rather than guessing.
- EXPLORE/HUNT approximations appear explicitly in result provenance.
- findings inherit fidelity history.

---

# Phase 7 — Adaptive Provenance and Flight Recorder

## Build

- Tier 0/1/2 event schema.
- Tier 1 structural provenance.
- per-worker circular pre-trigger flight recorder.
- Tier 2 trigger system.
- trace-governor scoring and hysteresis.
- structural repetition summarization.
- post-processing canonicalization/deduplication/causal extraction.
- retention profiles.
- quarantine-before-purge cleanup state.
- optional human approval workflow boundary.

## Exit criteria

- Tier 1 reconstructs state/constraint/finding lineage without instruction-level logging.
- crashes and other configured interest events retain pre-trigger context.
- repetitive Tier 2 regions decay automatically and compress substantially.
- provenance overhead is measured and bounded.
- cleanup actions are themselves auditable provenance.

---

# Phase 8 — Semantic Generator and Broad Intel 64 Coverage

## Build

- versioned semantic-definition schema/DSL.
- semantics compiler/generator.
- generated deterministic output.
- generated support manifest.
- generated instruction-form tests.
- explicit handwritten override mechanism.
- CI regeneration/diff gate.
- progressive family coverage for modern Intel extensions.

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

- generated and handwritten semantics use the same validation pipeline.
- a family is advertised only when its required form coverage passes the production support gate.
- host feature absence does not remove software target semantics.
- semantic disagreement artifacts are reproducible and persisted through the later knowledge-plane interface.

---

# Phase 9 — QIHSE / KEYSTONE Knowledge Plane

## Build

- asynchronous/batched engine event bridge.
- local buffering/spooling fallback.
- QIHSE artifact schema.
- KEYSTONE exact indexing/lookup path.
- graph storage for state/constraint/taint/finding lineage.
- document storage for findings/configuration.
- time-series telemetry storage.
- security-context inheritance.
- knowledge validity-key framework.
- knowledge-state lifecycle (`VALID`, `REVALIDATION_REQUIRED`, `ADVISORY_ONLY`, etc.).

## Exit criteria

- persistence can be disabled without changing execution semantics.
- QIHSE/KEYSTONE outages do not synchronously stall workers beyond configured bounded backpressure behavior.
- exact prior-run artifacts can be located by validity key.
- protected/classified writes fail closed when required authenticated context is unavailable.

---

# Phase 10 — Cumulative Solver and Semantic Reuse

## Build

- persistent exact SAT/UNSAT/model cache.
- UNSAT-core storage/reuse.
- alpha-equivalence canonicalization experiments.
- implication/subsumption/generalized fact schema.
- branch/function/loop summary schema.
- generalized-fact verification policy by fidelity profile.
- historical solver-performance records.
- solver-routing experiments based on measured query shape.

## Exit criteria

- exact reuse never crosses an invalid validity domain.
- stale facts become advisory/revalidation-required rather than silently reused.
- generalized facts used by PROVE meet configured verification requirements.
- cumulative reuse produces measurable solver-time/query-count reductions on repeated/correlated corpora.

---

# Phase 11 — Learned Fusion Retrieval

## Build

Specialist encoders for available modalities, including:

- semantic/AngryIR structure;
- CFG/path topology;
- constraint DAGs;
- taint/dataflow;
- dynamic/memory behavior;
- solver profile;
- fidelity/provenance;
- findings/context;
- analyst/context.

Then build:

- explicit missing-modality masks;
- learned gated/attention-style fusion layer;
- default 1024-D fused representation;
- optional 384/2048/4096-D profiles;
- QIHSE quantum-inspired/vector retrieval integration;
- modality contribution/explanation metadata;
- exact-validation stage after similarity retrieval.

## Exit criteria

- retrieval quality is evaluated on held-out semantic similarity tasks.
- 1024-D is compared empirically against smaller/larger profiles.
- approximate matches never bypass exact validity checks for authoritative reuse.
- similarity explanations identify the major contributing modalities.
- retrieval compute/storage cost is reported alongside quality gains.

---

# Phase 12 — Solver Optimization, Slicing, and Search Controls

## Build

- dependency-driven constraint slicing.
- normalized query reuse across sibling states.
- portfolio/cross-check policies.
- solver-cost-aware scheduling.
- coverage novelty.
- target distance.
- loop accounting.
- conservative optional state merging.
- merge cost model.

## Exit criteria

- sliced/unsliced queries are equivalent on the correctness corpus.
- state merging is optional and measurable.
- heuristics can be disabled.
- approximation/pruning modes remain explicitly marked.

---

# Phase 13 — JIT / Specialized Concrete Execution

## Build only if profiling justifies it

Potential maturity path:

```text
cold block -> compact interpreter
warm block -> specialized cached executor
hot block  -> Cranelift/native translation
```

Requirements:

- symbolic/taint transition hooks;
- memory permission checks;
- self-modifying-code invalidation;
- host-feature guards;
- software semantic fallback.

## Exit criteria

- JIT and interpreter are semantically equivalent on the differential suite.
- compile/cache overhead is exposed.
- end-to-end performance improves on designated concrete-heavy classes.

---

# Phase 14 — Environment Models, Fuzzing Integration, and Optional AI Advisor

## Build

- versioned syscall/library/environment-model framework.
- deterministic summary contracts.
- hybrid fuzzing boundary.
- import/export of concrete testcases/coverage.
- optional AI/agent search/triage advisor behind an advisory-only interface.

## Rules

- environment models participate in validity keys.
- model approximations enter the fidelity ledger.
- AI/LLM outputs never enter trusted instruction semantics or PROVE truth without machine validation.

---

# Phase 15 — API Stabilization and Packaging

## Build

- stable Rust library API.
- CLI documentation.
- optional PyO3 bindings.
- reproducible release builds.
- versioned support manifests.
- benchmark report generation.
- knowledge-schema migration/version policy.

---

# Production 1.0 Definition

Production 1.0 is not reached by merely executing a few symbolic binaries.

It requires:

1. ELF64 and PE32+ load/replay support for the declared scope;
2. Intel 64 XED decoding with explicit semantic-support manifest;
3. production semantic coverage for the declared Intel extension families, including AVX, AVX2, AVX-512 and AMX;
4. concrete/taint/concolic/symbolic execution;
5. COW state and sparse symbolic memory;
6. Z3 + Bitwuzla solver support;
7. native multicore exploration;
8. PROVE/EXPLORE/HUNT fidelity profiles;
9. adaptive Tier 1/Tier 2 provenance;
10. QIHSE/KEYSTONE cumulative knowledge integration;
11. exact cross-run reuse with validity keys;
12. learned-fusion advisory retrieval with exact validation before authoritative reuse;
13. successful native replay of generated testcases/findings where applicable;
14. reproducible correctness and performance reports.

JIT, distributed execution, GUI, additional ISAs, and AI-assisted search are not prerequisites unless later evidence promotes them.

---

# Go / No-Go Gates

## Gate A — after Phase 4

Proceed only if symbolic results are correct and solver boundaries are stable.

## Gate B — after Phase 5

Proceed only if branch-parallel workloads show useful multicore scaling. Otherwise investigate allocator contention, solver-context migration, cache locality, and NUMA before adding major features.

## Gate C — after Phase 7

Proceed only if provenance gives substantially greater causal insight without destroying execution throughput.

## Gate D — before broad generated semantics

Do not build a giant DSL until the handwritten corpus has demonstrated the required semantic shapes.

## Gate E — before cumulative reuse can suppress work

Validity keys and stale-knowledge handling must be proven first.

## Gate F — before learned fusion influences scheduling

Similarity retrieval must show useful precision/recall and must remain advisory.

## Gate G — before JIT

JIT proceeds only if profiling shows concrete execution remains a material wall-time component.

## Gate H — before another ISA

Do not allow AArch64/RISC-V work to substitute for proving the Intel 64 performance, correctness, and knowledge-reuse thesis.
