# Angryier(WIP ETA 15 September) 

> When you are absolutely furious your symbolic execution is taking too long and you just can't stand it anymore and you're not just angry, you're **Angryier**.

Angryier is a native, multicore binary symbolic/concolic execution and program-analysis engine under active development in Rust.

The objective is broader than making angr-style workflows faster. Angryier is being designed to improve **speed, correctness, and analyst insight simultaneously**, while accumulating reusable knowledge across analyses rather than treating every run as disposable.

It is not an angr rewrite or API clone.

## Design Thesis

```text
Do not symbolically interpret work that can remain concrete.
Do not copy state that can be shared.
Do not serialize work that can execute independently.
Do not persist telemetry synchronously on the execution hot path.
Do not treat similarity as proof.
Do not advertise semantics that have not passed validation gates.
```

## Locked Direction

- **Rust-native core**; Python is optional and never in the hot path.
- Architecture-neutral engine traits with **Intel 64 as the first production backend**.
- **Intel XED** for Intel 64 decode and instruction-form/feature metadata.
- Host and target feature sets are separate: binaries remain analyzable even when the host lacks the target extension.
- Software semantics for modern Intel features, including **AVX, AVX2, AVX-512, AVX10, AMX, CET and APX** as coverage is validated.
- **Hybrid generated semantics**: representative handwritten corpus first, then a semantics compiler/generator plus handwritten overrides for complex families.
- Canonical typed semantic representation before compact execution lowering to **AngryIR**.
- Concrete → taint → symbolic promotion rather than eager symbolic expression construction.
- Arena-allocated, hash-consed expression DAGs using compact IDs.
- Page-based copy-on-write state with sparse symbolic memory overlays.
- Structured vector, opmask and AMX tile domains with lazy symbolic materialization.
- **Z3 + Bitwuzla** behind a backend-independent solver interface.
- Per-worker incremental solver state plus persistent generalized solver knowledge.
- Native, locality-aware **work stealing** with solver/cache/NUMA affinity considered in migration cost.
- **PROVE / EXPLORE / HUNT** fidelity profiles with mandatory per-state fidelity provenance.
- Adaptive tiered provenance: always-retained structural Tier 1 plus triggered Tier 2 flight-recorder traces.
- **QIHSE + KEYSTONE** as the native persistence/index/retrieval substrate, off the execution hot path.
- Cross-run cumulative knowledge with exact validity keys and stale-knowledge handling.
- Specialist semantic encoders feeding a **learned fusion model** for approximate retrieval.
- Default fused representation: **1024 dimensions**, with benchmarked profiles from 384 to 4096.
- Similarity retrieval is advisory until exact structural/validity checks succeed.
- JIT/native block translation only after profiling proves it is justified.

## Three-Plane Architecture

```text
                           ANGRYIER
                              |
            +-----------------+-----------------+
            |                 |                 |
            v                 v                 v
      EXECUTION PLANE      TRUTH PLANE      KNOWLEDGE PLANE

      concrete/taint       semantics          QIHSE
      symbolic engine      validation         KEYSTONE
      COW state            fidelity           graph lineage
      worker solvers       replay             exact reuse
      scheduler            support manifest   learned retrieval
```

### Execution plane

Optimized state, memory, expression, solver and scheduling machinery. Persistence is asynchronous/batched and must not sit directly in the worker hot path.

### Truth plane

Defines semantic truth, validation, replay, target-feature assumptions, support coverage and fidelity/approximation history.

### Knowledge plane

Persists exact artifacts, solver facts, state/constraint/taint lineage, analyst knowledge, prior-run summaries and learned semantic similarity so later analyses can reuse validated previous work.

## Intel 64 Semantic Pipeline

```text
Intel XED decoded form
        +
Angryier semantic definitions
        +
handwritten overrides
        |
        v
semantics compiler / generator
        |
        v
canonical typed semantics
        |
        +--> concrete evaluation
        +--> taint
        +--> AngryIR
        +--> symbolic execution
        +--> generated tests
        +--> support manifest
```

XED is the decoder, not the semantics engine.

## Fidelity Profiles

```text
PROVE    exact-only policy; no silent approximation
EXPLORE  conservative approximation with explicit provenance
HUNT     aggressive bug-hunting policy; approximate results never presented as proof
```

Every finding inherits the fidelity history that made it possible.

## Adaptive Provenance

```text
Tier 0  transient worker-local execution detail
Tier 1  always-retained structural provenance
Tier 2  deep trace around interesting events
```

Each worker maintains a bounded pre-trigger flight recorder. Tier 2 activates on high-value events such as crashes, new symbolic behavior, solver anomalies or semantic uncertainty, then automatically decays when output becomes repetitive/high-volume/low-novelty.

Post-processing compacts before deleting. Ambiguous destructive cleanup may require human approval and supports quarantine-before-purge.

## Cumulative Knowledge

Angryier is designed to become more useful across runs.

Authoritative reuse may include:

```text
exact SAT/UNSAT results
models
UNSAT cores
validated branch/function summaries
canonical semantic facts
```

Advisory retrieval may identify:

```text
similar functions
similar constraints
similar paths
similar taint flows
similar findings
historically useful solver/search strategies
```

A similarity hit proposes a candidate. Exact machinery decides whether it is reusable.

## Learned Fusion Retrieval

The locked design is **specialist encoders + learned fusion**.

```text
IR/semantics
CFG/path
constraint DAG
taint/dataflow
memory/dynamic behavior
solver profile
provenance/fidelity
finding/context
analyst/context
      |
      v
masked/gated learned fusion
      |
      v
1024-D default semantic representation
```

All useful modalities may contribute. Missing modalities are explicitly masked.

QIHSE's quantum-inspired/vector retrieval layer stores the fused similarity representation, while canonical exact artifacts remain in KV/graph/document storage.

## Repository Blueprint

The architecture is frozen; the repository contains the complete **interface/contract scaffold** for all major subsystems, with real implementations in the foundation crates. A scaffolded crate reserves ownership and exposes the intended boundary. It does **not** imply that its backend is implemented.

The 32-crate workspace includes architecture/Intel 64, XED adaptation, semantics and generation, semantic identity/evidence, execution IR, expressions, memory, state, taint, execution, atomic ledger, replay, solver orchestration plus Z3/Bitwuzla seams, NUMA-aware scheduling, provenance, cumulative knowledge, learned fusion, environment models, loading/state import, fuzzing, telemetry, WAL/storage, JIT, QIHSE, KEYSTONE, plugins, benchmarking, CLI and future distribution boundaries.

See [`docs/architecture/crates.md`](docs/architecture/crates.md) for the full crate map with per-crate implementation status.

## Documentation

Full documentation index: [`docs/README.md`](docs/README.md)

### Architecture (split by subsystem)

- [`docs/architecture/overview.md`](docs/architecture/overview.md) — mission, non-goals, global invariants, three-plane architecture.
- [`docs/architecture/crates.md`](docs/architecture/crates.md) — 32-crate map, implementation status per crate, dependency direction.
- [`docs/architecture/identity.md`](docs/architecture/identity.md) — shared identity model, version domains, Intel 64 target profiles.
- [`docs/architecture/decode.md`](docs/architecture/decode.md) — Intel XED decode boundary.
- [`docs/architecture/semantic-pipeline.md`](docs/architecture/semantic-pipeline.md) — hybrid semantics, two-level IR, sealing, dual identity, vector/mask/AMX, floating-point.
- [`docs/architecture/execution.md`](docs/architecture/execution.md) — runtime values, expression DAG, layered memory, persistent state, fidelity profiles.
- [`docs/architecture/solver.md`](docs/architecture/solver.md) — solver architecture, query model, portfolio, persistent knowledge.
- [`docs/architecture/scheduler.md`](docs/architecture/scheduler.md) — search, multicore, NUMA, quantum-inspired scheduling.
- [`docs/architecture/provenance.md`](docs/architecture/provenance.md) — provenance tiers, flight recorder, telemetry, WAL, retention.
- [`docs/architecture/ledger-replay.md`](docs/architecture/ledger-replay.md) — atomic ledger, replay capsules, code-page invalidation.
- [`docs/architecture/knowledge.md`](docs/architecture/knowledge.md) — QIHSE/KEYSTONE, cumulative knowledge, learned fusion, retrieval pipeline.
- [`docs/architecture/jit-fuzzing-distribution.md`](docs/architecture/jit-fuzzing-distribution.md) — JIT, fuzzing, multi-host, plugins.
- [`docs/architecture/security.md`](docs/architecture/security.md) — trust boundaries, failure containment, stress scenarios, freeze rule.

### Design

- [`docs/design/decisions.md`](docs/design/decisions.md) — 28 locked design decisions (D-001–D-028) and open decisions.
- [`docs/design/trait-boundaries.md`](docs/design/trait-boundaries.md) — Rust ownership map, interface contracts, required architecture tests.

### Semantics

- [`docs/semantics/intel64.md`](docs/semantics/intel64.md) — Intel 64 decode, typed semantics, generator plan, AVX/AVX-512/AMX, validation gates.
- [`docs/semantics/identity.md`](docs/semantics/identity.md) — `ContentId`, semantic fingerprints, derivation and validity rules.

### Status

- [`docs/status/scaffold.md`](docs/status/scaffold.md) — per-crate implementation status, what's implemented vs scaffolded, test coverage.
- [`docs/status/implementation-plan.md`](docs/status/implementation-plan.md) — phase-by-phase implementation order with exit gates.

### Top-level

- [`Plan.md`](Plan.md) — operational architecture lock and Q9–Q54 decision baseline.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — broader implementation roadmap and go/no-go gates.
- [`docs/BENCHMARKING.md`](docs/BENCHMARKING.md) — performance, semantic correctness, provenance, cumulative reuse and retrieval benchmark contract.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build/check instructions, architecture rules, code style, commit and PR conventions.

## Current Status

**Architecture frozen. Phases 0–3 and Phase 5 foundations implemented. Phase 4 (handwritten semantic corpus) partially implemented — 93 foundational Intel 64 forms verified end-to-end. Phase 6 foundations (replay, WAL, provenance), Phase 7 foundations (taint), Phase 9 foundations (knowledge, QIHSE/KEYSTONE, fusion, semantic compiler), Phase 10 foundations (scheduler, distribution codec), Phase 11 foundations (models, telemetry, benchmark, plugins, loader, fuzz), Phase 12 foundations (QIHSE/KEYSTONE adapters), Phase 13 foundations (fuzz bridge), Phase 14 foundations (fusion model), and Phase 16 foundations (work codec) partially implemented in-memory.**

Implemented: shared IDs/versions, ISA-neutral arch traits, Intel 64 register/feature model, XED normalization boundary, typed semantic IR with sealing, AngryIR lowering and verification, expression DAG with hash-consing and constant folding, layered COW memory, persistent state with fork, concrete interpreter, solver-neutral query model with portfolio router and batch solver, atomic ledger with concurrent commit validation, handwritten Intel 64 semantic corpus (93 forms with RFLAGS ZF/SF/CF), in-memory replay engine + capsule store, in-memory taint engine with promotion, in-memory provenance store with adaptive governor, in-memory WAL with checkpoint replay, in-memory work-stealing scheduler with NUMA model, in-memory knowledge store with dependency graph, in-memory environment model + summary provider, in-memory telemetry sink with metric aggregation, in-memory image loader + state importer, in-memory fuzz bridge with stage gating, in-memory fusion model with specialist encoders, in-memory QIHSE adapter with fingerprint query, in-memory KEYSTONE adapter with inverted index, in-memory work codec with binary frame round-trip, in-memory plugin registry, in-memory benchmark sink with summary, in-memory semantic compiler with coverage manifest, in-memory semantic transformation contracts with fidelity acceptance policy, basic CLI with status/crates/version subcommands, **native Z3 solver FFI** (`angryier-solver-z3-ffi`, real SAT/UNSAT with model extraction; wired into safe `angryier-solver-z3` adapter behind `ffi` feature via `Z3Backend::native_ffi`), **native Bitwuzla solver FFI** (`angryier-solver-bitwuzla-ffi`, real SAT/UNSAT with model extraction; wired into safe `angryier-solver-bitwuzla` adapter behind `ffi` feature via `BitwuzlaBackend::native_ffi`), **native Intel XED decoder FFI** (`angryier-arch-xed-ffi`, real Intel 64 instruction decoding; wired through `angryier-decode-xed` safe normalization boundary).

Scaffolded (fail-closed): full Intel semantic corpus, durable WAL/persistence, native QIHSE/KEYSTONE SDK bindings, learned embedding training, native JIT, fuzzer-specific adapters, live process capture, distributed scheduler.

The repository intentionally does not fake missing native backends. All unimplemented integrations must fail explicitly until real implementations exist. See [`docs/status/scaffold.md`](docs/status/scaffold.md) for details.

Repository checks are defined by `scripts/check.sh` and `.github/workflows/ci.yml`: formatting, workspace compilation, Clippy with warnings denied, and tests. All 78 test suites pass (0 failures, 585 tests total).

## Performance Policy

Angryier does not claim a universal `10x`, `50x` or `100x` advantage.

Performance, semantic coverage, fidelity and knowledge-reuse improvements must be measured separately on named reproducible workload classes. Any speedup obtained by silently weakening semantics is invalid.
