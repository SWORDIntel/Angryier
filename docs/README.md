# Angryier Documentation

> **Architecture frozen. Implementation in progress.**
> Phases 0–3 and Phase 5 foundations are implemented. Phase 4 (handwritten semantic corpus) is the next active phase.

## Navigation

### Architecture

The complete frozen three-plane system architecture, split by subsystem.

| Document | Description |
|---|---|
| [overview](architecture/overview.md) | Mission, non-goals, global invariants, three-plane architecture |
| [crates](architecture/crates.md) | 32-crate workspace map, implementation status per crate, dependency direction |
| [identity](architecture/identity.md) | Shared identity model, version domains, architecture abstraction, Intel 64 target profiles |
| [decode](architecture/decode.md) | Intel XED decode boundary, normalized representation |
| [semantic-pipeline](architecture/semantic-pipeline.md) | Hybrid semantic definition, two-level IR, sealing, dual identity, structured vector/mask/AMX, floating-point |
| [execution](architecture/execution.md) | Runtime values, expression DAG, layered memory, persistent state, fidelity profiles, environment models, summaries, state merging |
| [solver](architecture/solver.md) | Solver architecture, query model, portfolio scheduling, persistent solver knowledge, reuse hierarchy |
| [scheduler](architecture/scheduler.md) | Search, multicore, NUMA, quantum-inspired batch scheduling, work stealing |
| [provenance](architecture/provenance.md) | Provenance tiers, flight recorder, trace governor, telemetry transport, WAL, retention |
| [ledger-replay](architecture/ledger-replay.md) | Atomic execution ledger, deterministic replay capsules, self-modifying code invalidation |
| [knowledge](architecture/knowledge.md) | QIHSE/KEYSTONE, cumulative knowledge, dependency invalidation, learned fusion, retrieval-to-reuse pipeline |
| [jit-fuzzing-distribution](architecture/jit-fuzzing-distribution.md) | JIT/native acceleration, bidirectional fuzzing, multi-host boundary, plugin model |
| [security](architecture/security.md) | Trust boundaries, failure containment, observability, stress scenarios, architecture freeze rule |
| [performance](architecture/performance.md) | Performance-oriented design: sharding, lock-free reads, inline values, sparse memory, lowered-block cache |

### Design

Locked design decisions and Rust trait/ownership boundaries.

| Document | Description |
|---|---|
| [decisions](design/decisions.md) | 28 locked design decisions (D-001 through D-028) and open decisions |
| [trait-boundaries](design/trait-boundaries.md) | Concrete Rust ownership map, decode/semantic/state/solver/ledger/knowledge boundaries, required architecture tests |

### Semantics

Intel 64 semantic architecture and identity contracts.

| Document | Description |
|---|---|
| [intel64](semantics/intel64.md) | Decode layer, host vs target, semantic development sequence, canonical representation, first-class types, AVX/AVX-512/AMX rules, validation strategy, production support gate |
| [identity](semantics/identity.md) | ContentId vs SemanticFingerprint, validation flow, versioning, required invariants, stress tests |

### Status

Current implementation state and implementation order.

| Document | Description |
|---|---|
| [scaffold](status/scaffold.md) | Per-crate implementation status, what's implemented vs scaffolded, test coverage |
| [implementation-plan](status/implementation-plan.md) | Phase-by-phase implementation order with exit gates (Phases 0–16) |

### Top-level

| Document | Description |
|---|---|
| [ROADMAP](ROADMAP.md) | Broader implementation roadmap, competitive performance mandate, go/no-go gates |
| [BENCHMARKING](BENCHMARKING.md) | Performance, semantic correctness, provenance, cumulative reuse, and retrieval benchmark contract |

### Root

| Document | Description |
|---|---|
| [Plan.md](../Plan.md) | Operational architecture lock and Q9–Q54 decision baseline |
| [README.md](../README.md) | Project overview and design thesis |
