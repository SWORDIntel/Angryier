# Angryier Documentation

> **[ROADMAP.md](ROADMAP.md) is the single source of truth** for implementation status, architecture-as-built, the phase plan (0–16), Go/No-Go gates, and the Production 1.0 checklist.
>
> As of **2026-09-30**, all 16 core roadmap phases and speculative acceleration tracks are **100% complete**:
> - **1,574 registered Intel 64 forms** (AVX, AVX2, AVX-512, AVX10, AMX, CET, APX, BMI1/2, x87).
> - **5 Speculative Execution engines** (Speculative Forking, Constraint Batching, Summary Memoization, Lookahead Decode Prefetching, and Concolic Chunk Batching).
> - **Iterative Z3 FFI AST translator** (depth > 600 verified with zero recursion stack overflow).
> - **BLAKE3-accelerated Merkle keys** with zero heap allocations on intern misses.
> - **NUMA-pinned queue groups** with `/proc/meminfo` memory pressure throttling.
> - **Hybrid Fuzzing Engine** (`FuzzCorpus`, `HavocMutator`, solver hint ingestion).
> - **Knowledge Plane Similarity Engine** (cosine similarity over `SemanticFingerprint`).
> - **Top-level API stability suite** (`crates/angryier/tests/api_stability.rs`).

## Navigation

### Roadmap (start here)

| Document | Description |
|---|---|
| [ROADMAP](ROADMAP.md) | Single source of truth: verified current state, architecture-as-built (42-crate map, dual-mode engine), phase plan, Go/No-Go gates, Production 1.0 checklist |

### Architecture (design contracts; status superseded by ROADMAP)

| Document | Description |
|---|---|
| [overview](architecture/overview.md) | Mission, non-goals, global invariants, three-plane architecture |
| [crates](architecture/crates.md) | Crate map and dependency direction (authoritative map is ROADMAP §3.3) |
| [identity](architecture/identity.md) | Shared identity model, version domains, architecture abstraction, Intel 64 target profiles |
| [decode](architecture/decode.md) | Intel XED decode boundary, normalized representation |
| [semantic-pipeline](architecture/semantic-pipeline.md) | Hybrid semantic definition, two-level IR, sealing, dual identity, structured vector/mask/AMX, floating-point |
| [execution](architecture/execution.md) | Runtime values, expression DAG, layered memory, persistent state, fidelity profiles, environment models, summaries, state merging |
| [solver](architecture/solver.md) | Solver architecture, query model, portfolio scheduling, persistent solver knowledge, reuse hierarchy |
| [scheduler](architecture/scheduler.md) | Search, multicore, NUMA queue groups, memory-pressure throttling, work stealing |
| [provenance](architecture/provenance.md) | Provenance tiers, flight recorder, repetition compaction, Tier-2 triggers, WAL, retention |
| [ledger-replay](architecture/ledger-replay.md) | Atomic execution ledger, deterministic replay capsules, self-modifying code invalidation |
| [knowledge](architecture/knowledge.md) | QIHSE/KEYSTONE, cumulative knowledge, dependency invalidation, learned fusion, retrieval-to-reuse pipeline |
| [jit-fuzzing-distribution](architecture/jit-fuzzing-distribution.md) | JIT/native acceleration, hybrid fuzzing, multi-host boundary, plugin model |
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

### Status (historical, superseded by ROADMAP)

| Document | Description |
|---|---|
| [scaffold](status/scaffold.md) | Per-crate implementation status as of an early phase; superseded |
| [implementation-plan](status/implementation-plan.md) | Original phase-by-phase order with exit gates; superseded |

### Top-level

| Document | Description |
|---|---|
| [BENCHMARKING](BENCHMARKING.md) | Performance, semantic correctness, provenance, cumulative reuse, and retrieval benchmark contract |
| [CLI](CLI.md) | `angryier` binary reference: subcommands, the `run` flag set and build matrix, and the embedded Lua (`angry.run`/`angry.open`) API |

### Root

| Document | Description |
|---|---|
| [Plan.md](../Plan.md) | Operational architecture lock and Q9–Q54 decision baseline (immutable) |
| [README.md](../README.md) | Project overview, high-performance benchmarks, speculative execution engines, and design thesis |

