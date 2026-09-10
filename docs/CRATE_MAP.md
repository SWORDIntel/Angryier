# Angryier Crate Map

This file maps the frozen architecture to code ownership. A crate existing here means the boundary is reserved; it does **not** imply the subsystem is implemented.

## Foundation

| Crate | Ownership |
| --- | --- |
| `angryier-types` | Cross-plane IDs, versions, fidelity, retention, dependency keys and analysis context |
| `angryier-core` | Engine-wide policy/configuration primitives |
| `angryier-arch` | ISA-neutral architecture and decoder traits |
| `angryier-arch-intel64` | Intel 64 profiles, features and architectural state contracts |
| `angryier-decode-xed` | Intel XED adapter boundary; XED ownership terminates here |

## Truth plane

| Crate | Ownership |
| --- | --- |
| `angryier-semantics` | Typed semantic domains and provider interfaces |
| `angryier-semantic-contracts` | Sealed identity, derivation and transformation-evidence contracts |
| `angryier-semantics-gen` | Declarative/Rust hybrid semantic generator/compiler boundary |
| `angryier-ir` | Compact execution IR downstream of sealed semantics |

## Execution plane

| Crate | Ownership |
| --- | --- |
| `angryier-expr` | Hash-consed expression DAG and canonicalization interfaces |
| `angryier-memory` | Page-backed COW memory and sparse symbolic overlay contracts |
| `angryier-state` | Persistent state roots, register state and fidelity ledger |
| `angryier-taint` | Taint/dataflow and concrete-to-symbolic promotion decisions |
| `angryier-execution` | Concrete/taint/symbolic execution boundary |
| `angryier-ledger` | Atomic state/code-version/provenance/replay publication |
| `angryier-replay` | Deterministic replay capsules and validation |
| `angryier-scheduler` | Multi-objective NUMA/locality-aware scheduling |
| `angryier-jit` | Profile-driven translated JIT and native isolation policy |
| `angryier-loader` | Binary loading plus static/snapshot/checkpoint/live import abstraction |

## Solver subsystem

| Crate | Ownership |
| --- | --- |
| `angryier-solver` | Backend-neutral queries, batching, result classes and routing |
| `angryier-solver-z3` | Z3 bridge seam only |
| `angryier-solver-bitwuzla` | Bitwuzla bridge seam only |

## Knowledge, provenance and persistence

| Crate | Ownership |
| --- | --- |
| `angryier-provenance` | Tier 0/1/2 causal provenance and trace-governor contracts |
| `angryier-knowledge` | Authoritative/advisory reuse, validity and dependency invalidation |
| `angryier-fusion` | Specialist modality encoders and learned masked/gated fusion |
| `angryier-storage` | Local WAL/spill, raw chunks and retention lifecycle |
| `angryier-telemetry` | Performance/backpressure/time-series metrics |
| `angryier-qihse` | Asynchronous QIHSE persistence adapter boundary |
| `angryier-keystone` | Asynchronous KEYSTONE indexing/ingestion/retrieval boundary |

## Models, fuzzing and extensibility

| Crate | Ownership |
| --- | --- |
| `angryier-models` | Environment models and exact/approximate function summaries |
| `angryier-fuzz` | Staged bidirectional hybrid-fuzzing boundary |
| `angryier-plugins` | Stable internal Rust plugin trait registry |
| `angryier-distribution` | Future multi-host serialization/work-envelope boundary |

## User and validation surfaces

| Crate | Ownership |
| --- | --- |
| `angryier-cli` | CLI orchestration entry point |
| `angryier-bench` | Reproducible correctness/performance benchmark records |

## Dependency rule

Dependencies should flow toward smaller foundational contracts. In particular, `angryier-types` must remain low-level; solver/JIT/database SDK objects must never leak into state, semantics or persistent identity types. QIHSE and KEYSTONE adapters must remain optional asynchronous edges, never prerequisites for execution correctness.
