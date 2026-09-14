# Crate Boundaries and Dependency Direction

> **Implementation status:** All 35 crates exist with manifests and public contract boundaries. Foundation crates (types, arch, arch-intel64, decode-xed, semantics, ir, expr, memory, state, execution, solver, ledger) have real implementations. Adapter and future-phase crates (qihse, keystone, fusion, fuzz, loader, plugins, bench, semantics-gen, distribution) have in-memory foundation implementations. Native integration crates (solver-z3, solver-bitwuzla, jit, cli, semantic-contracts) remain scaffolded contracts only.

---

## Crate map

The target workspace is deliberately decomposed around stable ownership boundaries rather than convenience modules.

```text
crates/
  angryier-types/             shared IDs, versions, hashes, small policy enums
  angryier-core/              orchestration contracts and engine-level context
  angryier-arch/              ISA-neutral architecture traits
  angryier-arch-intel64/      Intel 64 registers, features, CPU profiles
  angryier-decode-xed/        Intel XED adapter; no semantic truth
  angryier-loader/            ELF64/PE32+ loading and image mappings

  angryier-semantics/         semantic provider/builder contracts
  angryier-semantic-contracts sealed identity + transformation/evidence contracts
  angryier-semantics-gen/     declarative semantics compiler/generator boundary
  angryier-semantics-intel64/ handwritten Intel 64 semantic corpus (partial)
  angryier-ir/                compact AngryIR execution representation
  angryier-expr/              immutable symbolic expression DAG
  angryier-memory/            layered COW memory
  angryier-state/             persistent machine/path state
  angryier-taint/             cheap taint/dataflow domain
  angryier-execution/         concrete/taint/concolic/symbolic executor

  angryier-ledger/            atomic replay-visible publication boundary
  angryier-replay/            deterministic replay capsules and verifier
  angryier-solver/            solver-neutral queries, batching, portfolio policy
  angryier-solver-z3/         Z3 adapter
  angryier-solver-bitwuzla/   Bitwuzla adapter
  angryier-scheduler/         worker pool, NUMA groups, work stealing, search
  angryier-models/            syscall/libc/environment summaries/models

  angryier-provenance/        fidelity ledger, Tier 0/1/2 event contracts
  angryier-telemetry/         bounded queues, WAL/spill, trace compaction
  angryier-knowledge/         exact/advisory reuse + invalidation graph
  angryier-qihse/             QIHSE storage adapter
  angryier-keystone/          KEYSTONE ingestion/index adapter
  angryier-fusion/            specialist encoders + masked/gated learned fusion

  angryier-fuzz/              bidirectional hybrid fuzzing boundary
  angryier-jit/               optional JIT validity/isolation boundary
  angryier-plugins/           stable internal Rust extension traits
  angryier-distribution/      future work-unit serialization/distribution seam
  angryier-bench/             benchmark/correctness harness contracts
  angryier-cli/               CLI frontend
```

### Implementation status by crate

| Crate | Status | Notes |
|---|---|---|
| `angryier-types` | Implemented | ContentId, SemanticFingerprint, all cross-plane IDs, versions, fidelity profiles |
| `angryier-core` | Implemented | Engine-level context contracts |
| `angryier-arch` | Implemented | ISA-neutral decoder traits, DecodedInstruction, operand model |
| `angryier-arch-intel64` | Implemented | Intel 64 registers, features, CPU profiles, parent register map |
| `angryier-decode-xed` | Implemented | XED normalization boundary, metadata, error types (no native FFI yet) |
| `angryier-semantics` | Implemented | Semantic types, ops, provider/builder traits, sealed block builder (561 lines) |
| `angryier-semantic-contracts` | Implemented | In-memory sealed/derived blocks, identity transformation, fidelity acceptance policy (~400 lines) |
| `angryier-semantics-gen` | Implemented | In-memory semantic compiler with origin parsing, coverage manifest, duplicate form rejection (~390 lines) |
| `angryier-semantics-intel64` | Partial | Handwritten Intel 64 corpus: 351 forms (93 foundational integer/control-flow + 94 Phase 4a partial-write/bit-scan/32-bit forms + 164 Phase 4b SSE/SSE2/SSSE3/SSE4.1/SSE4.2 SIMD forms) with RFLAGS ZF/SF/CF/PF |
| `angryier-ir` | Implemented | AngryIR types, lowering, verification (545 + 233 lines) |
| `angryier-expr` | Implemented | Expression DAG, hash-consing, arena, constant folding (701 lines) |
| `angryier-memory` | Implemented | Layered COW memory, byte values, symbolic overlay contracts (539 lines) |
| `angryier-state` | Implemented | Persistent state, register state, fork, fidelity ledger (495 lines) |
| `angryier-taint` | Implemented | In-memory taint engine with labels, states, promotion threshold, transform/merge/sink (~567 lines) |
| `angryier-execution` | Implemented | Concrete interpreter with AngryIR execution (803 lines) |
| `angryier-ledger` | Implemented | Atomic ledger with epoch model, rejection classes, concurrent commit validation (503 lines) |
| `angryier-replay` | Implemented | In-memory replay capsule store, validator, basic replay engine (~250 lines) |
| `angryier-solver` | Implemented | Solver-neutral query/result model, result classes, canonical identity, portfolio router, batch solver, cache (679 lines) |
| `angryier-solver-z3` | Scaffolded | Fail-closed Z3 adapter stub |
| `angryier-solver-bitwuzla` | Scaffolded | Fail-closed Bitwuzla adapter stub |
| `angryier-scheduler` | Implemented | In-memory work-stealing scheduler with per-worker queues, NUMA distance model, greedy scoring (~834 lines) |
| `angryier-models` | Implemented | In-memory environment model with operation table, fidelity enforcement, summary provider (~440 lines) |
| `angryier-provenance` | Implemented | In-memory provenance store, adaptive trace governor, batching sink, tier-based eviction (~570 lines) |
| `angryier-telemetry` | Implemented | In-memory telemetry sink with metric aggregation, time-series recording, backpressure tracking (~400 lines) |
| `angryier-knowledge` | Implemented | In-memory knowledge store with exact-match cache, dependency graph with transitive invalidation (~320 lines) |
| `angryier-storage` | Implemented | In-memory WAL with checkpoint replay, priority-aware eviction, retention policy (~420 lines) |
| `angryier-qihse` | Implemented | In-memory QIHSE adapter with exact fetch, fingerprint vector query, duplicate rejection (~280 lines) |
| `angryier-keystone` | Implemented | In-memory KEYSTONE adapter with inverted index, substring lookup, duplicate rejection (~380 lines) |
| `angryier-fusion` | Implemented | In-memory fusion model with identity/constant encoders, element-wise averaging (~430 lines) |
| `angryier-fuzz` | Implemented | In-memory fuzz bridge with stage-gated seed/coverage/hint submission (~290 lines) |
| `angryier-jit` | Scaffolded | JIT validity contract only |
| `angryier-plugins` | Implemented | In-memory plugin registry with duplicate-name rejection, sorted lookup (~150 lines) |
| `angryier-distribution` | Implemented | In-memory work codec with deterministic binary frame encode/decode round-trip (~560 lines) |
| `angryier-loader` | Implemented | In-memory image loader with sequential IDs, state importer (rejects live capture) (~185 lines) |
| `angryier-bench` | Implemented | In-memory benchmark sink with validation, sorted records, aggregate summary (~435 lines) |
| `angryier-cli` | Implemented | Basic CLI with version/status/crates/help subcommands (no external deps, ~430 lines) |

---

## Dependency direction

The workspace must remain acyclic and layered:

```text
                    angryier-types
                         |
       +-----------------+-------------------+
       |                 |                   |
      arch            semantics             provenance
       |                 |                   |
   intel64/xed     semantic-contracts        |
       |                 |                   |
       +---------> IR / expr / memory / state+
                         |
                        exec
                         |
               solver / ledger / replay
                         |
                    scheduler/models
                         |
          telemetry / knowledge / fuzz / JIT
                         |
               QIHSE / KEYSTONE / fusion
```

Adapters depend inward on stable contracts. Core execution code must not depend on database SDK details, XED-owned lifetimes, Z3 AST types, Bitwuzla AST types, or ML model representations.

### Dependency rule

Dependencies should flow toward smaller foundational contracts. In particular, `angryier-types` must remain low-level; solver/JIT/database SDK objects must never leak into state, semantics or persistent identity types. QIHSE and KEYSTONE adapters must remain optional asynchronous edges, never prerequisites for execution correctness.
