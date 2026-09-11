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

The architecture is frozen; the repository now contains the complete **interface/contract scaffold** for the major subsystems. A scaffolded crate reserves ownership and exposes the intended boundary. It does **not** imply that its backend is implemented.

The workspace includes architecture/Intel 64, XED adaptation, semantics and generation, semantic identity/evidence, execution IR, expressions, memory, state, taint, execution, atomic ledger, replay, solver orchestration plus Z3/Bitwuzla seams, NUMA-aware scheduling, provenance, cumulative knowledge, learned fusion, environment models, loading/state import, fuzzing, telemetry, WAL/storage, JIT, QIHSE, KEYSTONE, plugins, benchmarking, CLI and future distribution boundaries.

## Documentation

- [`Plan.md`](Plan.md) — operational architecture lock and Q9–Q54 decision baseline.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — complete frozen three-plane system architecture and invariants.
- [`docs/IMPLEMENTATION_PLAN.md`](docs/IMPLEMENTATION_PLAN.md) — implementation order and phase exit gates.
- [`docs/CRATE_MAP.md`](docs/CRATE_MAP.md) — ownership map from architecture components to Rust crates.
- [`docs/SCAFFOLD_STATUS.md`](docs/SCAFFOLD_STATUS.md) — explicit distinction between scaffolded contracts and implemented functionality.
- [`docs/DESIGN_DECISIONS.md`](docs/DESIGN_DECISIONS.md) — locked design decisions and replacement-decision policy.
- [`docs/SEMANTICS.md`](docs/SEMANTICS.md) — Intel 64 decode, typed semantics, generator plan, AVX/AVX-512/AMX handling and validation gates.
- [`docs/SEMANTIC_IDENTITY.md`](docs/SEMANTIC_IDENTITY.md) — `ContentId`, semantic fingerprints, derivation and validity rules.
- [`docs/TRAIT_BOUNDARIES.md`](docs/TRAIT_BOUNDARIES.md) — semantic/execution/ledger interface contracts.
- [`docs/PROVENANCE_KNOWLEDGE.md`](docs/PROVENANCE_KNOWLEDGE.md) — adaptive provenance, cleanup, QIHSE/KEYSTONE mapping, cross-run reuse and learned fusion.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — broader implementation roadmap and go/no-go gates.
- [`docs/BENCHMARKING.md`](docs/BENCHMARKING.md) — performance, semantic correctness, provenance, cumulative reuse and retrieval benchmark contract.

## Current Status

**Architecture frozen; full interface/contract scaffold present; engine implementation not yet complete.**

The repository intentionally does not fake missing native backends. Native XED integration, Intel semantic coverage, COW memory internals, concrete/symbolic execution, Z3/Bitwuzla translation, scheduler implementation, durable replay/ledger storage, QIHSE/KEYSTONE bindings, learned models, fuzzing adapters and JIT remain implementation work and must fail explicitly until real implementations exist.

Repository checks are defined by `scripts/check.sh` and `.github/workflows/ci.yml`: formatting, workspace compilation, Clippy with warnings denied, and tests. The scaffold is only considered build-clean once those checks have actually passed.

## Performance Policy

Angryier does not claim a universal `10x`, `50x` or `100x` advantage.

Performance, semantic coverage, fidelity and knowledge-reuse improvements must be measured separately on named reproducible workload classes. Any speedup obtained by silently weakening semantics is invalid.
