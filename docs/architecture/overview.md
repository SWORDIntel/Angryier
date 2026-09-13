# Architecture Overview

> **Implementation status:** Architecture frozen. Phases 0–3 and Phase 5 foundations are implemented (types, state, memory, XED decode boundary, semantic IR/sealing, AngryIR lowering, concrete interpreter). Phases 4, 6–16 remain scaffolded.

> `Plan.md` is the operational decision baseline. This document set is the complete system architecture derived from that baseline. Implementation may refine mechanics, layouts, thresholds, and algorithms, but it must not silently weaken a locked invariant. Any architectural change requires an explicit replacement decision and migration note.

---

## 1. Mission

Angryier is a native, parallel symbolic/concolic binary-analysis platform designed to exceed Python-heavy symbolic-execution systems not only in raw throughput, but in semantic fidelity, multicore scalability, replayability, cumulative cross-run learning, and analyst insight.

The project is not a source-compatible or API-compatible rewrite of angr. It is a new execution architecture with different internal economics:

- **Concrete work stays concrete.** Symbolic structures are created only when path reasoning, symbolic output, symbolic addressing, or an analyst request actually requires them.
- **State is persistent rather than copied wholesale.** Forks share immutable structure and use copy-on-write deltas.
- **Parallelism is native.** Workers own their hot caches and solver contexts; the design assumes true multicore execution rather than Python-thread orchestration.
- **Semantic truth is explicit.** Decode support, semantic support, solver certainty, approximation, environment assumptions, and replay status are separate concepts.
- **Provenance is a first-class product.** Angryier must be able to answer why a branch was reachable, why a sibling was pruned, which input bytes controlled a value, which assumption affected a finding, and where solver time was spent.
- **Knowledge is cumulative.** Prior analyses contribute exact reusable facts and advisory similarity knowledge through QIHSE and KEYSTONE.
- **Similarity is never proof.** Learned retrieval may prioritize work or propose reuse candidates, but authoritative correctness remains grounded in exact identities, validity keys, semantics, and solver/replay checks.

The intended end state is an analysis engine that becomes materially more useful as it accumulates validated analyses, while remaining capable of running without the persistent knowledge plane.

---

## 2. Non-goals

The initial architecture explicitly does **not** require:

- angr API compatibility;
- Python in the execution hot path;
- AMD-specific instruction/system behavior in the Intel 64 backend;
- immediate multi-host execution;
- immediate JIT compilation;
- a universal single solver;
- eager symbolic conversion of vectors, AMX tiles, memory pages, or tainted data;
- a learned model anywhere in the proof/truth path;
- synchronous database access from execution workers;
- architectural support claims based only on successful instruction decode.

Additional ISAs may be added later through architecture-neutral traits, but implementation resources remain focused on **Intel 64** until that backend is mature and validated.

---

## 3. Global invariants

These rules apply across the entire repository.

1. **Decode is not semantics.** Intel XED identifies and describes an instruction; Angryier owns its semantics.
2. **Host capability is not target capability.** An analyzer host without AVX-512 or AMX must still be able to analyze target code that uses them.
3. **Published semantics are immutable.** A rich semantic block is mutable only while private to construction/normalization/validation. Once sealed, it is immutable and content-addressed.
4. **Exact identity and semantic similarity are separate.** `ContentId` is authoritative. `SemanticFingerprint` and learned embeddings are candidate/retrieval identities.
5. **Post-seal transformations are derivations.** They create new immutable blocks with explicit parentage, transformation contracts, and equivalence evidence.
6. **Execution artifacts are validity-scoped.** Execution IR and JIT artifacts are bound to exact semantic identity, target profile, image/block identity, and relevant code-page versions.
7. **Replay-visible mutation is atomic.** State changes, code-page versions, invalidation consequences, Tier-1 provenance advancement, semantic references, and replay checkpoints are committed under one execution-ledger epoch or not published at all.
8. **Solver uncertainty is never silently converted to UNSAT.** SAT, UNSAT, UNKNOWN, TIMEOUT, RESOURCE_LIMIT, and BACKEND_ERROR are distinct outcomes.
9. **Persistent reuse is fail-closed.** A stored result may affect correctness only after all required compatibility/dependency keys validate.
10. **Workers do not block on QIHSE/KEYSTONE.** Persistence is asynchronous/batched with priority-aware queues and local WAL/spill.
11. **Correctness-critical Tier-1 provenance is not silently dropped.** Backpressure is observable and recoverable.
12. **PROVE never silently approximates.** EXPLORE and HUNT may relax policy only with explicit fidelity provenance.
13. **Learned and quantum-inspired ranking are advisory.** They may change priority or worker assignment, never truth.
14. **Deterministic mode is mandatory.** Scheduler decisions, seeds, solver configuration, event order, and replay-relevant nondeterminism must be recordable/replayable.
15. **JIT is evidence-driven.** It is introduced only when profiling demonstrates end-to-end value.

---

## 4. System planes

Angryier is organized into three cooperating planes.

```text
                                  ANGRYIER
                                     |
             +-----------------------+-----------------------+
             |                       |                       |
             v                       v                       v
      EXECUTION PLANE            TRUTH PLANE           KNOWLEDGE PLANE

  loader / state import       canonical semantics       QIHSE system of record
  Intel 64 decode             support manifest          KEYSTONE indexes/ingest
  concrete execution           differential testing      exact reusable facts
  taint/dataflow              equivalence evidence      dependency graph
  concolic/symbolic           fidelity ledger           semantic fingerprints
  COW state/memory            replay validation         fused embeddings
  expression DAG              solver classification     analyst annotations
  solver orchestration        target-profile truth      time-series telemetry
  scheduler / NUMA            semantic identities       retention/cleanup
  optional JIT
```

### 4.1 Execution Plane

Owns the latency-sensitive analysis path:

- loading and state import;
- normalized Intel 64 decode;
- concrete, taint, concolic, and symbolic execution;
- register and memory state;
- expression DAG construction;
- path constraints;
- solver dispatch;
- state forking/merging;
- search scheduling;
- code-page invalidation;
- replay checkpoints;
- optional JIT/native acceleration.

The Execution Plane must remain useful with persistence completely disabled.

### 4.2 Truth Plane

Owns claims of correctness and fidelity:

- semantic definitions and generator versions;
- canonical typed semantic IR;
- semantic sealing/identity;
- transformation contracts and equivalence evidence;
- semantic support manifests;
- differential tests against hardware/reference engines;
- solver outcome classification;
- approximation/fidelity accounting;
- deterministic replay verification;
- target feature/profile assumptions.

### 4.3 Knowledge Plane

Turns runs into reusable intelligence:

- exact query/result caches;
- UNSAT cores and generalized solver facts;
- dependency-aware invalidation;
- function summaries;
- state/constraint/taint lineage;
- historical solver performance;
- semantic discrepancy history;
- hierarchical function/artifact identity;
- semantic fingerprints;
- specialist modality embeddings and learned fusion;
- analyst labels;
- trace summaries and retention decisions.

The Knowledge Plane suggests; exact validation authorizes.
