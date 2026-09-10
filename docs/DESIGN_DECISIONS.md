# Angryier Design Decisions

This document records decisions that are considered **locked** unless new evidence demonstrates that the chosen design is materially inferior. It exists to prevent later implementation work from silently drifting away from the design review.

A locked decision may still be amended, but the replacement decision must state why the previous one was insufficient.

## D-001 — Rust-native core

**Status:** Locked

The execution, state, scheduler, semantics, and solver-orchestration core is implemented in Rust. Python is permitted only as an optional control/API layer and never in the hot path.

## D-002 — Architecture-neutral core, Intel 64 first production backend

**Status:** Locked

The engine exposes architecture-neutral traits, but the first production backend targets **Intel 64**.

AMD CPUs and AMD-specific extensions/system behavior are not a validation target for the Intel 64 backend.

## D-003 — Host and target feature sets are separate

**Status:** Locked

The target program may use instructions that the analysis host cannot execute natively.

```text
HostFeatures   != TargetFeatures
```

If the host safely supports an instruction, a native/accelerated path may be used. Otherwise Angryier must retain a software semantic path.

## D-004 — Intel XED is the Intel 64 decoder

**Status:** Locked

Intel XED is used for decode, instruction-form normalization, operand metadata, and feature classification.

XED is not treated as an instruction-semantics engine.

## D-005 — Hybrid generated semantics

**Status:** Locked

Semantics implementation follows this sequence:

1. build a representative handwritten corpus;
2. stabilize the canonical semantic representation and AngryIR;
3. identify recurring semantic patterns;
4. implement a semantics compiler/generator;
5. migrate regular/repetitive families to generated definitions;
6. retain specialized handwritten overrides for complex families.

The generator itself is part of Angryier.

## D-006 — Canonical semantic layer before AngryIR

**Status:** Locked

Instruction definitions do not generate executor-specific Rust directly as their sole representation.

A typed canonical semantic representation sits between instruction semantics and execution lowering so the same semantics can drive concrete evaluation, taint, symbolic lowering, generated tests, and support manifests.

## D-007 — Structured vector/mask/tile semantics

**Status:** Locked

AVX/AVX-512/AMX semantics are not eagerly flattened into giant monolithic bitvectors.

Vectors, opmasks, floating-point values, and AMX tiles are explicit runtime/semantic domains with lazy solver materialization where possible.

## D-008 — PROVE / EXPLORE / HUNT fidelity profiles

**Status:** Locked

All three profiles use the same underlying semantic engine but different policy constraints.

- **PROVE:** exact-only policy; no silent concretization or unsupported behavior.
- **EXPLORE:** conservative approximations permitted with explicit provenance.
- **HUNT:** aggressive exploration/concretization permitted, but never presented as proof.

Every state and finding carries a fidelity ledger.

## D-009 — Adaptive tiered provenance

**Status:** Locked

Provenance uses three tiers:

- **Tier 0:** transient worker-local execution detail;
- **Tier 1:** always-retained structural provenance;
- **Tier 2:** deep trace activated around interesting events.

Tier 2 automatically decays under repetitive/high-volume/low-novelty conditions. Every worker maintains a pre-trigger flight-recorder ring.

## D-010 — Cleanup is compaction-first and human-reviewable

**Status:** Locked

Post-processing first canonicalizes, deduplicates, summarizes, and extracts causality. Destructive cleanup is a later operation.

High-value or ambiguous deletion may require human approval. Deletion supports quarantine-before-purge, and cleanup decisions are themselves provenance records.

## D-011 — QIHSE + KEYSTONE are the native knowledge substrate

**Status:** Locked

QIHSE is the persistent system of record. KEYSTONE is the preferred indexing/ingestion/retrieval acceleration layer.

Persistence never blocks the normal execution hot path.

## D-012 — Angryier is cumulative across runs

**Status:** Locked

Prior analyses are active knowledge, not passive logs.

Previous exact results may be reused only when validity keys match. Approximate/similarity retrieval is advisory until exact validation succeeds.

## D-013 — Persistent generalized solver knowledge

**Status:** Locked

The knowledge plane may store more than exact SAT/UNSAT cache entries, including:

- UNSAT cores;
- alpha-equivalent facts;
- implication/subsumption relationships;
- branch invariants;
- generalized incompatible predicate sets;
- historical solver-performance profiles.

Generalized facts carry machine-checkable provenance/validity metadata and are revalidated when policy requires it.

## D-014 — Two-level solver knowledge

**Status:** Locked

```text
Level 1: worker-local hot incremental contexts and caches
Level 2: persistent cross-worker/cross-run QIHSE/KEYSTONE knowledge
```

No global solver mutex is permitted on the normal execution/query path.

## D-015 — Shared-context batched solver API

**Status:** Locked

The solver interface is designed for groups of related queries sharing a path context, not only isolated `solve(expr)` calls.

This allows sibling states and branch alternatives to exploit shared context explicitly.

## D-016 — Locality-aware work stealing

**Status:** Locked

State migration considers scheduler load, solver-context rebuild cost, memory/cache locality, and NUMA placement rather than using queue depth alone.

## D-017 — Adaptive concrete → taint → symbolic promotion

**Status:** Locked

Concrete values remain concrete whenever possible. Cheap taint/dataflow tracking determines when symbolic reasoning becomes necessary.

Concrete-only blocks must avoid symbolic expression construction.

## D-018 — JIT only after profiling

**Status:** Locked

Cranelift/native translation is a later optimization. It is introduced only if profiling shows concrete block execution remains a meaningful fraction of wall time after state, taint, solver, and scheduler optimizations.

## D-019 — Specialist encoders + learned fusion

**Status:** Locked

Semantic similarity uses specialist modality encoders feeding a learned masked/gated fusion layer.

Modalities may include:

- AngryIR/semantic structure;
- CFG/path topology;
- constraint DAGs;
- taint/dataflow;
- memory-access behavior;
- solver profile;
- dynamic behavior;
- fidelity/provenance;
- findings/context;
- analyst annotations.

Missing modalities are explicitly masked.

## D-020 — Default 1024-D fused representation, variable profiles

**Status:** Locked

The default semantic embedding width is **1024 dimensions**.

Supported embedding profiles may range from 384 to 4096 dimensions. Dimensionality is selected by measured retrieval quality/cost rather than by assuming larger is always better.

## D-021 — All useful modalities contribute to learned fusion

**Status:** Locked

No single artifact class is declared the universal representation. The fusion system may learn from all useful structural, semantic, dynamic, solver, provenance, and analyst signals.

The fused embedding is never the authoritative semantic representation.

## D-022 — Explain similarity, do not only score it

**Status:** Locked

Where practical, store modality/sub-embedding contribution information so Angryier can explain whether a similarity match was driven primarily by constraints, CFG, taint flow, behavior, provenance, or another modality.

## D-023 — Exact knowledge and similarity knowledge are separate planes

**Status:** Locked

```text
Exact plane:
  canonical semantics, hashes, constraints, proofs, models, lineage

Similarity plane:
  learned fused embeddings and approximate nearest-neighbor retrieval
```

A similarity hit proposes a candidate. Exact machinery determines whether that candidate is reusable.

## D-024 — AI/LLM assistance is advisory only

**Status:** Locked

Future AI/agent assistance may advise search prioritization, model suggestions, triage, or analyst interaction. It is never trusted as instruction semantics or silently promoted into PROVE truth.

## D-025 — Sealed immutable semantic IR

**Status:** Locked

Rich semantic blocks use a two-stage lifecycle:

1. mutable/private while being constructed, normalized, optimized, and validated;
2. sealed, immutable, and content-addressed before entering lowering, caches, provenance, replay, or cross-run knowledge.

A sealed semantic object cannot be mutated in place. Any semantic transformation after sealing produces a new object with a new content identity and provenance link to its predecessor.

This prevents replay capsules, JIT validity keys, cache entries, and cross-run knowledge from observing semantic mutation after publication.

---

# Open Decisions

The following remain intentionally unresolved and should be handled through design Q&A rather than implementation-by-default:

- exact canonical semantic DSL syntax;
- exact structured representation for symbolic vectors/tiles;
- state-merge policy and merge cost model;
- solver-routing policy and proof/cross-check thresholds;
- exact trace-governor scoring function;
- cross-run knowledge invalidation granularity;
- learned fusion training objectives and negative-sampling strategy;
- which embedding profiles are retained simultaneously;
- persistent raw-trace chunk format and compression;
- library/syscall/environment-model architecture;
- fuzzing integration boundary;
- scope/timing of additional ISAs after Intel 64.
