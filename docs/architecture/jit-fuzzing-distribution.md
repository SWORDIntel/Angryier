# JIT, Fuzzing, and Distribution

> **Status superseded (2026-09-24):** see [ROADMAP.md](../ROADMAP.md). `fuzz_generate` is live end-to-end and the distribution codec is implemented; JIT remains contract-only by design (Gate G).

> **Implementation status:** Scaffolded. `angryier-jit` (144 lines), `angryier-fuzz` (36 lines), and `angryier-distribution` (19 lines) are contract-only. No Cranelift/native JIT, fuzzer adapters, or distributed execution is implemented.

---

## JIT / native acceleration

JIT is optional and late-stage.

Potential progression:

```text
cold block -> compact AngryIR interpreter
warm block -> specialized cached executor
hot block  -> Cranelift/native translation
```

JIT must prove an end-to-end win after accounting for compilation cost, invalidation, symbolic hooks, cache pressure, and state management.

### Isolation

- trusted Angryier-generated JIT code may execute in-process under strict validity guards;
- arbitrary/native target execution belongs in a restricted worker/sandbox boundary;
- privileged/system instructions are never blindly executed on the analyzer host.

---

## Bidirectional fuzzing boundary

Fuzzing integration is staged.

### Stage 1

```text
seed exchange
coverage exchange
```

### Stage 2

After deterministic replay and cache-validity invariants are hardened:

```text
bidirectional seeds
coverage
constraint hints
target hints
testcase feedback
```

Fuzzer-provided information is advisory input. It cannot authorize exact cache reuse or bypass semantic validity.

---

## Future multi-host boundary

Distributed execution is intentionally deferred until single-host NUMA scaling is proven, but serialization boundaries are defined early.

Serializable work units include or reference:

```text
WorkUnitId
TargetProfile
sealed semantic identities
state roots/deltas
expression/constraint identities
replay capsule context
fidelity/provenance context
solver-knowledge validity keys
required code/image content
scheduler objective metadata
```

No distributed scheduler is required for initial production readiness.

---

## Plugin and extension model

Internal extensibility uses versioned Rust traits rather than an unstable dynamic ABI in the execution hot path.

Extension seams include:

- architecture backends;
- decoders;
- semantic providers;
- environment models;
- solver backends;
- search policies;
- summary providers;
- provenance consumers;
- knowledge adapters;
- fuzzing adapters.

A stable C ABI may be introduced later for external binary plugins if a real interoperability requirement exists. It is not an initial constraint on internal Rust design.
