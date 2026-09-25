# Security, Trust Boundaries, and Failure Containment

> **Status superseded (2026-09-24):** see [ROADMAP.md](../ROADMAP.md). The three FFI crates are now the documented, audited `unsafe` exceptions; core crates remain `forbid(unsafe_code)`.

> **Implementation status:** Architecture-level. The workspace enforces `unsafe_code = "forbid"` and `panic/unwrap_used/expect_used = "deny"` across all crates. No FFI `unsafe` exceptions exist yet since no native backends are linked.

---

## Security and trust boundaries

Angryier processes untrusted binaries and must assume hostile inputs.

Key boundaries:

- parsers/loaders and XED adapters validate lengths/ranges before use;
- target code is not granted arbitrary analyzer-process execution;
- native target execution is sandboxed/restricted;
- JIT memory follows W^X discipline when implemented;
- solver responses are classified and may be cross-checked for high-value claims;
- generated semantics cannot shadow overrides ambiguously;
- persistent knowledge cannot bypass compatibility validation;
- corrupted/stale replay capsules fail closed;
- QIHSE/KEYSTONE failures cannot corrupt local execution truth;
- event/WAL payloads are versioned and checksummed;
- plugins do not receive unrestricted hot-path mutation access by default.

Rust `unsafe` is forbidden in pure-Rust core crates unless a future exception is explicitly documented. FFI crates may require narrowly audited `unsafe` blocks once XED/solver/native APIs are implemented; those exceptions must remain encapsulated at adapter boundaries rather than leaking through the workspace.

---

## Failure containment

The architecture is designed so subsystem failure degrades capability without silently corrupting truth.

| Failure | Required behavior |
|---|---|
| QIHSE unavailable | continue locally; queue/WAL durable events |
| KEYSTONE unavailable | fall back to exact local/persistent paths; no truth loss |
| learned model unavailable | deterministic search/retrieval paths remain usable |
| CUDA/OpenCL optimizer unavailable or fails | preserve the candidate batch and use the deterministic CPU scheduler |
| solver timeout | return TIMEOUT/UNKNOWN and apply policy; never UNSAT |
| one solver backend fails | portfolio fallback/cross-check according to policy |
| Tier-2 overload | reduce/summarize Tier-2, retain Tier-1 |
| WAL pressure | expose saturation, aggregate disposable telemetry, preserve required truth |
| semantic provider missing | explicit unsupported result |
| semantic disagreement | mark discrepancy and retain forensic evidence |
| JIT invalidated | fall back to valid execution IR/interpreter |
| replay mismatch | reject capsule/replay rather than repair silently |
| dependency mismatch | reject reuse and recompute |

---

## Observability and analyst insight

Angryier should answer causal questions directly from deterministic/provenance structures rather than reconstructing them from flat logs.

Target queries include:

```text
Why can this branch be reached?
Why was the sibling state pruned?
Which input bytes control this comparison?
Where did this symbolic value originate?
Which constraints dominate solver time?
Which model/summary/concretization affected this finding?
Which previous run contributed this reusable fact?
Why did the scheduler prioritize this state?
Why did the solver portfolio preempt backend A for backend B?
Can this finding reproduce without approximations?
Which code-page mutation invalidated this block?
Why are two functions considered semantically similar?
```

The causal graph is a product feature, not merely diagnostic logging.

---

## Architectural assumptions are hypotheses

Two explicit planning assumptions exist, but they are **not invariants**.

1. Custom firmware/hardware behavior may reduce context-switching cost on a particular host.
2. Baseline solver theories may generally remain healthy until portfolio fallback engages.

The implementation must remain correct when both assumptions are false.

Software metrics must expose context switches, NUMA migrations, solver fallback pressure, ledger conflicts, state steals, cache locality, and WAL pressure rather than allowing favorable hardware to conceal structural inefficiency.

---

## Critical stress scenarios

The implementation must deliberately attack its own design assumptions.

### Dependency graph scale

Generate millions of summaries/versioned artifacts and measure memory overhead, invalidation latency, and compaction behavior.

### Fuzzer cache poisoning

Inject millions of structurally similar but logically distinct constraints. No alpha-equivalence/subsumption/fingerprint path may authorize an incorrect exact result.

### Atomicity fault injection

Inject failure between every internal ledger step. No partially committed combination of state, page versions, provenance, or replay metadata may become visible.

### AMX contention

Compare lazy-chunked and dense-cell representations under heavy state forking and symbolic translation. Detect lock contention, cache-line bouncing, solver AST amplification, and migration costs.

### Solver preemption oscillation

Construct queries near policy thresholds to verify hysteresis/resource caps and deterministic replay of routing decisions.

### Telemetry saturation

Saturate event queues and WAL I/O while fuzzing. Required Tier-1 provenance must survive and latency impact must be measurable rather than silent.

### Emergent scheduler behavior

Record and replay multi-objective search + adaptive solver-preemption runs to isolate regressions caused by policy interactions.

### Accelerated batch-planner instability

Compare CPU, CUDA, and OpenCL scheduling decisions on identical bounded candidate batches. Inject device loss, compilation failure, timeout, out-of-memory, and numerically unstable scores. Runnable work must remain intact, fallback must be deterministic, and accelerator overhead must be reported separately from execution gains.

---

## Architecture freeze rule

The architectural Q&A phase is complete through Q54.

Implementation details may evolve, but the following require an explicit architecture-change record before modification:

- the three-plane separation;
- Intel 64 first / ISA-neutral core policy;
- XED decode-vs-semantics boundary;
- hybrid declarative/Rust semantic-definition model;
- rich semantic IR -> sealed identity -> AngryIR pipeline;
- structured vector/AMX and SMT-FP policies;
- PROVE/EXPLORE/HUNT fidelity model;
- atomic execution ledger and deterministic replay requirements;
- native worker/NUMA ownership model;
- layered canonicalization and validated cross-run reuse;
- QIHSE/KEYSTONE non-blocking knowledge plane;
- specialist encoder + learned fusion model;
- exact-vs-similarity trust separation;
- staged fuzzing and late JIT policy;
- deterministic replay/debug mode;
- optional CUDA/OpenCL quantum-inspired scheduling remains advisory, bounded, replay-visible, and removable;
- future distribution boundary without immediate distributed implementation.

`Plan.md`, [design decisions](../design/decisions.md), [trait boundaries](../design/trait-boundaries.md), [semantics](../semantics/intel64.md), [semantic identity](../semantics/identity.md), [provenance](provenance.md), [knowledge](knowledge.md), [benchmarking](../benchmarking.md), and the [implementation plan](../status/implementation-plan.md) provide narrower supporting contracts. The architecture documents in this directory are the complete top-level system architecture that ties them together.
