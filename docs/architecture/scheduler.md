# Scheduler and Multicore Architecture

> **Status superseded (2026-09-24):** see [ROADMAP.md](../ROADMAP.md). `OsWorkerPool` with work stealing is implemented and measured (3.93× on 4 workers); NUMA-pinned queue groups and the batch planner remain future work.

> **Implementation status:** Scaffolded. `angryier-scheduler` is contract-only. The deterministic CPU scheduler, work-stealing, NUMA groups, and quantum-inspired batch planner are not yet implemented.

---

## Search and scheduler architecture

Search is pluggable and multi-objective.

Potential score dimensions include:

- coverage novelty;
- target/reachability distance;
- taint relevance;
- symbolic depth;
- solver cost;
- semantic uncertainty;
- approximation debt;
- crash/finding proximity;
- analyst goals;
- historical usefulness of similar states.

Deterministic baseline strategies remain available even when learned ranking exists.

### Learned ranking

Learned models may reorder admissible work. They do not decide truth, SAT/UNSAT, semantic support, or proof validity.

### Quantum-inspired batch scheduling

After the deterministic CPU scheduler is correct and benchmarked, an optional `QuantumInspiredScheduler` may optimize bounded batches of already-admissible states. The intended formulation is a classical QUBO-style or related combinatorial objective over:

- coverage and path diversity;
- target proximity and analyst priorities;
- estimated solver cost;
- solver-context and cache affinity;
- memory working-set and NUMA migration cost;
- semantic uncertainty and fidelity debt;
- historical outcomes supplied by the optional knowledge plane.

The optimizer selects and assigns work; it does not execute states, classify solver results, validate semantics, or authorize cache reuse. Every selected state is executed by the normal CPU execution plane and remains subject to the same exact validity and fidelity rules.

The scheduler owns a backend-neutral batch-optimizer contract with these implementations:

```text
compatible CUDA device/runtime    -> CUDA accelerator
otherwise compatible OpenCL       -> OpenCL accelerator
otherwise                         -> deterministic CPU reference
```

CUDA eligibility is capability-based, not vendor-name-based: the runtime, driver, device compute capability, available memory, and compiled kernel targets must all satisfy the backend manifest. An NVIDIA card that is too old for the supported CUDA kernel/toolchain automatically tries OpenCL when it exposes the required OpenCL device capabilities, then falls back to CPU. No GPU is rejected merely because another accelerator API is unavailable.

Accelerated planning has a strict wall-time budget. Device discovery, compilation, allocation, transfer, kernel, timeout, numerical, or validation failure follows the same CUDA -> OpenCL -> CPU fallback ladder without losing runnable work. Accelerator-specific APIs and memory never enter execution-state, semantic, solver, replay, or persistence types.

GPU use is justified only for sufficiently large batches whose measured scheduling benefit exceeds host/device transfer and launch overhead. Small queues remain on the CPU. CUDA/OpenCL kernels operate on compact feature matrices and assignment candidates, not COW pages, symbolic AST mutation, or arbitrary target execution.

Quantum-inspired and GPU decisions are replay-visible. Deterministic mode either uses the CPU reference optimizer or records the complete candidate batch, objective/schema version, backend identity, device capability, kernel compatibility manifest, seed, budget, result, attempted fallback chain, and fallback reason.

---

## Native multicore and NUMA

The scheduler uses native worker threads with worker-local deques and work stealing.

Expected locality ownership:

```text
worker-local:
  solver contexts
  hot expression cache
  trace flight recorder
  local state deque
  temporary semantic builders

shared immutable/persistent:
  sealed semantic blocks
  decode/form tables
  expression/state roots
  code metadata
  target profiles

NUMA-local where profitable:
  worker groups
  block caches
  arenas/pages
  solver pools
  queue shards
```

State stealing is not based only on queue depth.

Conceptually:

```text
steal_value = load_imbalance_gain
            - solver_context_rebuild_cost
            - NUMA_migration_cost
            - cache_locality_loss
            - COW/materialization_cost
```

The implementation must expose migration and affinity telemetry so firmware or hardware behavior cannot hide poor software design.
