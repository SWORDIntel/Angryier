# Angryier Benchmarking Contract

Performance claims are only accepted when they are reproducible and split by workload class. A single headline speedup is not meaningful for symbolic execution because different binaries are dominated by different costs.

## Comparison Target

Primary reference: angr running equivalent symbolic/concolic tasks.

Optional secondary references may include SymCC/SymQEMU or other engines when the workload is genuinely comparable, but they must not replace the angr baseline.

## Workload Classes

### A — Concrete-heavy

Purpose: measure interpreter/runtime overhead and fast-path effectiveness.

Characteristics:

- mostly concrete execution;
- small amount of tainted/symbolic input;
- few solver calls;
- long basic-block sequences.

Primary metrics:

- wall time;
- instructions/second;
- blocks/second;
- expression nodes created;
- peak RSS.

### B — Branch-parallel

Purpose: measure scheduler scaling.

Characteristics:

- many independent feasible branches;
- modest solver complexity;
- enough runnable states to saturate workers.

Run at:

```text
1, 2, 4, 8, 16, ... workers up to physical-core count
```

Primary metrics:

- speedup vs 1 worker;
- parallel efficiency;
- steals;
- worker utilization;
- peak runnable states;
- peak RSS.

### C — Solver-heavy

Purpose: determine whether engine improvements matter once SMT dominates.

Characteristics:

- fewer branches;
- complex bitvector constraints;
- substantial solver time.

Primary metrics:

- total wall time;
- solver wall time;
- number of solver queries;
- query-cache hit rate;
- average serialized AST size;
- timeout count.

### D — Memory-symbolic

Purpose: stress symbolic memory and COW state.

Characteristics:

- symbolic bytes spread through mapped pages;
- repeated state forks;
- sparse writes after forks;
- concrete and symbolic address cases separated into subtests.

Primary metrics:

- fork latency;
- load/store throughput;
- page copies;
- symbolic overlay entries;
- peak RSS.

### E — State-explosion

Purpose: evaluate search policy rather than pretend language choice removes exponential complexity.

Characteristics:

- intentionally explosive branch structures;
- bounded target or coverage goal.

Primary metrics:

- time-to-target;
- states explored;
- states pruned;
- solver queries;
- coverage reached;
- peak RSS.

Results must state whether exploration was complete, bounded, or heuristic/pruned.

## Correctness Before Timing

A timed result is invalid unless the engines are solving the same problem.

For each benchmark record:

- binary SHA-256;
- architecture;
- entry point;
- symbolic input definition;
- target/avoid conditions;
- environment model assumptions;
- solver and timeout;
- search strategy;
- generated testcase hash;
- replay result.

If Angryier and angr disagree on reachability, that benchmark is classified as a correctness investigation and excluded from performance summaries.

## Host Control

Benchmark scripts should record and, where possible, control:

- CPU model and microcode;
- physical/logical core count;
- kernel version;
- Rust compiler version;
- build profile and target CPU flags;
- solver version;
- angr/Python versions;
- CPU affinity;
- governor/frequency policy;
- NUMA topology;
- memory capacity;
- transparent huge page state if relevant.

Avoid comparing runs from thermally or power constrained states without recording that condition.

## Build Profiles

At minimum test:

```text
debug        # correctness only, never quoted for speed
release      # standard production comparison
release-lto  # optional maximum-throughput comparison
```

Do not hide unsafe semantic changes behind the benchmark profile.

## Repetition

For short/medium tests:

- one warm-up run;
- at least 5 measured runs;
- report median;
- report min/max or dispersion.

For long solver-heavy tests, fewer repetitions may be used when total runtime is prohibitive, but this must be explicit.

## Metrics Schema

Every Angryier run should emit JSON containing at least:

```json
{
  "engine": "angryier",
  "git_sha": "...",
  "wall_ms": 0,
  "cpu_ms": 0,
  "peak_rss_bytes": 0,
  "workers": 1,
  "instructions": 0,
  "basic_blocks": 0,
  "states_created": 0,
  "states_completed": 0,
  "states_pruned": 0,
  "peak_states": 0,
  "expr_nodes_created": 0,
  "expr_cache_hits": 0,
  "solver_queries": 0,
  "solver_cache_hits": 0,
  "solver_ms": 0,
  "solver_timeouts": 0,
  "coverage_edges": 0,
  "result": "reached|not_reached|timeout|error"
}
```

The schema should be versioned before external consumption.

## Derived Metrics

### Speedup

```text
speedup = reference_wall_time / angryier_wall_time
```

### Parallel efficiency

```text
parallel_efficiency = speedup_N / N
```

### Solver fraction

```text
solver_fraction = solver_time / wall_time
```

This is crucial: if solver fraction approaches 1.0, further executor micro-optimisation cannot produce large end-to-end gains.

### Memory per live state

```text
approx_bytes_per_state = peak_rss / peak_live_states
```

Use only as an approximate diagnostic because shared pages/caches make attribution imperfect.

## Performance Gates

The following are engineering gates, not promises about all binaries.

### Gate 1 — Native overhead

On concrete-heavy microbenchmarks, Angryier must clearly outperform a Python-driven symbolic execution path before expensive optimisation work continues.

### Gate 2 — Fork scalability

Forking a state with large mapped memory but tiny write deltas must remain close to constant cost in total mapped-memory size.

### Gate 3 — Multicore

Branch-parallel workloads must show useful scaling from 1 to multiple physical cores. A flat curve is a blocker and must be profiled before adding features.

### Gate 4 — Solver discipline

Constraint slicing/caching must reduce solver work on at least the designated solver-heavy suite without changing satisfiability results.

### Gate 5 — JIT justification

JIT work is justified only when profiles show concrete execution remains a significant fraction of wall time after the earlier optimisations.

## Claims Policy

Never write claims such as `10x`, `50x`, or `100x faster than angr` into release documentation unless backed by a named benchmark suite and reproducible results.

Use wording such as:

```text
Median 8.4x speedup over angr on suite B at 16 workers; solver-heavy suite C showed 1.3x.
```

This distinction matters because an engine can be dramatically faster on runtime-dominated workloads and barely faster when both engines are waiting on equivalent SMT queries.

## Regression Policy

CI should preserve a rolling benchmark baseline.

Flag:

- >10% median wall-time regression on stable microbenchmarks;
- >10% peak-RSS regression unless explained;
- loss of parallel scaling;
- solver query-count increase without corresponding coverage/solution improvement;
- any semantic mismatch.

Performance regression checks should tolerate normal system noise and should not block on a single anomalous run.
