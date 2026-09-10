# Angryier Benchmarking Contract

Performance claims are accepted only when they are reproducible, semantically comparable, and split by workload class.

A symbolic-execution benchmark is invalid if one engine solves a weaker problem, uses a looser environment model, silently concretizes, or reaches a result with a different fidelity policy.

---

# Comparison Targets

Primary reference: angr on equivalent symbolic/concolic tasks.

Additional references may include SymCC/SymQEMU, Triton, KLEE, QSYM, S2E, Manticore, or other engines when the workload is genuinely comparable.

No single comparison target is sufficient for all workload classes.

---

# Workload Classes

## A — Concrete-heavy

Purpose: measure fast-path/runtime overhead.

Characteristics:

- mostly concrete execution;
- small symbolic/tainted surface;
- few solver calls;
- long basic-block sequences.

Metrics:

- wall time;
- instructions/second;
- blocks/second;
- expression nodes created;
- taint operations;
- peak RSS.

## B — Branch-parallel

Purpose: measure scheduler scaling.

Run at:

```text
1, 2, 4, 8, 16, ... workers up to physical-core count
```

Metrics:

- speedup vs one worker;
- parallel efficiency;
- steals;
- rejected steals due to affinity cost;
- solver-context rebuilds;
- worker utilization;
- NUMA migrations where measurable;
- peak runnable states;
- peak RSS.

## C — Solver-heavy

Purpose: measure solver architecture and reuse.

Metrics:

- total wall time;
- solver wall time;
- solver queries;
- shared-context batches;
- average predicates per batch;
- local cache hits;
- persistent exact hits;
- generalized-fact hits;
- UNSAT-core reuse;
- serialized AST size;
- timeout/UNKNOWN count;
- backend selection.

## D — Symbolic memory/state

Purpose: stress COW state and sparse symbolic memory.

Metrics:

- fork latency;
- page copies;
- symbolic overlay entries;
- symbolic-address queries;
- structured vector/tile materialization counts;
- load/store throughput;
- peak RSS.

## E — State explosion/search

Purpose: evaluate search policy honestly.

Metrics:

- time-to-target;
- coverage;
- states explored/pruned;
- solver work;
- peak states;
- approximation/pruning policy;
- whether exploration was complete, bounded, or heuristic.

## F — Intel semantic coverage

Purpose: measure semantic correctness, not speed.

Corpus should include representative and generated forms across declared feature families.

Metrics:

- decoded forms;
- semantic forms implemented;
- concrete differential pass rate;
- symbolic validation pass rate;
- taint validation pass rate;
- unsupported forms;
- semantic disagreements;
- family support percentage.

A decode success is never counted as semantic support.

## G — Fidelity profiles

Run equivalent tasks under:

```text
PROVE
EXPLORE
HUNT
```

Record:

- wall time;
- coverage;
- findings;
- approximations;
- concretizations;
- replay success;
- exact-upgrade success;
- false-positive/false-negative evidence where known.

The goal is to quantify the cost/value of fidelity tradeoffs.

## H — Provenance overhead

Compare:

```text
Tier 0 only / persistence disabled
Tier 1 structural provenance
Tier 1 + adaptive Tier 2
forced deep trace
```

Metrics:

- execution slowdown;
- event volume;
- retained bytes;
- trace-governor transitions;
- compression/dedup ratio;
- persistence queue depth;
- backpressure time;
- pre-trigger recovery success around injected events.

## I — Cumulative knowledge reuse

Run correlated binaries/workloads in cold and warm knowledge states.

Metrics:

- exact cross-run hit count;
- generalized-fact hit count;
- facts requiring revalidation;
- stale fact rejection;
- solver queries avoided;
- wall time saved;
- wrong-reuse count (**must be zero in PROVE**);
- knowledge lookup overhead.

## J — Learned fusion retrieval

Evaluate specialist encoders + learned fusion independently from execution speed.

Compare at least:

```text
384-D
1024-D
2048-D
4096-D
```

Metrics:

- precision@k;
- recall@k;
- MRR/nDCG where appropriate;
- validated-equivalence conversion rate;
- candidate usefulness to scheduler/analyst;
- query latency;
- index memory;
- raw vector storage;
- rerank cost;
- contribution/explanation quality.

A higher-dimensional profile wins only if measured retrieval benefit justifies cost.

## K — Vector/mask/tile semantics

Purpose: expose whether structured AVX/AVX-512/AMX representation controls symbolic growth.

Compare structured/lazy representation against deliberately flattened baselines where practical.

Metrics:

- expression-node count;
- solver AST size;
- solver time;
- materialized lanes/cells;
- peak RSS;
- semantic-equivalence pass rate.

---

# Correctness Before Timing

Every benchmark records at least:

```text
binary SHA-256
architecture/target profile
semantic version
semantics-generator version
environment model version
solver + version
fidelity profile
symbolic input definition
target/avoid conditions
search strategy
approximation policy
generated testcase hash
native replay result
knowledge-state identity (cold/warm)
```

If engines disagree on reachability or state semantics, classify the result as a correctness investigation and exclude it from performance summaries until resolved.

---

# Host Control

Record and control where possible:

- CPU model and microcode;
- physical/logical cores;
- Intel feature set;
- kernel;
- Rust compiler;
- build flags;
- solver versions;
- comparison-engine versions;
- CPU affinity;
- frequency/governor policy;
- NUMA topology;
- memory capacity;
- thermal/power throttling state;
- transparent huge page state where relevant.

Do not present thermally/power-limited runs as equivalent to unrestricted runs without labeling them.

---

# Build Profiles

At minimum:

```text
debug
release
release-lto
```

Debug is correctness-only and is never quoted for speed.

No build profile may silently alter semantic fidelity.

---

# Repetition and Statistics

For short/medium benchmarks:

- warm-up run;
- at least five measured runs;
- median reported;
- dispersion/min/max reported.

Long solver-heavy runs may use fewer repetitions when explicitly stated.

For scheduler/scaling tests, report both aggregate runtime and per-worker utilization/steal behavior so a misleading speedup is easier to detect.

---

# Metrics Schema

Every run should emit versioned machine-readable metrics including at least:

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
  "solver_local_cache_hits": 0,
  "solver_persistent_exact_hits": 0,
  "solver_generalized_hits": 0,
  "solver_ms": 0,
  "solver_timeouts": 0,
  "shared_context_batches": 0,
  "coverage_edges": 0,
  "fidelity_profile": "PROVE",
  "approximations": 0,
  "tier1_events": 0,
  "tier2_triggers": 0,
  "tier2_bytes": 0,
  "persistence_backpressure_ms": 0,
  "knowledge_exact_hits": 0,
  "knowledge_advisory_hits": 0,
  "native_replay": "pass|fail|not_applicable",
  "result": "reached|not_reached|timeout|unknown|error"
}
```

---

# Derived Metrics

## Speedup

```text
speedup = reference_wall_time / angryier_wall_time
```

## Parallel efficiency

```text
parallel_efficiency = speedup_N / N
```

## Solver fraction

```text
solver_fraction = solver_time / wall_time
```

## Approximate memory per live state

```text
peak_rss / peak_live_states
```

## Provenance cost

```text
provenance_overhead = (wall_with_provenance - wall_without) / wall_without
```

## Knowledge reuse efficiency

```text
reuse_efficiency = avoided_solver_or_analysis_time / knowledge_lookup_time
```

## Validated similarity yield

```text
validated_yield = validated_reusable_or_useful_candidates / similarity_candidates_returned
```

---

# Performance and Correctness Gates

## Gate 1 — Native overhead

Concrete-heavy execution must clearly outperform a Python-driven symbolic path before expensive optimization work proceeds.

## Gate 2 — Fork scalability

Fork cost must not scale linearly with unchanged mapped memory.

## Gate 3 — Multicore

Branch-parallel workloads must show useful physical-core scaling.

## Gate 4 — Solver discipline

Caching, shared-context batching, slicing, and persistent reuse must reduce solver work without changing satisfiability semantics.

## Gate 5 — Fidelity honesty

No benchmark may gain speed by silently weakening PROVE semantics.

## Gate 6 — Provenance budget

Tier 1 + adaptive Tier 2 must provide materially better causal observability without unacceptable hot-path overhead.

## Gate 7 — Knowledge safety

Wrong authoritative reuse in PROVE is a release-blocking correctness defect.

## Gate 8 — Fusion usefulness

Learned retrieval must improve candidate discovery, scheduling, or analyst insight enough to justify its compute/storage cost.

## Gate 9 — JIT justification

JIT work begins only if profiles show concrete execution remains a significant end-to-end cost.

---

# Claims Policy

Never publish a generic `10x`, `50x`, or `100x faster` claim without a named reproducible workload class.

Preferred wording:

```text
Median 8.4x speedup over angr on branch-parallel suite B at 16 workers;
solver-heavy suite C improved 1.3x; PROVE semantics and replay criteria matched.
```

Performance, semantic coverage, fidelity, and knowledge-reuse claims are reported separately.

---

# Regression Policy

CI or scheduled benchmark infrastructure should flag:

- >10% stable median wall-time regression;
- >10% peak-RSS regression unless justified;
- loss of multicore scaling;
- increased solver queries without corresponding coverage/solution benefit;
- provenance overhead regression;
- knowledge lookup/reuse regression;
- fusion retrieval-quality regression;
- any semantic mismatch;
- any incorrect authoritative cross-run reuse.

Normal system noise must be accounted for; a single anomalous run should not block without confirmation.
