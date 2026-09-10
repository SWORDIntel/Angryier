# Angryier Implementation Roadmap

This roadmap is ordered to establish correctness first, then remove the dominant costs one by one. A phase does not advance because code exists; it advances when its exit criteria are satisfied.

## Phase 0 — Repository and Measurement Baseline

### Deliverables

- Cargo workspace with the crate boundaries from `ARCHITECTURE.md`.
- CI for formatting, clippy, tests, sanitizers where applicable, and benchmark smoke tests.
- Benchmark harness capable of running Angryier and reference tools under identical limits.
- JSON metrics schema.
- Initial micro-binary corpus checked into `bench/corpus/` with source and build scripts.
- Reference angr runner for differential and performance comparison.

### Exit criteria

- Reproducible benchmark command from a clean checkout.
- Same binary, input constraints, CPU affinity, timeout, and memory limit can be supplied to both engines.
- Benchmark output records git SHA, compiler version, solver version, host CPU, kernel, wall time, CPU time, and peak RSS.

## Phase 1 — Loader + IR + Concrete Correctness

### Build

- ELF64 loader.
- PE32+ loader.
- x86-64 register model.
- libVEX FFI crate.
- VEX -> AngryIR lowering.
- AngryIR concrete interpreter.
- Block cache keyed by image/address/code identity.
- Minimal Linux userspace entry-state model sufficient for benchmark programs.

### Tests

- Instruction/IR unit tests.
- Differential block execution against native/Unicorn reference results.
- Loader address/permission/segment tests.

### Exit criteria

- Curated concrete programs execute deterministically to the expected exit point.
- Register and memory results match the reference executor for the supported instruction corpus.
- No Python runtime dependency exists in the execution path.

## Phase 2 — Symbolic Values + Expressions

### Build

- `ExprId` arena.
- Structural hashing/hash-consing.
- Constants, variables, arithmetic, logical, comparison, concat/extract, shifts, extensions.
- Constant folding and mandatory algebraic simplifications.
- Concrete/symbolic tagged runtime values.
- Symbolic register support.
- Expression serialization API for solvers.

### Exit criteria

- Symbolic micro-tests produce expressions equivalent to reference formulas.
- Repeated identical subexpressions intern to the same expression identity.
- Simplifier property tests show semantic equivalence using solver checks.
- Expression statistics are exposed in JSON metrics.

## Phase 3 — COW Memory + State Forking

### Build

- Page-based concrete backing.
- Sparse symbolic byte/cell overlay.
- Symbolic bitmap/taint metadata.
- Copy-on-write page ownership.
- Persistent constraint lineage.
- State fork primitive.

### Required benchmark

Create a synthetic branch tree that forks thousands of states while modifying a small fraction of memory.

### Exit criteria

- Fork cost does not scale linearly with total mapped memory.
- Unchanged pages are shared across sibling states.
- State destruction releases shared resources without leaks.
- Peak memory use is recorded and compared with a naive deep-copy baseline.

## Phase 4 — Z3 Backend + Path Exploration

### Build

- Backend-independent solver trait.
- Z3 implementation.
- Incremental context management.
- SAT/UNSAT/model APIs.
- Per-query timeout support.
- Solver query cache.
- Constraint dependency metadata for later slicing.
- Basic DFS/BFS exploration.

### Exit criteria

- Branch feasibility matches angr/reference expectations on the symbolic micro-corpus.
- Generated satisfying inputs reproduce the target native path.
- Solver timeout is represented as `unknown/timeout`, never silently as UNSAT.
- Solver time is separately measurable from engine time.

## Phase 5 — Native Parallel Scheduler

### Build

- Fixed-size worker pool.
- Per-worker local deque + work stealing.
- Per-worker solver context.
- Deterministic single-thread mode for debugging.
- State scoring policy trait.
- DFS, BFS, and coverage-novelty policies.
- Worker/scheduler telemetry.

### Exit criteria

- 1-thread results are semantically equivalent to Phase 4.
- N-thread execution reaches the same solution set for deterministic bounded tests.
- No global mutex appears on the normal execution or solver-query path.
- Parallel speedup is measured at 1/2/4/8/... workers on a branch-parallel corpus.
- Scaling regressions are visible in benchmark output rather than hidden by aggregate timing.

## Phase 6 — Taint-Guided Concrete Fast Path

### Build

- Cheap taint domain.
- Taint propagation through AngryIR.
- Promotion policy from tainted concrete to symbolic.
- Concrete-only execution path that allocates no symbolic expression nodes.
- Fast transition between concrete and symbolic domains.

### Exit criteria

- Mostly concrete workloads show materially fewer expression nodes and solver interactions than always-symbolic mode.
- Differential tests prove path behavior is unchanged for supported semantics.
- Metrics report time spent concrete vs symbolic.

## Phase 7 — Constraint Slicing + Solver Optimisation

### Build

- Variable/dependency tracking.
- Query-specific constraint slicing.
- Normalized solver-cache keys.
- Incremental-context reuse across related states.
- Optional Bitwuzla backend.
- Solver routing/portfolio experiments behind feature flags.

### Exit criteria

- Sliced and unsliced queries are solver-equivalent on the correctness corpus.
- Solver wall time and serialized AST size both improve on at least one designated solver-heavy benchmark class.
- Backend choice is isolated behind the solver trait.

## Phase 8 — JIT Concrete Blocks

### Build

- Cranelift lowering for supported AngryIR concrete operations.
- Executable block cache.
- Guarded transitions for taint/symbolic values.
- Memory access hooks and permission checks.
- Code cache invalidation policy for writable/executable mappings.

### Exit criteria

- JIT and interpreter produce identical architectural state on the concrete differential suite.
- JIT materially improves instructions/second for concrete-heavy benchmark classes.
- JIT compile cost and cache hit rate are exposed in metrics.

## Phase 9 — Search and State-Explosion Controls

### Build

- Coverage-novelty scheduler.
- Target-distance scheduler when CFG information is available.
- Loop-iteration accounting.
- Solver-cost-aware prioritisation.
- Optional conservative state merging.
- Merge cost model based on memory delta and expression growth.

### Exit criteria

- Every heuristic can be disabled.
- Baseline complete-search mode remains available for bounded tests.
- Approximation/pruning modes are explicitly marked in output.
- Heuristic wins are demonstrated as time-to-solution/coverage improvements, not anecdotal examples.

## Phase 10 — API Stabilisation and Packaging

### Build

- Stable Rust library API.
- CLI documentation.
- Optional Python bindings through PyO3.
- Reproducible release builds.
- Versioned benchmark reports.
- Corpus/results publication tooling where licensing permits.

### Exit criteria

- Core engine can be embedded without the CLI or Python package.
- Python bindings only marshal configuration/results and do not implement execution semantics.
- Release benchmark report is generated automatically.

# Initial CLI Contract

The first useful interface should remain small:

```text
angryier run <binary> \
  --symbolic-stdin 32 \
  --workers 16 \
  --strategy coverage \
  --target 0x401337 \
  --timeout 60s \
  --solver-timeout 2s \
  --metrics result.json
```

Useful additional commands:

```text
angryier lift <binary> --address 0x401000
angryier bench --suite micro --compare angr
angryier replay <binary> --input testcase.bin
```

# Definition of V1

V1 is reached when Angryier can:

1. load an x86-64 ELF or PE binary;
2. lift and execute supported code;
3. mark external input symbolic;
4. fork on symbolic branches;
5. solve branch constraints;
6. explore states across multiple CPU cores;
7. generate a concrete input for a reachable target;
8. replay that input successfully against the native target;
9. emit complete performance metrics; and
10. run a reproducible comparison against angr.

V1 does **not** require JIT, Bitwuzla, state merging, Python bindings, distributed execution, or broad OS emulation. Those are optimisation/expansion stages, not prerequisites for proving the architecture.

# Go/No-Go Gates

## Gate A — after Phase 4

Proceed only if symbolic results are correct and the native Rust core is already competitive with or faster than the reference on micro-workloads where Python overhead matters.

If not, profile before adding parallelism.

## Gate B — after Phase 5

Proceed only if branch-parallel workloads scale usefully across cores.

If scaling is poor, investigate allocator contention, shared caches, solver context contention, NUMA traffic, and state size before adding JIT.

## Gate C — after Phase 7

Proceed to JIT only if profiling shows concrete execution remains a major wall-time component.

If solver time dominates, spend engineering effort on slicing/caching/search rather than code generation.

## Gate D — before adding new architectures

Do not add ARM/AArch64 until x86-64 benchmark and correctness gates are automated. New ISA work must not become a substitute for proving the core performance thesis.
