# Angryier

> When you are absolutely furious your symbolic execution is taking too long and you just can't stand it anymore and you're not just angry, you're **Angryier**.

Angryier is a planned native, multicore symbolic/concolic execution engine written in Rust with one overriding objective: **reduce end-to-end time-to-solution compared with Python-heavy symbolic execution workflows.**

It is not intended to be an angr rewrite or API clone. The design focuses on removing avoidable runtime overhead and attacking the actual dominant costs of binary symbolic execution: state copying, expression construction, symbolic memory, solver orchestration, scheduling, and state explosion.

## Design Thesis

```text
Do not symbolically interpret work that can remain concrete.
Do not copy state that can be shared.
Do not serialize work that can execute independently.
Do not optimize a layer until profiling proves it matters.
```

## V1 Direction

- **Rust** native core.
- **x86-64** first.
- **ELF64 + PE32+** first.
- **libVEX** lifting behind a narrow adapter.
- Compact internal **AngryIR** shared by concrete and symbolic execution.
- Arena-allocated, hash-consed symbolic expression DAG using compact IDs.
- Page-based **copy-on-write memory** with sparse symbolic overlays.
- Persistent constraint lineage rather than deep state copies.
- **Z3** first, behind a backend-independent solver trait.
- **Per-worker solver contexts**, never a single globally locked solver.
- Native **work-stealing state scheduler** for multicore execution.
- Cheap taint/concrete domain before promotion to symbolic expressions.
- Concrete JIT only after profiling justifies it.
- Python only as an optional API layer, never in the execution hot path.

## Execution Model

```text
              ELF / PE
                 |
                 v
           loader + lifter
                 |
                 v
              AngryIR
                 |
          +------+------+
          |             |
          v             v
 concrete/taint      symbolic
   fast path         execution
          |             |
          +------+------+
                 |
              branch
                 |
                 v
       work-stealing scheduler
          /       |       \
       worker   worker   worker
          |       |       |
       COW state COW    COW state
          |       |       |
        SMT ctx SMT ctx SMT ctx
```

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — fixed architectural decisions, state/memory/expression/solver design, scheduler, JIT policy, correctness strategy, and non-goals.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — implementation order from repository bootstrap through loader/IR, symbolic execution, COW state, solver, parallel scheduler, taint fast-path, solver optimization, JIT, and packaging. Every phase has exit criteria.
- [`docs/BENCHMARKING.md`](docs/BENCHMARKING.md) — benchmark contract, workload classes, metrics schema, multicore scaling methodology, correctness requirements, and performance-regression rules.

## Definition of V1

V1 is reached when Angryier can:

1. load an x86-64 ELF or PE binary;
2. lift and execute supported code;
3. mark external input symbolic;
4. fork on symbolic branches;
5. solve branch constraints;
6. explore independent states across multiple CPU cores;
7. generate a concrete input reaching a requested target;
8. successfully replay that input against the target;
9. emit machine-readable performance metrics; and
10. run a reproducible comparison against angr.

JIT, Bitwuzla, state merging, Python bindings, distributed execution, broad OS emulation, and additional ISAs are **not V1 blockers**.

## Current Status

**Design/scaffold phase.** The architecture and implementation gates are defined; the Rust workspace and engine implementation have not yet been bootstrapped.

The first implementation milestone is Phase 0 in [`docs/ROADMAP.md`](docs/ROADMAP.md): create the Cargo workspace, CI, benchmark harness, angr reference runner, metrics schema, and differential micro-corpus before implementing the execution engine.

## Performance Policy

Angryier does not claim an arbitrary `10x`, `50x`, or `100x` advantage. Performance is workload-dependent. Claims must come from reproducible benchmark classes and must separate executor time from solver time.

The project succeeds if profiling and benchmarks demonstrate substantial speedups where engine/runtime overhead is dominant, useful multicore scaling on branch-parallel workloads, and no semantic regressions against reference execution.
