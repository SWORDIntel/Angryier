# Angryier Architecture

## Objective

Angryier is a native, parallel symbolic/concolic execution engine whose primary design constraint is throughput.

The project is **not** an angr rewrite and does not target angr API compatibility. It targets the workloads where angr spends substantial time in Python-side execution, state management, AST construction, memory modelling, scheduling, and solver orchestration.

The core design rule is:

> Do not symbolically interpret work that can remain concrete, do not copy state that can be shared, and do not serialize work that can be executed independently.

## Fixed V1 Decisions

| Area | Decision |
|---|---|
| Implementation language | Rust |
| Initial ISA | x86-64 |
| Initial binary formats | ELF64, PE32+ |
| Execution model | Hybrid concrete + concolic + symbolic |
| Parallelism | State-level work stealing |
| State model | Copy-on-write/persistent |
| Expression model | Arena allocated, interned DAG using compact IDs |
| Solver model | Per-worker incremental solver context |
| Initial solver | Z3 through native C API bindings |
| Secondary solver | Bitwuzla adapter after the solver trait stabilises |
| Initial lifter | libVEX through a narrow FFI adapter |
| Concrete fast path | Native/basic-block fast executor; Unicorn-backed MVP is acceptable behind a replaceable trait |
| JIT target | Cranelift-backed block JIT after baseline executor correctness |
| Python | Optional bindings only; never in the hot path |
| Scheduler | Native CPU worker pool; no async runtime |
| Scope | Single-host multicore first; distributed execution deferred |

## High-Level Pipeline

```text
ELF / PE
   |
   v
Loader + image model
   |
   v
libVEX lifter
   |
   v
Canonical AngryIR
   |
   +----------------------------+
   |                            |
   v                            v
Concrete / taint fast path      Symbolic executor
   |                            |
   +-------------+--------------+
                 |
                 v
          branch / fork
                 |
                 v
       work-stealing scheduler
          /      |       \
       worker  worker   worker
          |      |       |
       state   state   state
          |      |       |
       SMT ctx SMT ctx SMT ctx
```

## Component Boundaries

The repository should converge on this workspace layout:

```text
crates/
  angryier-cli/        # command-line frontend
  angryier-loader/     # ELF/PE image loading, relocations, mappings
  angryier-ir/         # canonical compact IR and block representation
  angryier-lifter-vex/ # libVEX FFI and VEX -> AngryIR lowering
  angryier-exec/       # concrete/concolic/symbolic execution engine
  angryier-state/      # registers, memory, constraints, fork/merge
  angryier-expr/       # symbolic expression DAG and simplifier
  angryier-memory/     # COW pages and symbolic byte/cell overlay
  angryier-solver/     # solver trait, incremental contexts, caches
  angryier-solver-z3/  # Z3 backend
  angryier-scheduler/  # worker pool and work stealing
  angryier-models/     # syscall/libc/environment models
  angryier-bench/      # benchmark harness and corpus
  angryier-python/     # optional pyo3 API; never required by core
```

Dependency direction must remain acyclic. In particular, solver backends depend on the solver interface, and frontends depend on the engine; the engine never depends on Python.

## AngryIR

VEX is an input representation, not the internal state API. Lower lifted blocks once into a compact internal IR that is cheap to dispatch and stable across backend changes.

Requirements:

- SSA-like temporaries within a basic block.
- Explicit register reads/writes.
- Explicit memory loads/stores.
- Explicit endianness and bit width.
- Integer/bitvector semantics first.
- Branch targets represented explicitly.
- No heap allocation per operand during execution.
- Operands encoded by compact IDs or inline immediates.
- Blocks cached by `(image_id, address, code_hash)`.

Example shape:

```rust
pub type ValueId = u32;
pub type ExprId = u32;

pub enum Op {
    Const { dst: ValueId, width: u16, imm: u128 },
    ReadReg { dst: ValueId, reg: RegId, width: u16 },
    WriteReg { reg: RegId, src: ValueId, width: u16 },
    Load { dst: ValueId, addr: ValueId, width: u16 },
    Store { addr: ValueId, src: ValueId, width: u16 },
    Add { dst: ValueId, lhs: ValueId, rhs: ValueId, width: u16 },
    CmpEq { dst: ValueId, lhs: ValueId, rhs: ValueId, width: u16 },
    Branch { cond: ValueId, taken: u64, not_taken: u64 },
}
```

The concrete executor and symbolic executor consume the same AngryIR.

## Value Domain

Every runtime value uses a tagged domain with the concrete case optimized for the common path:

```text
Concrete(value)
Symbolic(expr_id)
ConcreteTainted(value, taint_id)
```

A value should not become symbolic merely because it originated from an interesting input. Cheap taint propagation is used to determine whether symbolic promotion is required.

Promotion occurs when a tainted value participates in an operation where path reasoning or symbolic output is required.

## Expression Engine

Symbolic expressions are immutable and referenced through compact `ExprId` values.

Required properties:

- arena allocation;
- structural hashing/hash-consing;
- canonical commutative operands where valid;
- constant folding;
- width-aware simplification;
- cheap expression-depth and node-count accounting;
- stable serialization into solver ASTs;
- worker-local construction caches where contention would otherwise occur.

Mandatory simplifications include identities such as:

```text
x + 0 -> x
x ^ 0 -> x
x & x -> x
x == x -> true
extract(concat(a,b), exact-range) -> a/b when possible
```

The expression engine must expose statistics so simplification effectiveness can be measured.

## State Model

A state consists conceptually of:

```rust
pub struct State {
    pub pc: u64,
    pub regs: RegisterFile,
    pub memory: Memory,
    pub constraints: ConstraintSet,
    pub metadata: StateMetadata,
}
```

Forking must be close to O(1) in unchanged state size.

### Registers

Use a compact copy-on-write register file. x86-64 has a small enough architectural register set that a flat representation with dirty tracking is preferable to per-register heap objects.

### Memory

Memory is page based. A page contains:

- concrete byte backing;
- symbolic/taint bitmap;
- sparse symbolic overlay keyed by offset;
- page permissions;
- copy-on-write ownership metadata.

A mostly concrete page must remain mostly concrete. One symbolic byte must not turn 4096 bytes into symbolic objects.

Symbolic addresses use a separate slow path and must not contaminate ordinary concrete-address loads/stores.

### Constraints

Constraints are stored by immutable IDs with parent lineage rather than repeatedly copied vectors. Each worker materializes the required incremental solver stack for the state it is executing.

## Solver Architecture

```text
State
  |
  v
Constraint slicing
  |
  v
Native simplifier
  |
  +--> known/cache hit --> result
  |
  v
Solver backend
```

Rules:

1. No global solver mutex.
2. Each execution worker owns or leases a solver context.
3. Use incremental `push`/`pop` where lineage permits.
4. Cache SAT/UNSAT/model queries by normalized constraint/query identity.
5. Track wall time and solver time separately.
6. Support hard per-query timeouts.
7. Record timeout/unknown distinctly from UNSAT.
8. Constraint slicing should omit path constraints that cannot affect the queried expression.

The solver interface must allow Z3 and Bitwuzla to coexist without leaking backend AST types into the executor.

## Scheduler

V1 uses a fixed-size native worker pool with work stealing.

Each runnable state is an independent work item. Workers should preferentially continue locally-created states to preserve cache locality, while idle workers steal from peers.

Scheduler state scoring must be pluggable. Initial policies:

- breadth-first;
- depth-first;
- coverage novelty;
- target-distance;
- solver-cost-aware.

The scheduler records:

- runnable states;
- completed states;
- pruned states;
- steals;
- average queue depth;
- worker utilization;
- solver utilization;
- state forks/merges.

No Tokio or async executor is used for CPU execution.

## Concrete Fast Path

The executor should remain in the concrete domain as long as possible.

V1 may use an interpreter or Unicorn-backed executor to establish correctness. The long-term fast path is cached block execution/JIT.

Transition to the symbolic engine occurs only when symbolic semantics are required, for example:

- a branch condition depends on a symbolic expression;
- a symbolic value is loaded/stored;
- an address becomes symbolic;
- an externally requested symbolic observation is reached.

Concrete-only blocks should avoid expression construction entirely.

## JIT

JIT is deliberately **not** Phase 1. It is introduced only after the IR, state model, and differential tests are stable.

Cranelift is the preferred first JIT backend because it provides a Rust-friendly code-generation path and fast compilation suitable for basic-block JIT use.

The JIT must preserve hooks for:

- taint propagation;
- memory permissions;
- code invalidation/self-modifying code;
- transition back to symbolic execution.

## State Merging

Merging is optional and policy driven.

Only consider merge candidates sharing a program counter and compatible environment state. Reject merges when estimated expression growth exceeds configurable thresholds.

A merge is an optimization, never a requirement for correctness.

## Environment Models

Do not emulate a full OS in V1.

Implement deterministic models for the minimum required surface:

- process entry state;
- stdin/stdout/stderr;
- argv/envp;
- file-like symbolic input;
- heap allocation primitives needed by benchmark programs;
- a small syscall subset required by the initial corpus.

Unsupported syscalls terminate the state with an explicit reason rather than silently guessing semantics.

## Observability

Every run must emit machine-readable metrics, including:

```text
wall_time
instructions_executed
basic_blocks
states_created
states_completed
states_pruned
peak_states
expr_nodes_created
expr_cache_hits
solver_queries
solver_cache_hits
solver_time
solver_timeouts
peak_rss
coverage_edges
```

JSON output is mandatory for benchmark automation.

## Correctness Strategy

Performance is invalid without semantic equivalence.

Use four test layers:

1. Unit tests for every IR operation and simplification rule.
2. Differential concrete execution against native execution/Unicorn for small blocks.
3. Differential symbolic results against angr on curated micro-programs.
4. End-to-end testcase generation checks on benchmark binaries.

Any optimization that changes reachable-state semantics fails CI until proven equivalent or explicitly documented as an approximation mode.

## Explicit Non-Goals for V1

Do not add these until the core benchmark gates are satisfied:

- distributed execution;
- GUI;
- angr API compatibility;
- architecture support beyond x86-64;
- full POSIX/Linux emulation;
- Windows kernel modelling;
- plugin marketplace;
- decompiler;
- whole-program static analysis framework;
- speculative ML-guided scheduling;
- GPU symbolic execution.

These are scope traps until the native execution core proves itself.
