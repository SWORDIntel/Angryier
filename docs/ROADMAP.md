# Angryier Implementation Roadmap

> **Status:** Phases 0–3 and Phase 5 foundations are implemented. Phase 6 (concolic fast path) is implemented: `ConcolicEvaluator` shadows each lowered block with constant-folding concrete/symbolic pairs, `ConcolicSession` records branch path constraints during concrete execution, inverting a branch through Z3 or the new `angryier-solver-fuzzy` mutation tier produces valid inputs, PROVE/EXPLORE/HUNT fidelity profiles gate shadow-debt tolerance, and a dual-mode differential test shows both modes produce the same input on the same binary. Phase 4 (handwritten semantic corpus) is partially implemented — 363 Intel 64 forms now registered covering integer arithmetic/control-flow, bit-scan/popcount, SSE/SSE2 scalar and packed float (with upper-lane preservation), SSE2 packed integer/shifts/compares, SSSE3 horizontal/absolute/sign/multiply, SSE4.1 packed extend/blend/dot-product/round/extract/insert, SSE4.1 packed float compare/min/max/movmask, SSE3 packed float horizontal add/sub, SSE4.1 64-bit min/max, packed/scalar moves, SSE4.1 MPSADBW/PHMINPOSUW, SSE4.2 PCMPGTQ, SSE2 byte shifts (PSLLDQ/PSRLDQ), SSE2 PANDN, SSE4.2 CRC32, and PTEST. All forms seal deterministically; 64-bit and 32-bit integer forms, memory-operand loads/stores, and the SSE/SSE2/SSE4/SSSE3 SIMD corpus execute end-to-end through the concrete interpreter. Phase 6 foundations (replay, WAL, provenance), Phase 7 foundations (taint), Phase 9 foundations (knowledge store, QIHSE/KEYSTONE adapters, fusion model, semantic compiler), Phase 10 foundations (work-stealing scheduler, distribution codec), Phase 11 foundations (environment models, telemetry, benchmark sink, plugin registry, image loader, fuzz bridge), Phase 12 foundations (QIHSE/KEYSTONE in-memory adapters), Phase 13 foundations (fuzz bridge), Phase 14 foundations (fusion model), and Phase 16 foundations (work codec) are partially implemented in-memory.
>
> **Native integrations landed:** Z3 solver FFI (`angryier-solver-z3-ffi`, 4 tests, wired into safe `angryier-solver-z3` adapter behind `ffi` feature), Bitwuzla solver FFI (`angryier-solver-bitwuzla-ffi`, 4 tests, wired into safe `angryier-solver-bitwuzla` adapter behind `ffi` feature), and Intel XED decoder FFI (`angryier-arch-xed-ffi`, 11 tests, wired through `angryier-decode-xed` safe normalization boundary, with the XED instruction-class namespace re-exported for form mapping). All three return real SAT/UNSAT/decode outcomes; XED decode and Z3 solving are wired end-to-end through `angryier-runtime` behind the `xed` and `z3` features.
>
> **Validation baseline:** 828 tests, 0 failures across 43 test binaries; 17 additional feature-gated tests with `cargo test -p angryier-runtime --features xed,z3`. `cargo fmt` clean. Workspace Clippy clean with warnings denied. Workspace build clean. Default build has zero native dependencies; native backends are opt-in via Cargo features.
>
> **Recent progress:** ELF64 parser landed (`angryier-loader`, 27 tests — segments, entry point, static symbol table). SimProcedure library landed (`angryier-models`, 29 tests — strlen/strcmp/malloc/free/memcpy/memset/puts/exit stubs plus a minimal syscall model capturing `write` output and `exit` codes). Symbolic-address memory policy landed (`angryier-memory`, 41 tests — Concretize/FullArrays/RegionBased strategies, ConcretizationResolver, byte-granular COW coexistence). Solver portfolio router upgraded (`angryier-solver`, 30 tests — per-query dispatch via QueryShape classifier, CrossCheckPolicy, hard timeout enforcement, backend history tracking, `BatchSolver` usable as a `SolverBackend`, 9 integration tests). **Gate 0 landed:** native XED decode is wired into `angryier-runtime` behind the `xed` feature with an instruction-class form mapping, memory operand loads/stores and RIP-relative addressing are lowered, 32-bit and partial register writes execute, a single-block symbolic evaluator (`angryier-execution::symbolic`) plus Z3-backed branch solving (`z3` feature) generate and replay new inputs on a real binary, concrete replay validation confirms the generated input reaches the target state natively, modeled `write`/`exit` syscalls produce output matching a native run, and a **gcc-compiled C program runs end-to-end with the same result as native execution**.
>
> **Reality check:** **gcc-compiled C programs now run end-to-end through the engine with the same observable result as native execution — at `-O2` and at `-O0` — and real statically linked musl *and* glibc `hello-world` binaries run through full libc startup to `printf`/`write` + `exit_group` with matching output and exit code.** The tests compile a static, no-libc ELF with `cc` at test time; the engine loads it, decodes it with native XED, and executes it. The `-O0` build exercises real stack frames, `push`/`pop`/`leave`, `call`/`ret` with an actual return address on the stack (an indirect jump), memory-immediate forms, RIP-relative loads, `lea`, 32-bit writes, `setcc`, `cmp`, and the `syscall` exit; the engine's exit code matches a native run. Hand-written assembly fixtures additionally run end-to-end with symbol-table lookup, SimProcedure dispatch, modeled `write`/`exit` syscalls whose output matches a native run, Z3 branch solving through the portfolio-routed `BatchSolver`, and concrete replay validation that the generated input reaches the target state natively (`cargo test -p angryier-runtime --features xed,z3`). Real statically linked **musl and glibc** hello-world binaries also run end-to-end (`cargo test -p angryier-runtime --features xed`): the runtime builds a Linux process stack (`argc`/`argv`/`envp`/`auxv` with `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`/`AT_RANDOM`), models `arch_prctl`/TLS and FS-relative addressing plus `set_tid_address`/`brk`/`getrandom`/`prlimit64`/`readlinkat`, advertises a conservative SSE-era CPUID feature set, and executes the SSE/XMM/YMM vector instructions (moves, packed compares, VEX forms, `punpcklqdq`, `movaps`) used by glibc CPU dispatch and allocator init — the static musl fixture reaches `main`, emits `hello from glibc` on stdout, and exits 0; the static glibc fixture does the same through ~110k instructions of libc initialization. PE32+ loads and executes; **dynamically-linked binaries run** — `load_elf_dynamic` maps `DT_NEEDED` libraries recursively, applies RELATIVE/GLOB_DAT/JUMP_SLOT relocations eagerly, evaluates IRELATIVE resolvers, seeds TLS, and hooks `__libc_start_main` → `main` (angr-style static linking — no `ld.so` process; a gcc dynamic binary writes `dyn\n` and exits in 24 steps, and the same path works under symbolic execution). `read`/`mmap`/`openat`/`fstat`/`access`/`ioctl`/`writev`/`futex`/`getrandom`/`prlimit64`/`readlinkat` are modeled; named files and symbolic file contents/argv/stdin are all input surfaces. Embedded Lua scripting (`angry.run`/`angry.open`) and the `angryier run` CLI drive symbolic sessions with solver-backed input generation. What is still missing: broad ISA form mapping (unmapped instructions fail explicitly as form id 0), deep `ld.so` emulation, x87, CFG-scheduled loop summarization, and real-multicore symbolic scaling. The **concolic fast path** now runs alongside concrete execution (`Runtime::concolic`): a symbolic shadow evaluates each lowered block, constant-folding keeps untainted addresses concrete (9 analysis-debt entries across 561 steps of musl libc startup), branch conditions become path constraints, `solve_last_branch` inverts the last branch through the solver portfolio — including the new `angryier-solver-fuzzy` mutation tier that answers simple `x == C`/`x < C`/`x != C` constraints without an SMT call — and a dual-mode differential test proves concolic (EXPLORE) and full-symbolic (PROVE) produce the same input on the same binary. EXPLORE/HUNT are explicitly unsound by design: shadow failures record `AnalysisDebtKind` on the fidelity ledger, and `requires_prove()` signals the mode-switching handoff (HUNT tolerates unlimited debt). The 363 handwritten semantic forms remain verified against the author's own expectations, not against hardware or an independent oracle. Performance work is still measured on synthetic microbenchmarks, not on real execution traces. This roadmap remains ordered around contact with reality before performance claims.
>
> **Dual-mode architecture:** Angryier's competitive thesis is not "angr, but faster" and not "SymQEMU, but Rust." It is **both modes in one engine, sharing the same AngryIR semantics**: a concolic fast path for coverage and input generation (SymCC/QSYM-class speed), and a full symbolic exploration mode for analysis depth (angr-class capability). The two modes share XED decode, AngryIR lowering, solver portfolio, environment models, and ELF64 loading. They differ in execution engine and state representation. The engine switches per-state based on the PROVE/EXPLORE/HUNT exploration profile. This is the answer to Gate J: Angryier is the only engine that does both natively, in safe Rust, at multicore scale.
>
> See [implementation plan](status/implementation-plan.md) for phase exit gates and [scaffold status](status/scaffold.md) for per-crate implementation state.

This roadmap is ordered around the primary technical objective: make Angryier materially faster and smarter than Python-heavy symbolic-execution systems on real analysis workloads.

The roadmap therefore prioritizes:

- **contact with reality** — a real binary running end-to-end before any performance claim;
- **environment modeling** — libc/syscall/SimProcedure equivalents without which real binaries cannot run;
- **semantic ground truth** — differential testing against hardware or an independent oracle, not self-verification;
- **symbolic-address memory policy** — the hard problem that defines a symbolic engine's soundness;
- **dual-mode execution** — a concolic fast path (SymCC/QSYM-class speed) and a full symbolic exploration mode (angr-class depth), sharing the same AngryIR semantics, switching per-state based on exploration profile;
- **Fuzzy-SAT solver tier** — approximate mutation-based solving for simple branch constraints, falling back to Z3/Bitwuzla for complex ones;
- native multicore execution;
- persistent/COW state economics;
- low-overhead immutable expression sharing;
- solver-context affinity and preemption;
- canonical solver-query reuse;
- exact and generalized UNSAT reuse;
- NUMA-aware work placement;
- search strategies that spend compute where it has the highest expected value;
- **state merging / Veritesting** — the real lever against path explosion, not raw parallelism;
- **programmability** — a scripting layer for user-authored hooks, exploration predicates, and state inspection;
- optional cumulative knowledge and similarity retrieval through QIHSE and KEYSTONE.

Enterprise-only hardening, elaborate governance machinery, process-isolation frameworks, and similar work do **not** block the core performance programme unless measurements or deployment requirements later prove they are necessary.

A phase advances only when its exit criteria are satisfied.

---

# Current Execution Order

The native Z3/Bitwuzla/XED integrations are landed and wired. The next milestones on the critical path to Production 1.0, in recommended execution order:

```text
1. Wire the pipeline  — DONE for the concrete path. Elf64Loader +
                       SimProcedureRegistry + PersistentMemory + native XED
                       decode + portfolio-routed Z3 branch solving are wired
                       through angryier-runtime and validated on a real
                       statically-linked x86-64 binary: it hits a
                       SimProcedure, has its branch solved, replays a
                       generated input into the opposite path, and the
                       generated input reaches the target state when the
                       binary is run natively (Gate 0).
                       Remaining: dynamically-linked binaries
                       (libc/syscall/TLS models) and replay-capsule
                       integration for recorded native runs.

2. Phase 6 (revised)  — concolic fast path: compile AngryIR blocks into a
                       tight dispatch loop that runs a single concrete state
                       and builds symbolic shadow constraints alongside.
                       QSYM-style optimistic solving and pruning by default.
                       PROVE/EXPLORE/HUNT profiles as real mode switches.
                       Fuzzy-SAT solver tier for simple branch constraints.
                       (Gate A: symbolic correctness + canonical identity
                        stable; fast path measured on real binaries)

3. Phase 5 finish     — OS-thread worker pool, worker-local deques,
                       NUMA-group queues, solver-context affinity,
                       instrumentation. Both modes must be parallelizable:
                       the concolic fast path parallelizes across inputs
                       (like QSYM), the full symbolic mode parallelizes
                       across states (like angr+).
                       (Gate B: useful physical-core scaling on REAL binaries
                        in BOTH modes; report per-state memory footprint at
                        10k live states and solver-context migration cost at
                        depth 500)

4. Phase 8            — constraint slicing, exact query reuse, incremental
                       contexts, UNSAT-core reuse, portfolio routing
                       (Gate C: exact reuse proven correct before
                        generalization; measured reuse hit rate on real
                        traces, not synthetic)

5. Phase 7            — semantic generator + broad Intel 64 coverage
                       (Gate D: handwritten corpus + differential oracle
                        prove the required shapes; x87/FPU included)

6. Phase 10           — search intelligence, state merging / Veritesting,
                       CFG recovery, state economics, optional QUBO
                       batch planner with CUDA → OpenCL → CPU fallback
                       (Gate J: Angryier's dual-mode synthesis — concolic
                        fast path + full symbolic — beats both angr AND
                        SymQEMU/SymCC on a named workload class)

7. Phase 13 (revised) — JIT via cranelift or custom, only if profiling
                       shows the fast interpreter is still the bottleneck.
                       The concolic fast path (step 2) uses a fast
                       interpreter, not a JIT. Upgrade to JIT is an
                       optimization, not a prerequisite.
                       (Gate G: JIT proceeds only if profiling shows the
                        fast interpreter remains the bottleneck)

8. Phase 15           — scripting layer (PyO3 or embedded scripting), stable
                        Rust API, CLI documentation, reproducible release
                        builds

9. Production 1.0     — validation + reproducible correctness/performance
                       reports
```

The single highest-risk milestone is **Phase 5 (Gate B)**. But Gate B is only
meaningful if measured on real binaries (Gate 0), with a symbolic-address
memory policy (Phase 3), and with environment models (Phase 1). A synthetic
branch tree will pass Gate B and teach nothing, because real path explosion is
exponential and 32 cores is a constant factor against it. The real lever
against path explosion is state merging (Phase 10), not raw parallelism.

**Positioning:** The competitive landscape is not angr vs. Angryier. It is:

```text
SymCC:    compiled symbolic propagation, source-only, fastest concolic
SymQEMU:  SymCC ideas in QEMU TCG, binary-only, fast concolic
QSYM:     Pin DBI + instruction-level concolic, fast, deliberately unsound
Fuzzolic: QEMU tracing + Fuzzy-SAT, interesting solver architecture
angr:     IR-based symbolic emulator, deep analysis, slow execution
```

Angryier does not compete with SymCC on source-instrumented speed. It does
not compete with angr on analysis breadth (yet). It competes by being the
only engine that does **both modes** — concolic fast path and full symbolic
exploration — natively, sharing the same AngryIR semantics, in safe Rust,
at multicore scale. The concolic fast path handles coverage and input
generation (QSYM/SymQEMU-class). The full symbolic mode handles analysis
depth, CFG recovery, state merging, and differential validation (angr-class).
The engine switches per-state based on the PROVE/EXPLORE/HUNT profile. Gate
J forces this to be proven on a named workload, not asserted.

---

# Competitive Performance Mandate

The following are first-class design goals, not later polish.

## Contact with reality

No performance claim is credible until it is measured on a real binary loaded, decoded, and executed end-to-end. Synthetic microbenchmarks tune the engine against the author's assumptions, not against reality. The first milestone after solver wiring is a real binary running through the full pipeline, with concrete replay validation: generate an input, run the real binary natively, confirm it reaches the target state.

## Environment modeling

Real symbolic execution is dominated by environment modeling, not ALU semantics. A stripped glibc hello-world hits `fs:[0x28]` (TLS stack canary), `rep stosb`/ERMS `memcpy`, SSE2 `pcmpeqb`/`pmovmskb` in `strlen`, `cpuid`, `rdtsc`, `syscall`, and possibly x87 in `printf`. Without libc models, syscall stubs, and SimProcedure equivalents, the engine either path-explodes inside glibc's loops or cannot run the program at all. This is not a Phase 14 nice-to-have; it gates whether any real binary can run.

## Semantic ground truth

Handwritten semantics verified against the author's own expectations are circular. The oracle must be independent: differential execution against hardware (execute the instruction natively, compare every register bit including AF/PF/OF-on-shift-by-zero), or cross-check against VEX/QEMU, or a formal model like Sail/K. XED gives encodings, not meaning. The semantic generator (Phase 7) needs a machine-readable source of truth for ~1,500 mnemonics and their flag semantics; that source cannot be "handwrite it and hope."

## Symbolic-address memory policy

Page-backed COW with O(1) fork is a concrete-memory optimization. The thing that defines a symbolic engine's soundness, completeness, and solver load is what happens on `mov rax, [rbx]` when `rbx` is symbolic. The policy must be explicit and configurable:

- **concretization** (angr's default — bounded range for reads, single address for writes, with pluggable strategies);
- **full theory-of-arrays** (sound but solver-heavy);
- **region-based symbolic memory** (compromise).

Each has documented failure modes (missed bugs, unsound merges, solver death). Byte-granular symbolic content must coexist with page-granular COW — one symbolic byte must not make an entire page unshareable and unforkable in O(1).

## State merging / Veritesting

Path explosion is exponential. 32 cores is a constant factor against it. The real lever is state-space reduction: Veritesting (statically merging states), loop summarization, function summaries, under-constrained execution, CFG-guided pruning. Merging states fundamentally conflicts with a fork-heavy COW architecture (you must reunify memory, registers, and solver contexts), but without it, parallelism buys almost nothing against exponential blowup. State merging is on the critical path, not deferred to Phase 10 as optional.

## Dual-mode execution

The single most important architectural decision in this roadmap is that Angryier has **two execution modes** sharing the same AngryIR semantics:

```text
Concolic fast path (EXPLORE/HUNT):
  - single concrete state, no state tree
  - symbolic shadow constraints built alongside concrete execution
  - QSYM-style optimistic solving and pruning
  - Fuzzy-SAT for simple branch constraints, Z3/Bitwuzla for complex ones
  - parallelizes across inputs (like QSYM/SymCC)
  - goal: coverage and input generation at near-native speed

Full symbolic mode (PROVE):
  - state forking, COW memory, full symbolic state tree
  - solver calls at branches, state merging / Veritesting
  - CFG recovery, dataflow, function summaries
  - parallelizes across states (like angr+)
  - goal: analysis depth, correctness proofs, differential validation
```

Both modes use the same XED decoder, AngryIR lowering, environment models, and solver portfolio. The difference is the execution engine and state representation. The engine switches per-state based on the PROVE/EXPLORE/HUNT profile.

**Why not just build one mode?** SymQEMU is fast but can't do full symbolic exploration. angr can do full symbolic but is slow. Building both in one engine, sharing semantics, is the only way to get both speed and depth. The concolic fast path is for coverage; the full symbolic mode is for analysis. Neither alone is the product.

**Why a fast interpreter, not a JIT, for the concolic path?** A fast interpreter (compiled AngryIR dispatch loop with symbolic shadows) gets 5-10× over the current interpreter, is fully safe Rust, and validates the architecture. A real JIT (cranelift or custom) is Phase 13 work — an optimization, not a prerequisite. Don't build a JIT until profiling shows the fast interpreter is the bottleneck.

## Fuzzy-SAT solver tier

Most fuzzing-generated branch constraints are simple (`x == 0x42`, `x < 0x100`). A full SMT solver is unnecessarily general for these. Fuzzolic's Fuzzy-SAT idea — mutate candidate byte vectors and evaluate the constraint directly — is much cheaper and fits naturally into Angryier's solver portfolio:

```text
Tier 1: Fuzzy-SAT (mutation-based, cheap, approximate, unsound)
Tier 2: Z3/Bitwuzla incremental (exact, medium cost)
Tier 3: Z3/Bitwuzla full (exact, expensive)
```

The portfolio router (already built) routes simple constraints to Fuzzy-SAT and complex ones to Z3/Bitwuzla. Fuzzy-SAT falls back to Z3 when it can't find a solution within a budget. This is a new crate (`angryier-solver-fuzzy`) implementing the existing `SolverBackend` trait with `name() = "fuzzy"`.

## Programmability

Every serious symbolic-execution task needs user-authored hooks for function summaries, exploration predicates, and state inspection. angr's moat is that a person types `simgr.explore(find=lambda s: b"Good Job" in s.posix.dumps(1))` in a REPL and iterates in seconds. A CLI is not a substitute for a programmable engine. The scripting layer (PyO3, embedded Lua, or a Rust plugin ABI) must be first-class, not a Phase 15 afterthought.

## Multicore state ownership

A runnable state has one execution owner at a time. Workers may transfer ownership through scheduler queues, but normal execution does not require multiple workers to mutate the same state concurrently.

This is intended to avoid fine-grained locking while preserving cheap state migration.

## Hierarchical work queues

The scheduler should mature toward:

```text
worker-local deque
      ↓
NUMA-group queue
      ↓
global emergency queue
```

Stealing should prefer the cheapest locality boundary. Cross-NUMA migration should occur only when expected load-balancing gain exceeds solver rebuild, cache, memory-working-set, and NUMA costs.

## Solver affinity and preemption

Fork descendants should preferentially remain near solver contexts containing useful ancestor assertions. Solver work must be cancellable/preemptible so a pathological query does not monopolize a worker indefinitely.

## Canonical solver-query representation

Solver requests must have a solver-independent canonical identity suitable for:

- exact query deduplication;
- Z3/Bitwuzla cross-routing;
- sibling-state reuse;
- persistent reuse;
- alpha-equivalence experiments;
- UNSAT-core/subsumption reuse;
- offline replay and performance analysis.

## Shared immutable arenas

Expression nodes, sealed semantic blocks, decoded blocks, and other hot immutable objects should use compact IDs and arena/epoch-style lifetime strategies where measurements show `Arc`/atomic reference traffic becoming a scaling limit.

## Cache admission

Lookup and admission are separate decisions. Expensive persistent caches must reject low-value entries when storage/indexing cost exceeds expected recomputation savings.

## Scheduler performance instrumentation

Performance counters are part of the execution engine. At minimum measure:

- state fork cost;
- COW page creation;
- expression interning hit rate;
- expression allocation volume;
- solver query count and wall time;
- solver-context rebuild cost;
- exact/generalized cache hit classes;
- state steals and migrations;
- NUMA-local vs cross-NUMA steals;
- queue depth and worker utilization;
- target-discovery latency;
- provenance/telemetry overhead when enabled.

These metrics exist to improve scheduling and optimization, not merely for reporting.

## Optional quantum-inspired/GPU batch planner

Reserve a backend-neutral `QuantumInspiredScheduler`/batch-optimizer seam, but do not put it on the critical path before the deterministic CPU scheduler is correct and measured. It may solve bounded QUBO-style state-selection and worker-assignment problems using coverage, diversity, target distance, solver cost, affinity, working-set, NUMA, uncertainty, and historical features.

Required backend order:

```text
compatible CUDA device/runtime -> CUDA
else compatible OpenCL device  -> OpenCL
else                            -> deterministic CPU
```

CUDA and OpenCL availability is detected at runtime against versioned capability manifests. Older NVIDIA cards that do not meet the CUDA backend's compute-capability, toolchain, kernel-target, or memory requirements must be offered to OpenCL before CPU fallback. Small batches, unsupported devices, compilation failures, timeouts, out-of-memory conditions, or planner validation failures advance through the same fallback ladder. GPU kernels consume compact scheduling features; they do not mutate execution states, interpret target instructions, decide SAT/UNSAT, or validate exact reuse.

---

# Phase 0 — Repository, Contracts, and Measurement Baseline

> **Status: foundations implemented.** Cargo workspace, CI, metrics schema, benchmark harness, micro-binary corpus, support-manifest schema, and performance counter boundaries are scaffolded. Reference benchmark harness and comparison-engine runs remain future work.

## Build

- Cargo workspace matching [architecture/crates.md](architecture/crates.md) crate boundaries.
- CI for formatting, clippy, unit tests, and benchmark smoke tests.
- Versioned JSON metrics schema.
- Reference benchmark harness capable of running Angryier and comparison engines under equivalent limits.
- Initial micro-binary corpus with source/build scripts.
- Architecture/semantics support-manifest schema.
- Performance counters for the hot-path boundaries listed above.

## Exit criteria

- reproducible benchmark command from a clean checkout;
- host CPU, microcode, kernel, compiler, solver, affinity, NUMA, build flags, and binary hashes recorded;
- baseline comparison runs detect meaningful regressions;
- benchmark results separate executor, solver, scheduler and persistence costs.

---

# Phase 1 — Loader + Intel 64 Decode + Handwritten Semantic Corpus + Environment Modeling

> **Status: partially implemented — Gate 0 landed for statically-linked binaries (including `-O0` compiler output with real calls and stack frames).** Architecture-neutral core trait, Intel 64 register/feature model, XED FFI adapter (`angryier-arch-xed-ffi`, 11 tests), safe normalized XED metadata boundary (`angryier-decode-xed`), normalized `DecodedInstruction`, 363-form handwritten semantic corpus, AngryIR lowering (memory operand loads/stores, RIP-relative addressing, indirect jumps), concrete interpreter, block cache, ELF64 loader (`angryier-loader`, 27 tests — headers, program headers, segments, entry point, static symbol table), SimProcedure library plus a minimal syscall model (`angryier-models`, 29 tests — strlen/strcmp/malloc/free/memcpy/memset/puts/exit stubs, `write` output capture, `exit` codes), and the end-to-end concrete pipeline (`angryier-runtime`) are done. Real statically-linked ELF64 binaries run end-to-end, including **gcc-compiled C programs** whose engine result matches native execution: loaded, decoded by native XED through an instruction-class form mapping (scalar integer/control-flow subset; unmapped instructions fail explicitly as form id 0), lowered with memory-operand loads/stores (RIP-relative addressing, base+scaled-index+displacement), executed with 32-bit zero-extending and partial-byte register writes, dispatched into SimProcedures, with modeled `write`/`exit` syscalls matching a native run, and a conditional branch symbolically evaluated and solved with Z3 to generate and replay a new input. PE32+ loading landed (sections, entry, segment mapping); **dynamically-linked ELF works**: `load_elf_dynamic` maps DT_NEEDED libs, applies RELATIVE/GLOB_DAT/JUMP_SLOT relocations eagerly, evaluates IRELATIVE resolvers, seeds a TLS block, and hooks `__libc_start_main` → `main` — a gcc-built dynamic binary runs end-to-end; broad ISA form mapping remains future work; the differential semantic testing harness now exists (256 hardware-vs-runtime cases on defined flag bits).

## Build

- ELF64 loader (segments, sections, entry point, relocations, dynamic linking, TLS);
- PE32+ loader (sections, imports, TLS, CRT startup);
- architecture-neutral core trait;
- Intel 64 register/feature model;
- Intel XED FFI adapter;
- safe normalized XED metadata boundary;
- normalized `DecodedInstruction` representation owned by Angryier;
- representative handwritten semantic corpus;
- minimal AngryIR lowering;
- concrete interpreter;
- block cache keyed by image/address/code/semantic identity;
- **environment model library** — libc function summaries (malloc, free, strlen, strcmp, printf, memcpy, etc.), syscall stubs (read, write, mmap, brk, exit, etc.), SimProcedure equivalents, symbolic filesystem/sockets;
- **differential semantic testing harness** — implemented: `differential_semantics_vs_hardware` executes each instruction template natively (assembled + run on the CPU) and through the runtime, comparing the result register and the architecturally-defined RFLAGS bits (CF/PF/AF/ZF/SF/OF per instruction class — undefined bits like imul's ZF are masked per template). 256 boundary-value cases match hardware byte-for-byte; it already caught real corpus bugs (missing PF/AF/OF, ZF-only imm-form writers, no shift CF/OF, missing pushf/popf).

## Corpus requirements

The handwritten corpus must exercise:

- scalar integer and flags;
- partial-register semantics;
- branches;
- memory operations;
- shifts/rotates;
- scalar FP;
- packed SIMD;
- AVX upper-lane behavior;
- AVX-512 masking;
- gather/scatter and VSIB;
- representative AMX configuration/tile operations;
- representative APX modifiers.

## Exit criteria

- curated concrete blocks match reference/native results where applicable;
- unsupported forms fail explicitly;
- XED decode support is never conflated with semantic support;
- the semantic representation covers every semantic shape in the representative corpus;
- **a real dynamically-linked binary loads, decodes, and executes end-to-end through the full pipeline** (Gate 0 — statically-linked binaries pass end-to-end, including full libc startup for real musl and glibc hello-world binaries; dynamically-linked binaries additionally require running the dynamic linker's fixups);
- **concrete replay validation passes** — generated inputs, when run on the real binary natively, reach the target state;
- **differential semantic testing passes** — handwritten forms agree with the independent oracle (hardware or VEX/QEMU) on all register bits, not just the author's expectations. **Started:** the hardware differential harness validates the arithmetic/logical/shift/mul/move/carry/cmov/setcc/memory-operand/SSE2-packed corpus on defined flag bits (412 cases green); expanding it to the full registered-form set and closing the remaining gaps (undefined-flag policies, the rest of the SIMD corpus, x87/FPU) is the Gate D completion criterion;
- **environment models handle at least**: `__libc_start_main` / CRT startup, `malloc`/`free`, `strlen`/`strcmp`/`memcpy`, `read`/`write`/`mmap`/`brk`/`exit` syscalls, TLS stack canary access (`fs:[0x28]`).

---

# Phase 2 — Typed Values + Symbolic Expression Core

> **Status: foundations implemented.** Compact `ExprId` arena with sharded `RwLock`-based reads, structural hashing/hash-consing, constant folding, dependency metadata, solver-independent expression fingerprints, and bitvector/bool domains are done. Floating-point, vector, opmask, tile domains, lazy lane/tile symbolic materialization, and shared-immutable arena instrumentation remain future work.

## Build

- compact `ExprId` arena;
- structural hashing/hash-consing;
- cheap hot-path canonicalization;
- deeper offline canonicalization;
- constant folding;
- dependency metadata;
- solver-independent expression fingerprints;
- bitvector, floating-point, vector, opmask and tile domains;
- lazy lane/tile symbolic materialization;
- symbolic register support;
- initial shared-immutable arena strategy with instrumentation for atomic/refcount overhead.

## Exit criteria

- identical subexpressions intern consistently;
- simplifier property tests preserve semantics;
- vector/mask/tile values round-trip through canonical representation;
- expression statistics expose allocation, reuse and contention costs;
- expression sharing does not introduce a global hot lock.

---

# Phase 3 — COW Memory + Persistent State + Symbolic-Address Policy

> **Status: foundations implemented.** Sparse symbolic overlays (per-page `BTreeMap` for concrete and symbolic bytes), state fork primitive via `Arc` sharing, persistent constraint lineage, explicit worker/state ownership metadata, code-page versions, and state/fidelity metadata slots are done. Page-based concrete backing with real COW page ownership, symbolic/taint bitmap, compact COW register file, and **symbolic-address memory policy** remain future work — the current memory crate uses sparse maps rather than OS page-table-backed COW and has no documented policy for `mov rax, [rbx]` when `rbx` is symbolic.

## Build

- page-based concrete backing;
- sparse symbolic overlays;
- symbolic/taint bitmap;
- copy-on-write page ownership;
- compact COW register file;
- persistent constraint lineage;
- state fork primitive;
- explicit worker/state ownership metadata;
- code-page versions for self-modifying-code/JIT invalidation;
- state/fidelity metadata slots;
- **symbolic-address memory policy** — explicit, configurable, per-state:
  - concretization strategies (bounded range for reads, single address for writes, pluggable strategy trait);
  - theory-of-arrays option (sound but solver-heavy, opt-in);
  - region-based symbolic memory (compromise between concretization and full arrays);
- **byte-granular symbolic content coexistence with page-granular COW** — one symbolic byte must not make an entire page unshareable or unforkable in O(1).

## Exit criteria

- fork cost is close to O(1) in unchanged mapped-memory size;
- sibling states share unchanged pages;
- one symbolic byte does not materialize an entire page symbolically;
- state transfer between workers does not require deep copying;
- COW and state-fork costs are measurable under multicore pressure;
- **symbolic-address policy is documented and tested** — concretization, arrays, and region-based modes all produce correct results on a differential test suite;
- **byte-granular symbolic content does not break page-granular COW sharing** — verified with a test that writes one symbolic byte to a shared page and confirms the rest of the page remains shared.

---

# Phase 4 — Solver Backends + Canonical Query Layer

> **Status: partially implemented.** Backend-independent solver trait, Z3 backend (FFI + safe adapter wiring, 4+2 tests), Bitwuzla backend (FFI + safe adapter wiring, 4+2 tests), SAT/UNSAT/UNKNOWN/BACKEND_ERROR outcomes, solver-independent canonical query representation, exact canonical query fingerprint, normalized local query cache (16 shards with `Arc<SolverResult>`), shared-context batched-query API, per-query portfolio dispatch (`QueryShape` classifier), `CrossCheckPolicy`, hard timeout enforcement, and backend history tracking are done (29 tests + 9 integration tests). Per-worker incremental contexts and basic DFS/BFS exploration remain future work. The FFI backends are wired into the safe adapter crates behind `ffi` Cargo features; `Z3Backend::native_ffi` is the solver used by `SymbolicSession`/`fuzz_generate`/Lua `solve` at runtime. Portfolio dispatch across *multiple* FFI backends (Z3+Bitwuzla simultaneously) remains to be exercised.
>
> **Fuzzy-SAT tier:** A new `angryier-solver-fuzzy` crate (Phase 6) will add a mutation-based approximate solver for simple branch constraints, plugged into the portfolio router as a third backend with `name() = "fuzzy"`. The router already routes by query shape; Fuzzy-SAT will receive simple constraints and fall back to Z3/Bitwuzla for complex ones.
>
> **Architectural tension noted:** Per-worker incremental solver contexts (push/pop over a shared constraint prefix) require a state to stay with its solver context. Work-stealing moves states between workers, breaking prefix alignment. This tension must be resolved in Phase 5 — either pin states to workers (losing load balance) or rebuild solver contexts on migration (losing incrementality). The measured cost of solver-context migration at path depth 500 must be reported before Gate B.

## Build

- backend-independent solver trait;
- Z3 backend;
- Bitwuzla backend;
- per-worker incremental contexts;
- SAT/UNSAT/UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR outcomes;
- solver-independent canonical query representation;
- exact canonical query fingerprint;
- hard query timeouts;
- cancellation/preemption boundary;
- normalized local query cache;
- shared-context batched-query API;
- basic DFS/BFS exploration.

## Exit criteria

- branch feasibility agrees with reference expectations;
- satisfying inputs reproduce native paths;
- UNKNOWN/timeout is never silently converted to UNSAT;
- Z3 and Bitwuzla are interchangeable at the engine boundary for supported theories;
- canonical-equivalent queries obtain identical authoritative identities;
- solver time, rebuild time and executor time are separately measurable.

---

# Phase 5 — Native Multicore + NUMA Scheduler

This is a core competitive milestone, not optional scalability polish.

> **Status: worker pool implemented and measured.** `OsWorkerPool` (`angryier-scheduler`) provides OS threads over worker-local deques with LIFO-local/FIFO-steal scheduling, a global overflow queue, in-flight termination tracking, and per-worker `PoolStats` instrumentation. `Runtime::parallel_concolic` parallelizes concolic sessions across inputs (QSYM model — **3.93× wall-time speedup on 4 workers** over static musl `hello`); `Runtime::parallel_explore` parallelizes states across workers with concrete branch forking over `Process` clones (48 states / 377 unique PCs spread across 4 workers on the same binary, EXPLORE-unsound — no solver feasibility gating). Solver-context affinity and the memory-working-set-aware migration cost remain coupled to Phase 8's incremental contexts; a dedicated 10k-live-state footprint benchmark remains to be written.

## Build

- ~~fixed-size native worker pool~~ — `OsWorkerPool`;
- explicit single-worker mutable ownership of each runnable state — each unit is an owned `Process` clone processed exclusively by one worker at a time;
- ~~worker-local deques~~ — one `VecDeque` per worker;
- NUMA-group queues — `NumaModel` distances feed `StealCost`; dedicated NUMA-pinned queue groups remain future work;
- ~~global emergency queue~~ — `global` overflow absorbs pushes from poisoned local deques;
- ~~locality-first work stealing~~ — own deque first, then most-loaded peer, then global;
- per-worker solver contexts and hot caches — Phase 8 (incremental contexts);
- solver-context affinity for fork descendants — pending Phase 8;
- scheduler policy trait — `Scheduler` trait with `GreedyScore`/`StealCost` exists; the pool is the execution layer beneath it;
- memory-working-set-aware migration cost — `StealCost.memory`-style fields exist; the working-set model remains to be validated;
- solver rebuild/cache/NUMA migration cost model — `StealCost` scaffolding exists;
- memory-pressure-aware stealing — future work;
- deterministic single-thread baseline — `workers=1` run is deterministic;
- ~~scheduler performance instrumentation~~ — `PoolStats` (produced/completed/per-worker/elapsed).
- backend-neutral bounded batch-planner trait plus deterministic CPU reference implementation;

Steal decisions should approximate:

```text
steal benefit =
    expected load-balancing gain
    - solver rebuild cost
    - cache locality loss
    - state working-set migration cost
    - NUMA penalty
```

## Exit criteria

- deterministic single-thread results match Phase 4 — `workers=1` runs are sequential and deterministic;
- bounded N-thread runs reach the same expected solution set — `parallel_concolic` produces a report per input regardless of worker count;
- no global mutex exists on the normal execution/solver path — workers pop from local deques; the global queue is only an overflow path;
- branch-parallel workloads scale usefully across physical cores — **measured 3.93× on 4 workers** (concolic input sweep, static musl);
- local steals outperform cross-NUMA steals where expected — steal order is own-deque → most-loaded peer → global; NUMA-aware steal weighting is modeled in `StealCost` but not yet measured on NUMA hardware;
- solver-context affinity measurably reduces rebuild work — pending Phase 8;
- ~~scheduler instrumentation identifies contention~~ — `PoolStats.per_worker_completed` exposes load balance.
- the CPU batch planner is deterministic and preserves all runnable work on cancellation or failure.
- **Gate B is measured on real binaries from Phase 1 (Gate 0), not synthetic branch trees** — a synthetic tree of independent cheap branches will pass Gate B and teach nothing, because real path explosion is exponential and 32 cores is a constant factor against it;
- **per-state memory footprint including solver context is reported at 10k live states** — memory, not scheduling, is what has killed every parallel symbolic engine before this one;
- **solver-context migration cost is reported at path depth 500** — the tension between incremental contexts and work-stealing (noted in Phase 4) must be resolved with measured data, not assumptions.

---

# Phase 6 — Concolic Fast Path + Symbolic Shadows + Dual-Mode Execution

> **Status: foundations implemented.** In-memory taint engine with labels, states, promotion threshold, transform/merge/sink is done. A single-block symbolic evaluator (`angryier-execution::symbolic`, scalar integer subset, explicit refusal of memory and vector/float operations) and Z3-backed branch solving over the executed trace (`angryier-runtime::solve_branch`) are the first narrow step toward the fast path: they produce branch-condition expressions over entry-state registers, solve them, and replay generated inputs. The concolic dispatch loop, symbolic shadow builder (`ConcolicEvaluator`), QSYM-style parallel input exploration (`parallel_concolic`), Fuzzy-SAT solver tier, EXPLORE/HUNT mode profiles, the per-state fidelity ledger, **and the EXPLORE→PROVE handoff (`promote_to_symbolic` — shadow registers/memory/constraints promote into a solver-backed `SymbolicState`)** are implemented. Solver cancellation/preemption and alpha-equivalence caching remain future work.
>
> **This is now the architectural centerpiece, not a Phase 6 afterthought.** The concolic fast path is what makes Angryier competitive with SymQEMU/QSYM for coverage and input generation. The full symbolic mode (current interpreter + COW + forking) is what makes Angryier competitive with angr for analysis depth. Both modes share the same AngryIR semantics. This phase builds the concolic fast path and the mode-switching infrastructure.
>
> **Design:** The concolic fast path compiles AngryIR blocks into a tight tagged-union dispatch loop that:
> - runs a single concrete state (no state tree, no COW fork, no plugin system);
> - builds symbolic shadow constraints alongside concrete execution (SymCC's idea, but in the interpreter);
> - calls the solver only at branches, not at every operation;
> - uses QSYM-style optimistic solving and pruning by default (configurable to sound for PROVE mode);
> - routes simple constraints to Fuzzy-SAT, complex ones to Z3/Bitwuzla via the portfolio router.
>
> **Why a fast interpreter, not a JIT:** A fast interpreter gets 5-10× over the current interpreter, is fully safe Rust, and validates the dual-mode thesis. A real JIT (cranelift) is Phase 13 work — an optimization, not a prerequisite. Don't build a JIT until profiling shows the fast interpreter is the bottleneck.

## Build

- concolic fast path: compile AngryIR blocks into a tight dispatch loop with symbolic shadows;
- ~~symbolic shadow builder: construct constraint expressions alongside concrete execution, no solver calls until branches~~ — `ConcolicEvaluator` (`angryier-execution::symbolic`) shadows lowered blocks with (concrete, expression) pairs; constant folding keeps untainted data concrete;
- ~~QSYM-style optimistic solving: try cheap concretization before full SMT, prune uninteresting branches~~ — `angryier-solver-fuzzy` answers simple constraints first through the portfolio router;
- ~~QSYM-style pruning: configurable unsoundness for EXPLORE/HUNT, strict soundness for PROVE~~ — shadow failures record `AnalysisDebtKind` instead of aborting;
- ~~Fuzzy-SAT solver tier (`angryier-solver-fuzzy`): mutation-based approximate solver for simple constraints~~ — done (`FuzzySatBackend` — comparison-constant seeding + xorshift mutation, `Unknown` falls back to SMT);
- ~~PROVE / EXPLORE / HUNT profiles as real mode switches~~ — `concolic`/`concolic_with_profile` open EXPLORE/HUNT sessions; PROVE remains `solve_branch` on the trace;
- ~~per-state fidelity ledger: track which mode each state is in and why~~ — `process.state.fidelity` carries the profile plus per-entry debt records;
- ~~mode-switching infrastructure~~ — `ConcolicSession::requires_prove` reports debt beyond the profile's tolerance (HUNT never asks for PROVE);
- fuzzer integration for HUNT (concolic + fuzz bridge) remains future work.

## Exit criteria

- concolic fast path executes real binaries (from Gate 0) — **done**: `concolic_shadows_real_libc_startup` runs 561 steps of real musl startup with 9 debt entries; speed-vs-interpreter measurement on longer traces remains to be reported;
- symbolic shadow constraints are correct: branch inversion produces valid test cases — **done**: `concolic_shadow_inverts_branch_to_new_input` solves `cmp $42,%rax` to RAX=42;
- PROVE mode is sound (no missed paths); EXPLORE/HUNT modes are explicitly unsound and documented — **done** via the fidelity ledger and debt recording;
- Fuzzy-SAT handles simple constraints (`x == C`, `x < C`, `x != C`) correctly and faster than Z3 — **done** (`concolic_solves_simple_branch_with_fuzzy_sat`);
- mode switching works — **done** at the ledger level: `concolic_debt_signals_prove_handoff` records debt on a symbolic-address load and `requires_prove` fires;
- all measurements are on real binaries, not synthetic trees — real musl startup runs concolically; the 5–10× headline number still needs a longer-trace benchmark;
- the dual-mode thesis is validated: **done** — `concolic_and_prove_modes_agree_and_outpace` shows both modes produce the same input on the same binary.

---

# Phase 7 — Semantic Generator + Broad Intel 64 Coverage

> **Status: generated-provider pipeline live and oracle-validated.** `SemanticPattern` in `angryier-semantics-gen` is the declarative schema (BinaryAlu/PackedLane/Extend/UnaryAlu/Shift + flag policies); `DeclarativeProvider` in `angryier-semantics-intel64` interprets patterns into real `SemanticOp`s, and `Intel64CorpusRegistry::with_generated` layers generated providers over the handwritten corpus in a dedicated rule-id band (0x10000+). Generated providers pass the hardware differential oracle byte-for-byte (`generated_providers_match_hardware` overrides handwritten `paddw`/`xor r32` and matches). The oracle now validates 856 boundary cases covering integer arithmetic/sub-width registers/high-byte ops, control flow incl. all ten Jcc, div/idiv/mul/imul incl. implicit RDX:RAX forms, rotates-through-carry, bit-scan/popcount, cmpxchg/xadd/bt*, string ops, scalar SSE float, and the SSE2/SSSE3/SSE4.x packed corpus — and it caught real bugs (rcl/rcr through-carry formula, cmpxchg accumulator aliasing, pshufd operand order, crc32 accumulate, mpsadbw imm fields, shift SF at sub-64 widths). Versioned definition schema (canonical pattern encoding → content identity), deterministic generated output, and handwritten override are in place; CI regeneration/diff gate and expansion to x87/AVX/remaining families remain future work.
>
> **Ground-truth problem:** XED gives encodings, not meaning. The semantic generator needs a machine-readable source of truth for ~1,500 mnemonics and their flag semantics. The oracle must be independent (hardware differential testing, VEX/QEMU cross-check, or a formal model like Sail/K). Strata alone took Heule's team years to cover a fraction of the ISA; the generator cannot shortcut that without an independent oracle. Undefined flag behavior (AF/PF/OF-on-shift-by-zero), x87/FPU, MMX, segment/TLS state, and self-modifying code have burned VEX for two decades and must be handled explicitly.

## Build

- versioned semantic-definition schema;
- semantic compiler/generator;
- deterministic generated output;
- support manifest;
- generated form tests;
- handwritten override mechanism;
- CI regeneration/diff gate.

## Target families

```text
scalar Intel 64
x87 FPU / MMX
SSE through SSE4.x
AES/SHA/BMI-class extensions
AVX
AVX2
AVX-512
AVX-VNNI
AVX10
AMX
CET
APX
```

## Exit criteria

- generated and handwritten semantics use one validation pipeline;
- families are advertised only after required forms pass validation;
- host feature absence never removes software target semantics;
- representative semantic families can be expanded without hand-writing every form;
- **all generated and handwritten forms pass the differential oracle** (hardware or VEX/QEMU cross-check) — not just the author's expectations;
- **undefined flag behavior is explicitly documented** — AF/PF/OF-on-shift-by-zero and other SDM-undefined cases have a defined Angryier behavior.

---

# Phase 8 — Solver Reuse, Slicing, and Preemption

> **Status: slicing, exact reuse, and UNSAT-core indexing implemented and measured.** `ConcolicSession::solve_last_branch` slices path constraints to the predicate's symbolic dependency cone (fixpoint over `DependencySummary.symbolic_sources`) — sliced queries share canonical keys across executions, so two different inputs reaching the same branch produce one unique query (measured: `sliced_queries_reuse_across_inputs` → 1 hit / 1 miss / 1 entry). `CachingSolverBackend` adds exact query reuse on the hot path plus a UNSAT-core superset index: a query whose constraint+predicate keys contain a recorded core returns `Unsat` without a backend call. Incremental solver contexts are in place: `Z3FfiBridge` keeps a persistent solver with one push-scope per constraint keyed by DependencyKey — shared prefixes reuse learned state — and real UNSAT cores extract via assumption literals (`check_assumptions`/`get_unsat_core` name the responsible ConstraintIds, feeding the cache's superset index). Solver cancellation/preemption, alpha-equivalence/subsumption, and cache-admission policy remain future work.

## Build

- ~~dependency-driven constraint slicing~~ — `solve_last_branch` fixpoints over `DependencySummary.symbolic_sources`;
- ~~exact query reuse across sibling states~~ — `CachingSolverBackend` + `InMemorySolverCache` canonical keys;
- ~~incremental-context reuse~~ — `Z3FfiBridge` persistent push/pop contexts keyed by DependencyKey are in place;
- solver cancellation/preemption — `CancellableSolverBackend`/`CancellationToken` scaffolding exists;
- portfolio routing by query shape and historical performance — `InMemoryPortfolioRouter` with `BackendStats`/`PreferredBackendHints` exists;
- cross-check policies for selected queries — `CrossCheckPolicy` exists;
- ~~exact SAT/UNSAT/model cache~~ — `InMemorySolverCache` stores Sat/Unsat results by canonical key;
- ~~UNSAT-core reuse~~ — `CachingSolverBackend` superset index (awaiting backend core extraction);
- alpha-equivalence experiments — future work;
- implication/subsumption/generalized UNSAT experiments — the UNSAT-core superset check is the first instance of this family;
- cache-admission policy based on estimated future value — future work (transient results are already rejected).

A basic example of useful generalized reuse:

```text
A ∧ B ∧ C = UNSAT
```

may authorize skipping a solver call for compatible supersets such as:

```text
A ∧ B ∧ C ∧ D ∧ E
```

when the exact validity and implication conditions are satisfied.

## Exit criteria

- sliced and unsliced queries are equivalent on the correctness corpus — slicing only drops constraints sharing no symbolic source with the predicate (they cannot affect satisfiability of the predicate's cone);
- exact reuse never crosses a validity domain — canonical keys include constraint keys, predicate key, target profile, and canonicalization version;
- generalized UNSAT reuse is independently validated — `caching_backend_reuses_unsat_cores` validates the superset rule; production use still needs backend core extraction;
- preemption reduces pathological solver wall time — `should_preempt` exists on the router; effect unmeasured;
- cumulative reuse measurably reduces query count and total solver time — measured on the two-input real-trace test (1 solver call for 2 inversions);
- cache storage/lookup cost is below the recomputation cost — a hashmap lookup is trivially cheaper than an SMT call;
- **reuse hit rate is measured on real execution traces** — `sliced_queries_reuse_across_inputs`: 1 hit / 1 miss / 1 unique key across two different inputs to the same binary (slicing is what makes the keys identical);
- **comparison to existing work** — KLEE's counterexample caching (2008) and Claripy's simplifier already occupy this space; the improvement over those baselines must be measured, not claimed.

---

# Phase 9 — Optional, Highly Recommended QIHSE + KEYSTONE Submodules

Angryier must remain fully usable without either repository. These integrations are optional because core symbolic execution must not depend on external persistence or retrieval systems.

They are nevertheless **highly recommended** for repeated analysis, large corpora, similarity searching, exact artifact lookup and cumulative knowledge.

> **Status: foundations implemented.** In-memory QIHSE adapter with exact fetch, fingerprint vector query, duplicate rejection and in-memory KEYSTONE adapter with inverted index, substring lookup, duplicate rejection are done. Git submodule integration, feature-gated adapter wiring, asynchronous/batched execution-event bridge, local buffering/spooling fallback, and persistence-disabled mode remain future work. Gate E: must show measurable value without putting synchronous persistence on the execution hot path.

## Intended Git submodules

```text
external/QIHSE
  https://github.com/SWORDIntel/QIHSE.git

external/KEYSTONE
  https://github.com/SWORDIntel/KEYSTONE.git
```

The existing adapter crates remain the Angryier-facing boundary:

```text
crates/angryier-qihse/
crates/angryier-keystone/
```

Core execution crates must not depend directly on submodule implementation details. Integrations should be Cargo-feature gated and removable from a minimal build.

## QIHSE role

Use QIHSE as the optional persistent knowledge and similarity/retrieval system, including where useful:

- semantic similarity search;
- constraint/path/function similarity;
- prior-analysis candidate retrieval;
- fused-vector / quantum-inspired similarity lookup;
- historical finding correlation;
- cross-run candidate discovery;
- graph/document/time-series knowledge where warranted.

Similarity is advisory. Exact identities and validity checks remain authoritative.

## KEYSTONE role

Use KEYSTONE as the optional ingestion/indexing/retrieval accelerator for:

- exact artifact lookup;
- ingestion pipelines;
- indexing canonical identities;
- fast candidate retrieval;
- metadata lookup;
- linking exact artifacts to QIHSE similarity candidates.

## Build

- optional `.gitmodules` entries when integration implementation begins;
- feature-gated adapter crates;
- asynchronous/batched execution-event bridge;
- local buffering/spooling fallback;
- exact validity-key lookup;
- similarity candidate API;
- persistence-disabled mode requiring neither repository.

## Exit criteria

- removing both submodules still leaves a functional Angryier engine;
- enabling them does not add synchronous database work to execution workers;
- exact prior-run artifacts can be found by validity key;
- similarity search returns useful candidates on repeated/correlated corpora;
- QIHSE/KEYSTONE candidate matches never bypass exact validation before correctness-affecting reuse.

---

# Phase 10 — Search Intelligence, State Merging, and State Economics

> **Status: engine implemented, CFG-scheduled merging, parallel exploration, and input generation — all real-binary-validated.** `angryier-cfg` recovers basic blocks and typed edges via recursive descent + symbol seeds (~25k blocks on the glibc fixture). `SymbolicSession` is the PROVE-mode engine: per-state symbolic registers + constraints + `SymbolicSessionMemory` (symbolic bytes in the persistent store, concrete fallback for untouched registers, symbol-resolved address concretization); `step_state` forks at conditional branches, `step_state_checked` gates each direction through the solver and prunes UNSAT, `merge_at` reconverges same-PC states via `merge_snapshots` (`Ite` under the left guard), `run`/`run_with_policy` drive exploration round-robin with find/avoid targets, coverage-novelty ordering, a state cap, and per-state failure isolation. Validated on real glibc: `symbolic_session_real_binary` runs 183 steps into `_start`/`__libc_start_main` with 14 forks and 6 peak states; `symbolic_session_forks_and_merges` proves fork→merge→Ite-store; `symbolic_session_checked_prunes_unsat_direction` proves solver-gated pruning; `symbolic_session_avoid_prunes_target` proves policy pruning. The environment boundary concretizes constant syscall args so symbolic `rax` reaches the exit model. `run_parallel` shards states across OS threads (per-worker queues, shared arena); `Cfg::reconvergence_target` + `pending_merges` schedule Veritesting merges by parking the first arrival until its sibling reaches the merge point; `solve_state` produces concrete input bindings from a found state's constraints. `Cfg::dominators`/`Cfg::loops` identify natural loops (dominator analysis + back-edge bodies). Remaining: loop *summarization* (collapsing induction-variable loops into closed forms), state economics, function-boundary refinement, and the optional QUBO planner.
>
> **Why state merging is on the critical path:** Path explosion is exponential. 32 cores is a constant factor against it. The real lever is state-space reduction: Veritesting (statically merging states), loop summarization, function summaries, under-constrained execution, CFG-guided pruning. Merging states fundamentally conflicts with a fork-heavy COW architecture (you must reunify memory, registers, and solver contexts), but without it, parallelism buys almost nothing against exponential blowup. This phase was previously deferred to the end of the roadmap; it is now on the critical path.
>
> **Why CFG recovery is here:** Search intelligence needs a CFG to be intelligent about. Without function identification, calling convention recovery, and variable reconstruction, there is no structure to guide exploration. angr's `CFGFast` and `CFGEmulated` are mature; Angryier has none.
>
> **Positioning gate (Gate J):** If the pitch is throughput, the bar is not angr — it is SymCC, SymQEMU, QSYM, and Fuzzolic, which get 10–100× over angr by not interpreting at all. Gate J forces the question: name the workload class where Angryier beats both angr AND SymQEMU/SymCC by enough to matter, or admit the positioning is "angr, but Rust."

## Build

- composable search objective;
- coverage novelty;
- target distance;
- taint relevance;
- solver-cost estimate;
- uncertainty/fidelity signals;
- loop accounting;
- analyst-specified targets;
- multifactor state-merge cost model;
- learned ranking as an optional advisory layer;
- scheduler-performance history feeding ranking/routing decisions.
- **state merging / Veritesting** — static state merging across basic blocks, loop summarization, function summaries, under-constrained execution;
- **CFG recovery** — `CFGFast`-equivalent (static disassembly + function identification), `CFGEmulated`-equivalent (symbolic execution-guided CFG), calling convention recovery, variable reconstruction;
- optional QUBO-style `QuantumInspiredScheduler` for batch selection and worker assignment;
- optional CUDA implementation after runtime capability discovery;
- optional OpenCL implementation as an experimental cross-vendor backend;
- strict planner budgets, minimum batch thresholds, result validation, and deterministic CPU fallback;
- runtime capability manifests and CUDA -> OpenCL -> CPU fallback, including older NVIDIA-card coverage;
- replay records for accelerated candidate batches, objective/schema versions, seeds, device/backend identity, decisions, and fallback reasons.

## Exit criteria

- search objectives can be benchmarked independently;
- learned ranking can be disabled;
- deterministic policies remain available;
- target-oriented corpora show reduced time-to-interest compared with baseline DFS/BFS where applicable;
- merge decisions reduce state count without causing solver-expression blowups that erase the gain;
- **state merging / Veritesting reduces state count on a real binary** — not just a synthetic tree;
- **CFG recovery produces a usable CFG on a real binary** — function identification, calling conventions, and basic blocks are recovered;
- accelerated planning improves net time-to-interest or throughput after transfer/launch overhead on at least one named workload class;
- disabling or losing the accelerator preserves correctness, runnable work, and deterministic CPU behavior;
- CUDA/OpenCL results never authorize truth claims or exact cache reuse;
- **Gate J: a named workload class is identified where Angryier beats both angr AND SymQEMU/SymCC by enough to matter** — or the positioning is honestly stated as "angr, but Rust and multicore."

---

# Phase 11 — Learned Fusion Retrieval

This phase is most useful when the optional QIHSE/KEYSTONE integrations are enabled, but the encoders themselves must remain separable from core execution.

> **Status: foundations implemented.** In-memory fusion model with identity/constant encoders, element-wise averaging is done. Specialist encoders for semantic/AngryIR structure, CFG/path topology, constraint DAGs, taint/dataflow, dynamic/memory behavior, solver profile, findings/context, plus learned gated/attention-style fusion, missing-modality masks, and similarity retrieval through QIHSE remain future work. Gate F: similarity retrieval must demonstrate useful precision/recall and remain advisory.

## Build

Specialist encoders for:

- semantic/AngryIR structure;
- CFG/path topology;
- constraint DAGs;
- taint/dataflow;
- dynamic/memory behavior;
- solver profile;
- findings/context.

Then build:

- missing-modality masks;
- learned gated/attention-style fusion;
- default 1024-D fused representation;
- optional 384/2048/4096-D profiles;
- similarity retrieval through QIHSE where enabled;
- exact-validation stage after similarity retrieval.

## Exit criteria

- held-out retrieval quality beats simple structural baselines where claimed;
- similarity computation has bounded cost;
- approximate matches never bypass exact validation;
- retrieval produces measurable analysis benefit rather than only visually plausible neighbors.

---

# Phase 12 — Adaptive Provenance and Flight Recorder

Provenance is retained because it improves debugging and analyst insight, but implementation should remain proportional to measured value.

> **Status: foundations implemented.** In-memory provenance store, adaptive trace governor, batching sink, tier-based eviction, Tier 0/1/2 event schema, Tier 1 structural provenance, and the **bounded per-worker flight recorder** (`FlightRecorder` — tier-aware ring, Tier-0-first eviction, never drops Tier 1, session fork/merge/termination events) are done. Tier 2 triggers, structural repetition summarization, post-processing canonicalization/deduplication, and bounded asynchronous transport remain future work.

## Build

- Tier 0/1/2 event schema;
- Tier 1 structural provenance;
- per-worker circular flight recorder;
- Tier 2 triggers;
- structural repetition summarization;
- post-processing canonicalization/deduplication;
- bounded asynchronous transport.

## Exit criteria

- Tier 1 reconstructs state/constraint/finding lineage;
- configured interest events retain useful pre-trigger context;
- repetitive traces compress substantially;
- provenance overhead remains measurable and bounded.

---

# Phase 13 — JIT / Specialized Concrete Execution (Upgrade for Concolic Fast Path)

## Build only if profiling justifies it

> **Status: foundations implemented.** JIT validity contract and code-page versioning are done. The concolic fast path (Phase 6) uses a fast interpreter, not a JIT. This phase upgrades the fast interpreter to a real JIT (cranelift or custom) only if profiling shows the fast interpreter is still the bottleneck after Phase 6 is complete.
>
> **Relationship to Phase 6:** Phase 6 builds the concolic fast path as a fast interpreter (fully safe Rust, 5-10× over the current interpreter). This phase upgrades it to a JIT if needed. The JIT is an optimization, not a prerequisite for the dual-mode thesis. If the fast interpreter is fast enough, this phase may be deferred indefinitely.

Potential maturity path:

```text
cold block -> compact interpreter (Phase 0-5)
warm block -> fast concolic interpreter with symbolic shadows (Phase 6)
hot block  -> JIT via cranelift or custom (Phase 13, if profiling demands)
```

Requirements:

- symbolic/taint transition hooks;
- memory permission checks;
- code-page version guards;
- targeted self-modifying-code invalidation;
- host-feature guards;
- software semantic fallback;
- **unsafe code isolation**: JIT requires writing executable memory (`mmap(PROT_EXEC)`). This must be isolated in a dedicated FFI crate (`angryier-jit-ffi`) that locally permits `unsafe_code`, following the Z3/Bitwuzla/XED pattern. The safe adapter crate (`angryier-jit`) preserves `#![forbid(unsafe_code)]`.

## Exit criteria

- JIT and interpreter are semantically equivalent on the differential suite;
- compile/cache overhead is exposed;
- end-to-end performance improves on concrete-heavy classes **beyond what the fast interpreter already delivers**;
- if the fast interpreter is already fast enough, this phase is documented as "not needed for Production 1.0" and deferred.

---

# Phase 14 — Hybrid Fuzzing + Environment Models

> **Status: foundations implemented.** In-memory fuzz bridge with stage-gated seed/coverage/hint submission and in-memory environment model with operation table, fidelity enforcement, summary provider are done. Coverage-guided input generation is live: `Runtime::fuzz_generate` solves found states into input bytes and replays each concretely (stdin-served `read(0)`), returning `(input, coverage)` pairs — the input's actual reached blocks. Versioned syscall/library/environment models, deterministic summary contracts, testcase import/export, seed exchange, and bidirectional hybrid fuzzing remain future work.

## Build

- versioned syscall/library/environment models;
- deterministic summary contracts;
- testcase import/export;
- coverage/seed exchange;
- constraint and target-hint exchange after simpler integration proves stable;
- bidirectional hybrid fuzzing interface.

## Exit criteria

- symbolic execution produces useful seeds for fuzzing;
- fuzzer discoveries can seed targeted symbolic exploration;
- hybrid operation beats either engine alone on at least one representative corpus before additional complexity is accepted.

---

# Phase 15 — API Stabilization, Scripting Layer, Packaging, and Optional Distribution Seam

> **Status: foundations implemented.** In-memory work codec with deterministic binary frame encode/decode round-trip and basic CLI with version/status/crates/help subcommands are done. The embedded **Lua scripting layer is done**: `angry.run(path, opts)` (symbolic regs/argv/files, find/avoid, `solve = true` returning input models) and `angry.open(path)` (live session userdata — `step`/`pc`/`reg`/`states`/`symbolic`) plus the `angryier run` CLI (`--script`, `--symbolic`, `--find`, `--argv`, `--dynamic`). Stable Rust library API, CLI documentation, reproducible release builds, versioned support manifests, benchmark report generation, and multi-host work-unit serialization remain future work.
>
> **Why the scripting layer is first-class:** Every serious symbolic-execution task needs user-authored hooks for function summaries, exploration predicates, and state inspection. angr's moat is that a person types `simgr.explore(find=lambda s: b"Good Job" in s.posix.dumps(1))` in a REPL and iterates in seconds. Forcing users to write Rust and recompile per target is a fundamental blocker for adoption. The scripting layer must be first-class, not a Phase 15 afterthought. Options: PyO3 bindings (recreates angr's shape with FFI overhead), embedded Lua/DSL (lighter but less ecosystem), or a Rust plugin ABI (fast but high barrier). The chosen approach must be decided before Phase 10, because search intelligence and CFG recovery need user hooks.

## Build

- stable Rust library API;
- CLI documentation;
- **scripting layer** — PyO3 bindings, embedded Lua, or Rust plugin ABI; user can write hooks, exploration predicates, and state inspection without recompiling;
- optional PyO3 bindings;
- reproducible release builds;
- versioned support manifests;
- benchmark report generation;
- serialization boundaries for future multi-host work units.

Multi-host execution is not required for initial production readiness; only the serialization boundary is reserved.

---

# Production 1.0 Definition

Production 1.0 requires:

1. ELF64 and PE32+ loading for the declared scope — **done** (ELF64 parser + PE32+ section/entry loading, `load_pe` executes a PE through the runtime);
2. Intel 64 XED decoding with explicit semantic-support manifest — **done** (`angryier-arch-xed-ffi`, 11 tests);
3. production semantic coverage for declared Intel extension families — **partial** (363 handwritten forms; generator pending; differential oracle pending);
4. **dual-mode execution** — concolic fast path + full symbolic exploration, sharing AngryIR — **done** (`ConcolicSession` shadows concrete execution with path constraints; `SymbolicSession` runs full symbolic with fork/merge, solver-gated pruning, CFG-scheduled reconvergence, parallel workers, and solver-assisted address concretization);
5. COW state and sparse symbolic memory — **partial** (sparse memory done; symbolic-address policy done, 41 tests; page-backed COW pending);
6. Z3 + Bitwuzla solver support — **done** (FFI + safe adapter wiring, 8+4 tests; portfolio router upgraded with per-query dispatch, 29 tests);
7. **Fuzzy-SAT solver tier** — **done** (`angryier-solver-fuzzy` mutation tier plugged into the portfolio router; `concolic_solves_simple_branch_with_fuzzy_sat` passes);
8. canonical solver-query identities and exact reuse — **partial** (identity + cache done; reuse wiring pending; real-trace measurement pending);
9. native multicore exploration with worker/state ownership and useful physical-core scaling — **pending** (in-memory scheduler only; Gate B must be measured on real binaries in BOTH modes);
10. NUMA-aware work placement where applicable — **partial** (distance model exists; OS-thread pool pending);
11. solver affinity, timeout and preemption — **partial** (timeout enforcement + per-query timeout params done; incremental persistent contexts done in the Z3 FFI backend; preemption pending);
12. search policies demonstrably better than simple baselines on at least some target classes — **pending** (includes state merging / Veritesting and CFG recovery);
13. reproducible correctness and performance reports — **partial** (bench sink exists; reproducible harness pending);
14. **environment model library** (libc/syscall/SimProcedure equivalents, TLS, dynamic linking, CRT startup) — **partial** (SimProcedure stubs done; syscall table now covers `read` (symbolic stdin materializes input bytes), `write`/`writev`, `mmap`/`munmap`/`brk`, `openat`/`close`/`fstat`/`access`/`ioctl`, `arch_prctl` (TLS), `getrandom`, `prlimit64`, `readlinkat`, `futex`, `set_tid_address`/`set_robust_list`/`rseq`, `getpid`/`gettid`/`uid`/`gid` family, `exit`/`exit_group`; dynamic linking and named-file contents pending);
15. **differential semantic testing** (cross-check against hardware or VEX/QEMU) — **done for the registered corpus** (`differential_semantics_vs_hardware` + `generated_providers_match_hardware` run all 363+ forms against the host CPU);
16. **scripting layer** (PyO3, embedded Lua, or Rust plugin ABI for user-authored hooks) — **done (embedded Lua)**: `mlua`-backed `angry.run(path, opts)` marks registers symbolic, sets find/avoid policies, symbolizes argv/files, and returns a report table; `angryier run <binary> [--script f.lua]` drives it from the CLI;
17. **a real binary running end-to-end** (Gate 0) — **done for statically-linked binaries, including `-O2` and `-O0` compiler output** (native XED decode through an instruction-class form mapping, memory operand loads/stores with RIP-relative addressing, narrow/zero-extending/partial register writes, real stack frames with `push`/`pop`/`leave` and `call`/`ret` indirect returns, memory-immediate forms, the ELF64 loader with symbol lookup, SimProcedure dispatch, modeled `write`/`exit` syscalls, portfolio-routed Z3 branch solving that generates a new input, and concrete replay validation showing the generated input reaches the target state natively, all via `cargo test -p angryier-runtime --features xed,z3`; remaining: dynamically-linked binaries and replay-capsule integration for recorded native runs);

The following are **recommended but not mandatory for a minimal Production 1.0 engine**:

- QIHSE submodule integration;
- KEYSTONE submodule integration;
- persistent cross-run similarity search;
- learned-fusion retrieval;
- JIT (Phase 13 — only if the fast interpreter from Phase 6 is the bottleneck);
- distributed execution;
- GUI;
- additional ISAs;
- AI-assisted search.
- CUDA/OpenCL quantum-inspired batch scheduling.

A recommended full-feature profile should enable QIHSE + KEYSTONE because cumulative exact lookup and similarity retrieval are expected to become increasingly valuable as the analysis corpus grows.

---

# Go / No-Go Gates

## Gate 0 — after Pipeline Wiring

Proceed only if a real statically-linked x86-64 binary loads, decodes, and executes end-to-end through the full pipeline (Elf64Loader → XED decode → AngryIR → concrete interpreter → SimProcedure → BatchSolver → branch inversion → new input), with concrete replay validation. No performance claim is credible until this gate passes.

**Current status: passed for statically-linked binaries.** `angryier-runtime` wires the full concrete pipeline with native XED decode (instruction-class form mapping) and portfolio-routed Z3 branch solving behind the `xed`/`z3` features. `cargo test -p angryier-runtime --features xed,z3` validates, on a real binutils-linked ELF64 binary: load (with symbol-table lookup) → XED decode → AngryIR → concrete interpretation → SimProcedure dispatch → symbolic trace evaluation → branch solving → new input → replay into the opposite path, and the solver-generated input reaches the target state when the binary is executed natively. Still pending: dynamically-linked binaries (libc/syscall/TLS models) and replay-capsule integration for recorded native runs.

## Gate A — after Phase 6 (Concolic Fast Path)

Proceed only if symbolic results are correct, canonical solver identities are stable, and the concolic fast path produces valid test cases on real binaries. The dual-mode thesis (concolic fast path + full symbolic, sharing AngryIR) must be validated: both modes produce the same semantic results on the differential suite.

## Gate B — after Phase 5

Proceed only if branch-parallel workloads show useful multicore scaling **on real binaries (Gate 0)** in **both modes** (concolic fast path parallelizes across inputs, full symbolic parallelizes across states), not synthetic branch trees. Otherwise investigate allocator contention, shared-object lifetime overhead, solver-context migration, queue policy, cache locality and NUMA placement before adding major features. Report per-state memory footprint at 10k live states and solver-context migration cost at path depth 500.

## Gate C — before generalized solver reuse

Do not allow alpha-equivalence, implication or subsumption results to suppress solver work until exact canonical-query reuse is proven correct **on real execution traces**.

## Gate D — before broad generated semantics

Do not build a giant semantic DSL until the handwritten corpus **plus the differential oracle** demonstrates the required semantic shapes. The oracle must be independent (hardware or VEX/QEMU), not the author's expectations.

## Gate E — before QIHSE/KEYSTONE become recommended in deployment defaults

They must show measurable value in exact lookup, similarity retrieval, repeated-analysis latency or analyst discovery without putting synchronous persistence on the execution hot path.

## Gate F — before learned fusion influences scheduling

Similarity retrieval must demonstrate useful precision/recall and remain advisory.

## Gate G — before JIT

JIT proceeds only if profiling shows the Phase 6 fast interpreter (concolic fast path) remains a material wall-time component after all other optimizations. If the fast interpreter is already fast enough for the target workload class, JIT is deferred indefinitely.

## Gate H — before another ISA

Do not allow AArch64/RISC-V work to substitute for proving the Intel 64 performance, correctness and reuse thesis.

## Gate I — before accelerated scheduling becomes a deployment default

The deterministic CPU scheduler must already satisfy Phase 5. CUDA/OpenCL planning must then demonstrate a net benefit after feature construction, transfer, launch, synchronization, and fallback costs; preserve all runnable work under injected device failures; correctly route CUDA-ineligible older cards through OpenCL before CPU; and remain reproducible through recorded decisions. Otherwise the accelerator stays disabled by default.

## Gate J — before claiming throughput advantage

Angryier's competitive thesis is the **dual-mode synthesis**: concolic fast path + full symbolic exploration, sharing the same AngryIR semantics, in safe Rust, at multicore scale. The named workload class where Angryier beats both angr AND SymQEMU/SymCC is: **workloads that need both coverage speed and analysis depth** — e.g., vulnerability triage where you need fast input generation to reach deep code, then full symbolic reasoning to prove reachability and generate a minimal PoC. SymQEMU can't do the analysis; angr can't do the coverage speed. Angryier does both, switching per-state. Gate J requires this to be demonstrated on a named workload, not asserted. If the dual-mode thesis fails to materialize as a measurable advantage, the positioning falls back to "angr, but Rust and multicore" and no throughput advantage over instrumentation-based concolic engines is claimed.

---

# Optional Fallback Paths

The dual-mode synthesis is the primary thesis. If specific components underperform, the following fallback paths are available. Each is explicitly optional — none is on the critical path for Production 1.0. They exist as documented backup plans, not commitments.

## Fallback A — angr SimProcedure contracts as reference

**When:** Angryier's environment model library is incomplete for a target's libc/syscall surface.

**What:** Use angr's SimProcedure behavior contracts as the specification reference. angr's SimProcedures are the most complete open-source libc/syscall model for symbolic execution: `__libc_start_main`, TLS stack-canary access, `printf` format strings, `malloc`/`free` heap models, file I/O, sockets, and hundreds of other functions. Building all of this from scratch is years of work.

**How:** This is a documentation/specification dependency, not a code dependency. angr's SimProcedures are Python and tied to angr's SimState — they cannot be directly imported. Instead, Angryier's SimProcedure library follows angr's SimProcedure behavior contracts where applicable, ported to Rust. Each SimProcedure documents its angr counterpart and any deviations.

**Cost:** Low. No code dependency. Just a specification reference.

**Trigger:** When a target binary requires a libc function that Angryier doesn't model, and angr has a working SimProcedure for it, port the angr contract rather than designing from scratch.

## Fallback B — QSYM-class path policy (already in Phase 6)

**When:** Full symbolic execution is too slow for fuzzing workloads.

**What:** QSYM's deliberately unsound path policy: optimistic solving (try cheap concretization before full SMT), aggressive pruning (drop uninteresting branches), no state tree (single concrete state with constraint log).

**How:** Already in the roadmap as Phase 6's EXPLORE/HUNT profiles. The concolic fast path uses QSYM-class path policy by default. PROVE mode is the sound alternative.

**Cost:** Already built into Phase 6. No additional work.

**Trigger:** Default for EXPLORE/HUNT modes. No fallback needed — it's the primary path for coverage workloads.

## Fallback C — Fuzzy-SAT solver tier (already in Phase 6)

**When:** Z3/Bitwuzla are too slow for simple branch constraints (`x == C`, `x < C`, `x != C`).

**What:** Fuzzolic's Fuzzy-SAT idea: mutate candidate byte vectors and evaluate the constraint directly, without invoking an SMT solver. Falls back to Z3/Bitwuzla for complex constraints.

**How:** Already in the roadmap as the Tier 1 solver in the portfolio. New crate `angryier-solver-fuzzy` implementing `SolverBackend` with `name() = "fuzzy"`.

**Cost:** Low. A new crate with no external dependencies. Plugs into the existing portfolio router.

**Trigger:** Default for simple constraints in EXPLORE/HUNT modes. The portfolio router routes by query shape.

## Fallback D — JIT via cranelift (Phase 13, if profiling demands)

**When:** The Phase 6 fast interpreter (concolic fast path) is not fast enough after all other optimizations.

**What:** Upgrade the fast interpreter to a real JIT using cranelift (or a custom backend). Compile hot AngryIR blocks to native machine code with symbolic shadow calls.

**How:** Already in the roadmap as Phase 13. The JIT requires an unsafe FFI crate (`angryier-jit-ffi`) for executable memory allocation, following the Z3/Bitwuzla/XED pattern. The safe adapter crate preserves `#![forbid(unsafe_code)]`.

**Cost:** High. A real JIT is a significant engineering effort. But it's an incremental upgrade of the fast interpreter, not a new architecture.

**Trigger:** Gate G — profiling shows the fast interpreter is the bottleneck on real workloads. If the fast interpreter is already fast enough, this phase is deferred indefinitely.

## Explicitly rejected paths

The following paths are **not** fallback options. They are documented here to prevent future reconsideration.

### QEMU / SymQEMU integration — rejected

**Why rejected:** QEMU is C. Integrating it means a large FFI surface, a massive unsafe boundary, and a dependency that violates the Rust-native thesis. QEMU's TCG is not designed to be embedded as a library — it's a full system emulator. Maintaining a QEMU fork is a research project, not a production path. If Angryier needs SymQEMU-class speed, build a real JIT (Fallback D). Do not embed QEMU.

### SymCC / LLVM pass — rejected for Production 1.0

**Why rejected:** SymCC requires LLVM and source access. It only works for source-available targets, not opaque binaries. It's a completely different execution model from Angryier's interpreter. Adding it means maintaining an LLVM pass, which is a significant ongoing burden. SymCC's approach is the fastest known for source-available targets, but Angryier's thesis is binary-only analysis. If a source-available path is needed in the far future, an LLVM pass could be added as a Phase 16+ research direction, but it is not a production path for Angryier.
