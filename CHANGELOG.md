# Changelog

All notable changes to Angryier are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **Exact dynamic branch replay:** alternate-branch validation now binds to a three-part identity: static branch PC, recorded 1-based dynamic occurrence, and deterministic entry-to-branch trace fingerprint. Loops cannot falsely validate an earlier visit, and divergent paths reaching the same numbered visit return `path-context-mismatch`. Truncated trace provenance returns `ambiguous-branch-visit` instead of guessing.
- **Symbolic-address solver integrity:** address-concretization queries now fail closed on missing path or bounds dependency metadata instead of silently weakening the query.
- **Strict-Clippy test cleanup:** register-seed and speculative decode-pipeline tests use fallible helpers/results rather than denied unwrap/expect patterns.
- **Fail-closed symbolic constraint handling:** feasibility queries, opposite-edge branch solving, and concrete-model extraction no longer silently omit path constraints whose dependency summaries are unavailable. Such queries now report an explicit indexed error rather than yielding potentially unsound SAT results.
- **Branch candidate ranking safety:** named candidate fields replace the positional seven-element history tuple, preventing distance/priority fields from being accidentally interchanged.

### Added

- **Operator-grade symbolic diagnostics:** generated CLI runs now report state economics, trace frontier, timeout/failure context, concretization pressure, semantic/memory/vector fidelity debt, and evidence-driven follow-up ideas.
- **Primary-limiter analysis:** Angryier classifies the dominant observed constraint on a run (timeout, state pruning, model/semantic failure, unsupported semantics, under-constrained memory/address handling, vector debt, step budget, absent symbolic influence, or unresolved target reachability).
- **Path-relevant symbolic frontier:** `angry.run` now exposes a diagnostic `frontier` state with current symbolic registers and the symbolic leaf IDs that actually occur in retained path constraints. Register-backed dependencies are mapped back to register name/width/expression, allowing the CLI to distinguish predicate-driving inputs from merely-symbolic inputs.
- **Region-fork fidelity reporting:** result tables now expose region-fork child counts and the exact guessed address-world sites used to continue unresolved pointer paths.
- **Concrete alternate-branch replay:** SAT register-only branch models can now be restarted from a clean entry/environment snapshot and concretely checked against the recorded alternate successor. Replay mismatches downgrade steering confidence; stateful or non-register models fail closed instead of being partially replayed.
- **Bounded multi-branch steering:** symbolic states retain up to 64 branch decisions (cleared on merges); one shared CFG recovery ranks older alternate edges toward `find` targets, and at most one extra solver query/replay is spent on the highest-value older mutation point.
- **Early CLI compile gate:** CI compiles the run-capable CLI before the repository-wide rustfmt gate so functional regressions remain visible even while historical formatting debt exists elsewhere in the workspace.
- **Alternate-branch inversion:** symbolic states record their latest exact branch predicate, successors, chosen edge, and pre-branch constraint prefix. Post-run analysis can solve the opposite edge without asserting the already-chosen branch or later divergent constraints.
- **CFG-guided target direction:** bounded static CFG recovery compares each branch successor's edge distance to configured find targets. Solver feasibility and structural target preference are reported separately and combined only for evidence-backed next-run guidance.
- **Concrete replay seeds:** `angryier run --reg REG=VALUE` seeds full-width GPR values, including exact `u64` kernel pointers; alternate-branch register models now emit canonical `value_hex` values and replay-ready seed flags.
- **First-class search controls:** the CLI now exposes `--avoid`, `--states`, `--timeout`, `--branch-timeout-ms`, `--solve`, `--fork`, and `--dfs` instead of requiring a custom Lua driver for common exploration policy changes.
- **Branch-analysis regression gates:** CI runs alternate-edge prefix solving, CFG target-distance, and branch-analysis regressions before the historical repository-wide format gate.

### Fixed

- **Found-state solving contract:** `solve = true` now exclusively controls post-run found-state model extraction; the Z3 backend may still feasibility-gate symbolic branches when model extraction is disabled.
- **Merged-state branch provenance:** state merges now invalidate stored branch-prefix metadata instead of reusing an index from pre-merge constraint vectors, preventing potentially unsound alternate-edge queries.

## [1.0.0] — 2026-10-01

### Production 1.0 Release

Angryier is a native, parallel symbolic/concolic binary-analysis platform in safe Rust (`#![forbid(unsafe_code)]` in all core crates). It unifies a concolic fast path for high-speed coverage exploration with full symbolic execution for deep program verification, sharing Intel XED decoding, AngryIR lowering, environment models, and multi-backend SMT solvers.

---

### Highlights

- **Dual-Mode Engine:** Shared AngryIR semantics bridging QSYM-class concolic speed (single-state concrete execution with symbolic shadow constraints) and angr-class symbolic exploration (state trees, path forking, merging/Veritesting, loop summaries).
- **Extensive Intel 64 ISA Coverage:** 1,574 registered semantic providers, validated against a host hardware differential testing oracle across 856 integer/SSE + 462 x87 cases.
- **Enterprise Kernel & Userland Models:** Windows kernel DriverEntry/IRP models (ntoskrnl/HAL/NDIS), pool allocation tracking, PE dynamic linking and export parsing, plus Linux x86-64 syscall and SimProcedure suite.
- **Vulnerability Verdict Engine:** Dynamic detection of Double-Free (DF), Use-After-Free (UAF), and pool corruption with zero false positives across real Windows kernel drivers and synthetic test suites.
- **First-Class Lua 5.4 Scripting Subsystem:** High-performance automation layer with binary packing/unpacking, disassembly, fine-grained state manipulation, interactive stepping, hooks, breakpoints, and Z3 SMT constraint solving.
- **High-Performance SMT Stack:** Native Z3 and Bitwuzla FFI backends with iterative non-recursive translation (stack overflow proof at depth > 600), BLAKE3-accelerated Merkle dependency derivation with zero heap allocation, and mid-flight solver cancellation.
- **Multicore & NUMA Scaling:** Work-stealing scheduler with NUMA-aware worker groups, memory-pressure throttling via `/proc/meminfo`, and 3.93× scaling across 4 physical cores.

---

### Architecture

- **43-Crate Modular Workspace:** Layered architecture strictly dividing the Execution Plane, Truth Plane, and Knowledge Plane.
- **Safety Invariant:** `#![forbid(unsafe_code)]` strictly enforced across all 40 core crates. FFI boundaries (`angryier-solver-z3-ffi`, `angryier-solver-bitwuzla-ffi`, `angryier-arch-xed-ffi`) are isolated, audited exceptions wrapped by safe Rust adapters.
- **COW State & Memory:** Layered Copy-on-Write memory model with byte-granular tracking, under-constrained memory (`uc_memory`) debt accounting, and symbolic-address resolution policies (Concretize, FullArrays, RegionBased).
- **BLAKE3 Merkle Hashing:** High-speed constraint slicing and canonical query hashing using SIMD-accelerated BLAKE3 with stack-allocated buffers.

---

### Semantics & ISA Support (1,574 Registered Forms)

- **General Purpose:** Complete integer arithmetic, bit-scan/popcount, bit-test family (BT/BTS/BTR/BTC), multi-operand shifts/rotates with flag modeling, string operations (REP/REPE/REPNE MOVS/STOS/CMPS/SCAS), and port I/O (IN/OUT/INS/OUTS).
- **SIMD & Vector Extensions:**
  - SSE, SSE2, SSSE3, SSE4.1, SSE4.2 (scalar and packed float/integer operations, blends, roundings, dot products).
  - AVX & AVX2 (cross-lane permutes, variable shifts, broadcast, gather).
  - AVX-512 (EVEX ZMM packed arithmetic, opmask registers `k1..k7`, merging `{k}` and zeroing `{z}`).
  - AVX10 (EVEX integer ALU slice).
  - VNNI & VNNI-INT8 (dot products and saturated additions).
  - Intel AMX (tile configuration, tile load/store, matrix multiplication TDPB* / TDPFP16PS).
- **System & Security Features:**
  - Intel CET (Control-flow Enforcement Technology: shadow stack operations RDSSP, INCSSP, SAVEPREVSSP, RSTORSSP, WRSS, WRUSS).
  - Intel APX (Advanced Performance Extensions: 61 forms including JMPABS, PUSH2/POP2, CCMPcc/CTESTcc, CFCMOVcc, NDD forms, NF flag suppression).
  - x87 FPU: Complete status word (`X87_SW`), condition codes C0–C3, control word (`X87_CW`), stack management (TOP pointer), transcendentals, and hardware-validated FCOM/FCOMP/FUCOMI.

---

### Solver Infrastructure

- **Portfolio Orchestration:** Smart query routing across Fuzzy-SAT, Z3 Native FFI, and Bitwuzla Native FFI.
- **Iterative Work-Stack DAG AST Translation:** Replaces recursive translation with a two-phase post-order work stack, eliminating stack overflow vulnerabilities on deep symbolic execution paths.
- **Mid-Flight Cancellation:** Safe watchdog timer (`solve_with_deadline`) terminating runaway SMT queries in milliseconds without hanging worker threads or leaking solver instances.
- **Incremental Contexts:** Scoped push/pop Z3 solver contexts keyed by `DependencyKey` for 15.5–20.2× speedups over cold rebuilds.

---

### Full Repository Bug Sweep & Hardening

Over 58 confirmed bugs identified and resolved during comprehensive multi-agent audits:
- **Semantics:**
  - Fixed second-MSB offset calculation in `write_shift_flags` for `RotateRight`.
  - Added low-byte truncation (`& 0xFF`) to CET `INCSSPD`/`INCSSPQ` instruction semantics.
  - Implemented missing modulo-9 reduction for 8-bit RCL/RCR carry rotations.
  - Corrected x87 FCOM condition code clearing to include C1 bit.
  - Added upper-bound check on `operand_st_index` preventing status/control register index out-of-bounds.
  - Guarded `ExprOp::RotL`/`RotR` against `BitVec(0)` to prevent division-by-zero panics in constant folding.
  - Enforced unsupported operand error for VSIB memory operands in IR lowering.
- **Solvers:**
  - Inserted predicate key into `index_unsat_core` preventing malformed UNSAT cores.
  - Corrected `eliminate_redundancy` to deduplicate strictly on canonical query keys.
  - Fixed operand ordering for `Concat` in `FuzzySatBackend` and added `Bool` sort width.
  - Added proper solver reference decrement (`Z3_solver_dec_ref`) on `Z3FfiBridge::drop` preventing memory leaks.
  - Enforced scope rollback on translation errors during incremental Z3 solving.
  - Enforced `#![forbid(unsafe_code)]` in `angryier-solver-fuzzy`.
- **Runtime & Memory:**
  - Replaced panicking `.expect()` calls in `uc_ledger` with safe error propagation (`MemoryError::Unmapped`).
  - Deferred under-constrained memory debt recording until after access permissions are verified.
  - Cleared stale `concrete_registers` entries when registers transition to symbolic.
  - Fixed security cookie scanner to continue memory region scanning instead of prematurely aborting on encountering symbolic bytes.
  - Expanded UAF detection to cover `AccessKind::ReadWrite`.
  - Resolved ABBA deadlock in work-stealing scheduler by dropping donor locks before acquiring local queues.
- **Models & Security:**
  - Ensured SimProcedures returning `SimResult::Continue` properly commit written memory and set RAX return codes (`STATUS_SUCCESS`).
  - Corrected `PsCreateSystemThread` to write the thread handle to the output parameter and return `STATUS_SUCCESS`.
  - Added page alignment (`& !0xFFF`) to freed pointer tracking in UAF detection.
  - Bound PE export directory function counts to prevent allocation denial-of-service on untrusted binaries.
  - Fixed parent taint count corruption in `InMemoryTaintEngine::transform`.
  - Resolved priority inversion in WAL eviction under backpressure.
  - Added binary path escaping in CLI Lua template interpolation.

---

### Strong Lua 5.4 API

- **Modular Architecture:** Refactored into `crates/angryier-runtime/src/script/` (`mod.rs`, `utils.rs`, `state.rs`, `session.rs`).
- **`angry.*` Binary Utilities:**
  - `angry.hex(bytes)` / `angry.unhex(str)`
  - `angry.pack64(v)` / `angry.unpack64(bytes)` / `angry.pack32(v)` / `angry.unpack32(bytes)`
  - `angry.disasm(bytes, [base_addr])` returning XED instruction details (`len`, `length`, `hex`, `operands_count`).
- **`LuaState` UserData Handles:**
  - Monotonically stable `state_id: u64` identity.
  - Inspection: `:pc()`, `:reg(name)`, `:regs()`, `:read_bytes(addr, len)`, `:trace()`, `:constraints_count()`, `:is_alive()`.
  - Mutation: `:poke(addr, byte)`, `:write_bytes(addr, bytes)`, `:symbolic(reg, [width])`, `:symbolic_memory(addr, len, [name])`.
  - SMT Solving: `:solve()`, `:eval(reg_or_name)`, `:terminate([reason])`.
- **`LuaSession` Controller:**
  - Interactive instantiation via `angry.open(path, [opts])` with optional Z3 solver backend.
  - Stepping controls: `:step([n])`, `:step_until(target_pc, [max_steps])`.
  - Breakpoints: `:add_breakpoint(addr)`, `:remove_breakpoint(addr)`, `:breakpoints()`.
  - Dynamic Hooks: `:hook(addr, fn)` with support for `"terminate"` or `"abort"` return signals, `:unhook(addr)`.
  - State shortcuts delegation directly to active state (`session:pc()`, `session:reg()`, `session:read_bytes()`, etc.).
- Complete documentation available in [`docs/LUA_API.md`](docs/LUA_API.md).

---

### Performance & Benchmarks (Gate J & Gate A/B)

- **Gate J (Real Windows Drivers vs angr 10.0, Release Mode):**
  - `GVCIDrv64.sys`: 194 steps in 0.010 s (**18,835 steps/s**) vs angr 193 insts at 112 steps/s — **168× raw speedup**.
  - `sandra_x64.sys`: 691 steps in 0.025 s (**26,992 steps/s**) vs angr 698 insts at 130 steps/s — **207× raw speedup**.
  - Aligned SimProcedure models achieve up to **432× raw throughput** over Python/VEX emulation.
- **Gate A (Dual-Mode Concolic Speed):**
  - Concolic mode runs at 82–88% of pure concrete floor speed on real driver execution traces.
  - Concolic-vs-symbolic speedup: **2.6×–2.9×**.
- **Gate B (Memory Footprint & Scaling):**
  - Concrete state fork cost: **4.0 µs / state**, **2.7 KB RSS / state**.
  - Symbolic state fork cost: **80.9 µs / state**, **11.1 KB RSS / state**.
  - Z3 solver context at depth 500: **52 KB**.

---

### Known Limitations

- **Floating-point Division-by-Zero:** Concrete interpreter produces IEEE-754 ±Inf/NaN; certain x87 masked divide edge cases remain non-standard.
- **Memory Representation:** State backing uses sparse `BTreeMap` page maps rather than OS-page-table hardware COW.
- **ISA Coverage Tail:** Instructions outside the 1,574 registered forms explicitly fail as form ID 0.
- **JIT Acceleration:** JIT compiler integration (Phase 13) remains deferred pending evidence from Gate G profiling.
