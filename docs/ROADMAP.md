# Angryier — Consolidated Roadmap and Architecture-as-Built

> **Single source of truth — 2026-09-24.** This file merges the former phase
> tracker (ROADMAP.md), the implementation-status annotations of the
> `docs/architecture/` set (which froze 2026-09-14 and drifted stale), and the
> verified workspace state at commit `074156a` (224 commits, `main`). Where an
> architecture doc's status header disagrees with this file, this file wins.
> The architecture docs remain the detailed *design contracts* — invariants,
> boundaries, identity/trust models — and `Plan.md` remains the immutable
> Q9–Q54 decision baseline. `docs/status/*.md` are historical.

---

## 1. Mission and positioning

Angryier is a native, parallel symbolic/concolic binary-analysis platform in
safe Rust. The competitive thesis is **not** "angr, but faster" and not
"SymQEMU, but Rust": it is **dual-mode execution in one engine sharing the
same AngryIR semantics** — a concolic fast path for coverage and input
generation (SymCC/QSYM-class speed) and a full symbolic exploration mode for
analysis depth (angr-class capability), switching per-state via the
PROVE/EXPLORE/HUNT exploration profile.

```text
SymCC:    compiled symbolic propagation, source-only, fastest concolic
SymQEMU:  SymCC ideas in QEMU TCG, binary-only, fast concolic
QSYM:     Pin DBI + instruction-level concolic, fast, deliberately unsound
Fuzzolic: QEMU tracing + Fuzzy-SAT, interesting solver architecture
angr:     IR-based symbolic emulator, deep analysis, slow execution
```

Angryier does not compete with SymCC on source-instrumented speed or with
angr on analysis breadth (yet). It competes by being the only engine that
does both modes natively, sharing XED decode, AngryIR lowering, the solver
portfolio, environment models, and loading — in safe Rust, at multicore
scale. Gate J forces this to be demonstrated on a named workload, not
asserted.

Core ordering principle: **contact with reality before performance claims.**
No perf number is credible until measured on a real binary loaded, decoded,
and executed end-to-end (Gate 0 — passed), and semantic truth requires an
independent oracle (hardware differential testing — live), not
self-verification.

---

## 2. Verified current state (2026-09-24)

Facts verified on this checkout unless marked *reported* (feature-gated
suites require system Z3/XED):

- **Workspace:** 42 crates, 224 commits, clean build; workspace Clippy clean
  with warnings denied; `cargo fmt` clean. Default build has **zero native
  dependencies**; Z3/Bitwuzla/XED are opt-in Cargo features.
- **Tests:** 933 passed / 0 failed across 97 test binaries (default
  features); 73 passed under `-p angryier-runtime --features xed,z3`
  (end-to-end suites incl. Gate 0, x87, loop-summary differentials, and
  replay capsules); the x87 oracle drives 462 hardware-differential cases
  in one ~8 s test.
  `cargo fmt` clean, workspace Clippy clean (all targets, all features).
  Verified 2026-09-24 on this checkout.
- **Gate 0 — passed, including the dynamic case.** Statically-linked musl
  and glibc hello-world run end-to-end through full libc startup
  (~110k instructions for glibc) with matching stdout and exit code; gcc
  -O0 and -O2 programs match native execution; **dynamically-linked ELF
  runs**: `load_elf_dynamic` maps `DT_NEEDED` libraries recursively, applies
  RELATIVE/GLOB_DAT/JUMP_SLOT relocations, evaluates IRELATIVE resolvers,
  seeds TLS, and hooks `__libc_start_main` → `main` (angr-style static
  linking, no `ld.so` process). PE32+ loads and executes — statically
  linked images only (import-table linking out of scope). **Driver-
  campaign gap (2026-09-25):** Windows kernel `.sys` analysis needs PE
  IAT resolution to named stubs, a Windows kernel API model layer
  (ntoskrnl/NDIS/HAL — zero coverage; the environment model is Linux
  syscalls + libc), DriverEntry/IRP state shapes, and an integration
  surface for the external angr-based sweep (no Python API exists).
  Import-directory parsing, IAT-to-stub resolution, the DriverEntry entry mode, and per-export forced-return hooks landed (2026-09-25) on synthetic importing PEs. The Lua/CLI sweep surface now dispatches by magic bytes: `angry.run`/`angry.open` load `MZ` images through `load_pe_driver`/`load_pe` (2026-09-26) — real `.sys` drivers load and execute from DriverEntry (first contact via the byovd-harness escalation contract: 15-24 steps before failing on unmapped forms). **2026-09-27: the ~15-step wall was diagnosed as the MSVC security-cookie fastfail** — drivers ship the linker's DEFAULT `__security_cookie` (or zero) in `.data`, and their `__security_init_cookie` executes `int 29h` (`__fastfail`) unless the loader has randomized it first (real Win10+ loader behavior). `load_pe_driver` now scans writable sections for the DEFAULT cookie and its complement and overwrites both with a deterministic engine cookie, and seeds `gs:[0x30]` with the same value so `/GS` frame checks compare consistently — `__security_init_cookie` short-circuits and DriverEntry proceeds. **TbtBusDrv executes 200+ steps (was 15), AMDRyzenMaster 172 (was 15), and GVCIDrv64 completes DriverEntry and terminates cleanly.** The first ISA gaps the real prologues hit are closed: MOVHLPS/MOVLHPS lane moves and BT/BTS/BTR/BTC r32/r64 × reg/imm8 (14 new forms, hardware-oracle validated — the oracle caught a pre-existing `1 << 64` wrap in the write-back bit-test forms, now index-masked mod width). **Round 2 (2026-09-27):** the next wall was a second cookie-shape requirement — some builds' `__security_check_cookie` is the old-CRT form that succeeds only when `(cookie >> 48) == 0` (`rol rcx,16; test cx,0xFFFF; jnz fastfail`), so the seeded cookie's top 16 bits are now zero (real Windows init cookies are 48-bit random). With the kernel pool model attached, **TbtBusDrv executes DriverEntry end-to-end: 1657 steps, 41 kernel-API SimProcedure dispatches, clean NTSTATUS return (`0xc000009a`); AMDRyzenMaster runs 2000+ steps unblocked; GVCIDrv64 terminates cleanly.** The ISA gaps the deeper paths revealed are closed: XORPS/XORPD (reg+mem), RDMSR/WRMSR (zero model, debt-recorded), LFENCE/SFENCE/MFENCE + PAUSE (no-ops), IN/OUT port I/O (reads zero, writes dropped), a DIV/IDIV r32 width fix (32-bit results now zero-extend into the GPRs), and the r32 SHL/SHR/SAR/ROL/ROR count-masking + flag-modeling completion (old-CRT-correct `rol`-check shapes; 318 new hardware differential cases; the old unmasked r32 providers were replaced, and a form-id uniqueness test now guards the index against the IN_AL_DX/MOVDQU 0x01E2 collision class). **Round 3 (2026-09-27):** the kernel API model layer gained `IoBuildDeviceIoControlRequest` (returns a zero-backed IRP block — TbtBusDrv's `0xc000009a` wall was exactly this call returning NULL, i.e. "IRP allocation failed") and `RtlGetVersion` (writes a Win10-shaped version struct; the previous stub left zeros and sent version-branching drivers down legacy paths). TbtBusDrv now reaches step 1467 (36 dispatches) and stops on a driver-internal uninitialized function-pointer slot (a `.text` table entry filled with `0xCC` in the image, no static initializer anywhere — an under-constrained path, not a model gap). AMDRyzenMaster runs 15000+ steps through bounded I/O delay loops (`in eax, dx` counter loops) and PCI config-space probing (`out dx, eax` to port 0xCF8; reads return zero = "no device", honest semantics). **Verdict validation works:** the harness fixtures link stubs.c (local bump allocator, no-op free — static-analysis-only shapes), so import-based variants were built (mingw + a minimal ntoskrnl import lib); running `double_free_vuln_import_O2.sys` through the engine yields pool `a=1 f=2 df=1` — **the double-free is detected dynamically** — while the allocsize/refcount fixtures balance out. **Round 3b (2026-09-27):** the concrete interpreter now produces IEEE-754 results for float division by zero (`x/0` → ±Inf, `0/0` → NaN) instead of rejecting the divide — closing the x87-masked-divide gap; the AVX divide-by-zero oracle case now matches the host byte-for-byte. Verdict validation is a regression suite: 9 import-variant fixtures with per-fixture pool assertions (`double_free_vuln` → df=1 detected; safe/balanced fixtures → df=0; the pointer-reassign vuln is a UAF write, not a double free — both frees target distinct pointers), and the harness `fixtures/Makefile` gained a `make import` target (mingw dlltool ntoskrnl import lib) so the variants build reproducibly. Remaining: broad-form ISA coverage for DriverEntry prologues, more of the kernel API model layer (spec available: byovd-harness `windows_kernel_api_models` manifest), and real-.sys verdict validation. Gate J discipline:
  no cross-engine (angr-vs-Angryier) timing exists, so no driver-
  campaign throughput claim transfers yet.
- **Dual-mode engine (Phase 6, centerpiece):** `ConcolicSession` shadows
  concrete execution with (concrete, expression) pairs, constant-folds
  untainted data, records path constraints, and inverts branches through the
  portfolio (`solve_last_branch`); EXPLORE/HUNT record analysis debt instead
  of aborting; `requires_prove()`/`promote_to_symbolic` hand off to PROVE.
  A differential test proves concolic and full-symbolic modes produce the
  same input on the same binary. **Speed (release profile — thin
  LTO, 90k-step real trace, `tests/concolic_speed.rs`, packaged by
  `scripts/gate_report.sh`):** on the dense-influence fixture concolic
  runs at **1.8× full-symbolic** (3.98 s vs 7.18 s, 2026-09-25 after
  the FxHash round; the concrete-first fast path below is neutral there
  by construction — the input reaches every block) with the concrete
  floor at ~0.42 s (~213 steps/ms). **The QSYM-style concrete-first fast
  path landed the same day: blocks with no symbolic influence skip shadow
  evaluation entirely (buffered concrete walk, fallback on first
  influence, committed state indistinguishable from the full fold;
  concrete branch conditions record no constraint)** — on the new
  sparse-influence leg (input consulted once in 60k steps, the shape of
  real programs between input uses) **concolic runs at 1.96× the
  concrete floor** (108.7 vs 213.0 steps/ms, zero path constraints), vs
  9–12× overhead on dense code. Cumulative: concolic is ~4.6× faster
  than first measurement (18.3 s dense). The 5–10× target remains open;
  the profiled remainder is SHA-256 dependency keys (~16%).
- **Full symbolic mode (Phase 10 engine):** `SymbolicSession` forks at
  branches, solver-gates directions (`step_state_checked` prunes UNSAT),
  merges at reconvergence points (`merge_at`/`merge_snapshots` via `Ite`),
  explores in parallel (`run_parallel`), and solves found states into
  concrete inputs (`solve_state`). Validated on real glibc (183 steps, 14
  forks, 6 peak states).
- **CFG + loop summarization:** `angryier-cfg` recovers blocks and typed
  edges (~25k blocks on the glibc fixture); `Cfg::dominators`/`loops` find
  natural loops; `Runtime::loop_summaries` extracts pure induction loops —
  single-block **and straight-line multi-block bodies** (≤8 blocks) — and
  `SymbolicSession::enable_loop_summaries` collapses them: concrete trip
  counts in closed form (a 100-iteration loop runs in 5 steps instead of
  300+), **symbolic trip counts** as exact `Ite` closed forms with
  wraparound corner arms and exit-condition constraints, **Eq/Ne exits**
  (Ne guarded by a divisibility constraint; non-divisible distances fall
  through to stepping). Differential tests prove summarized runs replay
  identically to stepped runs (models replay to expected exit codes);
  nested mixed loops measure ~14× step reduction. Unsummarizable shapes
  (inner branches, mid-body entries, calls, per-iteration effects)
  explicitly fall through.
- **Function summaries (Phase 10):** `Runtime::function_summaries`
  extracts pure-function candidates — straight-line bodies ending in
  `ret`, register-only computation — and
  `SymbolicSession::enable_function_summaries` collapses calls to them:
  the body executes once per argument *shape* (callee entry + argument
  widths) in a scratch evaluator over placeholder symbols, and the
  resulting expression **template** is substituted with the caller's live
  arguments on every further call — repeated calls become O(1) expression
  rewrites (the hash-consed arena folds concrete arguments at intern
  time). Soundness is layered: a lowered-IR scan rejects any body whose
  instructions load, store, branch, or partially write a register;
  a dynamic purity check seeds exactly the argument registers and
  re-seeds with anything else the lowered IR reads (rflags
  read-modify-writes are the common discovery), so the template is always
  an exact function of inputs the caller substitutes; the template
  carries the exact caller-clobber register delta (rax plus every written
  GPR — flags are caller-saved per the ABIs and stay uncarried). Direct
  and constant-folded indirect calls (`call *%rax` — the DriverObject
  dispatch shape; indirect-only callees get a lazy per-target extraction)
  summarize. A placeholder **merge-cost model**
  (`FunctionSummaryCostModel` / `DepthWidthCostModel`, depth × width
  against a budget) is the summarize-vs-inline seam for the real
  multifactor model. Differential proof
  (`tests/function_summaries.rs`): a 50-iteration caller fixture — plain
  stepping 753 steps vs 304 summarized (2.5×) through direct `call`,
  803 vs 354 (2.3×) through `call *%rax` — with one template build, 50
  summary hits, matching exit values, and solver-model replay equivalence
  for symbolic arguments; impure callees (any memory operand) never
  summarize and stay exactly correct.
- **Semantics:** 429 handwritten Intel 64 forms (integer/control-flow,
  bit-scan/popcount, bit-test family — BT/BTS/BTR/BTC r32/r64 × reg/imm8
  with mod-width index masking — shifts/rotates complete at r32/r64 with
  count masking and CF/OF flag modeling, SSE/SSE2/SSSE3/SSE4.1/SSE4.2
  scalar+packed incl. MOVHLPS/MOVLHPS lane moves and XORPS/XORPD, CRC32,
  PTEST, byte shifts, port I/O (IN/OUT), RDMSR/WRMSR, memory fences, plus a
  39-form x87 slice — FLD/FST(P), the FADD/FSUB/FMUL/FDIV families,
  FUCOMI/FCOMI branch flags, FINIT — with a tag-in-data-plane stack model
  that fits the existing register file) plus a live declarative generator
  (`angryier-semantics-gen` patterns → `DeclarativeProvider` in
  `angryier-semantics-intel64`, layered over handwritten in a 0x10000+
  rule-id band). **Hardware differential oracle validates 856 integer/SSE +
  462 x87 boundary cases** against the host CPU on defined flag bits and
  has caught real corpus bugs (rcl/rcr carry formula, cmpxchg aliasing,
  pshufd operand order, crc32 accumulate, mpsadbw imm fields, shift SF at
  sub-64 widths, an inverted x87 stack-full select, and a `1 << 64` wrap
  in the write-back bit-test forms whose index now masks mod width).
- **Solver stack:** real Z3 and Bitwuzla FFI (SAT/UNSAT/UNKNOWN with model
  extraction); portfolio router with per-query `QueryShape` dispatch,
  `CrossCheckPolicy`, hard timeouts; `angryier-solver-fuzzy` mutation tier
  for simple `x==C`/`x<C`/`x!=C` constraints; constraint slicing to the
  predicate's dependency cone (measured: identical canonical query keys
  across different inputs); exact-result cache + UNSAT-core superset index;
  incremental push/pop Z3 contexts keyed by `DependencyKey`; **solver
  cancellation** via `Z3Backend::interrupt()` with a quiet error handler
  (replaces Z3's process-killing default), plus true **mid-flight
  cancellation** — `solve_with_deadline` arms a watchdog around the check
  itself (a 12 s grind returns `Unknown` in 83 ms with the soft limit
  parked at 30 s), composed with the per-query soft limit and routed
  through the safe adapter for every query; value-aware cache admission
  and a default-off alpha-equivalence tier round out reuse.
- **Scheduler:** `OsWorkerPool` — OS threads, worker-local deques,
  LIFO-local/FIFO-steal, global overflow, `PoolStats`. Measured 3.93×
  wall-time on 4 workers (`parallel_concolic`, static musl hello);
  `parallel_explore` spreads 48 states / 377 unique PCs across 4 workers.
- **Gate B measurements (post-rework):** after the
  state/memory/expr round (2026-09-24), 10k diverging concrete EXPLORE
  states cost **2.7 KB/state RSS** with **17 µs forks** in debug
  (was 42.8 KB / 255 µs — a 16× footprint collapse at the Process level;
  the memory layer alone measured 47 → 0.87 KB/state, 54×); 10k symbolic
  PROVE states cost **11.1 KB/state** plus a 285k-node shared interned
  arena. **Release rerun (2026-09-25):** footprints identical (layout is
  optimization-invariant) with forks at **4.0 µs concrete /
  80.9 µs symbolic**; solver migration is a *time* problem, not memory —
  Z3 context at depth 500 is only **52 KB**, cold rebuild 76–88 ms vs
  1.3–6.0 ms warm incremental (**15.5–20.2×** release), and a half-shared
  prefix recovers almost none of it. Benchmarks:
  `angryier-runtime/tests/gate_b.rs`,
  `angryier-solver-z3-ffi/tests/migration_bench.rs`.
- **Environment:** SimProcedure library (strlen/strcmp/malloc/free/memcpy/
  memset/puts/exit) and a syscall model covering read (symbolic stdin
  materializes input bytes), write/writev, mmap/munmap/brk, openat/close/
  fstat/access/ioctl, arch_prctl (TLS/FS-relative), getrandom, prlimit64,
  readlinkat, futex, set_tid_address/set_robust_list/rseq, getpid/gettid/
  uid/gid family, exit/exit_group. Named files and symbolic argv/file
  contents/stdin are input surfaces. Conservative SSE-era CPUID.
- **Symbolic-address memory policy (Phase 3):** Concretize / FullArrays /
  RegionBased strategies, `ConcretizationResolver`, byte-granular COW
  coexistence (41 tests).
- **Scripting (Phase 15):** embedded Lua — `angry.run(path, opts)` with
  symbolic regs/argv/files, find/avoid, `solve = true` returning input
  models; `angry.open(path)` live session handles (`step`/`pc`/`reg`/
  `states`/`symbolic`); `angryier run` CLI (`--script`, `--symbolic`,
  `--find`, `--argv`, `--dynamic`).
- **Fuzzing:** `Runtime::fuzz_generate` — solve found states into input
  bytes, replay concretely via stdin-served `read(0)`, return
  (input, reached-coverage) pairs.
- **Replay/provenance:** in-memory capsule store + validator + durable
  `FileReplayStore`; tier schema, adaptive trace governor, per-worker
  `FlightRecorder` ring (Tier-0-first eviction, never drops Tier 1).

### Known gaps (honest list)

- Broad ISA form mapping: unmapped instructions fail explicitly as form
  id 0 — real binaries still hit unmapped forms outside the exercised set.
- x87 executes end-to-end (39 forms wired into the runtime form map with
  the XED FSTPNCE/FSUB-swap quirks handled; engine-vs-native tests green);
  FSTSW AX still needs a status-word register and FST st(i) hits an XED
  decode quirk; deep `ld.so` emulation replaced by
  the static-hook approach; AVX/AVX-2/AVX-512 families not yet in the corpus.
- The concolic fast path is faster than full symbolic (1.5–1.6× release,
  re-measured 2026-09-25) but far from the 5–10× target. Of the five
  previously profiled costs, four are fixed (register-write BTreeMap
  deep-clone, per-read `Vec` in `LayeredMemory::read`, SHA-256 on
  hash-cons *hits*, full-node clones for sort/op-only probes);
  `PersistentMemory::write_materialized` still clones the page map per
  store but no longer registers in the profile. **Fresh callgrind profile
  (2026-09-25, 20k-step mix-loop, release+debuginfo):** ~50% of all
  instructions were hashing — SipHash (`RandomState`) over `ExprNode`
  keys in the arena hash-cons maps ~33% (**fixed the same day**: FxHash
  in `angryier-types`, arena + evaluator hot maps swapped; concolic −20%,
  symbolic −8%, Gate-A multiplier 1.5–1.6× → 1.8×), SHA-256 dependency
  keys on intern misses ~16% (loop workloads mint fresh expressions per
  iteration; derivation is already Merkle-style over child keys, so
  further wins need a digest change — deferred pending identity-cost
  review); malloc/free ~12%; shadow evaluation itself ~9%. Beyond
  hashing, the ratio target needs concolic-side short-circuits (skip
  shadow evaluation of blocks with no symbolic influence) — **landed
  2026-09-25** (`try_concrete_block`; sparse-influence overhead vs the
  concrete floor is 1.96×, dense-leg multiplier unchanged at 1.8×).
- Symbolic-evaluator gaps surfaced by the speed benchmark — **closed
  2026-09-25** except one: degenerate `ZExt` truncates via `Extract` with
  view-width-normalized register reads, comparison operands coerce
  mismatched widths (unsigned ZExt / signed SExt) with arena folding of
  `Ult/Ule/Slt/Sle`, and `RotL`/`RotR` work end-to-end (arena, symbolic +
  concolic evaluation, Z3, Bitwuzla, fuzzy tier). Remaining: concrete
  division by zero rejects where x87 masked semantics yield ±Inf.
- Memory is sparse-map backed, not OS-page-table COW; the 10k-live-state
  footprint and depth-500 solver-migration numbers are unmeasured.
- Concolic fast-path speedup (5–10× target) unmeasured on long traces.
- The Z3 FFI expression translator recurses without a depth guard: a
  solver-gated symbolic loop long enough to accumulate the per-step
  flag-composition chain (~118 nodes/iteration, pre-existing engine
  behavior — identical with or without summaries) overflows the test
  thread stack around ~40 iterations; the function-summary differentials
  run those legs on a large-stack thread. An iterative translator (or a
  depth guard with honest Unknown) is the follow-up.
- Function-summary current bounds: bodies are straight-line register-only
  chains (≤64 instructions); calls inside summarized callees, memory
  operands, and per-iteration-effect shapes fall through to stepping;
  flags are not carried (caller-saved). Alpha-equivalence reuse beyond
  the validation-mode tier, cache-admission policy, NUMA-pinned queue
  groups, and state economics are not implemented.
- Performance work is still measured on synthetic microbenchmarks plus a
  small set of real fixtures, not broad real execution traces.

---

## 3. Architecture (as built)

### 3.1 Three planes

```text
                                  ANGRYIER
                                     |
             +-----------------------+-----------------------+
             |                       |                       |
             v                       v                       v
      EXECUTION PLANE            TRUTH PLANE           KNOWLEDGE PLANE

  loader / state import       canonical semantics       QIHSE system of record
  Intel 64 decode (XED)       support manifest          KEYSTONE indexes/ingest
  concrete execution          differential testing      exact reusable facts
  taint/dataflow              equivalence evidence      dependency graph
  concolic/symbolic           fidelity ledger           semantic fingerprints
  COW state/memory            replay validation         fused embeddings
  expression DAG              solver classification     analyst annotations
  solver orchestration        target-profile truth      time-series telemetry
  scheduler / NUMA            semantic identities       retention/cleanup
  Lua scripting / fuzzing
```

The Execution Plane must remain useful with persistence completely disabled.
The Knowledge Plane suggests; exact validation authorizes.

### 3.2 Global invariants (unchanged, all still enforced)

1. Decode is not semantics — XED identifies; Angryier owns meaning.
2. Host capability is not target capability.
3. Published semantics are immutable once sealed and content-addressed.
4. `ContentId` (exact) and `SemanticFingerprint` (candidate) are separate.
5. Post-seal transformations are derivations with contracts and evidence.
6. Execution artifacts are validity-scoped (identity + profile + code-page versions).
7. Replay-visible mutation is atomic under one ledger epoch.
8. Solver uncertainty is never silently converted to UNSAT
   (SAT/UNSAT/UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR distinct).
9. Persistent reuse is fail-closed on compatibility/dependency keys.
10. Workers do not block on QIHSE/KEYSTONE.
11. Correctness-critical Tier-1 provenance is never silently dropped.
12. PROVE never silently approximates; EXPLORE/HUNT relaxations carry debt.
13. Learned/quantum-inspired ranking is advisory only.
14. Deterministic mode is mandatory and recordable/replayable.
15. JIT is evidence-driven (Gate G) — still deferred, correctly.

**Unsafe-code policy as practiced:** all core crates `forbid(unsafe_code)`;
the three FFI crates (`angryier-solver-z3-ffi`, `angryier-solver-bitwuzla-ffi`,
`angryier-arch-xed-ffi`) are the documented, narrowly-audited exceptions, with
safe adapter crates at the boundary — exactly the pattern `security.md`
prescribed. A future `angryier-jit-ffi` follows the same shape.

### 3.3 Crate map (42 crates, verified)

```text
crates/
  angryier-types/             shared IDs, versions, hashes, policy enums
  angryier-core/              orchestration contracts, engine context
  angryier-arch/              ISA-neutral architecture traits
  angryier-arch-intel64/      Intel 64 registers, features, CPU profiles
  angryier-decode-xed/        XED normalization boundary; no semantic truth
  angryier-arch-xed-ffi/      native XED decoder FFI (opt-in; 11 tests)
  angryier-loader/            ELF64 (static+dynamic) / PE32+ loading
  angryier-runtime/           pipeline glue + concolic/symbolic sessions
                              + Lua scripting + loop/function summaries
  angryier-semantics/         provider/builder contracts, sealed block builder
  angryier-semantic-contracts sealed identity + transformation/evidence
  angryier-semantics-gen/     declarative pattern compiler/generator
  angryier-semantics-intel64/ handwritten corpus (363 forms) + DeclarativeProvider
  angryier-ir/                AngryIR types, lowering, verification
  angryier-expr/              symbolic expression DAG, hash-consing, folding
  angryier-memory/            layered COW memory + symbolic-address policy
  angryier-state/             persistent machine/path state, fidelity ledger
  angryier-taint/             taint labels/states/promotion/transform/merge
  angryier-execution/         concrete interpreter + symbolic evaluator
  angryier-cfg/               CFG recovery: blocks, edges, dominators, loops
  angryier-ledger/            atomic replay-visible publication boundary
  angryier-replay/            replay capsules, validator, FileReplayStore
  angryier-solver/            queries, portfolio, batch, cache, cancellation
  angryier-solver-z3/         Z3 safe adapter (ffi feature)
  angryier-solver-z3-ffi/     native Z3 bridge: models, incremental, interrupt
  angryier-solver-bitwuzla/   Bitwuzla safe adapter (ffi feature)
  angryier-solver-bitwuzla-ffi/ native Bitwuzla bridge (vendored CaDiCaL)
  angryier-solver-fuzzy/      Fuzzy-SAT mutation tier (portfolio Tier 1)
  angryier-scheduler/         OsWorkerPool, work stealing, NUMA model
  angryier-models/            SimProcedures + Linux x86-64 syscall model
  angryier-provenance/        tier schema, trace governor, FlightRecorder
  angryier-telemetry/         bounded queues, aggregation, backpressure
  angryier-storage/           WAL, checkpoint replay, retention
  angryier-knowledge/         exact/advisory reuse + invalidation graph
  angryier-qihse/             QIHSE adapter (in-memory)
  angryier-keystone/          KEYSTONE adapter (in-memory)
  angryier-fusion/            encoders + masked/gated fusion (in-memory)
  angryier-fuzz/              hybrid fuzzing bridge + fuzz_generate
  angryier-jit/               validity/isolation contract only (deferred)
  angryier-plugins/           internal Rust extension traits, registry
  angryier-distribution/      work-unit codec (encode/decode round-trip)
  angryier-bench/             benchmark sink, records, aggregates
  angryier-cli/               CLI: version/status/crates + `run` (mlua)
```

Dependency direction: acyclic and layered toward `angryier-types`; adapters
depend inward on contracts; solver/JIT/database SDK objects never leak into
state, semantics, or identity types; QIHSE/KEYSTONE remain optional
asynchronous edges. Full layering diagram: [architecture/crates.md](architecture/crates.md).

### 3.4 Dual-mode execution (the centerpiece)

```text
Concolic fast path (EXPLORE/HUNT):
  - single concrete state, no state tree
  - symbolic shadow constraints built alongside concrete execution
  - QSYM-style optimistic solving and pruning; debt recorded, not fatal
  - Fuzzy-SAT for simple branch constraints; Z3/Bitwuzla for complex ones
  - parallelizes across inputs (QSYM model — parallel_concolic)

Full symbolic mode (PROVE):
  - state forking, COW memory, full symbolic state tree
  - solver-gated branching, state merging / Veritesting, loop summaries
  - CFG-guided reconvergence and pruning
  - parallelizes across states (run_parallel)

Both modes share: XED decode, AngryIR lowering, solver portfolio,
environment models, loader. Switching is per-state via
promote_to_symbolic when the fidelity ledger exceeds profile tolerance
(HUNT never promotes).
```

Why a fast interpreter, not a JIT, for the concolic path: a dispatch-loop
interpreter with symbolic shadows is safe Rust, validates the thesis, and
targets 5–10× over the reference interpreter. The JIT (Phase 13) is an
optimization behind Gate G, not a prerequisite.

### 3.5 Decode → semantics → AngryIR

- XED-owned objects terminate in `angryier-decode-xed`; downstream crates
  consume Angryier's serializable `DecodedInstruction`.
- Hybrid definition: declarative `SemanticPattern`s (families) + typed Rust
  combinators + handwritten overrides; multiple matching providers are a
  hard error; unsupported forms fail explicitly.
- Two-level IR: rich sealed canonical semantic IR (truth) → AngryIR
  (compact execution artifact). Sealed blocks carry dual identity
  (`ContentId` authoritative, `SemanticFingerprint` advisory).
- The hardware differential oracle is the independent ground truth
  (Gate D discipline): forms are only "done" when hardware agrees on all
  architecturally-defined bits.

### 3.6 Memory, state, expressions

- Values stay concrete unless promotion is required (branch feasibility,
  symbolic output/address, model, analyst request); taint tracks influence
  first. Concrete → taint → symbolic is the performance model.
- `angryier-expr`: sharded `RwLock` arena, hash-consing, hot-path
  canonicalization + constant folding; `ExprId` packs shard+local index.
- `angryier-memory`: sparse per-page maps (concrete + symbolic bytes),
  `Arc`-shared fork (O(1) in unchanged size), symbolic-address policy
  (Concretize/FullArrays/RegionBased), every concretization
  fidelity-visible. **Deviation from the frozen architecture:** backing is
  sparse `BTreeMap` pages, not OS-page-table COW — documented, accepted
  for now, revisit under Phase 3 remaining work.
- `angryier-state`: persistent roots, constraint lineage, fidelity ledger,
  ownership metadata.

### 3.7 Solver stack

```text
Tier 1: Fuzzy-SAT (mutation-based, cheap, approximate; Unknown falls back)
Tier 2: Z3/Bitwuzla incremental (exact, push/pop keyed by DependencyKey)
Tier 3: Z3/Bitwuzla full (exact, expensive)
```

- Canonical solver-independent queries with exact identity fingerprints;
  cache admission only for Sat/Unsat (transient results rejected).
- Constraint slicing to the predicate's dependency cone before solving —
  sliced queries share canonical keys across executions.
- UNSAT-core superset index: a query whose keys contain a recorded core
  returns Unsat without a backend call.
- Portfolio router dispatches per query shape with backend history and
  cross-check policy; hard timeouts; `Z3Backend::interrupt()` cancels.
- Known tension (unresolved): incremental contexts want state/worker
  pinning; work stealing wants migration. Gate B measures the cost.

### 3.8 Scheduler

`OsWorkerPool` beneath the `Scheduler` trait (`GreedyScore`/`StealCost` with
NUMA distances). Steal order: own deque → most-loaded peer → global
overflow. Single-owner mutation per state. Deterministic `workers=1`.
Remaining: NUMA-pinned queue groups, memory-pressure-aware stealing,
deterministic CPU batch planner (QUBO seam reserved, advisory only).

### 3.9 Provenance, telemetry, knowledge

- Tier 0 (transient) / Tier 1 (structural, never dropped) / Tier 2
  (flight-recorder deep trace, trigger-gated). `FlightRecorder` is a
  bounded per-worker ring with Tier-0-first eviction.
- Bounded queues, WAL/spill discipline, backpressure metrics; retention
  policies (forensic/research/standard/benchmark/disposable).
- Knowledge plane: exact/advisory split, dependency-aware invalidation
  graph with stale states (VALID/REVALIDATION_REQUIRED/ADVISORY_ONLY/
  SUPERSEDED/QUARANTINED/INVALID), in-memory adapters only — persistence
  and the real QIHSE/KEYSTONE submodules are future work behind Gate E.

### 3.10 Scripting, fuzzing, JIT, distribution

- **Scripting is first-class** (Phase 15 landed): embedded Lua via `mlua`
  (`angry.run`/`angry.open`) + `angryier run` CLI. Users author hooks,
  find/avoid policies, and inspect states without recompiling.
- Fuzzing: one-directional today (symbolic → seeds + coverage via
  `fuzz_generate`); bidirectional exchange is Phase 14 remaining work.
- JIT: contract-only (`angryier-jit`), deferred behind Gate G. When built:
  `angryier-jit-ffi` isolates `mmap(PROT_EXEC)`; safe adapter stays
  `forbid(unsafe_code)`; W^X discipline; code-page version guards.
- Distribution: work-unit codec exists; multi-host execution intentionally
  deferred until single-host NUMA scaling is proven.

---

## 4. Phase plan — landed vs remaining

Numbering is historical and kept for cross-references. Status reflects
commit `074156a`.

### Phase 0 — workspace, contracts, measurement baseline
**Status: foundations.** Cargo workspace, metrics schema, bench sink,
micro-binary corpus, manifest schema scaffolded.
**Remaining:** reference benchmark harness running Angryier *and comparison
engines* under equivalent limits; reproducible benchmark command from clean
checkout; CI benchmark smoke.

### Phase 1 — loader, decode, semantic corpus, environment models
**Status: Gate 0 passed and closed (static + dynamic + PE32+ + replay
capsules).** Replay capsules record native-agreeing runs through the
engine, persist via `FileReplayStore` (versioned v2 schema, v1
byte-compatible), and replay deterministically with fail-closed rejection
of tampered/incompatible capsules — proven by tests where the wrong image
rejects before execution (the fixture is deliberately unexecutable, so an
execution error would betray a validation bypass).
**Remaining:** broad ISA form mapping (unmapped → explicit form id 0);
full-registered-form differential-oracle coverage and undefined-flag
policy completion (Gate D).

### Phase 2 — typed values + expression core
**Status: foundations.** Arena/`ExprId`, hash-consing, folding, dependency
metadata, fingerprints, bitvector/bool domains.
**Remaining:** FP/vector/opmask/tile domains; lazy lane materialization;
shared-arena instrumentation.

### Phase 3 — COW memory + persistent state + symbolic-address policy
**Status: policy done (41 tests); sparse-map backing.**
**Remaining:** page-backed COW with real page ownership; symbolic/taint
bitmap; compact COW register file; byte-granular-symbolic × page-COW sharing
test; fork/COW cost measurement under multicore pressure.

### Phase 4 (solver backends) — canonical query layer
**Status: Z3 + Bitwuzla FFI real; portfolio, cache, timeouts done.**
**Remaining:** exercise portfolio dispatch across both FFI backends
simultaneously; per-worker incremental context strategy tied to Phase 5
migration data.

### Phase 5 — native multicore + NUMA scheduler
**Status: worker pool implemented and measured (3.93×/4 workers, concolic);
Gate B measurement pack landed (debug build).**
**Remaining:** release-build reruns of the footprint/migration benchmarks;
both-mode scaling evidence on real binaries (the 3.93× is concolic-only);
NUMA-pinned queue groups; memory-pressure-aware stealing; deterministic CPU
batch planner. The measured migration cost (11–13× cold/warm, prefix sharing
buys little) is the data the Phase 4 context-pinning tension needed —
scheduler policy can now be designed around it instead of assumptions.

### Phase 6 — concolic fast path + dual-mode (centerpiece)
**Status: implemented and differentially validated.** Shadow evaluator,
fuzzy tier, fidelity ledger, EXPLORE→PROVE promotion, `parallel_concolic`.
**Speed: 0.9× → 1.6× (release, direct)** after the per-PC step cache
(decode+seal+lower once per PC, guarded by byte identity and code-page
versions), constant-expression and width memos in the shadow, verifier
memoization keyed by `ContentId`, and allocation trims; correctness suites
green, and one unsound micro-optimization deliberately reverted (foldable-
root gating of the `WriteRegister` constant walk would have changed EXPLORE
debt behavior). **Remaining:** the profiled next wins sit in the
state/memory/expr crates (§5 item 6); HUNT fuzzer integration;
alpha-equivalence caching (shared with Phase 8); a no-state-cap deep-path
benchmark variant (the 32-state cap keeps symbolic states shallow,
flattering the comparison).

### Phase 7 — semantic generator + broad Intel 64 coverage
**Status: generator live and oracle-validated (856 integer/SSE + 462 x87
+ 284 rotate hardware cases); x87 family started (39 forms) and wired into
the runtime form map — float-using binaries execute end-to-end. All 8
handwritten ROL/ROR providers (r64/r32 × imm8/CL) emit the rotate
primitive directly (2026-09-25) — the rewiring exposed and fixed two
latent r32 bugs (`roll $imm` was a udiv no-op; r32-CL read at the wrong
width and never executed on real decodes) and r32-CL rotates are now
routed in the runtime form map.**
**Remaining:** FSTSW AX needs an FPU status-word register; **SHL/SHR/SAR
r32 count masking has the same bug class the rotate rewiring fixed
(unmasked counts vs x86 mod-32 → `shl $33, %eax` diverges)**; r32 rotate
flag modeling (CF) and r64-CL OF; then
expand families in order — AVX → AVX2 → AVX-512 →
VNNI/AVX10 → AMX → CET/APX (AES/SHA/BMI interleaved); CI regeneration/diff
gate; documented undefined-flag behavior (AF/PF/OF-on-shift-by-zero).

### Phase 8 (solver reuse, slicing, preemption)
**Status: slicing, exact reuse, UNSAT cores, incremental contexts, interrupt
landed; slice-key reuse measured (1 hit/1 miss across two inputs). Cache
admission, preemption measurement, and the alpha-equivalence tier landed
(2026-09-24): value-aware bounded admission (count-sketch reuse scoring,
deterministic eviction, observable rejection counters — bounding at 4
entries/shard costs zero hot hits on the repeated-key workload); budget-based
cancellation measured on semiprime-factoring queries (cancelled checks return
Unknown promptly at ~27 ms overhead, never a wrong answer — and an empirical
Z3 quirk documented: a pre-armed `interrupt()` flag is consumed by API calls
before the check, so true mid-flight cancellation needs a
`solve_cancellable` in the FFI crate); alpha-equivalence implemented as a
de-Bruijn-style `AlphaKey` with a cache index and a validation mode that
always returns the exact answer while counting confirmations/contradictions
(7/0 on renamed families, zero conflation on poisoned ones) — suppression
without confirmation exists but defaults to off behind `AlphaReuseConfig`.**
**Remaining:** enable alpha suppression only after real-trace
confirmation counts accumulate; broader real-trace reuse hit-rate
measurement. **Mid-flight cancellation landed** (`solve_with_deadline`:
the watchdog arms only around `Z3_solver_check_assumptions` and retires
before model/core extraction — proven by a 12 s grind cancelling to
`Unknown` at 83 ms with the soft limit parked at 30 s; soft-limit-first
composition and post-cancellation context recovery verified; the safe
adapter routes every query through the wall-clock deadline).

### Phase 9 — optional QIHSE + KEYSTONE submodules
**Status: in-memory adapters done.**
**Remaining (all optional, Gate E-gated):** `.gitmodules` integration,
feature-gated real adapters, asynchronous batched event bridge, local
spooling fallback, persistence-disabled mode proof.

### Phase 10 — search intelligence, state merging, state economics
**Status: engine real-binary-validated.** CFG recovery (~25k blocks),
fork/merge/prune, parallel exploration, reconvergence-scheduled Veritesting,
dominators/loops, **generalized loop summarization** (concrete and
symbolic trip counts, Eq/Ne exits, straight-line multi-block bodies —
differentially proven; landed 2026-09-24, including hardening of the
concrete closed-form math to signed/unsigned flavors and width masking),
and **function summaries** (landed 2026-09-26: pure-function extraction +
template reuse keyed by callee entry and argument shape, lowered-IR and
dynamic-purity soundness gates, direct + constant-indirect call sites,
placeholder depth × width merge-cost model — differentially proven, one
build per shape with N O(1) applications).
**Remaining:** bodies with per-iteration effects (needs merge-based
composed summaries); the real multifactor merge-cost model (the trait
seam and placeholder heuristic are in); under-constrained execution;
state economics; CFG function-boundary refinement + calling conventions;
optional QUBO planner (advisory, CUDA→OpenCL→CPU ladder). Exit: merging
reduces state count on a real binary without solver-expression blowup
erasing the gain.

### Phase 11 — learned fusion retrieval
**Status: identity/constant encoders + averaging fusion (in-memory).**
**Remaining (Gate F):** specialist encoders (IR/CFG/constraint/taint/memory/
solver/findings), missing-modality masks, learned gated fusion, retrieval
precision/recall evidence.

### Phase 12 — provenance + flight recorder
**Status: tiers, governor, FlightRecorder ring done.**
**Remaining:** Tier-2 triggers, structural repetition summarization,
post-processing canonicalization/dedup, bounded async transport.

### Phase 13 — JIT (conditional)
**Status: validity contract only — correctly deferred.** Proceeds only if
Gate G profiling shows the fast interpreter remains the bottleneck.

### Phase 14 — hybrid fuzzing + environment models
**Status: `fuzz_generate` live (solve → replay → coverage); syscall table
broad; dynamic linking + symbolic argv/files/stdin done.**
**Remaining:** versioned syscall/library models with deterministic summary
contracts; testcase import/export; seed exchange; bidirectional hybrid
fuzzing; hybrid-beats-either-alone evidence.

### Phase 15 — API, scripting, packaging
**Status: Lua scripting + `angryier run` CLI landed; CLI documented
(`docs/CLI.md`, incl. the full Lua surface); gate measurements packaged
reproducibly (`scripts/gate_report.sh` → dated md+json reports with
git/rustc/CPU metadata, shellcheck-clean, per-benchmark timeouts).**
**Remaining:** stable Rust library API; reproducible release profile
(thin-LTO block proposed, lands after in-flight agents finish, then gate
numbers regenerate under it); versioned support manifests; multi-host
work-unit serialization (seam only); CLI hygiene — largely fixed
(2026-09-24): `help` lists `run` (feature-aware), strict flag parsing with
clear errors (unknown flags, missing values, bad registers/argv/find all
exit 1), honest `--find` usage, single workspace version source, refreshed
  `crates`/`status` self-reporting, x87 iclasses re-exported from
  `angryier-arch-xed-ffi` with compile-time value pinning. Final quirks
  closed 2026-09-25: `--steps` flag with CLI/Lua defaults unified through
  shared constants (256/16), repeated positionals and repeated singular
  flags exit 1, symbolic register widths flow end-to-end (64/omitted
  accepted, other widths error honestly, unknown names error).

### Production 1.0 — validation + reproducible reports
The checklist in §6; the blocking items are Gate B numbers, ISA breadth,
and reproducible correctness/performance reports.

---

## 5. Current execution order (concrete next steps)

1. **Gate B measurement pack — DONE (debug build), release rerun DONE
   (2026-09-25).** Both benchmarks landed
   (`tests/gate_b.rs`, `tests/migration_bench.rs`); release numbers in §2
   (footprints identical, forks 4.0 µs concrete / 80.9 µs symbolic,
   migration 15.5–20.2×).
2. **Concolic speed measurement — DONE (negative result).** 90k-step real
   trace, `tests/concolic_speed.rs`: ~0.9× full-symbolic, ~3.2× concrete.
   The 5–10× claim is killed as implemented; the derived work is item 4.
3. **x87 first slice — DONE at corpus level.** 39 forms, 462 hardware-oracle
   cases; runtime form-map wiring is item 5.
4. **Make the concolic fast path actually fast — round 1 DONE (2026-09-24).**
   Step cache + shadow memos: 0.9× → 1.6× over full symbolic (release,
   direct); the concrete floor itself got 4× faster; correctness green,
   one unsound micro-opt deliberately reverted. Round 2 is item 6.
5. **x87 runtime integration — DONE.** 17 iclasses → all 39 forms wired
   into `form_map.rs` (XED quirks handled), 16-bit immediate forms mapped,
   engine-vs-native tests green.
6. **Performance rounds 2–3 — DONE (2026-09-24/25).** Round 2: four of
   five profiled hot spots fixed and adopted end-to-end (register
   pending-overlay writes, `read_into`, probe-before-hash intern, sort/op
   probes). Round 3 (profile-driven, callgrind 2026-09-25): FxHash for
   the arena hash-cons and evaluator hot maps — concolic **−20%**
   (22.9 steps/ms), symbolic −8%, multiplier **1.8×**. Remaining
   profiled costs: SHA-256 dependency keys (~16%, digest-change
   decision deferred), malloc/free (~12%), and concolic-side
   short-circuits (skip shadow evaluation of blocks with no symbolic
   influence) — the last is the next lever toward the 5–10× ratio.
7. **Solver-reuse completion (Phase 8 finish) — DONE (2026-09-24).**
   Value-aware cache admission (deterministic, measured); preemption
   measured via budget cancellation (prompt `Unknown`, ~27 ms overhead;
   pre-armed interrupt consumed-before-check quirk documented); alpha-
   equivalence tier behind default-off flags with exact-answer validation
   mode (7 confirmations / 0 contradictions renamed; 0 conflation
   poisoned). Follow-ups: real-trace alpha confirmation counts before any
   suppression. The FFI follow-up landed the same day: mid-flight
   cancellation via `solve_with_deadline`, proven at 83 ms on a 12 s
   grind, wired through the safe adapter.
8. **Loop-summary generalization + function summaries (Phase 10) —
   DONE (2026-09-24 loop half; 2026-09-26 function half).** Symbolic trip
   counts, Eq/Ne exits, multi-block straight-line bodies — differentially
   proven (~14× on nested mixed loops; 303→5 steps concrete). Function
   summaries landed 2026-09-26: pure callees execute once per argument
   shape into a substituted expression template (direct and
   constant-indirect call sites; lowered-IR + dynamic-purity gates;
   depth × width placeholder cost model as the merge-cost seam).
   Per-iteration-effect bodies remain (item 7 above in the phase list).
9. **Replay-capsule integration for recorded native runs (Phase 1
   remainder) — DONE (2026-09-24).** Record → `FileReplayStore` → fresh
   load → deterministic replay matching native ground truth; fail-closed
   tamper rejection proven. Gate 0's original remainder is closed.
10. **Polish-and-publish track — round 1 DONE (2026-09-24); release
    profile applied and gate numbers regenerated under it (2026-09-25,
    `reports/gate-report-2026-09-25.*`); CLI hygiene quirks closed
    (2026-09-25).** Remaining: stable API; the Production 1.0
    validation report.
11. **Docs hygiene (this file).** ROADMAP.md is the single status source;
    update it in the same commit as any phase-status change (the
    loop-summarization commits landed after the last ROADMAP edit and
    were untracked for a day — avoid repeats).

---

## 6. Production 1.0 checklist

1. ELF64 + PE32+ loading — **done** (static, dynamic, PE32+).
2. XED decoding with explicit semantic-support manifest — **done**.
3. Production semantic coverage for declared families — **partial**
   (429 handwritten incl. 39 x87 forms executing end-to-end + generator;
   AVX* pending; oracle live).
4. Dual-mode execution — **done** (concolic + full symbolic, shared
   AngryIR, per-state promotion).
5. COW state + sparse symbolic memory — **partial** (sparse maps +
   symbolic-address policy done; page-backed COW pending).
6. Z3 + Bitwuzla support — **done** (FFI, portfolio, cache, incremental,
   cancellation).
7. Fuzzy-SAT tier — **done**.
8. Canonical identities + exact reuse — **done and measured on a two-input
   trace**; broader real-trace measurement pending.
9. Native multicore with useful physical-core scaling — **partial**
   (3.93×/4 workers concolic; Gate B pack measured in debug and release:
   2.7 KB/state concrete, 11.1 KB/state symbolic, 15.5–20.2× cold/warm
   solver migration, 52 KB contexts; both-mode scaling on real binaries
   pending).
10. NUMA-aware placement — **partial** (distance model in `StealCost`;
    pinned queue groups pending).
11. Solver affinity, timeout, preemption — **done** (timeouts,
    incremental contexts, budget-based cancellation at ~23–27 ms overhead,
    and mid-flight `solve_with_deadline` cancellation proven at 83 ms on a
    12 s grind; the adapter routes every query through the wall-clock
    deadline).
12. Search policies beating simple baselines — **partial** (merging,
    CFG-guided reconvergence, and generalized loop summaries — concrete +
    symbolic + Eq/Ne + multi-block, differentially proven — landed;
    benchmark-vs-baseline evidence pending).
13. Reproducible correctness/performance reports — **partial** (bench
    sink + `scripts/gate_report.sh` packaging GATE-A/B/C with environment
    metadata; comparison-engine harness and release-profile regeneration
    pending).
14. Environment model library — **partial but broad** (SimProcedures +
    ~30-syscall model + TLS + dynamic linking; versioned models pending).
15. Differential semantic testing — **done for the registered corpus**
    (856 hardware cases); family expansion continues under Phase 7.
16. Scripting layer — **done (embedded Lua)**.
17. A real binary end-to-end (Gate 0) — **done**, static and dynamic.

Not required for minimal Production 1.0: QIHSE/KEYSTONE submodules,
persistent similarity search, learned fusion, JIT, distributed execution,
GUI, other ISAs, CUDA/OpenCL planning.

---

## 7. Go/No-Go gates

- **Gate 0 — pipeline wiring.** Real binary loads, decodes, executes
  end-to-end with concrete replay validation. **Passed** (static musl/glibc,
  gcc -O0/-O2, dynamic ELF, PE32+).
- **Gate A — concolic correctness.** Symbolic results correct, canonical
  identities stable, both modes agree on the differential suite.
  **Correctness passed** (dual-mode differential test). **Speed: 1.8×
  full-symbolic under the release profile** (re-measured 2026-09-25 after
  the FxHash round, up from 0.9× parity at first measurement; concolic
  itself ~4.7× faster than baseline); the 5–10× target remains open —
  next levers in §5 item 6.
- **Gate B — multicore scaling.** Useful scaling on real binaries in both
  modes; report 10k-state footprint and depth-500 migration cost.
  **Measured in debug and release (2026-09-25):** solver contexts are
  memory-cheap (52 KB at depth 500) but migration costs 15.5–20.2× warm
  incremental time, and prefix sharing recovers little — state footprint
  is 2.7 KB/state concrete, 11.1 KB/state symbolic.
  Still open: both-mode scaling on real binaries.
- **Gate C — generalized reuse.** No alpha-equivalence/subsumption
  suppressing solver work until exact reuse is proven on real traces.
  Exact reuse proven; the alpha tier now exists in validation mode with
  suppression default-off — Gate C discipline maintained; suppression
  flips on only after real-trace confirmations accumulate.
- **Gate D — generated semantics.** No giant semantic DSL until the
  handwritten corpus + independent oracle demonstrate the shapes. Oracle
  live; family expansion proceeds under it.
- **Gate E — QIHSE/KEYSTONE defaults.** Measurable value without
  synchronous persistence on the hot path. Open (adapters in-memory).
- **Gate F — learned fusion influence.** Precision/recall demonstrated,
  advisory only. Open.
- **Gate G — JIT.** Only if profiling shows the fast interpreter remains
  a material wall-time component. Open (correctly deferred).
- **Gate H — second ISA.** Do not substitute AArch64/RISC-V for proving the
  Intel 64 thesis. Standing.
- **Gate I — accelerated scheduling defaults.** Deterministic CPU scheduler
  first; accelerator must net-win after all overheads. Standing.
- **Gate J — throughput claims.** Name the workload class where Angryier
  beats both angr AND SymQEMU/SymCC (proposed: vulnerability triage needing
  both coverage speed and analysis depth), or the positioning is honestly
  "angr, but Rust and multicore." **Open — the thesis gate.** Reality
  check 2026-09-24: concolic measured at ~0.9× full-symbolic — until the
  fast path is materially faster than full symbolic, the dual-mode speed
  thesis is unproven.

---

## 8. Fallbacks and rejected paths

- **Fallback A — angr SimProcedure contracts as specification reference**
  (documentation dependency, not code). Trigger: target needs a libc
  function Angryier doesn't model.
- **Fallback B — QSYM-class path policy.** Already Phase 6's EXPLORE/HUNT
  defaults.
- **Fallback C — Fuzzy-SAT tier.** Already landed (`angryier-solver-fuzzy`).
- **Fallback D — JIT via cranelift.** Phase 13 behind Gate G; `unsafe`
  isolated in `angryier-jit-ffi`.
- **Rejected: QEMU/SymQEMU integration** (C, massive unsafe surface, not a
  library; if SymQEMU-class speed is needed, build the JIT).
- **Rejected: SymCC/LLVM pass for Production 1.0** (source-only; contrary
  to the binary-only thesis).

---

## 9. Document map

| Document | Role after this merge |
|---|---|
| this file | Single source of truth: status, architecture-as-built, plan, gates |
| [Plan.md](../Plan.md) | Immutable Q9–Q54 decision baseline (unchanged) |
| [architecture/](architecture/) | Detailed design contracts — invariants, boundaries, identity/trust models. Status headers froze 2026-09-14; treat this file as authoritative for status |
| [design/decisions.md](design/decisions.md), [design/trait-boundaries.md](design/trait-boundaries.md) | Locked design decisions and Rust trait/ownership boundaries |
| [semantics/intel64.md](semantics/intel64.md), [semantics/identity.md](semantics/identity.md) | Semantic architecture and identity contracts |
| [BENCHMARKING.md](BENCHMARKING.md) | Benchmark contract |
| [status/scaffold.md](status/scaffold.md), [status/implementation-plan.md](status/implementation-plan.md) | Historical; superseded by this file |
