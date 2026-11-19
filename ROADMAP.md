# Angryier — Native Symbolic & Concolic Binary Analysis Platform Roadmap

**Version:** 1.0  
**Status:** In Active Execution  
**Mission:** Native, multi-core dual-mode symbolic (PROVE) and concolic (EXPLORE) binary analysis engine in safe Rust, delivering 147×–432× speedup over angr with zero Python interpreter overhead.

---

## Sustained exploration and ARM64 status

- [Local Lua exploration](docs/LUA_API.md#9-durable-sustained-exploration-opt-in-xed--script) can resume a pinned frontier ledger. The separate [campaign executable](docs/guides/distributed-campaigns.md) coordinates 1, 2, or 4 workers over loopback. Finishing a bounded run does not establish whole-binary exhaustion; the raw Advisor GUI PE has no verified application path.
- ARM64 concrete and symbolic runtime tests exercise synthetic instruction sequences. The Titan listing census measures static decode coverage, not execution coverage. CLI architecture selection does not establish ARM64 image-loader support. See ANG-090 below for the instruction subsets and test evidence.

## 0a. Delivered — IA-32 (PE32) user-mode execution (2026-10-31)

PE32/IA-32 images now load and execute end-to-end (previously
`load_pe_driver: Loader(InvalidMachine)`):
- Loader accepts `IMAGE_FILE_MACHINE_I386` + PE32 magic 0x10B (PE32
  optional-header layout, u32 image base, 4-byte import thunks, ordinal
  flag bit 31); mismatched machine/magic pairs rejected; PE32 images tagged
  `TargetProfileId(2)`.
- Runtime `load_pe32_user`: 4-byte IAT patching against the sub-4-GiB stub
  region, 32-bit security-cookie scan, FS/TEB model (StackBase/StackLimit
  seeded), 16 MiB stack, 32-bit entry stack image, `PE32_EXIT_HOOK`
  sentinel. Decode constructed in `XedMachineMode::Legacy32`.
- Stack-form providers width-parameterized by target profile (`stack_layout`):
  PUSH/POP r32/imm/flags, CALL rel32/indirect, RET, LEAVE, ENTER, and the
  new `PUSH_MEM32` form (0x3022).
- IR lowering: width-32 instruction-pointer bases (IA-32 absolute
  addressing) lower to the absolute displacement; width-64 stays
  RIP-relative.
- EIP operand fix: `XED_REG_EIP` maps to the instruction-pointer reference
  (was silently dropped in legacy32, corrupting call-form operand layouts).
- Tests: loader `pe32_i386_*` fixtures; runtime `tests/pe32_user.rs`
  (IAT patching, TEB fields, entry-`ret` sentinel termination); full suite
  936 passed / 0 failed across runtime, semantics-intel64, arch-xed-ffi,
  ir, loader, memory.
- Validated on MDSec Nighthawk `Implant.x86.exe`: 20000-step concolic run,
  zero failed states, 4096-block trace. `Implant.x86.dll` is an unpatched
  template (entry 0 / base 0xb000) — not standalone-executable by design.

---

## 0b. Known Defects — solver AST interning (recorded 2026-10-31)

**Defect:** `ExprArenaError::SortMismatch(Concat)` aborts symbolic evaluation at
an indexed-memory-load address expression: instruction
`4b 8b 8c fe c0 74 01 00` (`mov rcx,[r14+rdi*8+0x174c0]`) at pc `0x140007463`
(CRT helper `sub_7434`) inside MDSec Nighthawk `Implant.x64.exe`
(`Samples/Original/PE/executables/`, sha256 `a3948755…`). Reproduces
deterministically with concrete and symbolic registers on a freshly rebuilt
binary from current source (`f1276a2`); not a stale-binary artifact
(`angryier doctor` reported `mismatched-checkout-and-binary` before the
rebuild — rebuild first when triaging engine behavior).

**Behavior:** fail-closed — `angryier-expr` correctly rejects the malformed
Concat (operand widths must sum to the node width, `lib.rs` validation) and
the run reports `failed=1` with the exact pc; no unsound output, no crash.

**Suspected layer:** the lift/evaluate site that builds the effective-address
expression for SIB-indexed loads interns a `Concat` whose operand widths do
not sum (width bookkeeping, not operand order). Fix requires a minimal repro
test driving one instruction through the lift→evaluate path and auditing the
address-expression construction for width mismatches.

**Workaround (field, until fixed):** redirect the enclosing helper to a `ret`
gadget via Lua `redirects` (applied in
`Samples/Analysed/PE/executables/Implant.x64/angryier/exe_entry.lua`:
`0x140007434 → 0x140016f00`), documented as model debt in the campaign
script.

- [ ] **Fix + regression test:** minimal repro (single indexed load,
  `mov r64,[r64+r64*8+disp32]`) through lift→`SymbolicEvaluator`; assert
  `intern(Concat)` receives width-consistent operands. Wire into CI.

---

## 1. Architectural Philosophy & Delivery Rules

1. **Honest Incompleteness (REA Paradigm)**:
   - When path exploration hits a timeout, recursion depth limit, or unsupported instruction, Angryier must emit `AnalysisOutcome::Unknown` with exact remaining bounds.
   - A solver timeout or resource exhaustion must **never** be interpreted as "unreachable" or "safe".
2. **Deterministic Replay Capsules**:
   - Every candidate finding must produce a self-contained, reproducible trigger capsule (`deterministic_replay_capsule.v1`) containing initial memory/register state, solver model, and execution trace.
   - Findings require 3/3 clean-room replay verification.
3. **Safe Rust Core & FFI Isolation**:
   - `#![forbid(unsafe_code)]` enforced across all analytical core crates.
   - Native solvers (Z3, Bitwuzla) and decoders isolated behind strictly audited FFI abstraction boundaries.
4. **Knowledge Plane & QIHSE Content Addressing**:
   - All SAT/UNSAT constraint queries, intermediate state DAGs, and synthesized PoCs persist to QIHSE as content-addressed artifacts (`cas://blake3:...`).

---

## 2. Milestone Gates & Capability Roadmap

### Phase S0: Core Execution Plane & Memory Architecture
- [x] **ANG-001**: 100% safe Rust core representation (`angryier-core`, `angryier-ir`, `angryier-types`).
- [x] **ANG-002**: Copy-on-Write (COW) hierarchical memory model (`angryier-memory`): page-level copy-on-write with sparse byte maps.
- [x] **ANG-003**: Symbolic address resolution: policy-based handling of symbolic pointers (concrete concretization, range bounding, bifurcation).
- [x] **ANG-004**: Non-allocating BLAKE3-accelerated Merkle state fingerprinting (`angryier-state`).
- [x] **ANG-005**: Unified dual-mode state switching: per-state transition between concolic tracing (EXPLORE) and deep symbolic exploration (PROVE).

### Phase S1: SMT Solver Portfolio & Expression Engine
- [x] **ANG-010**: Non-recursive work-stack Z3 FFI AST engine (`angryier-solver-z3`, `angryier-solver-z3-ffi`): $O(N)$ memoization, verified at AST depth > 600 without C stack overflow.
- [x] **ANG-011**: Bitwuzla SMT solver integration (`angryier-solver-bitwuzla`) for ultra-fast bitvector and floating-point constraint queries.
- [x] **ANG-012**: Solver portfolio scheduler: concurrent race between Z3 and Bitwuzla with adaptive preemption and timeout bounds.
- [x] **ANG-013**: Alpha-equivalence solver query caching (`angryier-solver`): structural query canonicalization to avoid re-solving identical constraint systems.
- [ ] **ANG-014**: Incremental solving with solver checkpoint push/pop optimization across branch forks.

### Phase S2: Intel 64 Semantics & Hardware Differential Validation
- [x] **ANG-020**: 1,574 Intel 64 instruction forms implemented in pure software semantics (`angryier-semantics-intel64`).
- [x] **ANG-021**: Support for modern instruction extensions: AVX, AVX2, AVX-512 (EVEX masking `{k}{z}`), AVX10, AMX tile registers, APX, and BMI1/2.
- [x] **ANG-022**: Hardware differential verification: 856 integer/SSE + 462 x87 boundary cases verified against physical Intel CPU silicon.
- [ ] **ANG-023**: AArch64 (ARM64) semantics expansion: A64 instruction semantics module (`angryier-arch-arm64`) for Android native shared library symbolic execution.
  - Phase 1 landed: `angryier-arch-arm64` (safe-Rust A64 decoder + register model, 21 golden tests) and `angryier-semantics-arm64` (handwritten providers + registry, 6 smoke tests). Decoded subset: branches, PC-relative, integer ALU with NZCV, wide immediates, bitfield/extract, conditional select, MADD/MSUB, loads/stores (scaled/unscaled/register-offset/pair). FP/SIMD, LDPSW, LDR-literal, atomics, and engine wiring remain.

### Phase S3: Speculative Execution & Multicore Scheduling
- [x] **ANG-030**: **5 Speculative Execution Engines**:
  - *Speculative Forking*: Hides solver latency by concurrently stepping speculative branch paths before SAT verification completes.
  - *Speculative Constraint Batching*: Union-Find dependency-cone slicing and query deduplication.
  - *Speculative Summary Memoization*: $O(1)$ function summary application with rollback checkpoints.
  - *Pipeline Decode Lookahead*: 256-slot ring cache with static CFG fall-through prediction.
  - *Speculative Concolic Batching*: Bulk concrete block execution with taint-barrier rollback.
- [x] **ANG-031**: NUMA-aware work-stealing scheduler (`angryier-scheduler`): hierarchical steal order (Own $\to$ Same-NUMA $\to$ Cross-NUMA $\to$ Global) with `/proc/meminfo` memory throttling.
- [x] **ANG-032**: Symbolic branch steering (`angryier-execution`): post-run branch inversion, distance-to-target CFG ranking, and concrete entry-state replay.

### Phase S4: Windows Kernel Driver Modeling & BYOVD Hunting
- [x] **ANG-040**: Windows kernel environment models (`angryier-models`): `DRIVER_OBJECT`, `DEVICE_OBJECT`, `IRP`, and `IO_STACK_LOCATION`.
- [x] **ANG-041**: Symbolic `DeviceIoControl` dispatcher exploration: automatic discovery of valid IOCTL codes and buffer size constraints.
- [x] **ANG-042**: BYOVD vulnerability checkers: detection of arbitrary physical memory mapping (`MmMapIoSpace`), physical section mapping (`ZwMapViewOfSection`), and arbitrary MSR read/write.
- [x] **ANG-043**: Memory corruption bug detectors: Double Free (DF), Use-After-Free (UAF), and integer buffer overflow detection.
- [ ] **ANG-044**: Minifilter and NDIS network driver environment simulation.
- [x] **ANG-045**: **Kernel Entry-Point Contracts & State Templates (`entry_context.py`)**:
  - Initial-state contracts for `dispatch` (IRP non-NULL, valid `IO_STACK_LOCATION`, `PASSIVE_LEVEL`, concretized GS base cookie).
  - `ioctl_handler` contract: symbolic `IoControlCode` with buffer length bounds ($\le 64\,\text{KiB}$) to avoid 64-bit solver path blowup.
  - `dpc` contract: `DISPATCH_LEVEL` IRQL constraint where paged memory access triggers simulated `IRQL_NOT_LESS_OR_EQUAL` bugchecks.
  - `work_item` and `completion_routine` contracts with explicit gap reporting (`IRP.RequestorMode`, unconstrained extension state) in findings metadata.
  - **Delivered (2026-10-19)**: `bridge/entry_context.py` (schema `angryier.entry_context.v1`) — `dispatch` (incl. concretized GS base + kernel cookie), `ioctl_handler` (symbolic IoControlCode, both buffer lengths ≤ 0x10000 with declared false-negative gap), `dpc` (DISPATCH_LEVEL + bugcheck rule 0x0A), `work_item`, `completion_routine`; 16 explicit gaps surfaced as `model_debt`, fail-closed `EntryContract.validate()`. 53/53 tests in `tests/test_angryier_entry_context_kernel_models.py`. Engine-bridge wiring deferred to the ANG-072 integration pass.
- [x] **ANG-046**: **Tier-1/2/3 Kernel API SimProcedure Models & Effect Contracts (`kernel_api_models.py`)**:
  - WDK-audited structure offset table (`KERNEL_OFFSETS_V1`) for x64 `IRP` and `IO_STACK_LOCATION`.
  - Tier-1 sound primitives: `ExAllocatePoolWithTag`/`ExAllocatePool2` with OOM `NULL` return modeling; `ExFreePool` pointer poisoning for double-free/UAF detection; `KeAcquireSpinLock`/`KeReleaseSpinLock` shadow IRQL modulation; `RtlCopyMemory` symbolic bounds checking.
  - Tier-2 NTSTATUS dichotomy approximations (`ZwOpenKey`, `ZwQueryValueKey` branching on `{STATUS_SUCCESS, STATUS_OBJECT_NAME_NOT_FOUND}`).
  - Tier-3 auditable NOPs (`DbgPrint`, `RtlInitUnicodeString`) recorded in `model_provenance` so abstractions are never silent.
  - **Delivered (2026-10-19)**: `bridge/kernel_api_models.py` (schema `angryier.kernel_models.v1`) — `KERNEL_OFFSETS_V1` x64 `_IRP`/`_IO_STACK_LOCATION` layouts with per-field provenance; Tier-1 pool/spinlock/copy models (OOM `NULL`, byte-exact pointer poisoning for double-free/UAF flags, shadow IRQL modulation, symbolic `RtlCopyMemory` bounds); Tier-2 NTSTATUS dichotomies with missing-status debt; Tier-3 audited NOPs all present in `model_provenance`. Known divergence flagged for wiring-time reconciliation: native `KernelBuildIrpProcedure` writes `StackCount`/`CurrentLocation` at +0x53/+0x54 vs public WDK x64 +0x42/+0x43. 53/53 tests (shared suite above).

### Phase S5: Android JNI & Cross-Runtime Symbolic Solving
- [x] **ANG-050**: JNI native environment stubbing (`JNIEnv*`, `jobject`, `jstring`, `jbyteArray`).
- [x] **ANG-051**: Symbolic taint propagation from Android Java parameters into native C/C++ `.so` functions.
- [x] **ANG-052**: Path reachability from exported JNI entry points to native vulnerability sinks.

### Phase S6: Exploit Primitive Synthesis & Trigger Generation
- [x] **ANG-060**: Concrete model extraction: extraction of satisfying assignments (`uint64_t` registers, memory buffer bytes).
- [x] **ANG-061**: Standalone C trigger generator (`poc.c`): emit ready-to-compile exploit harnesses targeting Windows `CreateFile` + `DeviceIoControl`.
  - **Delivered (2026-10-19)**: `bridge/trigger_generator.py` (schema `angryier.trigger.v1`) — self-contained deterministic `poc.c` emission with IOCTL/buffer-size defines, hex-dumped payloads, full error checking; ingestion adapters for solver models, legacy escalation results, ANG-073 verdict witnesses, and replay capsules; unrecovered payload bytes only emit behind `emit_unknown_payload=True` as labeled placeholders; advisory banner (trigger harness, not exploitability claim); live `gcc -fsyntax-only -Wall -Wextra` check passing. 48 tests in `tests/test_angryier_trigger_generator.py`.
- [ ] **ANG-062**: Automated write-what-where exploit primitive synthesis: proving arbitrary pointer dereference write bounds.
- [ ] **ANG-063**: ROP chain constraint validation: verifying stack pivot and gadget sequence constraints via SMT.

### Phase S7: QIHSE Knowledge DAG & Tool Surface
- [x] **ANG-070**: Content-addressed persistence: push SMT queries and verification results to QIHSE DAG as `angryier.finding.v1`.
- [x] **ANG-071**: CLI dispatcher: `kp15ctl symbolic <target> --solve --steps 500 --driver`.
- [x] **ANG-072**: Native Engine Bridge & Automated Pipeline Integration (Supersedes fragmented MCP approach):
  - Expose native controls for path exploration, sink reachability solving, crash primitive verification, and triage harness generation via `AngryierBridge` and `AutomatedIntakePipeline`.
  - Full headless programmatic execution via `bridge/engine_bridge.py` and `bin/kp15_intake.py`.
- [x] **ANG-073**: **Engine-Agnostic Escalation Contract & 6-Verdict Taxonomy (`escalation_contract.py`)**:
  - Implement standardized `EscalationRequest` $\to$ `EscalationVerdict` JSONL protocol for automated escalation from static findings to symbolic reachability.
  - Strict 6-category verdict taxonomy: `FEASIBLE_VALIDATED` (witness confirmed by concrete replay), `INFEASIBLE_CLOSED` (provably closed within step/recursion bounds), `NO_WITNESS_FOUND` (budget exhausted, frontier open), `MODEL_LIMITED`, `DECODE_ERROR`, `TIMEOUT`.
  - Enforce the Never-Safe Invariant: `is_safe = False` on all non-feasible/unknown outcomes; timeouts never translate to safety.
  - **Delivered (2026-10-19)**: `bridge/escalation_contract.py` (schema `angryier.escalation.v1`) — fail-closed `validate()` (FEASIBLE requires 3/3 clean-room replay witness + concrete model; INFEASIBLE_CLOSED stays `is_safe=False` as bounds-relative), JSONL stream pipeline, and `classify_legacy_escalation()` adapter that honestly downgrades legacy "SAT" to `NO_WITNESS_FOUND` with debt. 47 tests in `tests/test_angryier_escalation_contract.py`.

### Phase S8: angr-Grade OS Environment & SimProcedure Library
- [x] **ANG-080**: POSIX Libc SimProcedure Suite (250+ APIs):
  - Memory management: `malloc`, `calloc`, `realloc`, `free` with symbolic heap chunk tracking and double-free/UAF assertions.
  - String and memory routines: `strlen`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `memcpy`, `memmove`, `memset`, `sprintf`, `snprintf`.
  - File I/O & descriptors: `open`, `read`, `write`, `close`, `lseek`, `stat`, `fstat` with symbolic file content backing.
  - Network sockets: `socket`, `bind`, `connect`, `send`, `recv`, `select`, `poll`.
  - Concurrency: `pthread_create`, `pthread_mutex_lock`, `pthread_mutex_unlock`.
  - **Delivered (verified 2026-10-19)**: `crates/angryier-models/src/posix/` (`heap.rs` tracked symbolic heap with double-free/invalid-free/UAF assertions, `string.rs`, `io.rs` virtual descriptor table and socket models, `process.rs`, `mod.rs`). Cross-reference: master `ROADMAP.md` Phase 16, **KP15-150** (delivery claimed with these paths).
- [x] **ANG-081**: Win32 Userland API Environment Simulation:
  - Memory & execution: `VirtualAlloc`, `VirtualProtect`, `HeapCreate`, `HeapAlloc`, `CreateThread`.
  - File & device: `CreateFileA/W`, `ReadFile`, `WriteFile`, `DeviceIoControl`.
  - Registry: `RegOpenKeyExA/W`, `RegQueryValueExA/W`.
  - Dynamic linking: `LoadLibraryA/W`, `GetProcAddress`.
  - **Delivered (verified 2026-10-19)**: `crates/angryier-models/src/win32/` (`memory.rs` virtual memory/heap manager, `file.rs` handle table and file subsystem, `device.rs` `DeviceIoControl` IPC, `registry.rs` registry hive simulation, `module.rs` dynamic loading, `system.rs` system/thread/synchronization, `mod.rs`). Cross-reference: master `ROADMAP.md` Phase 16, **KP15-151** (delivery claimed with these paths).

### Phase S9: Multi-Architecture Symbolic Execution
- [ ] **ANG-090**: AArch64 (ARM64) Symbolic Execution Engine:
  - Progress: Phase 1 (concrete path) and Phase 2 (symbolic path) landed — `Runtime::new_arm64`, arch-aware register seeding (PC/SP/NZCV), CLI `--arch arm64`, ELF image profile re-stamp for AArch64, and two end-to-end tests: `tests/arm64_concrete.rs` (movz/add/sub/subs NZCV, cbnz loop, str/ldr round-trip, ret) and `tests/arm64_symbolic.rs` (symbolic x1 through `subs` flags into a `b.ne` fork — two states, distinct constraints, both PCs enumerated). A64 FCVT/FCSEL landed (llvm-mc opcodes: FCVT d0,s1=0x8B0, fcvt s0,d1=0x890, fcsel s=0x883, fcsel d=0x887 at bits[21:10]): FCVT emits FloatingOp::Convert (the interpreter's FConvert converts width via read_float/write_float), FCSEL reuses Select with the FP type and the NZCV condition evaluator (condition_value made pub(crate)). e2e proves width conversion and both EQ/NE selections. Census: 99.0% (2,806,689/2,834,483); 171 tests, 0 warnings. At that baseline, FCVTZS/FCVTZU (float->int primitives) and the SIMD long tail remained; see the verified FCVTZ increment below. A64 FMOV-immediate landed (VFPExpandImm): the 8-bit immediate expands as value = (-1)^a * 2^(immb[2:1] - 3 + 4*(1 - immh[0])) * (16 + efgh)/16 with a = imm8[7] at bits[20:13], efgh = imm8[3:0]; the S/D selector is immh[3:1] (0b010/0b110), and the opcode gate bits[15:10]==0b000100 separates FMOV-imm from FCVT (0b11000x) and FCSEL (0b000011) which share bits[21:19]==0b101. Verified against a 32-value llvm-mc sweep. Census: 99.0% (2,806,566/2,834,483); 169 tests, 0 warnings. decode_fp.rs was rewritten cleanly (three-stage dispatch: FMOV gen<->FP, scalar-arithmetic residues, FMOV-imm) after surgical edits accumulated cruft. Remaining: FCVT/FCSEL, SIMD long tail (sshll/xtn/dup/ins/ext), and the ~28k long-tail spread. A64 SIMD wave landed (llvm-mc cross-verified): lane-wise integer (ADD/SUB/AND/ORR/EOR/MOV v16b.8h.4s.2d) and float (FADD/FSUB/FMUL/FDIV v2s.4s.2d) arithmetic via the existing VecLane*/VecLaneF* IR primitives — decode is residue-based (OP_MASK = ~(Rm|Rn|Rd)), providers emit SemanticOp::Vector(LaneWise/LaneWiseFloat), and the concrete interpreter executes lane-wise f32/f64 math. Dispatch-order gotcha fixed: the SIMD residue matcher must run BEFORE the broad FP-pair gate (bits[29:27]=0b101 shares 0x6E-class words) and must not `return None` from inside the match (it killed every later group, including LDAR/STLR). e2e test proves fadd v3.4s on IEEE patterns. Census: 99.0% (2,805,931/2,834,483); 168 tests, 0 warnings. Remaining: FMOV-immediate (VFPExpandImm, 0x1E residual), FCVT/FCSEL, remaining SIMD (sshll/xtn/dup/ins/ext ~1.4k), and the long tail. A64 second wave landed (llvm-mc cross-verified): MSUB fix (bit15 discriminator), pre/post-index B/H loads/stores, STP/LDP Q pairs (128-bit, stride 16), LDAR/LDARB/LDARH/LDARW/LDARX + STLR family (bits[21:10]=0x7FF, bit22 = load selector, size at bits[31:30] incl. 0b10=W — ordering is documented debt: plain load/store semantics), FMOV general<->FP bit moves (W<->S in 0x1E, X<->D in 0x9E; 12-bit opcodes 0x980/0x9C0). Census: 98.9% (2,803,953/2,834,483); 166 tests, 0 warnings. Remaining: SIMD arithmetic (0x4E/0x0E/0x4C/0xCE/0x5E, ~5k), FMOV-immediate (VFPExpandImm family), FCVT/FCSEL. A64 FP/SIMD-memory increment landed (llvm-mc cross-verified): scalar FP arithmetic (FADD/FSUB/FMUL/FDIV/FNEG/FSQRT/FABS/FCMP S+D) with the IR FAdd/FSub/FMul/FDiv/FSqrt/FNeg/FAbs/FCompareFlags primitives executing concretely and as symbolic float-debt, FP/SIMD loads and stores (LDR/STR S/D/Q scaled, LDUR/STUR, register-offset, LDR literal, LDP/STP S/D), and the variable-shift family (LSLV/LSRV/ASRV/RORV) with variable-amount semantics. Titan census: 97.3% -> 98.7% (2,797,608/2,834,483). Remaining: FCVT/FMOV-imm/FCSEL, SIMD arithmetic, FCMP NaN corner (documented debt: NaN yields Z=1,C=1 vs ARM Z=0,C=1,V=1). A64 integer-core completeness pass landed (llvm-mc cross-verified encodings): pre/post-indexed LDR/STR, ADC/ADCS/SBC/SBCS with NZCV carry semantics, CCMN/CCMP, UDIV/SDIV, UMULL/SMULL/UMADDL/UMSUBL/SMADDL/SMSUBL, CSEL/CSINC/CSINV/CSNEG incl. CSET, LDURSB/LDURSH/LDURSW, LDPSW. Titan decode census: 90.9% -> 97.3% of 2,834,483 instructions (census tool: crates/angryier-arch-arm64/examples/a64_census.rs). Remaining classes: variable shifts (LSLV/LSRV/ASRV/RORV), scalar FP, SIMD. Solver-assisted path solving is landed for A64 forks: `tests/arm64_symbolic.rs::arm64_symbolic_fork_solves_path_models` runs Z3 over both fork paths (both SAT; the fall-through model pins x1 == 3, the taken path satisfies x1 != 3). FP/SIMD semantics remain.
  - **FCVTZ increment (verified 2026-11-15)**: scalar `FCVTZS`/`FCVTZU` now cover all eight S/D-to-W/X signed/unsigned forms. `FToIntSigned`/`FToIntUnsigned` lower to destination-width-correct truncation toward zero and saturation (NaN → zero, infinities/out-of-range inputs → the appropriate bound); W writes zero-extend X, and WZR/XZR destinations discard the result without touching SP. Concrete execution and constant symbolic/concolic folding share the same conversion. Nonconstant symbolic inputs, including concrete-seeded symbols, yield an unconstrained result with explicit conversion debt, not a floating-point solver proof. FPCR controls, FPSR exceptions/traps, FP16, fixed-point scaling and other rounding modes remain unmodeled.
    - Exact FCVTZ masks reject unsupported precision/reserved fields; FCVT S↔D validates both precisions. FCSEL masks now leave Rm/condition variable, and its provider handles AL/NV as always-true. Decode tests sweep all FCVTZ Rn/Rd combinations and all FCSEL conditions/Rm values; synthetic runtime tests cover all eight conversions with dirty X parents and boundary inputs, plus both FCSEL precisions across all 16 conditions × 16 NZCV values. This is not a whole-decoder reserved-encoding audit.
    - Validation: 291 tests passed across `angryier-arch-arm64`, `angryier-semantics-arm64`, `angryier-ir`, `angryier-execution` and `angryier-runtime` with default features (one unrelated doctest ignored); workspace `cargo check` passed. Existing warnings in other runtime tests/generated tables remain. Rebuilt static Titan listing census: **2,807,561 / 2,834,483 decoded (99.0502%)**, **26,922 unsupported**, zero truncated; net +872 decoded from the preceding FCVT/FCSEL baseline. This measures decoder acceptance, not semantic correctness or code/data classification. Titan was not executed or loaded into the runtime.
  - **FMOV-immediate correction and evidence-aware census (verified 2026-11-15)**: replaced the sample-derived gate, which incorrectly fixed immediate bits and rejected negative constants/most fractions, with architectural mask/value `0xFFA01FE0 / 0x1E201000`. Expansion is now bit-exact `VFPExpandImm`, with reserved sf/type/Rn rejection. Tests cover all 256 immediate patterns × S/D × 32 destinations (16,384 positive decodes), fixed-field mutations, and 512 synthetic concrete executions checking the entire dirty 128-bit parent; an independent LLVM 19 oracle agreed with the positive encodings and fixed-field exclusions. FP16/vector-immediate forms remain outside this increment.
    - `a64_census` retains raw totals and adds optional FDE PC-range code candidates and explicit analyst data ranges, with separate accepted/rejected named/undefined/directive buckets and candidate/unclassified mnemonic histograms. Metadata is evidence, not a reachability proof; no-FDE words and suspicious random-looking blocks stay unclassified, not automatically data. Read errors and malformed/overlapping data annotations fail rather than silently truncating results. The manually byte-verified, sample-SHA-pinned fixture `docs/status/titan-census-data-ranges.tsv` marks only the 72-byte attribution string/terminator/padding at VA `[0xfe8360, 0xfe83a8)`; the tool does not authenticate annotation files or automatically check that hash.
    - Rebuilt static Titan result: raw **2,807,895 / 2,834,483 accepted (99.0620%)**, **26,588 rejected**, zero truncated (net +334 accepted versus FCVTZ). With saved FDE ranges and the explicit data fixture: code candidates **2,782,523 words / 2,663 rejected** (99.9043% acceptance); known data **18 words / 9 rejected**; unclassified **51,942 words / 23,916 rejected**. Candidate refusals start with DUP 762, SCVTF 446, lane-MOV 131, UCVTF 111 and FCCMP 99. Unwind-free assembly functions may still be real code, and even known data can be accepted by the decoder; none of these ratios proves semantic correctness. No Titan execution/runtime loading.
    - Validation: 294 tests across the five relevant crates plus 7 explicit census-example tests passed with default features; one unrelated doctest remains ignored and existing runtime warnings remain. Workspace check, crate documentation build and scoped formatter/whitespace checks passed. Other instruction-family expansion is deferred to the evidence-prioritized backlog.
  - **DUP + SCVTF increment (verified 2026-11-15)**: added vector-element/GPR DUP broadcasts and scalar-element copies (including MOV aliases), using existing typed Extract/Concat operations. All B/H/S/D lanes, 64/128-bit vector destinations, high source lanes, in-place aliases and V31 are covered; Q=0/D and zero/size-4 selectors are excluded. GPR `imm5` bits above the lowest set bit are architecturally ignored, so noncanonical aliases are accepted too. GP ZR sources produce zero without reading the mutable backing slot, and all narrow FP results clear the remainder of the 128-bit parent.
    - Non-fixed-point SCVTF now covers W/X→S/D (four forms), scalar integer-bit S/D sources, and vectors 2S/4S/2D. New `FloatingOp::FromIntSigned` uses additive stable tag 19; `FFromIntSigned` casts directly to the destination precision, avoiding i64→f64→f32 double rounding. Constant symbolic/concolic folding shares the concrete helper; genuinely symbolic inputs, even when seeded, retain explicit conversion debt in both evaluators. This is default RNE only: FPCR alternative rounding, FPSR/exception effects, unsigned/fixed-point/FP16 variants and full symbolic FP remain outside scope. New provider registrations are appended after all previous groups, with a regression test preserving old receipt IDs and checking all 15 new form/rule identities for collisions.
    - Tests cover **158,720 valid encoding/register combinations**, family-boundary exclusions, **430 synthetic runtime cases** over full parent registers, and an integer-only RNE oracle over width boundaries and 4,096 pseudorandom inputs in all four scalar source/result width combinations. The discriminating i64 value `0x4000004000000001` converts directly to f32 bits `0x5e800001`; a staged f64 cast rounds differently. Validation: **314 tests across six relevant crates plus 7 census-example tests** passed with default features; one unrelated doctest ignored, existing runtime warnings remain. Workspace check, crate documentation and scoped formatter/whitespace checks passed.
    - Static evidence-aware Titan census: raw **2,809,163 / 2,834,483 accepted (99.1067%)**, **25,320 rejected**, zero truncated; net **+1,268** accepted. FDE candidates: **2,781,101 / 2,782,523 accepted**, **1,422 rejected** (99.9489%; 1,241 fewer refusals, including 33 scalar-copy MOV aliases). Known-data bucket remains **18 words / 9 rejected**; unclassified **51,942 words / 23,889 rejected**. No DUP/SCVTF refusals remain in the FDE-backed listing bucket for this sample; this is not a claim of complete ISA coverage or execution correctness. Next candidate backlog starts with UCVTF 111, FCCMP 99, remaining lane-MOV 98 and CNT 78. Titan was only read statically, never executed or loaded into the runtime.
  - A64 instruction semantics module with 64-bit general purpose registers (`X0..X30`), zero register (`XZR`), and stack pointer (`SP`).
  - Condition code evaluation (`EQ`, `NE`, `CS`, `CC`, `MI`, `PL`, `VS`, `VC`, `HI`, `LS`, `GE`, `LT`, `GT`, `LE`).
  - Link register `LR` return address tracking and indirect branch verification (`BLR Xn`).
- [ ] **ANG-091**: RISC-V (RV64GC) Symbolic Execution Engine:
  - Base integer instruction bitvector modeling (`ADDI`, `SLTI`, `ANDI`, `ORI`, `XORI`).
  - Compressed instruction decoding and execution.

### Phase S10: Autonomous Exploit Primitive Synthesis & Proofs
- [ ] **ANG-100**: Automated Write-What-Where Proof Engine:
  - Prove arbitrary write bounds: verify if solver can satisfy constraints where destination address and payload value are simultaneously attacker-controlled.
- [ ] **ANG-101**: Automated ROP Chain Synthesizer:
  - Gadget harvesting from target binary and loaded shared libraries (`.so` / `.dll`).
  - SMT constraint solving for stack pivot, argument placement in registers (`RDI`, `RSI`, `RDX` / `RCX`, `RDX`, `R8`, `R9`), and syscall/API dispatch.
- [ ] **ANG-102**: Verified Standalone Exploit Emission:
  - Generate standalone, ready-to-compile C exploit code (`exploit_poc.c`) with socket/device trigger and memory payload.

### Phase S11: VM-Aware Analysis, VPC Candidate Identification & Fixpoint MBA Deobfuscation
- [x] **ANG-110**: Multi-Shape Indirect Jump Table Resolver (`angryier-cfg`):
  - Multi-shape jump table resolution (indexed `[base+idx*scale+disp]` and PIE `lea; mov; add; jmp`) with predecessor-bound tracking across block splits (`cmp idx, imm; ja default; jmp table[idx]`).
  - Element-size verification (4/8 bytes), relative table and jump-end relocation candidates, and fail-closed whole-table verification (22 tests).
- [x] **ANG-111**: Themida Dispatch Classification (`angryier-cfg/themida`):
  - Data-driven classification informed by 75M-instruction census of `.themida`/`.boot` (`ContextTable`, `Indexed`, `RipSlot`, `RegisterRaw`).
  - Backward base-register provenance walk tracking `Constant`, `ContextRegister`, `PoppedFromStack`, `DerivedFrom`, and `Clobbered` (7 tests).
- [x] **ANG-112**: PUSHAN-style VPC Candidate Identification (`angryier-cfg/vpc`):
  - VPC candidate identification (arXiv 2603.18355, Themida-Research `VM_CONTEXT` randomized offsets) with 4 heuristics (dispatch read, table load, stable-VPC sibling tracking, VMProtect volatile register rotation) plus plain-switch negative control (5 tests).
- [x] **ANG-113**: Fixpoint MBA Deobfuscation Expression Simplifier (`angryier-expr/deobf`):
  - Fixpoint MBA simplifier over hash-consed expression DAGs: boolean-arithmetic reductions (`(x|y) + (x&y) = x+y`, `(x|y) - (x&y) = x^y`, `x + ~x = -1`, `x - x = 0`), double-negation elimination, `not(x) = -1 - x` strength reduction, constant XOR chains, and extension compositions (21 tests).
- [x] **ANG-114**: Runtime & Memory Engine Extensions:
  - `load_mem` bulk memory loads, `memory_dump_out` emulated memory export, exit state telemetry (`rax_exit`, `exit_pc`, `exit_kind`), `JumpIndirect` ret-form ground truth recovery, and non-executable indirect call return-0 model with debt recording.
- [x] **ANG-115**: XED Iform Metadata Preservation:
  - Preserved source-level XED iform metadata across the native bridge (`angryier-arch-xed-ffi`, `angryier-decode-xed`).
- [x] **ANG-116**: Opaque Predicate & Overlapping Junk-Code Pruner (`angryier-cfg/opaque`):
  - Invariant algebraic predicate detection: parity product $x \cdot (x \pm 1) \equiv 0 \pmod 2$, domain bounds $x^2 \ge 0$, bitwise ordering $(x \mid y) \ge (x \ \& \ y)$, identity comparisons ($x \oplus x = 0$, $cmp\ r, r$), MBA double-negation simplifications, and context register invariants (`[rsi + disp]`).
  - Overlapping junk-code stripper: detects and neutralizes mid-instruction `0xE8` (call over junk) and `0xEB 0xFF` (overlapping jump to target + 1).
  - Graph transformations: `EliminateDeadBranch`, `StraightenBlocks`, `NeutralizeJunkOverlap` with true-negative dynamic branch preservation (10 tests).

### Phase S12: Go Binary Metadata Recovery & Source-Backed Runtime Tracing

**Trigger / user case (2026-10-20):** Tracing feature-flag routing inside a stripped Go language-server executable required an external `pclntab` parser despite Angryier already having ELF loading, bounded CFG recovery, and source-backed xrefs. Goal: make Go binaries first-class static-analysis targets, integrated with the existing native Rust pipeline rather than bolting on another tracer. **Status: planned, not implemented. Execution deferred to the tail of the program (owner direction 2026-10-20): scheduled after the exploit-synthesis, multi-arch, and engine-integration lanes; see master ROADMAP §1 next-up order.**

- [ ] **ANG-120 — Native Go image identification and versioned metadata discovery** (`angryier-loader`):
  - Detect Go binaries in ELF, PE and Mach-O when supported by the underlying image loader; report actual loader limitations instead of assuming all three formats work.
  - Extract and validate `.go.buildinfo` / Go build information, compiler version, module path, dependency/module versions, build settings and build IDs when present.
  - Locate `gopclntab` / `pclntab` using section metadata and structurally validated, bounded fallbacks for stripped or sectionless images; locate/associate `moduledata` only when evidence permits. Handle PIE/image base/load-bias translation and file-offset-versus-VA conversions explicitly.
  - Use version-specific schemas and tested magic/layout variants; unsupported Go versions and malformed structures return typed `UnsupportedVersion` / `ParseError` with partial evidence, never guessed names or addresses. No unbounded scans, allocations, offsets or pointer arithmetic.

- [ ] **ANG-121 — Recover the Go function and source map** (`angryier-loader` with reusable metadata view):
  - Parse function entry PCs, function names, packages, boundaries, `pcfile`/`pcln` source mappings and inline-call metadata where validated for the detected version; normalize recovered symbols into a typed function index **without treating them as ELF `.symtab` entries**.
  - Detect Go ABI wrappers, methods, closures, compiler-generated functions and runtime functions; mark uncertain entries and overlapping/invalid ranges.
  - Work on statically linked, stripped binaries with no `.symtab`; compare results against trusted Go toolchain outputs on unstripped fixtures, and verify stripped/unstripped entry-PC parity.

- [ ] **ANG-122 — Go-aware whole-program call graph and xrefs** (`angryier-cfg` / `xrefs`):
  - Seed bounded CFG recovery at recovered Go function starts; resolve direct calls and return caller/callee lists with instruction-address provenance.
  - Add evidence-carrying references from strings, constant addresses and metadata to functions and source lines. Track package boundaries and link-time dead-code elimination without inventing missing callers.
  - Represent interface/itab dispatch, function values, method wrappers, closures, reflection, plugin/dynamic loading, and goroutine creation as separately classified *possible* edges. Promote an indirect edge to *resolved* only after concrete, trace, or sound static evidence; preserve `Unresolved` for unknown dispatch.
  - Keep existing `XrefIndex` semantics intact: metadata edges and inferred dynamic targets must **not** be misrepresented as source-backed direct calls.

- [ ] **ANG-123 — Go runtime/ABI-aware analysis bridge** (`angryier-runtime` / `angryier-execution`):
  - Recognize supported Go internal/cross-call ABI variants, register/stack parameter placement, compiler-generated stack-growth checks, goroutine scheduling, panic/defer/recover, and common runtime helpers.
  - Model or summarize these constructs only when contracts are defensible. Mark unsupported runtime versions, architectures and indirect concurrency behavior as `model_debt` / `AnalysisOutcome::Unknown`; never infer execution reachability from static call-graph connectivity alone.
  - First delivery is reliable x86-64 static tracing. AArch64 metadata parsing can be independent, but executable semantics remain gated on ANG-023 / ANG-090.

- [ ] **ANG-124 — Generic library initialization, value-flow and feature-flag tracing**:
  - Trace package `init` functions and call sites through client creation/configuration, flag reads and consumers, with bounded interprocedural backward/forward slicing across arguments, return values, globals, interfaces and wrapper functions.
  - Provide library-neutral call/constant/name matching, with `github.com/Unleash/unleash-client-go/v4` as a regression fixture: identify initialization, flag evaluation, key/default/fallback flows and conditional consumers.
  - Keep *distinct instances and trust domains* distinct (e.g. an extension stub/null client versus the language server's embedded Go client); do not conflate identical flag strings with shared runtime state or assume a flag was enabled.
  - Produce an evidence chain of file offset/VA -> function/package -> call/data xref -> flag consumer/branch, with per-edge `Direct | Inferred | Unresolved` provenance and explicit trace gaps.

- [ ] **ANG-125 — Native CLI and machine-readable results** (`angryier-cli`):
  - Planned read-only commands: `angryier go info <binary>`, `angryier go funcs <binary> [--match PATTERN]`, `angryier go callers <binary> <function>`, and `angryier go trace <binary> --match unleash [--format json]`. Names are proposed API, not presently available commands.
  - Emit deterministic JSONL/JSON records (schema `angryier.go_trace.v1`) with compiler/build provenance, module identity, function PC/name, exact xrefs, discovery method, confidence/evidence type, unsupported gaps and truncation/timeout bounds.
  - Integrate stable artifacts with existing QIHSE content addressing and KEYSTONE indexing; retain original image hash and source-backed address evidence. No claim of proven feature-flag behavior without validated execution.

- [ ] **ANG-126 — Differential fixtures, safety gates and acceptance tests**:
  - Create hermetic x86-64 Go samples with pinned toolchain versions covering multiple supported metadata layouts, ELF stripped/unstripped and PIE/non-PIE; add PE/Mach-O only once loader support is verified. Include an interface-call negative control, inlined function, method wrapper, closure, goroutine, and feature-flag consumer.
  - Compare function names/start PCs/source maps against `go tool nm` / `go tool objdump` where available and known symbols on stripped counterparts; diff direct-call evidence against decoded ground truth. Require zero invented direct edges on negative controls.
  - Fuzz malformed/truncated `pclntab`, forged magic/version, corrupted varints/offsets, huge claimed counts and overlapping function ranges. Hard bounds on memory, scan time and recursion; no panics or unsafe parser code.
  - **Delivery gate:** from a stripped Go language-server fixture, locate the embedded Unleash client, report its initialization and flag-evaluation call sites, return all statically supported consumer chains, and explicitly label every unresolved interface/data-flow gap. Reproducible output with identical hashes across runs.

**Delivery order:** ANG-120 -> ANG-121 -> ANG-122 -> ANG-125 (useful static tracer) -> ANG-123/124 (runtime-aware slicing) -> ANG-126 final release gate. A minimal read-only tracing workflow should not block on full Go runtime symbolic modeling. Cross-reference: Phase S0/S3/S7 loader, CFG, source-backed xref, execution and knowledge-plane contracts.

- [ ] **ANG-127 — Concolic routing pre-assessment for branch-free crypto targets**:
  - Field lesson (2026-10-30, bla-crackme v5.1): the decisive targets were straight-line,
    branch-free 32-bit sponge chains (48 rounds × 4 op calls, no data-dependent branches —
    lane selection was arithmetic, not control flow). Concolic execution adds taint + formula
    collection on such code but nothing else: the constraint system is identical to direct
    SMT/bit-blast, and the solve difficulty is decided by the encoding, not the engine.
    Routing rule: detect branch-free straight-line loops over arithmetic mixing → route to
    SMT/bit-blast directly with the METHRA MTR-151 encoding playbook (constant-lane rewrite,
    constant-rotation selects, no symbolic barrel shifters), and only invoke concolic when
    genuine input-dependent control flow exists. Unconstrained preimage search on XOR/adder-
    heavy unique-solution chains starves CDCL — report intractability instead of spinning
    (field: >200 s to `unknown` on a 24-round chain, and a 5-min single-round encode with
    symbolic rotations).
