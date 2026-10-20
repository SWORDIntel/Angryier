# Angryier — Native Symbolic & Concolic Binary Analysis Platform Roadmap

**Version:** 1.0  
**Status:** In Active Execution  
**Mission:** Native, multi-core dual-mode symbolic (PROVE) and concolic (EXPLORE) binary analysis engine in safe Rust, delivering 147×–432× speedup over angr with zero Python interpreter overhead.

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

**Trigger / user case (2026-10-20):** Tracing feature-flag routing inside a stripped Go language-server executable required an external `pclntab` parser despite Angryier already having ELF loading, bounded CFG recovery, and source-backed xrefs. Goal: make Go binaries first-class static-analysis targets, integrated with the existing native Rust pipeline rather than bolting on another tracer. **Status: planned, not implemented.**

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
