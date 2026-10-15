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

### Phase S5: Android JNI & Cross-Runtime Symbolic Solving
- [x] **ANG-050**: JNI native environment stubbing (`JNIEnv*`, `jobject`, `jstring`, `jbyteArray`).
- [x] **ANG-051**: Symbolic taint propagation from Android Java parameters into native C/C++ `.so` functions.
- [x] **ANG-052**: Path reachability from exported JNI entry points to native vulnerability sinks.

### Phase S6: Exploit Primitive Synthesis & Trigger Generation
- [x] **ANG-060**: Concrete model extraction: extraction of satisfying assignments (`uint64_t` registers, memory buffer bytes).
- [ ] **ANG-061**: Standalone C trigger generator (`poc.c`): emit ready-to-compile exploit harnesses targeting Windows `CreateFile` + `DeviceIoControl`.
- [ ] **ANG-062**: Automated write-what-where exploit primitive synthesis: proving arbitrary pointer dereference write bounds.
- [ ] **ANG-063**: ROP chain constraint validation: verifying stack pivot and gadget sequence constraints via SMT.

### Phase S7: QIHSE Knowledge DAG & Tool Surface
- [x] **ANG-070**: Content-addressed persistence: push SMT queries and verification results to QIHSE DAG as `angryier.finding.v1`.
- [x] **ANG-071**: CLI dispatcher: `kp15ctl symbolic <target> --solve --steps 500 --driver`.
- [x] **ANG-072**: Native Engine Bridge & Automated Pipeline Integration (Supersedes fragmented MCP approach):
  - Expose native controls for path exploration, sink reachability solving, crash primitive verification, and triage harness generation via `AngryierBridge` and `AutomatedIntakePipeline`.
  - Full headless programmatic execution via `bridge/engine_bridge.py` and `bin/kp15_intake.py`.

### Phase S8: angr-Grade OS Environment & SimProcedure Library
- [ ] **ANG-080**: POSIX Libc SimProcedure Suite (250+ APIs):
  - Memory management: `malloc`, `calloc`, `realloc`, `free` with symbolic heap chunk tracking and double-free/UAF assertions.
  - String and memory routines: `strlen`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `memcpy`, `memmove`, `memset`, `sprintf`, `snprintf`.
  - File I/O & descriptors: `open`, `read`, `write`, `close`, `lseek`, `stat`, `fstat` with symbolic file content backing.
  - Network sockets: `socket`, `bind`, `connect`, `send`, `recv`, `select`, `poll`.
  - Concurrency: `pthread_create`, `pthread_mutex_lock`, `pthread_mutex_unlock`.
- [ ] **ANG-081**: Win32 Userland API Environment Simulation:
  - Memory & execution: `VirtualAlloc`, `VirtualProtect`, `HeapCreate`, `HeapAlloc`, `CreateThread`.
  - File & device: `CreateFileA/W`, `ReadFile`, `WriteFile`, `DeviceIoControl`.
  - Registry: `RegOpenKeyExA/W`, `RegQueryValueExA/W`.
  - Dynamic linking: `LoadLibraryA/W`, `GetProcAddress`.

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

