# Implementation Plan

> **Status:** Architecture frozen. Phases 0–3 and Phase 5 foundations are implemented. Phase 4 (handwritten semantic corpus) is partially implemented — 251 forms now registered covering integer arithmetic, flags, shifts, comparison, control flow, immediate operands, CL shifts, unary ops, conditional branches, memory load/store, multiply/divide, rotates, stack push/pop, LEA, XCHG/TEST/XADD, partial writes, MOVZX/MOVSX, CMOVcc, BT/BTS/BTR/BTC, flag manipulation (CLC/STC/CMC), SETcc, ADC/SBB, sign extension (CBW/CWDE/CDQE/CWD/CDQ), CMPXCHG, PUSH imm, CALL/RET, additional conditional branches (JLE/JG/JA/JB/JBE/JAE), 32-bit arithmetic, additional CMOVcc/SETcc/branches, BSWAP, bit-scan/popcount (BSF/BSR/POPCNT/TZCNT/LZCNT), 32-bit shifts/rotates, additional memory/immediate forms, 32-bit multiply/divide, NOP variants, HLT/UD2, SSE scalar float (ADDSS/SD, SUBSS/SD, MULSS/SD, DIVSS/SD, SQRTSS/SD), SSE packed float (ADDPS/PD, SUBPS/PD, MULPS/PD, DIVPS/PD), SSE2 packed integer (PADDB/W/D/Q, PSUBB/W/D/Q, PMULLW/D, PAND/POR/PXOR), SSE2 packed shifts (PSLLW/D/Q, PSRLW/D/Q, PSRAW/D with imm8), SSE2 packed compares (PCMPEQB/W/D, PCMPGTB/W/D), SSE4 packed min/max (PMAXSB/W/D, PMAXUB/W/D, PMINSB/W/D, PMINUB/W/D), SSE2 packed multiply high (PMULHW, PMULHUW). Phase 4b IR primitives added: rotate, popcount, bit-scan, float arithmetic (f32/f64), vector lane-wise integer, float, shift, mask comparison, min/max, and multiply-high ops. All 251 forms seal successfully; 64-bit-executable forms, bit-scan/popcount, SSE float, SSE2 packed integer, SSE2 packed shifts, SSE2 packed compares, SSE4 packed min/max, and SSE2 packed multiply high verified end-to-end through concrete execution. Phase 6 foundations (replay engine, WAL, provenance store), Phase 7 foundations (taint engine), Phase 9 foundations (knowledge store, QIHSE/KEYSTONE adapters, fusion model, semantic compiler), Phase 10 foundations (work-stealing scheduler, distribution codec), Phase 11 foundations (environment models, telemetry, benchmark sink, plugin registry, image loader, fuzz bridge), Phase 12 foundations (QIHSE/KEYSTONE in-memory adapters), Phase 13 foundations (fuzz bridge), Phase 14 foundations (fusion model), and Phase 16 foundations (work codec) are also partially implemented in-memory. Phase 8 (native solver backends) and Phases 13–16 native integrations remain scaffolded.

`Plan.md` is the operational architectural baseline. This document defines implementation order and validation gates without weakening or reinterpreting any locked architectural decision.

The implementation sequence begins with foundational Execution Plane data structures, immediately followed by the Intel XED decode boundary. The rationale is simple: the decoder must target stable internal contracts rather than accidentally define them.

---

## Implementation Doctrine

1. Correctness contracts before optimization.
2. Stable internal identities before external adapters.
3. Deterministic single-thread behavior before multicore scheduling.
4. Concrete execution before symbolic promotion.
5. Exact cache validity before cross-run reuse.
6. Tier-1 provenance before deep tracing.
7. JIT only after profiling demonstrates a material need.
8. Bidirectional fuzzing only after deterministic replay and cache-validity invariants are hardened.
9. QIHSE/KEYSTONE integration must never become a synchronous execution dependency.
10. Every performance claim requires a matching correctness/replay result.

---

# Phase 0 — Build and Validation Skeleton — DONE

Create the workspace structure, CI, lints, test categories, benchmark schema, deterministic test seed handling, and feature gates.

Required outputs:

- workspace crate graph;
- `cargo fmt`, `clippy`, unit/integration tests;
- sanitizer/Miri-compatible test targets where applicable;
- deterministic test-seed plumbing;
- benchmark result schema;
- architecture invariant test harness;
- no hidden panics/unwraps in core crates.

**Exit gate:** CI can validate contract crates and deterministic test fixtures before engine behavior exists. **Passed.**

---

# Phase 1 — Foundational Execution Plane Data Structures — DONE

Implement stable internal types first.

Primary crates: `angryier-core`, `angryier-ir`, `angryier-state`, `angryier-memory`, `angryier-expr`, `angryier-arch`, `angryier-arch-intel64`, `angryier-provenance`.

Core structures:

- stable IDs for image, block, state, expression, constraint, semantic content, target profile, provenance node, code page, and replay capsule;
- immutable/persistent state roots;
- page-based COW memory;
- concrete backing plus sparse symbolic overlay;
- register-state abstraction;
- target CPU profile model;
- expression arena/hash-consing interfaces;
- fidelity ledger;
- code-page version records;
- execution-ledger epoch model;
- deterministic serialization contracts for identity-bearing objects.

The initial state/memory implementation must be usable without XED, Z3, Bitwuzla, QIHSE, KEYSTONE, JIT, or fuzzing.

**Exit gate:** synthetic states can fork, mutate isolated pages/registers, preserve parent state, serialize deterministically, and reject stale ledger publication. **Passed.**

---

# Phase 2 — Intel XED Decode Boundary — DONE (contract layer)

Implement `angryier-decode-xed` only after internal decoded-form and target-feature types exist.

Responsibilities:

- XED initialization;
- Intel 64 instruction decode;
- normalized operand descriptors;
- form IDs;
- feature classification;
- instruction length/address;
- normalized register references;
- target-profile legality checks;
- conversion into XED-independent `DecodedInstructionView` data.

XED-owned pointers/lifetimes must terminate at the adapter boundary.

**Exit gate:** decode corpus round-trips deterministically into normalized internal forms, including representative scalar, SSE/AVX, AVX-512, AMX, CET/APX-capable forms where supported by the XED release in use. **Contract passed; native FFI not yet linked.**

---

# Phase 3 — Rich Semantic IR and Sealing — DONE

Implement private mutable semantic construction followed by immutable sealing.

Required components:

- typed semantic nodes;
- values/effects;
- explicit architectural side effects;
- scalar/FP/vector/opmask/tile domains;
- normalization;
- validation;
- canonical serialization;
- `ContentId` generation;
- `SemanticFingerprint` generation;
- semantic schema versions;
- derivation/provenance linkage.

Only sealed blocks may be lowered, cached, persisted, replayed, or used by JIT validity.

**Exit gate:** semantically identical canonical blocks receive stable exact identities across runs, while relevant rounding/masking/exception changes alter authoritative identity. **Passed.**

---

# Phase 4 — Handwritten Semantic Corpus — PARTIAL

Before building the semantic generator, implement a deliberately small but structurally representative corpus.

Implemented forms (251 total, in `angryier-semantics-intel64`):

**Original 93 foundational forms:**

- **Integer arithmetic (r64, r64):** MOV, ADD, SUB, XOR, AND, OR
- **Integer arithmetic (r64, imm):** MOV r64,imm64; ADD/SUB/CMP r64,imm32 (sign-extended)
- **Memory load/store:** MOV r64,[m64]; MOV [m64],r64; ADD r64,[m64]; CMP r64,[m64]
- **Shifts (r64, imm8):** SHL, SHR, SAR
- **Shifts (r64, CL):** SHL, SHR, SAR (masked to 6 bits)
- **Comparison:** CMP (r64,r64 and r64,imm32) — flags only, no register write
- **Control flow:** JZ, JNZ, JC, JNC, JS, JNS, JL, JGE, JMP (rel32)
- **Unary operations:** INC, DEC, NEG, NOT (r64)
- **Multiply/divide:** IMUL, MUL, DIV, IDIV (r64, r64)
- **Rotates:** ROL, ROR, RCL, RCR (r64, imm8)
- **Stack:** PUSH r64, POP r64
- **Address computation:** LEA r64,[m]
- **Exchange/test:** XCHG r64,r64; TEST r64,r64; XADD r64,r64
- **NOP:** no operation
- **Additional forms:** 32-bit and 8-bit partial writes, MOVZX/MOVSX, CMOVcc, BT/BTS/BTR/BTC, CLC/STC/CMC, SETcc, ADC/SBB, CBW/CWDE/CDQE/CWD/CDQ, CMPXCHG, PUSH imm, CALL/RET, additional conditional branches (JLE/JG/JA/JB/JBE/JAE)

**Phase 4a expansion (94 new forms):**

- **Register aliasing / partial writes:** MOV r16,r16; MOVZX/MOVSX r32,r16; MOVZX/MOVSX r32,r8; MOV r32,imm32; MOV r16,imm16; MOV r8,imm8
- **32-bit arithmetic:** ADD/SUB/XOR/AND/OR/CMP r32,r32; INC/DEC/NEG/NOT r32
- **Conditional moves (r64):** CMOVA, CMOVB, CMOVBE, CMOVAE, CMOVS, CMOVNS, CMOVC, CMOVNC, CMOVLE, CMOVG
- **Additional SETcc:** SETA, SETB, SETBE, SETAE, SETS, SETNS, SETC, SETNC, SETLE, SETG
- **Additional branches:** JO, JNO, JPE, JPO (rel32)
- **Bit manipulation:** BSWAP r64 (composed from shifts/masks); BSF, BSR, POPCNT, TZCNT, LZCNT (implemented with dedicated IR primitives — CountTrailingZeros, CountLeadingZeros, Popcount)
- **32-bit shifts/rotates:** SHL/SHR/SAR r32,imm8; SHL/SHR/SAR r32,CL; ROL/ROR r32,imm8
- **Additional memory forms:** MOV r32,[m32]; MOV [m32],r32; ADD/SUB/CMP r32,[m32]; MOV r8,[m8]; MOV [m8],r8; ADD/SUB/CMP r8,[m8]
- **Additional immediates:** ADD/SUB/CMP r32,imm8; AND/OR/XOR/TEST r64,imm32; AND/OR/XOR/TEST r32,imm32
- **Stack (32-bit):** PUSH r32, POP r32
- **Multiply/divide (32-bit):** IMUL r32,r32; IMUL r32,r32,imm8; IMUL r32,r32,imm32; MUL r32,r32; DIV r32,r32; IDIV r32,r32; IMUL r64,r64,imm32
- **Other:** XADD r32,r32; CMPXCHG r32,r32; LEA r32,[m]; MOVQ xmm,xmm (integer path placeholder); NOP3–NOP9; HLT (raises vector 0); UD2 (raises vector 6)

Flag coverage: ZF, SF, CF are computed and written to RFLAGS. PF, AF, OF are cleared but not fully computed (documented simplification for this phase). INC/DEC preserve CF. NEG sets CF = (operand != 0). NOT modifies no flags. TEST clears CF (logical operation).

Each provider emits rich semantic IR through `SemanticBlockBuilder`, seals deterministically, lowers through `BasicSemanticLowerer`, and executes concretely through `ConcreteInterpreter`. The full pipeline is tested end-to-end with 9 unit tests + 138 integration tests + 17 interpreter unit tests.

**Phase 4b expansion (59 new SSE/SSE2/SSE4 forms + IR primitive extensions):**

- **Scalar single-precision (xmm, xmm):** ADDSS, SUBSS, MULSS, DIVSS, SQRTSS — simplified to treat XMM as scalar f32 (upper lanes not modeled)
- **Scalar double-precision (xmm, xmm):** ADDSD, SUBSD, MULSD, DIVSD, SQRTSD — simplified to treat XMM as scalar f64
- **Packed single-precision (xmm, xmm):** ADDPS, SUBPS, MULPS, DIVPS — 4x32 lane-wise float operations
- **Packed double-precision (xmm, xmm):** ADDPD, SUBPD, MULPD, DIVPD — 2x64 lane-wise float operations
- **Packed integer byte (xmm, xmm):** PADDB, PSUBB — 16x8 lanes, wrapping
- **Packed integer word (xmm, xmm):** PADDW, PSUBW, PMULLW — 8x16 lanes, wrapping
- **Packed integer dword (xmm, xmm):** PADDD, PSUBD, PMULLD — 4x32 lanes, wrapping
- **Packed integer qword (xmm, xmm):** PADDQ, PSUBQ — 2x64 lanes, wrapping
- **Packed logical (xmm, xmm):** PAND, POR, PXOR — 128-bit bitwise operations
- **Packed shifts (xmm, imm8):** PSLLW/PSRLW/PSRAW, PSLLD/PSRLD/PSRAD, PSLLQ/PSRLQ — uniform count per lane
- **Packed compares (xmm, xmm):** PCMPEQB/W/D (equality mask), PCMPGTB/W/D (signed greater-than mask)
- **Packed min/max (xmm, xmm):** PMAXSB/W/D, PMAXUB/W/D, PMINSB/W/D, PMINUB/W/D — signed and unsigned lane-wise min/max
- **Packed multiply high (xmm, xmm):** PMULHW (signed), PMULHUW (unsigned) — high 16 bits of 32-bit product, 8x16 lanes

**Phase 4b IR primitive extensions:** RotateLeft, RotateRight, Popcount, CountLeadingZeros, CountTrailingZeros added to PrimitiveOp/IrPrimitive. FAdd/FSub/FMul/FDiv/FSqrt/FConvert added to IrPrimitive for float arithmetic (f32/f64 evaluated in interpreter). VecLaneAdd/Sub/Mul/And/Or/Xor and VecLaneFAdd/FSub/FMul/FDiv added for lane-wise integer and float vector operations (IrType::Vector now carries lane_bits).

**Execution-plane limitation:** The current `BasicSemanticLowerer` only supports full-width (64-bit) register reads and writes. 32-bit and 8-bit forms seal correctly (verified by the `all_providers_seal_successfully` unit test) but cannot execute through the concrete interpreter until the lowerer supports partial-register operations. Integration tests cover all 64-bit-executable forms including BSWAP, bit-scan/popcount, AND/OR/XOR/TEST r64,imm32, CMOVA, SETA/SETB/SETS, JO/JNO, IMUL r64,r64,imm32, MOVQ, NOP3/9.

Remaining families for full Phase 4 completion:

- partial-register lowering support (32-bit/8-bit execution);
- rotates with CL (32-bit);
- scalar float upper-lane preservation (ADDSS/SD currently models XMM as scalar, not preserving upper lanes);
- AVX upper-lane behavior;
- AVX-512 masking and zero/merge semantics;
- gather/scatter representative cases;
- AMX tile configuration and representative tile operation;
- exception/unsupported behavior (HLT/UD2 trap execution in lowerer);
- float compare IR primitive (currently returns unsupported in lowerer);
- float16/bfloat16/float80 interpreter support;
- vector shuffle/permute/broadcast/blend/pack/unpack IR primitives;
- SSE/AVX memory operand forms (currently register-to-register only);
- additional packed integer ops (PUNPCK, PACKSS, PSHUFB);
- packed shift with register count (PSLLW xmm,xmm etc.).

The objective is to force the rich IR and execution IR contracts to stabilize before automation amplifies design mistakes.

**Exit gate:** corpus passes differential concrete tests and supports deterministic semantic sealing/lowering. **Partially passed — 251 forms registered, all seal successfully, 64-bit forms, bit-scan/popcount, SSE float, SSE2 packed integer, SSE2 packed shifts, SSE2 packed compares, SSE4 packed min/max, and SSE2 packed multiply high verified end-to-end; partial-register lowering, upper-lane preservation, and remaining families pending.**

---

# Phase 5 — Compact Execution IR and Concrete Interpreter — FOUNDATIONS DONE

Implement `AngryIR` as the compact execution representation downstream of sealed semantics.

Requirements:

- compact SSA-like temporaries;
- explicit register/memory effects;
- typed operations where structural preservation pays off;
- no solver types in IR;
- block validity keys including semantic `ContentId`, target profile, and code-page versions;
- deterministic interpretation;
- code-page invalidation handling.

**Exit gate:** handwritten semantic corpus executes concretely and matches native/reference behavior on the differential corpus. **Foundations built; blocked on Phase 4 corpus.**

---

# Phase 6 — Atomic Execution Ledger + Replay — FOUNDATIONS PARTIAL

Harden the state publication boundary before concurrency, cross-run knowledge, or bidirectional fuzzing.

Implemented foundations (in-memory):

- `angryier-ledger`: atomic ledger with epoch model, stale rejection, provenance gap detection, concurrent state commits
- `angryier-replay`: in-memory replay capsule store, validator (schema/binary/semantic/code-version/environment/scheduler checks), basic replay engine with monotonic sequence
- `angryier-provenance`: in-memory provenance store with bounded priority queue, tier-based eviction (Tier-1 never dropped), adaptive trace governor, batching sink for worker-local provenance
- `angryier-storage`: in-memory WAL with checkpoint-based replay, priority-aware eviction (best-effort → structural → critical), retention policy (forensic/research quarantine, disposable purge)

Remaining for full Phase 6:

- durable/persistent WAL backend (file/disk-based);
- replay engine integration with concrete interpreter;
- provenance transport to QIHSE/KEYSTONE;
- forced database unavailability stress tests;
- sustained backpressure observability tests.

Required failure tests (partially covered):

- stale epoch — **covered** (ledger);
- stale page version — **covered** (ledger);
- semantic mismatch — **covered** (ledger + replay);
- provenance gap — **covered** (ledger);
- replay mismatch — **covered** (replay validator);
- conflicting commit — **covered** (ledger);
- WAL saturation and eviction — **covered** (storage);
- provenance backpressure and tier eviction — **covered** (provenance).

**Exit gate:** deterministic replay reproduces committed executions and rejects intentionally corrupted/stale capsules. **Partially passed — in-memory foundations validated; durable backends pending.**

---

# Phase 7 — Expression DAG + Taint Promotion — FOUNDATIONS PARTIAL

Implement symbolic expression infrastructure without solver commitment leaking into the state model.

Implemented foundations (in-memory):

- `angryier-expr`: expression DAG with hash-consing, arena, constant folding (701 lines)
- `angryier-taint`: in-memory taint engine with labels (UserInput/NetworkInput/FileInput/Derived/Concrete), states (Concrete/Tainted/Symbolic), promotion threshold, transform/merge/sink operations, TaintEngine trait

Requirements (status):

- arena-allocated `ExprId` — **done** (expr);
- hash-consing — **done** (expr);
- constant folding — **done** (expr);
- cheap deterministic canonicalization — **done** (expr);
- dependency summaries — **scaffolded**;
- taint/dataflow IDs — **done** (taint);
- concrete -> tainted -> symbolic promotion — **done** (taint);
- hybrid vector representation — **scaffolded**;
- lazy chunked AMX representation with dense-cell fallback — **scaffolded**.

**Exit gate:** mostly-concrete execution does not allocate symbolic ASTs unnecessarily, and vector/tile representation transitions are semantically equivalent on the corpus. **Partially passed — expression DAG and taint promotion validated; vector/tile representations pending.**

---

# Phase 8 — Solver Interface and Z3/Bitwuzla Backends

Implement the solver-neutral query model, then Z3 and Bitwuzla adapters.

Required result classes:

```text
SAT
UNSAT
UNKNOWN
TIMEOUT
RESOURCE_LIMIT
BACKEND_ERROR
```

Required capabilities:

- per-worker incremental contexts;
- shared-context batched satisfiability;
- model extraction;
- UNSAT-core support where backend permits;
- canonical query fingerprints;
- hard resource limits;
- adaptive preemption hooks;
- no backend AST in persistent engine state.

**Exit gate:** solver backends agree on the designated cross-check corpus, and timeout/error states can never be misclassified as UNSAT.

---

# Phase 9 — Constraint Reuse and Knowledge Validity — FOUNDATIONS PARTIAL

Implement exact reuse before approximate retrieval.

Order:

1. exact canonical query cache;
2. compatibility/dependency keys;
3. alpha-equivalence candidates;
4. validated UNSAT-core reuse;
5. implication/subsumption facts;
6. dependency-aware invalidation graph;
7. deeper offline canonicalization.

Every hit that can affect correctness must validate all required dependency keys before reuse.

**Exit gate:** deliberate fingerprint collisions, stale semantic versions, model changes, and fuzzer-generated near-miss constraints cannot authorize incorrect reuse.

---

# Phase 10 — Multicore / NUMA Scheduler — FOUNDATIONS PARTIAL

Introduce parallelism only after deterministic single-thread behavior is stable.

Implement:

- worker-local queues;
- work stealing;
- per-worker solver contexts/caches;
- NUMA-aware worker groups;
- state/solver/cache affinity metadata;
- multifactor steal cost;
- deterministic scheduler-record mode;
- scheduler-decision replay.

**Exit gate:** independent states scale across physical cores without a global execution lock, and deterministic mode can reproduce a recorded exploration ordering.

---

# Phase 11 — State Merge, Search, Summaries, Environment Models — FOUNDATIONS PARTIAL

Implement the higher-level exploration policies:

- multifactor state-merge cost model;
- composable multi-objective search;
- optional learned/advisory ranking hook;
- exact and approximate function summaries;
- dependency-keyed summary invalidation;
- layered syscall/libc/environment models;
- static/snapshot/checkpoint/live state-import abstraction.

**Exit gate:** PROVE refuses insufficiently justified approximations, while EXPLORE/HUNT record every policy relaxation in the fidelity ledger.

---

# Phase 12 — Provenance Transport, WAL, and QIHSE/KEYSTONE — FOUNDATIONS PARTIAL

Implement the knowledge-plane transport only after correctness-critical local provenance is stable.

Requirements:

- Tier-1 structural events never silently dropped;
- bounded priority-aware queues;
- worker-local batching;
- local WAL/spill under backpressure;
- Tier-2 flight recorder;
- semantic structural trace compression;
- quarantine/retention lifecycle;
- QIHSE exact-plane persistence;
- KEYSTONE indexing/ingestion/retrieval acceleration;
- dependency graph persistence;
- time-series telemetry;
- future GraphDB binding if required by the Rust SDK boundary.

**Exit gate:** forced database unavailability cannot corrupt execution correctness, and sustained backpressure is observable rather than silent.

---

# Phase 13 — Hybrid Fuzzing — FOUNDATIONS PARTIAL

Start conservatively.

Stage 1:

```text
seed sharing + coverage exchange
```

Stage 2 after replay/cache validation stress tests pass:

```text
bidirectional seeds
coverage
constraint hints
target hints
testcase feedback
```

High-entropy fuzz inputs must be a dedicated stress corpus for canonicalization and solver-cache poisoning resistance.

**Exit gate:** fuzzing cannot authorize an exact knowledge reuse without the same dependency validation required for non-fuzzed states.

---

# Phase 14 — Learned Fusion and Retrieval — FOUNDATIONS PARTIAL

Only after exact identity/reuse works reliably:

- modality-specific encoders;
- masked/gated fusion;
- default 1024-D representation;
- optional 384/2048/4096 profiles;
- multi-objective contrastive/self-supervised/exact-pair/behavioral/analyst-feedback training;
- calibrated fused retrieval score;
- modality contribution attribution;
- exact-validation status returned beside similarity results.

Similarity remains advisory.

**Exit gate:** retrieval quality is benchmarked independently of exact validity, and no learned score can bypass exact-plane checks.

---

# Phase 15 — JIT / Native Acceleration

JIT remains profile-driven rather than schedule-driven.

Potential progression:

```text
cold block -> compact interpreter
warm block -> specialized cached executor
hot block  -> Cranelift/native translation
```

Trusted generated JIT may execute in-process under validity guards. Arbitrary/native target execution belongs in restricted worker/sandbox isolation.

**Exit gate:** JIT produces measurable end-to-end benefit on runtime-dominated workloads and aggressive invalidation stress cannot desynchronize state, provenance, code-page versions, or replay.

---

# Phase 16 — Distribution Boundary — FOUNDATIONS PARTIAL

Define wire/storage formats now, implement distributed execution only after single-host NUMA scaling is proven.

Serializable boundaries include:

- target profile;
- sealed semantics identity;
- state roots/deltas;
- expression/constraint identities;
- replay capsule;
- fidelity/provenance context;
- solver-knowledge validity keys;
- work-unit identity.

No distributed scheduler implementation is a near-term blocker.

---

# Critical Early Stress Tests

The first implementation cycle must deliberately attack the architecture's known failure modes:

- millions of dependency graph nodes with bounded metadata overhead;
- WAL saturation and recovery;
- page-version/JIT/provenance atomicity under injected failures;
- alpha-equivalence near misses from mutated fuzz inputs;
- canonicalization CPU amplification;
- solver-preemption oscillation;
- NUMA state migration versus solver-affinity cost;
- AMX lazy-chunk contention versus dense fallback;
- deterministic replay under scheduler nondeterminism;
- QIHSE/KEYSTONE unavailability;
- fingerprint collision and stale-dependency attacks against reuse.

---

# First Coding Milestone

The first implementation milestone is **not XED**. It is the minimal stable Execution Plane substrate required for XED to plug into:

```text
IDs + schemas
TargetProfile / HostFeatures
State root
Register state
COW memory
CodePageVersion
FidelityLedger
ExecutionLedger contract
Deterministic serialization
```

Immediately after that substrate passes its invariant tests, implement the XED adapter and feed normalized Intel 64 decode objects into the already-defined semantic boundary. **This milestone is complete.**
