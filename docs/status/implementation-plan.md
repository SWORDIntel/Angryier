# Implementation Plan

> **Status:** Architecture frozen. Phases 0–3 and Phase 5 foundations are implemented. Phase 4 (handwritten semantic corpus) is partially implemented — 357 forms now registered covering integer arithmetic, flags, shifts, comparison, control flow, immediate operands, CL shifts, unary ops, conditional branches, memory load/store, multiply/divide, rotates, stack push/pop, LEA, XCHG/TEST/XADD, partial writes, MOVZX/MOVSX, CMOVcc, BT/BTS/BTR/BTC, flag manipulation (CLC/STC/CMC), SETcc, ADC/SBB, sign extension (CBW/CWDE/CDQE/CWD/CDQ), CMPXCHG, PUSH imm, CALL/RET, additional conditional branches (JLE/JG/JA/JB/JBE/JAE), 32-bit arithmetic, additional CMOVcc/SETcc/branches, BSWAP, bit-scan/popcount (BSF/BSR/POPCNT/TZCNT/LZCNT), 32-bit shifts/rotates, additional memory/immediate forms, 32-bit multiply/divide, NOP variants, HLT/UD2, SSE scalar float (ADDSS/SD, SUBSS/SD, MULSS/SD, DIVSS/SD, SQRTSS/SD — upper-lane preserving), SSE packed float (ADDPS/PD, SUBPS/PD, MULPS/PD, DIVPS/PD), SSE2 packed integer (PADDB/W/D/Q, PSUBB/W/D/Q, PMULLW/D, PAND/POR/PXOR/PANDN), SSE2 packed shifts imm8 (PSLLW/D/Q, PSRLW/D/Q, PSRAW/D, PSLLDQ, PSRLDQ), SSE2 packed shifts register count (PSLLW/D/Q, PSRLW/D/Q, PSRAW/D xmm,xmm), SSE2 packed compares (PCMPEQB/W/D, PCMPGTB/W/D/Q), SSE4 packed min/max (PMAXSB/W/D, PMAXUB/W/D, PMINSB/W/D, PMINUB/W/D, PMAXSQ, PMINSQ), SSE2 packed multiply high (PMULHW, PMULHUW), SSSE3 packed shuffle bytes (PSHUFB), SSE2 packed unpack/interleave (PUNPCKLBW/LWD/LDQ/LQDQ, PUNPCKHBW/HWD/HDQ/HQDQ), SSE2/SSE4 packed saturate (PACKSSWB, PACKSSDW, PACKUSWB, PACKUSDW), SSE2 packed multiply and add (PMADDWD), SSE2 packed sum of absolute differences (PSADBW), SSE4.1 multiple packed sums of absolute differences (MPSADBW), SSE4.1 horizontal packed minimum (PHMINPOSUW), SSE2 packed shuffle doublewords (PSHUFD), SSE2 packed shuffle high/low words (PSHUFHW, PSHUFLW), SSSE3 packed multiply and add unsigned/signed bytes (PMADDUBSW), SSSE3 horizontal add/subtract (PHADDW, PHADDD, PHSUBW, PHSUBD), SSSE3 packed absolute value (PABSB, PABSW, PABSD), SSSE3 packed sign (PSIGNB, PSIGNW, PSIGND), SSSE3 packed multiply high with round and scale (PMULHRSW), SSSE3 horizontal add/subtract with saturation (PHADDSW, PHSUBSW), SSE4.1 packed compare qword equal (PCMPEQQ), SSE4.1 packed multiply doublewords (PMULDQ), SSE4.1 variable blend bytes (PBLENDVB), SSE4.1 packed sign/zero extend (PMOVSXBW/BD/WD/DQ/WQ/BQ, PMOVZXBW/BD/WD/DQ/WQ/BQ), SSE4.1 immediate blends (PBLENDW, BLENDPS, BLENDPD), SSE4.1 packed dot products (DPPS, DPPD), SSE4.1 byte extract/insert (PEXTRB, PINSRB), SSE3 packed float horizontal add/subtract (HADDPS/PD, HSUBPS/PD), SSE/SSE2 packed aligned/unaligned moves (MOVAPS/PD/UPS/UPD), SSE/SSE2 scalar moves (MOVSS/SD — zero-extended). Phase 4b IR primitives added: rotate, popcount, bit-scan, float arithmetic (f32/f64), vector lane-wise integer, float, shift, mask comparison, min/max, multiply-high, abs, sign, multiply-high-rs, byte shuffle, interleave, pack-saturate (signed and unsigned), multiply-add, sum-of-absolute-differences, 32-bit lane shuffle, 16-bit half lane shuffle, multiply-add-unsigned-bytes, register-count shift (logical left, logical right, arithmetic right), horizontal add/subtract, horizontal add/subtract with saturation, float horizontal add/subtract, multiply-doublewords, variable-blend, lane sign/zero extend, immediate blend, and float dot product ops. All 348 forms seal successfully; 64-bit-executable forms, bit-scan/popcount, SSE float, SSE2 packed integer, SSE2 packed shifts (imm8 and register count), SSE2 packed compares, SSE4 packed min/max, SSE2 packed multiply high, SSSE3 PSHUFB, SSE2 packed unpack/interleave, SSE2/SSE4 packed saturate, SSE2 packed multiply and add, SSE2 packed sum of absolute differences, SSE2 packed shuffle doublewords, SSE2 packed shuffle high/low words, SSSE3 packed multiply and add unsigned/signed bytes, SSSE3 horizontal add/subtract, SSSE3 packed absolute value/sign, SSSE3 PMULHRSW/PHADDSW/PHSUBSW, SSE4.1 PCMPEQQ/PMULDQ/PBLENDVB, SSE4.1 PMOV sign/zero extend, SSE4.1 immediate blends (PBLENDW/BLENDPS/BLENDPD), SSE4.1 dot products (DPPS/DPPD), SSE4.1 PINSRB, SSE/SSE2 scalar float compare with flags (UCOMISS/UCOMISD/COMISS/COMISD), SSE4.1 packed/scalar rounding (ROUNDPS/ROUNDPD/ROUNDSS/ROUNDSD), SSE4.1 PTEST, SSE4.2 CRC32 (r32/r64), SSE4.1 dword/qword extract/insert (PEXTRD/PEXTRQ/PINSRD/PINSRQ), and SSE4.1 INSERTPS/EXTRACTPS, SSE3 packed float horizontal add/subtract (HADDPS/PD/HSUBPS/PD), SSE4.1 packed min/max 64-bit (PMAXSQ/PMINSQ), SSE/SSE2 packed moves (MOVAPS/PD/UPS/UPD), and SSE/SSE2 scalar moves (MOVSS/SD) verified end-to-end through concrete execution. Phase 6 foundations (replay engine, WAL, provenance store), Phase 7 foundations (taint engine), Phase 9 foundations (knowledge store, QIHSE/KEYSTONE adapters, fusion model, semantic compiler), Phase 10 foundations (work-stealing scheduler, distribution codec), Phase 11 foundations (environment models, telemetry, benchmark sink, plugin registry, image loader, fuzz bridge), Phase 12 foundations (QIHSE/KEYSTONE in-memory adapters), Phase 13 foundations (fuzz bridge), Phase 14 foundations (fusion model), and Phase 16 foundations (work codec) are also partially implemented in-memory. Phase 8 (native solver backends) and Phases 13–16 native integrations remain scaffolded.

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

Implemented forms (357 total, in `angryier-semantics-intel64`):

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
- **Other:** XADD r32,r32; CMPXCHG r32,r32; LEA r32,[m]; MOVQ xmm,xmm (low 64-bit copy with zero-extended upper 64 bits); NOP3–NOP9; HLT (raises vector 0); UD2 (raises vector 6)

Flag coverage: ZF, SF, CF are computed and written to RFLAGS. PF, AF, OF are cleared but not fully computed (documented simplification for this phase). INC/DEC preserve CF. NEG sets CF = (operand != 0). NOT modifies no flags. TEST clears CF (logical operation).

Each provider emits rich semantic IR through `SemanticBlockBuilder`, seals deterministically, lowers through `BasicSemanticLowerer`, and executes concretely through `ConcreteInterpreter`. The full pipeline is tested end-to-end with 9 unit tests + 258 integration tests + 17 interpreter unit tests.

**Phase 4b expansion (163 new SSE/SSE2/SSE4/SSSE3 forms + IR primitive extensions):**

- **Scalar single-precision (xmm, xmm):** ADDSS, SUBSS, MULSS, DIVSS, SQRTSS — upper 96 bits preserved from source operand 1
- **Scalar double-precision (xmm, xmm):** ADDSD, SUBSD, MULSD, DIVSD, SQRTSD — upper 64 bits preserved from source operand 1
- **Packed single-precision (xmm, xmm):** ADDPS, SUBPS, MULPS, DIVPS — 4x32 lane-wise float operations
- **Packed double-precision (xmm, xmm):** ADDPD, SUBPD, MULPD, DIVPD — 2x64 lane-wise float operations
- **Packed integer byte (xmm, xmm):** PADDB, PSUBB — 16x8 lanes, wrapping
- **Packed integer word (xmm, xmm):** PADDW, PSUBW, PMULLW — 8x16 lanes, wrapping
- **Packed integer dword (xmm, xmm):** PADDD, PSUBD, PMULLD — 4x32 lanes, wrapping
- **Packed integer qword (xmm, xmm):** PADDQ, PSUBQ — 2x64 lanes, wrapping
- **Packed logical (xmm, xmm):** PAND, POR, PXOR, PANDN — 128-bit bitwise operations (PANDN composed from scalar Not + And over U128)
- **Packed shifts (xmm, imm8):** PSLLW/PSRLW/PSRAW, PSLLD/PSRLD/PSRAD, PSLLQ/PSRLQ — uniform count per lane; PSLLDQ/PSRLDQ — byte-level left/right shift of 128-bit value
- **Packed compares (xmm, xmm):** PCMPEQB/W/D (equality mask), PCMPGTB/W/D/Q (signed greater-than mask)
- **Packed min/max (xmm, xmm):** PMAXSB/W/D, PMAXUB/W/D, PMINSB/W/D, PMINUB/W/D — signed and unsigned lane-wise min/max
- **Packed multiply high (xmm, xmm):** PMULHW (signed), PMULHUW (unsigned) — high 16 bits of 32-bit product, 8x16 lanes
- **Packed shuffle bytes (xmm, xmm):** PSHUFB — SSSE3 parallel byte shuffle with zero-on-high-bit semantics
- **Packed unpack/interleave (xmm, xmm):** PUNPCKLBW/LWD/LDQ/LQDQ (low), PUNPCKHBW/HWD/HDQ/HQDQ (high) — lane-wise interleave from low or high half
- **Packed saturate (xmm, xmm):** PACKSSWB (16→8 signed saturate), PACKSSDW (32→16 signed saturate), PACKUSWB (16→8 unsigned saturate), PACKUSDW (32→16 unsigned saturate) — cross-width pack with saturation
- **Packed multiply and add (xmm, xmm):** PMADDWD — 8x16-bit signed → 4x32-bit signed, pairwise multiply and horizontal add
- **Packed sum of absolute differences (xmm, xmm):** PSADBW — 16x8-bit unsigned → 2x64-bit, horizontal SAD per 8-byte block
- **Multiple packed sums of absolute differences (xmm, xmm, imm8):** MPSADBW — 8x16-bit SAD results computed from 4-byte blocks at imm8-selected offsets in src1 and src2
- **Packed shuffle doublewords (xmm, imm8):** PSHUFD — 4x32-bit lane shuffle by imm8 selectors
- **Packed shuffle high/low words (xmm, imm8):** PSHUFHW (high 4x16 shuffle, low 64 unchanged), PSHUFLW (low 4x16 shuffle, high 64 unchanged) — 16-bit lane shuffle within a 64-bit half
- **Packed multiply and add unsigned/signed bytes (xmm, xmm):** PMADDUBSW — 16x8-bit (left signed, right unsigned) → 8x16-bit signed with saturation, pairwise multiply and horizontal add
- **Packed shift with register count (xmm, xmm):** PSLLW/D/Q (logical left), PSRLW/D/Q (logical right), PSRAW/D (arithmetic right) — shift all lanes by count from low 64 bits of second XMM operand
- **Horizontal add/subtract (xmm, xmm):** PHADDW (8x16→8x16 pairwise add), PHADDD (4x32→4x32 pairwise add), PHSUBW (8x16 pairwise sub), PHSUBD (4x32 pairwise sub) — horizontal pairwise add/subtract across two sources
- **Packed absolute value (xmm, xmm):** PABSB (8x8-bit), PABSW (8x16-bit), PABSD (4x32-bit) — per-lane signed absolute value
- **Horizontal packed minimum (xmm, xmm):** PHMINPOSUW — horizontal minimum of 8 unsigned 16-bit words, result[0:16]=min value, result[16:32]=min index, upper 96 bits zeroed
- **Packed sign (xmm, xmm):** PSIGNB (8x8-bit), PSIGNW (8x16-bit), PSIGND (4x32-bit) — per-lane sign application (multiply by sign of second operand)
- **Packed multiply high with round and scale (xmm, xmm):** PMULHRSW — 8x16-bit signed multiply, (product + 0x4000) >> 15 (round-to-nearest scaling)
- **Horizontal add/subtract with saturation (xmm, xmm):** PHADDSW (8x16 pairwise add with saturation), PHSUBSW (8x16 pairwise sub with saturation) — horizontal pairwise add/subtract across two sources with signed 16-bit saturation
- **Packed compare qword equal (xmm, xmm):** PCMPEQQ — 2x64-bit lane-wise equality mask
- **Packed multiply doublewords (xmm, xmm):** PMULDQ — 2x64-bit lanes, low 32 bits of each operand as signed, multiply to 64-bit signed result
- **Variable blend bytes (xmm, xmm, xmm):** PBLENDVB — per-byte blend using mask operand high bit (result[i] = mask[i]&0x80 ? src[i] : dst[i])
- **Packed sign/zero extend (xmm, xmm):** PMOVSXBW/BD/WD/DQ/WQ/BQ, PMOVZXBW/BD/WD/DQ/WQ/BQ — sign- or zero-extend low narrow lanes to wider destination type (8→16/32/64, 16→32/64, 32→64)
- **Immediate blends (xmm, xmm, imm8):** PBLENDW (8x16-bit), BLENDPS (4x32-bit float), BLENDPD (2x64-bit float) — per-lane blend selected by imm8 bit
- **Packed dot products (xmm, xmm, imm8):** DPPS (4x32-bit float), DPPD (2x64-bit float) — float dot product with imm8-controlled lane selection and broadcast
- **Byte extract/insert (r32/xmm, xmm/r32, imm8):** PEXTRB (extract byte from xmm to r32, zero-extended), PINSRB (insert low byte of r32 into xmm at imm8-selected byte index)
- **Scalar float compare with flags (xmm, xmm):** UCOMISS, UCOMISD, COMISS, COMISD — compare low scalar float, set ZF/CF/PF in RFLAGS (NaN → ZF=1,CF=1,PF=1; less → CF=1; equal → ZF=1; greater → no flags)
- **Packed/scalar float rounding (xmm, xmm, imm8):** ROUNDPS (4x32-bit), ROUNDPD (2x64-bit) — round all lanes per imm8[1:0] (0=nearest, 1=down, 2=up, 3=truncate); ROUNDSS, ROUNDSD — round low element, preserve upper lanes from src1
- **Packed test (xmm, xmm):** PTEST — set ZF if (dst AND src)==0, set CF if ((NOT dst) AND src)==0, write to RFLAGS
- **CRC-32C checksum (r32/r64, r32/r64):** CRC32 r32,r32 and CRC32 r64,r64 — compute CRC-32C (Castagnoli, reversed polynomial 0x82F63B78) over source register bytes, result zero-extended to destination width
- **Dword/qword extract/insert (r32/r64, xmm, imm8):** PEXTRD (extract dword to r32), PEXTRQ (extract qword to r64), PINSRD (insert dword from r32), PINSRQ (insert qword from r64) — imm8-selected lane index
- **Float dword extract/insert (xmm/r32, xmm, imm8):** EXTRACTPS (extract float dword raw bits to r32), INSERTPS (insert float dword from src at imm8[3:2] into dst at imm8[1:0], with imm8[7:4] ZMASK zeroing selected dwords)
- **32-bit rotates with CL (r32, CL):** ROL r32,CL and ROR r32,CL — rotate 32-bit register by CL count masked to 5 bits, result zero-extended to 64 bits
- **Packed float compare with imm8 (xmm, xmm, imm8):** CMPPS (4x32-bit), CMPPD (2x64-bit) — per-lane compare with imm8[2:0] predicate (0=EQ, 1=LT, 2=LE, 3=UNORD, 4=NEQ, 5=NLT, 6=NLE, 7=ORD), all-ones or all-zeros per lane
- **Packed float min/max (xmm, xmm):** MINPS, MAXPS (4x32-bit) — per-lane min/max with NaN-returns-source2 and signed-zero semantics (min returns source2 for +0/-0)
- **Move mask to r32 (r32, xmm):** MOVMSKPS (4x32-bit sign bits), MOVMSKPD (2x64-bit sign bits), PMOVMSKB (16x8-bit sign bits) — extract sign bit from each lane, pack into low result bits, zero-extend to 64 bits
- **Packed float horizontal add/subtract (xmm, xmm):** HADDPS (4x32-bit pairwise add), HADDPD (2x64-bit pairwise add), HSUBPS (4x32-bit pairwise sub), HSUBPD (2x64-bit pairwise sub) — horizontal pairwise add/subtract across two float sources
- **Packed min/max 64-bit (xmm, xmm):** PMAXSQ (2x64-bit signed max), PMINSQ (2x64-bit signed min) — lane-wise signed 64-bit min/max
- **Packed aligned/unaligned moves (xmm, xmm):** MOVAPS, MOVAPD, MOVUPS, MOVUPD — register-to-register 128-bit copy
- **Scalar moves (xmm, xmm):** MOVSS (copy low 32 bits, zero upper 96), MOVSD (copy low 64 bits, zero upper 64) — register-to-register scalar move with zero-extension

**Phase 4b IR primitive extensions:** RotateLeft, RotateRight, Popcount, CountLeadingZeros, CountTrailingZeros added to PrimitiveOp/IrPrimitive. FAdd/FSub/FMul/FDiv/FSqrt/FConvert added to IrPrimitive for float arithmetic (f32/f64 evaluated in interpreter). FCompareFlags added for scalar float compare with RFLAGS output. FRound/VecFRound added for scalar/packed float rounding with imm8 mode. VecTest added for PTEST bitwise test with ZF/CF output. Crc32 added for CRC-32C checksum computation. VecLaneAdd/Sub/Mul/And/Or/Xor and VecLaneFAdd/FSub/FMul/FDiv added for lane-wise integer and float vector operations (IrType::Vector now carries lane_bits). VecLaneSignExtend/VecLaneZeroExtend added for type-changing packed sign/zero extension. VecBlendImm added for immediate-controlled per-lane blending. VecDotF added for float dot product with imm8 lane selection and broadcast. VecCmpF added for packed float compare with imm8 predicate (8 predicates: EQ/LT/LE/UNORD/NEQ/NLT/NLE/ORD). VecFMin/VecFMax added for packed float min/max with NaN-returns-source2 and signed-zero semantics. VecMovMask added for extracting sign bits from vector lanes into a scalar register. VecHFAdd/VecHFSub added for packed float horizontal add/subtract across two sources. VecMpsadbw added for multiple packed sums of absolute differences with imm8-selected offsets. VecHMinUW added for horizontal minimum of 8 unsigned 16-bit words with index output. VecShiftLeftBytes/VecShiftRightBytes added for byte-level 128-bit left/right shift (PSLLDQ/PSRLDQ). FloatingOp::Compare and FloatingOp::Round added to SemanticOp::Float. VectorOp::FRound, VectorOp::Test, VectorOp::CmpF, VectorOp::FMin, VectorOp::FMax, VectorOp::MovMask, VectorOp::HFAdd, VectorOp::HFSub, VectorOp::Mpsadbw, VectorOp::HMinUW, VectorOp::ShiftLeftBytes, and VectorOp::ShiftRightBytes added to SemanticOp::Vector. PrimitiveOp::Crc32 added to SemanticOp::Primitive.

**Execution-plane limitation:** The current `BasicSemanticLowerer` only supports full-width (64-bit) register reads and writes. 32-bit and 8-bit forms seal correctly (verified by the `all_providers_seal_successfully` unit test) but cannot execute through the concrete interpreter until the lowerer supports partial-register operations. Integration tests cover all 64-bit-executable forms including BSWAP, bit-scan/popcount, AND/OR/XOR/TEST r64,imm32, CMOVA, SETA/SETB/SETS, JO/JNO, IMUL r64,r64,imm32, MOVQ (low 64-bit copy with zero-extended upper 64 bits), NOP3/9.

Remaining families for full Phase 4 completion:

- partial-register lowering support (32-bit/8-bit execution);
- AVX upper-lane behavior;
- AVX-512 masking and zero/merge semantics;
- gather/scatter representative cases;
- AMX tile configuration and representative tile operation;
- exception/unsupported behavior (HLT/UD2 trap execution in lowerer);
- float16/bfloat16/float80 interpreter support;
- vector permute/broadcast/blend IR primitives;
- SSE/AVX memory operand forms (currently register-to-register only).

The objective is to force the rich IR and execution IR contracts to stabilize before automation amplifies design mistakes.

**Exit gate:** corpus passes differential concrete tests and supports deterministic semantic sealing/lowering. **Partially passed — 357 forms registered, all seal successfully, 64-bit forms, bit-scan/popcount, SSE float, SSE2 packed integer, SSE2 packed shifts (imm8 and register count), SSE2 packed compares, SSE4 packed min/max, SSE2 packed multiply high, SSSE3 PSHUFB, SSE2 packed unpack/interleave, SSE2/SSE4 packed saturate, SSE2 packed multiply and add, SSE2 packed sum of absolute differences, SSE2 packed shuffle doublewords, SSE2 packed shuffle high/low words, SSSE3 packed multiply and add unsigned/signed bytes, SSSE3 horizontal add/subtract, SSSE3 packed absolute value/sign, SSSE3 PMULHRSW/PHADDSW/PHSUBSW, SSE4.1 PCMPEQQ/PMULDQ/PBLENDVB, SSE4.1 PMOV sign/zero extend, SSE4.1 immediate blends (PBLENDW/BLENDPS/BLENDPD), SSE4.1 dot products (DPPS/DPPD), SSE4.1 PINSRB, SSE/SSE2 scalar float compare with flags (UCOMISS/UCOMISD/COMISS/COMISD), SSE4.1 packed/scalar rounding (ROUNDPS/ROUNDPD/ROUNDSS/ROUNDSD), SSE4.1 PTEST, SSE4.2 CRC32 (r32/r64), SSE4.1 dword/qword extract/insert (PEXTRD/PEXTRQ/PINSRD/PINSRQ), SSE4.1 INSERTPS/EXTRACTPS, 32-bit rotates with CL (ROL/ROR r32,CL), scalar float upper-lane preservation (ADDSS/SD, SUBSS/SD, MULSS/SD, DIVSS/SD, SQRTSS/SD), packed float compare with imm8 (CMPPS/CMPPD), packed float min/max (MINPS/MAXPS), and move-mask (MOVMSKPS/MOVMSKPD/PMOVMSKB) verified end-to-end; partial-register lowering and remaining families pending.**

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
