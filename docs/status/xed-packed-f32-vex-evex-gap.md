# XED packed-F32 arithmetic provider gap

Survey of the pinned XED 2024.05.20 enum inventory (`ISANITY/catalogue/imports/xed-iform-enum-candidates.json`) for `VADDPS`, `VSUBPS`, `VMULPS`, and `VDIVPS` finds 40 named IFORMs: 10 per mnemonic. The Angryier runtime map covers 24 (6 per mnemonic): VEX.128 and VEX.256 register/memory pairs, EVEX.128 and EVEX.256 register forms, and EVEX.512 register/memory pairs. EVEX.128/256 memory mappings are restricted to k0 (unmasked); k1-k7 memory instructions stay unmapped until lane-granular fault suppression is supported.

The remaining 16 named forms in this inventory are the EVEX.128/256 ordinary masked-memory forms (8 total) and embedded-broadcast memory variants (8 total):

| Encoding/width | Forms per mnemonic | Total | Status |
| --- | ---: | ---: | --- |
| EVEX.128 masked memory (k1-k7) | 1 | 4 | Unsupported — lane-level memory fault suppression not representable |
| EVEX.256 masked memory (k1-k7) | 1 | 4 | Unsupported — lane-level memory fault suppression not representable |
| EVEX.128 `{1to4}` | 1 | 4 | Unsupported — broadcast semantics not representable |
| EVEX.256 `{1to8}` | 1 | 4 | Unsupported — broadcast semantics not representable |

The broadcast memory encodings share an IFORM name with the ordinary memory forms but decode a 32-bit memory operand (`Shape::Mem32`), so the shape-based runtime map leaves them unmapped cleanly. They cannot be implemented exactly today: `VectorOp::Broadcast` exists in the semantic IR but the compact-IR lowering rejects non-lane-wise vector ops with `UnsupportedValue("non-lane-wise vector operation")`, so a mapped form could not be lowered or executed. Mapping them would silently compute element-wise semantics on the scalar memory operand and produce wrong values, so they intentionally remain unsupported.

## What landed for EVEX.128/EVEX.256

- `crates/angryier-semantics-intel64/src/avx512.rs`: 16 new form ids `0x1170..0x117F` and 16 dedicated providers (rules `0x1670..0x167F`) built on `packed_float_evex_xmm`/`packed_float_evex_ymm` macros. EVEX operand layout is `[dst, opmask, src1, src2]`; `evex_source_indices` selects (2, 3) under XED's normalized decode and (1, 2) for synthetic views. Mask merge/zero goes through `apply_evex_mask` (`MaskMerge`/`MaskZero` on operand 1, with `k0`/no-mask treated as unmasked).
- Upper-lane clearing: EVEX XMM/YMM destinations are partial views of a ZMM parent whose writes are `SemanticDefined`. Each provider concatenates the masked low vector with an all-zero tail (`Concat(low, zero)` → full F32X16) and replaces the whole parent via `write_register`, so all 64 destination bytes are architecturally correct — unlike `write_operand`, which would preserve stale upper parent bits.
- 256-bit float lanewise work is chunked into two 128-bit `LaneWiseFloat` halves (the concrete interpreter's `VecLaneF*` path evaluates ≤128-bit vectors), then rejoined; masking stays at full YMM granularity, which the byte-level `VecMaskMerge`/`VecMaskZero` evaluators handle at any width.
- `crates/angryier-runtime/src/form_map.rs`: the four instruction-class arms map EVEX XMM/YMM register forms for k0-k7, but EVEX memory shapes resolve only when the explicit opmask operand is k0. k1-k7 memory forms remain unmapped because the lowerer/interpreter currently reads the entire source span before masking; masked-off inaccessible lanes could otherwise fault incorrectly. VEX forms still resolve to their pre-existing mappings.
- `crates/angryier-semantics-intel64/src/registry.rs`: the 16 forms are registered in `ALL_FORMS` at the same positions as the new providers (total 1617 forms).

## Tests

- `form_map::tests::maps_evex128_256_packed_single_arithmetic_forms`: all 16 shapes pinned to their IFORM names, merge/zero mask encodings map identically, `{1to4}`/`{1to8}` broadcast encodings assert unmapped.
- `avx512_engine.rs`: provider count 108 → 124, all 16 provider forms in the conformance sweep; engine-level tests cover register masks and full-64-byte upper-lane zeroing. Direct provider tests with fully mapped memory exercise arithmetic only; runtime mapping tests reject k1-k7 memory encodings because lane-fault suppression is not yet supported.
- `evex_ps_differential.rs`: assembles each supported case with binutils, extracts the instruction bytes, runs them through the full XED → form map → registry → provider → lowerer → interpreter pipeline, and compares the complete ZMM0 image against a Rust oracle (32 register and unmasked-memory cases). Masked EVEX memory cases are excluded because the runtime deliberately leaves them unmapped. On hosts with AVX512F+AVX512VL it also runs a static binary that seeds the same state and compares native output; native execution is skipped cleanly otherwise. GAS cannot emit an unmasked EVEX xmm/ymm form (k0 is not a legal writemask and unmasked syntax selects VEX), so the unmasked cases are emitted as raw `.byte` sequences.

## Remaining gap

The 8 embedded-broadcast forms (`*PS_XMM...{1to4}`/`*PS_YMM...{1to8}` memory operands) stay unsupported until the IR lowering grows broadcast support. The 8 regular EVEX.128/256 masked memory forms (k1-k7) also stay unmapped until masked lane loads suppress faults correctly. No EVEX.128/256 rounding-control (`{rn-sae}` etc.) forms exist for these mnemonics — `b=1` decodings round up to the ZMM IFORMs, which are already covered.
