# XED packed-F32 arithmetic provider gap

Survey of the pinned XED 2024.05.20 enum inventory (`ISANITY/catalogue/imports/xed-iform-enum-candidates.json`) for `VADDPS`, `VSUBPS`, `VMULPS`, and `VDIVPS` finds 40 named IFORMs: 10 per mnemonic. The current Angryier runtime map covers 16 of them: the VEX.256 register/memory pair for each mnemonic and the EVEX.512 register/memory pair for each mnemonic.

The remaining 24 named forms are:

| Encoding/width | Forms per mnemonic | Total | Missing behavior |
| --- | ---: | ---: | --- |
| VEX.128 | 2 | 8 | Three-operand packed-F32 XMM provider; the existing SSE XMM providers are destructive two-operand forms. VEX also zeroes the upper vector state. |
| EVEX.128 | 2 | 8 | XMM-width packed arithmetic with per-lane opmask merge/zero behavior and upper-vector clearing. |
| EVEX.256 | 2 | 8 | YMM-width packed arithmetic with per-lane opmask merge/zero behavior and upper-vector clearing. |

This is a provider gap, not a safe mapping-only opportunity. The existing ZMM EVEX provider demonstrates mask handling, and the semantic IR/concrete interpreter contain generic vector mask-merge/mask-zero operations, but there are no exact XMM/YMM forms/providers for these four operations. Reusing the VEX YMM provider for EVEX would ignore the opmask operand and produce incorrect results. Reusing SSE XMM providers would conflate destructive two-operand and non-destructive three-operand semantics. Until dedicated forms and differential tests also prove upper-lane clearing, these 24 forms should remain unsupported.

Evidence checked in source:

- `crates/angryier-runtime/src/form_map.rs`: the four instruction-class arms map VEX YMM and EVEX ZMM shapes only; EVEX XMM/YMM shapes fall through to `None`.
- `crates/angryier-semantics-intel64/src/providers_ext.rs`: VEX YMM providers read source operands 1/2, while the SSE `ADDPS`/`SUBPS`/`MULPS`/`DIVPS` providers read destination/source operands 0/1.
- `crates/angryier-semantics-intel64/src/avx512.rs`: the packed-F32 EVEX providers are ZMM-width and apply `MaskMerge`/`MaskZero` before writing the destination.
- The focused existing decoder/form-map test `maps_avx512_evex_forms` passes and exercises the mapped ZMM VADDPS register and memory shapes.

The enum inventory is a name count, not a claim that every entry is executable in long mode. Decoder fixtures and runtime mapping tests remain the required evidence before any of these 24 entries can be declared covered.
