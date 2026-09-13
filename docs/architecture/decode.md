# Intel XED Decode Boundary

> **Implementation status:** Implemented (contract layer). `angryier-decode-xed` owns the normalization boundary, metadata types, and error types. Native XED FFI integration is not yet linked — the adapter currently works with synthetic decode objects and must fail explicitly when XED is unavailable.

---

## Role

Intel XED is the canonical initial decoder/form classifier for Intel 64.

XED provides:

- instruction length;
- normalized form identity;
- operand metadata;
- register references;
- immediate/displacement metadata;
- encoding/form classification;
- Intel feature association.

XED does **not** provide Angryier semantic truth.

## Boundary rule

XED-owned pointers, opaque decoder state, and XED lifetimes terminate in `angryier-decode-xed`. Downstream crates consume a serializable, deterministic internal decoded representation.

The decoder must be independently fuzzable and replaceable. A synthetic decoder should be able to feed the semantic layer without linking XED.

## Normalized representation

The XED adapter normalizes decoded instructions into an Angryier-owned representation containing at least:

```text
instruction class
encoding/form
operand count
operand kinds
operand widths
read/write direction
memory operands
immediates
masking/broadcast/rounding attributes
feature/extension requirements
instruction length
raw bytes
```

XED objects do not escape into the rest of the engine.

The adapter must make it possible to replace or supplement the decoder later without rewriting the execution engine.
