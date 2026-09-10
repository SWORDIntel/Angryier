# Angryier Intel 64 Semantics Architecture

## Purpose

This document defines how Angryier should decode, represent, generate, validate, and execute Intel 64 instruction semantics.

The primary rule is:

> Decode metadata, semantic truth, and execution lowering are separate layers.

Being able to decode an instruction is not equivalent to supporting it semantically.

---

# 1. Decode Layer

Intel XED is the canonical Intel 64 decoder.

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

---

# 2. Host vs Target Semantics

Two independent feature sets exist:

```text
HostFeatures
TargetFeatures
```

`HostFeatures` describes what the physical analysis machine can safely execute natively.

`TargetFeatures` describes what instructions the analyzed binary is permitted to use.

Example:

```text
host:   AVX2
binary: AVX-512

result:
  decode succeeds
  software AVX-512 semantics execute
  native AVX-512 fast path is unavailable
```

The engine must never compile away target-semantic support because the build host lacks the feature.

---

# 3. Semantic Development Sequence

The semantics generator is a locked goal, but it is deliberately not the first implementation step.

## Stage A — representative handwritten corpus

Implement enough instructions manually to exercise all important semantic shapes:

- scalar arithmetic/logical;
- flags;
- register aliasing/partial writes;
- memory load/store;
- conditional branches;
- shifts/rotates;
- multiply/divide;
- scalar floating point;
- packed integer SIMD;
- packed floating point SIMD;
- AVX upper-lane behavior;
- AVX-512 masking and zero/merge semantics;
- gather/scatter representative cases;
- AMX tile configuration and representative tile operation;
- system/control-flow instructions required by the initial corpus.

The goal is not broad coverage at this stage. The goal is to discover what the semantic representation must express.

## Stage B — stabilize canonical semantics

The handwritten corpus is used to harden:

- operand binding;
- type rules;
- vector lane model;
- mask model;
- tile model;
- flag side effects;
- fault/exception representation;
- memory semantics;
- rounding/floating-point controls;
- execution lowering.

## Stage C — semantics compiler/generator

Once repeated patterns are visible, a declarative description system generates the regular cases.

Generated output should cover families such as:

```text
packed add/subtract
logical operations
comparisons
lane-wise min/max
shifts
permutations/shuffles where regular
conversions where regular
mask application
vector-width expansion
operand-form expansion
```

## Stage D — specialized overrides

Complex instructions remain eligible for handwritten semantic handlers.

Examples likely to need specialist treatment include:

```text
AMX tile operations
gather/scatter
fault-suppressed memory forms
complex floating-point behavior
string/REP families
system instructions
CET-specific behavior
instructions with unusual architectural state
```

The generator must never become a reason to force a naturally irregular instruction into an unreadable generic DSL.

---

# 4. Canonical Semantic Representation

Instruction definitions lower first into a canonical typed semantic form.

Conceptually:

```text
DecodedInstruction
      +
SemanticDefinition
      |
      v
CanonicalSemantics
      |
      +--> concrete evaluator
      +--> taint propagation
      +--> AngryIR lowering
      +--> symbolic execution
      +--> generated tests
      +--> support manifest
```

This layer must be deterministic and serializable enough to hash/version semantic meaning.

Potential primitive operations include:

```text
ReadReg
WriteReg
ReadFlag
WriteFlag
Load
Store
Add/Sub/Mul/Div
And/Or/Xor/Not
Shift/Rotate
Compare
Select
Concat/Extract
SignExtend/ZeroExtend
FPAdd/FPSub/FPMul/FPDiv
Convert
VectorMap
VectorZip
VectorPermute
ApplyMask
TileRead
TileWrite
Branch
RaiseFault
```

The exact DSL syntax remains open until the handwritten corpus establishes the required expressiveness.

---

# 5. First-Class Types

The semantic system should distinguish these domains rather than immediately flattening them:

```text
BitVec(bits)
Float(format)
Vector(lanes, element_type)
Opmask(lanes)
Tile(rows, cols, storage/element interpretation)
```

Additional structured types may be introduced when an instruction family warrants them.

## Bitvectors

Used for ordinary integer/register/memory semantics.

## Floating point

Must represent architectural floating-point behavior explicitly enough to model:

- IEEE formats;
- NaNs and signaling behavior where required;
- rounding modes;
- embedded rounding;
- SAE;
- MXCSR-related behavior;
- denormal/flush modes where fidelity policy requires them.

## Vectors

Vectors preserve lane structure where doing so reduces expression growth or improves semantic clarity.

The engine may lazily convert between:

```text
lane-structured vector
<->
packed solver bitvector
```

## Opmasks

AVX-512 opmask registers and merge-vs-zero semantics are explicit.

## Tiles

AMX tile state is explicit. TMM data should support lazy/sparse symbolic materialization.

A symbolic element must not automatically force an entire tile into thousands of independent symbolic nodes unless the operation requires it.

---

# 6. AVX / AVX-512 Rules

The semantics layer must model, as first-class behavior:

- VEX/EVEX operand widths;
- lane width and count;
- upper-lane zeroing/preservation rules;
- masking;
- zeroing vs merging;
- broadcast forms;
- embedded rounding;
- SAE;
- memory fault behavior where architecturally relevant;
- scalar-in-vector forms;
- cross-lane vs lane-local operations.

These properties should be metadata-driven when possible, but semantic truth remains explicit and testable.

---

# 7. AMX Rules

AMX support includes both data state and configuration state.

At minimum model:

```text
TMM register set
TILECFG state
configured dimensions/layout
load/store tile behavior
tile compute operations
state invalidation/config transitions
feature/profile gating
```

Concrete execution may use host AMX acceleration only when legal and safely configured. Otherwise software semantics remain authoritative.

---

# 8. Generated Semantics Requirements

The generator must produce deterministic output.

Required properties:

- stable input schema;
- schema versioning;
- stable generated ordering;
- no host-feature-dependent semantic omission;
- readable generated code/data;
- explicit source-definition reference for each generated instruction form;
- per-form support manifest;
- generated tests where possible;
- CI regeneration check with zero unexpected diff.

Recommended repository policy:

```text
semantic source definitions
+
generated artifacts checked into repository
+
CI regenerates and verifies no drift
```

This keeps normal builds independent of the generator toolchain while retaining reproducibility.

---

# 9. Semantic Overrides

A generated family may declare explicit override points.

Conceptually:

```rust
#[semantic_override("TDPBF16PS")]
fn tdpbf16ps(ctx: &mut SemanticBuilder, insn: &DecodedInstruction) -> Result<()> {
    // specialized semantics
}
```

Overrides must participate in the same validation and support-manifest system as generated semantics.

---

# 10. Support Manifest

Angryier must expose exact semantic coverage.

Example machine-readable data:

```json
{
  "iform": "VPADDD_ZMMu32_MASKmskw_ZMMu32_MEMu32_AVX512",
  "decode": "supported",
  "semantics": "generated",
  "concrete": "validated",
  "symbolic": "validated",
  "taint": "validated",
  "native_diff": "pass",
  "semantic_version": "..."
}
```

User-facing family summaries may aggregate this data, but unsupported or unvalidated forms must remain visible.

---

# 11. Validation Strategy

Semantic validation uses multiple independent methods where practical.

## Layer 1 — semantic unit/property tests

Validate primitive operations and DSL/compiler behavior.

## Layer 2 — instruction-form concrete tests

Generate randomized concrete inputs and compare architectural outputs.

## Layer 3 — native Intel differential testing

Where the host supports the instruction, execute controlled test blocks on real Intel hardware and compare:

- output registers;
- flags;
- memory effects;
- relevant exception/fault behavior.

## Layer 4 — reference-engine differential testing

Use suitable external semantic/execution engines as additional disagreement detectors.

No single external engine is automatically treated as truth.

## Layer 5 — symbolic consistency

For selected instructions, prove or test that symbolic lowering agrees with concrete evaluation over sampled/model-generated inputs.

## Layer 6 — solver cross-check

High-value semantic formulas may be checked across more than one solver backend.

---

# 12. Semantic Disagreement Knowledge

When Angryier, hardware, or a reference implementation disagree, the disagreement is itself a persistent artifact.

Store:

```text
instruction form
input state
expected/observed outputs
which oracle disagreed
semantic version
host CPU/microcode
target profile
solver/version if involved
reproduction block
resolution status
```

This turns semantic debugging into cumulative knowledge rather than repeated rediscovery.

---

# 13. Performance Rules

Semantic abstraction must not force avoidable runtime cost.

Principles:

- decode/lower blocks once and cache them;
- avoid heap allocation per operand;
- keep concrete structured values inline or compact;
- preserve lane/tile structure until flattening is required;
- avoid creating symbolic expressions for concrete-only operations;
- specialize common semantic patterns after profiling;
- do not add JIT complexity until measurements justify it.

---

# 14. Production Support Gate

An Intel instruction family is not advertised as production-supported until:

1. required decoded forms are enumerated;
2. semantic coverage is explicit;
3. concrete tests pass;
4. symbolic/taint behavior passes the defined tests;
5. unsupported forms fail explicitly rather than guessing;
6. support manifest is generated;
7. representative differential tests pass;
8. performance does not regress beyond accepted gates without justification.
