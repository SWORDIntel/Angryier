# angryier-arch-arm64

AArch64 (A64) architecture support for Angryier — **ANG-023 phase 1**.

## Phase-1 inventory (historical)

- **Register model** (`regs.rs`): canonical parents `X0..X30`, `XZR`, `PC`,
  `NZCV`, `FPCR`, `FPSR`, `V0..V31` (128-bit), plus a separate `SP`; 32-bit
  zero-extending `Wn`/`WZR` views and `B/H/S/D/Q` vector views with
  AAPCS64-compatible write behaviour.
- **`Architecture` impl** with an AArch64 target profile and feature set
  (baseline v8.0 + FP + SIMD declared).
- **Safe-Rust decoder** (`decode.rs`) for the integer core subset:
  - branches: `B`, `BL`, `B.cond` (14 codes), `CBZ/CBNZ`, `TBZ/TBNZ`,
    `BR`, `BLR`, `RET`
  - PC-relative: `ADR`, `ADRP`
  - data processing: `ADD/SUB` (immediate and shifted-register),
    `ADDS/SUBS/CMP/CMN`, `AND/ORR/EOR/ANDS/TST` (immediate and
    shifted-register), `MOVZ/MOVN/MOVK`, `UBFM/SBFM` (incl. `LSL/LSR/ASR`
    aliases), `EXTR`, `CSEL/CSINC/CSINV/CSNEG`, `MADD/MSUB`
  - loads/stores: `LDR/STR` (unsigned scaled, B/H/W/X + `LDRSW`),
    `LDUR/STUR` (unscaled), `LDR/STR` (register offset), `LDP/STP`
    (offset/post/pre-index with write-back operand)
  - `NOP`, `HINT`, `SVC`
- **Golden decode tests**: 21 vectors drawn from real-world AArch64 shared
  objects and the ARM ARM.

## Phase-1 exclusions (historical)

- FP/SIMD (scalar and vector), LDPSW, LDR literal, exclusive/monitor,
  system registers, pointer authentication, atomics (LSE), and the
  remaining branch/system space. Unsupported encodings fail closed with
  `Arm64DecodeError::UnsupportedEncoding`.
- `TBZ/TBNZ` bit positions are not yet conveyed to semantics (phase-1
  semantics models bit 0); the decoder emits the tested bit in a follow-up
  refinement.
- Runtime/engine wiring (`angryier-runtime` still instantiates the XED
  decoder); ANG-090 covers the AArch64 symbolic engine integration.

## Companion crate

`angryier-semantics-arm64` provides handwritten semantic providers for the
decoded forms (NZCV computation for `ADDS/SUBS/ANDS`, condition-code
evaluation for `B.cond`, load/store effective-address construction) plus the
`Arm64CorpusRegistry` (rule base `0x2000`).

## Scalar FMOV-immediate increment

The phase-1 lists above are historical, not the current coverage contract; see
[the project roadmap](../../ROADMAP.md) for subsequent ARM64 waves.
Scalar `FMOV S/Dn, #imm` now accepts all 256 immediate patterns per precision,
including negative values and fractional mantissas, for every destination.
The decoder uses the fixed mask/value `0xFFA01FE0 / 0x1E201000` and bit-exact
`VFPExpandImm`; bits 20:13 are the immediate, not opcode or precision fields.
Reserved sf/type/Rn fields do not alias these forms. This does not add FP16 or
vector-immediate forms. Golden tests cover 16,384 positive combinations and
fixed-field mutations; runtime tests execute all 512 values and check the full
128-bit parent after dirtying its S/D aliases.

## DUP and signed integer-to-float increment

`DUP` covers vector element broadcasts (64/128-bit destinations), GPR broadcasts
of low B/H/S/D values, and scalar element copies (including the `MOV` aliases).
All valid source lane indices are represented by register views into the full
128-bit parent. Q=0/D vector arrangements and zero/size-4 selectors remain
reserved. For the GPR form, bits above the lowest set bit of `imm5` are **ignored**,
not reserved; noncanonical selectors are accepted too. WZR/XZR sources are zero
without reading their mutable backing slot; V31 is a normal vector register.
Providers reuse existing Extract/Concat bit-vector operations, with no new
vector primitive. Narrow and 64-bit results clear the rest of the vector parent.

Non-fixed-point `SCVTF` covers W/X→S/D, scalar S/D integer-bit sources, and
vector 2S/4S/2D forms. `FloatingOp::FromIntSigned` (new stable serialization tag
19) lowers to `FFromIntSigned`; inputs remain signed Bits(32/64), not float
interpretations of the source register. Concrete execution and constant
symbolic/concolic folding cast directly to the destination format, avoiding
i64→f64→f32 double rounding. Only default round-to-nearest, ties-to-even is
modeled; FPCR alternatives, FPSR/exception effects, unsigned/fixed-point/FP16
forms are not implemented by this increment. Nonconstant conversion expressions,
including concrete-seeded symbols, produce fresh results with explicit debt in
both evaluators, not a floating-point solver proof. Vector providers convert each
signed lane before concatenation; in-place sources are read before writing.

New providers are appended after earlier groups to preserve existing receipt
rule IDs. Tests cover 158,720 valid DUP/SCVTF encoding/register combinations,
invalid-family boundaries, 430 synthetic runtime cases checking full parent
registers, and an integer-only nearest-even oracle over boundaries and 4,096
pseudorandom inputs for all four scalar width combinations.

## Evidence-aware static census

From the Angryier repository root:

```sh
cargo run -p angryier-arch-arm64 --example a64_census -- LISTING.txt \
  --fde-ranges FDE-RANGES.txt --data-ranges DATA-RANGES.tsv
cargo test -p angryier-arch-arm64 --example a64_census
```

Both metadata options are optional. The first summary retains the raw listing
word counts, including data; they measure decoder acceptance, **not semantic
correctness, execution, or a code/data classifier's accuracy**. All input is
read statically; no target code is loaded into the runtime or executed.
The subsequent buckets separate:

- `code_candidate`: a full four-byte word inside an unwind FDE PC range. This
  is function-bound evidence, not proof of reachability or instruction identity.
- `known_data`: a full word inside an explicit analyst-supplied data range.
  Data annotations take priority over FDE bounds, which can contain literal pools.
- `unclassified`: no sufficient range evidence, including partial-word data
  intersections. Absence of an FDE does **not** imply data; assembly functions
  can lack unwind records.

Each bucket independently reports listing `named`, `undefined` (`.inst` or
`<unknown>`), and `directive` words, with accepted/rejected counts. An undefined
listing label is not automatically treated as data, and a recognized mnemonic
is not proof of code. Separate rejected-mnemonic histograms for code candidates
and unclassified words help avoid prioritizing random data as an ISA backlog.

`--fde-ranges` accepts extracted readelf FDE records, one per line, for example:

```text
00000018 00000014 0000001c FDE cie=00000000 pc=000000000062a048..000000000062a0b0
```

Ranges are half-open; unsorted/overlapping FDE intervals are unioned. This input
is an FDE-only extract, not an entire readelf frame dump containing CIE records.
`--data-ranges` accepts hexadecimal `START END EVIDENCE` records (with or without
`0x`), also half-open. Blank lines and `#` comments are allowed in both files.
Missing evidence, reversed/empty ranges, overlapping data annotations, malformed
records and read failures return errors rather than plausible partial totals.

The manually byte-verified Titan attribution-string annotation is pinned to its
sample SHA-256 in
[`docs/status/titan-census-data-ranges.tsv`](../../docs/status/titan-census-data-ranges.tsv).
The tool does **not** automatically validate that hash or authenticate metadata;
use annotations only with their matching listing/sample. The fixture marks just
72 bytes, not the much larger suspicious mixed/undefined region.

For the existing static artifacts:

```sh
cargo run -p angryier-arch-arm64 --example a64_census -- \
  ../../Samples/Analysed/ELF/libraries/titan/05-raw-exports/titan.aarch64.disasm.txt \
  --fde-ranges ../../Samples/Analysed/ELF/libraries/titan/05-raw-exports/titan.fde-ranges.txt \
  --data-ranges docs/status/titan-census-data-ranges.tsv
```
