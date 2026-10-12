# ISANITY runtime handoff slice

This additive runtime bridge currently contains the pinned ISANITY identities
for long64 REX.W, register-direct MOV/ADD/SUB/CMP, the complete 16-condition
near-Jcc rel32 family, 18 exact fixed-ModRM zero-explicit-operand forms, and
24 MOV opcode-register selector identities. The exact-witness table includes
316 mapped long64 identities, including all 241 records in ISANITY's primary
register-direct slice, source-derived zero-operand SETSSBSY, XRESLDTRK, and
XSUSLDTRK, and the MOV B0..BF selector witnesses. The shared access model
preserves XED's conditional-write action as `AccessKind::ConditionalWrite`,
allowing the 48 CMOVcc width identities to retain that source distinction.
The three fixed-opcode identities and the register-direct mappings require an
exact pinned byte witness, matching XED IFORM name and value, long64 mode, and
operand metadata where representable.
Canonical identities remain separate from Angryier's existing legacy form IDs;
the old `form_map::map_form` behavior is unchanged. The Jcc and fixed-ModRM
resolvers do not require or invent a legacy form ID.

Generate or verify the checked-in runtime snapshot from the sibling ISANITY
checkout:

```sh
python3 tools/isanity-map/generate.py --catalogue ../ISANITY/catalogue/canonical/x86-register-direct-v2.json
python3 tools/isanity-map/generate.py --catalogue ../ISANITY/catalogue/canonical/x86-register-direct-v2.json --check
python3 tools/isanity-map/generate_branch.py
python3 tools/isanity-map/generate_branch.py --check
python3 tools/isanity-map/generate_fixed_modrm.py
python3 tools/isanity-map/generate_fixed_modrm.py --check
python3 tools/isanity-map/generate_exact_forms.py
python3 tools/isanity-map/generate_exact_forms.py --check
python3 tools/isanity-map/generate_accumulator_immediates.py
python3 tools/isanity-map/generate_accumulator_immediates.py --check
```

Runtime callers pass the same XED decode's IFORM name, explicit operand widths
and accesses, execution mode, complete instruction bytes, and existing legacy
form ID to `angryier_runtime::isanity_handoff::resolve` (or
`resolve_decoded`). Canonical-to-legacy lookup is exact; legacy-to-canonical
lookup reports both opcode directions as ambiguous. Unsupported modes,
encodings, widths, IFORMs, or mismatched legacy IDs remain unresolved.

This is identity provenance and a handoff mechanism only. ISANITY marks these
records' semantic status as unmapped and fidelity as unassessed; no semantic
coverage claim follows from the table. Conditional-write metadata records only
that the destination may be written; it does not encode the predicate or
promote semantic/fidelity status.

The exact-witness generator consumes the regular canonical identity slices
plus the primary register-direct slice and three-record zero-operand
fixed-opcode census. It verifies that the primary register-direct records are
bound to their source digest and valid XED long64 observations, and that the
fixed-opcode census records agree with their pinned candidate-evidence
artifact, including FormId, canonical bytes, source pattern, and concrete XED
byte witnesses. When multiple canonical identities share an IFORM, exact
bytes disambiguate; collisions are retained as explicit unmapped records.
Recognition is limited to witnessed byte strings; it does not assert the
complete legal encoding space or instruction semantics.

The same generator also consumes the separately hash-pinned
x86-mov-opcode-register-v2.json slice and its candidate-generator digest.
It checks each B0..B7/B8..BF source selector against the exact IFORM/value,
opcode byte, long64 runtime observation, register/immediate widths and
accesses, complete bytes, and canonical FormId. The B8..BF IFORM has both
default-32 and REX.W-64 identities per selector; exact opcode bytes and
decoded operand metadata distinguish those identities. Only the 24 recorded
long64 witnesses are recognized; REX.B extension, 16-bit, non-long64, other
prefix, semantics, and fidelity claims remain excluded/unassessed.

The Jcc table is generated from both source-backed conditional-branch
catalogues. It verifies the pinned source-forms artifact, source lock, source
pattern path, canonical-byte equality and FormId digest, then requires exactly
one source identity for each opcode condition code. Runtime matching accepts
only six-byte `0F 80..8F rel32` inputs whose IFORM comes from decoding those
same bytes. One source-permitted `2E` or `3E` branch-hint prefix is accepted;
short branches, other prefixes, and mismatched opcodes remain unresolved. It is
identity handoff only: it does not assert
semantic validation or fidelity.

The fixed-ModRM table is generated from
`x86-fixed-modrm-v2.json`. Its generator checks the canonical-byte/FormId
hashes, pinned source-forms artefact, XED toolchain lock against Angryier's
`Cargo.lock`, the exact source-pattern digest and opcode/MOD/REG/RM selectors,
and a byte-for-byte XED runtime witness including IFORM and decoded length.
At runtime `isanity_fixed_modrm::resolve_decoded` requires the IFORM and
normalized decode to come from those same bytes, long64 mode, and zero explicit
operands. It rejects every prefix and any opcode, ModRM, length, or IFORM
mismatch. This is deliberately a byte-exact identity slice, not a claim that
all forms for those mnemonics or their semantics are covered; ISANITY still
marks its semantics unmapped and fidelity unassessed.

The accumulator-immediate adapter consumes the hash-pinned 63-record IMM8
and 135-record SIMMz ISANITY candidate slices. It maps 90 identities for the
three execution modes Angryier models (`long64`, `legacy32`, `legacy16`),
discriminating same-IFORM cells by exact mode, operand width, prefix, opcode,
immediate width, and the decoder's IFORM name/value. XED is exercised across
all 90 mode/width/opcode cells and five representative immediate values per
cell; arbitrary immediate bytes retain the same identity only when the
decoder returns that exact IFORM and the encoded length/prefix/opcode/explicit
immediate metadata match. The remaining 108 compatibility/real-mode
identities remain available through
`isanity_accumulator_immediates::unsupported_identities()` with an
`unsupported-execution-mode` reason; they are not silently folded into a
supported mode. All 198 records remain candidate-only (semantic status
unmapped, fidelity unassessed), and this adapter adds no semantics.

The opcode-82 SIMM8 ModRM adapter consumes the hash-pinned 66-record
`x86-simm8-nonlong64-v2.json` slice. It maps the 11 `legacy32` IFORM-mode
tuples that Angryier's decoder and operand-normalization path can select.
Although a legacy16 selector exists, XED normalization rejects its 16-bit
memory-address metadata; the 11 such identities are retained with that reason,
alongside 44 `compat16`, `compat32`, `real16`, and `real32` records. Recognition
checks exact XED IFORM name/value, selected mode, LOCK-prefix class, opcode,
memory ModRM extension, and explicit memory/signed-immediate operand metadata.
Source identities remain unmapped semantically and unassessed for fidelity.
Regenerate and verify with `python3 tools/isanity-map/generate_nonlong_simm8.py`
and its `--check` mode.

The non-long64 UIMM8 slice in `x86-uimm8-nonlong64-v2.json` is consumed by
`isanity_uimm8_modrm`. Its 4 legacy32 identities are selectable by the current
decoder; the remaining 20 mode-specific identities are retained as
reason-coded unsupported (legacy16 normalization and compatibility/real-mode
selectors are unavailable). This adapter accepts only each row's exact pinned
profile witness bytes, exact XED IFORM name/value, mode, and unsigned explicit
immediate metadata. These are source/profile-derived candidate identities,
not semantic implementations or fidelity evidence. Regenerate and verify with
`python3 tools/isanity-map/generate_nonlong_uimm8.py` and `--check`.

The pinned UIMM32 XOP memory candidate slice is consumed by
`isanity_uimm32_memory`. It retains the 15 source-derived identity rows and
maps six identities through exact accepted XED profile witnesses in the
explicitly selectable long64 and legacy32 modes. Nine identities remain
reason-coded unsupported: legacy16 fails Angryier's current 16-bit memory
address normalization, 16-bit-address override witnesses under legacy32 are
excluded, and compat16/32 cannot be distinguished from legacy modes by the
current machine-mode API. The adapter preserves all 57 chip-profile decoder
rejects plus those 12 16-bit-address witnesses in a reason-coded profile
residue table. Callers must provide mode explicitly and no width-based mode
inference is performed. The
adapter additionally checks the XED IFORM name/value and explicit register,
memory, and unsigned-UIMM32 operand metadata. The records remain
candidate-only—semantics are unmapped and fidelity is unassessed. Regenerate
and verify with `python3 tools/isanity-map/generate_uimm32_memory.py` and
`--check`.

The reviewed ISANITY x87 memory sidecar is consumed by `isanity_x87_memory`.
It retains all 371 candidate identities across seven source modes, but maps
only the 53 exact long64 witnesses verified by Angryier's pinned XED provider.
Recognition requires caller-supplied `InstructionMode::Long64`, exact witness
bytes, exact XED IFORM name/value, and a successful normalized decode with an
explicit memory operand. The other 318 legacy/compatibility/real-mode rows
remain individually reason-coded unsupported; modes are never inferred from
bytes. Each row has one concrete `MOD=0, RM=0` witness, not general ModRM or
addressing coverage. The source candidate parser status remains partial. This
slice establishes no encoding legality, semantics, or fidelity. Regenerate
and check with `python3 tools/isanity-map/generate_x87_memory.py` and
`--check`.

The pinned fixed-opcode immediate scout is consumed by
`isanity_fixed_opcode_immediates`. It maps exactly four `long64` port-I/O
identities—IN AL, IN OeAX, OUT AL, and OUT OeAX—with all 256 UIMM8 byte
witnesses per identity. Resolution requires explicit `InstructionMode::Long64`,
the explicit pinned provider identity (`Intel XED`, `xed-sys 0.6.0+xed-2024.05.20`),
exact witness bytes, XED IFORM name/value, full two-byte length, and the full
normalized operand list, including implicit accumulator register metadata,
explicit unsigned UIMM8 metadata, and the provider's suppressed RFLAGS entry.
Immediate values are checked without narrowing, so values above 255 cannot
alias a witness by sharing its low byte.
The other 36 mode-qualified candidate identities remain individually
reason-coded unsupported. AAD/AAM receive explicit source-mode exclusions in
long64 because their source pattern requires `not64`; they are never collapsed
into a long64 identity. This establishes no semantics, legality, fidelity,
profile support, or prefix-combination coverage. Regenerate and check with
`python3 tools/isanity-map/generate_fixed_opcode_immediates.py` and `--check`.

The direct-ModRM UIMM16/UIMM32 identity slice is consumed by
`isanity_uimm16_32_direct_modrm`. It retains all 17 mode-qualified candidate
identities and 416 exact XED witnesses, mapping nine legacy/long-mode rows
(240 witnesses) where the current decoder exposes a distinct mode and the
ordered source operands. Six compatibility-mode rows (160 witnesses) remain
unsupported because the decoder cannot distinguish compatibility from the
corresponding legacy mode. URDMSR/UWRMSR long64 (two identities, 16 witnesses)
remain explicitly unobservable because the normalized XED operand list omits
their source-declared implicit MSR register; they are not partially mapped.
The adapter validates provider/version/default-chip provenance, exact mode,
IFORM name/value, complete witness bytes and length, unsigned immediate width
and value, and source-bound ModRM register selectors. Its provider-only
suppressed-RFLAGS projection is separately pinned per IFORM (one for BEXTR and
LWPINS, zero for LWPVAL); mutation tests reject missing, duplicate, or altered
entries. The generated evidence retains all 1,024 profile residues and 10,249
source exclusions. Candidate semantics remain unmapped and fidelity remains
unassessed. Regenerate and check with
`python3 tools/isanity-map/generate_uimm16_32_direct_modrm.py` and `--check`.
