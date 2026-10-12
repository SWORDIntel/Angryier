# ISANITY MOV GPRv-memory candidate identities

Angryier contains an additive, candidate-only recognition adapter for the
reviewed ISANITY MOV GPRv-memory package. From the Angryier repository root,
the generator reads the base package
`../ISANITY/tools/xed-gprv-mov-memory-identity/out/x86-mov-gprv-memory-package-v2.json`
and the bounded addressing observations in
`../ISANITY/tools/xed-gprv-mov-addressing/out/x86-mov-gprv-addressing-v1.json`.
The pinned base package SHA-256 is
`4c72d18360748f61b4357b89e1005b66876597bc02e4ac89008b9d1451e57800`; the
addressing evidence SHA-256 is
`8f8b5c75537d1a8a5f117432ab711f9c1e3a5e4c7bc9c48dc8517f0f11740165`.

The table contains six canonical identities across
`XED_IFORM_MOV_MEMv_GPRv` and `XED_IFORM_MOV_GPRv_MEMv`. Recognition requires
the pinned Intel XED provider/version, exact IFORM name/value, Long64 mode,
complete exact bytes and decoded length, and two ordered explicit operands
with exact kind, access, and width. The 108 witnesses comprise 18 original
direct-RAX observations plus 90 named address-case observations (15 per
identity). These include selected SIB, displacement, and address-size cases;
the sidecar's residue remains explicit, and every unlisted byte spelling is
unresolved.

This adapter assigns candidate identity only. Semantic status remains
unmapped, fidelity remains unassessed, and the sampled witnesses do not
establish legality or completeness. It is exposed as
`angryier_runtime::isanity_mov_memory` behind the `xed` feature; it does not
alter the legacy form map or semantic registry.

Regenerate/check the Rust table with:

```sh
python3 tools/isanity-map/generate_mov_memory.py
python3 tools/isanity-map/generate_mov_memory.py --check
cargo test -p angryier-runtime --features xed isanity_mov_memory --lib
```
