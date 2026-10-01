# Deployment Contract

What a downstream host needs to know to run the Angryier benchmark and
scripting surfaces. Two constraints, both learned the hard way on the
730xd buildout (2026-10-01).

## 1. Corpus locations: `CORPUS_DIR` / `FIXTURE_DIR`

The corpus benchmarks and the `corpus_exec` sweep read two fixture roots:

| Env var     | Contents                          | Default (if unset)                                          |
|-------------|-----------------------------------|-------------------------------------------------------------|
| `CORPUS_DIR`  | curated real-driver `.sys` corpus | `~/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic` |
| `FIXTURE_DIR` | vuln/safe harness fixtures        | `~/Documents/byovd-harness/ghidra_pipeline/fixtures/bin`     |

Set at least one on any host where those defaults do not exist. Surfaces
that consume them:

- `cargo test -p angryier-runtime --features xed --test corpus_exec` —
  sweeps both roots.
- `scripts/gate_j_corpus.py` — `CORPUS_DIR` env var > `--corpus-dir` flag
  > default; `FIXTURE_DIR` env var > default. The effective roots are
  exported to the `corpus_exec` subprocess so the Angryier leg resolves
  the same drivers as the angr leg.
- `scripts/gate_j_bench.py` — the default driver is
  `$CORPUS_DIR/GVCIDrv64.sys`; the sweep leg uses the driver's directory
  as `CORPUS_DIR` unless one is already set.

Behavior when a root is missing — never silent:

- `corpus_exec` prints one `SKIP: <VAR> fixture root not found (looked
  for <path>)` line per missing root and sweeps the rest; with no roots
  at all it prints a skip banner naming every path looked for and passes
  (an absent corpus is not a failure, but it is never a measurement).
- `gate_j_corpus.py` warns per missing root (path + env var), and exits 1
  listing every path looked for when no root exists.

## 2. Lua `u64` convention: `_hex` fields

Lua 5.4 integers are signed 64-bit. The engine's Rust values are `u64`,
and mlua pushes a `u64` above `i64::MAX` as a Lua *float* (double) —
exact only to 2^53. Kernel pointers (`0xffff8000...` pool base, kernel
stacks) therefore cannot round-trip through numeric fields: `&` masks and
`string.format("%x", ...)` both fail on the delivered float.

Convention: every address-bearing value the scripting surface exposes
also appears as a `<name>_hex` sibling — a Lua string, lowercase,
`0x`-prefixed, zero-padded to 16 hex digits, exact for all 64 bits.
Numeric fields remain for compatibility and are exact Lua integers up to
`i64::MAX` only.

- `angry.run(...)` result table: `entry_rsp_hex`, `trace_hex[i]`,
  `kernel.double_frees[i].pointer_hex` / `.caller_hex`,
  `unsupported_sites[i].pc_hex`, `unmapped_sites[i].address_hex` /
  `.page_hex`, `ro_write_reverts[i].address_hex`, and `regs_hex[id]`.
- Session/state accessors: `st:pc_hex()`, `st:reg_hex(name)`,
  `st:regs_hex()`, `st:trace_hex()` (also on the session as shortcuts).

Scripts that format, mask, or compare kernel addresses must use the
`_hex` forms; see `docs/LUA_API.md` for the field reference.
