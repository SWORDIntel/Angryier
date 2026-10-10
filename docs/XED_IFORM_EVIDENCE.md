# XED Runtime IFORM Evidence Tool

The `xed_iform_evidence` tool is a lightweight batch evidence extractor that executes
Intel XED instruction decoding via `XedDecoder::decode_with_iform()` to collect raw,
version-scoped XED IFORM evidence.

## Identity Boundary Principles

1. **Raw IFORM Scoping:**
   Raw XED IFORMs are source-level enumerants defined by the pinned `xed-sys` release
   (`xed-sys 0.6.0+xed-2024.05.20`). Their numeric values and symbolic names are specific
   to this release's generated tables.
2. **No Canonical ID Assignment:**
   This tool **does not** assign canonical form identifiers (such as ISANITY FormIdentity).
   It only extracts and preserves raw decoder evidence.
3. **Engine `form_id` Separation:**
   Angryier's internal engine `form_id` maps instruction classes (`XED_ICLASS_*`).
   It must not be confused with or emitted as XED IFORM evidence.

---

## Invocation

The tool is implemented as an example target in `crates/angryier-arch-xed-ffi`, minimizing
build dependencies (no Z3, Lua, or heavy solver dependencies required):

```bash
cargo run -p angryier-arch-xed-ffi --example xed_iform_evidence -- [OPTIONS] [INPUT] [OUTPUT]
```

### Options

| Flag | Description | Default |
|---|---|---|
| `-i, --input <PATH>` | Input newline-delimited JSON file | `stdin` |
| `-o, --output <PATH>` | Output newline-delimited JSON file | `stdout` |
| `-a, --address <ADDR>` | Default base address (hex or decimal) | `0x0` |
| `-s, --summary` | Print summary count to `stderr` upon completion | Disabled |
| `-h, --help` | Print usage help documentation | |
| `-v, --version` | Print tool and decoder version | |

### Examples

**Stream through standard input / output:**

```bash
printf '{"id":"nop","bytes":"90"}\n{"id":"mov","bytes":"4889c1"}\n' \
  | cargo run -p angryier-arch-xed-ffi --example xed_iform_evidence
```

**Process files directly:**

```bash
cargo run -p angryier-arch-xed-ffi --example xed_iform_evidence -- -i input.jsonl -o output.jsonl -s
```

---

## Input Schema

Records are supplied as newline-delimited JSON (`.jsonl`), with one record per line:

```json
{"id": "<stable_id>", "bytes": "<hex_bytes>", "address": <optional_addr>}
```

- `id`: Stable identifier (can be a string, integer, or other scalar).
- `bytes`: Hexadecimal string of instruction bytes (e.g. `"90"`, `"4889c1"`, `"48 89 c1"`, `"0x90"`).
- `address`: *(Optional)* Instruction memory address in hex or decimal (defaults to `--address` option or `0x0`).

---

## Output Schema

Output is emitted as newline-delimited JSON (`.jsonl`), one record per input line, in deterministic key order:

### Successful Decode (`status: "ok"`)

```json
{
  "id": "nop",
  "bytes": "90",
  "status": "ok",
  "decoder_version": "xed-sys 0.6.0+xed-2024.05.20",
  "iform_name": "XED_IFORM_NOP_90",
  "iform_value": 1735,
  "raw_iform": {
    "name": "XED_IFORM_NOP_90",
    "value": 1735
  },
  "length": 1
}
```

### Failed Decode or Parse Error (`status: "error"`)

```json
{
  "id": "bad_case",
  "bytes": "ffff",
  "status": "error",
  "decoder_version": "xed-sys 0.6.0+xed-2024.05.20",
  "iform_name": null,
  "iform_value": null,
  "raw_iform": null,
  "error": "Intel XED decode failed"
}
```

---

## Testing & Verification

Focused unit and integration test suites verify parsing, determinism, known instruction forms,
and error handling:

```bash
# Unit tests
cargo test -p angryier-arch-xed-ffi --lib evidence

# Integration tests
cargo test -p angryier-arch-xed-ffi --test batch_evidence_integration
```
