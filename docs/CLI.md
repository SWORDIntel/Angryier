# Angryier CLI Reference

> Binary: `angryier` (crate `angryier-cli`). The default build is dependency-free Rust — `version`, `status`, `crates`, and `help` work anywhere. The `run` subcommand (symbolic/concolic execution, optionally driven by an embedded Lua script) is a feature-gated build that pulls native decoding (Intel XED) and solver (Z3) dependencies.
>
> Source of truth: `crates/angryier-cli/src/main.rs` (argument parsing) and `crates/angryier-runtime/src/script.rs` (the Lua surface).

---

## Build and install

The workspace builds with stable Rust (`rust-toolchain.toml` pins the channel). Build matrix:

| Build | Command | Native requirements |
|---|---|---|
| Metadata-only (default) | `cargo build -p angryier-cli` | None. Pure `std`, zero dependencies. |
| With `run` | `cargo build -p angryier-cli --features run` | C/C++ toolchain (mlua compiles vendored Lua 5.4; `xed-sys` builds Intel XED from source) and the system `libz3` (linked by `z3-sys`, e.g. `apt install libz3-dev`). |

The `run` feature enables `angryier-runtime/xed` (native Intel XED decoding) and `angryier-runtime/script` (Lua + the native Z3 backend). Without it, `angryier run` prints a rebuild hint and exits 1.

To run from a checkout without installing:

```bash
cargo run -p angryier-cli -- status
cargo run -p angryier-cli --features run -- run ./target-fixture --symbolic rdi
```

The binary name is `angryier`; `cargo install --path crates/angryier-cli` (add `--features run` for the execution subcommand) installs it into `~/.cargo/bin`.

---

## Commands

```
Usage: angryier <command>

Commands:
  version    Print version information
  status     Print workspace status summary
  crates     List all crates with implementation status
  run        Execute a binary symbolically
  help       Print this help message
```

`angryier` with no arguments prints a one-line brief and exits 0. `-h` and `--help` are aliases for `help`. An unknown command prints an error to stderr and exits 1.

| Command | Output | Exit |
|---|---|---|
| `version` | `Angryier 0.1.0` | 0 |
| `status` | Workspace summary: 39 crates (37 implemented, 2 scaffolded), historical test totals | 0 |
| `crates` | One line per workspace crate: name, `Implemented`/`Scaffolded`, short description | 0 |
| `help`, `-h`, `--help` | The usage text above | 0 |
| *(none)* | One-line brief (version + tagline) | 0 |
| `run ...` | See below; requires the `run` feature | 0/1 |
| anything else | `error: unknown command '<cmd>'` on stderr | 1 |

Note: `help` always lists `run`. In builds without the feature its line reads `Not in this build (rebuild with --features run)`; in feature builds it reads `Execute a binary symbolically`.

---

## `angryier run` — execute a binary symbolically

```
usage: angryier run <binary> [--script f.lua] [--symbolic REG] [--find ADDR] [--argv N] [--dynamic]
note: --find ADDR is hexadecimal, 0x prefix optional
```

Loads an ELF64 image into the engine and runs it concretely/symbolically. The binary is loaded statically by default (`load_elf`); with `--dynamic` the dynamic-linking environment model is used (`load_elf_dynamic`).

### Flags

| Flag | Repeatable | Meaning |
|---|---|---|
| `<binary>` (positional) | — | Path to the ELF64 image to execute. Required, even when `--script` is given (the script chooses whether to reference it). |
| `--script f.lua` | no | Lua driver script (see the Lua API below). When set, the script has full control; the other flags are still validated but their values are unused. |
| `--symbolic REG` | yes | Mark a general-purpose register symbolic before execution. `REG` is one of `rax rcx rdx rbx rsp rbp rsi rdi r8`–`r15`; other names exit 1 with an error. Always marked 64 bits wide. |
| `--find ADDR` | yes | Add a target address (hexadecimal, `0x` prefix optional) to the exploration policy's find set. Non-hex values exit 1 with an error. |
| `--argv N` | no | Symbolize `argv[0]` as `N` bytes (the model materializes `N` bytes, NUL-terminated, on the initial stack). Non-numeric values exit 1 with an error. |
| `--dynamic` | no | Load via the dynamic-linking path (`__libc_start_main` hook, `main(argc, argv)` entry) instead of static `_start`. |

Address parsing for `--find` is hexadecimal with an optional `0x` prefix: `--find 0x40102a` and `--find 40102a` are equivalent, and `--find 1234` means address `0x1234`.

### The default driver

Without `--script`, the CLI synthesizes this Lua driver and evaluates it:

```lua
local r = angry.run("<binary>", { symbolic = { <regs marked 64-bit> },
                                  find = { <find addresses> },
                                  [argv = N,] [dynamic = true,]
                                  steps = 1024, states = 16 })
print(string.format("steps=%d forks=%d merges=%d terminated=%d found=%d",
                    r.steps, r.forks, r.merges, r.terminated, r.found))
```

So the CLI-flag defaults are `steps = 1024`, `states = 16`, solver off (found targets are counted, not solved — use `--script` with `solve = true` to get models). Note these defaults differ from the Lua API's own defaults (`steps = 256`).

### Exit codes

| Code | Cause |
|---|---|
| 0 | Driver/script evaluated successfully. |
| 1 | Missing `<binary>` positional; unknown flag (e.g. a typo); a flag missing its value; invalid `--symbolic` register; non-numeric `--argv`; non-hex `--find`; `--script` file unreadable; Lua init/eval error; or the binary was built without the `run` feature. |

Argument errors are prefixed `error:` followed by the `usage:` text on stderr; the remaining errors are prefixed `script init:`, `read <path>:`, or `script:`.

---

## Lua API (`angry` library)

Every driver script — the synthesized one or a `--script` file — runs in a fresh Lua 5.4 VM with a global `angry` table.

### `angry.run(path, opts) -> table`

Loads `path`, applies the symbolic-input configuration, explores, and returns a report table. The exploration itself is wall-clock capped at 30 seconds.

Options table (all fields optional):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `symbolic` | table | `{}` | Registers to mark symbolic. Either `{ rdi = 64 }` or `{ "rdi" }`. Values are accepted for documentation but the mark is always 64-bit. Valid names: the 16 GPRs listed above. |
| `find` | array of integer | `{}` | Target PCs; reaching one records a found state. |
| `avoid` | array of integer | `{}` | Avoid PCs for the exploration policy. |
| `steps` | integer | `256` | Instruction-step budget. |
| `states` | integer | `16` | Maximum live states. |
| `solve` | boolean | `false` | Solve each found state with the native Z3 backend and populate `inputs`. |
| `dynamic` | boolean | `false` | Dynamic-linking load path instead of static. |
| `argv` | integer | — | Symbolize `argv[0]` as this many bytes. |
| `files` | table name → `true` | — | Paths whose opens are backed by symbolic bytes (reads yield symbols instead of hitting the host). |
| `contents` | table name → string | — | Concrete file contents to inject into the environment model. |

Result table:

| Field | Meaning |
|---|---|
| `steps`, `forks`, `merges`, `terminated`, `failed` | Run counters. |
| `live_states` | States still live when the budget/limits ended the run. |
| `found` | Number of states that reached a `find` target. |
| `inputs` | Only with `solve = true`: one entry per solved found state, each an array of byte-strings (model bytes per symbol). Per-state model solving is capped at 10 seconds. |
| `regs` | Only when at least one state was found: the first found state's register bindings, keyed by engine register ID (rax = 0 … r15 = 15), values are integers for concretely-bound registers. |

### `angry.open(path) -> session`

REPL-style handle to a live symbolic session (static load). Methods:

| Call | Returns |
|---|---|
| `s:step()` | `"stepped"`, `"branched"`, or `"terminated"` (single step of state 0). |
| `s:pc()` | Current program counter of state 0. |
| `s:reg("rdi")` | Concrete register value, or `nil` when the register is symbolic. |
| `s:states()` | Number of live states. |
| `s:symbolic("rdi")` | Marks the register symbolic on state 0 (64-bit). |

### `angry.version()`

Returns the `angryier-runtime` crate version string.

---

## Examples

**Workspace status:**

```bash
$ cargo run -p angryier-cli -- status
Angryier 0.1.0 — Rust-native multicore symbolic/concolic execution engine

Workspace: 39 crates
Implemented: 37 crates with real logic
Scaffolded: 2 crates (contract boundaries, fail-closed)

Tests: 585 tests across 78 suites (0 failures, historical count)
```

**Symbolic run with a find target (CLI flags):** fork on symbolic `rdi`, hunt for the success branch at `0x40102a`, symbolize 8 bytes of `argv[0]`:

```bash
cargo run -p angryier-cli --features run -- run ./crackme \
    --symbolic rdi --find 0x40102a --argv 8
# steps=... forks=... merges=... terminated=... found=1
```

**Lua-scripted run with solving** — `find.lua`:

```lua
local r = angry.run("./crackme", {
    symbolic = { rdi = 64 },
    find     = { 0x40102a },   -- success branch
    avoid    = { 0x40103b },   -- failure exit
    argv     = 8,              -- symbolize argv[0]
    solve    = true,           -- solve found states with Z3
    steps    = 512, states = 32,
})
print(string.format("found=%d forks=%d steps=%d", r.found, r.forks, r.steps))
for i, input in ipairs(r.inputs) do
    print(string.format("model %d: %q", i, input[1]))
end
```

```bash
cargo run -p angryier-cli --features run -- run ./crackme --script find.lua
```

**Interactive stepping** (`angry.open`):

```lua
local s = angry.open("./demo")
s:symbolic("rdi")
while s:step() ~= "terminated" do
    print(string.format("pc=%#x states=%d", s:pc(), s:states()))
end
```

---

## Known quirks

- The `run` parser is strict: anything not listed in the usage line (including mistyped flags and flags without a value) exits 1 instead of being dropped. The one exception is a repeated `<binary>` positional, where the last path wins.
- `--symbolic` width is fixed at 64 bits from the CLI; the Lua opts table's width values are likewise accepted but not used.
- The CLI `version` string and Lua `angry.version()` both derive from the workspace package version (`version.workspace = true`), so they move together; they are only as granular as that single version.
- The `status` test figures are a historical snapshot from the 2026-09 documentation pass, not a live count.
- `regs` in the `angry.run` result is keyed by numeric register ID, not by name.
