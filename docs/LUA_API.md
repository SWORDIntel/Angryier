# Angryier Lua Scripting API Reference

Angryier provides a powerful embedded Lua 5.4 scripting environment (Phase 15 of [`docs/ROADMAP.md`](./ROADMAP.md)) designed for dynamic symbolic execution, binary inspection, interactive debugging, and automated vulnerability research.

---

## 1. Quick Start

```lua
-- Open a binary with a symbolic register and zeroed low memory
local s = angry.open("./fixtures/crackme.elf", {
    symbolic = { rdi = 64 },
    zero_low_pages = true,
})

-- Register a hook before entering the validation routine
s:hook(0x401120, function(st)
    print(string.format("[*] Hit validation at 0x%x, constraints: %d", st:pc(), st:constraints_count()))
end)

-- Step until the target success address is reached
local outcome, steps = s:step_until(0x4011a0, 500)
if outcome == "reached" then
    print("[+] Reached success block in " .. steps .. " steps!")
    -- Recover concrete solution from SMT constraints
    local model = s:solve()
    print("[+] Solution input bytes: " .. angry.hex(model[1]))
    print("[+] Evaluated rdi: " .. string.format("0x%x", s:eval("rdi")))
end
```

---

## 2. Binary Utilities (`angry.*`)

The `angry` table provides zero-overhead binary analysis and manipulation helpers:

### `angry.version() -> string`
Returns the Cargo package version of the running Angryier engine.

### `angry.hex(bytes: string) -> string`
Encodes a raw byte string into a lowercase hexadecimal string.
```lua
local hex = angry.hex("HELLO") -- "48454c4c4f"
```

### `angry.unhex(hex_str: string) -> string`
Decodes a hex string (ignoring spaces, underscores, and optional `0x` prefix) into raw bytes. Errors if length is odd or contains invalid characters.
```lua
local raw = angry.unhex("48 45 4c 4c 4f") -- "HELLO"
```

### `angry.pack64(integer: number) -> string`
Packs a 64-bit unsigned integer into 8 bytes in little-endian order.
```lua
local raw = angry.pack64(0xdeadbeef)
```

### `angry.unpack64(bytes: string) -> number`
Unpacks the first 8 bytes of a string into a 64-bit unsigned integer (little-endian).

### `angry.pack32(integer: number) -> string`
Packs a 32-bit unsigned integer into 4 bytes in little-endian order.

### `angry.unpack32(bytes: string) -> number`
Unpacks the first 4 bytes of a string into a 32-bit unsigned integer (little-endian).

### `angry.disasm(bytes: string, [base_pc: number]) -> table`
Disassembles raw x86_64 machine code using the native Intel XED engine. Returns an array of instruction tables:
```lua
local insns = angry.disasm("\x48\x31\xc0\xc3", 0x401000)
for i, insn in ipairs(insns) do
    print(string.format("0x%x: %s (%d bytes)", insn.pc, insn.hex, insn.len))
end
```
Each instruction entry contains:
- `pc`: 64-bit instruction virtual address.
- `len` / `length`: Instruction byte length.
- `bytes`: Raw instruction byte string.
- `hex`: Space-separated hex representation.
- `form_id`: Internal semantic form ID.
- `operands_count`: Number of decoded operands.
- `invalid`: Boolean present and true if decoding failed for this byte.

---

## 3. Headless Driver (`angry.run`)

Executes an exploration campaign non-interactively and returns a summary report:

```lua
local report = angry.run("./target.elf", {
    symbolic = { rdi = 64 },          -- registers to make symbolic
    find = { 0x4011a0 },              -- target addresses to search for
    avoid = { 0x4011c0 },             -- error addresses to avoid
    steps = 1024,                     -- maximum instruction step budget
    states = 16,                      -- maximum active state pool size
    solve = true,                     -- solve constraints when target is found
    zero_low_pages = true,            -- map 0x0..0x10000 to prevent null page faults
})

print("Found target states: " .. #report.found)
for i, solution in ipairs(report.inputs) do
    print(string.format("Solution #%d: %s", i, angry.hex(solution)))
end
```

### 64-bit Values: the `_hex` Fields

Lua 5.4 integers are signed 64-bit; a Rust `u64` above `i64::MAX`
(0x7fff_ffff_ffff_ffff) is pushed as a Lua float (double), exact only to
2^53. Kernel pointers (`0xffff8000...` pool bases, kernel stacks) cannot
round-trip through the numeric fields: `&` masks and
`string.format("%x", ...)` both misbehave on the delivered float.

Every address-bearing value therefore also appears as a `<name>_hex`
sibling — a Lua **string**, lowercase, `0x`-prefixed, zero-padded to 16
hex digits, exact for all 64 bits:

- `angry.run` result table: `entry_rsp_hex`, `trace_hex[i]`,
  `kernel.double_frees[i].pointer_hex` / `.caller_hex`,
  `unsupported_sites[i].pc_hex`, `unmapped_sites[i].address_hex` /
  `.page_hex`, `ro_write_reverts[i].address_hex`, `regs_hex[id]`.
- State/session accessors: `st:pc_hex()`, `st:reg_hex(name)`,
  `st:regs_hex()`, `st:trace_hex()` (also callable directly on the
  session as active-state shortcuts).

Scripts that format, mask, or compare kernel addresses must use the
`_hex` forms; the numeric fields remain for compatibility and are exact
Lua integers up to `i64::MAX` only.

---

## 4. Interactive Session Controller (`angry.open` / `LuaSession`)

`angry.open(path, [opts])` returns a live `LuaSession` userdata handle.

### Session Configuration Options (`opts`)
- `symbolic`: Table of register names to bit widths (e.g. `{ rdi = 64 }` or `{ "rdi" }`).
- `regs`: Initial register map (e.g. `{ rax = 0, rdi = 0x1000 }`).
- `poke`: Array of `{ addr = 0x..., value = 0x... }` memory writes performed before execution.
- `symbolic_memory`: Array of `{ addr = 0x..., len = 16 }` regions to mark symbolic.
- `entry`: Override program entry PC.
- `zero_low_pages`: Boolean. Maps the low 64 KiB (0x0 .. 0x10000) as zeroed RAM.
- `uc_memory`: Boolean. Enables under-constrained memory fallback.
- `uc_write_ro`: Boolean. Allows writes to read-only sections under UC memory.

### Session Stepping & Exploration
- `s:step([n]) -> string`: Advances the active state by up to `n` basic blocks (default 1). Returns outcome string:
  - `"stepped"`: Normal step completed.
  - `"branched"`: Execution branched into multiple paths.
  - `"terminated"`: Active state terminated.
  - `"breakpoint"`: Hit a registered breakpoint.
  - `"hook_terminated"`: Aborted by a Lua hook.
- `s:step_until(target_pc, [max_steps]) -> (string, number)`: Steps iteratively until the active state reaches `target_pc` or `max_steps` is exceeded. Returns `(outcome, steps_taken)`.

### State Management
- `s:states()` / `s:states_count() -> number`: Number of currently alive states.
- `s:dead_count() -> number`: Number of terminated / dead states.
- `s:active_index([new_idx]) -> number`: Gets or sets the 0-based index of the active state.
- `s:select_state(idx) -> boolean`: Selects the state at index `idx` as active.
- `s:state([idx]) -> LuaState`: Returns a `LuaState` handle for state `idx` (defaults to active state).
- `s:dead_state(idx) -> LuaState`: Returns a `LuaState` handle for dead state `idx`.

### Breakpoints & Hooks
- `s:add_breakpoint(addr)`: Adds a breakpoint at instruction address `addr`.
- `s:remove_breakpoint(addr) -> boolean`: Removes a breakpoint.
- `s:breakpoints() -> table`: Returns an array of active breakpoint addresses.
- `s:hook(addr, fn)`: Registers a callback `fn(state)` called immediately before executing `addr`. If `fn` returns `false` or `"terminate"`, the path is immediately terminated.
- `s:unhook(addr) -> boolean`: Removes a hook.

### Active State Shortcuts
All `LuaState` inspection and mutation methods (`pc`, `pc_hex`, `reg`, `reg_hex`, `regs`, `regs_hex`, `read_bytes`, `write_bytes`, `poke`, `symbolic`, `symbolic_memory`, `trace`, `trace_hex`, `constraints_count`, `solve`, `eval`, `is_alive`) are also callable directly on `s`, forwarding to the active state.

---

## 5. First-Class State Handle (`LuaState`)

A `LuaState` represents an individual symbolic or concrete execution path. State handles track their target by unique `state_id`, making them safe against list reordering, branching, and pruning.

### Identity & Lifecycle
- `st:id() -> number`: Unique 64-bit state ID.
- `st:is_alive() -> boolean`: True if the state is still active in the session.
- `st:terminate()`: Kills this execution path and moves it to the dead states pool.

### Registers
- `st:pc([new_pc]) -> number`: Reads or writes the instruction pointer (RIP).
- `st:pc_hex() -> string`: Exact 16-digit hex form of the PC (the `_hex` convention) for kernel addresses above `i64::MAX`.
- `st:reg(name, [new_val]) -> number | nil`: Reads or writes a register by name (`"rax"`, `"rbx"`, `"rip"`, `"rflags"`, etc.).
- `st:reg_hex(name) -> string | nil`: Exact 16-digit hex form of one register value.
- `st:regs() -> table`: Returns a table mapping register names to their current 64-bit concrete values.
- `st:regs_hex() -> table`: Same map with every value as an exact hex string (includes `rip`).

### Memory
- `st:read_bytes(addr, len) -> string`: Reads `len` bytes starting at `addr` as a Lua string.
- `st:write_bytes(addr, data)`: Writes raw bytes (`string` or array table of byte numbers) to `addr`.
- `st:poke(addr, val)`: Writes a 64-bit little-endian integer `val` to `addr`.

### Symbolic Reasoning & Solvers
- `st:symbolic(name, [width])`: Marks a register symbolic (64-bit GPR).
- `st:symbolic_memory(addr, len)`: Marks `len` bytes at `addr` as fresh symbolic variables.
- `st:constraints_count() -> number`: Number of accumulated path constraints.
- `st:trace() -> table`: Returns an array of executed PC addresses in this path's trace ring.
- `st:trace_hex() -> table`: The same trace as exact 16-digit hex strings (the `_hex` convention).
- `st:solve() -> table`: Queries the native Z3 SMT solver for a satisfiable assignment to all symbolic variables on this path. Returns an array of byte strings for each symbol.
- `st:eval(name) -> number`: Solves the path constraints and evaluates the concrete 64-bit integer value for register `name`.

---

## 6. Practical Examples

### Example 1: Crackme Solver
```lua
local s = angry.open("./fixtures/crackme.elf", {
    symbolic = { rdi = 64 },
    zero_low_pages = true,
})

-- Seek success basic block
local outcome, steps = s:step_until(0x401185, 200)
if outcome == "reached" then
    local key = s:eval("rdi")
    print(string.format("[*] Found valid serial key: 0x%016x", key))
else
    print("[-] Failed to find path: " .. outcome)
end
```

### Example 2: In-Memory Unpacker
```lua
local s = angry.open("./fixtures/packed.elf", { zero_low_pages = true })

-- Break at OEP (Original Entry Point)
local OEP = 0x401000
s:add_breakpoint(OEP)

local outcome = s:step_until(OEP, 5000)
if outcome == "reached" then
    print("[+] Reached OEP! Dumping unpacked text segment...")
    local code = s:read_bytes(OEP, 0x1000)
    print("[+] First 16 bytes: " .. angry.hex(code:sub(1, 16)))
end
```
