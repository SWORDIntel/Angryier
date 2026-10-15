--[[
    symex_target.lua — Generalized Goal-Directed Symbolic Exploration Driver
    Angryier Symbolic & Concolic Execution Framework

    Usage:
        ANGRY_TARGET=binary.exe angryier run binary.exe --script scripts/lua/symex_target.lua
        Or edit the TARGET and campaign configuration options below.
--]]

-- ============================================================================
-- Campaign Configuration
-- ============================================================================

local TARGET = os.getenv("ANGRY_TARGET") or "target.exe"

local OPTS = {
    -- Starting execution address (nil or 0 uses binary entry point)
    entry = nil,

    -- Target addresses to discover (array of integers or hex numbers)
    find = {},

    -- Unwanted / error branch addresses to prune
    avoid = {},

    -- Registers to mark as 64-bit symbolic inputs
    -- Example: { rcx = 64, rdx = 64 }
    symbolic = {},

    -- Initial concrete register values
    -- Example: { rax = 0, rbx = 0x1000 }
    regs = {},

    -- Exploration budget limits
    steps = tonumber(os.getenv("ANGRY_STEPS")) or 5000,
    states = tonumber(os.getenv("ANGRY_STATES")) or 32,
    timeout_secs = tonumber(os.getenv("ANGRY_TIMEOUT")) or 60,

    -- Exploration strategy: "fork" (worklist) or "dfs"
    exploration = "fork",

    -- SMT constraint solving: extract concrete models on find hits
    solve = true,

    -- Relaxations for under-constrained execution
    uc_memory = true,         -- Read unmapped pages as zero instead of faulting
    zero_low_pages = true,    -- Map 0x0..0x10000 to catch NULL-deref sentinels
    uc_write_ro = false,      -- Drop or allow writes to read-only sections

    -- Memory pokes performed prior to execution
    -- Array of { addr = 0x..., value = 0x... }
    poke = {},

    -- File-backed bulk memory loads (e.g. process dump segments or globals)
    -- Array of { addr = 0x..., path = "path/to/slice.bin" }
    load_mem = {},

    -- Memory dump output upon completion
    -- Example: { addr = 0x140000000, len = 0x1000, path = "dump.bin" }
    memory_dump_out = nil,
}

-- ============================================================================
-- Utility Formatting Helpers
-- ============================================================================

local function hex_format(val)
    if type(val) == "string" then return val end
    if type(val) == "number" then
        return string.format("0x%x", val)
    end
    return tostring(val)
end

local function print_banner(title)
    print(string.rep("=", 78))
    print("  " .. title)
    print(string.rep("=", 78))
end

local function format_hex_ascii(raw_bytes)
    if not raw_bytes or #raw_bytes == 0 then return "<empty>" end
    local hex_parts = {}
    local ascii_parts = {}
    for i = 1, #raw_bytes do
        local b = raw_bytes:byte(i)
        hex_parts[#hex_parts + 1] = string.format("%02x", b)
        if b >= 32 and b <= 126 then
            ascii_parts[#ascii_parts + 1] = string.char(b)
        else
            ascii_parts[#ascii_parts + 1] = "."
        end
    end
    return string.format("%s  |%s|", table.concat(hex_parts, " "), table.concat(ascii_parts, ""))
end

-- ============================================================================
-- Execution Driver
-- ============================================================================

print_banner("Angryier Symbolic Exploration: " .. TARGET)
if OPTS.entry then
    print(string.format("  Entry override   : 0x%x", OPTS.entry))
else
    print("  Entry override   : (default binary entry)")
end
print(string.format("  Budget           : %d steps, max %d states, %d s timeout",
    OPTS.steps, OPTS.states, OPTS.timeout_secs))
print(string.format("  Find targets     : %d configured", #OPTS.find))
print(string.format("  Avoid targets    : %d configured", #OPTS.avoid))
print(string.format("  Memory loads     : %d file slice(s)", #OPTS.load_mem))
print(string.rep("-", 78))

local start_clock = os.clock()
local r = angry.run(TARGET, OPTS)
local elapsed = os.clock() - start_clock

-- ============================================================================
-- Telemetry & Verdict Report
-- ============================================================================

print_banner("Exploration Results (Wall time: " .. string.format("%.2f s", elapsed) .. ")")
print(string.format("  Steps completed  : %s", tostring(r.steps or 0)))
print(string.format("  Forks created    : %s", tostring(r.forks or 0)))
print(string.format("  Merges           : %s", tostring(r.merges or 0)))
print(string.format("  Terminated paths : %s", tostring(r.terminated or 0)))
print(string.format("  Failed paths     : %s", tostring(r.failed or 0)))
print(string.format("  Pruned paths     : %s", tostring(r.pruned_states or 0)))
print(string.format("  Live states      : %s", tostring(r.live_states or 0)))
print(string.format("  Find hits        : %s", tostring(r.found or 0)))
print(string.format("  Timed out        : %s", tostring(r.timed_out or false)))
print(string.format("  Solver retries   : %s", tostring(r.concretization_retries or 0)))

if r.rax_exit ~= nil then
    print(string.format("  Exit RAX         : 0x%x (%d)", r.rax_exit, r.rax_exit))
end
if r.exit_pc ~= nil then
    print(string.format("  Exit PC          : 0x%x", r.exit_pc))
end
if r.exit_kind ~= nil then
    print(string.format("  Exit Kind        : %s", tostring(r.exit_kind)))
end
if r.last_error ~= nil then
    print(string.format("  Last Error       : %s", tostring(r.last_error)))
end

-- ============================================================================
-- SMT Solution Extraction
-- ============================================================================

if r.inputs and #r.inputs > 0 then
    print(string.rep("-", 78))
    print(string.format("SMT Models Recovered (%d solution(s)):", #r.inputs))
    for i, input_data in ipairs(r.inputs) do
        print(string.format("  Solution #%d: %s", i, format_hex_ascii(input_data)))
    end
elseif (r.found or 0) > 0 then
    print(string.rep("-", 78))
    print("Find target was reached, but no symbolic input variables were parameterized.")
end

-- ============================================================================
-- Execution Trace Tail
-- ============================================================================

local trace = r.trace_hex or r.trace or {}
local n_trace = #trace
if n_trace > 0 then
    print(string.rep("-", 78))
    local display_count = math.min(12, n_trace)
    local from_idx = n_trace - display_count + 1
    print(string.format("Execution Trace (%d total blocks, showing last %d):", n_trace, display_count))
    for i = from_idx, n_trace do
        print(string.format("  [%04d] %s", i - 1, hex_format(trace[i])))
    end
end

-- ============================================================================
-- Under-Constrained & Semantic Debt Audit
-- ============================================================================

local has_debt = false
if r.unmapped_sites and #r.unmapped_sites > 0 then
    if not has_debt then print(string.rep("-", 78)); has_debt = true end
    print(string.format("Under-Constrained Memory Accesses (%d unmapped site(s)):", #r.unmapped_sites))
    for i = 1, math.min(10, #r.unmapped_sites) do
        local site = r.unmapped_sites[i]
        print(string.format("  Site #%d: PC=%s TargetAddr=%s",
            i, hex_format(site.pc or site.pc_hex), hex_format(site.address or site.address_hex)))
    end
end

if r.ro_write_reverts and #r.ro_write_reverts > 0 then
    if not has_debt then print(string.rep("-", 78)); has_debt = true end
    print(string.format("Read-Only Page Write Interceptions (%d site(s)):", #r.ro_write_reverts))
    for i = 1, math.min(5, #r.ro_write_reverts) do
        local ro = r.ro_write_reverts[i]
        print(string.format("  RO Write #%d: Addr=%s", i, hex_format(ro.address or ro.address_hex)))
    end
end

print(string.rep("=", 78))
return r
