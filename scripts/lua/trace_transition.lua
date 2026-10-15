--[[
    trace_transition.lua — Boundary & Execution Transition Analyzer
    Angryier Symbolic & Concolic Execution Framework

    Usage:
        ANGRY_TARGET=binary.exe angryier run binary.exe --script scripts/lua/trace_transition.lua
        Or configure MODULE_START / MODULE_END below.

    Purpose:
        Identifies when and where execution transitions outside a primary module's
        code section (e.g. jumping to runtime packers, Themida/VMProtect VMs,
        dynamic trampolines, API wrappers, or unmapped memory regions). Also builds
        a page-level execution frequency histogram to detect tight loops.
--]]

-- ============================================================================
-- Configuration
-- ============================================================================

local TARGET = os.getenv("ANGRY_TARGET") or "target.exe"

-- Module boundary range to monitor (set to your module's .text or image bounds)
-- By default: base 0x140001000 to 0x1419A3000 (typical 64-bit PE .text range)
local MODULE_START = tonumber(os.getenv("MODULE_START")) or 0x140001000
local MODULE_END   = tonumber(os.getenv("MODULE_END"))   or 0x1419A3000

local OPTS = {
    entry = nil,
    steps = tonumber(os.getenv("ANGRY_STEPS")) or 5000,
    states = 16,
    uc_memory = true,
    zero_low_pages = true,
    symbolic = {},
    regs = {},
    load_mem = {},
    poke = {},
}

-- ============================================================================
-- Execution
-- ============================================================================

print(string.rep("=", 78))
print("  Angryier Transition & Boundary Analyzer")
print(string.rep("=", 78))
print(string.format("  Target           : %s", TARGET))
print(string.format("  Monitored Range  : 0x%x .. 0x%x", MODULE_START, MODULE_END))
print(string.format("  Step Budget      : %d", OPTS.steps))
print(string.rep("-", 78))

local r = angry.run(TARGET, OPTS)

local trace = r.trace or {}
local n = #trace
print(string.format("Execution finished: %d steps, %d trace block(s) recorded.", r.steps or 0, n))

if n == 0 then
    print("[-] No execution trace blocks recorded.")
    return r
end

-- ============================================================================
-- Transition Point Detection
-- ============================================================================

local last_inside_idx = nil
local first_outside_idx = nil
local transitions = {}

local currently_inside = (trace[1] >= MODULE_START and trace[1] < MODULE_END)

for i = 1, n do
    local pc = trace[i]
    local inside = (pc >= MODULE_START and pc < MODULE_END)
    if inside then
        last_inside_idx = i
    end

    if inside ~= currently_inside then
        transitions[#transitions + 1] = {
            index = i,
            from_pc = trace[i - 1],
            to_pc = pc,
            direction = inside and "ENTERING_MODULE" or "LEAVING_MODULE",
        }
        currently_inside = inside
    end
end

print(string.rep("-", 78))
print(string.format("Detected %d Boundary Transition(s):", #transitions))

for idx, trans in ipairs(transitions) do
    print(string.format("  Transition #%d at step [%d]: %s", idx, trans.index - 1, trans.direction))
    print(string.format("    From: 0x%x -> To: 0x%x", trans.from_pc, trans.to_pc))
end

if last_inside_idx then
    print(string.rep("-", 78))
    print(string.format("Last in-module execution block at index [%d]: 0x%x",
        last_inside_idx - 1, trace[last_inside_idx]))

    -- Context window around the final transition
    local win_start = math.max(1, last_inside_idx - 6)
    local win_end = math.min(n, last_inside_idx + 6)
    print(string.format("Context Window ([%d] .. [%d]):", win_start - 1, win_end - 1))

    for j = win_start, win_end do
        local pc = trace[j]
        local tag = "      "
        if j == last_inside_idx then
            tag = "[LAST]"
        elseif pc >= MODULE_START and pc < MODULE_END then
            tag = "[IN]  "
        else
            tag = "[OUT] "
        end
        print(string.format("  %s [%04d] 0x%x", tag, j - 1, pc))
    end
else
    print("[-] Execution never entered the monitored module range.")
end

-- ============================================================================
-- Page-Level Execution Heatmap (Loop & Hotspot Detector)
-- ============================================================================

print(string.rep("-", 78))
print("Page-Level Execution Heatmap (4 KiB granularity):")

local page_counts = {}
for i = 1, n do
    local pg = math.floor(trace[i] / 0x1000) * 0x1000
    page_counts[pg] = (page_counts[pg] or 0) + 1
end

-- Sort pages by frequency descending
local sorted_pages = {}
for pg, count in pairs(page_counts) do
    sorted_pages[#sorted_pages + 1] = { page = pg, count = count }
end
table.sort(sorted_pages, function(a, b) return a.count > b.count end)

for i = 1, math.min(10, #sorted_pages) do
    local entry = sorted_pages[i]
    local pct = (entry.count / n) * 100.0
    local in_mod = (entry.page >= MODULE_START and entry.page < MODULE_END) and "IN-MODULE " or "OUT-MODULE"
    print(string.format("  Page 0x%016x : %5d hits (%5.1f%%) [%s]",
        entry.page, entry.count, pct, in_mod))
end

print(string.rep("=", 78))
return r
