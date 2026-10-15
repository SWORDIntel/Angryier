--[[
    gdi_success_steerer.lua — Post-GDI+ Path Steerer & Success Solver
    Angryier Symbolic & Concolic Execution Framework
    Target: Sarin Advisor 8.3.0.461 (x86-64 PE, unlicense-unpacked)

    Context:
        Inside ExpertInitializations (0x1405E0EF0), execution reaches the GDI+
        startup call at 0x1405E1043: call [0x1421DD1C8].
        After returning into 0x1405E1049, the function evaluates several subsystem
        initialization checks before either reaching success at 0x1405E3BBC (bl = 1)
        or aborting at 0x1405E3B82 (status 41).

        This script handles the GDI+ call via forced return 0 (Ok), steps through the
        subsequent logic to 0x1405E3BBC, identifies any deviating branches, and solves
        the path constraints necessary to achieve the Gate 4 TRUE condition.

    Usage:
        ANGRY_TARGET=advisor_unpacked_state.exe angryier run advisor_unpacked_state.exe --script scripts/lua/gdi_success_steerer.lua
--]]

-- ============================================================================
-- Configuration
-- ============================================================================

local TARGET = os.getenv("ANGRY_TARGET") or "advisor_unpacked_state.exe"
local MEMLOADS_DIR = os.getenv("ANGRY_MEMLOADS_DIR") or "memloads/"
if MEMLOADS_DIR:sub(-1) ~= "/" and MEMLOADS_DIR:sub(-1) ~= "\\" then
    MEMLOADS_DIR = MEMLOADS_DIR .. "/"
end

-- Entry points:
--   0x1405E1044: Immediate continuation past preceding helper (GDI+ block entry)
--   0x1405E1049: Continuation past GdiplusStartup call
--   0x1405E0EF0: ExpertInitializations function prologue
local ENTRY_PC = tonumber(os.getenv("ANGRY_ENTRY")) or 0x1405E1044

local ADDR_GDI_CALL   = 0x1405E1043
local ADDR_GDI_CONT   = 0x1405E1049
local ADDR_TARGET_WIN = 0x1405E3BBC -- mov bl, 1 (SUCCESS)
local ADDR_TARGET_ERR = 0x1405E3B82 -- mov ecx, 29h (status 41 abort)

local TAIL_SPECS = {
    { addr = 0x142142000, file = "tail_1_2142000.bin" },
    { addr = 0x1421BF400, file = "tail_2_21BF400.bin" },
    { addr = 0x1423E5E00, file = "tail_3_23E5E00.bin" },
    { addr = 0x1423E7C00, file = "tail_4_23E7C00.bin" },
    { addr = 0x1423E8000, file = "tail_5_23E8000.bin" },
    { addr = 0x1437E9E00, file = "tail_6_37E9E00.bin" },
}

local LOAD_MEM = {}
for i, spec in ipairs(TAIL_SPECS) do
    LOAD_MEM[i] = {
        addr = spec.addr,
        path = os.getenv("ANGRY_TAIL_" .. i .. "_PATH") or (MEMLOADS_DIR .. spec.file),
    }
end

-- ============================================================================
-- Campaign Execution Options
-- ============================================================================

local OPTS = {
    entry = ENTRY_PC,
    find = { ADDR_TARGET_WIN },
    avoid = { ADDR_TARGET_ERR },

    symbolic = { rcx = 64, rdx = 64, r8 = 64 },

    -- Stub GdiplusStartup to return 0 (Ok) immediately
    stubs = {
        [ADDR_GDI_CALL] = 0,
    },

    load_mem = LOAD_MEM,

    steps = tonumber(os.getenv("ANGRY_STEPS")) or 15000,
    states = tonumber(os.getenv("ANGRY_STATES")) or 64,
    timeout_secs = tonumber(os.getenv("ANGRY_TIMEOUT_SECS")) or 120,

    uc_memory = true,
    zero_low_pages = true,
    solve = true,
}

print(string.rep("=", 78))
print("  Angryier GDI+ Gate Resolver & Success Steerer")
print(string.rep("=", 78))
print(string.format("  Target           : %s", TARGET))
print(string.format("  Entry PC         : 0x%016x", ENTRY_PC))
print(string.format("  Find Target      : 0x%016x (SUCCESS)", ADDR_TARGET_WIN))
print(string.format("  Avoid Target     : 0x%016x (STATUS 41)", ADDR_TARGET_ERR))
print(string.format("  Gdiplus Stub     : 0x%016x -> return 0", ADDR_GDI_CALL))
print(string.format("  Step Budget      : %d (max %d states)", OPTS.steps, OPTS.states))
print(string.rep("-", 78))

local r = angry.run(TARGET, OPTS)

print(string.rep("=", 78))
print("  Campaign Results")
print(string.rep("=", 78))
print(string.format("  Steps completed  : %s", tostring(r.steps or 0)))
print(string.format("  Forks created    : %s", tostring(r.forks or 0)))
print(string.format("  Merges           : %s", tostring(r.merges or 0)))
print(string.format("  Terminated       : %s", tostring(r.terminated or 0)))
print(string.format("  Live states      : %s", tostring(r.live_states or 0)))
print(string.format("  Find hits        : %s", tostring(r.found or 0)))
print(string.format("  Timed out        : %s", tostring(r.timed_out or false)))
if r.rax_exit ~= nil then
    print(string.format("  Exit RAX         : 0x%x (%d)", r.rax_exit, r.rax_exit))
end
if r.exit_pc ~= nil then
    print(string.format("  Exit PC          : 0x%x", r.exit_pc))
end
if r.exit_kind ~= nil then
    print(string.format("  Exit Kind        : %s", tostring(r.exit_kind)))
end

-- ============================================================================
-- Branch Analysis & Divergence Detection
-- ============================================================================

local trace = r.trace_hex or {}
local n_trace = #trace
local hit_win = false
local hit_err = false
local last_branch_pc = nil

for i = 1, n_trace do
    local pc = tonumber(trace[i])
    if pc == ADDR_TARGET_WIN then
        hit_win = true
    elseif pc == ADDR_TARGET_ERR then
        hit_err = true
        if i > 1 then
            last_branch_pc = trace[i - 1]
        end
    end
end

print(string.rep("-", 78))
print(string.format("Execution Trace Traversal (%d blocks):", n_trace))
if hit_win then
    print("  [+] SUCCESS: Target 0x1405E3BBC (bl = 1) was REACHED!")
elseif hit_err then
    print(string.format("  [-] DIVERGED: Reached error block 0x1405E3B82 from predecessor %s",
        tostring(last_branch_pc or "unknown")))
    print("      Recommended action: Check conditional branch at predecessor to invert decision.")
else
    print("  [*] INCOMPLETE: Execution paused before reaching find or avoid target.")
    if n_trace > 0 then
        local display_count = math.min(10, n_trace)
        print(string.format("      Trace tail (last %d blocks):", display_count))
        for j = n_trace - display_count + 1, n_trace do
            print(string.format("        [%04d] %s", j - 1, trace[j]))
        end
    end
end

-- ============================================================================
-- Model Extraction
-- ============================================================================

local n_models = 0
if r.inputs and #r.inputs > 0 then
    print(string.rep("-", 78))
    print(string.format("SMT Constraints Solved (%d model(s)):", #r.inputs))
    for idx, model in ipairs(r.inputs) do
        n_models = n_models + 1
        print(string.format("  Model #%d:", idx))
        for var_idx, byte_str in ipairs(model) do
            print(string.format("    Var[%d] (%d bytes): %s",
                var_idx, #byte_str, angry.hex(byte_str)))
        end
    end
end

-- ============================================================================
-- Verdict Line
-- ============================================================================

local verdict_status = "stalled"
if hit_win or (r.found or 0) > 0 then
    verdict_status = "reached_true"
elseif hit_err then
    verdict_status = "diverged"
elseif r.timed_out then
    verdict_status = "timeout"
end

print(string.rep("=", 78))
print(string.format("VERDICT gdi_steerer status=%s found=%d exit_pc=%s branches=%d",
    verdict_status, r.found or 0, tostring(r.exit_pc_hex or (r.exit_pc and string.format("0x%x", r.exit_pc)) or "none"), n_trace))
print(string.rep("=", 78))
return r
