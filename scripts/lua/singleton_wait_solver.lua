--[[
    singleton_wait_solver.lua — Symbolic State Solver for the 5-Minute Wait Machinery
    Angryier Symbolic & Concolic Execution Framework
    Target: Sarin Advisor 8.3.0.461 (x86-64 PE, unlicense-unpacked)

    Context:
        The central blocking function is 0x140404E10(obj, timeout_ms, expected_desc).
        Parameters intercepted live at step 29:
          rcx = 0x094464C0   (the processing singleton stored at global 0x14221A4E8)
          rdx = 0x493E0      (300,000 ms = exactly 5 minutes timeout)
          r8  = 0x141AAFE28  (expected-state descriptor pointer in read-only data)

        When executed offline without the external WCF service, the wait loops for the
        entire timeout or returns failure status 41. This script parameterizes the
        singleton object fields (0x094464C0..0x09446520) as symbolic memory and solves
        the exact state that causes 0x140404E10 to take an immediate SUCCESS exit (eax=0).

    Usage:
        ANGRY_TARGET=advisor_unpacked_state.exe angryier run advisor_unpacked_state.exe --script scripts/lua/singleton_wait_solver.lua
--]]

-- ============================================================================
-- Configuration
-- ============================================================================

local TARGET = os.getenv("ANGRY_TARGET") or "advisor_unpacked_state.exe"
local MEMLOADS_DIR = os.getenv("ANGRY_MEMLOADS_DIR") or "memloads/"
if MEMLOADS_DIR:sub(-1) ~= "/" and MEMLOADS_DIR:sub(-1) ~= "\\" then
    MEMLOADS_DIR = MEMLOADS_DIR .. "/"
end

local ENTRY_MODE = os.getenv("ENTRY_MODE") or "isolated" -- "isolated" or "wrapper"

local ADDR_SINGLETON  = 0x094464C0
local ADDR_DESCRIPTOR = 0x141AAFE28
local ADDR_WAIT_FN    = 0x140404E10
local ADDR_WRAPPER    = 0x1407C89C0
local ADDR_WAIT_RET   = 0x1407C8A4B

local ENTRY_PC = (ENTRY_MODE == "wrapper") and ADDR_WRAPPER or ADDR_WAIT_FN

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
-- Exploration Setup
-- ============================================================================

-- If isolated entry, pass singleton in RCX, timeout=0 in RDX, descriptor in R8
local REGS_INIT = {}
if ENTRY_MODE == "isolated" then
    REGS_INIT = {
        rcx = ADDR_SINGLETON,
        rdx = 0, -- Test whether timeout=0 unblocks immediately
        r8  = ADDR_DESCRIPTOR,
        r9  = 0,
    }
else
    REGS_INIT = {
        rcx = 0,
    }
end

local OPTS = {
    entry = ENTRY_PC,
    find = { ADDR_WAIT_RET },
    avoid = {},

    regs = REGS_INIT,

    -- Mark 96 bytes of the singleton object as symbolic memory
    symbolic_memory = {
        { addr = ADDR_SINGLETON, len = 96 },
    },

    load_mem = LOAD_MEM,

    steps = tonumber(os.getenv("ANGRY_STEPS")) or 5000,
    states = tonumber(os.getenv("ANGRY_STATES")) or 32,
    timeout_secs = tonumber(os.getenv("ANGRY_TIMEOUT_SECS")) or 60,

    uc_memory = true,
    zero_low_pages = true,
    solve = true,
}

print(string.rep("=", 78))
print("  Angryier Singleton Wait Synthesizer: " .. TARGET)
print(string.rep("=", 78))
print(string.format("  Mode             : %s (Entry 0x%x)", ENTRY_MODE, ENTRY_PC))
print(string.format("  Singleton        : 0x%08x (96 bytes symbolic)", ADDR_SINGLETON))
print(string.format("  Descriptor       : 0x%08x", ADDR_DESCRIPTOR))
print(string.format("  Step Budget      : %d (max %d states)", OPTS.steps, OPTS.states))
print(string.rep("-", 78))

local r = angry.run(TARGET, OPTS)

print(string.rep("=", 78))
print("  Exploration Results")
print(string.rep("=", 78))
print(string.format("  Steps completed  : %s", tostring(r.steps or 0)))
print(string.format("  Forks created    : %s", tostring(r.forks or 0)))
print(string.format("  Terminated paths : %s", tostring(r.terminated or 0)))
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
-- Solved Model & Memory Patch Emission
-- ============================================================================

local n_solutions = 0
if r.inputs and #r.inputs > 0 then
    print(string.rep("-", 78))
    print(string.format("SUCCESS: SMT Solved %d Model(s) Unblocking Wait!", #r.inputs))

    for m_idx, model in ipairs(r.inputs) do
        n_solutions = n_solutions + 1
        print(string.format("\n--- Solution #%d ---", m_idx))
        for var_idx, byte_str in ipairs(model) do
            print(string.format("  Variable #%d (%d bytes):", var_idx, #byte_str))
            print("    HEX:   " .. angry.hex(byte_str))

            -- Print formatted C-style pokes for advisor_unified.c
            print("\n  C-Ready Poke Definitions (for advisor_unified.c / g_static):")
            for off = 0, #byte_str - 1, 8 do
                local chunk_len = math.min(8, #byte_str - off)
                if chunk_len == 8 then
                    local val = string.unpack("<I8", byte_str, off + 1)
                    print(string.format("    { 0x%08x, 0x%016x }, // +0x%02x",
                        ADDR_SINGLETON + off, val, off))
                end
            end
        end
    end
else
    print(string.rep("-", 78))
    print("[-] No solver model returned. Function may require additional heap structures.")
end

-- ============================================================================
-- Telemetry & Verdict
-- ============================================================================

local status = "stalled"
if n_solutions > 0 then
    status = "solved"
elseif (r.found or 0) > 0 then
    status = "found_no_model"
elseif r.timed_out then
    status = "timeout"
end

print(string.rep("=", 78))
print(string.format("VERDICT wait_solver status=%s solutions=%d eax=%s",
    status, n_solutions, tostring(r.rax_exit or "unknown")))
print(string.rep("=", 78))
return r
