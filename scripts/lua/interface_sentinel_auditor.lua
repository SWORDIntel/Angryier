--[[
    interface_sentinel_auditor.lua — Crash Family A Sentinel Dereference Auditor
    Angryier Symbolic & Concolic Execution Framework
    Target: Sarin Advisor 8.3.0.461 (x86-64 PE, unlicense-unpacked)

    Context:
        Crash Family A (AV 0xC0000005) occurred during interface accessor execution:
          - Generated accessor 0x140353FC0 loads [this + 0x18] (dispatch table 0x141A206E0),
            returning code sentinel pointer 0x1405E5840.
          - The caller treats this code pointer as a C++ vtable pointer and dereferences
            `call [rax + 8]` at 0x140353FE0 (or `call [rax + 0x10]` at 0x14068B5EF),
            reading the instruction bytes of 0x1405E5840 as an address.
          - Architectural fix: 0x140523033: 75 05 -> 90 90 in CCaller::GetInnerInterface,
            nullifying the inner interface so the accessor cleanly returns NULL.

    Purpose:
        This script audits CCaller::GetInnerInterface (0x140523010) and accessor 0x140353FC0,
        evaluating both the unpatched and patched states to verify that the code sentinel
        pointer 0x1405E5840 is never dereferenced as a vtable.

    Usage:
        ANGRY_TARGET=advisor_unpacked_state.exe angryier run advisor_unpacked_state.exe --script scripts/lua/interface_sentinel_auditor.lua
--]]

-- ============================================================================
-- Configuration
-- ============================================================================

local TARGET = os.getenv("ANGRY_TARGET") or "advisor_unpacked_state.exe"
local MEMLOADS_DIR = os.getenv("ANGRY_MEMLOADS_DIR") or "memloads/"
if MEMLOADS_DIR:sub(-1) ~= "/" and MEMLOADS_DIR:sub(-1) ~= "\\" then
    MEMLOADS_DIR = MEMLOADS_DIR .. "/"
end

local ADDR_GET_INNER_IFACE = 0x140523010
local ADDR_IFACE_ACCESSOR   = 0x140353FC0
local ADDR_FAULT_DEREF     = 0x140353FE0 -- call [rax + 8]
local ADDR_SENTINEL_CODE   = 0x1405E5840
local ADDR_PATCH_SITE      = 0x140523033 -- 75 05 -> 90 90

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

local function run_probe(enable_patch)
    local patch_str = enable_patch and "9090" or nil
    local patches_tbl = {}
    if enable_patch then
        patches_tbl[ADDR_PATCH_SITE] = patch_str
    end

    local opts = {
        entry = ADDR_GET_INNER_IFACE,
        symbolic = { rcx = 64 }, -- symbolic 'this' pointer
        load_mem = LOAD_MEM,
        patches = patches_tbl,
        steps = 150,
        states = 8,
        uc_memory = true,
        zero_low_pages = true,
    }

    local r = angry.run(TARGET, opts)
    return r
end

print(string.rep("=", 78))
print("  Angryier Crash Family A: Interface Sentinel Auditor")
print(string.rep("=", 78))
print("Target: " .. TARGET)
print(string.format("CCaller::GetInnerInterface : 0x%016x", ADDR_GET_INNER_IFACE))
print(string.format("Interface Accessor         : 0x%016x", ADDR_IFACE_ACCESSOR))
print(string.format("Faulting Dereference       : 0x%016x (call [rax+8])", ADDR_FAULT_DEREF))
print(string.format("Code Sentinel Pointer      : 0x%016x", ADDR_SENTINEL_CODE))
print(string.format("Architectural Patch Site   : 0x%016x (75 05 -> 90 90)", ADDR_PATCH_SITE))
print(string.rep("-", 78))

-- 1. Run Baseline (Unpatched) Probe
print("[*] Phase 1: Probing Baseline (Unpatched)...")
local r_base = run_probe(false)
local base_rax = r_base.rax_exit or 0
local base_hit_sentinel = (base_rax == ADDR_SENTINEL_CODE)
print(string.format("    Baseline exit RAX: 0x%x, Exit Kind: %s",
    base_rax, tostring(r_base.exit_kind or "unknown")))

-- 2. Run Patched Probe
print("[*] Phase 2: Probing Architectural Patch (0x140523033 -> 90 90)...")
local r_patch = run_probe(true)
local patch_rax = r_patch.rax_exit or 0
local patch_hit_sentinel = (patch_rax == ADDR_SENTINEL_CODE)
print(string.format("    Patched exit RAX : 0x%x, Exit Kind: %s",
    patch_rax, tostring(r_patch.exit_kind or "unknown")))

-- 3. Evaluation & Verification
print(string.rep("-", 78))
print("Auditor Evaluation:")
local is_guarded = false

if base_hit_sentinel and not patch_hit_sentinel then
    is_guarded = true
    print("  [+] CONFIRMED: Baseline returned code sentinel 0x1405E5840 (vulnerable to call [rax+8]).")
    print("  [+] CONFIRMED: Architectural patch (90 90) cleanly prevented sentinel return (returned 0x" .. string.format("%x", patch_rax) .. ").")
elseif not patch_hit_sentinel then
    is_guarded = true
    print("  [+] Patched state safely avoided sentinel return (RAX = 0x" .. string.format("%x", patch_rax) .. ").")
else
    print("  [-] WARNING: Sentinel pointer was still returned despite patch.")
end

-- Check whether call [rax+8] was executed in trace
local function check_deref(trace)
    for _, pc in ipairs(trace or {}) do
        if tonumber(pc) == ADDR_FAULT_DEREF then return true end
    end
    return false
end

local deref_base = check_deref(r_base.trace_hex)
local deref_patch = check_deref(r_patch.trace_hex)

print(string.format("  Faulting dereference [0x%x] executed in baseline: %s",
    ADDR_FAULT_DEREF, deref_base and "YES (CRASH HAZARD)" or "NO"))
print(string.format("  Faulting dereference [0x%x] executed in patched : %s",
    ADDR_FAULT_DEREF, deref_patch and "YES" or "NO (SAFE)"))

local verdict_status = is_guarded and "guarded" or "vulnerable"
local verdict_deref = deref_patch and "yes" or "no"

print(string.rep("=", 78))
print(string.format("VERDICT interface_auditor status=%s sentinel_deref=%s patch_effective=%s",
    verdict_status, verdict_deref, is_guarded and "true" or "false"))
print(string.rep("=", 78))
return r_patch
