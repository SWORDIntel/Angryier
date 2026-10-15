--[[
    lazy_initterm_scanner.lua — Crash Family B Lazy Init Table & Marker Auditor
    Angryier Symbolic & Concolic Execution Framework
    Target: Sarin Advisor 8.3.0.461 (x86-64 PE, unlicense-unpacked)

    Context:
        Crash Family B (AV 0xC0000005 at msvcr120.dll+0x227AF) was caused by a worker
        thread executing _initterm over initializer table 0x141A1B7A0..0x141A1B7D0.
        The table resided in lazily decrypted .data pages; runtime startup raced ahead
        of page decryption, encountering un-decrypted Themida markers (0x5858585858585858
        / ASCII 'XXXXXXXX').

        Architectural fix: Patched caller at 0x14000DED7:
          0x14000DED7: e8 94 10 00 00 -> 31 c0 90 90 90 (xor eax, eax; nops)
        Forces the following `test eax, eax; jz +14` branch to cleanly bypass table walking.

    Purpose:
        1. Scans initializer table 0x141A1B7A0..0x141A1B7D0 for un-decrypted marker values.
        2. Probes caller execution at 0x14000DED0 with and without the caller bypass patch,
           verifying that the table walk is skipped and does not crash the worker thread.

    Usage:
        ANGRY_TARGET=advisor_unpacked_state.exe angryier run advisor_unpacked_state.exe --script scripts/lua/lazy_initterm_scanner.lua
--]]

-- ============================================================================
-- Configuration
-- ============================================================================

local TARGET = os.getenv("ANGRY_TARGET") or "advisor_unpacked_state.exe"
local MEMLOADS_DIR = os.getenv("ANGRY_MEMLOADS_DIR") or "memloads/"
if MEMLOADS_DIR:sub(-1) ~= "/" and MEMLOADS_DIR:sub(-1) ~= "\\" then
    MEMLOADS_DIR = MEMLOADS_DIR .. "/"
end

local ADDR_TABLE_START = 0x141A1B7A0
local ADDR_TABLE_END   = 0x141A1B7D0
local THEMIDA_MARKER   = 0x5858585858585858 -- 'XXXXXXXX'

local ADDR_CALLER_ENTRY = 0x14000DED0
local ADDR_CALL_SITE    = 0x14000DED7 -- e8 94 10 00 00 -> 31 c0 90 90 90
local ADDR_BYPASS_CONT  = 0x14000DEE2 -- continuation after jz +14

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

print(string.rep("=", 78))
print("  Angryier Crash Family B: Lazy _initterm Table & Marker Scanner")
print(string.rep("=", 78))
print("Target: " .. TARGET)
print(string.format("Table Range              : 0x%016x .. 0x%016x", ADDR_TABLE_START, ADDR_TABLE_END))
print(string.format("Themida Encrypted Marker : 0x%016x ('XXXXXXXX')", THEMIDA_MARKER))
print(string.format("Caller Block Entry       : 0x%016x", ADDR_CALLER_ENTRY))
print(string.format("Caller Patch Site        : 0x%016x", ADDR_CALL_SITE))
print(string.rep("-", 78))

-- ============================================================================
-- Phase 1: Static Inspection of Table Memory via Interactive Session
-- ============================================================================

print("[*] Phase 1: Scanning Initializer Table for Themida Markers...")
local s = angry.open(TARGET, {
    entry = ADDR_CALLER_ENTRY,
    load_mem = LOAD_MEM,
    uc_memory = true,
    zero_low_pages = true,
})

local st = s:state()
local table_len = ADDR_TABLE_END - ADDR_TABLE_START
local raw_table = st:read_bytes(ADDR_TABLE_START, table_len)

local markers_found = 0
local valid_pointers = 0
local table_entries = {}

for offset = 0, table_len - 1, 8 do
    local slot_addr = ADDR_TABLE_START + offset
    local ptr_val = string.unpack("<I8", raw_table, offset + 1)
    table_entries[#table_entries + 1] = {
        addr = slot_addr,
        value = ptr_val,
        is_marker = (ptr_val == THEMIDA_MARKER),
    }
    if ptr_val == THEMIDA_MARKER then
        markers_found = markers_found + 1
        print(string.format("  [!] Slot 0x%016x: 0x%016x [UN-DECRYPTED THEMIDA MARKER]",
            slot_addr, ptr_val))
    else
        valid_pointers = valid_pointers + 1
        print(string.format("  [*] Slot 0x%016x: 0x%016x", slot_addr, ptr_val))
    end
end

local table_status = (markers_found > 0) and "has_markers" or "decrypted"
print(string.format("Table Scan Complete: %d slots total, %d marker(s) found, %d pointer(s). Status: %s",
    #table_entries, markers_found, valid_pointers, table_status))

-- ============================================================================
-- Phase 2: Dynamic Verification of Caller Bypass Patch
-- ============================================================================

print(string.rep("-", 78))
print("[*] Phase 2: Verifying Caller Bypass Patch (0x14000DED7 -> 31 C0 90 90 90)...")

local function test_caller(apply_patch)
    local patch_str = apply_patch and "31c0909090" or nil
    local patches_tbl = {}
    if apply_patch then
        patches_tbl[ADDR_CALL_SITE] = patch_str
    end

    local r = angry.run(TARGET, {
        entry = ADDR_CALLER_ENTRY,
        patches = patches_tbl,
        load_mem = LOAD_MEM,
        steps = 50,
        states = 4,
        uc_memory = true,
        zero_low_pages = true,
    })
    return r
end

local r_unpatched = test_caller(false)
local r_patched = test_caller(true)

local function check_bypass(trace)
    for _, pc in ipairs(trace or {}) do
        if tonumber(pc) == ADDR_BYPASS_CONT then return true end
    end
    return false
end

local unpatched_bypassed = check_bypass(r_unpatched.trace_hex)
local patched_bypassed   = check_bypass(r_patched.trace_hex)

print(string.format("  Unpatched caller reached bypass continuation [0x%x]: %s",
    ADDR_BYPASS_CONT, unpatched_bypassed and "YES" or "NO (invoked table walk)"))
print(string.format("  Patched caller reached bypass continuation   [0x%x]: %s",
    ADDR_BYPASS_CONT, patched_bypassed and "YES (CLEAN BYPASS)" or "NO"))

local caller_status = patched_bypassed and "active" or "inactive"

print(string.rep("=", 78))
print(string.format("VERDICT initterm_scanner markers_found=%d table_status=%s caller_bypass=%s",
    markers_found, table_status, caller_status))
print(string.rep("=", 78))
return r_patched
