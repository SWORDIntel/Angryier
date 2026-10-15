-- expert_initializations_driver.lua
-- Lua 5.4 / Angryier embedded sandbox.
--
-- Target: Sarin Advisor 8.3.0.461, x86-64, unlicense-unpacked.
-- Image base: 0x140000000.
--
-- Already patched in the analysis image; intentionally NOT patched here:
--   __security_check_cookie 0x14140D3A0: F3 C3
--   trampoline              0x1408D21E9: E9 BF 00 00 00 90
--   std::_Tree::find branches NOPed at:
--     0x140E572F6, 0x140E57386, 0x140E57416, 0x140E574A6,
--     0x140E57665, 0x140E5792A, 0x140E57956.
--
-- No GDI+ stub, redirect, or synthetic return is installed. Crossing the
-- GdiplusStartup call must arise from execution of the supplied image/memory.
--
-- Environment:
--   ANGRY_TARGET          default: advisor_unpacked_state.exe
--   ANGRY_MEMLOADS_DIR    default: memloads/
--   ANGRY_STEPS           default: 20000
--   ANGRY_STATES          default: 64
--   ANGRY_TIMEOUT_SECS    default: 120
--   ANGRY_TAIL_1_PATH ... ANGRY_TAIL_6_PATH
--       Optional complete paths, overriding each tail's default filename.
--
-- The supplied workflow specifies tail_N_*.bin, not literal filenames.
-- The filenames below are an editable naming convention, not glob patterns.
-- Set the per-tail path variables or edit this table to match the actual files.

local TAIL_SPECS = {
    { addr = 0x142142000, file = "tail_1_2142000.bin" },
    { addr = 0x1421BF400, file = "tail_2_21BF400.bin" },
    { addr = 0x1423E5E00, file = "tail_3_23E5E00.bin" },
    { addr = 0x1423E7C00, file = "tail_4_23E7C00.bin" },
    { addr = 0x1423E8000, file = "tail_5_23E8000.bin" },
    { addr = 0x1437E9E00, file = "tail_6_37E9E00.bin" },
}

-- Optional registration-list experiments. Empty preserves dumped globals.
-- Known globals:
--   guard dword       0x1421DE1A8 = 1
--   list head         0x1421DE170 = 0x9476E80
--   first-node slot   0x1421DE178
--   dumped node count = 1
--   singleton         0x14221A4E8 = 0x94464C0
--
-- Example pointer seed ONLY, not a complete provider registration:
--   { addr = 0x1421DE170, value = 0x20000000 },
--   { addr = 0x20000000, value = 0x1421DE170 },
--   { addr = 0x20000008, value = 0x1421DE170 },
-- A real experiment must supply the actual node layout, provider payload,
-- required links/counts, and callable targets. poke writes EIGHT bytes:
-- do not use it on the guard dword without preserving the adjacent dword.
local EXTRA_POKES = {}

local ENTRY = 0x1405E0EF0
local FIND = { 0x1405E3BBC }
local AVOID = { 0x1405E3B82 }

local function fatal(message)
    print("FATAL: " .. tostring(message))
    print("VERDICT path=stalled found=0 rax=unknown gdi=not_reached wait=not_reached")
    error(tostring(message), 0)
end

local function getenv(name, default)
    local value = os.getenv(name)
    if value == nil or value == "" then
        return default
    end
    return value
end

local function positive_integer_env(name, default)
    local raw = getenv(name, tostring(default))
    if not raw:match("^%d+$") then
        fatal(name .. " must be a positive decimal integer; got " .. raw)
    end
    local value = math.tointeger(tonumber(raw))
    if not value or value < 1 then
        fatal(name .. " is outside the supported positive integer range: " .. raw)
    end
    return value
end

local function join_path(dir, filename)
    if dir:match("[/\\]$") then
        return dir .. filename
    end
    return dir .. "/" .. filename
end

local CONFIG = {
    target = getenv("ANGRY_TARGET", "advisor_unpacked_state.exe"),
    memloads_dir = getenv("ANGRY_MEMLOADS_DIR", "memloads/"),
    steps = positive_integer_env("ANGRY_STEPS", 20000),
    states = positive_integer_env("ANGRY_STATES", 64),
    timeout_secs = positive_integer_env("ANGRY_TIMEOUT_SECS", 120),
    load_mem = {},
}

for i, spec in ipairs(TAIL_SPECS) do
    CONFIG.load_mem[i] = {
        addr = spec.addr,
        path = getenv("ANGRY_TAIL_" .. i .. "_PATH",
                      join_path(CONFIG.memloads_dir, spec.file)),
    }
end

-- Canonicalize addresses entirely as strings. Never convert a kernel-address
-- hex string to a floating-point number.
local function canonical_hex(value)
    if type(value) ~= "string" then
        return nil
    end
    local hex = value:lower():gsub("^0x", "")
    if #hex == 0 or #hex > 16 or not hex:match("^[0-9a-f]+$") then
        return nil
    end
    return string.rep("0", 16 - #hex) .. hex
end

local function address_text(exact_hex, numeric)
    local hex = canonical_hex(exact_hex)
    if hex then
        return "0x" .. hex
    end
    -- Numeric fallback is only safe for actual Lua integers or floats within
    -- the consecutive-integer range. Refuse to format rounded upper pointers.
    if type(numeric) == "number" then
        local safe = math.type(numeric) == "integer"
            or (numeric >= 0 and numeric <= 9007199254740991)
        local integer = safe and math.tointeger(numeric) or nil
        if integer then
            return string.format("0x%016x", integer)
        end
        return "<inexact numeric address; exact _hex unavailable>"
    end
    return "<unavailable>"
end

local function scalar_text(value)
    if value == nil then
        return "unknown"
    end
    if type(value) == "number" then
        if math.type(value) == "integer" then
            return tostring(value)
        end
        if value >= -9007199254740991 and value <= 9007199254740991 then
            local integer = math.tointeger(value)
            if integer then
                return tostring(integer)
            end
        end
        return string.format("%.17g", value)
    end
    return tostring(value):gsub("%s+", "_")
end

local function counter(report, name)
    local value = report[name]
    if type(value) == "number" and value >= 0 then
        return value
    end
    return 0
end

local function preflight()
    local files = {
        { path = CONFIG.target, label = "analysis image (ANGRY_TARGET)" },
    }
    for i, entry in ipairs(CONFIG.load_mem) do
        files[#files + 1] = {
            path = entry.path,
            label = "tail at " .. address_text(nil, entry.addr)
                .. " (ANGRY_TAIL_" .. i .. "_PATH)",
        }
    end

    local errors = {}
    for _, input in ipairs(files) do
        local ok, file, open_error = pcall(io.open, input.path, "rb")
        if not ok or not file then
            errors[#errors + 1] = string.format(
                "%s: missing/unreadable input %q: %s",
                input.label, input.path,
                tostring(ok and open_error or file))
        else
            local read_ok, first_byte = pcall(function()
                return file:read(1)
            end)
            local close_ok, close_result, close_error = pcall(function()
                return file:close()
            end)
            if not read_ok or not first_byte or #first_byte == 0 then
                errors[#errors + 1] = string.format(
                    "%s: empty/unreadable input %q", input.label, input.path)
            end
            if not close_ok or not close_result then
                errors[#errors + 1] = string.format(
                    "could not close input %q: %s", input.path,
                    tostring(close_ok and close_error or close_result))
            end
        end
    end
    if #errors > 0 then
        fatal(table.concat(errors, "\n")
            .. "\nTail names are literal; configure their paths to match the dump.")
    end
end

preflight()

print("=== ExpertInitializations TRUE-path campaign ===")
print("Target: " .. CONFIG.target)
print(string.format("Entry=%s steps=%d states=%d timeout_secs=%d",
    address_text(nil, ENTRY), CONFIG.steps, CONFIG.states, CONFIG.timeout_secs))
print("Find=0x00000001405e3bbc avoid=0x00000001405e3b82")
print("Symbolic GPRs: rcx=64 rdx=64 r8=64")
print("uc_memory=true zero_low_pages=true solve=true; extra_pokes="
    .. tostring(#EXTRA_POKES))
for i, entry in ipairs(CONFIG.load_mem) do
    print(string.format("Load[%d] %s <- %s",
        i, address_text(nil, entry.addr), entry.path))
end

local ok, r = pcall(function()
    return angry.run(CONFIG.target, {
        entry = ENTRY,
        find = FIND,
        avoid = AVOID,
        symbolic = { rcx = 64, rdx = 64, r8 = 64 },
        load_mem = CONFIG.load_mem,
        poke = EXTRA_POKES,
        steps = CONFIG.steps,
        states = CONFIG.states,
        timeout_secs = CONFIG.timeout_secs,
        uc_memory = true,
        zero_low_pages = true,
        solve = true,
    })
end)

if not ok then
    fatal("angry.run failed for " .. CONFIG.target .. ": " .. tostring(r))
end
if type(r) ~= "table" then
    fatal("angry.run returned " .. type(r) .. ", expected a report table")
end

print("\n=== Campaign report ===")
for _, name in ipairs({
    "steps", "forks", "merges", "terminated", "pruned_states", "failed",
    "live_states", "dead_states", "peak_states", "found", "timed_out",
}) do
    print(name .. "=" .. scalar_text(r[name]))
end
if r.last_error then
    print("last_error=" .. tostring(r.last_error))
end
print("rax_exit=" .. scalar_text(r.rax_exit))
print("rax_exit_symbolic=" .. scalar_text(r.rax_exit_symbolic))
print("exit_pc=" .. address_text(r.exit_pc_hex, r.exit_pc))
print("exit_kind=" .. tostring(r.exit_kind or "unavailable"))
print("entry_rsp=" .. address_text(r.entry_rsp_hex, r.entry_rsp))

local found = counter(r, "found")
local status41 = r.rax_exit == 41 and r.rax_exit_symbolic ~= true

if r.exit_kind == "sentinel_ret" then
    print("Exit interpretation: EI returned cleanly through the synthetic sentinel.")
else
    print("Exit interpretation: a clean EI return is not established.")
end
if status41 then
    print("Status interpretation: RAX=41 (0x29), the known provider-registration wait failure.")
elseif r.rax_exit_symbolic == true then
    print("Status interpretation: symbolic RAX is not a confirmed concrete return status.")
end
if found > 0 then
    print("TRUE-path evidence: found > 0 at 0x1405E3BBC (the bl=1 block).")
else
    print("TRUE-path evidence: no find hit was reported.")
end

local sites = {
    { key = "gdi_call", hex = "00000001405e1043",
      label = "GdiplusStartup call [0x1421DD1C8]" },
    { key = "gdi_return", hex = "00000001405e1049",
      label = "GdiplusStartup return continuation" },
    { key = "wait_wrapper", hex = "00000001407c89c0",
      label = "processing singleton get-or-create / wait wrapper" },
    { key = "wait_function", hex = "0000000140404e10",
      label = "bounded wait(obj, 0x493E0, &expected)" },
    { key = "ctor", hex = "0000000140404b00",
      label = "processing singleton constructor" },
    { key = "getter", hex = "00000001405e3e90",
      label = "registration getter" },
}
local lookup, hits = {}, {}
for _, site in ipairs(sites) do
    lookup[site.hex] = site.key
    hits[site.key] = {}
end

local trace = type(r.trace_hex) == "table" and r.trace_hex or {}
for index, pc_hex in ipairs(trace) do
    local normalized = canonical_hex(pc_hex)
    local key = normalized and lookup[normalized]
    if key then
        hits[key][#hits[key] + 1] = index
    end
end

print("\n=== Exact trace-site observations ===")
print("trace_hex entries=" .. tostring(#trace))
for _, site in ipairs(sites) do
    local indices = {}
    for _, index in ipairs(hits[site.key]) do
        indices[#indices + 1] = tostring(index)
    end
    print(string.format("%s @ 0x%s: %s; indices=[%s]",
        site.label, site.hex,
        #indices > 0 and "observed" or "not_observed",
        table.concat(indices, ",")))
end

local crossed = false
local crossing_call, crossing_return
if #hits.gdi_call > 0 then
    for _, index in ipairs(hits.gdi_return) do
        if index > hits.gdi_call[1] then
            crossed = true
            crossing_call, crossing_return = hits.gdi_call[1], index
            break
        end
    end
end
local wait_reached = #hits.wait_wrapper > 0 or #hits.wait_function > 0

if crossed then
    print(string.format(
        "GDI+ gate evidence: call index %d precedes continuation index %d.",
        crossing_call, crossing_return))
else
    print("GDI+ gate evidence: no ordered call/continuation pair observed.")
end
print("Trace caveat: trace_hex records basic blocks, not every instruction;")
print("missing sites do not prove non-execution. Aggregated trace ordering alone")
print("does not prove that both observations belong to the same execution path.")
print("Bounded wait: 300000 ms; expected descriptor=0x141AAFE28.")
print("Constructor absence is compatible with an already-created dumped singleton.")

print("\n=== Semantic debt ===")
for _, name in ipairs({
    "unmapped_total", "ro_write_total", "vector_debt_total", "unsupported_total",
}) do
    print(name .. "=" .. scalar_text(r[name]))
end

local unmapped = type(r.unmapped_sites) == "table" and r.unmapped_sites or {}
print("unmapped_sites recorded=" .. tostring(#unmapped))
for i, site in ipairs(unmapped) do
    print(string.format("  [%d] op=%s address=%s page=%s",
        i, tostring(site.op or "unknown"),
        address_text(site.address_hex, site.address),
        address_text(site.page_hex, site.page)))
end
print("Fidelity: under-constrained reads, zero low pages, and symbolic object")
print("pointers can admit artificial paths; a find hit is not a native-run proof.")

local function ascii(bytes)
    return (bytes:gsub(".", function(char)
        local byte = string.byte(char)
        return byte >= 32 and byte <= 126 and char or "."
    end))
end

if found > 0 then
    print("\n=== Solver models ===")
    local models = type(r.inputs) == "table" and r.inputs or {}
    if #models == 0 then
        print("No solver models returned; reachability does not imply a model was produced.")
    end
    for model_index, model in ipairs(models) do
        print("Model #" .. tostring(model_index))
        if type(model) ~= "table" then
            print("  Unexpected model type: " .. type(model))
        else
            if #model == 0 then
                print("  <empty assignment>")
            end
            for variable_index, bytes in ipairs(model) do
                if type(bytes) ~= "string" then
                    print(string.format("  variable[%d]: unexpected type %s",
                        variable_index, type(bytes)))
                elseif #bytes == 0 then
                    print(string.format("  variable[%d]: len=0 hex= ascii=\"\"",
                        variable_index))
                else
                    print(string.format("  variable[%d]: len=%d",
                        variable_index, #bytes))
                    for offset = 1, #bytes, 32 do
                        local chunk = bytes:sub(offset, offset + 31)
                        print(string.format("    +%04x hex=%s ascii=%q",
                            offset - 1, angry.hex(chunk), ascii(chunk)))
                    end
                end
            end
        end
    end
    print("Model variable order is engine-defined; no register-name mapping is assumed.")
end

-- Verdict priority:
--   true_path: find hit, even if another/primary path returned status 41.
--   status41:  concrete known failure status.
--   incomplete: a budget interruption, remaining live states, or a clean
--               different return without a find hit.
--   stalled:   no hit/status41 and no remaining progress/clean-return evidence.
-- gdi/wait are trace-evidence flags, not claims of exhaustive non-execution.
local path
if found > 0 then
    path = "true_path"
elseif status41 then
    path = "status41"
elseif r.timed_out == true
    or counter(r, "live_states") > 0
    or counter(r, "steps") >= CONFIG.steps
    or r.exit_kind == "sentinel_ret"
then
    path = "incomplete"
else
    path = "stalled"
end

print(string.format(
    "VERDICT path=%s found=%s rax=%s gdi=%s wait=%s",
    path, scalar_text(found), scalar_text(r.rax_exit),
    crossed and "crossed" or "not_reached",
    wait_reached and "reached" or "not_reached"))