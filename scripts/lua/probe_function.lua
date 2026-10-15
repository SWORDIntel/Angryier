--[[
probe_function.lua
==================

Isolated function, API-stub, dispatcher, and runtime-wrapper probe for
Angryier's documented Lua 5.4 API.

Configuration
-------------
Edit CONFIG below. Addresses and register values may be Lua integers or
exact hexadecimal strings such as "0x0000000000401000".

Register values above INT64_MAX are converted to signed Lua integer bit
patterns and passed to the numeric register setter. Every register write
is verified using reg_hex(). If the binding rejects signed bit patterns,
the script fails explicitly rather than silently rounding the value.

Address-taking methods have no documented hexadecimal/string overload.
Consequently, memory addresses, entry, and the exit sentinel must be in
0 .. INT64_MAX. High-half register values can still be used if the setter
accepts and correctly preserves their bit patterns.

Execution model
---------------
* angry.open() loads the binary.
* Concrete registers and memory are initialized.
* A synthetic return address is installed at [rsp].
* Symbolic registers/memory are introduced after concrete initialization.
* An exit breakpoint intercepts the sentinel before it executes.
* Paths are scheduled round-robin using stable state identities.
* The active-state cap is enforced after each native step.
* Excess states are explicitly classified as state_cap_pruned.
* Remaining paths are finalized when the global step/time budget expires.

"clean_return" means:
    sentinel reached AND rsp == initial_rsp + expected_stack_delta.

This is return-frame evidence, not proof that a RET instruction executed.
Set expected_stack_delta appropriately for RET imm16 or unusual wrappers.

Fidelity limitations
--------------------
The supplied LuaSession API does NOT expose:
    unmapped_sites
    ro_write_reverts
    vector_debt_sites
    unsupported_sites

These are reported as UNAVAILABLE, never as empty/no-debt findings.
angry.run() has some report fields, but replaying a separate campaign would
not measure the session configured here and is deliberately not done.

The API also does not expose structured trap/fault termination reasons.
Ordinary dead paths are therefore "terminated_unknown". Native exceptions
are "engine_error", with an explicitly non-authoritative textual hint.

A finite budget cannot prove an infinite loop. Budget exhaustion is
"step_budget"; hot pages and repeated PCs are diagnostic evidence only.

Trace reporting includes:
* observed step(1) start PCs, which are block-step samples;
* the engine's bounded execution trace ring;
* 4 KiB page frequencies within that trace ring.

Trace-ring frequencies are not full-history execution counts.

Timeouts use os.time(), have approximately one-second resolution, and are
checked between API calls. Native stepping, memory operations, callbacks,
and solver calls cannot be preempted by this script.

Dump files
----------
Every dump path must contain "{id}", replaced by the stable state ID.
Writes use a temporary file followed by rename. overwrite_dumps=false
prevents ordinary accidental replacement; it is not a cross-process lock.
Parent directories must already exist.

No ABI emulation, import resolution, syscall environment, or allocation
model is invented by this probe. Configure the required environment.
]]

local CONFIG = {
    binary = os.getenv("ANGRY_TARGET") or "./target.elf",
    entry = os.getenv("ANGRY_ENTRY") or "0x0000000000401000",

    -- SysV AMD64 function-entry alignment: rsp % 16 == 8.
    -- For Windows x64 this also leaves room above rsp for shadow space.
    regs = {
        rsp = "0x000000000000f008",
        rdi = 0,
        rsi = 0,
        rdx = 0,
        rcx = 0,
        r8  = 0,
        r9  = 0,

        -- Exact high-bit register value, if supported by the binding:
        -- rax = "0xffffffffffffffff",
    },

    -- Map form: { rdi = 64, rsi = 64 }
    -- Array form: { "rdi", "rsi" }
    -- This probe deliberately permits only full-width, non-stack GPRs.
    symbolic = {},

    -- Optional additional symbolic input regions.
    symbolic_memory = {
        -- { addr = "0x8000", len = 32 },
    },

    -- Each write installs exactly eight little-endian bytes.
    -- Values may be integers or exact 64-bit hexadecimal strings.
    poke = {
        -- { addr = "0x9000", value = "0x1122334455667788" },
    },

    -- Applied before poke writes. Later segments may overwrite earlier ones.
    -- len omitted: read from offset to EOF, subject to max_load_bytes.
    load_mem = {
        -- {
        --     addr = "0x8000",
        --     path = "./input.bin",
        --     offset = 0,
        --     len = 128,
        -- },
    },

    -- A mapped low-memory sentinel is convenient with zero_low_pages=true.
    exit = "0x000000000000ff00",
    expected_stack_delta = 8,

    uc_memory = true,
    zero_low_pages = true,
    uc_write_ro = false,

    -- Global number of attempted s:step(1) calls, NOT instructions.
    steps = tonumber(os.getenv("ANGRY_STEPS")) or 10000,

    -- Maximum retained live states. A native step may transiently exceed it.
    states = tonumber(os.getenv("ANGRY_STATES")) or 32,

    -- Includes setup, exploration, and post-call checks; cooperative only.
    -- Set to 0 to disable.
    timeout_secs = tonumber(os.getenv("ANGRY_TIMEOUT")) or 30,

    stop_on_engine_error = true,
    verify_memory_writes = true,

    -- eval_return asks the solver to evaluate rax on sentinel-reaching paths.
    -- A high-half value returned as a Lua float is NOT accepted as exact.
    eval_return = true,

    -- Optional model dump; symbol identities/order are not documented.
    solve_on_exit = false,
    max_model_symbols = 32,
    max_model_bytes_per_symbol = 128,

    trace_tail = 16,
    hot_pages = 8,
    step_sample_tail = 16,

    max_load_bytes = 16 * 1024 * 1024,
    max_dump_bytes = 16 * 1024 * 1024,
    dump_chunk_bytes = 64 * 1024,
    overwrite_dumps = false,

    -- when = "exit": sentinel-reaching paths only.
    -- when = "all": every finalized path, including pruned/dead paths.
    memory_dump_out = {
        -- {
        --     addr = "0x8000",
        --     len = 256,
        --     path = "./probe-memory-{id}.bin",
        --     when = "exit",
        -- },
    },
}

------------------------------------------------------------------------
-- Exact integer helpers: no conversion of high-half u64 values to float.
------------------------------------------------------------------------

local MAX_SAFE_FLOAT_INTEGER = 9007199254740991
local MAX_SIGNED = math.maxinteger

local function fail(message)
    error(message, 0)
end

local function require_integer(value, name, minimum, maximum)
    if type(value) ~= "number" or math.type(value) ~= "integer" then
        fail(name .. " must be a Lua integer")
    end
    if value < minimum or value > maximum then
        fail(name .. " is outside the permitted range")
    end
    return value
end

local function u64_hex(value, name)
    name = name or "value"

    if type(value) == "string" then
        local digits = value:gsub("^0[xX]", "")
        if #digits == 0 or #digits > 16 or digits:find("[^%x]") then
            fail(name .. " must contain 1..16 hexadecimal digits")
        end
        return "0x" .. string.rep("0", 16 - #digits) .. digits:lower()
    end

    if type(value) ~= "number" then
        fail(name .. " must be an integer or hexadecimal string")
    end

    if math.type(value) ~= "integer" then
        if value ~= value or value == math.huge or value == -math.huge
            or math.abs(value) > MAX_SAFE_FLOAT_INTEGER
            or value % 1 ~= 0 then
            fail(name .. " is not an exact integer; use a hexadecimal string")
        end
        value = assert(math.tointeger(value))
    end

    -- Negative Lua integers intentionally represent 64-bit bit patterns.
    return string.format("0x%016x", value)
end

local function hex_bits(hex)
    local result = 0
    for i = 3, 18 do
        result = (result << 4) | assert(tonumber(hex:sub(i, i), 16))
    end
    return result
end

local function address(value, name)
    local hex = u64_hex(value, name)
    if tonumber(hex:sub(3, 3), 16) >= 8 then
        fail(name .. ": high-half addresses have no documented exact "
            .. "address-setter representation; refusing an unsafe conversion")
    end
    return hex_bits(hex), hex
end

local function checked_range(addr, len, name)
    require_integer(len, name .. ".len", 0, MAX_SIGNED)
    if len > 0 and addr > MAX_SIGNED - (len - 1) then
        fail(name .. " extends beyond the supported address range")
    end
end

local function le64(hex)
    local bytes = {}
    for i = 17, 3, -2 do
        bytes[#bytes + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
    end
    return table.concat(bytes)
end

-- Convert an exact u64 hex string to unsigned decimal using small arithmetic.
local function unsigned_decimal(hex)
    local decimal = "0"
    for i = 3, 18 do
        local carry = tonumber(hex:sub(i, i), 16)
        local reverse = {}
        for j = #decimal, 1, -1 do
            local n = tonumber(decimal:sub(j, j)) * 16 + carry
            reverse[#reverse + 1] = tostring(n % 10)
            carry = n // 10
        end
        while carry > 0 do
            reverse[#reverse + 1] = tostring(carry % 10)
            carry = carry // 10
        end
        local forward = {}
        for j = #reverse, 1, -1 do
            forward[#forward + 1] = reverse[j]
        end
        decimal = table.concat(forward)
    end
    return decimal
end

local function signed_decimal(hex)
    if tonumber(hex:sub(3, 3), 16) < 8 then
        return unsigned_decimal(hex)
    end

    local digits, carry = {}, 1
    for i = 18, 3, -1 do
        local n = 15 - tonumber(hex:sub(i, i), 16) + carry
        digits[i - 2] = string.format("%x", n % 16)
        carry = n // 16
    end
    return "-" .. unsigned_decimal("0x" .. table.concat(digits))
end

local function exact_api_hex(value)
    -- Numeric u64 accessors may deliver imprecise high-half floats.
    if type(value) ~= "number" then
        return nil, "API did not return a number"
    end
    if math.type(value) == "float"
        and (value ~= value or math.abs(value) > MAX_SAFE_FLOAT_INTEGER) then
        return nil, "API returned a potentially rounded float"
    end
    local ok, result = pcall(u64_hex, value, "API result")
    if ok then
        return result
    end
    return nil, tostring(result)
end

local function safe(call)
    local ok, value = pcall(call)
    if ok then
        return value, nil
    end
    return nil, tostring(value)
end

local function heading(text)
    print(("\n%s\n%s"):format(text, string.rep("-", #text)))
end

local function field(name, value)
    print(("  %-25s %s"):format(name .. ":", tostring(value)))
end

local function state_key(st)
    return tostring(st:id())
end

local function hex_accessor(call)
    local value, err = safe(call)
    if value == nil then
        return nil, err or "accessor returned nil"
    end
    local ok, result = pcall(u64_hex, value, "hex accessor")
    if ok then
        return result
    end
    return nil, tostring(result)
end

local function error_hint(message)
    local text = tostring(message):lower()
    if text:find("unmapped", 1, true) then
        return "unmapped memory mentioned in error text"
    elseif text:find("unsupported", 1, true) then
        return "unsupported operation mentioned in error text"
    elseif text:find("trap", 1, true)
        or text:find("exception", 1, true)
        or text:find("invalid opcode", 1, true) then
        return "trap/exception mentioned in error text"
    end
    return "no recognized textual hint"
end

------------------------------------------------------------------------
-- Configuration validation.
------------------------------------------------------------------------

local GPRS = {
    rax = true, rbx = true, rcx = true, rdx = true,
    rsi = true, rdi = true, rbp = true,
    r8 = true, r9 = true, r10 = true, r11 = true,
    r12 = true, r13 = true, r14 = true, r15 = true,
}

local function normalize_config(c)
    if type(c.binary) ~= "string" or c.binary == "" then
        fail("binary must be a nonempty path")
    end

    require_integer(c.steps, "steps", 1, MAX_SIGNED)
    require_integer(c.states, "states", 1, MAX_SIGNED)
    require_integer(c.timeout_secs, "timeout_secs", 0, MAX_SIGNED)
    require_integer(c.expected_stack_delta, "expected_stack_delta", 0, MAX_SIGNED)
    require_integer(c.trace_tail, "trace_tail", 0, 100000)
    require_integer(c.hot_pages, "hot_pages", 0, 100000)
    require_integer(c.step_sample_tail, "step_sample_tail", 0, 100000)
    require_integer(c.max_load_bytes, "max_load_bytes", 1, MAX_SIGNED - 1)
    require_integer(c.max_dump_bytes, "max_dump_bytes", 1, MAX_SIGNED)
    require_integer(c.dump_chunk_bytes, "dump_chunk_bytes", 1, c.max_dump_bytes)
    require_integer(c.max_model_symbols, "max_model_symbols", 0, 100000)
    require_integer(c.max_model_bytes_per_symbol,
        "max_model_bytes_per_symbol", 0, c.max_load_bytes)

    for _, name in ipairs({
        "uc_memory", "zero_low_pages", "uc_write_ro",
        "stop_on_engine_error", "verify_memory_writes",
        "eval_return", "solve_on_exit", "overwrite_dumps",
    }) do
        if type(c[name]) ~= "boolean" then
            fail(name .. " must be boolean")
        end
    end

    c.entry_num, c.entry_hex = address(c.entry, "entry")
    c.exit_num, c.exit_hex = address(c.exit, "exit")
    if c.entry_hex == c.exit_hex then
        fail("entry and exit sentinel must differ")
    end

    c.reg_hex = {}
    for name, value in pairs(c.regs) do
        if type(name) ~= "string" or name ~= name:lower() then
            fail("register names must be lowercase strings")
        end
        if name == "rip" or name == "eip" or name == "ip" then
            fail("use entry instead of initializing the instruction pointer")
        end
        c.reg_hex[name] = u64_hex(value, "regs." .. name)
    end

    if not c.reg_hex.rsp then
        fail("regs.rsp is required for the synthetic return frame")
    end

    c.rsp_num, c.rsp_hex = address(c.reg_hex.rsp, "regs.rsp")
    checked_range(c.rsp_num, 8, "return frame")
    if c.rsp_num > MAX_SIGNED - c.expected_stack_delta then
        fail("expected post-return rsp is outside the supported range")
    end
    c.expected_rsp_hex = u64_hex(c.rsp_num + c.expected_stack_delta)

    c.symbolic_names = {}
    local symbolic_seen = {}
    for key, value in pairs(c.symbolic) do
        local name, width
        if type(key) == "number" then
            name, width = value, 64
        else
            name, width = key, value
        end
        if not GPRS[name] or width ~= 64 then
            fail("symbolic accepts only full-width, non-stack GPRs")
        end
        if not symbolic_seen[name] then
            symbolic_seen[name] = true
            c.symbolic_names[#c.symbolic_names + 1] = name
        end
    end
    table.sort(c.symbolic_names)

    for i, item in ipairs(c.load_mem) do
        item.addr_num = address(item.addr, "load_mem[" .. i .. "].addr")
        if type(item.path) ~= "string" or item.path == "" then
            fail("load_mem paths must be nonempty strings")
        end
        item.offset = item.offset or 0
        require_integer(item.offset, "load_mem.offset", 0, MAX_SIGNED)
        if item.len ~= nil then
            require_integer(item.len, "load_mem.len", 0, c.max_load_bytes)
            checked_range(item.addr_num, item.len, "load_mem")
        end
    end

    for i, item in ipairs(c.poke) do
        item.addr_num = address(item.addr, "poke[" .. i .. "].addr")
        item.value_hex = u64_hex(item.value, "poke[" .. i .. "].value")
        checked_range(item.addr_num, 8, "poke")
    end

    for i, item in ipairs(c.symbolic_memory) do
        item.addr_num = address(item.addr, "symbolic_memory[" .. i .. "].addr")
        checked_range(item.addr_num, item.len, "symbolic_memory")
        if item.len == 0 then
            fail("symbolic_memory regions must be nonempty")
        end
        local last = item.addr_num + item.len - 1
        if item.addr_num <= c.rsp_num + 7 and last >= c.rsp_num then
            fail("symbolic_memory overlaps the synthetic return address")
        end
    end

    for i, item in ipairs(c.memory_dump_out) do
        item.addr_num = address(item.addr, "memory_dump_out[" .. i .. "].addr")
        require_integer(item.len, "memory_dump_out.len", 0, c.max_dump_bytes)
        checked_range(item.addr_num, item.len, "memory_dump_out")
        if type(item.path) ~= "string"
            or not item.path:find("{id}", 1, true) then
            fail("each memory_dump_out path must contain {id}")
        end
        item.when = item.when or "exit"
        if item.when ~= "exit" and item.when ~= "all" then
            fail("memory_dump_out.when must be 'exit' or 'all'")
        end
    end

    return c
end

------------------------------------------------------------------------
-- Main probe.
------------------------------------------------------------------------

local function main()
    assert(type(angry) == "table", "Angryier Lua environment required")
    assert(io and io.open, "Lua file I/O is required")
    assert(os and os.time and os.rename and os.remove,
        "Lua time and filesystem support are required")

    local c = normalize_config(CONFIG)
    local started = os.time()

    local function elapsed()
        return math.max(0, os.difftime(os.time(), started))
    end

    local function expired()
        return c.timeout_secs > 0 and elapsed() >= c.timeout_secs
    end

    local function check_setup_timeout()
        if expired() then
            fail("timeout expired during setup")
        end
    end

    heading("Angryier isolated function probe")
    field("engine", angry.version())
    field("binary", c.binary)
    field("entry", c.entry_hex)
    field("exit sentinel", c.exit_hex)
    field("initial rsp", c.rsp_hex)
    field("expected exit rsp", c.expected_rsp_hex)
    field("step-call budget", c.steps)
    field("retained-state cap", c.states)
    field("timeout seconds", c.timeout_secs == 0 and "disabled" or c.timeout_secs)
    field("uc_memory", c.uc_memory)
    field("zero_low_pages", c.zero_low_pages)
    field("uc_write_ro", c.uc_write_ro)

    if c.rsp_num % 16 ~= 8 then
        print("  [warning] rsp is not aligned to the usual x64 function-entry ABI.")
    end
    if c.uc_memory or c.zero_low_pages or c.uc_write_ro then
        print("  [fidelity] Memory relaxations may hide faults or alter behavior.")
    end

    local s = angry.open(c.binary, {
        entry = c.entry_num,
        zero_low_pages = c.zero_low_pages,
        uc_memory = c.uc_memory,
        uc_write_ro = c.uc_write_ro,
    })

    local initial = s:state()
    local actual_entry = hex_accessor(function() return initial:pc_hex() end)
    if actual_entry ~= c.entry_hex then
        fail("entry override did not round-trip exactly")
    end

    local register_names = {}
    for name in pairs(c.reg_hex) do
        register_names[#register_names + 1] = name
    end
    table.sort(register_names)

    for _, name in ipairs(register_names) do
        local wanted = c.reg_hex[name]
        local ok, err = pcall(function()
            initial:reg(name, hex_bits(wanted))
        end)
        if not ok then
            fail("cannot initialize " .. name .. " to " .. wanted
                .. ": " .. tostring(err)
                .. "\nThe binding may reject signed representations of u64 values.")
        end
        local observed = hex_accessor(function()
            return initial:reg_hex(name)
        end)
        if observed ~= wanted then
            fail("register write verification failed for " .. name
                .. ": wanted " .. wanted .. ", observed " .. tostring(observed))
        end
    end

    local function write_checked(addr, data, description)
        check_setup_timeout()
        initial:write_bytes(addr, data)
        if c.verify_memory_writes then
            local actual = initial:read_bytes(addr, #data)
            if actual ~= data then
                fail(description .. ": memory write did not persist exactly")
            end
        end
        check_setup_timeout()
    end

    for i, segment in ipairs(c.load_mem) do
        check_setup_timeout()
        local file, err = io.open(segment.path, "rb")
        if not file then
            fail("cannot open load_mem file: " .. tostring(err))
        end

        local ok, data = pcall(function()
            local position, seek_error = file:seek("set", segment.offset)
            if position == nil then
                fail("load_mem seek failed: " .. tostring(seek_error))
            end

            if segment.len ~= nil then
                if segment.len == 0 then
                    return ""
                end
                local bytes = file:read(segment.len)
                if not bytes or #bytes ~= segment.len then
                    fail("load_mem file is shorter than the requested segment")
                end
                return bytes
            end

            local bytes = file:read(c.max_load_bytes + 1) or ""
            if #bytes > c.max_load_bytes then
                fail("load_mem file exceeds max_load_bytes")
            end
            return bytes
        end)

        local closed, close_error = file:close()
        if not ok then
            fail(tostring(data))
        end
        if not closed then
            fail("load_mem close failed: " .. tostring(close_error))
        end

        checked_range(segment.addr_num, #data, "load_mem")
        if #data > 0 then
            write_checked(segment.addr_num, data, "load_mem[" .. i .. "]")
        end
        field("loaded segment " .. i,
            ("%s: %d bytes at %s"):format(
                segment.path, #data, u64_hex(segment.addr_num)))
    end

    for i, item in ipairs(c.poke) do
        write_checked(item.addr_num, le64(item.value_hex), "poke[" .. i .. "]")
    end

    -- Deliberately written last: the probe owns this return-address slot.
    write_checked(c.rsp_num, le64(c.exit_hex), "synthetic return frame")

    for _, name in ipairs(c.symbolic_names) do
        initial:symbolic(name, 64)
    end
    for _, item in ipairs(c.symbolic_memory) do
        initial:symbolic_memory(item.addr_num, item.len)
    end

    local symbolic_inputs =
        #c.symbolic_names > 0 or #c.symbolic_memory > 0

    s:add_breakpoint(c.exit_num)
    check_setup_timeout()

    --------------------------------------------------------------------
    -- Output and per-path inspection.
    --------------------------------------------------------------------

    local finalized = {}
    local metadata = {}
    local kinds = {}
    local used_dump_paths = {}

    local stats = {
        calls = 0,
        branches = 0,
        paths = 0,
        exits = 0,
        clean = 0,
        pruned = 0,
        errors = 0,
        dump_errors = 0,
        peak_live = s:states_count(),
    }

    local function meta(st)
        local id = state_key(st)
        if not metadata[id] then
            metadata[id] = {
                dispatches = 0,
                samples = {},
                last_outcome = "not dispatched",
            }
        end
        return metadata[id], id
    end

    local function print_return_audit(st, reached_exit)
        local observed, observed_error = hex_accessor(function()
            return st:reg_hex("rax")
        end)

        local audited = observed
        local source = "concrete register view"

        if reached_exit and c.eval_return then
            local value, eval_error = safe(function() return st:eval("rax") end)
            if value ~= nil then
                local conversion_error
                audited, conversion_error = exact_api_hex(value)
                source = audited and "solver evaluation"
                    or ("unavailable: " .. tostring(conversion_error))
            else
                audited = nil
                source = "solver evaluation failed: " .. tostring(eval_error)
            end
        elseif symbolic_inputs then
            audited = nil
            source = "not evaluated; symbolic inputs are present"
        end

        field("rax concrete view", observed or ("unavailable: "
            .. tostring(observed_error)))
        field("rax audit source", source)

        local label = reached_exit and "rax_exit" or "rax_at_stop"
        if audited then
            field(label .. " hex", audited)
            field(label .. " unsigned", unsigned_decimal(audited))
            field(label .. " signed", signed_decimal(audited))
        else
            field(label, "UNKNOWN (no exact audited value)")
        end

        if reached_exit and c.solve_on_exit then
            local model, err = safe(function() return st:solve() end)
            if type(model) ~= "table" then
                field("model", "unavailable: " .. tostring(err))
            else
                field("model symbols", #model)
                for i = 1, math.min(#model, c.max_model_symbols) do
                    if type(model[i]) == "string" then
                        local bytes = model[i]
                        local shown = bytes:sub(1, c.max_model_bytes_per_symbol)
                        field("symbol[" .. i .. "]",
                            angry.hex(shown)
                            .. (#shown < #bytes and " ... [truncated]" or ""))
                    else
                        field("symbol[" .. i .. "]", "unexpected non-string value")
                    end
                end
                if #model > c.max_model_symbols then
                    print("  ... additional model symbols omitted")
                end
                print("  [model] Symbol ordering/names are not specified by the API.")
            end
        end
    end

    local function print_trace(st, m)
        print("  Block-step sample tail (observed step(1) start PCs):")
        if #m.samples == 0 then
            print("    <no samples>")
        else
            for _, pc in ipairs(m.samples) do
                print("    " .. pc)
            end
        end

        local trace, err = safe(function() return st:trace_hex() end)
        if type(trace) ~= "table" then
            field("execution trace", "unavailable: " .. tostring(err))
            return
        end

        local normalized, pages, pcs = {}, {}, {}
        for _, value in ipairs(trace) do
            local ok, hex = pcall(u64_hex, value, "trace PC")
            if ok then
                normalized[#normalized + 1] = hex
                local page = hex:sub(1, 15) .. "000"
                pages[page] = (pages[page] or 0) + 1
                pcs[hex] = (pcs[hex] or 0) + 1
            end
        end

        local n = #normalized
        field("trace-ring entries", n)
        print("  Engine execution trace tail:")
        if n == 0 or c.trace_tail == 0 then
            print("    <empty or disabled>")
        else
            for i = math.max(1, n - c.trace_tail + 1), n do
                print("    " .. normalized[i])
            end
        end

        local ranked = {}
        for page, count in pairs(pages) do
            ranked[#ranked + 1] = { page = page, count = count }
        end
        table.sort(ranked, function(a, b)
            if a.count ~= b.count then
                return a.count > b.count
            end
            return a.page < b.page
        end)

        print("  4 KiB page frequencies (this path's bounded trace ring):")
        for i = 1, math.min(#ranked, c.hot_pages) do
            local item = ranked[i]
            print(("    %s  %8d  %6.2f%%"):format(
                item.page, item.count, 100 * item.count / n))
        end

        local repeated_pc, repeats = nil, 0
        for pc, count in pairs(pcs) do
            if count > repeats
                or (count == repeats and (not repeated_pc or pc < repeated_pc)) then
                repeated_pc, repeats = pc, count
            end
        end

        if repeated_pc then
            field("most frequent trace PC", repeated_pc .. " (" .. repeats .. ")")
        end
        if n >= 32 and ranked[1] and ranked[1].count / n >= 0.80 then
            print("  [hotspot] >=80% of retained trace entries occupy one page.")
            print("            Possible spin/local loop; not proof of nontermination.")
        end
    end

    local function dump_memory(st, id, reached_exit)
        for _, item in ipairs(c.memory_dump_out) do
            if item.when == "all" or reached_exit then
                local path = item.path:gsub("{id}", function() return id end)
                local temporary = path .. ".tmp-probe-" .. id
                local file

                local ok, err = pcall(function()
                    if used_dump_paths[path] then
                        fail("duplicate dump destination: " .. path)
                    end
                    used_dump_paths[path] = true

                    if not c.overwrite_dumps then
                        local existing = io.open(path, "rb")
                        if existing then
                            existing:close()
                            fail("dump destination already exists: " .. path)
                        end
                    end

                    local open_error
                    file, open_error = io.open(temporary, "wb")
                    if not file then
                        fail("cannot open dump temporary file: "
                            .. tostring(open_error))
                    end

                    local offset = 0
                    while offset < item.len do
                        local length = math.min(
                            c.dump_chunk_bytes, item.len - offset)
                        local bytes = st:read_bytes(item.addr_num + offset, length)
                        if type(bytes) ~= "string" or #bytes ~= length then
                            fail("short or invalid memory read during dump")
                        end
                        local written, write_error = file:write(bytes)
                        if not written then
                            fail("dump write failed: " .. tostring(write_error))
                        end
                        offset = offset + length
                    end

                    local closed, close_error = file:close()
                    file = nil
                    if not closed then
                        fail("dump close failed: " .. tostring(close_error))
                    end

                    local renamed, rename_error = os.rename(temporary, path)
                    if not renamed then
                        fail("dump rename failed: " .. tostring(rename_error))
                    end
                end)

                if not ok then
                    if file then
                        pcall(function() file:close() end)
                    end
                    os.remove(temporary)
                    stats.dump_errors = stats.dump_errors + 1
                    field("memory dump ERROR", err)
                else
                    field("memory dump",
                        ("%s (%d bytes from %s)"):format(
                            path, item.len, u64_hex(item.addr_num)))
                end
            end
        end
    end

    local function finish(st, kind, detail, reached_exit)
        local m, id = meta(st)
        if finalized[id] then
            return
        end
        finalized[id] = true
        stats.paths = stats.paths + 1
        kinds[kind] = (kinds[kind] or 0) + 1

        if reached_exit then stats.exits = stats.exits + 1 end
        if kind == "clean_return" then stats.clean = stats.clean + 1 end
        if kind == "state_cap_pruned" then stats.pruned = stats.pruned + 1 end
        if kind == "engine_error" then stats.errors = stats.errors + 1 end

        heading("Path " .. id)
        field("exit_kind", kind)
        field("sentinel reached", reached_exit and "yes" or "no")
        field("exit_pc", hex_accessor(function() return st:pc_hex() end)
            or "unavailable")
        field("rsp at stop", hex_accessor(function()
            return st:reg_hex("rsp")
        end) or "unavailable")
        field("step calls on state ID", m.dispatches)
        field("last native outcome", m.last_outcome)
        field("path constraints", safe(function()
            return st:constraints_count()
        end) or "unavailable")

        if detail then
            field("detail", detail)
        end
        if kind == "engine_error" then
            field("UNCONFIRMED error hint", error_hint(detail))
        elseif kind == "terminated_unknown" then
            print("  [unknown] Trap, unmapped access, normal termination, and other")
            print("            native causes cannot be distinguished by this API.")
        elseif kind == "step_budget" then
            print("  [budget] Possible loop or simply insufficient budget.")
        end

        print_return_audit(st, reached_exit)
        print_trace(st, m)
        dump_memory(st, id, reached_exit)
    end

    local function stop_state(st, kind, detail, reached_exit)
        finish(st, kind, detail, reached_exit)
        if st:is_alive() then
            st:terminate()
        end
    end

    --------------------------------------------------------------------
    -- Stable-identity round-robin scheduler.
    --------------------------------------------------------------------

    local queue, queued = {}, {}
    local head, tail = 1, 0
    local dead_cursor = 0

    local function enqueue(st)
        local id = state_key(st)
        if not queued[id] and not finalized[id] then
            tail = tail + 1
            queue[tail] = st
            queued[id] = true
        end
    end

    local function pop()
        while head <= tail do
            local st = queue[head]
            queue[head] = nil
            head = head + 1
            local id = state_key(st)
            queued[id] = nil
            if not finalized[id] and st:is_alive() then
                return st
            end
        end
        queue, head, tail = {}, 1, 0
        return nil
    end

    local function live_snapshot()
        local result = {}
        for index = 0, s:states_count() - 1 do
            result[#result + 1] = s:state(index)
        end
        return result
    end

    local function refresh()
        local live = live_snapshot()
        stats.peak_live = math.max(stats.peak_live, #live)

        -- Process successful sentinel hits before pruning for the state cap.
        for _, st in ipairs(live) do
            if st:is_alive() and not finalized[state_key(st)] then
                local pc = hex_accessor(function() return st:pc_hex() end)
                if pc == c.exit_hex then
                    local rsp = hex_accessor(function()
                        return st:reg_hex("rsp")
                    end)
                    if rsp == c.expected_rsp_hex then
                        stop_state(st, "clean_return",
                            "Sentinel and expected stack consumption observed.", true)
                    else
                        stop_state(st, "sentinel_reached_stack_mismatch",
                            "Sentinel reached, but expected rsp is "
                                .. c.expected_rsp_hex .. ".", true)
                    end
                end
            end
        end

        live = live_snapshot()
        for i = #live, c.states + 1, -1 do
            stop_state(live[i], "state_cap_pruned",
                "Retained-state cap exceeded; path was not explored to completion.",
                false)
        end

        for _, st in ipairs(live_snapshot()) do
            meta(st)
            enqueue(st)
        end

        -- Dead-state indices are documented as 0-based; no pool deletion is used.
        local dead_count = s:dead_count()
        for index = dead_cursor, dead_count - 1 do
            local st = s:dead_state(index)
            if not finalized[state_key(st)] then
                finish(st, "terminated_unknown",
                    "Native dead state; no structured termination reason exposed.",
                    false)
            end
        end
        dead_cursor = dead_count
    end

    local function select_handle(st)
        local wanted = state_key(st)
        for index = 0, s:states_count() - 1 do
            if state_key(s:state(index)) == wanted then
                if not s:select_state(index) then
                    fail("select_state failed for an enumerated live state")
                end
                return true
            end
        end
        return false
    end

    refresh()
    local campaign_stop = "exhausted"

    while s:states_count() > 0 do
        if expired() then
            campaign_stop = "timeout"
            break
        end
        if stats.calls >= c.steps then
            campaign_stop = "step_budget"
            break
        end

        local st = pop()
        if not st then
            refresh()
            st = pop()
            if not st then
                if s:states_count() > 0 then
                    fail("scheduler has live states but no runnable handle")
                end
                break
            end
        end

        if select_handle(st) then
            local m = meta(st)
            local pc = hex_accessor(function() return st:pc_hex() end)
            if pc and c.step_sample_tail > 0 then
                m.samples[#m.samples + 1] = pc
                if #m.samples > c.step_sample_tail then
                    table.remove(m.samples, 1)
                end
            end

            stats.calls = stats.calls + 1
            m.dispatches = m.dispatches + 1

            local ok, outcome = pcall(function() return s:step(1) end)
            if not ok then
                m.last_outcome = "exception"
                stop_state(st, "engine_error", tostring(outcome), false)
                refresh()
                if c.stop_on_engine_error then
                    campaign_stop = "campaign_aborted"
                    break
                end
            else
                m.last_outcome = tostring(outcome)

                if outcome == "branched" then
                    stats.branches = stats.branches + 1
                end

                -- A breakpoint other than our sentinel must not busy-loop.
                if outcome == "breakpoint" and s:states_count() > 0 then
                    local active = s:state()
                    local active_pc = hex_accessor(function()
                        return active:pc_hex()
                    end)
                    if active_pc ~= c.exit_hex then
                        stop_state(active, "unexpected_breakpoint",
                            "Native breakpoint outcome away from the sentinel.",
                            false)
                    end
                end

                refresh()

                if outcome ~= "stepped"
                    and outcome ~= "branched"
                    and outcome ~= "terminated"
                    and outcome ~= "breakpoint"
                    and outcome ~= "hook_terminated" then
                    campaign_stop = "campaign_aborted"
                    print("[error] Unexpected native step outcome: "
                        .. tostring(outcome))
                    break
                end
            end
        else
            refresh()
        end
    end

    for _, st in ipairs(live_snapshot()) do
        stop_state(st, campaign_stop,
            "Campaign stopped before this path reached the return sentinel.",
            false)
    end

    --------------------------------------------------------------------
    -- Campaign summary and explicit fidelity/debt accounting.
    --------------------------------------------------------------------

    heading("Campaign summary")
    field("stop reason", campaign_stop)
    field("elapsed wall seconds", elapsed())
    field("step(1) calls", stats.calls)
    field("native branch outcomes", stats.branches)
    field("behavior branched", stats.branches > 0 and "yes" or "not observed")
    field("peak live states", stats.peak_live)
    field("finalized paths", stats.paths)
    field("sentinel-reaching paths", stats.exits)
    field("clean return-frame paths", stats.clean)
    field("state-cap pruned paths", stats.pruned)
    field("engine errors", stats.errors)
    field("memory dump errors", stats.dump_errors)

    local kind_names = {}
    for kind in pairs(kinds) do
        kind_names[#kind_names + 1] = kind
    end
    table.sort(kind_names)
    for _, kind in ipairs(kind_names) do
        field("kind/" .. kind, kinds[kind])
    end

    heading("Debt and fidelity report")
    for _, name in ipairs({
        "unmapped_sites",
        "ro_write_reverts",
        "vector_debt_sites",
        "unsupported_sites",
    }) do
        field(name, "UNAVAILABLE: no documented LuaSession accessor")
    end

    print("  Missing telemetry is not evidence that no debt occurred.")
    print("  With UC memory enabled, an unmapped access may be tolerated without")
    print("  terminating the path; this session API cannot enumerate those accesses.")
    print("  Solver results characterize the engine's modeled execution, not a")
    print("  guarantee of equivalent native behavior under these relaxations.")
    print("  Memory dumps use read_bytes(): they are concrete memory views, not")
    print("  documented solver-model materializations of symbolic memory.")
    print("  Branch counts reflect reported native branch outcomes, not a complete")
    print("  control-flow graph or proof that every feasible branch was explored.")

    if stats.pruned > 0 then
        print("  [incomplete] State-cap pruning discarded paths.")
    end
    if campaign_stop == "step_budget" or campaign_stop == "timeout"
        or campaign_stop == "campaign_aborted" then
        print("  [incomplete] Exploration ended before all paths completed.")
    end
    if elapsed() > c.timeout_secs and c.timeout_secs > 0 then
        print("  [timeout] Native calls or final reporting exceeded the cooperative")
        print("            deadline; Lua cannot forcibly cancel those operations.")
    end
end

local function traceback(err)
    local message = tostring(err)
    if debug and debug.traceback then
        return debug.traceback(message, 2)
    end
    return message
end

local ok, err = xpcall(main, traceback)
if not ok then
    print("\n[probe_function: fatal]\n" .. tostring(err))
    -- Propagate failure to the embedding runner rather than claiming success.
    error("probe_function failed; see diagnostic above", 0)
end
