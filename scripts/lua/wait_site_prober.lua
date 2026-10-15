-- scripts/lua/wait_site_prober.lua
--
-- Concrete, interactive probing of the Windows x64 singleton/wait machinery.
-- RCX is seeded concretely: this machinery is data-driven, not solver-driven.
-- No symbolic registers or symbolic memory are introduced.
--
-- Tail filenames are installation-dependent. The defaults below use the naming
-- convention tail_<index>_<address>.bin. Set ANGRY_MEMLOAD_<index>_PATH to each
-- actual dump filename if your files differ; wildcard expansion is unavailable
-- in this sandbox.
--
-- STEP_BUDGET counts calls to step(1), not individual x86 instructions.
-- TIMEOUT_SECS is checked between API calls; it cannot interrupt a blocked
-- native step(), hook, or memory operation.

local CONFIG = {
    TARGET = "advisor_unpacked_state.exe",
    MEMLOADS_DIR = "memloads/",
    ENTRY = 0x1407C89C0,

    WATCH_SINGLETON_SLOT = 0x14221A4E8,
    WATCH_CTOR = 0x140404B00,
    WATCH_WAIT_FN = 0x140404E10,
    WATCH_WAIT_RET = 0x1407C8A4B,
    WATCH_HANG_CALL = 0x1405E398A,
    WATCH_HANG_TARGET = 0x140760100,

    STEP_BUDGET = 4000,
    TIMEOUT_SECS = 60,
    SPIN_VISITS = 64,
    SPIN_WINDOW_BYTES = 0x1000,

    -- Each address and path can also be overridden with:
    -- ANGRY_MEMLOAD_<index>_ADDR and ANGRY_MEMLOAD_<index>_PATH.
    LOAD_MEM = {
        { addr = 0x142142000, file = "tail_1_2142000.bin" },
        { addr = 0x1421BF400, file = "tail_2_21BF400.bin" },
        { addr = 0x1423E5E00, file = "tail_3_23E5E00.bin" },
        { addr = 0x1423E7C00, file = "tail_4_23E7C00.bin" },
        { addr = 0x1423E8000, file = "tail_5_23E8000.bin" },
        { addr = 0x1437E9E00, file = "tail_6_37E9E00.bin" },
    },
}

local ZERO_HEX = "0x0000000000000000"
local EXIT_SENTINEL = 0xDEADBEEF0000

local session
local events = {}
local postmortem = {}
local steps = 0
local outcome
local singleton_hex
local construction_seen = false
local started_at
local initial_slot_hex
local previous_slots = {}
local spin_counts = {}
local cfg

local function clean(value)
    return (tostring(value):gsub("[\r\n\t]", " "))
end

local function log(kind, message)
    events[#events + 1] = string.format(
        "EVENT step=%d kind=%s %s", steps, kind, clean(message)
    )
end

local function getenv(name)
    local value = os.getenv(name)
    if value == nil or value == "" then
        return nil
    end
    return value
end

-- Parse without ever constructing a floating-point address. Numeric API
-- arguments are restricted to nonnegative signed Lua integers: this API does
-- not document an exact string form for read_bytes() address arguments.
-- Upper-half addresses observed through *_hex remain fully supported as data.
local function parse_integer(text, label)
    if type(text) ~= "string" then
        error(label .. ": expected an integer string", 0)
    end

    text = text:match("^%s*(.-)%s*$")
    local base = 10
    if text:sub(1, 2):lower() == "0x" then
        base = 16
        text = text:sub(3)
    end
    if text == "" then
        error(label .. ": empty integer", 0)
    end

    local result = 0
    for i = 1, #text do
        local b = text:byte(i)
        local digit
        if b >= 48 and b <= 57 then
            digit = b - 48
        elseif b >= 65 and b <= 70 then
            digit = b - 65 + 10
        elseif b >= 97 and b <= 102 then
            digit = b - 97 + 10
        end

        if digit == nil or digit >= base then
            error(label .. ": invalid integer digit", 0)
        end
        if result > (math.maxinteger - digit) // base then
            error(label .. ": exceeds the exact nonnegative Lua integer range", 0)
        end
        result = result * base + digit
    end
    return result
end

local function env_integer(name, default, minimum)
    local text = getenv(name)
    local value = text and parse_integer(text, name) or default
    if math.type(value) ~= "integer" or value < (minimum or 0) then
        error(name .. ": invalid integer value", 0)
    end
    return value
end

local function integer_hex(value)
    assert(math.type(value) == "integer", "integer_hex requires an integer")
    return string.format("0x%016x", value)
end

-- Canonical exact hexadecimal representation, including upper-half pointers.
local function canonical_hex(value)
    if type(value) ~= "string" then
        error("expected an exact hexadecimal string from the API", 0)
    end
    local text = value:lower()
    if text:sub(1, 2) == "0x" then
        text = text:sub(3)
    end
    if #text == 0 or #text > 16 or not text:match("^[0-9a-f]+$") then
        error("invalid API hexadecimal string: " .. clean(value), 0)
    end
    return "0x" .. string.rep("0", 16 - #text) .. text
end

local function register_hex(st, name)
    local value = st:reg_hex(name)
    if value == nil then
        return "nil"
    end
    return canonical_hex(value)
end

local function state_label(st)
    -- Use strings as keys; never interpret a state ID as an address.
    return tostring(st:id())
end

local function read_slot(st)
    local bytes = st:read_bytes(cfg.WATCH_SINGLETON_SLOT, 8)
    if type(bytes) ~= "string" or #bytes ~= 8 then
        error("singleton slot read did not return exactly 8 bytes", 0)
    end

    -- Lua's native unsigned 8-byte unpack preserves the integer bit pattern,
    -- including values represented by negative signed Lua integers.
    local bits = string.unpack("<I8", bytes)
    return integer_hex(bits)
end

local function observe_slot(st, initial)
    local id = state_label(st)
    local current = read_slot(st)
    local previous = previous_slots[id]
    if previous == nil then
        previous = initial_slot_hex
    end

    singleton_hex = current ~= ZERO_HEX and current or nil
    previous_slots[id] = current

    if initial then
        initial_slot_hex = current
        log("SINGLETON_INITIAL", "state=" .. id .. " value=" .. current)
        if current ~= ZERO_HEX then
            log("NOTE", "singleton is already populated; no reset is performed")
        end
    elseif previous == ZERO_HEX and current ~= ZERO_HEX then
        construction_seen = true
        log("SINGLETON_CREATED",
            "state=" .. id .. " old=" .. ZERO_HEX .. " new=" .. current
            .. " evidence=observed_slot_publication")
    elseif previous ~= nil and previous ~= current then
        log("SINGLETON_CHANGED",
            "state=" .. id .. " old=" .. previous .. " new=" .. current)
    end
end

local function configure()
    cfg = {
        TARGET = getenv("ANGRY_TARGET") or CONFIG.TARGET,
        MEMLOADS_DIR = getenv("ANGRY_MEMLOADS_DIR") or CONFIG.MEMLOADS_DIR,
        ENTRY = env_integer("ANGRY_ENTRY", CONFIG.ENTRY),
        STEP_BUDGET = env_integer("STEP_BUDGET", CONFIG.STEP_BUDGET, 1),
        TIMEOUT_SECS = env_integer("TIMEOUT_SECS", CONFIG.TIMEOUT_SECS, 1),
        SPIN_VISITS = env_integer("SPIN_VISITS", CONFIG.SPIN_VISITS, 1),
        SPIN_WINDOW_BYTES = env_integer(
            "SPIN_WINDOW_BYTES", CONFIG.SPIN_WINDOW_BYTES, 1
        ),
        LOAD_MEM = {},
    }

    for _, name in ipairs({
        "WATCH_SINGLETON_SLOT",
        "WATCH_CTOR",
        "WATCH_WAIT_FN",
        "WATCH_WAIT_RET",
        "WATCH_HANG_CALL",
        "WATCH_HANG_TARGET",
    }) do
        cfg[name] = env_integer(name, CONFIG[name])
    end

    local dir = cfg.MEMLOADS_DIR
    if dir:sub(-1) ~= "/" and dir:sub(-1) ~= "\\" then
        dir = dir .. "/"
    end

    for i, slice in ipairs(CONFIG.LOAD_MEM) do
        local prefix = "ANGRY_MEMLOAD_" .. i
        local path = getenv(prefix .. "_PATH") or (dir .. slice.file)
        local addr = env_integer(prefix .. "_ADDR", slice.addr)

        local file, err = io.open(path, "rb")
        if not file then
            error(string.format(
                "cannot open memory slice %d (%s): %s; set %s_PATH "
                .. "to the actual filename (no wildcard expansion)",
                i, path, tostring(err), prefix
            ), 0)
        end
        file:close()
        cfg.LOAD_MEM[#cfg.LOAD_MEM + 1] = { addr = addr, path = path }
    end

    -- A symmetric vicinity around the VM transfer target. Compare canonical
    -- hex strings later, rather than converting observed PCs to numbers.
    local target = cfg.WATCH_HANG_TARGET
    local radius = cfg.SPIN_WINDOW_BYTES
    if target > math.maxinteger - radius then
        error("hang vicinity exceeds the supported numeric address range", 0)
    end
    cfg.SPIN_LOW_HEX = integer_hex(math.max(0, target - radius))
    cfg.SPIN_HIGH_HEX = integer_hex(target + radius)
    cfg.WAIT_RET_HEX = integer_hex(cfg.WATCH_WAIT_RET)
    cfg.CTOR_HEX = integer_hex(cfg.WATCH_CTOR)
    cfg.SENTINEL_HEX = integer_hex(EXIT_SENTINEL)
end

local function install_instrumentation()
    -- Group hooks so coincident environment overrides do not silently replace
    -- another callback at the same address.
    local hooks = {}
    local function add(addr, callback)
        if hooks[addr] == nil then
            hooks[addr] = {}
        end
        hooks[addr][#hooks[addr] + 1] = callback
    end

    add(cfg.WATCH_CTOR, function(st)
        log("CTOR_ENTRY",
            "state=" .. state_label(st)
            .. " pc=" .. canonical_hex(st:pc_hex())
            .. " rsp=" .. register_hex(st, "rsp")
            .. " rcx=" .. register_hex(st, "rcx"))
    end)

    add(cfg.WATCH_WAIT_FN, function(st)
        -- Windows x64 ABI, NOT SysV: arguments 1..4 are RCX/RDX/R8/R9.
        log("WAIT_ENTRY",
            "state=" .. state_label(st)
            .. " pc=" .. canonical_hex(st:pc_hex())
            .. " rcx=" .. register_hex(st, "rcx")
            .. " rdx=" .. register_hex(st, "rdx")
            .. " r8=" .. register_hex(st, "r8")
            .. " r9=" .. register_hex(st, "r9"))
    end)

    add(cfg.WATCH_HANG_CALL, function(st)
        log("HANG_CALL",
            "state=" .. state_label(st)
            .. " pc=" .. canonical_hex(st:pc_hex()))
    end)

    add(cfg.WATCH_HANG_TARGET, function(st)
        log("VM_TAIL_TRANSFER",
            "state=" .. state_label(st)
            .. " pc=" .. canonical_hex(st:pc_hex())
            .. " rsp=" .. register_hex(st, "rsp"))
    end)

    for addr, callbacks in pairs(hooks) do
        session:hook(addr, function(st)
            for _, callback in ipairs(callbacks) do
                callback(st)
            end
            -- nil means continue execution.
        end)
    end

    session:add_breakpoint(cfg.WATCH_WAIT_RET)
    session:add_breakpoint(cfg.WATCH_CTOR)

    -- Interactive entry probing uses a manual breakpoint at the synthetic
    -- return sentinel, avoiding an attempt to execute sentinel memory.
    session:add_breakpoint(EXIT_SENTINEL)
end

local function stepping_loop()
    while steps < cfg.STEP_BUDGET do
        if session:states_count() == 0 then
            outcome = construction_seen and "singleton_created" or "terminated"
            log("STOP", "reason=all_states_dead")
            return
        end

        if os.difftime(os.time(), started_at) >= cfg.TIMEOUT_SECS then
            outcome = construction_seen and "singleton_created" or "budget"
            log("STOP", "reason=timeout_secs limit=" .. cfg.TIMEOUT_SECS)
            return
        end

        -- Keep the current live state selected where possible. The concrete
        -- workload normally has only one path. If a path dies, choose another.
        local index = session:active_index()
        if index < 0 or index >= session:states_count() then
            if not session:select_state(0) then
                error("unable to select a live state", 0)
            end
        end

        local st = session:state()
        local id = state_label(st)

        -- Establish an inherited-path baseline before stepping a new state.
        if previous_slots[id] == nil then
            observe_slot(st, false)
        end

        steps = steps + 1
        local result = session:step(1)

        -- The handle remains valid even if this step moved its state into the
        -- dead pool. Always inspect the state that was actually stepped.
        local rip = st:reg_hex("rip")
        local pc = canonical_hex(rip or st:pc_hex())
        observe_slot(st, false)

        if result == "branched" then
            log("BRANCHED",
                "state=" .. id .. " live_states=" .. session:states_count())
        end

        if result == "breakpoint" then
            log("BREAKPOINT", "state=" .. id .. " pc=" .. pc)

            if pc == cfg.WAIT_RET_HEX then
                log("WAIT_RETURNED",
                    "state=" .. id .. " rax=" .. register_hex(st, "rax"))
                outcome = "wait_returned"
                return
            end

            if pc == cfg.SENTINEL_HEX then
                log("FUNCTION_RETURN",
                    "state=" .. id .. " rax=" .. register_hex(st, "rax"))
                if st:is_alive() then
                    st:terminate()
                end
            elseif pc == cfg.CTOR_HEX then
                -- One-shot breakpoint: remove it before the next step so the
                -- constructor can execute and its pre-execution hook can fire.
                session:remove_breakpoint(cfg.WATCH_CTOR)
                log("CTOR_RESUME", "constructor breakpoint removed")
            else
                error("unexpected breakpoint at " .. pc, 0)
            end
        elseif result == "terminated" or result == "hook_terminated" then
            log("STATE_STOP",
                "state=" .. id .. " result=" .. result .. " pc=" .. pc)
        elseif result ~= "stepped" and result ~= "branched" then
            error("unexpected step outcome: " .. tostring(result), 0)
        end

        if st:is_alive()
            and pc >= cfg.SPIN_LOW_HEX
            and pc <= cfg.SPIN_HIGH_HEX
        then
            if spin_counts[id] == nil then
                spin_counts[id] = {}
            end
            local counts = spin_counts[id]
            counts[pc] = (counts[pc] or 0) + 1
            if counts[pc] >= cfg.SPIN_VISITS then
                log("SPIN",
                    "state=" .. id .. " pc=" .. pc
                    .. " visits=" .. counts[pc]
                    .. " scope=sampled_same_pc_in_vm_vicinity")
                outcome = "spin"
                return
            end
        end

        if session:states_count() == 0 then
            outcome = construction_seen and "singleton_created" or "terminated"
            log("STOP", "reason=all_states_dead")
            return
        end
    end

    outcome = construction_seen and "singleton_created" or "budget"
    log("STOP", "reason=step_budget limit=" .. cfg.STEP_BUDGET)
end

local function run_probe()
    configure()
    started_at = os.time()

    log("CONFIG",
        "target=" .. cfg.TARGET
        .. " entry=" .. integer_hex(cfg.ENTRY)
        .. " singleton_slot=" .. integer_hex(cfg.WATCH_SINGLETON_SLOT))
    log("CONFIG",
        "step_budget=" .. cfg.STEP_BUDGET
        .. " timeout_secs=" .. cfg.TIMEOUT_SECS
        .. " spin_visits=" .. cfg.SPIN_VISITS
        .. " spin_low=" .. cfg.SPIN_LOW_HEX
        .. " spin_high=" .. cfg.SPIN_HIGH_HEX)

    session = angry.open(cfg.TARGET, {
        entry = cfg.ENTRY,
        uc_memory = true,
        zero_low_pages = true,
        load_mem = cfg.LOAD_MEM,
        regs = { rcx = 0 },
    })

    if session:states_count() == 0 then
        outcome = "terminated"
        log("STOP", "reason=no_initial_live_state")
        return
    end

    if not session:select_state(0) then
        error("unable to select initial state", 0)
    end
    observe_slot(session:state(), true)
    install_instrumentation()

    local ok, err = pcall(stepping_loop)
    if not ok then
        outcome = "error"
        log("FATAL", "stepping loop: " .. clean(err))
    end
end

local ok, err = pcall(run_probe)
if not ok then
    outcome = "error"
    log("FATAL", "probe setup/execution: " .. clean(err))
end

-- Do not terminate remaining live states merely to manufacture post-mortems.
-- Inspect only genuinely dead states, including explicit sentinel completion.
if session ~= nil then
    local inspected, inspection_error = pcall(function()
        local count = session:dead_count()
        for i = 0, count - 1 do
            local row_ok, row = pcall(function()
                local st = session:dead_state(i)
                local trace = st:trace_hex()
                local tail = {}
                for j = math.max(1, #trace - 11), #trace do
                    tail[#tail + 1] = canonical_hex(trace[j])
                end
                return {
                    index = i,
                    id = state_label(st),
                    pc = canonical_hex(st:pc_hex()),
                    rax = register_hex(st, "rax"),
                    tail = tail,
                }
            end)

            if row_ok then
                postmortem[#postmortem + 1] = row
            else
                outcome = "error"
                log("FATAL",
                    "dead_state[" .. i .. "] inspection: " .. clean(row))
                postmortem[#postmortem + 1] = {
                    index = i,
                    error = clean(row),
                }
            end
        end
    end)

    if not inspected then
        outcome = "error"
        log("FATAL", "post-mortem enumeration: " .. clean(inspection_error))
    end
end

print("=== wait_site_prober event log ===")
for _, event in ipairs(events) do
    print(event)
end

print("=== dead-state post-mortem ===")
print("index | state_id | pc | rax | trace_tail_last_12")
if #postmortem == 0 then
    print("(no dead states available)")
else
    for _, row in ipairs(postmortem) do
        if row.error then
            print(string.format("%d | ERROR | %s", row.index, row.error))
        else
            print(string.format(
                "%d | %s | %s | %s | %s",
                row.index, row.id, row.pc, row.rax,
                #row.tail > 0 and table.concat(row.tail, " ") or "(empty)"
            ))
        end
    end
end

print("=== fidelity / interpretation notes ===")
print("Per-state UC debt accessors are unavailable on LuaSession.")
print("Cross-check with an angry.run campaign and its semantic-debt telemetry if fidelity matters.")
print("UC memory and zero_low_pages can fabricate zero reads; observations are not proof of native behavior.")
print("A 0 -> nonzero slot transition records sampled singleton publication, not proof of constructor correctness.")
print("An initially populated singleton is preserved and is not counted as newly created.")
print("Spin detection counts sampled per-state PC visits near the VM target; it is a heuristic, not a liveness proof.")
print("Timeout checks occur between API calls and cannot interrupt a single native step.")
print("singleton_created takes precedence over budget/terminated only after an observed publication; wait_returned/spin/error take precedence.")

print(string.format(
    "VERDICT outcome=%s singleton=%s steps=%d",
    outcome or "error", singleton_hex or "nil", steps
))