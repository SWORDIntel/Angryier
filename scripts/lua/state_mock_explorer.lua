-- scripts/lua/state_mock_explorer.lua
--
-- Synthetic Environment & Object Mock Generator for Angryier / Lua 5.4.
--
-- FEATURES
--   * Bounded, aligned scratch arenas.
--   * Ordered memory overlays and supplementary file slices.
--   * Little-endian 32/64-bit fields.
--   * Sentinel and circular doubly-linked lists.
--   * C++-style objects, vtables, native stubs, and hook declarations.
--   * Baseline versus mocked angry.run campaigns.
--   * Solver input formatting, comparative metrics, trace/debt reporting.
--   * Documented LuaSession application through Builder:apply(session).
--
-- IMPORTANT API BOUNDARY
--   The supplied reference documents these angry.run options:
--     symbolic, find, avoid, steps, states, solve, zero_low_pages.
--
--   It does NOT specify headless entry/regs/poke/load_mem/hooks/timeouts,
--   nor a memory-mapping operation. These require CONFIG.headless_adapter.
--
--   Adapter contract:
--
--     options, cleanup = adapter(base_options, request)
--
--   The adapter MUST:
--     1. Preserve all base_options semantics.
--     2. Apply request.entry, request.regs and memory relaxations.
--     3. Honor request.timeout_ms, or raise an error if unsupported.
--     4. Provide mapped backing for request.allocations.
--     5. Apply request.operations IN ORDER before exploration.
--     6. Install request.hooks, or reject them explicitly.
--     7. Return options understood by this build's angry.run.
--
--   request.operations entries:
--     {
--       kind = "write_bytes" | "poke" | "load_mem",
--       addr = integer,
--       data = raw_byte_string,       -- authoritative final byte content
--       label = string,
--
--       -- For poke operations:
--       width = 4 | 8,
--       value = original_value,
--
--       -- For load_mem operations:
--       path = string,
--       offset = integer,
--       len = integer
--     }
--
--   "load_mem" is a builder operation, NOT an assumed angry.run schema.
--   File contents are captured during construction so both phases use
--   the same bytes even if the source file subsequently changes.
--
--   cleanup, when supplied, must be a no-argument function. It is called
--   after angry.run succeeds or fails. An adapter that fails during its
--   own preparation must clean up resources before raising its error.
--
-- ADDRESS POLICY
--   Allocation and memory-operation addresses must fit nonnegative Lua
--   integers. High-half addresses cannot safely be passed through the
--   numeric API specified in the reference and are rejected.
--
--   Pointer FIELD CONTENTS may contain any 64-bit bit pattern:
--     builder:u64(slot, "0xffff800000001000")
--
--   Reported addresses always prefer *_hex fields.
--
-- SAFETY / INTERPRETATION
--   Reachability under mocks is conditional on the synthetic environment.
--   Return-zero stubs are assumptions, not faithful implementations.
--   A successful mocked run does not prove feasibility in the original
--   program environment.
--
-- CONFIGURATION
--   Edit CONFIG below. ANGRY_TARGET supplies the target path.
--   Optional environment variables:
--     ANGRY_ENTRY : nonnegative address
--     ANGRY_FIND  : comma/space-separated addresses
--     ANGRY_AVOID : comma/space-separated addresses
--
--   Set library_only=true to load this file with dofile() and obtain:
--     { Builder = ..., config = ..., main = ... }
--
--   No third-party Lua modules are required.

local CONFIG = {
    library_only = false,

    target = os.getenv("ANGRY_TARGET") or "./target.elf",
    entry = os.getenv("ANGRY_ENTRY"),

    find = {},                 -- Or set ANGRY_FIND.
    avoid = {},                -- Or set ANGRY_AVOID.

    symbolic = {},             -- Example: { rsi = 64 }.
    regs = {},                 -- Concrete registers common to both phases.

    steps = tonumber(os.getenv("ANGRY_STEPS")) or 10000,
    states = tonumber(os.getenv("ANGRY_STATES")) or 64,
    timeout_ms = 30000,         -- Requires adapter enforcement.
    solve = true,

    uc_memory = true,
    zero_low_pages = true,
    uc_write_ro = false,

    -- Supplementary memory common to BOTH phases.
    -- This ensures the comparison isolates synthetic mocks.
    load_mem = {
        -- {
        --     path = "./dump.data",
        --     addr = 0x600000,
        --     offset = 0,
        --     len = 0x1000,     -- Omit to load through EOF.
        --     label = "supplementary data"
        -- },
    },

    arenas = {
        {
            name = "scratch",
            base = 0x20000000,
            size = 0x100000,
            alignment = 16,
        },
    },

    limits = {
        max_blob_bytes = 16 * 1024 * 1024,
        max_total_bytes = 64 * 1024 * 1024,
        max_operations = 100000,
        max_nodes = 10000,
        max_vtable_entries = 4096,
        max_models = 32,
        max_model_bytes = 512,
        trace_tail = 16,
        debt_items = 8,
    },

    -- All example ABI/layout choices are target-specific.
    example = {
        argument_register = "rdi",
        registry_slot = nil,   -- Optional absolute global pointer slot.
        object_size = 0x40,
        vptr_offset = 0x00,
        list_offset = 0x08,
        count_offset = 0x10,
        config_offset = 0x18,
    },

    -- Configure against the ACTUAL headless API in your checkout.
    --
    -- Do not simply pass request as angry.run options: its schema is
    -- deliberately independent of undocumented engine option schemas.
    --
    -- headless_adapter = function(base_options, request)
    --     ... translate / materialize all requested features ...
    --     return actual_engine_options, function()
    --         ... remove temporary resources ...
    --     end
    -- end,
    headless_adapter = function(base_options, request)
        local opts = {}
        for k, v in pairs(base_options) do opts[k] = v end

        if request.entry ~= nil then
            opts.entry = request.entry
        end
        if request.regs and next(request.regs) ~= nil then
            opts.regs = request.regs
        end
        if request.uc_memory ~= nil then
            opts.uc_memory = request.uc_memory
        end
        if request.uc_write_ro ~= nil then
            opts.uc_write_ro = request.uc_write_ro
        end

        local pokes = {}
        local load_mems = {}

        for _, op in ipairs(request.operations or {}) do
            if op.kind == "poke" then
                pokes[#pokes + 1] = {
                    addr = op.addr,
                    value = op.value,
                }
            elseif op.kind == "load_mem" then
                load_mems[#load_mems + 1] = {
                    addr = op.addr,
                    path = op.path,
                }
            elseif op.kind == "write_bytes" then
                -- Store as 8-byte pokes if possible
                local d = op.data
                local off = 0
                while off + 8 <= #d do
                    local val = string.unpack("<I8", d, off + 1)
                    pokes[#pokes + 1] = {
                        addr = op.addr + off,
                        value = val,
                    }
                    off = off + 8
                end
            end
        end

        if #pokes > 0 then
            opts.poke = pokes
        end
        if #load_mems > 0 then
            opts.load_mem = load_mems
        end

        return opts, nil
    end,

    -- Replace this callback with the layout required by your target.
    -- Its default implementation demonstrates all primary DSL features.
    build_mock = function(m, cfg)
        local ret0 = m:return0("return-zero assumption")

        local vt = m:vtable({
            ret0,
            ret0,
            -- Other supported entries:
            -- 0x401234,                       -- existing native code
            -- { native = "\x31\xc0\xc3" },    -- emitted machine code
            -- { hook = function(st) ... end,
            --   fallback = "\x31\xc0\xc3" },
        }, { label = "synthetic vtable" })

        local list = m:list({
            { id = 101, payload = "alpha\0" },
            { id = 202, payload = "beta\0" },
            { id = 303, payload = "gamma\0" },
        }, {
            mode = "sentinel",
            label = "synthetic registry",
            node_size = 0x20,
            layout = {
                next = 0x00,
                prev = 0x08,
                id = 0x10,
                payload = 0x18,
            },
        })

        local config = m:buffer(string.rep("\0", 0x20), {
            label = "subsystem configuration",
        })
        m:fields(config, {
            { offset = 0x00, type = "u32", value = 1 },
            { offset = 0x04, type = "u32", value = 3 },
            { offset = 0x08, type = "u64", value = list.head },
        })

        local e = cfg.example
        local object = m:object(e.object_size, vt, {
            vptr_offset = e.vptr_offset,
            label = "synthetic subsystem object",
        })
        m:fields(object, {
            { offset = e.list_offset, type = "u64", value = list.head },
            { offset = e.count_offset, type = "u32", value = list.count },
            { offset = e.config_offset, type = "u64", value = config },
        }, e.object_size)

        if e.registry_slot ~= nil then
            m:u64(e.registry_slot, object, "global registry pointer")
        end
        if e.argument_register ~= nil then
            m:set_reg(e.argument_register, object)
        end

        m:note("Object rooted at " .. string.format("0x%016x", object))
        m:note("Virtual methods assume return value zero")
        m:note("Node layout, ABI and configuration values require validation")
    end,
}

------------------------------------------------------------------------
-- General helpers
------------------------------------------------------------------------

local function fail(message)
    error("state_mock_explorer: " .. message, 0)
end

local function traceback(err)
    local msg = tostring(err)
    if debug and debug.traceback then
        return debug.traceback(msg, 2)
    end
    return msg
end

local function check(condition, message)
    if not condition then
        fail(message)
    end
end

local function integer(value, label, minimum)
    check(math.type(value) == "integer",
          label .. " must be a Lua integer")
    check(value >= (minimum or 0),
          label .. " is below its permitted minimum")
    return value
end

local function address(value, label)
    label = label or "address"
    if type(value) == "string" then
        local text = value:match("^%s*(.-)%s*$")
        local digits = text:match("^0[xX]([%da-fA-F]+)$")
        if digits then
            digits = digits:gsub("^0+", "")
            if digits == "" then digits = "0" end
            check(#digits <= 16, label .. " exceeds 64 bits")
            check(#digits < 16 or tonumber(digits:sub(1, 1), 16) < 8,
                  label .. ": high-half addresses need an API extension")
        else
            check(text:match("^%d+$") ~= nil,
                  label .. " must be decimal or 0x-prefixed hexadecimal")
        end
        value = tonumber(text)
    end
    return integer(value, label, 0)
end

local function add(a, b, label)
    integer(a, label or "addition", 0)
    integer(b, label or "addition", 0)
    check(a <= math.maxinteger - b,
          (label or "address addition") .. " overflows")
    return a + b
end

local function copy(value, seen)
    if type(value) ~= "table" then return value end
    seen = seen or {}
    if seen[value] then return seen[value] end
    local result = {}
    seen[value] = result
    for k, v in pairs(value) do
        result[copy(k, seen)] = copy(v, seen)
    end
    return result
end

local function merge(a, b)
    local result = copy(a or {})
    for k, v in pairs(b or {}) do result[k] = v end
    return result
end

local function nonempty(t)
    return type(t) == "table" and next(t) ~= nil
end

local function addresses_from_env(name)
    local result = {}
    for token in (os.getenv(name) or ""):gmatch("[^,%s]+") do
        result[#result + 1] = address(token, name)
    end
    return result
end

local function range_end(addr, len)
    address(addr)
    integer(len, "range length", 1)
    return add(addr, len - 1, "range end")
end

local function hex_bytes(data)
    return (data:gsub(".", function(c)
        return string.format("%02x", c:byte())
    end))
end

local function ascii_bytes(data)
    return (data:gsub(".", function(c)
        local n = c:byte()
        return n >= 32 and n <= 126 and c or "."
    end))
end

local function clean(value, limit)
    local text = tostring(value)
    text = text:gsub("[%c]", "?")
    limit = limit or 160
    if #text > limit then
        return text:sub(1, limit) .. "..."
    end
    return text
end

-- Encode field values without converting full-width hexadecimal pointers
-- through floating point.
local function pack_field(value, width)
    if type(value) == "string" then
        local digits = value:match("^0[xX]([%da-fA-F]+)$")
        check(digits ~= nil,
              "string field values must use 0x-prefixed hexadecimal")
        check(#digits <= width * 2, "field value exceeds its width")
        digits = string.rep("0", width * 2 - #digits) .. digits
        local bytes = {}
        for i = #digits - 1, 1, -2 do
            bytes[#bytes + 1] =
                string.char(tonumber(digits:sub(i, i + 1), 16))
        end
        return table.concat(bytes)
    end

    check(math.type(value) == "integer",
          "field value must be an integer or hexadecimal string")
    if width == 4 then
        check(value >= 0 and value <= 0xffffffff,
              "u32 value is outside 0..0xffffffff")
        return string.pack("<I4", value)
    end

    -- Negative integers are accepted as their two's-complement bit pattern.
    return string.pack("<i8", value)
end

local function reported_address(record, key)
    if type(record) ~= "table" then return "n/a" end

    local exact = record[key .. "_hex"]
    if type(exact) == "string" then
        return clean(exact)
    end

    local value = record[key]
    if value == nil then return "n/a" end
    if math.type(value) == "integer" then
        return string.format("0x%016x", value)
    end
    if type(value) == "string" then
        return clean(value)
    end
    if type(value) == "number" then
        return "<numeric address lacks exact _hex representation>"
    end
    return "<unrecognized address representation>"
end

------------------------------------------------------------------------
-- Mock builder
------------------------------------------------------------------------

local Builder = {}
Builder.__index = Builder

function Builder.new(arena_specs, limits)
    local self = setmetatable({
        arenas = {},
        arena_order = {},
        allocations = {},
        operations = {},
        hooks = {},
        regs = {},
        notes = {},
        total_bytes = 0,
        limits = copy(limits),
    }, Builder)

    for _, spec in ipairs(arena_specs or {}) do
        local name = spec.name
        check(type(name) == "string" and name ~= "", "arena needs a name")
        check(not self.arenas[name], "duplicate arena: " .. name)

        local base = address(spec.base, "arena base")
        local size = integer(spec.size, "arena size", 1)
        local last = range_end(base, size)
        local alignment = integer(spec.alignment or 16,
                                  "arena alignment", 1)

        for _, other in ipairs(self.arena_order) do
            check(last < other.base or base > other.last,
                  "overlapping arenas: " .. name .. " and " .. other.name)
        end

        local arena = {
            name = name, base = base, size = size, last = last,
            cursor = base, alignment = alignment,
        }
        self.arenas[name] = arena
        self.arena_order[#self.arena_order + 1] = arena
    end

    return self
end

function Builder:note(message)
    self.notes[#self.notes + 1] = tostring(message)
end

function Builder:_emit(op)
    check(type(op.data) == "string", "memory operation requires bytes")
    if #op.data == 0 then return op.addr end

    op.addr = address(op.addr)
    range_end(op.addr, #op.data)

    check(#op.data <= self.limits.max_blob_bytes,
          "memory operation exceeds max_blob_bytes")
    check(#self.operations < self.limits.max_operations,
          "operation count exceeds max_operations")
    check(self.total_bytes <= self.limits.max_total_bytes - #op.data,
          "memory operations exceed max_total_bytes")

    self.total_bytes = self.total_bytes + #op.data
    self.operations[#self.operations + 1] = op
    return op.addr
end

function Builder:write(addr, data, label)
    return self:_emit({
        kind = "write_bytes",
        addr = addr,
        data = data,
        label = label or "raw bytes",
    })
end

function Builder:u64(addr, value, label)
    return self:_emit({
        kind = "poke",
        addr = addr,
        data = pack_field(value, 8),
        width = 8,
        value = value,
        label = label or "u64",
    })
end

function Builder:u32(addr, value, label)
    return self:_emit({
        kind = "poke",
        addr = addr,
        data = pack_field(value, 4),
        width = 4,
        value = value,
        label = label or "u32",
    })
end

function Builder:fields(base, fields, object_size)
    base = address(base)
    if object_size ~= nil then
        integer(object_size, "object size", 1)
    end

    for _, field in ipairs(fields) do
        local offset = integer(field.offset, "field offset", 0)
        local width = field.type == "u64" and 8
                   or field.type == "u32" and 4
        check(width ~= nil, "field type must be u32 or u64")
        if object_size then
            check(offset <= object_size - width,
                  "field extends beyond its object")
        end

        local slot = add(base, offset, "field address")
        self[field.type](self, slot, field.value, field.label)
    end
    return base
end

function Builder:alloc(size, opts)
    opts = opts or {}
    integer(size, "allocation size", 1)
    check(size <= self.limits.max_blob_bytes,
          "allocation exceeds max_blob_bytes")

    local arena = opts.arena and self.arenas[opts.arena]
               or self.arena_order[1]
    check(arena ~= nil, "allocation requires a configured arena")

    local alignment = integer(opts.alignment or arena.alignment,
                              "allocation alignment", 1)
    local padding = (alignment - arena.cursor % alignment) % alignment
    local addr = add(arena.cursor, padding, "aligned allocation")
    local last = range_end(addr, size)
    check(last <= arena.last, "arena exhausted: " .. arena.name)

    -- Keep the cursor representable, including after the last allocation.
    check(last < math.maxinteger, "allocation leaves no representable cursor")
    arena.cursor = last + 1

    self.allocations[#self.allocations + 1] = {
        addr = addr,
        len = size,
        label = opts.label or "allocation",
        arena = arena.name,
        executable = opts.executable == true,
    }

    if opts.zero ~= false then
        self:write(addr, string.rep("\0", size),
                   (opts.label or "allocation") .. " zero initialization")
    end
    return addr
end

function Builder:buffer(data, opts)
    check(type(data) == "string", "buffer requires a byte string")
    check(#data > 0, "empty buffers need an explicit allocation size")
    opts = copy(opts or {})
    opts.zero = false
    local addr = self:alloc(#data, opts)
    self:write(addr, data, opts.label or "buffer")
    return addr
end

function Builder:load_mem(spec)
    check(type(spec.path) == "string" and spec.path ~= "",
          "load_mem requires a path")
    local addr = address(spec.addr, "load_mem address")
    local offset = integer(spec.offset or 0, "file offset", 0)

    local file, open_error = io.open(spec.path, "rb")
    check(file ~= nil, "cannot open " .. spec.path .. ": " ..
                      tostring(open_error))

    local ok, result = xpcall(function()
        local size, seek_error = file:seek("end")
        check(size ~= nil, "cannot seek input: " .. tostring(seek_error))
        check(offset <= size, "file slice begins past EOF")

        local len = spec.len
        if len == nil then len = size - offset end
        integer(len, "file slice length", 1)
        check(len <= size - offset, "file slice extends past EOF")
        check(len <= self.limits.max_blob_bytes,
              "file slice exceeds max_blob_bytes")
        range_end(addr, len)

        local position, position_error = file:seek("set", offset)
        check(position ~= nil,
              "cannot seek slice: " .. tostring(position_error))
        local data, read_error = file:read(len)
        check(type(data) == "string" and #data == len,
              "short/failed file read: " .. tostring(read_error))
        return {
            kind = "load_mem",
            addr = addr,
            data = data,
            path = spec.path,
            offset = offset,
            len = len,
            label = spec.label or spec.path,
        }
    end, traceback)

    local closed, close_error = file:close()
    if not ok then error(result, 0) end
    check(closed, "file close failed: " .. tostring(close_error))
    return self:_emit(result)
end

function Builder:native(code, label)
    check(type(code) == "string" and #code > 0,
          "native code must be a nonempty byte string")
    return self:buffer(code, {
        alignment = 16,
        executable = true,
        label = label or "native code",
    })
end

function Builder:return0(label)
    -- xor eax,eax ; ret
    -- Valid for ordinary x86-64 integer return values.
    -- Does not model structure returns, side effects, or special ABIs.
    return self:native("\x31\xc0\xc3", label or "return-zero stub")
end

function Builder:hook(addr, callback, label)
    addr = address(addr, "hook address")
    check(type(callback) == "function", "hook requires a Lua function")
    for _, hook in ipairs(self.hooks) do
        check(hook.addr ~= addr, "duplicate hook address")
    end
    self.hooks[#self.hooks + 1] = {
        addr = addr,
        callback = callback,
        label = label or "custom hook",
    }
    return addr
end

function Builder:vtable(entries, opts)
    opts = opts or {}
    check(type(entries) == "table" and #entries > 0,
          "vtable requires entries")
    check(#entries <= self.limits.max_vtable_entries,
          "too many vtable entries")

    local ptr = self:alloc(#entries * 8, {
        arena = opts.arena,
        alignment = 8,
        label = opts.label or "vtable",
    })

    for index, entry in ipairs(entries) do
        local target
        if type(entry) == "table" then
            if entry.hook ~= nil then
                check(entry.native == nil,
                      "hook entries use fallback, not native")
                target = self:native(entry.fallback or "\x31\xc0\xc3",
                                     entry.label or "hook fallback")
                self:hook(target, entry.hook, entry.label)
            elseif entry.native ~= nil then
                target = self:native(entry.native, entry.label)
            elseif entry.addr ~= nil then
                target = entry.addr
            else
                fail("vtable entry requires addr, native, or hook")
            end
        else
            target = entry
        end
        self:u64(ptr + (index - 1) * 8, target,
                 "vtable slot " .. (index - 1))
    end

    return ptr
end

function Builder:object(size, vtable, opts)
    opts = opts or {}
    local offset = integer(opts.vptr_offset or 0, "vptr offset", 0)
    integer(size, "object size", 1)
    check(offset <= size - 8, "vptr does not fit in object")

    local object = self:alloc(size, opts)
    self:u64(object + offset, vtable, "object vptr")
    return object
end

function Builder:set_reg(name, value)
    check(type(name) == "string" and name ~= "", "invalid register name")
    -- For pointer roots, prohibit lossy or high-half numeric values.
    self.regs[name] = address(value, "register root")
end

function Builder:list(items, opts)
    opts = opts or {}
    local mode = opts.mode or "sentinel"
    check(mode == "sentinel" or mode == "circular",
          "list mode must be sentinel or circular")
    check(#items <= self.limits.max_nodes, "list exceeds max_nodes")

    local layout = opts.layout or {
        next = 0, prev = 8, id = 16, payload = 24,
    }
    local node_size = integer(opts.node_size or 32, "node size", 1)
    local used = {}

    for _, name in ipairs({ "next", "prev", "id", "payload" }) do
        local offset = integer(layout[name], "node " .. name .. " offset", 0)
        check(offset <= node_size - 8, "node field exceeds node size")
        for byte = offset, offset + 7 do
            check(not used[byte], "overlapping node fields")
            used[byte] = true
        end
    end

    local function node(label)
        return self:alloc(node_size, {
            arena = opts.arena,
            alignment = 8,
            label = label,
        })
    end

    local label = opts.label or "list"
    local sentinel = mode == "sentinel" and node(label .. " sentinel") or nil
    local nodes = {}
    for i = 1, #items do
        nodes[i] = node(label .. " node " .. i)
    end

    for i, item in ipairs(items) do
        check(type(item) == "table", "list items must be tables")
        local payload = item.payload_ptr or 0
        if item.payload ~= nil then
            check(item.payload_ptr == nil,
                  "provide payload or payload_ptr, not both")
            check(type(item.payload) == "string", "payload must be bytes")
            if #item.payload > 0 then
                payload = self:buffer(item.payload, {
                    arena = opts.arena,
                    label = label .. " payload " .. i,
                })
            end
        end

        local next_ptr = nodes[i + 1]
                     or sentinel
                     or nodes[1]
        local prev_ptr = nodes[i - 1]
                     or sentinel
                     or nodes[#nodes]

        self:fields(nodes[i], {
            { offset = layout.next, type = "u64", value = next_ptr },
            { offset = layout.prev, type = "u64", value = prev_ptr },
            { offset = layout.id, type = "u64",
              value = item.id == nil and i or item.id },
            { offset = layout.payload, type = "u64", value = payload },
        }, node_size)
    end

    if sentinel then
        self:fields(sentinel, {
            { offset = layout.next, type = "u64",
              value = nodes[1] or sentinel },
            { offset = layout.prev, type = "u64",
              value = nodes[#nodes] or sentinel },
            { offset = layout.id, type = "u64",
              value = opts.sentinel_id or 0 },
            { offset = layout.payload, type = "u64", value = 0 },
        }, node_size)
    end

    -- Sentinel mode: head is the sentinel, even for an empty list.
    -- Circular mode: head is the first node; an empty list has head == 0.
    local head = sentinel or nodes[1] or 0
    if opts.head_slot ~= nil then
        self:u64(opts.head_slot, head, label .. " head pointer")
    end

    return {
        mode = mode,
        head = head,
        sentinel = sentinel,
        first = nodes[1] or 0,
        last = nodes[#nodes] or 0,
        count = #nodes,
        nodes = nodes,
        layout = copy(layout),
    }
end

-- Apply to an existing LuaSession using ONLY documented APIs.
--
-- Preconditions:
--   * Memory backing already exists and permits these writes.
--   * Executable allocations can be fetched as instructions.
--   * No execution has occurred that should have observed these bytes.
--
-- This method cannot create mappings: no mapper is specified by the API.
-- It is not transactional; an error can leave earlier writes applied.
function Builder:apply(session)
    for _, op in ipairs(self.operations) do
        if op.kind == "poke" and op.width == 8
           and math.type(op.value) == "integer" and op.value >= 0 then
            session:poke(op.addr, op.value)
        else
            session:write_bytes(op.addr, op.data)
        end
    end
    for name, value in pairs(self.regs) do
        session:reg(name, value)
    end
    for _, hook in ipairs(self.hooks) do
        session:hook(hook.addr, hook.callback)
    end
end

------------------------------------------------------------------------
-- Campaign construction and headless compatibility boundary
------------------------------------------------------------------------

local function append(destination, source)
    for _, item in ipairs(source) do
        destination[#destination + 1] = copy(item)
    end
end

local function symbolic_names(symbolic)
    local result = {}
    for key, value in pairs(symbolic or {}) do
        if type(key) == "number" then
            check(type(value) == "string",
                  "symbolic register arrays must contain names")
            result[value] = true
        else
            check(type(key) == "string", "invalid symbolic register name")
            integer(value, "symbolic register width", 1)
            check(value <= 64, "symbolic register width exceeds 64")
            result[key] = true
        end
    end
    return result
end

local function make_request(cfg, phase, common, mock)
    local request = {
        phase = phase,
        entry = cfg.entry,
        regs = copy(cfg.regs),
        uc_memory = cfg.uc_memory,
        uc_write_ro = cfg.uc_write_ro,
        timeout_ms = cfg.timeout_ms,
        operations = {},
        allocations = {},
        hooks = {},
        notes = {},
    }

    append(request.operations, common.operations)

    if mock then
        append(request.operations, mock.operations)
        append(request.allocations, mock.allocations)
        append(request.hooks, mock.hooks)
        append(request.notes, mock.notes)
        request.regs = merge(request.regs, mock.regs)

        local names = symbolic_names(cfg.symbolic)
        for name in pairs(mock.regs) do
            check(not names[name],
                  "mock root register " .. name ..
                  " is also symbolic; choose a different input/root")
        end
    end
    return request
end

local function required_extensions(request)
    local needed = {}
    if request.entry ~= nil then needed[#needed + 1] = "entry" end
    if nonempty(request.regs) then needed[#needed + 1] = "regs" end
    if request.uc_memory then needed[#needed + 1] = "uc_memory" end
    if request.uc_write_ro then needed[#needed + 1] = "uc_write_ro" end
    if request.timeout_ms ~= nil then needed[#needed + 1] = "timeout" end
    if #request.operations > 0 then
        needed[#needed + 1] = "ordered memory injection"
    end
    if #request.allocations > 0 then
        needed[#needed + 1] = "scratch backing"
    end
    if #request.hooks > 0 then needed[#needed + 1] = "hooks" end
    return needed
end

local function check_adapter(cfg, request)
    local needed = required_extensions(request)
    if #needed > 0 then
        check(type(cfg.headless_adapter) == "function",
              request.phase .. " requires a headless_adapter for: " ..
              table.concat(needed, ", ") ..
              ". These features are not specified for angry.run.")
    elseif cfg.headless_adapter ~= nil then
        check(type(cfg.headless_adapter) == "function",
              "headless_adapter must be a function")
    end
end

local function run_phase(cfg, request)
    local result = { phase = request.phase }
    local cleanup
    local started = os.clock()

    print(("\n== %s =="):format(request.phase))
    print(("  memory operations: %d; allocations: %d; hooks: %d")
        :format(#request.operations, #request.allocations, #request.hooks))

    local ok, report = xpcall(function()
        local options = {
            symbolic = copy(cfg.symbolic),
            find = copy(cfg.find),
            avoid = copy(cfg.avoid),
            steps = cfg.steps,
            states = cfg.states,
            solve = cfg.solve,
            zero_low_pages = cfg.zero_low_pages,
        }

        if cfg.headless_adapter then
            options, cleanup = cfg.headless_adapter(options, copy(request))
            check(type(options) == "table",
                  "headless_adapter must return an options table")
            check(cleanup == nil or type(cleanup) == "function",
                  "adapter cleanup must be a function")
        end

        local r = angry.run(cfg.target, options)
        check(type(r) == "table", "angry.run did not return a report table")
        return r
    end, traceback)

    result.cpu_seconds = os.clock() - started
    if ok then
        result.report = report
    else
        result.error = report
    end

    if type(cleanup) == "function" then
        local cleaned, cleanup_error = xpcall(cleanup, traceback)
        if not cleaned then
            result.cleanup_error = cleanup_error
        end
    end
    return result
end

------------------------------------------------------------------------
-- Reporting
------------------------------------------------------------------------

-- These optional aliases are presentation conveniences, not claims that
-- all Angryier builds return these fields. Missing values remain n/a.
local METRICS = {
    { "steps",       { "steps", "steps_taken" } },
    { "forks",       { "forks" } },
    { "merges",      { "merges" } },
    { "terminated",  { "terminated" } },
    { "failed",      { "failed" } },
    { "live_states", { "live_states" } },
}

local function metric(report, aliases)
    if type(report) ~= "table" then return nil end
    for _, name in ipairs(aliases) do
        if type(report[name]) == "number" then return report[name] end
        if type(report.stats) == "table"
           and type(report.stats[name]) == "number" then
            return report.stats[name]
        end
    end
    return nil
end

local function found_count(report)
    if type(report) ~= "table" then return nil end
    if type(report.found) == "table" then return #report.found end
    return nil
end

local function display_number(value)
    if value == nil then return "n/a" end
    return tostring(value)
end

local function telemetry(report, key)
    if type(report) ~= "table" then return "n/a" end
    if report[key] ~= nil or report[key .. "_hex"] ~= nil then
        if key == "exit_kind" then return clean(report[key]) end
        return reported_address(report, key)
    end
    return "n/a"
end

local function print_models(report, limits)
    local hits = found_count(report)
    if hits == nil or hits == 0 then return end

    print("  Solver inputs:")
    if type(report.inputs) ~= "table" then
        print("    n/a: engine did not provide r.inputs")
        return
    end
    if #report.inputs == 0 then
        print("    no input byte strings returned")
        print("    (an empty list is not interpreted as UNSAT)")
        return
    end

    for i = 1, math.min(#report.inputs, limits.max_models) do
        local input = report.inputs[i]
        if type(input) ~= "string" then
            print(("    [%d] unsupported model representation: %s")
                :format(i, type(input)))
        else
            local shown = input:sub(1, limits.max_model_bytes)
            print(("    [%d] %d bytes%s"):format(
                i, #input, #shown < #input and " (truncated display)" or ""))
            print("      hex:   " .. hex_bytes(shown))
            print("      ascii: " .. ascii_bytes(shown))
        end
    end
    if #report.inputs > limits.max_models then
        print(("    ... %d additional input entries omitted")
            :format(#report.inputs - limits.max_models))
    end
    print("    Input entries are shown in engine order; symbol names and")
    print("    per-state grouping are not defined by the supplied API.")
end

local function print_trace(report, limit)
    print("  Trace tail:")
    local exact = type(report.trace_hex) == "table" and report.trace_hex
    local numeric = type(report.trace) == "table" and report.trace
    local trace = exact or numeric
    if not trace then
        print("    n/a")
        return
    end
    if #trace == 0 then
        print("    empty")
        return
    end
    for i = math.max(1, #trace - limit + 1), #trace do
        local value
        if exact then
            value = clean(trace[i])
        else
            value = reported_address({ pc = trace[i] }, "pc")
        end
        print(("    [%d] %s"):format(i, value))
    end
end

local function print_debt(report, key, limit)
    local records = report[key]
    if type(records) ~= "table" then
        print("  " .. key .. ": n/a")
        return
    end

    print(("  %s: %d site records"):format(key, #records))
    for i = 1, math.min(#records, limit) do
        local record = records[i]
        if type(record) ~= "table" then
            print(("    [%d] %s"):format(i, clean(record)))
        else
            local fields = {}
            for _, name in ipairs({ "pc", "address", "page", "caller" }) do
                if record[name] ~= nil or record[name .. "_hex"] ~= nil then
                    fields[#fields + 1] =
                        name .. "=" .. reported_address(record, name)
                end
            end
            for _, name in ipairs({
                "kind", "reason", "count", "hits", "len", "size", "form_id",
            }) do
                if record[name] ~= nil
                   and type(record[name]) ~= "table" then
                    fields[#fields + 1] = name .. "=" .. clean(record[name])
                end
            end
            print(("    [%d] %s"):format(i,
                #fields > 0 and table.concat(fields, " ")
                or "<record has no recognized presentation fields>"))
        end
    end
    if #records > limit then
        print(("    ... %d additional sites omitted"):format(#records - limit))
    end
end

local function print_phase(result, cfg)
    print("\n-- " .. result.phase .. " report --")
    print(("  Host CPU time: %.3f seconds (not wall-clock timeout accounting)")
        :format(result.cpu_seconds))

    if result.error then
        print("  Execution error:")
        print(result.error)
    end
    if result.cleanup_error then
        print("  Cleanup error:")
        print(result.cleanup_error)
    end

    local r = result.report
    if not r then return end

    for _, row in ipairs(METRICS) do
        print(("  %-14s %s"):format(row[1], display_number(metric(r, row[2]))))
    end
    print(("  %-14s %s"):format("find hits", display_number(found_count(r))))
    print("  rax_exit: " .. telemetry(r, "rax_exit"))
    print("  exit_pc:  " .. telemetry(r, "exit_pc"))
    print("  exit_kind: " .. telemetry(r, "exit_kind"))

    print_trace(r, cfg.limits.trace_tail)
    for _, key in ipairs({
        "unmapped_sites",
        "ro_write_reverts",
        "vector_debt_sites",
        "unsupported_sites",
    }) do
        print_debt(r, key, cfg.limits.debt_items)
    end
    print_models(r, cfg.limits)
end

local function print_scorecard(baseline, mocked)
    print("\n== Comparative scorecard ==")
    print(("%-20s %16s %16s"):format("Metric", "Baseline", "Mocked"))
    print(string.rep("-", 54))

    for _, row in ipairs(METRICS) do
        print(("%-20s %16s %16s"):format(
            row[1],
            display_number(metric(baseline.report, row[2])),
            display_number(metric(mocked.report, row[2]))))
    end

    local before = found_count(baseline.report)
    local after = found_count(mocked.report)
    print(("%-20s %16s %16s"):format(
        "find hits", display_number(before), display_number(after)))

    for _, key in ipairs({
        "unmapped_sites", "ro_write_reverts", "vector_debt_sites",
    }) do
        local function count(result)
            local value = result.report and result.report[key]
            return type(value) == "table" and #value or nil
        end
        print(("%-20s %16s %16s"):format(
            key, display_number(count(baseline)),
            display_number(count(mocked))))
    end

    print("")
    if before == nil or after == nil then
        print("Result: inconclusive; one or both find-hit counts are unavailable.")
    elseif before == 0 and after > 0 then
        print("Result: target reachability was observed only with synthetic state.")
        print("This demonstrates unblocking within the configured search budgets.")
    elseif before > 0 and after > 0 then
        print("Result: targets were reachable in both environments.")
        print("The mocks were not necessary for the observed baseline reachability.")
    elseif before > 0 and after == 0 then
        print("Result: mocked execution did not reproduce baseline reachability.")
        print("Review object layout, ABI assumptions, roots, and search scheduling.")
    else
        print("Result: neither run reached a target within the configured campaign.")
        print("This is not a proof of unreachability or unsatisfiability.")
    end

    if baseline.error or mocked.error
       or baseline.cleanup_error or mocked.cleanup_error then
        print("Warning: execution or cleanup errors occurred; inspect phase reports.")
    end

    print("Debt counts above are site-record counts, not inferred event totals.")
    print("Missing telemetry is n/a; it is never treated as zero.")
    print("Mocked reachability remains conditional on all synthetic assumptions.")
end

------------------------------------------------------------------------
-- Validation and entry point
------------------------------------------------------------------------

local function validate(cfg)
    check(type(angry) == "table" and type(angry.run) == "function",
          "run this script inside Angryier's Lua environment")
    check(type(cfg.target) == "string" and cfg.target ~= "",
          "set ANGRY_TARGET or CONFIG.target")

    local file, reason = io.open(cfg.target, "rb")
    check(file ~= nil, "target is not readable: " .. tostring(reason))
    local closed, close_error = file:close()
    check(closed, "target close failed: " .. tostring(close_error))

    if cfg.entry ~= nil then
        cfg.entry = address(cfg.entry, "entry")
    end

    if #cfg.find == 0 then cfg.find = addresses_from_env("ANGRY_FIND") end
    if #cfg.avoid == 0 then cfg.avoid = addresses_from_env("ANGRY_AVOID") end
    check(#cfg.find > 0, "configure at least one find address")

    local find_set = {}
    for i, value in ipairs(cfg.find) do
        cfg.find[i] = address(value, "find address")
        check(not find_set[cfg.find[i]], "duplicate find address")
        find_set[cfg.find[i]] = true
    end
    for i, value in ipairs(cfg.avoid) do
        cfg.avoid[i] = address(value, "avoid address")
        check(not find_set[cfg.avoid[i]],
              "an address cannot be both find and avoid")
    end

    integer(cfg.steps, "step budget", 1)
    integer(cfg.states, "state budget", 1)
    if cfg.timeout_ms ~= nil then
        integer(cfg.timeout_ms, "timeout_ms", 1)
    end

    for _, name in ipairs({
        "solve", "uc_memory", "uc_write_ro", "zero_low_pages",
    }) do
        check(type(cfg[name]) == "boolean", name .. " must be boolean")
    end
    check(not cfg.uc_write_ro or cfg.uc_memory,
          "uc_write_ro requires uc_memory in this configuration")

    for name, value in pairs(cfg.regs) do
        check(type(name) == "string" and name ~= "", "invalid register name")
        cfg.regs[name] = address(value, "initial register " .. name)
    end
    symbolic_names(cfg.symbolic)

    for name, value in pairs(cfg.limits) do
        integer(value, "limit " .. name, 1)
    end
    check(cfg.limits.max_blob_bytes <= cfg.limits.max_total_bytes,
          "max_blob_bytes exceeds max_total_bytes")
    check(type(cfg.build_mock) == "function", "build_mock must be a function")
end

local function main(configuration)
    local cfg = copy(configuration or CONFIG)
    validate(cfg)

    print("State Mock Explorer")
    if type(angry.version) == "function" then
        local ok, version = pcall(angry.version)
        print("Engine: " .. (ok and clean(version) or "<version unavailable>"))
    end
    print("Target: " .. clean(cfg.target))
    print(("Budgets: steps=%d states=%d timeout_ms=%s")
        :format(cfg.steps, cfg.states, tostring(cfg.timeout_ms or "none")))
    print(("Relaxations: zero_low_pages=%s uc_memory=%s uc_write_ro=%s")
        :format(tostring(cfg.zero_low_pages),
                tostring(cfg.uc_memory), tostring(cfg.uc_write_ro)))

    local common = Builder.new({}, cfg.limits)
    for _, slice in ipairs(cfg.load_mem) do
        common:load_mem(slice)
    end

    local mock = Builder.new(cfg.arenas, cfg.limits)
    cfg.build_mock(mock, cfg)

    check(#common.operations + #mock.operations <= cfg.limits.max_operations,
          "combined operation count exceeds max_operations")
    check(common.total_bytes <= cfg.limits.max_total_bytes - mock.total_bytes,
          "combined memory operations exceed max_total_bytes")

    -- Scratch allocations must not overwrite supplementary slices.
    -- Explicit non-allocation writes may intentionally patch those slices.
    for _, allocation in ipairs(mock.allocations) do
        local allocation_last = range_end(allocation.addr, allocation.len)
        for _, operation in ipairs(common.operations) do
            local operation_last = range_end(operation.addr, #operation.data)
            check(allocation_last < operation.addr
                  or allocation.addr > operation_last,
                  "scratch allocation overlaps supplementary memory: " ..
                  allocation.label .. " / " .. operation.label)
        end
    end

    print(("\nMock plan: %d allocations, %d operations, %d encoded bytes")
        :format(#mock.allocations, #mock.operations, mock.total_bytes))
    for _, note in ipairs(mock.notes) do
        print("  assumption/note: " .. clean(note))
    end

    local baseline_request = make_request(cfg, "Baseline", common, nil)
    local mocked_request = make_request(cfg, "Mocked", common, mock)

    -- Validate both phases BEFORE spending time on either run.
    check_adapter(cfg, baseline_request)
    check_adapter(cfg, mocked_request)

    if cfg.timeout_ms == nil then
        print("\nWarning: no hard timeout requested.")
        print("Step/state budgets do not bound solver or native execution time.")
        print("Use a process supervisor if a wall-clock limit is required.")
    end

    -- Separate angry.run calls provide independent campaign state.
    local baseline = run_phase(cfg, baseline_request)
    print_phase(baseline, cfg)

    -- Still attempt the mocked campaign if baseline execution raised:
    -- a baseline environment fault may be exactly what the mock repairs.
    local mocked = run_phase(cfg, mocked_request)
    print_phase(mocked, cfg)

    print_scorecard(baseline, mocked)

    return {
        baseline = baseline,
        mocked = mocked,
        common = common,
        mock = mock,
    }
end

local module = {
    Builder = Builder,
    config = CONFIG,
    main = main,
}

if not CONFIG.library_only then
    local ok, result = xpcall(function()
        return main(CONFIG)
    end, traceback)
    if not ok then
        error(result, 0)
    end
    module.result = result
end

return module
