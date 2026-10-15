-- themida_dispatch_census.lua
-- Static, bounded-memory x86-64 indirect-dispatch census for Angryier Lua 5.4.
-- No symbolic execution, external modules, PE parsing, or external processes.
--
-- INPUT MAPPING
--   ANGRY_CENSUS_IMAGE          Required raw/file-backed byte image.
--   ANGRY_CENSUS_IMAGE_BASE     Default 0. Used ONLY for default offset mapping.
--   ANGRY_CENSUS_REGIONS        Optional replacement region list:
--       name:va:file_offset:length;name:va:file_offset:length
--       Integers may be decimal or 0x-prefixed hexadecimal.
--
-- Default regions describe the Sarin virtual ranges. Their default file offsets
-- are VA - IMAGE_BASE, appropriate ONLY for a contiguous virtual-memory image.
-- For a section-packed/file-backed image, supply actual offsets using REGIONS or:
--   ANGRY_CENSUS_THEMIDA_OFFSET
--   ANGRY_CENSUS_BOOT_OFFSET
-- This script does not infer PE section raw offsets.
--
-- OTHER SETTINGS
--   ANGRY_CENSUS_CHUNK          Core window bytes; default 1048576.
--   ANGRY_CENSUS_OVERLAP        Lookahead bytes; default 64, minimum 15.
--   ANGRY_CENSUS_DECODE_POLICY  "continue" (default) or "abort".
--   ANGRY_CENSUS_BACKTRACK      Prior instructions retained; default 32.
--   ANGRY_CENSUS_TOP            Top-N entries; default 20.
--   ANGRY_CENSUS_HIST_CAP       Maximum entries per histogram; default 65536.
--   ANGRY_CENSUS_REPORT         Optional Markdown output path.
--   ANGRY_CENSUS_SELFTEST       Set to 1 to run tests before the census.
--
-- Address arithmetic uses Lua integers exclusively. Hex formatting also works
-- for signed integer bit patterns representing upper-half immediate values.
--
-- Provenance is deliberately conservative:
--   * Resolve RIP-relative LEA, MOV r64,imm64, and MOV r64,sign_extended_imm32.
--   * Recognized intervening writes invalidate the affected register.
--   * Unknown instruction effects and control transfers are barriers.
--   * MOV r64,[rip+disp32] writes the register, but does NOT resolve its value:
--     the slot address is not the loaded pointer.
-- This is local linear provenance, not a CFG/reaching-definitions proof.
--
-- Histograms use bounded Space-Saving heavy hitters. Without replacements,
-- counts are exact. With replacements, reports include [lower, upper] bounds;
-- candidate rankings are approximate, not asserted exact global rankings.

local function fail(message)
    error(tostring(message), 0)
end

local function trim(s)
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function integer(text, label)
    if type(text) == "number" then
        if math.type(text) ~= "integer" or text < 0 then
            fail(label .. ": expected a nonnegative Lua integer")
        end
        return text
    end
    if type(text) ~= "string" then
        fail(label .. ": expected an integer string")
    end

    local s = trim(text)
    local base = 10
    if s:sub(1, 2):lower() == "0x" then
        base, s = 16, s:sub(3)
    end
    if s == "" then fail(label .. ": empty integer") end

    local value = 0
    for i = 1, #s do
        local b = s:byte(i)
        local d
        if b >= 48 and b <= 57 then d = b - 48
        elseif b >= 65 and b <= 70 then d = b - 65 + 10
        elseif b >= 97 and b <= 102 then d = b - 97 + 10
        end
        if not d or d >= base then
            fail(label .. ": invalid integer " .. text)
        end
        if value > (math.maxinteger - d) // base then
            fail(label .. ": integer exceeds signed 64-bit range")
        end
        value = value * base + d
    end
    return value
end

local function envint(name, default, minimum, maximum)
    local text = os.getenv(name)
    local n = text and integer(text, name) or default
    if n < minimum or n > maximum then
        fail(string.format("%s: expected %d..%d", name, minimum, maximum))
    end
    return n
end

local function hex(v)
    assert(math.type(v) == "integer", "noninteger address")
    return string.format("0x%x", v)
end

local function checked_end(start, length, label)
    if length > math.maxinteger - start then
        fail(label .. ": range overflows signed 64-bit arithmetic")
    end
    return start + length
end

local function configuration()
    local c = {
        image = os.getenv("ANGRY_CENSUS_IMAGE"),
        image_base = envint("ANGRY_CENSUS_IMAGE_BASE", 0, 0, math.maxinteger),
        chunk = envint("ANGRY_CENSUS_CHUNK", 1048576, 16, 16 * 1048576),
        overlap = envint("ANGRY_CENSUS_OVERLAP", 64, 15, 65536),
        backtrack = envint("ANGRY_CENSUS_BACKTRACK", 32, 1, 4096),
        top = envint("ANGRY_CENSUS_TOP", 20, 1, 1000),
        hist_cap = envint("ANGRY_CENSUS_HIST_CAP", 65536, 1, 1048576),
        policy = os.getenv("ANGRY_CENSUS_DECODE_POLICY") or "continue",
        report = os.getenv("ANGRY_CENSUS_REPORT"),
        selftest = os.getenv("ANGRY_CENSUS_SELFTEST") == "1",
    }
    if c.policy ~= "continue" and c.policy ~= "abort" then
        fail("ANGRY_CENSUS_DECODE_POLICY must be continue or abort")
    end
    if c.report == "" then c.report = nil end
    if c.top > c.hist_cap then
        fail("ANGRY_CENSUS_TOP must not exceed ANGRY_CENSUS_HIST_CAP")
    end

    local spec = os.getenv("ANGRY_CENSUS_REGIONS")
    c.regions = {}
    if spec and trim(spec) ~= "" then
        for item in spec:gmatch("[^;]+") do
            local name, va, offset, length =
                item:match("^%s*([^:]+):([^:]+):([^:]+):([^:]+)%s*$")
            if not name then
                fail("Invalid region; expected name:va:file_offset:length")
            end
            c.regions[#c.regions + 1] = {
                name = trim(name),
                va = integer(va, "region VA"),
                file_offset = integer(offset, "region file offset"),
                length = integer(length, "region length"),
            }
        end
    else
        local function default_region(name, va, finish, offset_env)
            local supplied = os.getenv(offset_env)
            local offset
            if supplied then
                offset = integer(supplied, offset_env)
            else
                if va < c.image_base then
                    fail(name .. ": VA precedes IMAGE_BASE; supply its file offset")
                end
                offset = va - c.image_base
            end
            c.regions[#c.regions + 1] = {
                name = name, va = va, file_offset = offset, length = finish - va,
            }
        end
        default_region(".themida", 0x1437F3000, 0x14BF4D000,
                       "ANGRY_CENSUS_THEMIDA_OFFSET")
        default_region(".boot", 0x14BF4D000, 0x15135B000,
                       "ANGRY_CENSUS_BOOT_OFFSET")
    end

    if #c.regions == 0 then fail("No regions configured") end
    local names, bytes = {}, 0
    for _, r in ipairs(c.regions) do
        if r.name == "" or r.name:find("[%c|]") then
            fail("Region names must be nonempty and contain no controls or '|'.")
        end
        if names[r.name] then fail("Duplicate region name: " .. r.name) end
        names[r.name] = true
        if r.length == 0 then fail(r.name .. ": zero-length region") end
        r.finish = checked_end(r.va, r.length, r.name .. " VA")
        checked_end(r.file_offset, r.length, r.name .. " file")
        bytes = checked_end(bytes, r.length, "total region size")
    end

    -- Disallow overlapping virtual ranges to avoid silently counting sites twice.
    local ordered = {}
    for i, r in ipairs(c.regions) do ordered[i] = r end
    table.sort(ordered, function(a, b) return a.va < b.va end)
    for i = 2, #ordered do
        if ordered[i].va < ordered[i - 1].finish then
            fail("Configured virtual regions overlap")
        end
    end
    return c
end

local legacy_prefix = {
    [0xf0] = true, [0xf2] = true, [0xf3] = true,
    [0x2e] = true, [0x36] = true, [0x3e] = true, [0x26] = true,
    [0x64] = true, [0x65] = true, [0x66] = true, [0x67] = true,
}

local function prefixes(s)
    local p = { rex = 0, addr32 = false, op16 = false, segment = nil }
    local i = 1
    while i <= #s and i <= 15 do
        local b = s:byte(i)
        if legacy_prefix[b] then
            -- A legacy prefix after REX makes that earlier REX ineffective.
            p.rex = 0
            if b == 0x66 then p.op16 = true
            elseif b == 0x67 then p.addr32 = true
            elseif b == 0xf0 then p.lock = true
            elseif b == 0xf2 or b == 0xf3 then p.rep = b
            else p.segment = b end
        elseif b >= 0x40 and b <= 0x4f then
            p.rex = b
        else
            p.pos, p.op = i, b
            return p
        end
        i = i + 1
    end
    return nil
end

local function signed32(s, i)
    if i + 3 > #s then return nil end
    local v = string.unpack("<i4", s, i)
    return v
end

local function modrm(s, i, p)
    local b = s:byte(i)
    if not b then return nil, "missing ModRM" end
    local m = {
        mod = b >> 6, ext = (b >> 3) & 7, rm = b & 7,
        disp = 0, rip = false,
    }
    m.reg = m.ext + (((p.rex >> 2) & 1) * 8)
    m.rmreg = m.rm + ((p.rex & 1) * 8)
    i = i + 1
    if m.mod == 3 then
        m.next = i
        return m
    end

    if m.rm == 4 then
        local sib = s:byte(i)
        if not sib then return nil, "missing SIB" end
        i = i + 1
        local idx, bas = (sib >> 3) & 7, sib & 7
        m.scale = 1 << (sib >> 6)
        -- Index=100 means no index ONLY when REX.X is clear.
        if idx ~= 4 or (p.rex & 2) ~= 0 then
            m.index = idx + (((p.rex >> 1) & 1) * 8)
        end
        -- mod=00/SIB.base=101 means no base, even with REX.B.
        if not (m.mod == 0 and bas == 5) then
            m.base = bas + ((p.rex & 1) * 8)
        end
        if m.mod == 0 and bas == 5 then m.disp_size = 4 end
    elseif m.mod == 0 and m.rm == 5 then
        m.rip = not p.addr32
        m.disp_size = 4
    else
        m.base = m.rmreg
    end

    if m.mod == 1 then m.disp_size = 1
    elseif m.mod == 2 then m.disp_size = 4 end

    if m.disp_size == 1 then
        local d = s:byte(i)
        if not d then return nil, "missing disp8" end
        m.disp = d >= 128 and d - 256 or d
        i = i + 1
    elseif m.disp_size == 4 then
        local d = signed32(s, i)
        if d == nil then return nil, "missing disp32" end
        m.disp, i = d, i + 4
    end
    m.next = i
    return m
end

local function classify(s)
    local p = prefixes(s)
    if not p or p.op ~= 0xff then return nil end
    local mb = s:byte(p.pos + 1)
    if not mb then return nil end
    local extension = (mb >> 3) & 7
    local kind
    if extension == 2 or extension == 3 then kind = "call"
    elseif extension == 4 or extension == 5 then kind = "jump"
    else return nil end

    local out = { kind = kind, class = "unclassified" }
    if extension == 3 or extension == 5 then
        out.reason = "far indirect transfer"
        return out
    end
    local m, why = modrm(s, p.pos + 1, p)
    if not m then out.reason = why; return out end
    if m.next ~= #s + 1 or #s > 15 then
        out.reason = "unexpected instruction length"
        return out
    end
    if p.lock then out.reason = "LOCK-prefixed transfer"; return out end

    if m.mod == 3 then
        out.class, out.target_register = "d", m.rmreg
    elseif p.addr32 then
        -- Do not mistake EIP-relative/32-bit address arithmetic for RIP-relative.
        out.reason = "32-bit address-size memory transfer"
    elseif m.rip then
        out.class = "c"
    elseif m.index ~= nil then
        out.class = "a"
    elseif m.base ~= nil then
        out.class = "a_noidx"
    else
        out.reason = "absolute displacement-only memory transfer"
    end
    out.base, out.index, out.scale, out.disp = m.base, m.index, m.scale, m.disp
    out.segment = p.segment
    return out
end

local function mask(reg)
    return 1 << reg
end

local function byte_register(reg, p)
    -- Without REX, encodings 4..7 select AH/CH/DH/BH, not SPL/BPL/SIL/DIL.
    if p.rex == 0 and reg >= 4 and reg <= 7 then return reg - 4 end
    return reg
end

local function effect(s, pc)
    local p = prefixes(s)
    if not p then return { barrier = true } end
    local op, at = p.op, p.pos + 1
    local function writes(bits, dest, value)
        return { writes = bits, dest = dest, value = value }
    end
    local function none() return writes(0) end
    local function unknown() return { barrier = true } end
    local function rm_mask(m, byte)
        if m.mod ~= 3 then return 0 end
        return mask(byte and byte_register(m.rmreg, p) or m.rmreg)
    end
    local function reg_mask(m, byte)
        return mask(byte and byte_register(m.reg, p) or m.reg)
    end

    -- Noncanonical prefix combinations are not used to infer write effects.
    if p.lock or p.rep then return unknown() end

    if op >= 0xb8 and op <= 0xbf then
        local dst = op - 0xb8 + ((p.rex & 1) * 8)
        if (p.rex & 8) ~= 0 and at + 8 == #s + 1 then
            local value = string.unpack("<i8", s, at)
            return writes(mask(dst), dst, value)
        end
        return writes(mask(dst))
    elseif op >= 0xb0 and op <= 0xb7 then
        local dst = op - 0xb0 + ((p.rex & 1) * 8)
        return writes(mask(byte_register(dst, p)))
    elseif op >= 0x50 and op <= 0x57 then
        return writes(mask(4))
    elseif op >= 0x58 and op <= 0x5f then
        return writes(mask(4) | mask(op - 0x58 + ((p.rex & 1) * 8)))
    elseif op == 0x68 or op == 0x6a or op == 0x9c or op == 0x9d then
        return writes(mask(4))
    elseif op >= 0x90 and op <= 0x97 then
        local other = op - 0x90 + ((p.rex & 1) * 8)
        return other == 0 and none() or writes(mask(0) | mask(other))
    elseif op == 0x98 then return writes(mask(0))
    elseif op == 0x99 then return writes(mask(2))
    elseif op == 0xc9 then return writes(mask(4) | mask(5))
    elseif op == 0xf8 or op == 0xf9 or op == 0xf5
        or op == 0xfc or op == 0xfd or op == 0x9e then
        return none()
    elseif op == 0x9f then return writes(mask(0))
    elseif op == 0xa8 or op == 0xa9 then return none()
    elseif op == 0xa0 or op == 0xa1 then return writes(mask(0))
    elseif op == 0xa2 or op == 0xa3 then return none()
    end

    if op == 0x0f then
        local second = s:byte(at)
        if not second then return unknown() end
        if second >= 0xc8 and second <= 0xcf then
            return writes(mask(second - 0xc8 + ((p.rex & 1) * 8)))
        end
        local m = modrm(s, at + 1, p)
        if not m then return unknown() end
        if second == 0x1f and m.ext == 0 then return none() end
        if second == 0xb6 or second == 0xb7 or second == 0xbe
            or second == 0xbf or second == 0xaf
            or (second >= 0x40 and second <= 0x4f) then
            return writes(reg_mask(m, false))
        end
        if second >= 0x90 and second <= 0x9f then
            return writes(rm_mask(m, true))
        end
        return unknown()
    end

    -- ADD/OR/ADC/SBB/AND/SUB/XOR/CMP, including accumulator immediate forms.
    if op <= 0x3d and (op & 7) <= 5 then
        local variant, family = op & 7, op >> 3
        if family == 7 then return none() end
        if variant >= 4 then return writes(mask(0)) end
        local m = modrm(s, at, p)
        if not m then return unknown() end
        if variant <= 1 then return writes(rm_mask(m, variant == 0)) end
        return writes(reg_mask(m, variant == 2))
    end

    local m = modrm(s, at, p)
    if not m then return unknown() end

    if op == 0x8d then
        if m.mod == 3 then return unknown() end
        if (p.rex & 8) ~= 0 and not p.addr32 and m.rip
            and m.next == #s + 1 then
            return writes(mask(m.reg), m.reg, pc + #s + m.disp)
        end
        return writes(mask(m.reg))
    elseif op == 0xc7 then
        if m.ext ~= 0 then return unknown() end
        if m.mod == 3 and (p.rex & 8) ~= 0 and m.next + 4 == #s + 1 then
            return writes(mask(m.rmreg), m.rmreg, signed32(s, m.next))
        end
        return writes(rm_mask(m, false))
    elseif op == 0xc6 then
        return m.ext == 0 and writes(rm_mask(m, true)) or unknown()
    elseif op == 0x88 or op == 0x89 then
        return writes(rm_mask(m, op == 0x88))
    elseif op == 0x8a or op == 0x8b then
        return writes(reg_mask(m, op == 0x8a))
    elseif op == 0x63 or op == 0x69 or op == 0x6b then
        return writes(reg_mask(m, false))
    elseif op == 0x84 or op == 0x85 then
        return none()
    elseif op == 0x86 or op == 0x87 then
        return writes(rm_mask(m, op == 0x86) | reg_mask(m, op == 0x86))
    elseif op == 0x80 or op == 0x81 or op == 0x83 then
        return m.ext == 7 and none() or writes(rm_mask(m, op == 0x80))
    elseif op == 0xc0 or op == 0xc1
        or (op >= 0xd0 and op <= 0xd3) then
        return writes(rm_mask(m, (op & 1) == 0))
    elseif op == 0xf6 or op == 0xf7 then
        if m.ext <= 1 then return none() end
        if m.ext <= 3 then return writes(rm_mask(m, op == 0xf6)) end
        return writes(mask(0) | mask(2))
    elseif op == 0xfe then
        return m.ext <= 1 and writes(rm_mask(m, true)) or unknown()
    elseif op == 0xff then
        if m.ext <= 1 then return writes(rm_mask(m, false)) end
        if m.ext == 6 then return writes(mask(4)) end
        return unknown()
    elseif op == 0x8f and m.ext == 0 then
        return writes(mask(4) | rm_mask(m, false))
    end
    return unknown()
end

local function new_ring(cap)
    return { cap = cap, head = 0, size = 0, data = {} }
end

local function clear_ring(r)
    r.head, r.size, r.data = 0, 0, {}
end

local function push_ring(r, e)
    r.head = r.head % r.cap + 1
    r.data[r.head] = e
    r.size = math.min(r.size + 1, r.cap)
end

local function provenance(r, base)
    if base == nil then return nil, "no base register" end
    local bit = mask(base)
    for distance = 0, r.size - 1 do
        local index = (r.head - 1 - distance) % r.cap + 1
        local e = r.data[index]
        if e.barrier then return nil, "unknown effect/control-flow barrier" end
        if (e.writes & bit) ~= 0 then
            if e.dest == base and e.value ~= nil then return e.value end
            return nil, "most recent write unresolved"
        end
    end
    return nil, "no definition within window"
end

-- Bounded Space-Saving histogram with an indexed min-heap.
local function new_hist(cap)
    return { cap = cap, heap = {}, map = {}, replacements = 0, events = 0 }
end

local function less(a, b)
    if a.count ~= b.count then return a.count < b.count end
    return a.key < b.key
end

local function heap_swap(h, i, j)
    h[i], h[j] = h[j], h[i]
    h[i].index, h[j].index = i, j
end

local function down(h, i)
    while true do
        local left, right, best = i * 2, i * 2 + 1, i
        if left <= #h and less(h[left], h[best]) then best = left end
        if right <= #h and less(h[right], h[best]) then best = right end
        if best == i then return end
        heap_swap(h, i, best)
        i = best
    end
end

local function hist_add(h, key)
    h.events = h.events + 1
    local node = h.map[key]
    if node then
        node.count = node.count + 1
        down(h.heap, node.index)
    elseif #h.heap < h.cap then
        node = { key = key, count = 1, error = 0, index = #h.heap + 1 }
        h.map[key], h.heap[node.index] = node, node
        local i = node.index
        while i > 1 do
            local parent = i // 2
            if not less(h.heap[i], h.heap[parent]) then break end
            heap_swap(h.heap, i, parent)
            i = parent
        end
    else
        node = h.heap[1]
        h.map[node.key] = nil
        node.key, node.error, node.count = key, node.count, node.count + 1
        h.map[key] = node
        h.replacements = h.replacements + 1
        down(h.heap, 1)
    end
end

local function hist_top(h, n)
    -- Reporting allocates at most cap references, never a site list.
    local rows = {}
    for i, node in ipairs(h.heap) do rows[i] = node end
    table.sort(rows, function(a, b)
        if a.count ~= b.count then return a.count > b.count end
        return a.key < b.key
    end)
    while #rows > n do rows[#rows] = nil end
    return rows
end

local CLASSES = { "a", "a_noidx", "c", "d", "unclassified" }

local function new_stats()
    local s = {
        decoded = 0, failed_bytes = 0, instructions = 0,
        decode_exceptions = 0, prov_hit = 0, prov_miss = 0, counts = {},
    }
    for _, class in ipairs(CLASSES) do
        s.counts[class] = { jump = 0, call = 0 }
    end
    return s
end

local function count_reason(t, reason)
    t[reason] = (t[reason] or 0) + 1
end

local function percent(part, whole)
    if whole == 0 then return "0.00%" end
    -- Two decimal places, using integer arithmetic exclusively.
    local scaled = part * 10000 // whole
    return string.format("%d.%02d%%", scaled // 100, scaled % 100)
end

local function io_call(label, fn)
    local ok, value, detail = pcall(fn)
    if not ok then fail(label .. ": " .. tostring(value)) end
    if value == nil or value == false then
        fail(label .. ": " .. tostring(detail or "operation failed"))
    end
    return value
end

local function selftests()
    local failures = 0
    local function test(name, fn)
        local ok, why = pcall(fn)
        if ok then print("[SELFTEST PASS] " .. name)
        else
            failures = failures + 1
            print("[SELFTEST FAIL] " .. name .. ": " .. tostring(why))
        end
    end

    local vectors = {
        -- The requested four-byte 41 FF 24 85 fragment is incomplete:
        -- SIB.base=5/mod=0 requires disp32 and has NO r13 base.
        { "incomplete requested SIB fragment", "41ff2485", "unclassified", "jump" },
        { "completed requested indexed SIB", "41ff248500000000", "a", "jump",
          no_base = true, index = 0, scale = 4 },
        { "actual [r13+rax*4]", "41ff648500", "a", "jump", base = 13, index = 0 },
        { "RIP-relative call", "ff1578563412", "c", "call" },
        { "REX.B register jump r14", "41ffe6", "d", "jump", target = 14 },
        { "[rax] context jump", "ff20", "a_noidx", "jump", base = 0 },
        { "[rax+disp8] context jump", "ff6020", "a_noidx", "jump", base = 0 },
        { "[rsp] no SIB index", "ff2424", "a_noidx", "jump", base = 4 },
        { "REX.X makes SIB index r12", "42ff2420", "a", "jump",
          base = 0, index = 12 },
        { "REX.B does not change RIP special case", "41ff2500000000", "c", "jump" },
        { "disp-only SIB is not a context base", "ff242500000000", "unclassified", "jump" },
        { "address-size override is explicit unsupported", "67ff2500000000",
          "unclassified", "jump" },
        { "far memory call", "ff18", "unclassified", "call" },
        { "register call", "ffd0", "d", "call", target = 0 },
        { "direct call is not indirect", "e800000000", false },
        { "E6 is OUT, not an indirect transfer", "e680", false },
        { "FF INC is not a transfer", "ffc0", false },
    }
    for _, vector in ipairs(vectors) do
        test(vector[1], function()
            local result = classify(angry.unhex(vector[2]))
            if vector[3] == false then
                assert(result == nil, "expected a non-dispatch instruction")
                return
            end
            assert(result and result.class == vector[3], "class mismatch")
            assert(result.kind == vector[4], "jump/call mismatch")
            if vector.base ~= nil then assert(result.base == vector.base) end
            if vector.no_base then assert(result.base == nil) end
            if vector.index ~= nil then assert(result.index == vector.index) end
            if vector.scale ~= nil then assert(result.scale == vector.scale) end
            if vector.target ~= nil then
                assert(result.target_register == vector.target)
            end
        end)
    end

    test("LEA RIP-relative provenance", function()
        local e = effect(angry.unhex("488d0510000000"), 0x1000)
        assert(e.dest == 0 and e.value == 0x1017)
    end)
    test("MOV r13,imm64 provenance", function()
        local e = effect(angry.unhex("49bd8877665544332211"), 0)
        assert(e.dest == 13 and e.value == 0x1122334455667788)
    end)
    test("MOV r13,imm32 sign extension", function()
        local e = effect(angry.unhex("49c7c5ffffffff"), 0)
        assert(e.dest == 13 and e.value == -1)
    end)
    test("MOV [RIP] kills prior RAX provenance, FF20 stays a_noidx", function()
        local r = new_ring(32)
        push_ring(r, effect(angry.unhex("48b80010000000000000"), 0))
        push_ring(r, effect(angry.unhex("488b0500000000"), 10))
        local site = classify(angry.unhex("ff20"))
        assert(site.class == "a_noidx")
        assert(provenance(r, site.base) == nil)
    end)
    test("intervening unrelated write preserves provenance", function()
        local r = new_ring(32)
        push_ring(r, effect(angry.unhex("488d0510000000"), 0x1000))
        push_ring(r, effect(angry.unhex("31c9"), 0x1007))
        assert(provenance(r, 0) == 0x1017)
        push_ring(r, effect(angry.unhex("31c0"), 0x1009))
        assert(provenance(r, 0) == nil)
    end)
    test("bounded histogram replacement bounds", function()
        local h = new_hist(2)
        hist_add(h, 1); hist_add(h, 2); hist_add(h, 3); hist_add(h, 3)
        assert(#h.heap == 2 and h.replacements == 1)
        assert(h.map[3].count - h.map[3].error <= 2)
        assert(h.map[3].count >= 2)
    end)

    if failures ~= 0 then fail("Self-tests failed: " .. failures) end
    print("[SELFTEST] All tests passed")
end

local function census_region(file, c, region, total, heat, prov_hist, reasons, misses)
    local stats, ring = new_stats(), new_ring(c.backtrack)
    local cursor, chunk_number = 0, 0

    local function decode_failure(n, pc, why)
        if n == 0 then return end
        if c.policy == "abort" then
            fail(region.name .. ": decode failure at " .. hex(pc) .. ": " .. why)
        end
        stats.failed_bytes = stats.failed_bytes + n
        total.failed_bytes = total.failed_bytes + n
        clear_ring(ring)
    end

    local function visit(bytes, pc)
        stats.instructions, total.instructions =
            stats.instructions + 1, total.instructions + 1
        stats.decoded, total.decoded =
            stats.decoded + #bytes, total.decoded + #bytes

        local site = classify(bytes)
        if site then
            local class, kind = site.class, site.kind
            stats.counts[class][kind] = stats.counts[class][kind] + 1
            total.counts[class][kind] = total.counts[class][kind] + 1
            hist_add(heat[class], pc - pc % 4096)
            if class == "unclassified" then
                count_reason(reasons, site.reason or "unspecified")
            elseif class == "a" or class == "a_noidx" then
                local value, why = provenance(ring, site.base)
                if value ~= nil then
                    stats.prov_hit, total.prov_hit = stats.prov_hit + 1, total.prov_hit + 1
                    hist_add(prov_hist, value)
                else
                    stats.prov_miss, total.prov_miss = stats.prov_miss + 1, total.prov_miss + 1
                    count_reason(misses, why)
                end
            end
        end
        push_ring(ring, effect(bytes, pc))
    end

    while cursor < region.length do
        chunk_number = chunk_number + 1
        local remaining = region.length - cursor
        local core = math.min(c.chunk, remaining)
        local wanted = math.min(core + c.overlap, remaining)
        local base = region.va + cursor
        local file_offset = region.file_offset + cursor
        io_call("seek " .. region.name .. " to " .. hex(file_offset),
                function() return file:seek("set", file_offset) end)
        local bytes = io_call("read " .. region.name .. " at " .. hex(file_offset),
                              function() return file:read(wanted) end)
        if #bytes ~= wanted then
            fail(string.format(
                "%s: short read at %s: requested %d, received %d; check raw offsets/lengths",
                region.name, hex(file_offset), wanted, #bytes))
        end

        local ok, instructions = pcall(angry.disasm, bytes, base)
        local consumed = 0
        if not ok then
            stats.decode_exceptions, total.decode_exceptions =
                stats.decode_exceptions + 1, total.decode_exceptions + 1
            print("[WARN] disasm " .. hex(base) .. ": " .. tostring(instructions))
            decode_failure(core, base, "angry.disasm raised an exception")
            consumed = core
        else
            if type(instructions) ~= "table" then
                fail("angry.disasm returned a non-table")
            end
            for _, insn in ipairs(instructions) do
                if consumed >= core then break end
                if type(insn) ~= "table" then fail("Invalid disassembly entry") end

                local pc = insn.pc
                if math.type(pc) ~= "integer" or pc ~= base + consumed then
                    fail("Noncontiguous/noninteger disassembly PC at " .. hex(base + consumed))
                end
                local length = insn.len or insn.length
                if insn.invalid and length == nil then length = 1 end
                if math.type(length) ~= "integer" or length < 1 or length > 15
                    or consumed + length > #bytes then
                    fail("Invalid disassembly length at " .. hex(pc))
                end

                if insn.invalid then
                    decode_failure(length, pc, "XED marked instruction invalid")
                else
                    local raw = bytes:sub(consumed + 1, consumed + length)
                    if type(insn.bytes) ~= "string" or insn.bytes ~= raw then
                        fail("Disassembly byte mismatch at " .. hex(pc))
                    end
                    visit(raw, pc)
                end
                consumed = consumed + length
            end
            if consumed < core then
                decode_failure(core - consumed, base + consumed,
                               "decoder stopped before the core-window boundary")
                consumed = core
            end
        end

        -- Own every instruction whose start lies in this core window, including
        -- one crossing its end. Resume at its END, not at an arbitrary byte.
        -- Lookahead is reread next time; no instruction/site is counted twice.
        cursor = cursor + consumed
        print(string.format(
            "[%s chunk %d] next=%s processed=%d/%d (%s) decoded=%d failed=%d",
            region.name, chunk_number, hex(region.va + cursor),
            cursor, region.length, percent(cursor, region.length),
            stats.decoded, stats.failed_bytes))
    end
    assert(stats.decoded + stats.failed_bytes == region.length,
           "region byte accounting mismatch")
    return stats
end

local function report_lines(c, results, total, heat, prov_hist, reasons, misses, emit)
    emit("# Themida indirect-dispatch census")
    emit("")
    emit("Image: " .. c.image:gsub("[\r\n]", " "))
    emit(string.format(
        "Core window: %d bytes; lookahead: %d; provenance window: %d instructions.",
        c.chunk, c.overlap, c.backtrack))
    emit("Decode policy: " .. c.policy .. ". Ranges are half-open.")
    emit("")
    emit("## Region mapping")
    emit("| Region | Start VA | End VA | File offset | Bytes |")
    emit("|---|---:|---:|---:|---:|")
    for _, r in ipairs(c.regions) do
        emit(string.format("| %s | %s | %s | %s | %d |",
            r.name, hex(r.va), hex(r.finish), hex(r.file_offset), r.length))
    end

    emit("")
    emit("## Dispatch counts")
    emit("| Region | Class | Jumps | Calls | Total |")
    emit("|---|---|---:|---:|---:|")
    local function count_rows(name, stats)
        for _, class in ipairs(CLASSES) do
            local row = stats.counts[class]
            emit(string.format("| %s | %s | %d | %d | %d |",
                name, class, row.jump, row.call, row.jump + row.call))
        end
    end
    for i, r in ipairs(c.regions) do count_rows(r.name, results[i]) end
    count_rows("TOTAL", total)

    emit("")
    emit("## Decode coverage and provenance")
    emit("| Region | Instructions | Decoded bytes | Failed bytes | Coverage | Provenance hit | Miss |")
    emit("|---|---:|---:|---:|---:|---:|---:|")
    local function coverage_row(name, s)
        emit(string.format("| %s | %d | %d | %d | %s | %d | %d |",
            name, s.instructions, s.decoded, s.failed_bytes,
            percent(s.decoded, s.decoded + s.failed_bytes), s.prov_hit, s.prov_miss))
    end
    for i, r in ipairs(c.regions) do coverage_row(r.name, results[i]) end
    coverage_row("TOTAL", total)
    emit("Decoder exceptions: " .. total.decode_exceptions)
    emit("Coverage measures syntactic decoding, not proof of executable code.")

    local function histogram(title, h)
        emit("")
        emit("## " .. title)
        emit(string.format("Events: %d; retained keys: %d; replacements: %d.",
                           h.events, #h.heap, h.replacements))
        if h.replacements == 0 then
            emit("Counts and ranking are exact.")
        else
            emit("Bounded heavy-hitter candidates: approximate ranking; true counts lie within bounds.")
        end
        emit("| Address | Estimated count / upper bound | Lower bound |")
        emit("|---|---:|---:|")
        local rows = hist_top(h, c.top)
        for _, node in ipairs(rows) do
            emit(string.format("| %s | %d | %d |",
                               hex(node.key), node.count, node.count - node.error))
        end
        if #rows == 0 then emit("| (none) | 0 | 0 |") end
    end

    for _, class in ipairs(CLASSES) do
        histogram("4 KiB page heatmap: " .. class .. " (jumps + calls)", heat[class])
    end
    histogram("Resolved base-provenance values", prov_hist)

    local function reason_table(title, counts)
        emit("")
        emit("## " .. title)
        emit("| Reason | Sites |")
        emit("|---|---:|")
        local keys = {}
        for key in pairs(counts) do keys[#keys + 1] = key end
        table.sort(keys)
        for _, key in ipairs(keys) do
            emit(string.format("| %s | %d |", key, counts[key]))
        end
        if #keys == 0 then emit("| (none) | 0 |") end
    end
    reason_table("Unclassified indirect transfers", reasons)
    reason_table("Base-provenance misses", misses)

    emit("")
    emit("## Interpretation and limitations")
    emit("- a: indexed memory; a_noidx: base-only memory; c: RIP-relative memory; d: register.")
    emit("- Indexed SIB operands can have no base register; those sites are provenance misses.")
    emit("- Far transfers, displacement-only memory, and 32-bit memory addressing are unclassified.")
    emit("- E6 is OUT imm8,AL, not an indirect control-transfer opcode.")
    emit("- FF /2 and /4 cover near indirect CALL/JMP; FF /3 and /5 are recorded but not inferred.")
    emit("- Provenance values are base-register values, not final effective addresses or table contents.")
    emit("- Segment overrides are not resolved into linear addresses; FS/GS bases are not inferred.")
    emit("- Unknown write effects and control transfers stop backward provenance searches.")
    emit("- RIP-relative MOV loads invalidate provenance; the load address is not treated as its value.")
    emit("- Static linear decoding may count data as code and misses alternate/overlapping instruction streams.")
    emit("- Invalid bytes reset provenance; continuation after decoder failure is a heuristic resynchronization.")
    emit("- Chunk lookahead preserves sequential instruction boundaries, not arbitrary branch-entry boundaries.")
    emit("- No instruction/site lists are retained; memory is bounded by windows, rings, and histogram caps.")
end

local input_file, output_file

local function main()
    local c = configuration()
    if c.selftest then selftests() end
    if not c.image or c.image == "" then
        fail("Set ANGRY_CENSUS_IMAGE to the raw/file-backed input image")
    end
    if c.report == c.image then
        fail("Report path must not equal the input image path")
    end

    input_file = io_call("open input " .. c.image,
                        function() return io.open(c.image, "rb") end)
    local size = io_call("query input size",
                        function() return input_file:seek("end", 0) end)
    if math.type(size) ~= "integer" or size < 0 then
        fail("Input size is not an exact nonnegative Lua integer")
    end
    for _, r in ipairs(c.regions) do
        if r.file_offset + r.length > size then
            fail(string.format(
                "%s: file range [%s,%s) exceeds input size %s; supply actual section offsets",
                r.name, hex(r.file_offset), hex(r.file_offset + r.length), hex(size)))
        end
    end

    print("[CENSUS] Static x86-64 census; no execution")
    for _, r in ipairs(c.regions) do
        print(string.format("[MAP] %s VA=[%s,%s) file=%s length=%d",
              r.name, hex(r.va), hex(r.finish), hex(r.file_offset), r.length))
    end

    local total, results = new_stats(), {}
    local heat, reasons, misses = {}, {}, {}
    for _, class in ipairs(CLASSES) do heat[class] = new_hist(c.hist_cap) end
    local prov_hist = new_hist(c.hist_cap)

    for i, region in ipairs(c.regions) do
        results[i] = census_region(input_file, c, region, total,
                                   heat, prov_hist, reasons, misses)
    end
    io_call("close input", function() return input_file:close() end)
    input_file = nil

    if c.report then
        output_file = io_call("open report " .. c.report,
                             function() return io.open(c.report, "wb") end)
    end
    local function emit(line)
        print(line)
        if output_file then
            io_call("write report", function() return output_file:write(line, "\n") end)
        end
    end
    report_lines(c, results, total, heat, prov_hist, reasons, misses, emit)
    if output_file then
        io_call("close report", function() return output_file:close() end)
        output_file = nil
        print("[CENSUS] Report written: " .. c.report)
    end
end

local ok, message = pcall(main)
if input_file then pcall(function() input_file:close() end) end
if output_file then pcall(function() output_file:close() end) end
if not ok then
    error("[themida_dispatch_census] " .. tostring(message), 0)
end