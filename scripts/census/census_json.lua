-- census_json.lua — minimal field extractor for Angryier bulk-census JSONL records.
-- Pure Lua 5.4, no libraries. Records are single-line JSON of the known schema.
--
-- Usage: local cj = dofile("census_json.lua")
--        cj.foreach(path, function(rec) ... end)
--        rec.entry / rec.exit_pc / rec.rax / rec.steps / rec.timed_out /
--        rec.err / rec.mode / rec.state / rec.elapsed_ms  (strings; hex as "0x…")

local M = {}

-- Lua 5.4 tonumber() rejects the 0x prefix with an explicit base (NOTEPAD gotcha).
function M.hex(v)
    if type(v) ~= "string" then return nil end
    if v:match("^0[xX]") then return tonumber(v:sub(3), 16) end
    if v:match("^[0-9a-fA-F]+$") then return tonumber(v, 16) end
    return nil
end

local function field(line, key, quoted)
    if quoted then
        return line:match('"' .. key .. '"%s*:%s*"([^"]*)"')
    end
    local v = line:match('"' .. key .. '"%s*:%s*([^,%s}]+)')
    if v == nil then return nil end
    if v == "true" then return true end
    if v == "false" then return false end
    return v
end

-- Parse one record line into a table (nil if not a record).
function M.parse(line)
    if not line:match('"entry"') then return nil end
    local rec = {}
    rec.entry = field(line, "entry", true)
    rec.exit_pc = field(line, "exit_pc", true) or ""
    rec.rax = field(line, "rax", true) or ""
    rec.state = field(line, "state", true)
    rec.mode = field(line, "mode", true)
    rec.err = field(line, "err", true)
    rec.steps = tonumber(field(line, "steps")) or 0
    rec.timed_out = field(line, "timed_out") == true
    rec.elapsed_ms = tonumber(field(line, "elapsed_ms"))
    rec.line = tonumber(field(line, "line"))
    rec.found = tonumber(field(line, "found")) or 0
    return rec
end

-- Iterate records; cb(rec, lineno).
function M.foreach(path, cb)
    local f = assert(io.open(path, "r"))
    for line in f:lines() do
        local rec = M.parse(line)
        if rec then cb(rec) end
    end
    f:close()
end

-- Read a TSV index (METHRA index.tsv: entry_va \t name \t status \t score \t lines \t debt)
-- into { [va] = { name=, status=, lines= } }.
function M.load_index(path)
    local idx = {}
    local f = io.open(path, "r")
    if not f then return idx end
    for line in f:lines() do
        local va, name, status, _, lines = line:match("^(0x%x+)\t(%S+)\t(%S+)\t(%S+)\t(%d+)")
        if va then
            idx[M.hex(va)] = { name = name, status = status, lines = tonumber(lines) or 0 }
        end
    end
    f:close()
    return idx
end

-- Resolve a VA to the enclosing index function {name, start}.
function M.enclosing(idx, va)
    local best = nil
    for start, v in pairs(idx) do
        if start <= va and (best == nil or start > best.start) then
            best = { start = start, name = v.name }
        end
    end
    return best
end

return M
