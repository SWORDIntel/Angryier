-- census_summary.lua — overall classification + histogram of a census JSONL.
-- Usage: lua5.4 census_summary.lua <results.jsonl> [index.tsv]
-- Prints: totals, classification counts, top exit targets (with enclosing
-- function names when an index is given), and a per-address-range histogram.

local cj = dofile(arg[0]:gsub("[^/]+$", "") .. "census_json.lua")

if not arg[1] then
    print("usage: lua5.4 census_summary.lua <results.jsonl> [index.tsv]")
    os.exit(2)
end

local idx = arg[2] and cj.load_index(arg[2]) or {}

-- classification ranges (advisory; adaptable)
local ranges = {
    { name = "sentinel-return",   lo = 0xDEADBEEF0000, hi = 0xDEADBEEF1000 },
    { name = "section12-exit",    lo = 0x1437F3000,     hi = 0x14BF4D000 },
    { name = "image-exit",        lo = 0x140001000,     hi = 0x14BF4D000 },
    { name = "low-unmapped",      lo = 0x0,             hi = 0x10000 },
}

local total, errs, to = 0, 0, 0
local cls = {}
local exits = {}
local step_total, step_n = 0, 0

cj.foreach(arg[1], function(rec)
    total = total + 1
    if rec.err and rec.err ~= "" and rec.err ~= "null" then errs = errs + 1 end
    if rec.timed_out then to = to + 1 end
    if rec.steps and rec.steps > 0 then
        step_total = step_total + rec.steps
        step_n = step_n + 1
    end
    local e = cj.hex(rec.exit_pc)
    local c = "other"
    if e then
        for _, r in ipairs(ranges) do
            if e >= r.lo and e < r.hi then c = r.name break end
        end
    end
    cls[c] = (cls[c] or 0) + 1
    if e then
        local k = string.format("%016x", e)
        exits[k] = (exits[k] or 0) + 1
    end
end)

print(string.format("total=%d errors=%d timed_out=%d avg_steps=%.1f",
    total, errs, to, step_n > 0 and (step_total / step_n) or 0))
print("classification:")
local order = {}
for c, _ in pairs(cls) do order[#order + 1] = c end
table.sort(order, function(a, b) return cls[a] > cls[b] end)
for _, c in ipairs(order) do
    print(string.format("  %-18s %d", c, cls[c]))
end

print("top exit targets:")
local ranked = {}
for k, v in pairs(exits) do ranked[#ranked + 1] = { k, v } end
table.sort(ranked, function(a, b) return a[2] > b[2] end)
for i = 1, math.min(15, #ranked) do
    local e = cj.hex(ranked[i][1])
    local enc = cj.enclosing(idx, e)
    local nm = enc and string.format("(%s+%#x)", enc.name, e - enc.start) or ""
    print(string.format("  %s x%-5d %s", ranked[i][1], ranked[i][2], nm))
end
