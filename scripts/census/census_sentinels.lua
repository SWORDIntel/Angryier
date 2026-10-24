-- census_sentinels.lua — cluster the normal-return (sentinel) functions by rax
-- value: functions that return the same constant are often the same family
-- (getters/setters, status codes, factory IDs).
--
-- Usage: lua5.4 census_sentinels.lua <results.jsonl> [index.tsv] [--min N]

local cj = dofile(arg[0]:gsub("[^/]+$", "") .. "census_json.lua")

if not arg[1] then
    print("usage: lua5.4 census_sentinels.lua <results.jsonl> [index.tsv] [--min N]")
    os.exit(2)
end
local idx, min_n = nil, 2
for i = 2, #arg do
    if arg[i] == "--min" then min_n = tonumber(arg[i + 1]) or 2
    elseif not idx then idx = cj.load_index(arg[i]) end
end

local by_rax = {}
local sentinel_total = 0
cj.foreach(arg[1], function(rec)
    local e = cj.hex(rec.exit_pc)
    if e and e >= 0xDEADBEEF0000 and e < 0xDEADBEEF1000 then
        sentinel_total = sentinel_total + 1
        local r = rec.rax or "0"
        local bucket = by_rax[r]
        if not bucket then bucket = {} by_rax[r] = bucket end
        bucket[#bucket + 1] = rec.entry
    end
end)

print(string.format("sentinel returns: %d, distinct rax values: %d",
    sentinel_total, table.getn and #by_rax or 0))
local ranked = {}
for r, list in pairs(by_rax) do
    if #list >= min_n then ranked[#ranked + 1] = { r, list } end
end
table.sort(ranked, function(a, b) return #a[2] > #b[2] end)
for _, e in ipairs(ranked) do
    print(string.format("rax=%s x%d", e[1], #e[2]))
    for i = 1, math.min(6, #e[2]) do
        local va = cj.hex(e[2][i])
        local v = va and idx[va]
        print(string.format("   %s  %s", e[2][i], v and v.name or ""))
    end
end
