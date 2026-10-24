-- census_xref.lua — reverse xref: which entry functions exit AT a target
-- address/range. This is the managed-boundary map: point it at the section-12
-- range to list every native caller of the generated handler stubs.
--
-- Usage: lua5.4 census_xref.lua <results.jsonl> --to <addr|lo-hi> [--index index.tsv]
--        lua5.4 census_xref.lua <results.jsonl> --to 0x1437f3000-0x14bf4d000
-- Output: TSV  entry  exit_pc  rax  steps  timed_out  enclosing_name

local cj = dofile(arg[0]:gsub("[^/]+$", "") .. "census_json.lua")

local results, lo, hi, index_path
for i = 1, #arg do
    if arg[i] == "--to" then
        local r = arg[i + 1]:gsub("0[xX]", "")
        local a, b = r:match("^(%x+)[-:](%x+)$")
        lo = cj.hex(a or r)
        hi = (b and cj.hex(b) or lo + 1)
        if not b then hi = lo + 1 end
    elseif arg[i] == "--index" then
        index_path = arg[i + 1]
    elseif not results then
        results = arg[i]
    end
end
if not results or not lo then
    print("usage: lua5.4 census_xref.lua <results.jsonl> --to <addr|lo-hi> [--index index.tsv]")
    os.exit(2)
end

local idx = index_path and cj.load_index(index_path) or {}
print(string.format("xref to %#x-%#x", lo, hi))
local n = 0
cj.foreach(results, function(rec)
    local e = cj.hex(rec.exit_pc)
    if e and e >= lo and e < hi then
        local enc = cj.enclosing(idx, cj.hex(rec.entry))
        print(string.format("%s\t%s\t%s\t%d\t%s\t%s",
            rec.entry, rec.exit_pc, rec.rax, rec.steps or 0,
            tostring(rec.timed_out or false),
            enc and enc.name or ""))
        n = n + 1
    end
end)
print(string.format("# total: %d", n))
