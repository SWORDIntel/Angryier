-- census_join.lua — join census rows with the METHRA index into a queryable TSV
-- (entry, name, status, c_lines, exit_pc, rax, steps, timed_out, mode, err).
-- The result loads into SQLite/pandas for any future question.
--
-- Usage: lua5.4 census_join.lua <results.jsonl> <index.tsv> [out.tsv]

local cj = dofile(arg[0]:gsub("[^/]+$", "") .. "census_json.lua")

if not arg[1] or not arg[2] then
    print("usage: lua5.4 census_join.lua <results.jsonl> <index.tsv> [out.tsv]")
    os.exit(2)
end

local idx = cj.load_index(arg[2])
local out = arg[3] and io.open(arg[3], "w") or io.stdout
out:write("entry\tname\tstatus\tc_lines\texit_pc\trax\tsteps\ttimed_out\tmode\terr\n")

cj.foreach(arg[1], function(rec)
    local va = cj.hex(rec.entry)
    local v = va and idx[va]
    local err = (rec.err and rec.err ~= "" and rec.err ~= "null") and rec.err or ""
    err = err:gsub("[\r\n\t]", " ")
    out:write(string.format("%s\t%s\t%s\t%d\t%s\t%s\t%d\t%s\t%s\t%s\n",
        rec.entry,
        v and v.name or "",
        v and v.status or "",
        v and v.lines or 0,
        rec.exit_pc, rec.rax, rec.steps or 0,
        tostring(rec.timed_out or false),
        rec.mode or "",
        err))
end)
if arg[3] then out:close() end
