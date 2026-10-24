-- bulk_resolve.lua — load-once bulk address-resolution driver.
--
-- `angry.prepare` loads the target image ONCE per process; every job then
-- runs as an `img:run` campaign on a fresh copy-on-write clone of the
-- pristine template (milliseconds of setup instead of a full image
-- re-parse per job). Set ANGRY_BATCH_THREADS > 1 to execute each shard's
-- jobs on a native in-process worker pool instead.
--
-- Env:
--   ANGRY_TARGET         path to the image (PE32+ driver or ELF64)
--   ANGRY_JOBS           jobs file
--   ANGRY_OUT            JSONL output (append)
--   ANGRY_SHARD / ANGRY_SHARDS  strided sharding (0-based)
--   ANGRY_BATCH_THREADS  optional worker-pool size for img:run_batch
--
-- Job line format (space-separated key=value):
--   entry=0x1405e0ef0 steps=400 states=16 find=0xa,0xb avoid=0xc \
--   symbolic=rcx:64 reg=rcx:1a2b3c solve=1 uc=1
-- Only `entry` is mandatory. Hex values may use 0x prefix or none.
--
-- Records: a `tombstone` line is written BEFORE each job executes, then a
-- `done` line with the result. The merge step pairs them; an unpaired
-- tombstone is a lost job (shard died mid-job), visible instead of silent.
-- exit_pc/rax use the exact `*_hex` report fields (kernel addresses above
-- 2^63 arrive lossy through Lua numbers).

local TARGET = os.getenv("ANGRY_TARGET")
local JOBS = os.getenv("ANGRY_JOBS")
local OUT = os.getenv("ANGRY_OUT") or "bulk_results.jsonl"
local SHARD = tonumber(os.getenv("ANGRY_SHARD") or "0")
local SHARDS = tonumber(os.getenv("ANGRY_SHARDS") or "1")
local BATCH_THREADS = tonumber(os.getenv("ANGRY_BATCH_THREADS") or "0")

if not TARGET or not JOBS then
    error("bulk_resolve: need ANGRY_TARGET and ANGRY_JOBS env vars")
end

local function hexval(v)
    -- Lua 5.4 tonumber() rejects the 0x prefix with an explicit base.
    if v:match("^0[xX]") then
        return tonumber(v:sub(3), 16)
    end
    return tonumber(v, 16)
end

local function parse(line)
    local job = { entry = nil, steps = 256, states = 16, find = {}, avoid = {},
                  symbolic = {}, solve = false, uc = false, regs = {} }
    for k, v in string.gmatch(line, "(%w+)=([^%s]+)") do
        if k == "entry" then
            job.entry = hexval(v)
        elseif k == "steps" then
            job.steps = tonumber(v)
        elseif k == "states" then
            job.states = tonumber(v)
        elseif k == "solve" then
            job.solve = (v == "1" or v == "true")
        elseif k == "uc" then
            job.uc = (v == "1" or v == "true")
        elseif k == "find" then
            for a in string.gmatch(v, "[^,]+") do
                table.insert(job.find, hexval(a))
            end
        elseif k == "avoid" then
            for a in string.gmatch(v, "[^,]+") do
                table.insert(job.avoid, hexval(a))
            end
        elseif k == "symbolic" then
            for spec in string.gmatch(v, "[^,]+") do
                local r, w = string.match(spec, "(%w+):(%d+)")
                if r then job.symbolic[r] = tonumber(w) end
            end
        elseif k == "reg" then
            for spec in string.gmatch(v, "[^,]+") do
                local r, w = string.match(spec, "(%w+):(%x+)")
                if r then job.regs[r] = hexval(w) end
            end
        end
    end
    if not job.entry then return nil end
    return job
end

local function hex16(x)
    if type(x) == "string" then return x end
    x = math.floor(x or 0)
    if x < 0 then x = x + 18446744073709551616 end
    if x >= 18446744073709551616 then x = x % 18446744073709551616 end
    local t = {}
    for i = 15, 0, -1 do
        local v = math.floor(x / (2 ^ (4 * i))) % 16
        table.insert(t, string.format("%x", v))
    end
    return table.concat(t)
end

local function esc(s)
    return string.gsub(s or "", "[%c\"\\]", function(c)
        return string.format("\\u%04x", string.byte(c))
    end)
end

local function to_opts(job)
    return {
        entry = job.entry,
        find = job.find,
        avoid = job.avoid,
        symbolic = job.symbolic,
        regs = job.regs,
        steps = job.steps,
        states = job.states,
        solve = job.solve,
        uc_memory = job.uc,
        zero_low_pages = job.uc,
    }
end

-- One image load per process, every campaign on a fresh COW clone.
local img = assert(angry.prepare(TARGET))

local f = assert(io.open(JOBS, "r"))
local out = assert(io.open(OUT, "a"))

-- Collect this shard's jobs first so run_batch can see them all.
local mine = {}   -- { [1] = line_idx, [2] = job, [3] = opts }
local idx = 0
for line in f:lines() do
    local is_job = line ~= "" and not line:match("^#")
    if is_job then
        if idx % SHARDS == SHARD then
            local job = parse(line)
            if job then
                mine[#mine + 1] = { idx, job, to_opts(job) }
            end
        end
        idx = idx + 1
    end
end
f:close()

local function emit_result(line_idx, entry_hex, state, fields)
    local extra = fields or ""
    out:write(string.format('{"line":%d,"state":"%s","entry":"%s"%s}\n',
        line_idx, state, entry_hex, extra))
    out:flush()
end

local function record_report(line_idx, entry_hex, report)
    local exit_pc = report.exit_pc_hex or hex16(report.exit_pc or 0)
    local rax = report.rax_exit_hex or hex16(report.rax_exit or 0)
    return string.format(
        ',"found":%d,"exit_pc":"%s","rax":"%s","steps":%d,"timed_out":%s,"elapsed_ms":%d',
        report.found or 0, exit_pc, rax, report.steps or 0,
        tostring(report.timed_out or false), report.elapsed_ms or 0)
end

local done = 0
local lost = 0

if BATCH_THREADS and BATCH_THREADS > 1 and #mine > 1 then
    local jobs = {}
    for i, item in ipairs(mine) do
        jobs[i] = item[3]
    end
    local batch = img:run_batch(jobs, { threads = BATCH_THREADS })
    for i, item in ipairs(mine) do
        local entry_hex = hex16(item[2].entry)
        emit_result(item[1], entry_hex, "tombstone")
        local entry = batch[i]
        if entry and entry.ok and entry.report then
            emit_result(item[1], entry_hex, "done", record_report(item[1], entry_hex, entry.report))
            done = done + 1
        else
            emit_result(item[1], entry_hex, "failed",
                string.format(',"err":"%s"', esc(tostring(entry and entry.error or "batch error"))))
            lost = lost + 1
        end
    end
else
    for _, item in ipairs(mine) do
        local line_idx, job = item[1], item[2]
        local entry_hex = hex16(job.entry)
        -- Tombstone first: a shard that dies mid-job leaves a visible gap.
        emit_result(line_idx, entry_hex, "tombstone")
        local ok, report = pcall(img.run, img, item[3])
        if ok and type(report) == "table" then
            emit_result(line_idx, entry_hex, "done", record_report(line_idx, entry_hex, report))
            done = done + 1
        else
            emit_result(line_idx, entry_hex, "failed",
                string.format(',"err":"%s"', esc(tostring(report))))
            lost = lost + 1
        end
    end
end

out:close()

local stats = img:stats()
print(string.format(
    "bulk_resolve shard %d/%d done: %d jobs processed (%d failed); load_ms=%d run_ms_total=%d avg_run_ms=%d",
    SHARD, SHARDS, done, lost, stats.load_ms, stats.run_ms_total, stats.avg_run_ms))
