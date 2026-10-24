-- bulk_resolve_session.lua — session-mode bulk resolution: ONE image load
-- per process via angry.open + s:spawn_state per job, s:step(1) to
-- completion. Same jobs-file format and JSONL record shape as
-- bulk_resolve.lua (plus a per-job "mode" field: session).

local TARGET = os.getenv("ANGRY_TARGET")
local JOBS = os.getenv("ANGRY_JOBS")
local OUT = os.getenv("ANGRY_OUT") or "bulk_session_results.jsonl"
local SHARD = tonumber(os.getenv("ANGRY_SHARD") or "0")
local SHARDS = tonumber(os.getenv("ANGRY_SHARDS") or "1")

if not TARGET or not JOBS then
    error("bulk_resolve_session: need ANGRY_TARGET and ANGRY_JOBS env vars")
end

local function hexval(v)
    if v:match("^0[xX]") then return tonumber(v:sub(3), 16) end
    return tonumber(v, 16)
end

local function parse(line)
    local job = { entry = nil, steps = 256, uc = false }
    for k, v in string.gmatch(line, "(%w+)=([^%s]+)") do
        if k == "entry" then job.entry = hexval(v)
        elseif k == "steps" then job.steps = tonumber(v)
        elseif k == "uc" then job.uc = (v == "1" or v == "true")
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

print(string.format("[session] opening %s", TARGET))
local s = angry.open(TARGET, {})

local f = assert(io.open(JOBS, "r"))
local out = assert(io.open(OUT, "a"))
local idx = 0
local done = 0
for line in f:lines() do
    if line ~= "" and not line:match("^#") then
        if idx % SHARDS == SHARD then
            local job = parse(line)
            -- Tombstone first: if the process dies mid-job, the shard still
            -- leaves a visible record behind.
            out:write(string.format(
                '{"line":%d,"entry":"%s","found":0,"exit_pc":"","rax":"","steps":0,"timed_out":false,"err":"tombstone:process_died","mode":"session"}\n',
                idx, hex16(job.entry)))
            out:flush()
            local rec
            local ok, result = pcall(function()
                s:spawn_state({ entry = job.entry, uc_memory = job.uc, zero_low_pages = job.uc })
                local steps = 0
                local status = "stepped"
                while steps < job.steps do
                    status = s:step(1)
                    steps = steps + 1
                    if status == "terminated" or status == "breakpoint" then break end
                end
                local pc, rax = "", ""
                if s:dead_count() > 0 then
                    local d = s:dead_state(s:dead_count() - 1)
                    pc = d:pc_hex()
                    rax = d:reg_hex("rax")
                elseif s:states_count() > 0 then
                    local a = s:state(0)
                    pc = a:pc_hex()
                    rax = a:reg_hex("rax")
                end
                -- pc_hex/reg_hex carry a 0x prefix; run-mode reports do not.
                return { pc = pc:gsub("^0[xX]", ""), rax = rax:gsub("^0[xX]", ""), steps = steps, status = status }
            end)
            if ok then
                rec = string.format(
                    '{"line":%d,"entry":"%s","found":0,"exit_pc":"%s","rax":"%s","steps":%d,"timed_out":%s,"err":null,"mode":"session"}',
                    idx, hex16(job.entry), result.pc, result.rax,
                    result.steps, tostring(result.status ~= "terminated"))
            else
                rec = string.format(
                    '{"line":%d,"entry":"%s","found":0,"exit_pc":"","rax":"","steps":0,"timed_out":false,"err":"%s","mode":"session"}',
                    idx, hex16(job.entry), esc(tostring(result)))
            end
            out:write(rec .. "\n")
            out:flush()
            done = done + 1
        end
        idx = idx + 1
    end
end
f:close()
out:close()
print(string.format("bulk_resolve_session shard %d/%d done: %d jobs", SHARD, SHARDS, done))
