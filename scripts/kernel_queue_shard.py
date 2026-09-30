#!/usr/bin/env python3
"""Sharded kernel-queue runner: N independent `angryier run` processes over one queue.

The single-process Lua runner executes queue items strictly in sequence —
one core, one image load per item, and one wall-budget straggler at a time.
Kernel triage is embarrassingly parallel across functions: this script
splits a prioritized queue (P1-first JSON with items[] of {function,
entry_rva, ...}) into N shards, writes one Lua runner per shard, launches N
detached `angryier run` processes, and concatenates their KITEM/SUMMARY
lines into one merged log as shards finish.

Usage:
  python3 scripts/kernel_queue_shard.py --binary <image> --queue <queue.json> \
      --out <outdir> [--workers N] [--timeout-secs 90] [--opts "uc_memory=true,..."]

Workers default to the CPU count. Results: <outdir>/shard-*.log plus
<outdir>/merged.log (created incrementally; safe to tail). The merged log
preserves per-item KITEM lines but per-shard SUMMARY lines are rewritten as
`SUMMARY shard=<i> ...` so totals are additive.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ANGRYIER = REPO_ROOT / "target" / "release" / "angryier"

RUNNER_TEMPLATE = """local items = {{
{entries}
}}
local t_all = os.clock()
for _, it in ipairs(items) do
  local t0 = os.clock()
  local ok, r = pcall(angry.run, "{binary}", {{
    entry = it.entry,
    symbolic = {{ rcx = 64, rdx = 64, r8 = 64, r9 = 64 }},
    steps = {steps}, states = {states}, zero_low_pages = true,{opts}
    unsupported = "fallthrough", timeout_secs = {timeout},
  }})
  if not ok then
    print(string.format("KITEM %s ERROR %s cpu=%.2fs", it.name,
      tostring(r):gsub("\\n", " "):sub(1, 100), os.clock() - t0))
    r = {{}}
  end
  local k = r.kernel or {{}}
  local dfs = k.double_frees or {{}}
  local sites = {{}}
  for i, ev in ipairs(dfs) do
    if i <= 4 then sites[#sites+1] = string.format("0x%x@0x%x", ev.pointer, ev.caller) end
  end
  print(string.format(
    "KITEM %s steps=%d forks=%d term=%d failed=%d live=%d unsup=%d timed=%s allocs=%d frees=%d df=%d %s cpu=%.2fs",
    it.name, r.steps or -1, r.forks or -1, r.terminated or -1, r.failed or -1,
    r.live_states or -1, r.unsupported_total or -1, tostring(r.timed_out or false),
    k.allocs or 0, k.frees or 0, #dfs, table.concat(sites, ","), os.clock() - t0))
  io.stdout:flush()
end
print(string.format("SUMMARY shard={shard} items=%d total_cpu=%.1fs", #items, os.clock() - t_all))
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True, help="target image (PE)")
    parser.add_argument("--queue", type=Path, required=True, help="queue JSON with items[]")
    parser.add_argument("--out", type=Path, required=True, help="output directory")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4)
    parser.add_argument("--timeout-secs", type=float, default=90.0)
    parser.add_argument("--steps", type=int, default=500_000)
    parser.add_argument("--states", type=int, default=64)
    parser.add_argument(
        "--opts",
        type=str,
        default="uc_memory = true, uc_write_ro = true,",
        help="extra Lua opts line (trailing comma), e.g. 'uc_memory = true,'",
    )
    args = parser.parse_args()

    if not ANGRYIER.is_file():
        parser.error(f"engine binary missing: {ANGRYIER} (cargo build --release -p angryier-cli --features run)")
    queue = json.loads(args.queue.read_text())
    items = queue["items"] if isinstance(queue, dict) else queue
    args.out.mkdir(parents=True, exist_ok=True)

    workers = max(1, min(args.workers, len(items)))
    # Round-robin shards keep priority order: shard i gets items i, i+N, i+2N,
    # so every shard samples the whole priority range evenly (a contiguous
    # split would put all the long P1 giants in one shard).
    shards: list[list[dict]] = [[] for _ in range(workers)]
    for index, item in enumerate(items):
        shards[index % workers].append(item)

    procs: list[tuple[int, subprocess.Popen]] = []
    for shard_index, shard in enumerate(shards):
        entries = "\n".join(
            f'  {{ name = "{item["function"]}",'
            f' entry = 0x{0x140000000 + int(item["entry_rva"], 16):x} }},'
            for item in shard
        )
        script = args.out / f"shard-{shard_index}.lua"
        script.write_text(
            RUNNER_TEMPLATE.format(
                entries=entries,
                binary=args.binary.resolve(),
                steps=args.steps,
                states=args.states,
                timeout=args.timeout_secs,
                opts=args.opts,
                shard=shard_index,
            )
        )
        log = open(args.out / f"shard-{shard_index}.log", "w")
        procs.append(
            (
                shard_index,
                subprocess.Popen(
                    [str(ANGRYIER), "run", str(args.binary.resolve()), "--script", str(script)],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                ),
            )
        )
    print(f"launched {workers} shards over {len(items)} items -> {args.out}", file=sys.stderr)

    merged = args.out / "merged.log"
    with merged.open("w") as sink:
        pending = list(procs)
        while pending:
            still: list[tuple[int, subprocess.Popen]] = []
            for shard_index, proc in pending:
                if proc.poll() is None:
                    still.append((shard_index, proc))
                    continue
                shard_log = args.out / f"shard-{shard_index}.log"
                sink.write(f"=== shard {shard_index} (rc={proc.returncode}) ===\n")
                sink.write(shard_log.read_text())
                sink.flush()
            pending = still
            time.sleep(5)
    print(f"merged log: {merged}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
