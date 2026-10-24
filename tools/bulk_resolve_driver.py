#!/usr/bin/env python3
"""Bulk address-resolution driver for Angryier (load-once shards).

Splits a jobs file across N parallel `angryier run --script bulk_resolve.lua`
processes (one per core by default). Inside each process the Lua driver
`angry.prepare`s the image ONCE and runs every shard job as a campaign on a
fresh copy-on-write clone — the per-job 288 MB image re-parse is gone.

Usage: bulk_resolve_driver.py --binary <PE> --jobs <jobs.txt> [--shards N]
                              [--batch-threads N] [--out results.jsonl]
                              [--angryier <path>]

--batch-threads N switches each shard to the native in-process worker pool
(`img:run_batch`), which runs one process with N threads by default (pass
--shards to combine process-level and thread-level parallelism).

Records: the Lua driver writes a `tombstone` line before each job and a
`done`/`failed` line after it. The merge pairs them: `done` records become
results, `failed` records carry `err`, and unpaired tombstones surface as
`lost` jobs — a shard that died mid-job is visible instead of silent.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "scripts" / "lua" / "bulk_resolve.lua"


def count_jobs(jobs_path: Path) -> int:
    n = 0
    with open(jobs_path) as f:
        for line in f:
            if line.strip() and not line.lstrip().startswith("#"):
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--jobs", required=True)
    ap.add_argument("--shards", type=int, default=None,
                    help="parallel shard processes (default: min(cores, jobs); "
                         "1 when --batch-threads is used)")
    ap.add_argument("--batch-threads", type=int, default=None,
                    help="in-process worker pool per shard (img:run_batch)")
    ap.add_argument("--out", default="bulk_results.jsonl")
    ap.add_argument("--angryier", default=None)
    args = ap.parse_args()

    jobs_path = Path(args.jobs)
    n_jobs = count_jobs(jobs_path)
    if n_jobs == 0:
        print("bulk_resolve_driver: jobs file has no jobs", file=sys.stderr)
        return 1

    if args.shards is not None:
        shards = max(1, args.shards)
    elif args.batch_threads:
        shards = 1  # one process, N native threads
    else:
        shards = max(1, min(os.cpu_count() or 8, n_jobs))
    angryier = args.angryier or "angryier"

    tmp = Path(tempfile.mkdtemp(prefix="bulk_resolve_"))
    procs = []
    for shard in range(shards):
        env = dict(os.environ)
        env.update({
            "ANGRY_TARGET": args.binary,
            "ANGRY_JOBS": str(jobs_path),
            "ANGRY_OUT": str(tmp / f"shard_{shard:02d}.jsonl"),
            "ANGRY_SHARD": str(shard),
            "ANGRY_SHARDS": str(shards),
        })
        if args.batch_threads:
            env["ANGRY_BATCH_THREADS"] = str(args.batch_threads)
        log = open(tmp / f"shard_{shard:02d}.log", "w")
        procs.append(subprocess.Popen(
            [angryier, "run", args.binary, "--script", str(SCRIPT)],
            env=env, stdout=log, stderr=log))
    fails = 0
    for shard, p in enumerate(procs):
        p.wait()
        if p.returncode != 0:
            fails += 1
            log_tail = (tmp / f"shard_{shard:02d}.log").read_text(errors="replace").strip()
            print(f"  shard {shard} exited {p.returncode}:", file=sys.stderr)
            print("  " + "\n  ".join(log_tail.splitlines()[-6:]), file=sys.stderr)

    # Merge: pair tombstone/done/failed by (line, entry). Done records are
    # results; failed records carry the error; unpaired tombstones are lost.
    by_line = {}
    for f in sorted(tmp.glob("shard_*.jsonl")):
        for line in f.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = rec.get("line")
            state = rec.get("state", "done")
            if state == "tombstone":
                by_line.setdefault(key, {}).setdefault("tombstones", 0)
                by_line[key]["tombstones"] += 1
            elif state == "done":
                out_rec = dict(rec)
                out_rec.pop("state", None)
                out_rec.setdefault("err", None)
                by_line.setdefault(key, {})["result"] = out_rec
            elif state == "failed":
                out_rec = {
                    "line": rec.get("line"),
                    "entry": rec.get("entry", ""),
                    "found": 0, "exit_pc": "", "rax": "", "steps": 0,
                    "timed_out": False,
                    "err": rec.get("err", "job failed"),
                    "elapsed_ms": 0,
                }
                by_line.setdefault(key, {})["result"] = out_rec

    records = []
    lost = 0
    for key in sorted(k for k in by_line if k is not None):
        entry = by_line[key]
        if "result" in entry:
            records.append(entry["result"])
        else:
            lost += 1
            records.append({
                "line": key, "entry": "", "found": 0, "exit_pc": "", "rax": "",
                "steps": 0, "timed_out": False,
                "err": "lost: shard died before this job produced a result",
                "elapsed_ms": 0,
            })
    records.sort(key=lambda r: r.get("line", 0))
    out = Path(args.out)
    out.write_text("".join(json.dumps(r) + "\n" for r in records))
    print(f"shards={shards} batch_threads={args.batch_threads or 0} "
          f"failed_procs={fails} jobs={n_jobs} results={len(records) - lost} "
          f"lost={lost} -> {out}")
    for f in sorted(tmp.glob("shard_*.log")):
        txt = f.read_text(errors="replace").strip()
        if "done:" in txt:
            print(f"  {f.name}: {txt.splitlines()[-1]}")
    return 1 if (fails or lost) else 0


if __name__ == "__main__":
    sys.exit(main())
