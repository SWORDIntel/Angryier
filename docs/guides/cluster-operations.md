# Cluster operations: running many campaigns across hosts

Operational findings from driving `angryier-campaign` across the three-host lab cluster (T420 controller, T320, 730xd) on real driver corpora. This is the **measured** companion to the [distributed operator guide](distributed-campaigns.md): that document describes one coordinator plus up to four workers; this one describes running hundreds of independent campaigns, each with one worker, spread over several machines.

Everything below was executed and counted; no figure is estimated.

## Topology that works

One coordinator host with light load, N worker hosts. Per campaign: **one worker process, one coordinator process, one ledger**. The coordinator is the sole ledger writer and independently replays each fenced subtree; the worker never writes the ledger.

| Role | Machine class | Placement used |
|---|---|---|
| Controller | 40-core, 110 GiB | ≤ 20 campaigns (2 concurrent) — kept light |
| Worker A | 16-core, 62 GiB | up to 400 campaigns (12–16 concurrent) |
| Worker B | 56-core, 93 GiB | up to 600 campaigns (20–24 concurrent) |

Measured throughput: **1,000 campaigns across three hosts in 111 s wall** (852 PE32+ drivers on B and A, 148 `.ko` on all three), 985 of 1,000 producing a ledger event.

## The fan-out pattern

Do not script N sequential `ssh` calls. Use one job file with **the host on every line** and one `parallel` invocation:

```
# jobs.tsv: host <TAB> args...
root@t320<TAB>windows<TAB>0042_win_ab12cd34.sys<TAB>pe-driver<TAB>-<TAB>0x14005e01b<TAB>33400<TAB>42<TAB>1024:512:120000
```

```sh
parallel --colsep '\t' -j 16 --delay 0.05 \
  'ssh -o ControlMaster=no -o ControlPath=none -o BatchMode=yes {1} \
     /opt/byovd/run_one.sh {2} {3} {4} {5} {6} {7} {8} {9}' :::: jobs.tsv > results.tsv
```

Reasons this shape is required, each learned the hard way:

- **`--sshlogin` slot routing was unreliable at this scale.** `--sshlogin '2/:' --sshlogin '10/root@t320' --sshlogin '10/root@730xd'` placed all accepted jobs on one host on two separate attempts, while an explicit host-per-line file split exactly as written.
- **`sshd` limits, not CPU, cap concurrency.** With one multiplexed connection and 10 simultaneous sessions, `sshd` refused sessions (`Session open refused by peer`). Fixes: `-o ControlMaster=no -o ControlPath=none` per job, and/or `--delay`; raising `MaxSessions`/`MaxStartups` is the alternative.
- **Worker binary startup dominates small campaigns.** A debug `angryier-campaign` (124 MB) takes ~45 s to reach `READY` because it hashes its own executable; the release build (11 MB) takes ~1 s. Always deploy the release binary for fan-out runs. One binary per host, byte-identical across hosts (`sha256sum` compared on all three).
- **Quote or avoid awkward filenames.** Corpus entries derived from Windows paths contain literal backslashes; passing them as shell arguments through `parallel --colsep` mangles them and the copy silently fails. Sanitise names at staging and drive remote loops from a per-host *list file* instead of per-job arguments.

## Worker placement and keys

- Each worker host runs one worker process per campaign, each with **its own pairwise key and its own AEAD config** (or the same flags). `--connections 0` keeps serving until the operator stops it; `--connections 1` is the right choice for a one-shot campaign because the worker exits after the session.
- Loopback only. For cross-host runs the coordinator must reach `127.0.0.1:<port>` on the worker through an SSH local forward (`ssh -L`), or run the pair on the same host. The frame HMAC authenticates but **does not encrypt**; never expose the listener directly.
- Provision the key and config at mode `0600` in a `0700` directory; the loader rejects group/world-readable keys.

## Failure taxonomy (measured, 1,000-campaign run)

| Outcome | Count | Meaning |
|---|---:|---|
| Ledger event produced | 985 | normal path |
| `Deferred / Unknown` | ~300 (PE) | Windows: call/return bookkeeping inside the image (`docs/BLOCKERS.md` §1) |
| `Deferred / Queued` | 507 (PE) | run forked; children unresolved when the wall bound closed. "Completed" overstates progress |
| `Deferred / ResourceLimit` | 19 (PE) | declared path/step budget exhausted |
| `CampaignMismatch` at handshake | several | sealed limits differ between coordinator and worker — now reported by name, not as `InvalidMac` |
| `root cannot be pinned (PeDriver)` | 9 | whole `vm3dmp*` family; environment cannot be pinned |
| `InvalidTransition` | 10 → 0 | was an evidence-size cap (69,840 B vs 65,536 B); fixed in `d7aed1a` |
| `transport: Truncated` / `Connection refused` | 2 / 4 | worker dropped or port already in use — usually a stale process on the port |

Practical consequences: pin the port per campaign (unique per job) so a stale worker cannot answer for a new one; treat `Queued` as "not finished" when scoring; keep `--max-wall-ms` generous enough for child resolution on forking images.

## What the numbers mean

Score three things separately, never one number:

1. **`trace_observed`** — the declared target PC appears on a coordinator-replayed accepted path.
2. **`observed`** — strict verified-terminal witness (`Completed` + `Terminal` + `ReplayVerification::Verified`).
3. **violations** — stateful model outcomes (`kernel double-free detected`, refcount underflow).

Measured on real corpora: Linux `.ko` target reach 59–70 %, Windows PE32+ 37–47 %, witness-verified terminals **0** on the real corpora, violations **0** on the real corpora (the stateful models are proven end-to-end only on synthetic `.ko` fixtures so far).

## Preflight and cleanup checklist

```sh
# 1) one release binary, identical bytes
cargo build -p angryier-campaign --release --locked --offline
sha256sum target/release/angryier-campaign           # compare on every host

# 2) corpus staged at an identical absolute path on every host, SHAs recorded
rsync -a corpus/ worker:/opt/byovd/corpus/

# 3) per-campaign keys, mode 0600
(umask 077; head -c 32 /dev/urandom > keys/w<N>.key)

# 4) dispatch, collect, score
parallel --colsep '\t' ... :::: jobs.tsv > results.tsv
```

After a run: kill workers by PID resolved from `ss -ltnp` (never `pkill -f` with a pattern that also matches your own SSH command line), remove `/tmp` work dirs, and `cargo clean` any build tree you no longer need — a full workspace release build is ~3 GiB.

## Scope limits

Three Proxmox hosts on 1 GbE, ≤ 24 concurrent campaigns per host, driver corpora of `ET_REL` `.ko` and PE32+ `.sys` up to 16 MiB. No InfiniBand, no multi-worker-per-campaign runs at scale (2- and 4-worker campaigns are covered by the separate-process test suite), and no claim about throughput beyond what is tabulated here.
