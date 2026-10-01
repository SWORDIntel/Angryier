# Full-system benchmark — 2026-10-01

Every number pairs with its command and environment; re-runnable unless noted.
Host: t420 (Xeon E5-2470 v2, 10c). Engine: Angryier @ 1595319. Pipeline: KP14 @ 06169966.

## 1. Engine — internal gates (scripts/gate_report.sh, all Exit 0)

| Gate | 2026-09-30 baseline | 2026-10-01 | Delta |
|---|---|---|---|
| GATE-A concolic throughput | 7.4 steps/ms | **10.4 steps/ms** | +40% (solver fix) |
| GATE-A concolic-vs-symbolic multiplier | 2.8× | **3.2×** | wider |
| GATE-B concrete footprint | 2.8 KB/state | 2.8 KB/state | unchanged |
| GATE-B symbolic fork cost | 1274 µs/state | **991 µs/state** | −22% |
| GATE-B solver warm/cold (d500) | 25.5× | 14.4× | warm path faster |

Full report: `reports/gate-report-2026-10-01.{md,json}`.

## 2. Solver — incremental prefix reuse (micro-benchmark, kernel-shaped chains)

| Metric | before | after |
|---|---|---|
| mean ms/query (200 growing-prefix) | 54.05 | **16.9 (3.2×)** |
| last-bucket median (prefix ~190) | 129.1 ms | **~24 ms (~4.5×)** |
| prefix reuse | collapsed to O(1) | shared=full, popped=0 (CI-enforced) |

## 3. Engine — angr parity (gate_j_corpus.py, equal fidelity, flag-off)

8/8 rows TERMINATED, Angryier steps = angr steps + 1 exactly on every row; raw rate ratios **91×–1262×**. Corpus regression byte-identical with all new features off; concolic fidelity sweep: **zero divergences across 70 drivers**.

## 4. Engine — ntoskrnl P1 queue (the headline)

255 double-free-candidate functions, 90 s/function cap, full relaxation set
(uc_memory, uc_write_ro, fallthrough), exploration=fork, search=dfs, sharded
×8 workers (scripts/kernel_queue_shard.py).

| Metric | 2026-09-30 baseline | 2026-10-01 |
|---|---|---|
| Clean completions (failed=0) | 2/255 (0.8%) | **201/255 (79%)** |
| Wall-budget divers (deep exploration) | 1 | **182** |
| Steps/function (mean) | 2,901 | **38,275 (13×)** |
| Steps/function (median / max) | — | 5,358 / 487,905 |
| Forks (total) | 1 | 134 |
| Pool double-free events | 0 | 2 |
| Wall time | ~24 min serial | ~45 min for P1 (within a full-queue run) |

Both df events are pointer-0 class (FUN_1402d9bd0 frees=2; FUN_140a8c970
df=1 @ caller 0x140a8db57 — the known tail-free site). Per the research
brief's hard gate, pointer-0 events are entry-artifact class until
reproduced with live frames; FUN_140a8c970's structured-entry follow-up
(F1 acceptance mission) reached the sink with verdict reached/MODEL_LIMITED.

Note: the sharded runner consumed the FULL 3,035-item queue (no P1 filter);
the P1 subset above is exact. The full-queue sweep continues detached as the
campaign opener (~440+ items complete at report time).

## 5. Pipeline — regression harness (P2, 18 synthetic drivers per run)

| Host / engine | verdict | wall |
|---|---|---|
| kp14-suite VM / Ghidra 11.0.1 | PASS 18/18 | 625 s |
| kp14-suite VM / Ghidra 11.0.1 (re-run) | PASS 18/18 | 584 s |
| 730xd / Ghidra 12.0.4 | PASS 18/18 | 499 s |
| 730xd / Ghidra 12.1.3 (post-portability-fix) | PASS 18/18 | 535 s |

Three-Ghidra-engine parity is proven by runs, not compiles.

## 6. System — distributed mesh

- Two-host exactly-once (VF drill): 2 jobs, workers 2 s apart on different
  hosts — single attempt each, write-once results; job durations 65.0 s
  (730xd) / 78.0 s (VM); 4-worker single-host race also exactly-once.
- QIHSE replication: dual-node readback sha256-identical; replica lag ~60 s.
- F1 acceptance mission: **8/8 PASS** across both hosts including one live
  failure+requeue recovery (root-defaulted KP14_HOME) and a structured-entry
  escalation probe on real findings.
- Clone materialization (reference): full ZFS send 137 GB→60 min at 1 GbE;
  linked-clone drill: minutes, netless.

## Environment pins

Angryier 1595319 (solver 6b8a195, region-fork a772564, hex/portability
1595319); KP14 pipeline 06169966; Ghidra 11.0.1 / 12.0.4 / 12.1.3;
QIHSE 3-node cluster (.91/.250/.90). Kernel target: ntoskrnl 26100.9168
(sha 13aa0721…), queue from the 2026-09-29 Ghidra campaign.
