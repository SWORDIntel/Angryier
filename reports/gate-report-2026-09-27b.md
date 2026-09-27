# Gate Report — 2026-09-27 (late session)

Addendum to `gate-report-2026-09-27.md` covering the real-driver rounds
(rounds 6–9): kernel API models, corpus-wide execution, dual-mode
measurements on real binaries, and the first cross-engine (angr) table.

## gate_a_dual_mode_real_driver

Command: `cargo test --release -p angryier-runtime --features xed --test dual_mode_driver_bench -- --nocapture`
Driver: GVCIDrv64.sys (194-step DriverEntry, clean termination).
Kernel pool model attached.

| mode | steps/s (release) | notes |
|---|---|---|
| Concrete | ~44,700 | baseline |
| Concolic (EXPLORE) | ~36,200–39,400 | 82–88% of concrete; shadow overhead 12–18% |
| Full-Symbolic | ~13,400–14,100 | bottleneck |

- Concolic-vs-symbolic multiplier: **~2.6–2.9×** (was 1.8× on the
  synthetic workload; target 5–10×).
- Path constraints recorded during stepping: 0 solver calls (EXPLORE
  contract).
- Conclusion: the symbolic evaluator is the measured bottleneck; the
  concolic fast path is close to concrete.

## gate_a_concolic_fidelity_real_drivers

Command: `cargo test -p angryier-runtime --features xed --test concolic_driver -- --nocapture`

| driver | concrete steps | concolic steps | exit rax | requires_prove |
|---|---|---|---|---|
| GVCIDrv64.sys | 194 | 194 | 0 | false |
| sandra_x64.sys | 691 | 691 | 0 | false |

EXPLORE matches concrete exactly on both real drivers with zero shadow
debt.

## gate_j_cross_engine_aligned

Command: `python3 scripts/gate_j_bench.py`
Driver: GVCIDrv64.sys. angr 10.0 with pool-alloc import hooks returning
fresh non-NULL pointers (0xFFFF800000000000 base, +0x1000 step,
zero-backed), DRIVER_OBJECT callbacks as ret-zero stubs, terminating
exit stub. Angryier release via `corpus_exec` per-driver timing.

| engine | instructions | unique PCs | wall s | steps/s | outcome |
|---|---|---|---|---|---|
| angr 10.0 | 193 | 183 | 0.613 | 315 | terminated |
| Angryier (release) | 194 | — | 0.004 | 46,190 | terminated |

- Semantically aligned: both engines execute the same DriverEntry to
  clean termination (193 vs 194 instructions; the difference is the
  synthetic exit hook).
- Raw rate gap: ~147×.
- Caveat recorded in the bench: the runs are aligned but the engines'
  kernel models differ in fidelity; the gap is directional evidence, not
  a gate verdict.

## corpus_execution_60k

Command: `cargo test --release -p angryier-runtime --features xed --test corpus_exec` (STEP_BUDGET temporarily 60000).
Corpus: 81 images (70 loadable x64 drivers; 11 load-fails are 32-bit
drivers / non-PE artifacts).

- **66 TERMINATED** (incl. zamguard64 at 58,494 steps)
- **4 BUDGET at 60,000 steps** (AMDRyzenMaster 0.29s, TmComm 0.38s,
  iQVW64 4.5s, libnicm 0.34s — long-running init/probe loops under the
  environment model)
- **0 blocked of any class** (BLOCK-FORM=0, BLOCK-NULL=0, BLOCK-OTHER=0)
- Total: 310,084 steps executed.

## verdict_validation_classes

Command: `cargo test -p angryier-runtime --features xed --test vuln_verdicts -- --nocapture`
9 import-variant fixtures; per-fixture assertions on pool events.

- Double-free: `double_free_vuln` → df=1 detected.
- **Use-after-free WRITE: `pointer_reassign_vuln` → uaf=1 detected**
  (new in round 9; the stale-pointer write is caught via freed-page
  write tracking).
- All safe/balanced fixtures: df=0, uaf=0 (no false positives).

## methodology_notes

- All release measurements on the same host (Xeon E5-2470 v2, Ivy
  Bridge); runs under a loaded machine, so absolute wall times vary a
  few percent — the ratios are stable across repeated runs.
- angr measured with `num_inst=1` stepping (VEX); Angryier per-driver
  timing parsed from the sweep's per-row seconds.
- Deterministic models: RDTSC/KeQueryPerformanceCounter fixed constants,
  PCI config space fixed values, pool pointers bump deterministically.
