# Gate measurement report — 2026-09-28

- Generated (UTC): 2026-09-28T18:35:01Z
- Git: 541d1116077b (dirty)
- rustc: rustc 1.98.0 (88d9e12ae 2026-08-18)
- CPU: Intel(R) Xeon(R) CPU E5-2470 v2 @ 2.40GHz
- Runner: scripts/gate_report.sh (GATE- lines captured verbatim from stdout)

## gate_a_concolic_speed

Command: `cargo test --release -p angryier-runtime --features xed --test concolic_speed -- --ignored --nocapture`

Exit: 0, duration 101 s

```text
GATE-A sparse: trace 60015 steps | concrete 675.1 ms (88.9 steps/ms) | concolic 1352.8 ms (44.4 steps/ms, 2.00x concrete) | path constraints 0 | arena nodes 42109 (distinct folded constants only)
GATE-A sparse fixture: cc -O2, LOOPS=3000 constant-derived arithmetic, input consulted once at the end (fast-path shape)
GATE-A speed: trace 89915 steps | concrete 1020.2 ms (88.1 steps/ms) | concolic 9677.6 ms (9.3 steps/ms, 9.49x concrete) | full-symbolic 17211.8 ms (5.2 steps/ms) | concolic-vs-symbolic multiplier 1.8x
GATE-A fixture: cc -O2, LOOPS=3000 immediate bound, seed RAX=0xc0ffee12345678, one data-dependent branch per iteration
GATE-A concolic detail: 6000 path constraints recorded, shadow debt (requires_prove) = false, solver calls during stepping = 0
GATE-A full-symbolic detail: 89915/89915 budget steps consumed, 4802 forks, peak 33 live states, 2016 terminated, 0 failed, 32 live at stop, max_states cap = 32
GATE-A multiplier basis: direct — full symbolic consumed the full 89915-step budget in 17211.8 ms vs concolic 9677.6 ms
```

## gate_b_footprint

Command: `cargo test -p angryier-runtime --features xed --test gate_b -- --ignored --nocapture`

Exit: 0, duration 23 s

```text
GATE-B footprint: concrete 10000 states, RSS +26.8 MB (2.7 KB/state), fork cost 45.2 us/state over 451.83ms
GATE-B footprint: symbolic 10000 states, RSS +108.3 MB (11.1 KB/state), arena nodes 285153, fork cost 1860.5 us/state over 18.60s
GATE-B footprint: concrete 10000 states, RSS +26.8 MB (2.7 KB/state) | symbolic 10000 states, RSS +108.3 MB (11.1 KB/state), arena nodes 285153
```

## gate_b_solver_migration

Command: `cargo test -p angryier-solver-z3-ffi --test migration_bench -- --ignored --nocapture`

Exit: 0, duration 1 s

```text
GATE-B solver: depth 100 cold=65.4ms partial=36.1ms warm=3.8ms (cold/warm ratio 17.2)
GATE-B solver: depth 250 cold=111.4ms partial=91.6ms warm=7.6ms (cold/warm ratio 14.6)
GATE-B solver: depth 500 cold=199.2ms partial=208.1ms warm=15.5ms (cold/warm ratio 12.9), ctx RSS +0.07 MB (68 KB)
```

## gate_c_preemption

Command: `cargo test --release -p angryier-solver-z3-ffi --test preemption_bench -- --ignored --nocapture`

Exit: 0, duration 23 s

```text
GATE-C preemption: family=semiprime factoring (32-bit N), budgets=10/50/100/500ms reps=3
GATE-C preemption: uninterrupted outcome=Unknown wall=20032ms (ceiling 20000ms)
GATE-C preemption: budget=10ms outcome=Unknown wall_mean=62ms overhead~52ms throughput=11.21 q/s (3 reps in 268ms)
GATE-C preemption: budget=50ms outcome=Unknown wall_mean=65ms overhead~52ms throughput=10.68 q/s (3 reps in 281ms)
GATE-C preemption: budget=100ms outcome=Unknown wall_mean=115ms overhead~52ms throughput=7.34 q/s (3 reps in 409ms)
GATE-C preemption: budget=500ms outcome=Unknown wall_mean=516ms overhead~52ms throughput=1.86 q/s (3 reps in 1609ms)
GATE-C preemption: prearmed interrupt() outcome=Sat wall=2.26ms (next-check cancellation consumed before check)
```

## gate_c_alpha

Command: `cargo test -p angryier-solver -- --ignored --nocapture`

Exit: 0, duration 1 s

```text
GATE-C alpha: family(8 renamed) confirmations=7 contradictions=0 proposals=16 suppressed=0 indexed_buckets=9
GATE-C alpha: exact cache entries=16 hits=0 misses=16
```

## gate_j_cross_engine_aligned (corpus)

Command: `python3 scripts/gate_j_corpus.py --driver GVCIDrv64.sys --driver sandra_x64.sys --driver double_free_vuln_import_O2.sys --driver allocsize_overflow_vuln_import_O2.sys`

Aligned environment both engines: pool allocators return fresh non-NULL
pointers (0xFFFF800000000000 base, +0x1000 step, zero-backed); all other
kernel externs return STATUS_SUCCESS (0); DRIVER_OBJECT callbacks return
0; the return slot points at a terminating stub. angr 10.0 steps
instruction-by-instruction (VEX), capped at 20k insts / 60 s. Angryier
release via the `corpus_exec` sweep (same loader, kernel pool model,
exit hook).

| driver | angr insts | angr unique PCs | angr s | angr steps/s | angr outcome | Angryier steps | Angryier s | Angryier steps/s | Angryier class | raw rate ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| GVCIDrv64.sys | 193 | 183 | 1.723 | 112.0 | terminated | 194 | 0.0103 | 18,835 | TERMINATED | **168×** |
| sandra_x64.sys | 698 | 436 | 5.357 | 130.3 | terminated | 691 | 0.0256 | 26,992 | TERMINATED | **207×** |
| double_free_vuln_import_O2.sys | 22 | 20 | 0.203 | 108.3 | terminated | 23 | 0.0014 | 16,429 | TERMINATED | **152×** |
| allocsize_overflow_vuln_import_O2.sys | 24 | 24 | 0.210 | 114.3 | terminated | 25 | 0.0015 | 16,667 | TERMINATED | **146×** |

Both engines execute the same DriverEntry to clean termination on every
row (step counts agree ±1 — the synthetic exit hook). Raw rate ratios are
directional evidence for the dual-mode thesis, not a semantic-throughput
verdict: the engines' kernel-model fidelity differs, and the SymQEMU/
SymCC-class leg is not measured (binary-only concolic engines need a full
Windows guest for kernel images — documented, not run).

## correctness_fixes_2026-09-28

- **Kernel-model skip on `call [IAT]` (symbolic session) — fixed.** The
  function-summary lazy extraction summarized the import stub's bare
  `ret` cell as a "pure function", silently skipping the kernel SimProcedure
  (pool allocations, status results) and diverging the symbolic path from
  concrete. `try_function_summary` now refuses SimProcedure hook
  addresses; regression tests in
  `crates/angryier-runtime/tests/symbolic_kernel_models.rs`
  (dispatch count on GVCIDrv64; pool events on the allocsize fixture).
- **Stable library API landed** (`crates/angryier`): `Engine`/`Image`/
  `RunOptions`/`RunReport`/`Session` mirroring the Lua surface; magic-byte
  dispatch, kernel pool model, entry override, symbolic inputs, solving,
  kernel verdict reports. 4 smoke tests green.
- **Known gap documented:** full-symbolic fidelity on real drivers is not
  yet concrete-faithful (constant branch conditions fork without a solver;
  some stack-derived register bindings resist folding) — concolic EXPLORE
  fidelity on real drivers remains validated; the PROVE leg is the open
  workstream.

