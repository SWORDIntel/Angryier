# Gate measurement report — 2026-09-27

- Generated (UTC): 2026-09-27T03:12:20Z
- Git: 8f646794062f (dirty)
- rustc: rustc 1.98.0 (88d9e12ae 2026-08-18)
- CPU: Intel(R) Xeon(R) CPU E5-2470 v2 @ 2.40GHz
- Runner: scripts/gate_report.sh (GATE- lines captured verbatim from stdout)

## gate_a_concolic_speed

Command: `cargo test --release -p angryier-runtime --features xed --test concolic_speed -- --ignored --nocapture`

Exit: 0, duration 75 s

```text
GATE-A sparse: trace 60015 steps | concrete 307.3 ms (195.3 steps/ms) | concolic 594.9 ms (100.9 steps/ms, 1.94x concrete) | path constraints 0 | arena nodes 42109 (distinct folded constants only)
GATE-A sparse fixture: cc -O2, LOOPS=3000 constant-derived arithmetic, input consulted once at the end (fast-path shape)
GATE-A speed: trace 89915 steps | concrete 417.2 ms (215.5 steps/ms) | concolic 4115.6 ms (21.8 steps/ms, 9.87x concrete) | full-symbolic 7331.6 ms (12.3 steps/ms) | concolic-vs-symbolic multiplier 1.8x
GATE-A fixture: cc -O2, LOOPS=3000 immediate bound, seed RAX=0xc0ffee12345678, one data-dependent branch per iteration
GATE-A concolic detail: 6000 path constraints recorded, shadow debt (requires_prove) = false, solver calls during stepping = 0
GATE-A full-symbolic detail: 89915/89915 budget steps consumed, 4802 forks, peak 33 live states, 2016 terminated, 0 failed, 32 live at stop, max_states cap = 32
GATE-A multiplier basis: direct — full symbolic consumed the full 89915-step budget in 7331.6 ms vs concolic 4115.6 ms
```

## gate_b_footprint

Command: `cargo test -p angryier-runtime --features xed --test gate_b -- --ignored --nocapture`

Exit: 0, duration 11 s

```text
GATE-B footprint: concrete 10000 states, RSS +27.1 MB (2.8 KB/state), fork cost 16.6 us/state over 165.88ms
GATE-B footprint: symbolic 10000 states, RSS +108.8 MB (11.1 KB/state), arena nodes 285153, fork cost 949.8 us/state over 9.50s
GATE-B footprint: concrete 10000 states, RSS +27.1 MB (2.8 KB/state) | symbolic 10000 states, RSS +108.8 MB (11.1 KB/state), arena nodes 285153
```

## gate_b_solver_migration

Command: `cargo test -p angryier-solver-z3-ffi --test migration_bench -- --ignored --nocapture`

Exit: 0, duration 1 s

```text
GATE-B solver: depth 100 cold=94.4ms partial=16.0ms warm=1.7ms (cold/warm ratio 54.9)
GATE-B solver: depth 250 cold=61.8ms partial=42.7ms warm=3.8ms (cold/warm ratio 16.1)
GATE-B solver: depth 500 cold=90.4ms partial=93.6ms warm=6.9ms (cold/warm ratio 13.0), ctx RSS +0.07 MB (68 KB)
```

## gate_c_preemption

Command: `cargo test --release -p angryier-solver-z3-ffi --test preemption_bench -- --ignored --nocapture`

Exit: 0, duration 27 s

```text
GATE-C preemption: family=semiprime factoring (32-bit N), budgets=10/50/100/500ms reps=3
GATE-C preemption: uninterrupted outcome=Sat wall=14259ms (ceiling 20000ms)
GATE-C preemption: verified ground truth Sat: 131071 * 65521 == N (32-bit)
GATE-C preemption: budget=10ms outcome=Unknown wall_mean=42ms overhead~32ms throughput=16.99 q/s (3 reps in 177ms)
GATE-C preemption: budget=50ms outcome=Unknown wall_mean=60ms overhead~32ms throughput=13.00 q/s (3 reps in 231ms)
GATE-C preemption: budget=100ms outcome=Unknown wall_mean=113ms overhead~32ms throughput=7.57 q/s (3 reps in 396ms)
GATE-C preemption: budget=500ms outcome=Unknown wall_mean=509ms overhead~32ms throughput=1.94 q/s (3 reps in 1547ms)
GATE-C preemption: prearmed interrupt() outcome=Sat wall=5.28ms (next-check cancellation consumed before check)
```

## gate_c_alpha

Command: `cargo test -p angryier-solver -- --ignored --nocapture`

Exit: 0, duration 2 s

```text
GATE-C alpha: family(8 renamed) confirmations=7 contradictions=0 proposals=16 suppressed=0 indexed_buckets=9
GATE-C alpha: exact cache entries=16 hits=0 misses=16
```

