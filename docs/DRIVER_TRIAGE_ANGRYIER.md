# Driver triage additions — Angryier

Split from [`DRIVER_TRIAGE_ADDITIONS.md`](https://github.com/SWORDIntel/KP15-SUITE/blob/main/docs/DRIVER_TRIAGE_ADDITIONS.md) (2026-11-22).
Provenance: live driver triage on the 47-driver pool; Angryier was not in the
loop for driver work, yet the core questions are symbolic.

## ANG-1xx — driver-idiom symbolic pack

**Observed.** Angryier was not in the loop for driver work, yet the questions
are symbolic: "can a caller-controlled buffer reach this sink given the
dispatch gate and DACL?"

**Change.** Ship a Lua script pack:

| script | proof |
|---|---|
| `driver/ioctl_reach.lua` | attacker buffer → handler → sink |
| `driver/method_neither.lua` | user VA used without probe |
| `driver/phys_map.lua` | `MmMapIoSpace`/`MmMapLockedPagesSpecifyCache` with attacker-controlled PA |
| `driver/token_prim.lua` | `ZwOpenProcess` + `KeStackAttachProcess` + `MmCopyVirtualMemory` |

Allow a DACL assumption input so the proof reports "reachable if device is
openable by X".

**Acceptance.** On `skyamdrv`, `method_neither.lua` reports the unprobed user
pointer path into the worker; on `mtcBSv64`, `ioctl_reach.lua` shows the
`0x88892810` handler with the MSR sink; both annotated with the DACL
assumption.

## Inputs from other tools

- **METHRA MTR-154** (MSR/port-I/O semantics,
  [DRIVER_TRIAGE_METHRA.md](DRIVER_TRIAGE_METHRA.md)) marks privileged
  operations with `privileged=true` and `reads_msr`/`writes_msr`/`io_port`
  metadata — the sinks `ioctl_reach.lua` reasons about.
- **radare3 RD3-112/114** (`surfaces` + `gates[]`,
  [DRIVER_TRIAGE_RADARE3.md](DRIVER_TRIAGE_RADARE3.md)) provide the dispatch
  map and gate/DACL evidence that parameterize the DACL assumption.
- **KP15 triage profile** ([DRIVER_TRIAGE_KP15.md](DRIVER_TRIAGE_KP15.md))
  supplies the per-driver JSON the scripts are invoked against.

## Sequencing

Last wave, after the triage profile and fixtures exist: the scripts are the
symbolic layer on top of the verdict engine.
