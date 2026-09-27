#!/usr/bin/env python3
"""Gate J first datapoint: run a real .sys driver through angr and report
wall-time / instruction / unique-PC counts for comparison with Angryier.

Setup for a minimal kernel-driver environment so angr can actually execute:
- the DRIVER_OBJECT scratch region is mapped and zeroed,
- the ntoskrnl/HAL imports are hooked to concrete returns (pool alloc
  returns a fresh pointer, frees are no-ops, everything else returns 0),
- stepping is instruction-by-instruction (`num_inst=1`).

This is a probe, not the final benchmark: angr is user-mode-focused and the
comparison targets the ENGINE loop mechanics and coverage, not semantic
fidelity. Run Angryier's equivalent on the same driver via:
  cargo test -p angryry-runtime --features xed --test isa_coverage ...

Usage: python3 scripts/gate_j_probe.py <driver.sys> [--max-inst N] [--timeout S]
"""

import argparse
import logging
import sys
import time

SCRATCH = 0x700010000000
POOL = 0xFFFF800000000000


def hook_imports(proj: "angr.Project") -> None:
    """Hook the imports a .sys driver references with concrete returns."""
    # The loader records unresolved imports as hooks by name when available.
    pool_next = {"v": POOL}

    def alloc(state, pool_type=None, size=0x100):  # noqa: ANN001
        ptr = pool_next["v"]
        pool_next["v"] += 0x1000
        state.regs.rax = ptr
        return None

    def free(state, ptr=None):  # noqa: ANN001
        state.regs.rax = 0
        return None

    def ret_zero(state, *args):  # noqa: ANN001, ANN002
        state.regs.rax = 0
        return None

    for name in [
        "ExAllocatePool",
        "ExAllocatePoolWithTag",
        "ExAllocatePool2",
        "ExAllocatePoolWithTagPriority",
    ]:
        proj.hook_symbol(name, alloc, kwargs={"size": 0x100})
    for name in ["ExFreePool", "ExFreePoolWithTag", "ExFreePoolWithQuota"]:
        proj.hook_symbol(name, free)
    for name in [
        "RtlInitUnicodeString",
        "RtlGetVersion",
        "IoCreateDevice",
        "IoDeleteDevice",
        "IoAttachDevice",
        "IoBuildDeviceIoControlRequest",
        "IofCompleteRequest",
        "KeInitializeEvent",
        "KeWaitForSingleObject",
        "KeSetEvent",
        "KeQueryPerformanceCounter",
        "MmGetSystemRoutineAddress",
        "PsCreateSystemThread",
        "RtlCopyMemory",
        "memcpy",
        "memset",
    ]:
        proj.hook_symbol(name, ret_zero)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("driver")
    ap.add_argument("--max-inst", type=int, default=20000)
    ap.add_argument("--timeout", type=float, default=60.0)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.quiet:
        logging.getLogger("angr").setLevel(logging.ERROR)
        logging.getLogger("cle").setLevel(logging.ERROR)

    import angr

    t0 = time.monotonic()
    proj = angr.Project(args.driver, auto_load_libs=False)
    t_load = time.monotonic() - t0

    entry = proj.entry
    state = proj.factory.blank_state(addr=entry)
    # Kernel-mode-ish layout: map the DRIVER_OBJECT scratch zeroed.
    state.memory.map_region(SCRATCH, 0x10000, 3)  # RWX to avoid page faults
    state.memory.store(SCRATCH, b"\x00" * 0x10000)
    state.regs.rcx = SCRATCH
    state.regs.rsp = 0x7FFFFFF00000
    state.memory.map_region(0x7FFFFFF00000 - 0x1000, 0x2000, 3)
    state.memory.store(0x7FFFFFF00000 - 0x1000, b"\x00" * 0x2000)

    hook_imports(proj)

    t1 = time.monotonic()
    insts = 0
    seen_pcs = set()
    deadline = t1 + args.timeout
    succ = None
    try:
        while insts < args.max_inst and time.monotonic() < deadline:
            succ = state.step(num_inst=1)
            if not succ.successors:
                break
            state = succ.successors[0]
            insts += 1
            seen_pcs.add(state.addr)
            if state.addr == 0:
                break
    except Exception as exc:  # noqa: BLE001 - probe survives engine edges
        print(f"angr engine edge at inst {insts}: {exc}")
    t_run = time.monotonic() - t1

    print(
        f"angr probe: load={t_load:.3f}s run={t_run:.3f}s insts={insts} "
        f"unique_pcs={len(seen_pcs)} entry={entry:#x} steps_per_s="
        f"{insts / t_run:.1f}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
