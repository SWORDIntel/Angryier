#!/usr/bin/env python3
"""Gate J cross-engine probe: run a real .sys driver through angr and
report wall-time / instruction / unique-PC counts vs Angryier.

Setup for a minimal kernel-driver environment so angr can actually execute:
- the DRIVER_OBJECT scratch region is mapped and zeroed,
- the ntoskrnl/HAL imports (CLE externs) are hooked at their REBASED
  ADDRESSES with concrete returns (pool alloc -> fresh pointer, frees and
  everything else -> 0) — hooking by name fails for many PE imports,
- stepping is instruction-by-instruction (`num_inst=1`).

This is a probe, not the final benchmark: angr is user-mode-focused and the
comparison targets the ENGINE loop mechanics and coverage, not semantic
fidelity. Angryier's equivalent on the same driver runs via:
  cargo test -p angryier-runtime --features xed --test corpus_exec -- --nocapture

Usage: python3 scripts/gate_j_probe.py <driver.sys> [--max-inst N] [--timeout S]
"""

import argparse
import logging
import sys
import time

SCRATCH = 0x700010000000
POOL = 0xFFFF800000000000
POOL_ALLOCS = {
    "ExAllocatePool",
    "ExAllocatePoolWithTag",
    "ExAllocatePool2",
    "ExAllocatePoolWithTagPriority",
    "ExAllocatePoolWithQuotaTag",
}
POOL_FREES = {
    "ExFreePool",
    "ExFreePoolWithTag",
    "ExFreePoolWithQuota",
}


def make_ret_zero():
    def ret_zero(state):
        state.regs.rax = 0
        return None

    return ret_zero


def hook_externs(proj: "angr.Project") -> int:
    """Hook every extern (unresolved import) symbol at its rebased address."""
    pool_next = {"v": POOL}
    hooked = 0

    def make_alloc():
        def alloc(state):
            ptr = pool_next["v"]
            pool_next["v"] += 0x1000
            state.regs.rax = ptr
            return None

        return alloc

    for obj in proj.loader.all_objects:
        for sym in obj.symbols:
            if not sym.is_extern or not sym.name or sym.rebased_addr is None:
                continue
            base = sym.name.rsplit(".", 1)[-1]
            if base in POOL_ALLOCS:
                proj.hook(sym.rebased_addr, make_alloc())
            else:
                proj.hook(sym.rebased_addr, make_ret_zero())
            hooked += 1
    return hooked


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

    hooked = hook_externs(proj)
    # Populate the DRIVER_OBJECT MajorFunction table (offset 0x70, 28
    # slots) with a hooked ret-zero stub — Angryier's loader fills the
    # same table with its universal callback; a zeroed table makes the
    # driver call NULL.
    STUB = 0x700020000000
    proj.hook(STUB, make_ret_zero())
    for i in range(28):
        state.memory.store(SCRATCH + 0x70 + 8 * i, STUB.to_bytes(8, "little"))
    # Seed DriverEntry's return address with a terminating stub: the
    # driver's final `ret` must end the run, not jump to address 0
    # (Angryier's loader points the same slot at its exit hook).
    EXIT = 0x700030000000
    proj.hook(EXIT, angr.SIM_PROCEDURES["stubs"]["PathTerminator"]())
    state.memory.store(state.regs.rsp, EXIT.to_bytes(8, "little"))

    t1 = time.monotonic()
    insts = 0
    seen_pcs = set()
    last_pcs = []
    deadline = t1 + args.timeout
    try:
        while insts < args.max_inst and time.monotonic() < deadline:
            prev = state.addr
            succ = state.step(num_inst=1)
            if not succ.successors:
                break
            state = succ.successors[0]
            insts += 1
            seen_pcs.add(state.addr)
            last_pcs.append(prev)
            last_pcs = last_pcs[-10:]
            if state.addr == 0:
                break
    except Exception as exc:  # noqa: BLE001 - probe survives engine edges
        print(f"angr engine edge at inst {insts}: {exc}")
    t_run = time.monotonic() - t1

    print(
        f"angr probe: load={t_load:.3f}s run={t_run:.3f}s insts={insts} "
        f"unique_pcs={len(seen_pcs)} entry={entry:#x} hooks={hooked} "
        f"steps_per_s={insts / t_run:.1f} last_pc={state.addr:#x}"
    )
    print("last pcs:", " ".join(f"{p:#x}" for p in last_pcs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
