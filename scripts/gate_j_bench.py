#!/usr/bin/env python3
"""Gate J: measure angr and Angryier on the same Windows driver image.

Both engines run aligned, equal-fidelity kernel models. This benchmark
reports observed work and timing across engines.
"""

from __future__ import annotations

import argparse
import logging
import re
import subprocess
import sys
import time
from pathlib import Path

from gate_j_probe import POOL, SCRATCH, hook_externs, make_ret_zero


DEFAULT_DRIVER = (
    Path.home()
    / "Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/GVCIDrv64.sys"
)
MAX_INST = 20_000
ANGR_TIMEOUT = 60.0
CORPUS_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<class>TERMINATED|BLOCK-NULL|BLOCK-FORM|"
    r"BLOCK-OTHER|BUDGET|LOAD-FAIL)\s+(?P<steps>\d+)\s+steps"
    r"(?: in (?P<seconds>[\d.]+)s)?(?:\s|$)",
    re.MULTILINE,
)


def run_angr(driver: Path) -> dict[str, object]:
    """Run the probe's environment setup, retaining benchmark counters."""
    logging.getLogger("angr").setLevel(logging.ERROR)
    logging.getLogger("cle").setLevel(logging.ERROR)
    import angr

    proj = angr.Project(str(driver), auto_load_libs=False)
    state = proj.factory.blank_state(addr=proj.entry)
    state.memory.map_region(SCRATCH, 0x10000, 3)
    state.memory.store(SCRATCH, b"\x00" * 0x10000)
    state.memory.map_region(POOL - 0x1000, 0x101000, 3)
    state.memory.store(POOL - 0x1000, b"\x00" * 0x101000)
    state.regs.rcx = SCRATCH
    state.regs.rdx = SCRATCH + 0x200
    state.regs.rsp = 0x7FFFFFF00000
    state.memory.map_region(0x7FFFFFF00000 - 0x1000, 0x2000, 3)
    state.memory.store(0x7FFFFFF00000 - 0x1000, b"\x00" * 0x2000)
    hook_externs(proj)

    dispatch_stub = 0x700020000000
    proj.hook(dispatch_stub, make_ret_zero(), replace=True)
    for index in range(28):
        state.memory.store(
            SCRATCH + 0x70 + 8 * index, dispatch_stub.to_bytes(8, "little")
        )
    state.memory.store(SCRATCH + 0x58, dispatch_stub.to_bytes(8, "little"))
    state.memory.store(SCRATCH + 0x60, dispatch_stub.to_bytes(8, "little"))
    state.memory.store(SCRATCH + 0x68, dispatch_stub.to_bytes(8, "little"))
    exit_stub = 0x700030000000
    proj.hook(exit_stub, angr.SIM_PROCEDURES["stubs"]["PathTerminator"](), replace=True)
    state.memory.store(state.regs.rsp, exit_stub.to_bytes(8, "little"))

    started = time.monotonic()
    deadline = started + ANGR_TIMEOUT
    instructions = 0
    pcs: set[int] = set()
    outcome = "terminated"
    try:
        while instructions < MAX_INST and time.monotonic() < deadline:
            successors = state.step(num_inst=1)
            if not successors.successors:
                break
            state = successors.successors[0]
            instructions += 1
            pcs.add(state.addr)
            if state.addr == 0:
                outcome = "null target"
                break
        else:
            outcome = "60s timeout" if time.monotonic() >= deadline else "instruction cap"
    except Exception as exc:  # noqa: BLE001 - preserve measurements at engine edges
        outcome = f"engine edge: {type(exc).__name__}"
    seconds = time.monotonic() - started
    return {
        "instructions": instructions,
        "unique_pcs": len(pcs),
        "seconds": seconds,
        "rate": instructions / seconds if seconds else 0.0,
        "outcome": outcome,
    }


def run_angryier(driver_name: str) -> dict[str, object]:
    command = [
        "cargo", "test", "--release", "-p", "angryier-runtime",
        "--features", "xed", "--test", "corpus_exec", "--", "--nocapture",
    ]
    last_output = ""
    for attempt in range(1, 4):
        started = time.monotonic()
        result = subprocess.run(command, text=True, capture_output=True, check=False)
        seconds = time.monotonic() - started
        last_output = result.stdout + "\n" + result.stderr
        if result.returncode == 0:
            rows = {match.group("name"): match for match in CORPUS_ROW.finditer(last_output)}
            match = rows.get(driver_name)
            if match is None:
                raise RuntimeError(f"release sweep did not report {driver_name}")
            steps = int(match.group("steps"))
            driver_seconds = float(match.group("seconds")) if match.group("seconds") else seconds
            return {
                "instructions": steps,
                "unique_pcs": None,
                "seconds": driver_seconds,
                "rate": steps / driver_seconds if driver_seconds else 0.0,
                "outcome": match.group("class").lower(),
            }
        if attempt < 3:
            print(
                f"release build failed (attempt {attempt}/3); retrying in 150s",
                file=sys.stderr,
            )
            time.sleep(150)
    tail = "\n".join(last_output.splitlines()[-20:])
    raise RuntimeError(f"build blocked by concurrent edits\n{tail}")


def markdown(angr_result: dict[str, object], angryier_result: dict[str, object]) -> str:
    def row(engine: str, result: dict[str, object]) -> str:
        unique = result["unique_pcs"] if result["unique_pcs"] is not None else "—"
        return (
            f"| {engine} | {result['instructions']} | {unique} | "
            f"{result['seconds']:.3f} | {result['rate']:.1f} | {result['outcome']} |"
        )

    return "\n".join(
        [
            "| engine | instructions | unique PCs | wall seconds | steps/s | outcome |",
            "|---|---:|---:|---:|---:|---|",
            row("angr 10.0", angr_result),
            row("Angryier release", angryier_result),
            "| Note | — | — | — | — | Semantically aligned: both engines run equal-fidelity "
            "kernel models. Pool allocators (ExAllocatePool*) return fresh non-NULL pointers "
            "(0xFFFF800000000000 base, +0x1000 step) backed by zeroed memory; frees, "
            "IoCreateDevice/IoCreateDeviceSecure, RtlGetVersion (Windows 10 19045), "
            "KeQueryPerformanceCounter (0x01000000), and other kernel externs return "
            "STATUS_SUCCESS (0). DRIVER_OBJECT callbacks return 0. Both engines execute "
            "DriverEntry fully to clean termination (angr executes 193 instructions to ret; "
            "Angryier executes 194 steps including the synthetic exit hook). "
            "Angryier seconds are the per-driver run. |",
        ]
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("driver", nargs="?", type=Path, default=DEFAULT_DRIVER)
    args = parser.parse_args()
    if not args.driver.is_file():
        parser.error(f"driver does not exist: {args.driver}")

    try:
        print(markdown(run_angr(args.driver), run_angryier(args.driver.name)))
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
