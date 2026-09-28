#!/usr/bin/env python3
"""Gate J corpus benchmark: aligned angr vs Angryier across real .sys drivers.

Runs the aligned probe environment (see gate_j_probe.py) on a curated set
of Windows kernel drivers from the corpus and reports one comparison table.
The Angryier leg reuses the release `corpus_exec` sweep output so both
engines see the same loader and kernel-model surface.

Workload class (the Gate J thesis): BYOVD driver triage — execute
DriverEntry end-to-end and classify the outcome. angr provides the
symbolic-depth leg (VEX instruction stepping); Angryier is the dual-mode
engine under test. SymQEMU/SymCC-class engines are not deployed here:
they are binary-only concolic engines that require a full Windows guest
for kernel images, which is out of scope for this machine (documented in
the report, not measured).

Usage: python3 scripts/gate_j_corpus.py [--max-inst N] [--timeout S]
       [--driver NAME ...]   # repeatable; default: auto-pick terminated
                             # drivers with <= MAX_ANGRYIER_STEPS steps
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

CORPUS_DIR = (
    Path.home()
    / "Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic"
)
# The second fixture root corpus_exec sweeps (vuln/safe harness fixtures).
FIXTURE_DIR = (
    Path.home() / "Documents/byovd-harness/ghidra_pipeline/fixtures/bin"
)
MAX_INST = 20_000
ANGR_TIMEOUT = 60.0
# Angryier drivers with more steps than this are excluded from the
# default selection (angr would need minutes at ~300 steps/s).
MAX_ANGRYIER_STEPS = 3_000
CORPUS_ROW = re.compile(
    r"^(?P<name>\S+)\s+(?P<class>TERMINATED|BLOCK-NULL|BLOCK-FORM|"
    r"BLOCK-OTHER|BUDGET|LOAD-FAIL)\s+(?P<steps>\d+)\s+steps"
    r"(?: in (?P<seconds>[\d.]+)s)?(?:\s|$)",
    re.MULTILINE,
)


def run_angr(driver: Path, max_inst: int, timeout: float) -> dict[str, object]:
    """Run one driver under angr with the aligned probe environment."""
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
    deadline = started + timeout
    instructions = 0
    pcs: set[int] = set()
    outcome = "terminated"
    try:
        while instructions < max_inst and time.monotonic() < deadline:
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
            outcome = "timeout" if time.monotonic() >= deadline else "inst cap"
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


def run_angryier_sweep() -> dict[str, dict[str, object]]:
    """One release corpus_exec run; returns per-driver rows keyed by name."""
    command = [
        "cargo", "test", "--release", "-p", "angryier-runtime",
        "--features", "xed", "--test", "corpus_exec", "--", "--nocapture",
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    output = result.stdout + "\n" + result.stderr
    if result.returncode != 0:
        tail = "\n".join(output.splitlines()[-20:])
        raise RuntimeError(f"corpus sweep failed\n{tail}")
    rows = {}
    for match in CORPUS_ROW.finditer(output):
        steps = int(match.group("steps"))
        seconds = float(match.group("seconds")) if match.group("seconds") else 0.0
        rows[match.group("name")] = {
            "class": match.group("class"),
            "steps": steps,
            "seconds": seconds,
            "rate": steps / seconds if seconds else 0.0,
        }
    return rows


def markdown(
    drivers: list[str],
    angr_results: dict[str, dict[str, object]],
    angryier_results: dict[str, dict[str, object]],
    max_inst: int,
    timeout: float,
) -> str:
    lines = [
        "| driver | angr insts | angr unique PCs | angr s | angr steps/s |",
        "| angr outcome | Angryier steps | Angryier s | Angryier steps/s |",
        "| Angryier class | raw rate ratio |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name in drivers:
        a = angr_results[name]
        g = angryier_results[name]
        ratio = g["rate"] / a["rate"] if a["rate"] else 0.0
        lines.append(
            f"| {name} | {a['instructions']} | {a['unique_pcs']} | "
            f"{a['seconds']:.3f} | {a['rate']:.1f} | {a['outcome']} | "
            f"{g['steps']} | {g['seconds']:.4f} | {g['rate']:.1f} | "
            f"{g['class']} | {ratio:.0f}× |"
        )
    lines.extend(
        [
            "",
            "Aligned setup: both engines run equal-fidelity kernel models.",
            f"Pool allocators return fresh non-NULL pointers ({POOL:#x} base,",
            "+0x1000 step, zero-backed); frees return 0; IoCreateDevice/",
            "IoCreateDeviceSecure return STATUS_SUCCESS and produce a",
            "DEVICE_OBJECT in pool; RtlGetVersion writes Windows-10 OSVERSIONINFOW",
            "(10.0.19045) through RCX; KeQueryPerformanceCounter returns",
            "0x01000000; DRIVER_OBJECT callbacks return 0; the return slot",
            "points at a terminating stub. angr steps instruction-by-",
            f"instruction (VEX), capped at {max_inst} insts / {timeout:.0f}s.",
            "Angryier runs the release corpus sweep (same loader, kernel",
            "models, exit hook). The rate ratio is raw steps/s across",
            "equal-fidelity kernel models.",
            "",
            "SymQEMU/SymCC-class leg: not measured here — binary-only concolic",
            "engines need a full Windows guest for kernel images; the",
            "comparison leg is documented, not run.",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-inst", type=int, default=MAX_INST)
    parser.add_argument("--timeout", type=float, default=ANGR_TIMEOUT)
    parser.add_argument("--driver", action="append", dest="drivers", default=[])
    parser.add_argument(
        "--corpus-dir", type=Path, default=CORPUS_DIR,
        help="driver corpus directory (default: %(default)s)",
    )
    args = parser.parse_args()
    if not args.corpus_dir.is_dir():
        parser.error(f"corpus dir does not exist: {args.corpus_dir}")

    def resolve(name: str) -> Path:
        for root in (args.corpus_dir, FIXTURE_DIR):
            candidate = root / name
            if candidate.is_file():
                return candidate
        raise FileNotFoundError(name)

    print("running Angryier release corpus sweep...", file=sys.stderr)
    sweep = run_angryier_sweep()
    if args.drivers:
        selected = args.drivers
    else:
        selected = [
            name
            for name, row in sorted(sweep.items())
            if row["class"] == "TERMINATED" and row["steps"] <= MAX_ANGRYIER_STEPS
        ]
        # Keep the table small and representative: shortest first, up to 8.
        selected = sorted(
            selected, key=lambda n: sweep[n]["steps"]
        )[:8]
    if not selected:
        print("no eligible drivers in the sweep", file=sys.stderr)
        return 1

    angr_results: dict[str, dict[str, object]] = {}
    for name in selected:
        try:
            driver = resolve(name)
        except FileNotFoundError:
            print(f"driver missing: {name}", file=sys.stderr)
            return 1
        print(f"angr: {name}...", file=sys.stderr, end=" ", flush=True)
        angr_results[name] = run_angr(driver, args.max_inst, args.timeout)
        print(
            f"{angr_results[name]['instructions']} insts in "
            f"{angr_results[name]['seconds']:.2f}s",
            file=sys.stderr,
        )

    print(markdown(selected, angr_results, sweep, args.max_inst, args.timeout))
    return 0


if __name__ == "__main__":
    sys.exit(main())
