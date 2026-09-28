#!/usr/bin/env python3
"""Gate J cross-engine probe: run a real .sys driver through angr and
report wall-time / instruction / unique-PC counts vs Angryier.

Setup for an aligned kernel-driver environment so angr executes with equal fidelity
to Angryier's kernel models:
- the DRIVER_OBJECT scratch region is mapped and zeroed,
- ntoskrnl/HAL imports (CLE externs) are hooked at their REBASED ADDRESSES
  with matching SimProcedure behavior:
    * RtlGetVersion: writes Windows-10 version info (10.0.19045, NT=2) through RCX
    * IoCreateDevice / IoCreateDeviceSecure: creates DEVICE_OBJECT in pool and writes *pptr
    * KeQueryPerformanceCounter: deterministic fixed value (0x01000000)
    * ExAllocatePool*: fresh zero-backed pool pointer
    * ExFreePool*: return 0
    * other kernel externs: return STATUS_SUCCESS (0)
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
    "ExAllocatePoolWithQuota",
}
POOL_FREES = {
    "ExFreePool",
    "ExFreePoolWithTag",
    "ExFreePoolWithQuota",
}
CREATE_DEVICE_NAMES = {"IoCreateDevice"}
CREATE_DEVICE_SECURE_NAMES = {"IoCreateDeviceSecure"}
GET_VERSION_NAMES = {"RtlGetVersion"}
QUERY_PERF_NAMES = {"KeQueryPerformanceCounter"}
ATTACH_DEVICE_NAMES = {"IoAttachDevice"}
RESOLVE_NAMES = {"MmGetSystemRoutineAddress"}
INIT_UNICODE_NAMES = {"RtlInitUnicodeString"}
CREATE_THREAD_NAMES = {"PsCreateSystemThread"}
BUILD_IRP_NAMES = {"IoBuildDeviceIoControlRequest"}
GET_DEVICE_POINTER_NAMES = {"IoGetDeviceObjectPointer"}
ETW_REGISTER_NAMES = {"EtwRegister"}
ETW_PROVIDER_NAMES = {"EtwProviderEnabled"}
ZW_OPEN_KEY_NAMES = {"ZwOpenKey"}
ZW_QUERY_VALUE_NAMES = {"ZwQueryValueKey"}
INIT_EVENT_NAMES = {"KeInitializeEvent"}
INIT_MUTEX_NAMES = {"KeInitializeMutex"}
QUERY_REGISTRY_NAMES = {"RtlQueryRegistryValues"}


def make_ret_zero():
    import angr

    class RetZero(angr.SimProcedure):
        def run(self):
            return 0

    return RetZero()


def hook_externs(proj: "angr.Project") -> int:
    """Hook every extern (unresolved import) symbol at its rebased address."""
    import angr

    pool_next = {"v": POOL}
    hooked = 0

    def ensure_mapped(state, addr, size=0x1000):
        try:
            state.memory.load(addr, 8)
        except Exception:
            state.memory.map_region(addr, size, 3)
            state.memory.store(addr, b"\x00" * size)

    class AllocProc(angr.SimProcedure):
        def run(self):
            ptr = pool_next["v"]
            pool_next["v"] += 0x1000
            ensure_mapped(self.state, ptr, 0x1000)
            return ptr

    class CreateDeviceProc(angr.SimProcedure):
        def __init__(self, is_secure=False):
            super().__init__()
            self.is_secure = is_secure

        def run(self):
            device = pool_next["v"]
            pool_next["v"] += 0x1000
            extension = pool_next["v"]
            pool_next["v"] += 0x1000
            ensure_mapped(self.state, device, 0x1000)
            ensure_mapped(self.state, extension, 0x1000)

            # DEVICE_OBJECT header: Type (u16 = 15) | Size (u16 = 0x1030)
            type_size = (0x1030 << 32) | 15
            self.state.memory.store(device, type_size.to_bytes(8, "little"))
            self.state.memory.store(device + 0x08, extension.to_bytes(8, "little"))
            device_type = self.state.solver.eval(self.state.regs.r9) & 0xFFFFFFFF
            self.state.memory.store(device + 0x1C, device_type.to_bytes(4, "little"))
            self.state.memory.store(device + 0x20, (1).to_bytes(4, "little"))

            # Extension back-pointer to driver object (RCX)
            driver_obj = self.state.solver.eval(self.state.regs.rcx)
            self.state.memory.store(extension, driver_obj.to_bytes(8, "little"))

            # OUT: *pptrDeviceObject = device
            # IoCreateDevice: 7th arg at [rsp + 0x38]
            # IoCreateDeviceSecure: 9th arg at [rsp + 0x48]
            rsp = self.state.solver.eval(self.state.regs.rsp)
            offset = 0x48 if self.is_secure else 0x38
            try:
                raw_pptr = self.state.memory.load(rsp + offset, 8, endness="Iend_LE")
                pptr = self.state.solver.eval(raw_pptr)
                if pptr != 0:
                    self.state.memory.store(pptr, device.to_bytes(8, "little"))
            except Exception:
                pass
            return 0

    class GetVersionProc(angr.SimProcedure):
        def run(self):
            rcx = self.state.solver.eval(self.state.regs.rcx)
            if rcx != 0:
                try:
                    raw = self.state.memory.load(rcx, 4, endness="Iend_LE")
                    size = self.state.solver.eval(raw)
                except Exception:
                    size = 0x90
                if size == 0:
                    size = 0x90
                try:
                    self.state.memory.store(rcx, size.to_bytes(4, "little"))
                    self.state.memory.store(rcx + 4, (10).to_bytes(4, "little"))      # dwMajorVersion
                    self.state.memory.store(rcx + 8, (0).to_bytes(4, "little"))       # dwMinorVersion
                    self.state.memory.store(rcx + 12, (19045).to_bytes(4, "little"))  # dwBuildNumber
                    self.state.memory.store(rcx + 16, (2).to_bytes(4, "little"))      # VER_PLATFORM_WIN32_NT
                except Exception:
                    pass
            return 0

    class QueryPerfProc(angr.SimProcedure):
        def run(self):
            rcx = self.state.solver.eval(self.state.regs.rcx)
            if rcx != 0:
                try:
                    self.state.memory.store(rcx, (10_000_000).to_bytes(8, "little"))
                except Exception:
                    pass
            return 0x0000000001000000

    class InitUnicodeStringProc(angr.SimProcedure):
        def run(self):
            dest = self.state.solver.eval(self.state.regs.rcx)
            src = self.state.solver.eval(self.state.regs.rdx)
            if dest != 0 and src != 0:
                length = 0
                addr = src
                try:
                    while length < 510:
                        raw = self.state.memory.load(addr, 2, endness="Iend_LE")
                        ch = self.state.solver.eval(raw)
                        if ch == 0:
                            break
                        length += 2
                        addr += 2
                    self.state.memory.store(dest, length.to_bytes(2, "little"))
                    self.state.memory.store(dest + 2, (length + 2).to_bytes(2, "little"))
                    self.state.memory.store(dest + 8, src.to_bytes(8, "little"))
                except Exception:
                    pass
            return 0

    class AttachDeviceProc(angr.SimProcedure):
        def run(self):
            attached = pool_next["v"]
            pool_next["v"] += 0x1000
            ensure_mapped(self.state, attached, 0x1000)
            out_ptr = self.state.solver.eval(self.state.regs.r8)
            if out_ptr != 0:
                try:
                    self.state.memory.store(out_ptr, attached.to_bytes(8, "little"))
                except Exception:
                    pass
            return 0

    class GetDeviceObjectPointerProc(angr.SimProcedure):
        def run(self):
            device = pool_next["v"]
            file_obj = pool_next["v"] + 0x1000
            driver = pool_next["v"] + 0x2000
            pool_next["v"] += 0x3000
            for addr in (device, file_obj, driver):
                ensure_mapped(self.state, addr, 0x1000)
            type_size = (0x1030 << 32) | 15
            self.state.memory.store(device, type_size.to_bytes(8, "little"))
            self.state.memory.store(device + 0x08, driver.to_bytes(8, "little"))
            stub = 0x700020000000
            for i in range(28):
                self.state.memory.store(device + 0x70 + 8 * i, stub.to_bytes(8, "little"))
            file_type_size = (0x98 << 32) | 5
            self.state.memory.store(file_obj, file_type_size.to_bytes(8, "little"))
            self.state.memory.store(file_obj + 0x08, device.to_bytes(8, "little"))
            p_file = self.state.solver.eval(self.state.regs.r8)
            p_device = self.state.solver.eval(self.state.regs.r9)
            if p_file != 0:
                try:
                    self.state.memory.store(p_file, file_obj.to_bytes(8, "little"))
                except Exception:
                    pass
            if p_device != 0:
                try:
                    self.state.memory.store(p_device, device.to_bytes(8, "little"))
                except Exception:
                    pass
            return 0

    class ResolveRoutineProc(angr.SimProcedure):
        def run(self):
            return 0x700020000000

    class CreateThreadProc(angr.SimProcedure):
        def run(self):
            return 0xFFFFFFFF00000042

    class BuildIrpProc(angr.SimProcedure):
        def run(self):
            irp = pool_next["v"]
            pool_next["v"] += 0x1000
            ensure_mapped(self.state, irp, 0x1000)
            type_size = (0x100 << 32) | 6
            self.state.memory.store(irp, type_size.to_bytes(8, "little"))
            self.state.memory.store(irp + 0x53, (1).to_bytes(1, "little"))
            self.state.memory.store(irp + 0x54, (1).to_bytes(1, "little"))
            return irp

    class EtwRegisterProc(angr.SimProcedure):
        def run(self):
            handle = pool_next["v"]
            pool_next["v"] += 0x1000
            p_handle = self.state.solver.eval(self.state.regs.r9)
            if p_handle != 0:
                try:
                    self.state.memory.store(p_handle, handle.to_bytes(8, "little"))
                except Exception:
                    pass
            return 0

    class ZwOpenKeyProc(angr.SimProcedure):
        def run(self):
            handle = pool_next["v"]
            pool_next["v"] += 0x1000
            p_handle = self.state.solver.eval(self.state.regs.rcx)
            if p_handle != 0:
                try:
                    self.state.memory.store(p_handle, handle.to_bytes(8, "little"))
                except Exception:
                    pass
            return 0

    class ZwQueryValueKeyProc(angr.SimProcedure):
        def run(self):
            info = self.state.solver.eval(self.state.regs.r9)
            if info != 0:
                try:
                    self.state.memory.store(info, (0x100).to_bytes(4, "little"))
                except Exception:
                    pass
            rsp = self.state.solver.eval(self.state.regs.rsp)
            try:
                raw_len = self.state.memory.load(rsp + 0x30, 8, endness="Iend_LE")
                p_len = self.state.solver.eval(raw_len)
                if p_len != 0:
                    self.state.memory.store(p_len, (4).to_bytes(4, "little"))
            except Exception:
                pass
            return 0

    class InitEventProc(angr.SimProcedure):
        def run(self):
            event = self.state.solver.eval(self.state.regs.rcx)
            signal = self.state.solver.eval(self.state.regs.r8) & 0xFFFFFFFF
            if event != 0:
                try:
                    self.state.memory.store(event, (0).to_bytes(2, "little"))
                    self.state.memory.store(event + 4, signal.to_bytes(4, "little"))
                except Exception:
                    pass
            return 0

    class InitMutexProc(angr.SimProcedure):
        def run(self):
            mutex = self.state.solver.eval(self.state.regs.rcx)
            if mutex != 0:
                try:
                    self.state.memory.store(mutex, (1).to_bytes(2, "little"))
                    self.state.memory.store(mutex + 4, (1).to_bytes(4, "little"))
                except Exception:
                    pass
            return 0

    for obj in proj.loader.all_objects:
        for sym in obj.symbols:
            if not sym.is_extern or not sym.name or sym.rebased_addr is None:
                continue
            base = sym.name.rsplit(".", 1)[-1]
            if base in POOL_ALLOCS:
                proj.hook(sym.rebased_addr, AllocProc(), replace=True)
            elif base in CREATE_DEVICE_NAMES:
                proj.hook(sym.rebased_addr, CreateDeviceProc(is_secure=False), replace=True)
            elif base in CREATE_DEVICE_SECURE_NAMES:
                proj.hook(sym.rebased_addr, CreateDeviceProc(is_secure=True), replace=True)
            elif base in GET_VERSION_NAMES:
                proj.hook(sym.rebased_addr, GetVersionProc(), replace=True)
            elif base in QUERY_PERF_NAMES:
                proj.hook(sym.rebased_addr, QueryPerfProc(), replace=True)
            elif base in INIT_UNICODE_NAMES:
                proj.hook(sym.rebased_addr, InitUnicodeStringProc(), replace=True)
            elif base in ATTACH_DEVICE_NAMES:
                proj.hook(sym.rebased_addr, AttachDeviceProc(), replace=True)
            elif base in RESOLVE_NAMES:
                proj.hook(sym.rebased_addr, ResolveRoutineProc(), replace=True)
            elif base in CREATE_THREAD_NAMES:
                proj.hook(sym.rebased_addr, CreateThreadProc(), replace=True)
            elif base in BUILD_IRP_NAMES:
                proj.hook(sym.rebased_addr, BuildIrpProc(), replace=True)
            elif base in GET_DEVICE_POINTER_NAMES:
                proj.hook(sym.rebased_addr, GetDeviceObjectPointerProc(), replace=True)
            elif base in ETW_REGISTER_NAMES:
                proj.hook(sym.rebased_addr, EtwRegisterProc(), replace=True)
            elif base in ETW_PROVIDER_NAMES:
                proj.hook(sym.rebased_addr, make_ret_zero(), replace=True)
            elif base in ZW_OPEN_KEY_NAMES:
                proj.hook(sym.rebased_addr, ZwOpenKeyProc(), replace=True)
            elif base in ZW_QUERY_VALUE_NAMES:
                proj.hook(sym.rebased_addr, ZwQueryValueKeyProc(), replace=True)
            elif base in INIT_EVENT_NAMES:
                proj.hook(sym.rebased_addr, InitEventProc(), replace=True)
            elif base in INIT_MUTEX_NAMES:
                proj.hook(sym.rebased_addr, InitMutexProc(), replace=True)
            elif base in QUERY_REGISTRY_NAMES:
                proj.hook(sym.rebased_addr, make_ret_zero(), replace=True)
            else:
                proj.hook(sym.rebased_addr, make_ret_zero(), replace=True)
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
    state.memory.map_region(POOL - 0x1000, 0x101000, 3)
    state.memory.store(POOL - 0x1000, b"\x00" * 0x101000)
    state.regs.rcx = SCRATCH
    state.regs.rdx = SCRATCH + 0x200
    state.regs.rsp = 0x7FFFFFF00000
    state.memory.map_region(0x7FFFFFF00000 - 0x1000, 0x2000, 3)
    state.memory.store(0x7FFFFFF00000 - 0x1000, b"\x00" * 0x2000)

    hooked = hook_externs(proj)
    # Populate the DRIVER_OBJECT MajorFunction table (offset 0x70, 28
    # slots) with a hooked ret-zero stub — Angryier's loader fills the
    # same table with its universal callback; a zeroed table makes the
    # driver call NULL.
    STUB = 0x700020000000
    proj.hook(STUB, make_ret_zero(), replace=True)
    for i in range(28):
        state.memory.store(SCRATCH + 0x70 + 8 * i, STUB.to_bytes(8, "little"))
    state.memory.store(SCRATCH + 0x58, STUB.to_bytes(8, "little"))
    state.memory.store(SCRATCH + 0x60, STUB.to_bytes(8, "little"))
    state.memory.store(SCRATCH + 0x68, STUB.to_bytes(8, "little"))
    # Seed DriverEntry's return address with a terminating stub: the
    # driver's final `ret` must end the run, not jump to address 0
    # (Angryier's loader points the same slot at its exit hook).
    EXIT = 0x700030000000
    proj.hook(EXIT, angr.SIM_PROCEDURES["stubs"]["PathTerminator"](), replace=True)
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
