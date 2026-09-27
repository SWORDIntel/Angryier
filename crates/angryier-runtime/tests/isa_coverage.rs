//! Diagnostic: disassemble a driver's entry path, check which XED iclasses
//! map to UNMAPPED_FORM_ID in the form_map, and report the gaps.
#![cfg(feature = "xed")]

use angryier_arch::Decoder;
use angryier_execution::ExecutionEngine;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::Runtime;
use angryier_runtime::form_map;
use angryier_state::RegisterState;
use angryier_types::{SemanticVersion, TargetProfileId};

const DRIVERS: [(&str, &str); 3] = [
    ("TbtBusDrv", "/tmp/tbt_driver.sys"),
    (
        "AMDRyzenMaster",
        "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/AMDRyzenMasterDriver.sys",
    ),
    (
        "GVCIDrv64",
        "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/GVCIDrv64.sys",
    ),
];

/// Read up to `len` concrete bytes at `addr` (symbolic bytes become 0xcc).
fn concrete_at(process: &angryier_runtime::Process, addr: u64, len: usize) -> Option<Vec<u8>> {
    let bytes = process.state.memory.read(addr, len).ok()?;
    Some(
        bytes
            .iter()
            .map(|b| match b {
                ByteValue::Concrete(v) => *v,
                ByteValue::Symbolic(_) => 0xcc,
            })
            .collect(),
    )
}

/// Linear-sweep decode the image region around the entry point and report
/// the form-id histogram plus the unmapped-instruction count.
fn sweep_entry(runtime: &Runtime<impl Decoder>, process: &angryier_runtime::Process) {
    let entry = process.pc().unwrap_or(0);
    let start = entry.saturating_sub(0x2000);
    let mut addr = start;
    let mut counts: std::collections::BTreeMap<u32, u64> = std::collections::BTreeMap::new();
    let mut unmapped: u64 = 0;
    let mut total: u64 = 0;
    for _ in 0..4096 {
        let Some(concrete) = concrete_at(process, addr, 15) else {
            break;
        };
        // Ask XED how long this instruction really is (sweep advances by
        // decoded length so we do not desync inside immediates).
        let Ok(decoded) = runtime.decoder.decode(addr, &concrete) else {
            addr = addr.wrapping_add(1);
            continue;
        };
        let len = usize::from(decoded.length);
        let form = form_map::map_form(&decoded).unwrap_or(form_map::UNMAPPED_FORM_ID);
        *counts.entry(form).or_insert(0) += 1;
        total += 1;
        if form == form_map::UNMAPPED_FORM_ID {
            unmapped += 1;
        }
        addr = addr.wrapping_add(len as u64);
        if len == 0 {
            break;
        }
    }
    let pct = if total > 0 {
        100.0 * unmapped as f64 / total as f64
    } else {
        0.0
    };
    eprintln!("  sweep: {total} instructions, {unmapped} unmapped ({pct:.1}%)");
    if unmapped > 0 {
        // Which mapped forms dominate (top 5) for context.
        let mut ranked: Vec<(u32, u64)> = counts.into_iter().collect();
        ranked.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
        let top: Vec<String> = ranked
            .iter()
            .filter(|(f, _)| *f != form_map::UNMAPPED_FORM_ID)
            .take(5)
            .map(|(f, n)| format!("{f:#06x}×{n}"))
            .collect();
        eprintln!("  top mapped forms: {}", top.join(", "));
    }
}

/// Step-execute from DriverEntry and print the instruction trace with form
/// ids, so the exact first blocker is visible.
fn trace_entry(runtime: &Runtime<impl Decoder>, process: &mut angryier_runtime::Process, max: usize) {
    let mut steps = 0;
    for i in 0..max {
        let pc = process.pc().unwrap_or(0);
        let desc = match concrete_at(process, pc, 15) {
            Some(bytes) => match runtime.decoder.decode(pc, &bytes) {
                Ok(d) => format!(
                    "form={:#06x} len={} bytes={}",
                    d.form_id,
                    d.length,
                    bytes[..usize::from(d.length)]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                Err(_) => "decode-fail".to_string(),
            },
            None => "mem-read-fail".to_string(),
        };
        let rax = process
            .read_register(angryier_arch_intel64::register_id::GPR_BASE)
            .unwrap_or(u64::MAX);
        let rcx = process
            .read_register(angryier_arch_intel64::register_id::GPR_BASE + 1)
            .unwrap_or(u64::MAX);
        let rflags = process
            .read_register(angryier_arch_intel64::register_id::RFLAGS.0)
            .unwrap_or(0);
        match runtime.step(process) {
            Ok(_) => {
                steps += 1;
                let after = process.pc().unwrap_or(0);
                eprintln!(
                    "  [{i:>3}] pc={pc:#018x} -> {after:#018x} rax={rax:#018x} rcx={rcx:#018x} zf={} ({desc})",
                    (rflags >> 6) & 1
                );
            }
            Err(e) => {
                eprintln!("  [{i:>3}] pc={pc:#018x} BLOCKED: {e:?} ({desc})");
                break;
            }
        }
        if process.terminated {
            let rax = process
                .read_register(angryier_arch_intel64::register_id::GPR_BASE)
                .unwrap_or(u64::MAX);
            eprintln!("  [{i:>3}] TERMINATED rax={rax:#x}");
            break;
        }
    }
    eprintln!("  steps={steps} simprocs={}", process.simproc_dispatches);
}

/// Decode and print a byte range (for cookie-init function forensics).
fn dump_range(runtime: &Runtime<impl Decoder>, process: &angryier_runtime::Process, start: u64, len: usize) {
    let Some(concrete) = concrete_at(process, start, len) else {
        eprintln!("  dump_range: unreadable @ {start:#x}");
        return;
    };
    let mut addr = start;
    let mut off = 0usize;
    while off < concrete.len() {
        let Ok(decoded) = runtime.decoder.decode(addr, &concrete[off..]) else {
            break;
        };
        let l = usize::from(decoded.length);
        let bytes_hex: Vec<String> = concrete[off..off + l].iter().map(|b| format!("{b:02x}")).collect();
        let form = form_map::map_form(&decoded).unwrap_or(form_map::UNMAPPED_FORM_ID);
        let tag = if form == form_map::UNMAPPED_FORM_ID {
            "UNMAPPED".to_string()
        } else {
            format!("{form:#06x}")
        };
        eprintln!("  {addr:#018x}: {}  {tag}", bytes_hex.join(" "));
        off += l;
        addr = addr.wrapping_add(l as u64);
    }
}

#[test]
fn security_cookie_forensics() {
    // Decode the __security_init_cookie bodies we know terminate in `int 29h`.
    for (name, path, region) in [
        ("TbtBusDrv", "/tmp/tbt_driver.sys", 0x143adc02cu64),
        (
            "AMDRyzenMaster",
            "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/AMDRyzenMasterDriver.sys",
            0x140030016u64,
        ),
    ] {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let Ok(process) = runtime.load_pe_driver(&bytes) else {
            continue;
        };
        eprintln!("=== {name} cookie-init region @ {region:#x} ===");
        dump_range(&runtime, &process, region, 0x180);
        // .data cookie slot read through the engine (TbtBusDrv: 0x1439f8cc0).
        for (label, addr) in [("cookie", 0x1439f8cc0u64), ("complement", 0x1439f8f00u64)] {
            if let Some(b) = concrete_at(&process, addr, 8) {
                let mut cell = [0u8; 8];
                cell.copy_from_slice(&b[..8]);
                let v = u64::from_le_bytes(cell);
                eprintln!("  .data {label} @ {addr:#x} = {v:#018x}");
            }
        }
    }
}

#[test]
fn rip_relative_ir_forensics() {
    // Lower `mov rax, [rip-0x43373]` (48 8b 05 8d cc fb ff) at 0x143adc02c
    // and dump the IR so the effective-address constant is visible.
    let Ok(bytes) = std::fs::read("/tmp/tbt_driver.sys") else {
        return;
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let Ok(mut process) = runtime.load_pe_driver(&bytes) else {
        return;
    };
    let pc = 0x143adc02cu64;
    let Some(slot) = concrete_at(&process, pc, 15) else {
        eprintln!("unreadable @ {pc:#x}");
        return;
    };
    let raw: Vec<u8> = slot.into_iter().take(7).collect();
    eprintln!(
        "bytes: {}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
    );
    let Ok(decoded) = runtime.decoder.decode(pc, &raw) else {
        eprintln!("decode failed");
        return;
    };
    eprintln!(
        "decoded: form={:#x} len={} operands={:?}",
        decoded.form_id, decoded.length, decoded.operands
    );
    let Ok((block, _)) = runtime.lower_at(&mut process, pc, &decoded) else {
        eprintln!("lower failed");
        return;
    };
    for insn in &block.instructions {
        eprintln!("IR: {:?}", insn.op);
    }
    // Memory at the true target, immediately before execution.
    for (label, addr) in [("cookie slot", 0x1439f8cc0u64), ("insn immediate", 0x143adc03au64)] {
        if let Some(b) = concrete_at(&process, addr, 8) {
            let mut cell = [0u8; 8];
            cell.copy_from_slice(&b[..8]);
            let v = u64::from_le_bytes(cell);
            eprintln!("  mem {label} @ {addr:#x} = {v:#018x}");
        }
    }
    // Execute the block concretely and check rax.
    let Ok((state, _outcome)) = runtime
        .interpreter
        .execute_block(&process.state, &block, angryier_execution::ExecutionMode::Concrete)
    else {
        eprintln!("execute failed");
        return;
    };
    let rax_bytes = state.registers.read(0).unwrap_or_default();
    let rax = if rax_bytes.len() >= 8 {
        let mut cell = [0u8; 8];
        cell.copy_from_slice(&rax_bytes[..8]);
        u64::from_le_bytes(cell)
    } else {
        u64::MAX
    };
    eprintln!("  rax after load = {rax:#018x}");
}

#[test]
fn scan_unmapped_forms() {
    for (name, path) in &DRIVERS {
        let bytes = match std::fs::read(path) {
            Ok(b) => b,
            Err(_) => {
                eprintln!("SKIP {}", name);
                continue;
            }
        };
        eprintln!("=== {} ({} bytes) ===", name, bytes.len());
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        match runtime.load_pe_driver(&bytes) {
            Ok(p) => {
                eprintln!(
                    "  loaded, entry={:#x}, imports={}",
                    p.pc().unwrap_or(0),
                    p.pe_imports().count()
                );
                sweep_entry(&runtime, &p);
                let mut proc = p;
                trace_entry(&runtime, &mut proc, 200);
            }
            Err(e) => eprintln!("  load failed: {:?}", e),
        }
    }
}

#[test]
fn entry_prologue_forms() {
    // Decode the raw first 64 bytes at each driver's entry from the loaded
    // image and report which forms they map to (prologue shape census).
    for (name, path) in &DRIVERS {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let Ok(process) = runtime.load_pe_driver(&bytes) else {
            continue;
        };
        let entry = process.pc().unwrap_or(0);
        let Some(concrete) = concrete_at(&process, entry, 64) else {
            continue;
        };
        eprintln!("=== {name} entry prologue @ {entry:#x} ===");
        let mut addr = entry;
        let mut off = 0usize;
        while off < concrete.len() {
            let Ok(decoded) = runtime.decoder.decode(addr, &concrete[off..]) else {
                break;
            };
            let len = usize::from(decoded.length);
            let bytes_hex: Vec<String> = concrete[off..off + len].iter().map(|b| format!("{b:02x}")).collect();
            let form = form_map::map_form(&decoded).unwrap_or(form_map::UNMAPPED_FORM_ID);
            let tag = if form == form_map::UNMAPPED_FORM_ID {
                "UNMAPPED".to_string()
            } else {
                format!("{form:#06x}")
            };
            eprintln!("  {addr:#018x}: {}  {tag}", bytes_hex.join(" "));
            off += len;
            addr = addr.wrapping_add(len as u64);
        }
    }
}
