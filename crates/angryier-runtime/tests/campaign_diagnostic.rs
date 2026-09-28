#![cfg(feature = "xed")]
#![allow(clippy::manual_range_contains, clippy::chunks_exact_to_as_chunks)]

use std::collections::BTreeMap;
use std::collections::VecDeque;

use angryier_arch::{AccessKind, Decoder, MemoryBase, MemoryIndex, OperandKind};
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::{Runtime, StepOutcome};
use angryier_types::{SemanticVersion, TargetProfileId};

#[test]
fn trace_amd_probe_loop() -> Result<(), Box<dyn std::error::Error>> {
    let path =
        "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/AMDRyzenMasterDriver.sys";
    let image = std::fs::read(path)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker)?;

    let mut pcs: BTreeMap<u64, u64> = BTreeMap::new();
    let mut edges: BTreeMap<(u64, u64), u64> = BTreeMap::new();
    let mut port_events: BTreeMap<(u64, u16, u32, u32, bool), u64> = BTreeMap::new();
    let mut prior_pc = None;
    let mut printed_ports = 0usize;
    eprintln!("AMD entry={:#x}", process.pc()?);
    for step in 0..100_000u64 {
        let pc = process.pc()?;
        *pcs.entry(pc).or_default() += 1;
        if let Some(from) = prior_pc {
            *edges.entry((from, pc)).or_default() += 1;
        }
        prior_pc = Some(pc);

        let raw = process
            .state
            .memory
            .read(pc, 15)?
            .iter()
            .map(|b| match b {
                ByteValue::Concrete(v) => *v,
                ByteValue::Symbolic(_) => 0xcc,
            })
            .collect::<Vec<_>>();
        let decoded = runtime.decoder.decode(pc, &raw)?;
        let rax_before = process.read_register(angryier_arch_intel64::register_id::GPR_BASE)?;
        let rdx = process.read_register(angryier_arch_intel64::register_id::GPR_BASE + 2)?;
        let latch_before = process.pci_config_address;
        use angryier_semantics_intel64::forms;
        let is_in = matches!(
            decoded.form_id,
            forms::IN_AL_DX
                | forms::IN_AX_DX
                | forms::IN_EAX_DX
                | forms::IN_AL_IMM8
                | forms::IN_AX_IMM8
                | forms::IN_EAX_IMM8
        );
        let is_out = matches!(
            decoded.form_id,
            forms::OUT_DX_AL
                | forms::OUT_DX_AX
                | forms::OUT_DX_EAX
                | forms::OUT_IMM8_AL
                | forms::OUT_IMM8_AX
                | forms::OUT_IMM8_EAX
        );

        let outcome = runtime.step(&mut process)?;
        if is_in || is_out {
            let port = rdx as u16;
            let rax_after = process.read_register(angryier_arch_intel64::register_id::GPR_BASE)? as u32;
            let value = if is_in { rax_after } else { rax_before as u32 };
            let latch = if is_out {
                process.pci_config_address
            } else {
                latch_before
            };
            *port_events.entry((pc, port, latch, value, is_in)).or_default() += 1;
            if printed_ports < 24 || (step >= 3500 && step < 4700) {
                eprintln!(
                    "PORT step={step:6} pc={pc:#x} {} dx={port:#06x} latch={latch:#010x} eax={value:#010x}",
                    if is_in { "IN " } else { "OUT" }
                );
                printed_ports += 1;
            }
        }
        if let StepOutcome::SimProcedure { address, name } = outcome {
            let import = process
                .pe_import_stubs
                .get(&address)
                .map(|(_, n)| n.as_str())
                .unwrap_or("?");
            eprintln!(
                "API step={step:6} at={address:#x} model={name} import={import} rax={:#x}",
                process.read_register(angryier_arch_intel64::register_id::GPR_BASE)?
            );
        }
        if process.terminated {
            eprintln!("AMD TERMINATED after {} steps", step + 1);
            break;
        }
    }

    let mut hot = pcs.into_iter().collect::<Vec<_>>();
    hot.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    eprintln!(
        "AMD end terminated={} steps={} pc={:#x} latch={:#010x}",
        process.terminated,
        process.step_count,
        process.pc()?,
        process.pci_config_address
    );
    eprintln!("HOT PCS:");
    for (pc, count) in hot.into_iter().take(40) {
        eprintln!("  {pc:#x} {count}");
    }
    let mut hot_edges = edges.iter().collect::<Vec<_>>();
    hot_edges.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
    eprintln!("HOT EDGES:");
    for ((from, to), count) in hot_edges.into_iter().take(40) {
        eprintln!("  {from:#x} -> {to:#x} {count}");
    }
    eprintln!("PORT RETURN EDGES:");
    for ((from, to), count) in &edges {
        if *from == 0x140004ead || *from == 0x1400051d3 {
            eprintln!("  {from:#x} -> {to:#x} {count}");
        }
    }
    let mut ports = port_events.into_iter().collect::<Vec<_>>();
    ports.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    eprintln!("PORT GROUPS:");
    for ((pc, port, latch, value, is_in), count) in ports.into_iter().take(80) {
        eprintln!(
            "  pc={pc:#x} {} port={port:#06x} latch={latch:#010x} value={value:#010x} count={count}",
            if is_in { "IN " } else { "OUT" }
        );
    }
    Ok(())
}

#[test]
fn run_amd_to_completion() -> Result<(), Box<dyn std::error::Error>> {
    let path =
        "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/AMDRyzenMasterDriver.sys";
    let image = std::fs::read(path)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker)?;
    let start = std::time::Instant::now();
    for _ in 0..12_000_000u64 {
        if let Err(error) = runtime.step(&mut process) {
            eprintln!(
                "AMD BLOCKED steps={} pc={:#x} error={error:?}",
                process.step_count,
                process.pc()?
            );
            return Ok(());
        }
        if process.terminated {
            eprintln!(
                "AMD COMPLETE steps={} elapsed={:?}",
                process.step_count,
                start.elapsed()
            );
            return Ok(());
        }
    }
    eprintln!(
        "AMD BUDGET steps={} pc={:#x} elapsed={:?}",
        process.step_count,
        process.pc()?,
        start.elapsed()
    );
    Ok(())
}

#[test]
fn run_amd_with_old_write_only_cf8_model() -> Result<(), Box<dyn std::error::Error>> {
    let path =
        "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/AMDRyzenMasterDriver.sys";
    let image = std::fs::read(path)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker)?;
    let start = std::time::Instant::now();
    for _ in 0..12_000_000u64 {
        let pc = process.pc()?;
        let old_cf8_read = pc == 0x140004ea2
            && process.read_register(angryier_arch_intel64::register_id::GPR_BASE + 2)? as u16 == 0xCF8;
        if let Err(error) = runtime.step(&mut process) {
            eprintln!(
                "AMD OLD BLOCKED steps={} pc={:#x} error={error:?}",
                process.step_count,
                process.pc()?
            );
            return Ok(());
        }
        if old_cf8_read {
            process.write_register(angryier_arch_intel64::register_id::GPR_BASE, 0)?;
        }
        if process.terminated {
            eprintln!(
                "AMD OLD COMPLETE steps={} elapsed={:?}",
                process.step_count,
                start.elapsed()
            );
            return Ok(());
        }
    }
    eprintln!(
        "AMD OLD BUDGET steps={} pc={:#x} elapsed={:?}",
        process.step_count,
        process.pc()?,
        start.elapsed()
    );
    Ok(())
}

fn concrete(bytes: &[ByteValue]) -> Vec<u8> {
    bytes
        .iter()
        .map(|b| match b {
            ByteValue::Concrete(v) => *v,
            ByteValue::Symbolic(_) => 0xcc,
        })
        .collect()
}

fn qword(process: &angryier_runtime::Process, address: u64) -> Option<u64> {
    let bytes = concrete(&process.state.memory.read(address, 8).ok()?);
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

fn unicode_at(process: &angryier_runtime::Process, address: u64) -> String {
    let Some(length_bytes) = process.state.memory.read(address, 2).ok().map(|v| concrete(&v)) else {
        return String::new();
    };
    let Ok(length) = <[u8; 2]>::try_from(length_bytes) else {
        return String::new();
    };
    let Some(buffer) = qword(process, address + 8) else {
        return String::new();
    };
    let Some(raw) = process
        .state
        .memory
        .read(buffer, usize::from(u16::from_le_bytes(length)))
        .ok()
        .map(|v| concrete(&v))
    else {
        return String::new();
    };
    let words = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&words)
}

fn wide_at(process: &angryier_runtime::Process, address: u64) -> String {
    let mut words = Vec::new();
    for i in 0..256u64 {
        let Some(raw) = process.state.memory.read(address + i * 2, 2).ok().map(|v| concrete(&v)) else {
            break;
        };
        let Ok(bytes) = <[u8; 2]>::try_from(raw) else {
            break;
        };
        let word = u16::from_le_bytes(bytes);
        if word == 0 {
            break;
        }
        words.push(word);
    }
    String::from_utf16_lossy(&words)
}

#[test]
fn trace_tbt_indirect_target() -> Result<(), Box<dyn std::error::Error>> {
    let image = match std::fs::read("/tmp/tbt_driver.sys") {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker)?;
    const TEXT_LO: u64 = 0x140001000;
    const TEXT_HI: u64 = 0x14054d4ce;
    const TARGET: u64 = 0x1404a07e8;
    const GUARD_IAT: u64 = 0x1409e07e8;
    let mut ring = VecDeque::new();
    let mut target = concrete(&process.state.memory.read(TARGET, 16)?);
    let mut guard = concrete(&process.state.memory.read(GUARD_IAT, 8)?);
    eprintln!(
        "TBT entry={:#x} target={target:02x?} guard_iat={guard:02x?}",
        process.pc()?
    );

    for step in 0..3_000u64 {
        let pc = process.pc()?;
        let raw = concrete(&process.state.memory.read(pc, 15)?);
        let decoded = runtime.decoder.decode(pc, &raw)?;
        let regs = (0..8u32)
            .map(|i| {
                process
                    .read_register(angryier_arch_intel64::register_id::GPR_BASE + i)
                    .unwrap_or(0)
            })
            .collect::<Vec<_>>();
        let bytes = raw[..usize::from(decoded.length)].to_vec();
        ring.push_back(format!(
            "step={step} pc={pc:#x} bytes={bytes:02x?} form={} gpr={regs:016x?} ops={:?}",
            decoded.form_id, decoded.operands
        ));
        if ring.len() > 80 {
            ring.pop_front();
        }
        if let Some((_, import)) = process.pe_import_stubs.get(&pc) {
            let rcx = regs[1];
            let rdx = regs[2];
            match import.as_str() {
                "RtlInitUnicodeString" => eprintln!(
                    "TBT STRING step={step} RtlInitUnicodeString {:?}",
                    wide_at(&process, rdx)
                ),
                "ZwLoadDriver" | "IoGetDeviceObjectPointer" => {
                    eprintln!("TBT STRING step={step} {import} {:?}", unicode_at(&process, rcx))
                }
                _ => {}
            }
        }

        let mut text_writes = Vec::new();
        for operand in &decoded.operands {
            if !matches!(operand.access, AccessKind::Write | AccessKind::ReadWrite) {
                continue;
            }
            let OperandKind::Memory(mem) = operand.kind else {
                continue;
            };
            let base = match mem.base {
                Some(MemoryBase::Register(view)) => process.read_register(view.parent.0).ok(),
                Some(MemoryBase::InstructionPointer { .. }) => Some(pc),
                None => Some(0),
            };
            let index = match mem.index {
                Some(MemoryIndex::Register(view)) => process
                    .read_register(view.parent.0)
                    .ok()
                    .map(|v| v.wrapping_mul(u64::from(mem.scale))),
                Some(MemoryIndex::Vsib { .. }) => None,
                None => Some(0),
            };
            if let (Some(base), Some(index)) = (base, index) {
                let address = base.wrapping_add(index).wrapping_add(mem.displacement as u64);
                let len = usize::from(operand.width_bits).div_ceil(8);
                if address < TEXT_HI && address.saturating_add(len as u64) > TEXT_LO {
                    let before = process.state.memory.read(address, len).ok().map(|v| concrete(&v));
                    text_writes.push((address, len, before));
                }
            }
        }

        let outcome = runtime.step(&mut process);
        for (address, len, before) in text_writes {
            let after = process.state.memory.read(address, len).ok().map(|v| concrete(&v));
            if before != after {
                eprintln!(
                    "TEXT WRITE step={step} pc={pc:#x} address={address:#x} before={before:02x?} after={after:02x?}"
                );
            }
        }
        let new_target = concrete(&process.state.memory.read(TARGET, 16)?);
        if new_target != target {
            eprintln!("TARGET CHANGED step={step} pc={pc:#x} {target:02x?} -> {new_target:02x?}");
            target = new_target;
        }
        let new_guard = concrete(&process.state.memory.read(GUARD_IAT, 8)?);
        if new_guard != guard {
            eprintln!("GUARD IAT CHANGED step={step} pc={pc:#x} {guard:02x?} -> {new_guard:02x?}");
            guard = new_guard;
        }
        match outcome {
            Ok(StepOutcome::SimProcedure { address, name }) => {
                let import = process
                    .pe_import_stubs
                    .get(&address)
                    .map(|(d, n)| format!("{d}!{n}"))
                    .unwrap_or_default();
                eprintln!(
                    "TBT API step={step} at={address:#x} model={name} import={import} rax={:#x}",
                    process.read_register(angryier_arch_intel64::register_id::GPR_BASE)?
                );
            }
            Ok(_) => {}
            Err(error) => {
                eprintln!("TBT BLOCK step={step} pc={pc:#x} error={error:?}");
                for line in ring {
                    eprintln!("TRACE {line}");
                }
                return Ok(());
            }
        }
        if process.terminated {
            eprintln!("TBT TERMINATED step={step}");
            return Ok(());
        }
    }
    eprintln!("TBT BUDGET pc={:#x}", process.pc()?);
    Ok(())
}

#[test]
fn tbt_with_completed_ioctl_information() -> Result<(), Box<dyn std::error::Error>> {
    let image = match std::fs::read("/tmp/tbt_driver.sys") {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker)?;
    for step in 0..10_000u64 {
        let pc = process.pc()?;
        if pc == 0x143adb36c {
            let rsp = process.read_register(angryier_arch_intel64::register_id::GPR_BASE + 4)?;
            eprintln!(
                "TBT before IO_STATUS copy status={:#x?} info={:#x?}",
                qword(&process, rsp + 0x50),
                qword(&process, rsp + 0x58)
            );
        }
        if pc == 0x1403ed2e9 {
            let rbp = process.read_register(angryier_arch_intel64::register_id::GPR_BASE + 5)?;
            process.state.memory = process.state.memory.write(
                rbp - 0x10,
                &angryier_models::KERNEL_UNIVERSAL_CALLBACK
                    .to_le_bytes()
                    .map(ByteValue::Concrete),
            )?;
            eprintln!("TBT injected DXGKrnl callback into output slot at {:#x}", rbp - 0x10);
        }
        if process
            .pe_import_stubs
            .get(&pc)
            .is_some_and(|(_, name)| name == "IoBuildDeviceIoControlRequest")
        {
            let rsp = process.read_register(angryier_arch_intel64::register_id::GPR_BASE + 4)?;
            if let Some(io_status) = qword(&process, rsp + 0x48) {
                process.state.memory = process.state.memory.write(
                    io_status + 8,
                    &angryier_models::KERNEL_UNIVERSAL_CALLBACK
                        .to_le_bytes()
                        .map(ByteValue::Concrete),
                )?;
                eprintln!(
                    "TBT injected completed IOCTL Information={:#x} at {:#x}",
                    angryier_models::KERNEL_UNIVERSAL_CALLBACK,
                    io_status + 8
                );
            }
        }
        match runtime.step(&mut process) {
            Ok(_) => {}
            Err(error) => {
                eprintln!("TBT INJECTED BLOCK step={step} pc={:#x} error={error:?}", process.pc()?);
                return Ok(());
            }
        }
        if process.terminated {
            eprintln!("TBT INJECTED COMPLETE steps={}", process.step_count);
            return Ok(());
        }
    }
    eprintln!(
        "TBT INJECTED BUDGET steps={} pc={:#x}",
        process.step_count,
        process.pc()?
    );
    Ok(())
}
