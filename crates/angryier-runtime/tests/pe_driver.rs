//! PE-driver loading (stage 2): IAT linking against native stubs,
//! DriverEntry state, and hooked kernel-export returns.
//!
//! The fixture is a hand-built minimal PE32+ driver (mirroring the loader's
//! `pe32_tests` layout: DOS at 0, PE at 0x80, optional header at 0x98 with
//! size 0xF0, import data directory at 0x110, section headers at 0x188 and
//! 0x1B0, `.text` raw at 0x200, `.rdata` raw at 0x400) importing exactly one
//! function — `ntoskrnl.exe!DbgPrint` by name. Its `DriverEntry` loads the
//! IAT slot into RAX, calls through it, stores RAX to `[RCX]` (the
//! DRIVER_OBJECT scratch), marks RCX with a constant, and returns into the
//! sentinel exit hook.

#![cfg(feature = "xed")]

use angryier_arch_intel64::register_id;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::{PE_DRIVER_SCRATCH_BASE, PE_DRIVER_STUB_BASE, Process, Runtime};
use angryier_types::{SemanticVersion, TargetProfileId};

/// Image base of the fixture driver (same as the loader fixtures).
const IMAGE_BASE: u64 = 0x1_4000_0000;
/// `DriverEntry` RVA — start of `.text`.
const ENTRY_RVA: u32 = 0x1000;
/// `.rdata` RVA.
const RDATA_VA: u32 = 0x2000;
/// `.rdata` offset of the single IAT slot (`FirstThunk`): descriptors 40 +
/// "ntoskrnl.exe\0" 13 padded to 56 + INT 8*(1+1) = 16 → the IAT starts at
/// 72.
const IAT_OFF: u32 = 72;

/// Builds the fixture driver image.
fn driver_image() -> Vec<u8> {
    // .rdata: one import descriptor (plus terminator) for ntoskrnl.exe,
    // importing DbgPrint by name — same layout as the loader's
    // `make_pe_with_imports`.
    let mut rdata = Vec::new();
    let desc_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 2 * 20]);
    let dll_off = rdata.len();
    rdata.extend_from_slice(b"ntoskrnl.exe\0");
    while rdata.len() % 8 != 0 {
        rdata.push(0);
    }
    let int_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 8 * 2]); // patched below
    let iat_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 8 * 2]); // patched below
    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }
    let by_name_off = rdata.len();
    rdata.extend_from_slice(&0x42u16.to_le_bytes()); // hint
    rdata.extend_from_slice(b"DbgPrint\0");
    if rdata.len() % 2 != 0 {
        rdata.push(0); // hint/name entries are 2-byte aligned
    }
    let rva = |off: usize| RDATA_VA + off as u32;
    let thunk = u64::from(rva(by_name_off));
    rdata[int_off..int_off + 8].copy_from_slice(&thunk.to_le_bytes());
    rdata[iat_off..iat_off + 8].copy_from_slice(&thunk.to_le_bytes());
    // Descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.
    rdata[desc_off..desc_off + 4].copy_from_slice(&rva(int_off).to_le_bytes());
    rdata[desc_off + 12..desc_off + 16].copy_from_slice(&rva(dll_off).to_le_bytes());
    rdata[desc_off + 16..desc_off + 20].copy_from_slice(&rva(iat_off).to_le_bytes());

    // .text: DriverEntry.
    let iat_va = IMAGE_BASE + u64::from(RDATA_VA + IAT_OFF);
    let after_mov = IMAGE_BASE + u64::from(ENTRY_RVA) + 7;
    let disp = iat_va.wrapping_sub(after_mov) as u32;
    let mut text = Vec::new();
    text.extend_from_slice(&[0x48, 0x8B, 0x05]); // mov rax, [rip+disp32]
    text.extend_from_slice(&disp.to_le_bytes());
    text.extend_from_slice(&[0xFF, 0xD0]); // call rax
    text.extend_from_slice(&[0x48, 0x89, 0x01]); // mov [rcx], rax
    text.extend_from_slice(&[0x48, 0xC7, 0xC1, 0x2A, 0x00, 0x00, 0x00]); // mov rcx, 0x2a
    text.push(0xC3); // ret (into the sentinel exit hook)

    let mut pe = vec![0u8; 0x400];
    // DOS header.
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    // PE signature + COFF header at 0x80.
    pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size 240
    // Optional header at 0x98.
    pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
    pe[0xA8..0xAC].copy_from_slice(&ENTRY_RVA.to_le_bytes());
    pe[0xB0..0xB8].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    pe[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    // Data directory 1 (IMPORT) at 0x110.
    pe[0x110..0x114].copy_from_slice(&rva(desc_off).to_le_bytes());
    pe[0x114..0x118].copy_from_slice(&(rdata.len() as u32).to_le_bytes());
    // .text section header at 0x188.
    pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
    pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
    pe[0x194..0x198].copy_from_slice(&ENTRY_RVA.to_le_bytes()); // va 0x1000
    pe[0x198..0x19C].copy_from_slice(&(text.len() as u32).to_le_bytes()); // raw size
    pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
    pe[0x1AC..0x1B0].copy_from_slice(&0x6000_0000u32.to_le_bytes()); // EXEC | READ
    // .rdata section header at 0x1B0.
    pe[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
    pe[0x1B8..0x1BC].copy_from_slice(&(rdata.len() as u32).to_le_bytes()); // virtual size
    pe[0x1BC..0x1C0].copy_from_slice(&RDATA_VA.to_le_bytes()); // va 0x2000
    pe[0x1C0..0x1C4].copy_from_slice(&(rdata.len() as u32).to_le_bytes()); // raw size
    pe[0x1C4..0x1C8].copy_from_slice(&0x400u32.to_le_bytes()); // raw ptr
    pe[0x1D4..0x1D8].copy_from_slice(&0x4000_0000u32.to_le_bytes()); // READ
    // Sections' raw data.
    pe[0x200..0x200 + text.len()].copy_from_slice(&text);
    pe.extend_from_slice(&rdata);
    pe
}

/// Reads a little-endian u64 from process memory (symbolic bytes fold to 0).
fn read_mem_u64(process: &Process, address: u64) -> Result<u64, Box<dyn std::error::Error>> {
    let data = LayeredMemory::read(&process.state.memory, address, 8)?;
    let mut value = 0u64;
    for (i, byte) in data.iter().enumerate() {
        let b = match byte {
            ByteValue::Concrete(b) => *b,
            ByteValue::Symbolic(_) => 0,
        };
        value |= u64::from(b) << (i * 8);
    }
    Ok(value)
}

/// (a) `load_pe_driver` patches the IAT slot to the stub address, plants a
/// `ret` byte in the stub cell, records the stub table, and sets up the
/// DriverEntry register state.
#[test]
fn load_pe_driver_patches_iat_and_entry_state() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_pe_driver(&driver_image())?;

    // One stub recorded for ntoskrnl.exe!DbgPrint at the region base.
    let stubs: Vec<_> = process.pe_imports().collect();
    assert_eq!(stubs.len(), 1);
    let (stub_address, dll, export) = stubs[0];
    assert_eq!(*stub_address, PE_DRIVER_STUB_BASE);
    assert_eq!(dll, "ntoskrnl.exe");
    assert_eq!(export, "DbgPrint");

    // The IAT slot now points at the stub; the stub cell is a bare `ret`.
    let slot_va = IMAGE_BASE + u64::from(RDATA_VA + IAT_OFF);
    assert_eq!(read_mem_u64(&process, slot_va)?, PE_DRIVER_STUB_BASE);
    let stub_cell = LayeredMemory::read(&process.state.memory, PE_DRIVER_STUB_BASE, 1)?;
    assert_eq!(stub_cell.first(), Some(&ByteValue::Concrete(0xC3)));

    // DriverEntry register state: RCX = DRIVER_OBJECT scratch,
    // RDX = UNICODE_STRING-shaped scratch 0x200 into the same region.
    assert_eq!(
        process.read_register(register_id::GPR_BASE + 1)?,
        PE_DRIVER_SCRATCH_BASE
    );
    assert_eq!(
        process.read_register(register_id::GPR_BASE + 2)?,
        PE_DRIVER_SCRATCH_BASE + 0x200
    );
    Ok(())
}

/// (b) Unhooked: the call through the import lands on the native stub and
/// returns, the DriverEntry body executes, and the sentinel exit hook
/// terminates the process cleanly.
#[test]
fn unhooked_import_executes_native_stub_and_terminates() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&driver_image())?;
    let summary = runtime.run(&mut process, 1000)?;

    assert!(process.terminated);
    assert!(summary.terminated);
    // The exit sentinel dispatched the `exit` SimProcedure.
    assert!(summary.simproc_dispatches >= 1);

    // DriverEntry's body executed past the call: the `mov rcx, 0x2a` marker
    // outlived entry.
    assert_eq!(process.read_register(register_id::GPR_BASE + 1)?, 0x2A);

    // The call returned through the native stub: the store to [RCX] (the
    // DRIVER_OBJECT scratch) captured RAX — the IAT slot value the `mov`
    // loaded, i.e. the stub address (a `call rax` leaves RAX untouched).
    assert_eq!(read_mem_u64(&process, PE_DRIVER_SCRATCH_BASE)?, PE_DRIVER_STUB_BASE);
    Ok(())
}

/// (c) Hooked: with `hook_export_return` set before running, the import's
/// return value reaches DriverEntry — RAX is stored to the scratch right
/// after the call.
#[test]
fn hooked_export_return_value_reaches_driver_entry() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&driver_image())?;
    // The dll matches case-insensitively.
    process.hook_export_return("NTOSKRNL.EXE", "DbgPrint", 0x42)?;

    let summary = runtime.run(&mut process, 1000)?;
    assert!(process.terminated);
    assert!(summary.terminated);
    // One kernel-stub dispatch plus the sentinel exit dispatch.
    assert_eq!(summary.simproc_dispatches, 2);

    // RAX == 0x42 right after the call: DriverEntry stored it to [RCX].
    assert_eq!(read_mem_u64(&process, PE_DRIVER_SCRATCH_BASE)?, 0x42);
    // The marker still executed — the stub returned call-correctly into the
    // instruction after `call rax`.
    assert_eq!(process.read_register(register_id::GPR_BASE + 1)?, 0x2A);
    Ok(())
}

/// (d) Hooking an export the driver does not import fails explicitly.
#[test]
fn hook_export_return_unknown_import_errors() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&driver_image())?;
    // Unknown export name.
    assert!(process.hook_export_return("ntoskrnl.exe", "NoSuchExport", 1).is_err());
    // Unknown dll.
    assert!(process.hook_export_return("HAL.dll", "DbgPrint", 1).is_err());
    // Nothing was registered by the failed lookups.
    assert!(process.simproc_instances.is_empty());
    Ok(())
}
