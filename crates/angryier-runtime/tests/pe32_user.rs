//! PE32 (IA-32) user-mode loading and execution: 4-byte IAT linking against
//! the sub-4-GiB stub region, the 32-bit entry stack image, and sentinel
//! exit termination through a `ret` at entry.
//!
//! Fixture layout mirrors the loader's `pe32_tests` (`pe32_tests::fixture32`
//! and `make_pe32_with_imports`): DOS at 0, PE at 0x80, optional header at
//! 0x98 (magic 0x10B, size 0xF0), section headers at 0x188/0x1B0, `.text`
//! raw at 0x200, `.rdata` raw at 0x400 with one KERNEL32.dll!ExitProcess
//! import whose 4-byte IAT slot sits at `.rdata` offset 68.

#![cfg(feature = "xed")]
#![allow(clippy::unwrap_used, clippy::identity_op, unused_mut, unused_variables)]

use angryier_arch_intel64::register_id;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::{PE32_STACK_BASE, PE32_TEB_BASE, PE32_USER_STUB_BASE, Process, Runtime};
use angryier_types::{SemanticVersion, TargetProfileId};

const IMAGE_BASE: u64 = 0x400_000;
const ENTRY_RVA: u32 = 0x1000;
const RDATA_VA: u32 = 0x2000;
/// `.rdata` offset of the single 4-byte IAT slot: descriptors 40 + name 13
/// padded to 4 → 56 + INT 4*(1+1) = 8 → IAT at 68.
const IAT_OFF: u32 = 64;

fn pe32_image() -> Vec<u8> {
    let mut rdata = Vec::new();
    let desc_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 2 * 20]);
    let dll_off = rdata.len();
    rdata.extend_from_slice(b"KERNEL32.dll\0");
    while rdata.len() % 4 != 0 {
        rdata.push(0);
    }
    let int_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 4 * 2]);
    let iat_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 4 * 2]);
    while rdata.len() % 2 != 0 {
        rdata.push(0);
    }
    let by_name_off = rdata.len();
    rdata.extend_from_slice(&0u16.to_le_bytes()); // hint
    rdata.extend_from_slice(b"ExitProcess\0");
    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }
    let rva = |off: usize| RDATA_VA + off as u32;
    let thunk = rva(by_name_off);
    rdata[int_off..int_off + 4].copy_from_slice(&thunk.to_le_bytes());
    rdata[iat_off..iat_off + 4].copy_from_slice(&thunk.to_le_bytes());
    rdata[desc_off..desc_off + 4].copy_from_slice(&rva(int_off).to_le_bytes());
    rdata[desc_off + 12..desc_off + 16].copy_from_slice(&rva(dll_off).to_le_bytes());
    rdata[desc_off + 16..desc_off + 20].copy_from_slice(&rva(iat_off).to_le_bytes());

    let mut pe = vec![0u8; 0x400];
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
    pe[0x84..0x86].copy_from_slice(&0x014Cu16.to_le_bytes()); // I386
    pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
    pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size
    pe[0x98..0x9A].copy_from_slice(&0x010Bu16.to_le_bytes()); // PE32 magic
    pe[0xA8..0xAC].copy_from_slice(&ENTRY_RVA.to_le_bytes());
    pe[0xB4..0xB8].copy_from_slice(&(IMAGE_BASE as u32).to_le_bytes()); // PE32 base
    pe[0xF4..0xF8].copy_from_slice(&2u32.to_le_bytes()); // NumberOfRvaAndSizes
    pe[0x100..0x104].copy_from_slice(&RDATA_VA.to_le_bytes()); // import dir RVA
    // .text at 0x188: `mov eax, 0x2A; ret` (raw 0x200).
    pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
    pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes());
    pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0x198..0x19C].copy_from_slice(&6u32.to_le_bytes());
    pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x1AC..0x1B0].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // exec+read
    pe.resize(0x206, 0);
    pe[0x200..0x205].copy_from_slice(&[0xB8, 0x2A, 0, 0, 0]); // mov eax,0x2A
    pe[0x205] = 0xC3;
    // .rdata at 0x1B0: raw 0x400.
    pe[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
    pe[0x1B8..0x1BC].copy_from_slice(&(rdata.len() as u32).to_le_bytes());
    pe[0x1BC..0x1C0].copy_from_slice(&RDATA_VA.to_le_bytes());
    pe[0x1C0..0x1C4].copy_from_slice(&(rdata.len() as u32).to_le_bytes());
    pe[0x1C4..0x1C8].copy_from_slice(&0x400u32.to_le_bytes());
    pe[0x1CC..0x1D0].copy_from_slice(&0u32.to_le_bytes());
    pe[0x1D4..0x1D8].copy_from_slice(&0x4000_0000u32.to_le_bytes()); // read
    pe.resize(0x400 + rdata.len(), 0);
    pe[0x400..0x400 + rdata.len()].copy_from_slice(&rdata);
    pe
}

fn read_mem_u32(process: &Process, address: u64) -> Result<u32, Box<dyn std::error::Error>> {
    let data = LayeredMemory::read(&process.state.memory, address, 4)?;
    let mut value = 0u32;
    for (i, byte) in data.iter().enumerate() {
        let b = match byte {
            ByteValue::Concrete(b) => *b,
            ByteValue::Symbolic(_) => 0,
        };
        value |= u32::from(b) << (i * 8);
    }
    Ok(value)
}

/// `load_pe32_user` patches the 4-byte IAT slot to the sub-4-GiB stub
/// address, records the stub, seeds the TEB stack fields, and plants the
/// 32-bit entry stack image with the PE32 sentinel.
#[test]
fn load_pe32_user_patches_iat_and_entry_state() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed_mode(
        SemanticVersion(1),
        TargetProfileId(2),
        angryier_runtime::XedMachineMode::Legacy32,
    );
    let process = runtime.load_pe32_user(&pe32_image())?;

    let stubs: Vec<_> = process.pe_imports().collect();
    assert_eq!(stubs.len(), 1);
    let (stub_address, dll, export) = stubs[0];
    assert_eq!(*stub_address, PE32_USER_STUB_BASE);
    assert_eq!(dll, "KERNEL32.dll");
    assert_eq!(export, "ExitProcess");

    // The 4-byte IAT slot points at the stub; the stub cell is a bare `ret`.
    let slot_va = IMAGE_BASE + u64::from(RDATA_VA + IAT_OFF);
    assert_eq!(read_mem_u32(&process, slot_va)?, PE32_USER_STUB_BASE as u32);
    let stub_cell = LayeredMemory::read(&process.state.memory, PE32_USER_STUB_BASE, 1)?;
    assert_eq!(stub_cell.first(), Some(&ByteValue::Concrete(0xC3)));

    // TEB stack fields seeded for __chkstk/_alloca probes (fs:[0x08] in
    // the TEB page of the FS scratch).
    let fs_limit = LayeredMemory::read(&process.state.memory, PE32_TEB_BASE + 0x08, 4)?;
    let limit = fs_limit
        .iter()
        .enumerate()
        .map(|(i, b)| match b {
            ByteValue::Concrete(v) => u32::from(*v) << (i * 8),
            ByteValue::Symbolic(_) => 0,
        })
        .reduce(|acc, v| acc | v)
        .unwrap();
    assert_eq!(limit, (PE32_STACK_BASE - 0x100_0000) as u32);
    Ok(())
}

/// The entry body (`mov eax, 0x2A; ret`) executes in legacy-32 mode and the
/// 4-byte `ret` lands on the PE32 sentinel exit hook, terminating cleanly.
#[test]
fn pe32_user_entry_ret_terminates_via_sentinel() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed_mode(
        SemanticVersion(1),
        TargetProfileId(2),
        angryier_runtime::XedMachineMode::Legacy32,
    );
    let mut process = runtime.load_pe32_user(&pe32_image())?;
    let summary = runtime.run(&mut process, 1000)?;

    assert!(process.terminated);
    assert!(summary.terminated);
    // The exit sentinel dispatched the `exit` SimProcedure.
    assert!(summary.simproc_dispatches >= 1);
    // EAX carries the `mov eax, 0x2A` marker past entry.
    assert_eq!(process.read_register(register_id::GPR_BASE)?, 0x2A);
    Ok(())
}

/// Probe: the FS scratch region accepts executor-level writes (the SEH
/// registration `mov fs:[0], eax` path lands here).
#[test]
fn pe32_fs_scratch_accepts_writes() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed_mode(
        SemanticVersion(1),
        TargetProfileId(2),
        angryier_runtime::XedMachineMode::Legacy32,
    );
    let mut process = runtime.load_pe32_user(&pe32_image())?;
    let bytes = [ByteValue::Concrete(0x11), ByteValue::Concrete(0x22), ByteValue::Concrete(0x33), ByteValue::Concrete(0x44)];
    process.state.memory = process
        .state
        .memory
        .write(angryier_runtime::PE32_FS_SCRATCH_BASE, &bytes)
        .map_err(|e| format!("{e:?}"))?;
    Ok(())
}
