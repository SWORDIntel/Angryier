//! Integration test for targeted Windows kernel driver IOCTL reachability and solver model extraction.
//!
//! Validates:
//! - Synthetic Windows kernel driver layout (`DriverIoctlTarget`, `DRIVER_OBJECT`, `IO_STACK_LOCATION`,
//!   `KernelLayout`, IOCTL dispatch routine).
//! - Formulating targeted reachability queries to discover valid IOCTL codes (`0x0001_0000 <= imm <= 0x7fff_ffff`)
//!   reaching driver sinks (`MmMapIoSpace`, `ZwOpenProcess`).
//! - Solver model extraction: extracting concrete trigger values (e.g. `0xFFFFFFFF`, `0x1337C0DE`)
//!   and input buffer sizes that satisfy branch constraints.
//! - Failure paths: asserting that solver timeouts, budget exhaustion, and unknown outcomes are reported
//!   with honest bounds, and never conflated with proofs of safety (`PATH_UNREACHABLE`).

use std::path::PathBuf;
use std::time::Duration;

use angryier::driver_ioctl::{
    DEVICE_EXTENSION_ADDR, DEVICE_OBJECT_ADDR, DriverIoctlTarget, DriverVerdict, INPUT_BUFFER_ADDR, IRP_ADDR,
    IRP_MJ_DEVICE_CONTROL, IRP_STACK_ADDR, KernelLayout, StaticHandoff,
};
use angryier::{Engine, RunReport};
use angryier_solver::{SolverOutcomeKind, SolverQuery};
use angryier_types::{ConstraintCanonicalizationVersion, DependencyKey, ExprId, SolverQueryId, TargetProfileId};

/// Base address for the synthetic PE driver.
const DRIVER_IMAGE_BASE: u64 = 0;
/// RVA of `DriverEntry`.
const DRIVER_ENTRY_RVA: u32 = 0x10000;
/// RVA of `.rdata` section.
const DRIVER_RDATA_RVA: u32 = 0x20000;

/// Valid Windows IOCTL codes conforming to `0x0001_0000 <= imm <= 0x7fff_ffff`.
/// Following `CTL_CODE(DeviceType, Function, Method, Access)` format.
const IOCTL_MM_MAP_IO_SPACE: u32 = 0x0022_2004; // METHOD_BUFFERED, FILE_ANY_ACCESS
const IOCTL_ZW_OPEN_PROCESS: u32 = 0x0022_2008; // METHOD_BUFFERED, FILE_ANY_ACCESS

/// Trigger value expected in `SystemBuffer[0..4]` for the `MmMapIoSpace` sink.
const TRIGGER_MM_MAP_PHYS_ADDR: u32 = 0xFFFF_FFFF;
/// Trigger value expected in `SystemBuffer[4..8]` for the `ZwOpenProcess` sink.
const TRIGGER_ZW_OPEN_PID: u32 = 0x1337_C0DE;

/// Constructs a synthetic PE32+ driver image importing `ntoskrnl.exe!MmMapIoSpace`
/// and `ntoskrnl.exe!ZwOpenProcess`.
///
/// Maps sections covering:
/// - `.text` at RVA 0x10000
/// - `.rdata` at RVA 0x20000
/// - Synthetic kernel objects matching POPKORN addresses:
///   `DEVICE_OBJECT_ADDR` (0x444D_0000), `DEVICE_EXTENSION_ADDR` (0x444E_0000),
///   `IRP_ADDR` (0x0133_7000), `IRP_STACK_ADDR` (0x0600_0000), `INPUT_BUFFER_ADDR` (0x0700_0000).
fn build_synthetic_driver_pe(code: &[u8]) -> (Vec<u8>, u64, u64) {
    let mut rdata = Vec::new();
    let desc_off = rdata.len();
    // 1 import descriptor for ntoskrnl.exe + 1 null terminator descriptor (2 * 20 bytes)
    rdata.extend_from_slice(&[0u8; 2 * 20]);

    let dll_off = rdata.len();
    rdata.extend_from_slice(b"ntoskrnl.exe\0");
    while rdata.len() % 8 != 0 {
        rdata.push(0);
    }

    let int_off = rdata.len();
    // INT: 2 thunks + 1 null terminator = 3 * 8 = 24 bytes
    rdata.extend_from_slice(&[0u8; 8 * 3]);

    let iat_off = rdata.len();
    // IAT: 2 thunks + 1 null terminator = 3 * 8 = 24 bytes
    rdata.extend_from_slice(&[0u8; 8 * 3]);

    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }

    // Name entries:
    let by_name_0 = rdata.len();
    rdata.extend_from_slice(&0u16.to_le_bytes()); // hint 0
    rdata.extend_from_slice(b"MmMapIoSpace\0");
    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }

    let by_name_1 = rdata.len();
    rdata.extend_from_slice(&1u16.to_le_bytes()); // hint 1
    rdata.extend_from_slice(b"ZwOpenProcess\0");
    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }

    let rva = |off: usize| DRIVER_RDATA_RVA + off as u32;

    let thunk0 = u64::from(rva(by_name_0));
    let thunk1 = u64::from(rva(by_name_1));

    // INT thunks
    rdata[int_off..int_off + 8].copy_from_slice(&thunk0.to_le_bytes());
    rdata[int_off + 8..int_off + 16].copy_from_slice(&thunk1.to_le_bytes());

    // IAT thunks
    rdata[iat_off..iat_off + 8].copy_from_slice(&thunk0.to_le_bytes());
    rdata[iat_off + 8..iat_off + 16].copy_from_slice(&thunk1.to_le_bytes());

    // Import Directory Descriptor:
    rdata[desc_off..desc_off + 4].copy_from_slice(&rva(int_off).to_le_bytes()); // OriginalFirstThunk
    rdata[desc_off + 12..desc_off + 16].copy_from_slice(&rva(dll_off).to_le_bytes()); // Name
    rdata[desc_off + 16..desc_off + 20].copy_from_slice(&rva(iat_off).to_le_bytes()); // FirstThunk

    let iat_slot_mm_map = DRIVER_IMAGE_BASE + u64::from(rva(iat_off));
    let iat_slot_zw_open = DRIVER_IMAGE_BASE + u64::from(rva(iat_off + 8));

    // Headers size = 0x400 (1024 bytes)
    let header_size = 0x400u32;
    let mut pe = vec![0u8; header_size as usize];
    pe[0] = 0x4D;
    pe[1] = 0x5A; // MZ
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // e_lfanew -> 0x80

    // COFF header at 0x80
    pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]); // PE\0\0
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
    pe[0x86..0x88].copy_from_slice(&7u16.to_le_bytes()); // 7 sections
    pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader = 240

    // Optional header at 0x98 (PE32+)
    pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // PE32+ magic
    pe[0xA8..0xAC].copy_from_slice(&DRIVER_ENTRY_RVA.to_le_bytes()); // AddressOfEntryPoint
    pe[0xB0..0xB8].copy_from_slice(&DRIVER_IMAGE_BASE.to_le_bytes()); // ImageBase = 0
    pe[0xD4..0xD8].copy_from_slice(&header_size.to_le_bytes()); // SizeOfHeaders = 1024
    pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes = 16

    // DataDirectory[1] = IMPORT
    pe[0x110..0x114].copy_from_slice(&rva(desc_off).to_le_bytes());
    pe[0x114..0x118].copy_from_slice(&(rdata.len() as u32).to_le_bytes());

    let text_raw_ptr = header_size;
    let text_raw_size = 0x200u32;
    let rdata_raw_ptr = text_raw_ptr + text_raw_size;
    let rdata_raw_size = 0x200u32;

    // Helper closure to write a 40-byte section header
    let mut write_section_hdr =
        |offset: usize, name: &[u8], va: u32, vsize: u32, raw_ptr: u32, raw_sz: u32, chars: u32| {
            pe[offset..offset + 8].copy_from_slice(name);
            pe[offset + 8..offset + 12].copy_from_slice(&vsize.to_le_bytes());
            pe[offset + 12..offset + 16].copy_from_slice(&va.to_le_bytes());
            pe[offset + 16..offset + 20].copy_from_slice(&raw_sz.to_le_bytes());
            pe[offset + 20..offset + 24].copy_from_slice(&raw_ptr.to_le_bytes());
            pe[offset + 36..offset + 40].copy_from_slice(&chars.to_le_bytes());
        };

    // Section 1: .text at 0x188
    write_section_hdr(
        0x188,
        b".text\0\0\0",
        DRIVER_ENTRY_RVA,
        0x1000,
        text_raw_ptr,
        text_raw_size,
        0x6000_0000,
    );
    // Section 2: .rdata at 0x1B0
    write_section_hdr(
        0x1B0,
        b".rdata\0\0",
        DRIVER_RDATA_RVA,
        0x1000,
        rdata_raw_ptr,
        rdata_raw_size,
        0x4000_0000,
    );
    // Section 3: .devobj at 0x1D8 (DEVICE_OBJECT_ADDR)
    write_section_hdr(
        0x1D8,
        b".devobj\0",
        DEVICE_OBJECT_ADDR as u32,
        0x1000,
        0,
        0,
        0xC000_0000,
    );
    // Section 4: .irp at 0x200 (IRP_ADDR)
    write_section_hdr(0x200, b".irp\0\0\0\0", IRP_ADDR as u32, 0x1000, 0, 0, 0xC000_0000);
    // Section 5: .stack at 0x228 (IRP_STACK_ADDR)
    write_section_hdr(0x228, b".stack\0\0", IRP_STACK_ADDR as u32, 0x1000, 0, 0, 0xC000_0000);
    // Section 6: .inbuf at 0x250 (INPUT_BUFFER_ADDR)
    write_section_hdr(
        0x250,
        b".inbuf\0\0",
        INPUT_BUFFER_ADDR as u32,
        0x1000,
        0,
        0,
        0xC000_0000,
    );
    // Section 7: .devext at 0x278 (DEVICE_EXTENSION_ADDR)
    write_section_hdr(
        0x278,
        b".devext\0",
        DEVICE_EXTENSION_ADDR as u32,
        0x1000,
        0,
        0,
        0xC000_0000,
    );

    // Raw section bytes
    pe.resize((text_raw_ptr + text_raw_size) as usize, 0);
    pe[text_raw_ptr as usize..text_raw_ptr as usize + code.len()].copy_from_slice(code);

    pe.resize((rdata_raw_ptr + rdata_raw_size) as usize, 0);
    pe[rdata_raw_ptr as usize..rdata_raw_ptr as usize + rdata.len()].copy_from_slice(&rdata);

    (pe, iat_slot_mm_map, iat_slot_zw_open)
}

/// Generates the x86-64 machine code for `DriverEntry` and `DispatchIoctl`.
fn generate_driver_code(iat_slot_mm_map: u64, iat_slot_zw_open: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(0x200);

    // -----------------------------------------------------------------------
    // RVA 0x10000: DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
    // RCX = DriverObject. Sets MajorFunction[IRP_MJ_DEVICE_CONTROL] (0x70 + 14*8 = 0xE0).
    // -----------------------------------------------------------------------
    // lea rax, [rip + 0x19] -> 0x10020 (DispatchIoctl)
    code.extend_from_slice(&[0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00]);
    // mov [rcx + 0xE0], rax
    code.extend_from_slice(&[0x48, 0x89, 0x81, 0xE0, 0x00, 0x00, 0x00]);
    // xor eax, eax (STATUS_SUCCESS)
    code.extend_from_slice(&[0x31, 0xC0]);
    // ret
    code.push(0xC3);

    // Pad to offset 0x20 (RVA 0x10020)
    while code.len() < 0x20 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x10020: DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
    // RCX = DeviceObject, RDX = Irp.
    // -----------------------------------------------------------------------
    // mov r8, [rdx + 0xB8] (Irp->Tail.Overlay.CurrentStackLocation)
    code.extend_from_slice(&[0x4C, 0x8B, 0x82, 0xB8, 0x00, 0x00, 0x00]);
    // mov eax, [r8 + 0x18] (stack->Parameters.DeviceIoControl.IoControlCode)
    code.extend_from_slice(&[0x41, 0x8B, 0x40, 0x18]);

    // cmp eax, IOCTL_MM_MAP_IO_SPACE (0x00222004)
    code.extend_from_slice(&[0x3D]);
    code.extend_from_slice(&IOCTL_MM_MAP_IO_SPACE.to_le_bytes());
    // je handle_mm_map (RVA 0x10050): disp = 0x10050 - (0x10030 + 6) = 0x1A
    code.extend_from_slice(&[0x0F, 0x84, 0x1A, 0x00, 0x00, 0x00]);

    // cmp eax, IOCTL_ZW_OPEN_PROCESS (0x00222008)
    code.extend_from_slice(&[0x3D]);
    code.extend_from_slice(&IOCTL_ZW_OPEN_PROCESS.to_le_bytes());
    // je handle_zw_open (RVA 0x10080): disp = 0x10080 - (0x1003B + 6) = 0x3F
    code.extend_from_slice(&[0x0F, 0x84, 0x3F, 0x00, 0x00, 0x00]);

    // Unknown IOCTL: mov eax, 0xC0000010 (STATUS_INVALID_DEVICE_REQUEST); ret
    code.extend_from_slice(&[0xB8, 0x10, 0x00, 0x00, 0xC0]);
    code.push(0xC3);

    // Pad to offset 0x50 (RVA 0x10050)
    while code.len() < 0x50 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x10050: handle_mm_map
    // -----------------------------------------------------------------------
    // cmp dword ptr [r8 + 0x10], 16 (InputBufferLength >= 16)
    code.extend_from_slice(&[0x41, 0x83, 0x78, 0x10, 0x10]);
    // jb error_buffer_size (RVA 0x100B0): disp = 0x100B0 - (0x10055 + 6) = 0x55
    code.extend_from_slice(&[0x0F, 0x82, 0x55, 0x00, 0x00, 0x00]);

    // mov r9, [rdx + 0x18] (Irp->AssociatedIrp.SystemBuffer)
    code.extend_from_slice(&[0x4C, 0x8B, 0x4A, 0x18]);

    // cmp dword ptr [r9], TRIGGER_MM_MAP_PHYS_ADDR (0xFFFFFFFF)
    code.extend_from_slice(&[0x41, 0x81, 0x39]);
    code.extend_from_slice(&TRIGGER_MM_MAP_PHYS_ADDR.to_le_bytes());
    // jne error_trigger (RVA 0x100C0): disp = 0x100C0 - (0x10066 + 6) = 0x54
    code.extend_from_slice(&[0x0F, 0x85, 0x54, 0x00, 0x00, 0x00]);

    // Pad to offset 0x70 (RVA 0x10070)
    while code.len() < 0x70 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x10070: SINK 1 (MmMapIoSpace call site)
    // -----------------------------------------------------------------------
    let call1_next = DRIVER_IMAGE_BASE + 0x10070 + 6;
    let disp1 = (iat_slot_mm_map.wrapping_sub(call1_next)) as u32;
    // call [rip + disp1]
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&disp1.to_le_bytes());
    // xor eax, eax; ret
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    // Pad to offset 0x80 (RVA 0x10080)
    while code.len() < 0x80 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x10080: handle_zw_open
    // -----------------------------------------------------------------------
    // cmp dword ptr [r8 + 0x10], 24 (InputBufferLength >= 24)
    code.extend_from_slice(&[0x41, 0x83, 0x78, 0x10, 0x18]);
    // jb error_buffer_size (RVA 0x100B0): disp = 0x100B0 - (0x10085 + 6) = 0x25
    code.extend_from_slice(&[0x0F, 0x82, 0x25, 0x00, 0x00, 0x00]);

    // mov r9, [rdx + 0x18] (Irp->AssociatedIrp.SystemBuffer)
    code.extend_from_slice(&[0x4C, 0x8B, 0x4A, 0x18]);

    // cmp dword ptr [r9 + 4], TRIGGER_ZW_OPEN_PID (0x1337C0DE)
    code.extend_from_slice(&[0x41, 0x81, 0x79, 0x04]);
    code.extend_from_slice(&TRIGGER_ZW_OPEN_PID.to_le_bytes());
    // jne error_trigger (RVA 0x100C0): disp = 0x100C0 - (0x10097 + 6) = 0x23
    code.extend_from_slice(&[0x0F, 0x85, 0x23, 0x00, 0x00, 0x00]);

    // Pad to offset 0xA0 (RVA 0x100A0)
    while code.len() < 0xA0 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x100A0: SINK 2 (ZwOpenProcess call site)
    // -----------------------------------------------------------------------
    let call2_next = DRIVER_IMAGE_BASE + 0x100A0 + 6;
    let disp2 = (iat_slot_zw_open.wrapping_sub(call2_next)) as u32;
    // call [rip + disp2]
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&disp2.to_le_bytes());
    // xor eax, eax; ret
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    // Pad to offset 0xB0 (RVA 0x100B0)
    while code.len() < 0xB0 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x100B0: error_buffer_size -> STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
    // -----------------------------------------------------------------------
    code.extend_from_slice(&[0xB8, 0x04, 0x00, 0x00, 0xC0, 0xC3]);

    // Pad to offset 0xC0 (RVA 0x100C0)
    while code.len() < 0xC0 {
        code.push(0x90);
    }

    // -----------------------------------------------------------------------
    // RVA 0x100C0: error_trigger -> STATUS_INVALID_PARAMETER (0xC000000D)
    // -----------------------------------------------------------------------
    code.extend_from_slice(&[0xB8, 0x0D, 0x00, 0x00, 0xC0, 0xC3]);

    code
}

/// Helper to write driver bytes to a temporary path and load through `Engine`.
fn create_and_load_synthetic_driver() -> (Engine, angryier::Image, PathBuf) {
    let dummy_code = vec![0xC3];
    let (_, iat_slot_mm_map, iat_slot_zw_open) = build_synthetic_driver_pe(&dummy_code);
    let real_code = generate_driver_code(iat_slot_mm_map, iat_slot_zw_open);
    let (driver_bytes, _, _) = build_synthetic_driver_pe(&real_code);

    let temp_path = std::env::temp_dir().join(format!(
        "angryier_driver_test_{}_{}.sys",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&temp_path, &driver_bytes).expect("write synthetic driver PE to temp file");

    let engine = Engine::new().expect("construct Angryier engine");
    let image = engine.load(&temp_path).expect("load synthetic PE driver image");
    assert_eq!(image.kind(), angryier::ImageKind::PeDriver);

    (engine, image, temp_path)
}

#[test]
fn test_kernel_layout_contract_and_structure_offsets() {
    let layout = KernelLayout::X64;
    assert_eq!(layout.pointer_size, 8);
    assert_eq!(layout.irp_system_buffer, 0x18);
    assert_eq!(layout.irp_user_buffer, 0x70);
    assert_eq!(layout.irp_current_stack_location, 0xB8);
    assert_eq!(layout.io_stack_io_control_code, 0x18);
    assert_eq!(layout.io_stack_input_buffer_length, 0x10);
    assert_eq!(layout.io_stack_output_buffer_length, 0x08);
    assert_eq!(layout.io_stack_type3_input_buffer, 0x20);
    assert_eq!(layout.device_object_device_extension, 0x40);
    assert_eq!(layout.driver_object_major_function, 0x70);
    assert_eq!(layout.driver_object_major_function_count, 28);

    // Verify synthetic base addresses match POPKORN seeding contract
    assert_eq!(DEVICE_OBJECT_ADDR, 0x444D_0000);
    assert_eq!(DEVICE_EXTENSION_ADDR, 0x444E_0000);
    assert_eq!(IRP_ADDR, 0x0133_7000);
    assert_eq!(IRP_STACK_ADDR, 0x0600_0000);
    assert_eq!(INPUT_BUFFER_ADDR, 0x0700_0000);
    assert_eq!(IRP_MJ_DEVICE_CONTROL, 0x0E);
}

#[test]
fn test_synthetic_driver_layout_and_ioctl_dispatch_reachability() {
    let (engine, image, temp_path) = create_and_load_synthetic_driver();

    let handler_va = DRIVER_IMAGE_BASE + 0x10020;
    let sink_mm_map_va = DRIVER_IMAGE_BASE + 0x10070;
    let sink_zw_open_va = DRIVER_IMAGE_BASE + 0x100A0;

    // -----------------------------------------------------------------------
    // 1. Pinned reachability query for MmMapIoSpace
    // -----------------------------------------------------------------------
    let target_mm_map_pinned = DriverIoctlTarget {
        handler_va,
        sink_va: sink_mm_map_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let opts1 = target_mm_map_pinned.run_options(256, 16).expect("build run options");
    assert_eq!(opts1.entry, Some(handler_va));
    assert_eq!(opts1.find, vec![sink_mm_map_va]);
    assert!(opts1.solve);

    let report1 = engine.run(&image, &opts1).expect("run symbolic execution");
    assert!(
        report1.found_pcs.contains(&sink_mm_map_va),
        "execution must reach MmMapIoSpace sink call site"
    );
    assert!(!report1.inputs.is_empty(), "model solving must succeed");

    let verdict1 = target_mm_map_pinned
        .classify_run(&report1, 0.05)
        .with_sink_name("MmMapIoSpace")
        .with_target_id("TGT-MM-MAP-PINNED");
    assert_eq!(
        verdict1.verdict,
        DriverVerdict::PathFeasibleConstrained,
        "pinned valid IOCTL reaching sink must be feasible constrained"
    );
    assert_eq!(verdict1.ioctl_code, Some(IOCTL_MM_MAP_IO_SPACE));

    // -----------------------------------------------------------------------
    // 2. Symbolic IOCTL discovery for MmMapIoSpace
    // (target.ioctl_code = None -> solver discovers the valid IOCTL code)
    // -----------------------------------------------------------------------
    let target_mm_map_symbolic = DriverIoctlTarget {
        handler_va,
        sink_va: sink_mm_map_va,
        ioctl_code: None,
    };
    let opts2 = target_mm_map_symbolic.run_options(256, 16).expect("build run options");
    // Verify IOCTL slot was left symbolic (not poked)
    assert!(
        !opts2.poke.iter().any(|(addr, _)| *addr == IRP_STACK_ADDR + 0x18),
        "symbolic IOCTL code must not be poked concretely"
    );

    let report2 = engine.run(&image, &opts2).expect("run symbolic execution");
    assert!(
        report2.found_pcs.contains(&sink_mm_map_va),
        "symbolic IOCTL exploration must discover path reaching MmMapIoSpace sink"
    );
    assert!(
        !report2.inputs.is_empty(),
        "solver must extract satisfying assignment for symbolic IOCTL"
    );

    let verdict2 = target_mm_map_symbolic
        .classify_run(&report2, 0.08)
        .with_sink_name("MmMapIoSpace")
        .with_target_id("TGT-MM-MAP-SYMBOLIC");
    assert!(
        verdict2.verdict == DriverVerdict::PathFeasibleConstrained
            || verdict2.verdict == DriverVerdict::PathFeasibleUnchecked
    );

    // -----------------------------------------------------------------------
    // 3. Pinned reachability query for ZwOpenProcess
    // -----------------------------------------------------------------------
    let target_zw_open = DriverIoctlTarget {
        handler_va,
        sink_va: sink_zw_open_va,
        ioctl_code: Some(IOCTL_ZW_OPEN_PROCESS),
    };
    let opts3 = target_zw_open.run_options(256, 16).expect("build run options");
    let report3 = engine.run(&image, &opts3).expect("run symbolic execution");
    assert!(
        report3.found_pcs.contains(&sink_zw_open_va),
        "execution must reach ZwOpenProcess sink call site"
    );

    let verdict3 = target_zw_open
        .classify_run(&report3, 0.05)
        .with_sink_name("ZwOpenProcess")
        .with_target_id("TGT-ZW-OPEN-PINNED");
    assert_eq!(verdict3.verdict, DriverVerdict::PathFeasibleConstrained);
    assert_eq!(verdict3.ioctl_code, Some(IOCTL_ZW_OPEN_PROCESS));

    // Verify JSON serialization matching POPKORN schema
    let json_str = verdict3.to_json();
    assert!(json_str.contains("\"verdict\":\"PATH_FEASIBLE_CONSTRAINED\""));
    assert!(json_str.contains("\"sink_name\":\"ZwOpenProcess\""));
    assert!(json_str.contains("\"ioctl_code\":\"0x222008\""));

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn test_solver_model_extraction_trigger_values_and_buffer_sizes() {
    let (engine, image, temp_path) = create_and_load_synthetic_driver();

    let handler_va = DRIVER_IMAGE_BASE + 0x10020;
    let sink_mm_map_va = DRIVER_IMAGE_BASE + 0x10070;
    let sink_zw_open_va = DRIVER_IMAGE_BASE + 0x100A0;

    // -----------------------------------------------------------------------
    // Test model extraction for MmMapIoSpace:
    // Requires: InputBufferLength >= 16, SystemBuffer[0..4] == 0xFFFFFFFF
    // -----------------------------------------------------------------------
    let target1 = DriverIoctlTarget {
        handler_va,
        sink_va: sink_mm_map_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let opts1 = target1.run_options(256, 16).expect("build run options");
    let report1 = engine.run(&image, &opts1).expect("run execution");
    assert!(report1.found_pcs.contains(&sink_mm_map_va));
    assert!(
        !report1.inputs.is_empty(),
        "solver must extract a model for found state"
    );

    let found_model1 = &report1.inputs[0];
    let model1_bytes: Vec<u8> = found_model1.iter().map(|val| val[0]).collect();
    // Verify solver extracted 4 concrete bytes of 0xFF, forming the 32-bit trigger 0xFFFFFFFF
    let ff_count = model1_bytes.iter().filter(|&&b| b == 0xFF).count();
    assert_eq!(
        ff_count, 4,
        "solver model must contain exactly 4 byte symbols of 0xFF forming 0xFFFFFFFF (found {ff_count})"
    );

    // -----------------------------------------------------------------------
    // Test model extraction for ZwOpenProcess:
    // Requires: InputBufferLength >= 24, SystemBuffer[4..8] == 0x1337C0DE
    // -----------------------------------------------------------------------
    let target2 = DriverIoctlTarget {
        handler_va,
        sink_va: sink_zw_open_va,
        ioctl_code: Some(IOCTL_ZW_OPEN_PROCESS),
    };
    let opts2 = target2.run_options(256, 16).expect("build run options");
    let report2 = engine.run(&image, &opts2).expect("run execution");
    assert!(report2.found_pcs.contains(&sink_zw_open_va));
    assert!(!report2.inputs.is_empty());

    let found_model2 = &report2.inputs[0];
    let model2_bytes: Vec<u8> = found_model2.iter().map(|val| val[0]).collect();

    // Verify solver extracted the 4 concrete bytes of 0x1337C0DE: [0xDE, 0xC0, 0x37, 0x13]
    assert!(
        model2_bytes.contains(&0xDE),
        "model must contain byte 0xDE of trigger PID"
    );
    assert!(
        model2_bytes.contains(&0xC0),
        "model must contain byte 0xC0 of trigger PID"
    );
    assert!(
        model2_bytes.contains(&0x37),
        "model must contain byte 0x37 of trigger PID"
    );
    assert!(
        model2_bytes.contains(&0x13),
        "model must contain byte 0x13 of trigger PID"
    );

    let _ = std::fs::remove_file(temp_path);
}

#[test]
fn test_failure_paths_honesty_timeouts_and_unknowns_never_safe() {
    let target = DriverIoctlTarget {
        handler_va: DRIVER_IMAGE_BASE + 0x10020,
        sink_va: DRIVER_IMAGE_BASE + 0x10070,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };

    // -----------------------------------------------------------------------
    // 1. Timeout / step budget exhaustion: MUST be TIMEOUT_BUDGET_EXCEEDED,
    //    NEVER PATH_UNREACHABLE (which would be an unsound safety proof).
    // -----------------------------------------------------------------------
    let timed_out_report = RunReport {
        steps: 100,
        live_states: 3,
        timed_out: true,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict1 = target.classify_run(&timed_out_report, 10.0);
    assert_eq!(
        verdict1.verdict,
        DriverVerdict::TimeoutBudgetExceeded,
        "timeout must be classified as TIMEOUT_BUDGET_EXCEEDED"
    );
    assert_ne!(
        verdict1.verdict,
        DriverVerdict::PathUnreachable,
        "timeout MUST NEVER be treated as proof of safety (PATH_UNREACHABLE)"
    );
    assert!(
        verdict1.notes.is_some(),
        "incomplete verdict must include diagnostic notes"
    );

    // Step budget exhausted with live states remaining
    let budget_exhausted_report = RunReport {
        steps: 256,
        live_states: 2,
        timed_out: false,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict2 = target.classify_run(&budget_exhausted_report, 5.0);
    assert_eq!(verdict2.verdict, DriverVerdict::TimeoutBudgetExceeded);
    assert_ne!(
        verdict2.verdict,
        DriverVerdict::PathUnreachable,
        "exhausted step budget with live states MUST NEVER be reported as unreachable"
    );

    // -----------------------------------------------------------------------
    // 2. State explosion cap pruning: MUST be EXPLOSION_SUPPRESSED,
    //    NEVER PATH_UNREACHABLE.
    // -----------------------------------------------------------------------
    let explosion_report = RunReport {
        steps: 80,
        pruned_states: 10,
        live_states: 16,
        peak_states: 16,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict3 = target.classify_run(&explosion_report, 2.0);
    assert_eq!(
        verdict3.verdict,
        DriverVerdict::ExplosionSuppressed,
        "pruned states must be classified as EXPLOSION_SUPPRESSED"
    );
    assert_ne!(
        verdict3.verdict,
        DriverVerdict::PathUnreachable,
        "pruned states MUST NEVER be reported as safe"
    );
    assert!(
        verdict3
            .notes
            .as_deref()
            .unwrap_or("")
            .contains("explosion_threshold_hit")
    );

    // -----------------------------------------------------------------------
    // 3. Engine error: MUST be EXPLOSION_SUPPRESSED, NEVER PATH_UNREACHABLE.
    // -----------------------------------------------------------------------
    let error_report = RunReport {
        steps: 12,
        last_error: Some("memory fault during symbolic execution".to_string()),
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict4 = target.classify_run(&error_report, 0.1);
    assert_eq!(verdict4.verdict, DriverVerdict::ExplosionSuppressed);
    assert_ne!(verdict4.verdict, DriverVerdict::PathUnreachable);
    assert!(verdict4.notes.as_deref().unwrap_or("").starts_with("engine_error:"));

    // -----------------------------------------------------------------------
    // 4. Honest PATH_UNREACHABLE: only when live_states == 0 without timeout or error.
    // -----------------------------------------------------------------------
    let truly_unreachable_report = RunReport {
        steps: 64,
        live_states: 0,
        dead_states: 4,
        terminated: 2,
        timed_out: false,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict5 = target.classify_run(&truly_unreachable_report, 0.5);
    assert_eq!(
        verdict5.verdict,
        DriverVerdict::PathUnreachable,
        "exhausted exploration with 0 live states is legitimately PATH_UNREACHABLE"
    );
}

#[test]
fn test_solver_level_timeout_and_unknown_outcomes_distinct_from_unsat() {
    // Validate that angryier_solver types distinguish between Sat, Unsat, Timeout, and Unknown.
    let outcome_sat = SolverOutcomeKind::Sat;
    let outcome_unsat = SolverOutcomeKind::Unsat;
    let outcome_timeout = SolverOutcomeKind::Timeout;
    let outcome_unknown = SolverOutcomeKind::Unknown;

    assert_ne!(outcome_timeout, outcome_unsat);
    assert_ne!(outcome_unknown, outcome_unsat);
    assert_ne!(outcome_timeout, outcome_sat);
    assert_ne!(outcome_unknown, outcome_sat);

    // Construct a SolverQuery with Duration timeout and verify canonical construction
    let dummy_query = SolverQuery::canonical(
        SolverQueryId(1),
        &[],
        ExprId(10),
        DependencyKey::ZERO,
        TargetProfileId(1),
        ConstraintCanonicalizationVersion(1),
        Duration::from_millis(50),
    )
    .expect("canonical query construction");

    assert_eq!(dummy_query.timeout(), Duration::from_millis(50));
    assert!(dummy_query.validate_identity().is_ok());

    // Zero timeout must be rejected explicitly
    assert!(
        SolverQuery::canonical(
            SolverQueryId(2),
            &[],
            ExprId(10),
            DependencyKey::ZERO,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::ZERO,
        )
        .is_err()
    );
}

#[test]
fn test_static_handoff_integration_for_driver_targets() {
    let json_handoff = format!(
        r#"{{
            "binary_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "binary_name": "SyntheticDriver.sys",
            "arch": "x64",
            "image_base": "0x{:x}",
            "entry_rva": "0x10000",
            "producer": "METHRA-re v1",
            "targets": [
                {{
                    "target_id": "TGT-SYNTH-MM-MAP-001",
                    "handler_rva": "0x10020",
                    "sink_rva": "0x10070",
                    "sink_name": "MmMapIoSpace",
                    "candidate_ioctl_codes": [{}, {}],
                    "static_finding_rule": "VULN.PROBE.MISSING",
                    "confidence": "HIGH",
                    "interprocedural_depth": 0,
                    "timeout_sec": 30
                }},
                {{
                    "target_id": "TGT-SYNTH-ZW-OPEN-002",
                    "handler_rva": "0x10020",
                    "sink_rva": "0x100A0",
                    "sink_name": "ZwOpenProcess",
                    "candidate_ioctl_codes": [{}],
                    "static_finding_rule": "VULN.PROCESS.OPEN",
                    "confidence": "MEDIUM",
                    "interprocedural_depth": 0,
                    "timeout_sec": 45
                }}
            ]
        }}"#,
        DRIVER_IMAGE_BASE,
        IOCTL_MM_MAP_IO_SPACE,
        0x0022_200C, // candidate that won't reach sink
        IOCTL_ZW_OPEN_PROCESS
    );

    let handoff = StaticHandoff::from_json(&json_handoff).expect("parse static handoff");
    assert_eq!(handoff.arch, "x64");
    assert_eq!(handoff.image_base, DRIVER_IMAGE_BASE);
    assert_eq!(handoff.targets.len(), 2);

    let driver_targets = handoff.to_driver_targets();
    assert_eq!(driver_targets.len(), 2);

    // Target 1: MmMapIoSpace has 2 candidate IOCTLs
    let (tgt_meta1, ioctl_targets1) = &driver_targets[0];
    assert_eq!(tgt_meta1.target_id, "TGT-SYNTH-MM-MAP-001");
    assert_eq!(tgt_meta1.sink_name, "MmMapIoSpace");
    assert_eq!(ioctl_targets1.len(), 2);
    assert_eq!(ioctl_targets1[0].handler_va, DRIVER_IMAGE_BASE + 0x10020);
    assert_eq!(ioctl_targets1[0].sink_va, DRIVER_IMAGE_BASE + 0x10070);
    assert_eq!(ioctl_targets1[0].ioctl_code, Some(IOCTL_MM_MAP_IO_SPACE));
    assert_eq!(ioctl_targets1[1].ioctl_code, Some(0x0022_200C));

    // Target 2: ZwOpenProcess has 1 candidate IOCTL
    let (tgt_meta2, ioctl_targets2) = &driver_targets[1];
    assert_eq!(tgt_meta2.target_id, "TGT-SYNTH-ZW-OPEN-002");
    assert_eq!(tgt_meta2.sink_name, "ZwOpenProcess");
    assert_eq!(ioctl_targets2.len(), 1);
    assert_eq!(ioctl_targets2[0].ioctl_code, Some(IOCTL_ZW_OPEN_PROCESS));
}
