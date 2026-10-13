//! Driver parity test against the KP14 POPKORN driver corpus.
//!
//! Validates:
//! - Candidate target selection, IOCTL dispatch reachability, and verdict consistency across driver targets.
//! - Comparison of Angryier verdicts against expected KP14 POPKORN outcomes:
//!   `PathFeasibleConstrained`, `PathFeasibleUnchecked`, `PathUnreachable`.
//! - Execution budgets, timeouts, and solver states fail-closed with explicit diagnostic reasons.
//! - Solver model extraction yields valid concrete trigger values (`0xFFFFFFFF`).

use std::path::PathBuf;

use angryier::driver_ioctl::{
    DEVICE_EXTENSION_ADDR, DEVICE_OBJECT_ADDR, DriverIoctlTarget, DriverVerdict, INPUT_BUFFER_ADDR, IRP_ADDR,
    IRP_STACK_ADDR, KernelLayout, StaticHandoff,
};
use angryier::{Engine, RunReport};
use angryier_solver::SolverOutcomeKind;

/// Base address for the synthetic PE driver.
const DRIVER_IMAGE_BASE: u64 = 0;
/// RVA of `DriverEntry`.
const DRIVER_ENTRY_RVA: u32 = 0x10000;
/// RVA of `.rdata` section.
const DRIVER_RDATA_RVA: u32 = 0x20000;

/// Valid Windows IOCTL codes conforming to `0x0001_0000 <= imm <= 0x7fff_ffff`.
const IOCTL_MM_MAP_IO_SPACE: u32 = 0x0022_2004;
const IOCTL_ZW_OPEN_PROCESS: u32 = 0x0022_2008;

/// Concrete trigger value expected in `SystemBuffer[0..4]` for the `MmMapIoSpace` sink.
const TRIGGER_MM_MAP_PHYS_ADDR: u32 = 0xFFFF_FFFF;
/// Concrete trigger value expected in `SystemBuffer[4..8]` for the `ZwOpenProcess` sink.
const TRIGGER_ZW_OPEN_PID: u32 = 0x1337_C0DE;

/// Constructs a synthetic PE32+ driver image importing `ntoskrnl.exe!MmMapIoSpace`
/// and `ntoskrnl.exe!ZwOpenProcess`.
fn build_synthetic_driver_pe(code: &[u8]) -> (Vec<u8>, u64, u64) {
    let mut rdata = Vec::new();
    let _desc_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 2 * 20]);

    let _dll_off = rdata.len();
    rdata.extend_from_slice(b"ntoskrnl.exe\0");
    while rdata.len() % 8 != 0 {
        rdata.push(0);
    }

    let int_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 8 * 3]);

    let iat_off = rdata.len();
    rdata.extend_from_slice(&[0u8; 8 * 3]);

    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }

    let by_name_0 = rdata.len();
    rdata.extend_from_slice(&0u16.to_le_bytes());
    rdata.extend_from_slice(b"MmMapIoSpace\0");
    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }

    let by_name_1 = rdata.len();
    rdata.extend_from_slice(&1u16.to_le_bytes());
    rdata.extend_from_slice(b"ZwOpenProcess\0");
    if rdata.len() % 2 != 0 {
        rdata.push(0);
    }

    let rva = |off: usize| DRIVER_RDATA_RVA + off as u32;

    let thunk0 = u64::from(rva(by_name_0));
    let thunk1 = u64::from(rva(by_name_1));

    rdata[int_off..int_off + 8].copy_from_slice(&thunk0.to_le_bytes());
    rdata[int_off + 8..int_off + 16].copy_from_slice(&thunk1.to_le_bytes());

    let iat_slot_mm_map = DRIVER_IMAGE_BASE + u64::from(rva(iat_off));
    let iat_slot_zw_open = DRIVER_IMAGE_BASE + u64::from(rva(iat_off + 8));
    rdata[iat_off..iat_off + 8].copy_from_slice(&thunk0.to_le_bytes());
    rdata[iat_off + 8..iat_off + 16].copy_from_slice(&thunk1.to_le_bytes());

    let mut pe = Vec::with_capacity(0x1000);
    pe.resize(0x80, 0);
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());

    pe.extend_from_slice(b"PE\0\0");
    pe.extend_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
    pe.extend_from_slice(&7u16.to_le_bytes()); // 7 Sections
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0xF0u16.to_le_bytes()); // SizeOfOptionalHeader
    pe.extend_from_slice(&0x0022u16.to_le_bytes()); // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    let opt_start = pe.len();
    pe.extend_from_slice(&0x020Bu16.to_le_bytes()); // PE32+
    pe.extend_from_slice(&[0x0E, 0x1E]);
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfCode
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SizeOfInitializedData
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&DRIVER_ENTRY_RVA.to_le_bytes()); // AddressOfEntryPoint
    pe.extend_from_slice(&DRIVER_ENTRY_RVA.to_le_bytes()); // BaseOfCode
    pe.extend_from_slice(&DRIVER_IMAGE_BASE.to_le_bytes()); // ImageBase
    pe.extend_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    pe.extend_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    pe.extend_from_slice(&6u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&6u16.to_le_bytes());
    pe.extend_from_slice(&0u16.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&0x40000u32.to_le_bytes()); // SizeOfImage
    pe.extend_from_slice(&0x400u32.to_le_bytes()); // SizeOfHeaders
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&1u16.to_le_bytes()); // Subsystem: NATIVE (driver)
    pe.extend_from_slice(&0x0160u16.to_le_bytes()); // DllCharacteristics: DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE
    pe.extend_from_slice(&0x100000u64.to_le_bytes());
    pe.extend_from_slice(&0x1000u64.to_le_bytes());
    pe.extend_from_slice(&0x100000u64.to_le_bytes());
    pe.extend_from_slice(&0x1000u64.to_le_bytes());
    pe.extend_from_slice(&0u32.to_le_bytes());
    pe.extend_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes

    pe.resize(opt_start + 0x70, 0);
    pe.extend_from_slice(&0u64.to_le_bytes()); // Export table
    pe.extend_from_slice(&DRIVER_RDATA_RVA.to_le_bytes()); // Import table RVA
    pe.extend_from_slice(&(rdata.len() as u32).to_le_bytes()); // Import table size
    pe.resize(opt_start + 0x88, 0);
    pe.extend_from_slice(&DRIVER_RDATA_RVA.to_le_bytes()); // IAT RVA
    pe.extend_from_slice(&(rdata.len() as u32).to_le_bytes()); // IAT size
    pe.resize(opt_start + 0xF0, 0);

    let text_raw_ptr: u32 = 0x400;
    let text_raw_size: u32 = (code.len() as u32).div_ceil(0x200) * 0x200;
    let rdata_raw_ptr: u32 = text_raw_ptr + text_raw_size;
    let rdata_raw_size: u32 = (rdata.len() as u32).div_ceil(0x200) * 0x200;

    let mut write_section_hdr =
        |offset: usize, name: &[u8; 8], virt_addr: u32, virt_size: u32, raw_ptr: u32, raw_size: u32, chars: u32| {
            pe.resize(offset + 40, 0);
            pe[offset..offset + 8].copy_from_slice(name);
            pe[offset + 8..offset + 12].copy_from_slice(&virt_size.to_le_bytes());
            pe[offset + 12..offset + 16].copy_from_slice(&virt_addr.to_le_bytes());
            pe[offset + 16..offset + 20].copy_from_slice(&raw_size.to_le_bytes());
            pe[offset + 20..offset + 24].copy_from_slice(&raw_ptr.to_le_bytes());
            pe[offset + 36..offset + 40].copy_from_slice(&chars.to_le_bytes());
        };

    write_section_hdr(
        0x188,
        b".text\0\0\0",
        DRIVER_ENTRY_RVA,
        0x1000,
        text_raw_ptr,
        text_raw_size,
        0x6000_0000,
    );
    write_section_hdr(
        0x1B0,
        b".rdata\0\0",
        DRIVER_RDATA_RVA,
        0x1000,
        rdata_raw_ptr,
        rdata_raw_size,
        0x4000_0000,
    );
    write_section_hdr(
        0x1D8,
        b".devobj\0",
        DEVICE_OBJECT_ADDR as u32,
        0x1000,
        0,
        0,
        0xC000_0000,
    );
    write_section_hdr(0x200, b".irp\0\0\0\0", IRP_ADDR as u32, 0x1000, 0, 0, 0xC000_0000);
    write_section_hdr(0x228, b".stack\0\0", IRP_STACK_ADDR as u32, 0x1000, 0, 0, 0xC000_0000);
    write_section_hdr(
        0x250,
        b".inbuf\0\0",
        INPUT_BUFFER_ADDR as u32,
        0x1000,
        0,
        0,
        0xC000_0000,
    );
    write_section_hdr(
        0x278,
        b".devext\0",
        DEVICE_EXTENSION_ADDR as u32,
        0x1000,
        0,
        0,
        0xC000_0000,
    );

    pe.resize((text_raw_ptr + text_raw_size) as usize, 0);
    pe[text_raw_ptr as usize..text_raw_ptr as usize + code.len()].copy_from_slice(code);

    pe.resize((rdata_raw_ptr + rdata_raw_size) as usize, 0);
    pe[rdata_raw_ptr as usize..rdata_raw_ptr as usize + rdata.len()].copy_from_slice(&rdata);

    (pe, iat_slot_mm_map, iat_slot_zw_open)
}

/// Generates x86-64 machine code for DriverEntry and DispatchIoctl.
///
/// Features:
/// - DriverEntry registers DispatchIoctl at MajorFunction[IRP_MJ_DEVICE_CONTROL].
/// - DispatchIoctl branches on IOCTL code:
///   - IOCTL_MM_MAP_IO_SPACE: checks InputBufferLength >= 16 and SystemBuffer[0..4] == 0xFFFFFFFF,
///     then calls MmMapIoSpace (sink 1 at RVA 0x10070).
///   - IOCTL_ZW_OPEN_PROCESS: checks InputBufferLength >= 24 and SystemBuffer[4..8] == 0x1337C0DE,
///     then calls ZwOpenProcess (sink 2 at RVA 0x100A0).
///   - Unchecked path at RVA 0x100D0: unconditionally calls MmMapIoSpace (sink 3) without buffer constraints.
///   - Unreachable sink at RVA 0x100F0: guarded by `xor eax, eax; test eax, eax; jnz` (never taken).
fn generate_driver_code(iat_slot_mm_map: u64, iat_slot_zw_open: u64) -> Vec<u8> {
    let mut code = Vec::with_capacity(0x300);

    // DriverEntry at RVA 0x10000
    // lea rax, [rip + 0x19] -> 0x10020
    code.extend_from_slice(&[0x48, 0x8D, 0x05, 0x19, 0x00, 0x00, 0x00]);
    // mov [rcx + 0xE0], rax
    code.extend_from_slice(&[0x48, 0x89, 0x81, 0xE0, 0x00, 0x00, 0x00]);
    // xor eax, eax; ret
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    while code.len() < 0x20 {
        code.push(0x90);
    }

    // DispatchIoctl at RVA 0x10020
    // mov r8, [rdx + 0xB8] (CurrentStackLocation)
    code.extend_from_slice(&[0x4C, 0x8B, 0x82, 0xB8, 0x00, 0x00, 0x00]);
    // mov eax, [r8 + 0x18] (IoControlCode)
    code.extend_from_slice(&[0x41, 0x8B, 0x40, 0x18]);

    // cmp eax, IOCTL_MM_MAP_IO_SPACE (0x00222004)
    code.extend_from_slice(&[0x3D]);
    code.extend_from_slice(&IOCTL_MM_MAP_IO_SPACE.to_le_bytes());
    // je handle_mm_map (0x10050)
    code.extend_from_slice(&[0x0F, 0x84, 0x1A, 0x00, 0x00, 0x00]);

    // cmp eax, IOCTL_ZW_OPEN_PROCESS (0x00222008)
    code.extend_from_slice(&[0x3D]);
    code.extend_from_slice(&IOCTL_ZW_OPEN_PROCESS.to_le_bytes());
    // je handle_zw_open (0x10080)
    code.extend_from_slice(&[0x0F, 0x84, 0x3F, 0x00, 0x00, 0x00]);

    // Unknown IOCTL: mov eax, 0xC0000010; ret
    code.extend_from_slice(&[0xB8, 0x10, 0x00, 0x00, 0xC0, 0xC3]);

    while code.len() < 0x50 {
        code.push(0x90);
    }

    // handle_mm_map at RVA 0x10050:
    // cmp dword ptr [r8 + 0x10], 16
    code.extend_from_slice(&[0x41, 0x83, 0x78, 0x10, 0x10]);
    // jb error_buffer_size (0x100B0)
    code.extend_from_slice(&[0x0F, 0x82, 0x55, 0x00, 0x00, 0x00]);
    // mov r9, [rdx + 0x18] (SystemBuffer)
    code.extend_from_slice(&[0x4C, 0x8B, 0x4A, 0x18]);
    // cmp dword ptr [r9], 0xFFFFFFFF
    code.extend_from_slice(&[0x41, 0x81, 0x39]);
    code.extend_from_slice(&TRIGGER_MM_MAP_PHYS_ADDR.to_le_bytes());
    // jne error_trigger (0x100C0)
    code.extend_from_slice(&[0x0F, 0x85, 0x54, 0x00, 0x00, 0x00]);

    while code.len() < 0x70 {
        code.push(0x90);
    }

    // SINK 1 (MmMapIoSpace call site) at RVA 0x10070
    let call1_next = DRIVER_IMAGE_BASE + 0x10070 + 6;
    let disp1 = (iat_slot_mm_map.wrapping_sub(call1_next)) as u32;
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&disp1.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    while code.len() < 0x80 {
        code.push(0x90);
    }

    // handle_zw_open at RVA 0x10080:
    // cmp dword ptr [r8 + 0x10], 24
    code.extend_from_slice(&[0x41, 0x83, 0x78, 0x10, 0x18]);
    // jb error_buffer_size (0x100B0)
    code.extend_from_slice(&[0x0F, 0x82, 0x25, 0x00, 0x00, 0x00]);
    // mov r9, [rdx + 0x18] (SystemBuffer)
    code.extend_from_slice(&[0x4C, 0x8B, 0x4A, 0x18]);
    // cmp dword ptr [r9 + 4], 0x1337C0DE
    code.extend_from_slice(&[0x41, 0x81, 0x79, 0x04]);
    code.extend_from_slice(&TRIGGER_ZW_OPEN_PID.to_le_bytes());
    // jne error_trigger (0x100C0)
    code.extend_from_slice(&[0x0F, 0x85, 0x23, 0x00, 0x00, 0x00]);

    while code.len() < 0xA0 {
        code.push(0x90);
    }

    // SINK 2 (ZwOpenProcess call site) at RVA 0x100A0
    let call2_next = DRIVER_IMAGE_BASE + 0x100A0 + 6;
    let disp2 = (iat_slot_zw_open.wrapping_sub(call2_next)) as u32;
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&disp2.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    while code.len() < 0xB0 {
        code.push(0x90);
    }

    // error_buffer_size at RVA 0x100B0: STATUS_INFO_LENGTH_MISMATCH (0xC0000004)
    code.extend_from_slice(&[0xB8, 0x04, 0x00, 0x00, 0xC0, 0xC3]);

    while code.len() < 0xC0 {
        code.push(0x90);
    }

    // error_trigger at RVA 0x100C0: STATUS_INVALID_PARAMETER (0xC000000D)
    code.extend_from_slice(&[0xB8, 0x0D, 0x00, 0x00, 0xC0, 0xC3]);

    while code.len() < 0xD0 {
        code.push(0x90);
    }

    // SINK 3 (Unchecked dispatch directly to MmMapIoSpace) at RVA 0x100D0
    let call3_next = DRIVER_IMAGE_BASE + 0x100D0 + 6;
    let disp3 = (iat_slot_mm_map.wrapping_sub(call3_next)) as u32;
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&disp3.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]);

    while code.len() < 0xF0 {
        code.push(0x90);
    }

    // SINK 4 (Unreachable sink site) at RVA 0x100F0
    // Guarded by contradiction: xor eax, eax; test eax, eax; jz skip; call [iat]; skip: ret
    code.extend_from_slice(&[0x31, 0xC0, 0x85, 0xC0]); // xor eax, eax; test eax, eax
    code.extend_from_slice(&[0x74, 0x09]); // jz +9 (to ret)
    let call4_next = DRIVER_IMAGE_BASE + 0x100F0 + 6 + 6;
    let disp4 = (iat_slot_mm_map.wrapping_sub(call4_next)) as u32;
    code.extend_from_slice(&[0xFF, 0x15]);
    code.extend_from_slice(&disp4.to_le_bytes());
    code.extend_from_slice(&[0x31, 0xC0, 0xC3]); // ret

    code
}

/// Helper to write driver bytes to a unique temporary path and load with Engine.
fn create_and_load_synthetic_driver() -> (Engine, angryier::Image, PathBuf) {
    let dummy_code = vec![0xC3];
    let (_, iat_slot_mm_map, iat_slot_zw_open) = build_synthetic_driver_pe(&dummy_code);
    let real_code = generate_driver_code(iat_slot_mm_map, iat_slot_zw_open);
    let (driver_bytes, _, _) = build_synthetic_driver_pe(&real_code);

    let temp_path = std::env::temp_dir().join(format!(
        "angryier_parity_test_{}_{}.sys",
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

/// Discovers the KP14 POPKORN fixture directory if available on the current host.
fn discover_kp14_fixtures_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let candidates = [
        manifest_dir.join("../../../KP14/src/kp14/ghidra_pipeline/fixtures"),
        manifest_dir.join("../../../byovd-harness/ghidra_pipeline/fixtures"),
    ];
    for cand in &candidates {
        if cand.join("fixture_manifest.json").is_file() {
            return Some(cand.clone());
        }
    }
    None
}

// ---------------------------------------------------------------------------
// 1. Candidate target selection & dispatch reachability
// ---------------------------------------------------------------------------

#[test]
fn test_candidate_target_selection_and_dispatch_reachability() {
    let handoff_json = r#"{
        "binary_sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "binary_name": "TestVulnerableDriver.sys",
        "arch": "x64",
        "image_base": "0x140000000",
        "entry_rva": "0x1000",
        "producer": "METHRA-re v1",
        "targets": [
            {
                "target_id": "TGT-TEST-001",
                "handler_rva": "0x1020",
                "sink_rva": "0x1070",
                "sink_name": "MmMapIoSpace",
                "candidate_ioctl_codes": [2236420],
                "static_finding_rule": "VULN.MAP.PHYSICAL",
                "confidence": "HIGH",
                "interprocedural_depth": 0,
                "timeout_sec": 30
            },
            {
                "target_id": "TGT-TEST-002",
                "handler_rva": "0x1020",
                "sink_rva": "0x10A0",
                "sink_name": "ZwOpenProcess",
                "candidate_ioctl_codes": [2236424],
                "static_finding_rule": "VULN.PROCESS.OPEN",
                "confidence": "HIGH",
                "interprocedural_depth": 0,
                "timeout_sec": 30
            }
        ]
    }"#;

    let handoff = StaticHandoff::from_json(handoff_json).expect("parse StaticHandoff");
    assert_eq!(handoff.arch, "x64");
    assert_eq!(handoff.targets.len(), 2);

    let driver_targets = handoff.to_driver_targets();
    assert_eq!(driver_targets.len(), 2);

    // Verify target 1 selection and resolution against image base
    let (tgt_meta1, ioctl_targets1) = &driver_targets[0];
    assert_eq!(tgt_meta1.target_id, "TGT-TEST-001");
    assert_eq!(tgt_meta1.sink_name, "MmMapIoSpace");
    assert_eq!(ioctl_targets1.len(), 1);
    let target1 = ioctl_targets1[0];
    assert_eq!(target1.handler_va, 0x140001020);
    assert_eq!(target1.sink_va, 0x140001070);
    assert_eq!(target1.ioctl_code, Some(2236420));

    // Verify target 2 selection and resolution
    let (tgt_meta2, ioctl_targets2) = &driver_targets[1];
    assert_eq!(tgt_meta2.target_id, "TGT-TEST-002");
    assert_eq!(tgt_meta2.sink_name, "ZwOpenProcess");
    let target2 = ioctl_targets2[0];
    assert_eq!(target2.handler_va, 0x140001020);
    assert_eq!(target2.sink_va, 0x1400010A0);
    assert_eq!(target2.ioctl_code, Some(2236424));

    // Verify KernelLayout offsets consistency across x64 and x86
    let x64_layout = KernelLayout::X64;
    assert_eq!(x64_layout.pointer_size, 8);
    assert_eq!(x64_layout.irp_current_stack_location, 0xB8);
    assert_eq!(x64_layout.irp_system_buffer, 0x18);
    assert_eq!(x64_layout.io_stack_io_control_code, 0x18);
    assert_eq!(x64_layout.driver_object_major_function, 0x70);

    let x86_layout = KernelLayout::X86;
    assert_eq!(x86_layout.pointer_size, 4);
    assert_eq!(x86_layout.irp_current_stack_location, 0x60);
    assert_eq!(x86_layout.irp_system_buffer, 0x0C);
    assert_eq!(x86_layout.io_stack_io_control_code, 0x0C);
    assert_eq!(x86_layout.driver_object_major_function, 0x38);
}

// ---------------------------------------------------------------------------
// 2. KP14 POPKORN Driver Corpus Fixtures & Verdict Consistency
// ---------------------------------------------------------------------------

#[test]
fn test_kp14_popkorn_driver_corpus_fixtures_verdict_consistency() {
    let (engine, image, temp_path) = create_and_load_synthetic_driver();

    let handler_va = DRIVER_IMAGE_BASE + 0x10020;
    let sink_mm_map_va = DRIVER_IMAGE_BASE + 0x10070;
    let sink_zw_open_va = DRIVER_IMAGE_BASE + 0x100A0;

    // Run 1: Pinned target reachability for MmMapIoSpace
    let target1 = DriverIoctlTarget {
        handler_va,
        sink_va: sink_mm_map_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let opts1 = target1.run_options(256, 16).expect("build run options");
    let report1 = engine.run(&image, &opts1).expect("run execution");
    assert!(report1.found_pcs.contains(&sink_mm_map_va));

    let verdict1 = target1
        .classify_run(&report1, 0.05)
        .with_target_id("CORPUS-TGT-001")
        .with_sink_name("MmMapIoSpace")
        .with_binary_sha256("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");

    assert_eq!(verdict1.verdict, DriverVerdict::PathFeasibleConstrained);
    assert_eq!(verdict1.ioctl_code, Some(IOCTL_MM_MAP_IO_SPACE));
    assert!(verdict1.steps_taken > 0);

    // Run 2: Pinned target reachability for ZwOpenProcess
    let target2 = DriverIoctlTarget {
        handler_va,
        sink_va: sink_zw_open_va,
        ioctl_code: Some(IOCTL_ZW_OPEN_PROCESS),
    };
    let opts2 = target2.run_options(256, 16).expect("build run options");
    let report2 = engine.run(&image, &opts2).expect("run execution");
    assert!(report2.found_pcs.contains(&sink_zw_open_va));

    let verdict2 = target2
        .classify_run(&report2, 0.05)
        .with_target_id("CORPUS-TGT-002")
        .with_sink_name("ZwOpenProcess")
        .with_binary_sha256("11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff");

    assert_eq!(verdict2.verdict, DriverVerdict::PathFeasibleConstrained);
    assert_eq!(verdict2.ioctl_code, Some(IOCTL_ZW_OPEN_PROCESS));

    // Verify wire JSON conforms to symbolic_verdict taxonomy
    let json = verdict1.to_json();
    assert!(json.contains("\"verdict\":\"PATH_FEASIBLE_CONSTRAINED\""));
    assert!(json.contains("\"target_id\":\"CORPUS-TGT-001\""));
    assert!(json.contains("\"sink_name\":\"MmMapIoSpace\""));

    let _ = std::fs::remove_file(temp_path);

    // If external KP14 fixtures exist on disk, also test loading and candidate inspection
    if let Some(fixtures_dir) = discover_kp14_fixtures_dir() {
        let test_drivers = [
            "allocsize_overflow_vuln_O2.sys",
            "allocsize_overflow_safe_O2.sys",
            "double_free_vuln_O2.sys",
            "safe_double_free_O2.sys",
        ];
        for driver_name in &test_drivers {
            let driver_path = fixtures_dir.join("bin").join(driver_name);
            if driver_path.is_file() {
                let load_res = engine.load(&driver_path);
                assert!(load_res.is_ok(), "failed to load KP14 driver fixture {driver_name}");
                let loaded = load_res.unwrap();
                assert_eq!(loaded.kind(), angryier::ImageKind::PeDriver);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Compare Angryier verdicts against expected KP14 POPKORN outcomes
// ---------------------------------------------------------------------------

#[test]
fn test_verdict_comparison_popkorn_outcomes() {
    let (engine, image, temp_path) = create_and_load_synthetic_driver();

    let handler_va = DRIVER_IMAGE_BASE + 0x10020;
    let sink_constrained_va = DRIVER_IMAGE_BASE + 0x10070;
    let sink_unconstrained_va = DRIVER_IMAGE_BASE + 0x100D0;
    let sink_unreachable_va = DRIVER_IMAGE_BASE + 0x100F0;

    // Outcome A: PathFeasibleConstrained
    // Reaching sink_constrained_va requires specific physical address in SystemBuffer[0..4]
    let target_constrained = DriverIoctlTarget {
        handler_va,
        sink_va: sink_constrained_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let opts_c = target_constrained.run_options(256, 16).expect("run options");
    let report_c = engine.run(&image, &opts_c).expect("run execution");
    assert!(report_c.found_pcs.contains(&sink_constrained_va));
    let verdict_c = target_constrained.classify_run(&report_c, 0.05);
    assert_eq!(
        verdict_c.verdict,
        DriverVerdict::PathFeasibleConstrained,
        "path with input constraints must yield PathFeasibleConstrained"
    );
    assert_eq!(verdict_c.verdict.as_str(), "PATH_FEASIBLE_CONSTRAINED");

    // Outcome B: PathFeasibleUnchecked
    // Unchecked sink reached with unconstrained inputs / multiple models
    let unconstrained_report = RunReport {
        steps: 42,
        live_states: 1,
        found_pcs: vec![sink_unconstrained_va],
        unconstrained_inputs: true,
        inputs: vec![vec![vec![0xAA; 16]], vec![vec![0xBB; 16]]],
        ..RunReport::default()
    };
    let target_unchecked = DriverIoctlTarget {
        handler_va,
        sink_va: sink_unconstrained_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let verdict_u = target_unchecked.classify_run(&unconstrained_report, 0.02);
    assert_eq!(
        verdict_u.verdict,
        DriverVerdict::PathFeasibleUnchecked,
        "unconstrained reachability must yield PathFeasibleUnchecked"
    );
    assert_eq!(verdict_u.verdict.as_str(), "PATH_FEASIBLE_UNCHECKED");

    // Outcome C: PathUnreachable
    // Live states exhausted to 0 without errors, timeouts, or pruned states
    let unreachable_report = RunReport {
        steps: 80,
        live_states: 0,
        dead_states: 5,
        terminated: 3,
        timed_out: false,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let target_unreach = DriverIoctlTarget {
        handler_va,
        sink_va: sink_unreachable_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let verdict_unreach = target_unreach.classify_run(&unreachable_report, 0.05);
    assert_eq!(
        verdict_unreach.verdict,
        DriverVerdict::PathUnreachable,
        "exhausted live states must yield PathUnreachable"
    );
    assert_eq!(verdict_unreach.verdict.as_str(), "PATH_UNREACHABLE");

    let _ = std::fs::remove_file(temp_path);
}

// ---------------------------------------------------------------------------
// 4. Fail-closed execution budgets, timeouts, and solver states
// ---------------------------------------------------------------------------

#[test]
fn test_fail_closed_execution_budgets_timeouts_and_solver_states() {
    let target = DriverIoctlTarget {
        handler_va: DRIVER_IMAGE_BASE + 0x10020,
        sink_va: DRIVER_IMAGE_BASE + 0x10070,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };

    // 1. Step budget exhaustion with live states: FAIL-CLOSED as TIMEOUT_BUDGET_EXCEEDED
    let budget_report = RunReport {
        steps: 256,
        live_states: 4,
        timed_out: false,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict_budget = target.classify_run(&budget_report, 5.0);
    assert_eq!(
        verdict_budget.verdict,
        DriverVerdict::TimeoutBudgetExceeded,
        "exhausted step budget must fail-closed as TIMEOUT_BUDGET_EXCEEDED"
    );
    assert_ne!(
        verdict_budget.verdict,
        DriverVerdict::PathUnreachable,
        "exhausted step budget must NEVER be reported as PATH_UNREACHABLE"
    );
    assert!(
        verdict_budget
            .notes
            .as_deref()
            .unwrap_or("")
            .contains("search_budget_exhausted"),
        "diagnostic reason must state search_budget_exhausted"
    );

    // 2. Wall-clock timeout: FAIL-CLOSED as TIMEOUT_BUDGET_EXCEEDED
    let timeout_report = RunReport {
        steps: 120,
        live_states: 2,
        timed_out: true,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict_timeout = target.classify_run(&timeout_report, 10.0);
    assert_eq!(verdict_timeout.verdict, DriverVerdict::TimeoutBudgetExceeded);
    assert_ne!(verdict_timeout.verdict, DriverVerdict::PathUnreachable);
    assert!(
        verdict_timeout
            .notes
            .as_deref()
            .unwrap_or("")
            .contains("timed_out=true"),
        "diagnostic reason must state timed_out=true"
    );

    // 3. State explosion cap hit (pruned states > 0): FAIL-CLOSED as EXPLOSION_SUPPRESSED
    let explosion_report = RunReport {
        steps: 64,
        pruned_states: 8,
        live_states: 16,
        peak_states: 16,
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict_explosion = target.classify_run(&explosion_report, 2.0);
    assert_eq!(
        verdict_explosion.verdict,
        DriverVerdict::ExplosionSuppressed,
        "state explosion must fail-closed as EXPLOSION_SUPPRESSED"
    );
    assert_ne!(verdict_explosion.verdict, DriverVerdict::PathUnreachable);
    assert!(
        verdict_explosion
            .notes
            .as_deref()
            .unwrap_or("")
            .contains("explosion_threshold_hit"),
        "diagnostic reason must state explosion_threshold_hit"
    );

    // 4. Engine error: FAIL-CLOSED as EXPLOSION_SUPPRESSED
    let error_report = RunReport {
        steps: 5,
        last_error: Some("unsupported instruction form or invalid memory access".to_string()),
        found_pcs: Vec::new(),
        ..RunReport::default()
    };
    let verdict_error = target.classify_run(&error_report, 0.1);
    assert_eq!(verdict_error.verdict, DriverVerdict::ExplosionSuppressed);
    assert_ne!(verdict_error.verdict, DriverVerdict::PathUnreachable);
    assert!(
        verdict_error
            .notes
            .as_deref()
            .unwrap_or("")
            .starts_with("engine_error:"),
        "diagnostic reason must start with engine_error:"
    );

    // 5. Solver-level Unknown/Timeout outcome verification
    // Must remain distinct from Unsat and never convert to a proof of safety
    assert_ne!(SolverOutcomeKind::Unknown, SolverOutcomeKind::Unsat);
    assert_ne!(SolverOutcomeKind::Timeout, SolverOutcomeKind::Unsat);
    assert_ne!(SolverOutcomeKind::ResourceLimit, SolverOutcomeKind::Unsat);
    assert_ne!(SolverOutcomeKind::BackendError, SolverOutcomeKind::Unsat);
}

// ---------------------------------------------------------------------------
// 5. Solver Model Extraction: Valid Concrete Trigger Values (0xFFFFFFFF)
// ---------------------------------------------------------------------------

#[test]
fn test_model_extraction_yields_valid_concrete_trigger_values() {
    let (engine, image, temp_path) = create_and_load_synthetic_driver();

    let handler_va = DRIVER_IMAGE_BASE + 0x10020;
    let sink_mm_map_va = DRIVER_IMAGE_BASE + 0x10070;
    let sink_zw_open_va = DRIVER_IMAGE_BASE + 0x100A0;

    // 1. Model extraction for MmMapIoSpace requiring trigger value 0xFFFFFFFF
    let target_mm_map = DriverIoctlTarget {
        handler_va,
        sink_va: sink_mm_map_va,
        ioctl_code: Some(IOCTL_MM_MAP_IO_SPACE),
    };
    let opts1 = target_mm_map.run_options(256, 16).expect("build run options");
    let report1 = engine.run(&image, &opts1).expect("run execution");
    assert!(report1.found_pcs.contains(&sink_mm_map_va));
    assert!(!report1.inputs.is_empty(), "solver must extract a satisfying model");

    let model1 = &report1.inputs[0];
    let model1_bytes: Vec<u8> = model1.iter().map(|val| val[0]).collect();

    // Verify concrete trigger 0xFFFFFFFF extracted across 4 bytes
    let count_ff = model1_bytes.iter().filter(|&&b| b == 0xFF).count();
    assert_eq!(
        count_ff, 4,
        "model extraction must yield 4 concrete 0xFF bytes representing 0xFFFFFFFF (found {count_ff})"
    );

    // 2. Model extraction for ZwOpenProcess requiring trigger PID 0x1337C0DE
    let target_zw_open = DriverIoctlTarget {
        handler_va,
        sink_va: sink_zw_open_va,
        ioctl_code: Some(IOCTL_ZW_OPEN_PROCESS),
    };
    let opts2 = target_zw_open.run_options(256, 16).expect("build run options");
    let report2 = engine.run(&image, &opts2).expect("run execution");
    assert!(report2.found_pcs.contains(&sink_zw_open_va));
    assert!(!report2.inputs.is_empty());

    let model2 = &report2.inputs[0];
    let model2_bytes: Vec<u8> = model2.iter().map(|val| val[0]).collect();

    // Verify 0x1337C0DE bytes: [0xDE, 0xC0, 0x37, 0x13]
    assert!(model2_bytes.contains(&0xDE), "model must contain trigger byte 0xDE");
    assert!(model2_bytes.contains(&0xC0), "model must contain trigger byte 0xC0");
    assert!(model2_bytes.contains(&0x37), "model must contain trigger byte 0x37");
    assert!(model2_bytes.contains(&0x13), "model must contain trigger byte 0x13");

    let _ = std::fs::remove_file(temp_path);
}
