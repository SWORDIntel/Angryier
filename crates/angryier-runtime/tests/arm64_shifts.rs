//! End-to-end concrete execution of the A64 variable-shift family (LSLV/LSRV/
//! ASRV/RORV, W and X) through the ARM64 runtime backend.
//!
//! The program is assembled from llvm-mc machine words (no external samples,
//! no Titan corpus, no network) and exercises every shift kind plus the
//! 32-bit zero-extending write path before `ret`.

#![allow(clippy::unwrap_used, clippy::panic)]

use angryier_arch::Decoder;
use angryier_arch_arm64::{Arm64Decoder, regs::register_id};
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

/// Base address of the first instruction in the minimal ELF harness. The ELF
/// header/single PT_LOAD layout matches `arm64_concrete.rs`.
const CODE_BASE: u64 = 0x400078;
/// Generous bound for the straight-line program (11 instructions).
const STEP_BUDGET: u64 = 64;

/// Minimal 64-bit ELF carrier matching the `arm64_concrete.rs` harness.
///
/// `e_machine` stays `EM_X86_64` because `Elf64Loader` (ANG-090 phase 1) only
/// accepts that machine; the AArch64 decoder never reads the ELF header — it
/// decodes the bytes at the program counter — so the A64 words ride in the
/// executable text segment unchanged.
fn build_test_elf(code: &[u8]) -> Vec<u8> {
    let segment_base = 0x400000u64;
    let code_offset = 0x78usize;
    let total_size = code_offset + code.len();
    let mut buf = vec![0u8; total_size];

    // ELF magic
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // 64-bit
    buf[5] = 1; // little endian
    buf[6] = 1; // version 1
    buf[7] = 0; // SYSV ABI

    // Header fields
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
    let entry = segment_base + code_offset as u64;
    buf[24..32].copy_from_slice(&entry.to_le_bytes()); // entry
    buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum

    // Program header (PT_LOAD, R|X)
    buf[64..68].copy_from_slice(&1u32.to_le_bytes());
    buf[68..72].copy_from_slice(&5u32.to_le_bytes());
    buf[72..80].copy_from_slice(&0u64.to_le_bytes());
    buf[80..88].copy_from_slice(&segment_base.to_le_bytes());
    buf[88..96].copy_from_slice(&segment_base.to_le_bytes());
    buf[96..104].copy_from_slice(&(total_size as u64).to_le_bytes());
    buf[104..112].copy_from_slice(&(total_size as u64).to_le_bytes());
    buf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

    buf[code_offset..code_offset + code.len()].copy_from_slice(code);
    buf
}

#[test]
fn arm64_variable_shift_concrete_execution() {
    let words: [u32; 11] = [
        0xD280_0020, // movz x0, #1
        0xD280_0041, // movz x1, #2
        0x9AC1_2002, // lslv x2, x0, x1        -> 1 << 2 = 4
        0x9AC0_2423, // lsrv x3, x1, x0        -> 2 >> 1 = 1
        0xD2F0_0004, // movz x4, #0x8000, lsl #48
        0x9AC1_2885, // asrv x5, x4, x1        -> 0x8000.. >> 2 = 0xE000000000000000
        0x9AC1_2C06, // rorv x6, x0, x1        -> ROR(1, 2) = 0x4000000000000000
        0x5280_0027, // movz w7, #1
        0x5280_0088, // movz w8, #4
        0x1AC8_20E9, // lslv w9, w7, w8        -> 1 << 4 = 16 (32-bit path)
        0xD65F_03C0, // ret
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    let target_profile = TargetProfileId(1);
    let decoder = Arm64Decoder::with_profile_id(target_profile);

    // Deterministic pre-flight: every hand-assembled word must decode as a
    // 4-byte A64 instruction before execution is attempted.
    for (index, word) in words.iter().enumerate() {
        let address = CODE_BASE + (index as u64) * 4;
        let decoded = decoder
            .decode(address, &word.to_le_bytes())
            .unwrap_or_else(|error| panic!("A64 word {word:#010x} must decode: {error}"));
        assert_eq!(decoded.length, 4, "instruction {index} must be 4 bytes");
    }

    let elf = build_test_elf(&code);
    let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), target_profile);
    let mut process = runtime.load_elf(&elf).unwrap();

    // Step until the program counter reaches the trailing `ret`; all observable
    // state is final there, before the indirect branch runs.
    let ret_address = CODE_BASE + (words.len() as u64 - 1) * 4;
    let mut steps = 0u64;
    while steps < STEP_BUDGET {
        let pc = process.read_register(register_id::PC.0).unwrap();
        if pc == ret_address {
            break;
        }
        if let Err(error) = runtime.step(&mut process) {
            panic!("step failed at pc={pc:#x}: {error:?}");
        }
        steps += 1;
        if process.terminated {
            break;
        }
    }

    assert_eq!(process.read_register(register_id::X0.0).unwrap(), 1, "movz x0,#1");
    assert_eq!(process.read_register(register_id::X1.0).unwrap(), 2, "movz x1,#2");
    assert_eq!(process.read_register(register_id::X2.0).unwrap(), 4, "lslv x2 = 1<<2");
    assert_eq!(process.read_register(register_id::X3.0).unwrap(), 1, "lsrv x3 = 2>>1");
    assert_eq!(
        process.read_register(register_id::X4.0).unwrap(),
        0x8000_0000_0000_0000,
        "movz x4,#0x8000,lsl#48"
    );
    assert_eq!(
        process.read_register(register_id::X5.0).unwrap(),
        0xE000_0000_0000_0000,
        "asrv x5 = sign >> 2"
    );
    assert_eq!(
        process.read_register(register_id::X6.0).unwrap(),
        0x4000_0000_0000_0000,
        "rorv x6 = ROR(1,2)"
    );
    assert_eq!(process.read_register(register_id::X7.0).unwrap(), 1, "movz w7,#1");
    assert_eq!(process.read_register(register_id::X8.0).unwrap(), 4, "movz w8,#4");
    assert_eq!(process.read_register(register_id::X9.0).unwrap(), 16, "lslv w9 = 1<<4");
}
