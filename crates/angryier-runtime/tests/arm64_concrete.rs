//! ANG-090 phase 1: end-to-end concrete execution of a hand-assembled A64
//! program through the ARM64 runtime backend.
//!
//! The program is assembled from fixed A64 machine words (no external samples,
//! no Titan corpus, no network): it exercises wide-immediate move, add/sub
//! (immediate and register with flags), a `cbnz` backward loop, a `str`/`ldr`
//! stack round-trip, and `ret`, then asserts the final architectural state.

#![allow(clippy::unwrap_used, clippy::panic)]

use angryier_arch::Decoder;
use angryier_arch_arm64::{Arm64Decoder, regs::register_id};
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

/// Base address of the first instruction in the minimal ELF harness. The ELF
/// header/single PT_LOAD layout matches `jni_reachability_test.rs`.
const CODE_BASE: u64 = 0x400078;
/// Generous bound for the deterministic program (4 straight-line + 7*2 loop
/// iterations + 2 memory + 1 ret = 21 steps).
const STEP_BUDGET: u64 = 64;

/// Minimal 64-bit ELF carrier matching the `jni_reachability_test.rs` harness.
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
fn arm64_concrete_execution_end_to_end() {
    let words: [u32; 9] = [
        0xD280_00A0, // movz x0, #5
        0x9100_0C00, // add  x0, x0, #3
        0xD100_0401, // sub  x1, x0, #1
        0xEB00_0042, // subs x2, x2, x0        (x2 = -8; N set)
        0xD100_0421, // sub  x1, x1, #1        (loop body)
        0xB5FF_FFE1, // cbnz x1, -4            (loop back while x1 != 0)
        0xB900_0BE0, // str  w0, [sp, #8]
        0xB940_0BE2, // ldr  w2, [sp, #8]
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

    // The ARM64 runtime seeds the AArch64 SP register directly from the ELF
    // loader's initial stack pointer; assert it points at mapped memory.
    let stack_pointer = process.read_register(register_id::SP.0).unwrap();
    assert!(stack_pointer > 0, "SP must be seeded by the ARM64 load path");

    // Step until the program counter reaches the trailing `ret`; all observable
    // state (x0, x2, NZCV) is final there, before the indirect branch runs.
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

    assert_eq!(
        process.read_register(register_id::X0.0).unwrap(),
        8,
        "movz #5 + add #3 => x0 == 8"
    );
    assert_eq!(
        process.read_register(register_id::X1.0).unwrap(),
        0,
        "cbnz loop decrements x1 to zero"
    );
    assert_eq!(
        process.read_register(register_id::X2.0).unwrap(),
        8,
        "ldr w2,[sp,#8] reloads the low 32 bits of x0 written by str w0"
    );
    assert_eq!(
        process.read_register(register_id::NZCV.0).unwrap(),
        0x8000_0000,
        "subs x2,x2,x0 (0-8) is negative => N set, Z/C/V clear"
    );
}

/// ANG-023 extension: carry arithmetic, long multiply, divide, and
/// pre-index write-back execute end-to-end on the concrete ARM64 path.
/// Encodings generated with llvm-mc (aarch64).
#[test]
fn arm64_extended_arithmetic_concrete_execution() {
    let words: [u32; 9] = [
        0xD280_0100, // movz x0, #8
        0xD280_0061, // movz x1, #3
        0xAB01_0002, // adds x2, x0, x1      -> x2 = 11, NZCV = 0
        0xBA01_0003, // adcs x3, x0, x1      -> x3 = 11 + C(0) = 11
        0xDA01_0044, // sbc  x4, x2, x1      -> x4 = 11 - 3 - 1 + C(0) = 7
        0x9BA1_7C05, // umull x5, w0, w1     -> x5 = 24
        0x9AC1_0846, // udiv x6, x2, x1      -> x6 = 3
        0xF81F_0FFE, // str x30, [sp, #-16]! -> pre-index write-back
        0xD65F_03C0, // ret
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let target_profile = TargetProfileId(1);
    let decoder = Arm64Decoder::with_profile_id(target_profile);
    let elf = build_test_elf(&code);
    let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), target_profile);
    let mut process = runtime.load_elf(&elf).unwrap();

    let sp_before = process.read_register(register_id::SP.0).unwrap();
    let mut steps = 0u64;
    while steps < 64 {
        let pc = process.read_register(register_id::PC.0).unwrap();
        if pc == CODE_BASE + (words.len() as u64 - 1) * 4 {
            break;
        }
        runtime.step(&mut process).unwrap();
        steps += 1;
    }

    assert_eq!(process.read_register(register_id::X2.0).unwrap(), 11, "adds");
    assert_eq!(process.read_register(register_id::X3.0).unwrap(), 11, "adcs with C=0");
    assert_eq!(process.read_register(register_id::X4.0).unwrap(), 7, "sbc with C=0");
    assert_eq!(process.read_register(register_id::X5.0).unwrap(), 24, "umull");
    assert_eq!(process.read_register(register_id::X6.0).unwrap(), 3, "udiv");
    assert_eq!(
        process.read_register(register_id::NZCV.0).unwrap(),
        0,
        "adds 8+3 sets no flags"
    );
    let sp_after = process.read_register(register_id::SP.0).unwrap();
    assert_eq!(sp_before.wrapping_sub(sp_after), 16, "pre-index str write-back");
}

#[test]
fn arm64_bit_test_register_offset_and_pair_postindex_concrete() {
    let words: [u32; 13] = [
        0x5280_0400, // movz w0, #32
        0x3628_0040, // tbz w0, #5, +8 (must not branch)
        0xD280_0221, // movz x1, #0x11
        0xD280_0442, // movz x2, #0x22
        0xA881_0BE1, // stp x1, x2, [sp], #16
        0xA97F_17E4, // ldp x4, x5, [sp, #-16]
        0x1280_0007, // movn w7, #0 -> w7 = -1
        0x5280_0AA8, // movz w8, #0x55
        0xB81F_C3E8, // stur w8, [sp, #-4]
        0xB867_DBE6, // ldr w6, [sp, w7, sxtw #2]
        0xD2C0_2009, // movz x9, #0x100, lsl #32
        0xB740_0049, // tbnz x9, #40, +8 (must branch)
        0x529B_D5A8, // movz w8, #0xdead (must be skipped)
    ];
    let mut code_words = words.to_vec();
    code_words.push(0xD65F_03C0); // ret
    let code: Vec<u8> = code_words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let target_profile = TargetProfileId(1);
    let decoder = Arm64Decoder::with_profile_id(target_profile);
    let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), target_profile);
    let mut process = runtime.load_elf(&build_test_elf(&code)).unwrap();
    let ret_address = CODE_BASE + (code_words.len() as u64 - 1) * 4;
    let sp_before = process.read_register(register_id::SP.0).unwrap();
    for _ in 0..64 {
        if process.read_register(register_id::PC.0).unwrap() == ret_address {
            break;
        }
        let pc = process.read_register(register_id::PC.0).unwrap();
        runtime
            .step(&mut process)
            .unwrap_or_else(|error| panic!("step failed at {pc:#x}: {error:?}"));
    }

    assert_eq!(
        process.read_register(register_id::X4.0).unwrap(),
        0x11,
        "post-index pair reads at old base"
    );
    assert_eq!(
        process.read_register(register_id::X5.0).unwrap(),
        0x22,
        "second pair element follows first"
    );
    assert_eq!(
        process.read_register(register_id::SP.0).unwrap(),
        sp_before + 16,
        "post-index writeback updates SP"
    );
    assert_eq!(
        process.read_register(register_id::X6.0).unwrap(),
        0x55,
        "SXTW index sign-extends before scaling"
    );
    assert_eq!(
        process.read_register(register_id::X8.0).unwrap(),
        0x55,
        "TBNZ tests encoded bit 40 and skips marker"
    );
}
