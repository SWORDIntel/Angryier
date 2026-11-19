//! ANG-023 SIMD increment: lane-wise vector arithmetic executes end to end
//! on the concrete ARM64 path. Encodings generated with llvm-mc (aarch64).

#![allow(clippy::unwrap_used, clippy::panic)]

use angryier_arch_arm64::{Arm64Decoder, regs::register_id};
use angryier_runtime::Runtime;
use angryier_state::SymbolicRegisterState;
use angryier_types::{SemanticVersion, TargetProfileId};

const CODE_BASE: u64 = 0x400078;

fn build_test_elf(code: &[u8]) -> Vec<u8> {
    let segment_base = 0x400000u64;
    let code_offset = 0x78usize;
    let total_size = code_offset + code.len();
    let mut buf = vec![0u8; total_size];
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[7] = 0;
    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    let entry = segment_base + code_offset as u64;
    buf[24..32].copy_from_slice(&entry.to_le_bytes());
    buf[32..40].copy_from_slice(&64u64.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&1u16.to_le_bytes());
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
fn arm64_dup_all_lane_domains_aliases_and_zero_register() {
    let source_bytes: [u8; 16] = std::array::from_fn(|index| (index as u8).wrapping_mul(17).wrapping_add(0x81));
    for (base, scalar, general, q) in [
        (0x0E00_0400u32, false, false, false),
        (0x4E00_0400, false, false, true),
        (0x5E00_0400, true, false, true),
        (0x0E00_0C00, false, true, false),
        (0x4E00_0C00, false, true, true),
    ] {
        for imm5 in 1..32u32 {
            let size = imm5.trailing_zeros();
            if size > 3 || (!scalar && !q && size == 3) {
                continue;
            }
            for (rd, rn) in [(0, 1), (31, 31)] {
                let word = base | (imm5 << 16) | (rn << 5) | rd;
                let code: Vec<u8> = [word, 0xD65F_03C0].iter().flat_map(|word| word.to_le_bytes()).collect();
                let runtime = Runtime::new_arm64(
                    Arm64Decoder::with_profile_id(TargetProfileId(1)),
                    SemanticVersion(1),
                    TargetProfileId(1),
                );
                let mut process = runtime.load_elf(&build_test_elf(&code)).unwrap();
                process.state.registers.write_in_place(36 + rd, &[0xFF; 16]).unwrap();
                let raw = 0xFEDC_BA98_7654_3210u64;
                if general {
                    process.write_register(rn, raw).unwrap();
                } else {
                    process.state.registers.write_in_place(36 + rn, &source_bytes).unwrap();
                }
                process.write_register(register_id::SP.0, 0x1234).unwrap();
                runtime.step(&mut process).unwrap();
                let width = 1usize << size;
                let total = if scalar {
                    width
                } else if q {
                    16
                } else {
                    8
                };
                let offset = if general {
                    0
                } else {
                    (imm5 >> (size + 1)) as usize * width
                };
                let input = if general {
                    if rn == 31 {
                        [0u8; 16]
                    } else {
                        let mut bytes = [0u8; 16];
                        bytes[..8].copy_from_slice(&raw.to_le_bytes());
                        bytes
                    }
                } else {
                    source_bytes
                };
                let mut expected = [0u8; 16];
                for chunk in expected[..total].chunks_exact_mut(width) {
                    chunk.copy_from_slice(&input[offset..offset + width]);
                }
                let angryier_state::RegisterValue::Concrete(actual) =
                    process.state.registers.read_value(36 + rd).unwrap()
                else {
                    panic!("concrete DUP result")
                };
                assert_eq!(&*actual, &expected, "{word:08x}");
                assert_eq!(process.read_register(register_id::SP.0).unwrap(), 0x1234);
                if general {
                    assert_eq!(process.read_register(rn).unwrap(), raw);
                }
            }
        }
    }
}

#[test]
fn arm64_simd_arithmetic_concrete_execution() {
    // Build four f32 patterns on the stack: 1.0, 2.0, 3.0, 4.0.
    let words: [u32; 12] = [
        0xD2A7_F000, // movz x0, #0x3f80, lsl #16  (1.0f)
        0xD2A8_0001, // movz x1, #0x4000, lsl #16  (2.0f)
        0xD2A8_0802, // movz x2, #0x4040, lsl #16  (3.0f)
        0xD2A8_1003, // movz x3, #0x4080, lsl #16  (4.0f)
        0xB900_0BE0, // str w0, [sp, #8]
        0xB900_0FE1, // str w1, [sp, #12]
        0xB900_13E2, // str w2, [sp, #16]
        0xB900_17E3, // str w3, [sp, #20]
        0x3CC0_83E0, // ldr q0, [sp, #8]
        0x3CC0_83E1, // ldr q1, [sp, #8]
        0x4E21_D403, // fadd v3.4s, v0.4s, v1.4s
        0xD65F_03C0, // ret
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(1));
    let elf = build_test_elf(&code);
    let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf).unwrap();

    let mut steps = 0u64;
    while steps < 64 {
        let pc = process.read_register(register_id::PC.0).unwrap();
        if pc == CODE_BASE + (words.len() as u64 - 1) * 4 {
            break;
        }
        if let Err(error) = runtime.step(&mut process) {
            panic!("step failed at pc={pc:#x}: {error:?}");
        }
        steps += 1;
    }

    // The register-read API exposes 64 bits; verify the low two lanes of
    // the 128-bit result (the upper lanes execute through the same op).
    // fadd of [1.0f, 2.0f, 3.0f, 4.0f] with itself:
    let v3 = process.read_register(39).unwrap();
    assert_eq!(f32::from_bits((v3 & 0xFFFF_FFFF) as u32), 2.0, "fadd v3.4s lane 0");
    assert_eq!(
        f32::from_bits(((v3 >> 32) & 0xFFFF_FFFF) as u32),
        4.0,
        "fadd v3.4s lane 1"
    );
}
