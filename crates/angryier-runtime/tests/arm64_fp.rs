//! ANG-023 FP increment: scalar FP arithmetic executes end to end on the
//! concrete ARM64 path. Encodings generated with llvm-mc (aarch64).

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

fn f32_bits(register: u32, process: &angryier_runtime::Process) -> u32 {
    let value = process.read_register(register).unwrap();
    value as u32
}

#[test]
fn arm64_fp_arithmetic_concrete_execution() {
    let words: [u32; 10] = [
        0xD2A7_F800, // movz x0, #0x3fc0, lsl #16   -> x0 = 0x3FC00000 (1.5f32)
        0xB900_0BE0, // str w0, [sp, #8]
        0xBD40_0BE0, // ldr s0, [sp, #8]            -> s0 = 1.5
        0xBD40_0BE1, // ldr s1, [sp, #8]            -> s1 = 1.5
        0x1E21_2802, // fadd s2, s0, s1             -> 3.0
        0x1E22_0803, // fmul s3, s0, s2             -> 4.5
        0x1E21_4044, // fneg s4, s2                 -> -3.0
        0x1E21_C025, // fsqrt s5, s1                -> sqrt(1.5)
        0x1E21_2000, // fcmp s0, s1                 -> equal: NZCV = 0x40000000
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

    assert_eq!(f32_bits(36, &process), 0x3FC0_0000, "s0 = 1.5"); // V0
    assert_eq!(f32_bits(37, &process), 0x3FC0_0000, "s1 = 1.5"); // V1
    assert_eq!(f32_bits(38, &process), 0x4040_0000, "s2 = 3.0"); // V2
    assert_eq!(f32_bits(39, &process), 0x4090_0000, "s3 = 4.5"); // V3
    assert_eq!(f32_bits(40, &process), 0xC040_0000, "s4 = -3.0"); // V4
    let sqrt = f32::from_bits(f32_bits(41, &process)); // V5
    assert!((sqrt - 1.5f32.sqrt()).abs() < 1e-6, "s5 = sqrt(1.5)");
    assert_eq!(
        process.read_register(register_id::NZCV.0).unwrap(),
        0x4000_0000,
        "fcmp equal sets Z"
    );
}

/// FCVT width conversion and FCSEL conditional selection execute end to end.
/// Encodings generated with llvm-mc.
#[test]
fn arm64_fcvt_fcsel_concrete_execution() {
    let words: [u32; 9] = [
        0x1E6C_1000, // fmov d0, #0.5
        0x1E62_4001, // fcvt s1, d0         -> s1 = 0.5f
        0x1E2E_1002, // fmov s2, #1.0
        0x1E22_C046, // fcvt d6, s2         -> d6 = 1.0
        0xEB00_0000, // subs x0, x0, x0     -> Z = 1
        0x1E22_0C23, // fcsel s3, s1, s2, eq -> s3 = s1 = 0.5
        0x1E21_2020, // fcmp s1, s1         -> Z = 1
        0x1E22_1C25, // fcsel s5, s1, s2, ne -> s5 = s2 = 1.0
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

    assert_eq!(f32_bits(37, &process), 0x3F00_0000, "s1 = 0.5"); // V1
    let d6 = process.read_register(42).unwrap(); // V6
    assert_eq!(d6, 0x3FF0_0000_0000_0000, "d6 = 1.0");
    assert_eq!(f32_bits(39, &process), 0x3F00_0000, "s3 = s1 (EQ taken)"); // V3
    assert_eq!(f32_bits(41, &process), 0x3F80_0000, "s5 = s2 (NE not taken)"); // V5
}

#[test]
fn arm64_fmov_immediate_exhaustive_execution_and_scalar_aliasing() {
    for double in [false, true] {
        for imm8 in 0..256u32 {
            let word = 0x1E20_1000 | (u32::from(double) << 22) | (imm8 << 13) | 31;
            let code: Vec<u8> = [word, 0xD65F_03C0].iter().flat_map(|word| word.to_le_bytes()).collect();
            let runtime = Runtime::new_arm64(
                Arm64Decoder::with_profile_id(TargetProfileId(1)),
                SemanticVersion(1),
                TargetProfileId(1),
            );
            let mut process = runtime.load_elf(&build_test_elf(&code)).unwrap();
            process.state.registers.write_in_place(67, &[0xFF; 16]).unwrap();
            runtime.step(&mut process).unwrap();
            let exponent = ((imm8 >> 4) & 3) as i32 + if imm8 & 0x40 == 0 { 1 } else { -3 };
            let value =
                (16 + (imm8 & 15)) as f64 / 16.0 * 2f64.powi(exponent) * if imm8 & 0x80 == 0 { 1.0 } else { -1.0 };
            let expected = if double {
                value.to_bits()
            } else {
                u64::from((value as f32).to_bits())
            };
            let mut expected_parent = [0u8; 16];
            let width = if double { 8 } else { 4 };
            expected_parent[..width].copy_from_slice(&expected.to_le_bytes()[..width]);
            let angryier_state::RegisterValue::Concrete(actual) = process.state.registers.read_value(67).unwrap()
            else {
                panic!("concrete FP register")
            };
            assert_eq!(&*actual, &expected_parent, "{word:08x}");
            assert_eq!(process.read_register(register_id::PC.0).unwrap(), CODE_BASE + 4);
        }
    }
}

#[test]
fn arm64_scvtf_scalar_forms_rounding_aliases_and_zero_sources() {
    for (base, destination_bits, source_bits, general) in [
        (0x1E22_0000u32, 32, 32, true),
        (0x1E62_0000, 64, 32, true),
        (0x9E22_0000, 32, 64, true),
        (0x9E62_0000, 64, 64, true),
        (0x5E21_D800, 32, 32, false),
        (0x5E61_D800, 64, 64, false),
    ] {
        for value in [
            0i64,
            1,
            -1,
            16_777_217,
            16_777_219,
            i32::MIN as i64,
            i32::MAX as i64,
            i64::MIN,
            i64::MAX,
            0x4000_0040_0000_0001,
            -0x4000_0040_0000_0001,
        ] {
            for (rd, rn) in [(0, 1), (31, 31)] {
                let word = base | (rn << 5) | rd;
                let code: Vec<u8> = [word, 0xD65F_03C0].iter().flat_map(|word| word.to_le_bytes()).collect();
                let runtime = Runtime::new_arm64(
                    Arm64Decoder::with_profile_id(TargetProfileId(1)),
                    SemanticVersion(1),
                    TargetProfileId(1),
                );
                let mut process = runtime.load_elf(&build_test_elf(&code)).unwrap();
                process.state.registers.write_in_place(36 + rd, &[0xFF; 16]).unwrap();
                if general {
                    process.write_register(rn, value as u64).unwrap();
                } else {
                    let mut input = [0xA5u8; 16];
                    let width = source_bits / 8;
                    input[..width].copy_from_slice(&value.to_le_bytes()[..width]);
                    process.state.registers.write_in_place(36 + rn, &input).unwrap();
                }
                process.write_register(register_id::SP.0, 0x1234).unwrap();
                process
                    .state
                    .registers
                    .write_in_place(register_id::NZCV.0, &0xA000_0000u32.to_le_bytes())
                    .unwrap();
                runtime.step(&mut process).unwrap();
                let signed = if general && rn == 31 {
                    0
                } else if source_bits == 32 {
                    value as i32 as i64
                } else {
                    value
                };
                let raw = if destination_bits == 32 {
                    u64::from((signed as f32).to_bits())
                } else {
                    (signed as f64).to_bits()
                };
                let mut expected = [0u8; 16];
                let width = destination_bits / 8;
                expected[..width].copy_from_slice(&raw.to_le_bytes()[..width]);
                let angryier_state::RegisterValue::Concrete(actual) =
                    process.state.registers.read_value(36 + rd).unwrap()
                else {
                    panic!("concrete SCVTF result")
                };
                assert_eq!(&*actual, &expected, "{word:08x} {value}");
                assert_eq!(process.read_register(register_id::NZCV.0).unwrap(), 0xA000_0000);
                assert_eq!(process.read_register(register_id::SP.0).unwrap(), 0x1234);
                if general {
                    assert_eq!(process.read_register(rn).unwrap(), value as u64);
                }
            }
        }
    }
}

#[test]
fn arm64_scvtf_vector_lanes_and_in_place_aliasing() {
    for (base, lane_bits, lanes) in [(0x0E21_D800u32, 32, 2), (0x4E21_D800, 32, 4), (0x4E61_D800, 64, 2)] {
        for (rd, rn) in [(0, 1), (31, 31)] {
            let word = base | (rn << 5) | rd;
            let code: Vec<u8> = [word, 0xD65F_03C0].iter().flat_map(|word| word.to_le_bytes()).collect();
            let runtime = Runtime::new_arm64(
                Arm64Decoder::with_profile_id(TargetProfileId(1)),
                SemanticVersion(1),
                TargetProfileId(1),
            );
            let mut process = runtime.load_elf(&build_test_elf(&code)).unwrap();
            let mut source = [0xA5u8; 16];
            let mut expected = [0u8; 16];
            let values = if lane_bits == 32 {
                [-1i64, 16_777_219, i32::MIN as i64, i32::MAX as i64]
            } else {
                [0x4000_0040_0000_0001, i64::MIN, 0, 0]
            };
            let width = lane_bits / 8;
            for lane in 0..lanes {
                source[lane * width..(lane + 1) * width].copy_from_slice(&values[lane].to_le_bytes()[..width]);
                let raw = if lane_bits == 32 {
                    u64::from((values[lane] as i32 as f32).to_bits())
                } else {
                    (values[lane] as f64).to_bits()
                };
                expected[lane * width..(lane + 1) * width].copy_from_slice(&raw.to_le_bytes()[..width]);
            }
            process.state.registers.write_in_place(36 + rd, &[0xFF; 16]).unwrap();
            process.state.registers.write_in_place(36 + rn, &source).unwrap();
            runtime.step(&mut process).unwrap();
            let angryier_state::RegisterValue::Concrete(actual) = process.state.registers.read_value(36 + rd).unwrap()
            else {
                panic!("concrete SCVTF vector")
            };
            assert_eq!(&*actual, &expected, "{word:08x}");
        }
    }
}

#[test]
fn arm64_fcvtz_all_forms_and_boundaries() {
    for (word, double, bits, unsigned) in [
        (0x1E38_0001u32, false, 32, false),
        (0x1E78_0001, true, 32, false),
        (0x9E38_0001, false, 64, false),
        (0x9E78_0001, true, 64, false),
        (0x1E39_0001, false, 32, true),
        (0x1E79_0001, true, 32, true),
        (0x9E39_0001, false, 64, true),
        (0x9E79_0001, true, 64, true),
    ] {
        let signed_min = 1u64 << (bits - 1);
        let signed_max = signed_min - 1;
        let unsigned_max = if bits == 32 { u32::MAX as u64 } else { u64::MAX };
        // FMOV GPR -> FP avoids depending on immediate expansion for NaNs,
        // infinities and boundaries. Each case starts with a dirty X1 parent.
        let words = [if double { 0x9E67_0000 } else { 0x1E27_0000 }, word, 0xD65F_03C0];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let decoder = Arm64Decoder::with_profile_id(TargetProfileId(1));
        let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), TargetProfileId(1));
        let elf = build_test_elf(&code);
        for (input, signed, positive) in [
            (3.75f64, 3, 3),
            (-3.75, if bits == 32 { 0xffff_fffd } else { u64::MAX - 2 }, 0),
            (0.0, 0, 0),
            (-0.0, 0, 0),
            (f64::from(f32::from_bits(1)), 0, 0),
            (f64::NAN, 0, 0),
            (f64::INFINITY, signed_max, unsigned_max),
            (f64::NEG_INFINITY, signed_min, 0),
            (
                2147483648.0,
                if bits == 32 { signed_max } else { 2147483648 },
                2147483648,
            ),
            (
                4294967296.0,
                if bits == 32 { signed_max } else { 4294967296 },
                if bits == 32 { unsigned_max } else { 4294967296 },
            ),
            (
                9223372036854775808.0,
                signed_max,
                if bits == 32 {
                    unsigned_max
                } else {
                    0x8000_0000_0000_0000
                },
            ),
            (18446744073709551616.0, signed_max, unsigned_max),
        ] {
            let raw = if double {
                input.to_bits()
            } else {
                u64::from((input as f32).to_bits())
            };
            let expected = if unsigned { positive } else { signed };
            let mut process = runtime.load_elf(&elf).unwrap();
            process.write_register(register_id::X0.0, raw).unwrap();
            process.write_register(register_id::X1.0, u64::MAX).unwrap();
            runtime.step(&mut process).unwrap();
            runtime.step(&mut process).unwrap();
            assert_eq!(process.read_register(register_id::PC.0).unwrap(), CODE_BASE + 8);
            assert_eq!(
                process.read_register(register_id::X1.0).unwrap(),
                expected,
                "{word:08x} input {input:?}"
            );
            assert_eq!(
                process.read_register(register_id::V0.0).unwrap(),
                raw,
                "conversion must preserve its S/D source"
            );
            assert_eq!(process.read_register(register_id::X0.0).unwrap(), raw);
        }
    }
}

#[test]
fn arm64_fcvtz_zero_register_destinations_discard_results() {
    for base in [
        0x1E38_0000u32,
        0x1E78_0000,
        0x9E38_0000,
        0x9E78_0000,
        0x1E39_0000,
        0x1E79_0000,
        0x9E39_0000,
        0x9E79_0000,
    ] {
        let double = base & (1 << 22) != 0;
        let words = [if double { 0x9E67_0000 } else { 0x1E27_0000 }, base | 31, 0xD65F_03C0];
        let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
        let runtime = Runtime::new_arm64(
            Arm64Decoder::with_profile_id(TargetProfileId(1)),
            SemanticVersion(1),
            TargetProfileId(1),
        );
        let mut process = runtime.load_elf(&build_test_elf(&code)).unwrap();
        process
            .write_register(
                register_id::X0.0,
                if double {
                    3.75f64.to_bits()
                } else {
                    u64::from(3.75f32.to_bits())
                },
            )
            .unwrap();
        process.write_register(register_id::SP.0, 0x1234).unwrap();
        runtime.step(&mut process).unwrap();
        runtime.step(&mut process).unwrap();
        assert_eq!(process.read_register(register_id::ZR.0).unwrap(), 0, "{base:08x}");
        assert_eq!(process.read_register(register_id::SP.0).unwrap(), 0x1234);
    }
}

#[test]
fn arm64_fcsel_all_conditions_and_nzcv() {
    for double in [false, true] {
        for cond in 0..16u32 {
            // Non-sample register fields, including V31 as a normal FP register.
            let words = [
                if double { 0x9E67_0011u32 } else { 0x1E27_0011 }, // fmov s/d17,w/x0
                if double { 0x9E67_003E } else { 0x1E27_003E },    // fmov s/d30,w/x1
                0x1E3E_0E3F | (u32::from(double) << 22) | (cond << 12),
                0xD65F_03C0,
            ];
            let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
            let runtime = Runtime::new_arm64(
                Arm64Decoder::with_profile_id(TargetProfileId(1)),
                SemanticVersion(1),
                TargetProfileId(1),
            );
            let elf = build_test_elf(&code);
            let first = if double {
                1.25f64.to_bits()
            } else {
                u64::from(1.25f32.to_bits())
            };
            let second = if double {
                (-2.5f64).to_bits()
            } else {
                u64::from((-2.5f32).to_bits())
            };
            for flags in 0..16u32 {
                let n = flags & 8 != 0;
                let z = flags & 4 != 0;
                let c = flags & 2 != 0;
                let v = flags & 1 != 0;
                let take_first = match cond {
                    0 => z,
                    1 => !z,
                    2 => c,
                    3 => !c,
                    4 => n,
                    5 => !n,
                    6 => v,
                    7 => !v,
                    8 => c && !z,
                    9 => !c || z,
                    10 => n == v,
                    11 => n != v,
                    12 => !z && n == v,
                    13 => z || n != v,
                    _ => true, // AL and NV both hold in A64 ConditionHolds.
                };
                let mut process = runtime.load_elf(&elf).unwrap();
                process.write_register(register_id::X0.0, first).unwrap();
                process.write_register(register_id::X1.0, second).unwrap();
                process
                    .state
                    .registers
                    .write_in_place(register_id::NZCV.0, &(flags << 28).to_le_bytes())
                    .unwrap();
                for _ in 0..3 {
                    runtime.step(&mut process).unwrap();
                }
                assert_eq!(
                    process.read_register(67).unwrap(),
                    if take_first { first } else { second },
                    "double={double} cond={cond} NZCV={flags:x}"
                );
                assert_eq!(
                    process.read_register(register_id::NZCV.0).unwrap(),
                    u64::from(flags << 28)
                );
            }
        }
    }
}
