#![forbid(unsafe_code)]

//! Runtime tests for string port I/O instruction family with REP prefix:
//! REP INSB, REP INSW, REP INSD, REP OUTSB, REP OUTSW, REP OUTSD.
//!
//! Validates:
//! - execution through `runtime.step` in `execute_string_instruction`
//! - RCX loop count decrement to 0
//! - zero-fill of memory at [RDI] for REP IN*
//! - dropping values read from [RSI] for REP OUT*
//! - RDI / RSI advancement by count * size (DF = 0)
//! - RDI / RSI decrement by count * size (DF = 1)
//! - zero loop count (RCX = 0) edge case

use angryier_arch_intel64::register_id;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::{Runtime, StepOutcome};
use angryier_types::{SemanticVersion, TargetProfileId};

const IMAGE_BASE: u64 = 0x140000000;
const ENTRY_RVA: u32 = 0x1000;
const ENTRY_VA: u64 = IMAGE_BASE + ENTRY_RVA as u64;
const BUFFER_VA: u64 = ENTRY_VA + 0x800;

const RCX: u32 = register_id::GPR_BASE + 1;
const RSI: u32 = register_id::GPR_BASE + 6;
const RDI: u32 = register_id::GPR_BASE + 7;
const RFLAGS: u32 = register_id::RFLAGS.0;
const DF_BIT: u64 = 1 << 10;

type BoxError = Box<dyn std::error::Error>;

fn make_test_pe(code: &[u8]) -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
    pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
    pe[0xA8..0xAC].copy_from_slice(&ENTRY_RVA.to_le_bytes());
    pe[0xB0..0xB8].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
    pe[0x190..0x194].copy_from_slice(&0x1000u32.to_le_bytes()); // virtual size 4096
    pe[0x194..0x198].copy_from_slice(&ENTRY_RVA.to_le_bytes()); // va 0x1000
    pe[0x198..0x19C].copy_from_slice(&0x1000u32.to_le_bytes()); // raw size 4096
    pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr 0x200
    pe[0x1AC..0x1B0].copy_from_slice(&0xE000_0000u32.to_le_bytes()); // EXEC | READ | WRITE
    pe.resize(0x200 + 0x1000, 0);
    pe[0x200..0x200 + code.len()].copy_from_slice(code);
    pe
}

#[test]
fn test_rep_insb_forward() -> Result<(), BoxError> {
    // REP INSB: F3 6C
    let pe = make_test_pe(&[0xF3, 0x6C]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    // Seed 4 bytes of non-zero data at BUFFER_VA
    let initial_data = [ByteValue::Concrete(0xAA); 4];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 4)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?; // DF = 0

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    // RCX must be 0
    assert_eq!(process.read_register(RCX)?, 0, "RCX should decrement to 0");
    // RDI must advance by 4
    assert_eq!(process.read_register(RDI)?, BUFFER_VA + 4, "RDI should advance by 4");

    // Memory at BUFFER_VA must be 4 zero bytes
    let mut buf = [ByteValue::Concrete(0xFF); 4];
    process
        .state
        .memory
        .read_into(BUFFER_VA, &mut buf)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0); 4], "Memory must be zeroed");

    Ok(())
}

#[test]
fn test_rep_insb_backward() -> Result<(), BoxError> {
    // REP INSB: F3 6C with DF = 1
    let pe = make_test_pe(&[0xF3, 0x6C]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    let initial_data = [ByteValue::Concrete(0xBB); 4];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA - 3, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 3)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, DF_BIT)?; // DF = 1

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RDI)?, BUFFER_VA - 3, "RDI decrements by 3");

    // Bytes at BUFFER_VA, BUFFER_VA - 1, BUFFER_VA - 2 must be zeroed
    let mut buf = [ByteValue::Concrete(0xFF); 3];
    process
        .state
        .memory
        .read_into(BUFFER_VA - 2, &mut buf)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0); 3]);

    Ok(())
}

#[test]
fn test_rep_insb_zero_count() -> Result<(), BoxError> {
    // REP INSB with RCX = 0 -> loop executes 0 times, RDI unchanged
    let pe = make_test_pe(&[0xF3, 0x6C]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 0)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RDI)?, BUFFER_VA, "RDI unchanged when RCX=0");

    Ok(())
}

#[test]
fn test_rep_insw_forward() -> Result<(), BoxError> {
    // REP INSW: F3 66 6D
    let pe = make_test_pe(&[0xF3, 0x66, 0x6D]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    let initial_data = [ByteValue::Concrete(0xCC); 6];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 3)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RDI)?, BUFFER_VA + 6, "RDI advances by 3 * 2 = 6");

    let mut buf = [ByteValue::Concrete(0xFF); 6];
    process
        .state
        .memory
        .read_into(BUFFER_VA, &mut buf)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0); 6]);

    Ok(())
}

#[test]
fn test_rep_insw_backward() -> Result<(), BoxError> {
    // REP INSW: F3 66 6D with DF = 1
    let pe = make_test_pe(&[0xF3, 0x66, 0x6D]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 2)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, DF_BIT)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(
        process.read_register(RDI)?,
        BUFFER_VA - 4,
        "RDI decrements by 2 * 2 = 4"
    );

    Ok(())
}

#[test]
fn test_rep_insd_forward() -> Result<(), BoxError> {
    // REP INSD: F3 6D
    let pe = make_test_pe(&[0xF3, 0x6D]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    let initial_data = [ByteValue::Concrete(0xDD); 8];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 2)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RDI)?, BUFFER_VA + 8, "RDI advances by 2 * 4 = 8");

    let mut buf = [ByteValue::Concrete(0xFF); 8];
    process
        .state
        .memory
        .read_into(BUFFER_VA, &mut buf)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(buf, [ByteValue::Concrete(0); 8]);

    Ok(())
}

#[test]
fn test_rep_insd_backward() -> Result<(), BoxError> {
    // REP INSD: F3 6D with DF = 1
    let pe = make_test_pe(&[0xF3, 0x6D]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 2)?;
    process.write_register(RDI, BUFFER_VA)?;
    process.write_register(RFLAGS, DF_BIT)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(
        process.read_register(RDI)?,
        BUFFER_VA - 8,
        "RDI decrements by 2 * 4 = 8"
    );

    Ok(())
}

#[test]
fn test_rep_outsb_forward() -> Result<(), BoxError> {
    // REP OUTSB: F3 6E
    let pe = make_test_pe(&[0xF3, 0x6E]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    let initial_data = [ByteValue::Concrete(0x55); 5];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 5)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RSI)?, BUFFER_VA + 5, "RSI advances by 5");

    Ok(())
}

#[test]
fn test_rep_outsb_backward() -> Result<(), BoxError> {
    // REP OUTSB: F3 6E with DF = 1
    let pe = make_test_pe(&[0xF3, 0x6E]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 4)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, DF_BIT)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RSI)?, BUFFER_VA - 4, "RSI decrements by 4");

    Ok(())
}

#[test]
fn test_rep_outsb_zero_count() -> Result<(), BoxError> {
    // REP OUTSB with RCX = 0
    let pe = make_test_pe(&[0xF3, 0x6E]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 0)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RSI)?, BUFFER_VA);

    Ok(())
}

#[test]
fn test_rep_outsw_forward() -> Result<(), BoxError> {
    // REP OUTSW: F3 66 6F
    let pe = make_test_pe(&[0xF3, 0x66, 0x6F]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    let initial_data = [ByteValue::Concrete(0x55); 6];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 3)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RSI)?, BUFFER_VA + 6, "RSI advances by 3 * 2 = 6");

    Ok(())
}

#[test]
fn test_rep_outsw_backward() -> Result<(), BoxError> {
    // REP OUTSW: F3 66 6F with DF = 1
    let pe = make_test_pe(&[0xF3, 0x66, 0x6F]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 2)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, DF_BIT)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(
        process.read_register(RSI)?,
        BUFFER_VA - 4,
        "RSI decrements by 2 * 2 = 4"
    );

    Ok(())
}

#[test]
fn test_rep_outsd_forward() -> Result<(), BoxError> {
    // REP OUTSD: F3 6F
    let pe = make_test_pe(&[0xF3, 0x6F]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    let initial_data = [ByteValue::Concrete(0x77); 8];
    process.state.memory = process
        .state
        .memory
        .write(BUFFER_VA, &initial_data)
        .map_err(|e| format!("{e:?}"))?;

    process.write_register(RCX, 2)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, 0)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(process.read_register(RSI)?, BUFFER_VA + 8, "RSI advances by 2 * 4 = 8");

    Ok(())
}

#[test]
fn test_rep_outsd_backward() -> Result<(), BoxError> {
    // REP OUTSD: F3 6F with DF = 1
    let pe = make_test_pe(&[0xF3, 0x6F]);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;

    process.write_register(RCX, 2)?;
    process.write_register(RSI, BUFFER_VA)?;
    process.write_register(RFLAGS, DF_BIT)?;

    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, StepOutcome::Stepped { .. }));

    assert_eq!(process.read_register(RCX)?, 0);
    assert_eq!(
        process.read_register(RSI)?,
        BUFFER_VA - 8,
        "RSI decrements by 2 * 4 = 8"
    );

    Ok(())
}
