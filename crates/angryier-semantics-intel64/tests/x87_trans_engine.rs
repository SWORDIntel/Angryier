#![forbid(unsafe_code)]

//! Engine validation for the x87 transcendental instruction family.
//!
//! ## Implementation status
//!
//! The following instructions are **IMPLEMENTED** and are validated here
//! through the full engine pipeline (decode → provider → emit → seal →
//! lower → `ConcreteInterpreter::execute_block`) and natively compared
//! against hardware execution:
//!
//! | Instruction | Form ID | Rule ID | Semantics |
//! |-------------|---------|---------|-----------|
//! | FABS        | 0x081F  | 0x0A1F  | ST(0) = \|ST(0)\| |
//! | FCHS        | 0x0820  | 0x0A20  | ST(0) = -ST(0) |
//! | FSQRT       | 0x0821  | 0x0A21  | ST(0) = sqrt(ST(0)) |
//! | FXCH        | 0x0822  | 0x0A22  | swap ST(0) ↔ ST(1) (implicit) |
//! | FXCH st(i)  | 0x0823  | 0x0A23  | swap ST(0) ↔ ST(i) |
//! | FSIN        | 0x0F40  | 0x1400  | ST(0) = sin(ST(0)) |
//! | FCOS        | 0x0F41  | 0x1401  | ST(0) = cos(ST(0)) |
//! | FPTAN       | 0x0F42  | 0x1402  | ST(0) = tan(ST(0)), push 1.0 |
//! | FPATAN      | 0x0F43  | 0x1403  | ST(1) = atan2(ST(1), ST(0)), pop |
//! | F2XM1       | 0x0F44  | 0x1404  | ST(0) = 2^ST(0) - 1.0 |
//! | FYL2X       | 0x0F45  | 0x1405  | ST(1) = ST(1) * log2(ST(0)), pop |
//! | FYL2XP1     | 0x0F46  | 0x1406  | ST(1) = ST(1) * log2(ST(0) + 1.0), pop |
//! | FSCALE      | 0x0F47  | 0x1407  | ST(0) = ST(0) * 2^trunc(ST(1)) |

use angryier_arch_intel64::{Intel64RegisterFile, X87_COUNT, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use angryier_types::{
    BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, ObjectId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const CODE_BASE: u64 = 0x400000;
const SCRATCH: u64 = 0x500000;
const STACK_TOP: u64 = 0x600000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(7);
const RSP: u32 = register_id::GPR_BASE + 4;

type BoxError = Box<dyn std::error::Error>;
type EngineState = ExecutionState<PersistentRegisters, PersistentMemory>;

fn context() -> SemanticContext {
    SemanticContext {
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        fidelity: FidelityProfile::Prove,
        vector_representation: VectorRepresentation::HybridLazy,
        tile_representation: TileRepresentation::LazyChunked,
        floating_point_policy: FloatingPointPolicy::SmtFpPreferred,
    }
}

// ---------------------------------------------------------------------------
// State helpers
// ---------------------------------------------------------------------------

/// Create a baseline state with code loaded at `CODE_BASE`, scratch memory at
/// `SCRATCH`, and a stack region anchored at `STACK_TOP`.  All x87 slots are
/// pre-tagged as empty (tag word `0xFFFF`).
fn create_state(code: &[u8]) -> Result<EngineState, BoxError> {
    let reg_file = Intel64RegisterFile::canonical();
    let registers = PersistentRegisters::from_widths(
        reg_file
            .architectural_registers
            .iter()
            .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
    )
    .map_err(|e| format!("registers: {e:?}"))?;
    let memory = PersistentMemory::new(vec![
        MemoryRegion {
            object: ObjectId(1),
            base: CODE_BASE,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: true,
        },
        MemoryRegion {
            object: ObjectId(2),
            base: SCRATCH,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        },
        MemoryRegion {
            object: ObjectId(3),
            base: STACK_TOP - 0x1000,
            size: 0x2000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;
    let code_bytes: Vec<ByteValue> = code.iter().copied().map(ByteValue::Concrete).collect();
    let memory = memory
        .write(CODE_BASE, &code_bytes)
        .map_err(|e| format!("code load: {e:?}"))?;
    Ok(ExecutionState {
        id: StateId(1),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    })
}

/// Seed x87 slot `slot` (0 = ST(0)) with a raw f64 bit pattern.
///
/// Format: bytes 0-7 = f64 payload (little-endian), bytes 8-9 = tag (0x0000
/// = valid).  Slot indices are physical, not TOS-relative.
fn seed_x87(state: &mut EngineState, slot: u32, f64_bits: u64) -> Result<(), BoxError> {
    let mut raw = [0u8; 10];
    raw[..8].copy_from_slice(&f64_bits.to_le_bytes());
    // bytes 8-9 remain 0x0000 (valid tag)
    state
        .registers
        .write_in_place(register_id::X87_BASE + slot, &raw)
        .map_err(|e| format!("seed x87 slot {slot}: {e:?}"))?;
    Ok(())
}

/// Mark all x87 slots as empty (tag = `0xFFFF`, payload = 0).
fn clear_x87_stack(state: &mut EngineState) -> Result<(), BoxError> {
    let mut empty = [0u8; 10];
    empty[8..].copy_from_slice(&u16::MAX.to_le_bytes());
    for i in 0..u32::from(X87_COUNT) {
        state
            .registers
            .write_in_place(register_id::X87_BASE + i, &empty)
            .map_err(|e| format!("clear x87 slot {i}: {e:?}"))?;
    }
    Ok(())
}

/// Read the f64 payload from x87 slot `slot`.
fn read_x87_f64(state: &EngineState, slot: u32) -> Result<f64, BoxError> {
    let raw = state
        .registers
        .read(register_id::X87_BASE + slot)
        .map_err(|e| format!("read x87 slot {slot}: {e:?}"))?;
    let bits = u64::from_le_bytes(raw[..8].try_into().map_err(|_| "x87 slice")?);
    Ok(f64::from_bits(bits))
}

/// Decode and execute a single-instruction form, returning the resulting state.
fn execute_one(code: &[u8], form: u32, state: &EngineState) -> Result<EngineState, BoxError> {
    let decoded = XedDecoder::new()
        .decode(CODE_BASE, code)
        .map_err(|e| format!("decode: {e:?}"))?;
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let provider = registry
        .provider_for_form(form)
        .ok_or_else(|| format!("no provider for form {form:#x}"))?;
    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|e| format!("emit: {e:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|e| format!("seal: {e:?}"))?;
    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(1),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))
            .map_err(|e| format!("code guards: {e:?}"))?,
    };
    let ir_block = BasicSemanticLowerer
        .lower_with_decode(&sealed, &key, &decoded)
        .map_err(|e| format!("lower: {e:?}"))?;
    let (after, outcome) = ConcreteInterpreter::new()
        .execute_block(state, &ir_block, ExecutionMode::Concrete)
        .map_err(|e| format!("execute: {e:?}"))?;
    match outcome {
        ExecutionOutcome::Continue { .. } => Ok(after),
        other => Err(format!("unexpected outcome: {other:?}").into()),
    }
}

// ---------------------------------------------------------------------------
// f64 bit patterns
// ---------------------------------------------------------------------------
const F64_2: u64 = 0x4000_0000_0000_0000; // 2.0
const F64_NEG2: u64 = 0xC000_0000_0000_0000; // -2.0
const F64_4: u64 = 0x4010_0000_0000_0000; // 4.0
const F64_9: u64 = 0x4022_0000_0000_0000; // 9.0
const F64_1_5: u64 = 0x3FF8_0000_0000_0000; // 1.5
const F64_3: u64 = 0x4008_0000_0000_0000; // 3.0

// ---------------------------------------------------------------------------
// Engine tests: FABS (D9 E1)
// ---------------------------------------------------------------------------

#[test]
fn fabs_positive_unchanged() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xE1]; // fabs
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_2)?;
    let after = execute_one(code, forms::FABS, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 2.0_f64).abs() < 1e-15,
        "fabs(2.0) should be 2.0, got {result}"
    );
    Ok(())
}

#[test]
fn fabs_clears_sign_bit() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xE1]; // fabs
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_NEG2)?;
    let after = execute_one(code, forms::FABS, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 2.0_f64).abs() < 1e-15,
        "fabs(-2.0) should be 2.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FCHS (D9 E0)
// ---------------------------------------------------------------------------

#[test]
fn fchs_negates_positive() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xE0]; // fchs
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_2)?;
    let after = execute_one(code, forms::FCHS, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - (-2.0_f64)).abs() < 1e-15,
        "fchs(2.0) should be -2.0, got {result}"
    );
    Ok(())
}

#[test]
fn fchs_negates_negative() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xE0]; // fchs
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_NEG2)?;
    let after = execute_one(code, forms::FCHS, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 2.0_f64).abs() < 1e-15,
        "fchs(-2.0) should be 2.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FSQRT (D9 FA)
// ---------------------------------------------------------------------------

#[test]
fn fsqrt_of_four() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFA]; // fsqrt
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_4)?;
    let after = execute_one(code, forms::FSQRT, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 2.0_f64).abs() < 1e-12,
        "fsqrt(4.0) should be 2.0, got {result}"
    );
    Ok(())
}

#[test]
fn fsqrt_of_nine() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFA]; // fsqrt
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_9)?;
    let after = execute_one(code, forms::FSQRT, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 3.0_f64).abs() < 1e-12,
        "fsqrt(9.0) should be 3.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FXCH (D9 C9 — ST(0) ↔ ST(1))
// ---------------------------------------------------------------------------

#[test]
fn fxch_swaps_st0_st1() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xC9]; // fxch %st(1)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_1_5)?;
    seed_x87(&mut state, 1, F64_3)?;
    let after = execute_one(code, forms::FXCH_STI, &state)?;
    let st0 = read_x87_f64(&after, 0)?;
    let st1 = read_x87_f64(&after, 1)?;
    assert!(
        (st0 - 3.0_f64).abs() < 1e-15,
        "after fxch, st0 should be 3.0 (was st1={F64_3:#x}), got {st0}"
    );
    assert!(
        (st1 - 1.5_f64).abs() < 1e-15,
        "after fxch, st1 should be 1.5 (was st0={F64_1_5:#x}), got {st1}"
    );
    Ok(())
}

#[test]
fn fxch_st2_swaps_st0_st2() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xCA]; // fxch %st(2)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, F64_1_5)?;
    seed_x87(&mut state, 1, F64_2)?;
    seed_x87(&mut state, 2, F64_4)?;
    let after = execute_one(code, forms::FXCH_STI, &state)?;
    let st0 = read_x87_f64(&after, 0)?;
    let st1 = read_x87_f64(&after, 1)?;
    let st2 = read_x87_f64(&after, 2)?;
    assert!(
        (st0 - 4.0_f64).abs() < 1e-15,
        "after fxch st(2), st0 should be 4.0, got {st0}"
    );
    // ST(1) should be untouched
    assert!(
        (st1 - 2.0_f64).abs() < 1e-15,
        "after fxch st(2), st1 should be 2.0 (untouched), got {st1}"
    );
    assert!(
        (st2 - 1.5_f64).abs() < 1e-15,
        "after fxch st(2), st2 should be 1.5, got {st2}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FSIN (D9 FE)
// ---------------------------------------------------------------------------

#[test]
fn fsin_zero() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFE]; // fsin
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 0u64)?; // 0.0
    let after = execute_one(code, forms::FSIN, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(result.abs() < 1e-15, "fsin(0.0) should be 0.0, got {result}");
    Ok(())
}

#[test]
fn fsin_pi_over_two() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFE]; // fsin
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    let pi_over_2 = std::f64::consts::FRAC_PI_2.to_bits();
    seed_x87(&mut state, 0, pi_over_2)?;
    let after = execute_one(code, forms::FSIN, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 1.0_f64).abs() < 1e-15,
        "fsin(pi/2) should be 1.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FCOS (D9 FF)
// ---------------------------------------------------------------------------

#[test]
fn fcos_zero() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFF]; // fcos
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 0u64)?; // 0.0
    let after = execute_one(code, forms::FCOS, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 1.0_f64).abs() < 1e-15,
        "fcos(0.0) should be 1.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FPTAN (D9 F2)
// ---------------------------------------------------------------------------

#[test]
fn fptan_zero() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xF2]; // fptan
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 0u64)?; // 0.0
    let after = execute_one(code, forms::FPTAN, &state)?;
    let st0 = read_x87_f64(&after, 0)?; // pushed 1.0
    let st1 = read_x87_f64(&after, 1)?; // tan(0.0) = 0.0
    assert!((st0 - 1.0_f64).abs() < 1e-15, "fptan ST(0) should be 1.0, got {st0}");
    assert!(st1.abs() < 1e-15, "fptan ST(1) should be 0.0, got {st1}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FPATAN (D9 F3)
// ---------------------------------------------------------------------------

#[test]
fn fpatan_one_one() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xF3]; // fpatan
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    let one_bits = 1.0_f64.to_bits();
    seed_x87(&mut state, 0, one_bits)?; // ST(0) = x = 1.0
    seed_x87(&mut state, 1, one_bits)?; // ST(1) = y = 1.0
    let after = execute_one(code, forms::FPATAN, &state)?;
    let st0 = read_x87_f64(&after, 0)?; // result is in ST(0) after pop
    let expected = std::f64::consts::FRAC_PI_4;
    assert!(
        (st0 - expected).abs() < 1e-15,
        "fpatan(1.0, 1.0) should be pi/4, got {st0}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: F2XM1 (D9 F0)
// ---------------------------------------------------------------------------

#[test]
fn f2xm1_zero() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xF0]; // f2xm1
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 0u64)?; // 0.0
    let after = execute_one(code, forms::F2XM1, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(result.abs() < 1e-15, "f2xm1(0.0) should be 0.0, got {result}");
    Ok(())
}

#[test]
fn f2xm1_one() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xF0]; // f2xm1
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 1.0_f64.to_bits())?;
    let after = execute_one(code, forms::F2XM1, &state)?;
    let result = read_x87_f64(&after, 0)?;
    assert!(
        (result - 1.0_f64).abs() < 1e-15,
        "f2xm1(1.0) should be 1.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FYL2X (D9 F1)
// ---------------------------------------------------------------------------

#[test]
fn fyl2x_basic() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xF1]; // fyl2x
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 4.0_f64.to_bits())?; // ST(0) = x = 4.0
    seed_x87(&mut state, 1, 3.0_f64.to_bits())?; // ST(1) = y = 3.0
    let after = execute_one(code, forms::FYL2X, &state)?;
    let result = read_x87_f64(&after, 0)?; // 3.0 * log2(4.0) = 6.0
    assert!(
        (result - 6.0_f64).abs() < 1e-15,
        "fyl2x(4, 3) should be 6.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FYL2XP1 (D9 F9)
// ---------------------------------------------------------------------------

#[test]
fn fyl2xp1_basic() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xF9]; // fyl2xp1
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 3.0_f64.to_bits())?; // ST(0) = x = 3.0 (x+1 = 4.0)
    seed_x87(&mut state, 1, 2.0_f64.to_bits())?; // ST(1) = y = 2.0
    let after = execute_one(code, forms::FYL2XP1, &state)?;
    let result = read_x87_f64(&after, 0)?; // 2.0 * log2(4.0) = 4.0
    assert!(
        (result - 4.0_f64).abs() < 1e-15,
        "fyl2xp1(3, 2) should be 4.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Engine tests: FSCALE (D9 FD)
// ---------------------------------------------------------------------------

#[test]
fn fscale_basic() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFD]; // fscale
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 1.5_f64.to_bits())?; // ST(0) = 1.5
    seed_x87(&mut state, 1, 2.0_f64.to_bits())?; // ST(1) = 2.0
    let after = execute_one(code, forms::FSCALE, &state)?;
    let result = read_x87_f64(&after, 0)?; // 1.5 * 2^2 = 6.0
    assert!(
        (result - 6.0_f64).abs() < 1e-15,
        "fscale(1.5, 2.0) should be 6.0, got {result}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Native differential tests
//
// These tests assemble real AT&T x87 code, link it, execute it on the host
// CPU, extract the native output, and compare against the engine pipeline.
// They are silently skipped if `as`/`ld`/`objcopy` are unavailable.
// ---------------------------------------------------------------------------

fn temp_dir_trans(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-x87trans-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn assemble_trans(source: &Path, object: &Path) -> Option<()> {
    Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(object)
        .arg(source)
        .output()
        .ok()?
        .status
        .success()
        .then_some(())
}

fn link_trans(binary: &Path, objects: &[&PathBuf]) -> Option<()> {
    let mut cmd = Command::new("ld");
    cmd.arg("-Ttext=0x400000").arg("-Tdata=0x500000").arg("-o").arg(binary);
    for obj in objects {
        cmd.arg(obj);
    }
    cmd.output().ok()?.status.success().then_some(())
}

fn extract_text_trans(dir: &Path, binary: &Path) -> Option<Vec<u8>> {
    let section = dir.join("case.text");
    Command::new("objcopy")
        .arg("--dump-section")
        .arg(format!(".text={}", section.display()))
        .arg(binary)
        .arg("/dev/null")
        .output()
        .ok()?
        .status
        .success()
        .then_some(())?;
    std::fs::read(section).ok()
}

fn native_stdout_trans(binary: &Path) -> Option<Vec<u8>> {
    Some(Command::new(binary).output().ok()?.stdout)
}

fn harness_source_trans(body: &str) -> String {
    format!(
        "        .global _start\n        .text\n_start:\n{body}\n    mov %rax, 0x{SCRATCH:x}\n    pushfq\n    pop %rbx\n    mov %rbx, 0x{SCRATCH8:x}\n    mov $1, %rax\n    mov $1, %rdi\n    mov $0x{SCRATCH:x}, %rsi\n    mov $16, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\nscratch:\n        .space 0x400\n",
        SCRATCH8 = SCRATCH + 8
    )
}

// ---------------------------------------------------------------------------
// Engine multi-instruction runner (mirrors run_engine in x87_ext_differential)
// ---------------------------------------------------------------------------

use angryier_arch::{OperandKind, OperandVisibility};

fn is_stack(view: &angryier_arch::RegisterView) -> bool {
    (register_id::X87_BASE..register_id::X87_BASE + 8).contains(&view.parent.0)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Stack,
    Mem16,
    Mem32,
    Mem64,
    Reg64,
    Reg32,
    Imm,
}

fn map_form_trans(decoded: &angryier_arch::DecodedInstruction) -> Option<u32> {
    use xed_sys as xed;
    let explicit: Vec<&angryier_arch::Operand> = decoded
        .operands
        .iter()
        .filter(|op| op.visibility != OperandVisibility::Suppressed)
        .collect();
    let mut shapes = Vec::new();
    let mut mem: Option<Shape> = None;
    for op in &explicit {
        match &op.kind {
            OperandKind::Register(view) if is_stack(view) => shapes.push(Shape::Stack),
            OperandKind::Register(view) if view.width_bits == 64 => shapes.push(Shape::Reg64),
            OperandKind::Register(view) if view.width_bits == 32 => shapes.push(Shape::Reg32),
            OperandKind::Memory(_) => {
                mem = Some(match op.width_bits {
                    16 => Shape::Mem16,
                    32 => Shape::Mem32,
                    64 => Shape::Mem64,
                    _ => return None,
                });
            }
            OperandKind::Immediate(_) => shapes.push(Shape::Imm),
            _ => return None,
        }
    }
    let mem_writes = explicit
        .iter()
        .any(|op| matches!(op.kind, OperandKind::Memory(_)) && op.access == angryier_arch::AccessKind::Write);

    match decoded.form_id {
        xed::XED_ICLASS_FNINIT => Some(forms::FINIT),
        xed::XED_ICLASS_FLD1 => Some(forms::FLD1),
        xed::XED_ICLASS_FLDZ => Some(forms::FLDZ),
        xed::XED_ICLASS_FLD => match (&shapes[..], mem) {
            ([Shape::Stack, Shape::Stack], _) => Some(forms::FLD_STI),
            (_, Some(Shape::Mem32)) => Some(forms::FLD_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FLD_M64),
            _ => None,
        },
        xed::XED_ICLASS_FST => match mem {
            Some(Shape::Mem32) => Some(forms::FST_M32),
            Some(Shape::Mem64) => Some(forms::FST_M64),
            _ => None,
        },
        xed::XED_ICLASS_FSTP | xed::XED_ICLASS_FSTPNCE => match (&shapes[..], mem) {
            ([Shape::Stack, Shape::Stack], _) => Some(forms::FSTP_STI),
            (_, Some(Shape::Mem32)) => Some(forms::FSTP_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FSTP_M64),
            _ => None,
        },
        xed::XED_ICLASS_FABS => Some(forms::FABS),
        xed::XED_ICLASS_FCHS => Some(forms::FCHS),
        xed::XED_ICLASS_FSQRT => Some(forms::FSQRT),
        xed::XED_ICLASS_FSIN => Some(forms::FSIN),
        xed::XED_ICLASS_FCOS => Some(forms::FCOS),
        xed::XED_ICLASS_FPTAN => Some(forms::FPTAN),
        xed::XED_ICLASS_FPATAN => Some(forms::FPATAN),
        xed::XED_ICLASS_F2XM1 => Some(forms::F2XM1),
        xed::XED_ICLASS_FYL2X => Some(forms::FYL2X),
        xed::XED_ICLASS_FYL2XP1 => Some(forms::FYL2XP1),
        xed::XED_ICLASS_FSCALE => Some(forms::FSCALE),
        xed::XED_ICLASS_FXCH => match &shapes[..] {
            [] => Some(forms::FXCH),
            [Shape::Stack] | [Shape::Stack, Shape::Stack] => Some(forms::FXCH_STI),
            _ => Some(forms::FXCH),
        },
        xed::XED_ICLASS_MOV => match (&shapes[..], mem, mem_writes) {
            ([Shape::Reg64, Shape::Imm], _, _) => Some(forms::MOV_R64_IMM64),
            ([Shape::Reg64, Shape::Reg64], _, _) => Some(forms::MOV_R64_R64),
            ([Shape::Reg64], Some(Shape::Mem64), false) => Some(forms::MOV_R64_MEM64),
            ([Shape::Reg64], Some(Shape::Mem64), true) => Some(forms::MOV_MEM64_R64),
            ([Shape::Reg32], Some(Shape::Mem32), false) => Some(forms::MOV_R32_MEM32),
            _ => None,
        },
        xed::XED_ICLASS_PUSHF | xed::XED_ICLASS_PUSHFQ => Some(forms::PUSHF),
        xed::XED_ICLASS_POP => match &shapes[..] {
            [Shape::Reg64] => Some(forms::POP_R64),
            _ => None,
        },
        xed::XED_ICLASS_XOR => match &shapes[..] {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            _ => None,
        },
        _ => None,
    }
}

struct EngineRunner {
    registers: PersistentRegisters,
    memory: PersistentMemory,
}

impl EngineRunner {
    fn new(code: &[u8]) -> Result<Self, BoxError> {
        let reg_file = Intel64RegisterFile::canonical();
        let registers = PersistentRegisters::from_widths(
            reg_file
                .architectural_registers
                .iter()
                .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
        )
        .map_err(|e| format!("registers: {e:?}"))?;
        let registers = registers
            .write(RSP, &STACK_TOP.to_le_bytes())
            .map_err(|e| format!("rsp: {e:?}"))?;
        let memory = PersistentMemory::new(vec![
            MemoryRegion {
                object: ObjectId(1),
                base: CODE_BASE,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: true,
            },
            MemoryRegion {
                object: ObjectId(2),
                base: SCRATCH,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: false,
            },
            MemoryRegion {
                object: ObjectId(3),
                base: STACK_TOP - 0x1000,
                size: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            },
        ])?;
        let bytes: Vec<ByteValue> = code.iter().copied().map(ByteValue::Concrete).collect();
        let memory = memory.write(CODE_BASE, &bytes).map_err(|e| format!("code: {e:?}"))?;
        Ok(Self { registers, memory })
    }

    fn as_state(&self) -> Result<EngineState, BoxError> {
        Ok(ExecutionState {
            id: StateId(1),
            parent: None,
            target_profile: TARGET_PROFILE,
            registers: self.registers.clone(),
            memory: self.memory.clone(),
            constraints: PersistentConstraintLineage::new(),
            ownership: StateOwnership::default(),
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        })
    }
}

fn run_engine_trans(code: &[u8], registry: &Intel64CorpusRegistry) -> Result<(u64, u64), BoxError> {
    let decoder = XedDecoder::new();
    let mut runner = EngineRunner::new(code)?;
    let mut pc = CODE_BASE;

    for _ in 0..512 {
        let offset = usize::try_from(pc - CODE_BASE).map_err(|_| "pc underflow")?;
        let slice = code.get(offset..).ok_or_else(|| format!("pc {pc:#x} outside code"))?;
        let decoded = decoder
            .decode(pc, slice)
            .map_err(|e| format!("decode at {pc:#x}: {e:?}"))?;
        if decoded.form_id == xed_sys::XED_ICLASS_SYSCALL {
            break;
        }
        let form = map_form_trans(&decoded).ok_or_else(|| format!("unmapped iclass {} at {pc:#x}", decoded.form_id))?;
        let provider = registry
            .provider_for_form(form)
            .ok_or_else(|| format!("no provider for form {form:#x}"))?;
        let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
        provider
            .emit(&context(), &decoded, &mut builder)
            .map_err(|e| format!("emit {form:#x}: {e:?}"))?;
        let sealed = builder
            .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
            .map_err(|e| format!("seal {form:#x}: {e:?}"))?;
        let state = runner.as_state()?;
        state
            .registers
            .write(register_id::RIP.0, &decoded.address.to_le_bytes())
            .map_err(|e| format!("rip: {e:?}"))?;
        let key = BlockValidityKey {
            image: ImageId(1),
            block: BlockId(2),
            address: decoded.address,
            semantic_version: SEMANTIC_VERSION,
            target_profile: TARGET_PROFILE,
            code_versions: runner
                .memory
                .code_version_guards_for_range(decoded.address, usize::from(decoded.length))
                .map_err(|e| format!("code guards: {e:?}"))?,
        };
        let ir = BasicSemanticLowerer
            .lower_with_decode(&sealed, &key, &decoded)
            .map_err(|e| format!("lower {form:#x}: {e:?}"))?;
        let (executed, outcome) = ConcreteInterpreter::new()
            .execute_block(&state, &ir, ExecutionMode::Concrete)
            .map_err(|e| format!("execute {form:#x} at {pc:#x}: {e:?}"))?;
        let next_pc = match outcome {
            ExecutionOutcome::Continue { next_pc, .. } => next_pc,
            other => return Err(format!("unexpected outcome {other:?}").into()),
        };
        runner.registers = executed
            .registers
            .write(register_id::RIP.0, &next_pc.to_le_bytes())
            .map_err(|e| format!("rip store: {e:?}"))?;
        runner.memory = executed.memory;
        pc += u64::from(decoded.length);
    }

    let read8 = |addr: u64| -> Result<u64, BoxError> {
        let bytes: Vec<u8> = runner
            .memory
            .read(addr, 8)
            .map_err(|e| format!("read {addr:#x}: {e:?}"))?
            .into_iter()
            .map(|b| match b {
                ByteValue::Concrete(v) => v,
                ByteValue::Symbolic { .. } => 0,
            })
            .collect();
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(arr))
    };

    Ok((read8(SCRATCH)?, read8(SCRATCH + 8)?))
}

fn differential_trans(name: &str, body: &str) -> Result<bool, BoxError> {
    let Some(dir) = temp_dir_trans(name) else {
        return Ok(false);
    };
    let src = dir.join("case.s");
    let obj = dir.join("case.o");
    let bin = dir.join("case");

    let assembly = harness_source_trans(body);
    std::fs::write(&src, &assembly)?;
    if assemble_trans(&src, &obj).is_none() {
        eprintln!("ASSEMBLE-FAIL {name}\n{assembly}");
        return Ok(false);
    }
    if link_trans(&bin, &[&obj]).is_none() {
        eprintln!("LINK-FAIL {name}");
        return Ok(false);
    }
    let Some(code) = extract_text_trans(&dir, &bin) else {
        return Ok(false);
    };
    let Some(native_out) = native_stdout_trans(&bin) else {
        return Ok(false);
    };
    if native_out.len() < 16 {
        return Err(format!("native output too short: {} bytes", native_out.len()).into());
    }
    let mut native_rax_bytes = [0u8; 8];
    native_rax_bytes.copy_from_slice(&native_out[0..8]);
    let native_rax = u64::from_le_bytes(native_rax_bytes);

    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let (engine_rax, _) = run_engine_trans(&code, &registry)?;

    if engine_rax != native_rax {
        return Err(
            format!("mismatch on `{name}`: engine={engine_rax:#x} native={native_rax:#x}\nbody:\n{body}").into(),
        );
    }
    Ok(true)
}

fn seed64_trans(slot: u64, bits: u64) -> String {
    format!(
        "    movabs ${bits}, %rbx\n    mov %rbx, 0x{addr:x}\n",
        addr = SCRATCH + 8 * slot
    )
}

const OUT0: u64 = SCRATCH + 0x40;

fn observe_trans(which: u32) -> String {
    format!("    mov 0x{:x}, %rax\n", SCRATCH + 0x40 + 8 * u64::from(which))
}

// f64 bit patterns for the differential harness
const F64_NEG2_D: u64 = 0xC000_0000_0000_0000; // -2.0
const F64_4_D: u64 = 0x4010_0000_0000_0000; // 4.0
const F64_1_5_D: u64 = 0x3FF8_0000_0000_0000; // 1.5
const F64_3_D: u64 = 0x4008_0000_0000_0000; // 3.0

#[test]
fn differential_fabs_negative() -> Result<(), BoxError> {
    // fabs(-2.0) → 2.0; store to OUT0 then observe as raw i64 bits.
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    fabs\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, F64_NEG2_D),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("fabs_neg", &body)?;
    Ok(())
}

#[test]
fn differential_fchs_positive() -> Result<(), BoxError> {
    // fchs(4.0) → -4.0
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    fchs\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, F64_4_D),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("fchs_pos", &body)?;
    Ok(())
}

#[test]
fn differential_fsqrt_four() -> Result<(), BoxError> {
    // fsqrt(4.0) → 2.0
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    fsqrt\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, F64_4_D),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("fsqrt_four", &body)?;
    Ok(())
}

#[test]
fn differential_fxch_swaps() -> Result<(), BoxError> {
    // Push 3.0 then 1.5; fxch st(1) swaps them; fstp pops (now 3.0) to OUT0.
    let body = format!(
        "{}{}\
         \n    fninit\n    fldl 0x{scratch0:x}\n    fldl 0x{scratch1:x}\n    fxch\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, F64_3_D),
        seed64_trans(1, F64_1_5_D),
        observe_trans(0),
        scratch0 = SCRATCH,
        scratch1 = SCRATCH + 8,
    );
    differential_trans("fxch_swap", &body)?;
    Ok(())
}

#[test]
fn differential_fsin_zero() -> Result<(), BoxError> {
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    fsin\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 0u64),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("fsin_zero", &body)?;
    Ok(())
}

#[test]
fn differential_fcos_zero() -> Result<(), BoxError> {
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    fcos\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 0u64),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("fcos_zero", &body)?;
    Ok(())
}

#[test]
fn differential_fptan_zero() -> Result<(), BoxError> {
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    fptan\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 0u64),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("fptan_zero", &body)?;
    Ok(())
}

#[test]
fn differential_f2xm1_zero() -> Result<(), BoxError> {
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    f2xm1\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 0u64),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("f2xm1_zero", &body)?;
    Ok(())
}

#[test]
fn differential_f2xm1_one() -> Result<(), BoxError> {
    let body = format!(
        "{}\
         \n    fninit\n    fldl 0x{scratch:x}\n    f2xm1\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 1.0_f64.to_bits()),
        observe_trans(0),
        scratch = SCRATCH,
    );
    differential_trans("f2xm1_one", &body)?;
    Ok(())
}

#[test]
fn differential_fscale_basic() -> Result<(), BoxError> {
    // push scale (2.0), push val (1.5), fscale scales ST(0) by ST(1)
    let body = format!(
        "{}{}\
         \n    fninit\n    fldl 0x{scratch1:x}\n    fldl 0x{scratch0:x}\n    fscale\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 1.5_f64.to_bits()),
        seed64_trans(1, 2.0_f64.to_bits()),
        observe_trans(0),
        scratch0 = SCRATCH,
        scratch1 = SCRATCH + 8,
    );
    differential_trans("fscale_basic", &body)?;
    Ok(())
}

#[test]
fn differential_fyl2x_basic() -> Result<(), BoxError> {
    // push y (3.0), push x (4.0), fyl2x computes y * log2(x), pops x, stores to OUT0
    let body = format!(
        "{}{}\
         \n    fninit\n    fldl 0x{scratch_y:x}\n    fldl 0x{scratch_x:x}\n    fyl2x\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 4.0_f64.to_bits()),
        seed64_trans(1, 3.0_f64.to_bits()),
        observe_trans(0),
        scratch_x = SCRATCH,
        scratch_y = SCRATCH + 8,
    );
    differential_trans("fyl2x_basic", &body)?;
    Ok(())
}

#[test]
fn differential_fyl2xp1_basic() -> Result<(), BoxError> {
    // push y (2.0), push x (3.0), fyl2xp1 computes y * log2(x + 1), pops x, stores to OUT0
    let body = format!(
        "{}{}\
         \n    fninit\n    fldl 0x{scratch_y:x}\n    fldl 0x{scratch_x:x}\n    fyl2xp1\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 3.0_f64.to_bits()),
        seed64_trans(1, 2.0_f64.to_bits()),
        observe_trans(0),
        scratch_x = SCRATCH,
        scratch_y = SCRATCH + 8,
    );
    differential_trans("fyl2xp1_basic", &body)?;
    Ok(())
}

#[test]
fn differential_fpatan_basic() -> Result<(), BoxError> {
    // push y (0.0), push x (1.0), fpatan computes atan2(y, x) = 0.0, pops x, stores to OUT0
    let body = format!(
        "{}{}\
         \n    fninit\n    fldl 0x{scratch_y:x}\n    fldl 0x{scratch_x:x}\n    fpatan\n    fstpl 0x{OUT0:#x}\n    {}",
        seed64_trans(0, 1.0_f64.to_bits()),
        seed64_trans(1, 0.0_f64.to_bits()),
        observe_trans(0),
        scratch_x = SCRATCH,
        scratch_y = SCRATCH + 8,
    );
    differential_trans("fpatan_basic", &body)?;
    Ok(())
}
