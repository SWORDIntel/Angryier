#![forbid(unsafe_code)]

//! Engine validation for extended x87 instructions and Intel 64 system forms.

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

const CODE_BASE: u64 = 0x400000;
const SCRATCH: u64 = 0x500000;
const STACK_TOP: u64 = 0x600000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(7);

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

fn seed_x87(state: &mut EngineState, slot: u32, f64_bits: u64) -> Result<(), BoxError> {
    let mut raw = [0u8; 10];
    raw[..8].copy_from_slice(&f64_bits.to_le_bytes());
    state
        .registers
        .write_in_place(register_id::X87_BASE + slot, &raw)
        .map_err(|e| format!("seed x87 slot {slot}: {e:?}"))?;
    Ok(())
}

fn read_x87(state: &EngineState, slot: u32) -> Result<u64, BoxError> {
    let raw = state.registers.read(register_id::X87_BASE + slot)?;
    Ok(u64::from_le_bytes(raw[..8].try_into()?))
}

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
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_fldpi() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xEB]; // fldpi
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    let after = execute_one(code, forms::FLDPI, &state)?;
    let val = f64::from_bits(read_x87(&after, 0)?);
    assert!((val - std::f64::consts::PI).abs() < 1e-12, "expected pi, got {val}");
    Ok(())
}

#[test]
fn test_fnop() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xD0]; // fnop
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    let after = execute_one(code, forms::FNOP, &state)?;
    let sw = after.registers.read(register_id::X87_SW.0)?;
    assert_eq!(sw[..2], [0, 0]);
    Ok(())
}

fn read_concrete_bytes(memory: &PersistentMemory, address: u64, size: usize) -> Result<Vec<u8>, BoxError> {
    let bytes = memory.read(address, size)?;
    bytes
        .into_iter()
        .map(|byte| match byte {
            ByteValue::Concrete(value) => Ok(value),
            ByteValue::Symbolic { .. } => Err("symbolic byte in memory".into()),
        })
        .collect()
}

#[test]
fn test_fldcw_fnstcw_roundtrip() -> Result<(), BoxError> {
    // Write 0x037F to SCRATCH, load into CW with fldcw (%rax), then store to SCRATCH+2 with fnstcw (%rax)
    let code_fldcw: &[u8] = &[0xD9, 0x28]; // fldcw (%rax)
    let mut state = create_state(code_fldcw)?;
    state
        .registers
        .write_in_place(register_id::GPR_BASE, &SCRATCH.to_le_bytes())?;
    let val_bytes: [u8; 2] = 0x037F_u16.to_le_bytes();
    let mem = state.memory.write(
        SCRATCH,
        &[ByteValue::Concrete(val_bytes[0]), ByteValue::Concrete(val_bytes[1])],
    )?;
    state.memory = mem;

    let after_fldcw = execute_one(code_fldcw, forms::FLDCW_M16, &state)?;
    let cw_bytes = after_fldcw.registers.read(register_id::X87_CW.0)?;
    let cw = u16::from_le_bytes(cw_bytes[..2].try_into()?);
    assert_eq!(cw, 0x037F, "expected CW = 0x037F, got {cw:#x}");

    // fnstcw (%rax)
    let code_fnstcw: &[u8] = &[0xD9, 0x38]; // fnstcw (%rax)
    let mut state_fnstcw = after_fldcw;
    state_fnstcw
        .registers
        .write_in_place(register_id::GPR_BASE, &(SCRATCH + 2).to_le_bytes())?;
    let after_fnstcw = execute_one(code_fnstcw, forms::FNSTCW_M16, &state_fnstcw)?;
    let stored = read_concrete_bytes(&after_fnstcw.memory, SCRATCH + 2, 2)?;
    let stored_cw = u16::from_le_bytes(stored[..2].try_into()?);
    assert_eq!(stored_cw, 0x037F, "expected stored CW = 0x037F, got {stored_cw:#x}");
    Ok(())
}

#[test]
fn test_fnclex_clears_exception_flags() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDB, 0xE2]; // fnclex
    let mut state = create_state(code)?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0xFFFF_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FNCLEX, &state)?;
    let sw_bytes = after.registers.read(register_id::X87_SW.0)?;
    let sw = u16::from_le_bytes(sw_bytes[..2].try_into()?);
    // Bits 0..7 and bit 15 cleared: 0xFFFF & 0x7F00 = 0x7F00
    assert_eq!(sw, 0x7F00, "expected SW = 0x7F00, got {sw:#x}");
    Ok(())
}

#[test]
fn test_ftst_positive_zero_negative() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xE4]; // ftst
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;

    // Positive value (e.g. 42.0)
    seed_x87(&mut state, 0, 42.0_f64.to_bits())?;
    let after = execute_one(code, forms::FTST, &state)?;
    let sw = u16::from_le_bytes(after.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    // C3 (bit 14), C2 (bit 10), C0 (bit 8) all 0 for ST(0) > 0
    let c_bits = ((sw >> 14) & 1) << 3 | ((sw >> 10) & 1) << 2 | ((sw >> 8) & 1);
    assert_eq!(c_bits, 0, "expected C3=0, C2=0, C0=0 for positive");

    // Zero
    seed_x87(&mut state, 0, 0.0_f64.to_bits())?;
    let after = execute_one(code, forms::FTST, &state)?;
    let sw = u16::from_le_bytes(after.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    // C3=1 (bit 14), C2=0, C0=0 for ST(0) == 0
    assert_ne!(sw & (1 << 14), 0, "expected C3=1 for zero");
    assert_eq!(sw & ((1 << 10) | (1 << 8)), 0, "expected C2=0, C0=0 for zero");

    // Negative value
    seed_x87(&mut state, 0, (-5.0_f64).to_bits())?;
    let after = execute_one(code, forms::FTST, &state)?;
    let sw = u16::from_le_bytes(after.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    // C3=0, C2=0, C0=1 (bit 8) for ST(0) < 0
    assert_ne!(sw & (1 << 8), 0, "expected C0=1 for negative");
    assert_eq!(sw & ((1 << 14) | (1 << 10)), 0, "expected C3=0, C2=0 for negative");
    Ok(())
}

#[test]
fn test_fxam_classification() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xE5]; // fxam
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;

    // Positive normal
    seed_x87(&mut state, 0, 1.0_f64.to_bits())?;
    let after = execute_one(code, forms::FXAM, &state)?;
    let sw = u16::from_le_bytes(after.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    // C1 is sign bit = 0
    assert_eq!(sw & (1 << 9), 0, "expected positive sign (C1=0)");
    // Normal: C3=0, C2=1, C0=0 -> bit 10 is 1
    assert_ne!(sw & (1 << 10), 0, "expected normal (C2=1)");

    // Negative normal
    seed_x87(&mut state, 0, (-1.0_f64).to_bits())?;
    let after = execute_one(code, forms::FXAM, &state)?;
    let sw = u16::from_le_bytes(after.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    // C1 is sign bit = 1
    assert_ne!(sw & (1 << 9), 0, "expected negative sign (C1=1)");
    Ok(())
}

#[test]
fn test_fdecstp_fincstp() -> Result<(), BoxError> {
    let code_dec: &[u8] = &[0xD9, 0xF6]; // fdecstp
    let code_inc: &[u8] = &[0xD9, 0xF7]; // fincstp
    let state = create_state(code_dec)?;
    // TOP = 0
    let after_dec = execute_one(code_dec, forms::FDECSTP, &state)?;
    let sw_dec = u16::from_le_bytes(after_dec.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    let top_dec = (sw_dec >> 11) & 0x7;
    assert_eq!(top_dec, 7, "TOP should wrap 0 -> 7 on fdecstp");

    let after_inc = execute_one(code_inc, forms::FINCSTP, &after_dec)?;
    let sw_inc = u16::from_le_bytes(after_inc.registers.read(register_id::X87_SW.0)?[..2].try_into()?);
    let top_inc = (sw_inc >> 11) & 0x7;
    assert_eq!(top_inc, 0, "TOP should advance 7 -> 0 on fincstp");
    Ok(())
}

#[test]
fn test_ffree_sti() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDD, 0xC1]; // ffree %st(1)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 1, 123.0_f64.to_bits())?;
    let after = execute_one(code, forms::FFREE_STI, &state)?;
    let raw = after.registers.read(register_id::X87_BASE + 1)?;
    let exp = u16::from_le_bytes(raw[8..10].try_into()?);
    assert_eq!(exp, u16::MAX, "tag should mark empty (exp = 0xFFFF)");
    Ok(())
}

#[test]
fn test_frndint() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD9, 0xFC]; // frndint
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 3.75_f64.to_bits())?;
    let after = execute_one(code, forms::FRNDINT, &state)?;
    let rounded = f64::from_bits(read_x87(&after, 0)?);
    assert_eq!(rounded, 4.0, "expected 3.75 rounded to 4.0, got {rounded}");
    Ok(())
}

#[test]
fn test_fcmovb() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDA, 0xC1]; // fcmovb %st(1), %st(0)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 10.0_f64.to_bits())?;
    seed_x87(&mut state, 1, 20.0_f64.to_bits())?;

    // Case 1: CF = 0 -> condition false, ST(0) remains 10.0
    state
        .registers
        .write_in_place(register_id::RFLAGS.0, &0_u64.to_le_bytes())?;
    let after_false = execute_one(code, forms::FCMOVB_ST0_STI, &state)?;
    let v_false = f64::from_bits(read_x87(&after_false, 0)?);
    assert_eq!(v_false, 10.0, "ST(0) should be untouched when CF=0");

    // Case 2: CF = 1 -> condition true, ST(0) takes ST(1) = 20.0
    state
        .registers
        .write_in_place(register_id::RFLAGS.0, &1_u64.to_le_bytes())?;
    let after_true = execute_one(code, forms::FCMOVB_ST0_STI, &state)?;
    let v_true = f64::from_bits(read_x87(&after_true, 0)?);
    assert_eq!(v_true, 20.0, "ST(0) should take ST(1) when CF=1");
    Ok(())
}

#[test]
fn test_system_rdtscp_xgetbv() -> Result<(), BoxError> {
    let code_rdtscp: &[u8] = &[0x0F, 0x01, 0xF9]; // rdtscp
    let state = create_state(code_rdtscp)?;
    let after_rdtscp = execute_one(code_rdtscp, forms::RDTSCP, &state)?;
    // Verifies it executes cleanly
    let rax = after_rdtscp.registers.read(register_id::GPR_BASE)?;
    assert_eq!(rax.len(), 8);

    let code_xgetbv: &[u8] = &[0x0F, 0x01, 0xD0]; // xgetbv
    let after_xgetbv = execute_one(code_xgetbv, forms::XGETBV, &state)?;
    let rax = after_xgetbv.registers.read(register_id::GPR_BASE)?;
    let rdx = after_xgetbv.registers.read(register_id::GPR_BASE + 2)?;
    let eax = u32::from_le_bytes(rax[..4].try_into()?);
    let edx = u32::from_le_bytes(rdx[..4].try_into()?);
    assert_eq!(eax, 7, "xgetbv should return 7 in EAX (XCR0 default)");
    assert_eq!(edx, 0, "xgetbv should return 0 in EDX");
    Ok(())
}

#[test]
fn test_x87_constants() -> Result<(), BoxError> {
    // fldl2e (D9 EA)
    let code_l2e: &[u8] = &[0xD9, 0xEA];
    let mut state = create_state(code_l2e)?;
    clear_x87_stack(&mut state)?;
    let after_l2e = execute_one(code_l2e, forms::FLDL2E, &state)?;
    let val_l2e = f64::from_bits(read_x87(&after_l2e, 0)?);
    assert!((val_l2e - std::f64::consts::LOG2_E).abs() < 1e-12);

    // fldl2t (D9 E9)
    let code_l2t: &[u8] = &[0xD9, 0xE9];
    let mut state = create_state(code_l2t)?;
    clear_x87_stack(&mut state)?;
    let after_l2t = execute_one(code_l2t, forms::FLDL2T, &state)?;
    let val_l2t = f64::from_bits(read_x87(&after_l2t, 0)?);
    assert!((val_l2t - 10.0_f64.log2()).abs() < 1e-12);

    // fldlg2 (D9 EC)
    let code_lg2: &[u8] = &[0xD9, 0xEC];
    let mut state = create_state(code_lg2)?;
    clear_x87_stack(&mut state)?;
    let after_lg2 = execute_one(code_lg2, forms::FLDLG2, &state)?;
    let val_lg2 = f64::from_bits(read_x87(&after_lg2, 0)?);
    assert!((val_lg2 - std::f64::consts::LOG10_2).abs() < 1e-12);

    // fldln2 (D9 ED)
    let code_ln2: &[u8] = &[0xD9, 0xED];
    let mut state = create_state(code_ln2)?;
    clear_x87_stack(&mut state)?;
    let after_ln2 = execute_one(code_ln2, forms::FLDLN2, &state)?;
    let val_ln2 = f64::from_bits(read_x87(&after_ln2, 0)?);
    assert!((val_ln2 - std::f64::consts::LN_2).abs() < 1e-12);
    Ok(())
}

#[test]
fn test_fst_sti() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDD, 0xD1]; // fst %st(1)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 77.0_f64.to_bits())?;
    seed_x87(&mut state, 1, 11.0_f64.to_bits())?;

    let after = execute_one(code, forms::FST_STI, &state)?;
    let st0 = f64::from_bits(read_x87(&after, 0)?);
    let st1 = f64::from_bits(read_x87(&after, 1)?);
    assert_eq!(st0, 77.0, "ST(0) should be preserved");
    assert_eq!(st1, 77.0, "ST(1) should take ST(0)");
    Ok(())
}

#[test]
fn test_fstsw_m16() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDD, 0x38]; // fnstsw (%rax)
    let mut state = create_state(code)?;
    state
        .registers
        .write_in_place(register_id::GPR_BASE, &SCRATCH.to_le_bytes())?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0x3841_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FSTSW_M16, &state)?;
    let stored = read_concrete_bytes(&after.memory, SCRATCH, 2)?;
    let stored_sw = u16::from_le_bytes(stored[..2].try_into()?);
    assert_eq!(stored_sw, 0x3841, "fnstsw m16 should store exact status word");
    Ok(())
}

#[test]
fn test_wbinvd_and_invd() -> Result<(), BoxError> {
    let code_wbinvd: &[u8] = &[0x0F, 0x09]; // wbinvd
    let state = create_state(code_wbinvd)?;
    let _after_wbinvd = execute_one(code_wbinvd, forms::WBINVD, &state)?;

    let code_invd: &[u8] = &[0x0F, 0x08]; // invd
    let _after_invd = execute_one(code_invd, forms::INVD, &state)?;
    Ok(())
}

#[test]
fn test_fcmovcc_suite() -> Result<(), BoxError> {
    let rflags = register_id::RFLAGS.0;

    // Helper closure to test a condition
    let test_cmov = |code: &[u8], form: u32, true_flags: u64, false_flags: u64| -> Result<(), BoxError> {
        let mut state = create_state(code)?;
        clear_x87_stack(&mut state)?;
        seed_x87(&mut state, 0, 100.0_f64.to_bits())?;
        seed_x87(&mut state, 1, 200.0_f64.to_bits())?;

        // Test false case
        state.registers.write_in_place(rflags, &false_flags.to_le_bytes())?;
        let after_f = execute_one(code, form, &state)?;
        assert_eq!(
            f64::from_bits(read_x87(&after_f, 0)?),
            100.0,
            "should not move when condition false"
        );

        // Test true case
        state.registers.write_in_place(rflags, &true_flags.to_le_bytes())?;
        let after_t = execute_one(code, form, &state)?;
        assert_eq!(
            f64::from_bits(read_x87(&after_t, 0)?),
            200.0,
            "should move when condition true"
        );
        Ok(())
    };

    // fcmove (DA C9): ZF=1
    test_cmov(&[0xDA, 0xC9], forms::FCMOVE_ST0_STI, 1 << 6, 0)?;
    // fcmovne (DB C9): ZF=0
    test_cmov(&[0xDB, 0xC9], forms::FCMOVNE_ST0_STI, 0, 1 << 6)?;
    // fcmovb (DA C1): CF=1
    test_cmov(&[0xDA, 0xC1], forms::FCMOVB_ST0_STI, 1, 0)?;
    // fcmovnb (DB C1): CF=0
    test_cmov(&[0xDB, 0xC1], forms::FCMOVNB_ST0_STI, 0, 1)?;
    // fcmovbe (DA D1): CF=1 or ZF=1
    test_cmov(&[0xDA, 0xD1], forms::FCMOVBE_ST0_STI, 1 << 6, 0)?;
    // fcmovnbe (DB D1): CF=0 and ZF=0
    test_cmov(&[0xDB, 0xD1], forms::FCMOVNBE_ST0_STI, 0, 1)?;
    // fcmovu (DA D9): PF=1
    test_cmov(&[0xDA, 0xD9], forms::FCMOVU_ST0_STI, 1 << 2, 0)?;
    // fcmovnu (DB D9): PF=0
    test_cmov(&[0xDB, 0xD9], forms::FCMOVNU_ST0_STI, 0, 1 << 2)?;

    Ok(())
}
