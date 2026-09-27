#![forbid(unsafe_code)]

//! Native hardware differential oracle for scalar SSE arithmetic, square root,
//! conversions, min/max, and floating-point comparisons.
//!
//! Every case compiles and executes on the native host CPU, captures the
//! resulting XMM register lanes or RFLAGS condition bits, and executes the
//! identical instruction bytes through the decoder -> corpus provider ->
//! lowerer -> concrete interpreter pipeline to prove bit-for-bit equivalence.

use angryier_arch::{OperandKind, OperandVisibility};
use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_state::{ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState};
use angryier_types::{BlockId, FidelityProfile, ImageId, ObjectId, SemanticVersion, StateId, TargetProfileId};
use std::path::{Path, PathBuf};
use std::process::Command;

const CODE_BASE: u64 = 0x400000;
const SCRATCH: u64 = 0x500000;
const RESULT: u64 = SCRATCH + 0x80;
const STACK_TOP: u64 = 0x600000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(3);
const RSP: u32 = register_id::GPR_BASE + 4;

type BoxError = Box<dyn std::error::Error>;

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

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-scalar-sse-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn assemble(source: &Path, object: &Path) -> Option<()> {
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

fn link(binary: &Path, object: &Path) -> Option<()> {
    Command::new("ld")
        .arg("-Ttext=0x400000")
        .arg("-Tdata=0x500000")
        .arg("-o")
        .arg(binary)
        .arg(object)
        .output()
        .ok()?
        .status
        .success()
        .then_some(())
}

fn extract_text(dir: &Path, binary: &Path) -> Option<Vec<u8>> {
    let section = dir.join("case.text");
    let output = Command::new("objcopy")
        .arg("--dump-section")
        .arg(format!(".text={}", section.display()))
        .arg(binary)
        .arg("/dev/null")
        .output()
        .ok()?;
    output.status.success().then(|| std::fs::read(section).ok()).flatten()
}

fn xmm_harness_source(instruction: &str, left: [u8; 16], right: [u8; 16]) -> String {
    let mut left_lo_buf = [0u8; 8];
    left_lo_buf.copy_from_slice(&left[0..8]);
    let left_lo = u64::from_le_bytes(left_lo_buf);

    let mut left_hi_buf = [0u8; 8];
    left_hi_buf.copy_from_slice(&left[8..16]);
    let left_hi = u64::from_le_bytes(left_hi_buf);

    let mut right_lo_buf = [0u8; 8];
    right_lo_buf.copy_from_slice(&right[0..8]);
    let right_lo = u64::from_le_bytes(right_lo_buf);

    let mut right_hi_buf = [0u8; 8];
    right_hi_buf.copy_from_slice(&right[8..16]);
    let right_hi = u64::from_le_bytes(right_hi_buf);

    format!(
        r#"        .global _start
        .text
_start:
        movabs ${left_lo:#x}, %rax
        mov %rax, {SCRATCH:#x}
        movabs ${left_hi:#x}, %rax
        mov %rax, {SCRATCH_HI:#x}
        movabs ${right_lo:#x}, %rax
        mov %rax, {SCRATCH_RIGHT:#x}
        movabs ${right_hi:#x}, %rax
        mov %rax, {SCRATCH_RIGHT_HI:#x}
        movdqu {SCRATCH:#x}, %xmm0
        movdqu {SCRATCH_RIGHT:#x}, %xmm1
        {instruction}
        movdqu %xmm0, {RESULT:#x}
        mov $1, %rax
        mov $1, %rdi
        mov ${RESULT:#x}, %rsi
        mov $16, %rdx
        syscall
        mov $60, %rax
        xor %rdi, %rdi
        syscall
        .data
        .space 0x400
"#,
        SCRATCH = SCRATCH,
        SCRATCH_HI = SCRATCH + 8,
        SCRATCH_RIGHT = SCRATCH + 16,
        SCRATCH_RIGHT_HI = SCRATCH + 24,
        RESULT = RESULT,
        instruction = instruction,
    )
}

fn compare_harness_source(instruction: &str, left: [u8; 16], right: [u8; 16]) -> String {
    let mut left_lo_buf = [0u8; 8];
    left_lo_buf.copy_from_slice(&left[0..8]);
    let left_lo = u64::from_le_bytes(left_lo_buf);

    let mut left_hi_buf = [0u8; 8];
    left_hi_buf.copy_from_slice(&left[8..16]);
    let left_hi = u64::from_le_bytes(left_hi_buf);

    let mut right_lo_buf = [0u8; 8];
    right_lo_buf.copy_from_slice(&right[0..8]);
    let right_lo = u64::from_le_bytes(right_lo_buf);

    let mut right_hi_buf = [0u8; 8];
    right_hi_buf.copy_from_slice(&right[8..16]);
    let right_hi = u64::from_le_bytes(right_hi_buf);

    format!(
        r#"        .global _start
        .text
_start:
        movabs ${left_lo:#x}, %rax
        mov %rax, {SCRATCH:#x}
        movabs ${left_hi:#x}, %rax
        mov %rax, {SCRATCH_HI:#x}
        movabs ${right_lo:#x}, %rax
        mov %rax, {SCRATCH_RIGHT:#x}
        movabs ${right_hi:#x}, %rax
        mov %rax, {SCRATCH_RIGHT_HI:#x}
        movdqu {SCRATCH:#x}, %xmm0
        movdqu {SCRATCH_RIGHT:#x}, %xmm1
        {instruction}
        pushfq
        pop %rax
        movabs $0x45, %rbx
        and %rbx, %rax
        mov %rax, {RESULT:#x}
        mov $1, %rax
        mov $1, %rdi
        mov ${RESULT:#x}, %rsi
        mov $8, %rdx
        syscall
        mov $60, %rax
        xor %rdi, %rdi
        syscall
        .data
        .space 0x400
"#,
        SCRATCH = SCRATCH,
        SCRATCH_HI = SCRATCH + 8,
        SCRATCH_RIGHT = SCRATCH + 16,
        SCRATCH_RIGHT_HI = SCRATCH + 24,
        RESULT = RESULT,
        instruction = instruction,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reg64,
    Imm,
    Mem64,
    Mem128,
    Xmm,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 128 => Some(Shape::Xmm),
        OperandKind::Immediate(_) => Some(Shape::Imm),
        OperandKind::Memory(_) if operand.width_bits == 64 => Some(Shape::Mem64),
        OperandKind::Memory(_) if operand.width_bits == 128 => Some(Shape::Mem128),
        _ => None,
    }
}

fn map_form(decoded: &angryier_arch::DecodedInstruction) -> Option<u32> {
    use xed_sys as xed;
    let shapes = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility != OperandVisibility::Suppressed)
        .map(shape_of)
        .collect::<Option<Vec<_>>>()?;
    match decoded.form_id {
        xed::XED_ICLASS_MOV => match shapes.as_slice() {
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            _ => None,
        },
        xed::XED_ICLASS_MOVDQU => match shapes.as_slice() {
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVDQU_XMM_MEM),
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVDQU_MEM_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVDQU_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PUSHF | xed::XED_ICLASS_PUSHFQ => Some(forms::PUSHF),
        xed::XED_ICLASS_POPFQ => Some(forms::POPF),
        xed::XED_ICLASS_POP => match shapes.as_slice() {
            [Shape::Reg64] => Some(forms::POP_R64),
            _ => None,
        },
        xed::XED_ICLASS_AND => match shapes.as_slice() {
            [Shape::Reg64, Shape::Reg64] => Some(forms::AND_R64_R64),
            _ => None,
        },
        xed::XED_ICLASS_ADDSS => Some(forms::ADDSS_XMM_XMM),
        xed::XED_ICLASS_SUBSS => Some(forms::SUBSS_XMM_XMM),
        xed::XED_ICLASS_MULSS => Some(forms::MULSS_XMM_XMM),
        xed::XED_ICLASS_DIVSS => Some(forms::DIVSS_XMM_XMM),
        xed::XED_ICLASS_SQRTSS => Some(forms::SQRTSS_XMM_XMM),
        xed::XED_ICLASS_ADDSD => Some(forms::ADDSD_XMM_XMM),
        xed::XED_ICLASS_SUBSD => Some(forms::SUBSD_XMM_XMM),
        xed::XED_ICLASS_MULSD => Some(forms::MULSD_XMM_XMM),
        xed::XED_ICLASS_DIVSD => Some(forms::DIVSD_XMM_XMM),
        xed::XED_ICLASS_SQRTSD => Some(forms::SQRTSD_XMM_XMM),
        xed::XED_ICLASS_CVTSS2SD => Some(forms::CVTSS2SD_XMM_XMM),
        xed::XED_ICLASS_CVTSD2SS => Some(forms::CVTSD2SS_XMM_XMM),
        xed::XED_ICLASS_MAXSS => Some(forms::MAXSS_XMM_XMM),
        xed::XED_ICLASS_MAXSD => Some(forms::MAXSD_XMM_XMM),
        xed::XED_ICLASS_MINSS => Some(forms::MINSS_XMM_XMM),
        xed::XED_ICLASS_MINSD => Some(forms::MINSD_XMM_XMM),
        xed::XED_ICLASS_COMISS => Some(forms::COMISS_XMM_XMM),
        xed::XED_ICLASS_COMISD => Some(forms::COMISD_XMM_XMM),
        xed::XED_ICLASS_UCOMISS => Some(forms::UCOMISS_XMM_XMM),
        xed::XED_ICLASS_UCOMISD => Some(forms::UCOMISD_XMM_XMM),
        _ => None,
    }
}

struct EngineState {
    registers: PersistentRegisters,
    memory: PersistentMemory,
}

impl EngineState {
    fn new(code: &[u8]) -> Result<Self, BoxError> {
        let registers = PersistentRegisters::from_widths(
            Intel64RegisterFile::canonical()
                .architectural_registers
                .iter()
                .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
        )
        .map_err(|error| format!("register file: {error:?}"))?
        .write(RSP, &STACK_TOP.to_le_bytes())
        .map_err(|error| format!("rsp: {error:?}"))?;
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
        ])?
        .write(
            CODE_BASE,
            &code.iter().copied().map(ByteValue::Concrete).collect::<Vec<_>>(),
        )
        .map_err(|error| format!("code load: {error:?}"))?;
        Ok(Self { registers, memory })
    }
}

fn execution_state(engine: &EngineState) -> ExecutionState<PersistentRegisters, PersistentMemory> {
    ExecutionState {
        id: StateId(1),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers: engine.registers.clone(),
        memory: engine.memory.clone(),
        constraints: PersistentConstraintLineage::new(),
        ownership: angryier_state::StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    }
}

fn run_engine(code: &[u8], result_bytes: usize, registry: &Intel64CorpusRegistry) -> Result<Vec<u8>, BoxError> {
    let decoder = XedDecoder::new();
    let mut engine = EngineState::new(code)?;
    let mut pc = CODE_BASE;
    for _ in 0..512 {
        let offset = usize::try_from(pc - CODE_BASE).map_err(|_| "pc underflow")?;
        let bytes = code.get(offset..).ok_or_else(|| format!("pc {pc:#x} outside code"))?;
        let decoded = decoder
            .decode(pc, bytes)
            .map_err(|error| format!("decode at {pc:#x}: {error:?}"))?;
        if decoded.form_id == xed_sys::XED_ICLASS_SYSCALL {
            break;
        }
        let form = map_form(&decoded).ok_or_else(|| format!("unmapped iclass {} at {pc:#x}", decoded.form_id))?;
        let provider = registry
            .provider_for_form(form)
            .ok_or_else(|| format!("no provider for form {form:#x}"))?;
        let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
        provider
            .emit(&context(), &decoded, &mut builder)
            .map_err(|error| format!("emit form {form:#x}: {error:?}"))?;
        let sealed = builder
            .seal(
                angryier_types::ContentIdentitySchemaVersion(1),
                angryier_types::SemanticFingerprintSchemaVersion(1),
            )
            .map_err(|error| format!("seal form {form:#x}: {error:?}"))?;
        let key = BlockValidityKey {
            image: ImageId(1),
            block: BlockId(2),
            address: decoded.address,
            semantic_version: SEMANTIC_VERSION,
            target_profile: TARGET_PROFILE,
            code_versions: engine
                .memory
                .code_version_guards_for_range(decoded.address, usize::from(decoded.length))?,
        };
        let ir = BasicSemanticLowerer.lower_with_decode(&sealed, &key, &decoded)?;
        let state = execution_state(&engine);
        state
            .registers
            .write(register_id::RIP.0, &decoded.address.to_le_bytes())?;
        let (executed, outcome) = ConcreteInterpreter::new().execute_block(&state, &ir, ExecutionMode::Concrete)?;
        let next_pc = match outcome {
            ExecutionOutcome::Continue { next_pc, .. } => next_pc,
            other => return Err(format!("unexpected outcome {other:?}").into()),
        };
        engine.registers = executed.registers.write(register_id::RIP.0, &next_pc.to_le_bytes())?;
        engine.memory = executed.memory;
        pc = next_pc;
    }
    let bytes = engine.memory.read(RESULT, result_bytes)?;
    bytes
        .into_iter()
        .map(|byte| match byte {
            ByteValue::Concrete(value) => Ok(value),
            ByteValue::Symbolic { .. } => Err("symbolic result".into()),
        })
        .collect()
}

fn differential_xmm_case(name: &str, instruction: &str, left: [u8; 16], right: [u8; 16]) -> Result<(), BoxError> {
    let dir = temp_dir(name).ok_or("failed to create temp dir")?;
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    std::fs::write(&source, xmm_harness_source(instruction, left, right))?;
    if assemble(&source, &object).is_none() || link(&binary, &object).is_none() {
        return Err(format!("assembly/link failed for `{name}`").into());
    }
    let code = extract_text(&dir, &binary).ok_or("objcopy failed")?;
    let native = Command::new(&binary).output()?.stdout;
    if native.len() != 16 {
        return Err(format!("native wrote {} bytes, expected 16", native.len()).into());
    }
    let engine = run_engine(&code, 16, &Intel64CorpusRegistry::new(SEMANTIC_VERSION))
        .map_err(|error| format!("case `{name}`: {error}"))?;
    if engine != native {
        return Err(format!("mismatch in `{name}`: engine={engine:02x?} native={native:02x?}").into());
    }
    Ok(())
}

fn differential_cmp_case(name: &str, instruction: &str, left: [u8; 16], right: [u8; 16]) -> Result<(), BoxError> {
    let dir = temp_dir(name).ok_or("failed to create temp dir")?;
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    std::fs::write(&source, compare_harness_source(instruction, left, right))?;
    if assemble(&source, &object).is_none() || link(&binary, &object).is_none() {
        return Err(format!("assembly/link failed for `{name}`").into());
    }
    let code = extract_text(&dir, &binary).ok_or("objcopy failed")?;
    let native = Command::new(&binary).output()?.stdout;
    if native.len() != 8 {
        return Err(format!("native wrote {} bytes, expected 8", native.len()).into());
    }
    let engine = run_engine(&code, 8, &Intel64CorpusRegistry::new(SEMANTIC_VERSION))
        .map_err(|error| format!("case `{name}`: {error}"))?;
    if engine != native {
        return Err(format!("mismatch in `{name}`: engine={engine:02x?} native={native:02x?}").into());
    }
    Ok(())
}

fn pack_f32x4(lanes: [f32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, lane) in lanes.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&lane.to_le_bytes());
    }
    bytes
}

fn pack_f64x2(lanes: [f64; 2]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (i, lane) in lanes.iter().enumerate() {
        bytes[i * 8..(i + 1) * 8].copy_from_slice(&lane.to_le_bytes());
    }
    bytes
}

#[test]
fn test_scalar_sse_addss_subss_mulss_divss_preserves_upper() -> Result<(), BoxError> {
    let left = pack_f32x4([10.5, 1.0, 2.0, 3.0]);
    let right = pack_f32x4([4.25, 99.0, 99.0, 99.0]);

    differential_xmm_case("addss", "addss %xmm1, %xmm0", left, right)?;
    differential_xmm_case("subss", "subss %xmm1, %xmm0", left, right)?;
    differential_xmm_case("mulss", "mulss %xmm1, %xmm0", left, right)?;
    differential_xmm_case("divss", "divss %xmm1, %xmm0", left, right)?;
    Ok(())
}

#[test]
fn test_scalar_sse_addsd_subsd_mulsd_divsd_preserves_upper() -> Result<(), BoxError> {
    let left = pack_f64x2([15.5, 42.0]);
    let right = pack_f64x2([2.5, 99.0]);

    differential_xmm_case("addsd", "addsd %xmm1, %xmm0", left, right)?;
    differential_xmm_case("subsd", "subsd %xmm1, %xmm0", left, right)?;
    differential_xmm_case("mulsd", "mulsd %xmm1, %xmm0", left, right)?;
    differential_xmm_case("divsd", "divsd %xmm1, %xmm0", left, right)?;
    Ok(())
}

#[test]
fn test_scalar_sse_sqrtss_and_sqrtsd_preserves_upper() -> Result<(), BoxError> {
    let left_f32 = pack_f32x4([0.0, 10.0, 20.0, 30.0]);
    let right_f32_4 = pack_f32x4([4.0, 0.0, 0.0, 0.0]);
    let right_f32_2 = pack_f32x4([2.0, 0.0, 0.0, 0.0]);

    differential_xmm_case("sqrtss_4", "sqrtss %xmm1, %xmm0", left_f32, right_f32_4)?;
    differential_xmm_case("sqrtss_2", "sqrtss %xmm1, %xmm0", left_f32, right_f32_2)?;

    let left_f64 = pack_f64x2([0.0, 88.0]);
    let right_f64_4 = pack_f64x2([4.0, 0.0]);
    let right_f64_2 = pack_f64x2([2.0, 0.0]);

    differential_xmm_case("sqrtsd_4", "sqrtsd %xmm1, %xmm0", left_f64, right_f64_4)?;
    differential_xmm_case("sqrtsd_2", "sqrtsd %xmm1, %xmm0", left_f64, right_f64_2)?;
    Ok(())
}

#[test]
fn test_scalar_sse_cvtss2sd_and_cvtsd2ss_preserves_upper() -> Result<(), BoxError> {
    let dst_for_sd = pack_f64x2([0.0, 1234.5]);
    let src_ss = pack_f32x4([1.5, 99.0, 99.0, 99.0]);
    differential_xmm_case("cvtss2sd_1_5", "cvtss2sd %xmm1, %xmm0", dst_for_sd, src_ss)?;

    let src_ss_neg = pack_f32x4([-256.75, 99.0, 99.0, 99.0]);
    differential_xmm_case("cvtss2sd_neg", "cvtss2sd %xmm1, %xmm0", dst_for_sd, src_ss_neg)?;

    let dst_for_ss = pack_f32x4([0.0, 10.0, 20.0, 30.0]);
    let src_sd = pack_f64x2([1.5, 99.0]);
    differential_xmm_case("cvtsd2ss_1_5", "cvtsd2ss %xmm1, %xmm0", dst_for_ss, src_sd)?;

    let src_sd_large = pack_f64x2([1024.125, 99.0]);
    differential_xmm_case("cvtsd2ss_large", "cvtsd2ss %xmm1, %xmm0", dst_for_ss, src_sd_large)?;
    Ok(())
}

#[test]
fn test_scalar_sse_maxss_minss_maxsd_minsd_preserves_upper() -> Result<(), BoxError> {
    let left_f32 = pack_f32x4([2.0, 10.0, 20.0, 30.0]);
    let right_f32 = pack_f32x4([5.0, 99.0, 99.0, 99.0]);

    differential_xmm_case("maxss_less", "maxss %xmm1, %xmm0", left_f32, right_f32)?;
    differential_xmm_case("maxss_greater", "maxss %xmm1, %xmm0", right_f32, left_f32)?;
    differential_xmm_case("minss_less", "minss %xmm1, %xmm0", left_f32, right_f32)?;
    differential_xmm_case("minss_greater", "minss %xmm1, %xmm0", right_f32, left_f32)?;

    let left_f64 = pack_f64x2([2.5, 42.0]);
    let right_f64 = pack_f64x2([8.5, 99.0]);

    differential_xmm_case("maxsd", "maxsd %xmm1, %xmm0", left_f64, right_f64)?;
    differential_xmm_case("minsd", "minsd %xmm1, %xmm0", left_f64, right_f64)?;
    Ok(())
}

#[test]
fn test_scalar_sse_comiss_and_ucomiss_flag_outcomes() -> Result<(), BoxError> {
    let eq1 = pack_f32x4([2.0, 0.0, 0.0, 0.0]);
    let eq2 = pack_f32x4([2.0, 0.0, 0.0, 0.0]);
    let lt = pack_f32x4([1.0, 0.0, 0.0, 0.0]);
    let gt = pack_f32x4([3.0, 0.0, 0.0, 0.0]);
    let nan = pack_f32x4([f32::NAN, 0.0, 0.0, 0.0]);

    // COMISS
    differential_cmp_case("comiss_eq", "comiss %xmm1, %xmm0", eq1, eq2)?;
    differential_cmp_case("comiss_lt", "comiss %xmm1, %xmm0", lt, eq2)?;
    differential_cmp_case("comiss_gt", "comiss %xmm1, %xmm0", gt, eq2)?;
    differential_cmp_case("comiss_nan", "comiss %xmm1, %xmm0", nan, eq2)?;

    // UCOMISS
    differential_cmp_case("ucomiss_eq", "ucomiss %xmm1, %xmm0", eq1, eq2)?;
    differential_cmp_case("ucomiss_lt", "ucomiss %xmm1, %xmm0", lt, eq2)?;
    differential_cmp_case("ucomiss_gt", "ucomiss %xmm1, %xmm0", gt, eq2)?;
    differential_cmp_case("ucomiss_nan", "ucomiss %xmm1, %xmm0", eq1, nan)?;
    Ok(())
}

#[test]
fn test_scalar_sse_comisd_and_ucomisd_flag_outcomes() -> Result<(), BoxError> {
    let eq1 = pack_f64x2([2.0, 0.0]);
    let eq2 = pack_f64x2([2.0, 0.0]);
    let lt = pack_f64x2([1.0, 0.0]);
    let gt = pack_f64x2([3.0, 0.0]);
    let nan = pack_f64x2([f64::NAN, 0.0]);

    // COMISD
    differential_cmp_case("comisd_eq", "comisd %xmm1, %xmm0", eq1, eq2)?;
    differential_cmp_case("comisd_lt", "comisd %xmm1, %xmm0", lt, eq2)?;
    differential_cmp_case("comisd_gt", "comisd %xmm1, %xmm0", gt, eq2)?;
    differential_cmp_case("comisd_nan", "comisd %xmm1, %xmm0", nan, eq2)?;

    // UCOMISD
    differential_cmp_case("ucomisd_eq", "ucomisd %xmm1, %xmm0", eq1, eq2)?;
    differential_cmp_case("ucomisd_lt", "ucomisd %xmm1, %xmm0", lt, eq2)?;
    differential_cmp_case("ucomisd_gt", "ucomisd %xmm1, %xmm0", gt, eq2)?;
    differential_cmp_case("ucomisd_nan", "ucomisd %xmm1, %xmm0", eq1, nan)?;
    Ok(())
}
