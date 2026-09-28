#![forbid(unsafe_code)]

//! Native differential oracle for AVX packed-single arithmetic/logical forms
//! and VEX scalar-single arithmetic forms. Every case assembles with binutils,
//! executes on the host, and runs the identical bytes through the semantic
//! provider, lowerer, and concrete interpreter.

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
    let dir = std::env::temp_dir().join(format!("angryier-avx-{name}-{}", std::process::id()));
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

fn harness_source(instruction: &str, left: [u32; 8], right: [u32; 8]) -> String {
    let mut body = String::from("        .global _start\n        .text\n_start:\n");
    for (base, values) in [(SCRATCH, left), (SCRATCH + 32, right)] {
        for (index, pair) in values.as_chunks::<2>().0.iter().enumerate() {
            let qword = u64::from(pair[0]) | (u64::from(pair[1]) << 32);
            body.push_str(&format!(
                "    movabs ${qword:#x}, %rax\n    mov %rax, {:#x}\n",
                base + (index as u64 * 8)
            ));
        }
    }
    body.push_str(&format!(
        "    vmovdqu {SCRATCH:#x}, %ymm1\n    vmovdqu {:#x}, %ymm2\n    vmovdqu {SCRATCH:#x}, %ymm3\n    {instruction}\n    vmovdqu %ymm0, {RESULT:#x}\n    mov $1, %rax\n    mov $1, %rdi\n    mov ${RESULT:#x}, %rsi\n    mov $32, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\n        .space 0x400\n",
        SCRATCH + 32
    ));
    body
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reg64,
    Imm,
    Mem64,
    Mem32,
    Mem,
    Xmm,
    Ymm,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 128 => Some(Shape::Xmm),
        OperandKind::Register(view) if view.width_bits == 256 => Some(Shape::Ymm),
        OperandKind::Immediate(_) => Some(Shape::Imm),
        OperandKind::Memory(_) if operand.width_bits == 32 => Some(Shape::Mem32),
        OperandKind::Memory(_) if operand.width_bits == 64 => Some(Shape::Mem64),
        OperandKind::Memory(_) if operand.width_bits == 256 => Some(Shape::Mem),
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
        xed::XED_ICLASS_VMOVDQU => match shapes.as_slice() {
            [Shape::Ymm, Shape::Mem] => Some(forms::VMOVDQU_YMM_MEM),
            [Shape::Mem, Shape::Ymm] => Some(forms::VMOVDQU_MEM_YMM),
            _ => None,
        },
        xed::XED_ICLASS_VADDPS => packed_form(&shapes, forms::VADDPS_YMM_YMM_YMM, forms::VADDPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VSUBPS => packed_form(&shapes, forms::VSUBPS_YMM_YMM_YMM, forms::VSUBPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VMULPS => packed_form(&shapes, forms::VMULPS_YMM_YMM_YMM, forms::VMULPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VDIVPS => packed_form(&shapes, forms::VDIVPS_YMM_YMM_YMM, forms::VDIVPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VANDPS => packed_form(&shapes, forms::VANDPS_YMM_YMM_YMM, forms::VANDPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VANDNPS => packed_form(&shapes, forms::VANDNPS_YMM_YMM_YMM, forms::VANDNPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VORPS => packed_form(&shapes, forms::VORPS_YMM_YMM_YMM, forms::VORPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VADDSS => scalar_form(&shapes, forms::VADDSS_XMM_XMM_XMM, forms::VADDSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VSUBSS => scalar_form(&shapes, forms::VSUBSS_XMM_XMM_XMM, forms::VSUBSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VMULSS => scalar_form(&shapes, forms::VMULSS_XMM_XMM_XMM, forms::VMULSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VDIVSS => scalar_form(&shapes, forms::VDIVSS_XMM_XMM_XMM, forms::VDIVSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VADDPD => packed_form(&shapes, forms::VADDPD_YMM_YMM_YMM, forms::VADDPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VSUBPD => packed_form(&shapes, forms::VSUBPD_YMM_YMM_YMM, forms::VSUBPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VMULPD => packed_form(&shapes, forms::VMULPD_YMM_YMM_YMM, forms::VMULPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VDIVPD => packed_form(&shapes, forms::VDIVPD_YMM_YMM_YMM, forms::VDIVPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VADDSD => scalar_double_form(&shapes, forms::VADDSD_XMM_XMM_XMM, forms::VADDSD_XMM_XMM_MEM64),
        xed::XED_ICLASS_VSUBSD => scalar_double_form(&shapes, forms::VSUBSD_XMM_XMM_XMM, forms::VSUBSD_XMM_XMM_MEM64),
        xed::XED_ICLASS_VMULSD => scalar_double_form(&shapes, forms::VMULSD_XMM_XMM_XMM, forms::VMULSD_XMM_XMM_MEM64),
        xed::XED_ICLASS_VDIVSD => scalar_double_form(&shapes, forms::VDIVSD_XMM_XMM_XMM, forms::VDIVSD_XMM_XMM_MEM64),
        xed::XED_ICLASS_VANDPD => packed_form(&shapes, forms::VANDPD_YMM_YMM_YMM, forms::VANDPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VANDNPD => packed_form(&shapes, forms::VANDNPD_YMM_YMM_YMM, forms::VANDNPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VORPD => packed_form(&shapes, forms::VORPD_YMM_YMM_YMM, forms::VORPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VXORPD => packed_form(&shapes, forms::VXORPD_YMM_YMM_YMM, forms::VXORPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VCVTSS2SD => scalar_form(&shapes, forms::VCVTSS2SD_XMM_XMM_XMM, forms::VCVTSS2SD_XMM_XMM_MEM32),
        xed::XED_ICLASS_VCVTSD2SS => {
            scalar_double_form(&shapes, forms::VCVTSD2SS_XMM_XMM_XMM, forms::VCVTSD2SS_XMM_XMM_MEM64)
        }
        xed::XED_ICLASS_VBLENDPS => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VBLENDPS_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VBLENDPS_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VBLENDPD => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VBLENDPD_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VBLENDPD_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VBLENDVPS => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VBLENDVPS_YMM_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Ymm] => Some(forms::VBLENDVPS_YMM_YMM_MEM_YMM),
            _ => None,
        },
        xed::XED_ICLASS_VBLENDVPD => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VBLENDVPD_YMM_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Ymm] => Some(forms::VBLENDVPD_YMM_YMM_MEM_YMM),
            _ => None,
        },
        xed::XED_ICLASS_VPERM2F128 => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERM2F128_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERM2F128_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VPERMILPS => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERMILPS_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERMILPS_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VPERMILPD => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERMILPD_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERMILPD_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VSHUFPS => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VSHUFPS_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VSHUFPS_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VSHUFPD => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VSHUFPD_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VSHUFPD_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_VUNPCKLPS => packed_form(&shapes, forms::VUNPCKLPS_YMM_YMM_YMM, forms::VUNPCKLPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VUNPCKHPS => packed_form(&shapes, forms::VUNPCKHPS_YMM_YMM_YMM, forms::VUNPCKHPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VUNPCKLPD => packed_form(&shapes, forms::VUNPCKLPD_YMM_YMM_YMM, forms::VUNPCKLPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VUNPCKHPD => packed_form(&shapes, forms::VUNPCKHPD_YMM_YMM_YMM, forms::VUNPCKHPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VMINPS => packed_form(&shapes, forms::VMINPS_YMM_YMM_YMM, forms::VMINPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VMAXPS => packed_form(&shapes, forms::VMAXPS_YMM_YMM_YMM, forms::VMAXPS_YMM_YMM_MEM),
        xed::XED_ICLASS_VMINPD => packed_form(&shapes, forms::VMINPD_YMM_YMM_YMM, forms::VMINPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VMAXPD => packed_form(&shapes, forms::VMAXPD_YMM_YMM_YMM, forms::VMAXPD_YMM_YMM_MEM),
        xed::XED_ICLASS_VMINSS => scalar_form(&shapes, forms::VMINSS_XMM_XMM_XMM, forms::VMINSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VMAXSS => scalar_form(&shapes, forms::VMAXSS_XMM_XMM_XMM, forms::VMAXSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VMINSD => scalar_double_form(&shapes, forms::VMINSD_XMM_XMM_XMM, forms::VMINSD_XMM_XMM_MEM64),
        xed::XED_ICLASS_VMAXSD => scalar_double_form(&shapes, forms::VMAXSD_XMM_XMM_XMM, forms::VMAXSD_XMM_XMM_MEM64),
        xed::XED_ICLASS_VSQRTPS => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VSQRTPS_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VSQRTPS_YMM_MEM),
            _ => None,
        },
        xed::XED_ICLASS_VSQRTPD => match shapes.as_slice() {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VSQRTPD_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VSQRTPD_YMM_MEM),
            _ => None,
        },
        xed::XED_ICLASS_VSQRTSS => scalar_form(&shapes, forms::VSQRTSS_XMM_XMM_XMM, forms::VSQRTSS_XMM_XMM_MEM32),
        xed::XED_ICLASS_VSQRTSD => {
            scalar_double_form(&shapes, forms::VSQRTSD_XMM_XMM_XMM, forms::VSQRTSD_XMM_XMM_MEM64)
        }
        _ => None,
    }
}

fn packed_form(shapes: &[Shape], register: u32, memory: u32) -> Option<u32> {
    match shapes {
        [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(register),
        [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(memory),
        _ => None,
    }
}

fn scalar_form(shapes: &[Shape], register: u32, memory: u32) -> Option<u32> {
    match shapes {
        [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(register),
        [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(memory),
        _ => None,
    }
}

fn scalar_double_form(shapes: &[Shape], register: u32, memory: u32) -> Option<u32> {
    match shapes {
        [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(register),
        [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(memory),
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

fn run_engine(code: &[u8], registry: &Intel64CorpusRegistry) -> Result<[u8; 32], BoxError> {
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
    let bytes = engine.memory.read(RESULT, 32)?;
    let concrete = bytes
        .into_iter()
        .map(|byte| match byte {
            ByteValue::Concrete(value) => Ok(value),
            ByteValue::Symbolic { .. } => Err("symbolic result"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(concrete.try_into().map_err(|_| "wrong result length")?)
}

fn differential_case(name: &str, instruction: &str, left: [u32; 8], right: [u32; 8]) -> Result<bool, BoxError> {
    let Some(dir) = temp_dir(name) else { return Ok(false) };
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    std::fs::write(&source, harness_source(instruction, left, right))?;
    if assemble(&source, &object).is_none() || link(&binary, &object).is_none() {
        return Ok(false);
    }
    let code = extract_text(&dir, &binary).ok_or("objcopy failed")?;
    let native = Command::new(&binary).output()?.stdout;
    let native: [u8; 32] = native
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("native wrote {} bytes", bytes.len()))?;
    let engine = run_engine(&code, &Intel64CorpusRegistry::new(SEMANTIC_VERSION))
        .map_err(|error| format!("case `{name}`: {error}"))?;
    if engine != native {
        return Err(format!("AVX mismatch in `{name}`: engine={engine:02x?} native={native:02x?}").into());
    }
    Ok(true)
}

const PATTERNS: [([u32; 8], [u32; 8]); 2] = [
    (
        [
            0,
            0xffff_ffff,
            0x3f80_0000,
            0x4000_0000,
            0x7f80_0000,
            0x7fc0_0001,
            1,
            0x8000_0000,
        ],
        [0x3f80_0000, 0, 0x4000_0000, 0x3f80_0000, 0, 0x7f80_0000, 1, 0xbf80_0000],
    ),
    (
        [
            0x4040_0000,
            0xc000_0000,
            0x0080_0000,
            1,
            0x7f7f_ffff,
            0xff80_0000,
            0x5555_5555,
            0xaaaa_aaaa,
        ],
        [
            0x3f00_0000,
            0x4000_0000,
            1,
            0,
            0x3f80_0000,
            0x7f80_0000,
            0x0f0f_0f0f,
            0xf0f0_f0f0,
        ],
    ),
];

#[test]
fn avx_family_differential() -> Result<(), BoxError> {
    let forms = [
        ("vaddps_reg", "vaddps %ymm2, %ymm1, %ymm0"),
        ("vaddps_mem", "vaddps 0x500020, %ymm1, %ymm0"),
        ("vsubps_reg", "vsubps %ymm2, %ymm1, %ymm0"),
        ("vsubps_mem", "vsubps 0x500020, %ymm1, %ymm0"),
        ("vmulps_reg", "vmulps %ymm2, %ymm1, %ymm0"),
        ("vmulps_mem", "vmulps 0x500020, %ymm1, %ymm0"),
        ("vdivps_reg", "vdivps %ymm2, %ymm1, %ymm0"),
        ("vdivps_mem", "vdivps 0x500020, %ymm1, %ymm0"),
        ("vaddss_reg", "vaddss %xmm2, %xmm1, %xmm0"),
        ("vaddss_mem", "vaddss 0x500020, %xmm1, %xmm0"),
        ("vsubss_reg", "vsubss %xmm2, %xmm1, %xmm0"),
        ("vsubss_mem", "vsubss 0x500020, %xmm1, %xmm0"),
        ("vmulss_reg", "vmulss %xmm2, %xmm1, %xmm0"),
        ("vmulss_mem", "vmulss 0x500020, %xmm1, %xmm0"),
        ("vdivss_reg", "vdivss %xmm2, %xmm1, %xmm0"),
        ("vdivss_mem", "vdivss 0x500020, %xmm1, %xmm0"),
        ("vandps_reg", "vandps %ymm2, %ymm1, %ymm0"),
        ("vandps_mem", "vandps 0x500020, %ymm1, %ymm0"),
        ("vandnps_reg", "vandnps %ymm2, %ymm1, %ymm0"),
        ("vandnps_mem", "vandnps 0x500020, %ymm1, %ymm0"),
        ("vorps_reg", "vorps %ymm2, %ymm1, %ymm0"),
        ("vorps_mem", "vorps 0x500020, %ymm1, %ymm0"),
    ];
    let mut count = 0usize;
    for (pattern, (left, right)) in PATTERNS.into_iter().enumerate() {
        for (name, instruction) in forms {
            let case_right = if name.starts_with("vdiv") {
                right.map(|lane| if lane & 0x7fff_ffff == 0 { 0x3f80_0000 } else { lane })
            } else {
                right
            };
            if differential_case(&format!("{name}_{pattern}"), instruction, left, case_right)? {
                count += 1;
            }
        }
    }
    if count == 0 {
        eprintln!("SKIP: binutils unavailable");
    } else {
        eprintln!("AVX differential: {count} native cases passed");
    }
    if count != 0 && count != 44 {
        return Err(format!("expected 44 native cases, ran {count}").into());
    }
    Ok(())
}

/// `vdivps` by a zero divisor must produce the architectural IEEE-754
/// result (+Inf for 1.0/0.0, -Inf for -1.0/0.0), matching the host CPU
/// byte-for-byte. The concrete interpreter previously rejected the divide.
#[test]
fn avx_divide_by_zero_matches_hardware() -> Result<(), BoxError> {
    let Some(dir) = temp_dir("vdivps_zero_probe") else {
        eprintln!("SKIP: binutils unavailable");
        return Ok(());
    };
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    let left = [0x3f80_0000; 8];
    let right = [0; 8];
    std::fs::write(&source, harness_source("vdivps %ymm2, %ymm1, %ymm0", left, right))?;
    if assemble(&source, &object).is_none() || link(&binary, &object).is_none() {
        eprintln!("SKIP: binutils unavailable");
        return Ok(());
    }
    let native = Command::new(&binary).output()?.stdout;
    if native.len() != 32 {
        return Err(format!("divide-by-zero native probe wrote {} bytes", native.len()).into());
    }
    let code = extract_text(&dir, &binary).ok_or("objcopy failed")?;
    let engine = run_engine(&code, &Intel64CorpusRegistry::new(SEMANTIC_VERSION))
        .map_err(|e| format!("engine failed to execute vdivps-by-zero: {e}"))?;
    if native != engine {
        return Err(format!("vdivps-by-zero mismatch: native={native:02x?} engine={engine:02x?}").into());
    }
    let lane = u32::from_le_bytes(native[..4].try_into()?);
    if lane != 0x7f80_0000 {
        return Err(format!("expected +Inf lane 0x7f800000, got {lane:#x}").into());
    }
    eprintln!("AVX divide-by-zero: 1 native case matched (+Inf lanes)");
    Ok(())
}

const DOUBLE_PATTERNS: [([u32; 8], [u32; 8]); 2] = [
    (
        // Pattern 0: left = [1.0, 2.0, 3.0, 4.0], right = [5.0, 6.0, 7.0, 8.0]
        [
            0x0000_0000,
            0x3ff0_0000, // 1.0
            0x0000_0000,
            0x4000_0000, // 2.0
            0x0000_0000,
            0x4008_0000, // 3.0
            0x0000_0000,
            0x4010_0000, // 4.0
        ],
        [
            0x0000_0000,
            0x4014_0000, // 5.0
            0x0000_0000,
            0x4018_0000, // 6.0
            0x0000_0000,
            0x401c_0000, // 7.0
            0x0000_0000,
            0x4020_0000, // 8.0
        ],
    ),
    (
        // Pattern 1: mixed positive, negative, fractional
        [
            0x0000_0000,
            0x4059_2000, // 100.5
            0x0000_0000,
            0xc034_4000, // -20.25
            0x0000_0000,
            0x0000_0000, // 0.0
            0x0000_0000,
            0xbff0_0000, // -1.0
        ],
        [
            0x0000_0000,
            0x4004_0000, // 2.5
            0x0000_0000,
            0x4010_0000, // 4.0
            0x0000_0000,
            0xc014_0000, // -5.0
            0x0000_0000,
            0x4000_0000, // 2.0
        ],
    ),
];

#[test]
fn avx_double_family_differential() -> Result<(), BoxError> {
    let forms = [
        ("vaddpd_reg", "vaddpd %ymm2, %ymm1, %ymm0"),
        ("vaddpd_mem", "vaddpd 0x500020, %ymm1, %ymm0"),
        ("vsubpd_reg", "vsubpd %ymm2, %ymm1, %ymm0"),
        ("vsubpd_mem", "vsubpd 0x500020, %ymm1, %ymm0"),
        ("vmulpd_reg", "vmulpd %ymm2, %ymm1, %ymm0"),
        ("vmulpd_mem", "vmulpd 0x500020, %ymm1, %ymm0"),
        ("vdivpd_reg", "vdivpd %ymm2, %ymm1, %ymm0"),
        ("vdivpd_mem", "vdivpd 0x500020, %ymm1, %ymm0"),
        ("vaddsd_reg", "vaddsd %xmm2, %xmm1, %xmm0"),
        ("vaddsd_mem", "vaddsd 0x500020, %xmm1, %xmm0"),
        ("vsubsd_reg", "vsubsd %xmm2, %xmm1, %xmm0"),
        ("vsubsd_mem", "vsubsd 0x500020, %xmm1, %xmm0"),
        ("vmulsd_reg", "vmulsd %xmm2, %xmm1, %xmm0"),
        ("vmulsd_mem", "vmulsd 0x500020, %xmm1, %xmm0"),
        ("vdivsd_reg", "vdivsd %xmm2, %xmm1, %xmm0"),
        ("vdivsd_mem", "vdivsd 0x500020, %xmm1, %xmm0"),
        ("vandpd_reg", "vandpd %ymm2, %ymm1, %ymm0"),
        ("vandpd_mem", "vandpd 0x500020, %ymm1, %ymm0"),
        ("vandnpd_reg", "vandnpd %ymm2, %ymm1, %ymm0"),
        ("vandnpd_mem", "vandnpd 0x500020, %ymm1, %ymm0"),
        ("vorpd_reg", "vorpd %ymm2, %ymm1, %ymm0"),
        ("vorpd_mem", "vorpd 0x500020, %ymm1, %ymm0"),
        ("vxorpd_reg", "vxorpd %ymm2, %ymm1, %ymm0"),
        ("vxorpd_mem", "vxorpd 0x500020, %ymm1, %ymm0"),
    ];
    let mut count = 0usize;
    for (pattern, (left, right)) in DOUBLE_PATTERNS.into_iter().enumerate() {
        for (name, instruction) in forms {
            if differential_case(&format!("{name}_{pattern}"), instruction, left, right)? {
                count += 1;
            }
        }
    }
    if count == 0 {
        eprintln!("SKIP: binutils unavailable");
    } else {
        eprintln!("AVX double differential: {count} native cases passed");
    }
    if count != 0 && count != 48 {
        return Err(format!("expected 48 native cases, ran {count}").into());
    }
    Ok(())
}

#[test]
fn avx_double_divide_by_zero_matches_hardware() -> Result<(), BoxError> {
    let Some(dir) = temp_dir("vdivpd_zero_probe") else {
        eprintln!("SKIP: binutils unavailable");
        return Ok(());
    };
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    let left = [
        0x0000_0000,
        0x3ff0_0000,
        0x0000_0000,
        0x3ff0_0000,
        0x0000_0000,
        0x3ff0_0000,
        0x0000_0000,
        0x3ff0_0000,
    ];
    let right = [0; 8];
    std::fs::write(&source, harness_source("vdivpd %ymm2, %ymm1, %ymm0", left, right))?;
    if assemble(&source, &object).is_none() || link(&binary, &object).is_none() {
        eprintln!("SKIP: binutils unavailable");
        return Ok(());
    }
    let native = Command::new(&binary).output()?.stdout;
    if native.len() != 32 {
        return Err(format!("vdivpd divide-by-zero native probe wrote {} bytes", native.len()).into());
    }
    let code = extract_text(&dir, &binary).ok_or("objcopy failed")?;
    let engine = run_engine(&code, &Intel64CorpusRegistry::new(SEMANTIC_VERSION))
        .map_err(|e| format!("engine failed to execute vdivpd-by-zero: {e}"))?;
    if native != engine {
        return Err(format!("vdivpd-by-zero mismatch: native={native:02x?} engine={engine:02x?}").into());
    }
    let lane = u64::from_le_bytes(native[..8].try_into()?);
    if lane != 0x7ff0_0000_0000_0000 {
        return Err(format!("expected +Inf lane 0x7ff0000000000000, got {lane:#x}").into());
    }
    eprintln!("AVX double divide-by-zero: 1 native case matched (+Inf lanes)");
    Ok(())
}

#[test]
fn avx_blend_cvt_perm_differential() -> Result<(), BoxError> {
    let forms = [
        ("vcvtss2sd_reg", "vcvtss2sd %xmm2, %xmm1, %xmm0"),
        ("vcvtss2sd_mem", "vcvtss2sd 0x500020, %xmm1, %xmm0"),
        ("vcvtsd2ss_reg", "vcvtsd2ss %xmm2, %xmm1, %xmm0"),
        ("vcvtsd2ss_mem", "vcvtsd2ss 0x500020, %xmm1, %xmm0"),
        ("vblendps_reg", "vblendps $0x55, %ymm2, %ymm1, %ymm0"),
        ("vblendps_mem", "vblendps $0x55, 0x500020, %ymm1, %ymm0"),
        ("vblendpd_reg", "vblendpd $0x0a, %ymm2, %ymm1, %ymm0"),
        ("vblendpd_mem", "vblendpd $0x0a, 0x500020, %ymm1, %ymm0"),
        ("vblendvps_reg", "vblendvps %ymm3, %ymm2, %ymm1, %ymm0"),
        ("vblendvps_mem", "vblendvps %ymm3, 0x500020, %ymm1, %ymm0"),
        ("vblendvpd_reg", "vblendvpd %ymm3, %ymm2, %ymm1, %ymm0"),
        ("vblendvpd_mem", "vblendvpd %ymm3, 0x500020, %ymm1, %ymm0"),
        ("vperm2f128_reg", "vperm2f128 $0x31, %ymm2, %ymm1, %ymm0"),
        ("vperm2f128_mem", "vperm2f128 $0x31, 0x500020, %ymm1, %ymm0"),
        ("vpermilps_reg", "vpermilps $0x4e, %ymm1, %ymm0"),
        ("vpermilps_mem", "vpermilps $0x4e, 0x500000, %ymm0"),
        ("vpermilpd_reg", "vpermilpd $0x05, %ymm1, %ymm0"),
        ("vpermilpd_mem", "vpermilpd $0x05, 0x500000, %ymm0"),
    ];
    let mut count = 0usize;
    for (pattern, (left, right)) in PATTERNS.into_iter().enumerate() {
        for (name, instruction) in forms {
            if differential_case(&format!("{name}_{pattern}"), instruction, left, right)? {
                count += 1;
            }
        }
    }
    if count == 0 {
        eprintln!("SKIP: binutils unavailable");
    } else {
        eprintln!("AVX blend/cvt/perm differential: {count} native cases passed");
    }
    if count != 0 && count != 36 {
        return Err(format!("expected 36 native cases, ran {count}").into());
    }
    Ok(())
}

#[test]
fn avx_shuf_unpck_differential() -> Result<(), BoxError> {
    let forms = [
        ("vshufps_reg", "vshufps $0x4e, %ymm2, %ymm1, %ymm0"),
        ("vshufps_mem", "vshufps $0x4e, 0x500020, %ymm1, %ymm0"),
        ("vshufpd_reg", "vshufpd $0x05, %ymm2, %ymm1, %ymm0"),
        ("vshufpd_mem", "vshufpd $0x05, 0x500020, %ymm1, %ymm0"),
        ("vunpcklps_reg", "vunpcklps %ymm2, %ymm1, %ymm0"),
        ("vunpcklps_mem", "vunpcklps 0x500020, %ymm1, %ymm0"),
        ("vunpckhps_reg", "vunpckhps %ymm2, %ymm1, %ymm0"),
        ("vunpckhps_mem", "vunpckhps 0x500020, %ymm1, %ymm0"),
        ("vunpcklpd_reg", "vunpcklpd %ymm2, %ymm1, %ymm0"),
        ("vunpcklpd_mem", "vunpcklpd 0x500020, %ymm1, %ymm0"),
        ("vunpckhpd_reg", "vunpckhpd %ymm2, %ymm1, %ymm0"),
        ("vunpckhpd_mem", "vunpckhpd 0x500020, %ymm1, %ymm0"),
    ];
    let mut count = 0usize;
    for (pattern, (left, right)) in PATTERNS.into_iter().enumerate() {
        for (name, instruction) in forms {
            if differential_case(&format!("{name}_{pattern}"), instruction, left, right)? {
                count += 1;
            }
        }
    }
    if count == 0 {
        eprintln!("SKIP: binutils unavailable");
    } else {
        eprintln!("AVX shuf/unpck differential: {count} native cases passed");
    }
    if count != 0 && count != 24 {
        return Err(format!("expected 24 native cases, ran {count}").into());
    }
    Ok(())
}

#[test]
fn avx_minmax_sqrt_differential() -> Result<(), BoxError> {
    let forms = [
        ("vminps_reg", "vminps %ymm2, %ymm1, %ymm0"),
        ("vminps_mem", "vminps 0x500020, %ymm1, %ymm0"),
        ("vmaxps_reg", "vmaxps %ymm2, %ymm1, %ymm0"),
        ("vmaxps_mem", "vmaxps 0x500020, %ymm1, %ymm0"),
        ("vminpd_reg", "vminpd %ymm2, %ymm1, %ymm0"),
        ("vminpd_mem", "vminpd 0x500020, %ymm1, %ymm0"),
        ("vmaxpd_reg", "vmaxpd %ymm2, %ymm1, %ymm0"),
        ("vmaxpd_mem", "vmaxpd 0x500020, %ymm1, %ymm0"),
        ("vminss_reg", "vminss %xmm2, %xmm1, %xmm0"),
        ("vminss_mem", "vminss 0x500020, %xmm1, %xmm0"),
        ("vmaxss_reg", "vmaxss %xmm2, %xmm1, %xmm0"),
        ("vmaxss_mem", "vmaxss 0x500020, %xmm1, %xmm0"),
        ("vminsd_reg", "vminsd %xmm2, %xmm1, %xmm0"),
        ("vminsd_mem", "vminsd 0x500020, %xmm1, %xmm0"),
        ("vmaxsd_reg", "vmaxsd %xmm2, %xmm1, %xmm0"),
        ("vmaxsd_mem", "vmaxsd 0x500020, %xmm1, %xmm0"),
        ("vsqrtps_reg", "vsqrtps %ymm2, %ymm0"),
        ("vsqrtps_mem", "vsqrtps 0x500020, %ymm0"),
        ("vsqrtpd_reg", "vsqrtpd %ymm2, %ymm0"),
        ("vsqrtpd_mem", "vsqrtpd 0x500020, %ymm0"),
        ("vsqrtss_reg", "vsqrtss %xmm2, %xmm1, %xmm0"),
        ("vsqrtss_mem", "vsqrtss 0x500020, %xmm1, %xmm0"),
        ("vsqrtsd_reg", "vsqrtsd %xmm2, %xmm1, %xmm0"),
        ("vsqrtsd_mem", "vsqrtsd 0x500020, %xmm1, %xmm0"),
    ];
    let mut count = 0usize;
    for (pattern, (left, right)) in PATTERNS.into_iter().enumerate() {
        for (name, instruction) in forms {
            if differential_case(&format!("{name}_{pattern}"), instruction, left, right)? {
                count += 1;
            }
        }
    }
    if count == 0 {
        eprintln!("SKIP: binutils unavailable");
    } else {
        eprintln!("AVX min/max/sqrt differential: {count} native cases passed");
    }
    if count != 0 && count != 48 {
        return Err(format!("expected 48 native cases, ran {count}").into());
    }
    Ok(())
}
