#![forbid(unsafe_code)]

//! Hardware differential oracle for the SHL/SHR/SAR and ROL/ROR semantic families.
//!
//! Validates mod-32 and mod-64 count masking and flag modeling against the host CPU:
//! - r32 shifts (SHL, SHR, SAR) by imm8 and CL across boundary values and counts,
//!   verifying value and flags (CF, PF, ZF, SF, and OF for count==1).
//! - r32 rotates (ROL, ROR) by imm8 and CL across boundary values and counts,
//!   verifying value and flags (CF, and OF for count==1).
//! - r64 rotates with CL counts checking CF and OF (count==1).
//! - CL test cases seed garbage in upper RCX bits to prove only CL is consulted.

use angryier_arch::{OperandKind, OperandVisibility};
use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::LayeredMemory;
use angryier_memory::{ByteValue, MemoryRegion, PersistentMemory};
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
const STACK_TOP: u64 = 0x600000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(3);

const RSP: u32 = register_id::GPR_BASE + 4;

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;

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

// ---------------------------------------------------------------------------
// Native side: assemble, link, run
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-shift-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn assemble(source: &Path, object: &Path) -> Option<()> {
    let output = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(object)
        .arg(source)
        .output()
        .ok()?;
    output.status.success().then_some(())
}

fn link(binary: &Path, objects: &[&PathBuf]) -> Option<()> {
    let mut command = Command::new("ld");
    command
        .arg("-Ttext=0x400000")
        .arg("-Tdata=0x500000")
        .arg("-o")
        .arg(binary);
    for object in objects {
        command.arg(object);
    }
    command.output().ok()?.status.success().then_some(())
}

/// Extracts the `.text` section as raw bytes at its link address.
fn extract_text(dir: &Path, binary: &Path) -> Option<Vec<u8>> {
    let section = dir.join("case.text");
    let output = Command::new("objcopy")
        .arg("--dump-section")
        .arg(format!(".text={}", section.display()))
        .arg(binary)
        .arg("/dev/null")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    std::fs::read(section).ok()
}

fn native_stdout(binary: &Path) -> Option<Vec<u8>> {
    let output = Command::new(binary).output().ok()?;
    Some(output.stdout)
}

/// Wraps the shift/rotate body: after it runs, `[rax, rflags]` land in the scratch
/// area and are written to stdout.
fn harness_source(body: &str) -> String {
    format!(
        "        .global _start\n        .text\n_start:\n{body}\n    mov %rax, 0x{SCRATCH:x}\n    pushfq\n    pop %rbx\n    mov %rbx, 0x{SCRATCH8:x}\n    mov $1, %rax\n    mov $1, %rdi\n    mov $0x{SCRATCH:x}, %rsi\n    mov $16, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\nscratch:\n        .space 0x400\n",
        SCRATCH8 = SCRATCH + 8
    )
}

// ---------------------------------------------------------------------------
// Engine side: XED decode -> corpus form -> semantic pipeline
// ---------------------------------------------------------------------------

enum Shape {
    Reg64,
    Reg32,
    Imm,
    Mem64,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 32 => Some(Shape::Reg32),
        OperandKind::Immediate(_) => Some(Shape::Imm),
        OperandKind::Memory(_) if operand.width_bits == 64 => Some(Shape::Mem64),
        _ => None,
    }
}

/// The implicit 8-bit `CL` of variable-count shifts and rotates.
fn is_cl(operand: &angryier_arch::Operand) -> bool {
    matches!(
        &operand.kind,
        OperandKind::Register(view)
            if view.width_bits == 8
                && view.parent.0 == register_id::GPR_BASE + 1
                && view.bit_offset == 0
    )
}

fn map_form(decoded: &angryier_arch::DecodedInstruction) -> Option<u32> {
    use xed_sys as xed;

    let explicit: Vec<Shape> = decoded
        .operands
        .iter()
        .filter(|operand| {
            operand.visibility != OperandVisibility::Suppressed
                && !(operand.visibility == OperandVisibility::Implicit && is_cl(operand))
        })
        .map(shape_of)
        .collect::<Option<_>>()?;
    let shapes = explicit.as_slice();
    let has_cl = decoded
        .operands
        .iter()
        .any(|operand| operand.visibility == OperandVisibility::Implicit && is_cl(operand));

    match decoded.form_id {
        xed::XED_ICLASS_SHL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SHL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHL_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHL_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHL_R32_CL),
            [Shape::Reg32] => Some(forms::SHL_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_SHR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SHR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHR_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHR_R32_CL),
            [Shape::Reg32] => Some(forms::SHR_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_SAR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SAR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SAR_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::SAR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SAR_R32_CL),
            [Shape::Reg32] => Some(forms::SAR_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_ROL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ROL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROL_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROL_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::ROL_R32_CL),
            _ => None,
        },
        xed::XED_ICLASS_ROR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ROR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROR_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::ROR_R32_CL),
            _ => None,
        },
        xed::XED_ICLASS_RCL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::RCL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCL_R64_CL),
            _ => None,
        },
        xed::XED_ICLASS_RCR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::RCR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCR_R64_CL),
            _ => None,
        },
        xed::XED_ICLASS_STC => Some(forms::STC),
        // Plumbing forms the harness itself needs.
        xed::XED_ICLASS_MOV => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::MOV_R64_R64),
            [Shape::Reg32, Shape::Imm] => Some(forms::MOV_R32_IMM32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            _ => None,
        },
        xed::XED_ICLASS_PUSHF | xed::XED_ICLASS_PUSHFQ => Some(forms::PUSHF),
        xed::XED_ICLASS_POP => match shapes {
            [Shape::Reg64] => Some(forms::POP_R64),
            _ => None,
        },
        xed::XED_ICLASS_XOR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            _ => None,
        },
        _ => None,
    }
}

struct EngineState {
    registers: PersistentRegisters,
    memory: PersistentMemory,
}

impl EngineState {
    fn new(code: &[u8]) -> Result<Self, BoxError> {
        let reg_file = Intel64RegisterFile::canonical();
        let registers = PersistentRegisters::from_widths(
            reg_file
                .architectural_registers
                .iter()
                .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
        )
        .map_err(|e| format!("register file: {e:?}"))?;
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
        let bytes: Vec<ByteValue> = code.iter().map(|byte| ByteValue::Concrete(*byte)).collect();
        let memory = memory
            .write(CODE_BASE, &bytes)
            .map_err(|e| format!("code load: {e:?}"))?;
        Ok(Self { registers, memory })
    }
}

fn execution_state(engine: &EngineState) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    Ok(ExecutionState {
        id: StateId(1),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers: engine.registers.clone(),
        memory: engine.memory.clone(),
        constraints: PersistentConstraintLineage::new(),
        ownership: angryier_state::StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    })
}

fn run_engine(code: &[u8], registry: &Intel64CorpusRegistry) -> Result<(u64, u64), BoxError> {
    let decoder = XedDecoder::new();
    let mut engine = EngineState::new(code)?;
    let mut pc = CODE_BASE;
    for _ in 0..512 {
        let offset = usize::try_from(pc - CODE_BASE).map_err(|_| "pc underflow")?;
        let bytes = code.get(offset..).ok_or_else(|| format!("pc {pc:#x} outside code"))?;
        let decoded = decoder
            .decode(pc, bytes)
            .map_err(|e| format!("decode at {pc:#x}: {e:?}"))?;
        if decoded.form_id == xed_sys::XED_ICLASS_SYSCALL {
            break;
        }

        let form = map_form(&decoded)
            .ok_or_else(|| format!("unmapped iclass {} at {:#x}", decoded.form_id, decoded.address))?;
        let provider = registry
            .provider_for_form(form)
            .ok_or_else(|| format!("no provider for form {form:#x}"))?;
        let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
        provider
            .emit(&context(), &decoded, &mut builder)
            .map_err(|e| format!("emit form {form:#x}: {e:?}"))?;
        let sealed = builder
            .seal(
                angryier_types::ContentIdentitySchemaVersion(1),
                angryier_types::SemanticFingerprintSchemaVersion(1),
            )
            .map_err(|e| format!("seal form {form:#x}: {e:?}"))?;
        let key = BlockValidityKey {
            image: ImageId(1),
            block: BlockId(2),
            address: decoded.address,
            semantic_version: SEMANTIC_VERSION,
            target_profile: TARGET_PROFILE,
            code_versions: engine
                .memory
                .code_version_guards_for_range(decoded.address, usize::from(decoded.length))
                .map_err(|e| format!("code guards: {e:?}"))?,
        };
        let ir_block = BasicSemanticLowerer
            .lower_with_decode(&sealed, &key, &decoded)
            .map_err(|e| format!("lower form {form:#x}: {e:?}"))?;
        let state = execution_state(&engine)?;
        state
            .registers
            .write(register_id::RIP.0, &decoded.address.to_le_bytes())
            .map_err(|e| format!("rip: {e:?}"))?;
        let (executed, outcome) = ConcreteInterpreter::new()
            .execute_block(&state, &ir_block, ExecutionMode::Concrete)
            .map_err(|e| format!("execute form {form:#x} at {:#x}: {e:?}", decoded.address))?;
        let next_pc = match outcome {
            ExecutionOutcome::Continue { next_pc, .. } => next_pc,
            other => return Err(format!("unexpected outcome {other:?}").into()),
        };
        let executed_registers = executed
            .registers
            .write(register_id::RIP.0, &next_pc.to_le_bytes())
            .map_err(|e| format!("rip store: {e:?}"))?;
        engine.registers = executed_registers;
        engine.memory = executed.memory;
        pc += u64::from(decoded.length);
    }
    let read_cell = |address: u64| -> Result<u64, BoxError> {
        let bytes = engine
            .memory
            .read(address, 8)
            .map_err(|e| format!("dump read: {e:?}"))?
            .into_iter()
            .map(|byte| match byte {
                ByteValue::Concrete(value) => value,
                ByteValue::Symbolic { .. } => 0,
            })
            .collect::<Vec<u8>>();
        let mut cell = [0u8; 8];
        cell.copy_from_slice(&bytes);
        Ok(u64::from_le_bytes(cell))
    };
    Ok((read_cell(SCRATCH)?, read_cell(SCRATCH + 8)?))
}

// ---------------------------------------------------------------------------
// Differential driver
// ---------------------------------------------------------------------------

fn differential_case(name: &str, body: &str, flag_mask: u64) -> Result<bool, BoxError> {
    let Some(dir) = temp_dir(name) else {
        return Ok(false);
    };
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    std::fs::write(&source, harness_source(body))?;
    if assemble(&source, &object).is_none() || link(&binary, &[&object]).is_none() {
        return Ok(false);
    }
    let code = extract_text(&dir, &binary).ok_or("objcopy failed")?;
    let expected = native_stdout(&binary).ok_or("native run failed")?;
    if expected.len() < 16 {
        return Err(format!("native harness produced {} bytes", expected.len()).into());
    }

    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let (engine_rax, engine_flags) =
        run_engine(&code, &registry).map_err(|e| format!("case `{name}`: {e}\nbody:\n{body}"))?;

    let native_rax = u64::from_le_bytes(expected[..8].try_into()?);
    let native_flags = u64::from_le_bytes(expected[8..16].try_into()?);
    if engine_rax != native_rax {
        return Err(format!(
            "differential mismatch on `{name}`: rax engine={engine_rax:#x} native={native_rax:#x}\nbody:\n{body}"
        )
        .into());
    }
    if engine_flags & flag_mask != native_flags & flag_mask {
        return Err(format!(
            "differential flag mismatch on `{name}`: engine={engine_flags:#x} native={native_flags:#x} mask={flag_mask:#x}\nbody:\n{body}"
        )
        .into());
    }
    Ok(true)
}

fn flag_mask_for_shift(masked_count: u64) -> u64 {
    match masked_count {
        0 => CF | PF | ZF | SF | OF,
        1 => CF | PF | ZF | SF | OF,
        _ => CF | PF | ZF | SF,
    }
}

fn flag_mask_for_rotate(masked_count: u64) -> u64 {
    match masked_count {
        0 => CF | OF,
        1 => CF | OF,
        _ => CF,
    }
}

fn flag_mask_for_rcl_rcr(masked_count: u64) -> u64 {
    match masked_count {
        0 | 1 => CF | OF,
        _ => CF,
    }
}

// ---------------------------------------------------------------------------
// Test vectors
// ---------------------------------------------------------------------------

const VALUES32: [u32; 3] = [0, 0xdead_beef, 0xffff_ffff];
const COUNTS_R32: [u64; 9] = [0, 1, 31, 32, 33, 63, 64, 127, 255];

const VALUES64: [u64; 4] = [0, 0xdead_beef_cafe_f00d, 0x8000_0000_0000_0001, 0xffff_ffff_ffff_ffff];
const COUNTS64_CL: [u64; 6] = [0, 1, 63, 64, 65, 255];
const COUNTS_RCL_IMM: [u64; 5] = [0, 1, 2, 63, 64];
const COUNTS_RCL_CL: [u64; 6] = [0, 1, 2, 63, 64, 255];

#[test]
fn shift_and_rotate_semantics_match_hardware() -> Result<(), BoxError> {
    let mut executed = 0usize;
    let mut skipped = false;
    let mut case = |name: String, body: String, mask: u64| -> Result<(), BoxError> {
        let ran = differential_case(&name, &body, mask)?;
        skipped |= !ran;
        executed += usize::from(ran);
        Ok(())
    };

    // 1. r32 shifts: values x counts x {shl, shr, sar} x {imm8, CL}
    for mnemonic in ["shl", "shr", "sar"] {
        for &count in &COUNTS_R32 {
            let masked = count & 0x1F;
            let mask = flag_mask_for_shift(masked);
            for &value in &VALUES32 {
                // Immediate form
                let body_imm = format!("    mov ${value:#x}, %eax\n    {mnemonic}l ${count}, %eax\n");
                case(format!("{mnemonic}l_imm{count}_{value:#x}"), body_imm, mask)?;

                // CL form: seed garbage in upper RCX bits (e.g. 0xaabbccddffffffXX)
                let cl_seed = 0xaabb_ccdd_ffff_ff00u64 | (count & 0xff);
                let body_cl =
                    format!("    movabs ${cl_seed:#x}, %rcx\n    mov ${value:#x}, %eax\n    {mnemonic}l %cl, %eax\n");
                case(format!("{mnemonic}l_cl{count}_{value:#x}"), body_cl, mask)?;
            }
        }
    }

    // 2. r32 rotates: same value/count sweep x {rol, ror} x {imm8, CL}
    for mnemonic in ["rol", "ror"] {
        for &count in &COUNTS_R32 {
            let masked = count & 0x1F;
            let mask = flag_mask_for_rotate(masked);
            for &value in &VALUES32 {
                // Immediate form
                let body_imm = format!("    mov ${value:#x}, %eax\n    {mnemonic}l ${count}, %eax\n");
                case(format!("{mnemonic}l_imm{count}_{value:#x}"), body_imm, mask)?;

                // CL form: seed garbage in upper RCX bits
                let cl_seed = 0xaabb_ccdd_ffff_ff00u64 | (count & 0xff);
                let body_cl =
                    format!("    movabs ${cl_seed:#x}, %rcx\n    mov ${value:#x}, %eax\n    {mnemonic}l %cl, %eax\n");
                case(format!("{mnemonic}l_cl{count}_{value:#x}"), body_cl, mask)?;
            }
        }
    }

    // 3. r64 rotates with CL counts [0, 1, 63, 64, 65, 255] checking CF and OF (count==1)
    for mnemonic in ["rol", "ror"] {
        for &cl in &COUNTS64_CL {
            let masked = cl & 0x3F;
            let mask = flag_mask_for_rotate(masked);
            for &value in &VALUES64 {
                let cl_seed = 0xaabb_ccdd_ffff_ff00u64 | (cl & 0xff);
                let body_cl = format!(
                    "    movabs ${cl_seed:#x}, %rcx\n    movabs ${value:#x}, %rax\n    {mnemonic}q %cl, %rax\n"
                );
                case(format!("{mnemonic}q_cl{cl}_{value:#x}"), body_cl, mask)?;
            }
        }
    }

    // 4. r64 shifts with CL counts [0, 1, 63, 64, 65, 255] checking CF, PF, ZF, SF, and OF
    for mnemonic in ["shl", "shr", "sar"] {
        for &cl in &COUNTS64_CL {
            let masked = cl & 0x3F;
            let mask = flag_mask_for_shift(masked);
            for &value in &VALUES64 {
                let cl_seed = 0xaabb_ccdd_ffff_ff00u64 | (cl & 0xff);
                let body_cl = format!(
                    "    movabs ${cl_seed:#x}, %rcx\n    movabs ${value:#x}, %rax\n    {mnemonic}q %cl, %rax\n"
                );
                case(format!("{mnemonic}q_cl{cl}_{value:#x}"), body_cl, mask)?;
            }
        }
    }

    // 5. r64 RCL/RCR imm8 and CL sweeps with incoming CF varied (alternating STC)
    let mut stc_toggle = false;
    for mnemonic in ["rcl", "rcr"] {
        // imm8 counts {0, 1, 2, 63, 64}
        for &count in &COUNTS_RCL_IMM {
            let masked = count & 0x3F;
            let mask = flag_mask_for_rcl_rcr(masked);
            for &value in &VALUES64 {
                let stc = if stc_toggle { "    stc\n" } else { "" };
                stc_toggle = !stc_toggle;
                let body = format!("{stc}    movabs ${value:#x}, %rax\n    {mnemonic}q ${count}, %rax\n");
                case(format!("{mnemonic}q_imm{count}_{value:#x}"), body, mask)?;
            }
        }
        // CL counts {0, 1, 2, 63, 64, 255}
        for &cl in &COUNTS_RCL_CL {
            let masked = cl & 0x3F;
            let mask = flag_mask_for_rcl_rcr(masked);
            for &value in &VALUES64 {
                let stc = if stc_toggle { "    stc\n" } else { "" };
                stc_toggle = !stc_toggle;
                let cl_seed = 0xaabb_ccdd_ffff_ff00u64 | (cl & 0xff);
                let body = format!(
                    "{stc}    movabs ${cl_seed:#x}, %rcx\n    movabs ${value:#x}, %rax\n    {mnemonic}q %cl, %rax\n"
                );
                case(format!("{mnemonic}q_cl{cl}_{value:#x}"), body, mask)?;
            }
        }
    }

    // 6. Dedicated zero-count flag preservation: stc then count 0 (imm8 $0 and CL=0)
    for mnemonic in ["shl", "shr", "sar", "rol", "ror", "rcl", "rcr"] {
        let mask = CF | PF | ZF | SF | OF;
        let value = 0xdead_beef_cafe_f00du64;

        // imm8 $0
        let body_imm = format!("    stc\n    movabs ${value:#x}, %rax\n    {mnemonic}q $0, %rax\n");
        case(format!("{mnemonic}q_imm0_preserve_cf"), body_imm, mask)?;

        // CL=0 with garbage upper bits
        let cl_seed = 0xaabb_ccdd_ffff_ff00u64;
        let body_cl = format!(
            "    movabs ${cl_seed:#x}, %rcx\n    stc\n    movabs ${value:#x}, %rax\n    {mnemonic}q %cl, %rax\n"
        );
        case(format!("{mnemonic}q_cl0_preserve_cf"), body_cl, mask)?;
    }

    if skipped && executed == 0 {
        eprintln!("skipping shift differential: binutils unavailable");
        return Ok(());
    }
    eprintln!("shift differential oracle: {executed} cases matched hardware byte-for-byte");
    if executed < 450 {
        return Err(format!("expected >= 450 shift differential cases, ran {executed}").into());
    }
    Ok(())
}
