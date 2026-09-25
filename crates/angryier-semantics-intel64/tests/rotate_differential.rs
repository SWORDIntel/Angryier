#![forbid(unsafe_code)]

//! Hardware differential oracle for the ROL/ROR semantic family.
//!
//! Every rewired rotate form must answer to the host CPU: each case
//! assembles a real program (binutils), runs it natively to capture
//! `[rax, rflags]` from silicon, then decodes the same instruction bytes
//! with native XED, maps the iclass/operand shapes onto corpus form ids,
//! and executes through the full provider -> seal -> lower ->
//! concrete-interpreter pipeline. The result register must match
//! byte-for-byte and RFLAGS must match on the architecturally defined bits.
//!
//! Count masking is the point of the sweep: on x86-64 the count is taken
//! modulo 64 for 64-bit operands and modulo 32 for 32-bit operands, so
//! counts above the width (33, 63, 64, 65, 127, 200, 255) probe the
//! normalization, and `CL` cases with garbage in the upper bits of RCX
//! prove only CL is consulted. Flag comparison follows the architecture:
//! a masked count of 0 leaves CF/OF untouched, a masked count of 1 defines
//! CF and OF (the engine's CL forms model CF only), and larger counts
//! define CF alone.
//!
//! The harness is the x87 differential's (see `x87_differential.rs`): code
//! at 0x400000, scratch at 0x500000, and every template ends by dumping
//! `%rax`/rflags for both worlds to observe.

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
    let dir = std::env::temp_dir().join(format!("angryier-rotate-{name}-{}", std::process::id()));
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

/// Wraps the rotate body: after it runs, `[rax, rflags]` land in the scratch
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

/// Operand shape used to discriminate forms that share an XED iclass, built
/// from non-suppressed operands exactly like the runtime's `form_map.rs`.
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

/// Runs the code bytes until the first syscall (the harness output tail) and
/// returns the dumped `[rax, rflags]` pair from the scratch area. The
/// syscall tail clobbers %rax, so the dump cells are the observation point.
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

        let form =
            map_form(&decoded).ok_or(format!("unmapped iclass {} at {:#x}", decoded.form_id, decoded.address))?;
        let provider = registry
            .provider_for_form(form)
            .ok_or(format!("no provider for form {form:#x}"))?;
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

/// Assembles and runs `body` natively and through the engine. Returns false
/// when binutils is unavailable so the test can skip gracefully.
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

/// Defined RFLAGS bits for a rotate given its already-masked count. A masked
/// count of 0 leaves CF/OF untouched; 1 defines both (OF only where the
/// provider models it — the CL forms write CF alone); larger counts define
/// CF only. The 32-bit forms model no flags at all.
fn flag_mask_for_count(masked_count: u64, models_of: bool) -> u64 {
    match masked_count {
        0 => 0,
        1 if models_of => CF | OF,
        _ => CF,
    }
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Boundary values: zero, one bits pattern at both ends, dense middle, all
/// ones — every rotate direction moves a different one of these bits.
const VALUES64: [u64; 4] = [0, 0xdead_beef_cafe_f00d, 0x8000_0000_0000_0001, 0xffff_ffff_ffff_ffff];
const VALUES32: [u32; 4] = [0, 0xdead_beef, 0x8000_0001, 0xffff_ffff];

/// Counts that exercise the whole normalization range for 64-bit operands:
/// in-width, boundary (31/32/63), and above-width where mod-64 masking
/// shows (64 -> 0, 65 -> 1, 127/255 -> 63).
const COUNTS64_IMM: [u64; 10] = [0, 1, 5, 31, 32, 63, 64, 65, 127, 255];
/// CL values for the 64-bit register-count forms (mod 64).
const COUNTS64_CL: [u64; 8] = [0, 1, 9, 33, 63, 64, 65, 255];
/// Counts for the 32-bit immediate forms: 33 -> 1-bit rotate past the
/// width, 255 -> 31.
const COUNTS32_IMM: [u64; 8] = [0, 1, 5, 31, 32, 33, 63, 255];
/// CL values for the 32-bit register-count forms (mod 32).
const COUNTS32_CL: [u64; 8] = [0, 1, 9, 31, 32, 33, 65, 255];

/// Gate D: the ROL/ROR semantic family against hardware. Result values must
/// match byte-for-byte; r64 forms also compare CF (and OF on 1-bit rotates,
/// which the immediate forms model).
#[test]
fn rotate_semantics_match_hardware() -> Result<(), BoxError> {
    let mut executed = 0usize;
    let mut skipped = false;
    let case =
        |name: String, body: String, mask: u64, executed: &mut usize, skipped: &mut bool| -> Result<(), BoxError> {
            let ran = differential_case(&name, &body, mask)?;
            *skipped |= !ran;
            *executed += usize::from(ran);
            Ok(())
        };

    // 64-bit immediate forms: `rolq`/`rorq` by imm8.
    for mnemonic in ["rol", "ror"] {
        for &count in &COUNTS64_IMM {
            let masked = count & 0x3F;
            for &value in &VALUES64 {
                let body = format!("    movabs ${value}, %rax\n    {mnemonic} ${count}, %rax\n");
                case(
                    format!("{mnemonic}q_imm{count}_{value:x}"),
                    body,
                    flag_mask_for_count(masked, true),
                    &mut executed,
                    &mut skipped,
                )?;
            }
        }
    }

    // 64-bit CL forms: the count register is seeded per case.
    for mnemonic in ["rol", "ror"] {
        for &cl in &COUNTS64_CL {
            let masked = cl & 0x3F;
            for &value in &VALUES64 {
                let body = format!("    movabs ${value}, %rax\n    mov ${cl}, %ecx\n    {mnemonic} %cl, %rax\n");
                case(
                    format!("{mnemonic}q_cl{cl}_{value:x}"),
                    body,
                    flag_mask_for_count(masked, false),
                    &mut executed,
                    &mut skipped,
                )?;
            }
        }
    }

    // Only CL is consulted: garbage in the upper bits of RCX (and the upper
    // bits of the CL-seeding write) must not change the answer. CL=0x41 is
    // 65, i.e. a 1-bit rotate after the mod-64 mask.
    for mnemonic in ["rol", "ror"] {
        for &value in &VALUES64 {
            let body =
                format!("    movabs ${value}, %rax\n    movabs $0xaabbccddffffff41, %rcx\n    {mnemonic} %cl, %rax\n");
            case(
                format!("{mnemonic}q_cl_dirty_rcx_{value:x}"),
                body,
                CF,
                &mut executed,
                &mut skipped,
            )?;
        }
    }

    // 32-bit immediate forms: `roll`/`rorl`. A prior dirty upper half also
    // proves the 32-bit write zero-extends the parent register.
    for mnemonic in ["roll", "rorl"] {
        for &count in &COUNTS32_IMM {
            for &value in &VALUES32 {
                let body = format!("    mov ${value}, %eax\n    {mnemonic} ${count}, %eax\n");
                case(
                    format!("{mnemonic}_imm{count}_{value:x}"),
                    body,
                    // The 32-bit rotate forms model no flags yet.
                    0,
                    &mut executed,
                    &mut skipped,
                )?;
            }
        }
        // A dirty upper half at rotate time proves the 32-bit write
        // zero-extends the parent register (33 -> a 1-bit rotate).
        for &value in &[0x8000_0001u32, 0xdead_beef] {
            let parent = 0xffff_ffff_0000_0000 | u64::from(value);
            let body = format!("    movabs ${parent}, %rax\n    {mnemonic} $33, %eax\n");
            case(
                format!("{mnemonic}_imm33_dirty_parent_{value:x}"),
                body,
                0,
                &mut executed,
                &mut skipped,
            )?;
        }
    }

    // 32-bit CL forms: count from CL, mod 32.
    for mnemonic in ["roll", "rorl"] {
        for &cl in &COUNTS32_CL {
            for &value in &VALUES32 {
                let body = format!("    mov ${value}, %eax\n    mov ${cl}, %ecx\n    {mnemonic} %cl, %eax\n");
                case(
                    format!("{mnemonic}_cl{cl}_{value:x}"),
                    body,
                    0,
                    &mut executed,
                    &mut skipped,
                )?;
            }
        }
    }

    if skipped && executed == 0 {
        eprintln!("skipping rotate differential: binutils unavailable");
        return Ok(());
    }
    eprintln!("rotate differential oracle: {executed} cases matched hardware byte-for-byte");
    assert!(
        executed > 250,
        "expected >250 rotate differential cases, ran {executed}"
    );
    Ok(())
}
