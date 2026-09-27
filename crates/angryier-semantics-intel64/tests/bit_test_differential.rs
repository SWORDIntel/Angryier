#![forbid(unsafe_code)]

//! Hardware differential oracle for the BT/BTS/BTR/BTC bit-test family
//! (register and immediate forms, 32/64-bit operands) plus the SSE
//! MOVHLPS/MOVLHPS lane moves.
//!
//! Same harness as `rotate_differential.rs` (binutils assemble/link/run,
//! native capture of `[rax, rflags]`, XED decode -> corpus form -> provider
//! -> seal -> lower -> concrete interpreter) with the bit-test forms
//! exercising the mod-width index normalization (indices above the operand
//! width probe mod-32/mod-64 masking) and the lane moves proving the
//! half-preserving register writes.
//!
//! Bit tests define CF only; the lane moves define no flags.

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
    let dir = std::env::temp_dir().join(format!("angryier-bittest-{name}-{}", std::process::id()));
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

/// Wraps the test body: after it runs, `[rax, rflags]` land in the scratch
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
    Mem128,
    Xmm,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 32 => Some(Shape::Reg32),
        OperandKind::Register(view) if view.width_bits == 128 => Some(Shape::Xmm),
        OperandKind::Immediate(_) => Some(Shape::Imm),
        OperandKind::Memory(_) if operand.width_bits == 64 => Some(Shape::Mem64),
        OperandKind::Memory(_) if operand.width_bits == 128 => Some(Shape::Mem128),
        _ => None,
    }
}

fn map_form(decoded: &angryier_arch::DecodedInstruction) -> Option<u32> {
    use xed_sys as xed;

    let explicit: Vec<Shape> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility != OperandVisibility::Suppressed)
        .map(shape_of)
        .collect::<Option<_>>()?;
    let shapes = explicit.as_slice();

    match decoded.form_id {
        xed::XED_ICLASS_BT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BT_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BT_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BT_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BT_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_BTS => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTS_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BTS_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BTS_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BTS_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_BTR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTR_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BTR_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BTR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BTR_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_BTC => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTC_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BTC_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BTC_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BTC_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_MOVHLPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVHLPS_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_MOVLHPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVLHPS_XMM_XMM),
            _ => None,
        },
        // Plumbing forms the harness itself needs.
        xed::XED_ICLASS_MOV => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::MOV_R64_R64),
            [Shape::Reg32, Shape::Imm] => Some(forms::MOV_R32_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::MOV_R32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            _ => None,
        },
        xed::XED_ICLASS_MOVQ => match shapes {
            [Shape::Xmm, Shape::Reg64] => Some(forms::MOVQ_XMM_R64),
            [Shape::Reg64, Shape::Xmm] => Some(forms::MOVQ_R64_XMM),
            _ => None,
        },
        xed::XED_ICLASS_MOVDQA => match shapes {
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVDQA_XMM_MEM),
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

/// Runs the code bytes until the first syscall and returns the dumped
/// `[rax, rflags]` pair from the scratch area.
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

        if std::env::var("ANGRYIER_DBG_MEM").is_ok() {
            let shown: Vec<String> = bytes.iter().take(8).map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "DBG exec {:#x} iclass={} len={} bytes=[{}] ops={:?}",
                decoded.address,
                decoded.form_id,
                decoded.length,
                shown.join(" "),
                decoded
                    .operands
                    .iter()
                    .map(|o| format!("{:?}", o.kind))
                    .collect::<Vec<_>>()
            );
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

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

const VALUES64: [u64; 3] = [0, 0xdead_beef_cafe_f00d, 0xffff_ffff_ffff_ffff];
const VALUES32: [u32; 3] = [0, 0xdead_beef, 0xffff_ffff];
/// Indices probing the mod-64 normalization: in-width, boundary, and
/// above-width (64 -> 0, 65 -> 1, 127/255 -> 63).
const INDICES64: [u64; 8] = [0, 1, 31, 63, 64, 65, 127, 255];
/// Indices probing the mod-32 normalization (32 -> 0, 33 -> 1, 255 -> 31).
const INDICES32: [u64; 7] = [0, 1, 31, 32, 33, 127, 255];

#[test]
fn bit_test_r64_r64_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for value in VALUES64 {
        for index in INDICES64 {
            for (_op, mnemonic) in [("bt", "bt"), ("bts", "bts"), ("btr", "btr"), ("btc", "btc")] {
                ran |= differential_case(
                    &format!("{mnemonic}_r64_r64_{value:x}_{index}"),
                    &format!("    mov ${value:#x}, %rax\n    mov ${index:#x}, %rcx\n    {mnemonic} %rcx, %rax\n"),
                    CF,
                )?;
            }
        }
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn bit_test_r64_imm8_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for value in VALUES64 {
        for index in INDICES64 {
            for (_op, mnemonic) in [("bt", "bt"), ("bts", "bts"), ("btr", "btr"), ("btc", "btc")] {
                let body = if index > 255 {
                    // imm8 encodings only carry 0..255; keep the sweep honest.
                    continue;
                } else {
                    format!("    mov ${value:#x}, %rax\n    {mnemonic} ${index}, %rax\n")
                };
                ran |= differential_case(&format!("{mnemonic}_r64_imm8_{value:x}_{index}"), &body, CF)?;
            }
        }
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn bit_test_r32_r32_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for value in VALUES32 {
        for index in INDICES32 {
            for (_op, mnemonic) in [("bt", "bt"), ("bts", "bts"), ("btr", "btr"), ("btc", "btc")] {
                ran |= differential_case(
                    &format!("{mnemonic}_r32_r32_{value:x}_{index}"),
                    &format!(
                        "    mov ${value:#x}, %eax\n    mov ${index:#x}, %ecx\n    {mnemonic} %ecx, %eax\n    mov %eax, %eax\n"
                    ),
                    CF,
                )?;
            }
        }
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn bit_test_r32_imm8_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for value in VALUES32 {
        for index in INDICES32 {
            for (_op, mnemonic) in [("bt", "bt"), ("bts", "bts"), ("btr", "btr"), ("btc", "btc")] {
                let body = if index > 255 {
                    continue;
                } else {
                    format!("    mov ${value:#x}, %eax\n    {mnemonic} ${index}, %eax\n    mov %eax, %eax\n")
                };
                ran |= differential_case(&format!("{mnemonic}_r32_imm8_{value:x}_{index}"), &body, CF)?;
            }
        }
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

/// MOVHLPS: dest[63:0] = src[127:64]; dest[127:64] unchanged. Builds
/// `xmm1 = [lo, hi]` from scratch memory and seeds a distinct low half in
/// xmm0, then observes dest's low half via `movq %xmm0, %rax`.
#[test]
fn movhlps_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for (lo, hi, seed) in [
        (
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222u64,
            0x3333_3333_3333_3333u64,
        ),
        (0, 0xffff_ffff_ffff_ffff, 0),
        (0x8000_0000_0000_0000, 0x0000_0000_0000_0001, 0xdead_beef_cafe_f00d),
    ] {
        let body = format!(
            "    mov ${lo:#x}, %rax\n    mov %rax, 0x{SCRATCH:x}\n    mov ${hi:#x}, %rax\n    mov %rax, 0x{SCRATCH8:x}\n    movdqa 0x{SCRATCH:x}, %xmm1\n    mov ${seed:#x}, %rax\n    movq %rax, %xmm0\n    movhlps %xmm1, %xmm0\n    movq %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("movhlps_{lo:x}_{hi:x}_{seed:x}"), &body, 0)?;
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

/// MOVLHPS: dest[127:64] = src[63:0]; dest[63:0] unchanged. After the move,
/// `movhlps %xmm0, %xmm0` folds the high half into the low half so the
/// observed rax is the lane MOVLHPS wrote.
#[test]
fn movlhps_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for (lo, hi, seed) in [
        (
            0x1111_1111_1111_1111u64,
            0x2222_2222_2222_2222u64,
            0x3333_3333_3333_3333u64,
        ),
        (0, 0xffff_ffff_ffff_ffff, 0xaaaa_aaaa_aaaa_aaaa),
        (0x8000_0000_0000_0000, 0x0000_0000_0000_0001, 0xdead_beef_cafe_f00d),
    ] {
        let body = format!(
            "    mov ${lo:#x}, %rax\n    mov %rax, 0x{SCRATCH:x}\n    mov ${hi:#x}, %rax\n    mov %rax, 0x{SCRATCH8:x}\n    movdqa 0x{SCRATCH:x}, %xmm1\n    mov ${seed:#x}, %rax\n    movq %rax, %xmm0\n    movlhps %xmm1, %xmm0\n    movhlps %xmm0, %xmm0\n    movq %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("movlhps_{lo:x}_{hi:x}_{seed:x}"), &body, 0)?;
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}
