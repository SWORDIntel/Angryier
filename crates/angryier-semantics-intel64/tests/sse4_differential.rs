#![forbid(unsafe_code)]

//! Hardware differential oracle for the SSE4.1/SSE4.2 completion batch:
//! PEXTRD/PEXTRQ, PINSRD/PINSRQ, PMAXSD/PMAXUD/PMINSD/PMINUD,
//! ROUNDPS/ROUNDPD modes, BLENDVPS/BLENDVPD/PBLENDVB, INSERTPS/EXTRACTPS,
//! MOVNTDQA, PMOVSX*/PMOVZX* sign/zero extensions, and PTEST.

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
const ZF: u64 = 1 << 6;

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
    let dir = std::env::temp_dir().join(format!("angryier-sse4test-{name}-{}", std::process::id()));
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

fn harness_source(body: &str) -> String {
    format!(
        "        .global _start\n        .text\n_start:\n{body}\n    mov %rax, 0x{SCRATCH:x}\n    pushfq\n    pop %rbx\n    mov %rbx, 0x{SCRATCH8:x}\n    mov $1, %rax\n    mov $1, %rdi\n    mov $0x{SCRATCH:x}, %rsi\n    mov $16, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\nscratch:\n        .space 0x400\n",
        SCRATCH8 = SCRATCH + 8
    )
}

// ---------------------------------------------------------------------------
// Engine side: XED decode -> corpus form -> semantic pipeline
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
        xed::XED_ICLASS_PEXTRD => match shapes {
            [Shape::Reg32, Shape::Xmm, Shape::Imm] => Some(forms::PEXTRD_R32_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_PEXTRQ => match shapes {
            [Shape::Reg64, Shape::Xmm, Shape::Imm] => Some(forms::PEXTRQ_R64_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_PINSRD => match shapes {
            [Shape::Xmm, Shape::Reg32, Shape::Imm] => Some(forms::PINSRD_XMM_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_PINSRQ => match shapes {
            [Shape::Xmm, Shape::Reg64, Shape::Imm] => Some(forms::PINSRQ_XMM_R64_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_PMAXSD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMAXSD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMAXUD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMAXUD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMINSD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMINSD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMINUD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMINUD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_ROUNDPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDPS_XMM_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_ROUNDPD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDPD_XMM_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_ROUNDSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDSS_XMM_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_ROUNDSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDSD_XMM_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_BLENDVPS => match shapes {
            [Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::BLENDVPS_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_BLENDVPD => match shapes {
            [Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::BLENDVPD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PBLENDVB => match shapes {
            [Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::PBLENDVB_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_INSERTPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::INSERTPS_XMM_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_EXTRACTPS => match shapes {
            [Shape::Reg32, Shape::Xmm, Shape::Imm] => Some(forms::EXTRACTPS_R32_XMM_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_MOVNTDQA => match shapes {
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVNTDQA_XMM_MEM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVSXBW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXBW_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVZXBW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXBW_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVSXBD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXBD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVZXBD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXBD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVSXWD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXWD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVZXWD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXWD_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVSXDQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXDQ_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVZXDQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXDQ_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVSXWQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXWQ_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVZXWQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXWQ_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVSXBQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXBQ_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PMOVZXBQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXBQ_XMM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_PTEST => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PTEST_XMM_XMM),
            _ => None,
        },
        // Harness helpers
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
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVDQA_MEM_XMM),
            _ => None,
        },
        xed::XED_ICLASS_MOVHLPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVHLPS_XMM_XMM),
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
// Tests
// ---------------------------------------------------------------------------

#[test]
fn pextrd_pextrq_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for lane in 0..4u32 {
        let body = format!(
            "    mov $0x1122334455667788, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0x99aabbccddeeff00, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm0\n\
                 pextrd ${lane}, %xmm0, %eax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("pextrd_lane_{lane}"), &body, 0)?;
    }
    for lane in 0..2u32 {
        let body = format!(
            "    mov $0x1122334455667788, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0x99aabbccddeeff00, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm0\n\
                 pextrq ${lane}, %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("pextrq_lane_{lane}"), &body, 0)?;
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn pinsrd_pinsrq_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for lane in 0..4u32 {
        let readback = if lane < 2 {
            "movq %xmm0, %rax\n"
        } else {
            "movhlps %xmm0, %xmm0\n    movq %xmm0, %rax\n"
        };
        let body = format!(
            "    mov $0x0123456789abcdef, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0xfedcba9876543210, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm0\n\
                 mov $0xaabbccdd, %eax\n\
                 pinsrd ${lane}, %eax, %xmm0\n\
                 {readback}",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("pinsrd_lane_{lane}"), &body, 0)?;
    }

    for lane in 0..2u32 {
        let readback = if lane == 0 {
            "movq %xmm0, %rax\n"
        } else {
            "movhlps %xmm0, %xmm0\n    movq %xmm0, %rax\n"
        };
        let body = format!(
            "    mov $0x0123456789abcdef, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0xfedcba9876543210, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm0\n\
                 mov $0xaabbccddeeff0011, %rax\n\
                 pinsrq ${lane}, %rax, %xmm0\n\
                 {readback}",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("pinsrq_lane_{lane}"), &body, 0)?;
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn pmax_pmin_signed_unsigned_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for (op, mnemonic) in [
        ("pmaxsd", "pmaxsd"),
        ("pmaxud", "pmaxud"),
        ("pminsd", "pminsd"),
        ("pminud", "pminud"),
    ] {
        for read_high in [false, true] {
            let readback = if read_high {
                "movhlps %xmm0, %xmm0\n    movq %xmm0, %rax\n"
            } else {
                "movq %xmm0, %rax\n"
            };
            let body = format!(
                "    mov $0x7fffffff_ffffffff, %rax\n\
                     mov %rax, 0x{SCRATCH:x}\n\
                     mov $0x00000000_80000000, %rax\n\
                     mov %rax, 0x{SCRATCH8:x}\n\
                     movdqa 0x{SCRATCH:x}, %xmm0\n\
                     mov $0x80000000_00000001, %rax\n\
                     mov %rax, 0x{SCRATCH:x}\n\
                     mov $0xffffffff_7fffffff, %rax\n\
                     mov %rax, 0x{SCRATCH8:x}\n\
                     movdqa 0x{SCRATCH:x}, %xmm1\n\
                     {mnemonic} %xmm1, %xmm0\n\
                     {readback}",
                SCRATCH8 = SCRATCH + 8
            );
            ran |= differential_case(&format!("{op}_high_{read_high}"), &body, 0)?;
        }
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn roundps_roundpd_modes_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // Test values: 1.5, -1.5, 2.5, -2.5
    // f32: 1.5 = 0x3fc00000, -1.5 = 0xbfc00000, 2.5 = 0x40200000, -2.5 = 0xc0200000
    // f64: 1.5 = 0x3ff8000000000000, -1.5 = 0xbff8000000000000, 2.5 = 0x4004000000000000, -2.5 = 0xc004000000000000
    for mode in [0u8, 1, 2, 3] {
        // ROUNDPS low half
        let body_ps_lo = format!(
            "    mov $0xbfc00000_3fc00000, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0xc0200000_40200000, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm1\n\
                 roundps ${mode}, %xmm1, %xmm0\n\
                 movq %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("roundps_m{mode}_lo"), &body_ps_lo, 0)?;

        // ROUNDPS high half
        let body_ps_hi = format!(
            "    mov $0xbfc00000_3fc00000, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0xc0200000_40200000, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm1\n\
                 roundps ${mode}, %xmm1, %xmm0\n\
                 movhlps %xmm0, %xmm0\n\
                 movq %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("roundps_m{mode}_hi"), &body_ps_hi, 0)?;

        // ROUNDPD low half
        let body_pd_lo = format!(
            "    mov $0x3ff8000000000000, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0xbff8000000000000, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm1\n\
                 roundpd ${mode}, %xmm1, %xmm0\n\
                 movq %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("roundpd_m{mode}_lo"), &body_pd_lo, 0)?;

        // ROUNDPD high half
        let body_pd_hi = format!(
            "    mov $0x4004000000000000, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0xc004000000000000, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm1\n\
                 roundpd ${mode}, %xmm1, %xmm0\n\
                 movhlps %xmm0, %xmm0\n\
                 movq %xmm0, %rax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("roundpd_m{mode}_hi"), &body_pd_hi, 0)?;
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn blendv_sign_bit_differential() -> Result<(), BoxError> {
    let mut ran = false;

    // PBLENDVB: byte blend with alternating bit 7 in XMM0 mask
    let body_pblendvb = format!(
        "    mov $0x8000ff008000ff00, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x8000ff008000ff00, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0x1111111111111111, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x1111111111111111, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm2\n\
             mov $0x2222222222222222, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x2222222222222222, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pblendvb %xmm0, %xmm1, %xmm2\n\
             movq %xmm2, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pblendvb_sign_bit", &body_pblendvb, 0)?;

    // BLENDVPS: dword blend on sign bit of XMM0
    // dword 0: 0x80000000 (sign set -> pick src=0x22222222)
    // dword 1: 0x7fffffff (sign clear -> pick dst=0x11111111)
    let body_blendvps = format!(
        "    mov $0x7fffffff_80000000, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x80000001_00000000, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0x11111111_11111111, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x11111111_11111111, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm2\n\
             mov $0x22222222_22222222, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x22222222_22222222, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             blendvps %xmm0, %xmm1, %xmm2\n\
             movq %xmm2, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("blendvps_sign_bit_lo", &body_blendvps, 0)?;

    let body_blendvps_hi = format!(
        "    mov $0x7fffffff_80000000, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x80000001_00000000, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0x11111111_11111111, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x11111111_11111111, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm2\n\
             mov $0x22222222_22222222, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x22222222_22222222, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             blendvps %xmm0, %xmm1, %xmm2\n\
             movhlps %xmm2, %xmm2\n\
             movq %xmm2, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("blendvps_sign_bit_hi", &body_blendvps_hi, 0)?;

    // BLENDVPD: qword blend on sign bit of XMM0
    let body_blendvpd = format!(
        "    mov $0x8000000000000000, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x7fffffffffffffff, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0x1111111111111111, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x1111111111111111, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm2\n\
             mov $0x2222222222222222, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x2222222222222222, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             blendvpd %xmm0, %xmm1, %xmm2\n\
             movq %xmm2, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("blendvpd_sign_bit", &body_blendvpd, 0)?;

    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn insertps_extractps_differential() -> Result<(), BoxError> {
    let mut ran = false;

    // EXTRACTPS
    for lane in 0..4u32 {
        let body = format!(
            "    mov $0x1122334455667788, %rax\n\
                 mov %rax, 0x{SCRATCH:x}\n\
                 mov $0x99aabbccddeeff00, %rax\n\
                 mov %rax, 0x{SCRATCH8:x}\n\
                 movdqa 0x{SCRATCH:x}, %xmm0\n\
                 extractps ${lane}, %xmm0, %eax\n",
            SCRATCH8 = SCRATCH + 8
        );
        ran |= differential_case(&format!("extractps_lane_{lane}"), &body, 0)?;
    }

    // INSERTPS: insert src lane 1 into dst lane 2, zeroing lane 0 (imm = 0x10 | (1 << 2) | 2 = 0x16)
    let body_insertps = format!(
        "    mov $0x1111111122222222, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x3333333344444444, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0xaaaaaaaa_bbbbbbbb, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0xcccccccc_dddddddd, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             insertps $0x16, %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("insertps_lo", &body_insertps, 0)?;

    let body_insertps_hi = format!(
        "    mov $0x1111111122222222, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x3333333344444444, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0xaaaaaaaa_bbbbbbbb, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0xcccccccc_dddddddd, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             insertps $0x16, %xmm1, %xmm0\n\
             movhlps %xmm0, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("insertps_hi", &body_insertps_hi, 0)?;

    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn movntdqa_differential() -> Result<(), BoxError> {
    let mut ran = false;
    let body = format!(
        "    mov $0x0123456789abcdef, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0xfedcba9876543210, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             mov $0x{SCRATCH:x}, %rax\n\
             movntdqa (%rax), %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("movntdqa_load_lo", &body, 0)?;

    let body_hi = format!(
        "    mov $0x0123456789abcdef, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0xfedcba9876543210, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             mov $0x{SCRATCH:x}, %rax\n\
             movntdqa (%rax), %xmm0\n\
             movhlps %xmm0, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("movntdqa_load_hi", &body_hi, 0)?;

    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn pmovsx_pmovzx_differential() -> Result<(), BoxError> {
    let mut ran = false;

    // PMOVSXBW / PMOVZXBW (8 -> 16)
    let body_sxbw = format!(
        "    mov $0x01807fff02817efe, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x0000000000000000, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovsxbw %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovsxbw", &body_sxbw, 0)?;

    let body_zxbw = format!(
        "    mov $0x01807fff02817efe, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0x0000000000000000, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovzxbw %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovzxbw", &body_zxbw, 0)?;

    // PMOVSXBD / PMOVZXBD (8 -> 32)
    let body_sxbd = format!(
        "    mov $0x01807ffe, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovsxbd %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovsxbd", &body_sxbd, 0)?;

    let body_zxbd = format!(
        "    mov $0x01807ffe, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovzxbd %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovzxbd", &body_zxbd, 0)?;

    // PMOVSXWD / PMOVZXWD (16 -> 32)
    let body_sxwd = format!(
        "    mov $0x8000_7fff_fffe_0001, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovsxwd %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovsxwd", &body_sxwd, 0)?;

    let body_zxwd = format!(
        "    mov $0x8000_7fff_fffe_0001, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovzxwd %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovzxwd", &body_zxwd, 0)?;

    // PMOVSXBQ / PMOVZXBQ (8 -> 64)
    let body_sxbq = format!(
        "    mov $0x807f, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovsxbq %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovsxbq", &body_sxbq, 0)?;

    let body_zxbq = format!(
        "    mov $0x807f, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovzxbq %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovzxbq", &body_zxbq, 0)?;

    // PMOVSXWQ / PMOVZXWQ (16 -> 64)
    let body_sxwq = format!(
        "    mov $0x8000_7fff, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovsxwq %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovsxwq", &body_sxwq, 0)?;

    let body_zxwq = format!(
        "    mov $0x8000_7fff, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovzxwq %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovzxwq", &body_zxwq, 0)?;

    // PMOVSXDQ / PMOVZXDQ (32 -> 64)
    let body_sxdq = format!(
        "    mov $0x80000000_7fffffff, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovsxdq %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovsxdq", &body_sxdq, 0)?;

    let body_zxdq = format!(
        "    mov $0x80000000_7fffffff, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov $0, %rax\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             pmovzxdq %xmm1, %xmm0\n\
             movq %xmm0, %rax\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("pmovzxdq", &body_zxdq, 0)?;

    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn ptest_differential() -> Result<(), BoxError> {
    let mut ran = false;

    // Both zero -> ZF=1, CF=1
    let body_both_zero = format!(
        "    mov $0, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             ptest %xmm1, %xmm0\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("ptest_both_zero", &body_both_zero, ZF | CF)?;

    // xmm0 & xmm1 == 0 -> ZF=1, CF=0
    let body_zf_set = format!(
        "    mov $0x0f0f0f0f0f0f0f0f, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0xf0f0f0f0f0f0f0f0, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             ptest %xmm1, %xmm0\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("ptest_zf_set", &body_zf_set, ZF | CF)?;

    // xmm0 = all 1s -> (~xmm0) & xmm1 == 0 -> CF=1, ZF=0
    let body_cf_set = format!(
        "    mov $0xffffffffffffffff, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm0\n\
             mov $0x1111111111111111, %rax\n\
             mov %rax, 0x{SCRATCH:x}\n\
             mov %rax, 0x{SCRATCH8:x}\n\
             movdqa 0x{SCRATCH:x}, %xmm1\n\
             ptest %xmm1, %xmm0\n",
        SCRATCH8 = SCRATCH + 8
    );
    ran |= differential_case("ptest_cf_set", &body_cf_set, ZF | CF)?;

    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}
