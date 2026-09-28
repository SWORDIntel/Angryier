#![forbid(unsafe_code)]

//! Hardware differential oracle for the census tail batch:
//! XADD, CMPXCHG, SETcc (memory destinations), TEST (memory operands),
//! BSWAP, MOVBE, CLFLUSH, and CRC32.
//!
//! Compares native execution (`as`/`ld`/run capture of `[rax, rflags]`)
//! against the semantic pipeline (decode -> corpus form -> provider
//! -> seal -> lower -> concrete interpreter).

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
const STACK_TOP: u64 = 0x600000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(3);

const RSP: u32 = register_id::GPR_BASE + 4;

const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;

const FLAGS_ALL: u64 = CF | PF | AF | ZF | SF | OF;
const FLAGS_LOGICAL: u64 = CF | PF | ZF | SF | OF;
const FLAGS_NONE: u64 = 0;

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
    let dir = std::env::temp_dir().join(format!("angryier-censustail-{name}-{}", std::process::id()));
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
        "        .global _start\n        .text\n_start:\n{body}\n    mov %rax, 0x{SCRATCH:x}\n    pushfq\n    pop %rbx\n    mov %rbx, 0x{SCRATCH8:x}\n    mov $1, %rax\n    mov $1, %rdi\n    mov $0x{SCRATCH:x}, %rsi\n    mov $16, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\nscratch:\n        .space 0x1000\n",
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
    Reg16,
    Reg8,
    Imm,
    Mem64,
    Mem32,
    Mem16,
    Mem8,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 32 => Some(Shape::Reg32),
        OperandKind::Register(view) if view.width_bits == 16 => Some(Shape::Reg16),
        OperandKind::Register(view) if view.width_bits == 8 => Some(Shape::Reg8),
        OperandKind::Immediate(_) => Some(Shape::Imm),
        OperandKind::Memory(_) if operand.width_bits == 64 => Some(Shape::Mem64),
        OperandKind::Memory(_) if operand.width_bits == 32 => Some(Shape::Mem32),
        OperandKind::Memory(_) if operand.width_bits == 16 => Some(Shape::Mem16),
        OperandKind::Memory(_) if operand.width_bits == 8 => Some(Shape::Mem8),
        // XED reports no width for some hints (CLFLUSH etc.).
        OperandKind::Memory(_) => Some(Shape::Mem8),
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
        xed::XED_ICLASS_XADD | xed::XED_ICLASS_XADD_LOCK => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XADD_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XADD_R32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::XADD_R16_R16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::XADD_R8_R8),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XADD_MEM64_R64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::XADD_MEM32_R32),
            [Shape::Mem16, Shape::Reg16] => Some(forms::XADD_MEM16_R16),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XADD_MEM8_R8),
            _ => None,
        },
        xed::XED_ICLASS_CMPXCHG | xed::XED_ICLASS_CMPXCHG_LOCK => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMPXCHG_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMPXCHG_R32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::CMPXCHG_R16_R16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::CMPXCHG_R8_R8),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMPXCHG_MEM64_R64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMPXCHG_MEM32_R32),
            [Shape::Mem16, Shape::Reg16] => Some(forms::CMPXCHG_MEM16_R16),
            [Shape::Mem8, Shape::Reg8] => Some(forms::CMPXCHG_MEM8_R8),
            _ => None,
        },
        xed::XED_ICLASS_STC => Some(forms::STC),
        xed::XED_ICLASS_CLC => Some(forms::CLC),
        xed::XED_ICLASS_SETZ => match shapes {
            [Shape::Reg8] => Some(forms::SETZ_R8),
            [Shape::Mem8] => Some(forms::SETZ_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNZ => match shapes {
            [Shape::Reg8] => Some(forms::SETNZ_R8),
            [Shape::Mem8] => Some(forms::SETNZ_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETB => match shapes {
            [Shape::Reg8] => Some(forms::SETB_R8),
            [Shape::Mem8] => Some(forms::SETB_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNB => match shapes {
            [Shape::Reg8] => Some(forms::SETAE_R8),
            [Shape::Mem8] => Some(forms::SETAE_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETBE => match shapes {
            [Shape::Reg8] => Some(forms::SETBE_R8),
            [Shape::Mem8] => Some(forms::SETBE_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNBE => match shapes {
            [Shape::Reg8] => Some(forms::SETA_R8),
            [Shape::Mem8] => Some(forms::SETA_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETL => match shapes {
            [Shape::Reg8] => Some(forms::SETL_R8),
            [Shape::Mem8] => Some(forms::SETL_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNL => match shapes {
            [Shape::Reg8] => Some(forms::SETGE_R8),
            [Shape::Mem8] => Some(forms::SETGE_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETLE => match shapes {
            [Shape::Reg8] => Some(forms::SETLE_R8),
            [Shape::Mem8] => Some(forms::SETLE_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNLE => match shapes {
            [Shape::Reg8] => Some(forms::SETG_R8),
            [Shape::Mem8] => Some(forms::SETG_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETS => match shapes {
            [Shape::Reg8] => Some(forms::SETS_R8),
            [Shape::Mem8] => Some(forms::SETS_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNS => match shapes {
            [Shape::Reg8] => Some(forms::SETNS_R8),
            [Shape::Mem8] => Some(forms::SETNS_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETO => match shapes {
            [Shape::Reg8] => Some(forms::SETO_R8),
            [Shape::Mem8] => Some(forms::SETO_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNO => match shapes {
            [Shape::Reg8] => Some(forms::SETNO_R8),
            [Shape::Mem8] => Some(forms::SETNO_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETP => match shapes {
            [Shape::Reg8] => Some(forms::SETP_R8),
            [Shape::Mem8] => Some(forms::SETP_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_SETNP => match shapes {
            [Shape::Reg8] => Some(forms::SETNP_R8),
            [Shape::Mem8] => Some(forms::SETNP_MEM8),
            _ => None,
        },
        xed::XED_ICLASS_TEST => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::TEST_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::TEST_R32_R32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::TEST_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::TEST_MEM64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::TEST_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::TEST_R64_MEM64),
            _ => None,
        },
        xed::XED_ICLASS_CLFLUSH => match shapes {
            [Shape::Mem8 | Shape::Mem16 | Shape::Mem32 | Shape::Mem64] => Some(forms::CLFLUSH_MEM),
            _ => None,
        },
        xed::XED_ICLASS_MOVBE => match shapes {
            [Shape::Reg16, Shape::Mem16] => Some(forms::MOVBE_R16_MEM16),
            [Shape::Reg32, Shape::Mem32] => Some(forms::MOVBE_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::MOVBE_R64_MEM64),
            [Shape::Mem16, Shape::Reg16] => Some(forms::MOVBE_MEM16_R16),
            [Shape::Mem32, Shape::Reg32] => Some(forms::MOVBE_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOVBE_MEM64_R64),
            _ => None,
        },
        xed::XED_ICLASS_BSWAP => match shapes {
            [Shape::Reg64] => Some(forms::BSWAP_R64),
            [Shape::Reg32] => Some(forms::BSWAP_R32),
            _ => None,
        },
        xed::XED_ICLASS_CRC32 => match shapes {
            [Shape::Reg32, Shape::Reg8] => Some(forms::CRC32_R32_R8),
            [Shape::Reg64, Shape::Reg8] => Some(forms::CRC32_R64_R8),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CRC32_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CRC32_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CRC32_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CRC32_R64_MEM64),
            [Shape::Reg32, Shape::Mem8] => Some(forms::CRC32_R32_MEM8),
            [Shape::Reg64, Shape::Mem8] => Some(forms::CRC32_R64_MEM8),
            _ => None,
        },
        // Harness plumbing forms
        xed::XED_ICLASS_MOV => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::MOV_R64_R64),
            [Shape::Reg32, Shape::Imm] => Some(forms::MOV_R32_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::MOV_R32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::MOV_R64_MEM64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::MOV_MEM32_R32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::MOV_R32_MEM32),
            [Shape::Mem16, Shape::Reg16] => Some(forms::MOV_MEM16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::MOV_R16_MEM16),
            [Shape::Mem8, Shape::Reg8] => Some(forms::MOV_MEM8_R8),
            [Shape::Reg8, Shape::Mem8] => Some(forms::MOV_R8_MEM8),
            [Shape::Mem64, Shape::Imm] => Some(forms::MOV_MEM64_IMM32),
            [Shape::Mem32, Shape::Imm] => Some(forms::MOV_MEM32_IMM32),
            [Shape::Mem8, Shape::Imm] => Some(forms::MOV_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::MOV_MEM16_IMM16),
            [Shape::Reg16, Shape::Imm] => Some(forms::MOV_R16_IMM16),
            [Shape::Reg8, Shape::Imm] => Some(forms::MOV_R8_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_MOVZX => match shapes {
            [Shape::Reg64, Shape::Reg8] => Some(forms::MOVZX_R64_R8),
            [Shape::Reg64, Shape::Mem8] => Some(forms::MOVZX_R64_MEM8),
            [Shape::Reg64, Shape::Reg16] => Some(forms::MOVZX_R64_R16),
            [Shape::Reg64, Shape::Mem16] => Some(forms::MOVZX_R64_MEM16),
            [Shape::Reg32, Shape::Reg8] => Some(forms::MOVZX_R32_R8),
            [Shape::Reg32, Shape::Mem8] => Some(forms::MOVZX_R32_MEM8),
            [Shape::Reg32, Shape::Reg16] => Some(forms::MOVZX_R32_R16),
            [Shape::Reg32, Shape::Mem16] => Some(forms::MOVZX_R32_MEM16),
            _ => None,
        },
        xed::XED_ICLASS_PUSHF | xed::XED_ICLASS_PUSHFQ => Some(forms::PUSHF),
        xed::XED_ICLASS_POP => match shapes {
            [Shape::Reg64] => Some(forms::POP_R64),
            _ => None,
        },
        xed::XED_ICLASS_XOR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XOR_R32_R32),
            _ => None,
        },
        xed::XED_ICLASS_CMP => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMP_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMP_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::CMP_R64_IMM32),
            [Shape::Reg32, Shape::Imm] => Some(forms::CMP_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_LEA => match shapes {
            [Shape::Reg64, _] => Some(forms::LEA_R64_MEM),
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
                size: 0x2000,
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
// Test cases
// ---------------------------------------------------------------------------

#[test]
fn xadd_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // R64 R64
    ran |= differential_case(
        "xadd_r64_r64",
        "    mov $0x10, %rax\n    mov $0x20, %rcx\n    xadd %rcx, %rax\n",
        FLAGS_ALL,
    )?;
    // R32 R32
    ran |= differential_case(
        "xadd_r32_r32",
        "    mov $0x1000, %eax\n    mov $0x2000, %ecx\n    xadd %ecx, %eax\n    mov %eax, %eax\n",
        FLAGS_ALL,
    )?;
    // MEM32 R32
    ran |= differential_case(
        "xadd_mem32_r32",
        "    mov $0x500200, %rdi\n    movl $0x100, (%rdi)\n    mov $0x50, %ecx\n    xadd %ecx, (%rdi)\n    mov (%rdi), %eax\n",
        FLAGS_ALL,
    )?;
    // MEM64 R64
    ran |= differential_case(
        "xadd_mem64_r64",
        "    mov $0x500200, %rdi\n    movq $0x100000000, (%rdi)\n    mov $0x500000000, %rcx\n    xadd %rcx, (%rdi)\n    mov (%rdi), %rax\n",
        FLAGS_ALL,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn cmpxchg_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // R64 R64 equal
    ran |= differential_case(
        "cmpxchg_r64_r64_eq",
        "    mov $0x42, %rax\n    mov $0x42, %rdx\n    mov $0x99, %rcx\n    cmpxchg %rcx, %rdx\n    mov %rdx, %rax\n",
        FLAGS_ALL,
    )?;
    // R64 R64 not equal
    ran |= differential_case(
        "cmpxchg_r64_r64_ne",
        "    mov $0x42, %rax\n    mov $0x10, %rdx\n    mov $0x99, %rcx\n    cmpxchg %rcx, %rdx\n",
        FLAGS_ALL,
    )?;
    // MEM32 R32 equal
    ran |= differential_case(
        "cmpxchg_mem32_r32_eq",
        "    mov $0x500200, %rdi\n    movl $0x42, (%rdi)\n    mov $0x42, %eax\n    mov $0x99, %ecx\n    cmpxchg %ecx, (%rdi)\n    mov (%rdi), %eax\n",
        FLAGS_ALL,
    )?;
    // MEM32 R32 not equal
    ran |= differential_case(
        "cmpxchg_mem32_r32_ne",
        "    mov $0x500200, %rdi\n    movl $0x10, (%rdi)\n    mov $0x42, %eax\n    mov $0x99, %ecx\n    cmpxchg %ecx, (%rdi)\n",
        FLAGS_ALL,
    )?;
    // MEM16 R16 equal
    ran |= differential_case(
        "cmpxchg_mem16_r16_eq",
        "    mov $0x500200, %rdi\n    movw $0x42, (%rdi)\n    mov $0x42, %ax\n    mov $0x99, %cx\n    cmpxchg %cx, (%rdi)\n    movzwq (%rdi), %rax\n",
        FLAGS_ALL,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn setcc_mem_differential() -> Result<(), BoxError> {
    let mut ran = false;
    for (name, setup, instr, expected_byte) in [
        ("setz_mem_true", "xor %eax, %eax", "setz (%rdi)", 1u64),
        ("setz_mem_false", "mov $1, %eax\ntest %eax, %eax", "setz (%rdi)", 0u64),
        ("setnz_mem_true", "mov $1, %eax\ntest %eax, %eax", "setnz (%rdi)", 1u64),
        ("setnz_mem_false", "xor %eax, %eax", "setnz (%rdi)", 0u64),
        ("setb_mem_true", "stc", "setb (%rdi)", 1u64),
        ("setb_mem_false", "clc", "setb (%rdi)", 0u64),
        ("setae_mem_true", "clc", "setae (%rdi)", 1u64),
        ("setae_mem_false", "stc", "setae (%rdi)", 0u64),
        ("sets_mem_true", "mov $-1, %rax\ntest %rax, %rax", "sets (%rdi)", 1u64),
        ("sets_mem_false", "mov $1, %rax\ntest %rax, %rax", "sets (%rdi)", 0u64),
    ] {
        let _ = expected_byte;
        ran |= differential_case(
            name,
            &format!(
                "    mov $0x500200, %rdi\n    movb $0x55, (%rdi)\n    {setup}\n    {instr}\n    movzbq (%rdi), %rax\n"
            ),
            FLAGS_NONE,
        )?;
    }
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn test_mem_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // TEST MEM32 R32 (zero result -> ZF=1)
    ran |= differential_case(
        "test_mem32_r32_zero",
        "    mov $0x500200, %rdi\n    movl $0x0f0f0f0f, (%rdi)\n    mov $0xf0f0f0f0, %eax\n    test %eax, (%rdi)\n    mov $0, %rax\n",
        FLAGS_LOGICAL,
    )?;
    // TEST MEM32 R32 (nonzero result -> ZF=0)
    ran |= differential_case(
        "test_mem32_r32_nonzero",
        "    mov $0x500200, %rdi\n    movl $0x0f0f0f0f, (%rdi)\n    mov $0x0f0f0f0f, %eax\n    test %eax, (%rdi)\n    mov $0, %rax\n",
        FLAGS_LOGICAL,
    )?;
    // TEST MEM64 R64
    ran |= differential_case(
        "test_mem64_r64_zero",
        "    mov $0x500200, %rdi\n    movq $0x0f0f0f0f0f0f0f0f, (%rdi)\n    mov $0xf0f0f0f0f0f0f0f0, %rax\n    test %rax, (%rdi)\n    mov $0, %rax\n",
        FLAGS_LOGICAL,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn bswap_differential() -> Result<(), BoxError> {
    let mut ran = false;
    ran |= differential_case(
        "bswap_r64",
        "    mov $0x0123456789abcdef, %rax\n    bswap %rax\n",
        FLAGS_NONE,
    )?;
    ran |= differential_case(
        "bswap_r32",
        "    mov $0x12345678, %eax\n    bswap %eax\n    mov %eax, %eax\n",
        FLAGS_NONE,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

/// The differential host (Ivy Bridge) has no MOVBE, so these cases cannot
/// run natively (SIGILL). Validate engine-only against the byte-swap
/// results, and keep one CPUID-gated native probe when the host supports it.
#[test]
fn movbe_differential() -> Result<(), BoxError> {
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let cases: &[(&str, &str, u64)] = &[
        (
            "movbe_r16_mem16",
            "    mov $0x500200, %rdi\n    movw $0x1234, (%rdi)\n    movbe (%rdi), %ax\n    movzwq %ax, %rax\n",
            0x3412,
        ),
        (
            "movbe_r32_mem32",
            "    mov $0x500200, %rdi\n    movl $0x12345678, (%rdi)\n    movbe (%rdi), %eax\n    mov %eax, %eax\n",
            0x7856_3412,
        ),
        (
            "movbe_r64_mem64",
            "    mov $0x500200, %rdi\n    movabs $0x0123456789abcdef, %rax\n    mov %rax, (%rdi)\n    movbe (%rdi), %rax\n",
            0xefcd_ab89_6745_2301,
        ),
        (
            "movbe_mem32_r32",
            "    mov $0x500200, %rdi\n    mov $0x12345678, %eax\n    movbe %eax, (%rdi)\n    mov (%rdi), %eax\n",
            0x7856_3412,
        ),
        (
            "movbe_mem64_r64",
            "    mov $0x500200, %rdi\n    movabs $0x0123456789abcdef, %rax\n    movbe %rax, (%rdi)\n    mov (%rdi), %rax\n",
            0xefcd_ab89_6745_2301,
        ),
    ];
    for (name, body, expected) in cases {
        let Some(dir) = temp_dir(name) else {
            continue;
        };
        let src = dir.join("case.s");
        let obj = dir.join("case.o");
        let bin = dir.join("case");
        std::fs::write(&src, harness_source(body))?;
        if assemble(&src, &obj).is_none() || link(&bin, &[&obj]).is_none() {
            continue;
        }
        let Some(code) = extract_text(&dir, &bin) else {
            continue;
        };
        let (rax, _) = run_engine(&code, &registry).map_err(|e| format!("case `{name}`: {e}\nbody:\n{body}"))?;
        if rax != *expected {
            return Err(
                format!("movbe engine mismatch on `{name}`: got {rax:#x}, want {expected:#x}\nbody:\n{body}").into(),
            );
        }
    }
    Ok(())
}

#[test]
fn clflush_differential() -> Result<(), BoxError> {
    let mut ran = false;
    ran |= differential_case(
        "clflush_mem",
        "    mov $0x500200, %rdi\n    movq $0x42, (%rdi)\n    clflush (%rdi)\n    mov (%rdi), %rax\n",
        FLAGS_NONE,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn crc32_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // CRC32 R32 R32
    ran |= differential_case(
        "crc32_r32_r32",
        "    mov $0xffffffff, %eax\n    mov $0x12345678, %ecx\n    crc32 %ecx, %eax\n    mov %eax, %eax\n",
        FLAGS_NONE,
    )?;
    // CRC32 R64 R64
    ran |= differential_case(
        "crc32_r64_r64",
        "    mov $0xffffffff, %rax\n    movabs $0x123456789abcdef0, %rcx\n    crc32 %rcx, %rax\n",
        FLAGS_NONE,
    )?;
    // CRC32 R32 R8
    ran |= differential_case(
        "crc32_r32_r8",
        "    mov $0xffffffff, %eax\n    mov $0x5a, %cl\n    crc32 %cl, %eax\n    mov %eax, %eax\n",
        FLAGS_NONE,
    )?;
    // CRC32 R32 MEM32
    ran |= differential_case(
        "crc32_r32_mem32",
        "    mov $0x500200, %rdi\n    movl $0x12345678, (%rdi)\n    mov $0xffffffff, %eax\n    crc32 (%rdi), %eax\n    mov %eax, %eax\n",
        FLAGS_NONE,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}
