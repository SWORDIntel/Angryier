#![forbid(unsafe_code)]

//! Hardware differential oracle for the control-flow/flag batch: LOOP,
//! LOOPE, LOOPNE, JRCXZ, LAHF, SAHF, CLD, STD, RET imm16, ENTER, LEAVE.
//!
//! Same harness as `bit_test_differential.rs`: binutils assemble/link/run,
//! native capture of `[rax, rflags]`, XED decode -> corpus form -> provider
//! -> seal -> lower -> concrete interpreter, comparing the result register
//! and the defined RFLAGS bits.
//!
//! RET_FAR is privileged (segment selectors) and cannot run natively; it is
//! covered by engine-side decode tests instead.

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
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const DF: u64 = 1 << 10;
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
// Native side
// ---------------------------------------------------------------------------

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-cflow-{name}-{}", std::process::id()));
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
// Engine side
// ---------------------------------------------------------------------------

enum Shape {
    Reg64,
    Reg16,
    Reg8,
    Reg32,
    Imm,
    Rel,
    Mem64,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 16 => Some(Shape::Reg16),
        OperandKind::Register(view) if view.width_bits == 32 => Some(Shape::Reg32),
        OperandKind::Register(view) if view.width_bits == 8 => Some(Shape::Reg8),
        OperandKind::Immediate(_) => Some(Shape::Imm),
        OperandKind::RelativeBranch(_) => Some(Shape::Rel),
        OperandKind::Memory(_) if operand.width_bits == 64 => Some(Shape::Mem64),
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
        xed::XED_ICLASS_LOOP => Some(forms::LOOP_REL8),
        xed::XED_ICLASS_LOOPE => Some(forms::LOOPE_REL8),
        xed::XED_ICLASS_LOOPNE => Some(forms::LOOPNE_REL8),
        xed::XED_ICLASS_JRCXZ => Some(forms::JRCXZ_REL8),
        xed::XED_ICLASS_LAHF => Some(forms::LAHF),
        xed::XED_ICLASS_SAHF => Some(forms::SAHF),
        xed::XED_ICLASS_CLD => Some(forms::CLD),
        xed::XED_ICLASS_STD => Some(forms::STD),
        xed::XED_ICLASS_RET_NEAR => match shapes {
            [Shape::Imm] => Some(forms::RET_IMM16),
            [] => Some(forms::RET),
            _ => None,
        },
        xed::XED_ICLASS_ENTER => Some(forms::ENTER_IMM16_IMM8),
        xed::XED_ICLASS_LEAVE => Some(forms::LEAVE),
        xed::XED_ICLASS_CALL_NEAR => Some(forms::CALL_REL32),
        xed::XED_ICLASS_JMP => Some(forms::JMP_REL32),
        xed::XED_ICLASS_JZ => Some(forms::JZ_REL32),
        xed::XED_ICLASS_CMP => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::CMP_R64_IMM32),
            _ => None,
        },
        xed::XED_ICLASS_PUSH => Some(forms::PUSH_R64),
        xed::XED_ICLASS_POP => match shapes {
            [Shape::Reg64] => Some(forms::POP_R64),
            _ => None,
        },
        xed::XED_ICLASS_MOV => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::MOV_R64_R64),
            [Shape::Reg32, Shape::Imm] => Some(forms::MOV_R32_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::MOV_R32_R32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::MOV_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            _ => None,
        },
        xed::XED_ICLASS_INC => match shapes {
            [Shape::Reg32] => Some(forms::INC_R32),
            [Shape::Reg64] => Some(forms::INC_R64),
            _ => None,
        },
        xed::XED_ICLASS_XOR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XOR_R32_R32),
            _ => None,
        },
        xed::XED_ICLASS_ADD => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ADD_R64_IMM32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::ADD_R64_R64),
            _ => None,
        },
        xed::XED_ICLASS_SUB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::SUB_R64_R64),
            [Shape::Reg32, Shape::Imm] => Some(forms::SUB_R32_IMM8),
            _ => None,
        },
        xed::XED_ICLASS_TEST => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::TEST_R64_R64),
            _ => None,
        },
        xed::XED_ICLASS_PUSHF | xed::XED_ICLASS_PUSHFQ => Some(forms::PUSHF),
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
    for _ in 0..1024 {
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
        pc = next_pc;
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

#[test]
fn loop_family_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // LOOP: counts down; exits when RCX hits 0. rax carries the final RCX.
    for count in [1u64, 3, 255] {
        ran |= differential_case(
            &format!("loop_{count}"),
            &format!("    mov ${count:#x}, %rcx\nloop1:\n    mov %rcx, %rax\n    loop loop1\n"),
            ZF,
        )?;
    }
    // LOOPE: continues while ZF=1; the body clears ZF after the first pass,
    // so a count of 3 executes exactly one iteration.
    ran |= differential_case(
        "loope_zf_clear",
        "    mov $3, %rcx\n    xor %eax, %eax\n    inc %eax\nloop2:\n    mov %rcx, %rax\n    xor %eax, %eax\n    inc %eax\n    loope loop2\n",
        ZF,
    )?;
    // LOOPE with ZF=1 throughout: runs the full count.
    ran |= differential_case(
        "loope_full",
        "    mov $3, %rcx\nloop3:\n    mov %rcx, %rax\n    test %rax, %rax\n    loope loop3\n",
        ZF,
    )?;
    // LOOPNE: continues while ZF=0.
    ran |= differential_case(
        "loopne_zf_set",
        "    mov $3, %rcx\n    xor %eax, %eax\nloop4:\n    mov %rcx, %rax\n    cmp $0, %rax\n    loopne loop4\n",
        ZF,
    )?;
    // JRCXZ taken (rcx=0) and not taken.
    ran |= differential_case(
        "jrcxz_taken",
        "    xor %rcx, %rcx\n    jrcxz taken\n    mov $0xdead, %rax\n    jmp done\ntaken:\n    mov $0xbeef, %rax\ndone:\n",
        0,
    )?;
    ran |= differential_case(
        "jrcxz_not_taken",
        "    mov $1, %rcx\n    jrcxz taken\n    mov $0xbeef, %rax\n    jmp done\ntaken:\n    mov $0xdead, %rax\ndone:\n",
        0,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn lahf_sahf_cld_std_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // LAHF after xor (ZF=1, PF=1, CF=0): AH = 0x46.
    ran |= differential_case(
        "lahf_after_xor",
        "    xor %eax, %eax\n    lahf\n    mov %eax, %eax\n",
        0,
    )?;
    // LAHF after an op that sets CF (1 - 2).
    ran |= differential_case(
        "lahf_after_sub",
        "    mov $1, %eax\n    sub $2, %eax\n    lahf\n    mov %eax, %eax\n",
        0,
    )?;
    // STD sets DF; observed in the dumped rflags.
    ran |= differential_case("std_sets_df", "    std\n    xor %eax, %eax\n", DF)?;
    ran |= differential_case("cld_clears_df", "    std\n    cld\n    xor %eax, %eax\n", DF)?;
    // SAHF then a ZF branch: AH=0x46 -> ZF=1 -> taken.
    ran |= differential_case(
        "sahf_zf_branch",
        "    mov $0x46, %eax\n    sahf\n    jz taken\n    mov $0xdead, %rax\n    jmp done\ntaken:\n    mov $0xbeef, %rax\ndone:\n",
        ZF,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}

#[test]
fn ret_imm16_enter_leave_differential() -> Result<(), BoxError> {
    let mut ran = false;
    // RET imm16: caller pushes an arg, callee returns with `ret $2`; rax
    // observes the stack depth inside the callee (deterministic in both
    // worlds: RSP starts at STACK_TOP).
    ran |= differential_case(
        "ret_imm16",
        "    mov %rsp, %rbx\n    push $0x1234\n    call fn\n    jmp done\nfn:\n    mov %rsp, %rax\n    sub %rbx, %rax\n    ret $2\ndone:\n",
        0,
    )?;
    // ENTER 0: rbp = rsp - frame; rax observes rbp.
    ran |= differential_case(
        "enter_0",
        "    mov %rsp, %rbx\n    enter $0x10, $0\n    mov %rbp, %rax\n    sub %rbx, %rax\n    leave\n",
        0,
    )?;
    // ENTER 1: pushes the caller's frame pointer chain.
    ran |= differential_case(
        "enter_1",
        "    mov %rsp, %rbx\n    mov $0x1111, %rbp\n    enter $0x10, $1\n    mov %rbp, %rax\n    sub %rbx, %rax\n    leave\n",
        0,
    )?;
    if !ran {
        eprintln!("SKIP: binutils unavailable");
    }
    Ok(())
}
