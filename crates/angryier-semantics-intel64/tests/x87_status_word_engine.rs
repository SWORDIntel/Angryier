#![forbid(unsafe_code)]

//! Engine and differential validation for the x87 status word (X87_SW) and FSTSW AX.

use angryier_arch::{OperandKind, OperandVisibility};
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

fn seed_x87(state: &mut EngineState, slot: u32, f64_bits: u64) -> Result<(), BoxError> {
    let mut raw = [0u8; 10];
    raw[..8].copy_from_slice(&f64_bits.to_le_bytes());
    state
        .registers
        .write_in_place(register_id::X87_BASE + slot, &raw)
        .map_err(|e| format!("seed x87 slot {slot}: {e:?}"))?;
    Ok(())
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
// Unit tests (single instruction)
// ---------------------------------------------------------------------------

#[test]
fn fninit_clears_dirty_status_word() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDB, 0xE3]; // fninit
    let mut state = create_state(code)?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0xFFFF_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FINIT, &state)?;
    let sw_bytes = after.registers.read(register_id::X87_SW.0)?;
    let sw = u16::from_le_bytes(sw_bytes[..2].try_into().map_err(|_| "sw slice")?);
    assert_eq!(sw, 0, "fninit should clear status word to 0, got {sw:#x}");
    Ok(())
}

#[test]
fn fstsw_ax_copies_sw_and_preserves_rax_upper_bits() -> Result<(), BoxError> {
    let code: &[u8] = &[0xDF, 0xE0]; // fnstsw %ax
    let mut state = create_state(code)?;
    state
        .registers
        .write_in_place(register_id::GPR_BASE, &0xAAAA_0000_0000_0000_u64.to_le_bytes())?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0x3800_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FSTSW_AX, &state)?;
    let rax_bytes = after.registers.read(register_id::GPR_BASE)?;
    let rax = u64::from_le_bytes(rax_bytes[..8].try_into().map_err(|_| "rax slice")?);
    assert_eq!(
        rax, 0xAAAA_0000_0000_3800_u64,
        "expected 0xAAAA_0000_0000_3800, got {rax:#x}"
    );
    Ok(())
}

#[test]
fn push_and_pop_track_top() -> Result<(), BoxError> {
    let code_fld1: &[u8] = &[0xD9, 0xE8]; // fld1
    let mut state = create_state(code_fld1)?;
    clear_x87_stack(&mut state)?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0_u16.to_le_bytes())?;
    let after_push = execute_one(code_fld1, forms::FLD1, &state)?;
    let sw_bytes = after_push.registers.read(register_id::X87_SW.0)?;
    let sw_push = u16::from_le_bytes(sw_bytes[..2].try_into().map_err(|_| "sw slice")?);
    assert_eq!(
        sw_push, 0x3800,
        "fld1 push should decrement TOP to 7 (0x3800), got {sw_push:#x}"
    );

    let code_fstp: &[u8] = &[0xDD, 0xD8]; // fstp %st(0)
    let after_pop = execute_one(code_fstp, forms::FSTP_STI, &after_push)?;
    let sw_bytes_pop = after_pop.registers.read(register_id::X87_SW.0)?;
    let sw_pop = u16::from_le_bytes(sw_bytes_pop[..2].try_into().map_err(|_| "sw slice")?);
    assert_eq!(sw_pop, 0, "fstp pop should increment TOP back to 0, got {sw_pop:#x}");
    Ok(())
}

#[test]
fn fcom_sti_condition_codes() -> Result<(), BoxError> {
    let code: &[u8] = &[0xD8, 0xD1]; // fcom %st(1)

    // ST0=2.0 vs ST1=3.0: 2.0 < 3.0 -> C0=1 (bit 8 = 0x0100)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 2.0_f64.to_bits())?;
    seed_x87(&mut state, 1, 3.0_f64.to_bits())?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FCOM_STI, &state)?;
    let sw = u16::from_le_bytes(
        after.registers.read(register_id::X87_SW.0)?[..2]
            .try_into()
            .map_err(|_| "sw")?,
    );
    assert_ne!(sw & 0x0100, 0, "expected C0 bit set for 2.0 < 3.0, got {sw:#x}");
    assert_eq!(sw & 0x4000, 0, "expected C3 bit clear for 2.0 < 3.0, got {sw:#x}");

    // ST0=2.0 vs ST1=2.0: Equal -> C3=1 (bit 14 = 0x4000)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 2.0_f64.to_bits())?;
    seed_x87(&mut state, 1, 2.0_f64.to_bits())?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FCOM_STI, &state)?;
    let sw = u16::from_le_bytes(
        after.registers.read(register_id::X87_SW.0)?[..2]
            .try_into()
            .map_err(|_| "sw")?,
    );
    assert_eq!(sw & 0x0100, 0, "expected C0 clear for equal, got {sw:#x}");
    assert_ne!(sw & 0x4000, 0, "expected C3 set for equal, got {sw:#x}");

    // ST0=NaN vs ST1=1.0: Unordered -> C0=1, C2=1, C3=1 (0x4500)
    let mut state = create_state(code)?;
    clear_x87_stack(&mut state)?;
    seed_x87(&mut state, 0, 0x7FF8_0000_0000_0001_u64)?;
    seed_x87(&mut state, 1, 1.0_f64.to_bits())?;
    state
        .registers
        .write_in_place(register_id::X87_SW.0, &0_u16.to_le_bytes())?;
    let after = execute_one(code, forms::FCOM_STI, &state)?;
    let sw = u16::from_le_bytes(
        after.registers.read(register_id::X87_SW.0)?[..2]
            .try_into()
            .map_err(|_| "sw")?,
    );
    assert_eq!(
        sw & 0x5500,
        0x4500,
        "expected C0|C2|C3 set for NaN unordered, got {sw:#x}"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Native differential harness
// ---------------------------------------------------------------------------

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
    Reg16,
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
            OperandKind::Register(view) if view.width_bits == 16 => shapes.push(Shape::Reg16),
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
            ([Shape::Stack, Shape::Stack], _) | ([Shape::Stack], _) => Some(forms::FLD_STI),
            (_, Some(Shape::Mem64)) => Some(forms::FLD_M64),
            _ => None,
        },
        xed::XED_ICLASS_FSTP | xed::XED_ICLASS_FSTPNCE => match (&shapes[..], mem) {
            ([Shape::Stack, Shape::Stack], _) | ([Shape::Stack], _) => Some(forms::FSTP_STI),
            (_, Some(Shape::Mem64)) => Some(forms::FSTP_M64),
            _ => None,
        },
        xed::XED_ICLASS_FCOM => match &shapes[..] {
            [Shape::Stack, Shape::Stack] | [Shape::Stack] => Some(forms::FCOM_STI),
            _ => Some(forms::FCOM_STI),
        },
        xed::XED_ICLASS_FCOMP => match &shapes[..] {
            [Shape::Stack, Shape::Stack] | [Shape::Stack] => Some(forms::FCOMP_STI),
            _ => Some(forms::FCOMP_STI),
        },
        xed::XED_ICLASS_FCOMPP => Some(forms::FCOMPP),
        xed::XED_ICLASS_FNSTSW => match &shapes[..] {
            [Shape::Reg16] => Some(forms::FSTSW_AX),
            _ => None,
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

fn temp_dir_trans(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-x87sw-{name}-{}", std::process::id()));
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

    // The engine implements the masked-exceptions model where exception/summary flags
    // (bits 0..7 of the status word, e.g. Invalid Operation IE on NaN) stay 0,
    // while hardware sets IE (bit 0) on NaN comparison. Condition codes C0/C2/C3,
    // TOP (bits 11..13), and the preserved upper 48 RAX bits are compared directly.
    if engine_rax != (native_rax & !0x00FF) {
        return Err(
            format!("mismatch on `{name}`: engine={engine_rax:#x} native={native_rax:#x}\nbody:\n{body}").into(),
        );
    }
    Ok(true)
}

#[test]
fn differential_status_word_suite() -> Result<(), BoxError> {
    let nan_body = format!(
        "    movabs $0x7FF8000000000001, %rbx\n    mov %rbx, 0x{SCRATCH:x}\n    fninit\n    fldl 0x{SCRATCH:x}\n    fld1\n    fcom %st(1)\n    fnstsw %ax\n"
    );

    let cases: [(&str, String); 9] = [
        ("fninit_fnstsw", "    fninit\n    fnstsw %ax\n".to_string()),
        (
            "fld_top5",
            "    fninit\n    fld1\n    fldz\n    fld1\n    fnstsw %ax\n".to_string(),
        ),
        (
            "fld_fstp_top7",
            "    fninit\n    fld1\n    fldz\n    fstp %st(0)\n    fnstsw %ax\n".to_string(),
        ),
        (
            "fcom_less",
            "    fninit\n    fld1\n    fldz\n    fcom %st(1)\n    fnstsw %ax\n".to_string(),
        ),
        (
            "fcom_greater",
            "    fninit\n    fldz\n    fld1\n    fcom %st(1)\n    fnstsw %ax\n".to_string(),
        ),
        (
            "fcom_equal",
            "    fninit\n    fldz\n    fldz\n    fcom %st(1)\n    fnstsw %ax\n".to_string(),
        ),
        ("fcom_nan", nan_body),
        (
            "fcomp_pop",
            "    fninit\n    fld1\n    fldz\n    fcomp %st(1)\n    fnstsw %ax\n".to_string(),
        ),
        (
            "fcompp_pop2",
            "    fninit\n    fld1\n    fldz\n    fcompp\n    fnstsw %ax\n".to_string(),
        ),
    ];

    let mut executed = 0usize;
    let mut skipped = false;
    for (name, body) in &cases {
        let full_body = format!("    movabs $0x1122334455667788, %rax\n{body}");
        let ran = differential_trans(name, &full_body)?;
        skipped |= !ran;
        executed += usize::from(ran);
    }

    if skipped && executed == 0 {
        eprintln!("skipping x87 status word differential: binutils unavailable");
        return Ok(());
    }
    eprintln!("x87 status word differential oracle: {executed} cases matched hardware byte-for-byte");
    assert_eq!(executed, 9, "expected all 9 differential cases to execute");
    Ok(())
}
