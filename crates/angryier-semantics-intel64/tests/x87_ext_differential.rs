#![forbid(unsafe_code)]

//! Hardware differential oracle for the extended x87 semantic family.
//!
//! Validates new x87 forms against the host CPU:
//! - FCOM/FCOMP/FCOMPP variants (stack top vs st(i)/memory)
//! - FIADD/FISUB/FIMUL/FIDIV/FICOM/FICOMP (integer memory sources, values incl. negative and large)
//! - FILD/FISTP round-trips (0, 1.5, -2.25, 1e10)
//! - FABS/FCHS/FSQRT (known values)
//! - FXCH (stack swap observed via FSTP dumps)
//!
//! Skipped ops (unsupported transcendentals / status word):
//! - FSTSW AX / FNSTSW AX: The architectural register file has no FPU status word
//!   register. Attempting to fabricate one would corrupt architectural invariants.
//! - FST st(i): XED decode quirk (rejected by XED or aliased to FNOP); FSTP st(i) is
//!   supported via FSTP_STI.
//! - FSIN, FCOS, FSINCOS, FPTAN, FPATAN, F2XM1, FYL2X, FYL2XP1, FSCALE:
//!   The IR and execution engine have no transcendental primitives.

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
    let dir = std::env::temp_dir().join(format!("angryier-x87ext-{name}-{}", std::process::id()));
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
    Stack,
    Mem16,
    Mem32,
    Mem64,
    Reg64,
    Reg32,
    Imm,
}

fn is_stack(view: &angryier_arch::RegisterView) -> bool {
    (register_id::X87_BASE..register_id::X87_BASE + 8).contains(&view.parent.0)
}

fn map_form(decoded: &angryier_arch::DecodedInstruction) -> Option<u32> {
    use xed_sys as xed;

    let explicit: Vec<&angryier_arch::Operand> = decoded
        .operands
        .iter()
        .filter(|op| op.visibility != OperandVisibility::Suppressed)
        .collect();
    let mut shapes = Vec::new();
    let mut mem = None;
    for op in &explicit {
        match &op.kind {
            OperandKind::Register(view) if is_stack(view) => shapes.push(Shape::Stack),
            OperandKind::Register(view) if view.width_bits == 64 => shapes.push(Shape::Reg64),
            OperandKind::Register(view) if view.width_bits == 32 => shapes.push(Shape::Reg32),
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
            ([Shape::Stack, Shape::Stack], _) => Some(forms::FLD_STI),
            (_, Some(Shape::Mem32)) => Some(forms::FLD_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FLD_M64),
            _ => None,
        },
        xed::XED_ICLASS_FST => match mem {
            Some(Shape::Mem32) => Some(forms::FST_M32),
            Some(Shape::Mem64) => Some(forms::FST_M64),
            _ => None,
        },
        xed::XED_ICLASS_FSTP | xed::XED_ICLASS_FSTPNCE => match (&shapes[..], mem) {
            ([Shape::Stack, Shape::Stack], _) => Some(forms::FSTP_STI),
            (_, Some(Shape::Mem32)) => Some(forms::FSTP_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FSTP_M64),
            _ => None,
        },
        // FCOM / FCOMP / FCOMPP
        xed::XED_ICLASS_FCOM => match (&shapes[..], mem) {
            (_, Some(Shape::Mem32)) => Some(forms::FCOM_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FCOM_M64),
            ([Shape::Stack, ..], _) | ([], _) => Some(forms::FCOM_STI),
            _ => None,
        },
        xed::XED_ICLASS_FCOMP => match (&shapes[..], mem) {
            (_, Some(Shape::Mem32)) => Some(forms::FCOMP_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FCOMP_M64),
            ([Shape::Stack, ..], _) | ([], _) => Some(forms::FCOMP_STI),
            _ => None,
        },
        xed::XED_ICLASS_FCOMPP => Some(forms::FCOMPP),
        // Integer arithmetic
        xed::XED_ICLASS_FIADD => match mem {
            Some(Shape::Mem16) => Some(forms::FIADD_M16),
            Some(Shape::Mem32) => Some(forms::FIADD_M32),
            _ => None,
        },
        xed::XED_ICLASS_FISUB => match mem {
            Some(Shape::Mem16) => Some(forms::FISUB_M16),
            Some(Shape::Mem32) => Some(forms::FISUB_M32),
            _ => None,
        },
        xed::XED_ICLASS_FISUBR => match mem {
            Some(Shape::Mem16) => Some(forms::FISUBR_M16),
            Some(Shape::Mem32) => Some(forms::FISUBR_M32),
            _ => None,
        },
        xed::XED_ICLASS_FIMUL => match mem {
            Some(Shape::Mem16) => Some(forms::FIMUL_M16),
            Some(Shape::Mem32) => Some(forms::FIMUL_M32),
            _ => None,
        },
        xed::XED_ICLASS_FIDIV => match mem {
            Some(Shape::Mem16) => Some(forms::FIDIV_M16),
            Some(Shape::Mem32) => Some(forms::FIDIV_M32),
            _ => None,
        },
        xed::XED_ICLASS_FIDIVR => match mem {
            Some(Shape::Mem16) => Some(forms::FIDIVR_M16),
            Some(Shape::Mem32) => Some(forms::FIDIVR_M32),
            _ => None,
        },
        xed::XED_ICLASS_FICOM => match mem {
            Some(Shape::Mem16) => Some(forms::FICOM_M16),
            Some(Shape::Mem32) => Some(forms::FICOM_M32),
            _ => None,
        },
        xed::XED_ICLASS_FICOMP => match mem {
            Some(Shape::Mem16) => Some(forms::FICOMP_M16),
            Some(Shape::Mem32) => Some(forms::FICOMP_M32),
            _ => None,
        },
        // Integer load/store
        xed::XED_ICLASS_FILD => match mem {
            Some(Shape::Mem16) => Some(forms::FILD_M16),
            Some(Shape::Mem32) => Some(forms::FILD_M32),
            Some(Shape::Mem64) => Some(forms::FILD_M64),
            _ => None,
        },
        xed::XED_ICLASS_FIST => match mem {
            Some(Shape::Mem16) => Some(forms::FIST_M16),
            Some(Shape::Mem32) => Some(forms::FIST_M32),
            _ => None,
        },
        xed::XED_ICLASS_FISTP => match mem {
            Some(Shape::Mem16) => Some(forms::FISTP_M16),
            Some(Shape::Mem32) => Some(forms::FISTP_M32),
            Some(Shape::Mem64) => Some(forms::FISTP_M64),
            _ => None,
        },
        // Sign, sqrt, exchange
        xed::XED_ICLASS_FABS => Some(forms::FABS),
        xed::XED_ICLASS_FCHS => Some(forms::FCHS),
        xed::XED_ICLASS_FSQRT => Some(forms::FSQRT),
        xed::XED_ICLASS_FXCH => match &shapes[..] {
            [] => Some(forms::FXCH),
            [Shape::Stack] | [Shape::Stack, Shape::Stack] => Some(forms::FXCH_STI),
            _ => Some(forms::FXCH),
        },
        // Harness plumbing forms
        xed::XED_ICLASS_MOV => match (&shapes[..], mem, mem_writes) {
            ([Shape::Reg64, Shape::Imm], _, _) => Some(forms::MOV_R64_IMM64),
            ([Shape::Reg64, Shape::Reg64], _, _) => Some(forms::MOV_R64_R64),
            ([Shape::Reg64], Some(Shape::Mem64), false) => Some(forms::MOV_R64_MEM64),
            ([Shape::Reg64], Some(Shape::Mem64), true) => Some(forms::MOV_MEM64_R64),
            ([Shape::Reg32], Some(Shape::Mem32), false) => Some(forms::MOV_R32_MEM32),
            ([Shape::Imm], Some(Shape::Mem32), true) => Some(forms::MOV_MEM32_IMM32),
            ([Shape::Imm], Some(Shape::Mem16), true) => Some(forms::MOV_MEM16_IMM16),
            _ => None,
        },
        xed::XED_ICLASS_MOVZX => match (&shapes[..], mem) {
            ([Shape::Reg64], Some(Shape::Mem16)) => Some(forms::MOVZX_R64_MEM16),
            ([Shape::Reg32], Some(Shape::Mem16)) => Some(forms::MOVZX_R32_MEM16),
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
    let rax_bytes = engine
        .memory
        .read(SCRATCH, 8)
        .map_err(|e| format!("dump read: {e:?}"))?
        .into_iter()
        .map(|b| match b {
            ByteValue::Concrete(v) => v,
            ByteValue::Symbolic { .. } => 0,
        })
        .collect::<Vec<u8>>();
    let flags_bytes = engine
        .memory
        .read(SCRATCH + 8, 8)
        .map_err(|e| format!("dump read: {e:?}"))?
        .into_iter()
        .map(|b| match b {
            ByteValue::Concrete(v) => v,
            ByteValue::Symbolic { .. } => 0,
        })
        .collect::<Vec<u8>>();
    let mut rax = [0u8; 8];
    rax.copy_from_slice(&rax_bytes);
    let mut flags = [0u8; 8];
    flags.copy_from_slice(&flags_bytes);
    Ok((u64::from_le_bytes(rax), u64::from_le_bytes(flags)))
}

fn differential_case(name: &str, body: &str) -> Result<bool, BoxError> {
    let Some(dir) = temp_dir(name) else {
        return Ok(false);
    };
    let src = dir.join("case.s");
    let obj = dir.join("case.o");
    let bin = dir.join("case");

    let assembly = harness_source(body);
    std::fs::write(&src, &assembly)?;

    if assemble(&src, &obj).is_none() {
        eprintln!("ASSEMBLE-FAIL {name}\n{assembly}");
        return Ok(false);
    }
    if link(&bin, &[&obj]).is_none() {
        eprintln!("LINK-FAIL {name}");
        return Ok(false);
    }
    let Some(code) = extract_text(&dir, &bin) else {
        return Ok(false);
    };
    let Some(native_out) = native_stdout(&bin) else {
        return Ok(false);
    };
    if native_out.len() < 16 {
        return Err(format!("native harness output too short: {} bytes", native_out.len()).into());
    }

    let mut native_rax_bytes = [0u8; 8];
    native_rax_bytes.copy_from_slice(&native_out[0..8]);
    let native_rax = u64::from_le_bytes(native_rax_bytes);

    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let (engine_rax, _) = run_engine(&code, &registry)?;

    if engine_rax != native_rax {
        return Err(format!(
            "differential mismatch on `{name}`: rax engine={engine_rax:#x} native={native_rax:#x}\nbody:\n{body}"
        )
        .into());
    }
    Ok(true)
}

fn seed64(slot: u64, bits: u64) -> String {
    format!("    movabs ${bits}, %rbx\n    mov %rbx, 0x{:x}\n", SCRATCH + 8 * slot)
}

fn seed32(slot: u64, bits: u32) -> String {
    format!("    movl ${bits}, 0x{:x}\n", SCRATCH + 8 * slot)
}

fn seed16(slot: u64, bits: u16) -> String {
    format!("    movw ${bits}, 0x{:x}\n", SCRATCH + 8 * slot)
}

fn observe(which: u32) -> String {
    format!("    mov 0x{:x}, %rax\n", SCRATCH + 0x40 + 8 * u64::from(which))
}

const OUT0: u64 = SCRATCH + 0x40;
const OUT1: u64 = SCRATCH + 0x48;

const F1_5: u64 = 0x3FF8_0000_0000_0000;
const F2_25N: u64 = 0xC002_0000_0000_0000;
const F2_5: u64 = 0x4004_0000_0000_0000;
const F100: u64 = 0x4059_0000_0000_0000;
const F0_5: u64 = 0x3FE0_0000_0000_0000;
const F4: u64 = 0x4010_0000_0000_0000;
const F0_25: u64 = 0x3FD0_0000_0000_0000;

#[test]
fn x87_ext_semantics_match_hardware() -> Result<(), BoxError> {
    let mut executed = 0usize;
    let mut skipped = false;
    let mut case = |name: &str, body: String| -> Result<(), BoxError> {
        let ran = differential_case(name, &body)?;
        skipped |= !ran;
        executed += usize::from(ran);
        Ok(())
    };

    // -----------------------------------------------------------------------
    // 1. FCOM / FCOMP / FCOMPP
    // -----------------------------------------------------------------------
    // FCOM ST(1): leaves stack intact; ST(0) and ST(1) preserved.
    case(
        "fcom_sti_stack_preserved",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fcom %st(1)\n    fstpl {OUT0:#x}\n    fstpl {OUT1:#x}\n    {}",
            seed64(0, F1_5),
            seed64(1, F2_5),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    // FCOM M32 / M64: compares against memory, leaves stack intact.
    case(
        "fcom_m32",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fcoms 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed32(0, 0x4000_0000), // 2.0f32
            SCRATCH + 8,
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fcom_m64",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fcoml 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            SCRATCH + 8,
            SCRATCH,
            observe(0)
        ),
    )?;
    // FCOMP ST(1): pops ST(0); ST(1) becomes new ST(0).
    case(
        "fcomp_sti_pops",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fcomp %st(1)\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            seed64(1, F2_5),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    // FCOMP M32 / M64: compares against memory and pops.
    case(
        "fcomp_m32_pops",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fcomps 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed32(0, 0x4000_0000),
            seed64(1, F4),
            SCRATCH + 16,
            SCRATCH + 8,
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fcomp_m64_pops",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fcompl 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            seed64(1, F100),
            SCRATCH + 16,
            SCRATCH + 8,
            SCRATCH,
            observe(0)
        ),
    )?;
    // FCOMPP: compares ST(0) and ST(1), pops twice.
    case(
        "fcompp_pops_twice",
        format!(
            "{}{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fcompp\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F100),
            seed64(1, F1_5),
            seed64(2, F2_5),
            SCRATCH,
            SCRATCH + 8,
            SCRATCH + 16,
            observe(0)
        ),
    )?;

    // -----------------------------------------------------------------------
    // 2. FIADD / FISUB / FISUBR / FIMUL / FIDIV / FIDIVR / FICOM / FICOMP
    // -----------------------------------------------------------------------
    // FIADD: m32 / m16 (positive, negative, large)
    case(
        "fiadd_m32_pos",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fiadds 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            seed32(1, 10),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fiadd_m32_neg",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fiadds 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            seed32(1, (-5i32) as u32),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fiadd_m32_large",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fiadds 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F0_5),
            seed32(1, 100_000),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fiadd_m16_neg",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fiadd 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F4),
            seed16(1, (-20i16) as u16),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;

    // FISUB / FISUBR
    case(
        "fisub_m32",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fisubs 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            seed32(1, 2),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fisub_m16_neg",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fisub 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            seed16(1, (-3i16) as u16),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fisubr_m32",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fisubrs 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            seed32(1, 10),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fisubr_m16",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fisubr 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            seed16(1, 5),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;

    // FIMUL
    case(
        "fimul_m32",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fimuls 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            seed32(1, 4),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fimul_m16_neg",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fimul 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            seed16(1, (-2i16) as u16),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;

    // FIDIV / FIDIVR
    case(
        "fidiv_m32",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fidivs 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F100),
            seed32(1, 4),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fidiv_m16_neg",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fidiv 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F4),
            seed16(1, (-2i16) as u16),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fidivr_m32",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fidivrs 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_5),
            seed32(1, 10),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "fidivr_m16",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fidivr 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F4),
            seed16(1, 12),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;

    // FICOM / FICOMP
    case(
        "ficom_m32",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    ficoms 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            seed32(1, 10),
            SCRATCH,
            SCRATCH + 8,
            observe(0)
        ),
    )?;
    case(
        "ficomp_m32_pops",
        format!(
            "{}{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    ficomps 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F4),
            seed64(1, F1_5),
            seed32(2, 10),
            SCRATCH,
            SCRATCH + 8,
            SCRATCH + 16,
            observe(0)
        ),
    )?;
    case(
        "ficomp_m16_pops",
        format!(
            "{}{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    ficomp 0x{:x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F100),
            seed64(1, F2_5),
            seed16(2, 5),
            SCRATCH,
            SCRATCH + 8,
            SCRATCH + 16,
            observe(0)
        ),
    )?;

    // -----------------------------------------------------------------------
    // 3. FILD / FISTP round-trips: 0, 1.5, -2.25, 1e10
    // -----------------------------------------------------------------------
    // Value 0: m32 round-trip
    case(
        "fild_fistp_0",
        format!(
            "{}    fninit\n    filds 0x{:x}\n    fistps {OUT0:#x}\n    movl {OUT0:#x}, %eax\n",
            seed32(0, 0),
            SCRATCH
        ),
    )?;
    // Value 1.5: load f64 1.5, store to int32 (rounds to 2), load int32, store to OUT0
    case(
        "fild_fistp_1_5",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fistps {OUT0:#x}\n    filds {OUT0:#x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            SCRATCH,
            observe(0)
        ),
    )?;
    // Value -2.25: load f64 -2.25, store to int32 (rounds to -2), load int32, store to OUT0
    case(
        "fild_fistp_neg2_25",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fistps {OUT0:#x}\n    filds {OUT0:#x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_25N),
            SCRATCH,
            observe(0)
        ),
    )?;
    // Value 1e10: 64-bit integer load/store round-trip
    case(
        "fild_fistp_1e10",
        format!(
            "{}    fninit\n    fildq 0x{:x}\n    fistpq {OUT0:#x}\n    fildq {OUT0:#x}\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, 10_000_000_000u64),
            SCRATCH,
            observe(0)
        ),
    )?;
    // 16-bit integer load/store round trip
    case(
        "fild_fistp_m16",
        format!(
            "{}    fninit\n    fild 0x{:x}\n    fistp {OUT0:#x}\n    movzwl {OUT0:#x}, %eax\n",
            seed16(0, 42),
            SCRATCH
        ),
    )?;

    // -----------------------------------------------------------------------
    // 4. FABS / FCHS / FSQRT
    // -----------------------------------------------------------------------
    case(
        "fabs_neg",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fabs\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_25N),
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fabs_pos",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fabs\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fchs_pos",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fchs\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F1_5),
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fchs_neg",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fchs\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F2_25N),
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fsqrt_4",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fsqrt\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F4),
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fsqrt_0_25",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fsqrt\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F0_25),
            SCRATCH,
            observe(0)
        ),
    )?;
    case(
        "fsqrt_100",
        format!(
            "{}    fninit\n    fldl 0x{:x}\n    fsqrt\n    fstpl {OUT0:#x}\n    {}",
            seed64(0, F100),
            SCRATCH,
            observe(0)
        ),
    )?;

    // -----------------------------------------------------------------------
    // 5. FXCH
    // -----------------------------------------------------------------------
    // FXCH default (ST(0) <-> ST(1))
    case(
        "fxch_default",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fxch\n    fstpl {OUT0:#x}\n    fstpl {OUT1:#x}\n    {}",
            seed64(0, F1_5),
            seed64(1, F2_5),
            SCRATCH,
            SCRATCH + 8,
            observe(0) // Should observe F1_5 at OUT0 (was at ST(1) before fxch)
        ),
    )?;
    case(
        "fxch_default_out1",
        format!(
            "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fxch\n    fstpl {OUT0:#x}\n    fstpl {OUT1:#x}\n    {}",
            seed64(0, F1_5),
            seed64(1, F2_5),
            SCRATCH,
            SCRATCH + 8,
            observe(1) // Should observe F2_5 at OUT1 (was at ST(0) before fxch)
        ),
    )?;
    // FXCH ST(2): swap ST(0) and ST(2)
    case(
        "fxch_st2",
        format!(
            "{}{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fldl 0x{:x}\n    fxch %st(2)\n    fstpl {OUT0:#x}\n    fstpl {OUT1:#x}\n    {}",
            seed64(0, F100),
            seed64(1, F2_5),
            seed64(2, F1_5),
            SCRATCH,
            SCRATCH + 8,
            SCRATCH + 16,
            observe(0) // Should observe F100 at OUT0 (swapped from ST(2))
        ),
    )?;

    assert!(!skipped, "differential harness skipped native execution");
    assert!(executed >= 30, "expected at least 30 cases, executed {executed}");
    Ok(())
}
