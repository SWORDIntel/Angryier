#![forbid(unsafe_code)]

//! Hardware differential oracle for the x87 semantic family.
//!
//! Every x87 corpus form must answer to the host CPU: each case assembles a
//! real program (binutils), runs it natively to capture `[rax, rflags]` from
//! silicon, then decodes the same instruction bytes with native XED, maps the
//! iclass/operand shapes onto corpus form ids, and executes through the full
//! provider -> seal -> lower -> concrete-interpreter pipeline. The result
//! register must match byte-for-byte and RFLAGS must match on the
//! architecturally defined bits.
//!
//! This is the same gate as the runtime's `differential_semantics_vs_hardware`,
//! driven from the semantics crate because the runtime's iclass->form map
//! (`form_map.rs`) does not cover x87 yet. The iclass->form translation below
//! is the blueprint for those runtime entries.
//!
//! The harness places code at 0x10000 and scratch data at 0x500000 through
//! linker flags so the engine driver can host the same bytes with flat memory
//! regions, and every template ends by loading its result into %rax — the
//! only register both worlds observe.

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

const ZF: u64 = 1 << 6;
const PF: u64 = 1 << 2;
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
    let dir = std::env::temp_dir().join(format!("angryier-x87-{name}-{}", std::process::id()));
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

/// Wraps the x87 body: after it runs, `[rax, rflags]` land in the scratch
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
    /// An x87 stack register (80-bit view of an X87_BASE parent).
    Stack,
    Mem32,
    Mem64,
    Reg64,
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
            OperandKind::Memory(_) => {
                mem = Some(match op.width_bits {
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
        // XED reports the register-destination FSTP encoding (D9 D8+i) as
        // FSTPNCE; both iclasses route to the same corpus form.
        xed::XED_ICLASS_FSTP | xed::XED_ICLASS_FSTPNCE => match (&shapes[..], mem) {
            ([Shape::Stack, Shape::Stack], _) => Some(forms::FSTP_STI),
            (_, Some(Shape::Mem32)) => Some(forms::FSTP_M32),
            (_, Some(Shape::Mem64)) => Some(forms::FSTP_M64),
            _ => None,
        },
        iclass @ (xed::XED_ICLASS_FADD
        | xed::XED_ICLASS_FSUB
        | xed::XED_ICLASS_FSUBR
        | xed::XED_ICLASS_FMUL
        | xed::XED_ICLASS_FDIV
        | xed::XED_ICLASS_FDIVR) => {
            let (st0_dst, sti_dst, m32, m64) = match iclass {
                xed::XED_ICLASS_FADD => (
                    forms::FADD_ST0_STI,
                    forms::FADD_STI_ST0,
                    forms::FADD_M32,
                    forms::FADD_M64,
                ),
                xed::XED_ICLASS_FSUB => (
                    forms::FSUB_ST0_STI,
                    forms::FSUB_STI_ST0,
                    forms::FSUB_M32,
                    forms::FSUB_M64,
                ),
                xed::XED_ICLASS_FSUBR => (
                    forms::FSUBR_ST0_STI,
                    forms::FSUBR_STI_ST0,
                    forms::FSUBR_M32,
                    forms::FSUBR_M64,
                ),
                xed::XED_ICLASS_FMUL => (
                    forms::FMUL_ST0_STI,
                    forms::FMUL_STI_ST0,
                    forms::FMUL_M32,
                    forms::FMUL_M64,
                ),
                xed::XED_ICLASS_FDIV => (
                    forms::FDIV_ST0_STI,
                    forms::FDIV_STI_ST0,
                    forms::FDIV_M32,
                    forms::FDIV_M64,
                ),
                _ => (
                    forms::FDIVR_ST0_STI,
                    forms::FDIVR_STI_ST0,
                    forms::FDIVR_M32,
                    forms::FDIVR_M64,
                ),
            };
            // Operand 0 names the destination: st(0) for the D8 encodings,
            // st(i) for the DC encodings.
            let dst_is_st0 = match decoded.operands.first().map(|op| &op.kind) {
                Some(OperandKind::Register(view)) => view.parent.0 == register_id::X87_BASE,
                _ => return None,
            };
            match (&shapes[..], mem) {
                ([Shape::Stack, Shape::Stack], _) => Some(if dst_is_st0 { st0_dst } else { sti_dst }),
                (_, Some(Shape::Mem32)) => Some(m32),
                (_, Some(Shape::Mem64)) => Some(m64),
                _ => None,
            }
        }
        xed::XED_ICLASS_FUCOMI => Some(forms::FUCOMI_ST0_STI),
        xed::XED_ICLASS_FUCOMIP => Some(forms::FUCOMIP_ST0_STI),
        xed::XED_ICLASS_FCOMI => Some(forms::FCOMI_ST0_STI),
        xed::XED_ICLASS_FCOMIP => Some(forms::FCOMIP_ST0_STI),
        // Plumbing forms the harness itself needs.
        xed::XED_ICLASS_MOV => match (&shapes[..], mem, mem_writes) {
            ([Shape::Reg64, Shape::Imm], _, _) => Some(forms::MOV_R64_IMM64),
            ([Shape::Reg64, Shape::Reg64], _, _) => Some(forms::MOV_R64_R64),
            ([Shape::Reg64], Some(Shape::Mem64), false) => Some(forms::MOV_R64_MEM64),
            ([Shape::Reg64], Some(Shape::Mem64), true) => Some(forms::MOV_MEM64_R64),
            ([Shape::Imm], Some(Shape::Mem32), true) => Some(forms::MOV_MEM32_IMM32),
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
    let (engine_rax, engine_rbx) =
        run_engine(&code, &registry).map_err(|e| format!("case `{name}`: {e}\nbody:\n{body}"))?;

    let native_rax = u64::from_le_bytes(expected[..8].try_into()?);
    let native_flags = u64::from_le_bytes(expected[8..16].try_into()?);
    if engine_rax != native_rax {
        return Err(format!(
            "differential mismatch on `{name}`: rax engine={engine_rax:#x} native={native_rax:#x}\nbody:\n{body}"
        )
        .into());
    }
    if engine_rbx & flag_mask != native_flags & flag_mask {
        return Err(format!(
            "differential flag mismatch on `{name}`: engine={engine_rbx:#x} native={native_flags:#x} mask={flag_mask:#x}\nbody:\n{body}"
        )
        .into());
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Templates
// ---------------------------------------------------------------------------

/// Seeds a 64-bit scratch qword at `SCRATCH + 8*slot`.
fn seed64(slot: u64, bits: u64) -> String {
    format!("    movabs ${bits}, %rbx\n    mov %rbx, 0x{:x}\n", SCRATCH + 8 * slot)
}

/// Seeds a 32-bit scratch word at `SCRATCH + 8*slot`.
fn seed32(slot: u64, bits: u32) -> String {
    format!("    movl ${bits}, 0x{:x}\n", SCRATCH + 8 * slot)
}

/// Loads the dumped result qword `which` (0 or 1) into %rax.
fn observe(which: u32) -> String {
    format!("    mov 0x{:x}, %rax\n", SCRATCH + 0x40 + 8 * u64::from(which))
}

const OUT0: u64 = SCRATCH + 0x40;
const OUT1: u64 = SCRATCH + 0x48;

// f64 bit patterns chosen so every modeled operation is exact in both the
// engine's 64-bit payload and the CPU's 80-bit intermediate: all values are
// small-mantissa dyadic rationals, so sums, products, and quotients are exact
// in 64 significand bits and no double rounding can diverge.
const F1_5: u64 = 0x3FF8_0000_0000_0000;
const F2_25N: u64 = 0xC002_0000_0000_0000;
const F2_5: u64 = 0x4004_0000_0000_0000;
const F100: u64 = 0x4059_0000_0000_0000;
const F0_5: u64 = 0x3FE0_0000_0000_0000;
const F4: u64 = 0x4010_0000_0000_0000;
const F0_25: u64 = 0x3FD0_0000_0000_0000;
const QNAN: u64 = 0x7FF8_0000_0000_0000;
const SEEDS_A: [u64; 4] = [F1_5, F2_25N, F2_5, F100];
const SEEDS_B: [u64; 3] = [F0_5, F4, F0_25];

/// Gate D: the x87 semantic family against hardware. Result values must
/// match byte-for-byte; FCOMI-family cases also compare the defined ZF/PF/CF.
#[test]
fn x87_semantics_match_hardware() -> Result<(), BoxError> {
    let mut executed = 0usize;
    let mut skipped = false;
    let case =
        |name: String, body: String, mask: u64, executed: &mut usize, skipped: &mut bool| -> Result<(), BoxError> {
            let ran = differential_case(&name, &body, mask)?;
            *skipped |= !ran;
            *executed += usize::from(ran);
            Ok(())
        };

    // Memory round trips in every width combination. `fninit` first: the
    // engine starts with all slots valid-zero while silicon starts empty.
    for (name, load, store) in [
        ("fldl_fstpl", format!("fldl 0x{SCRATCH:x}"), format!("fstpl {OUT0}")),
        ("flds_fstpl", format!("flds 0x{SCRATCH:x}"), format!("fstpl {OUT0}")),
        ("fldl_fstps", format!("fldl 0x{SCRATCH:x}"), format!("fstps {OUT0}")),
        ("fldl_fstl", format!("fldl 0x{SCRATCH:x}"), format!("fstl {OUT0}")),
        ("fldl_fsts", format!("fldl 0x{SCRATCH:x}"), format!("fsts {OUT0}")),
    ] {
        for &bits in &SEEDS_A {
            let full = format!(
                "{}    fninit\n    {}\n    {}\n    {}\n",
                seed64(0, bits),
                load,
                store,
                observe(0)
            );
            case(format!("{name}_{bits:x}"), full, 0, &mut executed, &mut skipped)?;
        }
    }
    // 32-bit loads with genuine f32 seeds.
    for &bits in &[0x3FC0_0000u32, 0xC020_0000u32, 0x42C8_0000u32] {
        let full = format!(
            "{}    fninit\n    flds 0x{:x}\n    fstpl {OUT0}\n    {}\n",
            seed32(0, bits),
            SCRATCH,
            observe(0)
        );
        case(format!("flds_f32_{bits:x}"), full, 0, &mut executed, &mut skipped)?;
    }

    // Stack movement: constants, st(i) duplication, FSTP st(i) destinations.
    for (name, body, observers) in [
        ("fld1", format!("fninit\n    fld1\n    fstpl {OUT0}"), vec![0u32]),
        ("fldz", format!("fninit\n    fldz\n    fstpl {OUT0}"), vec![0u32]),
        (
            "fld_st1",
            format!(
                "fninit\n    fld1\n    fldl {}\n    fld %st(1)\n    fstpl {OUT0}\n    fstpl {OUT1}",
                SCRATCH
            ),
            vec![0, 1],
        ),
        (
            "fstp_st1",
            format!(
                "fninit\n    fld1\n    fldl {}\n    fstp %st(1)\n    fstpl {OUT0}\n    fstpl {OUT1}",
                SCRATCH
            ),
            vec![0, 1],
        ),
        (
            "fstp_st2",
            format!(
                "fninit\n    fld1\n    fldl {}\n    fldl {}\n    fstp %st(2)\n    fstpl {OUT0}\n    fstpl {OUT1}",
                SCRATCH,
                SCRATCH + 8
            ),
            vec![0, 1],
        ),
    ] {
        for which in observers {
            for &bits in &SEEDS_A[..3] {
                let full = format!("{}    {}\n    {}\n", seed64(0, bits), body, observe(which));
                case(
                    format!("{name}_{bits:x}_obs{which}"),
                    full,
                    0,
                    &mut executed,
                    &mut skipped,
                )?;
            }
        }
    }

    // Empty-stack behavior after fninit: masked silicon stores the m64 real
    // indefinite (0xFFF8000000000000); the engine must agree byte-for-byte.
    for (name, body) in [
        ("finit_fstpl_empty", format!("fninit\n    fstpl {OUT0}")),
        ("finit_fstl_empty", format!("fninit\n    fstl {OUT0}")),
        ("finit_fstps_empty", format!("fninit\n    fstps {OUT0}")),
    ] {
        let full = format!("    {}\n    {}\n", body, observe(0));
        case(name.to_string(), full, 0, &mut executed, &mut skipped)?;
    }

    // Arithmetic, two-register forms; AT&T operand order and the reversed
    // R-forms are pinned by what silicon actually computes.
    for (name, op) in [
        ("fadd_st0_sti", "fadd %st(1), %st"),
        ("fadd_sti_st0", "fadd %st, %st(1)"),
        ("fsub_st0_sti", "fsub %st(1), %st"),
        ("fsub_sti_st0", "fsub %st, %st(1)"),
        ("fsubr_st0_sti", "fsubr %st(1), %st"),
        ("fsubr_sti_st0", "fsubr %st, %st(1)"),
        ("fmul_st0_sti", "fmul %st(1), %st"),
        ("fmul_sti_st0", "fmul %st, %st(1)"),
        ("fdiv_st0_sti", "fdiv %st(1), %st"),
        ("fdiv_sti_st0", "fdiv %st, %st(1)"),
        ("fdivr_st0_sti", "fdivr %st(1), %st"),
        ("fdivr_sti_st0", "fdivr %st, %st(1)"),
    ] {
        for &a in &SEEDS_A {
            for &b in &SEEDS_B {
                for which in [0u32, 1] {
                    let full = format!(
                        "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    {}\n    fstpl {OUT0}\n    fstpl {OUT1}\n    {}\n",
                        seed64(0, a),
                        seed64(1, b),
                        SCRATCH,
                        SCRATCH + 8,
                        op,
                        observe(which)
                    );
                    case(
                        format!("{name}_{a:x}_{b:x}_obs{which}"),
                        full,
                        0,
                        &mut executed,
                        &mut skipped,
                    )?;
                }
            }
        }
    }

    // Arithmetic, memory forms.
    for (name, op) in [
        ("fadds", "fadds"),
        ("faddl", "faddl"),
        ("fsubs", "fsubs"),
        ("fsubl", "fsubl"),
        ("fsubrs", "fsubrs"),
        ("fsubrl", "fsubrl"),
        ("fmuls", "fmuls"),
        ("fmull", "fmull"),
        ("fdivs", "fdivs"),
        ("fdivl", "fdivl"),
        ("fdivrs", "fdivrs"),
        ("fdivrl", "fdivrl"),
    ] {
        // m64 forms sweep the f64 seed pairs. The m32 forms run only on the
        // genuine f32 seeds below: an f64 seed's low word is +0.0, and the
        // interpreter rejects float division by zero (x87 would produce an
        // infinity), so the m32 sweep would not be honest coverage.
        let is_m32 = name.ends_with('s');
        if !is_m32 {
            for &a in &SEEDS_A {
                for &b in &SEEDS_B {
                    let full = format!(
                        "{}{}    fninit\n    fldl 0x{:x}\n    {} 0x{:x}\n    fstpl {OUT0}\n    {}\n",
                        seed64(0, a),
                        seed64(16, b),
                        SCRATCH,
                        op,
                        SCRATCH + 0x80,
                        observe(0)
                    );
                    case(format!("{name}_{a:x}_{b:x}"), full, 0, &mut executed, &mut skipped)?;
                }
            }
        }
        // Genuine f32 memory operands (exact widening into the 64-bit model).
        for &bits in &[0x3F000000u32, 0x3FC00000u32, 0x3F400000u32] {
            let full = format!(
                "{}    movl ${bits}, 0x{:x}\n    fninit\n    fldl 0x{:x}\n    {} 0x{:x}\n    fstpl {OUT0}\n    {}\n",
                seed64(0, F1_5),
                SCRATCH + 0x80,
                SCRATCH,
                op,
                SCRATCH + 0x80,
                observe(0)
            );
            case(format!("{name}_f32_{bits:x}"), full, 0, &mut executed, &mut skipped)?;
        }
    }

    // FCOMI family: ZF/PF/CF compared on the defined bits; the stack stores
    // continue so pop behavior stays observable.
    for (name, op, extra_pop) in [
        ("fcomi", "fcomi %st(1), %st", 1u32),
        ("fcomip", "fcomip %st(1), %st", 0),
        ("fucomi", "fucomi %st(1), %st", 1),
        ("fucomip", "fucomip %st(1), %st", 0),
    ] {
        for &(a, b) in &[
            (F2_5, F2_5), // equal
            (F1_5, F2_5), // less
            (F100, F2_5), // greater
            (QNAN, F2_5), // unordered
        ] {
            let mut body = format!(
                "{}{}    fninit\n    fldl 0x{:x}\n    fldl 0x{:x}\n    {}\n    fstpl {OUT0}\n",
                seed64(0, a),
                seed64(1, b),
                SCRATCH,
                SCRATCH + 8,
                op
            );
            if extra_pop > 0 {
                body.push_str(&format!("    fstpl {OUT1}\n"));
            }
            body.push_str(&observe(0));
            body.push('\n');
            case(
                format!("{name}_{a:x}_{b:x}"),
                body,
                ZF | PF | CF,
                &mut executed,
                &mut skipped,
            )?;
        }
    }

    if skipped && executed == 0 {
        eprintln!("skipping x87 differential: binutils unavailable");
        return Ok(());
    }
    eprintln!("x87 differential oracle: {executed} cases matched hardware byte-for-byte");
    assert!(executed > 150, "expected >150 x87 differential cases, ran {executed}");
    Ok(())
}
