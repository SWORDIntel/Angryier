#![forbid(unsafe_code)]

//! Native differential oracle for the EVEX.128/EVEX.256 packed single-precision
//! forms (VADDPS, VSUBPS, VMULPS, VDIVPS).
//!
//! The corpus has no ZMM move or KMOV semantics yet, so the native binary is
//! used purely as an arithmetic/masking oracle: it seeds registers with
//! `vmovdqu64`/`kmovw`, executes the instruction under test, and dumps the full
//! 64-byte ZMM destination. The semantic engine executes only the extracted
//! instruction bytes with the identical vector/mask/memory state seeded
//! directly, going through the real XED decode → form map → registry →
//! provider → lowerer → concrete interpreter pipeline.
//!
//! Even without an AVX-512-capable host the engine output is still checked
//! against a Rust oracle, so regressions are caught everywhere; native
//! execution additionally requires AVX512F+AVX512VL (EVEX.128/256 forms are
//! VL-gated) and is skipped cleanly otherwise.

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
use angryier_semantics_intel64::{Intel64CorpusRegistry, evex_forms};
use angryier_state::{ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState};
use angryier_types::{
    BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, ObjectId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};
use std::path::{Path, PathBuf};
use std::process::Command;

const CODE_BASE: u64 = 0x400000;
const SCRATCH: u64 = 0x500000;
const SRC2_ADDR: u64 = SCRATCH + 0x40;
const RESULT: u64 = SCRATCH + 0x180;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(3);

const ZMM0: u32 = register_id::ZMM_BASE;
const ZMM1: u32 = register_id::ZMM_BASE + 1;
const ZMM2: u32 = register_id::ZMM_BASE + 2;
const K2: u32 = register_id::OPMASK_BASE + 2;

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
    let dir = std::env::temp_dir().join(format!("angryier-evex-{name}-{}", std::process::id()));
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

fn extract_text(object: &Path, out: &Path) -> Option<Vec<u8>> {
    let output = Command::new("objcopy")
        .arg("--dump-section")
        .arg(format!(".text={}", out.display()))
        .arg(object)
        .arg("/dev/null")
        .output()
        .ok()?;
    output.status.success().then(|| std::fs::read(out).ok()).flatten()
}

/// Assembles a single instruction and returns its machine bytes (the `.text`
/// section of a one-instruction object).
fn assemble_one(dir: &Path, name: &str, instruction: &str) -> Option<Vec<u8>> {
    let source = dir.join(format!("{name}.s"));
    let object = dir.join(format!("{name}.o"));
    std::fs::write(
        &source,
        format!("        .text\n        .global _start\n_start:\n    {instruction}\n"),
    )
    .ok()?;
    assemble(&source, &object)?;
    extract_text(&object, &dir.join(format!("{name}.text")))
}

/// True when the host can execute EVEX.128/256 packed-single encodings
/// (AVX512F plus the vector-length extension AVX512VL).
fn host_has_avx512() -> bool {
    let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") else {
        return false;
    };
    let flags = cpuinfo
        .lines()
        .find(|line| line.starts_with("flags"))
        .map(str::to_owned)
        .unwrap_or_default();
    flags.split_whitespace().any(|f| f == "avx512f") && flags.split_whitespace().any(|f| f == "avx512vl")
}

// ---------------------------------------------------------------------------
// Engine side: decode the extracted instruction bytes, map, emit, lower,
// execute once, and return the full 64-byte ZMM0 image.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reg64,
    Mem128,
    Mem,
    Xmm,
    Ymm,
}

fn shape_of(operand: &angryier_arch::Operand) -> Option<Shape> {
    match &operand.kind {
        OperandKind::Register(view) if view.width_bits == 64 => Some(Shape::Reg64),
        OperandKind::Register(view) if view.width_bits == 128 => Some(Shape::Xmm),
        OperandKind::Register(view) if view.width_bits == 256 => Some(Shape::Ymm),
        OperandKind::Memory(_) if operand.width_bits == 128 => Some(Shape::Mem128),
        OperandKind::Memory(_) if operand.width_bits == 256 => Some(Shape::Mem),
        _ => None,
    }
}

/// Mirrors `angryier_runtime::form_map` for the four EVEX packed-single
/// iclasses (the test crate cannot depend on the runtime crate). Broadcast
/// `{1to4}`/`{1to8}` decodings report a 32-bit memory operand and fall
/// through unmapped, exactly like the runtime map.
fn map_form(decoded: &angryier_arch::DecodedInstruction) -> Option<u32> {
    use xed_sys as xed;
    let shapes = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility != OperandVisibility::Suppressed)
        .map(shape_of)
        .collect::<Option<Vec<_>>>()?;
    let unmasked_memory = decoded.operands.get(1).is_some_and(|operand| {
        matches!(
            &operand.kind,
            OperandKind::Register(register) if register.parent.0 == register_id::OPMASK_BASE
        )
    });
    match decoded.form_id {
        xed::XED_ICLASS_VADDPS => match shapes.as_slice() {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VADDPS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] if unmasked_memory => {
                Some(evex_forms::VADDPS_EVEX_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VADDPS_EVEX_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] if unmasked_memory => {
                Some(evex_forms::VADDPS_EVEX_YMM_YMM_MEM)
            }
            _ => None,
        },
        xed::XED_ICLASS_VSUBPS => match shapes.as_slice() {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VSUBPS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] if unmasked_memory => {
                Some(evex_forms::VSUBPS_EVEX_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VSUBPS_EVEX_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] if unmasked_memory => {
                Some(evex_forms::VSUBPS_EVEX_YMM_YMM_MEM)
            }
            _ => None,
        },
        xed::XED_ICLASS_VMULPS => match shapes.as_slice() {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VMULPS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] if unmasked_memory => {
                Some(evex_forms::VMULPS_EVEX_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VMULPS_EVEX_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] if unmasked_memory => {
                Some(evex_forms::VMULPS_EVEX_YMM_YMM_MEM)
            }
            _ => None,
        },
        xed::XED_ICLASS_VDIVPS => match shapes.as_slice() {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VDIVPS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] if unmasked_memory => {
                Some(evex_forms::VDIVPS_EVEX_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VDIVPS_EVEX_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] if unmasked_memory => {
                Some(evex_forms::VDIVPS_EVEX_YMM_YMM_MEM)
            }
            _ => None,
        },
        _ => None,
    }
}

struct Seeds {
    dst: [u8; 64],
    left: [u8; 64],
    right: [u8; 64],
    k2: Option<u64>,
}

fn engine_run(code: &[u8], seeds: &Seeds) -> Result<[u8; 64], BoxError> {
    let registry = Intel64CorpusRegistry::new(SEMANTIC_VERSION);
    let decoder = XedDecoder::new();
    let decoded = decoder
        .decode(CODE_BASE, code)
        .map_err(|error| format!("decode: {error:?}"))?;
    let form = map_form(&decoded).ok_or_else(|| format!("unmapped iclass {}", decoded.form_id))?;
    let provider = registry
        .provider_for_form(form)
        .ok_or_else(|| format!("no provider for form {form:#x}"))?;

    let registers = PersistentRegisters::from_widths(
        Intel64RegisterFile::canonical()
            .architectural_registers
            .iter()
            .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
    )
    .map_err(|error| format!("register file: {error:?}"))?;
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
    ])?;
    let code_bytes: Vec<ByteValue> = code.iter().map(|b| ByteValue::Concrete(*b)).collect();
    let mut memory = memory
        .write(CODE_BASE, &code_bytes)
        .map_err(|error| format!("code load: {error:?}"))?;
    let src2_bytes: Vec<ByteValue> = seeds.right.iter().map(|b| ByteValue::Concrete(*b)).collect();
    memory = memory
        .write(SRC2_ADDR, &src2_bytes)
        .map_err(|error| format!("src2 load: {error:?}"))?;

    let mut state = ExecutionState {
        id: StateId(1),
        parent: None,
        target_profile: TARGET_PROFILE,
        registers,
        memory,
        constraints: PersistentConstraintLineage::new(),
        ownership: angryier_state::StateOwnership::default(),
        fidelity: FidelityLedger::new(FidelityProfile::Prove),
    };
    state
        .registers
        .write_in_place(ZMM0, &seeds.dst)
        .map_err(|error| format!("zmm0 seed: {error:?}"))?;
    state
        .registers
        .write_in_place(ZMM1, &seeds.left)
        .map_err(|error| format!("zmm1 seed: {error:?}"))?;
    state
        .registers
        .write_in_place(ZMM2, &seeds.right)
        .map_err(|error| format!("zmm2 seed: {error:?}"))?;
    if let Some(mask) = seeds.k2 {
        state
            .registers
            .write_in_place(K2, &mask.to_le_bytes())
            .map_err(|error| format!("k2 seed: {error:?}"))?;
    }

    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|error| format!("emit form {form:#x}: {error:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|error| format!("seal form {form:#x}: {error:?}"))?;
    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(2),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))?,
    };
    let ir = BasicSemanticLowerer.lower_with_decode(&sealed, &key, &decoded)?;
    state
        .registers
        .write_in_place(register_id::RIP.0, &decoded.address.to_le_bytes())
        .map_err(|error| format!("rip: {error:?}"))?;
    let (executed, outcome) = ConcreteInterpreter::new().execute_block(&state, &ir, ExecutionMode::Concrete)?;
    match outcome {
        ExecutionOutcome::Continue { next_pc, .. } => {
            if next_pc != CODE_BASE + u64::from(decoded.length) {
                return Err(format!("next_pc {next_pc:#x} did not fall through").into());
            }
        }
        other => return Err(format!("unexpected outcome {other:?}").into()),
    }
    let bytes = executed
        .registers
        .read(ZMM0)
        .map_err(|error| format!("zmm0 read: {error:?}"))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[..64]);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Native side: a static binary that seeds the same state with real
// instructions, executes the instruction under test, and writes 64 bytes.
// ---------------------------------------------------------------------------

fn native_source(instruction: &str, seeds: &Seeds, mask: Option<u64>) -> String {
    let mut body = String::from("        .global _start\n        .text\n_start:\n");
    for (base, values) in [
        (SCRATCH, &seeds.left),
        (SRC2_ADDR, &seeds.right),
        (SCRATCH + 0x80, &seeds.dst),
    ] {
        for (index, qword) in values.as_chunks::<8>().0.iter().enumerate() {
            let qword = u64::from_le_bytes(*qword);
            body.push_str(&format!(
                "    movabs ${qword:#x}, %rax\n    mov %rax, {:#x}\n",
                base + (index as u64 * 8)
            ));
        }
    }
    body.push_str(&format!(
        "    vmovdqu64 {SCRATCH:#x}, %zmm1\n    vmovdqu64 {SRC2_ADDR:#x}, %zmm2\n    vmovdqu64 {:#x}, %zmm0\n",
        SCRATCH + 0x80
    ));
    if let Some(mask) = mask {
        body.push_str(&format!("    mov ${mask:#x}, %eax\n    kmovw %eax, %k2\n"));
    }
    body.push_str(&format!(
        "    {instruction}\n    vmovdqu64 %zmm0, {RESULT:#x}\n    mov $1, %rax\n    mov $1, %rdi\n    mov ${RESULT:#x}, %rsi\n    mov $64, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\n        .space 0x400\n"
    ));
    body
}

fn native_run(dir: &Path, name: &str, source: &str) -> Result<[u8; 64], BoxError> {
    let src = dir.join(format!("{name}.s"));
    let obj = dir.join(format!("{name}.o"));
    let bin = dir.join(name);
    std::fs::write(&src, source)?;
    if assemble(&src, &obj).is_none() || link(&bin, &obj).is_none() {
        return Err("assemble/link failed".into());
    }
    let out = Command::new(&bin).output()?;
    if !out.status.success() {
        return Err(format!("native exited {}", out.status).into());
    }
    out.stdout.try_into().map_err(|_| "native wrote wrong length".into())
}

// ---------------------------------------------------------------------------
// Rust oracle: op lane-wise + opmask merge/zero + upper-lane zeroing.
// ---------------------------------------------------------------------------

fn oracle(op: char, vl_lanes: usize, mask: Option<u64>, zeroing: bool, seeds: &Seeds) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..16 {
        let lane = &mut out[i * 4..i * 4 + 4];
        let result: [u8; 4] = if i >= vl_lanes {
            0.0f32.to_le_bytes()
        } else {
            let enabled = mask.map_or(true, |m| (m >> i) & 1 == 1);
            if enabled {
                let l = f32::from_le_bytes(seeds.left[i * 4..i * 4 + 4].try_into().unwrap());
                let r = f32::from_le_bytes(seeds.right[i * 4..i * 4 + 4].try_into().unwrap());
                match op {
                    '+' => l + r,
                    '-' => l - r,
                    '*' => l * r,
                    '/' => l / r,
                    _ => unreachable!(),
                }
                .to_le_bytes()
            } else if zeroing {
                0.0f32.to_le_bytes()
            } else {
                seeds.dst[i * 4..i * 4 + 4].try_into().unwrap()
            }
        };
        lane.copy_from_slice(&result);
    }
    out
}

fn f32_seeds() -> Seeds {
    let mut seeds = Seeds {
        dst: [0u8; 64],
        left: [0u8; 64],
        right: [0u8; 64],
        k2: None,
    };
    for i in 0..16usize {
        let dst = 100.0f32 + i as f32;
        let left = if i % 4 == 3 { -(i as f32 + 1.0) } else { i as f32 + 1.0 };
        let right = if i % 5 == 4 { -2.0f32 } else { i as f32 + 2.0 };
        seeds.dst[i * 4..i * 4 + 4].copy_from_slice(&dst.to_le_bytes());
        seeds.left[i * 4..i * 4 + 4].copy_from_slice(&left.to_le_bytes());
        seeds.right[i * 4..i * 4 + 4].copy_from_slice(&right.to_le_bytes());
    }
    seeds
}

#[derive(Clone)]
struct Case {
    name: String,
    mnemonic: &'static str,
    opcode: u8,
    op: char,
    ymm: bool,
    mem: bool,
    mask: Option<u64>,
    zeroing: bool,
}

fn instruction(case: &Case) -> String {
    // GAS encodes unmasked xmm/ymm `v*ps` as VEX and rejects `{%k0}` (k0 is not
    // a legal writemask), so the true unmasked EVEX encoding (EVEX aaa=000) is
    // emitted as raw bytes. Masked forms assemble normally.
    let Some(_) = case.mask else {
        let p2 = if case.ymm { 0x28 } else { 0x08 };
        let tail = if case.mem {
            // modrm 0x04 (SIB), sib 0x25 (disp32), disp 0x00500040 LE
            ",0x04,0x25,0x40,0x00,0x50,0x00"
        } else {
            ",0xc2"
        };
        return format!(".byte 0x62,0xf1,0x74,{p2:#x},{:#x}{tail}", case.opcode);
    };
    let suffix = if case.zeroing { "{%k2}{z}" } else { "{%k2}" };
    let (w1, w0) = if case.ymm {
        ("%ymm1", "%ymm0")
    } else {
        ("%xmm1", "%xmm0")
    };
    if case.mem {
        format!("{} {SRC2_ADDR:#x}, {w1}, {w0}{suffix}", case.mnemonic)
    } else {
        let w2 = if case.ymm { "%ymm2" } else { "%xmm2" };
        format!("{} {w2}, {w1}, {w0}{suffix}", case.mnemonic)
    }
}

fn cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (mnemonic, opcode, op) in [
        ("vaddps", 0x58u8, '+'),
        ("vsubps", 0x5cu8, '-'),
        ("vmulps", 0x59u8, '*'),
        ("vdivps", 0x5eu8, '/'),
    ] {
        for ymm in [false, true] {
            let tag = if ymm { "ymm" } else { "xmm" };
            let mask = if ymm { 0x55u64 } else { 0x5u64 };
            for (suffix, mem, mask, zeroing) in [
                ("reg_nomask", false, None, false),
                ("reg_merge", false, Some(mask), false),
                ("reg_zero", false, Some(mask), true),
                ("mem_nomask", true, None, false),
            ] {
                cases.push(Case {
                    name: format!("{mnemonic}_{tag}_{suffix}"),
                    mnemonic,
                    opcode,
                    op,
                    ymm,
                    mem,
                    mask,
                    zeroing,
                });
            }
        }
    }
    cases
}

#[test]
fn evex128_256_packed_single_differential() -> Result<(), BoxError> {
    let Some(dir) = temp_dir("ps-differential") else {
        eprintln!("SKIP: temp dir unavailable");
        return Ok(());
    };
    let native_ok = host_has_avx512();
    if !native_ok {
        eprintln!("NOTE: host lacks AVX512F+AVX512VL; native oracle skipped, engine checked against Rust oracle only");
    }
    let mut ran_engine = 0usize;
    let mut ran_native = 0usize;
    for case in cases() {
        let mut seeds = f32_seeds();
        seeds.k2 = case.mask;
        let insn_asm = instruction(&case);
        let code = assemble_one(&dir, &case.name, &insn_asm).ok_or_else(|| format!("as failed for `{insn_asm}`"))?;
        let engine = engine_run(&code, &seeds).map_err(|e| format!("case `{}`: {e}", case.name))?;
        let vl = if case.ymm { 8 } else { 4 };
        let expected = oracle(case.op, vl, case.mask, case.zeroing, &seeds);
        assert_eq!(
            engine, expected,
            "engine mismatch vs oracle in `{}` ({insn_asm})",
            case.name
        );
        ran_engine += 1;
        if native_ok {
            let source = native_source(&insn_asm, &seeds, case.mask);
            let native = native_run(&dir, &format!("{}_bin", case.name), &source)?;
            assert_eq!(
                engine, native,
                "native mismatch in `{}` ({insn_asm}): engine={engine:02x?} native={native:02x?}",
                case.name
            );
            ran_native += 1;
        }
    }
    eprintln!("EVEX PS differential: {ran_engine} engine-vs-oracle cases, {ran_native} native-verified");
    Ok(())
}

/// Broadcast `{1to4}`/`{1to8}` encodings must keep resolving to nothing: the IR
/// has no broadcast-capable lowering, so mapping them would silently compute
/// the wrong semantics.
#[test]
fn evex_broadcast_forms_stay_unmapped() -> Result<(), BoxError> {
    let decoder = XedDecoder::new();
    // vaddps {1to4}(%rax), %xmm1, %xmm0{%k0} — 62 f1 74 18 58 00
    let decoded = decoder.decode(CODE_BASE, &[0x62, 0xf1, 0x74, 0x18, 0x58, 0x00])?;
    assert_eq!(map_form(&decoded), None, "{{1to4}} broadcast must stay unmapped");
    // vaddps {1to8}(%rax), %ymm1, %ymm0{%k0} — 62 f1 74 38 58 00
    let decoded = decoder.decode(CODE_BASE, &[0x62, 0xf1, 0x74, 0x38, 0x58, 0x00])?;
    assert_eq!(map_form(&decoded), None, "{{1to8}} broadcast must stay unmapped");
    Ok(())
}
