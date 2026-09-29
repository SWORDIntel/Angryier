#![forbid(unsafe_code)]

#[path = "../src/avx512.rs"]
mod avx512;

use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_arch_xed_ffi::XedDecoder;
use angryier_execution::{ConcreteInterpreter, ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::BasicSemanticLowerer;
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_semantics::{
    BlockValidityKey, DecodedInstructionView, FeatureId, FloatingPointPolicy, FormId, OperandDescriptor,
    SemanticBlockBuilder, SemanticContext, SemanticProvider, TileRepresentation, VectorRepresentation,
};
use angryier_semantics_intel64::forms;
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use angryier_types::Address;
use angryier_types::{
    BlockId, ContentIdentitySchemaVersion, FidelityProfile, ImageId, ObjectId, SemanticFingerprintSchemaVersion,
    SemanticVersion, StateId, TargetProfileId,
};
use std::collections::BTreeSet;

const CODE_BASE: u64 = 0x400000;
const DATA_BASE: u64 = 0x500000;
const SEMANTIC_VERSION: SemanticVersion = SemanticVersion(1);
const TARGET_PROFILE: TargetProfileId = TargetProfileId(1);

const RAX: u32 = register_id::GPR_BASE;
const ZMM0: u32 = register_id::ZMM_BASE;
const ZMM1: u32 = register_id::ZMM_BASE + 1;
const ZMM2: u32 = register_id::ZMM_BASE + 2;
const K1: u32 = register_id::OPMASK_BASE + 1;
const K2: u32 = register_id::OPMASK_BASE + 2;
const K3: u32 = register_id::OPMASK_BASE + 3;

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

fn create_state(
    code: &[u8],
    mem_data: Option<&[u8; 64]>,
) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
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
            base: DATA_BASE,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        },
    ])?;

    let code_bytes: Vec<ByteValue> = code.iter().map(|b| ByteValue::Concrete(*b)).collect();
    let mut memory = memory
        .write(CODE_BASE, &code_bytes)
        .map_err(|e| format!("load code: {e:?}"))?;

    if let Some(data) = mem_data {
        let data_bytes: Vec<ByteValue> = data.iter().map(|b| ByteValue::Concrete(*b)).collect();
        memory = memory
            .write(DATA_BASE, &data_bytes)
            .map_err(|e| format!("load data: {e:?}"))?;
    }

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

struct EngineCase<'a> {
    code: &'a [u8],
    provider: &'a dyn SemanticProvider,
    zmm1: Option<&'a [u8; 64]>,
    zmm2: Option<&'a [u8; 64]>,
    k2: Option<u64>,
    k3: Option<u64>,
    mem_data: Option<&'a [u8; 64]>,
}

fn run_engine(case: EngineCase<'_>) -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, BoxError> {
    let decoder = XedDecoder::new();
    let decoded = decoder
        .decode(CODE_BASE, case.code)
        .map_err(|e| format!("decode: {e:?}"))?;

    let mut builder = SemanticBlockBuilder::new(SEMANTIC_VERSION);
    case.provider
        .emit(&context(), &decoded, &mut builder)
        .map_err(|e| format!("emit: {e:?}"))?;
    let sealed = builder
        .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
        .map_err(|e| format!("seal: {e:?}"))?;

    let mut state = create_state(case.code, case.mem_data)?;
    if case.mem_data.is_some() {
        state
            .registers
            .write_in_place(RAX, &DATA_BASE.to_le_bytes())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(seed1) = case.zmm1 {
        state
            .registers
            .write_in_place(ZMM1, seed1)
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(seed2) = case.zmm2 {
        state
            .registers
            .write_in_place(ZMM2, seed2)
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(val2) = case.k2 {
        state
            .registers
            .write_in_place(K2, &val2.to_le_bytes())
            .map_err(|e| format!("{e:?}"))?;
    }
    if let Some(val3) = case.k3 {
        state
            .registers
            .write_in_place(K3, &val3.to_le_bytes())
            .map_err(|e| format!("{e:?}"))?;
    }

    let key = BlockValidityKey {
        image: ImageId(1),
        block: BlockId(1),
        address: decoded.address,
        semantic_version: SEMANTIC_VERSION,
        target_profile: TARGET_PROFILE,
        code_versions: state
            .memory
            .code_version_guards_for_range(decoded.address, usize::from(decoded.length))
            .map_err(|e| format!("{e:?}"))?,
    };
    let ir_block = BasicSemanticLowerer
        .lower_with_decode(&sealed, &key, &decoded)
        .map_err(|e| format!("lower: {e:?}"))?;

    let (final_state, outcome) = ConcreteInterpreter::new()
        .execute_block(&state, &ir_block, ExecutionMode::Concrete)
        .map_err(|e| format!("execute: {e:?}"))?;

    match outcome {
        ExecutionOutcome::Continue { next_pc, .. } => {
            assert_eq!(next_pc, CODE_BASE + u64::from(decoded.length));
        }
        other => return Err(format!("unexpected outcome {other:?}").into()),
    }

    Ok(final_state)
}

fn read_zmm_bytes(
    state: &ExecutionState<PersistentRegisters, PersistentMemory>,
    reg: u32,
) -> Result<[u8; 64], BoxError> {
    let bytes = state.registers.read(reg).map_err(|e| format!("{e:?}"))?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes[..64]);
    Ok(out)
}

fn read_f32_lanes(bytes: &[u8; 64]) -> Result<[f32; 16], BoxError> {
    let mut lanes = [0f32; 16];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let chunk: [u8; 4] = bytes[i * 4..(i + 1) * 4].try_into().map_err(|e| format!("{e:?}"))?;
        *lane = f32::from_le_bytes(chunk);
    }
    Ok(lanes)
}

fn read_f64_lanes(bytes: &[u8; 64]) -> Result<[f64; 8], BoxError> {
    let mut lanes = [0f64; 8];
    for (i, lane) in lanes.iter_mut().enumerate() {
        let chunk: [u8; 8] = bytes[i * 8..(i + 1) * 8].try_into().map_err(|e| format!("{e:?}"))?;
        *lane = f64::from_le_bytes(chunk);
    }
    Ok(lanes)
}

fn read_k_reg(state: &ExecutionState<PersistentRegisters, PersistentMemory>, reg: u32) -> Result<u64, BoxError> {
    let bytes = state.registers.read(reg).map_err(|e| format!("{e:?}"))?;
    let chunk: [u8; 8] = bytes[..8].try_into().map_err(|e| format!("{e:?}"))?;
    Ok(u64::from_le_bytes(chunk))
}

// ---------------------------------------------------------------------------
// 1. Registry Conformance and Rule-ID Uniqueness Test
// ---------------------------------------------------------------------------

struct SyntheticDecoded {
    form_id: u32,
}

impl std::fmt::Debug for SyntheticDecoded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SyntheticDecoded(form_id={:#x})", self.form_id)
    }
}

impl DecodedInstructionView for SyntheticDecoded {
    fn address(&self) -> Address {
        CODE_BASE
    }
    fn form_id(&self) -> FormId {
        self.form_id
    }
    fn length(&self) -> u8 {
        6
    }
    fn feature_ids(&self) -> &[FeatureId] {
        &[]
    }
    fn operand_count(&self) -> usize {
        0
    }
    fn operand(&self, _index: u8) -> Option<OperandDescriptor> {
        None
    }
}

#[test]
fn test_registry_and_rule_id_conformance() -> Result<(), BoxError> {
    let providers = avx512::providers();
    assert_eq!(providers.len(), 84, "expected 84 AVX-512 providers");

    let mut rule_ids = BTreeSet::new();
    for provider in &providers {
        let rid = provider.rule_id();
        assert!(
            rid.0 >= 0x2600 && rid.0 <= 0x2660,
            "rule id {:#x} outside assigned band 0x2600..0x2660",
            rid.0
        );
        let inserted = rule_ids.insert(rid.0);
        assert!(inserted, "duplicate rule id {:#x}", rid.0);
    }

    assert_eq!(rule_ids.len(), 84, "all 84 rule IDs must be unique");

    // All form constants in forms module
    let all_forms = [
        forms::VADDPS_ZMM_ZMM_ZMM,
        forms::VADDPS_ZMM_ZMM_MEM,
        forms::VSUBPS_ZMM_ZMM_ZMM,
        forms::VSUBPS_ZMM_ZMM_MEM,
        forms::VMULPS_ZMM_ZMM_ZMM,
        forms::VMULPS_ZMM_ZMM_MEM,
        forms::VDIVPS_ZMM_ZMM_ZMM,
        forms::VDIVPS_ZMM_ZMM_MEM,
        forms::VADDPD_ZMM_ZMM_ZMM,
        forms::VADDPD_ZMM_ZMM_MEM,
        forms::VSUBPD_ZMM_ZMM_ZMM,
        forms::VSUBPD_ZMM_ZMM_MEM,
        forms::VMULPD_ZMM_ZMM_ZMM,
        forms::VMULPD_ZMM_ZMM_MEM,
        forms::VDIVPD_ZMM_ZMM_ZMM,
        forms::VDIVPD_ZMM_ZMM_MEM,
        avx512::forms::VADDSS_EVEX_XMM_XMM_XMM,
        avx512::forms::VADDSS_EVEX_XMM_XMM_MEM32,
        avx512::forms::VSUBSS_EVEX_XMM_XMM_XMM,
        avx512::forms::VSUBSS_EVEX_XMM_XMM_MEM32,
        avx512::forms::VMULSS_EVEX_XMM_XMM_XMM,
        avx512::forms::VMULSS_EVEX_XMM_XMM_MEM32,
        avx512::forms::VDIVSS_EVEX_XMM_XMM_XMM,
        avx512::forms::VDIVSS_EVEX_XMM_XMM_MEM32,
        avx512::forms::VADDSD_EVEX_XMM_XMM_XMM,
        avx512::forms::VADDSD_EVEX_XMM_XMM_MEM64,
        avx512::forms::VSUBSD_EVEX_XMM_XMM_XMM,
        avx512::forms::VSUBSD_EVEX_XMM_XMM_MEM64,
        avx512::forms::VMULSD_EVEX_XMM_XMM_XMM,
        avx512::forms::VMULSD_EVEX_XMM_XMM_MEM64,
        avx512::forms::VDIVSD_EVEX_XMM_XMM_XMM,
        avx512::forms::VDIVSD_EVEX_XMM_XMM_MEM64,
        forms::VANDPS_ZMM_ZMM_ZMM,
        forms::VANDPS_ZMM_ZMM_MEM,
        forms::VANDNPS_ZMM_ZMM_ZMM,
        forms::VANDNPS_ZMM_ZMM_MEM,
        forms::VORPS_ZMM_ZMM_ZMM,
        forms::VORPS_ZMM_ZMM_MEM,
        forms::VXORPS_ZMM_ZMM_ZMM,
        forms::VXORPS_ZMM_ZMM_MEM,
        forms::VANDPD_ZMM_ZMM_ZMM,
        forms::VANDPD_ZMM_ZMM_MEM,
        forms::VANDNPD_ZMM_ZMM_ZMM,
        forms::VANDNPD_ZMM_ZMM_MEM,
        forms::VORPD_ZMM_ZMM_ZMM,
        forms::VORPD_ZMM_ZMM_MEM,
        forms::VXORPD_ZMM_ZMM_ZMM,
        forms::VXORPD_ZMM_ZMM_MEM,
        avx512::forms::KANDW_K_K_K,
        avx512::forms::KANDNW_K_K_K,
        avx512::forms::KORW_K_K_K,
        avx512::forms::KXORW_K_K_K,
        avx512::forms::KNOTW_K_K,
        avx512::forms::KXNORW_K_K_K,
        avx512::forms::KANDQ_K_K_K,
        avx512::forms::KANDNQ_K_K_K,
        avx512::forms::KORQ_K_K_K,
        avx512::forms::KXORQ_K_K_K,
        avx512::forms::KNOTQ_K_K,
        avx512::forms::KXNORQ_K_K_K,
        avx512::forms::VPDPBUSD_XMM_XMM_XMM,
        avx512::forms::VPDPBUSD_XMM_XMM_MEM128,
        avx512::forms::VPDPBUSD_YMM_YMM_YMM,
        avx512::forms::VPDPBUSD_YMM_YMM_MEM,
        avx512::forms::VPDPBUSD_ZMM_ZMM_ZMM,
        avx512::forms::VPDPBUSD_ZMM_ZMM_MEM,
        avx512::forms::VPDPBUSDS_XMM_XMM_XMM,
        avx512::forms::VPDPBUSDS_XMM_XMM_MEM128,
        avx512::forms::VPDPBUSDS_YMM_YMM_YMM,
        avx512::forms::VPDPBUSDS_YMM_YMM_MEM,
        avx512::forms::VPDPBUSDS_ZMM_ZMM_ZMM,
        avx512::forms::VPDPBUSDS_ZMM_ZMM_MEM,
        avx512::forms::VPDPWSSD_XMM_XMM_XMM,
        avx512::forms::VPDPWSSD_XMM_XMM_MEM128,
        avx512::forms::VPDPWSSD_YMM_YMM_YMM,
        avx512::forms::VPDPWSSD_YMM_YMM_MEM,
        avx512::forms::VPDPWSSD_ZMM_ZMM_ZMM,
        avx512::forms::VPDPWSSD_ZMM_ZMM_MEM,
        avx512::forms::VPDPWSSDS_XMM_XMM_XMM,
        avx512::forms::VPDPWSSDS_XMM_XMM_MEM128,
        avx512::forms::VPDPWSSDS_YMM_YMM_YMM,
        avx512::forms::VPDPWSSDS_YMM_YMM_MEM,
        avx512::forms::VPDPWSSDS_ZMM_ZMM_ZMM,
        avx512::forms::VPDPWSSDS_ZMM_ZMM_MEM,
    ];

    let mut form_set = BTreeSet::new();
    for (i, &form) in all_forms.iter().enumerate() {
        assert!(form_set.insert(form), "duplicate form id {form:#x}");
        let view = SyntheticDecoded { form_id: form };
        assert!(
            providers[i].matches(&view),
            "provider {i} does not match form {form:#x}"
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Packed Single Float Arithmetic Engine Tests (VADDPS, VSUBPS, VMULPS, VDIVPS)
// ---------------------------------------------------------------------------

#[test]
fn test_packed_single_arithmetic() -> Result<(), BoxError> {
    let mut left = [0u8; 64];
    let mut right = [0u8; 64];
    for i in 0..16 {
        let f1 = (i + 1) as f32 * 2.0; // 2, 4, 6, ...
        let f2 = (i + 1) as f32; // 1, 2, 3, ...
        left[i * 4..(i + 1) * 4].copy_from_slice(&f1.to_le_bytes());
        right[i * 4..(i + 1) * 4].copy_from_slice(&f2.to_le_bytes());
    }

    // VADDPS reg-reg: 62 f1 74 48 58 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x58, 0xc2],
        provider: &avx512::VaddpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f32 * 3.0;
        assert_eq!(v, exp, "vaddps reg lane {i}");
    }

    // VADDPS reg-mem: 62 f1 74 48 58 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x58, 0x00],
        provider: &avx512::VaddpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f32 * 3.0;
        assert_eq!(v, exp, "vaddps mem lane {i}");
    }

    // VSUBPS reg-reg: 62 f1 74 48 5c c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x5c, 0xc2],
        provider: &avx512::VsubpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f32 * 1.0;
        assert_eq!(v, exp, "vsubps reg lane {i}");
    }

    // VSUBPS reg-mem: 62 f1 74 48 5c 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x5c, 0x00],
        provider: &avx512::VsubpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f32 * 1.0;
        assert_eq!(v, exp, "vsubps mem lane {i}");
    }

    // VMULPS reg-reg: 62 f1 74 48 59 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x59, 0xc2],
        provider: &avx512::VmulpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = ((i + 1) * (i + 1) * 2) as f32;
        assert_eq!(v, exp, "vmulps reg lane {i}");
    }

    // VMULPS reg-mem: 62 f1 74 48 59 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x59, 0x00],
        provider: &avx512::VmulpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = ((i + 1) * (i + 1) * 2) as f32;
        assert_eq!(v, exp, "vmulps mem lane {i}");
    }

    // VDIVPS reg-reg: 62 f1 74 48 5e c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x5e, 0xc2],
        provider: &avx512::VdivpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        assert_eq!(v, 2.0, "vdivps reg lane {i}");
    }

    // VDIVPS reg-mem: 62 f1 74 48 5e 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x5e, 0x00],
        provider: &avx512::VdivpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        assert_eq!(v, 2.0, "vdivps mem lane {i}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 3. Packed Double Float Arithmetic Engine Tests (VADDPD, VSUBPD, VMULPD, VDIVPD)
// ---------------------------------------------------------------------------

#[test]
fn test_packed_double_arithmetic() -> Result<(), BoxError> {
    let mut left = [0u8; 64];
    let mut right = [0u8; 64];
    for i in 0..8 {
        let f1 = (i + 1) as f64 * 3.0; // 3, 6, 9, ...
        let f2 = (i + 1) as f64; // 1, 2, 3, ...
        left[i * 8..(i + 1) * 8].copy_from_slice(&f1.to_le_bytes());
        right[i * 8..(i + 1) * 8].copy_from_slice(&f2.to_le_bytes());
    }

    // VADDPD reg-reg: 62 f1 f5 48 58 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x58, 0xc2],
        provider: &avx512::VaddpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f64 * 4.0;
        assert_eq!(v, exp, "vaddpd reg lane {i}");
    }

    // VADDPD reg-mem: 62 f1 f5 48 58 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x58, 0x00],
        provider: &avx512::VaddpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f64 * 4.0;
        assert_eq!(v, exp, "vaddpd mem lane {i}");
    }

    // VSUBPD reg-reg: 62 f1 f5 48 5c c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x5c, 0xc2],
        provider: &avx512::VsubpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f64 * 2.0;
        assert_eq!(v, exp, "vsubpd reg lane {i}");
    }

    // VSUBPD reg-mem: 62 f1 f5 48 5c 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x5c, 0x00],
        provider: &avx512::VsubpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = (i + 1) as f64 * 2.0;
        assert_eq!(v, exp, "vsubpd mem lane {i}");
    }

    // VMULPD reg-reg: 62 f1 f5 48 59 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x59, 0xc2],
        provider: &avx512::VmulpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = ((i + 1) * (i + 1) * 3) as f64;
        assert_eq!(v, exp, "vmulpd reg lane {i}");
    }

    // VMULPD reg-mem: 62 f1 f5 48 59 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x59, 0x00],
        provider: &avx512::VmulpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        let exp = ((i + 1) * (i + 1) * 3) as f64;
        assert_eq!(v, exp, "vmulpd mem lane {i}");
    }

    // VDIVPD reg-reg: 62 f1 f5 48 5e c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x5e, 0xc2],
        provider: &avx512::VdivpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        assert_eq!(v, 3.0, "vdivpd reg lane {i}");
    }

    // VDIVPD reg-mem: 62 f1 f5 48 5e 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x5e, 0x00],
        provider: &avx512::VdivpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    for (i, &v) in lanes.iter().enumerate() {
        assert_eq!(v, 3.0, "vdivpd mem lane {i}");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Scalar Single Float Arithmetic Engine Tests (VADDSS, VSUBSS, VMULSS, VDIVSS)
// ---------------------------------------------------------------------------

#[test]
fn test_scalar_single_arithmetic() -> Result<(), BoxError> {
    let mut left = [0u8; 64];
    let mut right = [0u8; 64];
    for (i, v) in [10.0f32, 20.0, 30.0, 40.0].iter().enumerate() {
        left[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
    }
    for (i, v) in [5.0f32, 99.0, 99.0, 99.0].iter().enumerate() {
        right[i * 4..(i + 1) * 4].copy_from_slice(&v.to_le_bytes());
    }

    // VADDSS reg: 62 f1 76 08 58 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x58, 0xc2],
        provider: &avx512::VaddssEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 15.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0], "upper lanes preserved from src1");

    // VADDSS mem: 62 f1 76 08 58 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x58, 0x00],
        provider: &avx512::VaddssEvexXmmXmmMem32,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 15.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    // VSUBSS reg: 62 f1 76 08 5c c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x5c, 0xc2],
        provider: &avx512::VsubssEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 5.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    // VSUBSS mem: 62 f1 76 08 5c 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x5c, 0x00],
        provider: &avx512::VsubssEvexXmmXmmMem32,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 5.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    // VMULSS reg: 62 f1 76 08 59 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x59, 0xc2],
        provider: &avx512::VmulssEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 50.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    // VMULSS mem: 62 f1 76 08 59 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x59, 0x00],
        provider: &avx512::VmulssEvexXmmXmmMem32,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 50.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    // VDIVSS reg: 62 f1 76 08 5e c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x5e, 0xc2],
        provider: &avx512::VdivssEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 2.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    // VDIVSS mem: 62 f1 76 08 5e 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x76, 0x08, 0x5e, 0x00],
        provider: &avx512::VdivssEvexXmmXmmMem32,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f32_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 2.0);
    assert_eq!(&lanes[1..4], &[20.0, 30.0, 40.0]);

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Scalar Double Float Arithmetic Engine Tests (VADDSD, VSUBSD, VMULSD, VDIVSD)
// ---------------------------------------------------------------------------

#[test]
fn test_scalar_double_arithmetic() -> Result<(), BoxError> {
    let mut left = [0u8; 64];
    let mut right = [0u8; 64];
    for (i, v) in [100.0f64, 200.0].iter().enumerate() {
        left[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }
    for (i, v) in [25.0f64, 999.0].iter().enumerate() {
        right[i * 8..(i + 1) * 8].copy_from_slice(&v.to_le_bytes());
    }

    // VADDSD reg: 62 f1 f7 08 58 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x58, 0xc2],
        provider: &avx512::VaddsdEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 125.0);
    assert_eq!(lanes[1], 200.0, "upper lane preserved from src1");

    // VADDSD mem: 62 f1 f7 08 58 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x58, 0x00],
        provider: &avx512::VaddsdEvexXmmXmmMem64,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 125.0);
    assert_eq!(lanes[1], 200.0);

    // VSUBSD reg: 62 f1 f7 08 5c c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x5c, 0xc2],
        provider: &avx512::VsubsdEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 75.0);
    assert_eq!(lanes[1], 200.0);

    // VSUBSD mem: 62 f1 f7 08 5c 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x5c, 0x00],
        provider: &avx512::VsubsdEvexXmmXmmMem64,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 75.0);
    assert_eq!(lanes[1], 200.0);

    // VMULSD reg: 62 f1 f7 08 59 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x59, 0xc2],
        provider: &avx512::VmulsdEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 2500.0);
    assert_eq!(lanes[1], 200.0);

    // VMULSD mem: 62 f1 f7 08 59 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x59, 0x00],
        provider: &avx512::VmulsdEvexXmmXmmMem64,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 2500.0);
    assert_eq!(lanes[1], 200.0);

    // VDIVSD reg: 62 f1 f7 08 5e c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x5e, 0xc2],
        provider: &avx512::VdivsdEvexXmmXmmXmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 4.0);
    assert_eq!(lanes[1], 200.0);

    // VDIVSD mem: 62 f1 f7 08 5e 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf7, 0x08, 0x5e, 0x00],
        provider: &avx512::VdivsdEvexXmmXmmMem64,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    let lanes = read_f64_lanes(&read_zmm_bytes(&s, ZMM0)?)?;
    assert_eq!(lanes[0], 4.0);
    assert_eq!(lanes[1], 200.0);

    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Packed Logic Single and Double Engine Tests (AND, ANDN, OR, XOR)
// ---------------------------------------------------------------------------

#[test]
fn test_packed_logic_single_and_double() -> Result<(), BoxError> {
    let mut left = [0u8; 64];
    let mut right = [0u8; 64];
    for (i, (l, r)) in left.iter_mut().zip(right.iter_mut()).enumerate() {
        *l = 0xAA ^ (i as u8);
        *r = 0x55 ^ (i as u8);
    }

    let mut exp_and = [0u8; 64];
    let mut exp_andn = [0u8; 64];
    let mut exp_or = [0u8; 64];
    let mut exp_xor = [0u8; 64];
    for i in 0..64 {
        exp_and[i] = left[i] & right[i];
        exp_andn[i] = (!left[i]) & right[i];
        exp_or[i] = left[i] | right[i];
        exp_xor[i] = left[i] ^ right[i];
    }

    // VANDPS reg: 62 f1 74 48 54 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x54, 0xc2],
        provider: &avx512::VandpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_and, "vandps reg");

    // VANDPS mem: 62 f1 74 48 54 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x54, 0x00],
        provider: &avx512::VandpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_and, "vandps mem");

    // VANDNPS reg: 62 f1 74 48 55 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x55, 0xc2],
        provider: &avx512::VandnpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_andn, "vandnps reg");

    // VANDNPS mem: 62 f1 74 48 55 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x55, 0x00],
        provider: &avx512::VandnpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_andn, "vandnps mem");

    // VORPS reg: 62 f1 74 48 56 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x56, 0xc2],
        provider: &avx512::VorpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_or, "vorps reg");

    // VORPS mem: 62 f1 74 48 56 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x56, 0x00],
        provider: &avx512::VorpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_or, "vorps mem");

    // VXORPS reg: 62 f1 74 48 57 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x57, 0xc2],
        provider: &avx512::VxorpsZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_xor, "vxorps reg");

    // VXORPS mem: 62 f1 74 48 57 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0x74, 0x48, 0x57, 0x00],
        provider: &avx512::VxorpsZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_xor, "vxorps mem");

    // VANDPD reg: 62 f1 f5 48 54 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x54, 0xc2],
        provider: &avx512::VandpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_and, "vandpd reg");

    // VANDPD mem: 62 f1 f5 48 54 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x54, 0x00],
        provider: &avx512::VandpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_and, "vandpd mem");

    // VANDNPD reg: 62 f1 f5 48 55 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x55, 0xc2],
        provider: &avx512::VandnpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_andn, "vandnpd reg");

    // VANDNPD mem: 62 f1 f5 48 55 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x55, 0x00],
        provider: &avx512::VandnpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_andn, "vandnpd mem");

    // VORPD reg: 62 f1 f5 48 56 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x56, 0xc2],
        provider: &avx512::VorpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_or, "vorpd reg");

    // VORPD mem: 62 f1 f5 48 56 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x56, 0x00],
        provider: &avx512::VorpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_or, "vorpd mem");

    // VXORPD reg: 62 f1 f5 48 57 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x57, 0xc2],
        provider: &avx512::VxorpdZmmZmmZmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_xor, "vxorpd reg");

    // VXORPD mem: 62 f1 f5 48 57 00
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf1, 0xf5, 0x48, 0x57, 0x00],
        provider: &avx512::VxorpdZmmZmmMem,
        zmm1: Some(&left),
        zmm2: None,
        k2: None,
        k3: None,
        mem_data: Some(&right),
    })?;
    assert_eq!(read_zmm_bytes(&s, ZMM0)?, exp_xor, "vxorpd mem");

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Opmask Word Logic Engine Tests (KANDW, KANDNW, KORW, KXORW, KNOTW, KXNORW)
// ---------------------------------------------------------------------------

#[test]
fn test_opmask_logic_word() -> Result<(), BoxError> {
    // Seed with high bits set to verify upper 48 bits are zeroed!
    let val2: u64 = 0xAAAA_BBBB_CCCC_DEF0;
    let val3: u64 = 0x5555_6666_7777_4321;

    // KANDW: c5 ec 41 cb (kandw %k3, %k2, %k1)
    let s = run_engine(EngineCase {
        code: &[0xc5, 0xec, 0x41, 0xcb],
        provider: &avx512::KandwKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    let exp = (val2 & val3) & 0xFFFF;
    assert_eq!(k1, exp, "kandw");

    // KANDNW: c5 ec 42 cb (kandnw %k3, %k2, %k1 -> (!k2) & k3)
    let s = run_engine(EngineCase {
        code: &[0xc5, 0xec, 0x42, 0xcb],
        provider: &avx512::KandnwKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    let exp = ((!val2) & val3) & 0xFFFF;
    assert_eq!(k1, exp, "kandnw");

    // KORW: c5 ec 45 cb
    let s = run_engine(EngineCase {
        code: &[0xc5, 0xec, 0x45, 0xcb],
        provider: &avx512::KorwKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    let exp = (val2 | val3) & 0xFFFF;
    assert_eq!(k1, exp, "korw");

    // KXORW: c5 ec 47 cb
    let s = run_engine(EngineCase {
        code: &[0xc5, 0xec, 0x47, 0xcb],
        provider: &avx512::KxorwKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    let exp = (val2 ^ val3) & 0xFFFF;
    assert_eq!(k1, exp, "kxorw");

    // KNOTW: c5 f8 44 ca (knotw %k2, %k1)
    let s = run_engine(EngineCase {
        code: &[0xc5, 0xf8, 0x44, 0xca],
        provider: &avx512::KnotwKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: None,
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    let exp = (!val2) & 0xFFFF;
    assert_eq!(k1, exp, "knotw");

    // KXNORW: c5 ec 46 cb
    let s = run_engine(EngineCase {
        code: &[0xc5, 0xec, 0x46, 0xcb],
        provider: &avx512::KxnorwKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    let exp = (!(val2 ^ val3)) & 0xFFFF;
    assert_eq!(k1, exp, "kxnorw");

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Opmask Qword Logic Engine Tests (KANDQ, KANDNQ, KORQ, KXORQ, KNOTQ, KXNORQ)
// ---------------------------------------------------------------------------

#[test]
fn test_opmask_logic_qword() -> Result<(), BoxError> {
    let val2: u64 = 0xAAAA_BBBB_CCCC_DEF0;
    let val3: u64 = 0x5555_6666_7777_4321;

    // KANDQ: c4 e1 ec 41 cb
    let s = run_engine(EngineCase {
        code: &[0xc4, 0xe1, 0xec, 0x41, 0xcb],
        provider: &avx512::KandqKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    assert_eq!(k1, val2 & val3, "kandq");

    // KANDNQ: c4 e1 ec 42 cb
    let s = run_engine(EngineCase {
        code: &[0xc4, 0xe1, 0xec, 0x42, 0xcb],
        provider: &avx512::KandnqKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    assert_eq!(k1, (!val2) & val3, "kandnq");

    // KORQ: c4 e1 ec 45 cb
    let s = run_engine(EngineCase {
        code: &[0xc4, 0xe1, 0xec, 0x45, 0xcb],
        provider: &avx512::KorqKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    assert_eq!(k1, val2 | val3, "korq");

    // KXORQ: c4 e1 ec 47 cb
    let s = run_engine(EngineCase {
        code: &[0xc4, 0xe1, 0xec, 0x47, 0xcb],
        provider: &avx512::KxorqKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    assert_eq!(k1, val2 ^ val3, "kxorq");

    // KNOTQ: c4 e1 f8 44 ca
    let s = run_engine(EngineCase {
        code: &[0xc4, 0xe1, 0xf8, 0x44, 0xca],
        provider: &avx512::KnotqKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: None,
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    assert_eq!(k1, !val2, "knotq");

    // KXNORQ: c4 e1 ec 46 cb
    let s = run_engine(EngineCase {
        code: &[0xc4, 0xe1, 0xec, 0x46, 0xcb],
        provider: &avx512::KxnorqKKK,
        zmm1: None,
        zmm2: None,
        k2: Some(val2),
        k3: Some(val3),
        mem_data: None,
    })?;
    let k1 = read_k_reg(&s, K1)?;
    assert_eq!(k1, !(val2 ^ val3), "kxnorq");

    Ok(())
}

// ---------------------------------------------------------------------------
// 8. VNNI Dot-Product Accumulate Engine Tests (VPDPBUSD/VPDPWSSD + saturating)
// ---------------------------------------------------------------------------

fn vnni_u8s8_dot(a: &[u8; 64], b: &[u8; 64]) -> [i32; 8] {
    let mut out = [0i32; 8];
    for (i, lane) in out.iter_mut().enumerate() {
        let mut acc = 0i32;
        for j in 0..4 {
            acc = acc.wrapping_add(a[4 * i + j] as i32 * (b[4 * i + j] as i8 as i32));
        }
        *lane = acc;
    }
    out
}

fn vnni_i16_madd(a: &[u8; 64], b: &[u8; 64]) -> [i32; 8] {
    let mut out = [0i32; 8];
    for (i, lane) in out.iter_mut().enumerate() {
        let a0 = i16::from_le_bytes([a[4 * i], a[4 * i + 1]]) as i32;
        let a1 = i16::from_le_bytes([a[4 * i + 2], a[4 * i + 3]]) as i32;
        let b0 = i16::from_le_bytes([b[4 * i], b[4 * i + 1]]) as i32;
        let b1 = i16::from_le_bytes([b[4 * i + 2], b[4 * i + 3]]) as i32;
        *lane = a0.wrapping_mul(b0).wrapping_add(a1.wrapping_mul(b1));
    }
    out
}

#[test]
fn test_vnni_dot_products() -> Result<(), BoxError> {
    let mut left = [0u8; 64];
    let mut right = [0u8; 64];
    for i in 0..32 {
        left[i] = ((i * 7 + 3) & 0xFF) as u8;
        right[i] = ((i * 13 + 91) & 0xFF) as u8;
    }
    let dot_exp = vnni_u8s8_dot(&left, &right);
    let madd_exp = vnni_i16_madd(&left, &right);

    // vpdpbusd %ymm2, %ymm1, %ymm0 — 62 f2 75 28 50 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf2, 0x75, 0x28, 0x50, 0xc2],
        provider: &avx512::VpdpbusdYmmYmmYmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let out = read_zmm_bytes(&s, ZMM0)?;
    for (i, &exp) in dot_exp.iter().enumerate() {
        let got = i32::from_le_bytes(out[i * 4..(i + 1) * 4].try_into().map_err(|e| format!("{e:?}"))?);
        assert_eq!(got, exp, "vpdpbusd ymm lane {i}");
    }

    // vpdpbusds %ymm2, %ymm1, %ymm0 — 62 f2 75 28 51 c2 (same value, no saturation at zero dst)
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf2, 0x75, 0x28, 0x51, 0xc2],
        provider: &avx512::VpdpbusdsYmmYmmYmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let out = read_zmm_bytes(&s, ZMM0)?;
    for (i, &exp) in dot_exp.iter().enumerate() {
        let got = i32::from_le_bytes(out[i * 4..(i + 1) * 4].try_into().map_err(|e| format!("{e:?}"))?);
        assert_eq!(got, exp, "vpdpbusds ymm lane {i}");
    }

    // vpdpwssd %ymm2, %ymm1, %ymm0 — 62 f2 75 28 52 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf2, 0x75, 0x28, 0x52, 0xc2],
        provider: &avx512::VpdpwssdYmmYmmYmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let out = read_zmm_bytes(&s, ZMM0)?;
    for (i, &exp) in madd_exp.iter().enumerate() {
        let got = i32::from_le_bytes(out[i * 4..(i + 1) * 4].try_into().map_err(|e| format!("{e:?}"))?);
        assert_eq!(got, exp, "vpdpwssd ymm lane {i}");
    }

    // vpdpwssds %ymm2, %ymm1, %ymm0 — 62 f2 75 28 53 c2
    let s = run_engine(EngineCase {
        code: &[0x62, 0xf2, 0x75, 0x28, 0x53, 0xc2],
        provider: &avx512::VpdpwssdsYmmYmmYmm,
        zmm1: Some(&left),
        zmm2: Some(&right),
        k2: None,
        k3: None,
        mem_data: None,
    })?;
    let out = read_zmm_bytes(&s, ZMM0)?;
    for (i, &exp) in madd_exp.iter().enumerate() {
        let got = i32::from_le_bytes(out[i * 4..(i + 1) * 4].try_into().map_err(|e| format!("{e:?}"))?);
        assert_eq!(got, exp, "vpdpwssds ymm lane {i}");
    }

    Ok(())
}
