//! Integration tests for ANG-052:
//! Path reachability from exported JNI entry points to native vulnerability sinks.
//!
//! Verifies:
//! - Reachability from a JNI function to a memcpy sink with user-controlled length (Feasible, model generated).
//! - Unreachable or sanitized sink branch (Unsat or rejected).
//! - Bounded execution with Honest Incompleteness when step limit or recursion depth is exceeded.
//! - Deterministic replay capsule metadata generation for feasible paths.

#![allow(clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::time::Duration;

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprReader, ExprSort, ShardedExprArena};
use angryier_models::{SimProcedure, SimResult, SimState};
use angryier_runtime::jni::JNI_HEAP_BASE;
use angryier_runtime::{
    JniArgumentTaint, JniPathStatus, JniReachabilityConfig, JniSinkDescriptor,
    JniSinkReachabilityAnalyzer, Runtime, SinkConstraintPredicate,
    SinkControlledParam,
};
use angryier_taint::TaintLabel;
use angryier_types::{
    Address, ExpressionNormalizationVersion, SemanticVersion, TaintId, TargetProfileId,
};

/// Dummy synthetic decoder for testing SimProcedure and redirect stepping.
#[derive(Clone, Copy, Debug, Default)]
struct TestSyntheticDecoder;

impl Decoder for TestSyntheticDecoder {
    type Error = String;

    fn decode(&self, _address: Address, _bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        Err("synthetic decoder: not needed for simproc and redirect dispatch".into())
    }
}

/// Builds a minimal valid 64-bit ELF executable containing `code`.
fn build_test_elf(code: &[u8]) -> Vec<u8> {
    let segment_base = 0x400000u64;
    let code_offset = 0x78usize;
    let total_size = code_offset + code.len();
    let mut buf = vec![0u8; total_size];

    // ELF magic
    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2; // 64-bit
    buf[5] = 1; // little endian
    buf[6] = 1; // version 1
    buf[7] = 0; // SYSV ABI

    // Header fields
    buf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    buf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    buf[20..24].copy_from_slice(&1u32.to_le_bytes()); // version
    let entry = segment_base + code_offset as u64;
    buf[24..32].copy_from_slice(&entry.to_le_bytes()); // entry
    buf[32..40].copy_from_slice(&64u64.to_le_bytes()); // phoff
    buf[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
    buf[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
    buf[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum

    // Program header (PT_LOAD, R|X)
    buf[64..68].copy_from_slice(&1u32.to_le_bytes());
    buf[68..72].copy_from_slice(&5u32.to_le_bytes());
    buf[72..80].copy_from_slice(&0u64.to_le_bytes());
    buf[80..88].copy_from_slice(&segment_base.to_le_bytes());
    buf[88..96].copy_from_slice(&segment_base.to_le_bytes());
    buf[96..104].copy_from_slice(&(total_size as u64).to_le_bytes());
    buf[104..112].copy_from_slice(&(total_size as u64).to_le_bytes());
    buf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

    buf[code_offset..code_offset + code.len()].copy_from_slice(code);
    buf
}

/// Simulated JNI function that forwards tainted input to a memcpy call site.
struct MockJniMemcpyEntryProcedure {
    _sink_pc: Address,
    dest_addr: Address,
}

impl SimProcedure for MockJniMemcpyEntryProcedure {
    fn name(&self) -> &'static str {
        "Java_com_example_NativeBridge_processBuffer"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        // Read JNI arguments:
        // Arg 0 (RDI): env
        // Arg 1 (RSI): thiz
        // Arg 2 (RDX): length (tainted)
        // Arg 3 (RCX): jstring input
        let length_val = state.get_reg(2); // RDX
        let _str_handle = state.get_reg(1); // RCX

        let mut next = state.clone();
        // Setup arguments for memcpy(dest, src, n):
        // Arg 0 (RDI): dest
        // Arg 1 (RSI): src (pointer in JNI heap)
        // Arg 2 (RDX): n (length_val)
        next.set_reg(7, self.dest_addr);
        next.set_reg(6, JNI_HEAP_BASE);
        next.set_reg(2, length_val);
        next.return_value = Some(0);

        // Advance to sink PC
        SimResult::Continue(next)
    }
}

// ---------------------------------------------------------------------------
// Test 1: Feasible reachability to memcpy sink with user-controlled length
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_memcpy_user_controlled_length_feasible() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes).unwrap();

    let entry_pc = 0x401000u64;
    let sink_pc = 0x402000u64;
    let dest_addr = 0x5000_1000u64;

    // Register entry procedure and control flow redirect to sink
    process.simproc_instances.insert(
        entry_pc,
        Arc::new(MockJniMemcpyEntryProcedure { _sink_pc: sink_pc, dest_addr }),
    );
    process.redirects.insert(entry_pc, sink_pc);

    let taint_specs = vec![
        JniArgumentTaint::Int {
            arg_index: 2, // RDX
            initial_value: 10,
            taint_id: TaintId(0x100),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
        JniArgumentTaint::String {
            arg_index: 3, // RCX
            initial_value: "SecretPayloadData".into(),
            taint_id: TaintId(0x200),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
    ];

    // Sink descriptor: memcpy sink where length must be greater than 64
    let sink = JniSinkDescriptor::memcpy(sink_pc, Some(64));

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 100,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(50),
            initial_constraints: Vec::new(),
        });

    let result = analyzer.analyze(&mut process, entry_pc, &taint_specs, sink, &mut backend).unwrap();

    assert_eq!(result.status, JniPathStatus::Feasible);
    assert!(!result.model_values.is_empty(), "Solver model values must be generated");

    // Verify trace starts at entry point and reaches sink
    assert!(!result.trace.is_empty());
    assert_eq!(result.trace.first().copied(), Some(entry_pc));
    assert_eq!(result.trace.last().copied(), Some(sink_pc));

    // Verify deterministic replay capsule metadata
    assert!(result.replay_metadata.is_some());
    let metadata = result.replay_metadata.unwrap();
    assert_eq!(metadata.entry_pc, entry_pc);
    assert_eq!(metadata.sink_pc, sink_pc);
    assert!(metadata.capsule_id.0 != 0);
    assert!(metadata.capsule.is_some());
}

// ---------------------------------------------------------------------------
// Test 2: Sanitized sink branch is proven Unsat
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_sanitized_sink_branch_unsat() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes).unwrap();

    let entry_pc = 0x401000u64;
    let sink_pc = 0x402000u64;
    let dest_addr = 0x5000_1000u64;

    process.simproc_instances.insert(
        entry_pc,
        Arc::new(MockJniMemcpyEntryProcedure { _sink_pc: sink_pc, dest_addr }),
    );
    process.redirects.insert(entry_pc, sink_pc);

    let taint_specs = vec![
        JniArgumentTaint::Int {
            arg_index: 2, // RDX
            initial_value: 10,
            taint_id: TaintId(0x100),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
    ];

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));

    // Create a path constraint modeling a sanitizer: length <= 32
    // Symbol index 1000 is the first symbol generated for taint_specs
    let len_sym = arena.intern(ExprNode {
        sort: ExprSort::BitVec(64),
        op: ExprOp::Symbol,
        operands: Vec::new(),
        immediate: 1000u64.to_le_bytes().to_vec(),
    }).unwrap();

    let bound_32 = arena.intern(ExprNode {
        sort: ExprSort::BitVec(64),
        op: ExprOp::Constant,
        operands: Vec::new(),
        immediate: 32u64.to_le_bytes().to_vec(),
    }).unwrap();

    // length <= 32
    let sanitizer_constraint = arena.intern(ExprNode {
        sort: ExprSort::Bool,
        op: ExprOp::Ule,
        operands: vec![len_sym, bound_32],
        immediate: Vec::new(),
    }).unwrap();

    // Sink asserts length > 64: combined with sanitizer (length <= 32), this is UNSAT!
    let sink = JniSinkDescriptor::memcpy(sink_pc, Some(64));

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 100,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(50),
            initial_constraints: vec![sanitizer_constraint],
        });

    let result = analyzer.analyze(&mut process, entry_pc, &taint_specs, sink, &mut backend).unwrap();

    assert_eq!(result.status, JniPathStatus::Unsat);
    assert!(result.model_values.is_empty());
    assert!(result.replay_metadata.is_none());
}

// ---------------------------------------------------------------------------
// Test 3: Unreachable sink branch is rejected as Unsat
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_unreachable_sink_branch() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes).unwrap();

    let entry_pc = 0x401000u64;
    let exit_pc = 0x403000u64;
    let sink_pc = 0x409999u64; // Never targeted by redirects

    // Redirect execution away from sink to exit
    process.redirects.insert(entry_pc, exit_pc);

    let taint_specs = vec![
        JniArgumentTaint::Int {
            arg_index: 2,
            initial_value: 10,
            taint_id: TaintId(0x100),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
    ];

    let sink = JniSinkDescriptor::memcpy(sink_pc, Some(64));

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 100,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(50),
            initial_constraints: Vec::new(),
        });

    let result = analyzer.analyze(&mut process, entry_pc, &taint_specs, sink, &mut backend).unwrap();

    assert_eq!(result.status, JniPathStatus::Unsat);
}

// ---------------------------------------------------------------------------
// Test 4: Bounded execution with Honest Incompleteness (step budget)
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_bounded_execution_step_budget_exhausted() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes).unwrap();

    let entry_pc = 0x401000u64;
    let block1_pc = 0x401010u64;
    let block2_pc = 0x401020u64;
    let sink_pc = 0x402000u64;

    // Multi-hop path: entry -> block1 -> block2 -> sink (requires 3 steps)
    process.redirects.insert(entry_pc, block1_pc);
    process.redirects.insert(block1_pc, block2_pc);
    process.redirects.insert(block2_pc, sink_pc);

    let taint_specs = vec![
        JniArgumentTaint::Int {
            arg_index: 2,
            initial_value: 10,
            taint_id: TaintId(0x100),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
    ];

    let sink = JniSinkDescriptor::memcpy(sink_pc, Some(64));

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    // Budget of only 1 step: will not reach sink
    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 1,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(50),
            initial_constraints: Vec::new(),
        });

    let result = analyzer.analyze(&mut process, entry_pc, &taint_specs, sink, &mut backend).unwrap();

    match result.status {
        JniPathStatus::BoundedUnknown { reason } => {
            assert!(
                reason.contains("budget") || reason.contains("step"),
                "Reason must mention step budget limitation: {reason}"
            );
        }
        other => panic!("Expected BoundedUnknown, got {other:?}"),
    }
    assert!(!result.model_debt.is_empty(), "Model debt must record incomplete exploration");
}

// ---------------------------------------------------------------------------
// Test 5: Bounded execution with Honest Incompleteness (depth limit)
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_bounded_execution_depth_limit_exceeded() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes).unwrap();

    let entry_pc = 0x401000u64;
    let block1_pc = 0x401010u64;
    let block2_pc = 0x401020u64;
    let sink_pc = 0x402000u64;

    process.redirects.insert(entry_pc, block1_pc);
    process.redirects.insert(block1_pc, block2_pc);
    process.redirects.insert(block2_pc, sink_pc);

    let taint_specs = vec![
        JniArgumentTaint::Int {
            arg_index: 2,
            initial_value: 10,
            taint_id: TaintId(0x100),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
    ];

    let sink = JniSinkDescriptor::memcpy(sink_pc, None);

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    // Trace depth will be 4, but max_depth is 2
    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 100,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(2),
            initial_constraints: Vec::new(),
        });

    let result = analyzer.analyze(&mut process, entry_pc, &taint_specs, sink, &mut backend).unwrap();

    match result.status {
        JniPathStatus::BoundedUnknown { reason } => {
            assert!(
                reason.contains("depth"),
                "Reason must mention depth limitation: {reason}"
            );
        }
        other => panic!("Expected BoundedUnknown, got {other:?}"),
    }
    assert!(!result.model_debt.is_empty(), "Model debt must record depth limit bound");
}

// ---------------------------------------------------------------------------
// Test 6: Memory Store sink with controlled pointer
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_store_sink_controlled_pointer() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes).unwrap();

    let entry_pc = 0x401000u64;
    let sink_pc = 0x402000u64;

    process.redirects.insert(entry_pc, sink_pc);

    let taint_specs = vec![
        JniArgumentTaint::Register {
            register_index: 7, // RDI (Destination)
            initial_value: 0x6000_1000,
            taint_id: TaintId(0x300),
            label: TaintLabel::UserInput,
        },
    ];

    let sink = JniSinkDescriptor::store(
        sink_pc,
        SinkControlledParam::Destination,
        Some(SinkConstraintPredicate::Equal(0x6000_1000)),
    );

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 50,
            max_states: 16,
            timeout: Duration::from_secs(5),
            max_depth: Some(20),
            initial_constraints: Vec::new(),
        });

    let result = analyzer.analyze(&mut process, entry_pc, &taint_specs, sink, &mut backend).unwrap();

    assert_eq!(result.status, JniPathStatus::Feasible);
    assert!(!result.model_values.is_empty());
    assert!(result.replay_metadata.is_some());
}

// ---------------------------------------------------------------------------
// Test 7: analyze_elf convenience wrapper reaches sink
// ---------------------------------------------------------------------------

#[test]
fn test_jni_reachability_analyze_elf_wrapper() {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let runtime = Runtime::new(TestSyntheticDecoder, SemanticVersion(1), TargetProfileId(1));

    let entry_pc = 0x400078u64; // ELF entry point
    let sink_pc = 0x400078u64;

    let taint_specs = vec![
        JniArgumentTaint::Int {
            arg_index: 2,
            initial_value: 42,
            taint_id: TaintId(0x100),
            label: TaintLabel::UserInput,
            symbolic: true,
        },
    ];

    let sink = JniSinkDescriptor::memcpy(sink_pc, Some(10));

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).unwrap();

    let analyzer = JniSinkReachabilityAnalyzer::new(&runtime)
        .with_arena(arena)
        .with_config(JniReachabilityConfig {
            max_steps: 10,
            max_states: 4,
            timeout: Duration::from_secs(5),
            max_depth: Some(10),
            initial_constraints: Vec::new(),
        });

    let result = analyzer.analyze_elf(&elf_bytes, entry_pc, &taint_specs, sink, &mut backend).unwrap();
    assert_eq!(result.status, JniPathStatus::Feasible);
    assert!(!result.model_values.is_empty());
}
