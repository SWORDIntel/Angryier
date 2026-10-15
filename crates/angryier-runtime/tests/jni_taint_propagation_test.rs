//! Integration tests for ANG-050 and ANG-051:
//! - JNI native environment stubbing (JNIEnv*, jobject, jclass, jstring, jbyteArray, jint, jlong).
//! - SimProcedures for critical JNIEnv functions:
//!   - GetStringUTFChars / ReleaseStringUTFChars
//!   - GetByteArrayElements / ReleaseByteArrayElements
//!   - GetArrayLength
//!   - NewStringUTF
//!   - GetByteArrayRegion / SetByteArrayRegion
//! - Symbolic taint propagation from Android Java parameters into native C/C++ memory buffers.
//! - Reverse taint propagation from native memory into Java strings/arrays.
//! - Process memory mapping, JNIEnv* vtable layout, and instance SimProcedure dispatch.

use std::sync::Arc;

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_arch_intel64::register_id;
use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_models::{SimProcedure, SimProcedureRegistry, SimResult, SimState};
use angryier_runtime::Runtime;
use angryier_runtime::jni::{
    self, JNI_COMMIT, JNI_ENV_PTR_ADDR, JNI_HEAP_BASE, JNI_STUB_BASE, JNI_STUB_STRIDE, JNI_TRUE, JNI_VERSION_1_6,
    JNI_VTABLE_ADDR, JniEnvironment, jboolean, jbyte, jclass, jdouble, jfloat, jint, jlong, jsize, jstring, vtable_idx,
};
use angryier_taint::TaintLabel;
use angryier_types::{Address, ExprId, ExpressionNormalizationVersion, SemanticVersion, TaintId, TargetProfileId};

/// Dummy decoder for SimProcedure-only stepping.
#[derive(Clone, Copy, Debug, Default)]
struct TestSyntheticDecoder;

impl Decoder for TestSyntheticDecoder {
    type Error = String;

    fn decode(&self, _address: Address, _bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        Err("synthetic decoder: not needed for simproc dispatch".into())
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

#[test]
fn test_jni_environment_modeling_and_types() {
    let env_arc = JniEnvironment::new();
    let mut env = env_arc.write().unwrap();

    // Verify Java primitive type representation
    let i: jint = 42;
    let l: jlong = 0x1234_5678_9ABC_DEF0;
    let b: jbyte = -1;
    let bool_val: jboolean = JNI_TRUE;
    let s: jsize = 100;
    let f: jfloat = 3.14159;
    let d: jdouble = 2.71828;

    assert_eq!(i, 42);
    assert_eq!(l, 0x1234_5678_9ABC_DEF0);
    assert_eq!(b, -1);
    assert_eq!(bool_val, 1);
    assert_eq!(s, 100);
    assert!((f - 3.14159).abs() < 1e-4);
    assert!((d - 2.71828).abs() < 1e-4);

    // Verify Java reference handle allocation & objects
    let str_handle: jstring = env.create_string("HelloWorld");
    let byte_arr_handle = env.create_byte_array(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let class_handle: jclass = env.create_class("com/example/TestClass");

    assert!(str_handle != 0);
    assert!(byte_arr_handle != 0);
    assert!(class_handle != 0);
    assert_ne!(str_handle, byte_arr_handle);

    assert_eq!(env.get_string(str_handle), Some("HelloWorld"));
    assert_eq!(env.get_byte_array(byte_arr_handle), Some(&[0xDE, 0xAD, 0xBE, 0xEF][..]));
    assert!(!env.is_handle_tainted(str_handle));
    assert!(!env.is_handle_tainted(byte_arr_handle));
}

#[test]
fn test_critical_jnienv_procedures_direct() {
    let env_arc = JniEnvironment::new();

    let str_handle = {
        let mut env = env_arc.write().unwrap();
        env.create_string("JniSecretAuthPayload")
    };

    // 1. GetStringUTFChars
    let mut state = SimState::new();
    state.set_arg(0, JNI_ENV_PTR_ADDR);
    state.set_arg(1, str_handle);
    let is_copy_slot = 0x5000_1000u64;
    state.set_arg(2, is_copy_slot);

    let get_str_proc = jni::GetStringUTFCharsProcedure::new(env_arc.clone());
    let res = get_str_proc.apply(&state);

    let next_state = match res {
        SimResult::Continue(s) => s,
        other => panic!("expected Continue, got {other:?}"),
    };

    let native_buf_ptr = next_state.return_value.expect("must return RAX buffer pointer");
    assert!(native_buf_ptr >= JNI_HEAP_BASE);

    // Read null-terminated string from native memory
    let read_chars = next_state.read_null_terminated_string(native_buf_ptr, 64);
    assert_eq!(read_chars, b"JniSecretAuthPayload");

    // Verify isCopy was written with JNI_TRUE (1)
    let is_copy_val = next_state.read_byte(is_copy_slot);
    assert_eq!(is_copy_val, Some(JNI_TRUE));

    // 2. ReleaseStringUTFChars
    let mut rel_state = SimState::new();
    rel_state.set_arg(0, JNI_ENV_PTR_ADDR);
    rel_state.set_arg(1, str_handle);
    rel_state.set_arg(2, native_buf_ptr);

    let rel_str_proc = jni::ReleaseStringUTFCharsProcedure::new(env_arc.clone());
    let rel_res = rel_str_proc.apply(&rel_state);
    assert!(matches!(rel_res, SimResult::Continue(_)));

    // 3. GetByteArrayElements and ReleaseByteArrayElements (commit)
    let arr_handle = {
        let mut env = env_arc.write().unwrap();
        env.create_byte_array(vec![10, 20, 30, 40])
    };

    let mut arr_state = SimState::new();
    arr_state.set_arg(0, JNI_ENV_PTR_ADDR);
    arr_state.set_arg(1, arr_handle);
    arr_state.set_arg(2, 0); // isCopy = NULL

    let get_arr_proc = jni::GetByteArrayElementsProcedure::new(env_arc.clone());
    let arr_res = get_arr_proc.apply(&arr_state);
    let arr_next = match arr_res {
        SimResult::Continue(s) => s,
        other => panic!("expected Continue, got {other:?}"),
    };
    let arr_native_buf = arr_next.return_value.expect("must return native buf");
    assert_eq!(arr_next.read_bytes(arr_native_buf, 4), vec![10, 20, 30, 40]);

    // Mutate native buffer and commit back
    let mut mutate_state = arr_next.clone();
    mutate_state.write_memory(arr_native_buf, vec![99, 88, 77, 66]);
    mutate_state.set_arg(0, JNI_ENV_PTR_ADDR);
    mutate_state.set_arg(1, arr_handle);
    mutate_state.set_arg(2, arr_native_buf);
    mutate_state.set_arg(3, JNI_COMMIT as u64);

    let rel_arr_proc = jni::ReleaseByteArrayElementsProcedure::new(env_arc.clone());
    let _ = rel_arr_proc.apply(&mutate_state);

    let env = env_arc.read().unwrap();
    assert_eq!(env.get_byte_array(arr_handle), Some(&[99, 88, 77, 66][..]));
}

#[test]
fn test_get_array_length_and_new_string_utf() {
    let env_arc = JniEnvironment::new();

    let arr_handle = {
        let mut env = env_arc.write().unwrap();
        env.create_byte_array(vec![0u8; 128])
    };

    // GetArrayLength
    let mut state = SimState::new();
    state.set_arg(0, JNI_ENV_PTR_ADDR);
    state.set_arg(1, arr_handle);
    let len_proc = jni::GetArrayLengthProcedure::new(env_arc.clone());
    let res = len_proc.apply(&state);
    assert_eq!(
        match res {
            SimResult::Continue(s) => s.return_value,
            _ => None,
        },
        Some(128)
    );

    // NewStringUTF
    let mut new_str_state = SimState::new();
    let c_str_addr = 0x7000_2000u64;
    new_str_state.write_memory(c_str_addr, b"CreatedFromNativeC\0".to_vec());
    new_str_state.set_arg(0, JNI_ENV_PTR_ADDR);
    new_str_state.set_arg(1, c_str_addr);

    let new_str_proc = jni::NewStringUTFProcedure::new(env_arc.clone());
    let new_res = new_str_proc.apply(&new_str_state);
    let created_handle = match new_res {
        SimResult::Continue(s) => s.return_value.expect("must return jstring handle"),
        other => panic!("expected Continue, got {other:?}"),
    };

    let env = env_arc.read().unwrap();
    assert_eq!(env.get_string(created_handle), Some("CreatedFromNativeC"));
}

#[test]
fn test_symbolic_taint_propagation_string() {
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let env_arc = JniEnvironment::new();

    let raw_text = "TaintedUserKey123";
    let str_handle = {
        let mut env = env_arc.write().unwrap();
        env.create_string(raw_text)
    };

    // Generate symbolic expressions for each character
    let sym_exprs: Vec<ExprId> = (0..raw_text.len())
        .map(|idx| {
            arena
                .intern(ExprNode {
                    sort: ExprSort::BitVec(8),
                    op: ExprOp::Symbol,
                    operands: Vec::new(),
                    immediate: (5000 + idx as u64).to_le_bytes().to_vec(),
                })
                .unwrap()
        })
        .collect();

    // Mark Android Java parameter as tainted!
    {
        let mut env = env_arc.write().unwrap();
        env.mark_string_symbolic(str_handle, TaintId(0xCAFE), TaintLabel::UserInput, sym_exprs.clone());
        assert!(env.is_handle_tainted(str_handle));
    }

    // Call GetStringUTFChars
    let mut state = SimState::new();
    state.set_arg(0, JNI_ENV_PTR_ADDR);
    state.set_arg(1, str_handle);
    state.set_arg(2, 0);

    let get_str_proc = jni::GetStringUTFCharsProcedure::new(env_arc.clone());
    let res = get_str_proc.apply(&state);
    let next_state = match res {
        SimResult::Continue(s) => s,
        other => panic!("expected Continue, got {other:?}"),
    };

    let buf_addr = next_state.return_value.expect("native buffer returned");

    // Check that taint was propagated into the native memory buffer!
    let env = env_arc.read().unwrap();
    assert!(env.taint_tracker.is_range_tainted(buf_addr, raw_text.len()));

    for (i, &sym_id) in sym_exprs.iter().enumerate() {
        let byte_addr = buf_addr + i as u64;
        let taint_record = env
            .taint_tracker
            .get_byte_taint(byte_addr)
            .expect("byte must be marked tainted");
        assert_eq!(taint_record.taint_id, TaintId(0xCAFE));
        assert_eq!(taint_record.label, TaintLabel::UserInput);
        assert_eq!(taint_record.symbol, Some(sym_id));
    }

    let buffer_meta = env.taint_tracker.get_buffer(buf_addr).expect("buffer meta exists");
    assert_eq!(buffer_meta.source_type, "jstring");
    assert_eq!(buffer_meta.source_handle, str_handle);
    assert_eq!(buffer_meta.taint_id, TaintId(0xCAFE));
}

#[test]
fn test_symbolic_taint_propagation_byte_array() {
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let env_arc = JniEnvironment::new();

    let raw_bytes = vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    let arr_handle = {
        let mut env = env_arc.write().unwrap();
        env.create_byte_array(raw_bytes.clone())
    };

    let sym_exprs: Vec<ExprId> = (0..raw_bytes.len())
        .map(|idx| {
            arena
                .intern(ExprNode {
                    sort: ExprSort::BitVec(8),
                    op: ExprOp::Symbol,
                    operands: Vec::new(),
                    immediate: (8000 + idx as u64).to_le_bytes().to_vec(),
                })
                .unwrap()
        })
        .collect();

    // Mark byte array parameter tainted!
    {
        let mut env = env_arc.write().unwrap();
        env.mark_byte_array_symbolic(
            arr_handle,
            TaintId(0xBEEF),
            TaintLabel::NetworkInput,
            sym_exprs.clone(),
            None,
        );
        assert!(env.is_handle_tainted(arr_handle));
    }

    // Call GetByteArrayElements
    let mut state = SimState::new();
    state.set_arg(0, JNI_ENV_PTR_ADDR);
    state.set_arg(1, arr_handle);
    state.set_arg(2, 0);

    let get_arr_proc = jni::GetByteArrayElementsProcedure::new(env_arc.clone());
    let res = get_arr_proc.apply(&state);
    let next_state = match res {
        SimResult::Continue(s) => s,
        other => panic!("expected Continue, got {other:?}"),
    };

    let buf_addr = next_state.return_value.expect("native buffer returned");

    // Check taint propagation
    let env = env_arc.read().unwrap();
    assert!(env.taint_tracker.is_range_tainted(buf_addr, raw_bytes.len()));

    for (i, &sym_id) in sym_exprs.iter().enumerate() {
        let byte_addr = buf_addr + i as u64;
        let taint_record = env
            .taint_tracker
            .get_byte_taint(byte_addr)
            .expect("byte must be marked tainted");
        assert_eq!(taint_record.taint_id, TaintId(0xBEEF));
        assert_eq!(taint_record.label, TaintLabel::NetworkInput);
        assert_eq!(taint_record.symbol, Some(sym_id));
    }

    let buffer_meta = env.taint_tracker.get_buffer(buf_addr).expect("buffer meta exists");
    assert_eq!(buffer_meta.source_type, "jbyteArray");
    assert_eq!(buffer_meta.taint_id, TaintId(0xBEEF));
}

#[test]
fn test_reverse_taint_propagation_new_string_utf() {
    let env_arc = JniEnvironment::new();

    // Setup native buffer with tainted bytes
    let native_addr = 0x6010_5000u64;
    let text = b"LeakedSensitiveString\0";

    {
        let mut env = env_arc.write().unwrap();
        env.taint_tracker.record_buffer(
            native_addr,
            text.len() - 1,
            TaintId(777),
            TaintLabel::UserInput,
            0,
            "native_buffer",
            None,
        );
    }

    let mut state = SimState::new();
    state.write_memory(native_addr, text.to_vec());
    state.set_arg(0, JNI_ENV_PTR_ADDR);
    state.set_arg(1, native_addr);

    let new_str_proc = jni::NewStringUTFProcedure::new(env_arc.clone());
    let res = new_str_proc.apply(&state);

    let created_handle = match res {
        SimResult::Continue(s) => s.return_value.unwrap(),
        other => panic!("expected Continue, got {other:?}"),
    };

    // Verify reverse taint propagation: new jstring is tainted!
    let env = env_arc.read().unwrap();
    assert!(env.is_handle_tainted(created_handle));
    match env.objects.get(&created_handle) {
        Some(jni::JavaObject::String {
            tainted,
            taint_id,
            label,
            value,
            ..
        }) => {
            assert!(*tainted);
            assert_eq!(*taint_id, Some(TaintId(777)));
            assert_eq!(*label, Some(TaintLabel::UserInput));
            assert_eq!(value, "LeakedSensitiveString");
        }
        _ => panic!("expected String object"),
    }
}

#[test]
fn test_byte_array_region_taint_propagation() {
    let env_arc = JniEnvironment::new();
    let data = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let arr_handle = {
        let mut env = env_arc.write().unwrap();
        let h = env.create_byte_array(data);
        env.mark_byte_array_tainted(h, TaintId(333), TaintLabel::FileInput);
        h
    };

    // GetByteArrayRegion propagates taint from array into native buffer
    let mut state = SimState::new();
    let native_dest = 0x6010_8000u64;
    state.set_arg(0, JNI_ENV_PTR_ADDR);
    state.set_arg(1, arr_handle);
    state.set_arg(2, 2); // start offset 2
    state.set_arg(3, 4); // length 4
    state.set_arg(4, native_dest);

    let get_region_proc = jni::GetByteArrayRegionProcedure::new(env_arc.clone());
    let res = get_region_proc.apply(&state);
    let next_state = match res {
        SimResult::Continue(s) => s,
        other => panic!("expected Continue, got {other:?}"),
    };

    assert_eq!(next_state.read_bytes(native_dest, 4), vec![3, 4, 5, 6]);

    let env = env_arc.read().unwrap();
    assert!(env.taint_tracker.is_range_tainted(native_dest, 4));
    assert_eq!(
        env.taint_tracker.get_byte_taint(native_dest).map(|b| b.taint_id),
        Some(TaintId(333))
    );
}

#[test]
fn test_simprocedure_registry_registration() {
    let env_arc = JniEnvironment::new();
    let mut registry = SimProcedureRegistry::new();
    jni::register_jni_procedures(&mut registry, env_arc);

    assert!(registry.contains("GetStringUTFChars"));
    assert!(registry.contains("ReleaseStringUTFChars"));
    assert!(registry.contains("GetByteArrayElements"));
    assert!(registry.contains("ReleaseByteArrayElements"));
    assert!(registry.contains("GetArrayLength"));
    assert!(registry.contains("NewStringUTF"));
    assert!(registry.contains("GetStringUTFLength"));
    assert!(registry.contains("NewByteArray"));
    assert!(registry.contains("GetByteArrayRegion"));
    assert!(registry.contains("SetByteArrayRegion"));
    assert!(registry.contains("GetVersion"));
    assert!(registry.contains("FindClass"));
    assert!(registry.contains("GetObjectClass"));

    let state = SimState::new();
    let version_res = registry.apply_by_name("GetVersion", &state);
    assert_eq!(
        match version_res {
            Some(SimResult::Continue(s)) => s.return_value,
            _ => None,
        },
        Some(JNI_VERSION_1_6 as u64)
    );
}

#[test]
fn test_jnienv_vtable_and_process_wiring() -> Result<(), angryier_runtime::RuntimeError> {
    let elf_bytes = build_test_elf(&[0x90, 0xC3]);
    let decoder = TestSyntheticDecoder;
    let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes)?;

    let env_arc = JniEnvironment::new();
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));

    let raw_secret = "AndroidJniSecretToken";
    let str_handle = {
        let mut env = env_arc.write().unwrap();
        env.create_string(raw_secret)
    };

    let sym_exprs: Vec<ExprId> = (0..raw_secret.len())
        .map(|idx| {
            arena
                .intern(ExprNode {
                    sort: ExprSort::BitVec(8),
                    op: ExprOp::Symbol,
                    operands: Vec::new(),
                    immediate: (9000 + idx as u64).to_le_bytes().to_vec(),
                })
                .unwrap()
        })
        .collect();

    {
        let mut env = env_arc.write().unwrap();
        env.mark_string_symbolic(str_handle, TaintId(0x7777), TaintLabel::UserInput, sym_exprs.clone());
    }

    // Attach JNI environment to process
    let env_ptr = runtime.attach_jni_environment(&mut process, env_arc.clone())?;
    assert_eq!(env_ptr, JNI_ENV_PTR_ADDR);

    // Verify JNIEnv* struct layout: [JNI_ENV_PTR_ADDR] contains pointer to vtable
    let vtable_ptr_bytes = process
        .state
        .memory
        .read(JNI_ENV_PTR_ADDR, 8)
        .map_err(|e| angryier_runtime::RuntimeError::Memory(format!("{e:?}")))?;
    let mut raw_vtable = [0u8; 8];
    for (i, b) in vtable_ptr_bytes.iter().enumerate() {
        if let ByteValue::Concrete(val) = b {
            raw_vtable[i] = *val;
        }
    }
    let vtable_ptr = u64::from_le_bytes(raw_vtable);
    assert_eq!(vtable_ptr, JNI_VTABLE_ADDR);

    // Verify vtable at GetStringUTFChars slot (index 169) points to stub address
    let stub_slot_addr = JNI_VTABLE_ADDR + (vtable_idx::GET_STRING_UTF_CHARS as u64 * 8);
    let stub_bytes = process
        .state
        .memory
        .read(stub_slot_addr, 8)
        .map_err(|e| angryier_runtime::RuntimeError::Memory(format!("{e:?}")))?;
    let mut raw_stub = [0u8; 8];
    for (i, b) in stub_bytes.iter().enumerate() {
        if let ByteValue::Concrete(val) = b {
            raw_stub[i] = *val;
        }
    }
    let stub_addr = u64::from_le_bytes(raw_stub);
    let expected_stub = JNI_STUB_BASE + (vtable_idx::GET_STRING_UTF_CHARS as u64 * JNI_STUB_STRIDE);
    assert_eq!(stub_addr, expected_stub);

    // Verify process.simproc_instances contains the stub
    assert!(process.simproc_instances.contains_key(&expected_stub));

    // Setup register arguments for calling GetStringUTFChars stub:
    // rdi = env_ptr, rsi = str_handle, rdx = 0
    process.write_register(register_id::GPR_BASE + 7, env_ptr)?; // RDI
    process.write_register(register_id::GPR_BASE + 6, str_handle)?; // RSI
    process.write_register(register_id::GPR_BASE + 2, 0)?; // RDX

    // Setup stack for call return
    let return_pc = 0x400200u64;
    let stack_pointer = process.read_register(register_id::GPR_BASE + 4)? - 8;
    process.write_register(register_id::GPR_BASE + 4, stack_pointer)?;
    process.state.memory = process
        .state
        .memory
        .write(stack_pointer, &return_pc.to_le_bytes().map(ByteValue::Concrete))
        .map_err(|e| angryier_runtime::RuntimeError::Memory(format!("{e:?}")))?;

    // Jump PC to stub address and step
    process.write_pc(expected_stub)?;
    let outcome = runtime.step(&mut process)?;
    assert!(matches!(outcome, angryier_runtime::StepOutcome::SimProcedure { .. }));

    // Verify RAX contains native buffer pointer in JNI heap
    let rax = process.read_register(register_id::GPR_BASE)?;
    assert!(rax >= JNI_HEAP_BASE);

    // Verify PC returned to return_pc and stack popped
    assert_eq!(process.pc()?, return_pc);
    assert_eq!(process.read_register(register_id::GPR_BASE + 4)?, stack_pointer + 8);

    // Verify symbolic taint was written to process.state.memory!
    let mem_bytes = process
        .state
        .memory
        .read(rax, raw_secret.len())
        .map_err(|e| angryier_runtime::RuntimeError::Memory(format!("{e:?}")))?;
    for (i, b) in mem_bytes.iter().enumerate() {
        match b {
            ByteValue::Symbolic(sym_id) => {
                assert_eq!(
                    *sym_id, sym_exprs[i],
                    "byte {i} must carry exact symbolic taint expression"
                );
            }
            ByteValue::Concrete(_) => {
                panic!(
                    "byte {i} at {:#x} should be symbolic due to taint propagation",
                    rax + i as u64
                );
            }
        }
    }

    Ok(())
}
