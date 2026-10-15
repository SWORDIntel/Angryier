#![forbid(unsafe_code)]

//! JNI (Java Native Interface) environment modeling and symbolic taint propagation.
//!
//! Implements ANG-050 and ANG-051:
//! - Modeling of `JNIEnv*`, Java primitive types (`jint`, `jlong`, `jbyte`, etc.),
//!   and reference handles (`jobject`, `jclass`, `jstring`, `jbyteArray`).
//! - Complete SimProcedures for critical JNIEnv operations:
//!   - `GetStringUTFChars` / `ReleaseStringUTFChars`
//!   - `GetByteArrayElements` / `ReleaseByteArrayElements`
//!   - `GetArrayLength`
//!   - `NewStringUTF`
//!   - `GetStringUTFLength`
//!   - `NewByteArray`
//!   - `GetByteArrayRegion` / `SetByteArrayRegion`
//!   - `GetVersion`, `FindClass`, `GetObjectClass`, `GetMethodID`
//! - Symbolic taint propagation: when an Android Java parameter (`jstring` or `jbyteArray`)
//!   is marked tainted with a `TaintId` and/or symbolic `ExprId`s, the taint is propagated
//!   through `GetStringUTFChars` and `GetByteArrayElements` directly into the allocated
//!   native memory buffer returned to C/C++.
//! - Reverse taint propagation: when native memory buffer carries taint, `NewStringUTF`
//!   and `SetByteArrayRegion` propagate the taint back into the created/updated Java object.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion};
use angryier_models::{SimProcedure, SimProcedureRegistry, SimResult, SimState};
use angryier_taint::TaintLabel;
use angryier_types::{Address, ExprId, ObjectId, TaintId};

use crate::{Process, RuntimeError};

// ---------------------------------------------------------------------------
// Standard JNI Primitive & Reference Types
// ---------------------------------------------------------------------------

#[allow(non_camel_case_types)]
pub type jint = i32;
#[allow(non_camel_case_types)]
pub type jlong = i64;
#[allow(non_camel_case_types)]
pub type jbyte = i8;
#[allow(non_camel_case_types)]
pub type jboolean = u8;
#[allow(non_camel_case_types)]
pub type jchar = u16;
#[allow(non_camel_case_types)]
pub type jshort = i16;
#[allow(non_camel_case_types)]
pub type jfloat = f32;
#[allow(non_camel_case_types)]
pub type jdouble = f64;
#[allow(non_camel_case_types)]
pub type jsize = i32;

#[allow(non_camel_case_types)]
pub type jobject = u64;
#[allow(non_camel_case_types)]
pub type jclass = u64;
#[allow(non_camel_case_types)]
pub type jstring = u64;
#[allow(non_camel_case_types)]
pub type jarray = u64;
#[allow(non_camel_case_types)]
pub type jbyteArray = u64;
#[allow(non_camel_case_types)]
pub type jbooleanArray = u64;
#[allow(non_camel_case_types)]
pub type jcharArray = u64;
#[allow(non_camel_case_types)]
pub type jshortArray = u64;
#[allow(non_camel_case_types)]
pub type jintArray = u64;
#[allow(non_camel_case_types)]
pub type jlongArray = u64;
#[allow(non_camel_case_types)]
pub type jfloatArray = u64;
#[allow(non_camel_case_types)]
pub type jdoubleArray = u64;
#[allow(non_camel_case_types)]
pub type jobjectArray = u64;
#[allow(non_camel_case_types)]
pub type jthrowable = u64;
#[allow(non_camel_case_types)]
pub type jmethodID = u64;
#[allow(non_camel_case_types)]
pub type jfieldID = u64;

pub const JNI_FALSE: jboolean = 0;
pub const JNI_TRUE: jboolean = 1;

pub const JNI_OK: jint = 0;
pub const JNI_ERR: jint = -1;

pub const JNI_COMMIT: jint = 1;
pub const JNI_ABORT: jint = 2;

pub const JNI_VERSION_1_1: jint = 0x00010001;
pub const JNI_VERSION_1_2: jint = 0x00010002;
pub const JNI_VERSION_1_4: jint = 0x00010004;
pub const JNI_VERSION_1_6: jint = 0x00010006;
pub const JNI_VERSION_1_8: jint = 0x00010008;

// ---------------------------------------------------------------------------
// JNI Memory Layout Offsets & Regions
// ---------------------------------------------------------------------------

/// Address where the `JNIEnv*` pointer structure resides in process memory.
pub const JNI_ENV_PTR_ADDR: Address = 0x0000_6000_0000;
/// Address where the `JNINativeInterface` function pointer table resides.
pub const JNI_VTABLE_ADDR: Address = 0x0000_6000_1000;
/// Base address where JNI SimProcedure entry stubs reside.
pub const JNI_STUB_BASE: Address = 0x0000_6000_2000;
/// Byte stride between consecutive JNI stub cells.
pub const JNI_STUB_STRIDE: u64 = 16;
/// Base address for native memory buffers allocated by `GetStringUTFChars` etc.
pub const JNI_HEAP_BASE: Address = 0x0000_6010_0000;
/// Size of the JNI interface region (env pointer + vtable + stubs).
pub const JNI_INTERFACE_REGION_SIZE: u64 = 0x0002_0000; // 128 KiB
/// Size of the JNI native heap region.
pub const JNI_HEAP_REGION_SIZE: u64 = 0x0010_0000; // 1 MiB

// ---------------------------------------------------------------------------
// Standard JNINativeInterface Function Indices
// ---------------------------------------------------------------------------

pub mod vtable_idx {
    pub const GET_VERSION: usize = 4;
    pub const DEFINE_CLASS: usize = 5;
    pub const FIND_CLASS: usize = 6;
    pub const GET_OBJECT_CLASS: usize = 31;
    pub const GET_METHOD_ID: usize = 33;
    pub const GET_STATIC_METHOD_ID: usize = 113;
    pub const NEW_STRING_UTF: usize = 167;
    pub const GET_STRING_UTF_LENGTH: usize = 168;
    pub const GET_STRING_UTF_CHARS: usize = 169;
    pub const RELEASE_STRING_UTF_CHARS: usize = 170;
    pub const GET_ARRAY_LENGTH: usize = 171;
    pub const NEW_BYTE_ARRAY: usize = 176;
    pub const GET_BYTE_ARRAY_ELEMENTS: usize = 184;
    pub const RELEASE_BYTE_ARRAY_ELEMENTS: usize = 192;
    pub const GET_BYTE_ARRAY_REGION: usize = 199;
    pub const SET_BYTE_ARRAY_REGION: usize = 207;
    pub const TOTAL_ENTRIES: usize = 256;
}

// ---------------------------------------------------------------------------
// Java Object Models
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JavaValue {
    Boolean(bool),
    Byte(i8),
    Char(u16),
    Short(i16),
    Int(i32),
    Long(i64),
    Float(u32),
    Double(u64),
    Object(jobject),
    Void,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JavaObject {
    Class {
        name: String,
    },
    String {
        value: String,
        tainted: bool,
        taint_id: Option<TaintId>,
        label: Option<TaintLabel>,
        symbolic_bytes: Option<Vec<ExprId>>,
    },
    ByteArray {
        data: Vec<u8>,
        tainted: bool,
        taint_id: Option<TaintId>,
        label: Option<TaintLabel>,
        symbolic_bytes: Option<Vec<ExprId>>,
        symbolic_length: Option<ExprId>,
    },
    Object {
        class_name: String,
        fields: BTreeMap<String, JavaValue>,
    },
}

// ---------------------------------------------------------------------------
// Taint Tracking & Native Buffer Management
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintedMemoryByte {
    pub taint_id: TaintId,
    pub label: TaintLabel,
    pub symbol: Option<ExprId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintedBuffer {
    pub base: Address,
    pub size: usize,
    pub taint_id: TaintId,
    pub label: TaintLabel,
    pub source_handle: jobject,
    pub source_type: &'static str,
    pub symbolic_bytes: Option<Vec<ExprId>>,
}

#[derive(Clone, Debug, Default)]
pub struct JniTaintTracker {
    pub byte_taint: BTreeMap<Address, TaintedMemoryByte>,
    pub buffers: BTreeMap<Address, TaintedBuffer>,
}

impl JniTaintTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_buffer(
        &mut self,
        base: Address,
        size: usize,
        taint_id: TaintId,
        label: TaintLabel,
        source_handle: jobject,
        source_type: &'static str,
        symbolic_bytes: Option<Vec<ExprId>>,
    ) {
        let syms_ref = symbolic_bytes.clone();
        self.buffers.insert(
            base,
            TaintedBuffer {
                base,
                size,
                taint_id,
                label,
                source_handle,
                source_type,
                symbolic_bytes,
            },
        );

        for i in 0..size {
            let addr = base.wrapping_add(i as u64);
            let symbol = syms_ref.as_ref().and_then(|s| s.get(i).copied());
            self.byte_taint.insert(
                addr,
                TaintedMemoryByte {
                    taint_id,
                    label,
                    symbol,
                },
            );
        }
    }

    pub fn is_memory_tainted(&self, addr: Address) -> bool {
        self.byte_taint.contains_key(&addr)
    }

    pub fn is_range_tainted(&self, base: Address, len: usize) -> bool {
        for i in 0..len {
            if self.byte_taint.contains_key(&base.wrapping_add(i as u64)) {
                return true;
            }
        }
        false
    }

    pub fn get_byte_taint(&self, addr: Address) -> Option<&TaintedMemoryByte> {
        self.byte_taint.get(&addr)
    }

    pub fn get_buffer(&self, addr: Address) -> Option<&TaintedBuffer> {
        for buf in self.buffers.values() {
            if addr >= buf.base && addr < buf.base.wrapping_add(buf.size as u64) {
                return Some(buf);
            }
        }
        None
    }

    pub fn clear_range(&mut self, base: Address, len: usize) {
        for i in 0..len {
            self.byte_taint.remove(&base.wrapping_add(i as u64));
        }
        self.buffers.remove(&base);
    }
}

#[derive(Clone, Debug)]
pub struct JniNativeBuffer {
    pub base: Address,
    pub size: usize,
    pub source_object: jobject,
    pub is_string: bool,
    pub released: bool,
}

// ---------------------------------------------------------------------------
// JNI Environment
// ---------------------------------------------------------------------------

pub struct JniEnvironment {
    pub objects: BTreeMap<jobject, JavaObject>,
    next_handle: u64,
    pub native_buffers: BTreeMap<Address, JniNativeBuffer>,
    heap_cursor: Address,
    pub taint_tracker: JniTaintTracker,
    pub env_ptr: Address,
    pub vtable_ptr: Address,
    pub stubs_base: Address,
}

impl JniEnvironment {
    pub fn new() -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            objects: BTreeMap::new(),
            next_handle: 0x1000,
            native_buffers: BTreeMap::new(),
            heap_cursor: JNI_HEAP_BASE,
            taint_tracker: JniTaintTracker::new(),
            env_ptr: JNI_ENV_PTR_ADDR,
            vtable_ptr: JNI_VTABLE_ADDR,
            stubs_base: JNI_STUB_BASE,
        }))
    }

    fn allocate_handle(&mut self) -> jobject {
        let handle = self.next_handle;
        self.next_handle = self.next_handle.wrapping_add(8);
        handle
    }

    // ── Object Factory APIs ──────────────────────────────────────────────────

    pub fn create_string(&mut self, value: &str) -> jstring {
        let handle = self.allocate_handle();
        self.objects.insert(
            handle,
            JavaObject::String {
                value: value.to_string(),
                tainted: false,
                taint_id: None,
                label: None,
                symbolic_bytes: None,
            },
        );
        handle
    }

    pub fn create_byte_array(&mut self, data: Vec<u8>) -> jbyteArray {
        let handle = self.allocate_handle();
        self.objects.insert(
            handle,
            JavaObject::ByteArray {
                data,
                tainted: false,
                taint_id: None,
                label: None,
                symbolic_bytes: None,
                symbolic_length: None,
            },
        );
        handle
    }

    pub fn create_class(&mut self, name: &str) -> jclass {
        let handle = self.allocate_handle();
        self.objects.insert(
            handle,
            JavaObject::Class {
                name: name.to_string(),
            },
        );
        handle
    }

    // ── Taint Annotation APIs ───────────────────────────────────────────────

    pub fn mark_string_tainted(&mut self, handle: jstring, taint_id: TaintId, label: TaintLabel) {
        if let Some(JavaObject::String {
            tainted,
            taint_id: id_slot,
            label: label_slot,
            ..
        }) = self.objects.get_mut(&handle)
        {
            *tainted = true;
            *id_slot = Some(taint_id);
            *label_slot = Some(label);
        }
    }

    pub fn mark_string_symbolic(
        &mut self,
        handle: jstring,
        taint_id: TaintId,
        label: TaintLabel,
        symbols: Vec<ExprId>,
    ) {
        if let Some(JavaObject::String {
            tainted,
            taint_id: id_slot,
            label: label_slot,
            symbolic_bytes,
            ..
        }) = self.objects.get_mut(&handle)
        {
            *tainted = true;
            *id_slot = Some(taint_id);
            *label_slot = Some(label);
            *symbolic_bytes = Some(symbols);
        }
    }

    pub fn mark_byte_array_tainted(&mut self, handle: jbyteArray, taint_id: TaintId, label: TaintLabel) {
        if let Some(JavaObject::ByteArray {
            tainted,
            taint_id: id_slot,
            label: label_slot,
            ..
        }) = self.objects.get_mut(&handle)
        {
            *tainted = true;
            *id_slot = Some(taint_id);
            *label_slot = Some(label);
        }
    }

    pub fn mark_byte_array_symbolic(
        &mut self,
        handle: jbyteArray,
        taint_id: TaintId,
        label: TaintLabel,
        symbols: Vec<ExprId>,
        symbol_len: Option<ExprId>,
    ) {
        if let Some(JavaObject::ByteArray {
            tainted,
            taint_id: id_slot,
            label: label_slot,
            symbolic_bytes,
            symbolic_length,
            ..
        }) = self.objects.get_mut(&handle)
        {
            *tainted = true;
            *id_slot = Some(taint_id);
            *label_slot = Some(label);
            *symbolic_bytes = Some(symbols);
            *symbolic_length = symbol_len;
        }
    }

    pub fn is_handle_tainted(&self, handle: jobject) -> bool {
        match self.objects.get(&handle) {
            Some(JavaObject::String { tainted, .. }) => *tainted,
            Some(JavaObject::ByteArray { tainted, .. }) => *tainted,
            _ => false,
        }
    }

    pub fn get_string(&self, handle: jstring) -> Option<&str> {
        match self.objects.get(&handle) {
            Some(JavaObject::String { value, .. }) => Some(value.as_str()),
            _ => None,
        }
    }

    pub fn get_byte_array(&self, handle: jbyteArray) -> Option<&[u8]> {
        match self.objects.get(&handle) {
            Some(JavaObject::ByteArray { data, .. }) => Some(data.as_slice()),
            _ => None,
        }
    }

    // ── Native Heap Allocation ──────────────────────────────────────────────

    pub fn allocate_native_buffer(
        &mut self,
        size: usize,
        source_object: jobject,
        is_string: bool,
    ) -> Address {
        let addr = self.heap_cursor;
        // Align to 16 bytes.
        let aligned_size = (size + 15) & !15;
        self.heap_cursor = self.heap_cursor.wrapping_add(aligned_size as u64);

        self.native_buffers.insert(
            addr,
            JniNativeBuffer {
                base: addr,
                size,
                source_object,
                is_string,
                released: false,
            },
        );
        addr
    }

    // ── SimProcedure Implementations ────────────────────────────────────────
}

/// Extracts the argument at `index` (0-based) for a JNI function call.
///
/// In System V AMD64 ABI:
/// - Arg 0: RDI (GPR 7)
/// - Arg 1: RSI (GPR 6)
/// - Arg 2: RDX (GPR 2)
/// - Arg 3: RCX (GPR 1)
/// - Arg 4: R8 (GPR 8)
/// - Arg 5: R9 (GPR 9)
///
/// If ABI registers are present (RDI or RSI non-zero, as populated by runtime register bridging),
/// the ABI register mapping is used. Otherwise, direct positional arguments
/// (from `SimState::set_arg` or `SimState::get_arg`) are used.
pub fn get_jni_arg(state: &SimState, index: usize) -> u64 {
    let rdi = state.get_reg(7);
    let rsi = state.get_reg(6);
    if rdi != 0 || rsi != 0 {
        match index {
            0 => rdi,
            1 => rsi,
            2 => state.get_reg(2),
            3 => state.get_reg(1),
            4 => state.get_reg(8),
            5 => state.get_reg(9),
            _ => state.get_arg(index),
        }
    } else {
        state.get_arg(index)
    }
}

impl JniEnvironment {

    /// `GetStringUTFChars(JNIEnv *env, jstring str, jboolean *isCopy)`
    /// Arg 0: env, Arg 1: str, Arg 2: isCopy
    pub fn get_string_utf_chars(&mut self, state: &SimState) -> SimResult {
        let str_handle = get_jni_arg(state, 1);
        let is_copy_ptr = get_jni_arg(state, 2);

        let (val_bytes, tainted, taint_id, label, sym_bytes) = match self.objects.get(&str_handle) {
            Some(JavaObject::String {
                value,
                tainted,
                taint_id,
                label,
                symbolic_bytes,
            }) => (
                value.as_bytes().to_vec(),
                *tainted,
                *taint_id,
                *label,
                symbolic_bytes.clone(),
            ),
            _ => {
                let mut next = state.clone();
                next.set_reg(0, 0); // NULL
                next.return_value = Some(0);
                return SimResult::Continue(next);
            }
        };

        let mut data = val_bytes;
        let str_len = data.len();
        data.push(0); // Null terminator

        let buf_addr = self.allocate_native_buffer(data.len(), str_handle, true);

        // Propagate taint if source jstring was marked tainted!
        if tainted {
            let tid = taint_id.unwrap_or(TaintId(1));
            let lbl = label.unwrap_or(TaintLabel::UserInput);
            self.taint_tracker.record_buffer(
                buf_addr,
                str_len, // mark the string characters tainted
                tid,
                lbl,
                str_handle,
                "jstring",
                sym_bytes,
            );
        }

        let mut next = state.clone();
        next.write_memory(buf_addr, data);

        if is_copy_ptr != 0 {
            next.write_memory(is_copy_ptr, vec![JNI_TRUE]);
        }

        next.set_reg(0, buf_addr);
        next.return_value = Some(buf_addr);
        SimResult::Continue(next)
    }

    /// `ReleaseStringUTFChars(JNIEnv *env, jstring str, const char* chars)`
    /// Arg 0: env, Arg 1: str, Arg 2: chars
    pub fn release_string_utf_chars(&mut self, state: &SimState) -> SimResult {
        let chars_ptr = get_jni_arg(state, 2);
        if let Some(buf) = self.native_buffers.get_mut(&chars_ptr) {
            buf.released = true;
        }

        let mut next = state.clone();
        next.set_reg(0, 0);
        next.return_value = Some(0);
        SimResult::Continue(next)
    }

    /// `GetByteArrayElements(JNIEnv *env, jbyteArray array, jboolean *isCopy)`
    /// Arg 0: env, Arg 1: array, Arg 2: isCopy
    pub fn get_byte_array_elements(&mut self, state: &SimState) -> SimResult {
        let array_handle = get_jni_arg(state, 1);
        let is_copy_ptr = get_jni_arg(state, 2);

        let (data, tainted, taint_id, label, sym_bytes) = match self.objects.get(&array_handle) {
            Some(JavaObject::ByteArray {
                data,
                tainted,
                taint_id,
                label,
                symbolic_bytes,
                ..
            }) => (
                data.clone(),
                *tainted,
                *taint_id,
                *label,
                symbolic_bytes.clone(),
            ),
            _ => {
                let mut next = state.clone();
                next.set_reg(0, 0);
                next.return_value = Some(0);
                return SimResult::Continue(next);
            }
        };

        let len = data.len();
        let buf_addr = self.allocate_native_buffer(len.max(1), array_handle, false);

        // Propagate taint if source jbyteArray was marked tainted!
        if tainted {
            let tid = taint_id.unwrap_or(TaintId(1));
            let lbl = label.unwrap_or(TaintLabel::UserInput);
            self.taint_tracker.record_buffer(
                buf_addr,
                len,
                tid,
                lbl,
                array_handle,
                "jbyteArray",
                sym_bytes,
            );
        }

        let mut next = state.clone();
        if !data.is_empty() {
            next.write_memory(buf_addr, data);
        }

        if is_copy_ptr != 0 {
            next.write_memory(is_copy_ptr, vec![JNI_TRUE]);
        }

        next.set_reg(0, buf_addr);
        next.return_value = Some(buf_addr);
        SimResult::Continue(next)
    }

    /// `ReleaseByteArrayElements(JNIEnv *env, jbyteArray array, jbyte *elems, jint mode)`
    /// Arg 0: env, Arg 1: array, Arg 2: elems, Arg 3: mode
    pub fn release_byte_array_elements(&mut self, state: &SimState) -> SimResult {
        let array_handle = get_jni_arg(state, 1);
        let elems_ptr = get_jni_arg(state, 2);
        let mode = get_jni_arg(state, 3) as jint;

        let buf_size = self
            .native_buffers
            .get(&elems_ptr)
            .map(|b| b.size)
            .unwrap_or(0);

        // Mode 0 (commit and free) or Mode 1 (commit, no free): copy back to Java array
        if (mode == 0 || mode == JNI_COMMIT) && buf_size > 0 {
            let updated_bytes = state.read_bytes(elems_ptr, buf_size);
            let is_tainted = self.taint_tracker.is_range_tainted(elems_ptr, buf_size);
            let taint_id = self
                .taint_tracker
                .get_buffer(elems_ptr)
                .map(|b| b.taint_id);

            if let Some(JavaObject::ByteArray {
                data,
                tainted,
                taint_id: id_slot,
                ..
            }) = self.objects.get_mut(&array_handle)
            {
                *data = updated_bytes;
                if is_tainted {
                    *tainted = true;
                    if taint_id.is_some() {
                        *id_slot = taint_id;
                    }
                }
            }
        }

        // Mode 0 (free) or Mode 2 (abort, free): mark released
        if mode == 0 || mode == JNI_ABORT {
            if let Some(buf) = self.native_buffers.get_mut(&elems_ptr) {
                buf.released = true;
            }
        }

        let mut next = state.clone();
        next.set_reg(0, 0);
        next.return_value = Some(0);
        SimResult::Continue(next)
    }

    /// `GetArrayLength(JNIEnv *env, jarray array)`
    /// Arg 0: env, Arg 1: array
    pub fn get_array_length(&mut self, state: &SimState) -> SimResult {
        let array_handle = get_jni_arg(state, 1);
        let len = match self.objects.get(&array_handle) {
            Some(JavaObject::ByteArray { data, .. }) => data.len() as u64,
            _ => 0,
        };

        let mut next = state.clone();
        next.set_reg(0, len);
        next.return_value = Some(len);
        SimResult::Continue(next)
    }

    /// `NewStringUTF(JNIEnv *env, const char *bytes)`
    /// Arg 0: env, Arg 1: bytes
    pub fn new_string_utf(&mut self, state: &SimState) -> SimResult {
        let bytes_ptr = get_jni_arg(state, 1);
        let raw_bytes = state.read_null_terminated_string(bytes_ptr, 65536);
        let text = String::from_utf8_lossy(&raw_bytes).to_string();

        // Check if native buffer carries taint!
        let is_tainted = self.taint_tracker.is_range_tainted(bytes_ptr, raw_bytes.len());
        let taint_meta = self.taint_tracker.get_buffer(bytes_ptr).cloned();

        let handle = self.allocate_handle();
        let (taint_id, label, sym_bytes) = if let Some(meta) = taint_meta {
            (Some(meta.taint_id), Some(meta.label), meta.symbolic_bytes)
        } else if is_tainted {
            let first_byte = self.taint_tracker.get_byte_taint(bytes_ptr);
            let tid = first_byte.map(|b| b.taint_id).unwrap_or(TaintId(1));
            let lbl = first_byte.map(|b| b.label).unwrap_or(TaintLabel::Derived);
            (Some(tid), Some(lbl), None)
        } else {
            (None, None, None)
        };

        self.objects.insert(
            handle,
            JavaObject::String {
                value: text,
                tainted: is_tainted,
                taint_id,
                label,
                symbolic_bytes: sym_bytes,
            },
        );

        let mut next = state.clone();
        next.set_reg(0, handle);
        next.return_value = Some(handle);
        SimResult::Continue(next)
    }

    /// `GetStringUTFLength(JNIEnv *env, jstring str)`
    /// Arg 0: env, Arg 1: str
    pub fn get_string_utf_length(&mut self, state: &SimState) -> SimResult {
        let str_handle = get_jni_arg(state, 1);
        let len = match self.objects.get(&str_handle) {
            Some(JavaObject::String { value, .. }) => value.len() as u64,
            _ => 0,
        };

        let mut next = state.clone();
        next.set_reg(0, len);
        next.return_value = Some(len);
        SimResult::Continue(next)
    }

    /// `NewByteArray(JNIEnv *env, jsize len)`
    /// Arg 0: env, Arg 1: len
    pub fn new_byte_array(&mut self, state: &SimState) -> SimResult {
        let len = (get_jni_arg(state, 1) as i32).max(0) as usize;
        let data = vec![0u8; len];
        let handle = self.create_byte_array(data);

        let mut next = state.clone();
        next.set_reg(0, handle);
        next.return_value = Some(handle);
        SimResult::Continue(next)
    }

    /// `GetByteArrayRegion(JNIEnv *env, jbyteArray array, jsize start, jsize len, jbyte *buf)`
    /// Arg 0: env, Arg 1: array, Arg 2: start, Arg 3: len, Arg 4: buf
    pub fn get_byte_array_region(&mut self, state: &SimState) -> SimResult {
        let array_handle = get_jni_arg(state, 1);
        let start = (get_jni_arg(state, 2) as i32).max(0) as usize;
        let len = (get_jni_arg(state, 3) as i32).max(0) as usize;
        let buf_ptr = get_jni_arg(state, 4);

        let mut next = state.clone();

        if let Some(JavaObject::ByteArray {
            data,
            tainted,
            taint_id,
            label,
            symbolic_bytes,
            ..
        }) = self.objects.get(&array_handle)
        {
            if start + len <= data.len() {
                let slice = data[start..start + len].to_vec();
                next.write_memory(buf_ptr, slice);

                if *tainted {
                    let tid = taint_id.unwrap_or(TaintId(1));
                    let lbl = label.unwrap_or(TaintLabel::UserInput);
                    let sub_syms = symbolic_bytes.as_ref().and_then(|s| {
                        if start + len <= s.len() {
                            Some(s[start..start + len].to_vec())
                        } else {
                            None
                        }
                    });
                    self.taint_tracker.record_buffer(
                        buf_ptr,
                        len,
                        tid,
                        lbl,
                        array_handle,
                        "jbyteArray",
                        sub_syms,
                    );
                }
            }
        }

        next.set_reg(0, 0);
        next.return_value = Some(0);
        SimResult::Continue(next)
    }

    /// `SetByteArrayRegion(JNIEnv *env, jbyteArray array, jsize start, jsize len, const jbyte *buf)`
    /// Arg 0: env, Arg 1: array, Arg 2: start, Arg 3: len, Arg 4: buf
    pub fn set_byte_array_region(&mut self, state: &SimState) -> SimResult {
        let array_handle = get_jni_arg(state, 1);
        let start = (get_jni_arg(state, 2) as i32).max(0) as usize;
        let len = (get_jni_arg(state, 3) as i32).max(0) as usize;
        let buf_ptr = get_jni_arg(state, 4);

        let src_bytes = state.read_bytes(buf_ptr, len);
        let is_tainted = self.taint_tracker.is_range_tainted(buf_ptr, len);
        let taint_meta = self.taint_tracker.get_buffer(buf_ptr).cloned();

        if let Some(JavaObject::ByteArray {
            data,
            tainted,
            taint_id: id_slot,
            label: label_slot,
            ..
        }) = self.objects.get_mut(&array_handle)
        {
            if start + len <= data.len() {
                data[start..start + len].copy_from_slice(&src_bytes);
                if is_tainted {
                    *tainted = true;
                    if let Some(meta) = taint_meta {
                        *id_slot = Some(meta.taint_id);
                        *label_slot = Some(meta.label);
                    }
                }
            }
        }

        let mut next = state.clone();
        next.set_reg(0, 0);
        next.return_value = Some(0);
        SimResult::Continue(next)
    }

    // ── Setup & Memory Synchronization ──────────────────────────────────────

    /// Wires the JNI interface, vtable, and stub regions into `process`, registering
    /// all JNI SimProcedures at their canonical offsets. Returns the `JNIEnv*` pointer.
    pub fn setup_in_process(
        this: Arc<RwLock<Self>>,
        process: &mut Process,
    ) -> Result<Address, RuntimeError> {
        let (env_ptr, vtable_ptr, stubs_base) = {
            let guard = this
                .read()
                .map_err(|e| RuntimeError::Environment(format!("{e:?}")))?;
            (guard.env_ptr, guard.vtable_ptr, guard.stubs_base)
        };

        // 1. Map JNI Interface memory region (JNIEnv* + vtable + stubs).
        let iface_region = MemoryRegion {
            object: ObjectId(200),
            base: env_ptr,
            size: JNI_INTERFACE_REGION_SIZE,
            readable: true,
            writable: true,
            executable: true,
        };
        process.state.memory = process
            .state
            .memory
            .with_region(iface_region)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // 2. Map JNI Native Heap region.
        let heap_region = MemoryRegion {
            object: ObjectId(201),
            base: JNI_HEAP_BASE,
            size: JNI_HEAP_REGION_SIZE,
            readable: true,
            writable: true,
            executable: false,
        };
        process.state.memory = process
            .state
            .memory
            .with_region(heap_region)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // 3. Write JNIEnv struct: pointer to JNINativeInterface vtable at env_ptr.
        process.state.memory = process
            .state
            .memory
            .load_concrete(env_ptr, &vtable_ptr.to_le_bytes())
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // 4. Populate vtable and register SimProcedure instances for all function slots.
        let mut vtable_bytes = vec![0u8; vtable_idx::TOTAL_ENTRIES * 8];
        let default_stub = Arc::new(GetVersionProcedure);

        for idx in 0..vtable_idx::TOTAL_ENTRIES {
            let stub_addr = stubs_base + (idx as u64 * JNI_STUB_STRIDE);
            vtable_bytes[idx * 8..(idx + 1) * 8].copy_from_slice(&stub_addr.to_le_bytes());

            // Write 16-byte stub cell (`ret; nop; ...`).
            let mut stub_code = [0x90u8; JNI_STUB_STRIDE as usize];
            stub_code[0] = 0xC3; // ret
            process.state.memory = process
                .state
                .memory
                .load_concrete(stub_addr, &stub_code)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

            let proc: Arc<dyn SimProcedure> = match idx {
                vtable_idx::GET_VERSION => Arc::new(GetVersionProcedure),
                vtable_idx::FIND_CLASS => Arc::new(FindClassProcedure::new(this.clone())),
                vtable_idx::GET_OBJECT_CLASS => Arc::new(GetObjectClassProcedure::new(this.clone())),
                vtable_idx::GET_METHOD_ID => Arc::new(GetMethodIDProcedure),
                vtable_idx::GET_STATIC_METHOD_ID => Arc::new(GetStaticMethodIDProcedure),
                vtable_idx::NEW_STRING_UTF => Arc::new(NewStringUTFProcedure::new(this.clone())),
                vtable_idx::GET_STRING_UTF_LENGTH => Arc::new(GetStringUTFLengthProcedure::new(this.clone())),
                vtable_idx::GET_STRING_UTF_CHARS => Arc::new(GetStringUTFCharsProcedure::new(this.clone())),
                vtable_idx::RELEASE_STRING_UTF_CHARS => Arc::new(ReleaseStringUTFCharsProcedure::new(this.clone())),
                vtable_idx::GET_ARRAY_LENGTH => Arc::new(GetArrayLengthProcedure::new(this.clone())),
                vtable_idx::NEW_BYTE_ARRAY => Arc::new(NewByteArrayProcedure::new(this.clone())),
                vtable_idx::GET_BYTE_ARRAY_ELEMENTS => Arc::new(GetByteArrayElementsProcedure::new(this.clone())),
                vtable_idx::RELEASE_BYTE_ARRAY_ELEMENTS => Arc::new(ReleaseByteArrayElementsProcedure::new(this.clone())),
                vtable_idx::GET_BYTE_ARRAY_REGION => Arc::new(GetByteArrayRegionProcedure::new(this.clone())),
                vtable_idx::SET_BYTE_ARRAY_REGION => Arc::new(SetByteArrayRegionProcedure::new(this.clone())),
                _ => default_stub.clone(),
            };

            process.simproc_instances.insert(stub_addr, proc);
        }

        // Write the complete vtable into process memory.
        process.state.memory = process
            .state
            .memory
            .load_concrete(vtable_ptr, &vtable_bytes)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        Ok(env_ptr)
    }

    /// Propagates symbolic expressions from `taint_tracker` into `memory`
    /// as `ByteValue::Symbolic(expr_id)`.
    pub fn apply_symbolic_memory_taint(
        &self,
        memory: &mut angryier_memory::PersistentMemory,
    ) -> Result<(), RuntimeError> {
        for buf in self.taint_tracker.buffers.values() {
            if let Some(syms) = &buf.symbolic_bytes {
                let values: Vec<ByteValue> = syms.iter().map(|&e| ByteValue::Symbolic(e)).collect();
                *memory = memory
                    .write(buf.base, &values)
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Standalone SimProcedure Wrappers
// ---------------------------------------------------------------------------

pub struct GetStringUTFCharsProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl GetStringUTFCharsProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for GetStringUTFCharsProcedure {
    fn name(&self) -> &'static str {
        "GetStringUTFChars"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.get_string_utf_chars(state)
    }
}

pub struct ReleaseStringUTFCharsProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl ReleaseStringUTFCharsProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for ReleaseStringUTFCharsProcedure {
    fn name(&self) -> &'static str {
        "ReleaseStringUTFChars"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.release_string_utf_chars(state)
    }
}

pub struct GetByteArrayElementsProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl GetByteArrayElementsProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for GetByteArrayElementsProcedure {
    fn name(&self) -> &'static str {
        "GetByteArrayElements"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.get_byte_array_elements(state)
    }
}

pub struct ReleaseByteArrayElementsProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl ReleaseByteArrayElementsProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for ReleaseByteArrayElementsProcedure {
    fn name(&self) -> &'static str {
        "ReleaseByteArrayElements"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.release_byte_array_elements(state)
    }
}

pub struct GetArrayLengthProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl GetArrayLengthProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for GetArrayLengthProcedure {
    fn name(&self) -> &'static str {
        "GetArrayLength"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.get_array_length(state)
    }
}

pub struct NewStringUTFProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl NewStringUTFProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for NewStringUTFProcedure {
    fn name(&self) -> &'static str {
        "NewStringUTF"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.new_string_utf(state)
    }
}

pub struct GetStringUTFLengthProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl GetStringUTFLengthProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for GetStringUTFLengthProcedure {
    fn name(&self) -> &'static str {
        "GetStringUTFLength"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.get_string_utf_length(state)
    }
}

pub struct NewByteArrayProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl NewByteArrayProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for NewByteArrayProcedure {
    fn name(&self) -> &'static str {
        "NewByteArray"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.new_byte_array(state)
    }
}

pub struct GetByteArrayRegionProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl GetByteArrayRegionProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for GetByteArrayRegionProcedure {
    fn name(&self) -> &'static str {
        "GetByteArrayRegion"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.get_byte_array_region(state)
    }
}

pub struct SetByteArrayRegionProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl SetByteArrayRegionProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for SetByteArrayRegionProcedure {
    fn name(&self) -> &'static str {
        "SetByteArrayRegion"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        guard.set_byte_array_region(state)
    }
}

pub struct GetVersionProcedure;

impl SimProcedure for GetVersionProcedure {
    fn name(&self) -> &'static str {
        "GetVersion"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut next = state.clone();
        next.set_reg(0, JNI_VERSION_1_6 as u64);
        next.return_value = Some(JNI_VERSION_1_6 as u64);
        SimResult::Continue(next)
    }
}

pub struct FindClassProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl FindClassProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for FindClassProcedure {
    fn name(&self) -> &'static str {
        "FindClass"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let name_ptr = get_jni_arg(state, 1);
        let name_bytes = state.read_null_terminated_string(name_ptr, 1024);
        let name = String::from_utf8_lossy(&name_bytes).to_string();

        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        let handle = guard.create_class(&name);

        let mut next = state.clone();
        next.set_reg(0, handle);
        next.return_value = Some(handle);
        SimResult::Continue(next)
    }
}

pub struct GetObjectClassProcedure {
    pub env: Arc<RwLock<JniEnvironment>>,
}

impl GetObjectClassProcedure {
    pub fn new(env: Arc<RwLock<JniEnvironment>>) -> Self {
        Self { env }
    }
}

impl SimProcedure for GetObjectClassProcedure {
    fn name(&self) -> &'static str {
        "GetObjectClass"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mut guard = self.env.write().unwrap_or_else(|e| e.into_inner());
        let handle = guard.create_class("java/lang/Object");

        let mut next = state.clone();
        next.set_reg(0, handle);
        next.return_value = Some(handle);
        SimResult::Continue(next)
    }
}

pub struct GetMethodIDProcedure;

impl SimProcedure for GetMethodIDProcedure {
    fn name(&self) -> &'static str {
        "GetMethodID"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        // Return deterministic non-null jmethodID handle
        let method_id: u64 = 0x7000_1000;
        let mut next = state.clone();
        next.set_reg(0, method_id);
        next.return_value = Some(method_id);
        SimResult::Continue(next)
    }
}

pub struct GetStaticMethodIDProcedure;

impl SimProcedure for GetStaticMethodIDProcedure {
    fn name(&self) -> &'static str {
        "GetStaticMethodID"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let method_id: u64 = 0x7000_2000;
        let mut next = state.clone();
        next.set_reg(0, method_id);
        next.return_value = Some(method_id);
        SimResult::Continue(next)
    }
}

/// Registers all standard JNI procedures into a `SimProcedureRegistry`.
pub fn register_jni_procedures(
    registry: &mut SimProcedureRegistry,
    env: Arc<RwLock<JniEnvironment>>,
) {
    registry.register(Box::new(GetStringUTFCharsProcedure::new(env.clone())));
    registry.register(Box::new(ReleaseStringUTFCharsProcedure::new(env.clone())));
    registry.register(Box::new(GetByteArrayElementsProcedure::new(env.clone())));
    registry.register(Box::new(ReleaseByteArrayElementsProcedure::new(env.clone())));
    registry.register(Box::new(GetArrayLengthProcedure::new(env.clone())));
    registry.register(Box::new(NewStringUTFProcedure::new(env.clone())));
    registry.register(Box::new(GetStringUTFLengthProcedure::new(env.clone())));
    registry.register(Box::new(NewByteArrayProcedure::new(env.clone())));
    registry.register(Box::new(GetByteArrayRegionProcedure::new(env.clone())));
    registry.register(Box::new(SetByteArrayRegionProcedure::new(env.clone())));
    registry.register(Box::new(GetVersionProcedure));
    registry.register(Box::new(FindClassProcedure::new(env.clone())));
    registry.register(Box::new(GetObjectClassProcedure::new(env)));
    registry.register(Box::new(GetMethodIDProcedure));
    registry.register(Box::new(GetStaticMethodIDProcedure));
}
