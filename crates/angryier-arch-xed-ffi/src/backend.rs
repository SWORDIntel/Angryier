//! Native XED decode backend.
//!
//! This module contains all `unsafe` FFI calls to `libxed` (via `xed_sys`). It
//! translates raw XED output into value-only `XedDecodedMetadata` so that no
//! raw `xed_sys` type crosses the public API of this crate. The metadata is then
//! validated and normalized by the safe `angryier-decode-xed` adapter.

use crate::feature::map_feature;
use crate::register::{map_register, map_segment, register_width};
use angryier_decode_xed::metadata::{
    XedAccess, XedDecodedMetadata, XedEncoding, XedFarPointerOperand, XedImmediateOperand, XedInstructionModifiers,
    XedMachineMode, XedMemoryBase, XedMemoryIndex, XedMemoryOperand, XedOperand, XedOperandKind, XedOperandVisibility,
    XedRegisterRef, XedRelativeBranchOperand, XedRepetition,
};
use angryier_decode_xed::{XedAdapterError, XedDecodeBackend, XedDecodeConfig};
use core::ffi::c_uint;
use std::mem::MaybeUninit;
use std::sync::Once;
use xed_sys::{
    XED_ADDRESS_WIDTH_64b, XED_ERROR_NONE, XED_MACHINE_MODE_LONG_64, XED_OPERAND_ABSBR, XED_OPERAND_AGEN,
    XED_OPERAND_IMM0, XED_OPERAND_IMM1, XED_OPERAND_MEM0, XED_OPERAND_MEM1, XED_OPERAND_PTR, XED_OPERAND_REG0,
    XED_OPERAND_REG1, XED_OPERAND_REG2, XED_OPERAND_REG3, XED_OPERAND_REG4, XED_OPERAND_REG5, XED_OPERAND_REG6,
    XED_OPERAND_REG7, XED_OPERAND_REG8, XED_OPERAND_REG9, XED_OPERAND_RELBR, xed_decode, xed_decoded_inst_get_base_reg,
    xed_decoded_inst_get_branch_displacement, xed_decoded_inst_get_branch_displacement_width_bits,
    xed_decoded_inst_get_iclass, xed_decoded_inst_get_immediate_is_signed, xed_decoded_inst_get_immediate_width_bits,
    xed_decoded_inst_get_index_reg, xed_decoded_inst_get_isa_set, xed_decoded_inst_get_length,
    xed_decoded_inst_get_memop_address_width, xed_decoded_inst_get_memory_displacement,
    xed_decoded_inst_get_memory_displacement_width_bits, xed_decoded_inst_get_memory_operand_length,
    xed_decoded_inst_get_reg, xed_decoded_inst_get_scale, xed_decoded_inst_get_seg_reg,
    xed_decoded_inst_get_signed_immediate, xed_decoded_inst_get_unsigned_immediate, xed_decoded_inst_inst,
    xed_decoded_inst_number_of_memory_operands, xed_decoded_inst_operands_const, xed_decoded_inst_set_mode,
    xed_decoded_inst_zero, xed_error_enum_t, xed_inst_noperands, xed_inst_operand, xed_operand_action_enum_t,
    xed_operand_enum_t, xed_operand_name, xed_operand_operand_visibility, xed_operand_rw,
    xed_operand_values_has_lock_prefix, xed_operand_values_has_rep_prefix, xed_operand_values_has_repne_prefix,
    xed_reg_enum_t, xed_tables_init,
};

static XED_INIT: Once = Once::new();

/// Initializes the global XED state tables exactly once.
///
/// XED requires `xed_tables_init()` before any decode or query. The call is
/// idempotent and thread-safe via `std::sync::Once`.
fn ensure_xed_initialized() {
    XED_INIT.call_once(|| unsafe {
        xed_tables_init();
    });
}

/// The native XED decode backend.
///
/// Holds no per-instance state; XED's decode context is constructed locally for
/// each instruction. The type is `Send + Sync` because decoding is stateless
/// once the global tables are initialized.
#[derive(Debug, Default, Clone, Copy)]
pub struct NativeXedBackend;

impl XedDecodeBackend for NativeXedBackend {
    fn decode_metadata(
        &self,
        config: &XedDecodeConfig,
        _address: angryier_types::Address,
        bytes: &[u8],
    ) -> Result<XedDecodedMetadata, XedAdapterError> {
        if bytes.is_empty() {
            return Err(XedAdapterError::EmptyInput);
        }
        if config.mode != XedMachineMode::Intel64 {
            return Err(XedAdapterError::UnsupportedMode);
        }

        ensure_xed_initialized();

        // XED reads at most 15 bytes per instruction.
        let max_bytes = bytes.len().min(15) as c_uint;

        let metadata = unsafe { decode_raw(bytes, max_bytes) }?;

        Ok(metadata)
    }
}

/// Performs the raw FFI decode and metadata extraction.
///
/// # Safety
///
/// Calls into `libxed` via `xed_sys` FFI. The `xed_decoded_inst_t` is fully
/// owned on the stack and initialized before use.
unsafe fn decode_raw(bytes: &[u8], max_bytes: c_uint) -> Result<XedDecodedMetadata, XedAdapterError> {
    let mut xedd = MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
    let xedd_ptr = xedd.as_mut_ptr();

    xed_decoded_inst_zero(xedd_ptr);
    xed_decoded_inst_set_mode(xedd_ptr, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);

    let error: xed_error_enum_t = xed_decode(xedd_ptr, bytes.as_ptr(), max_bytes);
    if error != XED_ERROR_NONE {
        return Err(XedAdapterError::DecodeFailed);
    }

    let length = xed_decoded_inst_get_length(xedd_ptr);
    if length == 0 || length > 15 {
        return Err(XedAdapterError::InvalidLength {
            reported: length as u8,
            available: bytes.len(),
        });
    }

    let iclass = xed_decoded_inst_get_iclass(xedd_ptr);
    let isa_set = xed_decoded_inst_get_isa_set(xedd_ptr);

    // The native bridge owns the mapping from XED's generated form namespace to
    // an engine-owned identifier. We use the instruction class as the stable
    // form identifier; this is a deliberate engine choice, not a raw iform
    // discriminant.
    let form_id = iclass as u32;

    let mut features = Vec::new();
    if let Some(feature) = map_feature(isa_set) {
        features.push(feature);
    }

    let operands = extract_operands(xedd_ptr)?;

    let modifiers = extract_modifiers(xedd_ptr);

    Ok(XedDecodedMetadata {
        length: length as u8,
        form_id,
        features,
        operands,
        modifiers,
    })
}

/// Extracts the operand list from a decoded instruction.
///
/// XED reports memory operands as several sub-operands (MEM0, BASE0, INDEX0,
/// SEG0, DISP0, ...). This function folds the addressing sub-operands into a
/// single `XedOperandKind::Memory` entry and emits register/immediate/branch
/// operands for the remaining operand names.
unsafe fn extract_operands(xedd: *const xed_sys::xed_decoded_inst_t) -> Result<Vec<XedOperand>, XedAdapterError> {
    let inst = xed_decoded_inst_inst(xedd);
    if inst.is_null() {
        return Ok(Vec::new());
    }

    let n_operands = xed_inst_noperands(inst);

    let mut operands = Vec::new();
    let mut next_index: u8 = 0;

    for i in 0..n_operands {
        let op = xed_inst_operand(inst, i);
        if op.is_null() {
            continue;
        }
        let name = xed_operand_name(op);
        let visibility = map_visibility(xed_operand_operand_visibility(op));
        let access = map_access(xed_operand_rw(op));

        let kind = match operand_kind_for_name(xedd, name, access)? {
            Some(kind) => kind,
            None => continue,
        };

        let width_bits = operand_width_bits(xedd, name, &kind);

        let index = next_index;
        next_index = next_index.checked_add(1).ok_or(XedAdapterError::InvalidLength {
            reported: 0,
            available: 0,
        })?;

        operands.push(XedOperand {
            index,
            width_bits,
            access,
            visibility,
            kind,
        });
    }

    Ok(operands)
}

/// Determines the `XedOperandKind` for a given XED operand name.
///
/// Returns `None` for sub-operands that are folded into a memory operand
/// (BASE0, INDEX0, SEG0, DISP0, SCALE, ...) or for registers that do not map to
/// a canonical Angryier register (e.g. `STACKPUSH`/`STACKPOP`).
unsafe fn operand_kind_for_name(
    xedd: *const xed_sys::xed_decoded_inst_t,
    name: xed_operand_enum_t,
    access: XedAccess,
) -> Result<Option<XedOperandKind>, XedAdapterError> {
    match name {
        XED_OPERAND_REG0 | XED_OPERAND_REG1 | XED_OPERAND_REG2 | XED_OPERAND_REG3 | XED_OPERAND_REG4
        | XED_OPERAND_REG5 | XED_OPERAND_REG6 | XED_OPERAND_REG7 | XED_OPERAND_REG8 | XED_OPERAND_REG9 => {
            let reg = xed_decoded_inst_get_reg(xedd, name);
            Ok(map_register(reg).map(|mapped| XedOperandKind::Register(mapped.reference)))
        }
        XED_OPERAND_IMM0 | XED_OPERAND_IMM1 => Ok(Some(extract_immediate(xedd))),
        XED_OPERAND_MEM0 => Ok(extract_memory(xedd, 0, false).map(|kind| adjust_stack_store(xedd, 0, kind, access))),
        XED_OPERAND_MEM1 => Ok(extract_memory(xedd, 1, false).map(|kind| adjust_stack_store(xedd, 1, kind, access))),
        XED_OPERAND_AGEN => Ok(extract_memory(xedd, 0, true)),
        XED_OPERAND_RELBR => Ok(Some(extract_relative_branch(xedd))),
        XED_OPERAND_ABSBR => Ok(Some(extract_absolute_branch(xedd))),
        XED_OPERAND_PTR => Ok(Some(extract_far_pointer(xedd))),
        // All other operand names (BASE0, INDEX0, SEG0, DISP0, SCALE, ...)
        // are addressing sub-operands folded into the MEM0/MEM1 entry.
        _ => Ok(None),
    }
}

/// Adjusts a stack-write memory operand so its effective address is expressed
/// relative to the pre-instruction stack pointer.
///
/// XED models `push`/`call` stack slots at `[RSP]` *after* the stack pointer
/// update, while the execution plane computes operand addresses from the
/// pre-instruction register values. Reporting `[RSP - 8]` keeps both views
/// consistent.
unsafe fn adjust_stack_store(
    xedd: *const xed_sys::xed_decoded_inst_t,
    mem_idx: c_uint,
    kind: XedOperandKind,
    access: XedAccess,
) -> XedOperandKind {
    let XedOperandKind::Memory(mut memory) = kind else {
        return kind;
    };
    // Only the stack-store operand (a write) is re-expressed relative to the
    // pre-instruction stack pointer; an explicit `push [rsp+disp]` source is
    // a read and must keep its encoded displacement.
    if !matches!(access, XedAccess::Write | XedAccess::ReadWrite) {
        return kind;
    }
    let iclass = xed_decoded_inst_get_iclass(xedd);
    let is_stack_write = matches!(iclass, xed_sys::XED_ICLASS_PUSH | xed_sys::XED_ICLASS_CALL_NEAR);
    let base_is_stack_pointer = xed_decoded_inst_get_base_reg(xedd, mem_idx) == xed_sys::XED_REG_RSP;
    if is_stack_write && base_is_stack_pointer {
        memory.displacement = memory.displacement.saturating_sub(8);
    }
    XedOperandKind::Memory(memory)
}

/// Extracts an immediate operand from a decoded instruction.
unsafe fn extract_immediate(xedd: *const xed_sys::xed_decoded_inst_t) -> XedOperandKind {
    let signed = xed_decoded_inst_get_immediate_is_signed(xedd) != 0;
    let value = if signed {
        xed_decoded_inst_get_signed_immediate(xedd) as i64 as u64
    } else {
        xed_decoded_inst_get_unsigned_immediate(xedd)
    };

    XedOperandKind::Immediate(XedImmediateOperand { value, signed })
}

/// Extracts a memory operand (or address-generation operand for `AGEN`) from a
/// decoded instruction at the given memory operand index.
unsafe fn extract_memory(
    xedd: *const xed_sys::xed_decoded_inst_t,
    mem_idx: c_uint,
    address_generation: bool,
) -> Option<XedOperandKind> {
    let n_mem = xed_decoded_inst_number_of_memory_operands(xedd);
    if mem_idx >= n_mem {
        return None;
    }

    let seg_reg: xed_reg_enum_t = xed_decoded_inst_get_seg_reg(xedd, mem_idx);
    let base_reg: xed_reg_enum_t = xed_decoded_inst_get_base_reg(xedd, mem_idx);
    let index_reg: xed_reg_enum_t = xed_decoded_inst_get_index_reg(xedd, mem_idx);
    let scale = xed_decoded_inst_get_scale(xedd, mem_idx) as u8;
    let displacement = xed_decoded_inst_get_memory_displacement(xedd, mem_idx);
    let displacement_width_bits = xed_decoded_inst_get_memory_displacement_width_bits(xedd, mem_idx) as u8;
    let address_width_bits = xed_decoded_inst_get_memop_address_width(xedd, mem_idx) as u16;

    let segment = map_segment(seg_reg);

    let base = if base_reg != 0 {
        match map_register(base_reg) {
            // RIP-relative addressing is relative to the next instruction; the
            // adapter models it as an instruction-pointer base rather than a
            // general-purpose register.
            Some(mapped) if matches!(mapped.reference, XedRegisterRef::InstructionPointer) => {
                Some(XedMemoryBase::InstructionPointer {
                    width_bits: address_width_bits,
                })
            }
            Some(mapped) => Some(XedMemoryBase::Register(mapped.reference)),
            None => None,
        }
    } else {
        None
    };

    let index = if index_reg != 0 {
        map_register(index_reg).map(|mapped| XedMemoryIndex::Register(mapped.reference))
    } else {
        None
    };

    let memory = XedMemoryOperand {
        memory_index: mem_idx as u8,
        address_width_bits,
        segment,
        base,
        index,
        scale,
        displacement,
        displacement_width_bits,
    };

    Some(if address_generation {
        XedOperandKind::AddressGeneration(memory)
    } else {
        XedOperandKind::Memory(memory)
    })
}

/// Extracts a relative branch operand.
unsafe fn extract_relative_branch(xedd: *const xed_sys::xed_decoded_inst_t) -> XedOperandKind {
    let displacement = xed_decoded_inst_get_branch_displacement(xedd);
    let displacement_width_bits = xed_decoded_inst_get_branch_displacement_width_bits(xedd) as u8;

    XedOperandKind::RelativeBranch(XedRelativeBranchOperand {
        displacement,
        displacement_width_bits,
    })
}

/// Extracts an absolute branch operand as a far-pointer operand.
unsafe fn extract_absolute_branch(xedd: *const xed_sys::xed_decoded_inst_t) -> XedOperandKind {
    let displacement = xed_decoded_inst_get_branch_displacement(xedd);
    let width = xed_decoded_inst_get_branch_displacement_width_bits(xedd) as u16;

    XedOperandKind::FarPointer(XedFarPointerOperand {
        segment: 0,
        offset: displacement as u64,
        offset_width_bits: width,
    })
}

/// Extracts a far-pointer operand (PTR).
unsafe fn extract_far_pointer(xedd: *const xed_sys::xed_decoded_inst_t) -> XedOperandKind {
    let displacement = xed_decoded_inst_get_branch_displacement(xedd);
    let width = xed_decoded_inst_get_branch_displacement_width_bits(xedd) as u16;

    XedOperandKind::FarPointer(XedFarPointerOperand {
        segment: 0,
        offset: displacement as u64,
        offset_width_bits: width,
    })
}

/// Computes the width in bits for an operand.
///
/// Register widths are derived from the actual register enumerant (XED's
/// template width is mode-dependent and unreliable for direct use). Memory
/// widths come from the memory operand length. Immediate widths come from the
/// immediate width in bits. Branch/far-pointer widths come from the branch
/// displacement width.
unsafe fn operand_width_bits(
    xedd: *const xed_sys::xed_decoded_inst_t,
    _name: xed_operand_enum_t,
    kind: &XedOperandKind,
) -> u16 {
    match kind {
        XedOperandKind::Register(reference) => register_width(reference),
        XedOperandKind::Memory(memory) | XedOperandKind::AddressGeneration(memory) => {
            let len = xed_decoded_inst_get_memory_operand_length(xedd, memory.memory_index as c_uint);
            (len as u16) * 8
        }
        XedOperandKind::Immediate(_) => xed_decoded_inst_get_immediate_width_bits(xedd) as u16,
        XedOperandKind::RelativeBranch(branch) => branch.displacement_width_bits as u16,
        XedOperandKind::FarPointer(pointer) => pointer.offset_width_bits,
    }
}

/// Extracts instruction modifiers (encoding, lock, repetition) from a decoded
/// instruction.
unsafe fn extract_modifiers(xedd: *const xed_sys::xed_decoded_inst_t) -> XedInstructionModifiers {
    let operand_values = xed_decoded_inst_operands_const(xedd);
    let lock = if !operand_values.is_null() {
        xed_operand_values_has_lock_prefix(operand_values) != 0
    } else {
        false
    };

    let repetition = if !operand_values.is_null() {
        let has_rep = xed_operand_values_has_rep_prefix(operand_values) != 0;
        let has_repne = xed_operand_values_has_repne_prefix(operand_values) != 0;
        if has_repne {
            Some(XedRepetition::Repne)
        } else if has_rep {
            Some(XedRepetition::Repe)
        } else {
            None
        }
    } else {
        None
    };

    // Encoding detection: VEX/EVEX/REX2 detection is a future enhancement.
    // For now, all decoded instructions are reported as Legacy encoding.
    XedInstructionModifiers {
        encoding: XedEncoding::Legacy,
        lock,
        repetition,
        predicate: None,
        rounding: None,
        suppress_all_exceptions: false,
        no_flags: false,
        broadcast: None,
    }
}

/// Maps an XED operand visibility enumerant to Angryier's `XedOperandVisibility`.
fn map_visibility(vis: xed_sys::xed_operand_visibility_enum_t) -> XedOperandVisibility {
    match vis {
        2 => XedOperandVisibility::Implicit,
        3 => XedOperandVisibility::Suppressed,
        _ => XedOperandVisibility::Explicit,
    }
}

/// Maps an XED operand action enumerant to Angryier's `XedAccess`.
fn map_access(action: xed_operand_action_enum_t) -> XedAccess {
    match action {
        // XED_OPERAND_ACTION_R (2)
        2 => XedAccess::Read,
        // XED_OPERAND_ACTION_W (3)
        3 => XedAccess::Write,
        // RW (1), RCW (4), CRW (6) -> ReadWrite
        1 | 4 | 6 => XedAccess::ReadWrite,
        // CW (5) -> Write (conditional write)
        5 => XedAccess::Write,
        // CR (7) -> Read (conditional read)
        7 => XedAccess::Read,
        _ => XedAccess::Read,
    }
}
