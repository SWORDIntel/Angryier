//! Native XED decode backend.
//!
//! This module contains all `unsafe` FFI calls to `libxed` (via `xed_sys`). It
//! translates raw XED output into value-only `XedDecodedMetadata` so that no
//! raw `xed_sys` type crosses the public API of this crate. The metadata is then
//! validated and normalized by the safe `angryier-decode-xed` adapter.

use crate::feature::map_feature;
use crate::register::{map_register, map_segment, register_width};
use angryier_decode_xed::metadata::{
    XedAccess, XedDecodedMetadata, XedEncoding, XedFarPointerOperand, XedIformMetadata, XedImmediateOperand,
    XedInstructionModifiers, XedMachineMode, XedMemoryBase, XedMemoryIndex, XedMemoryOperand, XedOperand,
    XedOperandKind, XedOperandVisibility, XedRegisterRef, XedRelativeBranchOperand, XedRepetition,
};
use angryier_decode_xed::{XedAdapterError, XedDecodeBackend, XedDecodeConfig};
use core::ffi::{CStr, c_uint};
use std::mem::MaybeUninit;
use std::sync::Once;
use xed_sys::{
    XED_ADDRESS_WIDTH_16b, XED_ADDRESS_WIDTH_32b, XED_ADDRESS_WIDTH_64b, XED_ERROR_NONE, XED_MACHINE_MODE_LEGACY_16,
    XED_MACHINE_MODE_LEGACY_32, XED_MACHINE_MODE_LONG_64, XED_OPERAND_ABSBR, XED_OPERAND_AGEN, XED_OPERAND_IMM0,
    XED_OPERAND_IMM1, XED_OPERAND_MEM0, XED_OPERAND_MEM1, XED_OPERAND_PTR, XED_OPERAND_REG0, XED_OPERAND_REG1,
    XED_OPERAND_REG2, XED_OPERAND_REG3, XED_OPERAND_REG4, XED_OPERAND_REG5, XED_OPERAND_REG6, XED_OPERAND_REG7,
    XED_OPERAND_REG8, XED_OPERAND_REG9, XED_OPERAND_RELBR, xed_address_width_enum_t, xed_decode,
    xed_decoded_inst_get_base_reg, xed_decoded_inst_get_branch_displacement,
    xed_decoded_inst_get_branch_displacement_width_bits, xed_decoded_inst_get_iclass, xed_decoded_inst_get_iform_enum,
    xed_decoded_inst_get_immediate_is_signed, xed_decoded_inst_get_immediate_width_bits,
    xed_decoded_inst_get_index_reg, xed_decoded_inst_get_isa_set, xed_decoded_inst_get_length,
    xed_decoded_inst_get_memop_address_width, xed_decoded_inst_get_memory_displacement,
    xed_decoded_inst_get_memory_displacement_width_bits, xed_decoded_inst_get_memory_operand_length,
    xed_decoded_inst_get_reg, xed_decoded_inst_get_scale, xed_decoded_inst_get_seg_reg,
    xed_decoded_inst_get_signed_immediate, xed_decoded_inst_get_unsigned_immediate, xed_decoded_inst_inst,
    xed_decoded_inst_number_of_memory_operands, xed_decoded_inst_operands_const, xed_decoded_inst_set_mode,
    xed_decoded_inst_zero, xed_error_enum_t, xed_iform_enum_t2str, xed_inst_noperands, xed_inst_operand,
    xed_machine_mode_enum_t, xed_operand_action_enum_t, xed_operand_enum_t, xed_operand_name,
    xed_operand_operand_visibility, xed_operand_rw, xed_operand_values_has_lock_prefix,
    xed_operand_values_has_rep_prefix, xed_operand_values_has_repne_prefix, xed_reg_enum_t, xed_tables_init,
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
        let (machine_mode, stack_address_width) = xed_mode(config.mode);

        ensure_xed_initialized();

        // XED reads at most 15 bytes per instruction.
        let max_bytes = bytes.len().min(15) as c_uint;

        let metadata = unsafe { decode_raw(bytes, max_bytes, machine_mode, stack_address_width) }?;

        Ok(metadata)
    }
}

/// Maps an engine [`XedMachineMode`] to the raw XED machine mode and stack
/// addressing width passed to `xed_decoded_inst_set_mode`.
///
/// XED's decoder state pairs a machine mode (default operand width and
/// addressing model) with a separate stack addressing width; for every mode
/// other than 64-bit long mode that width must be supplied explicitly. The
/// mapping follows the mode selection used by XED's own decoder examples
/// (`LEGACY_32`/`32b` for 32-bit, `LEGACY_16`/`16b` for 16-bit).
fn xed_mode(mode: XedMachineMode) -> (xed_machine_mode_enum_t, xed_address_width_enum_t) {
    match mode {
        XedMachineMode::Intel64 => (XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b),
        XedMachineMode::Legacy32 => (XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b),
        XedMachineMode::Legacy16 => (XED_MACHINE_MODE_LEGACY_16, XED_ADDRESS_WIDTH_16b),
    }
}

/// Performs the raw FFI decode and metadata extraction.
///
/// # Safety
///
/// Calls into `libxed` via `xed_sys` FFI. The `xed_decoded_inst_t` is fully
/// owned on the stack and initialized before use.
unsafe fn decode_raw(
    bytes: &[u8],
    max_bytes: c_uint,
    machine_mode: xed_machine_mode_enum_t,
    stack_address_width: xed_address_width_enum_t,
) -> Result<XedDecodedMetadata, XedAdapterError> {
    let mut xedd = MaybeUninit::<xed_sys::xed_decoded_inst_t>::uninit();
    let xedd_ptr = xedd.as_mut_ptr();

    xed_decoded_inst_zero(xedd_ptr);
    xed_decoded_inst_set_mode(xedd_ptr, machine_mode, stack_address_width);
    xed_sys::xed3_operand_set_cet(xedd_ptr, 1);

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
    let xed_iform_value = xed_decoded_inst_get_iform_enum(xedd_ptr);
    let xed_iform_name_ptr = xed_iform_enum_t2str(xed_iform_value);
    if xed_iform_name_ptr.is_null() {
        return Err(XedAdapterError::InvalidIformMetadata);
    }
    let xed_iform = XedIformMetadata {
        xed_sys_version: "xed-sys 0.6.0+xed-2024.05.20",
        name: format!("XED_IFORM_{}", CStr::from_ptr(xed_iform_name_ptr).to_string_lossy()),
        value: xed_iform_value as u32,
    };

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
        xed_iform,
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
            if (xed_sys::XED_REG_DFV0..=xed_sys::XED_REG_DFV15).contains(&reg) {
                let val = (reg - xed_sys::XED_REG_DFV0) as u64;
                return Ok(Some(XedOperandKind::Immediate(XedImmediateOperand {
                    value: val,
                    signed: false,
                })));
            }
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
        XedOperandKind::Immediate(_) => {
            let width = xed_decoded_inst_get_immediate_width_bits(xedd) as u16;
            if width == 0 { 8 } else { width }
        }
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

    let zeroing = unsafe { xed_sys::xed_decoded_inst_zeroing(xedd) != 0 };
    let mask_reg = unsafe { xed_sys::xed_decoded_inst_get_reg(xedd, xed_sys::XED_OPERAND_REG1) };
    let predicate = if (crate::register::REG_K0 + 1..=crate::register::REG_K0 + 7).contains(&mask_reg) {
        Some(angryier_decode_xed::metadata::XedPredicateMask {
            register: angryier_decode_xed::metadata::XedRegisterRef::Opmask {
                index: (mask_reg - crate::register::REG_K0) as u8,
            },
            zeroing,
        })
    } else {
        None
    };

    let vexvalid = unsafe { xed_sys::xed3_operand_get_vexvalid(xedd) };
    let rex2 = unsafe { xed_sys::xed3_operand_get_rex2(xedd) != 0 };
    let encoding = if rex2 {
        XedEncoding::Rex2
    } else {
        match vexvalid {
            1 => XedEncoding::Vex,
            2 => XedEncoding::Evex,
            _ => XedEncoding::Legacy,
        }
    };

    let no_flags = unsafe {
        xed_sys::xed_decoded_inst_get_attribute(xedd, xed_sys::XED_ATTRIBUTE_APX_NF) != 0
            || xed_sys::xed3_operand_get_nf(xedd) != 0
    };

    XedInstructionModifiers {
        encoding,
        lock,
        repetition,
        predicate,
        rounding: None,
        suppress_all_exceptions: false,
        no_flags,
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

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch_intel64::{FeatureSet, Intel64ProfileKind, Intel64TargetProfile};
    use angryier_decode_xed::metadata::XedGprView;
    use angryier_types::TargetProfileId;

    fn config(mode: XedMachineMode) -> XedDecodeConfig {
        XedDecodeConfig {
            mode,
            profile: Intel64TargetProfile {
                id: TargetProfileId(1),
                kind: Intel64ProfileKind::Custom,
                features: FeatureSet {
                    features: Vec::new(),
                    xcr0: 0,
                },
            },
        }
    }

    /// Returns the register kind + view of the first explicit register operand.
    fn first_gpr(metadata: &XedDecodedMetadata) -> (u8, XedGprView, u16) {
        for operand in &metadata.operands {
            if let XedOperandKind::Register(XedRegisterRef::Gpr { index, view }) = operand.kind {
                return (index, view, operand.width_bits);
            }
        }
        panic!("expected a register operand in {metadata:?}");
    }

    #[test]
    fn live_decode_preserves_version_scoped_xed_iform_evidence() {
        let backend = NativeXedBackend;
        let config = config(XedMachineMode::Intel64);

        // Names/values are from the pinned XED generated enum tables and
        // checked against live decode results from that same build.
        for (bytes, name, value, engine_form) in [
            (&[0x90][..], "XED_IFORM_NOP_90", 1735, xed_sys::XED_ICLASS_NOP),
            (
                &[0x48, 0x89, 0xc1][..],
                "XED_IFORM_MOV_GPRv_GPRv_89",
                1560,
                xed_sys::XED_ICLASS_MOV,
            ),
        ] {
            let metadata = backend.decode_metadata(&config, 0, bytes).expect("XED decode succeeds");
            assert_eq!(metadata.xed_iform.xed_sys_version, "xed-sys 0.6.0+xed-2024.05.20");
            assert_eq!(metadata.xed_iform.name, name);
            assert_eq!(metadata.xed_iform.value, value);
            assert_eq!(metadata.form_id, engine_form);
        }
    }

    /// The same bytes must decode differently under different declared modes:
    /// `0x40` is a bare REX prefix in 64-bit mode (undecodable alone) but
    /// `inc r/eAX` in the legacy modes. This proves `config.mode` reaches
    /// `xed_decoded_inst_set_mode`.
    #[test]
    fn byte_0x40_decodes_by_machine_mode() {
        let backend = NativeXedBackend;

        assert_eq!(
            backend.decode_metadata(&config(XedMachineMode::Intel64), 0, &[0x40]),
            Err(XedAdapterError::DecodeFailed)
        );

        for (mode, expected_index, expected_view, expected_width) in [
            (XedMachineMode::Legacy32, 0u8, XedGprView::Dword, 32u16),
            (XedMachineMode::Legacy16, 0u8, XedGprView::Word, 16u16),
        ] {
            let metadata = backend
                .decode_metadata(&config(mode), 0, &[0x40])
                .expect("legacy mode decodes 0x40 as INC");
            assert_eq!(metadata.length, 1);
            assert_eq!(metadata.form_id, xed_sys::XED_ICLASS_INC);
            assert_eq!(first_gpr(&metadata), (expected_index, expected_view, expected_width));
        }
    }

    /// The operand-size prefix `0x66` flips the default operand width, which
    /// itself comes from the declared machine mode: identical bytes produce a
    /// 32-bit register pair in 16-bit mode and a 16-bit pair elsewhere.
    #[test]
    fn identical_prefixed_bytes_flip_width_per_mode() {
        let backend = NativeXedBackend;
        let bytes = &[0x66, 0x89, 0xd8]; // MOV r/m, r with operand-size override

        let metadata = backend
            .decode_metadata(&config(XedMachineMode::Legacy16), 0, bytes)
            .expect("legacy-16 decode succeeds");
        assert_eq!(metadata.length, 3);
        assert_eq!(metadata.form_id, xed_sys::XED_ICLASS_MOV);
        assert_eq!(first_gpr(&metadata), (0, XedGprView::Dword, 32));

        for mode in [XedMachineMode::Legacy32, XedMachineMode::Intel64] {
            let metadata = backend
                .decode_metadata(&config(mode), 0, bytes)
                .expect("decode succeeds");
            assert_eq!(metadata.length, 3);
            assert_eq!(metadata.form_id, xed_sys::XED_ICLASS_MOV);
            assert_eq!(first_gpr(&metadata), (0, XedGprView::Word, 16));
        }
    }

    /// Address-size and base-register selection are machine-mode properties:
    /// `8B 07` is `mov ax, [bx]` / `mov eax, [edi]` / `mov eax, [rdi]` purely
    /// by declared mode. XED metadata must reflect the mode's addressing.
    #[test]
    fn memory_addressing_follows_machine_mode() {
        let backend = NativeXedBackend;
        let bytes = &[0x8b, 0x07];

        for (mode, address_width, base_index, base_view) in [
            (XedMachineMode::Legacy16, 16u16, 3u8, XedGprView::Word),
            (XedMachineMode::Legacy32, 32u16, 7u8, XedGprView::Dword),
            (XedMachineMode::Intel64, 64u16, 7u8, XedGprView::Qword),
        ] {
            let metadata = backend
                .decode_metadata(&config(mode), 0, bytes)
                .expect("decode succeeds");
            assert_eq!(metadata.form_id, xed_sys::XED_ICLASS_MOV);
            let memory = metadata
                .operands
                .iter()
                .find_map(|operand| match &operand.kind {
                    XedOperandKind::Memory(memory) => Some(memory),
                    _ => None,
                })
                .expect("mov decodes a memory operand");
            assert_eq!(memory.address_width_bits, address_width);
            match memory.base {
                Some(XedMemoryBase::Register(XedRegisterRef::Gpr { index, view })) => {
                    assert_eq!((index, view), (base_index, base_view));
                }
                other => panic!("unexpected memory base {other:?}"),
            }
        }
    }

    /// Immediate width is a machine-mode property: `B8` takes a 16-bit
    /// immediate in 16-bit mode (3-byte instruction) but a 32-bit immediate
    /// elsewhere, so the truncated 3-byte form fails closed.
    #[test]
    fn immediate_width_and_truncation_follow_mode() {
        let backend = NativeXedBackend;
        let bytes = &[0xb8, 0x34, 0x12];

        let metadata = backend
            .decode_metadata(&config(XedMachineMode::Legacy16), 0, bytes)
            .expect("legacy-16 decodes mov ax, imm16");
        assert_eq!(metadata.length, 3);
        assert_eq!(metadata.form_id, xed_sys::XED_ICLASS_MOV);
        let immediate = metadata
            .operands
            .iter()
            .find_map(|operand| match &operand.kind {
                XedOperandKind::Immediate(immediate) => Some(immediate),
                _ => None,
            })
            .expect("mov decodes an immediate operand");
        assert_eq!(immediate.value, 0x1234);

        for mode in [XedMachineMode::Legacy32, XedMachineMode::Intel64] {
            assert_eq!(
                backend.decode_metadata(&config(mode), 0, bytes),
                Err(XedAdapterError::DecodeFailed)
            );
        }
    }

    /// IFORM evidence and feature metadata must stay version-scoped and valid
    /// in every supported mode.
    #[test]
    fn mode_specific_metadata_stays_valid() {
        let backend = NativeXedBackend;

        for mode in [
            XedMachineMode::Intel64,
            XedMachineMode::Legacy32,
            XedMachineMode::Legacy16,
        ] {
            let metadata = backend
                .decode_metadata(&config(mode), 0, &[0x90])
                .expect("nop decodes in every mode");
            assert_eq!(metadata.length, 1);
            assert_eq!(metadata.form_id, xed_sys::XED_ICLASS_NOP);
            assert_eq!(metadata.xed_iform.xed_sys_version, "xed-sys 0.6.0+xed-2024.05.20");
            assert!(metadata.xed_iform.name.starts_with("XED_IFORM_"));
            assert!(metadata.xed_iform.value != 0);
        }
    }

    /// Invalid inputs fail closed in every supported mode: empty input is
    /// `EmptyInput` and undecodable/truncated byte strings are `DecodeFailed`.
    #[test]
    fn invalid_inputs_fail_closed_in_all_modes() {
        let backend = NativeXedBackend;

        for mode in [
            XedMachineMode::Intel64,
            XedMachineMode::Legacy32,
            XedMachineMode::Legacy16,
        ] {
            assert_eq!(
                backend.decode_metadata(&config(mode), 0, &[]),
                Err(XedAdapterError::EmptyInput)
            );
            // A bare two-byte opcode lead with no second byte is undecodable.
            assert_eq!(
                backend.decode_metadata(&config(mode), 0, &[0x0f]),
                Err(XedAdapterError::DecodeFailed)
            );
        }
    }

    /// Full normalization still works end-to-end for modes whose memory
    /// operands fit the normalized model (32/64-bit addressing).
    #[test]
    fn bound_decoder_normalizes_legacy32_memory() {
        use angryier_arch::{Decoder, MemoryBase, OperandKind};
        use angryier_decode_xed::{BoundXedDecoder, XedDecoderAdapter};

        let decoder = BoundXedDecoder {
            adapter: XedDecoderAdapter {
                config: config(XedMachineMode::Legacy32),
            },
            backend: NativeXedBackend,
        };

        // 8B 03: mov eax, [ebx] — 32-bit addressing survives normalization.
        let decoded = decoder.decode(0x1000, &[0x8b, 0x03]).expect("decode succeeds");
        let memory = decoded
            .operands
            .iter()
            .find_map(|operand| match &operand.kind {
                OperandKind::Memory(memory) => Some(memory),
                _ => None,
            })
            .expect("memory operand present");
        assert_eq!(memory.address_width_bits, 32);
        let Some(MemoryBase::Register(base)) = memory.base else {
            panic!("expected a register base");
        };
        assert_eq!(base.width_bits, 32);

        // 16-bit addressing is outside the normalized model and fails closed
        // at the adapter boundary rather than producing a malformed operand.
        let decoder = BoundXedDecoder {
            adapter: XedDecoderAdapter {
                config: config(XedMachineMode::Legacy16),
            },
            backend: NativeXedBackend,
        };
        assert_eq!(
            decoder.decode(0x1000, &[0x8b, 0x07]),
            Err(XedAdapterError::InvalidMemoryAddressWidth(16))
        );
        // Non-memory 16-bit decodes still normalize.
        let decoded = decoder.decode(0x1000, &[0x89, 0xd8]).expect("decode succeeds");
        assert_eq!(decoded.length, 2);
        assert!(matches!(decoded.operands[0].kind, OperandKind::Register(_)));
    }
}
