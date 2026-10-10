//! Focused tests for opt-in XED machine-mode selection through the public
//! runtime decoder.
//!
//! `Runtime::with_native_xed` pins the decoder to 64-bit long mode.
//! `Runtime::with_native_xed_mode` exposes XED's machine mode so the same
//! byte strings decode the way a legacy decoder would read them. These tests
//! pin the decode contract only — `DecodedInstruction` fields returned by
//! `runtime.decoder.decode` — not execution semantics, which stay Intel 64
//! regardless of decode mode.
#![cfg(feature = "xed")]

use angryier_arch::{DecodedInstruction, Decoder, OperandKind};
use angryier_arch_intel64::register_id;
use angryier_arch_xed_ffi::{XedAdapterError, XedDecoder, XedMachineMode};
use angryier_runtime::{Runtime, XedFormTranslator, form_map};
use angryier_semantics_intel64::forms;
use angryier_types::{SemanticVersion, TargetProfileId};

type XedRuntime = Runtime<XedFormTranslator<XedDecoder>>;

fn runtime(mode: XedMachineMode) -> XedRuntime {
    Runtime::with_native_xed_mode(SemanticVersion(1), TargetProfileId(1), mode)
}

/// Register view of the first explicit register operand, if any.
fn first_register(decoded: &DecodedInstruction) -> Option<&angryier_arch::RegisterView> {
    decoded.operands.iter().find_map(|operand| match &operand.kind {
        OperandKind::Register(register) => Some(register),
        _ => None,
    })
}

/// First immediate operand, if any.
fn first_immediate(decoded: &DecodedInstruction) -> Option<angryier_arch::ImmediateOperand> {
    decoded.operands.iter().find_map(|operand| match &operand.kind {
        OperandKind::Immediate(immediate) => Some(*immediate),
        _ => None,
    })
}

/// `0x40` is `inc ax`/`inc eax` in the legacy modes but a bare REX prefix —
/// an incomplete, undecodable instruction on its own — in 64-bit long mode.
/// This proves `XedMachineMode` reaches `xed_decoded_inst_set_mode` through
/// the public runtime decoder, and that the default constructor stays
/// pinned to Intel 64.
#[test]
fn byte_0x40_decodes_by_machine_mode() -> Result<(), XedAdapterError> {
    // Default constructor: byte-for-byte Intel 64 behavior.
    let default = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    assert_eq!(
        default.decoder.decode(0x1000, &[0x40]),
        Err(XedAdapterError::DecodeFailed),
        "default with_native_xed is Intel64: a bare REX prefix fails closed"
    );

    let intel64 = runtime(XedMachineMode::Intel64);
    assert_eq!(
        intel64.decoder.decode(0x1000, &[0x40]),
        Err(XedAdapterError::DecodeFailed)
    );

    let legacy32 = runtime(XedMachineMode::Legacy32);
    let decoded32 = legacy32.decoder.decode(0x1000, &[0x40])?;
    assert_eq!(decoded32.length, 1);
    assert_eq!(decoded32.form_id, forms::INC_R32);
    let reg32 = first_register(&decoded32);
    assert!(reg32.is_some(), "inc eax reports a register operand");
    if let Some(register) = reg32 {
        assert_eq!(register.parent.0, register_id::GPR_BASE);
        assert_eq!(register.width_bits, 32);
    }

    let legacy16 = runtime(XedMachineMode::Legacy16);
    let decoded16 = legacy16.decoder.decode(0x1000, &[0x40])?;
    assert_eq!(decoded16.length, 1);
    assert_eq!(decoded16.form_id, forms::INC_R16);
    let reg16 = first_register(&decoded16);
    assert!(reg16.is_some(), "inc ax reports a register operand");
    if let Some(register) = reg16 {
        assert_eq!(register.parent.0, register_id::GPR_BASE);
        assert_eq!(register.width_bits, 16);
    }

    Ok(())
}

/// Immediate and operand width follow the mode's default operand size:
/// `B8` is `mov eAX, imm32` under a 32-bit default (Intel64, Legacy32) and
/// `mov aX, imm16` under a 16-bit default (Legacy16), so the five-byte tail
/// is only fully consumed by the 32-bit-default modes.
#[test]
fn mov_immediate_width_follows_default_operand_size() -> Result<(), XedAdapterError> {
    let bytes = &[0xb8, 0x78, 0x56, 0x34, 0x12];

    for mode in [XedMachineMode::Intel64, XedMachineMode::Legacy32] {
        let decoded = runtime(mode).decoder.decode(0x1000, bytes)?;
        assert_eq!(decoded.length, 5, "{mode:?}: mov eAX, imm32 is 5 bytes");
        assert_eq!(decoded.form_id, forms::MOV_R32_IMM32, "{mode:?}");
        let register = first_register(&decoded);
        assert!(register.is_some());
        if let Some(register) = register {
            assert_eq!(register.width_bits, 32, "{mode:?}");
        }
        let immediate = first_immediate(&decoded);
        assert_eq!(immediate.map(|imm| imm.value), Some(0x1234_5678), "{mode:?}");
    }

    let decoded16 = runtime(XedMachineMode::Legacy16).decoder.decode(0x1000, bytes)?;
    assert_eq!(decoded16.length, 3, "legacy16: mov ax, imm16 is 3 bytes");
    assert_eq!(decoded16.form_id, forms::MOV_R16_IMM16);
    let register = first_register(&decoded16);
    assert!(register.is_some());
    if let Some(register) = register {
        assert_eq!(register.width_bits, 16);
    }
    let immediate = first_immediate(&decoded16);
    assert_eq!(immediate.map(|imm| imm.value), Some(0x5678));

    Ok(())
}

/// The operand-size prefix `0x66` flips the mode's default width in opposite
/// directions: it narrows to 16 bits under a 32-bit default and widens to
/// 32 bits under a 16-bit default.
#[test]
fn operand_size_prefix_flips_per_mode() -> Result<(), XedAdapterError> {
    let bytes = &[0x66, 0xb8, 0x78, 0x56, 0x34, 0x12];

    for mode in [XedMachineMode::Intel64, XedMachineMode::Legacy32] {
        let decoded = runtime(mode).decoder.decode(0x1000, bytes)?;
        assert_eq!(decoded.length, 4, "{mode:?}: mov ax, imm16 is 4 bytes");
        assert_eq!(decoded.form_id, forms::MOV_R16_IMM16, "{mode:?}");
        let register = first_register(&decoded);
        if let Some(register) = register {
            assert_eq!(register.width_bits, 16, "{mode:?}");
        }
        assert_eq!(first_immediate(&decoded).map(|imm| imm.value), Some(0x5678), "{mode:?}");
    }

    let decoded16 = runtime(XedMachineMode::Legacy16).decoder.decode(0x1000, bytes)?;
    assert_eq!(decoded16.length, 6, "legacy16: mov eax, imm32 is 6 bytes");
    assert_eq!(decoded16.form_id, forms::MOV_R32_IMM32);
    let register = first_register(&decoded16);
    if let Some(register) = register {
        assert_eq!(register.width_bits, 32);
    }
    assert_eq!(first_immediate(&decoded16).map(|imm| imm.value), Some(0x1234_5678));

    Ok(())
}

/// One byte string, three different decodes: `48 B8` is REX.W + `mov r64,
/// imm64` in long mode, while `0x48` itself is `dec eAX`/`dec aX` in the
/// legacy modes — the only imm64 form in the ISA exists solely in 64-bit.
#[test]
fn rex_imm64_decode_differs_in_every_mode() -> Result<(), XedAdapterError> {
    let bytes = &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    let intel64 = runtime(XedMachineMode::Intel64).decoder.decode(0x1000, bytes)?;
    assert_eq!(intel64.length, 10, "mov rax, imm64 is 10 bytes");
    assert_eq!(intel64.form_id, forms::MOV_R64_IMM64);
    let register = first_register(&intel64);
    if let Some(register) = register {
        assert_eq!(register.width_bits, 64);
    }
    assert_eq!(
        first_immediate(&intel64).map(|imm| imm.value),
        Some(0x1122_3344_5566_7788)
    );

    let legacy32 = runtime(XedMachineMode::Legacy32).decoder.decode(0x1000, bytes)?;
    assert_eq!(legacy32.length, 1, "0x48 is dec eax in legacy-32");
    assert_eq!(legacy32.form_id, forms::DEC_R32);
    let register = first_register(&legacy32);
    if let Some(register) = register {
        assert_eq!(register.width_bits, 32);
    }

    let legacy16 = runtime(XedMachineMode::Legacy16).decoder.decode(0x1000, bytes)?;
    assert_eq!(legacy16.length, 1, "0x48 is dec ax in legacy-16");
    // `dec r16` decodes fine but has no corpus form: the semantic corpus is
    // Intel 64 scoped, so unmapped forms report the sentinel.
    assert_eq!(legacy16.form_id, form_map::UNMAPPED_FORM_ID);
    let register = first_register(&legacy16);
    if let Some(register) = register {
        assert_eq!(register.width_bits, 16);
    }

    // All three modes produced pairwise-distinct decodes.
    assert_ne!(intel64.form_id, legacy32.form_id);
    assert_ne!(legacy32.form_id, legacy16.form_id);
    assert_ne!(intel64.form_id, legacy16.form_id);

    Ok(())
}

/// Unsupported and truncated inputs fail closed in every mode: empty input
/// is `EmptyInput`, a bare two-byte opcode lead is `DecodeFailed`, and the
/// far-jump `0xEA` — defined only in the legacy modes — fails closed under
/// 64-bit long mode.
#[test]
fn unsupported_or_truncated_bytes_fail_closed() -> Result<(), XedAdapterError> {
    let bytes = &[0x0f]; // opcode lead with no second byte
    for mode in [
        XedMachineMode::Intel64,
        XedMachineMode::Legacy32,
        XedMachineMode::Legacy16,
    ] {
        let runtime = runtime(mode);
        assert_eq!(
            runtime.decoder.decode(0x1000, &[]),
            Err(XedAdapterError::EmptyInput),
            "{mode:?}: empty input fails closed"
        );
        assert_eq!(
            runtime.decoder.decode(0x1000, bytes),
            Err(XedAdapterError::DecodeFailed),
            "{mode:?}: truncated opcode fails closed"
        );
        // ModRM-needing opcode with no ModRM byte is also undecodable.
        assert_eq!(
            runtime.decoder.decode(0x1000, &[0xff]),
            Err(XedAdapterError::DecodeFailed),
            "{mode:?}: truncated modrm fails closed"
        );
    }

    // `EA ptr16:16/32` far jump exists only in legacy modes; in long mode it
    // is undefined and must fail closed rather than decode as anything else.
    let bytes = &[0xea, 0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a];
    let intel64 = runtime(XedMachineMode::Intel64);
    assert_eq!(
        intel64.decoder.decode(0x1000, bytes),
        Err(XedAdapterError::DecodeFailed)
    );

    // The same bytes are a valid far jump in the legacy modes — mode-gated
    // validity, not bad bytes — with the encoded offset sized by the mode.
    let legacy32 = runtime(XedMachineMode::Legacy32).decoder.decode(0x1000, bytes)?;
    assert_eq!(legacy32.length, 7, "jmp far ptr16:32 is 7 bytes");
    let offset32 = legacy32.operands.iter().find_map(|operand| match &operand.kind {
        OperandKind::FarPointer(pointer) => Some(*pointer),
        _ => None,
    });
    assert!(offset32.is_some(), "far jump reports a far-pointer operand");
    if let Some(pointer) = offset32 {
        assert_eq!(pointer.offset, 0x1234_5678);
        assert_eq!(pointer.offset_width_bits, 32);
    }

    let legacy16 = runtime(XedMachineMode::Legacy16).decoder.decode(0x1000, bytes)?;
    assert_eq!(legacy16.length, 5, "jmp far ptr16:16 is 5 bytes");
    let offset16 = legacy16.operands.iter().find_map(|operand| match &operand.kind {
        OperandKind::FarPointer(pointer) => Some(*pointer),
        _ => None,
    });
    assert!(offset16.is_some(), "far jump reports a far-pointer operand");
    if let Some(pointer) = offset16 {
        assert_eq!(pointer.offset, 0x5678);
        assert_eq!(pointer.offset_width_bits, 16);
    }
    Ok(())
}

/// `with_native_xed` stays byte-for-byte compatible with the Intel 64 mode:
/// both constructors produce identical `DecodedInstruction`s, including
/// form-id translation.
#[test]
fn default_constructor_matches_explicit_intel64_mode() -> Result<(), XedAdapterError> {
    let default = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let explicit = runtime(XedMachineMode::Intel64);

    for bytes in [
        &[0x90][..],                                                       // nop
        &[0x48, 0x89, 0xc1][..],                                           // mov rcx, rax
        &[0x48, 0xb8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11][..], // mov rax, imm64
        &[0x0f][..],                                                       // undecodable
    ] {
        assert_eq!(
            default.decoder.decode(0x1000, bytes),
            explicit.decoder.decode(0x1000, bytes),
            "{bytes:02x?} must decode identically"
        );
    }
    Ok(())
}
