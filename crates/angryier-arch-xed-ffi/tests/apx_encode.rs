//! Test-only XED encoder harness.
//!
//! Regenerates the canonical APX byte sequences pinned by the
//! `decode_apx_instructions` unit test with the raw `xed-sys` encoder and
//! round-trips every result through the bridge decoder. This proves both
//! directions: XED's encoder emits exactly the pinned bytes for these operand
//! tuples, and the native bridge decodes them back into the expected shape.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind};
use angryier_arch_xed_ffi::XedDecoder;

/// One encoder request operand: a register slot, an imm8, an imm64, or the
/// APX NF (no-flags) modifier request.
enum EncOp {
    Reg(u32, xed_sys::xed_reg_enum_t),
    Imm(u64),
    Imm64(u64),
    Nf,
}

/// Encodes `iclass` with the given operand sequence in 64-bit mode.
///
/// `operand_width` is the effective operand width in bits (32/64).
///
/// # Safety
///
/// Calls into `libxed` via `xed_sys` FFI with a fully owned, zeroed encoder
/// request.
unsafe fn encode(iclass: xed_sys::xed_iclass_enum_t, operand_width: u32, ops: &[EncOp]) -> Result<Vec<u8>, String> {
    use xed_sys::*;
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| unsafe { xed_tables_init() });
    let mut req: xed_encoder_request_t = std::mem::zeroed();
    xed_encoder_request_zero(&mut req);
    xed_decoded_inst_set_mode(&mut req, XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b);
    xed_encoder_request_set_iclass(&mut req, iclass);
    xed_encoder_request_set_effective_operand_width(&mut req, operand_width as xed_uint_t);
    let mut order = 0usize;
    for op in ops {
        match *op {
            EncOp::Reg(name, reg) => {
                xed_encoder_request_set_reg(&mut req, name, reg);
                xed_encoder_request_set_operand_order(&mut req, order as xed_uint_t, name);
                order += 1;
            }
            EncOp::Imm(value) => {
                xed_encoder_request_set_uimm0_bits(&mut req, value, 8);
                xed_encoder_request_set_operand_order(&mut req, order as xed_uint_t, XED_OPERAND_IMM0);
                order += 1;
            }
            EncOp::Imm64(value) => {
                xed_encoder_request_set_uimm0_bits(&mut req, value, 64);
                xed_encoder_request_set_operand_order(&mut req, order as xed_uint_t, XED_OPERAND_IMM0);
                order += 1;
            }
            EncOp::Nf => {
                xed3_operand_set_nf(&mut req, 1);
            }
        }
    }
    let mut buf = [0u8; 15];
    let mut olen: xed_uint_t = 0;
    let err = xed_encode(&mut req, buf.as_mut_ptr(), 15, &mut olen);
    if err == XED_ERROR_NONE {
        Ok(buf[..olen as usize].to_vec())
    } else {
        Err(format!("encode error {err:?}"))
    }
}

/// Encodes `iclass` with `ops`, asserts the output equals the canonical
/// `expected` bytes, and decodes the result through the bridge.
///
/// # Panics
///
/// On any encoder error, non-canonical output, or decode failure.
fn round_trip(
    label: &str,
    expected: &[u8],
    iclass: xed_sys::xed_iclass_enum_t,
    operand_width: u32,
    ops: &[EncOp],
) -> DecodedInstruction {
    let bytes = unsafe { encode(iclass, operand_width, ops) }
        .unwrap_or_else(|error| panic!("{label}: encoder rejected the form ({error})"));
    assert_eq!(bytes, expected, "{label}: encoder produced non-canonical bytes");
    let decoded = XedDecoder::new()
        .decode(0x1000, &bytes)
        .unwrap_or_else(|error| panic!("{label}: round-trip decode failed ({error:?})"));
    assert_eq!(decoded.form_id, iclass, "{label}: wrong decoded iclass");
    decoded
}

/// The three legacy (non-APX) sanity cases kept from the original harness.
#[test]
fn encode_simple_legacy() {
    use xed_sys::*;

    // NOP
    let nop = round_trip("NOP", &[0x90], XED_ICLASS_NOP, 0, &[]);
    assert!(nop.operands.is_empty(), "NOP should decode without operands");

    // ADD eax, ecx (legacy 32-bit)
    round_trip(
        "ADD eax,ecx",
        &[0x01, 0xc8],
        XED_ICLASS_ADD,
        32,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_EAX),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_ECX),
        ],
    );

    // PUSH rax: explicit GPR read plus the suppressed stack write.
    let push = round_trip(
        "PUSH rax",
        &[0x50],
        XED_ICLASS_PUSH,
        64,
        &[EncOp::Reg(XED_OPERAND_REG0, XED_REG_RAX)],
    );
    let stack_write = push
        .operands
        .iter()
        .any(|o| matches!(o.kind, OperandKind::Memory(_)) && o.access == AccessKind::Write);
    assert!(stack_write, "PUSH should decode with a suppressed stack write");
}

/// Regenerates every canonical APX encoding pinned by the unit-test decode
/// legs and round-trips it through the bridge.
#[test]
fn encode_apx_forms() {
    use xed_sys::*;

    // CFCMOVZ rdx, rax: EVEX-promoted conditional fused compare-and-move.
    let cfcmovz = round_trip(
        "CFCMOVZ rdx,rax",
        &[0x62, 0xf4, 0xfc, 0x08, 0x44, 0xd0],
        XED_ICLASS_CFCMOVZ,
        64,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_RDX),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_RAX),
        ],
    );
    assert_eq!(cfcmovz.operands[0].access, AccessKind::Write);
    assert_eq!(cfcmovz.operands[1].access, AccessKind::Read);

    let push2_ops = &[
        EncOp::Reg(XED_OPERAND_REG0, XED_REG_R15),
        EncOp::Reg(XED_OPERAND_REG1, XED_REG_RCX),
    ];

    // PUSH2 r15, rcx and its 128-bit paired-shadow-store PUSH2P variant.
    let push2 = round_trip(
        "PUSH2 r15,rcx",
        &[0x62, 0xf4, 0x04, 0x18, 0xff, 0xf1],
        XED_ICLASS_PUSH2,
        64,
        push2_ops,
    );
    assert_eq!(push2.operands.len(), 3, "PUSH2: two GPRs plus the stack slot");
    assert_eq!(push2.operands[2].width_bits, 64, "PUSH2 stack slot is 64-bit");
    let push2p = round_trip(
        "PUSH2P r15,rcx",
        &[0x62, 0xf4, 0x84, 0x18, 0xff, 0xf1],
        XED_ICLASS_PUSH2P,
        64,
        push2_ops,
    );
    assert_eq!(push2p.operands[2].width_bits, 128, "PUSH2P shadow slot is 128-bit");

    // POP2/POP2P mirror PUSH2/PUSH2P with a suppressed stack read.
    let pop2 = round_trip(
        "POP2 r15,rcx",
        &[0x62, 0xf4, 0x04, 0x18, 0x8f, 0xc1],
        XED_ICLASS_POP2,
        64,
        push2_ops,
    );
    assert_eq!(pop2.operands.len(), 3);
    assert_eq!(pop2.operands[2].width_bits, 64, "POP2 stack slot is 64-bit");
    let pop2p = round_trip(
        "POP2P r15,rcx",
        &[0x62, 0xf4, 0x84, 0x18, 0x8f, 0xc1],
        XED_ICLASS_POP2P,
        64,
        push2_ops,
    );
    assert_eq!(pop2p.operands[2].width_bits, 128, "POP2P shadow slot is 128-bit");

    // CCMPZ rax, rcx, DFV=8 (64-bit GPRv): the DFV register must surface
    // as an immediate operand with value 8.
    let ccmpz = round_trip(
        "CCMPZ rax,rcx,dfv8",
        &[0x62, 0xf4, 0xc4, 0x04, 0x39, 0xc8],
        XED_ICLASS_CCMPZ,
        64,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_RAX),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_RCX),
            EncOp::Reg(XED_OPERAND_REG2, XED_REG_DFV8),
        ],
    );
    let dfv = ccmpz.operands.iter().find_map(|o| match &o.kind {
        OperandKind::Immediate(immediate) => Some(immediate.value),
        _ => None,
    });
    assert_eq!(dfv, Some(8), "DFV8 register must decode as immediate 8");

    // CTESTZ rax, rcx, DFV=0 (64-bit).
    round_trip(
        "CTESTZ rax,rcx,dfv0",
        &[0x62, 0xf4, 0x84, 0x04, 0x85, 0xc8],
        XED_ICLASS_CTESTZ,
        64,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_RAX),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_RCX),
            EncOp::Reg(XED_OPERAND_REG2, XED_REG_DFV0),
        ],
    );

    // ADD r16, r17, r9 with NF (no-flags): three-register NDD form whose
    // RFLAGS side effect is suppressed.
    let add_ndd = round_trip(
        "ADD r16,r17,r9 NF",
        &[0x62, 0x7c, 0xfc, 0x14, 0x01, 0xc9],
        XED_ICLASS_ADD,
        64,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_R16),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_R17),
            EncOp::Reg(XED_OPERAND_REG2, XED_REG_R9),
            EncOp::Nf,
        ],
    );
    assert_eq!(add_ndd.operands.len(), 3, "NDD ADD has three register operands");
    assert!(add_ndd.modifiers.no_flags, "NF must decode into modifiers.no_flags");

    // SHL r16, r17, 3: NDD shift with an imm8 count.
    let shl_ndd = round_trip(
        "SHL r16,r17,3 NDD",
        &[0x62, 0xfc, 0xfc, 0x10, 0xc1, 0xe1, 0x03],
        XED_ICLASS_SHL,
        64,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_R16),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_R17),
            EncOp::Imm(3),
        ],
    );
    assert_eq!(shl_ndd.operands.len(), 4);
    assert!(matches!(shl_ndd.operands[2].kind, OperandKind::Immediate(_)));

    // SHL NDD 32-bit sanity (eax/ecx shape).
    round_trip(
        "SHL NDD 32",
        &[0x62, 0xf4, 0x7c, 0x18, 0xc1, 0xe1, 0x03],
        XED_ICLASS_SHL,
        32,
        &[
            EncOp::Reg(XED_OPERAND_REG0, XED_REG_EAX),
            EncOp::Reg(XED_OPERAND_REG1, XED_REG_ECX),
            EncOp::Imm(3),
        ],
    );

    // SHL rax, 3: legacy two-operand count-form sanity (REX.W for the
    // qword view).
    round_trip(
        "SHL rax,3 legacy",
        &[0x48, 0xc1, 0xe0, 0x03],
        XED_ICLASS_SHL,
        64,
        &[EncOp::Reg(XED_OPERAND_REG0, XED_REG_RAX), EncOp::Imm(3)],
    );

    // JMPABS cannot be produced by this simple uimm0-based request setup
    // (XED rejects it); its canonical bytes are pinned by the
    // `decode_apx_instructions` decode leg instead.
    let jmpabs = unsafe { encode(XED_ICLASS_JMPABS, 64, &[EncOp::Imm64(0x1122334455667788)]) };
    assert!(jmpabs.is_err(), "JMPABS is not encodable via the simple uimm0 request");
}
