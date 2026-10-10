//! Integration tests for batch XED runtime IFORM evidence tool.

use angryier_arch_xed_ffi::XedDecoder;
use angryier_arch_xed_ffi::evidence::{PINNED_XED_VERSION, process_evidence_stream};
use angryier_arch_xed_ffi::iclass;

#[test]
fn test_batch_evidence_known_xed_forms() {
    let decoder = XedDecoder::new();
    let input = r#"
{"id": "nop_1", "bytes": "90"}
{"id": "mov_reg64", "bytes": "48 89 c1"}
{"id": "mov_reg8_88", "bytes": "88 c0"}
{"id": "mov_reg8_8a", "bytes": "8a c0"}
{"id": "ret_near", "bytes": "c3"}
"#;

    let mut output = Vec::new();
    let stats =
        process_evidence_stream(&decoder, input.as_bytes(), &mut output, 0x1000).expect("batch stream succeeds");

    assert_eq!(stats.total, 5);
    assert_eq!(stats.ok, 5);
    assert_eq!(stats.errors, 0);

    let output_str = String::from_utf8(output).expect("output must be utf8");
    let lines: Vec<&str> = output_str.lines().collect();
    assert_eq!(lines.len(), 5);

    // 1. NOP
    assert!(lines[0].contains(r#""id":"nop_1""#));
    assert!(lines[0].contains(r#""bytes":"90""#));
    assert!(lines[0].contains(r#""status":"ok""#));
    assert!(lines[0].contains(&format!(r#""decoder_version":"{PINNED_XED_VERSION}""#)));
    assert!(lines[0].contains(r#""iform_name":"XED_IFORM_NOP_90""#));
    assert!(lines[0].contains(r#""iform_value":1735"#));
    assert!(lines[0].contains(r#""raw_iform":{"name":"XED_IFORM_NOP_90","value":1735}"#));
    assert!(lines[0].contains(r#""length":1"#));

    // 2. MOV GPRv GPRv
    assert!(lines[1].contains(r#""id":"mov_reg64""#));
    assert!(lines[1].contains(r#""bytes":"48 89 c1""#));
    assert!(lines[1].contains(r#""iform_name":"XED_IFORM_MOV_GPRv_GPRv_89""#));
    assert!(lines[1].contains(r#""iform_value":1560"#));
    assert!(lines[1].contains(r#""length":3"#));

    // 3. MOV 88
    assert!(lines[2].contains(r#""id":"mov_reg8_88""#));
    assert!(lines[2].contains(r#""bytes":"88 c0""#));
    assert!(lines[2].contains(r#""iform_name":"XED_IFORM_MOV_GPR8_GPR8_88""#));
    assert!(lines[2].contains(r#""iform_value":1555"#));
    assert!(lines[2].contains(r#""length":2"#));

    // 4. MOV 8A
    assert!(lines[3].contains(r#""id":"mov_reg8_8a""#));
    assert!(lines[3].contains(r#""bytes":"8a c0""#));
    assert!(lines[3].contains(r#""iform_name":"XED_IFORM_MOV_GPR8_GPR8_8A""#));
    assert!(lines[3].contains(r#""iform_value":1556"#));
    assert!(lines[3].contains(r#""length":2"#));

    // 5. RET
    assert!(lines[4].contains(r#""id":"ret_near""#));
    assert!(lines[4].contains(r#""bytes":"c3""#));
    assert!(lines[4].contains(r#""iform_name":"XED_IFORM_RET_NEAR""#));
    assert!(lines[4].contains(r#""iform_value":2505"#));
    assert!(lines[4].contains(r#""length":1"#));
}

#[test]
fn test_batch_evidence_error_handling() {
    let decoder = XedDecoder::new();
    let input = r#"
{"id": "bad_opcode", "bytes": "0f 0f"}
{"id": "bad_hex_chars", "bytes": "0xGG"}
{"id": "odd_hex_nibbles", "bytes": "abc"}
{"id": "empty_bytes", "bytes": ""}
{bad json line}
"#;

    let mut output = Vec::new();
    let stats = process_evidence_stream(&decoder, input.as_bytes(), &mut output, 0x1000)
        .expect("batch stream succeeds despite item errors");

    assert_eq!(stats.total, 5);
    assert_eq!(stats.ok, 0);
    assert_eq!(stats.errors, 5);

    let output_str = String::from_utf8(output).expect("output must be utf8");
    let lines: Vec<&str> = output_str.lines().collect();
    assert_eq!(lines.len(), 5);

    for line in lines {
        assert!(line.contains(r#""status":"error""#));
        assert!(line.contains(r#""iform_name":null"#));
        assert!(line.contains(r#""iform_value":null"#));
        assert!(line.contains(r#""raw_iform":null"#));
        assert!(line.contains(r#""error":""#));
    }
}

#[test]
fn test_batch_evidence_determinism() {
    let decoder = XedDecoder::new();
    let input = r#"{"id":"1","bytes":"90"}
{"id":"2","bytes":"4889c1"}
{"id":"3","bytes":"88c0"}
{"id":"4","bytes":"ffff"}
{"id":"5","bytes":"c3"}
"#;

    let mut baseline = Vec::new();
    process_evidence_stream(&decoder, input.as_bytes(), &mut baseline, 0x2000).expect("baseline run succeeds");

    for iter in 0..10 {
        let mut check = Vec::new();
        process_evidence_stream(&decoder, input.as_bytes(), &mut check, 0x2000).expect("check run succeeds");
        assert_eq!(
            baseline, check,
            "evidence batch emission must be strictly deterministic (failed on iteration {iter})"
        );
    }
}

#[test]
fn test_batch_evidence_does_not_treat_engine_form_id_as_iform() {
    let decoder = XedDecoder::new();

    // Decode NOP with raw decoder: engine form_id is ICLASS_NOP (898)
    let (decoded, iform) = decoder.decode_with_iform(0x1000, &[0x90]).expect("NOP decodes");
    assert_eq!(decoded.form_id, iclass::XED_ICLASS_NOP);
    assert_ne!(decoded.form_id, iform.value);

    // Verify evidence output emits iform.value (1735), NOT decoded.form_id (898)
    let mut output = Vec::new();
    let input = r#"{"id":"check_form","bytes":"90"}"#;
    process_evidence_stream(&decoder, input.as_bytes(), &mut output, 0x1000).expect("evidence decodes");
    let out_str = String::from_utf8(output).expect("utf8 output");

    assert!(out_str.contains(r#""iform_value":1735"#));
    assert!(
        !out_str.contains(&format!(r#""iform_value":{}"#, decoded.form_id)),
        "engine form_id must not be treated as iform_value"
    );
    assert!(
        !out_str.contains("form_id"),
        "engine form_id must not be exposed as iform"
    );
}
