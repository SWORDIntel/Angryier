#!/usr/bin/env python3
"""Generate Angryier's long64 fixed-opcode UIMM8 identity adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT.parent / "ISANITY/tools/xed-fixed-opcode-imm-scout/out/x86-fixed-opcode-imm-candidates-v1.json"
SOURCE_SHA256 = "99ceb6e14697faa837d05e7ae819931b2520a4610666ba3abbf658fdb9dbe4a8"
OUT = ROOT / "crates/angryier-runtime/src/isanity_fixed_opcode_immediates_generated.rs"
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
SUPPORTED_MODE = "long64"
UNSUPPORTED_REASONS = {
    mode: f"unsupported-mode:{mode}:Angryier fixed-opcode immediate adapter is explicitly scoped to long64"
    for mode in ("legacy32", "legacy16", "compat32", "compat16", "real32", "real16")
}
AAD_AAM_VALUES = {"XED_IFORM_AAD_IMMb": 2, "XED_IFORM_AAM_IMMb": 7}


def fail(message: str) -> None:
    raise ValueError(message)


def verify_record(record: dict) -> tuple[str, str, int, str, int, list[bytes], list[dict]]:
    iform = record["iform"]["name"]
    value = record["iform"]["value"]
    identity = record["identity"]
    mode = identity["execution_mode"]
    canonical = record.get("canonical_bytes")
    match = ID_RE.fullmatch(record.get("form_id", ""))
    if not isinstance(canonical, str) or json.loads(canonical) != identity or not match:
        fail(f"{iform}/{mode}: malformed canonical identity")
    raw = canonical.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(raw).to_bytes(8, "big") + raw).hexdigest()
    if digest != match.group(1):
        fail(f"{iform}/{mode}: FormId digest mismatch")
    encoding = identity["encoding"]
    shapes = identity["operand_shape"]
    if not (
        identity.get("architecture") == "x86"
        and identity.get("instruction_class") in {"IN", "OUT", "AAD", "AAM"}
        and encoding.get("family") == "legacy"
        and encoding.get("immediate_encoding") == "uimm8"
        and encoding.get("opcode_map") == "primary"
        and record.get("semantic_status") == "unmapped"
        and record.get("fidelity_status") == "unassessed"
        and 1 <= len(shapes) <= 3
        and any(shape.get("kind") == "immediate" and shape.get("width_bits") == 8 for shape in shapes)
    ):
        fail(f"{iform}/{mode}: candidate escaped fixed-opcode UIMM8 identity scope")
    expected_modes = set(UNSUPPORTED_REASONS) if iform in AAD_AAM_VALUES else {SUPPORTED_MODE, *UNSUPPORTED_REASONS}
    if mode not in expected_modes:
        fail(f"{iform}/{mode}: unexpected execution context")
    if iform in AAD_AAM_VALUES and not (
        value == AAD_AAM_VALUES[iform]
        and "not-long64" in encoding.get("prefix_constraints", [])
        and mode != "long64"
    ):
        fail(f"{iform}/{mode}: AAD/AAM source exclusion from long64 changed")
    observations = record.get("evidence", {}).get("runtime_observations", [])
    if len(observations) != 256:
        fail(f"{iform}/{mode}: expected all 256 immediate-byte observations")
    witnesses: list[bytes] = []
    seen_immediates: set[int] = set()
    opcode = int(encoding["opcode_bytes"], 16)
    for obs in observations:
        if not (
            obs.get("iform_name") == iform
            and obs.get("iform_value") == value
            and obs.get("decoded_length") == 2
            and isinstance(obs.get("immediate"), int)
            and 0 <= obs["immediate"] <= 255
        ):
            fail(f"{iform}/{mode}: observation does not bind exact IFORM and UIMM8 byte")
        try:
            witness = bytes.fromhex(obs["bytes_hex"])
        except (KeyError, ValueError) as error:
            fail(f"{iform}/{mode}: invalid witness ({error})")
        if witness != bytes((opcode, obs["immediate"])) or obs["immediate"] in seen_immediates:
            fail(f"{iform}/{mode}: witness bytes disagree with opcode/immediate or duplicate")
        seen_immediates.add(obs["immediate"])
        witnesses.append(witness)
    if seen_immediates != set(range(256)):
        fail(f"{iform}/{mode}: immediate witnesses do not cover the complete byte domain")
    if mode == SUPPORTED_MODE:
        mode_width = record.get("evidence", {}).get("mode_operand_width_witness")
        if iform in {"XED_IFORM_IN_OeAX_IMMb", "XED_IFORM_OUT_IMMb_OeAX"}:
            if not (
                isinstance(mode_width, dict)
                and mode_width.get("source_operand") == "OeAX()"
                and mode_width.get("width_bits") == 32
            ):
                fail(f"{iform}/{mode}: long64 OeAX width is not explicitly witnessed as 32 bits")
        elif mode_width is not None:
            fail(f"{iform}/{mode}: unexpected mode-width witness")
    return record["form_id"], iform, value, mode, opcode, witnesses, shapes


def rust_operand(shape: dict) -> str:
    kind = shape["kind"]
    if kind not in {"register", "immediate"}:
        fail(f"unsupported fixed-immediate operand kind: {kind}")
    access = {"read": "Read", "write": "Write", "read-write": "ReadWrite"}.get(shape["access"])
    if access is None:
        fail(f"unsupported fixed-immediate operand access: {shape['access']}")
    visibility = "Implicit" if shape.get("presence") == "implicit" else "Explicit"
    width = shape.get("width_bits")
    if not isinstance(width, int):
        fail("fixed immediate adapter requires source-resolved operand widths")
    return (
        "FixedImmediateOperand { "
        f"kind: FixedImmediateOperandKind::{kind.title()}, width_bits: {width}, "
        f"access: AccessKind::{access}, visibility: OperandVisibility::{visibility}, "
        f"parent_register_id: {'Some(0)' if kind == 'register' else 'None'} "
        "}"
    )


def render() -> str:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("ISANITY fixed-opcode immediate sidecar digest changed; review and repin")
    data = json.loads(raw)
    coverage = data.get("coverage", {})
    if not (
        data.get("artifact_kind") == "isanity-fixed-opcode-immediate-identity-scout"
        and data.get("status") == "candidate-only"
        and data.get("source_lock", {}).get("upstream_commit") == "a425c75467e1f4c0ef7311c988474c61d7e9e293"
        and coverage.get("admitted_identity_count") == 40
        and coverage.get("admitted_iform_count") == 6
        and coverage.get("runtime_observations") == 10240
        and coverage.get("semantic_unmapped") == 40
        and coverage.get("fidelity_unassessed") == 40
        and len(data.get("records", [])) == 40
    ):
        fail("ISANITY fixed-opcode immediate schema, coverage, or candidate status changed")
    mapped = []
    unsupported = []
    ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for record in data["records"]:
        form_id, iform, value, mode, opcode, witnesses, shapes = verify_record(record)
        if form_id in ids or (iform, mode) in pairs:
            fail(f"duplicate source identity {iform}/{mode}")
        ids.add(form_id)
        pairs.add((iform, mode))
        if mode == SUPPORTED_MODE:
            mapped.append((form_id, iform, value, opcode, witnesses, shapes))
        else:
            unsupported.append((form_id, iform, value, mode, UNSUPPORTED_REASONS[mode]))
    if len(mapped) != 4 or len(unsupported) != 36 or len(ids) != 40:
        fail(f"slice accounting changed: mapped={len(mapped)}, unsupported={len(unsupported)}")
    if {row[1] for row in mapped} & set(AAD_AAM_VALUES):
        fail("AAD/AAM must never produce long64 identity candidates")
    exclusions = [(name, value, "source-prefix-constraint:not-long64; no long64 candidate identity")
                  for name, value in sorted(AAD_AAM_VALUES.items())]
    lines = [
        "// @generated by tools/isanity-map/generate_fixed_opcode_immediates.py; do not edit.",
        f"// ISANITY x86-fixed-opcode-imm-candidates-v1.json SHA-256: {SOURCE_SHA256}",
        "pub(super) static FIXED_IMMEDIATE_FORMS: &[FixedOpcodeImmediateForm] = &[",
    ]
    for form_id, iform, value, opcode, witnesses, shapes in sorted(mapped, key=lambda row: row[1]):
        witness_text = "&[" + ", ".join(
            "&[" + ", ".join(f"0x{byte:02x}" for byte in witness) + "]" for witness in witnesses
        ) + "]"
        provider_flags = (
            "FixedImmediateOperand { kind: FixedImmediateOperandKind::Register, width_bits: 64, "
            "access: AccessKind::Read, visibility: OperandVisibility::Suppressed, parent_register_id: Some(33) }"
        )
        operands = "&[" + ", ".join([*(rust_operand(shape) for shape in shapes), provider_flags]) + "]"
        lines.append(
            f'    FixedOpcodeImmediateForm {{ canonical_id: "{form_id}", iform: "{iform}", '
            f"iform_value: {value}, mode: InstructionMode::Long64, opcode: 0x{opcode:02x}, "
            f"witnesses: {witness_text}, operands: {operands} }},"
        )
    lines.append("];\npub(super) static FIXED_IMMEDIATE_UNSUPPORTED: &[UnsupportedFixedImmediateIdentity] = &[")
    for form_id, iform, value, mode, reason in sorted(unsupported, key=lambda row: (row[1], row[3], row[0])):
        lines.append(
            f'    UnsupportedFixedImmediateIdentity {{ canonical_id: "{form_id}", iform: "{iform}", '
            f'iform_value: {value}, source_mode: "{mode}", reason: "{reason}" }},'
        )
    lines.append("];\npub(super) static FIXED_IMMEDIATE_LONG64_EXCLUSIONS: &[FixedImmediateLong64Exclusion] = &[")
    for iform, value, reason in exclusions:
        lines.append(
            f'    FixedImmediateLong64Exclusion {{ iform: "{iform}", iform_value: {value}, reason: "{reason}" }},'
        )
    lines.extend([
        "];",
        "#[cfg(test)]",
        "pub(super) const FIXED_IMMEDIATE_MAPPED_COUNT: usize = 4;",
        "#[cfg(test)]",
        "pub(super) const FIXED_IMMEDIATE_UNSUPPORTED_COUNT: usize = 36;",
        "#[cfg(test)]",
        "pub(super) const FIXED_IMMEDIATE_LONG64_EXCLUSION_COUNT: usize = 2;",
    ])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        output = render()
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    if args.check:
        if not OUT.is_file() or OUT.read_text(encoding="utf-8") != output:
            print(f"stale generated table: {OUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print("ISANITY fixed-opcode immediate map current (4 long64 exact identities, 36 unsupported, 2 AAD/AAM long64 exclusions)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY fixed-opcode immediate map (4 long64 exact identities, 36 unsupported, 2 AAD/AAM long64 exclusions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
