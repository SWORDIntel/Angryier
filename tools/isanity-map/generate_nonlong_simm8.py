#!/usr/bin/env python3
"""Generate Angryier's mode-qualified x86 opcode-82 signed-imm8 identity map."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISANITY = ROOT.parent / "ISANITY"
SOURCE = ISANITY / "catalogue/canonical/x86-simm8-nonlong64-v2.json"
SOURCE_SHA256 = "dde64f2d4cd01c0adfb16a8d256513b7750afb8c2bd36a1473ce3177bd0ab744"
OUT = ROOT / "crates/angryier-runtime/src/isanity_simm8_modrm_generated.rs"
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
SUPPORTED = {"legacy32": "Legacy32"}
UNSUPPORTED_REASONS = {
    "legacy16": "unsupported-mode:legacy16:Angryier XED normalization rejects 16-bit memory-address metadata",
    "compat16": "unsupported-mode:compat16:Angryier decoder exposes no compatibility-mode selector",
    "compat32": "unsupported-mode:compat32:Angryier decoder exposes no compatibility-mode selector",
    "real16": "unsupported-mode:real16:Angryier decoder exposes no real-address-mode selector",
    "real32": "unsupported-mode:real32:Angryier decoder exposes no real-address-mode selector",
}


def fail(message: str) -> None:
    raise ValueError(message)


def verify_record(record: dict) -> tuple[str, str, int, bool, str, int]:
    iform = record["iform"]["name"]
    value = record["iform"]["value"]
    mode = record["identity"]["execution_mode"]
    identity = record["identity"]
    canonical = record.get("canonical_bytes")
    match = ID_RE.fullmatch(record.get("form_id", ""))
    if not isinstance(canonical, str) or json.loads(canonical) != identity or not match:
        fail(f"{iform}/{mode}: malformed canonical identity")
    raw = canonical.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(raw).to_bytes(8, "big") + raw).hexdigest()
    if digest != match.group(1):
        fail(f"{iform}/{mode}: FormId digest mismatch")
    encoding = identity["encoding"]
    shape = identity["operand_shape"]
    modrm = identity["modrm"]
    if not (
        identity.get("architecture") == "x86"
        and encoding.get("family") == "legacy"
        and encoding.get("opcode_map") == "primary"
        and encoding.get("opcode_bytes") == "0x82"
        and encoding.get("immediate_encoding") == "simm8-signed"
        and encoding.get("modrm_reg_extension") in range(8)
        and modrm.get("mod_values") == [0, 1, 2]
        and modrm.get("reg_operand") is None
        and modrm.get("rm_operand") == 0
        and len(shape) == 2
        and shape[0].get("role") == "mem0"
        and shape[0].get("kind") == "memory"
        and shape[0].get("width_bits") == 8
        and shape[0].get("access") in {"read", "read-write"}
        and shape[1].get("role") == "imm0"
        and shape[1].get("kind") == "immediate"
        and shape[1].get("width_bits") == 8
        and shape[1].get("access") == "read"
        and record.get("semantic_status") == "unmapped"
        and record.get("fidelity_status") == "unassessed"
    ):
        fail(f"{iform}/{mode}: candidate identity escaped opcode-82 signed SIMM8 scope")
    constraints = encoding.get("prefix_constraints")
    lock = constraints == ["lock-prefix"]
    if constraints not in (["lock-prefix"], ["no-lock-prefix"], []):
        fail(f"{iform}/{mode}: unrecognized prefix constraint")
    if ("LOCK" in identity.get("instruction_class", "")) != lock:
        fail(f"{iform}/{mode}: lock-prefix constraint disagrees with instruction class")
    if mode not in SUPPORTED and mode not in UNSUPPORTED_REASONS:
        fail(f"{iform}/{mode}: unexpected source execution mode")
    observations = record.get("evidence", {}).get("runtime_observations", [])
    if not observations:
        fail(f"{iform}/{mode}: no profile observation")
    for obs in observations:
        if not (
            obs.get("err") == "NONE"
            and obs.get("iform_name") == iform
            and obs.get("iform_value") == value
            and obs.get("mode") == mode
            and obs.get("execution_mode") == mode
            and obs.get("opcode_bytes") == "0x82"
            and obs.get("assignment_audit", {}).get("accepted") == 24
            and obs.get("assignment_audit", {}).get("attempted") == 24
        ):
            fail(f"{iform}/{mode}: runtime observation does not bind this candidate")
        witness = bytes.fromhex(obs["bytes_hex"])
        prefix_len = 1 if lock else 0
        modrm_byte = witness[prefix_len + 1] if len(witness) > prefix_len + 1 else 0
        if (
            len(witness) < prefix_len + 3
            or witness[:prefix_len] != (b"\xf0" if lock else b"")
            or witness[prefix_len] != 0x82
            or modrm_byte >> 6 not in {0, 1, 2}
            or ((modrm_byte >> 3) & 7) != encoding["modrm_reg_extension"]
        ):
            fail(f"{iform}/{mode}: malformed opcode/ModRM witness")
        if hashlib.sha256(witness).hexdigest() != obs.get("bytes_sha256") or len(witness) != obs.get("decoded_length"):
            fail(f"{iform}/{mode}: witness digest/length mismatch")
    return record["form_id"], iform, value, lock, shape[0]["access"], encoding["modrm_reg_extension"]


def render() -> str:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("ISANITY opcode-82 SIMM8 catalogue digest changed; repin after review")
    data = json.loads(raw)
    if data.get("identity_schema") != "form-identity-v2" or len(data.get("records", [])) != 66:
        fail("ISANITY opcode-82 SIMM8 schema or identity count changed")
    mapped = []
    unsupported = []
    ids = set()
    for record in data["records"]:
        form_id, iform, value, lock, access, extension = verify_record(record)
        mode = record["identity"]["execution_mode"]
        if form_id in ids:
            fail(f"duplicate canonical identity {form_id}")
        ids.add(form_id)
        if mode in SUPPORTED:
            mapped.append((form_id, iform, value, SUPPORTED[mode], lock, access, extension))
        else:
            unsupported.append((form_id, iform, value, mode, UNSUPPORTED_REASONS[mode]))
    if len(mapped) != 11 or len(unsupported) != 55 or len(ids) != 66:
        fail(f"slice accounting changed: mapped={len(mapped)}, unsupported={len(unsupported)}")
    if len({(row[1], row[3]) for row in mapped}) != 11:
        fail("supported (IFORM, mode) selection tuples are not unique")
    lines = [
        "// @generated by tools/isanity-map/generate_nonlong_simm8.py; do not edit.",
        f"// ISANITY x86-simm8-nonlong64-v2.json SHA-256: {SOURCE_SHA256}",
        "pub(super) static SIMM8_MODRM_FORMS: &[Simm8ModrmForm] = &[",
    ]
    for form_id, iform, value, mode, lock, access, extension in sorted(mapped, key=lambda r: (r[1], r[3], r[0])):
        access_variant = "Read" if access == "read" else "ReadWrite"
        lines.append(
            f'    Simm8ModrmForm {{ canonical_id: "{form_id}", iform: "{iform}", iform_value: {value}, '
            f'mode: InstructionMode::{mode}, lock_prefix: {str(lock).lower()}, memory_access: AccessKind::{access_variant} }},'
        )
    lines.append("];")
    lines.append("pub(super) static SIMM8_MODRM_EXTENSION_BY_ID: &[(&str, u8)] = &[")
    for form_id, _, _, _, _, _, extension in sorted(mapped, key=lambda r: r[0]):
        lines.append(f'    ("{form_id}", {extension}),')
    lines.append("];")
    lines.append("pub(super) static SIMM8_MODRM_UNSUPPORTED: &[UnsupportedSimm8ModrmIdentity] = &[")
    for form_id, iform, value, mode, reason in sorted(unsupported, key=lambda r: (r[1], r[3], r[0])):
        lines.append(
            f'    UnsupportedSimm8ModrmIdentity {{ canonical_id: "{form_id}", iform: "{iform}", '
            f'iform_value: {value}, source_mode: "{mode}", reason: "{reason}" }},'
        )
    lines.extend([
        "];",
        "#[cfg(test)]",
        "pub(super) const SIMM8_MODRM_MAPPED_COUNT: usize = 11;",
        "#[cfg(test)]",
        "pub(super) const SIMM8_MODRM_UNSUPPORTED_COUNT: usize = 55;",
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
        print("ISANITY opcode-82 SIMM8 map is current (11 mapped, 55 reason-coded unsupported)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY opcode-82 SIMM8 map (11 mapped, 55 reason-coded unsupported)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
