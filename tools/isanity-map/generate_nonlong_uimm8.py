#!/usr/bin/env python3
"""Generate Angryier's exact-witness x86 opcode-82 unsigned-imm8 map."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISANITY = ROOT.parent / "ISANITY"
SOURCE = ISANITY / "catalogue/canonical/x86-uimm8-nonlong64-v2.json"
SOURCE_SHA256 = "b5f1a9cc33bc602950432129f45accb23b9c4ee7e5ba503264a595a4163443aa"
OUT = ROOT / "crates/angryier-runtime/src/isanity_uimm8_modrm_generated.rs"
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


def verify_record(record: dict) -> tuple[str, str, int, str, bytes, bool]:
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
        and encoding.get("immediate_encoding") == "uimm8"
        and encoding.get("modrm_reg_extension") in {4, 6}
        and modrm.get("mod_values") == [0, 1, 2]
        and modrm.get("reg_operand") is None
        and modrm.get("rm_operand") == 0
        and len(shape) == 2
        and shape[0].get("role") == "mem0"
        and shape[0].get("kind") == "memory"
        and shape[0].get("width_bits") == 8
        and shape[0].get("access") == "read-write"
        and shape[1].get("role") == "imm0"
        and shape[1].get("kind") == "immediate"
        and shape[1].get("width_bits") == 8
        and shape[1].get("access") == "read"
        and record.get("semantic_status") == "unmapped"
        and record.get("fidelity_status") == "unassessed"
    ):
        fail(f"{iform}/{mode}: candidate escaped opcode-82 unsigned UIMM8 scope")
    constraints = encoding.get("prefix_constraints")
    lock = constraints == ["lock-required"]
    if constraints not in (["lock-required"], ["lock-forbidden"]):
        fail(f"{iform}/{mode}: unrecognized prefix constraint")
    if ("LOCK" in identity.get("instruction_class", "")) != lock:
        fail(f"{iform}/{mode}: lock-prefix constraint disagrees with instruction class")
    if mode not in SUPPORTED and mode not in UNSUPPORTED_REASONS:
        fail(f"{iform}/{mode}: unexpected source execution mode")
    observations = record.get("evidence", {}).get("runtime_observations", [])
    expected_observations = 2 if mode in SUPPORTED else 1
    if len(observations) != expected_observations:
        fail(f"{iform}/{mode}: expected {expected_observations} pinned profile witness(es)")
    join = record["evidence"].get("source_candidate_join", {})
    candidate = join.get("candidate_artifact", {})
    if not (
        candidate.get("sha256") == "8c7dd30be664e7ee7141c9d0f79123c15a9f9c98d3c9672802eaa2c37f47d069"
        and join.get("source_lock", {}).get("crate_version") == "0.6.0+xed-2024.05.20"
        and join.get("source_lock", {}).get("source_commit") == "a425c75467e1f4c0ef7311c988474c61d7e9e293"
        and join.get("source_pattern", {}).get("uimm8", {}).get("signed") is False
        and join.get("source_pattern", {}).get("uimm8", {}).get("width_bits") == 8
    ):
        fail(f"{iform}/{mode}: profile observation/source join does not bind this candidate")
    prefix_len = 1 if lock else 0
    witnesses = set()
    for obs in observations:
        audit = obs.get("assignment_audit", {})
        if not (
            obs.get("err") == "NONE"
            and obs.get("iform_name") == iform
            and obs.get("iform_value") == value
            and obs.get("mode") == mode
            and obs.get("execution_mode") == mode
            and obs.get("opcode_bytes") == "0x82"
            and obs.get("operand_size_bits") == 8
            and audit.get("accepted") == 24
            and audit.get("attempted") == 24
            and audit.get("rejected") == 0
            and audit.get("unique_observed_iform_count") == 1
        ):
            fail(f"{iform}/{mode}: runtime observation does not bind this candidate")
        witness = bytes.fromhex(obs["bytes_hex"])
        if (
            len(witness) != obs.get("decoded_length")
            or hashlib.sha256(witness).hexdigest() != obs.get("bytes_sha256")
            or witness[:prefix_len] != (b"\xf0" if lock else b"")
            or witness[prefix_len : prefix_len + 1] != b"\x82"
            or len(witness) < prefix_len + 3
            or witness[prefix_len + 1] >> 6 == 3
            or ((witness[prefix_len + 1] >> 3) & 7) != encoding["modrm_reg_extension"]
            or witness[-1] != 0
        ):
            fail(f"{iform}/{mode}: malformed opcode/ModRM/UIMM8 witness")
        witnesses.add(witness)
    if len(witnesses) != 1:
        fail(f"{iform}/{mode}: profile witnesses disagree on exact bytes")
    witness = next(iter(witnesses))
    return record["form_id"], iform, value, mode, witness, lock


def render() -> str:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("ISANITY non-long64 UIMM8 catalogue digest changed; repin after review")
    data = json.loads(raw)
    if data.get("identity_schema") != "form-identity-v2" or len(data.get("records", [])) != 24:
        fail("ISANITY non-long64 UIMM8 schema or identity count changed")
    mapped = []
    unsupported = []
    ids = set()
    for record in data["records"]:
        form_id, iform, value, mode, witness, lock = verify_record(record)
        if form_id in ids:
            fail(f"duplicate canonical identity {form_id}")
        ids.add(form_id)
        if mode in SUPPORTED:
            mapped.append((form_id, iform, value, SUPPORTED[mode], witness, lock))
        else:
            unsupported.append((form_id, iform, value, mode, UNSUPPORTED_REASONS[mode]))
    if len(mapped) != 4 or len(unsupported) != 20 or len(ids) != 24:
        fail(f"slice accounting changed: mapped={len(mapped)}, unsupported={len(unsupported)}")
    lines = [
        "// @generated by tools/isanity-map/generate_nonlong_uimm8.py; do not edit.",
        f"// ISANITY x86-uimm8-nonlong64-v2.json SHA-256: {SOURCE_SHA256}",
        "pub(super) static UIMM8_MODRM_FORMS: &[Uimm8ModrmForm] = &[",
    ]
    for form_id, iform, value, mode, witness, lock in sorted(mapped, key=lambda r: (r[1], r[3], r[0])):
        byte_list = ", ".join(f"0x{byte:02x}" for byte in witness)
        lines.append(
            f'    Uimm8ModrmForm {{ canonical_id: "{form_id}", iform: "{iform}", iform_value: {value}, '
            f'mode: InstructionMode::{mode}, witness: &[{byte_list}], lock_prefix: {str(lock).lower()} }},'
        )
    lines.append("];\npub(super) static UIMM8_MODRM_UNSUPPORTED: &[UnsupportedUimm8ModrmIdentity] = &[")
    for form_id, iform, value, mode, reason in sorted(unsupported, key=lambda r: (r[1], r[3], r[0])):
        lines.append(
            f'    UnsupportedUimm8ModrmIdentity {{ canonical_id: "{form_id}", iform: "{iform}", '
            f'iform_value: {value}, source_mode: "{mode}", reason: "{reason}" }},'
        )
    lines.extend([
        "];",
        "#[cfg(test)]",
        "pub(super) const UIMM8_MODRM_MAPPED_COUNT: usize = 4;",
        "#[cfg(test)]",
        "pub(super) const UIMM8_MODRM_UNSUPPORTED_COUNT: usize = 20;",
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
        print("ISANITY non-long64 UIMM8 map is current (4 exact-witness mapped, 20 reason-coded unsupported)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY non-long64 UIMM8 map (4 exact-witness mapped, 20 reason-coded unsupported)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
