#!/usr/bin/env python3
"""Generate Angryier's long64 exact-witness x87 memory identity map."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT.parent / "ISANITY/tools/xed-x87-memory-identity/out/x86-x87-memory-v2-candidates.json"
SOURCE_SHA256 = "7561b8aec5da96ecd158335dd2d27af56482754b7ad386d0dc0b670f7952cc0e"
OUT = ROOT / "crates/angryier-runtime/src/isanity_x87_memory_generated.rs"
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
SUPPORTED_MODE = "long64"
UNSUPPORTED_MODES = {
    "legacy32": "unsupported-mode:legacy32:Angryier x87 identity adapter is explicitly scoped to long64",
    "legacy16": "unsupported-mode:legacy16:Angryier x87 identity adapter is explicitly scoped to long64",
    "compat32": "unsupported-mode:compat32:Angryier x87 identity adapter is explicitly scoped to long64",
    "compat16": "unsupported-mode:compat16:Angryier x87 identity adapter is explicitly scoped to long64",
    "real32": "unsupported-mode:real32:Angryier x87 identity adapter is explicitly scoped to long64",
    "real16": "unsupported-mode:real16:Angryier x87 identity adapter is explicitly scoped to long64",
}


def fail(message: str) -> None:
    raise ValueError(message)


def verify_record(record: dict) -> tuple[str, str, int, str, bytes]:
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
    if not (
        identity.get("architecture") == "x86"
        and identity.get("execution_mode") in {SUPPORTED_MODE, *UNSUPPORTED_MODES}
        and record.get("identity_review") == "candidate-only-not-in-shared-catalogue"
        and record.get("semantic_status") == "unmapped"
        and record.get("fidelity_status") == "unassessed"
        and identity.get("encoding", {}).get("family") == "legacy"
        and identity.get("encoding", {}).get("opcode_map") == "primary"
        and identity.get("modrm", {}).get("mod_values") == [0, 1, 2]
        and len(identity.get("operand_shape", [])) >= 2
        and sum(op.get("kind") == "memory" for op in identity["operand_shape"]) == 1
    ):
        fail(f"{iform}/{mode}: identity outside candidate-only x87 memory scope")
    observations = record.get("evidence", {}).get("runtime_observations", [])
    if len(observations) != 1:
        fail(f"{iform}/{mode}: expected one exact witness")
    obs = observations[0]
    if not (
        obs.get("mode") == mode
        and obs.get("iform_name") == iform
        and obs.get("iform_value") == value
        and obs.get("error") == "NONE"
        and obs.get("instruction_class") == identity.get("instruction_class")
    ):
        fail(f"{iform}/{mode}: runtime witness does not bind candidate identity")
    try:
        witness = bytes.fromhex(obs["bytes_hex"])
    except (KeyError, ValueError) as error:
        fail(f"{iform}/{mode}: invalid witness ({error})")
    if (
        not witness
        or len(witness) != obs.get("decoded_length")
        or hashlib.sha256(witness).hexdigest() != obs.get("bytes_sha256")
        or obs.get("address_instance") != "MOD=0, RM=0; addressing is a witness parameter, not identity completeness"
    ):
        fail(f"{iform}/{mode}: malformed exact witness")
    return record["form_id"], iform, value, mode, witness


def render() -> str:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("ISANITY x87 memory sidecar digest changed; review and repin")
    data = json.loads(raw)
    if not (
        data.get("artifact_kind") == "isanity-xed-x87-memory-identity-candidates"
        and data.get("status") == "candidate-only"
        and data.get("source_lock", {}).get("upstream_commit") == "a425c75467e1f4c0ef7311c988474c61d7e9e293"
        and data.get("coverage", {}).get("candidate_identities") == 371
        and data.get("coverage", {}).get("exact_pinned_xed_witnesses") == 371
        and data.get("coverage", {}).get("distinct_form_ids") == 371
        and len(data.get("records", [])) == 371
    ):
        fail("ISANITY x87 memory sidecar schema, counts, or candidate status changed")
    mapped = []
    unsupported = []
    ids: set[str] = set()
    pairs: set[tuple[str, str]] = set()
    for record in data["records"]:
        form_id, iform, value, mode, witness = verify_record(record)
        if form_id in ids or (iform, mode) in pairs:
            fail(f"duplicate source identity {iform}/{mode}")
        ids.add(form_id)
        pairs.add((iform, mode))
        if mode == SUPPORTED_MODE:
            mapped.append((form_id, iform, value, mode, witness))
        else:
            unsupported.append((form_id, iform, value, mode, UNSUPPORTED_MODES[mode]))
    if len(mapped) != 53 or len(unsupported) != 318 or len(ids) != 371:
        fail(f"slice accounting changed: mapped={len(mapped)}, unsupported={len(unsupported)}")
    lines = [
        "// @generated by tools/isanity-map/generate_x87_memory.py; do not edit.",
        f"// ISANITY x86-x87-memory-v2-candidates.json SHA-256: {SOURCE_SHA256}",
        "pub(super) static X87_MEMORY_FORMS: &[X87MemoryForm] = &[",
    ]
    for form_id, iform, value, mode, witness in sorted(mapped, key=lambda row: (row[1], row[0])):
        byte_list = ", ".join(f"0x{byte:02x}" for byte in witness)
        lines.append(
            f'    X87MemoryForm {{ canonical_id: "{form_id}", iform: "{iform}", '
            f"iform_value: {value}, mode: InstructionMode::Long64, witness: &[{byte_list}] }},"
        )
    lines.append("];\npub(super) static X87_MEMORY_UNSUPPORTED: &[UnsupportedX87MemoryIdentity] = &[")
    for form_id, iform, value, mode, reason in sorted(unsupported, key=lambda row: (row[1], row[3], row[0])):
        lines.append(
            f'    UnsupportedX87MemoryIdentity {{ canonical_id: "{form_id}", iform: "{iform}", '
            f'iform_value: {value}, source_mode: "{mode}", reason: "{reason}" }},'
        )
    lines.extend([
        "];",
        "#[cfg(test)]",
        "pub(super) const X87_MEMORY_MAPPED_COUNT: usize = 53;",
        "#[cfg(test)]",
        "pub(super) const X87_MEMORY_UNSUPPORTED_COUNT: usize = 318;",
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
        print("ISANITY x87 memory map current (53 long64 exact witnesses, 318 reason-coded non-long64 identities)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY x87 memory map (53 long64 exact witnesses, 318 reason-coded non-long64 identities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
