#!/usr/bin/env python3
"""Generate the exact fixed-ModRM identity handoff from ISANITY's catalogue."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "crates/angryier-runtime/src/isanity_fixed_modrm_generated.rs"
ISANITY = ROOT.parent / "ISANITY"
CATALOGUE = ISANITY / "catalogue/canonical/x86-fixed-modrm-v2.json"
TOOLCHAIN_LOCK = ISANITY / "catalogue/source-toolchain-lock-v1.json"
CARGO_LOCK = ROOT / "Cargo.lock"
FORM_ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
FORM_ID_DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
HEX_BYTE_RE = re.compile(r"\b0x([0-9a-fA-F]{2})\b")


def fail(message: str) -> None:
    raise SystemExit(f"ISANITY fixed-ModRM map generation failed: {message}")


def validate_toolchain(data: dict) -> dict:
    lock = json.loads(TOOLCHAIN_LOCK.read_text(encoding="utf-8"))
    matches = [source for source in lock.get("sources", []) if source.get("name") == "intel-xed"]
    if len(matches) != 1:
        fail("ISANITY source-toolchain lock must identify exactly one Intel XED source")
    source = matches[0]
    distribution = source.get("distribution", {})
    packages = [
        part for part in CARGO_LOCK.read_text(encoding="utf-8").split("[[package]]")
        if re.search(r'^name = "xed-sys"$', part, re.MULTILINE)
    ]
    if len(packages) != 1:
        fail("Angryier Cargo.lock must pin exactly one xed-sys package")
    version = re.search(r'^version = "([^"]+)"$', packages[0], re.MULTILINE)
    checksum = re.search(r'^checksum = "([0-9a-f]{64})"$', packages[0], re.MULTILINE)
    if (
        not version or version.group(1) != distribution.get("version")
        or not checksum or checksum.group(1) != distribution.get("registry_checksum_sha256")
    ):
        fail("Angryier Cargo.lock does not match the pinned ISANITY xed-sys package")
    catalogue_lock = data.get("source_lock", {})
    for key in ("name", "revision", "upstream_commit"):
        if catalogue_lock.get(key) != source.get(key):
            fail(f"catalogue source lock {key} differs from ISANITY toolchain pin")
    if catalogue_lock.get("xed_sys_version") != distribution.get("version"):
        fail("catalogue xed-sys version differs from ISANITY toolchain pin")
    if catalogue_lock.get("registry_checksum_sha256", distribution.get("registry_checksum_sha256")) != distribution.get("registry_checksum_sha256"):
        fail("catalogue XED registry checksum differs from ISANITY toolchain pin")
    return source


def exact_source_pattern(record: dict, data: dict) -> tuple[int, int, int, list[int]]:
    name = record.get("iform", {}).get("name", "<unknown>")
    identity = record.get("identity", {})
    encoding = identity.get("encoding", {})
    modrm = identity.get("modrm", {})
    evidence = record.get("evidence", {}).get("source_pattern", {})
    source_path = evidence.get("path")
    source_digest = evidence.get("sha256")
    pinned = data.get("inputs", {}).get(f"pinned-xed-source:{source_path}", {})
    if not source_path or pinned.get("path") != source_path or pinned.get("sha256") != source_digest:
        fail(f"{name}: exact source-pattern digest is not matched by catalogue input pins")
    binding = evidence.get("iform_binding", {})
    if binding.get("status") != "unique-exact-compiled-source-pattern-iform-join":
        fail(f"{name}: source/compiled IFORM join is not unique and exact")
    if evidence.get("unresolved_source_effects") != [] or evidence.get("operands") != "":
        fail(f"{name}: source pattern has unresolved effects or non-empty operands")
    pattern = evidence.get("pattern", "")
    pattern_opcodes = [int(value, 16) for value in HEX_BYTE_RE.findall(pattern)]
    opcode_map = encoding.get("opcode_map")
    opcode = int(encoding.get("opcode_bytes", "0x00"), 16)
    expected_opcodes = ([0x0F, opcode] if opcode_map == "0f" else [opcode])
    if pattern_opcodes != expected_opcodes:
        fail(f"{name}: source PATTERN opcode sequence differs from canonical identity")
    reg_match = re.search(r"\bREG\[0b([01]{3})\]", pattern)
    rm_match = re.search(r"\bRM\[0b([01]{3})\]", pattern)
    if not re.search(r"\bMOD\[0b11\]\s+MOD=3\b", pattern) or not reg_match or not rm_match:
        fail(f"{name}: expected exact MOD=3, fixed REG/RM source selector")
    reg = int(reg_match.group(1), 2)
    rm = int(rm_match.group(1), 2)
    if reg != encoding.get("modrm_reg_extension"):
        fail(f"{name}: source REG selector differs from canonical identity")
    if modrm.get("mod_values") != [3] or modrm.get("rm_value") != rm:
        fail(f"{name}: source MOD/RM selectors differ from canonical identity")
    prefix_rules = ["no-refining-prefix"] if re.search(r"\bno_refining_prefix\b", pattern) else []
    if encoding.get("prefix_constraints") != prefix_rules:
        fail(f"{name}: source prefix rule differs from canonical identity")
    if identity.get("operand_shape") != []:
        fail(f"{name}: fixed-ModRM slice must have zero explicit operands")
    return opcode, reg, rm, expected_opcodes


def load() -> tuple[list[dict], str, str]:
    raw = CATALOGUE.read_bytes()
    catalogue_digest = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw)
    if data.get("identity_schema") != "form-identity-v2":
        fail("catalogue identity_schema is not form-identity-v2")
    source = validate_toolchain(data)
    xed_distribution = source["distribution"]
    source_forms_pin = data.get("inputs", {}).get("catalogue/imports/xed-source-forms-v1.json", {})
    source_forms = ISANITY / "catalogue/imports/xed-source-forms-v1.json"
    if (
        source_forms_pin.get("path") != "catalogue/imports/xed-source-forms-v1.json"
        or not source_forms.is_file()
        or hashlib.sha256(source_forms.read_bytes()).hexdigest() != source_forms_pin.get("sha256")
    ):
        fail("pinned XED source-forms artefact digest is stale")

    rows = []
    seen_names: set[str] = set()
    seen_keys: set[tuple[int, int, int]] = set()
    for record in data.get("records", []):
        name = record.get("iform", {}).get("name")
        value = record.get("iform", {}).get("value")
        identity = record.get("identity", {})
        encoding = identity.get("encoding", {})
        if not isinstance(name, str):
            fail("record has malformed IFORM name")
        opcode_map = encoding.get("opcode_map")
        if opcode_map not in ("primary", "0f"):
            fail(f"{name}: unsupported opcode map")
        opcode, reg, rm, _ = exact_source_pattern(record, data)
        if not (
            identity.get("architecture") == "x86"
            and identity.get("execution_mode") == "long64"
            and identity.get("schema_version") == 2
            and encoding.get("family") == "legacy"
            and encoding.get("mandatory_prefix") is None
            and encoding.get("immediate_encoding") is None
            and encoding.get("address_size_policy") is None
            and encoding.get("operand_size_policy") == "not-applicable"
            and record.get("semantic_status") == "unmapped"
            and record.get("fidelity_status") == "unassessed"
            and record.get("identity_review") == "accepted-for-this-exact-fixed-opcode-modrm-selector-zero-operand-source-slice"
        ):
            fail(f"{name}: record is outside accepted fixed-ModRM zero-operand candidate scope")
        canonical = record.get("canonical_bytes")
        form_id = record.get("form_id", "")
        match = FORM_ID_RE.fullmatch(form_id)
        if not isinstance(canonical, str) or not match or json.loads(canonical) != identity:
            fail(f"{name}: malformed canonical bytes, FormId, or canonical identity mismatch")
        canonical_raw = canonical.encode("utf-8")
        actual = hashlib.sha256(
            FORM_ID_DOMAIN + len(canonical_raw).to_bytes(8, "big") + canonical_raw
        ).hexdigest()
        if actual != match.group(1):
            fail(f"{name}: FormId digest mismatch")
        observations = record.get("evidence", {}).get("runtime_observations", [])
        exact = [
            observation for observation in observations
            if observation.get("iform_name") == name
            and observation.get("mode") == "long64"
            and observation.get("err") == "NONE"
            and observation.get("decoded_length") == len(bytes.fromhex(observation.get("bytes_hex", "")))
            and observation.get("bytes_sha256") == hashlib.sha256(bytes.fromhex(observation.get("bytes_hex", ""))).hexdigest()
        ]
        if not exact:
            fail(f"{name}: missing exact pinned-XED decode observation")
        selected = None
        for observation in exact:
            byte_seq = bytes.fromhex(observation["bytes_hex"])
            if len(byte_seq) not in (2, 3) or observation.get("decoded_length") != len(byte_seq):
                continue
            if opcode_map == "0f":
                if byte_seq[0] != 0x0F or byte_seq[1] != opcode:
                    continue
                modrm_byte = byte_seq[2] if len(byte_seq) == 3 else -1
            else:
                if byte_seq[0] != opcode:
                    continue
                modrm_byte = byte_seq[1] if len(byte_seq) == 2 else -1
            if modrm_byte >= 0 and modrm_byte >> 6 == 3 and ((modrm_byte >> 3) & 7) == reg and (modrm_byte & 7) == rm:
                selected = observation
                break
        if selected is None:
            fail(f"{name}: no exact XED byte witness confirms opcode, MOD, REG, RM, and length")
        if name in seen_names or (0 if opcode_map == "primary" else 1, opcode, reg, rm) in seen_keys:
            fail(f"{name}: duplicate IFORM or ambiguous fixed-ModRM encoding selector")
        seen_names.add(name)
        seen_keys.add((0 if opcode_map == "primary" else 1, opcode, reg, rm))
        rows.append({
            "iform": name,
            "iform_value": value,
            "opcode_map": opcode_map,
            "opcode": opcode,
            "modrm_reg": reg,
            "modrm_rm": rm,
            "canonical_id": form_id,
            "canonical_sha256": match.group(1),
            "example_bytes": selected["bytes_hex"].lower(),
            "explicit_operands": 0,
        })
    rows.sort(key=lambda row: (row["opcode_map"], row["opcode"], row["modrm_reg"], row["modrm_rm"], row["iform"]))
    if len(rows) != 18:
        fail(f"expected exactly 18 fixed-ModRM identities, found {len(rows)}")
    catalogue_source_sha = data["inputs"].get("pinned-xed-source:xed/datafiles/xed-isa.txt", {}).get("sha256")
    if not isinstance(catalogue_source_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", catalogue_source_sha):
        fail("catalogue lacks pinned xed-isa.txt source digest")
    return rows, catalogue_digest, catalogue_source_sha


def render(rows: list[dict], catalogue_digest: str, source_digest: str) -> str:
    lines = [
        "// @generated by tools/isanity-map/generate_fixed_modrm.py; do not edit by hand.",
        f"// ISANITY fixed-ModRM catalogue SHA-256: {catalogue_digest}",
        f"// Pinned XED xed-isa.txt SHA-256: {source_digest}",
        "pub(super) const FIXED_MODRM_CATALOGUE_SHA256: &str =",
        f"    {json.dumps(catalogue_digest)};",
        "pub(super) const FIXED_MODRM_XED_SOURCE_SHA256: &str =",
        f"    {json.dumps(source_digest)};",
        "pub(super) static GENERATED_FIXED_MODRM_FORMS: &[GeneratedFixedModrmForm] = &[",
    ]
    for row in rows:
        lines.extend([
            "    GeneratedFixedModrmForm {",
            f"        iform: {json.dumps(row['iform'])},",
            f"        iform_value: {row['iform_value']},",
            f"        opcode_map: {json.dumps(row['opcode_map'])},",
            f"        opcode: 0x{row['opcode']:02x},",
            f"        modrm_reg: {row['modrm_reg']},",
            f"        modrm_rm: {row['modrm_rm']},",
            f"        canonical_id: {json.dumps(row['canonical_id'])},",
            f"        canonical_sha256: {json.dumps(row['canonical_sha256'])},",
            f"        example_bytes: {json.dumps(row['example_bytes'])},",
            f"        explicit_operands: {row['explicit_operands']},",
            "    },",
        ])
    lines.append("];")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check the checked-in Rust snapshot")
    args = parser.parse_args()
    rows, catalogue_digest, source_digest = load()
    expected = render(rows, catalogue_digest, source_digest)
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            fail(f"{OUTPUT.relative_to(ROOT)} is stale; rerun generator")
        print(f"ISANITY fixed-ModRM map is current ({len(rows)} identities)")
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} ({len(rows)} identities)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
