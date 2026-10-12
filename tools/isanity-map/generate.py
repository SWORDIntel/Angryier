#!/usr/bin/env python3
"""Generate Angryier's checked-in ISANITY canonical-ID handoff table.

Run from any directory, for example:
  python3 tools/isanity-map/generate.py --catalogue ../ISANITY/catalogue/canonical/x86-register-direct-v2.json
  python3 tools/isanity-map/generate.py --catalogue ../ISANITY/catalogue/canonical/x86-register-direct-v2.json --check

The generated Rust has no runtime dependency on an ISANITY checkout.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "crates/angryier-runtime/src/isanity_handoff_generated.rs"
TARGET_IFORMS = {
    "XED_IFORM_MOV_GPRv_GPRv_89": (0x89, "MOV_R64_R64", 1, 0),
    "XED_IFORM_MOV_GPRv_GPRv_8B": (0x8B, "MOV_R64_R64", 0, 1),
    "XED_IFORM_ADD_GPRv_GPRv_01": (0x01, "ADD_R64_R64", 1, 0),
    "XED_IFORM_ADD_GPRv_GPRv_03": (0x03, "ADD_R64_R64", 0, 1),
    "XED_IFORM_SUB_GPRv_GPRv_29": (0x29, "SUB_R64_R64", 1, 0),
    "XED_IFORM_SUB_GPRv_GPRv_2B": (0x2B, "SUB_R64_R64", 0, 1),
    "XED_IFORM_CMP_GPRv_GPRv_39": (0x39, "CMP_R64_R64", 1, 0),
    "XED_IFORM_CMP_GPRv_GPRv_3B": (0x3B, "CMP_R64_R64", 0, 1),
}
LEGACY_SYMBOLS = {
    "MOV_R64_R64": "crate::forms::MOV_R64_R64",
    "ADD_R64_R64": "crate::forms::ADD_R64_R64",
    "SUB_R64_R64": "crate::forms::SUB_R64_R64",
    "CMP_R64_R64": "crate::forms::CMP_R64_R64",
}
FORM_ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
FORM_ID_DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"


def fail(message: str) -> None:
    raise SystemExit(f"isanity map generation failed: {message}")


def rust_string(value: str) -> str:
    return json.dumps(value)


def load(catalogue_path: Path) -> tuple[dict, list[dict], str]:
    raw = catalogue_path.read_bytes()
    catalogue_sha = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw)
    if data.get("identity_schema") != "form-identity-v2":
        fail("catalogue identity_schema is not form-identity-v2")
    xed_sha = data.get("inputs", {}).get("intel-xed-v2024.05.20/xed/datafiles/xed-isa.txt")
    if not isinstance(xed_sha, str) or len(xed_sha) != 64:
        fail("catalogue lacks the pinned xed-isa.txt SHA-256")

    by_iform: dict[str, list[dict]] = {}
    for record in data.get("records", []):
        iform = record.get("iform", {}).get("name")
        if iform in TARGET_IFORMS:
            by_iform.setdefault(iform, []).append(record)

    if set(by_iform) != set(TARGET_IFORMS):
        fail(f"target IFORM set mismatch: found {sorted(by_iform)}")

    rows = []
    for iform, (opcode, legacy_name, reg_operand, rm_operand) in TARGET_IFORMS.items():
        candidates = by_iform[iform]
        matching = []
        for record in candidates:
            canonical = record.get("canonical_bytes")
            claimed = record.get("form_id", "")
            match = FORM_ID_RE.fullmatch(claimed)
            if not isinstance(canonical, str) or not match:
                fail(f"{iform}: malformed canonical bytes or form_id")
            canonical_raw = canonical.encode("utf-8")
            actual = hashlib.sha256(
                FORM_ID_DOMAIN + len(canonical_raw).to_bytes(8, "big") + canonical_raw
            ).hexdigest()
            if actual != match.group(1):
                fail(f"{iform}: canonical form ID hash mismatch")
            identity = json.loads(canonical)
            source_sha = record.get("evidence", {}).get("source_pattern", {}).get("sha256")
            if source_sha != xed_sha:
                fail(f"{iform}: source SHA-256 differs from pinned XED ISA source")
            enc = identity.get("encoding", {})
            shape = identity.get("operand_shape", [])
            if (
                identity.get("architecture") == "x86"
                and identity.get("execution_mode") == "long64"
                and identity.get("instruction_class") == iform.split("_", 3)[2]
                and enc.get("family") == "legacy"
                and enc.get("opcode_map") == "primary"
                and enc.get("opcode_bytes", "").lower() == f"0x{opcode:02x}"
                and enc.get("operand_size_policy") == "rex-w-64"
                and enc.get("prefix_constraints") == ["rex-w-one"]
                and identity.get("modrm", {}).get("mod_values") == [3]
                and identity.get("modrm", {}).get("reg_operand") == reg_operand
                and identity.get("modrm", {}).get("rm_operand") == rm_operand
                and len(shape) == 2
                and all(item.get("kind") == "gpr" and item.get("width_bits") == 64 for item in shape)
            ):
                matching.append(record)
        if len(matching) != 1:
            fail(f"{iform}: expected exactly one long64/R64/MOD=3 identity, got {len(matching)}")
        record = matching[0]
        if record.get("identity_review") != "accepted-for-this-exact-long64-register-direct-width-slice":
            fail(f"{iform}: identity is not accepted for exact register-direct slice")
        rows.append(
            {
                "iform": iform,
                "opcode": opcode,
                "legacy_name": legacy_name,
                "form_id": record["form_id"],
                "reg_operand": reg_operand,
                "rm_operand": rm_operand,
            }
        )

    mappings = {item.get("symbol"): int(item.get("legacy_id", "-1"), 16) for item in data.get("legacy_mappings", [])}
    for name, symbol in LEGACY_SYMBOLS.items():
        if symbol not in mappings:
            fail(f"catalogue has no legacy mapping for {symbol}")
    for row in rows:
        row["legacy_id"] = mappings[LEGACY_SYMBOLS[row["legacy_name"]]]
    return data, rows, catalogue_sha


def render(data: dict, rows: list[dict], catalogue_sha: str) -> str:
    xed_sha = data["inputs"]["intel-xed-v2024.05.20/xed/datafiles/xed-isa.txt"]
    lines = [
        "// @generated by tools/isanity-map/generate.py; do not edit by hand.",
        f"// ISANITY catalogue SHA-256: {catalogue_sha}",
        f"// Pinned XED xed-isa.txt SHA-256: {xed_sha}",
        "pub(super) const GENERATED_CATALOGUE_SHA256: &str =",
        f"    {rust_string(catalogue_sha)};",
        "pub(super) const GENERATED_XED_SOURCE_SHA256: &str =",
        f"    {rust_string(xed_sha)};",
        "pub(super) static GENERATED_FORMS: &[GeneratedForm] = &[",
    ]
    for row in rows:
        digest = FORM_ID_RE.fullmatch(row["form_id"]).group(1)
        lines.extend(
            [
                "    GeneratedForm {",
                f"        iform: {rust_string(row['iform'])},",
                f"        opcode: 0x{row['opcode']:02x},",
                f"        reg_operand: {row['reg_operand']},",
                f"        rm_operand: {row['rm_operand']},",
                f"        canonical_id: {rust_string(row['form_id'])},",
                f"        canonical_sha256: {rust_string(digest)},",
                f"        legacy_form: {rust_string(row['legacy_name'])},",
                f"        legacy_id: 0x{row['legacy_id']:08x},",
                "    },",
            ]
        )
    lines.extend(["];"])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalogue", type=Path, required=True, help="ISANITY canonical identity catalogue")
    parser.add_argument("--check", action="store_true", help="fail if checked-in Rust differs from generated output")
    args = parser.parse_args()
    data, rows, catalogue_sha = load(args.catalogue)
    expected = render(data, rows, catalogue_sha)
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            fail(f"{OUTPUT.relative_to(ROOT)} is stale; rerun generator")
        print(f"ISANITY handoff is current ({len(rows)} canonical forms)")
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} ({len(rows)} canonical forms)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
