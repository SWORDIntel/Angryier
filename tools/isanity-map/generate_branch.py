#!/usr/bin/env python3
"""Generate Angryier's ISANITY near-Jcc identity map from pinned catalogues."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "crates/angryier-runtime/src/isanity_branch_generated.rs"
ISANITY = ROOT.parent / "ISANITY"
CATALOGUES = (
    ISANITY / "catalogue/canonical/x86-conditional-branch-v2.json",
    ISANITY / "catalogue/canonical/x86-conditional-branch-expansion-v2.json",
)
TOOLCHAIN_LOCK = ISANITY / "catalogue/source-toolchain-lock-v1.json"
CARGO_LOCK = ROOT / "Cargo.lock"
FORM_ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
FORM_ID_DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
SOURCE_PATH = "intel-xed-v2024.05.20/xed/datafiles/xed-isa.txt"


def fail(message: str) -> None:
    raise SystemExit(f"ISANITY branch map generation failed: {message}")


def load_rows(paths: tuple[Path, ...]) -> tuple[list[dict], str, str]:
    rows: dict[str, dict] = {}
    catalogue_digests = []
    source_digest: str | None = None
    toolchain = json.loads(TOOLCHAIN_LOCK.read_text(encoding="utf-8"))
    xed_sources = [source for source in toolchain.get("sources", []) if source.get("name") == "intel-xed"]
    if len(xed_sources) != 1:
        fail("ISANITY source-toolchain lock must identify exactly one Intel XED source")
    pinned_xed = xed_sources[0]
    cargo_blocks = CARGO_LOCK.read_text(encoding="utf-8").split("[[package]]")
    xed_packages = [
        block
        for block in cargo_blocks
        if re.search(r'^name = "xed-sys"$', block, re.MULTILINE)
    ]
    if len(xed_packages) != 1:
        fail("Angryier Cargo.lock must pin exactly one xed-sys package")
    xed_version = re.search(r'^version = "([^"]+)"$', xed_packages[0], re.MULTILINE)
    xed_checksum = re.search(r'^checksum = "([0-9a-f]{64})"$', xed_packages[0], re.MULTILINE)
    distribution = pinned_xed.get("distribution", {})
    if (
        not xed_version
        or xed_version.group(1) != distribution.get("version")
        or not xed_checksum
        or xed_checksum.group(1) != distribution.get("registry_checksum_sha256")
    ):
        fail("Angryier Cargo.lock does not match the pinned ISANITY xed-sys package")
    for path in paths:
        raw = path.read_bytes()
        catalogue_digests.append(hashlib.sha256(raw).hexdigest())
        data = json.loads(raw)
        if data.get("identity_schema") != "form-identity-v2":
            fail(f"{path.name}: identity_schema is not form-identity-v2")
        import_digest = data.get("inputs", {}).get("xed-source-forms", {}).get("sha256")
        if not isinstance(import_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", import_digest):
            fail(f"{path.name}: missing pinned XED source-forms artifact digest")
        source_forms_path = ISANITY / "catalogue/imports/xed-source-forms-v1.json"
        if hashlib.sha256(source_forms_path.read_bytes()).hexdigest() != import_digest:
            fail(f"{path.name}: XED source-forms artifact digest is stale")
        lock = data.get("source_lock", {})
        if any(
            lock.get(key) != pinned_xed.get(lock_key)
            for key, lock_key in (
                ("name", "name"),
                ("revision", "revision"),
                ("upstream_commit", "upstream_commit"),
            )
        ):
            fail(f"{path.name}: source lock differs from the ISANITY toolchain pin")
        if lock.get("xed_sys_version", distribution.get("version")) != distribution.get("version"):
            fail(f"{path.name}: xed-sys version differs from the ISANITY toolchain pin")
        if lock.get("registry_checksum_sha256", distribution.get("registry_checksum_sha256")) != distribution.get("registry_checksum_sha256"):
            fail(f"{path.name}: XED registry checksum differs from the ISANITY toolchain pin")
        for record in data.get("records", []):
            identity = record.get("identity", {})
            encoding = identity.get("encoding", {})
            shape = identity.get("operand_shape", [])
            if not (
                identity.get("architecture") == "x86"
                and identity.get("execution_mode") == "long64"
                and encoding.get("opcode_map") == "0f"
                and encoding.get("opcode_bytes", "").lower().startswith("0x0f8")
                and encoding.get("operand_size_policy") == "rel32"
                and encoding.get("immediate_encoding") == "rel32"
                and len(shape) == 1
                and shape[0].get("kind") == "relative-branch"
                and shape[0].get("width_bits") == 32
            ):
                continue
            if "branch_hint" not in encoding.get("prefix_constraints", []):
                fail(f"{record.get('iform', {}).get('name')}: source identity omits branch-hint policy")
            if record.get("semantic_status") != "unmapped" or record.get("fidelity_status") != "unassessed":
                fail(f"{path.name}: branch identity unexpectedly claims semantic/fidelity status")
            if not str(record.get("identity_review", "")).startswith((
                "accepted-for-this-exact-long64-relative-branch-shape",
                "source-pattern-opcode-condition-and-pinned-XED-witness-derived",
            )):
                fail(f"{path.name}: identity is not accepted as a branch identity")
            digest = record.get("evidence", {}).get("source_pattern", {}).get("sha256")
            source_pattern = record.get("evidence", {}).get("source_pattern", {})
            if source_pattern.get("path") != "xed/datafiles/xed-isa.txt":
                fail(f"{name}: source path is not the pinned xed-isa.txt")
            if digest is not None:
                if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                    fail(f"{name}: malformed exact source-pattern digest")
                if source_digest is not None and source_digest != digest:
                    fail("branch catalogues pin different XED ISA source revisions")
                source_digest = digest
            name = record.get("iform", {}).get("name")
            canonical = record.get("canonical_bytes")
            form_id = record.get("form_id", "")
            match = FORM_ID_RE.fullmatch(form_id)
            if not isinstance(name, str) or not isinstance(canonical, str) or not match:
                fail(f"{path.name}: malformed IFORM, canonical identity, or FormId")
            actual = hashlib.sha256(
                FORM_ID_DOMAIN + len(canonical.encode()).to_bytes(8, "big") + canonical.encode()
            ).hexdigest()
            if actual != match.group(1) or json.loads(canonical) != identity:
                fail(f"{name}: FormId/canonical identity integrity check failed")
            opcode_match = re.fullmatch(r"0x0f8([0-9a-f])", encoding["opcode_bytes"].lower())
            if not opcode_match:
                fail(f"{name}: expected exact 0F 8x rel32 opcode")
            opcode = int(opcode_match.group(1), 16)
            source_opcode = re.search(r"\b0x0F\s+0x([0-9A-Fa-f]{2})\b", source_pattern.get("pattern", ""))
            if not source_opcode or int(source_opcode.group(1), 16) != 0x80 + opcode:
                fail(f"{name}: source PATTERN opcode disagrees with canonical identity")
            condition_code = source_pattern.get("condition_code_from_opcode_low_nibble")
            if condition_code is not None and condition_code != opcode:
                fail(f"{name}: source condition-code selector disagrees with opcode")
            expected_class = name.removeprefix("XED_IFORM_").removesuffix("_RELBRd")
            if identity.get("instruction_class") != expected_class:
                fail(f"{name}: IFORM instruction class disagrees with canonical identity")
            observations = record.get("evidence", {}).get("runtime_observations", [])
            if not any(
                observation.get("iform_name") == name
                and observation.get("mode") == "long64"
                and isinstance(observation.get("bytes_hex"), str)
                and re.fullmatch(r"0f8[0-9a-f]{1}[0-9a-f]{8}", observation["bytes_hex"].lower())
                and int(observation["bytes_hex"][2:4], 16) == 0x80 + opcode
                for observation in observations
            ):
                fail(f"{name}: no exact long64 XED runtime observation confirms opcode/length")
            if name in rows and rows[name]["form_id"] != form_id:
                fail(f"{name}: conflicting branch identities across source slices")
            rows[name] = {"iform": name, "opcode_low_nibble": opcode, "form_id": form_id}

    ordered = sorted(rows.values(), key=lambda row: (row["opcode_low_nibble"], row["iform"]))
    if len(ordered) != 16 or [row["opcode_low_nibble"] for row in ordered] != list(range(16)):
        fail(f"expected the full 16-condition rel32 family, found {len(ordered)} rows")
    catalogue_digest = hashlib.sha256("".join(catalogue_digests).encode("ascii")).hexdigest()
    return ordered, catalogue_digest, source_digest or ""


def render(rows: list[dict], catalogue_digest: str, source_digest: str) -> str:
    lines = [
        "// @generated by tools/isanity-map/generate_branch.py; do not edit by hand.",
        f"// Ordered source-catalogue digest: {catalogue_digest}",
        f"// Pinned XED xed-isa.txt SHA-256: {source_digest}",
        "pub(super) const BRANCH_CATALOGUE_SHA256: &str =",
        f"    {json.dumps(catalogue_digest)};",
        "pub(super) const BRANCH_XED_SOURCE_SHA256: &str =",
        f"    {json.dumps(source_digest)};",
        "pub(super) static GENERATED_BRANCH_FORMS: &[GeneratedBranchForm] = &[",
    ]
    for row in rows:
        lines.extend([
            "    GeneratedBranchForm {",
            f"        iform: {json.dumps(row['iform'])},",
            f"        opcode_low_nibble: 0x{row['opcode_low_nibble']:x},",
            f"        canonical_id: {json.dumps(row['form_id'])},",
            "    },",
        ])
    lines.append("];")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check generated Rust is current")
    args = parser.parse_args()
    rows, catalogue_digest, source_digest = load_rows(CATALOGUES)
    expected = render(rows, catalogue_digest, source_digest)
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != expected:
            fail(f"{OUTPUT.relative_to(ROOT)} is stale; rerun generator")
        print(f"ISANITY branch map is current ({len(rows)} near-Jcc identities)")
        return 0
    OUTPUT.write_text(expected, encoding="utf-8")
    print(f"generated {OUTPUT.relative_to(ROOT)} ({len(rows)} near-Jcc identities)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
