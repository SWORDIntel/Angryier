#!/usr/bin/env python3
"""Generate Angryier's narrow MOV GPRv-memory candidate identity table."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

EXPECTED_SHA256 = "4c72d18360748f61b4357b89e1005b66876597bc02e4ac89008b9d1451e57800"
ADDRESSING_SHA256 = "8f8b5c75537d1a8a5f117432ab711f9c1e3a5e4c7bc9c48dc8517f0f11740165"
EXPECTED_IFORMS = {"XED_IFORM_MOV_MEMv_GPRv", "XED_IFORM_MOV_GPRv_MEMv"}
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INPUT = ROOT.parent / "ISANITY/tools/xed-gprv-mov-memory-identity/out/x86-mov-gprv-memory-package-v2.json"
DEFAULT_ADDRESSING_INPUT = ROOT.parent / "ISANITY/tools/xed-gprv-mov-addressing/out/x86-mov-gprv-addressing-v1.json"
DEFAULT_OUTPUT = ROOT / "crates/angryier-runtime/src/isanity_mov_memory_generated.rs"


def rust_bytes(text: str) -> str:
    return "&[" + ", ".join(f"0x{byte:02x}" for byte in bytes.fromhex(text)) + "]"


def render(source: Path, addressing_source: Path) -> bytes:
    raw = source.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != EXPECTED_SHA256:
        raise ValueError(f"MOV package SHA mismatch: expected {EXPECTED_SHA256}, got {digest}")
    document = json.loads(raw)
    records = document.get("records")
    if (document.get("identity_schema") != "form-identity-v2"
            or document.get("status") != "partial-source-backed-slice"
            or not isinstance(records, list) or len(records) != 6):
        raise ValueError("unexpected MOV package schema, status, or record count")
    addressing_raw = addressing_source.read_bytes()
    addressing_digest = hashlib.sha256(addressing_raw).hexdigest()
    if addressing_digest != ADDRESSING_SHA256:
        raise ValueError(f"MOV addressing SHA mismatch: expected {ADDRESSING_SHA256}, got {addressing_digest}")
    addressing = json.loads(addressing_raw)
    coverage = addressing.get("coverage", {})
    if (addressing.get("artifact_kind") != "isanity-xed-gprv-mov-addressing-witness-slice"
            or addressing.get("artifact_status") != "candidate-only-observation-evidence"
            or addressing.get("inputs", {}).get("base_mov_identity_wrapper", {}).get("sha256") != digest
            or coverage.get("accepted_witnesses") != 90
            or coverage.get("semantic_status") != "unmapped"
            or coverage.get("fidelity_status") != "unassessed"
            or len(addressing.get("address_case_definitions", [])) != 15
            or len(addressing.get("residue", [])) != 6):
        raise ValueError("unexpected MOV addressing package join, scope, or coverage")
    address_observations = addressing.get("observations")
    if not isinstance(address_observations, list) or len(address_observations) != 90:
        raise ValueError("expected exactly 90 accepted MOV addressing witnesses")
    case_names = {case.get("name") for case in addressing["address_case_definitions"]}
    if None in case_names or len(case_names) != 15:
        raise ValueError("addressing cases contain a missing or duplicate name")
    rows: list[str] = []
    ids: set[str] = set()
    iforms: set[str] = set()
    seen_witnesses: set[str] = set()
    for record in records:
        identity = record["identity"]
        evidence = record["evidence"]
        if (record.get("semantic_status") != "unmapped"
                or record.get("fidelity_status") != "unassessed"
                or record.get("identity_review") != "candidate-only-exact-source-generator-and-pinned-XED-witness-slice"
                or identity.get("execution_mode") != "long64"
                or identity.get("instruction_class") != "MOV"):
            raise ValueError("candidate-only scope/status changed")
        form = record["iform"]
        if form.get("name") not in EXPECTED_IFORMS:
            raise ValueError(f"unexpected IFORM: {form.get('name')}")
        if evidence.get("mode_applicability", {}).get("status") != "applicable":
            raise ValueError("mode applicability lacks a positive observation")
        source_operands = identity.get("operand_shape")
        if not isinstance(source_operands, list) or len(source_operands) != 2:
            raise ValueError("expected two ordered source operands")
        operands = []
        for operand in source_operands:
            kind = {"gpr": "Register", "memory": "Memory"}.get(operand.get("kind"))
            access = {"read": "Read", "write": "Write"}.get(operand.get("access"))
            width = operand.get("width_bits")
            if kind is None or access is None or not isinstance(width, int):
                raise ValueError("unsupported source operand kind/access/width")
            operands.append((kind, width, access))
        observations = evidence.get("runtime_observations")
        if not isinstance(observations, list) or len(observations) != 3:
            raise ValueError("expected three XED observations per identity")
        witnesses = []
        for observation in observations:
            byte_text = observation.get("bytes_hex", "")
            byte_data = bytes.fromhex(byte_text)
            if (hashlib.sha256(byte_data).hexdigest() != observation.get("bytes_sha256")
                    or observation.get("decoded_length") != len(byte_data)
                    or observation.get("iform_name") != form["name"]
                    or observation.get("iform_value") != form["value"]
                    or observation.get("execution_mode") != "long64"
                    or observation.get("err") != "NONE"):
                raise ValueError("runtime witness failed its pinned XED join/length check")
            decoded_shapes = observation.get("source_operand_shapes", [])
            if observation.get("source_operand_widths_bits") != [op[1] for op in operands]:
                raise ValueError("runtime witness operand width order differs")
            projected = [(op.get("name"), op.get("action"), op.get("visibility")) for op in decoded_shapes]
            expected = [("MEM0" if kind == "Memory" else "REG0", "W" if access == "Write" else "R", "EXPLICIT")
                        for kind, _, access in operands]
            if projected != expected:
                raise ValueError("runtime witness operand order/access differs")
            if byte_text in seen_witnesses:
                raise ValueError("duplicate base witness across canonical identities")
            seen_witnesses.add(byte_text)
            witnesses.append(rust_bytes(byte_text))
        operand_widths = [operand[1] for operand in operands]
        matching_addresses = [
            observation for observation in address_observations
            if observation.get("iform", {}).get("name") == form["name"]
            and observation.get("iform", {}).get("value") == form["value"]
            and observation.get("expected", {}).get("operand_widths_bits") == operand_widths
        ]
        if len(matching_addresses) != 15:
            raise ValueError("expected 15 address witnesses for each source-bound identity")
        for observation in matching_addresses:
            byte_text = observation.get("bytes_hex", "")
            byte_data = bytes.fromhex(byte_text)
            expected = observation.get("expected", {})
            observed = observation.get("observed", {})
            if (observation.get("status") != "accepted"
                    or observation.get("case") not in case_names
                    or observation.get("rejection_reasons") != []
                    or byte_text in seen_witnesses
                    or observed.get("decode_status") != "decoded"
                    or observed.get("decoded_length") != len(byte_data)
                    or observed.get("iform_name") != form["name"]
                    or observed.get("iform_value") != form["value"]):
                raise ValueError("address observation failed accepted-XED witness checks")
            for key in ("instruction_class", "operand_widths_bits", "operand_shapes",
                        "address_width_bits", "base_register", "index_register", "scale",
                        "displacement_width_bytes", "displacement_signed"):
                if expected.get(key) != observed.get(key):
                    raise ValueError(f"address observation expected/observed mismatch for {key}")
            if expected.get("instruction_class") != "MOV" or expected.get("operand_widths_bits") != operand_widths:
                raise ValueError("address observation does not match identity operand widths/class")
            projected = [(op.get("name"), op.get("action"), op.get("visibility"))
                         for op in expected.get("operand_shapes", [])]
            wanted = [("MEM0" if kind == "Memory" else "REG0",
                       "W" if access == "Write" else "R", "EXPLICIT")
                      for kind, _, access in operands]
            if projected != wanted:
                raise ValueError("address observation ordered operand action mismatch")
            seen_witnesses.add(byte_text)
            witnesses.append(rust_bytes(byte_text))
        canonical_id = record.get("form_id")
        if not isinstance(canonical_id, str) or canonical_id in ids:
            raise ValueError("missing or duplicate canonical ID")
        ids.add(canonical_id)
        iforms.add(form["name"])
        rust_operands = ", ".join(
            f"ExpectedOperand {{ kind: OperandKindTag::{kind}, width_bits: {width}, access: AccessKind::{access} }}"
            for kind, width, access in operands
        )
        rows.append(
            "    MovMemoryForm { "
            f'canonical_id: "{canonical_id}", iform: "{form["name"]}", iform_value: {form["value"]}, '
            f"mode: InstructionMode::Long64, operands: [{rust_operands}], witnesses: &[{', '.join(witnesses)}] }},"
        )
    if iforms != EXPECTED_IFORMS:
        raise ValueError(f"source IFORM set mismatch: {sorted(iforms)}")
    residue_ids = {row.get("form_id") for row in addressing["residue"]}
    if residue_ids != ids or len(seen_witnesses) != 108:
        raise ValueError("MOV addressing residue/source identity join or 108-witness union mismatch")
    lines = [
        "// @generated by tools/isanity-map/generate_mov_memory.py; do not edit.",
        f"// ISANITY MOV GPRv memory package SHA-256: {digest}",
        f"// ISANITY MOV addressing evidence SHA-256: {addressing_digest}",
        "pub(super) static MOV_MEMORY_FORMS: &[MovMemoryForm] = &[",
        *rows,
        "];",
        "",
    ]
    return "\n".join(lines).encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--addressing-input", type=Path, default=DEFAULT_ADDRESSING_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        generated = render(args.input, args.addressing_input)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"generate_mov_memory: {error}", file=sys.stderr)
        return 1
    if args.check:
        try:
            current = args.output.read_bytes()
        except OSError as error:
            print(f"generate_mov_memory: {error}", file=sys.stderr)
            return 1
        if current != generated:
            print(f"generated file is stale: {args.output}", file=sys.stderr)
            return 1
        print(f"checked {args.output}")
        return 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(generated)
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
