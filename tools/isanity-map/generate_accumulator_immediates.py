#!/usr/bin/env python3
"""Generate mode/width/opcode-qualified ISANITY accumulator-immediate maps."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISANITY = ROOT.parent / "ISANITY"
OUT = ROOT / "crates/angryier-runtime/src/isanity_accumulator_immediates_generated.rs"
SOURCES = (
    ("x86-accumulator-imm8-v2.json", 63, "cd1e420f3ab2674831e002472a1167a78311fea9ffdcdf998e0be6f30eb93245"),
    ("x86-accumulator-simmz-v2.json", 135, "f5435636dd40ced81e3b3cf2f23efa6bb892d873f3dd6708ce419118308d1047"),
)
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
RUNTIME_MODES = {"long64": "Long64", "legacy32": "Legacy32", "legacy16": "Legacy16"}
OPCODES = {
    "ADD": (0x04, 0x05), "OR": (0x0C, 0x0D), "ADC": (0x14, 0x15),
    "SBB": (0x1C, 0x1D), "AND": (0x24, 0x25), "SUB": (0x2C, 0x2D),
    "XOR": (0x34, 0x35), "CMP": (0x3C, 0x3D), "TEST": (0xA8, 0xA9),
}


def fail(message: str) -> None:
    raise ValueError(message)


def verify_id(record: dict) -> None:
    canonical = record.get("canonical_bytes")
    match = ID_RE.fullmatch(record.get("form_id", ""))
    identity = record.get("identity", {})
    if not isinstance(canonical, str) or json.loads(canonical) != identity or not match:
        fail("malformed canonical identity bytes/FormId")
    raw = canonical.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(raw).to_bytes(8, "big") + raw).hexdigest()
    if digest != match.group(1):
        fail(f"{record.get('iform', {}).get('name')}: FormId digest mismatch")


def expected_prefix(mode: str, width: int, category: str) -> int | None:
    if category == "imm8":
        return None
    table = {
        ("long64", 16): 0x66,
        ("long64", 32): None,
        ("long64", 64): 0x48,
        ("legacy16", 16): None,
        ("legacy16", 32): 0x66,
        ("legacy32", 16): 0x66,
        ("legacy32", 32): None,
    }
    return table.get((mode, width), ...)


def make_pattern(record: dict, category: str) -> tuple[str, int, int, int, int, int] | None:
    iform = record["iform"]["name"]
    identity = record["identity"]
    mode = identity["execution_mode"]
    if mode not in RUNTIME_MODES:
        return None
    width = identity["operand_shape"][0]["width_bits"]
    immediate_width = identity["operand_shape"][1]["width_bits"]
    opcode_text = identity["encoding"]["opcode_bytes"]
    opcode = int(opcode_text, 16)
    op_index = 0 if category == "imm8" else 1
    if opcode != OPCODES.get(identity.get("instruction_class"), (None, None))[op_index]:
        fail(f"{iform}: source opcode does not match the accumulator operation")
    prefix = expected_prefix(mode, width, category)
    if prefix is ...:
        return None
    shape = identity["operand_shape"]
    accumulator_access = "read" if identity.get("instruction_class") in {"CMP", "TEST"} else "read-write"
    if not (
        len(shape) == 2
        and shape[0].get("kind") == "register"
        and shape[0].get("presence") == "implicit"
        and shape[0].get("access") == accumulator_access
        and shape[1].get("kind") == "immediate"
        and shape[1].get("access") == "read"
        and shape[1].get("presence", "explicit") == "explicit"
        and identity.get("architecture") == "x86"
        and identity.get("encoding", {}).get("opcode_map") == "primary"
        and identity.get("encoding", {}).get("family") == "legacy"
        and identity.get("modrm") is None
        and record.get("semantic_status") == "unmapped"
        and record.get("fidelity_status") == "unassessed"
    ):
        fail(f"{iform}: identity is not an unmapped implicit-accumulator/immediate candidate")
    expected_shape = (
        (width == 8 and immediate_width == 8 and opcode in {0x04, 0x0C, 0x14, 0x1C, 0x24, 0x2C, 0x34, 0x3C, 0xA8})
        if category == "imm8"
        else (width in {16, 32, 64} and immediate_width == (16 if width == 16 else 32))
    )
    if not expected_shape:
        fail(f"{iform}: unsupported accumulator/immediate widths")
    if category == "imm8":
        expected_encoding = "uimm8" if identity.get("instruction_class") in {"OR", "XOR"} else "simm8-signed"
        if identity["encoding"].get("immediate_encoding") != expected_encoding:
            fail(f"{iform}: IMM8 signedness changed")
    if category == "simmz" and identity["encoding"].get("immediate_encoding") != ("simm16" if width == 16 else "simm32"):
        fail(f"{iform}: SIMMz immediate encoding changed")
    if iform.startswith("XED_IFORM_TEST_") and category == "simmz":
        pass
    if category == "imm8" and "AL_IMMb" not in iform:
        fail(f"{iform}: IMM8 identity is not in the pinned AL family")
    if category == "simmz" and "_OrAX_IMMz" not in iform:
        fail(f"{iform}: SIMMz identity is not in the pinned accumulator family")
    constraints = identity["encoding"].get("prefix_constraints", [])
    if category == "imm8":
        if constraints not in ([], ["rex2-forbidden"]):
            fail(f"{iform}: IMM8 candidate unexpectedly constrains a prefix")
    else:
        expected_constraints = {
            None: ["legacy-prefixes-forbidden", "rex-forbidden"],
            0x66: ["legacy-prefixes-forbidden-except-66", "operand-size-override-66", "rex-forbidden"],
            0x48: ["legacy-prefixes-forbidden", "rex-byte-exact-0x48"],
        }[prefix]
        if identity.get("instruction_class") == "TEST":
            expected_constraints = [*expected_constraints, "rex2-forbidden"]
        if constraints != expected_constraints:
            fail(f"{iform}: unsupported prefix-constraint profile {constraints}")
    observations = record.get("evidence", {}).get("runtime_observations", [])
    if not observations:
        fail(f"{iform}: candidate has no pinned runtime witnesses")
    if len({(obs.get("iform_name"), obs.get("iform_value")) for obs in observations}) != 1:
        fail(f"{iform}: observations disagree on exact XED IFORM")
    value = record["iform"]["value"]
    opcode_offset = 1 if prefix is not None else 0
    imm_bytes = immediate_width // 8
    for obs in observations:
        if not (
            obs.get("err") == "NONE"
            and obs.get("iform_name") == iform
            and obs.get("iform_value") == value
            and obs.get("mode") == mode
            and obs.get("execution_mode") == mode
            and obs.get("operand_size_bits") == width
        ):
            fail(f"{iform}: observation mode/IFORM/width does not match identity")
        try:
            raw = bytes.fromhex(obs["bytes_hex"])
        except (KeyError, TypeError, ValueError):
            fail(f"{iform}: malformed runtime witness")
        expected_bytes = (bytes([prefix]) if prefix is not None else b"") + bytes([opcode]) + bytes(imm_bytes)
        if len(raw) != len(expected_bytes) or raw[opcode_offset] != opcode or raw[:opcode_offset] != expected_bytes[:opcode_offset]:
            fail(f"{iform}: runtime witness does not match opcode/prefix/immediate width")
    signed = identity["encoding"].get("immediate_encoding") != "uimm8"
    return mode, value, opcode, prefix if prefix is not None else 256, width, immediate_width, imm_bytes, signed


def render() -> str:
    rows: list[tuple[str, str, int, int, int, int, int, str]] = []
    unsupported: list[tuple[str, str, int, str, str]] = []
    seen_ids: set[str] = set()
    counts = {"imm8": 0, "simmz": 0}
    for filename, expected_count, expected_sha in SOURCES:
        path = ISANITY / "catalogue/canonical" / filename
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != expected_sha:
            fail(f"{filename}: source catalogue digest changed; review and repin explicitly")
        data = json.loads(raw)
        category = "imm8" if "imm8" in filename else "simmz"
        if data.get("identity_schema") != "form-identity-v2" or len(data.get("records", [])) != expected_count:
            fail(f"{filename}: schema or record count changed")
        for record in data["records"]:
            verify_id(record)
            form_id = record["form_id"]
            if form_id in seen_ids:
                fail(f"{filename}: duplicate candidate identity {form_id}")
            seen_ids.add(form_id)
            pattern = make_pattern(record, category)
            if pattern is None:
                mode = record["identity"]["execution_mode"]
                iform = record["iform"]["name"]
                unsupported.append((form_id, iform, record["iform"]["value"], mode, f"unsupported-execution-mode:{mode}:Angryier adapter exposes only long64, legacy32, and legacy16"))
                continue
            mode, value, opcode, prefix_code, width, immediate_width, imm_bytes, signed = pattern
            if mode not in RUNTIME_MODES:
                fail(f"{filename}: supported pattern escaped mode filter")
            counts[category] += 1
            rows.append((form_id, record["iform"]["name"], value, opcode, prefix_code, width, immediate_width, imm_bytes, RUNTIME_MODES[mode], signed))
    if counts != {"imm8": 27, "simmz": 63} or len(unsupported) != 108 or len(rows) != 90:
        fail(f"slice accounting changed: mapped={counts}, unsupported={len(unsupported)}, rows={len(rows)}")
    if len({row[0] for row in rows} | {row[0] for row in unsupported}) != 198:
        fail("candidate identities are not partitioned exactly once")
    lines = [
        "// @generated by tools/isanity-map/generate_accumulator_immediates.py; do not edit.",
        *(f"// {name} SHA-256: {digest}" for name, _, digest in SOURCES),
        "pub(super) static ACCUMULATOR_IMMEDIATE_FORMS: &[AccumulatorImmediateForm] = &[",
    ]
    for form_id, iform, value, opcode, prefix, width, immediate_width, imm_bytes, mode, signed in sorted(rows, key=lambda row: (row[1], row[5], row[8], row[0])):
        lines.append(
            f'    AccumulatorImmediateForm {{ canonical_id: "{form_id}", iform: "{iform}", iform_value: {value}, '
            f'mode: InstructionMode::{mode}, opcode_byte: 0x{opcode:02x}, prefix_byte: {"None" if prefix == 256 else f"Some(0x{prefix:02x})"}, '
            f'operand_width_bits: {width}, immediate_width_bits: {immediate_width}, immediate_width_bytes: {imm_bytes}, signed_immediate: {str(signed).lower()} }},'
        )
    lines.append("];\npub(super) static ACCUMULATOR_IMMEDIATE_UNSUPPORTED: &[UnsupportedAccumulatorIdentity] = &[")
    for form_id, iform, value, mode, reason in sorted(unsupported, key=lambda row: (row[1], row[3], row[0])):
        lines.append(f'    UnsupportedAccumulatorIdentity {{ canonical_id: "{form_id}", iform: "{iform}", iform_value: {value}, source_mode: "{mode}", reason: "{reason}" }},')
    lines.extend([
        "];",
        "#[cfg(test)]",
        "pub(super) const IMM8_MAPPED_COUNT: usize = 27;",
        "#[cfg(test)]",
        "pub(super) const SIMMZ_MAPPED_COUNT: usize = 63;",
        "#[cfg(test)]",
        "pub(super) const ACCUMULATOR_UNSUPPORTED_COUNT: usize = 108;",
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
        print("ISANITY accumulator immediate map is current (90 mapped, 108 reason-coded unsupported identities)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY accumulator immediate map (90 mapped, 108 reason-coded unsupported identities)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
