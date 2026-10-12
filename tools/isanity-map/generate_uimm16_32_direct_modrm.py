#!/usr/bin/env python3
"""Generate Angryier's direct-ModRM UIMM16/UIMM32 candidate adapter."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT.parent / "ISANITY/tools/xed-uimm16-32-direct-modrm-identity/out/x86-uimm16-32-direct-modrm-v2.json"
SOURCE_SHA256 = "1a29f432141c4bf7b47acda93062256ac8e425fcf040534702f44d85c2644462"
OUT = ROOT / "crates/angryier-runtime/src/isanity_uimm16_32_direct_modrm_generated.rs"
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
SUPPORTED_MODES = {"long64": "Long64", "legacy32": "Legacy32", "legacy16": "Legacy16"}
UNSUPPORTED_REASON = "unsupported-mode:{mode}:Angryier XED mode API cannot represent compatibility-mode identity distinctly"
UNOBSERVABLE_IFORMS = {"XED_IFORM_URDMSR_GPR64u64_IMM32", "XED_IFORM_UWRMSR_IMM32_GPR64u64"}
UNOBSERVABLE_REASON = "unobservable-operand:Angryier XED normalized operands omit the source-declared implicit MSR register"


def fail(message: str) -> None:
    raise ValueError(message)


def rust_bytes(raw: bytes) -> str:
    return "&[" + ", ".join(f"0x{byte:02x}" for byte in raw) + "]"


def render() -> str:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("ISANITY direct-ModRM UIMM16/32 sidecar digest changed; review and repin")
    data = json.loads(raw)
    coverage = data.get("coverage", {})
    if not (
        data.get("artifact_kind") == "isanity-xed-uimm16-32-direct-modrm-candidate-identity-slice"
        and data.get("artifact_status") == "candidate-only-source-derived-identity-evidence"
        and data.get("source_pattern_audit_complete") is True
        and data.get("source_lock", {}).get("upstream_commit") == "a425c75467e1f4c0ef7311c988474c61d7e9e293"
        and coverage.get("assigned_candidate_identities") == 17
        and coverage.get("assigned_iforms") == 6
        and coverage.get("accepted_probe_witnesses") == 416
        and coverage.get("profile_residue_count") == 1024
        and coverage.get("source_alternatives_audited") == 10255
        and coverage.get("semantic_status") == "unmapped"
        and coverage.get("fidelity_status") == "unassessed"
        and len(data.get("records", [])) == 17
        and len(data.get("profile_residue", [])) == 1024
        and len(data.get("excluded_source_pattern_audit", [])) == 10249
    ):
        fail("ISANITY direct-ModRM schema, coverage, or candidate status changed")

    mapped: list[dict] = []
    unsupported: list[dict] = []
    seen_ids: set[str] = set()
    seen_pairs: set[tuple[str, str]] = set()
    for record in data["records"]:
        iform = record["iform"]["name"]
        value = record["iform"]["value"]
        identity = record["identity"]
        mode = identity["execution_mode"]
        canonical = record.get("canonical_bytes")
        match = ID_RE.fullmatch(record.get("form_id", ""))
        if not isinstance(canonical, str) or json.loads(canonical) != identity or not match:
            fail(f"{iform}/{mode}: malformed canonical identity")
        encoded = canonical.encode("utf-8")
        if hashlib.sha256(DOMAIN + len(encoded).to_bytes(8, "big") + encoded).hexdigest() != match.group(1):
            fail(f"{iform}/{mode}: FormId digest mismatch")
        encoding = identity["encoding"]
        modrm = identity["modrm"]
        width = {"uimm16": 16, "uimm32": 32}.get(encoding.get("immediate_encoding"))
        observations = record.get("evidence", {}).get("xed_witnesses", [])
        if not (
            identity.get("architecture") == "x86"
            and identity.get("schema_version") == 2
            and identity.get("instruction_class") in {"BEXTR_XOP", "LWPINS", "LWPVAL", "URDMSR", "UWRMSR"}
            and encoding.get("family") in {"xop", "evex"}
            and width in {16, 32}
            and modrm.get("mod_values") == [3]
            and record.get("identity_status") == "candidate-only-source-and-XED-probe-join"
            and record.get("semantic_status") == "unmapped"
            and record.get("fidelity_status") == "unassessed"
            and len(observations) > 0
        ):
            fail(f"{iform}/{mode}: candidate escaped direct-ModRM UIMM identity scope")
        key = (iform, mode)
        if record["form_id"] in seen_ids or key in seen_pairs:
            fail(f"duplicate candidate identity {iform}/{mode}")
        seen_ids.add(record["form_id"])
        seen_pairs.add(key)
        source_join = record["evidence"].get("source_join", {})
        source_projection = source_join.get("source_selector_projection", {})
        fixed_extension = source_projection.get("reg", {}).get("identity_binding", "")
        fixed_match = re.fullmatch(r"fixed-extension:(\d+)", fixed_extension)
        binding = source_join.get("iform_binding_kind")
        triple_bound = (
            binding == "pinned-generator-exact-ICLASS-PATTERN-OPERANDS-triple"
            and source_join.get("compiled_mapping_evidence") == "pinned-generator-exact-triple"
            and source_join.get("generator_join", {}).get("kind") == "pinned-generator-exact-triple"
            and source_join.get("generator_join", {}).get("row", {}).get("iform") == iform.removeprefix("XED_IFORM_")
            and iform.removeprefix("XED_IFORM_")
            in source_join.get("generator_join", {}).get("row", {}).get("exact_triple_generator_candidates", [])
        )
        literal_bound = (
            binding == "literal-source-IFORM-tag"
            and source_join.get("compiled_mapping_evidence") == "literal-iform"
            and source_join.get("source_iform_tag") == iform.removeprefix("XED_IFORM_")
        )
        if not (
            (triple_bound or literal_bound)
            and source_projection.get("mod", {}).get("value") == 3
            and source_projection.get("immediate_width_bits") == width
            and source_projection.get("immediate_call") == f"UIMM{width}()"
        ):
            fail(f"{iform}/{mode}: source/compiled join or direct selector provenance changed")
        shapes = identity.get("operand_shape", [])
        if not shapes:
            fail(f"{iform}/{mode}: source operand shape is missing")
        operands = []
        for operand_index, shape in enumerate(shapes):
            kind = shape.get("kind")
            access = shape.get("access")
            if kind not in {"register", "immediate"} or access not in {"read", "write", "read-write"}:
                fail(f"{iform}/{mode}: unsupported normalized source operand shape")
            field = None
            if kind == "register":
                if record["identity"]["instruction_class"] in {"LWPINS", "LWPVAL"}:
                    # Only the second explicit GPR is bound to the free RM selector.
                    if operand_index == 1:
                        field = "Rm"
                elif modrm.get("reg_operand") is not None and operand_index == modrm["reg_operand"]:
                    field = "Reg"
                elif modrm.get("rm_operand") is not None and operand_index == modrm["rm_operand"]:
                    field = "Rm"
            operands.append((kind, shape.get("width_bits"), access, shape.get("presence") != "implicit", field))
        immediate_shapes = [row for row in operands if row[0] == "immediate"]
        if len(immediate_shapes) != 1 or immediate_shapes[0][1] != width:
            fail(f"{iform}/{mode}: exact immediate operand width missing")
        witnesses = []
        seen_assignments: set[tuple[int, int]] = set()
        for observation in observations:
            assignment = observation.get("assignment", {})
            if assignment.get("MOD") != 3 or not (0 <= assignment.get("REG", -1) <= 7 and 0 <= assignment.get("RM", -1) <= 7):
                fail(f"{iform}/{mode}: invalid direct ModRM assignment")
            if fixed_match and assignment["REG"] != int(fixed_match.group(1)):
                fail(f"{iform}/{mode}: observed ModRM.REG differs from the source fixed extension")
            pair = (assignment["REG"], assignment["RM"])
            if pair in seen_assignments:
                fail(f"{iform}/{mode}: duplicate ModRM selector assignment")
            seen_assignments.add(pair)
            try:
                witness = bytes.fromhex(observation["bytes_hex"])
            except (KeyError, ValueError) as error:
                fail(f"{iform}/{mode}: invalid XED witness ({error})")
            if (
                observation.get("iform_name") != iform.removeprefix("XED_IFORM_")
                or observation.get("decoded_length") != len(witness)
                or observation.get("candidate_id") is None
                or observation.get("profile", {}).get("mode") != mode
                or len(witness) < 2 + width // 8
                or (witness[-(width // 8):] != bytes(width // 8))
            ):
                fail(f"{iform}/{mode}: witness does not bind full-length IFORM/UIMM evidence")
            modrm_byte = witness[-(width // 8) - 1]
            if (modrm_byte >> 6, (modrm_byte >> 3) & 7, modrm_byte & 7) != (3, *pair):
                fail(f"{iform}/{mode}: witness bytes disagree with source ModRM selector assignment")
            witnesses.append((witness, assignment["REG"], assignment["RM"]))
        if mode in SUPPORTED_MODES and iform not in UNOBSERVABLE_IFORMS:
            mapped.append({"id": record["form_id"], "iform": iform, "value": value, "mode": SUPPORTED_MODES[mode],
                           "width": width, "operands": operands, "witnesses": witnesses})
        else:
            reason = UNOBSERVABLE_REASON if iform in UNOBSERVABLE_IFORMS else UNSUPPORTED_REASON.format(mode=mode)
            unsupported.append({"id": record["form_id"], "iform": iform, "value": value, "mode": mode,
                                "reason": reason, "witnesses": witnesses})

    if len(mapped) != 9 or len(unsupported) != 8 or sum(len(r["witnesses"]) for r in mapped + unsupported) != 416:
        fail(f"adapter accounting changed: mapped={len(mapped)}, unsupported={len(unsupported)}")
    residues = data["profile_residue"]
    residue_counts: dict[str, int] = {}
    for residue in residues:
        reason = residue.get("reason", "unknown")
        residue_counts[reason] = residue_counts.get(reason, 0) + 1
    source_counts: dict[str, int] = {}
    for exclusion in data["excluded_source_pattern_audit"]:
        disposition = exclusion.get("disposition", "unknown")
        source_counts[disposition] = source_counts.get(disposition, 0) + 1
    lines = [
        "// @generated by tools/isanity-map/generate_uimm16_32_direct_modrm.py; do not edit.",
        f"// ISANITY x86-uimm16-32-direct-modrm-v2.json SHA-256: {SOURCE_SHA256}",
        "pub(super) static UIMM16_32_DIRECT_MODRM_FORMS: &[UimmDirectModrmForm] = &[",
    ]
    for row in sorted(mapped, key=lambda r: (r["iform"], r["mode"])):
        shape_text = "&[" + ", ".join(
            "UimmDirectOperand { "
            f"kind: DirectOperandKind::{kind.title()}, width_bits: {('Some(' + str(width) + ')') if width is not None else 'None'}, "
            f"access: DirectAccess::{ {'read':'Read','write':'Write','read-write':'ReadWrite'}[access] }, "
            f"visibility: OperandVisibility::{ 'Explicit' if explicit else 'Implicit' }, "
            f"selector: {('Some(ModRmField::' + selector + ')') if selector else 'None'} "
            "}"
            for kind, width, access, explicit, selector in row["operands"]
        ) + "]"
        witness_text = "&[" + ", ".join(
            "UimmDirectWitness { bytes: " + rust_bytes(raw) + f", reg: {reg}, rm: {rm} }}"
            for raw, reg, rm in row["witnesses"]
        ) + "]"
        lines.append(
            f'    UimmDirectModrmForm {{ canonical_id: "{row["id"]}", iform: "{row["iform"]}", '
            f'iform_value: {row["value"]}, mode: InstructionMode::{row["mode"]}, immediate_width_bits: {row["width"]}, '
            f'operands: {shape_text}, witnesses: {witness_text} }},'
        )
    lines.append("];\npub(super) static UIMM16_32_DIRECT_MODRM_UNSUPPORTED: &[UnsupportedUimmDirectModrmIdentity] = &[")
    for row in sorted(unsupported, key=lambda r: (r["iform"], r["mode"])):
        witnesses = "&[" + ", ".join(rust_bytes(item[0]) for item in row["witnesses"]) + "]"
        lines.append(
            f'    UnsupportedUimmDirectModrmIdentity {{ canonical_id: "{row["id"]}", iform: "{row["iform"]}", '
            f'iform_value: {row["value"]}, source_mode: "{row["mode"]}", reason: "{row["reason"]}", witnesses: {witnesses} }},'
        )
    lines.append("];\npub(super) static DIRECT_MODRM_PROFILE_RESIDUE_COUNTS: &[(&str, usize)] = &[")
    for reason, count in sorted(residue_counts.items()):
        lines.append(f'    ("{reason}", {count}),')
    lines.append("];\npub(super) static DIRECT_MODRM_SOURCE_EXCLUSION_COUNTS: &[(&str, usize)] = &[")
    for reason, count in sorted(source_counts.items()):
        lines.append(f'    ("{reason}", {count}),')
    lines.extend([
        "];",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_CANDIDATE_COUNT: usize = 17;",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_MAPPED_COUNT: usize = 9;",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_UNSUPPORTED_COUNT: usize = 8;",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_WITNESS_COUNT: usize = 416;",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_PROFILE_RESIDUE_COUNT: usize = 1024;",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_SOURCE_EXCLUSION_COUNT: usize = 10249;",
        "#[cfg(test)] pub(super) const DIRECT_MODRM_SOURCE_AUDIT_TOTAL_COUNT: usize = 10255;",
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
        print("ISANITY direct-ModRM UIMM16/32 map current (9 mapped, 8 unsupported/unobservable; all 416 witnesses retained)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY direct-ModRM UIMM16/32 map (9 mapped, 8 unsupported/unobservable; all 416 witnesses retained)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
