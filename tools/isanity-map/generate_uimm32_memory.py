#!/usr/bin/env python3
"""Generate Angryier's exact-witness ISANITY UIMM32 memory identity map."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT.parent / "ISANITY/tools/xed-uimm32-memory-identity/out/x86-uimm32-memory-v2.json"
SOURCE_SHA256 = "cee4d4c39f242a664b185efc1c77224362d26d7ca216a3638fe59819c3452191"
OUT = ROOT / "crates/angryier-runtime/src/isanity_uimm32_memory_generated.rs"
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")
SUPPORTED = {"long64": "Long64", "legacy32": "Legacy32"}
UNSUPPORTED_REASONS = {
    "legacy16": "unsupported-mode:legacy16:Angryier XED normalization rejects 16-bit memory-address metadata",
    "compat16": "unsupported-mode:compat16:Angryier XED machine-mode API cannot distinguish compatibility-16 from legacy16",
    "compat32": "unsupported-mode:compat32:Angryier XED machine-mode API cannot distinguish compatibility-32 from legacy32",
}
EXPECTED_IFORMS = {
    "XED_IFORM_BEXTR_XOP_GPR32d_MEMd_IMMd": 248,
    "XED_IFORM_BEXTR_XOP_GPRyy_MEMy_IMMd": 250,
    "XED_IFORM_LWPINS_GPRyy_MEMd_IMMd": 1525,
    "XED_IFORM_LWPVAL_GPRyy_MEMd_IMMd": 1527,
}


def fail(message: str) -> None:
    raise ValueError(message)


def verify_record(record: dict) -> tuple[str, str, int, str, list[bytes], int | None, int | None]:
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
    operands = identity["operand_shape"]
    if not (
        identity.get("architecture") == "x86"
        and iform in EXPECTED_IFORMS
        and value == EXPECTED_IFORMS[iform]
        and encoding.get("family") == "xop"
        and encoding.get("opcode_map") == "xop-map8"
        and encoding.get("immediate_encoding") == "uimm32"
        and record.get("semantic_status") == "unmapped"
        and record.get("fidelity_status") == "unassessed"
        and len(operands) == 3
        and operands[0].get("kind") == "gpr"
        and operands[0].get("access") == "write"
        and operands[1].get("kind") == "memory"
        and operands[1].get("access") == "read"
        and operands[2].get("kind") == "immediate"
        and operands[2].get("width_bits") == 32
        and operands[2].get("access") == "read"
    ):
        fail(f"{iform}/{mode}: identity escaped pinned XOP UIMM32 memory scope")
    if mode not in SUPPORTED and mode not in UNSUPPORTED_REASONS:
        fail(f"{iform}/{mode}: unexpected machine mode")
    observations = record.get("evidence", {}).get("accepted_profile_observations", [])
    witnesses: set[bytes] = set()
    for obs in observations:
        instance = obs.get("instance_parameters", {})
        decoder = obs.get("decoder", {})
        if not (
            obs.get("mode") == mode
            and obs.get("iform_name") == iform
            and obs.get("iform_value") == value
            and obs.get("disposition") == "decode-accepted-exact-iform"
            and decoder.get("error") == "NONE"
            and decoder.get("iform") == iform.removeprefix("XED_IFORM_")
            and decoder.get("length", 0) > 0
            and obs.get("reason_code") is None
        ):
            fail(f"{iform}/{mode}: malformed accepted profile observation")
        try:
            witness = bytes.fromhex(instance["bytes_hex"])
        except (KeyError, ValueError) as error:
            fail(f"{iform}/{mode}: invalid witness bytes ({error})")
        if len(witness) != decoder["length"] or len(witness) > 15:
            fail(f"{iform}/{mode}: witness length mismatch")
        # Angryier's current normalizer cannot represent 16-bit effective
        # addressing. Keep 16-bit address-override observations out of the
        # legacy32 selectable witness set without deleting their identities.
        if not (mode == "legacy32" and instance.get("address_size_bits") == 16):
            witnesses.add(witness)
    if not witnesses:
        fail(f"{iform}/{mode}: no exact decoder witnesses")
    return (
        record["form_id"], iform, value, mode, sorted(witnesses),
        operands[0].get("width_bits"), operands[1].get("width_bits"),
    )


def render() -> str:
    raw = SOURCE.read_bytes()
    if hashlib.sha256(raw).hexdigest() != SOURCE_SHA256:
        fail("ISANITY UIMM32 memory artifact digest changed; review and repin")
    data = json.loads(raw)
    if not (
        data.get("identity_schema") == "form-identity-v2"
        and data.get("status") == "partial-source-backed-slice"
        and data.get("artifact_status") == "candidate-only-source-derived-memory-iform-identities"
        and data.get("source_lock", {}).get("upstream_commit") == "a425c75467e1f4c0ef7311c988474c61d7e9e293"
        and len(data.get("records", [])) == 15
        and data.get("coverage", {}).get("semantic_status") == "unmapped"
        and data.get("coverage", {}).get("fidelity_status") == "unassessed"
    ):
        fail("ISANITY UIMM32 memory schema, source pin, or candidate status changed")
    mapped: list[tuple[str, str, int, str, list[bytes], int | None, int | None]] = []
    unsupported: list[tuple[str, str, int, str, str]] = []
    seen: set[str] = set()
    ids_by_iform_mode: dict[tuple[str, str], str] = {}
    for record in data["records"]:
        form_id, iform, value, mode, witnesses, gpr_width, memory_width = verify_record(record)
        if form_id in seen:
            fail(f"duplicate canonical identity {form_id}")
        seen.add(form_id)
        ids_by_iform_mode[(iform, mode)] = form_id
        if mode in SUPPORTED:
            mapped.append((form_id, iform, value, mode, witnesses, gpr_width, memory_width))
        else:
            unsupported.append((form_id, iform, value, mode, UNSUPPORTED_REASONS[mode]))
    if len(mapped) != 6 or len(unsupported) != 9 or len(seen) != 15:
        fail(f"slice accounting changed: mapped={len(mapped)}, unsupported={len(unsupported)}")
    profile_residue: list[tuple[str, str, str, str, int, str, str, bytes]] = []
    for obs in data.get("profile_observations", []):
        mode = obs.get("mode")
        iform = obs.get("iform_name")
        value = obs.get("iform_value")
        if (iform, mode) not in ids_by_iform_mode:
            fail(f"profile observation has no identity join: {iform}/{mode}")
        params = obs.get("instance_parameters", {})
        if obs.get("disposition") == "decode-accepted-exact-iform":
            if not (mode == "legacy32" and params.get("address_size_bits") == 16):
                continue
            reason = "unsupported-address-size:16:Angryier XED normalization rejects 16-bit memory-address metadata"
        elif obs.get("disposition") == "decode-rejected-or-divergent":
            reason = obs.get("reason_code")
            if not isinstance(reason, str) or not reason:
                fail(f"{iform}/{mode}: rejected profile observation has no reason code")
        else:
            fail(f"{iform}/{mode}: unrecognized profile disposition")
        try:
            witness = bytes.fromhex(params["bytes_hex"])
        except (KeyError, ValueError) as error:
            fail(f"{iform}/{mode}: invalid profile residue bytes ({error})")
        profile_residue.append((
            ids_by_iform_mode[(iform, mode)], iform, mode, obs.get("profile", ""), value,
            obs.get("chip", "unknown"), reason, witness,
        ))
    if len(profile_residue) != 69:
        fail(f"profile residue accounting changed: expected 69, got {len(profile_residue)}")
    lines = [
        "// @generated by tools/isanity-map/generate_uimm32_memory.py; do not edit.",
        f"// ISANITY x86-uimm32-memory-v2.json SHA-256: {SOURCE_SHA256}",
        "pub(super) static UIMM32_MEMORY_FORMS: &[Uimm32MemoryForm] = &[",
    ]
    for form_id, iform, value, mode, witnesses, gpr_width, memory_width in sorted(mapped, key=lambda row: (row[1], row[3], row[0])):
        witness_text = "&[" + ", ".join(
            "&[" + ", ".join(f"0x{byte:02x}" for byte in witness) + "]" for witness in witnesses
        ) + "]"
        lines.append(
            f'    Uimm32MemoryForm {{ canonical_id: "{form_id}", iform: "{iform}", '
            f"iform_value: {value}, mode: InstructionMode::{SUPPORTED[mode]}, gpr_width_bits: {option_width(gpr_width)}, "
            f"memory_width_bits: {option_width(memory_width)}, witnesses: {witness_text} }},"
        )
    lines.append("];\npub(super) static UIMM32_MEMORY_UNSUPPORTED: &[UnsupportedUimm32MemoryIdentity] = &[")
    for form_id, iform, value, mode, reason in sorted(unsupported, key=lambda row: (row[1], row[3], row[0])):
        lines.append(
            f'    UnsupportedUimm32MemoryIdentity {{ canonical_id: "{form_id}", iform: "{iform}", '
            f'iform_value: {value}, source_mode: "{mode}", reason: "{reason}" }},'
        )
    lines.append("];\npub(super) static UIMM32_MEMORY_UNSUPPORTED_PROFILES: &[UnsupportedUimm32MemoryProfileObservation] = &[")
    for form_id, iform, mode, profile, value, chip, reason, witness in sorted(
        profile_residue, key=lambda row: (row[1], row[2], row[3], row[7])
    ):
        witness_text = "&[" + ", ".join(f"0x{byte:02x}" for byte in witness) + "]"
        lines.append(
            f'    UnsupportedUimm32MemoryProfileObservation {{ canonical_id: "{form_id}", '
            f'iform: "{iform}", iform_value: {value}, source_mode: "{mode}", profile: "{profile}", chip: "{chip}", '
            f'reason: "{reason}", witness: {witness_text} }},'
        )
    lines.extend([
        "];",
        "#[cfg(test)]",
        "pub(super) const UIMM32_MEMORY_MAPPED_COUNT: usize = 6;",
        "#[cfg(test)]",
        "pub(super) const UIMM32_MEMORY_UNSUPPORTED_COUNT: usize = 9;",
        "#[cfg(test)]",
        "pub(super) const UIMM32_MEMORY_UNSUPPORTED_PROFILE_COUNT: usize = 69;",
    ])
    return "\n".join(lines) + "\n"


def option_width(width: int | None) -> str:
    return "None" if width is None else f"Some({width})"


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
        print("ISANITY UIMM32 memory map current (6 exact-witness mapped, 9 reason-coded unsupported)")
        return 0
    OUT.write_text(output, encoding="utf-8")
    print("generated ISANITY UIMM32 memory map (6 exact-witness mapped, 9 reason-coded unsupported)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
