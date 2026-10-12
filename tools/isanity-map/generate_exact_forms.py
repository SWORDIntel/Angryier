#!/usr/bin/env python3
"""Generate exact-witness identity rows for additive ISANITY byte slices."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ISANITY = ROOT.parent / "ISANITY"
OUTPUT = ROOT / "crates/angryier-runtime/src/isanity_catalogue_forms_generated.rs"
SOURCES = (
    ISANITY / "catalogue/canonical/x86-uimm8-modrm-v2.json",
    ISANITY / "catalogue/canonical/x86-simm8-modrm-v2.json",
    ISANITY / "catalogue/canonical/x86-uimm16-32-v2.json",
    ISANITY / "catalogue/canonical/x86-zero-operand-fixed-opcode-v2.json",
    ISANITY / "catalogue/canonical/x86-zero-operand-fixed-opcode-census-v2.json",
    ISANITY / "catalogue/canonical/x86-register-direct-v2.json",
    ISANITY / "catalogue/canonical/x86-mov-opcode-register-v2.json",
)
MOV_OPCODE_REGISTER_SHA256 = "cd6198dbddf030a5a856e09da3a6082b65cb02d1526f03ed20afe499ebd276eb"
DOMAIN = b"ISANITY:FORM:IDENTITY:v2\0"
ID_PREFIX = "isanity:form:v2:sha256:"
SOURCE_LOCK = {"name": "intel-xed", "revision": "v2024.05.20", "upstream_commit": "a425c75467e1f4c0ef7311c988474c61d7e9e293", "xed_sys_version": "0.6.0+xed-2024.05.20"}
ID_RE = re.compile(r"^isanity:form:v2:sha256:([0-9a-f]{64})$")


def fail(message: str) -> None:
    raise ValueError(message)


def validate_record(record: dict, artifact: dict, category: str) -> tuple[str, int, list[bytes], str, list[dict]]:
    iform = record.get("iform", {}).get("name")
    value = record.get("iform", {}).get("value")
    identity = record.get("identity", {})
    evidence = record.get("evidence", {})
    source = evidence.get("source_pattern", {})
    if not isinstance(iform, str) or not isinstance(value, int):
        fail("record has malformed XED IFORM identity")
    if record.get("semantic_status") != "unmapped" or record.get("fidelity_status") != "unassessed":
        fail(f"{iform}: identity candidates must not promote semantics or fidelity")
    if category == "primary_register_direct":
        if source.get("iform_binding_source") not in {"exact-compiled-source-join", "source-iform-token"}:
            fail(f"{iform}: unsupported primary register-direct source-to-IFORM binding")
        allowed_source_paths = {"xed/datafiles/xed-isa.txt", "xed/datafiles/xed-amd-prefetch.txt"}
        source_input = artifact.get("inputs", {}).get(f"intel-xed-v2024.05.20/{source.get('path')}")
        if source.get("path") not in allowed_source_paths or source_input != source.get("sha256"):
            fail(f"{iform}: primary register-direct source digest is not pinned")
    else:
        binding = source.get("iform_binding", {})
        if binding.get("status") not in {
            "unique-exact-compiled-source-pattern-iform-join",
            "pinned-merged-source-record-and-runtime-observation-join",
            "unique-exact-compiled-form-pattern-join-verified-by-all-pinned-xed-candidates",
        } or any("execution semantics" not in item and "fidelity" not in item for item in source.get("unresolved_source_effects", [])):
            fail(f"{iform}: source-to-IFORM binding is not exact and complete")
        pinned = artifact.get("inputs", {}).get(f"pinned-xed-source:{source.get('path')}", {})
        if pinned.get("sha256") != source.get("sha256"):
            pinned = artifact.get("inputs", {}).get("merged-xed-dec-instructions", {})
        if pinned.get("sha256") != source.get("sha256") and category != "fixed_opcode_census":
            fail(f"{iform}: source digest is not pinned by the canonical sidecar")
    observations = evidence.get("runtime_observations", [])
    if category == "primary_register_direct":
        matches = [
            item for item in observations
            if item.get("iform_name") == iform and item.get("iform_value") == value
            and item.get("context", {}).get("mode") == "long64" and item.get("error") == "NONE"
        ]
    else:
        matches = [item for item in observations if item.get("iform_name") == iform and item.get("iform_value") == value and item.get("mode") == "long64" and item.get("err") == "NONE"]
    if not matches:
        fail(f"{iform}: expected at least one accepted long64 XED observation")
    observed_rows = sorted(
        matches,
        key=lambda item: (
            item.get("bytes", item.get("bytes_hex", "")),
            item.get("instruction_length", item.get("decoded_length", 0)),
        ),
    )
    witnesses = []
    for observed in observed_rows:
        try:
            encoded = bytes.fromhex(observed.get("bytes", observed.get("bytes_hex", "")))
        except (TypeError, ValueError):
            fail(f"{iform}: invalid runtime byte witness")
        expected_length = observed.get("instruction_length", observed.get("decoded_length"))
        expected_digest = observed.get("bytes_sha256")
        if not encoded or len(encoded) != expected_length or (expected_digest is not None and hashlib.sha256(encoded).hexdigest() != expected_digest):
            fail(f"{iform}: runtime byte witness length or digest mismatch")
        if encoded not in witnesses:
            witnesses.append(encoded)
    canonical = record.get("canonical_bytes")
    match = ID_RE.fullmatch(record.get("form_id", ""))
    if not isinstance(canonical, str) or json.loads(canonical) != identity or not match:
        fail(f"{iform}: malformed canonical identity bytes/ID")
    canonical_raw = canonical.encode("utf-8")
    digest = hashlib.sha256(DOMAIN + len(canonical_raw).to_bytes(8, "big") + canonical_raw).hexdigest()
    if digest != match.group(1):
        fail(f"{iform}: FormId digest mismatch")
    if identity.get("architecture") != "x86" or identity.get("operand_shape") is None:
        fail(f"{iform}: unsupported canonical identity shape")
    operands = []
    signed = identity.get("encoding", {}).get("immediate_encoding") == "simm8-signed"
    source_operands = source.get("operands", "")
    runtime_meta = observed_rows[0].get("operand_metadata")
    if runtime_meta is None and category == "uimm8":
        # The UIMM8 projection records source metadata but not XED visibility
        # metadata. Do not map a register-shaped source operand unless the
        # backend visibility can be independently tied to that source role.
        if any(shape.get("kind") not in {"memory", "immediate"} for shape in identity["operand_shape"]):
            fail(f"{iform}: canonical register operand lacks pinned explicit-visibility metadata")
        visible_roles = {shape.get("role", "").upper() for shape in identity["operand_shape"]}
    elif isinstance(runtime_meta, list):
        visible_roles = {item.get("name") for item in runtime_meta if item.get("visibility") == 1}
    else:
        visible_roles = {shape.get("role", "").upper() for shape in identity["operand_shape"]}
    for shape in identity["operand_shape"]:
        kind = shape.get("kind")
        if kind not in {"register", "gpr", "system-register", "memory", "immediate"}:
            fail(f"{iform}: unsupported explicit operand kind {kind}")
        if shape.get("role", "").upper() not in visible_roles:
            continue
        source_marker = re.search(rf"\b{re.escape(shape['role'].upper())}\b[^\s]*\bSUPP\b", source_operands)
        if source_marker:
            continue
        if isinstance(runtime_meta, list):
            metadata = next((item for item in runtime_meta if item.get("name") == shape["role"].upper() and item.get("visibility") == 1), None)
            action_access = {1: "read-write", 2: "read", 3: "write"}.get(metadata.get("action")) if metadata else None
            if metadata is None or (shape.get("width_bits") is not None and metadata.get("width_bits") != shape.get("width_bits")) or action_access != shape.get("access"):
                fail(f"{iform}: source identity operand shape disagrees with pinned XED explicit operand metadata for {shape['role']}")
        kind = "register" if kind in {"gpr", "system-register"} else kind
        operands.append({"kind": kind, "width_bits": shape.get("width_bits"), "access": shape.get("access"), "signed_immediate": bool(signed and kind == "immediate")})
    mode = observed_rows[0].get("context", {}).get("mode") if category == "primary_register_direct" else observed_rows[0]["mode"]
    mode_constant = {"long64": "Long64", "legacy32": "Legacy32", "legacy16": "Legacy16"}.get(mode)
    if mode_constant is None:
        fail(f"{iform}: unsupported exact witness mode {mode}")
    return iform, value, witnesses, mode_constant, operands


def validate_fixed_opcode_census_source(data: dict) -> None:
    """Bind the three new census records to ISANITY's pinned expansion artifact."""
    relative = "tools/xed-zero-operand-census-expansion/out/xed-zero-operand-fixed-opcode-candidates-v1.json"
    pin = data.get("inputs", {}).get(relative, {})
    path = ISANITY / relative
    if pin.get("path") != relative or not path.is_file():
        fail("fixed-opcode census lacks its pinned zero-operand candidate source")
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != pin.get("sha256"):
        fail("fixed-opcode census candidate source digest is stale")
    artifact = json.loads(raw)
    candidates = artifact.get("candidate_identities", [])
    expected_names = {"XED_IFORM_SETSSBSY", "XED_IFORM_XRESLDTRK", "XED_IFORM_XSUSLDTRK"}
    by_name = {row.get("iform", {}).get("name"): row for row in candidates}
    if set(by_name) != expected_names or len(candidates) != len(expected_names):
        fail("pinned zero-operand candidate source no longer contains exactly the three census IFORMs")
    records = {row.get("iform", {}).get("name"): row for row in data.get("records", [])}
    if set(records) != expected_names or len(records) != len(expected_names):
        fail("fixed-opcode census must contain exactly SETSSBSY, XRESLDTRK, and XSUSLDTRK")
    for name in sorted(expected_names):
        record = records[name]
        candidate = by_name[name]
        source = record.get("evidence", {}).get("source_pattern", {})
        witness = record.get("evidence", {}).get("runtime_observations", [{}])[0]
        if not (
            candidate.get("iform") == record.get("iform")
            and candidate.get("form_id") == record.get("form_id")
            and candidate.get("identity") == record.get("identity")
            and candidate.get("canonical_bytes") == record.get("canonical_bytes")
            and candidate.get("bytes_hex", "").lower() == witness.get("bytes_hex", "").lower()
            and candidate.get("bytes_sha256") == witness.get("bytes_sha256")
            and candidate.get("source", {}).get("file") == source.get("path")
            and candidate.get("source", {}).get("sha256") == source.get("sha256")
            and candidate.get("pattern") == source.get("pattern")
            and candidate.get("disposition") == "source-and-census-supported-identity"
        ):
            fail(f"{name}: canonical record disagrees with pinned zero-operand candidate evidence")


def validate_mov_opcode_register_record(record: dict, artifact: dict) -> tuple[str, int, list[bytes], str, list[dict], int, int]:
    """Validate a concrete MOV B0..BF selector row and return its opcode witness."""
    iform = record.get("iform", {}).get("name")
    value = record.get("iform", {}).get("value")
    identity = record.get("identity", {})
    evidence = record.get("evidence", {})
    source = evidence.get("source_pattern", {})
    encoding = identity.get("encoding", {})
    shape = identity.get("operand_shape", [])
    observations = evidence.get("runtime_observations", [])
    if (record.get("semantic_status") != "unmapped" or record.get("fidelity_status") != "unassessed"
            or identity.get("architecture") != "x86" or identity.get("execution_mode") != "long64"
            or identity.get("instruction_class") != "MOV" or len(observations) != 1):
        fail(f"{iform}: MOV candidates must remain one-observation long64 identities only")
    if source.get("file") != "xed/datafiles/xed-isa.txt" or source.get("sha256") != "70f8f55fd72f14e285a3b219e763b5846cbeca3c9547d71afbd064277ee02f78":
        fail(f"{iform}: MOV source pattern is not pinned to the expected XED ISA file")
    selector = source.get("selector", {})
    opcode = int(encoding.get("opcode_bytes", "0"), 16)
    expected_width = 8 if opcode < 0xB8 else (64 if identity.get("execution_mode") == "long64" and encoding.get("operand_size_policy") == "rex-w" else 32)
    # The canonical identity's operand shape is the controlling source for width;
    # the runtime observation must independently agree with it.
    if len(shape) != 2 or shape[0].get("role") != "reg0" or shape[0].get("kind") != "register" or shape[0].get("access") != "write" or shape[1].get("role") != "imm0" or shape[1].get("kind") != "immediate" or shape[1].get("access") != "read":
        fail(f"{iform}: unsupported MOV destination/immediate operand shape")
    width = shape[0].get("width_bits")
    if width not in {8, 32, 64} or shape[1].get("width_bits") != width or expected_width != width:
        fail(f"{iform}: MOV selector width is outside the B0 or B8 long64 slice")
    if not 0xB0 <= opcode <= 0xBF or (width == 8) != (opcode < 0xB8):
        fail(f"{iform}: opcode is outside the expected B0..BF width group")
    selector_value = opcode & 7
    if not (selector.get("field") == "SRM[rrr]" and selector.get("opcode_byte") == f"0x{opcode:02x}"
            and selector.get("register_operand_slot") == "REG0" and selector.get("value") == selector_value
            and source.get("pattern") == ("0b1011_0 SRM[rrr] UIMM8()" if width == 8 else "0b1011_1 SRM[rrr] UIMMv()")):
        fail(f"{iform}: source opcode-register selector does not match the canonical opcode")
    if iform != ("XED_IFORM_MOV_GPR8_IMMb_B0" if width == 8 else "XED_IFORM_MOV_GPRv_IMMv"):
        fail(f"{iform}: MOV IFORM does not match the width group")
    observed = observations[0]
    if not (observed.get("err") == "NONE" and observed.get("mode") == "long64" and observed.get("execution_mode") == "long64"
            and observed.get("iform_name") == iform and observed.get("iform_value") == value
            and observed.get("opcode_bytes") == f"0x{opcode:02x}" and observed.get("operand_size_bits") == width):
        fail(f"{iform}: runtime observation does not bind exact IFORM/mode/opcode/width")
    try:
        encoded = bytes.fromhex(observed.get("bytes_hex", ""))
    except (TypeError, ValueError):
        fail(f"{iform}: malformed MOV runtime byte witness")
    if len(encoded) != observed.get("decoded_length"):
        fail(f"{iform}: MOV runtime witness length mismatch")
    offset = 1 if encoded and encoded[0] in {0x66, 0x48} else 0
    if not encoded or encoded[offset] != opcode or len(encoded) != offset + 1 + width // 8:
        fail(f"{iform}: byte witness does not encode the pinned B0..BF opcode and immediate width")
    if (width == 64 and (offset != 1 or encoded[0] != 0x48)) or (width == 32 and offset != 0) or (width == 8 and offset != 0):
        fail(f"{iform}: MOV witness uses an excluded prefix/mode form")
    if observed.get("operand0") != {"action": "write", "register": selector.get("register_name"), "width_bits": width} or observed.get("operand1") != {"action": "read", "name": "IMM0", "width_bits": width}:
        fail(f"{iform}: MOV runtime operand metadata disagrees with selector identity")
    match = ID_RE.fullmatch(record.get("form_id", ""))
    canonical = record.get("canonical_bytes")
    if not isinstance(canonical, str) or json.loads(canonical) != identity or not match:
        fail(f"{iform}: malformed MOV canonical bytes/FormId")
    digest = hashlib.sha256(DOMAIN + len(canonical.encode("utf-8")).to_bytes(8, "big") + canonical.encode("utf-8")).hexdigest()
    if digest != match.group(1):
        fail(f"{iform}: MOV FormId digest mismatch")
    mode_constant = "Long64"
    immediate_signed = encoding.get("immediate_encoding") == "simm8-signed"
    operands = [
        {"kind": "register", "width_bits": width, "access": "write", "signed_immediate": False},
        {"kind": "immediate", "width_bits": width, "access": "read", "signed_immediate": immediate_signed},
    ]
    return iform, value, [encoded], mode_constant, operands, opcode, offset


def render() -> str:
    rows = []
    excluded = []
    digests = []
    seen_ids = set()
    seen_iforms = set()
    counts = {
        "uimm8": 0, "simm8": 0, "uimm16_32": 0, "fixed_opcode": 0,
        "fixed_opcode_census": 0, "primary_register_direct": 0, "mov_opcode_register": 0,
    }
    register_direct_unmapped = []
    mov_selector_keys = set()
    for path in SOURCES:
        raw = path.read_bytes()
        data = json.loads(raw)
        if path.name == "x86-mov-opcode-register-v2.json":
            if hashlib.sha256(raw).hexdigest() != MOV_OPCODE_REGISTER_SHA256:
                fail("MOV opcode-register catalogue digest differs from the pinned ISANITY slice")
            candidate = data.get("evidence_generator_artifact", {})
            if candidate.get("path") != "tools/xed-opcode-register-selector/out/mov-opcode-register-exact-identity-candidates-v1.json" or candidate.get("sha256") != "0a18c9f9bec8dc3fa6b27566d241ff9ef4faf9b037449c1849a2c9efd4abfdff":
                fail("MOV opcode-register evidence generator is not hash-pinned")
            if data.get("coverage", {}).get("assigned_identities_in_this_slice") != 24 or data.get("coverage", {}).get("assigned_iforms") != ["XED_IFORM_MOV_GPR8_IMMb_B0", "XED_IFORM_MOV_GPRv_IMMv"]:
                fail("MOV opcode-register coverage no longer describes the pinned 24-record/two-IFORM slice")
        digests.append((path.name, hashlib.sha256(raw).hexdigest()))
        source_lock = data.get("source_lock", {})
        if (data.get("identity_schema") != "form-identity-v2"
                or any(source_lock.get(key) != value for key, value in SOURCE_LOCK.items() if key != "xed_sys_version")
                or source_lock.get("xed_sys_version") not in {"xed-sys", SOURCE_LOCK["xed_sys_version"]}):
            fail(f"{path.name}: unexpected identity schema or XED source lock")
        if path.name == "x86-zero-operand-fixed-opcode-census-v2.json":
            validate_fixed_opcode_census_source(data)
        category = (
            "primary_register_direct" if path.name == "x86-register-direct-v2.json"
            else "mov_opcode_register" if path.name == "x86-mov-opcode-register-v2.json"
            else "fixed_opcode_census" if path.name == "x86-zero-operand-fixed-opcode-census-v2.json"
            else "uimm8" if "uimm8" in path.name
            else "simm8" if "simm8" in path.name
            else "uimm16_32" if "uimm16" in path.name
            else "fixed_opcode"
        )
        for record in data.get("records", []):
            iform = record.get("iform", {}).get("name")
            if category == "fixed_opcode_census":
                identity = record.get("identity", {})
                encoding = identity.get("encoding", {})
                expected = {
                    "XED_IFORM_SETSSBSY": ("SETSSBSY", "f3", 0),
                    "XED_IFORM_XRESLDTRK": ("XRESLDTRK", "f2", 1),
                    "XED_IFORM_XSUSLDTRK": ("XSUSLDTRK", "f2", 0),
                }
                selector = expected.get(iform)
                if selector is None:
                    fail(f"{iform}: unexpected IFORM in the fixed-opcode census slice")
                iclass, mandatory_prefix, rm_value = selector
                if not (
                    identity.get("architecture") == "x86"
                    and identity.get("execution_mode") == "long64"
                    and identity.get("instruction_class") == iclass
                    and identity.get("operand_shape") == []
                    and encoding.get("family") == "legacy"
                    and encoding.get("opcode_map") == "0f"
                    and encoding.get("opcode_bytes") == "0x01"
                    and encoding.get("mandatory_prefix") == mandatory_prefix
                    and encoding.get("modrm_reg_extension") == 5
                    and identity.get("modrm", {}).get("mod_values") == [3]
                    and identity.get("modrm", {}).get("rm_value") == rm_value
                    and record.get("identity_review") == "accepted-for-this-exact-fixed-opcode-zero-operand-source-slice"
                ):
                    fail(f"{iform}: record is outside the exact fixed-opcode zero-operand identity slice")
            if category == "mov_opcode_register":
                opcode = int(record.get("identity", {}).get("encoding", {}).get("opcode_bytes", "0"), 16)
                width = record.get("identity", {}).get("operand_shape", [{}])[0].get("width_bits")
                key = (iform, record.get("iform", {}).get("value"), opcode, width)
                if key in mov_selector_keys:
                    fail(f"{iform}: duplicate MOV IFORM/opcode selector identity")
                mov_selector_keys.add(key)
            if category == "uimm16_32" and record.get("evidence", {}).get("runtime_observations", [{}])[0].get("mode") != "long64":
                excluded.append((iform, "source-constrained legacy32-only witness is outside the long64 resolver profile"))
                continue
            try:
                row = validate_mov_opcode_register_record(record, data) if category == "mov_opcode_register" else (*validate_record(record, data, category), None, None)
            except ValueError as error:
                if (category == "uimm8"
                        and record.get("evidence", {}).get("runtime_observations", [{}])[0].get("operand_metadata") is None
                        and any(item.get("kind") not in {"memory", "immediate"} for item in record.get("identity", {}).get("operand_shape", []))):
                    excluded.append((iform, "source identity includes a register role but this consumer slice lacks pinned runtime visibility evidence to distinguish explicit from suppressed operands"))
                    continue
                raise error
            if record["form_id"] in seen_ids:
                fail(f"duplicate FormId across canonical inputs: {iform}")
            seen_ids.add(record["form_id"])
            counts[category] += 1
            rows.append((row, record["form_id"], path.name))

    # The same exact IFORM/value/byte witness must not claim multiple canonical
    # identities. Preserve ambiguous primary-slice records as explicit unmapped
    # dispositions instead of selecting one by catalogue order.
    owners = {}
    for index, (row, form_id, source_name) in enumerate(rows):
        iform, value, witnesses, _, _, _, _ = row
        for witness in witnesses:
            owners.setdefault((iform, value, witness), []).append(index)
    ambiguous_indexes = {
        index
        for indexes in owners.values()
        if len({rows[index][1] for index in indexes}) > 1
        for index in indexes
        if rows[index][2] == "x86-register-direct-v2.json"
    }
    if ambiguous_indexes:
        retained = []
        for index, (row, form_id, source_name) in enumerate(rows):
            if index in ambiguous_indexes:
                register_direct_unmapped.append((
                    row, form_id,
                    "exact IFORM/value/byte witness is shared by multiple canonical identities",
                ))
            else:
                retained.append((row, form_id, source_name))
        rows = retained

    expected = {
        "uimm8": 13, "simm8": 29, "uimm16_32": 5, "fixed_opcode": 1,
        "fixed_opcode_census": 3, "primary_register_direct": 241, "mov_opcode_register": 24,
    }
    if mov_selector_keys != (
        {("XED_IFORM_MOV_GPR8_IMMb_B0", 1557, opcode, 8) for opcode in range(0xB0, 0xB8)}
        | {("XED_IFORM_MOV_GPRv_IMMv", 1562, opcode, width) for opcode in range(0xB8, 0xC0) for width in (32, 64)}
    ):
        fail("MOV opcode-register selector table must contain each exact B0..BF opcode/IFORM join once")
    direct_mapped_count = sum(1 for _, _, source in rows if source == "x86-register-direct-v2.json")
    if (
        counts != expected or len(excluded) != 2 or len(rows) != 316
        or len(register_direct_unmapped) != 0
        or direct_mapped_count != 241
    ):
        fail(f"slice accounting changed: mapped={counts}, excluded={excluded}")
    lines = [
        "// @generated by tools/isanity-map/generate_exact_forms.py; do not edit.",
        *[f"// {name} SHA-256: {digest}" for name, digest in digests],
        "#[cfg(test)]",
        f"pub(super) const GENERATED_CANONICAL_FORM_COUNT: usize = {len(rows)};",
        "#[cfg(test)]",
        "pub(super) const GENERATED_MOV_OPCODE_REGISTER_FORM_COUNT: usize = 24;",
        "#[cfg(test)]",
        "pub(super) const GENERATED_PRIMARY_REGISTER_DIRECT_SOURCE_COUNT: usize = 241;",
        "#[cfg(test)]",
        f"pub(super) const GENERATED_PRIMARY_REGISTER_DIRECT_FORM_COUNT: usize = {direct_mapped_count};",
        "#[cfg(test)]",
        f"pub(super) const GENERATED_PRIMARY_REGISTER_DIRECT_UNMAPPED_COUNT: usize = {len(register_direct_unmapped)};",
        "pub(super) const GENERATED_LONG64_EXCLUSIONS: &[(&str, &str)] = &[",
        *[f'    ("{name}", "{reason}"),' for name, reason in excluded],
        "];",
        "pub(super) static GENERATED_CANONICAL_FORMS: &[GeneratedCanonicalForm] = &[",
    ]
    for (row, form_id, source_name) in sorted(rows, key=lambda item: (item[0][0], item[1])):
        (iform, value, witnesses, mode, operands, opcode_byte, opcode_offset) = row
        lines.extend([
            "    GeneratedCanonicalForm {",
            f'        source_catalogue: "{source_name}",',
            f'        iform: "{iform}",',
            f"        iform_value: {value},",
            f"        mode: InstructionMode::{mode},",
            f"        opcode_byte: {f'Some(0x{opcode_byte:02x})' if opcode_byte is not None else 'None'},",
            f"        opcode_offset: {f'Some({opcode_offset})' if opcode_offset is not None else 'None'},",
            "        witnesses: &[",
            *["            &[" + ", ".join(f"0x{byte:02x}" for byte in witness) + "]," for witness in witnesses],
            "        ],",
            f'        canonical_id: "{form_id}",',
            "        operands: &[",
        ])
        for op in operands:
            width = "None" if op["width_bits"] is None else f"Some({op['width_bits']})"
            access = {
                "read": "Read",
                "write": "Write",
                "read-write": "ReadWrite",
                "conditional-write": "ConditionalWrite",
            }.get(op["access"])
            if access is None:
                fail(f"{iform}: unsupported operand access {op['access']}")
            kind = {"register": "Register", "memory": "Memory", "immediate": "Immediate"}[op["kind"]]
            lines.append(f"            GeneratedCanonicalOperand {{ kind: OperandKindTag::{kind}, width_bits: {width}, access: AccessTag::{access}, signed_immediate: {str(op['signed_immediate']).lower()} }},")
        lines.extend(["        ],", "    },"])
    lines.append("];" )
    lines.append("pub(super) static GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS: &[GeneratedUnmappedForm] = &[")
    for (row, form_id, reason) in sorted(register_direct_unmapped, key=lambda item: (item[0][0], item[1])):
        iform, value, witnesses, mode, _, _, _ = row
        lines.extend([
            "    GeneratedUnmappedForm {",
            f'        iform: "{iform}",',
            f"        iform_value: {value},",
            f"        mode: InstructionMode::{mode},",
            "        witnesses: &[",
            *["            &[" + ", ".join(f"0x{byte:02x}" for byte in witness) + "]," for witness in witnesses],
            "        ],",
            f'        canonical_id: "{form_id}",',
            f'        reason: {json.dumps(reason)},',
            "    },",
        ])
    lines.append("];" )
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
        if not OUTPUT.is_file() or OUTPUT.read_text(encoding="utf-8") != output:
            print(f"stale generated table: {OUTPUT.relative_to(ROOT)}", file=sys.stderr)
            return 1
        print("ISANITY exact-witness form table is current (316 mapped identities; includes 24 MOV B0..BF selector records)")
        return 0
    OUTPUT.write_text(output, encoding="utf-8")
    print("generated ISANITY exact-witness form table (316 mapped identities; includes 24 MOV B0..BF selector records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
