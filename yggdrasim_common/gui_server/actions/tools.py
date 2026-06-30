# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Offline-tool Command Center actions.

Wraps the pure-function engine panels (BER-TLV parse, ASN.1/TLV decode,
SW translate, EUICCInfo2 decode, SAIP lint, eIM lint, GSMA error-code
tables) as Command Center actions so the same task lives alongside
subsystem flows in one unified surface. No hardware is involved;
dispatchers run synchronously on the FastAPI threadpool.

All dispatchers resolve their backend through
``yggdrasim_common.registry`` so the action layer stays uncoupled from
the subsystem source trees.
"""

from __future__ import annotations

import binascii
import json
import logging
from pathlib import Path
from typing import Any

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.tools")
OFFLINE_TOOLS_SUBSYSTEM = "Offline Tools"


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------


def _parse_hex(raw: str, *, field_name: str = "hex") -> bytes:
    compact = "".join(ch for ch in (raw or "") if ch.strip())
    if len(compact) == 0:
        raise ValueError(f"{field_name} is empty.")
    if len(compact) % 2 != 0:
        raise ValueError(f"{field_name} must contain an even number of hex characters.")
    try:
        return binascii.unhexlify(compact)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"{field_name} is not valid hex: {error}") from error


def _schema_paths_from_text(raw: Any) -> list[Path] | None:
    text = str(raw or "").strip()
    if len(text) == 0:
        return None
    paths: list[Path] = []
    for chunk in text.replace(",", "\n").replace(";", "\n").splitlines():
        item = chunk.strip()
        if len(item) == 0:
            continue
        path = Path(item).expanduser()
        if path.is_dir():
            paths.extend(sorted(path.glob("*.asn")))
            paths.extend(sorted(path.glob("*.asn1")))
        else:
            paths.append(path)
    return paths or None


def _tlv_dict_to_nodes(parsed: dict) -> list[dict[str, Any]]:
    """Same projection the ``/api/tools/tlv/parse`` route uses, but returns
    plain dicts (the GUI can JSON-round-trip these directly).
    """
    nodes: list[dict[str, Any]] = []
    for tag_int, raw_value in parsed.items():
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        for value in values:
            tag_hex = format(tag_int, "X")
            if len(tag_hex) % 2 == 1:
                tag_hex = "0" + tag_hex
            if isinstance(value, dict):
                children = _tlv_dict_to_nodes(value)
                total = _estimate_nested_length(value)
                nodes.append({
                    "tag_hex": tag_hex,
                    "length": total,
                    "children": children,
                })
            else:
                raw_bytes = bytes(value) if isinstance(value, (bytes, bytearray)) else b""
                nodes.append({
                    "tag_hex": tag_hex,
                    "length": len(raw_bytes),
                    "value_hex": raw_bytes.hex().upper(),
                })
    return nodes


def _estimate_nested_length(parsed: dict) -> int:
    total = 0
    for raw_value in parsed.values():
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        for value in values:
            if isinstance(value, dict):
                total += _estimate_nested_length(value)
            elif isinstance(value, (bytes, bytearray)):
                total += len(value)
    return total


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_tlv_decode(ctx: ActionContext, *, hex: Any = None) -> dict[str, Any]:
    from yggdrasim_common import registry as yggdrasim_registry

    data = _parse_hex(str(hex or ""), field_name="hex")
    parser_cls = yggdrasim_registry.get("scp03.core.utils.tlv")
    result = parser_cls.parse_detailed(data)
    nodes = _tlv_dict_to_nodes(result["parsed"])
    return {
        "complete": bool(result.get("complete", False)),
        "consumed": int(result.get("consumed", 0)),
        "error": result.get("error"),
        "nodes": nodes,
        "input_length": len(data),
    }


def _dispatch_asn1_tlv_decode(
    ctx: ActionContext,
    *,
    hex_text: Any = None,
    schema_paths: Any = None,
    type_name: Any = None,
    codec: Any = None,
) -> dict[str, Any]:
    from Tools.Asn1TlvDecode.main import TagRegistry, decode_bytes, normalise_hex

    data = normalise_hex(str(hex_text or ""))
    schema_path_list = _schema_paths_from_text(schema_paths)
    type_name_s = str(type_name or "").strip() or None
    codec_s = str(codec or "der").strip().lower() or "der"
    if schema_path_list and type_name_s is None:
        raise ValueError("type_name is required when schema_paths is set.")
    if type_name_s is not None and not schema_path_list:
        raise ValueError("schema_paths is required when type_name is set.")
    try:
        return decode_bytes(
            data,
            registry=TagRegistry.load(),
            schema_paths=schema_path_list,
            type_name=type_name_s,
            codec=codec_s,
        )
    except ValueError as error:
        raise ValueError(f"ASN.1/TLV decode failed: {error}") from error


def _dispatch_sw_lookup(ctx: ActionContext, *, sw: Any = None) -> dict[str, Any]:
    from yggdrasim_common import registry as yggdrasim_registry

    raw = str(sw or "").replace(" ", "").strip().upper()
    if len(raw) != 4:
        raise ValueError("sw must be exactly 4 hex characters (e.g. '9000').")
    try:
        data = binascii.unhexlify(raw)
    except (binascii.Error, ValueError) as error:
        raise ValueError(f"sw is not valid hex: {error}") from error
    sw1, sw2 = data[0], data[1]
    translator_cls = yggdrasim_registry.get("scp03.core.utils.sw")
    description = translator_cls.translate(sw1, sw2)
    return {
        "sw_hex": format((sw1 << 8) | sw2, "04X"),
        "sw1": sw1,
        "sw2": sw2,
        "description": description,
    }


def _dispatch_euicc_info2(ctx: ActionContext, *, hex: Any = None) -> dict[str, Any]:
    from yggdrasim_common import registry as yggdrasim_registry

    data = _parse_hex(str(hex or ""), field_name="hex")
    if len(data) < 2 or data[:2] != b"\xBF\x22":
        raise ValueError("EUICCInfo2 payload must start with tag BF22.")
    build_detail = yggdrasim_registry.get("scp03.logic.euicc_info2.build_detail")
    build_validation = yggdrasim_registry.get("scp03.logic.euicc_info2.build_validation")
    try:
        detail_tuples = build_detail(data)
    except Exception as error:
        raise ValueError(f"EUICCInfo2 decode failed: {error}") from error
    try:
        validation_tuples = build_validation(data)
    except Exception as error:
        raise ValueError(f"EUICCInfo2 validation failed: {error}") from error

    detail = [
        {"indent": int(i), "label": str(l), "value": str(v)} for i, l, v in detail_tuples
    ]
    validation = [
        {"indent": int(i), "label": str(l), "value": str(v)} for i, l, v in validation_tuples
    ]
    return {
        "detail_lines": detail,
        "validation_lines": validation,
        "input_length": len(data),
    }


def _dispatch_sima_response_decode(ctx: ActionContext, *, hex: Any = None) -> dict[str, Any]:
    from SCP11.shared.sima_response import decode_sima_response

    data = _parse_hex(str(hex or ""), field_name="hex")
    return decode_sima_response(data)


def _dispatch_saip_lint(
    ctx: ActionContext,
    *,
    json_text: Any = None,
    profile_label: Any = None,
    strict: Any = None,
) -> dict[str, Any]:
    from Tools.ProfilePackage.saip_tui_lint import lint_profile_json_buffer

    label = str(profile_label or "ad-hoc") or "ad-hoc"
    strict_flag = bool(strict)
    try:
        outcome = lint_profile_json_buffer(
            str(json_text or ""),
            label,
            strict=strict_flag,
        )
    except Exception as error:
        raise ValueError(f"SAIP lint invocation failed: {error}") from error

    report_dict: dict[str, Any] | None = None
    findings: list[dict[str, Any]] = []
    if outcome.report is not None:
        report_dict = outcome.report.to_dict()
        findings = list(report_dict.get("findings", []) or [])

    return {
        "parse_error": outcome.parse_error,
        "template_mode": bool(outcome.template_mode),
        "undefined_tokens": sorted(outcome.undefined_tokens),
        "placeholder_paths": sorted(outcome.placeholder_paths),
        "report": report_dict,
        "findings": findings,
        "profile_label": label,
        "strict": strict_flag,
    }


def _dispatch_eim_lint(ctx: ActionContext, *, document_json: Any = None) -> dict[str, Any]:
    from yggdrasim_common import registry as yggdrasim_registry

    try:
        document = json.loads(str(document_json or ""))
    except json.JSONDecodeError as error:
        raise ValueError(f"document_json is not valid JSON: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("document_json root must be a JSON object.")
    linter = yggdrasim_registry.get("scp11.eim_local.package_lint")
    try:
        report = linter(document)
    except Exception as error:
        raise ValueError(f"eIM lint failed: {error}") from error
    errors = [str(item) for item in report.get("errors", []) or []]
    warnings = [str(item) for item in report.get("warnings", []) or []]
    summary = {k: v for k, v in report.items() if k not in ("errors", "warnings")}
    return {"errors": errors, "warnings": warnings, "summary": summary}


def _dispatch_gsma_codes(ctx: ActionContext) -> dict[str, Any]:
    from SCP11.shared import gsma_error_codes as gsma

    wanted = [
        ("es10b_profile_state", "SGP22_ES10B_PROFILE_STATE_RESULT"),
        ("notification_sent", "SGP22_NOTIFICATION_SENT_RESULT"),
        ("download_error", "SGP22_DOWNLOAD_ERROR_CODE"),
        ("profile_installation", "SGP22_PROFILE_INSTALLATION_RESULT_REASON"),
        ("sgp32_eim_package_error", "SGP32_EIM_PACKAGE_ERROR"),
        ("sgp32_eim_package_result_error", "SGP32_EIM_PACKAGE_RESULT_ERROR"),
        ("sgp32_profile_download_error_reason", "SGP32_PROFILE_DOWNLOAD_ERROR_REASON"),
    ]
    tables: dict[str, dict[str, str]] = {}
    order: list[str] = []
    for label, attr_name in wanted:
        raw = getattr(gsma, attr_name, None)
        if not isinstance(raw, dict):
            continue
        tables[label] = {str(code): str(desc) for code, desc in raw.items()}
        order.append(label)
    return {"tables": tables, "order": order}


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


TLV_DECODE_SPEC = ActionSpec(
    id="tool.tlv.decode",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="TLV parse",
    description="Decode a BER-TLV hex buffer into a tag / length / value tree.",
    inputs=(
        ActionField(
            name="hex",
            label="TLV hex",
            kind="hex",
            required=True,
            multiline=True,
            placeholder="6F 16 84 08 A0 00 00 01 51 00 00 00 …",
            help="Compact or spaced hex; mixed case allowed.",
        ),
    ),
    output_kind="tlv_tree",
    dispatcher=_dispatch_tlv_decode,
    tags=("decode", "tlv"),
)


ASN1_TLV_DECODE_SPEC = ActionSpec(
    id="tool.asn1_tlv.decode",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="ASN.1/TLV decode",
    description=(
        "Decode BER/DER ASN.1, BER-TLV, or command APDU hex into JSON "
        "and ASN.1-like value notation."
    ),
    inputs=(
        ActionField(
            name="hex_text",
            label="Input hex",
            kind="text",
            required=True,
            multiline=True,
            placeholder="BF 22 03 81 01 02",
            help="Compact or spaced hex; common separators and 0x prefixes are accepted.",
        ),
        ActionField(
            name="schema_paths",
            label="ASN.1 schema paths",
            kind="text",
            required=False,
            multiline=True,
            placeholder="path/to/schema.asn",
            help="Optional newline/comma-separated .asn/.asn1 files or directories.",
        ),
        ActionField(
            name="type_name",
            label="ASN.1 type name",
            kind="string",
            required=False,
            placeholder="EuiccPackageRequest",
            help="Optional schema type to decode with asn1tools.",
        ),
        ActionField(
            name="codec",
            label="Schema codec",
            kind="enum",
            required=False,
            default="der",
            choices=["der", "ber", "uper", "per", "oer", "jer", "gser", "xer"],
            help="asn1tools codec used only for schema-aware decode.",
        ),
    ),
    output_kind="asn1_tlv",
    dispatcher=_dispatch_asn1_tlv_decode,
    tags=("decode", "asn1", "tlv", "apdu"),
)


SW_LOOKUP_SPEC = ActionSpec(
    id="tool.sw.lookup",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="Status-word lookup",
    description="Translate a 2-byte SW response (e.g. 9000, 6A82) into a human description.",
    inputs=(
        ActionField(
            name="sw",
            label="SW",
            kind="string",
            required=True,
            placeholder="9000",
            help="Two-byte hex, e.g. '9000', '6A 82', '6982'.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_sw_lookup,
    tags=("decode", "sw"),
)


EUICC_INFO2_SPEC = ActionSpec(
    id="tool.euicc_info2.decode",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="EUICCInfo2 decode",
    description="Decode an EUICCInfo2 (tag BF22) TLV blob into labeled detail lines + validation.",
    inputs=(
        ActionField(
            name="hex",
            label="EUICCInfo2 hex",
            kind="hex",
            required=True,
            multiline=True,
            placeholder="BF 22 81 …",
            help="Compact hex of the EUICCInfo2 response.",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_euicc_info2,
    tags=("decode", "euicc"),
)


SIMA_RESPONSE_DECODE_SPEC = ActionSpec(
    id="tool.sima_response.decode",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="SIMa response decode",
    description="Decode a SIMa simaResponse TLV into final-result fields and a TLV tree.",
    inputs=(
        ActionField(
            name="hex",
            label="SIMa response hex",
            kind="hex",
            required=True,
            multiline=True,
            placeholder="30 07 A0 05 30 03 80 01 00",
            help="Paste the simaResponse value from ProfileInstallationResult.",
        ),
    ),
    output_kind="sima_response",
    dispatcher=_dispatch_sima_response_decode,
    tags=("decode", "sima", "sgp22"),
)


SAIP_LINT_SPEC = ActionSpec(
    id="tool.saip.lint",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="SAIP lint",
    description="Lint a SAIP TRANSCODE-TUI editor JSON buffer. Returns findings grouped by severity.",
    inputs=(
        ActionField(
            name="json_text",
            label="Editor JSON",
            kind="text",
            required=True,
            multiline=True,
            placeholder="Paste the editor JSON buffer here.",
        ),
        ActionField(
            name="profile_label",
            label="Profile label",
            kind="string",
            required=False,
            default="ad-hoc",
            help="Appears in finding evidence for context only.",
        ),
        ActionField(
            name="strict",
            label="Strict mode",
            kind="bool",
            required=False,
            default=False,
            help="Treat warnings as errors.",
        ),
    ),
    output_kind="findings",
    dispatcher=_dispatch_saip_lint,
    tags=("lint", "saip"),
)


EIM_LINT_SPEC = ActionSpec(
    id="tool.eim.lint",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="eIM package lint",
    description="Validate an eIM package document (JSON object) and surface errors + warnings.",
    inputs=(
        ActionField(
            name="document_json",
            label="Document JSON",
            kind="text",
            required=True,
            multiline=True,
            placeholder="{ \"header\": { … }, \"body\": { … } }",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_eim_lint,
    tags=("lint", "eim"),
)


GSMA_CODES_SPEC = ActionSpec(
    id="tool.gsma.codes",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="GSMA error-code reference",
    description="Dump the bundled GSMA error-code tables (SGP.22 / SGP.32) for quick lookup.",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_gsma_codes,
    tags=("reference", "gsma"),
)


get_registry().register(TLV_DECODE_SPEC)
get_registry().register(ASN1_TLV_DECODE_SPEC)
get_registry().register(SW_LOOKUP_SPEC)
get_registry().register(EUICC_INFO2_SPEC)
get_registry().register(SIMA_RESPONSE_DECODE_SPEC)
get_registry().register(SAIP_LINT_SPEC)
get_registry().register(EIM_LINT_SPEC)
get_registry().register(GSMA_CODES_SPEC)
