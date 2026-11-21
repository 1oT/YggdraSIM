# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Offline-tool Command Center actions.

The context decoder, the ASN.1/TLV decode against a schema, the TERMINAL
PROFILE decode and build, SAIP lint, eIM lint and the GSMA error-code
tables as Command Center actions, so the same task lives alongside the
subsystem flows. No hardware is involved; dispatchers run synchronously
on the FastAPI threadpool. A bare TLV, a status word, an EUICCInfo2 and
an EUICCResponse have no action of their own: the context decoder reads
each of them.

All dispatchers resolve their backend through
``yggdrasim_common.registry`` so the action layer stays uncoupled from
the subsystem source trees.
"""

from __future__ import annotations

import binascii
import json
import logging
import re
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


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


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


# What the Decoder panel shows of one input: the page draws a card per exchange, and a thousand
# of them (some 55 000 nodes, a few megabytes of JSON) is a size seen to render at once.
CONTEXT_DECODE_PANEL_EXCHANGES = 1000


def _dispatch_context_decode(
    ctx: ActionContext,
    *,
    input_text: Any = None,
    context: Any = None,
) -> dict[str, Any]:
    from Tools.Asn1TlvDecode.context import decode_context_text
    from Tools.Asn1TlvDecode.main import DecodeError

    text = str(input_text or "")
    if len(text.strip()) == 0:
        raise ValueError("input_text is empty.")
    try:
        return decode_context_text(text, hint=str(context or "auto"), max_exchanges=CONTEXT_DECODE_PANEL_EXCHANGES)
    except DecodeError as error:
        raise ValueError(f"Context decode failed: {error}") from error


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
        # SGP.22 v3.1 §5.7.16 to §5.7.18 give each of the three functions its
        # own enumeration; the merged table above cannot name a value whose
        # meaning differs between them.
        ("enable_profile", "SGP22_ENABLE_PROFILE_RESULT"),
        ("disable_profile", "SGP22_DISABLE_PROFILE_RESULT"),
        ("delete_profile", "SGP22_DELETE_PROFILE_RESULT"),
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


_TP_ADDRESS_LIST = r"^\s*\d{1,3}\.\d(?:-\d)?(?:\s*[,\s]\s*\d{1,3}\.\d(?:-\d)?)*\s*$"


def _tp_items(raw: Any) -> list[str]:
    """One facility per line; a line of addresses only may hold several, comma-separated.

    A facility name may itself contain commas ("MCC, MNC, LAC, Cell ID & IMEI"),
    so only a line made of addresses is split.
    """
    items: list[str] = []
    for line in str(raw or "").splitlines():
        text = line.strip()
        if len(text) == 0:
            continue
        if re.match(_TP_ADDRESS_LIST, text):
            items.extend(part for part in re.split(r"[,\s]+", text) if part)
        else:
            items.append(text)
    return items


def _tp_values(raw: Any) -> list[tuple[str, int]]:
    """``ADDRESS=VALUE`` per line or comma-separated; VALUE in decimal or 0x hex."""
    values: list[tuple[str, int]] = []
    for line in str(raw or "").splitlines():
        for chunk in line.split(","):
            text = chunk.strip()
            if len(text) == 0:
                continue
            item, separator, value = text.rpartition("=")
            if separator != "=" or len(item.strip()) == 0:
                raise ValueError(f"field value {text!r} is not ADDRESS=VALUE")
            try:
                values.append((item.strip(), int(value.strip(), 0)))
            except ValueError as error:
                raise ValueError(f"field value {text!r}: {value.strip()!r} is not a number") from error
    return values


def _tp_detail_lines(result: Any, *, set_only: bool) -> list[dict[str, Any]]:
    """One line per byte, the bits and fields under it, the TS 31.111 reading under those."""
    from yggdrasim_common import terminal_profile

    data = result.profile
    lines: list[dict[str, Any]] = []
    current_byte = 0
    for facility, value in result.values:
        if set_only and value == 0:
            continue
        if facility.byte != current_byte:
            current_byte = facility.byte
            title = terminal_profile.BYTE_TITLES.get(current_byte, "")
            lines.append({
                "indent": 0,
                "label": f"Byte {current_byte}" + (f" ({title})" if title else ""),
                "value": f"{data[current_byte - 1]:02X}" if current_byte <= len(data) else "absent",
            })
        shown = ("yes" if value else "no") if facility.width == 1 else str(value)
        lines.append({
            "indent": 1,
            "label": f"{facility.address} {facility.describe()}",
            "value": shown,
        })
        if len(facility.usat) > 0:
            lines.append({"indent": 2, "label": "TS 31.111", "value": facility.usat})
    return lines


def _tp_finding_lines(findings: Any) -> list[dict[str, Any]]:
    return [
        {
            "indent": 0,
            "label": f"{finding.severity} {finding.address}".strip(),
            "value": finding.text,
        }
        for finding in findings
    ]


def _dispatch_tp_decode(
    ctx: ActionContext,
    *,
    profile: Any = None,
    compare: Any = None,
    show: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common import terminal_profile

    data, notes = terminal_profile.split_apdu(terminal_profile.parse_hex(str(profile or "")))
    compare_text = str(compare or "").strip()
    if len(compare_text) > 0:
        other, other_notes = terminal_profile.split_apdu(terminal_profile.parse_hex(compare_text))
        changed = terminal_profile.diff(data, other)
        detail = [
            {"indent": 0, "label": "Profile", "value": data.hex().upper()},
            {"indent": 0, "label": "Compared with", "value": other.hex().upper()},
        ]
        detail.extend(
            {
                "indent": 1,
                "label": f"{facility.address} {facility.describe()}",
                "value": f"{left} -> {right}",
            }
            for facility, left, right in changed
        )
        return {
            "input_length": len(data),
            "note": (
                terminal_profile.count_text(len(changed), "facility differs", "facilities differ")
                + f" between the profile ({len(data)} B) and the comparison ({len(other)} B)."
            ),
            "detail_lines": detail,
            "validation_lines": _tp_finding_lines(list(notes) + list(other_notes)),
        }
    result = terminal_profile.decode(data)
    set_only = str(show or "all").strip().lower() == "set"
    detail = [{"indent": 0, "label": "Profile", "value": data.hex().upper() or "(empty)"}]
    detail.extend(_tp_detail_lines(result, set_only=set_only))
    return {
        "input_length": len(data),
        "note": (
            f"TERMINAL PROFILE, {terminal_profile.count_text(len(data), 'byte', 'bytes')} "
            f"({terminal_profile.SPEC})."
        ),
        "detail_lines": detail,
        "validation_lines": _tp_finding_lines(list(notes) + list(result.findings)),
    }


_TP_BASES = ("maximal", "empty", "pasted")


def _dispatch_tp_build(
    ctx: ActionContext,
    *,
    base: Any = None,
    base_profile: Any = None,
    set_items: Any = None,
    clear_items: Any = None,
    field_values: Any = None,
    length: Any = None,
) -> dict[str, Any]:
    from yggdrasim_common import terminal_profile

    base_name = str(base or "maximal").strip().lower()
    if base_name not in _TP_BASES:
        raise ValueError(f"base must be one of {', '.join(_TP_BASES)}.")
    start = b""
    if base_name == "maximal":
        start = terminal_profile.maximal()
    elif base_name == "pasted":
        if len(str(base_profile or "").strip()) == 0:
            raise ValueError("base_profile is empty; paste the profile to start from.")
        start, _ = terminal_profile.split_apdu(terminal_profile.parse_hex(str(base_profile)))
    built = terminal_profile.build(
        start,
        set_items=_tp_items(set_items),
        clear_items=_tp_items(clear_items),
        values=_tp_values(field_values),
        length=None if length is None else int(length),
    )
    result = terminal_profile.decode(built)
    detail = [
        {"indent": 0, "label": "Profile", "value": built.hex().upper() or "(empty)"},
        {
            "indent": 0,
            "label": "TERMINAL PROFILE APDU",
            "value": terminal_profile.terminal_profile_apdu(built).hex().upper(),
        },
    ]
    detail.extend(_tp_detail_lines(result, set_only=True))
    return {
        "input_length": len(built),
        "note": (
            f"Built from the {base_name} profile: "
            f"{terminal_profile.count_text(len(built), 'byte', 'bytes')}."
        ),
        "detail_lines": detail,
        "validation_lines": _tp_finding_lines(result.findings),
    }


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


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


CONTEXT_DECODE_SPEC = ActionSpec(
    id="tool.decoder.context",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="Context decoder",
    description=(
        "Decode an APDU, a response, a bare TLV, a status word, a script of "
        "one command per row or a whole exchange trace against the "
        "specification the CLA/INS pair selects: UICC file commands, CAT, "
        "GlobalPlatform, ES10 and 3GPP authentication. A "
        "ProfileInstallationResult or a bare EUICCResponse is headed by its "
        "outcome, and an EUICCInfo2 carries the SGP.32 check."
    ),
    inputs=(
        ActionField(
            name="input_text",
            label="APDU, response, TLV, script or trace",
            kind="text",
            required=True,
            multiline=True,
            placeholder="00A4040407A0000000871002\n< 6F...9000",
            help=(
                "One hex string, or several rows: one command per row as in a "
                "script file (# starts a comment), or exchanges. Rows may start "
                "with >, <, ->, <-, C:, R: or carry sw=XXXX; without a marker a "
                "row that is a known command starts a new exchange and any other "
                "row answers the one above. Separators and 0x prefixes are "
                "ignored. AT+CSIM, +CRSM, +CGLA and +CRLA lines are read as "
                "exchanges; PEM, a JSON body, base64, an identifier in digits, "
                "an ATR and TLS records are read where hex is not."
            ),
        ),
        ActionField(
            name="context",
            label="Context",
            kind="enum",
            required=False,
            default="auto",
            choices=["auto", "apdu", "response", "es10", "gp", "uicc", "cat", "tlv", "sw", "ef"],
            help=(
                "Auto detects from CLA/INS and the leading tag; pick a domain to force it. "
                "apdu reads every row as a command, response every row as an answer. "
                "ef reads the content of a file: the file identifier on the first line, the content below."
            ),
        ),
    ),
    output_kind="context_decode",
    dispatcher=_dispatch_context_decode,
    tags=("decode", "apdu", "tlv", "es10", "gp", "cat"),
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
            placeholder="{ \"header\": { ... }, \"body\": { ... } }",
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


TP_DECODE_SPEC = ActionSpec(
    id="tool.tp.decode",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="TERMINAL PROFILE decode",
    description=(
        "Name each facility a TERMINAL PROFILE claims (ETSI TS 102 223 §5.2, "
        "3GPP TS 31.111 §5.2), report bits its coding keeps 0, or compare two profiles."
    ),
    inputs=(
        ActionField(
            name="profile",
            label="Profile hex",
            kind="text",
            required=True,
            multiline=True,
            placeholder="80 10 00 00 27 FF FF FF FF 1F ...",
            help=(
                "The profile bytes or the whole TERMINAL PROFILE APDU; spaces, "
                "colons and 0x prefixes are accepted."
            ),
        ),
        ActionField(
            name="compare",
            label="Compare with",
            kind="text",
            required=False,
            multiline=True,
            placeholder="FF FF FF FF 1F ...",
            help="Optional second profile; the result then lists only the facilities that differ.",
        ),
        ActionField(
            name="show",
            label="Show",
            kind="enum",
            required=False,
            default="all",
            choices=["all", "set"],
            help="all lists every bit and field; set lists only what the profile claims.",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_tp_decode,
    tags=("decode", "cat", "terminal-profile"),
)


TP_BUILD_SPEC = ActionSpec(
    id="tool.tp.build",
    subsystem=OFFLINE_TOOLS_SUBSYSTEM,
    title="TERMINAL PROFILE build",
    description=(
        "Build a TERMINAL PROFILE by setting and clearing facilities and count fields, "
        "starting from the toolchain's maximal profile, an empty one or a pasted one."
    ),
    inputs=(
        ActionField(
            name="base",
            label="Start from",
            kind="enum",
            required=False,
            default="maximal",
            choices=list(_TP_BASES),
            help=(
                "maximal is the profile every YggdraSIM shell sends: every facility "
                "claimed, every bit coded 0 left clear."
            ),
        ),
        ActionField(
            name="base_profile",
            label="Pasted profile",
            kind="text",
            required=False,
            multiline=True,
            placeholder="FF FF FF FF 1F ...",
            help="Used when Start from is pasted; the whole APDU is accepted too.",
        ),
        ActionField(
            name="set_items",
            label="Set",
            kind="text",
            required=False,
            multiline=True,
            placeholder="5.5\nEvent: Data available",
            help=(
                "One facility per line, by byte.bit as the specification counts them "
                "(5.5 = byte 5 b5) or by a piece of its name; addresses may share a line."
            ),
        ),
        ActionField(
            name="clear_items",
            label="Clear",
            kind="text",
            required=False,
            multiline=True,
            placeholder="33.1",
            help="Same form as Set; clearing a field sets it to 0.",
        ),
        ActionField(
            name="field_values",
            label="Field values",
            kind="text",
            required=False,
            multiline=True,
            placeholder="13.6-8=1\n11.1-8=0x08",
            help="ADDRESS=VALUE per line, decimal or 0x; a field by its bit range.",
        ),
        ActionField(
            name="length",
            label="Length",
            kind="int",
            required=False,
            min_value=0,
            max_value=255,
            help="Optional; pads with zero bytes and never cuts a byte that carries a set bit.",
        ),
    ),
    output_kind="key_value_lines",
    dispatcher=_dispatch_tp_build,
    tags=("build", "cat", "terminal-profile"),
)


get_registry().register(CONTEXT_DECODE_SPEC)
get_registry().register(ASN1_TLV_DECODE_SPEC)
get_registry().register(SAIP_LINT_SPEC)
get_registry().register(EIM_LINT_SPEC)
get_registry().register(GSMA_CODES_SPEC)
get_registry().register(TP_DECODE_SPEC)
get_registry().register(TP_BUILD_SPEC)
