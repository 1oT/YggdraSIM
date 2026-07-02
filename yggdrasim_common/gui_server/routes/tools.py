# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""``/api/tools/*`` — pure-function engine panels (Milestone B-1).

Every endpoint in this router wraps a stateless helper that already
exists in the codebase (resolved through :mod:`yggdrasim_common.registry`
so the gui_server package has no direct dependency on SCP03/SCP11/Tools).
These routes are the lowest-risk wiring surface: no PTY, no hardware,
no long-running sessions. They are intended to stay safe to call from
untrusted frontends as long as the bearer-token gate is up-front.

Shape contract per endpoint:

* Inputs are validated via ``pydantic`` models; malformed bodies yield
  HTTP 422 from FastAPI's built-in handler.
* Runtime parse failures (bad hex, truncated TLV, invalid JSON) return
  HTTP 400 with ``{"detail": "..."}`` — the frontend renders this
  verbatim in the per-panel error strip.
* Unexpected exceptions bubble up as HTTP 500 so operator logs catch
  programming bugs rather than masking them behind a generic success.
"""

from __future__ import annotations

import binascii
import json
from typing import Any, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field


router = APIRouter(prefix="/api/tools", tags=["tools"])


# --- helpers ------------------------------------------------------------


def _parse_hex(raw: str, *, field_name: str = "hex") -> bytes:
    """Accept both compact (``"6F00"``) and spaced (``"6F 00"``) hex forms."""
    compact = "".join(ch for ch in (raw or "") if ch.strip())
    if len(compact) == 0:
        raise HTTPException(status_code=400, detail=f"{field_name} is empty.")
    if len(compact) % 2 != 0:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} must contain an even number of hex characters.",
        )
    try:
        return binascii.unhexlify(compact)
    except (binascii.Error, ValueError) as error:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} is not valid hex: {error}",
        )


# --- TLV parse ----------------------------------------------------------


class TlvParseRequest(BaseModel):
    hex: str = Field(..., description="Compact or spaced hex string of the TLV buffer.")


class TlvNode(BaseModel):
    tag_hex: str
    length: int
    value_hex: Optional[str] = None
    children: Optional[list["TlvNode"]] = None


class TlvParseResponse(BaseModel):
    complete: bool
    consumed: int
    error: Optional[str]
    nodes: list[TlvNode]


def _tlv_dict_to_nodes(parsed: dict) -> list[TlvNode]:
    """Project the TlvParser output (int-keyed, possibly nested dict)
    into a serialisable tree. Duplicate tags (value is a list) are
    expanded into sibling nodes so the frontend renders them distinctly.
    """
    nodes: list[TlvNode] = []
    for tag_int, raw_value in parsed.items():
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        for value in values:
            tag_hex = format(tag_int, "X")
            if len(tag_hex) % 2 == 1:
                tag_hex = "0" + tag_hex
            if isinstance(value, dict):
                # Nested constructed TLV — recurse.
                children = _tlv_dict_to_nodes(value)
                child_byte_count = _estimate_nested_length(value)
                nodes.append(
                    TlvNode(
                        tag_hex=tag_hex,
                        length=child_byte_count,
                        children=children,
                    )
                )
            else:
                raw_bytes = bytes(value) if isinstance(value, (bytes, bytearray)) else b""
                nodes.append(
                    TlvNode(
                        tag_hex=tag_hex,
                        length=len(raw_bytes),
                        value_hex=raw_bytes.hex().upper(),
                    )
                )
    return nodes


def _estimate_nested_length(parsed: dict) -> int:
    """Approximate byte length of a constructed value by summing children.

    This is informational — we do not attempt to reconstruct the exact
    original TLV encoding; the goal is to give the operator a sensible
    length column for the tree view.
    """
    total = 0
    for raw_value in parsed.values():
        values = raw_value if isinstance(raw_value, list) else [raw_value]
        for value in values:
            if isinstance(value, dict):
                total += _estimate_nested_length(value)
            elif isinstance(value, (bytes, bytearray)):
                total += len(value)
    return total


@router.post("/tlv/parse", response_model=TlvParseResponse)
def parse_tlv(body: TlvParseRequest) -> TlvParseResponse:
    """Parse a hex TLV blob and return a nested JSON representation."""
    from yggdrasim_common import registry as yggdrasim_registry

    data = _parse_hex(body.hex)
    parser_cls = yggdrasim_registry.get("scp03.core.utils.tlv")
    result = parser_cls.parse_detailed(data)
    nodes = _tlv_dict_to_nodes(result["parsed"])
    return TlvParseResponse(
        complete=bool(result.get("complete", False)),
        consumed=int(result.get("consumed", 0)),
        error=result.get("error"),
        nodes=nodes,
    )


# --- Status-word translate ---------------------------------------------


class SwTranslateRequest(BaseModel):
    hex: Optional[str] = Field(None, description="Two-byte hex (e.g. '9000').")
    sw1: Optional[int] = Field(None, ge=0, le=0xFF)
    sw2: Optional[int] = Field(None, ge=0, le=0xFF)


class SwTranslateResponse(BaseModel):
    sw1: int
    sw2: int
    sw_hex: str
    description: str


@router.post("/sw/translate", response_model=SwTranslateResponse)
def translate_sw(body: SwTranslateRequest) -> SwTranslateResponse:
    """Translate a status-word hex string to a human-readable description."""
    from yggdrasim_common import registry as yggdrasim_registry

    if body.hex is not None:
        data = _parse_hex(body.hex, field_name="sw")
        if len(data) != 2:
            raise HTTPException(status_code=400, detail="sw hex must decode to exactly 2 bytes.")
        sw1, sw2 = data[0], data[1]
    elif body.sw1 is not None and body.sw2 is not None:
        sw1, sw2 = int(body.sw1), int(body.sw2)
    else:
        raise HTTPException(
            status_code=400,
            detail="Provide either `hex` (4 chars) or both `sw1` and `sw2`.",
        )

    translator_cls = yggdrasim_registry.get("scp03.core.utils.sw")
    description = translator_cls.translate(sw1, sw2)
    sw_hex = format((sw1 << 8) | sw2, "04X")
    return SwTranslateResponse(sw1=sw1, sw2=sw2, sw_hex=sw_hex, description=description)


# --- euicc_info2 decode -------------------------------------------------


class EuiccInfo2Request(BaseModel):
    hex: str = Field(..., description="Compact hex of the EUICCInfo2 response (tag BF22).")


class EuiccInfo2Line(BaseModel):
    indent: int
    label: str
    value: str


class EuiccInfo2Response(BaseModel):
    detail_lines: list[EuiccInfo2Line]
    validation_lines: list[EuiccInfo2Line]


@router.post("/euicc-info2/decode", response_model=EuiccInfo2Response)
def decode_euicc_info2(body: EuiccInfo2Request) -> EuiccInfo2Response:
    """Decode an EUICCInfo2 hex response and return a structured JSON breakdown."""
    from yggdrasim_common import registry as yggdrasim_registry

    data = _parse_hex(body.hex)
    if len(data) < 2 or data[:2] != b"\xBF\x22":
        raise HTTPException(status_code=400, detail="EUICCInfo2 payload must start with tag BF22.")
    build_detail = yggdrasim_registry.get("scp03.logic.euicc_info2.build_detail")
    build_validation = yggdrasim_registry.get("scp03.logic.euicc_info2.build_validation")

    try:
        detail_tuples = build_detail(data)
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"EUICCInfo2 decode failed: {error}")
    try:
        validation_tuples = build_validation(data)
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"EUICCInfo2 validation failed: {error}")

    detail = [EuiccInfo2Line(indent=int(i), label=str(l), value=str(v)) for i, l, v in detail_tuples]
    validation = [
        EuiccInfo2Line(indent=int(i), label=str(l), value=str(v)) for i, l, v in validation_tuples
    ]
    return EuiccInfo2Response(detail_lines=detail, validation_lines=validation)


# --- SAIP lint (editor-JSON path) --------------------------------------


class SaipLintRequest(BaseModel):
    json_text: str = Field(..., description="SAIP TRANSCODE-TUI editor JSON buffer.")
    profile_label: str = Field(default="ad-hoc")
    strict: bool = Field(default=False)


class SaipLintFinding(BaseModel):
    code: str
    severity: str
    spec: str
    path: str
    message: str
    recommendation: str
    evidence: Any = None


class SaipLintResponse(BaseModel):
    parse_error: Optional[str]
    template_mode: bool
    undefined_tokens: list[str]
    placeholder_paths: list[str]
    report: Optional[dict[str, Any]]
    findings: list[SaipLintFinding]


@router.post("/saip/lint", response_model=SaipLintResponse)
def lint_saip(body: SaipLintRequest) -> SaipLintResponse:
    # Deferred import: Tools.ProfilePackage drags in asn1 + saip-tool which
    # are heavy and we do not want to penalise callers that never hit the
    # linter panel.
    """Run the SAIP profile linter on a submitted profile JSON and return the findings."""
    from Tools.ProfilePackage.saip_tui_lint import lint_profile_json_buffer

    try:
        outcome = lint_profile_json_buffer(
            body.json_text,
            body.profile_label,
            strict=bool(body.strict),
        )
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"SAIP lint invocation failed: {error}")

    report_dict: Optional[dict[str, Any]] = None
    findings: list[SaipLintFinding] = []
    if outcome.report is not None:
        report_dict = outcome.report.to_dict()
        findings = [SaipLintFinding(**item) for item in report_dict.get("findings", [])]

    return SaipLintResponse(
        parse_error=outcome.parse_error,
        template_mode=bool(outcome.template_mode),
        undefined_tokens=sorted(outcome.undefined_tokens),
        placeholder_paths=sorted(outcome.placeholder_paths),
        report=report_dict,
        findings=findings,
    )


# --- eIM package lint --------------------------------------------------


class EimLintRequest(BaseModel):
    document_json: str = Field(
        ...,
        description="Raw JSON text of the eIM package document (parsed server-side).",
    )


class EimLintResponse(BaseModel):
    errors: list[str]
    warnings: list[str]
    summary: dict[str, Any]


@router.post("/eim/lint", response_model=EimLintResponse)
def lint_eim_package(body: EimLintRequest) -> EimLintResponse:
    """HTTP handler: run the eIM-package linter and return findings as JSON."""
    from yggdrasim_common import registry as yggdrasim_registry

    try:
        document = json.loads(body.document_json)
    except json.JSONDecodeError as error:
        raise HTTPException(status_code=400, detail=f"document_json is not valid JSON: {error}")
    if not isinstance(document, dict):
        raise HTTPException(status_code=400, detail="document_json root must be a JSON object.")

    linter = yggdrasim_registry.get("scp11.eim_local.package_lint")
    try:
        report = linter(document)
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"eIM lint failed: {error}")

    errors = [str(item) for item in report.get("errors", []) or []]
    warnings = [str(item) for item in report.get("warnings", []) or []]
    summary = {k: v for k, v in report.items() if k not in ("errors", "warnings")}
    return EimLintResponse(errors=errors, warnings=warnings, summary=summary)


# --- GSMA error-code tables --------------------------------------------


class GsmaTablesResponse(BaseModel):
    tables: dict[str, dict[str, str]]
    order: list[str]


@router.get("/gsma/codes", response_model=GsmaTablesResponse)
def list_gsma_codes() -> GsmaTablesResponse:
    # Direct import — the table lives in SCP11.shared.gsma_error_codes which
    # is pure-python and always importable.
    """HTTP handler: return the full GSMA reason-code table as JSON."""
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
    for slug, attr in wanted:
        table = getattr(gsma, attr, None)
        if not isinstance(table, dict):
            continue
        order.append(slug)
        tables[slug] = {str(code): str(label) for code, label in sorted(table.items())}
    return GsmaTablesResponse(tables=tables, order=order)


TlvNode.model_rebuild()
