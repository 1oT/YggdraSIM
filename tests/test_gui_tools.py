# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Narrow tests for ``yggdrasim_common/gui_server/routes/tools.py`` (B-1).

The route handlers are exercised directly so the tests cover their
request/response contracts without starting an HTTP client or event-loop
portal.  The bearer gate is tested independently at its pure-ASGI boundary.
"""

from __future__ import annotations

import asyncio
import json

import pytest

# The tools router imports ``fastapi`` at module scope, so the entire
# test file only makes sense when the optional GUI stack is installed.
pytest.importorskip("fastapi")

from yggdrasim_common.gui_server.routes import tools as tools_module  # noqa: E402


# --- Helpers that are independent of FastAPI ---------------------------


class TestParseHexHelper:
    def test_compact_uppercase_round_trip(self) -> None:
        assert tools_module._parse_hex("9000") == b"\x90\x00"

    def test_spaced_mixed_case(self) -> None:
        assert tools_module._parse_hex(" 6f 00  ") == b"\x6F\x00"

    def test_empty_raises_http_400(self) -> None:
        with pytest.raises(Exception) as excinfo:
            tools_module._parse_hex("   ")
        assert getattr(excinfo.value, "status_code", None) == 400

    def test_odd_length_raises_http_400(self) -> None:
        with pytest.raises(Exception) as excinfo:
            tools_module._parse_hex("9FA")
        assert getattr(excinfo.value, "status_code", None) == 400

    def test_non_hex_raises_http_400(self) -> None:
        with pytest.raises(Exception) as excinfo:
            tools_module._parse_hex("ZZ00")
        assert getattr(excinfo.value, "status_code", None) == 400


class TestTlvNodeProjection:
    def test_flat_primitive_tags(self) -> None:
        parsed = {0x80: b"\x01\x02", 0x81: b"\x03"}
        nodes = tools_module._tlv_dict_to_nodes(parsed)
        assert len(nodes) == 2
        tags = sorted(node.tag_hex for node in nodes)
        assert tags == ["80", "81"]

    def test_duplicate_tag_expands_to_siblings(self) -> None:
        parsed = {0x80: [b"\x01", b"\x02", b"\x03"]}
        nodes = tools_module._tlv_dict_to_nodes(parsed)
        assert len(nodes) == 3
        assert all(node.tag_hex == "80" for node in nodes)

    def test_constructed_tag_emits_children(self) -> None:
        parsed = {0xA0: {0x80: b"\xAA"}}
        nodes = tools_module._tlv_dict_to_nodes(parsed)
        assert len(nodes) == 1
        assert nodes[0].tag_hex == "A0"
        assert nodes[0].children is not None
        assert len(nodes[0].children) == 1
        assert nodes[0].children[0].tag_hex == "80"
        assert nodes[0].children[0].value_hex == "AA"


# --- Route request/response contracts ---------------------------------


class TestTlvRoute:
    def test_parse_flat_tag(self) -> None:
        response = tools_module.parse_tlv(tools_module.TlvParseRequest(hex="80 02 9000"))
        assert response.complete is True
        assert response.error is None
        assert response.consumed == 4
        assert len(response.nodes) == 1
        assert response.nodes[0].tag_hex == "80"
        assert response.nodes[0].value_hex == "9000"

    def test_parse_invalid_hex_returns_400(self) -> None:
        with pytest.raises(tools_module.HTTPException) as excinfo:
            tools_module.parse_tlv(tools_module.TlvParseRequest(hex="not-hex"))
        assert excinfo.value.status_code == 400

    def test_parse_truncated_reports_incomplete(self) -> None:
        response = tools_module.parse_tlv(tools_module.TlvParseRequest(hex="8005AB"))
        assert response.complete is False
        assert response.error is not None


class TestSwRoute:
    def test_hex_9000_is_success(self) -> None:
        response = tools_module.translate_sw(tools_module.SwTranslateRequest(hex="9000"))
        assert response.sw_hex == "9000"
        assert "Success" in response.description

    def test_dynamic_63cx_retries(self) -> None:
        response = tools_module.translate_sw(tools_module.SwTranslateRequest(hex="63C3"))
        assert "3 retries" in response.description

    def test_requires_hex_or_split_bytes(self) -> None:
        with pytest.raises(tools_module.HTTPException) as excinfo:
            tools_module.translate_sw(tools_module.SwTranslateRequest())
        assert excinfo.value.status_code == 400


class TestEuiccInfo2Route:
    def test_invalid_payload_400(self) -> None:
        with pytest.raises(tools_module.HTTPException) as excinfo:
            tools_module.decode_euicc_info2(tools_module.EuiccInfo2Request(hex="00"))
        assert excinfo.value.status_code == 400


class TestEimLintRoute:
    def test_valid_document_returns_report(self) -> None:
        document = {
            "package_type": "sm_dp_plus_address",
            "package_version": "1.0.0",
            "command_tag_hex": "BF40",
            "matching_id": "ABC-123",
            "additional_tlvs": [],
        }
        response = tools_module.lint_eim_package(
            tools_module.EimLintRequest(document_json=json.dumps(document))
        )
        assert isinstance(response.errors, list)
        assert isinstance(response.warnings, list)

    def test_non_json_returns_400(self) -> None:
        with pytest.raises(tools_module.HTTPException) as excinfo:
            tools_module.lint_eim_package(
                tools_module.EimLintRequest(document_json="{not valid")
            )
        assert excinfo.value.status_code == 400


class TestGsmaRoute:
    def test_tables_include_es10b(self) -> None:
        response = tools_module.list_gsma_codes()
        assert "es10b_profile_state" in response.order
        assert response.tables["es10b_profile_state"]["0"] == "ok"


class TestAuthGate:
    def test_missing_token_is_401(self) -> None:
        from yggdrasim_common.gui_server.auth import AuthMiddleware

        downstream_called = False
        messages: list[dict] = []

        async def downstream(scope, receive, send) -> None:
            nonlocal downstream_called
            downstream_called = True

        async def receive() -> dict:
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message: dict) -> None:
            messages.append(message)

        middleware = AuthMiddleware(
            downstream,
            expected_token="0123456789abcdef0123456789abcdef",
        )
        scope = {
            "type": "http",
            "method": "GET",
            "path": "/api/tools/gsma/codes",
            "headers": [],
            "client": ("127.0.0.1", 12345),
        }
        asyncio.run(middleware(scope, receive, send))

        assert downstream_called is False
        response_start = next(item for item in messages if item["type"] == "http.response.start")
        response_body = next(item for item in messages if item["type"] == "http.response.body")
        assert response_start["status"] == 401
        assert (b"www-authenticate", b"Bearer") in response_start["headers"]
        assert json.loads(response_body["body"]) == {"error": "unauthorized"}
