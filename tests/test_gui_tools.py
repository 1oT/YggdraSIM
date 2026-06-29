# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Narrow tests for ``yggdrasim_common/gui_server/routes/tools.py`` (B-1).

The file is structured so the low-level helpers run in every environment
(no FastAPI needed), while the HTTP-surface tests use
``pytest.importorskip`` to gracefully skip when the ``gui`` optional
dependency stack is not installed.
"""

from __future__ import annotations

import json

import pytest

# The tools router imports ``fastapi`` at module scope, so the entire
# test file only makes sense when the optional ``gui`` / ``gui-server``
# stack is installed. Skip the whole file in environments where it is
# not, rather than each test individually.
pytest.importorskip("fastapi")
pytest.importorskip("starlette")

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


# --- HTTP-surface tests via starlette TestClient -----------------------


@pytest.fixture(scope="module")
def test_client():
    pytest.importorskip("fastapi")
    pytest.importorskip("starlette")
    from starlette.testclient import TestClient

    from yggdrasim_common.gui_server.app import create_app
    from yggdrasim_common.gui_server.config import GuiServerConfig

    config = GuiServerConfig(
        mode="desktop",
        host="127.0.0.1",
        port=0,
        token="0123456789abcdef0123456789abcdef",
        allow_origins=tuple(),
        tls_cert_path="",
        tls_key_path="",
        tls_self_signed=False,
        token_source="test-fixture",
        token_strength="generated",
        allow_ephemeral_port=True,
        idle_seconds=300,
        webview_debug=False,
    )
    app = create_app(config)
    client = TestClient(app)
    client.headers.update({"Authorization": "Bearer " + config.token})
    yield client


class TestTlvRoute:
    def test_parse_flat_tag(self, test_client) -> None:
        response = test_client.post("/api/tools/tlv/parse", json={"hex": "80 02 9000"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["complete"] is True
        assert payload["error"] is None
        assert payload["consumed"] == 4
        assert len(payload["nodes"]) == 1
        assert payload["nodes"][0]["tag_hex"] == "80"
        assert payload["nodes"][0]["value_hex"] == "9000"

    def test_parse_invalid_hex_returns_400(self, test_client) -> None:
        response = test_client.post("/api/tools/tlv/parse", json={"hex": "not-hex"})
        assert response.status_code == 400

    def test_parse_truncated_reports_incomplete(self, test_client) -> None:
        response = test_client.post("/api/tools/tlv/parse", json={"hex": "8005AB"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["complete"] is False
        assert payload["error"] is not None


class TestSwRoute:
    def test_hex_9000_is_success(self, test_client) -> None:
        response = test_client.post("/api/tools/sw/translate", json={"hex": "9000"})
        assert response.status_code == 200
        payload = response.json()
        assert payload["sw_hex"] == "9000"
        assert "Success" in payload["description"]

    def test_dynamic_63cx_retries(self, test_client) -> None:
        response = test_client.post("/api/tools/sw/translate", json={"hex": "63C3"})
        assert response.status_code == 200
        assert "3 retries" in response.json()["description"]

    def test_requires_hex_or_split_bytes(self, test_client) -> None:
        response = test_client.post("/api/tools/sw/translate", json={})
        assert response.status_code == 400


class TestEuiccInfo2Route:
    def test_invalid_payload_400(self, test_client) -> None:
        response = test_client.post("/api/tools/euicc-info2/decode", json={"hex": "00"})
        assert response.status_code == 400


class TestEimLintRoute:
    def test_valid_document_returns_report(self, test_client) -> None:
        document = {
            "package_type": "sm_dp_plus_address",
            "package_version": "1.0.0",
            "command_tag_hex": "BF40",
            "matching_id": "ABC-123",
            "additional_tlvs": [],
        }
        response = test_client.post(
            "/api/tools/eim/lint",
            json={"document_json": json.dumps(document)},
        )
        assert response.status_code == 200
        payload = response.json()
        assert isinstance(payload["errors"], list)
        assert isinstance(payload["warnings"], list)

    def test_non_json_returns_400(self, test_client) -> None:
        response = test_client.post(
            "/api/tools/eim/lint",
            json={"document_json": "{not valid"},
        )
        assert response.status_code == 400


class TestGsmaRoute:
    def test_tables_include_es10b(self, test_client) -> None:
        response = test_client.get("/api/tools/gsma/codes")
        assert response.status_code == 200
        payload = response.json()
        assert "es10b_profile_state" in payload["order"]
        assert payload["tables"]["es10b_profile_state"]["0"] == "ok"


class TestAuthGate:
    def test_missing_token_is_401(self, test_client) -> None:
        # Create a fresh client without the auth header to confirm
        # /api/tools/* is gated by the existing middleware.
        from fastapi import FastAPI
        from starlette.testclient import TestClient

        # Reuse the configured app but strip the default header.
        app: FastAPI = test_client.app  # type: ignore[attr-defined]
        unauth = TestClient(app)
        response = unauth.get("/api/tools/gsma/codes")
        assert response.status_code == 401
