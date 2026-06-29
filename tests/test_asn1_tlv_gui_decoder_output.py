# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

from pathlib import Path

from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath: str) -> str:
    return (ROOT / relpath).read_text(encoding="utf-8")


def test_asn1_tlv_decoder_uses_custom_gui_output_kind() -> None:
    registry = ensure_builtin_actions_loaded()
    spec = registry.get("tool.asn1_tlv.decode")

    assert spec.output_kind == "asn1_tlv"


def test_asn1_tlv_decoder_frontend_has_focused_form_and_renderer() -> None:
    command_js = _read("gui_frontend/src/js/command-center.js")
    compact_css = _read("gui_frontend/src/css/views/command-center-compact-pane.css")
    tlv_css = _read("gui_frontend/src/css/views/command-center-tlv-tree.css")

    assert "ccEnhanceAsn1TlvDecodeForm" in command_js
    assert "renderAsn1TlvDecodeResult" in command_js
    assert 'kind === "asn1_tlv"' in command_js
    assert "Schema-aware decode" in command_js
    assert ".cc-asn1-decode-form" in compact_css
    assert ".cc-asn1-notation" in tlv_css
    assert ".cc-asn1-raw-json" in tlv_css


def test_built_static_contains_asn1_tlv_decoder_gui_hooks() -> None:
    static_js = _read("yggdrasim_common/gui_server/static/app.js")
    static_css = _read("yggdrasim_common/gui_server/static/app.css")

    assert "ccEnhanceAsn1TlvDecodeForm" in static_js
    assert "renderAsn1TlvDecodeResult" in static_js
    assert 'kind === "asn1_tlv"' in static_js
    assert ".cc-asn1-decode-form" in static_css
    assert ".cc-asn1-notation" in static_css
