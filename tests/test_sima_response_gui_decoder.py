# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath: str) -> str:
    return (ROOT / relpath).read_text(encoding="utf-8")


def test_sima_response_frontend_renderer_hooks() -> None:
    command_js = _read("gui_frontend/src/js/command-center.js")
    tlv_css = _read("gui_frontend/src/css/views/command-center-tlv-tree.css")

    assert "renderSimaResponseResult" in command_js
    assert 'kind === "sima_response"' in command_js
    assert "SIMa final result" in command_js
    assert ".cc-sima-summary" in tlv_css
    assert ".cc-sima-result-chip--failure" in tlv_css


def test_built_static_contains_sima_response_renderer_hooks() -> None:
    static_js = _read("yggdrasim_common/gui_server/static/app.js")
    static_css = _read("yggdrasim_common/gui_server/static/app.css")

    assert "renderSimaResponseResult" in static_js
    assert 'kind === "sima_response"' in static_js
    assert ".cc-sima-summary" in static_css
