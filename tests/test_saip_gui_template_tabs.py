# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Static GUI contracts for SAIP file template/default-content tabs."""

from __future__ import annotations

from pathlib import Path


_APP_JS = Path("yggdrasim_common/gui_server/static/app.js")


def _read_app_js() -> str:
    return _APP_JS.read_text(encoding="utf-8")


def test_template_default_content_renders_from_template_tab() -> None:
    js = _read_app_js()
    assert "function saipFileRenderTemplate(host, data)" in js
    assert 'mkTab(\n        "template",' in js
    assert "saipBuildTemplateDefaultInfoCardForData(data || {})" in js


def test_data_tabs_suppress_template_default_content_card() -> None:
    js = _read_app_js()
    assert "showTemplateDefault = renderOptions.showTemplateDefault !== false" in js
    assert js.count("showTemplateDefault: false") >= 2
    assert "content is inherited from the template default on the Template tab" in js


def test_profile_header_gfste_editor_has_template_rail() -> None:
    js = _read_app_js()
    assert "function saipHeaderRenderGfsteRail(" in js
    assert "saip-profile-gfste-rail-btn" in js
    assert 'gfsteRail.setAttribute("role", "radiogroup")' in js
    assert 'gfsteRail.setAttribute("aria-label", "Applied GFSTE templates")' in js
