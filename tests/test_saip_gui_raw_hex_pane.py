# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Static GUI contracts for the SAIP raw file hex pane."""

from __future__ import annotations

from pathlib import Path


_APP_JS = Path("yggdrasim_common/gui_server/static/app.js")
_APP_CSS = Path("yggdrasim_common/gui_server/static/app.css")


def test_raw_file_hex_uses_spaced_octets_and_soft_wrap() -> None:
    js = _APP_JS.read_text(encoding="utf-8")
    assert 'ta.wrap = "soft";' in js
    assert 'ta.value = saipFormatHexPretty(String(opts.currentHex || ""));' in js
    assert 'replace(/(.{32})/g, "$1\\n")' not in js


def test_file_data_view_hex_pane_uses_full_width() -> None:
    css = _APP_CSS.read_text(encoding="utf-8")
    marker = ".saip-file-data-view {"
    start = css.find(marker)
    assert start >= 0
    end = css.find("}", start)
    block = css[start:end]
    assert "grid-template-columns: minmax(0, 1fr);" in block
    assert "minmax(280px, 42%)" not in block
