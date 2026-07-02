# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the bitmap service-table decoders.

Operators asked for the EF.UST / EF.IST decoded view to display
*not-set* services as well as the active ones, so the GUI can render
a checklist-style audit view rather than only echoing the subset the
card has flipped on.

The contract is:

  * ``decode_ust`` / ``decode_isim_ist`` / ``decode_service_table_bits``
    all return a dict with ``service_table=True``, ``active`` /
    ``inactive`` / ``total_count`` and a human ``summary``.
  * ``decode_obj`` passes the dict straight through (no ``items`` wrap).
  * The frontend ``app.js`` carries a matching ``isServiceTablePayload``
    detector and a ``renderPrettyServiceTable`` renderer, plus CSS for
    the two-column checklist view.

Tests are pure-Python / static-grep; no card and no GUI server are
required.
"""

from __future__ import annotations

from pathlib import Path


# ----------------------------------------------------------------------
# Backend — SCP03/core/decoders.py
# ----------------------------------------------------------------------


def test_decode_ust_returns_active_and_inactive() -> None:
    from SCP03.core.decoders import AdvancedDecoders

    # Bit pattern 0x02 in byte 0 → service 2 active. Pad the rest of
    # the body with zeros so we have 14 bytes (matches the screenshot
    # the operator pasted).
    sample_hex = "02" + "00" * 13

    out = AdvancedDecoders.decode_ust(sample_hex)
    assert isinstance(out, dict), "decoder must return a dict for the new contract"
    assert out["service_table"] is True, "service_table marker is required"
    assert out["table"] == "UST"
    assert out["full_name"] == "USIM Service Table"

    # Bit 1 of byte 0 (= service 2) is the only flag we set.
    assert out["active"] == ["2: FDN"], out["active"]
    assert out["active_count"] == 1
    # Total bits = 14 bytes * 8 = 112; inactive = 111.
    assert out["total_count"] == 14 * 8
    assert out["inactive_count"] == 14 * 8 - 1

    # The human-readable summary is what the GUI shows in the header
    # chip — keep its shape stable so the renderer test pins below
    # match.
    assert out["summary"] == "1 of 112 active"

    # Inactive list must include both named services (from the map)
    # and any out-of-map placeholders. Service 1 is named.
    assert "1: Local Phone Book" in out["inactive"]


def test_decode_ust_handles_empty_and_invalid_input() -> None:
    from SCP03.core.decoders import AdvancedDecoders

    empty = AdvancedDecoders.decode_ust("")
    # The error path still has the active/inactive keys so the renderer
    # never crashes on edge inputs.
    assert empty["error"] == "Empty"
    assert empty["active"] == []
    assert empty["inactive"] == []

    bad = AdvancedDecoders.decode_ust("ZZ")
    assert bad["error"] == "UST Decode Error"
    assert bad["active"] == []
    assert bad["inactive"] == []


def test_decode_isim_ist_splits_active_and_inactive() -> None:
    from SCP03.core.decoders import ContentDecoder

    # 0x07 in the first byte = services 1 / 2 / 3 active. One byte → 8
    # services total, so 5 inactive.
    out = ContentDecoder.decode_isim_ist("07")
    assert out["service_table"] is True
    assert out["table"] == "IST"
    assert out["active"] == [
        "1: P-CSCF address",
        "2: GBA",
        "3: HTTP Digest",
    ]
    assert out["active_count"] == 3
    assert out["total_count"] == 8
    assert out["inactive_count"] == 5
    # Inactive entries must still carry the human name when the bit
    # number lives in the IST name map.
    assert "4: GBA-based Local Key Establishment" in out["inactive"]


def test_decode_service_table_bits_uses_numeric_labels() -> None:
    from SCP03.core.decoders import ContentDecoder

    out = ContentDecoder.decode_service_table_bits("FF00")
    assert out["service_table"] is True
    assert out["active"] == ["1", "2", "3", "4", "5", "6", "7", "8"]
    assert out["inactive"][0] == "9"
    assert out["total_count"] == 16


def test_decode_obj_passes_service_table_through_unchanged() -> None:
    """``decode_obj`` must not wrap service-table dicts in ``items``.

    Pre-refactor the UST decoder returned a list which got wrapped as
    ``{"items": [...]}``. The new dict contract should bypass that
    branch — the frontend keys off ``service_table=True`` and would
    silently fall back to the generic object renderer otherwise.
    """
    from SCP03.core.decoders import ContentDecoder

    out = ContentDecoder.decode_obj("6F38", "020A140CE33000000000100000")
    assert isinstance(out, dict)
    assert out.get("service_table") is True
    assert "items" not in out, \
        "decode_obj must not wrap dict-style decoders in an items list"
    assert "active" in out and "inactive" in out


# ----------------------------------------------------------------------
# Frontend — yggdrasim_common/gui_server/static/app.js / app.css
# ----------------------------------------------------------------------


_STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (_STATIC / name).read_text(encoding="utf-8")


def test_app_js_has_service_table_detector_and_renderer() -> None:
    js = _read("app.js")
    assert "function isServiceTablePayload(value)" in js, \
        "missing service-table detector"
    assert "function renderPrettyServiceTable(value)" in js, \
        "missing service-table renderer"

    # The detector must accept the explicit marker AND the structural
    # fallback (so a backend that forgets the flag still renders).
    assert "value.service_table === true" in js
    assert "Array.isArray(value.active)" in js
    assert "Array.isArray(value.inactive)" in js

    # ``renderPrettyValue`` must dispatch to the renderer before the
    # generic array / object branches — otherwise an object with both
    # ``active`` and ``inactive`` would fall through to the dl walk.
    render_pretty_pos = js.index("function renderPrettyValue(value, depth, options)")
    detector_pos = js.index("isServiceTablePayload(value)", render_pretty_pos)
    array_pos = js.index("if (Array.isArray(value)) {", render_pretty_pos)
    assert detector_pos < array_pos, \
        "service-table dispatch must come before the array branch"

    # The two columns are rendered with stable class hooks the CSS
    # contract pins to — keep them grepable. Class names are built via
    # string concatenation in the renderer (``"cc-svc-table-row--" +
    # modifier``), so we anchor on the prefixes plus the modifier
    # literals that appear in the build helpers.
    for hook in (
        "cc-svc-table-row cc-svc-table-row--",
        "cc-svc-table-col cc-svc-table-col--",
        "cc-svc-table-summary",
        "cc-svc-table-mark",
        "cc-svc-table-name",
        "\"active\", \"\\u25CF\"",
        "\"inactive\", \"\\u25CB\"",
    ):
        assert hook in js, f"renderer no longer emits class hook: {hook}"


def test_app_css_styles_service_table() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-svc-table",
        ".cc-svc-table-head",
        ".cc-svc-table-grid",
        ".cc-svc-table-col",
        ".cc-svc-table-col-head",
        ".cc-svc-table-list",
        ".cc-svc-table-row",
        ".cc-svc-table-row--active",
        ".cc-svc-table-row--inactive",
        ".cc-svc-table-mark",
        ".cc-svc-table-name",
        ".cc-svc-table-empty",
    ):
        assert selector in css, f"CSS contract missing selector: {selector}"

    # Grid must lay out two columns side by side at the default
    # breakpoint — the entire point of the layout is comparing active
    # vs inactive at a glance.
    assert "grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);" in css
    # And collapse to one column on narrow viewports so popouts at half
    # width stay readable.
    assert "@media (max-width: 720px)" in css
