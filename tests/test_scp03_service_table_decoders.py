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

import json
from pathlib import Path
import shutil
import subprocess

import pytest


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


def _extract_javascript_function(source: str, name: str) -> str:
    """Return one function declaration without pinning its argument list."""

    start = source.index(f"function {name}(")
    brace = source.index("{", start)
    depth = 0
    quote = ""
    escaped = False
    line_comment = False
    block_comment = False
    index = brace
    while index < len(source):
        current = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if line_comment:
            if current in "\r\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if current == "*" and following == "/":
                block_comment = False
                index += 2
                continue
            index += 1
            continue
        if quote:
            if escaped:
                escaped = False
            elif current == "\\":
                escaped = True
            elif current == quote:
                quote = ""
            index += 1
            continue
        if current in ("'", '"', "`"):
            quote = current
            index += 1
            continue
        if current == "/" and following == "/":
            line_comment = True
            index += 2
            continue
        if current == "/" and following == "*":
            block_comment = True
            index += 2
            continue
        if current == "{":
            depth += 1
        elif current == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
        index += 1
    raise AssertionError(f"unterminated JavaScript function: {name}")


def test_app_js_renders_service_table_payload_behaviorally() -> None:
    js = _read("app.js")
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required for the JavaScript renderer contract.")

    functions = "\n".join(
        _extract_javascript_function(js, name)
        for name in (
            "renderPrettyServiceTable",
            "isServiceTablePayload",
            "renderPrettyValue",
        )
    )
    harness = f"""
class TestNode {{
  constructor(tagName) {{
    this.tagName = tagName;
    this.className = "";
    this.textContent = "";
    this.children = [];
    this.classList = {{ add: (...names) => {{
      this.className = [this.className, ...names].filter(Boolean).join(" ");
    }} }};
  }}
  appendChild(child) {{
    this.children.push(child);
    return child;
  }}
}}
globalThis.document = {{
  createElement: (tagName) => new TestNode(tagName)
}};
function renderPrettyPrimitive(value) {{
  const node = new TestNode("span");
  node.textContent = String(value);
  return node;
}}
{functions}
function flatten(node, rows) {{
  rows.push({{
    tagName: node.tagName,
    className: node.className,
    textContent: node.textContent
  }});
  node.children.forEach((child) => flatten(child, rows));
}}
const payload = {{
  service_table: true,
  table: "UST",
  full_name: "USIM Service Table",
  summary: "1 of 2 active",
  active: ["1: Local Phone Book"],
  inactive: ["2: FDN"]
}};
const rendered = renderPrettyValue(payload, 0, {{ legacyOption: true }});
const rows = [];
flatten(rendered, rows);
process.stdout.write(JSON.stringify(rows));
"""
    completed = subprocess.run(
        [node, "-e", harness],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    rows = json.loads(completed.stdout)
    by_class = {row["className"]: row["textContent"] for row in rows}
    assert rows[0]["className"] == "cc-svc-table"
    assert by_class["cc-svc-table-summary"] == "1 of 2 active"
    assert by_class["cc-svc-table-name"] in {
        "1: Local Phone Book",
        "2: FDN",
    }
    assert {
        row["textContent"]
        for row in rows
        if row["className"] == "cc-svc-table-name"
    } == {"1: Local Phone Book", "2: FDN"}
    assert {
        row["textContent"]
        for row in rows
        if row["className"] == "cc-svc-table-mark"
    } == {"\u25cf", "\u25cb"}


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
