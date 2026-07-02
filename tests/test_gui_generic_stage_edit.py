# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static contract for the generic Stage-edit popout (Task 3).

The Stage-edit affordance was originally bitmap-only (EF.UST / EF.IST /
generic service tables); operators asked for the same workflow on every
decoded EF. Service-table payloads keep their purpose-built checklist —
its UI value comes from the bitmap-aware encoder backend — but every
other transparent EF that arrives with raw bytes now opens a generic
side-by-side hex editor pre-filled with the current EF body.

The "Send to UPDATE BINARY" button must be gated through the existing
``scp03GateOpen`` helper so the auth modal still pops before the wizard
pre-fills.

Pure file-read assertions; no FastAPI / browser surface required.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# JS surface
# ----------------------------------------------------------------------


def test_generic_stage_function_exists() -> None:
    js = _read("app.js")
    assert "function scp03ShowGenericStaging(decoded, currentHex)" in js, (
        "generic stage-edit popout must exist on the SPA bundle"
    )


def test_generic_stage_popout_uses_extras_card_and_gates() -> None:
    js = _read("app.js")
    fn_start = js.index("function scp03ShowGenericStaging(decoded, currentHex)")
    fn_window = js[fn_start : fn_start + 9000]
    assert 'scp03BuildExtrasCard("Stage edit \\u2014 "' in fn_window, (
        "generic stage popout must title itself via scp03BuildExtrasCard"
    )
    assert "scp03GateOpen" in fn_window, (
        "generic stage popout must funnel Send through scp03GateOpen so "
        "the auth modal still gates the UPDATE BINARY write"
    )
    assert "scp03StageOpenUpdateBinary" in fn_window, (
        "generic stage popout must hand staged bytes to the UPDATE BINARY "
        "wizard via scp03StageOpenUpdateBinary"
    )


def test_generic_stage_popout_renders_required_controls() -> None:
    js = _read("app.js")
    fn_start = js.index("function scp03ShowGenericStaging(decoded, currentHex)")
    fn_window = js[fn_start : fn_start + 9000]
    for needle in (
        '"Copy hex"',
        '"Reset"',
        '"Send to UPDATE BINARY"',
        "cc-stage-editor",
        "cc-svc-stage-diff",
        "cc-svc-stage-counts",
    ):
        assert needle in fn_window, (
            f"generic stage popout missing required affordance: {needle}"
        )


def test_decoded_toolbar_dispatches_to_generic_or_service_table() -> None:
    js = _read("app.js")
    fn_start = js.index("function buildDecodedToolbar(decoded, prettyEl, jsonEl, meta)")
    fn_window = js[fn_start : fn_start + 4000]
    # Service-table bitmaps still get their dedicated checklist popout.
    assert "scp03ShowServiceTableStaging" in fn_window, (
        "service-table dispatch must remain in the decoded toolbar"
    )
    # Non-bitmap decoded EFs fall through to the generic editor.
    assert "scp03ShowGenericStaging" in fn_window, (
        "decoded toolbar must dispatch non-bitmap payloads to the generic "
        "stage-edit popout"
    )
    assert "isServiceTablePayload" in fn_window, (
        "decoded toolbar must branch on isServiceTablePayload to pick the "
        "right stage handler"
    )


def test_diff_chip_handles_odd_hex_length() -> None:
    """Odd hex must be flagged before the operator hits Send."""
    js = _read("app.js")
    fn_start = js.index("function scp03ShowGenericStaging(decoded, currentHex)")
    fn_window = js[fn_start : fn_start + 9000]
    assert '"odd hex length"' in fn_window, (
        "stage editor must surface odd hex length before the operator hits "
        "Send to UPDATE BINARY"
    )


# ----------------------------------------------------------------------
# CSS surface
# ----------------------------------------------------------------------


def test_generic_stage_styles_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-stage-context",
        ".cc-stage-context-summary",
        ".cc-stage-context-body",
        ".cc-stage-editor",
        ".cc-stage-editor:focus",
    ):
        assert selector in css, f"stage-edit selector missing: {selector}"
