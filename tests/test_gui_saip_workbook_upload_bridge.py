# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static contracts for the browser-side Excel → SAIP upload bridge."""

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]


def _sources() -> tuple[str, str]:
    canonical = (
        _ROOT / "gui_frontend/src/js/command-center.js"
    ).read_text(encoding="utf-8")
    served = (
        _ROOT / "yggdrasim_common/gui_server/static/app.js"
    ).read_text(encoding="utf-8")
    return canonical, served


def _assert_hardened_upload_bridge(body: str) -> None:
    assert 'CC_SAIP_WORKBOOK_GENERATOR_TAG = "saip-filesystem-workbook"' in body
    assert "workbook_filename: true" in body
    assert "workbook_content_base64: true" in body
    assert "function ccIsSaipWorkbookInternalField(action, field)" in body
    assert "function ccShowSaipWorkbookUploadSource(" in body
    assert (
        "tags.indexOf(CC_SAIP_WORKBOOK_GENERATOR_TAG) !== -1"
        in body
    )
    assert (
        "field.secret && !ccIsSaipWorkbookInternalField(action, field)"
        in body
    )
    assert "row.dataset.saipWorkbookInternal" in body
    assert 'control.setAttribute("autocomplete", "off")' in body
    assert 'control.setAttribute("aria-hidden", "true")' in body
    assert "control.tabIndex = -1" in body
    assert 'display.value = "upload:" + uploadName' in body
    assert "pathControl.disabled = true" in body
    assert "pathRow.hidden = true" in body
    assert (
        "Browser-local workbook prepared in memory; it is not staged on disk."
        in body
    )
    assert 'workbookOutput.placeholder = "Workspace/SAIP/generated (default)"' in body
    assert "consumedWorkbookUpload = true" in body
    assert (
        "Upload payload cleared after use. Drop the workbook again to rerun."
        in body
    )
    assert "runButton.disabled = true" in body


def test_canonical_action_form_has_hardened_workbook_upload_bridge() -> None:
    canonical, _served = _sources()
    _assert_hardened_upload_bridge(canonical)


def test_served_bundle_has_hardened_workbook_upload_bridge() -> None:
    _canonical, served = _sources()
    _assert_hardened_upload_bridge(served)
