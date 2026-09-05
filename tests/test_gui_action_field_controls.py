# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Contracts for shared action-form controls used by the SAIP palette."""

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]


def _bodies() -> tuple[str, str]:
    source = (
        _ROOT / "gui_frontend/src/js/command-center.js"
    ).read_text(encoding="utf-8")
    served = (
        _ROOT / "yggdrasim_common/gui_server/static/app.js"
    ).read_text(encoding="utf-8")
    return source, served


def _style_bodies() -> tuple[str, str]:
    source = (
        _ROOT / "gui_frontend/src/css/views/command-center-compact-pane.css"
    ).read_text(encoding="utf-8")
    served = (
        _ROOT / "yggdrasim_common/gui_server/static/app.css"
    ).read_text(encoding="utf-8")
    return source, served


def _assert_controls(body: str) -> None:
    assert 'if (field.kind === "internal")' in body
    assert 'input.type = "hidden"' in body
    assert 'row.dataset.internalActionField = "true"' in body
    assert 'field.multiline || field.kind === "json"' in body
    assert 'input.rows = field.kind === "json" ? 6 : 4' in body
    assert "input.spellcheck = false" in body
    assert 'input.setAttribute("autocapitalize", "off")' in body


def test_canonical_action_controls_hide_internal_fields_and_expand_json() -> None:
    source, _served = _bodies()
    _assert_controls(source)


def test_served_action_controls_hide_internal_fields_and_expand_json() -> None:
    _source, served = _bodies()
    _assert_controls(served)


def test_hidden_internal_action_rows_override_grid_layout() -> None:
    source, _served = _style_bodies()
    assert ".cc-action-form > .cc-form-row[hidden]" in source
    assert "display: none;" in source


def test_served_hidden_action_rows_override_grid_layout() -> None:
    _source, served = _style_bodies()
    assert ".cc-action-form > .cc-form-row[hidden]" in served
    assert "display: none;" in served
