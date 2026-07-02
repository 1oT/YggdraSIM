# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Regression checks for SAIP GUI template-derived FCP fields."""

from __future__ import annotations

from types import SimpleNamespace

from yggdrasim_common.gui_server.actions.saip import _template_fcp_info


def test_template_transparent_ef_size_uses_minimal_hex() -> None:
    template = SimpleNamespace(file_type="TR", file_size=12)

    info = _template_fcp_info(template)

    assert info["ef_size"] == "0C"
    assert info["ef_size_source"] == "template"


def test_template_record_ef_size_uses_minimal_hex() -> None:
    template = SimpleNamespace(file_type="LF", rec_len=3, nb_rec=4)

    info = _template_fcp_info(template)

    assert info["ef_size"] == "0C"
    assert info["ef_size_source"] == "template"


def test_template_size_above_one_octet_keeps_required_octets() -> None:
    template = SimpleNamespace(file_type="TR", file_size=256)

    info = _template_fcp_info(template)

    assert info["ef_size"] == "0100"
