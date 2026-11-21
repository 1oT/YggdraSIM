# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Data tab of a link entry follows ``saip.show_file``'s ``link_source``.

A link entry (TCA SAIP V3.4.1 section 8.3.2 ``Fcp.linkPath``) shows the
source file's bytes under the source file's geometry, names that file in a
card, and a body write through it drops every cached view the backend
names. These checks read the canonical modular source; the bundle is
rebuilt from it.
"""

from __future__ import annotations

from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_SOURCE = _ROOT / "gui_frontend/src/js/saip-workbench.js"
_CSS = _ROOT / "gui_frontend/src/css/views/saip/applications-tab-cards.css"


def _function(body: str, name: str) -> str:
    start = body.index("function " + name + "(")
    end = body.index("\n  function ", start + 1)
    async_end = body.find("\n  async function ", start + 1)
    if async_end != -1:
        end = min(end, async_end)
    return body[start:end]


def test_data_tab_sizes_a_link_with_the_source_fcp_and_shows_the_source_card() -> None:
    body = _SOURCE.read_text(encoding="utf-8")
    render = _function(body, "saipFileRenderData")
    assert "var fcpForData = saipEffectiveFcpForData(data);" in render
    assert "saipBuildLinkSourceCard(data, pkg, peList, validation)" in render
    assert "saipFillPadLabel(data.fcp)" not in render
    assert render.count("saipFillPadLabel(fcpForData)") == 3
    # The entry's own template default does not apply to a resolved link.
    assert "if (showTemplateDefault && !linkSource) {" in render
    layout = _function(body, "saipFileRecordLayoutForData")
    assert "var fcp = saipEffectiveFcpForData(data);" in layout
    card = _function(body, "saipBuildLinkSourceCard")
    assert 'saipEditorCard(\n      "Linked file",' in card
    assert 'saipEditorKv(card, "Link path", saipFormatFidPath(link.link_path)' in card
    assert 'saipEditorKvNode(card, "Source file", jump);' in card
    assert "saip-link-source-card--unresolved" in card
    css = _CSS.read_text(encoding="utf-8")
    assert ".saip-link-source-card {" in css
    assert ".saip-link-source-card--unresolved {" in css


def test_body_writes_drop_every_view_the_backend_names() -> None:
    body = _SOURCE.read_text(encoding="utf-8")
    drop = _function(body, "saipDropLinkedFileCaches")
    assert "data.link_entry" in drop
    assert "data.link_aliases" in drop
    assert "if (key !== requestKey) delete pkg.showFileCache[key];" in drop
    for name in ("saipApplyFileContent", "saipApplyRecordEdit"):
        apply = _function(body, name)
        assert "saipDropLinkedFileCaches(pkg, data, fileKey);" in apply, name
