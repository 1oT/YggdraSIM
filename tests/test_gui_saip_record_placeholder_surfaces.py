# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Record surfaces read the substituted file image and write back through it.

Every record wizard and the record-scope hex card slice one file image.
That image used to be pySim's raw body with the template sentinels in
it, so a wizard decoded the dummy bytes while the whole-file pane showed
the stored value, and the record list stopped at pySim's record count.
The image is now the one the hex pane shows, the list follows the
layout, a record Apply stores a changed placeholder range as the
variable's value and puts the sentinel back before the record reaches
the backend, and the length bytes that follow a stored value ride along
with the placeholder ranges.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _js() -> str:
    return (STATIC / "app.js").read_text(encoding="utf-8")


def _function_source(body: str, start: str) -> str:
    begin = body.index(start)
    candidates = [
        body.find(marker, begin + len(start))
        for marker in ("\n  function ", "\n  async function ")
    ]
    ends = [index for index in candidates if index > 0]
    return body[begin : min(ends)] if ends else body[begin:]


def test_record_surfaces_read_the_shown_image() -> None:
    js = _js()
    render = _function_source(js, "  function saipFileRenderData(")
    assert "shownImageBytes = saipHexToByteArray(" in render
    assert "saipPlaceholderShownImage(efImageHex, filePlaceholders).hex" in render
    assert render.count("imageBytes: shownImageBytes,") == 2
    assert "imageBytes: image.bytes" not in render
    # The whole-file wizard keeps reading the same merged ranges.
    assert "var wizardPlaceholders = filePlaceholders;" in render
    assert "? saipPlaceholderShownImage(efImageHex, wizardPlaceholders).hex" in render
    # The navigator threads the write-back context into each record block.
    navigator = _function_source(js, "  function saipBuildRecordNavigator(")
    assert "imageHex: opts.imageHex," in navigator
    assert "placeholders: opts.placeholders," in navigator


def test_record_list_follows_the_layout() -> None:
    js = _js()
    extend = _function_source(js, "  function saipExtendRecordRowsToLayout(")
    assert "layout.recordCount > rows.length" in extend
    assert 'summary: allFf ? "Unallocated record slot -- FF padding." : ""' in extend
    assert "saipExtendRecordRowsToLayout(backendRecords, shownImageBytes, layout)" in js
    assert "saipSynthesizeRecordRowsFromLayout(shownImageBytes, layout)" in js


def test_record_writes_go_through_the_placeholder_guard() -> None:
    js = _js()
    guard = _function_source(js, "  async function saipApplyRecordEditOverPlaceholders(")
    assert "saipSetVariableValue(opts.pkg, name, after)" in guard
    assert "imageHex.slice(startNibble, endNibble)" in guard
    assert "spans a record boundary" in guard
    assert 'if (entry.kind === "length_field") {' in guard
    assert "next = next + rawRecord.slice(next.length)" in guard
    assert js.count("saipApplyRecordEditOverPlaceholders(opts, opts.recordIndex, ") == 2
    assert "saipApplyRecordEditOverPlaceholders(opts, recordNumber, raw)" in js
    for start in ("  function saipBuildRecordBlock(", "  function saipBuildRecordHexCard("):
        source = _function_source(js, start).replace("saipApplyRecordEditOverPlaceholders(", "")
        assert "saipApplyRecordEdit(" not in source, start


def test_length_fields_ride_with_the_placeholders() -> None:
    js = _js()
    assert "filePlaceholders = filePlaceholders.concat(data.inline_length_fields);" in js
    row = _function_source(js, "  function saipRenderLengthFieldRow(")
    assert '"Length byte"' in row
    assert "The template keeps " in row
    assert (
        'if (entry && entry.kind === "length_field") return saipRenderLengthFieldRow(entry);'
        in js
    )
    restore = _function_source(js, "  function saipRestorePlaceholderSentinels(")
    assert 'entry.kind === "length_field"' in restore
    wizard = _function_source(js, "  async function saipApplyWizardHexOverPlaceholders(")
    assert 'if (entry.kind === "length_field") {' in wizard
    card = _function_source(js, "  function saipBuildRawBytesCard(")
    assert "(the template keeps " in card
    assert '"inline_length_fields",' in js
