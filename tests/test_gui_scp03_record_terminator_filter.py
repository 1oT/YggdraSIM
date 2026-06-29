# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression test for the SCP03 record terminator-sentinel filter.

Background
----------
``_read_file_body`` walks records 1..254 for linear-fixed / cyclic
files and, on the first non-``9000`` status word, appends a synthetic
record carrying ``ok=False`` + ``length=0`` + the terminating SW so
CLI / JSON consumers can audit *why* the walker stopped. The
``stop_reason`` field ("record_not_found" / "sw_6A86" / …) surfaces
the same information at the header level.

Operator feedback: "I also see that the 'end record scan' is
presented, let's not present these for the file system." — the
terminator sentinel appeared as an extra record row (``#2 · SW 6A83
· 0 B · EMPTY``) after the last real record, which read as noise
next to the genuine file content.

Fix: the file-system view filters terminator sentinels out before
rendering, while the action JSON still returns the full list
(preserving byte-level parity with CLI dumps). The header's
``records:`` count reflects the *displayed* count so the summary
no longer off-by-ones.

All tests are static-bundle contracts against ``app.js`` — the
filter is pure frontend JavaScript and doesn't touch the backend.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_terminator_helper_is_defined() -> None:
    """The sentinel detector must ship as a named helper so it can be
    reused (and unit-pinned) independently of the render function."""
    js = _read("app.js")
    assert "function scp03IsRecordTerminator(rec)" in js


def test_terminator_helper_accepts_zero_length_not_ok_records() -> None:
    """Contract pins: a record is a terminator iff ``ok === false`` AND
    ``length === 0``. A real record with ``ok === true`` is never a
    terminator regardless of other fields."""
    js = _read("app.js")
    block = js.split("function scp03IsRecordTerminator(rec)", 1)[1].split("function renderRecordsPayload")[0]
    # ``ok === true`` returns false early — guarantees real records pass through.
    assert "rec.ok === true" in block
    assert "return false" in block
    # Length gate so a weird real record with ``ok: false`` but non-zero
    # payload doesn't get swallowed silently.
    assert "Number(rec.length" in block
    assert "if (length > 0) return false" in block


def test_terminator_helper_matches_6axx_status_words() -> None:
    """ETSI TS 102 221 §10.1.2 returns ``6A83`` for record-not-found,
    ``6A82`` for file-not-found, ``6A86`` for wrong P1/P2. The walker
    treats any ``6A*`` with zero bytes as a loop epilogue."""
    js = _read("app.js")
    block = js.split("function scp03IsRecordTerminator(rec)", 1)[1].split("function renderRecordsPayload")[0]
    # Uppercase-safe SW comparison.
    assert 'String(rec.sw || "").toUpperCase()' in block
    assert '"6A"' in block


def test_render_records_applies_filter() -> None:
    """``renderRecordsPayload`` must filter the record list through the
    terminator detector before counting + rendering. Without the filter,
    the operator sees a phantom ``#2 · SW 6A83 · 0 B · EMPTY`` row that
    confused the original bug report."""
    js = _read("app.js")
    block = js.split("function renderRecordsPayload(payload)", 1)[1].split("function renderSingleRecord")[0]
    assert "rawRecords = payload.records" in block
    assert "displayRecords = rawRecords.filter" in block
    assert "scp03IsRecordTerminator(rec)" in block


def test_records_meta_counts_displayed_rows_not_raw() -> None:
    """The header chip ``records: N`` must reflect the filtered count so
    it matches what the operator actually sees in the list. Reading
    ``payload.record_count`` directly would be off-by-one whenever the
    walker appended a terminator."""
    js = _read("app.js")
    block = js.split("function renderRecordsPayload(payload)", 1)[1].split("function renderSingleRecord")[0]
    assert '"records: " + displayRecords.length' in block
    # ``non_empty_count`` stays — the backend never increments it for
    # terminator sentinels (they aren't ok:true records).
    assert 'non-empty: " + (payload.non_empty_count' in block


def test_empty_display_surfaces_stop_reason() -> None:
    """If the filter leaves zero records (e.g. the very first READ RECORD
    returned 6A83 so the file has no readable content), the UI must
    surface the stop reason rather than rendering a silent blank."""
    js = _read("app.js")
    block = js.split("function renderRecordsPayload(payload)", 1)[1].split("function renderSingleRecord")[0]
    # Empty-display branch must consult payload.stop_reason when raw
    # records existed but all were filtered out.
    assert "rawRecords.length > 0" in block
    assert 'no readable records (stop: "' in block


def test_non_empty_count_field_unchanged() -> None:
    """Sanity: the filter is UI-only. The backend ``non_empty_count``
    field is a pure ``ok: true`` counter and must stay authoritative
    for API consumers — we must not recompute it from the filtered
    frontend list and risk drift."""
    js = _read("app.js")
    block = js.split("function renderRecordsPayload(payload)", 1)[1].split("function renderSingleRecord")[0]
    # The non-empty chip reads from payload, never from displayRecords.
    assert "displayRecords.length" in block
    assert "non_empty_count" in block
    # Guard: we must not recompute non-empty from displayRecords — a
    # wrongly-rewired patch would change this line. The test pins the
    # fact that ``non_empty`` is still sourced from ``payload``.
    assert (
        'non-empty: " + (payload.non_empty_count' in block
    ), "non_empty_count must come from the backend payload, not the filtered list"
