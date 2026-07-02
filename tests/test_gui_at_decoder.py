# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Coverage for ``yggdrasim_common.gui_server.at_decoder``.

Verifies:

* :class:`LineAccumulator` correctly buffers byte streams, splits on
  CR/LF boundaries, strips ANSI control sequences, and respects the
  buffer-overflow + line-length safety caps.
* :func:`decode_line` recognises every AT shape we promise on the
  Host shell view: ``AT+CSIM=`` request, ``+CSIM:`` response,
  ``AT+CRSM=`` request (with and without trailing data / path),
  ``+CRSM:`` response (with and without payload), and rejects
  malformed lines without raising.
* :func:`feed_and_decode` integrates the two and emits one entry per
  recognisable line.
"""

from __future__ import annotations

import json

import pytest

from yggdrasim_common.gui_server import at_decoder


# ---------------------------------------------------------------------------
# LineAccumulator
# ---------------------------------------------------------------------------


def test_accumulator_splits_on_lf():
    acc = at_decoder.LineAccumulator()
    out = list(acc.feed(b"foo\nbar\n"))
    assert out == ["foo", "bar"]


def test_accumulator_strips_trailing_cr():
    acc = at_decoder.LineAccumulator()
    out = list(acc.feed(b"hello\r\nworld\r\n"))
    assert out == ["hello", "world"]


def test_accumulator_buffers_partial_lines():
    acc = at_decoder.LineAccumulator()
    assert list(acc.feed(b"AT+CS")) == []
    assert list(acc.feed(b"IM=14,\"00A40004023F00\"\r\n")) == [
        'AT+CSIM=14,"00A40004023F00"'
    ]


def test_accumulator_strips_ansi_csi():
    acc = at_decoder.LineAccumulator()
    raw = b"\x1b[1;31mAT+CSIM=14,\"00A40004023F00\"\x1b[0m\r\n"
    out = list(acc.feed(raw))
    assert out == ['AT+CSIM=14,"00A40004023F00"']


def test_accumulator_drops_overflow_silently():
    acc = at_decoder.LineAccumulator(buffer_limit=64)
    huge = b"A" * 200
    out = list(acc.feed(huge))
    assert out == []
    assert acc.dropped_overflow_count == 1


def test_accumulator_long_line_flushed_at_cap():
    acc = at_decoder.LineAccumulator(buffer_limit=8192, line_max=64)
    raw = b"X" * 80
    out = list(acc.feed(raw))
    assert out == ["X" * 80]


# ---------------------------------------------------------------------------
# decode_line — request shapes
# ---------------------------------------------------------------------------


def test_decode_csim_request_select_mf():
    entry = at_decoder.decode_line('AT+CSIM=14,"00A40004023F00"', "tx")
    assert entry is not None
    assert entry["kind"] == "csim_request"
    assert entry["direction"] == "tx"
    decoded = entry["decoded"]
    assert decoded["apdu_hex"] == "00A40004023F00"
    assert decoded["cla_hex"] == "00"
    assert decoded["ins_hex"] == "A4"
    assert decoded["ins_label"] == "SELECT"
    assert decoded["lc"] == 2
    assert decoded["data_hex"] == "3F00"


def test_decode_csim_request_case2_no_data():
    entry = at_decoder.decode_line('AT+CSIM=10,"00C0000010"', "tx")
    assert entry is not None
    assert entry["kind"] == "csim_request"
    decoded = entry["decoded"]
    assert decoded["case"] == "Case 2"
    assert decoded["le"] == 0x10
    assert decoded["data_hex"] == ""


def test_decode_csim_request_rejects_length_mismatch():
    # length declares 14 hex chars but the body has 12 — at_simlink
    # will reject it, so the decoder must too.
    entry = at_decoder.decode_line('AT+CSIM=14,"00A4000400"', "tx")
    assert entry is None


def test_decode_crsm_request_with_select_path():
    entry = at_decoder.decode_line(
        'AT+CRSM=176,12258,0,0,16,"","3F007FFF"', "tx"
    )
    assert entry is not None
    assert entry["kind"] == "crsm_request"
    decoded = entry["decoded"]
    assert decoded["command_id"] == 176
    assert decoded["command_label"] == "READ BINARY"
    assert decoded["select_path_hex"] == "3F007FFF"
    assert decoded["p3"] == 16


def test_decode_crsm_request_minimal():
    entry = at_decoder.decode_line('AT+CRSM=242,28423,0,0,0', "tx")
    assert entry is not None
    decoded = entry["decoded"]
    assert decoded["command_id"] == 242
    assert decoded["command_label"] == "STATUS"
    assert decoded["data_hex"] == ""


def test_decode_crsm_request_rejects_unknown_command():
    entry = at_decoder.decode_line('AT+CRSM=999,12258,0,0,16', "tx")
    assert entry is None


# ---------------------------------------------------------------------------
# decode_line — response shapes
# ---------------------------------------------------------------------------


def test_decode_csim_response_with_payload():
    entry = at_decoder.decode_line('+CSIM: 8,"610A9000"', "rx")
    assert entry is not None
    assert entry["kind"] == "csim_response"
    decoded = entry["decoded"]
    assert decoded["sw1_hex"] == "90"
    assert decoded["sw2_hex"] == "00"
    assert decoded["data_hex"] == "610A"
    assert "Success" in decoded["sw_meaning"]


def test_decode_csim_response_status_word_only():
    entry = at_decoder.decode_line('+CSIM: 4,"9000"', "rx")
    assert entry is not None
    decoded = entry["decoded"]
    assert decoded["data_hex"] == ""
    assert decoded["sw1_hex"] == "90"
    assert decoded["sw2_hex"] == "00"


def test_decode_csim_response_rejects_length_mismatch():
    entry = at_decoder.decode_line('+CSIM: 8,"9000"', "rx")
    assert entry is None


def test_decode_crsm_response_no_payload():
    entry = at_decoder.decode_line('+CRSM: 144,0', "rx")
    assert entry is not None
    decoded = entry["decoded"]
    assert decoded["sw1_hex"] == "90"
    assert decoded["sw2_hex"] == "00"
    assert decoded["data_hex"] == ""


def test_decode_crsm_response_with_payload():
    entry = at_decoder.decode_line('+CRSM: 144,0,"FF40FF"', "rx")
    assert entry is not None
    decoded = entry["decoded"]
    assert decoded["data_hex"] == "FF40FF"
    assert decoded["sw_meaning"] != ""


def test_decode_unknown_line_returns_none():
    assert at_decoder.decode_line("OK", "rx") is None
    assert at_decoder.decode_line("ERROR", "rx") is None
    assert at_decoder.decode_line("", "rx") is None


# ---------------------------------------------------------------------------
# feed_and_decode — integration
# ---------------------------------------------------------------------------


def test_feed_and_decode_pipes_request_then_response():
    acc = at_decoder.LineAccumulator()
    chunk = (
        b'AT+CSIM=14,"00A40004023F00"\r\n'
        b'+CSIM: 4,"9000"\r\n'
        b'OK\r\n'
    )
    entries = list(at_decoder.feed_and_decode(acc, chunk, "rx"))
    kinds = [entry["kind"] for entry in entries]
    assert kinds == ["csim_request", "csim_response"]


def test_feed_and_decode_serialisable():
    """Every entry must round-trip through json.dumps for WS framing."""
    acc = at_decoder.LineAccumulator()
    chunk = (
        b'AT+CSIM=14,"00A40004023F00"\r\n'
        b'+CSIM: 4,"9000"\r\n'
    )
    for entry in at_decoder.feed_and_decode(acc, chunk, "tx"):
        json.dumps(entry)
