# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the restructured ``scp03.get_sgp32_all_data`` dispatcher.

Before this change the dispatcher simply captured ``get_sgp32_all_data``'s
``print(...)`` output into a single ``trace`` string. The GUI then dumped
that blob into a green-on-black ``<pre>``, which — per the user's feedback
— still "only outputs in terminal".

The dispatcher now emits a **structured** ``sections`` array (one entry
per ES10 retrieval: scan / RAT / notifications / eIM config / certs) so
the GUI can render each step as its own titled card with KV rows, a raw
hex viewer and a collapsible trace. These tests pin the contract.

The tests are dependency-free on purpose: no PC/SC, no pySim, no
``TlvParser`` internals — they exercise the pure helpers that shape the
dispatcher response.
"""

from __future__ import annotations

from typing import Any


def _load_helpers():
    # Lazy import so collection doesn't pull in the heavy GP/SCP03 stack.
    from yggdrasim_common.gui_server.actions.scp03 import (
        _sgp32_bulk_trace_lines,
        _sgp32_run_section,
    )

    return _sgp32_bulk_trace_lines, _sgp32_run_section


# ----------------------------------------------------------------------
# _sgp32_bulk_trace_lines — stdout -> clean line list normaliser
# ----------------------------------------------------------------------


def test_trace_line_normaliser_strips_ansi_and_trailing_spaces():
    trace_lines, _ = _load_helpers()
    raw = "\x1b[95m=== Header ===\x1b[0m\n\x1b[1m[+] Step\x1b[0m   \n"
    out = trace_lines(raw)
    assert out == ["=== Header ===", "[+] Step"]


def test_trace_line_normaliser_collapses_blank_runs():
    trace_lines, _ = _load_helpers()
    raw = "line1\n\n\n\nline2\n\n\n"
    out = trace_lines(raw)
    # One blank separator between paragraphs, no trailing blanks.
    assert out == ["line1", "", "line2"]


def test_trace_line_normaliser_handles_empty_and_none():
    trace_lines, _ = _load_helpers()
    assert trace_lines("") == []
    assert trace_lines(None) == []


# ----------------------------------------------------------------------
# _sgp32_run_section — per-section runner
# ----------------------------------------------------------------------


class _FakeSgp22Ok:
    """Minimal fake that returns non-empty bytes + emits compact output."""

    def __init__(self) -> None:
        self.called_tag: str | None = None
        self.printer_calls: list[tuple[str, Any]] = []

    def _es10_retrieve_data(self, tag: str) -> bytes:
        self.called_tag = tag
        return bytes.fromhex("BF430401020304")

    def _print_rat_compact_response(self, response: bytes) -> None:
        self.printer_calls.append(("rat", response))
        print("[+] GetRAT (Rules Authorisation Table)")
        print("    | Accepted CI: 01020304")


class _FakeSgp22Empty:
    """Returns empty bytes -> section must mark itself as ``empty``."""

    def _es10_retrieve_data(self, tag: str) -> bytes:
        return b""

    def _print_rat_compact_response(self, response: bytes) -> None:  # noqa: D401
        raise AssertionError("printer should not run on empty responses")


class _FakeSgp22Error:
    """Retrieve raises -> section must mark itself as ``error``."""

    def _es10_retrieve_data(self, tag: str) -> bytes:
        raise RuntimeError("transport broke while reading " + tag)


class _FakeSgp22PrinterCrash:
    """Retrieve succeeds but the printer blows up mid-format.

    Contract: section still reports ``ok`` (we got the bytes) but the
    ``note`` surfaces the printer failure so we don't silently drop
    diagnostic data on the floor.
    """

    def _es10_retrieve_data(self, tag: str) -> bytes:
        return bytes.fromhex("BF2B020100")

    def _print_notifications_list_compact(self, parsed: Any) -> None:  # noqa: D401
        raise ValueError("printer blew up")


def test_section_runner_ok_path_captures_hex_and_printer_output():
    _, run_section = _load_helpers()
    fake = _FakeSgp22Ok()

    section = run_section(
        fake,
        key="rat",
        title="GetRAT",
        es10_tag="BF4300",
        printer_name="_print_rat_compact_response",
        parser_mode="response",
    )

    assert fake.called_tag == "BF4300"
    assert section["status"] == "ok"
    assert section["key"] == "rat"
    assert section["title"] == "GetRAT"
    assert section["es10_tag"] == "BF4300"
    assert section["hex"] == "BF430401020304"
    assert "GetRAT" in section["trace"]
    assert section["lines"] == [
        "[+] GetRAT (Rules Authorisation Table)",
        "    | Accepted CI: 01020304",
    ]
    assert section["note"] == ""


def test_section_runner_empty_body_marks_section_empty():
    _, run_section = _load_helpers()
    fake = _FakeSgp22Empty()

    section = run_section(
        fake,
        key="rat",
        title="GetRAT",
        es10_tag="BF4300",
        printer_name="_print_rat_compact_response",
        parser_mode="response",
    )

    assert section["status"] == "empty"
    assert section["hex"] == ""
    assert section["lines"] == []
    assert "No data returned" in section["note"]


def test_section_runner_retrieve_exception_marks_section_error():
    _, run_section = _load_helpers()
    fake = _FakeSgp22Error()

    section = run_section(
        fake,
        key="rat",
        title="GetRAT",
        es10_tag="BF4300",
        printer_name="_print_rat_compact_response",
        parser_mode="response",
    )

    assert section["status"] == "error"
    assert "transport broke" in section["note"]
    assert section["hex"] == ""


def test_section_runner_printer_exception_keeps_hex_and_records_note():
    _, run_section = _load_helpers()
    fake = _FakeSgp22PrinterCrash()

    section = run_section(
        fake,
        key="notifications",
        title="RetrieveNotificationsList",
        es10_tag="BF2B00",
        printer_name="_print_notifications_list_compact",
        parser_mode="parsed",
    )

    # Retrieval itself succeeded — operators still need the raw hex
    # and the status must reflect "we got data, but rendering failed".
    assert section["status"] == "ok"
    assert section["hex"] == "BF2B020100"
    assert "printer" in section["note"]
    assert "blew up" in section["note"]


def test_section_runner_rejects_unknown_parser_mode():
    _, run_section = _load_helpers()
    fake = _FakeSgp22Ok()

    section = run_section(
        fake,
        key="rat",
        title="GetRAT",
        es10_tag="BF4300",
        printer_name="_print_rat_compact_response",
        parser_mode="nonsense",
    )

    # Unknown parser_mode raises inside the printer capture block —
    # handled as a printer-note while preserving the hex body.
    assert section["status"] == "ok"
    assert section["hex"] == "BF430401020304"
    assert "unknown parser_mode" in section["note"]
