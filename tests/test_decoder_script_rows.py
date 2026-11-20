# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Several commands at once in the context decoder: a script of one command per row, and exchanges.

A script file is what the SCP03 shell's RUN and the SCP80 shell's ``script``
read: rows that start with ``#`` are comments, a row of hex is one APDU. The
decoder has to give the same commands as those runners, keep reading a trace
of commands and answers as before, and say which rows it left unread without
ever quoting one.
"""
from __future__ import annotations

import json

import pytest

from Tools.Asn1TlvDecode.context import DecodeError, _unread_rows_note, decode_context_text, parse_exchanges

SELECT_USIM = "00A4040007A0000000871002"
SELECT_IMSI = "00A40004026F07"
READ_IMSI = "00B0000009"
# EF.IMSI of the default test USIM with its status word.
IMSI_ANSWER = "0809101000000000109000"

SCRIPT = "\n".join([
    "# Select the USIM, then EF.IMSI, and read it",
    SELECT_USIM,
    "",
    SELECT_IMSI + "   # EF.IMSI",
    "00 B0 00 00 09",
])


def _commands(result: dict) -> list[str]:
    return [str((exchange.get("command") or {}).get("hex")) for exchange in result["exchanges"]]


def _shape(result: dict) -> list[tuple]:
    """Per exchange: the command, the answer data and the status word."""
    out = []
    for exchange in result["exchanges"]:
        response = exchange.get("response") or {}
        out.append(((exchange.get("command") or {}).get("hex"), response.get("dataHex"), (response.get("sw") or {}).get("sw")))
    return out


# ----------------------------------------------------------------------
# One command per row
# ----------------------------------------------------------------------


def test_one_command_per_row_is_that_many_commands() -> None:
    out = decode_context_text(SCRIPT)
    assert out["inputKind"] == "trace" and out["exchangeCount"] == 3 and out["context"]["label"] == "3 commands"
    assert _commands(out) == [SELECT_USIM, SELECT_IMSI, READ_IMSI]
    assert [exchange["command"]["name"] for exchange in out["exchanges"]] == ["SELECT FILE", "SELECT FILE", "READ BINARY"]
    assert all("response" not in exchange for exchange in out["exchanges"])
    # Where each command stands in the input: the comment and the empty row are counted.
    assert [exchange["row"] for exchange in out["exchanges"]] == [2, 4, 5]
    assert "inputNotes" not in out
    # A file saved on Windows: a byte order mark and CRLF cost no row.
    windows = "\ufeff" + SCRIPT.replace("\n", "\r\n") + "\r\n"
    assert _commands(decode_context_text(windows)) == _commands(out)
    # One command alone reads as it always did, without a row number.
    single = decode_context_text(SELECT_IMSI)
    assert single["inputKind"] == "apdu" and "row" not in single["exchanges"][0]


@pytest.mark.parametrize("ota", [False, True])
def test_the_install_script_reads_as_the_shells_run_it(tmp_path, ota: bool) -> None:
    """The script the CAP install wizard writes gives the decoder the commands it gives RUN and ``script``."""
    from SCP03.core import install_script
    from SCP03.core.cap import CapFileParser
    from SCP80.cli import OtaShell
    from test_scp03_wizard_apdu_builders import _write_ijc

    ijc = _write_ijc(tmp_path, bytes.fromhex("F000000001"), bytes.fromhex("F00000000101"), method_payload=bytes(range(256)) * 3)
    plan = install_script.plan_install_sequence(
        CapFileParser.parse_with_metadata(str(ijc)),
        applet_aid_hex="F00000000101",
        module_aid_hex="F00000000101",
        privileges_hex="00",
        install_params_hex="C900",
        ota=ota,
        cipher_mode="AES",
    )
    lines = install_script.render_install_script(plan, str(ijc))
    out = decode_context_text("\n".join(lines) + "\n")
    runner = [row for row in (OtaShell._normalize_script_hex_line(line) for line in lines) if row]
    assert len(runner) > 5
    assert _commands(out) == [row.upper() for row in runner] == [apdu.upper() for apdu in plan.apdus]
    names = [exchange["command"]["name"] for exchange in out["exchanges"]]
    assert names[0] == "INSTALL" and names[-1] == "INSTALL" and set(names[1:-1]) == {"LOAD"}
    assert all("response" not in exchange for exchange in out["exchanges"]) and "inputNotes" not in out


def test_a_comment_after_the_hex_is_the_decoders_and_the_ota_shells() -> None:
    """Both runners skip a row that starts with ``#``; only the SCP80 one drops a comment after the hex."""
    from SCP03.interface.shell import ShellDispatcher
    from SCP80.cli import OtaShell

    row = READ_IMSI + "   # nine bytes"
    assert _commands(decode_context_text(f"{SELECT_IMSI}\n{row}")) == [SELECT_IMSI, READ_IMSI]
    assert OtaShell._normalize_script_hex_line(row) == READ_IMSI
    # RUN in the SCP03 shell hands the whole row to its command line, where it is no APDU: the guides
    # therefore show a script with comments on rows of their own.
    assert ShellDispatcher._parse_manual_apdu_line(row) is None
    assert ShellDispatcher._parse_manual_apdu_line(READ_IMSI) == bytes.fromhex(READ_IMSI)


def test_a_long_input_is_decoded_up_to_a_limit_and_says_so() -> None:
    text = "\n".join([SELECT_IMSI, READ_IMSI] * 30)
    out = decode_context_text(text, max_exchanges=10)
    assert out["exchangeCount"] == 10 and len(out["exchanges"]) == 10 and out["inputExchanges"] == 60
    assert out["context"]["label"] == "10 of 60 commands"
    assert out["inputNotes"] == ["The input holds 60 commands; the first 10 are decoded here. Send the rest in parts."]
    whole = decode_context_text(text, max_exchanges=60)
    assert whole["exchangeCount"] == 60 and "inputExchanges" not in whole and "inputNotes" not in whole
    # The panel's action sets the limit; the command line has none.
    from yggdrasim_common.gui_server.actions import tools

    rows = "\n".join([READ_IMSI] * (tools.CONTEXT_DECODE_PANEL_EXCHANGES + 5))
    panel = tools._dispatch_context_decode(None, input_text=rows, context="auto")
    assert panel["exchangeCount"] == tools.CONTEXT_DECODE_PANEL_EXCHANGES
    assert panel["inputExchanges"] == tools.CONTEXT_DECODE_PANEL_EXCHANGES + 5
    assert decode_context_text(rows)["exchangeCount"] == tools.CONTEXT_DECODE_PANEL_EXCHANGES + 5


# ----------------------------------------------------------------------
# Commands and answers
# ----------------------------------------------------------------------


def test_exchanges_keep_reading_as_commands_and_answers() -> None:
    plain = decode_context_text(f"{SELECT_IMSI}\n9000\n{READ_IMSI}\n{IMSI_ANSWER}")
    marked = decode_context_text(f"> {SELECT_IMSI}\n< 9000\n> {READ_IMSI}\n< {IMSI_ANSWER}")
    expected = [(SELECT_IMSI, None, "9000"), (READ_IMSI, "080910100000000010", "9000")]
    assert _shape(plain) == _shape(marked) == expected
    assert [exchange["row"] for exchange in plain["exchanges"]] == [1, 3] and plain["context"]["label"] == "2 exchanges"
    assert plain["exchanges"][1]["response"]["payload"]["title"] == "EF 6F07 content"
    # A row of no known instruction is the answer to the command above it.
    assert _shape(decode_context_text("00B0000003\n0102039000")) == [("00B0000003", "010203", "9000")]
    # A command without its answer, then one with: each row falls where it belongs.
    mixed = decode_context_text(f"{SELECT_IMSI}\n{READ_IMSI}\n{IMSI_ANSWER}")
    assert _shape(mixed) == [(SELECT_IMSI, None, None), (READ_IMSI, "080910100000000010", "9000")]
    # A command and its answer may share a row, parted by a bar, a semicolon or a tab; a space parts nothing.
    for separator in (" | ", " ; ", "\t"):
        shared = decode_context_text(f"{SELECT_IMSI}{separator}9000\n{READ_IMSI}{separator}{IMSI_ANSWER}")
        assert _shape(shared) == expected, separator
    # A marker says what a row is, whatever its bytes look like.
    forced = decode_context_text(f"> {SELECT_IMSI}\n< {READ_IMSI}")
    assert _shape(forced) == [(SELECT_IMSI, "00B000", "0009")]


def test_an_explicit_context_is_taken_at_face_value() -> None:
    rows = f"{SELECT_IMSI}\n0102039000"
    assert _shape(decode_context_text(rows)) == [(SELECT_IMSI, "010203", "9000")]
    # Command APDU: every row is a command, also one of an instruction the decoder does not know.
    assert _commands(decode_context_text(rows, hint="apdu")) == [SELECT_IMSI, "0102039000"]
    # Response: every row is an answer.
    assert _shape(decode_context_text(rows, hint="response")) == [(None, "00A4000402", "6F07"), (None, "010203", "9000")]
    # Two bytes are no command (TS 102 221 v18.4 section 10.1.0, Table 10.2: case 1 is four): under Command APDU
    # they stay a status word.
    assert _shape(decode_context_text(f"{SELECT_IMSI}\n9000", hint="apdu")) == [(SELECT_IMSI, None, "9000")]
    # A marked row keeps its marker under either context.
    assert _shape(decode_context_text(f"> {READ_IMSI}\n< {IMSI_ANSWER}", hint="apdu")) == [(READ_IMSI, "080910100000000010", "9000")]


def test_a_miswritten_command_is_shown_as_a_command() -> None:
    """A row that opens like a known command and cannot be an answer is no answer to the row above."""
    wrong = "80E60C001905F00000000106F0000000010106F0000000010101000002C90000"
    out = decode_context_text(f"80E80000050102030405\n{wrong}\n80E8800105060708090A")
    assert [bool(exchange.get("response")) for exchange in out["exchanges"]] == [False, False, False]
    assert "extra bytes" in out["exchanges"][1]["command"]["error"]
    assert out["exchanges"][2]["command"]["name"] == "LOAD"
    # An answer written without its status word, as one whole TLV, stays the answer.
    fetched = decode_context_text("8012000010\nD00E810301250082028182050353544B")
    assert _commands(fetched) == ["8012000010"] and "response" in fetched["exchanges"][0]


def test_a_status_word_written_on_the_row() -> None:
    assert _shape(decode_context_text(f"{READ_IMSI} sw=9000")) == [(READ_IMSI, None, "9000")]
    assert _shape(decode_context_text("< 080910100000000010 sw=9000")) == [(None, "080910100000000010", "9000")]
    # The line of the GUI event log: command, answer, status word and duration between middle dots.
    logged = decode_context_text(f"\u2192 {READ_IMSI} \u00b7 \u2190 080910100000000010 \u00b7 sw=9000 \u00b7 1.42 ms")
    assert _shape(logged) == [(READ_IMSI, "080910100000000010", "9000")]
    silent = parse_exchanges("\u2192 00A4000C023F00 \u00b7 \u2190 \u00b7 sw=9000 \u00b7 1.42 ms")
    assert len(silent) == 1 and silent[0].sw == b"\x90\x00" and silent[0].response is None


def test_the_raw_lines_of_the_scp11_transport_are_read(monkeypatch, capsys) -> None:
    """``[label] > command`` and ``[label] < SW: .. Data: ..``, printed here by the transport itself."""
    import SCP11.transport as transport

    monkeypatch.setattr(transport, "_APDU_TRACE_RENDERER", None)
    transport._print_apdu_exchange("ES10b.GetEUICCInfo", bytes.fromhex("81E2910006BF2E035C0181"), bytes.fromhex("BF2E035A0189"), 0x90, 0x00, raw=True)
    transport._print_apdu_exchange("[eIM] ES10b.LoadBoundProfilePackage [Block 2]", bytes.fromhex("81E2910003BF2D00"), b"", 0x69, 0x85, raw=True)
    printed = capsys.readouterr().out
    assert "] > 81E2910006BF2E035C0181" in printed and "< SW: 9000 Data: BF2E035A0189" in printed
    out = decode_context_text(printed)
    assert _shape(out) == [("81E2910006BF2E035C0181", "BF2E035A0189", "9000"), ("81E2910003BF2D00", None, "6985")]
    assert "inputNotes" not in out


# ----------------------------------------------------------------------
# Rows that hold no hex
# ----------------------------------------------------------------------


def test_rows_that_hold_no_hex_are_counted_and_never_quoted() -> None:
    text = "\n".join([
        "SELECT 3F00",
        SELECT_IMSI,
        "VERIFY 31323334",
        "",
        "AUTH KEY 404142434445464748494A4B4C4D4E4F",
        READ_IMSI,
    ])
    out = decode_context_text(text)
    assert _commands(out) == [SELECT_IMSI, READ_IMSI]
    assert [exchange["row"] for exchange in out["exchanges"]] == [2, 6]
    assert out["inputNotes"] == ["3 rows held no hex and were left unread: rows 1, 3, 5."]
    assert out["notation"].splitlines()[-1] == "note: 3 rows held no hex and were left unread: rows 1, 3, 5."
    # A shell verb row is not mined for hex: no status word '3F00', and nothing of an unread row comes back.
    answer = json.dumps(out)
    for part in ("3F00", "31323334", "404142434445464748494A4B4C4D4E4F", "VERIFY", "AUTH KEY"):
        assert part not in answer, part
    one = decode_context_text(f"SELECT 3F00\n{SELECT_IMSI}")
    assert one["inputKind"] == "apdu" and one["inputNotes"] == ["1 row held no hex and was left unread: row 1."]
    assert one["notation"].splitlines()[-1].startswith("note: 1 row held no hex")
    # Runs of rows are given as ranges, and a long list is cut.
    assert _unread_rows_note([1, 2, 3, 5, 9, 10]) == "6 rows held no hex and were left unread: rows 1-3, 5, 9-10."
    assert _unread_rows_note(list(range(1, 60, 2))).endswith("rows 1, 3, 5, 7, 9, 11, 13, 15, 17, 19, 21, 23 and 18 more.")
    # With no hex row at all the input is refused as before.
    with pytest.raises(DecodeError):
        decode_context_text("SELECT 3F00\nAUTH")


# ----------------------------------------------------------------------
# Trace state when commands have no answers
# ----------------------------------------------------------------------


def test_trace_state_holds_without_answers() -> None:
    # Segmented STORE DATA: the blocks are joined although no row answers them.
    segmented = decode_context_text("80E2110003BF3E03\n80E29101035C015A")
    assert segmented["exchanges"][0]["command"]["payload"]["title"].startswith("ES10 request block")
    assert segmented["exchanges"][1]["command"]["payload"]["title"] == "GetEuiccDataRequest"
    # GET RESPONSE completes the command right before it (TS 102 221 v18.4 section 12.1.1.1) ...
    chained = decode_context_text(f"> {SELECT_IMSI}\n< 611E\n00C000001E")
    assert chained["exchanges"][1]["command"]["continues"] == "SELECT FILE"
    # ... and a command in between, answered or not, ends the chain.
    broken = decode_context_text(f"> {SELECT_IMSI}\n< 611E\n{READ_IMSI}\n00C000001E")
    assert [exchange["command"]["name"] for exchange in broken["exchanges"]] == ["SELECT FILE", "READ BINARY", "GET RESPONSE"]
    assert "continues" not in broken["exchanges"][2]["command"]


# ----------------------------------------------------------------------
# The command line and the MCP tool
# ----------------------------------------------------------------------


def test_the_command_line_reads_a_script_file(tmp_path) -> None:
    import io

    from Tools.Asn1TlvDecode.main import run_cli

    def run(path) -> str:
        out = io.StringIO()
        assert run_cli(["--context", "--color", "never", "--file", str(path)], stdout=out, stderr=io.StringIO()) == 0
        return out.getvalue()

    windows = "\r\n".join(SCRIPT.splitlines()) + "\r\n"
    utf8 = tmp_path / "script-utf8.txt"
    utf8.write_bytes(b"\xef\xbb\xbf" + windows.encode("utf-8"))
    utf16 = tmp_path / "script-utf16.txt"
    utf16.write_bytes(windows.encode("utf-16"))
    for path in (utf8, utf16):
        printed = run(path)
        assert [line.split(" [")[0] for line in printed.splitlines() if line.startswith("#")] == ["#1 SELECT FILE", "#2 SELECT FILE", "#3 READ BINARY"]


def test_a_long_mcp_answer_is_cut_at_whole_exchanges() -> None:
    server = pytest.importorskip("Tools.YggdraMCP.server")
    tool = getattr(server.context_decode, "fn", server.context_decode)
    short = json.loads(tool(SCRIPT))
    assert short["exchangeCount"] == 3 and "exchanges" in short and "truncated" not in short
    rows = "\n".join("80E800" + f"{index & 0xFF:02X}" + "5D" + f"{index & 0xFF:02X}" * 93 for index in range(120))
    answer = tool(rows)
    assert len(answer) < server._CONTEXT_ANSWER_LIMIT + 2000
    cut = json.loads(answer)
    assert cut["exchangeCount"] == 120 and 0 < cut["shownExchanges"] < 120 and "exchanges" not in cut
    assert f"exchanges 1 to {cut['shownExchanges']} of 120" in cut["truncated"]
    # Past what any answer can show, the rows are counted and not decoded.
    many = json.loads(tool("\n".join([READ_IMSI] * (server._CONTEXT_ANSWER_EXCHANGES + 50))))
    assert many["exchangeCount"] == server._CONTEXT_ANSWER_EXCHANGES
    assert many["inputExchanges"] == server._CONTEXT_ANSWER_EXCHANGES + 50
    assert f"of {server._CONTEXT_ANSWER_EXCHANGES + 50}" in many["truncated"]
    shown = [line for line in cut["notation"].splitlines() if line.startswith("#")]
    assert len(shown) == cut["shownExchanges"] and shown[0].startswith("#1 LOAD") and shown[-1].startswith(f"#{cut['shownExchanges']} LOAD")


# ----------------------------------------------------------------------
# The panel: a file read in the page, and how a script is counted
# ----------------------------------------------------------------------

_PAGE_HARNESS = r"""
%s
%s
var script = "# x\r\n00A40004026F07\r\n";
var le = Buffer.from(script, "utf16le");
var be = Buffer.from(le);
be.swap16();
function read(buffer) { return ccDecodeTextFile(new Uint8Array(buffer)); }
var command = { command: {} };
console.log(JSON.stringify({
  utf8: read(Buffer.concat([Buffer.from([0xEF, 0xBB, 0xBF]), Buffer.from(script, "utf8")])),
  plain: read(Buffer.from(script, "utf8")),
  utf16le: read(Buffer.concat([Buffer.from([0xFF, 0xFE]), le])),
  utf16be: read(Buffer.concat([Buffer.from([0xFE, 0xFF]), be])),
  binary: read(Buffer.from([0x00, 0x01, 0x02, 0x00])),
  expected: script,
  script: _decoderSummaryText({ inputKind: "trace", exchangeCount: 3, domains: ["uicc"], exchanges: [command, command, command] }),
  trace: _decoderSummaryText({ inputKind: "trace", exchangeCount: 2, domains: ["uicc"], exchanges: [{ command: {}, response: {} }, command] }),
  held: _decoderSummaryText({ inputKind: "trace", exchangeCount: 2, inputExchanges: 95000, domains: ["uicc"], exchanges: [command, command] }),
}));
"""


def _page_function(source: str, name: str) -> str:
    """One function of the page, from its header to the brace that closes it at the same indent."""
    start = source.index(f"  function {name}(")
    return source[start:source.index("\n  }\n", start) + len("\n  }\n")]


def test_the_page_reads_a_file_as_text_and_counts_a_script_as_commands() -> None:
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    source = (Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
    script = _PAGE_HARNESS % (_page_function(source, "ccDecodeTextFile"), _page_function(source, "_decoderSummaryText"))
    done = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    page = json.loads(done.stdout)
    # UTF-8 with or without a byte order mark, and UTF-16 either way round, give the same text; a binary file gives none.
    assert page["utf8"] == page["plain"] == page["utf16le"] == page["utf16be"] == page["expected"]
    assert page["binary"] is None
    # No row has an answer: the summary counts commands, not exchanges.
    assert page["script"].startswith("3 commands") and page["trace"].startswith("2 exchanges")
    assert page["held"].startswith("2 of 95000 commands")
    # The file never leaves the page as a path: the button reads it and fills the box.
    assert "file.arrayBuffer()" in source and "input_text: text" in source
    # A drop goes through the page's drop helper, which the stray-drop guard and the desktop window need.
    assert "enablePanelFileDrop(input, function ()" in source
