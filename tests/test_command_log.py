# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Command logs: the --log flag parser, what a capture writes, and the shell helper."""
from __future__ import annotations

import io
import os
import re
import stat
import sys
import threading
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import pytest

from yggdrasim_common import command_log
from yggdrasim_common.command_log import (
    CommandLog,
    default_log_directory,
    log_flag_present,
    resolve_log_path,
    run_with_command_log,
    split_log_flag,
    split_words,
    strip_log_flag,
)
from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

# A body line is a block's first line behind its nesting margin and time stamp, or a
# continuation behind the margin and the stamp's width in blanks.
_STAMPED_RE = re.compile(r"^(?P<margin>(?:  )+)\d{2}:\d{2}:\d{2}\.\d{3}  (?P<text>\S.*)$")
_CONTINUED_RE = re.compile(r"^ {16,}\S")
_HEADER_RE = re.compile(r"^=== \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}  (?P<title>.*) ===$")
_TRAILER_RE = re.compile(r"^=== \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}  (?P<ending>.*) after \d+\.\d s ===$")


class _Terminal(io.StringIO):
    """A terminal stand-in: it says it is a tty and has a file descriptor."""

    def isatty(self) -> bool:
        return True

    def fileno(self) -> int:
        return 99


def _text(line: str) -> str:
    """A body line's text: margin and stamp off a block's first line, the blanks off a continuation."""
    if len(line) == 0:
        return ""
    stamped = _STAMPED_RE.match(line)
    if stamped is not None:
        return stamped.group("text")
    assert _CONTINUED_RE.match(line), line
    return line.strip()


def _indent(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _raw_body(path: Path) -> list[str]:
    """The lines between the header and the trailer, as written."""
    lines = path.read_text(encoding="utf-8").splitlines()
    assert _HEADER_RE.match(lines[0]), lines[0]
    assert _TRAILER_RE.match(lines[-1]), lines[-1]
    return lines[1:-1]


def _body(path: Path) -> list[str]:
    """The lines between the header and the trailer, margins and time stamps removed."""
    return [_text(line) for line in _raw_body(path)]


@pytest.fixture(autouse=True)
def _debug_flag_unset(monkeypatch):
    monkeypatch.delenv(GLOBAL_DEBUG_ENV, raising=False)


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("scan --log out.log --json", ("scan --json", "out.log")),
        ("scan --json --log=out.log", ("scan --json", "out.log")),
        ("--log out.log scan", ("scan", "out.log")),
        ('scan --log "my logs/out.log"', ("scan", "my logs/out.log")),
        ("scan --log='my logs/out.log'", ("scan", "my logs/out.log")),
        ("scan --LOG out.log", ("scan", "out.log")),
        (r"select --log C:\logs\out.log", ("select", r"C:\logs\out.log")),
        ('download "a  b" --log x.log', ('download "a  b"', "x.log")),
    ],
)
def test_the_flag_and_its_file_come_off_the_line(line: str, expected: tuple[str, str]) -> None:
    assert split_log_flag(line) == expected


@pytest.mark.parametrize(
    "line",
    [
        "scan --json",
        "  spaced   line  ",
        'store-data "--log" 80',
        "cmd --logfile x",
        "unbalanced 'quote --log x",
    ],
)
def test_a_line_without_the_flag_comes_back_unchanged(line: str) -> None:
    assert split_log_flag(line) == (line, "")


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("scan --log", "needs a file"),
        ("scan --log=", "needs a file"),
        ('scan --log ""', "needs a file"),
        ("scan --log --json", "not the option --json"),
        ("scan --log -d", "not the option -d"),
        ("scan --log a.log --log b.log", "given twice"),
    ],
)
def test_a_malformed_flag_is_refused(line: str, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        split_log_flag(line)


def test_strip_log_flag_never_raises_and_cuts_a_stray_flag() -> None:
    assert strip_log_flag("SELECT 3F00 --log x.log") == "SELECT 3F00"
    assert strip_log_flag("0020000108AABBCCDD --log") == "0020000108AABBCCDD"
    assert strip_log_flag("a --log x --log y") == "a"
    assert strip_log_flag("plain line") == "plain line"


def test_log_flag_present_counts_a_malformed_flag() -> None:
    assert log_flag_present("scan --log x") is True
    assert log_flag_present("scan --log") is True
    assert log_flag_present("scan --logx") is False
    assert log_flag_present('x "--log" y') is False


def test_split_words_groups_quotes_and_keeps_backslashes() -> None:
    assert split_words(r'START "C:\my logs\trace.log"') == ["START", r"C:\my logs\trace.log"]
    assert split_words("") == []


def test_a_relative_path_is_taken_from_the_working_directory(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert resolve_log_path("out/scan.log", label="scan") == tmp_path / "out" / "scan.log"


def test_a_home_relative_path_is_expanded(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    assert resolve_log_path("~/scan.log", label="scan") == tmp_path / "scan.log"


def test_a_directory_gets_a_file_named_after_the_label_and_time(tmp_path) -> None:
    moment = datetime(2026, 10, 14, 10, 22, 33)
    assert resolve_log_path(str(tmp_path), label="SCAN", now=moment) == (
        tmp_path / "scan-20261014-102233.log"
    )
    assert resolve_log_path(f"{tmp_path / 'new'}{os.sep}", label="scan", now=moment) == (
        tmp_path / "new" / "scan-20261014-102233.log"
    )


def test_no_path_names_the_default_log_directory(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(command_log, "runtime_root", lambda: str(tmp_path))
    moment = datetime(2026, 10, 14, 10, 22, 33)
    assert default_log_directory() == tmp_path / "reports" / "command_logs"
    assert resolve_log_path("", label="scp03-trace", now=moment) == (
        tmp_path / "reports" / "command_logs" / "scp03-trace-20261014-102233.log"
    )


def test_a_capture_copies_the_terminal_text_without_escapes(tmp_path, monkeypatch) -> None:
    terminal = _Terminal()
    errors = _Terminal()
    monkeypatch.setattr(sys, "stdout", terminal)
    monkeypatch.setattr(sys, "stderr", errors)
    path = tmp_path / "out.log"

    with CommandLog(str(path), title="Shell > CMD") as log, log.capture():
        print("\x1b[32m[*] green\x1b[0m")
        print("partial ", end="")
        print("line")
        print("progress 1\rprogress 2")
        print()
        print("\x1b]8;;https://example.test\x1b\\link\x1b]8;;\x1b\\")
        print("to stderr", file=sys.stderr)

    assert sys.stdout is terminal
    assert sys.stderr is errors
    assert terminal.getvalue().startswith("\x1b[32m[*] green\x1b[0m\npartial line\n")
    assert errors.getvalue() == "to stderr\n"
    assert _body(path) == ["[*] green", "partial line", "progress 2", "", "link", "to stderr"]
    lines = path.read_text(encoding="utf-8").splitlines()
    assert _HEADER_RE.match(lines[0]).group("title") == "Shell > CMD"
    assert _TRAILER_RE.match(lines[-1]).group("ending") == "ended"


def test_the_tee_answers_terminal_questions_with_the_terminal(tmp_path, monkeypatch) -> None:
    terminal = _Terminal()
    monkeypatch.setattr(sys, "stdout", terminal)
    with CommandLog(str(tmp_path / "x.log"), title="t") as log, log.capture():
        assert sys.stdout is not terminal
        assert sys.stdout.isatty() is True
        assert sys.stdout.fileno() == 99
        assert sys.stdout.encoding == "utf-8"


@pytest.mark.parametrize("before", [None, "0"])
def test_a_capture_turns_global_debug_on_and_puts_it_back(tmp_path, monkeypatch, before) -> None:
    if before is not None:
        monkeypatch.setenv(GLOBAL_DEBUG_ENV, before)
    seen: list[str | None] = []
    with CommandLog(str(tmp_path / "x.log"), title="t") as log, log.capture():
        seen.append(os.environ.get(GLOBAL_DEBUG_ENV))
    assert seen == ["1"]
    assert os.environ.get(GLOBAL_DEBUG_ENV) == before


def test_the_shell_debug_scope_runs_inside_the_capture(tmp_path) -> None:
    events: list[str] = []

    @contextmanager
    def debug():
        events.append("on")
        yield
        events.append("off")

    with CommandLog(str(tmp_path / "x.log"), title="t") as log:
        with log.capture(debug=debug):
            events.append("body")
    assert events == ["on", "body", "off"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_new_log_is_owner_only_and_an_existing_one_keeps_its_mode(tmp_path) -> None:
    fresh = tmp_path / "fresh.log"
    with CommandLog(str(fresh), title="t"):
        pass
    assert stat.S_IMODE(fresh.stat().st_mode) == 0o600

    shared = tmp_path / "shared.log"
    shared.write_text("earlier\n", encoding="utf-8")
    shared.chmod(0o644)
    with CommandLog(str(shared), title="t"):
        pass
    assert stat.S_IMODE(shared.stat().st_mode) == 0o644
    assert shared.read_text(encoding="utf-8").startswith("earlier\n\n=== ")


def test_a_second_run_appends_after_a_blank_line(tmp_path) -> None:
    path = tmp_path / "runs.log"
    for title in ("first", "second"):
        with CommandLog(str(path), title=title) as log, log.capture():
            print(title)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert _HEADER_RE.match(lines[0]).group("title") == "first"
    assert _text(lines[1]) == "first"
    assert lines[3] == ""
    assert _HEADER_RE.match(lines[4]).group("title") == "second"
    assert len(lines) == 7


def test_parent_directories_are_created(tmp_path) -> None:
    path = tmp_path / "a" / "b" / "x.log"
    with CommandLog(str(path), title="t"):
        pass
    assert path.is_file()


def test_an_exception_goes_to_the_file_with_its_traceback_and_on(tmp_path, monkeypatch) -> None:
    terminal = _Terminal()
    monkeypatch.setattr(sys, "stdout", terminal)
    path = tmp_path / "x.log"

    with pytest.raises(KeyError):
        with CommandLog(str(path), title="t") as log, log.capture():
            print("before")
            raise KeyError("missing-thing")

    body = _body(path)
    assert body[0] == "before"
    assert body[1] == "Traceback (most recent call last):"
    assert body[-1] == "KeyError: 'missing-thing'"
    assert "Traceback" not in terminal.getvalue()
    assert sys.stdout is terminal
    assert GLOBAL_DEBUG_ENV not in os.environ


def test_an_interrupt_is_noted_in_the_file(tmp_path) -> None:
    path = tmp_path / "x.log"
    with pytest.raises(KeyboardInterrupt):
        with CommandLog(str(path), title="t") as log, log.capture():
            raise KeyboardInterrupt
    assert _body(path) == ["! interrupted (Ctrl+C)"]


def test_a_nested_capture_of_the_same_log_notes_only_a_different_command(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log:
        with log.capture("RUN script.txt"):
            with log.capture("RUN script.txt"):
                print("same")
            with log.capture("SELECT 3F00"):
                print("selected")
    assert _body(path) == ["> RUN script.txt", "same", "> SELECT 3F00", "selected"]


def test_an_indented_line_continues_the_block_above_it_without_a_stamp(tmp_path) -> None:
    """The file folds by indentation: a block's rows sit under its first line."""
    path = tmp_path / "x.log"
    header = "Card:      SEND DATA #1                             90 00"
    row = "           81 03 01 43 01  Command details     SEND DATA #1"
    data_row = "           36 76 16 03..03 Channel data        118 bytes"
    full_hex = "                           16 03 03 00 71"
    with CommandLog(str(path), title="t") as log, log.capture():
        for line in (header, row, data_row, full_hex, "Network:   sent 118 bytes"):
            print(line)

    lines = _raw_body(path)

    assert _STAMPED_RE.match(lines[0]).group("text") == header
    assert lines[1] == "  " + " " * 14 + row
    assert lines[3] == "  " + " " * 14 + full_hex
    assert [_indent(line) for line in lines] == [2, 27, 27, 43, 2]
    assert _STAMPED_RE.match(lines[4]).group("text") == "Network:   sent 118 bytes"


def test_a_blank_line_stays_empty_and_an_indented_first_line_is_kept(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log, log.capture():
        print("   lone detail")
        print()
        print("next")

    lines = _raw_body(path)

    assert lines[0] == "  " + " " * 14 + "   lone detail"
    assert lines[1] == ""
    assert _STAMPED_RE.match(lines[2]).group("margin") == "  "


def test_a_noted_command_s_output_sits_one_level_under_its_note(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="SCP03 > TRACE START") as log:
        with log.capture("SELECT 3F00"):
            print("selected")
            print("   detail")
        with log.capture("SELECT 7FFF"):
            print("selected")

    lines = _raw_body(path)

    assert [_text(line) for line in lines] == ["> SELECT 3F00", "selected", "detail", "> SELECT 7FFF", "selected"]
    assert [_indent(line) for line in lines] == [2, 4, 4 + 14 + 3, 2, 4]


def test_a_nested_noted_command_sits_one_level_deeper(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log:
        with log.capture("RUN script.txt"):
            print("running")
            with log.capture("SELECT 3F00"):
                print("selected")
            print("done")

    lines = _raw_body(path)

    assert [_text(line) for line in lines] == ["> RUN script.txt", "running", "> SELECT 3F00", "selected", "done"]
    assert [_indent(line) for line in lines] == [2, 4, 4, 6, 4]


def test_a_line_a_noted_command_leaves_open_stays_at_its_level(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log:
        with log.capture("RUN script.txt"):
            with log.capture("SELECT 3F00"):
                print("Proceed? [y/N] ", end="")
            print("after")

    lines = _raw_body(path)

    assert [(_indent(line), _text(line)) for line in lines] == [
        (2, "> RUN script.txt"),
        (4, "> SELECT 3F00"),
        (6, "Proceed? [y/N]"),
        (4, "after"),
    ]


def test_a_traceback_folds_under_its_first_line(tmp_path) -> None:
    path = tmp_path / "x.log"
    with pytest.raises(KeyError):
        with CommandLog(str(path), title="t") as log, log.capture():
            raise KeyError("missing-thing")

    lines = _raw_body(path)
    frames = [line for line in lines if 'File "' in line]

    assert _STAMPED_RE.match(lines[0]).group("text") == "Traceback (most recent call last):"
    assert len(frames) > 0
    assert all(_STAMPED_RE.match(line) is None and _indent(line) > _indent(lines[0]) for line in frames)
    assert _STAMPED_RE.match(lines[-1]).group("text") == "KeyError: 'missing-thing'"


def test_text_without_a_final_newline_is_written_when_the_capture_ends(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log, log.capture():
        print("Proceed? [y/N] ", end="")
    assert _body(path) == ["Proceed? [y/N]"]


def test_a_writer_that_never_ends_its_line_is_written_in_bounded_pieces(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(command_log, "_MAX_PENDING_CHARACTERS", 8)
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log, log.capture():
        sys.stdout.write("0123456789")
        sys.stdout.write("AB")
    assert _body(path) == ["0123456789", "AB"]


def test_a_background_thread_printing_during_the_capture_is_written(tmp_path) -> None:
    path = tmp_path / "x.log"
    with CommandLog(str(path), title="t") as log, log.capture():
        worker = threading.Thread(target=print, args=("from the worker thread",))
        worker.start()
        worker.join()
    assert _body(path) == ["from the worker thread"]


def test_a_file_that_cannot_be_written_raises_runtime_error(tmp_path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="cannot write"):
        CommandLog(str(blocker / "x.log"), title="t").open()


def test_a_line_without_the_flag_runs_as_typed_and_writes_nothing(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    seen: list[str] = []

    def execute(line: str) -> str:
        seen.append(line)
        return "ran"

    assert run_with_command_log("scan  --json", execute, shell="S", refused="refused") == "ran"
    assert seen == ["scan  --json"]
    assert list(tmp_path.iterdir()) == []


def test_the_flag_runs_the_command_without_it_under_debug_and_a_log(tmp_path, capsys) -> None:
    path = tmp_path / "scan.log"
    seen: list[tuple[str, str | None]] = []
    events: list[str] = []

    @contextmanager
    def debug():
        events.append("on")
        try:
            yield
        finally:
            events.append("off")

    def execute(line: str) -> bool:
        seen.append((line, os.environ.get(GLOBAL_DEBUG_ENV)))
        print("[*] scanned")
        return True

    result = run_with_command_log(
        f'scan --log "{path}" --json',
        execute,
        shell="eSIM Management",
        refused=False,
        debug=debug,
        shown=str.upper,
    )

    assert result is True
    assert seen == [("scan --json", "1")]
    assert events == ["on", "off"]
    assert _body(path) == ["[*] scanned"]
    lines = path.read_text(encoding="utf-8").splitlines()
    assert _HEADER_RE.match(lines[0]).group("title") == "eSIM Management > SCAN --JSON"
    assert _TRAILER_RE.match(lines[-1]).group("ending") == "ended"
    out = capsys.readouterr().out
    assert f"the output also goes to {path}" in out
    assert f"1 line(s) appended to {path}" in out
    assert GLOBAL_DEBUG_ENV not in os.environ


@pytest.mark.parametrize("line", ["scan --log", "--log x.log", "scan --log a --log b"])
def test_a_refused_line_does_not_run(line: str, capsys) -> None:
    ran: list[str] = []
    assert run_with_command_log(line, ran.append, shell="S", refused="refused") == "refused"
    assert ran == []
    assert capsys.readouterr().out.startswith("[!] --log")


def test_raise_refusal_raises_instead_of_printing(tmp_path) -> None:
    with pytest.raises(ValueError, match="needs a file"):
        run_with_command_log("scan --log", lambda line: None, shell="S", refused=None, raise_refusal=True)
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    with pytest.raises(RuntimeError, match="--log: cannot write"):
        run_with_command_log(
            f'scan --log "{blocker / "x.log"}"',
            lambda line: None,
            shell="S",
            refused=None,
            raise_refusal=True,
        )


def test_an_unwritable_log_refuses_the_command(tmp_path, capsys) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    ran: list[str] = []
    result = run_with_command_log(f'scan --log "{blocker / "x.log"}"', ran.append, shell="S", refused=False)
    assert result is False
    assert ran == []
    assert "[!] --log: cannot write" in capsys.readouterr().out


def test_an_interrupted_command_says_so_in_the_trailer(tmp_path) -> None:
    path = tmp_path / "x.log"

    def execute(line: str) -> None:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        run_with_command_log(f'scan --log "{path}"', execute, shell="S", refused=None)
    lines = path.read_text(encoding="utf-8").splitlines()
    assert _TRAILER_RE.match(lines[-1]).group("ending") == "interrupted (Ctrl+C)"
