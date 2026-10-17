# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Every shell takes --log <file> off a command line; SCP03 TRACE spans commands."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import sys
import tempfile
import types
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return
    if importlib.util.find_spec("smartcard") is not None:
        # pyscard is installed: a partial stub left in sys.modules would break
        # every later test that reaches smartcard.util.
        return
    smartcard_module = types.ModuleType("smartcard")
    system_module = types.ModuleType("smartcard.System")
    card_connection_module = types.ModuleType("smartcard.CardConnection")
    system_module.readers = lambda: []
    card_connection_module.CardConnection = type("CardConnection", (), {})
    smartcard_module.System = system_module
    smartcard_module.CardConnection = card_connection_module
    sys.modules["smartcard"] = smartcard_module
    sys.modules["smartcard.System"] = system_module
    sys.modules["smartcard.CardConnection"] = card_connection_module


_install_smartcard_stubs()

from SCP03.interface.shell import ShellDispatcher  # noqa: E402
from SCP03.interface.stk_shell import StkShell  # noqa: E402
from SCP11.eim_local.main import EimLocalShell  # noqa: E402
from SCP11.live.console import SCP11Console as LiveConsole  # noqa: E402
from SCP11.local_access.main import LocalAccessShell  # noqa: E402
from SCP80.cli import OtaShell  # noqa: E402
from Tools.ProfilePackage.shell import ProfilePackageShell  # noqa: E402
from Tools.SuciTool.shell import SuciToolShell  # noqa: E402

# A block's first line sits behind its nesting margin and time stamp; a continuation
# behind the margin and the stamp's width in blanks.
_STAMPED_RE = re.compile(r"^(?:  )+\d{2}:\d{2}:\d{2}\.\d{3}  (?P<text>\S.*)$")
# A VERIFY line: INS '20' is in SCP03.interface.shell.CREDENTIAL_INSTRUCTIONS.
_VERIFY_PIN_APDU = "002000010831323334FFFFFFFF"


def _text(line: str) -> str:
    stamped = _STAMPED_RE.match(line)
    return stamped.group("text") if stamped is not None else line.strip()


def _body(path: Path) -> list[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("=== ") and lines[-1].startswith("=== ")
    return [_text(line) for line in lines[1:-1]]


@pytest.fixture(autouse=True)
def _debug_flag_unset(monkeypatch):
    monkeypatch.delenv(GLOBAL_DEBUG_ENV, raising=False)


class _RawLoggingChannel:
    def __init__(self) -> None:
        self.raw = False

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self.raw = bool(enabled)

    def get_raw_apdu_logging(self) -> bool:
        return self.raw


def _live_console() -> LiveConsole:
    provider = SimpleNamespace(
        set_base_url=lambda value: None,
        set_verify_tls=lambda enabled: None,
        set_ca_bundle_path=lambda path: None,
    )
    cfg = SimpleNamespace(
        RSP_SERVER_URL="rsp.example.com",
        ES9_BASE_URL="https://rsp.example.com",
        ES9_VERIFY_TLS=True,
        ES9_CA_BUNDLE_PATH="",
    )
    client = SimpleNamespace(
        cfg=cfg,
        apdu_channel=None,
        orchestrator=SimpleNamespace(profile_provider=provider),
    )
    console = LiveConsole(client)
    console._initialize_session = lambda: None
    console._deactivate_locked_help_pane = lambda: None
    return console


def test_live_console_runs_a_logged_command_without_the_flag_and_with_debug(tmp_path) -> None:
    console = _live_console()
    channel = _RawLoggingChannel()
    console.apdu_channel = channel
    seen: list[tuple[str, str | None, bool]] = []

    def handler(argument: str) -> bool:
        seen.append((argument, os.environ.get(GLOBAL_DEBUG_ENV), channel.raw))
        print("[*] handled")
        return True

    console._commands["HELP"].handler = handler
    path = tmp_path / "help.log"
    with contextlib.redirect_stdout(io.StringIO()):
        console.run_commands(f'HELP EXPERT --log "{path}"')

    assert seen == [("EXPERT", "1", True)]
    assert channel.raw is False
    assert GLOBAL_DEBUG_ENV not in os.environ
    assert path.read_text(encoding="utf-8").splitlines()[0].endswith("  eSIM Management > HELP EXPERT ===")
    assert _body(path) == ["[*] handled"]


def test_live_console_refuses_the_flag_where_the_gui_dispatches(tmp_path) -> None:
    console = _live_console()
    ran: list[str] = []
    console._commands["HELP"].handler = lambda argument: ran.append(argument) or True
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        keep_running = console._execute_command("HELP", f'--log "{tmp_path / "x.log"}"')

    assert keep_running is True
    assert ran == []
    assert "--log is read from a terminal command line only" in buffer.getvalue()
    assert list(tmp_path.iterdir()) == []


def _eim_local_shell() -> EimLocalShell:
    with mock.patch("SCP11.eim_local.main.EimLocalSession", return_value=SimpleNamespace(apdu_channel=None)):
        return EimLocalShell()


def test_eim_local_logged_command_switches_the_ipad_debug_on_for_its_run(tmp_path) -> None:
    shell = _eim_local_shell()
    shell._global_debug = False
    seen: list[tuple[str, bool]] = []
    shell._commands["DISCOVER"] = lambda argument: seen.append((argument, shell._global_debug))
    path = tmp_path / "discover.log"
    with contextlib.redirect_stdout(io.StringIO()):
        assert shell._execute_command_line(f'DISCOVER sample --log "{path}"') is True

    assert seen == [("sample", True)]
    assert shell._global_debug is False
    assert path.is_file()


def test_local_access_logged_command_reaches_its_handler_without_the_flag(tmp_path) -> None:
    shell = LocalAccessShell()
    seen: list[tuple[list[str], bool]] = []
    shell._cmd_certs = lambda arguments: seen.append((list(arguments), shell._global_debug))
    path = tmp_path / "certs.log"
    with contextlib.redirect_stdout(io.StringIO()):
        assert shell._execute_command_line(f'CERTS --json --log "{path}"') is True

    assert seen == [(["--json"], True)]
    assert shell._global_debug is False
    assert path.is_file()


def test_local_access_batch_fails_on_a_malformed_flag() -> None:
    shell = LocalAccessShell()
    shell._build_session = lambda: None
    ran: list[str] = []
    shell._print_status = lambda: ran.append("status")
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        with pytest.raises(SystemExit) as raised:
            shell.run_commands("STATUS --log")

    assert raised.value.code == 1
    assert ran == []
    assert "--log needs a file" in buffer.getvalue()


def _scp03_shell() -> ShellDispatcher:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.command_map = {}
    shell.commands = {}
    shell.transport = None
    shell.debug_mode = False
    shell._update_prompt_state = lambda: None
    shell._sync_manual_command = lambda apdu, data: None
    return shell


def test_scp03_logged_command_runs_in_debug_mode_without_the_flag(tmp_path) -> None:
    shell = _scp03_shell()
    transport = SimpleNamespace(debug=False, proactive_handler=None)
    shell.transport = transport
    seen: list[tuple[str, bool, bool]] = []
    shell.commands = {"SELECT": lambda arg: seen.append((arg, shell.debug_mode, transport.debug))}
    path = tmp_path / "select.log"
    with contextlib.redirect_stdout(io.StringIO()):
        shell._exec_line(f'SELECT 3F00 --log "{path}"')

    assert seen == [("3F00", True, True)]
    assert shell.debug_mode is False
    assert transport.debug is False
    assert path.read_text(encoding="utf-8").splitlines()[0].endswith("  SCP03 > SELECT 3F00 ===")


def test_scp03_trace_copies_every_command_until_trace_stop(tmp_path) -> None:
    shell = _scp03_shell()
    debug_seen: list[bool] = []

    def select(arg: str) -> None:
        debug_seen.append(shell.debug_mode)
        print(f"selected {arg}")

    shell.commands = {"SELECT": select, "TRACE": shell._handle_trace}
    path = tmp_path / "trace.log"
    terminal = io.StringIO()
    with contextlib.redirect_stdout(terminal):
        shell._exec_line(f'TRACE START "{path}"')
        shell._exec_line("SELECT 3F00")
        shell._exec_line("SELECT 7FFF")
        shell._exec_line("TRACE STOP")
        shell._exec_line("SELECT 2F00")

    assert debug_seen == [True, True, False]
    assert shell.debug_mode is False
    assert shell._active_trace_log() is None
    assert _body(path) == [
        "> SELECT 3F00",
        "selected 3F00",
        "> SELECT 7FFF",
        "selected 7FFF",
        "> TRACE STOP",
    ]
    lines = path.read_text(encoding="utf-8").splitlines()
    assert lines[0].endswith("  SCP03 > TRACE START ===")
    assert "  TRACE STOP after " in lines[-1]
    # Each command folds over its output: the note one level in, the output one deeper.
    assert [len(line) - len(line.lstrip(" ")) for line in lines[1:-1]] == [2, 4, 2, 4, 2]
    assert "selected 2F00" in terminal.getvalue()


def test_scp03_trace_start_without_a_file_uses_the_default_directory(tmp_path, monkeypatch) -> None:
    from yggdrasim_common import command_log

    monkeypatch.setattr(command_log, "runtime_root", lambda: str(tmp_path))
    shell = _scp03_shell()
    shell.commands = {"TRACE": shell._handle_trace}
    with contextlib.redirect_stdout(io.StringIO()):
        shell._exec_line("TRACE START")
        trace_log = shell._active_trace_log()
        assert trace_log is not None
        shell._exec_line("TRACE STOP")

    assert trace_log.path.parent == tmp_path / "reports" / "command_logs"
    assert trace_log.path.name.startswith("scp03-trace-")


def test_scp03_trace_refuses_a_second_start_and_reports_its_state(tmp_path) -> None:
    shell = _scp03_shell()
    shell.commands = {"TRACE": shell._handle_trace}
    path = tmp_path / "trace.log"
    terminal = io.StringIO()
    with contextlib.redirect_stdout(terminal):
        shell._exec_line("TRACE")
        shell._exec_line(f'TRACE START "{path}"')
        shell._exec_line(f'TRACE START "{tmp_path / "other.log"}"')
        shell._exec_line("TRACE STATUS")
        shell._exec_line("TRACE STOP")
        shell._exec_line("TRACE STOP")
        shell._exec_line("TRACE SIDEWAYS")

    output = terminal.getvalue()
    assert "TRACE is off" in output
    assert f"TRACE is already writing to {path}" in output
    assert f"TRACE is writing to {path}" in output
    assert "TRACE is not running" in output
    assert "Usage: TRACE START [File] | TRACE STOP | TRACE STATUS" in output
    assert not (tmp_path / "other.log").exists()


def test_scp03_exit_closes_an_open_trace(tmp_path) -> None:
    shell = _scp03_shell()
    shell._save_history = lambda: None
    shell.commands = {"TRACE": shell._handle_trace, "EXIT": shell._exit}
    # A registry verb outside the argument tables is called bare.
    shell.command_map = {"EXIT": shell._exit}
    path = tmp_path / "trace.log"
    with contextlib.redirect_stdout(io.StringIO()):
        shell._exec_line(f'TRACE START "{path}"')
        with pytest.raises(SystemExit):
            shell._exec_line("EXIT")

    assert "  ended by EXIT after " in path.read_text(encoding="utf-8").splitlines()[-1]


def test_scp03_prompt_shows_the_trace_marker_while_tracing(tmp_path) -> None:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.transport = SimpleNamespace(session=None)
    shell.gp_ctrl = SimpleNamespace(target_aid=bytes.fromhex("A000000151000000"))
    shell.fs_ctrl = SimpleNamespace(current_path_hint="", current_fid=None, current_fcp={}, fid_map={})
    shell.aid_lookup = {}
    shell._prompt_context_label = ""
    shell.prompt_str = ""
    shell._update_prompt_state()
    assert "[APDU] >" in shell.prompt_str

    with contextlib.redirect_stdout(io.StringIO()):
        shell._start_trace(str(tmp_path / "trace.log"))
    shell._update_prompt_state()
    assert "[TRACE APDU] >" in shell.prompt_str

    with contextlib.redirect_stdout(io.StringIO()):
        shell._close_trace("TRACE STOP")
    shell._update_prompt_state()
    assert "[APDU] >" in shell.prompt_str


def test_scp03_a_credential_line_with_the_flag_stays_out_of_history_and_display() -> None:
    shell = _scp03_shell()
    assert shell._history_line_is_sensitive(_VERIFY_PIN_APDU) is True
    assert shell._history_line_is_sensitive(f"{_VERIFY_PIN_APDU} --log x.log") is True
    assert shell._history_line_is_sensitive(f"{_VERIFY_PIN_APDU} --log") is True
    shown = shell._redact_command_line_for_display(f"{_VERIFY_PIN_APDU} --log x.log")
    assert "31323334" not in shown
    assert shown == shell._redact_command_line_for_display(_VERIFY_PIN_APDU)


def test_stk_logged_command_turns_the_controller_debug_on_for_its_run(tmp_path) -> None:
    controller = SimpleNamespace(debug=False)
    controller.set_debug = lambda enabled: setattr(controller, "debug", bool(enabled))
    shell = StkShell.__new__(StkShell)
    shell.controller = controller
    seen: list[tuple[str, bool]] = []
    shell._commands = {"STATE": lambda arg: seen.append((arg, controller.debug)) or True}
    path = tmp_path / "stk.log"
    with contextlib.redirect_stdout(io.StringIO()):
        assert shell._exec_line(f'STATE --log "{path}"') is True

    assert seen == [("", True)]
    assert controller.debug is False
    assert path.is_file()


def _ota_shell() -> OtaShell:
    shell = OtaShell.__new__(OtaShell)
    shell.last_command_ok = True
    shell.global_debug = False
    return shell


def test_scp80_logged_command_runs_verbose(tmp_path) -> None:
    shell = _ota_shell()
    seen: list[tuple[tuple[str, ...], bool]] = []
    shell.do_show = lambda *args: seen.append((args, shell.global_debug))
    path = tmp_path / "show.log"
    with contextlib.redirect_stdout(io.StringIO()):
        assert shell._process_line(f'show --log "{path}"') is True

    assert seen == [((), True)]
    assert shell.global_debug is False
    assert shell.last_command_ok is True
    assert path.is_file()


def test_scp80_refused_flag_marks_the_command_failed() -> None:
    shell = _ota_shell()
    ran: list[tuple[str, ...]] = []
    shell.do_show = lambda *args: ran.append(args)
    with contextlib.redirect_stdout(io.StringIO()):
        assert shell._process_line("show --log") is True

    assert ran == []
    assert shell.last_command_ok is False


def test_suci_and_saip_shells_take_the_flag_off(tmp_path) -> None:
    workspace = Path(tempfile.mkdtemp(dir=tmp_path))
    suci = SuciToolShell(workspace_root=workspace)
    with mock.patch.object(ProfilePackageShell, "_setup_readline", lambda self: None):
        saip = ProfilePackageShell(workspace_root=workspace)
    for name, shell in (("suci", suci), ("saip", saip)):
        seen: list[tuple[str, str | None]] = []
        shell._commands["STATUS"] = lambda argument, seen=seen: seen.append(
            (argument, os.environ.get(GLOBAL_DEBUG_ENV))
        )
        path = tmp_path / f"{name}.log"
        with contextlib.redirect_stdout(io.StringIO()):
            shell._exec_line(f'STATUS now --log "{path}"')
        assert seen == [("now", "1")], name
        assert path.is_file(), name
