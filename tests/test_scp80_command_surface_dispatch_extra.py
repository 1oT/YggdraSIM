import contextlib
import io
import sys
import types
import unittest
from types import SimpleNamespace
from unittest import mock

from yggdrasim_common.quit_control import QuitAllRequested


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
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

import SCP80.cli as scp80_cli
from SCP80.cli import OtaShell


class _DummyConfig:
    def __init__(self) -> None:
        self.data = {"transport": "print", "counter": "1"}
        self.save_calls = 0

    def get(self, key: str):
        return self.data.get(key)

    def save(self) -> None:
        self.save_calls += 1


class _DummyTransport:
    def __init__(self) -> None:
        self.disconnect_calls = 0
        self.reset_calls = 0

    def disconnect(self) -> None:
        self.disconnect_calls += 1

    def reset_connection(self) -> None:
        self.reset_calls += 1


class OtaShellCommandSurfaceDispatchExtraTests(unittest.TestCase):
    _COMMAND_CASES = {
        "history": ("history", "do_history", ()),
        "show": ("show", "do_show", ()),
        "set": ("set counter 9", "do_set", ("counter", "9")),
        "iccid": ("iccid 8901234567890123456", "do_iccid", ("8901234567890123456",)),
        "build": ("build -v", "do_build", ("-v",)),
        "send": ("send -v", "do_send", ("-v",)),
        "sendraw": ("sendraw 00A40400", "do_sendraw", ("00A40400",)),
        "reset": ("reset", "do_reset", ()),
        "script": ("script tests/demo_script.txt", "do_script", ("tests/demo_script.txt",)),
        "ota": ("ota 00A40400", "do_ota", ("00A40400",)),
        "help": ("help", "do_help", ()),
    }

    def test_command_cases_cover_all_public_do_handlers(self) -> None:
        declared_handlers = {name for name in dir(OtaShell) if name.startswith("do_")}
        covered_handlers = {
            handler_name for _line, handler_name, _expected_args in self._COMMAND_CASES.values()
        }
        self.assertEqual(covered_handlers, declared_handlers)

    @staticmethod
    def _make_shell() -> OtaShell:
        shell = OtaShell.__new__(OtaShell)
        shell.config = _DummyConfig()
        shell.transport = _DummyTransport()
        shell.current_iccid = ""
        shell.last_command_ok = True
        shell.decoder = SimpleNamespace(
            sniff_context=lambda raw_apdu: (None, 0),
            try_decode=lambda fid, le, por: None,
        )
        shell._print_result = lambda result: None
        shell._print_reader_protocol_caveat = lambda multipart_required=False: None
        shell._bind_inventory_profile = lambda iccid, announce=True: True
        shell._refresh_inventory_from_reader = lambda announce=True: True
        shell.builder = SimpleNamespace(build_plan=lambda verbose=False, override_payload=None: None)
        return shell

    def test_each_named_command_dispatches_to_matching_handler(self) -> None:
        for command_name, (line, handler_name, expected_args) in sorted(self._COMMAND_CASES.items()):
            with self.subTest(command=command_name):
                shell = self._make_shell()
                captured_calls: list[tuple[str, ...]] = []
                setattr(
                    shell,
                    handler_name,
                    lambda *args: captured_calls.append(tuple(str(part) for part in args)),
                )

                with contextlib.redirect_stdout(io.StringIO()):
                    keep_running = shell._process_line(line)

                self.assertTrue(keep_running)
                self.assertEqual(captured_calls, [expected_args])

    def test_admin_command_routes_to_admin_shell_process(self) -> None:
        shell = self._make_shell()
        admin_calls: list[str] = []
        shell._run_scp03_tool = lambda: admin_calls.append("admin")

        with contextlib.redirect_stdout(io.StringIO()):
            keep_running = shell._process_line("admin")

        self.assertTrue(keep_running)
        self.assertEqual(admin_calls, ["admin"])

    def test_exit_aliases_disconnect_and_stop_processing(self) -> None:
        for command_name in ("quit", "exit", "q"):
            with self.subTest(command=command_name):
                shell = self._make_shell()

                with contextlib.redirect_stdout(io.StringIO()):
                    keep_running = shell._process_line(command_name)

                self.assertFalse(keep_running)
                self.assertEqual(shell.config.save_calls, 1)
                self.assertEqual(shell.transport.disconnect_calls, 1)

    def test_qa_command_disconnects_and_raises_global_quit(self) -> None:
        shell = self._make_shell()

        with mock.patch(
            "SCP80.cli.quit_all",
            side_effect=QuitAllRequested(),
        ):
            with self.assertRaises(QuitAllRequested):
                with contextlib.redirect_stdout(io.StringIO()):
                    shell._process_line("qa")

        self.assertEqual(shell.config.save_calls, 1)
        self.assertEqual(shell.transport.disconnect_calls, 1)


if __name__ == "__main__":
    unittest.main()
