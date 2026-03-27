import io
import sys
import types
import unittest
from contextlib import redirect_stdout


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

from SCP03.interface.commands import CommandRegistry
from SCP03.interface.shell import ShellDispatcher


class _CallableProxy:
    def __call__(self, *args, **kwargs):
        return None

    def __getattr__(self, name: str):
        del name
        return _CallableProxy()


class DummyTransport:
    def __init__(self, response: tuple[bytes, int, int]):
        self.response = response
        self.calls: list[tuple[str, bool]] = []

    def transmit(self, line: str, silent: bool = False):
        self.calls.append((line, silent))
        return self.response


class ShellDispatcherCommandRegistryTests(unittest.TestCase):
    def test_arg_requirements_are_disjoint_and_known(self) -> None:
        command_map = CommandRegistry.build(_CallableProxy())
        required, optional = CommandRegistry.get_arg_requirements()

        self.assertTrue(set(required).issubset(set(command_map)))
        self.assertTrue(set(optional).issubset(set(command_map)))
        self.assertTrue(set(required).isdisjoint(set(optional)))


class ShellDispatcherExecLineTests(unittest.TestCase):
    def _make_shell(self) -> ShellDispatcher:
        shell = ShellDispatcher.__new__(ShellDispatcher)
        shell.commands = {}
        shell.transport = None
        shell.prompt_updates = 0
        shell.synced: list[tuple[bytes, bytes]] = []
        shell._update_prompt_state = lambda: setattr(shell, "prompt_updates", shell.prompt_updates + 1)
        shell._sync_manual_command = lambda apdu, data: shell.synced.append((apdu, data))
        return shell

    def test_required_command_without_argument_prints_warning(self) -> None:
        shell = self._make_shell()
        calls: list[str] = []
        shell.commands = {"SELECT": lambda arg: calls.append(arg)}

        buffer = io.StringIO()
        with redirect_stdout(buffer):
            shell._exec_line("SELECT")

        self.assertEqual(calls, [])
        self.assertIn("Argument required for SELECT", buffer.getvalue())
        self.assertEqual(shell.prompt_updates, 1)

    def test_required_command_with_argument_invokes_handler(self) -> None:
        shell = self._make_shell()
        calls: list[str] = []
        shell.commands = {"SELECT": lambda arg: calls.append(arg)}

        shell._exec_line("SELECT 3F00")

        self.assertEqual(calls, ["3F00"])
        self.assertEqual(shell.prompt_updates, 1)

    def test_optional_command_without_argument_calls_zero_arg_handler(self) -> None:
        shell = self._make_shell()
        calls: list[str] = []
        shell.commands = {"GUIDE": lambda: calls.append("called")}

        shell._exec_line("GUIDE")

        self.assertEqual(calls, ["called"])

    def test_optional_command_with_argument_passes_argument(self) -> None:
        shell = self._make_shell()
        calls: list[str] = []
        shell.commands = {"GUIDE": lambda arg: calls.append(arg)}

        shell._exec_line("GUIDE SAIP")

        self.assertEqual(calls, ["SAIP"])

    def test_zero_arg_command_calls_handler(self) -> None:
        shell = self._make_shell()
        calls: list[str] = []
        shell.commands = {"HELP": lambda: calls.append("help")}

        shell._exec_line("HELP")

        self.assertEqual(calls, ["help"])

    def test_unknown_hex_apdu_transmits_and_syncs_on_success(self) -> None:
        shell = self._make_shell()
        shell.transport = DummyTransport((b"\xAA\xBB", 0x90, 0x00))

        shell._exec_line("00A4040000")

        self.assertEqual(shell.transport.calls, [("00A4040000", False)])
        self.assertEqual(shell.synced, [(bytes.fromhex("00A4040000"), b"\xAA\xBB")])

    def test_unknown_hex_apdu_does_not_sync_on_failure_status(self) -> None:
        shell = self._make_shell()
        shell.transport = DummyTransport((b"", 0x6A, 0x82))

        shell._exec_line("00A4040000")

        self.assertEqual(shell.transport.calls, [("00A4040000", False)])
        self.assertEqual(shell.synced, [])

    def test_unknown_text_command_prints_error(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell._exec_line("NOT-A-COMMAND")

        self.assertIn("Unknown command: NOT-A-COMMAND", buffer.getvalue())


if __name__ == "__main__":
    unittest.main()
