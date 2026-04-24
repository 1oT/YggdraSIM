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


class DummySequenceTransport:
    def __init__(self, responses: list[tuple[bytes, int, int]]):
        self.responses = list(responses)
        self.calls: list[tuple[str, bool]] = []
        self.reset_calls = 0

    def transmit(self, line: str, silent: bool = False):
        self.calls.append((line, silent))
        if len(self.responses) == 0:
            raise AssertionError("No queued APDU response")
        return self.responses.pop(0)

    def reset(self) -> bool:
        self.reset_calls += 1
        return True


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

    def test_unknown_spaced_hex_apdu_transmits_and_syncs_on_success(self) -> None:
        shell = self._make_shell()
        shell.transport = DummyTransport((b"\xAA\xBB", 0x90, 0x00))

        shell._exec_line("00 A4 04 00 00")

        self.assertEqual(shell.transport.calls, [("00 A4 04 00 00", False)])
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


class ShellDispatcherIdentityProbeTests(unittest.TestCase):
    @staticmethod
    def _make_shell(transport) -> ShellDispatcher:
        shell = ShellDispatcher.__new__(ShellDispatcher)
        shell.transport = transport
        shell.current_iccid = ""
        return shell

    def test_read_live_iccid_accepts_warning_status_with_data(self) -> None:
        shell = self._make_shell(
            DummySequenceTransport(
                [
                    (b"", 0x90, 0x00),
                    (b"", 0x90, 0x00),
                    (bytes.fromhex("98010300005089547021"), 0x62, 0x82),
                ]
            )
        )

        iccid = shell._read_live_iccid()

        self.assertEqual(iccid, "89103000000598450712")
        self.assertEqual(
            shell.transport.calls,
            [
                ("00A40004023F00", True),
                ("00A40004022FE2", True),
                ("00B000000A", True),
            ],
        )

    def test_read_live_iccid_accepts_9f_select_status(self) -> None:
        shell = self._make_shell(
            DummySequenceTransport(
                [
                    (b"", 0x90, 0x00),
                    (b"", 0x9F, 0x10),
                    (bytes.fromhex("98010300005089547021"), 0x90, 0x00),
                ]
            )
        )

        iccid = shell._read_live_iccid()

        self.assertEqual(iccid, "89103000000598450712")


class ShellDispatcherPromptStateTests(unittest.TestCase):
    @staticmethod
    def _make_shell() -> ShellDispatcher:
        shell = ShellDispatcher.__new__(ShellDispatcher)
        shell.transport = types.SimpleNamespace(session=None)
        shell.gp_ctrl = types.SimpleNamespace(
            target_aid=bytes.fromhex("A000000151000000"),
            list_registry=lambda _kind: None,
            sgp22=types.SimpleNamespace(),
        )
        shell.fs_ctrl = types.SimpleNamespace(
            current_path_hint="",
            current_fid=None,
            current_fcp={},
            fid_map={
                "MF": ["3F00"],
                "ADF_USIM": ["7FF0"],
                "USIM": ["7FF0"],
                "EF_IMSI": ["6F07"],
                "IMSI": ["6F07"],
            },
        )
        shell.aid_lookup = {
            bytes.fromhex("A000000151000000"): "MNO-SD",
        }
        shell._prompt_context_label = ""
        shell.prompt_str = ""
        return shell

    def test_update_prompt_state_shows_apdu_context_suffix(self) -> None:
        shell = self._make_shell()

        shell._set_prompt_context("MNO-SD")
        shell._update_prompt_state()

        self.assertIn("APDU -> MNO-SD", shell.prompt_str)

    def test_update_prompt_state_appends_selection_to_secure_prompt(self) -> None:
        shell = self._make_shell()
        shell.transport = types.SimpleNamespace(
            session=types.SimpleNamespace(is_authenticated=True, protocol_name="SCP03")
        )

        shell._set_prompt_context("EF_IMSI")
        shell._update_prompt_state()

        self.assertIn("SCP03:MNO-SD -> EF_IMSI", shell.prompt_str)

    def test_handle_registry_sets_prompt_context_to_gp_target(self) -> None:
        shell = self._make_shell()
        calls: list[str] = []
        shell.gp_ctrl = types.SimpleNamespace(
            target_aid=bytes.fromhex("A000000151000000"),
            list_registry=lambda kind: calls.append(kind),
        )

        shell._handle_registry("APPS")

        self.assertEqual(calls, ["APPS"])
        self.assertEqual(shell._prompt_context_label, "MNO-SD")

    def test_sync_manual_select_updates_prompt_context(self) -> None:
        shell = self._make_shell()

        shell._sync_manual_command(bytes.fromhex("00A40004023F00"), b"")

        self.assertEqual(shell._prompt_context_label, "MF")
        self.assertEqual(shell.fs_ctrl.current_path_hint, "MF")

    def test_handle_read_binary_refreshes_prompt_context_from_fs_state(self) -> None:
        shell = self._make_shell()

        def _read_binary(path=None):
            self.assertEqual(path, "16")
            shell.fs_ctrl.current_fid = "6F07"
            shell.fs_ctrl.current_path_hint = "USIM/EF_IMSI"

        shell.fs_ctrl.read_binary = _read_binary

        shell._set_prompt_context("ISD-R")
        shell._handle_read_binary("16")

        self.assertEqual(shell._prompt_context_label, "USIM/EF_IMSI")

    def test_handle_scan_tree_resets_prompt_context_to_mf(self) -> None:
        shell = self._make_shell()

        def _scan_tree():
            shell.fs_ctrl.current_fid = "3F00"
            shell.fs_ctrl.current_path_hint = ""

        shell.fs_ctrl.scan_tree = _scan_tree

        shell._set_prompt_context("ISD-R")
        shell.fs_ctrl.current_path_hint = "ISD-R"
        shell._handle_scan_tree()

        self.assertEqual(shell._prompt_context_label, "MF")
        self.assertEqual(shell.fs_ctrl.current_path_hint, "MF")


if __name__ == "__main__":
    unittest.main()
