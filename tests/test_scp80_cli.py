import io
import sys
import types
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return

    smartcard_module = types.ModuleType("smartcard")
    system_module = types.ModuleType("smartcard.System")
    card_connection_module = types.ModuleType("smartcard.CardConnection")
    atr_module = types.ModuleType("smartcard.ATR")

    class _CardConnection:
        T0_protocol = 0
        T1_protocol = 1
        RAW_protocol = 2

    class _Atr:
        def __init__(self, _raw):
            pass

        @staticmethod
        def getSupportedProtocols():
            return {"T=1": True}

    system_module.readers = lambda: []
    card_connection_module.CardConnection = _CardConnection
    atr_module.ATR = _Atr

    smartcard_module.System = system_module
    smartcard_module.CardConnection = card_connection_module
    smartcard_module.ATR = atr_module

    sys.modules["smartcard"] = smartcard_module
    sys.modules["smartcard.System"] = system_module
    sys.modules["smartcard.CardConnection"] = card_connection_module
    sys.modules["smartcard.ATR"] = atr_module


_install_smartcard_stubs()

import SCP80.cli as scp80_cli
from SCP80.cli import OtaShell


class DummyConfig:
    def __init__(self, transport: str = "print"):
        self.transport = transport
        self.data = {
            "transport": transport,
            "counter": "1",
        }
        self.set_calls: list[tuple[str, str]] = []
        self.save_calls = 0

    def get(self, key: str):
        if key == "transport":
            return self.transport
        return self.data.get(key)

    def set(self, key: str, value: str) -> None:
        if key == "bad":
            raise ValueError("bad value")
        self.set_calls.append((key, value))
        self.data[key] = value

    def save(self) -> None:
        self.save_calls += 1


class DummyTransport:
    def __init__(self):
        self.disconnect_calls = 0
        self.send_calls: list[tuple[list[str], bool]] = []
        self.transmit_calls: list[str] = []
        self.reset_calls = 0

    def disconnect(self) -> None:
        self.disconnect_calls += 1

    def send_ota_sequence(self, apdus, verbose: bool = False):
        self.send_calls.append((list(apdus), verbose))
        return {"delivered": True, "por": ""}

    def transmit(self, apdu_hex: str) -> None:
        self.transmit_calls.append(apdu_hex)

    def reset_connection(self) -> None:
        self.reset_calls += 1

    def get_protocol_summary(self):
        return {
            "available": True,
            "supports_t1": True,
            "active_protocol": "T=1",
            "atr_hex": "3B00",
        }


class OtaShellTests(unittest.TestCase):
    def _make_shell(self, *, transport_mode: str = "print") -> OtaShell:
        shell = OtaShell.__new__(OtaShell)
        shell.config = DummyConfig(transport=transport_mode)
        shell.transport = DummyTransport()
        shell.current_iccid = ""
        shell.last_command_ok = True
        shell.decoder = SimpleNamespace(
            sniff_context=lambda raw_apdu: (None, 0),
            try_decode=lambda fid, le, por: None,
        )
        shell._print_result = lambda result: setattr(shell, "_last_result", result)
        shell._print_reader_protocol_caveat = lambda multipart_required=False: setattr(
            shell,
            "_last_caveat",
            multipart_required,
        )
        shell._run_scp03_tool = lambda: setattr(shell, "_admin_called", True)
        shell._bind_inventory_profile = lambda iccid, announce=True: setattr(
            shell,
            "_bound_iccid",
            (iccid, announce),
        ) or True
        shell._refresh_inventory_from_reader = lambda announce=True: setattr(
            shell,
            "_reader_refresh",
            announce,
        ) or True
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: SimpleNamespace(
                is_concatenated=False,
                apdus=[SimpleNamespace(index=0, total=1, apdu_hex="A1B2")],
                reader_apdus=[],
            )
        )
        return shell

    def test_normalize_script_hex_line_strips_comments_and_whitespace(self) -> None:
        self.assertEqual(
            OtaShell._normalize_script_hex_line(" 00 A4 04 00 # select"),
            "00A40400",
        )
        self.assertEqual(OtaShell._normalize_script_hex_line("no hex here"), "")

    def test_process_line_routes_admin_command(self) -> None:
        shell = self._make_shell()

        keep_running = shell._process_line("admin")

        self.assertTrue(keep_running)
        self.assertTrue(getattr(shell, "_admin_called", False))

    def test_process_line_quit_saves_and_disconnects(self) -> None:
        shell = self._make_shell()

        keep_running = shell._process_line("quit")

        self.assertFalse(keep_running)
        self.assertEqual(shell.config.save_calls, 1)
        self.assertEqual(shell.transport.disconnect_calls, 1)

    def test_process_line_qa_triggers_global_quit(self) -> None:
        shell = self._make_shell()
        quit_calls: list[str] = []

        with patch.object(scp80_cli, "quit_all", lambda: quit_calls.append("quit")):
            shell._process_line("qa")

        self.assertEqual(shell.config.save_calls, 1)
        self.assertEqual(shell.transport.disconnect_calls, 1)
        self.assertEqual(quit_calls, ["quit"])

    def test_process_line_dispatches_named_command(self) -> None:
        shell = self._make_shell()
        calls: list[tuple[str, ...]] = []
        shell.do_ping = lambda *args: calls.append(args)

        keep_running = shell._process_line("ping alpha beta")

        self.assertTrue(keep_running)
        self.assertEqual(calls, [("alpha", "beta")])

    def test_process_line_dispatches_hex_to_ota(self) -> None:
        shell = self._make_shell()
        calls: list[tuple[str, ...]] = []
        shell.do_ota = lambda *args: calls.append(args)

        keep_running = shell._process_line("00 A4 04 00")

        self.assertTrue(keep_running)
        self.assertEqual(calls, [("00 A4 04 00",)])

    def test_process_line_unknown_command_prints_error(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell._process_line("wat")

        self.assertIn("Unknown command or invalid hex.", buffer.getvalue())

    def test_do_set_updates_config_and_saves(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("counter", "9")

        self.assertEqual(shell.config.set_calls, [("counter", "9")])
        self.assertEqual(shell.config.save_calls, 1)
        self.assertIn("counter updated", buffer.getvalue())

    def test_do_set_reports_value_errors(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("bad", "value")

        self.assertIn("bad value", buffer.getvalue())

    def test_do_iccid_sanitizes_digits_before_binding_profile(self) -> None:
        shell = self._make_shell()

        shell.do_iccid("89-01 23AB")

        self.assertEqual(getattr(shell, "_bound_iccid", None), ("890123", True))

    def test_do_send_uses_standard_apdu_list_in_print_mode(self) -> None:
        shell = self._make_shell()
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: SimpleNamespace(
                is_concatenated=False,
                apdus=[SimpleNamespace(index=0, total=1, apdu_hex="A1B2")],
                reader_apdus=[],
            )
        )

        shell.do_send()

        self.assertEqual(shell.transport.send_calls, [(["A1B2"], False)])
        self.assertTrue(shell.last_command_ok)
        self.assertEqual(getattr(shell, "_last_result", None), {"delivered": True, "por": ""})

    def test_do_send_uses_reader_apdu_when_concatenated_in_reader_mode(self) -> None:
        shell = self._make_shell(transport_mode="reader")
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: SimpleNamespace(
                is_concatenated=True,
                apdus=[
                    SimpleNamespace(index=0, total=2, apdu_hex="A1B2"),
                    SimpleNamespace(index=1, total=2, apdu_hex="C3D4"),
                ],
                reader_apdus=["80C20000"],
            )
        )

        shell.do_send("-v")

        self.assertEqual(shell.transport.send_calls, [(["80C20000"], True)])
        self.assertTrue(shell.last_command_ok)
        self.assertTrue(getattr(shell, "_last_caveat", False))

    def test_do_send_uses_global_debug_as_verbose(self) -> None:
        shell = self._make_shell()
        shell.global_debug = True
        build_calls: list[tuple[bool, object]] = []
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: build_calls.append(
                (bool(verbose), override_payload)
            )
            or SimpleNamespace(
                is_concatenated=False,
                apdus=[SimpleNamespace(index=0, total=1, apdu_hex="A1B2")],
                reader_apdus=[],
            )
        )

        shell.do_send()

        self.assertEqual(build_calls, [(True, None)])
        self.assertEqual(shell.transport.send_calls, [(["A1B2"], True)])

    def test_do_ota_uses_global_debug_as_verbose(self) -> None:
        shell = self._make_shell()
        shell.global_debug = True
        build_calls: list[tuple[bool, object]] = []
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: build_calls.append(
                (bool(verbose), override_payload)
            )
            or SimpleNamespace(
                is_concatenated=False,
                apdus=[SimpleNamespace(index=0, total=1, apdu_hex="A1B2")],
                reader_apdus=[],
            )
        )

        shell.do_ota("00A4040000")

        self.assertEqual(build_calls, [(True, "00A4040000")])
        self.assertEqual(shell.transport.send_calls, [(["A1B2"], True)])


if __name__ == "__main__":
    unittest.main()
