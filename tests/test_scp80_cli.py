# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import importlib.util
import io
import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return
    if importlib.util.find_spec("smartcard") is not None:
        # pyscard is installed. The stub carries only the submodules this
        # file needs, so leaving it in sys.modules would break every later
        # test in the session that reaches smartcard.util.
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

# The stubs installed above must be in sys.modules before the modules
# under test import their smart-card dependencies.
import SCP80.cli as scp80_cli  # noqa: E402
from SCP80.cli import OtaShell  # noqa: E402


class DummyConfig:
    def __init__(self, transport: str = "print"):
        self.transport = transport
        self.data = dict(scp80_cli.ConfigManager.DEFAULTS)
        self.data["transport"] = transport
        self.set_calls: list[tuple[str, str]] = []
        self.save_calls = 0

    def get(self, key: str):
        if key == "transport":
            return self.transport
        return self.data.get(key)

    def set(self, key: str, value: str) -> None:
        if key == "bad":
            raise ValueError("bad value")
        if key not in self.data:
            raise ValueError(f"Unknown SCP80 config key: {key}.")
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

    def reset_connection(self, verbose: bool = False) -> None:
        self.reset_verbose = verbose
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
            try_decode=lambda fid, le, por, por_info=None: None,
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

    def test_print_result_suppresses_successful_por_summary(self) -> None:
        shell = OtaShell.__new__(OtaShell)
        result = {
            "sw": "9130",
            "por": "D02E",
            "por_decoded": {
                "valid": True,
                "status_code": "00",
                "status_meaning": "PoR OK",
                "tar": "B00001",
                "cntr": "000000FFFF",
                "pcntr": "00",
                "command_count": 1,
                "command_response": "9000",
                "command_sw": "9000",
                "fetch_sw": "9130",
            },
        }
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell._print_result(result)

        output = buffer.getvalue()
        self.assertIn("[<--]", output)
        self.assertNotIn("[POR]", output)

    def test_print_result_includes_failed_por_summary(self) -> None:
        shell = OtaShell.__new__(OtaShell)
        result = {
            "sw": "912D",
            "por": "D02B",
            "por_decoded": {
                "valid": True,
                "status_code": "02",
                "status_meaning": "CNTR low",
                "tar": "B00001",
                "cntr": "0000000000",
                "pcntr": "00",
                "fetch_sw": "912D",
            },
        }
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell._print_result(result)

        output = buffer.getvalue()
        self.assertIn("[POR]", output)
        self.assertIn("CNTR low (02)", output)
        self.assertIn("fetch SW 912D", output)

    def test_print_result_includes_failed_inner_apdu_summary(self) -> None:
        shell = OtaShell.__new__(OtaShell)
        result = {
            "sw": "9130",
            "por": "D02E",
            "por_decoded": {
                "valid": True,
                "status_code": "00",
                "status_meaning": "PoR OK",
                "tar": "B00001",
                "cntr": "0000010010",
                "pcntr": "00",
                "command_count": 1,
                "command_response": "6A82",
                "command_sw": "6A82",
                "fetch_sw": "9130",
            },
        }
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell._print_result(result)

        output = buffer.getvalue()
        self.assertIn("[POR]", output)
        self.assertIn("PoR OK (00)", output)
        self.assertIn("response 6A82", output)

    def test_smart_decoder_skips_failed_inner_apdu_response(self) -> None:
        decoder = scp80_cli.SmartDecoder.__new__(scp80_cli.SmartDecoder)
        decoder.fid_lookup = {"2FE2": "EF_ICCID"}
        decode_calls: list[tuple[str, str]] = []
        content_decoder = SimpleNamespace(
            decode=lambda fid, payload: decode_calls.append((fid, payload)) or "decoded"
        )
        por_info = {
            "valid": True,
            "status_code": "00",
            "command_count": 1,
            "command_response": "6A82",
            "command_sw": "6A82",
        }

        with patch.object(scp80_cli, "SCP03_AVAIL", True):
            with patch.object(scp80_cli, "ContentDecoder", content_decoder, create=True):
                with redirect_stdout(io.StringIO()):
                    decoder.try_decode("2FE2", 10, "D02E", por_info)

        self.assertEqual(decode_calls, [])

    def test_smart_decoder_skips_proactive_pending_inner_apdu_response(self) -> None:
        decoder = scp80_cli.SmartDecoder.__new__(scp80_cli.SmartDecoder)
        decoder.fid_lookup = {"6F07": "EF_IMSI"}
        decode_calls: list[tuple[str, str]] = []
        content_decoder = SimpleNamespace(
            decode=lambda fid, payload: decode_calls.append((fid, payload)) or "decoded"
        )
        por_info = {
            "valid": True,
            "status_code": "00",
            "command_count": 1,
            "command_response": "912D",
            "command_sw": "912D",
            "fetch_sw": "912D",
        }

        with patch.object(scp80_cli, "SCP03_AVAIL", True):
            with patch.object(scp80_cli, "ContentDecoder", content_decoder, create=True):
                with redirect_stdout(io.StringIO()):
                    decoder.try_decode("6F07", 9, "D02B810301130082028183050086028001", por_info)

        self.assertEqual(decode_calls, [])

    def test_smart_decoder_skips_raw_proactive_fetch_body_without_por_decode(self) -> None:
        decoder = scp80_cli.SmartDecoder.__new__(scp80_cli.SmartDecoder)
        decoder.fid_lookup = {"6F07": "EF_IMSI"}
        decode_calls: list[tuple[str, str]] = []
        content_decoder = SimpleNamespace(
            decode=lambda fid, payload: decode_calls.append((fid, payload)) or "decoded"
        )
        fetch_body = (
            "D02B8103011300820281830500860280018B1A410005811250F341F610"
            "027100000B0AB0001000000000000009"
        )

        with patch.object(scp80_cli, "SCP03_AVAIL", True):
            with patch.object(scp80_cli, "ContentDecoder", content_decoder, create=True):
                with redirect_stdout(io.StringIO()):
                    decoder.try_decode("6F07", 9, fetch_body, None)

        self.assertEqual(decode_calls, [])

    def test_smart_decoder_uses_successful_command_response_payload(self) -> None:
        decoder = scp80_cli.SmartDecoder.__new__(scp80_cli.SmartDecoder)
        decoder.fid_lookup = {"2FE2": "EF_ICCID"}
        decode_calls: list[tuple[str, str]] = []
        content_decoder = SimpleNamespace(
            decode=lambda fid, payload: decode_calls.append((fid, payload)) or "decoded"
        )
        por_info = {
            "valid": True,
            "status_code": "00",
            "command_count": 2,
            "command_response": "900098888011111111111111",
            "command_sw": None,
        }

        with patch.object(scp80_cli, "SCP03_AVAIL", True):
            with patch.object(scp80_cli, "ContentDecoder", content_decoder, create=True):
                with redirect_stdout(io.StringIO()):
                    decoder.try_decode("2FE2", 10, "D02E", por_info)

        self.assertEqual(decode_calls, [("2FE2", "98888011111111111111")])

    def test_do_set_updates_config_and_saves(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("cla", "80")

        self.assertEqual(shell.config.set_calls, [("cla", "80")])
        self.assertEqual(shell.config.save_calls, 1)
        self.assertIn("cla updated", buffer.getvalue())

    def test_do_set_aliases_counter_to_cntr(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("counter", "9")

        self.assertEqual(shell.config.set_calls, [("cntr", "9")])
        self.assertEqual(shell.config.save_calls, 1)
        self.assertIn("cntr updated", buffer.getvalue())

    def test_do_set_aliases_identifier_names_to_indicator_slots(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("kic_identifier", "32")
            shell.do_set("kid_identifier", "32")

        self.assertEqual(
            shell.config.set_calls,
            [("kic_indicator", "32"), ("kid_indicator", "32")],
        )
        self.assertEqual(shell.config.save_calls, 2)
        self.assertIn("kic_indicator updated", buffer.getvalue())
        self.assertIn("kid_indicator updated", buffer.getvalue())

    def test_do_set_uses_all_value_tokens(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("payload", "AA", "BB")

        self.assertEqual(shell.config.set_calls, [("payload", "AABB")])
        self.assertEqual(shell.config.save_calls, 1)

    def test_do_set_reports_value_errors(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("bad", "value")

        self.assertIn("bad value", buffer.getvalue())
        self.assertEqual(shell.config.save_calls, 0)

    def test_do_set_reports_unknown_keys_without_saving(self) -> None:
        shell = self._make_shell()
        buffer = io.StringIO()

        with redirect_stdout(buffer):
            shell.do_set("kic_identifer", "32")

        self.assertIn("Unknown SCP80 config key: kic_identifer", buffer.getvalue())
        self.assertEqual(shell.config.set_calls, [])
        self.assertEqual(shell.config.save_calls, 0)

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

    def test_do_send_runs_response_decoder_for_successful_por(self) -> None:
        shell = self._make_shell()
        decode_calls: list[tuple[str, int, str]] = []
        payload = "00A4080C022FE200B000000A"
        por = (
            "D0388103011300820281830500860280018B27410005811250F341F61D"
            "02710000180AB000010000010006000002900098888011111111111111"
        )
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: SimpleNamespace(
                is_concatenated=False,
                apdus=[SimpleNamespace(index=0, total=1, apdu_hex="A1B2")],
                reader_apdus=[],
                payload_hex=payload,
            )
        )
        shell.transport.send_ota_sequence = lambda apdus, verbose=False: {
            "delivered": True,
            "por": por,
            "sw": "913A",
        }
        shell.decoder = SimpleNamespace(
            sniff_context=lambda raw_apdu: ("2FE2", 10),
            try_decode=lambda fid, le, por_hex, por_info=None: decode_calls.append((fid, le, por_hex)),
        )

        shell.do_send()

        self.assertEqual(decode_calls, [("2FE2", 10, por)])

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


class _FakeReadline:
    """GNU readline stand-in that records the completer wiring."""

    def __init__(self, line_buffer: str = "", doc: str = "GNU readline stand-in") -> None:
        self.__doc__ = doc
        self.line_buffer = line_buffer
        self.completer = None
        self.delims = ""
        self.bindings: list[str] = []
        self.history_reads: list[str] = []
        self.history_writes: list[str] = []
        self.history_length = 0

    def get_line_buffer(self) -> str:
        return self.line_buffer

    def set_completer(self, completer) -> None:
        self.completer = completer

    def set_completer_delims(self, delims: str) -> None:
        self.delims = delims

    def parse_and_bind(self, binding: str) -> None:
        self.bindings.append(binding)

    def read_history_file(self, path: str) -> None:
        self.history_reads.append(path)

    def set_history_length(self, length: int) -> None:
        self.history_length = length

    def write_history_file(self, path: str) -> None:
        self.history_writes.append(path)


class OtaShellCompletionTests(unittest.TestCase):
    def _make_shell(self) -> OtaShell:
        shell = OtaShell.__new__(OtaShell)
        shell.config = DummyConfig()
        shell.transport = DummyTransport()
        shell.current_iccid = ""
        shell.history_file = os.path.join(tempfile.gettempdir(), "scp80-completion-test-history")
        return shell

    @staticmethod
    def _complete(shell: OtaShell, line: str) -> list[str]:
        # readline hands the completer the word after the last delimiter.
        text = line.rsplit(" ", 1)[-1]
        options: list[str] = []
        with patch.object(scp80_cli, "readline", _FakeReadline(line)):
            state = 0
            while True:
                option = shell._completer(text, state)
                if option is None:
                    break
                options.append(option)
                state += 1
        return options

    def test_completer_lists_commands_for_the_first_word(self) -> None:
        shell = self._make_shell()

        self.assertEqual(
            self._complete(shell, "s"),
            ["script ", "send ", "sendraw ", "set ", "show "],
        )

    def test_completer_matches_case_insensitively_with_lowercase_result(self) -> None:
        shell = self._make_shell()

        self.assertEqual(self._complete(shell, "SHO"), ["show "])

    def test_completer_lists_builtin_verbs_beside_do_handlers(self) -> None:
        shell = self._make_shell()

        self.assertEqual(self._complete(shell, "q"), ["q ", "qa ", "quit "])
        self.assertEqual(self._complete(shell, "ad"), ["admin "])

    def test_completer_offers_set_keys_without_legacy_spellings(self) -> None:
        shell = self._make_shell()

        self.assertEqual(
            self._complete(shell, "set k"),
            [
                "kic ",
                "kic_identifier ",
                "kic_indicator ",
                "kid ",
                "kid_identifier ",
                "kid_indicator ",
            ],
        )
        self.assertEqual(self._complete(shell, "set COUNT"), ["counter "])

    def test_completer_offers_set_values_for_enumerated_keys(self) -> None:
        shell = self._make_shell()

        self.assertEqual(self._complete(shell, "set transport "), ["print ", "reader "])
        self.assertEqual(self._complete(shell, "set transport r"), ["reader "])
        self.assertEqual(self._complete(shell, "set concat_sms o"), ["ON ", "OFF "])
        self.assertEqual(self._complete(shell, "set cntr "), [])
        self.assertEqual(self._complete(shell, "set transport print "), [])

    def test_completer_offers_script_paths(self) -> None:
        shell = self._make_shell()
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "alpha.txt"), "w", encoding="utf-8") as handle:
                handle.write("00A40400\n")
            with open(os.path.join(tmp, ".hidden"), "w", encoding="utf-8") as handle:
                handle.write("")
            os.mkdir(os.path.join(tmp, "Beta"))

            self.assertEqual(
                self._complete(shell, f"script {tmp}/"),
                [f"{tmp}/alpha.txt ", f"{tmp}/Beta{os.sep}"],
            )
            self.assertEqual(self._complete(shell, f"script {tmp}/al"), [f"{tmp}/alpha.txt "])
            self.assertEqual(self._complete(shell, f"script {tmp}/.h"), [f"{tmp}/.hidden "])
            self.assertEqual(self._complete(shell, f"script {tmp}/missing/"), [])
            self.assertEqual(self._complete(shell, f"script {tmp}/alpha.txt "), [])

    def test_completer_offers_verbose_flag_only_after_a_dash(self) -> None:
        shell = self._make_shell()

        self.assertEqual(self._complete(shell, "send -"), ["-v "])
        self.assertEqual(self._complete(shell, "build -v"), ["-v "])
        self.assertEqual(self._complete(shell, "reset -"), ["-v "])
        self.assertEqual(self._complete(shell, "send 00A4"), [])
        self.assertEqual(self._complete(shell, "build -v -"), [])
        self.assertEqual(self._complete(shell, "sendraw -"), [])

    def test_completer_offers_inventory_iccids(self) -> None:
        shell = self._make_shell()
        kinds: list[str] = []
        shell.config.inventory = SimpleNamespace(
            list_identities=lambda kind: kinds.append(kind)
            or [
                {"identity_kind": "iccid", "identity_value": "8988209876543210987"},
                {"identity_kind": "iccid", "identity_value": "NULL"},
                {"identity_kind": "iccid", "identity_value": "8988201234567890123"},
            ]
        )

        self.assertEqual(
            self._complete(shell, "iccid "),
            ["8988201234567890123 ", "8988209876543210987 "],
        )
        self.assertEqual(self._complete(shell, "iccid 89882012"), ["8988201234567890123 "])
        self.assertEqual(self._complete(shell, "iccid 8988201234567890123 "), [])
        self.assertEqual(kinds, ["iccid", "iccid"])

    def test_completer_without_inventory_offers_no_iccids(self) -> None:
        shell = self._make_shell()

        self.assertEqual(self._complete(shell, "iccid "), [])

    def test_completer_without_readline_returns_none(self) -> None:
        shell = self._make_shell()

        with patch.object(scp80_cli, "readline", None):
            self.assertIsNone(shell._completer("s", 0))

    def test_setup_readline_binds_tab_completion_and_registers_one_saver(self) -> None:
        shell = self._make_shell()
        fake = _FakeReadline()
        registered: list[object] = []

        with patch.object(scp80_cli, "readline", fake):
            with patch.object(scp80_cli.atexit, "register", lambda saver: registered.append(saver)):
                shell._setup_readline()
                shell._setup_readline()

        self.assertEqual(fake.completer, shell._completer)
        self.assertEqual(fake.delims, " \t\n")
        self.assertIn("tab: complete", fake.bindings)
        self.assertNotIn("bind ^I rl_complete", fake.bindings)
        self.assertIn("set show-all-if-ambiguous on", fake.bindings)
        self.assertEqual(fake.history_length, 1000)
        self.assertEqual(registered, [shell._save_history])

    def test_setup_readline_uses_libedit_binding(self) -> None:
        shell = self._make_shell()
        fake = _FakeReadline(doc="This module is based on libedit.")

        with patch.object(scp80_cli, "readline", fake):
            with patch.object(scp80_cli.atexit, "register", lambda saver: None):
                shell._setup_readline()

        self.assertIn("bind ^I rl_complete", fake.bindings)
        self.assertNotIn("tab: complete", fake.bindings)

    def test_setup_readline_reads_an_existing_history_file(self) -> None:
        shell = self._make_shell()
        fake = _FakeReadline()
        with tempfile.TemporaryDirectory() as tmp:
            shell.history_file = os.path.join(tmp, "history")
            with open(shell.history_file, "w", encoding="utf-8") as handle:
                handle.write("show\n")

            with patch.object(scp80_cli, "readline", fake):
                with patch.object(scp80_cli.atexit, "register", lambda saver: None):
                    shell._setup_readline()

        self.assertEqual(fake.history_reads, [shell.history_file])

    def test_save_history_writes_the_history_file(self) -> None:
        shell = self._make_shell()
        fake = _FakeReadline()

        with patch.object(scp80_cli, "readline", fake):
            shell._save_history()

        self.assertEqual(fake.history_writes, [shell.history_file])

    def test_save_history_without_readline_is_a_no_op(self) -> None:
        shell = self._make_shell()

        with patch.object(scp80_cli, "readline", None):
            shell._save_history()


if __name__ == "__main__":
    unittest.main()
