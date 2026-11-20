# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""What the SCP80 shell prints once a PoR has been fetched.

A PoR sent by SMS-SUBMIT reaches the shell as a SEND SHORT MESSAGE that the
transport FETCHes and acknowledges. The shell then prints the data and status
of the last command the script ran (TS 102 226 v19 table 5.1), not the
proactive command beside the ENVELOPE's '91 xx'; it counts the commands that
ran against those sent and decodes the data.
"""

from __future__ import annotations

import contextlib
import io
import re
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

from SCP80 import transport as scp80_transport
from SCP80.cli import OtaShell, SmartDecoder

#: Two registry entries ('E3' holding an AID '4F') as a GET STATUS with the
#: tag list '5C 01 4F' returns them. The AIDs are synthetic.
REGISTRY_DATA = bytes.fromhex("E3094F07F0010203040501E3094F07F0010203040502")
#: GET STATUS as a T=0 TPDU (no Le), then GET RESPONSE twice.
GET_STATUS_SCRIPT = "80F24002054F005C014F" "00C0000000" "00C0000000"
ENVELOPE = "80C2000000"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _send_short_message(additional: bytes) -> bytes:
    """Return a SEND SHORT MESSAGE whose SMS-SUBMIT carries a PoR OK.

    TS 31.115 v19 table 3: the RPI '71' with a null element, RPL, RHL, the
    rest of the response header (TAR, CNTR, PCNTR, status '00') and then
    the additional response data.
    """
    header = bytes.fromhex("B00001" "0000000001" "00" "00")
    packet = bytes([len(header)]) + header + additional
    ud = bytes.fromhex("027100") + len(packet).to_bytes(2, "big") + packet
    tpdu = bytes.fromhex("410005811250F300F6") + bytes([len(ud)]) + ud
    body = (
        bytes.fromhex("8103011300" "82028183" "0500" "86028001")
        + bytes([0x8B, len(tpdu)])
        + tpdu
    )
    return bytes([0xD0, len(body)]) + body


#: Two commands ran, the last answered '90 00' with the registry entries.
POR_TWO_COMMANDS = _send_short_message(b"\x02" + bytes.fromhex("9000") + REGISTRY_DATA)


class _Config:
    def __init__(self) -> None:
        self.counter_increments = 0

    def get(self, key: str) -> str:
        return {"transport": "reader", "spi": "1621"}.get(key, "")

    def increment_counter(self) -> None:
        self.counter_increments += 1


def _transport(por: bytes) -> tuple[Any, list[str]]:
    """Return a transport whose card answers the ENVELOPE with '91 xx' and the PoR."""

    calls: list[str] = []

    class _Card:
        def transmit(self, apdu: list[int]):
            apdu_hex = bytes(apdu).hex().upper()
            calls.append(apdu_hex)
            if apdu_hex == ENVELOPE:
                return [], 0x91, len(por)
            if apdu_hex.startswith("80120000"):
                return list(por), 0x90, 0x00
            return [], 0x90, 0x00

    # The real ``transmit`` over a scripted card, so the trace lines print.
    transport = scp80_transport.Transport.__new__(scp80_transport.Transport)
    transport.cfg = _Config()
    transport.conn = _Card()
    transport.active_protocol = None
    transport._stk_bootstrap_trace = []
    transport._stk_bootstrap_trace_printed = True
    transport._ensure_reader_protocol = lambda apdus, verbose=False: True
    return transport, calls


def _shell_output(result: dict[str, Any], payload_hex: str, verbose: bool = False) -> str:
    shell = OtaShell.__new__(OtaShell)
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        shell._print_result(result, payload_hex=payload_hex, verbose=verbose)
    return ANSI.sub("", buffer.getvalue())


class FetchedPorReply(unittest.TestCase):
    def test_the_transport_fetches_and_acknowledges_the_send_short_message(self) -> None:
        transport, calls = _transport(POR_TWO_COMMANDS)

        result = transport.send_ota_sequence([ENVELOPE])

        self.assertTrue(result["delivered"], result.get("error"))
        self.assertEqual(
            calls,
            [
                ENVELOPE,
                f"80120000{len(POR_TWO_COMMANDS):02X}",
                "801400000C810301130082028281030100",
            ],
        )
        self.assertEqual(result["por_decoded"]["command_count"], 2)
        self.assertEqual(result["por_decoded"]["command_sw"], "9000")
        self.assertEqual(result["por_decoded"]["command_response"], REGISTRY_DATA.hex().upper())

    def test_the_reply_line_is_the_last_commands_data_and_status(self) -> None:
        transport, _calls = _transport(POR_TWO_COMMANDS)
        result = transport.send_ota_sequence([ENVELOPE])

        output = _shell_output(result, GET_STATUS_SCRIPT)

        # Neither the proactive command nor the ENVELOPE's '91 xx'.
        self.assertEqual(output.splitlines()[0], f"[<--] {REGISTRY_DATA.hex().upper()} 9000")
        self.assertNotIn(POR_TWO_COMMANDS.hex().upper(), output)

    def test_a_command_string_cut_short_after_get_response_is_reported(self) -> None:
        transport, _calls = _transport(POR_TWO_COMMANDS)
        result = transport.send_ota_sequence([ENVELOPE])

        output = _shell_output(result, GET_STATUS_SCRIPT)

        self.assertIn("commands 2 of 3", output)
        self.assertIn("via SEND SHORT MESSAGE", output)
        self.assertIn("Command 2 is a GET RESPONSE", output)
        self.assertIn("the command sent after it did not run", output)

    def test_a_clean_success_stays_on_one_line_unless_verbose(self) -> None:
        transport, _calls = _transport(POR_TWO_COMMANDS)
        result = transport.send_ota_sequence([ENVELOPE])
        script = "80F24002054F005C014F" "00C0000000"

        quiet = _shell_output(result, script)
        verbose = _shell_output(result, script, verbose=True)

        self.assertNotIn("[POR]", quiet)
        self.assertIn("[POR] PoR OK (00), TAR B00001", verbose)
        self.assertIn("commands 2 of 2", verbose)

    def test_a_61_status_names_the_get_response_to_append(self) -> None:
        por = _send_short_message(b"\x01" + bytes.fromhex("6116"))
        transport, _calls = _transport(por)
        result = transport.send_ota_sequence([ENVELOPE])

        output = _shell_output(result, "80F24002054F005C014F")

        self.assertIn("[<--] 6116\n", output)
        self.assertIn("GET RESPONSE 00C0000016", output)

    def test_the_verbose_trace_names_each_exchange(self) -> None:
        transport, _calls = _transport(POR_TWO_COMMANDS)
        buffer = io.StringIO()

        with contextlib.redirect_stdout(buffer):
            transport.send_ota_sequence([ENVELOPE], verbose=True)

        trace = ANSI.sub("", buffer.getvalue())
        self.assertIn("[OTA] SMS-PP data download", trace)
        self.assertIn(f"{ENVELOPE} (ENVELOPE)", trace)
        self.assertIn(f"80120000{len(POR_TWO_COMMANDS):02X} (FETCH)", trace)
        self.assertIn("801400000C810301130082028281030100 (TERMINAL RESPONSE)", trace)


class CompactCommandString(unittest.TestCase):
    def test_get_response_takes_no_data_wherever_it_stands(self) -> None:
        commands = SmartDecoder.compact_commands(GET_STATUS_SCRIPT)

        self.assertEqual(
            [command.hex().upper() for command in commands or []],
            ["80F24002054F005C014F", "00C0000000", "00C0000000"],
        )

    def test_a_string_that_does_not_divide_has_no_count(self) -> None:
        cases = {
            "empty": "",
            "header only": "80F240",
            "over-claiming lc": "80F24002054F00",
            "trailing le after case 4": "80F24002054F005C014F00",
            "not hex": "80F2400Z",
        }
        for label, payload in cases.items():
            with self.subTest(label):
                self.assertIsNone(SmartDecoder.compact_commands(payload))


class DecodedReplyData(unittest.TestCase):
    def _por_info(self, data: bytes, sw: str) -> dict[str, Any]:
        por = _send_short_message(b"\x01" + bytes.fromhex(sw) + data)
        return scp80_transport.Transport.decode_por(por, 0x9000)

    def _decode(self, por_info: dict[str, Any], fid: str | None = None) -> str:
        decoder = SmartDecoder.__new__(SmartDecoder)
        decoder.fid_lookup = {}
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            decoder.try_decode(fid, 0, "D0", por_info)
        return ANSI.sub("", buffer.getvalue())

    def test_registry_entries_decode_without_a_selected_file(self) -> None:
        output = self._decode(self._por_info(REGISTRY_DATA, "9000"))

        self.assertIn("--- Decoded (GlobalPlatform", output)
        self.assertIn("E3 GlobalPlatform Registry related data", output)

    def test_entries_before_more_data_available_still_decode(self) -> None:
        output = self._decode(self._por_info(REGISTRY_DATA, "6310"))

        self.assertIn("E3 GlobalPlatform Registry related data", output)

    def test_an_error_status_or_no_data_decodes_nothing(self) -> None:
        self.assertEqual(self._decode(self._por_info(REGISTRY_DATA, "6A88")), "")
        self.assertEqual(self._decode(self._por_info(b"", "9000")), "")

    def test_data_that_is_not_tlv_decodes_nothing(self) -> None:
        self.assertEqual(self._decode(self._por_info(bytes.fromhex("0102030405"), "9000")), "")


class WrongLengthRetry(unittest.TestCase):
    """``ota`` offers the '6C xx' retry on the last command's status alone."""

    def _retries(self, additional: bytes) -> list[str]:
        por = _send_short_message(additional)
        result = {
            "delivered": True,
            "sw": f"91{len(por):02X}",
            "por": por.hex().upper(),
            "por_decoded": scp80_transport.Transport.decode_por(por, 0x9100 | len(por)),
        }
        shell = OtaShell.__new__(OtaShell)
        shell.config = SimpleNamespace(get=lambda key: "print")
        shell.builder = SimpleNamespace(
            build_plan=lambda verbose=False, override_payload=None: SimpleNamespace(
                is_concatenated=False,
                apdus=[SimpleNamespace(apdu_hex=ENVELOPE)],
                reader_apdus=[],
            )
        )
        shell.transport = SimpleNamespace(send_ota_sequence=lambda apdus, verbose=False: result)
        shell.decoder = SimpleNamespace(
            sniff_context=lambda raw_apdu: (None, 0),
            try_decode=lambda fid, le, por_hex, por_info=None: None,
        )
        retries: list[str] = []
        shell._handle_wrong_length = lambda apdu, le: retries.append(le)
        with contextlib.redirect_stdout(io.StringIO()):
            shell.do_ota("00B0000000")
        return retries

    def test_a_6c_status_offers_the_retry(self) -> None:
        self.assertEqual(self._retries(b"\x01" + bytes.fromhex("6C10")), ["10"])

    def test_data_that_ends_in_6c_bytes_is_not_a_status(self) -> None:
        additional = b"\x01" + bytes.fromhex("9000") + bytes.fromhex("0102036C10")
        self.assertEqual(self._retries(additional), [])


class GuiPorDecode(unittest.TestCase):
    def test_smart_ota_decodes_a_por_that_came_by_send_short_message(self) -> None:
        from yggdrasim_common.gui_server.actions import scp80 as scp80_actions

        por_info = scp80_transport.Transport.decode_por(POR_TWO_COMMANDS, 0x9146)
        text = scp80_actions._try_decode_por(
            GET_STATUS_SCRIPT, POR_TWO_COMMANDS.hex().upper(), por_info
        )

        self.assertIn(f"[<--] {REGISTRY_DATA.hex().upper()} 9000", text)
        self.assertIn("E3 GlobalPlatform Registry related data", text)

    def test_send_returns_the_decoded_por(self) -> None:
        from yggdrasim_common.gui_server.actions import scp80 as scp80_actions
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        transport, _calls = _transport(POR_TWO_COMMANDS)
        plan = SimpleNamespace(
            apdus=[SimpleNamespace(apdu_hex=ENVELOPE)],
            reader_apdus=[ENVELOPE],
            is_concatenated=False,
            payload_hex=GET_STATUS_SCRIPT,
        )
        builder = SimpleNamespace(build_plan=lambda verbose=False, override_payload=None: plan)
        with patch.object(scp80_actions, "_load_config", lambda: _Config()), patch.object(
            scp80_actions, "_build_packet_builder", lambda config: builder
        ), patch.object(scp80_actions, "_build_transport", lambda config: transport), patch.object(
            scp80_actions, "_apply_reader_choice", lambda name, index, config: 0
        ), patch.object(scp80_actions, "_plan_to_dict", lambda plan: {}):
            result = scp80_actions._dispatch_send(ActionContext(), payload=GET_STATUS_SCRIPT)

        self.assertTrue(result["ok"], result.get("note"))
        self.assertIn(f"[<--] {REGISTRY_DATA.hex().upper()} 9000", result["por_decoded"])


if __name__ == "__main__":
    unittest.main()
