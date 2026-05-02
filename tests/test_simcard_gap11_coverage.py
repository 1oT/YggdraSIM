"""Coverage for TS 102 222 DELETE FILE, Cell Broadcast Download, Menu Selection and TS 102 223 TR-side latches:

* ETSI TS 102 222 §6.5 ``DELETE FILE`` (`INS 0xE4`). Admin-scope,
  SCP03-gated; cascades through DF subtrees and rejects MF.
* 3GPP TS 23.041 §9.4.1 Cell Broadcast Download envelope (root
  tag ``D2``). The CB Page TLV (``8C``) is parsed into Serial
  Number, Message Identifier, DCS, Page Parameter and Content;
  all five are latched into ``state.toolkit``.
* ETSI TS 102 223 §7.5.6 Menu Selection envelope (``D3``). Item
  Identifier (TLV ``10`` / ``90``) is recorded plus an optional
  help-request flag.
* ETSI TS 102 223 §6.4 SEND SS / SEND USSD / SEND SHORT MESSAGE /
  SEND DTMF / PLAY TONE / LANGUAGE NOTIFICATION TR-side latches.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    LANGUAGE_NOTIFICATION_COMMAND,
    PLAY_TONE_COMMAND,
    SEND_DTMF_COMMAND,
    SEND_SHORT_MESSAGE_COMMAND,
    SEND_SS_COMMAND,
    SEND_USSD_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _terminal_response(
    *,
    command_number: int,
    command_type: int,
    qualifier: int,
    extra: bytes = b"",
    result_code: int = 0x00,
) -> bytes:
    return (
        tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((result_code & 0xFF,)))
        + bytes(extra or b"")
    )


class _AdminEngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "missing_quirks.py"),
            isdr_config_path=str(root / "missing_isdr.json"),
            sim_eim_identity_path=str(root / "missing_eim_identity.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "profile_store"),
        )
        self.engine.state.scp03_session.authenticated = True

    def tearDown(self) -> None:
        self._td.cleanup()

    def _select_mf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40004023F00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _create_transparent(self, fid: str, size: int = 16) -> None:
        descriptor = bytes((0x82, 0x02, 0x01, 0x21))
        fid_tlv = bytes((0x83, 0x02)) + bytes.fromhex(fid)
        size_tlv = bytes((0x80, 0x02)) + size.to_bytes(2, "big")
        fcp_body = descriptor + fid_tlv + size_tlv
        body = bytes((0x62, len(fcp_body))) + fcp_body
        apdu = bytes([0x00, 0xE0, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class DeleteFileTests(_AdminEngineHarness):
    """ETSI TS 102 222 §6.5 DELETE FILE."""

    def test_delete_existing_ef_under_mf(self) -> None:
        self._select_mf()
        self._create_transparent("7770")
        self.assertIn("7770", self.engine.state.nodes)
        body = bytes.fromhex("83027770")
        apdu = bytes([0x00, 0xE4, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertNotIn("7770", self.engine.state.nodes)
        mf_children = self.engine.state.nodes["3F00"].children
        self.assertNotIn("7770", mf_children)

    def test_delete_unknown_fid_falls_back_to_current_ef(self) -> None:
        self._select_mf()
        self._create_transparent("7771")
        # Select the EF; deleting with an empty body targets it.
        _, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40004027771"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        apdu = bytes([0x00, 0xE4, 0x00, 0x00, 0x00])
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertNotIn("7771", self.engine.state.nodes)

    def test_delete_mf_returns_6986(self) -> None:
        self._select_mf()
        body = bytes.fromhex("83023F00")
        apdu = bytes([0x00, 0xE4, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x69, 0x86))
        self.assertIn("3F00", self.engine.state.nodes)

    def test_delete_without_scp03_returns_6982(self) -> None:
        self._select_mf()
        self._create_transparent("7772")
        self.engine.state.scp03_session.authenticated = False
        body = bytes.fromhex("83027772")
        apdu = bytes([0x00, 0xE4, 0x00, 0x00, len(body)]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x69, 0x82))
        self.assertIn("7772", self.engine.state.nodes)


class _ToolkitHarness(unittest.TestCase):
    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901234",
            iccid="8949000000000000001",
            imsi="999990000000001",
            default_dp_address="",
            root_ci_pkid=b"",
        )
        self.toolkit = ToolkitLogic(self.state)

    def _envelope(self, root_tag: bytes, *body: bytes) -> bytes:
        joined = b"".join(body)
        return bytes((root_tag[0], len(joined))) + joined

    def _fallback(self, payload: bytes) -> tuple[bytes, int, int]:
        del payload
        return b"", 0x90, 0x00


class CellBroadcastDownloadTests(_ToolkitHarness):
    """3GPP TS 23.041 §9.4.1 Cell Broadcast Download (D2)."""

    def _build_cb_page(
        self,
        *,
        serial: int,
        message_id: int,
        dcs: int,
        page_param: int,
        content: bytes,
    ) -> bytes:
        page = (
            serial.to_bytes(2, "big")
            + message_id.to_bytes(2, "big")
            + bytes((dcs & 0xFF, page_param & 0xFF))
            + bytes(content[:82])
        )
        return page + b"\x0D" * (88 - len(page))

    def test_cb_page_decoded_into_state(self) -> None:
        page = self._build_cb_page(
            serial=0x4321,
            message_id=0x1112,
            dcs=0x0F,
            page_param=0x11,
            content=b"AMBER ALERT: test broadcast",
        )
        envelope = self._envelope(b"\xD2", tlv("82", bytes((0x82, 0x81))), tlv("8C", page))
        self.toolkit.handle_envelope(envelope, self._fallback)
        toolkit_state = self.state.toolkit
        self.assertEqual(toolkit_state.last_cb_serial_number, 0x4321)
        self.assertEqual(toolkit_state.last_cb_message_id, 0x1112)
        self.assertEqual(toolkit_state.last_cb_dcs, 0x0F)
        self.assertEqual(toolkit_state.last_cb_page_parameter, 0x11)
        self.assertEqual(toolkit_state.last_cb_page_raw, page)
        self.assertTrue(
            toolkit_state.last_cb_content.startswith(b"AMBER ALERT")
        )
        self.assertEqual(toolkit_state.cb_pages_received, 1)

    def test_cb_pages_received_counter_increments(self) -> None:
        page = self._build_cb_page(
            serial=0x0001,
            message_id=0x0002,
            dcs=0x00,
            page_param=0x21,
            content=b"first page",
        )
        envelope = self._envelope(b"\xD2", tlv("8C", page))
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.cb_pages_received, 2)

    def test_missing_cb_page_tlv_does_not_crash(self) -> None:
        envelope = self._envelope(b"\xD2", tlv("82", bytes((0x82, 0x81))))
        _data, sw1, sw2 = self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self.state.toolkit.last_cb_page_raw, b"")


class MenuSelectionEnvelopeTests(_ToolkitHarness):
    """ETSI TS 102 223 §7.5.6 Menu Selection (D3)."""

    def test_menu_selection_records_item_id(self) -> None:
        envelope = self._envelope(
            b"\xD3",
            tlv("82", bytes((0x82, 0x81))),
            tlv("90", bytes((0x07,))),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_menu_item_id, 0x07)
        self.assertFalse(self.state.toolkit.last_menu_help_request)
        self.assertEqual(self.state.toolkit.menu_selections, [0x07])

    def test_menu_help_request_flag(self) -> None:
        envelope = self._envelope(
            b"\xD3",
            tlv("82", bytes((0x82, 0x81))),
            tlv("90", bytes((0x03,))),
            tlv("15", b""),
        )
        self.toolkit.handle_envelope(envelope, self._fallback)
        self.assertEqual(self.state.toolkit.last_menu_item_id, 0x03)
        self.assertTrue(self.state.toolkit.last_menu_help_request)


class SendSSResponseTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.11 SEND SS TR latch."""

    def test_send_ss_success_captures_response_string(self) -> None:
        result = self.toolkit.queue_send_ss("*100#")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        # SS response: Network reply mapped under TLV 0x89 (TON/NPI 0x91 + BCD)
        ss_response = bytes.fromhex("91") + bytes.fromhex("212143")
        tr = _terminal_response(
            command_number=cmd,
            command_type=SEND_SS_COMMAND,
            qualifier=0x00,
            extra=tlv("89", ss_response),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_send_ss_result, 0x00)
        self.assertEqual(self.state.toolkit.last_send_ss_response, ss_response)

    def test_send_ss_failure_records_additional_information(self) -> None:
        result = self.toolkit.queue_send_ss("*100#")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SEND_SS_COMMAND,
            qualifier=0x00,
            extra=tlv("1A", b"\x21"),
            result_code=0x32,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_send_ss_result, 0x32)
        self.assertEqual(self.state.toolkit.last_send_ss_additional, b"\x21")


class SendUSSDResponseTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.12 SEND USSD TR latch."""

    def test_send_ussd_success_captures_response(self) -> None:
        result = self.toolkit.queue_send_ussd("*100#")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        # 0x0F DCS = 8-bit data; text follows verbatim.
        body = b"\x0F" + b"BALANCE 100"
        tr = _terminal_response(
            command_number=cmd,
            command_type=SEND_USSD_COMMAND,
            qualifier=0x00,
            extra=tlv("8A", body),
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_send_ussd_result, 0x00)
        self.assertEqual(self.state.toolkit.last_send_ussd_response_dcs, 0x0F)
        self.assertEqual(self.state.toolkit.last_send_ussd_response_text, "BALANCE 100")

    def test_send_ussd_failure_clears_response_cache(self) -> None:
        self.state.toolkit.last_send_ussd_response_text = "STALE"
        result = self.toolkit.queue_send_ussd("*100#")
        cmd = int(result["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SEND_USSD_COMMAND,
            qualifier=0x00,
            result_code=0x20,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_send_ussd_response_text, "")
        self.assertEqual(self.state.toolkit.last_send_ussd_result, 0x20)


class SimpleProactiveResultTests(_ToolkitHarness):
    """SEND SHORT MESSAGE / DTMF / PLAY TONE / LANGUAGE NOTIFICATION."""

    def _do(self, queue_kwargs: dict, command_type: int, *, result: int = 0x00) -> None:
        if command_type == SEND_SHORT_MESSAGE_COMMAND:
            outcome = self.toolkit.queue_send_short_message(**queue_kwargs)
        elif command_type == SEND_DTMF_COMMAND:
            outcome = self.toolkit.queue_send_dtmf(**queue_kwargs)
        elif command_type == PLAY_TONE_COMMAND:
            outcome = self.toolkit.queue_play_tone(**queue_kwargs)
        elif command_type == LANGUAGE_NOTIFICATION_COMMAND:
            outcome = self.toolkit.queue_language_notification(**queue_kwargs)
        else:
            raise AssertionError(f"unknown command type {command_type:#x}")
        cmd = int(outcome["commandNumber"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=command_type,
            qualifier=0x00,
            result_code=result,
        )
        self.toolkit.handle_terminal_response(tr)

    def test_short_message_result_latched(self) -> None:
        self._do(
            {"destination": "1234", "text": "hi"},
            SEND_SHORT_MESSAGE_COMMAND,
            result=0x32,
        )
        self.assertEqual(self.state.toolkit.last_send_short_message_result, 0x32)

    def test_dtmf_result_latched(self) -> None:
        self._do({"digits": "12*#"}, SEND_DTMF_COMMAND, result=0x00)
        self.assertEqual(self.state.toolkit.last_send_dtmf_result, 0x00)

    def test_play_tone_result_latched(self) -> None:
        self._do({}, PLAY_TONE_COMMAND, result=0x20)
        self.assertEqual(self.state.toolkit.last_play_tone_result, 0x20)

    def test_language_notification_result_latched(self) -> None:
        self._do({"language": "en"}, LANGUAGE_NOTIFICATION_COMMAND, result=0x00)
        self.assertEqual(
            self.state.toolkit.last_language_notification_result, 0x00
        )


if __name__ == "__main__":
    unittest.main()
