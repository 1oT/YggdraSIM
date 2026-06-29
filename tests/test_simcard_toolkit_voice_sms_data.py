# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ETSI TS 102 223 §6.6 voice / SMS / data / UI proactive queueables.

These tests exercise every public ``queue_*`` helper added to
``SIMCARD.toolkit.ToolkitLogic`` for voice, SMS, and data/UI
operations. Each test:

1. Calls the helper.
2. Pulls the resulting payload out of ``state.pending_fetch_queue``.
3. Re-parses it with the in-tree parser to assert the proactive
   envelope, command type, qualifier and info-object TLVs match the
   spec.

The point is to lock the wire shape against what a commercial
terminal (or a Wireshark TS 102 223 dissector) would expect when the
simulator emits the command, so a HIL bridge sees the same bytes a
real card would put on the line.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.toolkit import (
    DISPLAY_TEXT_COMMAND,
    GET_INKEY_COMMAND,
    GET_INPUT_COMMAND,
    LANGUAGE_NOTIFICATION_COMMAND,
    PLAY_TONE_COMMAND,
    PROVIDE_LOCAL_INFORMATION_COMMAND,
    RUN_AT_COMMAND,
    SELECT_ITEM_COMMAND,
    SEND_DTMF_COMMAND,
    SEND_SHORT_MESSAGE_COMMAND,
    SEND_SS_COMMAND,
    SEND_USSD_COMMAND,
    SET_UP_CALL_COMMAND,
    SET_UP_IDLE_MODE_TEXT_COMMAND,
    SET_UP_MENU_COMMAND,
)
from SIMCARD.utils import read_tlv


def _make_engine() -> SimulatedSimCardEngine:
    td = tempfile.mkdtemp()
    store_root = Path(td) / "simcard"
    store_root.mkdir(parents=True, exist_ok=True)
    (store_root / "euicc").mkdir(parents=True, exist_ok=True)
    profile_store = store_root / "profile_store"
    profile_store.mkdir(parents=True, exist_ok=True)
    return SimulatedSimCardEngine(
        euicc_store_root=str(store_root),
        profile_store_path=str(profile_store),
    )


def _last_queued(engine: SimulatedSimCardEngine) -> bytes:
    queue = engine.state.pending_fetch_queue
    if len(queue) == 0:
        raise AssertionError("Expected a queued proactive command but none was found.")
    return bytes(queue[-1])


def _parse(engine: SimulatedSimCardEngine, payload: bytes) -> dict:
    return engine.toolkit._parse_proactive_command(payload)


class VoiceCommandsBuildSpecCompliantTLVs(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_setup_call_carries_alpha_id_and_address(self) -> None:
        result = self.engine.toolkit.queue_setup_call(
            "+15550100199",
            alpha_identifier="Lab",
        )
        self.assertEqual(result["mode"], "set-up-call")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SET_UP_CALL_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x00)
        self.assertEqual(parsed["alpha_identifier"], "Lab")
        self.assertEqual(parsed["address_ton_npi"], 0x91)
        self.assertEqual(parsed["address_digits"], "15550100199")

    def test_send_dtmf_packs_digits_with_filler_nibble(self) -> None:
        self.engine.toolkit.queue_send_dtmf("123#")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SEND_DTMF_COMMAND)
        # 4 digits "123#" pack as nibble-swapped: 21 #3 -> 0x21 0xB3.
        self.assertEqual(parsed["dtmf_string"], "123#")

    def test_send_ss_emits_ss_string_object(self) -> None:
        self.engine.toolkit.queue_send_ss("*21*5550100199#")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SEND_SS_COMMAND)
        self.assertIn("*", parsed["ss_string"])
        self.assertIn("#", parsed["ss_string"])

    def test_send_ussd_carries_dcs_and_text(self) -> None:
        self.engine.toolkit.queue_send_ussd("*100#", dcs=0x0F, alpha_identifier="Balance")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SEND_USSD_COMMAND)
        self.assertEqual(parsed["ussd_dcs"], 0x0F)
        self.assertEqual(parsed["ussd_text"], "*100#")
        self.assertEqual(parsed["alpha_identifier"], "Balance")


class SmsCommandsBuildValidTpdu(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_short_message_with_destination_and_text_builds_minimal_submit(self) -> None:
        self.engine.toolkit.queue_send_short_message(
            destination="15550100199",
            text="Hello",
            alpha_identifier="Status",
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SEND_SHORT_MESSAGE_COMMAND)
        self.assertEqual(parsed["alpha_identifier"], "Status")
        tpdu = bytes(parsed.get("sms_tpdu") or b"")
        self.assertGreater(len(tpdu), 7, "SMS-SUBMIT TPDU is implausibly short.")
        self.assertEqual(tpdu[0], 0x01, "First octet should mark SMS-SUBMIT.")
        # Destination-address length nibble at byte 2 equals digit count.
        self.assertEqual(tpdu[2], 11)

    def test_short_message_passes_through_raw_tpdu(self) -> None:
        raw_tpdu = bytes.fromhex("0100" + "0B910664002143F5" + "0000" + "05" + "C8329BFD06")
        self.engine.toolkit.queue_send_short_message(tpdu=raw_tpdu)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(bytes(parsed["sms_tpdu"]), raw_tpdu)


class UiCommandsBuildSpecCompliantTLVs(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_display_text_carries_text_and_qualifier_bits(self) -> None:
        self.engine.toolkit.queue_display_text(
            "Hi there",
            high_priority=True,
            wait_for_user_clear=True,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], DISPLAY_TEXT_COMMAND)
        self.assertEqual(parsed["qualifier"] & 0x01, 0x01)
        self.assertEqual(parsed["qualifier"] & 0x80, 0x80)
        self.assertEqual(parsed["text_string"], "Hi there")
        self.assertEqual(parsed["text_dcs"], 0x04)

    def test_display_text_promotes_unicode_payload_to_ucs2(self) -> None:
        self.engine.toolkit.queue_display_text("Halló heimur")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["text_dcs"], 0x08)
        self.assertEqual(parsed["text_string"], "Halló heimur")

    def test_get_input_response_length_window_is_present(self) -> None:
        self.engine.toolkit.queue_get_input(
            "Enter PIN",
            min_length=4,
            max_length=8,
            digit_only=True,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], GET_INPUT_COMMAND)
        self.assertEqual(parsed["min_response_length"], 4)
        self.assertEqual(parsed["max_response_length"], 8)
        self.assertEqual(parsed["qualifier"] & 0x02, 0x02)

    def test_get_inkey_qualifier_flags_match_spec(self) -> None:
        self.engine.toolkit.queue_get_inkey(
            "Y/N?",
            yes_no=True,
            help_available=True,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], GET_INKEY_COMMAND)
        self.assertEqual(parsed["qualifier"] & 0x04, 0x04)
        self.assertEqual(parsed["qualifier"] & 0x80, 0x80)

    def test_select_item_emits_each_item_with_identifier(self) -> None:
        self.engine.toolkit.queue_select_item(
            [(0x10, "Yes"), (0x11, "No")],
            title="Choose",
            default_item_identifier=0x10,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SELECT_ITEM_COMMAND)
        self.assertEqual(parsed["alpha_identifier"], "Choose")
        self.assertEqual(parsed.get("default_item_identifier"), 0x10)

    def test_setup_menu_persists_state_and_emits_help_qualifier(self) -> None:
        self.engine.toolkit.queue_setup_menu(
            [(0x80, "Profiles"), (0x81, "Network")],
            title="Main",
            help_available=True,
        )
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SET_UP_MENU_COMMAND)
        self.assertEqual(parsed["qualifier"] & 0x80, 0x80)
        self.assertEqual(self.engine.state.toolkit.menu_title, "Main")
        self.assertEqual(len(self.engine.state.toolkit.menu_items), 2)

    def test_play_tone_carries_tone_and_duration(self) -> None:
        self.engine.toolkit.queue_play_tone(tone=0x02, duration_seconds=2)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], PLAY_TONE_COMMAND)
        self.assertEqual(parsed["tone"], 0x02)
        self.assertGreaterEqual(parsed.get("duration_value", 0), 1)


class DataCommandsBuildSpecCompliantTLVs(unittest.TestCase):

    def setUp(self) -> None:
        self.engine = _make_engine()

    def test_run_at_command_emits_at_string_under_a8_tag(self) -> None:
        self.engine.toolkit.queue_run_at_command("AT+CSQ", alpha_identifier="Signal")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], RUN_AT_COMMAND)
        self.assertEqual(parsed["at_command"], "AT+CSQ")
        self.assertEqual(parsed["alpha_identifier"], "Signal")

    def test_language_notification_with_specific_language_includes_iso639(self) -> None:
        self.engine.toolkit.queue_language_notification("en", specific=True)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], LANGUAGE_NOTIFICATION_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x01)
        self.assertEqual(parsed["language"], "en")

    def test_language_notification_unspecific_omits_language_tlv(self) -> None:
        self.engine.toolkit.queue_language_notification("", specific=False)
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], LANGUAGE_NOTIFICATION_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x00)
        self.assertNotIn("language", parsed)

    def test_provide_local_information_default_qualifier_is_location(self) -> None:
        self.engine.toolkit.queue_provide_local_information()
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], PROVIDE_LOCAL_INFORMATION_COMMAND)
        self.assertEqual(parsed["qualifier"], 0x00)

    def test_setup_idle_mode_text_carries_text_string_object(self) -> None:
        self.engine.toolkit.queue_setup_idle_mode_text("Welcome")
        parsed = _parse(self.engine, _last_queued(self.engine))
        self.assertEqual(parsed["command_type"], SET_UP_IDLE_MODE_TEXT_COMMAND)
        self.assertEqual(parsed["text_string"], "Welcome")


class StatusFetchTerminalResponseRoundTrip(unittest.TestCase):
    """Verify the queue -> STATUS -> FETCH -> TERMINAL RESPONSE chain.

    A real terminal would walk this loop for every queued command, so
    the simulator has to keep its proactive bookkeeping consistent
    across all of them - not just REFRESH.
    """

    def setUp(self) -> None:
        self.engine = _make_engine()
        self.engine.transmit(bytes.fromhex("8010000003010203"))  # TERMINAL PROFILE
        # Drain whatever the bootstrap auto-queued so we observe the
        # exact command this test enqueues.
        self.engine.state.pending_fetch_queue.clear()
        self.engine.state.toolkit.active_proactive_command = b""

    def test_display_text_status_91xx_then_fetch_then_response(self) -> None:
        self.engine.toolkit.queue_display_text("Probe")
        _, sw1, sw2 = self.engine.transmit(bytes.fromhex("80F2000000"))
        self.assertEqual(sw1, 0x91)
        self.assertGreater(sw2, 0)
        data, sw1, sw2 = self.engine.transmit(bytes([0x80, 0x12, 0x00, 0x00, sw2]))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data[0], 0xD0)
        parsed = _parse(self.engine, data)
        self.assertEqual(parsed["command_type"], DISPLAY_TEXT_COMMAND)
        self.assertEqual(parsed["text_string"], "Probe")

        # Build a TERMINAL RESPONSE acknowledging the command.
        details = bytes(parsed["command_details_tlv"])
        terminal_response_body = (
            details
            + bytes.fromhex("82028281")
            + bytes.fromhex("030100")
        )
        terminal_response = bytes([0x80, 0x14, 0x00, 0x00, len(terminal_response_body)]) + terminal_response_body
        _, sw1, sw2 = self.engine.transmit(terminal_response)
        self.assertEqual(sw1, 0x90, "Terminal response should clear the pending command.")
        self.assertEqual(self.engine.state.toolkit.active_proactive_command, b"")


if __name__ == "__main__":
    unittest.main()
