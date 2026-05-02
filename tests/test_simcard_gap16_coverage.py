"""Coverage for TS 102 223 user-facing TR-side latches (DISPLAY TEXT / GET INKEY / GET INPUT / SELECT ITEM / SET UP MENU / SET UP IDLE MODE TEXT):

* ETSI TS 102 223 §6.4.1 ``DISPLAY TEXT`` -- result code only.
* ETSI TS 102 223 §6.4.2 ``GET INKEY`` -- result + decoded char
  from TLV ``0D`` / ``8D``.
* ETSI TS 102 223 §6.4.3 ``GET INPUT`` -- result + decoded text
  from TLV ``0D`` / ``8D``.
* ETSI TS 102 223 §6.4.4 ``SELECT ITEM`` -- result + chosen item
  identifier from TLV ``10`` / ``90``.
* ETSI TS 102 223 §6.4.5 ``SET UP MENU`` -- result code only.
* ETSI TS 102 223 §6.4.20 ``SET UP IDLE MODE TEXT`` -- result
  code only.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    DISPLAY_TEXT_COMMAND,
    GET_INKEY_COMMAND,
    GET_INPUT_COMMAND,
    SELECT_ITEM_COMMAND,
    SET_UP_IDLE_MODE_TEXT_COMMAND,
    SET_UP_MENU_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv

del Path  # only imported for parity with sibling suites


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


def _text_string_tlv_8bit(text: str) -> bytes:
    return tlv("8D", b"\x04" + text.encode("ascii"))


def _text_string_tlv_ucs2(text: str) -> bytes:
    return tlv("8D", b"\x08" + text.encode("utf-16-be"))


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
        self._td = tempfile.TemporaryDirectory()

    def tearDown(self) -> None:
        self._td.cleanup()


class DisplayTextTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.1 DISPLAY TEXT TR latch."""

    def test_success_records_result_zero(self) -> None:
        result = self.toolkit.queue_display_text("Hello")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=DISPLAY_TEXT_COMMAND,
            qualifier=qualifier,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_display_text_result, 0x00)

    def test_user_back_records_result_0x11(self) -> None:
        result = self.toolkit.queue_display_text("Bye")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=DISPLAY_TEXT_COMMAND,
            qualifier=qualifier,
            result_code=0x11,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_display_text_result, 0x11)


class GetInkeyTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.2 GET INKEY TR latch."""

    def test_typed_character_decoded(self) -> None:
        result = self.toolkit.queue_get_inkey("Pick a key")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_INKEY_COMMAND,
            qualifier=qualifier,
            extra=_text_string_tlv_8bit("Y"),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_get_inkey_result, 0x00)
        self.assertEqual(toolkit.last_get_inkey_text, "Y")
        self.assertEqual(toolkit.last_get_inkey_dcs, 0x04)

    def test_no_response_does_not_clobber_prior_text(self) -> None:
        # Seed a prior good value.
        self.state.toolkit.last_get_inkey_text = "X"
        result = self.toolkit.queue_get_inkey("Pick")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_INKEY_COMMAND,
            qualifier=qualifier,
            result_code=0x12,
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_get_inkey_result, 0x12)
        self.assertEqual(toolkit.last_get_inkey_text, "X")


class GetInputTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.3 GET INPUT TR latch."""

    def test_typed_string_decoded(self) -> None:
        result = self.toolkit.queue_get_input("PIN?")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_INPUT_COMMAND,
            qualifier=qualifier,
            extra=_text_string_tlv_8bit("1234"),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_get_input_result, 0x00)
        self.assertEqual(toolkit.last_get_input_text, "1234")
        self.assertEqual(toolkit.last_get_input_dcs, 0x04)

    def test_ucs2_input_decoded(self) -> None:
        result = self.toolkit.queue_get_input("Name?", ucs2=True)
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=GET_INPUT_COMMAND,
            qualifier=qualifier,
            extra=_text_string_tlv_ucs2("\u00e9clat"),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_get_input_text, "\u00e9clat")
        self.assertEqual(toolkit.last_get_input_dcs, 0x08)


class SelectItemTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.4 SELECT ITEM TR latch."""

    def test_chosen_id_recorded(self) -> None:
        items = [(1, "First"), (2, "Second"), (3, "Third")]
        result = self.toolkit.queue_select_item(items, title="Choose")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SELECT_ITEM_COMMAND,
            qualifier=qualifier,
            extra=tlv("90", bytes((0x02,))),
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_select_item_result, 0x00)
        self.assertEqual(toolkit.last_select_item_id, 0x02)

    def test_back_response_does_not_overwrite_id(self) -> None:
        self.state.toolkit.last_select_item_id = 0x07
        items = [(1, "Only")]
        result = self.toolkit.queue_select_item(items)
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SELECT_ITEM_COMMAND,
            qualifier=qualifier,
            result_code=0x11,
        )
        self.toolkit.handle_terminal_response(tr)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_select_item_result, 0x11)
        self.assertEqual(toolkit.last_select_item_id, 0x07)


class SetUpMenuAndIdleTextTrLatchTests(_ToolkitHarness):
    """ETSI TS 102 223 §6.4.8 / §6.4.20 simple TR latches."""

    def test_set_up_menu_records_result(self) -> None:
        items = [(1, "Alpha"), (2, "Beta")]
        result = self.toolkit.queue_setup_menu(items, title="Menu")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_MENU_COMMAND,
            qualifier=qualifier,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_set_up_menu_result, 0x00)

    def test_set_up_menu_failure_records_result(self) -> None:
        items = [(1, "Alpha")]
        result = self.toolkit.queue_setup_menu(items)
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_MENU_COMMAND,
            qualifier=qualifier,
            result_code=0x32,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(self.state.toolkit.last_set_up_menu_result, 0x32)

    def test_idle_mode_text_records_result(self) -> None:
        result = self.toolkit.queue_setup_idle_mode_text("Ready")
        cmd = int(result["commandNumber"])
        qualifier = int(result["qualifier"])
        self.toolkit.handle_fetch()
        tr = _terminal_response(
            command_number=cmd,
            command_type=SET_UP_IDLE_MODE_TEXT_COMMAND,
            qualifier=qualifier,
        )
        self.toolkit.handle_terminal_response(tr)
        self.assertEqual(
            self.state.toolkit.last_set_up_idle_mode_text_result, 0x00
        )


if __name__ == "__main__":
    unittest.main()
