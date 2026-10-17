# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP03 CARD INFO, the identity probe and the GUI GetEID action show only a real EID.

SGP.22 v3.1 §5.7.20 GetEuiccDataResponse carries eidValue '5A' Octet16 inside
'BF3E'. A card may answer GetEID under a success status word with a BF3E body
that holds no EID; that body is neither shown as the eID nor used as the
inventory key, and it does not replace the EID the ECASD returned for
GET DATA '5A' (SGP.02 v4.2 §2.2.2).
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace

from SCP03.interface.shell import ShellDispatcher
from SCP03.logic.sgp22 import Sgp22Manager

# SGP.26 v3.0.2 §3.2.1 Table 5 test eUICC.
TEST_EID = "89049032123451234512345678901235"
SELECT_ECASD = "00A4040010A0000005591010FFFFFFFF8900000200"
GET_DATA_EID = "00CA005A00"
# A BF3E answer that carries no '5A', returned under a success status word.
NO_EID_BODY = bytes.fromhex("BF3E0380017F")


def _tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + bytes([len(value)]) + value


class _Transport:
    """Answer APDUs from a table; anything else is '6A 82'."""

    def __init__(self, answers: dict[str, tuple[bytes, int, int]]) -> None:
        self.answers = answers
        self.sent: list[str] = []
        self.connection = SimpleNamespace(getATR=lambda: [0x3B, 0x00])

    def reset(self) -> bool:
        return True

    def transmit(self, apdu_hex: str, silent: bool = False):
        self.sent.append(apdu_hex.upper())
        return self.answers.get(apdu_hex.upper(), (b"", 0x6A, 0x82))


class _ScriptedSgp22(Sgp22Manager):
    """ES10 answers from a table keyed by STORE DATA payload; anything else is '6A 88'."""

    def __init__(self, answers: dict[str, tuple[bytes, int, int]]) -> None:
        super().__init__(transport=None)
        self.answers = answers

    def _select_isd_r(self) -> None:
        return None

    def _send_store_data_with_retry_ladder(self, payload, *args, **kwargs):
        return self.answers.get(str(payload).upper(), (b"", 0x6A, 0x88))


def _shell(transport: _Transport, sgp22: _ScriptedSgp22) -> ShellDispatcher:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.transport = transport
    shell.gp_ctrl = SimpleNamespace(sgp22=sgp22)
    shell.fs_ctrl = SimpleNamespace(current_fid="7FFF")
    shell.current_iccid = ""
    shell.current_eid = ""
    shell.inventory_keys = []
    shell._read_live_iccid = lambda: ""
    shell._apply_inventory_profile_for_identifiers = (
        lambda _iccid, eid, announce=False: shell.inventory_keys.append(eid)
    )
    shell._clear_prompt_context_tracking = lambda: None
    return shell


def _ecasd_answers_eid() -> _Transport:
    return _Transport(
        {
            SELECT_ECASD: (b"", 0x90, 0x00),
            GET_DATA_EID: (_tlv("5A", bytes.fromhex(TEST_EID)), 0x90, 0x00),
        }
    )


def _ecasd_without_eid() -> _Transport:
    return _Transport({SELECT_ECASD: (b"", 0x90, 0x00)})


def _get_eid_without_eid() -> _ScriptedSgp22:
    return _ScriptedSgp22(
        {
            "BF3E035C015A": (NO_EID_BODY, 0x90, 0x00),
            "BF3E00": (NO_EID_BODY, 0x90, 0x00),
        }
    )


class CardInfoEidTests(unittest.TestCase):
    def _card_info(self, shell: ShellDispatcher) -> str:
        output = io.StringIO()
        with redirect_stdout(output):
            shell._print_card_info()
        return output.getvalue()

    def test_get_eid_without_eid_keeps_the_ecasd_value(self) -> None:
        shell = _shell(_ecasd_answers_eid(), _get_eid_without_eid())

        output = self._card_info(shell)

        self.assertIn(TEST_EID, output)
        self.assertNotIn(NO_EID_BODY.hex().upper(), output)
        self.assertEqual(shell.current_eid, TEST_EID)
        self.assertEqual(shell.inventory_keys, [TEST_EID])

    def test_no_eid_line_when_no_answer_carries_one(self) -> None:
        shell = _shell(_ecasd_without_eid(), _get_eid_without_eid())

        output = self._card_info(shell)

        self.assertNotIn("eID", output)
        self.assertNotIn(NO_EID_BODY.hex().upper(), output)
        self.assertEqual(shell.current_eid, "")
        self.assertEqual(shell.inventory_keys, [""])


class IdentityProbeEidTests(unittest.TestCase):
    def test_get_eid_without_eid_keeps_the_ecasd_value(self) -> None:
        shell = _shell(_ecasd_answers_eid(), _get_eid_without_eid())

        self.assertEqual(shell._probe_card_identity(), ("", TEST_EID))

    def test_answers_without_eid_yield_no_eid(self) -> None:
        shell = _shell(_ecasd_without_eid(), _get_eid_without_eid())

        self.assertEqual(shell._probe_card_identity(), ("", ""))


class GuiGetEidActionTests(unittest.TestCase):
    def _dispatch(self, sgp22: _ScriptedSgp22) -> dict:
        from unittest import mock

        from yggdrasim_common.gui_server.actions import scp03 as mod

        with (
            mock.patch.object(mod, "_get_scp03_session", lambda _sid: (None, None, "gui-1")),
            mock.patch.object(mod, "_get_or_make_gp_ctrl", lambda _session: SimpleNamespace(sgp22=sgp22)),
            mock.patch.object(mod, "_restore_fs_root_best_effort", lambda _session: {}),
        ):
            return mod._dispatch_get_eid(None, session_id="gui-1")

    def test_answer_without_eid_leaves_the_field_empty(self) -> None:
        result = self._dispatch(_get_eid_without_eid())

        self.assertEqual(result["eid"], "")
        self.assertEqual(result["sw"], "9000")
        self.assertIn("No EID in response: BF3E0380017F", result["trace"])

    def test_spec_answer_fills_the_field(self) -> None:
        sgp22 = _ScriptedSgp22(
            {"BF3E035C015A": (_tlv("BF3E", _tlv("5A", bytes.fromhex(TEST_EID))), 0x90, 0x00)}
        )

        result = self._dispatch(sgp22)

        self.assertEqual(result["eid"], TEST_EID)
        self.assertIn(TEST_EID, result["trace"])


if __name__ == "__main__":
    unittest.main()
