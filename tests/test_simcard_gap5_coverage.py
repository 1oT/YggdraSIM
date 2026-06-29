# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Fifth-pass gap-coverage suite for SIMCARD surfaces beyond ES10.

The previous four passes closed:

* SGP.32 v1.2 / SGP.22 v3.1 ES10b/c command backlog.
* PIN lifecycle (CHANGE / DISABLE / ENABLE PIN) and GET CHALLENGE.
* GP GET DATA fingerprinting tags (CPLC, CRD, IIN, CIN).
* TS 31.111 / TS 102 223 envelope dispatch by tag.
* SAIP profile-header connectivity parameters.

This pass closes a different class of gaps -- behaviours that a real
UICC always exposes but the simulator was missing:

* ETSI TS 102 221 §11.1.13 / §11.1.14 file lifecycle commands
  (DEACTIVATE FILE / ACTIVATE FILE -- INS 0x04 / 0x44). The 8A
  byte in FCP must reflect the current state and READ/UPDATE
  must return ``62 83`` while a file is deactivated.
* ETSI TS 102 221 §11.1.7 SEARCH RECORD (INS 0xA2). Modems use
  this to look up entries in EF.SMS / EF.ADN without dragging
  every record across the wire.
* ETSI TS 102 221 §11.1.22 SUSPEND UICC (INS 0x76). LTE/NR
  modems issue this during DRX-extended sleep windows; the
  card returns an 8-byte resume token that must be quoted in
  the matching RESUME.
* GP Card Spec v2.3.1 Amendment B §H.6 GET DATA tag ``FF21``
  (Extended Card Resources). RAM management tools probe this
  before they issue INSTALL [for load] to size CAP files.
* ETSI TS 102 223 §6.4.26 LAUNCH BROWSER (proactive type 0x15).
  Bootstrap-OTA flows on consumer devices rely on this to
  redirect the browser to the operator portal.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.gp import GpLogic
from SIMCARD.state import SimCardState, SimScp03Session
from SIMCARD.toolkit import LAUNCH_BROWSER_COMMAND, ToolkitLogic
from SIMCARD.utils import read_tlv


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_root = Path(self._temp_dir.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(temp_root / "missing_quirks.py"),
            isdr_config_path=str(temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(temp_root / "euicc_store"),
            profile_store_path=str(temp_root / "profile_store"),
        )
        self._select_usim_adf()

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _select_usim_adf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _select_ef(self, fid_hex: str) -> bytes:
        fid = bytes.fromhex(fid_hex)
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA4, 0x00, 0x04, len(fid)]) + fid
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data

    @staticmethod
    def _fcp_lifecycle_byte(fcp_response: bytes) -> int | None:
        # SELECT response: 62 LL <FCP body>. Walk the body and grab the
        # 8A tag (life-cycle status) value. None when the tag is absent.
        outer_tag, outer_value, _raw, _next = read_tlv(fcp_response, 0)
        if outer_tag != b"\x62":
            return None
        offset = 0
        while offset < len(outer_value):
            tag, value, _raw_inner, offset = read_tlv(outer_value, offset)
            if tag == b"\x8A" and len(value) >= 1:
                return int(value[0])
        return None


class FileLifecycleTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.13 / §11.1.14 DEACTIVATE / ACTIVATE FILE."""

    def test_freshly_selected_ef_reports_lifecycle_05(self) -> None:
        fcp = self._select_ef("6F05")
        self.assertEqual(self._fcp_lifecycle_byte(fcp), 0x05)

    def test_deactivate_file_flips_lifecycle_byte_in_subsequent_select(self) -> None:
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0004000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fcp = self._select_ef("6F05")
        self.assertEqual(self._fcp_lifecycle_byte(fcp), 0x04)

    def test_read_binary_on_deactivated_ef_returns_6283(self) -> None:
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0004000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # The DEACTIVATE response left the cursor on EF.LI; a read must
        # now report "selected file invalidated" rather than the data.
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00B0000002"))
        self.assertEqual((sw1, sw2), (0x62, 0x83))

    def test_update_binary_on_deactivated_ef_returns_6283(self) -> None:
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0004000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xD6, 0x00, 0x00, 0x02]) + b"xx"
        )
        self.assertEqual((sw1, sw2), (0x62, 0x83))

    def test_activate_file_restores_lifecycle_05_and_reads(self) -> None:
        self._select_ef("6F05")
        self.engine.transmit(bytes.fromhex("0004000000"))
        # Re-select so the cursor is on the (still deactivated) node.
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0044000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fcp = self._select_ef("6F05")
        self.assertEqual(self._fcp_lifecycle_byte(fcp), 0x05)
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00B0000002"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"en")

    def test_deactivate_with_mf_selected_returns_6986(self) -> None:
        # 3F00 = MF. SELECT it via P1=0x00 P2=0x00 (default scope).
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("00A40000023F00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0004000000"))
        self.assertEqual((sw1, sw2), (0x69, 0x86))


class SearchRecordTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.7 SEARCH RECORD (INS 0xA2)."""

    def setUp(self) -> None:
        super().setUp()
        # EF.ECC is linear-fixed and ships with two records in the
        # default profile (`11F2FF00`, `19F1FF00`). Use it as a stable
        # search target -- modems do not typically search EF.ECC, but
        # we just need a linear-fixed EF whose records the test can
        # control deterministically.
        self._select_ef("6FB7")

    def test_simple_forward_search_returns_matching_record_numbers(self) -> None:
        # Pattern "F1" appears only in record 2.
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA2, 0x01, 0x04, 0x01]) + b"\xF1"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\x02")

    def test_simple_forward_search_matches_multiple_records(self) -> None:
        # Pattern "FF" appears in both records.
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA2, 0x01, 0x04, 0x01]) + b"\xFF"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(set(data), {0x01, 0x02})

    def test_simple_backward_search_walks_from_p1_down(self) -> None:
        # P2 mode 0x05 = backward simple, starting at record 2.
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA2, 0x02, 0x05, 0x01]) + b"\xFF"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(list(data), [0x02, 0x01])

    def test_no_match_returns_6a83(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA2, 0x01, 0x04, 0x01]) + b"\xAA"
        )
        self.assertEqual((sw1, sw2), (0x6A, 0x83))

    def test_empty_pattern_returns_6a80(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00A2010400")
        )
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

    def test_search_on_transparent_ef_returns_6981(self) -> None:
        # EF.LI (6F05) is transparent.
        self._select_ef("6F05")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA2, 0x01, 0x04, 0x01]) + b"e"
        )
        self.assertEqual((sw1, sw2), (0x69, 0x81))

    def test_search_on_deactivated_linear_fixed_returns_6283(self) -> None:
        # Cursor is on EF.ECC after setUp. Deactivate, then search.
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0004000000"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self._select_ef("6FB7")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA2, 0x01, 0x04, 0x01]) + b"\xF1"
        )
        self.assertEqual((sw1, sw2), (0x62, 0x83))


class SuspendUiccTests(_EngineHarness):
    """ETSI TS 102 221 §11.1.22 SUSPEND UICC (INS 0x76)."""

    def test_suspend_returns_negotiated_durations_and_8byte_token(self) -> None:
        # Body: 80 02 0001 (min=1) | 81 02 0014 (max=20). Le=00 = 256.
        body = bytes.fromhex("8002000181020014")
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x00, 0x00, len(body)]) + body + b"\x00"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # 80 02 <min> 81 02 <max> 82 08 <token>.
        self.assertEqual(data[:2], b"\x80\x02")
        self.assertEqual(int.from_bytes(data[2:4], "big"), 0x0001)
        self.assertEqual(data[4:6], b"\x81\x02")
        self.assertEqual(int.from_bytes(data[6:8], "big"), 0x0014)
        self.assertEqual(data[8:10], b"\x82\x08")
        token = data[10:18]
        self.assertEqual(len(token), 8)
        self.assertEqual(self.engine.state.last_suspend_token, token)
        self.assertEqual(self.engine.state.last_suspend_duration_seconds, 0x0014)

    def test_suspend_clamps_max_below_min_to_min(self) -> None:
        body = bytes.fromhex("8002001081020001")
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x00, 0x00, len(body)]) + body + b"\x00"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(int.from_bytes(data[2:4], "big"), 0x0010)
        self.assertEqual(int.from_bytes(data[6:8], "big"), 0x0010)

    def test_resume_with_correct_token_returns_9000_and_clears_state(self) -> None:
        body = bytes.fromhex("8002000181020014")
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x00, 0x00, len(body)]) + body + b"\x00"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        token = data[10:18]
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x01, 0x00, 0x08]) + token
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self.engine.state.last_suspend_token, b"")
        self.assertEqual(self.engine.state.last_suspend_duration_seconds, 0)

    def test_resume_with_wrong_token_returns_6985(self) -> None:
        body = bytes.fromhex("8002000181020014")
        self.engine.transmit(
            bytes([0x00, 0x76, 0x00, 0x00, len(body)]) + body + b"\x00"
        )
        bogus = b"\xDE\xAD\xBE\xEF\x00\x11\x22\x33"
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x01, 0x00, 0x08]) + bogus
        )
        self.assertEqual((sw1, sw2), (0x69, 0x85))
        # Token must remain so a second RESUME attempt with the right
        # value can still succeed; commercial cards do not invalidate
        # the resume context on a single mismatch.
        self.assertNotEqual(self.engine.state.last_suspend_token, b"")

    def test_resume_without_prior_suspend_returns_6985(self) -> None:
        bogus = b"\x00" * 8
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x01, 0x00, 0x08]) + bogus
        )
        self.assertEqual((sw1, sw2), (0x69, 0x85))

    def test_invalid_p2_returns_6a86(self) -> None:
        body = bytes.fromhex("8002000181020014")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x76, 0x00, 0x01, len(body)]) + body + b"\x00"
        )
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class GpExtendedCardResourcesTests(unittest.TestCase):
    """GP Card Spec v2.3.1 Amendment B §H.6 GET DATA ``FF21``."""

    def setUp(self) -> None:
        self.state = SimCardState(
            atr=b"",
            eid="89049032123451234512345678901234",
            iccid="8949000000000000001",
            imsi="999990000000001",
            default_dp_address="testsmdpplus.example.com",
            root_ci_pkid=b"",
        )
        self.state.scp03_session = SimScp03Session(key_version=0x30)
        self.gp = GpLogic(self.state)

    def test_ff21_returns_extended_card_resources_template(self) -> None:
        data, sw1, sw2 = self.gp.handle_get_data(0xFF, 0x21)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value, _raw, _next = read_tlv(data, 0)
        self.assertEqual(outer_tag, b"\xFF\x21")
        offset = 0
        seen: dict[bytes, bytes] = {}
        while offset < len(outer_value):
            tag, value, _raw_inner, offset = read_tlv(outer_value, offset)
            seen[tag] = value
        self.assertEqual(seen[b"\x81"], bytes([self.state.euicc_info.ext_card_resources.system_apps_count & 0xFF]))
        self.assertEqual(
            int.from_bytes(seen[b"\x82"], "big"),
            int(self.state.euicc_info.ext_card_resources.free_nvm),
        )
        self.assertEqual(
            int.from_bytes(seen[b"\x83"], "big"),
            int(self.state.euicc_info.ext_card_resources.free_ram),
        )

    def test_ff21_lengths_match_spec_widths(self) -> None:
        # 81 = 1 byte, 82 = 3 bytes, 83 = 2 bytes per Amendment B §H.6.
        data, _sw1, _sw2 = self.gp.handle_get_data(0xFF, 0x21)
        _outer_tag, outer_value, _raw, _next = read_tlv(data, 0)
        widths: dict[bytes, int] = {}
        offset = 0
        while offset < len(outer_value):
            tag, value, _raw_inner, offset = read_tlv(outer_value, offset)
            widths[tag] = len(value)
        self.assertEqual(widths[b"\x81"], 1)
        self.assertEqual(widths[b"\x82"], 3)
        self.assertEqual(widths[b"\x83"], 2)


class ToolkitLaunchBrowserTests(unittest.TestCase):
    """ETSI TS 102 223 §6.4.26 LAUNCH BROWSER queueing + parsing."""

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

    def test_queue_launch_browser_returns_queued_status(self) -> None:
        result = self.toolkit.queue_launch_browser(
            "http://otaprovision.example.com/start",
            alpha_identifier="OTA",
        )
        self.assertEqual(result["status"], "queued")
        self.assertEqual(result["mode"], "launch-browser")
        self.assertEqual(result["qualifier"], "02")
        self.assertGreaterEqual(int(result["pendingCount"]), 1)

    def test_fetch_returns_proactive_command_with_browser_identity_and_url(self) -> None:
        self.toolkit.queue_launch_browser(
            "http://otaprovision.example.com/start",
            browser_identity=0x00,
            alpha_identifier="OTA",
        )
        payload, sw1, sw2 = self.toolkit.handle_fetch()
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fields = self.toolkit._parse_proactive_command(payload)
        self.assertIsNotNone(fields)
        assert fields is not None
        self.assertEqual(fields["command_type"], LAUNCH_BROWSER_COMMAND)
        self.assertEqual(fields["qualifier"], 0x02)
        self.assertEqual(fields["browser_identity"], 0x00)
        self.assertEqual(fields["browser_url"], "http://otaprovision.example.com/start")
        self.assertEqual(fields["alpha_identifier"], "OTA")

    def test_fetch_carries_optional_gateway_proxy_when_supplied(self) -> None:
        self.toolkit.queue_launch_browser(
            "http://operator.example.com/lp",
            gateway_proxy="proxy.operator.example.com:8080",
        )
        payload, sw1, sw2 = self.toolkit.handle_fetch()
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        fields = self.toolkit._parse_proactive_command(payload)
        self.assertIsNotNone(fields)
        assert fields is not None
        self.assertEqual(
            fields["browser_gateway_proxy"],
            "proxy.operator.example.com:8080",
        )

    def test_qualifier_03_keeps_existing_browser_session(self) -> None:
        result = self.toolkit.queue_launch_browser(
            "http://second.example.com/",
            qualifier=0x03,
        )
        self.assertEqual(result["qualifier"], "03")
        payload, _sw1, _sw2 = self.toolkit.handle_fetch()
        fields = self.toolkit._parse_proactive_command(payload)
        assert fields is not None
        self.assertEqual(fields["qualifier"], 0x03)


if __name__ == "__main__":
    unittest.main()
