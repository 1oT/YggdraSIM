"""Coverage for SIMCARD operator-side envelope decoders and EF.LND seed:

* 3GPP TS 31.111 §7.3.1.1 ``Call Control by USIM`` (root tag
  ``D4``). The simulator extracts the dialled-number Address TLV
  (``06`` / ``86``), the optional Capability Configuration
  Parameters (``07`` / ``87``), the Sub-Address (``08`` / ``88``)
  and the Location Information (``13`` / ``93``).
* 3GPP TS 31.111 §7.3.2.1 ``MO Short Message Control`` (``D5``).
  The two Address TLVs in the envelope (RP-DA destination first,
  RP-OA SC second per §7.3.2.2) plus Location Information are
  decoded into ``state.toolkit``.
* 3GPP TS 31.111 §7.3.3 ``USSD Download`` (``D8``). The USSD
  String TLV (``8A`` / ``0A``) is split into DCS + raw bytes +
  best-effort decoded text.

``EF.LND`` (``6F44``) is also seeded as a cyclic EF with one
all-FF record so READ RECORD against the empty slot returns
deterministic data instead of ``6A 83``.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.state import SimCardState
from SIMCARD.toolkit import ToolkitLogic
from SIMCARD.utils import tlv


def _envelope(root_tag: bytes, *body: bytes) -> bytes:
    joined = b"".join(body)
    return bytes((root_tag[0], len(joined))) + joined


def _fallback(payload: bytes) -> tuple[bytes, int, int]:
    del payload
    return b"", 0x90, 0x00


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


class CallControlEnvelopeTests(_ToolkitHarness):
    """3GPP TS 31.111 §7.3.1.1 Call Control by USIM (D4)."""

    def test_dialled_number_decoded(self) -> None:
        # Address TLV: TON/NPI 0x91 + BCD digits "0123456789".
        address = bytes.fromhex("91") + bytes.fromhex("1032547698")
        envelope = _envelope(
            b"\xD4",
            tlv("82", bytes((0x82, 0x81))),
            tlv("86", address),
        )
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, bytes.fromhex("800100"))
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_cc_address, "0123456789")
        self.assertEqual(toolkit.last_cc_address_ton_npi, 0x91)
        self.assertEqual(toolkit.cc_envelopes_received, 1)

    def test_subaddress_and_capability_params_latched(self) -> None:
        address = bytes.fromhex("91") + bytes.fromhex("21436587F9")
        sub_addr = bytes.fromhex("AABBCC")
        cap_params = bytes.fromhex("0102030405")
        envelope = _envelope(
            b"\xD4",
            tlv("82", bytes((0x82, 0x81))),
            tlv("86", address),
            tlv("87", cap_params),
            tlv("88", sub_addr),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_cc_address, "123456789")
        self.assertEqual(toolkit.last_cc_subaddress, sub_addr)
        self.assertEqual(toolkit.last_cc_capability_params, cap_params)

    def test_location_information_latched(self) -> None:
        # Location info: MCC/MNC + LAC + CI (typical 8 bytes).
        location_info = bytes.fromhex("21F4030001AABB1234")
        envelope = _envelope(
            b"\xD4",
            tlv("82", bytes((0x82, 0x81))),
            tlv("86", bytes.fromhex("9112")),
            tlv("93", location_info),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual(
            self.state.toolkit.last_cc_location_information,
            location_info,
        )

    def test_counter_increments_per_envelope(self) -> None:
        envelope = _envelope(
            b"\xD4",
            tlv("82", bytes((0x82, 0x81))),
            tlv("86", bytes.fromhex("9132")),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        self.toolkit.handle_envelope(envelope, _fallback)
        self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual(self.state.toolkit.cc_envelopes_received, 3)


class MoSmsControlEnvelopeTests(_ToolkitHarness):
    """3GPP TS 31.111 §7.3.2.1 MO Short Message Control (D5)."""

    def test_destination_and_sc_addresses_decoded(self) -> None:
        rp_da = bytes.fromhex("91") + bytes.fromhex("1032547698")
        rp_oa = bytes.fromhex("91") + bytes.fromhex("214365F9")
        envelope = _envelope(
            b"\xD5",
            tlv("82", bytes((0x82, 0x81))),
            tlv("86", rp_da),
            tlv("86", rp_oa),
        )
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, bytes.fromhex("800100"))
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_mo_sms_destination_address, "0123456789")
        self.assertEqual(toolkit.last_mo_sms_destination_ton_npi, 0x91)
        self.assertEqual(toolkit.last_mo_sms_sc_address, "1234569")
        self.assertEqual(toolkit.last_mo_sms_sc_ton_npi, 0x91)
        self.assertEqual(toolkit.mo_sms_envelopes_received, 1)

    def test_location_information_latched(self) -> None:
        location_info = bytes.fromhex("12F300010102FF")
        envelope = _envelope(
            b"\xD5",
            tlv("82", bytes((0x82, 0x81))),
            tlv("86", bytes.fromhex("911234")),
            tlv("86", bytes.fromhex("915678")),
            tlv("93", location_info),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual(
            self.state.toolkit.last_mo_sms_location_information,
            location_info,
        )


class UssdDownloadEnvelopeTests(_ToolkitHarness):
    """3GPP TS 31.111 §7.3.3 USSD Download (D8)."""

    def test_8bit_text_decoded(self) -> None:
        # DCS 0x04 = 8-bit ASCII; payload = "*100#" reply text.
        ussd_body = b"\x04" + b"Welcome"
        envelope = _envelope(
            b"\xD8",
            tlv("82", bytes((0x82, 0x81))),
            tlv("8A", ussd_body),
        )
        data, sw1, sw2 = self.toolkit.handle_envelope(envelope, _fallback)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, bytes.fromhex("800100"))
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_ussd_download_dcs, 0x04)
        self.assertEqual(toolkit.last_ussd_download_text, "Welcome")
        self.assertEqual(toolkit.last_ussd_download_raw, b"Welcome")
        self.assertEqual(toolkit.ussd_downloads_received, 1)

    def test_ucs2_text_decoded(self) -> None:
        # DCS 0x08 = UCS-2/BE.
        text = "Héllo"
        ussd_body = b"\x08" + text.encode("utf-16-be")
        envelope = _envelope(
            b"\xD8",
            tlv("82", bytes((0x82, 0x81))),
            tlv("8A", ussd_body),
        )
        self.toolkit.handle_envelope(envelope, _fallback)
        toolkit = self.state.toolkit
        self.assertEqual(toolkit.last_ussd_download_dcs, 0x08)
        self.assertEqual(toolkit.last_ussd_download_text, text)
        self.assertEqual(toolkit.last_ussd_download_raw, text.encode("utf-16-be"))


class _EngineHarness(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self._root = Path(self._td.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(self._root / "missing_quirks.py"),
            isdr_config_path=str(self._root / "missing_isdr.json"),
            sim_eim_identity_path=str(self._root / "missing_eim_identity.json"),
            euicc_store_root=str(self._root / "euicc"),
            profile_store_path=str(self._root / "profile_store"),
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    def _select_usim(self) -> None:
        aid_bytes = bytes.fromhex(USIM_AID)
        body = bytes((len(aid_bytes),)) + aid_bytes
        apdu = bytes([0x00, 0xA4, 0x04, 0x04]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _select_ef(self, fid: str) -> None:
        body = bytes.fromhex(fid)
        apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class EfLndSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.32 EF.LND default seed."""

    def test_ef_lnd_present_with_one_record(self) -> None:
        self._select_usim()
        self._select_ef("6F44")
        # READ RECORD #1 (P1=01, P2=04 = current EF + absolute mode).
        apdu = bytes([0x00, 0xB2, 0x01, 0x04, 0x16])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\xFF" * 22)

    def test_cyclic_read_record_p1_zero_returns_current(self) -> None:
        # TS 102 221 §11.1.5: P1=00 mode 0x04 on cyclic EF means
        # "current record" = most-recent slot.
        self._select_usim()
        self._select_ef("6F44")
        apdu = bytes([0x00, 0xB2, 0x00, 0x04, 0x16])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\xFF" * 22)

    def test_cyclic_update_record_mode_03_rotates_ring(self) -> None:
        # TS 102 221 §11.1.6: UPDATE RECORD on cyclic uses mode
        # 0x03 (previous). New record becomes the most-recent.
        self._select_usim()
        self._select_ef("6F44")
        new_record = bytes.fromhex("AA" * 22)
        apdu = (
            bytes([0x00, 0xDC, 0x00, 0x03, len(new_record)])
            + new_record
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Read it back via P1=00 (current record).
        apdu_read = bytes([0x00, 0xB2, 0x00, 0x04, 0x16])
        data, sw1, sw2 = self.engine.transmit(apdu_read)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, new_record)

    def test_cyclic_update_record_mode_04_rejected(self) -> None:
        # Absolute UPDATE on a cyclic EF must be rejected per
        # §11.1.6 ("not allowed for cyclic structure").
        self._select_usim()
        self._select_ef("6F44")
        apdu = bytes([0x00, 0xDC, 0x01, 0x04, 0x01]) + b"\x55"
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x69, 0x81))


if __name__ == "__main__":
    unittest.main()
