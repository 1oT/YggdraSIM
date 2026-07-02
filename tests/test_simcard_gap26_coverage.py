# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Twenty-sixth-pass gap-coverage suite for EF.PSISMSC.

3GPP TS 31.102 §4.2.81 places ``EF.PSISMSC`` (FID ``6FE5``)
under ``ADF.USIM`` to publish the Public Service Identity of
the SM-SC used by SM-over-IP messaging (TS 23.204). The EF is
linear-fixed; each record carries a TLV-formatted SIP URI:

    Tag 0x80, length, type byte (0x00 = SIP/TEL URI),
    UTF-8 URI bytes, FF padding to a fixed 64-byte width.

EF.UST advertises this via **service 91 ("Support for
SM-over-IP")**. Modems keying SIP/IMS messaging discovery off
that service bit need both pieces -- otherwise discovery
falls back to a hard-coded vendor default (or fails outright
on locked builds). Round-26 closes the gap by enabling the
service bit and seeding a record rooted in the simulator's
reserved test PLMN (MCC 001 / MNC 01).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID


class _UsimEngineHarness(unittest.TestCase):
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

    def _select_ef(self, fid: str) -> tuple[int, int]:
        body = bytes.fromhex(fid)
        apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        return sw1, sw2

    def _select_ok(self, fid: str) -> None:
        self.assertEqual(self._select_ef(fid), (0x90, 0x00))

    def _read_binary(self, length: int) -> bytes:
        apdu = bytes([0x00, 0xB0, 0x00, 0x00, length & 0xFF])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data

    def _read_record(self, record: int, length: int) -> bytes:
        apdu = bytes([0x00, 0xB2, record & 0xFF, 0x04, length & 0xFF])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data


class EfPsismscSeedTests(_UsimEngineHarness):
    """3GPP TS 31.102 §4.2.81 EF.PSISMSC default seed."""

    def test_default_record_is_64_bytes_tlv(self) -> None:
        self._select_usim()
        self._select_ok("6FE5")
        record = self._read_record(record=1, length=64)
        self.assertEqual(len(record), 64)
        self.assertEqual(record[0], 0x80)              # tag
        body_length = record[1]
        self.assertGreater(body_length, 1)
        self.assertEqual(record[2], 0x00)              # SIP-URI type indicator
        # Remaining bytes after the TLV are FF padding.
        tlv_total = 2 + body_length
        self.assertEqual(record[tlv_total:], b"\xFF" * (64 - tlv_total))

    def test_default_record_carries_sip_uri(self) -> None:
        self._select_usim()
        self._select_ok("6FE5")
        record = self._read_record(record=1, length=64)
        body_length = record[1]
        uri_bytes = record[3:2 + body_length]          # skip tag, length, type
        uri_text = uri_bytes.decode("utf-8")
        self.assertTrue(
            uri_text.startswith("sip:"),
            msg=f"PSISMSC default URI is not a SIP URI: {uri_text!r}",
        )

    def test_update_record_persists_new_uri(self) -> None:
        self._select_usim()
        self._select_ok("6FE5")
        new_uri = b"sip:smsc.example.com"
        body = b"\x00" + new_uri
        tlv = bytes((0x80, len(body))) + body
        new_record = tlv + b"\xFF" * (64 - len(tlv))
        self.assertEqual(len(new_record), 64)
        apdu = (
            bytes([0x00, 0xDC, 0x01, 0x04, len(new_record) & 0xFF])
            + new_record
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_record(1, 64), new_record)


class UstSmOverIpServiceCoherenceTests(_UsimEngineHarness):
    """If EF.UST advertises service 91 (Support for SM-over-IP)
    the EF.PSISMSC backing must be reachable -- otherwise a
    modem keying SIP/IMS messaging discovery off the service
    bit walks straight into ``6A 82``.
    """

    def test_ust_advertises_sm_over_ip(self) -> None:
        self._select_usim()
        self._select_ok("6F38")
        ust = self._read_binary(0x11)
        # Service 91 lives in byte 11 (= (91-1) // 8) bit 2 (= (91-1) % 8).
        self.assertGreater(len(ust), 11)
        self.assertTrue(
            ust[11] & (1 << 2),
            msg="EF.UST service 91 (SM-over-IP support) not advertised",
        )

    def test_psismsc_is_present(self) -> None:
        self._select_usim()
        self.assertEqual(
            self._select_ef("6FE5"), (0x90, 0x00),
            msg="EF.PSISMSC unreachable from ADF.USIM",
        )


if __name__ == "__main__":
    unittest.main()
