# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Twenty-fourth-pass gap-coverage suite for ISIM SMS storage.

3GPP TS 31.103 §4.2.7 lays out the ISIM Service Table, and the
simulator advertises every bit (`EF.IST = 0xFF`):

    bit 6 = service 6: SMS storage in ISIM
    bit 7 = service 7: SMS status reports in ISIM
    bit 8 = service 8: SM-over-IP support indication

Round-23 closed the GBA pair (services 2 / 4); round-24 closes
the SMS-side coherence gap. Without these EFs, a modem that
keys SMS storage off the ISIM service table walks straight into
``6A 82`` on every SMS-MO/MT save.

| FID  | Name    | Structure        | Default                           |
| ---- | ------- | ---------------- | --------------------------------- |
| 6F3C | EF.SMS  | linear-fixed 176 | 0x00 status + 175 byte FF pad     |
| 6F43 | EF.SMSS | transparent  2   | 0x00 last-MR + 0xFF cap-exceeded  |
| 6F47 | EF.SMSR | linear-fixed 30  | 0x00 link + 29 byte FF pad        |

Same record encoders are reused as the USIM-side seeds, so the
modem sees identical defaults regardless of which app stores a
given message.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import ISIM_AID


class _IsimEngineHarness(unittest.TestCase):
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

    def _select_isim(self) -> None:
        aid_bytes = bytes.fromhex(ISIM_AID)
        body = bytes((len(aid_bytes),)) + aid_bytes
        apdu = bytes([0x00, 0xA4, 0x04, 0x04]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _select_ef(self, fid: str) -> None:
        body = bytes.fromhex(fid)
        apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

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


class EfIsimSmsSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 §4.2.13 EF.SMS default seed under ADF.ISIM."""

    def test_default_record_is_176_bytes(self) -> None:
        self._select_isim()
        self._select_ef("6F3C")
        record = self._read_record(record=1, length=176)
        self.assertEqual(len(record), 176)
        self.assertEqual(record[0], 0x00)
        self.assertEqual(record[1:], b"\xFF" * 175)

    def test_update_record_persists_status_and_tpdu(self) -> None:
        self._select_isim()
        self._select_ef("6F3C")
        new_record = bytes((0x01,)) + b"TP" + b"\xFF" * (176 - 3)
        self.assertEqual(len(new_record), 176)
        apdu = (
            bytes([0x00, 0xDC, 0x01, 0x04, len(new_record) & 0xFF])
            + new_record
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_record(1, 176), new_record)


class EfIsimSmssSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 §4.2.14 EF.SMSS default seed under ADF.ISIM."""

    def test_default_two_bytes(self) -> None:
        self._select_isim()
        self._select_ef("6F43")
        body = self._read_binary(0x02)
        self.assertEqual(body, bytes((0x00, 0xFF)))

    def test_update_binary_round_trip(self) -> None:
        self._select_isim()
        self._select_ef("6F43")
        new_body = bytes((0x42, 0x00))
        apdu = bytes([0x00, 0xD6, 0x00, 0x00, 0x02]) + new_body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_binary(0x02), new_body)


class EfIsimSmsrSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 §4.2.15 EF.SMSR default seed under ADF.ISIM."""

    def test_default_record_is_30_bytes(self) -> None:
        self._select_isim()
        self._select_ef("6F47")
        record = self._read_record(record=1, length=30)
        self.assertEqual(len(record), 30)
        self.assertEqual(record[0], 0x00)
        self.assertEqual(record[1:], b"\xFF" * 29)


class IsimSmsServiceCoherenceTests(_IsimEngineHarness):
    """If EF.IST advertises SMS storage / status reports, the
    backing EFs must be reachable so a modem keying SMS storage
    off the service table never hits ``6A 82``.
    """

    def test_ist_advertises_sms_services(self) -> None:
        self._select_isim()
        self._select_ef("6F07")
        ist = self._read_binary(0x01)
        self.assertEqual(len(ist), 1)
        # Bit 6 = service 6 (SMS storage), bit 7 = service 7 (SMSR).
        self.assertTrue(ist[0] & 0x20, msg="SMS storage bit not set in EF.IST")
        self.assertTrue(ist[0] & 0x40, msg="SMSR bit not set in EF.IST")

    def test_sms_supporting_efs_are_present(self) -> None:
        for fid in ("6F3C", "6F43", "6F47"):
            self._select_isim()
            apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + bytes.fromhex(fid)
            _data, sw1, sw2 = self.engine.transmit(apdu)
            self.assertEqual(
                (sw1, sw2), (0x90, 0x00),
                msg=f"ISIM SMS EF {fid} unreachable from ADF.ISIM",
            )


if __name__ == "__main__":
    unittest.main()
