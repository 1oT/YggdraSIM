# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Twenty-third-pass gap-coverage suite for ISIM-side GBA EFs.

3GPP TS 31.103 v19 §4.2.7 lists the ISIM Service Table; the
simulator advertises **service 2 (GBA)**, so §4.2.9 / §4.2.10 have
it provide EF.GBABP and EF.GBANL under ``ADF.ISIM``:

* EF.GBABP (`6FD5`) -- transparent, length-prefixed RAND, B-TID and
  key lifetime fields, 'FF' before the first bootstrap (Annex C).
  The ISIM writes RAND when it bootstraps, the ME the B-TID and the
  lifetime.
* EF.GBANL (`6FD7`) -- linear-fixed, '80' NAF_ID / '81' B-TID records,
  'FF' at issue, UPDATE ADM: the ISIM fills them in NAF Derivation
  Mode.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import ISIM_AID
from SIMCARD.utils import tlv


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


class EfGbabpSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 v19 §4.2.9 EF.GBABP seed."""

    def test_default_is_unwritten(self) -> None:
        self._select_isim()
        self._select_ef("6FD5")
        body = self._read_binary(0x80)
        self.assertEqual(body, b"\xFF" * 0x80)

    def test_update_binary_round_trip(self) -> None:
        self._select_isim()
        self._select_ef("6FD5")
        # L RAND, RAND, L B-TID, B-TID, L key lifetime, key lifetime.
        rand = bytes(range(16))
        b_tid = b"AAECAwQFBgcICQoLDA0ODw==@bsf.example.test"
        lifetime = bytes.fromhex("00000E10")
        new_body = (
            bytes((len(rand),)) + rand
            + bytes((len(b_tid),)) + b_tid
            + bytes((len(lifetime),)) + lifetime
        )
        apdu = (
            bytes([0x00, 0xD6, 0x00, 0x00, len(new_body)])
            + new_body
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_binary(len(new_body)), new_body)


class EfGbanlSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 v19 §4.2.10 EF.GBANL seed."""

    def test_default_records_are_free(self) -> None:
        self._select_isim()
        self._select_ef("6FD7")
        for record in (1, 2):
            self.assertEqual(self._read_record(record=record, length=0x80), b"\xFF" * 0x80)

    def test_update_record_needs_adm(self) -> None:
        self._select_isim()
        self._select_ef("6FD7")
        new_record = tlv("80", b"naf.example.test" + bytes(5)) + tlv("81", b"btid@bsf.example.test")
        apdu = (
            bytes([0x00, 0xDC, 0x01, 0x04, len(new_record)])
            + new_record
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x69, 0x82))
        self.assertEqual(self._read_record(1, 0x80), b"\xFF" * 0x80)


class IsimGbaServiceCoherenceTests(_IsimEngineHarness):
    """If EF.IST advertises GBA (service 2) the supporting EFs
    must be reachable -- otherwise a real ME hits ``6A 82``
    on its first bootstrap.
    """

    def test_ist_advertises_gba(self) -> None:
        self._select_isim()
        self._select_ef("6F07")
        ist = self._read_binary(0x01)
        self.assertEqual(len(ist), 1)
        self.assertTrue(ist[0] & 0x02, msg="GBA service bit not set in EF.IST")

    def test_gba_supporting_efs_are_present(self) -> None:
        # If GBA is advertised but EF.GBABP / EF.GBANL are
        # missing, every bootstrap stalls. SELECT each EF and
        # assert the SW pair is 9000.
        for fid in ("6FD5", "6FD7"):
            self._select_isim()
            apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + bytes.fromhex(fid)
            _data, sw1, sw2 = self.engine.transmit(apdu)
            self.assertEqual(
                (sw1, sw2), (0x90, 0x00),
                msg=f"GBA EF {fid} unreachable from ADF.ISIM",
            )


if __name__ == "__main__":
    unittest.main()
