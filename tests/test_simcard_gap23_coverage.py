"""Twenty-third-pass gap-coverage suite for ISIM-side GBA EFs.

3GPP TS 31.103 §4.2.7 lists the ISIM Service Table; the
simulator advertises every service bit (`EF.IST = 0xFF`),
which means **service 2 (GBA)** is "available + activated".
Per §4.2.10 / §4.2.11 a card that flips service 2 on must
provide both EF.GBABP and EF.GBANL or every GBA bootstrap
attempt by the ME will hit ``6A 82``.

Round-23 seeds the missing pair under ``ADF.ISIM``:

* EF.GBABP (`6FD5`) -- transparent, six bytes
  (``80 00 81 00 82 00``). The three empty TLVs let a modem
  read a deterministic shape before any successful Ks_NAF
  derivation, then UPDATE BINARY over the placeholder once
  bootstrapping succeeds.
* EF.GBANL (`6FD7`) -- linear-fixed, single 28-byte all-FF
  record. The modem populates per-NAF rows via UPDATE RECORD.
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


class EfGbabpSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 §4.2.10 EF.GBABP seed."""

    def test_default_holds_three_empty_tlvs(self) -> None:
        self._select_isim()
        self._select_ef("6FD5")
        body = self._read_binary(0x06)
        # 80 00 (B-TID), 81 00 (Ks_NAF), 82 00 (Lifetime).
        self.assertEqual(body, bytes((0x80, 0x00, 0x81, 0x00, 0x82, 0x00)))

    def test_update_binary_round_trip(self) -> None:
        self._select_isim()
        self._select_ef("6FD5")
        # Stage a fake B-TID / Ks_NAF / Lifetime triplet.
        new_body = (
            bytes((0x80, 0x04)) + b"BTID"
            + bytes((0x81, 0x04)) + b"KEYZ"
            + bytes((0x82, 0x02)) + bytes((0x0E, 0x10))   # 3600 s lifetime
        )
        apdu = (
            bytes([0x00, 0xD6, 0x00, 0x00, len(new_body)])
            + new_body
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_binary(len(new_body)), new_body)


class EfGbanlSeedTests(_IsimEngineHarness):
    """3GPP TS 31.103 §4.2.11 EF.GBANL seed."""

    def test_default_record_is_28_bytes_of_ff(self) -> None:
        self._select_isim()
        self._select_ef("6FD7")
        record = self._read_record(record=1, length=28)
        self.assertEqual(record, b"\xFF" * 28)

    def test_update_record_persists_naf_pair(self) -> None:
        self._select_isim()
        self._select_ef("6FD7")
        new_record = b"NAF1" + b"\x00" * 8 + b"BTID-XYZ" + b"\xFF" * 8
        self.assertEqual(len(new_record), 28)
        apdu = (
            bytes([0x00, 0xDC, 0x01, 0x04, len(new_record)])
            + new_record
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_record(1, 28), new_record)


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
