"""Twentieth-pass gap-coverage suite for SIMCARD default EFs.

Round-20 closes the call-history / SMS-storage EFs that real
USIMs always ship pre-allocated. Without these defaults a modem
boot-sequence read against any of these FIDs returns ``6A 82``
("file not found"), which short-circuits voice / SMS init flows
that depend on UPDATE RECORD round-trips:

* EF.ICI (``6F80``) -- 3GPP TS 31.102 §4.2.20 Incoming Call
  Information. Cyclic, 30 bytes per record (8-byte alpha plus
  22-byte body covering BCD number, timestamp, duration, status
  and phonebook-link).
* EF.OCI (``6F81``) -- TS 31.102 §4.2.21 Outgoing Call
  Information. Cyclic, same layout as EF.ICI (the unread-status
  byte is unused but the slot is preserved for FCP-driven
  length negotiation).
* EF.ICT (``6F82``) -- TS 31.102 §4.2.22 Incoming Call Timer.
  Cyclic, 3-byte BE cumulative-seconds counter.
* EF.OCT (``6F83``) -- TS 31.102 §4.2.23 Outgoing Call Timer.
  Cyclic, 3-byte BE cumulative-seconds counter.
* EF.SMS (``6F3C``) -- TS 31.102 §4.2.25 SMS storage.
  Linear-fixed, 176 bytes per record (1-byte status + 175-byte
  TPDU). Default seed: one free slot (status ``0x00`` + 0xFF
  TPDU padding).
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID


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

    def _read_record(self, record: int, length: int) -> bytes:
        # P2 = 0x04 absolute, current EF.
        apdu = bytes([0x00, 0xB2, record & 0xFF, 0x04, length & 0xFF])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data

    def _update_record_cyclic(self, payload: bytes) -> None:
        # P2 = 0x03 (PREVIOUS) is the only mode allowed on cyclic EFs.
        apdu = (
            bytes([0x00, 0xDC, 0x00, 0x03, len(payload) & 0xFF])
            + payload
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class EfIciSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.20 EF.ICI default seed."""

    def test_default_record_is_30_bytes_all_ff(self) -> None:
        self._select_usim()
        self._select_ef("6F80")
        record = self._read_record(record=1, length=30)
        self.assertEqual(record, b"\xFF" * 30)

    def test_cyclic_update_writes_new_head(self) -> None:
        self._select_usim()
        self._select_ef("6F80")
        new_entry = b"\xAA" * 30
        self._update_record_cyclic(new_entry)
        record = self._read_record(record=1, length=30)
        self.assertEqual(record, new_entry)


class EfOciSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.21 EF.OCI default seed."""

    def test_default_record_is_30_bytes_all_ff(self) -> None:
        self._select_usim()
        self._select_ef("6F81")
        record = self._read_record(record=1, length=30)
        self.assertEqual(record, b"\xFF" * 30)


class EfIctSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.22 EF.ICT default seed."""

    def test_timer_starts_at_zero(self) -> None:
        self._select_usim()
        self._select_ef("6F82")
        record = self._read_record(record=1, length=3)
        self.assertEqual(record, bytes((0x00, 0x00, 0x00)))


class EfOctSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.23 EF.OCT default seed."""

    def test_timer_starts_at_zero(self) -> None:
        self._select_usim()
        self._select_ef("6F83")
        record = self._read_record(record=1, length=3)
        self.assertEqual(record, bytes((0x00, 0x00, 0x00)))


class EfSmsSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.25 EF.SMS default seed."""

    def test_default_record_is_free_slot(self) -> None:
        self._select_usim()
        self._select_ef("6F3C")
        record = self._read_record(record=1, length=176)
        self.assertEqual(record[0], 0x00)
        self.assertEqual(record[1:], b"\xFF" * 175)

    def test_update_record_overwrites_slot(self) -> None:
        self._select_usim()
        self._select_ef("6F3C")
        new_record = bytes((0x01,)) + bytes(range(175))
        # Linear-fixed UPDATE RECORD: P1 = record id, P2 = 0x04.
        apdu = bytes([0x00, 0xDC, 0x01, 0x04, 0xB0]) + new_record
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        readback = self._read_record(record=1, length=176)
        self.assertEqual(readback, new_record)


if __name__ == "__main__":
    unittest.main()
