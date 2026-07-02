# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Twenty-second-pass gap-coverage suite for the call-forwarding
and EHPLMN-presentation EFs.

Round-22 closes two USIM EFs that real cards always pre-allocate
but the simulator was returning ``6A 82`` (file not found) for:

* EF.EHPLMNPI (``6FDB``) -- 3GPP TS 31.102 §4.2.84 Equivalent
  HPLMN Presentation Indication. Single transparent byte; bit 1
  set means "display every EHPLMN", cleared means "display
  HPLMN only" (default behaviour, matches what most operators
  ship). Service 71 in EF.UST.
* EF.CFIS (``6FCB``) -- TS 31.102 §4.2.64 Call Forwarding
  Indication Status. Linear-fixed, 16 bytes per record:

      Byte  0     MSP ID (default 0x01 = profile 1)
      Byte  1     CFU indicator status (bit 1 = active; default 0x00)
      Byte  2     TON / NPI byte (placeholder 0xFF)
      Bytes 3..13 BCD-encoded forwarding-to dialling number (placeholder)
      Byte 14     CCP record id (0xFF = none)
      Byte 15     Ext7 record id (0xFF = none)

  Service 49 in EF.UST.

Both UST bits are flipped on so a modem that gates EF reads on
the service table actually issues the SELECT / READ.
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

    def _ust_service_enabled(self, service: int) -> bool:
        self._select_usim()
        self._select_ef("6F38")
        ust = self._read_binary(0x11)
        byte_index = (service - 1) // 8
        bit_index = (service - 1) % 8
        if byte_index >= len(ust):
            return False
        return bool(ust[byte_index] & (1 << bit_index))


class EfEhplmnPiSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.84 EF.EHPLMNPI default seed."""

    def test_default_byte_is_zero(self) -> None:
        self._select_usim()
        self._select_ef("6FDB")
        body = self._read_binary(0x01)
        self.assertEqual(body, bytes((0x00,)))

    def test_ust_service_71_enabled(self) -> None:
        self.assertTrue(
            self._ust_service_enabled(71),
            msg="EF.UST service 71 (EHPLMN PI) not advertised",
        )

    def test_update_binary_persists_presentation_bit(self) -> None:
        self._select_usim()
        self._select_ef("6FDB")
        # Set bit 1 = display every EHPLMN.
        apdu = bytes([0x00, 0xD6, 0x00, 0x00, 0x01, 0x01])
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_binary(0x01), bytes((0x01,)))


class EfCfisSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.64 EF.CFIS default seed."""

    def test_default_record_is_16_bytes(self) -> None:
        self._select_usim()
        self._select_ef("6FCB")
        record = self._read_record(record=1, length=16)
        # Byte 0 = MSP ID 0x01, byte 1 = CFU off (0x00), bytes 2..13 = FF
        # placeholders, bytes 14..15 = FF (CCP / Ext7 record ids).
        self.assertEqual(len(record), 16)
        self.assertEqual(record[0], 0x01)
        self.assertEqual(record[1], 0x00)
        self.assertEqual(record[2:14], b"\xFF" * 12)
        self.assertEqual(record[14:], b"\xFF\xFF")

    def test_ust_service_49_enabled(self) -> None:
        self.assertTrue(
            self._ust_service_enabled(49),
            msg="EF.UST service 49 (CFIS) not advertised",
        )

    def test_update_record_activates_cfu(self) -> None:
        self._select_usim()
        self._select_ef("6FCB")
        # Activate CFU forwarding to "1234567" (7 BCD digits => 4
        # packed bytes; length byte = 1 + 4 = 5 covering TON/NPI
        # plus the BCD body per TS 31.102 §4.2.64).
        new_record = (
            bytes((0x01, 0x01))                       # MSP ID + CFU active
            + bytes((0x05,))                          # Length of BCD body
            + bytes((0x91,))                          # TON/NPI international
            + bytes.fromhex("21436587FFFFFFFFFFFF")    # BCD digits + padding (10 B)
            + bytes((0xFF,))                          # CCP id none
            + bytes((0xFF,))                          # Ext7 id none
        )
        self.assertEqual(len(new_record), 16)
        apdu = (
            bytes([0x00, 0xDC, 0x01, 0x04, len(new_record)])
            + new_record
        )
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        readback = self._read_record(record=1, length=16)
        self.assertEqual(readback, new_record)


if __name__ == "__main__":
    unittest.main()
