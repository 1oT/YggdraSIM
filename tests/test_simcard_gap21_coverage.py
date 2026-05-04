"""Coverage for the USIM Service Table coherence with voice / SMS EFs:

A modem that respects EF.UST (3GPP TS 31.102 §4.2.8) needs the
service bits for EF.LND, EF.ICI, EF.OCI, EF.SMS to be set or it
will not read those EFs. The corresponding service bits are
flipped to ON and two remaining linear-fixed EFs in the same
family are added:

* EF.SMSR (``6F47``) -- SMS Status Reports, linear-fixed, 30
  bytes per record. Service 11 in EF.UST.
* EF.SDN (``6F49``) -- Service Dialling Numbers, linear-fixed,
  22-byte records (8-byte alpha + 14-byte dial body). Service 4
  in EF.UST.

Existing 5G UST assertions (services 122 / 124 / 125 / 129 /
130) continue to pass because the update only *adds* bits.
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

    def _assert_service_enabled(self, ust: bytes, service: int) -> None:
        byte_index = (service - 1) // 8
        bit_index = (service - 1) % 8
        self.assertGreater(
            len(ust),
            byte_index,
            msg=f"EF.UST too short for service {service}",
        )
        self.assertTrue(
            ust[byte_index] & (1 << bit_index),
            msg=f"EF.UST service {service} not advertised",
        )


class UsimServiceTableTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.8 EF.UST advertised services."""

    def test_voice_sms_services_all_enabled(self) -> None:
        self._select_usim()
        self._select_ef("6F38")
        ust = self._read_binary(0x11)
        # Voice / SMS service bits whose backing EFs the simulator
        # seeds and whose envelopes it decodes.
        for service in (4, 8, 9, 10, 11, 12, 21, 30, 31, 55):
            self._assert_service_enabled(ust, service)

    def test_5g_attach_services_still_enabled(self) -> None:
        self._select_usim()
        self._select_ef("6F38")
        ust = self._read_binary(0x11)
        # Attach baseline. Services 45 / 46 are PNN / OPL per
        # TS 31.102 §4.2.8; service 50 is reserved and not set.
        for service in (19, 27, 33, 38, 45, 46, 51, 122, 124, 125, 126, 129, 130):
            self._assert_service_enabled(ust, service)


class EfSmsrSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.28 EF.SMSR default seed."""

    def test_default_record_is_30_bytes_unused(self) -> None:
        self._select_usim()
        self._select_ef("6F47")
        record = self._read_record(record=1, length=30)
        # Byte 0 = link-to-EF.SMS (0x00 = unused), bytes 1..29 = TPDU
        # padding (0xFF) per §4.2.28.
        self.assertEqual(record[0], 0x00)
        self.assertEqual(record[1:], b"\xFF" * 29)


class EfSdnSeedTests(_EngineHarness):
    """3GPP TS 31.102 §4.2.46 EF.SDN default seed."""

    def test_default_record_is_22_bytes_all_ff(self) -> None:
        self._select_usim()
        self._select_ef("6F49")
        record = self._read_record(record=1, length=22)
        self.assertEqual(record, b"\xFF" * 22)


if __name__ == "__main__":
    unittest.main()
