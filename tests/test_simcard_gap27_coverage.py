"""Coverage for EF.UST / EF.SPDI coherence:

``_encode_ef_ust_default`` advertises USIM service **51**
(Service Provider Display Information) and must seed the
matching backing EF. Per TS 31.102 §4.2.8 services **45** /
**46** are PNN / OPL; service **50** is "Reserved (and shall
be ignored)".

The simulator's EF.UST is kept honest with respect to its
actual file system:

* Drop service 50 (reserved) from ``enabled_services``.
* Add services 45 (PNN) and 46 (OPL); both EFs are already
  seeded under ``ADF.USIM`` (FIDs ``6FC5`` / ``6FC6``).
* Add EF.SPDI (`6FCD`) so service 51 has a backing EF, then
  keep service 51 enabled.

Default EF.SPDI content is ``A3 02 80 00`` -- an empty SPDI
list per §4.2.66 -- so a modem reading the EF before any
operator OTA gets a well-formed TLV scaffold instead of
``6A 82``.
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

    def _ust_service_enabled(self, ust: bytes, service: int) -> bool:
        byte_index = (service - 1) // 8
        bit_index = (service - 1) % 8
        if byte_index >= len(ust):
            return False
        return bool(ust[byte_index] & (1 << bit_index))


class UstServiceNumberCorrectionTests(_UsimEngineHarness):
    """Verify the UST correction matches TS 31.102 §4.2.8."""

    def test_pnn_and_opl_now_advertised(self) -> None:
        self._select_usim()
        self._select_ok("6F38")
        ust = self._read_binary(0x11)
        # Services 45 (PNN) and 46 (OPL) per TS 31.102 §4.2.8.
        self.assertTrue(
            self._ust_service_enabled(ust, 45),
            msg="UST service 45 (PNN) not advertised",
        )
        self.assertTrue(
            self._ust_service_enabled(ust, 46),
            msg="UST service 46 (OPL) not advertised",
        )

    def test_reserved_service_50_is_clear(self) -> None:
        self._select_usim()
        self._select_ok("6F38")
        ust = self._read_binary(0x11)
        # TS 31.102 §4.2.8 lists service 50 as "Reserved (and
        # shall be ignored)"; the simulator must not advertise it.
        self.assertFalse(
            self._ust_service_enabled(ust, 50),
            msg="UST service 50 (reserved) still advertised",
        )

    def test_spdi_service_51_still_advertised_with_backing(self) -> None:
        self._select_usim()
        self._select_ok("6F38")
        ust = self._read_binary(0x11)
        self.assertTrue(
            self._ust_service_enabled(ust, 51),
            msg="UST service 51 (SPDI) not advertised",
        )

    def test_psismsc_service_91_still_advertised(self) -> None:
        # Sanity check that the SM-over-IP advertisement is intact.
        self._select_usim()
        self._select_ok("6F38")
        ust = self._read_binary(0x11)
        self.assertTrue(
            self._ust_service_enabled(ust, 91),
            msg="UST service 91 (SM-over-IP) regression",
        )


class EfSpdiSeedTests(_UsimEngineHarness):
    """3GPP TS 31.102 §4.2.66 EF.SPDI default seed."""

    def test_default_is_empty_spdi_list(self) -> None:
        self._select_usim()
        self._select_ok("6FCD")
        body = self._read_binary(0x04)
        # A3 02 80 00 = SPDI list TLV containing an empty PLMN
        # list (inner 80 LL value of zero length).
        self.assertEqual(body, bytes((0xA3, 0x02, 0x80, 0x00)))

    def test_update_binary_persists_plmn_list(self) -> None:
        self._select_usim()
        self._select_ok("6FCD")
        # Two PLMNs (3 bytes BCD each) -> inner length 6.
        plmn_list = bytes.fromhex("00F11000F210")
        new_body = bytes((0xA3, 0x08, 0x80, 0x06)) + plmn_list
        apdu = bytes([0x00, 0xD6, 0x00, 0x00, len(new_body)]) + new_body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_binary(len(new_body)), new_body)


class UstSpdiServiceCoherenceTests(_UsimEngineHarness):
    """If EF.UST advertises service 51 (SPDI), EF.SPDI must be
    reachable -- otherwise a modem keying SP-display rules off
    the service bit walks straight into ``6A 82``.
    """

    def test_spdi_is_present(self) -> None:
        self._select_usim()
        self.assertEqual(
            self._select_ef("6FCD"), (0x90, 0x00),
            msg="EF.SPDI unreachable from ADF.USIM",
        )


if __name__ == "__main__":
    unittest.main()
