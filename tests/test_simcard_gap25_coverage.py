"""Twenty-fifth-pass gap-coverage suite for DF.GSM-ACCESS.

3GPP TS 31.102 §4.4.3 places ``DF.GSM-ACCESS`` under
``ADF.USIM`` at FID ``5F3B``. The DF caches the GSM /
GPRS ciphering keys a modem reuses on inter-RAT fallback
(5G/4G -> 2G/2.5G). EF.UST advertises **service 27 ("GSM
access")**, so a spec-conformant card MUST also expose at
least EF.Kc and EF.KcGPRS or every Kc fetch trips ``6A 82``.

Round-25 closes that coherence gap with the same pattern
rounds 23/24 used for the ISIM IST coherence:

* `5F3B` DF.GSM-ACCESS
* `4F20` EF.Kc       transparent, 9 bytes (8-byte Kc + 1-byte CKSN).
* `4F52` EF.KcGPRS   transparent, 9 bytes (same layout).

Default contents are 8x 0x00 + CKSN ``0x07`` (= "no key set"
per TS 24.008 §10.5.1.2) so the modem always re-runs AKA
before encrypting traffic on a freshly issued card.
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

    def _select_by_fid(self, fid: str) -> tuple[int, int]:
        body = bytes.fromhex(fid)
        # P1=0x00, P2=0x04 => "select by file ID, return FCP".
        apdu = bytes([0x00, 0xA4, 0x00, 0x04, 0x02]) + body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        return sw1, sw2

    def _select_ok(self, fid: str) -> None:
        self.assertEqual(self._select_by_fid(fid), (0x90, 0x00))

    def _read_binary(self, length: int) -> bytes:
        apdu = bytes([0x00, 0xB0, 0x00, 0x00, length & 0xFF])
        data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return data

    def _ust_byte(self, byte_index: int) -> int:
        self._select_usim()
        self._select_ok("6F38")
        ust = self._read_binary(0x11)
        return ust[byte_index] if byte_index < len(ust) else 0


class DfGsmAccessSeedTests(_UsimEngineHarness):
    """3GPP TS 31.102 §4.4.3 DF.GSM-ACCESS reachable from ADF.USIM."""

    def test_df_selectable(self) -> None:
        self._select_usim()
        self._select_ok("5F3B")

    def test_ef_kc_default_is_zero_kc_plus_cksn_7(self) -> None:
        self._select_usim()
        self._select_ok("5F3B")
        self._select_ok("4F20")
        body = self._read_binary(0x09)
        self.assertEqual(body, b"\x00" * 8 + bytes((0x07,)))

    def test_ef_kcgprs_default_is_zero_kc_plus_cksn_7(self) -> None:
        self._select_usim()
        self._select_ok("5F3B")
        self._select_ok("4F52")
        body = self._read_binary(0x09)
        self.assertEqual(body, b"\x00" * 8 + bytes((0x07,)))

    def test_ef_kc_update_round_trip(self) -> None:
        self._select_usim()
        self._select_ok("5F3B")
        self._select_ok("4F20")
        new_body = bytes.fromhex("0123456789ABCDEF") + bytes((0x03,))
        apdu = bytes([0x00, 0xD6, 0x00, 0x00, 0x09]) + new_body
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._read_binary(0x09), new_body)


class GsmAccessServiceCoherenceTests(_UsimEngineHarness):
    """If EF.UST advertises GSM access (service 27) the
    DF.GSM-ACCESS supporting EFs must be reachable.
    """

    def test_ust_advertises_gsm_access(self) -> None:
        # Service 27 lives in byte (27-1)//8 == 3, bit (27-1)%8 == 2.
        byte_value = self._ust_byte(byte_index=3)
        self.assertTrue(
            byte_value & (1 << 2),
            msg="EF.UST service 27 (GSM access) not advertised",
        )

    def test_gsm_access_efs_are_present(self) -> None:
        for fid in ("4F20", "4F52"):
            self._select_usim()
            self._select_ok("5F3B")
            self.assertEqual(
                self._select_by_fid(fid), (0x90, 0x00),
                msg=f"DF.GSM-ACCESS EF {fid} unreachable",
            )


if __name__ == "__main__":
    unittest.main()
