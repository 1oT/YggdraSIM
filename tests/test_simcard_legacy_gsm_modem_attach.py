"""Legacy 2G modem cold-attach regression.

Real basebands -- particularly Quectel BG95/BG96/EC25 derivatives and
older Cinterion/Telit modules -- still issue ``CLA=A0`` commands per
3GPP TS 11.11 / TS 51.011 even when the card is a UICC, because their
SIM driver layer was originally written for plain GSM SIMs and the
boot path was never re-targeted at ETSI TS 102 221's ``CLA=00`` family.

The script below mirrors the byte sequence captured live on the HIL
bridge against a Telna BPP-provisioned UICC. Two failures observed
there motivate this test:

1. ``A0 B0 00 00 0A`` (READ BINARY of EF.ICCID under legacy CLA) used
   to fall through ``SimulatedSimCardEngine._is_supported_cla`` and
   come back as ``6E 00`` ("CLA not supported"), aborting cold-attach
   before the modem could even read the ICCID.

2. ``A0 A4 00 00 02 7F20`` (SELECT DF.GSM) used to return ``6A 82``
   when the active profile's ``genericFileManagement`` directives did
   not carve out a 7F20 DF (e.g. profiles imported before today's
   GFM consumer landed). Real-world dual-mode UICCs always present
   DF.GSM as a baseline so 2G probes succeed even when the BPP omits
   it; ``rebuild_runtime_filesystem`` now synthesises the stub.

Both fixes are exercised through ``SimulatedModemCardChannel`` so the
test sees exactly the bytes the modem would, including ``61 XX`` /
GET RESPONSE chaining.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ.setdefault("YGGDRASIM_ALLOW_QUIRKS", "1")

from SIMCARD.engine import SimulatedSimCardEngine
from Tools.HilBridge.sim_modem import SimulatedModemCardChannel


class _PyscardLikeConnection:
    """Minimal pyscard-shaped wrapper around the engine."""

    def __init__(self, engine: SimulatedSimCardEngine) -> None:
        self._engine = engine

    def disconnect(self) -> None:
        return None

    def getATR(self) -> list[int]:
        return list(self._engine.state.atr)

    def transmit(self, apdu) -> tuple[list[int], int, int]:
        response, sw1, sw2 = self._engine.transmit(bytes(apdu))
        return list(response), int(sw1), int(sw2)


class LegacyGsmModemAttachTests(unittest.TestCase):
    """Cold-attach script using TS 11.11 / TS 51.011 CLA=A0 framing."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._td = tempfile.TemporaryDirectory()
        root = Path(cls._td.name)
        cls.engine = SimulatedSimCardEngine(
            quirks_path=str(root / "q.py"),
            isdr_config_path=str(root / "i.json"),
            sim_eim_identity_path=str(root / "e.json"),
            euicc_store_root=str(root / "euicc"),
            profile_store_path=str(root / "ps"),
        )
        cls.connection = _PyscardLikeConnection(cls.engine)
        cls.modem = SimulatedModemCardChannel(cls.connection)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.modem.disconnect()
        cls._td.cleanup()

    def _exchange(self, apdu_hex: str) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self.modem.transmit(bytes.fromhex(apdu_hex))
        return bytes(data), int(sw1), int(sw2)

    def _drain_get_response(
        self,
        sw1: int,
        sw2: int,
        cla: int = 0xA0,
    ) -> tuple[bytes, int, int]:
        accumulated = b""
        while sw1 == 0x61:
            requested = sw2 & 0xFF
            apdu = bytes([cla, 0xC0, 0x00, 0x00, requested])
            chunk, sw1, sw2 = self.modem.transmit(apdu)
            accumulated += bytes(chunk)
        return accumulated, int(sw1), int(sw2)

    # -- the script --------------------------------------------------

    def test_01_select_mf_under_legacy_cla(self) -> None:
        # Modem opens with the modern CLA on some SoCs, then switches
        # to A0 once the UICC class is fixed at the SIM driver layer.
        data, sw1, sw2 = self._exchange("00A40004023F00")
        self.assertEqual(sw1, 0x61, msg=f"modern SELECT MF -> {sw1:02X}{sw2:02X}")
        fcp, sw1, sw2 = self._drain_get_response(sw1, sw2, cla=0xA0)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(fcp[0], 0x62)
        self.assertIn(b"\x83\x02\x3f\x00", fcp)

    def test_02_select_df_gsm_returns_fcp(self) -> None:
        # The fix under test: legacy SELECT 7F20 must succeed even when
        # the active BPP did not carve out a DF.GSM via GFM. The stub
        # is what 2G modems like BG95 expect to find right after MF.
        data, sw1, sw2 = self._exchange("A0A40000027F20")
        self.assertEqual(
            sw1,
            0x61,
            msg=f"SELECT DF.GSM under CLA=A0 -> {sw1:02X}{sw2:02X} (expected 61 XX)",
        )
        fcp, sw1, sw2 = self._drain_get_response(sw1, sw2, cla=0xA0)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(fcp[0], 0x62)
        # Tag 83 in the FCP carries the 2-byte file identifier.
        self.assertIn(b"\x83\x02\x7f\x20", fcp)

    def test_03_select_back_to_mf_under_legacy_cla(self) -> None:
        data, sw1, sw2 = self._exchange("A0A40000023F00")
        self.assertEqual(sw1, 0x61)
        fcp, sw1, sw2 = self._drain_get_response(sw1, sw2, cla=0xA0)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(b"\x83\x02\x3f\x00", fcp)

    def test_04_select_eficcid_under_legacy_cla(self) -> None:
        # SELECT EF.ICCID (2FE2) and READ BINARY 10 bytes via CLA=A0.
        # READ BINARY (INS=B0) used to be rejected with 6E00 by the
        # engine's CLA gate; the dispatcher now accepts the legacy
        # 0xA0..0xAF family per TS 11.11 §9.4 / TS 102 221 §10.1.1.
        data, sw1, sw2 = self._exchange("A0A40000022FE2")
        self.assertEqual(sw1, 0x61)
        fcp, sw1, sw2 = self._drain_get_response(sw1, sw2, cla=0xA0)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(b"\x83\x02\x2f\xe2", fcp)

        # Now the failing READ BINARY: the 10 ICCID bytes come back as
        # nibble-swapped BCD per TS 102 221 §13.2.
        body, sw1, sw2 = self._exchange("A0B000000A")
        self.assertEqual(
            (sw1, sw2),
            (0x90, 0x00),
            msg=f"READ BINARY under CLA=A0 -> {sw1:02X}{sw2:02X} (was 6E00 before fix)",
        )
        self.assertEqual(len(body), 10)

    def test_05_unsupported_cla_still_rejected(self) -> None:
        # Sanity: opening up CLA=A0..AF must not have broadened the
        # accept list to the proprietary 0xB0+ range. The bridge
        # wrapper intercepts SELECT regardless of CLA, so we exercise
        # the engine's dispatcher directly with a non-SELECT INS that
        # hits ``_dispatch`` end-to-end -- READ BINARY (INS=B0) under
        # the unallocated CLA=B0 must still come back as 6E 00.
        body, sw1, sw2 = self.engine.transmit(bytes.fromhex("B0B000000A"))
        self.assertEqual((int(sw1), int(sw2)), (0x6E, 0x00))


if __name__ == "__main__":
    unittest.main()
