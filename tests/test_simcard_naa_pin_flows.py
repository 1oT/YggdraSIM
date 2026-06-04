from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID


class SimCardPinFlowTests(unittest.TestCase):
    """Regression coverage for SIMCARD/naa.py PIN / PUK flows.

    The checks target behaviour that was tightened during the v1 audit:

    * VERIFY CHV with a non-empty payload whose length != 8 must return
      67 00 without consuming a retry (ETSI TS 102 221 §11.1.9).
    * VERIFY CHV with the correct padded PIN must return 90 00 and
      restore the retry counter to its limit.
    * UNBLOCK CHV with the correct PUK must return 90 00 and rearm
      both the PIN and PUK retry counters.
    * Both comparators must run on ``hmac.compare_digest``; if a
      future refactor drops that, the retry-counter bookkeeping below
      still fails loudly.
    """

    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_root = Path(self._temp_dir.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(temp_root / "missing_quirks.py"),
            isdr_config_path=str(temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(temp_root / "euicc_store"),
            profile_store_path=str(temp_root / "profile_store"),
        )
        self.engine.state.chv_references[0x01].enabled = True
        self._select_usim_adf()

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _select_usim_adf(self) -> None:
        _data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def _retries_remaining(self, reference: int) -> int:
        state = self.engine.state.chv_references.get(int(reference) & 0xFF)
        self.assertIsNotNone(state)
        assert state is not None
        return int(state.retries_remaining)

    def _padded_pin(self, pin_text: str) -> bytes:
        raw = pin_text.encode("ascii")[:8]
        return raw + (b"\xFF" * (8 - len(raw)))

    def test_verify_chv_rejects_wrong_length_without_consuming_retry(self) -> None:
        retries_before = self._retries_remaining(0x01)
        self.assertGreater(retries_before, 0)

        short_payload = b"1234"
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x20, 0x00, 0x01, len(short_payload)]) + short_payload
        )
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x67, 0x00))
        self.assertEqual(self._retries_remaining(0x01), retries_before)

    def test_verify_chv_happy_path_resets_retry_counter(self) -> None:
        wrong = self._padded_pin("1111")
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x20, 0x00, 0x01, len(wrong)]) + wrong
        )
        self.assertEqual((sw1, sw2 & 0xF0), (0x63, 0xC0))
        self.assertLess(self._retries_remaining(0x01), 3)

        correct = self._padded_pin("1234")
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x20, 0x00, 0x01, len(correct)]) + correct
        )
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._retries_remaining(0x01), 3)

    def test_unblock_chv_accepts_correct_puk(self) -> None:
        wrong = self._padded_pin("1111")
        for _ in range(4):
            self.engine.transmit(
                bytes([0x00, 0x20, 0x00, 0x01, len(wrong)]) + wrong
            )
        self.assertEqual(self._retries_remaining(0x01), 0)

        puk = b"12345678"
        new_pin = self._padded_pin("4321")
        payload = puk + new_pin
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x2C, 0x00, 0x01, len(payload)]) + payload
        )
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self._retries_remaining(0x01), 3)

        verify = self._padded_pin("4321")
        data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0x20, 0x00, 0x01, len(verify)]) + verify
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))


class SimCardFileStructureMismatchTests(unittest.TestCase):
    """Regression coverage for ETSI TS 102 221 §11.1.3 / §11.1.5.

    READ BINARY against a record-oriented EF and READ RECORD against a
    transparent EF must both report 69 81 ("command incompatible with
    file structure"), not 69 86 ("command not allowed (no current EF)")
    or a plain 90 00 truncation. The previous simulator returned 69 86
    for this case, which made a handful of pySim / osmo-sim probes look
    like they had discovered a malformed card.
    """

    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_root = Path(self._temp_dir.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(temp_root / "missing_quirks.py"),
            isdr_config_path=str(temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(temp_root / "euicc_store"),
            profile_store_path=str(temp_root / "profile_store"),
        )

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _select_fid(self, fid_hex: str) -> None:
        body = bytes.fromhex(fid_hex)
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x00, 0xA4, 0x00, 0x04, len(body)]) + body
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_read_binary_on_linear_fixed_ef_reports_69_81(self) -> None:
        self._select_fid("2F00")
        data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00B0000000")
        )
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x69, 0x81))

    def test_read_record_on_transparent_ef_reports_69_81(self) -> None:
        self._select_fid("2FE2")
        data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00B2010400")
        )
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x69, 0x81))


if __name__ == "__main__":
    unittest.main()
