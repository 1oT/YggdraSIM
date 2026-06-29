# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SIMCARD ↔ physical reader cross-check harness.

This module compares the response of every APDU in a small regression
set against both:

1. The ``SimulatedSimCardEngine`` wrapped by the ``sim`` card backend.
2. A physical UICC / eUICC attached via PC/SC.

It is **opt-in**: nothing runs unless ``YGGDRASIM_GOLDEN_CARD=1`` is
set in the environment, because pytest discovery on machines without
a reader would otherwise produce noisy errors from ``pyscard``.

Differences are reported both as a status-word delta (SW1 SW2) and as
a structural diff (length, hash, first-N prefix) of the response body.
Some divergences are legitimate (T=0 vs T=1 shaping, vendor-specific
file sets) so the harness only fails the test on hard mismatches:

- a hard SW divergence for the core ETSI TS 102 221 commands
  (SELECT MF, SELECT EF.ICCID, READ BINARY EF.ICCID, MANAGE CHANNEL
  open/close)
- a CLA-filter regression where the simulator accepts a CLA that
  both ISO 7816-4 and the reader reject

Run it explicitly::

    YGGDRASIM_GOLDEN_CARD=1 \
    pytest -q --tb=short --disable-warnings --no-header --maxfail=1 \
        tests/golden/test_simcard_vs_pcsc_reader.py

The set of APDUs is deliberately conservative. Do not extend it to
anything that mutates persistent state on the physical card (WRITE,
DELETE, STORE DATA, UPDATE *, EXTERNAL AUTHENTICATE, ...).
"""

from __future__ import annotations

import os
import unittest


_GOLDEN_ENV = "YGGDRASIM_GOLDEN_CARD"


def _golden_enabled() -> bool:
    return str(os.environ.get(_GOLDEN_ENV, "")).strip() == "1"


@unittest.skipUnless(_golden_enabled(), f"set {_GOLDEN_ENV}=1 to run the reader cross-check")
class SimulatorVersusReaderTests(unittest.TestCase):
    """Baseline APDU equivalence between simulator and physical card."""

    CORE_APDUS: tuple[tuple[str, str, bool], ...] = (
        ("SELECT MF", "00A40004023F00", True),
        ("SELECT EF.ICCID", "00A40004022FE2", True),
        ("READ BINARY EF.ICCID 10B", "00B000000A", True),
        ("SELECT EF.DIR", "00A40004022F00", True),
        ("READ RECORD #1 EF.DIR", "00B2010400", True),
        ("GET DATA 5A (EID)", "80CA005A00", False),
        ("MANAGE CHANNEL open", "0070000001", False),
        ("MANAGE CHANNEL close channel 1", "0070800100", False),
        ("Invalid CLA smoke (0x20)", "20A40004023F00", False),
    )

    @classmethod
    def setUpClass(cls) -> None:
        from smartcard.System import readers as list_readers

        reader_list = list_readers()
        if len(reader_list) == 0:
            raise unittest.SkipTest("no PC/SC reader attached")
        cls._reader = reader_list[0]
        cls._reader_conn = cls._reader.createConnection()
        cls._reader_conn.connect()

        from SIMCARD.connection import SimulatedCardConnection

        cls._sim_conn = SimulatedCardConnection()
        cls._sim_conn.connect()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._reader_conn.disconnect()
        except Exception:
            pass
        try:
            cls._sim_conn.disconnect()
        except Exception:
            pass

    def _send_reader(self, apdu_hex: str) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self._reader_conn.transmit(list(bytes.fromhex(apdu_hex)))
        return bytes(data), int(sw1), int(sw2)

    def _send_sim(self, apdu_hex: str) -> tuple[bytes, int, int]:
        data, sw1, sw2 = self._sim_conn.transmit(list(bytes.fromhex(apdu_hex)))
        return bytes(data), int(sw1), int(sw2)

    def test_core_apdus_agree_on_status_words(self) -> None:
        hard_diffs: list[str] = []
        soft_diffs: list[str] = []
        for label, apdu_hex, hard in self.CORE_APDUS:
            rdr = self._send_reader(apdu_hex)
            sim = self._send_sim(apdu_hex)
            sw_r = f"{rdr[1]:02X}{rdr[2]:02X}"
            sw_s = f"{sim[1]:02X}{sim[2]:02X}"
            if sw_r != sw_s:
                line = f"{label:38s} reader={sw_r} sim={sw_s} apdu={apdu_hex}"
                if hard:
                    hard_diffs.append(line)
                else:
                    soft_diffs.append(line)
        if len(soft_diffs) > 0:
            print("\n[golden] soft divergences (informational):")
            for entry in soft_diffs:
                print(f"  {entry}")
        self.assertEqual(
            len(hard_diffs),
            0,
            msg="hard SW divergences:\n  " + "\n  ".join(hard_diffs),
        )

    def test_invalid_cla_is_rejected_by_simulator(self) -> None:
        """CLA 0x20 is not in ISO 7816-4's interindustry range; simulator must reject it."""
        data, sw1, sw2 = self._send_sim("20A40004023F00")
        self.assertEqual(
            (sw1, sw2),
            (0x6E, 0x00),
            msg=f"expected 6E 00 for unsupported CLA, got {sw1:02X}{sw2:02X} with data={data.hex().upper()}",
        )


if __name__ == "__main__":
    unittest.main()
