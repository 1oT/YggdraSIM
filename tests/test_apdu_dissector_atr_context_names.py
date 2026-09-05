# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ATR interpretation, tag-context correctness, and file-name resolution.

Each class pins a defect that shipped decoded-but-wrong:

* ATR interface bytes were labelled (TA1/TC2/TA3...) but never
  interpreted; T=15 was reported as an "offered protocol" though it only
  flags global interface bytes; historical bytes stayed raw.
* 'A9'/'AA' carried the SGP.22 euiccCiPKId names globally, so a
  DF.TELECOM/DF.PHONEBOOK/EF.PBR record's Type-2/3 file tags read as
  euiccCiPKIdListForVerification. They are EUICCInfo tags only inside a
  BF20/BF22.
* SELECT by path showed the raw identifier run; the selected file's name
  was never resolved.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    write_capture,
)

# The ATR from the reported capture: direct convention, TA1=0x97 (Fi=512,
# Di=64), TC2=0x0A (WI=10), TD2 announces T=15, TA3/TB3 are the T=15
# globals, fifteen historical bytes in compact-TLV, TCK=0x04.
REPORTED_ATR = bytes.fromhex(
    "3b9f97c00a3fc6828031e073fe211f65d002331643810f04"
)

# One EF.PBR record exactly as captured: A8/A9/AA Type-1/2/3 file tags,
# each holding C_ file-id references.
EF_PBR_RECORD = bytes.fromhex(
    "a81ec0034f3a1ac1034f2505c4034f1111c5034f0909c6034f2606c9034f2101"
    "a90ac3034f1908ca034f5010"
    "aa14c7034f4b0bc8034f4c0ccb034f4f0fc2034f4a0a"
)


class AnswerToReset(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "atr.pcap", [], atr=REPORTED_ATR
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_ta1_yields_fi_and_di(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("Fi=512", text)
        self.assertIn("Di=64", text)

    def test_tc2_is_the_waiting_time_integer(self) -> None:
        self.assertIn("WI=10", decode_text(self.capture))

    def test_t15_is_not_reported_as_an_offered_protocol(self) -> None:
        self.assertIn(
            "global interface bytes indicator", decode_text(self.capture)
        )

    def test_historical_bytes_parse_as_compact_tlv(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("Card service data", text)
        self.assertIn("Card capabilities", text)

    def test_the_checksum_verifies(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.atr.tck_valid"])
        self.assertIn("1", [row[0] for row in rows if row and row[0]])


class ContextTagsOutsideEuiccInfo(unittest.TestCase):
    """'A9'/'AA' in a phone-book record must not read as euiccCiPKId."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "pbr.pcap",
            [Exchange(bytes.fromhex("00B201044E"), EF_PBR_RECORD + b"\x90\x00")],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_a9_is_a_generic_context_tag(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("context-9 constructed", text)
        self.assertNotIn("euiccCiPKIdListForVerification", text)


class ContextTagsInsideEuiccInfo(unittest.TestCase):
    """The same 'A9' inside a BF22 keeps its EUICCInfo meaning."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "euicc.pcap",
            [
                Exchange(
                    bytes.fromhex("80CABF2200"),
                    bytes.fromhex("bf2208a906040401020304") + b"\x90\x00",
                )
            ],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_a9_names_the_euicc_ci_pkid_list(self) -> None:
        self.assertIn(
            "euiccCiPKIdListForVerification", decode_text(self.capture)
        )


class PathSelectResolvesTheFileName(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "select.pcap",
            [Exchange(bytes.fromhex("00A40804067F105F3A4F30"), b"\x90\x00")],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_the_selected_target_is_named(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.detail"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertTrue(values, "the operation field should be populated")
        self.assertIn("DF.PHONEBOOK", values[0])
        self.assertIn("EF.PBR", values[0])


if __name__ == "__main__":
    unittest.main()
