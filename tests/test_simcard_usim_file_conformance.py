# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""EF structures in the simulated UICC, pinned to 3GPP TS 31.102.

The file structure decides how the simulator answers: a transparent EF is
read with READ BINARY and reports file size in its FCP, a linear-fixed EF
is read with READ RECORD and reports a record length. Getting it backwards
gives a card that answers the wrong command, so these are checked against
the values in TS 31.102 clause 4.2 rather than left to drift.

Nine EFs were corrected against the spec; the vectors below are the ones
that were wrong, plus their neighbours, which were already right and would
catch an over-broad edit.
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_profile import _FILE_SPECS


class UsimFileStructureConformance(unittest.TestCase):
    #: file id -> (structure, TS 31.102 clause). Every entry read from the
    #: spec text, not from the implementation.
    SPEC_STRUCTURES = {
        "6F58": ("linear-fixed", "4.2.46 EF_CMI"),
        "6FB1": ("transparent", "4.2.73 EF_VGCS"),
        "6FB2": ("transparent", "4.2.74 EF_VGCSS"),
        "6FB3": ("transparent", "4.2.75 EF_VBS"),
        "6FB4": ("transparent", "4.2.76 EF_VBSS"),
        "6FB6": ("transparent", "4.2.40 EF_AaeM"),
        "6FD4": ("transparent", "4.2.77 EF_VGCSCA"),
        "6FD7": ("linear-fixed", "4.2.79 EF_GBABP"),
        "6FE4": ("linear-fixed", "4.2.92 EF_EPSNSC"),
        "6FE5": ("linear-fixed", "EF_PSISMSC"),
        "6FE7": ("linear-fixed", "EF_UICCIARI"),
        # Core files, unchanged, included so a sweeping edit is caught.
        "6F07": ("transparent", "4.2.2 EF_IMSI"),
        "2FE2": ("transparent", "TS 102 221 EF_ICCID"),
        "6FB7": ("linear-fixed", "4.2.41 EF_ECC"),
    }

    def _by_fid(self) -> dict[str, dict]:
        table: dict[str, dict] = {}
        for spec in _FILE_SPECS.values():
            fid = str(spec.get("fid") or "").upper()
            if fid:
                table.setdefault(fid, spec)
        return table

    def test_structures_match_the_spec(self) -> None:
        table = self._by_fid()
        for fid, (expected, clause) in self.SPEC_STRUCTURES.items():
            with self.subTest(fid=fid, clause=clause):
                entry = table.get(fid)
                self.assertIsNotNone(entry, f"{fid} missing from the file table")
                self.assertEqual(
                    entry["structure"],
                    expected,
                    f"{entry['name']} ({fid}) is {expected} per TS 31.102 {clause}",
                )

    def test_every_structure_is_one_the_runtime_understands(self) -> None:
        allowed = {"transparent", "linear-fixed", "cyclic"}
        for key, spec in _FILE_SPECS.items():
            with self.subTest(key):
                self.assertIn(spec["structure"], allowed)

    def test_short_file_identifiers_stay_in_range(self) -> None:
        """TS 102 221 clause 8.2.1.2 codes an SFI in five bits."""

        for key, spec in _FILE_SPECS.items():
            sfi = spec.get("sfi")
            if sfi is None:
                continue
            with self.subTest(key):
                self.assertGreaterEqual(sfi, 1)
                self.assertLessEqual(sfi, 0x1E)


if __name__ == "__main__":
    unittest.main()
