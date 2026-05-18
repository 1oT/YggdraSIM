# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``saip_aka_mapping``."""

from __future__ import annotations

import unittest

from Tools.ProfilePackage import saip_aka_mapping as A


class AlgoParameterTests(unittest.TestCase):

    def test_set_algo_parameter_with_id(self) -> None:
        pe: dict = {}
        A.set_algo_parameter(pe, algorithm_id=4)
        choice = A.get_choice(pe)
        self.assertEqual(choice["choice"], "algoParameter")
        self.assertEqual(choice["algorithm_id"], 4)

    def test_absent_choice(self) -> None:
        choice = A.get_choice({})
        self.assertEqual(choice["choice"], "absent")
        self.assertIsNone(choice["algorithm_id"])


class MappingParameterTests(unittest.TestCase):

    def test_set_mapping_parameter_with_flags(self) -> None:
        pe: dict = {}
        A.set_mapping_parameter(
            pe,
            mapping_source_aid="A0000000871002",
            mapping_options_flags=["share-K", "share-OPc"],
        )
        choice = A.get_choice(pe)
        self.assertEqual(choice["choice"], "mappingParameter")
        self.assertEqual(choice["mapping_source_aid_hex"], "A0000000871002")
        self.assertEqual(choice["mapping_options_hex"], "C0")
        self.assertEqual(choice["mapping_options_flags"], ["share-K", "share-OPc"])

    def test_set_mapping_parameter_with_explicit_hex(self) -> None:
        pe: dict = {}
        A.set_mapping_parameter(
            pe,
            mapping_source_aid="A0000000871002",
            mapping_options_hex="40",
        )
        choice = A.get_choice(pe)
        self.assertEqual(choice["mapping_options_hex"], "40")
        self.assertEqual(choice["mapping_options_flags"], ["share-OPc"])

    def test_mapping_options_hex_and_flags_conflict(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter(
                {},
                mapping_source_aid="A0000000871002",
                mapping_options_hex="40",
                mapping_options_flags=["share-K"],
            )

    def test_aid_too_short(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter({}, mapping_source_aid="A1B2C3")

    def test_aid_too_long(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter({}, mapping_source_aid="00" * 17)

    def test_unknown_flag_rejected(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter(
                {},
                mapping_source_aid="A0000000871002",
                mapping_options_flags=["nonsense"],
            )

    def test_stash_round_trip(self) -> None:
        pe: dict = {}
        A.set_algo_parameter(pe, algorithm_id=4)
        A.set_mapping_parameter(pe, mapping_source_aid="A0000000871002")
        self.assertIn("_ygg_algo_parameter_stash", pe)
        A.set_algo_parameter(pe)
        choice = A.get_choice(pe)
        self.assertEqual(choice["choice"], "algoParameter")
        self.assertEqual(choice["algorithm_id"], 4)
        self.assertNotIn("_ygg_algo_parameter_stash", pe)

    def test_catalog_shape(self) -> None:
        catalog = A.mapping_option_catalog()
        self.assertEqual(len(catalog), 8)
        self.assertEqual(
            sum(entry["bit_mask"] for entry in catalog),
            0xFF,
        )


if __name__ == "__main__":
    unittest.main()
