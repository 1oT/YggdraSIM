# SPDX-License-Identifier: GPL-3.0-or-later
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
    """TCA SAIP v3.4.1 §8.4.2 (page 49): mappingOptions b3-b2 name one SQN
    sharing mode; the other bits are RFU."""

    def test_set_mapping_parameter_with_a_mode(self) -> None:
        pe: dict = {}
        A.set_mapping_parameter(
            pe,
            mapping_source_aid="A0000000871002",
            mapping_options_flags=["share-sqn-parameters"],
        )
        choice = A.get_choice(pe)
        self.assertEqual(choice["choice"], "mappingParameter")
        self.assertEqual(choice["mapping_options_hex"], "04")
        self.assertEqual(choice["mapping_options_flags"], ["share-sqn-parameters"])
        self.assertEqual(pe["algoConfiguration"][0], "mappingParameter")
        self.assertEqual(pe["algoConfiguration"][1]["mappingOptions"], b"\x04")

    def test_set_mapping_parameter_with_explicit_hex(self) -> None:
        pe: dict = {}
        A.set_mapping_parameter(
            pe,
            mapping_source_aid="A0000000871002",
            mapping_options_hex="06",
        )
        choice = A.get_choice(pe)
        self.assertEqual(choice["mapping_options_hex"], "06")
        self.assertEqual(choice["mapping_options_mode"], "share-sqn-parameters-and-array")

    def test_rfu_bits_are_refused(self) -> None:
        for value in ("40", "01", "08", "FF"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    A.set_mapping_parameter(
                        {}, mapping_source_aid="A0000000871002", mapping_options_hex=value,
                    )

    def test_mapping_options_hex_and_mode_conflict(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter(
                {},
                mapping_source_aid="A0000000871002",
                mapping_options_hex="04",
                mapping_options_flags=["share-no-sqn"],
            )

    def test_two_modes_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter(
                {},
                mapping_source_aid="A0000000871002",
                mapping_options_flags=["share-no-sqn", "share-sqn-parameters"],
            )

    def test_aid_too_short(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter({}, mapping_source_aid="A000")

    def test_aid_too_long(self) -> None:
        with self.assertRaises(ValueError):
            A.set_mapping_parameter({}, mapping_source_aid="A0" * 17)

    def test_unknown_mode_rejected(self) -> None:
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

    def test_the_session_tuple_shape_is_read_and_stashed(self) -> None:
        # A session document holds the CHOICE as a native tuple.
        payload = {"algorithmID": 1, "algorithmOptions": b"\x00", "key": bytes(16), "opc": bytes(16)}
        pe: dict = {"algoConfiguration": ("algoParameter", payload)}
        self.assertEqual(A.get_choice(pe)["algorithm_id"], 1)
        A.set_mapping_parameter(pe, mapping_source_aid="A0000000871002")
        self.assertEqual(pe["_ygg_algo_parameter_stash"], payload)
        A.set_algo_parameter(pe)
        self.assertEqual(pe["algoConfiguration"], ("algoParameter", payload))

    def test_the_json_transport_shape_is_still_read(self) -> None:
        pe: dict = {"algoConfiguration": {"__ygg_saip_tuple__": [
            "mappingParameter",
            {"mappingOptions": {"__ygg_saip_bytes__": "02"},
             "mappingSource": {"__ygg_saip_bytes__": "A0000000871002"}},
        ]}}
        choice = A.get_choice(pe)
        self.assertEqual(choice["mapping_options_mode"], "share-sqn-init-and-parameters")
        self.assertEqual(choice["mapping_source_aid_hex"], "A0000000871002")

    def test_catalog_shape(self) -> None:
        catalog = A.mapping_option_catalog()
        self.assertEqual([entry["hex"] for entry in catalog], ["00", "02", "04", "06"])


if __name__ == "__main__":
    unittest.main()
