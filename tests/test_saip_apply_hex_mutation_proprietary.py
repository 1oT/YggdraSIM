# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for `_apply_hex_mutation` proprietary-nested support.

`saip.update_file_field` originally only addressed top-level CHOICE-payload
keys (shortEFID, fileDescriptor, …). The proprietary block lives one level
deeper inside `fileDescriptor / proprietaryEFInfo`, so the mutation helper
now resolves a single dotted path before substituting bytes.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict

from yggdrasim_common.gui_server.actions.saip import (
    _apply_hex_mutation,
    _summarise_file_choices,
)


def _build_choice_list_with_proprietary(
    initial_special: bytes,
    initial_details: bytes,
) -> list:
    payload = OrderedDict(
        [
            ("fileDescriptor", b"\x42\x21\x00\x14\x16"),
            (
                "proprietaryEFInfo",
                OrderedDict(
                    [
                        ("specialFileInformation", initial_special),
                        ("fileDetails", initial_details),
                    ]
                ),
            ),
        ]
    )
    return [("fileDescriptor", payload)]


class TestApplyHexMutationProprietary(unittest.TestCase):
    """Dotted sub_key paths splice into nested dicts."""

    def test_top_level_path_unchanged_behaviour(self) -> None:
        choice_list = [
            ("fileDescriptor", OrderedDict([("fileDescriptor", b"\x42\x21\x00\x14")])),
        ]

        applied = _apply_hex_mutation(
            choice_list, "fileDescriptor", b"\x42\x21\x00\x28\x10",
        )

        self.assertTrue(applied)
        self.assertEqual(
            choice_list[0][1]["fileDescriptor"], b"\x42\x21\x00\x28\x10",
        )

    def test_proprietary_special_information_dotted_path(self) -> None:
        choice_list = _build_choice_list_with_proprietary(b"\x00", b"\x01")

        applied = _apply_hex_mutation(
            choice_list,
            "proprietaryEFInfo.specialFileInformation",
            b"\x80",
        )

        self.assertTrue(applied)
        proprietary = choice_list[0][1]["proprietaryEFInfo"]
        self.assertEqual(proprietary["specialFileInformation"], b"\x80")
        # File details left untouched.
        self.assertEqual(proprietary["fileDetails"], b"\x01")

    def test_proprietary_file_details_dotted_path(self) -> None:
        choice_list = _build_choice_list_with_proprietary(b"\x00", b"\x01")

        applied = _apply_hex_mutation(
            choice_list,
            "proprietaryEFInfo.fileDetails",
            b"\x42",
        )

        self.assertTrue(applied)
        proprietary = choice_list[0][1]["proprietaryEFInfo"]
        self.assertEqual(proprietary["fileDetails"], b"\x42")

    def test_dotted_path_grows_container_when_outer_missing(self) -> None:
        # PEDocumentation ProprietaryEFInfo is optional — SAIP packages
        # often omit it when default. The mutation helper grows it on
        # demand when the host CHOICE payload carries FCP siblings,
        # so a freshly cloned EF can land its first proprietary value
        # without requiring a full re-encode.
        choice_list = [
            ("fileDescriptor", OrderedDict([("fileDescriptor", b"\x42\x21\x00\x14")])),
        ]

        applied = _apply_hex_mutation(
            choice_list,
            "proprietaryEFInfo.specialFileInformation",
            b"\x80",
        )

        self.assertTrue(applied)
        proprietary = choice_list[0][1]["proprietaryEFInfo"]
        self.assertEqual(proprietary["specialFileInformation"], b"\x80")

    def test_dotted_path_returns_false_when_no_fcp_host(self) -> None:
        choice_list = [
            ("fillFileContent", OrderedDict([("body", b"\xFF\xFF")])),
        ]

        applied = _apply_hex_mutation(
            choice_list,
            "proprietaryEFInfo.specialFileInformation",
            b"\x80",
        )

        self.assertFalse(applied)

    def test_dotted_path_grows_container_for_fill_pattern(self) -> None:
        # ETSI TS 102 222 §6.3.2.2 — fillPattern is a leaf inside
        # proprietaryEFInfo; the mutation helper must let the GUI add
        # it even when the package omitted the proprietary block.
        choice_list = [
            ("fileDescriptor", OrderedDict([("fileID", b"\x6F\x07")])),
        ]

        applied = _apply_hex_mutation(
            choice_list,
            "proprietaryEFInfo.fillPattern",
            b"\xDE\xAD\xBE\xEF",
        )

        self.assertTrue(applied)
        proprietary = choice_list[0][1]["proprietaryEFInfo"]
        self.assertEqual(proprietary["fillPattern"], b"\xDE\xAD\xBE\xEF")

    def test_summary_extracts_proprietary_pair(self) -> None:
        choice_list = _build_choice_list_with_proprietary(b"\x80", b"\x01")
        summary = _summarise_file_choices(choice_list)

        self.assertIsNotNone(summary)
        assert summary is not None  # type narrowing for mypy
        self.assertEqual(summary["proprietary_special_info"], "80")
        self.assertEqual(summary["proprietary_details"], "01")
        # Top-level descriptor + sentinel still detected.
        self.assertEqual(summary["descriptor"], "4221001416")

    def test_summary_extracts_pattern_and_max_size(self) -> None:
        # PEDocumentation ProprietaryEFInfo includes fillPattern,
        # repeatPattern and (for BER-TLV) maximumFileSize. All three
        # must reach the FCP row so the GUI can render and edit them.
        payload = OrderedDict(
            [
                ("fileDescriptor", b"\x42\x21\x00\x14\x16"),
                (
                    "proprietaryEFInfo",
                    OrderedDict(
                        [
                            ("fillPattern", b"\xDE\xAD\xBE\xEF"),
                            ("repeatPattern", b"\xAA\xBB"),
                            ("maximumFileSize", b"\x02\x00"),
                        ]
                    ),
                ),
            ]
        )
        choice_list = [("fileDescriptor", payload)]

        summary = _summarise_file_choices(choice_list)

        self.assertIsNotNone(summary)
        assert summary is not None  # type narrowing
        self.assertEqual(summary["proprietary_fill_pattern"], "DEADBEEF")
        self.assertEqual(summary["proprietary_repeat_pattern"], "AABB")
        self.assertEqual(summary["proprietary_max_size"], "0200")


if __name__ == "__main__":
    unittest.main()
