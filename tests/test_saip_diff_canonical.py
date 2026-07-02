# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.ProfilePackage.saip_diff_canonical``.

Pure-function module: no I/O, no pySim, no card transport. The tests
lock in the contract the diff CLI relies on:

* ``filePath`` → ``createFCP`` chains turn into ``<dir>/<fid>`` keys.
* Two profiles that contain the same EFs at different list-index
  positions produce byte-identical canonical maps (the whole reason
  this module exists).
* Commands that arrive before any select / create land in
  ``<unscoped>`` rather than colliding with a real path key.
* Top-level keys outside ``sections.genericFileManagement`` flow
  through unchanged.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_diff_canonical import (
    canonicalize_document_for_diff,
    canonicalize_generic_file_management,
)


def _tuple(tag: str, payload):
    return {"@": [tag, payload]}


def _bytes(hex_str: str) -> dict:
    return {"hex": hex_str}


def _block(*cmds) -> dict:
    return {"file": {"fileManagementCMD": list(cmds)}}


class CanonicaliseGfmTests(unittest.TestCase):
    def test_empty_section_yields_empty_map(self) -> None:
        self.assertEqual(canonicalize_generic_file_management([]), {})

    def test_simple_select_then_create(self) -> None:
        # MF / DF.Telecom / EF.MSISDN — single SELECT chain, single FCP.
        gfm = [
            _block(
                _tuple("filePath", _bytes("3F007F10")),
                _tuple("createFCP", {"fileID": _bytes("6F40")}),
                _tuple("fillFileContent", _bytes("AABBCC")),
            ),
        ]
        result = canonicalize_generic_file_management(gfm)
        self.assertEqual(list(result.keys()), ["3F00/7F10/6F40"])
        cmds = result["3F00/7F10/6F40"]
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0]["@"][0], "createFCP")
        self.assertEqual(cmds[1]["@"][0], "fillFileContent")
        self.assertEqual(cmds[1]["@"][1]["hex"], "AABBCC")

    def test_index_shift_collapses_to_identical_keys(self) -> None:
        # Same two EFs in different list-index positions; the canonical
        # form must be byte-identical so the diff engine sees no delta.
        gfm_a = [
            _block(
                _tuple("filePath", _bytes("3F00")),
                _tuple("createFCP", {"fileID": _bytes("2F05")}),
                _tuple("fillFileContent", _bytes("DEAD")),
            ),
            _block(
                _tuple("filePath", _bytes("3F007F20")),
                _tuple("createFCP", {"fileID": _bytes("6F07")}),
                _tuple("fillFileContent", _bytes("BEEF")),
            ),
        ]
        gfm_b = [
            _block(
                _tuple("filePath", _bytes("3F007F20")),
                _tuple("createFCP", {"fileID": _bytes("6F07")}),
                _tuple("fillFileContent", _bytes("BEEF")),
                _tuple("filePath", _bytes("3F00")),
                _tuple("createFCP", {"fileID": _bytes("2F05")}),
                _tuple("fillFileContent", _bytes("DEAD")),
            ),
        ]
        self.assertEqual(
            canonicalize_generic_file_management(gfm_a),
            canonicalize_generic_file_management(gfm_b),
        )

    def test_genuine_content_change_survives(self) -> None:
        # Same EF, same path, different content. Canonical maps must
        # differ — otherwise the diff engine would lose the real delta.
        gfm_a = [
            _block(
                _tuple("filePath", _bytes("3F00")),
                _tuple("createFCP", {"fileID": _bytes("2F05")}),
                _tuple("fillFileContent", _bytes("DEAD")),
            ),
        ]
        gfm_b = [
            _block(
                _tuple("filePath", _bytes("3F00")),
                _tuple("createFCP", {"fileID": _bytes("2F05")}),
                _tuple("fillFileContent", _bytes("CAFE")),
            ),
        ]
        result_a = canonicalize_generic_file_management(gfm_a)
        result_b = canonicalize_generic_file_management(gfm_b)
        self.assertEqual(list(result_a.keys()), list(result_b.keys()))
        self.assertNotEqual(result_a, result_b)

    def test_orphan_commands_bucket_under_unscoped(self) -> None:
        # A profile that emits a fillFileContent before any select.
        gfm = [_block(_tuple("fillFileContent", _bytes("00")))]
        result = canonicalize_generic_file_management(gfm)
        self.assertIn("<unscoped>", result)
        self.assertEqual(len(result["<unscoped>"]), 1)

    def test_create_without_file_id_uses_select_chain_only(self) -> None:
        # If the FCP omits fileID, the canonical key falls back to the
        # current select chain. This keeps the entry visible without
        # silently merging with a sibling EF.
        gfm = [
            _block(
                _tuple("filePath", _bytes("3F007F20")),
                _tuple("createFCP", {}),
                _tuple("fillFileContent", _bytes("AA")),
            ),
        ]
        result = canonicalize_generic_file_management(gfm)
        self.assertEqual(list(result.keys()), ["3F00/7F20"])

    def test_pe_block_metadata_is_dropped(self) -> None:
        # A block may carry sibling fields next to fileManagementCMD
        # (header references, etc.). Those are stripped by canonical
        # form because they do not survive cross-block flattening.
        gfm = [
            {
                "header": {"identification": _bytes("01")},
                "file": {
                    "fileManagementCMD": [
                        _tuple("filePath", _bytes("3F00")),
                        _tuple("createFCP", {"fileID": _bytes("2F05")}),
                    ],
                },
            },
        ]
        result = canonicalize_generic_file_management(gfm)
        self.assertEqual(list(result.keys()), ["3F00/2F05"])


class CanonicaliseDocumentTests(unittest.TestCase):
    def test_passes_other_sections_through_with_equal_payload(self) -> None:
        original_aka = {"algoConfiguration": {"@": ["something", _bytes("AABB")]}}
        document = {
            "intro": ["profile foo"],
            "sections": {
                "akaParameter": original_aka,
                "genericFileManagement": [
                    _block(
                        _tuple("filePath", _bytes("3F00")),
                        _tuple("createFCP", {"fileID": _bytes("2F05")}),
                    ),
                ],
            },
        }
        out = canonicalize_document_for_diff(document)
        self.assertEqual(out["intro"], ["profile foo"])
        # Identity is no longer preserved: every section dict is walked
        # so the PE-header identification stripper can recurse. The
        # contract is structural equality, not reference equality.
        self.assertEqual(out["sections"]["akaParameter"], original_aka)
        self.assertEqual(
            list(out["sections"]["genericFileManagement"].keys()),
            ["3F00/2F05"],
        )

    def test_already_canonical_document_is_idempotent(self) -> None:
        document = {
            "sections": {
                "genericFileManagement": {
                    "3F00/2F05": [_tuple("createFCP", {"fileID": _bytes("2F05")})],
                },
            },
        }
        out = canonicalize_document_for_diff(document)
        self.assertEqual(
            out["sections"]["genericFileManagement"],
            document["sections"]["genericFileManagement"],
        )

    def test_non_dict_input_returns_as_is(self) -> None:
        self.assertEqual(canonicalize_document_for_diff("not-a-dict"), "not-a-dict")
        self.assertEqual(canonicalize_document_for_diff(None), None)


class StripPeHeaderIdentificationTests(unittest.TestCase):
    """Lock the PE-header ``identification`` stripping contract."""

    def test_strips_identification_from_pe_header_block(self) -> None:
        document = {
            "sections": {
                "akaParameter": {
                    "aka-header": {
                        "mandated": None,
                        "identification": 11,
                    },
                    "algoConfiguration": {"@": ["seq", _bytes("DEAD")]},
                },
            },
        }
        out = canonicalize_document_for_diff(document)
        header = out["sections"]["akaParameter"]["aka-header"]
        self.assertNotIn("identification", header)
        self.assertIn("mandated", header)

    def test_strips_identification_from_capital_h_header_blocks(self) -> None:
        # SAIP PE-PIN / PE-PUK / SecurityDomain encoders use the
        # ``<short>-Header`` (capital H) spelling — see
        # ``saip_pe_editors/_base.py``. The strip must match both
        # casings or it leaves the noisiest section types untouched.
        document = {
            "sections": {
                "pinCodes": {
                    "pin-Header": {"mandated": None, "identification": 5},
                    "pinConfig": _bytes("AA"),
                },
                "pukCodes": {
                    "puk-Header": {"mandated": None, "identification": 6},
                    "pukConfig": _bytes("BB"),
                },
                "securityDomain": {
                    "sd-Header": {"mandated": None, "identification": 7},
                    "sdPersoData": _bytes("CC"),
                },
                "application": {
                    "app-header": {"mandated": None, "identification": 8},
                    "appData": _bytes("DD"),
                },
            },
        }
        out = canonicalize_document_for_diff(document)
        for section_key, header_key in (
            ("pinCodes", "pin-Header"),
            ("pukCodes", "puk-Header"),
            ("securityDomain", "sd-Header"),
            ("application", "app-header"),
        ):
            self.assertNotIn(
                "identification",
                out["sections"][section_key][header_key],
                msg=f"{section_key}.{header_key}.identification still present",
            )

    def test_two_documents_differing_only_in_identification_become_equal(self) -> None:
        doc_a = {
            "sections": {
                "usimContent": {
                    "pe-header": {"identification": 7, "mandated": None},
                    "body": _bytes("CAFE"),
                },
            },
        }
        doc_b = {
            "sections": {
                "usimContent": {
                    "pe-header": {"identification": 12, "mandated": None},
                    "body": _bytes("CAFE"),
                },
            },
        }
        self.assertEqual(
            canonicalize_document_for_diff(doc_a),
            canonicalize_document_for_diff(doc_b),
        )

    def test_strips_identification_inside_list_of_pe_records(self) -> None:
        document = {
            "sections": {
                "fileSystem": [
                    {
                        "pe-header": {"identification": 1, "mandated": None},
                        "payload": _bytes("AA"),
                    },
                    {
                        "pe-header": {"identification": 2, "mandated": None},
                        "payload": _bytes("BB"),
                    },
                ],
            },
        }
        out = canonicalize_document_for_diff(document)
        records = out["sections"]["fileSystem"]
        self.assertEqual(len(records), 2)
        for record in records:
            self.assertNotIn("identification", record["pe-header"])

    def test_does_not_strip_keys_that_only_contain_substring(self) -> None:
        # ``identification`` is a top-level field on a PE in some
        # SAIP encodings; only the per-PE ``<x>-header`` block is
        # mechanical noise. Anything that simply *contains* the word
        # without sitting under a ``-header`` parent must survive.
        document = {
            "sections": {
                "preIssuingData": {
                    "identification": _bytes("01020304"),
                    "data": _bytes("AA"),
                },
            },
        }
        out = canonicalize_document_for_diff(document)
        self.assertIn(
            "identification",
            out["sections"]["preIssuingData"],
        )

    def test_does_not_strip_when_header_value_is_not_dict(self) -> None:
        document = {
            "sections": {
                "weird": {
                    "broken-header": "not-a-dict",
                },
            },
        }
        out = canonicalize_document_for_diff(document)
        self.assertEqual(
            out["sections"]["weird"]["broken-header"],
            "not-a-dict",
        )


if __name__ == "__main__":
    unittest.main()
