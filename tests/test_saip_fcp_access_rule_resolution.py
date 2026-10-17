# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the FCP tab's `securityAttributesReferenced` resolution.

`saip.show_file` answers each file with the access rules its FCP points at.
Two things have to be decided before those rules mean anything, and both are
what these tests pin:

  - **which EF.ARR.** TS 102 221 §9.2.7 resolves the file identifier in the DF
    holding an EF (the parent DF of a DF; the MF for the MF and an ADF) and
    then upwards, stopping at the ADF or the MF, so a package that creates FID
    '6F06' under DF.TELECOM and again under ADF.USIM must send each citer to
    the one above it. A one-byte reference names a record of the EF.ARR SAIP
    V3.4.1 §8.3 implies: '2F06' for an ADF, the MF and files directly under
    the MF, '6F06' for anything deeper.
  - **which reading.** The record does not say which operations its
    access-mode byte gates -- the citing file does (ISO/IEC 7816-4 AM byte,
    TS 102 221 §9.2.2), so an EF sees READ / UPDATE / APPEND where MF, a DF
    or an ADF sees DELETE FILE (child) / CREATE FILE (EF) / CREATE FILE (DF).

The fixtures are synthetic rows plus a hand-encoded EF.ARR body, so the suite
runs without pySim installed.
"""

from __future__ import annotations

import unittest
from typing import Any

from yggdrasim_common.gui_server.actions import saip as gui_saip
from yggdrasim_common.gui_server.actions.saip import (
    _arr_record_citations,
    _arr_reference_search_chain,
    _implicit_arr_file_id,
    _resolve_referenced_access_rule,
)


# Linear-fixed descriptor: working EF, 8 B records, 3 records.
_DESCRIPTOR: bytes = bytes.fromhex("4221000803")

# Record 1: AM '01' (READ for an EF) under Always.
# Record 2: unallocated -- an FF slot.
# Record 3: AM '03' (READ + UPDATE for an EF) under Always.
_ARR_BODY: bytes = (
    bytes.fromhex("8001019000") + b"\xFF" * 3
    + b"\xFF" * 8
    + bytes.fromhex("8001039000") + b"\xFF" * 3
)


def _arr_file_value() -> list[tuple[str, Any]]:
    """The tagged-tuple shape ``_decode_for_show_file`` consumes."""
    return [
        ("fileDescriptor", {"fileDescriptor": _DESCRIPTOR}),
        ("fillFileContent", _ARR_BODY),
    ]


def _row(
    section_key: str,
    field_path: str,
    file_id: str,
    kind: str,
    parent_path: str,
    *,
    security_attrs: str = "",
    friendly_name: str = "",
) -> dict[str, Any]:
    fid_chain = f"{parent_path}/{file_id}" if parent_path else file_id
    return {
        "section_key": section_key,
        "field_path": field_path,
        "file_id": file_id,
        "kind": kind,
        "parent_path": parent_path,
        "fid_chain": fid_chain,
        "security_attrs": security_attrs,
        "friendly_name": friendly_name,
    }


class TestArrReferenceSearchChain(unittest.TestCase):
    """The DF walk TS 102 221 §9.2.7 prescribes."""

    def test_ef_starts_at_its_own_df(self) -> None:
        row = _row("telecom", "ef-adn", "6F3A", "ef-lf", "3F00/7F10")
        self.assertEqual(
            _arr_reference_search_chain(row),
            ["3F00/7F10", "3F00"],
        )

    def test_df_starts_at_its_parent(self) -> None:
        # "For a DF, if the EF(ARR) ... cannot be found in the parent DF, the
        # grandparent DF shall be searched": a DF's own ARR is not inside it.
        row = _row("telecom", "df-telecom", "7F10", "df", "3F00")
        self.assertEqual(_arr_reference_search_chain(row), ["3F00"])
        nested = _row("telecom", "df-phonebook", "5F3A", "df", "3F00/7F10")
        self.assertEqual(
            _arr_reference_search_chain(nested),
            ["3F00/7F10", "3F00"],
        )

    def test_mf_and_adf_search_under_the_mf(self) -> None:
        mf_row = _row("mf", "mf", "3F00", "mf", "")
        self.assertEqual(_arr_reference_search_chain(mf_row), ["3F00"])
        adf_row = _row("usim", "adf-usim", "7FFF", "adf", "")
        adf_row["fid_chain"] = "ADF.USIM"
        self.assertEqual(_arr_reference_search_chain(adf_row), ["3F00"])

    def test_walk_stops_at_the_adf(self) -> None:
        # An ADF is its own root: a file inside one never reaches the MF.
        row = _row("usim", "ef-pbr", "4F30", "ef-lf", "ADF.USIM/5F3A")
        self.assertEqual(
            _arr_reference_search_chain(row),
            ["ADF.USIM/5F3A", "ADF.USIM"],
        )
        # A GFM section that SELECTs through the ADF's temporary identifier
        # anchors the same file under 3F00/7FFx; the walk still stops there.
        gfm = _row(
            "genericFileManagement", "fileManagementCMD[0][3]", "4F30",
            "ef-lf", "3F00/7FF0/5F3A",
        )
        self.assertEqual(
            _arr_reference_search_chain(gfm),
            ["3F00/7FF0/5F3A", "3F00/7FF0"],
        )

    def test_root_without_a_path_has_nothing_to_walk(self) -> None:
        row = _row("usim", "ef-imsi", "6F07", "ef-trans", "")
        self.assertEqual(_arr_reference_search_chain(row), [])


class TestImplicitArrFileId(unittest.TestCase):
    """SAIP V3.4.1 §8.3: the EF.ARR a 1-byte reference names."""

    def test_mf_adf_and_files_directly_under_the_mf_use_2f06(self) -> None:
        self.assertEqual(
            _implicit_arr_file_id(_row("mf", "mf", "3F00", "mf", ""))[0], "2F06",
        )
        self.assertEqual(
            _implicit_arr_file_id(_row("usim", "adf-usim", "7FFF", "adf", ""))[0],
            "2F06",
        )
        self.assertEqual(
            _implicit_arr_file_id(_row("mf", "ef-pl", "2F05", "ef-trans", "3F00"))[0],
            "2F06",
        )
        self.assertEqual(
            _implicit_arr_file_id(_row("telecom", "df-telecom", "7F10", "df", "3F00"))[0],
            "2F06",
        )

    def test_files_below_a_df_or_adf_use_6f06(self) -> None:
        self.assertEqual(
            _implicit_arr_file_id(
                _row("telecom", "ef-adn", "6F3A", "ef-lf", "3F00/7F10"),
            )[0],
            "6F06",
        )
        self.assertEqual(
            _implicit_arr_file_id(
                _row("telecom", "df-phonebook", "5F3A", "df", "3F00/7F10"),
            )[0],
            "6F06",
        )
        self.assertEqual(
            _implicit_arr_file_id(
                _row("usim", "ef-imsi", "6F07", "ef-trans", "ADF.USIM"),
            )[0],
            "6F06",
        )
        self.assertEqual(
            _implicit_arr_file_id(
                _row("usim", "df-5gs", "5FC0", "df", "ADF.USIM"),
            )[0],
            "6F06",
        )

    def test_unknown_place_in_the_tree_implies_nothing(self) -> None:
        fid, reason = _implicit_arr_file_id(
            _row("usim", "ef-imsi", "6F07", "ef-trans", ""),
        )
        self.assertEqual(fid, "")
        self.assertIn("unknown", reason)


class TestResolveReferencedAccessRule(unittest.TestCase):
    """Reference → EF.ARR record → the reading this file's kind selects."""

    def _document(self, *sections: tuple[str, str]) -> dict[str, Any]:
        return {
            "sections": {
                section: {field: _arr_file_value()}
                for section, field in sections
            },
        }

    def test_one_byte_reference_uses_the_dfs_default_arr(self) -> None:
        arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        citer = _row(
            "mf", "ef-pl", "2F05", "ef-trans", "3F00", security_attrs="03",
        )
        result = _resolve_referenced_access_rule(
            [arr, citer],
            citer,
            decoded_document=self._document(("mf", "ef-arr")),
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["form"], "record-id")
        self.assertEqual(result["record"], 3)
        self.assertEqual(result["resolution"], "path")
        self.assertTrue(result["resolved"])
        self.assertEqual(result["arr_file_id"], "2F06")
        self.assertEqual(result["scope"], "ef")
        self.assertEqual(
            [rule["accessModes"] for rule in result["rules"]],
            [["READ", "UPDATE"]],
        )

    def test_three_byte_reference_prefers_the_nearest_df(self) -> None:
        # Same FID under two parents: the citer under ADF.USIM must not read
        # DF.TELECOM's rules.
        telecom_arr = _row(
            "telecom", "ef-arr", "6F06", "ef-lf", "3F00/7F10",
            friendly_name="EF.ARR",
        )
        usim_arr = _row(
            "usim", "ef-arr", "6F06", "ef-lf", "ADF.USIM",
            friendly_name="EF.ARR",
        )
        citer = _row(
            "genericFileManagement", "fileManagementCMD[0][4]", "6F07",
            "ef-trans", "ADF.USIM", security_attrs="6F0601",
        )
        result = _resolve_referenced_access_rule(
            [telecom_arr, usim_arr, citer],
            citer,
            decoded_document=self._document(
                ("telecom", "ef-arr"), ("usim", "ef-arr"),
            ),
        )

        self.assertEqual(result["form"], "arr-fid-record")
        self.assertEqual(result["resolution"], "path")
        self.assertEqual(result["arr_section_key"], "usim")
        self.assertEqual(result["record"], 1)
        self.assertEqual(
            [rule["accessModes"] for rule in result["rules"]],
            [["READ"]],
        )

    def test_container_reads_the_other_access_mode_table(self) -> None:
        arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        mf_row = _row("mf", "mf", "3F00", "mf", "", security_attrs="03")
        result = _resolve_referenced_access_rule(
            [arr, mf_row],
            mf_row,
            decoded_document=self._document(("mf", "ef-arr")),
        )

        self.assertEqual(result["scope"], "df")
        self.assertEqual(
            [rule["accessModes"] for rule in result["rules"]],
            [["DELETE_CHILD", "CREATE_EF"]],
        )

    def test_unallocated_record_is_reported_not_decoded(self) -> None:
        arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        citer = _row(
            "mf", "ef-pl", "2F05", "ef-trans", "3F00", security_attrs="02",
        )
        result = _resolve_referenced_access_rule(
            [arr, citer],
            citer,
            decoded_document=self._document(("mf", "ef-arr")),
        )

        self.assertTrue(result["resolved"])
        self.assertTrue(result["record_empty"])
        self.assertIn("unallocated", result["note"])

    def test_record_outside_the_window_is_reported(self) -> None:
        arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        citer = _row(
            "mf", "ef-pl", "2F05", "ef-trans", "3F00", security_attrs="09",
        )
        result = _resolve_referenced_access_rule(
            [arr, citer],
            citer,
            decoded_document=self._document(("mf", "ef-arr")),
        )

        self.assertFalse(result["resolved"])
        self.assertIn("record window", result["note"])

    def test_missing_arr_names_the_identifier_the_card_looks_for(self) -> None:
        citer = _row(
            "mf", "ef-pl", "2F05", "ef-trans", "3F00", security_attrs="03",
        )
        result = _resolve_referenced_access_rule(
            [citer], citer, decoded_document={"sections": {}},
        )

        self.assertFalse(result["resolved"])
        self.assertEqual(result["arr_file_id"], "2F06")
        self.assertTrue(result["implicit_file_id"])
        self.assertIn("'2F06'", result["note"])
        self.assertIn("§9.2.7", result["note"])

    def test_adf_one_byte_reference_names_the_mf_arr(self) -> None:
        # SAIP §8.3 sends an ADF to '2F06' even when the package also creates
        # a '6F06' inside the ADF; TS 102 221 §9.2.7 searches under the MF.
        mf_arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        usim_arr = _row(
            "usim", "ef-arr", "6F06", "ef-lf", "ADF.USIM", friendly_name="EF.ARR",
        )
        adf_row = _row("usim", "adf-usim", "7FFF", "adf", "", security_attrs="01")
        adf_row["fid_chain"] = "ADF.USIM"
        result = _resolve_referenced_access_rule(
            [mf_arr, usim_arr, adf_row],
            adf_row,
            decoded_document=self._document(("mf", "ef-arr"), ("usim", "ef-arr")),
        )

        self.assertEqual(result["resolution"], "path")
        self.assertEqual(result["arr_section_key"], "mf")
        self.assertEqual(result["arr_file_id"], "2F06")
        self.assertEqual(result["scope"], "df")
        self.assertEqual(
            [rule["accessModes"] for rule in result["rules"]],
            [["DELETE_CHILD"]],
        )

    def test_df_one_byte_reference_resolves_in_its_parent(self) -> None:
        # DF.TELECOM sits directly under the MF, so its own '6F06' is not the
        # file the reference names -- the MF's '2F06' is.
        mf_arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        telecom_arr = _row(
            "telecom", "ef-arr", "6F06", "ef-lf", "3F00/7F10",
            friendly_name="EF.ARR",
        )
        df_row = _row(
            "telecom", "df-telecom", "7F10", "df", "3F00", security_attrs="03",
        )
        result = _resolve_referenced_access_rule(
            [mf_arr, telecom_arr, df_row],
            df_row,
            decoded_document=self._document(("mf", "ef-arr"), ("telecom", "ef-arr")),
        )

        self.assertEqual(result["resolution"], "path")
        self.assertEqual(result["arr_section_key"], "mf")
        self.assertEqual(result["arr_file_id"], "2F06")

    def test_ef_below_a_df_does_not_fall_back_to_the_mf_arr(self) -> None:
        # The one-byte form implies '6F06' for an EF inside DF.TELECOM; the MF's
        # '2F06' is on the walk but is not that identifier, so the card fails
        # and the tab says what SAIP §8.3 asks for instead.
        mf_arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        citer = _row(
            "telecom", "ef-adn", "6F3A", "ef-lf", "3F00/7F10", security_attrs="01",
        )
        result = _resolve_referenced_access_rule(
            [mf_arr, citer],
            citer,
            decoded_document=self._document(("mf", "ef-arr")),
        )

        self.assertFalse(result["resolved"])
        self.assertNotIn("resolution", result)
        self.assertEqual(result["arr_file_id"], "6F06")
        self.assertEqual(result["search_chain"], ["3F00/7F10", "3F00"])
        self.assertIn("'6F06'", result["note"])
        self.assertIn("3-byte form", result["note"])

    def test_explicit_mf_arr_from_inside_an_adf_is_matched_by_file_id(self) -> None:
        # The walk from inside an ADF never reaches the MF, so the explicit
        # '2F06' is found by identifier alone and labelled as such.
        mf_arr = _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR")
        citer = _row(
            "usim", "ef-imsi", "6F07", "ef-trans", "ADF.USIM",
            security_attrs="2F0601",
        )
        result = _resolve_referenced_access_rule(
            [mf_arr, citer],
            citer,
            decoded_document=self._document(("mf", "ef-arr")),
        )

        self.assertTrue(result["resolved"])
        self.assertEqual(result["resolution"], "file-id")
        self.assertEqual(result["search_chain"], ["ADF.USIM"])

    def test_unplaced_file_takes_the_arr_of_its_own_section(self) -> None:
        usim_arr = _row(
            "usim", "ef-arr", "6F06", "ef-lf", "ADF.USIM", friendly_name="EF.ARR",
        )
        citer = _row("usim", "ef-imsi", "6F07", "ef-trans", "", security_attrs="01")
        result = _resolve_referenced_access_rule(
            [usim_arr, citer],
            citer,
            decoded_document=self._document(("usim", "ef-arr")),
        )

        self.assertTrue(result["resolved"])
        self.assertEqual(result["resolution"], "section")
        self.assertEqual(result["arr_file_id"], "6F06")

    def test_no_reference_returns_nothing(self) -> None:
        citer = _row("mf", "ef-pl", "2F05", "ef-trans", "3F00")
        self.assertIsNone(
            _resolve_referenced_access_rule(
                [citer], citer, decoded_document={"sections": {}},
            ),
        )

    def test_unrecognised_reference_length_is_named(self) -> None:
        citer = _row(
            "mf", "ef-pl", "2F05", "ef-trans", "3F00", security_attrs="8B03",
        )
        result = _resolve_referenced_access_rule(
            [citer], citer, decoded_document={"sections": {}},
        )

        self.assertEqual(result["form"], "unrecognised")
        self.assertIn("1-byte and 3-byte", result["note"])


class TestArrRecordCitationsFollowTheWalk(unittest.TestCase):
    """The reverse map agrees with the FCP tab on who cites which EF.ARR."""

    _ROWS = [
        _row("mf", "mf", "3F00", "mf", "", security_attrs="0E", friendly_name="MF"),
        _row("mf", "ef-arr", "2F06", "ef-lf", "3F00", friendly_name="EF.ARR"),
        _row(
            "mf", "ef-pl", "2F05", "ef-trans", "3F00", security_attrs="01",
            friendly_name="EF.PL",
        ),
        # DF.TELECOM sits directly under the MF: its one-byte reference names
        # the MF's '2F06', not the '6F06' it carries itself.
        _row(
            "telecom", "df-telecom", "7F10", "df", "3F00", security_attrs="0E",
            friendly_name="DF.TELECOM",
        ),
        _row(
            "telecom", "ef-arr", "6F06", "ef-lf", "3F00/7F10",
            friendly_name="EF.ARR",
        ),
        _row(
            "telecom", "ef-adn", "6F3A", "ef-lf", "3F00/7F10", security_attrs="01",
            friendly_name="EF.ADN",
        ),
        _row(
            "usim", "ef-arr", "6F06", "ef-lf", "ADF.USIM", friendly_name="EF.ARR",
        ),
        _row(
            "usim", "ef-imsi", "6F07", "ef-trans", "ADF.USIM", security_attrs="01",
            friendly_name="EF.IMSI",
        ),
        # An explicit '6F06' from under the ADF names the ADF's own copy.
        _row(
            "usim", "ef-ust", "6F38", "ef-trans", "ADF.USIM",
            security_attrs="6F0602", friendly_name="EF.UST",
        ),
    ]

    def _citations(self, section_key: str, file_id: str, field_path: str = "") -> dict:
        original = gui_saip._filesystem_tree_rows
        gui_saip._filesystem_tree_rows = lambda _doc: [dict(r) for r in self._ROWS]
        try:
            return _arr_record_citations(
                {}, section_key=section_key, file_id=file_id, field_path=field_path,
            )
        finally:
            gui_saip._filesystem_tree_rows = original

    def test_mf_level_files_and_top_level_dfs_cite_2f06(self) -> None:
        citations = self._citations("mf", "2F06")
        self.assertEqual(
            sorted(item["file"] for item in citations[0x0E]["citedBy"]),
            ["DF.TELECOM", "MF"],
        )
        self.assertEqual(
            [item["file"] for item in citations[1]["citedBy"]], ["EF.PL"],
        )

    def test_files_inside_a_df_cite_that_dfs_6f06_only(self) -> None:
        telecom = self._citations("telecom", "6F06")
        self.assertEqual(
            [item["file"] for item in telecom[1]["citedBy"]], ["EF.ADN"],
        )
        self.assertNotIn(0x0E, telecom)

    def test_same_fid_under_the_adf_keeps_its_own_citers(self) -> None:
        usim = self._citations("usim", "6F06")
        self.assertEqual(
            [item["file"] for item in usim[1]["citedBy"]], ["EF.IMSI"],
        )
        self.assertEqual(
            [item["file"] for item in usim[2]["citedBy"]], ["EF.UST"],
        )
        # And the MF's table does not pick up any of them.
        self.assertNotIn(2, self._citations("mf", "2F06"))


if __name__ == "__main__":
    unittest.main()
