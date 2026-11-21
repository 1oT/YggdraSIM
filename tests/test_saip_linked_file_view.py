# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Linked files in the workbench: ``saip.show_file`` and the body writes.

TCA Profile interoperability technical specification V3.4.1 section 8.3.2
defines ``Fcp.linkPath`` as the MF-relative path of the file an entry is
linked to (a file inside an ADF is addressed through the ADF's temporary
file identifier); section 8.3.3 Note 1 and the section 8.3.5 createFCP
table give the linked file the source file's fileDescriptor, efFileSize
and proprietaryEFInfo. A link entry therefore has no body of its own:
``show_file`` answers it with the source file's bytes and layout, and a
body write addressed to it lands on the source. The reference profile
links most of ADF.USIM to the generic-file-management files under DF.GSM
and DF.TELECOM, which is the shape these tests read.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

from yggdrasim_common.gui_server.actions import saip as saip_actions

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_HEX = (
    _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
)


def _row(
    section_key: str,
    field_path: str,
    fid_chain: str,
    link_path: str = "",
) -> dict[str, Any]:
    return {
        "section_key": section_key,
        "field_path": field_path,
        "fid_chain": fid_chain,
        "link_path": link_path,
        "file_id": fid_chain.rsplit("/", 1)[-1],
    }


class LinkPathResolutionTests(unittest.TestCase):
    """``linkPath`` bytes to tree rows, without a session."""

    ADF_MAP = {"7FF0": "ADF.USIM"}

    def test_mf_relative_path_is_rooted_at_the_mf(self) -> None:
        self.assertEqual(saip_actions._link_path_fid_chain("7F206F46", {}), "3F00/7F20/6F46")
        self.assertEqual(saip_actions._link_path_fid_chain(bytes.fromhex("2F06"), {}), "3F00/2F06")
        self.assertEqual(saip_actions._link_path_fid_chain("3F007F206F46", {}), "3F00/7F20/6F46")

    def test_adf_temporary_fid_lands_under_the_adf_label(self) -> None:
        self.assertEqual(saip_actions._link_path_fid_chain("7FF06F46", self.ADF_MAP), "ADF.USIM/6F46")
        self.assertEqual(saip_actions._link_path_fid_chain("7FF0", self.ADF_MAP), "ADF.USIM")

    def test_malformed_paths_resolve_to_nothing(self) -> None:
        for raw in ("", "6F4", "7F206F4", "zz", "7F20 6F"):
            self.assertEqual(saip_actions._link_path_fid_chain(raw, {}), "", raw)

    def test_link_chain_follows_a_link_to_a_link(self) -> None:
        rows = [
            _row("usim", "ef-sume", "ADF.USIM/6F54", "7F206F54"),
            _row("genericFileManagement", "fileManagementCMD[0][3]", "3F00/7F20/6F54", "7F106F54"),
            _row("telecom", "ef-sume", "3F00/7F10/6F54"),
        ]
        lookup = saip_actions._link_source_lookup(rows, rows[0], {})
        self.assertTrue(lookup["resolved"])
        self.assertIs(lookup["row"], rows[2])
        self.assertEqual(lookup["hops"], ["3F00/7F20/6F54", "3F00/7F10/6F54"])

    def test_missing_target_and_loops_are_reported(self) -> None:
        rows = [_row("usim", "ef-spn", "ADF.USIM/6F46", "7F206F46")]
        lookup = saip_actions._link_source_lookup(rows, rows[0], {})
        self.assertFalse(lookup["resolved"])
        self.assertIn("no file at 3F00/7F20/6F46", lookup["reason"])
        loop = [
            _row("a", "x", "3F00/7F20/6F46", "7F106F46"),
            _row("b", "y", "3F00/7F10/6F46", "7F206F46"),
        ]
        lookup = saip_actions._link_source_lookup(loop, loop[0], {})
        self.assertFalse(lookup["resolved"])
        self.assertIn("loops", lookup["reason"])
        self_link = [_row("a", "x", "3F00/7F20/6F46", "7F206F46")]
        self.assertFalse(saip_actions._link_source_lookup(self_link, self_link[0], {})["resolved"])

    def test_tail_match_stands_in_only_when_unique(self) -> None:
        rows = [
            _row("a", "x", "ADF.USIM/5F3B/4F20"),
            _row("b", "y", "ADF.ISIM/5F3B/4F20"),
        ]
        self.assertIsNone(saip_actions._tree_row_for_chain(rows, "3F00/5F3B/4F20"))
        self.assertIs(saip_actions._tree_row_for_chain(rows[:1], "3F00/5F3B/4F20"), rows[0])
        self.assertIs(saip_actions._tree_row_for_chain(rows, "ADF.ISIM/5F3B/4F20"), rows[1])


class LinkedFileSessionTests(unittest.TestCase):
    """The reference profile's links from ADF.USIM into DF.GSM and DF.TELECOM."""

    @classmethod
    def setUpClass(cls) -> None:
        if _REFERENCE_HEX.is_file() is False:
            raise unittest.SkipTest("No tracked reference SAIP profile fixture")
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.manager = get_manager()

    def setUp(self) -> None:
        self.sid = saip_actions._dispatch_open_package(None, path=str(_REFERENCE_HEX))["session_id"]
        self.handle = self.manager.claim(self.sid)

    def tearDown(self) -> None:
        self.manager.close(self.sid)

    def _show(self, section_key: str, field_path: str) -> dict[str, Any]:
        return saip_actions._dispatch_show_file(
            None, session_id=self.sid, section_key=section_key, field_path=field_path
        )

    def _row_at(self, fid_chain: str) -> dict[str, Any]:
        rows = saip_actions._filesystem_tree_rows(self.handle["decoded_document"])
        for row in rows:
            if row["fid_chain"] == fid_chain:
                return row
        raise AssertionError(f"no row at {fid_chain}")

    def _payload(self, section_key: str, field_path: str) -> Any:
        return saip_actions._locate_file_payload(
            self.handle["decoded_document"], section_key=section_key, field_path=field_path
        )

    def test_transparent_link_shows_the_source_bytes_and_geometry(self) -> None:
        shown = self._show("usim", "ef-spn")
        link = shown["link_source"]
        self.assertTrue(link["resolved"])
        self.assertEqual(link["chain"], ["3F00/7F20/6F46"])
        self.assertEqual(
            (link["section_key"], link["fid_chain"], link["source"], link["friendly_name"]),
            ("genericFileManagement_2", "3F00/7F20/6F46", "gfm", "EF.SPN"),
        )
        self.assertEqual((link["fcp"]["descriptor"], link["fcp"]["ef_size"]), ("4121", "11"))
        self.assertEqual(link["own_content_bytes"], 0)
        source = self._row_at("3F00/7F20/6F46")
        expected = saip_actions._virtual_file_image_from_entries(
            self._payload(source["section_key"], source["field_path"]), 17
        )
        self.assertEqual(shown["body_hex"], expected.hex().upper())
        self.assertNotEqual(shown["body_hex"], "FF" * 17)
        self.assertEqual((shown["body_size"], shown["body_declared_size"]), (17, 17))
        # The entry keeps its own FCP, link path included.
        self.assertEqual(shown["fcp"]["link_path"], "7F206F46")

    def test_record_link_takes_the_source_layout(self) -> None:
        shown = self._show("opt-usim", "ef-msisdn")
        self.assertEqual((shown["body_record_size"], shown["body_record_count"]), (28, 3))
        self.assertEqual(len(shown["records"]), 3)
        self.assertFalse(shown["records"][0]["empty"])
        source = self._row_at("3F00/7F10/6F40")
        source_shown = self._show(source["section_key"], source["field_path"])
        self.assertEqual(
            [entry.get("decoded") for entry in shown["records"]],
            [entry.get("decoded") for entry in source_shown["records"]],
        )

    def test_link_to_a_link_reaches_the_template_source(self) -> None:
        row = self._row_at("3F00/7F20/6F54")
        shown = self._show(row["section_key"], row["field_path"])
        link = shown["link_source"]
        self.assertEqual(link["chain"], ["3F00/7F10/6F54"])
        self.assertEqual((link["section_key"], link["field_path"]), ("telecom", "ef-sume"))
        source_shown = self._show("telecom", "ef-sume")
        self.assertEqual(shown["body_hex"], source_shown["body_hex"])
        self.assertEqual(shown["decoded"], source_shown["decoded"])

    def test_independent_file_carries_no_link_block(self) -> None:
        self.assertNotIn("link_source", self._show("usim", "ef-arr"))

    def test_whole_body_write_through_a_link_lands_on_the_source(self) -> None:
        source = self._row_at("3F00/7F20/6F46")
        written = saip_actions._dispatch_update_file_content(
            None, session_id=self.sid, section_key="usim", field_path="ef-spn",
            hex_value="01546573744E6574",
        )
        self.assertEqual(
            (written["section_key"], written["field_path"]),
            (source["section_key"], source["field_path"]),
        )
        self.assertEqual(
            written["link_entry"],
            {"section_key": "usim", "field_path": "ef-spn", "fid_chain": "ADF.USIM/6F46"},
        )
        self.assertEqual([alias["fid_chain"] for alias in written["link_aliases"]], ["ADF.USIM/6F46"])
        self.assertEqual(written["new_hex"], "01546573744E6574" + "FF" * 9)
        usim_index = saip_actions._resolve_pe_index(self.handle, "usim")
        self.assertIn(written["pe_index"], self.handle["dirty_pes"])
        self.assertNotIn(usim_index, self.handle["dirty_pes"])
        self.assertEqual(self._show("usim", "ef-spn")["body_hex"], written["new_hex"])
        # The link entry itself gained no content tuples.
        self.assertEqual([name for name, _value in self._payload("usim", "ef-spn")], ["fileDescriptor"])

    def test_record_write_through_a_link_lands_on_the_source(self) -> None:
        written = saip_actions._dispatch_update_record_bytes(
            None, session_id=self.sid, section_key="opt-usim", field_path="ef-msisdn",
            record_index=2, hex_value="AA",
        )
        self.assertEqual(written["section_key"], "genericFileManagement")
        self.assertEqual(written["record_size"], 28)
        self.assertEqual(written["link_entry"]["field_path"], "ef-msisdn")
        shown = self._show("opt-usim", "ef-msisdn")
        self.assertFalse(shown["records"][1]["empty"])
        self.assertEqual(shown["body_hex"][56:58], "AA")

    def test_write_to_the_source_names_its_links(self) -> None:
        source = self._row_at("3F00/7F20/6F46")
        written = saip_actions._dispatch_update_file_content(
            None, session_id=self.sid, section_key=source["section_key"],
            field_path=source["field_path"], hex_value="00",
        )
        self.assertNotIn("link_entry", written)
        self.assertEqual([alias["fid_chain"] for alias in written["link_aliases"]], ["ADF.USIM/6F46"])

    def test_json_edit_stays_on_the_link_entry(self) -> None:
        shown = self._show("usim", "ef-spn")
        written = saip_actions._dispatch_update_file_decoded(
            None, session_id=self.sid, section_key="usim", field_path="ef-spn",
            payload=shown["payload"],
        )
        self.assertEqual((written["section_key"], written["field_path"]), ("usim", "ef-spn"))

    def test_unresolvable_link_shows_the_entry_itself_and_refuses_writes(self) -> None:
        shown = self._show("usim", "ef-spn")
        payload = shown["payload"]
        payload[0][1]["linkPath"] = "7F206FEE"
        saip_actions._dispatch_update_file_decoded(
            None, session_id=self.sid, section_key="usim", field_path="ef-spn", payload=payload
        )
        again = self._show("usim", "ef-spn")
        self.assertFalse(again["link_source"]["resolved"])
        self.assertIn("no file at 3F00/7F20/6FEE", again["link_source"]["reason"])
        self.assertNotIn("section_key", again["link_source"])
        with self.assertRaises(ValueError) as caught:
            saip_actions._dispatch_update_file_content(
                None, session_id=self.sid, section_key="usim", field_path="ef-spn", hex_value="00"
            )
        self.assertIn("not in this package", str(caught.exception))

    def test_link_with_its_own_content_shows_it_over_the_source_and_refuses_writes(self) -> None:
        shown = self._show("usim", "ef-spn")
        payload = list(shown["payload"]) + [["fillFileContent", "02"]]
        saip_actions._dispatch_update_file_decoded(
            None, session_id=self.sid, section_key="usim", field_path="ef-spn", payload=payload
        )
        again = self._show("usim", "ef-spn")
        self.assertEqual(again["link_source"]["own_content_bytes"], 1)
        self.assertEqual(again["body_hex"][:2], "02")
        self.assertEqual(again["body_hex"][2:], shown["body_hex"][2:])
        with self.assertRaises(ValueError) as caught:
            saip_actions._dispatch_update_file_content(
                None, session_id=self.sid, section_key="usim", field_path="ef-spn", hex_value="00"
            )
        self.assertIn("of its own", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
