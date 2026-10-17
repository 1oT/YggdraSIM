# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The image and the FCP edits of a file generic file management creates.

ETSI TS 102 222 V17.1.0 §6.3.2.2.2 initialises a new EF from the Fcp Filling
Pattern (tag 'C1') or Repeat Pattern (tag 'C2'): across the body of a
transparent EF, across each record of a record EF. A GFM file has no
``pe.files`` entry under its ``fileManagementCMD[i][j]`` address, so
``saip.show_file`` builds its image from the live ``createFCP`` span -- the
pySim ``File`` the body editors write through -- instead of an erased virtual
image that ignores the pattern.

One GFM transaction creates any number of files (TCA SAIP V3.4.1 §8.3.5), so
an FCP edit addressed to one ``createFCP`` must land on that file: the whole
transaction handed to the mutation wrote the first ``createFCP`` that already
carried the member. A link entry's EF.ARR records are the source file's (TCA
SAIP V3.4.1 §8.3.3 note 1), which is where a citing file's access rule reads
them.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict
from pathlib import Path
from typing import Any
from unittest import mock

from yggdrasim_common.gui_server.actions import saip as saip_module

try:
    from pySim.esim.saip import File as _PysimFile
except ImportError:  # pragma: no cover -- exercised on a pySim-less install
    _PysimFile = None

_REFERENCE_HEX = (
    Path(__file__).resolve().parents[1]
    / "Tools"
    / "ProfilePackage"
    / "profile"
    / "reference_test_profile.txt"
)
SECTION = "genericFileManagement"


def _fcp(descriptor: str, fid: str, size: str = "", **proprietary: str) -> OrderedDict:
    fcp: OrderedDict = OrderedDict(
        [("fileDescriptor", bytes.fromhex(descriptor)), ("fileID", bytes.fromhex(fid))]
    )
    if size:
        fcp["efFileSize"] = bytes.fromhex(size)
    if proprietary:
        fcp["proprietaryEFInfo"] = OrderedDict(
            (name, bytes.fromhex(value)) for name, value in proprietary.items()
        )
    return fcp


class _GfmPe:
    """Stand-in for ``pySim.esim.saip.ProfileElementGFM``: no ``files`` entry
    under the workbench address, the transaction under ``decoded``."""

    type = "genericFileManagement"

    def __init__(self, transaction: list[tuple[str, Any]]) -> None:
        self.files: dict[str, Any] = {}
        self.decoded = {"fileManagementCMD": [list(transaction)]}


class _StubPes:
    def __init__(self, pes: list[Any]) -> None:
        self.pe_list = pes


def _image(transaction: list[tuple[str, Any]], cmd_index: int = 0) -> Any:
    return saip_module._file_body_from_pe(
        pes=_StubPes([_GfmPe(transaction)]),
        decoded_document={"sections": {SECTION: {}}},
        section_key=SECTION,
        field_path=f"fileManagementCMD[0][{cmd_index}]",
    )


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class GfmFileImageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from Tools.ProfilePackage.saip_pysim_compat import (
            install_erased_state_file_fill,
            install_record_aware_fill_pattern,
        )

        saip_module._ensure_pysim_importable()
        install_erased_state_file_fill()
        install_record_aware_fill_pattern()

    def test_fill_pattern_opens_every_record(self) -> None:
        # Four 5-byte records, fillPattern '00FF'.
        body, rec_len, nb_rec, size = _image(
            [("createFCP", _fcp("42210005", "6F3C", "14", fillPattern="00FF"))]
        )
        self.assertEqual((rec_len, nb_rec, size), (5, 4, 20))
        self.assertEqual(body, bytes.fromhex("00FFFFFFFF") * 4)

    def test_repeat_pattern_restarts_in_every_record(self) -> None:
        # A two-byte pattern in 5-byte records is cut at each record's end;
        # tiled across the whole body, record two would open with '5A'.
        body, _rec_len, _nb_rec, _size = _image(
            [("createFCP", _fcp("42210005", "6F3C", "0F", repeatPattern="A55A"))]
        )
        self.assertEqual(body, bytes.fromhex("A55AA55AA5") * 3)

    def test_content_lands_over_the_pattern(self) -> None:
        body, _rec_len, _nb_rec, _size = _image(
            [
                ("createFCP", _fcp("42210005", "6F3C", "14", fillPattern="00FF")),
                ("fillFileContent", b"\x01\x02"),
            ]
        )
        self.assertEqual(
            body, bytes.fromhex("0102FFFFFF") + bytes.fromhex("00FFFFFFFF") * 3
        )

    def test_short_body_without_a_pattern_reads_erased_to_the_declared_size(self) -> None:
        body, _rec_len, _nb_rec, size = _image(
            [("createFCP", _fcp("4121", "6F3E", "08")), ("fillFileContent", b"\x01\x02")]
        )
        self.assertEqual(size, 8)
        self.assertEqual(body, bytes.fromhex("0102FFFFFFFFFFFF"))

    def test_a_file_at_a_later_address_gets_its_own_image(self) -> None:
        transaction = [
            ("createFCP", _fcp("4121", "6F3E", "02")),
            ("fillFileContent", b"\xaa\xbb"),
            ("createFCP", _fcp("42210003", "6F3F", "06", fillPattern="00FF")),
        ]
        body, rec_len, nb_rec, _size = _image(transaction, cmd_index=2)
        self.assertEqual((rec_len, nb_rec), (3, 2))
        self.assertEqual(body, bytes.fromhex("00FFFF00FFFF"))

    def test_a_container_and_an_unsized_record_file_have_no_image(self) -> None:
        self.assertIsNone(_image([("createFCP", _fcp("3821", "7F20"))]))
        # Record length without a count or a size: pySim cannot size it, and
        # the virtual image stands in.
        self.assertIsNone(
            _image([("createFCP", _fcp("42210005", "6F3D", fillPattern="00FF"))])
        )


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class GfmFcpEditTargetTests(unittest.TestCase):
    """An FCP edit lands on the ``createFCP`` its address names."""

    def _handle(self, transaction: list[tuple[str, Any]]) -> dict[str, Any]:
        return {
            "pes": _StubPes([_GfmPe(transaction)]),
            "source_path": "/tmp/example.der",
            "decoded_document": {"sections": {SECTION: {}}, "intro": []},
            "dirty_pes": set(),
            "applied_overrides": {},
        }

    def _update(self, handle: dict[str, Any], field_path: str, sub_key: str, hex_value: str) -> Any:
        manager_stub = mock.Mock()
        manager_stub.claim.return_value = handle
        with (
            mock.patch.object(saip_module, "_refresh_decoded_document", lambda _h: None),
            mock.patch(
                "yggdrasim_common.gui_server.sessions.get_manager",
                return_value=manager_stub,
            ),
        ):
            return saip_module._dispatch_update_file_field(
                ctx=mock.Mock(),
                session_id="sid-test",
                section_key=SECTION,
                field_path=field_path,
                sub_key=sub_key,
                hex_value=hex_value,
            )

    def test_size_of_the_second_file_leaves_the_first_alone(self) -> None:
        first = _fcp("4121", "6F05", "05")
        second = _fcp("4121", "6FAD", "04")
        handle = self._handle(
            [
                ("createFCP", first),
                ("fillFileContent", bytes.fromhex("0801040302")),
                ("createFCP", second),
                ("fillFileContent", bytes.fromhex("00000002")),
            ]
        )
        self._update(handle, "fileManagementCMD[0][2]", "efFileSize", "03")
        self.assertEqual(second["efFileSize"], b"\x03")
        self.assertEqual(first["efFileSize"], b"\x05")

    def test_a_member_the_file_lacks_is_added_to_that_file(self) -> None:
        first = _fcp("42210005", "6F3B", "14", fillPattern="FF")
        second = _fcp("42210005", "6F3C", "14")
        handle = self._handle([("createFCP", first), ("createFCP", second)])
        self._update(handle, "fileManagementCMD[0][1]", "proprietaryEFInfo.fillPattern", "00FF")
        self.assertEqual(second["proprietaryEFInfo"]["fillPattern"], b"\x00\xff")
        self.assertEqual(first["proprietaryEFInfo"]["fillPattern"], b"\xff")

    def test_an_address_off_a_create_fcp_is_refused(self) -> None:
        handle = self._handle(
            [("createFCP", _fcp("4121", "6F3E", "02")), ("fillFileContent", b"\xaa\xbb")]
        )
        with self.assertRaises(LookupError):
            self._update(handle, "fileManagementCMD[0][1]", "efFileSize", "03")


@unittest.skipUnless(_REFERENCE_HEX.is_file(), "No tracked reference SAIP profile fixture")
class ReferenceProfileTests(unittest.TestCase):
    """The reference profile's GFM files under DF.TELECOM and its EF.ARR files."""

    @classmethod
    def setUpClass(cls) -> None:
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.manager = get_manager()

    def setUp(self) -> None:
        self.sid = saip_module._dispatch_open_package(None, path=str(_REFERENCE_HEX))["session_id"]
        self.handle = self.manager.claim(self.sid)

    def tearDown(self) -> None:
        self.manager.close(self.sid)

    def _show(self, section_key: str, field_path: str) -> dict[str, Any]:
        return saip_module._dispatch_show_file(
            None, session_id=self.sid, section_key=section_key, field_path=field_path
        )

    def _row_at(self, fid_chain: str) -> dict[str, Any]:
        for row in saip_module._filesystem_tree_rows(self.handle["decoded_document"]):
            if row["fid_chain"] == fid_chain:
                return row
        raise AssertionError(f"no row at {fid_chain}")

    def test_a_fill_pattern_set_on_a_gfm_record_file_opens_every_record(self) -> None:
        fdn = self._row_at("3F00/7F10/6F3B")
        adn = self._row_at("3F00/7F10/6F3A")
        self.assertEqual(fdn["section_key"], adn["section_key"])
        saip_module._dispatch_update_file_field(
            None,
            session_id=self.sid,
            section_key=fdn["section_key"],
            field_path=fdn["field_path"],
            sub_key="proprietaryEFInfo.fillPattern",
            hex_value="00FF",
        )
        shown = self._show(fdn["section_key"], fdn["field_path"])
        self.assertEqual((shown["body_record_size"], shown["body_record_count"]), (26, 20))
        body = bytes.fromhex(shown["body_hex"])
        self.assertEqual(body, (b"\x00" + b"\xff" * 25) * 20)
        # Still the content the file is created with: unallocated.
        self.assertTrue(all(entry["empty"] for entry in shown["records"]))
        # The ADN created earlier in the same transaction keeps its Fcp.
        self.assertEqual(self._show(adn["section_key"], adn["field_path"])["fcp"]["proprietary_fill_pattern"], "")

    def test_a_record_written_over_the_pattern_is_the_only_one_allocated(self) -> None:
        fdn = self._row_at("3F00/7F10/6F3B")
        common = {"session_id": self.sid, "section_key": fdn["section_key"], "field_path": fdn["field_path"]}
        saip_module._dispatch_update_file_field(
            None, sub_key="proprietaryEFInfo.fillPattern", hex_value="00FF", **common
        )
        saip_module._dispatch_update_record_bytes(None, record_index=2, hex_value="01", **common)
        records = self._show(fdn["section_key"], fdn["field_path"])["records"]
        self.assertEqual([entry["empty"] for entry in records[:3]], [True, False, True])
        self.assertEqual(sum(1 for entry in records if not entry["empty"]), 1)

    def test_a_linked_ef_arr_is_read_on_its_source(self) -> None:
        saip_module._dispatch_update_file_decoded(
            None,
            session_id=self.sid,
            section_key="telecom",
            field_path="ef-arr",
            payload=[["fileDescriptor", {"linkPath": "2F06", "lcsi": "05"}]],
        )
        rule = self._show("telecom", "ef-sume")["access_rule"]
        self.assertEqual((rule["arr_path"], rule["record"]), ("3F00/7F10/6F06", 3))
        self.assertTrue(rule["resolved"])
        self.assertEqual(rule["arr_link_source"], "3F00/2F06")
        source = next(
            entry for entry in self._show("mf", "ef-arr")["records"] if entry["record"] == 3
        )
        self.assertEqual(rule["summary"], source["decoded"]["summary"])


if __name__ == "__main__":
    unittest.main()
