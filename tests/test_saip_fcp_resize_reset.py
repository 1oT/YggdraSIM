# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""An Fcp edit that resizes a file returns it to the content it is created with.

ETSI TS 102 222 V17.1.0 §6.3.2.2.2 creates an EF from its Filling or Repeat
Pattern, and TCA SAIP V3.4.1 §8.3.3 (page 30) makes ``fillFileContent`` /
``fillFileOffset`` an UPDATE after that creation. Content written for one
geometry has no meaning in another, so ``saip.update_file_field`` drops a
file's content entries when the file type, the record length or the size
changes -- or when a sizing edit leaves content running past the declared
size -- and the file reads back as its pattern, the template default, or
erased. Any other Fcp edit keeps the content, and the image follows the edited
Fcp at once instead of the object pySim cached at load.
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
    type = "genericFileManagement"

    def __init__(self, transaction: list[tuple[str, Any]]) -> None:
        self.files: dict[str, Any] = {}
        self.decoded = {"fileManagementCMD": [list(transaction)]}


class _StubPes:
    def __init__(self, pes: list[Any]) -> None:
        self.pe_list = pes


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class GfmResizeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from Tools.ProfilePackage.saip_pysim_compat import (
            install_erased_state_file_fill,
            install_record_aware_fill_pattern,
        )

        saip_module._ensure_pysim_importable()
        install_erased_state_file_fill()
        install_record_aware_fill_pattern()

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

    @staticmethod
    def _image(handle: dict[str, Any], field_path: str) -> Any:
        return saip_module._file_body_from_pe(
            pes=handle["pes"],
            decoded_document=handle["decoded_document"],
            section_key=SECTION,
            field_path=field_path,
        )

    @staticmethod
    def _transaction(handle: dict[str, Any]) -> list[tuple[str, Any]]:
        return handle["pes"].pe_list[0].decoded["fileManagementCMD"][0]

    def _two_files(self) -> dict[str, Any]:
        return self._handle(
            [
                ("createFCP", _fcp("4121", "6F05", "05")),
                ("fillFileContent", bytes.fromhex("0801040302")),
                ("createFCP", _fcp("4121", "6FAD", "04")),
                ("fillFileContent", bytes.fromhex("00000002")),
            ]
        )

    def test_a_new_size_drops_the_content_and_reads_erased(self) -> None:
        handle = self._two_files()
        result = self._update(handle, "fileManagementCMD[0][2]", "efFileSize", "03")
        self.assertEqual(
            result["content_reset"],
            {"reason": "resized", "dropped_bytes": 4, "source": "erased", "size": 3},
        )
        self.assertTrue(result["gfm_reindexed"])
        self.assertEqual(self._image(handle, "fileManagementCMD[0][2]")[0], b"\xff\xff\xff")
        # The file created before it keeps its content and its size.
        self.assertEqual(
            self._transaction(handle)[:2],
            [("createFCP", _fcp("4121", "6F05", "05")), ("fillFileContent", bytes.fromhex("0801040302"))],
        )

    def test_a_record_file_reads_its_pattern_at_the_new_count(self) -> None:
        handle = self._handle(
            [
                ("createFCP", _fcp("42210005", "6F3C", "0A", fillPattern="00FF")),
                ("fillFileContent", bytes.fromhex("01020304")),
            ]
        )
        result = self._update(handle, "fileManagementCMD[0][0]", "efFileSize", "0F")
        self.assertEqual(result["content_reset"]["source"], "fillPattern")
        body, rec_len, nb_rec, _size = self._image(handle, "fileManagementCMD[0][0]")
        self.assertEqual((rec_len, nb_rec), (5, 3))
        self.assertEqual(body, bytes.fromhex("00FFFFFFFF") * 3)

    def test_a_new_record_length_in_the_descriptor_resets_too(self) -> None:
        handle = self._handle(
            [
                ("createFCP", _fcp("42210005", "6F3C", "0A")),
                ("fillFileContent", bytes.fromhex("AABB")),
            ]
        )
        result = self._update(handle, "fileManagementCMD[0][0]", "fileDescriptor", "4221000A")
        self.assertEqual(result["content_reset"]["dropped_bytes"], 2)
        self.assertEqual(self._image(handle, "fileManagementCMD[0][0]")[0], b"\xff" * 10)

    def test_resizing_to_the_same_size_resets_only_content_that_does_not_fit(self) -> None:
        # Declared 3 B, holding 4: the state a size edit left before this rule.
        handle = self._handle(
            [("createFCP", _fcp("4121", "6FAD", "03")), ("fillFileContent", bytes.fromhex("00000002"))]
        )
        result = self._update(handle, "fileManagementCMD[0][0]", "efFileSize", "03")
        self.assertEqual(result["content_reset"]["reason"], "overflow")
        self.assertEqual(result["content_reset"]["dropped_bytes"], 4)
        self.assertEqual(self._image(handle, "fileManagementCMD[0][0]")[0], b"\xff" * 3)
        fitting = self._handle(
            [("createFCP", _fcp("4121", "6FAD", "04")), ("fillFileContent", bytes.fromhex("00000002"))]
        )
        self.assertNotIn("content_reset", self._update(fitting, "fileManagementCMD[0][0]", "efFileSize", "04"))

    def test_edits_that_keep_the_geometry_keep_the_content(self) -> None:
        for sub_key, value in (("lcsi", "05"), ("fileDescriptor", "0121"), ("securityAttributesReferenced", "03")):
            handle = self._two_files()
            result = self._update(handle, "fileManagementCMD[0][2]", sub_key, value)
            self.assertNotIn("content_reset", result, sub_key)
            self.assertEqual(
                self._image(handle, "fileManagementCMD[0][2]")[0], bytes.fromhex("00000002"), sub_key
            )


@unittest.skipUnless(_REFERENCE_HEX.is_file(), "No tracked reference SAIP profile fixture")
class TemplateFileResizeTests(unittest.TestCase):
    """Template files of the reference profile's MF."""

    @classmethod
    def setUpClass(cls) -> None:
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.manager = get_manager()

    def setUp(self) -> None:
        self.sid = saip_module._dispatch_open_package(None, path=str(_REFERENCE_HEX))["session_id"]
        self.handle = self.manager.claim(self.sid)

    def tearDown(self) -> None:
        self.manager.close(self.sid)

    def _update(self, field_path: str, sub_key: str, hex_value: str) -> dict[str, Any]:
        return saip_module._dispatch_update_file_field(
            None, session_id=self.sid, section_key="mf", field_path=field_path,
            sub_key=sub_key, hex_value=hex_value,
        )

    def _show(self, field_path: str) -> dict[str, Any]:
        return saip_module._dispatch_show_file(
            None, session_id=self.sid, section_key="mf", field_path=field_path
        )

    def test_a_new_size_drops_the_content_and_resizes_the_image(self) -> None:
        self.assertEqual(self._show("ef-iccid")["body_size"], 10)
        result = self._update("ef-iccid", "efFileSize", "0C")
        self.assertEqual(
            result["content_reset"],
            {"reason": "resized", "dropped_bytes": 10, "source": "erased", "size": 12},
        )
        shown = self._show("ef-iccid")
        self.assertEqual(shown["body_declared_size"], 12)
        self.assertEqual(shown["body_hex"].strip("F"), "")
        self.assertEqual([name for name, _value in shown["payload"]], ["fileDescriptor"])

    def test_a_placeholder_in_the_dropped_content_leaves_the_session(self) -> None:
        written = saip_module._dispatch_update_file_content(
            None, session_id=self.sid, section_key="mf", field_path="ef-iccid",
            hex_value="{iccid:ICCID:10}",
        )
        self.assertEqual(len(written["placeholders"]["added"]), 1)
        result = self._update("ef-iccid", "efFileSize", "0C")
        self.assertEqual(result["placeholders"]["dropped"], ["{iccid:ICCID:10}"])
        self.assertEqual(list(self.handle.get("inline_placeholder_records") or []), [])

    def test_a_pattern_edit_keeps_the_content_and_shows_at_once(self) -> None:
        # EF.PL carries '656E' over a 6-byte body; its Fcp names no descriptor.
        result = self._update("ef-pl", "proprietaryEFInfo.fillPattern", "AA")
        self.assertNotIn("content_reset", result)
        self.assertEqual(self._show("ef-pl")["body_hex"], "656EAAAAAAAA")


    def test_a_body_write_over_a_pattern_saves_what_it_shows(self) -> None:
        # Three differences from the 'AA' pattern, one byte equal to the
        # template default 'FF': the encoding has to start from the pattern
        # and move the pointer from where each write left it.
        self._update("ef-pl", "proprietaryEFInfo.fillPattern", "AA")
        written = saip_module._dispatch_update_file_content(
            None, session_id=self.sid, section_key="mf", field_path="ef-pl",
            hex_value="FFAA11AA22AA",
        )
        self.assertEqual(written["new_hex"], "FFAA11AA22AA")
        pe = self.handle["pes"].pe_list[saip_module._resolve_pe_index(self.handle, "mf")]
        self.assertEqual(saip_module._fcp_edit_file(pe, "ef-pl").body, bytes.fromhex("FFAA11AA22AA"))
        self.assertEqual(self._show("ef-pl")["body_hex"], "FFAA11AA22AA")


if __name__ == "__main__":
    unittest.main()
