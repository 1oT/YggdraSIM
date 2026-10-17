# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A record file's count lives in efFileSize, never in its file descriptor.

TCA SAIP V3.4.1 §8.3.2 codes ``Fcp.fileDescriptor`` as ``SIZE(2..4)`` per ETSI
TS 102 222 V17.1.0 §6.3.2.2.2 Table 4: the descriptor byte, the data coding
byte and, for a linear fixed or cyclic EF, the 2-byte record length. Tag '80'
(efFileSize) is record length x records. The 5-byte layout ending in a record
count is the SELECT response of TS 102 221 V18.4.0 §11.1.1.4.3; a card that
meets it in a profile answers invalid-request-format.

These tests pin the write boundary (``saip.update_file_field`` and
``saip.gfm_add_file_element``), the linter's pass over the Fcps pySim decodes
as ``(choice, payload)`` tuples, and how the decoders read a stored fifth byte.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict
from pathlib import Path
from typing import Any
from unittest import mock

from Tools.ProfilePackage.lint_engine import SaipProfileLinter
from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_file_descriptor,
    _record_layout_from_descriptor_payload,
)
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


def _fcp(descriptor: str, fid: str, size: str = "") -> OrderedDict:
    fcp: OrderedDict = OrderedDict(
        [("fileDescriptor", bytes.fromhex(descriptor)), ("fileID", bytes.fromhex(fid))]
    )
    if size:
        fcp["efFileSize"] = bytes.fromhex(size)
    return fcp


class _GfmPe:
    type = "genericFileManagement"

    def __init__(self, transaction: list[tuple[str, Any]]) -> None:
        self.files: dict[str, Any] = {}
        self.decoded = {"fileManagementCMD": [list(transaction)]}


class _StubPes:
    def __init__(self, pes: list[Any]) -> None:
        self.pe_list = pes


class DescriptorShapeTests(unittest.TestCase):
    """``_check_create_fcp_descriptor``: 2 bytes, or 4 for a record file."""

    def test_a_record_descriptor_is_four_bytes(self) -> None:
        # Shareable and not shareable linear fixed, shareable cyclic.
        for descriptor in ("42210002", "0221001C", "4621000A"):
            saip_module._check_create_fcp_descriptor(bytes.fromhex(descriptor))

    def test_a_fifth_byte_is_refused_naming_the_count(self) -> None:
        with self.assertRaisesRegex(ValueError, r"record count \(250\).*efFileSize"):
            saip_module._check_create_fcp_descriptor(bytes.fromhex("42210002FA"))

    def test_a_record_descriptor_needs_its_record_length(self) -> None:
        for descriptor in ("4221", "422100", "42210000"):
            with self.assertRaises(ValueError, msg=descriptor):
                saip_module._check_create_fcp_descriptor(bytes.fromhex(descriptor))

    def test_other_structures_take_two_bytes(self) -> None:
        # Transparent EF, DF, BER-TLV EF (TS 102 221 V18.4.0 Table 11.5).
        for descriptor in ("4121", "7821", "7921"):
            saip_module._check_create_fcp_descriptor(bytes.fromhex(descriptor))
        with self.assertRaises(ValueError):
            saip_module._check_create_fcp_descriptor(bytes.fromhex("41210000"))

    def test_the_size_is_written_on_the_fewest_octets(self) -> None:
        self.assertEqual(saip_module._minimal_size_octets(100), b"\x64")
        self.assertEqual(saip_module._minimal_size_octets(500), b"\x01\xf4")
        self.assertEqual(saip_module._minimal_size_octets(0), b"\x00")


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class GfmRecordCountTests(unittest.TestCase):
    """``saip.update_file_field`` on a generic file management record file."""

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

    def _update(self, handle: dict[str, Any], sub_key: str, hex_value: str, **extra: Any) -> Any:
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
                field_path="fileManagementCMD[0][0]",
                sub_key=sub_key,
                hex_value=hex_value,
                **extra,
            )

    @staticmethod
    def _fcp_of(handle: dict[str, Any]) -> OrderedDict:
        return handle["pes"].pe_list[0].decoded["fileManagementCMD"][0][0][1]

    def _record_file(self) -> dict[str, Any]:
        return self._handle(
            [
                ("createFCP", _fcp("42210005", "6F3C", "0A")),
                ("fillFileContent", bytes.fromhex("AABB")),
            ]
        )

    def test_the_record_count_sets_ef_file_size_in_the_same_edit(self) -> None:
        handle = self._record_file()
        result = self._update(handle, "fileDescriptor", "4221000A", record_count=3)
        fcp = self._fcp_of(handle)
        self.assertEqual(fcp["fileDescriptor"], bytes.fromhex("4221000A"))
        self.assertEqual(fcp["efFileSize"], b"\x1e")
        self.assertEqual(result["ef_file_size"], "1E")
        self.assertEqual(result["content_reset"]["size"], 30)

    def test_two_hundred_and_fifty_records_take_two_size_octets(self) -> None:
        handle = self._record_file()
        self._update(handle, "fileDescriptor", "42210002", record_count="250")
        fcp = self._fcp_of(handle)
        self.assertEqual(fcp["fileDescriptor"], bytes.fromhex("42210002"))
        self.assertEqual(fcp["efFileSize"], bytes.fromhex("01F4"))

    def test_a_fifth_descriptor_byte_is_refused_and_nothing_changes(self) -> None:
        handle = self._record_file()
        with self.assertRaises(ValueError):
            self._update(handle, "fileDescriptor", "42210002FA")
        self.assertEqual(self._fcp_of(handle), _fcp("42210005", "6F3C", "0A"))

    def test_a_partial_last_record_is_refused_without_a_count(self) -> None:
        handle = self._record_file()
        with self.assertRaisesRegex(ValueError, "record_count"):
            self._update(handle, "fileDescriptor", "42210003")
        self.assertEqual(self._fcp_of(handle), _fcp("42210005", "6F3C", "0A"))

    def test_the_record_count_belongs_to_a_record_descriptor(self) -> None:
        handle = self._record_file()
        with self.assertRaises(ValueError):
            self._update(handle, "efFileSize", "14", record_count=2)
        with self.assertRaises(ValueError):
            self._update(handle, "fileDescriptor", "4121", record_count=2)
        for count in (0, 255, "x"):
            with self.assertRaises(ValueError, msg=repr(count)):
                self._update(handle, "fileDescriptor", "42210005", record_count=count)
        self.assertEqual(self._fcp_of(handle), _fcp("42210005", "6F3C", "0A"))

    def test_ef_file_size_is_stored_on_the_fewest_octets(self) -> None:
        handle = self._record_file()
        result = self._update(handle, "efFileSize", "000F")
        self.assertEqual(result["new_hex"], "0F")
        self.assertEqual(self._fcp_of(handle)["efFileSize"], b"\x0f")

    def test_a_record_file_size_takes_whole_records(self) -> None:
        handle = self._record_file()
        with self.assertRaisesRegex(ValueError, "whole number of 5 B records"):
            self._update(handle, "efFileSize", "0B")
        self.assertEqual(self._fcp_of(handle), _fcp("42210005", "6F3C", "0A"))


@unittest.skipUnless(_REFERENCE_HEX.is_file(), "No tracked reference SAIP profile fixture")
class TemplateRecordCountTests(unittest.TestCase):
    """MF EF.DIR of the reference profile: 4 records of 38 bytes."""

    @classmethod
    def setUpClass(cls) -> None:
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.manager = get_manager()

    def setUp(self) -> None:
        self.sid = saip_module._dispatch_open_package(None, path=str(_REFERENCE_HEX))["session_id"]
        self.handle = self.manager.claim(self.sid)
        self.pe = self.handle["pes"].pe_list[saip_module._resolve_pe_index(self.handle, "mf")]

    def tearDown(self) -> None:
        self.manager.close(self.sid)

    def _fcp(self) -> dict[str, Any]:
        choices = saip_module._mutable_file_choice_list_for_path(self.pe, "ef-dir")
        return saip_module._fcp_host_payload(choices)

    def _lint_codes(self) -> list[tuple[str, str]]:
        document = {"sections": {"mf": self.pe.decoded}}
        report = SaipProfileLinter().lint_decoded_document(document, "reference")
        return [(item.code, item.path) for item in report.findings if item.code.startswith("YRL-FIL")]

    def test_the_record_count_resizes_the_template_file(self) -> None:
        result = saip_module._dispatch_update_file_field(
            None, session_id=self.sid, section_key="mf", field_path="ef-dir",
            sub_key="fileDescriptor", hex_value="42210026", record_count=6,
        )
        self.assertEqual(result["ef_file_size"], "E4")
        self.assertEqual(self._fcp()["fileDescriptor"], bytes.fromhex("42210026"))
        self.assertEqual(self._fcp()["efFileSize"], b"\xe4")
        shown = saip_module._dispatch_show_file(
            None, session_id=self.sid, section_key="mf", field_path="ef-dir"
        )
        self.assertEqual(shown["body_declared_size"], 228)

    def test_a_stored_fifth_byte_is_linted_and_apply_writes_it_right(self) -> None:
        # The state the record-count editor used to leave: a 5-byte
        # descriptor whose count disagrees with efFileSize.
        self._fcp()["fileDescriptor"] = bytes.fromhex("42210026FA")
        self.assertIn(("YRL-FIL-002", "mf::ef-dir"), self._lint_codes())
        saip_module._dispatch_update_file_field(
            None, session_id=self.sid, section_key="mf", field_path="ef-dir",
            sub_key="fileDescriptor", hex_value="42210026", record_count=4,
        )
        self.assertEqual(self._fcp()["fileDescriptor"], bytes.fromhex("42210026"))
        self.assertEqual(self._fcp()["efFileSize"], b"\x98")
        self.assertEqual(self._lint_codes(), [])


@unittest.skipUnless(_REFERENCE_HEX.is_file(), "No tracked reference SAIP profile fixture")
class GfmAddFileSizingTests(unittest.TestCase):
    """``saip.gfm_add_file_element``: record size and count reach the Fcp."""

    @classmethod
    def setUpClass(cls) -> None:
        from yggdrasim_common.gui_server.sessions import get_manager

        cls.manager = get_manager()

    def setUp(self) -> None:
        self.sid = saip_module._dispatch_open_package(None, path=str(_REFERENCE_HEX))["session_id"]
        self.handle = self.manager.claim(self.sid)

    def tearDown(self) -> None:
        self.manager.close(self.sid)

    def _add(self, **inputs: Any) -> dict[str, Any]:
        return saip_module._dispatch_gfm_add_file_element(
            None, session_id=self.sid, section_key=SECTION, parent_path="7F10",
            file_id="6F77", **inputs,
        )

    def _created(self, result: dict[str, Any]) -> dict[str, Any]:
        pe = self.handle["pes"].pe_list[result["pe_index"]]
        transaction = pe.decoded["fileManagementCMD"][result["transaction_index"]]
        return dict(transaction[-1][1])

    def test_record_size_and_count_build_descriptor_and_size(self) -> None:
        result = self._add(file_descriptor="4221", record_size="1E", record_count="02")
        self.assertEqual((result["file_descriptor"], result["ef_file_size"]), ("4221001E", "3C"))
        fcp = self._created(result)
        self.assertEqual(fcp["fileDescriptor"], bytes.fromhex("4221001E"))
        self.assertEqual(fcp["efFileSize"], b"\x3c")
        self.assertNotIn("proprietaryEFInfo", fcp)

    def test_sizes_that_disagree_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            self._add(file_descriptor="4221001E", record_count="02", ef_size="3D")
        with self.assertRaises(ValueError):
            self._add(file_descriptor="4221001E", ef_size="3D")
        with self.assertRaises(ValueError):
            self._add(file_descriptor="4221001E", record_size="1F")
        with self.assertRaises(ValueError):
            self._add(file_descriptor="4121", record_count="02")
        with self.assertRaises(ValueError):
            self._add(file_descriptor="4221001E02")


class LintTupleFcpTests(unittest.TestCase):
    """The pySim tuple shape of template PEs and GFM transactions is linted."""

    @staticmethod
    def _findings(sections: dict[str, Any]) -> list[tuple[str, str]]:
        report = SaipProfileLinter().lint_decoded_document({"sections": sections}, "unit")
        return [(item.code, item.path) for item in report.findings if item.code.startswith("YRL-FIL")]

    def test_a_template_file_with_a_fifth_byte_fails(self) -> None:
        telecom = {
            "ef-pbc": [("fileDescriptor", _fcp("42210002FA", "4F09", "64"))],
            "ef-gas": [("fileDescriptor", _fcp("42210018", "4F4C", "60"))],
        }
        self.assertEqual(self._findings({"telecom": telecom}), [("YRL-FIL-002", "telecom::ef-pbc")])

    def test_a_gfm_record_file_needs_whole_records(self) -> None:
        gfm = {
            "fileManagementCMD": [
                [
                    ("filePath", bytes.fromhex("7F10")),
                    ("createFCP", _fcp("4221001C", "6F3A", "0578")),
                    ("createFCP", _fcp("4221001C", "6F3B", "0579")),
                    ("createFCP", _fcp("42210001", "6F3C", "FF")),
                ]
            ]
        }
        self.assertEqual(
            self._findings({SECTION: gfm}),
            [
                ("YRL-FIL-067", f"{SECTION}::fileManagementCMD[0][2]"),
                ("YRL-FIL-038", f"{SECTION}::fileManagementCMD[0][3]"),
            ],
        )


class DecoderFifthByteTests(unittest.TestCase):
    """A stored fifth byte is reported; efFileSize still sizes the file."""

    def test_the_decoder_warns_about_a_fifth_byte(self) -> None:
        decoded = _decode_file_descriptor(bytes.fromhex("42210002FA"))
        self.assertEqual(decoded["numberOfRecords"], 250)
        self.assertIn("card rejects", decoded["warning"])
        self.assertNotIn("derivedFileSize", decoded)
        self.assertNotIn("warning", _decode_file_descriptor(bytes.fromhex("42210002")))

    def test_ef_file_size_gives_the_record_count(self) -> None:
        payload = {"fileDescriptor": bytes.fromhex("42210002FA"), "efFileSize": b"\x64"}
        self.assertEqual(_record_layout_from_descriptor_payload(payload), (2, 50, 100))


if __name__ == "__main__":
    unittest.main()
