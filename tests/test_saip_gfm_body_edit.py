# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Body edits on files a genericFileManagement PE creates.

A GFM PE carries no ``pe.decoded[field_path]`` entry and no pySim ``File``
under the workbench's ``fileManagementCMD[i][j]`` address, so
``saip.update_file_content`` and ``saip.update_record_bytes`` resolve the
``createFCP`` and the body span that follows it (TCA Profile interoperability
technical specification V3.4.1 §8.3.5) and splice the re-encoded tuples back
into the live transaction.

The cases that decide the implementation:

  - an all-erased body survives the write. ``file_content_to_tuples`` with
    ``optimize=True`` compresses against the erased state when there is no
    template -- every GFM ``createFCP`` -- and encodes such a body as no tuples
    at all, so the operator's write would read back empty,
  - a span that gains or loses tuples moves every later ``createFCP``, which
    the response reports as ``gfm_reindexed`` so the GUI can drop the addresses
    it cached,
  - a span that opened with a no-op ``fillFileOffset`` of zero keeps it, which
    holds the transaction length steady for that encoding style.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict
from typing import Any
from unittest import mock

from yggdrasim_common.gui_server.actions import saip as saip_module

try:
    from pySim.esim.saip import File as _PysimFile
except ImportError:  # pragma: no cover -- exercised on a pySim-less install
    _PysimFile = None


SECTION = "genericFileManagement_2"

# Transparent EF, 8 bytes; cyclic EF, one 3-byte record; DF. The descriptor
# bytes are ETSI TS 102 222 v17.1 6.3.2.2.1 file descriptors, the identifiers
# are from the 3GPP TS 31.102 file range.
_FCP_TRANSPARENT = OrderedDict(
    [
        ("fileDescriptor", b"\x41\x21"),
        ("fileID", b"\x6f\x3e"),
        ("efFileSize", b"\x08"),
        ("lcsi", b"\x05"),
    ]
)
_FCP_CYCLIC = OrderedDict(
    [
        ("fileDescriptor", b"\x46\x21\x00\x03"),
        ("fileID", b"\x6f\x39"),
        ("efFileSize", b"\x03"),
        ("lcsi", b"\x05"),
    ]
)
_FCP_SIZELESS = OrderedDict(
    [
        ("fileDescriptor", b"\x41\x21"),
        ("fileID", b"\x6f\x41"),
        ("lcsi", b"\x05"),
    ]
)
_FCP_DF = OrderedDict(
    [
        ("fileDescriptor", b"\x38\x21"),
        ("fileID", b"\x7f\x20"),
    ]
)


class _GfmPe:
    """Stand-in for ``pySim.esim.saip.ProfileElementGFM``."""

    type = "genericFileManagement"

    def __init__(self, transaction: list[tuple[str, Any]]) -> None:
        # pySim indexes a GFM PE's files by the path it walks through the
        # transaction, never by the workbench address, so this dict is
        # deliberately empty -- that is what the dispatchers see in a session.
        self.files: dict[str, Any] = {}
        self.decoded = {"fileManagementCMD": [list(transaction)]}


class _StubPes:
    def __init__(self, pes: list[Any]) -> None:
        self.pe_list = pes


class _GfmDispatchCase(unittest.TestCase):
    """Shared session stub and dispatcher plumbing."""

    def _build_handle(self, transaction: list[tuple[str, Any]]) -> dict[str, Any]:
        return {
            "pes": _StubPes([_GfmPe(transaction)]),
            "source_path": "/tmp/example.der",
            "decoded_document": {"sections": {SECTION: {}}, "intro": []},
            "dirty_pes": set(),
            "applied_overrides": {},
        }

    def _transaction(self, handle: dict[str, Any]) -> list[tuple[str, Any]]:
        return handle["pes"].pe_list[0].decoded["fileManagementCMD"][0]

    def _span(
        self,
        handle: dict[str, Any],
        cmd_index: int,
    ) -> list[tuple[str, Any]]:
        """Return the body tuples that follow the createFCP at ``cmd_index``."""
        transaction = self._transaction(handle)
        out: list[tuple[str, Any]] = []
        for item in transaction[cmd_index + 1:]:
            if item[0] in ("createFCP", "filePath"):
                break
            out.append(item)
        return out

    def _dispatch(
        self,
        dispatcher: Any,
        handle: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        manager_stub = mock.Mock()
        manager_stub.claim.return_value = handle
        with (
            mock.patch.object(
                saip_module,
                "_refresh_decoded_document",
                lambda _h: None,
            ),
            mock.patch(
                "yggdrasim_common.gui_server.sessions.get_manager",
                return_value=manager_stub,
            ),
        ):
            return dispatcher(
                ctx=mock.Mock(),
                session_id="sid-test",
                section_key=SECTION,
                **kwargs,
            )

    def _update_content(
        self,
        handle: dict[str, Any],
        field_path: str,
        hex_value: str,
    ) -> dict[str, Any]:
        return self._dispatch(
            saip_module._dispatch_update_file_content,
            handle,
            field_path=field_path,
            hex_value=hex_value,
        )

    def _update_record(
        self,
        handle: dict[str, Any],
        field_path: str,
        record_index: int,
        hex_value: str,
    ) -> dict[str, Any]:
        return self._dispatch(
            saip_module._dispatch_update_record_bytes,
            handle,
            field_path=field_path,
            record_index=record_index,
            hex_value=hex_value,
        )


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class GfmBodyTargetTests(_GfmDispatchCase):
    """Resolution of the synthetic ``fileManagementCMD[i][j]`` address."""

    def test_target_carries_the_span_and_a_built_file(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileOffset", 0),
                ("fillFileContent", b"connect1"),
                ("createFCP", _FCP_CYCLIC),
            ]
        )
        pe = handle["pes"].pe_list[0]

        target = saip_module._gfm_body_target(pe, "fileManagementCMD[0][0]")

        self.assertIsNotNone(target)
        transaction, cmd_index, span_end, pe_file = target
        self.assertIs(transaction, self._transaction(handle))
        self.assertEqual((cmd_index, span_end), (0, 3))
        self.assertEqual(pe_file.file_type, "TR")
        self.assertEqual(pe_file.fid, 0x6F3E)
        self.assertEqual(pe_file.file_size, 8)
        self.assertEqual(bytes(pe_file.body), b"connect1")

    def test_span_stops_at_a_file_path(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileContent", b"connect1"),
                ("filePath", b"\x7f\x20"),
                ("fillFileContent", b"\x00\x00\x00"),
            ]
        )
        pe = handle["pes"].pe_list[0]

        _transaction, _cmd, span_end, _file = saip_module._gfm_body_target(
            pe, "fileManagementCMD[0][0]"
        )

        self.assertEqual(span_end, 2)

    def test_non_gfm_pe_and_out_of_range_addresses_resolve_to_none(self) -> None:
        handle = self._build_handle([("createFCP", _FCP_TRANSPARENT)])
        pe = handle["pes"].pe_list[0]

        self.assertIsNone(
            saip_module._gfm_body_target(pe, "fileManagementCMD[0][7]")
        )
        self.assertIsNone(
            saip_module._gfm_body_target(pe, "fileManagementCMD[4][0]")
        )
        self.assertIsNone(saip_module._gfm_body_target(pe, "ef-imsi"))

        pe.type = "usim"
        self.assertIsNone(
            saip_module._gfm_body_target(pe, "fileManagementCMD[0][0]")
        )


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class UpdateFileContentGfmTests(_GfmDispatchCase):
    """Whole-body writes against a GFM-created EF."""

    def _single_file_handle(self) -> dict[str, Any]:
        return self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileContent", b"connect1"),
            ]
        )

    def test_body_is_replaced_in_the_live_transaction(self) -> None:
        handle = self._single_file_handle()

        result = self._update_content(
            handle, "fileManagementCMD[0][0]", "0102030405060708"
        )

        self.assertEqual(result["byte_count"], 8)
        self.assertEqual(result["file_type"], "TR")
        self.assertEqual(result["pad_bytes"], 0)
        self.assertIs(result["gfm_reindexed"], False)
        self.assertEqual(
            self._span(handle, 0),
            [("fillFileContent", bytes.fromhex("0102030405060708"))],
        )
        self.assertIn(0, handle["dirty_pes"])

    def test_all_erased_body_is_written_verbatim(self) -> None:
        # The regression that ``optimize=False`` on the GFM path exists for:
        # a createFCP has no template, so the optimiser compresses an all-FF
        # body down to no tuples at all and the write reads back empty.
        handle = self._single_file_handle()

        self._update_content(handle, "fileManagementCMD[0][0]", "FF" * 8)

        self.assertEqual(self._span(handle, 0), [("fillFileContent", b"\xff" * 8)])

    def test_short_write_is_padded_to_the_declared_size(self) -> None:
        handle = self._single_file_handle()

        result = self._update_content(handle, "fileManagementCMD[0][0]", "AABB")

        self.assertEqual(result["new_hex"], "AABBFFFFFFFFFFFF")
        self.assertEqual(result["pad_bytes"], 6)
        self.assertEqual(result["pad_source"], "erased")
        self.assertEqual(
            self._span(handle, 0),
            [("fillFileContent", bytes.fromhex("AABBFFFFFFFFFFFF"))],
        )

    def test_single_byte_write_is_padded(self) -> None:
        handle = self._single_file_handle()

        result = self._update_content(handle, "fileManagementCMD[0][0]", "5A")

        self.assertEqual(result["new_hex"], "5AFFFFFFFFFFFFFF")
        self.assertEqual(result["byte_count"], 8)

    def test_write_longer_than_the_declared_size_is_refused(self) -> None:
        handle = self._single_file_handle()

        with self.assertRaises(ValueError) as caught:
            self._update_content(handle, "fileManagementCMD[0][0]", "00" * 9)

        self.assertIn("file_size declares 8", str(caught.exception))
        self.assertEqual(self._span(handle, 0), [("fillFileContent", b"connect1")])

    def test_empty_hex_is_refused(self) -> None:
        handle = self._single_file_handle()

        with self.assertRaises(ValueError):
            self._update_content(handle, "fileManagementCMD[0][0]", "")

    def test_a_descriptor_without_a_size_takes_the_body_unpadded(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_SIZELESS),
                ("fillFileContent", b"\x01\x02\x03"),
            ]
        )

        result = self._update_content(handle, "fileManagementCMD[0][0]", "AABB")

        self.assertEqual(result["pad_bytes"], 0)
        self.assertEqual(result["byte_count"], 2)
        self.assertEqual(self._span(handle, 0), [("fillFileContent", b"\xaa\xbb")])

    def test_a_no_op_leading_offset_is_preserved(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileOffset", 0),
                ("fillFileContent", b"connect1"),
                ("createFCP", _FCP_CYCLIC),
            ]
        )

        result = self._update_content(handle, "fileManagementCMD[0][0]", "00" * 8)

        self.assertIs(result["gfm_reindexed"], False)
        self.assertEqual(
            self._span(handle, 0),
            [("fillFileOffset", 0), ("fillFileContent", b"\x00" * 8)],
        )
        self.assertEqual(self._transaction(handle)[3][0], "createFCP")

    def test_a_file_created_without_content_reports_the_reindex(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("createFCP", _FCP_CYCLIC),
                ("fillFileContent", b"\x00\x00\x00"),
            ]
        )

        result = self._update_content(handle, "fileManagementCMD[0][0]", "00" * 8)

        self.assertIs(result["gfm_reindexed"], True)
        self.assertEqual(
            self._span(handle, 0),
            [("fillFileContent", b"\x00" * 8)],
        )
        # The cyclic file moved from index 1 to index 2.
        transaction = self._transaction(handle)
        self.assertEqual(transaction[2][0], "createFCP")
        self.assertEqual(transaction[2][1]["fileID"], b"\x6f\x39")

    def test_a_container_carries_no_body(self) -> None:
        handle = self._build_handle([("createFCP", _FCP_DF)])

        with self.assertRaises(ValueError) as caught:
            self._update_content(handle, "fileManagementCMD[0][0]", "AABB")

        self.assertIn("carries no body", str(caught.exception))

    def test_an_address_outside_the_transaction_still_raises(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileContent", b"connect1"),
            ]
        )

        with self.assertRaises(LookupError) as caught:
            self._update_content(handle, "fileManagementCMD[0][9]", "AABB")

        self.assertIn("no File object", str(caught.exception))


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class UpdateRecordBytesGfmTests(_GfmDispatchCase):
    """Per-record writes against a GFM-created record EF."""

    def test_record_splice_keeps_the_leading_offset(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_CYCLIC),
                ("fillFileOffset", 0),
                ("fillFileContent", b"\x00\x00\x00"),
            ]
        )

        result = self._update_record(handle, "fileManagementCMD[0][0]", 1, "AB")

        self.assertEqual(result["record_size"], 3)
        self.assertEqual(result["new_hex"], "ABFFFF")
        self.assertEqual(result["pad_bytes"], 2)
        self.assertEqual(result["pad_source"], "erased")
        self.assertIs(result["gfm_reindexed"], False)
        self.assertEqual(
            self._span(handle, 0),
            [("fillFileOffset", 0), ("fillFileContent", bytes.fromhex("ABFFFF"))],
        )

    def test_a_transparent_file_is_refused(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileContent", b"connect1"),
            ]
        )

        with self.assertRaises(ValueError) as caught:
            self._update_record(handle, "fileManagementCMD[0][0]", 1, "AB")

        self.assertIn("not record-fixed", str(caught.exception))


@unittest.skipUnless(_PysimFile is not None, "pySim required")
class UpdateFileDecodedGfmTests(_GfmDispatchCase):
    """The JSON tab names the GFM limitation instead of reporting a miss."""

    def test_json_edit_is_refused_with_the_reason(self) -> None:
        handle = self._build_handle(
            [
                ("createFCP", _FCP_TRANSPARENT),
                ("fillFileContent", b"connect1"),
            ]
        )

        with self.assertRaises(ValueError) as caught:
            self._dispatch(
                saip_module._dispatch_update_file_decoded,
                handle,
                field_path="fileManagementCMD[0][0]",
                payload=[["fillFileContent", "AABB"]],
            )

        message = str(caught.exception)
        self.assertIn("generic file management", message)
        self.assertIn("Data tab", message)


if __name__ == "__main__":
    unittest.main()
