# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the `saip.update_file_content` dispatcher.

Covers the whole-body write path that backs the YggdraSIM schema-aware EF
wizards and the workbench's "Whole file" hex scope. The dispatcher must:

  - accept transparent, BER-TLV, linear-fixed and cyclic EFs and refuse a
    DF, which carries no body,
  - pad short writes up to the declared size -- ``efFileSize`` for a
    transparent EF, record length times record count for a record-structured
    one -- with the file's Fcp fill / repeat pattern where it declares one,
    otherwise with the erased state; the pattern initialises every record
    anew (ETSI TS 102 222 6.3.2.2.2, tags '80', 'C1' and 'C2'),
  - replace ``fillFileContent`` / ``fillFileOffset`` tuples in
    ``pe.decoded`` while preserving every other tuple,
  - mark the PE dirty and refresh the cached decoded document.

The test stubs out the pySim-backed ``File`` object and patches the
two helpers that touch the disk (``_refresh_decoded_document``,
``get_manager``) so the suite runs without pySim installed; the pattern
cases use pySim's own ``ts_102_222.expand_pattern`` and skip when it is
absent.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict
from typing import Any
from unittest import mock

from yggdrasim_common.gui_server.actions import saip as saip_module

try:
    from pySim import ts_102_222 as _ts_102_222
except ImportError:  # pragma: no cover -- exercised on a pySim-less install
    _ts_102_222 = None


class _StubFile:
    """Minimal ``pySim.esim.saip.File`` stand-in."""

    def __init__(
        self,
        body: bytes,
        file_type: str = "TR",
        file_size: int | None = None,
        rec_len: int | None = None,
        nb_rec: int | None = None,
        fill_pattern: bytes | None = None,
        fill_pattern_repeat: bool = False,
    ) -> None:
        self.body = bytearray(body)
        self.file_type = file_type
        self._file_size = file_size
        self.rec_len = rec_len
        self.nb_rec = nb_rec
        self.fill_pattern = fill_pattern
        self.fill_pattern_repeat = fill_pattern_repeat

    @property
    def file_size(self) -> int | None:
        return self._file_size

    def file_content_to_tuples(self, *, optimize: bool = True) -> list:
        # Minimal optimiser stand-in: emit a single fillFileContent
        # tuple carrying the whole body. The real pySim splitter is
        # exercised by its own suite; here we only verify wiring.
        return [("fillFileContent", bytes(self.body))]


class _StubPe:
    def __init__(self, files: dict[str, _StubFile], decoded: dict[str, list]) -> None:
        self.files = files
        self.decoded = decoded


class _StubPes:
    def __init__(self, pes: list[_StubPe]) -> None:
        self.pe_list = pes


class TestUpdateFileContent(unittest.TestCase):
    """Whole-body splice for transparent EFs."""

    def _build_handle(
        self,
        pe_file: _StubFile,
        decoded_pre: list[tuple[str, Any]],
        path: str = "ef-imsi",
        section: str = "USIM (1)",
    ) -> dict[str, Any]:
        pe = _StubPe(
            files={path: pe_file},
            decoded={path: list(decoded_pre)},
        )
        pes = _StubPes([pe])
        handle = {
            "pes": pes,
            "source_path": "/tmp/example.der",
            "decoded_document": {"sections": {section: {}}, "intro": []},
            "dirty_pes": set(),
            "applied_overrides": {},
        }
        return handle

    def _run_dispatch(
        self,
        handle: dict[str, Any],
        *,
        section: str,
        field_path: str,
        hex_value: str,
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
            return saip_module._dispatch_update_file_content(
                ctx=mock.Mock(),
                session_id="sid-test",
                section_key=section,
                field_path=field_path,
                hex_value=hex_value,
            )

    def test_transparent_full_body_replace(self) -> None:
        pe_file = _StubFile(
            body=b"\xFF" * 9,
            file_type="TR",
            file_size=9,
        )
        decoded_pre = [
            ("fileDescriptor", OrderedDict([("fileDescriptor", b"\x41\x21\x00\x09")])),
            ("fillFileContent", b"\xFF" * 9),
        ]
        handle = self._build_handle(pe_file, decoded_pre)

        new_hex = "08" + "0102030405060708"  # 9 bytes
        result = self._run_dispatch(
            handle,
            section="USIM (1)",
            field_path="ef-imsi",
            hex_value=new_hex,
        )

        self.assertEqual(result["byte_count"], 9)
        self.assertEqual(result["file_type"], "TR")
        self.assertNotIn("record_size", result)
        self.assertEqual(result["new_hex"], new_hex.upper())
        self.assertEqual(bytes(pe_file.body), bytes.fromhex(new_hex))
        post = handle["pes"].pe_list[0].decoded["ef-imsi"]
        # FCP tuple preserved, fillFileContent replaced.
        self.assertEqual(post[0][0], "fileDescriptor")
        data_tuples = [t for t in post if t[0] in {"fillFileContent", "fillFileOffset"}]
        self.assertEqual(len(data_tuples), 1)
        self.assertEqual(data_tuples[0][1], bytes.fromhex(new_hex))
        self.assertIn(0, handle["dirty_pes"])

    def test_short_write_is_ff_padded(self) -> None:
        pe_file = _StubFile(
            body=b"\xFF" * 9,
            file_type="TR",
            file_size=9,
        )
        decoded_pre = [
            ("fillFileContent", b"\xFF" * 9),
        ]
        handle = self._build_handle(pe_file, decoded_pre)

        # 4 bytes; dispatcher should FF-pad to 9.
        result = self._run_dispatch(
            handle,
            section="USIM (1)",
            field_path="ef-imsi",
            hex_value="DEADBEEF",
        )

        expected = b"\xDE\xAD\xBE\xEF" + b"\xFF" * 5
        self.assertEqual(result["byte_count"], 9)
        self.assertEqual(bytes(pe_file.body), expected)

    @unittest.skipIf(_ts_102_222 is None, "pySim is not installed")
    def test_short_write_uses_fill_pattern(self) -> None:
        # Tag 'C2' (repeat pattern): the bytes the write does not cover carry
        # the pattern the file was created with, not a flat FF.
        pe_file = _StubFile(
            body=b"\x00" * 8,
            file_type="TR",
            file_size=8,
            fill_pattern=b"\xA5\xA6",
            fill_pattern_repeat=True,
        )
        handle = self._build_handle(pe_file, [])

        result = self._run_dispatch(
            handle,
            section="USIM (1)",
            field_path="ef-imsi",
            hex_value="DEADBEEF",
        )

        self.assertEqual(result["pad_bytes"], 4)
        self.assertEqual(result["pad_source"], "repeatPattern")
        self.assertEqual(
            bytes(pe_file.body),
            b"\xDE\xAD\xBE\xEF\xA5\xA6\xA5\xA6",
        )

    def test_oversize_write_rejected(self) -> None:
        pe_file = _StubFile(
            body=b"\xFF" * 4,
            file_type="TR",
            file_size=4,
        )
        handle = self._build_handle(pe_file, [])
        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(
                handle,
                section="USIM (1)",
                field_path="ef-imsi",
                hex_value="00" * 8,
            )
        self.assertIn("file_size", str(cm.exception))

    def test_df_rejected(self) -> None:
        pe_file = _StubFile(body=b"", file_type="DF")
        handle = self._build_handle(pe_file, [], path="df-telecom")
        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(
                handle,
                section="USIM (1)",
                field_path="df-telecom",
                hex_value="00",
            )
        self.assertIn("no body", str(cm.exception))


class TestUpdateFileContentRecordFixed(unittest.TestCase):
    """Whole-body splice for linear-fixed / cyclic EFs.

    The workbench's "Whole file" hex scope writes a record-structured EF
    through this dispatcher; the per-record splice is
    ``saip.update_record_bytes``.
    """

    SECTION = "mf"
    PATH = "ef-arr"

    def _build_handle(
        self,
        pe_file: _StubFile,
        decoded_pre: list[tuple[str, Any]] | None = None,
    ) -> dict[str, Any]:
        pe = _StubPe(
            files={self.PATH: pe_file},
            decoded={self.PATH: list(decoded_pre or [])},
        )
        return {
            "pes": _StubPes([pe]),
            "source_path": "/tmp/example.der",
            "decoded_document": {"sections": {self.SECTION: {}}, "intro": []},
            "dirty_pes": set(),
            "applied_overrides": {},
        }

    def _run_dispatch(self, handle: dict[str, Any], *, hex_value: str) -> dict[str, Any]:
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
            return saip_module._dispatch_update_file_content(
                ctx=mock.Mock(),
                session_id="sid-test",
                section_key=self.SECTION,
                field_path=self.PATH,
                hex_value=hex_value,
            )

    def test_full_body_replace(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 12, file_type="LF", rec_len=4, nb_rec=3)
        decoded_pre = [
            ("fileDescriptor", OrderedDict([("fileDescriptor", b"\x42\x21\x00\x04")])),
            ("fillFileContent", b"\xFF" * 4),
            ("fillFileOffset", 4),
            ("fillFileContent", b"\xFF" * 4),
        ]
        handle = self._build_handle(pe_file, decoded_pre)

        new_hex = "80010190" + "80017E97" + "00FFFFFF"
        result = self._run_dispatch(handle, hex_value=new_hex)

        self.assertEqual(result["file_type"], "LF")
        self.assertEqual(result["record_size"], 4)
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(result["byte_count"], 12)
        self.assertEqual(result["pad_bytes"], 0)
        self.assertEqual(bytes(pe_file.body), bytes.fromhex(new_hex))
        post = handle["pes"].pe_list[0].decoded[self.PATH]
        self.assertEqual(post[0][0], "fileDescriptor")
        data_tuples = [t for t in post if t[0] in {"fillFileContent", "fillFileOffset"}]
        self.assertEqual(len(data_tuples), 1)
        self.assertEqual(data_tuples[0][1], bytes.fromhex(new_hex))
        self.assertIn(0, handle["dirty_pes"])

    def test_cyclic_file_accepted(self) -> None:
        pe_file = _StubFile(body=b"\x00" * 6, file_type="CY", rec_len=3, nb_rec=2)
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, hex_value="010203040506")

        self.assertEqual(result["file_type"], "CY")
        self.assertEqual(result["record_count"], 2)
        self.assertEqual(bytes(pe_file.body), bytes.fromhex("010203040506"))

    def test_short_write_is_erased_padded(self) -> None:
        pe_file = _StubFile(body=b"\x00" * 12, file_type="LF", rec_len=4, nb_rec=3)
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, hex_value="DEAD BEEF 0102")

        self.assertEqual(result["pad_bytes"], 6)
        self.assertEqual(result["pad_source"], "erased")
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(
            bytes(pe_file.body),
            b"\xDE\xAD\xBE\xEF\x01\x02" + b"\xFF" * 6,
        )

    @unittest.skipIf(_ts_102_222 is None, "pySim is not installed")
    def test_short_write_restarts_fill_pattern_per_record(self) -> None:
        # Tag 'C1' 01 02 03 across 4-byte records expands to 01 02 03 03 in
        # every record. A write ending inside record 2 continues that
        # record's pattern (03 03) and record 3 starts over (01 02 03 03) --
        # the pattern is per record, not one run across the body.
        pe_file = _StubFile(
            body=b"\x00" * 12,
            file_type="LF",
            rec_len=4,
            nb_rec=3,
            fill_pattern=b"\x01\x02\x03",
        )
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, hex_value="DEADBEEF0102")

        self.assertEqual(result["pad_bytes"], 6)
        self.assertEqual(result["pad_source"], "fillPattern")
        self.assertEqual(
            bytes(pe_file.body),
            b"\xDE\xAD\xBE\xEF\x01\x02" + b"\x03\x03" + b"\x01\x02\x03\x03",
        )

    def test_record_count_derived_from_file_size(self) -> None:
        # pySim fills ``nb_rec`` lazily from the declared size; the
        # dispatcher takes the size the File reports when the count is absent.
        pe_file = _StubFile(
            body=b"\x00" * 12,
            file_type="LF",
            file_size=12,
            rec_len=4,
            nb_rec=None,
        )
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, hex_value="AA")

        self.assertEqual(result["byte_count"], 12)
        self.assertEqual(result["record_count"], 3)
        self.assertEqual(bytes(pe_file.body), b"\xAA" + b"\xFF" * 11)

    def test_oversize_write_names_the_record_geometry(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 12, file_type="LF", rec_len=4, nb_rec=3)
        handle = self._build_handle(pe_file)
        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(handle, hex_value="00" * 13)
        self.assertIn("3 records of 4 B", str(cm.exception))

    def test_missing_record_length_rejected(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 12, file_type="LF", rec_len=None, nb_rec=3)
        handle = self._build_handle(pe_file)
        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(handle, hex_value="00" * 4)
        self.assertIn("record length", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
