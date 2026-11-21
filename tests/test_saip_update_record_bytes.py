# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the `saip.update_record_bytes` dispatcher.

The per-record write path backs the SAIP workbench's hex editors and rule
wizards. A value shorter than ``record_size`` is not an error: ETSI TS 102 222
§6.3.2.2 says the bytes the edit does not cover keep what the file was created
with -- its Fcp fill pattern (tag 'C1'), its repeat pattern (tag 'C2'), or the
erased state when it declares neither -- so the dispatcher completes the record
from that pattern and only refuses a value longer than the record.

The pySim-backed ``File`` is stubbed and the two helpers that touch the disk
(``_refresh_decoded_document``, ``get_manager``) are patched, so the cases with
no pattern run without pySim installed. The pattern cases use pySim's own
``ts_102_222.expand_pattern`` and skip when it is absent.
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
    """Minimal record-fixed ``pySim.esim.saip.File`` stand-in."""

    def __init__(
        self,
        body: bytes,
        rec_len: int,
        nb_rec: int,
        *,
        file_type: str = "LF",
        fill_pattern: bytes | None = None,
        fill_pattern_repeat: bool = False,
    ) -> None:
        self.body = bytes(body)
        self.file_type = file_type
        self.rec_len = rec_len
        self.nb_rec = nb_rec
        self.fill_pattern = fill_pattern
        self.fill_pattern_repeat = fill_pattern_repeat

    def file_content_to_tuples(self, *, optimize: bool = True) -> list:
        return [("fillFileContent", bytes(self.body))]


class _StubPe:
    def __init__(self, files: dict[str, _StubFile], decoded: dict[str, list]) -> None:
        self.files = files
        self.decoded = decoded


class _StubPes:
    def __init__(self, pes: list[_StubPe]) -> None:
        self.pe_list = pes


class TestUpdateRecordBytes(unittest.TestCase):
    """Per-record splice for linear-fixed / cyclic EFs."""

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

    def _run_dispatch(
        self,
        handle: dict[str, Any],
        *,
        record_index: int,
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
            return saip_module._dispatch_update_record_bytes(
                ctx=mock.Mock(),
                session_id="sid-test",
                section_key=self.SECTION,
                field_path=self.PATH,
                record_index=record_index,
                hex_value=hex_value,
            )

    def test_full_record_replace(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 12, rec_len=4, nb_rec=3)
        decoded_pre = [
            ("fileDescriptor", OrderedDict([("fileDescriptor", b"\x42\x21\x00\x04")])),
            ("fillFileContent", b"\xFF" * 12),
        ]
        handle = self._build_handle(pe_file, decoded_pre)

        result = self._run_dispatch(handle, record_index=2, hex_value="01020304")

        self.assertEqual(result["record_size"], 4)
        self.assertEqual(result["pad_bytes"], 0)
        self.assertEqual(result["pad_source"], "")
        self.assertEqual(
            pe_file.body,
            b"\xFF" * 4 + b"\x01\x02\x03\x04" + b"\xFF" * 4,
        )
        post = handle["pes"].pe_list[0].decoded[self.PATH]
        self.assertEqual(post[0][0], "fileDescriptor")
        self.assertIn(0, handle["dirty_pes"])

    def test_short_record_is_erased_padded(self) -> None:
        pe_file = _StubFile(body=b"\x00" * 12, rec_len=4, nb_rec=3)
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, record_index=1, hex_value="AABB")

        self.assertEqual(result["pad_bytes"], 2)
        self.assertEqual(result["pad_source"], "erased")
        self.assertEqual(result["new_hex"], "AABBFFFF")
        self.assertEqual(pe_file.body[:4], b"\xAA\xBB\xFF\xFF")
        # Records the edit does not name are left alone.
        self.assertEqual(pe_file.body[4:], b"\x00" * 8)

    def test_short_record_accepts_spaced_hex(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 8, rec_len=4, nb_rec=2)
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, record_index=1, hex_value="80 01 47")

        self.assertEqual(result["new_hex"], "800147FF")
        self.assertEqual(result["pad_bytes"], 1)

    def test_odd_length_hex_rejected(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 8, rec_len=4, nb_rec=2)
        handle = self._build_handle(pe_file)

        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(handle, record_index=1, hex_value="ABC")
        self.assertIn("odd length", str(cm.exception))

    def test_oversize_record_rejected(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 8, rec_len=4, nb_rec=2)
        handle = self._build_handle(pe_file)

        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(handle, record_index=1, hex_value="00" * 5)
        self.assertIn("longer than one record", str(cm.exception))

    @unittest.skipIf(_ts_102_222 is None, "pySim is not installed")
    def test_short_record_uses_fill_pattern(self) -> None:
        # Tag 'C1': the pattern opens the record and its last byte covers the
        # rest of it (TS 102 222 §6.3.2.2), so EF.EXT-style '00FF' keeps the
        # record-type byte only where the record starts.
        pe_file = _StubFile(
            body=b"\x11" * 16,
            rec_len=8,
            nb_rec=2,
            fill_pattern=b"\x00\xFF",
        )
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, record_index=2, hex_value="AABB")

        self.assertEqual(result["pad_source"], "fillPattern")
        self.assertEqual(result["pad_bytes"], 6)
        self.assertEqual(result["new_hex"], "AABB" + "FF" * 6)
        self.assertEqual(pe_file.body[:8], b"\x11" * 8)

    @unittest.skipIf(_ts_102_222 is None, "pySim is not installed")
    def test_short_record_uses_repeat_pattern(self) -> None:
        # Tag 'C2' tiles the pattern, and it restarts at every record boundary,
        # so record 2's tail carries the same bytes as record 1's.
        pe_file = _StubFile(
            body=b"\x11" * 12,
            rec_len=6,
            nb_rec=2,
            fill_pattern=b"\xA5\xA6",
            fill_pattern_repeat=True,
        )
        handle = self._build_handle(pe_file)

        result = self._run_dispatch(handle, record_index=2, hex_value="010203")

        self.assertEqual(result["pad_source"], "repeatPattern")
        self.assertEqual(result["new_hex"], "010203" + "A6A5A6")
        self.assertEqual(pe_file.body[6:], b"\x01\x02\x03\xA6\xA5\xA6")

    @unittest.skipIf(_ts_102_222 is None, "pySim is not installed")
    def test_body_growth_uses_pattern(self) -> None:
        # A package that only ever wrote record 1 leaves the body short. The
        # records the write head crosses carry the file's pattern, not a byte
        # picked because it was convenient.
        pe_file = _StubFile(
            body=b"\x01\x02\x03\x04",
            rec_len=4,
            nb_rec=3,
            fill_pattern=b"\xA5\xA6",
            fill_pattern_repeat=True,
        )
        handle = self._build_handle(pe_file)

        self._run_dispatch(handle, record_index=3, hex_value="0F0E0D0C")

        self.assertEqual(len(pe_file.body), 12)
        self.assertEqual(pe_file.body[4:8], b"\xA5\xA6\xA5\xA6")
        self.assertEqual(pe_file.body[8:], b"\x0F\x0E\x0D\x0C")

    def test_record_index_beyond_nb_rec_rejected(self) -> None:
        pe_file = _StubFile(body=b"\xFF" * 8, rec_len=4, nb_rec=2)
        handle = self._build_handle(pe_file)

        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(handle, record_index=3, hex_value="00000000")
        self.assertIn("nb_rec", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
