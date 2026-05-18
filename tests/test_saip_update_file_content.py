# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for `saip.update_file_content` dispatcher.

Covers the transparent / BER-TLV write path that backs the YggdraSIM
schema-aware EF wizards. The dispatcher must:

  - reject record-fixed EFs (those go through update_record_bytes),
  - FF-pad short writes up to ``efFileSize``,
  - replace ``fillFileContent`` / ``fillFileOffset`` tuples in
    ``pe.decoded`` while preserving every other tuple,
  - mark the PE dirty and refresh the cached decoded document.

The test stubs out the pySim-backed ``File`` object and patches the
two helpers that touch the disk (``_refresh_decoded_document``,
``get_manager``) so the suite runs without pySim installed.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict
from typing import Any
from unittest import mock

from yggdrasim_common.gui_server.actions import saip as saip_module


class _StubFile:
    """Minimal ``pySim.esim.saip.File`` stand-in."""

    def __init__(
        self,
        body: bytes,
        file_type: str = "TR",
        file_size: int | None = None,
        record_len: int = 0,
    ) -> None:
        self.body = bytearray(body)
        self.file_type = file_type
        self._file_size = file_size
        self.record_len = record_len

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

    def test_record_fixed_file_rejected(self) -> None:
        pe_file = _StubFile(
            body=b"\xFF" * 40,
            file_type="LF",
            file_size=40,
            record_len=10,
        )
        handle = self._build_handle(pe_file, [])
        with self.assertRaises(ValueError) as cm:
            self._run_dispatch(
                handle,
                section="USIM (1)",
                field_path="ef-imsi",
                hex_value="00" * 10,
            )
        self.assertIn("not transparent", str(cm.exception))

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


if __name__ == "__main__":
    unittest.main()
