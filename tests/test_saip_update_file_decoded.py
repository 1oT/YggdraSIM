# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for `_unjsonify_decoded` + `saip.update_file_decoded` dispatcher.

The JSON tab in the GUI projects each file's CHOICE list via
``_jsonify_decoded`` (bytes → uppercase hex, dicts → plain dicts).
This test pins the inverse direction:

  - hex strings round-trip back to ``bytes``,
  - non-hex strings pass through unchanged,
  - dicts become ``OrderedDict`` (so re-emitted JSON keeps the same
    key order operators saw on screen),
  - the dispatcher rejects malformed payloads cleanly,
  - a successful apply replaces ``pe.decoded[path]`` and re-hydrates
    ``pe.files[path]`` via ``File.from_tuples``.
"""

from __future__ import annotations

import unittest
from collections import OrderedDict
from typing import Any
from unittest import mock

from yggdrasim_common.gui_server.actions import saip as saip_module


class _StubFile:
    def __init__(self) -> None:
        self.body = b""
        self.tuples_seen: list[Any] = []

    def from_tuples(self, tuples: list) -> None:
        self.tuples_seen = list(tuples)
        # Mimic pySim's behaviour: refresh body from any
        # fillFileContent payload in the tuple list.
        body = bytearray()
        for name, value in tuples:
            if name == "fillFileContent" and isinstance(value, (bytes, bytearray)):
                body.extend(value)
        self.body = bytes(body)


class _StubPe:
    def __init__(self, files: dict[str, _StubFile], decoded: dict[str, list]) -> None:
        self.files = files
        self.decoded = decoded


class _StubPes:
    def __init__(self, pes: list[_StubPe]) -> None:
        self.pe_list = pes


class TestUnjsonifyDecoded(unittest.TestCase):
    """Inverse codec hex / dict / list behaviour."""

    def test_hex_string_becomes_bytes(self) -> None:
        self.assertEqual(saip_module._unjsonify_decoded("DEADBEEF"), b"\xDE\xAD\xBE\xEF")

    def test_lowercase_hex_string_becomes_bytes(self) -> None:
        self.assertEqual(saip_module._unjsonify_decoded("deadbeef"), b"\xDE\xAD\xBE\xEF")

    def test_non_hex_string_passes_through(self) -> None:
        self.assertEqual(saip_module._unjsonify_decoded("note: rfu"), "note: rfu")

    def test_odd_length_string_passes_through(self) -> None:
        self.assertEqual(saip_module._unjsonify_decoded("ABC"), "ABC")

    def test_empty_string_passes_through(self) -> None:
        self.assertEqual(saip_module._unjsonify_decoded(""), "")

    def test_int_passes_through(self) -> None:
        self.assertEqual(saip_module._unjsonify_decoded(7), 7)

    def test_dict_becomes_ordered_dict_with_recursion(self) -> None:
        result = saip_module._unjsonify_decoded({
            "a": "AB",
            "b": "not hex",
            "c": {"nested": "C0DE"},
        })
        self.assertIsInstance(result, OrderedDict)
        self.assertEqual(list(result.keys()), ["a", "b", "c"])
        self.assertEqual(result["a"], b"\xAB")
        self.assertEqual(result["b"], "not hex")
        self.assertIsInstance(result["c"], OrderedDict)
        self.assertEqual(result["c"]["nested"], b"\xC0\xDE")

    def test_list_passthrough_recurses(self) -> None:
        self.assertEqual(
            saip_module._unjsonify_decoded(["AB", 1, "x"]),
            [b"\xAB", 1, "x"],
        )


class TestUpdateFileDecodedDispatcher(unittest.TestCase):
    """End-to-end JSON-edit round-trip with stubbed pySim handles."""

    def _build_handle(self) -> tuple[dict[str, Any], _StubFile, _StubPe]:
        pe_file = _StubFile()
        pe = _StubPe(
            files={"ef-imsi": pe_file},
            decoded={
                "ef-imsi": [
                    ("fileDescriptor", OrderedDict([("fileDescriptor", b"\x41\x21\x00\x09")])),
                    ("fillFileContent", b"\xFF" * 9),
                ],
            },
        )
        pes = _StubPes([pe])
        handle: dict[str, Any] = {
            "pes": pes,
            "source_path": "/tmp/example.der",
            "decoded_document": {"sections": {"USIM (1)": {}}, "intro": []},
            "dirty_pes": set(),
            "applied_overrides": {},
        }
        return handle, pe_file, pe

    def _run(
        self,
        handle: dict[str, Any],
        *,
        section: str,
        field_path: str,
        payload: Any,
    ) -> dict[str, Any]:
        manager_stub = mock.Mock()
        manager_stub.claim.return_value = handle
        with (
            mock.patch.object(saip_module, "_refresh_decoded_document", lambda _h: None),
            mock.patch(
                "yggdrasim_common.gui_server.sessions.get_manager",
                return_value=manager_stub,
            ),
        ):
            return saip_module._dispatch_update_file_decoded(
                ctx=mock.Mock(),
                session_id="sid-test",
                section_key=section,
                field_path=field_path,
                payload=payload,
            )

    def test_replace_choice_list(self) -> None:
        handle, pe_file, pe = self._build_handle()
        result = self._run(
            handle,
            section="USIM (1)",
            field_path="ef-imsi",
            payload=[
                ["fileDescriptor", {"fileDescriptor": "41210009"}],
                ["fillFileContent", "0801020304050607080F"],
            ],
        )
        self.assertEqual(result["tuple_count"], 2)
        self.assertEqual(result["tuple_names"], ["fileDescriptor", "fillFileContent"])
        self.assertIn(0, handle["dirty_pes"])

        new_choices = pe.decoded["ef-imsi"]
        self.assertEqual(new_choices[0][0], "fileDescriptor")
        self.assertIsInstance(new_choices[0][1], OrderedDict)
        self.assertEqual(new_choices[0][1]["fileDescriptor"], b"\x41\x21\x00\x09")
        self.assertEqual(new_choices[1][0], "fillFileContent")
        self.assertEqual(
            new_choices[1][1],
            b"\x08\x01\x02\x03\x04\x05\x06\x07\x08\x0F",
        )
        # File.from_tuples was invoked; body reflects the new write.
        self.assertEqual(pe_file.tuples_seen, new_choices)
        self.assertEqual(pe_file.body, b"\x08\x01\x02\x03\x04\x05\x06\x07\x08\x0F")

    def test_rejects_non_list_payload(self) -> None:
        handle, _, _ = self._build_handle()
        with self.assertRaises(ValueError) as cm:
            self._run(
                handle,
                section="USIM (1)",
                field_path="ef-imsi",
                payload="not-a-list",
            )
        self.assertIn("payload must be", str(cm.exception))

    def test_rejects_bad_entry_shape(self) -> None:
        handle, _, _ = self._build_handle()
        with self.assertRaises(ValueError) as cm:
            self._run(
                handle,
                section="USIM (1)",
                field_path="ef-imsi",
                payload=[["fileDescriptor"]],
            )
        self.assertIn("[name, value] pair", str(cm.exception))

    def test_rejects_unknown_field_path(self) -> None:
        handle, _, _ = self._build_handle()
        with self.assertRaises(LookupError) as cm:
            self._run(
                handle,
                section="USIM (1)",
                field_path="ef-does-not-exist",
                payload=[["fillFileContent", "00"]],
            )
        self.assertIn("no decoded entry", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
