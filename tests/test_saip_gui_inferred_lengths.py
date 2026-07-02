# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Static checks for inferred-length behavior in the SAIP GUI form."""

from __future__ import annotations

import unittest
from pathlib import Path


_APP_JS = Path("yggdrasim_common/gui_server/static/app.js")


class SaipGuiInferredLengthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(_APP_JS.is_file(), f"missing {_APP_JS}")
        self.text = _APP_JS.read_text()

    def test_generic_hex_length_helpers_are_present(self) -> None:
        for needle in (
            "function _saipLengthFieldByteCount(",
            "function _saipIsByteLengthField(",
            '"valueHex", "value", "rawHex", "raw", "hex"',
            '"contentHex", "content", "aid", "applicationAID"',
        ):
            self.assertIn(needle, self.text, needle)

    def test_record_layout_inference_rules_are_present(self) -> None:
        for needle in (
            "function _saipRecordProductFromSiblings(",
            'fn === "recordcount"',
            'fn === "recordlength"',
            'fn === "effilesize"',
            "recordProduct.recordSize",
            "recordProduct.recordCount",
        ):
            self.assertIn(needle, self.text, needle)

    def test_inference_precedes_locked_field_fallback(self) -> None:
        func_start = self.text.find("function saipFormRenderNode(")
        self.assertGreater(func_start, 0)
        infer_pos = self.text.find(
            "var inferred = saipFormFieldInferred(",
            func_start,
        )
        lock_pos = self.text.find(
            'var locked = (typeof key === "string")',
            func_start,
        )
        self.assertGreater(infer_pos, func_start)
        self.assertGreater(lock_pos, func_start)
        self.assertLess(infer_pos, lock_pos)


if __name__ == "__main__":
    unittest.main()
