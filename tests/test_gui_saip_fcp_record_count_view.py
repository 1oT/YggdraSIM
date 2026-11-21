# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The FCP tab sizes a record file through efFileSize, never a fifth descriptor byte.

A createFCP file descriptor is 2 bytes, or 4 with the record length of a
linear fixed or cyclic EF (ETSI TS 102 222 V17.1.0 §6.3.2.2.2 Table 4; TCA
SAIP V3.4.1 §8.3.2 SIZE(2..4)), and efFileSize is record length x records.
The descriptor editor keeps its Record count field, but Apply sends the count
beside a 4-byte descriptor and the server sets efFileSize; the EF size row
and the descriptor caption read the stored efFileSize. A fifth byte a package
already carries is named as such and never taken as the count. The helpers
run under ``node`` from the built bundle; the Apply wiring is pinned on the
canonical source.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path

from tests.test_gui_saip_fcp_link_and_apply_keys import _constant, _table

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_SOURCE = _REPO_ROOT / "gui_frontend" / "src" / "js" / "saip-workbench.js"

_FUNCTIONS = (
    "saipDecodeFileDescriptor",
    "saipFileDescriptorCaption",
    "saipDeriveEfSize",
    "saipDescriptorCaption",
    "_saipFdStructureFromInfo",
    "_saipFdFileTypeFromInfo",
    "saipBuildFileDescriptorEditor",
)
_TABLES = ("_SAIP_FD_STRUCTURE", "_SAIP_FD_FILETYPE")
_CONSTANTS = ("_SAIP_FD_STRUCTURE_OPTIONS", "_SAIP_FD_FILETYPE_OPTIONS")


def _function(source: str, name: str) -> str:
    """The text of ``function <name>(...) {...}``, braces matched outside strings and comments."""
    start = source.index(f"function {name}(")
    if source[max(0, start - 6):start] == "async ":
        start -= 6
    index = source.index("{", source.index(")", start))
    depth = 0
    quote = ""
    while index < len(source):
        char = source[index]
        pair = source[index:index + 2]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif pair == "//":
            index = source.index("\n", index)
            continue
        elif pair == "/*":
            index = source.index("*/", index) + 2
            continue
        elif char in "\"'":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
        index += 1
    raise AssertionError(f"unterminated function {name}")


_HARNESS = r"""
var _saipControlSeq = 0;
function fakeElement(tag) {
  var el = {
    tagName: String(tag).toUpperCase(), className: "", textContent: "", value: "",
    hidden: false, checked: false, id: "", type: "", min: "", max: "",
    dataset: {}, children: [], listeners: {},
    appendChild: function (child) { this.children.push(child); return child; },
    addEventListener: function (type, fn) {
      (this.listeners[type] = this.listeners[type] || []).push(fn);
    },
    setAttribute: function () {},
    fire: function (type) { (this.listeners[type] || []).forEach(function (fn) { fn({}); }); },
  };
  return el;
}
var document = { createElement: fakeElement };
function walk(el, out) {
  out.push(el);
  (el.children || []).forEach(function (child) { walk(child, out); });
  return out;
}
__DEFS__

var out = {};
var stored = saipDecodeFileDescriptor("42210002FA");
out.decoded = { hasCount: "record_count" in stored, fifth: stored.fifth_byte_count,
                size: stored.record_size, bytes: stored.byte_length };
out.fileCaption = saipFileDescriptorCaption("42210002FA");
out.derived = saipDeriveEfSize({ descriptor: "42210002FA", ef_size: "64" }, "ef-lf");
out.misaligned = saipDeriveEfSize({ descriptor: "42210003", ef_size: "64" }, "ef-lf");
out.noSize = saipDeriveEfSize({ descriptor: "42210002" }, "ef-lf");
out.caption = saipDescriptorCaption({ descriptor: "42210002FA", ef_size: "64" }, "ef-lf");

var editor = saipBuildFileDescriptorEditor("42210002FA", { ef_size: "64" });
var nodes = walk(editor.el, []);
var count = nodes.filter(function (n) { return n.max === "254"; })[0];
var warning = nodes.filter(function (n) { return /saip-fd-warning/.test(n.className); })[0];
var caption = nodes.filter(function (n) { return /saip-fd-hex-caption/.test(n.className); })[0];
out.editor = { hex: editor.getHex(), count: editor.getRecordCount(),
               countField: count.value, warning: warning ? warning.textContent : "" };
count.value = "250";
count.fire("input");
out.edited = { hex: editor.getHex(), count: editor.getRecordCount(), caption: caption.textContent };

var transparent = saipBuildFileDescriptorEditor("4121", { ef_size: "0A" });
out.transparent = { hex: transparent.getHex(), count: transparent.getRecordCount(),
                    warned: walk(transparent.el, []).some(function (n) {
                      return /saip-fd-warning/.test(n.className); }) };
process.stdout.write(JSON.stringify(out));
"""


def _run_node() -> dict:
    bundle = _APP_JS.read_text(encoding="utf-8")
    defs = "\n".join(
        [_constant(bundle, name) for name in _CONSTANTS]
        + [_table(bundle, name) for name in _TABLES]
        + [_function(bundle, name) for name in _FUNCTIONS]
    )
    script = _HARNESS.replace("__DEFS__", defs)
    completed = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=30, check=False
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


@unittest.skipUnless(shutil.which("node"), "node is required to run the bundle's helpers")
class RecordCountHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_node()

    def test_a_fifth_byte_is_reported_not_taken_as_the_count(self) -> None:
        self.assertEqual(
            self.out["decoded"], {"hasCount": False, "fifth": 250, "size": 2, "bytes": 5}
        )
        self.assertIn("fifth byte 250 is not allowed in a profile", self.out["fileCaption"])

    def test_the_size_and_count_come_from_ef_file_size(self) -> None:
        self.assertEqual(
            self.out["derived"],
            {"recordSize": 2, "recordCount": 50, "total": 100, "aligned": True},
        )
        self.assertEqual(
            self.out["misaligned"],
            {"recordSize": 3, "recordCount": 33, "total": 100, "aligned": False},
        )
        self.assertIsNone(self.out["noSize"])
        self.assertTrue(self.out["caption"].startswith("50 records (EF size / record size)"))
        self.assertIn("fifth byte 250", self.out["caption"])

    def test_the_editor_writes_four_bytes_and_hands_over_the_count(self) -> None:
        editor = self.out["editor"]
        self.assertEqual((editor["hex"], editor["count"], editor["countField"]), ("42210002", 50, "50"))
        self.assertIn("fifth byte (250 records)", editor["warning"])
        edited = self.out["edited"]
        self.assertEqual((edited["hex"], edited["count"]), ("42210002", 250))
        self.assertIn("EF size 500 B (250 x 2 B)", edited["caption"])

    def test_a_transparent_descriptor_has_no_count(self) -> None:
        self.assertEqual(
            self.out["transparent"], {"hex": "4121", "count": None, "warned": False}
        )


class ApplyWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = _SOURCE.read_text(encoding="utf-8")

    def test_apply_sends_the_record_count_beside_the_descriptor(self) -> None:
        apply = _function(self.source, "saipApplyFieldEdit")
        self.assertIn("if (recordCount) fieldInputs.record_count = recordCount;", apply)
        self.assertIn("body: JSON.stringify({ inputs: fieldInputs }),", apply)
        self.assertIn("getExtraInputs ? getExtraInputs() : null", self.source)
        self.assertIn("return rc ? { record_count: rc } : null;", self.source)

    def test_the_ef_size_row_shows_the_stored_size(self) -> None:
        self.assertNotIn("padStart(4, \"0\")", self.source[
            self.source.index("Linear-fixed / cyclic EF size is record size x record count"):
            self.source.index("getHexValue = function () { return hidden.value; };")
        ])


if __name__ == "__main__":
    unittest.main()
