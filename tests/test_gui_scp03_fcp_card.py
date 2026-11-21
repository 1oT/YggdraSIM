# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The File system FCP is a folded card, and the FCP and the body carry Copy keys.

A file picked in the File system tree shows its FCP (ETSI TS 102 221 v18.4
§11.1.1.4) as a card that starts folded, so the body is the first thing
under the file actions. The summary line carries file size or records, SFI,
life cycle status and the EF ARR reference; the session tab remembers an
opened card while the operator browses. The kind="fcp" result of a SELECT or
READ action, which has no tab, starts open. Opened, the card puts the short
parameters in a grid of cells, the long ones (raw bytes, rules, nested
templates) on full-width rows after them, and names the parameters without a
value once on the toolbar line. Every top-level parameter with a value, in
the FCP and in a decoded body, has a Copy key that copies the value as the
server sent it, and a body or a record has a key that copies its bytes as
one hex string. Other views that render a decoded block keep their two
columns. The helpers run under ``node`` from the built bundle on FCPs decoded
by the server's own decoder.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path
from typing import Any

from SCP03.logic.fs import FileSystemController
from tests.test_gui_saip_fcp_record_count_view import _function

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_TRAILING = _REPO_ROOT / "gui_frontend" / "src" / "js" / "trailing.js"
_COMMAND_CENTER = _REPO_ROOT / "gui_frontend" / "src" / "js" / "command-center.js"
_CSS = _REPO_ROOT / "gui_frontend" / "src" / "css" / "views" / "scp03-bulk.css"
_RECORDS_CSS = _REPO_ROOT / "gui_frontend" / "src" / "css" / "views" / "records-viewer.css"

_FUNCTIONS = (
    "scp03BuildFcpCard",
    "scp03FcpFieldGroups",
    "scp03FcpFieldIsWide",
    "scp03BuildFcpFieldRow",
    "looksLikeHex",
    "scp03FcpCardFacts",
    "scp03CopyText",
    "scp03BuildCopyButton",
    "scp03AppendFieldCopyKey",
    "scp03BuildBodyCopyButton",
    "scp03StageHexNormalise",
    "renderDecodedBlock",
)

# SELECT responses: a transparent EF (FID 6F07, SFI from tag '88'), a linear
# fixed EF of 10 records of 28 bytes, the MF with a total file size, and a
# GlobalPlatform FCI ('6F') naming the ISD AID.
_RESPONSES = {
    "transparent": "62178202412183026F078A01058B036F060A80020009880138",
    "linear": "621A82054221001C0A83026F3C8A01058B036F0605800201188801A0",
    "df": "62148202782183023F00810210008A01058B032F0601",
    "fci": "6F108408A000000151000000A5049F6501FF",
}

# An EF ICCID body (the test ICCID of the naming guide, nibble-swapped and
# F-padded) and the fields a decoder returns for it.
_ICCID_BODY = "98 88 02 21 43 65 87 09 21 F3"
_ICCID_DECODED = {"iccid": "8988201234567890123", "digit_count": 19, "spare": None}


def _decoded(raw_hex: str) -> dict[str, Any]:
    """The FCP dict the server sends for ``raw_hex``, access rules left unresolved."""
    controller = FileSystemController.__new__(FileSystemController)
    controller._parse_fcp_internal(bytes.fromhex(raw_hex), resolve=False)
    return dict(controller.current_fcp)


def _fixtures() -> dict[str, Any]:
    fixtures: dict[str, Any] = {name: _decoded(raw) for name, raw in _RESPONSES.items()}
    # What the access-rule resolution reads from EF ARR on a card.
    fixtures["transparent"]["rules"] = [
        "READ: Always",
        "UPDATE/DEACTIVATE/ACTIVATE/TERMINATE/DELETE_FILE: ADM1",
    ]
    fixtures["transparent"]["arr_se_records"] = {"01": 10, "00": 3}
    fixtures["unknown"] = {"template": "Unknown", "raw": "9000", "parse_error": "no FCP template"}
    return fixtures


_HARNESS = r"""
(async function () {
  function fakeElement(tag) {
    var el = {
      tagName: String(tag).toUpperCase(), className: "", textContent: "", title: "",
      type: "", hidden: false, open: false, children: [], listeners: {}, attributes: {},
      appendChild: function (child) { this.children.push(child); return child; },
      addEventListener: function (type, fn) {
        (this.listeners[type] = this.listeners[type] || []).push(fn);
      },
      setAttribute: function (name, value) { this.attributes[name] = String(value); },
      fire: function (type) { (this.listeners[type] || []).forEach(function (fn) { fn({}); }); },
    };
    el.classList = {
      contains: function (name) { return el.className.split(" ").indexOf(name) !== -1; },
      add: function (name) {
        if (!this.contains(name)) el.className = (el.className + " " + name).trim();
      },
      remove: function (name) {
        el.className = el.className.split(" ").filter(function (c) {
          return c && c !== name;
        }).join(" ");
      },
    };
    return el;
  }
  var document = { createElement: fakeElement };
  function renderPrettyValue(value) {
    var el = fakeElement("span");
    el.textContent = JSON.stringify(value);
    return el;
  }
  function isServiceTablePayload() { return false; }
  function renderPrettyServiceTable() { return fakeElement("div"); }
  function renderJsonBlock() { return fakeElement("pre"); }
  function buildDecodedToolbar() {
    var el = fakeElement("div");
    el.className = "cc-decoded-tools";
    return el;
  }
  var clipboard = [];
  var copyResult = true;
  function copyTextToClipboard(text) {
    clipboard.push(text);
    return Promise.resolve(copyResult);
  }
  var logged = [];
  var logBus = { emit: function (entry) { logged.push(entry); } };
  var timers = [];
  function setTimeout(fn, ms) { timers.push({ fn: fn, ms: ms }); return timers.length; }
  function walk(el, out) {
    out.push(el);
    (el.children || []).forEach(function (child) { walk(child, out); });
    return out;
  }
  function byClass(root, name) {
    return walk(root, []).filter(function (n) { return n.classList && n.classList.contains(name); });
  }
  function settle() { return new Promise(function (resolve) { setImmediate(resolve); }); }
  async function copyKeys(root) {
    var result = {};
    var rows = byClass(root, "cc-pv-field");
    for (var i = 0; i < rows.length; i += 1) {
      var key = rows[i].children[0].textContent;
      var button = byClass(rows[i], "cc-pv-copy")[0] || null;
      if (!button) {
        result[key] = { cls: rows[i].className, key: null };
        continue;
      }
      var label = button.textContent;
      clipboard.length = 0;
      button.fire("click");
      await settle();
      result[key] = { cls: rows[i].className, label: label, type: button.type,
                      aria: button.attributes["aria-label"], last: rows[i].children[2] === button,
                      copied: clipboard.slice() };
    }
    return result;
  }

__DEFS__

  var F = __FIXTURES__;
  var out = {};

  var tab = {};
  var card = scp03BuildFcpCard(F.transparent, tab);
  var head = card.children[0];
  out.folded = { tag: card.tagName, cls: card.className, open: card.open, headTag: head.tagName,
                 title: byClass(head, "cc-fcp-card-title")[0].textContent,
                 facts: byClass(head, "cc-fcp-card-facts")[0].textContent,
                 headButtons: walk(head, []).filter(function (n) { return n.tagName === "BUTTON"; }).length,
                 body: card.children[1].className };

  card.open = true;
  card.fire("toggle");
  out.remembered = { tab: tab.fcpCardOpen, next: scp03BuildFcpCard(F.linear, tab).open };
  var again = scp03BuildFcpCard(F.linear, tab);
  again.open = false;
  again.fire("toggle");
  out.refolded = { tab: tab.fcpCardOpen, next: scp03BuildFcpCard(F.transparent, tab).open };
  out.actionResult = scp03BuildFcpCard(F.transparent, null).open;
  out.fciTitle = byClass(scp03BuildFcpCard(F.fci, {}), "cc-fcp-card-title")[0].textContent;

  out.fcpKeys = await copyKeys(card);

  var block = card.children[1];
  var metaRow = block.children[0];
  out.layout = {
    block: block.children.map(function (c) { return c.className; }),
    meta: metaRow.children.map(function (c) { return c.className; }),
    noValue: byClass(metaRow, "cc-fcp-novalue").map(function (p) {
      return { title: p.title, text: p.children.map(function (c) { return c.textContent; }) };
    }),
    rows: byClass(block.children[1], "cc-pv-field").map(function (r) {
      return [r.children[0].textContent, r.className];
    }),
  };
  out.fciMeta = scp03BuildFcpCard(F.fci, {}).children[1].children[0].children.map(function (c) {
    return c.className;
  });
  out.groups = {};
  ["transparent", "linear", "df", "fci", "unknown"].forEach(function (name) {
    out.groups[name] = scp03FcpFieldGroups(F[name]);
  });
  out.wide = {
    raw: scp03FcpFieldIsWide(F.transparent.raw), aid16: scp03FcpFieldIsWide("A0" + "00".repeat(15)),
    aid8: scp03FcpFieldIsWide("A000000151000000"), fid: scp03FcpFieldIsWide("6F07"),
    lcsName: scp03FcpFieldIsWide("Operational state - deactivated"),
    note: scp03FcpFieldIsWide("Present in compact format (tag 8C); not decoded."),
    list: scp03FcpFieldIsWide(["READ: Always"]), emptyList: scp03FcpFieldIsWide([]),
    obj: scp03FcpFieldIsWide({ "01": 10 }), emptyObj: scp03FcpFieldIsWide({}),
    num: scp03FcpFieldIsWide(9), bool: scp03FcpFieldIsWide(true), nul: scp03FcpFieldIsWide(null),
  };

  var rawRow = byClass(card, "cc-pv-field").filter(function (r) {
    return r.children[0].textContent === "raw";
  })[0];
  var rawButton = byClass(rawRow, "cc-pv-copy")[0];
  timers.length = 0;
  rawButton.fire("click");
  await settle();
  out.flash = { text: rawButton.textContent, copied: rawButton.classList.contains("is-copied"),
                ms: timers.length ? timers[timers.length - 1].ms : null };
  timers[timers.length - 1].fn();
  out.restored = { text: rawButton.textContent, copied: rawButton.classList.contains("is-copied") };

  copyResult = false;
  timers.length = 0;
  rawButton.fire("click");
  await settle();
  out.rejected = { text: rawButton.textContent, timers: timers.length,
                   logged: logged.map(function (e) { return e.level + " " + e.source; }) };
  copyResult = true;

  out.bodyKeys = await copyKeys(renderDecodedBlock(F.iccidDecoded, { rawHex: "00" }, { copyKeys: true }));
  out.plainKeys = await copyKeys(renderDecodedBlock(F.iccidDecoded, null, { omitHead: true }));

  var bodyButton = scp03BuildBodyCopyButton(F.iccidBody, "Copy body");
  clipboard.length = 0;
  bodyButton.fire("click");
  await settle();
  out.bodyButton = { label: "Copy body", cls: bodyButton.className, title: bodyButton.title,
                     disabled: !!bodyButton.disabled, copied: clipboard.slice(),
                     text: bodyButton.textContent };
  timers[timers.length - 1].fn();
  out.bodyButtonRestored = { text: bodyButton.textContent, cls: bodyButton.className };
  var emptyButton = scp03BuildBodyCopyButton("", "Copy record");
  out.emptyButton = { text: emptyButton.textContent, disabled: !!emptyButton.disabled,
                      title: emptyButton.title };

  out.facts = {};
  ["transparent", "linear", "df", "fci", "unknown"].forEach(function (name) {
    out.facts[name] = scp03FcpCardFacts(F[name]);
  });
  out.compactFacts = scp03FcpCardFacts({ template: "FCP", type: "EF", size: 4, security_format: "compact" });
  out.copyText = {
    str: scp03CopyText("6F07"), num: scp03CopyText(9), zero: scp03CopyText(0),
    no: scp03CopyText(false), nul: scp03CopyText(null), empty: scp03CopyText(""),
    list: scp03CopyText(["a", "b"]), emptyList: scp03CopyText([]),
    obj: scp03CopyText({ "01": 5 }), emptyObj: scp03CopyText({}),
    objs: scp03CopyText([{ k: 1 }]),
  };
  process.stdout.write(JSON.stringify(out));
})().catch(function (err) {
  process.stderr.write(String((err && err.stack) || err));
  process.exit(1);
});
"""


def _run_node() -> dict[str, Any]:
    bundle = _APP_JS.read_text(encoding="utf-8")
    defs = "\n".join(_function(bundle, name) for name in _FUNCTIONS)
    fixtures = _fixtures()
    fixtures["iccidBody"] = _ICCID_BODY
    fixtures["iccidDecoded"] = _ICCID_DECODED
    script = _HARNESS.replace("__DEFS__", defs).replace("__FIXTURES__", json.dumps(fixtures))
    completed = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=30, check=False
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


@unittest.skipUnless(shutil.which("node"), "node is required to run the bundle's helpers")
class FcpCardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_node()

    def test_the_card_starts_folded_in_the_file_system_view(self) -> None:
        self.assertEqual(
            self.out["folded"],
            {
                "tag": "DETAILS",
                "cls": "cc-fcp-card",
                "open": False,
                "headTag": "SUMMARY",
                "title": "FCP",
                "facts": "file size 9 B · SFI 07 · Operational state - activated · ARR 6F06 record 10",
                "headButtons": 0,
                "body": "cc-fcp-block",
            },
        )

    def test_an_opened_card_stays_open_for_the_next_file_until_folded(self) -> None:
        self.assertEqual(self.out["remembered"], {"tab": True, "next": True})
        self.assertEqual(self.out["refolded"], {"tab": False, "next": False})

    def test_the_action_result_without_a_tab_starts_open(self) -> None:
        self.assertIs(self.out["actionResult"], True)
        self.assertEqual(self.out["fciTitle"], "FCI")

    def test_every_fcp_parameter_with_a_value_has_a_copy_key(self) -> None:
        keys = self.out["fcpKeys"]
        for absent in ("total_size", "aid", "pin_status", "proprietary"):
            self.assertNotIn(absent, keys)
        for present in ("raw", "fid", "size", "rec_len", "shareable", "lcs_name", "rules"):
            entry = dict(keys[present])
            entry.pop("copied")
            row = "cc-pv-field cc-fcp-field--wide" if present in ("raw", "rules") else "cc-pv-field"
            self.assertEqual(
                entry,
                {
                    "cls": row + " cc-pv-field--copy",
                    "label": "Copy",
                    "type": "button",
                    "aria": f"Copy {present}",
                    "last": True,
                },
                present,
            )

    def test_the_open_card_puts_short_parameters_in_cells_and_long_ones_after(self) -> None:
        fixture = _fixtures()["transparent"]
        wide = ["raw", "arr_se_records", "rules"]
        cells = [key for key, value in fixture.items() if value is not None and key not in wide]
        layout = self.out["layout"]
        self.assertEqual(
            layout["block"], ["cc-fcp-meta", "cc-fcp-fields cc-pv-object cc-pv-object--depth-0", ""]
        )
        self.assertEqual(
            layout["rows"],
            [[key, "cc-pv-field cc-pv-field--copy"] for key in cells]
            + [[key, "cc-pv-field cc-fcp-field--wide cc-pv-field--copy"] for key in wide],
        )

    def test_parameters_without_a_value_are_named_once_beside_the_toolbar(self) -> None:
        layout = self.out["layout"]
        self.assertEqual(layout["meta"], ["cc-fcp-novalue", "cc-decoded-tools"])
        self.assertEqual(
            layout["noValue"],
            [
                {
                    "title": "Listed as null under Show JSON.",
                    "text": ["No value", "total_size · aid · pin_status · proprietary"],
                }
            ],
        )
        self.assertEqual(self.out["fciMeta"], ["cc-decoded-tools"])

    def test_the_groups_split_every_fixture_in_server_order(self) -> None:
        fixtures = _fixtures()
        for name, groups in self.out["groups"].items():
            fixture = fixtures[name]
            self.assertEqual(
                groups["empty"], [key for key, value in fixture.items() if value is None], name
            )
            self.assertEqual(
                sorted(groups["cells"] + groups["wide"] + groups["empty"]), sorted(fixture), name
            )
            self.assertEqual(
                groups["cells"], [key for key in fixture if key in groups["cells"]], name
            )
        self.assertEqual(self.out["groups"]["linear"]["wide"], ["raw"])
        self.assertEqual(self.out["groups"]["df"]["wide"], ["raw"])
        self.assertEqual(self.out["groups"]["fci"]["cells"], ["template", "type", "aid", "max_len", "lcs"])
        self.assertEqual(
            self.out["groups"]["unknown"],
            {"cells": ["template", "raw", "parse_error"], "wide": [], "empty": []},
        )

    def test_a_string_drawn_wider_than_a_cell_gets_its_own_row(self) -> None:
        self.assertEqual(
            self.out["wide"],
            {
                "raw": True,
                "aid16": True,
                "aid8": False,
                "fid": False,
                "lcsName": False,
                "note": True,
                "list": True,
                "emptyList": False,
                "obj": True,
                "emptyObj": False,
                "num": False,
                "bool": False,
                "nul": False,
            },
        )

    def test_copy_puts_the_value_as_sent_on_the_clipboard(self) -> None:
        keys = self.out["fcpKeys"]
        self.assertEqual(keys["raw"]["copied"], [_RESPONSES["transparent"]])
        self.assertEqual(keys["fid"]["copied"], ["6F07"])
        self.assertEqual(keys["file_descriptor"]["copied"], ["4121"])
        self.assertEqual(keys["size"]["copied"], ["9"])
        self.assertEqual(keys["rec_len"]["copied"], ["0"])
        self.assertEqual(keys["shareable"]["copied"], ["true"])
        self.assertEqual(
            keys["rules"]["copied"],
            ["READ: Always\nUPDATE/DEACTIVATE/ACTIVATE/TERMINATE/DELETE_FILE: ADM1"],
        )
        self.assertEqual(keys["arr_se_records"]["copied"], ['{\n  "01": 10,\n  "00": 3\n}'])

    def test_a_copy_flashes_copied_and_a_rejected_write_is_logged(self) -> None:
        self.assertEqual(self.out["flash"], {"text": "Copied", "copied": True, "ms": 900})
        self.assertEqual(self.out["restored"], {"text": "Copy", "copied": False})
        self.assertEqual(
            self.out["rejected"], {"text": "Copy", "timers": 0, "logged": ["warn scp03.copy"]}
        )

    def test_a_file_system_body_has_a_copy_key_per_decoded_field(self) -> None:
        keys = self.out["bodyKeys"]
        self.assertEqual(keys["iccid"]["copied"], ["8988201234567890123"])
        self.assertEqual(keys["iccid"]["aria"], "Copy iccid")
        self.assertEqual(keys["digit_count"]["copied"], ["19"])
        self.assertEqual(keys["spare"], {"cls": "cc-pv-field cc-pv-field--copy", "key": None})

    def test_other_decoded_blocks_keep_two_columns(self) -> None:
        self.assertEqual(
            self.out["plainKeys"],
            {
                "iccid": {"cls": "cc-pv-field", "key": None},
                "digit_count": {"cls": "cc-pv-field", "key": None},
                "spare": {"cls": "cc-pv-field", "key": None},
            },
        )

    def test_the_body_key_copies_its_bytes_as_one_hex_string(self) -> None:
        self.assertEqual(
            self.out["bodyButton"],
            {
                "label": "Copy body",
                "cls": "cc-payload-copy-btn is-copied",
                "title": "Copy the 10 bytes as hex",
                "disabled": False,
                "copied": ["988802214365870921F3"],
                "text": "Copied",
            },
        )
        self.assertEqual(
            self.out["bodyButtonRestored"], {"text": "Copy body", "cls": "cc-payload-copy-btn"}
        )
        self.assertEqual(
            self.out["emptyButton"],
            {"text": "Copy record", "disabled": True, "title": "No bytes to copy."},
        )

    def test_the_summary_says_what_the_kind_chip_does_not(self) -> None:
        facts = self.out["facts"]
        self.assertEqual(
            facts["linear"],
            ["10 records × 28 B", "SFI 14", "Operational state - activated", "ARR 6F06 record 5"],
        )
        self.assertEqual(
            facts["df"],
            ["total file size 4096 B", "Operational state - activated", "ARR 2F06 record 1"],
        )
        self.assertEqual(facts["fci"], ["AID A000000151000000"])
        self.assertEqual(facts["unknown"], ["not decoded: no FCP template"])
        self.assertEqual(self.out["compactFacts"], ["file size 4 B", "compact security attributes"])

    def test_copy_text_keeps_values_and_skips_empty_ones(self) -> None:
        self.assertEqual(
            self.out["copyText"],
            {
                "str": "6F07",
                "num": "9",
                "zero": "0",
                "no": "false",
                "nul": "",
                "empty": "",
                "list": "a\nb",
                "emptyList": "",
                "obj": '{\n  "01": 5\n}',
                "emptyObj": "",
                "objs": '[\n  {\n    "k": 1\n  }\n]',
            },
        )


def _body(source: str, signature: str) -> str:
    """The text of one function of ``source``, up to the next top-level function."""
    return source.split(signature, 1)[1].split("\n  function ", 1)[0].split("\n  async function ", 1)[0]


class FcpCardWiringTests(unittest.TestCase):
    def test_render_fcp_result_builds_the_card_with_the_tab(self) -> None:
        source = _TRAILING.read_text(encoding="utf-8")
        body = _body(source, "function renderFcpResult(data, container, tab)")
        self.assertIn("wrap.appendChild(scp03BuildFcpCard(fcp, tab));", body)
        self.assertIn("renderDecodedBlock(payload, null, { omitHead: true, copyKeys: true })", body)
        self.assertNotIn('h4.textContent = "FCP";', source)

    def test_the_file_system_bodies_opt_in_to_copy_keys(self) -> None:
        source = _TRAILING.read_text(encoding="utf-8")
        transparent = _body(source, "function renderTransparentPayload(payload)")
        self.assertIn('scp03BuildBodyCopyButton(payload.hex || "", "Copy body")', transparent)
        self.assertIn("}, { copyKeys: true }));", transparent)
        record = _body(source, "function renderSingleRecord(rec, payload)")
        self.assertIn('actions.appendChild(scp03BuildBodyCopyButton(rec.hex, "Copy record"));', record)
        self.assertIn("}, { copyKeys: true }));", record)
        read_binary = _body(
            _COMMAND_CENTER.read_text(encoding="utf-8"), "async function scp03ReadBinary(tab)"
        )
        self.assertIn('hexHead.appendChild(scp03BuildBodyCopyButton(data.hex || "", "Copy body"));', read_binary)
        self.assertIn("}, { copyKeys: true }));", read_binary)

    def test_the_copy_key_shows_on_hover_and_focus_in_its_own_column(self) -> None:
        css = _CSS.read_text(encoding="utf-8")
        self.assertIn(
            ".cc-pv-object--depth-0 > .cc-pv-field--copy {\n"
            "  grid-template-columns: minmax(96px, 200px) minmax(0, 1fr) auto;",
            css,
        )
        self.assertIn(
            ".cc-fcp-block .cc-pv-object--depth-0 > .cc-pv-field--copy,\n"
            ".cc-payload-transparent .cc-pv-object--depth-0 > .cc-pv-field--copy {\n"
            "  grid-template-columns: minmax(76px, 148px) minmax(0, 1fr) auto;",
            css,
        )
        self.assertIn(
            ".cc-pv-field--copy:hover > .cc-pv-copy,\n"
            ".cc-pv-field--copy:focus-within > .cc-pv-copy,\n"
            ".cc-pv-copy.is-copied {\n  opacity: 1;\n}",
            css,
        )
        self.assertIn(".cc-fcp-card-head::-webkit-details-marker {\n  display: none;\n}", css)
        self.assertIn(
            ".cc-fcp-block .cc-fcp-fields {\n"
            "  display: grid;\n"
            "  grid-template-columns: repeat(auto-fill, minmax(min(272px, 100%), 1fr));",
            css,
        )
        self.assertIn(
            ".cc-fcp-block .cc-fcp-fields > .cc-pv-field--copy {\n"
            "  position: relative;\n"
            "  grid-template-columns: 96px minmax(0, 1fr);",
            css,
        )
        self.assertIn(
            ".cc-fcp-fields > .cc-pv-field--copy > .cc-pv-copy {\n"
            "  position: absolute;",
            css,
        )
        self.assertIn(
            ".cc-fcp-block .cc-fcp-fields > .cc-fcp-field--wide {\n  grid-column: 1 / -1;", css
        )
        records_css = _RECORDS_CSS.read_text(encoding="utf-8")
        self.assertIn(".cc-payload-update-btn,\n.cc-payload-copy-btn {\n  min-height: 28px;", records_css)
        self.assertIn(".cc-payload-copy-btn.is-copied {", records_css)


if __name__ == "__main__":
    unittest.main()
