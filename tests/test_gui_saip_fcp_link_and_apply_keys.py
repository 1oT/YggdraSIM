# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""FCP rows of a link entry, the EF size chip, Ctrl+Enter and Ctrl+S.

TCA SAIP V3.4.1 §8.3.3 note 1 (page 30): the card creates a link with the
source file's fileDescriptor, efFileSize and proprietaryEFInfo and ignores the
template's, so the FCP tab shows those rows from the source, read-only, and a
field the source leaves empty stays empty. An editable EF size shows the bytes
it allocates (ETSI TS 102 222 V17.1.0 §6.3.2.2.2 tag '80') in decimal beside
the hex.

Ctrl/Cmd+Enter applies in every workbench editor that has an Apply button,
Ctrl+S saves with focus in an editor, and a save waits for a session mutation
still in flight, so Ctrl+Enter then Ctrl+S writes the applied edit. The
helpers run under ``node`` from the built bundle; the wiring is pinned on the
canonical source.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_SOURCE = _REPO_ROOT / "gui_frontend" / "src" / "js" / "saip-workbench.js"

_FUNCTIONS = (
    "saipDecodeFileDescriptor",
    "saipTokenizeHexWithPlaceholders",
    "saipFormatHexPretty",
    "saipStructureUiLabel",
    "saipDeriveEfSize",
    "saipEfFileSizeChip",
    "saipLinkedFcpValueText",
    "saipResolvedLinkSource",
    "saipEffectiveFcpForData",
    "saipEventTargetIsEditable",
    "saipBindApplyChord",
    "saipMutationFetch",
    "saipFlushPendingAutoApplies",
    "saipContentResetLabel",
)
_TABLES = ("_SAIP_FD_STRUCTURE", "_SAIP_FD_FILETYPE")
_CONSTANTS = ("_SAIP_INLINE_PLACEHOLDER_SOURCE",)

_SESSION_MUTATIONS = (
    "apply_decoded_edit",
    "update_file_field",
    "update_file_content",
    "update_record_bytes",
    "update_file_decoded",
    "update_profile_header_field",
    "update_sd_parameters",
    "set_variable",
)


def _function(source: str, name: str) -> str:
    """The text of ``function <name>(...) {...}``, braces matched outside string literals."""
    start = source.index(f"function {name}(")
    if source[max(0, start - 6):start] == "async ":
        start -= 6
    depth = 0
    quote = ""
    index = source.index("{", source.index(")", start))
    while index < len(source):
        char = source[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : index + 1]
        index += 1
    raise AssertionError(f"unterminated function {name}")


def _table(source: str, name: str) -> str:
    start = source.index(f"var {name} = {{")
    end = source.index("};", start)
    return source[start : end + 2]


def _constant(source: str, name: str) -> str:
    start = source.index(f"var {name} =")
    end = source.index(";\n", start)
    return source[start : end + 1]


_HARNESS = r"""
var apiCalls = [];
var pendingApi = [];
function apiFetch(path, options) {
  apiCalls.push(path);
  return new Promise(function (resolve) { pendingApi.push(resolve); });
}
var _saipInFlightMutations = new Set();
__DEFS__

function fakeScope() {
  var listeners = [];
  return {
    listeners: listeners,
    addEventListener: function (type, fn) { listeners.push([type, fn]); },
    fire: function (init) {
      var ev = Object.assign({
        key: "Enter", ctrlKey: false, metaKey: false, shiftKey: false, altKey: false,
        prevented: false, stopped: false,
        preventDefault: function () { this.prevented = true; },
        stopPropagation: function () { this.stopped = true; },
      }, init);
      listeners.forEach(function (pair) { if (pair[0] === "keydown") pair[1](ev); });
      return ev;
    },
  };
}
function fakeButton() {
  return { clicks: 0, disabled: false, hidden: false, isConnected: true,
           click: function () { this.clicks += 1; } };
}

var out = {};
out.sizeChip = ["17", "0208", "", "1", "XYZ", "0017"].map(saipEfFileSizeChip);

var source = { descriptor: "42210031", ef_size: "024C", proprietary_fill_pattern: "",
               proprietary_repeat_pattern: "A55A" };
out.linked = {
  descriptor: saipLinkedFcpValueText({ sub: "fileDescriptor", row: "descriptor" }, source, "ef-lf"),
  size: saipLinkedFcpValueText({ sub: "efFileSize", row: "ef_size" }, source, "ef-lf"),
  fill: saipLinkedFcpValueText({ sub: "proprietaryEFInfo.fillPattern", row: "proprietary_fill_pattern" }, source, "ef-lf"),
  repeat: saipLinkedFcpValueText({ sub: "proprietaryEFInfo.repeatPattern", row: "proprietary_repeat_pattern" }, source, "ef-lf"),
  transparentSize: saipLinkedFcpValueText({ sub: "efFileSize", row: "ef_size" }, { descriptor: "4121", ef_size: "11" }, "ef-t"),
};

var merged = saipEffectiveFcpForData({
  fcp: { descriptor: "4221", ef_size: "06E0", proprietary_fill_pattern: "FF", lcsi: "05" },
  link_source: { resolved: true, fcp: { descriptor: "422100B0", ef_size: "2260", proprietary_fill_pattern: "" } },
});
out.merged = { descriptor: merged.descriptor, ef_size: merged.ef_size,
               fill: merged.proprietary_fill_pattern, lcsi: merged.lcsi };
out.unresolved = saipEffectiveFcpForData({
  fcp: { ef_size: "06E0" }, link_source: { resolved: false, fcp: { ef_size: "2260" } },
}).ef_size;

var input = { tagName: "INPUT" };
var scope = fakeScope();
var btn = fakeButton();
saipBindApplyChord(scope, btn);
var chord = scope.fire({ ctrlKey: true, target: input });
scope.fire({ target: input });
scope.fire({ ctrlKey: true, target: { tagName: "BUTTON" } });
scope.fire({ metaKey: true, target: { tagName: "TEXTAREA" } });
scope.fire({ ctrlKey: true, shiftKey: true, target: input });
btn.disabled = true;
scope.fire({ ctrlKey: true, target: input });
out.chord = { clicks: btn.clicks, prevented: chord.prevented, stopped: chord.stopped };

out.resetLabels = ["fillPattern", "repeatPattern", "templateDefault", "erased", ""]
  .map(saipContentResetLabel);

var order = [];
var request = saipMutationFetch("/api/actions/saip.update_file_field/run", {});
saipFlushPendingAutoApplies({}).then(function () {
  order.push("flushed");
  out.order = order;
  out.inFlightAfter = _saipInFlightMutations.size;
  out.apiCalls = apiCalls;
  process.stdout.write(JSON.stringify(out));
});
setTimeout(function () {
  order.push("applied");
  pendingApi[0]({ ok: true });
}, 20);
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
class BundleHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_node()

    def test_ef_size_chip_reads_the_hex_in_decimal(self) -> None:
        self.assertEqual(
            self.out["sizeChip"],
            ["23 B ('17')", "520 B ('0208')", "", "", "", "23 B ('0017')"],
        )

    def test_link_rows_show_the_source_values(self) -> None:
        linked = self.out["linked"]
        self.assertEqual(linked["descriptor"], "42210031 · Linear fixed · 12 records of 49 B")
        self.assertEqual(linked["size"], "588 B · 12 records of 49 B")
        self.assertEqual(linked["fill"], "none in the source file")
        self.assertEqual(linked["repeat"], "A5 5A")
        self.assertEqual(linked["transparentSize"], "17 B ('11')")

    def test_a_link_takes_every_inherited_field_from_its_source(self) -> None:
        # The source's empty fill pattern wins over the entry's own: the
        # template's value is ignored, not a fallback.
        self.assertEqual(
            self.out["merged"],
            {"descriptor": "422100B0", "ef_size": "2260", "fill": "", "lcsi": "05"},
        )
        self.assertEqual(self.out["unresolved"], "06E0")

    def test_ctrl_enter_presses_apply_from_an_editable_control_only(self) -> None:
        # Ctrl+Enter on an input and Cmd+Enter on a textarea; plain Enter, a
        # chord on a button, Ctrl+Shift+Enter and a disabled button do not.
        self.assertEqual(self.out["chord"], {"clicks": 2, "prevented": True, "stopped": True})

    def test_a_reset_names_what_the_file_holds_again(self) -> None:
        self.assertEqual(
            self.out["resetLabels"],
            ["its fill pattern", "its repeat pattern", "the template default", "FF (erased)", "FF (erased)"],
        )

    def test_a_save_waits_for_the_mutation_in_flight(self) -> None:
        self.assertEqual(self.out["order"], ["applied", "flushed"])
        self.assertEqual(self.out["inFlightAfter"], 0)
        self.assertEqual(self.out["apiCalls"], ["/api/actions/saip.update_file_field/run"])


class SourceWiringTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = _SOURCE.read_text(encoding="utf-8")

    def test_every_editor_apply_takes_the_chord(self) -> None:
        for function, binding in (
            ("saipBuildRawBytesCard", "saipBindApplyChord(card, applyBtn);"),
            ("saipBuildRecordHexCard", "saipBindApplyChord(card, applyBtn);"),
            ("saipFileRenderJson", "saipBindApplyChord(card, applyJson);"),
            ("saipBuildPlaceholderValueEditor", "saipBindApplyChord(wrap, applyBtn);"),
            ("saipHeaderControlRow", "saipBindApplyChord(row, btn);"),
        ):
            self.assertIn(binding, _function(self.source, function), function)
        self.assertGreaterEqual(self.source.count("saipBindApplyChord("), 16)

    def test_session_mutations_are_tracked_for_save(self) -> None:
        for name in _SESSION_MUTATIONS:
            self.assertNotIn(f'apiFetch("/api/actions/saip.{name}/run"', self.source, name)
            self.assertIn(f'saipMutationFetch("/api/actions/saip.{name}/run"', self.source, name)
        save = _function(self.source, "saipRibbonSavePackage")
        self.assertIn("await saipFlushPendingAutoApplies(pkg);", save)

    def test_ctrl_s_saves_from_inside_an_editor_but_not_a_modal(self) -> None:
        handler = _function(self.source, "saipShortcutHandler")
        save_at = handler.index('if (ctrl && !alt && key === "s") {')
        self.assertLess(save_at, handler.index("if (saipEventTargetIsEditable(evt.target)) return;"))
        self.assertIn('evt.target.closest("[aria-modal=\\"true\\"]")', handler)
        self.assertEqual(len(re.findall(r'key === "s"', handler)), 1)

    def test_a_resize_reports_the_reset_and_drops_moved_files(self) -> None:
        apply = _function(self.source, "saipApplyFieldEdit")
        self.assertIn("if (data.content_reset && typeof data.content_reset === \"object\") {", apply)
        self.assertIn("saipContentResetLabel(data.content_reset.source)", apply)
        self.assertIn('data.content_reset.reason === "overflow"', apply)
        self.assertIn('saipNotePlaceholderEdit(pkg, data, "saip.update_file_field");', apply)
        self.assertIn("saipDropReindexedFileCache(pkg, data);", apply)
        # The rows that resize a file say so before Apply.
        self.assertEqual(self.source.count("resets the content to the fill pattern, or to FF without one."), 2)

    def test_a_pattern_conflict_is_named_only_when_both_are_set(self) -> None:
        general = _function(self.source, "saipFileRenderGeneral")
        both = general.index('"conflict -- fillPattern and repeatPattern are both declared; clear one."')
        # The conflict needs this row's own pattern; the other pattern alone
        # only asks for it to be cleared first.
        self.assertLess(general.rindex("if (compact) {", 0, both), both)
        self.assertIn('" pattern; clear it before setting this one."', general)
        self.assertNotIn("clear the other before applying", general)

    def test_fcp_rows_of_a_link_come_from_the_source(self) -> None:
        general = _function(self.source, "saipFileRenderGeneral")
        self.assertIn("var linkSource = saipResolvedLinkSource(data);", general)
        self.assertIn("? saipEffectiveFcpForData(data) : null;", general)
        self.assertIn("Object.prototype.hasOwnProperty.call(linkSource.fcp, spec.row);", general)
        self.assertIn("saipLinkedFcpValueText(spec, rowFcp, rowKind);", general)
        self.assertIn('note.textContent = fromLink ? "source file" : "auto";', general)
        # The glyph reads the row's kind and where its Fcp lives: TCA SAIP
        # v3.4.1 tabulates template files (page 30) apart from generic file
        # management (page 46).
        self.assertIn("var glyph = saipFcpApplyGlyph(", general)
        self.assertIn(
            'spec, rowKind, String((fromLink ? linkSource.source : fcp.source) || ""),', general,
        )
        # An editable EF size carries the decimal chip.
        self.assertIn('sizeChip.className = "saip-edit-readonly saip-fcp-size-chip";', general)
        self.assertIn("saipEfFileSizeChip(input.value)", general)

    def test_an_empty_link_path_is_sent_and_other_rows_still_refuse_empty(self) -> None:
        apply = _function(self.source, "saipApplyFieldEdit")
        self.assertIn('var removesLink = hex.length === 0 && subKey === "linkPath";', apply)
        self.assertIn("if (hex.length === 0 && !removesLink) {", apply)
        self.assertIn('data.content_reset.reason === "linked"', apply)
        self.assertIn("var linkChange = data.link_change;", apply)


_LINK_HARNESS = r"""
__DEFS__
var linkSpec = _SAIP_EDIT_FIELDS.filter(function (spec) { return spec.sub === "linkPath"; })[0];
var kinds = ["mf", "adf", "df", "ef-t", "ef-lf", "ef-cy", "ef-ber", "link"];
var out = {};
["template", "gfm", ""].forEach(function (source) {
  out[source || "none"] = {};
  kinds.forEach(function (kind) {
    var glyph = saipFcpApplyGlyph(linkSpec, kind, source);
    out[source || "none"][kind] = glyph ? glyph.label : null;
  });
});
var lcsiSpec = _SAIP_EDIT_FIELDS.filter(function (spec) { return spec.sub === "lcsi"; })[0];
out.lcsiOnGfmLink = saipFcpApplyGlyph(lcsiSpec, "link", "gfm").label;
process.stdout.write(JSON.stringify(out));
"""


def _array(source: str, name: str) -> str:
    start = source.index(f"var {name} = [")
    end = source.index("\n  ];", start)
    return source[start : end + len("\n  ];")]


@unittest.skipUnless(shutil.which("node") and _APP_JS.exists(), "node or the built bundle missing")
class LinkPathApplicabilityTests(unittest.TestCase):
    """The Link path row of the FCP tab, from the built bundle.

    TCA SAIP v3.4.1 page 30: an EF a template defines may become a link
    (note 1, C), a link may be retargeted or made independent (note 3, C),
    an ADF or a DF may not become one (F). Page 46: a generic file management
    Create EF Link names it (M). A row coded F and empty is not rendered, so
    the row only shows on an EF once it is C.
    """

    @classmethod
    def setUpClass(cls) -> None:
        bundle = _APP_JS.read_text(encoding="utf-8")
        defs = "\n".join([
            _array(bundle, "_SAIP_EDIT_FIELDS"),
            _table(bundle, "_SAIP_FCP_APPLY_GLYPHS"),
            _function(bundle, "saipFcpApplyGlyph"),
        ])
        completed = subprocess.run(
            ["node", "-e", _LINK_HARNESS.replace("__DEFS__", defs)],
            capture_output=True, text=True, timeout=30, check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr)
        cls.out = json.loads(completed.stdout)

    def test_an_independent_ef_can_be_linked(self) -> None:
        for source in ("template", "gfm", "none"):
            for kind in ("ef-t", "ef-lf", "ef-cy", "ef-ber"):
                self.assertEqual(self.out[source][kind], "C", (source, kind))

    def test_mf_adf_and_df_cannot_become_a_link(self) -> None:
        for source in ("template", "gfm", "none"):
            for kind in ("mf", "adf", "df"):
                self.assertEqual(self.out[source][kind], "F", (source, kind))

    def test_a_link_keeps_its_path_by_source(self) -> None:
        self.assertEqual(self.out["template"]["link"], "C")
        self.assertEqual(self.out["gfm"]["link"], "M")
        self.assertEqual(self.out["none"]["link"], "C")

    def test_a_row_without_a_source_table_reads_the_shared_codes(self) -> None:
        # lcsi is optional for a link in both tables (pages 30 and 46).
        self.assertEqual(self.out["lcsiOnGfmLink"], "O")


if __name__ == "__main__":
    unittest.main()
