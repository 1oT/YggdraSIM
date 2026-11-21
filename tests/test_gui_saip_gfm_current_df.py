# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The GFM card states the current DF of every file it lists.

TCA SAIP V3.4.1 section 8.3.5: a Generic File Management PE starts at the
MF, ``filePath`` selects a DF or ADF by path from the MF, a created DF or
ADF is selected automatically and an EF is created in the current DF. The
card resolves that walk in the browser (``saipGfmApplyImplicitContext``).
These tests run the bundle's resolver under ``node`` on the command shapes
the reference profile carries and pin the surface that shows the result.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.css"
_NAMING = _REPO_ROOT / "guides" / "NAMING_CONVENTIONS.md"

_FUNCTIONS = (
    "saipDecodeFileDescriptor",
    "saipGfmFidLabel",
    "saipGfmFileDisplayName",
    "saipGfmViewCreatesDf",
    "saipGfmNormaliseParentHex",
    "saipGfmChainHops",
    "saipGfmPathTextFromHex",
    "saipGfmAdfMap",
    "saipGfmHopLabel",
    "saipGfmAnchorChain",
    "saipGfmChainNames",
    "saipGfmFormatParentPath",
    "saipGfmApplyImplicitContext",
    "saipGfmCurrentDfList",
    "saipGfmParentSourceText",
    "saipGfmComputeParentSummary",
)
_TABLES = ("_SAIP_FD_STRUCTURE", "_SAIP_FD_FILETYPE", "_GFM_FID_NAMES", "_GFM_DF_NAMES")

# The command shapes of the reference profile's four GFM PEs plus the
# GFM-first vendor shape (the MF created by the PE itself). ``select``
# is the filePath value as the profile spells it, ``None`` when the
# command carries none.
_DF = "7821"
_TR = "4121"
_LF = "42210020"
_CASES = {
    "explicit_df": [
        {"select": "7F10", "fid": "6F3A", "fd": _LF},
        {"select": None, "fid": "6F3B", "fd": _LF},
        {"select": None, "fid": "6F3C", "fd": _LF},
    ],
    "created_df": [
        {"select": None, "fid": "7F20", "fd": _DF},
        {"select": None, "fid": "6F05", "fd": _TR},
        {"select": None, "fid": "6F07", "fd": _TR},
    ],
    "adf_temp_fid": [
        {"select": "7FF0", "fid": "5F50", "fd": _DF},
        {"select": "7FF05F50", "fid": "4F83", "fd": _LF},
        {"select": None, "fid": "4F81", "fd": _LF},
    ],
    "created_adf": [
        {"select": None, "fid": "7F50", "fd": _DF, "dfName": "A000000063504B43532D3135"},
        {"select": None, "fid": "6F06", "fd": _LF},
        {"select": None, "fid": "5031", "fd": _TR},
    ],
    "gfm_first_mf": [
        {"select": None, "fid": "3F00", "fd": _DF},
        {"select": None, "fid": "2F00", "fd": _LF},
        {"select": "", "fid": "2FE2", "fd": _TR},
        {"select": "3F007F10", "fid": "6F3A", "fd": _LF},
    ],
}


def _function(source: str, name: str) -> str:
    """The text of ``function <name>(...) {...}``, braces matched outside string literals."""
    start = source.index(f"function {name}(")
    depth = 0
    quote = ""
    index = source.index("{", start)
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
    """The text of ``var <name> = {...};``."""
    start = source.index(f"var {name} = {{")
    end = source.index("};", start)
    return source[start : end + 2]


_HARNESS = r"""
%(defs)s
var cases = %(cases)s;
var adfRows = { fileRows: [{ kind: "adf", file_id: "7FF0", friendly_name: "ADF.USIM" }] };
var out = {};
Object.keys(cases).forEach(function (name) {
  ["rows", "norows"].forEach(function (mode) {
    var views = cases[name].map(function (block) {
      var seen = block.select !== null && block.select !== undefined;
      var raw = seen ? String(block.select) : null;
      var hex = seen ? saipGfmNormaliseParentHex(raw) : null;
      var fcp = { descriptor: block.fd, file_id: block.fid, df_name: block.dfName || "" };
      return {
        fileId: block.fid,
        fcp: fcp,
        parentSeen: seen,
        parentHex: hex,
        parentRawHex: raw,
        displayName: saipGfmFileDisplayName(block.fid, block.fd, !!block.dfName),
        summaryParentHex: seen ? hex : null,
      };
    });
    var adfMap = saipGfmAdfMap(mode === "rows" ? adfRows : { fileRows: null });
    saipGfmApplyImplicitContext(views, adfMap);
    var summary = saipGfmComputeParentSummary(views, adfMap);
    out[name + ":" + mode] = {
      views: views.map(function (v) {
        return {
          fid: v.fileId,
          name: v.displayName,
          parentHex: v.parentHex,
          parent_path: v.fcp.parent_path,
          fid_chain: v.fcp.fid_chain,
          source: v.parentSource.kind,
          sourceIdx: v.parentSource.idx,
          pretty: saipGfmFormatParentPath(v.parentHex, adfMap),
          text: saipGfmParentSourceText(v, views),
          creates: v.createsContainer,
          adf: v.createsAdf,
        };
      }),
      summary: {
        state: summary.state,
        path: summary.path,
        pretty: summary.pretty,
        dfs: summary.dfs.map(function (d) { return [d.hex, d.pretty, d.count, d.firstIdx]; }),
      },
      adfMap: adfMap,
    };
  });
});
process.stdout.write(JSON.stringify(out));
"""


def _run_resolver() -> dict:
    node = shutil.which("node")
    if node is None:
        raise unittest.SkipTest("node is not installed")
    bundle = _APP_JS.read_text(encoding="utf-8")
    defs = "\n".join([_table(bundle, name) for name in _TABLES] + [_function(bundle, name) for name in _FUNCTIONS])
    harness = _HARNESS % {"defs": defs, "cases": json.dumps(_CASES)}
    completed = subprocess.run(
        [node, "-e", harness], check=False, capture_output=True, text=True, timeout=20,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


class GfmCurrentDfResolverTests(unittest.TestCase):
    """The walk of SAIP V3.4.1 section 8.3.5, run from the served bundle."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.out = _run_resolver()

    def _case(self, name: str, mode: str = "rows") -> dict:
        return self.out[f"{name}:{mode}"]

    def test_explicit_select_is_inherited_by_the_commands_that_follow(self) -> None:
        case = self._case("explicit_df")
        views = case["views"]
        self.assertEqual([v["parentHex"] for v in views], ["7F10", "7F10", "7F10"])
        self.assertEqual([v["source"] for v in views], ["explicit", "inherited", "inherited"])
        self.assertEqual([v["sourceIdx"] for v in views], [0, 0, 0])
        self.assertEqual(views[0]["parent_path"], "3F00/7F10")
        self.assertEqual(views[1]["fid_chain"], "3F00/7F10/6F3B")
        self.assertEqual(views[0]["pretty"], "7F10 · DF.TELECOM")
        self.assertIn("filePath '7F10' in this command", views[0]["text"])
        self.assertIn("carried by EF(ADN) 6F3A", views[1]["text"])
        self.assertEqual(case["summary"]["state"], "bound")
        self.assertEqual(case["summary"]["path"], "7F10")
        self.assertEqual(case["summary"]["dfs"], [["7F10", "7F10 · DF.TELECOM", 3, 0]])

    def test_created_df_becomes_the_current_df(self) -> None:
        case = self._case("created_df")
        views = case["views"]
        self.assertEqual(views[0]["parentHex"], "")
        self.assertEqual(views[0]["source"], "default")
        self.assertTrue(views[0]["creates"])
        self.assertEqual(views[0]["parent_path"], "3F00")
        self.assertEqual(views[0]["fid_chain"], "3F00/7F20")
        self.assertEqual([v["parentHex"] for v in views[1:]], ["7F20", "7F20"])
        self.assertEqual([v["source"] for v in views[1:]], ["created", "created"])
        self.assertEqual(views[1]["fid_chain"], "3F00/7F20/6F05")
        self.assertIn("DF.GSM 7F20 was created before this command", views[1]["text"])
        self.assertIn("starts at the MF", views[0]["text"])
        # The created DF does not bind the Add-file bar; its EFs do.
        self.assertEqual(case["summary"]["state"], "bound")
        self.assertEqual(case["summary"]["path"], "7F20")
        self.assertEqual(
            case["summary"]["dfs"],
            [["", "3F00 · MF", 1, 0], ["7F20", "7F20 · DF.GSM", 2, 1]],
        )

    def test_adf_temporary_fid_resolves_to_the_adf_name(self) -> None:
        case = self._case("adf_temp_fid")
        views = case["views"]
        self.assertEqual(views[0]["parent_path"], "ADF.USIM")
        self.assertEqual(views[0]["fid_chain"], "ADF.USIM/5F50")
        self.assertEqual(views[0]["pretty"], "7FF0 · ADF.USIM")
        self.assertEqual(views[1]["parentHex"], "7FF05F50")
        self.assertEqual(views[1]["parent_path"], "ADF.USIM/5F50")
        self.assertEqual(views[1]["pretty"], "7FF0/5F50 · ADF.USIM/DF.GRAPHICS")
        self.assertEqual(views[2]["source"], "inherited")
        self.assertEqual(views[2]["fid_chain"], "ADF.USIM/5F50/4F81")
        self.assertEqual(case["summary"]["path"], "7FF05F50")
        # Without the package file list the temporary FID stays a FID.
        plain = self._case("adf_temp_fid", "norows")
        self.assertEqual(plain["views"][0]["parent_path"], "3F00/7FF0")
        self.assertEqual(plain["views"][1]["pretty"], "7FF0/5F50 · DF(7FF0)/DF.GRAPHICS")

    def test_adf_created_by_the_gfm_roots_its_files(self) -> None:
        case = self._case("created_adf")
        views = case["views"]
        self.assertTrue(views[0]["adf"])
        self.assertEqual(views[0]["name"], "ADF(7F50)")
        self.assertEqual(views[0]["fid_chain"], "3F00/7F50")
        self.assertEqual(views[1]["parentHex"], "7F50")
        self.assertEqual(views[1]["parent_path"], "ADF(7F50)")
        self.assertEqual(views[2]["fid_chain"], "ADF(7F50)/5031")
        self.assertEqual(case["adfMap"]["7F50"], "ADF(7F50)")

    def test_gfm_first_profile_keeps_the_mf_as_root(self) -> None:
        case = self._case("gfm_first_mf")
        views = case["views"]
        self.assertEqual(views[0]["name"], "MF")
        self.assertEqual(views[0]["fid_chain"], "3F00/3F00")
        self.assertEqual(views[1]["parentHex"], "")
        self.assertEqual(views[1]["source"], "created")
        self.assertIn("MF 3F00 was created before this command", views[1]["text"])
        self.assertEqual(views[2]["source"], "explicit")
        self.assertIn("empty filePath in this command, which selects the MF", views[2]["text"])
        self.assertEqual(views[3]["parentHex"], "7F10")
        self.assertIn("filePath '3F007F10' in this command", views[3]["text"])
        self.assertEqual(case["summary"]["state"], "mixed")
        self.assertEqual([d[0] for d in case["summary"]["dfs"]], ["", "7F10"])


class GfmCurrentDfSurfaceTests(unittest.TestCase):
    """The chip, the list groups and the detail card carry the label."""

    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")
        self.css = _APP_CSS.read_text(encoding="utf-8")

    def test_card_surfaces_are_in_the_bundle(self) -> None:
        for needle in (
            'chipLabel.textContent = "Current DF";',
            "saip-gfm-df-pill",
            "saip-gfm-list-group-head",
            'setAttribute("role", "group")',
            'saipEditorKv(whereCard, "Selected by", saipGfmParentSourceText(v, cmdViews));',
            "saipLoadFileRows(pkg).then(function () {",
        ):
            self.assertIn(needle, self.js, needle)
        self.assertNotIn('"N distinct parent paths"', self.js)

    def test_styles_reach_the_bundle_through_tokens(self) -> None:
        for selector in (
            ".saip-gfm-df-pill",
            ".saip-gfm-df-pill-count",
            ".saip-gfm-list-group-head",
            ".saip-gfm-list-group-hex",
        ):
            self.assertIn(selector, self.css, selector)

    def test_label_is_anchored_in_the_naming_guide(self) -> None:
        text = _NAMING.read_text(encoding="utf-8")
        self.assertIn("| Current DF | TCA SAIP v3.4.1 §8.3.5", text)
        self.assertIn("| Parent path     |", text)


if __name__ == "__main__":
    unittest.main()
