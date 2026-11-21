# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PE library: the saved-profile-element store and the GUI dispatchers over it."""

from __future__ import annotations

import importlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from Tools.ProfilePackage import saip_pe_library as lib

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = (
    _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
)


def _document(name: str = "sd-standard", placeholders: tuple[str, ...] = ()) -> dict:
    return {
        lib.PE_DOCUMENT_META_KEY: {
            "schema": lib.PE_DOCUMENT_SCHEMA,
            "pe_type": "securityDomain",
            "label": "MNO-SD",
            "library_name": name,
            "template": bool(placeholders),
            "placeholders": list(placeholders),
            "saved_at": "2026-10-02T12:00:00Z",
        },
        "intro": ["test"],
        "sections": {"securityDomain": {"sd-Header": {"identification": 12}}},
    }


class PeLibraryStoreTests(unittest.TestCase):
    """The on-disk store: names, round trip, refusals, listing."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "lib"

    def test_directory_follows_the_env_override(self) -> None:
        self.assertEqual(lib.pe_library_dir({lib.PE_LIBRARY_DIR_ENV: str(self.dir)}), self.dir)
        default = lib.pe_library_dir({})
        self.assertEqual(default.name, lib.PE_LIBRARY_DIR_NAME)
        self.assertEqual(default.parent.name, ".yggdrasim")

    def test_entry_name_rules(self) -> None:
        self.assertEqual(lib.normalise_entry_name(" sd-standard.pe.json "), "sd-standard")
        self.assertEqual(lib.normalise_entry_name("MNO_SD.v2"), "MNO_SD.v2")
        for bad in ("", "-leading", "has space", "x" * 65, "a/b", "..", "sd?"):
            with self.assertRaises(lib.PeLibraryError):
                lib.normalise_entry_name(bad)

    def test_write_read_list_delete_round_trip(self) -> None:
        path = lib.write_entry("sd-standard", _document(), directory=self.dir)
        self.assertEqual(path, self.dir / "sd-standard.pe.json")
        document = lib.read_entry("sd-standard", self.dir)
        self.assertEqual(document[lib.PE_DOCUMENT_META_KEY]["pe_type"], "securityDomain")
        rows = lib.list_entries(self.dir)
        self.assertEqual([row["name"] for row in rows], ["sd-standard"])
        self.assertEqual(rows[0]["pe_type"], "securityDomain")
        self.assertEqual(rows[0]["label"], "MNO-SD")
        self.assertEqual(rows[0]["saved_at"], "2026-10-02T12:00:00Z")
        self.assertFalse(rows[0]["template"])
        self.assertEqual(rows[0]["placeholders"], [])
        self.assertGreater(rows[0]["size_bytes"], 0)
        self.assertEqual(lib.delete_entry("sd-standard", self.dir), path)
        self.assertFalse(path.exists())
        self.assertEqual(lib.list_entries(self.dir), [])

    def test_write_refuses_an_existing_entry_unless_overwrite(self) -> None:
        lib.write_entry("sd-standard", _document(), directory=self.dir)
        with self.assertRaises(FileExistsError):
            lib.write_entry("sd-standard", _document(), directory=self.dir)
        lib.write_entry(
            "sd-standard", _document(placeholders=("scp80_kic1",)), directory=self.dir, overwrite=True
        )
        self.assertEqual(lib.list_entries(self.dir)[0]["placeholders"], ["scp80_kic1"])

    def test_write_refuses_a_foreign_document(self) -> None:
        with self.assertRaises(lib.PeLibraryError):
            lib.write_entry("x", {"sections": {}}, directory=self.dir)
        with self.assertRaises(lib.PeLibraryError):
            lib.write_entry(
                "x",
                {lib.PE_DOCUMENT_META_KEY: {"schema": "other"}, "sections": {}},
                directory=self.dir,
            )
        self.assertFalse(self.dir.exists() and any(self.dir.iterdir()))

    def test_listing_reads_the_pe_name_from_the_tree(self) -> None:
        lean = {
            lib.PE_DOCUMENT_META_KEY: {
                "schema": lib.PE_DOCUMENT_SCHEMA,
                "pe_type": "securityDomain",
                "library_name": "sd-lean",
                "saved_at": "2026-10-02T12:00:00Z",
            },
            "sections": {
                "securityDomain": {"sd-Header": {"identification": 12, "pe-name": "MNO-SD"}}
            },
        }
        lib.write_entry("sd-lean", lean, directory=self.dir)
        earlier = _document("sd-earlier")
        earlier[lib.PE_DOCUMENT_META_KEY].update(
            {"source_package": "operator.varder", "summary": {"pe_type": "securityDomain"}}
        )
        lib.write_entry("sd-earlier", earlier, directory=self.dir)
        rows = {row["name"]: row for row in lib.list_entries(self.dir)}
        self.assertEqual(rows["sd-lean"]["pe_name"], "MNO-SD")
        self.assertEqual(rows["sd-lean"]["label"], "")
        self.assertFalse(rows["sd-lean"]["template"])
        self.assertEqual(rows["sd-lean"]["placeholders"], [])
        self.assertEqual(rows["sd-earlier"]["label"], "MNO-SD")
        for row in rows.values():
            self.assertNotIn("source_package", row)
            self.assertNotIn("summary", row)

    def test_listing_reports_an_unreadable_entry(self) -> None:
        self.dir.mkdir(parents=True)
        (self.dir / "broken.pe.json").write_text("nope", encoding="utf-8")
        (self.dir / "notes.txt").write_text("ignored", encoding="utf-8")
        rows = lib.list_entries(self.dir)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["name"], "broken")
        self.assertIn("error", rows[0])

    def test_missing_entry_raises(self) -> None:
        with self.assertRaises(lib.PeLibraryError):
            lib.read_entry("absent", self.dir)
        with self.assertRaises(lib.PeLibraryError):
            lib.delete_entry("absent", self.dir)

    def test_document_constants_match_the_gui_actions(self) -> None:
        actions = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.assertEqual(actions._PE_DOCUMENT_KEY, lib.PE_DOCUMENT_META_KEY)
        self.assertEqual(actions._PE_DOCUMENT_SCHEMA, lib.PE_DOCUMENT_SCHEMA)

    def test_env_flag_is_registered(self) -> None:
        from yggdrasim_common import env_flags

        flag = env_flags.get_flag(lib.PE_LIBRARY_DIR_ENV)
        self.assertIsNotNone(flag)
        self.assertEqual(flag.default_hint, "~/.yggdrasim/saip_pe_library/")


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class PeLibraryDispatcherTests(unittest.TestCase):
    """saip.save_pe / list_pe_library / load_pe / delete_saved_pe over a session."""

    def setUp(self) -> None:
        self.actions = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        self.actions._ensure_pysim_importable()
        self.sessions = importlib.import_module("yggdrasim_common.gui_server.sessions")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name) / "pe-library"
        patcher = mock.patch.dict(os.environ, {lib.PE_LIBRARY_DIR_ENV: str(self.dir)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.sid = self._open_session()

    def _open_session(self) -> str:
        return self.actions._dispatch_open_package(ctx=None, path=str(_REFERENCE_PROFILE))[
            "session_id"
        ]

    def _pe_rows(self, sid: str) -> list:
        return self.actions._dispatch_list_pes(ctx=None, session_id=sid)["rows"]

    def _sd_index(self, sid: str) -> int:
        for row in self._pe_rows(sid):
            if str(row.get("type") or "").lower() == "securitydomain":
                return int(row["index"])
        self.fail("reference profile has no securityDomain PE")

    def test_save_list_load_delete(self) -> None:
        idx = self._sd_index(self.sid)
        saved = self.actions._dispatch_save_pe(
            ctx=None, session_id=self.sid, pe_index=idx, name="sd-standard"
        )
        self.assertEqual(saved["name"], "sd-standard")
        self.assertEqual(saved["pe_type"], "securityDomain")
        self.assertFalse(saved["template"])
        self.assertTrue(Path(saved["path"]).is_file())
        self.assertIn("Saved PE[", saved["summary"])
        # The entry is the lean PE document plus the library's own two keys.
        stored_text = Path(saved["path"]).read_text(encoding="utf-8")
        stored = json.loads(stored_text)
        self.assertEqual(sorted(stored), sorted([lib.PE_DOCUMENT_META_KEY, "sections"]))
        self.assertEqual(
            sorted(stored[lib.PE_DOCUMENT_META_KEY]),
            ["library_name", "pe_type", "saved_at", "schema"],
        )
        self.assertNotIn(_REFERENCE_PROFILE.name, stored_text)

        listing = self.actions._dispatch_list_pe_library(ctx=None)
        self.assertEqual(listing["directory"], str(self.dir))
        self.assertEqual(listing["count"], 1)
        self.assertEqual(listing["entries"][0]["name"], "sd-standard")
        self.assertEqual(listing["entries"][0]["pe_type"], "securityDomain")
        self.assertTrue(listing["entries"][0]["saved_at"].endswith("Z"))

        with self.assertRaises(FileExistsError):
            self.actions._dispatch_save_pe(
                ctx=None, session_id=self.sid, pe_index=idx, name="sd-standard"
            )

        before = len(self._pe_rows(self.sid))
        loaded = self.actions._dispatch_load_pe(
            ctx=None, session_id=self.sid, name="sd-standard", insert_at=before - 1
        )
        self.assertEqual(loaded["pe_index"], before - 1)
        self.assertEqual(loaded["pe_type"], "securityDomain")
        self.assertEqual(loaded["pe_count"], before + 1)
        self.assertEqual(loaded["name"], "sd-standard")
        self.assertIn("Loaded library entry 'sd-standard' as PE[", loaded["summary"])
        self.assertEqual(len(self._pe_rows(self.sid)), before + 1)
        shown = self.actions._dispatch_show_pe(
            ctx=None, session_id=self.sid, pe_index=loaded["pe_index"]
        )
        self.assertEqual(str(shown["type"]).lower(), "securitydomain")

        deleted = self.actions._dispatch_delete_saved_pe(ctx=None, name="sd-standard")
        self.assertFalse(Path(deleted["path"]).exists())
        self.assertEqual(self.actions._dispatch_list_pe_library(ctx=None)["count"], 0)
        with self.assertRaises(lib.PeLibraryError):
            self.actions._dispatch_load_pe(ctx=None, session_id=self.sid, name="sd-standard")

    def test_load_rejects_a_bad_insert_index_before_touching_the_session(self) -> None:
        idx = self._sd_index(self.sid)
        self.actions._dispatch_save_pe(ctx=None, session_id=self.sid, pe_index=idx, name="sd")
        before = len(self._pe_rows(self.sid))
        with self.assertRaises(ValueError):
            self.actions._dispatch_load_pe(ctx=None, session_id=self.sid, name="sd", insert_at=0)
        with self.assertRaises(ValueError):
            self.actions._dispatch_load_pe(
                ctx=None, session_id=self.sid, name="sd", insert_at=before
            )
        self.assertEqual(len(self._pe_rows(self.sid)), before)

    def test_a_saved_template_pe_brings_its_placeholders_into_another_package(self) -> None:
        idx = self._sd_index(self.sid)
        handle = self.sessions.get_manager().claim(self.sid)
        section = self.actions._sections_by_pe_index(handle["decoded_document"])[idx]
        # The first key of the MNO-SD takes a placeholder: the session is a template now.
        self.actions._dispatch_apply_decoded_edit(
            ctx=None,
            session_id=self.sid,
            section_key=section,
            rel_path=["keyList", 0, "keyComponents", 0, "keyData"],
            field_name="keyData",
            editor_kind="raw_hex_decoded",
            editor_payload={"hex": "{scp80_kic1:BINARY:16}"},
        )
        saved = self.actions._dispatch_save_pe(
            ctx=None, session_id=self.sid, pe_index=idx, name="sd-template"
        )
        self.assertTrue(saved["template"])
        self.assertEqual(saved["placeholders"], ["scp80_kic1"])
        self.assertEqual(self.actions._dispatch_list_pe_library(ctx=None)["entries"][0]["placeholders"], ["scp80_kic1"])

        fresh = self._open_session()
        fresh_handle = self.sessions.get_manager().claim(fresh)
        self.assertEqual(list(fresh_handle.get("inline_placeholder_records") or []), [])
        before = len(self._pe_rows(fresh))

        loaded = self.actions._dispatch_load_pe(ctx=None, session_id=fresh, name="sd-template")

        self.assertEqual(loaded["pe_count"], before + 1)
        names = {
            str(record.variable_name)
            for record in fresh_handle.get("inline_placeholder_records") or []
        }
        self.assertIn("scp80_kic1", names)
        self.assertIsInstance(loaded.get("placeholders"), dict)
        self.assertGreater(int(loaded.get("inline_placeholder_count") or 0), 0)

    def test_import_pe_still_refuses_a_template_document(self) -> None:
        idx = self._sd_index(self.sid)
        handle = self.sessions.get_manager().claim(self.sid)
        section = self.actions._sections_by_pe_index(handle["decoded_document"])[idx]
        self.actions._dispatch_apply_decoded_edit(
            ctx=None,
            session_id=self.sid,
            section_key=section,
            rel_path=["keyList", 0, "keyComponents", 0, "keyData"],
            field_name="keyData",
            editor_kind="raw_hex_decoded",
            editor_payload={"hex": "{scp80_kic1:BINARY:16}"},
        )
        target = Path(self.tmp.name) / "sd.pe.json"
        self.actions._dispatch_export_pe(
            ctx=None, session_id=self.sid, pe_index=idx, output_path=str(target), format="json"
        )
        with self.assertRaises(ValueError) as caught:
            self.actions._dispatch_import_pe(
                ctx=None, session_id=self.sid, input_path=str(target)
            )
        self.assertIn("is a template", str(caught.exception))



class PeLibraryBundleWiringTests(unittest.TestCase):
    """The served bundle carries the PE library, Insert PE and Save-as dialogs."""

    def setUp(self) -> None:
        self.app_js = Path("yggdrasim_common/gui_server/static/app.js").read_text(encoding="utf-8")
        self.app_css = Path("yggdrasim_common/gui_server/static/app.css").read_text(encoding="utf-8")

    def test_ribbon_and_dialogs_are_wired(self) -> None:
        for symbol in (
            'label: "Save PE"',
            'label: "PE library"',
            "async function saipRibbonSavePe(",
            "async function saipShowPeLibraryModal(",
            "async function saipLoadLibraryEntryIntoPackage(",
            "/api/actions/saip.save_pe/run",
            "/api/actions/saip.list_pe_library/run",
            "/api/actions/saip.load_pe/run",
            "/api/actions/saip.delete_saved_pe/run",
        ):
            self.assertIn(symbol, self.app_js, f"missing: {symbol}")
        for css_class in (".saip-pe-library-table", ".saip-pe-library-actions"):
            self.assertIn(css_class, self.app_css, f"missing CSS rule: {css_class}")

    def test_insert_pe_dialog_replaces_the_prompt(self) -> None:
        self.assertIn("async function saipShowAddPeModal(", self.app_js)
        self.assertIn("/api/actions/saip.list_pe_types/run", self.app_js)
        self.assertIn("/api/actions/saip.list_pe_presets/run", self.app_js)
        self.assertIn('textContent = "Insert profile element"', self.app_js)
        self.assertIn('textContent = "From the PE library"', self.app_js)
        self.assertNotIn("PE type to insert (akaParameter", self.app_js)
        self.assertNotIn("async function saipPromptPePreset(", self.app_js)
        self.assertIn(".saip-add-pe-modal .saip-action-palette-row", self.app_css)

    def test_save_as_dialog_names_every_package_format(self) -> None:
        self.assertIn("function saipPackageSaveFormatOptions(", self.app_js)
        self.assertIn('title: "Save package as"', self.app_js)
        for value in ('value: "der"', 'value: "hex"', 'value: "asn1"', 'value: "json"', 'value: "varder"'):
            self.assertIn(value, self.app_js)

    def test_link_jump_re_renders_the_top_tabs(self) -> None:
        start = self.app_js.index("function saipOpenFileRow(")
        block = self.app_js[start:start + 1500]
        self.assertIn("renderSaipTopTabs(saipTopTabsEl(), saipDrawerEl(), peList, detail, validation);", block)

    def test_fcp_rows_carry_df_name_and_the_link_column(self) -> None:
        self.assertIn('sub: "dfName"', self.app_js)
        self.assertIn('row: "df_name"', self.app_js)
        start = self.app_js.index('label: "EF size"')
        self.assertIn('link: "C"', self.app_js[start:start + 700])

    def test_per_view_ui_state_helpers_wrap_the_renderers(self) -> None:
        for symbol in (
            "function saipCaptureDetailUiState(",
            "function saipRestoreDetailUiState(",
            "function saipCaptureListUiState(",
            "function saipRestoreListUiState(",
            "function renderSaipPeListBody(",
        ):
            self.assertIn(symbol, self.app_js, f"missing: {symbol}")
        start = self.app_js.index("function renderSaipDetail(")
        self.assertIn("saipCaptureDetailUiState(detail);", self.app_js[start:start + 400])


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class ListPeTypesTests(unittest.TestCase):
    def test_lists_the_choice_alternatives_without_anchors_and_dummies(self) -> None:
        actions = importlib.import_module("yggdrasim_common.gui_server.actions.saip")
        rows = actions._dispatch_list_pe_types(ctx=None)["rows"]
        names = [row["pe_type"] for row in rows]
        self.assertEqual(names[0], "genericFileManagement")
        for anchor_name in ("header", "end"):
            self.assertNotIn(anchor_name, names)
        self.assertFalse([name for name in names if name.startswith("rfu")])
        for expected in ("securityDomain", "rfm", "usim", "opt-iot"):
            self.assertIn(expected, names)
        sd = next(row for row in rows if row["pe_type"] == "securityDomain")
        self.assertTrue(sd["has_class"])
        self.assertIsInstance(sd["presets"], int)

if __name__ == "__main__":
    unittest.main()
