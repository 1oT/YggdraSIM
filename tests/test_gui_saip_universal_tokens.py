# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Universal test values on a SAIP session.

A hex template is built from the tracked reference profile by turning its
ProfileHeader ICCID into ``{iccidICCID10}``; the universal list lives in a
temporary file with a reserved-range ICCID. The session must resolve the
placeholder through the list, keep a typed value ahead of it, forget it on
reset and undo, restore it from the variables sidecar, and export the
bytes.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
_COMMAND_CENTER_SOURCE = _REPO_ROOT / "gui_frontend" / "src" / "js" / "command-center.js"
_WORKBENCH_SOURCE = _REPO_ROOT / "gui_frontend" / "src" / "js" / "saip-workbench.js"
_SERVED_BUNDLE = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_MANAGER_INPUT_NAMES = frozenset(
    {"configuration_id", "registry_json", "reload_current", "list_configurations"}
)


def _js_between(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    return body[start : body.index(end_marker, start)]
_HEADER_ICCID_HEX = "89880811111111111112"
_TEST_ICCID_HEX = "8988201234567890123F"


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class UniversalTokenSessionTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_universal_"))
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self.assertEqual(reference.count(_HEADER_ICCID_HEX), 1)
        self._template = self._tmpdir / "template.hex"
        self._template.write_text(
            reference.replace(_HEADER_ICCID_HEX, "{iccidICCID10}"), encoding="utf-8"
        )
        self._list_path = self._tmpdir / "universal.csv"
        self._list_path.write_text(f"iccidICCID10,{_TEST_ICCID_HEX}\n", encoding="utf-8")
        self._sids: list[str] = []

    def tearDown(self) -> None:
        for sid in self._sids:
            try:
                self._manager.release(sid)
            except Exception:
                pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _open(self) -> str:
        result = self._actions._dispatch_open_package(ctx=None, path=str(self._template))
        sid = result["session_id"]
        self._sids.append(sid)
        return sid

    def _row(self, sid: str, name: str) -> dict:
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        for row in listing["variables"]:
            if str(row.get("name") or "").casefold() == name.casefold():
                return row
        raise AssertionError(f"variable {name!r} not listed: {listing['variables']}")

    def _apply(self, sid: str, **extra):
        # The registered dispatcher carries the history wrapper, so undo
        # sees the apply the way the GUI performs it.
        from yggdrasim_common.gui_server.actions.registry import get_registry

        spec = get_registry().get("saip.apply_universal_tokens")
        return spec.dispatcher(None, session_id=sid, path=str(self._list_path), **extra)

    def test_apply_resolves_the_placeholder_and_the_export_carries_the_bytes(self) -> None:
        sid = self._open()
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_UNRESOLVED")

        result = self._apply(sid)

        self.assertEqual(result["applied_count"], 1)
        self.assertEqual(result["applied"][0]["key"], "iccidICCID10")
        self.assertEqual(result["inline_template"]["universal_variables"], ["iccid"])
        self.assertEqual(result["inline_template"]["unresolved_variables"], [])
        row = self._row(sid, "iccid")
        self.assertEqual(row["status"], "BOUND_INLINE_RESOLVED")
        self.assertTrue(row["universal"])
        self.assertEqual(row["value"], _TEST_ICCID_HEX)

        out_path = self._tmpdir / "complete.der"
        saved = self._actions._dispatch_save_package(
            ctx=None,
            session_id=sid,
            output_path=str(out_path),
            format="der",
            resolve_variables=True,
        )
        self.assertTrue(out_path.is_file(), saved)
        self.assertIn(_TEST_ICCID_HEX, out_path.read_bytes().hex().upper())
        # The session keeps its template: the placeholder is still there.
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_RESOLVED")

    def test_typed_value_wins_and_reset_clears_the_universal_value(self) -> None:
        sid = self._open()
        self._apply(sid)

        self._actions._dispatch_set_variable(
            ctx=None, session_id=sid, name="iccid", value="8988201234567890123"
        )
        row = self._row(sid, "iccid")
        self.assertFalse(row["universal"])
        self.assertEqual(row["value"], "8988201234567890123")
        session = self._manager.get(sid)
        self.assertEqual(session.handle["inline_raw_values"], {})

        reset = self._actions._dispatch_reset_variable(ctx=None, session_id=sid, name="iccid")
        self.assertTrue(reset["removed"])
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_UNRESOLVED")

        self._apply(sid)
        self.assertTrue(self._row(sid, "iccid")["universal"])
        reset = self._actions._dispatch_reset_variable(ctx=None, session_id=sid, name="iccid")
        self.assertTrue(reset["removed"])
        self.assertIn("universal test value cleared", reset["summaries"][0])
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_UNRESOLVED")

    def test_apply_keeps_typed_values_unless_asked_to_replace_them(self) -> None:
        sid = self._open()
        self._actions._dispatch_set_variable(
            ctx=None, session_id=sid, name="iccid", value="8988201234567890123"
        )

        kept = self._apply(sid)
        self.assertEqual(kept["applied_count"], 0)
        self.assertEqual(kept["kept"], ["iccid"])
        self.assertEqual(self._row(sid, "iccid")["value"], "8988201234567890123")

        replaced = self._apply(sid, overwrite=True)
        self.assertEqual(replaced["applied_count"], 1)
        self.assertEqual(replaced["kept"], [])
        self.assertTrue(self._row(sid, "iccid")["universal"])
        self.assertEqual(self._manager.get(sid).handle["applied_overrides"], {})

    def test_apply_reports_rejected_lines_and_unanswered_placeholders(self) -> None:
        sid = self._open()
        self._list_path.write_text("iccidICCID10,8988201234567890123\n", encoding="utf-8")

        result = self._apply(sid)

        self.assertEqual(result["applied_count"], 0)
        self.assertEqual(len(result["problems"]), 1)
        self.assertIn("odd hex length", result["problems"][0]["reason"])
        self.assertEqual(result["unmatched"][0]["key"], "iccidICCID10")
        # The reason names the list that rejected the line, then the line.
        self.assertIn("universal.csv line 1:", result["unmatched"][0]["reason"])
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_UNRESOLVED")

    def test_missing_list_is_reported_not_raised(self) -> None:
        sid = self._open()
        self._list_path.unlink()

        result = self._apply(sid)

        self.assertFalse(result["loaded"])
        self.assertEqual(result["applied_count"], 0)
        self.assertIn("No token list at", result["summaries"][0])

    def test_undo_forgets_the_universal_value(self) -> None:
        sid = self._open()
        self._apply(sid)
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_RESOLVED")

        undone = self._actions._dispatch_undo(ctx=None, session_id=sid)

        self.assertTrue(undone["applied"])
        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_UNRESOLVED")

    def test_template_save_and_reopen_restore_the_universal_value(self) -> None:
        sid = self._open()
        self._apply(sid)
        saved_template = self._tmpdir / "saved.varder"

        self._actions._dispatch_save_package(
            ctx=None,
            session_id=sid,
            output_path=str(saved_template),
            format="varder",
            resolve_variables=False,
            write_variable_sidecar=True,
        )

        sidecar = saved_template.with_suffix(".variables.json")
        self.assertTrue(sidecar.is_file())
        self.assertIn('"raw_values"', sidecar.read_text(encoding="utf-8"))
        reopened = self._actions._dispatch_open_package(ctx=None, path=str(saved_template))
        self._sids.append(reopened["session_id"])
        row = self._row(reopened["session_id"], "iccid")
        self.assertEqual(row["status"], "BOUND_INLINE_RESOLVED")
        self.assertTrue(row["universal"])

    def test_placeholder_ranges_name_their_source(self) -> None:
        sid = self._open()
        self._apply(sid)
        handle = self._manager.get(sid).handle
        records = handle["inline_placeholder_records"]
        sentinel = bytes.fromhex(records[0].sentinel_hex)

        ranges = self._actions._inline_placeholder_ranges(handle, b"\x00" + sentinel + b"\x01")

        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0]["source"], "universal")
        self.assertEqual(ranges[0]["key"], "iccidICCID10")
        self.assertEqual(ranges[0]["stored_value"], _TEST_ICCID_HEX)


class UniversalTokensEditorActionTests(unittest.TestCase):

    def setUp(self) -> None:
        from yggdrasim_common.gui_server.actions import saip as saip_actions

        self._actions = saip_actions
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_universal_editor_"))
        self._list_path = self._tmpdir / "universal.csv"

    def tearDown(self) -> None:
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_show_then_save_then_show(self) -> None:
        shown = self._actions._dispatch_universal_tokens(ctx=None, path=str(self._list_path))
        self.assertFalse(shown["exists"])
        self.assertEqual(shown["entry_count"], 0)

        saved = self._actions._dispatch_universal_tokens(
            ctx=None,
            path=str(self._list_path),
            contents="accBINARY2,0040\nscp80kic1BINARY8,1122\n",
            save=True,
        )
        self.assertTrue(saved["saved"])
        self.assertEqual(saved["entry_count"], 1)
        self.assertEqual(saved["problems"][0]["line"], 2)
        self.assertEqual(self._list_path.read_text(encoding="utf-8"), "accBINARY2,0040\nscp80kic1BINARY8,1122\n")

        with self.assertRaises(ValueError):
            self._actions._dispatch_universal_tokens(
                ctx=None, path=str(self._list_path), contents="broken line\n", save=True
            )
        self.assertIn("accBINARY2", self._list_path.read_text(encoding="utf-8"))

    def test_specs_are_registered_for_both_ribbon_paths(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        apply_spec = get_registry().get("saip.apply_universal_tokens")
        self.assertIsNotNone(apply_spec)
        # The Variables panel is the surface for applying, binding and
        # exporting lists; none of the three is a ribbon button any more.
        self.assertNotIn("saip-ribbon-active-session-form", apply_spec.tags)
        self.assertEqual({field.name for field in apply_spec.inputs}, {"session_id", "path", "overwrite"})
        editor_spec = get_registry().get("saip.universal_tokens")
        self.assertIsNotNone(editor_spec)
        self.assertIn("saip-ribbon-tokens-form", editor_spec.tags)
        self.assertEqual(
            {field.name for field in editor_spec.inputs},
            {"list", "path", "contents", "save", "save_as", "delete"},
        )
        bind_spec = get_registry().get("saip.set_test_value_list")
        self.assertEqual({field.name for field in bind_spec.inputs}, {"session_id", "list", "apply"})
        export_spec = get_registry().get("saip.export_test_value_list")
        self.assertEqual(
            {field.name for field in export_spec.inputs},
            {"session_id", "list", "overwrite", "bind", "style"},
        )
        for spec in (bind_spec, export_spec):
            self.assertNotIn("saip-ribbon-active-session-form", spec.tags)


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class UniversalTokenSecretNameTests(unittest.TestCase):
    """PIN placeholders sit inside a longer value (``[pin1TEXT4utf8]FFFFFFFF``)
    and carry a secret-classified name. A universal test value is shared
    operator data and must show; a typed value stays hidden."""

    _PIN_VALUE_HEX = "31323334FFFFFFFF"

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_universal_pin_"))
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self.assertEqual(reference.count(self._PIN_VALUE_HEX), 2)
        template = self._tmpdir / "pins.hex"
        template.write_text(
            reference.replace(self._PIN_VALUE_HEX, "{pin1TEXT4utf8}FFFFFFFF"),
            encoding="utf-8",
        )
        self._list_path = self._tmpdir / "universal.csv"
        self._list_path.write_text("pin1TEXT4utf8,31323334\n", encoding="utf-8")
        opened = saip_actions._dispatch_open_package(ctx=None, path=str(template))
        self._sid = opened["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _row(self, name: str) -> dict:
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=self._sid)
        for row in listing["variables"]:
            if str(row.get("name") or "").casefold() == name.casefold():
                return row
        raise AssertionError(f"variable {name!r} not listed")

    def _ranges(self) -> list:
        handle = self._manager.get(self._sid).handle
        records = handle["inline_placeholder_records"]
        self.assertEqual(len(records), 2)
        image = b"".join(bytes.fromhex(record.sentinel_hex) + b"\xff" * 4 for record in records)
        return self._actions._inline_placeholder_ranges(handle, image)

    def test_universal_value_shows_despite_the_secret_name(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        result = get_registry().get("saip.apply_universal_tokens").dispatcher(
            None, session_id=self._sid, path=str(self._list_path)
        )
        self.assertEqual(result["applied_count"], 2)
        self.assertEqual(result["inline_template"]["stored_values"], {"pin1": "31323334"})

        row = self._row("pin1")
        self.assertTrue(row["secret"])
        self.assertTrue(row["universal"])
        self.assertFalse(row["masked"])
        self.assertEqual(row["value"], "31323334")

        ranges = self._ranges()
        self.assertEqual([entry["source"] for entry in ranges], ["universal", "universal"])
        self.assertEqual(ranges[0]["stored_value"], "31323334")
        self.assertEqual(ranges[0]["value_hex"], "31323334")

    def test_typed_value_for_a_secret_name_shows_in_full(self) -> None:
        """The classification stays on the row; the value is not masked."""
        self._actions._dispatch_set_variable(
            ctx=None, session_id=self._sid, name="pin1", value="5678"
        )

        row = self._row("pin1")
        self.assertTrue(row["secret"])
        self.assertFalse(row["masked"])
        self.assertEqual(row["value"], "5678")
        state = self._actions._inline_template_state(self._manager.get(self._sid).handle)
        self.assertEqual(state["stored_values"], {"pin1": "5678"})
        ranges = self._ranges()
        self.assertEqual(ranges[0]["source"], "typed")
        self.assertEqual(ranges[0]["stored_value"], "5678")
        self.assertEqual(ranges[0]["value_hex"], "35363738")

    def test_typed_value_for_a_plain_name_hands_the_pane_its_bytes(self) -> None:
        handle = self._manager.get(self._sid).handle
        # Relabel the occurrences as a non-secret variable to exercise the
        # typed-value encoding path the hex pane relies on.
        from Tools.ProfilePackage.saip_hex_template import InlinePlaceholderRecord

        handle["inline_placeholder_records"] = [
            InlinePlaceholderRecord(
                index=record.index,
                literal=record.literal,
                variable_name="label1",
                type_name=record.type_name,
                byte_length=record.byte_length,
                modifier=record.modifier,
                sentinel_hex=record.sentinel_hex,
            )
            for record in handle["inline_placeholder_records"]
        ]
        handle["inline_variable_names"] = {"label1"}
        self._actions._dispatch_set_variable(
            ctx=None, session_id=self._sid, name="label1", value="9876"
        )

        ranges = self._ranges()
        self.assertEqual(ranges[0]["source"], "typed")
        self.assertEqual(ranges[0]["stored_value"], "9876")
        self.assertEqual(ranges[0]["value_hex"], "39383736")


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class UniversalTokenGenericFileViewTests(unittest.TestCase):
    """A placeholder inside a generic-file-management file has no pySim body;
    the file view must still locate it and hand the workbench an image."""

    _EF_AD_BODY_HEX = "00000002"

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_universal_gfm_"))
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8").strip().upper()
        if reference.count(self._EF_AD_BODY_HEX) != 1:
            self.skipTest("reference profile no longer carries a unique EF.AD body")
        template = self._tmpdir / "gfm.hex"
        template.write_text(reference.replace(self._EF_AD_BODY_HEX, "{riRI4}"), encoding="utf-8")
        self._list_path = self._tmpdir / "universal.csv"
        self._list_path.write_text("riRI4,F0FF0000\n", encoding="utf-8")
        self._sid = saip_actions._dispatch_open_package(ctx=None, path=str(template))["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._sid)
        except Exception:
            pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _ef_ad_view(self) -> dict:
        rows = self._actions._dispatch_list_files(ctx=None, session_id=self._sid)["rows"]
        row = next(r for r in rows if str(r.get("file_id") or "").upper() == "6FAD"
                   and str(r.get("section_key") or "").lower().startswith("genericfilemanagement"))
        return self._actions._dispatch_show_file(
            ctx=None, session_id=self._sid,
            section_key=row["section_key"], field_path=row["field_path"],
        )

    def test_file_view_locates_the_placeholder_without_a_pysim_body(self) -> None:
        view = self._ef_ad_view()
        handle = self._manager.get(self._sid).handle
        sentinel = next(r for r in handle["inline_placeholder_records"] if r.variable_name == "ri").sentinel_hex

        self.assertEqual(view["body_hex"], sentinel.upper())
        self.assertEqual([p["literal"] for p in view["inline_placeholders"]], ["{riRI4}"])
        self.assertEqual((view["inline_placeholders"][0]["start"], view["inline_placeholders"][0]["end"]), (0, 4))
        self.assertFalse(view["inline_placeholders"][0]["resolved"])
        self.assertEqual(view["decoded"]["format"], "Inline template placeholder")

    def test_universal_value_reaches_the_file_view(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        get_registry().get("saip.apply_universal_tokens").dispatcher(
            None, session_id=self._sid, path=str(self._list_path)
        )

        entry = self._ef_ad_view()["inline_placeholders"][0]
        self.assertEqual(entry["source"], "universal")
        self.assertEqual(entry["value_hex"], "F0FF0000")


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class UniversalDefaultsOnOpenTests(unittest.TestCase):
    """An opened template takes the universal list's bytes for every
    occurrence without a stored value; stored values win; the flag turns
    the seeding off."""

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_universal_defaults_"))
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self._template = self._tmpdir / "template.hex"
        self._template.write_text(
            reference.replace(_HEADER_ICCID_HEX, "{iccidICCID10}"), encoding="utf-8"
        )
        self._list_path = self._tmpdir / "universal.csv"
        self._list_path.write_text(f"iccidICCID10,{_TEST_ICCID_HEX}\n", encoding="utf-8")
        self._sids: list[str] = []

    def tearDown(self) -> None:
        for sid in self._sids:
            try:
                self._manager.release(sid)
            except Exception:
                pass
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _open(self, env: dict) -> str:
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, env):
            result = self._actions._dispatch_open_package(ctx=None, path=str(self._template))
        self._sids.append(result["session_id"])
        return result["session_id"]

    def _row(self, sid: str, name: str) -> dict:
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        return next(r for r in listing["variables"] if str(r.get("name") or "").casefold() == name)

    def test_open_seeds_the_universal_value(self) -> None:
        sid = self._open({"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self._list_path)})

        row = self._row(sid, "iccid")
        self.assertEqual(row["status"], "BOUND_INLINE_RESOLVED")
        self.assertTrue(row["universal"])
        self.assertEqual(row["value"], _TEST_ICCID_HEX)
        # Nothing was edited: the session opens clean.
        self.assertEqual(self._manager.get(sid).handle.get("dirty_pes") or set(), set())

    def test_flag_turns_the_seeding_off(self) -> None:
        sid = self._open({
            "YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self._list_path),
            "YGGDRASIM_SAIP_UNIVERSAL_DEFAULTS": "0",
        })

        self.assertEqual(self._row(sid, "iccid")["status"], "BOUND_INLINE_UNRESOLVED")

    def test_stored_values_win_over_the_list(self) -> None:
        from Tools.ProfilePackage.saip_variable_materialization import write_inline_variable_sidecar

        write_inline_variable_sidecar(
            self._template.with_suffix(".variables.json"),
            {"iccid": "8988201234567890123"},
            created_from=self._template.name,
        )
        sid = self._open({"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self._list_path)})

        row = self._row(sid, "iccid")
        self.assertFalse(row["universal"])
        self.assertEqual(row["value"], "8988201234567890123")

    def test_rejected_list_lines_become_a_load_warning(self) -> None:
        self._list_path.write_text("iccidICCID10,8988201234567890123\n", encoding="utf-8")
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self._list_path)}):
            result = self._actions._dispatch_open_package(ctx=None, path=str(self._template))
        self._sids.append(result["session_id"])

        warnings = [w for w in result.get("load_warnings") or [] if w.get("stage") == "universal-tokens"]
        self.assertEqual(len(warnings), 1)
        self.assertIn("1 line(s) rejected", warnings[0]["error"])
        self.assertEqual(self._row(result["session_id"], "iccid")["status"], "BOUND_INLINE_UNRESOLVED")


class UniversalTokenEditorFormTests(unittest.TestCase):
    """The editor form shares the Tokens ribbon tag with the plugin's
    token-configuration manager but none of its inputs. The frontend reads
    the list when the form opens (the catalogue default is fixed at server
    start) and refreshes the box after a save."""

    def test_editor_spec_carries_none_of_the_manager_inputs(self) -> None:
        from yggdrasim_common.gui_server.actions.registry import (
            ensure_builtin_actions_loaded,
        )

        editor = ensure_builtin_actions_loaded().get("saip.universal_tokens")
        self.assertIn("saip-ribbon-tokens-form", editor.tags)
        names = {field.name for field in editor.inputs}
        self.assertTrue(_MANAGER_INPUT_NAMES.isdisjoint(names), names)

    def test_frontend_reads_the_list_on_open_and_after_save(self) -> None:
        source = _COMMAND_CENTER_SOURCE.read_text(encoding="utf-8")
        served = _SERVED_BUNDLE.read_text(encoding="utf-8")
        block_start = '  var CC_SAIP_UNIVERSAL_TOKENS_ACTION_ID = "saip.universal_tokens";'
        block_end = "\n  function ccCompactHexText("
        source_block = _js_between(source, block_start, block_end)
        self.assertEqual(source_block, _js_between(served, block_start, block_end))
        self.assertIn('ccActionHasInput(action, "contents")', source_block)
        self.assertIn('var CC_SAIP_TOKEN_LIST_BROWSE = "__browse__";', source_block)
        self.assertIn("function ccTokenListSelect(form)", source_block)
        self.assertIn("function ccPopulateTokenListSelect(", source_block)
        self.assertIn("function ccReadTokenList(", source_block)
        self.assertIn("function ccInitializeUniversalTokensEditor(", source_block)
        self.assertIn('inputs.list = String(selector || "universal")', source_block)
        self.assertIn("inputs.path = pathText", source_block)
        self.assertIn("body: JSON.stringify({ inputs: inputs })", source_block)
        self.assertIn("ccApplyUniversalTokensContents(action, form, response.data || {})", source_block)
        self.assertIn("runBtn.disabled = previousRunDisabled", source_block)
        self.assertIn('form.dataset.saipTokenListDirty = "true"', source_block)
        self.assertIn('window.confirm("Discard the unsaved edits in the list contents?")', source_block)
        self.assertIn('"Other file\\u2026"', source_block)
        dispatch = source_block[
            source_block.index("  function ccInitializeSaipTokenConfigurationForm(") :
        ]
        self.assertIn("if (ccIsSaipUniversalTokensEditor(action)) {", dispatch)
        self.assertIn("if (ccIsSaipTokenConfigurationManager(action)) {", dispatch)
        for body in (source, served):
            enhancement = _js_between(
                body,
                "  function ccEnhanceActionForm(action, form)",
                "\n  function ccEnhanceAsn1TlvDecodeForm(form)",
            )
            self.assertIn("if (ccIsSaipUniversalTokensEditor(action)) {", enhancement)
            self.assertIn("listInput.rows = Math.max(Number(listInput.rows || 0), 22)", enhancement)
            run = _js_between(
                body,
                "  async function runActionFromForm(action, form, statusEl, resultEl)",
                "\n  function renderErrorBlock(message)",
            )
            self.assertIn("resp.data.saved === true || resp.data.deleted === true", run)
            self.assertIn("{ list: resp.data.list, lists: resp.data.lists }", run)

    def test_token_editor_binds_exports_and_opens_the_lists(self) -> None:
        source = _WORKBENCH_SOURCE.read_text(encoding="utf-8")
        served = _SERVED_BUNDLE.read_text(encoding="utf-8")
        block_start = "  function saipBoundTestValueList(pkg) {"
        block_end = "\n  async function saipApplyUniversalTokens("
        source_block = _js_between(source, block_start, block_end)
        self.assertEqual(source_block, _js_between(served, block_start, block_end))
        for fragment in (
            "function saipBuildTestValueListControls(",
            'select.className = "saip-token-list-select"',
            "pathPicker.pickFile(",
            'applyBtn.className = "btn btn-small saip-token-apply-universal"',
            'applyBtn.textContent = "Apply test values"',
            'exportBtn.textContent = "Export list\\u2026"',
            'editBtn.textContent = "Edit lists\\u2026"',
            "/api/actions/saip.set_test_value_list/run",
            "/api/actions/saip.export_test_value_list/run",
            "bind: !!result.values.bind",
            '_ccBuildActionPopout(action, { list: String(bound.selector || "universal") })',
        ):
            self.assertIn(fragment, source_block)
        for body in (source, served):
            self.assertIn(
                "saipBuildTestValueListControls(pkg, vars, drawer, peList, detail, validation)",
                body,
            )
            self.assertIn('" \u00b7 test-value list: " + String(boundList.name || "Universal")', body)
            self.assertIn('sourceChip.textContent = universal ? "test value" : "stored";', body)
            self.assertNotIn('universalBtn.textContent = "Apply universal values"', body)


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class TestValueListBindingTests(unittest.TestCase):
    """A profile binds a library list on top of the universal one.

    The bound list answers first; the binding survives undo, a template
    save (sidecar and tagged JSON) and, through the machine-local store,
    a reopen of a template that was never saved."""

    _OTHER_ICCID_HEX = "8988209876543210987F"

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import get_manager

        self._actions = saip_actions
        self._manager = get_manager()
        self._tmpdir = Path(tempfile.mkdtemp(prefix="ygg_bind_"))
        self._env = mock.patch.dict(
            os.environ,
            {
                "YGGDRASIM_RUNTIME_ROOT": str(self._tmpdir / "runtime"),
                "YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self._tmpdir / "universal.csv"),
                "YGGDRASIM_SAIP_TOKEN_LISTS": str(self._tmpdir / "lib"),
            },
        )
        self._env.start()
        os.environ.pop("YGGDRASIM_SAIP_UNIVERSAL_DEFAULTS", None)
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self._template = self._tmpdir / "template.hex"
        self._template.write_text(
            reference.replace(_HEADER_ICCID_HEX, "{iccidICCID10}"), encoding="utf-8"
        )
        (self._tmpdir / "universal.csv").write_text(
            f"iccidICCID10,{_TEST_ICCID_HEX}\n", encoding="utf-8"
        )
        self._sids: list[str] = []

    def tearDown(self) -> None:
        for sid in self._sids:
            try:
                self._manager.release(sid)
            except Exception:
                pass
        self._env.stop()
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def _open(self, path: Path | None = None) -> dict:
        result = self._actions._dispatch_open_package(ctx=None, path=str(path or self._template))
        self._sids.append(result["session_id"])
        return result

    def _value(self, sid: str) -> str:
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        for row in listing["variables"]:
            if str(row.get("name") or "").casefold() == "iccid":
                return str(row["value"])
        raise AssertionError(listing["variables"])

    def _bound(self, sid: str) -> dict:
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        return listing["inline_template"]["test_value_list"]

    def _bind(self, sid: str, selector: str) -> dict:
        from yggdrasim_common.gui_server.actions.registry import get_registry

        spec = get_registry().get("saip.set_test_value_list")
        return spec.dispatcher(None, session_id=sid, list=selector)

    def _make_library_list(self) -> None:
        result = self._actions._dispatch_universal_tokens(
            ctx=None, contents=f"iccidICCID10,{self._OTHER_ICCID_HEX}\n", save_as="opA"
        )
        self.assertTrue(result["saved"])
        self.assertEqual(result["list"]["kind"], "library")
        self.assertEqual([row["name"] for row in result["lists"]], ["Universal", "opA"])

    def test_bound_list_answers_before_the_universal_one_and_undo_restores(self) -> None:
        opened = self._open()
        sid = opened["session_id"]
        self.assertEqual(self._value(sid), _TEST_ICCID_HEX)
        self.assertEqual(opened["inline_template"]["test_value_list"]["name"], "Universal")
        self._make_library_list()

        bound = self._bind(sid, "opA")
        self.assertEqual(bound["applied_count"], 1)
        self.assertEqual(self._value(sid), self._OTHER_ICCID_HEX)
        self.assertEqual(self._bound(sid)["selector"], "opA")
        listing = self._actions._dispatch_list_variables(ctx=None, session_id=sid)
        self.assertEqual([row["name"] for row in listing["test_value_lists"]], ["Universal", "opA"])

        self._actions._dispatch_undo(ctx=None, session_id=sid)
        self.assertEqual(self._value(sid), _TEST_ICCID_HEX)
        self.assertEqual(self._bound(sid)["name"], "Universal")
        self._actions._dispatch_redo(ctx=None, session_id=sid)
        self.assertEqual(self._value(sid), self._OTHER_ICCID_HEX)
        self.assertEqual(self._bound(sid)["selector"], "opA")

        back = self._bind(sid, "universal")
        self.assertEqual(back["previous_list"], "opA")
        self.assertEqual(self._value(sid), _TEST_ICCID_HEX)
        with self.assertRaises(ValueError):
            self._bind(sid, "nothere")

    def test_binding_travels_with_the_template_and_the_store_covers_the_rest(self) -> None:
        sid = self._open()["session_id"]
        self._make_library_list()
        self._bind(sid, "opA")

        self._actions._dispatch_save_package(
            ctx=None,
            session_id=sid,
            output_path=str(self._tmpdir / "t.varder"),
            format="varder",
            resolve_variables=False,
        )
        sidecar = json.loads((self._tmpdir / "t.variables.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar["test_value_list"], "opA")
        reopened = self._open(self._tmpdir / "t.varder")
        self.assertEqual(reopened["inline_template"]["test_value_list"]["selector"], "opA")
        self.assertEqual(self._value(reopened["session_id"]), self._OTHER_ICCID_HEX)

        self._actions._dispatch_save_package(
            ctx=None,
            session_id=sid,
            output_path=str(self._tmpdir / "t.json"),
            format="json",
            resolve_variables=False,
        )
        block = json.loads((self._tmpdir / "t.json").read_text(encoding="utf-8"))
        self.assertEqual(block["__ygg_inline_placeholders__"]["test_value_list"], "opA")
        from_json = self._open(self._tmpdir / "t.json")
        self.assertEqual(from_json["inline_template"]["test_value_list"]["selector"], "opA")

        # The hex template itself was never saved: the store remembers it.
        store_path = self._tmpdir / "runtime" / "state" / "saip_test_value_lists.json"
        store = json.loads(store_path.read_text(encoding="utf-8"))
        self.assertEqual(store["bindings"][str(self._template.resolve())]["list"], "opA")
        again = self._open()
        self.assertEqual(again["inline_template"]["test_value_list"]["selector"], "opA")
        self.assertEqual(self._value(again["session_id"]), self._OTHER_ICCID_HEX)
        self._bind(again["session_id"], "universal")
        store = json.loads(store_path.read_text(encoding="utf-8"))
        self.assertNotIn(str(self._template.resolve()), store["bindings"])

    def test_missing_bound_list_is_reported_and_the_universal_list_answers(self) -> None:
        sid = self._open()["session_id"]
        self._make_library_list()
        self._bind(sid, "opA")
        deleted = self._actions._dispatch_universal_tokens(ctx=None, list="opA", delete=True)
        self.assertTrue(deleted["deleted"])
        self.assertEqual([row["name"] for row in deleted["lists"]], ["Universal"])

        again = self._open()
        self.assertTrue(
            any("opA not found" in str(w.get("error")) for w in again["load_warnings"]),
            again["load_warnings"],
        )
        self.assertFalse(again["inline_template"]["test_value_list"]["exists"])
        self.assertEqual(self._value(again["session_id"]), _TEST_ICCID_HEX)

    def test_export_writes_wire_bytes_with_secrets_and_can_bind(self) -> None:
        sid = self._open()["session_id"]
        self._actions._dispatch_set_variable(
            ctx=None, session_id=sid, name="iccid", value="8988201234567890123"
        )
        exported = self._actions._dispatch_export_test_value_list(
            ctx=None, session_id=sid, list="mine", bind=True
        )
        self.assertEqual(exported["entry_count"], 1)
        self.assertEqual(exported["list"]["kind"], "library")
        written = (self._tmpdir / "lib" / "mine.csv").read_text(encoding="utf-8")
        # A new list is written in the typed spelling.
        self.assertIn("{iccid:ICCID:10},8988201234567890123F", written)
        self.assertTrue(written.startswith("# test values exported from template.hex"))
        self.assertEqual(self._bound(sid)["selector"], "mine")
        with self.assertRaises(ValueError):
            self._actions._dispatch_export_test_value_list(ctx=None, session_id=sid, list="mine")
        with self.assertRaises(ValueError):
            self._actions._dispatch_export_test_value_list(
                ctx=None, session_id=sid, list="universal"
            )
        to_file = self._actions._dispatch_export_test_value_list(
            ctx=None, session_id=sid, list=str(self._tmpdir / "out" / "values.csv")
        )
        self.assertEqual(to_file["list"]["kind"], "path")
        self.assertTrue((self._tmpdir / "out" / "values.csv").is_file())

    def test_export_writes_typed_unless_the_destination_has_a_style(self) -> None:
        sid = self._open()["session_id"]
        typed = self._actions._dispatch_export_test_value_list(
            ctx=None, session_id=sid, list="typed-list", style="typed"
        )
        self.assertEqual(typed["style"], "typed")
        written = (self._tmpdir / "lib" / "typed-list.csv").read_text(encoding="utf-8")
        self.assertIn("# style: typed\n", written)
        self.assertIn(f"{{iccid:ICCID:10}},{_TEST_ICCID_HEX}", written)
        # A new list takes the typed spelling, the only one the tool chooses,
        # whatever the (compact, undeclared) universal list of this fixture uses.
        fresh = self._actions._dispatch_export_test_value_list(
            ctx=None, session_id=sid, list="fresh-list"
        )
        self.assertEqual(fresh["style"], "typed")
        self.assertIn(
            f"{{iccid:ICCID:10}},{_TEST_ICCID_HEX}",
            (self._tmpdir / "lib" / "fresh-list.csv").read_text(encoding="utf-8"),
        )
        # "universal" names the universal list's spelling on purpose.
        followed = self._actions._dispatch_export_test_value_list(
            ctx=None, session_id=sid, list="follow-list", style="universal"
        )
        self.assertEqual(followed["style"], "compact")
        self.assertIn(
            f"iccidICCID10,{_TEST_ICCID_HEX}",
            (self._tmpdir / "lib" / "follow-list.csv").read_text(encoding="utf-8"),
        )
        # An existing list keeps its own spelling.
        saved = self._actions._dispatch_universal_tokens(
            ctx=None, contents=f"iccidICCID10,{self._OTHER_ICCID_HEX}\n", save_as="opA"
        )
        self.assertTrue(saved["saved"])
        kept = self._actions._dispatch_export_test_value_list(
            ctx=None, session_id=sid, list="opA", overwrite=True
        )
        self.assertEqual(kept["style"], "compact")
        self.assertIn(
            f"iccidICCID10,{_TEST_ICCID_HEX}",
            (self._tmpdir / "lib" / "opA.csv").read_text(encoding="utf-8"),
        )

    def test_editor_action_reads_saves_and_refuses_the_wrong_targets(self) -> None:
        view = self._actions._dispatch_universal_tokens(ctx=None)
        self.assertEqual(view["list"]["name"], "Universal")
        self.assertEqual(view["contents"], f"iccidICCID10,{_TEST_ICCID_HEX}\n")
        self.assertEqual([row["name"] for row in view["lists"]], ["Universal"])
        self.assertEqual(view["lists"][0]["entry_count"], 1)

        self._make_library_list()
        with self.assertRaises(ValueError):
            self._actions._dispatch_universal_tokens(
                ctx=None, contents="accBINARY2,0040\n", save_as="opA"
            )
        with self.assertRaises(ValueError):
            self._actions._dispatch_universal_tokens(ctx=None, delete=True)
        with self.assertRaises(ValueError):
            self._actions._dispatch_universal_tokens(ctx=None, list="bad name!")
        updated = self._actions._dispatch_universal_tokens(
            ctx=None, list="opA", contents="accBINARY2,0040\n", save=True
        )
        self.assertTrue(updated["saved"])
        self.assertEqual(updated["entry_count"], 1)
        self.assertEqual(
            (self._tmpdir / "lib" / "opA.csv").read_text(encoding="utf-8"), "accBINARY2,0040\n"
        )
        other = self._actions._dispatch_universal_tokens(
            ctx=None, path=str(self._tmpdir / "elsewhere.csv"), contents="accBINARY2,0041\n", save=True
        )
        self.assertEqual(other["list"]["kind"], "path")
        self.assertEqual(other["lists"][-1]["path"], str(self._tmpdir / "elsewhere.csv"))
