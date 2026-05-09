import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import pytest
from textual.app import App

from Tools.ProfilePackage import saip_tui_lint as saip_tui_lint_module
from Tools.ProfilePackage.saip_json_codec import (
    build_decoded_document_from_sequence,
    encode_der_from_document,
    ensure_workspace_pysim_on_path,
    humanize_saip_display_name,
)
from Tools.ProfilePackage.saip_pe_quick_add import insert_blank_pe_for_menu_id
from Tools.ProfilePackage.saip_tool import SaipToolBridge
from Tools.ProfilePackage.saip_transcode_tui import run_saip_transcode_tui


# The full Textual TUI suite boots a live app per test (~5-7 s/each on a
# modest workstation). Individual cases are fast enough to debug ad-hoc
# with ``pytest -k <name>``, but running all 40+ tests back-to-back
# exceeds the 90 s pytest-timeout cap. Mark the module ``slow`` so the
# default ``pytest`` run skips it; release validation runs ``pytest
# --runslow tests/test_saip_transcode_tui.py`` instead (see conftest.py).
pytestmark = pytest.mark.slow


class SaipTranscodeTuiInteractionTests(unittest.TestCase):
    def _build_app(
        self,
        input_path: str = "Tools/ProfilePackage/profile/reference_test_profile.txt",
    ) -> App:
        captured: dict[str, App] = {}
        original_run = App.run

        def fake_run(app_self: App, *args: object, **kwargs: object) -> None:
            del args
            del kwargs
            captured["app"] = app_self

        App.run = fake_run
        try:
            workspace_root = Path(__file__).resolve().parents[1]
            bridge = SaipToolBridge(workspace_root)
            bridge.set_input_file(input_path)
            run_saip_transcode_tui(bridge)
        finally:
            App.run = original_run

        self.assertIn("app", captured)
        return captured["app"]

    def _write_minimal_generic_gfm_profile(self, target_path: Path) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(workspace_root)
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        document = build_decoded_document_from_sequence(
            pes,
            intro_lines=["Minimal MF + GFM profile for TUI interaction tests"],
        )
        document = insert_blank_pe_for_menu_id(
            document,
            workspace_root,
            menu_id="mf",
        )
        document = insert_blank_pe_for_menu_id(
            document,
            workspace_root,
            menu_id="genericFileManagement",
        )
        raw_der = encode_der_from_document(document, workspace_root)
        target_path.write_text(raw_der.hex().upper() + "\n", encoding="utf-8")

    def _write_minimal_opt_usim_profile(self, target_path: Path) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(workspace_root)
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        document = build_decoded_document_from_sequence(
            pes,
            intro_lines=["Minimal MF + USIM optional profile for TUI interaction tests"],
        )
        for menu_id in ("mf", "usim", "opt-usim"):
            document = insert_blank_pe_for_menu_id(
                document,
                workspace_root,
                menu_id=menu_id,
            )
        raw_der = encode_der_from_document(document, workspace_root)
        target_path.write_text(raw_der.hex().upper() + "\n", encoding="utf-8")

    def _write_minimal_usim_service_table_profile(self, target_path: Path) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        ensure_workspace_pysim_on_path(workspace_root)
        from pySim.esim.saip import (
            ProfileElementEnd,
            ProfileElementHeader,
            ProfileElementSequence,
        )

        pes = ProfileElementSequence()
        pes.append(ProfileElementHeader())
        pes.append(ProfileElementEnd())
        document = build_decoded_document_from_sequence(
            pes,
            intro_lines=["Minimal MF + USIM service table profile for TUI interaction tests"],
        )
        for menu_id in ("mf", "usim"):
            document = insert_blank_pe_for_menu_id(
                document,
                workspace_root,
                menu_id=menu_id,
            )
        document["sections"]["usim"]["ef-ust"].append(
            ("fillFileContent", bytes.fromhex("0200000000000000000000000000000000"))
        )
        raw_der = encode_der_from_document(document, workspace_root)
        target_path.write_text(raw_der.hex().upper() + "\n", encoding="utf-8")

    def _find_hex_by_label(self, node: object, expected_label: str) -> str | None:
        if isinstance(node, dict):
            label = str(node.get("label", "") or "").strip()
            if label == expected_label and "hex" in node:
                return str(node.get("hex", "") or "")
            for value in node.values():
                found = self._find_hex_by_label(value, expected_label)
                if found is not None:
                    return found
            return None
        if isinstance(node, list):
            for item in node:
                found = self._find_hex_by_label(item, expected_label)
                if found is not None:
                    return found
        return None

    def test_adf_bootstrap_defaults_remember_last_values_per_root_kind(self) -> None:
        app = self._build_app()

        usim_defaults = {
            "root_kind": "adf-usim",
            "root_name": "ADF.USIM",
            "temporary_fid": "7FF0",
            "df_name": "A0000000871002FF86FF0289060100FF",
            "aid_prefix": "A0000000871002",
        }
        merged_usim_defaults = app._adf_bootstrap_defaults_for_picker(usim_defaults)
        self.assertEqual(merged_usim_defaults["temporary_fid"], "7FF0")

        app._remember_adf_bootstrap_values(
            "adf-usim",
            {
                "temporary_fid": "7FF1",
                "df_name": "A0000000871002FF1122334455667788",
            },
        )
        merged_usim_defaults = app._adf_bootstrap_defaults_for_picker(usim_defaults)
        self.assertEqual(merged_usim_defaults["temporary_fid"], "7FF1")
        self.assertEqual(
            merged_usim_defaults["df_name"],
            "A0000000871002FF1122334455667788",
        )

        isim_defaults = {
            "root_kind": "adf-isim",
            "root_name": "ADF.ISIM",
            "temporary_fid": "7FF2",
            "df_name": "A0000000871004FF34FF0789312E30FF",
            "aid_prefix": "A0000000871004",
        }
        merged_isim_defaults = app._adf_bootstrap_defaults_for_picker(isim_defaults)
        self.assertEqual(merged_isim_defaults["temporary_fid"], "7FF2")
        self.assertEqual(
            merged_isim_defaults["df_name"],
            "A0000000871004FF34FF0789312E30FF",
        )

    def test_der_single_click_does_not_hijack_json_editor(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                editor = app.query_one("#json_editor")
                await pilot.click("#der_view", offset=(10, 1))
                await pilot.pause()

                self.assertTrue(editor.selection.is_empty)

                await pilot.click("#json_editor", offset=(10, 5))
                await pilot.pause()

                self.assertTrue(editor.selection.is_empty)
                self.assertEqual(getattr(app.focused, "id", None), "json_editor")

        asyncio.run(scenario())

    def test_der_double_click_jumps_to_json_selection(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                editor = app.query_one("#json_editor")
                await pilot.double_click("#der_view", offset=(10, 1))
                await pilot.pause()

                self.assertFalse(editor.selection.is_empty)
                self.assertIn('"major-version"', editor.selected_text)
                self.assertEqual(getattr(app.focused, "id", None), "json_editor")

        asyncio.run(scenario())

    def test_invalid_profile_raises_clean_asn1_error(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            invalid_profile = Path(temp_dir) / "invalid_profile.der"
            invalid_profile.write_bytes(b"\xDE\xAD\xBE\xEF")

            bridge = SaipToolBridge(workspace_root)
            bridge.set_input_file(str(invalid_profile))

            with self.assertRaisesRegex(ValueError, "Profile ASN1 is not valid\\."):
                run_saip_transcode_tui(bridge)

    def test_save_refresh_writes_json_der_and_plain_hex_txt(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        source_profile = (
            workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        )
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "save_profile.txt"
            custom_profile.write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")

            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    app.action_save_refresh()
                    await pilot.pause()

                    self.assertTrue(json_path.exists())
                    self.assertTrue(der_path.exists())
                    self.assertTrue(txt_path.exists())
                    self.assertEqual(
                        txt_path.read_text(encoding="utf-8"),
                        der_path.read_bytes().hex().upper() + "\n",
                    )

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_lint_does_not_run_live_on_editor_changes(self) -> None:
        async def scenario() -> None:
            with mock.patch.object(
                saip_tui_lint_module,
                "lint_profile_json_buffer",
                wraps=saip_tui_lint_module.lint_profile_json_buffer,
            ) as mocked_lint:
                app = self._build_app()
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    await pilot.pause(0.7)

                    self.assertEqual(mocked_lint.call_count, 0)
                    self.assertTrue(getattr(app, "_lint_dirty", False))

                    editor.text = editor.text + " "
                    await pilot.pause(0.7)

                    self.assertEqual(mocked_lint.call_count, 0)
                    self.assertTrue(getattr(app, "_lint_dirty", False))

                    app.action_run_lint_now()
                    await pilot.pause(0.4)

                    self.assertEqual(mocked_lint.call_count, 1)
                    self.assertFalse(getattr(app, "_lint_dirty", True))
                    self.assertEqual(getattr(app, "_lint_last_trigger", ""), "manual")

        asyncio.run(scenario())

    def test_save_refresh_updates_lint_cache(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                editor = app.query_one("#json_editor")
                await pilot.pause(0.7)

                editor.text = editor.text + " "
                await pilot.pause(0.7)
                self.assertTrue(getattr(app, "_lint_dirty", False))

                app.action_save_refresh()
                await pilot.pause(0.6)

                self.assertFalse(getattr(app, "_lint_dirty", True))
                self.assertEqual(getattr(app, "_lint_last_trigger", ""), "save")
                self.assertEqual(getattr(app, "_lint_cached_text", None), editor.text)
                self.assertIsNotNone(getattr(app, "_lint_cached_outcome", None))

        asyncio.run(scenario())

    def test_editor_copy_selection_updates_app_clipboard(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            with mock.patch(
                "Tools.ProfilePackage.saip_transcode_tui._copy_text_to_system_clipboard",
                return_value="xclip",
            ) as mocked_copy:
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    editor.focus()
                    await pilot.pause()
                    editor.select_all()
                    await pilot.pause()
                    app.action_copy_text_selection()
                    await pilot.pause()

                    mocked_copy.assert_called_once_with(editor.text)
                    self.assertEqual(app.clipboard, editor.text)

        asyncio.run(scenario())

    def test_editor_paste_uses_system_clipboard_when_available(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            replacement = '{\n  "intro": [],\n  "sections": {}\n}\n'
            with mock.patch(
                "Tools.ProfilePackage.saip_transcode_tui._read_text_from_system_clipboard",
                return_value=(replacement, "xclip"),
            ) as mocked_read:
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    editor.focus()
                    await pilot.pause()
                    editor.select_all()
                    await pilot.pause()
                    app.copy_to_clipboard("internal clipboard text")
                    app.action_paste_text_clipboard()
                    await pilot.pause()

                    mocked_read.assert_called_once()
                    self.assertEqual(editor.text, replacement)

        asyncio.run(scenario())

    def test_pane_actions_toggle_outline_cycle_right_and_hide_bottom_row(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                app._outline_visible = True
                app._pane_modes = dict(app._SLOT_DEFAULTS)
                app._apply_pane_layout()
                await pilot.pause()

                outline = app.query_one("#json_outline")
                right_switcher = app.query_one("#right_switcher")
                bottom_row = app.query_one("#bottom_row")

                self.assertTrue(outline.display)
                self.assertTrue(bottom_row.display)
                self.assertEqual(right_switcher.current, "der_view")

                app.action_toggle_outline_pane()
                await pilot.pause()
                self.assertFalse(outline.display)

                app.action_cycle_right_pane()
                await pilot.pause()
                self.assertEqual(right_switcher.current, "right_inspect_log")

                app.action_cycle_bottom_left_pane()
                app.action_cycle_bottom_left_pane()
                app.action_cycle_bottom_right_pane()
                await pilot.pause()
                self.assertFalse(bottom_row.display)

        asyncio.run(scenario())

    def test_pane_layout_menu_choice_sets_slot_and_resets_defaults(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                app._outline_visible = True
                app._pane_modes = dict(app._SLOT_DEFAULTS)
                app._apply_pane_layout()
                await pilot.pause()

                right_switcher = app.query_one("#right_switcher")
                bottom_row = app.query_one("#bottom_row")
                outline = app.query_one("#json_outline")

                app._on_pane_layout_choice("slot:right:lint")
                await pilot.pause()
                self.assertEqual(app._pane_modes["right"], "lint")
                self.assertEqual(right_switcher.current, "right_lint_log")

                app._on_pane_layout_choice("outline:toggle")
                await pilot.pause()
                self.assertFalse(outline.display)

                app._on_pane_layout_choice("slot:bottom_left:none")
                app._on_pane_layout_choice("slot:bottom_right:none")
                await pilot.pause()
                self.assertFalse(bottom_row.display)

                app._on_pane_layout_choice("reset")
                await pilot.pause()
                self.assertTrue(outline.display)
                self.assertTrue(bottom_row.display)
                self.assertEqual(app._pane_modes, dict(app._SLOT_DEFAULTS))
                self.assertEqual(right_switcher.current, "der_view")

        asyncio.run(scenario())

    def test_pane_layout_menu_can_show_decoded_view_mode(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                right_switcher = app.query_one("#right_switcher")

                app._on_pane_layout_choice("slot:right:decoded")
                await pilot.pause()

                self.assertEqual(app._pane_modes["right"], "decoded")
                self.assertEqual(right_switcher.current, "right_decoded_editor")

        asyncio.run(scenario())

    def test_f1_opens_keybind_help_picker(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                await pilot.press("f1")
                await pilot.pause()

                help_screen = app.screen_stack[-1]
                help_text = help_screen.query_one("#keybind_help_text")
                self.assertIn("Shortcut Reference", help_text.text)
                self.assertIn("Ctrl+T", help_text.text)
                self.assertIn("Ctrl+A", help_text.text)
                self.assertIn("F3", help_text.text)
                self.assertIn("F10", help_text.text)
                self.assertIn("Tree right-click", help_text.text)

        asyncio.run(scenario())

    def test_ctrl_t_opens_tree_action_menu(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                outline = app.query_one("#json_outline")
                outline.root.expand_all()
                await pilot.pause(0.1)

                def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                    if str(getattr(node, "label", "")).startswith(expected_prefix):
                        return node
                    for child in getattr(node, "children", []):
                        try:
                            return first_node_with_label_prefix(child, expected_prefix)
                        except AssertionError:
                            continue
                    raise AssertionError(f"Could not find outline node with prefix: {expected_prefix}")

                phonebook_node = first_node_with_label_prefix(
                    outline.root,
                    humanize_saip_display_name("df-phonebook"),
                )
                outline.focus()
                await pilot.pause(0.1)
                outline.move_cursor_to_line(phonebook_node.line)
                outline.select_node(phonebook_node)
                await pilot.pause(0.1)

                await pilot.press("ctrl+t")
                await pilot.pause()

                context_screen = app.screen_stack[-1]
                context_screen.query_one("#tree_context_opts")

        asyncio.run(scenario())

    def test_ctrl_a_opens_selected_pe_file_picker(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                outline = app.query_one("#json_outline")
                outline.root.expand_all()
                await pilot.pause(0.1)

                def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                    if str(getattr(node, "label", "")).startswith(expected_prefix):
                        return node
                    for child in getattr(node, "children", []):
                        try:
                            return first_node_with_label_prefix(child, expected_prefix)
                        except AssertionError:
                            continue
                    raise AssertionError(f"Could not find outline node with prefix: {expected_prefix}")

                phonebook_node = first_node_with_label_prefix(
                    outline.root,
                    humanize_saip_display_name("df-phonebook"),
                )
                outline.focus()
                await pilot.pause(0.1)
                outline.move_cursor_to_line(phonebook_node.line)
                outline.select_node(phonebook_node)
                await pilot.pause(0.1)

                await pilot.press("ctrl+a")
                await pilot.pause()

                picker_screen = app.screen_stack[-1]
                picker_screen.query_one("#pe_file_opts")

        asyncio.run(scenario())

    def test_ctrl_a_on_non_filesystem_selection_emits_toast(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            toasts: list[tuple[str, str]] = []
            original_notify = type(app).notify

            def capture_notify(
                self,
                message,
                *,
                title="",
                severity="information",
                timeout=None,
                markup=True,
            ):
                toasts.append((str(severity), str(message)))
                return original_notify(
                    self,
                    message,
                    title=title,
                    severity=severity,
                    timeout=timeout,
                    markup=markup,
                )

            type(app).notify = capture_notify
            try:
                async with app.run_test() as pilot:
                    await pilot.pause(0.7)
                    editor = app.query_one("#json_editor")
                    intro_offset = editor.text.index('"intro"')
                    app._jump_editor_to_span(intro_offset, intro_offset)
                    editor.focus()
                    await pilot.pause(0.2)

                    await pilot.press("ctrl+a")
                    await pilot.pause(0.3)
                    self.assertTrue(
                        any(
                            sev == "warning" and "Add file failed" in msg
                            for sev, msg in toasts
                        ),
                        toasts,
                    )
            finally:
                type(app).notify = original_notify

        asyncio.run(scenario())

    def test_inspect_logs_do_not_cap_retained_lines(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                del pilot
                self.assertIsNone(app.query_one("#inspect_log").max_lines)
                self.assertIsNone(app.query_one("#right_inspect_log").max_lines)
                self.assertIsNone(app.query_one("#lint_inspect_log").max_lines)

        asyncio.run(scenario())

    def test_invalid_editor_buffer_marks_error_state_and_reports_cause(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                editor = app.query_one("#json_editor")
                status = app.query_one("#status_line")
                editor.text = (
                    '{\n'
                    '  "intro": [],\n'
                    '  "sections": {\n'
                    '    "header": {\n'
                    '      "blob": {\n'
                    '        "hex": "ABC"\n'
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n"
                )
                await pilot.pause(0.7)

                self.assertTrue(editor.has_class("invalid-buffer"))
                self.assertTrue(status.has_class("error-state"))
                validation_issue = getattr(app, "_validation_issue", None)
                self.assertIsNotNone(validation_issue)
                summary = getattr(validation_issue, "summary", "")
                self.assertIn("sections.header.blob", summary)
                self.assertIn("odd length", summary.lower())

        asyncio.run(scenario())

    def test_generic_file_management_outline_uses_file_names(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                await pilot.pause(0.7)
                outline = app.query_one("#json_outline")
                sections_root = outline.root.children[0]

                def child_with_exact_label(parent: object, expected: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label) == expected:
                            return child
                    raise AssertionError(f"Could not find outline node: {expected}")

                def child_with_label_prefix(parent: object, expected_prefix: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label).startswith(expected_prefix):
                            return child
                    raise AssertionError(
                        f"Could not find outline node prefix: {expected_prefix}"
                    )

                generic = child_with_exact_label(
                    sections_root,
                    f"{humanize_saip_display_name('genericFileManagement')} {{2}}",
                )
                generic_commands = child_with_exact_label(
                    generic,
                    f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                )
                first_group = generic_commands.children[0]
                first_group_label = str(first_group.label)
                self.assertIn("DF.TELECOM", first_group_label)
                self.assertIn("EF.ADN", first_group_label)
                self.assertIn("EF.FDN", first_group_label)
                self.assertIn("EF.SMS", first_group_label)

                first_group_labels = [str(child.label) for child in first_group.children]
                self.assertIn(
                    f"[0] ({humanize_saip_display_name('filePath')}) — DF.TELECOM",
                    first_group_labels,
                )
                # The remaining children are EF entries rendered as
                # "EF.<name> (<hex FID>)"; assert by substring so the
                # outline format may evolve (alias-first vs. FID-first)
                # without dragging this test along.
                self.assertTrue(
                    any("DF.TELECOM" in label for label in first_group_labels)
                )
                self.assertTrue(any("EF.ADN" in label for label in first_group_labels))
                self.assertTrue(any("EF.FDN" in label for label in first_group_labels))
                self.assertTrue(any("EF.SMS" in label for label in first_group_labels))

                pkcs15_generic = child_with_exact_label(
                    sections_root,
                    f"{humanize_saip_display_name('genericFileManagement_4')} {{2}}",
                )
                pkcs15_commands = child_with_exact_label(
                    pkcs15_generic,
                    f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                )
                pkcs15_group = pkcs15_commands.children[0]
                pkcs15_labels = [str(child.label) for child in pkcs15_group.children]
                self.assertTrue(any(label.startswith("EF.PKCS15-ODF") for label in pkcs15_labels))
                pkcs15_file = child_with_label_prefix(pkcs15_group, "EF.PKCS15-ODF")
                pkcs15_file_labels = [str(child.label) for child in pkcs15_file.children]
                self.assertTrue(
                    any(humanize_saip_display_name("createFCP") in label for label in pkcs15_file_labels)
                )
                self.assertTrue(
                    any(
                        humanize_saip_display_name("fillFileContent") in label
                        for label in pkcs15_file_labels
                    )
                )

                generic_gsm = child_with_exact_label(
                    sections_root,
                    f"{humanize_saip_display_name('genericFileManagement_2')} {{2}}",
                )
                generic_gsm_commands = child_with_exact_label(
                    generic_gsm,
                    f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                )
                generic_gsm_group = generic_gsm_commands.children[0]
                generic_gsm_label = str(generic_gsm_group.label)
                self.assertIn("DF.GSM", generic_gsm_label)
                self.assertIn("EF.LI", generic_gsm_label)
                self.assertTrue(
                    any("EF.KC" in str(child.label) for child in generic_gsm_group.children)
                )

                generic_graphics = child_with_exact_label(
                    sections_root,
                    f"{humanize_saip_display_name('genericFileManagement_3')} {{2}}",
                )
                generic_graphics_commands = child_with_exact_label(
                    generic_graphics,
                    f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                )
                generic_graphics_label = str(generic_graphics_commands.children[0].label)
                self.assertIn("ADF.USIM", generic_graphics_label)
                self.assertIn("DF.GRAPHICS", generic_graphics_label)

        asyncio.run(scenario())

    def test_selecting_gfm_file_outline_node_refreshes_inspect_decode(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                await pilot.pause(0.7)
                outline = app.query_one("#json_outline")
                sections_root = outline.root.children[0]

                def child_with_exact_label(parent: object, expected: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label) == expected:
                            return child
                    raise AssertionError(f"Could not find outline node: {expected}")

                def child_with_label_prefix(parent: object, expected_prefix: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label).startswith(expected_prefix):
                            return child
                    raise AssertionError(
                        f"Could not find outline node prefix: {expected_prefix}"
                    )

                pkcs15_generic = child_with_exact_label(
                    sections_root,
                    f"{humanize_saip_display_name('genericFileManagement_4')} {{2}}",
                )
                pkcs15_commands = child_with_exact_label(
                    pkcs15_generic,
                    f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                )
                pkcs15_group = pkcs15_commands.children[0]
                pkcs15_file = child_with_label_prefix(pkcs15_group, "EF.PKCS15-ODF")

                outline.focus()
                outline.select_node(pkcs15_file)
                outline.move_cursor(pkcs15_file, animate=False)
                app._refresh_inspect_panel()
                await pilot.pause(0.2)

                inspect_body = str(getattr(app, "_inspect_cache_body", "") or "")
                self.assertIn(humanize_saip_display_name("fillFileContent"), inspect_body)
                self.assertIn("Field semantics", inspect_body)

        asyncio.run(scenario())

    def test_outline_labels_ef_record_lists_as_records(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                await pilot.pause(0.7)
                outline = app.query_one("#json_outline")
                outline.root.expand_all()
                await pilot.pause(0.1)

                def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                    if str(getattr(node, "label", "")).startswith(expected_prefix):
                        return node
                    for child in getattr(node, "children", []):
                        try:
                            return first_node_with_label_prefix(child, expected_prefix)
                        except AssertionError:
                            continue
                    raise AssertionError(
                        f"Could not find outline node with prefix: {expected_prefix}"
                    )

                ef_arr_node = first_node_with_label_prefix(outline.root, "EF.ARR [")
                descriptor_record = first_node_with_label_prefix(
                    ef_arr_node,
                    "File descriptor",
                )
                content_record = first_node_with_label_prefix(
                    ef_arr_node,
                    "Record 1",
                )

                descriptor_labels = [str(child.label) for child in descriptor_record.children]
                content_labels = [str(child.label) for child in content_record.children]
                self.assertTrue(
                    any(label.startswith("File descriptor [") for label in descriptor_labels)
                )
                self.assertIn("Template defaults", descriptor_labels)
                self.assertTrue(
                    any(
                        label.startswith(f"{humanize_saip_display_name('fillFileContent')} [")
                        for label in content_labels
                    )
                )

        asyncio.run(scenario())

    def test_selecting_template_defaults_outline_child_refreshes_inspect(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                await pilot.pause(0.7)
                outline = app.query_one("#json_outline")
                outline.root.expand_all()
                await pilot.pause(0.1)

                def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                    if str(getattr(node, "label", "")).startswith(expected_prefix):
                        return node
                    for child in getattr(node, "children", []):
                        try:
                            return first_node_with_label_prefix(child, expected_prefix)
                        except AssertionError:
                            continue
                    raise AssertionError(
                        f"Could not find outline node with prefix: {expected_prefix}"
                    )

                def child_with_exact_label(parent: object, expected: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label) == expected:
                            return child
                    raise AssertionError(f"Could not find outline node: {expected}")

                ef_arr_node = first_node_with_label_prefix(outline.root, "EF.ARR [")
                descriptor_record = first_node_with_label_prefix(
                    ef_arr_node,
                    "File descriptor",
                )
                template_defaults_node = child_with_exact_label(
                    descriptor_record,
                    "Template defaults",
                )

                outline.focus()
                await pilot.pause(0.1)
                outline.move_cursor_to_line(template_defaults_node.line)
                outline.select_node(template_defaults_node)
                app._refresh_inspect_panel()
                await pilot.pause(0.2)

                inspect_body = str(getattr(app, "_inspect_cache_body", "") or "")
                self.assertIn("Template defaults", inspect_body)
                self.assertIn("Selected file: EF.ARR", inspect_body)
                self.assertNotIn("Field semantics", inspect_body)

        asyncio.run(scenario())

    def test_selecting_file_descriptor_outline_node_omits_template_defaults(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                await pilot.pause(0.7)
                outline = app.query_one("#json_outline")
                outline.root.expand_all()
                await pilot.pause(0.1)

                def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                    if str(getattr(node, "label", "")).startswith(expected_prefix):
                        return node
                    for child in getattr(node, "children", []):
                        try:
                            return first_node_with_label_prefix(child, expected_prefix)
                        except AssertionError:
                            continue
                    raise AssertionError(
                        f"Could not find outline node with prefix: {expected_prefix}"
                    )

                descriptor_record = first_node_with_label_prefix(
                    outline.root,
                    "File descriptor",
                )

                outline.focus()
                await pilot.pause(0.1)
                outline.move_cursor_to_line(descriptor_record.line)
                outline.select_node(descriptor_record)
                app._refresh_inspect_panel()
                await pilot.pause(0.2)

                inspect_body = str(getattr(app, "_inspect_cache_body", "") or "")
                self.assertIn("Field semantics", inspect_body)
                self.assertNotIn("Template defaults", inspect_body)

        asyncio.run(scenario())

    def test_grouped_gfm_file_jump_preserves_exact_file_slice(self) -> None:
        async def scenario() -> None:
            app = self._build_app()
            async with app.run_test() as pilot:
                editor = app.query_one("#json_editor")
                await pilot.pause(0.7)
                outline = app.query_one("#json_outline")
                sections_root = outline.root.children[0]

                def child_with_exact_label(parent: object, expected: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label) == expected:
                            return child
                    raise AssertionError(f"Could not find outline node: {expected}")

                def child_with_label_prefix(parent: object, expected_prefix: str) -> object:
                    for child in getattr(parent, "children", []):
                        if str(child.label).startswith(expected_prefix):
                            return child
                    raise AssertionError(
                        f"Could not find outline node prefix: {expected_prefix}"
                    )

                pkcs15_generic = child_with_exact_label(
                    sections_root,
                    f"{humanize_saip_display_name('genericFileManagement_4')} {{2}}",
                )
                pkcs15_commands = child_with_exact_label(
                    pkcs15_generic,
                    f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                )
                pkcs15_group = pkcs15_commands.children[0]
                pkcs15_file = child_with_label_prefix(pkcs15_group, "EF.PKCS15-ODF")

                outline.focus()
                outline.select_node(pkcs15_file)
                outline.move_cursor(pkcs15_file, animate=False)
                span = app._outline_data_span(pkcs15_file.data)
                self.assertIsNotNone(span)
                app._jump_editor_to_span(
                    span[0],
                    span[1],
                    preserve_exact_span=app._outline_preserves_exact_span(pkcs15_file.data),
                )
                await pilot.pause()

                self.assertFalse(editor.selection.is_empty)
                self.assertIn('"createFCP"', editor.selected_text)
                self.assertIn('"fillFileContent"', editor.selected_text)
                self.assertNotIn('"filePath"', editor.selected_text)

        asyncio.run(scenario())

    def test_remove_selected_pe_action_updates_document(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        source_profile = (
            workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        )
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "remove_profile.txt"
            custom_profile.write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    target_text = '"genericFileManagement_4"'
                    start = editor.text.index(target_text)
                    app._jump_editor_to_span(start, start + len(target_text))
                    await pilot.pause()

                    app.action_remove_selected_pe()
                    await pilot.pause()

                    self.assertIn(target_text, editor.text)
                    confirm_screen = app.screen_stack[-1]
                    confirm_screen.query_one("#pe_remove_confirm_opts")
                    confirm_screen.dismiss("confirm_remove")
                    await pilot.pause(1.3)

                    self.assertNotIn(target_text, editor.text)
                    self.assertIn('"securityDomain"', editor.text)
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_direct_insert_before_selected_pe_skips_target_picker(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        source_profile = (
            workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        )
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "insert_profile.txt"
            custom_profile.write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    target_text = '"mf"'
                    start = editor.text.index(target_text)
                    app._jump_editor_to_span(start, start + len(target_text))
                    await pilot.pause()

                    app.action_insert_selected_pe_before_direct()
                    await pilot.pause()

                    picker_screen = app.screen_stack[-1]
                    picker_screen.query_one("#pe_opts")
                    picker_screen.dismiss("application")
                    await pilot.pause(1.3)

                    document = json.loads(editor.text)
                    section_keys = list(document["sections"].keys())
                    self.assertEqual(section_keys[:4], ["header", "application", "mf", "pukCodes"])
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_add_selected_pe_file_action_uses_selected_df_context(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        source_profile = (
            workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        )
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "add_file_profile.txt"
            custom_profile.write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    await pilot.pause(0.7)
                    outline = app.query_one("#json_outline")

                    def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                        if str(getattr(node, "label", "")).startswith(expected_prefix):
                            return node
                        for child in getattr(node, "children", []):
                            try:
                                return first_node_with_label_prefix(child, expected_prefix)
                            except AssertionError:
                                continue
                        raise AssertionError(
                            f"Could not find outline node with prefix: {expected_prefix}"
                        )

                    phonebook_node = first_node_with_label_prefix(
                        outline.root,
                        humanize_saip_display_name("df-phonebook"),
                    )
                    phonebook_span = getattr(phonebook_node, "data", None)
                    self.assertIsInstance(phonebook_span, tuple)
                    self.assertEqual(len(phonebook_span), 2)
                    app._jump_editor_to_span(phonebook_span[0], phonebook_span[1])
                    await pilot.pause()

                    app.action_add_selected_pe_file()
                    await pilot.pause()

                    picker_screen = app.screen_stack[-1]
                    picker_screen.query_one("#pe_file_opts")
                    picker_screen.dismiss("ef-aas")
                    await pilot.pause()
                    follow_up_screen = app.screen_stack[-1]
                    if len(list(follow_up_screen.query("#pe_file_override_apply"))) > 0:
                        follow_up_screen.action_submit_form()
                    await pilot.pause(1.3)

                    document = json.loads(editor.text)
                    telecom_section = document["sections"]["telecom"]
                    self.assertIn("ef-aas", telecom_section)
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_right_click_tree_menu_can_add_selected_pe_file(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        source_profile = (
            workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        )
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "add_file_context_menu_profile.txt"
            custom_profile.write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    await pilot.pause(0.7)
                    outline = app.query_one("#json_outline")
                    outline.root.expand_all()
                    await pilot.pause(0.1)

                    def first_node_with_label_prefix(node: object, expected_prefix: str) -> object:
                        if str(getattr(node, "label", "")).startswith(expected_prefix):
                            return node
                        for child in getattr(node, "children", []):
                            try:
                                return first_node_with_label_prefix(child, expected_prefix)
                            except AssertionError:
                                continue
                        raise AssertionError(
                            f"Could not find outline node with prefix: {expected_prefix}"
                        )

                    phonebook_node = first_node_with_label_prefix(
                        outline.root,
                        humanize_saip_display_name("df-phonebook"),
                    )
                    outline.focus()
                    await pilot.pause(0.1)
                    outline.move_cursor_to_line(phonebook_node.line)
                    outline.select_node(phonebook_node)
                    await pilot.pause(0.1)

                    class DummyTreeContextClick:
                        def __init__(self, widget: object) -> None:
                            self.widget = widget
                            self.button = 3

                        def get_content_offset(self, _widget: object) -> object:
                            raise RuntimeError("Use current tree cursor line for context-menu target.")

                        def stop(self) -> None:
                            return

                        def prevent_default(self) -> None:
                            return

                    app.on_mouse_down(DummyTreeContextClick(outline))
                    await pilot.pause()

                    context_screen = app.screen_stack[-1]
                    context_screen.query_one("#tree_context_opts")
                    context_screen.dismiss(None)
                    await pilot.pause()
                    outline = app.query_one("#json_outline")
                    outline.root.expand_all()
                    await pilot.pause(0.1)
                    phonebook_node = first_node_with_label_prefix(
                        outline.root,
                        humanize_saip_display_name("df-phonebook"),
                    )
                    outline.focus()
                    await pilot.pause(0.1)
                    outline.move_cursor_to_line(phonebook_node.line)
                    outline.select_node(phonebook_node)
                    await pilot.pause(0.1)
                    app._on_tree_context_action_chosen("add_file")
                    await pilot.pause()

                    picker_screen = app.screen_stack[-1]
                    picker_screen.query_one("#pe_file_opts")
                    picker_screen.dismiss("ef-aas")
                    await pilot.pause()
                    follow_up_screen = app.screen_stack[-1]
                    if len(list(follow_up_screen.query("#pe_file_override_apply"))) > 0:
                        follow_up_screen.action_submit_form()
                    await pilot.pause(1.3)

                    document = json.loads(editor.text)
                    telecom_section = document["sections"]["telecom"]
                    self.assertIn("ef-aas", telecom_section)
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_add_selected_gfm_file_action_auto_creates_parent_df(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        source_profile = (
            workspace_root / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
        )
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "add_gfm_file_profile.txt"
            custom_profile.write_text(source_profile.read_text(encoding="utf-8"), encoding="utf-8")
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    await pilot.pause(0.7)
                    outline = app.query_one("#json_outline")
                    sections_root = outline.root.children[0]

                    def child_with_exact_label(parent: object, expected: str) -> object:
                        for child in getattr(parent, "children", []):
                            if str(child.label) == expected:
                                return child
                        raise AssertionError(f"Could not find outline node: {expected}")

                    generic = child_with_exact_label(
                        sections_root,
                        f"{humanize_saip_display_name('genericFileManagement')} {{2}}",
                    )
                    generic_commands = child_with_exact_label(
                        generic,
                        f"{humanize_saip_display_name('fileManagementCMD')} [1]",
                    )
                    first_group = generic_commands.children[0]
                    group_span = getattr(first_group, "data", None)
                    self.assertIsInstance(group_span, tuple)
                    self.assertEqual(len(group_span), 2)
                    before_count = len(json.loads(editor.text)["sections"]["genericFileManagement"]["fileManagementCMD"])

                    app._jump_editor_to_span(group_span[0], group_span[1])
                    await pilot.pause()

                    app.action_add_selected_pe_file()
                    await pilot.pause()

                    picker_screen = app.screen_stack[-1]
                    picker_screen.query_one("#pe_file_opts")
                    picker_screen.dismiss("ef-img")
                    await pilot.pause()
                    follow_up_screen = app.screen_stack[-1]
                    if len(list(follow_up_screen.query("#pe_file_override_apply"))) > 0:
                        follow_up_screen.action_submit_form()
                    await pilot.pause(1.3)

                    document = json.loads(editor.text)
                    commands = document["sections"]["genericFileManagement"]["fileManagementCMD"]
                    self.assertEqual(len(commands), before_count + 2)
                    file_ids: list[str] = []
                    file_paths: list[str] = []
                    for group in commands:
                        for item in group:
                            tagged = item.get("@")
                            if isinstance(tagged, list) is False or len(tagged) != 2:
                                continue
                            tag_name, payload = tagged
                            if tag_name == "filePath" and isinstance(payload, dict):
                                file_paths.append(str(payload.get("hex", "")).lower())
                            if tag_name == "createFCP" and isinstance(payload, dict):
                                file_id = payload.get("fileID", {})
                                if isinstance(file_id, dict):
                                    file_ids.append(str(file_id.get("hex", "")).lower())
                    self.assertIn("5f50", file_ids)
                    self.assertIn("4f20", file_ids)
                    self.assertIn("7f10", file_paths)
                    self.assertIn("7f105f50", file_paths)
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_add_selected_gfm_file_prompts_for_adf_bootstrap_values(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "add_adf_bootstrap_profile.txt"
            self._write_minimal_generic_gfm_profile(custom_profile)
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    await pilot.pause(0.7)
                    outline = app.query_one("#json_outline")
                    sections_root = outline.root.children[0]

                    def child_with_exact_label(parent: object, expected: str) -> object:
                        for child in getattr(parent, "children", []):
                            if str(child.label) == expected:
                                return child
                        raise AssertionError(f"Could not find outline node: {expected}")

                    generic = child_with_exact_label(
                        sections_root,
                        f"{humanize_saip_display_name('genericFileManagement')} {{2}}",
                    )
                    generic_span = getattr(generic, "data", None)
                    self.assertIsInstance(generic_span, tuple)
                    self.assertEqual(len(generic_span), 2)

                    app._jump_editor_to_span(generic_span[0], generic_span[1])
                    await pilot.pause()

                    app.action_add_selected_pe_file()
                    await pilot.pause()

                    picker_screen = app.screen_stack[-1]
                    picker_screen.query_one("#pe_file_opts")
                    picker_screen.dismiss("adf-usim")
                    await pilot.pause()

                    bootstrap_screen = app.screen_stack[-1]
                    fid_input = bootstrap_screen.query_one("#adf_bootstrap_fid")
                    aid_input = bootstrap_screen.query_one("#adf_bootstrap_aid")
                    fid_input.value = "7FF1"
                    aid_input.value = "A0000000871002FF1122334455667788"
                    bootstrap_screen.action_submit_form()
                    await pilot.pause()
                    follow_up_screen = app.screen_stack[-1]
                    if len(list(follow_up_screen.query("#pe_file_override_apply"))) > 0:
                        follow_up_screen.action_submit_form()
                    await pilot.pause(1.3)

                    document = json.loads(editor.text)
                    commands = document["sections"]["genericFileManagement"]["fileManagementCMD"]
                    self.assertEqual(len(commands), 2)
                    file_ids: list[str] = []
                    df_names: list[str] = []
                    for group in commands:
                        for item in group:
                            tagged = item.get("@")
                            if isinstance(tagged, list) is False or len(tagged) != 2:
                                continue
                            tag_name, payload = tagged
                            if tag_name != "createFCP" or isinstance(payload, dict) is False:
                                continue
                            file_id = payload.get("fileID", {})
                            if isinstance(file_id, dict):
                                file_ids.append(str(file_id.get("hex", "")).lower())
                            df_name = payload.get("dfName", {})
                            if isinstance(df_name, dict):
                                df_names.append(str(df_name.get("hex", "")).upper())
                    self.assertIn("7ff1", file_ids)
                    self.assertIn("6f06", file_ids)
                    self.assertIn("A0000000871002FF1122334455667788", df_names)
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_add_selected_pe_file_prompts_for_file_overrides(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "add_file_override_profile.txt"
            self._write_minimal_opt_usim_profile(custom_profile)
            bridge = SaipToolBridge(workspace_root)
            resolved_input = bridge.set_input_file(str(custom_profile))
            json_path, der_path, txt_path = bridge.resolve_transcode_sidecar_paths(resolved_input)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    await pilot.pause(0.7)
                    outline = app.query_one("#json_outline")
                    sections_root = outline.root.children[0]

                    def child_with_label_prefix(parent: object, expected_prefix: str) -> object:
                        for child in getattr(parent, "children", []):
                            if str(child.label).startswith(expected_prefix):
                                return child
                        raise AssertionError(f"Could not find outline node starting with: {expected_prefix}")

                    # The outline renders section keys through
                    # ``humanize_saip_display_name`` which maps ``opt-usim``
                    # to "Optional USIM tree". Match on that humanized
                    # prefix so the test tracks the user-visible label.
                    opt_usim = child_with_label_prefix(sections_root, "Optional USIM tree")
                    opt_usim_span = getattr(opt_usim, "data", None)
                    self.assertIsInstance(opt_usim_span, tuple)
                    self.assertEqual(len(opt_usim_span), 2)

                    app._jump_editor_to_span(opt_usim_span[0], opt_usim_span[1])
                    await pilot.pause()

                    app.action_add_selected_pe_file()
                    await pilot.pause()

                    picker_screen = app.screen_stack[-1]
                    picker_screen.query_one("#pe_file_opts")
                    picker_screen.dismiss("ef-pnn")
                    await pilot.pause()

                    override_screen = app.screen_stack[-1]
                    override_screen.query_one("#pe_file_override_short_efid")
                    override_screen.query_one("#pe_file_override_arr_record").value = "12"
                    override_screen.query_one("#pe_file_override_short_efid").value = "28"
                    override_screen.query_one("#pe_file_override_record_length").value = "20"
                    override_screen.query_one("#pe_file_override_record_count").value = "4"
                    override_screen.action_submit_form()
                    await pilot.pause(1.3)

                    document = json.loads(editor.text)
                    file_descriptor = None
                    for item in document["sections"]["opt-usim"]["ef-pnn"]:
                        tagged = item.get("@")
                        if isinstance(tagged, list) is False or len(tagged) != 2:
                            continue
                        if tagged[0] != "fileDescriptor" or isinstance(tagged[1], dict) is False:
                            continue
                        file_descriptor = tagged[1]
                        break
                    self.assertIsInstance(file_descriptor, dict)
                    assert file_descriptor is not None
                    self.assertEqual(
                        file_descriptor["shortEFID"]["hex"].upper(),
                        "1C",
                    )
                    self.assertEqual(
                        file_descriptor["securityAttributesReferenced"]["hex"].upper(),
                        "0C",
                    )
                    self.assertEqual(
                        file_descriptor["efFileSize"]["hex"].upper(),
                        "50",
                    )
                    self.assertEqual(
                        file_descriptor["fileDescriptor"]["hex"].upper(),
                        "42210014",
                    )
                    await pilot.pause(0.2)

            try:
                asyncio.run(scenario())
            finally:
                for path_value in (json_path, der_path, txt_path):
                    if path_value.exists():
                        path_value.unlink()

    def test_outline_search_jumps_to_matching_tree_node(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "outline_search_profile.txt"
            self._write_minimal_usim_service_table_profile(custom_profile)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    search_input = app.query_one("#json_outline_search")
                    await pilot.pause(0.7)

                    app.action_focus_outline_search()
                    await pilot.pause()
                    self.assertEqual(getattr(app.focused, "id", None), "json_outline_search")

                    search_input.value = "ef-ust"
                    await pilot.pause(0.3)

                    self.assertEqual(getattr(app.focused, "id", None), "json_outline_search")
                    self.assertGreaterEqual(getattr(app, "_outline_search_match_count", 0), 1)
                    self.assertEqual(getattr(app, "_outline_search_index", -1), 0)
                    matches = app._outline_search_matches("ef-ust")
                    self.assertGreaterEqual(len(matches), 1)
                    self.assertGreater(len(getattr(matches[0].label, "spans", [])), 0)
                    self.assertIn('"fillFileContent"', editor.selected_text)

            asyncio.run(scenario())

    def test_outline_search_bindings_cycle_matches_without_opening_insert_picker(self) -> None:
        workspace_root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(dir=workspace_root) as temp_dir:
            custom_profile = Path(temp_dir) / "outline_search_nav_profile.txt"
            self._write_minimal_usim_service_table_profile(custom_profile)

            async def scenario() -> None:
                app = self._build_app(str(custom_profile))
                async with app.run_test() as pilot:
                    editor = app.query_one("#json_editor")
                    search_input = app.query_one("#json_outline_search")
                    await pilot.pause(0.7)

                    app.action_focus_outline_search()
                    await pilot.pause()
                    search_input.value = "ef-arr"
                    await pilot.pause(0.3)

                    self.assertEqual(getattr(app.focused, "id", None), "json_outline_search")
                    self.assertGreaterEqual(getattr(app, "_outline_search_match_count", 0), 2)
                    self.assertEqual(getattr(app, "_outline_search_index", -1), 0)
                    matches = app._outline_search_matches("ef-arr")
                    self.assertGreaterEqual(len(matches), 2)
                    initial_active_style = matches[0].label.spans[0].style
                    initial_background_style = matches[1].label.spans[0].style
                    self.assertNotEqual(initial_active_style, initial_background_style)

                    await pilot.press("f3")
                    await pilot.pause(0.3)

                    self.assertEqual(len(app.screen_stack), 1)
                    self.assertEqual(getattr(app.focused, "id", None), "json_outline_search")
                    self.assertEqual(getattr(app, "_outline_search_index", -1), 1)
                    matches = app._outline_search_matches("ef-arr")
                    self.assertEqual(matches[0].label.spans[0].style, initial_background_style)
                    self.assertEqual(matches[1].label.spans[0].style, initial_active_style)

                    await pilot.press("ctrl+shift+g")
                    await pilot.pause(0.3)

                    self.assertEqual(getattr(app.focused, "id", None), "json_outline_search")
                    self.assertEqual(getattr(app, "_outline_search_index", -1), 0)

            asyncio.run(scenario())

if __name__ == "__main__":
    unittest.main()
