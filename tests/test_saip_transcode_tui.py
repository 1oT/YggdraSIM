import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from textual.app import App

from Tools.ProfilePackage.saip_tool import SaipToolBridge
from Tools.ProfilePackage.saip_transcode_tui import run_saip_transcode_tui


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


if __name__ == "__main__":
    unittest.main()
