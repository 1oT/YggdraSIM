import asyncio
import tempfile
import unittest
from pathlib import Path

from textual.app import App

from Tools.ProfilePackage.saip_tool import SaipToolBridge
from Tools.ProfilePackage.saip_transcode_tui import run_saip_transcode_tui


class SaipTranscodeTuiInteractionTests(unittest.TestCase):
    def _build_app(self) -> App:
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
            bridge.set_input_file("Tools/ProfilePackage/profile/reference_test_profile.txt")
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
