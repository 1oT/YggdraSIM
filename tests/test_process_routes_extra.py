import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import SCP03.main as scp03_main
import SCP11.eim_local.main as scp11_eim_local_main
import SCP11.local_access.main as scp11_local_access_main
import SCP80.main as scp80_main
import Tools.ProfilePackage.main as profile_package_main
import Tools.SuciTool.main as suci_tool_main
from yggdrasim_common.process_debug import GLOBAL_DEBUG_ENV

MAIN_WRAPPER_PATH = Path(__file__).resolve().parent.parent / "main" / "main.py"
MAIN_WRAPPER_SPEC = importlib.util.spec_from_file_location(
    "main_wrapper_module",
    MAIN_WRAPPER_PATH,
)
assert MAIN_WRAPPER_SPEC is not None
assert MAIN_WRAPPER_SPEC.loader is not None
main_wrapper = importlib.util.module_from_spec(MAIN_WRAPPER_SPEC)
sys.modules[MAIN_WRAPPER_SPEC.name] = main_wrapper
MAIN_WRAPPER_SPEC.loader.exec_module(main_wrapper)


class BatchEntryReaderTests(unittest.TestCase):
    def test_scp03_entry_stdin_batches_commands_and_preserves_yaml_target(self) -> None:
        with mock.patch.object(scp03_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.stdin", io.StringIO("AUTH-SD\n# skip\nLIST\n")):
                scp03_main.entry_stdin(yaml_out="report.yaml")

        mocked_entry_cmd.assert_called_once_with("AUTH-SD; LIST", yaml_out="report.yaml")

    def test_profile_package_entry_stdin_batches_commands(self) -> None:
        with mock.patch.object(profile_package_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.stdin", io.StringIO("STATUS\n# skip\nEXIT\n")):
                profile_package_main.entry_stdin()

        mocked_entry_cmd.assert_called_once_with("STATUS; EXIT")

    def test_suci_tool_entry_stdin_batches_commands(self) -> None:
        with mock.patch.object(suci_tool_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.stdin", io.StringIO("STATUS\n# skip\nEXIT\n")):
                suci_tool_main.entry_stdin()

        mocked_entry_cmd.assert_called_once_with("STATUS; EXIT")

    def test_local_access_entry_stdin_batches_commands(self) -> None:
        with mock.patch.object(scp11_local_access_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.stdin", io.StringIO("STATUS\n# skip\nHELP\n")):
                scp11_local_access_main.entry_stdin()

        mocked_entry_cmd.assert_called_once_with("STATUS; HELP")

    def test_eim_local_entry_stdin_batches_commands(self) -> None:
        with mock.patch.object(scp11_eim_local_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.stdin", io.StringIO("PATHS\n# skip\nEXIT\n")):
                scp11_eim_local_main.entry_stdin()

        mocked_entry_cmd.assert_called_once_with("PATHS; EXIT")


class StandaloneRouteTests(unittest.TestCase):
    def test_scp03_standalone_routes_cmd_and_out_to_entry_cmd(self) -> None:
        with mock.patch.object(scp03_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.argv", ["prog", "--cmd", "AUTH-SD; LIST", "--out", "report.yaml"]):
                scp03_main.run_standalone()

        mocked_entry_cmd.assert_called_once_with("AUTH-SD; LIST", yaml_out="report.yaml")

    def test_scp80_standalone_routes_stdin_to_batch_mode(self) -> None:
        with mock.patch("SCP80.cli.OtaShell.run_commands", autospec=True) as mocked_batch:
            with mock.patch("sys.argv", ["prog", "--stdin"]):
                with mock.patch("sys.stdin", io.StringIO("help\n# ignore\nquit\n")):
                    scp80_main.run_standalone()

        mocked_batch.assert_called_once()
        self.assertEqual(mocked_batch.call_args.args[1], "help; quit")

    def test_profile_package_standalone_routes_cmd(self) -> None:
        with mock.patch.object(profile_package_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.argv", ["prog", "--cmd", "STATUS; EXIT"]):
                profile_package_main.run_standalone()

        mocked_entry_cmd.assert_called_once_with("STATUS; EXIT")

    def test_profile_package_standalone_routes_inspect_with_profile(self) -> None:
        shell = SimpleNamespace(
            bridge=SimpleNamespace(set_input_file=mock.Mock()),
            _cmd_inspect=mock.Mock(),
        )

        with mock.patch.object(profile_package_main, "ProfilePackageShell", return_value=shell):
            with mock.patch("sys.argv", ["prog", "--inspect", "--profile", "demo.der"]):
                profile_package_main.run_standalone()

        shell.bridge.set_input_file.assert_called_once_with("demo.der")
        shell._cmd_inspect.assert_called_once_with("")

    def test_suci_tool_standalone_routes_cmd(self) -> None:
        with mock.patch.object(suci_tool_main, "entry_cmd") as mocked_entry_cmd:
            with mock.patch("sys.argv", ["prog", "--cmd", "STATUS; EXIT"]):
                suci_tool_main.run_standalone()

        mocked_entry_cmd.assert_called_once_with("STATUS; EXIT")


class MainWrapperProcessRouteTests(unittest.TestCase):
    def test_run_profile_package_launches_tool_entrypoint(self) -> None:
        with mock.patch.object(main_wrapper.importlib, "reload", side_effect=lambda module: module):
            with mock.patch("Tools.ProfilePackage.main.entry") as mocked_entry:
                main_wrapper.run_profile_package()

        mocked_entry.assert_called_once_with()

    def test_run_suci_tool_launches_tool_entrypoint(self) -> None:
        with mock.patch.object(main_wrapper.importlib, "reload", side_effect=lambda module: module):
            with mock.patch("Tools.SuciTool.main.entry") as mocked_entry:
                main_wrapper.run_suci_tool()

        mocked_entry.assert_called_once_with()

    def test_run_scp03_cmd_routes_yaml_output_to_module_entry(self) -> None:
        with mock.patch("SCP03.main.entry_cmd") as mocked_entry_cmd:
            main_wrapper.run_scp03_cmd("AUTH-SD; LIST", yaml_out="report.yaml")

        mocked_entry_cmd.assert_called_once_with("AUTH-SD; LIST", yaml_out="report.yaml")

    def test_main_wrapper_cli_accepts_debug_for_batch_mode(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(main_wrapper, "run_scp03_cmd") as mocked_entry_cmd:
                exit_code = main_wrapper.run_cli(
                    ["--debug", "--scp03", "--cmd", "AUTH-SD; LIST"]
                )
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("AUTH-SD; LIST", yaml_out=None)

    def test_main_wrapper_cli_accepts_verbose_alias_for_batch_mode(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            with mock.patch.object(main_wrapper, "run_scp03_cmd") as mocked_entry_cmd:
                exit_code = main_wrapper.run_cli(
                    ["--verbose", "--scp03", "--cmd", "AUTH-SD; LIST"]
                )
                debug_value = os.environ.get(GLOBAL_DEBUG_ENV)

        self.assertEqual(exit_code, 0)
        self.assertEqual(debug_value, "1")
        mocked_entry_cmd.assert_called_once_with("AUTH-SD; LIST", yaml_out=None)

    def test_run_scp03_script_launches_script_execution_with_prompted_path(self) -> None:
        with mock.patch.object(main_wrapper, "clear_screen"):
            with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                with mock.patch("builtins.input", return_value="tests/demo_script.txt"):
                    with mock.patch.object(
                        main_wrapper.importlib,
                        "reload",
                        side_effect=lambda module: module,
                    ):
                        with mock.patch("SCP03.main.run_script") as mocked_run_script:
                            main_wrapper.run_scp03_script()

        mocked_run_script.assert_called_once_with("tests/demo_script.txt")
        mocked_pause.assert_called_once_with()

    def test_run_scp03_report_launches_report_wizard(self) -> None:
        with mock.patch.object(main_wrapper, "pause") as mocked_pause:
            with mock.patch.object(
                main_wrapper.importlib,
                "reload",
                side_effect=lambda module: module,
            ):
                with mock.patch("SCP03.main.run_report_wizard") as mocked_run_report:
                    main_wrapper.run_scp03_report()

        mocked_run_report.assert_called_once_with()
        mocked_pause.assert_called_once_with()

    def test_run_scp80_script_launches_script_execution_with_prompted_path(self) -> None:
        with mock.patch.object(main_wrapper, "clear_screen"):
            with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                with mock.patch("builtins.input", return_value="tests/demo_script.txt"):
                    with mock.patch.object(
                        main_wrapper.importlib,
                        "reload",
                        side_effect=lambda module: module,
                    ):
                        with mock.patch("SCP80.cli.OtaShell") as mocked_shell_cls:
                            main_wrapper.run_scp80_script()

        mocked_shell_cls.return_value.do_script.assert_called_once_with("tests/demo_script.txt")
        mocked_pause.assert_called_once_with()

    def test_main_menu_routes_profile_tools_and_reference_entries(self) -> None:
        with mock.patch.object(main_wrapper, "run_scp03") as mocked_scp03:
            main_wrapper._dispatch_main_menu_choice("1")
        mocked_scp03.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_scp80") as mocked_scp80:
            main_wrapper._dispatch_main_menu_choice("2")
        mocked_scp80.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_profile_package") as mocked_profile_package:
            main_wrapper._dispatch_main_menu_choice("7")
        mocked_profile_package.assert_called_once_with()

        with mock.patch.object(main_wrapper, "run_suci_tool") as mocked_suci_tool:
            main_wrapper._dispatch_main_menu_choice("8")
        mocked_suci_tool.assert_called_once_with()

        with mock.patch.object(main_wrapper, "show_guides") as mocked_guides:
            main_wrapper._dispatch_main_menu_choice("G")
        mocked_guides.assert_called_once_with()

        with mock.patch.object(main_wrapper, "show_about") as mocked_about:
            main_wrapper._dispatch_main_menu_choice("A")
        mocked_about.assert_called_once_with()

        with mock.patch.object(main_wrapper, "show_license") as mocked_license:
            main_wrapper._dispatch_main_menu_choice("L")
        mocked_license.assert_called_once_with()

    def test_main_menu_quit_tokens_raise_system_exit(self) -> None:
        for token in ("Q", "QA"):
            with self.subTest(token=token):
                with self.assertRaises(SystemExit) as raised:
                    main_wrapper._dispatch_main_menu_choice(token)

                self.assertEqual(raised.exception.code, 0)


class MainWrapperGuideTests(unittest.TestCase):
    def test_show_text_document_reports_missing_file(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            with mock.patch.object(main_wrapper, "PROJECT_ROOT", temp_dir):
                with mock.patch.object(main_wrapper, "clear_screen"):
                    with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                        with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                            main_wrapper._show_text_document("Demo", "docs/missing.md")

        self.assertIn("Document not found: docs/missing.md", captured.getvalue())
        mocked_pause.assert_called_once_with()

    def test_show_text_document_reports_empty_file(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            document_path = Path(temp_dir) / "docs" / "empty.md"
            document_path.parent.mkdir(parents=True, exist_ok=True)
            document_path.write_text("", encoding="utf-8")

            with mock.patch.object(main_wrapper, "PROJECT_ROOT", temp_dir):
                with mock.patch.object(main_wrapper, "clear_screen"):
                    with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                        with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                            main_wrapper._show_text_document("Demo", "docs/empty.md")

        self.assertIn("(Document is empty)", captured.getvalue())
        mocked_pause.assert_called_once_with()

    def test_show_text_document_renders_existing_file_contents(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            document_path = Path(temp_dir) / "docs" / "guide.md"
            document_path.parent.mkdir(parents=True, exist_ok=True)
            document_path.write_text("line-one\nline-two\n", encoding="utf-8")

            with mock.patch.object(main_wrapper, "PROJECT_ROOT", temp_dir):
                with mock.patch.object(main_wrapper, "clear_screen"):
                    with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                        with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                            main_wrapper._show_text_document("Demo", "docs/guide.md")

        rendered = captured.getvalue()
        self.assertIn("line-one", rendered)
        self.assertIn("line-two", rendered)
        mocked_pause.assert_called_once_with()

    def test_show_shell_guide_wizard_requests_wizard_topic(self) -> None:
        guides = SimpleNamespace(print_guide=mock.Mock())

        with mock.patch.object(main_wrapper, "_load_shell_guides", return_value=guides):
            main_wrapper._show_shell_guide_wizard()

        guides.print_guide.assert_called_once_with("WIZARD")

    def test_show_shell_guide_topic_routes_known_topic(self) -> None:
        guides = SimpleNamespace(
            _print_ota_guide=mock.Mock(),
            _print_saip_guide=mock.Mock(),
            _print_suci_guide=mock.Mock(),
        )

        with mock.patch.object(main_wrapper, "_load_shell_guides", return_value=guides):
            with mock.patch.object(main_wrapper, "clear_screen"):
                with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                    main_wrapper._show_shell_guide_topic("saip")

        guides._print_saip_guide.assert_called_once_with()
        mocked_pause.assert_called_once_with()

    def test_show_shell_guide_topic_reports_unknown_topic(self) -> None:
        guides = SimpleNamespace(
            _print_ota_guide=mock.Mock(),
            _print_saip_guide=mock.Mock(),
            _print_suci_guide=mock.Mock(),
        )

        with mock.patch.object(main_wrapper, "_load_shell_guides", return_value=guides):
            with mock.patch.object(main_wrapper, "clear_screen"):
                with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                    with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                        main_wrapper._show_shell_guide_topic("bad-topic")

        self.assertIn("Unknown guide topic: BAD-TOPIC", captured.getvalue())
        mocked_pause.assert_called_once_with()

    def test_show_guides_routes_readme_reference(self) -> None:
        with mock.patch.object(main_wrapper, "clear_screen"):
            with mock.patch.object(main_wrapper, "_show_text_document") as mocked_show_doc:
                with mock.patch("builtins.input", side_effect=["R", "Q"]):
                    main_wrapper.show_guides()

        mocked_show_doc.assert_called_once_with("YggdraSIM README", "README.md")

    def test_show_guides_invalid_choice_reprompts_until_quit(self) -> None:
        with mock.patch.object(main_wrapper, "clear_screen"):
            with mock.patch("builtins.input", side_effect=["bad", "", "Q"]):
                with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                    main_wrapper.show_guides()

        self.assertIn("Invalid guide selection.", captured.getvalue())

    def test_show_license_reports_missing_file(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        missing_license_path = state_dir / "missing-LICENSE"

        with mock.patch.object(main_wrapper, "clear_screen"):
            with mock.patch.object(main_wrapper, "pause") as mocked_pause:
                with mock.patch.dict(
                    main_wrapper.DIRS,
                    {"LICENSE": str(missing_license_path)},
                    clear=False,
                ):
                    with mock.patch("sys.stdout", new_callable=io.StringIO) as captured:
                        main_wrapper.show_license()

        self.assertIn("License file not found", captured.getvalue())
        mocked_pause.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
