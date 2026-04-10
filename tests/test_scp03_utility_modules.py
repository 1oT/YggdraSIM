import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from SCP03.core.utils import HexUtils, StatusWordTranslator, TlvParser
from SCP03.interface.custom_binds import CommandBinder, manage_binds_wizard
from SCP03.interface.guides import ShellGuides
from SCP03.interface.help_menu import HelpMenu
from SCP03.logic.euicc_info2 import (
    build_euicc_info2_detail_lines,
    build_euicc_info2_validation_lines,
    decode_ipa_mode,
    format_version_bytes,
)
from SCP03.logic.profile_snapshot_diff import combined_profile_unified_diff, strip_generated_fields


class HexUtilsAndTlvParserTests(unittest.TestCase):
    def test_hexutils_support_multiple_input_shapes(self) -> None:
        self.assertEqual(HexUtils.to_bytes("0xAA:BB"), b"\xAA\xBB")
        self.assertEqual(HexUtils.to_bytes([0xAA, 0xBB]), b"\xAA\xBB")
        self.assertEqual(HexUtils.to_hex(b"\xAA\xBB", space=True), "AA BB")

    def test_tlv_parser_handles_duplicate_and_multibyte_tags(self) -> None:
        parsed = TlvParser.parse(bytes.fromhex("4F01AA4F01BB9F700107"))
        self.assertEqual(parsed[0x4F], [b"\xAA", b"\xBB"])
        self.assertEqual(parsed[0x9F70], b"\x07")

    def test_tlv_parser_reports_truncated_input(self) -> None:
        detailed = TlvParser.parse_detailed(bytes.fromhex("4F02AA"))
        self.assertFalse(detailed["complete"])
        self.assertIn("overruns input buffer", str(detailed["error"]))

    def test_status_word_translator_covers_dynamic_statuses(self) -> None:
        self.assertEqual(StatusWordTranslator.translate(0x90, 0x00), "Success")
        self.assertIn("bytes of data available", StatusWordTranslator.translate(0x61, 0x1A))
        self.assertIn("Correct length is 16", StatusWordTranslator.translate(0x6C, 0x10))
        self.assertIn("2 retries remaining", StatusWordTranslator.translate(0x63, 0xC2))


class EuiccInfo2HelperTests(unittest.TestCase):
    def test_basic_decoders_render_human_readable_values(self) -> None:
        self.assertEqual(format_version_bytes(b"\x01\x02\x03"), "v1.2.3 (010203)")
        self.assertEqual(decode_ipa_mode(b"\x01"), "ipae (IPAe is active) (1)")

    def test_build_detail_lines_includes_iot_and_validation_sections(self) -> None:
        response = bytes.fromhex(
            "BF228192810302030182030206008303260116840D81010882040002EC08830224"
            "DF8505007FB6F3C1860311020087030203008802029CA916041481370F5125D0B1D4"
            "08D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "990206400403FFFFFF0C0D4B4E2D444E2D55502D30333237AF050403030301900101"
            "B40BA005040301020081008200"
        )

        lines = build_euicc_info2_detail_lines(response)

        self.assertTrue(any(label == "IPA Mode" and "ipae" in value for _, label, value in lines))
        self.assertTrue(any(label == "IoT Specific Info" for _, label, _ in lines))
        self.assertTrue(any(label == "SGP.32 Validation" for _, label, _ in lines))

    def test_validation_lines_warn_when_iot_fields_are_incomplete(self) -> None:
        lines = build_euicc_info2_validation_lines(bytes.fromhex("BF2205900101B400"))

        self.assertTrue(any(label == "SGP.32 Validation" and value == "WARN" for _, label, value in lines))
        self.assertTrue(any("Missing mandatory fields" in value for _, _, value in lines))


class ProfileSnapshotDiffTests(unittest.TestCase):
    def test_generated_fields_are_stripped_recursively(self) -> None:
        cleaned = strip_generated_fields(
            {
                "generated": "drop",
                "nested": {"generated": "drop", "keep": 1},
                "items": [{"generated": "drop", "value": 2}],
            }
        )
        self.assertEqual(cleaned, {"nested": {"keep": 1}, "items": [{"value": 2}]})

    def test_combined_profile_diff_ignores_generated_noise(self) -> None:
        identical, diff_text = combined_profile_unified_diff(
            {"generated": "one", "fs": {"value": 1}},
            {"generated": "two", "fs": {"value": 1}},
        )
        self.assertTrue(identical)
        self.assertEqual(diff_text, "")

    def test_combined_profile_diff_returns_unified_diff_when_changed(self) -> None:
        identical, diff_text = combined_profile_unified_diff(
            {"fs": {"value": 1}},
            {"fs": {"value": 2}},
            gold_label="golden",
            live_label="captured",
        )
        self.assertFalse(identical)
        self.assertIn("--- golden", diff_text)
        self.assertIn("+++ captured", diff_text)
        self.assertIn("-  value: 1", diff_text)
        self.assertIn("+  value: 2", diff_text)


class HelpAndGuideTests(unittest.TestCase):
    def test_help_menu_mentions_newer_command_surface(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            HelpMenu.print_help()
        rendered = buffer.getvalue()
        self.assertIn("SCP02-SD", rendered)
        self.assertIn("PROFILE-DIFF", rendered)
        self.assertIn("MANAGE-PROFILE", rendered)

    def test_shell_guides_link_helper_and_unknown_topic_path(self) -> None:
        self.assertEqual(ShellGuides._link("Guide", ""), "Guide")
        buffer = io.StringIO()
        with mock.patch("SCP03.interface.guides.os.system", return_value=0):
            with redirect_stdout(buffer):
                ShellGuides.print_guide("missing")
        self.assertIn("Unknown guide topic: MISSING", buffer.getvalue())


class CommandBinderTests(unittest.TestCase):
    def test_binder_default_add_delete_and_resolve_sequence(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            binds_path = Path(temp_dir) / "binds.json"
            binder = CommandBinder(filepath=str(binds_path))

            self.assertIn("adm", binder.binds)
            binder.add_bind("demo", "HELP; SHOW {0}")
            self.assertEqual(binder.resolve("demo value"), ["HELP", "SHOW value"])
            binder.del_bind("demo")
            self.assertEqual(binder.resolve("demo value"), ["demo value"])

    def test_manage_binds_wizard_adds_bind(self) -> None:
        binder = SimpleNamespace(added=[], binds={})
        binder.add_bind = lambda trigger, sequence: binder.added.append((trigger, sequence))
        binder.del_bind = lambda trigger: None
        colors = SimpleNamespace(HEADER="", ENDC="", CYAN="", GREEN="")

        class FakeWizard:
            def __init__(self, *args, **kwargs):
                del args
                del kwargs

            def add_step(self, *args, **kwargs):
                del args
                del kwargs

            @staticmethod
            def run():
                return {
                    "action": "ADD",
                    "trigger": "demo",
                    "sequence": "HELP",
                }

        with mock.patch("SCP03.interface.custom_binds.InteractiveWizard", FakeWizard):
            manage_binds_wizard(colors, binder)

        self.assertEqual(binder.added, [("demo", "HELP")])


if __name__ == "__main__":
    unittest.main()
