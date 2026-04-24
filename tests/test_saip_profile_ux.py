"""
UX-layer tests for the SAIP profile scaffold surface: randomizer, wizard,
detail view / preview / diff commands, AUTO expansion, VERIFY, default output
path, user-preset loading, APPLY-TEMPLATE, and tab completion. All tests mock
pySim-backed encoding so they run without heavy dependencies.
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest import mock

from Tools.ProfilePackage import saip_profile_scaffold as scaffold_module
from Tools.ProfilePackage.saip_profile_randomizer import (
    generate_random_iccid,
    generate_random_imsi,
    is_auto_sentinel,
    resolve_auto_assignments,
    resolve_auto_value,
)
from Tools.ProfilePackage.saip_profile_scaffold import (
    ProfilePreset,
    default_preset_id,
    describe_menu_id,
    describe_preset,
    diff_presets,
    list_preset_placeholders,
    load_user_presets,
)
from Tools.ProfilePackage.saip_profile_wizard import (
    NewProfileWizard,
    WizardAborted,
    resolve_default_scaffold_output_path,
)
from Tools.ProfilePackage.shell import ProfilePackageShell


class PresetIntrospectionTests(unittest.TestCase):
    def test_describe_menu_id_returns_hint_text_from_quick_add_rows(self) -> None:
        hint = describe_menu_id("header")
        self.assertIn("profile header", hint)

    def test_describe_menu_id_unknown_menu_id_returns_empty_string(self) -> None:
        self.assertEqual(describe_menu_id("does-not-exist"), "")

    def test_list_preset_placeholders_usim_exposes_iccid_and_imsi(self) -> None:
        placeholders = list_preset_placeholders("USIM")
        self.assertIn("ICCID", placeholders)
        self.assertIn("IMSI", placeholders)

    def test_list_preset_placeholders_minimal_exposes_iccid_only(self) -> None:
        placeholders = list_preset_placeholders("MINIMAL")
        self.assertEqual(placeholders, ["ICCID"])

    def test_describe_preset_exposes_pe_list_with_descriptions(self) -> None:
        description = describe_preset("BASIC-MF")
        menu_ids = [entry["menu_id"] for entry in description["pes"]]
        self.assertEqual(menu_ids, ["header", "mf", "end"])
        self.assertEqual(description["pe_count"], 3)
        self.assertIn("ICCID", description["placeholders"])

    def test_diff_presets_highlights_added_and_removed_menu_ids(self) -> None:
        diff = diff_presets("BASIC-MF", "USIM")
        self.assertIn("pinCodes", diff.only_in_b)
        self.assertIn("usim", diff.only_in_b)
        self.assertEqual(diff.only_in_a, tuple())
        self.assertIn("header", diff.common)
        self.assertIn("mf", diff.common)
        self.assertIn("end", diff.common)


class RandomizerTests(unittest.TestCase):
    def test_is_auto_sentinel_accepts_common_spellings(self) -> None:
        self.assertTrue(is_auto_sentinel("AUTO"))
        self.assertTrue(is_auto_sentinel("random"))
        self.assertTrue(is_auto_sentinel(" Rand "))
        self.assertFalse(is_auto_sentinel("89460000000000000001"))
        self.assertFalse(is_auto_sentinel(""))

    def test_generate_random_iccid_yields_20_digits_with_valid_luhn(self) -> None:
        value = generate_random_iccid()
        self.assertEqual(len(value), 20)
        self.assertTrue(value.isdigit())
        total = 0
        reversed_digits = value[::-1]
        for index, digit_char in enumerate(reversed_digits):
            digit_value = int(digit_char)
            if index % 2 == 1:
                digit_value *= 2
                if digit_value > 9:
                    digit_value -= 9
            total += digit_value
        self.assertEqual(total % 10, 0)

    def test_generate_random_iccid_respects_prefix_digits(self) -> None:
        value = generate_random_iccid(prefix="8946")
        self.assertTrue(value.startswith("8946"))

    def test_generate_random_imsi_default_uses_test_mcc_and_is_15_digits(self) -> None:
        value = generate_random_imsi()
        self.assertEqual(len(value), 15)
        self.assertTrue(value.isdigit())
        self.assertTrue(value.startswith("00101"))

    def test_resolve_auto_value_expands_iccid_sentinel(self) -> None:
        value = resolve_auto_value("ICCID", "AUTO")
        self.assertEqual(len(value), 20)
        self.assertTrue(value.isdigit())

    def test_resolve_auto_value_passes_through_concrete_value(self) -> None:
        value = resolve_auto_value("ICCID", "89460000000000000001")
        self.assertEqual(value, "89460000000000000001")

    def test_resolve_auto_value_rejects_unsupported_placeholder(self) -> None:
        with self.assertRaisesRegex(ValueError, "only supported for ICCID / IMSI"):
            resolve_auto_value("CUSTOM", "AUTO")

    def test_resolve_auto_assignments_expands_and_summarises(self) -> None:
        resolved, summaries = resolve_auto_assignments(
            {"ICCID": "AUTO", "IMSI": "123456781234567"}
        )
        self.assertEqual(len(resolved["ICCID"]), 20)
        self.assertEqual(resolved["IMSI"], "123456781234567")
        self.assertEqual(len(summaries), 1)
        self.assertIn("ICCID auto-generated", summaries[0])


class WizardTimestampAndPathTests(unittest.TestCase):
    def test_resolve_default_scaffold_output_path_uses_preset_and_extension(self) -> None:
        path = resolve_default_scaffold_output_path(
            "USIM",
            "der",
            Path("/tmp/profiles"),
            timestamp_fn=lambda: "20260101-120000",
        )
        self.assertEqual(
            path,
            Path("/tmp/profiles/scaffold-usim-20260101-120000.der"),
        )

    def test_resolve_default_scaffold_output_path_rejects_unknown_extension(self) -> None:
        with self.assertRaisesRegex(ValueError, "'der' or 'json'"):
            resolve_default_scaffold_output_path(
                "USIM",
                "bin",
                Path("/tmp"),
                timestamp_fn=lambda: "t",
            )


class WizardFlowTests(unittest.TestCase):
    def _make_wizard(
        self,
        answers: list[str],
        *,
        workspace_root: Path,
        default_output_dir: Path,
    ) -> NewProfileWizard:
        answer_iter = iter(answers)

        def _fake_input(_prompt: str) -> str:
            return next(answer_iter)

        return NewProfileWizard(
            workspace_root=workspace_root,
            default_output_dir=default_output_dir,
            input_fn=_fake_input,
            output_fn=lambda _message: None,
            timestamp_fn=lambda: "20260101-120000",
        )

    def test_run_happy_path_der_output_with_iccid_auto(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            profile_dir = workspace / "profiles"
            profile_dir.mkdir()
            wizard = self._make_wizard(
                answers=[
                    "MINIMAL",
                    "",
                    "AUTO",
                    "1",
                    "",
                    "y",
                    "y",
                ],
                workspace_root=workspace,
                default_output_dir=profile_dir,
            )
            decision = wizard.run()
        self.assertEqual(decision.preset_id, "MINIMAL")
        self.assertEqual(decision.menu_ids, ("header", "end"))
        self.assertEqual(decision.output_format, "der")
        self.assertEqual(decision.placeholders, {"ICCID": "AUTO"})
        self.assertTrue(decision.verify)
        self.assertEqual(
            decision.output_path.name,
            "scaffold-minimal-20260101-120000.der",
        )

    def test_run_json_output_skips_verify_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            profile_dir = workspace / "profiles"
            profile_dir.mkdir()
            wizard = self._make_wizard(
                answers=[
                    "2",
                    "",
                    "",
                    "2",
                    "",
                    "",
                    "",
                    "y",
                ],
                workspace_root=workspace,
                default_output_dir=profile_dir,
            )
            decision = wizard.run()
        self.assertEqual(decision.preset_id, "BASIC-MF")
        self.assertEqual(decision.output_format, "json")
        self.assertFalse(decision.verify)
        self.assertEqual(decision.token_defs, {})
        self.assertEqual(decision.placeholder_style, "brace")
        self.assertTrue(decision.output_path.name.endswith(".json"))

    def test_run_numeric_preset_selection_out_of_range_raises(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            wizard = self._make_wizard(
                answers=["999"],
                workspace_root=workspace,
                default_output_dir=workspace,
            )
            with self.assertRaisesRegex(ValueError, "out of range"):
                wizard.run()

    def test_run_drop_mandatory_pe_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            wizard = self._make_wizard(
                answers=[
                    "MINIMAL",
                    "header",
                ],
                workspace_root=workspace,
                default_output_dir=workspace,
            )
            with self.assertRaisesRegex(ValueError, "mandatory PEs"):
                wizard.run()

    def test_run_json_with_declared_tokens_round_trips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            profile_dir = workspace / "profiles"
            profile_dir.mkdir()
            wizard = self._make_wizard(
                answers=[
                    "MINIMAL",
                    "",
                    "",
                    "2",
                    "bracket",
                    "ICCID",
                    "89461111111111111112",
                    "IMSI",
                    '{"pattern_hex":"FF","byte_len":8}',
                    "",
                    "",
                    "y",
                ],
                workspace_root=workspace,
                default_output_dir=profile_dir,
            )
            decision = wizard.run()
        self.assertEqual(decision.output_format, "json")
        self.assertEqual(decision.placeholder_style, "bracket")
        self.assertEqual(
            set(decision.token_defs.keys()), {"ICCID", "IMSI"}
        )
        self.assertEqual(decision.token_defs["ICCID"], "89461111111111111112")
        self.assertEqual(
            decision.token_defs["IMSI"],
            {"pattern_hex": "FF", "byte_len": 8},
        )

    def test_run_json_rejects_invalid_token_name_and_retries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            profile_dir = workspace / "profiles"
            profile_dir.mkdir()
            wizard = self._make_wizard(
                answers=[
                    "MINIMAL",
                    "",
                    "",
                    "2",
                    "",
                    "1bad",
                    "ICCID",
                    "AABB",
                    "",
                    "",
                    "y",
                ],
                workspace_root=workspace,
                default_output_dir=profile_dir,
            )
            decision = wizard.run()
        self.assertEqual(list(decision.token_defs.keys()), ["ICCID"])
        self.assertEqual(decision.placeholder_style, "brace")

    def test_run_der_output_skips_token_step_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            profile_dir = workspace / "profiles"
            profile_dir.mkdir()
            wizard = self._make_wizard(
                answers=[
                    "MINIMAL",
                    "",
                    "",
                    "1",
                    "",
                    "n",
                    "y",
                ],
                workspace_root=workspace,
                default_output_dir=profile_dir,
            )
            decision = wizard.run()
        self.assertEqual(decision.output_format, "der")
        self.assertEqual(decision.token_defs, {})

    def test_run_aborts_when_user_declines_final_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir)
            wizard = self._make_wizard(
                answers=[
                    "MINIMAL",
                    "",
                    "",
                    "1",
                    "",
                    "n",
                    "n",
                ],
                workspace_root=workspace,
                default_output_dir=workspace,
            )
            with self.assertRaises(WizardAborted):
                wizard.run()


class UserPresetLoadingTests(unittest.TestCase):
    def test_load_user_presets_returns_empty_list_for_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = load_user_presets(Path(temp_dir) / "does-not-exist.json")
        self.assertEqual(result, [])

    def test_load_user_presets_accepts_flat_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preset_file = Path(temp_dir) / "presets.json"
            preset_file.write_text(
                json.dumps(
                    {
                        "HOUSE-MINIMAL": {
                            "description": "House-style minimal",
                            "menu_ids": ["header", "mf", "end"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            presets = load_user_presets(preset_file)
        self.assertEqual(len(presets), 1)
        self.assertEqual(presets[0].preset_id, "HOUSE-MINIMAL")
        self.assertEqual(presets[0].menu_ids, ("header", "mf", "end"))
        self.assertEqual(presets[0].source, "user")

    def test_load_user_presets_rejects_preset_missing_header(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preset_file = Path(temp_dir) / "presets.json"
            preset_file.write_text(
                json.dumps(
                    {
                        "BROKEN": {
                            "description": "missing header",
                            "menu_ids": ["mf", "end"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must start with 'header'"):
                load_user_presets(preset_file)

    def test_load_user_presets_rejects_invalid_preset_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            preset_file = Path(temp_dir) / "presets.json"
            preset_file.write_text(
                json.dumps(
                    {
                        "bad name!": {
                            "menu_ids": ["header", "end"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must match"):
                load_user_presets(preset_file)


class PresetShellCommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.shell = ProfilePackageShell(workspace_root=Path(self._temp_workspace.name))

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def _capture_stdout(self, thunk) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            thunk()
        return buffer.getvalue()

    def test_cmd_presets_with_id_prints_detail_view(self) -> None:
        output = self._capture_stdout(lambda: self.shell._cmd_presets("USIM"))
        self.assertIn("Preset detail: USIM", output)
        self.assertIn("PE count:", output)
        self.assertIn("Typed placeholders: ICCID, IMSI", output)
        self.assertIn("akaParameter", output)

    def test_cmd_presets_rejects_multiple_tokens(self) -> None:
        with self.assertRaisesRegex(ValueError, "at most one preset id"):
            self.shell._cmd_presets("USIM FULL")

    def test_cmd_preview_preset_prints_tree_without_writing(self) -> None:
        profile_dir = self.shell.bridge.default_profile_dir
        existing = list(profile_dir.glob("scaffold-*"))
        output = self._capture_stdout(lambda: self.shell._cmd_preview_preset("BASIC-MF"))
        self.assertIn("Preview: BASIC-MF", output)
        self.assertIn("header", output)
        self.assertIn("mf", output)
        self.assertIn("end", output)
        after_files = list(profile_dir.glob("scaffold-*"))
        self.assertEqual(existing, after_files)

    def test_cmd_preview_preset_requires_argument(self) -> None:
        with self.assertRaisesRegex(ValueError, "Usage: PREVIEW-PRESET"):
            self.shell._cmd_preview_preset("")

    def test_cmd_diff_preset_lists_added_and_removed_menu_ids(self) -> None:
        output = self._capture_stdout(
            lambda: self.shell._cmd_diff_preset("BASIC-MF USIM")
        )
        self.assertIn("Only in BASIC-MF: (none)", output)
        self.assertIn("Only in USIM:", output)
        self.assertIn("pinCodes", output)

    def test_cmd_diff_preset_requires_two_arguments(self) -> None:
        with self.assertRaisesRegex(ValueError, "Usage: DIFF-PRESET"):
            self.shell._cmd_diff_preset("USIM")


class NewProfileAutoAndVerifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.shell = ProfilePackageShell(workspace_root=Path(self._temp_workspace.name))

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_cmd_new_profile_expands_auto_iccid_to_20_digit_value(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {
                "header": OrderedDict(
                    [("iccid", bytes.fromhex("0000000000000000000F"))]
                ),
                "mf": OrderedDict(
                    [
                        (
                            "ef-iccid",
                            [("fillFileContent", bytes.fromhex("0000000000000000000F"))],
                        )
                    ]
                ),
                "end": OrderedDict(),
            },
        }
        with mock.patch(
            "Tools.ProfilePackage.shell.build_scaffold_profile_document",
            return_value=fake_document,
        ):
            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    return_value=b"\x01\x02",
                ) as mocked_encode:
                    with contextlib.redirect_stdout(io.StringIO()) as captured:
                        self.shell._cmd_new_profile("PRESET=BASIC-MF ICCID=AUTO")
        encoded_document = mocked_encode.call_args.args[0]
        iccid_bytes = encoded_document["sections"]["header"]["iccid"]
        self.assertEqual(len(iccid_bytes), 10)
        self.assertIn("AUTO value expansion", captured.getvalue())
        self.assertIn("ICCID auto-generated", captured.getvalue())

    def test_cmd_new_profile_sets_current_input_file_after_success(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "out.der"
            with mock.patch(
                "Tools.ProfilePackage.shell.build_scaffold_profile_document",
                return_value=fake_document,
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
                ):
                    with mock.patch(
                        "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                        return_value=b"\xDE\xAD\xBE\xEF",
                    ):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.shell._cmd_new_profile(f'"{output_path}"')
            self.assertEqual(self.shell.bridge.current_input_file, output_path)

    def test_cmd_new_profile_invokes_verify_path_when_flag_set(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        with mock.patch(
            "Tools.ProfilePackage.shell.build_scaffold_profile_document",
            return_value=fake_document,
        ):
            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    return_value=b"\x00",
                ):
                    with mock.patch.object(
                        self.shell,
                        "_verify_scaffolded_der",
                    ) as mocked_verify:
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.shell._cmd_new_profile("PRESET=MINIMAL VERIFY")
        mocked_verify.assert_called_once()

    def test_cmd_new_profile_verify_off_does_not_call_verifier(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        with mock.patch(
            "Tools.ProfilePackage.shell.build_scaffold_profile_document",
            return_value=fake_document,
        ):
            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    return_value=b"\x00",
                ):
                    with mock.patch.object(
                        self.shell,
                        "_verify_scaffolded_der",
                    ) as mocked_verify:
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.shell._cmd_new_profile("PRESET=MINIMAL VERIFY=OFF")
        mocked_verify.assert_not_called()


class ApplyTemplateShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.shell = ProfilePackageShell(workspace_root=Path(self._temp_workspace.name))

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_cmd_apply_template_writes_der_and_marks_active_file(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            template_path = Path(temp_dir) / "template.json"
            template_path.write_text(
                json.dumps({"intro": ["x"], "sections": {}}),
                encoding="utf-8",
            )
            output_path = Path(temp_dir) / "apply_out.der"
            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.dejsonify_document",
                    return_value={"intro": ["x"], "sections": {}},
                ):
                    with mock.patch(
                        "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                        return_value=b"\xAA\xBB",
                    ):
                        with contextlib.redirect_stdout(io.StringIO()):
                            self.shell._cmd_apply_template(
                                f'"{template_path}" "{output_path}"'
                            )
            self.assertEqual(output_path.read_bytes(), b"\xAA\xBB")
            self.assertEqual(self.shell.bridge.current_input_file, output_path)

    def test_cmd_apply_template_requires_two_arguments(self) -> None:
        with self.assertRaisesRegex(ValueError, "Usage: APPLY-TEMPLATE"):
            self.shell._cmd_apply_template("only_one_arg.json")


class UserPresetIntegrationTests(unittest.TestCase):
    def test_shell_registers_user_presets_from_home_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_home:
            preset_file = Path(temp_home) / ".yggdrasim_saip_presets.json"
            preset_file.write_text(
                json.dumps(
                    {
                        "HOUSE-STYLE": {
                            "description": "House-style preset",
                            "menu_ids": ["header", "mf", "end"],
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch(
                "Tools.ProfilePackage.shell.default_user_presets_path",
                return_value=preset_file,
            ):
                with tempfile.TemporaryDirectory() as workspace:
                    with contextlib.redirect_stdout(io.StringIO()):
                        shell = ProfilePackageShell(workspace_root=Path(workspace))
            preset_ids = {
                preset.preset_id for preset in scaffold_module.list_profile_presets()
            }
            self.assertIn("HOUSE-STYLE", preset_ids)
            self.assertIn("HOUSE-STYLE", shell._loaded_user_preset_ids)
        scaffold_module._PROFILE_PRESETS.pop("HOUSE-STYLE", None)

    def test_shell_survives_invalid_user_preset_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_home:
            preset_file = Path(temp_home) / ".yggdrasim_saip_presets.json"
            preset_file.write_text("{not json", encoding="utf-8")
            with mock.patch(
                "Tools.ProfilePackage.shell.default_user_presets_path",
                return_value=preset_file,
            ):
                with tempfile.TemporaryDirectory() as workspace:
                    buffer = io.StringIO()
                    with contextlib.redirect_stdout(buffer):
                        shell = ProfilePackageShell(workspace_root=Path(workspace))
            self.assertEqual(shell._loaded_user_preset_ids, [])
            self.assertIn("Skipped user presets", buffer.getvalue())


class WizardShellIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.shell = ProfilePackageShell(workspace_root=Path(self._temp_workspace.name))

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_cmd_new_profile_wizard_der_path_invokes_materialise_with_decision(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        answers = iter(
            [
                "MINIMAL",
                "",
                "",
                "1",
                "",
                "n",
                "y",
            ]
        )
        self.shell._input_fn = lambda _prompt: next(answers)
        with mock.patch(
            "Tools.ProfilePackage.shell.build_scaffold_profile_document_from_menu_ids",
            return_value=fake_document,
        ):
            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    return_value=b"\x01\x02\x03",
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.shell._cmd_new_profile_wizard("")
        generated = sorted(
            self.shell.bridge.default_profile_dir.glob("scaffold-minimal-*.der")
        )
        self.assertEqual(len(generated), 1)
        self.assertEqual(self.shell.bridge.current_input_file, generated[0])

    def test_cmd_new_profile_wizard_honours_abort(self) -> None:
        answers = iter(
            [
                "MINIMAL",
                "",
                "",
                "1",
                "",
                "n",
                "n",
            ]
        )
        self.shell._input_fn = lambda _prompt: next(answers)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_new_profile_wizard("")
        self.assertIn("Wizard cancelled", buffer.getvalue())


class ScaffoldTabCompletionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        self.shell = ProfilePackageShell(workspace_root=Path(self._temp_workspace.name))

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_preset_equal_completion_offers_known_preset_ids(self) -> None:
        options = self.shell._complete_scaffold_token("NEW-PROFILE", "PRESET=")
        self.assertTrue(any("PRESET=USIM" in option for option in options))
        self.assertTrue(any("PRESET=MINIMAL" in option for option in options))

    def test_placeholder_keyword_completion_offers_iccid_and_imsi(self) -> None:
        options = self.shell._complete_scaffold_token("NEW-PROFILE", "out.der I")
        self.assertIn("ICCID=", options)
        self.assertIn("IMSI=", options)

    def test_placeholder_value_auto_completion_offers_auto_literal(self) -> None:
        options = self.shell._complete_scaffold_token("NEW-PROFILE", "out.der ICCID=")
        self.assertEqual(options, ["ICCID=AUTO "])

    def test_presets_detail_completion_offers_preset_names(self) -> None:
        options = self.shell._complete_scaffold_token("PRESETS", "U")
        self.assertTrue(any(option.startswith("USIM") for option in options))


if __name__ == "__main__":
    unittest.main()
