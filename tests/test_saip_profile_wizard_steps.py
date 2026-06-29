# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for interactive steps in ``Tools.ProfilePackage.saip_profile_wizard.NewProfileWizard``
not covered by test_saip_profile_wizard_utils.py.

Covers: step_customise_menu_ids, step_collect_placeholders,
step_declare_tokens, step_confirm.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_profile_scaffold import describe_preset
from Tools.ProfilePackage.saip_profile_wizard import NewProfileWizard, WizardAborted


def _make_wizard(workspace: Path, inputs: list[str]) -> NewProfileWizard:
    it = iter(inputs)
    return NewProfileWizard(
        workspace,
        input_fn=lambda _prompt: next(it, ""),
        output_fn=lambda _msg: None,
    )


def _wizard_with_state(
    workspace: Path,
    inputs: list[str],
    *,
    preset_id: str = "USIM",
    output_format: str = "der",
    output_path: Path | None = None,
) -> NewProfileWizard:
    desc = describe_preset(preset_id)
    menu_ids = tuple(e["menu_id"] for e in desc["pes"])
    wiz = _make_wizard(workspace, inputs)
    wiz._state.preset_id = preset_id
    wiz._state.menu_ids = menu_ids
    wiz._state.output_format = output_format
    wiz._state.output_path = output_path
    return wiz


class StepCustomiseMenuIdsTests(unittest.TestCase):

    def test_blank_input_keeps_all(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), [""])
            original = wiz._state.menu_ids
            wiz.step_customise_menu_ids()
            self.assertEqual(wiz._state.menu_ids, original)

    def test_drop_optional_pe(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), ["mf"])
            wiz.step_customise_menu_ids()
            self.assertNotIn("mf", wiz._state.menu_ids)

    def test_drop_header_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), ["header"])
            with self.assertRaises(ValueError):
                wiz.step_customise_menu_ids()

    def test_drop_unknown_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), ["nonexistent_pe_xyz"])
            with self.assertRaises(ValueError):
                wiz.step_customise_menu_ids()

    def test_drop_multiple_optional_pes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), ["mf,pinCodes"])
            wiz.step_customise_menu_ids()
            self.assertNotIn("mf", wiz._state.menu_ids)
            self.assertNotIn("pinCodes", wiz._state.menu_ids)

    def test_menu_ids_remain_tuple(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), [""])
            wiz.step_customise_menu_ids()
            self.assertIsInstance(wiz._state.menu_ids, tuple)


class StepCollectPlaceholdersTests(unittest.TestCase):

    def test_blank_input_skips_all(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), [""] * 20)
            wiz.step_collect_placeholders()
            self.assertEqual(wiz._state.placeholders, {})

    def test_value_stored_for_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # Provide a value for ICCID only, skip IMSI.
            wiz = _wizard_with_state(Path(td), ["8988201234567890123", ""])
            wiz.step_collect_placeholders()
            self.assertIn("ICCID", wiz._state.placeholders)
            self.assertEqual(
                wiz._state.placeholders["ICCID"], "8988201234567890123"
            )

    def test_auto_sentinel_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), ["AUTO"] + [""] * 10)
            wiz.step_collect_placeholders()
            self.assertIn("ICCID", wiz._state.placeholders)
            self.assertEqual(wiz._state.placeholders["ICCID"], "AUTO")

    def test_no_placeholders_available_exits_cleanly(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # MINIMAL preset has no typed placeholders.
            wiz = _wizard_with_state(Path(td), [], preset_id="MINIMAL")
            wiz.step_collect_placeholders()
            self.assertEqual(wiz._state.placeholders, {})


class StepDeclareTokensTests(unittest.TestCase):

    def test_der_format_skips_entirely(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), [], output_format="der")
            wiz.step_declare_tokens()
            self.assertEqual(wiz._state.token_defs, {})

    def test_json_format_blank_declares_no_tokens(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # brace style, then blank token name
            wiz = _wizard_with_state(Path(td), ["brace", ""], output_format="json")
            wiz.step_declare_tokens()
            self.assertEqual(wiz._state.token_defs, {})
            self.assertEqual(wiz._state.placeholder_style, "brace")

    def test_bracket_style_stored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = _wizard_with_state(Path(td), ["bracket", ""], output_format="json")
            wiz.step_declare_tokens()
            self.assertEqual(wiz._state.placeholder_style, "bracket")

    def test_valid_token_declared(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # style=brace, name=MYTOKEN, value=AABBCCDD, blank to finish
            wiz = _wizard_with_state(
                Path(td), ["brace", "MYTOKEN", "AABBCCDD", ""], output_format="json"
            )
            wiz.step_declare_tokens()
            self.assertIn("MYTOKEN", wiz._state.token_defs)

    def test_invalid_token_name_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # 1-bad-name, then blank to finish
            wiz = _wizard_with_state(
                Path(td), ["brace", "123-bad", "", ""], output_format="json"
            )
            wiz.step_declare_tokens()
            self.assertNotIn("123-bad", wiz._state.token_defs)

    def test_empty_value_skips_token(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # valid name but empty value -> skipped
            wiz = _wizard_with_state(
                Path(td), ["brace", "MYTOKEN", "", ""], output_format="json"
            )
            wiz.step_declare_tokens()
            self.assertNotIn("MYTOKEN", wiz._state.token_defs)


class StepConfirmTests(unittest.TestCase):

    def _make_for_confirm(
        self,
        workspace: str,
        inputs: list[str],
        *,
        output_format: str = "der",
        token_defs: dict | None = None,
    ) -> NewProfileWizard:
        wiz = _wizard_with_state(
            Path(workspace),
            inputs,
            output_format=output_format,
            output_path=Path(workspace) / "out.der",
        )
        if token_defs is not None:
            wiz._state.token_defs = token_defs
        return wiz

    def test_accept_confirm(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = self._make_for_confirm(td, ["n", "Y"])
            wiz.step_confirm()  # should not raise

    def test_blank_confirm_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = self._make_for_confirm(td, ["n", ""])
            wiz.step_confirm()  # blank = default Y

    def test_reject_confirm_raises_wizard_aborted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = self._make_for_confirm(td, ["n", "n"])
            with self.assertRaises(WizardAborted):
                wiz.step_confirm()

    def test_verify_set_on_yes(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = self._make_for_confirm(td, ["y", "Y"])
            wiz.step_confirm()
            self.assertTrue(wiz._state.verify)

    def test_verify_not_set_on_no(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wiz = self._make_for_confirm(td, ["n", "Y"])
            wiz.step_confirm()
            self.assertFalse(wiz._state.verify)

    def test_json_format_skips_verify_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            # JSON mode: no verify prompt, only confirm
            wiz = self._make_for_confirm(
                td, ["Y"], output_format="json", token_defs={"T": bytes(2)}
            )
            wiz.step_confirm()
            self.assertFalse(wiz._state.verify)


if __name__ == "__main__":
    unittest.main()
