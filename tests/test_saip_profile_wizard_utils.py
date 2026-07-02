# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``Tools.ProfilePackage.saip_profile_wizard``.

Covers: summarise_wizard_decision (pure), and the individual
step_pick_preset / step_pick_output_format / step_pick_output_path
wizard steps via canned ``input_fn`` responses.  No file I/O occurs
outside a temporary directory; no external subprocess is spawned.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from Tools.ProfilePackage.saip_profile_wizard import (
    NewProfileWizard,
    WizardDecision,
    summarise_wizard_decision,
)


def _make_wizard(
    tmp: Path,
    responses: list[str],
) -> NewProfileWizard:
    it = iter(responses)
    return NewProfileWizard(
        workspace_root=tmp,
        input_fn=lambda _prompt: next(it),
        output_fn=lambda _msg: None,
    )


class SummariseWizardDecisionTests(unittest.TestCase):

    def _decision(self, **kw) -> WizardDecision:
        defaults = dict(
            preset_id="minimal",
            menu_ids=(),
            placeholders={},
            output_format="der",
            output_path=Path("/tmp/out.der"),
            verify=False,
        )
        defaults.update(kw)
        return WizardDecision(**defaults)

    def test_returns_iterable_of_strings(self) -> None:
        lines = list(summarise_wizard_decision(self._decision()))
        for line in lines:
            self.assertIsInstance(line, str)

    def test_preset_in_summary(self) -> None:
        lines = list(summarise_wizard_decision(self._decision(preset_id="usim")))
        self.assertTrue(any("usim" in ln for ln in lines))

    def test_format_uppercased(self) -> None:
        lines = list(summarise_wizard_decision(self._decision(output_format="json")))
        self.assertTrue(any("JSON" in ln for ln in lines))

    def test_output_path_in_summary(self) -> None:
        p = Path("/workspace/out.der")
        lines = list(summarise_wizard_decision(self._decision(output_path=p)))
        self.assertTrue(any(str(p) in ln for ln in lines))

    def test_verify_on_in_summary(self) -> None:
        lines = list(summarise_wizard_decision(self._decision(verify=True)))
        self.assertTrue(any("verify=on" in ln for ln in lines))

    def test_verify_off_not_in_summary(self) -> None:
        lines = list(summarise_wizard_decision(self._decision(verify=False)))
        self.assertFalse(any("verify" in ln for ln in lines))

    def test_placeholders_in_summary(self) -> None:
        dec = self._decision(placeholders={"ICCID": "8988201234567890123"})
        lines = list(summarise_wizard_decision(dec))
        combined = " ".join(lines)
        self.assertIn("ICCID", combined)
        self.assertIn("8988201234567890123", combined)

    def test_no_placeholders_no_placeholder_line(self) -> None:
        lines = list(summarise_wizard_decision(self._decision(placeholders={})))
        self.assertFalse(any("placeholders" in ln for ln in lines))


class StepPickPresetTests(unittest.TestCase):

    def test_empty_input_selects_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), [""])
            wizard.step_pick_preset()
            self.assertGreater(len(wizard._state.preset_id), 0)

    def test_numeric_1_selects_first_preset(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), ["1"])
            wizard.step_pick_preset()
            self.assertIsInstance(wizard._state.preset_id, str)

    def test_name_input_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), ["minimal"])
            wizard.step_pick_preset()
            self.assertEqual(wizard._state.preset_id.lower(), "minimal")

    def test_out_of_range_number_raises(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), ["9999"])
            with self.assertRaises(ValueError):
                wizard.step_pick_preset()

    def test_preset_sets_menu_ids(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), ["1"])
            wizard.step_pick_preset()
            self.assertIsInstance(wizard._state.menu_ids, tuple)


class StepPickOutputFormatTests(unittest.TestCase):

    def test_empty_input_defaults_to_der(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), [""])
            wizard.step_pick_output_format()
            self.assertEqual(wizard._state.output_format, "der")

    def test_json_input_sets_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), ["json"])
            wizard.step_pick_output_format()
            self.assertEqual(wizard._state.output_format, "json")

    def test_der_input_sets_der(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), ["der"])
            wizard.step_pick_output_format()
            self.assertEqual(wizard._state.output_format, "der")

    def test_format_is_string(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), [""])
            wizard.step_pick_output_format()
            self.assertIsInstance(wizard._state.output_format, str)


class StepPickOutputPathTests(unittest.TestCase):

    def test_absolute_path_stored(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = str(Path(td) / "profile.der")
            wizard = _make_wizard(Path(td), [target])
            wizard.step_pick_output_path()
            self.assertEqual(str(wizard._state.output_path), target)

    def test_empty_input_uses_default(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), [""])
            wizard._state.preset_id = "minimal"
            wizard.step_pick_output_path()
            self.assertIsNotNone(wizard._state.output_path)

    def test_output_path_is_path_object(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            wizard = _make_wizard(Path(td), [""])
            wizard._state.preset_id = "minimal"
            wizard.step_pick_output_path()
            self.assertIsInstance(wizard._state.output_path, Path)


if __name__ == "__main__":
    unittest.main()
