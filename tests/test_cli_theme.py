# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
"""Coverage for the themeable CLI palette.

Two contracts are load-bearing here. The default theme must render
byte for byte what the CLI rendered before the palettes existed, and
the generated table must still match the GUI token files it was
transcribed from.
"""

from __future__ import annotations

import importlib.util
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

from yggdrasim_common import cli_theme
from yggdrasim_common.cli_palettes import GENERATED_APPEARANCE, GENERATED_PALETTES
from yggdrasim_common.nord_palette import NORD, NordAnsi, hex_to_ansi


REPO_ROOT = Path(__file__).resolve().parents[1]
TOKENS_DIR = REPO_ROOT / "gui_frontend" / "src" / "css" / "tokens"
GENERATOR = REPO_ROOT / "scripts" / "generate_cli_palettes.py"
_HEX_RE = re.compile(r"^#[0-9A-F]{6}$")


def _load_generator():
    spec = importlib.util.spec_from_file_location("_ygg_palette_gen", GENERATOR)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class _ThemeIsolation(unittest.TestCase):
    """Restore the ambient theme so an operator's own flag cannot leak in."""

    def setUp(self) -> None:
        self._saved_env = os.environ.get(cli_theme.ENV_VAR)
        os.environ.pop(cli_theme.ENV_VAR, None)
        cli_theme.set_active_theme(cli_theme.DEFAULT_THEME)

    def tearDown(self) -> None:
        if self._saved_env is None:
            os.environ.pop(cli_theme.ENV_VAR, None)
        else:
            os.environ[cli_theme.ENV_VAR] = self._saved_env
        cli_theme.set_active_theme(None)


class DefaultThemeIsUnchangedTests(_ThemeIsolation):
    """The default palette must not re-tint a single existing call site."""

    def test_every_role_matches_the_frozen_nord_table(self) -> None:
        for role in cli_theme.COLOUR_ROLES:
            with self.subTest(role=role):
                self.assertEqual(cli_theme.role_ansi(role), getattr(NordAnsi, role))

    def test_aliases_match_the_frozen_nord_table(self) -> None:
        for alias in cli_theme.ROLE_ALIASES:
            with self.subTest(alias=alias):
                self.assertEqual(cli_theme.role_ansi(alias), getattr(NordAnsi, alias))

    def test_singleton_matches_the_frozen_nord_table(self) -> None:
        self.assertEqual(NORD.HEADER, NordAnsi.HEADER)
        self.assertEqual(NORD.CYAN, NordAnsi.CYAN)
        self.assertEqual(NORD.FAIL, NordAnsi.FAIL)
        self.assertEqual(NORD.GUIDE, NordAnsi.GUIDE)

    def test_style_codes_are_not_themed(self) -> None:
        cli_theme.set_active_theme("dracula")
        self.assertEqual(NORD.RESET, NordAnsi.RESET)
        self.assertEqual(NORD.BOLD, NordAnsi.BOLD)

    def test_nord_dark_is_an_alias_of_the_default(self) -> None:
        self.assertEqual(
            cli_theme.set_active_theme("nord-dark"), cli_theme.DEFAULT_THEME
        )


class GeneratedTableTests(unittest.TestCase):
    """The tracked table must still agree with the GUI token files."""

    def test_table_is_not_stale(self) -> None:
        generator = _load_generator()
        rendered = generator.render_module(generator.collect_palettes())
        tracked = (REPO_ROOT / "yggdrasim_common" / "cli_palettes.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            tracked,
            rendered,
            "cli_palettes.py is stale; run python scripts/generate_cli_palettes.py",
        )

    def test_every_gui_theme_has_a_cli_palette(self) -> None:
        skip = {"base", "matrix-font-override"}
        expected = {
            path.stem for path in TOKENS_DIR.glob("*.css") if path.stem not in skip
        }
        # nord-dark is served by the hand-kept 'nord' entry.
        covered = set(GENERATED_PALETTES) | {"nord-dark"}
        self.assertEqual(expected, covered)

    def test_every_value_is_a_six_digit_hex(self) -> None:
        for theme, palette in GENERATED_PALETTES.items():
            for role, value in palette.items():
                with self.subTest(theme=theme, role=role):
                    self.assertRegex(value, _HEX_RE)

    def test_every_theme_defines_every_role(self) -> None:
        for theme, palette in GENERATED_PALETTES.items():
            with self.subTest(theme=theme):
                self.assertEqual(set(palette), set(cli_theme.COLOUR_ROLES))

    def test_status_roles_stay_distinguishable(self) -> None:
        """Pass, warn and fail must never collapse to one colour."""
        for theme, palette in GENERATED_PALETTES.items():
            with self.subTest(theme=theme):
                statuses = {palette["GREEN"], palette["YELLOW"], palette["RED"]}
                self.assertEqual(len(statuses), 3)

    def test_appearance_is_recorded_for_every_theme(self) -> None:
        self.assertEqual(set(GENERATED_APPEARANCE), set(GENERATED_PALETTES))
        self.assertEqual(set(GENERATED_APPEARANCE.values()), {"light", "dark"})


class ThemeSelectionTests(_ThemeIsolation):
    """Resolution order, aliases and the fallback."""

    def test_env_var_selects_a_theme(self) -> None:
        os.environ[cli_theme.ENV_VAR] = "dracula"
        cli_theme.set_active_theme(None)
        self.assertEqual(cli_theme.active_theme(), "dracula")
        self.assertEqual(
            cli_theme.role_hex("GREEN"), GENERATED_PALETTES["dracula"]["GREEN"]
        )

    def test_env_var_is_case_insensitive(self) -> None:
        os.environ[cli_theme.ENV_VAR] = "Tokyo-Night"
        cli_theme.set_active_theme(None)
        self.assertEqual(cli_theme.active_theme(), "tokyo-night")

    def test_persisted_override_is_used_when_env_is_unset(self) -> None:
        from yggdrasim_common import env_flags

        original = env_flags.load_persisted_overrides
        env_flags.load_persisted_overrides = lambda: {cli_theme.ENV_VAR: "gruv-dark"}
        try:
            cli_theme.set_active_theme(None)
            self.assertEqual(cli_theme.active_theme(), "gruv-dark")
        finally:
            env_flags.load_persisted_overrides = original

    def test_env_var_beats_a_persisted_value(self) -> None:
        from yggdrasim_common import env_flags

        original = env_flags.load_persisted_overrides
        env_flags.load_persisted_overrides = lambda: {cli_theme.ENV_VAR: "gruv-dark"}
        os.environ[cli_theme.ENV_VAR] = "matrix"
        try:
            cli_theme.set_active_theme(None)
            self.assertEqual(cli_theme.active_theme(), "matrix")
        finally:
            env_flags.load_persisted_overrides = original

    def test_unknown_theme_falls_back_to_the_default(self) -> None:
        os.environ[cli_theme.ENV_VAR] = "no-such-theme"
        cli_theme.set_active_theme(None)
        self.assertEqual(cli_theme.active_theme(), cli_theme.DEFAULT_THEME)

    def test_set_active_theme_rejects_an_unknown_name(self) -> None:
        with self.assertRaises(ValueError):
            cli_theme.set_active_theme("no-such-theme")

    def test_mono_leaves_no_escape_behind(self) -> None:
        """Mono is the off switch the legacy Colors classes never had.

        NO_COLOR is honoured by the terminal_output helpers but not by
        ``Colors.HEADER`` and friends, so mono has to blank the style
        codes too or plain output would still carry a stray reset.
        """
        cli_theme.set_active_theme(cli_theme.MONO_THEME)
        for role in cli_theme.COLOUR_ROLES:
            with self.subTest(role=role):
                self.assertEqual(cli_theme.role_ansi(role), "")
        for name in cli_theme.STYLE_ATTRS:
            with self.subTest(style=name):
                self.assertEqual(cli_theme.style_code(name), "")
        self.assertEqual(NORD.RESET, "")
        self.assertEqual(NORD.BOLD, "")

        from main.main import Colors as launcher_colors

        rendered = (
            f"{launcher_colors.HEADER}head{launcher_colors.ENDC}"
            f"{launcher_colors.BOLD}!{launcher_colors.ENDC}"
        )
        self.assertEqual(rendered, "head!")

    def test_default_is_first_in_the_choice_list(self) -> None:
        self.assertEqual(cli_theme.theme_choices()[0], cli_theme.DEFAULT_THEME)


class ColorsClassesFollowTheThemeTests(_ThemeIsolation):
    """The three legacy ``Colors`` classes resolve on read, not on import."""

    def _colors(self) -> list[tuple[str, type]]:
        from main.main import Colors as launcher_colors
        from SCP03.config import Config
        from SCP80.utils import Colors as scp80_colors

        return [
            ("launcher", launcher_colors),
            ("scp03", Config.Colors),
            ("scp80", scp80_colors),
        ]

    def test_default_values_are_unchanged(self) -> None:
        expected = {
            "launcher": {"HEADER": NordAnsi.HEADER, "CYAN": NordAnsi.CYAN},
            "scp03": {"HEADER": NordAnsi.PURPLE, "MINT": NordAnsi.HEADER},
            "scp80": {"HEADER": NordAnsi.HEADER, "FAIL": NordAnsi.FAIL},
        }
        for label, colors in self._colors():
            for attribute, value in expected[label].items():
                with self.subTest(module=label, attribute=attribute):
                    self.assertEqual(getattr(colors, attribute), value)

    def test_switching_theme_retints_every_class(self) -> None:
        cli_theme.set_active_theme("solarized-light")
        expected = hex_to_ansi(GENERATED_PALETTES["solarized-light"]["CYAN"])
        for label, colors in self._colors():
            with self.subTest(module=label):
                self.assertEqual(colors.CYAN, expected)

    def test_endc_and_bold_survive_a_theme_switch(self) -> None:
        cli_theme.set_active_theme("matrix")
        for label, colors in self._colors():
            with self.subTest(module=label):
                self.assertEqual(colors.ENDC, NordAnsi.RESET)
                self.assertEqual(colors.BOLD, NordAnsi.BOLD)

    def test_scp03_header_stays_distinct_from_the_launcher(self) -> None:
        from main.main import Colors as launcher_colors
        from SCP03.config import Config

        for theme in ("nord", "dracula", "github-light"):
            with self.subTest(theme=theme):
                cli_theme.set_active_theme(theme)
                self.assertNotEqual(Config.Colors.HEADER, launcher_colors.HEADER)

    def test_unknown_attribute_still_raises(self) -> None:
        from main.main import Colors as launcher_colors

        with self.assertRaises(AttributeError):
            launcher_colors.NOT_A_ROLE


class NoImportTimeSnapshotTests(unittest.TestCase):
    """No surface may copy an escape into a constant at import time.

    ``HEADER = NORD.HEADER`` in a class or module body resolves once,
    when that module is first imported, and then never follows a theme
    change again. Five surfaces shipped that shape before the palettes
    existed; this test is what stops a sixth.

    Tracked files only. ``plugins/`` is operator code that is never
    committable here, so a finding there would name a file the user
    cannot fix in a commit; ``git ls-files`` also keeps the gitignored
    ``pysim/``, ``docs/`` and ``Workspace/`` trees out without an
    exclusion list.
    """

    PATTERN = re.compile(
        r"^[ \t]*[A-Z_]+ *= *(?:NORD|NordAnsi|Colors|_Colors|colors)\.[A-Z]",
        re.MULTILINE,
    )

    def _tracked_python_files(self) -> list[str]:
        try:
            completed = subprocess.run(
                ["git", "ls-files", "*.py"],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
        except (OSError, subprocess.CalledProcessError) as exc:
            self.skipTest(f"git ls-files unavailable: {exc}")
        return [line for line in completed.stdout.splitlines() if len(line) > 0]

    def test_no_module_or_class_scope_colour_snapshots(self) -> None:
        offenders: list[str] = []
        for relative in self._tracked_python_files():
            if relative.startswith("tests/"):
                continue
            try:
                body = (REPO_ROOT / relative).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                continue
            for match in self.PATTERN.finditer(body):
                line = body.count("\n", 0, match.start()) + 1
                offenders.append(f"{relative}:{line}")
        self.assertEqual(
            offenders,
            [],
            "these resolve once at import and stop following the theme; "
            "use ThemedColorsMeta with a _ROLE_MAP, or read the role per call",
        )


class RegistryTests(unittest.TestCase):
    """The flag is advertised so the GUI and the launcher can offer it."""

    def test_flag_is_registered_with_every_theme_as_a_choice(self) -> None:
        from yggdrasim_common.env_flags import CATEGORY_ORDER, get_flag

        flag = get_flag(cli_theme.ENV_VAR)
        self.assertIsNotNone(flag)
        self.assertEqual(tuple(flag.choices), cli_theme.theme_choices())
        self.assertIn(flag.category, CATEGORY_ORDER)


if __name__ == "__main__":
    unittest.main()
