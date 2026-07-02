# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the minimalist icon vocabulary and the
Yggdrasil-themed Nord palette weave.

Background:

* The SCP03 ribbon used to mix heraldic / emoji-leaning glyphs
  (fleur-de-lis, atom, lightning bolt, cloud emoji, question-mark,
  squared-key, etc.) alongside cleaner geometric forms. The result
  was visually noisy. The agreed direction is a small, neutral
  vocabulary built around circled-operators (⊕ ⊖ ⊘ ⊙ ⊚ ⊜ ⊞ ⊟ ⊡),
  simple arrows (↻ ↺ ↶ ↪ ⇄ ⤓ ⬇ ↑) and squares (▣ ▤ ▦ ▩) plus a
  handful of long-standing iconography (✓ ✗ ★ ⓘ).

* For the Nord theme specifically (and *only* Nord), we weave in a
  handful of Yggdrasil-inspired tokens — frost, amber, runic violet,
  leaf, bark, ember, mist — so the file-system tree icons and the
  background tint hint at the world-tree imagery without breaking
  Nord's calm/cool aesthetic. Other themes are unaffected; the
  ``--tree-*-*`` tokens fall back to the legacy hard-coded values
  when ``--ygg-*`` are not defined.

These tests pin the contract so a future edit doesn't silently
re-introduce the noisy glyphs or smuggle Yggdrasil colours into
non-Nord themes.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path


_REPO = Path(__file__).resolve().parents[1]
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_APP_CSS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.css"


# ---------------------------------------------------------------------- #
# JS contract — centralised icon palette
# ---------------------------------------------------------------------- #


class IconPaletteJsContract(unittest.TestCase):
    """The ribbon must source every icon from ``SCP03_ICONS``."""

    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_icon_palette_constant_exists(self) -> None:
        # The palette is frozen so future edits land in one spot
        # rather than drifting across 50+ inline literals.
        self.assertIn("var SCP03_ICONS = Object.freeze({", self.js)

    def test_icon_palette_exposed_on_window(self) -> None:
        # DevTools introspection + regression tests rely on the
        # global handle. If this is removed the rest of these tests
        # also lose their footing, so we pin it explicitly.
        self.assertIn("window.YggdraSimIcons = SCP03_ICONS;", self.js)

    def test_no_inline_icon_literals_in_ribbon(self) -> None:
        # Anything of the shape ``icon: "\u...."`` would mean a
        # ribbon site reverted to inline glyphs. Disallow.
        # We allow ``icon: SCP03_ICONS.<key>`` and ``icon: "" `` only.
        pattern = re.compile(r'icon:\s*"\\u[0-9a-fA-F]')
        hits = pattern.findall(self.js)
        self.assertEqual(
            [],
            hits,
            "ribbon icons must reference SCP03_ICONS, not inline literals",
        )

    def test_named_icon_keys_are_referenced_by_ribbon(self) -> None:
        # Spot-check a handful of representative bindings to make
        # sure the palette is actually consumed (catches a "defined
        # but never referenced" regression).
        for name in (
            "rescan",
            "resetCard",
            "clearSelection",
            "readSelected",
            "authSession",
            "apps",
            "securityDomains",
            "profiles",
            "setGold",
            "diff",
            "deriveOpc",
            "installCap",
            "installApp",
            "perso",
            "stkShell",
            "otaShell",
            "guides",
            "close",
        ):
            with self.subTest(icon=name):
                self.assertIn("SCP03_ICONS." + name, self.js)


class IconVocabularyMinimalismContract(unittest.TestCase):
    """The retired exotic glyphs must not return as ribbon icons."""

    # Each entry is (codepoint, human-readable name for the failure
    # message). All of these were removed in favour of cleaner forms
    # — they should no longer appear *as ribbon-button icons*. They
    # MAY still appear elsewhere in the bundle (e.g. the ``× close``
    # button on a popout reuses ``\u00D7``), so we constrain the
    # search to the ``icon: "..."`` literal form.
    _RETIRED = (
        ("\\u26BF", "squared-key (⛿)"),
        ("\\u2756", "black-diamond-minus-x (❖)"),
        ("\\u2632", "trigram (☲)"),
        ("\\u269C", "fleur-de-lis (⚜)"),
        ("\\u269B", "atom symbol (⚛)"),
        ("\\u26A1", "lightning bolt (⚡)"),
        ("\\u23EF", "play/pause (⏯)"),
        ("\\u2753", "question mark (❓)"),
        ("\\u2302", "house (⌂)"),
        ("\\u29C1", "circled equals (⦁)"),
        ("\\u29C0", "circled less-than (⦀)"),
        ("\\u25C9", "fisheye (◉)"),
        ("\\u21EA", "up-arrow on bar (⇪)"),
        ("\\u21E9", "downwards arrow (⇩)"),
        ("\\u29F8", "big solidus (⧸)"),
    )

    def setUp(self) -> None:
        self.js = _APP_JS.read_text(encoding="utf-8")

    def test_retired_glyphs_absent_as_ribbon_icons(self) -> None:
        for codepoint, label in self._RETIRED:
            with self.subTest(glyph=label):
                pattern = 'icon: "' + codepoint + '"'
                self.assertNotIn(
                    pattern,
                    self.js,
                    "retired glyph " + label + " resurfaced as a ribbon icon",
                )


# ---------------------------------------------------------------------- #
# CSS contract — Yggdrasil weave (Nord-only)
# ---------------------------------------------------------------------- #


class YggdrasilNordPaletteContract(unittest.TestCase):
    def setUp(self) -> None:
        self.css = _APP_CSS.read_text(encoding="utf-8")

    # Helpers ---------------------------------------------------------
    def _block_for(self, theme_selector: str) -> str:
        """Return the CSS block for a given theme selector.

        Naive — the test stylesheet is hand-written, so a balanced
        ``{...}`` slice anchored at the selector is enough.
        """
        idx = self.css.find(theme_selector)
        self.assertNotEqual(
            idx,
            -1,
            "selector " + theme_selector + " not found in stylesheet",
        )
        open_brace = self.css.find("{", idx)
        depth = 1
        cursor = open_brace + 1
        while cursor < len(self.css) and depth > 0:
            ch = self.css[cursor]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            cursor += 1
        return self.css[open_brace:cursor]

    # Palette tokens --------------------------------------------------
    def test_nord_dark_defines_yggdrasil_tokens(self) -> None:
        block = self._block_for('html[data-theme="nord-dark"]')
        for token in (
            "--ygg-frost",
            "--ygg-amber",
            "--ygg-runic",
            "--ygg-leaf",
            "--ygg-bark",
            "--ygg-ember",
            "--ygg-mist",
        ):
            with self.subTest(token=token):
                self.assertIn(token + ":", block)

    def test_nord_light_defines_yggdrasil_tokens(self) -> None:
        block = self._block_for('html[data-theme="nord-light"]')
        for token in (
            "--ygg-frost",
            "--ygg-amber",
            "--ygg-runic",
            "--ygg-leaf",
            "--ygg-bark",
            "--ygg-ember",
            "--ygg-mist",
        ):
            with self.subTest(token=token):
                self.assertIn(token + ":", block)

    def test_other_themes_do_not_redefine_ygg_tokens(self) -> None:
        # The user explicitly asked for "color handling only for
        # nord theme". The other themes therefore must not declare
        # --ygg-* tokens of their own — they should fall through to
        # the ``var(--ygg-*, fallback)`` defaults that the consumers
        # provide.
        for selector in (
            'html[data-theme="oneot-dark"]',
            'html[data-theme="oneot-light"]',
            'html[data-theme="matrix"]',
            'html[data-theme="gruv-dark"]',
            'html[data-theme="ink-light"]',
            'html[data-theme="ocean-dark"]',
        ):
            block = self._block_for(selector)
            for token in ("--ygg-frost", "--ygg-amber", "--ygg-runic", "--ygg-leaf"):
                with self.subTest(selector=selector, token=token):
                    self.assertNotIn(
                        token + ":",
                        block,
                        token
                        + " leaked into "
                        + selector
                        + " (should stay Nord-only)",
                    )

    # Tree-icon palette ----------------------------------------------
    def test_nord_dark_overrides_tree_palette(self) -> None:
        block = self._block_for('html[data-theme="nord-dark"]')
        for token in (
            "--tree-mf-fg",
            "--tree-mf-bg",
            "--tree-mf-edge",
            "--tree-adf-fg",
            "--tree-adf-bg",
            "--tree-adf-edge",
            "--tree-df-fg",
            "--tree-df-bg",
            "--tree-df-edge",
            "--tree-ef-fg",
            "--tree-ef-bg",
            "--tree-ef-edge",
        ):
            with self.subTest(token=token):
                self.assertIn(token + ":", block)

    def test_tree_icon_rules_consume_tree_tokens(self) -> None:
        # Each kind rule must reference the matching ``--tree-*-*``
        # token *with a fallback* so non-Nord themes keep their
        # legacy palette.
        for kind in ("mf", "adf", "df", "ef"):
            with self.subTest(kind=kind):
                # Match the rule body — the selector header alone is
                # not enough since we want to verify the property.
                rule_re = re.compile(
                    r"\.cc-tree-icon--" + kind + r"\s*\{[^}]*?\}",
                    re.DOTALL,
                )
                match = rule_re.search(self.css)
                self.assertIsNotNone(
                    match,
                    "missing rule for .cc-tree-icon--" + kind,
                )
                body = match.group(0)
                self.assertIn("var(--tree-" + kind + "-bg", body)
                self.assertIn("var(--tree-" + kind + "-fg", body)
                self.assertIn("var(--tree-" + kind + "-edge", body)

    def test_tree_icon_rules_keep_legacy_fallbacks(self) -> None:
        # The fallback chain protects non-Nord themes — make sure
        # the legacy hard-coded values still appear inside the
        # var() chain. We pick the most recognisable byte values
        # for each kind.
        for kind, marker in (
            ("mf", "#6aa9ff"),
            ("adf", "#ffb85c"),
            ("df", "#b19cd9"),
            ("ef", "#78dcb4"),
        ):
            with self.subTest(kind=kind):
                rule_re = re.compile(
                    r"\.cc-tree-icon--" + kind + r"\s*\{[^}]*?\}",
                    re.DOTALL,
                )
                body = rule_re.search(self.css).group(0)
                self.assertIn(marker, body)

    # Theme tint ------------------------------------------------------
    def test_nord_theme_tint_includes_yggdrasil_radial(self) -> None:
        # The tint should weave in an amber radial in addition to
        # the existing frost/runic ones — that's the most visible
        # cue of the Yggdrasil colour story without altering the
        # bg/fg/accent triplet that the rest of the UI builds on.
        for selector in (
            'html[data-theme="nord-dark"]',
            'html[data-theme="nord-light"]',
        ):
            block = self._block_for(selector)
            with self.subTest(selector=selector):
                # 4 radials = 3 legacy + 1 amber. Counting beats
                # matching a literal RGB so the exact colour can
                # still be tweaked.
                self.assertGreaterEqual(
                    block.count("radial-gradient("),
                    4,
                    selector + " should weave at least four radials",
                )


if __name__ == "__main__":
    unittest.main()
