# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The dissector's Lua tables stay in step with their Python sources.

``Tools/ApduDissector/lua/yggdrasim_apdu/tables.lua`` is generated and
committed: committed so the Lua tree works standalone with no Python,
generated so a status word cannot mean one thing in the MCP server and
another in a packet trace.

Those two properties only hold while the checked-in file matches what
the generator produces right now, which is what this module enforces.
It deliberately imports nothing from the tool packages, so it runs in a
bare CI job with no smart-card dependencies and no tshark.
"""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR_PATH = REPO_ROOT / "scripts" / "generate_apdu_dissector_tables.py"
TABLES_PATH = (
    REPO_ROOT / "Tools" / "ApduDissector" / "lua" / "yggdrasim_apdu" / "tables.lua"
)
REGENERATE_HINT = "python scripts/generate_apdu_dissector_tables.py --write"


def _load_generator():
    """Import the generator by path; ``scripts/`` is not an importable package."""
    spec = importlib.util.spec_from_file_location(
        "_generate_apdu_dissector_tables", GENERATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {GENERATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class GeneratedTablesAreCurrent(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = _load_generator()

    def test_checked_in_lua_matches_the_generator(self) -> None:
        rendered = self.generator.render_tables_lua()
        existing = TABLES_PATH.read_text(encoding="utf-8")
        self.assertEqual(
            existing,
            rendered,
            f"{TABLES_PATH.relative_to(REPO_ROOT)} is stale. Run `{REGENERATE_HINT}`.",
        )

    def test_generation_is_deterministic(self) -> None:
        """Two runs must agree, or the drift check above would flap."""
        self.assertEqual(
            self.generator.render_tables_lua(),
            self.generator.render_tables_lua(),
        )

    def test_check_mode_passes_against_the_checked_in_file(self) -> None:
        self.assertEqual(self.generator.main(["--check"]), 0)


class GeneratedTablesContent(unittest.TestCase):
    """Spot-checks that catch a generator that runs but emits nothing useful.

    A byte-identity test alone would happily pass on an empty file.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.text = TABLES_PATH.read_text(encoding="utf-8")
        cls.generator = _load_generator()
        cls.tables = cls.generator.collect_tables()

    def test_module_shape(self) -> None:
        self.assertTrue(self.text.startswith("-- SPDX-License-Identifier: GPL-3.0-or-later"))
        self.assertIn("Do not edit by hand", self.text)
        self.assertIn("local M = {}", self.text)
        self.assertTrue(self.text.endswith("return M\n"))

    def test_source_digest_is_present_and_stable(self) -> None:
        digest = self.generator._source_digest(self.tables)
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertIn(f'M.SOURCE_DIGEST = "{digest}"', self.text)

    def test_every_risk_instruction_survives_generation(self) -> None:
        for instruction in self.tables["risk"]:
            with self.subTest(ins=f"0x{instruction:02X}"):
                self.assertIn(f"    [0x{instruction:02X}] =", self.text)

    def test_destructive_instructions_keep_the_highest_risk_value(self) -> None:
        """A misordered enum would silently downgrade TERMINATE CARD USAGE."""
        self.assertIn('M.APDU_RISK_DEFAULT = 2', self.text)
        for instruction, (risk_class, _name) in self.tables["risk"].items():
            if risk_class != "destructive":
                continue
            with self.subTest(ins=f"0x{instruction:02X}"):
                self.assertIn(f"    [0x{instruction:02X}] = 3,", self.text)

    def test_landmark_status_words_are_present(self) -> None:
        for status_word in (0x9000, 0x6A82, 0x6982, 0x6985):
            with self.subTest(sw=f"0x{status_word:04X}"):
                self.assertIn(f"    [0x{status_word:04X}] =", self.text)

    def test_landmark_tags_and_commands_are_present(self) -> None:
        self.assertIn('["BF36"]', self.text)
        self.assertIn('["BF2D"]', self.text)
        self.assertIn('[0xA4] = "SELECT"', self.text)
        self.assertIn('[0x80E2] = "STORE_DATA"', self.text)

    def test_well_known_aids_are_named(self) -> None:
        self.assertIn('"ISD-R"', self.text)
        self.assertIn('"ECASD"', self.text)
        self.assertIn('"ADF.USIM"', self.text)


class GeneratedTablesAreAsciiClean(unittest.TestCase):
    """The generated Lua must satisfy the repo hygiene rules.

    The names come from Python docstrings that contain em dashes and
    section signs, so the generator folds typography to ASCII. Without
    that, adding ``.lua`` to the hygiene scanner's suffix list would
    immediately report violations in a generated file.
    """

    def test_output_is_pure_ascii(self) -> None:
        text = TABLES_PATH.read_text(encoding="utf-8")
        offenders = sorted({character for character in text if ord(character) > 0x7F})
        self.assertEqual(offenders, [], f"non-ASCII characters in {TABLES_PATH.name}")

    def test_banned_typography_is_absent(self) -> None:
        # Written as escapes on purpose. Spelling these characters
        # literally would make this test its own counter-example, and a
        # find-and-replace sweep over the repo would quietly rewrite the
        # assertion into one that always passes.
        banned_characters = {
            "em dash": "\u2014",
            "en dash": "\u2013",
            "left single quote": "\u2018",
            "right single quote": "\u2019",
            "left double quote": "\u201c",
            "right double quote": "\u201d",
            "ellipsis": "\u2026",
            "section sign": "\u00a7",
        }
        text = TABLES_PATH.read_text(encoding="utf-8")
        for description, character in banned_characters.items():
            with self.subTest(character=description):
                self.assertNotIn(character, text)

    def test_lua_strings_escape_embedded_quotes(self) -> None:
        generator = _load_generator()
        self.assertEqual(generator.lua_string('a"b'), '"a\\"b"')
        self.assertEqual(generator.lua_string("a\\b"), '"a\\\\b"')
        self.assertEqual(generator.lua_string("a\nb"), '"a\\nb"')
        self.assertEqual(generator.lua_string("a\tb"), '"a\\tb"')

    def test_lua_strings_fold_typography_to_ascii(self) -> None:
        generator = _load_generator()
        self.assertEqual(generator.lua_string("em\u2014dash"), '"em--dash"')
        self.assertEqual(generator.lua_string("en\u2013dash"), '"en-dash"')
        self.assertEqual(
            generator.lua_string("clause \u00a75.7"), '"clause section 5.7"'
        )
        self.assertEqual(generator.lua_string("1oT O\u00dc"), '"1oT OU"')


class GeneratorFailsLoudlyOnMissingSources(unittest.TestCase):
    """A renamed constant must break the build, not silently drop a table."""

    def test_missing_table_raises(self) -> None:
        import tempfile

        generator = _load_generator()
        with tempfile.TemporaryDirectory() as directory:
            fake_root = Path(directory)
            for relative in generator.SOURCES.values():
                target = fake_root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("# deliberately empty\n", encoding="utf-8")
            with self.assertRaises(generator.TableExtractionError):
                generator.collect_tables(fake_root)


if __name__ == "__main__":
    unittest.main()
