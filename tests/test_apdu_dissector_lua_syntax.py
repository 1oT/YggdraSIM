# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static invariants for the dissector's Lua sources.

Wireshark's plugin loader walks its plugin directory recursively and
executes every ``.lua`` file it finds as a top-level script, in
alphabetical order. ``yggdrasim_apdu/tlv.lua`` therefore runs standalone,
possibly before the entry point that is supposed to ``require`` it.

Two invariants make that harmless, and this module enforces both
mechanically rather than by convention:

1. Every module under ``yggdrasim_apdu/`` is side-effect free, so running
   one as a script builds a table and discards it.
2. The entry point is idempotent, because ``Proto()`` raises on a
   duplicate name.

The file-content checks need no tshark. The load check does, and reports
honestly when Lua could not actually run.
"""

from __future__ import annotations

import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    DISSECTOR_PATH,
    Exchange,
    require_working_tshark,
    run_tshark,
    write_capture,
)

LUA_ROOT = DISSECTOR_PATH.parent
MODULE_DIR = LUA_ROOT / "yggdrasim_apdu"

#: Constructs that register with Wireshark. Legal in the entry point,
#: forbidden at module scope anywhere else.
REGISTERING_CONSTRUCTS = (
    "Proto(",
    "ProtoExpert.new(",
    "register_postdissector(",
    "DissectorTable.get(",
    "Field.new(",
)

#: Constructs no dissector module has any business using.
FORBIDDEN_ANYWHERE = (
    "os.execute",
    "io.popen",
    "loadstring(",
    'require("socket")',
    "os.remove",
    "os.rename",
)


def _module_files() -> list[Path]:
    return sorted(path for path in MODULE_DIR.glob("*.lua"))


def _all_lua_files() -> list[Path]:
    return sorted(LUA_ROOT.rglob("*.lua"))


def _top_level_lines(text: str) -> list[tuple[int, str]]:
    """Lines that start in column zero, i.e. run at module load."""
    lines = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not line or line[0] in " \t":
            continue
        if line.lstrip().startswith("--"):
            continue
        lines.append((number, line))
    return lines


class LuaSourcesAreWellFormed(unittest.TestCase):
    def test_the_expected_modules_exist(self) -> None:
        self.assertTrue(DISSECTOR_PATH.is_file(), f"missing {DISSECTOR_PATH}")
        names = {path.name for path in _module_files()}
        for required in ("util.lua", "split.lua", "fields.lua", "iso7816.lua", "tables.lua"):
            with self.subTest(module=required):
                self.assertIn(required, names)

    def test_every_file_carries_the_licence_header(self) -> None:
        for path in _all_lua_files():
            with self.subTest(path=path.name):
                head = path.read_text(encoding="utf-8")[:400]
                self.assertIn("SPDX-License-Identifier: GPL-3.0-or-later", head)
                self.assertIn("Copyright (c) 2026 1oT", head)

    def test_modules_return_a_table(self) -> None:
        for path in _module_files():
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8").rstrip()
                self.assertTrue(
                    text.endswith("return M"),
                    f"{path.name} must end with `return M` to be require-able",
                )


class LuaModulesArePure(unittest.TestCase):
    """A module executed standalone by the plugin loader must do nothing."""

    def test_no_module_registers_at_load_time(self) -> None:
        for path in _module_files():
            text = path.read_text(encoding="utf-8")
            for number, line in _top_level_lines(text):
                for construct in REGISTERING_CONSTRUCTS:
                    if construct in line:
                        self.fail(
                            f"{path.name}:{number} calls {construct} at module "
                            "scope. The Wireshark plugin loader runs this file "
                            "standalone, so registration must stay in "
                            "yggdrasim_apdu.lua."
                        )

    def test_no_module_touches_the_filesystem_at_load_time(self) -> None:
        for path in _module_files():
            text = path.read_text(encoding="utf-8")
            for number, line in _top_level_lines(text):
                for construct in ("io.open", "os.getenv"):
                    if construct in line:
                        self.fail(f"{path.name}:{number} calls {construct} at module scope")

    def test_no_file_uses_forbidden_constructs(self) -> None:
        for path in _all_lua_files():
            text = path.read_text(encoding="utf-8")
            for construct in FORBIDDEN_ANYWHERE:
                with self.subTest(path=path.name, construct=construct):
                    self.assertNotIn(construct, text)

    def test_the_entry_point_guards_against_double_loading(self) -> None:
        text = DISSECTOR_PATH.read_text(encoding="utf-8")
        self.assertIn("YGGDRASIM_APDU_LOADED", text)
        # The guard has to precede the Proto() call or it cannot help.
        guard_at = text.index("YGGDRASIM_APDU_LOADED")
        proto_at = text.index('Proto("yapdu"')
        self.assertLess(guard_at, proto_at)

    def test_the_entry_point_bootstraps_package_path(self) -> None:
        """Neither -X lua_script: nor the plugin loader sets package.path."""
        text = DISSECTOR_PATH.read_text(encoding="utf-8")
        self.assertIn("debug.getinfo", text)
        self.assertIn("package.path", text)

    def test_every_module_that_requires_also_bootstraps_the_path(self) -> None:
        """A module cannot assume the entry point ran first.

        Wireshark's plugin loader executes each file standalone in
        alphabetical order, so cat.lua runs before yggdrasim_apdu.lua.
        Without its own path bootstrap its require fails and the whole
        plugin is refused with "module 'yggdrasim_apdu.util' not found"
        -- which is what happened the first time this was installed into
        a real plugin directory.
        """
        for path in _module_files():
            text = path.read_text(encoding="utf-8")
            if 'require("yggdrasim_apdu.' not in text:
                continue
            with self.subTest(module=path.name):
                self.assertIn(
                    "debug.getinfo",
                    text,
                    f"{path.name} requires a sibling module but never puts "
                    "its own directory on package.path",
                )
                bootstrap_at = text.index("package.path")
                first_require = text.index('require("yggdrasim_apdu.')
                self.assertLess(
                    bootstrap_at,
                    first_require,
                    f"{path.name} bootstraps package.path after its first "
                    "require, which is too late",
                )


class LuaSourcesAreAsciiClean(unittest.TestCase):
    def test_no_banned_typography(self) -> None:
        # Escapes, not literals: spelling these out would make this
        # file its own counter-example under the repo hygiene scanner.
        banned = {
            "em dash": "\u2014",
            "en dash": "\u2013",
            "left single quote": "\u2018",
            "right single quote": "\u2019",
            "left double quote": "\u201c",
            "right double quote": "\u201d",
            "section sign": "\u00a7",
        }
        for path in _all_lua_files():
            text = path.read_text(encoding="utf-8")
            for description, character in banned.items():
                with self.subTest(path=path.name, character=description):
                    self.assertNotIn(character, text)


class LuaLoadsUnderTshark(unittest.TestCase):
    """The dissector actually loads. Nothing else in the suite matters otherwise."""

    @classmethod
    def setUpClass(cls) -> None:
        import tempfile

        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "load.pcap",
            [Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("3F00"),
                      bytes.fromhex("9000"))],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_loading_emits_no_lua_error(self) -> None:
        result = run_tshark(
            ["-X", f"lua_script:{DISSECTOR_PATH}", "-r", str(self.capture)]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Lua Error", result.stderr)
        self.assertNotIn("stack traceback", result.stderr)

    def test_the_protocol_registers_its_own_layer(self) -> None:
        result = run_tshark(
            [
                "-X",
                f"lua_script:{DISSECTOR_PATH}",
                "-r",
                str(self.capture),
                "-T",
                "fields",
                "-e",
                "frame.protocols",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("yapdu", result.stdout)

    def test_the_stock_gsm_sim_dissector_still_runs(self) -> None:
        """Binding to gsmtap.type displaces gsm_sim unless we chain it."""
        result = run_tshark(
            [
                "-X",
                f"lua_script:{DISSECTOR_PATH}",
                "-r",
                str(self.capture),
                "-T",
                "fields",
                "-e",
                "gsm_sim.apdu.ins",
            ]
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("0xa4", result.stdout.lower())


if __name__ == "__main__":
    unittest.main()
