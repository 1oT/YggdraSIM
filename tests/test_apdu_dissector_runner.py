# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Command construction, installation and packaging for the dissector.

Pure Python: no tshark is invoked, so this module runs everywhere. It
covers the parts that break quietly -- a misplaced ``-X`` that stops the
Lua loading, a packaging file that forgets a new Lua module so the wheel
ships a dissector that cannot ``require`` its own tables.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from Tools.ApduDissector import install as installer
from Tools.ApduDissector import sidecar
from Tools.ApduDissector import tshark_runner
from Tools.ApduDissector.main import run_cli

REPO_ROOT = Path(__file__).resolve().parent.parent
LUA_ROOT = REPO_ROOT / "Tools" / "ApduDissector" / "lua"


class DissectorLocation(unittest.TestCase):
    def test_the_entry_point_is_bundled(self) -> None:
        path = tshark_runner.locate_dissector()
        self.assertTrue(path.is_file(), f"missing {path}")
        self.assertEqual(path.name, "yggdrasim_apdu.lua")

    def test_availability_reflects_the_filesystem(self) -> None:
        self.assertTrue(tshark_runner.dissector_is_available())
        with tempfile.TemporaryDirectory() as directory:
            self.assertFalse(
                tshark_runner.dissector_is_available(module_dir=Path(directory))
            )


class DissectorArguments(unittest.TestCase):
    """Callers splat these into an argv list, so the empty cases matter."""

    def test_arguments_name_the_bundled_script(self) -> None:
        arguments = tshark_runner.dissector_arguments(environ={})
        self.assertEqual(arguments[0], "-X")
        self.assertTrue(arguments[1].startswith("lua_script:"))
        self.assertIn("yggdrasim_apdu.lua", arguments[1])

    def test_the_env_var_switches_it_off(self) -> None:
        arguments = tshark_runner.dissector_arguments(
            environ={tshark_runner.ENABLED_ENV_VAR: "0"}
        )
        self.assertEqual(arguments, [])

    def test_a_missing_dissector_yields_no_arguments(self) -> None:
        """A partial install must not stop a capture from starting."""
        with tempfile.TemporaryDirectory() as directory:
            arguments = tshark_runner.dissector_arguments(
                module_dir=Path(directory), environ={}
            )
            self.assertEqual(arguments, [])

    def test_any_other_value_leaves_it_enabled(self) -> None:
        for value in ("", "1", "true", "yes"):
            with self.subTest(value=value):
                self.assertTrue(
                    tshark_runner.dissector_enabled(
                        {tshark_runner.ENABLED_ENV_VAR: value}
                    )
                )


class InvocationShape(unittest.TestCase):
    def test_lua_script_precedes_the_capture(self) -> None:
        """Some builds ignore -X once -r has been consumed."""
        invocation = tshark_runner.build_tshark_invocation(
            pcap_path=Path("/tmp/example.pcap"), existing_env={}
        )
        command = list(invocation.command)
        self.assertEqual(command[1], "-X")
        self.assertTrue(command[2].startswith("lua_script:"))
        self.assertLess(command.index("-X"), command.index("-r"))

    def test_the_gsmtap_decode_rule_is_passed(self) -> None:
        invocation = tshark_runner.build_tshark_invocation(
            pcap_path=Path("/tmp/example.pcap"), existing_env={}
        )
        command = list(invocation.command)
        self.assertIn("-d", command)
        self.assertIn("udp.port==4729,gsmtap", command)

    def test_extra_arguments_come_last(self) -> None:
        invocation = tshark_runner.build_tshark_invocation(
            pcap_path=Path("/tmp/example.pcap"),
            extra_args=["-V"],
            existing_env={},
        )
        self.assertEqual(invocation.command[-1], "-V")

    def test_the_sidecar_is_passed_through_the_environment(self) -> None:
        invocation = tshark_runner.build_tshark_invocation(
            pcap_path=Path("/tmp/example.pcap"),
            sidecar_path=Path("/tmp/example.sidecar.json"),
            existing_env={},
        )
        self.assertIn(tshark_runner.SIDECAR_ENV_VAR, invocation.env)

    def test_no_sidecar_leaves_the_variable_unset(self) -> None:
        invocation = tshark_runner.build_tshark_invocation(
            pcap_path=Path("/tmp/example.pcap"), existing_env={}
        )
        self.assertNotIn(tshark_runner.SIDECAR_ENV_VAR, invocation.env)


class FolderParsing(unittest.TestCase):
    """``tshark -G folders`` pads its labels and appends a colon."""

    SAMPLE = (
        "Personal configuration:\t/home/u/.config/wireshark\n"
        "Personal Lua Plugins:\t/home/u/.local/lib/wireshark/plugins\n"
        "Global Lua Plugins:  \t/usr/lib/wireshark/plugins\n"
    )

    def test_the_personal_folder_is_found(self) -> None:
        self.assertEqual(
            installer.parse_personal_lua_folder(self.SAMPLE),
            "/home/u/.local/lib/wireshark/plugins",
        )

    def test_the_global_folder_is_not_mistaken_for_it(self) -> None:
        folder = installer.parse_personal_lua_folder(self.SAMPLE)
        self.assertNotIn("/usr/lib", folder)

    def test_a_build_without_lua_reports_nothing(self) -> None:
        self.assertEqual(
            installer.parse_personal_lua_folder("Personal configuration:\t/x\n"), ""
        )

    def test_empty_input_is_handled(self) -> None:
        self.assertEqual(installer.parse_personal_lua_folder(""), "")


class Installation(unittest.TestCase):
    def test_install_copies_the_whole_lua_tree(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = installer.install(override=Path(directory))
            copied = sorted(
                path.relative_to(plan.destination).as_posix()
                for path in plan.destination.rglob("*.lua")
            )
            self.assertIn("yggdrasim_apdu.lua", copied)
            self.assertIn("yggdrasim_apdu/tables.lua", copied)
            self.assertIn("yggdrasim_apdu/split.lua", copied)

    def test_the_diagnostic_probe_is_not_installed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = installer.install(override=Path(directory))
            names = {path.name for path in plan.destination.rglob("*.lua")}
            self.assertNotIn("probe_wireshark_env.lua", names)

    def test_install_is_repeatable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            installer.install(override=Path(directory))
            plan = installer.install(override=Path(directory))
            self.assertTrue(plan.destination.is_dir())

    def test_uninstall_removes_the_copy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            plan = installer.install(override=Path(directory))
            installer.uninstall(override=Path(directory))
            self.assertFalse(plan.destination.exists())


class CommandLine(unittest.TestCase):
    def test_path_prints_the_dissector(self) -> None:
        import io

        out = io.StringIO()
        self.assertEqual(run_cli(["path"], stdout=out, stderr=io.StringIO()), 0)
        self.assertIn("yggdrasim_apdu.lua", out.getvalue())

    def test_decode_rejects_a_missing_capture(self) -> None:
        import io

        err = io.StringIO()
        code = run_cli(
            ["decode", "--pcap", "/nonexistent/none.pcap"],
            stdout=io.StringIO(),
            stderr=err,
        )
        self.assertEqual(code, 1)
        self.assertIn("capture not found", err.getvalue())

    def test_install_dry_run_copies_nothing(self) -> None:
        import io

        with tempfile.TemporaryDirectory() as directory:
            out = io.StringIO()
            code = run_cli(
                ["install", "--dest", directory, "--dry-run"],
                stdout=out,
                stderr=io.StringIO(),
            )
            self.assertEqual(code, 0)
            self.assertIn("dry run", out.getvalue())
            self.assertEqual(list(Path(directory).rglob("*.lua")), [])


class PackagingCoversEveryLuaFile(unittest.TestCase):
    """A Lua module missing from packaging ships a dissector that cannot load.

    ``require("yggdrasim_apdu.tables")`` fails at runtime if the wheel or
    the frozen bundle left that file out, and the failure surfaces as an
    empty decode rather than an install error.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.lua_files = sorted(
            path.relative_to(REPO_ROOT).as_posix()
            for path in LUA_ROOT.rglob("*.lua")
            if path.name != "probe_wireshark_env.lua"
        )

    def test_there_is_something_to_check(self) -> None:
        self.assertGreater(len(self.lua_files), 5)

    def test_the_manifest_includes_the_tree(self) -> None:
        manifest = (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn("recursive-include Tools/ApduDissector/lua *.lua", manifest)

    def test_pyproject_declares_the_package_and_its_data(self) -> None:
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('"Tools.ApduDissector" = [', pyproject)
        self.assertIn('"Tools.ApduDissector",', pyproject)
        self.assertIn(
            'yggdrasim-apdu-dissect = "yggdrasim_common.console_scripts:apdu_dissect"',
            pyproject,
        )

    def test_the_frozen_bundle_lists_every_lua_file(self) -> None:
        data = json.loads(
            (REPO_ROOT / "scripts" / "release" / "bundle-data.json").read_text(
                encoding="utf-8"
            )
        )
        bundled = {entry["path"] for entry in data["entries"]}
        for path in self.lua_files:
            with self.subTest(path=path):
                self.assertIn(path, bundled)

    def test_the_spec_publishes_the_package(self) -> None:
        spec = (REPO_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")
        self.assertIn('"Tools.ApduDissector"', spec)


class SidecarSplitMatchesTheDissector(unittest.TestCase):
    """The sidecar and the Lua have to cut the frame in the same place.

    An entry is bound to a frame by comparing its ``command_hex`` against
    the bytes on the wire, so the two splits agreeing is not a tidiness
    concern -- it is the whole binding. When they disagree by one byte
    the operator is told the sidecar came from a different capture,
    which is both false and the most misleading thing the tool can say.

    No tshark needed: this exercises the Python side against the rule
    the Lua scorer applies.
    """

    def split(self, hex_text: str) -> int | None:
        result = sidecar.split_exchange(bytes.fromhex(hex_text))
        if result is None:
            return None
        return len(result[0])

    def test_a_wrapped_case_three_command_keeps_its_whole_body(self) -> None:
        # 84 E2 91 00 with a 24-byte body, answered by 9000 alone.
        payload = "84E2910018" + ("00" * 24) + "9000"
        self.assertEqual(self.split(payload), 29)

    def test_a_wrapped_case_four_command_keeps_its_trailing_le(self) -> None:
        """A GlobalPlatform INSTALL is sent case 4.

        Assuming case 3 leaves the Le byte on the response side, so the
        recorded command is one byte short of the frame.
        """
        payload = "84E60C0020" + ("11" * 32) + "00" + "9000"
        self.assertEqual(self.split(payload), 38)

    def test_response_data_is_attributed_to_a_case_four_command(self) -> None:
        # The response carries 4 bytes plus SW1SW2, which a case 3
        # command could not have asked for.
        payload = "84CA00A004" + ("22" * 4) + "04" + "AABBCCDD" + "9000"
        self.assertEqual(self.split(payload), 10)

    def test_an_unwrapped_command_is_not_a_sidecar_candidate(self) -> None:
        self.assertIsNone(self.split("00A40004023F009000"))

    def test_a_truncated_frame_is_refused_rather_than_guessed(self) -> None:
        self.assertIsNone(self.split("84E2910018" + ("00" * 4)))


class SidecarSessionContext(unittest.TestCase):
    """The replay engine filters on facts the builder has to supply."""

    def test_a_successful_plaintext_select_records_the_aid(self) -> None:
        payload = bytes.fromhex("00A4040405A0000005599000")
        self.assertEqual(sidecar._selected_aid(payload), "A000000559")

    def test_a_refused_select_does_not_move_the_selection(self) -> None:
        payload = bytes.fromhex("00A4040405A0000005596A82")
        self.assertIsNone(sidecar._selected_aid(payload))

    def test_a_secure_messaged_select_is_ignored(self) -> None:
        """Its body is ciphertext, not an AID."""
        payload = bytes.fromhex("0CA4040405A0000005599000")
        self.assertIsNone(sidecar._selected_aid(payload))


if __name__ == "__main__":
    unittest.main()
