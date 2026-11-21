# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""ProfilePackage shell verbs for the universal placeholder test values."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from Tools.ProfilePackage.shell import ProfilePackageShell

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"
_HEADER_ICCID_HEX = "89880811111111111112"
_TEST_ICCID_HEX = "8988201234567890123F"


class UniversalTokenShellTests(unittest.TestCase):

    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self.root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.root)
        self.list_path = self.root / "universal.csv"
        self.list_path.write_text(
            f"iccidICCID10,{_TEST_ICCID_HEX}\nICCID,89880811111111111112\nbadBINARY2,004\n",
            encoding="utf-8",
        )
        self._env = mock.patch.dict(
            os.environ, {"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.list_path)}
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        self._workspace.cleanup()

    def _run(self, handler, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            handler(arg)
        return buffer.getvalue()

    def test_show_lists_entries_and_rejected_lines(self) -> None:
        output = self._run(self.shell._cmd_universal_tokens, "")

        self.assertIn(str(self.list_path), output)
        self.assertIn("2 usable entries", output)
        self.assertIn("iccidICCID10", output)
        self.assertIn("line 3: badBINARY2: odd hex length (3 chars)", output)

    def test_path_prints_the_configured_location(self) -> None:
        output = self._run(self.shell._cmd_universal_tokens, "PATH")

        self.assertEqual(output.strip(), str(self.list_path))

    def test_unknown_verb_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            self.shell._cmd_universal_tokens("FROBNICATE")

    def test_apply_fills_json_token_definitions_in_place(self) -> None:
        template = self.root / "template.json"
        template.write_text(
            json.dumps({"sections": {"header": {"iccid": {"hex": "{ICCID}"}, "imsi": {"hex": "{IMSI}"}}}}),
            encoding="utf-8",
        )

        output = self._run(self.shell._cmd_apply_universal_tokens, str(template))

        loaded = json.loads(template.read_text(encoding="utf-8"))
        self.assertEqual(loaded["__ygg_token_defs__"], {"ICCID": {"hex": "89880811111111111112"}})
        self.assertEqual(loaded["__ygg_placeholder_style__"], "brace")
        self.assertIn("1 definition(s) added, 0 replaced, 0 kept", output)
        self.assertIn("Remaining placeholders without defs: IMSI", output)

        # A second run keeps the existing definition unless told otherwise.
        loaded["__ygg_token_defs__"]["ICCID"] = {"hex": "00" * 10}
        template.write_text(json.dumps(loaded), encoding="utf-8")
        kept = self._run(self.shell._cmd_apply_universal_tokens, str(template))
        self.assertIn("0 replaced, 1 kept", kept)
        replaced = self._run(self.shell._cmd_apply_universal_tokens, f"{template} OVERWRITE")
        self.assertIn("1 replaced, 0 kept", replaced)
        self.assertEqual(
            json.loads(template.read_text(encoding="utf-8"))["__ygg_token_defs__"]["ICCID"]["hex"],
            "89880811111111111112",
        )

    def test_apply_without_a_list_fails_with_the_path(self) -> None:
        self.list_path.unlink()
        template = self.root / "template.json"
        template.write_text(json.dumps({"sections": {}}), encoding="utf-8")

        with self.assertRaises(ValueError) as caught:
            self.shell._cmd_apply_universal_tokens(str(template))
        self.assertIn(str(self.list_path), str(caught.exception))


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class UniversalTokenInlineTemplateShellTests(unittest.TestCase):

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        self._workspace = tempfile.TemporaryDirectory()
        self.root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.root)
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self.template = self.root / "template.hex"
        self.template.write_text(
            reference.replace(_HEADER_ICCID_HEX, "{iccidICCID10}"), encoding="utf-8"
        )
        self.list_path = self.root / "universal.csv"
        self.list_path.write_text(f"iccidICCID10,{_TEST_ICCID_HEX}\n", encoding="utf-8")
        self._env = mock.patch.dict(
            os.environ, {"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.list_path)}
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        self._workspace.cleanup()

    def _run(self, handler, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            handler(arg)
        return buffer.getvalue()

    def test_check_names_the_answered_occurrence(self) -> None:
        output = self._run(self.shell._cmd_universal_tokens, f"CHECK {self.template}")

        self.assertIn("1 placeholder occurrence(s); the list answers 1", output)
        self.assertIn("+ {iccidICCID10}", output)

    def test_apply_records_raw_values_in_the_variables_sidecar(self) -> None:
        output = self._run(self.shell._cmd_apply_universal_tokens, str(self.template))

        sidecar = self.template.with_suffix(".variables.json")
        self.assertTrue(sidecar.is_file())
        stored = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(stored["raw_values"], {"iccidICCID10": _TEST_ICCID_HEX})
        self.assertIn("1 occurrence(s) took universal bytes", output)

    def test_materialize_with_the_universal_flag_writes_the_bytes(self) -> None:
        out_path = self.root / "complete.der"

        output = self._run(
            self.shell._cmd_materialize_template, f"{self.template} {out_path} --universal"
        )

        self.assertTrue(out_path.is_file())
        self.assertIn(_TEST_ICCID_HEX, out_path.read_bytes().hex().upper())
        self.assertIn("[universal]", output)

    def test_materialize_takes_the_universal_defaults_without_the_flag(self) -> None:
        out_path = self.root / "defaults.der"

        self._run(self.shell._cmd_materialize_template, f"{self.template} {out_path}")

        self.assertIn(_TEST_ICCID_HEX, out_path.read_bytes().hex().upper())

    def test_materialize_refuses_when_the_defaults_are_off(self) -> None:
        with mock.patch.dict(os.environ, {"YGGDRASIM_SAIP_UNIVERSAL_DEFAULTS": "0"}):
            with self.assertRaises(ValueError) as caught:
                self.shell._cmd_materialize_template(f"{self.template} {self.root / 'x.der'}")
        self.assertIn("Unresolved inline template variable(s): iccid", str(caught.exception))


@unittest.skipUnless(_REFERENCE_PROFILE.is_file(), "reference test profile fixture is required")
class TokenListShellTests(unittest.TestCase):
    """``TOKEN-LISTS`` manages the universal list, the library and a
    template's binding; ``MATERIALIZE-TEMPLATE --universal`` consults the
    bound list before the universal one."""

    _OTHER_ICCID_HEX = "8988209876543210987F"

    def setUp(self) -> None:
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed: {error}")
        self._workspace = tempfile.TemporaryDirectory()
        self.root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.root)
        self._env = mock.patch.dict(
            os.environ,
            {
                "YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.root / "universal.csv"),
                "YGGDRASIM_SAIP_TOKEN_LISTS": str(self.root / "lib"),
                "YGGDRASIM_RUNTIME_ROOT": str(self.root / "runtime"),
            },
        )
        self._env.start()
        os.environ.pop("YGGDRASIM_SAIP_UNIVERSAL_DEFAULTS", None)
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self.template = self.root / "template.hex"
        self.template.write_text(
            reference.replace(_HEADER_ICCID_HEX, "{iccidICCID10}"), encoding="utf-8"
        )

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        self._workspace.cleanup()

    def _lists(self, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_token_lists(arg)
        return buffer.getvalue()

    def test_set_unset_show_and_list_cover_the_library(self) -> None:
        self.assertIn("missing", self._lists(""))
        self._lists(f"SET universal iccidICCID10 {_TEST_ICCID_HEX}")
        self._lists(f"SET opA iccidICCID10 {self._OTHER_ICCID_HEX}")
        self._lists("SET opA pin1TEXT4utf8 31323334")
        self.assertIn("2 usable entries", self._lists("SHOW opA"))
        self.assertIn("pin1TEXT4utf8 removed", self._lists("UNSET opA pin1TEXT4utf8"))
        listing = self._lists("LIST")
        self.assertIn("Universal", listing)
        self.assertIn("opA", listing)
        # A new library list is written in the default, typed, style whatever
        # spelling the SET line used.
        self.assertEqual(
            (self.root / "lib" / "opA.csv").read_text(encoding="utf-8"),
            f"{{iccid:ICCID:10}},{self._OTHER_ICCID_HEX}\n",
        )
        with self.assertRaises(ValueError):
            self._lists("SET opA accBINARY2 00")
        with self.assertRaises(ValueError):
            self._lists("UNSET opA nothere")
        with self.assertRaises(ValueError):
            self._lists("DELETE universal")
        self.assertIn("deleted opA", self._lists("DELETE opA"))
        self.assertFalse((self.root / "lib" / "opA.csv").exists())

    def test_export_style_and_set_follow_the_list_style(self) -> None:
        self._lists(f"SET universal {{iccid:ICCID:10}} {_TEST_ICCID_HEX}")
        universal = self.root / "universal.csv"
        self.assertEqual(
            universal.read_text(encoding="utf-8"), f"{{iccid:ICCID:10}},{_TEST_ICCID_HEX}\n"
        )
        # A compact spelling typed later still lands in the list's typed style,
        # the modifier in its snake_case spelling.
        self._lists("SET universal pin1TEXT4utf8 31323334")
        self.assertIn("{pin1:TEXT:4:utf_8},31323334", universal.read_text(encoding="utf-8"))
        self.assertIn("style typed", self._lists("SHOW universal"))
        self.assertIn("typed", self._lists("LIST"))
        # The typed entry answers the template's compact literal.
        self.assertIn("+ {iccidICCID10}", self._lists("CHECK template.hex"))

        exported = self._lists("EXPORT template.hex exported STYLE=bracket")
        self.assertIn("(style bracket)", exported)
        written = (self.root / "lib" / "exported.csv").read_text(encoding="utf-8")
        self.assertIn("# style: bracket\n", written)
        self.assertIn(f"[iccidICCID10],{_TEST_ICCID_HEX}", written)
        self.assertIn("(style typed)", self._lists("EXPORT template.hex followed"))
        self.assertIn(
            f"{{iccid:ICCID:10}},{_TEST_ICCID_HEX}",
            (self.root / "lib" / "followed.csv").read_text(encoding="utf-8"),
        )
        with self.assertRaises(ValueError):
            self._lists("EXPORT template.hex other STYLE=fancy")

    def test_bind_check_export_and_materialize_follow_the_bound_list(self) -> None:
        self._lists(f"SET universal iccidICCID10 {_TEST_ICCID_HEX}")
        self._lists(f"SET opA iccidICCID10 {self._OTHER_ICCID_HEX}")
        self.assertIn("universal.csv line 1", self._lists("CHECK template.hex"))

        self.assertIn("bound to opA", self._lists("BIND template.hex opA"))
        sidecar = json.loads((self.root / "template.variables.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar["test_value_list"], "opA")
        store = json.loads(
            (self.root / "runtime" / "state" / "saip_test_value_lists.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(store["bindings"][str(self.template.resolve())]["list"], "opA")
        check = self._lists("CHECK template.hex")
        self.assertIn("bound list opA", check)
        self.assertIn("opA.csv line 1", check)

        exported = self._lists("EXPORT template.hex exported")
        self.assertIn("1 entry written", exported)
        # The universal list was created by SET above, so it is written in the
        # default, typed, style and the export follows it.
        self.assertIn(
            f"{{iccid:ICCID:10}},{self._OTHER_ICCID_HEX}",
            (self.root / "lib" / "exported.csv").read_text(encoding="utf-8"),
        )
        with self.assertRaises(ValueError):
            self._lists("EXPORT template.hex exported")
        with self.assertRaises(ValueError):
            self._lists("EXPORT template.hex universal")

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_materialize_template("template.hex out.der --universal")
        self.assertIn("bound list: opA", buffer.getvalue())
        self.assertIn(self._OTHER_ICCID_HEX, (self.root / "out.der").read_bytes().hex().upper())

        self.assertIn("bound to Universal", self._lists("BIND template.hex universal"))
        sidecar = json.loads((self.root / "template.variables.json").read_text(encoding="utf-8"))
        self.assertNotIn("test_value_list", sidecar)
        with self.assertRaises(ValueError):
            self._lists("BIND template.hex nothere")

    def test_tokens_namespace_reaches_the_lists(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_tokens("LISTS LIST")
        self.assertIn("test-value list(s)", buffer.getvalue())
        with self.assertRaises(ValueError):
            self._lists("FROB")



class VariablesVerbTests(unittest.TestCase):
    """``VARIABLES`` is one verb over a template's typed values, lists and export."""

    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self.root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.root)
        self.list_path = self.root / "universal.csv"
        self.list_path.write_text(f"iccidICCID10,{_TEST_ICCID_HEX}\n", encoding="utf-8")
        self._env = mock.patch.dict(
            os.environ, {"YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.list_path)}
        )
        self._env.start()
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self.template = self.root / "template.varder"
        self.template.write_text(
            reference.replace(_HEADER_ICCID_HEX, "{iccidICCID10}"), encoding="utf-8"
        )
        self.shell.bridge.set_input_file(str(self.template))

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        self._workspace.cleanup()

    def _run(self, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_variables(arg)
        return buffer.getvalue()

    def test_list_names_the_list_that_answers_an_open_placeholder(self) -> None:
        output = self._run("")
        self.assertIn("bound list: universal", output)
        self.assertRegex(output, rf"iccid\s+ICCID\s+10\s+{_TEST_ICCID_HEX}\s+universal.csv")
        self.assertIn("1 of 1 have a value; EXPORT is ready.", output)

    def test_set_writes_the_sidecar_and_clear_drops_it(self) -> None:
        output = self._run("SET iccid=8988201234567890123")
        self.assertIn("iccid: value set for 1 occurrence", output)
        sidecar = self.template.with_suffix(".variables.json")
        stored = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(stored["values"], {"iccid": "8988201234567890123"})
        listing = self._run("")
        self.assertRegex(listing, r"iccid\s+ICCID\s+10\s+8988201234567890123\s+typed")
        cleared = self._run("CLEAR iccid")
        self.assertIn("iccid: typed value cleared", cleared)
        stored = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(stored["values"], {})
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("CLEAR iccid")

    def test_set_refuses_a_value_the_placeholder_cannot_encode(self) -> None:
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("SET iccid=notdigits")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("SET nosuch=1")
        self.assertFalse(self.template.with_suffix(".variables.json").exists())

    def test_export_writes_the_complete_profile_from_the_list(self) -> None:
        out = self.root / "complete.der"
        output = self._run(f"EXPORT {out}")
        self.assertTrue(out.is_file())
        self.assertIn(_TEST_ICCID_HEX, out.read_bytes().hex().upper())
        self.assertTrue(output.strip())

    def test_generate_is_export_and_a_hex_target_takes_ascii_hex(self) -> None:
        out = self.root / "test_profile.hex"
        output = self._run(f"GENERATE {out}")
        self.assertIn("bytes DER as hex text", output)
        text = out.read_text(encoding="utf-8").strip()
        self.assertTrue(text and set(text) <= set("0123456789ABCDEF"))
        self.assertIn(_TEST_ICCID_HEX, text)
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("GENERATE")

    def test_usage_errors(self) -> None:
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("FROBNICATE")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("USE")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("EXPORT")


class VariablesVerbRemainderTests(unittest.TestCase):
    """The one verb covers both grammars, the lists and the typed spelling."""

    _JSON_TEMPLATE = {
        "sections": {"header": {"iccid": {"hex": "{ICCID}"}, "ki": {"hex": "{KI}"}}},
    }

    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self.root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.root)
        self.list_path = self.root / "universal.csv"
        self.list_path.write_text(
            f"iccidICCID10,{_TEST_ICCID_HEX}\nICCID,{_HEADER_ICCID_HEX}\n", encoding="utf-8"
        )
        self.lists_dir = self.root / "lists"
        self._env = mock.patch.dict(
            os.environ,
            {
                "YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.list_path),
                "YGGDRASIM_SAIP_TOKEN_LISTS": str(self.lists_dir),
            },
        )
        self._env.start()
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        self.compact = self.root / "compact.varder"
        self.compact.write_text(
            reference.replace(_HEADER_ICCID_HEX, "[iccidICCID10]"), encoding="utf-8"
        )
        self.tokens = self.root / "tokens.json"
        self.tokens.write_text(json.dumps(self._JSON_TEMPLATE), encoding="utf-8")

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        self._workspace.cleanup()

    def _run(self, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_variables(arg)
        return buffer.getvalue()

    def test_normalise_reports_then_rewrites_with_a_backup(self) -> None:
        self.shell.bridge.set_input_file(str(self.compact))
        dry = self._run("NORMALISE")
        self.assertIn("[iccidICCID10] -> {iccid:ICCID:10}", dry)
        self.assertIn("Dry run", dry)
        self.assertIn("[iccidICCID10]", self.compact.read_text(encoding="utf-8"))
        written = self._run("NORMALIZE IN-PLACE")
        self.assertIn("backup written", written)
        self.assertIn("{iccid:ICCID:10}", self.compact.read_text(encoding="utf-8"))
        backup = self.compact.with_suffix(self.compact.suffix + ".bak")
        self.assertIn("[iccidICCID10]", backup.read_text(encoding="utf-8"))
        again = self._run("NORMALISE")
        self.assertIn("already typed", again)
        # The values file keeps answering: the occurrence key did not change.
        listing = self._run("")
        self.assertRegex(listing, rf"iccid\s+ICCID\s+10\s+{_TEST_ICCID_HEX}\s+universal.csv")

    def test_normalise_output_and_flags(self) -> None:
        self.shell.bridge.set_input_file(str(self.compact))
        out = self.root / "typed.varder"
        self._run(f"NORMALISE OUTPUT={out}")
        self.assertIn("{iccid:ICCID:10}", out.read_text(encoding="utf-8"))
        self.assertIn("[iccidICCID10]", self.compact.read_text(encoding="utf-8"))
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("NORMALISE IN-PLACE OUTPUT=x.varder")
        self.shell.bridge.set_input_file(str(self.tokens))
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("NORMALISE")

    def test_fill_lists_and_export_list_reach_the_long_form(self) -> None:
        self.shell.bridge.set_input_file(str(self.compact))
        lists = self._run("LISTS")
        self.assertIn("test-value list(s)", lists)
        filled = self._run("FILL")
        self.assertTrue(filled.strip())
        sidecar = json.loads(self.compact.with_suffix(".variables.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar["raw_values"], {"iccidICCID10": _TEST_ICCID_HEX})
        exported = self._run("EXPORT-LIST mine")
        self.assertIn("mine", exported)
        written = (self.lists_dir / "mine.csv").read_text(encoding="utf-8")
        # A new list takes the typed spelling whatever the universal list uses.
        self.assertIn("# style: typed", written)
        self.assertIn(f"{{iccid:ICCID:10}},{_TEST_ICCID_HEX}", written)

    def test_token_template_list_set_clear_and_export(self) -> None:
        self.shell.bridge.set_input_file(str(self.tokens))
        listing = self._run("")
        self.assertIn("{NAME} tokens", listing)
        self.assertRegex(listing, r"ICCID\s+\(from the universal list on FILL\)\s+universal list")
        self.assertRegex(listing, r"KI\s+-\s+none")
        self.assertIn("0 of 2 have a definition", listing)
        self._run("SET KI=00112233445566778899AABBCCDDEEFF ICCID=8988201234567890123")
        loaded = json.loads(self.tokens.read_text(encoding="utf-8"))
        self.assertEqual(loaded["__ygg_token_defs__"]["KI"], {"hex": "00112233445566778899AABBCCDDEEFF"})
        self.assertIn("ICCID_EF", loaded["__ygg_token_defs__"])
        listing = self._run("")
        self.assertRegex(listing, r"KI\s+00112233445566778899AABBCCDDEEFF\s+defined")
        self.assertIn("2 of 2 have a definition; EXPORT is ready.", listing)
        self._run("CLEAR KI")
        loaded = json.loads(self.tokens.read_text(encoding="utf-8"))
        self.assertNotIn("KI", loaded["__ygg_token_defs__"])
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("SET NOSUCH=00")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("USE universal")
        with mock.patch.object(self.shell, "_cmd_apply_template") as apply:
            self._run(f"EXPORT {self.root / 'out.der'}")
        apply.assert_called_once()
        self.assertIn("out.der", apply.call_args[0][0])


class VariablesDefineTests(unittest.TestCase):
    """``VARIABLES DEFINE`` and ``TOKEN-LISTS SET`` declare or set a placeholder."""

    def setUp(self) -> None:
        self._workspace = tempfile.TemporaryDirectory()
        self.root = Path(self._workspace.name)
        self.shell = ProfilePackageShell(workspace_root=self.root)
        self.list_path = self.root / "universal.csv"
        self.lists_dir = self.root / "lists"
        self._env = mock.patch.dict(
            os.environ,
            {
                "YGGDRASIM_SAIP_UNIVERSAL_TOKENS": str(self.list_path),
                "YGGDRASIM_SAIP_TOKEN_LISTS": str(self.lists_dir),
            },
        )
        self._env.start()

    def tearDown(self) -> None:
        self._env.stop()
        shutil.rmtree(self.root, ignore_errors=True)
        self._workspace.cleanup()

    def _run(self, arg: str) -> str:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_variables(arg)
        return buffer.getvalue()

    def test_define_declares_then_sets_and_the_listing_flags_the_declaration(self) -> None:
        declared = self._run("DEFINE {smsc:MSISDN:6:nibble_swap}")
        self.assertIn("declared without a value", declared)
        self.assertIn("length byte", declared)
        self.assertEqual(self.list_path.read_text(encoding="utf-8"), "{smsc:MSISDN:6:nibble_swap},\n")
        reference = _REFERENCE_PROFILE.read_text(encoding="utf-8")
        template = self.root / "t.varder"
        template.write_text(
            reference.replace("98888011111111111111", "{smsc:MSISDN:10:nibble_swap}"), encoding="utf-8"
        )
        self.shell.bridge.set_input_file(str(template))
        self._run("DEFINE {smsc:MSISDN:10:nibble_swap}")
        listing = self._run("")
        self.assertRegex(listing, r"smsc\s+MSISDN\s+10\s+-\s+declared, no value \(length byte not reconciled\)")
        self._run("DEFINE {smsc:MSISDN:10:nibble_swap} 551018010700")
        # The template opens with the list's bytes stored for the occurrence.
        listing = self._run("")
        self.assertRegex(listing, r"smsc\s+MSISDN\s+10\s+550181107000FFFFFFFF\s+universal.csv")
        self.assertIn("{smsc:MSISDN:10:nibble_swap},550181107000FFFFFFFF", self.list_path.read_text(encoding="utf-8"))
        typed = self._run("DEFINE [pin1TEXT4] 1234 LIST=opA")
        self.assertIn("{pin1:TEXT:4} = 31323334", typed)
        self.assertEqual((self.lists_dir / "opA.csv").read_text(encoding="utf-8"), "{pin1:TEXT:4},31323334\n")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("DEFINE notaliteral")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("DEFINE {x:BOGUS:4}")
        with self.assertRaises(ValueError):
            self.shell._cmd_variables("DEFINE {pin1:TEXT:4} 12345")

    def test_token_lists_set_without_a_value_declares(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_token_lists("SET universal {ki:BINARY:16}")
        self.assertIn("declared without a value", buffer.getvalue())
        self.assertEqual(self.list_path.read_text(encoding="utf-8"), "{ki:BINARY:16},\n")
