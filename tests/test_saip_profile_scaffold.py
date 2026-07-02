# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import contextlib
import io
import json
import tempfile
import unittest
from collections import OrderedDict
from pathlib import Path
from unittest import mock

from Tools.ProfilePackage.saip_profile_scaffold import (
    build_scaffold_profile_document,
    default_preset_id,
    get_preset,
    list_profile_presets,
    normalize_preset_id,
)
from Tools.ProfilePackage.shell import ProfilePackageShell


class _StubProfileElement:
    def __init__(self, pe_type: str) -> None:
        self.type = pe_type
        self.decoded = OrderedDict()
        self.pe_sequence = None
        self.header = {}


class _StubProfileElementSequence:
    def __init__(self) -> None:
        self.pe_list: list[_StubProfileElement] = []
        self._processed_calls = 0
        self._renumber_calls = 0

    def _process_pelist(self) -> None:
        self._processed_calls += 1

    def renumber_identification(self) -> None:
        self._renumber_calls += 1


def _install_stub_pysim(monkeypatch_target: unittest.TestCase) -> None:
    """Replace pySim-backed factories with lightweight stubs for deterministic tests."""
    import Tools.ProfilePackage.saip_profile_scaffold as scaffold_module

    captured_factories: dict[str, mock.Mock] = {}

    def _make_factory(pe_type: str) -> mock.Mock:
        factory = mock.Mock()

        def _call() -> _StubProfileElement:
            stub = _StubProfileElement(pe_type)
            return stub

        factory.side_effect = _call
        captured_factories[pe_type] = factory
        return factory

    fake_factories = {
        "header": _make_factory("header"),
        "end": _make_factory("end"),
        "mf": _make_factory("mf"),
        "pinCodes": _make_factory("pinCodes"),
        "pukCodes": _make_factory("pukCodes"),
        "telecom": _make_factory("telecom"),
        "usim": _make_factory("usim"),
        "opt-usim": _make_factory("opt-usim"),
        "isim": _make_factory("isim"),
        "opt-isim": _make_factory("opt-isim"),
        "akaParameter": _make_factory("akaParameter"),
    }

    factory_patch = mock.patch.object(
        scaffold_module,
        "_factory_map",
        return_value=fake_factories,
    )
    factory_patch.start()
    monkeypatch_target.addCleanup(factory_patch.stop)

    fake_pysim_module = mock.Mock()
    fake_pysim_module.ProfileElementSequence = _StubProfileElementSequence

    pysim_patch = mock.patch.dict(
        "sys.modules",
        {"pySim.esim.saip": fake_pysim_module},
    )
    pysim_patch.start()
    monkeypatch_target.addCleanup(pysim_patch.stop)

    ensure_patch = mock.patch.object(
        scaffold_module,
        "ensure_workspace_pysim_on_path",
    )
    ensure_patch.start()
    monkeypatch_target.addCleanup(ensure_patch.stop)


class ProfileScaffoldModuleTests(unittest.TestCase):
    def test_list_profile_presets_exposes_minimal_and_usim_entries(self) -> None:
        preset_ids = [preset.preset_id for preset in list_profile_presets()]
        self.assertIn("MINIMAL", preset_ids)
        self.assertIn("USIM", preset_ids)
        self.assertIn("USIM-ISIM", preset_ids)
        self.assertIn("FULL", preset_ids)

    def test_default_preset_id_is_known(self) -> None:
        preset_ids = {preset.preset_id for preset in list_profile_presets()}
        self.assertIn(default_preset_id(), preset_ids)

    def test_normalize_preset_id_accepts_lowercase_names(self) -> None:
        self.assertEqual(normalize_preset_id("minimal"), "MINIMAL")
        self.assertEqual(normalize_preset_id("Usim-Isim"), "USIM-ISIM")

    def test_normalize_preset_id_rejects_unknown_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unknown profile preset"):
            normalize_preset_id("does-not-exist")

    def test_get_preset_minimal_contains_header_and_end_only(self) -> None:
        preset = get_preset("MINIMAL")
        self.assertEqual(preset.menu_ids, ("header", "end"))

    def test_build_scaffold_profile_document_minimal_returns_header_end_sections(self) -> None:
        _install_stub_pysim(self)

        with tempfile.TemporaryDirectory() as temp_dir:
            document = build_scaffold_profile_document("MINIMAL", Path(temp_dir))

        self.assertIn("sections", document)
        self.assertEqual(
            list(document["sections"].keys()),
            ["header", "end"],
        )
        self.assertIn("intro", document)
        self.assertTrue(
            any("MINIMAL" in line for line in document["intro"]),
            f"intro should mention preset name; got {document['intro']!r}",
        )

    def test_build_scaffold_profile_document_usim_preset_calls_expected_factories(self) -> None:
        _install_stub_pysim(self)

        with tempfile.TemporaryDirectory() as temp_dir:
            document = build_scaffold_profile_document("USIM", Path(temp_dir))

        self.assertEqual(
            list(document["sections"].keys()),
            [
                "header",
                "mf",
                "pinCodes",
                "pukCodes",
                "usim",
                "opt-usim",
                "akaParameter",
                "end",
            ],
        )


class NewProfileScaffoldShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_workspace = tempfile.TemporaryDirectory()
        workspace_root = Path(self._temp_workspace.name)
        self.shell = ProfilePackageShell(workspace_root=workspace_root)

    def tearDown(self) -> None:
        self._temp_workspace.cleanup()

    def test_cmd_presets_lists_all_known_presets(self) -> None:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            self.shell._cmd_presets("")

        output = buffer.getvalue()
        self.assertIn("MINIMAL", output)
        self.assertIn("USIM", output)
        self.assertIn("USIM-ISIM", output)
        self.assertIn("FULL", output)
        self.assertIn("(default)", output)

    def test_cmd_new_template_writes_tagged_json_for_minimal_preset(self) -> None:
        fake_document = {
            "intro": ["Scaffolded profile for preset 'MINIMAL' (2 PEs)"],
            "sections": {
                "header": OrderedDict(
                    [
                        ("major-version", 2),
                        ("minor-version", 3),
                        ("iccid", bytes.fromhex("89461111111111111112")),
                        ("eUICC-Mandatory-services", {}),
                        ("eUICC-Mandatory-GFSTEList", []),
                    ]
                ),
                "end": OrderedDict(),
            },
        }

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "scaffold_template.json"
            with mock.patch(
                "Tools.ProfilePackage.shell.build_scaffold_profile_document",
                return_value=fake_document,
            ) as mocked_build:
                with contextlib.redirect_stdout(io.StringIO()) as captured:
                    self.shell._cmd_new_template(
                        f'"{output_path}" PRESET=MINIMAL ICCID=89461111111111111112'
                    )

            rendered = json.loads(output_path.read_text(encoding="utf-8"))

        mocked_build.assert_called_once_with("MINIMAL", self.shell.bridge.workspace_root)
        self.assertEqual(rendered["sections"]["header"]["iccid"]["hex"], "{ICCID}")
        self.assertEqual(
            rendered["__ygg_token_defs__"]["ICCID"]["hex"],
            "89461111111111111112",
        )
        self.assertIn("Scaffolded MINIMAL template", captured.getvalue())

    def test_cmd_new_template_defaults_to_configured_default_preset(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "scaffold_default.json"
            with mock.patch(
                "Tools.ProfilePackage.shell.build_scaffold_profile_document",
                return_value=fake_document,
            ) as mocked_build:
                with contextlib.redirect_stdout(io.StringIO()):
                    self.shell._cmd_new_template(f'"{output_path}"')

        mocked_build.assert_called_once_with(
            default_preset_id(),
            self.shell.bridge.workspace_root,
        )

    def test_cmd_new_template_rejects_unknown_preset(self) -> None:
        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "scaffold_bad.json"
            with self.assertRaisesRegex(ValueError, "Unknown profile preset"):
                self.shell._cmd_new_template(f'"{output_path}" PRESET=does-not-exist')

    def test_cmd_new_template_generates_default_path_when_no_tokens(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        profile_dir = self.shell.bridge.default_profile_dir
        with mock.patch(
            "Tools.ProfilePackage.shell.build_scaffold_profile_document",
            return_value=fake_document,
        ):
            with contextlib.redirect_stdout(io.StringIO()):
                self.shell._cmd_new_template("")
        generated = sorted(profile_dir.glob("scaffold-*.json"))
        self.assertEqual(len(generated), 1)
        self.assertIn(f"scaffold-{default_preset_id().lower()}-", generated[0].name)

    def test_cmd_new_profile_writes_der_bytes_via_encoder(self) -> None:
        fake_document = {
            "intro": ["Scaffolded profile for preset 'MINIMAL' (2 PEs)"],
            "sections": {
                "header": OrderedDict(
                    [
                        ("iccid", bytes.fromhex("89461111111111111112")),
                    ]
                ),
                "end": OrderedDict(),
            },
        }

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "scaffold_profile.der"
            with mock.patch(
                "Tools.ProfilePackage.shell.build_scaffold_profile_document",
                return_value=fake_document,
            ) as mocked_build:
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
                ) as mocked_ensure:
                    with mock.patch(
                        "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                        return_value=b"\xAA\xBB\xCC",
                    ) as mocked_encode:
                        with contextlib.redirect_stdout(io.StringIO()) as captured:
                            self.shell._cmd_new_profile(
                                f'"{output_path}" PRESET=MINIMAL'
                            )

            written_bytes = output_path.read_bytes()

        mocked_build.assert_called_once_with("MINIMAL", self.shell.bridge.workspace_root)
        mocked_ensure.assert_called_once_with(self.shell.bridge.workspace_root)
        mocked_encode.assert_called_once()
        self.assertEqual(written_bytes, b"\xAA\xBB\xCC")
        self.assertIn("Scaffolded MINIMAL profile", captured.getvalue())

    def test_cmd_new_profile_applies_iccid_placeholder_override(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {
                "header": OrderedDict(
                    [
                        ("iccid", bytes.fromhex("0000000000000000000F")),
                    ]
                ),
                "mf": OrderedDict(
                    [
                        (
                            "ef-iccid",
                            [
                                (
                                    "fillFileContent",
                                    bytes.fromhex("0000000000000000000F"),
                                )
                            ],
                        )
                    ]
                ),
                "end": OrderedDict(),
            },
        }

        with tempfile.TemporaryDirectory(dir=self.shell.bridge.workspace_root) as temp_dir:
            output_path = Path(temp_dir) / "scaffold_iccid.der"
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
                            self.shell._cmd_new_profile(
                                f'"{output_path}" PRESET=BASIC-MF '
                                "ICCID=89461111111111111112"
                            )

        encoded_document = mocked_encode.call_args.args[0]
        self.assertEqual(
            encoded_document["sections"]["header"]["iccid"],
            bytes.fromhex("89461111111111111112"),
        )
        self.assertEqual(
            encoded_document["sections"]["mf"]["ef-iccid"][0][1],
            bytes.fromhex("98641111111111111121"),
        )
        self.assertEqual(
            encoded_document["__ygg_token_defs__"]["ICCID"]["hex"],
            "89461111111111111112",
        )
        self.assertIn("Placeholder override summary", captured.getvalue())

    def test_cmd_new_profile_generates_default_path_when_no_tokens(self) -> None:
        fake_document = {
            "intro": ["scaffold"],
            "sections": {"header": OrderedDict(), "end": OrderedDict()},
        }
        profile_dir = self.shell.bridge.default_profile_dir
        with mock.patch(
            "Tools.ProfilePackage.shell.build_scaffold_profile_document",
            return_value=fake_document,
        ):
            with mock.patch(
                "Tools.ProfilePackage.saip_json_codec.ensure_workspace_pysim_on_path"
            ):
                with mock.patch(
                    "Tools.ProfilePackage.saip_json_codec.encode_der_from_document",
                    return_value=b"\xDE\xAD",
                ):
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.shell._cmd_new_profile("")
        generated = sorted(profile_dir.glob("scaffold-*.der"))
        self.assertEqual(len(generated), 1)
        self.assertEqual(generated[0].read_bytes(), b"\xDE\xAD")
        self.assertEqual(self.shell.bridge.current_input_file, generated[0])


if __name__ == "__main__":
    unittest.main()
