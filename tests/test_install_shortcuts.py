# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the native desktop-launcher installer.

``scripts/install_shortcuts.py`` writes files into a user's desktop
environment, so the rendering functions are covered directly and the
filesystem-touching paths run against a temporary ``--install-dir``.
The Windows and macOS builders are exercised through their rendered
command text: the launcher content is what a wrong quoting rule breaks,
and neither ``WScript.Shell`` nor ``osacompile`` exists on the CI host.
"""

from __future__ import annotations

import importlib.util
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_installer():
    path = _REPO_ROOT / "scripts" / "install_shortcuts.py"
    spec = importlib.util.spec_from_file_location("yggdrasim_install_shortcuts", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    # ``dataclasses`` resolves a class's module through ``sys.modules``,
    # so a module loaded by path has to be registered before it runs.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


shortcuts = _load_installer()


def _target(*command: str, windowless: bool = True) -> object:
    return shortcuts.LauncherTarget(
        command=tuple(command),
        origin="test",
        windowless=windowless,
    )


class DesktopEntryRenderingTests(unittest.TestCase):
    def test_entry_disables_the_terminal(self) -> None:
        body = shortcuts.render_desktop_entry(_target("/opt/bin/yggdrasim-desktop"))
        self.assertIn("[Desktop Entry]", body)
        self.assertIn("Type=Application", body)
        self.assertIn("Terminal=false", body)
        self.assertIn("Exec=/opt/bin/yggdrasim-desktop", body)
        self.assertIn("TryExec=/opt/bin/yggdrasim-desktop", body)

    def test_string_list_keys_are_semicolon_terminated(self) -> None:
        body = shortcuts.render_desktop_entry(_target("/opt/bin/yggdrasim-desktop"))
        for key in ("Categories", "Keywords"):
            value = next(
                line.split("=", 1)[1]
                for line in body.splitlines()
                if line.startswith(f"{key}=")
            )
            self.assertTrue(
                value.endswith(";"),
                msg=f"{key} is a string list and needs a trailing semicolon",
            )

    def test_no_icon_key_is_emitted_without_an_icon_asset(self) -> None:
        body = shortcuts.render_desktop_entry(_target("/opt/bin/yggdrasim-desktop"))
        self.assertNotIn("Icon=", body)

    def test_exec_quotes_paths_containing_spaces(self) -> None:
        value = shortcuts._desktop_exec_value(("/opt/My Tools/yggdrasim-desktop",))
        self.assertEqual(value, '"/opt/My Tools/yggdrasim-desktop"')

    def test_exec_escapes_percent_signs(self) -> None:
        value = shortcuts._desktop_exec_value(("/opt/bin/run%tool",))
        self.assertEqual(value, "/opt/bin/run%%tool")

    def test_exec_keeps_module_fallback_arguments(self) -> None:
        value = shortcuts._desktop_exec_value(
            ("/opt/venv/bin/python", "-m", "main.gui")
        )
        self.assertEqual(value, "/opt/venv/bin/python -m main.gui")


class LinuxInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.install_dir = Path(self._temp.name) / "applications"
        self.entry = self.install_dir / "yggdrasim.desktop"
        self.target = _target("/opt/bin/yggdrasim-desktop")

    def _install(self, **kwargs: object) -> int:
        defaults: dict[str, object] = {
            "install_dir": self.install_dir,
            "dry_run": False,
            "force": False,
        }
        defaults.update(kwargs)
        with mock.patch.object(shortcuts, "_emit"):
            return shortcuts.install_linux(self.target, **defaults)

    def test_dry_run_writes_nothing(self) -> None:
        self.assertEqual(self._install(dry_run=True), shortcuts.EXIT_OK)
        self.assertFalse(self.install_dir.exists())

    def test_install_writes_a_readable_entry(self) -> None:
        with mock.patch.object(shortcuts, "_refresh_desktop_database"):
            self.assertEqual(self._install(), shortcuts.EXIT_OK)
        self.assertTrue(self.entry.is_file())
        self.assertIn("Terminal=false", self.entry.read_text(encoding="utf-8"))
        self.assertEqual(self.entry.stat().st_mode & 0o777, 0o644)

    def test_second_install_leaves_the_existing_entry_alone(self) -> None:
        with mock.patch.object(shortcuts, "_refresh_desktop_database"):
            self._install()
            self.entry.write_text("[Desktop Entry]\nName=edited\n", encoding="utf-8")
            self.assertEqual(self._install(), shortcuts.EXIT_OK)
        self.assertIn("Name=edited", self.entry.read_text(encoding="utf-8"))

    def test_force_overwrites_the_existing_entry(self) -> None:
        with mock.patch.object(shortcuts, "_refresh_desktop_database"):
            self._install()
            self.entry.write_text("[Desktop Entry]\nName=edited\n", encoding="utf-8")
            self.assertEqual(self._install(force=True), shortcuts.EXIT_OK)
        self.assertIn("Terminal=false", self.entry.read_text(encoding="utf-8"))

    def test_uninstall_removes_the_entry(self) -> None:
        with mock.patch.object(shortcuts, "_refresh_desktop_database"):
            self._install()
            with mock.patch.object(shortcuts, "_emit"):
                rc = shortcuts.uninstall_linux(
                    install_dir=self.install_dir, dry_run=False
                )
        self.assertEqual(rc, shortcuts.EXIT_OK)
        self.assertFalse(self.entry.exists())

    def test_uninstall_dry_run_keeps_the_entry(self) -> None:
        with mock.patch.object(shortcuts, "_refresh_desktop_database"):
            self._install()
            with mock.patch.object(shortcuts, "_emit"):
                rc = shortcuts.uninstall_linux(
                    install_dir=self.install_dir, dry_run=True
                )
        self.assertEqual(rc, shortcuts.EXIT_OK)
        self.assertTrue(self.entry.exists())

    def test_applications_dir_follows_xdg_data_home(self) -> None:
        with mock.patch.dict(os.environ, {"XDG_DATA_HOME": "/xdg/data"}, clear=False):
            resolved = shortcuts._linux_applications_dir(None)
        self.assertEqual(resolved, Path("/xdg/data/applications"))


class WindowsShortcutRenderingTests(unittest.TestCase):
    def test_script_targets_the_resolved_executable(self) -> None:
        script = shortcuts.render_shortcut_script(
            _target(r"C:\Users\op\pipx\venvs\yggdrasim\Scripts\yggdrasim-desktop.exe"),
            Path(r"C:\Menu\YggdraSIM.lnk"),
        )
        self.assertIn("WScript.Shell", script)
        self.assertIn(r"$link.TargetPath = 'C:\Users\op\pipx", script)
        self.assertIn(r"CreateShortcut('C:\Menu\YggdraSIM.lnk')", script)
        self.assertIn("$link.Save()", script)

    def test_window_style_is_normal(self) -> None:
        # Windowlessness comes from the pythonw-backed target, not from a
        # WindowStyle of 7 (minimized), which would only hide the window.
        script = shortcuts.render_shortcut_script(
            _target("C:/bin/yggdrasim-desktop.exe"), Path("C:/Menu/YggdraSIM.lnk")
        )
        self.assertIn("$link.WindowStyle = 1", script)

    def test_single_quotes_are_doubled_for_powershell(self) -> None:
        script = shortcuts.render_shortcut_script(
            _target("C:/o'brien/yggdrasim-desktop.exe"), Path("C:/Menu/YggdraSIM.lnk")
        )
        self.assertIn("'C:/o''brien/yggdrasim-desktop.exe'", script)

    def test_module_fallback_arguments_are_passed_separately(self) -> None:
        script = shortcuts.render_shortcut_script(
            _target("C:/venv/Scripts/pythonw.exe", "-m", "main.gui"),
            Path("C:/Menu/YggdraSIM.lnk"),
        )
        self.assertIn("$link.TargetPath = 'C:/venv/Scripts/pythonw.exe'", script)
        self.assertIn("$link.Arguments = '-m main.gui'", script)


class MacosAppletRenderingTests(unittest.TestCase):
    def test_applet_backgrounds_the_command(self) -> None:
        source = shortcuts.render_applescript(_target("/opt/bin/yggdrasim-desktop"))
        self.assertTrue(source.startswith("do shell script"))
        self.assertIn("'/opt/bin/yggdrasim-desktop'", source)
        self.assertIn("> /dev/null 2>&1 &", source)

    def test_user_applications_dir_is_the_default(self) -> None:
        self.assertEqual(
            shortcuts._macos_applications_dir(None, False),
            Path.home() / "Applications",
        )
        self.assertEqual(
            shortcuts._macos_applications_dir(None, True),
            Path("/Applications"),
        )

    def test_uninstall_refuses_a_path_that_is_not_a_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as work_dir:
            stray = Path(work_dir) / "YggdraSIM.app"
            stray.write_text("not a bundle", encoding="utf-8")
            with mock.patch.object(shortcuts, "_emit"):
                rc = shortcuts.uninstall_macos(
                    install_dir=Path(work_dir), system_wide=False, dry_run=False
                )
            self.assertEqual(rc, shortcuts.EXIT_FAILED)
            self.assertTrue(stray.exists())


class TargetResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.bin_dir = Path(self._temp.name) / "bin"
        self.bin_dir.mkdir()

    def _make_entry(self, name: str) -> Path:
        path = self.bin_dir / name
        path.write_text("#!/bin/sh\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_windowless_entry_point_wins_over_the_console_entry(self) -> None:
        self._make_entry("yggdrasim-desktop")
        self._make_entry("yggdrasim-gui")
        with mock.patch.object(shortcuts.shutil, "which", return_value=None):
            with mock.patch.object(
                shortcuts, "_interpreter_script_dir", return_value=self.bin_dir
            ):
                target = shortcuts.resolve_target(None)
        self.assertEqual(target.command, (str(self.bin_dir / "yggdrasim-desktop"),))
        self.assertTrue(target.windowless)

    def test_console_entry_point_is_the_fallback(self) -> None:
        self._make_entry("yggdrasim-gui")
        with mock.patch.object(shortcuts.shutil, "which", return_value=None):
            with mock.patch.object(
                shortcuts, "_interpreter_script_dir", return_value=self.bin_dir
            ):
                target = shortcuts.resolve_target(None)
        self.assertEqual(target.command, (str(self.bin_dir / "yggdrasim-gui"),))
        self.assertFalse(target.windowless)

    def test_module_fallback_is_rejected_when_the_import_fails(self) -> None:
        with mock.patch.object(shortcuts.shutil, "which", return_value=None):
            with mock.patch.object(
                shortcuts, "_interpreter_script_dir", return_value=self.bin_dir
            ):
                with mock.patch.object(
                    shortcuts, "_module_fallback_is_importable", return_value=False
                ):
                    with self.assertRaises(shortcuts.ResolutionError):
                        shortcuts.resolve_target(None)

    def test_module_fallback_is_used_when_the_import_succeeds(self) -> None:
        with mock.patch.object(shortcuts.shutil, "which", return_value=None):
            with mock.patch.object(
                shortcuts, "_interpreter_script_dir", return_value=self.bin_dir
            ):
                with mock.patch.object(
                    shortcuts, "_module_fallback_is_importable", return_value=True
                ):
                    target = shortcuts.resolve_target(None)
        self.assertEqual(target.command[1:], ("-m", "main.gui"))

    def test_explicit_target_must_exist(self) -> None:
        with self.assertRaises(shortcuts.ResolutionError):
            shortcuts.resolve_target(str(self.bin_dir / "absent-launcher"))


class IconAssetTests(unittest.TestCase):
    """The packaged mark must stay the one the docs and GUI show."""

    CANONICAL_SVG = _REPO_ROOT / "site-docs" / "assets" / "images" / "yggdrasil-mark.svg"
    ASSET_DIR = _REPO_ROOT / "yggdrasim_common" / "assets"

    def test_packaged_svg_matches_the_canonical_mark(self) -> None:
        self.assertEqual(
            (self.ASSET_DIR / "yggdrasim.svg").read_bytes(),
            self.CANONICAL_SVG.read_bytes(),
            msg=(
                "the packaged launcher icon has drifted from "
                "site-docs/assets/images/yggdrasil-mark.svg; re-copy it "
                "rather than editing the packaged copy"
            ),
        )

    def test_rendered_pngs_carry_the_expected_dimensions(self) -> None:
        # Dimensions and parseability only: a byte comparison against a
        # fresh render would fail on a different librsvg or zlib.
        for name, expected in (
            ("yggdrasim-256.png", (256, 256)),
            ("yggdrasim-512.png", (512, 512)),
        ):
            with self.subTest(asset=name):
                data = (self.ASSET_DIR / name).read_bytes()
                self.assertEqual(shortcuts._png_dimensions(data), expected)

    def test_png_dimension_reader_rejects_other_formats(self) -> None:
        with self.assertRaises(ValueError):
            shortcuts._png_dimensions(b"GIF89a" + b"\x00" * 32)

    def test_asset_directory_resolves_in_a_checkout(self) -> None:
        self.assertEqual(shortcuts.asset_directory(), self.ASSET_DIR)


class IcoContainerTests(unittest.TestCase):
    """The ICO writer replaces an image library, so its bytes are pinned."""

    def _ico(self) -> bytes:
        png = (
            _REPO_ROOT / "yggdrasim_common" / "assets" / "yggdrasim-256.png"
        ).read_bytes()
        return shortcuts.build_ico(png)

    def test_header_declares_one_icon_image(self) -> None:
        reserved, image_type, count = struct.unpack("<HHH", self._ico()[:6])
        self.assertEqual((reserved, image_type, count), (0, 1, 1))

    def test_entry_encodes_256_as_zero(self) -> None:
        width, height = struct.unpack("<BB", self._ico()[6:8])
        self.assertEqual((width, height), (0, 0))

    def test_entry_offset_points_at_the_png_payload(self) -> None:
        ico = self._ico()
        # ICONDIRENTRY: dwBytesInRes at 14, dwImageOffset at 18.
        length, offset = struct.unpack("<II", ico[14:22])
        self.assertEqual(offset, 22)
        self.assertEqual(ico[offset : offset + 8], shortcuts.PNG_SIGNATURE)
        self.assertEqual(len(ico), offset + length)

    def test_oversized_source_is_rejected(self) -> None:
        large = (
            _REPO_ROOT / "yggdrasim_common" / "assets" / "yggdrasim-512.png"
        ).read_bytes()
        with self.assertRaisesRegex(ValueError, "256x256"):
            shortcuts.build_ico(large)


class IconInstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory()
        self.addCleanup(self._temp.cleanup)
        self.data_home = Path(self._temp.name) / "data"
        self.install_dir = Path(self._temp.name) / "applications"
        self.entry = self.install_dir / "yggdrasim.desktop"
        self.target = _target("/opt/bin/yggdrasim-desktop")
        self._env = mock.patch.dict(
            os.environ, {"XDG_DATA_HOME": str(self.data_home)}, clear=False
        )
        self._env.start()
        self.addCleanup(self._env.stop)
        self._cache = mock.patch.object(shortcuts, "_refresh_icon_cache")
        self._cache.start()
        self.addCleanup(self._cache.stop)

    def _install(self, **kwargs: object) -> int:
        defaults: dict[str, object] = {
            "install_dir": self.install_dir,
            "dry_run": False,
            "force": False,
        }
        defaults.update(kwargs)
        with mock.patch.object(shortcuts, "_emit"):
            with mock.patch.object(shortcuts, "_refresh_desktop_database"):
                return shortcuts.install_linux(self.target, **defaults)

    def test_entry_names_the_icon_theme_entry(self) -> None:
        self.assertEqual(self._install(), shortcuts.EXIT_OK)
        self.assertIn("Icon=yggdrasim", self.entry.read_text(encoding="utf-8"))

    def test_icons_land_in_the_hicolor_theme(self) -> None:
        self._install()
        theme = self.data_home / "icons" / "hicolor"
        self.assertTrue((theme / "scalable" / "apps" / "yggdrasim.svg").is_file())
        self.assertTrue((theme / "256x256" / "apps" / "yggdrasim.png").is_file())

    def test_no_icon_omits_the_key_and_installs_nothing(self) -> None:
        self.assertEqual(self._install(with_icon=False), shortcuts.EXIT_OK)
        self.assertNotIn("Icon=", self.entry.read_text(encoding="utf-8"))
        self.assertFalse((self.data_home / "icons").exists())

    def test_missing_assets_still_produce_a_working_entry(self) -> None:
        with mock.patch.object(shortcuts, "asset_directory", return_value=None):
            self.assertEqual(self._install(), shortcuts.EXIT_OK)
        body = self.entry.read_text(encoding="utf-8")
        self.assertNotIn("Icon=", body)
        self.assertIn("Terminal=false", body)

    def test_uninstall_removes_the_installed_icons(self) -> None:
        self._install()
        with mock.patch.object(shortcuts, "_emit"):
            with mock.patch.object(shortcuts, "_refresh_desktop_database"):
                shortcuts.uninstall_linux(install_dir=self.install_dir, dry_run=False)
        theme = self.data_home / "icons" / "hicolor"
        self.assertFalse((theme / "scalable" / "apps" / "yggdrasim.svg").exists())
        self.assertFalse((theme / "256x256" / "apps" / "yggdrasim.png").exists())

    def test_dry_run_installs_no_icon_files(self) -> None:
        self.assertEqual(self._install(dry_run=True), shortcuts.EXIT_OK)
        self.assertFalse((self.data_home / "icons").exists())

    def test_shortcut_script_points_at_the_ico(self) -> None:
        script = shortcuts.render_shortcut_script(
            self.target,
            Path("C:/Menu/YggdraSIM.lnk"),
            Path("C:/Users/op/AppData/Local/YggdraSIM/yggdrasim.ico"),
        )
        self.assertIn(
            "$link.IconLocation = "
            "'C:/Users/op/AppData/Local/YggdraSIM/yggdrasim.ico,0'",
            script,
        )

    def test_shortcut_script_omits_icon_location_without_an_icon(self) -> None:
        script = shortcuts.render_shortcut_script(
            self.target, Path("C:/Menu/YggdraSIM.lnk"), None
        )
        self.assertNotIn("IconLocation", script)


class ReleaseRegistrationTests(unittest.TestCase):
    """A new package-data file has to clear every release gate at once."""

    ASSETS = (
        "yggdrasim_common/assets/yggdrasim.svg",
        "yggdrasim_common/assets/yggdrasim-256.png",
        "yggdrasim_common/assets/yggdrasim-512.png",
    )

    def test_assets_are_in_the_bundle_data_allowlist(self) -> None:
        payload = json.loads(
            (_REPO_ROOT / "scripts" / "release" / "bundle-data.json").read_text(
                encoding="utf-8"
            )
        )
        paths = {entry["path"] for entry in payload["entries"]}
        for asset in self.ASSETS:
            with self.subTest(asset=asset):
                self.assertIn(asset, paths)

    def test_assets_are_in_the_sdist_manifest(self) -> None:
        manifest = (_REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        for asset in self.ASSETS:
            with self.subTest(asset=asset):
                self.assertIn(f"include {asset}", manifest)

    def test_wireshark_probe_stays_out_of_the_artifacts(self) -> None:
        # The probe's own header says it is not shipped, but the
        # lua/*.lua include globs reach it; without both exclusions a
        # real wheel build fails verify_wheel.py.
        import tomllib

        with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
            payload = tomllib.load(handle)
        excluded = payload["tool"]["setuptools"]["exclude-package-data"]
        self.assertIn(
            "lua/probe_wireshark_env.lua",
            excluded.get("Tools.ApduDissector", []),
        )
        manifest = (_REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8")
        self.assertIn(
            "exclude Tools/ApduDissector/lua/probe_wireshark_env.lua",
            manifest,
        )

    def test_assets_are_declared_as_package_data(self) -> None:
        import tomllib

        with (_REPO_ROOT / "pyproject.toml").open("rb") as handle:
            payload = tomllib.load(handle)
        declared = payload["tool"]["setuptools"]["package-data"]["yggdrasim_common"]
        for asset in self.ASSETS:
            with self.subTest(asset=asset):
                self.assertIn(asset.split("/", 1)[1], declared)


class CliRoutingTests(unittest.TestCase):
    def test_unsupported_platform_reports_a_dedicated_exit_code(self) -> None:
        with mock.patch.object(shortcuts.platform, "system", return_value="Plan9"):
            with mock.patch.object(
                shortcuts, "resolve_target", return_value=_target("/opt/bin/x")
            ):
                with mock.patch.object(shortcuts, "_emit"):
                    rc = shortcuts.run_cli([])
        self.assertEqual(rc, shortcuts.EXIT_UNSUPPORTED)

    def test_unresolved_target_fails_before_touching_the_filesystem(self) -> None:
        with mock.patch.object(
            shortcuts,
            "resolve_target",
            side_effect=shortcuts.ResolutionError("nothing installed"),
        ):
            with mock.patch.object(shortcuts, "_emit"):
                rc = shortcuts.run_cli([])
        self.assertEqual(rc, shortcuts.EXIT_FAILED)

    def test_uninstall_routes_without_resolving_a_target(self) -> None:
        with mock.patch.object(shortcuts.platform, "system", return_value="Linux"):
            with mock.patch.object(shortcuts, "resolve_target") as resolver:
                with mock.patch.object(shortcuts, "uninstall_linux", return_value=0):
                    with mock.patch.object(shortcuts, "_emit"):
                        rc = shortcuts.run_cli(["--uninstall"])
        self.assertEqual(rc, shortcuts.EXIT_OK)
        resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
