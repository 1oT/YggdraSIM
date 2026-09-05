# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the plugin-loading gate in ``yggdrasim_common.plugin_runtime``.

The gate is intentionally default-deny because plugins are executable
operator-supplied Python loaded from the active runtime root. This module
pins the exact opt-in semantics and the one-shot announce banner.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

from yggdrasim_common import plugin_runtime


_ALLOW = plugin_runtime._ALLOW_PLUGINS_ENV
_DISALLOW = plugin_runtime._DISALLOW_PLUGINS_ENV


class _EnvScope:
    """Context manager that isolates plugin env flags under test."""

    def __init__(self, **overrides: str | None) -> None:
        self._overrides = overrides
        self._saved: dict[str, str | None] = {}

    def __enter__(self) -> "_EnvScope":
        for name, value in self._overrides.items():
            self._saved[name] = os.environ.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        return self

    def __exit__(self, *exc_info: object) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _write_demo_plugin(target_dir: Path) -> Path:
    """Write a minimal plugin that exposes a ``demo`` capability."""
    suffix = target_dir.name.replace("-", "_")
    plugin_path = target_dir / f"demo_plugin_{suffix}.py"
    plugin_path.write_text(
        "class DemoProvider:\n"
        "    def extend_target(self, target):\n"
        "        target.extended = True\n"
        "\n"
        "def register_plugins(manager):\n"
        "    manager.register_capability('demo', DemoProvider())\n",
        encoding="utf-8",
    )
    return plugin_path


class PluginGateDefaultDenyTests(unittest.TestCase):
    def test_blocks_without_any_env_flag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            with _EnvScope(**{_ALLOW: None, _DISALLOW: None}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()
            self.assertFalse(manager.has_capability("demo"))
            errors = manager.load_errors()
            self.assertIn("__gate__", errors)
            self.assertIn("disabled by default", errors["__gate__"])
            self.assertIn(_ALLOW, errors["__gate__"])

    def test_explicit_allow_truthy_loads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            with _EnvScope(**{_ALLOW: "1", _DISALLOW: None}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()
            self.assertTrue(manager.has_capability("demo"))


class PluginGateHardLockTests(unittest.TestCase):
    def test_disallow_flag_blocks_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            with _EnvScope(**{_ALLOW: None, _DISALLOW: "1"}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()
            self.assertFalse(manager.has_capability("demo"))
            errors = manager.load_errors()
            self.assertIn("__gate__", errors)
            self.assertIn(_DISALLOW, errors["__gate__"])

    def test_disallow_overrides_allow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            with _EnvScope(**{_ALLOW: "1", _DISALLOW: "1"}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()
            self.assertFalse(manager.has_capability("demo"))

    def test_explicit_allow_falsy_is_opt_out(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            with _EnvScope(**{_ALLOW: "0", _DISALLOW: None}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()
            self.assertFalse(manager.has_capability("demo"))
            errors = manager.load_errors()
            self.assertIn("__gate__", errors)
            self.assertIn(_ALLOW, errors["__gate__"])

    def test_unrecognised_allow_value_blocks_loading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            with _EnvScope(**{_ALLOW: "maybe", _DISALLOW: None}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()
            self.assertFalse(manager.has_capability("demo"))
            errors = manager.load_errors()
            self.assertIn("__gate__", errors)
            self.assertIn("not truthy", errors["__gate__"])


class PluginGateAnnounceBannerTests(unittest.TestCase):
    def test_announce_banner_fires_once_for_first_party_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            plugin_path = _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            banner_stream = []

            def capture(message: str) -> int:
                banner_stream.append(message)
                return len(message)

            with _EnvScope(**{_ALLOW: "1", _DISALLOW: None}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ), mock.patch.object(plugin_runtime.sys.stderr, "write", side_effect=capture):
                manager.ensure_loaded()
                manager.ensure_loaded()

            announce_lines = [line for line in banner_stream if line.startswith("[plugins]")]
            self.assertEqual(len(announce_lines), 1)
            self.assertIn(plugin_path.name, announce_lines[0])
            self.assertIn(f"{_ALLOW}=1", announce_lines[0])
            self.assertIn(f"set {_DISALLOW}=1", announce_lines[0])
            self.assertIn("hard-lock plugin loading", announce_lines[0])


class PluginCapabilityRegistrationTests(unittest.TestCase):
    def test_same_provider_registration_is_idempotent(self) -> None:
        manager = plugin_runtime.PluginManager()
        provider = object()

        manager.register_capability("Example.Capability", provider)
        manager.register_capability("example.capability", provider)

        self.assertIs(manager.get_capability("EXAMPLE.CAPABILITY"), provider)

    def test_conflicting_provider_registration_is_rejected(self) -> None:
        manager = plugin_runtime.PluginManager()
        first_provider = object()
        second_provider = object()

        manager.register_capability("example.capability", first_provider)

        with self.assertRaisesRegex(ValueError, "already registered"):
            manager.register_capability("EXAMPLE.CAPABILITY", second_provider)

        self.assertIs(manager.get_capability("example.capability"), first_provider)

    def test_none_provider_is_rejected(self) -> None:
        manager = plugin_runtime.PluginManager()

        with self.assertRaisesRegex(ValueError, "must not be None"):
            manager.register_capability("example.capability", None)

    def test_failed_plugin_registration_rolls_back_capabilities(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_path = Path(temp_dir) / "broken_plugin.py"
            plugin_path.write_text(
                "def register_plugins(manager):\n"
                "    manager.register_capability('partial', object())\n"
                "    raise RuntimeError('registration failed')\n",
                encoding="utf-8",
            )
            manager = plugin_runtime.PluginManager()

            loaded = manager._load_plugin_module(
                module_name="yggdrasim_plugin_broken_plugin",
                source_path=str(plugin_path),
            )

        self.assertFalse(loaded)
        self.assertNotIn("partial", manager._capabilities)


class PluginDirectoryPackageTests(unittest.TestCase):
    def test_existing_canonical_module_from_other_path_is_not_overwritten(self) -> None:
        module_name = "plugins.audit_collision"
        previous = sys.modules.get(module_name)
        existing = ModuleType(module_name)
        existing.__file__ = "/existing/private/plugin/__init__.py"
        sys.modules[module_name] = existing
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                package_dir = Path(temp_dir) / "audit_collision"
                package_dir.mkdir()
                init_path = package_dir / "__init__.py"
                init_path.write_text(
                    "def register_plugins(manager):\n"
                    "    manager.register_capability('partial', object())\n"
                    "    raise RuntimeError('registration failed')\n",
                    encoding="utf-8",
                )
                manager = plugin_runtime.PluginManager()

                loaded = manager._load_plugin_module(
                    module_name=module_name,
                    source_path=str(init_path),
                )

            self.assertFalse(loaded)
            self.assertIs(sys.modules[module_name], existing)
            self.assertNotIn("partial", manager._capabilities)
            self.assertIn("module name collision", manager._load_errors[module_name])
        finally:
            if previous is None:
                sys.modules.pop(module_name, None)
            else:
                sys.modules[module_name] = previous

    def test_drop_in_package_supports_relative_imports_without_repo_on_path(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            package_dir = plugin_dir / "package_plugin"
            package_dir.mkdir()
            (package_dir / "provider.py").write_text(
                "class Provider:\n    pass\n",
                encoding="utf-8",
            )
            (package_dir / "__init__.py").write_text(
                "from .provider import Provider\n"
                "def register_plugins(manager):\n"
                "    manager.register_capability('package.demo', Provider())\n",
                encoding="utf-8",
            )
            saved_modules = {
                name: module
                for name, module in sys.modules.items()
                if name == "plugins"
                or name.startswith("plugins.")
                or name == "yggdrasim_plugin_package_plugin"
                or name.startswith("yggdrasim_plugin_package_plugin.")
            }
            for name in saved_modules:
                sys.modules.pop(name, None)
            manager = plugin_runtime.PluginManager()
            try:
                with (
                    _EnvScope(**{_ALLOW: "1", _DISALLOW: None}),
                    mock.patch.object(
                        plugin_runtime,
                        "ensure_runtime_dir",
                        return_value=str(plugin_dir),
                    ),
                ):
                    manager.ensure_loaded()

                self.assertIn("package.demo", manager._capabilities)
                loaded_package = sys.modules["plugins.package_plugin"]
                self.assertIs(
                    loaded_package,
                    sys.modules["yggdrasim_plugin_package_plugin"],
                )
            finally:
                for name in tuple(sys.modules):
                    if (
                        name == "plugins"
                        or name.startswith("plugins.")
                        or name == "yggdrasim_plugin_package_plugin"
                        or name.startswith("yggdrasim_plugin_package_plugin.")
                    ):
                        sys.modules.pop(name, None)
                sys.modules.update(saved_modules)


if __name__ == "__main__":
    unittest.main()
