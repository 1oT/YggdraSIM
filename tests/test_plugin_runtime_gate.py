"""Tests for the plugin-loading gate in ``yggdrasim_common.plugin_runtime``.

The gate is intentionally default-on so first-party plugins shipped in
the tracked tree (``plugins/polling_plugin.py`` — the ``POLL`` and
``IPAE-*`` watchdog backers) load without an env dance. This module
pins the exact tri-state semantics and the one-shot announce banner.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
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
    plugin_path = target_dir / "demo_plugin.py"
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


class PluginGateDefaultOnTests(unittest.TestCase):
    def test_loads_without_any_env_flag(self) -> None:
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
            self.assertTrue(manager.has_capability("demo"))
            self.assertNotIn("__gate__", manager.load_errors())

    def test_explicit_allow_truthy_still_loads(self) -> None:
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


class PluginGateAnnounceBannerTests(unittest.TestCase):
    def test_announce_banner_fires_once_for_first_party_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin_dir = Path(temp_dir)
            _write_demo_plugin(plugin_dir)
            manager = plugin_runtime.PluginManager()
            banner_stream = []

            def capture(message: str) -> int:
                banner_stream.append(message)
                return len(message)

            with _EnvScope(**{_ALLOW: None, _DISALLOW: None}), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ), mock.patch.object(plugin_runtime.sys.stderr, "write", side_effect=capture):
                manager.ensure_loaded()
                manager.ensure_loaded()

            announce_lines = [line for line in banner_stream if line.startswith("[plugins]")]
            self.assertEqual(len(announce_lines), 1)
            self.assertIn("demo_plugin.py", announce_lines[0])
            self.assertIn(_DISALLOW, announce_lines[0])


if __name__ == "__main__":
    unittest.main()
