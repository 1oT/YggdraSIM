# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yggdrasim_common.plugin_runtime as plugin_runtime
import yggdrasim_common.quit_control as quit_control
import yggdrasim_common.registry as registry
import yggdrasim_common.console_scripts as console_scripts


class PluginRuntimeTests(unittest.TestCase):
    def test_plugin_manager_loads_plugin_file_and_extends_target_once(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            plugin_dir = Path(temp_dir)
            (plugin_dir / "demo_plugin.py").write_text(
                "class DemoProvider:\n"
                "    def extend_target(self, target):\n"
                "        target.plugin_hits = getattr(target, 'plugin_hits', 0) + 1\n"
                "\n"
                "def register_plugins(manager):\n"
                "    manager.register_capability('demo', DemoProvider())\n",
                encoding="utf-8",
            )

            manager = plugin_runtime.PluginManager()
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_ALLOW_PLUGINS": "1"},
                clear=False,
            ), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                manager.ensure_loaded()

            self.assertTrue(manager.has_capability("demo"))
            target = SimpleNamespace()
            manager.extend_target(target)
            manager.extend_target(target)
            self.assertEqual(target.plugin_hits, 1)

    def test_plugin_manager_records_plugin_load_errors(self) -> None:
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            plugin_dir = Path(temp_dir)
            (plugin_dir / "broken_plugin.py").write_text(
                "raise RuntimeError('broken load')\n",
                encoding="utf-8",
            )

            manager = plugin_runtime.PluginManager()
            with mock.patch.dict(
                os.environ,
                {"YGGDRASIM_ALLOW_PLUGINS": "1"},
                clear=False,
            ), mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_dir),
            ):
                errors = manager.load_errors()

            self.assertIn("yggdrasim_plugin_broken_plugin", errors)
            self.assertIn("broken load", errors["yggdrasim_plugin_broken_plugin"])

    def test_register_capability_rejects_empty_name(self) -> None:
        manager = plugin_runtime.PluginManager()
        with self.assertRaisesRegex(ValueError, "must not be empty"):
            manager.register_capability("", object())


class RegistryTests(unittest.TestCase):
    def test_resolve_rejects_bad_qualified_name(self) -> None:
        with self.assertRaisesRegex(ValueError, "Expected 'module.path:Attribute'"):
            registry.resolve("not-qualified")

    def test_get_resolves_patched_symbol(self) -> None:
        with mock.patch.dict(
            registry.SYMBOL_REGISTRY,
            {"unit.quit": "yggdrasim_common.quit_control:quit_all"},
            clear=False,
        ):
            self.assertIs(registry.get("unit.quit"), quit_control.quit_all)

    def test_get_unknown_symbol_raises_key_error(self) -> None:
        with self.assertRaises(KeyError):
            registry.get("missing.symbol")

    def test_search_list_and_cli_description_are_stable(self) -> None:
        hits = registry.search("scp80")
        self.assertTrue(any(key == "scp80.builder" for key, _ in hits))
        self.assertIn("scp80.cli.shell", registry.list_keys("scp80"))
        self.assertIn("python -m SCP80", registry.describe_cli_modules())
        subsystems = list(registry.iter_subsystems())
        self.assertTrue(any(name == "SCP80" for name, _ in subsystems))


class ConsoleScriptTests(unittest.TestCase):
    def test_invoke_returns_zero_for_none_result(self) -> None:
        fake_module = SimpleNamespace(entry=lambda: None)
        with mock.patch.object(console_scripts.importlib, "import_module", return_value=fake_module):
            self.assertEqual(console_scripts._invoke("fake.module", "entry"), 0)

    def test_invoke_returns_integer_result(self) -> None:
        fake_module = SimpleNamespace(entry=lambda: 7)
        with mock.patch.object(console_scripts.importlib, "import_module", return_value=fake_module):
            self.assertEqual(console_scripts._invoke("fake.module", "entry"), 7)

    def test_invoke_maps_quit_request_to_zero(self) -> None:
        def _raise_quit() -> None:
            raise quit_control.QuitAllRequested()

        fake_module = SimpleNamespace(entry=_raise_quit)
        with mock.patch.object(console_scripts.importlib, "import_module", return_value=fake_module):
            self.assertEqual(console_scripts._invoke("fake.module", "entry"), 0)

    def test_console_scripts_dispatch_expected_targets(self) -> None:
        expected_targets = {
            "scp03": ("SCP03.main", "run_standalone"),
            "scp80": ("SCP80.main", "run_standalone"),
            "scp11": ("SCP11.main", "entry"),
            "scp11_live": ("SCP11.live.main", "entry"),
            "scp11_relay": ("SCP11.relay.main", "entry"),
            "scp11_local_access": ("SCP11.local_access.main", "run_standalone"),
            "scp11_eim_local": ("SCP11.eim_local.main", "run_standalone"),
            "profile_package": ("Tools.ProfilePackage.main", "run_standalone"),
            "suci_tool": ("Tools.SuciTool.main", "run_standalone"),
        }

        for function_name, expected in expected_targets.items():
            with self.subTest(function=function_name):
                with mock.patch.object(console_scripts, "_invoke", return_value=0) as mocked:
                    result = getattr(console_scripts, function_name)()
                self.assertEqual(result, 0)
                mocked.assert_called_once_with(*expected)


class QuitControlTests(unittest.TestCase):
    def test_quit_all_raises_control_exception(self) -> None:
        with self.assertRaises(quit_control.QuitAllRequested):
            quit_control.quit_all()


if __name__ == "__main__":
    unittest.main()
