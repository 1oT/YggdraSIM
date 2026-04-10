import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import yggdrasim_common.plugin_runtime as plugin_runtime
import yggdrasim_common.polling_plugin_support as polling_plugin_support
import yggdrasim_common.quit_control as quit_control
import yggdrasim_common.registry as registry


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
            with mock.patch.object(
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
            with mock.patch.object(
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


class QuitControlTests(unittest.TestCase):
    def test_quit_all_raises_control_exception(self) -> None:
        with self.assertRaises(quit_control.QuitAllRequested):
            quit_control.quit_all()


class PollingPluginSupportTests(unittest.TestCase):
    def test_require_polling_plugin_raises_when_missing(self) -> None:
        with mock.patch.object(polling_plugin_support, "get_capability", return_value=None):
            with self.assertRaisesRegex(RuntimeError, "optional plugin"):
                polling_plugin_support.require_polling_plugin()

    def test_dispatch_poll_command_normalizes_surface_and_command_name(self) -> None:
        calls: list[dict[str, object]] = []

        class Provider:
            @staticmethod
            def handle_command(**kwargs):
                calls.append(kwargs)
                return kwargs

        with mock.patch.object(
            polling_plugin_support,
            "get_capability",
            return_value=Provider(),
        ):
            result = polling_plugin_support.dispatch_poll_command(
                " Eim_Local ",
                "ipae-live",
                target=object(),
                argument="--debug",
            )

        self.assertEqual(result["surface"], "eim_local")
        self.assertEqual(result["command_name"], "IPAE-LIVE")
        self.assertEqual(result["argument"], "--debug")
        self.assertEqual(len(calls), 1)

    def test_parse_eim_local_ipae_args_uses_plugin_parser(self) -> None:
        provider = SimpleNamespace(
            parse_eim_local_ipae_options=lambda arg: {
                "poll_attempts_per_fqdn": 5,
                "timer_expiration_window_seconds": 40,
                "debug": "--debug" in arg,
            }
        )
        with mock.patch.object(
            polling_plugin_support,
            "get_capability",
            return_value=provider,
        ):
            self.assertEqual(
                polling_plugin_support.parse_eim_local_ipae_args("--debug"),
                (5, 40, True),
            )

    def test_install_poll_method_stubs_dispatches_to_plugin_runtime(self) -> None:
        class DummySurface:
            pass

        polling_plugin_support.install_poll_method_stubs(DummySurface)
        surface = DummySurface()

        with mock.patch.object(
            polling_plugin_support,
            "dispatch_poll_method",
            return_value=("ok",),
        ) as dispatch:
            result = surface._decode_stk_timer_value_seconds("AA")

        self.assertEqual(result, ("ok",))
        dispatch.assert_called_once_with(surface, "_decode_stk_timer_value_seconds", "AA")


if __name__ == "__main__":
    unittest.main()
