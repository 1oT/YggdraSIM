# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Pin the plug-in-only publication boundary for GUI actions."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from unittest import mock

from yggdrasim_common import plugin_runtime
from yggdrasim_common.gui_server.actions.registry import ActionRegistry


def _load_into_registry(plugin_directory: Path) -> ActionRegistry:
    manager = plugin_runtime.PluginManager()
    registry = ActionRegistry()
    environment = {
        plugin_runtime._ALLOW_PLUGINS_ENV: "1",
        plugin_runtime._DISALLOW_PLUGINS_ENV: "0",
    }
    with (
        mock.patch.dict(os.environ, environment),
        mock.patch.object(
            plugin_runtime,
            "ensure_runtime_dir",
            return_value=str(plugin_directory),
        ),
    ):
        manager.extend_target(registry)
    return registry


def test_action_is_absent_when_its_plugin_is_absent() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        registry = _load_into_registry(Path(temp_dir))

    assert registry.has("plugin.private_validation.run") is False


def test_action_is_registered_only_after_plugin_is_present() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        plugin_directory = Path(temp_dir)
        suffix = plugin_directory.name.replace("-", "_")
        plugin_path = plugin_directory / f"private_validation_{suffix}.py"
        plugin_path.write_text(
            "from yggdrasim_common.gui_server.actions.registry import ActionSpec\n"
            "\n"
            "class Provider:\n"
            "    def extend_target(self, target):\n"
            "        target.register(ActionSpec(\n"
            "            id='plugin.private_validation.run',\n"
            "            subsystem='Private Validation',\n"
            "            title='Run',\n"
            "            description='Private plug-in action.',\n"
            "        ))\n"
            "\n"
            "def register_plugins(manager):\n"
            "    manager.register_capability('private.validation.test', Provider())\n",
            encoding="utf-8",
        )

        registry = _load_into_registry(plugin_directory)

    assert registry.has("plugin.private_validation.run") is True


def test_unhealthy_plugin_provider_does_not_publish_actions() -> None:
    with tempfile.TemporaryDirectory() as temp_dir:
        plugin_directory = Path(temp_dir)
        plugin_path = plugin_directory / "unhealthy_validation.py"
        plugin_path.write_text(
            "from yggdrasim_common.gui_server.actions.registry import ActionSpec\n"
            "\n"
            "class Provider:\n"
            "    def health(self):\n"
            "        return {\n"
            "            'status': 'degraded',\n"
            "            'actions_available': False,\n"
            "            'dependency_issues': ['required decoder is unavailable'],\n"
            "        }\n"
            "    def extend_target(self, target):\n"
            "        target.register(ActionSpec(\n"
            "            id='plugin.unhealthy_validation.run',\n"
            "            subsystem='Private Validation',\n"
            "            title='Run',\n"
            "            description='Must remain hidden.',\n"
            "        ))\n"
            "\n"
            "def register_plugins(manager):\n"
            "    manager.register_capability('private.validation.unhealthy', Provider())\n",
            encoding="utf-8",
        )
        manager = plugin_runtime.PluginManager()
        registry = ActionRegistry()
        environment = {
            plugin_runtime._ALLOW_PLUGINS_ENV: "1",
            plugin_runtime._DISALLOW_PLUGINS_ENV: "0",
        }
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(
                plugin_runtime,
                "ensure_runtime_dir",
                return_value=str(plugin_directory),
            ),
        ):
            manager.extend_target(registry)

    assert registry.has("plugin.unhealthy_validation.run") is False
    assert any(key.endswith(":health") for key in manager.load_errors())
