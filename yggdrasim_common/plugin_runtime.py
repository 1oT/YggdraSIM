from __future__ import annotations

import importlib.util
import os
import sys
from types import ModuleType
from typing import Any

from .runtime_paths import ensure_runtime_dir


_PLUGIN_DIR_NAME = "plugins"


class PluginManager:
    def __init__(self) -> None:
        self._loaded = False
        self._loading = False
        self._capabilities: dict[str, Any] = {}
        self._modules: dict[str, ModuleType] = {}
        self._load_errors: dict[str, str] = {}

    def ensure_loaded(self) -> None:
        if self._loaded or self._loading:
            return
        self._loading = True
        try:
            plugins_dir = ensure_runtime_dir(_PLUGIN_DIR_NAME)
            if os.path.isdir(plugins_dir) is False:
                self._loaded = True
                return
            for entry_name in sorted(os.listdir(plugins_dir)):
                plugin_path = os.path.join(plugins_dir, entry_name)
                if entry_name.startswith(".") or entry_name.startswith("_"):
                    continue
                module_name = ""
                source_path = ""
                if os.path.isfile(plugin_path) and entry_name.endswith(".py"):
                    module_name = f"yggdrasim_plugin_{entry_name[:-3]}"
                    source_path = plugin_path
                elif os.path.isdir(plugin_path):
                    init_path = os.path.join(plugin_path, "__init__.py")
                    if os.path.isfile(init_path) is False:
                        continue
                    module_name = f"yggdrasim_plugin_{entry_name}"
                    source_path = init_path
                if len(module_name) == 0 or len(source_path) == 0:
                    continue
                self._load_plugin_module(module_name=module_name, source_path=source_path)
            self._loaded = True
        finally:
            self._loading = False

    def _load_plugin_module(self, module_name: str, source_path: str) -> None:
        try:
            spec = importlib.util.spec_from_file_location(module_name, source_path)
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Unable to create import spec for {source_path}.")
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
            register = getattr(module, "register_plugins", None)
            if callable(register):
                register(self)
            self._modules[module_name] = module
            self._load_errors.pop(module_name, None)
        except Exception as error:
            self._load_errors[module_name] = str(error)

    def register_capability(self, name: str, provider: Any) -> None:
        capability_name = str(name or "").strip().lower()
        if len(capability_name) == 0:
            raise ValueError("Plugin capability name must not be empty.")
        self._capabilities[capability_name] = provider

    def get_capability(self, name: str) -> Any:
        self.ensure_loaded()
        capability_name = str(name or "").strip().lower()
        if len(capability_name) == 0:
            return None
        return self._capabilities.get(capability_name)

    def has_capability(self, name: str) -> bool:
        return self.get_capability(name) is not None

    def load_errors(self) -> dict[str, str]:
        self.ensure_loaded()
        return dict(self._load_errors)

    def extend_target(self, target: Any) -> Any:
        self.ensure_loaded()
        target_dict = getattr(target, "__dict__", None)
        if isinstance(target_dict, dict) is False:
            return target
        applied = target_dict.get("_yggdrasim_applied_plugin_capabilities")
        if isinstance(applied, set) is False:
            applied = set()
            target_dict["_yggdrasim_applied_plugin_capabilities"] = applied
        for capability_name, provider in self._capabilities.items():
            if capability_name in applied:
                continue
            extender = getattr(provider, "extend_target", None)
            if callable(extender):
                extender(target)
            applied.add(capability_name)
        return target


_PLUGIN_MANAGER: PluginManager | None = None


def get_plugin_manager() -> PluginManager:
    global _PLUGIN_MANAGER
    if _PLUGIN_MANAGER is None:
        _PLUGIN_MANAGER = PluginManager()
    return _PLUGIN_MANAGER


def ensure_plugins_loaded() -> PluginManager:
    manager = get_plugin_manager()
    manager.ensure_loaded()
    return manager


def get_capability(name: str) -> Any:
    return get_plugin_manager().get_capability(name)


def has_capability(name: str) -> bool:
    return get_plugin_manager().has_capability(name)


def plugin_load_errors() -> dict[str, str]:
    return get_plugin_manager().load_errors()


def extend_target_with_plugins(target: Any) -> Any:
    return get_plugin_manager().extend_target(target)
