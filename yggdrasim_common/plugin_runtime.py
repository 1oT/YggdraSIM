# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Plugin runtime gate for optional, operator-supplied extension code."""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
from importlib.machinery import ModuleSpec
from types import ModuleType
from typing import Any

from .runtime_paths import ensure_runtime_dir


_PLUGIN_DIR_NAME = "plugins"
_ALLOW_PLUGINS_ENV = "YGGDRASIM_ALLOW_PLUGINS"
_DISALLOW_PLUGINS_ENV = "YGGDRASIM_DISALLOW_PLUGINS"

_TRUTHY = frozenset(("1", "true", "yes", "on"))
_FALSY = frozenset(("0", "false", "no", "off"))


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _TRUTHY


def _env_falsy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in _FALSY


def _plugin_loading_allowed() -> bool:
    """Return whether runtime plugins may be imported.

    Plugins are executable Python loaded from the active runtime root,
    so the secure default is opt-in:

    * ``YGGDRASIM_DISALLOW_PLUGINS=1`` hard-locks the loader and wins
      over every other flag.
    * ``YGGDRASIM_ALLOW_PLUGINS=1`` explicitly enables plugin imports.
    * unset, false, or unrecognised ``YGGDRASIM_ALLOW_PLUGINS`` values
      leave plugin imports disabled.
    """
    if _env_truthy(_DISALLOW_PLUGINS_ENV):
        return False
    return _env_truthy(_ALLOW_PLUGINS_ENV)


def _plugin_loading_block_reason() -> str:
    if _env_truthy(_DISALLOW_PLUGINS_ENV):
        return (
            f"Plugin loading hard-locked via {_DISALLOW_PLUGINS_ENV}=1. "
            f"Clear {_DISALLOW_PLUGINS_ENV} and set {_ALLOW_PLUGINS_ENV}=1 "
            "to allow plugins from the runtime root."
        )
    raw_allow = os.environ.get(_ALLOW_PLUGINS_ENV, "")
    allow_text = raw_allow.strip()
    if len(allow_text) == 0:
        return (
            f"Plugin loading disabled by default. Set {_ALLOW_PLUGINS_ENV}=1 "
            "to allow plugins from the runtime root."
        )
    if _env_falsy(_ALLOW_PLUGINS_ENV):
        return (
            f"Plugin loading disabled via {_ALLOW_PLUGINS_ENV}={allow_text!r}. "
            f"Set {_ALLOW_PLUGINS_ENV}=1 to allow plugins from the runtime root."
        )
    return (
        f"Plugin loading disabled because {_ALLOW_PLUGINS_ENV}={allow_text!r} "
        f"is not truthy. Set {_ALLOW_PLUGINS_ENV}=1 to allow plugins from "
        "the runtime root."
    )


def _ensure_plugins_namespace(plugins_dir: str) -> None:
    """Make drop-in directory plugins importable as ``plugins.<name>``."""
    namespace_name = "plugins"
    normalized_dir = os.path.abspath(plugins_dir)
    existing = sys.modules.get(namespace_name)
    if existing is None:
        module = ModuleType(namespace_name)
        module.__package__ = namespace_name
        module.__path__ = [normalized_dir]
        spec = ModuleSpec(namespace_name, loader=None, is_package=True)
        spec.submodule_search_locations = [normalized_dir]
        module.__spec__ = spec
        sys.modules[namespace_name] = module
        return

    namespace_paths = getattr(existing, "__path__", None)
    if namespace_paths is None:
        raise RuntimeError(
            "Cannot load directory plugins because 'plugins' is already a non-package module."
        )
    paths = [os.path.abspath(str(path)) for path in namespace_paths]
    if normalized_dir not in paths:
        paths.append(normalized_dir)
        existing.__path__ = paths
    spec = getattr(existing, "__spec__", None)
    if spec is not None:
        spec.submodule_search_locations = list(paths)


def _plugin_label(source_path: str) -> str:
    """Display name for a plugin path — ``pkg/`` for a directory plugin,
    ``file.py`` for a single-file plugin. Kept in one place so the startup
    banner and the operator-facing status report always agree.
    """
    base = os.path.basename(source_path)
    if base == "__init__.py":
        return os.path.basename(os.path.dirname(source_path)) + "/"
    return base


class PluginManager:
    def __init__(self) -> None:
        self._loaded = False
        self._loading = False
        self._capabilities: dict[str, Any] = {}
        self._modules: dict[str, ModuleType] = {}
        self._load_errors: dict[str, str] = {}
        self._announced = False
        # ``ensure_loaded`` is typically called once at dispatcher startup,
        # but the SCP11 test harness and the shell dispatcher can both
        # trigger it from different threads. RLock so plugin ``register`` /
        # ``extend_target`` callbacks that re-enter the manager (e.g. to
        # probe another capability) do not deadlock on themselves.
        self._lock = threading.RLock()

    def ensure_loaded(self) -> None:
        # RLock: we want a second caller on the same thread (via
        # ``register_plugins`` → ``register_capability`` or a plugin that
        # probes ``has_capability`` during its own load) to pass through,
        # but a second caller on another thread to block until the first is
        # done so they see a consistent capability map. ``_loading`` is kept
        # as a belt-and-suspenders guard for anyone that defeats the lock by
        # calling the internals directly.
        """Ensure the plugin at *path* is loaded, importing it if not already present."""
        with self._lock:
            if self._loaded or self._loading:
                return
            self._loading = True
            try:
                plugins_dir = ensure_runtime_dir(_PLUGIN_DIR_NAME)
                if os.path.isdir(plugins_dir) is False:
                    self._loaded = True
                    return
                if _plugin_loading_allowed() is False:
                    self._load_errors["__gate__"] = (
                        f"{_plugin_loading_block_reason()} Directory: {plugins_dir}."
                    )
                    self._loaded = True
                    return
                try:
                    _ensure_plugins_namespace(plugins_dir)
                except Exception as error:
                    self._load_errors["__namespace__"] = str(error)
                    self._loaded = True
                    return
                loaded_paths: list[str] = []
                for entry_name in sorted(os.listdir(plugins_dir)):
                    plugin_path = os.path.join(plugins_dir, entry_name)
                    if entry_name.startswith(".") or entry_name.startswith("_"):
                        continue
                    module_name = ""
                    source_path = ""
                    legacy_alias = ""
                    if os.path.isfile(plugin_path) and entry_name.endswith(".py"):
                        # Single-file plugins live outside the ``plugins``
                        # namespace package (they are not directories), so
                        # we keep the historical legacy name for them.
                        module_name = f"yggdrasim_plugin_{entry_name[:-3]}"
                        source_path = plugin_path
                    elif os.path.isdir(plugin_path):
                        init_path = os.path.join(plugin_path, "__init__.py")
                        if os.path.isfile(init_path) is False:
                            continue
                        # Directory-based plugins use their natural
                        # ``plugins.<name>`` Python package path so tests
                        # and operator tools import the exact same module
                        # object the runtime registers.
                        module_name = f"plugins.{entry_name}"
                        legacy_alias = f"yggdrasim_plugin_{entry_name}"
                        source_path = init_path
                    if len(module_name) == 0 or len(source_path) == 0:
                        continue
                    if self._load_plugin_module(
                        module_name=module_name,
                        source_path=source_path,
                        legacy_alias=legacy_alias,
                    ):
                        loaded_paths.append(source_path)
                self._loaded = True
                if len(loaded_paths) > 0:
                    self._announce_loaded(loaded_paths)
            finally:
                self._loading = False

    def _announce_loaded(self, loaded_paths: list[str]) -> None:
        if self._announced:
            return
        self._announced = True
        # Quiet info line so operators can eyeball which modules are
        # actually executing at startup. Matches the COMMON-P4-02
        # audit intent ("print a banner listing every loaded plugin
        # path").
        labels = ", ".join(_plugin_label(path) for path in loaded_paths)
        sys.stderr.write(
            f"[plugins] loaded {len(loaded_paths)}: {labels} "
            f"({_ALLOW_PLUGINS_ENV}=1; set {_DISALLOW_PLUGINS_ENV}=1 "
            "to hard-lock plugin loading).\n"
        )

    def _load_plugin_module(
        self,
        module_name: str,
        source_path: str,
        legacy_alias: str = "",
    ) -> bool:
        capabilities_before = dict(self._capabilities)
        modules_before = set(sys.modules)
        try:
            # If the module (or its namespace package wrapper) is
            # already in sys.modules because an earlier ``import
            # plugins.<name>`` beat the runtime to the punch, reuse
            # that object. This prevents sys.modules from forking into
            # two distinct copies of the same plugin -- a condition
            # that silently breaks ``mock.patch`` targets in tests.
            existing = sys.modules.get(module_name)
            if existing is not None:
                existing_path = str(getattr(existing, "__file__", "") or "")
                if (
                    len(existing_path) == 0
                    or os.path.realpath(existing_path) != os.path.realpath(source_path)
                ):
                    raise RuntimeError(
                        f"Plugin module name collision for {module_name!r}: "
                        f"existing path {existing_path!r}, requested path {source_path!r}."
                    )
            elif any(name.startswith(f"{module_name}.") for name in sys.modules):
                raise RuntimeError(
                    f"Plugin module prefix collision for {module_name!r}."
                )
            alias = str(legacy_alias or "").strip()
            alias_existing = sys.modules.get(alias) if alias else None
            if alias_existing is not None and alias_existing is not existing:
                raise RuntimeError(
                    f"Plugin legacy alias collision for {alias!r}."
                )
            if existing is not None:
                module = existing
                if getattr(module, "__spec__", None) is None:
                    module.__spec__ = importlib.util.spec_from_file_location(
                        module_name, source_path
                    )
            else:
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
            # Alias legacy ``yggdrasim_plugin_<name>`` to keep older
            # tooling and transcripts resolving correctly. The alias
            # points to the canonical module object; patching through
            # either path hits the same attribute table.
            if len(alias) > 0 and alias != module_name:
                sys.modules.setdefault(alias, module)
                prefix_with_dot = f"{module_name}."
                for loaded_name in list(sys.modules.keys()):
                    if loaded_name.startswith(prefix_with_dot) is False:
                        continue
                    suffix = loaded_name[len(prefix_with_dot):]
                    sys.modules.setdefault(f"{alias}.{suffix}", sys.modules[loaded_name])
            return True
        except Exception as error:
            self._capabilities.clear()
            self._capabilities.update(capabilities_before)
            for loaded_name in tuple(sys.modules):
                if loaded_name in modules_before:
                    continue
                if loaded_name == module_name or loaded_name.startswith(f"{module_name}."):
                    sys.modules.pop(loaded_name, None)
            self._load_errors[module_name] = str(error)
            return False

    def register_capability(self, name: str, provider: Any) -> None:
        capability_name = str(name or "").strip().lower()
        if len(capability_name) == 0:
            raise ValueError("Plugin capability name must not be empty.")
        if provider is None:
            raise ValueError("Plugin capability provider must not be None.")
        existing = self._capabilities.get(capability_name)
        if existing is provider:
            return
        if capability_name in self._capabilities:
            raise ValueError(f"Plugin capability name already registered: {capability_name!r}.")
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

    def loaded_plugins(self) -> list[dict[str, str]]:
        """Return the plugin modules that imported successfully at load time.

        Each entry carries the import ``name``, a display ``label`` (matching
        the startup banner), and the source ``path`` (absolute; callers that
        expose this over HTTP should relativise it first).
        """
        self.ensure_loaded()
        with self._lock:
            plugins: list[dict[str, str]] = []
            for name, module in sorted(self._modules.items()):
                source = str(getattr(module, "__file__", "") or "")
                plugins.append(
                    {
                        "name": name,
                        "label": _plugin_label(source) if source else name,
                        "path": source,
                    }
                )
            return plugins

    def capabilities(self) -> list[str]:
        """Return the sorted names of registered plugin capabilities."""
        self.ensure_loaded()
        with self._lock:
            return sorted(self._capabilities)

    def extend_target(self, target: Any) -> Any:
        """Extend *target* with the callables registered for the named extension point."""
        self.ensure_loaded()
        target_dict = getattr(target, "__dict__", None)
        if isinstance(target_dict, dict) is False:
            return target
        applied = target_dict.get("_yggdrasim_applied_plugin_capabilities")
        if isinstance(applied, set) is False:
            applied = set()
            target_dict["_yggdrasim_applied_plugin_capabilities"] = applied
        applied_providers = target_dict.get("_yggdrasim_applied_plugin_providers")
        if isinstance(applied_providers, set) is False:
            applied_providers = set()
            target_dict["_yggdrasim_applied_plugin_providers"] = applied_providers
        for capability_name, provider in self._capabilities.items():
            if capability_name in applied:
                continue
            provider_identity = id(provider)
            if provider_identity in applied_providers:
                applied.add(capability_name)
                continue
            health = getattr(provider, "health", None)
            if callable(health):
                try:
                    health_report = health()
                except Exception as error:
                    self._load_errors[f"{capability_name}:health"] = (
                        f"Plugin health check failed: {error}"
                    )
                    applied.add(capability_name)
                    applied_providers.add(provider_identity)
                    continue
                if (
                    isinstance(health_report, dict)
                    and health_report.get("actions_available") is False
                ):
                    issues = health_report.get("dependency_issues") or ()
                    detail = "; ".join(str(item) for item in issues if str(item))
                    self._load_errors[f"{capability_name}:health"] = (
                        "Plugin actions are unavailable"
                        + (f": {detail}" if detail else ".")
                    )
                    applied.add(capability_name)
                    applied_providers.add(provider_identity)
                    continue
            extender = getattr(provider, "extend_target", None)
            if callable(extender):
                extender(target)
            applied.add(capability_name)
            applied_providers.add(provider_identity)
        return target


_PLUGIN_MANAGER: PluginManager | None = None
_PLUGIN_MANAGER_LOCK = threading.Lock()


def get_plugin_manager() -> PluginManager:
    """Return the singleton PluginManager, creating it on first call."""
    global _PLUGIN_MANAGER
    # Fast path keeps the common case lock-free; slow path serialises the
    # one-time construction so two threads calling ``ensure_plugins_loaded``
    # from distinct dispatchers cannot race and build two managers.
    if _PLUGIN_MANAGER is not None:
        return _PLUGIN_MANAGER
    with _PLUGIN_MANAGER_LOCK:
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


def plugin_status_report() -> dict[str, Any]:
    """Summarise plugin-loading state for operator surfaces (GUI / CLI).

    Reflects what the singleton manager actually did: plugin loading is
    evaluated once at process start and latched, so the report also computes
    ``requires_restart`` when the live ``YGGDRASIM_ALLOW_PLUGINS`` /
    ``YGGDRASIM_DISALLOW_PLUGINS`` gate now disagrees with that latched
    decision (e.g. the operator just toggled the flag from the UI).

    Synthetic ``_load_errors`` keys are split out so callers can render them
    distinctly: ``__gate__`` / ``__namespace__`` say why nothing loaded,
    ``<capability>:health`` are health-check failures, and the remainder are
    genuine per-plugin import errors.
    """
    manager = ensure_plugins_loaded()
    errors = manager.load_errors()

    block_reason = errors.pop("__gate__", "")
    namespace_error = errors.pop("__namespace__", "")
    health_errors = {
        key: errors.pop(key) for key in list(errors) if key.endswith(":health")
    }

    loaded_at_startup = len(block_reason) == 0 and len(namespace_error) == 0
    requires_restart = _plugin_loading_allowed() != loaded_at_startup

    plugins_dir = ""
    try:
        plugins_dir = ensure_runtime_dir(_PLUGIN_DIR_NAME)
    except Exception:  # noqa: BLE001 -- never let reporting raise
        plugins_dir = ""

    plugins: list[dict[str, str]] = []
    for entry in manager.loaded_plugins():
        source = entry.get("path", "")
        shown = source
        if source:
            try:
                shown = os.path.relpath(source, plugins_dir) if plugins_dir else os.path.basename(source)
            except ValueError:
                shown = os.path.basename(source)
        plugins.append({"name": entry["name"], "label": entry["label"], "path": shown})

    return {
        "allowed": loaded_at_startup,
        "requires_restart": requires_restart,
        "block_reason": block_reason,
        "namespace_error": namespace_error,
        "plugins": plugins,
        "capabilities": manager.capabilities(),
        "health_errors": health_errors,
        "errors": errors,
    }


def extend_target_with_plugins(target: Any) -> Any:
    return get_plugin_manager().extend_target(target)


def reset_plugin_manager_for_tests() -> None:
    """Drop the cached ``PluginManager`` so the next call re-scans.

    Intended for unit tests that need to re-evaluate
    plugin gate flags / plugin directory contents after a dynamic
    environment change. Not safe for concurrent use.
    """
    global _PLUGIN_MANAGER
    with _PLUGIN_MANAGER_LOCK:
        _PLUGIN_MANAGER = None
