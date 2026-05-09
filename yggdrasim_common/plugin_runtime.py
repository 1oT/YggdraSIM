# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Plugin runtime gate: enforces the absence of optional hardware-dependent plugins in environments that declare them unavailable."""
from __future__ import annotations

import importlib.util
import os
import sys
import threading
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
    """Plugins load by default unless explicitly hard-locked.

    The posture mirrors the TLS-introspection gate in
    ``SCP11/shared/tls_helpers.py``:

    * Default: **on**. If the active runtime root has a ``plugins/``
      directory with loadable modules, they are loaded. This matches
      the shipped reality that ``plugins/polling_plugin.py`` is
      first-party, tracked code backing the ``POLL`` / ``IPAE-LIVE`` /
      ``IPAE-TEST`` command families.
    * ``YGGDRASIM_DISALLOW_PLUGINS=1`` → hard-lock. Refuse every
      plugin even if ``YGGDRASIM_ALLOW_PLUGINS=1`` is also set.
      Intended for attestation / CI / air-gapped deployments where no
      out-of-tree code may execute.
    * ``YGGDRASIM_ALLOW_PLUGINS=0`` (or ``false``/``no``/``off``) →
      explicit opt-out, equivalent to setting the disallow flag.
      Kept for backward compat with prior opt-in-only deployments
      that want to keep loading disabled after the default flip.
    * ``YGGDRASIM_ALLOW_PLUGINS=1`` (or truthy) → explicit opt-in.
      Redundant now that the default is on, but still honoured.
    """
    if _env_truthy(_DISALLOW_PLUGINS_ENV):
        return False
    if _env_falsy(_ALLOW_PLUGINS_ENV):
        return False
    return True


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
                    lock_source = (
                        _DISALLOW_PLUGINS_ENV
                        if _env_truthy(_DISALLOW_PLUGINS_ENV)
                        else _ALLOW_PLUGINS_ENV
                    )
                    self._load_errors["__gate__"] = (
                        f"Plugin loading hard-locked via {lock_source}. "
                        f"Unset or clear the variable to allow plugins from "
                        f"{plugins_dir}."
                    )
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
        # path") without becoming a noisy warning for the default
        # first-party ``polling_plugin.py`` case.
        label_parts: list[str] = []
        for path in loaded_paths:
            base = os.path.basename(path)
            if base == "__init__.py":
                # Directory-based plugin: surface the package name, not
                # the boilerplate ``__init__.py`` filename.
                label_parts.append(os.path.basename(os.path.dirname(path)) + "/")
            else:
                label_parts.append(base)
        labels = ", ".join(label_parts)
        sys.stderr.write(
            f"[plugins] loaded {len(loaded_paths)}: {labels} "
            f"(hard-lock with {_DISALLOW_PLUGINS_ENV}=1).\n"
        )

    def _load_plugin_module(
        self,
        module_name: str,
        source_path: str,
        legacy_alias: str = "",
    ) -> bool:
        try:
            # If the module (or its namespace package wrapper) is
            # already in sys.modules because an earlier ``import
            # plugins.<name>`` beat the runtime to the punch, reuse
            # that object. This prevents sys.modules from forking into
            # two distinct copies of the same plugin — a condition
            # that silently breaks ``mock.patch`` targets in tests.
            existing = sys.modules.get(module_name)
            if existing is not None and getattr(existing, "__file__", None) == source_path:
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
            alias = str(legacy_alias or "").strip()
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
            self._load_errors[module_name] = str(error)
            return False

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
        """Extend *target* with the callables registered for the named extension point."""
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


def extend_target_with_plugins(target: Any) -> Any:
    return get_plugin_manager().extend_target(target)


def reset_plugin_manager_for_tests() -> None:
    """Drop the cached ``PluginManager`` so the next call re-scans.

    Intended for unit tests that need to re-evaluate
    ``YGGDRASIM_DISALLOW_PLUGINS`` / plugin directory contents after a
    dynamic environment change. Not safe for concurrent use.
    """
    global _PLUGIN_MANAGER
    with _PLUGIN_MANAGER_LOCK:
        _PLUGIN_MANAGER = None
