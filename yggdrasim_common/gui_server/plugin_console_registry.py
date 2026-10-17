# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The consoles loaded plugins offer the GUI, collected once per process.

``PluginConsoleRegistry`` is one more target the plugin runtime hands to
every provider's ``extend_target``: a provider with a console calls
``add_console`` with an object that answers ``manifest()`` and ``status()``,
plus ``start(values)`` / ``stop()`` when the manifest has a start form,
``command(line)`` when it has actions or a command line, ``stream(id,
after)`` when it has streams, the run methods (``run_start``, ``runs``,
``run``, ``run_events``, ``run_cancel``, and the ``credential`` trio when it
declares credentials) when it has a run form, ``pills()`` when it declares
top bar pills, and optionally ``help()``. The manifest is
checked on the way in; a console that does not fit is kept as a refusal
with its reason, never offered to the view. The registry is built on first
use, after the plugin gate has latched, and lives for the process because
the runtime marks a target it has extended.
"""
from __future__ import annotations

import threading
from typing import Any

from yggdrasim_common.plugin_runtime import extend_target_with_plugins

from .plugin_console_manifest import ConsoleManifestError, validate_manifest

# The registry lives for the process (CLAUDE.md, Memory discipline): both lists
# are bounded, and a console past the cap is kept as a refusal, not listed.
MAX_CONSOLES = 16
MAX_REFUSALS = 32


def required_methods(manifest: dict[str, Any]) -> tuple[str, ...]:
    """The console methods a validated manifest depends on."""
    methods = ["manifest", "status"]
    if manifest["start"] is not None:
        methods += ["start", "stop"]
        if any(field["fill"] for field in manifest["start"]["fields"]):
            methods.append("fill")
    if manifest["actions"] or manifest["command_line"] is not None:
        methods.append("command")
    if manifest["streams"]:
        methods.append("stream")
    if manifest["pills"]:
        methods.append("pills")
    if manifest["runs"] is not None:
        methods += ["run_start", "runs", "run", "run_events", "run_cancel"]
        if manifest["runs"]["credentials"]:
            methods += ["credentials", "credential_store", "credential_forget"]
    return tuple(methods)


class PluginConsoleRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._consoles: dict[str, tuple[dict[str, Any], Any]] = {}
        self._refused: list[dict[str, str]] = []

    def _refuse_locked(self, offered: str, reason: str) -> bool:
        if len(self._refused) < MAX_REFUSALS:
            self._refused.append({"id": offered, "reason": reason})
        return False

    def _refuse(self, offered: str, reason: str) -> bool:
        with self._lock:
            return self._refuse_locked(offered, reason)

    def add_console(self, console: Any) -> bool:
        """Register *console*; False, with a refusal kept, when it does not fit the contract."""
        offered = ""
        try:
            raw = console.manifest()
            if isinstance(raw, dict) and isinstance(raw.get("id"), str):
                offered = raw["id"][:32]
            manifest = validate_manifest(raw)
            missing = [name for name in required_methods(manifest) if not callable(getattr(console, name, None))]
            if missing:
                raise ConsoleManifestError(f"console {manifest['id']!r}: missing method(s) " + ", ".join(missing))
        # Plugin contract: whatever a broken console raises becomes its refusal, never the caller's error.
        except Exception as error:  # noqa: BLE001
            return self._refuse(offered, f"{type(error).__name__}: {error}")
        with self._lock:
            if manifest["id"] in self._consoles:
                return self._refuse_locked(manifest["id"], f"console id {manifest['id']!r} is already registered")
            if len(self._consoles) >= MAX_CONSOLES:
                return self._refuse_locked(manifest["id"], f"the GUI lists at most {MAX_CONSOLES} plugin consoles")
            self._consoles[manifest["id"]] = (manifest, console)
        return True

    def get(self, console_id: str) -> tuple[dict[str, Any], Any] | None:
        with self._lock:
            return self._consoles.get(str(console_id))

    def manifests(self) -> list[dict[str, Any]]:
        with self._lock:
            return [manifest for manifest, _console in self._consoles.values()]

    def refused(self) -> list[dict[str, str]]:
        with self._lock:
            return [dict(entry) for entry in self._refused]


_REGISTRY: PluginConsoleRegistry | None = None
_REGISTRY_LOCK = threading.Lock()


def console_registry() -> PluginConsoleRegistry:
    """The process-wide registry, filled from the loaded plugins on first call."""
    global _REGISTRY
    if _REGISTRY is not None:
        return _REGISTRY
    with _REGISTRY_LOCK:
        if _REGISTRY is None:
            registry = PluginConsoleRegistry()
            extend_target_with_plugins(registry)
            _REGISTRY = registry
        return _REGISTRY


def reset_console_registry_for_tests() -> None:
    """Drop the cached registry so the next ``console_registry()`` asks the plugins again."""
    global _REGISTRY
    with _REGISTRY_LOCK:
        _REGISTRY = None
