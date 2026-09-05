# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Plugin-status report + the ``/api/env_flags/plugins`` GUI route.

The GUI "Configuration" (env_flags) view surfaces which optional runtime
plugins loaded -- or why none did. Loading is gated by
``YGGDRASIM_ALLOW_PLUGINS`` and evaluated once at startup, so the report is
latch-aware: a live flag flip must advertise ``requires_restart`` rather than
silently contradicting the toggle sitting next to it in the same panel.
"""

from __future__ import annotations

import os

import pytest

from yggdrasim_common import plugin_runtime


_ALLOW = plugin_runtime._ALLOW_PLUGINS_ENV
_DISALLOW = plugin_runtime._DISALLOW_PLUGINS_ENV


_FASTAPI_AVAILABLE = True
try:
    import fastapi as _fastapi  # noqa: F401
except ImportError:
    _FASTAPI_AVAILABLE = False

_needs_gui_stack = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="FastAPI not installed -- gui extra missing.",
)


class _EnvScope:
    """Isolate the plugin gate env flags and reset the manager singleton."""

    def __init__(self, **overrides: "str | None") -> None:
        self._overrides = overrides
        self._saved: "dict[str, str | None]" = {}

    def __enter__(self) -> "_EnvScope":
        for name, value in self._overrides.items():
            self._saved[name] = os.environ.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        plugin_runtime.reset_plugin_manager_for_tests()
        return self

    def __exit__(self, *exc: object) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        plugin_runtime.reset_plugin_manager_for_tests()


def test_report_disabled_by_default() -> None:
    with _EnvScope(**{_ALLOW: None, _DISALLOW: None}):
        report = plugin_runtime.plugin_status_report()
    assert report["allowed"] is False
    assert report["requires_restart"] is False
    assert "disabled by default" in report["block_reason"]
    assert report["plugins"] == []
    assert report["capabilities"] == []
    assert report["errors"] == {}


def test_report_flags_restart_after_live_enable() -> None:
    with _EnvScope(**{_ALLOW: None, _DISALLOW: None}):
        first = plugin_runtime.plugin_status_report()
        assert first["allowed"] is False
        assert first["requires_restart"] is False
        # Operator flips the gate live in the Configuration panel + Refresh;
        # the manager latched "disabled" at startup and cannot re-scan safely.
        os.environ[_ALLOW] = "1"
        second = plugin_runtime.plugin_status_report()
    assert second["allowed"] is False
    assert second["requires_restart"] is True


def test_report_splits_synthetic_error_keys() -> None:
    with _EnvScope(**{_ALLOW: None, _DISALLOW: None}):
        manager = plugin_runtime.ensure_plugins_loaded()
        manager._load_errors.update(
            {
                "__namespace__": "boom",
                "acme:health": "unhealthy",
                "plugins.acme": "ImportError: nope",
            }
        )
        report = plugin_runtime.plugin_status_report()
    assert report["namespace_error"] == "boom"
    assert report["health_errors"] == {"acme:health": "unhealthy"}
    assert report["errors"] == {"plugins.acme": "ImportError: nope"}
    assert "__gate__" not in report["errors"]
    assert "acme:health" not in report["errors"]


@_needs_gui_stack
def test_route_returns_status_model() -> None:
    from yggdrasim_common.gui_server.routes import env_flags as route

    with _EnvScope(**{_ALLOW: None, _DISALLOW: None}):
        resp = route.list_plugins()
    assert resp.allowed is False
    assert isinstance(resp.plugins, list)
    assert "disabled by default" in resp.block_reason


@_needs_gui_stack
def test_route_is_registered_in_openapi() -> None:
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.routes import env_flags as route

    app = FastAPI()
    app.include_router(route.router)
    schema = app.openapi()
    assert "/api/env_flags/plugins" in schema["paths"]
