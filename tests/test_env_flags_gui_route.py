# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Route-level tests for the GUI environment-flag surface."""

from __future__ import annotations

import os

import pytest

from yggdrasim_common.env_flags import FLAG_REGISTRY, PERSIST_SESSION


_FASTAPI_AVAILABLE = True
try:
    import fastapi as _fastapi  # noqa: F401
    import starlette as _starlette  # noqa: F401
except ImportError:
    _FASTAPI_AVAILABLE = False


_needs_gui_stack = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="FastAPI / Starlette not installed -- gui extra missing.",
)


def _openapi_schema() -> dict:
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.routes import env_flags as env_flags_routes

    app = FastAPI()
    app.include_router(env_flags_routes.router)
    return app.openapi()


@_needs_gui_stack
def test_clear_flag_schema_accepts_payload_without_value() -> None:
    schema = _openapi_schema()

    clear_body = schema["paths"]["/api/env_flags/{name}/clear"]["post"]["requestBody"]
    clear_schema = clear_body["content"]["application/json"]["schema"]
    clear_ref = clear_schema["anyOf"][0]["$ref"]
    clear_name = clear_ref.rsplit("/", 1)[-1]
    clear_model = schema["components"]["schemas"][clear_name]

    assert clear_name == "EnvFlagClearRequest"
    assert clear_model.get("required", []) == []
    assert "persist" in clear_model["properties"]
    assert "value" not in clear_model["properties"]


@_needs_gui_stack
def test_clear_flag_handler_removes_session_value(monkeypatch) -> None:
    from yggdrasim_common.gui_server.routes import env_flags as env_flags_routes

    flag = next(item for item in FLAG_REGISTRY if item.persist_scope == PERSIST_SESSION)
    monkeypatch.setenv(flag.name, "route-test-value")

    payload = env_flags_routes.EnvFlagClearRequest(persist=True)
    response = env_flags_routes.clear_flag(flag.name, payload)

    assert response.flag.name == flag.name
    assert response.flag.is_set is False
    assert flag.name in response.note
    assert flag.name not in os.environ


def test_every_opt_in_gui_capability_is_discoverable() -> None:
    """A gate an operator must set has to be findable in the registry."""
    from yggdrasim_common.env_flags import FLAG_REGISTRY

    flags = {flag.name: flag for flag in FLAG_REGISTRY}
    assert "YGGDRASIM_GUI_HOST_SHELL" in flags


def test_the_modem_terminal_is_not_gated_by_a_flag() -> None:
    """It was one, and the flag was the whole problem.

    Read once at startup, it could not be turned on from the window that
    needed it, and it guarded a scope already constrained to a known
    serial terminal against an explicit device path.
    """
    from yggdrasim_common.env_flags import FLAG_REGISTRY

    assert "YGGDRASIM_GUI_HIL_MODEM" not in {flag.name for flag in FLAG_REGISTRY}


def test_the_registry_lists_each_flag_once() -> None:
    from collections import Counter

    from yggdrasim_common.env_flags import FLAG_REGISTRY

    duplicated = [
        name for name, count in Counter(f.name for f in FLAG_REGISTRY).items() if count > 1
    ]
    assert duplicated == []
