# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Contracts of the plugin console registry and its route family.

No plugin is needed on disk: a neutral fake console is registered on a fresh
registry that the route resolves through ``console_registry``, and the
absent-plugin answer is the runtime's own report. The route never names a
plugin; a console is whatever registered, and nothing reaches it that its
manifest did not declare.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

try:  # pragma: no cover - the import itself is under test
    import fastapi as _fastapi  # noqa: F401
    from fastapi.testclient import TestClient

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _FASTAPI_AVAILABLE, reason="FastAPI not installed -- gui extra missing.")

_ALLOWED = {"allowed": True, "requires_restart": False, "block_reason": "", "errors": {}}


class _FakeConsole:
    def __init__(self, console_id: str = "demo") -> None:
        self.console_id = console_id
        self.started: list[dict[str, Any]] = []
        self.lines: list[str] = []
        self.running = False
        self.fail_status = False

    def manifest(self) -> dict[str, Any]:
        return {
            "id": self.console_id,
            "title": "Demo console",
            "start": {"fields": [{"name": "count", "label": "Count", "type": "number", "min": 1, "max": 9, "default": 3}]},
            "actions": [
                {
                    "id": "echo",
                    "label": "Echo",
                    "template": "ECHO {word} {times}",
                    "fields": [
                        {"name": "word", "label": "Word", "type": "text"},
                        {"name": "times", "label": "Times", "type": "number"},
                    ],
                }
            ],
            "command_line": {"placeholder": "HELP"},
            "streams": [{"id": "log", "title": "Log", "columns": [{"key": "at", "label": "Time", "format": "time"}, {"key": "text", "label": "Text"}]}],
        }

    def status(self) -> dict[str, Any]:
        if self.fail_status:
            raise OSError("reader gone")
        return {"running": self.running, "state": {"lines": len(self.lines), "raw": b"\x01\x02"}}

    def start(self, values: dict[str, Any]) -> dict[str, Any]:
        if self.running:
            raise RuntimeError("already running; stop it first")
        self.started.append(values)
        self.running = True
        return self.status()

    def stop(self) -> dict[str, Any]:
        self.running = False
        return self.status()

    def command(self, line: str) -> dict[str, Any]:
        if line.startswith("BAD"):
            raise ValueError("unknown command 'BAD'")
        self.lines.append(line)
        return {"line": line, "output": "ok: " + line}

    def stream(self, stream_id: str, after: int) -> dict[str, Any]:
        entries = [{"seq": index + 1, "at": 1700000000.0 + index, "text": line, "secret": "dropped"} for index, line in enumerate(self.lines)]
        return {"entries": [entry for entry in entries if entry["seq"] > after], "next": len(entries)}

    def help(self) -> dict[str, Any]:
        return {"groups": [{"group": "basics", "commands": [{"name": "ECHO", "usage": "ECHO <word> <times>", "summary": "Say it back.", "aliases": ["SAY"]}]}]}


class _NoStream(_FakeConsole):
    stream = None  # type: ignore[assignment]


class _BadManifest(_FakeConsole):
    def manifest(self) -> dict[str, Any]:
        return {**super().manifest(), "html": "<script>"}


@pytest.fixture()
def route(monkeypatch):
    from yggdrasim_common.gui_server.plugin_console_registry import PluginConsoleRegistry
    from yggdrasim_common.gui_server.routes import plugin_consoles

    registry = PluginConsoleRegistry()
    monkeypatch.setattr(plugin_consoles, "console_registry", lambda: registry)
    monkeypatch.setattr(plugin_consoles, "plugin_status_report", lambda: dict(_ALLOWED))
    monkeypatch.setattr(plugin_consoles, "test_registry", registry, raising=False)
    return plugin_consoles


@pytest.fixture()
def client(route):
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(route.router)
    return TestClient(app)


@pytest.fixture()
def console(route) -> _FakeConsole:
    fake = _FakeConsole()
    assert route.test_registry.add_console(fake) is True
    return fake


# --- registry ------------------------------------------------------------------------


def test_the_registry_keeps_refusals_instead_of_raising(route) -> None:
    registry = route.test_registry
    assert registry.add_console(_FakeConsole()) is True
    assert registry.add_console(_FakeConsole()) is False
    assert registry.add_console(_BadManifest("other")) is False
    assert registry.add_console(_NoStream("third")) is False
    assert registry.add_console(object()) is False
    reasons = [entry["reason"] for entry in registry.refused()]
    assert "already registered" in reasons[0]
    assert "unknown key(s) html" in reasons[1]
    assert "missing method(s) stream" in reasons[2]
    assert reasons[3].startswith("AttributeError")
    assert [entry["id"] for entry in registry.refused()] == ["demo", "other", "third", ""]
    assert [manifest["id"] for manifest in registry.manifests()] == ["demo"]


def test_the_registry_is_bounded(route) -> None:
    from yggdrasim_common.gui_server import plugin_console_registry as module

    registry = route.test_registry
    accepted = [registry.add_console(_FakeConsole(f"c{index}")) for index in range(module.MAX_CONSOLES + 1)]
    assert accepted.count(True) == module.MAX_CONSOLES and accepted[-1] is False
    assert "at most" in registry.refused()[-1]["reason"]
    for index in range(module.MAX_REFUSALS * 2):
        assert registry.add_console(_BadManifest(f"bad{index}")) is False
    assert len(registry.refused()) == module.MAX_REFUSALS
    assert len(registry.manifests()) == module.MAX_CONSOLES


def test_the_registry_is_filled_once_through_extend_target(monkeypatch) -> None:
    from yggdrasim_common.gui_server import plugin_console_registry as module

    calls: list[Any] = []

    def fake_extend(target: Any) -> Any:
        calls.append(target)
        target.add_console(_FakeConsole())
        return target

    monkeypatch.setattr(module, "extend_target_with_plugins", fake_extend)
    module.reset_console_registry_for_tests()
    try:
        first = module.console_registry()
        assert module.console_registry() is first
        assert len(calls) == 1 and type(calls[0]).__name__ == "PluginConsoleRegistry"
        assert first.get("demo") is not None
    finally:
        module.reset_console_registry_for_tests()


# --- list ------------------------------------------------------------------------------


def test_the_list_offers_consoles_and_refusals(client, console, route) -> None:
    route.test_registry.add_console(_BadManifest("other"))
    body = client.get("/api/plugin-consoles").json()
    assert body["available"] is True and body["reason"] == ""
    assert [manifest["id"] for manifest in body["consoles"]] == ["demo"]
    assert body["consoles"][0]["actions"][0]["template"] == "ECHO {word} {times}"
    assert body["refused"][0]["id"] == "other"


def test_the_list_reports_the_loader_reason_when_plugins_are_off(client, route, monkeypatch) -> None:
    monkeypatch.setattr(route, "plugin_status_report", lambda: {"allowed": False, "block_reason": "Plugin loading disabled by default.", "requires_restart": True})
    body = client.get("/api/plugin-consoles").json()
    assert body["available"] is False and "disabled by default" in body["reason"]
    assert body["consoles"] == [] and body["requires_restart"] is True


def test_the_list_never_fails(client, route, monkeypatch) -> None:
    def broken() -> Any:
        raise OSError("runtime root unreadable")

    monkeypatch.setattr(route, "console_registry", broken)
    response = client.get("/api/plugin-consoles")
    assert response.status_code == 200
    assert response.json()["available"] is False and "OSError" in response.json()["reason"]


# --- per-console routes -------------------------------------------------------------------


def test_an_unknown_console_is_404(client, console) -> None:
    assert client.get("/api/plugin-consoles/nope/status").status_code == 404
    assert client.post("/api/plugin-consoles/nope/command", json={"line": "PING"}).status_code == 404


def test_start_checks_values_before_the_console_sees_them(client, console) -> None:
    refused = client.post("/api/plugin-consoles/demo/start", json={"values": {"count": 11}})
    assert refused.status_code == 422 and "Count: above 9" in refused.json()["detail"]
    assert client.post("/api/plugin-consoles/demo/start", json={"values": {"extra": 1}}).status_code == 422
    assert console.started == []
    started = client.post("/api/plugin-consoles/demo/start", json={"values": {"count": "4"}})
    assert started.status_code == 200 and started.json()["running"] is True
    assert console.started == [{"count": 4}]
    again = client.post("/api/plugin-consoles/demo/start", json={})
    assert again.status_code == 409 and "already running" in again.json()["detail"]
    assert client.post("/api/plugin-consoles/demo/stop").json()["running"] is False


def test_a_command_line_reaches_the_console_as_typed(client, console) -> None:
    answer = client.post("/api/plugin-consoles/demo/command", json={"line": "  PING now "})
    assert answer.json() == {"line": "PING now", "output": "ok: PING now", "truncated": False}
    failed = client.post("/api/plugin-consoles/demo/command", json={"line": "BAD"})
    assert failed.status_code == 422 and "unknown command" in failed.json()["detail"]
    assert client.post("/api/plugin-consoles/demo/command", json={"line": "a\u0000b"}).status_code == 422


def test_an_action_is_rendered_from_its_template(client, console) -> None:
    answer = client.post("/api/plugin-consoles/demo/command", json={"action": "echo", "values": {"word": "hi", "times": 2}})
    assert answer.status_code == 200 and answer.json()["line"] == "ECHO hi 2"
    for values in ({"word": "hi there", "times": 1}, {"word": "--flag", "times": 1}, {"word": "hi"}):
        refused = client.post("/api/plugin-consoles/demo/command", json={"action": "echo", "values": values})
        assert refused.status_code == 422, values
    assert console.lines == ["ECHO hi 2"]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"line": "PING", "action": "echo"},
        {"action": "nope"},
        {"line": "PING", "values": {"word": "x"}},
    ],
)
def test_a_command_is_a_line_or_a_declared_action(client, console, body: dict[str, Any]) -> None:
    assert client.post("/api/plugin-consoles/demo/command", json=body).status_code == 422
    assert console.lines == []


def test_one_poll_answers_status_and_every_stream(client, console) -> None:
    client.post("/api/plugin-consoles/demo/start", json={})
    client.post("/api/plugin-consoles/demo/command", json={"line": "ONE"})
    client.post("/api/plugin-consoles/demo/command", json={"line": "TWO"})
    body = client.get("/api/plugin-consoles/demo/stream", params={"cursor": "log:0"}).json()
    assert body["status"]["running"] is True and body["status"]["state"]["raw"] == "0102"
    log = body["streams"]["log"]
    assert [row["text"] for row in log["entries"]] == ["ONE", "TWO"] and log["next"] == 2
    assert set(log["entries"][0]) == {"at", "text"}
    later = client.get("/api/plugin-consoles/demo/stream", params={"cursor": "log:2"}).json()
    assert later["streams"]["log"]["entries"] == []
    assert client.get("/api/plugin-consoles/demo/stream").json()["streams"]["log"]["next"] == 2
    for cursor in ("nope:1", "log:x", "log"):
        assert client.get("/api/plugin-consoles/demo/stream", params={"cursor": cursor}).status_code == 422


def test_polls_report_provider_failures_instead_of_failing(client, console) -> None:
    console.fail_status = True
    status = client.get("/api/plugin-consoles/demo/status")
    assert status.status_code == 200
    assert status.json() == {"running": False, "last_error": "OSError: reader gone"}
    poll = client.get("/api/plugin-consoles/demo/stream")
    assert poll.status_code == 200 and poll.json()["status"]["last_error"] == "OSError: reader gone"


def test_help_is_passed_through_the_sanitiser(client, console) -> None:
    body = client.get("/api/plugin-consoles/demo/help").json()
    assert body["groups"][0]["commands"][0] == {"name": "ECHO", "usage": "ECHO <word> <times>", "summary": "Say it back.", "aliases": ["SAY"]}


def test_a_console_without_a_start_form_refuses_start_and_stop(client, route) -> None:
    class _Lines(_FakeConsole):
        def manifest(self) -> dict[str, Any]:
            return {"id": "lines", "title": "Lines", "command_line": {}}

    assert route.test_registry.add_console(_Lines()) is True
    assert client.post("/api/plugin-consoles/lines/start", json={}).status_code == 409
    assert client.post("/api/plugin-consoles/lines/stop").status_code == 409
    assert client.post("/api/plugin-consoles/lines/command", json={"line": "PING"}).json()["output"] == "ok: PING"


# --- wiring ---------------------------------------------------------------------------------


def test_the_routes_are_registered_in_openapi() -> None:
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.routes import plugin_consoles

    app = FastAPI()
    app.include_router(plugin_consoles.router)
    paths = app.openapi()["paths"]
    for verb in ("status", "start", "stop", "command", "stream", "help"):
        assert f"/api/plugin-consoles/{{console_id}}/{verb}" in paths, verb
    assert "/api/plugin-consoles" in paths and "/api/plugin-consoles/pills" in paths


def test_the_app_mounts_the_router() -> None:
    source = (_REPO_ROOT / "yggdrasim_common" / "gui_server" / "app.py").read_text(encoding="utf-8")
    assert "from .routes import plugin_consoles as plugin_console_routes" in source
    assert "app.include_router(plugin_console_routes.router)" in source


# --- comparison panel ----------------------------------------------------------------


class _CompareConsole(_FakeConsole):
    """A console whose status carries a comparison nested deeper than ``plain`` keeps."""

    def manifest(self) -> dict[str, Any]:
        return {
            **super().manifest(),
            "id": "pair",
            "compare": {"title": "Card and platform", "sides": [{"id": "card", "label": "Card"}, {"id": "platform", "label": "Platform"}]},
        }

    def status(self) -> dict[str, Any]:
        payload = super().status()
        payload["compare"] = {
            "sections": [
                {
                    "title": "Profiles",
                    "rows": [
                        {"label": "8988201234567890123", "cells": {"card": "enabled", "platform": {"state": "disabled"}}, "verdict": "differs"},
                        {"label": "only here", "cells": {"card": "present", "elsewhere": "dropped"}, "verdict": "missing"},
                    ],
                }
            ]
        }
        return payload


def test_a_comparison_reaches_the_view_as_text_cells_on_every_status_path(route, client) -> None:
    assert route.test_registry.add_console(_CompareConsole()) is True
    listed = client.get("/api/plugin-consoles").json()["consoles"][0]
    assert listed["compare"]["sides"] == [{"id": "card", "label": "Card"}, {"id": "platform", "label": "Platform"}]
    answers = [
        client.get("/api/plugin-consoles/pair/status").json(),
        client.get("/api/plugin-consoles/pair/stream?cursor=log:0").json()["status"],
        client.post("/api/plugin-consoles/pair/start", json={"values": {}}).json(),
        client.post("/api/plugin-consoles/pair/stop").json(),
    ]
    for answer in answers:
        rows = answer["compare"]["sections"][0]["rows"]
        assert rows[0]["cells"] == {"card": "enabled", "platform": "{'state': 'disabled'}"}
        assert rows[1] == {"label": "only here", "cells": {"card": "present", "platform": ""}, "verdict": "missing"}
        assert all(isinstance(cell, str) for row in rows for cell in row["cells"].values())


def test_a_console_without_a_comparison_never_passes_one_on(route, client, console) -> None:
    console.status = lambda: {"running": False, "compare": {"sections": [{"title": "x", "rows": []}]}}  # type: ignore[method-assign]
    assert "compare" not in client.get("/api/plugin-consoles/demo/status").json()


# --- filling a start field -----------------------------------------------------------


class _FillConsole(_FakeConsole):
    def __init__(self) -> None:
        super().__init__("filler")
        self.asked: list[tuple[str, dict[str, Any]]] = []

    def manifest(self) -> dict[str, Any]:
        base = super().manifest()
        base["start"] = {"fields": [
            {"name": "count", "label": "Count", "type": "number", "min": 1, "max": 9, "default": 3, "required": True},
            {"name": "serial", "label": "Serial", "type": "text", "pattern": "[0-9]{4}", "max_length": 4, "fill": {"label": "Read from card"}},
        ]}
        return base

    def fill(self, field: str, values: dict[str, Any]) -> dict[str, Any]:
        self.asked.append((field, values))
        if values["count"] == 9:
            raise RuntimeError("no card in the reader")
        return {"value": "123456", "note": "read from the test reader"}


def test_a_start_field_is_filled_from_the_other_values(route, client) -> None:
    filler = _FillConsole()
    assert route.test_registry.add_console(filler) is True
    answer = client.post("/api/plugin-consoles/filler/fill", json={"field": "serial", "values": {"count": 2, "serial": "99"}})
    assert answer.status_code == 200 and answer.json() == {"value": "1234", "note": "read from the test reader"}
    # The field being filled is not checked (a half-typed value), the others are, none required.
    assert filler.asked == [("serial", {"count": 2, "serial": ""})]
    assert client.post("/api/plugin-consoles/filler/fill", json={"field": "count", "values": {}}).status_code == 422
    assert client.post("/api/plugin-consoles/filler/fill", json={"field": "serial", "values": {"count": "x"}}).status_code == 422
    refused = client.post("/api/plugin-consoles/filler/fill", json={"field": "serial", "values": {"count": 9}})
    assert refused.status_code == 409 and "no card" in refused.json()["detail"]


def test_a_console_with_a_fill_field_needs_a_fill_method(route) -> None:
    class _NoFill(_FillConsole):
        fill = None  # type: ignore[assignment]

    assert route.test_registry.add_console(_NoFill()) is False
    assert "missing method(s) fill" in route.test_registry.refused()[-1]["reason"]


# --- top bar pills -----------------------------------------------------------------------


class _PillConsole(_FakeConsole):
    def __init__(self, console_id: str = "pilled", answer: Any = None) -> None:
        super().__init__(console_id)
        self.answer = answer

    def manifest(self) -> dict[str, Any]:
        return {**super().manifest(), "pills": [{"id": "network", "label": "Net"}, {"id": "link", "label": "Link"}]}

    def pills(self) -> Any:
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def test_the_pills_poll_answers_every_console_with_a_value(route, client, console) -> None:
    assert route.test_registry.add_console(_PillConsole("first", {"network": {"value": "001/01 LTE", "state": "ok"}, "link": {"value": ""}})) is True
    assert route.test_registry.add_console(_PillConsole("broken", OSError("reader gone"))) is True
    assert route.test_registry.add_console(_PillConsole("junk", ["not", "a", "dict"])) is True
    answer = client.get("/api/plugin-consoles/pills")
    assert answer.status_code == 200
    # The console without pills, the broken one and the junk answer add nothing.
    assert answer.json() == {"pills": [{"console": "first", "title": "Demo console", "id": "network", "label": "Net", "value": "001/01 LTE", "state": "ok"}]}


def test_the_pills_poll_never_fails(client, route, monkeypatch) -> None:
    def broken() -> Any:
        raise RuntimeError("registry exploded")

    monkeypatch.setattr(route, "console_registry", broken)
    assert client.get("/api/plugin-consoles/pills").json() == {"pills": []}


def test_a_console_with_pills_needs_a_pills_method(route) -> None:
    class _NoPills(_PillConsole):
        pills = None  # type: ignore[assignment]

    assert route.test_registry.add_console(_NoPills()) is False
    assert "missing method(s) pills" in route.test_registry.refused()[-1]["reason"]
