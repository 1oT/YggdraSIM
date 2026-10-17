# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Contracts of the run-form routes: what reaches a console and what comes back.

A neutral fake console answers the run methods on a fresh registry. The
route passes a provider only the visible fields in use, refuses a start
whose credential is not stored, and cuts every answer to the closed shapes:
unknown states read ``unknown``, a stored secret never comes back, and a
report's lists and texts are capped.
"""
from __future__ import annotations

from typing import Any

import pytest

from tests.plugin_console_runs_support import demo_manifest, named_demo_runs, pick_demo_runs

try:  # pragma: no cover - the import itself is under test
    import fastapi as _fastapi  # noqa: F401
    from fastapi.testclient import TestClient

    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

pytestmark = pytest.mark.skipif(not _FASTAPI_AVAILABLE, reason="FastAPI not installed -- gui extra missing.")


class _RunsConsole:
    def __init__(self) -> None:
        self.started: list[dict[str, Any]] = []
        self.cancelled: list[str] = []
        self.stored: dict[str, dict[str, Any]] = {}
        self.report: dict[str, Any] = {}

    def manifest(self) -> dict[str, Any]:
        return demo_manifest()

    def status(self) -> dict[str, Any]:
        return {"running": bool(self.started), "active_run": "run-1" if self.started else ""}

    def run_start(self, request: dict[str, Any]) -> dict[str, Any]:
        if request["values"].get("note") == "busy":
            raise RuntimeError("a run is in progress")
        self.started.append(request)
        return {"id": "run-1", "status": "QUEUED", "title": "Basic by Ann", "time": "2026-09-25T10:00:00Z", "private": "dropped"}

    def runs(self, limit: int) -> list[dict[str, Any]]:
        rows = [{"id": f"run-{index}", "status": "passed", "title": f"Run {index}"} for index in range(300)]
        return rows[:limit] + [{"id": "odd", "status": "<b>WON</b>"}]

    def run(self, run_id: str) -> dict[str, Any]:
        if run_id != "run-1":
            raise KeyError(run_id)
        return self.report

    def run_events(self, run_id: str, after: int) -> dict[str, Any]:
        rows = [{"seq": index + 1, "time": "10:00:0" + str(index), "level": level, "text": f"event {index}"} for index, level in enumerate(("info", "ok", "warn", "error", "shout"))]
        return {"entries": [row for row in rows if row["seq"] > after], "next": 5, "finished": True}

    def run_cancel(self, run_id: str) -> dict[str, Any]:
        self.cancelled.append(run_id)
        return {"run_id": run_id, "cancel_requested": True}

    def credentials(self) -> dict[str, Any]:
        entry = self.stored.get("service")
        if entry is None:
            return {"service": {"stored": False, "usable": False, "summary": "Not stored yet."}, "stray": {"stored": True}}
        return {"service": {"stored": True, "usable": True, "summary": "Stored, fingerprint ab12", "values": {"url": entry["url"], "token": entry["token"]}, "token": entry["token"]}}

    def credential_store(self, credential_id: str, values: dict[str, Any]) -> dict[str, Any]:
        self.stored[credential_id] = dict(values)
        return self.credentials()[credential_id]

    def credential_forget(self, credential_id: str) -> dict[str, Any]:
        self.stored.pop(credential_id, None)
        return self.credentials()[credential_id]


@pytest.fixture()
def console(monkeypatch) -> _RunsConsole:
    from yggdrasim_common.gui_server.plugin_console_registry import PluginConsoleRegistry
    from yggdrasim_common.gui_server.routes import plugin_console_runs

    registry = PluginConsoleRegistry()
    fake = _RunsConsole()
    assert registry.add_console(fake), registry.refused()
    monkeypatch.setattr(plugin_console_runs, "console_registry", lambda: registry)
    return fake


@pytest.fixture()
def client(console):
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.routes import plugin_console_runs

    app = FastAPI()
    app.include_router(plugin_console_runs.router)
    return TestClient(app)


def _start(client, items: list[str], values: dict[str, Any]):
    return client.post("/api/plugin-consoles/runner/runs", json={"variant": "basic", "items": items, "values": values})


def test_a_start_passes_only_the_visible_fields_in_use(client, console) -> None:
    answer = _start(client, ["ping"], {"operator": "Ann", "reader": "R", "mode": "remote", "host": "h", "key": "K"})
    assert answer.status_code == 200, answer.text
    assert answer.json() == {"id": "run-1", "status": "queued", "title": "Basic by Ann", "summary": "", "time": "2026-09-25T10:00:00Z"}
    assert console.started == [
        {
            "variant": "basic",
            "items": ["ping"],
            "auto_items": [],
            "values": {"operator": "Ann", "note": "", "reader": "R", "source": "card", "count": 2, "verbose": False},
            "credentials": [],
        }
    ]


def test_a_start_refused_by_the_form_rules_never_reaches_the_console(client, console) -> None:
    answer = _start(client, ["ping"], {"reader": "R"})
    assert answer.status_code == 422 and "Operator: required" in answer.json()["detail"]
    assert _start(client, ["ping"], {"operator": "A", "reader": "R", "note": "busy"}).status_code == 409
    assert console.started == []


def test_a_needed_credential_has_to_be_stored_first(client, console) -> None:
    values = {"operator": "Ann", "reader": "R", "use_key": True, "key": "K"}
    refused = _start(client, ["sign"], values)
    assert refused.status_code == 409 and refused.json()["detail"] == "store the Service key first"
    stored = client.post("/api/plugin-consoles/runner/credentials/service", json={"values": {"url": "https://api.example.test/v1", "token": "SECRET-TOKEN"}})
    assert stored.status_code == 200, stored.text
    assert "SECRET-TOKEN" not in stored.text
    assert stored.json() == {"stored": True, "usable": True, "summary": "Stored, fingerprint ab12", "values": {"url": "https://api.example.test/v1"}}
    assert _start(client, ["sign"], values).status_code == 200
    assert console.started[-1]["credentials"] == ["service"]


def test_credential_status_is_a_closed_shape(client, console) -> None:
    listing = client.get("/api/plugin-consoles/runner/credentials").json()
    assert listing == {"credentials": {"service": {"stored": False, "usable": False, "summary": "Not stored yet.", "values": {}}}}
    assert client.post("/api/plugin-consoles/runner/credentials/ghost", json={"values": {}}).status_code == 404
    assert client.post("/api/plugin-consoles/runner/credentials/service", json={"values": {"token": "T", "html": "<b>"}}).status_code == 422
    console.stored["service"] = {"url": "u", "token": "SECRET"}
    forgotten = client.delete("/api/plugin-consoles/runner/credentials/service")
    assert forgotten.status_code == 200 and forgotten.json()["stored"] is False


def test_the_history_is_capped_and_states_are_a_fixed_vocabulary(client) -> None:
    rows = client.get("/api/plugin-consoles/runner/runs?limit=3").json()["runs"]
    assert [row["id"] for row in rows] == ["run-0", "run-1", "run-2"]
    assert client.get("/api/plugin-consoles/runner/runs?limit=500").status_code == 422
    everything = client.get("/api/plugin-consoles/runner/runs?limit=200").json()["runs"]
    assert len(everything) == 200


def test_a_report_is_cut_to_its_shape(client, console) -> None:
    console.report = {
        "id": "run-1",
        "status": "FAILED",
        "title": "Basic by Ann",
        "meta": ["started 10:00"] * 40,
        "results": [
            {
                "label": "Ping",
                "status": "PASSED",
                "note": "",
                "checks": [{"ok": True, "text": "answered"}, {"ok": "yes", "text": "truthy text is not ok"}],
                "details": [{"summary": "trace", "text": "x" * 20000, "extra": 1}],
            },
            {"label": "Sign", "status": "melted"},
        ],
        "script": "<script>",
    }
    report = client.get("/api/plugin-consoles/runner/runs/run-1").json()
    assert set(report) == {"id", "status", "finished", "title", "meta", "error", "results"}
    assert report["status"] == "failed" and report["finished"] is True and len(report["meta"]) == 16
    first, second = report["results"]
    assert first["status"] == "passed" and [check["ok"] for check in first["checks"]] == [True, False]
    assert first["details"] == [{"summary": "trace", "text": "x" * 16384}]
    assert second == {"label": "Sign", "status": "unknown", "note": "", "checks": [], "details": []}
    assert client.get("/api/plugin-consoles/runner/runs/run-9").status_code == 404
    assert client.get("/api/plugin-consoles/runner/runs/..%2Fetc").status_code in (404, 422)
    assert client.get("/api/plugin-consoles/runner/runs/-rf").status_code == 422


def test_events_keep_the_level_vocabulary(client) -> None:
    batch = client.get("/api/plugin-consoles/runner/runs/run-1/events?after=1").json()
    assert [entry["level"] for entry in batch["entries"]] == ["ok", "warn", "error", "info"]
    assert batch["next"] == 5 and batch["finished"] is True and batch["truncated"] is False
    assert client.get("/api/plugin-consoles/runner/runs/run-1/events?after=-1").status_code == 422


def test_cancel_answers_whether_it_was_accepted(client, console) -> None:
    answer = client.post("/api/plugin-consoles/runner/runs/run-1/cancel")
    assert answer.json() == {"id": "run-1", "cancel_requested": True}
    assert console.cancelled == ["run-1"]


def test_a_console_without_a_run_form_is_refused(monkeypatch, client) -> None:
    from yggdrasim_common.gui_server.plugin_console_registry import PluginConsoleRegistry
    from yggdrasim_common.gui_server.routes import plugin_console_runs

    class _Lines:
        def manifest(self) -> dict[str, Any]:
            return {"id": "lines", "title": "Lines", "command_line": {}}

        def status(self) -> dict[str, Any]:
            return {"running": True}

        def command(self, line: str) -> dict[str, Any]:
            return {"output": line}

    registry = PluginConsoleRegistry()
    assert registry.add_console(_Lines())
    monkeypatch.setattr(plugin_console_runs, "console_registry", lambda: registry)
    assert client.get("/api/plugin-consoles/lines/runs").status_code == 409
    assert client.get("/api/plugin-consoles/nobody/runs").status_code == 404


def test_a_console_missing_a_run_method_is_refused_at_registration() -> None:
    from yggdrasim_common.gui_server.plugin_console_registry import PluginConsoleRegistry

    class _Half(_RunsConsole):
        run_events = None  # type: ignore[assignment]

    registry = PluginConsoleRegistry()
    assert registry.add_console(_Half()) is False
    assert "missing method(s) run_events" in registry.refused()[0]["reason"]


# --- named credentials ----------------------------------------------------------


class _NamedConsole(_RunsConsole):
    """The demo console with a named credential whose entries live in ``vault``."""

    def __init__(self) -> None:
        super().__init__()
        self.vault: dict[str, dict[str, Any]] = {}
        self.calls: list[tuple[Any, ...]] = []

    def manifest(self) -> dict[str, Any]:
        return demo_manifest(named_demo_runs())

    def _vault(self) -> dict[str, Any]:
        entries = [
            {"name": name, "usable": entry.get("usable", True), "summary": "fingerprint " + name, "values": {"url": entry["url"], "token": entry["token"]}, "token": entry["token"]}
            for name, entry in self.vault.items()
        ]
        return {"summary": f"{len(entries)} stored", "entries": entries, "token": "LEAK"}

    def credentials(self) -> dict[str, Any]:
        return {**super().credentials(), "vault": self._vault()}

    def credential_store(self, credential_id: str, values: dict[str, Any], name: Any = None) -> dict[str, Any]:
        self.calls.append(("store", credential_id, name))
        if credential_id != "vault":
            return super().credential_store(credential_id, values)
        self.vault[name] = dict(values)
        return self._vault()

    def credential_forget(self, credential_id: str, name: Any = None) -> dict[str, Any]:
        self.calls.append(("forget", credential_id, name))
        if credential_id != "vault":
            return super().credential_forget(credential_id)
        self.vault.pop(name, None)
        return self._vault()


@pytest.fixture()
def named(monkeypatch) -> tuple[Any, _NamedConsole]:
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.plugin_console_registry import PluginConsoleRegistry
    from yggdrasim_common.gui_server.routes import plugin_console_runs

    registry = PluginConsoleRegistry()
    fake = _NamedConsole()
    assert registry.add_console(fake), registry.refused()
    monkeypatch.setattr(plugin_console_runs, "console_registry", lambda: registry)
    app = FastAPI()
    app.include_router(plugin_console_runs.router)
    return TestClient(app), fake


_VAULT = "/api/plugin-consoles/runner/credentials/vault"


def test_a_named_credential_lists_its_entries_without_secrets(named) -> None:
    client, console = named
    assert client.get("/api/plugin-consoles/runner/credentials").json()["credentials"]["vault"] == {"stored": False, "usable": False, "summary": "0 stored", "entries": []}
    console.vault = {"prod": {"url": "https://vault.example.test", "token": "SECRET-1"}, "PROD": {"url": "u", "token": "SECRET-2"}, "bad name": {"url": "u", "token": "SECRET-3"}}
    console.vault.update({f"k{index}": {"url": "u", "token": "SECRET-4", "usable": False} for index in range(40)})
    listing = client.get("/api/plugin-consoles/runner/credentials")
    assert "SECRET" not in listing.text and "LEAK" not in listing.text
    vault = listing.json()["credentials"]["vault"]
    assert set(vault) == {"stored", "usable", "summary", "entries"} and vault["usable"] is True
    # A malformed name and a second spelling of a name are dropped; the list is capped.
    assert [entry["name"] for entry in vault["entries"][:2]] == ["prod", "k0"] and len(vault["entries"]) == 32
    assert vault["entries"][0] == {"name": "prod", "usable": True, "summary": "fingerprint prod", "values": {"url": "https://vault.example.test"}}


def test_storing_and_forgetting_a_named_entry_names_it(named) -> None:
    client, console = named
    stored = client.post(_VAULT, json={"name": " prod ", "values": {"token": "SECRET-1"}})
    assert stored.status_code == 200, stored.text
    assert "SECRET-1" not in stored.text and [entry["name"] for entry in stored.json()["entries"]] == ["prod"]
    assert console.calls[-1] == ("store", "vault", "prod")
    assert client.post(_VAULT, json={"values": {"token": "T"}}).json()["detail"] == "Vault token: an entry name is required"
    assert client.post(_VAULT, json={"name": "two words", "values": {"token": "T"}}).status_code == 422
    assert client.delete(_VAULT).status_code == 422
    forgotten = client.delete(_VAULT + "?name=prod")
    assert forgotten.status_code == 200 and forgotten.json()["entries"] == []
    assert console.calls[-1] == ("forget", "vault", "prod")
    # A plain credential keeps one entry: it takes no name and its methods get none.
    service = "/api/plugin-consoles/runner/credentials/service"
    assert client.post(service, json={"name": "prod", "values": {"token": "T"}}).status_code == 422
    assert client.delete(service + "?name=prod").status_code == 422
    assert client.post(service, json={"values": {"token": "T"}}).status_code == 200
    assert console.calls[-1] == ("store", "service", None)


def _start_other(client, picks: Any = None):
    body: dict[str, Any] = {"variant": "other", "items": ["only"], "values": {"operator": "Ann"}}
    if picks is not None:
        body["credential_entries"] = picks
    return client.post("/api/plugin-consoles/runner/runs", json=body)


class _PickConsole(_RunsConsole):
    """A console whose second variant has a field it fills from its status."""

    def __init__(self) -> None:
        super().__init__()
        self.lists: Any = {"targets": [{"value": "t1", "label": "One"}, {"value": "t2", "label": "Two"}]}
        self.status_calls = 0

    def manifest(self) -> dict[str, Any]:
        return demo_manifest(pick_demo_runs())

    def status(self) -> dict[str, Any]:
        self.status_calls += 1
        if isinstance(self.lists, Exception):
            raise self.lists
        return {**super().status(), "choices": self.lists}


@pytest.fixture()
def picking(monkeypatch):
    from fastapi import FastAPI

    from yggdrasim_common.gui_server.plugin_console_registry import PluginConsoleRegistry
    from yggdrasim_common.gui_server.routes import plugin_console_runs

    registry = PluginConsoleRegistry()
    fake = _PickConsole()
    assert registry.add_console(fake), registry.refused()
    monkeypatch.setattr(plugin_console_runs, "console_registry", lambda: registry)
    app = FastAPI()
    app.include_router(plugin_console_runs.router)
    return TestClient(app), fake


def _start_pick(client, target: str):
    return client.post("/api/plugin-consoles/runner/runs", json={"variant": "other", "items": ["aim"], "values": {"operator": "Ann", "target": target}})


def test_a_pick_is_checked_against_the_list_current_at_the_start(picking) -> None:
    client, console = picking
    started = _start_pick(client, "t2")
    assert started.status_code == 200, started.text
    assert console.started[-1]["values"] == {"operator": "Ann", "note": "", "target": "t2"} and console.status_calls == 1
    refused = _start_pick(client, "t9")
    assert refused.status_code == 422 and refused.json()["detail"] == "Target: not one of the current choices"
    blank = _start_pick(client, "")
    assert blank.status_code == 422 and blank.json()["detail"] == "Target: required"
    console.lists = {"targets": [{"value": "t9", "label": "Nine"}]}
    assert _start_pick(client, "t9").status_code == 200
    # A status the console cannot answer leaves nothing to pick from; the start says so.
    console.lists = RuntimeError("no session")
    failed = _start_pick(client, "t9")
    assert failed.status_code == 422 and failed.json()["detail"] == "Target: nothing to pick from yet"
    assert len(console.started) == 2
    # The console's own answer is cut to the declared sources on the status route too.
    console.lists = {"targets": [{"value": "t1", "label": "One"}], "stray": [{"value": "s", "label": "S"}]}


def test_a_form_without_a_filled_choice_never_asks_the_console_for_lists(client, console) -> None:
    calls = {"status": 0}
    original = console.status

    def counted() -> dict[str, Any]:
        calls["status"] += 1
        return original()

    console.status = counted
    assert _start(client, ["ping"], {"operator": "Ann", "reader": "R"}).status_code == 200
    assert calls["status"] == 0


def test_a_start_needs_a_stored_usable_pick(named) -> None:
    client, console = named
    assert _start_other(client).json()["detail"] == "store the Vault token first"
    console.vault = {"prod": {"url": "u", "token": "T1"}, "stage": {"url": "u", "token": "T2"}, "old": {"url": "u", "token": "T3", "usable": False}}
    assert _start_other(client).json()["detail"] == "Vault token: pick the entry this run uses"
    for pick in ("old", "ghost"):
        refused = _start_other(client, {"vault": pick})
        assert refused.status_code == 409 and refused.json()["detail"] == "Vault token: the picked entry is not stored or not usable"
    assert console.started == []
    started = _start_other(client, {"vault": "stage"})
    assert started.status_code == 200, started.text
    assert console.started[-1]["credentials"] == ["vault"] and console.started[-1]["credential_entries"] == {"vault": "stage"}
