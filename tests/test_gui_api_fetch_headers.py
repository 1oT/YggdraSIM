# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""The page's request helper sends one content-type header.

Header names are case-insensitive, so a caller's ``content-type`` beside a
``Content-Type`` the helper adds is one header with a doubled value. The
server does not read such a body as JSON and answers 422, which is what the
Set, Clear and Reset buttons of Environment > Configuration ran into. The
helper runs here under ``node`` with ``fetch`` replaced, and the route is
asked what it makes of the doubled value.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

_SOURCE = Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "core.js"

_HARNESS = r"""
var seen = [];
function getToken() { return "token"; }
function setApiBadge() {}
function setStatusError() {}
async function apiErrorDetail() { return ""; }
async function fetch(path, options) {
  seen.push(options.headers);
  return { status: 200, ok: true, json: async function () { return {}; } };
}
%s
(async function () {
  await apiFetch("/a", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  await apiFetch("/b", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  await apiFetch("/c", { method: "POST", body: "{}" });
  await apiFetch("/d", { method: "POST", headers: { "CONTENT-TYPE": "text/plain" }, body: "x" });
  await apiFetch("/e", {});
  console.log(JSON.stringify(seen));
})();
"""


def _content_types(headers: dict[str, str]) -> list[str]:
    return [value for name, value in headers.items() if name.lower() == "content-type"]


def test_one_content_type_whatever_case_the_caller_used() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    source = _SOURCE.read_text(encoding="utf-8")
    start = source.index("  async function apiFetch(path, options) {")
    helper = source[start:source.index("\n  }\n", start) + len("\n  }\n")]
    done = subprocess.run([node, "-e", _HARNESS % helper], capture_output=True, text=True, timeout=30, check=True)
    lowercase, capitalised, absent, other, bodiless = json.loads(done.stdout)
    assert _content_types(lowercase) == ["application/json"]
    assert _content_types(capitalised) == ["application/json"]
    assert _content_types(absent) == ["application/json"]
    # A caller's own type is kept, and a request without a body gets none.
    assert _content_types(other) == ["text/plain"]
    assert _content_types(bodiless) == []
    for headers in (lowercase, capitalised, absent, other, bodiless):
        assert headers["Authorization"] == "Bearer token"


def test_the_route_refuses_a_doubled_content_type() -> None:
    """What the page sent before: the body is then no JSON to the server."""
    fastapi = pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    from yggdrasim_common.gui_server.routes import env_flags as route

    app = fastapi.FastAPI()
    app.include_router(route.router)
    client = TestClient(app)
    # The router's own routes carry the full path. app.routes holds one _IncludedRouter in its place from
    # the FastAPI of the lock (0.139.2) on, where 0.136.1 copied the routes in.
    path = next(
        item.path for item in route.router.routes if getattr(item, "path", "").endswith("/{name}/set")
    ).replace("{name}", "YGGDRASIM_NO_SUCH_FLAG")
    body = json.dumps({"value": "x", "persist": False})
    doubled = client.post(path, content=body, headers={"content-type": "application/json, application/json"})
    assert doubled.status_code == 422
    # With one header the body is read: the answer is about the flag, here an unknown one.
    single = client.post(path, content=body, headers={"content-type": "application/json"})
    assert single.status_code != 422
