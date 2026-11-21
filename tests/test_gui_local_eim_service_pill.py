# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The Local eIM service pill in the top bar: its status route, its wording and its wiring.

The service runs as a process of its own, so the page asks the server for its
state (``/api/local-eim/service``) on a gated background poll; a click runs
the Start service or Stop service action, the SERVE verb of the shell. The
page's own function words each state under ``node``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from unittest import mock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from yggdrasim_common.gui_server.routes import local_eim as local_eim_routes

REPO = Path(__file__).resolve().parents[1]
CENTER = REPO / "gui_frontend" / "src" / "js" / "command-center.js"
INDEX = REPO / "gui_frontend" / "src" / "index.html"


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(local_eim_routes.router)
    return TestClient(app)


def test_the_route_reports_a_stopped_service_and_nothing_of_the_store() -> None:
    stopped = {"running": False, "store": "/srv/store", "log": "/srv/store/server.log"}
    with mock.patch("SCP11.eim_local.engine.server.describe", return_value=stopped):
        answer = _client().get("/api/local-eim/service")
    assert answer.status_code == 200
    assert answer.json() == {"running": False, "answers": False}


def test_the_route_reports_where_a_running_service_answers() -> None:
    running = {"running": True, "answers": True, "url": "http://127.0.0.1:8743", "pid": 4242,
               "started_at": "2026-11-18T14:02:00+00:00", "eim_fqdn": "eim1.yggdrasim.local",
               "tls_url": "https://127.0.0.1:8744", "tls_setup": "ygg-eim1", "smdp_tls_url": "https://127.0.0.1:8745",
               "smds_tls_url": "", "store": "/srv/store", "log": "/srv/store/server.log", "host": "127.0.0.1"}
    with mock.patch("SCP11.eim_local.engine.server.describe", return_value=running):
        state = _client().get("/api/local-eim/service").json()
    assert state == {"running": True, "answers": True, "url": "http://127.0.0.1:8743", "pid": 4242,
                     "started_at": "2026-11-18T14:02:00+00:00", "eim_fqdn": "eim1.yggdrasim.local",
                     "tls_url": "https://127.0.0.1:8744", "tls_setup": "ygg-eim1",
                     "smdp_tls_url": "https://127.0.0.1:8745"}


def test_the_status_handler_is_a_plain_function_run_off_the_event_loop() -> None:
    # The /ping check can take two seconds: FastAPI runs a plain def on a worker thread.
    import inspect

    assert not inspect.iscoroutinefunction(local_eim_routes.service_state)


_HARNESS = """
%s
var services = %s;
console.log(JSON.stringify(services.map(function (service) { return ccLocalEimPillView(service); })));
"""


def test_the_pill_words_each_state() -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    text = CENTER.read_text(encoding="utf-8")
    start = text.index("  function ccLocalEimPillView(service) {")
    function = text[start:text.index("  function ccRenderLocalEimPill(", start)]
    services = [
        None,
        {"running": False, "answers": False},
        {"running": True, "answers": True, "url": "http://127.0.0.1:8743", "tls_url": "https://127.0.0.1:8744",
         "pid": 4242},
        {"running": True, "answers": False, "url": "http://127.0.0.1:8743", "pid": 4242},
    ]
    views = json.loads(subprocess.run([node, "-e", _HARNESS % (function, json.dumps(services))], capture_output=True,
                                      text=True, timeout=30, check=True).stdout)
    assert [(view["state"], view["value"]) for view in views] == [
        ("idle", "unknown"), ("idle", "stopped"), ("running", "running"), ("warn", "not answering")]
    assert "restart the GUI" in views[0]["title"]
    assert "Click to start it with the defaults: port 8743" in views[1]["title"]
    assert views[2]["title"] == ("Local eIM service running at http://127.0.0.1:8743, card TLS https://127.0.0.1:8744 "
                                 "(pid 4242). Click to stop it.")
    assert "does not answer" in views[3]["title"] and "Click to stop it." in views[3]["title"]


def test_the_pill_is_in_the_top_bar_and_wired_to_the_service_actions() -> None:
    index = INDEX.read_text(encoding="utf-8")
    assert 'id="topbar-local-eim"' in index
    assert ('<span class="topbar-card-bridge-label"><span class="topbar-local-eim-qualifier">Local </span>'
            '<span class="topbar-card-bridge-name">eIM</span></span>' in index)
    # The legend is set in capitals; the name inside it keeps its case.
    assert ".topbar-card-bridge-name {\n  text-transform: none;\n}" in (
        REPO / "gui_frontend" / "src" / "css" / "layout" / "shell.css").read_text(encoding="utf-8")
    assert index.index('id="topbar-card-bridge"') < index.index('id="topbar-local-eim"')
    # The bar gives way in order: at 1300 px the crumb goes for every page (the pill made Classic overlap
    # it at 1280 px), at 1240 px the pill drops the word Local.
    shell = (REPO / "gui_frontend" / "src" / "css" / "layout" / "shell.css").read_text(encoding="utf-8")
    narrow = shell[shell.index("@media (max-width: 1300px) {"):]
    assert ".topbar > .breadcrumbs {" in narrow[:narrow.index("@media (max-width: 1240px) {")]
    assert ".topbar-local-eim-qualifier {" in narrow[narrow.index("@media (max-width: 1240px) {"):]
    center = CENTER.read_text(encoding="utf-8")
    assert 'backgroundPollDue("local-eim-service")' in center
    assert '"eim_local.service_stop" : "eim_local.service_start"' in center
    assert "ccToggleLocalEimService();" in center and "ccStartLocalEimPillPoll();" in center
    from yggdrasim_common.gui_server.actions.eim_local_ops import SPECS

    registered = {spec.id for spec in SPECS}
    assert {"eim_local.service_start", "eim_local.service_stop"} <= registered
    naming = (REPO / "guides" / "NAMING_CONVENTIONS.md").read_text(encoding="utf-8")
    assert "Local eIM (top bar pill)" in naming
