# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""An idle desktop window holds its memory and polls less when nobody looks.

QtWebEngine 6.11.1 does not collect renderer garbage on its own
(``upstream_patches/qt-qtwebengine-renderer-gc``), so the desktop window
starts V8 with ``--expose-gc`` and the page asks for a collection once a
minute; a QtWebEngine page without the collector says so in the event log.
The background polls run at full rate with focus, once per 30 s without it
and not at all while the page is hidden. The page helpers run under
``node`` from the built bundle.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests.test_gui_saip_fcp_record_count_view import _function
from yggdrasim_common.gui_server import app as gui_app

_REPO = Path(__file__).resolve().parents[1]
_APP_JS = _REPO / "yggdrasim_common" / "gui_server" / "static" / "app.js"
_SRC_JS = _REPO / "gui_frontend" / "src" / "js"

# The stand-ins live in a function scope: from Node 21 on ``navigator`` is a
# read-only global, and a script-level ``var navigator`` leaves it in place.
_HARNESS = r"""
(function () {
var clock = 1000000;
var realNow = Date.now;
Date.now = function () { return clock; };
var document = { hidden: false, focused: true, hasFocus: function () { return this.focused; } };
var navigator = { userAgent: "" };
var intervals = [];
var warnings = [];
var collections = 0;
var window = {};
function setInterval(fn, ms) { intervals.push({ fn: fn, ms: ms }); return intervals.length; }
var logBus = { emit: function (entry) { warnings.push(entry); } };
__DEFS__
var out = {};

out.focused = [backgroundPollDue("a"), backgroundPollDue("a"), backgroundPollDue("a")];
document.focused = false;
clock += 60000;
out.unfocused_first = backgroundPollDue("a");
out.unfocused_repeat = backgroundPollDue("a");
out.other_key = backgroundPollDue("b");
clock += BACKGROUND_POLL_UNFOCUSED_MS - 1;
out.unfocused_before_window = backgroundPollDue("a");
clock += 1;
out.unfocused_after_window = backgroundPollDue("a");
document.focused = true;
out.refocused = backgroundPollDue("a");
document.hidden = true;
out.hidden = backgroundPollDue("a");
document.hidden = false;
delete document.hasFocus;
out.no_focus_api = backgroundPollDue("a");
out.slow_window_ms = BACKGROUND_POLL_UNFOCUSED_MS;

navigator.userAgent = "Mozilla/5.0 QtWebEngine/6.11.1 Chrome/140.0.7339.80 Safari/537.36";
out.qt_without_collector = scheduleEngineCollection();
out.qt_warnings = warnings.map(function (w) { return w.level + ":" + w.message; });
out.qt_intervals = intervals.length;

warnings = [];
navigator.userAgent = "Mozilla/5.0 Chrome/140.0.7339.80 Safari/537.36";
out.browser_without_collector = scheduleEngineCollection();
out.browser_warnings = warnings.length;

window.gc = function () { collections += 1; };
out.with_collector = scheduleEngineCollection();
out.collector_interval_ms = intervals.length === 1 ? intervals[0].ms : -1;
intervals[0].fn();
intervals[0].fn();
out.collections = collections;
window.gc = function () { throw new Error("collector failed"); };
intervals[0].fn();
out.survives_a_failing_collection = true;
console.log(JSON.stringify(out));
})();
"""


def _constant(bundle: str, name: str) -> str:
    match = re.search(rf"^\s*var {name} = [^;]+;", bundle, re.MULTILINE)
    assert match is not None, name
    return match.group(0)


@pytest.fixture(scope="module")
def page() -> dict[str, Any]:
    if shutil.which("node") is None:
        pytest.skip("node is required to run the bundle's helpers")
    bundle = _APP_JS.read_text(encoding="utf-8")
    defs = "\n".join(
        [_constant(bundle, name) for name in (
            "BACKGROUND_POLL_UNFOCUSED_MS", "backgroundPollLastRun", "ENGINE_COLLECTION_INTERVAL_MS",
        )]
        + [_function(bundle, name) for name in ("backgroundPollDue", "scheduleEngineCollection")]
    )
    completed = subprocess.run(
        ["node", "-e", _HARNESS.replace("__DEFS__", defs)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    if completed.returncode != 0:
        raise AssertionError(completed.stderr)
    return json.loads(completed.stdout)


def test_the_engine_starts_with_the_collector_exposed_in_one_word() -> None:
    js_flags = [flag for flag in gui_app._QTWEBENGINE_DEFAULT_FLAGS if flag.startswith("--js-flags=")]
    assert len(js_flags) == 1
    # The env value is split on spaces, so two V8 flags travel comma-separated.
    assert " " not in js_flags[0]
    assert js_flags[0].split("=", 1)[1].split(",") == ["--max-old-space-size=256", "--expose-gc"]
    assert js_flags[0] in gui_app._qtwebengine_flags(True)
    assert js_flags[0] in gui_app._qtwebengine_flags(False)


def test_the_flag_reaches_the_environment_whole(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(gui_app._QTWEBENGINE_CHROMIUM_FLAGS_ENV, "--operator-flag")
    gui_app._prepare_webview_environment("qt")
    words = __import__("os").environ[gui_app._QTWEBENGINE_CHROMIUM_FLAGS_ENV].split()
    assert "--operator-flag" in words
    assert "--js-flags=--max-old-space-size=256,--expose-gc" in words


def test_a_focused_window_polls_at_full_rate(page: dict[str, Any]) -> None:
    assert page["focused"] == [True, True, True]
    assert page["refocused"] is True
    assert page["no_focus_api"] is True


def test_an_unfocused_window_polls_once_per_window_per_poll(page: dict[str, Any]) -> None:
    assert page["slow_window_ms"] == 30000
    assert page["unfocused_first"] is True
    assert page["unfocused_repeat"] is False
    assert page["other_key"] is True
    assert page["unfocused_before_window"] is False
    assert page["unfocused_after_window"] is True


def test_a_hidden_page_does_not_poll(page: dict[str, Any]) -> None:
    assert page["hidden"] is False


def test_the_page_collects_once_a_minute_when_the_engine_allows_it(page: dict[str, Any]) -> None:
    assert page["with_collector"] is True
    assert page["collector_interval_ms"] == 60000
    assert page["collections"] == 2
    assert page["survives_a_failing_collection"] is True


def test_a_qtwebengine_page_without_the_collector_says_so(page: dict[str, Any]) -> None:
    assert page["qt_without_collector"] is False
    assert page["qt_intervals"] == 0
    assert len(page["qt_warnings"]) == 1
    assert page["qt_warnings"][0].startswith("warn:")
    assert "--expose-gc" in page["qt_warnings"][0]


def test_another_browser_without_the_collector_stays_quiet(page: dict[str, Any]) -> None:
    assert page["browser_without_collector"] is False
    assert page["browser_warnings"] == 0


def test_every_background_poll_goes_through_the_gate_and_the_page_starts_collecting() -> None:
    sources = {name: (_SRC_JS / name).read_text(encoding="utf-8") for name in (
        "core.js", "command-center.js", "plugin-console-pills.js", "trailing.js",
    )}
    gates = {
        "core.js": ('backgroundPollDue("health")', 'backgroundPollDue("remote-lab-sessions")'),
        "command-center.js": ('backgroundPollDue("readers")', 'backgroundPollDue("local-eim-service")'),
        "plugin-console-pills.js": ('backgroundPollDue("plugin-pills")',),
    }
    for name, calls in gates.items():
        for call in calls:
            assert call in sources[name], (name, call)
    assert "scheduleEngineCollection();" in sources["trailing.js"]
