# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A file dropped on the desktop window opens by its own path.

pywebview records the paths of a native drop only while its listener
count is positive; ``native_drops.py`` raises the count once the window
exists and answers the page's ``/api/gui/native_drop/resolve`` with one
path per dropped file, matched by name and size and consumed on use. The
page then opens the file by path, so Ctrl+S saves back in place instead
of asking where an ``upload:<name>`` copy should go.
"""

from __future__ import annotations

import importlib.util
import threading
from pathlib import Path

import pytest

from yggdrasim_common.gui_server import native_drops


_ROOT = Path(__file__).resolve().parents[1]
_APP = _ROOT / "yggdrasim_common/gui_server/app.py"
_TRAILING = _ROOT / "gui_frontend/src/js/trailing.js"
_WORKBENCH = _ROOT / "gui_frontend/src/js/saip-workbench.js"

_needs_gui_stack = pytest.mark.skipif(
    importlib.util.find_spec("fastapi") is None
    or importlib.util.find_spec("starlette") is None,
    reason="GUI stack (fastapi / starlette) not installed",
)
_needs_pywebview = pytest.mark.skipif(
    importlib.util.find_spec("webview") is None, reason="pywebview not installed"
)


def _between(body: str, start_marker: str, end_marker: str) -> str:
    start = body.index(start_marker)
    end = body.index(end_marker, start)
    return body[start:end]


@pytest.fixture
def fake_state(monkeypatch: pytest.MonkeyPatch) -> dict:
    state: dict = {"num_listeners": 0, "paths": []}
    monkeypatch.setattr(native_drops, "_shared_state", lambda: state)
    monkeypatch.setattr(native_drops, "_STATE", native_drops._CaptureState())
    monkeypatch.setattr(native_drops, "RESOLVE_WAIT_S", 0.0)
    return state


# -- capture switch ---------------------------------------------------------


def test_capture_switch_raises_the_listener_count_once(fake_state: dict) -> None:
    assert native_drops.enable_native_drop_capture() is True
    assert native_drops.enable_native_drop_capture() is True
    assert fake_state["num_listeners"] == 1
    assert native_drops.capture_enabled() is True


def test_capture_switch_fails_closed_without_the_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native_drops, "_shared_state", lambda: None)
    monkeypatch.setattr(native_drops, "_STATE", native_drops._CaptureState())
    assert native_drops.enable_native_drop_capture() is False
    assert native_drops.capture_enabled() is False
    # Off means an immediate answer with nothing placed, never a wait.
    assert native_drops.resolve_dropped_paths([("a.der", 1)], wait_s=5.0) == [None]


def test_state_of_another_shape_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Dom:
        _dnd_state = {"num_listeners": "1", "paths": []}

    monkeypatch.setitem(__import__("sys").modules, "webview", type("_W", (), {})())
    monkeypatch.setitem(__import__("sys").modules, "webview.dom", _Dom())
    assert native_drops._shared_state() is None


# -- resolver ---------------------------------------------------------------


def test_resolver_matches_name_and_size_and_consumes_the_entry(
    fake_state: dict, tmp_path: Path
) -> None:
    first = tmp_path / "profile.der"
    first.write_bytes(b"\x30\x03\x02\x01\x05")
    other = tmp_path / "sub" / "profile.der"
    other.parent.mkdir()
    other.write_bytes(b"\x30\x00")
    native_drops.enable_native_drop_capture()
    fake_state["paths"] += [("profile.der", str(first)), ("profile.der", str(other))]

    # Two same-named files: the size tells them apart, in either order.
    assert native_drops.resolve_dropped_paths(
        [("profile.der", 2), ("profile.der", 5)], wait_s=0.0
    ) == [str(other), str(first)]
    assert fake_state["paths"] == []
    # A consumed entry cannot serve a later drop.
    assert native_drops.resolve_dropped_paths([("profile.der", 5)], wait_s=0.0) == [None]


def test_resolver_decodes_percent_encoded_entries_and_skips_missing_files(
    fake_state: dict, tmp_path: Path
) -> None:
    spaced = tmp_path / "my profile.der"
    spaced.write_bytes(b"x" * 7)
    native_drops.enable_native_drop_capture()
    encoded_dir = str(tmp_path).replace(" ", "%20")
    fake_state["paths"] += [
        ("my%20profile.der", encoded_dir + "/my%20profile.der"),
        ("gone.der", str(tmp_path / "gone.der")),
    ]
    assert native_drops.resolve_dropped_paths(
        [("my profile.der", 7), ("gone.der", None)], wait_s=0.0
    ) == [str(spaced), None]
    # The unmatched entry stays for a drop that can place it; the missing
    # file's entry is never a match.
    assert fake_state["paths"] == [("gone.der", str(tmp_path / "gone.der"))]


def test_resolver_bounds_the_record_pywebview_never_trims(fake_state: dict) -> None:
    native_drops.enable_native_drop_capture()
    fake_state["paths"] += [
        (f"stale{index}.der", f"/nonexistent/stale{index}.der")
        for index in range(native_drops.RECORDED_DROP_CAP + 10)
    ]
    native_drops.resolve_dropped_paths([("x.der", None)], wait_s=0.0)
    assert len(fake_state["paths"]) == native_drops.RECORDED_DROP_CAP


def test_resolver_waits_for_a_backend_that_records_after_the_page_asks(
    fake_state: dict, tmp_path: Path
) -> None:
    late = tmp_path / "late.der"
    late.write_bytes(b"late")
    native_drops.enable_native_drop_capture()

    def record() -> None:
        fake_state["paths"].append(("late.der", str(late)))

    threading.Timer(0.15, record).start()
    assert native_drops.resolve_dropped_paths([("late.der", 4)], wait_s=2.0) == [str(late)]


@_needs_pywebview
def test_installed_pywebview_carries_the_state_the_capture_relies_on() -> None:
    """The capture rests on a private pywebview attribute.

    A pin move that renames or reshapes it must fail here, not in the
    desktop window; ``upstream_patches/pywebview/README.md`` records why
    the public DOM API cannot be used instead.
    """
    import webview.dom as webview_dom

    state = webview_dom._dnd_state
    assert isinstance(state, dict)
    assert isinstance(state["num_listeners"], int)
    assert isinstance(state["paths"], list)
    assert native_drops._shared_state() is state


# -- route and launch wiring ------------------------------------------------


@_needs_gui_stack
def test_resolve_route_is_token_gated_and_aligned_with_the_request(
    fake_state: dict, tmp_path: Path
) -> None:
    from starlette.testclient import TestClient

    from yggdrasim_common.gui_server import config
    from yggdrasim_common.gui_server.app import create_app

    dropped = tmp_path / "dropped.der"
    dropped.write_bytes(b"\x30\x00")
    native_drops.enable_native_drop_capture()
    fake_state["paths"].append(("dropped.der", str(dropped)))

    token = "t" * 40
    app = create_app(
        config.GuiServerConfig(
            mode=config.MODE_DESKTOP, host="127.0.0.1", port=0, token=token
        )
    )
    client = TestClient(app)
    payload = {
        "files": [
            {"name": "dropped.der", "size": 2},
            {"name": "unknown.der", "size": 9},
        ]
    }
    assert client.post("/api/gui/native_drop/resolve", json=payload).status_code == 401
    headers = {"Authorization": f"Bearer {token}"}
    response = client.post("/api/gui/native_drop/resolve", json=payload, headers=headers)
    assert response.status_code == 200
    assert response.json() == {"paths": [str(dropped), None]}
    # Consumed: the same request now places nothing.
    again = client.post("/api/gui/native_drop/resolve", json=payload, headers=headers)
    assert again.json() == {"paths": [None, None]}


def test_desktop_launch_switches_the_capture_on_once_the_window_module_loads() -> None:
    body = _APP.read_text(encoding="utf-8")
    launch = _between(body, "def _launch_pywebview(", "    webview.start(")
    assert "enable_native_drop_capture()" in launch
    assert launch.index("bridge.attach(webview)") < launch.index("enable_native_drop_capture()")


# -- page -------------------------------------------------------------------


def test_page_asks_the_desktop_process_where_a_native_drop_came_from() -> None:
    js = _TRAILING.read_text(encoding="utf-8")
    announce = _between(js, "  function announceNativeDrop(event) {", "\n  }\n")
    # WebView2 learns the paths from the page, the way pywebview's own
    # bridge posts them.
    assert 'host.postMessageWithAdditionalObjects("FilesDropped", dt.files);' in announce

    resolve = _between(js, "  async function resolveDroppedFilePaths(files) {", "\n  }\n")
    assert 'apiFetch("/api/gui/native_drop/resolve"' in resolve
    assert 'method: "POST"' in resolve
    assert "JSON.stringify({ files: wanted })" in resolve
    assert 'resolved.push((typeof path === "string" && path.length > 0) ? path : null);' in resolve
    assert "window.YggdraSimResolveDroppedFilePaths = resolveDroppedFilePaths;" in js

    # A path input takes the resolved location when no transport carried
    # one; a browser tab, where nothing resolves, is left as it was.
    path_drop = _between(js, "  function enableFilePathDrop(input, onPath) {", "\n  }\n\n")
    assert "announceNativeDrop(event);" in path_drop
    assert "resolveDroppedFilePaths([files[0]]).then(function (paths) {" in path_drop
    assert "if (paths[0]) applyPath(paths[0]);" in path_drop


def test_workbench_opens_a_placed_file_by_path_and_uploads_the_rest() -> None:
    body = _WORKBENCH.read_text(encoding="utf-8")
    drop = _between(
        body,
        "  function wireSaipWorkbenchDrop(wb) {",
        "\n  // Open every entry of one drop",
    )
    assert 'if (typeof announceNativeDrop === "function") announceNativeDrop(event);' in drop
    assert "entries = resolveDroppedFilePaths(files).then(function (resolved) {" in drop
    assert "return resolved[index] ? { path: resolved[index] } : { file: file };" in drop
    # A path entry goes through the same opener as the Open button, so
    # the record keeps a real ``sourcePath`` and Ctrl+S saves in place.
    batch = _between(
        body,
        "  async function saipOpenDroppedEntries(entries) {",
        "\n  function renderSaipWorkbench(",
    )
    assert "entry.path\n          ? await saipOpenPackageByPath(" in batch
