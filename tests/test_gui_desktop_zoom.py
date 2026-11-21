# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Desktop window page zoom: the setting, the ladder, the ``auto`` fit and
the hand-over from pywebview's event threads to the toolkit thread.

Nothing here needs Qt or GTK. The toolkit attach functions are replaced
by recorders, so the module runs on a baseline install.
"""

from __future__ import annotations

import os
import types

import pytest

from yggdrasim_common import env_flags
from yggdrasim_common.gui_server import config

gui_app = pytest.importorskip("yggdrasim_common.gui_server.app")

FLAG_NAME = "YGGDRASIM_GUI_ZOOM"


def _mk_args(**overrides):
    namespace = types.SimpleNamespace(
        host=None,
        port=None,
        token_file=None,
        tls_cert=None,
        tls_key=None,
        tls_self_signed=False,
        allow_origin=[],
    )
    for key, value in overrides.items():
        setattr(namespace, key, value)
    return namespace


@pytest.fixture
def no_persist(monkeypatch):
    """Keep the registry from touching the overrides files on disk."""
    monkeypatch.setattr(env_flags, "_persist_flag_value", lambda flag, value: None)
    monkeypatch.delenv(FLAG_NAME, raising=False)


# ---------------------------------------------------------------------------
# The setting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", "1"),
        ("1", "1"),
        ("1.0", "1"),
        ("off", "1"),
        ("0", "1"),
        ("none", "1"),
        ("auto", "auto"),
        (" AUTO ", "auto"),
        ("1.25", "1.25"),
        ("1.5", "1.5"),
        ("2", "2"),
        ("0.5", "0.5"),
        ("abc", "1"),
        ("9", "1"),
        ("0.2", "1"),
    ],
)
def test_normalize_webview_zoom(raw, expected):
    assert config.normalize_webview_zoom(raw) == expected


def test_desktop_config_defaults_to_native_size(monkeypatch):
    for flag in ("YGGDRASIM_GUI_TOKEN", "YGGDRASIM_GUI_TOKEN_FILE", FLAG_NAME):
        monkeypatch.delenv(flag, raising=False)
    resolved = config.build_desktop_config(_mk_args())
    assert resolved.webview_zoom == "1"
    assert resolved.redacted()["webview_zoom"] == "1"


@pytest.mark.parametrize("raw", ["1.25", "auto"])
def test_desktop_config_reads_the_flag(monkeypatch, raw):
    for flag in ("YGGDRASIM_GUI_TOKEN", "YGGDRASIM_GUI_TOKEN_FILE"):
        monkeypatch.delenv(flag, raising=False)
    monkeypatch.setenv(FLAG_NAME, raw)
    assert config.build_desktop_config(_mk_args()).webview_zoom == raw


def test_flag_is_registered_with_the_ladder():
    flag = env_flags.get_flag(FLAG_NAME)
    assert flag is not None
    assert flag.category == env_flags.CATEGORY_GUI
    assert flag.kind == env_flags.KIND_CHOICE
    assert flag.applies == env_flags.APPLIES_RUNTIME
    assert flag.persist_scope == env_flags.PERSIST_FILE
    assert "auto" in flag.choices
    for rung in config.WEBVIEW_ZOOM_LADDER:
        assert format(rung, "g") in flag.choices
    assert config.WEBVIEW_ZOOM_LADDER[0] == config.WEBVIEW_ZOOM_FIXED_MIN
    assert config.WEBVIEW_ZOOM_LADDER[-1] == config.WEBVIEW_ZOOM_FIXED_MAX


# ---------------------------------------------------------------------------
# Factor math
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("width", "height", "expected"),
    [
        (1280, 800, 1.0),  # the window create_window opens
        (1920, 1080, 1.35),  # height-bound: 1080 / 800
        (1920, 1050, 1.30),  # 1.3125 rounds down to the 0.05 step
        (2560, 1440, 1.80),
        (3840, 2160, 2.0),  # ceiling
        (1000, 600, 1.0),  # never below the reference size
        (1400, 900, 1.05),  # width-bound: 1.09375 -> 1.05
    ],
)
def test_auto_zoom_factor(width, height, expected):
    assert gui_app.auto_zoom_factor(width, height) == pytest.approx(expected)


@pytest.mark.parametrize(
    ("width", "height"),
    [(0, 0), (-1, 5), (None, None), ("a", "b"), (float("nan"), 900)],
)
def test_auto_zoom_factor_falls_back_on_garbage(width, height):
    assert gui_app.auto_zoom_factor(width, height) == 1.0


@pytest.mark.parametrize(
    ("current", "direction", "expected"),
    [
        (1.0, 1, 1.1),
        (1.0, -1, 0.9),
        (1.25, 1, 1.5),
        (1.3, 1, 1.5),  # off the ladder: next rung up
        (1.3, -1, 1.25),  # off the ladder: next rung down
        (3.0, 1, 3.0),  # top clamps
        (0.5, -1, 0.5),  # bottom clamps
        (0.55, -1, 0.5),
        ("garbage", 1, 1.1),
    ],
)
def test_zoom_step(current, direction, expected):
    assert gui_app.zoom_step(current, direction) == pytest.approx(expected)


def test_zoom_policy_mapping():
    assert gui_app._zoom_policy("auto") is gui_app.auto_zoom_factor
    fixed = gui_app._zoom_policy("1.25")
    assert fixed(1280, 800) == 1.25
    assert fixed(3840, 2160) == 1.25
    for setting in ("", "garbage", "off"):
        assert gui_app._zoom_policy(setting)(3840, 2160) == 1.0


# ---------------------------------------------------------------------------
# Reading and remembering the flag
# ---------------------------------------------------------------------------


def test_setting_round_trips_through_the_registry(no_persist):
    assert gui_app._zoom_setting_raw() == ""
    gui_app._remember_zoom("1.25")
    assert os.environ[FLAG_NAME] == "1.25"
    assert gui_app._zoom_setting_raw() == "1.25"
    gui_app._remember_zoom("")
    assert FLAG_NAME not in os.environ
    assert gui_app._zoom_setting_raw() == ""


def test_remember_zoom_persists_through_the_registry(monkeypatch, no_persist):
    written = []
    monkeypatch.setattr(env_flags, "_persist_flag_value", lambda flag, value: written.append((flag.name, value)))
    gui_app._remember_zoom("1.5")
    gui_app._remember_zoom("")
    assert written == [(FLAG_NAME, "1.5"), (FLAG_NAME, "")]


def test_remember_zoom_survives_a_persistence_error(monkeypatch, no_persist):
    def boom(flag, value):
        raise OSError("read-only state dir")

    monkeypatch.setattr(env_flags, "_persist_flag_value", boom)
    gui_app._remember_zoom("1.5")  # the registry logs; the value still applies to the process
    assert os.environ[FLAG_NAME] == "1.5"


# ---------------------------------------------------------------------------
# Toolkit hand-over
# ---------------------------------------------------------------------------


class _QtLikeView:
    def __init__(self):
        self.factors = []

    def setZoomFactor(self, factor):  # Qt spelling
        self.factors.append(factor)


class _QtLikeWindow:
    def __init__(self):
        self.webview = _QtLikeView()


class _GtkLikeWindow:
    def get_children(self):
        return []

    def connect(self, *_args):
        return 0


class _FakeEvent:
    """pywebview ``Event`` stand-in: ``+=`` registers, ``fire`` dispatches."""

    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self

    def fire(self, *args):
        for handler in list(self.handlers):
            handler(*args)


class _FakeWindow:
    def __init__(self, native=None):
        self.native = native
        self.events = types.SimpleNamespace(
            shown=_FakeEvent(), loaded=_FakeEvent(), resized=_FakeEvent()
        )


def test_zoom_target_detection():
    qt_window = _QtLikeWindow()
    assert gui_app._zoom_target(qt_window) == ("qt", qt_window.webview)
    gtk_window = _GtkLikeWindow()
    assert gui_app._zoom_target(gtk_window) == ("gtk", gtk_window)
    assert gui_app._zoom_target(object()) is None
    assert gui_app._zoom_target(None) is None


def test_install_window_zoom_attaches_once_when_the_native_window_is_up(monkeypatch):
    calls = []

    def recorder(window, view, policy):
        calls.append((window, view, policy))
        return "controller"

    monkeypatch.setattr(gui_app, "_attach_qt_zoom", recorder)
    window = _FakeWindow()  # native window not created yet
    policy = gui_app._zoom_policy("1.25")
    gui_app._install_window_zoom(window, policy)

    for event in (window.events.shown, window.events.loaded, window.events.resized):
        assert len(event.handlers) == 1

    window.events.shown.fire()  # too early: nothing to attach to, no error
    assert calls == []

    window.native = _QtLikeWindow()
    window.events.resized.fire(1920, 1080)
    window.events.loaded.fire()
    window.events.resized.fire(1280, 800)
    assert len(calls) == 1
    assert calls[0][0] is window
    assert calls[0][1] is window.native.webview
    assert calls[0][2] is policy


def test_install_window_zoom_swallows_a_toolkit_failure_and_does_not_retry(monkeypatch):
    attempts = []

    def boom(window, view, policy):
        attempts.append(view)
        raise RuntimeError("no display")

    monkeypatch.setattr(gui_app, "_attach_qt_zoom", boom)
    window = _FakeWindow(native=_QtLikeWindow())
    gui_app._install_window_zoom(window, gui_app._zoom_policy("1"))

    window.events.shown.fire()  # must not raise: zoom is a convenience
    window.events.resized.fire(1920, 1080)
    assert len(attempts) == 1


# --- window identity ----------------------------------------------------
# The compositor names the window from the toolkit, which names it after
# the process; without this the operator sees "python3" in the dock.


def test_apply_window_identity_names_the_qt_window(monkeypatch):
    import sys

    recorded = []

    class _QGuiApplication:
        @staticmethod
        def setDesktopFileName(name):  # noqa: N802  (Qt spelling)
            recorded.append(name)

    qtgui = types.ModuleType("PyQt6.QtGui")
    qtgui.QGuiApplication = _QGuiApplication
    monkeypatch.setitem(sys.modules, "PyQt6", types.ModuleType("PyQt6"))
    monkeypatch.setitem(sys.modules, "PyQt6.QtGui", qtgui)
    monkeypatch.setattr(gui_app.sys, "platform", "linux")

    gui_app._apply_window_identity("qt")
    assert recorded == [gui_app._DESKTOP_APP_ID]


def test_apply_window_identity_names_the_gtk_window(monkeypatch):
    import sys

    recorded = []

    glib = types.ModuleType("gi.repository.GLib")
    glib.set_prgname = recorded.append
    repository = types.ModuleType("gi.repository")
    repository.GLib = glib
    monkeypatch.setitem(sys.modules, "gi", types.ModuleType("gi"))
    monkeypatch.setitem(sys.modules, "gi.repository", repository)
    monkeypatch.setitem(sys.modules, "gi.repository.GLib", glib)
    monkeypatch.setattr(gui_app.sys, "platform", "linux")

    gui_app._apply_window_identity(None)
    assert recorded == [gui_app._DESKTOP_APP_ID]


def test_apply_window_identity_is_a_no_op_without_the_toolkit(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def refuse(name, *args, **kwargs):
        if name in {"PyQt6.QtGui", "gi.repository"}:
            raise ImportError(name)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", refuse)
    monkeypatch.setattr(gui_app.sys, "platform", "linux")

    gui_app._apply_window_identity("qt")  # a missing toolkit never fails a launch
    gui_app._apply_window_identity(None)


def test_apply_window_identity_matches_the_desktop_entry_basename():
    """A Wayland window reaches its icon only when app_id is the entry stem."""
    import ast
    from pathlib import Path

    # Read the constant rather than import the installer: executing it puts
    # a second copy of a top-level script on the path for one assertion.
    installer = Path(__file__).resolve().parents[1] / "scripts" / "install_shortcuts.py"
    tree = ast.parse(installer.read_text(encoding="utf-8"))
    stems = [
        node.value.value
        for node in tree.body
        if isinstance(node, ast.Assign)
        and isinstance(node.value, ast.Constant)
        for target in node.targets
        if isinstance(target, ast.Name) and target.id == "DESKTOP_ENTRY_STEM"
    ]

    assert stems == [gui_app._DESKTOP_APP_ID]
