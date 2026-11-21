# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""YGGDRASIM_GUI_GPU: the Qt desktop window draws with the GPU only when the operator opts in.

Off (the default) keeps Chromium's GPU-off switches; on drops exactly those
three and keeps every other process limit. The GTK backend is never touched,
and the flag is a registered, persistable startup toggle.
"""
from __future__ import annotations

import pytest

from yggdrasim_common import env_flags
from yggdrasim_common.gui_server import config

gui_app = pytest.importorskip("yggdrasim_common.gui_server.app")

_FLAGS_ENV = "QTWEBENGINE_CHROMIUM_FLAGS"
_GPU_OFF = ("--disable-gpu", "--disable-gpu-compositing", "--num-raster-threads=1")


def test_the_default_keeps_the_window_off_the_gpu(monkeypatch) -> None:
    monkeypatch.delenv(config.ENV_GUI_GPU, raising=False)
    monkeypatch.setenv(_FLAGS_ENV, "")
    assert config.webview_gpu_enabled() is False
    gui_app._prepare_webview_environment("qt")
    words = gui_app.os.environ[_FLAGS_ENV].split()
    for flag in _GPU_OFF:
        assert flag in words, flag


@pytest.mark.parametrize("value", ["1", "true", "on", "YES"])
def test_opting_in_drops_only_the_gpu_off_switches(monkeypatch, value: str) -> None:
    monkeypatch.setenv(config.ENV_GUI_GPU, value)
    monkeypatch.setenv(_FLAGS_ENV, "")
    gui_app._prepare_webview_environment("qt")
    words = gui_app.os.environ[_FLAGS_ENV].split()
    for flag in _GPU_OFF:
        assert flag not in words, flag
    kept = [flag for flag in gui_app._QTWEBENGINE_DEFAULT_FLAGS if flag not in _GPU_OFF]
    assert words == kept and "--renderer-process-limit=1" in words


def test_other_backends_are_left_alone(monkeypatch) -> None:
    monkeypatch.setenv(config.ENV_GUI_GPU, "1")
    monkeypatch.setenv(_FLAGS_ENV, "")
    gui_app._prepare_webview_environment("gtk")
    assert gui_app.os.environ[_FLAGS_ENV] == ""


def test_the_flag_is_a_persisted_startup_toggle() -> None:
    flag = env_flags.get_flag(config.ENV_GUI_GPU)
    assert flag is not None
    assert flag.kind == env_flags.KIND_BOOL_TOGGLE and flag.applies == env_flags.APPLIES_STARTUP
    assert flag.persist_scope == env_flags.PERSIST_FILE and flag.category == env_flags.CATEGORY_GUI
