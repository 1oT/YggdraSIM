# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Tests for ``yggdrasim_common.gui_server.app._PywebviewJsBridge`` dialog helpers.

Covers: pick_file, pick_folder, save_file.
The pywebview runtime is replaced with a MagicMock; no GUI window is
opened and no external process is spawned.
"""

from __future__ import annotations

import unittest
from unittest.mock import MagicMock

import yggdrasim_common.gui_server.app as gui_app
from yggdrasim_common.gui_server.app import _PywebviewJsBridge


def _make_bridge(*, dialog_result=None, dialog_raises=False) -> _PywebviewJsBridge:
    mock_wv = MagicMock()
    window = MagicMock()
    mock_wv.windows = [window]
    if dialog_raises:
        window.create_file_dialog.side_effect = RuntimeError("dialog unavailable")
    else:
        window.create_file_dialog.return_value = dialog_result
    bridge = _PywebviewJsBridge()
    bridge.attach(mock_wv)
    return bridge


class AttachStateTests(unittest.TestCase):

    def test_no_attach_active_window_raises(self) -> None:
        bridge = _PywebviewJsBridge()
        with self.assertRaises(RuntimeError):
            bridge._active_window()

    def test_no_windows_active_window_raises(self) -> None:
        bridge = _PywebviewJsBridge()
        mock_wv = MagicMock()
        mock_wv.windows = []
        bridge.attach(mock_wv)
        with self.assertRaises(RuntimeError):
            bridge._active_window()

    def test_attach_with_window_succeeds(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        win = bridge._active_window()
        self.assertIsNotNone(win)


class FilePickerModeTests(unittest.TestCase):

    def test_file_picker_mode_defaults_to_web(self) -> None:
        with unittest.mock.patch.dict("os.environ", {}, clear=True):
            bridge = _PywebviewJsBridge()
            self.assertEqual(bridge.file_picker_mode(), "web")

    def test_file_picker_mode_accepts_web_aliases(self) -> None:
        for value in ("web", "WEB", "browser", "in-app", "in_app"):
            with self.subTest(value=value):
                with unittest.mock.patch.dict(
                    "os.environ",
                    {"YGGDRASIM_GUI_FILE_PICKER": value},
                    clear=True,
                ):
                    bridge = _PywebviewJsBridge()
                    self.assertEqual(bridge.file_picker_mode(), "web")

    def test_file_picker_mode_accepts_native_aliases(self) -> None:
        for value in ("native", "os", "qt", "system"):
            with self.subTest(value=value):
                with unittest.mock.patch.dict(
                    "os.environ",
                    {"YGGDRASIM_GUI_FILE_PICKER": value},
                    clear=True,
                ):
                    bridge = _PywebviewJsBridge()
                    self.assertEqual(bridge.file_picker_mode(), "native")

    def test_file_picker_mode_ignores_unknown_values(self) -> None:
        with unittest.mock.patch.dict(
            "os.environ",
            {"YGGDRASIM_GUI_FILE_PICKER": "unknown"},
            clear=True,
        ):
            bridge = _PywebviewJsBridge()
            self.assertEqual(bridge.file_picker_mode(), "web")


class PickFileTests(unittest.TestCase):

    def test_none_result_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        self.assertEqual(bridge.pick_file(), "")

    def test_tuple_result_returns_first(self) -> None:
        bridge = _make_bridge(dialog_result=("/tmp/file.der",))
        self.assertEqual(bridge.pick_file(), "/tmp/file.der")

    def test_list_result_returns_first(self) -> None:
        bridge = _make_bridge(dialog_result=["/tmp/a.der", "/tmp/b.der"])
        self.assertEqual(bridge.pick_file(), "/tmp/a.der")

    def test_string_result_returned_as_is(self) -> None:
        bridge = _make_bridge(dialog_result="/tmp/file.der")
        self.assertEqual(bridge.pick_file(), "/tmp/file.der")

    def test_dialog_exception_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_raises=True)
        self.assertEqual(bridge.pick_file(), "")

    def test_returns_string(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        self.assertIsInstance(bridge.pick_file(), str)

    def test_empty_tuple_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_result=())
        self.assertEqual(bridge.pick_file(), "")


class PickFolderTests(unittest.TestCase):

    def test_none_result_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        self.assertEqual(bridge.pick_folder(), "")

    def test_string_result_returned(self) -> None:
        bridge = _make_bridge(dialog_result="/tmp/folder")
        self.assertEqual(bridge.pick_folder(), "/tmp/folder")

    def test_tuple_result_returns_first(self) -> None:
        bridge = _make_bridge(dialog_result=("/tmp/folder",))
        self.assertEqual(bridge.pick_folder(), "/tmp/folder")

    def test_dialog_exception_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_raises=True)
        self.assertEqual(bridge.pick_folder(), "")

    def test_returns_string(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        self.assertIsInstance(bridge.pick_folder(), str)


class SaveFileTests(unittest.TestCase):

    def test_none_result_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        self.assertEqual(bridge.save_file(), "")

    def test_string_result_returned(self) -> None:
        bridge = _make_bridge(dialog_result="/tmp/out.der")
        self.assertEqual(bridge.save_file(save_filename="out.der"), "/tmp/out.der")

    def test_tuple_result_returns_first(self) -> None:
        bridge = _make_bridge(dialog_result=("/tmp/out.der",))
        self.assertEqual(bridge.save_file(), "/tmp/out.der")

    def test_dialog_exception_returns_empty_string(self) -> None:
        bridge = _make_bridge(dialog_raises=True)
        self.assertEqual(bridge.save_file(), "")

    def test_returns_string(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        self.assertIsInstance(bridge.save_file(), str)


class WebviewBackendSelectionTests(unittest.TestCase):

    def test_env_forced_backend_wins(self) -> None:
        with unittest.mock.patch.dict("os.environ", {"PYWEBVIEW_GUI": "gtk"}, clear=True):
            self.assertEqual(gui_app._select_pywebview_backend(), "gtk")

    def test_linux_without_gtk_selects_qt(self) -> None:
        def fake_find_spec(name: str):
            if name == "gi":
                return None
            if name == "qtpy":
                return object()
            return None

        with unittest.mock.patch.object(gui_app.sys, "platform", "linux"):
            with unittest.mock.patch.dict("os.environ", {}, clear=True):
                with unittest.mock.patch.object(gui_app.importlib.util, "find_spec", fake_find_spec):
                    self.assertEqual(gui_app._select_pywebview_backend(), "qt")

    def test_qt_environment_flags_are_bounded_and_idempotent(self) -> None:
        existing = "--disable-background-networking --custom-flag"
        with unittest.mock.patch.dict(
            "os.environ",
            {"QTWEBENGINE_CHROMIUM_FLAGS": existing},
            clear=True,
        ):
            gui_app._prepare_webview_environment("qt")
            first = gui_app.os.environ["QTWEBENGINE_CHROMIUM_FLAGS"]
            gui_app._prepare_webview_environment("qt")
            second = gui_app.os.environ["QTWEBENGINE_CHROMIUM_FLAGS"]

        self.assertEqual(first, second)
        self.assertIn("--custom-flag", first)
        self.assertIn("--renderer-process-limit=1", first)
        self.assertNotIn("--disable-gpu", first)
        self.assertNotIn("--num-raster-threads=1", first)
        self.assertEqual(first.count("--disable-background-networking"), 1)

    def test_non_qt_backend_leaves_qt_environment_alone(self) -> None:
        with unittest.mock.patch.dict("os.environ", {}, clear=True):
            gui_app._prepare_webview_environment("gtk")
            self.assertNotIn("QTWEBENGINE_CHROMIUM_FLAGS", gui_app.os.environ)


if __name__ == "__main__":
    unittest.main()
