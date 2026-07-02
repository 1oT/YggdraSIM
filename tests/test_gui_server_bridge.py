# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

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
from yggdrasim_common.gui_server import lifecycle
from yggdrasim_common.gui_server.actions import card_bridge
from yggdrasim_common.gui_server.app import _PywebviewJsBridge


def _make_bridge(
    *,
    dialog_result=None,
    dialog_raises=False,
    on_close_requested=None,
) -> _PywebviewJsBridge:
    mock_wv = MagicMock()
    window = MagicMock()
    mock_wv.windows = [window]
    if dialog_raises:
        window.create_file_dialog.side_effect = RuntimeError("dialog unavailable")
    else:
        window.create_file_dialog.return_value = dialog_result
    bridge = _PywebviewJsBridge(on_close_requested=on_close_requested)
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

    def test_close_app_destroys_active_window(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        win = bridge._active_window()

        self.assertTrue(bridge.close_app())
        win.destroy.assert_called_once_with()

    def test_close_app_returns_false_without_window(self) -> None:
        bridge = _PywebviewJsBridge()

        self.assertFalse(bridge.close_app())

    def test_close_app_falls_back_to_close_method(self) -> None:
        bridge = _make_bridge(dialog_result=None)
        win = bridge._active_window()
        win.destroy = None

        self.assertTrue(bridge.close_app())
        win.close.assert_called_once_with()

    def test_close_app_runs_shutdown_callback_before_destroy(self) -> None:
        calls: list[str] = []
        bridge = _make_bridge(
            dialog_result=None,
            on_close_requested=lambda: calls.append("cleanup"),
        )
        win = bridge._active_window()
        win.destroy.side_effect = lambda: calls.append("destroy")

        self.assertTrue(bridge.close_app())
        self.assertEqual(calls, ["cleanup", "destroy"])

    def test_desktop_close_shutdown_cleans_up_and_schedules_exit(self) -> None:
        with unittest.mock.patch.object(gui_app, "_cleanup_gui_runtime_on_shutdown") as cleanup:
            with unittest.mock.patch.object(gui_app, "_schedule_desktop_process_exit") as schedule:
                gui_app._request_desktop_close_shutdown()

        cleanup.assert_called_once_with(include_default_hil_service=True)
        schedule.assert_called_once_with()

    def test_desktop_close_shutdown_schedules_exit_after_cleanup_error(self) -> None:
        with unittest.mock.patch.object(
            gui_app,
            "_cleanup_gui_runtime_on_shutdown",
            side_effect=RuntimeError("cleanup failed"),
        ):
            with unittest.mock.patch.object(gui_app, "_schedule_desktop_process_exit") as schedule:
                with self.assertRaises(RuntimeError):
                    gui_app._request_desktop_close_shutdown()

        schedule.assert_called_once_with()


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
        self.assertIn("--disable-gpu", first)
        self.assertIn("--disable-gpu-compositing", first)
        self.assertIn("--num-raster-threads=1", first)
        self.assertIn("--disk-cache-size=67108864", first)
        self.assertIn("--media-cache-size=16777216", first)
        self.assertIn("--js-flags=--max-old-space-size=256", first)
        self.assertEqual(first.count("--disable-background-networking"), 1)

    def test_non_qt_backend_leaves_qt_environment_alone(self) -> None:
        with unittest.mock.patch.dict("os.environ", {}, clear=True):
            gui_app._prepare_webview_environment("gtk")
            self.assertNotIn("QTWEBENGINE_CHROMIUM_FLAGS", gui_app.os.environ)


class RuntimeCleanupTests(unittest.TestCase):
    def tearDown(self) -> None:
        lifecycle._reset_for_tests()

    def test_cleanup_runtime_can_include_card_bridge_state(self) -> None:
        with unittest.mock.patch.object(lifecycle, "_close_card_sessions", return_value=0):
            with unittest.mock.patch.object(lifecycle, "_terminate_registered_processes", return_value=[]):
                with unittest.mock.patch.object(
                    lifecycle,
                    "_stop_card_bridge_runtime_state",
                    return_value=[{"action": "pc"}],
                ) as stop_bridge:
                    with unittest.mock.patch.object(lifecycle, "_stop_registered_services", return_value=[]):
                        payload = lifecycle.cleanup_gui_runtime(
                            include_card_bridge_state=True,
                        )

        stop_bridge.assert_called_once_with()
        self.assertEqual(payload["card_bridge"], [{"action": "pc"}])

    def test_card_bridge_state_cleanup_stops_tunnel_and_local_bridge(self) -> None:
        state = {
            "ssh_tunnel_pid": 1001,
            "local_card_bridge_pid": 1002,
            "local_card_bridge_external": False,
        }
        with unittest.mock.patch.object(card_bridge, "_load_remote_rig_state", return_value=state):
            with unittest.mock.patch.object(
                card_bridge,
                "_dispatch_tunnel_stop",
                return_value={"ok": True, "status": "terminated"},
            ) as tunnel:
                with unittest.mock.patch.object(
                    card_bridge,
                    "_dispatch_local_stop",
                    return_value={"ok": True, "status": "terminated"},
                ) as local:
                    payload = lifecycle._stop_card_bridge_runtime_state()

        tunnel.assert_called_once()
        local.assert_called_once()
        self.assertEqual(
            [entry["action"] for entry in payload],
            ["ssh_tunnel_stop", "pc_card_bridge_stop"],
        )

    def test_card_bridge_state_cleanup_stops_reused_local_bridge(self) -> None:
        state = {
            "local_card_bridge_pid": 1002,
            "local_card_bridge_external": True,
        }
        with unittest.mock.patch.object(card_bridge, "_load_remote_rig_state", return_value=state):
            with unittest.mock.patch.object(
                card_bridge,
                "_dispatch_local_stop",
                return_value={"ok": True, "status": "terminated"},
            ) as local:
                payload = lifecycle._stop_card_bridge_runtime_state()

        local.assert_called_once()
        self.assertEqual(payload, [{
            "action": "pc_card_bridge_stop",
            "ok": True,
            "status": "terminated",
        }])


if __name__ == "__main__":
    unittest.main()
