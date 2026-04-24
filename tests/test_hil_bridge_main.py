from __future__ import annotations

import threading
import unittest
from unittest import mock

from Tools.HilBridge.main import build_stop_signal_handler, run_bridge_server


class _FakeBridgeServer:
    def __init__(self) -> None:
        self.stop_event = None
        self.close_calls = 0

    def serve_forever(self, *, stop_event=None) -> None:
        self.stop_event = stop_event
        if stop_event is not None:
            stop_event.set()

    def close(self) -> None:
        self.close_calls += 1


class HilBridgeMainTests(unittest.TestCase):
    def test_stop_signal_handler_sets_stop_event(self) -> None:
        stop_event = threading.Event()
        handler = build_stop_signal_handler(stop_event)

        handler(15, None)

        self.assertTrue(stop_event.is_set())

    def test_run_bridge_server_closes_server_after_stop(self) -> None:
        server = _FakeBridgeServer()

        with mock.patch("Tools.HilBridge.main._install_stop_signal_handlers", lambda stop_event: None):
            run_bridge_server(server)

        self.assertIsNotNone(server.stop_event)
        self.assertTrue(server.stop_event.is_set())
        self.assertEqual(server.close_calls, 1)


if __name__ == "__main__":
    unittest.main()
