# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import argparse
import threading
import unittest
from unittest import mock

from Tools.HilBridge.main import (
    add_bridge_runtime_arguments,
    build_bridge_config_from_args,
    build_stop_signal_handler,
    run_bridge_server,
)


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

    def test_bridge_config_accepts_apdu_timeout_flag(self) -> None:
        parser = argparse.ArgumentParser()
        add_bridge_runtime_arguments(parser, include_list_readers=False)
        args = parser.parse_args(["--apdu-timeout-ms", "15000"])

        config = build_bridge_config_from_args(args)

        self.assertEqual(config.apdu_timeout_ms, 15000)

    def test_bridge_config_accepts_card_trace_flag(self) -> None:
        parser = argparse.ArgumentParser()
        add_bridge_runtime_arguments(parser, include_list_readers=False)
        args = parser.parse_args(["--card-trace"])

        config = build_bridge_config_from_args(args)

        self.assertTrue(config.card_trace_enabled)

    def test_bridge_config_accepts_card_trace_env_default(self) -> None:
        with mock.patch.dict("os.environ", {"YGGDRASIM_HIL_CARD_TRACE": "1"}):
            parser = argparse.ArgumentParser()
            add_bridge_runtime_arguments(parser, include_list_readers=False)
            args = parser.parse_args([])

        config = build_bridge_config_from_args(args)

        self.assertTrue(config.card_trace_enabled)


if __name__ == "__main__":
    unittest.main()
