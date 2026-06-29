# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Functional tests for the standalone Card Bridge daemon.

The daemon is built on top of ``HilBridgeApduRelayService`` (already
covered by ``test_hil_bridge_apdu_relay_auth``) and ``PcscCardChannel``
(integration-tested by HilBridge). The new behaviour to validate here:

* ``build_config_from_args`` resolves tokens correctly, including the
  generate-on-first-run path and the refusal to bind a non-loopback
  host with ``--no-token``.
* ``run_card_bridge`` opens the (faked) channel, starts the relay, and
  serves an authenticated round-trip APDU before tearing down cleanly
  when the stop event is set.

A fake card channel substitutes for ``PcscCardChannel`` so tests run
without pyscard or a physical reader.
"""

from __future__ import annotations

import json
import os
import threading
import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch
from urllib import error as urllib_error
from urllib import request as urllib_request

from Tools.CardBridge.server import (
    CardBridgeConfig,
    CardBridgeError,
    _build_argument_parser,
    build_config_from_args,
    run_card_bridge,
)


def _post(url: str, payload: dict, *, token: str = "") -> tuple[int, dict]:
    body = json.dumps(payload).encode("utf-8")
    request = urllib_request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib_request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if len(raw) > 0 else {}
    except urllib_error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


def _get(url: str, *, token: str = "") -> tuple[int, dict]:
    request = urllib_request.Request(url, method="GET")
    if len(token) > 0:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib_request.urlopen(request, timeout=5) as response:
            raw = response.read().decode("utf-8")
            return response.status, json.loads(raw) if len(raw) > 0 else {}
    except urllib_error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8") or "{}")


class _FakeCardChannel:
    def __init__(self, reader_index: int = 0, reader_name: str = "") -> None:
        self.reader_index = reader_index
        self.reader_name = reader_name
        self.reader_label = "Fake PC/SC reader (test)"
        self.connected = False
        self.disconnected = False
        self.last_apdu: bytes = b""

    def connect(self) -> None:
        self.connected = True

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B9F")

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.last_apdu = bytes(apdu)
        return bytes.fromhex("CAFEBABE"), 0x90, 0x00

    def disconnect(self) -> None:
        self.disconnected = True


class ConfigBuildingTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tempdir = Path(self._tempdir.name).resolve()

    def _parse(self, *args: str):
        parser = _build_argument_parser()
        return parser.parse_args(list(args))

    def test_loopback_with_no_token_flag_yields_empty_token(self) -> None:
        config = build_config_from_args(self._parse("--no-token"))
        self.assertEqual(config.auth_token, "")
        self.assertIsNone(config.token_file)
        self.assertFalse(config.token_file_was_written)

    def test_non_loopback_with_no_token_flag_refuses(self) -> None:
        with self.assertRaises(CardBridgeError) as ctx:
            build_config_from_args(self._parse("--host", "0.0.0.0", "--no-token"))
        self.assertIn("0.0.0.0", str(ctx.exception))

    def test_token_file_is_generated_on_first_run(self) -> None:
        path = self.tempdir / "first.token"
        config = build_config_from_args(self._parse("--token-file", str(path)))
        self.assertTrue(path.is_file())
        self.assertNotEqual(config.auth_token, "")
        self.assertEqual(config.token_file, path.resolve())
        self.assertTrue(config.token_file_was_written)
        # Re-running with the same path should reload the same token.
        second = build_config_from_args(self._parse("--token-file", str(path)))
        self.assertEqual(second.auth_token, config.auth_token)
        self.assertFalse(second.token_file_was_written)

    def test_default_token_file_lands_in_xdg_config_home(self) -> None:
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.tempdir)}):
            config = build_config_from_args(self._parse("--port", "9999"))
        expected = self.tempdir / "yggdrasim" / "card_bridge" / "9999.token"
        self.assertEqual(config.token_file, expected.resolve())
        self.assertTrue(expected.is_file())

    def test_invalid_port_is_rejected(self) -> None:
        with self.assertRaises(CardBridgeError):
            build_config_from_args(self._parse("--port", "0", "--no-token"))

    def test_apdu_timeout_flag_is_resolved(self) -> None:
        config = build_config_from_args(
            self._parse("--token-file", str(self.tempdir / "tok"), "--apdu-timeout-ms", "12000")
        )
        self.assertEqual(config.apdu_timeout_ms, 12000)

    def test_pcsc_share_mode_defaults_to_shared_and_can_be_overridden(self) -> None:
        default_config = build_config_from_args(
            self._parse("--token-file", str(self.tempdir / "tok-default"))
        )
        exclusive_config = build_config_from_args(
            self._parse(
                "--token-file",
                str(self.tempdir / "tok-exclusive"),
                "--pcsc-share-mode",
                "exclusive",
            )
        )
        self.assertEqual(default_config.pcsc_share_mode, "shared")
        self.assertEqual(exclusive_config.pcsc_share_mode, "exclusive")


class RunCardBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tempdir = Path(self._tempdir.name).resolve()

    def _make_config(self, *, auth_token: str = "test-token") -> tuple[CardBridgeConfig, _FakeCardChannel]:
        channel = _FakeCardChannel()

        def factory(reader_index: int, reader_name: str) -> Any:
            channel.reader_index = reader_index
            channel.reader_name = reader_name
            return channel

        config = CardBridgeConfig(
            host="127.0.0.1",
            port=0,
            reader_index=0,
            reader_name="",
            auth_token=auth_token,
            token_file=None,
            token_file_was_written=False,
            audit_enabled=False,
            audit_full_apdu=False,
            card_channel_factory=factory,
        )
        return config, channel

    def test_round_trip_apdu_against_running_bridge(self) -> None:
        config, channel = self._make_config(auth_token="round-trip-token")
        stop_event = threading.Event()
        bridge_done = threading.Event()
        captured_output = StringIO()

        # Start the bridge in a worker thread so the test can issue
        # HTTP requests against it. Discover the actual bound port by
        # parsing the banner output.
        thread = threading.Thread(
            target=lambda: (run_card_bridge(config, output=captured_output, stop_event=stop_event), bridge_done.set()),
            name="card-bridge-runner",
            daemon=True,
        )
        thread.start()

        # Wait until the banner is printed so we know the relay is up.
        deadline = threading.Event()
        for _ in range(50):
            if "apdu URL" in captured_output.getvalue():
                break
            deadline.wait(0.05)
        else:
            stop_event.set()
            thread.join(timeout=1.0)
            self.fail("Bridge banner never appeared")

        banner = captured_output.getvalue()
        url_line = next(
            line for line in banner.splitlines() if "apdu URL" in line
        )
        apdu_url = url_line.split(":", 1)[1].strip()
        # banner format: "  apdu URL   : http://127.0.0.1:PORT/apdu"
        apdu_url = url_line.split("apdu URL", 1)[1].split(":", 1)[1].strip()

        try:
            status_url = apdu_url.rsplit("/", 1)[0] + "/status"
            status_code, status_payload = _get(status_url, token="round-trip-token")
            status, payload = _post(
                apdu_url, {"apdu": "00A40400"}, token="round-trip-token"
            )
        finally:
            stop_event.set()
            thread.join(timeout=2.0)

        self.assertEqual(status_code, 200)
        self.assertEqual(status_payload["pid"], os.getpid())
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"data": "CAFEBABE", "sw1": "90", "sw2": "00"})
        self.assertEqual(channel.last_apdu, bytes.fromhex("00A40400"))
        self.assertTrue(channel.disconnected)

    def test_unauthenticated_request_is_rejected_against_running_bridge(self) -> None:
        config, _ = self._make_config(auth_token="locked-down")
        stop_event = threading.Event()
        captured_output = StringIO()

        thread = threading.Thread(
            target=lambda: run_card_bridge(config, output=captured_output, stop_event=stop_event),
            daemon=True,
        )
        thread.start()

        for _ in range(50):
            if "apdu URL" in captured_output.getvalue():
                break
            threading.Event().wait(0.05)
        banner = captured_output.getvalue()
        url_line = next(line for line in banner.splitlines() if "apdu URL" in line)
        apdu_url = url_line.split("apdu URL", 1)[1].split(":", 1)[1].strip()

        try:
            status, payload = _post(apdu_url, {"apdu": "00A40400"})
        finally:
            stop_event.set()
            thread.join(timeout=2.0)

        self.assertEqual(status, 401)
        self.assertIn("error", payload)


class StartupBannerTests(unittest.TestCase):
    def test_banner_emits_token_fingerprint_not_token(self) -> None:
        config, _ = RunCardBridgeTests._make_config(self, auth_token="confidential-token-value")
        stop_event = threading.Event()
        stop_event.set()  # exit immediately after banner is printed
        captured_output = StringIO()
        run_card_bridge(config, output=captured_output, stop_event=stop_event)
        banner = captured_output.getvalue()
        self.assertIn("apdu URL", banner)
        self.assertIn("token", banner.lower())
        self.assertNotIn("confidential-token-value", banner)


if __name__ == "__main__":
    unittest.main()
