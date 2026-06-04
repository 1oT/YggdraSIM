"""Coverage for the HIL-Bridge remote-relay card channel.

Verifies the streaming-card path that lets the rig consume APDUs from
an operator's laptop running ``yggdrasim-card-bridge``. Goes through:

* ``resolve_remote_card_url`` / ``resolve_remote_card_token`` — env
  var + explicit-arg precedence, file expansion, missing-file errors.
* ``RemoteRelayCardChannel`` proxies a real round-trip through an
  in-process Card Bridge daemon backed by a fake card channel.
* ``BackendCardChannel.connect`` selects the remote channel when a
  remote URL is configured and falls back to local PC/SC otherwise.
* ``proactive_status_payload`` is empty for remote physical-card relays.

Pyscard is intentionally never imported — the tests stub out the local
PC/SC channel via ``BackendCardChannel.remote_card_url`` so the suite
runs on hosts without smartcard drivers installed.
"""
from __future__ import annotations

import os
import threading
import time
import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

from Tools.CardBridge.server import CardBridgeConfig, run_card_bridge
from Tools.HilBridge.pcsc import PcscBridgeError
from Tools.HilBridge.remote_card import (
    REMOTE_CARD_TOKEN_ENV,
    REMOTE_CARD_TOKEN_FILE_ENV,
    REMOTE_CARD_URL_ENV,
    RemoteRelayCardChannel,
    resolve_remote_card_token,
    resolve_remote_card_url,
)


# ----------------------------------------------------------------------
# Test scaffolding
# ----------------------------------------------------------------------


class _FakeCardChannel:
    """Minimal stand-in for ``PcscCardChannel``. Mirrors the interface
    the Card Bridge daemon expects: ``connect`` / ``get_atr`` /
    ``transmit`` / ``disconnect`` plus a ``reader_label`` attribute.
    """

    def __init__(self, reader_index: int = 0, reader_name: str = "") -> None:
        self.reader_index = reader_index
        self.reader_name = reader_name
        self.reader_label = "Fake reader (test)"
        self.connected = False
        self.disconnected = False
        self.reset_card_calls = 0
        self.transmit_log: list[bytes] = []

    def connect(self) -> None:
        self.connected = True

    def get_atr(self) -> bytes:
        return bytes.fromhex("3B9F95800FFE")

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        self.transmit_log.append(bytes(apdu))
        # Echo a deterministic R-APDU so callers can assert on shape.
        return bytes.fromhex("AABBCCDD"), 0x90, 0x00

    def disconnect(self) -> None:
        self.disconnected = True

    def reset_card(self) -> None:
        self.reset_card_calls += 1
        self.connected = True


class _RunningBridge:
    """Context manager that spins up an in-process Card Bridge daemon.

    Yields the bound ``http://127.0.0.1:<port>/apdu`` URL once the
    startup banner confirms the relay is up; tears the daemon down on
    exit so the listening socket is released between tests.
    """

    def __init__(self, *, auth_token: str = "test-token") -> None:
        self.auth_token = auth_token
        self.channel = _FakeCardChannel()
        self.stop_event = threading.Event()
        self.captured_output = StringIO()
        self.thread: threading.Thread | None = None

    def __enter__(self) -> tuple[str, _FakeCardChannel]:
        def factory(_idx: int, _name: str) -> Any:
            return self.channel

        config = CardBridgeConfig(
            host="127.0.0.1",
            port=0,
            reader_index=0,
            reader_name="",
            auth_token=self.auth_token,
            token_file=None,
            token_file_was_written=False,
            audit_enabled=False,
            audit_full_apdu=False,
            card_channel_factory=factory,
        )
        self.thread = threading.Thread(
            target=lambda: run_card_bridge(
                config, output=self.captured_output, stop_event=self.stop_event
            ),
            name="card-bridge-runner",
            daemon=True,
        )
        self.thread.start()
        # Wait for the banner so we can extract the bound port.
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if "apdu URL" in self.captured_output.getvalue():
                break
            time.sleep(0.05)
        else:  # pragma: no cover — safety net
            self.stop_event.set()
            raise RuntimeError("card-bridge banner never appeared")
        url_line = next(
            line
            for line in self.captured_output.getvalue().splitlines()
            if "apdu URL" in line
        )
        apdu_url = url_line.split("apdu URL", 1)[1].split(":", 1)[1].strip()
        return apdu_url, self.channel

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=2.0)


# ----------------------------------------------------------------------
# resolve_remote_card_url / resolve_remote_card_token
# ----------------------------------------------------------------------


class ResolveUrlTests(unittest.TestCase):
    def setUp(self) -> None:
        self._patcher = patch.dict(os.environ, {}, clear=False)
        self._patcher.start()
        os.environ.pop(REMOTE_CARD_URL_ENV, None)

    def tearDown(self) -> None:
        self._patcher.stop()

    def test_explicit_overrides_env(self) -> None:
        os.environ[REMOTE_CARD_URL_ENV] = "http://from-env:8642/apdu"
        self.assertEqual(
            resolve_remote_card_url("http://explicit:8642"),
            "http://explicit:8642/apdu",
        )

    def test_env_used_when_no_explicit(self) -> None:
        os.environ[REMOTE_CARD_URL_ENV] = "http://from-env:8642"
        self.assertEqual(
            resolve_remote_card_url(""), "http://from-env:8642/apdu"
        )

    def test_empty_when_neither_set(self) -> None:
        self.assertEqual(resolve_remote_card_url(""), "")

    def test_invalid_scheme_dropped(self) -> None:
        # _normalize_card_relay_url drops anything not http/https.
        self.assertEqual(resolve_remote_card_url("ftp://x:1"), "")


class ResolveTokenTests(unittest.TestCase):
    def setUp(self) -> None:
        self._patcher = patch.dict(os.environ, {}, clear=False)
        self._patcher.start()
        os.environ.pop(REMOTE_CARD_TOKEN_ENV, None)
        os.environ.pop(REMOTE_CARD_TOKEN_FILE_ENV, None)
        self._tempdir = TemporaryDirectory()
        self.addCleanup(self._tempdir.cleanup)
        self.tempdir = Path(self._tempdir.name).resolve()

    def tearDown(self) -> None:
        self._patcher.stop()

    def test_explicit_token_wins(self) -> None:
        os.environ[REMOTE_CARD_TOKEN_ENV] = "from-env"
        self.assertEqual(
            resolve_remote_card_token(explicit_token="from-arg"), "from-arg"
        )

    def test_explicit_file_wins_over_env_token(self) -> None:
        path = self.tempdir / "tok.txt"
        path.write_text("from-file\n", encoding="utf-8")
        os.environ[REMOTE_CARD_TOKEN_ENV] = "from-env"
        self.assertEqual(
            resolve_remote_card_token(explicit_token_file=str(path)),
            "from-file",
        )

    def test_env_file_used_when_no_explicit(self) -> None:
        path = self.tempdir / "tok.txt"
        path.write_text("from-env-file", encoding="utf-8")
        os.environ[REMOTE_CARD_TOKEN_FILE_ENV] = str(path)
        self.assertEqual(resolve_remote_card_token(), "from-env-file")

    def test_env_token_used_when_no_explicit(self) -> None:
        os.environ[REMOTE_CARD_TOKEN_ENV] = "tok-via-env"
        self.assertEqual(resolve_remote_card_token(), "tok-via-env")

    def test_missing_file_raises(self) -> None:
        ghost = self.tempdir / "missing.txt"
        with self.assertRaises(PcscBridgeError) as ctx:
            resolve_remote_card_token(explicit_token_file=str(ghost))
        self.assertIn("not found", str(ctx.exception))

    def test_empty_when_nothing_set(self) -> None:
        self.assertEqual(resolve_remote_card_token(), "")


# ----------------------------------------------------------------------
# Round-trip via in-process Card Bridge
# ----------------------------------------------------------------------


class RoundTripTests(unittest.TestCase):
    def test_remote_channel_proxies_apdu(self) -> None:
        with _RunningBridge(auth_token="rt-token") as (apdu_url, fake_channel):
            channel = RemoteRelayCardChannel(
                url=apdu_url, auth_token="rt-token"
            )
            channel.connect()
            self.assertEqual(channel.get_atr(), bytes.fromhex("3B9F95800FFE"))
            data, sw1, sw2 = channel.transmit(bytes.fromhex("00A40400"))
            self.assertEqual(data, bytes.fromhex("AABBCCDD"))
            self.assertEqual(sw1, 0x90)
            self.assertEqual(sw2, 0x00)
            self.assertEqual(
                fake_channel.transmit_log[-1], bytes.fromhex("00A40400")
            )
            channel.disconnect()

    def test_remote_channel_authentication_failure(self) -> None:
        with _RunningBridge(auth_token="correct") as (apdu_url, _):
            channel = RemoteRelayCardChannel(url=apdu_url, auth_token="wrong")
            with self.assertRaises(PcscBridgeError):
                channel.connect()

    def test_invalid_url_rejected(self) -> None:
        channel = RemoteRelayCardChannel(url="not-a-url", auth_token="")
        with self.assertRaises(PcscBridgeError):
            channel.connect()

    def test_proactive_status_empty_for_remote_card(self) -> None:
        with _RunningBridge(auth_token="rt-token") as (apdu_url, _):
            channel = RemoteRelayCardChannel(
                url=apdu_url, auth_token="rt-token"
            )
            channel.connect()
            try:
                self.assertEqual(channel.proactive_status_payload(), {})
            finally:
                channel.disconnect()

    def test_remote_channel_forwards_card_reset(self) -> None:
        with _RunningBridge(auth_token="rt-token") as (apdu_url, fake_channel):
            channel = RemoteRelayCardChannel(
                url=apdu_url, auth_token="rt-token"
            )
            channel.connect()
            try:
                channel.reset_card()
                self.assertEqual(fake_channel.reset_card_calls, 1)
                self.assertEqual(channel.get_atr(), bytes.fromhex("3B9F95800FFE"))
            finally:
                channel.disconnect()


# ----------------------------------------------------------------------
# BackendCardChannel selection
# ----------------------------------------------------------------------


class BackendSelectionTests(unittest.TestCase):
    """``BackendCardChannel`` picks the remote channel when a URL is
    configured and falls back to the local PC/SC channel otherwise.

    The local-PC/SC fallback is verified without instantiating
    ``PcscCardChannel`` (which would import pyscard); we monkey-patch
    the constructor on the router module so the test can run on a
    bare CI host.
    """

    def setUp(self) -> None:
        self._env_patch = patch.dict(os.environ, {}, clear=False)
        self._env_patch.start()
        os.environ.pop(REMOTE_CARD_URL_ENV, None)
        os.environ.pop(REMOTE_CARD_TOKEN_ENV, None)
        os.environ.pop(REMOTE_CARD_TOKEN_FILE_ENV, None)
        os.environ.pop("YGGDRASIM_CARD_BACKEND", None)

    def tearDown(self) -> None:
        self._env_patch.stop()

    def test_remote_url_selects_remote_channel(self) -> None:
        from Tools.HilBridge.router import BackendCardChannel

        with _RunningBridge(auth_token="sel") as (apdu_url, _):
            channel = BackendCardChannel(
                remote_card_url=apdu_url,
                remote_card_auth_token="sel",
            )
            channel.connect()
            try:
                self.assertEqual(channel.backend_name, "remote")
                self.assertIn("remote", channel.reader_label)
                data, sw1, sw2 = channel.transmit(bytes.fromhex("80AA0000"))
                self.assertEqual(data, bytes.fromhex("AABBCCDD"))
                self.assertEqual((sw1, sw2), (0x90, 0x00))
            finally:
                channel.disconnect()

    def test_env_url_selects_remote_channel(self) -> None:
        from Tools.HilBridge.router import BackendCardChannel

        with _RunningBridge(auth_token="env-token") as (apdu_url, _):
            os.environ[REMOTE_CARD_URL_ENV] = apdu_url
            os.environ[REMOTE_CARD_TOKEN_ENV] = "env-token"
            channel = BackendCardChannel()
            channel.connect()
            try:
                self.assertEqual(channel.backend_name, "remote")
                _, sw1, sw2 = channel.transmit(b"\x00\xa4\x04\x00")
                self.assertEqual((sw1, sw2), (0x90, 0x00))
            finally:
                channel.disconnect()

    def test_no_remote_url_falls_back_to_local_pcsc(self) -> None:
        # Stub the local PC/SC channel so the selector resolves to it
        # without importing pyscard.
        from Tools.HilBridge import router

        invocations: list[tuple[int, str]] = []

        class _StubPcsc:
            def __init__(self, reader_index: int = 0, reader_name: str = ""):
                invocations.append((reader_index, reader_name))
                self.reader_label = "stubbed PC/SC"

            def connect(self) -> None:
                pass

            def disconnect(self) -> None:
                pass

            def get_atr(self) -> bytes:
                return b"\x3b\x90"

            def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
                return b"", 0x90, 0x00

        with patch.object(router, "PcscCardChannel", _StubPcsc):
            channel = router.BackendCardChannel(
                reader_index=2, reader_name="probe"
            )
            channel.connect()
            self.assertEqual(channel.backend_name, "reader")
            self.assertEqual(invocations, [(2, "probe")])
            self.assertEqual(channel.reader_label, "stubbed PC/SC")


# ----------------------------------------------------------------------
# Console-script entry
# ----------------------------------------------------------------------


class ConsoleScriptEntryTests(unittest.TestCase):
    def test_card_bridge_entry_resolves(self) -> None:
        from yggdrasim_common import console_scripts

        self.assertTrue(callable(getattr(console_scripts, "card_bridge")))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
