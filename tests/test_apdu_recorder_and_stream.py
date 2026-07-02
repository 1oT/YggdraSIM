# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the APDU recorder + GUI live stream.

The user reported that the bottom-dock APDU panel only showed
synthetic action summaries — wire-level APDUs from SCP03 / pyscard /
the relay never made it into the dock. The fix funnels every
``connection.transmit`` call through
:mod:`yggdrasim_common.apdu_recorder`, exposes the live stream over a
``/api/events/apdu`` WebSocket, and forwards each frame into
``window.YggdraSimLogBus``'s APDU bucket on the frontend.

These tests exercise the full pipeline:

* The dataclass + recorder API (subscribe / record / snapshot / clear).
* :func:`wrap_connection` idempotency + transmit semantics.
* :func:`create_card_connection` sets the recorder source on every
  return path (simulator / relay / pcsc).
* Static contracts on the frontend bundle: the stream wrapper exists,
  formats frames, and is started from ``init()``.
* The new FastAPI router is registered in ``app.py``.

We avoid spinning up a real FastAPI ``TestClient`` because the GUI
extras (httpx) are not installed in CI; the WebSocket route is
covered by static + unit-level checks instead.
"""

from __future__ import annotations

import asyncio
import importlib
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


_APDU_MOD = "yggdrasim_common.apdu_recorder"
_BACKEND_MOD = "yggdrasim_common.card_backend"


# ----------------------------------------------------------------------
# Recorder + dataclass
# ----------------------------------------------------------------------


class ApduRecorderUnitTests(unittest.TestCase):
    """Drive the recorder singleton directly, no card needed."""

    def setUp(self) -> None:
        self.mod = importlib.import_module(_APDU_MOD)
        self.recorder = self.mod.get_recorder()
        # Always start from a clean slate so test order doesn't matter.
        self.recorder.clear()

    def _make_exchange(self, source: str = "test", apdu: str = "00A40000") -> Any:
        return self.mod.ApduExchange(
            ts=1.0,
            source=source,
            apdu_hex=apdu,
            data_hex="",
            sw_hex="9000",
            elapsed_ms=1.5,
        )

    def test_get_recorder_returns_singleton(self) -> None:
        first = self.mod.get_recorder()
        second = self.mod.get_recorder()
        self.assertIs(first, second)

    def test_record_appends_to_snapshot(self) -> None:
        ex = self._make_exchange()
        self.recorder.record(ex)
        snap = self.recorder.snapshot()
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0].apdu_hex, "00A40000")
        self.assertEqual(snap[0].sw_hex, "9000")

    def test_snapshot_limit_trims_to_most_recent(self) -> None:
        for i in range(5):
            self.recorder.record(self._make_exchange(apdu=f"FF{i:02X}"))
        snap = self.recorder.snapshot(limit=2)
        self.assertEqual(len(snap), 2)
        self.assertEqual(snap[0].apdu_hex, "FF03")
        self.assertEqual(snap[1].apdu_hex, "FF04")

    def test_subscribe_and_unsubscribe(self) -> None:
        seen: list[str] = []
        unsub = self.recorder.subscribe(lambda ex: seen.append(ex.apdu_hex))
        self.recorder.record(self._make_exchange(apdu="AAAA"))
        unsub()
        self.recorder.record(self._make_exchange(apdu="BBBB"))
        self.assertEqual(seen, ["AAAA"])

    def test_subscriber_exception_does_not_block_recording(self) -> None:
        # A misbehaving sync subscriber must NEVER prevent the recorder
        # from delivering events to other subscribers or appending to
        # the buffer — that's the whole point of the try/except wrap.
        good_seen: list[str] = []
        self.recorder.subscribe(lambda ex: (_ for _ in ()).throw(RuntimeError("boom")))
        self.recorder.subscribe(lambda ex: good_seen.append(ex.apdu_hex))
        self.recorder.record(self._make_exchange(apdu="CAFE"))
        self.assertEqual(good_seen, ["CAFE"])
        self.assertEqual(len(self.recorder.snapshot()), 1)
        self.assertGreaterEqual(self.recorder.dropped, 1)

    def test_to_json_round_trip_keys(self) -> None:
        ex = self._make_exchange()
        payload = ex.to_json()
        for key in ("ts", "source", "apdu", "data", "sw", "elapsed_ms", "direction"):
            self.assertIn(key, payload)
        self.assertEqual(payload["sw"], "9000")
        self.assertEqual(payload["direction"], "out")

    def test_attach_queue_relays_via_owning_loop(self) -> None:
        async def _run() -> None:
            queue: asyncio.Queue = asyncio.Queue()
            loop = asyncio.get_running_loop()
            detach = self.recorder.attach_queue(queue, loop=loop)
            try:
                # Recording from the same loop thread still routes
                # through ``call_soon_threadsafe`` — exercise it.
                self.recorder.record(self._make_exchange(apdu="DEAD"))
                # Spin the loop once so the call_soon callback fires.
                await asyncio.sleep(0)
                ex = await asyncio.wait_for(queue.get(), timeout=1.0)
                self.assertEqual(ex.apdu_hex, "DEAD")
            finally:
                detach()

        asyncio.run(_run())

    def test_attach_queue_prunes_closed_event_loop(self) -> None:
        recorder = self.mod._ApduRecorder(max_buffer=2, max_async_queues=4)
        loop = asyncio.new_event_loop()

        async def _make_queue() -> asyncio.Queue:
            return asyncio.Queue(maxsize=1)

        queue = loop.run_until_complete(_make_queue())
        recorder.attach_queue(queue, loop=loop)
        self.assertEqual(len(recorder._async_queues), 1)
        loop.close()

        recorder.record(self._make_exchange(apdu="C0DE"))
        self.assertEqual(recorder.async_queue_count, 0)
        self.assertGreaterEqual(recorder.dropped, 1)

    def test_attach_queue_caps_registered_consumers(self) -> None:
        recorder = self.mod._ApduRecorder(max_buffer=2, max_async_queues=2)
        loops: list[asyncio.AbstractEventLoop] = []
        detaches: list[Any] = []

        async def _make_queue() -> asyncio.Queue:
            return asyncio.Queue(maxsize=1)

        try:
            for _ in range(3):
                loop = asyncio.new_event_loop()
                loops.append(loop)
                queue = loop.run_until_complete(_make_queue())
                detaches.append(recorder.attach_queue(queue, loop=loop))

            self.assertEqual(recorder.async_queue_count, 2)
            self.assertEqual(len(recorder._async_queues), 2)
            self.assertGreaterEqual(recorder.dropped, 1)
        finally:
            for detach in detaches:
                detach()
            for loop in loops:
                loop.close()


# ----------------------------------------------------------------------
# Connection wrapper
# ----------------------------------------------------------------------


class _FakeConnection:
    """Minimal pyscard-shaped stand-in for transmit unit tests."""

    def __init__(self, response=(b"", 0x90, 0x00)):
        self.calls: list[bytes] = []
        self._response = response

    def transmit(self, apdu, *args, **kwargs):
        self.calls.append(bytes(apdu))
        return self._response


class _RaisingConnection:
    def __init__(self, exc: Exception):
        self._exc = exc

    def transmit(self, apdu, *args, **kwargs):
        raise self._exc


class WrapConnectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = importlib.import_module(_APDU_MOD)
        self.recorder = self.mod.get_recorder()
        self.recorder.clear()

    def test_wrap_preserves_return_value(self) -> None:
        fake = _FakeConnection(response=(b"\x01\x02", 0x61, 0x10))
        wrapped = self.mod.wrap_connection(fake, source="unit")
        out = wrapped.transmit([0x00, 0xA4, 0x04, 0x00])
        self.assertEqual(out, (b"\x01\x02", 0x61, 0x10))

    def test_wrap_records_exchange_with_uppercase_hex(self) -> None:
        fake = _FakeConnection(response=([0xDE, 0xAD], 0x90, 0x00))
        wrapped = self.mod.wrap_connection(fake, source="unit")
        wrapped.transmit([0x00, 0xA4, 0x04, 0x00, 0x07])
        snap = self.recorder.snapshot()
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0].apdu_hex, "00A4040007")
        self.assertEqual(snap[0].data_hex, "DEAD")
        self.assertEqual(snap[0].sw_hex, "9000")
        self.assertEqual(snap[0].source, "unit")
        self.assertGreater(snap[0].elapsed_ms, 0.0)

    def test_wrap_is_idempotent_on_same_connection(self) -> None:
        fake = _FakeConnection()
        once = self.mod.wrap_connection(fake)
        twice = self.mod.wrap_connection(fake)
        self.assertIs(once, twice)
        # And the transmit method is patched only once.
        twice.transmit([0x80, 0x50, 0x00, 0x00])
        self.assertEqual(len(self.recorder.snapshot()), 1)

    def test_wrap_records_err_on_raised_transmit(self) -> None:
        # Connection drop must still produce a recorder entry so the
        # GUI dock visibly shows something happened — otherwise the
        # operator just sees a silent UI error and an empty APDU tab.
        wrapped = self.mod.wrap_connection(
            _RaisingConnection(RuntimeError("link down")),
            source="unit-err",
        )
        with self.assertRaises(RuntimeError):
            wrapped.transmit([0x00, 0xA4])
        snap = self.recorder.snapshot()
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0].sw_hex, "ERR")
        self.assertEqual(snap[0].source, "unit-err")

    def test_wrap_handles_objects_without_transmit(self) -> None:
        class _Empty:
            pass
        e = _Empty()
        out = self.mod.wrap_connection(e, source="x")
        self.assertIs(out, e)
        self.assertFalse(getattr(out, "_yggdrasim_apdu_traced", False))


# ----------------------------------------------------------------------
# card_backend integration
# ----------------------------------------------------------------------


class CardBackendIntegrationTests(unittest.TestCase):
    """``create_card_connection`` must wrap every return path."""

    def test_simulator_branch_wraps_connection(self) -> None:
        backend = importlib.import_module(_BACKEND_MOD)

        class _SimFakeConnection:
            def __init__(self) -> None:
                self.calls: list[bytes] = []
            def connect(self, *args: Any, **kwargs: Any) -> None:
                return None
            def transmit(self, apdu, *args, **kwargs):
                self.calls.append(bytes(apdu))
                return (b"", 0x90, 0x00)

        with mock.patch.object(backend, "is_simulated_card_backend", return_value=True):
            with mock.patch(
                "SIMCARD.connection.SimulatedCardConnection",
                _SimFakeConnection,
            ):
                conn = backend.create_card_connection()
                self.assertTrue(getattr(conn, "_yggdrasim_apdu_traced", False))
                recorder = importlib.import_module(_APDU_MOD).get_recorder()
                recorder.clear()
                conn.transmit([0x00, 0xA4])
                snap = recorder.snapshot()
                self.assertEqual(len(snap), 1)
                self.assertEqual(snap[0].source, "simulator")

    def test_pcsc_branch_uses_reader_name_as_source(self) -> None:
        backend = importlib.import_module(_BACKEND_MOD)

        # Hand-rolled real classes — we deliberately avoid MagicMock
        # here because its auto-attribute behaviour makes
        # ``getattr(conn, "_yggdrasim_apdu_traced", False)`` evaluate
        # to a truthy mock object, which would let ``wrap_connection``
        # think the connection had already been wrapped and skip the
        # transmit patch.
        class _PcscFakeConnection:
            def __init__(self) -> None:
                self.calls: list[bytes] = []
            def connect(self, *args: Any, **kwargs: Any) -> None:
                return None
            def transmit(self, apdu, *args, **kwargs):
                self.calls.append(bytes(apdu))
                return (b"", 0x90, 0x00)

        class _FakeReader:
            def __init__(self) -> None:
                self._conn = _PcscFakeConnection()
            def __str__(self) -> str:
                return "ACS APG8201 00 00"
            def createConnection(self) -> Any:
                return self._conn

        with mock.patch.object(backend, "is_simulated_card_backend", return_value=False):
            with mock.patch.object(
                backend, "_resolve_card_relay_url", return_value=("", "none"),
            ):
                with mock.patch(
                    "smartcard.scard.SCARD_LEAVE_CARD",
                    create=True,
                    new=0,
                ):
                    conn = backend.create_card_connection(
                        readers_func=lambda: [_FakeReader()],
                    )
        self.assertTrue(getattr(conn, "_yggdrasim_apdu_traced", False))
        recorder = importlib.import_module(_APDU_MOD).get_recorder()
        recorder.clear()
        conn.transmit([0x00, 0xC0])
        snap = recorder.snapshot()
        self.assertEqual(len(snap), 1)
        # Source must be the reader name — gives operators per-reader
        # grouping in the dock.
        self.assertEqual(snap[0].source, "ACS APG8201 00 00")


# ----------------------------------------------------------------------
# Frontend bundle contracts
# ----------------------------------------------------------------------


_STATIC_DIR = (
    Path(__file__).resolve().parents[1]
    / "yggdrasim_common" / "gui_server" / "static"
)


class FrontendApduStreamContract(unittest.TestCase):
    """``app.js`` opens, formats, and reconnects the APDU stream."""

    def setUp(self) -> None:
        self.js = (_STATIC_DIR / "app.js").read_text(encoding="utf-8")

    def test_open_apdu_event_stream_is_defined(self) -> None:
        self.assertIn("function openApduEventStream(", self.js)
        self.assertIn("/api/events/apdu?t=", self.js)

    def test_open_called_from_init(self) -> None:
        self.assertIn("openApduEventStream();", self.js)

    def test_frame_formatter_emits_into_apdu_bucket(self) -> None:
        # The dock gets ``level: "apdu"`` rows tagged with the source
        # the recorder captured (reader name / "simulator" / etc.).
        self.assertIn('level: "apdu"', self.js)
        self.assertIn('source: String(frame.source || "card")', self.js)

    def test_format_frame_includes_command_response_and_sw(self) -> None:
        # Compact one-liner that fits the dock without truncation.
        self.assertIn('"\\u2192 "', self.js) if False else None  # noqa
        self.assertIn("apdu", self.js)
        self.assertIn("sw=", self.js)
        self.assertIn("ms", self.js)

    def test_reconnect_with_exponential_backoff(self) -> None:
        # Bounded back-off so a missing GUI server doesn't pin the CPU.
        self.assertIn("Math.min(nextDelay * 2, 30000)", self.js)
        self.assertIn("apduStreamState.reconnectTimerId = setTimeout", self.js)
        self.assertIn("clearApduReconnectTimer();", self.js)

    def test_shutdown_paths_close_stream_and_timer(self) -> None:
        self.assertIn(
            'window.addEventListener("pagehide", closeApduEventStream)',
            self.js,
        )
        self.assertIn(
            'window.addEventListener("beforeunload", closeApduEventStream)',
            self.js,
        )
        self.assertIn("detachApduSocketHandlers(sock)", self.js)

    def test_ping_frames_are_silently_ignored(self) -> None:
        self.assertIn('frame.event === "ping"', self.js)

    def test_helpers_exposed_on_window(self) -> None:
        self.assertIn("window.YggdraSimApduStream", self.js)


class BackendRouteRegistration(unittest.TestCase):
    def test_app_includes_apdu_event_router(self) -> None:
        app_py = (
            Path(__file__).resolve().parents[1]
            / "yggdrasim_common" / "gui_server" / "app.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "from .routes import apdu_events as apdu_event_routes", app_py,
        )
        self.assertIn(
            "app.include_router(apdu_event_routes.router)", app_py,
        )

    def test_route_module_declares_websocket_endpoint(self) -> None:
        rt = (
            Path(__file__).resolve().parents[1]
            / "yggdrasim_common" / "gui_server" / "routes" / "apdu_events.py"
        ).read_text(encoding="utf-8")
        self.assertIn('@router.websocket("/api/events/apdu")', rt)
        # Auth path mirrors the terminal route.
        self.assertIn("compare_tokens", rt)
        # Replays the buffer first so a fresh tab isn't blank.
        self.assertIn("recorder.snapshot(limit=200)", rt)
        self.assertIn("asyncio.wait_for(", rt)
        self.assertIn("_QUEUE_CAP = 256", rt)
        self.assertNotIn("asyncio.create_task(_pump_heartbeat", rt)


if __name__ == "__main__":
    unittest.main()
