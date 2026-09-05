# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OU. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Privacy-preserving APDU exchange recorder.

Every wire-level APDU that flows through ``card_backend.create_card_connection``
is funnelled into this recorder so the GUI's bottom-dock APDU tab can
display the full live trace without each call site having to opt in.

Subscribers may be either:

* **synchronous callables** invoked on the recorder thread (typically
  the FastAPI worker thread that dispatched the action) — keep them
  fast, they run inside the same lock that the wire-level transmit
  call holds; or
* **asyncio.Queue** instances attached via :meth:`attach_queue`, used
  by the WebSocket bridge to stream events to the SPA without blocking
  the recorder thread.

The recorder also keeps a bounded ring buffer of the last N exchanges
so a freshly-opened WebSocket can replay recent activity instead of
showing a blank dock until the next call.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any, Callable


__all__ = [
    "ApduExchange",
    "get_recorder",
    "wrap_connection",
]

_DEFAULT_APDU_BUFFER_CAP = 1000
_DEFAULT_ASYNC_QUEUE_CAP = 8


@dataclass(frozen=True)
class ApduExchange:
    """One APDU command/response pair captured from a card connection.

    All hex fields are uppercase and stripped of separators so they
    round-trip cleanly through ``bytes.fromhex``. ``sw_hex`` carries
    the four-character ``SW1SW2`` for normal exchanges and the literal
    string ``"ERR"`` for transmits that raised before producing a
    response (so the GUI can flag connection drops without having to
    map exception types).
    """

    ts: float
    source: str
    apdu_hex: str
    data_hex: str
    sw_hex: str
    elapsed_ms: float
    direction: str = "out"
    command_length: int = 0
    response_length: int = 0
    scope: str = ""
    payload_redacted: bool = True
    raw_capture: bool = False

    def to_json(self) -> dict[str, Any]:
        """Serialise the recorded APDU session to a JSON-compatible dict."""
        return {
            "ts": self.ts,
            "source": self.source,
            "apdu": self.apdu_hex,
            "data": self.data_hex,
            "sw": self.sw_hex,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "direction": self.direction,
            "command_length": self.command_length,
            "response_length": self.response_length,
            "scope": self.scope,
            "payload_redacted": self.payload_redacted,
        }


class _ApduRecorder:
    """Thread-safe singleton holding subscribers + a recent-events buffer."""

    def __init__(
        self,
        max_buffer: int = _DEFAULT_APDU_BUFFER_CAP,
        max_async_queues: int = _DEFAULT_ASYNC_QUEUE_CAP,
    ) -> None:
        self._lock = threading.RLock()
        self._buffer: deque[ApduExchange] = deque(maxlen=max(1, max_buffer))
        self._buffers: dict[str, deque[ApduExchange]] = {}
        self._max_buffer = max(1, int(max_buffer))
        self._sync_subs: list[Callable[[ApduExchange], None]] = []
        # Queues are paired with the loop they were created on so
        # ``put_nowait`` from a worker thread can be relayed via
        # ``call_soon_threadsafe`` instead of crashing on a foreign loop.
        self._async_queues: list[
            tuple[
                asyncio.Queue[ApduExchange],
                asyncio.AbstractEventLoop,
                str | None,
            ]
        ] = []
        self._max_async_queues = max(1, max_async_queues)
        self._dropped: int = 0
        self._raw_capture_deadlines: dict[str, float] = {}

    # ---------------------------------------------------------------- record
    def record(self, exchange: ApduExchange) -> None:
        """Append *exchange* to the buffer and fan it out to subscribers.

        Sync callbacks that raise are swallowed and counted under
        :pyattr:`dropped`; we do not let a misbehaving listener kill
        the card-touching call. Async queue puts use the queue's
        owning loop via :func:`call_soon_threadsafe` so cross-thread
        emits stay loop-safe.
        """
        with self._lock:
            self._expire_raw_consents_locked()
            safe_exchange = _redacted_exchange(exchange)
            self._buffer.append(safe_exchange)
            scope = _normalise_scope(exchange.scope or exchange.source)
            raw_allowed = (
                self._raw_capture_deadlines.get(scope, 0.0)
                > time.monotonic()
            )
            scoped_exchange = exchange if raw_allowed else safe_exchange
            scoped_buffer = self._buffers.setdefault(
                scope,
                deque(maxlen=self._max_buffer),
            )
            scoped_buffer.append(scoped_exchange)
            sync_subs = list(self._sync_subs)
            async_queues = list(self._async_queues)

        dropped = 0
        stale_queues: list[
            tuple[
                asyncio.Queue[ApduExchange],
                asyncio.AbstractEventLoop,
                str | None,
            ]
        ] = []

        for fn in sync_subs:
            try:
                fn(safe_exchange)
            except Exception:  # noqa: BLE001 — never trust subscribers
                dropped += 1

        for queue, loop, requested_scope in async_queues:
            if loop.is_closed():
                stale_queues.append((queue, loop, requested_scope))
                dropped += 1
                continue
            event_scope = _normalise_scope(exchange.scope or exchange.source)
            if requested_scope is not None and requested_scope != event_scope:
                continue
            delivered = (
                scoped_exchange
                if requested_scope is not None
                else safe_exchange
            )
            try:
                loop.call_soon_threadsafe(self._safe_put, queue, delivered)
            except RuntimeError:
                # Loop has shut down (websocket closed mid-emit).
                stale_queues.append((queue, loop, requested_scope))
                dropped += 1

        if dropped > 0 or stale_queues:
            with self._lock:
                self._dropped += dropped
                for binding in stale_queues:
                    try:
                        self._async_queues.remove(binding)
                    except ValueError:
                        pass

    @staticmethod
    def _safe_put(
        queue: asyncio.Queue[ApduExchange],
        exchange: ApduExchange,
    ) -> None:
        try:
            queue.put_nowait(exchange)
        except asyncio.QueueFull:
            # Slow consumer — drop oldest by pulling and re-pushing.
            try:
                _ = queue.get_nowait()
                queue.put_nowait(exchange)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

    # ---------------------------------------------------------- subscribers
    def _prune_async_queues_locked(self) -> None:
        live: list[
            tuple[
                asyncio.Queue[ApduExchange],
                asyncio.AbstractEventLoop,
                str | None,
            ]
        ] = []
        removed = 0
        for queue, loop, requested_scope in self._async_queues:
            if loop.is_closed():
                removed += 1
            else:
                live.append((queue, loop, requested_scope))
        if removed > 0:
            self._async_queues = live
            self._dropped += removed

    def subscribe(
        self, fn: Callable[[ApduExchange], None]
    ) -> Callable[[], None]:
        """Register a callback to receive new APDU events in real time."""
        with self._lock:
            self._sync_subs.append(fn)

        def _unsub() -> None:
            with self._lock:
                try:
                    self._sync_subs.remove(fn)
                except ValueError:
                    pass

        return _unsub

    def attach_queue(
        self,
        queue: asyncio.Queue[ApduExchange],
        loop: asyncio.AbstractEventLoop | None = None,
        *,
        scope: str | None = None,
    ) -> Callable[[], None]:
        """Register *queue* for live event delivery.

        *loop* defaults to the running loop at the call site; the
        WebSocket route hands its own loop in to make the cross-thread
        relay explicit.
        """
        owning_loop = loop or asyncio.get_event_loop()
        requested_scope = (
            _normalise_scope(scope)
            if scope is not None and str(scope).strip()
            else None
        )
        with self._lock:
            self._prune_async_queues_locked()
            self._async_queues.append((queue, owning_loop, requested_scope))
            overflow = len(self._async_queues) - self._max_async_queues
            if overflow > 0:
                del self._async_queues[:overflow]
                self._dropped += overflow

        def _detach() -> None:
            with self._lock:
                try:
                    self._async_queues.remove(
                        (queue, owning_loop, requested_scope)
                    )
                except ValueError:
                    pass

        return _detach

    # ----------------------------------------------------------- snapshots
    def snapshot(
        self,
        limit: int | None = None,
        *,
        scope: str | None = None,
    ) -> list[ApduExchange]:
        with self._lock:
            self._expire_raw_consents_locked()
            if scope is None or not str(scope).strip():
                items = list(self._buffer)
            else:
                items = list(
                    self._buffers.get(_normalise_scope(scope), ())
                )
        if limit is not None and limit < len(items):
            items = items[-limit:]
        return items

    def clear(self, *, scope: str | None = None) -> None:
        with self._lock:
            if scope is None or not str(scope).strip():
                self._buffer.clear()
                self._buffers.clear()
                self._raw_capture_deadlines.clear()
            else:
                normalised = _normalise_scope(scope)
                self._buffers.pop(normalised, None)
                self._raw_capture_deadlines.pop(normalised, None)
                self._buffer = deque(
                    (
                        item
                        for item in self._buffer
                        if _normalise_scope(item.scope or item.source) != normalised
                    ),
                    maxlen=self._max_buffer,
                )
            self._dropped = 0

    def enable_raw_capture(
        self,
        scope: str,
        *,
        ttl_seconds: int,
        consent: str,
    ) -> float:
        """Enable short-lived raw capture for one exact reader/source scope."""
        normalised = _normalise_scope(scope)
        if consent != "I_UNDERSTAND_RAW_APDU_SECRETS":
            raise ValueError("explicit raw APDU consent phrase is required")
        ttl = int(ttl_seconds)
        if ttl < 30 or ttl > 300:
            raise ValueError("raw APDU capture TTL must be between 30 and 300 seconds")
        deadline = time.monotonic() + ttl
        with self._lock:
            self._buffers.pop(normalised, None)
            self._raw_capture_deadlines[normalised] = deadline
        return deadline

    def disable_raw_capture(self, scope: str) -> None:
        """Disable raw capture and purge the scoped raw buffer."""
        normalised = _normalise_scope(scope)
        with self._lock:
            self._raw_capture_deadlines.pop(normalised, None)
            self._buffers.pop(normalised, None)

    def raw_capture_enabled(self, scope: str) -> bool:
        normalised = _normalise_scope(scope)
        with self._lock:
            self._expire_raw_consents_locked()
            deadline = self._raw_capture_deadlines.get(normalised, 0.0)
            return deadline > time.monotonic()

    def _expire_raw_consents_locked(self) -> None:
        now = time.monotonic()
        expired = [
            scope
            for scope, deadline in self._raw_capture_deadlines.items()
            if deadline <= now
        ]
        for scope in expired:
            self._raw_capture_deadlines.pop(scope, None)
            self._buffers.pop(scope, None)

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def async_queue_count(self) -> int:
        with self._lock:
            self._prune_async_queues_locked()
            return len(self._async_queues)

    @property
    def async_queue_cap(self) -> int:
        return self._max_async_queues


_RECORDER = _ApduRecorder()


def _normalise_scope(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return "card"
    if len(text) > 256 or any(ord(character) < 32 for character in text):
        raise ValueError("APDU recorder scope is invalid")
    return text


def _redacted_exchange(exchange: ApduExchange) -> ApduExchange:
    """Return the metadata-only form used by aggregate/global consumers."""
    if not exchange.raw_capture and exchange.payload_redacted:
        return exchange
    return replace(
        exchange,
        apdu_hex=str(exchange.apdu_hex)[:8],
        data_hex="",
        payload_redacted=True,
        raw_capture=False,
    )


def get_recorder() -> _ApduRecorder:
    """Return the process-wide :class:`_ApduRecorder` singleton."""
    return _RECORDER


# ----------------------------------------------------------- wrap_connection
def wrap_connection(connection: Any, *, source: str = "card") -> Any:
    """Monkey-patch ``connection.transmit`` to record every APDU.

    The wrapper is idempotent (calling it twice on the same connection
    is a no-op). It preserves the original ``transmit`` semantics —
    return value, raised exceptions, kwargs — and adds a single side
    effect: every successful response and every raised exception
    appends one :class:`ApduExchange` to the global recorder.

    The captured ``source`` is just a free-form label routed to the
    GUI's "source" column. ``card_backend`` defaults it to a string
    describing where the connection came from (relay / pcsc / sim);
    individual modules may pre-wrap with a more specific label
    (e.g. ``"scp03.scan"``) before handing the connection to a deeper
    transporter.
    """
    if connection is None:
        return connection
    if getattr(connection, "_yggdrasim_apdu_traced", False):
        return connection

    original = getattr(connection, "transmit", None)
    if not callable(original):
        return connection

    def _traced(apdu, *args, **kwargs):
        try:
            apdu_bytes = bytes(apdu)
        except Exception:  # noqa: BLE001 — exotic apdu shapes
            apdu_bytes = b""

        start = time.perf_counter()
        try:
            data, sw1, sw2 = original(apdu, *args, **kwargs)
        except Exception:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            raw_capture = _RECORDER.raw_capture_enabled(source)
            exchange = ApduExchange(
                ts=datetime.now(timezone.utc).timestamp(),
                source=source,
                apdu_hex=(
                    apdu_bytes.hex().upper()
                    if raw_capture
                    else apdu_bytes[:4].hex().upper()
                ),
                data_hex="",
                sw_hex="ERR",
                elapsed_ms=elapsed_ms,
                command_length=len(apdu_bytes),
                response_length=0,
                scope=source,
                payload_redacted=not raw_capture,
                raw_capture=raw_capture,
            )
            _RECORDER.record(exchange)
            raise

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        try:
            data_bytes = bytes(data) if data else b""
        except Exception:  # noqa: BLE001 — pyscard returns list[int]
            data_bytes = bytes(list(data)) if data else b""
        raw_capture = _RECORDER.raw_capture_enabled(source)
        exchange = ApduExchange(
            ts=datetime.now(timezone.utc).timestamp(),
            source=source,
            apdu_hex=(
                apdu_bytes.hex().upper()
                if raw_capture
                else apdu_bytes[:4].hex().upper()
            ),
            data_hex=data_bytes.hex().upper() if raw_capture else "",
            sw_hex=f"{int(sw1) & 0xFF:02X}{int(sw2) & 0xFF:02X}",
            elapsed_ms=elapsed_ms,
            command_length=len(apdu_bytes),
            response_length=len(data_bytes),
            scope=source,
            payload_redacted=not raw_capture,
            raw_capture=raw_capture,
        )
        _RECORDER.record(exchange)
        return data, sw1, sw2

    connection.transmit = _traced  # type: ignore[assignment]
    setattr(connection, "_yggdrasim_apdu_traced", True)
    return connection
