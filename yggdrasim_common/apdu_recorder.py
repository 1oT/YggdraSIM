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

"""Process-wide APDU exchange recorder.

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
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


__all__ = [
    "ApduExchange",
    "get_recorder",
    "wrap_connection",
]


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
        }


class _ApduRecorder:
    """Thread-safe singleton holding subscribers + a recent-events buffer."""

    def __init__(self, max_buffer: int = 5000) -> None:
        self._lock = threading.RLock()
        self._buffer: deque[ApduExchange] = deque(maxlen=max_buffer)
        self._sync_subs: list[Callable[[ApduExchange], None]] = []
        # Queues are paired with the loop they were created on so
        # ``put_nowait`` from a worker thread can be relayed via
        # ``call_soon_threadsafe`` instead of crashing on a foreign loop.
        self._async_queues: list[tuple[asyncio.Queue, asyncio.AbstractEventLoop]] = []
        self._dropped: int = 0

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
            self._buffer.append(exchange)
            sync_subs = list(self._sync_subs)
            async_queues = list(self._async_queues)

        for fn in sync_subs:
            try:
                fn(exchange)
            except Exception:  # noqa: BLE001 — never trust subscribers
                self._dropped += 1

        for queue, loop in async_queues:
            try:
                loop.call_soon_threadsafe(self._safe_put, queue, exchange)
            except RuntimeError:
                # Loop has shut down (websocket closed mid-emit).
                self._dropped += 1

    @staticmethod
    def _safe_put(queue: asyncio.Queue, exchange: ApduExchange) -> None:
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
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> Callable[[], None]:
        """Register *queue* for live event delivery.

        *loop* defaults to the running loop at the call site; the
        WebSocket route hands its own loop in to make the cross-thread
        relay explicit.
        """
        owning_loop = loop or asyncio.get_event_loop()
        with self._lock:
            self._async_queues.append((queue, owning_loop))

        def _detach() -> None:
            with self._lock:
                try:
                    self._async_queues.remove((queue, owning_loop))
                except ValueError:
                    pass

        return _detach

    # ----------------------------------------------------------- snapshots
    def snapshot(self, limit: int | None = None) -> list[ApduExchange]:
        with self._lock:
            items = list(self._buffer)
        if limit is not None and limit < len(items):
            items = items[-limit:]
        return items

    def clear(self) -> None:
        with self._lock:
            self._buffer.clear()
            self._dropped = 0

    @property
    def dropped(self) -> int:
        return self._dropped


_RECORDER = _ApduRecorder()


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
            exchange = ApduExchange(
                ts=datetime.now(timezone.utc).timestamp(),
                source=source,
                apdu_hex=apdu_bytes.hex().upper(),
                data_hex="",
                sw_hex="ERR",
                elapsed_ms=elapsed_ms,
            )
            _RECORDER.record(exchange)
            raise

        elapsed_ms = (time.perf_counter() - start) * 1000.0
        try:
            data_bytes = bytes(data) if data else b""
        except Exception:  # noqa: BLE001 — pyscard returns list[int]
            data_bytes = bytes(list(data)) if data else b""
        exchange = ApduExchange(
            ts=datetime.now(timezone.utc).timestamp(),
            source=source,
            apdu_hex=apdu_bytes.hex().upper(),
            data_hex=data_bytes.hex().upper(),
            sw_hex=f"{int(sw1) & 0xFF:02X}{int(sw2) & 0xFF:02X}",
            elapsed_ms=elapsed_ms,
        )
        _RECORDER.record(exchange)
        return data, sw1, sw2

    connection.transmit = _traced  # type: ignore[assignment]
    setattr(connection, "_yggdrasim_apdu_traced", True)
    return connection
