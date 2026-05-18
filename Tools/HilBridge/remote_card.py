# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge remote-relay card channel.

Adapter that lets the HIL bridge router consume a card published by a
remote ``Tools/CardBridge`` instance instead of opening a local PC/SC
reader. The two ends speak the same ``/apdu`` HTTP relay protocol the
bridge already exposes, so the on-the-wire format is identical to a
local relay round-trip; the only thing that changes is the direction
the TCP socket points.

Topology
--------

::

    operator laptop                       rig (modem + simtrace2)
    ------------------------              -----------------------
    physical SIM in PC/SC ─┐              ┌─ modem
                           │              │
    yggdrasim-card-bridge  ──── SSH ────  HIL bridge ── GSMTAP ── tshark
    (HilBridgeApduRelaySvc) RemoteForward (RemoteRelayCardChannel)
                           │              │
                          :8642 ←──────── /apdu
                                          │
                                          └─ apdu_relay (rig-side
                                             surface unchanged: any
                                             SCP03 / SAIP consumer
                                             on the rig keeps using
                                             the same endpoint)

Notes
-----

* Drop-in for :class:`Tools.HilBridge.pcsc.PcscCardChannel` — exposes
  the same ``connect`` / ``disconnect`` / ``reconnect`` / ``get_atr``
  / ``transmit`` surface :class:`BackendCardChannel` consumes.
* ``queue_modem_refresh`` and ``proactive_status_payload`` are not
  implemented over the relay protocol; the laptop side has no modem
  to refresh and no proactive broker to surface. Calls raise
  :class:`PcscBridgeError` so callers see a clean error rather than
  a silent no-op.
* GSMTAP / pcap mirroring keeps working without changes — capture is
  driven from the rig-side router as TPDUs transit it.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from yggdrasim_common.card_backend import (
    DEFAULT_CARD_RELAY_TIMEOUT_SECONDS,
    RelayCardConnection,
    _build_card_relay_status_url,
    _normalize_card_relay_url,
    _request_card_relay_json,
)

from .pcsc import PcscBridgeError

_LOGGER = logging.getLogger(__name__)


# ----------------------------------------------------------------------
# Env-var surface (HIL-bridge specific so it doesn't collide with the
# global YGGDRASIM_CARD_RELAY_* vars consumed by the SCP03/SAIP CLIs).
# ----------------------------------------------------------------------

REMOTE_CARD_URL_ENV = "YGGDRASIM_HIL_REMOTE_CARD_URL"
REMOTE_CARD_TOKEN_ENV = "YGGDRASIM_HIL_REMOTE_CARD_TOKEN"
REMOTE_CARD_TOKEN_FILE_ENV = "YGGDRASIM_HIL_REMOTE_CARD_TOKEN_FILE"


def resolve_remote_card_url(explicit: str = "") -> str:
    """Return the configured remote-relay URL or ``""`` when unset.

    Resolution order: explicit string → env var. Both go through
    :func:`_normalize_card_relay_url` so a bare ``http://host:port``
    is accepted alongside the canonical ``…/apdu`` form.
    """
    candidate = str(explicit or "").strip()
    if len(candidate) == 0:
        candidate = os.environ.get(REMOTE_CARD_URL_ENV, "") or ""
    return _normalize_card_relay_url(candidate)


def resolve_remote_card_token(
    *, explicit_token: str = "", explicit_token_file: str = ""
) -> str:
    """Return the bearer token for the remote relay or ``""`` when unset.

    Resolution order:
      1. ``explicit_token`` (caller-supplied raw value)
      2. ``explicit_token_file`` (caller-supplied path)
      3. ``YGGDRASIM_HIL_REMOTE_CARD_TOKEN`` env var
      4. ``YGGDRASIM_HIL_REMOTE_CARD_TOKEN_FILE`` env var

    File reads tolerate a trailing newline. Missing files raise
    :class:`PcscBridgeError` so the operator gets a clear failure
    instead of silently falling through to an unauthenticated bind.
    """
    raw = str(explicit_token or "").strip()
    if len(raw) > 0:
        return raw

    candidate_file = str(explicit_token_file or "").strip()
    if len(candidate_file) == 0:
        env_token = (os.environ.get(REMOTE_CARD_TOKEN_ENV, "") or "").strip()
        if len(env_token) > 0:
            return env_token
        candidate_file = (os.environ.get(REMOTE_CARD_TOKEN_FILE_ENV, "") or "").strip()

    if len(candidate_file) == 0:
        return ""

    token_path = Path(os.path.expanduser(candidate_file)).resolve()
    if token_path.is_file() is False:
        raise PcscBridgeError(
            f"Remote card token file not found: {token_path}"
        )
    try:
        return token_path.read_text(encoding="utf-8").strip()
    except OSError as read_error:
        raise PcscBridgeError(
            f"Cannot read remote card token file {token_path}: {read_error}"
        ) from read_error


# ----------------------------------------------------------------------
# Channel adapter
# ----------------------------------------------------------------------


@dataclass(slots=True)
class RemoteRelayCardChannel:
    """Adapter that exposes a remote :class:`RelayCardConnection` as a
    :class:`PcscCardChannel`-shaped channel.

    The HIL bridge's :class:`BackendCardChannel` calls into this object
    the same way it calls into ``PcscCardChannel``; the relay client
    handles the JSON envelope + SSH-tunnelled HTTP transport.
    """

    url: str
    auth_token: str = ""
    timeout_seconds: int = DEFAULT_CARD_RELAY_TIMEOUT_SECONDS
    _connection: Any = field(default=None, init=False, repr=False)
    _reader_label: str = field(default="", init=False, repr=False)
    _atr: bytes = field(default=b"", init=False, repr=False)

    @property
    def reader_label(self) -> str:
        return self._reader_label

    def connect(self) -> None:
        """Open the remote relay connection and prime the ATR cache.

        ``RelayCardConnection.connect`` issues a ``GET /status`` to the
        relay; we mirror its result into our own ATR cache so
        ``get_atr`` matches the local PC/SC channel's contract of
        returning the value cached at connect-time.
        """
        normalized = _normalize_card_relay_url(self.url)
        if len(normalized) == 0:
            raise PcscBridgeError(
                f"Invalid remote card relay URL: {self.url!r}"
            )
        self.url = normalized

        connection = RelayCardConnection(
            normalized,
            timeout_seconds=self.timeout_seconds,
            auth_token=self.auth_token,
        )
        try:
            connection.connect()
        except Exception as connect_error:
            raise PcscBridgeError(
                f"Cannot connect to remote card relay at {normalized}: {connect_error}"
            ) from connect_error

        self._connection = connection
        try:
            self._atr = bytes(connection.getATR())
        except Exception:
            self._atr = b""

        # Pull the human-readable reader label off the relay status
        # endpoint so logs and the GUI bridge can show "remote: <reader
        # at host>" rather than a bare URL. Failure is non-fatal — the
        # reader label is purely cosmetic.
        try:
            status_url = _build_card_relay_status_url(normalized)
            payload = _request_card_relay_json(
                status_url,
                method="GET",
                timeout_seconds=self.timeout_seconds,
                auth_token=self.auth_token,
            )
            reader_text = str(payload.get("reader") or "").strip()
            if len(reader_text) > 0:
                self._reader_label = f"remote: {reader_text}"
            else:
                self._reader_label = f"remote relay {normalized}"
        except Exception as status_error:
            _LOGGER.debug(
                "remote_card: status fetch failed (%s: %s); using URL as label.",
                status_error.__class__.__name__,
                status_error,
            )
            self._reader_label = f"remote relay {normalized}"

    def reconnect(self) -> None:
        """Drop and re-open the relay connection (re-fetches ATR + label)."""
        self.disconnect()
        self.connect()

    def disconnect(self) -> None:
        if self._connection is None:
            return
        try:
            self._connection.disconnect()
        except Exception as disconnect_error:
            _LOGGER.debug(
                "remote_card: disconnect swallowed %s: %s",
                disconnect_error.__class__.__name__,
                disconnect_error,
            )
        self._connection = None

    def get_atr(self) -> bytes:
        """Return the cached ATR (filled at ``connect`` time).

        Falls through to a live ``getATR`` call when the cache is empty
        — the relay's ``/status`` endpoint may have failed at connect
        but the card itself can still be queried.
        """
        if len(self._atr) > 0:
            return self._atr
        connection = self._require_connection()
        return bytes(connection.getATR())

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        connection = self._require_connection()
        try:
            data, sw1, sw2 = connection.transmit(bytes(apdu))
        except Exception as transmit_error:
            raise PcscBridgeError(
                f"Remote card relay APDU transmit failed: {transmit_error}"
            ) from transmit_error
        return bytes(data), int(sw1), int(sw2)

    def queue_modem_refresh(self, mode: Any, *, source: str = "") -> dict[str, Any]:
        """Not supported on the remote relay channel.

        The laptop-side ``yggdrasim-card-bridge`` daemon publishes a
        physical card and has no modem. ``simtrace2`` / ``cardem``
        REFRESH live on the rig and are driven by the rig-side
        router, not by the card channel itself.
        """
        del mode, source
        raise PcscBridgeError(
            "Modem REFRESH queueing is not available when the HIL bridge "
            "consumes a remote card relay; trigger REFRESH from the "
            "rig-side simtrace2 / cardem stack instead."
        )

    def proactive_status_payload(self) -> dict[str, Any]:
        """Empty by design — proactive broker is rig-local."""
        return {}

    def _require_connection(self) -> Any:
        if self._connection is None:
            raise PcscBridgeError(
                "Remote relay card channel is not connected."
            )
        return self._connection
