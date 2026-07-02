# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge PCSC channel: wraps pyscard to open a physical reader slot and exchange raw ISO 7816 APDUs."""
from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

_LOGGER = logging.getLogger(__name__)

DEFAULT_APDU_TIMEOUT_MS = 5000
APDU_TIMEOUT_ENV = "YGGDRASIM_HIL_APDU_TIMEOUT_MS"
PCSC_SHARE_MODE_EXCLUSIVE = "exclusive"
PCSC_SHARE_MODE_SHARED = "shared"
PCSC_SHARE_MODES = (PCSC_SHARE_MODE_EXCLUSIVE, PCSC_SHARE_MODE_SHARED)


def resolve_apdu_timeout_ms(value: Any = None) -> int:
    """Return a bounded APDU transmit timeout in milliseconds."""
    raw_value = value
    if raw_value is None:
        raw_value = os.environ.get(APDU_TIMEOUT_ENV, "")
    text = str(raw_value or "").strip()
    if len(text) == 0:
        return DEFAULT_APDU_TIMEOUT_MS
    try:
        parsed = int(text)
    except (TypeError, ValueError):
        return DEFAULT_APDU_TIMEOUT_MS
    return max(100, parsed)


class PcscBridgeError(RuntimeError):
    """Raised when the physical reader bridge cannot be established."""


def _load_smartcard_runtime() -> tuple[Any, Any, Any, Any, Any, Any, Any]:
    try:
        from smartcard.System import readers
        from smartcard.scard import (
            SCARD_LEAVE_CARD,
            SCARD_SHARE_EXCLUSIVE,
            SCARD_SHARE_SHARED,
            SCARD_UNPOWER_CARD,
        )
    except ImportError as exc:
        raise PcscBridgeError(
            "pyscard is required for the HIL bridge. Install it in the active Python environment."
        ) from exc

    try:
        from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
    except ImportError:
        ExclusiveConnectCardConnection = None

    return (
        readers,
        SCARD_SHARE_EXCLUSIVE,
        SCARD_SHARE_SHARED,
        SCARD_UNPOWER_CARD,
        SCARD_LEAVE_CARD,
        ExclusiveConnectCardConnection,
        PcscBridgeError,
    )


def _normalize_share_mode(value: Any) -> str:
    normalized = str(value or PCSC_SHARE_MODE_EXCLUSIVE).strip().lower()
    if normalized in PCSC_SHARE_MODES:
        return normalized
    raise PcscBridgeError(
        "PC/SC share mode must be one of: " + ", ".join(PCSC_SHARE_MODES)
    )


@dataclass(slots=True)
class PcscCardChannel:
    reader_index: int = 0
    reader_name: str = ""
    share_mode: str = PCSC_SHARE_MODE_EXCLUSIVE
    _connection: Any = field(default=None, init=False, repr=False)
    _reader_label: str = field(default="", init=False)
    _last_reset_summary: dict[str, Any] = field(default_factory=dict, init=False, repr=False)

    @staticmethod
    def list_reader_names() -> list[str]:
        readers, _, _, _, _, _, _ = _load_smartcard_runtime()
        return [str(reader) for reader in readers()]

    @property
    def reader_label(self) -> str:
        return self._reader_label

    def connect(self) -> None:
        """Connect to the PCSC reader identified by *reader_name* and return True on success."""
        (
            readers,
            share_exclusive,
            share_shared,
            _unpower_card,
            _leave_card,
            exclusive_wrapper,
            error_type,
        ) = _load_smartcard_runtime()
        available_readers = list(readers())
        if len(available_readers) == 0:
            raise error_type("No PC/SC readers are available.")

        selected_reader = self._select_reader(available_readers)
        connection = selected_reader.createConnection()
        share_mode = _normalize_share_mode(self.share_mode)
        pcsc_share_mode = (
            share_shared
            if share_mode == PCSC_SHARE_MODE_SHARED
            else share_exclusive
        )
        if share_mode == PCSC_SHARE_MODE_EXCLUSIVE and exclusive_wrapper is not None:
            connection = exclusive_wrapper(connection)

        try:
            connection.connect(mode=pcsc_share_mode)
        except Exception as exc:
            pcsc_name = (
                "SCARD_SHARE_SHARED"
                if share_mode == PCSC_SHARE_MODE_SHARED
                else "SCARD_SHARE_EXCLUSIVE"
            )
            raise error_type(
                f"Failed to open reader '{selected_reader}' in {pcsc_name} mode."
            ) from exc

        self._connection = connection
        self._reader_label = str(selected_reader)

    def reconnect(self) -> None:
        self.disconnect()
        self.connect()

    @property
    def last_reset_summary(self) -> dict[str, Any]:
        return dict(self._last_reset_summary)

    def reset_card(self) -> dict[str, Any]:
        """Power-cycle the card slot and reconnect to a clean selected state."""
        if self._connection is None:
            self.connect()
            self._last_reset_summary = {"mode": "connect-only", "pcscHandle": False}
            return self.last_reset_summary

        (
            _readers,
            share_exclusive,
            share_shared,
            unpower_card,
            leave_card,
            _exclusive_wrapper,
            _error_type,
        ) = _load_smartcard_runtime()
        pcsc_share_mode = (
            share_shared
            if _normalize_share_mode(self.share_mode) == PCSC_SHARE_MODE_SHARED
            else share_exclusive
        )
        connection = self._connection
        self._connection = None
        target = self._unwrap_connection(connection)
        had_handle = getattr(target, "hcard", None) is not None
        did_reconnect = self._reconnect_with_unpower(target, pcsc_share_mode, unpower_card)
        disconnect_disposition = leave_card if did_reconnect else unpower_card
        self._disconnect_with_disposition(target, disconnect_disposition)
        time.sleep(0.2)
        self.connect()
        self._last_reset_summary = {
            "mode": "pcsc-reconnect-unpower" if did_reconnect else "pcsc-disconnect-unpower",
            "pcscHandle": had_handle,
        }
        return self.last_reset_summary

    def _unwrap_connection(self, connection: Any) -> Any:
        target = connection
        while hasattr(target, "component"):
            target = target.component
        return target

    def _reconnect_with_unpower(self, connection: Any, share_mode: Any, disposition: Any) -> bool:
        hcard = getattr(connection, "hcard", None)
        if hcard is None:
            return False
        try:
            from smartcard.scard import (
                SCARD_PROTOCOL_T0,
                SCARD_PROTOCOL_T1,
                SCARD_S_SUCCESS,
                SCardGetErrorMessage,
                SCardReconnect,
            )
        except ImportError:
            return False

        protocol = SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1
        hresult, active_protocol = SCardReconnect(
            hcard,
            share_mode,
            protocol,
            disposition,
        )
        if hresult != SCARD_S_SUCCESS:
            raise PcscBridgeError(
                "PC/SC reset reconnect failed: " + SCardGetErrorMessage(hresult)
            )
        try:
            connection.setProtocol(active_protocol)
        except Exception:
            pass
        return True

    def _disconnect_with_disposition(self, connection: Any, disposition: Any) -> None:
        try:
            connection.disposition = disposition
        except Exception:
            pass

        try:
            connection.disconnect()
            return
        except TypeError:
            pass

        try:
            connection.disconnect(disposition)
            return
        except TypeError:
            connection.disconnect(disposition=disposition)

    def disconnect(self) -> None:
        """Disconnect the active PCSC reader connection."""
        if self._connection is None:
            return
        try:
            self._connection.disconnect()
        except Exception as disconnect_error:
            _LOGGER.debug(
                "PC/SC disconnect swallowed %s: %s",
                disconnect_error.__class__.__name__,
                disconnect_error,
            )
        self._connection = None

    def get_atr(self) -> bytes:
        connection = self._require_connection()
        atr = connection.getATR()
        return bytes(atr)

    def transmit(self, apdu: bytes, *, timeout_ms: int | None = None) -> tuple[bytes, int, int]:
        """Transmit a raw APDU byte list and return (response_bytes, SW1, SW2).

        The underlying PC/SC ``transmit`` call blocks until the card
        responds.  A worker thread is spawned so the caller can cap the
        wait with *timeout_ms*.  When the timeout fires the caller
        receives a :class:`PcscBridgeError`; the abandoned thread
        eventually completes (or errors) against the old connection and
        exits cleanly.
        """
        effective_timeout_ms = resolve_apdu_timeout_ms(timeout_ms)
        connection = self._require_connection()
        apdu_list = list(bytes(apdu))
        result_holder: list[tuple[list[int], int, int]] = []
        error_holder: list[Exception] = []

        def _do_transmit() -> None:
            try:
                result_holder.append(connection.transmit(apdu_list))
            except Exception as exc:
                error_holder.append(exc)

        worker = threading.Thread(target=_do_transmit, daemon=True)
        worker.start()
        worker.join(timeout=max(0.1, effective_timeout_ms / 1000.0))

        if worker.is_alive():
            raise PcscBridgeError(
                f"PC/SC APDU transmit timed out after {effective_timeout_ms}ms."
            )

        if error_holder:
            raise PcscBridgeError("PC/SC APDU transmit failed.") from error_holder[0]

        if not result_holder:
            raise PcscBridgeError("PC/SC APDU transmit returned no result.")

        response_list, sw1, sw2 = result_holder[0]
        return bytes(response_list), int(sw1), int(sw2)

    def _require_connection(self) -> Any:
        if self._connection is None:
            raise PcscBridgeError("Reader is not connected.")
        return self._connection

    def _select_reader(self, available_readers: list[Any]) -> Any:
        if self.reader_name:
            needle = self.reader_name.casefold()
            for reader in available_readers:
                if needle in str(reader).casefold():
                    return reader
            raise PcscBridgeError(
                f"No reader matched '{self.reader_name}'. Available readers: "
                + ", ".join(str(reader) for reader in available_readers)
            )

        if self.reader_index < 0 or self.reader_index >= len(available_readers):
            raise PcscBridgeError(
                f"Reader index {self.reader_index} is out of range for {len(available_readers)} reader(s)."
            )
        return available_readers[self.reader_index]
