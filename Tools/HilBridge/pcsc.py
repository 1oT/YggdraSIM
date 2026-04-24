from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

_LOGGER = logging.getLogger(__name__)


class PcscBridgeError(RuntimeError):
    """Raised when the physical reader bridge cannot be established."""


def _load_smartcard_runtime() -> tuple[Any, Any, Any, Any]:
    try:
        from smartcard.System import readers
        from smartcard.scard import SCARD_SHARE_EXCLUSIVE
    except ImportError as exc:
        raise PcscBridgeError(
            "pyscard is required for the HIL bridge. Install it in the active Python environment."
        ) from exc

    try:
        from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
    except ImportError:
        ExclusiveConnectCardConnection = None

    return readers, SCARD_SHARE_EXCLUSIVE, ExclusiveConnectCardConnection, PcscBridgeError


@dataclass(slots=True)
class PcscCardChannel:
    reader_index: int = 0
    reader_name: str = ""
    _connection: Any = field(default=None, init=False, repr=False)
    _reader_label: str = field(default="", init=False)

    @staticmethod
    def list_reader_names() -> list[str]:
        readers, _, _, _ = _load_smartcard_runtime()
        return [str(reader) for reader in readers()]

    @property
    def reader_label(self) -> str:
        return self._reader_label

    def connect(self) -> None:
        readers, share_exclusive, exclusive_wrapper, error_type = _load_smartcard_runtime()
        available_readers = list(readers())
        if len(available_readers) == 0:
            raise error_type("No PC/SC readers are available.")

        selected_reader = self._select_reader(available_readers)
        connection = selected_reader.createConnection()
        if exclusive_wrapper is not None:
            connection = exclusive_wrapper(connection)

        try:
            connection.connect(mode=share_exclusive)
        except Exception as exc:
            raise error_type(
                f"Failed to open reader '{selected_reader}' in SCARD_SHARE_EXCLUSIVE mode."
            ) from exc

        self._connection = connection
        self._reader_label = str(selected_reader)

    def reconnect(self) -> None:
        self.disconnect()
        self.connect()

    def disconnect(self) -> None:
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

    def transmit(self, apdu: bytes) -> tuple[bytes, int, int]:
        connection = self._require_connection()
        apdu_list = list(bytes(apdu))
        try:
            response_list, sw1, sw2 = connection.transmit(apdu_list)
        except Exception as exc:
            raise PcscBridgeError("PC/SC APDU transmit failed.") from exc

        response_bytes = bytes(response_list)
        return response_bytes, int(sw1), int(sw2)

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
