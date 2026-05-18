# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge proactive-command relay: intercepts FETCH R-APDUs and re-delivers the proactive TLV to registered handlers."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any

from .protocol import (
    REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    build_proactive_refresh_command,
    describe_refresh_mode,
    ensure_bytes,
    normalize_refresh_mode,
)

STATUS_INS = 0xF2
FETCH_INS = 0x12
TERMINAL_RESPONSE_INS = 0x14


@dataclass(frozen=True, slots=True)
class QueuedProactiveRefresh:
    mode_name: str
    qualifier: int
    command_number: int
    payload: bytes
    source: str = ""


@dataclass(frozen=True, slots=True)
class ProactiveApduDecision:
    action: str
    response: bytes
    command: QueuedProactiveRefresh


class ProactiveRefreshBroker:
    """Queue and inject synthetic REFRESH proactive commands for the modem."""

    def __init__(self) -> None:
        self._queue: deque[QueuedProactiveRefresh] = deque()
        self._active: QueuedProactiveRefresh | None = None
        self._next_command_number = 1

    @property
    def active_command(self) -> QueuedProactiveRefresh | None:
        return self._active

    @property
    def queued_commands(self) -> list[QueuedProactiveRefresh]:
        return list(self._queue)

    def clear(self) -> None:
        self._queue.clear()
        self._active = None
        self._next_command_number = 1

    def queue_refresh(
        self,
        mode: str | int = REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
        *,
        source: str = "",
    ) -> dict[str, Any]:
        """Queue a REFRESH proactive command for the next FETCH response."""
        mode_name, qualifier = normalize_refresh_mode(mode)
        if self._active is not None and self._active.qualifier == qualifier:
            return self._build_queue_result("coalesced", self._active)

        for pending in self._queue:
            if pending.qualifier == qualifier:
                return self._build_queue_result("coalesced", pending)

        command_number = self._allocate_command_number()
        queued = QueuedProactiveRefresh(
            mode_name=mode_name,
            qualifier=qualifier,
            command_number=command_number,
            payload=build_proactive_refresh_command(
                command_number=command_number,
                qualifier=qualifier,
            ),
            source=str(source or "").strip(),
        )
        self._queue.append(queued)
        return self._build_queue_result("queued", queued)

    def handle_apdu(self, apdu: bytes | bytearray | list[int] | tuple[int, ...]) -> ProactiveApduDecision | None:
        """Route an APDU to the correct proactive-command handler and return (data, SW1, SW2)."""
        apdu_bytes = ensure_bytes(apdu)
        if len(apdu_bytes) < 2:
            return None

        ins = apdu_bytes[1]

        if self._active is None:
            if ins != STATUS_INS or len(self._queue) == 0:
                return None
            self._active = self._queue.popleft()
            return ProactiveApduDecision(
                action="announce",
                response=bytes((0x91, len(self._active.payload))),
                command=self._active,
            )

        if ins == STATUS_INS:
            return ProactiveApduDecision(
                action="announce",
                response=bytes((0x91, len(self._active.payload))),
                command=self._active,
            )

        if ins == FETCH_INS:
            return ProactiveApduDecision(
                action="fetch",
                response=self._active.payload + b"\x90\x00",
                command=self._active,
            )

        if ins == TERMINAL_RESPONSE_INS:
            active = self._active
            self._active = None
            return ProactiveApduDecision(
                action="terminal-response",
                response=b"\x90\x00",
                command=active,
            )

        return None

    def status_payload(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict of the current proactive command queue state."""
        active = self._active
        queued = list(self._queue)
        return {
            "pendingCount": len(queued) + (1 if active is not None else 0),
            "queuedCount": len(queued),
            "activeMode": active.mode_name if active is not None else "",
            "activeQualifier": f"{active.qualifier:02X}" if active is not None else "",
            "queuedModes": [entry.mode_name for entry in queued],
            "deliveryHint": "Queued REFRESH is announced on modem STATUS and served on FETCH.",
        }

    def _allocate_command_number(self) -> int:
        command_number = self._next_command_number
        self._next_command_number += 1
        if self._next_command_number > 0xFE:
            self._next_command_number = 1
        return command_number

    def _build_queue_result(self, status: str, command: QueuedProactiveRefresh) -> dict[str, Any]:
        return {
            "status": status,
            "mode": command.mode_name,
            "qualifier": f"{command.qualifier:02X}",
            "commandNumber": command.command_number,
            "pendingCount": len(self._queue) + (1 if self._active is not None else 0),
            "queuedModes": [entry.mode_name for entry in self._queue],
            "activeMode": self._active.mode_name if self._active is not None else "",
            "activeQualifier": (
                f"{self._active.qualifier:02X}" if self._active is not None else ""
            ),
            "description": describe_refresh_mode(command.qualifier),
            "deliveryHint": "Queued REFRESH is announced on modem STATUS and served on FETCH.",
        }
