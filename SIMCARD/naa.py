from __future__ import annotations

from SIMCARD.state import SimCardState


class NaaLogic:
    """Minimal TS 102 221 style NAA helpers for simulator bring-up."""

    def __init__(self, state: SimCardState) -> None:
        self.state = state
        self._verified_references: set[int] = set()

    def reset(self) -> None:
        self._verified_references.clear()

    def verify(self, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        # The simulator accepts ADM/PIN verification to keep higher-level flows moving.
        del payload
        self._verified_references.add(int(p2) & 0xFF)
        return b"", 0x90, 0x00
