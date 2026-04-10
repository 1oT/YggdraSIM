from __future__ import annotations

from SIMCARD.state import SimCardState


class Scp80Logic:
    def __init__(self, state: SimCardState) -> None:
        self.state = state

    def handle_envelope(self, payload: bytes) -> tuple[bytes, int, int]:
        self.state.ota_history.append(payload.hex().upper())
        # Queue a tiny proactive object so SCP80 reader-mode code can FETCH a POR-like body.
        proactive_por = bytes.fromhex("D00C8103011300820281828B0100")
        self.state.pending_fetch_queue.append(proactive_por)
        return b"", 0x91, len(proactive_por)
