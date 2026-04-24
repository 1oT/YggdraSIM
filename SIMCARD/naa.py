from __future__ import annotations

import hmac

from SIMCARD.state import SimCardState


class NaaLogic:
    """Minimal TS 102 221 style NAA helpers for simulator bring-up."""

    def __init__(self, state: SimCardState) -> None:
        self.state = state
        self._verified_references: set[int] = set()

    def reset(self) -> None:
        self._verified_references.clear()
        for reference_state in self.state.chv_references.values():
            reference_state.verified = False

    def verify(self, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.9 VERIFY PIN.

        Lc=0 queries the retry counter (63 Cx / 69 83). Lc=8 attempts
        a verification. Any other Lc is rejected with 67 00 and does
        NOT consume a retry, matching the behaviour of commercial
        UICC references. Previously non-8-byte payloads were silently
        compared against the padded stored value and therefore
        consumed a retry on mismatch, which could lock a CHV after a
        handful of malformed probes.
        """
        reference_state = self._reference_state(p2)
        if reference_state is None:
            return b"", 0x6A, 0x88
        normalized_payload = bytes(payload or b"")
        if len(normalized_payload) == 0:
            return self._query_retry_counter(reference_state.retries_remaining)
        if len(normalized_payload) != 8:
            return b"", 0x67, 0x00
        if reference_state.retries_remaining <= 0:
            return b"", 0x69, 0x83
        # Constant-time compare: CHV value handling is security-sensitive
        # even on a simulator (tests run against it) and must not leak
        # byte-by-byte timing. The rest of the codebase standardised on
        # ``hmac.compare_digest``; NAA now matches.
        if hmac.compare_digest(normalized_payload, self._pad_chv_value(reference_state.value)):
            reference_state.verified = True
            reference_state.retries_remaining = reference_state.retry_limit
            self._verified_references.add(int(p2) & 0xFF)
            return b"", 0x90, 0x00
        reference_state.verified = False
        self._verified_references.discard(int(p2) & 0xFF)
        reference_state.retries_remaining = max(0, reference_state.retries_remaining - 1)
        if reference_state.retries_remaining <= 0:
            return b"", 0x69, 0x83
        return self._query_retry_counter(reference_state.retries_remaining)

    def unblock_chv(self, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        reference_state = self._reference_state(p2)
        if reference_state is None:
            return b"", 0x6A, 0x88
        normalized_payload = bytes(payload or b"")
        if len(normalized_payload) == 0:
            return self._query_retry_counter(reference_state.unblock_retries_remaining)
        if reference_state.unblock_retries_remaining <= 0:
            return b"", 0x69, 0x83
        if len(normalized_payload) != 16:
            return b"", 0x67, 0x00
        provided_puk = normalized_payload[:8]
        new_pin = normalized_payload[8:16]
        if hmac.compare_digest(provided_puk, self._pad_chv_value(reference_state.unblock_value)) is False:
            reference_state.unblock_retries_remaining = max(0, reference_state.unblock_retries_remaining - 1)
            if reference_state.unblock_retries_remaining <= 0:
                return b"", 0x69, 0x83
            return self._query_retry_counter(reference_state.unblock_retries_remaining)
        reference_state.value = self._decode_chv_value(new_pin)
        reference_state.verified = True
        reference_state.retries_remaining = reference_state.retry_limit
        reference_state.unblock_retries_remaining = reference_state.unblock_retry_limit
        self._verified_references.add(int(p2) & 0xFF)
        return b"", 0x90, 0x00

    def _reference_state(self, p2: int):
        reference = int(p2) & 0xFF
        state = self.state.chv_references.get(reference)
        if state is None or state.enabled is False:
            return None
        return state

    @staticmethod
    def _query_retry_counter(retries_remaining: int) -> tuple[bytes, int, int]:
        if retries_remaining <= 0:
            return b"", 0x69, 0x83
        return b"", 0x63, 0xC0 | min(0x0F, int(retries_remaining))

    @staticmethod
    def _pad_chv_value(value: str) -> bytes:
        normalized = str(value or "").encode("ascii", "ignore")[:8]
        return normalized + (b"\xFF" * (8 - len(normalized)))

    @staticmethod
    def _decode_chv_value(value: bytes) -> str:
        normalized = bytes(value or b"")
        trimmed = normalized.split(b"\xFF", 1)[0]
        return trimmed.decode("ascii", "ignore")
