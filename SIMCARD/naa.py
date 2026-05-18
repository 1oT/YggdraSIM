# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Network Access Application logic: PIN verification, AUTHENTICATE routing, and NAA file-system scope management (ETSI TS 102 221)."""
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

        Disabled-PIN handling follows TS 102 221 §11.1.9 / §10.2.1.5:

        * Retry-counter probes (Lc=0) report the counter regardless
          of enable state -- the modem is allowed to query it without
          attempting a comparison.
        * A real comparison attempt (Lc=8) against a disabled PIN
          returns 69 84 ("referenced data invalidated") without
          consuming a retry. That matches sysmoUSIM-SJS1, sysmoEUICC,
          and pySim's reference behaviour. The previous 6A 88 reply
          ("referenced data not found") implied the PIN slot itself
          was missing, which broke modems that probe disabled PINs
          before consulting PS_DO.
        """
        reference_state = self._reference_state(p2)
        if reference_state is None:
            return b"", 0x6A, 0x88
        normalized_payload = bytes(payload or b"")
        if len(normalized_payload) == 0:
            return self._query_retry_counter(reference_state.retries_remaining)
        if len(normalized_payload) != 8:
            return b"", 0x67, 0x00
        if reference_state.enabled is False:
            return b"", 0x69, 0x84
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
        """Handle UNBLOCK CHV (ETSI TS 102 221 §11.1.12) using the supplied PUK and new PIN."""
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

    def change_chv(self, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.10 CHANGE PIN.

        The terminal supplies the current PIN and the new one in a single
        16-byte payload (8 bytes padded with FF each). Lc=0 is a retry-
        counter probe identical to VERIFY. CHANGE PIN does not work if the
        reference is disabled (subclause 11.1.11) -- commercial UICCs
        return 69 84 (referenced data invalidated) in that case.
        """
        reference = int(p2) & 0xFF
        reference_state = self.state.chv_references.get(reference)
        if reference_state is None:
            return b"", 0x6A, 0x88
        normalized_payload = bytes(payload or b"")
        if len(normalized_payload) == 0:
            return self._query_retry_counter(reference_state.retries_remaining)
        if reference_state.enabled is False:
            return b"", 0x69, 0x84
        if reference_state.retries_remaining <= 0:
            return b"", 0x69, 0x83
        if len(normalized_payload) != 16:
            return b"", 0x67, 0x00
        provided_old = normalized_payload[:8]
        new_pin = normalized_payload[8:16]
        if hmac.compare_digest(provided_old, self._pad_chv_value(reference_state.value)) is False:
            reference_state.verified = False
            self._verified_references.discard(reference)
            reference_state.retries_remaining = max(0, reference_state.retries_remaining - 1)
            if reference_state.retries_remaining <= 0:
                return b"", 0x69, 0x83
            return self._query_retry_counter(reference_state.retries_remaining)
        reference_state.value = self._decode_chv_value(new_pin)
        reference_state.verified = True
        reference_state.retries_remaining = reference_state.retry_limit
        self._verified_references.add(reference)
        return b"", 0x90, 0x00

    def disable_chv(self, p1: int, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.11 DISABLE PIN.

        P1 bit 7 (0x80) selects "PIN reference data ignored / use
        universal PIN" replacement, which we accept but do not yet model
        (no Universal PIN slot in state). P1 bits 0..2 must be zero.
        """
        return self._toggle_enabled_chv(p2, payload, target_enabled=False, p1=p1)

    def enable_chv(self, p1: int, p2: int, payload: bytes) -> tuple[bytes, int, int]:
        """ETSI TS 102 221 §11.1.12 ENABLE PIN."""
        return self._toggle_enabled_chv(p2, payload, target_enabled=True, p1=p1)

    def _toggle_enabled_chv(
        self,
        p2: int,
        payload: bytes,
        *,
        target_enabled: bool,
        p1: int,
    ) -> tuple[bytes, int, int]:
        reference = int(p2) & 0xFF
        reference_state = self.state.chv_references.get(reference)
        if reference_state is None:
            return b"", 0x6A, 0x88
        # P1 bits 0..2 are RFU per TS 102 221; bit 7 toggles "use
        # universal PIN" which we don't model. Anything else is rejected.
        if (int(p1) & 0x7F) != 0:
            return b"", 0x6A, 0x86
        normalized_payload = bytes(payload or b"")
        if len(normalized_payload) == 0:
            return self._query_retry_counter(reference_state.retries_remaining)
        if reference_state.enabled == target_enabled:
            # ETSI TS 102 221 §11.1.11/12: "command may be successfully
            # processed even if the PIN was already in the requested
            # state". Most commercial UICCs return 9000 in that case.
            if hmac.compare_digest(
                normalized_payload, self._pad_chv_value(reference_state.value)
            ) is False:
                reference_state.retries_remaining = max(0, reference_state.retries_remaining - 1)
                if reference_state.retries_remaining <= 0:
                    return b"", 0x69, 0x83
                return self._query_retry_counter(reference_state.retries_remaining)
            reference_state.verified = True
            self._verified_references.add(reference)
            return b"", 0x90, 0x00
        if reference_state.retries_remaining <= 0:
            return b"", 0x69, 0x83
        if len(normalized_payload) != 8:
            return b"", 0x67, 0x00
        if hmac.compare_digest(
            normalized_payload, self._pad_chv_value(reference_state.value)
        ) is False:
            reference_state.retries_remaining = max(0, reference_state.retries_remaining - 1)
            if reference_state.retries_remaining <= 0:
                return b"", 0x69, 0x83
            return self._query_retry_counter(reference_state.retries_remaining)
        reference_state.enabled = target_enabled
        reference_state.verified = True
        reference_state.retries_remaining = reference_state.retry_limit
        self._verified_references.add(reference)
        return b"", 0x90, 0x00

    def _reference_state(self, p2: int):
        """Look up a CHV reference by P2.

        Returns ``None`` only when the slot does not exist (so the
        caller can issue 6A 88 "referenced data not found"). The
        ``enabled`` flag is *not* consulted here -- that decision
        belongs to the individual command handlers because the
        spec-correct response code differs (e.g. VERIFY against a
        disabled PIN returns 69 84 per TS 102 221 §11.1.9, while
        UNBLOCK PIN must still operate per §11.1.13).
        """
        reference = int(p2) & 0xFF
        return self.state.chv_references.get(reference)

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
