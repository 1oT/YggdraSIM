# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""In-process AKMA Anchor Function (AAnF) reference state.

Implements the minimum bookkeeping the AAnF needs per TS 33.535 \u00a76.1
and \u00a76.2:

* ``register(supi, a_kid, k_akma, lifetime_seconds)`` mirrors
  ``Naanf_AKMA_KeyRegistration`` -- the AUSF pushes the
  ``(SUPI, A-KID, KAKMA)`` tuple after a successful primary auth, with
  an implementation-defined expiration.
* ``application_key_get(a_kid, af_id)`` mirrors
  ``Naanf_AKMA_ApplicationKey_Get`` -- given an A-KID and AF_ID, the
  AAnF derives a fresh ``KAF`` and returns it together with the SUPI
  and an expiration timestamp.

The state is process-local and intentionally not persisted; the GUI
"clear" action wipes it cleanly. A single :class:`threading.Lock`
serialises mutation so the FastAPI thread pool and the future stub
HTTP server can both share the registry without races.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Optional

from SIMCARD.akma import derive_k_af


# Default lifetime for an AAnF registration. TS 33.535 leaves the
# concrete value to operator policy (typically minutes -- the lifetime
# is bounded by the next primary authentication anyway). 30 minutes
# is enough for a manual GUI walk-through without forcing the operator
# to constantly re-register.
DEFAULT_AANF_LIFETIME_SECONDS = 30 * 60

# Default KAF expiration. Per TS 33.535 \u00a76.2.1 this is bounded by
# the AAnF context expiration; we mirror the same default so the GUI
# trace shows two coherent timestamps.
DEFAULT_KAF_LIFETIME_SECONDS = 30 * 60


class AAnFLookupError(KeyError):
    """Raised when an A-KID is unknown or its registration has expired."""


@dataclass(frozen=True)
class AAnFRegistration:
    """One ``(SUPI, A-KID, KAKMA)`` tuple stored on the AAnF.

    ``expires_at`` is a wall-clock UNIX timestamp (seconds). The store
    treats expired entries as absent on the next read; it does not
    spawn a background reaper.
    """

    supi: str
    a_kid: str
    k_akma: bytes
    registered_at: float
    expires_at: float


@dataclass(frozen=True)
class ApplicationKeyResponse:
    """Result of an ``Naanf_AKMA_ApplicationKey_Get`` invocation."""

    supi: str
    a_kid: str
    af_id: str
    k_af: bytes
    k_af_expires_at: float


class AAnFStub:
    """Process-local AAnF registry. Thread-safe for single-process use."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[str, AAnFRegistration] = {}

    def register(
        self,
        *,
        supi: str,
        a_kid: str,
        k_akma: bytes,
        lifetime_seconds: int = DEFAULT_AANF_LIFETIME_SECONDS,
    ) -> AAnFRegistration:
        normalised_supi = self._coerce_supi(supi)
        normalised_a_kid = self._coerce_a_kid(a_kid)
        normalised_kakma = self._coerce_kakma(k_akma)
        if int(lifetime_seconds) <= 0:
            raise ValueError("lifetime_seconds must be positive.")
        now = time.time()
        entry = AAnFRegistration(
            supi=normalised_supi,
            a_kid=normalised_a_kid,
            k_akma=normalised_kakma,
            registered_at=now,
            expires_at=now + float(lifetime_seconds),
        )
        with self._lock:
            self._entries[normalised_a_kid] = entry
        return entry

    def deregister(self, a_kid: str) -> bool:
        normalised = self._coerce_a_kid(a_kid)
        with self._lock:
            return self._entries.pop(normalised, None) is not None

    def lookup(self, a_kid: str) -> AAnFRegistration:
        normalised = self._coerce_a_kid(a_kid)
        now = time.time()
        with self._lock:
            entry = self._entries.get(normalised)
            if entry is None:
                raise AAnFLookupError(f"unknown A-KID: {normalised!r}")
            if entry.expires_at <= now:
                self._entries.pop(normalised, None)
                raise AAnFLookupError(f"expired A-KID: {normalised!r}")
            return entry

    def application_key_get(
        self,
        *,
        a_kid: str,
        af_id: str,
        kaf_lifetime_seconds: int = DEFAULT_KAF_LIFETIME_SECONDS,
    ) -> ApplicationKeyResponse:
        if int(kaf_lifetime_seconds) <= 0:
            raise ValueError("kaf_lifetime_seconds must be positive.")
        entry = self.lookup(a_kid)
        af_text = self._coerce_af_id(af_id)
        k_af = derive_k_af(entry.k_akma, af_text)
        # TS 33.535 \u00a76.2.1: KAF lifetime is bounded by the AAnF entry's.
        bounded_lifetime = min(
            float(kaf_lifetime_seconds),
            entry.expires_at - time.time(),
        )
        if bounded_lifetime <= 0:
            raise AAnFLookupError(
                "AAnF entry already expired; refresh primary auth first."
            )
        return ApplicationKeyResponse(
            supi=entry.supi,
            a_kid=entry.a_kid,
            af_id=af_text,
            k_af=k_af,
            k_af_expires_at=time.time() + bounded_lifetime,
        )

    def snapshot(self) -> list[AAnFRegistration]:
        """Return a list copy of all live entries (expired pruned)."""
        now = time.time()
        with self._lock:
            stale = [a_kid for a_kid, entry in self._entries.items() if entry.expires_at <= now]
            for a_kid in stale:
                self._entries.pop(a_kid, None)
            return list(self._entries.values())

    def clear(self) -> int:
        with self._lock:
            count = len(self._entries)
            self._entries.clear()
            return count

    @staticmethod
    def _coerce_supi(supi: str) -> str:
        text = str(supi or "").strip()
        if len(text) == 0:
            raise ValueError("SUPI must not be empty.")
        return text

    @staticmethod
    def _coerce_a_kid(a_kid: str) -> str:
        text = str(a_kid or "").strip()
        if len(text) == 0:
            raise ValueError("A-KID must not be empty.")
        if "@" not in text:
            raise ValueError("A-KID must be a NAI (username@realm).")
        return text

    @staticmethod
    def _coerce_kakma(k_akma: bytes) -> bytes:
        value = bytes(k_akma or b"")
        if len(value) != 32:
            raise ValueError("KAKMA must be exactly 32 bytes.")
        return value

    @staticmethod
    def _coerce_af_id(af_id: str) -> str:
        text = str(af_id or "").strip()
        if len(text) == 0:
            raise ValueError("AF_ID must not be empty.")
        return text


_DEFAULT_STUB: Optional[AAnFStub] = None


def get_default_aanf_stub() -> AAnFStub:
    """Process-wide AAnF singleton.

    Lazy-instantiated; tests that need an isolated registry should
    construct their own :class:`AAnFStub` instead of mutating this one.
    """
    global _DEFAULT_STUB
    if _DEFAULT_STUB is None:
        _DEFAULT_STUB = AAnFStub()
    return _DEFAULT_STUB


def reset_default_aanf_stub() -> None:
    """Clear the process-wide singleton. Intended for tests / GUI reset."""
    global _DEFAULT_STUB
    if _DEFAULT_STUB is not None:
        _DEFAULT_STUB.clear()


__all__ = [
    "AAnFLookupError",
    "AAnFRegistration",
    "AAnFStub",
    "ApplicationKeyResponse",
    "DEFAULT_AANF_LIFETIME_SECONDS",
    "DEFAULT_KAF_LIFETIME_SECONDS",
    "get_default_aanf_stub",
    "reset_default_aanf_stub",
]
