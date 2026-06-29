# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""In-process stub of the 3GPP AUSF (TS 33.501 \u00a76.1.3 / \u00a76.1.4).

Implements the minimum AUSF surface needed to drive a 5G AKA round
trip end-to-end against the simulated USIM:

* :meth:`AusfStub.start_ue_authentication`  -- mirrors
  ``Nausf_UEAuthentication_Authenticate`` (POST). Generates a fresh
  RAND, increments the subscriber's SQN, builds AUTN per Milenage,
  computes XRES* (TS 33.501 Annex A.4) and KAUSF (Annex A.2), and
  hands back a 5G HE AV plus an opaque ``ctxId``.
* :meth:`AusfStub.confirm_5g_aka` -- mirrors
  ``Nausf_UEAuthentication_Authenticate`` (PUT
  ``5g-aka-confirmation``). Verifies the UE-side RES*, derives KSEAF
  on success, and -- if the subscription has AKMA enabled -- pushes
  ``(SUPI, A-KID, KAKMA)`` into the in-process AAnF stub per
  TS 33.535 \u00a76.1.

The stub is intentionally minimal:

* No SUCI decryption -- callers pass SUPI directly.
* No HXRES* layer (SEAF role is collapsed into the AUSF).
* No persistence beyond the in-memory auth-context dictionary;
  contexts expire after a fixed lifetime to keep the dictionary
  bounded across long-running test sessions.

SUCI / SEAF / NRF pieces are not implemented in this release; the
production answer is the BYO Open5GS bridge.
"""

from __future__ import annotations

import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from SIMCARD.aka_5g import derive_k_ausf, derive_k_seaf, derive_res_star
from SIMCARD.akma import derive_a_tid, derive_k_akma, format_a_kid
from SIMCARD.auth import milenage_vectors

from .aanf_stub import AAnFStub, get_default_aanf_stub
from .subscription_store import (
    SubscriptionStore,
    SubscriptionStoreError,
    get_default_subscription_store,
)


# Auth-context lifetime. TS 33.501 doesn't pin this; 60s is plenty for
# a test rig and short enough that a forgotten context can't pile up.
DEFAULT_AUTH_CONTEXT_LIFETIME_SECONDS = 60


class AusfStubError(RuntimeError):
    """Generic failure from the stub AUSF (subscription / context / verify)."""


class AuthContextNotFoundError(AusfStubError):
    """Raised when ``confirm_5g_aka`` cannot find or has dropped the ctxId."""


class AuthVerificationError(AusfStubError):
    """Raised when the supplied RES* does not match the stored XRES*."""


@dataclass(frozen=True)
class FiveGHeAv:
    """5G Home-Environment Authentication Vector (TS 33.501 \u00a76.1.3.2.0).

    The simulator returns this from the start step and the caller
    forwards ``(rand, autn)`` to the UE; ``xres_star`` and ``k_ausf``
    stay on the AUSF side and feed the confirmation step.
    """

    rand: bytes
    autn: bytes
    xres_star: bytes
    k_ausf: bytes


@dataclass(frozen=True)
class AuthenticateResponse:
    """Result of the start-auth call."""

    ctx_id: str
    supi: str
    sn_name: str
    av: FiveGHeAv
    auth_method: str = "5G_AKA"


@dataclass(frozen=True)
class ConfirmResponse:
    """Result of a successful ``confirm_5g_aka`` call.

    ``a_kid`` is populated only when the subscription has AKMA
    enabled; otherwise it is ``None`` and no AAnF state is touched.
    """

    supi: str
    k_seaf: bytes
    a_kid: Optional[str]
    k_akma: Optional[bytes]


@dataclass
class _AuthContext:
    ctx_id: str
    supi: str
    sn_name: str
    rand: bytes
    autn: bytes
    expected_xres_star: bytes
    k_ausf: bytes
    akma_enabled: bool
    mcc: str
    mnc: str
    routing_indicator: str
    expires_at: float


class AusfStub:
    """Minimal stub AUSF tied to a :class:`SubscriptionStore` + AAnF."""

    def __init__(
        self,
        *,
        subscription_store: Optional[SubscriptionStore] = None,
        aanf_stub: Optional[AAnFStub] = None,
        auth_context_lifetime_seconds: int = DEFAULT_AUTH_CONTEXT_LIFETIME_SECONDS,
        rand_source: Optional[callable] = None,
    ) -> None:
        if int(auth_context_lifetime_seconds) <= 0:
            raise ValueError("auth_context_lifetime_seconds must be positive.")
        self._subscriptions = subscription_store or get_default_subscription_store()
        self._aanf = aanf_stub or get_default_aanf_stub()
        self._lifetime = int(auth_context_lifetime_seconds)
        self._rand_source = rand_source or (lambda: secrets.token_bytes(16))
        self._lock = threading.Lock()
        self._contexts: dict[str, _AuthContext] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start_ue_authentication(
        self,
        *,
        supi: str,
        sn_name: str,
    ) -> AuthenticateResponse:
        """Start a 5G AKA round trip for ``supi`` / ``sn_name``.

        Always returns a 5G HE AV; serving-network mismatches are not
        rejected at this layer because TS 33.501 leaves PLMN policing
        to the SEAF/AUSF policy plane and a stub deployment will
        typically run with one PLMN anyway. Pre-flight validation is
        the operator's job.
        """
        try:
            record = self._subscriptions.get(supi)
        except SubscriptionStoreError as error:
            raise AusfStubError(f"AUSF: unknown SUPI {supi!r}: {error}") from error

        sn_text = str(sn_name or "").strip()
        if len(sn_text) == 0:
            raise AusfStubError("AUSF: serving network name must not be empty.")

        rand = bytes(self._rand_source())
        if len(rand) != 16:
            raise AusfStubError("AUSF: rand_source must produce 16 bytes.")
        sqn = self._subscriptions.reserve_next_sqn(supi)

        vectors = milenage_vectors(record.k, record.opc, rand, sqn, record.amf)
        concealed_sqn = bytes(a ^ b for a, b in zip(sqn, vectors.ak))
        autn = concealed_sqn + record.amf + vectors.mac_a
        xres_star = derive_res_star(vectors.ck, vectors.ik, sn_text, rand, vectors.res)
        k_ausf = derive_k_ausf(vectors.ck, vectors.ik, sn_text, concealed_sqn)

        ctx_id = uuid.uuid4().hex
        ctx = _AuthContext(
            ctx_id=ctx_id,
            supi=record.supi,
            sn_name=sn_text,
            rand=rand,
            autn=autn,
            expected_xres_star=xres_star,
            k_ausf=k_ausf,
            akma_enabled=record.akma_enabled,
            mcc=record.mcc,
            mnc=record.mnc,
            routing_indicator=record.routing_indicator,
            expires_at=time.time() + self._lifetime,
        )
        with self._lock:
            self._prune_expired_locked(time.time())
            self._contexts[ctx_id] = ctx

        return AuthenticateResponse(
            ctx_id=ctx_id,
            supi=record.supi,
            sn_name=sn_text,
            av=FiveGHeAv(
                rand=rand,
                autn=autn,
                xres_star=xres_star,
                k_ausf=k_ausf,
            ),
        )

    def confirm_5g_aka(
        self,
        *,
        ctx_id: str,
        res_star: bytes,
    ) -> ConfirmResponse:
        """Verify the UE-side RES*; on success register AKMA + return KSEAF."""
        ctx = self._pop_context(ctx_id)
        supplied = bytes(res_star or b"")
        if len(supplied) != len(ctx.expected_xres_star):
            raise AuthVerificationError(
                f"AUSF: RES* length mismatch (expected {len(ctx.expected_xres_star)} bytes, "
                f"got {len(supplied)})"
            )
        if not _constant_time_equal(supplied, ctx.expected_xres_star):
            raise AuthVerificationError("AUSF: RES* mismatch \u2014 authentication failed.")

        k_seaf = derive_k_seaf(ctx.k_ausf, ctx.sn_name)
        if not ctx.akma_enabled:
            return ConfirmResponse(
                supi=ctx.supi,
                k_seaf=k_seaf,
                a_kid=None,
                k_akma=None,
            )

        k_akma = derive_k_akma(ctx.k_ausf, ctx.supi)
        a_tid = derive_a_tid(ctx.k_ausf, ctx.supi)
        a_kid = format_a_kid(
            a_tid,
            routing_indicator=ctx.routing_indicator,
            mcc=ctx.mcc,
            mnc=ctx.mnc,
        )
        self._aanf.register(supi=ctx.supi, a_kid=a_kid, k_akma=k_akma)
        return ConfirmResponse(
            supi=ctx.supi,
            k_seaf=k_seaf,
            a_kid=a_kid,
            k_akma=k_akma,
        )

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def in_flight_context_count(self) -> int:
        with self._lock:
            self._prune_expired_locked(time.time())
            return len(self._contexts)

    def cancel_context(self, ctx_id: str) -> bool:
        with self._lock:
            return self._contexts.pop(ctx_id, None) is not None

    def clear_contexts(self) -> int:
        with self._lock:
            count = len(self._contexts)
            self._contexts.clear()
            return count

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _pop_context(self, ctx_id: str) -> _AuthContext:
        text = str(ctx_id or "").strip()
        if len(text) == 0:
            raise AuthContextNotFoundError("AUSF: ctxId must not be empty.")
        now = time.time()
        with self._lock:
            self._prune_expired_locked(now)
            ctx = self._contexts.pop(text, None)
            if ctx is None:
                raise AuthContextNotFoundError(f"AUSF: unknown or expired ctxId {text!r}.")
            return ctx

    def _prune_expired_locked(self, now: float) -> None:
        stale = [ctx_id for ctx_id, ctx in self._contexts.items() if ctx.expires_at <= now]
        for ctx_id in stale:
            self._contexts.pop(ctx_id, None)


def _constant_time_equal(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for left, right in zip(a, b):
        diff |= left ^ right
    return diff == 0


# ----------------------------------------------------------------------
# Mode gating
# ----------------------------------------------------------------------


def yggdra_core_mode() -> str:
    """Return the active YGGDRASIM_5GCORE_MODE setting (lower-cased).

    Recognised values:
      * ``"off"``  (default) -- no HTTP surface, no AAnF registration
                                 from the stub AUSF. Library use only.
      * ``"stub"``           -- HTTP launcher allowed; AUSF + AAnF are
                                 a self-contained loopback test rig.

    Anything else is treated as ``"off"`` to keep the safe default.
    """
    raw = os.environ.get("YGGDRASIM_5GCORE_MODE", "off").strip().lower()
    if raw not in ("off", "stub"):
        return "off"
    return raw


_DEFAULT_STUB: Optional[AusfStub] = None


def get_default_ausf_stub() -> AusfStub:
    """Process-wide AUSF singleton (lazy)."""
    global _DEFAULT_STUB
    if _DEFAULT_STUB is None:
        _DEFAULT_STUB = AusfStub()
    return _DEFAULT_STUB


def reset_default_ausf_stub() -> None:
    global _DEFAULT_STUB
    if _DEFAULT_STUB is not None:
        _DEFAULT_STUB.clear_contexts()


__all__ = [
    "AusfStub",
    "AusfStubError",
    "AuthContextNotFoundError",
    "AuthVerificationError",
    "AuthenticateResponse",
    "ConfirmResponse",
    "FiveGHeAv",
    "DEFAULT_AUTH_CONTEXT_LIFETIME_SECONDS",
    "get_default_ausf_stub",
    "reset_default_ausf_stub",
    "yggdra_core_mode",
]
