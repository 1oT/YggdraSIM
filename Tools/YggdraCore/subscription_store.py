"""In-memory subscriber database for the YggdraCore stub AUSF.

Holds the minimum 3GPP material the AUSF needs to answer
``Nausf_UEAuthentication_Authenticate`` for one or more test SIMs:

* ``K``      -- 16-byte subscriber key (TS 35.205)
* ``OPc``    -- 16-byte operator-variant constant
* ``AMF``    -- 2-byte authentication management field
* ``SQN``    -- 6-byte sequence number; mutated on every successful
  challenge so consecutive authentications produce fresh AUTNs
* PLMN identity ``MCC`` / ``MNC`` and the ``RID`` -- needed to build
  the serving-network name and the AKMA realm
* ``akma_enabled`` -- mirrors the AKMA indication the UDM would send
  the AUSF (TS 33.535 \u00a76.1 step 2)

The store is intentionally kept process-local; persistence belongs
in Phase 2 (BYO Open5GS / MongoDB). Mutation is serialised by a
single :class:`threading.Lock` so the FastAPI thread pool can read
and write safely.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace
from typing import Optional

from SIMCARD.aka_5g import format_sn_name
from SIMCARD.akma import format_home_network_identifier


# Default SQN increment per successful authentication. TS 33.102
# Annex C Section C.2 allows operator policy to choose any
# monotonically increasing scheme; +1 is enough for a stub.
DEFAULT_SQN_INCREMENT = 1


class SubscriptionStoreError(LookupError):
    """Raised when a SUPI is unknown or already exists on insert."""


@dataclass(frozen=True)
class SubscriptionRecord:
    """Snapshot of one subscriber the AUSF can answer for."""

    supi: str
    k: bytes
    opc: bytes
    amf: bytes
    sqn: bytes
    mcc: str
    mnc: str
    routing_indicator: str
    akma_enabled: bool

    def serving_network_name(self) -> str:
        return format_sn_name(mnc=self.mnc, mcc=self.mcc)

    def akma_realm(self) -> str:
        return format_home_network_identifier(mcc=self.mcc, mnc=self.mnc)

    def public_view(self) -> dict[str, object]:
        """Sanitised dict for GUI / HTTP responses (no key material)."""
        return {
            "supi": self.supi,
            "mcc": self.mcc,
            "mnc": self.mnc,
            "routing_indicator": self.routing_indicator,
            "amf_hex": self.amf.hex().upper(),
            "sqn_hex": self.sqn.hex().upper(),
            "akma_enabled": self.akma_enabled,
            "serving_network_name": self.serving_network_name(),
        }


class SubscriptionStore:
    """Process-local subscriber registry. Thread-safe."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: dict[str, SubscriptionRecord] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def upsert(
        self,
        *,
        supi: str,
        k: bytes,
        opc: bytes,
        amf: bytes = b"\x80\x00",
        sqn: bytes = b"\x00\x00\x00\x00\x00\x00",
        mcc: str = "001",
        mnc: str = "01",
        routing_indicator: str = "0",
        akma_enabled: bool = True,
    ) -> SubscriptionRecord:
        record = SubscriptionRecord(
            supi=self._coerce_supi(supi),
            k=self._coerce_16_bytes("K", k),
            opc=self._coerce_16_bytes("OPc", opc),
            amf=self._coerce_amf(amf),
            sqn=self._coerce_sqn(sqn),
            mcc=self._coerce_mcc(mcc),
            mnc=self._coerce_mnc(mnc),
            routing_indicator=self._coerce_rid(routing_indicator),
            akma_enabled=bool(akma_enabled),
        )
        with self._lock:
            self._records[record.supi] = record
        return record

    def delete(self, supi: str) -> bool:
        normalised = self._coerce_supi(supi)
        with self._lock:
            return self._records.pop(normalised, None) is not None

    def get(self, supi: str) -> SubscriptionRecord:
        normalised = self._coerce_supi(supi)
        with self._lock:
            record = self._records.get(normalised)
            if record is None:
                raise SubscriptionStoreError(f"unknown SUPI: {normalised!r}")
            return record

    def list(self) -> list[SubscriptionRecord]:
        with self._lock:
            return sorted(self._records.values(), key=lambda r: r.supi)

    def clear(self) -> int:
        with self._lock:
            count = len(self._records)
            self._records.clear()
            return count

    # ------------------------------------------------------------------
    # SQN management
    # ------------------------------------------------------------------

    def reserve_next_sqn(
        self,
        supi: str,
        *,
        increment: int = DEFAULT_SQN_INCREMENT,
    ) -> bytes:
        """Atomically read+bump SQN for the next authentication.

        Returns the SQN that should be used for the *current*
        Milenage challenge; the stored value is updated to the next
        SQN so the following call is naturally fresh. ``increment``
        is the operator-policy step (1, 32, etc.) and must be > 0.
        """
        if int(increment) <= 0:
            raise ValueError("SQN increment must be positive.")
        normalised = self._coerce_supi(supi)
        with self._lock:
            record = self._records.get(normalised)
            if record is None:
                raise SubscriptionStoreError(f"unknown SUPI: {normalised!r}")
            current = int.from_bytes(record.sqn, "big") + int(increment)
            if current >= 1 << 48:
                # 6-byte SQN field overflow -- TS 33.102 says the AuC
                # should refuse to wrap; in the stub we just clamp and
                # surface the misuse so a buggy test can't poison the
                # store silently.
                raise SubscriptionStoreError(
                    f"SQN counter overflow for {normalised!r}; reset the subscription."
                )
            new_sqn = current.to_bytes(6, "big")
            self._records[normalised] = replace(record, sqn=new_sqn)
            return new_sqn

    # ------------------------------------------------------------------
    # Validation helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _coerce_supi(supi: str) -> str:
        text = str(supi or "").strip()
        if len(text) == 0:
            raise ValueError("SUPI must not be empty.")
        if len(text) > 256:
            raise ValueError("SUPI must be at most 256 characters.")
        return text

    @staticmethod
    def _coerce_16_bytes(label: str, value: bytes) -> bytes:
        data = bytes(value or b"")
        if len(data) != 16:
            raise ValueError(f"{label} must be exactly 16 bytes.")
        return data

    @staticmethod
    def _coerce_amf(amf: bytes) -> bytes:
        data = bytes(amf or b"")
        if len(data) != 2:
            raise ValueError("AMF must be exactly 2 bytes.")
        return data

    @staticmethod
    def _coerce_sqn(sqn: bytes) -> bytes:
        data = bytes(sqn or b"")
        if len(data) != 6:
            raise ValueError("SQN must be exactly 6 bytes.")
        return data

    @staticmethod
    def _coerce_mcc(mcc: str) -> str:
        text = "".join(ch for ch in str(mcc or "").strip() if ch.isdigit())
        if len(text) != 3:
            raise ValueError("MCC must be exactly 3 digits.")
        return text

    @staticmethod
    def _coerce_mnc(mnc: str) -> str:
        text = "".join(ch for ch in str(mnc or "").strip() if ch.isdigit())
        if len(text) not in (2, 3):
            raise ValueError("MNC must be 2 or 3 digits.")
        return text

    @staticmethod
    def _coerce_rid(rid: str) -> str:
        text = str(rid or "").strip()
        if len(text) == 0:
            raise ValueError("Routing indicator must not be empty.")
        if any(ch not in "0123456789" for ch in text):
            raise ValueError("Routing indicator must be 1..4 digits.")
        if len(text) > 4:
            raise ValueError("Routing indicator must be at most 4 digits.")
        return text


_DEFAULT_STORE: Optional[SubscriptionStore] = None


def get_default_subscription_store() -> SubscriptionStore:
    """Process-wide store singleton used by the GUI + HTTP launcher."""
    global _DEFAULT_STORE
    if _DEFAULT_STORE is None:
        _DEFAULT_STORE = SubscriptionStore()
    return _DEFAULT_STORE


def reset_default_subscription_store() -> None:
    global _DEFAULT_STORE
    if _DEFAULT_STORE is not None:
        _DEFAULT_STORE.clear()


__all__ = [
    "DEFAULT_SQN_INCREMENT",
    "SubscriptionRecord",
    "SubscriptionStore",
    "SubscriptionStoreError",
    "get_default_subscription_store",
    "reset_default_subscription_store",
]
