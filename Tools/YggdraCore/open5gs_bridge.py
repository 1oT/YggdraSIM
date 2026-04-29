"""Bring-Your-Own Open5GS provisioning bridge.

Glue between YggdraSIM's :class:`SubscriptionStore` and a *natively
installed* Open5GS deployment. No Docker, no orchestration -- if the
operator already has Open5GS + MongoDB running, this module pushes
subscribers into the same ``open5gs.subscribers`` collection the
WebUI / ``open5gs-dbctl`` writes to.

Components:

* :class:`Open5gsDetector` -- looks for the standard 5GC binaries on
  ``$PATH`` and (optionally, if ``pymongo`` is importable) probes
  the configured MongoDB endpoint with a short server-selection
  timeout. Returns a structured :class:`Open5gsDetection` snapshot.
* :class:`Open5gsSubscriberRepository` -- pymongo-backed wrapper
  with :meth:`provision`, :meth:`read`, :meth:`list_subscribers`,
  :meth:`remove`, and :meth:`purge_yggdrasim`. The collection
  reference is injectable so tests can pass a hand-rolled fake
  matching only the methods this module calls.

Schema reference: ``misc/db/open5gs-dbctl`` in the upstream
open5gs/open5gs repository (commit ``main`` at v0.10.x). Each
subscriber doc YggdraSIM writes is tagged with
``_yggdrasim_provisioned`` so :meth:`purge_yggdrasim` can later
remove only the docs *we* created without touching anything
WebUI-managed.

SQN handling: the Open5GS UDR/UDM tracks SQN server-side after the
first authentication; the ``security`` block in the document does
not carry it. YggdraSIM's :class:`SubscriptionStore` keeps a parallel
SQN counter for the stub AUSF, but a real Open5GS pipeline ignores
it once the subscriber is provisioned -- this is the source of
truth split that BYO mode introduces.
"""

from __future__ import annotations

import datetime as _dt
import os
import shutil
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .subscription_store import (
    SubscriptionRecord,
    SubscriptionStore,
    get_default_subscription_store,
)


# Default MongoDB endpoint Open5GS ships with -- override via env or
# the Open5gsBridgeConfig dataclass below.
DEFAULT_MONGO_URI = "mongodb://127.0.0.1:27017"
DEFAULT_DB_NAME = "open5gs"
DEFAULT_COLLECTION_NAME = "subscribers"

# Marker fields YggdraSIM writes alongside the canonical Open5GS
# subscriber schema so :meth:`purge_yggdrasim` can find its own.
PROVENANCE_TAG_FIELD = "_yggdrasim_provisioned"
PROVENANCE_SUPI_FIELD = "_yggdrasim_supi"

# Standard 5G SA control-plane binaries Open5GS ships. The detector
# reports which are present / missing; absence of any one means a
# real 5G AKA round trip won't run, but the bridge can still
# provision into MongoDB for later use.
OPEN5GS_5G_SA_BINARIES = (
    "open5gs-amfd",
    "open5gs-ausfd",
    "open5gs-udmd",
    "open5gs-udrd",
    "open5gs-smfd",
    "open5gs-upfd",
    "open5gs-nrfd",
    "open5gs-pcfd",
)


# ----------------------------------------------------------------------
# Detection
# ----------------------------------------------------------------------


@dataclass(frozen=True)
class Open5gsDetection:
    """Snapshot of what the detector sees on the host.

    ``mongo_reachable`` is ``None`` when ``pymongo`` is not installed
    (we cannot tell either way) so the GUI can offer a
    distinct "install pymongo" hint instead of a misleading
    "MongoDB is down".
    """

    binaries_present: tuple[str, ...]
    binaries_missing: tuple[str, ...]
    binary_paths: dict[str, str]
    mongo_uri: str
    mongo_reachable: Optional[bool]
    mongo_error: Optional[str]
    pymongo_available: bool

    @property
    def has_complete_5g_sa(self) -> bool:
        return len(self.binaries_missing) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "binaries_present": list(self.binaries_present),
            "binaries_missing": list(self.binaries_missing),
            "binary_paths": dict(self.binary_paths),
            "mongo_uri": self.mongo_uri,
            "mongo_reachable": self.mongo_reachable,
            "mongo_error": self.mongo_error,
            "pymongo_available": self.pymongo_available,
            "has_complete_5g_sa": self.has_complete_5g_sa,
        }


@dataclass(frozen=True)
class Open5gsBridgeConfig:
    """User-facing configuration for the bridge."""

    mongo_uri: str = DEFAULT_MONGO_URI
    db_name: str = DEFAULT_DB_NAME
    collection_name: str = DEFAULT_COLLECTION_NAME

    @classmethod
    def from_env(cls) -> "Open5gsBridgeConfig":
        return cls(
            mongo_uri=os.environ.get("YGGDRASIM_OPEN5GS_MONGO_URI", DEFAULT_MONGO_URI),
            db_name=os.environ.get("YGGDRASIM_OPEN5GS_DB", DEFAULT_DB_NAME),
            collection_name=os.environ.get(
                "YGGDRASIM_OPEN5GS_COLLECTION",
                DEFAULT_COLLECTION_NAME,
            ),
        )


class Open5gsDetector:
    """Static-detection of an Open5GS install on the host."""

    def __init__(
        self,
        *,
        config: Optional[Open5gsBridgeConfig] = None,
        binary_names: tuple[str, ...] = OPEN5GS_5G_SA_BINARIES,
        which: Any = None,
        mongo_probe: Any = None,
    ) -> None:
        self._config = config or Open5gsBridgeConfig.from_env()
        self._binary_names = tuple(binary_names)
        self._which = which or shutil.which
        self._mongo_probe = mongo_probe

    def detect(self) -> Open5gsDetection:
        binaries_present: list[str] = []
        binaries_missing: list[str] = []
        binary_paths: dict[str, str] = {}
        for name in self._binary_names:
            path = self._which(name)
            if path:
                binaries_present.append(name)
                binary_paths[name] = str(path)
            else:
                binaries_missing.append(name)
        reachable, error, pymongo_ok = self._probe_mongo()
        return Open5gsDetection(
            binaries_present=tuple(binaries_present),
            binaries_missing=tuple(binaries_missing),
            binary_paths=dict(binary_paths),
            mongo_uri=self._config.mongo_uri,
            mongo_reachable=reachable,
            mongo_error=error,
            pymongo_available=pymongo_ok,
        )

    def _probe_mongo(self) -> tuple[Optional[bool], Optional[str], bool]:
        if self._mongo_probe is not None:
            try:
                self._mongo_probe(self._config.mongo_uri)
            except Exception as error:  # noqa: BLE001 -- expose every failure
                return False, str(error), True
            return True, None, True
        try:
            from pymongo import MongoClient  # type: ignore[import]
            from pymongo.errors import PyMongoError  # type: ignore[import]
        except ImportError:
            return None, "pymongo not installed", False
        try:
            client = MongoClient(
                self._config.mongo_uri,
                serverSelectionTimeoutMS=1000,
            )
            try:
                client.admin.command("ping")
            finally:
                client.close()
        except PyMongoError as error:
            return False, str(error), True
        except Exception as error:  # noqa: BLE001 -- network errors etc.
            return False, str(error), True
        return True, None, True


# ----------------------------------------------------------------------
# Subscriber repository
# ----------------------------------------------------------------------


class Open5gsBridgeError(RuntimeError):
    """Raised on provisioning / removal failures."""


@dataclass(frozen=True)
class ProvisioningResult:
    """Result of a single :meth:`Open5gsSubscriberRepository.provision` call."""

    imsi: str
    supi: str
    matched: bool      # an existing doc was overwritten
    upserted: bool     # a fresh doc was inserted
    document: dict[str, Any] = field(default_factory=dict)

    def public_view(self) -> dict[str, Any]:
        return {
            "imsi": self.imsi,
            "supi": self.supi,
            "matched": self.matched,
            "upserted": self.upserted,
        }


class Open5gsSubscriberRepository:
    """Wraps the ``open5gs.subscribers`` MongoDB collection.

    The collection reference is injectable so tests can pass a
    light-weight fake. In production callers either pass a
    ``pymongo.collection.Collection`` directly or rely on the
    :meth:`from_config` factory which builds one from a
    :class:`Open5gsBridgeConfig`.
    """

    def __init__(self, *, collection: Any) -> None:
        if collection is None:
            raise ValueError("Collection reference must not be None.")
        self._collection = collection

    @classmethod
    def from_config(
        cls,
        config: Optional[Open5gsBridgeConfig] = None,
    ) -> "Open5gsSubscriberRepository":
        cfg = config or Open5gsBridgeConfig.from_env()
        try:
            from pymongo import MongoClient  # type: ignore[import]
        except ImportError as error:
            raise Open5gsBridgeError(
                "pymongo is required for Open5GS provisioning. "
                "Install with `pip install yggdrasim[open5gs]` or `pip install pymongo`."
            ) from error
        client = MongoClient(cfg.mongo_uri, serverSelectionTimeoutMS=2000)
        return cls(collection=client[cfg.db_name][cfg.collection_name])

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def provision(
        self,
        record: SubscriptionRecord,
        *,
        apn: str = "internet",
        sst: int = 1,
        sd: Optional[str] = None,
        session_type: int = 3,
        qos_index: int = 9,
        ambr_value_bps: int = 1_000_000_000,
    ) -> ProvisioningResult:
        """Upsert a YggdraSIM :class:`SubscriptionRecord` into Open5GS.

        Defaults match ``open5gs-dbctl add``: 1 Gbps AMBR, IPv4v6,
        QCI/QI 9, single ``internet`` APN on slice ``sst=1`` with no
        ``sd``. Override any of those via keyword arguments.
        """
        imsi = _supi_to_imsi(record.supi)
        document = _build_subscriber_document(
            record=record,
            imsi=imsi,
            apn=apn,
            sst=sst,
            sd=sd,
            session_type=session_type,
            qos_index=qos_index,
            ambr_value_bps=ambr_value_bps,
        )
        try:
            outcome = self._collection.replace_one(
                {"imsi": imsi},
                document,
                upsert=True,
            )
        except Exception as error:  # noqa: BLE001 -- pymongo errors etc.
            raise Open5gsBridgeError(
                f"Open5GS provisioning failed for IMSI {imsi!r}: {error}"
            ) from error
        matched = bool(getattr(outcome, "matched_count", 0))
        upserted = bool(getattr(outcome, "upserted_id", None))
        return ProvisioningResult(
            imsi=imsi,
            supi=record.supi,
            matched=matched,
            upserted=upserted,
            document=document,
        )

    def read(self, imsi: str) -> Optional[dict[str, Any]]:
        normalised = _coerce_imsi(imsi)
        document = self._collection.find_one({"imsi": normalised})
        if document is None:
            return None
        return _sanitise_document(document)

    def list_subscribers(
        self,
        *,
        only_yggdrasim: bool = False,
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {}
        if only_yggdrasim:
            query[PROVENANCE_TAG_FIELD] = {"$exists": True}
        cursor = self._collection.find(query)
        return [_sanitise_document(doc) for doc in cursor]

    def remove(self, imsi: str) -> bool:
        normalised = _coerce_imsi(imsi)
        try:
            outcome = self._collection.delete_one({"imsi": normalised})
        except Exception as error:  # noqa: BLE001
            raise Open5gsBridgeError(
                f"Open5GS removal failed for IMSI {normalised!r}: {error}"
            ) from error
        return bool(getattr(outcome, "deleted_count", 0))

    def purge_yggdrasim(self) -> int:
        try:
            outcome = self._collection.delete_many(
                {PROVENANCE_TAG_FIELD: {"$exists": True}},
            )
        except Exception as error:  # noqa: BLE001
            raise Open5gsBridgeError(f"Open5GS purge failed: {error}") from error
        return int(getattr(outcome, "deleted_count", 0))

    def provision_all(
        self,
        records: Iterable[SubscriptionRecord],
        **provision_kwargs: Any,
    ) -> list[ProvisioningResult]:
        return [self.provision(record, **provision_kwargs) for record in records]


# ----------------------------------------------------------------------
# Convenience top-level API
# ----------------------------------------------------------------------


def provision_default_store(
    *,
    repository: Optional[Open5gsSubscriberRepository] = None,
    subscription_store: Optional[SubscriptionStore] = None,
    only_akma_enabled: bool = False,
) -> list[ProvisioningResult]:
    """Push every record from the default subscription store to Open5GS."""
    repo = repository or Open5gsSubscriberRepository.from_config()
    store = subscription_store or get_default_subscription_store()
    records = store.list()
    if only_akma_enabled:
        records = [record for record in records if record.akma_enabled]
    return repo.provision_all(records)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _supi_to_imsi(supi: str) -> str:
    text = str(supi or "").strip()
    if text.lower().startswith("imsi-"):
        return text[5:]
    if text.lower().startswith("nai-"):
        raise Open5gsBridgeError(
            f"Open5GS provisioning is IMSI-only; refusing NAI SUPI {supi!r}."
        )
    return text


def _coerce_imsi(imsi: str) -> str:
    text = str(imsi or "").strip()
    if len(text) == 0:
        raise ValueError("IMSI must not be empty.")
    if text.lower().startswith("imsi-"):
        text = text[5:]
    if any(ch not in "0123456789" for ch in text):
        raise ValueError(f"IMSI must be digits only; got {imsi!r}.")
    return text


def _build_subscriber_document(
    *,
    record: SubscriptionRecord,
    imsi: str,
    apn: str,
    sst: int,
    sd: Optional[str],
    session_type: int,
    qos_index: int,
    ambr_value_bps: int,
) -> dict[str, Any]:
    """Construct an Open5GS-shaped subscriber document.

    Field order follows the reference ``open5gs-dbctl add`` output:
    schema_version, imsi, msisdn, slice (sst/sd/default_indicator/session),
    security (k/op/opc/amf), ambr, access_restriction_data, et al.
    """
    if int(sst) < 0 or int(sst) > 0xFF:
        raise ValueError("SST must fit in one octet (0..255).")
    if sd is not None and any(ch not in "0123456789abcdefABCDEF" for ch in str(sd)):
        raise ValueError("SD must be hex.")
    if int(session_type) not in (1, 2, 3):
        raise ValueError("session_type must be 1 (IPv4) / 2 (IPv6) / 3 (IPv4v6).")
    if int(ambr_value_bps) <= 0:
        raise ValueError("AMBR value must be positive.")

    slice_doc: dict[str, Any] = {
        "sst": int(sst),
        "default_indicator": True,
        "session": [
            {
                "name": str(apn or "internet"),
                "type": int(session_type),
                "qos": {
                    "index": int(qos_index),
                    "arp": {
                        "priority_level": 8,
                        "pre_emption_capability": 1,
                        "pre_emption_vulnerability": 2,
                    },
                },
                "ambr": {
                    "downlink": {"value": int(ambr_value_bps), "unit": 0},
                    "uplink": {"value": int(ambr_value_bps), "unit": 0},
                },
                "pcc_rule": [],
            },
        ],
    }
    if sd is not None:
        slice_doc["sd"] = str(sd).lower()

    document: dict[str, Any] = {
        "schema_version": 1,
        "imsi": imsi,
        "msisdn": [],
        "imeisv": [],
        "mme_host": [],
        "mm_realm": [],
        "purge_flag": [],
        "slice": [slice_doc],
        "security": {
            "k": record.k.hex().upper(),
            "op": None,
            "opc": record.opc.hex().upper(),
            "amf": record.amf.hex().upper(),
        },
        "ambr": {
            "downlink": {"value": int(ambr_value_bps), "unit": 0},
            "uplink": {"value": int(ambr_value_bps), "unit": 0},
        },
        "access_restriction_data": 32,
        "network_access_mode": 0,
        "subscriber_status": 0,
        "operator_determined_barring": 0,
        "subscribed_rau_tau_timer": 12,
        "__v": 0,
        # YggdraSIM provenance markers -- safe to leave in the doc;
        # Open5GS ignores unknown top-level fields.
        PROVENANCE_TAG_FIELD: _dt.datetime.now(_dt.timezone.utc).isoformat(),
        PROVENANCE_SUPI_FIELD: record.supi,
    }
    return document


def _sanitise_document(document: dict[str, Any]) -> dict[str, Any]:
    """Return a copy with key material redacted to a fingerprint.

    The GUI / HTTP layers only ever see this shape, never the full
    K / OPc. The full document is still available on the wire to
    Open5GS itself; we just don't echo it back to the operator.
    """
    sanitised = dict(document)
    sanitised.pop("_id", None)
    security = dict(document.get("security") or {})
    if "k" in security:
        security["k"] = _fingerprint(security["k"])
    if "opc" in security:
        security["opc"] = _fingerprint(security["opc"])
    sanitised["security"] = security
    return sanitised


def _fingerprint(hex_value: Any) -> str:
    text = str(hex_value or "")
    if len(text) <= 8:
        return text
    return f"{text[:4]}\u2026{text[-4:]} ({len(text) // 2} bytes)"


__all__ = [
    "DEFAULT_COLLECTION_NAME",
    "DEFAULT_DB_NAME",
    "DEFAULT_MONGO_URI",
    "OPEN5GS_5G_SA_BINARIES",
    "Open5gsBridgeConfig",
    "Open5gsBridgeError",
    "Open5gsDetection",
    "Open5gsDetector",
    "Open5gsSubscriberRepository",
    "PROVENANCE_SUPI_FIELD",
    "PROVENANCE_TAG_FIELD",
    "ProvisioningResult",
    "provision_default_store",
]
