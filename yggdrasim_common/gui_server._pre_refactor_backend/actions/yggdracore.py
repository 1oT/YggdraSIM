# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""YggdraCore stub-AUSF Command Center actions (Phase 1c + 2).

Surface-level glue between the Command Center and the in-process
:class:`Tools.YggdraCore.subscription_store.SubscriptionStore` +
:class:`Tools.YggdraCore.ausf_stub.AusfStub` singletons, plus the
Phase-2 BYO Open5GS bridge. Lets the operator drive the test rig
end-to-end from the GUI without ever opening a terminal:

Stub AUSF (Phase 1c):

* ``yggdracore.subscription_upsert``  -- add / update a subscriber
* ``yggdracore.subscription_list``    -- list registered subscribers
                                          (sanitised, no key material)
* ``yggdracore.subscription_delete``  -- remove one subscriber
* ``yggdracore.subscription_clear``   -- wipe the store
* ``yggdracore.status``               -- diagnostics snapshot
* ``yggdracore.clear_auth_contexts``  -- drop in-flight auth contexts

BYO Open5GS bridge (Phase 2):

* ``yggdracore.open5gs_status``       -- detect Open5GS install + Mongo
* ``yggdracore.open5gs_provision``    -- push one subscription to Mongo
* ``yggdracore.open5gs_provision_all``-- push every subscription store entry
* ``yggdracore.open5gs_read``         -- read one subscriber (sanitised)
* ``yggdracore.open5gs_remove``       -- delete one subscriber from Mongo
* ``yggdracore.open5gs_purge_yggdrasim`` -- delete only YggdraSIM-tagged docs

All actions report ``mode = yggdra_core_mode()`` so the operator can
tell at a glance whether the HTTP launcher would be live (``stub``)
or library-only (``off``); the GUI dispatchers themselves are always
available regardless of the env flag.
"""

from __future__ import annotations

from typing import Any, Optional

from .registry import ActionContext, ActionField, ActionSpec, get_registry


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _decode_hex(field_name: str, raw: Any, *, expected_bytes: int) -> bytes:
    cleaned = str(raw or "").replace(" ", "").replace(":", "").strip().upper()
    if len(cleaned) == 0:
        raise ValueError(f"{field_name}: hex string is empty")
    if len(cleaned) % 2 != 0:
        raise ValueError(f"{field_name}: hex string has odd length")
    try:
        value = bytes.fromhex(cleaned)
    except ValueError as error:
        raise ValueError(f"{field_name}: invalid hex -- {error}") from error
    if len(value) != expected_bytes:
        raise ValueError(
            f"{field_name}: must be {expected_bytes} bytes ({expected_bytes * 2} hex chars), "
            f"got {len(value)}"
        )
    return value


def _coerce_text(field_name: str, raw: Any, *, required: bool = True) -> str:
    text = str(raw or "").strip()
    if len(text) == 0:
        if required:
            raise ValueError(f"{field_name}: required field is empty")
        return ""
    return text


# ----------------------------------------------------------------------
# Subscription CRUD
# ----------------------------------------------------------------------


def _dispatch_subscription_upsert(
    ctx: ActionContext,
    *,
    supi: Any = None,
    k: Any = None,
    opc: Any = None,
    amf: Any = None,
    sqn: Any = None,
    mcc: Any = None,
    mnc: Any = None,
    routing_indicator: Any = None,
    akma_enabled: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.subscription_store import get_default_subscription_store

    supi_text = _coerce_text("supi", supi)
    k_bytes = _decode_hex("k", k, expected_bytes=16)
    opc_bytes = _decode_hex("opc", opc, expected_bytes=16)
    amf_text = _coerce_text("amf", amf, required=False) or "8000"
    amf_bytes = _decode_hex("amf", amf_text, expected_bytes=2)
    sqn_text = _coerce_text("sqn", sqn, required=False) or "000000000000"
    sqn_bytes = _decode_hex("sqn", sqn_text, expected_bytes=6)
    mcc_text = _coerce_text("mcc", mcc, required=False) or "001"
    mnc_text = _coerce_text("mnc", mnc, required=False) or "01"
    rid_text = _coerce_text("routing_indicator", routing_indicator, required=False) or "0"
    akma_flag = bool(akma_enabled) if akma_enabled is not None else True

    store = get_default_subscription_store()
    record = store.upsert(
        supi=supi_text,
        k=k_bytes,
        opc=opc_bytes,
        amf=amf_bytes,
        sqn=sqn_bytes,
        mcc=mcc_text,
        mnc=mnc_text,
        routing_indicator=rid_text,
        akma_enabled=akma_flag,
    )
    return {
        "mode": _mode(),
        "subscription": record.public_view(),
    }


def _dispatch_subscription_list(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.subscription_store import get_default_subscription_store

    store = get_default_subscription_store()
    records = [record.public_view() for record in store.list()]
    return {
        "mode": _mode(),
        "count": len(records),
        "subscriptions": records,
    }


def _dispatch_subscription_delete(
    ctx: ActionContext,
    *,
    supi: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.subscription_store import get_default_subscription_store

    supi_text = _coerce_text("supi", supi)
    store = get_default_subscription_store()
    removed = store.delete(supi_text)
    return {
        "mode": _mode(),
        "supi": supi_text,
        "removed": bool(removed),
    }


def _dispatch_subscription_clear(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.subscription_store import get_default_subscription_store

    store = get_default_subscription_store()
    cleared = store.clear()
    return {
        "mode": _mode(),
        "cleared_subscriptions": cleared,
    }


# ----------------------------------------------------------------------
# AUSF diagnostics
# ----------------------------------------------------------------------


def _dispatch_status(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.aanf_stub import get_default_aanf_stub
    from Tools.YggdraCore.ausf_stub import get_default_ausf_stub
    from Tools.YggdraCore.subscription_store import get_default_subscription_store

    return {
        "mode": _mode(),
        "subscriptions": len(get_default_subscription_store().list()),
        "aanf_entries": len(get_default_aanf_stub().snapshot()),
        "in_flight_auth_contexts": get_default_ausf_stub().in_flight_context_count(),
        "http_endpoints": [
            "POST /nausf-auth/v1/ue-authentications",
            "PUT /nausf-auth/v1/ue-authentications/{ctxId}/5g-aka-confirmation",
            "GET /yggdracore/healthz",
            "GET /yggdracore/diagnostics",
        ],
        "launcher_hint": (
            "YGGDRASIM_5GCORE_MODE=stub python -m Tools.YggdraCore.http_app"
        ),
    }


def _dispatch_clear_auth_contexts(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.ausf_stub import get_default_ausf_stub

    cleared = get_default_ausf_stub().clear_contexts()
    return {
        "mode": _mode(),
        "cleared_contexts": cleared,
    }


def _mode() -> str:
    from Tools.YggdraCore.ausf_stub import yggdra_core_mode

    return yggdra_core_mode()


# ----------------------------------------------------------------------
# ActionSpecs
# ----------------------------------------------------------------------


SUBSCRIPTION_UPSERT_SPEC = ActionSpec(
    id="yggdracore.subscription_upsert",
    subsystem="YggdraCore",
    title="Subscription \u2014 add or update",
    description=(
        "Insert or replace a subscriber in the in-memory store backing "
        "the YggdraCore stub AUSF. Mirrors what ``mongo`` would hold "
        "in a Phase-2 BYO Open5GS deployment. K and OPc are 16-byte "
        "hex; AMF defaults to 8000, SQN to 000000000000, MCC/MNC to "
        "001/01, RID to 0, AKMA to enabled."
    ),
    inputs=(
        ActionField(
            name="supi",
            label="SUPI",
            kind="string",
            required=True,
            placeholder="imsi-001010000000001",
        ),
        ActionField(
            name="k",
            label="K (32 hex)",
            kind="hex",
            required=True,
            secret=True,
            help="16-byte subscriber key.",
        ),
        ActionField(
            name="opc",
            label="OPc (32 hex)",
            kind="hex",
            required=True,
            secret=True,
            help="16-byte operator-variant constant.",
        ),
        ActionField(
            name="amf",
            label="AMF (4 hex)",
            kind="hex",
            required=False,
            default="8000",
            help="2-byte authentication management field.",
        ),
        ActionField(
            name="sqn",
            label="SQN (12 hex)",
            kind="hex",
            required=False,
            default="000000000000",
            help="6-byte initial sequence number.",
        ),
        ActionField(
            name="mcc",
            label="Home MCC",
            kind="string",
            required=False,
            default="001",
        ),
        ActionField(
            name="mnc",
            label="Home MNC",
            kind="string",
            required=False,
            default="01",
        ),
        ActionField(
            name="routing_indicator",
            label="Routing Indicator",
            kind="string",
            required=False,
            default="0",
        ),
        ActionField(
            name="akma_enabled",
            label="AKMA enabled",
            kind="bool",
            required=False,
            default=True,
            help="Set to false to disable AKMA registration on successful auth.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_subscription_upsert,
    requires_card=False,
    tags=("yggdracore", "subscription", "stub"),
)


SUBSCRIPTION_LIST_SPEC = ActionSpec(
    id="yggdracore.subscription_list",
    subsystem="YggdraCore",
    title="Subscription \u2014 list",
    description=(
        "List every subscriber currently held by the YggdraCore "
        "subscription store. K / OPc are intentionally redacted; the "
        "diagnostic surface only shows SUPI, MCC, MNC, AMF, SQN, RID, "
        "AKMA-enabled flag, and the formatted serving network name."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_subscription_list,
    requires_card=False,
    tags=("yggdracore", "subscription", "stub"),
)


SUBSCRIPTION_DELETE_SPEC = ActionSpec(
    id="yggdracore.subscription_delete",
    subsystem="YggdraCore",
    title="Subscription \u2014 delete",
    description="Remove a single SUPI from the subscription store.",
    inputs=(
        ActionField(
            name="supi",
            label="SUPI",
            kind="string",
            required=True,
            placeholder="imsi-001010000000001",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_subscription_delete,
    requires_card=False,
    tags=("yggdracore", "subscription", "stub"),
)


SUBSCRIPTION_CLEAR_SPEC = ActionSpec(
    id="yggdracore.subscription_clear",
    subsystem="YggdraCore",
    title="Subscription \u2014 clear",
    description="Wipe every subscriber from the store. Use between demos.",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_subscription_clear,
    requires_card=False,
    tags=("yggdracore", "subscription", "stub"),
)


STATUS_SPEC = ActionSpec(
    id="yggdracore.status",
    subsystem="YggdraCore",
    title="Status",
    description=(
        "Diagnostics snapshot of the in-process stub AUSF: active "
        "mode, subscription count, AAnF entry count, in-flight auth "
        "contexts, the HTTP endpoint surface, and the one-liner that "
        "starts the loopback launcher."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_status,
    requires_card=False,
    tags=("yggdracore", "diagnostics"),
)


CLEAR_AUTH_CONTEXTS_SPEC = ActionSpec(
    id="yggdracore.clear_auth_contexts",
    subsystem="YggdraCore",
    title="Clear in-flight auth contexts",
    description=(
        "Wipe every in-flight 5G AKA context the stub AUSF is "
        "tracking. Useful after a misbehaving test rig has left "
        "stale ctxIds dangling; does not affect the subscription "
        "store or the AAnF state."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_clear_auth_contexts,
    requires_card=False,
    tags=("yggdracore", "diagnostics"),
)


get_registry().register(SUBSCRIPTION_UPSERT_SPEC)
get_registry().register(SUBSCRIPTION_LIST_SPEC)
get_registry().register(SUBSCRIPTION_DELETE_SPEC)
get_registry().register(SUBSCRIPTION_CLEAR_SPEC)
get_registry().register(STATUS_SPEC)
get_registry().register(CLEAR_AUTH_CONTEXTS_SPEC)


# ----------------------------------------------------------------------
# Phase 2 -- BYO Open5GS bridge
# ----------------------------------------------------------------------


_OPEN5GS_REPOSITORY_OVERRIDE: Any = None
_OPEN5GS_DETECTOR_OVERRIDE: Any = None


def set_open5gs_repository_for_testing(repository: Any) -> None:
    """Inject a hand-rolled or mongomock-backed repository for tests."""
    global _OPEN5GS_REPOSITORY_OVERRIDE
    _OPEN5GS_REPOSITORY_OVERRIDE = repository


def set_open5gs_detector_for_testing(detector: Any) -> None:
    """Inject a fake :class:`Open5gsDetector` for tests."""
    global _OPEN5GS_DETECTOR_OVERRIDE
    _OPEN5GS_DETECTOR_OVERRIDE = detector


def _open5gs_repository() -> Any:
    if _OPEN5GS_REPOSITORY_OVERRIDE is not None:
        return _OPEN5GS_REPOSITORY_OVERRIDE
    from Tools.YggdraCore.open5gs_bridge import Open5gsSubscriberRepository

    return Open5gsSubscriberRepository.from_config()


def _open5gs_detector() -> Any:
    if _OPEN5GS_DETECTOR_OVERRIDE is not None:
        return _OPEN5GS_DETECTOR_OVERRIDE
    from Tools.YggdraCore.open5gs_bridge import Open5gsDetector

    return Open5gsDetector()


def _dispatch_open5gs_status(ctx: ActionContext) -> dict[str, Any]:
    detector = _open5gs_detector()
    snapshot = detector.detect().to_dict()
    snapshot["mode"] = _mode()
    return snapshot


def _dispatch_open5gs_provision(
    ctx: ActionContext,
    *,
    supi: Any = None,
    apn: Any = None,
    sst: Any = None,
    sd: Any = None,
    session_type: Any = None,
    qos_index: Any = None,
    ambr_value_bps: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.open5gs_bridge import Open5gsBridgeError
    from Tools.YggdraCore.subscription_store import (
        SubscriptionStoreError,
        get_default_subscription_store,
    )

    supi_text = _coerce_text("supi", supi)
    apn_text = _coerce_text("apn", apn, required=False) or "internet"
    sst_value = int(sst) if sst not in (None, "") else 1
    sd_text: Optional[str] = _coerce_text("sd", sd, required=False) or None
    session_type_value = int(session_type) if session_type not in (None, "") else 3
    qos_index_value = int(qos_index) if qos_index not in (None, "") else 9
    ambr_value = (
        int(ambr_value_bps) if ambr_value_bps not in (None, "") else 1_000_000_000
    )

    store = get_default_subscription_store()
    try:
        record = store.get(supi_text)
    except SubscriptionStoreError as error:
        raise ValueError(str(error)) from error

    repository = _open5gs_repository()
    try:
        result = repository.provision(
            record,
            apn=apn_text,
            sst=sst_value,
            sd=sd_text,
            session_type=session_type_value,
            qos_index=qos_index_value,
            ambr_value_bps=ambr_value,
        )
    except Open5gsBridgeError as error:
        raise RuntimeError(str(error)) from error
    return {"mode": _mode(), **result.public_view()}


def _dispatch_open5gs_provision_all(
    ctx: ActionContext,
    *,
    only_akma_enabled: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.open5gs_bridge import Open5gsBridgeError, provision_default_store

    only_akma = bool(only_akma_enabled) if only_akma_enabled is not None else False
    repository = _open5gs_repository()
    try:
        results = provision_default_store(
            repository=repository,
            only_akma_enabled=only_akma,
        )
    except Open5gsBridgeError as error:
        raise RuntimeError(str(error)) from error
    return {
        "mode": _mode(),
        "count": len(results),
        "results": [r.public_view() for r in results],
        "only_akma_enabled": only_akma,
    }


def _dispatch_open5gs_read(
    ctx: ActionContext,
    *,
    imsi: Any = None,
) -> dict[str, Any]:
    imsi_text = _coerce_text("imsi", imsi)
    repository = _open5gs_repository()
    document = repository.read(imsi_text)
    return {
        "mode": _mode(),
        "imsi": imsi_text,
        "found": document is not None,
        "subscriber": document,
    }


def _dispatch_open5gs_remove(
    ctx: ActionContext,
    *,
    imsi: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.open5gs_bridge import Open5gsBridgeError

    imsi_text = _coerce_text("imsi", imsi)
    repository = _open5gs_repository()
    try:
        removed = repository.remove(imsi_text)
    except Open5gsBridgeError as error:
        raise RuntimeError(str(error)) from error
    return {
        "mode": _mode(),
        "imsi": imsi_text,
        "removed": bool(removed),
    }


def _dispatch_open5gs_purge_yggdrasim(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.open5gs_bridge import Open5gsBridgeError

    repository = _open5gs_repository()
    try:
        purged = repository.purge_yggdrasim()
    except Open5gsBridgeError as error:
        raise RuntimeError(str(error)) from error
    return {
        "mode": _mode(),
        "purged": int(purged),
    }


OPEN5GS_STATUS_SPEC = ActionSpec(
    id="yggdracore.open5gs_status",
    subsystem="YggdraCore",
    title="Open5GS \u2014 detect installation",
    description=(
        "Static-detect a natively-installed Open5GS deployment: which "
        "control-plane binaries are on $PATH and whether the configured "
        "MongoDB endpoint is reachable. ``mongo_reachable`` is null when "
        "pymongo is not installed -- install with "
        "``pip install yggdrasim[open5gs]`` to enable the probe."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_open5gs_status,
    requires_card=False,
    tags=("yggdracore", "open5gs", "byo"),
)


OPEN5GS_PROVISION_SPEC = ActionSpec(
    id="yggdracore.open5gs_provision",
    subsystem="YggdraCore",
    title="Open5GS \u2014 provision one subscriber",
    description=(
        "Push a single subscription store entry into the Open5GS "
        "MongoDB ``subscribers`` collection. The doc shape mirrors "
        "what ``open5gs-dbctl add`` writes: schema_version=1, slice "
        "with default APN, AMBR 1 Gbps, security {k, op=null, opc, "
        "amf}. The provenance tag ``_yggdrasim_provisioned`` lets a "
        "later ``purge_yggdrasim`` action remove only YggdraSIM-managed "
        "docs without touching WebUI subscribers."
    ),
    inputs=(
        ActionField(
            name="supi",
            label="SUPI",
            kind="string",
            required=True,
            placeholder="imsi-001010000000001",
            help="Must already exist in the YggdraCore subscription store.",
        ),
        ActionField(
            name="apn",
            label="APN / DNN",
            kind="string",
            required=False,
            default="internet",
        ),
        ActionField(
            name="sst",
            label="Slice SST",
            kind="int",
            required=False,
            default=1,
        ),
        ActionField(
            name="sd",
            label="Slice SD (hex, optional)",
            kind="string",
            required=False,
            placeholder="ffffff",
        ),
        ActionField(
            name="session_type",
            label="Session Type (1=IPv4, 2=IPv6, 3=IPv4v6)",
            kind="int",
            required=False,
            default=3,
        ),
        ActionField(
            name="qos_index",
            label="QoS Index (5QI)",
            kind="int",
            required=False,
            default=9,
        ),
        ActionField(
            name="ambr_value_bps",
            label="AMBR (bps, both directions)",
            kind="int",
            required=False,
            default=1_000_000_000,
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open5gs_provision,
    requires_card=False,
    tags=("yggdracore", "open5gs", "byo"),
)


OPEN5GS_PROVISION_ALL_SPEC = ActionSpec(
    id="yggdracore.open5gs_provision_all",
    subsystem="YggdraCore",
    title="Open5GS \u2014 provision all subscriptions",
    description=(
        "Push every entry from the YggdraCore subscription store into "
        "the Open5GS Mongo collection using default slice/AMBR. Set "
        "``only_akma_enabled`` to limit the push to AKMA-flagged "
        "subscribers."
    ),
    inputs=(
        ActionField(
            name="only_akma_enabled",
            label="Only AKMA-enabled subscribers",
            kind="bool",
            required=False,
            default=False,
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open5gs_provision_all,
    requires_card=False,
    tags=("yggdracore", "open5gs", "byo"),
)


OPEN5GS_READ_SPEC = ActionSpec(
    id="yggdracore.open5gs_read",
    subsystem="YggdraCore",
    title="Open5GS \u2014 read subscriber",
    description=(
        "Fetch one subscriber by IMSI. K and OPc are redacted to a "
        "fingerprint of the form ``ABCD\u2026EFGH (16 bytes)`` -- the "
        "full key material is never echoed back through the GUI."
    ),
    inputs=(
        ActionField(
            name="imsi",
            label="IMSI",
            kind="string",
            required=True,
            placeholder="001010000000001",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open5gs_read,
    requires_card=False,
    tags=("yggdracore", "open5gs", "byo"),
)


OPEN5GS_REMOVE_SPEC = ActionSpec(
    id="yggdracore.open5gs_remove",
    subsystem="YggdraCore",
    title="Open5GS \u2014 remove subscriber",
    description=(
        "Delete one subscriber from Open5GS Mongo by IMSI. Use this "
        "for surgical removal when the subscriber is *not* tagged as "
        "YggdraSIM-managed; ``purge_yggdrasim`` is safer for our own."
    ),
    inputs=(
        ActionField(
            name="imsi",
            label="IMSI",
            kind="string",
            required=True,
            placeholder="001010000000001",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_open5gs_remove,
    requires_card=False,
    tags=("yggdracore", "open5gs", "byo"),
)


OPEN5GS_PURGE_YGGDRASIM_SPEC = ActionSpec(
    id="yggdracore.open5gs_purge_yggdrasim",
    subsystem="YggdraCore",
    title="Open5GS \u2014 purge YggdraSIM-managed docs",
    description=(
        "Delete every subscriber doc carrying the YggdraSIM "
        "provenance tag. WebUI / dbctl-managed docs are untouched. "
        "Use between demo runs."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_open5gs_purge_yggdrasim,
    requires_card=False,
    tags=("yggdracore", "open5gs", "byo"),
)


get_registry().register(OPEN5GS_STATUS_SPEC)
get_registry().register(OPEN5GS_PROVISION_SPEC)
get_registry().register(OPEN5GS_PROVISION_ALL_SPEC)
get_registry().register(OPEN5GS_READ_SPEC)
get_registry().register(OPEN5GS_REMOVE_SPEC)
get_registry().register(OPEN5GS_PURGE_YGGDRASIM_SPEC)
