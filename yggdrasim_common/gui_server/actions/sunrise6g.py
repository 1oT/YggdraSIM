# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SUNRISE-6G OpenSDK Command Center actions (Phase 3).

Surfaces the CAMARA Quality-on-Demand v1.0.0 and Location
Retrieval v0.4.0 API shapes the SUNRISE-6G OpenSDK exposes. Two
modes are supported, selected by ``YGGDRASIM_SUNRISE6G_MODE``:

* ``stub`` (default) -- fully in-process; no SDK / network needed.
* ``sdk``            -- delegates to ``sunrise6g_opensdk.Sdk`` with
                         a CAMARA gateway you have configured via
                         ``YGGDRASIM_SUNRISE6G_NETWORK_*`` env vars.
* ``off``            -- every action raises a clear error.

The mode is reported in every action's response so an operator
can never confuse a local stub walk-through with a live testbed.

Actions:

* ``sunrise6g.status``                  -- bridge diagnostics.
* ``sunrise6g.qod_create``              -- CAMARA POST /sessions.
* ``sunrise6g.qod_get``                 -- CAMARA GET  /sessions/{id}.
* ``sunrise6g.qod_list``                -- list live sessions (stub).
* ``sunrise6g.qod_delete``              -- CAMARA DELETE /sessions/{id}.
* ``sunrise6g.qod_expire_due``          -- prune expired sessions (stub).
* ``sunrise6g.location_set_anchor``     -- seed an anchor (stub).
* ``sunrise6g.location_retrieve``       -- CAMARA Retrieval v0.4.0.
* ``sunrise6g.location_verify``         -- CAMARA Verification v2.x.
* ``sunrise6g.location_list_anchors``   -- inspect stub anchors.
* ``sunrise6g.clear_state``             -- wipe stub state.
"""

from __future__ import annotations

from typing import Any, Optional

from .registry import ActionContext, ActionField, ActionSpec, get_registry


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _coerce_text(field_name: str, raw: Any, *, required: bool = True) -> str:
    text = str(raw or "").strip()
    if not text:
        if required:
            raise ValueError(f"{field_name}: required field is empty")
        return ""
    return text


def _coerce_int(field_name: str, raw: Any, *, default: Optional[int] = None) -> int:
    if raw in (None, ""):
        if default is None:
            raise ValueError(f"{field_name}: required numeric field is empty")
        return default
    try:
        return int(raw)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name}: expected an integer, got {raw!r}") from error


def _coerce_float(field_name: str, raw: Any, *, default: Optional[float] = None) -> float:
    if raw in (None, ""):
        if default is None:
            raise ValueError(f"{field_name}: required numeric field is empty")
        return default
    try:
        return float(raw)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name}: expected a number, got {raw!r}") from error


def _coerce_port_list(field_name: str, raw: Any) -> list[int]:
    if raw in (None, ""):
        return []
    if isinstance(raw, (list, tuple)):
        items = list(raw)
    else:
        items = [chunk.strip() for chunk in str(raw).split(",") if chunk.strip()]
    ports: list[int] = []
    for item in items:
        try:
            port = int(item)
        except (TypeError, ValueError) as error:
            raise ValueError(f"{field_name}: invalid port {item!r}") from error
        if not (0 <= port <= 65535):
            raise ValueError(f"{field_name}: port {port!r} out of [0, 65535]")
        ports.append(port)
    return ports


def _build_device_payload(
    *,
    phone_number: Any,
    nai: Any,
    ipv4_public: Any,
    ipv4_private: Any,
    ipv6: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    phone_text = _coerce_text("phone_number", phone_number, required=False)
    nai_text = _coerce_text("network_access_identifier", nai, required=False)
    ipv4_pub_text = _coerce_text("ipv4_public", ipv4_public, required=False)
    ipv4_priv_text = _coerce_text("ipv4_private", ipv4_private, required=False)
    ipv6_text = _coerce_text("ipv6", ipv6, required=False)
    if phone_text:
        payload["phoneNumber"] = phone_text
    if nai_text:
        payload["networkAccessIdentifier"] = nai_text
    if ipv4_pub_text or ipv4_priv_text:
        ipv4: dict[str, Any] = {}
        if ipv4_pub_text:
            ipv4["publicAddress"] = ipv4_pub_text
        if ipv4_priv_text:
            ipv4["privateAddress"] = ipv4_priv_text
        payload["ipv4Address"] = ipv4
    if ipv6_text:
        payload["ipv6Address"] = ipv6_text
    if not payload:
        raise ValueError(
            "device: supply at least one of phone_number, network_access_identifier, "
            "ipv4_public, ipv4_private, or ipv6."
        )
    return payload


# ----------------------------------------------------------------------
# Bridge access (test-injection friendly)
# ----------------------------------------------------------------------


_BRIDGE_OVERRIDE: Any = None


def set_bridge_for_testing(bridge: Any) -> None:
    """Inject a hand-rolled bridge for tests; pass ``None`` to revert."""
    global _BRIDGE_OVERRIDE
    _BRIDGE_OVERRIDE = bridge


def _bridge() -> Any:
    if _BRIDGE_OVERRIDE is not None:
        return _BRIDGE_OVERRIDE
    from Tools.Sunrise6G.bridge import get_default_bridge

    return get_default_bridge()


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_status(ctx: ActionContext) -> dict[str, Any]:
    bridge = _bridge()
    return bridge.diagnostics()


def _dispatch_qod_create(
    ctx: ActionContext,
    *,
    qos_profile: Any = None,
    duration_seconds: Any = None,
    application_server_ip: Any = None,
    sink_url: Any = None,
    device_phone_number: Any = None,
    device_nai: Any = None,
    device_ipv4_public: Any = None,
    device_ipv4_private: Any = None,
    device_ipv6: Any = None,
    device_ports: Any = None,
    application_server_ports: Any = None,
) -> dict[str, Any]:
    profile = _coerce_text("qos_profile", qos_profile)
    duration = _coerce_int("duration_seconds", duration_seconds, default=3_600)
    as_ip = _coerce_text("application_server_ip", application_server_ip)
    sink_text = _coerce_text("sink_url", sink_url, required=False)
    device_payload = _build_device_payload(
        phone_number=device_phone_number,
        nai=device_nai,
        ipv4_public=device_ipv4_public,
        ipv4_private=device_ipv4_private,
        ipv6=device_ipv6,
    )
    session_info: dict[str, Any] = {
        "qosProfile": profile,
        "duration": duration,
        "applicationServer": {"ipv4Address": as_ip},
        "device": device_payload,
    }
    if sink_text:
        session_info["sink"] = sink_text
    device_port_list = _coerce_port_list("device_ports", device_ports)
    if device_port_list:
        session_info["devicePorts"] = {"ports": device_port_list}
    as_port_list = _coerce_port_list("application_server_ports", application_server_ports)
    if as_port_list:
        session_info["applicationServerPorts"] = {"ports": as_port_list}

    bridge = _bridge()
    response = bridge.create_qod_session(session_info)
    return {"mode": getattr(bridge, "mode", "stub"), "session": response}


def _dispatch_qod_get(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    sid = _coerce_text("session_id", session_id)
    bridge = _bridge()
    return {
        "mode": getattr(bridge, "mode", "stub"),
        "session": bridge.get_qod_session(sid),
    }


def _dispatch_qod_list(ctx: ActionContext) -> dict[str, Any]:
    bridge = _bridge()
    sessions = bridge.list_qod_sessions()
    return {
        "mode": getattr(bridge, "mode", "stub"),
        "count": len(sessions),
        "sessions": list(sessions),
    }


def _dispatch_qod_delete(
    ctx: ActionContext,
    *,
    session_id: Any = None,
) -> dict[str, Any]:
    sid = _coerce_text("session_id", session_id)
    bridge = _bridge()
    bridge.delete_qod_session(sid)
    return {"mode": getattr(bridge, "mode", "stub"), "session_id": sid, "deleted": True}


def _dispatch_qod_expire_due(ctx: ActionContext) -> dict[str, Any]:
    from Tools.Sunrise6G.qod import get_default_qod_stub_client

    client = get_default_qod_stub_client()
    pruned = client.expire_due()
    return {"mode": "stub", "pruned": int(pruned)}


def _dispatch_location_set_anchor(
    ctx: ActionContext,
    *,
    latitude: Any = None,
    longitude: Any = None,
    radius_meters: Any = None,
    device_phone_number: Any = None,
    device_nai: Any = None,
    device_ipv4_public: Any = None,
    device_ipv4_private: Any = None,
    device_ipv6: Any = None,
) -> dict[str, Any]:
    from Tools.Sunrise6G.location import get_default_location_stub_client
    from Tools.Sunrise6G.models import DeviceIdentity

    lat = _coerce_float("latitude", latitude)
    lon = _coerce_float("longitude", longitude)
    radius = _coerce_int("radius_meters", radius_meters, default=500)
    device_payload = _build_device_payload(
        phone_number=device_phone_number,
        nai=device_nai,
        ipv4_public=device_ipv4_public,
        ipv4_private=device_ipv4_private,
        ipv6=device_ipv6,
    )
    device = DeviceIdentity.from_camara(device_payload)
    client = get_default_location_stub_client()
    fix = client.set_anchor(
        device,
        latitude=lat,
        longitude=lon,
        radius_meters=radius,
    )
    return {"mode": "stub", "anchor": fix}


def _dispatch_location_retrieve(
    ctx: ActionContext,
    *,
    max_age_seconds: Any = None,
    device_phone_number: Any = None,
    device_nai: Any = None,
    device_ipv4_public: Any = None,
    device_ipv4_private: Any = None,
    device_ipv6: Any = None,
) -> dict[str, Any]:
    from Tools.Sunrise6G.models import DeviceIdentity

    device_payload = _build_device_payload(
        phone_number=device_phone_number,
        nai=device_nai,
        ipv4_public=device_ipv4_public,
        ipv4_private=device_ipv4_private,
        ipv6=device_ipv6,
    )
    device = DeviceIdentity.from_camara(device_payload)
    max_age = _coerce_int("max_age_seconds", max_age_seconds, default=60)
    bridge = _bridge()
    location = bridge.retrieve_location(device, max_age_seconds=max_age)
    return {
        "mode": getattr(bridge, "mode", "stub"),
        "location": location,
    }


def _dispatch_location_verify(
    ctx: ActionContext,
    *,
    latitude: Any = None,
    longitude: Any = None,
    accuracy_meters: Any = None,
    max_age_seconds: Any = None,
    device_phone_number: Any = None,
    device_nai: Any = None,
    device_ipv4_public: Any = None,
    device_ipv4_private: Any = None,
    device_ipv6: Any = None,
) -> dict[str, Any]:
    from Tools.Sunrise6G.models import DeviceIdentity, LocationVerification

    device_payload = _build_device_payload(
        phone_number=device_phone_number,
        nai=device_nai,
        ipv4_public=device_ipv4_public,
        ipv4_private=device_ipv4_private,
        ipv6=device_ipv6,
    )
    device = DeviceIdentity.from_camara(device_payload)
    lat = _coerce_float("latitude", latitude)
    lon = _coerce_float("longitude", longitude)
    accuracy = _coerce_int("accuracy_meters", accuracy_meters, default=500)
    max_age = _coerce_int("max_age_seconds", max_age_seconds, default=60)
    verification = LocationVerification(
        device=device,
        latitude=lat,
        longitude=lon,
        accuracy_meters=accuracy,
        max_age_seconds=max_age,
    )
    bridge = _bridge()
    return {
        "mode": getattr(bridge, "mode", "stub"),
        "verification": bridge.verify_location(verification),
    }


def _dispatch_location_list_anchors(ctx: ActionContext) -> dict[str, Any]:
    from Tools.Sunrise6G.location import get_default_location_stub_client

    client = get_default_location_stub_client()
    anchors = client.list_anchors()
    return {"mode": "stub", "count": len(anchors), "anchors": anchors}


def _dispatch_clear_state(ctx: ActionContext) -> dict[str, Any]:
    from Tools.Sunrise6G.location import reset_default_location_stub_client
    from Tools.Sunrise6G.qod import reset_default_qod_stub_client

    reset_default_qod_stub_client()
    reset_default_location_stub_client()
    return {"mode": "stub", "cleared": True}


# ----------------------------------------------------------------------
# Common device-input fields, reused across QoD + Location forms
# ----------------------------------------------------------------------


_DEVICE_FIELDS: tuple[ActionField, ...] = (
    ActionField(
        name="device_phone_number",
        label="Device phone number (E.164)",
        kind="string",
        required=False,
        placeholder="+15558675309",
        help="Use any one of the device identifiers; CAMARA accepts any single match.",
    ),
    ActionField(
        name="device_nai",
        label="Device NAI",
        kind="string",
        required=False,
        placeholder="user@example.com",
    ),
    ActionField(
        name="device_ipv4_public",
        label="Device IPv4 (public)",
        kind="string",
        required=False,
        placeholder="203.0.113.4",
    ),
    ActionField(
        name="device_ipv4_private",
        label="Device IPv4 (private)",
        kind="string",
        required=False,
        placeholder="10.0.0.4",
    ),
    ActionField(
        name="device_ipv6",
        label="Device IPv6",
        kind="string",
        required=False,
        placeholder="2001:db8::4",
    ),
)


# ----------------------------------------------------------------------
# ActionSpecs
# ----------------------------------------------------------------------


STATUS_SPEC = ActionSpec(
    id="sunrise6g.status",
    subsystem="Sunrise6G",
    title="Bridge \u2014 status",
    description=(
        "Report the active SUNRISE-6G bridge mode (stub / sdk / off) and "
        "any backing-state counters. ``mode`` is read from "
        "YGGDRASIM_SUNRISE6G_MODE; flip it and call this again to "
        "verify the new mode is in effect."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_status,
    requires_card=False,
    tags=("sunrise6g", "camara", "diagnostics"),
)


QOD_CREATE_SPEC = ActionSpec(
    id="sunrise6g.qod_create",
    subsystem="Sunrise6G",
    title="QoD \u2014 create session",
    description=(
        "Create a CAMARA Quality-on-Demand v1.0.0 session. In stub "
        "mode the bridge mints a UUID-shaped sessionId and tracks "
        "the duration locally. In SDK mode the call is forwarded "
        "to the configured network adapter (open5gs / oai / "
        "open5gcore)."
    ),
    inputs=(
        ActionField(
            name="qos_profile",
            label="QoS profile",
            kind="enum",
            required=True,
            default="QOS_E",
            choices=["QOS_E", "QOS_S", "QOS_M", "QOS_L"],
            help=(
                "CAMARA shorthand: E=edge / S=small / M=medium / L=large. "
                "Operators map to NEF QCI/QI 1..9."
            ),
        ),
        ActionField(
            name="duration_seconds",
            label="Duration (s)",
            kind="int",
            required=False,
            default=3_600,
            min_value=1,
            max_value=86_400,
        ),
        ActionField(
            name="application_server_ip",
            label="Application server IPv4",
            kind="string",
            required=True,
            placeholder="203.0.113.10",
        ),
        ActionField(
            name="sink_url",
            label="Notification sink URL (optional)",
            kind="string",
            required=False,
            placeholder="https://example.com/qod-events",
        ),
        ActionField(
            name="device_ports",
            label="Device ports (csv)",
            kind="string",
            required=False,
            placeholder="80, 443",
        ),
        ActionField(
            name="application_server_ports",
            label="Application server ports (csv)",
            kind="string",
            required=False,
            placeholder="80, 443",
        ),
        *_DEVICE_FIELDS,
    ),
    output_kind="json",
    dispatcher=_dispatch_qod_create,
    requires_card=False,
    tags=("sunrise6g", "camara", "qod"),
)


QOD_GET_SPEC = ActionSpec(
    id="sunrise6g.qod_get",
    subsystem="Sunrise6G",
    title="QoD \u2014 get session",
    description="Fetch one CAMARA QoD session by sessionId.",
    inputs=(
        ActionField(
            name="session_id",
            label="sessionId (UUID)",
            kind="string",
            required=True,
            placeholder="9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_qod_get,
    requires_card=False,
    tags=("sunrise6g", "camara", "qod"),
)


QOD_LIST_SPEC = ActionSpec(
    id="sunrise6g.qod_list",
    subsystem="Sunrise6G",
    title="QoD \u2014 list sessions",
    description=(
        "List every live QoD session. SDK mode returns an empty "
        "list because CAMARA QoD v1.0.0 does not expose a list "
        "endpoint -- track session IDs out of band when running "
        "against a real NEF."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_qod_list,
    requires_card=False,
    tags=("sunrise6g", "camara", "qod"),
)


QOD_DELETE_SPEC = ActionSpec(
    id="sunrise6g.qod_delete",
    subsystem="Sunrise6G",
    title="QoD \u2014 delete session",
    description="Delete one CAMARA QoD session by sessionId.",
    inputs=(
        ActionField(
            name="session_id",
            label="sessionId (UUID)",
            kind="string",
            required=True,
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_qod_delete,
    requires_card=False,
    tags=("sunrise6g", "camara", "qod"),
)


QOD_EXPIRE_DUE_SPEC = ActionSpec(
    id="sunrise6g.qod_expire_due",
    subsystem="Sunrise6G",
    title="QoD \u2014 prune expired (stub)",
    description=(
        "Stub-only housekeeping: drop every QoD session whose duration "
        "has elapsed. The real CAMARA gateway prunes server-side."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_qod_expire_due,
    requires_card=False,
    tags=("sunrise6g", "camara", "qod", "stub"),
)


LOCATION_SET_ANCHOR_SPEC = ActionSpec(
    id="sunrise6g.location_set_anchor",
    subsystem="Sunrise6G",
    title="Location \u2014 set anchor (stub)",
    description=(
        "Stub-only seed: tell the in-process Location stub where a "
        "device is right now. Subsequent ``location_retrieve`` / "
        "``location_verify`` calls answer from this anchor. Has no "
        "effect in SDK mode."
    ),
    inputs=(
        ActionField(
            name="latitude",
            label="Latitude (degrees)",
            kind="string",
            required=True,
            placeholder="59.32938",
        ),
        ActionField(
            name="longitude",
            label="Longitude (degrees)",
            kind="string",
            required=True,
            placeholder="18.06871",
        ),
        ActionField(
            name="radius_meters",
            label="Anchor radius (m)",
            kind="int",
            required=False,
            default=500,
            min_value=1,
            max_value=200_000,
        ),
        *_DEVICE_FIELDS,
    ),
    output_kind="json",
    dispatcher=_dispatch_location_set_anchor,
    requires_card=False,
    tags=("sunrise6g", "camara", "location", "stub"),
)


LOCATION_RETRIEVE_SPEC = ActionSpec(
    id="sunrise6g.location_retrieve",
    subsystem="Sunrise6G",
    title="Location \u2014 retrieve",
    description=(
        "CAMARA Location-Retrieval v0.4.0 (POST /retrieve). Returns "
        "the device's last-known position as a CIRCLE area + ISO "
        "timestamp. In stub mode the answer comes from "
        "``location_set_anchor``; in SDK mode the bridge subscribes "
        "to the NEF Monitoring-Event surface and translates the "
        "polygon back."
    ),
    inputs=(
        ActionField(
            name="max_age_seconds",
            label="Max age (s)",
            kind="int",
            required=False,
            default=60,
            min_value=1,
            max_value=86_400,
        ),
        *_DEVICE_FIELDS,
    ),
    output_kind="json",
    dispatcher=_dispatch_location_retrieve,
    requires_card=False,
    tags=("sunrise6g", "camara", "location"),
)


LOCATION_VERIFY_SPEC = ActionSpec(
    id="sunrise6g.location_verify",
    subsystem="Sunrise6G",
    title="Location \u2014 verify",
    description=(
        "CAMARA Location-Verification v2.x (POST /verify). Returns "
        "MATCH / NO_MATCH / PARTIAL / UNKNOWN given a candidate point "
        "and an accuracy radius. The stub uses the haversine formula; "
        "the SDK bridge calls retrieve and computes the match locally "
        "(no SDK-level verify endpoint exists in 1.0.x)."
    ),
    inputs=(
        ActionField(
            name="latitude",
            label="Latitude (degrees)",
            kind="string",
            required=True,
            placeholder="59.32938",
        ),
        ActionField(
            name="longitude",
            label="Longitude (degrees)",
            kind="string",
            required=True,
            placeholder="18.06871",
        ),
        ActionField(
            name="accuracy_meters",
            label="Accuracy (m)",
            kind="int",
            required=False,
            default=500,
            min_value=1,
            max_value=200_000,
        ),
        ActionField(
            name="max_age_seconds",
            label="Max age (s)",
            kind="int",
            required=False,
            default=60,
            min_value=1,
            max_value=86_400,
        ),
        *_DEVICE_FIELDS,
    ),
    output_kind="json",
    dispatcher=_dispatch_location_verify,
    requires_card=False,
    tags=("sunrise6g", "camara", "location"),
)


LOCATION_LIST_ANCHORS_SPEC = ActionSpec(
    id="sunrise6g.location_list_anchors",
    subsystem="Sunrise6G",
    title="Location \u2014 list anchors (stub)",
    description="List every anchor currently held by the in-process Location stub.",
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_location_list_anchors,
    requires_card=False,
    tags=("sunrise6g", "camara", "location", "stub"),
)


CLEAR_STATE_SPEC = ActionSpec(
    id="sunrise6g.clear_state",
    subsystem="Sunrise6G",
    title="Clear stub state",
    description=(
        "Wipe every QoD session and Location anchor held by the "
        "in-process stub. SDK mode is unaffected."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_clear_state,
    requires_card=False,
    tags=("sunrise6g", "camara", "stub"),
)


get_registry().register(STATUS_SPEC)
get_registry().register(QOD_CREATE_SPEC)
get_registry().register(QOD_GET_SPEC)
get_registry().register(QOD_LIST_SPEC)
get_registry().register(QOD_DELETE_SPEC)
get_registry().register(QOD_EXPIRE_DUE_SPEC)
get_registry().register(LOCATION_SET_ANCHOR_SPEC)
get_registry().register(LOCATION_RETRIEVE_SPEC)
get_registry().register(LOCATION_VERIFY_SPEC)
get_registry().register(LOCATION_LIST_ANCHORS_SPEC)
get_registry().register(CLEAR_STATE_SPEC)
