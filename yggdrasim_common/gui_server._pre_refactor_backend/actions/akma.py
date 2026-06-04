# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""AKMA (TS 33.535) Command Center actions.

Five Phase-1b actions that surface the simulator's AKMA support
through the GUI without requiring a real 5GC:

* ``akma.derive_keys``           -- pure crypto wizard (KAUSF in,
  KAKMA / A-TID / A-KID / optional KAF out).
* ``akma.aanf_register``         -- push ``(SUPI, A-KID, KAKMA)`` into
  the in-process AAnF stub (mirrors ``Naanf_AKMA_KeyRegistration``).
* ``akma.aanf_list``             -- snapshot of live AAnF entries.
* ``akma.af_session_establish``  -- end-to-end app-session bootstrap
  (mirrors ``Naanf_AKMA_ApplicationKey_Get``).
* ``akma.aanf_clear``            -- wipe stub state.

All actions report ``mode: "stub"`` in their result so the operator
can never accidentally confuse a local crypto walk-through with a
live OpenCAPIF / AAnF round-trip.
"""

from __future__ import annotations

from typing import Any

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
# akma.derive_keys
# ----------------------------------------------------------------------


def _dispatch_derive_keys(
    ctx: ActionContext,
    *,
    k_ausf: Any = None,
    supi: Any = None,
    routing_indicator: Any = None,
    mcc: Any = None,
    mnc: Any = None,
    af_id: Any = None,
    encoding: Any = None,
) -> dict[str, Any]:
    from SIMCARD.akma import (
        derive_a_tid,
        derive_k_af,
        derive_k_akma,
        format_a_kid,
        format_home_network_identifier,
    )

    k_ausf_bytes = _decode_hex("k_ausf", k_ausf, expected_bytes=32)
    supi_text = _coerce_text("supi", supi)
    rid_text = _coerce_text("routing_indicator", routing_indicator)
    mcc_text = _coerce_text("mcc", mcc)
    mnc_text = _coerce_text("mnc", mnc)
    af_id_text = _coerce_text("af_id", af_id, required=False)
    encoding_text = str(encoding or "base64url").strip().lower()
    if encoding_text not in ("base64url", "hex"):
        raise ValueError("encoding: must be 'base64url' or 'hex'.")

    kakma = derive_k_akma(k_ausf_bytes, supi_text)
    a_tid = derive_a_tid(k_ausf_bytes, supi_text)
    a_kid = format_a_kid(
        a_tid,
        routing_indicator=rid_text,
        mcc=mcc_text,
        mnc=mnc_text,
        encoding=encoding_text,
    )
    realm = format_home_network_identifier(mcc=mcc_text, mnc=mnc_text)

    result: dict[str, Any] = {
        "mode": "stub",
        "spec": {
            "kakma": "TS 33.535 Annex A.2",
            "a_tid": "TS 33.535 Annex A.3",
            "a_kid": "TS 33.535 \u00a76.1 + TS 23.003 \u00a728.7.3",
            "k_af": "TS 33.535 Annex A.4",
        },
        "inputs": {
            "supi": supi_text,
            "routing_indicator": rid_text,
            "mcc": mcc_text,
            "mnc": mnc_text,
            "encoding": encoding_text,
        },
        "kakma_hex": kakma.hex().upper(),
        "a_tid_hex": a_tid.hex().upper(),
        "a_kid": a_kid,
        "realm": realm,
    }
    if len(af_id_text) > 0:
        k_af = derive_k_af(kakma, af_id_text)
        result["af_id"] = af_id_text
        result["k_af_hex"] = k_af.hex().upper()
    return result


# ----------------------------------------------------------------------
# akma.aanf_register
# ----------------------------------------------------------------------


def _dispatch_aanf_register(
    ctx: ActionContext,
    *,
    supi: Any = None,
    a_kid: Any = None,
    k_akma: Any = None,
    lifetime_seconds: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.aanf_stub import (
        DEFAULT_AANF_LIFETIME_SECONDS,
        get_default_aanf_stub,
    )

    supi_text = _coerce_text("supi", supi)
    a_kid_text = _coerce_text("a_kid", a_kid)
    kakma_bytes = _decode_hex("k_akma", k_akma, expected_bytes=32)
    lifetime = int(lifetime_seconds) if lifetime_seconds is not None else DEFAULT_AANF_LIFETIME_SECONDS
    if lifetime <= 0:
        raise ValueError("lifetime_seconds: must be positive.")

    stub = get_default_aanf_stub()
    entry = stub.register(
        supi=supi_text,
        a_kid=a_kid_text,
        k_akma=kakma_bytes,
        lifetime_seconds=lifetime,
    )
    return {
        "mode": "stub",
        "spec": "TS 33.535 \u00a76.1 step 4 (Naanf_AKMA_KeyRegistration)",
        "registered": {
            "supi": entry.supi,
            "a_kid": entry.a_kid,
            "registered_at": entry.registered_at,
            "expires_at": entry.expires_at,
            "lifetime_seconds": lifetime,
        },
    }


# ----------------------------------------------------------------------
# akma.aanf_list
# ----------------------------------------------------------------------


def _dispatch_aanf_list(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.aanf_stub import get_default_aanf_stub

    stub = get_default_aanf_stub()
    rows: list[dict[str, Any]] = []
    for entry in stub.snapshot():
        rows.append({
            "supi": entry.supi,
            "a_kid": entry.a_kid,
            "registered_at": entry.registered_at,
            "expires_at": entry.expires_at,
            "kakma_first8_hex": entry.k_akma[:8].hex().upper(),
        })
    return {
        "mode": "stub",
        "count": len(rows),
        "entries": rows,
    }


# ----------------------------------------------------------------------
# akma.af_session_establish
# ----------------------------------------------------------------------


def _dispatch_af_session_establish(
    ctx: ActionContext,
    *,
    a_kid: Any = None,
    af_id: Any = None,
    kaf_lifetime_seconds: Any = None,
) -> dict[str, Any]:
    from Tools.YggdraCore.aanf_stub import (
        AAnFLookupError,
        DEFAULT_KAF_LIFETIME_SECONDS,
        get_default_aanf_stub,
    )

    a_kid_text = _coerce_text("a_kid", a_kid)
    af_id_text = _coerce_text("af_id", af_id)
    lifetime = int(kaf_lifetime_seconds) if kaf_lifetime_seconds is not None else DEFAULT_KAF_LIFETIME_SECONDS
    if lifetime <= 0:
        raise ValueError("kaf_lifetime_seconds: must be positive.")

    stub = get_default_aanf_stub()
    try:
        response = stub.application_key_get(
            a_kid=a_kid_text,
            af_id=af_id_text,
            kaf_lifetime_seconds=lifetime,
        )
    except AAnFLookupError as error:
        raise ValueError(f"AAnF lookup failed: {error}") from error

    return {
        "mode": "stub",
        "spec": "TS 33.535 \u00a76.2 (Naanf_AKMA_ApplicationKey_Get)",
        "supi": response.supi,
        "a_kid": response.a_kid,
        "af_id": response.af_id,
        "k_af_hex": response.k_af.hex().upper(),
        "k_af_expires_at": response.k_af_expires_at,
    }


# ----------------------------------------------------------------------
# akma.aanf_clear
# ----------------------------------------------------------------------


def _dispatch_aanf_clear(ctx: ActionContext) -> dict[str, Any]:
    from Tools.YggdraCore.aanf_stub import get_default_aanf_stub

    stub = get_default_aanf_stub()
    cleared = stub.clear()
    return {
        "mode": "stub",
        "cleared_entries": cleared,
    }


# ----------------------------------------------------------------------
# ActionSpecs
# ----------------------------------------------------------------------


DERIVE_KEYS_SPEC = ActionSpec(
    id="akma.derive_keys",
    subsystem="AKMA",
    title="Derive AKMA keys",
    description=(
        "Run TS 33.535 Annex A.2 / A.3 / A.4 against a KAUSF you "
        "already have (typically the output of the simulator's 5G AKA "
        "wizard). Produces KAKMA, A-TID, the full A-KID NAI per "
        "TS 23.003 \u00a728.7.3, and \u2014 if AF_ID is provided \u2014 the "
        "per-AF KAF. Pure crypto, no AAnF state is touched."
    ),
    inputs=(
        ActionField(
            name="k_ausf",
            label="KAUSF (64 hex)",
            kind="hex",
            required=True,
            secret=True,
            help="32-byte primary-auth anchor key. Output of TS 33.501 Annex A.2.",
        ),
        ActionField(
            name="supi",
            label="SUPI",
            kind="string",
            required=True,
            placeholder="imsi-001010000000001",
            help="TS 33.501 Annex A.7.0 P0 -- typically imsi-<MCC><MNC><MSIN>.",
        ),
        ActionField(
            name="routing_indicator",
            label="Routing Indicator",
            kind="string",
            required=False,
            default="0",
            help="1..4 digits. From the SUCI of the active subscriber. Defaults to '0' if left empty.",
        ),
        ActionField(
            name="mcc",
            label="Home MCC",
            kind="string",
            required=True,
            default="001",
            help="3 digits. Used in the AKMA realm part of the A-KID.",
        ),
        ActionField(
            name="mnc",
            label="Home MNC",
            kind="string",
            required=True,
            default="01",
            help="2 or 3 digits. Zero-padded to 3 in the realm.",
        ),
        ActionField(
            name="af_id",
            label="AF_ID (optional)",
            kind="string",
            required=False,
            placeholder="af.example.com",
            help=(
                "FQDN of the Application Function per TS 33.535 Annex A.4. "
                "Leave empty to skip the KAF derivation."
            ),
        ),
        ActionField(
            name="encoding",
            label="A-TID encoding inside A-KID",
            kind="enum",
            required=False,
            default="base64url",
            choices=["base64url", "hex"],
            help="free5GC convention is base64url no-padding.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_derive_keys,
    requires_card=False,
    tags=("akma", "5g", "crypto", "ts-33-535"),
)


AANF_REGISTER_SPEC = ActionSpec(
    id="akma.aanf_register",
    subsystem="AKMA",
    title="AAnF \u2014 register A-KID (stub)",
    description=(
        "Push a (SUPI, A-KID, KAKMA) tuple into the in-process AAnF "
        "stub. Mirrors Naanf_AKMA_KeyRegistration as documented in "
        "TS 33.535 \u00a76.1 step 4. The simulator's AUSF-side action "
        "would do this automatically after a primary auth; this entry "
        "point is for manual walkthroughs and tests."
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
            name="a_kid",
            label="A-KID (NAI)",
            kind="string",
            required=True,
            placeholder="0.<base64url>@akma.5gc.mnc001.mcc001.3gppnetwork.org",
        ),
        ActionField(
            name="k_akma",
            label="KAKMA (64 hex)",
            kind="hex",
            required=True,
            secret=True,
            help="32-byte AKMA anchor. Output of akma.derive_keys.",
        ),
        ActionField(
            name="lifetime_seconds",
            label="Lifetime (s)",
            kind="int",
            required=False,
            default=1800,
            min_value=1,
            max_value=86400,
            help="Operator policy. Bounded by next primary auth in any case.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_aanf_register,
    requires_card=False,
    tags=("akma", "aanf", "stub", "ts-33-535"),
)


AANF_LIST_SPEC = ActionSpec(
    id="akma.aanf_list",
    subsystem="AKMA",
    title="AAnF \u2014 list registrations (stub)",
    description=(
        "Snapshot of every live (SUPI, A-KID, KAKMA) entry the AAnF "
        "stub holds right now. Expired entries are pruned on read."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_aanf_list,
    requires_card=False,
    tags=("akma", "aanf", "stub"),
)


AF_SESSION_ESTABLISH_SPEC = ActionSpec(
    id="akma.af_session_establish",
    subsystem="AKMA",
    title="AF \u2014 establish session via AAnF (stub)",
    description=(
        "Mirrors the TS 33.535 \u00a76.2 application-session bootstrap. "
        "Looks up the A-KID in the AAnF stub, derives a fresh KAF for "
        "the supplied AF_ID, and returns the per-AF key + expiration. "
        "The simulator does not execute any Ua* protocol here \u2014 "
        "the result is the key material an AF would use to start one."
    ),
    inputs=(
        ActionField(
            name="a_kid",
            label="A-KID (NAI)",
            kind="string",
            required=True,
            placeholder="0.<base64url>@akma.5gc.mnc001.mcc001.3gppnetwork.org",
        ),
        ActionField(
            name="af_id",
            label="AF_ID",
            kind="string",
            required=True,
            placeholder="af.example.com",
            help="FQDN of the Application Function (TS 33.535 Annex A.4).",
        ),
        ActionField(
            name="kaf_lifetime_seconds",
            label="KAF lifetime (s)",
            kind="int",
            required=False,
            default=1800,
            min_value=1,
            max_value=86400,
            help="Bounded by the AAnF entry's own expiration.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_af_session_establish,
    requires_card=False,
    tags=("akma", "af", "stub", "ts-33-535"),
)


AANF_CLEAR_SPEC = ActionSpec(
    id="akma.aanf_clear",
    subsystem="AKMA",
    title="AAnF \u2014 clear (stub)",
    description=(
        "Wipe every entry currently held by the AAnF stub. Use between "
        "demos or when a stale A-KID is in the way; does not affect the "
        "simulated SIMCARD or any persisted profile state."
    ),
    inputs=(),
    output_kind="json",
    dispatcher=_dispatch_aanf_clear,
    requires_card=False,
    tags=("akma", "aanf", "stub"),
)


get_registry().register(DERIVE_KEYS_SPEC)
get_registry().register(AANF_REGISTER_SPEC)
get_registry().register(AANF_LIST_SPEC)
get_registry().register(AF_SESSION_ESTABLISH_SPEC)
get_registry().register(AANF_CLEAR_SPEC)
