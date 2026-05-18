# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""3GPP TS 33.535 AKMA key-derivation helpers (Annex A.2 / A.3 / A.4).

AKMA (Authentication and Key Management for Applications) reuses the
5G primary-authentication ``KAUSF`` already produced by the simulated
USIM (see :func:`SIMCARD.aka_5g.derive_k_ausf`). After a successful
5G AKA / EAP-AKA' run, both the UE and the AUSF derive:

* :func:`derive_k_akma`  -- TS 33.535 Annex A.2 (AKMA Anchor Key)
* :func:`derive_a_tid`   -- TS 33.535 Annex A.3 (AKMA Temporary UE ID)
* :func:`derive_k_af`    -- TS 33.535 Annex A.4 (Application key)
* :func:`format_a_kid`   -- TS 33.535 \u00a76.1 + TS 23.003 \u00a728.7.3
  (RFC 7542 NAI envelope around RID + A-TID + Home Network Identifier)

The KDF itself is the generic TS 33.220 Annex B.2.1 HMAC-SHA-256
construction shared with 5G AKA; we reuse :func:`SIMCARD.aka_5g.kdf`
so every AKMA derivation stays byte-identical to the AKA pipeline.

The serving-network/home-network identifier convention follows
TS 23.003 \u00a728.7.3 -- ``akma.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org``
-- and is consistent with free5GC and OAI test deployments.
"""

from __future__ import annotations

import base64

from SIMCARD.aka_5g import kdf

# TS 33.535 \u00a7A.1.2: AKMA function codes live in the range 0x80..0x82.
FC_KAKMA = 0x80
FC_A_TID = 0x81
FC_KAF = 0x82

# TS 33.535 Annex A.2 / A.3: P0 is a fixed ASCII label.
_AKMA_LABEL = b"AKMA"
_A_TID_LABEL = b"A-TID"


def derive_k_akma(k_ausf: bytes, supi: str | bytes) -> bytes:
    """TS 33.535 Annex A.2 -- AKMA Anchor Key derivation.

    ``S = FC=0x80 || "AKMA" || L0=0x0004 || SUPI || L1=len(SUPI)``,
    ``KAKMA = HMAC-SHA-256(KAUSF, S)``.

    SUPI shall be the same value as parameter P0 in TS 33.501 Annex
    A.7.0 (i.e. ``imsi-<MCC><MNC><MSIN>`` or ``nai-...``). Empty SUPIs
    are rejected because the underlying KDF requires a non-empty P1.
    """
    key = _coerce_kausf(k_ausf)
    supi_bytes = _coerce_supi(supi)
    return kdf(key, FC_KAKMA, _AKMA_LABEL, supi_bytes)


def derive_a_tid(k_ausf: bytes, supi: str | bytes) -> bytes:
    """TS 33.535 Annex A.3 -- AKMA Temporary UE Identifier.

    Output is the full 32-byte HMAC-SHA-256 result. The spec leaves
    the on-the-wire encoding of the A-TID inside the A-KID NAI to
    deployments; :func:`format_a_kid` does the conventional
    base64url-no-padding encoding used by free5GC and OAI test rigs.
    """
    key = _coerce_kausf(k_ausf)
    supi_bytes = _coerce_supi(supi)
    return kdf(key, FC_A_TID, _A_TID_LABEL, supi_bytes)


def derive_k_af(k_akma: bytes, af_id: str | bytes) -> bytes:
    """TS 33.535 Annex A.4 -- KAF derivation.

    ``AF_ID = FQDN(AF) || Ua*-security-protocol-identifier`` per
    Annex A.4 / TS 33.220 Annex H. We treat the AF_ID as one opaque
    octet string so callers can match whatever the AAnF on the other
    side produces -- string concatenation, hex-encoded protocol-id,
    etc. The caller is responsible for the join.
    """
    key = _coerce_kakma(k_akma)
    af_bytes = _coerce_af_id(af_id)
    return kdf(key, FC_KAF, af_bytes)


def format_home_network_identifier(mcc: str, mnc: str) -> str:
    """TS 23.003 \u00a728.7.3 -- AKMA realm part of an A-KID.

    Renders ``akma.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`` with the
    MNC zero-padded to three digits and the MCC validated to three
    digits. Mirrors :func:`SIMCARD.aka_5g.format_sn_name` for the
    primary-auth side.
    """
    mcc_text = "".join(ch for ch in str(mcc or "").strip() if ch.isdigit())
    mnc_text = "".join(ch for ch in str(mnc or "").strip() if ch.isdigit())
    if len(mcc_text) != 3:
        raise ValueError("MCC must be exactly 3 digits.")
    if len(mnc_text) not in (2, 3):
        raise ValueError("MNC must be 2 or 3 digits.")
    if len(mnc_text) == 2:
        mnc_text = "0" + mnc_text
    return f"akma.5gc.mnc{mnc_text}.mcc{mcc_text}.3gppnetwork.org"


def format_a_kid(
    a_tid: bytes,
    *,
    routing_indicator: str,
    mcc: str,
    mnc: str,
    encoding: str = "base64url",
) -> str:
    """Build a full A-KID NAI per TS 33.535 \u00a76.1 + TS 23.003 \u00a728.7.3.

    Shape::

        <RID>.<encoded(A-TID)>@akma.5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org

    The exact concatenation of RID and A-TID inside the NAI username
    is left undefined by TS 33.535. We default to the convention used
    by free5GC's AAnF reference implementation -- a dot-separated pair
    with the A-TID encoded as base64url (no padding) -- so test rigs
    interoperate without remapping. ``encoding="hex"`` is provided as
    an escape hatch for deployments that prefer lowercase hex.
    """
    a_tid_bytes = _coerce_a_tid(a_tid)
    rid = str(routing_indicator or "").strip()
    if len(rid) == 0:
        raise ValueError("Routing indicator must not be empty.")
    if any(ch not in "0123456789" for ch in rid):
        # TS 23.003: RID is 1..4 BCD digits; surface the misuse loudly.
        raise ValueError("Routing indicator must be 1..4 digits (0..9).")
    if len(rid) > 4:
        raise ValueError("Routing indicator must not exceed 4 digits.")
    encoded = _encode_a_tid_for_nai(a_tid_bytes, encoding=encoding)
    realm = format_home_network_identifier(mcc=mcc, mnc=mnc)
    return f"{rid}.{encoded}@{realm}"


def _encode_a_tid_for_nai(a_tid_bytes: bytes, *, encoding: str) -> str:
    style = str(encoding or "").strip().lower()
    if style == "base64url":
        return base64.urlsafe_b64encode(a_tid_bytes).rstrip(b"=").decode("ascii")
    if style == "hex":
        return a_tid_bytes.hex()
    raise ValueError(f"Unsupported A-TID encoding: {encoding!r} (use 'base64url' or 'hex').")


def _coerce_kausf(k_ausf: bytes | bytearray | memoryview | None) -> bytes:
    if k_ausf is None:
        raise ValueError("KAUSF must not be None.")
    key = bytes(k_ausf)
    if len(key) != 32:
        raise ValueError("KAUSF must be exactly 32 bytes.")
    return key


def _coerce_kakma(k_akma: bytes | bytearray | memoryview | None) -> bytes:
    if k_akma is None:
        raise ValueError("KAKMA must not be None.")
    key = bytes(k_akma)
    if len(key) != 32:
        raise ValueError("KAKMA must be exactly 32 bytes.")
    return key


def _coerce_supi(supi: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(supi, str):
        encoded = supi.encode("utf-8")
    elif isinstance(supi, (bytes, bytearray, memoryview)):
        encoded = bytes(supi)
    else:
        raise TypeError(
            "SUPI must be a UTF-8 str or bytes-like value, got "
            f"{type(supi).__name__}"
        )
    if len(encoded) == 0:
        raise ValueError("SUPI must not be empty.")
    if len(encoded) > 0xFFFF:
        raise ValueError("SUPI must be at most 65535 bytes.")
    return encoded


def _coerce_af_id(af_id: str | bytes | bytearray | memoryview) -> bytes:
    if isinstance(af_id, str):
        encoded = af_id.encode("utf-8")
    elif isinstance(af_id, (bytes, bytearray, memoryview)):
        encoded = bytes(af_id)
    else:
        raise TypeError(
            "AF_ID must be a UTF-8 str or bytes-like value, got "
            f"{type(af_id).__name__}"
        )
    if len(encoded) == 0:
        raise ValueError("AF_ID must not be empty.")
    if len(encoded) > 0xFFFF:
        raise ValueError("AF_ID must be at most 65535 bytes.")
    return encoded


def _coerce_a_tid(a_tid: bytes | bytearray | memoryview) -> bytes:
    value = bytes(a_tid or b"")
    if len(value) == 0:
        raise ValueError("A-TID must not be empty.")
    return value


__all__ = [
    "FC_KAKMA",
    "FC_A_TID",
    "FC_KAF",
    "derive_k_akma",
    "derive_a_tid",
    "derive_k_af",
    "format_home_network_identifier",
    "format_a_kid",
]
