"""5G AKA and EAP-AKA' key-derivation helpers (TS 33.501 Annex A).

The USIM-side AUTHENTICATE command for 5G AKA is unchanged from
3G/EPS AKA: TS 33.501 §6.1.3.2.0 explicitly states that the USIM
returns the same (RES, CK, IK) tuple it would for an EPS-AKA*
authentication; the serving-network binding happens in the ME.
This module supplies the ME-side (or test-bench-side) derivations:

* :func:`derive_res_star` -- TS 33.501 Annex A.4 (RES* / XRES*)
* :func:`derive_k_ausf`   -- TS 33.501 Annex A.2 (KAUSF for 5G AKA)
* :func:`derive_k_seaf`   -- TS 33.501 Annex A.6 (KSEAF)
* :func:`derive_eap_aka_prime_keys` -- TS 33.402 Annex A / TS 33.501
  Annex A.3 (CK' / IK' for EAP-AKA')

All four sit on top of the generic key-derivation function defined
in TS 33.220 Annex B.2.1:

    S = FC || P0 || L0 || P1 || L1 || ... || Pn || Ln
    T = HMAC-SHA-256(Key, S)

where each ``Li`` is the length of ``Pi`` encoded as a 2-byte
big-endian unsigned integer.

Serving-network names follow TS 33.501 §6.1.1.4 (e.g.
``"5G:mnc001.mcc001.3gppnetwork.org"``) and are passed verbatim as
UTF-8 octet strings; the caller is responsible for the textual
formatting.
"""

from __future__ import annotations

import hmac
from hashlib import sha256

# Generic KDF function-code prefixes per TS 33.501 Annex A.
FC_EAP_AKA_PRIME = 0x20  # TS 33.402 Annex A / TS 33.501 Annex A.3
FC_KAUSF = 0x6A          # TS 33.501 Annex A.2
FC_RES_STAR = 0x6B       # TS 33.501 Annex A.4
FC_KSEAF = 0x6C          # TS 33.501 Annex A.6


def _coerce_bytes(value: bytes | bytearray | memoryview | None, *, label: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{label} must be a bytes-like value, got {type(value).__name__}")


def _coerce_sn_name(sn_name: str | bytes) -> bytes:
    """Accept the SN-name as either UTF-8 ``str`` or a pre-encoded
    octet string. Empty SN-names are rejected so a misconfigured
    test cannot silently produce a spec-noncompliant short vector
    (Annex A KDFs all require a non-empty P0)."""
    if isinstance(sn_name, str):
        encoded = sn_name.encode("utf-8")
    elif isinstance(sn_name, (bytes, bytearray, memoryview)):
        encoded = bytes(sn_name)
    else:
        raise TypeError(
            "sn_name must be a UTF-8 str or bytes-like value, got "
            f"{type(sn_name).__name__}"
        )
    if len(encoded) == 0:
        raise ValueError("Serving-network name (P0) must not be empty.")
    if len(encoded) > 0xFFFF:
        raise ValueError("Serving-network name (P0) must be at most 65535 bytes.")
    return encoded


def _length_prefix(value: bytes) -> bytes:
    length = len(value)
    if length > 0xFFFF:
        raise ValueError("KDF parameter length exceeds 16-bit field.")
    return length.to_bytes(2, "big")


def kdf(key: bytes, fc: int, *parameters: bytes) -> bytes:
    """Generic TS 33.220 Annex B.2.1 KDF (HMAC-SHA-256 based).

    The function-code byte ``fc`` and each parameter ``Pi`` are
    concatenated with their two-byte big-endian length prefix. The
    output is a single 32-byte HMAC-SHA-256 tag; callers slice it
    according to the specific Annex A formula they need.
    """
    fc_value = int(fc) & 0xFF
    if int(fc) != fc_value:
        raise ValueError("FC must fit in a single byte (0x00..0xFF).")
    key_bytes = _coerce_bytes(key, label="key")
    if len(key_bytes) == 0:
        raise ValueError("KDF key must not be empty.")
    if len(key_bytes) > 0xFFFF:
        raise ValueError("KDF key length exceeds 16-bit field.")
    payload = bytearray()
    payload.append(fc_value)
    for index, parameter in enumerate(parameters):
        parameter_bytes = _coerce_bytes(parameter, label=f"P{index}")
        payload.extend(parameter_bytes)
        payload.extend(_length_prefix(parameter_bytes))
    return hmac.new(key_bytes, bytes(payload), sha256).digest()


def derive_res_star(
    ck: bytes,
    ik: bytes,
    sn_name: str | bytes,
    rand: bytes,
    res: bytes,
) -> bytes:
    """TS 33.501 Annex A.4 -- RES* and XRES* derivation.

    The HMAC-SHA-256 output is 32 bytes; per the spec the rightmost
    128 bits become RES* (when the network requested an 8-byte RES,
    XRES* is constructed identically with XRES in place of RES).
    """
    ck_bytes = _coerce_bytes(ck, label="ck")
    ik_bytes = _coerce_bytes(ik, label="ik")
    rand_bytes = _coerce_bytes(rand, label="rand")
    res_bytes = _coerce_bytes(res, label="res")
    if len(ck_bytes) != 16:
        raise ValueError("CK must be exactly 16 bytes.")
    if len(ik_bytes) != 16:
        raise ValueError("IK must be exactly 16 bytes.")
    if len(rand_bytes) != 16:
        raise ValueError("RAND must be exactly 16 bytes.")
    if len(res_bytes) < 4 or len(res_bytes) > 16:
        # TS 31.102 §7.1.2.1: USIM RES is 4..16 bytes. 8 in practice.
        raise ValueError("RES must be 4..16 bytes long.")
    output = kdf(
        ck_bytes + ik_bytes,
        FC_RES_STAR,
        _coerce_sn_name(sn_name),
        rand_bytes,
        res_bytes,
    )
    return output[16:32]


def derive_k_ausf(
    ck: bytes,
    ik: bytes,
    sn_name: str | bytes,
    sqn_xor_ak: bytes,
) -> bytes:
    """TS 33.501 Annex A.2 -- KAUSF derivation for 5G AKA.

    The home network derives KAUSF from CK || IK and the
    SQN-XOR-AK token taken straight out of AUTN[0:6]. The output is
    256 bits.
    """
    ck_bytes = _coerce_bytes(ck, label="ck")
    ik_bytes = _coerce_bytes(ik, label="ik")
    sqn_ak = _coerce_bytes(sqn_xor_ak, label="sqn_xor_ak")
    if len(ck_bytes) != 16:
        raise ValueError("CK must be exactly 16 bytes.")
    if len(ik_bytes) != 16:
        raise ValueError("IK must be exactly 16 bytes.")
    if len(sqn_ak) != 6:
        raise ValueError("SQN XOR AK must be exactly 6 bytes (per TS 33.102).")
    return kdf(
        ck_bytes + ik_bytes,
        FC_KAUSF,
        _coerce_sn_name(sn_name),
        sqn_ak,
    )


def derive_k_seaf(k_ausf: bytes, sn_name: str | bytes) -> bytes:
    """TS 33.501 Annex A.6 -- KSEAF derivation.

    KSEAF is what the AUSF hands the SEAF; everything KDF'd inside
    the visited PLMN ultimately hangs off this 256-bit anchor key.
    """
    key_bytes = _coerce_bytes(k_ausf, label="k_ausf")
    if len(key_bytes) != 32:
        raise ValueError("KAUSF must be exactly 32 bytes.")
    return kdf(key_bytes, FC_KSEAF, _coerce_sn_name(sn_name))


def derive_eap_aka_prime_keys(
    ck: bytes,
    ik: bytes,
    sn_name: str | bytes,
    sqn_xor_ak: bytes,
) -> tuple[bytes, bytes]:
    """TS 33.402 Annex A / TS 33.501 Annex A.3 -- CK' || IK'.

    Used by the 5G EAP-AKA' authentication method (TS 33.501
    §6.1.3.1). The 32-byte KDF output splits in half: first 16
    bytes = CK', second 16 bytes = IK'.
    """
    ck_bytes = _coerce_bytes(ck, label="ck")
    ik_bytes = _coerce_bytes(ik, label="ik")
    sqn_ak = _coerce_bytes(sqn_xor_ak, label="sqn_xor_ak")
    if len(ck_bytes) != 16:
        raise ValueError("CK must be exactly 16 bytes.")
    if len(ik_bytes) != 16:
        raise ValueError("IK must be exactly 16 bytes.")
    if len(sqn_ak) != 6:
        raise ValueError("SQN XOR AK must be exactly 6 bytes (per TS 33.102).")
    output = kdf(
        ck_bytes + ik_bytes,
        FC_EAP_AKA_PRIME,
        _coerce_sn_name(sn_name),
        sqn_ak,
    )
    return output[:16], output[16:32]


def format_sn_name(mnc: str, mcc: str) -> str:
    """Format the canonical 5G serving-network name per TS 33.501 §6.1.1.4.

    Convenience helper for tests/integration code that hold MCC and
    MNC separately. ``mnc`` shorter than three digits is left-padded
    with ``0`` so the formatted name uses the spec's three-digit
    MNC field; the MCC is always three digits per E.212.
    """
    mcc_text = "".join(ch for ch in str(mcc or "").strip() if ch.isdigit())
    mnc_text = "".join(ch for ch in str(mnc or "").strip() if ch.isdigit())
    if len(mcc_text) != 3:
        raise ValueError("MCC must be exactly 3 digits.")
    if len(mnc_text) not in (2, 3):
        raise ValueError("MNC must be 2 or 3 digits.")
    if len(mnc_text) == 2:
        mnc_text = "0" + mnc_text
    return f"5G:mnc{mnc_text}.mcc{mcc_text}.3gppnetwork.org"


__all__ = [
    "FC_EAP_AKA_PRIME",
    "FC_KAUSF",
    "FC_RES_STAR",
    "FC_KSEAF",
    "kdf",
    "derive_res_star",
    "derive_k_ausf",
    "derive_k_seaf",
    "derive_eap_aka_prime_keys",
    "format_sn_name",
]
