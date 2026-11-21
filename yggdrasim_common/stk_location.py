# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Serving cell and registration a simulated terminal reports to the card.

The Location Information layouts of 3GPP TS 31.111 V19.4.0 §8.19 per access
technology (pp. 100-102), the Access Technology codes of ETSI TS 102 223
V18.3.0 §8.61 (p. 182), the PLMN coding of TS 24.008 V19.5 §10.5.1.3
(figure 10.5.3, p. 495), and the registration identities a network allocates,
in the EF_LOCI / EF_PSLOCI / EF_EPSLOCI bodies of TS 31.102 V19.5 §4.2.
"""
from __future__ import annotations

import dataclasses
import random

# ETSI TS 102 223 V18.3.0 §8.61 Access technology.
ACCESS_TECHNOLOGY_GSM = 0x00
ACCESS_TECHNOLOGY_UTRAN = 0x03
ACCESS_TECHNOLOGY_E_UTRAN = 0x08
ACCESS_TECHNOLOGY_NG_RAN = 0x0A
ACCESS_TECHNOLOGY_SATELLITE_NG_RAN = 0x0B
ACCESS_TECHNOLOGY_SATELLITE_E_UTRAN = 0x0C

ACCESS_TECHNOLOGY_NAMES = {
    ACCESS_TECHNOLOGY_GSM: "GSM",
    ACCESS_TECHNOLOGY_UTRAN: "UTRAN",
    ACCESS_TECHNOLOGY_E_UTRAN: "E-UTRAN",
    ACCESS_TECHNOLOGY_NG_RAN: "NG-RAN",
    ACCESS_TECHNOLOGY_SATELLITE_NG_RAN: "Satellite NG-RAN",
    ACCESS_TECHNOLOGY_SATELLITE_E_UTRAN: "Satellite E-UTRAN",
}

# Operator-facing spellings for the access technologies a terminal can camp on.
ACCESS_TECHNOLOGY_ALIASES = {
    "gsm": ACCESS_TECHNOLOGY_GSM,
    "geran": ACCESS_TECHNOLOGY_GSM,
    "2g": ACCESS_TECHNOLOGY_GSM,
    "utran": ACCESS_TECHNOLOGY_UTRAN,
    "umts": ACCESS_TECHNOLOGY_UTRAN,
    "3g": ACCESS_TECHNOLOGY_UTRAN,
    "eutran": ACCESS_TECHNOLOGY_E_UTRAN,
    "e-utran": ACCESS_TECHNOLOGY_E_UTRAN,
    "lte": ACCESS_TECHNOLOGY_E_UTRAN,
    "4g": ACCESS_TECHNOLOGY_E_UTRAN,
    "nr": ACCESS_TECHNOLOGY_NG_RAN,
    "ngran": ACCESS_TECHNOLOGY_NG_RAN,
    "ng-ran": ACCESS_TECHNOLOGY_NG_RAN,
    "5g": ACCESS_TECHNOLOGY_NG_RAN,
    "sat-nr": ACCESS_TECHNOLOGY_SATELLITE_NG_RAN,
    "sat-lte": ACCESS_TECHNOLOGY_SATELLITE_E_UTRAN,
}

# TS 31.102 V19.5 §4.2.17 / §4.2.23 / §4.2.91: body lengths and the update
# status coding "updated" (b3..b1 = 000) shared by all three files.
EF_LOCI_LENGTH = 11
EF_PSLOCI_LENGTH = 14
EF_EPSLOCI_LENGTH = 18
UPDATE_STATUS_UPDATED = 0x00
UPDATE_STATUS_NOT_UPDATED = 0x01


def access_technology_from_text(text: str) -> int:
    """The §8.61 code for an operator spelling (``lte``, ``nr``, ``08``, ...)."""
    token = str(text or "").strip().lower()
    if token in ACCESS_TECHNOLOGY_ALIASES:
        return ACCESS_TECHNOLOGY_ALIASES[token]
    try:
        value = int(token, 16)
    except ValueError:
        raise ValueError(
            f"access technology {text!r} is not one of "
            f"{', '.join(sorted(ACCESS_TECHNOLOGY_ALIASES))} or a §8.61 hex code"
        ) from None
    if value not in ACCESS_TECHNOLOGY_NAMES:
        raise ValueError(f"access technology '{value:02X}' is not one §8.61 assigns")
    return value


def is_e_utran(rat: int) -> bool:
    return int(rat) in (ACCESS_TECHNOLOGY_E_UTRAN, ACCESS_TECHNOLOGY_SATELLITE_E_UTRAN)


def is_ng_ran(rat: int) -> bool:
    return int(rat) in (ACCESS_TECHNOLOGY_NG_RAN, ACCESS_TECHNOLOGY_SATELLITE_NG_RAN)


def area_bits(rat: int) -> int:
    """LAC (GSM, UTRAN) and E-UTRAN TAC are 16 bits; the NG-RAN TAC is 24 (§8.19.4)."""
    return 24 if is_ng_ran(rat) else 16


def cell_bits(rat: int) -> int:
    """Cell ID 16 (GERAN, UTRAN C-id), ECI 28 (§8.19.3), NCI 36 (§8.19.4)."""
    if is_ng_ran(rat):
        return 36
    if is_e_utran(rat):
        return 28
    return 16


def plmn_bytes(mcc: str, mnc: str) -> bytes:
    """MCC/MNC in the TS 24.008 §10.5.1.3 layout: '21', 'N3 3', '21' digit pairs.

    A two-digit MNC codes its third digit as 'F'.
    """
    mcc_digits = str(mcc or "").strip()
    mnc_digits = str(mnc or "").strip()
    if len(mcc_digits) != 3 or not mcc_digits.isdigit():
        raise ValueError(f"MCC {mcc!r} is not three digits")
    if len(mnc_digits) not in (2, 3) or not mnc_digits.isdigit():
        raise ValueError(f"MNC {mnc!r} is not two or three digits")
    third = int(mnc_digits[2]) if len(mnc_digits) == 3 else 0x0F
    return bytes(
        [
            (int(mcc_digits[1]) << 4) | int(mcc_digits[0]),
            (third << 4) | int(mcc_digits[2]),
            (int(mnc_digits[1]) << 4) | int(mnc_digits[0]),
        ]
    )


def plmn_digits(plmn: bytes) -> tuple[str, str]:
    """(MCC, MNC) back out of three TS 24.008 §10.5.1.3 octets."""
    value = bytes(plmn or b"")
    if len(value) < 3:
        raise ValueError(f"PLMN needs three octets, got {len(value)}")
    mcc = f"{value[0] & 0x0F}{value[0] >> 4}{value[1] & 0x0F}"
    mnc = f"{value[2] & 0x0F}{value[2] >> 4}"
    if (value[1] >> 4) != 0x0F:
        mnc += f"{value[1] >> 4}"
    return mcc, mnc


def parse_plmn_text(text: str) -> tuple[str, str]:
    """``001/01``, ``999-99`` or ``00101`` to (MCC, MNC)."""
    token = str(text or "").strip().replace("-", "/")
    if "/" in token:
        mcc, _, mnc = token.partition("/")
    else:
        mcc, mnc = token[:3], token[3:]
    plmn_bytes(mcc, mnc)
    return mcc, mnc


def _left_aligned(value: int, bits: int, length: int) -> bytes:
    """*value* in the top *bits* of *length* bytes, the unused low bits set to 1.

    TS 31.111 V19.4.0 §8.19.3 and §8.19.4: the ECI (28 bits) and NCI (36 bits)
    start at the most significant bit of their first byte, and "the 4 least
    significant bits of byte 11 [13] shall be set to 1".
    """
    width = 8 * length
    filler = (1 << (width - bits)) - 1
    return (((int(value) & ((1 << bits) - 1)) << (width - bits)) | filler).to_bytes(length, "big")


def location_information(
    plmn: bytes,
    area: int,
    cell: int,
    rat: int,
    *,
    rnc: int = 0,
) -> bytes:
    """The Location Information value (without tag or length) for *rat*.

    - GERAN, §8.19.1: MCC/MNC || LAC || Cell ID, 7 bytes;
    - UTRAN, §8.19.2: MCC/MNC || LAC || C-id || RNC-id (12 bits, left padded), 9;
    - E-UTRAN, §8.19.3: MCC/MNC || TAC || ECI (28 bits, left aligned), 9;
    - NG-RAN, §8.19.4: MCC/MNC || TAC (3 bytes) || NCI (36 bits, left aligned), 11.
    """
    prefix = bytes(plmn)[:3]
    if is_ng_ran(rat):
        return prefix + (int(area) & 0xFFFFFF).to_bytes(3, "big") + _left_aligned(cell, 36, 5)
    if is_e_utran(rat):
        return prefix + (int(area) & 0xFFFF).to_bytes(2, "big") + _left_aligned(cell, 28, 4)
    lac_and_cell = (int(area) & 0xFFFF).to_bytes(2, "big") + (int(cell) & 0xFFFF).to_bytes(2, "big")
    if int(rat) == ACCESS_TECHNOLOGY_UTRAN:
        return prefix + lac_and_cell + (int(rnc) & 0x0FFF).to_bytes(2, "big")
    return prefix + lac_and_cell


def rejection_location_information(plmn: bytes, area: int, rat: int) -> bytes:
    """The short form the Network Rejection event carries (§8.19 notes).

    GERAN, UTRAN and E-UTRAN drop the cell and keep MCC/MNC || LAC or TAC
    (length '05'); NG-RAN keeps MCC/MNC alone (length '03').
    """
    prefix = bytes(plmn)[:3]
    if is_ng_ran(rat):
        return prefix
    return prefix + (int(area) & 0xFFFF).to_bytes(2, "big")


def parse_location_information(value: bytes, rat: int) -> tuple[bytes, int, int]:
    """(PLMN, area, cell) out of a §8.19 Location Information value for *rat*."""
    data = bytes(value or b"")
    if is_ng_ran(rat):
        if len(data) < 11:
            raise ValueError(f"NG-RAN Location Information needs 11 bytes, got {len(data)}")
        return data[:3], int.from_bytes(data[3:6], "big"), int.from_bytes(data[6:11], "big") >> 4
    if is_e_utran(rat):
        if len(data) < 9:
            raise ValueError(f"E-UTRAN Location Information needs 9 bytes, got {len(data)}")
        return data[:3], int.from_bytes(data[3:5], "big"), int.from_bytes(data[5:9], "big") >> 4
    if len(data) < 7:
        raise ValueError(f"GERAN/UTRAN Location Information needs 7 bytes, got {len(data)}")
    return data[:3], int.from_bytes(data[3:5], "big"), int.from_bytes(data[5:7], "big")


def _draw(rng: random.Random, bits: int) -> int:
    """A value of *bits* bits that is neither all zeros nor all ones ("none")."""
    ceiling = (1 << bits) - 1
    while True:
        value = rng.getrandbits(bits)
        if value not in (0, ceiling):
            return value


def random_area(rat: int, rng: random.Random) -> int:
    """A LAC or TAC for a new registration; all zeros is a deleted area (TS 24.008 §10.5.5.15)."""
    return _draw(rng, area_bits(rat))


def random_cell(rat: int, rng: random.Random) -> int:
    return _draw(rng, cell_bits(rat))


@dataclasses.dataclass(frozen=True)
class RegistrationIdentity:
    """What one registration leaves at the terminal and on the card.

    The TMSI of EF_LOCI (TS 31.102 V19.5 §4.2.17), the P-TMSI, its signature
    and the RAC of EF_PSLOCI (§4.2.23) and the GUTI of EF_EPSLOCI (§4.2.91),
    all allocated by the network that ``plmn`` names for the area ``area``.
    """

    plmn: bytes
    area: int
    tmsi: bytes
    ptmsi: bytes
    ptmsi_signature: bytes
    rac: int
    mme_group_id: bytes
    mme_code: int
    m_tmsi: bytes

    @property
    def guti(self) -> bytes:
        # TS 31.102 §4.2.91: bytes 1-12 are octets 2-13 of the EPS mobile
        # identity IE; TS 24.301 table 9.9.3.12.1 codes octet 3 as "1111",
        # even, type of identity GUTI, then MCC/MNC, MME group id, MME code and
        # M-TMSI.
        return (
            b"\x0b\xf6"
            + self.plmn[:3]
            + self.mme_group_id[:2]
            + bytes([self.mme_code & 0xFF])
            + self.m_tmsi[:4]
        )


def new_registration_identity(plmn: bytes, area: int, rng: random.Random) -> RegistrationIdentity:
    """A registration in *area* of *plmn*: every identity drawn afresh.

    A terminal that changed network was attached by another MSC, SGSN or MME
    and holds none of its old identities; none is all zeros or all ones.
    """
    return RegistrationIdentity(
        plmn=bytes(plmn)[:3],
        area=int(area),
        tmsi=_draw(rng, 32).to_bytes(4, "big"),
        ptmsi=_draw(rng, 32).to_bytes(4, "big"),
        ptmsi_signature=_draw(rng, 24).to_bytes(3, "big"),
        rac=rng.getrandbits(8),
        mme_group_id=_draw(rng, 16).to_bytes(2, "big"),
        mme_code=rng.getrandbits(8),
        m_tmsi=_draw(rng, 32).to_bytes(4, "big"),
    )


def _area_bytes(identity: RegistrationIdentity) -> bytes:
    # The files carry a two-byte LAC or TAC; an NG-RAN run keeps the low two
    # bytes of its three-byte TAC there, which is what a combined registration
    # reports in the 2G/3G/4G files.
    return (int(identity.area) & 0xFFFF).to_bytes(2, "big")


def _require_length(body: bytes, length: int, name: str, clause: str) -> bytes:
    current = bytes(body or b"")
    if len(current) != length:
        raise ValueError(f"{name} is {len(current)} byte(s); TS 31.102 {clause} defines {length}")
    return current


def loci_with_identity(body: bytes, identity: RegistrationIdentity) -> bytes:
    """EF_LOCI (§4.2.17): TMSI || LAI || RFU (kept) || location update status 'updated'."""
    current = _require_length(body, EF_LOCI_LENGTH, "EF_LOCI", "§4.2.17")
    return (
        identity.tmsi[:4]
        + identity.plmn[:3]
        + _area_bytes(identity)
        + current[9:10]
        + bytes([UPDATE_STATUS_UPDATED])
    )


def psloci_with_identity(body: bytes, identity: RegistrationIdentity) -> bytes:
    """EF_PSLOCI (§4.2.23): P-TMSI || signature || RAI (MCC/MNC, LAC, RAC) || 'updated'."""
    _require_length(body, EF_PSLOCI_LENGTH, "EF_PSLOCI", "§4.2.23")
    return (
        identity.ptmsi[:4]
        + identity.ptmsi_signature[:3]
        + identity.plmn[:3]
        + _area_bytes(identity)
        + bytes([identity.rac & 0xFF])
        + bytes([UPDATE_STATUS_UPDATED])
    )


def epsloci_with_identity(body: bytes, identity: RegistrationIdentity) -> bytes:
    """EF_EPSLOCI (§4.2.91): GUTI || last visited registered TAI || EPS update status 'updated'."""
    _require_length(body, EF_EPSLOCI_LENGTH, "EF_EPSLOCI", "§4.2.91")
    return (
        identity.guti
        + identity.plmn[:3]
        + _area_bytes(identity)
        + bytes([UPDATE_STATUS_UPDATED])
    )
