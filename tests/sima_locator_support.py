# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Synthetic SAIP package for the PEStatus offset locator tests.

The package is a Profile header (with a services list and a template list), a
GenericFileManagement PE (identification 11) whose first command creates link
files in DF TELECOM and whose second creates DF GSM and an EF inside it, and a
PE-End (identification 12). Element bytes are kept so a test can find their
offsets inside the PE instead of hard-coding them.
"""

from __future__ import annotations


def tlv(tag: str, value: bytes = b"") -> bytes:
    length = len(value)
    if length < 0x80:
        encoded = bytes([length])
    elif length < 0x100:
        encoded = b"\x81" + bytes([length])
    else:
        encoded = b"\x82" + length.to_bytes(2, "big")
    return bytes.fromhex(tag) + encoded + value


def pe_header(identification: int) -> bytes:
    return tlv("A0", tlv("80") + tlv("81", bytes([identification])))


def link_fcp(fid: str, descriptor: str, arr: str, link_path: str) -> bytes:
    return tlv(
        "62",
        tlv("82", bytes.fromhex(descriptor))
        + tlv("83", bytes.fromhex(fid))
        + tlv("8B", bytes.fromhex(arr))
        + tlv("88")
        + tlv("C7", bytes.fromhex(link_path)),
    )


# usim, milenage, javacard, dfLink (ServicesList members [1], [4], [11], [19]).
SERVICES = tlv("A5", tlv("81") + tlv("84") + tlv("8B") + tlv("93"))
TEMPLATE_MF = tlv("06", bytes.fromhex("67810F010201"))
TEMPLATES = tlv("A6", TEMPLATE_MF + tlv("06", bytes.fromhex("67810F010203")))
HEADER = tlv(
    "A0",
    tlv("80", b"\x02")
    + tlv("81", b"\x03")
    + tlv("82", b"Test")
    + tlv("83", bytes.fromhex("89882012345678901232"))
    + tlv("84", b"\x00")
    + SERVICES
    + TEMPLATES,
)

SELECT_TELECOM = tlv("80", bytes.fromhex("7F10"))
ADN_LINK = link_fcp("6F3A", "4221001C", "09", "7F105F3A4F3A")
FDN_LINK = link_fcp("6F3B", "4221001C", "08", "7FFF6F3B")
SMS_LINK = link_fcp("6F3C", "422100B0", "06", "7FFF6F3C")
SELECT_MF = tlv("80")
CREATE_DF_GSM = tlv(
    "62",
    tlv("82", bytes.fromhex("7821"))
    + tlv("83", bytes.fromhex("7F20"))
    + tlv("8B", b"\x01")
    + tlv("C6", bytes.fromhex("010A")),
)
CREATE_EF_LP = tlv(
    "62",
    tlv("82", bytes.fromhex("4121"))
    + tlv("83", bytes.fromhex("6F05"))
    + tlv("8B", b"\x03")
    + tlv("80", b"\x04")
    + tlv("88"),
)
FILL_EF_LP = tlv("81", bytes.fromhex("08010403"))

GFM = tlv(
    "A1",
    pe_header(11)
    + tlv(
        "A1",
        tlv("30", SELECT_TELECOM + ADN_LINK + FDN_LINK + SMS_LINK)
        + tlv("30", SELECT_MF + CREATE_DF_GSM + CREATE_EF_LP + FILL_EF_LP),
    ),
)
END = tlv("AA", pe_header(12))
PACKAGE = HEADER + GFM + END


def span_in(pe: bytes, element: bytes) -> tuple[int, int]:
    """Start and end of ``element`` inside ``pe``; the element must occur once."""
    start = pe.find(element)
    if start < 0 or pe.find(element, start + 1) >= 0:
        raise ValueError("element must occur exactly once in the PE")
    return start, start + len(element)
