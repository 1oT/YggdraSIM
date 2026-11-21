# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Secured packets of ETSI TS 102 225 as a short message carries them.

The command packet header (SPI, KIc, KID, TAR, counter, padding counter) and
the response packet header with its status code, by the tables of TS 102 225
V19.0.0 clauses 5.1 and 5.2. The lengths are read the way 3GPP TS 31.115 V19
clauses 4.2 and 4.4 fix them for a short message: two octets for the packet
length, one for the header length, no header identifier. Nothing is
deciphered: with ciphering indicated, the octets after the TAR are shown as
the ciphered run they are.
"""

from __future__ import annotations

from dataclasses import dataclass

# TS 102 225 V19.0.0 section 5.1.1, first octet of the SPI: b2 b1.
SPI_INTEGRITY: dict[int, str] = {
    0: "no RC, CC or DS",
    1: "Redundancy Check",
    2: "Cryptographic Checksum",
    3: "reserved for Digital Signature",
}

# First octet, b5 b4.
SPI_COUNTER: dict[int, str] = {
    0: "no counter available",
    1: "counter available; no replay or sequence checking",
    2: "process if and only if the counter is higher than the value in the RE",
    3: "process if and only if the counter is one higher than the value in the RE",
}

# Second octet, b2 b1.
SPI_POR: dict[int, str] = {
    0: "no PoR reply to the Sending Entity",
    1: "PoR required to be sent to the Sending Entity",
    2: "PoR required only when an error has occurred",
    3: "reserved",
}

# Second octet, b4 b3.
SPI_POR_INTEGRITY: dict[int, str] = {
    0: "no RC, CC or DS applied to the PoR response",
    1: "PoR response with simple RC applied to it",
    2: "PoR response with CC applied to it",
    3: "reserved for PoR response with DS applied to it",
}

# Sections 5.1.2, 5.1.3.1: b2 b1 of the KIc, and of the KID for a Cryptographic Checksum.
KEY_ALGORITHM: dict[int, str] = {
    0: "algorithm known implicitly by both entities",
    1: "DES",
    2: "AES",
    3: "proprietary implementations",
}

# Section 5.1.2: b4 b3 of the KIc when b2 b1 say DES.
KIC_DES_MODE: dict[int, str] = {
    0: "DES (reserved, as defined in previous releases)",
    1: "triple DES in outer-CBC mode using two different keys",
    2: "triple DES in outer-CBC mode using three different keys",
    3: "DES (reserved, as defined in previous releases)",
}

# Section 5.1.3.1: b4 b3 of the KID for a Cryptographic Checksum when b2 b1 say DES.
KID_DES_MODE: dict[int, str] = {
    0: "DES (reserved, as defined in previous releases)",
    1: "triple DES in outer-CBC mode using two different keys",
    2: "triple DES in outer-CBC mode using three different keys",
    3: "reserved",
}

# Section 5.1.3.2: b2 b1 of the KID for a Redundancy Check, and b4 b3 when they say CRC.
KID_RC_ALGORITHM: dict[int, str] = {
    0: "algorithm known implicitly by both entities",
    1: "CRC",
    2: "reserved",
    3: "proprietary implementations",
}
KID_CRC_MODE: dict[int, str] = {0: "CRC 16", 1: "CRC 32", 2: "reserved", 3: "reserved"}

# TS 102 225 V19.0.0 Table 5; '0B' and '0C' are named by TS 31.115 V19 clause 7. The one table
# for every surface that names a status code: the decoder's packet rows and the SCP80 shell's PoR line.
RESPONSE_STATUS: dict[int, str] = {
    0x00: "PoR OK",
    0x01: "RC/CC/DS failed",
    0x02: "CNTR low",
    0x03: "CNTR high",
    0x04: "CNTR Blocked",
    0x05: "Ciphering error",
    0x06: "Unidentified security error",
    0x07: "Insufficient memory to process incoming message",
    0x08: "more time: the Receiving Entity needs more time to process the Command Packet",
    0x09: "TAR Unknown",
    0x0A: "Insufficient security level",
    0x0B: "Actual response data to be sent using SMS-SUBMIT",
    0x0C: "Actual response data to be sent using a ProcessUnstructuredSS-Request invoke component (SEND USSD)",
}

# SPI to PCNTR, the part of the command header that is always there (Table 1).
COMMAND_HEADER_FIXED = 13
# TAR to the status code, the part of the response header that is always there (Table 3).
RESPONSE_HEADER_FIXED = 10


@dataclass(frozen=True)
class PacketRow:
    """One element of a packet: its name, its octets in hex and what they say.

    ``bits`` marks a field inside an octet: its value is the bits as written
    in the clause (``10``), not octets.
    """

    label: str
    value: str
    meaning: str = ""
    bits: bool = False


def response_status_name(code: int) -> str:
    """The meaning of a response status code, the reserved ranges of Table 5 included.

    '0D' to 'BF' and 'FF' are reserved for future use, 'C0' to 'FE' for
    proprietary use, spelled as the table spells them.
    """
    code = int(code) & 0xFF
    if code in RESPONSE_STATUS:
        return RESPONSE_STATUS[code]
    if 0xC0 <= code <= 0xFE:
        return "Reserved for proprietary use"
    return "Reserved for future use"


def describe_spi(spi: bytes) -> list[PacketRow]:
    """The two SPI octets, one row per field (TS 102 225 V19.0.0 section 5.1.1; b6 of the second octet per TS 31.115 V19 section 4.2)."""
    if len(spi) != 2:
        raise ValueError("the SPI is two octets")
    first, second = spi[0], spi[1]
    rows = [
        PacketRow("SPI", f"{first:02X}{second:02X}"),
        PacketRow("SPI / integrity", f"{first & 0x03:02b}", SPI_INTEGRITY[first & 0x03], bits=True),
        PacketRow("SPI / ciphering", str((first >> 2) & 1), "ciphering" if first & 0x04 else "no ciphering", bits=True),
        PacketRow("SPI / counter", f"{(first >> 3) & 0x03:02b}", SPI_COUNTER[(first >> 3) & 0x03], bits=True),
        PacketRow("SPI / PoR", f"{second & 0x03:02b}", SPI_POR[second & 0x03], bits=True),
        PacketRow("SPI / PoR integrity", f"{(second >> 2) & 0x03:02b}", SPI_POR_INTEGRITY[(second >> 2) & 0x03], bits=True),
        PacketRow("SPI / PoR ciphering", str((second >> 4) & 1), "PoR response shall be ciphered" if second & 0x10 else "PoR response shall not be ciphered", bits=True),
        PacketRow("SPI / PoR transport", str((second >> 5) & 1), "PoR response sent using SMS-SUBMIT" if second & 0x20 else "PoR response sent using SMS-DELIVER-REPORT", bits=True),
    ]
    if first & 0xE0 or second & 0xC0:
        rows.append(PacketRow("SPI / reserved bits", f"{first & 0xE0:02X} {second & 0xC0:02X}", "reserved bits are set", bits=True))
    return rows


def describe_kic(value: int) -> str:
    """The KIc octet: algorithm, mode and the key indication in b8-b5 (TS 102 225 V19.0.0 section 5.1.2)."""
    algorithm, mode, keys = value & 0x03, (value >> 2) & 0x03, value >> 4
    if algorithm == 1:
        text = KIC_DES_MODE[mode]
    elif algorithm == 2:
        text = "AES in CBC mode" if mode == 0 else "AES, reserved mode"
    else:
        text = KEY_ALGORITHM[algorithm]
    return f"{text}; keys indication {keys}"


def describe_kid(value: int, integrity: int) -> str:
    """The KID octet, read by what the first SPI octet says it is for (TS 102 225 V19.0.0 sections 5.1.3.1, 5.1.3.2)."""
    algorithm, mode, keys = value & 0x03, (value >> 2) & 0x03, value >> 4
    if integrity == 1:
        text = KID_CRC_MODE[mode] if algorithm == 1 else KID_RC_ALGORITHM[algorithm]
        return f"{text}; b8-b5 {keys} (proprietary use, or the Key Version Number on a GlobalPlatform card)"
    if integrity == 2:
        if algorithm == 1:
            text = KID_DES_MODE[mode]
        elif algorithm == 2:
            text = "AES in CMAC mode" if mode == 0 else "AES, reserved mode"
        else:
            text = KEY_ALGORITHM[algorithm]
        return f"{text}; keys indication {keys}"
    return "not used: the SPI asks for no RC, CC or DS" if integrity == 0 else "for a Digital Signature; the coding is not defined"


def command_packet_rows(data: bytes) -> list[PacketRow]:
    """The elements of a command packet that starts at its length (TS 31.115 V19 section 4.2 Table 1).

    Raises ``ValueError`` when the octets do not hold a whole command header.
    """
    data = bytes(data or b"")
    if len(data) < 3 + COMMAND_HEADER_FIXED:
        raise ValueError(f"a command packet needs at least {3 + COMMAND_HEADER_FIXED} octets, {len(data)} given")
    packet_length = int.from_bytes(data[0:2], "big")
    header_length = data[2]
    if header_length < COMMAND_HEADER_FIXED:
        raise ValueError(f"the Command Header Length {header_length} is below the {COMMAND_HEADER_FIXED} octets from SPI to PCNTR")
    if 3 + header_length > len(data):
        raise ValueError(f"the Command Header Length {header_length} runs past the {len(data)} octets given")
    spi, kic, kid, tar = data[3:5], data[5], data[6], data[7:10]
    integrity = spi[0] & 0x03
    ciphered = bool(spi[0] & 0x04)
    actual = len(data) - 2
    rows = [PacketRow("CPL", f"{packet_length:04X}", f"{packet_length} octets" + ("" if packet_length == actual else f"; {actual} follow here (the packet may continue in a further short message)"))]
    rows.append(PacketRow("CHL", f"{header_length:02X}", f"{header_length} octets"))
    rows.extend(describe_spi(spi))
    rows.append(PacketRow("KIc", f"{kic:02X}", describe_kic(kic)))
    rows.append(PacketRow("KID", f"{kid:02X}", describe_kid(kid, integrity)))
    rows.append(PacketRow("TAR", tar.hex().upper()))
    rest = data[10:]
    if ciphered:
        rows.append(PacketRow("Ciphered", rest.hex().upper(), "CNTR, PCNTR, RC/CC/DS and the secured data, ciphered"))
        return rows
    check = data[16:3 + header_length]
    rows.append(PacketRow("CNTR", data[10:15].hex().upper(), str(int.from_bytes(data[10:15], "big"))))
    rows.append(PacketRow("PCNTR", f"{data[15]:02X}", f"{data[15]} padding octet(s)"))
    if check:
        rows.append(PacketRow("RC/CC/DS", check.hex().upper(), f"{len(check)} octets"))
    elif integrity:
        rows.append(PacketRow("RC/CC/DS", "", "none, although the SPI asks for one"))
    rows.append(PacketRow("Secured data", data[3 + header_length:].hex().upper(), f"{len(data) - 3 - header_length} octets"))
    return rows


def response_packet_rows(data: bytes) -> list[PacketRow]:
    """The elements of a response packet that starts at its length (TS 31.115 V19 section 4.4).

    The packet does not say whether it is ciphered: that is the command's SPI.
    Raises ``ValueError`` when the octets do not hold a whole response header.
    """
    data = bytes(data or b"")
    if len(data) < 3 + RESPONSE_HEADER_FIXED:
        raise ValueError(f"a response packet needs at least {3 + RESPONSE_HEADER_FIXED} octets, {len(data)} given")
    packet_length = int.from_bytes(data[0:2], "big")
    header_length = data[2]
    if header_length < RESPONSE_HEADER_FIXED:
        raise ValueError(f"the Response Header Length {header_length} is below the {RESPONSE_HEADER_FIXED} octets from TAR to the status code")
    if 3 + header_length > len(data):
        raise ValueError(f"the Response Header Length {header_length} runs past the {len(data)} octets given")
    actual = len(data) - 2
    status = data[12]
    check = data[13:3 + header_length]
    rows = [
        PacketRow("RPL", f"{packet_length:04X}", f"{packet_length} octets" + ("" if packet_length == actual else f"; {actual} follow here")),
        PacketRow("RHL", f"{header_length:02X}", f"{header_length} octets"),
        PacketRow("TAR", data[3:6].hex().upper()),
        PacketRow("CNTR", data[6:11].hex().upper(), str(int.from_bytes(data[6:11], "big"))),
        PacketRow("PCNTR", f"{data[11]:02X}", f"{data[11]} padding octet(s)"),
        PacketRow("Status code", f"{status:02X}", response_status_name(status)),
    ]
    if check:
        rows.append(PacketRow("RC/CC/DS", check.hex().upper(), f"{len(check)} octets"))
    rows.append(PacketRow("Additional response data", data[3 + header_length:].hex().upper(), f"{len(data) - 3 - header_length} octets"))
    return rows
