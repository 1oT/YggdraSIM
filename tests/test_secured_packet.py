# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Secured packets of TS 102 225 as TS 31.115 carries them in a short message.

The tables are pinned row by row against TS 102 225 V19.0.0 clauses 5.1.1 to
5.1.3 and Table 5, and TS 31.115 V19 clauses 4.2 and 7; the packet readers are
run on whole packets and on the boundary inputs a decoder has to survive.
"""
from __future__ import annotations

import pytest

from yggdrasim_common import secured_packet as packet

# SPI '0000', KIc '00', KID '00', TAR 'B00010', CNTR 1, PCNTR 0, then a seven-byte command.
PLAIN_COMMAND = "0015" + "0D" + "0000" + "00" + "00" + "B00010" + "0000000001" + "00" + "A0A40000023F00"


def _rows(rows: list[packet.PacketRow]) -> dict[str, packet.PacketRow]:
    return {row.label: row for row in rows}


def test_spi_tables_hold_every_coding_of_the_clause() -> None:
    """TS 102 225 V19.0.0 section 5.1.1: four codings for each two-bit field, the reserved ones named as such."""
    assert packet.SPI_INTEGRITY == {
        0: "no RC, CC or DS", 1: "Redundancy Check", 2: "Cryptographic Checksum", 3: "reserved for Digital Signature",
    }
    assert sorted(packet.SPI_COUNTER) == [0, 1, 2, 3]
    assert "one higher than the value in the RE" in packet.SPI_COUNTER[3]
    assert "higher than the value in the RE" in packet.SPI_COUNTER[2] and "one higher" not in packet.SPI_COUNTER[2]
    assert sorted(packet.SPI_POR) == [0, 1, 2, 3] and packet.SPI_POR[3] == "reserved"
    assert sorted(packet.SPI_POR_INTEGRITY) == [0, 1, 2, 3]
    # Every value of both octets reads without an error, and the reserved bits are reported.
    for first in range(256):
        rows = packet.describe_spi(bytes([first, first ^ 0xFF]))
        assert rows[0].label == "SPI" and len(rows) in (8, 9)
    assert _rows(packet.describe_spi(b"\xE0\x00"))["SPI / reserved bits"].meaning == "reserved bits are set"
    # A field inside an octet is marked, so a reader never shows its bits as an octet.
    plain = packet.describe_spi(b"\x12\x21")
    assert [row.label for row in plain if not row.bits] == ["SPI"] and _rows(plain)["SPI / counter"].value == "10"
    # b6 of the second octet is the one TS 31.115 V19 section 4.2 defines for a short message.
    assert _rows(packet.describe_spi(b"\x00\x20"))["SPI / PoR transport"].meaning == "PoR response sent using SMS-SUBMIT"
    assert _rows(packet.describe_spi(b"\x00\x00"))["SPI / PoR transport"].meaning == "PoR response sent using SMS-DELIVER-REPORT"
    for bad in (b"", b"\x00", b"\x00\x00\x00"):
        with pytest.raises(ValueError):
            packet.describe_spi(bad)


def test_kic_and_kid_codings() -> None:
    """Sections 5.1.2, 5.1.3.1, 5.1.3.2: algorithm in b2 b1, mode in b4 b3, key indication in b8-b5."""
    assert packet.KEY_ALGORITHM == {
        0: "algorithm known implicitly by both entities", 1: "DES", 2: "AES", 3: "proprietary implementations",
    }
    assert packet.KIC_DES_MODE[1] == "triple DES in outer-CBC mode using two different keys"
    assert packet.KIC_DES_MODE[2] == "triple DES in outer-CBC mode using three different keys"
    assert packet.KIC_DES_MODE[0] == packet.KIC_DES_MODE[3] and packet.KID_DES_MODE[3] == "reserved"
    assert packet.KID_RC_ALGORITHM == {
        0: "algorithm known implicitly by both entities", 1: "CRC", 2: "reserved", 3: "proprietary implementations",
    }
    assert packet.KID_CRC_MODE == {0: "CRC 16", 1: "CRC 32", 2: "reserved", 3: "reserved"}
    assert packet.describe_kic(0x12) == "AES in CBC mode; keys indication 1"
    assert packet.describe_kic(0x25) == "triple DES in outer-CBC mode using two different keys; keys indication 2"
    assert packet.describe_kic(0x16) == "AES, reserved mode; keys indication 1"
    assert packet.describe_kid(0x12, 2) == "AES in CMAC mode; keys indication 1"
    assert packet.describe_kid(0x15, 1).startswith("CRC 32; b8-b5 1")
    assert packet.describe_kid(0x12, 0) == "not used: the SPI asks for no RC, CC or DS"
    for value in range(256):
        for integrity in range(4):
            assert packet.describe_kid(value, integrity) and packet.describe_kic(value)


def test_response_status_codes_are_table_5_whole() -> None:
    """TS 102 225 V19.0.0 Table 5: '00' to '0A', the two codes of TS 31.115 V19 clause 7, then the reserved ranges."""
    assert sorted(packet.RESPONSE_STATUS) == list(range(0x0D))
    assert packet.RESPONSE_STATUS[0x00] == "PoR OK" and packet.RESPONSE_STATUS[0x0A] == "Insufficient security level"
    assert packet.RESPONSE_STATUS[0x0B] == "Actual response data to be sent using SMS-SUBMIT"
    assert packet.RESPONSE_STATUS[0x0C].startswith("Actual response data to be sent using a ProcessUnstructuredSS-Request")
    assert packet.RESPONSE_STATUS[0x04] == "CNTR Blocked" and packet.RESPONSE_STATUS[0x09] == "TAR Unknown"
    assert packet.RESPONSE_STATUS[0x08].startswith("more time") and packet.RESPONSE_STATUS[0x0C].endswith("(SEND USSD)")
    for code in range(0x0D, 0xC0):
        assert packet.response_status_name(code) == "Reserved for future use"
    for code in range(0xC0, 0xFF):
        assert packet.response_status_name(code) == "Reserved for proprietary use"
    assert packet.response_status_name(0xFF) == "Reserved for future use"


def test_the_ota_shell_names_a_status_code_from_the_same_table() -> None:
    """The SCP80 transport keeps no table of its own: every code reads as the shared one says."""
    from SCP80 import transport

    assert not hasattr(transport, "_POR_STATUS_MEANINGS")
    for code in range(256):
        assert transport.Transport._por_status_meaning(code) == packet.response_status_name(code)
    decoded = transport.Transport._por_status_meaning(0x09)
    assert decoded == "TAR Unknown"


def test_command_packet_rows() -> None:
    rows = _rows(packet.command_packet_rows(bytes.fromhex(PLAIN_COMMAND)))
    assert rows["CPL"].meaning == "21 octets" and rows["CHL"].meaning == "13 octets"
    # The KID is there whatever the SPI says, so the TAR sits behind it.
    assert rows["TAR"].value == "B00010" and rows["CNTR"].meaning == "1"
    assert rows["Secured data"].value == "A0A40000023F00"
    assert "RC/CC/DS" not in rows

    # A cryptographic checksum of eight octets: the header length grows by them.
    signed = "001D" + "15" + "1221" + "12" + "12" + "000001" + "0000000002" + "00" + "1122334455667788" + "A0A40000023F00"
    rows = _rows(packet.command_packet_rows(bytes.fromhex(signed)))
    assert rows["RC/CC/DS"].value == "1122334455667788" and rows["KID"].meaning == "AES in CMAC mode; keys indication 1"
    assert rows["SPI / counter"].meaning.startswith("process if and only if the counter is higher")
    assert rows["SPI / PoR"].meaning == "PoR required to be sent to the Sending Entity"

    # With ciphering indicated, the octets after the TAR stay one ciphered run.
    ciphered = _rows(packet.command_packet_rows(bytes.fromhex("0015" + "0D" + "0400" + "12" + "00" + "B00010" + "AA" * 14)))
    assert ciphered["Ciphered"].value == "AA" * 14 and "CNTR" not in ciphered
    # A packet that continues in a further short message says so instead of failing.
    short = _rows(packet.command_packet_rows(bytes.fromhex("0040" + PLAIN_COMMAND[4:])))
    assert "the packet may continue in a further short message" in short["CPL"].meaning


def test_response_packet_rows() -> None:
    response = "000C" + "0A" + "B00010" + "0000000001" + "00" + "00" + "029000"
    rows = _rows(packet.response_packet_rows(bytes.fromhex(response)))
    assert rows["Status code"].meaning == "PoR OK" and rows["TAR"].value == "B00010"
    assert rows["Additional response data"].value == "029000"
    failed = _rows(packet.response_packet_rows(bytes.fromhex("000A" + "0A" + "B00010" + "0000000001" + "00" + "09")))
    assert failed["Status code"].meaning == "TAR Unknown" and failed["Additional response data"].value == ""


@pytest.mark.parametrize("reader", [packet.command_packet_rows, packet.response_packet_rows])
def test_packet_readers_refuse_what_is_not_a_whole_header(reader) -> None:
    for raw in (b"", b"\x00", b"\x00\x15", bytes.fromhex("00150D"), bytes.fromhex("0015FF") + bytes(20), bytes.fromhex("001505") + bytes(20)):
        with pytest.raises(ValueError):
            reader(raw)
    with pytest.raises(ValueError):
        reader(None)  # type: ignore[arg-type]
