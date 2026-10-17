# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""GSM 7-bit default alphabet and the Network Name information element.

The default alphabet and its extension table are TS 23.038 v19 §6.2.1 and
§6.2.1.1; the Network Name IE is TS 24.008 v19.5 §10.5.3.5a table 10.5.94.
Callers adapt the neutral result below to their own key names, so a live-card
view and a profile view read the same octets the same way.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Iterable

# TS 23.038 v19 §6.2.1 table -- the GSM 7-bit default alphabet, code 0x00 first.
GSM7_DEFAULT_ALPHABET: Final[str] = (
    "@£$¥èéùìòÇ\nØø\rÅå"
    "Δ_ΦΓΛΩΠΨΣΘΞ\x1bÆæßÉ"
    " !\"#¤%&'()*+,-./"
    "0123456789:;<=>?"
    "¡ABCDEFGHIJKLMNO"
    "PQRSTUVWXYZÄÖÑÜ§"
    "¿abcdefghijklmno"
    "pqrstuvwxyzäöñüà"
)

# TS 23.038 v19 §6.2.1.1 -- the extension table reached through escape 0x1B.
GSM7_EXTENSION_TABLE: Final[dict[int, str]] = {
    0x0A: "\f",
    0x14: "^",
    0x28: "{",
    0x29: "}",
    0x2F: "\\",
    0x3C: "[",
    0x3D: "~",
    0x3E: "]",
    0x40: "|",
    0x65: "€",
}

# Coding scheme values of Network Name octet 3 b7-b5 (TS 24.008 table 10.5.94).
NETWORK_NAME_CODING_GSM7: Final[int] = 0
NETWORK_NAME_CODING_UCS2: Final[int] = 1

# Neutral encoding tokens; each call site maps these onto its own wording.
ENCODING_GSM7_PACKED: Final[str] = "gsm7-packed"
ENCODING_UCS2_BE: Final[str] = "ucs2-be"
ENCODING_RESERVED: Final[str] = "reserved"


def decode_gsm7_septets(septets: Iterable[int]) -> str | None:
    """Map GSM 7-bit septets to text (TS 23.038 v19 §6.2.1 and §6.2.1.1).

    An escape (0x1B) selects the extension table. Clause 6.2.1.1 has a receiver
    show the main-table character for an unassigned extension code and a space
    for a second escape; clause 6.2.1 note 1 treats a trailing escape as a
    space as well. Returns ``None`` only when a value is not a septet.
    """
    values = list(septets)
    output: list[str] = []
    index = 0
    while index < len(values):
        value = values[index]
        if not 0 <= value < 0x80:
            return None
        if value == 0x1B:
            index += 1
            if index >= len(values):
                output.append(" ")
                break
            follower = values[index]
            if not 0 <= follower < 0x80:
                return None
            if follower == 0x1B:
                output.append(" ")
            else:
                extension = GSM7_EXTENSION_TABLE.get(follower)
                if extension is None:
                    extension = GSM7_DEFAULT_ALPHABET[follower]
                output.append(extension)
        else:
            output.append(GSM7_DEFAULT_ALPHABET[value])
        index += 1
    return "".join(output)


def decode_gsm7_packed(data: bytes, spare_bits: int = 0) -> str | None:
    """Unpack a GSM 7-bit packed octet string into default-alphabet text.

    ``spare_bits`` is octet 3 b3-b1 of the Network Name IE (TS 24.008 v19.5
    table 10.5.94): 1..7 spare bits sit at the top of the last octet and are
    set to zero, except that 7 may carry the CR the network added to reach the
    octet boundary; 0 means the field carries no information, so every whole
    septet is decoded and the leftover bits are dropped.
    """
    if spare_bits not in range(8):
        return None
    total_bits = len(data) * 8
    if spare_bits == 0:
        septet_count = total_bits // 7
    else:
        useful_bits = total_bits - spare_bits
        if useful_bits < 0 or useful_bits % 7 != 0:
            return None
        septet_count = useful_bits // 7
        if data:
            spare_value = data[-1] >> (8 - spare_bits)
            cr_padding = spare_bits == 7 and spare_value == 0x0D
            if spare_value != 0 and not cr_padding:
                return None
    packed_value = int.from_bytes(data, "little")
    septets = [(packed_value >> (index * 7)) & 0x7F for index in range(septet_count)]
    return decode_gsm7_septets(septets)


def decode_gsm7_unpacked(data: bytes) -> str | None:
    """Decode a byte-per-character GSM 7-bit string (TS 23.038 v19 §6.2.1).

    Returns ``None`` when any octet has b8 set or an escape is unterminated,
    which lets an alpha-identifier reader fall through to another encoding.
    """
    output: list[str] = []
    index = 0
    while index < len(data):
        septet = data[index]
        if septet & 0x80:
            return None
        if septet == 0x1B:
            index += 1
            if index >= len(data):
                return None
            extension = GSM7_EXTENSION_TABLE.get(data[index])
            if extension is None:
                return None
            output.append(extension)
        else:
            output.append(GSM7_DEFAULT_ALPHABET[septet])
        index += 1
    return "".join(output)


@dataclass(frozen=True)
class NetworkNameIe:
    """One decoded TS 24.008 v19.5 §10.5.3.5a Network Name IE value."""

    coding_scheme: int
    add_country_initials: bool
    spare_bits: int
    encoding: str
    text: str = ""
    error: str | None = None
    note: str | None = None


def decode_network_name_ie(value: bytes) -> NetworkNameIe | None:
    """Decode a Network Name IE value (TS 24.008 v19.5 table 10.5.94).

    ``value`` starts at octet 3, so ``value[0]`` carries the extension bit,
    the coding scheme, the add-country-initials flag and the spare-bit count.
    Returns ``None`` when the extension bit is clear, which is not a Network
    Name IE at all; the caller decides what to do with those octets.
    """
    raw = bytes(value)
    if len(raw) == 0:
        return None
    header = raw[0]
    if (header & 0x80) == 0:
        return None
    coding_scheme = (header >> 4) & 0x07
    add_country_initials = bool(header & 0x08)
    spare_bits = header & 0x07
    payload = raw[1:]
    if coding_scheme == NETWORK_NAME_CODING_GSM7:
        text = decode_gsm7_packed(payload, spare_bits)
        if text is None:
            return NetworkNameIe(
                coding_scheme=coding_scheme,
                add_country_initials=add_country_initials,
                spare_bits=spare_bits,
                encoding=ENCODING_GSM7_PACKED,
                error="invalid GSM 7-bit payload or spare-bit count",
            )
        note = None
        leftover_bits = (len(payload) * 8) % 7
        if spare_bits == 0 and leftover_bits:
            note = (
                "spare-bit count not indicated; "
                f"{leftover_bits} trailing bit(s) ignored"
            )
        return NetworkNameIe(
            coding_scheme=coding_scheme,
            add_country_initials=add_country_initials,
            spare_bits=spare_bits,
            encoding=ENCODING_GSM7_PACKED,
            text=text,
            note=note,
        )
    if coding_scheme == NETWORK_NAME_CODING_UCS2:
        # Table 10.5.94: the spare-bit count only applies to coding scheme 000,
        # so for UCS-2 a non-zero count is reported and otherwise ignored.
        note = "spare-bit count ignored for UCS-2" if spare_bits else None
        if len(payload) % 2:
            return NetworkNameIe(
                coding_scheme=coding_scheme,
                add_country_initials=add_country_initials,
                spare_bits=spare_bits,
                encoding=ENCODING_UCS2_BE,
                error="UCS-2 payload has an odd byte count",
                note=note,
            )
        try:
            text = payload.decode("utf-16-be")
        except UnicodeDecodeError:
            return NetworkNameIe(
                coding_scheme=coding_scheme,
                add_country_initials=add_country_initials,
                spare_bits=spare_bits,
                encoding=ENCODING_UCS2_BE,
                error="invalid UCS-2 payload",
                note=note,
            )
        return NetworkNameIe(
            coding_scheme=coding_scheme,
            add_country_initials=add_country_initials,
            spare_bits=spare_bits,
            encoding=ENCODING_UCS2_BE,
            text=text.rstrip("\x00"),
            note=note,
        )
    return NetworkNameIe(
        coding_scheme=coding_scheme,
        add_country_initials=add_country_initials,
        spare_bits=spare_bits,
        encoding=ENCODING_RESERVED,
    )
