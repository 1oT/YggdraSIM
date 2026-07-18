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

"""SCP03 core utilities: byte conversion, BCD helpers, and TLV construction."""
from typing import Any, Dict, List, Union

class HexUtils :
    """Static helpers for byte manipulation."""
    @staticmethod 
    def to_bytes(
        data: Union[str, bytes, bytearray, memoryview, List[int]],
    ) -> bytes:
        if isinstance(data, bytes):
            return data
        if isinstance(data, (bytearray, memoryview)):
            return bytes(data)
        if isinstance(data, list):
            if any(
                isinstance(item, bool) or not isinstance(item, int)
                for item in data
            ):
                raise TypeError("Byte lists must contain integers.")
            return bytes(data)
        if not isinstance(data, str):
            raise TypeError(
                "Hex input must be a string, bytes-like object, or byte list."
            )

        clean = (
            "".join(data.split())
            .replace(":", "")
            .replace("-", "")
            .replace("_", "")
        )
        if clean[:2].lower() == "0x":
            clean = clean[2:]
        if "0x" in clean.lower():
            raise ValueError(
                "The 0x prefix is only valid at the start of hex input."
            )
        return bytes.fromhex(clean)

    @staticmethod 
    def to_hex(
        data: Union[bytes, bytearray, memoryview],
        space: bool = False,
    ) -> str:
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("Hex output input must be bytes-like.")
        if not isinstance(space, bool):
            raise TypeError("space must be a boolean.")
        s =bytes(data).hex().upper()
        return ' '.join (s [i :i +2 ]for i in range (0 ,len (s ),2 ))if space else s 

class TlvParser:
    """BER-TLV decoder with duplicate-tag and constructed-value support.

    ``parse_detailed`` is intended for diagnostic views and therefore returns
    an error result instead of raising for malformed input. ``parse`` is the
    strict convenience API: it raises ``ValueError`` rather than silently
    returning the valid prefix of a truncated or otherwise invalid stream.
    """

    DEFAULT_MAX_DEPTH = 32
    MAX_TAG_OCTETS = 8
    MAX_LENGTH_OCTETS = 8

    @staticmethod
    def get_first(parsed: Dict[int, Any], tag: int, default: Any = None) -> Any:
        """
        Return the first value for a tag from parsed TLV dict.
        Supports duplicate-tag representation where parsed[tag] may be a list.
        """
        if tag not in parsed:
            return default
        value = parsed[tag]
        if isinstance(value, list):
            if len(value) == 0:
                return default
            return value[0]
        return value

    @staticmethod
    def as_list(value: Any) -> List[Any]:
        """Normalize parsed TLV value to list form."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value ]

    @staticmethod
    def _store_tag(parsed: Dict[int, Any], tag_val: int, value: Any) -> None:
        """
        Store TLV value while preserving duplicate tags.
        - First occurrence: parsed[tag] = value
        - Repeated occurrence: parsed[tag] = [first, second, ...]
        """
        if tag_val not in parsed:
            parsed[tag_val] = value
            return

        current = parsed[tag_val]
        if isinstance(current, list):
            current.append(value)
            return

        parsed[tag_val] = [current, value]

    @staticmethod
    def _error(parsed: Dict[int, Any], offset: int, message: str) -> Dict[str, Any]:
        return {
            "parsed": parsed,
            "consumed": offset,
            "complete": False,
            "error": f"BER-TLV error at offset {offset}: {message}",
        }

    @classmethod
    def _parse_level(
        cls,
        data: bytes,
        *,
        depth: int,
        max_depth: int,
    ) -> Dict[str, Any]:
        offset = 0
        parsed: Dict[int, Any] = {}

        while offset < len(data):
            item_offset = offset
            first_tag_byte = data[offset]
            offset += 1

            # 0x00 is reserved for end-of-contents in indefinite encodings,
            # which this definite-length parser deliberately does not accept.
            # 0xFF is a valid private-class, constructed high-tag identifier
            # (for example ARA-M tag FF40) and must not be rejected here.
            if first_tag_byte == 0x00:
                return cls._error(
                    parsed,
                    item_offset,
                    f"reserved tag octet 0x{first_tag_byte:02X}.",
                )

            tag_octets = bytearray([first_tag_byte])
            if (first_tag_byte & 0x1F) == 0x1F:
                tag_number = 0
                saw_terminal = False
                first_continuation = True
                while offset < len(data):
                    next_byte = data[offset]
                    offset += 1
                    tag_octets.append(next_byte)
                    if len(tag_octets) > cls.MAX_TAG_OCTETS:
                        return cls._error(
                            parsed,
                            item_offset,
                            f"tag exceeds {cls.MAX_TAG_OCTETS} octets.",
                        )
                    if first_continuation and (next_byte & 0x7F) == 0:
                        return cls._error(
                            parsed,
                            item_offset,
                            "non-minimal high-tag-number encoding.",
                        )
                    first_continuation = False
                    tag_number = (tag_number << 7) | (next_byte & 0x7F)
                    if (next_byte & 0x80) == 0:
                        saw_terminal = True
                        break
                if saw_terminal is False:
                    return cls._error(parsed, item_offset, "truncated multi-byte tag.")
                if tag_number < 0x1F:
                    return cls._error(
                        parsed,
                        item_offset,
                        "high-tag-number form used for a tag below 31.",
                    )

            tag_value = int.from_bytes(tag_octets, "big")
            if offset >= len(data):
                return cls._error(parsed, item_offset, "missing length field.")

            first_length_byte = data[offset]
            offset += 1
            if first_length_byte < 0x80:
                value_length = first_length_byte
            else:
                length_octets = first_length_byte & 0x7F
                if length_octets == 0:
                    return cls._error(
                        parsed,
                        item_offset,
                        "indefinite length is not supported.",
                    )
                if length_octets == 0x7F:
                    return cls._error(
                        parsed,
                        item_offset,
                        "length octet 0xFF is reserved.",
                    )
                if length_octets > cls.MAX_LENGTH_OCTETS:
                    return cls._error(
                        parsed,
                        item_offset,
                        f"length field exceeds {cls.MAX_LENGTH_OCTETS} octets.",
                    )
                if offset + length_octets > len(data):
                    return cls._error(parsed, item_offset, "truncated long-form length.")
                encoded_length = data[offset : offset + length_octets]
                offset += length_octets
                if encoded_length[0] == 0:
                    return cls._error(
                        parsed,
                        item_offset,
                        "long-form length has a leading zero octet.",
                    )
                value_length = int.from_bytes(encoded_length, "big")
                if value_length < 0x80:
                    return cls._error(
                        parsed,
                        item_offset,
                        "long-form length used for a value shorter than 128 octets.",
                    )
                minimum_octets = max(1, (value_length.bit_length() + 7) // 8)
                if length_octets != minimum_octets:
                    return cls._error(
                        parsed,
                        item_offset,
                        "non-minimal long-form length encoding.",
                    )

            value_end = offset + value_length
            if value_end > len(data):
                return cls._error(parsed, item_offset, "value overruns input buffer.")
            value = data[offset:value_end]
            offset = value_end

            if first_tag_byte & 0x20:
                if depth >= max_depth:
                    return cls._error(
                        parsed,
                        item_offset,
                        f"maximum constructed nesting depth ({max_depth}) exceeded.",
                    )
                nested_info = cls._parse_level(
                    value,
                    depth=depth + 1,
                    max_depth=max_depth,
                )
                if nested_info["complete"] is False:
                    nested_error = str(nested_info["error"] or "malformed value")
                    return cls._error(
                        parsed,
                        item_offset,
                        f"constructed tag {tag_octets.hex().upper()} contains "
                        f"malformed TLV data ({nested_error}).",
                    )
                cls._store_tag(parsed, tag_value, nested_info["parsed"])
            else:
                cls._store_tag(parsed, tag_value, value)

        return {
            "parsed": parsed,
            "consumed": offset,
            "complete": True,
            "error": None,
        }

    @classmethod
    def parse_detailed(
        cls,
        data: bytes,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Dict[str, Any]:
        """Parse a complete definite-length BER-TLV stream.

        Malformed input is represented by ``complete=False`` and an offset-rich
        ``error`` string. The returned ``parsed`` mapping contains only complete
        TLVs preceding the error and must not be treated as a successful decode.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("BER-TLV input must be bytes-like.")
        if isinstance(max_depth, bool) or not isinstance(max_depth, int):
            raise TypeError("max_depth must be an integer.")
        if max_depth < 0:
            raise ValueError("max_depth must not be negative.")
        return cls._parse_level(bytes(data), depth=0, max_depth=max_depth)

    @classmethod
    def parse(
        cls,
        data: bytes,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Dict[int, Any]:
        """Strictly parse *data*, raising ``ValueError`` on any malformed TLV."""
        result = cls.parse_detailed(data, max_depth=max_depth)
        if result["complete"] is False:
            raise ValueError(str(result["error"]))
        return result["parsed"]

    @classmethod
    def parse_padded(
        cls,
        data: bytes,
        *,
        padding_byte: int = 0xFF,
        max_depth: int = DEFAULT_MAX_DEPTH,
    ) -> Dict[int, Any]:
        """Parse TLVs followed by fixed-record padding.

        Padding is accepted only after at least one complete top-level TLV and
        only when every remaining octet equals ``padding_byte``. This avoids
        the common but unsafe ``rstrip(b"\\xFF")`` pattern, which corrupts a
        legitimate final value octet before validating the enclosing length.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("BER-TLV input must be bytes-like.")
        if (
            isinstance(padding_byte, bool)
            or not isinstance(padding_byte, int)
            or not 0 <= padding_byte <= 0xFF
        ):
            raise ValueError("padding_byte must be in range 0x00..0xFF.")
        raw = bytes(data)
        result = cls.parse_detailed(raw, max_depth=max_depth)
        if result["complete"]:
            return result["parsed"]
        consumed = int(result["consumed"])
        remainder = raw[consumed:]
        if result["parsed"] and remainder and all(
            octet == padding_byte for octet in remainder
        ):
            return result["parsed"]
        raise ValueError(str(result["error"]))

class StatusWordTranslator :
    """Translates ISO 7816-4 and GlobalPlatform Status Words into human-readable strings."""

    SW_MAP ={
    0x9000 :"Success",
    0x6283 :"Selected file invalidated",
    0x6300 :"Authentication failed",
    0x6310 :"More data available (GET STATUS continuation)",
    0x6400 :"State of non-volatile memory unchanged",
    0x6700 :"Wrong length",
    0x6881 :"Logical channel not supported",
    0x6882 :"Secure messaging not supported",
    0x6982 :"Security status not satisfied",
    0x6983 :"Authentication method blocked",
    0x6984 :"Referenced data invalidated",
    0x6985 :"Conditions of use not satisfied",
    0x6A80 :"Incorrect parameters in data field",
    0x6A81 :"Function not supported",
    0x6A82 :"File not found / Applet not found",
    0x6A83 :"Record not found",
    0x6A84 :"Not enough memory space in file",
    0x6A86 :"Incorrect parameters P1-P2",
    0x6A88 :"Referenced data not found",
    0x6A89 :"File already exists",
    0x6D00 :"Instruction code not supported or invalid",
    0x6E00 :"Class not supported",
    0x6F00 :"Unknown error / No precise diagnosis"
    }

    @staticmethod
    def translate(sw1: int, sw2: int) -> str:
        """Return a human-readable description string for the given SW1/SW2 status-word pair (ISO 7816-4 §5.1.3)."""
        for name, value in (("SW1", sw1), ("SW2", sw2)):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(f"{name} must be an integer byte.")
            if not 0 <= value <= 0xFF:
                raise ValueError(f"{name} must be in range 0x00..0xFF.")

        if sw1 == 0x61:
            available = 256 if sw2 == 0 else sw2
            return f"Success. {available} bytes of data available to read."

        if sw1 == 0x6C:
            correct_length = 256 if sw2 == 0 else sw2
            return f"Wrong Le length. Correct length is {correct_length}."

        if sw1 == 0x63:
            if (sw2 & 0xF0) == 0xC0:
                retries = sw2 & 0x0F
                return f"Verification failed. {retries} retries remaining."

        if sw1 == 0x91:
            available = 256 if sw2 == 0 else sw2
            return (
                "Normal processing. "
                f"{available} bytes of proactive-command data available."
            )

        sw = (sw1 << 8) | sw2
        if sw in StatusWordTranslator.SW_MAP:
            return StatusWordTranslator.SW_MAP[sw]

        if sw1 == 0x62:
            return f"Warning; non-volatile memory unchanged (SW2=0x{sw2:02X})."
        if sw1 == 0x63:
            return f"Warning; non-volatile memory changed (SW2=0x{sw2:02X})."

        return "Unknown Status"
