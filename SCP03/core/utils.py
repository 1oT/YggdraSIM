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
from typing import Any, Dict, Iterable, List, Optional, Union

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

    # ITU-T X.690 (02/2021) §8.1.2.5: "Bit 6 shall be set to zero if the
    # encoding is primitive, and shall be set to one if the encoding is
    # constructed." GlobalPlatform Secure Element Access Control v1.1
    # assigns two data objects a tag with bit 6 set whose value is not a TLV
    # stream: table 6-12 gives 'E6' Device-Interface-Version-DO a 3-byte
    # version number, and table 6-13 gives 'E7' Block-DO a 2-byte offset
    # followed by a 1-byte length (Annex B table B-1 names both). A caller
    # decoding those hands this set to ``primitive_tags`` so their contents
    # are kept as bytes; the remaining SE Access Control objects ('E1'-'E5',
    # 'FF40' and the rest) really are constructed and must keep the default.
    GP_SE_ACCESS_CONTROL_PRIMITIVE_TAGS = frozenset({0xE6, 0xE7})

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

    @staticmethod
    def _normalize_primitive_tags(
        primitive_tags: Optional[Iterable[int]],
    ) -> frozenset:
        if primitive_tags is None:
            return frozenset()
        normalized = set()
        for tag in primitive_tags:
            if isinstance(tag, bool) or not isinstance(tag, int):
                raise TypeError("primitive_tags must contain integer tag values.")
            if tag < 0:
                raise ValueError("primitive_tags must not contain negative values.")
            normalized.add(tag)
        return frozenset(normalized)

    @classmethod
    def _parse_level(
        cls,
        data: bytes,
        *,
        depth: int,
        max_depth: int,
        primitive_tags: frozenset = frozenset(),
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

            if first_tag_byte & 0x20 and tag_value not in primitive_tags:
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
                    primitive_tags=primitive_tags,
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
        primitive_tags: Optional[Iterable[int]] = None,
    ) -> Dict[str, Any]:
        """Parse a complete definite-length BER-TLV stream.

        Malformed input is represented by ``complete=False`` and an offset-rich
        ``error`` string. The returned ``parsed`` mapping contains only complete
        TLVs preceding the error and must not be treated as a successful decode.

        ``primitive_tags`` names whole tags (``0xE6``, ``0xDF20``) whose value
        is kept as bytes even though X.690 §8.1.2.5 bit 6 marks them
        constructed. It exists for specifications that assign such a tag to a
        non-TLV value; see ``GP_SE_ACCESS_CONTROL_PRIMITIVE_TAGS``. Nothing is
        treated as primitive unless the caller asks.
        """
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("BER-TLV input must be bytes-like.")
        if isinstance(max_depth, bool) or not isinstance(max_depth, int):
            raise TypeError("max_depth must be an integer.")
        if max_depth < 0:
            raise ValueError("max_depth must not be negative.")
        return cls._parse_level(
            bytes(data),
            depth=0,
            max_depth=max_depth,
            primitive_tags=cls._normalize_primitive_tags(primitive_tags),
        )

    @classmethod
    def parse(
        cls,
        data: bytes,
        *,
        max_depth: int = DEFAULT_MAX_DEPTH,
        primitive_tags: Optional[Iterable[int]] = None,
    ) -> Dict[int, Any]:
        """Strictly parse *data*, raising ``ValueError`` on any malformed TLV."""
        result = cls.parse_detailed(
            data, max_depth=max_depth, primitive_tags=primitive_tags
        )
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
        primitive_tags: Optional[Iterable[int]] = None,
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
        result = cls.parse_detailed(
            raw, max_depth=max_depth, primitive_tags=primitive_tags
        )
        if result["complete"]:
            return result["parsed"]
        consumed = int(result["consumed"])
        remainder = raw[consumed:]
        if result["parsed"] and remainder and all(
            octet == padding_byte for octet in remainder
        ):
            return result["parsed"]
        if len(raw) > 0 and all(octet == padding_byte for octet in raw):
            # TS 102 221 v18.4 §13.4: "Unused bytes in the record are set to
            # 'FF'". A record the card has never written carries nothing but
            # padding, which is an empty record rather than a malformed one.
            # 'FF' also opens the high-tag-number form, so the strict parser
            # reads it as a tag that never ends.
            return {}
        raise ValueError(str(result["error"]))

class StatusWordTranslator :
    """Translates ISO 7816-4 and GlobalPlatform Status Words into human-readable strings."""

    # Static status words. Sources: ETSI TS 102 221 v18.4 Tables 10.7 to
    # 10.15 (UICC), ETSI TS 102 222 v17.1 Table 6 (administrative commands),
    # GlobalPlatform Card Specification v2.3.1 Table 11-38, GlobalPlatform
    # Amendment D v1.1.2 Table 7-7, and 3GPP TS 51.011 v4.15 §9.4 (GSM SIM,
    # class 'A0'). Length-carrying words ('61xx', '6Cxx', '63Cx', '91xx',
    # '92xx', '9Exx', '9Fxx') are rendered by ``translate``.
    SW_MAP = {
        # TS 102 221 v18.4 Table 10.7 - normal processing
        0x9000: "Success",
        # TS 102 221 v18.4 Table 10.8 - postponed processing
        0x9300: (
            "SIM Application Toolkit is busy; command cannot be executed at "
            "present, further normal commands are allowed"
        ),
        # TS 102 221 v18.4 Table 10.9 - warnings
        0x6200: "No information given, state of non-volatile memory unchanged",
        0x6281: "Part of returned data may be corrupted",
        0x6282: "End of file/record reached before reading Le bytes or unsuccessful search",
        0x6283: "Selected file invalidated",
        0x6285: "Selected file in termination state",
        0x62F1: "More data available",
        0x62F2: "More data available and proactive command pending",
        0x62F3: "Response data available",
        0x63F1: "More data expected",
        0x63F2: "More data expected and proactive command pending",
        # GlobalPlatform Amendment D v1.1.2 Table 7-7 (EXTERNAL AUTHENTICATE)
        0x6300: "Authentication of host cryptogram failed",
        # GlobalPlatform Card Specification v2.3.1 Table 11-38 (GET STATUS)
        0x6310: "More data available (GET STATUS continuation)",
        # TS 102 221 v18.4 Table 10.10 - execution errors
        0x6400: "No information given, state of non-volatile memory unchanged",
        0x6500: "No information given, state of non-volatile memory changed",
        0x6581: "Memory problem",
        # TS 102 221 v18.4 Table 10.11 - checking errors
        0x6700: "Wrong length",
        0x6B00: "Wrong parameter(s) P1-P2",
        0x6D00: "Instruction code not supported or invalid",
        0x6E00: "Class not supported",
        0x6F00: "Technical problem, no precise diagnosis",
        # TS 102 221 v18.4 Table 10.12 - functions in CLA not supported
        0x6800: "No information given (functions in CLA not supported)",
        0x6881: "Logical channel not supported",
        0x6882: "Secure messaging not supported",
        # TS 102 221 v18.4 Table 10.13 - command not allowed
        0x6900: "No information given (command not allowed)",
        0x6981: "Command incompatible with file structure",
        0x6982: "Security status not satisfied",
        0x6983: "Authentication/PIN method blocked",
        0x6984: "Referenced data invalidated",
        0x6985: "Conditions of use not satisfied",
        0x6986: "Command not allowed (no EF selected)",
        0x6989: "Command not allowed - secure channel - security not satisfied",
        # TS 102 221 v18.4 Table 10.14 - wrong parameters
        0x6A80: "Incorrect parameters in the data field",
        0x6A81: "Function not supported",
        0x6A82: "File not found (GlobalPlatform: application not found)",
        0x6A83: "Record not found",
        0x6A84: "Not enough memory space",
        0x6A86: "Incorrect parameters P1 to P2",
        0x6A87: "Lc inconsistent with P1 to P2",
        0x6A88: "Referenced data not found",
        # TS 102 222 v17.1 Table 6 (CREATE FILE)
        0x6A89: "File ID already exists",
        0x6A8A: "DF name already exists",
        # TS 102 221 v18.4 Table 10.15 - application errors
        0x9850: "INCREASE cannot be performed, max value reached",
        0x9862: "Authentication error, application specific",
        0x9863: "Security session or association expired",
        0x9864: "Minimum UICC suspension time is too long",
        # TS 51.011 v4.15 §9.4.3 to §9.4.5 - GSM SIM (class 'A0') status words
        0x9240: "Memory problem",
        0x9400: "No EF selected",
        0x9402: "Out of range (invalid address)",
        0x9404: "File ID not found / pattern not found",
        0x9408: "File is inconsistent with the command",
        0x9802: "No CHV initialized",
        0x9804: (
            "Access condition not fulfilled / unsuccessful CHV verification, "
            "at least one attempt left / authentication failed"
        ),
        0x9808: "In contradiction with CHV status",
        0x9810: "In contradiction with invalidation status",
        0x9840: (
            "Unsuccessful CHV verification, no attempt left / CHV blocked / "
            "UNBLOCK CHV blocked"
        ),
    }

    @staticmethod
    def translate(sw1: int, sw2: int) -> str:
        """Return a human-readable description for SW1/SW2 (TS 102 221 v18.4 §10.2.1)."""
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
            # TS 102 221 v18.4 Table 10.7: 'XX' is the length of the pending
            # proactive command, with no 256 convention for 'XX' = '00'.
            return (
                "Normal processing. "
                f"{sw2} bytes of proactive-command data available (FETCH)."
            )

        if sw1 == 0x9F:
            # TS 51.011 v4.15 §9.4.1: a GSM SIM announces response data with
            # '9F' 'XX' instead of the '61xx' procedure bytes.
            return f"Length {sw2} of the response data (GSM SIM; use GET RESPONSE)."

        if sw1 == 0x9E:
            return (
                f"Length {sw2} of the response data given in case of a "
                "SIM data download error."
            )

        sw = (sw1 << 8) | sw2
        if sw in StatusWordTranslator.SW_MAP:
            return StatusWordTranslator.SW_MAP[sw]

        if sw1 == 0x92:
            # TS 102 221 v18.4 Table 10.7 for a UICC; TS 51.011 v4.15 §9.4.3
            # reads '92 0X' on a GSM SIM as X internal update retries.
            return (
                "Normal ending of the command, with extra information "
                f"concerning an ongoing data transfer session (SW2=0x{sw2:02X}; "
                "on a GSM SIM: command successful after internal update retries)."
            )

        if sw1 == 0x62:
            return f"Warning; non-volatile memory unchanged (SW2=0x{sw2:02X})."
        if sw1 == 0x63:
            return f"Warning; non-volatile memory changed (SW2=0x{sw2:02X})."
        if sw1 == 0x67:
            # TS 102 221 v18.4 Table 10.11: SW2 other than '00' is command dependent.
            return f"Wrong length (SW2=0x{sw2:02X} is command dependent)."
        if sw1 == 0x6F:
            return f"Technical problem (SW2=0x{sw2:02X} is command dependent)."

        return "Unknown Status"
