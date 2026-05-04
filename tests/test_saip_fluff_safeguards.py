"""Context-safeguard tests for the SAIP ASN.1 decoder.

These tests lock in the following properties of the decoder:

* ``_decode_fill_pattern`` / ``_decode_repeat_pattern`` do not
  fabricate ASCII output for short (< 3 byte) patterns and never
  surface ASCII for byte sequences that are not fully printable.

* ``_decode_pin_secret_value`` follows ETSI TS 102 221 §9.2 strictly:
  only ASCII-digit payloads surface ``digits`` / ``summary`` text; any
  non-digit content leaves the hex representation visible without a
  forged ``ascii`` field.

* ``_decode_universal_primitive`` (generic ASN.1 OCTET STRING, tag 4)
  requires at least three fully printable bytes before emitting an
  ``ascii`` hint -- short OCTET STRINGs that happen to be printable by
  coincidence (key material, counters, tags) are not surfaced as text.
"""

from __future__ import annotations

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_fill_pattern,
    _decode_pin_secret_value,
    _decode_universal_primitive,
)


class TestFillPatternContextSafeguards:
    def test_single_ff_padding_byte_has_no_ascii(self) -> None:
        decoded = _decode_fill_pattern(b"\xFF", repeat_pattern=False)
        assert decoded is not None
        assert "ascii" not in decoded
        assert decoded["summary"] == "FF"
        assert decoded["byteValue"] == "0xFF"

    def test_two_byte_pattern_has_no_ascii(self) -> None:
        decoded = _decode_fill_pattern(b"AB", repeat_pattern=True)
        assert decoded is not None
        assert "ascii" not in decoded
        assert decoded["summary"] == "4142"

    def test_long_printable_pattern_surfaces_ascii(self) -> None:
        decoded = _decode_fill_pattern(b"TESTPAD", repeat_pattern=False)
        assert decoded is not None
        assert decoded.get("ascii") == "TESTPAD"
        assert decoded["summary"] == "TESTPAD"

    def test_mixed_printable_and_binary_has_no_ascii(self) -> None:
        decoded = _decode_fill_pattern(b"AB\x00CD", repeat_pattern=False)
        assert decoded is not None
        assert "ascii" not in decoded
        assert decoded["summary"] == "41420043" + "44"


class TestPinSecretValueStrictDigits:
    def test_pure_ascii_digits_with_ff_padding_surfaces_digits(self) -> None:
        decoded = _decode_pin_secret_value(b"1234" + b"\xFF" * 4)
        assert decoded is not None
        assert decoded["digits"] == "1234"
        assert decoded["summary"] == "1234"
        assert decoded["paddingHex"] == "FFFFFFFF"
        assert decoded["reference"] == "ETSI TS 102 221 §9.2"

    def test_alpha_ascii_does_not_surface_as_digits(self) -> None:
        decoded = _decode_pin_secret_value(b"ABCD" + b"\xFF" * 4)
        assert decoded is not None
        assert "digits" not in decoded
        assert "ascii" not in decoded
        assert decoded["summary"] == "41424344FFFFFFFF"

    def test_random_bytes_stay_hex(self) -> None:
        raw = bytes.fromhex("A1B2C3D4E5F60708")
        decoded = _decode_pin_secret_value(raw)
        assert decoded is not None
        assert "digits" not in decoded
        assert "ascii" not in decoded
        assert decoded["summary"] == "A1B2C3D4E5F60708"

    def test_all_ff_padding_returns_hex_summary(self) -> None:
        decoded = _decode_pin_secret_value(b"\xFF" * 8)
        assert decoded is not None
        assert "digits" not in decoded
        assert decoded["summary"] == "FFFFFFFFFFFFFFFF"


class TestUniversalOctetStringAsciiGuard:
    def test_two_byte_printable_octet_string_has_no_ascii(self) -> None:
        # Tag 4, length 2, "AB" -- too short to be treated as text
        decoded = _decode_universal_primitive(4, b"AB")
        assert isinstance(decoded, dict)
        assert decoded["hex"] == "4142"
        assert "ascii" not in decoded

    def test_three_byte_printable_octet_string_surfaces_ascii(self) -> None:
        decoded = _decode_universal_primitive(4, b"XYZ")
        assert isinstance(decoded, dict)
        assert decoded["hex"] == "58595A"
        assert decoded.get("ascii") == "XYZ"

    def test_mixed_binary_octet_string_has_no_ascii(self) -> None:
        decoded = _decode_universal_primitive(4, b"AB\x01CD")
        assert isinstance(decoded, dict)
        assert decoded["hex"] == "41420143" + "44"
        assert "ascii" not in decoded
