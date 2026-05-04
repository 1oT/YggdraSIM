"""Coverage for the SAIP alpha-string + bare-TLV migration.

The tests below lock in strict behaviour for the following
generic pass-through decoders, which must not fabricate
``ascii`` / ``summary`` fields when the underlying spec leaves
the inner layout opaque:

* ``_decode_spec_opaque_ef`` and ``_decode_opaque_ef`` -- generic
  pass-through decoders that must not fabricate ``ascii`` /
  ``summary`` fields when the underlying spec leaves the inner
  layout opaque.
* ``_decode_group_identifier`` (EF.GID1 / EF.GID2) -- operator-defined
  binary identifiers; not rendered as ASCII when raw bytes happen
  to be printable.
* ``_decode_ef_ipd_opaque`` -- TS 31.102 §4.2.99 IP Data, explicitly
  opaque per-profile.

Concurrently, four BER-TLV EF decoders were migrated to declare a
per-tag ``value_decoders`` map so spec-typed fields surface the right
primitive shape (and the rest stays raw):

* EF.AAS (TS 31.102 §4.4.2.13) -- tag 0x80 = Annex A alpha string.
* EF.REID (TS 102 310 §5.2.2)  -- tag 0x80 = UTF-8 identity.
* EF.PBR  (TS 31.102 §4.4.2.1) -- tags 0xC0..0xCB = 2-byte FID refs.
* EF.ARR security condition     -- tags 0x83 / 0x95 = small integers.
* 5G ProSe TLV EFs              -- tags 85/92/94/95 = integer timers.

The TS 31.102 Annex A alpha string helper added by the same sweep is
also exercised here to pin the selector behaviour for the GSM 7-bit
default alphabet and the three UCS-2 variants (0x80 / 0x81 / 0x82).
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_alpha_string_bytes,
    _decode_alpha_string_text,
    _decode_known_ef_payload,
    _decode_opaque_ef,
    _decode_spec_opaque_ef,
)


# ---------------------------------------------------------------------------
# TS 31.102 Annex A alpha string helper
# ---------------------------------------------------------------------------


class TestAlphaStringHelper:
    def test_plain_gsm7_bytes_decode_without_leader(self) -> None:
        decoded = _decode_alpha_string_bytes(b"Hello")
        assert decoded is not None
        assert decoded["encoding"] == "gsm-7bit"
        assert decoded["text"] == "Hello"

    def test_ucs2_leader_80_decodes_big_endian(self) -> None:
        payload = b"\x80" + "HÉ".encode("utf-16-be")
        decoded = _decode_alpha_string_bytes(payload)
        assert decoded is not None
        assert decoded["encoding"] == "ucs-2-be"
        assert decoded["text"] == "HÉ"

    def test_ucs2_leader_81_uses_8bit_pointer(self) -> None:
        # len=3, base-pointer octet = 0x04 (base = 0x04 << 7 = 0x0200);
        # character 0x80 maps to base + 0x00 = 0x0200 (ⁱ).
        payload = b"\x81\x03\x04\x80\x41\x42"
        decoded = _decode_alpha_string_bytes(payload)
        assert decoded is not None
        assert decoded["encoding"] == "ucs-2-shift-81"
        assert len(decoded["text"]) == 3
        assert decoded["text"].endswith("AB")
        assert ord(decoded["text"][0]) == 0x0200

    def test_ucs2_leader_82_uses_full_base_pointer(self) -> None:
        payload = b"\x82\x02\x04\xE2\x80\x41"
        decoded = _decode_alpha_string_bytes(payload)
        assert decoded is not None
        assert decoded["encoding"] == "ucs-2-shift-82"
        assert ord(decoded["text"][0]) == 0x04E2
        assert decoded["text"].endswith("A")

    def test_trailing_and_leading_filler_are_stripped(self) -> None:
        payload = b"\xFF\xFF\xFFIDF\xFF\xFF"
        assert _decode_alpha_string_text(payload) == "IDF"

    def test_all_filler_returns_empty_string_payload(self) -> None:
        payload = b"\xFF\xFF\xFF\xFF"
        decoded = _decode_alpha_string_bytes(payload)
        assert decoded is not None
        assert decoded["encoding"] == "filler"
        assert decoded["text"] == ""

    def test_non_gsm7_high_bit_returns_none(self) -> None:
        # Bytes with the high bit set and no TS 31.102 leader cannot
        # be interpreted as GSM 7-bit; helper must decline rather than
        # guess UTF-8 / Latin-1.
        assert _decode_alpha_string_bytes(b"\xC0\xC1\xC2") is None
        assert _decode_alpha_string_text(b"\xC0\xC1\xC2") == ""


# ---------------------------------------------------------------------------
# BER-TLV migrations
# ---------------------------------------------------------------------------


def _decode_ef(token: str, hex_input: str) -> dict[str, object]:
    decoded = _decode_known_ef_payload(
        ef_key=token,
        fid=None,
        hex_clean=hex_input,
    )
    assert isinstance(decoded, dict), f"{token} did not return a dict"
    return decoded


class TestEfAasAlphaStringDeclaration:
    def test_aas_tag_80_returns_alpha_string_payload(self) -> None:
        # Tag 0x80, value = GSM-7 text "ABC"
        decoded = _decode_ef("ef-aas", "8003414243")
        items = decoded["items"]
        assert isinstance(items, list) and len(items) == 1
        item = items[0]
        assert item["tag"] == "80"
        decoded_value = item["decoded"]
        assert isinstance(decoded_value, dict)
        assert decoded_value["encoding"] == "gsm-7bit"
        assert decoded_value["text"] == "ABC"

    def test_aas_tag_80_ucs2_leader_still_typed(self) -> None:
        ucs2_payload = "80" + "00410042".upper()  # UCS-2 BE for "AB"
        hex_input = "8005" + ucs2_payload.replace(" ", "")
        decoded = _decode_ef("ef-aas", hex_input)
        items = decoded["items"]
        decoded_value = items[0]["decoded"]
        assert decoded_value["encoding"] == "ucs-2-be"
        assert decoded_value["text"] == "AB"


class TestEfReidTextDeclaration:
    def test_reid_tag_80_is_text_typed(self) -> None:
        hex_input = "80047573723A"  # tag 80, len 4, "usr:" ASCII
        decoded = _decode_ef("ef-reid", hex_input)
        items = decoded["items"]
        assert items[0]["tag"] == "80"
        assert items[0]["decoded"] == "usr:"

    def test_reid_non_printable_stays_raw(self) -> None:
        hex_input = "800400010203"
        decoded = _decode_ef("ef-reid", hex_input)
        items = decoded["items"]
        assert items[0]["raw"] == "00010203"
        assert "decoded" not in items[0]


class TestEfPbrFileIdentifierDeclaration:
    def test_pbr_cx_tags_decode_as_fid_pair(self) -> None:
        # A8 wraps C0 (2-byte FID 6F3A = EF.ADN) + C2 (6F4B = EF.EXT1).
        hex_input = "A808" + "C0026F3A" + "C2026F4B"
        decoded = _decode_ef("ef-pbr", hex_input)
        items = decoded["items"]
        assert isinstance(items, list) and len(items) == 1
        wrapper = items[0]
        assert wrapper["tag"] == "A8"
        inner_items = wrapper["items"]
        assert isinstance(inner_items, list) and len(inner_items) == 2
        adn_ref = inner_items[0]
        ext1_ref = inner_items[1]
        assert adn_ref["tag"] == "C0"
        assert adn_ref["decoded"]["fid"] == "6F3A"
        assert ext1_ref["tag"] == "C2"
        assert ext1_ref["decoded"]["fid"] == "6F4B"


class TestFiveGProseTimerDeclaration:
    @pytest.mark.parametrize(
        ("token", "timer_tag"),
        [
            ("ef-5g-prose-dd", "85"),
            ("ef-5g-prose-dc", "85"),
            ("ef-5g-prose-u2nru", "85"),
            ("ef-5g-prose-ru", "85"),
            ("ef-5g-prose-uir", "85"),
        ],
    )
    def test_validity_timer_decoded_as_integer(
        self,
        token: str,
        timer_tag: str,
    ) -> None:
        # A0 wrapper carrying a single 2-byte validity timer (0x012C = 300).
        hex_input = "A004" + timer_tag + "02" + "012C"
        decoded = _decode_ef(token, hex_input)
        items = decoded["items"]
        wrapper = items[0]
        assert wrapper["tag"] == "A0"
        inner_items = wrapper["items"]
        assert len(inner_items) == 1
        timer_item = inner_items[0]
        assert timer_item["tag"] == timer_tag
        assert timer_item["decoded"]["decimal"] == 300

    def test_non_timer_tag_stays_raw(self) -> None:
        hex_input = "A005" + "8003" + "ABCDEF"
        decoded = _decode_ef("ef-5g-prose-dd", hex_input)
        items = decoded["items"]
        inner = items[0]["items"][0]
        assert inner["tag"] == "80"
        assert inner["raw"] == "ABCDEF"
        assert "decoded" not in inner


# ---------------------------------------------------------------------------
# Opaque pass-through decoders no longer emit ASCII fluff
# ---------------------------------------------------------------------------


class TestOpaqueEfFluffSuppressed:
    def test_spec_opaque_ef_omits_ascii_even_when_printable(self) -> None:
        # "HELLO" (all printable ASCII) routed through the spec-opaque
        # pass-through. The decoder used to surface an ``ascii`` key
        # which was context-blind fluff.
        printable_hex = "48454C4C4F"
        decoded = _decode_spec_opaque_ef(
            printable_hex,
            format_name="Test Opaque",
            spec_reference="TEST",
            summary_prefix="Test",
        )
        assert decoded is not None
        assert "ascii" not in decoded
        assert decoded["summary"] == "Test (5 bytes)"

    def test_generic_opaque_ef_omits_ascii_even_when_printable(self) -> None:
        printable_hex = "544553544552"  # "TESTER"
        decoded = _decode_opaque_ef(
            printable_hex,
            format_name="Generic Opaque",
        )
        assert decoded is not None
        assert "ascii" not in decoded
        assert decoded["summary"] == printable_hex

    def test_gid_is_not_rendered_as_ascii(self) -> None:
        # EF.GID1 with a printable binary identifier; ASCII inference
        # here is not spec-defined.
        hex_input = "4142FFFFFFFFFFFFFFFFFFFFFFFFFFFF"
        decoded = _decode_ef("ef-gid1", hex_input)
        assert "ascii" not in decoded
        assert decoded["format"] == "Group Identifier Level 1"


class TestUsimIpDataOpaque:
    def test_ipd_is_not_rendered_as_ascii(self) -> None:
        hex_input = "7465737470617468FFFFFFFF"  # "testpath" + FF padding
        decoded = _decode_ef("ef-ipd", hex_input)
        assert "ascii" not in decoded
        assert decoded["format"] == "USIM IP Data"
