# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Context-aware primitive typing for the SAIP decoder.

These tests pin down the post-audit contract that guards against
``fluff'' decoding (opportunistic ASCII / BCD / small-integer guessing
in places the specification does not mandate such rendering):

* ``_decode_field_ber_tlv_stream`` defaults to ``opaque`` primitive
  typing; primitive values surface only as ``raw`` unless the caller
  declared an explicit per-tag ``value_decoders`` entry.
* ``_parse_ber_stream`` stops inferring ASCII / BCD for non-universal
  primitives; universal primitives still decode per BER rules.
* ``_summarize_binary_blob`` stops emitting ``ascii`` / ``bcdDigits``
  by default; callers must opt in via ``infer_text`` / ``infer_bcd``
  when the containing spec field is text / BCD-typed.

Concrete EFs exercised:
  * ef-eapkeys — MSK / EMSK must never be ASCII-rendered.
  * ef-mmsicp  — MMS relay URL (tag 81) is declared text.
  * ef-xcapconfigdata — URI / username are text; password stays raw.
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_field_ber_tlv_stream,
    _decode_known_ef_payload,
    _parse_ber_stream,
    _summarize_binary_blob,
    _tlv_value_decoder_small_int,
    _tlv_value_decoder_text,
)


class TestBerTlvStreamStrictDefault:
    def test_primitive_without_declaration_returns_raw_only(self) -> None:
        # Tag 80 carries ASCII bytes but nothing is declared.
        items = _decode_field_ber_tlv_stream(
            b"\x80\x05HELLO",
            tag_names={"80": "Test"},
        )
        assert len(items) == 1
        assert items[0]["raw"] == "48454C4C4F"
        assert "decoded" not in items[0]

    def test_declared_text_decoder_surfaces_string(self) -> None:
        items = _decode_field_ber_tlv_stream(
            b"\x80\x05HELLO",
            tag_names={"80": "Test"},
            value_decoders={"80": _tlv_value_decoder_text},
        )
        assert items[0]["decoded"] == "HELLO"

    def test_declared_small_int_decoder_emits_integer(self) -> None:
        items = _decode_field_ber_tlv_stream(
            b"\x80\x02\x00\x2A",
            tag_names={"80": "Count"},
            value_decoders={"80": _tlv_value_decoder_small_int},
        )
        decoded = items[0]["decoded"]
        assert isinstance(decoded, dict)
        assert decoded["decimal"] == 42

    def test_opportunistic_mode_still_available_for_legacy_callers(
        self,
    ) -> None:
        items = _decode_field_ber_tlv_stream(
            b"\x80\x05HELLO",
            tag_names={"80": "Test"},
            default_primitive_type="opportunistic",
        )
        assert items[0]["decoded"] == "HELLO"

    def test_universal_oid_always_decoded(self) -> None:
        # OID 1.2.840.113549 (RSA)
        items = _decode_field_ber_tlv_stream(
            b"\x06\x06\x2A\x86\x48\x86\xF7\x0D",
            tag_names={},
        )
        assert items[0]["decoded"] == "1.2.840.113549"

    def test_unknown_default_primitive_type_raises(self) -> None:
        with pytest.raises(ValueError):
            _decode_field_ber_tlv_stream(
                b"\x80\x01\x00",
                tag_names={"80": "Test"},
                default_primitive_type="magic",
            )


class TestParseBerStreamNoFluff:
    def test_context_tag_with_printable_bytes_stays_raw(self) -> None:
        # Context-specific primitive [0] holding ASCII bytes. The
        # spec gives no universal interpretation, so no ``decoded``
        # field must be invented.
        items, end_offset = _parse_ber_stream(
            b"\x80\x05HELLO", 0, allow_eoc=False, depth=0,
        )
        assert end_offset == 7
        assert len(items) == 1
        item = items[0]
        assert item["class"] == "context"
        assert item["raw"] == "48454C4C4F"
        assert "decoded" not in item

    def test_context_tag_with_bcd_like_bytes_stays_raw(self) -> None:
        # Bytes 0x21 0x43 0x65 happen to ``look like`` BCD but no spec
        # says a context-specific primitive carries BCD.
        items, _ = _parse_ber_stream(
            b"\x81\x03\x21\x43\x65", 0, allow_eoc=False, depth=0,
        )
        assert items[0]["raw"] == "214365"
        assert "decoded" not in items[0]

    def test_universal_integer_still_decodes(self) -> None:
        items, _ = _parse_ber_stream(
            b"\x02\x01\x2A", 0, allow_eoc=False, depth=0,
        )
        assert items[0]["decoded"] == 42


class TestSummarizeBinaryBlobStrict:
    def test_default_emits_length_and_hex_only(self) -> None:
        summary = _summarize_binary_blob(b"ABCD\x01\x02\x03\x04")
        assert summary == {
            "length": 8,
            "hex": "4142434401020304",
        }

    def test_infer_text_opt_in_surfaces_ascii_when_all_printable(
        self,
    ) -> None:
        summary = _summarize_binary_blob(
            b"hello-world",
            infer_text=True,
        )
        assert summary["ascii"] == "hello-world"

    def test_infer_text_does_not_falsely_claim_mixed_bytes(self) -> None:
        summary = _summarize_binary_blob(
            b"ABCD\x01\x02",
            infer_text=True,
        )
        assert "ascii" not in summary

    def test_infer_bcd_opt_in_surfaces_digits(self) -> None:
        # Nibble-swapped BCD for digits "1234"
        summary = _summarize_binary_blob(
            b"\x21\x43",
            infer_bcd=True,
        )
        assert summary["bcdDigits"] == "1234"

    def test_infer_bcd_default_off_even_for_bcd_like_bytes(self) -> None:
        summary = _summarize_binary_blob(b"\x21\x43")
        assert "bcdDigits" not in summary


class TestEapKeysNoAsciiFluff:
    def test_msk_key_material_stays_raw_hex(self) -> None:
        # Construct a TLV 80 40 <64 bytes whose leading bytes are
        # printable ASCII ('HELLO' * n), to prove the key material is
        # never rendered as text.
        msk_bytes = (b"HELLO!" * 11)[:64]
        hex_input = ("8040" + msk_bytes.hex()).upper()
        decoded = _decode_known_ef_payload(
            ef_key="ef-eapkeys", fid=None, hex_clean=hex_input,
        )
        assert decoded is not None
        items = decoded["items"]
        assert items[0]["tag"] == "80"
        assert items[0]["raw"] == msk_bytes.hex().upper()
        assert "decoded" not in items[0]


class TestMmsicpContextualText:
    def test_mms_relay_url_is_surfaced_as_text(self) -> None:
        url = b"http://mms.op/relay"
        tlv = b"\x80\x01\x00\x81" + bytes([len(url)]) + url
        decoded = _decode_known_ef_payload(
            ef_key="ef-mmsicp", fid=None, hex_clean=tlv.hex().upper(),
        )
        assert decoded is not None
        tags = {item["tag"]: item for item in decoded["items"]}
        assert tags["80"]["decoded"]["decimal"] == 0
        assert tags["81"]["decoded"] == "http://mms.op/relay"


class TestXcapConfigDataContextualTyping:
    def test_uri_and_username_are_text_password_is_raw_only(self) -> None:
        uri = b"http://xcap.op/abc"
        username = b"alice"
        password = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        tlv = (
            b"\x84" + bytes([len(uri)]) + uri
            + b"\x85" + bytes([len(username)]) + username
            + b"\x86" + bytes([len(password)]) + password
        )
        decoded = _decode_known_ef_payload(
            ef_key="ef-xcapconfigdata",
            fid=None,
            hex_clean=tlv.hex().upper(),
        )
        assert decoded is not None
        tags = {item["tag"]: item for item in decoded["items"]}
        assert tags["84"]["decoded"] == "http://xcap.op/abc"
        assert tags["85"]["decoded"] == "alice"
        # Password stays opaque — no text inference for credentials.
        assert "decoded" not in tags["86"]
