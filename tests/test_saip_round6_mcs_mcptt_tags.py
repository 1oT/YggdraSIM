# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Round-6 Sweep 1 — MCS / MCPTT per-tag text decoder regression tests.

The MCS family (TS 31.102 §4.4.13 / TS 24.483) uses the shared
``_EF_MCS_TAGS`` vocabulary plus per-tag UTF-8 decoders for the MC
Service Identifier (0x80 — SIP URI), MC User Profile (0x81), and
MC Configuration Data (0x82). Tags 0x83 / 0x84 / 0x85 are opaque
security material and must NOT surface as text.
"""

from __future__ import annotations

from Tools.ProfilePackage.saip_asn1_decode import (
    _EF_MCS_TAGS,
    _EF_MCS_VALUE_DECODERS,
    _decode_known_ef_payload,
    _tlv_value_decoder_utf8_text,
)


class TestMcsUtf8Decoder:
    def test_decodes_sip_uri(self) -> None:
        uri = b"sip:alice@mcptt.example"
        result = _tlv_value_decoder_utf8_text(uri)
        assert result == uri.decode("ascii")

    def test_rejects_binary_noise(self) -> None:
        result = _tlv_value_decoder_utf8_text(b"\x01\x02\x03\x04")
        assert result is None

    def test_accepts_xml_payload(self) -> None:
        xml_bytes = b"<?xml version=\"1.0\"?><mcptt/>"
        result = _tlv_value_decoder_utf8_text(xml_bytes)
        assert result == xml_bytes.decode("utf-8")

    def test_accepts_utf8_multibyte(self) -> None:
        text = "mcptt-id:Ω".encode("utf-8")
        result = _tlv_value_decoder_utf8_text(text)
        assert result == "mcptt-id:Ω"

    def test_rejects_empty(self) -> None:
        assert _tlv_value_decoder_utf8_text(b"") is None


class TestMcsValueDecoderRegistry:
    def test_tag_80_is_utf8(self) -> None:
        assert _EF_MCS_VALUE_DECODERS["80"] is _tlv_value_decoder_utf8_text

    def test_tag_81_is_utf8(self) -> None:
        assert _EF_MCS_VALUE_DECODERS["81"] is _tlv_value_decoder_utf8_text

    def test_tag_82_is_utf8(self) -> None:
        assert _EF_MCS_VALUE_DECODERS["82"] is _tlv_value_decoder_utf8_text

    def test_security_tags_stay_opaque(self) -> None:
        # Tags 0x83 / 0x84 / 0x85 carry security material and must not
        # be decoded as text to avoid context-blind fluff (Round-5 Sweep 1).
        assert "83" not in _EF_MCS_VALUE_DECODERS
        assert "84" not in _EF_MCS_VALUE_DECODERS
        assert "85" not in _EF_MCS_VALUE_DECODERS

    def test_tag_names_cover_all_registered_decoders(self) -> None:
        for tag_hex in _EF_MCS_VALUE_DECODERS:
            assert tag_hex in _EF_MCS_TAGS


class TestMcsPerTagDispatch:
    def test_mc_service_identifier_surfaces_text(self) -> None:
        # Build a minimal BER-TLV payload: [80 LL "sip:alice@mcptt"].
        uri = b"sip:alice@mcptt.example"
        payload = bytes([0x80, len(uri)]) + uri
        decoded = _decode_known_ef_payload(
            ef_key="ef-mcs-root",
            fid=None,
            hex_clean=payload.hex().upper(),
        )
        assert decoded is not None
        assert decoded["format"] == "MCS Root"
        items = decoded.get("items")
        assert isinstance(items, list) and len(items) == 1
        first = items[0]
        assert first["tag"] == "80"
        assert first["name"] == "MC Service Identifier"
        assert first.get("decoded") == uri.decode("ascii")

    def test_mc_configuration_data_surfaces_xml_text(self) -> None:
        xml_bytes = b"<?xml version=\"1.0\"?><mcptt/>"
        payload = bytes([0x82, len(xml_bytes)]) + xml_bytes
        decoded = _decode_known_ef_payload(
            ef_key="ef-mcptt-cfg",
            fid=None,
            hex_clean=payload.hex().upper(),
        )
        assert decoded is not None
        items = decoded.get("items")
        assert isinstance(items, list) and len(items) == 1
        first = items[0]
        assert first["tag"] == "82"
        assert first.get("decoded") == xml_bytes.decode("utf-8")

    def test_mc_key_material_stays_opaque(self) -> None:
        # Tag 0x85 (MC Key Material) must remain raw hex only, even when
        # the bytes happen to contain printable ASCII.
        key_bytes = b"AAAAAAAAAAAAAAAA"  # Plaintext-looking key material.
        payload = bytes([0x85, len(key_bytes)]) + key_bytes
        decoded = _decode_known_ef_payload(
            ef_key="ef-mcs-keyset",
            fid=None,
            hex_clean=payload.hex().upper(),
        )
        assert decoded is not None
        items = decoded.get("items")
        assert isinstance(items, list) and len(items) == 1
        first = items[0]
        assert first["tag"] == "85"
        assert "decoded" not in first
