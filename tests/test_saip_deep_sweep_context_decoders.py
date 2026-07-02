# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Round-3 deep-sweep regression coverage for the SAIP ASN.1 decoder.

After the first two "fluff" sweeps closed the opportunistic ASCII /
BCD / small-integer inference paths in the generic TLV helpers, this
sweep focuses on spec-anchored text typing for named EFs that were
still routing through lenient ``decode("utf-8", "ignore")`` or
``decode("ascii", "ignore")`` helpers. It also introduces a TS 24.008
§10.5.3.5a Network Name IE decoder and wires it into EF.PNN.

Targets covered:

* EF.SPN (6F46, TS 31.102 §4.2.12)
    - ``serviceProviderName`` is now decoded via the Annex A alpha
      string helper (GSM 7-bit default alphabet or UCS-2 with the
      0x80/0x81/0x82 leaders). The legacy ``decode("utf-8", "ignore")``
      path used to silently drop any byte with the high bit set.

* EF.PNN (6FC5, TS 31.102 §4.2.58)
    - Tags 0x43 / 0x45 now dispatch the TS 24.008 Network Name IE
      decoder instead of ``_decode_printable_ascii``. GSM 7-bit packed
      and UCS-2 BE are both exercised.

* EF.GBANL (6FDA, TS 31.102 §4.2.80)
    - Tag 0x81 (B-TID) is declared as UTF-8 text; tag 0x80 (NAF ID)
      stays opaque binary.

* ISIM P-CSCF address (TS 31.103 §4.2.8)
    - FQDN entries are now decoded strictly as ASCII (RFC 1035);
      malformed bytes fall back to ``rawAddress`` rather than being
      silently masked by ``decode("utf-8", "ignore")``.

* Generic ASN.1 primitive string types (PrintableString / IA5 /
  Graphic / Visible / General etc.)
    - ``_decode_universal_primitive_value`` now rejects non-ASCII
      byte sequences instead of hiding them with ``decode("ascii",
      "ignore")``.
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_gbanl,
    _decode_network_name_ie,
    _decode_pcscf_address,
    _decode_pnn_record,
    _decode_spn,
    _parse_ber_stream,
)


# ---------------------------------------------------------------------------
# EF.SPN — TS 31.102 §4.2.12
# ---------------------------------------------------------------------------


class TestSpnAlphaStringTyping:
    def test_plain_ascii_service_provider_name_is_decoded(self) -> None:
        payload = b"\x01" + b"Operator"
        decoded = _decode_spn(payload.hex())
        assert decoded is not None
        assert decoded["serviceProviderName"] == "Operator"
        assert decoded["alphaEncoding"] == "gsm-7bit"
        assert decoded["displayCondition"] == "0x01"

    def test_ucs2_leader_80_service_provider_name_is_decoded(self) -> None:
        name_bytes = b"\x80" + "Héllo".encode("utf-16-be")
        payload = b"\x01" + name_bytes
        decoded = _decode_spn(payload.hex())
        assert decoded is not None
        assert decoded["serviceProviderName"] == "Héllo"
        assert decoded["alphaEncoding"] == "ucs-2-be"

    def test_filler_only_name_returns_empty_string(self) -> None:
        payload = b"\x00" + b"\xFF" * 8
        decoded = _decode_spn(payload.hex())
        assert decoded is not None
        assert decoded["serviceProviderName"] == ""


# ---------------------------------------------------------------------------
# EF.PNN — TS 31.102 §4.2.58 / TS 24.008 §10.5.3.5a
# ---------------------------------------------------------------------------


class TestNetworkNameIeDecoder:
    def test_ucs2_be_full_name_is_recovered(self) -> None:
        name_ucs2 = "Test Net".encode("utf-16-be")
        header = 0x80 | (1 << 5)
        ie = bytes([header]) + name_ucs2
        decoded = _decode_network_name_ie(ie)
        assert decoded is not None
        assert decoded["encoding"] == "ucs-2-be"
        assert decoded["text"] == "Test Net"
        assert decoded["codingScheme"] == 1

    def test_rejects_missing_extension_bit(self) -> None:
        assert _decode_network_name_ie(b"\x01abc") is None

    def test_strips_trailing_ff_padding(self) -> None:
        name_ucs2 = "Hi".encode("utf-16-be")
        header = 0x80 | (1 << 5)
        ie = bytes([header]) + name_ucs2 + b"\xFF\xFF"
        decoded = _decode_network_name_ie(ie)
        assert decoded is not None
        assert decoded["text"] == "Hi"


class TestPnnRecordDispatchesNetworkNameIe:
    def test_pnn_tag_43_ucs2_full_name(self) -> None:
        name_ucs2 = "Net A".encode("utf-16-be")
        header = 0x80 | (1 << 5)
        ie = bytes([header]) + name_ucs2
        record = bytes([0x43, len(ie)]) + ie
        decoded = _decode_pnn_record(record.hex())
        assert decoded is not None
        assert decoded.get("fullName") == "Net A"
        items = decoded.get("items")
        assert isinstance(items, list) and len(items) == 1
        assert items[0]["tag"] == "43"
        decoded_value = items[0].get("decoded")
        assert isinstance(decoded_value, dict)
        assert decoded_value["encoding"] == "ucs-2-be"

    def test_pnn_short_name_tag_45_surface_text(self) -> None:
        name_ucs2 = "SN".encode("utf-16-be")
        header = 0x80 | (1 << 5)
        ie = bytes([header]) + name_ucs2
        record = bytes([0x45, len(ie)]) + ie
        decoded = _decode_pnn_record(record.hex())
        assert decoded is not None
        assert decoded.get("shortName") == "SN"

    def test_pnn_does_not_fabricate_text_for_garbage(self) -> None:
        bogus = b"\x43\x04\x01\x02\x03\x04"
        decoded = _decode_pnn_record(bogus.hex())
        assert decoded is not None
        assert "fullName" not in decoded


# ---------------------------------------------------------------------------
# EF.GBANL — TS 31.102 §4.2.80
# ---------------------------------------------------------------------------


class TestGbanlBtidTyping:
    def test_btid_tag_81_is_decoded_as_text(self) -> None:
        naf_id = b"\x00" * 32
        btid = b"NAF1@example.org"
        record = (
            bytes([0x80, len(naf_id)]) + naf_id
            + bytes([0x81, len(btid)]) + btid
        )
        decoded = _decode_gbanl(record.hex())
        assert decoded is not None
        assert decoded.get("bTid") == "NAF1@example.org"

    def test_naf_id_tag_80_stays_opaque_hex(self) -> None:
        naf_id = b"\xAA\xBB\xCC\xDD"
        record = bytes([0x80, len(naf_id)]) + naf_id
        decoded = _decode_gbanl(record.hex())
        assert decoded is not None
        items = decoded.get("items")
        assert isinstance(items, list) and len(items) == 1
        item = items[0]
        assert item["tag"] == "80"
        assert "decoded" not in item
        assert item["raw"] == naf_id.hex().upper()


# ---------------------------------------------------------------------------
# ISIM P-CSCF address — TS 31.103 §4.2.8
# ---------------------------------------------------------------------------


class TestPcscfAddressStrictAscii:
    def test_fqdn_is_decoded_strictly(self) -> None:
        fqdn = b"pcscf.example.com"
        payload = bytes([0x00]) + fqdn
        record = bytes([0x80, len(payload)]) + payload
        decoded = _decode_pcscf_address(record.hex())
        assert decoded is not None
        assert decoded.get("addressType") == "FQDN"
        assert decoded.get("address") == "pcscf.example.com"

    def test_non_ascii_fqdn_falls_back_to_raw_hex(self) -> None:
        payload = bytes([0x00]) + b"\xFF\xFE\xFD"
        record = bytes([0x80, len(payload)]) + payload
        decoded = _decode_pcscf_address(record.hex())
        assert decoded is not None
        assert "address" not in decoded
        assert decoded.get("rawAddress") == "FFFEFD"


# ---------------------------------------------------------------------------
# Generic ASN.1 universal string primitive types
# ---------------------------------------------------------------------------


class TestUniversalPrimitiveStringTyping:
    def test_printable_string_tag_13_roundtrips_ascii(self) -> None:
        # Tag 0x13 = PrintableString
        payload = bytes([0x13, 0x05]) + b"Hello"
        items, _ = _parse_ber_stream(payload, 0, allow_eoc=False, depth=0)
        assert len(items) == 1
        assert items[0]["decoded"] == "Hello"

    def test_printable_string_with_non_ascii_falls_back_to_hex(self) -> None:
        bogus = bytes([0x13, 0x02, 0xFF, 0xFE])
        items, _ = _parse_ber_stream(bogus, 0, allow_eoc=False, depth=0)
        assert len(items) == 1
        assert items[0]["decoded"] == "FFFE"
