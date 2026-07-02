# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Round-6 Sweep 4 — structured round-trip encoder coverage for the
Round-4 / Round-5 PE-body decoders.

Each test asserts two invariants for one field:

1. **Hex passthrough** — when ``hex`` is present on the decoded form
   the encoder returns identical bytes (lossless verbatim path that
   keeps legacy JSON documents stable).
2. **Structured re-encode** — when ``hex`` is stripped the encoder
   must rebuild the on-card bytes from the decoder's spec-named
   fields (OID dotted string, bit flags, TLV items, etc.).

References:
  * SAIP §2.8.2 (applicationProviderIdentifier)
  * SAIP §2.6.3 Table 2-6 (globalServiceParameters)
  * GlobalPlatform Card Spec Amd A §A.3 (implicitSelectionParameter)
  * GlobalPlatform Card Spec Amd C §5 (contactlessProtocolParameters)
  * GlobalPlatform Card Spec Amd C §6 (userInteractionContactlessParameters)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_application_provider_identifier,
    _decode_contactless_protocol_parameters,
    _decode_global_service_parameters,
    _decode_implicit_selection_parameter,
    _decode_user_interaction_contactless_parameters,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_decoded_roundtrip_bytes,
    roundtrip_capable_fields,
)


class TestRoundtripRegistration:
    def test_all_five_fields_registered_as_bytes(self) -> None:
        capable = roundtrip_capable_fields()
        for field_name in (
            "applicationProviderIdentifier",
            "globalServiceParameters",
            "implicitSelectionParameter",
            "contactlessProtocolParameters",
            "userInteractionContactlessParameters",
        ):
            assert capable.get(field_name) == "bytes"


class TestApplicationProviderIdentifier:
    def test_hex_passthrough_roundtrips(self) -> None:
        raw = bytes.fromhex("2A864886F7000101")
        decoded = _decode_application_provider_identifier(raw)
        assert decoded is not None
        assert decoded["oid"] == "1.2.840.113536.1.1"
        encoded = encode_decoded_roundtrip_bytes(
            "applicationProviderIdentifier",
            decoded,
        )
        assert encoded == raw

    def test_oid_only_reconstructs_bytes(self) -> None:
        raw = bytes.fromhex("2A864886F7000101")
        decoded = _decode_application_provider_identifier(raw)
        assert decoded is not None
        decoded_without_hex = dict(decoded)
        decoded_without_hex.pop("hex")
        encoded = encode_decoded_roundtrip_bytes(
            "applicationProviderIdentifier",
            decoded_without_hex,
        )
        assert encoded == raw

    def test_missing_both_hex_and_oid_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "applicationProviderIdentifier",
                {"format": "Application Provider OID"},
            )

    def test_short_oid_is_rejected(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "applicationProviderIdentifier",
                {"oid": "1"},
            )


class TestGlobalServiceParameters:
    def test_hex_passthrough_roundtrips(self) -> None:
        raw = bytes.fromhex("A8")
        decoded = _decode_global_service_parameters(raw)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes(
            "globalServiceParameters",
            decoded,
        )
        assert encoded == raw

    def test_bitmap_string_reconstructs(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "globalServiceParameters",
            {"bitmap": "0xA8"},
        )
        assert encoded == bytes([0xA8])

    def test_active_services_reconstructs(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "globalServiceParameters",
            {
                "activeServices": [
                    "Global PIN",
                    "Secure messaging",
                    "Application selection assisted",
                ]
            },
        )
        assert encoded == bytes([0xA8])

    def test_unknown_service_name_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "globalServiceParameters",
                {"activeServices": ["Nonexistent service"]},
            )

    def test_missing_all_forms_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "globalServiceParameters",
                {"format": "Global Service Parameters"},
            )


class TestImplicitSelectionParameter:
    def test_hex_passthrough_roundtrips(self) -> None:
        raw = bytes.fromhex("83")
        decoded = _decode_implicit_selection_parameter(raw)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes(
            "implicitSelectionParameter",
            decoded,
        )
        assert encoded == raw

    def test_structured_reconstructs_bytes(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "implicitSelectionParameter",
            {"defaultSelected": True, "channelMask": "0x03"},
        )
        assert encoded == bytes([0x83])

    def test_channel_mask_integer_also_accepted(self) -> None:
        encoded = encode_decoded_roundtrip_bytes(
            "implicitSelectionParameter",
            {"defaultSelected": False, "channelMask": 0x1F},
        )
        assert encoded == bytes([0x1F])

    def test_channel_mask_out_of_range_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "implicitSelectionParameter",
                {"defaultSelected": False, "channelMask": 0x7F},
            )

    def test_missing_fields_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "implicitSelectionParameter",
                {"format": "Implicit Selection Parameter"},
            )


class TestContactlessProtocolParameters:
    def test_hex_passthrough_roundtrips(self) -> None:
        raw = bytes.fromhex("80010182025678")
        decoded = _decode_contactless_protocol_parameters(raw)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes(
            "contactlessProtocolParameters",
            decoded,
        )
        assert encoded == raw

    def test_items_only_reconstructs(self) -> None:
        raw = bytes.fromhex("80010182025678")
        decoded = _decode_contactless_protocol_parameters(raw)
        assert decoded is not None
        decoded_without_hex = dict(decoded)
        decoded_without_hex.pop("hex")
        encoded = encode_decoded_roundtrip_bytes(
            "contactlessProtocolParameters",
            decoded_without_hex,
        )
        assert encoded == raw

    def test_missing_hex_and_items_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "contactlessProtocolParameters",
                {"format": "Contactless Protocol Parameters"},
            )


class TestUserInteractionContactlessParameters:
    def test_hex_passthrough_roundtrips(self) -> None:
        raw = bytes.fromhex("8001018206746167676564")
        decoded = _decode_user_interaction_contactless_parameters(raw)
        assert decoded is not None
        encoded = encode_decoded_roundtrip_bytes(
            "userInteractionContactlessParameters",
            decoded,
        )
        assert encoded == raw

    def test_items_reconstructs_text_decoded(self) -> None:
        raw = bytes.fromhex("8001018206746167676564")
        decoded = _decode_user_interaction_contactless_parameters(raw)
        assert decoded is not None
        decoded_without_hex = dict(decoded)
        decoded_without_hex.pop("hex")
        encoded = encode_decoded_roundtrip_bytes(
            "userInteractionContactlessParameters",
            decoded_without_hex,
        )
        assert encoded == raw

    def test_missing_hex_and_items_raises(self) -> None:
        with pytest.raises(RoundtripEncoderError):
            encode_decoded_roundtrip_bytes(
                "userInteractionContactlessParameters",
                {"format": "User Interaction Contactless Parameters"},
            )
