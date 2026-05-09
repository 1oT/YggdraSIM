"""
Round-4 Pass 3 regression tests for ProfileElement body field decoders.

Covers the four SAIP ASN.1 octet-string fields that were previously dumped
as opaque hex via ``_summarize_binary_blob``:

- ``applicationProviderIdentifier``  -> OBJECT IDENTIFIER (SAIP §2.8.2)
- ``globalServiceParameters``        -> 1-byte service bitmap (SAIP §2.6.3)
- ``implicitSelectionParameter``     -> 1-byte selection flags (GP Amd A §A.3)
- ``contactlessProtocolParameters``  -> BER-TLV stream (GP Amd C §5)

The decoders hang off ``_decode_special_field`` which is the dispatcher
used by the edit-decoded TUI when annotating PE payload fields.
"""

from __future__ import annotations

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_application_provider_identifier,
    _decode_contactless_protocol_parameters,
    _decode_global_service_parameters,
    _decode_implicit_selection_parameter,
    _decode_special_field,
    _decode_user_interaction_contactless_parameters,
)


class ApplicationProviderIdentifierTests(unittest.TestCase):
    """``applicationProviderIdentifier`` holds a BER-encoded OID."""

    def test_oid_2_23_143_1_2_1(self) -> None:
        # 2.23.143.1.2.1 encodes to 67 81 0F 01 02 01 (first two arcs
        # packed, 143 = 0x8F -> base-128 [0x81, 0x0F]).
        payload = bytes.fromhex("67810F010201")
        decoded = _decode_application_provider_identifier(payload)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["format"], "Application Provider OID")
        self.assertEqual(decoded["oid"], "2.23.143.1.2.1")
        self.assertEqual(decoded["reference"], "SAIP §2.8.2")

    def test_dispatcher_wires_the_decoder(self) -> None:
        payload = bytes.fromhex("2B0601040182370102")
        decoded = _decode_special_field(
            "applicationProviderIdentifier", payload
        )
        self.assertIsNotNone(decoded)
        self.assertIn("oid", decoded)

    def test_empty_payload_returns_none(self) -> None:
        self.assertIsNone(_decode_application_provider_identifier(b""))


class GlobalServiceParametersTests(unittest.TestCase):
    """``globalServiceParameters`` is a 1-byte bitmap (SAIP Table 2-6)."""

    def test_no_services_set(self) -> None:
        decoded = _decode_global_service_parameters(b"\x00")
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["bitmap"], "0x00")
        self.assertEqual(decoded["activeServices"], [])

    def test_global_pin_and_secure_messaging(self) -> None:
        decoded = _decode_global_service_parameters(b"\xA0")
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["bitmap"], "0xA0")
        self.assertIn("Global PIN", decoded["activeServices"])
        self.assertIn("Secure messaging", decoded["activeServices"])

    def test_dispatcher_wires_the_decoder(self) -> None:
        decoded = _decode_special_field(
            "globalServiceParameters", b"\x80"
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["format"], "Global Service Parameters")

    def test_wrong_length_returns_none(self) -> None:
        self.assertIsNone(_decode_global_service_parameters(b"\x00\x00"))


class ImplicitSelectionParameterTests(unittest.TestCase):
    """``implicitSelectionParameter`` is a 1-byte selection flag byte."""

    def test_default_selected_all_channels(self) -> None:
        decoded = _decode_implicit_selection_parameter(b"\x9F")
        self.assertIsNotNone(decoded)
        self.assertTrue(decoded["defaultSelected"])
        self.assertEqual(decoded["channelMask"], "0x1F")

    def test_not_default_specific_channel(self) -> None:
        decoded = _decode_implicit_selection_parameter(b"\x01")
        self.assertIsNotNone(decoded)
        self.assertFalse(decoded["defaultSelected"])
        self.assertEqual(decoded["channelMask"], "0x01")

    def test_dispatcher_wires_the_decoder(self) -> None:
        decoded = _decode_special_field(
            "implicitSelectionParameter", b"\x00"
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["format"], "Implicit Selection Parameter")


class ContactlessProtocolParametersTests(unittest.TestCase):
    """``contactlessProtocolParameters`` carries BER-TLV NFC data."""

    def test_single_tlv_recognised(self) -> None:
        # 80 01 04 (protocol type=4) + 82 04 A000000096 (selector AID)
        payload = bytes.fromhex("8001048204A0000000")
        # Last length byte intentionally truncated-but-valid (4 bytes A0000000)
        payload = bytes.fromhex("800104820400112233")
        decoded = _decode_contactless_protocol_parameters(payload)
        self.assertIsNotNone(decoded)
        tags = [item.get("tag") for item in decoded["items"]]
        self.assertIn("80", tags)
        self.assertIn("82", tags)
        self.assertEqual(
            decoded["reference"], "GlobalPlatform Card Spec Amd C §5"
        )

    def test_dispatcher_wires_the_decoder(self) -> None:
        decoded = _decode_special_field(
            "contactlessProtocolParameters",
            bytes.fromhex("80010A"),
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["format"], "Contactless Protocol Parameters")

    def test_malformed_payload_returns_none(self) -> None:
        # An all-FF blob produces only parse errors; decoder returns None
        # so the caller can fall back to the ``_summarize_binary_blob`` shim.
        self.assertIsNone(
            _decode_contactless_protocol_parameters(b"\xFF" * 4)
        )


class UserInteractionContactlessParametersTests(unittest.TestCase):
    """``userInteractionContactlessParameters`` per GP Amd C §6."""

    def test_application_name_and_message_surface_as_text(self) -> None:
        # 82 04 'Name' + 84 05 'Hello'
        payload = bytes.fromhex("82044E616D658405" + b"Hello".hex())
        decoded = _decode_user_interaction_contactless_parameters(payload)
        self.assertIsNotNone(decoded)
        self.assertEqual(
            decoded["reference"], "GlobalPlatform Card Spec Amd C §6"
        )
        tag_to_text = {
            item["tag"]: item.get("decoded")
            for item in decoded["items"]
            if isinstance(item, dict)
        }
        self.assertEqual(tag_to_text.get("82"), "Name")
        self.assertEqual(tag_to_text.get("84"), "Hello")

    def test_dispatcher_wires_the_decoder(self) -> None:
        payload = bytes.fromhex("8101018302010184054E616D6531")
        decoded = _decode_special_field(
            "userInteractionContactlessParameters",
            payload,
        )
        self.assertIsNotNone(decoded)
        self.assertEqual(
            decoded["format"], "User Interaction Contactless Parameters"
        )

    def test_empty_payload_returns_none(self) -> None:
        self.assertIsNone(
            _decode_user_interaction_contactless_parameters(b"")
        )

    def test_malformed_payload_returns_none(self) -> None:
        self.assertIsNone(
            _decode_user_interaction_contactless_parameters(b"\xFF\xFF\xFF")
        )


if __name__ == "__main__":
    unittest.main()
