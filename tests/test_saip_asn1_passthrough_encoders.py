# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Wave A — pass-through round-trip guards for the SAIP decoded editor.

Each field below is a tagged-bytes OCTET STRING whose decoded view is a
hex summary and whose encoder re-emits the original bytes verbatim
(``_encode_tagged_hex_passthrough``). The fields come from four
distinct surfaces:

- GlobalPlatform Amendment A memory quotas / reserved memory (C7/C8).
- GP / TS 102 226 system-specific install parameters.
- UICC application-specific parameters (TS 102 226 §8.2.1.3.2).
- GSMA SAIP Annex D — PE-CDMAParameter authentication credentials.
- PE-NonStandard / PE-SecurityDomain.openPersoData opaque blobs.
- ProfileHeader.eUICC-Mandatory-AIDs child fields (aid, version).
- TS102226AdditionalContactlessParameters.protocolParameterData.
- IotOptions.pix.

The test locks the encode/decode pair's byte-identity on a
representative non-trivial sample and asserts that
``roundtrip_capable_fields`` exposes the field under the ``"bytes"``
label. AID aliases are round-tripped through the AID encoder so that
``aid`` / ``extraditeSecurityDomainAID`` pick up the existing
``encode_application_identifier`` path.
"""

import unittest

from Tools.ProfilePackage.saip_asn1_decode import (
    _AID_FIELD_NAMES,
    _decode_special_field,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    RoundtripEncoderError,
    encode_decoded_roundtrip_bytes,
    roundtrip_capable_fields,
)


_PASSTHROUGH_FIELDS: tuple[str, ...] = (
    "volatileMemoryQuotaC7",
    "nonVolatileMemoryQuotaC8",
    "volatileReservedMemory",
    "nonVolatileReservedMemory",
    "cumulativeGrantedVolatileMemory",
    "cumulativeGrantedNonVolatileMemory",
    "globalServiceParameters",
    "implicitSelectionParameter",
    "ts102226SIMFileAccessToolkitParameter",
    "contactlessProtocolParameters",
    "userInteractionContactlessParameters",
    "uiccAccessApplicationSpecificParametersField",
    "uiccAdministrativeAccessApplicationSpecificParametersField",
    "applicationProviderIdentifier",
    "loadBlockObject",
    "restrictParameter",
    "content",
    "authenticationKey",
    "ssd",
    "hrpdAccessAuthenticationData",
    "simpleIPAuthenticationData",
    "mobileIPAuthenticationData",
    "version",
    "protocolParameterData",
    "pix",
)


_SAMPLE_BYTES = bytes.fromhex("A0B1C203D4E506F7")


class PassthroughEncoderRoundTripTests(unittest.TestCase):
    def test_fields_are_registered_as_roundtrip_bytes(self):
        capable = roundtrip_capable_fields()
        for field_name in _PASSTHROUGH_FIELDS:
            kind = capable.get(field_name)
            self.assertEqual(
                kind,
                "bytes",
                msg=f"{field_name!r} must be registered with kind='bytes'",
            )

    def test_round_trip_identity(self):
        for field_name in _PASSTHROUGH_FIELDS:
            decoded = _decode_special_field(field_name, _SAMPLE_BYTES)
            self.assertIsInstance(
                decoded,
                dict,
                msg=f"{field_name!r}: decoder returned non-dict",
            )
            self.assertEqual(
                decoded.get("hex"),
                _SAMPLE_BYTES.hex().upper(),
                msg=f"{field_name!r}: hex payload mismatch",
            )
            self.assertEqual(
                decoded.get("length"),
                len(_SAMPLE_BYTES),
                msg=f"{field_name!r}: length payload mismatch",
            )
            encoded = encode_decoded_roundtrip_bytes(field_name, decoded)
            self.assertEqual(
                encoded,
                _SAMPLE_BYTES,
                msg=f"{field_name!r}: round-trip byte mismatch",
            )

    def test_empty_hex_is_rejected(self):
        for field_name in _PASSTHROUGH_FIELDS:
            with self.assertRaises(
                RoundtripEncoderError,
                msg=f"{field_name!r}: empty payload must be rejected",
            ):
                encode_decoded_roundtrip_bytes(field_name, {"hex": ""})

    def test_non_hex_payload_is_rejected(self):
        for field_name in _PASSTHROUGH_FIELDS:
            with self.assertRaises(RoundtripEncoderError):
                encode_decoded_roundtrip_bytes(field_name, {"hex": "ZZ"})


class AidAliasRoundTripTests(unittest.TestCase):
    _AID_PAYLOAD = bytes.fromhex("A000000087300001000000000000")

    def test_aid_aliases_are_registered(self):
        self.assertIn("extraditeSecurityDomainAID", _AID_FIELD_NAMES)
        self.assertIn("aid", _AID_FIELD_NAMES)

    def test_aid_aliases_round_trip_through_aid_encoder(self):
        expected_hex = self._AID_PAYLOAD.hex().upper()
        for alias in ("extraditeSecurityDomainAID", "aid"):
            decoded = _decode_special_field(alias, self._AID_PAYLOAD)
            self.assertIsInstance(decoded, dict, msg=f"{alias}: decoder result")
            self.assertEqual(
                str(decoded.get("aid") or "").upper(),
                expected_hex,
                msg=f"{alias}: decoded 'aid' field mismatch",
            )
            encoded = encode_decoded_roundtrip_bytes(alias, decoded)
            self.assertEqual(
                encoded,
                self._AID_PAYLOAD,
                msg=f"{alias}: round-trip byte mismatch",
            )


if __name__ == "__main__":
    unittest.main()
