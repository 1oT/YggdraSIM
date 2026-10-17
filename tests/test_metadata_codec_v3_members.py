# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.22 v3.1 §5.5.3 StoreMetadataRequest members, and the BIT STRING they ride on.

These tests fail closed against an unpatched pySim: ``asn1tools`` drops a
payload key the compiled schema does not define without raising, so a reverted
``pysim/`` would otherwise encode profiles with the fields quietly missing.
The schema extension lives in
``upstream_patches/osmocom-pysim-rsp-v3-metadata/``.
"""

from __future__ import annotations

import unittest
from unittest import mock

from SCP11.local_access import metadata_codec
from SCP11.local_access.metadata_codec import (
    NOTIFICATION_EVENT_ORDER,
    PROFILE_POLICY_RULE_ORDER,
    _bitstring_from_named_flags,
    build_store_metadata_request_payload,
    encode_store_metadata_request,
)
from SCP11.shared.pysim_support import decode_rsp_type, rsp_type_members

# The ten members the schema extension adds (SGP.22 v3.1 §5.5.3). Upstream
# pySim defines StoreMetadataRequest at v2 and carries none of them, so a
# stock install cannot reach the wire for any of them and the encoder refuses
# rather than dropping them -- which SchemaGapFailsClosedTests pins, on every
# tree, by stubbing the member set.
_V3_MEMBERS = frozenset(
    {
        "rpmConfiguration",
        "hriServerAddress",
        "lprConfiguration",
        "enterpriseConfiguration",
        "serviceProviderMessage",
        "serviceDescription",
        "deviceChangeConfiguration",
        "estimatedProfileSize",
        "serviceSpecificDataStoredInEuicc",
        "serviceSpecificDataNotStoredInEuicc",
    }
)
_SCHEMA_CARRIES_V3 = _V3_MEMBERS <= rsp_type_members("StoreMetadataRequest")


class SchemaSupplementTests(unittest.TestCase):
    """``SCP11.rsp_v3_schema`` declares what upstream pySim omits."""

    def test_compiled_schema_carries_every_v3_member(self) -> None:
        # Not a precondition: YggdraSIM supplies these itself, so a schema
        # without them means the supplement stopped applying -- most likely
        # because upstream reformatted the anchor line. The reachability
        # tests below skip in that case; this one names the cause.
        missing = sorted(_V3_MEMBERS - rsp_type_members("StoreMetadataRequest"))
        self.assertEqual(
            missing,
            [],
            "SCP11.rsp_v3_schema did not declare "
            + ", ".join(missing)
            + "; see upstream_patches/osmocom-pysim-rsp-v3-metadata/",
        )

    def test_supplement_is_skipped_once_upstream_declares_them(self) -> None:
        # Self-retiring: applied to a schema that already has the members,
        # the anchor is absent and the text comes back untouched.
        from SCP11.rsp_v3_schema import apply_v3_metadata_supplement

        already_current = "StoreMetadataRequest ::= SEQUENCE {\n    iccid [0] Iccid\n}\n"
        self.assertEqual(
            apply_v3_metadata_supplement(already_current), already_current
        )

    def test_supplement_patches_store_metadata_not_a_namesake(self) -> None:
        # The anchor line occurs in three types. A first-match replace
        # patches the wrong one and yields a nine-member schema silently.
        from SCP11.rsp_v3_schema import apply_v3_metadata_supplement

        tail = "    profilePolicyRules [25] PprIds OPTIONAL -- Tag '99'\n}"
        schema = (
            "ProfileInfo ::= SEQUENCE {\n" + tail + "\n\n"
            "StoreMetadataRequest ::= SEQUENCE {\n" + tail + "\n"
        )
        patched = apply_v3_metadata_supplement(schema)
        profile_info, store_metadata = patched.split("StoreMetadataRequest ::=")
        self.assertNotIn("estimatedProfileSize", profile_info)
        self.assertIn("estimatedProfileSize", store_metadata)

_PROFILE = {
    "iccid": "8988201234567890123",
    "name": "Test Profile",
    "profile_class": "operational",
}
_OPERATOR = {"name": "SP", "mcc": "001", "mnc": "01"}


def _document(v3: dict | None = None) -> dict:
    document: dict = {"profile": dict(_PROFILE), "operator": dict(_OPERATOR)}
    if v3 is not None:
        document["v3"] = v3
    return document


def _round_trip(v3: dict) -> dict:
    return decode_rsp_type(
        "StoreMetadataRequest", encode_store_metadata_request(_document(v3))
    )


class BitStringWidthTests(unittest.TestCase):
    """``asn1tools`` reads the tuple as (payload, significant bits).

    The packer returned the unused-bit count instead, which understated every
    named bit string in the request.
    """

    def test_notification_event_keeps_all_eight_bits(self) -> None:
        # Eight flags used to give an unused count of 0, which asn1tools read
        # as "zero significant bits" -- the card got an empty BIT STRING.
        bits = _bitstring_from_named_flags(
            {name: True for name in NOTIFICATION_EVENT_ORDER},
            NOTIFICATION_EVENT_ORDER,
        )
        self.assertEqual(bits, (b"\xFF", 8))

    def test_ppr_ids_declares_the_three_bits_the_type_defines(self) -> None:
        bits = _bitstring_from_named_flags(
            {"disable_not_allowed": True}, PROFILE_POLICY_RULE_ORDER
        )
        self.assertEqual(bits, (b"\x40", 3))

    def test_notification_events_survive_the_encoder(self) -> None:
        document = _document()
        document["notification_events"] = {
            "address": "notify.example.test",
            **{name: True for name in NOTIFICATION_EVENT_ORDER},
        }
        decoded = decode_rsp_type(
            "StoreMetadataRequest", encode_store_metadata_request(document)
        )
        entry = decoded["notificationConfigurationInfo"][0]
        self.assertEqual(entry["profileManagementOperation"], (b"\xFF", 8))

    def test_ppr_ids_encode_with_five_unused_bits(self) -> None:
        document = _document()
        document["policy_rules"] = {"disable_not_allowed": True}
        encoded = encode_store_metadata_request(document).hex().upper()
        # Tag '99', length 02, unused-bit octet 05, payload 40.
        self.assertIn("99020540", encoded)


@unittest.skipUnless(
    _SCHEMA_CARRIES_V3,
    "The pySim in use defines StoreMetadataRequest at SGP.22 v2. Apply "
    "upstream_patches/osmocom-pysim-rsp-v3-metadata/ to exercise these.",
)
class V3MemberReachabilityTests(unittest.TestCase):
    """Each v3 member reaches the wire under the tag §5.5.3 assigns it."""

    def test_absent_v3_block_changes_nothing(self) -> None:
        self.assertEqual(
            encode_store_metadata_request(_document()),
            encode_store_metadata_request(_document({})),
        )

    def test_hri_server_address(self) -> None:
        decoded = _round_trip({"hri_server_address": "hri.example.test"})
        self.assertEqual(decoded["hriServerAddress"], "hri.example.test")

    def test_estimated_profile_size(self) -> None:
        self.assertEqual(
            _round_trip({"estimated_profile_size": 65536})["estimatedProfileSize"],
            65536,
        )

    def test_negative_estimated_profile_size_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            encode_store_metadata_request(_document({"estimated_profile_size": -1}))

    def test_service_description(self) -> None:
        decoded = _round_trip({"service_description": {"voice": True, "data": True}})
        self.assertEqual(decoded["serviceDescription"], (b"\xC0", 2))

    def test_service_provider_message_omits_the_default_language(self) -> None:
        decoded = _round_trip({"service_provider_message": {"message": "hello"}})
        self.assertEqual(decoded["serviceProviderMessage"]["message"], "hello")
        # Omitted on the wire; the decoder supplies the ASN.1 DEFAULT.
        self.assertEqual(decoded["serviceProviderMessage"]["languageTag"], "en")

    def test_service_provider_message_carries_a_non_default_language(self) -> None:
        decoded = _round_trip(
            {"service_provider_message": {"language_tag": "sv", "message": "hej"}}
        )
        self.assertEqual(decoded["serviceProviderMessage"]["languageTag"], "sv")

    def test_lpr_configuration(self) -> None:
        decoded = _round_trip(
            {
                "lpr_configuration": {
                    "pcmp_address": "pcmp.example.test",
                    "dpi_enable": "dpi",
                    "trigger_lpr_on_enable_profile": True,
                }
            }
        )
        lpr = decoded["lprConfiguration"]
        self.assertEqual(lpr["pcmpAddress"], "pcmp.example.test")
        self.assertEqual(lpr["dpiEnable"], "dpi")
        self.assertIn("triggerLprOnEnableProfile", lpr)

    def test_enterprise_configuration_with_rules(self) -> None:
        decoded = _round_trip(
            {
                "enterprise_configuration": {
                    "enterprise_oid": "1.3.6.1.4.1.1",
                    "enterprise_name": "Acme",
                    "enterprise_rules": {
                        "priority_enterprise_profile": True,
                        "number_of_non_enterprise_profiles": 2,
                    },
                }
            }
        )
        enterprise = decoded["enterpriseConfiguration"]
        self.assertEqual(enterprise["enterpriseOid"], "1.3.6.1.4.1.1")
        rules = enterprise["enterpriseRules"]
        self.assertEqual(rules["numberOfNonEnterpriseProfiles"], 2)
        self.assertEqual(rules["enterpriseRuleBits"], (b"\x40", 3))

    def test_over_long_enterprise_name_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            encode_store_metadata_request(
                _document(
                    {
                        "enterprise_configuration": {
                            "enterprise_oid": "1.3.6.1.4.1.1",
                            "enterprise_name": "x" * 65,
                        }
                    }
                )
            )

    def test_rpm_configuration(self) -> None:
        decoded = _round_trip(
            {
                "rpm_configuration": {
                    "profile_owner_oid": "1.3.6.1.4.1.3",
                    "polling_address": "smdp.example.test",
                    "managing_dp_list": [
                        {
                            "managing_dp_oid": "1.3.6.1.4.1.2",
                            "rpm_type": {"enable": True, "disable": True},
                            "tag_list_hex": "5C03",
                        },
                        {"managing_dp_oid": "1.3.6.1.4.1.5"},
                    ],
                }
            }
        )
        rpm = decoded["rpmConfiguration"]
        self.assertEqual(rpm["profileOwnerOid"], "1.3.6.1.4.1.3")
        self.assertEqual(rpm["pollingAddress"], "smdp.example.test")
        self.assertEqual(len(rpm["managingDpList"]), 2)
        first = rpm["managingDpList"][0]
        self.assertEqual(first["rpmType"], (b"\xC0", 5))
        self.assertEqual(first["tagList"], bytes.fromhex("5C03"))

    def test_managing_dp_row_without_an_oid_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            encode_store_metadata_request(
                _document(
                    {
                        "rpm_configuration": {
                            "profile_owner_oid": "1.3.6.1.4.1.3",
                            "managing_dp_list": [{"polling_address": "x"}],
                        }
                    }
                )
            )

    def test_device_change_using_stored_activation_code(self) -> None:
        decoded = _round_trip(
            {
                "device_change_configuration": {
                    "using_stored_ac": {
                        "activation_code": "1$smdp.example.test$TOKEN",
                        "delete_old_profile": True,
                    }
                }
            }
        )
        alternative, value = decoded["deviceChangeConfiguration"]
        self.assertEqual(alternative, "usingStoredAc")
        self.assertEqual(value["activationCodeForDc"], "1$smdp.example.test$TOKEN")
        self.assertIn("deleteOldProfile", value)

    def test_device_change_request_to_dp(self) -> None:
        decoded = _round_trip(
            {
                "device_change_configuration": {
                    "request_to_dp": {
                        "smdp_address": "smdp.example.test",
                        "eid_required": True,
                    }
                }
            }
        )
        alternative, value = decoded["deviceChangeConfiguration"]
        self.assertEqual(alternative, "requestToDp")
        self.assertEqual(value["smdpAddressForDc"], "smdp.example.test")
        self.assertIn("eidRequired", value)
        self.assertNotIn("tacRequired", value)

    def test_device_change_without_either_alternative_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            encode_store_metadata_request(
                _document({"device_change_configuration": {"request_to_dp": {}}})
            )

    def test_vendor_specific_extensions(self) -> None:
        decoded = _round_trip(
            {
                "service_specific_data_stored_in_euicc": [
                    {"vendor_oid": "1.3.6.1.4.1.4", "vendor_data_hex": "0402AABB"}
                ],
                "service_specific_data_not_stored_in_euicc": [
                    {"vendor_oid": "1.3.6.1.4.1.5", "vendor_data_hex": "040100"}
                ],
            }
        )
        stored = decoded["serviceSpecificDataStoredInEuicc"][0]
        self.assertEqual(stored["vendorOid"], "1.3.6.1.4.1.4")
        self.assertEqual(stored["vendorSpecificData"], bytes.fromhex("0402AABB"))
        self.assertEqual(
            decoded["serviceSpecificDataNotStoredInEuicc"][0]["vendorOid"],
            "1.3.6.1.4.1.5",
        )

    def test_vendor_extension_with_odd_length_hex_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            encode_store_metadata_request(
                _document(
                    {
                        "service_specific_data_stored_in_euicc": [
                            {"vendor_oid": "1.3.6.1.4.1.4", "vendor_data_hex": "ABC"}
                        ]
                    }
                )
            )


class V3PayloadShapeTests(unittest.TestCase):
    """The payload builder stays additive over the v2 member set."""

    def test_v2_members_are_untouched_by_a_v3_block(self) -> None:
        without = build_store_metadata_request_payload(_document())
        with_v3 = build_store_metadata_request_payload(
            _document({"hri_server_address": "hri.example.test"})
        )
        for key, value in without.items():
            self.assertEqual(with_v3[key], value)

    def test_only_populated_v3_members_appear(self) -> None:
        payload = build_store_metadata_request_payload(
            _document({"hri_server_address": "hri.example.test"})
        )
        self.assertIn("hriServerAddress", payload)
        for absent in (
            "rpmConfiguration",
            "lprConfiguration",
            "enterpriseConfiguration",
            "serviceDescription",
            "deviceChangeConfiguration",
            "estimatedProfileSize",
            "serviceProviderMessage",
        ):
            self.assertNotIn(absent, payload)


class SchemaGapFailsClosedTests(unittest.TestCase):
    """The encoder refuses a member the compiled schema cannot represent.

    Independent of which pySim supplied the schema: the member set is stubbed
    so the test states the same thing against a patched and an unpatched tree.
    """

    def test_missing_member_raises_instead_of_encoding(self) -> None:
        with mock.patch.object(
            metadata_codec, "rsp_type_members", return_value=frozenset({"iccid"})
        ):
            with self.assertRaises(RuntimeError) as raised:
                metadata_codec.encode_store_metadata_request(
                    _document({"estimated_profile_size": 65536})
                )
        message = str(raised.exception)
        self.assertIn("estimatedProfileSize", message)
        self.assertIn("osmocom-pysim-rsp-v3-metadata", message)

    def test_unknown_member_set_defers_to_the_encoder(self) -> None:
        # An empty set means "could not introspect", not "defines nothing" --
        # rejecting there would refuse every document whenever the codec is
        # unavailable, which the empty-encoding check already reports better.
        with mock.patch.object(
            metadata_codec, "rsp_type_members", return_value=frozenset()
        ):
            with mock.patch.object(
                metadata_codec, "encode_rsp_type", return_value=b"\x01\x02"
            ):
                self.assertEqual(
                    metadata_codec.encode_store_metadata_request(_document()),
                    b"\x01\x02",
                )

    def test_a_schema_carrying_every_member_encodes(self) -> None:
        payload = build_store_metadata_request_payload(
            _document({"estimated_profile_size": 65536})
        )
        with mock.patch.object(
            metadata_codec, "rsp_type_members", return_value=frozenset(payload)
        ):
            with mock.patch.object(
                metadata_codec, "encode_rsp_type", return_value=b"\x03"
            ):
                self.assertEqual(
                    metadata_codec.encode_store_metadata_request(
                        _document({"estimated_profile_size": 65536})
                    ),
                    b"\x03",
                )


if __name__ == "__main__":
    unittest.main()
