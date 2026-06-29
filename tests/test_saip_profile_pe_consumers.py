# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Unit coverage for the four PE consumers added on the SAIP loader side
to close the inbound-BPP gap for cdmaParameter / application /
nonStandard / ssimEaptls. Each test feeds the consumer a hand-built
decoded dict (matching what asn1tools would emit for the SAIP 3.3
schema, plus the documented 3.4 shape for SSIM-EAPTLS) and asserts the
canonical ``SimProfileImage`` projection.
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_profile import (
    _consume_application,
    _consume_cdma_parameter,
    _consume_non_standard,
    _consume_ssim_eaptls,
    _consume_profile_element,
    known_profile_element_types,
)
from SIMCARD.state import SimProfileImage


class CdmaParameterConsumerTests(unittest.TestCase):

    def test_minimum_payload_only_a_key(self):
        img = SimProfileImage()
        _consume_cdma_parameter(img, {"authenticationKey": bytes.fromhex("00112233445566AA")})
        self.assertIsNotNone(img.cdma_parameter)
        self.assertEqual(img.cdma_parameter.authentication_key.hex().upper(), "00112233445566AA")
        self.assertEqual(img.cdma_parameter.ssd, b"")

    def test_optional_blobs_round_trip(self):
        img = SimProfileImage()
        _consume_cdma_parameter(
            img,
            {
                "authenticationKey": bytes(range(8)),
                "ssd": bytes(range(16)),
                "hrpdAccessAuthenticationData": b"\xaa" * 16,
                "simpleIPAuthenticationData": b"\xbb" * 9,
                "mobileIPAuthenticationData": b"\xcc" * 11,
            },
        )
        cdma = img.cdma_parameter
        self.assertIsNotNone(cdma)
        self.assertEqual(len(cdma.ssd), 16)
        self.assertEqual(len(cdma.hrpd_access_authentication_data), 16)
        self.assertEqual(len(cdma.simple_ip_authentication_data), 9)
        self.assertEqual(len(cdma.mobile_ip_authentication_data), 11)

    def test_missing_a_key_yields_nothing(self):
        img = SimProfileImage()
        _consume_cdma_parameter(img, {"authenticationKey": b""})
        self.assertIsNone(img.cdma_parameter)

    def test_wrong_a_key_length_rejected(self):
        # C.S0023 fixes the A-Key at 8 bytes; a shorter blob is invalid.
        img = SimProfileImage()
        _consume_cdma_parameter(img, {"authenticationKey": bytes.fromhex("DEADBEEF")})
        self.assertIsNone(img.cdma_parameter)

    def test_dispatch_through_consume_profile_element(self):
        img = SimProfileImage()
        _consume_profile_element(
            img,
            "cdmaParameter",
            {"authenticationKey": bytes.fromhex("0123456789ABCDEF")},
        )
        self.assertIsNotNone(img.cdma_parameter)


class ApplicationConsumerTests(unittest.TestCase):

    def _load_block(self) -> dict:
        return {
            "loadPackageAID": bytes.fromhex("A0000000871002"),
            "securityDomainAID": bytes.fromhex("A0000001515350"),
            "nonVolatileCodeLimitC6": bytes.fromhex("1000"),
            "loadBlockObject": bytes.fromhex("C402DEAD"),
        }

    def _instance(self, iaid_hex: str) -> dict:
        return {
            "applicationLoadPackageAID": bytes.fromhex("A0000000871002"),
            "classAID": bytes.fromhex("A0000000871002FF33FF"),
            "instanceAID": bytes.fromhex(iaid_hex),
            "applicationPrivileges": bytes.fromhex("00"),
            "lifeCycleState": bytes.fromhex("07"),
            "applicationSpecificParametersC9": bytes.fromhex("C900"),
            "applicationParameters": {
                "uiccToolkitApplicationSpecificParametersField": bytes.fromhex("0102"),
                "uiccAccessApplicationSpecificParametersField": bytes.fromhex("03"),
            },
            "processData": [bytes.fromhex("0A0B")],
        }

    def test_load_block_and_instance(self):
        img = SimProfileImage()
        _consume_application(
            img,
            {
                "loadBlock": self._load_block(),
                "instanceList": [self._instance("A0000000871002FF33FF01")],
            },
        )
        self.assertEqual(len(img.application_packages), 1)
        pkg = img.application_packages[0]
        self.assertEqual(pkg.load_package_aid, "A0000000871002")
        self.assertEqual(pkg.security_domain_aid, "A0000001515350")
        self.assertEqual(pkg.non_volatile_code_limit, bytes.fromhex("1000"))
        self.assertEqual(pkg.load_block_object, bytes.fromhex("C402DEAD"))

        self.assertEqual(len(img.application_instances), 1)
        inst = img.application_instances[0]
        self.assertEqual(inst.instance_aid, "A0000000871002FF33FF01")
        self.assertEqual(inst.lifecycle_state, 0x07)
        self.assertEqual(inst.application_specific_parameters, bytes.fromhex("C900"))
        self.assertEqual(inst.uicc_toolkit_parameters, bytes.fromhex("0102"))
        self.assertEqual(inst.uicc_access_parameters, bytes.fromhex("03"))
        self.assertEqual(inst.process_data, [bytes.fromhex("0A0B")])

    def test_instance_only_no_load_block(self):
        img = SimProfileImage()
        _consume_application(img, {"instanceList": [self._instance("A0000000871002FF33FF02")]})
        self.assertEqual(len(img.application_packages), 0)
        self.assertEqual(len(img.application_instances), 1)

    def test_multiple_instances_preserve_order(self):
        img = SimProfileImage()
        _consume_application(
            img,
            {
                "instanceList": [
                    self._instance("A0000000871002FF33FF03"),
                    self._instance("A0000000871002FF33FF04"),
                ]
            },
        )
        self.assertEqual(
            [i.instance_aid for i in img.application_instances],
            ["A0000000871002FF33FF03", "A0000000871002FF33FF04"],
        )

    def test_empty_payload_is_noop(self):
        img = SimProfileImage()
        _consume_application(img, {})
        self.assertEqual(img.application_packages, [])
        self.assertEqual(img.application_instances, [])


class NonStandardConsumerTests(unittest.TestCase):

    def test_oid_and_content_preserved(self):
        img = SimProfileImage()
        _consume_non_standard(
            img,
            {"issuerID": "1.3.6.1.4.1.99999.1", "content": bytes.fromhex("AABBCCDD")},
        )
        self.assertEqual(len(img.non_standard_blobs), 1)
        self.assertEqual(img.non_standard_blobs[0].issuer_oid, "1.3.6.1.4.1.99999.1")
        self.assertEqual(img.non_standard_blobs[0].content, bytes.fromhex("AABBCCDD"))

    def test_tuple_oid_form_accepted(self):
        img = SimProfileImage()
        _consume_non_standard(
            img,
            {"issuerID": (1, 3, 6, 1, 4, 1, 12345), "content": b"hi"},
        )
        self.assertEqual(img.non_standard_blobs[0].issuer_oid, "1.3.6.1.4.1.12345")

    def test_missing_oid_drops_entry(self):
        img = SimProfileImage()
        _consume_non_standard(img, {"content": b"hi"})
        self.assertEqual(img.non_standard_blobs, [])


class SsimEaptlsConsumerTests(unittest.TestCase):

    def test_full_bundle(self):
        img = SimProfileImage()
        _consume_ssim_eaptls(
            img,
            {
                "instanceAID": bytes.fromhex("A0000005591010FFFFFFFF8911000001"),
                "caCertificate": bytes.fromhex("30820100"),
                "clientCertificate": bytes.fromhex("30820200"),
                "clientCertificateChain": bytes.fromhex("30820300"),
                "clientPrivateKey": bytes.fromhex("30820400"),
            },
        )
        self.assertEqual(len(img.ssim_eaptls_bundles), 1)
        bundle = img.ssim_eaptls_bundles[0]
        self.assertEqual(bundle.instance_aid, "A0000005591010FFFFFFFF8911000001")
        self.assertEqual(bundle.ca_certificate, bytes.fromhex("30820100"))
        self.assertEqual(bundle.client_certificate, bytes.fromhex("30820200"))
        self.assertEqual(bundle.client_certificate_chain, bytes.fromhex("30820300"))
        self.assertEqual(bundle.client_private_key, bytes.fromhex("30820400"))

    def test_hyphenated_aliases_accepted(self):
        img = SimProfileImage()
        _consume_ssim_eaptls(
            img,
            {
                "instance-aid": bytes.fromhex("A000000559101000"),
                "client-certificate": bytes.fromhex("30820200"),
            },
        )
        self.assertEqual(len(img.ssim_eaptls_bundles), 1)
        bundle = img.ssim_eaptls_bundles[0]
        self.assertEqual(bundle.instance_aid, "A000000559101000")
        self.assertEqual(bundle.client_certificate, bytes.fromhex("30820200"))
        self.assertEqual(bundle.ca_certificate, b"")

    def test_dispatch_through_consume_profile_element_alias(self):
        img = SimProfileImage()
        _consume_profile_element(
            img,
            "ssim-eaptls",
            {"clientCertificate": bytes.fromhex("DEADBEEF")},
        )
        self.assertEqual(len(img.ssim_eaptls_bundles), 1)

    def test_completely_empty_payload_drops(self):
        img = SimProfileImage()
        _consume_ssim_eaptls(img, {})
        self.assertEqual(img.ssim_eaptls_bundles, [])


class ProfileHeaderConsumerTests(unittest.TestCase):
    """Full-coverage tests for ``_consume_profile_header``. Every
    documented SAIP §A.2 ProfileHeader field must be reflected on the
    ``SimProfileImage`` so a downstream consumer can read it without
    re-walking the BPP.
    """

    def test_all_documented_fields_captured(self):
        img = SimProfileImage()
        _consume_profile_element(
            img,
            "header",
            {
                "major-version": 3,
                "minor-version": 3,
                "profileType": "Lab Test Profile",
                "iccid": bytes.fromhex("98981002143256789031"),
                "pol": bytes.fromhex("04"),
                "eUICC-Mandatory-services": {"usim": None, "milenage": None},
                "eUICC-Mandatory-GFSTEList": ["2.23.143.1.2.1", "2.23.143.1.2.4"],
                "connectivityParameters": bytes.fromhex("AA01020304"),
                "eUICC-Mandatory-AIDs": [
                    {"aid": bytes.fromhex("A0000000871002"), "version": bytes.fromhex("0103")},
                ],
                "iotOptions": {"pix": bytes.fromhex("89001A1B1C1D1E")},
            },
        )
        self.assertEqual(img.profile_name, "Lab Test Profile")
        self.assertEqual(img.header_major_version, 3)
        self.assertEqual(img.header_minor_version, 3)
        # ICCID stripped of trailing 0xF (none here) and uppercased.
        self.assertEqual(img.iccid, "98981002143256789031")
        self.assertEqual(img.header_pol, bytes.fromhex("04"))
        self.assertEqual(img.header_mandatory_services, ("milenage", "usim"))
        self.assertEqual(img.header_mandatory_gfste, ("2.23.143.1.2.1", "2.23.143.1.2.4"))
        self.assertEqual(img.connectivity_params_http, bytes.fromhex("AA01020304"))
        self.assertEqual(img.header_mandatory_aids, (("A0000000871002", "0103"),))
        self.assertEqual(img.header_iot_pix, bytes.fromhex("89001A1B1C1D1E"))

    def test_minimal_header_only_versions(self):
        img = SimProfileImage()
        _consume_profile_element(img, "header", {"major-version": 3, "minor-version": 4})
        self.assertEqual(img.header_major_version, 3)
        self.assertEqual(img.header_minor_version, 4)
        self.assertEqual(img.header_pol, b"")
        self.assertEqual(img.header_mandatory_services, ())
        self.assertEqual(img.header_mandatory_aids, ())

    def test_iccid_trailing_f_nibbles_stripped(self):
        # 19-digit ICCID — encoder pads with 0xF in the low nibble of byte 9.
        img = SimProfileImage()
        _consume_profile_element(
            img,
            "header",
            {"iccid": bytes.fromhex("9898100214325678903F")},
        )
        self.assertEqual(img.iccid, "9898100214325678903")

    def test_uint8_clamping_on_out_of_range_versions(self):
        img = SimProfileImage()
        _consume_profile_element(
            img,
            "header",
            {"major-version": 999, "minor-version": -42},
        )
        self.assertEqual(img.header_major_version, 0xFF)
        self.assertEqual(img.header_minor_version, 0x00)


class DispatchTableCoverageTests(unittest.TestCase):
    """Pin the loader dispatch table against the SAIP 3.3.1 ProfileElement
    CHOICE catalogue + the SAIP 3.4 ssim / ssimEaptls extensions. A
    schema bump that adds a new CHOICE alternative must extend
    ``_PE_TYPE_DISPATCH`` here at the same time."""

    SAIP_33_NON_FS = frozenset(
        {
            "header",
            "genericFileManagement",
            "pinCodes",
            "pukCodes",
            "akaParameter",
            "cdmaParameter",
            "securityDomain",
            "rfm",
            "application",
            "nonStandard",
            "end",
        }
    )
    SAIP_33_FS = frozenset(
        {
            "mf",
            "cd",
            "telecom",
            "usim",
            "opt-usim",
            "isim",
            "opt-isim",
            "phonebook",
            "gsm-access",
            "csim",
            "opt-csim",
            "eap",
            "df-5gs",
            "df-saip",
            "df-snpn",
            "df-5gprose",
            "iot",
            "opt-iot",
        }
    )
    SAIP_34_EXT = frozenset({"ssim", "ssimEaptls"})

    def test_dispatch_table_covers_full_pe_catalogue(self):
        known = known_profile_element_types()
        required = self.SAIP_33_NON_FS | self.SAIP_33_FS | self.SAIP_34_EXT
        self.assertEqual(required - known, frozenset(), msg="PEs missing from dispatch table")

    def test_dispatch_table_accepts_ssim_eaptls_alias(self):
        # The hyphenated alias keeps salvage-walker decoded dicts that
        # use the asn1tools field-name spelling from being dropped.
        self.assertIn("ssim-eaptls", known_profile_element_types())

    def test_unknown_pe_type_does_not_raise(self):
        img = SimProfileImage()
        _consume_profile_element(img, "definitelyNotARealPE", {})
        self.assertEqual(img.nodes, [])

    def test_end_sentinel_is_noop(self):
        img = SimProfileImage()
        _consume_profile_element(img, "end", {"end-header": {}})
        self.assertEqual(img.nodes, [])
        self.assertIsNone(img.auth_config)


if __name__ == "__main__":
    unittest.main()
