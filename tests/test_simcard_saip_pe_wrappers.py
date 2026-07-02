# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression coverage for pySim ``ProfileElement*`` wrappers.

Pins the ``saip_pysim_specs.pysim_pe_wrapper`` factory plus the typed
extractors used by the ``_consume_*`` migrations:

  * ``pysim_pe_wrapper`` -- routes a decoded dict through pySim's
    ``ProfileElement.class_for_petype`` while remaining fail-soft.
  * ``pysim_sd_keys`` -- exposes ``SecurityDomainKey.from_saip_dict``
    output as frozen snapshots (KVN/KID/usage byte/components).
  * ``pysim_normalize_aka_decoded`` -- materialises the asn1tools
    ``sqnInit`` default into a 32 x 6-byte zero list (TS 35.205
    Annex E SQN init layout).
"""

from __future__ import annotations

import unittest

from SIMCARD.saip_pysim_specs import (
    pysim_normalize_aka_decoded,
    pysim_pe_wrapper,
    pysim_sd_keys,
)


class WrapperFactoryTests(unittest.TestCase):
    """``pysim_pe_wrapper`` should resolve canonical PE types."""

    def test_pin_codes_wrapper_returns_pySim_class(self) -> None:
        decoded = {
            "pin-Header": {"identification": 1, "mandated": None},
            "pinCodes": ("pinconfig", []),
        }

        wrapper = pysim_pe_wrapper("pinCodes", decoded)

        self.assertIsNotNone(wrapper)
        self.assertEqual(wrapper.type, "pinCodes")
        self.assertEqual(wrapper.decoded, decoded)

    def test_puk_codes_wrapper_returns_pySim_class(self) -> None:
        decoded = {
            "puk-Header": {"identification": 1, "mandated": None},
            "pukCodes": [],
        }

        wrapper = pysim_pe_wrapper("pukCodes", decoded)

        self.assertIsNotNone(wrapper)
        self.assertEqual(wrapper.type, "pukCodes")

    def test_rfm_wrapper_returns_pySim_class(self) -> None:
        decoded = {
            "rfm-header": {"identification": 1, "mandated": None},
            "instanceAID": b"\xa0\x00\x00\x00\x87\x10\x02",
            "tarList": [b"\xb0\x01\x00"],
            "minimumSecurityLevel": b"\x06",
            "uiccAccessDomain": b"\x02\x00\x01\x00",
            "uiccAdminAccessDomain": b"\x02\x00\x01\x00",
        }

        wrapper = pysim_pe_wrapper("rfm", decoded)

        self.assertIsNotNone(wrapper)
        self.assertEqual(wrapper.type, "rfm")
        self.assertEqual(wrapper.decoded["instanceAID"], decoded["instanceAID"])

    def test_unknown_pe_type_returns_None(self) -> None:
        wrapper = pysim_pe_wrapper("not-a-real-pe-type", {})
        self.assertIsNone(wrapper)

    def test_non_dict_decoded_returns_None(self) -> None:
        wrapper = pysim_pe_wrapper("pinCodes", None)
        self.assertIsNone(wrapper)

    def test_malformed_decoded_does_not_propagate_exception(self) -> None:
        # ``ProfileElementSD._post_decode`` accesses ``instance['applicationSpecificParametersC9']``
        # which raises ``KeyError`` when missing. The wrapper factory must
        # swallow the failure and return ``None`` instead of bubbling it
        # up so the local fallback parser can run.
        wrapper = pysim_pe_wrapper("securityDomain", {"sd-Header": {}})

        self.assertIsNone(wrapper)


class SecurityDomainKeyDecodeTests(unittest.TestCase):
    """``pysim_sd_keys`` should mirror ``SecurityDomainKey.from_saip_dict``."""

    @staticmethod
    def _scp03_install_params() -> bytes:
        # GP Amd. D §7.5: tag 81 = SCP byte (03), tag 82 = i byte (70).
        return bytes.fromhex("8201038201708701f0")

    def _make_sd_decoded(self) -> dict:
        return {
            "sd-Header": {"identification": 7, "mandated": None},
            "instance": {
                "applicationLoadPackageAID": bytes.fromhex("A0000001515350"),
                "classAID": bytes.fromhex("A000000251535041"),
                "instanceAID": bytes.fromhex("A000000151000000"),
                "applicationPrivileges": bytes.fromhex("82FC80"),
                "applicationSpecificParametersC9": self._scp03_install_params(),
                "applicationParameters": {
                    "uiccToolkitApplicationSpecificParametersField": bytes.fromhex(
                        "0100000100000002011203B2010000"
                    ),
                },
            },
            "keyList": [
                {
                    "keyUsageQualifier": b"\x10",
                    "keyIdentifier": b"\x01",
                    "keyVersionNumber": b"\x30",
                    "keyComponents": [
                        {
                            "keyType": b"\x88",
                            "keyData": b"\x00" * 16,
                            "macLength": 8,
                        }
                    ],
                },
                {
                    "keyUsageQualifier": b"\x14",
                    "keyIdentifier": b"\x02",
                    "keyVersionNumber": b"\x30",
                    "keyComponents": [
                        {
                            "keyType": b"\x88",
                            "keyData": b"\x11" * 16,
                            "macLength": 8,
                        }
                    ],
                },
            ],
        }

    def test_returns_one_snapshot_per_key_entry(self) -> None:
        keys = pysim_sd_keys(self._make_sd_decoded())

        self.assertEqual(len(keys), 2)

    def test_key_identifier_and_version_decoded(self) -> None:
        keys = pysim_sd_keys(self._make_sd_decoded())

        self.assertEqual(keys[0].key_identifier, 0x01)
        self.assertEqual(keys[0].key_version_number, 0x30)
        self.assertEqual(keys[1].key_identifier, 0x02)
        self.assertEqual(keys[1].key_version_number, 0x30)

    def test_components_carry_resolved_key_type_string_and_data(self) -> None:
        keys = pysim_sd_keys(self._make_sd_decoded())

        self.assertEqual(len(keys[0].components), 1)
        comp_type, comp_data, mac_len = keys[0].components[0]
        # GP §11.1.8: 0x88 = AES key type
        self.assertEqual(comp_type, "aes")
        self.assertEqual(comp_data, b"\x00" * 16)
        self.assertEqual(mac_len, 8)

    def test_returns_empty_when_keylist_missing(self) -> None:
        # The instance dict is well-formed but ``keyList`` is absent;
        # the wrapper still constructs but ``keys`` is empty.
        decoded = self._make_sd_decoded()
        decoded.pop("keyList")

        keys = pysim_sd_keys(decoded)

        self.assertEqual(keys, ())

    def test_returns_empty_when_decoded_is_unrecognised(self) -> None:
        self.assertEqual(pysim_sd_keys({}), ())
        self.assertEqual(pysim_sd_keys(None), ())


class AkaSqnInitNormalizationTests(unittest.TestCase):
    """``_fixup_sqnInit_dec`` is exposed via ``pysim_normalize_aka_decoded``."""

    def test_default_placeholder_expanded_to_32x6_zeros(self) -> None:
        decoded = {
            "aka-header": {"identification": 9, "mandated": None},
            "algoConfiguration": ("algoParameter", {
                "algorithmID": 1,
                "algorithmOptions": b"\x00",
                "key": b"\x00" * 16,
                "opc": b"\x00" * 16,
            }),
            "sqnInit": "0x000000000000",
        }

        result = pysim_normalize_aka_decoded(decoded)

        sqn = result.get("sqnInit")
        self.assertIsInstance(sqn, list)
        self.assertEqual(len(sqn), 32)
        for entry in sqn:
            self.assertEqual(entry, b"\x00" * 6)

    def test_explicit_sqn_init_preserved(self) -> None:
        # When SAIP carries actual SQN values, the normaliser must not
        # rewrite them.
        bespoke = [bytes.fromhex("000000000001")] + [b"\x00" * 6] * 31
        decoded = {
            "aka-header": {"identification": 9, "mandated": None},
            "algoConfiguration": ("algoParameter", {
                "algorithmID": 1,
                "algorithmOptions": b"\x00",
                "key": b"\x00" * 16,
                "opc": b"\x00" * 16,
            }),
            "sqnInit": bespoke,
        }

        result = pysim_normalize_aka_decoded(decoded)

        self.assertEqual(result.get("sqnInit"), bespoke)

    def test_missing_sqn_init_returns_dict_unchanged(self) -> None:
        decoded = {
            "aka-header": {"identification": 9, "mandated": None},
            "algoConfiguration": ("algoParameter", {
                "algorithmID": 1,
                "algorithmOptions": b"\x00",
                "key": b"\x00" * 16,
                "opc": b"\x00" * 16,
            }),
        }

        result = pysim_normalize_aka_decoded(decoded)

        self.assertNotIn("sqnInit", result)


class ConsumerIntegrationTests(unittest.TestCase):
    """End-to-end check that ``_consume_*`` migrations produce the same
    ``SimProfileImage`` shape they did before pySim wrapping.

    Acts as a guardrail against regressions where the wrapper-routed
    path silently drops fields.
    """

    def _new_image(self):
        from SIMCARD.state import SimProfileImage
        return SimProfileImage()

    def test_consume_pin_codes_reads_pinconfig_through_wrapper(self) -> None:
        from SIMCARD.saip_profile import _consume_pin_codes

        decoded = {
            "pin-Header": {"identification": 1, "mandated": None},
            "pinCodes": (
                "pinconfig",
                [
                    {
                        "keyReference": 1,
                        "pinValue": b"00000000",
                        "maxNumOfAttemps-retryNumLeft": 0x33,
                        "pinAttributes": 6,
                        "unblockingPINReference": 1,
                    },
                ],
            ),
        }

        image = self._new_image()
        _consume_pin_codes(image, decoded)

        self.assertEqual(len(image.pin_codes), 1)
        pin = image.pin_codes[0]
        self.assertEqual(pin.key_reference, 1)
        self.assertEqual(pin.value, b"00000000")
        self.assertEqual(pin.max_attempts, 3)
        self.assertEqual(pin.retries_remaining, 3)
        self.assertEqual(pin.attributes, 6)
        self.assertEqual(pin.unblock_reference, 1)

    def test_consume_puk_codes_reads_through_wrapper(self) -> None:
        from SIMCARD.saip_profile import _consume_puk_codes

        decoded = {
            "puk-Header": {"identification": 1, "mandated": None},
            "pukCodes": [
                {
                    "keyReference": 1,
                    "pukValue": b"11111111",
                    "maxNumOfAttemps-retryNumLeft": 0xAA,
                },
            ],
        }

        image = self._new_image()
        _consume_puk_codes(image, decoded)

        self.assertEqual(len(image.puk_codes), 1)
        puk = image.puk_codes[0]
        self.assertEqual(puk.key_reference, 1)
        self.assertEqual(puk.value, b"11111111")
        self.assertEqual(puk.max_attempts, 10)
        self.assertEqual(puk.retries_remaining, 10)

    def test_consume_security_domain_uses_pysim_typed_keys(self) -> None:
        from SIMCARD.saip_profile import _consume_security_domain

        decoded = SecurityDomainKeyDecodeTests()._make_sd_decoded()

        image = self._new_image()
        _consume_security_domain(image, decoded)

        self.assertEqual(len(image.security_domains), 1)
        sd = image.security_domains[0]
        self.assertEqual(len(sd.keys), 2)
        # First key from pySim resolution: KeyType 0x88 (AES) -> byte 0x88
        self.assertEqual(sd.keys[0].key_type, 0x88)
        self.assertEqual(sd.keys[0].key_data, b"\x00" * 16)
        self.assertEqual(sd.keys[0].mac_length, 8)
        # KVN/KID end up in the materialised dataclass
        self.assertEqual(sd.keys[0].key_identifier, 0x01)
        self.assertEqual(sd.keys[0].key_version, 0x30)

    def test_consume_aka_parameter_populates_sqn_when_default(self) -> None:
        from SIMCARD.saip_profile import _consume_aka_parameter

        decoded = {
            "aka-header": {"identification": 9, "mandated": None},
            "algoConfiguration": ("algoParameter", {
                "algorithmID": 1,
                "algorithmOptions": b"\x00",
                "key": b"\x11" * 16,
                "opc": b"\x22" * 16,
            }),
            "sqnInit": "0x000000000000",
        }

        image = self._new_image()
        _consume_aka_parameter(image, decoded)

        self.assertIsNotNone(image.auth_config)
        self.assertEqual(image.auth_config.algorithm, "milenage")
        self.assertEqual(image.auth_config.ki, b"\x11" * 16)
        self.assertEqual(image.auth_config.opc, b"\x22" * 16)
        # The pySim normaliser produces a 32-element list of zero SQNs;
        # the consumer picks the first entry (still six bytes of zero).
        self.assertEqual(image.auth_config.sqn, b"\x00" * 6)


if __name__ == "__main__":
    unittest.main()
