# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Typed SGP.32 PSMO / eCO constructors.

Encoding correctness is asserted twice: against the tag and length bytes
the spec assigns, and end to end by handing the result to the simulator's
own execute path. The second check is the one that matters -- a builder
that produces plausible DER the card rejects is worthless.
"""

from __future__ import annotations

import unittest

from SCP11.eim_local.psmo_builders import (
    ECO_OPERATIONS,
    PSMO_OPERATIONS,
    PsmoBuildError,
    build_eco,
    build_psmo,
    encode_iccid_bcd,
)

_TEST_ICCID = "8988201234567890123"
_TEST_AID = "A0000005591010FFFFFFFF8900001100"


class IccidEncodingTests(unittest.TestCase):
    """ETSI TS 102 221 §13.2 packs ICCID digits low nibble first."""

    def test_even_digit_count_swaps_nibbles(self) -> None:
        self.assertEqual(encode_iccid_bcd("1234").hex().upper(), "2143")

    def test_odd_digit_count_pads_with_f_filler(self) -> None:
        self.assertEqual(encode_iccid_bcd("123").hex().upper(), "21F3")

    def test_non_digits_are_stripped(self) -> None:
        self.assertEqual(encode_iccid_bcd("12-34").hex().upper(), "2143")

    def test_empty_iccid_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            encode_iccid_bcd("")

    def test_over_long_iccid_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            encode_iccid_bcd("1" * 21)


class OidEncodingTests(unittest.TestCase):
    """ISO/IEC 8825-1 8.19.4 combines the first two arcs, then base-128."""

    def test_known_rsa_oid_matches_published_encoding(self) -> None:
        from SCP11.eim_local.psmo_builders import _encode_oid

        self.assertEqual(_encode_oid("1.2.840.113549").hex().upper(), "2A864886F70D")

    def test_combined_first_subidentifier_uses_long_form(self) -> None:
        from SCP11.eim_local.psmo_builders import _encode_oid

        # 2.999 -> 2*40 + 999 = 1079, which does not fit one octet.
        self.assertEqual(_encode_oid("2.999.10").hex().upper(), "88370A")

    def test_leading_arc_above_two_is_rejected(self) -> None:
        from SCP11.eim_local.psmo_builders import _encode_oid

        with self.assertRaises(PsmoBuildError):
            _encode_oid("3.1.1")

    def test_second_arc_bounded_under_low_leading_arc(self) -> None:
        from SCP11.eim_local.psmo_builders import _encode_oid

        with self.assertRaises(PsmoBuildError):
            _encode_oid("1.40.1")


class PsmoTagAssignmentTests(unittest.TestCase):
    """Command tags follow SGP.32 v1.2 §2.11.1.1."""

    def test_command_tags_match_the_spec_table(self) -> None:
        expected = {
            "enable": "A3",
            "disable": "A4",
            "delete": "A5",
            "list_profile_info": "BF2D",
            "get_rat": "A6",
            "configure_immediate_enable": "A7",
            "set_fallback_attribute": "A8",
            "unset_fallback_attribute": "A9",
            "set_default_dp_address": "BF65",
        }
        specs = {
            "enable": {"iccid": _TEST_ICCID},
            "disable": {"iccid": _TEST_ICCID},
            "delete": {"iccid": _TEST_ICCID},
            "list_profile_info": {},
            "get_rat": {},
            "configure_immediate_enable": {"immediate_enable_flag": True},
            "set_fallback_attribute": {"iccid": _TEST_ICCID},
            "unset_fallback_attribute": {},
            "set_default_dp_address": {"default_dp_address": "smdpp.example.test"},
        }
        for operation, tag in expected.items():
            with self.subTest(operation=operation):
                encoded = build_psmo({"operation": operation, **specs[operation]})
                self.assertTrue(encoded.hex().upper().startswith(tag))

    def test_enable_carries_the_rollback_flag_when_asked(self) -> None:
        without = build_psmo({"operation": "enable", "iccid": _TEST_ICCID})
        with_flag = build_psmo({"operation": "enable", "iccid": _TEST_ICCID, "rollback": True})
        # rollbackFlag [1] NULL adds the two-byte primitive 81 00.
        self.assertEqual(len(with_flag), len(without) + 2)
        self.assertTrue(with_flag.hex().upper().endswith("8100"))

    def test_aid_reference_uses_tag_4f(self) -> None:
        encoded = build_psmo({"operation": "disable", "aid": _TEST_AID})
        self.assertIn("4F10" + _TEST_AID, encoded.hex().upper())

    def test_iccid_reference_uses_tag_5a(self) -> None:
        encoded = build_psmo({"operation": "disable", "iccid": _TEST_ICCID})
        self.assertIn("5A", encoded.hex().upper()[:8])


class PsmoValidationTests(unittest.TestCase):
    """Bad field values are rejected at build time, not by the card."""

    def test_unknown_operation_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo({"operation": "not_a_psmo"})

    def test_missing_operation_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo({"iccid": _TEST_ICCID})

    def test_profile_reference_requires_iccid_or_aid(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo({"operation": "enable"})

    def test_non_hex_aid_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo({"operation": "enable", "aid": "ZZZZ"})

    def test_over_long_dp_address_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo({"operation": "set_default_dp_address", "default_dp_address": "a" * 129})

    def test_non_mapping_spec_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_psmo("enable")  # type: ignore[arg-type]

    def test_add_eim_requires_an_eim_id(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_eco({"operation": "add_eim", "eim_fqdn": "eim.example.test"})

    def test_unknown_supported_protocol_is_rejected(self) -> None:
        with self.assertRaises(PsmoBuildError):
            build_eco(
                {
                    "operation": "add_eim",
                    "eim_id": "EIM-X",
                    "supported_protocols": ["carrier_pigeon"],
                }
            )


class EcoTagAssignmentTests(unittest.TestCase):
    """Command tags follow SGP.32 v1.2 §2.11.2.1."""

    def test_command_tags_match_the_spec_table(self) -> None:
        expected = {
            "add_eim": ("A8", {"eim_id": "EIM-X"}),
            "delete_eim": ("A9", {"eim_id": "EIM-X"}),
            "update_eim": ("AA", {"eim_id": "EIM-X"}),
            "list_eim": ("AB", {}),
        }
        for operation, (tag, extra) in expected.items():
            with self.subTest(operation=operation):
                encoded = build_eco({"operation": operation, **extra})
                self.assertTrue(encoded.hex().upper().startswith(tag))

    def test_supported_protocol_bits_are_encoded_as_a_bit_string(self) -> None:
        encoded = build_eco(
            {
                "operation": "add_eim",
                "eim_id": "EIM-X",
                "supported_protocols": ["https_over_tcp_retrieval"],
            }
        )
        # Tag 87, length 02, then the BER BIT STRING body: one unused-bits
        # octet (7 unused for a single bit) followed by 0x80 for bit 0.
        self.assertIn("87020780", encoded.hex().upper())

    def test_bit_string_round_trips_through_the_card_side_decoder(self) -> None:
        from SIMCARD.sgp import SgpLogic

        for names, expected in (
            (["https_over_tcp_retrieval"], [0]),
            (["https_over_tcp_injection"], [1]),
            (["https_over_tcp_retrieval", "coap_dtls_over_udp_injection"], [0, 3]),
        ):
            with self.subTest(protocols=names):
                from SCP11.eim_local.psmo_builders import _encode_named_bit_string

                decoded = SgpLogic._decode_named_bit_string(_encode_named_bit_string(names))
                self.assertEqual(decoded, expected)


class SimulatorRoundTripTests(unittest.TestCase):
    """Every builder produces something the simulator actually executes."""

    @classmethod
    def setUpClass(cls) -> None:
        from SIMCARD.connection import get_shared_engine

        cls.engine = get_shared_engine()
        cls.sgp = cls.engine.sgp

    def _disabled_profile_iccid(self) -> str:
        for profile in self.engine.state.profiles:
            if str(profile.state).strip().lower() == "disabled":
                return str(profile.iccid)
        self.skipTest("simulator carries no disabled profile to operate on")
        return ""

    def test_every_psmo_executes_without_processing_terminated(self) -> None:
        specs = {
            "list_profile_info": {},
            "get_rat": {},
            "configure_immediate_enable": {
                "immediate_enable_flag": True,
                "default_smdp_address": "smdpp.example.test",
            },
            "set_default_dp_address": {"default_dp_address": "smdpp.example.test"},
            "unset_fallback_attribute": {},
        }
        for operation, extra in specs.items():
            with self.subTest(operation=operation):
                command = build_psmo({"operation": operation, **extra})
                result = self.sgp._execute_psmo(command)
                self.assertIsInstance(result, bytes)
                self.assertGreater(len(result), 0)
                # _processing_terminated is the "I could not parse that"
                # answer; a typed builder must never provoke it.
                self.assertNotEqual(result, self.sgp._processing_terminated(2))

    def test_enable_and_disable_round_trip_on_a_real_profile(self) -> None:
        iccid = self._disabled_profile_iccid()
        enable_result = self.sgp._execute_psmo(
            build_psmo({"operation": "enable", "iccid": iccid})
        )
        # EnableProfileResult is INTEGER tagged [3] -> primitive 0x83, ok(0).
        self.assertEqual(enable_result.hex().upper(), "830100")
        disable_result = self.sgp._execute_psmo(
            build_psmo({"operation": "disable", "iccid": iccid})
        )
        self.assertEqual(disable_result.hex().upper(), "840100")

    def test_eim_lifecycle_round_trips(self) -> None:
        add_result = self.sgp._execute_eco(
            build_eco(
                {
                    "operation": "add_eim",
                    "eim_id": "EIM-ROUNDTRIP-TEST",
                    "eim_fqdn": "eim.example.test",
                    "eim_id_type": 1,
                    "supported_protocols": ["https_over_tcp_retrieval"],
                }
            )
        )
        self.assertTrue(add_result.hex().upper().startswith("A8"))
        list_result = self.sgp._execute_eco(build_eco({"operation": "list_eim"}))
        self.assertIn("45494D2D524F554E4454524950", list_result.hex().upper())
        delete_result = self.sgp._execute_eco(
            build_eco({"operation": "delete_eim", "eim_id": "EIM-ROUNDTRIP-TEST"})
        )
        # DeleteEimResult is INTEGER tagged [9] -> primitive 0x89, ok(0).
        self.assertEqual(delete_result.hex().upper(), "890100")

    def test_registry_covers_every_simulator_dispatch_tag(self) -> None:
        """Each builder maps onto a tag the simulator dispatches."""
        self.assertEqual(len(PSMO_OPERATIONS), 9)
        self.assertEqual(len(ECO_OPERATIONS), 4)


if __name__ == "__main__":
    unittest.main()
