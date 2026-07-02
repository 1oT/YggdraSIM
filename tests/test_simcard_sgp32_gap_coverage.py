# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Gap-coverage suite for SGP.32 IoT-deployment-grade conformance.

The suites below complement ``test_simcard_sgp32_load_euicc_package`` by
exercising the surfaces that surfaced during the v1.2 audit:

- Wire-format result tags for ``deleteEim`` (``[9]``) and ``updateEim``
  (``[10]``) — primitive ``89`` / ``8A`` per AUTOMATIC TAGS, not the
  constructed forms used on the eCO command side.
- Package-level constraints from §2.11.1.1: at most one ``enable`` per
  package, at most one ``disable`` per package, ``listProfileInfo`` must
  not follow ``enable`` / ``disable`` / ``delete``.
- Real ``setFallbackAttribute`` / ``unsetFallbackAttribute`` semantics.
- ``configureImmediateEnable`` persistence on ``SimCardState``.
- ``enable.rollbackFlag`` capture.
- Standalone ES10b surfaces ``BF5D`` ``ExecuteFallbackMechanism``,
  ``BF5E`` ``ReturnFromFallback`` and ``BF58`` ``ProfileRollback``.
"""

from __future__ import annotations

import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.sgp32_packages import encode_der_integer
from SIMCARD.state import SimCardState, SimEimEntry, SimProfileEntry
from SIMCARD.utils import encode_iccid_ef, find_first_tlv, read_tlv, tlv

from tests.test_simcard_sgp32_load_euicc_package import (
    _build_state_with_test_eim,
    _sign_euicc_package,
)


def _add_secondary_profile(state: SimCardState) -> SimProfileEntry:
    """Append a second profile so package-level multi-profile checks
    have something to operate on."""

    primary = state.profiles[0]
    secondary = SimProfileEntry(
        aid="A0000000871002FFFFFFFF8907090000",
        iccid="8949000000000000200",
        state="disabled",
        profile_class=primary.profile_class,
        profile_name="Secondary Test Profile",
        imsi="999990000000200",
        impi=primary.impi,
        notification_address=primary.notification_address,
    )
    state.profiles.append(secondary)
    return secondary


def _peel_outer(response: bytes) -> tuple[bytes, bytes]:
    tag, value, _raw, _next = read_tlv(response, 0)
    return tag, value


class _Sgp32GapBase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.state, self.eim_key, self.eim_id = _build_state_with_test_eim()
        self.state.next_notification_seq = 1
        self.logic = SgpLogic(self.state)


class Sgp32EcoResultTagsTests(_Sgp32GapBase):
    def test_delete_eim_result_uses_primitive_context_tag_89(self) -> None:
        eco_delete = tlv(b"\xA9", tlv(b"\x80", self.eim_id.encode("utf-8")))
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA1",
            inner_items=eco_delete,
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel_outer(response)
        self.assertEqual(outer_tag, b"\xBF\x51")
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA0")
        seq_tag, seq_value, _raw_seq, _seq_next = read_tlv(choice_value, 0)
        self.assertEqual(seq_tag, b"\x30")
        # The deleteEim path makes the test eIM the only entry, so the
        # eUICC SHALL respond with lastEimDeleted(2) under primitive 89.
        self.assertIn(b"\x89\x01\x02", seq_value)
        self.assertNotIn(b"\xA9\x03\x02\x01\x02", seq_value)

    def test_update_eim_result_uses_primitive_context_tag_8a(self) -> None:
        new_key = ec.generate_private_key(ec.SECP256R1())
        new_spki = new_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        update_body = (
            tlv(b"\x80", self.eim_id.encode("utf-8"))
            + tlv(b"\x83", encode_der_integer(5))
            + tlv(b"\xA5", new_spki)
        )
        eco_update = tlv(b"\xAA", update_body)
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=2,
            inner_choice_tag=b"\xA1",
            inner_items=eco_update,
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _outer_tag, outer_value = _peel_outer(response)
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA0")
        seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        self.assertEqual(seq_tag, b"\x30")
        # ok(0) under primitive 8A.
        self.assertIn(b"\x8A\x01\x00", seq_value)


class Sgp32PsmoConstraintsTests(_Sgp32GapBase):
    def test_two_enables_in_one_package_terminate_with_processing_terminated(self) -> None:
        secondary = _add_secondary_profile(self.state)
        primary = self.state.profiles[0]
        primary.state = "disabled"
        psmo_enable_primary = tlv(
            b"\xA3", tlv(b"\x5A", encode_iccid_ef(primary.iccid))
        )
        psmo_enable_secondary = tlv(
            b"\xA3", tlv(b"\x5A", encode_iccid_ef(secondary.iccid))
        )

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_enable_primary + psmo_enable_secondary,
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _outer_tag, outer_value = _peel_outer(response)
        choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        self.assertEqual(choice_tag, b"\xA0")
        seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        # The constraint violator is encoded as enableResult 83 with
        # undefinedError(127); processingTerminated 02 follows.
        self.assertIn(b"\x83\x01\x7F", seq_value)
        self.assertIn(b"\x02\x01\x02", seq_value)
        # Neither profile should have been activated.
        self.assertEqual(primary.state, "disabled")
        self.assertEqual(secondary.state, "disabled")

    def test_list_profile_info_after_disable_returns_profile_change_ongoing(self) -> None:
        primary = self.state.profiles[0]
        primary.state = "enabled"
        psmo_disable = tlv(
            b"\xA4", tlv(b"\x5A", encode_iccid_ef(primary.iccid))
        )
        psmo_list = tlv(bytes.fromhex("BF2D"), b"")

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_disable + psmo_list,
        )

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _outer_tag, outer_value = _peel_outer(response)
        _choice_tag, choice_value, _raw, _next = read_tlv(outer_value, 0)
        _seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        # disableResult ok then listProfileInfoError profileChangeOngoing(11)
        # under BF2D / 02 01 0B, then processingTerminated.
        self.assertIn(b"\x84\x01\x00", seq_value)
        self.assertIn(b"\xBF\x2D\x03\x02\x01\x0B", seq_value)
        self.assertIn(b"\x02\x01\x02", seq_value)


class Sgp32FallbackAttributeTests(_Sgp32GapBase):
    def test_set_fallback_on_disabled_profile_marks_attribute(self) -> None:
        secondary = _add_secondary_profile(self.state)
        secondary.state = "disabled"
        primary = self.state.profiles[0]
        primary.state = "enabled"
        psmo_set_fallback = tlv(
            b"\xA8", tlv(b"\x5A", encode_iccid_ef(secondary.iccid))
        )

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_set_fallback,
        )

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel_outer(response)
        _choice_tag, choice_value, _, _ = read_tlv(outer_value, 0)
        _seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        self.assertIn(b"\x8D\x01\x00", seq_value)  # ok(0)
        self.assertTrue(secondary.fallback_attribute)
        self.assertFalse(primary.fallback_attribute)

    def test_unset_fallback_when_none_set_returns_no_fallback_attribute(self) -> None:
        psmo_unset = tlv(b"\xA9", b"")
        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_unset,
        )

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel_outer(response)
        _choice_tag, choice_value, _, _ = read_tlv(outer_value, 0)
        _seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        self.assertIn(b"\x8E\x01\x02", seq_value)  # noFallbackAttribute(2)


class Sgp32ImmediateEnableTests(_Sgp32GapBase):
    def test_configure_immediate_enable_persists_flag_and_address(self) -> None:
        smdp_oid_payload = bytes([0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D])
        smdp_oid_value = bytes.fromhex("2A864886F70D")
        address_value = b"smdp.example.test"
        body = (
            tlv(b"\x80", b"")  # immediateEnableFlag NULL [0]
            + tlv(b"\x81", smdp_oid_value)  # defaultSmdpOid [1]
            + tlv(b"\x82", address_value)  # defaultSmdpAddress [2]
        )
        del smdp_oid_payload  # silence unused-var checker; only used for clarity
        psmo = tlv(b"\xA7", body)

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo,
        )

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel_outer(response)
        _choice_tag, choice_value, _, _ = read_tlv(outer_value, 0)
        _seq_tag, seq_value, _, _ = read_tlv(choice_value, 0)
        self.assertIn(b"\x87\x01\x00", seq_value)  # ok(0)
        self.assertTrue(self.state.immediate_enable_flag)
        self.assertEqual(self.state.immediate_enable_smdp_address, "smdp.example.test")
        self.assertEqual(self.state.immediate_enable_smdp_oid, "1.2.840.113549")


class Sgp32EnableRollbackFlagTests(_Sgp32GapBase):
    def test_enable_with_rollback_flag_arms_rollback_and_remembers_previous(self) -> None:
        secondary = _add_secondary_profile(self.state)
        secondary.state = "disabled"
        primary = self.state.profiles[0]
        primary.state = "enabled"
        # enable [3] SEQUENCE { iccid [APPLICATION 26], rollbackFlag NULL OPTIONAL }
        # rollbackFlag carries auto-tag [1] -> primitive NULL 0x81 00.
        psmo_enable = tlv(
            b"\xA3",
            tlv(b"\x5A", encode_iccid_ef(secondary.iccid)) + tlv(b"\x81", b""),
        )

        request = _sign_euicc_package(
            self.eim_key,
            eim_id=self.eim_id,
            eid_hex=self.state.eid,
            counter_value=1,
            inner_choice_tag=b"\xA0",
            inner_items=psmo_enable,
        )

        _response, _sw1, _sw2 = self.logic.handle_store_data(request)

        self.assertTrue(secondary.rollback_armed)
        self.assertFalse(primary.rollback_armed)
        self.assertEqual(self.state.previous_enabled_aid, primary.aid)


class Sgp32ProfileRollbackTests(_Sgp32GapBase):
    def test_bf58_with_boolean_payload_reverts_to_previous(self) -> None:
        secondary = _add_secondary_profile(self.state)
        primary = self.state.profiles[0]
        primary.state = "disabled"
        secondary.state = "enabled"
        secondary.rollback_armed = True
        self.state.previous_enabled_aid = primary.aid

        # ProfileRollbackRequest: BF58 03 01 01 FF (refreshFlag = TRUE).
        request = bytes.fromhex("BF58030101FF")
        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response[:2], b"\xBF\x58")
        self.assertIn(b"\x80\x01\x00", response)  # cmdResult ok(0)
        self.assertEqual(primary.state, "enabled")
        self.assertEqual(secondary.state, "disabled")
        self.assertFalse(secondary.rollback_armed)

    def test_bf58_when_no_rollback_armed_returns_rollback_not_allowed(self) -> None:
        request = bytes.fromhex("BF58030101FF")
        response, _sw1, _sw2 = self.logic.handle_store_data(request)
        self.assertIn(b"\x80\x01\x01", response)


class Sgp32FallbackEs10bTests(_Sgp32GapBase):
    def _arrange_fallback(self) -> tuple[SimProfileEntry, SimProfileEntry]:
        secondary = _add_secondary_profile(self.state)
        primary = self.state.profiles[0]
        primary.state = "enabled"
        secondary.state = "disabled"
        secondary.fallback_attribute = True
        return primary, secondary

    def test_bf5d_swaps_enabled_with_fallback_profile(self) -> None:
        primary, secondary = self._arrange_fallback()
        request = bytes.fromhex("BF5D030101FF")
        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response[:2], b"\xBF\x5D")
        self.assertIn(b"\x80\x01\x00", response)  # ok(0)
        self.assertEqual(primary.state, "disabled")
        self.assertEqual(secondary.state, "enabled")
        self.assertEqual(self.state.previous_enabled_aid, primary.aid)

    def test_bf5d_without_fallback_attribute_returns_fallback_not_available(self) -> None:
        primary = self.state.profiles[0]
        primary.state = "enabled"
        request = bytes.fromhex("BF5D030101FF")
        response, _sw1, _sw2 = self.logic.handle_store_data(request)
        self.assertIn(b"\x80\x01\x06", response)  # fallbackNotAvailable(6)

    def test_bf5e_returns_from_fallback_to_previous(self) -> None:
        primary, secondary = self._arrange_fallback()
        # Move into fallback state before the test.
        primary.state = "disabled"
        secondary.state = "enabled"
        self.state.previous_enabled_aid = primary.aid

        request = bytes.fromhex("BF5E030101FF")
        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(b"\x80\x01\x00", response)
        self.assertEqual(primary.state, "enabled")
        self.assertEqual(secondary.state, "disabled")

    def test_bf5e_when_fallback_not_active_returns_fallback_not_available(self) -> None:
        primary = self.state.profiles[0]
        primary.state = "enabled"
        request = bytes.fromhex("BF5E030101FF")
        response, _sw1, _sw2 = self.logic.handle_store_data(request)
        self.assertIn(b"\x80\x01\x06", response)


if __name__ == "__main__":
    unittest.main()
