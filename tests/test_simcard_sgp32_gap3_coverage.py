# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Third-pass gap-coverage suite for SGP.32 v1.2 ES10b surfaces.

The first and second passes closed the LoadEuiccPackage / PSMO / eCO
seam and the immediate-enable / memory-reset / EIM-config-search seam
respectively. This pass exercises the IoT-only surfaces that stay
unimplemented until the eUICC actually engages with eCall and the
HTTP/CoAP connectivity flow used by IPAd:

- ``BF5B`` ``ES10b.EnableEmergencyProfile`` (SGP.32 v1.2 §5.9.22)
  including ``ecallNotAvailable``, ``profileNotInDisabledState``, and
  the success path (silent profile swap, no notifications, sticky
  ``emergency_profile_active`` flag).
- ``BF5C`` ``ES10b.DisableEmergencyProfile`` (SGP.32 v1.2 §5.9.23)
  including ``profileNotInEnabledState`` and the success path that
  restores the previously enabled Profile and emits the disable+enable
  notifications mandated by §5.9.23.
- ``BF5F`` ``ES10b.GetConnectivityParameters`` (SGP.32 v1.2 §5.9.24)
  for both the ``parametersNotAvailable`` and the populated
  ``httpParams`` branches of the response CHOICE.
- ``BF65`` ``ES10b.SetDefaultDpAddress`` (SGP.32 v1.2 §5.9.25), the
  IoT-side counterpart of SGP.22 v3 ``BF3F`` SetDefaultDpAddress, with
  the ``ok`` and length-bound rejection paths.
"""

from __future__ import annotations

import unittest

from SIMCARD.sgp import SgpLogic
from SIMCARD.state import SimProfileEntry
from SIMCARD.utils import read_tlv, tlv

from tests.test_simcard_sgp32_load_euicc_package import _build_state_with_test_eim


def _peel(response: bytes) -> tuple[bytes, bytes]:
    tag, value, _raw, _next = read_tlv(response, 0)
    return tag, value


class _Gap3Base(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.state, self.eim_key, self.eim_id = _build_state_with_test_eim()
        self.logic = SgpLogic(self.state)


class _EmergencyProfileBase(_Gap3Base):
    def _seed_emergency_profile(
        self,
        *,
        emergency_state: str = "disabled",
        active_state: str = "enabled",
    ) -> tuple[SimProfileEntry, SimProfileEntry]:
        active = self.state.profiles[0]
        active.state = active_state
        if active_state == "enabled":
            self.state.active_profile_aid = str(active.aid or "")
        emergency = SimProfileEntry(
            aid="A0000000871002FFFFFFFF8907090111",
            iccid="894900000000000111",
            state=emergency_state,
            profile_class="operational",
            profile_name="eCall",
            imsi="999990000000111",
            impi=active.impi,
            notification_address=active.notification_address,
            ecall_indication=True,
        )
        self.state.profiles.append(emergency)
        return active, emergency


class EnableEmergencyProfileBf5BTests(_EmergencyProfileBase):
    def test_returns_ecall_not_available_when_feature_disabled(self) -> None:
        self._seed_emergency_profile()
        self.state.euicc_info.iot_specific_info.ecall_supported = False

        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5B03010100"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x5B")
        self.assertIn(b"\x80\x01\x08", outer_value)  # ecallNotAvailable(8)

    def test_returns_ecall_not_available_when_no_emergency_profile(self) -> None:
        # No profile carries ecall_indication=True.
        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5B03010100"))

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x08", outer_value)

    def test_returns_profile_not_in_disabled_state_when_already_enabled(self) -> None:
        # Emergency Profile already enabled ⇒ profileNotInDisabledState.
        self._seed_emergency_profile(emergency_state="enabled", active_state="disabled")

        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5B03010100"))

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x02", outer_value)

    def test_returns_undefined_error_for_malformed_refresh_flag(self) -> None:
        self._seed_emergency_profile()
        # Inner BOOLEAN tag forced to 0x02 (INTEGER) - malformed.
        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5B03020100"))

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x7F", outer_value)

    def test_swaps_profiles_silently_and_sets_sticky_flag(self) -> None:
        active, emergency = self._seed_emergency_profile()
        baseline_notifications = list(self.state.notifications)

        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5B03010100"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x5B")
        self.assertIn(b"\x80\x01\x00", outer_value)  # ok(0)
        self.assertEqual(active.state, "disabled")
        self.assertEqual(emergency.state, "enabled")
        self.assertEqual(self.state.active_profile_aid, emergency.aid)
        self.assertTrue(self.state.emergency_profile_active)
        self.assertEqual(self.state.emergency_pre_aid, active.aid.upper())
        # §5.9.22: SHALL NOT generate any Notifications upon enabling.
        self.assertEqual(self.state.notifications, baseline_notifications)


class DisableEmergencyProfileBf5CTests(_EmergencyProfileBase):
    def _arm_emergency_active(self) -> tuple[SimProfileEntry, SimProfileEntry]:
        active, emergency = self._seed_emergency_profile(
            emergency_state="enabled",
            active_state="disabled",
        )
        self.state.emergency_profile_active = True
        self.state.emergency_pre_aid = str(active.aid or "").upper()
        self.state.active_profile_aid = str(emergency.aid or "")
        return active, emergency

    def test_returns_profile_not_in_enabled_state_when_emergency_not_enabled(self) -> None:
        self._seed_emergency_profile()  # disabled emergency profile
        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5C03010100"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x5C")
        self.assertIn(b"\x80\x01\x02", outer_value)  # profileNotInEnabledState(2)

    def test_returns_profile_not_in_enabled_state_when_no_emergency_profile(self) -> None:
        # No ecall_indication profile present at all.
        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5C03010100"))

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x02", outer_value)

    def test_disable_restores_previous_profile_and_emits_notifications(self) -> None:
        active, emergency = self._arm_emergency_active()
        baseline_count = len(self.state.notifications)

        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5C03010100"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x00", outer_value)  # ok(0)
        self.assertEqual(emergency.state, "disabled")
        self.assertEqual(active.state, "enabled")
        self.assertEqual(self.state.active_profile_aid, active.aid)
        self.assertFalse(self.state.emergency_profile_active)
        self.assertEqual(self.state.emergency_pre_aid, "")
        # §5.9.23 allows notifications; the simulator emits both.
        self.assertEqual(len(self.state.notifications), baseline_count + 2)
        operations = [entry.operation for entry in self.state.notifications[-2:]]
        self.assertEqual(
            operations,
            [SgpLogic.NOTIF_DISABLE, SgpLogic.NOTIF_ENABLE],
        )


class GetConnectivityParametersBf5FTests(_Gap3Base):
    def test_returns_parameters_not_available_when_active_profile_has_none(self) -> None:
        for profile in self.state.profiles:
            profile.connectivity_params_http = b""
        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5F00"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x5F")
        self.assertIn(b"\x80\x01\x01", outer_value)  # parametersNotAvailable(1)

    def test_returns_parameters_not_available_when_no_active_profile(self) -> None:
        self.state.active_profile_aid = ""
        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5F00"))

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x01", outer_value)

    def test_returns_http_params_when_active_profile_has_them(self) -> None:
        active = self.state.profiles[0]
        active.state = "enabled"
        self.state.active_profile_aid = str(active.aid or "")
        active.connectivity_params_http = bytes.fromhex("DEADBEEFCAFE")

        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5F00"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x5F")
        # CHOICE branch ConnectivityParameters → httpParams [1] OCTET STRING.
        self.assertEqual(outer_value, bytes.fromhex("8106DEADBEEFCAFE"))


class SetDefaultDpAddressBf65Tests(_Gap3Base):
    def test_persists_address_and_returns_ok(self) -> None:
        new_address = "smdp.iot.example.test"
        request = tlv(b"\xBF\x65", tlv(b"\x80", new_address.encode("utf-8")))

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x65")
        self.assertIn(b"\x80\x01\x00", outer_value)  # ok(0)
        self.assertEqual(self.state.default_dp_address, new_address)

    def test_empty_address_resets_state(self) -> None:
        self.state.default_dp_address = "smdp.previous.test"
        request = tlv(b"\xBF\x65", tlv(b"\x80", b""))

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x00", outer_value)
        self.assertEqual(self.state.default_dp_address, "")

    def test_oversized_address_returns_undefined_error(self) -> None:
        oversized = ("a" * 200).encode("utf-8")
        request = tlv(b"\xBF\x65", tlv(b"\x80", oversized))

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x7F", outer_value)  # undefinedError(127)


if __name__ == "__main__":
    unittest.main()
