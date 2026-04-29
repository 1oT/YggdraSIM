"""Second-pass gap-coverage suite for SGP.32 / SGP.22 v3 ES10 surfaces.

The first gap pass (``test_simcard_sgp32_gap_coverage``) closed the
``LoadEuiccPackage`` / PSMO / eCO seam. This pass exercises the
remaining standalone ES10b / ES10c surfaces that surfaced during the
deep audit:

- ``BF5A`` ``ES10b.ImmediateEnable`` (SGP.32 v1.2 §5.9.15) including the
  ``immediateEnableNotAvailable`` and ``noSessionContext`` error paths.
- ``BF34`` ``ES10c.eUICCMemoryReset`` (SGP.22 v3 §5.7.19) for the
  classic LPA-driven memory reset that pre-dates the SGP.32 IoT
  variant.
- ``BF59`` ``ES10b.ConfigureImmediateProfileEnabling`` (SGP.32 v1.2
  §5.9.17) standalone surface, including the ``associatedEimAlreadyExists``
  guard and the legacy delete-eIM regression path.
- ``BF64`` ``ES10b.eUICCMemoryReset`` extended bit handling: delete
  Operational / Test / Provisioning Profiles, reset default SM-DP+
  address, reset immediate-enable configuration.
- ``BF55`` ``ES10b.GetEimConfigurationData`` ``searchCriteria`` filter.
"""

from __future__ import annotations

import unittest

from SIMCARD.sgp import SgpLogic
from SIMCARD.state import SimCardState, SimEimEntry, SimProfileEntry
from SIMCARD.utils import read_tlv, tlv

from tests.test_simcard_sgp32_load_euicc_package import _build_state_with_test_eim


def _peel(response: bytes) -> tuple[bytes, bytes]:
    tag, value, _raw, _next = read_tlv(response, 0)
    return tag, value


class _Gap2Base(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.state, self.eim_key, self.eim_id = _build_state_with_test_eim()
        self.logic = SgpLogic(self.state)


class ImmediateEnableTests(_Gap2Base):
    def _seed_two_profiles(self) -> tuple[SimProfileEntry, SimProfileEntry]:
        # The default state ships exactly one profile; promote it to
        # "enabled" and append a fresh disabled candidate so the
        # ImmediateEnable handler has something to swap onto.
        active = self.state.profiles[0]
        active.state = "enabled"
        candidate = SimProfileEntry(
            aid="A0000000871002FFFFFFFF8907090000",
            iccid="8949000000000000200",
            state="disabled",
            profile_class=active.profile_class,
            profile_name="Pending Immediate Enable",
            imsi="999990000000201",
            impi=active.impi,
            notification_address=active.notification_address,
        )
        self.state.profiles.append(candidate)
        return active, candidate

    def test_returns_immediate_enable_not_available_when_flag_unset(self) -> None:
        self._seed_two_profiles()
        self.state.immediate_enable_flag = False

        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5A030101FF"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response[:2], b"\xBF\x5A")
        self.assertIn(b"\x80\x01\x01", response)

    def test_returns_no_session_context_when_no_disabled_candidate(self) -> None:
        for profile in self.state.profiles:
            profile.state = "enabled"
        self.state.immediate_enable_flag = True

        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5A030101FF"))

        self.assertIn(b"\x80\x01\x04", response)

    def test_swaps_enabled_profile_with_pending_candidate(self) -> None:
        active, candidate = self._seed_two_profiles()
        self.state.immediate_enable_flag = True

        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5A030101FF"))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertIn(b"\x80\x01\x00", response)
        self.assertEqual(active.state, "disabled")
        self.assertEqual(candidate.state, "enabled")
        self.assertEqual(self.state.active_profile_aid, candidate.aid)


class Es10cMemoryResetBf34Tests(_Gap2Base):
    def _add_operational_profile(self) -> SimProfileEntry:
        operational = SimProfileEntry(
            aid="A0000000871002FFFFFFFF8907090099",
            iccid="8949000000000000999",
            state="disabled",
            profile_class="operational",
            profile_name="Operational",
        )
        self.state.profiles.append(operational)
        return operational

    def test_delete_operational_profiles_returns_ok(self) -> None:
        operational = self._add_operational_profile()

        # BF34 04 82 02 07 80 → resetOptions [2] BIT STRING with
        # bit 0 set ("deleteOperationalProfiles", unused-bits=7).
        request = bytes.fromhex("BF340482020780")
        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x34")
        self.assertIn(b"\x80\x01\x00", outer_value)  # ok(0)
        self.assertNotIn(operational, self.state.profiles)

    def test_no_matching_class_returns_nothing_to_delete(self) -> None:
        # Default state ships only "operational" + "test" profiles.
        # Bit 4 (deleteProvisioningProfiles) thus has no targets ⇒
        # resetResult must be nothingToDelete(1).
        request = bytes.fromhex("BF340482020308")
        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x01", outer_value)

    def test_empty_options_returns_undefined_error(self) -> None:
        # BF34 with no resetOptions ⇒ undefinedError(127) per spec
        # interpretation.
        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF3400"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x7F", outer_value)


class ConfigureImmediateProfileEnablingBf59Tests(_Gap2Base):
    def test_persists_flag_address_and_oid(self) -> None:
        # Drop the seeded test eIM so the spec precondition
        # "no eIM Configuration Data present" holds.
        self.state.eim_entries = []
        smdp_oid_value = bytes.fromhex("2A864886F70D")
        body = (
            tlv(b"\x80", b"")
            + tlv(b"\x81", smdp_oid_value)
            + tlv(b"\x82", b"smdp.fast.test")
        )
        request = tlv(b"\xBF\x59", body)

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        outer_tag, outer_value = _peel(response)
        self.assertEqual(outer_tag, b"\xBF\x59")
        self.assertIn(b"\x80\x01\x00", outer_value)  # ok(0)
        self.assertTrue(self.state.immediate_enable_flag)
        self.assertEqual(self.state.immediate_enable_smdp_oid, "1.2.840.113549")
        self.assertEqual(self.state.immediate_enable_smdp_address, "smdp.fast.test")

    def test_returns_associated_eim_already_exists_when_eim_present(self) -> None:
        # Default fixture seeds an eIM, so the precondition fails.
        body = tlv(b"\x80", b"")
        request = tlv(b"\xBF\x59", body)

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x02", outer_value)  # associatedEimAlreadyExists(2)

    def test_legacy_delete_eim_path_still_works(self) -> None:
        # The simulator's eim-local fixtures issue ``BF59 80 NN <eim_id>``
        # to drop a stored eIM. The dispatcher must still route to the
        # legacy handler for non-empty [0] string bodies.
        legacy_request = tlv(b"\xBF\x59", tlv(b"\x80", self.eim_id.encode("utf-8")))
        response, sw1, sw2 = self.logic.handle_store_data(legacy_request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF5900"))
        self.assertEqual(self.state.eim_entries, [])

    def test_clears_flag_when_immediate_enable_flag_omitted(self) -> None:
        self.state.eim_entries = []
        self.state.immediate_enable_flag = True
        self.state.immediate_enable_smdp_address = "smdp.example.test"
        request = tlv(b"\xBF\x59", b"")

        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        _outer_tag, outer_value = _peel(response)
        self.assertIn(b"\x80\x01\x00", outer_value)
        self.assertFalse(self.state.immediate_enable_flag)
        self.assertEqual(self.state.immediate_enable_smdp_address, "smdp.example.test")


class EuiccMemoryResetBf64ExpandedTests(_Gap2Base):
    def test_delete_operational_profiles_drops_class(self) -> None:
        # Default state already ships an "operational" profile; append a
        # second one so the bit-0 sweep clears at least two entries.
        operational_extra = SimProfileEntry(
            aid="A0000000871002FFFFFFFF8907090071",
            iccid="894900000000000071",
            state="disabled",
            profile_class="operational",
        )
        self.state.profiles.append(operational_extra)
        before_operational = sum(
            1 for p in self.state.profiles if str(p.profile_class).lower() == "operational"
        )
        self.assertGreaterEqual(before_operational, 2)

        request = bytes.fromhex("BF640482020780")
        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF6400"))
        self.assertNotIn(operational_extra, self.state.profiles)
        leftover = [
            p for p in self.state.profiles if str(p.profile_class).lower() == "operational"
        ]
        self.assertEqual(leftover, [])

    def test_reset_default_smdp_address_clears_address(self) -> None:
        self.state.default_dp_address = "smdp.previous.test"

        # Bit 2 = resetDefaultSmdpAddress (unused-bits=5, payload=0x20).
        request = bytes.fromhex("BF640482020520")
        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        self.assertEqual(response, bytes.fromhex("BF6400"))
        self.assertEqual(self.state.default_dp_address, "")

    def test_reset_immediate_enable_clears_configuration(self) -> None:
        self.state.immediate_enable_flag = True
        self.state.immediate_enable_smdp_oid = "1.2.840.113549"
        self.state.immediate_enable_smdp_address = "smdp.example.test"

        # Bit 6 = resetImmediateEnableConfig (unused-bits=1, payload=0x02).
        request = bytes.fromhex("BF640482020102")
        response, _sw1, _sw2 = self.logic.handle_store_data(request)

        self.assertEqual(response, bytes.fromhex("BF6400"))
        self.assertFalse(self.state.immediate_enable_flag)
        self.assertEqual(self.state.immediate_enable_smdp_oid, "")
        self.assertEqual(self.state.immediate_enable_smdp_address, "")


class GetEimConfigurationDataSearchCriteriaTests(_Gap2Base):
    def _add_secondary_eim(self) -> SimEimEntry:
        secondary = SimEimEntry(
            eim_id="other-eim.alpha.test",
            eim_fqdn="alpha.test",
            eim_id_type=2,
            counter_value=0,
            association_token=0,
            supported_protocol_bits=[0],
            euicc_ci_pkid=bytes(self.state.root_ci_pkid),
            indirect_profile_download=False,
            eim_public_key_data=b"",
            trusted_tls_public_key_data=b"",
        )
        self.state.eim_entries.append(secondary)
        return secondary

    def test_search_criteria_filters_to_single_entry(self) -> None:
        self._add_secondary_eim()
        request = tlv(b"\xBF\x55", tlv(b"\x80", self.eim_id.encode("utf-8")))

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response[:2], b"\xBF\x55")
        self.assertIn(self.eim_id.encode("utf-8"), response)
        self.assertNotIn(b"other-eim.alpha.test", response)

    def test_search_criteria_no_match_returns_empty_list(self) -> None:
        request = tlv(b"\xBF\x55", tlv(b"\x80", b"missing-eim.example.test"))

        response, sw1, sw2 = self.logic.handle_store_data(request)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(response, bytes.fromhex("BF5500"))

    def test_empty_request_returns_full_list(self) -> None:
        self._add_secondary_eim()
        response, _sw1, _sw2 = self.logic.handle_store_data(bytes.fromhex("BF5500"))

        self.assertIn(self.eim_id.encode("utf-8"), response)
        self.assertIn(b"other-eim.alpha.test", response)


if __name__ == "__main__":
    unittest.main()
