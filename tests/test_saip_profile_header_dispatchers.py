# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Integration tests for the ProfileHeader edit dispatchers.

These exercise the full action pipeline: open a real DER package, run
each ``saip.*_profile_header*`` dispatcher, and verify the round-trip
through ``build_profile_sequence_from_document`` succeeds.
"""

from __future__ import annotations

import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_REFERENCE_PROFILE = _REPO_ROOT / "Tools" / "ProfilePackage" / "profile" / "reference_test_profile.txt"


@unittest.skipUnless(
    _REFERENCE_PROFILE.is_file(),
    "reference test profile fixture is required",
)
class ProfileHeaderDispatcherTests(unittest.TestCase):

    def setUp(self) -> None:
        # Ensure pySim + asn1tools are importable; the GUI dispatchers
        # lazy-load them but we want a clean failure here if either is
        # missing in the runner env.
        try:
            import asn1tools  # noqa: F401
        except ImportError as error:
            self.skipTest(f"asn1tools not installed in runner env: {error}")

        from yggdrasim_common.gui_server.actions import saip as saip_actions
        from yggdrasim_common.gui_server.sessions import (
            get_manager,
        )

        # Cold-import the dispatchers module so the registry registers.
        self._actions = saip_actions
        self._manager = get_manager()
        self._sid = "test_profile_header_session"

        # Load the reference profile via the open_package dispatcher.
        # Wrapping in CardSession matches the SessionManager contract.
        result = saip_actions._dispatch_open_package(
            ctx=None,
            path=str(_REFERENCE_PROFILE),
        )
        self._opened_session_id = result["session_id"]

    def tearDown(self) -> None:
        try:
            self._manager.release(self._opened_session_id)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Read path
    # ------------------------------------------------------------------

    def test_get_profile_header_returns_summary(self) -> None:
        result = self._actions._dispatch_get_profile_header(
            ctx=None,
            session_id=self._opened_session_id,
        )
        self.assertEqual(result["pe_index"], 0)
        self.assertIn("header", result)
        header = result["header"]
        self.assertIn("iccid_digits", header)
        # Reference profile may use either a 19- or 20-digit ICCID
        # (E.118 (09/2025) §6 fixes 19 digits; EF_ICCID, TS 102 221 v18.4 §13.2, holds 20).
        self.assertIn(len(header["iccid_digits"]), (19, 20))
        self.assertIn("major_version", header)

    def test_get_profile_header_section_key_is_canonical(self) -> None:
        result = self._actions._dispatch_get_profile_header(
            ctx=None,
            session_id=self._opened_session_id,
        )
        self.assertIn(result["section_key"], ("header", "profileHeader"))

    # ------------------------------------------------------------------
    # Scalar updates
    # ------------------------------------------------------------------

    def test_update_profile_type_round_trips(self) -> None:
        result = self._actions._dispatch_update_profile_header_field(
            ctx=None,
            session_id=self._opened_session_id,
            field="profile_type",
            value="Lab Test Profile",
        )
        self.assertEqual(result["header"]["profile_type"], "Lab Test Profile")

    def test_update_iccid_digits_round_trips(self) -> None:
        new_iccid = "8988201234567890123"
        result = self._actions._dispatch_update_profile_header_field(
            ctx=None,
            session_id=self._opened_session_id,
            field="iccid_digits",
            value=new_iccid,
        )
        self.assertEqual(result["header"]["iccid_digits"], new_iccid)

    def test_update_version_pair_round_trips(self) -> None:
        result = self._actions._dispatch_update_profile_header_field(
            ctx=None,
            session_id=self._opened_session_id,
            field="version",
            value="3.3",
        )
        self.assertEqual(result["header"]["major_version"], 3)
        self.assertEqual(result["header"]["minor_version"], 3)

    def test_update_smsc_from_ef_smsp_syncs_the_sms_bearer(self) -> None:
        from Tools.ProfilePackage import saip_profile_header_edit as ph
        from Tools.ProfilePackage.saip_connectivity_parameters import (
            decode_connectivity_parameters,
        )

        before = decode_connectivity_parameters(
            self._actions._dispatch_get_profile_header(
                ctx=None,
                session_id=self._opened_session_id,
            )["header"]["connectivity_parameters_hex"]
        )
        sms_indexes = [
            index for index, bearer in enumerate(before["bearers"])
            if bearer["bearer"] == "sms"
        ]
        self.assertEqual(len(sms_indexes), 1)
        sms_index = sms_indexes[0]
        # The reference profile's USIM ef-smsp links to DF.TELECOM
        # 7F10/6F42, which generic file management fills.
        handle = self._manager.claim(self._opened_session_id)
        smsp = ph._first_ef_smsp_file(handle["decoded_document"])
        self.assertEqual((smsp.parent_fid, smsp.fid), ("7F10", "6F42"))
        expected = ph._ef_smsp_service_centre_address(smsp.image, smsp.record_size)

        result = self._actions._dispatch_update_profile_header_field(
            ctx=None,
            session_id=self._opened_session_id,
            field="smsc_from_ef_smsp",
            value=str(sms_index),
        )
        self.assertIn("7F10/6F42", " ".join(result["summaries"]))
        after = decode_connectivity_parameters(
            result["header"]["connectivity_parameters_hex"]
        )
        synced = after["bearers"][sms_index]["dialing_number"]
        self.assertEqual(
            (synced["ton"], synced["npi"], synced["digits"]),
            (expected["ton"], expected["npi"], expected["digits"]),
        )
        self.assertNotEqual(
            synced["digits"],
            before["bearers"][sms_index]["dialing_number"]["digits"],
        )
        # Only the address changed: PID, DCS, the other bearers and the
        # trailing bytes re-encode as they were.
        for index, bearer in enumerate(before["bearers"]):
            if index == sms_index:
                for key in ("pid_hex", "dcs_hex"):
                    self.assertEqual(after["bearers"][index].get(key), bearer.get(key))
                continue
            self.assertEqual(after["bearers"][index], bearer)
        self.assertEqual(after["trailing_hex"], before["trailing_hex"])

    def test_update_smsc_from_ef_smsp_rejects_a_non_sms_bearer_index(self) -> None:
        with self.assertRaisesRegex(ValueError, "not an SMS-PP block"):
            self._actions._dispatch_update_profile_header_field(
                ctx=None,
                session_id=self._opened_session_id,
                field="smsc_from_ef_smsp",
                value="99",
            )

    def test_update_unknown_field_raises(self) -> None:
        with self.assertRaises(ValueError):
            self._actions._dispatch_update_profile_header_field(
                ctx=None,
                session_id=self._opened_session_id,
                field="bogus",
                value="x",
            )

    # ------------------------------------------------------------------
    # List updates
    # ------------------------------------------------------------------

    def test_set_mandatory_services_replaces_set(self) -> None:
        result = self._actions._dispatch_set_mandatory_services(
            ctx=None,
            session_id=self._opened_session_id,
            services={"usim": True, "milenage": True, "tuak128": True},
        )
        services = set(result["header"]["mandatory_services"].keys())
        self.assertEqual(services, {"usim", "milenage", "tuak128"})

    def test_set_mandatory_gfste_replaces_list(self) -> None:
        result = self._actions._dispatch_set_mandatory_gfste(
            ctx=None,
            session_id=self._opened_session_id,
            oids=["2.23.143.1.2.1", "2.23.143.1.2.4"],
        )
        self.assertEqual(
            result["header"]["mandatory_gfste"],
            ["2.23.143.1.2.1", "2.23.143.1.2.4"],
        )

    def test_set_mandatory_aids_round_trips(self) -> None:
        result = self._actions._dispatch_set_mandatory_aids(
            ctx=None,
            session_id=self._opened_session_id,
            aids=[
                {"aid": "A0000000871002", "version": "0100"},
            ],
        )
        aids = result["header"]["mandatory_aids"]
        self.assertEqual(len(aids), 1)
        self.assertEqual(aids[0]["aid_hex"], "A0000000871002")
        self.assertEqual(aids[0]["version_hex"], "0100")

    # ------------------------------------------------------------------
    # Catalog
    # ------------------------------------------------------------------

    def test_list_mandatory_service_keys(self) -> None:
        result = self._actions._dispatch_list_mandatory_service_keys(ctx=None)
        self.assertIn("usim", result["keys"])
        self.assertIn("eaka", result["keys"])
        # Spot-check a label so the dispatcher isn't returning empty
        # strings.
        self.assertEqual(result["labels"]["usim"], "USIM (3GPP)")


if __name__ == "__main__":
    unittest.main()
