# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Coverage for ``render_card_overview_snapshot`` in the shared layer.

The quick-overview renderer is the SCAN/INFO output every SCP11 shell
prints. The tests below check that the output stays stable across
shells (so the eSIM Live header card and the Local SMDP+ header card
look the same) and that the optional eIM block / notification count
behave correctly when the snapshot omits those fields.
"""

from __future__ import annotations

import io
from contextlib import redirect_stdout
from dataclasses import dataclass

from SCP11.shared.discovery_snapshot import render_card_overview_snapshot


@dataclass
class _MetadataRow:
    iccid: str = ""
    aid: str = ""
    nickname: str = ""
    profile_name: str = ""
    state: str = "DISABLED"
    profile_class: str = "OPER"


def _capture(snapshot: dict, **kwargs) -> str:
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        render_card_overview_snapshot(snapshot, **kwargs)
    return buffer.getvalue()


class TestHeaderFields:
    def test_renders_eid_and_issuer(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "issuer_name": "ACME Cards",
            "issuer_number": "0042",
            "configured_decoded": {
                "default_smdp": "smdp.example.com",
                "root_smds_primary": "smds.example.com",
            },
            "profiles": [],
        }
        output = _capture(snapshot)
        assert "EID:" in output
        assert "89001012345678901234" in output
        assert "ACME Cards" in output
        assert "smdp.example.com" in output
        assert "smds.example.com" in output

    def test_falls_back_when_eid_missing(self) -> None:
        snapshot = {
            "eid": "",
            "issuer_name": "",
            "issuer_number": "",
            "configured_decoded": {},
            "profiles": [],
        }
        output = _capture(snapshot)
        assert "(unavailable)" in output
        assert "(not present)" in output

    def test_includes_additional_smds_list(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {
                "default_smdp": "smdp.example.com",
                "root_smds_primary": "smds.example.com",
                "root_smds_additional": ["smds-eu.example.com", "smds-us.example.com"],
            },
            "profiles": [],
        }
        output = _capture(snapshot)
        assert "smds-eu.example.com" in output
        assert "smds-us.example.com" in output


class TestProfileTable:
    def test_emits_empty_message_when_no_profiles(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [],
        }
        output = _capture(snapshot)
        assert "(No profile metadata decoded)" in output

    def test_renders_profile_rows(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [
                _MetadataRow(
                    iccid="89012345678901234500",
                    aid="A0000000871002FF33FFFF8950000111200000000000",
                    nickname="HomeNet",
                    profile_class="OPER",
                    state="ENABLED",
                ),
                _MetadataRow(
                    iccid="89012345678901234501",
                    aid="A0000000871002FF33FFFF8950000111200000000001",
                    nickname="Travel",
                    profile_class="OPER",
                    state="DISABLED",
                ),
            ],
        }
        output = _capture(snapshot)
        assert "HomeNet" in output
        assert "Travel" in output
        assert "ENABLED" in output
        assert "DISABLED" in output

    def test_falls_back_to_profile_name_when_nickname_blank(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [
                _MetadataRow(
                    iccid="89012345678901234500",
                    aid="A0000000871002",
                    nickname="",
                    profile_name="Field Profile",
                    state="ENABLED",
                ),
            ],
        }
        output = _capture(snapshot)
        assert "Field Profile" in output


class TestNotificationsAndEim:
    def test_explicit_notification_count_overrides_decoded(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [],
        }
        output = _capture(snapshot, notification_count=7)
        assert "Queued Notifications:" in output
        assert "7" in output

    def test_skips_notifications_section_when_no_data(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [],
        }
        output = _capture(snapshot)
        assert "Queued Notifications" not in output

    def test_renders_eim_summary_entries(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [],
            "eim_summary": {
                "entries": [
                    {
                        "eim_fqdn": "eim.example.com",
                        "eim_id": "2.25.123",
                        "eim_id_type": "OID",
                    },
                ],
            },
        }
        output = _capture(snapshot)
        assert "eIM Entries:" in output
        assert "eim.example.com" in output
        assert "2.25.123" in output

    def test_omits_eim_block_when_no_entries(self) -> None:
        snapshot = {
            "eid": "89001012345678901234",
            "configured_decoded": {},
            "profiles": [],
        }
        output = _capture(snapshot)
        assert "eIM Entries:" not in output
