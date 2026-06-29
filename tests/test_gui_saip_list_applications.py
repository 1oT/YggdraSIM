# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for ``saip.list_applications`` (SA-G4 backend dispatcher).

Covers:

- Privilege bit decoder (single-byte / 3-byte payloads, GP 2.3 §6 Table 6-1).
- Lifecycle state decoder (SD vs Application tables per GP 2.3 §11.1.1).
- Hex-envelope extraction across pySim's ``{"hex": ..., "label": ...}``
  wrapper, plain strings, raw bytes, and ``None``.
- The ``_dispatch_list_applications`` walker exposes the right rows for
  the in-tree reference profile and falls back to top-level
  ``instanceAID`` / ``tarList`` when an RFM / RAM PE doesn't nest its
  bookkeeping under ``instance``.
- Action spec is registered with the GUI registry under the expected
  id / subsystem / output kind.
"""

from __future__ import annotations

import pathlib

import pytest

from yggdrasim_common.gui_server.actions.saip import (
    _APP_FRIENDLY_TYPES,
    _APP_PE_TYPES,
    _SD_PE_TYPES,
    _decode_gp_lifecycle,
    _decode_gp_privileges,
    _dispatch_list_applications,
    _hex_value,
    _load_package_from_path,
    LIST_APPLICATIONS_SPEC,
)
from yggdrasim_common.gui_server.sessions import get_manager
from yggdrasim_common.gui_server.actions.registry import get_registry


_REFERENCE_PROFILE = pathlib.Path(
    "Workspace/SAIP/profile/transcoded/1oT_test_profile.transcode.der"
)


# ---------------------------------------------------------------------
# Hex-envelope extraction
# ---------------------------------------------------------------------


class TestHexValueExtractor:
    def test_none_returns_empty_string(self) -> None:
        assert _hex_value(None) == ""

    def test_plain_string_passes_through(self) -> None:
        assert _hex_value("abcd") == "abcd"

    def test_dict_envelope_returns_hex_field(self) -> None:
        envelope = {"hex": "deadBEEF", "label": "anything"}
        assert _hex_value(envelope) == "deadBEEF"

    def test_dict_without_hex_field_returns_empty(self) -> None:
        assert _hex_value({"label": "no hex here"}) == ""

    def test_bytes_are_hex_encoded(self) -> None:
        assert _hex_value(bytes.fromhex("a000000151000000")) == "a000000151000000"

    def test_bytearray_is_hex_encoded(self) -> None:
        assert _hex_value(bytearray.fromhex("01020304")) == "01020304"

    def test_unrecognised_input_returns_empty(self) -> None:
        assert _hex_value(42) == ""


# ---------------------------------------------------------------------
# Privilege bit decoder
# ---------------------------------------------------------------------


class TestPrivilegeDecoder:
    def test_empty_input_yields_no_flags(self) -> None:
        result = _decode_gp_privileges("")
        assert result == {"hex": "", "names": [], "byte_count": 0}

    def test_odd_length_input_is_rejected_silently(self) -> None:
        # Odd hex lengths can't decode to bytes — emit empty rather
        # than raising so a malformed package doesn't kill list_applications.
        result = _decode_gp_privileges("a0c")
        assert result["names"] == []
        assert result["byte_count"] == 0

    def test_single_byte_security_domain_bit(self) -> None:
        result = _decode_gp_privileges("80")
        assert result == {
            "hex": "80",
            "names": ["Security Domain"],
            "byte_count": 1,
        }

    def test_single_byte_card_lock_plus_terminate(self) -> None:
        # 0x18 == 0001 1000 → Card Lock (0x10) + Card Terminate (0x08)
        result = _decode_gp_privileges("18")
        assert result["names"] == ["Card Lock", "Card Terminate"]

    def test_three_byte_isd_canonical(self) -> None:
        # 82DC20 — the canonical ISD-R privilege set in the in-tree
        # reference profile. The result must enumerate the eight
        # GP 2.3 Table 6-1 flags in spec order.
        result = _decode_gp_privileges("82DC20")
        assert result["byte_count"] == 3
        assert result["names"] == [
            "Security Domain",
            "CVM Management",
            "Trusted Path",
            "Authorized Management",
            "Global Delete",
            "Global Lock",
            "Global Registry",
            "Contactless Activation",
        ]

    def test_input_case_is_normalised_to_uppercase(self) -> None:
        result = _decode_gp_privileges("82dc20")
        assert result["hex"] == "82DC20"

    def test_whitespace_is_tolerated(self) -> None:
        # Some packages emit privilege hex with embedded whitespace.
        # The cleaner strips any non-hex character before parsing.
        result = _decode_gp_privileges(" 82-DC:20 ")
        assert result["names"][0] == "Security Domain"


# ---------------------------------------------------------------------
# Lifecycle decoder
# ---------------------------------------------------------------------


class TestLifecycleDecoder:
    def test_empty_input(self) -> None:
        assert _decode_gp_lifecycle("", "securityDomain") == {
            "hex": "",
            "label": "—",
            "category": "",
        }

    def test_sd_table_personalized(self) -> None:
        result = _decode_gp_lifecycle("0F", "securityDomain")
        assert result["category"] == "sd"
        assert result["label"] == "PERSONALIZED"

    def test_app_table_selectable(self) -> None:
        result = _decode_gp_lifecycle("07", "application")
        assert result["category"] == "app"
        assert result["label"] == "SELECTABLE"

    def test_unknown_value_falls_through_to_unknown_label(self) -> None:
        result = _decode_gp_lifecycle("AA", "application")
        assert result["label"] == "(unknown)"

    def test_pe_type_case_is_normalised(self) -> None:
        # The PE type comes from pySim verbatim — accept ``securityDomain``
        # (camelCase), ``securitydomain``, and ``MNO-SD`` interchangeably.
        for variant in ("securityDomain", "securitydomain", "MNO-SD", "mnoSD"):
            assert _decode_gp_lifecycle("0F", variant)["category"] == "sd"

    def test_application_pe_takes_app_table(self) -> None:
        for variant in ("application", "APPLICATION", "rfm", "ram"):
            assert _decode_gp_lifecycle("0F", variant)["category"] == "app"


# ---------------------------------------------------------------------
# Type registries
# ---------------------------------------------------------------------


class TestTypeRegistries:
    def test_sd_types_are_lowercase(self) -> None:
        # The frozenset is consulted with ``.lower()`` so every entry
        # must be lowercase. A camelCase entry would silently miss.
        for entry in _SD_PE_TYPES:
            assert entry == entry.lower()

    def test_app_types_include_sd_and_app_flavours(self) -> None:
        for required in ("securitydomain", "mnosd", "ssd", "application", "rfm", "ram"):
            assert required in _APP_PE_TYPES

    def test_friendly_types_cover_every_app_type(self) -> None:
        for pe_type in _APP_PE_TYPES:
            assert pe_type in _APP_FRIENDLY_TYPES

    def test_friendly_label_examples(self) -> None:
        assert _APP_FRIENDLY_TYPES["securitydomain"] == "Security Domain"
        assert _APP_FRIENDLY_TYPES["mnosd"] == "MNO Security Domain"
        assert _APP_FRIENDLY_TYPES["rfm"] == "Remote File Mgmt"


# ---------------------------------------------------------------------
# Dispatcher integration (uses the in-tree reference profile)
# ---------------------------------------------------------------------


@pytest.fixture
def saip_session():
    if not _REFERENCE_PROFILE.exists():
        pytest.skip(f"reference profile not present: {_REFERENCE_PROFILE}")
    handle = _load_package_from_path(_REFERENCE_PROFILE)
    session = get_manager().open(kind="saip", handle=handle, close=lambda: None)
    yield session
    get_manager().close(session.id)


class TestDispatchListApplications:
    def test_session_id_required(self) -> None:
        with pytest.raises(ValueError):
            _dispatch_list_applications(None, session_id="")

    def test_returns_two_rows_for_reference_profile(self, saip_session) -> None:
        result = _dispatch_list_applications(None, session_id=saip_session.id)
        assert result["count"] == 2
        assert len(result["rows"]) == 2

    def test_security_domain_row_shape(self, saip_session) -> None:
        result = _dispatch_list_applications(None, session_id=saip_session.id)
        sd_row = next(
            r for r in result["rows"] if r["pe_type"].lower() == "securitydomain"
        )
        assert sd_row["instance_aid"] == "A000000151000000"
        assert sd_row["class_aid"] == "A000000151535041"
        assert sd_row["load_pkg_aid"] == "A0000001515350"
        assert sd_row["lifecycle"]["label"] == "PERSONALIZED"
        assert sd_row["lifecycle"]["category"] == "sd"
        assert sd_row["is_security_domain"] is True
        assert sd_row["key_count"] == 12
        assert "Security Domain" in sd_row["privileges"]["names"]
        assert sd_row["c9_params_hex"] != ""

    def test_rfm_row_falls_back_to_top_level_aid(self, saip_session) -> None:
        result = _dispatch_list_applications(None, session_id=saip_session.id)
        rfm_row = next(r for r in result["rows"] if r["pe_type"].lower() == "rfm")
        # RFM doesn't nest its instanceAID under ``instance`` — the
        # dispatcher must fall through to the top-level read.
        assert rfm_row["instance_aid"] != ""
        assert rfm_row["instance_aid"].startswith("A0000005591010")
        # TAR list is RFM/RAM-specific surface.
        assert rfm_row["tar_list"] == ["B00001"]
        assert rfm_row["friendly_type"] == "Remote File Mgmt"

    def test_session_kind_unrelated_to_app_count(self, saip_session) -> None:
        # Defensive: opening list_applications twice on the same session
        # must produce identical rows (no hidden state mutation).
        a = _dispatch_list_applications(None, session_id=saip_session.id)
        b = _dispatch_list_applications(None, session_id=saip_session.id)
        assert a == b


# ---------------------------------------------------------------------
# Spec registration
# ---------------------------------------------------------------------


class TestActionSpecRegistration:
    def test_spec_is_registered(self) -> None:
        registry = get_registry()
        spec = registry.get("saip.list_applications")
        assert spec is LIST_APPLICATIONS_SPEC

    def test_spec_metadata(self) -> None:
        assert LIST_APPLICATIONS_SPEC.id == "saip.list_applications"
        assert LIST_APPLICATIONS_SPEC.subsystem == "SAIP"
        assert LIST_APPLICATIONS_SPEC.output_kind == "table"
        assert LIST_APPLICATIONS_SPEC.requires_card is False
        assert "applications" in LIST_APPLICATIONS_SPEC.tags
