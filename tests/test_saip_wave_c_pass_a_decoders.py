# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Wave C Pass A — semantic decoder coverage for DF.5GS / DF.5G_ProSe /
DF.SNPN / ADF.USIM ePDG EFs.

The decoders live in ``Tools.ProfilePackage.saip_asn1_decode`` and are
reached through ``_decode_known_ef_payload``. For every EF promoted
from opaque pass-through we verify:

1. Routing: the ``ef-*`` token dispatches to the new decoder.
2. Semantic: the decoder exposes the spec-named fields.
3. Roundtrip: the dispatcher encoder round-trips byte-exact through
   ``encode_decoded_roundtrip_ef_content`` (opaque fallback).

Spec references (TS 31.102):
  ef-5g-prose-st        §4.4.13.2
  ef-5g-prose-dd        §4.4.13.3
  ef-5g-prose-dc        §4.4.13.4
  ef-5g-prose-u2nru     §4.4.13.5
  ef-5g-prose-ru        §4.4.13.6
  ef-5g-prose-uir       §4.4.13.7
  ef-pws-snpn           §4.4.12.2
  ef-suci-calc-info     §4.4.11.8
  ef-supi-nai           §4.4.11.10
  ef-cag                §4.4.11.14
  ef-sor-cmci           §4.4.11.15
  ef-dri                §4.4.11.17
  ef-mchpplmn           §4.4.11.20
  ef-kausf-derivation   §4.4.11.18
  ef-ipd                §4.2.99
  ef-ips                §4.2.100
  ef-epdgid             §4.2.103
  ef-epdgidem           §4.2.103
  ef-epdgselection      §4.2.104
  ef-epdgselectionem    §4.2.104
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_C_PASS_A_TOKENS: tuple[str, ...] = (
    "ef-5g-prose-st",
    "ef-5g-prose-dd",
    "ef-5g-prose-dc",
    "ef-5g-prose-u2nru",
    "ef-5g-prose-ru",
    "ef-5g-prose-uir",
    "ef-pws-snpn",
    "ef-suci-calc-info",
    "ef-supi-nai",
    "ef-cag",
    "ef-sor-cmci",
    "ef-dri",
    "ef-mchpplmn",
    "ef-kausf-derivation",
    "ef-ipd",
    "ef-ips",
    "ef-epdgid",
    "ef-epdgidem",
    "ef-epdgselection",
    "ef-epdgselectionem",
)


def _roundtrip(token: str, hex_input: str) -> dict[str, object]:
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=hex_input,
    )
    assert decoded is not None, f"{token} was not routed to a semantic decoder"
    assert "hex" in decoded, f"{token} decoder did not emit 'hex' field"
    encoded = encode_decoded_roundtrip_ef_content(
        token, decoded, target_length=len(hex_input) // 2,
    )
    assert encoded is not None, f"{token} has no registered encoder"
    assert encoded.hex().upper() == hex_input.upper(), (
        f"{token} roundtrip mismatch: "
        f"in={hex_input.upper()} out={encoded.hex().upper()}"
    )
    return decoded


class Test5gProseServiceTable:
    def test_active_services_bitmap(self) -> None:
        decoded = _roundtrip("ef-5g-prose-st", "0B")
        assert decoded["format"] == "5G ProSe Service Table"
        assert decoded["activeServices"] == [1, 2, 4]
        services_by_number = {row["service"]: row for row in decoded["services"]}
        assert services_by_number[1]["enabled"] is True
        assert services_by_number[3]["enabled"] is False
        assert services_by_number[1]["name"] == "ProSe Direct Discovery"

    def test_empty_table_reports_none_active(self) -> None:
        decoded = _roundtrip("ef-5g-prose-st", "00")
        assert decoded["activeServices"] == []
        assert decoded["summary"] == "no services active"


class Test5gProseTlvDecoders:
    def test_direct_discovery_tlv_parsing(self) -> None:
        hex_input = "A00680040102030F"
        decoded = _roundtrip("ef-5g-prose-dd", hex_input)
        items = decoded["items"]
        assert isinstance(items, list)
        assert len(items) == 1
        outer = items[0]
        assert outer["tag"] == "A0"
        assert outer["name"] == "ProSe direct-discovery configuration"
        inner_items = outer["items"]
        assert inner_items[0]["tag"] == "80"
        assert inner_items[0]["name"] == "Served by NG-RAN"

    def test_direct_communication_tag_name_map(self) -> None:
        decoded = _roundtrip("ef-5g-prose-dc", "A0048702AA55")
        outer = decoded["items"][0]
        assert outer["name"] == "ProSe direct-communication configuration"
        assert outer["items"][0]["tag"] == "87"
        assert outer["items"][0]["name"] == "Privacy configuration"

    def test_remote_ue_tag_name_map(self) -> None:
        decoded = _roundtrip("ef-5g-prose-ru", "A0058F0388888F")
        outer = decoded["items"][0]
        assert outer["name"] == "ProSe remote-UE configuration"
        assert outer["items"][0]["tag"] == "8F"
        assert outer["items"][0]["name"] == "Default destination L2 IDs"

    def test_u2nru_tag_name_map(self) -> None:
        decoded = _roundtrip("ef-5g-prose-u2nru", "A00481027FFF")
        outer = decoded["items"][0]
        assert outer["name"] == "ProSe UE-to-network relay UE configuration"
        assert outer["items"][0]["tag"] == "81"
        assert outer["items"][0]["name"] == "Not served by NG-RAN"

    def test_usage_info_reporting_tag_name_map(self) -> None:
        decoded = _roundtrip("ef-5g-prose-uir", "A003850100")
        outer = decoded["items"][0]
        assert outer["name"] == (
            "ProSe usage-information reporting configuration"
        )
        assert outer["items"][0]["tag"] == "85"
        assert outer["items"][0]["name"] == "Validity timer"


class TestPwsSnpn:
    def test_all_flags_set(self) -> None:
        decoded = _roundtrip("ef-pws-snpn", "03")
        assert decoded["ignorePwsInSubscribedSnpns"] is True
        assert decoded["ignorePwsInNonSubscribedSnpns"] is True
        assert "ignore PWS in subscribed SNPNs" in decoded["summary"]

    def test_no_flags_set(self) -> None:
        decoded = _roundtrip("ef-pws-snpn", "00")
        assert decoded["ignorePwsInSubscribedSnpns"] is False
        assert decoded["ignorePwsInNonSubscribedSnpns"] is False
        assert decoded["summary"] == "no PWS suppression"

    def test_wrong_length_returns_none(self) -> None:
        assert _decode_known_ef_payload(
            ef_key="ef-pws-snpn", fid=None, hex_clean="0102",
        ) is None


class TestSuciCalcInfoAndSupiNai:
    def test_suci_calc_info_routes_to_existing_helper(self) -> None:
        decoded = _roundtrip("ef-suci-calc-info", "A0038001FFA100")
        assert decoded["format"] == "SUCI Calculation Information"
        assert isinstance(decoded["items"], list)

    def test_supi_nai_decodes_utf8_payload(self) -> None:
        hex_input = "800A7573657240666F6F2E6465"
        decoded = _decode_known_ef_payload(
            ef_key="ef-supi-nai", fid=None, hex_clean=hex_input,
        )
        assert decoded is not None
        assert decoded["nai"] == "user@foo.d"


class TestAnnotatedOpaqueEfs:
    def test_cag_is_annotated_as_spec_opaque(self) -> None:
        decoded = _roundtrip("ef-cag", "13F01041")
        assert decoded["specReference"] == "TS 31.102 §4.4.11.14"
        assert decoded["format"] == "Pre-configured CAG Information List"

    def test_sor_cmci_is_annotated_as_spec_opaque(self) -> None:
        decoded = _roundtrip("ef-sor-cmci", "AA55AA55")
        assert decoded["specReference"] == "TS 31.102 §4.4.11.15"
        assert decoded["format"] == (
            "SoR Connected-Mode Control Information"
        )


class TestDri:
    def test_dri_7byte_struct(self) -> None:
        decoded = _roundtrip("ef-dri", "01030001000200")
        assert decoded["disasterRoamingEnabled"] is True
        assert decoded["roamingWaitRangeMinutes"] == 1
        assert decoded["returnWaitRangeMinutes"] == 2
        assert "roamingWaitRange" in decoded["parametersIndicatorFlags"]
        assert "returnWaitRange" in decoded["parametersIndicatorFlags"]
        assert "applicabilityIndicator" not in decoded[
            "parametersIndicatorFlags"
        ]

    def test_dri_wrong_length_returns_none(self) -> None:
        assert _decode_known_ef_payload(
            ef_key="ef-dri", fid=None, hex_clean="010203",
        ) is None


class TestMchpPlmn:
    def test_mchpplmn_decodes_plmn_triples(self) -> None:
        decoded = _roundtrip("ef-mchpplmn", "13F0105A06FF")
        entries = decoded["entries"]
        assert len(entries) == 2
        assert entries[0]["plmn"] == "310-01"
        assert entries[1]["raw"] == "5A06FF"
        assert "310-01" in decoded["activePlmns"]

    def test_all_ff_marks_slot_as_empty(self) -> None:
        decoded = _roundtrip("ef-mchpplmn", "FFFFFF")
        assert decoded["entries"][0]["plmn"] is None
        assert decoded["activePlmns"] == []

    def test_non_triple_length_returns_none(self) -> None:
        assert _decode_known_ef_payload(
            ef_key="ef-mchpplmn", fid=None, hex_clean="13F010AB",
        ) is None


class TestKausfDerivation:
    def test_use_msk_flag(self) -> None:
        decoded = _roundtrip("ef-kausf-derivation", "01FF")
        assert decoded["useMsk"] is True
        assert decoded["rfuHex"] == "FF"

    def test_no_flags(self) -> None:
        decoded = _roundtrip("ef-kausf-derivation", "00")
        assert decoded["useMsk"] is False
        assert decoded["rfuHex"] == ""


class TestIpdIps:
    def test_ipd_returns_opaque_preview(self) -> None:
        decoded = _roundtrip("ef-ipd", "01020304")
        assert decoded["format"] == "USIM IP Data"
        assert decoded["specReference"] == "TS 31.102 §4.2.99"

    def test_ips_record_fields(self) -> None:
        decoded = _roundtrip("ef-ips", "30300200")
        assert decoded["format"] == "IMEI(SV) Pairing Status"
        assert decoded["status"] == "00"
        assert decoded["linkToEfIpd"] == 2

    def test_ips_wrong_length_returns_none(self) -> None:
        assert _decode_known_ef_payload(
            ef_key="ef-ips", fid=None, hex_clean="3030",
        ) is None


class TestEpdgId:
    def test_ipv4_address(self) -> None:
        decoded = _roundtrip("ef-epdgid", "800501C0000201")
        assert decoded["addressType"] == "IPv4"
        assert decoded["address"] == "192.0.2.1"

    def test_ipv6_address(self) -> None:
        decoded = _roundtrip(
            "ef-epdgid", "80110220010DB8000000000000000000000023",
        )
        assert decoded["addressType"] == "IPv6"
        assert "2001:0db8" in decoded["address"]

    def test_fqdn_address(self) -> None:
        decoded = _roundtrip(
            "ef-epdgid", "801100657064672E6578616D706C652E6F7267",
        )
        assert decoded["addressType"] == "FQDN"
        assert decoded["address"] == "epdg.example.org"

    def test_emergency_uses_emergency_format_name(self) -> None:
        decoded = _roundtrip("ef-epdgidem", "800501C0000202")
        assert decoded["format"] == "Emergency ePDG Identifier"
        assert decoded["address"] == "192.0.2.2"


class TestEpdgSelection:
    def test_single_entry(self) -> None:
        decoded = _roundtrip("ef-epdgselection", "800600F110000100")
        entries = decoded["entries"]
        assert len(entries) == 1
        entry = entries[0]
        assert entry["plmn"] == "001-01"
        assert entry["priority"] == 1
        assert entry["fqdnFormat"] == "operator_identified"

    def test_emergency_format_name(self) -> None:
        decoded = _roundtrip("ef-epdgselectionem", "800600F110000101")
        assert decoded["format"] == "Emergency ePDG Selection Information"
        assert decoded["entries"][0]["fqdnFormat"] == "location_based"


@pytest.mark.parametrize("token", _WAVE_C_PASS_A_TOKENS)
def test_every_wave_c_pass_a_ef_has_semantic_route(token: str) -> None:
    """Each Wave C Pass A token must dispatch to a semantic decoder for a
    plausible payload (does not fall through to the generic opaque
    catalog fallback).
    """
    probes = {
        "ef-5g-prose-st": "0F",
        "ef-5g-prose-dd": "A00680040102030F",
        "ef-5g-prose-dc": "A0048702AA55",
        "ef-5g-prose-u2nru": "A00481027FFF",
        "ef-5g-prose-ru": "A0058F0388888F",
        "ef-5g-prose-uir": "A003850100",
        "ef-pws-snpn": "00",
        "ef-suci-calc-info": "A0038001FFA100",
        "ef-supi-nai": "800A7573657240666F6F2E",
        "ef-cag": "13F01041",
        "ef-sor-cmci": "AA55AA55",
        "ef-dri": "01030001000200",
        "ef-mchpplmn": "13F0105A06FF",
        "ef-kausf-derivation": "01FF",
        "ef-ipd": "01020304",
        "ef-ips": "30300200",
        "ef-epdgid": "800501C0A8A001",
        "ef-epdgidem": "800501C0A8A002",
        "ef-epdgselection": "800600F110000100",
        "ef-epdgselectionem": "800600F110000101",
    }
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=probes[token],
    )
    assert decoded is not None, f"{token} not routed"
    assert decoded.get("format") is not None, f"{token} missing format"
    generic_opaque_formats = {
        "Opaque",
        "UNKNOWN",
    }
    assert decoded["format"] not in generic_opaque_formats, (
        f"{token} still routes to generic opaque"
    )
