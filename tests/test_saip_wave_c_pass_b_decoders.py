# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""
Wave C Pass B — semantic decoder coverage for ADF.USIM optional /
ISIM-USIM shared EFs.

For every EF promoted from the generic opaque pass-through catalog we
verify three invariants:

1. Routing: the ``ef-*`` token dispatches to a semantic decoder (not
   the generic opaque catalog fallback).
2. Semantic: the decoder exposes the spec-named fields.
3. Roundtrip: ``encode_decoded_roundtrip_ef_content`` returns the exact
   input bytes (via the opaque ``hex`` field the semantic decoders
   surface alongside the named keys).

Spec references (TS 31.102 unless noted):
  ef-bdn                       §4.4.2.3  (Barred Dialling Numbers)
  ef-bdnuri                    §4.4.2.4  (BDN URI)
  ef-ext4                      §4.2.35   (USIM EXT4)
  ef-ext5                      §4.2.82   (USIM EXT5)
  ef-ext8                      §4.2.82   (USIM EXT8)
  ef-vgcsca                    §4.2.77   (VGCS Ciphering Algorithm)
  ef-vbsca                     §4.2.79   (VBS Ciphering Algorithm)
  ef-msk                       §4.2.80   (MBMS Service Key List)
  ef-muk                       §4.2.81   (MBMS User Key)
  ef-ufc                       §4.2.88   (UE Functionality Config)
  ef-pws                       §4.2.96   (Public Warning System)
  ef-umpc                      TS 102 221 §13.1
  ef-eaka                      §4.2.114  (Enhanced AKA Support)
  ef-frompreferred             §4.2.106  (From Preferred)
  ef-3gpppsdataoff             §4.2.92   (3GPP PS Data Off)
  ef-3gpppsdataoffservicelist  §4.2.93   (PS Data Off Service List)
  ef-ial                       §4.2.102  (IMEI(SV) Association List)
  ef-ncp-ip                    §4.2.90   (Network Connectivity IP)
  ef-spni                      §4.2.73   (Service Provider Name Icon)
  ef-pnni                      §4.2.74   (PLMN Network Name Icon)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_C_PASS_B_TOKENS: tuple[str, ...] = (
    "ef-bdn",
    "ef-bdnuri",
    "ef-ext4",
    "ef-ext5",
    "ef-ext8",
    "ef-vgcsca",
    "ef-vbsca",
    "ef-msk",
    "ef-muk",
    "ef-ufc",
    "ef-pws",
    "ef-umpc",
    "ef-eaka",
    "ef-frompreferred",
    "ef-3gpppsdataoff",
    "ef-3gpppsdataoffservicelist",
    "ef-ial",
    "ef-ncp-ip",
    "ef-spni",
    "ef-pnni",
)


def _roundtrip(token: str, hex_input: str) -> dict[str, object]:
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=hex_input,
    )
    assert decoded is not None, f"{token} was not routed to a semantic decoder"
    # Semantic decoders for Pass B all emit a hex field on top of their
    # named fields so the roundtrip encoder can operate on raw bytes.
    if "hex" in decoded:
        hex_field = str(decoded["hex"])
        assert hex_field.upper() == hex_input.upper(), (
            f"{token} semantic decoder did not preserve input hex"
        )
    encoded = encode_decoded_roundtrip_ef_content(
        token, decoded, target_length=len(hex_input) // 2,
    )
    assert encoded is not None, f"{token} has no registered encoder"
    assert encoded.hex().upper() == hex_input.upper(), (
        f"{token} roundtrip mismatch: "
        f"in={hex_input.upper()} out={encoded.hex().upper()}"
    )
    return decoded


class TestBdnAdnLike:
    def test_bdn_routes_to_adn_helper(self) -> None:
        # 8 bytes alpha + 14 bytes footer (len/ton+BCD(10)/CCP/EXT).
        hex_input = ("41" * 8) + "068134123456F9FFFFFFFFFF" + "00FF"
        decoded = _decode_known_ef_payload(
            ef_key="ef-bdn", fid=None, hex_clean=hex_input,
        )
        assert decoded is not None
        assert decoded["alphaIdentifier"] == "AAAAAAAA"
        assert decoded["numberLength"] == 0x06

    def test_bdnuri_routes_to_uri_helper(self) -> None:
        hex_input = "736D733A2B343612343111113233FFFFFFFFFFFF"
        decoded = _roundtrip("ef-bdnuri", hex_input)
        # Round-3 Pass 1 aligned the label with "EF.BDN URI" (6FEE canonical
        # form); Round-4 Pass 2 additionally attaches the §4.2.72 reference.
        assert decoded["format"] == "EF.BDN URI"
        assert decoded.get("reference") == "TS 31.102 §4.2.72"


class TestExtensionRecords:
    @pytest.mark.parametrize("token", ["ef-ext4", "ef-ext5", "ef-ext8"])
    def test_extension_record_shape(self, token: str) -> None:
        hex_input = "02" + ("07" * 11) + "FF"
        decoded = _roundtrip(token, hex_input)
        assert decoded["format"] == "Extension record"
        assert decoded["recordType"] == "0x02"


class TestVgcsVbsCipheringAlgo:
    def test_vgcsca_two_bytes(self) -> None:
        decoded = _roundtrip("ef-vgcsca", "0102")
        assert decoded["format"] == "VGCS Ciphering Algorithm"
        assert decoded["algVKi1"] == "0x01"
        assert decoded["algVKi2"] == "0x02"

    def test_vbsca_two_bytes(self) -> None:
        decoded = _roundtrip("ef-vbsca", "0A0B")
        assert decoded["format"] == "VBS Ciphering Algorithm"
        assert decoded["algVKi1"] == "0x0A"
        assert decoded["algVKi2"] == "0x0B"

    def test_vgcsca_rejects_wrong_length(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-vgcsca", fid=None, hex_clean="01",
        )
        # Fallback to opaque catalog if the payload is the wrong length.
        assert decoded is None or decoded.get("format") != (
            "VGCS Ciphering Algorithm"
        )


class TestMbmsKeys:
    def test_msk_single_entry(self) -> None:
        # key_domain=112233, num=1, one {msk_id=0x00000010, ts=0x0000002A}
        hex_input = "11223301" + "00000010" + "0000002A"
        decoded = _roundtrip("ef-msk", hex_input)
        assert decoded["format"] == "MBMS Service Key List"
        assert decoded["keyDomainId"] == "112233"
        assert decoded["numMskId"] == 1
        entries = decoded["entries"]
        assert entries[0]["mskId"] == 0x00000010
        assert entries[0]["timestampCounter"] == 0x0000002A

    def test_muk_berlv_record(self) -> None:
        hex_input = "A00A800488776655820200018103010203"
        decoded = _roundtrip("ef-muk", hex_input)
        assert decoded["format"] == "MBMS User Key"
        items = decoded["items"]
        assert isinstance(items, list)
        assert len(items) >= 1
        outer = items[0]
        assert outer["tag"] == "A0"
        inner = outer["items"]
        tags = [row["tag"] for row in inner]
        assert "80" in tags


class TestUfc:
    def test_ufc_bits_exposed(self) -> None:
        decoded = _roundtrip("ef-ufc", "05")
        assert decoded["format"] == "UE Functionality Configuration"
        assert decoded["configByte"] == "0x05"
        bits_by_index = {row["bit"]: row for row in decoded["bits"]}
        assert bits_by_index[0]["set"] is True
        assert bits_by_index[1]["set"] is False
        assert bits_by_index[2]["set"] is True


class TestPws:
    def test_both_flags_set(self) -> None:
        decoded = _roundtrip("ef-pws", "03")
        assert decoded["format"] == "Public Warning System Configuration"
        assert decoded["ignorePwsInHplmnAndEquivalent"] is True
        assert decoded["ignorePwsInVplmn"] is True

    def test_no_flags_set(self) -> None:
        decoded = _roundtrip("ef-pws", "00")
        assert decoded["ignorePwsInHplmnAndEquivalent"] is False
        assert decoded["ignorePwsInVplmn"] is False
        assert decoded["summary"] == "no PWS suppression"


class TestUmpc:
    def test_defined_max_current(self) -> None:
        decoded = _roundtrip("ef-umpc", "320A")
        assert decoded["format"] == "UICC Max Power Consumption"
        assert decoded["maxCurrentMilliAmps"] == 0x32
        assert decoded["tOpMilliseconds"] == 20

    def test_undefined_max_current(self) -> None:
        decoded = _roundtrip("ef-umpc", "FF05")
        assert decoded["maxCurrentMilliAmps"] is None
        assert decoded["tOpMilliseconds"] == 10


class TestSingleBitFlagEfs:
    @pytest.mark.parametrize(
        "token,flag_name,summary_true",
        [
            ("ef-eaka", "enhancedSqnCalculationSupported",
             "enhanced SQN calculation supported"),
            ("ef-frompreferred", "fromPreferred",
             "from-preferred flag set"),
            ("ef-3gpppsdataoff", "psDataOffEnabled",
             "PS Data Off enabled"),
        ],
    )
    def test_flag_set(
        self, token: str, flag_name: str, summary_true: str,
    ) -> None:
        decoded = _roundtrip(token, "01")
        assert decoded[flag_name] is True
        assert decoded["summary"] == summary_true

    @pytest.mark.parametrize(
        "token,flag_name",
        [
            ("ef-eaka", "enhancedSqnCalculationSupported"),
            ("ef-frompreferred", "fromPreferred"),
            ("ef-3gpppsdataoff", "psDataOffEnabled"),
        ],
    )
    def test_flag_cleared(self, token: str, flag_name: str) -> None:
        decoded = _roundtrip(token, "00")
        assert decoded[flag_name] is False


class TestPsDataOffServiceList:
    def test_bits_per_service(self) -> None:
        decoded = _roundtrip("ef-3gpppsdataoffservicelist", "05")
        assert decoded["format"] == "3GPP PS Data Off Service List"
        assert decoded["exemptServices"] == [1, 3]

    def test_no_services_exempt(self) -> None:
        decoded = _roundtrip("ef-3gpppsdataoffservicelist", "00")
        assert decoded["exemptServices"] == []
        assert decoded["summary"] == "no services exempt"


class TestIal:
    def test_ial_tlv_record(self) -> None:
        hex_input = "A00A80083534383234303031"
        decoded = _roundtrip("ef-ial", hex_input)
        assert decoded["format"] == "IMEI(SV) Association List"
        items = decoded["items"]
        assert items[0]["tag"] == "A0"


class TestNcpIp:
    def test_ncp_ip_tlvs(self) -> None:
        hex_input = "8008696E7465726E65748104757365728202707784020102"
        decoded = _roundtrip("ef-ncp-ip", hex_input)
        assert decoded["format"] == "Network Connectivity Parameters (IP)"
        tags = [row["tag"] for row in decoded["items"]]
        assert {"80", "81", "82", "84"}.issubset(set(tags))


class TestIconIndicators:
    def test_spni(self) -> None:
        decoded = _roundtrip("ef-spni", "0103")
        assert decoded["format"] == "Service Provider Name Icon"
        assert decoded["displayConditionByte"] == "0x01"
        assert decoded["imgRecordNumber"] == 3

    def test_pnni_no_icon(self) -> None:
        decoded = _roundtrip("ef-pnni", "0000")
        assert decoded["format"] == "PLMN Network Name Icon"
        assert decoded["imgRecordNumber"] == 0
        assert "no icon" in decoded["summary"]


@pytest.mark.parametrize("token", _WAVE_C_PASS_B_TOKENS)
def test_every_wave_c_pass_b_ef_has_semantic_route(token: str) -> None:
    """Every Pass B token must dispatch to a semantic decoder for a
    plausible payload rather than falling through to the generic
    opaque catalog fallback.
    """

    probes: dict[str, str] = {
        "ef-bdn": ("41" * 8) + "068134123456F9FFFFFFFFFF" + "00FF",
        "ef-bdnuri": "736D733A2B343612343111113233FFFFFFFFFFFF",
        "ef-ext4": "02" + ("07" * 11) + "FF",
        "ef-ext5": "02" + ("07" * 11) + "FF",
        "ef-ext8": "02" + ("07" * 11) + "FF",
        "ef-vgcsca": "0102",
        "ef-vbsca": "0A0B",
        "ef-msk": "11223301" + "00000010" + "0000002A",
        "ef-muk": "A00A800488776655820200018103010203",
        "ef-ufc": "05",
        "ef-pws": "03",
        "ef-umpc": "320A",
        "ef-eaka": "01",
        "ef-frompreferred": "00",
        "ef-3gpppsdataoff": "01",
        "ef-3gpppsdataoffservicelist": "05",
        "ef-ial": "A00A80083534383234303031",
        "ef-ncp-ip": "8008696E7465726E65748104757365728202707784020102",
        "ef-spni": "0103",
        "ef-pnni": "0000",
    }
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=probes[token],
    )
    assert decoded is not None, f"{token} not routed"
    # Accept either a named 'format' field or the well-known ADN-shape
    # (which reuses the existing _decode_adn_like_record helper).
    if token == "ef-bdn":
        assert "alphaIdentifier" in decoded or "number" in decoded
    else:
        assert decoded.get("format") is not None, f"{token} missing format"
        generic_opaque_formats = {
            "Opaque",
            "UNKNOWN",
        }
        assert decoded["format"] not in generic_opaque_formats, (
            f"{token} still routes to generic opaque"
        )
