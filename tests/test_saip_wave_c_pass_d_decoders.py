"""
Wave C Pass D — semantic decoder coverage for ADF.CSIM / OPT-CSIM core
EFs (3GPP2 C.S0023 / C.S0065).

For every EF promoted from the generic opaque pass-through catalog we
verify three invariants:

1. Routing: the ``ef-*`` token dispatches to a semantic decoder (not
   the generic opaque catalog fallback).
2. Semantic: the decoder exposes the spec-named fields.
3. Roundtrip: ``encode_decoded_roundtrip_ef_content`` returns the exact
   input bytes via the ``hex`` field surfaced alongside the named
   keys.

Spec references (3GPP2 C.S0023 / C.S0065):
  ef-csim-st          C.S0065 §5.2.28  (CSIM Service Table)
  ef-accolc           C.S0023 §3.4.20  (Access Overload Class)
  ef-mipcap           C.S0023 §3.4.36  (MIP Capabilities)
  ef-ipv6cap          C.S0023 §3.4.45  (IPv6 Capability)
  ef-smscap           C.S0023 §3.4.38  (SMS Capability)
  ef-sipcap           C.S0023 §3.4.46  (SIP Capability)
  ef-3gcik            C.S0023 §3.4.40  (3G CIK)
  ef-imsi-m           C.S0023 §3.4.8   (IMSI-M)
  ef-imsi-t           C.S0023 §3.4.9   (IMSI-T)
  ef-ruimid           C.S0023 §3.4.41  (R-UIM ID)
  ef-sf-euimid        C.S0023 §3.4.42  (Short Form EUIMID)
  ef-esn-meid-me      C.S0023 §3.4.48  (ESN/MEID-ME)
  ef-mdn              C.S0023 §3.4.7   (Mobile Directory Number)
  ef-prl              C.S0023 §3.4.24  (Preferred Roaming List)
  ef-eprl             C.S0023 §3.4.25  (Extended PRL)
  ef-cdmahome         C.S0023 §3.4.27  (CDMA Home SID/NID)
  ef-home-tag         C.S0023 §3.4.22  (Home Tag)
  ef-group-tag        C.S0023 §3.4.21  (Group Tag)
  ef-specific-tag     C.S0023 §3.4.23  (Specific Tag)
  ef-tmsi             C.S0023 §3.4.17  (CSIM TMSI)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_C_PASS_D_TOKENS: tuple[str, ...] = (
    "ef-csim-st",
    "ef-accolc",
    "ef-mipcap",
    "ef-ipv6cap",
    "ef-smscap",
    "ef-sipcap",
    "ef-3gcik",
    "ef-imsi-m",
    "ef-imsi-t",
    "ef-ruimid",
    "ef-sf-euimid",
    "ef-esn-meid-me",
    "ef-mdn",
    "ef-prl",
    "ef-eprl",
    "ef-cdmahome",
    "ef-home-tag",
    "ef-group-tag",
    "ef-specific-tag",
    "ef-tmsi",
)


def _roundtrip(token: str, hex_input: str) -> dict[str, object]:
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=hex_input,
    )
    assert decoded is not None, f"{token} was not routed to a semantic decoder"
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


class TestCsimServiceTable:
    def test_active_services_exposed(self) -> None:
        # 0x07 (byte0) -> services 1, 2, 3 active.
        # 0x0F (byte1) -> services 9, 10, 11, 12 active.
        decoded = _roundtrip("ef-csim-st", "070F")
        assert decoded["format"] == "CSIM Service Table"
        active = decoded["activeServices"]
        assert any("1: Local phone book" in row for row in active)
        assert any("3: Short message storage (SMS)" in row for row in active)
        assert any("9: Extension 1" in row for row in active)
        assert decoded["activeCount"] == 7


class TestAccolc:
    def test_accolc_lower_nibble(self) -> None:
        decoded = _roundtrip("ef-accolc", "05")
        assert decoded["format"] == "Access Overload Class"
        assert decoded["accolc"] == 5

    def test_accolc_upper_nibble_reserved(self) -> None:
        decoded = _roundtrip("ef-accolc", "A3")
        assert decoded["accolc"] == 3
        assert decoded["reservedNibble"] == "0xA"


class TestCsimCapabilities:
    @pytest.mark.parametrize(
        "token,raw,expected",
        [
            ("ef-mipcap", "07", ["Simple IP", "Mobile IPv4", "Mobile IPv6"]),
            ("ef-mipcap", "00", []),
            ("ef-ipv6cap", "03", ["IPv6 supported", "Dual-stack supported"]),
            ("ef-smscap", "05", ["Point-to-point SMS", "Enhanced SMS"]),
            ("ef-sipcap", "04", ["SIP MWI"]),
        ],
    )
    def test_capability_flags(
        self, token: str, raw: str, expected: list[str],
    ) -> None:
        decoded = _roundtrip(token, raw)
        assert decoded["enabled"] == expected


class TestAnnotatedOpaqueCsimEfs:
    @pytest.mark.parametrize(
        "token,expected_format,expected_spec",
        [
            ("ef-3gcik", "3G Cellular Identification Key",
             "3GPP2 C.S0023 §3.4.40"),
            ("ef-imsi-m", "IMSI-M", "3GPP2 C.S0023 §3.4.8"),
            ("ef-imsi-t", "IMSI-T", "3GPP2 C.S0023 §3.4.9"),
            ("ef-ruimid", "R-UIM ID", "3GPP2 C.S0023 §3.4.41"),
            ("ef-sf-euimid", "Short Form EUIMID",
             "3GPP2 C.S0023 §3.4.42"),
            ("ef-esn-meid-me", "ESN / MEID ME",
             "3GPP2 C.S0023 §3.4.48"),
            ("ef-prl", "Preferred Roaming List",
             "3GPP2 C.S0023 §3.4.24"),
            ("ef-eprl", "Extended Preferred Roaming List",
             "3GPP2 C.S0023 §3.4.25"),
            ("ef-cdmahome", "CDMA Home SID/NID",
             "3GPP2 C.S0023 §3.4.27"),
            ("ef-home-tag", "Home Tag", "3GPP2 C.S0023 §3.4.22"),
            ("ef-group-tag", "Group Tag", "3GPP2 C.S0023 §3.4.21"),
            ("ef-specific-tag", "Specific Tag",
             "3GPP2 C.S0023 §3.4.23"),
            ("ef-tmsi", "CSIM TMSI", "3GPP2 C.S0023 §3.4.17"),
        ],
    )
    def test_spec_annotated_opaque(
        self, token: str, expected_format: str, expected_spec: str,
    ) -> None:
        decoded = _roundtrip(token, "AABBCCDDEEFF")
        assert decoded["format"] == expected_format
        assert decoded["specReference"] == expected_spec


class TestMdnBcdDecode:
    def test_mdn_bcd_digits(self) -> None:
        # len=0x0B (11 digits), BCD "12345678901" padded to 10 bytes.
        # BCD low-nibble first: "21 43 65 87 09 F1 FF FF FF FF"
        hex_input = "0B" + "21436587091FFFFFFFFF"
        decoded = _roundtrip("ef-mdn", hex_input)
        assert decoded["format"] == "Mobile Directory Number (CSIM)"
        assert decoded["mdnLength"] == 0x0B
        assert decoded["mdn"].startswith("1234567890")


@pytest.mark.parametrize("token", _WAVE_C_PASS_D_TOKENS)
def test_every_wave_c_pass_d_ef_has_semantic_route(token: str) -> None:
    """Every Pass D token must dispatch to a semantic decoder for a
    plausible payload rather than falling through to the generic
    opaque catalog fallback or the ``ef-csim-*`` opaque bucket.
    """

    probes: dict[str, str] = {
        "ef-csim-st": "070F",
        "ef-accolc": "05",
        "ef-mipcap": "07",
        "ef-ipv6cap": "03",
        "ef-smscap": "05",
        "ef-sipcap": "04",
        "ef-3gcik": "0102030405",
        "ef-imsi-m": "00000000000000000001",
        "ef-imsi-t": "00000000000000000002",
        "ef-ruimid": "0102030405060708",
        "ef-sf-euimid": "01020304050607",
        "ef-esn-meid-me": "0102030405060708",
        "ef-mdn": "0B21436587091FFFFFFFFF",
        "ef-prl": "00000000000000000001",
        "ef-eprl": "00000000000000000002",
        "ef-cdmahome": "01020304",
        "ef-home-tag": "48545F30",
        "ef-group-tag": "47545F30",
        "ef-specific-tag": "53545F30",
        "ef-tmsi": "0102030405",
    }
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=probes[token],
    )
    assert decoded is not None, f"{token} not routed"
    assert decoded.get("format") is not None, f"{token} missing format"
    # Must not be the generic CSIM opaque bucket (which uppercases the
    # token suffix, e.g. "CSIM ST" instead of "CSIM Service Table").
    assert not str(decoded["format"]).startswith("CSIM ") or (
        decoded["format"] == "CSIM Service Table"
        or decoded["format"] == "CSIM TMSI"
        or decoded["format"] == "Mobile Directory Number (CSIM)"
    ), f"{token} still routes to generic CSIM opaque bucket"
    generic_opaque_formats = {"Opaque", "UNKNOWN"}
    assert decoded["format"] not in generic_opaque_formats, (
        f"{token} still routes to generic opaque"
    )
