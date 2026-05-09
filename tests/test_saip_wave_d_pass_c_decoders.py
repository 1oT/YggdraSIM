"""
Wave D Pass C — CSIM legacy / analog / registration / PUZL / PRL / LCS
annotated opaque EFs.

This is the final pass of the opaque-catalog promotion campaign. With
these 19 EFs upgraded, every entry in
:data:`_OPAQUE_PASSTHROUGH_EF_CATALOG` has a dedicated ``if token ==
...`` route in ``_decode_known_ef_payload`` and the generic opaque
catalog label is only ever reached for truly unreferenced EFs.

Spec references (3GPP2 C.S0023):
  ef-ah           §3.4.4   (Analog Home)
  ef-aloc         §3.4.5   (Analog Location)
  ef-aop          §3.4.6   (Analog Operational Parameters)
  ef-bakpara      §3.4.53  (BAK Parameters)
  ef-cdmacnl      §3.4.17  (CDMA Co-operative Network List)
  ef-distregi     §3.4.16  (Distance-based Registration)
  ef-jdl          §3.4.64  (Java Download List)
  ef-lcscp        §3.4.65  (LCS Client Profile)
  ef-lcsver       §3.4.66  (LCS Version)
  ef-max-prl      §3.4.22  (Maximum PRL)
  ef-maxpuzl      §3.4.42  (Maximum PUZL)
  ef-puzl         §3.4.41  (Preferred User Zone List)
  ef-rc           §3.4.44  (Root Certificate)
  ef-snregi       §3.4.15  (SID/NID-based Registration)
  ef-spcs         §3.4.25  (SPC Status)
  ef-ssci         §3.4.38  (Short Message Service Call Indicator)
  ef-ssfc         §3.4.39  (SS Feature Code)
  ef-upbakpara    §3.4.54  (Updated BAK Parameters)
  ef-znregi       §3.4.18  (Zone-based Registration)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _OPAQUE_PASSTHROUGH_EF_CATALOG,
    _decode_known_ef_payload,
    _lookup_opaque_passthrough_ef,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_D_PASS_C_TOKENS: tuple[str, ...] = (
    "ef-ah",
    "ef-aloc",
    "ef-aop",
    "ef-bakpara",
    "ef-cdmacnl",
    "ef-distregi",
    "ef-jdl",
    "ef-lcscp",
    "ef-lcsver",
    "ef-max-prl",
    "ef-maxpuzl",
    "ef-puzl",
    "ef-rc",
    "ef-snregi",
    "ef-spcs",
    "ef-ssci",
    "ef-ssfc",
    "ef-upbakpara",
    "ef-znregi",
)


_EXPECTED_FORMAT: dict[str, str] = {
    "ef-ah": "Analog Home",
    "ef-aloc": "Analog Location",
    "ef-aop": "Analog Operational Parameters",
    "ef-bakpara": "BAK Parameters",
    "ef-cdmacnl": "CDMA Co-operative Network List",
    "ef-distregi": "Distance-based Registration",
    "ef-jdl": "Java Download List",
    "ef-lcscp": "LCS Client Profile",
    "ef-lcsver": "LCS Version",
    "ef-max-prl": "Maximum PRL",
    "ef-maxpuzl": "Maximum PUZL",
    "ef-puzl": "Preferred User Zone List",
    "ef-rc": "Root Certificate",
    "ef-snregi": "SID/NID-based Registration",
    "ef-spcs": "SPC Status",
    "ef-ssci": "Short Message Service Call Indicator",
    "ef-ssfc": "SS Feature Code",
    "ef-upbakpara": "Updated BAK Parameters",
    "ef-znregi": "Zone-based Registration",
}


def _roundtrip(token: str, hex_input: str) -> dict[str, object]:
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=hex_input,
    )
    assert decoded is not None, f"{token} was not routed to a semantic decoder"
    hex_field = str(decoded.get("hex", ""))
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


class TestCsimLegacyAnnotatedOpaqueEfs:
    @pytest.mark.parametrize("token", _WAVE_D_PASS_C_TOKENS)
    def test_spec_reference_and_hex_fields(self, token: str) -> None:
        hex_input = "0102030405060708"
        decoded = _roundtrip(token, hex_input)
        assert decoded["format"] == _EXPECTED_FORMAT[token]
        assert decoded["specReference"].startswith("3GPP2 C.S0023")
        assert decoded["length"] == 8


class TestCatalogShadowing:
    @pytest.mark.parametrize("token", _WAVE_D_PASS_C_TOKENS)
    def test_semantic_format_shadows_catalog_label(self, token: str) -> None:
        catalog_label = _lookup_opaque_passthrough_ef(token)
        assert catalog_label is not None, (
            f"{token} is missing from the opaque catalog"
        )
        decoded = _decode_known_ef_payload(
            ef_key=token, fid=None, hex_clean="0102030405060708",
        )
        assert decoded is not None
        assert decoded["format"] == _EXPECTED_FORMAT[token]
        assert "Opaque" not in decoded["format"]


def test_every_wave_d_pass_c_ef_has_semantic_route() -> None:
    for token in _WAVE_D_PASS_C_TOKENS:
        decoded = _decode_known_ef_payload(
            ef_key=token, fid=None, hex_clean="0102030405060708",
        )
        assert decoded is not None, f"{token} is not routed"
        assert "format" in decoded
        assert "specReference" in decoded
        assert "hex" in decoded


def test_opaque_catalog_has_no_remaining_gap() -> None:
    """Final invariant: every catalog key has a semantic dispatch route.

    We detect this by monkey-patching ``_lookup_opaque_passthrough_ef``
    to record every time the catalog fallback is consulted. After Wave
    D Pass C, no catalog key should fall through to the generic opaque
    decoder for an 8-byte probe.
    """

    from Tools.ProfilePackage import saip_asn1_decode as decode_module

    hit_tokens: set[str] = set()
    original = decode_module._lookup_opaque_passthrough_ef

    def tracer(ef_key: str) -> str | None:
        result = original(ef_key)
        if result is not None:
            hit_tokens.add(str(ef_key).lower())
        return result

    decode_module._lookup_opaque_passthrough_ef = tracer
    try:
        for raw_key in _OPAQUE_PASSTHROUGH_EF_CATALOG.keys():
            decode_module._decode_known_ef_payload(
                ef_key=raw_key.lower(),
                fid=None,
                hex_clean="0102030405060708",
            )
    finally:
        decode_module._lookup_opaque_passthrough_ef = original

    assert hit_tokens == set(), (
        "Opaque catalog still owns format label for: "
        f"{sorted(hit_tokens)!r}"
    )
