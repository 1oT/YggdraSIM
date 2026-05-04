"""
CSIM MIP / SIP / BCSMS / 3GPD / WAP / OTA annotated
opaque EFs.

These 3GPP2 C.S0023 structures have fixed spec sections but their
inner layout is operator/device-specific. We promote them from the
generic opaque catalog to :func:`_decode_spec_opaque_ef` so the TUI
surfaces:

  * a semantic ``format`` label (shadowing the generic "Opaque EF ..."
    catalog label),
  * the formal spec reference for the operator, and
  * ``hex`` / ``length`` for byte-exact roundtrip.

Spec references:
  ef-3gpdopm         3GPP2 C.S0023 §3.4.45
  ef-3gpduppext      3GPP2 C.S0023 §3.4.77
  ef-bcsmscfg        3GPP2 C.S0023 §3.4.47
  ef-bcsmsp          3GPP2 C.S0023 §3.4.48
  ef-bcsmspref       3GPP2 C.S0023 §3.4.49
  ef-bcsmstable      3GPP2 C.S0023 §3.4.50
  ef-me3gpdopc       3GPP2 C.S0023 §3.4.46
  ef-mecrp           3GPP2 C.S0023 §3.4.63
  ef-mipflags        3GPP2 C.S0023 §3.4.27
  ef-mipsp           3GPP2 C.S0023 §3.4.28
  ef-mipupp          3GPP2 C.S0023 §3.4.29
  ef-sippapss        3GPP2 C.S0023 §3.4.31
  ef-sipsp           3GPP2 C.S0023 §3.4.32
  ef-sipupp          3GPP2 C.S0023 §3.4.33
  ef-ota             3GPP2 C.S0023 §3.4.78
  ef-otapaspc        3GPP2 C.S0023 §3.4.79
  ef-sp              3GPP2 C.S0023 §3.4.21
  ef-tcpconfig       3GPP2 C.S0023 §3.4.76
  ef-wapbrowserbm    3GPP2 C.S0023 §3.4.73
  ef-wapbrowsercp    3GPP2 C.S0023 §3.4.74
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _OPAQUE_PASSTHROUGH_EF_CATALOG,
    _decode_known_ef_payload,
)
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_D_PASS_B_TOKENS: tuple[str, ...] = (
    "ef-3gpdopm",
    "ef-3gpduppext",
    "ef-bcsmscfg",
    "ef-bcsmsp",
    "ef-bcsmspref",
    "ef-bcsmstable",
    "ef-me3gpdopc",
    "ef-mecrp",
    "ef-mipflags",
    "ef-mipsp",
    "ef-mipupp",
    "ef-sippapss",
    "ef-sipsp",
    "ef-sipupp",
    "ef-ota",
    "ef-otapaspc",
    "ef-sp",
    "ef-tcpconfig",
    "ef-wapbrowserbm",
    "ef-wapbrowsercp",
)


_EXPECTED_FORMAT: dict[str, str] = {
    "ef-3gpdopm": "3GPD Operating Mode",
    "ef-3gpduppext": "3GPD UPP Extension",
    "ef-bcsmscfg": "Broadcast SMS Configuration",
    "ef-bcsmsp": "Broadcast SMS Parameters",
    "ef-bcsmspref": "Broadcast SMS Preferences",
    "ef-bcsmstable": "Broadcast SMS Table",
    "ef-me3gpdopc": "ME 3GPD Operating Capability",
    "ef-mecrp": "ME-Specific Crypto",
    "ef-mipflags": "MIP Flags",
    "ef-mipsp": "MIP Status Parameters",
    "ef-mipupp": "MIP User Profile Parameters",
    "ef-sippapss": "SIP PAP Supplementary Services",
    "ef-sipsp": "SIP Status Parameters",
    "ef-sipupp": "SIP User Profile Parameters",
    "ef-ota": "OTA Parameters",
    "ef-otapaspc": "OTAPA Service Programming Code",
    "ef-sp": "Service Preferences",
    "ef-tcpconfig": "TCP Configuration",
    "ef-wapbrowserbm": "WAP Browser Bookmarks",
    "ef-wapbrowsercp": "WAP Browser Connection Parameters",
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


class TestCsimAnnotatedOpaqueEfs:
    @pytest.mark.parametrize("token", _WAVE_D_PASS_B_TOKENS)
    def test_spec_reference_and_hex_fields(self, token: str) -> None:
        hex_input = "0102030405060708"
        decoded = _roundtrip(token, hex_input)
        assert decoded["format"] == _EXPECTED_FORMAT[token]
        assert decoded["specReference"].startswith("3GPP2 C.S0023")
        assert decoded["length"] == 8


class TestCatalogShadowing:
    @pytest.mark.parametrize("token", _WAVE_D_PASS_B_TOKENS)
    def test_semantic_format_shadows_catalog_label(self, token: str) -> None:
        catalog_label = _OPAQUE_PASSTHROUGH_EF_CATALOG.get(token)
        if catalog_label is None:
            # The catalog is case-sensitive on the verbatim key; lower
            # our token to match.
            for key, value in _OPAQUE_PASSTHROUGH_EF_CATALOG.items():
                if key.lower() == token:
                    catalog_label = value
                    break
        assert catalog_label is not None, (
            f"{token} is missing from the opaque catalog"
        )
        decoded = _decode_known_ef_payload(
            ef_key=token, fid=None, hex_clean="0102030405060708",
        )
        assert decoded is not None
        assert decoded["format"] == _EXPECTED_FORMAT[token]
        # The semantic label must be distinct from the generic catalog
        # "Opaque ..." label so the TUI renders the upgraded name.
        assert "Opaque" not in decoded["format"]


def test_every_wave_d_pass_b_ef_has_semantic_route() -> None:
    for token in _WAVE_D_PASS_B_TOKENS:
        decoded = _decode_known_ef_payload(
            ef_key=token, fid=None, hex_clean="0102030405060708",
        )
        assert decoded is not None, f"{token} is not routed"
        assert "format" in decoded
        assert "specReference" in decoded
        assert "hex" in decoded
