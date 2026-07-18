"""Cross-surface regression tests for EPS/5GS location-file layouts.

The embedded mobile identities include their TS 24.301/24.501 length and
identity-header octets.  These tests keep the profile decoder, simulator
defaults, and generated GUI bundle on the same byte offsets.
"""

from __future__ import annotations

from pathlib import Path

from SIMCARD.etsi_fs import _default_df_5gs_nodes, _encode_ef_epsloci
from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_5gs_loci,
    _decode_eps_loci,
    _decode_known_ef_payload,
)


_PLMN_001_01 = bytes.fromhex("00F110")
_EPS_ASSIGNED = bytes.fromhex(
    "0BF6" "00F110" "0001" "02" "11223344"
    "00F110" "0001"
    "02"
)
_FIVE_G_ASSIGNED = bytes.fromhex(
    "000B" "F2" "00F110" "AA" "BBCC" "11223344"
    "00F110" "000001"
    "02"
)


def test_epsloci_decoder_honours_mobile_identity_header_and_offsets() -> None:
    decoded = _decode_eps_loci(_EPS_ASSIGNED.hex())

    assert decoded is not None
    assert decoded["length"] == 18
    assert decoded["guti"] == {
        "assigned": True,
        "hex": "0BF600F11000010211223344",
        "identityLength": 11,
        "identityLengthHex": "0B",
        "identityHeaderHex": "F6",
        "plmn": "001-01",
        "plmnRaw": "00F110",
        "mmeGroupIdHex": "0001",
        "mmeCodeHex": "02",
        "mTmsiHex": "11223344",
    }
    assert decoded["tai"]["plmn"] == "001-01"
    assert decoded["tai"]["tacHex"] == "0001"
    assert decoded["updateStatus"]["label"] == "roaming not allowed"
    assert "validationErrors" not in decoded


def test_epsloci_dispatch_no_longer_uses_the_11_byte_loci_layout() -> None:
    decoded = _decode_known_ef_payload(
        ef_key="ef-epsloci",
        fid="6FE3",
        hex_clean=_EPS_ASSIGNED.hex(),
    )

    assert decoded is not None
    assert decoded["format"] == "EPS Location Information"
    assert decoded["guti"]["mTmsiHex"] == "11223344"


def test_epsloci_reports_a_nonstandard_assigned_identity_prefix() -> None:
    malformed = bytearray(_EPS_ASSIGNED)
    malformed[0:2] = b"\x0A\xF4"

    decoded = _decode_eps_loci(malformed.hex())

    assert decoded is not None
    assert decoded["validationErrors"] == [
        "GUTI identity length is 0x0A; expected 0x0B",
        "GUTI identity header is 0xF4; expected 0xF6",
    ]


def test_5gsloci_decoder_honours_mobile_identity_header_and_offsets() -> None:
    decoded = _decode_5gs_loci(
        _FIVE_G_ASSIGNED.hex(),
        format_name="5GS 3GPP Location Info",
        spec_reference="TS 31.102 §4.4.11.2",
    )

    assert decoded is not None
    assert decoded["length"] == 20
    assert decoded["guti"]["identityLength"] == 11
    assert decoded["guti"]["identityLengthHex"] == "000B"
    assert decoded["guti"]["identityHeaderHex"] == "F2"
    assert decoded["guti"]["plmn"] == "001-01"
    assert decoded["guti"]["amfRegionId"] == "0xAA"
    assert decoded["guti"]["amfSetAndPointerHex"] == "BBCC"
    assert decoded["guti"]["tmsiHex"] == "11223344"
    assert decoded["tai"]["plmn"] == "001-01"
    assert decoded["tai"]["tacHex"] == "000001"
    assert decoded["updateStatus"]["label"] == "5U3 ROAMING NOT ALLOWED"
    assert "validationErrors" not in decoded


def test_location_defaults_use_unassigned_guti_and_separate_tai_offsets() -> None:
    eps = _encode_ef_epsloci(_PLMN_001_01)
    assert len(eps) == 18
    assert eps[:12] == b"\xFF" * 12
    assert eps[12:17] == _PLMN_001_01 + b"\x00\x00"
    assert eps[17] == 0x01

    nodes = _default_df_5gs_nodes(plmn_bytes=_PLMN_001_01)
    by_name = {node.name: node for node in nodes}
    for name, fid in (
        ("EF.5GS3GPPLOCI", "4F01"),
        ("EF.5GSN3GPPLOCI", "4F02"),
    ):
        node = by_name[name]
        assert node.fid == fid
        assert len(node.data) == 20
        assert node.data[:13] == b"\xFF" * 13
        assert node.data[13:19] == _PLMN_001_01 + b"\x00\x00\x00"
        assert node.data[19] == 0x01
    assert by_name["EF.5GS3GPPNSC"].fid == "4F03"
    assert by_name["EF.5GSN3GPPNSC"].fid == "4F04"


def test_frontend_source_and_built_bundle_share_the_standard_df5gs_map() -> None:
    for path in (
        Path("gui_frontend/src/js/saip-workbench.js"),
        Path("yggdrasim_common/gui_server/static/app.js"),
    ):
        source = path.read_text(encoding="utf-8")
        template_map = source.index("var _SAIP_TEMPLATE_FIDS = {")
        anchor = source.index('"df-5gs": {', template_map)
        mapping = source[anchor : anchor + 500]
        assert '"ef-5gs3gpploci": ["4F01", null]' in mapping
        assert '"ef-5gsn3gpploci": ["4F02", null]' in mapping
        assert '"ef-5gs3gppnsc": ["4F03", null]' in mapping
        assert '"ef-5gsn3gppnsc": ["4F04", null]' in mapping
        assert "ef-5gs3gppguti" not in source
        assert "[0x00, 0x0B, 0xF2].concat(gp)" in source
        assert "bytes.slice(3, 6)" in source
        assert "bytes.slice(9, 13)" in source
