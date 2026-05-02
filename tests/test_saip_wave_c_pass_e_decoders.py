"""Semantic decoder coverage for DF.TELECOM / DF.PHONEBOOK / ICE /
DF.V2X / EAP / MCS / multimedia EFs.

For every EF promoted from the generic opaque pass-through catalog we
verify three invariants:

1. Routing: the ``ef-*`` token dispatches to a semantic decoder (not
   the generic opaque catalog fallback).
2. Semantic: the decoder exposes the spec-named fields.
3. Roundtrip: ``encode_decoded_roundtrip_ef_content`` returns the exact
   input bytes via the ``hex`` field surfaced alongside the named
   keys.

Spec references:
  ef-aas              TS 31.102 §4.4.2.13 (Additional Alpha String)
  ef-pbc              TS 31.102 §4.4.2.5  (Phonebook Control)
  ef-puri             TS 31.102 §4.4.2.17 (Phonebook URI)
  ef-uid              TS 31.102 §4.4.2.14 (Phonebook Unique Identifier)
  ef-ice-dn           TS 31.102 §4.4.3.3  (ICE Dialling Numbers)
  ef-ice-ff           TS 31.102 §4.4.3.4  (ICE Free Format)
  ef-ice-graphics     TS 31.102 §4.4.3.5  (ICE Graphics)
  ef-icon             TS 31.102 §4.6.1.1  (Icon)
  ef-img              TS 31.102 §4.6.1.2  (Image)
  ef-iidf             TS 31.102 §4.6.1.3  (Image Instance Data File)
  ef-launch-scws      TS 31.102 §4.4.8    (Launch SCWS)
  ef-launchpad        Operator Launchpad  (vendor-specific)
  ef-mcs-config       TS 31.102 §4.6.4.2  (MCS Configuration)
  ef-v2x-config       TS 31.102 §4.6.5.3  (V2X Configuration)
  ef-v2xp-Uu          TS 31.102 §4.6.5.4  (V2X Uu Parameters)
  ef-v2xp-pc5         TS 31.102 §4.6.5.5  (V2X PC5 Parameters)
  ef-vst              TS 31.102 §4.6.5.2  (V2X Service Table)
  ef-curid            TS 102 310 §5.2.2   (EAP Current ID)
  ef-ps               TS 102 310 §5.2.2   (EAP Pseudonym)
  ef-realm            TS 102 310 §5.2.2   (EAP Realm)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_C_PASS_E_TOKENS: tuple[str, ...] = (
    "ef-aas",
    "ef-pbc",
    "ef-puri",
    "ef-uid",
    "ef-ice-dn",
    "ef-ice-ff",
    "ef-ice-graphics",
    "ef-icon",
    "ef-img",
    "ef-iidf",
    "ef-launch-scws",
    "ef-launchpad",
    "ef-mcs-config",
    "ef-v2x-config",
    "ef-v2xp-Uu",
    "ef-v2xp-pc5",
    "ef-vst",
    "ef-curid",
    "ef-ps",
    "ef-realm",
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


class TestPhonebookEfs:
    def test_aas_ber_tlv(self) -> None:
        # tag=80 len=5 val="Hello"
        decoded = _roundtrip("ef-aas", "80054 8656C6C6F".replace(" ", ""))
        assert decoded["format"] == "Phonebook Additional Alpha String"
        items = decoded["items"]
        assert items[0]["tag"] == "80"

    def test_pbc_bits(self) -> None:
        decoded = _roundtrip("ef-pbc", "03")
        assert decoded["controlByte"] == "0x03"
        bits = {row["name"]: row["set"] for row in decoded["bits"]}
        assert bits["hiddenEntry"] is True
        assert bits["inUse"] is True

    def test_puri_routes_to_uri(self) -> None:
        decoded = _roundtrip(
            "ef-puri", "800B6578616D706C652E636F6D",
        )
        assert decoded["format"] == "Phonebook URI"

    def test_uid_big_endian(self) -> None:
        decoded = _roundtrip("ef-uid", "01FE")
        assert decoded["uid"] == 0x01FE
        assert decoded["uidHex"] == "01FE"


class TestIceFamily:
    def test_ice_dn_routes_to_adn(self) -> None:
        # Alpha="AA" (2 bytes) + 14-byte footer:
        #  number_len=05, ton_npi=81, digits=21 43 65 87 09 + 5 x FF
        #  + CCP=FF, Ext1=FF
        hex_input = "4141" + "05" + "81" + "2143658709FFFFFFFFFF" + "FF" + "FF"
        decoded = _roundtrip("ef-ice-dn", hex_input)
        assert decoded["alphaIdentifier"] == "AA"
        assert decoded["numberLength"] == 5
        assert decoded["tonNpi"] == "0x81"
        assert decoded["number"].startswith("12345")

    def test_ice_ff_spec_annotated(self) -> None:
        decoded = _roundtrip("ef-ice-ff", "01020304")
        assert decoded["format"] == "ICE Free Format"
        assert decoded["specReference"] == "TS 31.102 §4.4.3.4"

    def test_ice_graphics_spec_annotated(self) -> None:
        decoded = _roundtrip("ef-ice-graphics", "89504E470D0A1A0A")
        assert decoded["format"] == "ICE Graphics"
        assert decoded["specReference"] == "TS 31.102 §4.4.3.5"


class TestImageFamily:
    def test_icon_spec_annotated(self) -> None:
        decoded = _roundtrip("ef-icon", "010203")
        assert decoded["format"] == "Icon"
        assert decoded["specReference"] == "TS 31.102 §4.6.1.1"

    def test_img_metadata(self) -> None:
        # num_images=1 + one 9-byte slot:
        # width=16, height=16, coding=01, offset=0203, length=0405, fid=0607
        hex_input = "01" + "10100102030405" + "0607"
        decoded = _roundtrip("ef-img", hex_input)
        assert decoded["numImages"] == 1
        slot = decoded["images"][0]
        assert slot["widthPixels"] == 16
        assert slot["heightPixels"] == 16
        assert slot["imageCoding"] == "0x01"
        assert slot["offsetHex"] == "0203"
        assert slot["lengthBytes"] == 0x0405
        assert slot["instanceFileId"] == "0607"

    def test_iidf_spec_annotated(self) -> None:
        decoded = _roundtrip("ef-iidf", "000102030405")
        assert decoded["format"] == "Image Instance Data File"
        assert decoded["specReference"] == "TS 31.102 §4.6.1.3"


class TestLaunchEfs:
    def test_launch_scws_uri(self) -> None:
        decoded = _roundtrip(
            "ef-launch-scws",
            "800B687474703A2F2F7363",
        )
        assert decoded["format"] == "Launch SCWS URL"

    def test_launchpad_annotated(self) -> None:
        decoded = _roundtrip("ef-launchpad", "010203")
        assert decoded["format"] == "Operator Launchpad"


class TestMcsAndV2xConfig:
    def test_mcs_config_tlvs(self) -> None:
        decoded = _roundtrip("ef-mcs-config", "8001018102AA55")
        tags = [row["tag"] for row in decoded["items"]]
        assert "80" in tags and "81" in tags

    def test_v2x_config_tlv(self) -> None:
        decoded = _roundtrip("ef-v2x-config", "8001018102AA55")
        items = decoded["items"]
        assert items[0]["tag"] == "80"

    def test_v2xp_uu_annotated(self) -> None:
        decoded = _roundtrip("ef-v2xp-Uu", "AABBCC")
        assert decoded["format"] == "V2X Uu Parameters"
        # Semantic decoder exposes ``reference``; opaque fallback (prior to
        # earlier work) exposed ``specReference``. Accept either for
        # forward/backward-compat with older tree-pane consumers.
        ref = decoded.get("reference") or decoded.get("specReference")
        assert ref == "TS 31.102 §4.6.5.4"

    def test_v2xp_pc5_annotated(self) -> None:
        decoded = _roundtrip("ef-v2xp-pc5", "AABBCC")
        assert decoded["format"] == "V2X PC5 Parameters"
        ref = decoded.get("reference") or decoded.get("specReference")
        assert ref == "TS 31.102 §4.6.5.5"

    def test_vst_service_bitmap(self) -> None:
        # TS 31.102 Rel-18 §4.6.5.2: byte 0 is the "Coding of V2X data"
        # indicator (0x00 = XML/TS 24.385), byte 1+ carries the service
        # bitmap. 0x03 in byte 1 activates services 1 and 2.
        decoded = _roundtrip("ef-vst", "0003")
        assert decoded["format"] == "V2X Service Table"
        assert decoded["codingOfV2xData"]["name"] == "XML (TS 24.385)"
        active_names = [entry["name"] for entry in decoded["services"]]
        assert "V2X configuration data" in active_names
        assert "V2X policy configuration data over PC5" in active_names


class TestEapIdentityEfs:
    def test_curid_tlv(self) -> None:
        decoded = _roundtrip("ef-curid", "80046F706572")
        items = decoded["items"]
        assert items[0]["tag"] == "80"

    def test_ps_tlv(self) -> None:
        decoded = _roundtrip("ef-ps", "800468656C6C")
        items = decoded["items"]
        assert items[0]["tag"] == "80"

    def test_realm_tlv(self) -> None:
        decoded = _roundtrip(
            "ef-realm",
            "800B6578616D706C652E636F6D",
        )
        items = decoded["items"]
        assert items[0]["tag"] == "80"


@pytest.mark.parametrize("token", _WAVE_C_PASS_E_TOKENS)
def test_every_wave_c_pass_e_ef_has_semantic_route(token: str) -> None:
    """Every Pass E token must dispatch to a semantic decoder for a
    plausible payload rather than falling through to the generic
    opaque catalog fallback.
    """

    probes: dict[str, str] = {
        "ef-aas": "8005" + "48656C6C6F",
        "ef-pbc": "03",
        "ef-puri": "800B6578616D706C652E636F6D",
        "ef-uid": "01FE",
        "ef-ice-dn": (
            "4141" + "05" + "81" + "2143658709FFFFFFFFFF" + "FF" + "FF"
        ),
        "ef-ice-ff": "01020304",
        "ef-ice-graphics": "89504E470D0A1A0A",
        "ef-icon": "010203",
        "ef-img": "01" + "10100102030405" + "0607",
        "ef-iidf": "000102030405",
        "ef-launch-scws": "800B687474703A2F2F7363",
        "ef-launchpad": "010203",
        "ef-mcs-config": "8001018102AA55",
        "ef-v2x-config": "8001018102AA55",
        "ef-v2xp-Uu": "AABBCC",
        "ef-v2xp-pc5": "AABBCC",
        "ef-vst": "0300",
        "ef-curid": "80046F706572",
        "ef-ps": "800468656C6C",
        "ef-realm": "800B6578616D706C652E636F6D",
    }
    decoded = _decode_known_ef_payload(
        ef_key=token, fid=None, hex_clean=probes[token],
    )
    assert decoded is not None, f"{token} not routed"
    assert decoded.get("format") is not None, f"{token} missing format"
    generic_opaque_formats = {"Opaque", "UNKNOWN"}
    assert decoded["format"] not in generic_opaque_formats, (
        f"{token} still routes to generic opaque"
    )
