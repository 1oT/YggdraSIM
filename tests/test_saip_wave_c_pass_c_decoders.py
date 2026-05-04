"""
semantic decoder coverage for ADF.ISIM / DF.MULTIMEDIA /
DF.MCS / MMS family EFs.

For every EF promoted from the generic opaque pass-through catalog we
verify three invariants:

1. Routing: the ``ef-*`` token dispatches to a semantic decoder (not
   the generic opaque catalog fallback).
2. Semantic: the decoder exposes the spec-named fields.
3. Roundtrip: ``encode_decoded_roundtrip_ef_content`` returns the exact
   input bytes via the ``hex`` field surfaced alongside the named
   keys.

Spec references (TS 31.103 / TS 31.102 §4.6 / TS 51.011):
  ef-gbabp             TS 31.103 §4.2.9  (GBA Bootstrapping Params)
  ef-uicciari          TS 31.103 §4.2.16 (UICC IARI list)
  ef-imsconfigdata     TS 31.103 §4.2.18 (IMS Config Data)
  ef-xcapconfigdata    TS 31.103 §4.2.19 (XCAP Config Data)
  ef-webrtcuri         TS 31.103 §4.2.20 (WebRTC URI)
  ef-mudmidconfigdata  TS 31.103 §4.2.21 (MuD/MiD Config Data)
  ef-mml               TS 31.102 §4.6.3.1 (MM Messages List)
  ef-mmdf              TS 31.102 §4.6.3.2 (MM Messages Data)
  ef-mst               TS 31.102 §4.6.4.1 (MCS Service Table)
  ef-mlpl              TS 31.102 §4.6.3.3 (MMS List Preferred)
  ef-mspl              TS 31.102 §4.6.3.4 (MMS Sender Preferred)
  ef-mmssmode          TS 31.102 §4.6.3.5 (MMS Storage Mode)
  ef-mmsicp            TS 51.011 §10.3.53 (MMS Issuer Conn Params)
  ef-mmsn              TS 51.011 §10.3.51 (MMS Notifications)
  ef-mmsucp            TS 51.011 §10.3.55 (MMS User Conn Params)
  ef-mmsup             TS 51.011 §10.3.54 (MMS User Preferences)
  ef-mmsconfig         3GPP2 C.S0023 §3.4.59 (CSIM MMS Config)
  ef-hrpdcap           3GPP2 C.S0023 §3.4.43 (HRPD Capability)
  ef-hrpdupp           3GPP2 C.S0023 §3.4.44 (HRPD User Profile)
  ef-spc               3GPP2 C.S0023 §3.4.39 (Service Programming Code)
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import _decode_known_ef_payload
from Tools.ProfilePackage.saip_asn1_encode import (
    encode_decoded_roundtrip_ef_content,
)


_WAVE_C_PASS_C_TOKENS: tuple[str, ...] = (
    "ef-gbabp",
    "ef-uicciari",
    "ef-imsconfigdata",
    "ef-xcapconfigdata",
    "ef-webrtcuri",
    "ef-mudmidconfigdata",
    "ef-mml",
    "ef-mmdf",
    "ef-mst",
    "ef-mlpl",
    "ef-mspl",
    "ef-mmssmode",
    "ef-mmsicp",
    "ef-mmsn",
    "ef-mmsucp",
    "ef-mmsup",
    "ef-mmsconfig",
    "ef-hrpdcap",
    "ef-hrpdupp",
    "ef-spc",
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


class TestGbabp:
    def test_lv_triple(self) -> None:
        # rand(4)=00112233 + b_tid(4)=01020304 + key_lifetime(1)=FF
        hex_input = "0400112233040102030401FF"
        decoded = _roundtrip("ef-gbabp", hex_input)
        assert decoded["format"] == "GBA Bootstrapping Parameters"
        assert decoded["rand"] == "00112233"
        assert decoded["bTid"] == "01020304"
        assert decoded["keyLifetime"] == "FF"
        assert decoded["randLength"] == 4
        assert decoded["bTidLength"] == 4
        assert decoded["keyLifetimeLength"] == 1


class TestUriAndIariBerTlv:
    def test_uicciari_tag80(self) -> None:
        # tag=80 len=0x15 (21) val="sip:+test@example.com"
        hex_input = "80157369703A2B74657374406578616D706C652E636F6D"
        decoded = _roundtrip("ef-uicciari", hex_input)
        items = decoded["items"]
        assert isinstance(items, list)
        assert items[0]["tag"] == "80"
        assert items[0]["name"] == "IARI (UTF-8)"

    def test_webrtcuri_tag80(self) -> None:
        hex_input = "80147765627274633A2B74657374406578616D706C65"
        decoded = _roundtrip("ef-webrtcuri", hex_input)
        items = decoded["items"]
        assert items[0]["tag"] == "80"


class TestConfigDataBerTlv:
    def test_ims_config_data(self) -> None:
        # tag=80 len=1 val=01 + tag=81 len=7 val="abcdefg"
        hex_input = "800101810761626364656667"
        decoded = _roundtrip("ef-imsconfigdata", hex_input)
        tags = [row["tag"] for row in decoded["items"]]
        assert "80" in tags and "81" in tags

    def test_mudmid_config_data(self) -> None:
        # tag=80 len=1 val=01 + tag=81 len=5 val="hello"
        hex_input = "8001018105" + "68656C6C6F"
        decoded = _roundtrip("ef-mudmidconfigdata", hex_input)
        tags = [row["tag"] for row in decoded["items"]]
        assert "80" in tags and "81" in tags

    def test_xcap_config_data(self) -> None:
        # outer tag=80 len=10 (0x0A) value contains nested tags
        # inner: 81 02 02 84 + 82 04 65787478 + 85 02 6A6F
        # = 4 + 6 + 4 = 14 bytes of inner -> too long for len=10
        # Use: 81 02 0284 + 82 02 6578 = 4+4 = 8 bytes
        hex_input = "800881020284820265 78".replace(" ", "")
        decoded = _roundtrip("ef-xcapconfigdata", hex_input)
        items = decoded["items"]
        assert items[0]["tag"] == "80"
        assert items[0]["name"] == "XCAP Config DO"


class TestMultimediaBerTlv:
    def test_mml_entry(self) -> None:
        hex_input = "A00A80020001810200048203010203"
        decoded = _roundtrip("ef-mml", hex_input)
        items = decoded["items"]
        outer = items[0]
        assert outer["tag"] == "A0"
        assert outer["name"] == "Multimedia message list entry"

    def test_mmdf_entry(self) -> None:
        hex_input = "A00680020123810102"
        decoded = _roundtrip("ef-mmdf", hex_input)
        items = decoded["items"]
        outer = items[0]
        assert outer["tag"] == "A0"


class TestMcsServiceTable:
    def test_mcs_service_bitmap(self) -> None:
        # 0x0007 in LE bit order: bits 0,1,2 of byte[0] => services 1,2,3.
        decoded = _roundtrip("ef-mst", "0700")
        assert decoded["format"] == "MCS Service Table"
        active = decoded["activeServices"]
        assert any("1: MCPTT UE configuration data" in row for row in active)
        assert any("2: MCPTT User profile data" in row for row in active)
        assert any("3: MCS Group configuration data" in row for row in active)


class TestMmsPreferredLists:
    def test_mlpl_entries(self) -> None:
        decoded = _roundtrip("ef-mlpl", "80055461736B2181010A")
        tags = [row["tag"] for row in decoded["items"]]
        assert "80" in tags and "81" in tags

    def test_mspl_entries(self) -> None:
        decoded = _roundtrip("ef-mspl", "800561646D696E81010A")
        tags = [row["tag"] for row in decoded["items"]]
        assert "80" in tags and "81" in tags


class TestMmsStorageMode:
    def test_enabled(self) -> None:
        decoded = _roundtrip("ef-mmssmode", "01")
        assert decoded["mmsStorageEnabled"] is True
        assert decoded["summary"] == "MMS storage on UICC enabled"

    def test_disabled(self) -> None:
        decoded = _roundtrip("ef-mmssmode", "00")
        assert decoded["mmsStorageEnabled"] is False


class TestMmsIcpAndUp:
    def test_mmsicp_tlvs(self) -> None:
        decoded = _roundtrip(
            "ef-mmsicp", "8001018104657865658202AA55",
        )
        tags = [row["tag"] for row in decoded["items"]]
        assert {"80", "81", "82"}.issubset(set(tags))

    def test_mmsup_tlvs(self) -> None:
        decoded = _roundtrip(
            "ef-mmsup", "8001018104757365728202AA55",
        )
        tags = [row["tag"] for row in decoded["items"]]
        assert "80" in tags and "81" in tags and "82" in tags


class TestMmsNotificationStruct:
    def test_mmsn_fields(self) -> None:
        # status(2)=0001 impl=08 notif=00AABBCC ext=FF (7 bytes notif+ext)
        hex_input = "00010800AABBCCDDFF"
        decoded = _roundtrip("ef-mmsn", hex_input)
        assert decoded["mmsStatusHex"] == "0001"
        assert decoded["mmsImplementationByte"] == "0x08"
        assert decoded["mmsImplementationWap"] is False
        assert decoded["extensionRecordIdentifier"] == "0xFF"
        assert decoded["mmsNotificationHex"] == "00AABBCCDD"


class TestAnnotatedOpaqueEfs:
    @pytest.mark.parametrize(
        "token,expected_format,expected_spec",
        [
            ("ef-mmsucp", "MMS User Connectivity Parameters",
             "TS 51.011 §10.3.55"),
            ("ef-mmsconfig", "CSIM MMS Configuration",
             "3GPP2 C.S0023 §3.4.59"),
            ("ef-hrpdcap", "HRPD Capability",
             "3GPP2 C.S0023 §3.4.43"),
            ("ef-hrpdupp", "HRPD User Profile Parameters",
             "3GPP2 C.S0023 §3.4.44"),
            ("ef-spc", "Service Programming Code",
             "3GPP2 C.S0023 §3.4.39"),
        ],
    )
    def test_spec_annotated_opaque(
        self, token: str, expected_format: str, expected_spec: str,
    ) -> None:
        decoded = _roundtrip(token, "AABBCCDDEEFF")
        assert decoded["format"] == expected_format
        assert decoded["specReference"] == expected_spec


@pytest.mark.parametrize("token", _WAVE_C_PASS_C_TOKENS)
def test_every_wave_c_pass_c_ef_has_semantic_route(token: str) -> None:
    """Every Pass C token must dispatch to a semantic decoder for a
    plausible payload rather than falling through to the generic
    opaque catalog fallback.
    """

    probes: dict[str, str] = {
        "ef-gbabp": "0400112233040102030401FF",
        "ef-uicciari": "80157369703A2B74657374406578616D706C652E636F6D",
        "ef-imsconfigdata": "800101810761626364656667",
        "ef-xcapconfigdata": "8008810202848202657 8".replace(" ", ""),
        "ef-webrtcuri": "80147765627274633A2B74657374406578616D706C65",
        "ef-mudmidconfigdata": "80010181056 8656C6C6F".replace(" ", ""),
        "ef-mml": "A00A80020001810200048203010203",
        "ef-mmdf": "A00680020123810102",
        "ef-mst": "0700",
        "ef-mlpl": "80055461736B2181010A",
        "ef-mspl": "800561646D696E81010A",
        "ef-mmssmode": "01",
        "ef-mmsicp": "8001018104657865658202AA55",
        "ef-mmsn": "00010800AABBCCDDFF",
        "ef-mmsucp": "AABBCC",
        "ef-mmsup": "8001018104757365728202AA55",
        "ef-mmsconfig": "AABBCCDD",
        "ef-hrpdcap": "00010203",
        "ef-hrpdupp": "11223344",
        "ef-spc": "12345678",
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
