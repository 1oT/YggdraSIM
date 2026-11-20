# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Context-aware APDU / TLV decoding (``Tools.Asn1TlvDecode.context``).

Every vector is built from the standards' own test bodies (the 3GPP USIM
AID prefix, the GSMA ISD-R AID, the DISPLAY TEXT example of ETSI TS 102 223
v18.3 Annex B) and the project's 8988 test IIN.
"""

from __future__ import annotations

import json
import re
import sys
from io import StringIO

import pytest

from Tools.Asn1TlvDecode import gsma_schema
from Tools.Asn1TlvDecode.context import (
    classify_command,
    decode_context_text,
    decode_fcp,
    decode_gp_registry,
    decode_rsp_object,
    parse_exchanges,
)
from Tools.Asn1TlvDecode.main import DecodeError, decode_bytes, run_cli


def _tlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + bytes([len(value)]) + value


USIM_AID = bytes.fromhex("A0000000871002")
ISDR_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")

FCP_USIM = _tlv(
    "62",
    _tlv("82", bytes.fromhex("7821"))
    + _tlv("83", bytes.fromhex("7FF0"))
    + _tlv("84", USIM_AID)
    + _tlv("A5", _tlv("80", bytes.fromhex("71")))
    + _tlv("8A", bytes.fromhex("05"))
    + _tlv("8B", bytes.fromhex("2F0601"))
    + _tlv("C6", _tlv("90", bytes.fromhex("40")) + _tlv("83", bytes.fromhex("01"))),
)

REGISTRY_ISDR = _tlv(
    "E3",
    _tlv("4F", ISDR_AID) + _tlv("9F70", bytes.fromhex("0F")) + _tlv("C5", bytes.fromhex("9EFE80")),
)

# TS 102 223 v18.3 Annex B table B.1.
DISPLAY_TEXT = bytes.fromhex("D0158103012100820281028D04044341" "54C80401020304")


def _nodes_by_tag(nodes: list[dict]) -> dict[str, dict]:
    return {node["tag"]: node for node in nodes}


class TestClassification:
    def test_select_by_aid_is_uicc_with_fcp_response(self) -> None:
        ctx = classify_command(0x00, 0xA4, 0x04, 0x04, USIM_AID)
        assert ctx.domain == "uicc"
        assert ctx.name == "SELECT FILE"
        assert ctx.response_kind == "fcp"
        assert "DF name" in ctx.summary
        p2 = [entry for entry in ctx.header if entry["label"] == "P2"][0]
        assert "return FCP template" in p2["meaning"]
        assert p2["spec"] == "TS 102 221 v18.4 table 11.2"

    def test_gp_get_status_is_not_etsi_status(self) -> None:
        gp = classify_command(0x80, 0xF2, 0x40, 0x02, bytes.fromhex("4F00"))
        assert gp.domain == "gp"
        assert gp.name == "GET STATUS"
        assert gp.response_kind == "gp_registry"
        etsi = classify_command(0x80, 0xF2, 0x00, 0x0C, b"")
        assert etsi.domain == "uicc"
        assert etsi.name == "STATUS"

    def test_store_data_with_bf_payload_is_es10(self) -> None:
        ctx = classify_command(0x80, 0xE2, 0x91, 0x00, bytes.fromhex("BF2D00"))
        assert ctx.domain == "es10"
        assert ctx.payload_kind == "es10_request"
        assert ctx.spec == "SGP.22 v3.1 section 5.7.2 table 47"
        plain = classify_command(0x80, 0xE2, 0x80, 0x00, bytes.fromhex("0102"))
        assert plain.domain == "gp"
        assert plain.payload_kind == "gp_store_data"

    def test_cat_and_auth_domains(self) -> None:
        assert classify_command(0x80, 0x12, 0x00, 0x00, b"").domain == "cat"
        assert classify_command(0x80, 0xC2, 0x00, 0x00, b"\xd6\x00").payload_kind == "cat_envelope"
        auth = classify_command(0x00, 0x88, 0x00, 0x81, b"")
        assert auth.domain == "auth"
        assert "3G/EPS/5G" in auth.summary

    def test_install_roles_follow_table_11_41(self) -> None:
        ctx = classify_command(0x80, 0xE6, 0x0C, 0x00, b"")
        assert ctx.summary == "INSTALL [for make selectable] + [for install]"
        more = classify_command(0x80, 0xE6, 0x82, 0x00, b"")
        p1 = [entry for entry in more.header if entry["label"] == "P1"][0]
        assert p1["meaning"].startswith("more INSTALL commands follow")

    def test_class_byte_fields_name_channel_and_secure_messaging(self) -> None:
        ctx = classify_command(0x84, 0xE2, 0x91, 0x00, b"")
        channel = [entry for entry in ctx.header if entry["label"] == "Logical channel"][0]
        sm = [entry for entry in ctx.header if entry["label"] == "Secure messaging"][0]
        assert channel["value"] == 0
        assert "GlobalPlatform secure channel" in sm["meaning"]


class TestPayloadDecoders:
    def test_terminal_profile_names_the_facilities_of_each_byte(self) -> None:
        # TS 102 223 v18.3 section 5.2; the header is the context's, the rows the profile's.
        result = decode_context_text("80 10 00 00 05 FF 1F 00 00 7F")
        payload = result["exchanges"][0]["command"]["payload"]
        fields = {field["label"]: field for field in payload["fields"]}
        assert payload["kind"] == "terminal_profile"
        assert fields["Profile bytes"]["value"] == "FF1F00007F"
        assert fields["Byte 3 (Proactive UICC)"]["meaning"] == "nothing claimed"
        events = fields["Byte 5 (Event driven information)"]["meaning"].split("; ")
        assert events[0] == "Proactive UICC: SET UP EVENT LIST"
        assert "Event: Location status" in events
        assert any(note.startswith("info: 8.8 Call Control by USIM") for note in payload["notes"])

    def test_a_full_terminal_profile_reads_clean_and_flags_bytes_past_39(self) -> None:
        from yggdrasim_common.stk_terminal import terminal_profile_apdu

        clean = decode_context_text(terminal_profile_apdu().hex())
        payload = clean["exchanges"][0]["command"]["payload"]
        assert "notes" not in payload
        assert payload["fields"][-1]["label"] == "Byte 39"
        padded = (terminal_profile_apdu()[5:] + bytes.fromhex("0001")).hex()
        tail = decode_context_text(f"8010000029{padded}")["exchanges"][0]["command"]["payload"]
        assert tail["fields"][-1] == {"label": "Bytes 40-41", "value": "0001", "meaning": "RFU"}
        assert any("Byte 41 onwards" in note for note in tail["notes"])

    def test_fcp_template_names_fields_by_clause(self) -> None:
        payload = decode_fcp(FCP_USIM)
        nodes = _nodes_by_tag(payload["nodes"])
        assert payload["kind"] == "fcp"
        assert "7FF0" in payload["title"]
        assert nodes["82"]["decoded"] == "DF or ADF, shareable"
        assert nodes["84"]["decoded"] == "USIM (3GPP)"
        assert nodes["8A"]["decoded"] == "operational state - activated"
        assert nodes["8B"]["decoded"] == "EF_ARR 2F06 record 1"
        assert nodes["8B"]["spec"] == "TS 102 221 v18.4 section 11.1.1.4.7"
        assert "disabled" in nodes["C6"]["decoded"]

    def test_registry_entry_reads_lcs_from_sd_table_when_privileged(self) -> None:
        payload = decode_gp_registry(REGISTRY_ISDR, subset_p1=0x40)
        entry = payload["nodes"][0]
        children = _nodes_by_tag(entry["children"])
        assert entry["tag"] == "E3"
        assert children["4F"]["decoded"] == "ISDR"
        assert children["9F70"]["decoded"] == "PERSONALIZED"
        assert children["C5"]["decoded"].startswith("Security Domain")
        plain_app = _tlv("E3", _tlv("4F", USIM_AID) + _tlv("9F70", bytes.fromhex("07")) + _tlv("C5", bytes.fromhex("000000")))
        app_children = _nodes_by_tag(decode_gp_registry(plain_app, subset_p1=0x40)["nodes"][0]["children"])
        assert app_children["9F70"]["decoded"] == "SELECTABLE"

    @pytest.mark.parametrize(
        ("aid_hex", "package"),
        [
            # Oracle's Java Card API export files.
            ("A0000000620001", "java.lang"),
            ("A00000006202080101", "javacardx.framework.util.intx"),
            # GPC v2.4 section A.1.2.
            ("A00000015100", "org.globalplatform"),
            # ETSI TS 102 241 v18.1 tables C.1b and C.6.
            ("A0000000090005FFFFFFFF8912000000", "uicc.toolkit"),
            ("A0000000090005FFFFFFFF8917000000", "uicc.suspendresume"),
            # ETSI TS 102 267 v19 table C.1.
            ("A0000000090005FFFFFFFF8915000000", "uicc.connection"),
            # 3GPP TS 31.130 v19.2 annex C.
            ("A0000000871005FFFFFFFF8913400000", "uicc.usim.suci"),
            # 3GPP TS 43.019 v6.0.0 annex C.
            ("A0000000090003FFFFFFFF8910710002", "sim.toolkit"),
        ],
    )
    def test_load_file_entries_name_their_api_package(self, aid_hex: str, package: str) -> None:
        payload = decode_gp_registry(_tlv("E3", _tlv("4F", bytes.fromhex(aid_hex))), subset_p1=0x20)
        assert payload["nodes"][0]["children"][0]["decoded"] == package

    def test_a_package_aid_is_matched_whole(self) -> None:
        # One octet more or less is another load file, not the API package.
        for aid_hex in ("A00000006200", "A000000062000101", "A0000000090005FFFFFFFF89120000"):
            payload = decode_gp_registry(_tlv("E3", _tlv("4F", bytes.fromhex(aid_hex))), subset_p1=0x20)
            assert "decoded" not in payload["nodes"][0]["children"][0]

    def test_notation_keeps_the_value_of_a_named_aid(self) -> None:
        data = _tlv("E3", _tlv("4F", bytes.fromhex("A0000000620101"))) + _tlv("E3", _tlv("4F", bytes.fromhex("F0010203040501")))
        notation = decode_context_text((data + bytes.fromhex("9000")).hex(), hint="response")["notation"]
        assert "4F AID = 'A0000000620101'H (javacard.framework)" in notation
        assert "4F AID = 'F0010203040501'H\n" in notation


class TestExchanges:
    def test_trace_with_markers_and_fcp_response(self) -> None:
        text = "> 00A4040407A0000000871002\n< " + FCP_USIM.hex().upper() + "9000"
        result = decode_context_text(text)
        assert result["inputKind"] == "apdu"
        exchange = result["exchanges"][0]
        assert exchange["command"]["payload"]["fields"][0]["meaning"] == "USIM (3GPP)"
        assert exchange["response"]["sw"]["sw"] == "9000"
        assert exchange["response"]["payload"]["kind"] == "fcp"

    def test_gui_bus_line_format_is_parsed(self) -> None:
        exchanges = parse_exchanges("→ 00A4000C023F00 · ← · sw=9000 · 1.42 ms")
        assert len(exchanges) == 1
        assert exchanges[0].command == bytes.fromhex("00A4000C023F00")
        assert exchanges[0].sw == bytes.fromhex("9000")

    def test_get_status_registry_response_uses_the_subset(self) -> None:
        text = "> 80F24002024F0000\n< " + REGISTRY_ISDR.hex().upper() + "9000"
        result = decode_context_text(text)
        response = result["exchanges"][0]["response"]["payload"]
        assert response["kind"] == "gp_registry"
        assert _nodes_by_tag(response["nodes"][0]["children"])["9F70"]["decoded"] == "PERSONALIZED"

    def test_install_for_install_reads_lv_fields(self) -> None:
        body = (
            bytes([16]) + ISDR_AID + bytes([0]) + bytes([16])
            + bytes.fromhex("A0000005591010FFFFFFFF8900001000")
            + bytes([3]) + bytes.fromhex("80C000") + bytes([2]) + bytes.fromhex("C900") + bytes([0])
        )
        apdu = "80E60C00" + f"{len(body):02X}" + body.hex().upper() + "00"
        result = decode_context_text(apdu)
        payload = result["exchanges"][0]["command"]["payload"]
        labels = {entry["label"]: entry for entry in payload["fields"]}
        assert payload["spec"] == "GPC v2.3.1 table 11-43"
        assert labels["Executable Load File AID"]["meaning"] == "ISDR"
        assert labels["Privileges"]["meaning"] == "Security Domain, Trusted Path, Authorized Management"
        assert payload["nodes"][0]["tag"] == "C9"

    def test_proactive_command_from_annex_b(self) -> None:
        text = "> 8012000017\n< " + DISPLAY_TEXT.hex().upper() + "9000"
        result = decode_context_text(text)
        payload = result["exchanges"][0]["response"]["payload"]
        assert payload["kind"] == "cat"
        assert payload["title"].endswith("command number 1, DISPLAY TEXT, qualifier 00")
        children = _nodes_by_tag(payload["nodes"][0]["children"])
        assert children["02"]["decoded"] == "UICC -> Display"
        assert children["0D"]["decoded"] == "CAT"
        assert children["01"]["comprehensionRequired"] is True
        # Annex B calls byte 18 ('C8') the text attribute tag; the tag registry
        # (TS 101 220 v19 table 7.23) assigns '48' to 3GPP2 and text attribute
        # to '50', and the decoder follows the registry.
        assert children["48"]["name"] == "Reserved for 3GPP2 (3GPP2 tag 2)"
        assert children["48"]["comprehensionRequired"] is True

    def test_authenticate_3g_request_and_db_response(self) -> None:
        rand = bytes(range(16))
        autn = bytes(range(16, 32))
        command = "0088008122" + "10" + rand.hex() + "10" + autn.hex() + "00"
        response = "DB08" + "0011223344556677" + "08" + "AABBCCDDEEFF0011" + "08" + "8877665544332211" + "9000"
        result = decode_context_text("> " + command + "\n< " + response)
        exchange = result["exchanges"][0]
        request = {entry["label"]: entry["value"] for entry in exchange["command"]["payload"]["fields"]}
        assert request["RAND"] == rand.hex().upper()
        assert request["AUTN"] == autn.hex().upper()
        answer = {entry["label"]: entry["value"] for entry in exchange["response"]["payload"]["fields"]}
        assert answer["CK"] == "AABBCCDDEEFF0011"
        assert exchange["response"]["payload"]["title"].startswith("Successful 3G")

    def test_get_response_chain_reassembles_the_es10_answer(self) -> None:
        text = (
            "> 80E2910003BF2E00\n"
            "< 6112\n"
            "> 00C0000012\n"
            "< BF2E128010" + "00112233445566778899AABBCCDDEEFF" + "9000"
        )
        result = decode_context_text(text)
        first, second = result["exchanges"]
        assert first["response"]["chained"] is True
        assert first["response"]["sw"]["followUp"].startswith("GET RESPONSE")
        assert second["command"]["continues"] == "STORE DATA"
        payload = second["response"]["payload"]
        assert payload["kind"] == "es10"
        assert payload["tag"] == "BF2E"
        assert "GetEuiccChallengeResponse" in payload["typeCandidates"]

    def test_selected_file_names_the_read_binary_content(self) -> None:
        text = (
            "> 00A4000C027FF0\n< 9000\n"
            "> 00A4000C026F07\n< 9000\n"
            "> 00B0000009\n< 0809101010101010109000"
        )
        result = decode_context_text(text)
        payload = result["exchanges"][2]["response"]["payload"]
        assert payload["title"] == "EF 6F07 content"
        fields = {entry["label"]: entry["value"] for entry in payload["fields"]}
        assert fields["imsi"] == "001010101010101"


class TestStandaloneInputs:
    def test_bare_fcp_is_recognised(self) -> None:
        result = decode_context_text(FCP_USIM.hex())
        assert result["inputKind"] == "tlv"
        assert result["context"]["domain"] == "uicc"
        assert result["payload"]["kind"] == "fcp"

    def test_response_with_trailing_status_word_is_split(self) -> None:
        result = decode_context_text("BF22038201029000")
        assert result["inputKind"] == "response"
        assert result["sw"]["sw"] == "9000"
        assert result["payload"]["tag"] == "BF22"

    def test_status_word_alone(self) -> None:
        result = decode_context_text("6A82")
        assert result["inputKind"] == "sw"
        assert result["sw"]["meaning"].startswith("File not found")

    def test_hint_forces_domain(self) -> None:
        forced = decode_context_text(REGISTRY_ISDR.hex(), hint="gp")
        assert forced["context"]["domain"] == "gp"
        assert forced["payload"]["kind"] == "gp_registry"

    def test_empty_and_garbage_inputs_raise(self) -> None:
        with pytest.raises(DecodeError):
            decode_context_text("   ")
        with pytest.raises(DecodeError):
            decode_context_text("not hex at all")

    @pytest.mark.parametrize("command", ["00", "00A4", "00A400"])
    def test_a_command_shorter_than_its_header_is_reported_not_raised(self, command: str) -> None:
        result = decode_context_text(f"> {command}")
        exchange = result["exchanges"][0]
        assert exchange["command"] == {"hex": command, "error": "APDU input must be at least 4 bytes"}
        assert exchange["context"]["summary"] == "APDU header could not be parsed"

    def test_one_command_per_marked_line_decodes_each_line(self) -> None:
        text = "> 00A4080C022FE2\n> 00B000000A\n> 00A4040008A000000151000000"
        result = decode_context_text(text)
        names = [exchange["command"]["name"] for exchange in result["exchanges"]]
        assert names == ["SELECT FILE", "READ BINARY", "SELECT FILE"]
        assert all("response" not in exchange for exchange in result["exchanges"])

    def test_notation_mentions_the_domain(self) -> None:
        result = decode_context_text("> 00A4040407A0000000871002")
        assert "SELECT FILE" in result["notation"]
        assert "UICC (ETSI TS 102 221)" in result["notation"]


@pytest.mark.skipif(not gsma_schema.rsp_specification_status()["available"], reason="pySim RSP schema not compiled")
class TestSchemaDecode:
    def test_profile_info_list_response_decodes_by_type(self) -> None:
        # ICCID 8988201234567890123 as EF_ICCID stores it: nibble-swapped, F padded.
        text = "> 80E2910003BF2D0000\n< BF2D14A012E3105A0A988802214365870921F39F7001019000"
        result = decode_context_text(text)
        response = result["exchanges"][0]["response"]["payload"]
        assert response["schemaType"] == "ProfileInfoListResponse"
        assert response["schema"]["kind"] == "choice"
        assert response["schema"]["choice"] == "profileInfoListOk"
        iccid = response["schema"]["children"][0]["children"][0]["children"][0]
        assert iccid["name"] == "iccid"
        assert iccid["decoded"] == "8988201234567890123"

    def test_sgp32_types_are_compiled_when_the_asset_exists(self) -> None:
        status = gsma_schema.rsp_specification_status()
        if not any("SGP.32" in module for module in status["modules"]):
            pytest.skip("SGP.32 asset not unpacked")
        assert gsma_schema.has_type("EuiccPackageRequest")
        assert gsma_schema.has_type("ProfileInfoListResponse")

    def test_sgp32_euicc_info2_keeps_its_iot_specific_info(self) -> None:
        # SGP.32 v1.3 declares its own EUICCInfo2 and IoTSpecificInfo; an SGP.22 module that
        # declares IoTSpecificInfo too (an empty SEQUENCE in SGP.22 v3.1) must not take over.
        status = gsma_schema.rsp_specification_status()
        if not any(module.startswith("SGP.32 v1.3") for module in status["modules"]):
            pytest.skip("SGP.32 v1.3 asset not unpacked")
        ski = bytes.fromhex("11" * 20)
        info2 = _tlv(
            "BF22",
            _tlv("81", bytes.fromhex("020300")) + _tlv("82", bytes.fromhex("020500"))
            + _tlv("83", bytes.fromhex("010203")) + _tlv("84", bytes.fromhex("0103"))
            + _tlv("85", bytes.fromhex("0780")) + _tlv("88", bytes.fromhex("0490"))
            + _tlv("A9", _tlv("04", ski)) + _tlv("AA", _tlv("04", ski))
            + _tlv("04", bytes.fromhex("010000")) + _tlv("0C", b"")
            + _tlv("90", b"\x00")
            + _tlv("B4", _tlv("A0", _tlv("04", bytes.fromhex("010300"))) + bytes.fromhex("81008200")),
        )
        text = "> 80E2910003BF220000\n< " + info2.hex().upper() + "9000"
        response = decode_context_text(text)["exchanges"][0]["response"]["payload"]
        assert response["schemaType"] == "EUICCInfo2"
        assert response["schemaJson"]["iotSpecificInfo"] == {
            "iotVersion": [{"hex": "010300"}], "ecallSupported": None, "fallbackSupported": None,
        }


def test_sgp32_compiles_with_rsp_asn_first_or_last() -> None:
    # SGP.32 v1.3 imports OperatorId from RSPDefinitions, which the pinned pySim declares
    # (upstream_patches/osmocom-pysim-rsp-operatorid/). pySim's asn1/rsp files are read in
    # directory order, which ext4 leaves to its hash; a missing name surfaced only as
    # "SGP.32 module skipped".
    asn1tools = pytest.importorskip("asn1tools")
    asset = gsma_schema._sgp32_asset_path()
    if not asset.is_file():
        pytest.skip("SGP.32 v1.3 asset not unpacked")
    try:
        from importlib import resources

        directory = resources.files("pySim.esim").joinpath("asn1").joinpath("rsp")
        files = sorted((entry for entry in directory.iterdir() if entry.name.endswith(".asn")),
                       key=lambda entry: entry.name != "rsp.asn")
    except (ImportError, OSError):
        pytest.skip("pySim not importable")
    for ordered in (files, list(reversed(files))):
        text = "\n".join(entry.read_text(encoding="utf-8") for entry in ordered) + "\n"
        spec = asn1tools.compile_string(text + "\n" + asset.read_text(encoding="utf-8"), codec="der")
        assert "SGP32Definitions" in spec.modules


# The BF-tagged types SGP.22 v3.1 added: ES10 (sections 5.7.3, 5.7.23-5.7.29), ES9+ (5.6.6,
# 5.6.7), ES11 (5.8.3) and DeleteNotificationForDc of AuthenticateClientRequest (5.6.3).
SGP22_V31_BF_TYPES = (
    "EuiccConfiguredDataRequest", "EuiccConfiguredDataResponse",
    "LoadRpmPackageRequest", "LoadRpmPackageResult",
    "VerifySmdsResponseRequest", "VerifySmdsResponseResponse",
    "CheckEventRequest", "CheckEventResponse", "AlertData",
    "VerifyDeviceChangeRequest", "VerifyDeviceChangeResponse",
    "ConfirmDeviceChangeRequest", "ConfirmDeviceChangeResponse",
    "PrepareDeviceChangeRequest", "PrepareDeviceChangeResponse",
    "VerifySmdpResponseRequest", "VerifySmdpResponseResponse",
    "CheckProgressRequest", "CheckProgressResponse",
    "VerifyProfileRecoveryRequest", "VerifyProfileRecoveryResponse",
    "DeleteNotificationForDc",
)

SKI_V2 = bytes.fromhex("11" * 20)
SKI_V3 = bytes.fromhex("22" * 20)

# EUICCInfo1 of an SGP.22 v3.1 eUICC: lowestSvn [2], the CI lists [9] and [10],
# euiccCiPKIdListForSigningV3 [17], euiccRspCapability [8], highestSvn [19].
EUICC_INFO1_V3 = _tlv(
    "BF20",
    _tlv("82", bytes.fromhex("030100"))
    + _tlv("A9", _tlv("04", SKI_V2))
    + _tlv("AA", _tlv("04", SKI_V2))
    + _tlv("B1", _tlv("04", SKI_V3))
    + _tlv("88", bytes.fromhex("05900020"))
    + _tlv("93", bytes.fromhex("030100")),
)


# The pinned pySim carries the SGP.22 v3.1 module (upstream_patches/osmocom-pysim-rsp-v3-module/);
# only a missing pySim skips, as for TestSchemaDecode.
@pytest.mark.skipif(not gsma_schema.rsp_specification_status()["available"], reason="pySim RSP schema not compiled")
class TestSchemaDecodeV3:
    def test_every_v31_bf_type_resolves(self) -> None:
        assert [name for name in SGP22_V31_BF_TYPES if not gsma_schema.has_type(name)] == []
        assert "SGP.22 v3.1 (pySim rsp_v3)" in gsma_schema.rsp_specification_status()["modules"]

    def test_v31_only_type_decodes_with_the_v31_module(self) -> None:
        # ES10a GetEuiccConfiguredData (SGP.22 v3.1 section 5.7.3), which replaced
        # GetEuiccConfiguredAddresses under the same tag.
        response_hex = (
            "BF3C24" + "8010" + b"smdp.example.com".hex() + "8110" + b"smds.example.com".hex()
        ).upper()
        result = decode_context_text("> 80E2910003BF3C0000\n< " + response_hex + "9000")
        exchange = result["exchanges"][0]
        request = exchange["command"]["payload"]
        response = exchange["response"]["payload"]
        assert request["schemaType"] == "EuiccConfiguredDataRequest"
        assert response["schemaType"] == "EuiccConfiguredDataResponse"
        assert response["schemaJson"] == {"defaultDpAddress": "smdp.example.com", "rootDsAddress": "smds.example.com"}
        assert response["schemaSource"] == ["SGP.22 v3.1 (pySim rsp_v3)"]

    def test_types_of_the_joint_compile_keep_their_source(self) -> None:
        text = "> 80E2910003BF2D0000\n< BF2D14A012E3105A0A988802214365870921F39F7001019000"
        response = decode_context_text(text)["exchanges"][0]["response"]["payload"]
        assert response["schemaType"] == "ProfileInfoListResponse"
        assert "SGP.22 v3.1 (pySim rsp_v3)" not in response["schemaSource"]

    def test_euicc_info1_keeps_its_v3_members(self) -> None:
        text = "> 80E2910003BF200000\n< " + EUICC_INFO1_V3.hex().upper() + "9000"
        response = decode_context_text(text)["exchanges"][0]["response"]["payload"]
        assert response["schemaType"] == "EUICCInfo1"
        assert response["schemaSource"] == ["SGP.22 v3.1 (pySim rsp_v3)"]
        decoded = response["schemaJson"]
        assert decoded["highestSvn"] == {"hex": "030100"}
        assert decoded["euiccCiPKIdListForSigningV3"] == [{"hex": SKI_V3.hex()}]

    def test_a_v2_euicc_info1_decodes_under_the_v31_names(self) -> None:
        info1 = _tlv(
            "BF20",
            _tlv("82", bytes.fromhex("020500")) + _tlv("A9", _tlv("04", SKI_V2)) + _tlv("AA", _tlv("04", SKI_V2)),
        )
        text = "> 80E2910003BF200000\n< " + info1.hex().upper() + "9000"
        decoded = decode_context_text(text)["exchanges"][0]["response"]["payload"]["schemaJson"]
        assert sorted(decoded) == ["euiccCiPKIdListForSigning", "euiccCiPKIdListForVerification", "lowestSvn"]
        assert decoded["lowestSvn"] == {"hex": "020500"}

    def test_store_metadata_request_keeps_its_v3_members(self) -> None:
        # SGP.22 v3.1 section 5.5.3; pySim's v2 text has no estimatedProfileSize.
        from SCP11.pysim_support import pysim_rsp_v3_asn1

        request = pysim_rsp_v3_asn1().encode("StoreMetadataRequest", {
            "iccid": bytes.fromhex("988802214365870921F3"),
            "serviceProviderName": "SP",
            "profileName": "Test",
            "estimatedProfileSize": 65536,
        })
        text = f"> 80E29100{len(request):02X}{request.hex().upper()}\n< 9000"
        command = decode_context_text(text)["exchanges"][0]["command"]["payload"]
        assert command["schemaType"] == "StoreMetadataRequest"
        assert command["schemaSource"] == ["SGP.22 v3.1 (pySim rsp_v3)"]
        assert command["schemaJson"]["estimatedProfileSize"] == 65536


# SGP.32 v1.3 §2.11.1.2: an eIM asking for every IPA and eUICC data item, with
# its eimTransactionId.
IPA_EUICC_DATA_REQUEST = bytes.fromhex("BF52195C0DA081A2BF20BF228384A5A6A8A983080000000000002475")


def _reading_lines(notation: str) -> list[str]:
    # Sibling values are aligned in one column; a single space around '=' keeps the
    # assertions readable.
    return [re.sub(r"\s+= ", " = ", line.strip(), count=1) for line in notation.splitlines()]


def _require_sgp32() -> None:
    # docs/ is gitignored: without the SGP.32 v1.3 asset the joint compile is SGP.22 alone.
    if not any(module.startswith("SGP.32 v1.3") for module in gsma_schema.rsp_specification_status()["modules"]):
        pytest.skip("SGP.32 v1.3 asset not unpacked")


@pytest.mark.skipif(not gsma_schema.rsp_specification_status()["available"], reason="pySim RSP schema not compiled")
class TestRspObjectReading:
    def test_a_bf52_request_is_not_read_as_the_response(self) -> None:
        _require_sgp32()
        # IpaEuiccDataResponse (§2.11.2.2) shares 'BF52'; asn1tools reads its extensible
        # CHOICE as (None, None) for this content instead of failing.
        with pytest.raises(ValueError):
            gsma_schema.decode_type_strict("IpaEuiccDataResponse", IPA_EUICC_DATA_REQUEST)
        payload = decode_context_text(IPA_EUICC_DATA_REQUEST.hex())["payload"]
        assert payload["schemaType"] == "IpaEuiccDataRequest"
        assert payload["title"] == "IpaEuiccDataRequest"

    def test_the_tag_list_names_the_ipa_euicc_data_members(self) -> None:
        _require_sgp32()
        reading = decode_rsp_object(IPA_EUICC_DATA_REQUEST)
        assert reading is not None
        tag_list = reading["schema"]["children"][0]
        assert tag_list["name"] == "tagList"
        assert [(entry["name"], entry["value"]) for entry in tag_list["children"]] == [
            ("A0", "notificationsList"), ("81", "defaultSmdpAddress"), ("A2", "euiccPackageResultList"),
            ("BF20", "euiccInfo1"), ("BF22", "euiccInfo2"), ("83", "rootSmdsAddress"),
            ("84", "associationToken"), ("A5", "eumCertificate"), ("A6", "euiccCertificate"),
            ("A8", "ipaCapabilities"), ("A9", "deviceInfo"),
        ]
        lines = _reading_lines(reading["notation"])
        assert lines[0] == "IpaEuiccDataRequest  [SGP.32-v1.3]"
        assert "tagList = 'A081A2BF20BF228384A5A6A8A9'H (11 IpaEuiccData tags, SGP.32 v1.3 §2.11.1.2)" in lines
        assert "BF20  euiccInfo1" in lines
        assert lines[-1] == "eimTransactionId = '0000000000002475'H"

    def test_a_response_with_ipa_capabilities_names_its_bits(self) -> None:
        _require_sgp32()
        response = gsma_schema.rsp_specification().encode(
            "IpaEuiccDataResponse",
            (
                "ipaEuiccData",
                {
                    "defaultSmdpAddress": "smdp.example.test",
                    "ipaCapabilities": {"ipaFeatures": (b"\xa0", 3), "ipaSupportedProtocols": (b"\x80", 2)},
                },
            ),
        )
        reading = decode_rsp_object(response)
        assert reading is not None and reading["schemaType"] == "IpaEuiccDataResponse"
        lines = _reading_lines(reading["notation"])
        assert 'defaultSmdpAddress = "smdp.example.test"' in lines
        # Inline named bits of IpaCapabilities (SGP.32 v1.3 §4.1): every named bit is
        # listed, the set ones marked.
        assert "ipaFeatures = '101'B (2 of 6 set)" in lines
        assert "[x] 0  directRspServerCommunication" in lines
        assert "[ ] 1  indirectRspServerCommunication" in lines
        assert "[x] 2  eimDownloadDataHandling" in lines
        assert "ipaSupportedProtocols = '10'B (1 of 5 set)" in lines
        assert "[x] 0  ipaRetrieveHttps" in lines

    def test_named_numbers_and_versions_are_read(self) -> None:
        profiles = decode_rsp_object(bytes.fromhex("BF2D14A012E3105A0A988802214365870921F39F700101"))
        assert profiles is not None
        lines = _reading_lines(profiles["notation"])
        assert "iccid = '988802214365870921F3'H (8988201234567890123)" in lines
        assert "profileState = 1 (enabled)" in lines
        # Every number the type names is listed, the one taken marked.
        assert lines[lines.index("profileState = 1 (enabled)") + 1:][:2] == ["( ) 0  disabled", "(*) 1  enabled"]
        ski = bytes.fromhex("11" * 20)
        info2 = _tlv(
            "BF22",
            _tlv("81", bytes.fromhex("020300")) + _tlv("82", bytes.fromhex("020500"))
            + _tlv("83", bytes.fromhex("010203")) + _tlv("84", bytes.fromhex("0103"))
            + _tlv("85", bytes.fromhex("0780")) + _tlv("88", bytes.fromhex("0490"))
            + _tlv("A9", _tlv("04", ski)) + _tlv("AA", _tlv("04", ski))
            + _tlv("04", bytes.fromhex("010000")) + _tlv("0C", b""),
        )
        reading = decode_rsp_object(info2)
        assert reading is not None and reading["schemaType"] == "EUICCInfo2"
        lines = _reading_lines(reading["notation"])
        # VersionType, SGP.22 v3.1 §2.4a.1.0: '02 03 00' is v2.3.0.
        assert "profileVersion = '020300'H (v2.3.0)" in lines
        # The v2 RspCapability names four bits; the bits past them take their
        # names from the type SGP.22 v3.1 section 4.3 calls EuiccRspCapability.
        later = gsma_schema.named_values("EuiccRspCapability")
        total = len(gsma_schema.named_values("RspCapability"))
        assert total == len(later) > 4
        heading = f"rspCapability = '1001'B (2 of {total} set)"
        assert heading in lines
        start = lines.index(heading) + 1
        assert lines[start:start + 6] == [
            "[x]  0  additionalProfile", "[ ]  1  crlSupport", "[ ]  2  rpmSupport", "[x]  3  testProfileSupport",
            "[ ]  4  deviceInfoExtensibilitySupport", "[ ]  5  serviceSpecificDataSupport",
        ]

    def test_a_tag_list_inside_an_euicc_package_names_profile_info_members(self) -> None:
        _require_sgp32()
        package = gsma_schema.rsp_specification().encode(
            "EuiccPackageRequest",
            {
                "euiccPackageSigned": {
                    "eimId": "eim.example.test",
                    "eidValue": bytes.fromhex("89049032123451234512345678901235"),
                    "counterValue": 7,
                    "eimTransactionId": bytes.fromhex("0102030405060708"),
                    "euiccPackage": ("psmoList", [("listProfileInfo", {"tagList": bytes.fromhex("5A9F70BF76")})]),
                },
                "eimSignature": b"\xaa" * 64,
            },
        )
        reading = decode_rsp_object(package)
        assert reading is not None and reading["schemaType"] == "EuiccPackageRequest"
        lines = _reading_lines(reading["notation"])
        assert "euiccPackage: psmoList" in lines
        # A list element is named by its index; the list line above carries the name.
        assert "[0]: listProfileInfo" in lines
        assert "tagList = '5A9F70BF76'H (3 ProfileInfo tags, SGP.22 v3.1 §5.7.15)" in lines
        assert "9F70  profileState" in lines
        assert "BF76  no ProfileInfo member" in lines

    def test_a_cut_short_tag_ends_the_list(self) -> None:
        reading = decode_rsp_object(bytes.fromhex("BF2D045C025A9F"))
        assert reading is not None
        entries = reading["schema"]["children"][0]["children"]
        assert [(entry["name"], entry["value"]) for entry in entries] == [("5A", "iccid"), ("9F", "tag cut short")]

    def test_a_json_member_name_selects_the_type(self) -> None:
        # ES9+ AuthenticateClient carries smdpSigned2 as base64 of SmdpSigned2.
        signed = bytes.fromhex("300D800801000000000007AC010100")
        assert decode_rsp_object(signed) is None
        reading = decode_rsp_object(signed, type_hint="smdpSigned2")
        assert reading is not None
        assert _reading_lines(reading["notation"]) == [
            "SmdpSigned2", "transactionId = '01000000000007AC'H", "ccRequiredFlag = FALSE",
        ]

    def test_content_no_type_reads_stays_generic(self) -> None:
        # A BF52 whose content fits neither type: the request lacks its tagList and the
        # response CHOICE has no alternative for '8A'.
        data = bytes.fromhex("BF52038A0100")
        assert decode_rsp_object(data) is None
        payload = decode_context_text(data.hex())["payload"]
        assert "schemaType" not in payload
        assert payload["nodes"]

    def test_the_plain_reading_is_the_schema_with_the_ber_tree_apart(self) -> None:
        _require_sgp32()
        decoded = decode_bytes(IPA_EUICC_DATA_REQUEST)
        notation = decoded["asn1Notation"]
        assert notation.startswith("IpaEuiccDataRequest  [SGP.32-v1.3]\n")
        assert "BF52" not in notation.splitlines()[0] and "-- BER-TLV" not in notation
        assert decoded["berNotation"].startswith("IPA_EUICC_DATA [BF52] ::= {")
        assert decoded["rspSchema"]["schemaType"] == "IpaEuiccDataRequest"
        stdout = StringIO()
        assert run_cli(["--ber", "--color", "never", IPA_EUICC_DATA_REQUEST.hex()], stdout=stdout, stderr=StringIO()) == 0
        assert "\n\n-- BER-TLV\nIPA_EUICC_DATA [BF52] ::= {" in stdout.getvalue()

    def test_colour_reaches_the_terminal_only(self) -> None:
        _require_sgp32()
        plain = decode_bytes(IPA_EUICC_DATA_REQUEST)["asn1Notation"]
        assert "\x1b[" not in plain
        stdout = StringIO()
        assert run_cli(["--color", "always", IPA_EUICC_DATA_REQUEST.hex()], stdout=stdout, stderr=StringIO()) == 0
        painted = stdout.getvalue()
        if "\x1b[" not in painted:
            pytest.skip("the active CLI theme paints nothing (mono)")
        assert re.sub(r"\x1b\[[0-9;]*m", "", painted).strip() == plain.strip()
        each = StringIO()
        original = sys.stdin
        try:
            sys.stdin = StringIO(IPA_EUICC_DATA_REQUEST.hex() + "\n")
            assert run_cli(["--each", "--color", "always"], stdout=each, stderr=StringIO()) == 0
        finally:
            sys.stdin = original
        assert "\x1b[" in json.loads(each.getvalue())["notation"]

    def test_each_line_is_decoded_on_its_own(self) -> None:
        # SGP.22 objects only, so the case runs without the SGP.32 asset as well.
        lines = "smdpSigned2\t300D800801000000000007AC010100\nBF2D035C015A\nx\tDEADBEEF\n"
        stdin, stdout = StringIO(lines), StringIO()
        original = sys.stdin
        try:
            sys.stdin = stdin
            code = run_cli(["--each"], stdout=stdout, stderr=StringIO())
        finally:
            sys.stdin = original
        assert code == 0
        entries = [json.loads(line) for line in stdout.getvalue().splitlines()]
        assert [(entry["label"], entry["kind"], entry.get("schemaType")) for entry in entries] == [
            ("smdpSigned2", "schema", "SmdpSigned2"),
            ("", "schema", "ProfileInfoListRequest"),
            # Four bytes are never read as a case 1 APDU here.
            ("x", "none", None),
        ]


@pytest.mark.skipif(not gsma_schema.rsp_specification_status()["available"], reason="pySim RSP schema not compiled")
class TestReadingLayout:
    def test_tac_and_imei_read_as_telephony_bcd(self) -> None:
        # SGP.22 v3.1 §4.2's example: IMEI 12345678901234, check digit 7, is
        # '21 43 65 87 09 21 43 F7'; its TAC '21 43 65 87'.
        info = _tlv("80", bytes.fromhex("21436587")) + _tlv("A1", b"") + _tlv("82", bytes.fromhex("21436587092143F7"))
        lines = _reading_lines(decode_rsp_object(_tlv("30", info), type_hint="deviceInfo")["notation"])
        assert "tac = '21436587'H (12345678)" in lines
        assert "imei = '21436587092143F7'H (123456789012347)" in lines

    def test_extended_card_resources_are_read(self) -> None:
        # ETSI TS 102 226 v19.0 §8.2.1.7.2: '81' installed applications, '82' free
        # non-volatile and '83' free volatile memory.
        resources = bytes.fromhex("810100" "82040002C360" "830224DF")
        ski = bytes.fromhex("11" * 20)
        info2 = _tlv(
            "BF22",
            _tlv("81", bytes.fromhex("020300")) + _tlv("82", bytes.fromhex("020500"))
            + _tlv("83", bytes.fromhex("010203")) + _tlv("84", resources)
            + _tlv("85", bytes.fromhex("00FFFFFF")) + _tlv("88", bytes.fromhex("0490"))
            + _tlv("A9", _tlv("04", ski)) + _tlv("AA", _tlv("04", ski))
            + _tlv("04", bytes.fromhex("010000")) + _tlv("0C", b""),
        )
        reading = decode_rsp_object(info2)
        lines = _reading_lines(reading["notation"])
        assert (
            "extCardResource = '81010082040002C360830224DF'H "
            "(0 installed applications, 181088 B free non-volatile memory, 9439 B free volatile memory)"
        ) in lines
        # Every named UICC capability is listed below the value, the 24 set ones marked.
        uicc = next(node for node in reading["schema"]["children"] if node["name"] == "uiccCapability")
        options = uicc["options"]
        assert sum(option["set"] for option in options) == 24
        raw = reading["notation"].splitlines()
        start = next(index for index, line in enumerate(raw) if line.strip().startswith("uiccCapability "))
        assert _reading_lines(raw[start])[0] == f"uiccCapability = '{'1' * 24}'B (24 of {len(options)} set)"
        column = raw[start].index("'")
        width = len(str(options[-1]["bit"]))
        expected = [f"{'[x]' if option['set'] else '[ ]'} {str(option['bit']).rjust(width)}  {option['name']}" for option in options]
        assert [line[column:] for line in raw[start + 1:start + 1 + len(options)]] == expected

    def test_sibling_values_share_one_column(self) -> None:
        reading = decode_rsp_object(bytes.fromhex("BF2D14A012E3105A0A988802214365870921F39F700101"))
        raw = reading["notation"].splitlines()
        iccid = next(line for line in raw if line.strip().startswith("iccid"))
        state = next(line for line in raw if line.strip().startswith("profileState"))
        assert iccid.index(" = ") == state.index(" = ")


@pytest.mark.skipif(not gsma_schema.rsp_specification_status()["available"], reason="pySim RSP schema not compiled")
class TestNamedValuesEverywhere:
    def test_an_inline_type_inside_an_anonymous_structure_keeps_its_names(self) -> None:
        _require_sgp32()
        # SGP.32 v1.3 ProfileDownloadTriggerResult (BF54): profileDownloadError is an
        # anonymous SEQUENCE whose profileDownloadErrorReason [0] INTEGER names
        # ecallActive(104) and undefinedError(127).
        data = bytes.fromhex("BF540F82080102030405060708" "3003800168")
        lines = _reading_lines(decode_rsp_object(data)["notation"])
        assert "profileDownloadTriggerResultData: profileDownloadError" in lines
        start = lines.index("profileDownloadErrorReason = 104 (ecallActive)") + 1
        assert lines[start:start + 2] == ["(*) 104  ecallActive", "( ) 127  undefinedError"]

    def test_every_named_field_of_every_type_finds_its_parse_tree_entry(self) -> None:
        # Walk each compiled RSP type with the parse tree beside it, as the reading
        # does, and count the INTEGER and BIT STRING fields the walk loses track of.
        from Tools.Asn1TlvDecode.context import _member_definition, _type_label, _type_members, _unwrap_type

        walked, named, lost = 0, 0, []

        def walk(compiled, definition, tree, module, path, depth):
            nonlocal walked, named
            shape = _unwrap_type(compiled)
            kind = type(shape).__name__
            pairs = []
            if kind in ("Sequence", "Set", "Choice"):
                entries = gsma_schema.members_of(definition)
                pairs = [(member, entries.get(name), f"{path}.{name}") for name, member in _type_members(shape).items()]
            elif kind in ("SequenceOf", "SetOf"):
                entry = definition.get("element") if isinstance(definition, dict) else None
                pairs = [(shape.element_type, entry, path + "[]")]
            for member, entry, child_path in pairs:
                child, child_module = _member_definition(tree, entry, member, module)
                if type(_unwrap_type(member)).__name__ in ("Integer", "BitString"):
                    walked += 1
                    if child is None:
                        lost.append(child_path)
                    elif gsma_schema.definition_values(child, _type_label(member)):
                        named += 1
                if depth < 14:
                    walk(member, child, tree, child_module, child_path, depth + 1)

        spec = gsma_schema.rsp_specification()
        tree = gsma_schema._CACHE["parsed"]
        for module in ("RSPDefinitions", "SGP32Definitions"):
            for type_name, compiled in (spec.modules.get(module) or {}).items():
                definition, found_module = gsma_schema.resolve_definition(tree, tree[module]["types"].get(type_name), module)
                walk(compiled.type, definition, tree, found_module, type_name, 0)
        # SGP.22 alone walks some 350 fields, with SGP.32 v1.3 well over a thousand.
        assert walked > 200 and named > 100
        assert lost == []
