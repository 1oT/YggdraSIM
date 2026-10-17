# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Context-aware APDU / TLV decoding (``Tools.Asn1TlvDecode.context``).

Every vector is built from the standards' own test bodies (the 3GPP USIM
AID prefix, the GSMA ISD-R AID, the DISPLAY TEXT example of ETSI TS 102 223
v18.3 Annex B) and the project's 8988 test IIN.
"""

from __future__ import annotations

import pytest

from Tools.Asn1TlvDecode import gsma_schema
from Tools.Asn1TlvDecode.context import (
    classify_command,
    decode_context_text,
    decode_fcp,
    decode_gp_registry,
    parse_exchanges,
)
from Tools.Asn1TlvDecode.main import DecodeError


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
