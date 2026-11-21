# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(relpath: str) -> str:
    return (ROOT / relpath).read_text(encoding="utf-8")


def test_decoder_panel_heads_a_payload_with_the_euicc_response_outcome() -> None:
    """The Decoder draws what an EUICCResponse reports over the tree; the SIMa action's own renderer is gone."""
    decoder_css = _read("gui_frontend/src/css/views/offline-decoder.css")
    assert ".cc-decoder-outcome {" in decoder_css and ".cc-decoder-chip--fail {" in decoder_css
    for relpath in ("gui_frontend/src/js/command-center.js", "yggdrasim_common/gui_server/static/app.js"):
        text = _read(relpath)
        assert "renderSimaResponseResult" not in text and 'kind === "sima_response"' not in text
        block = text[text.index("function _decoderPayloadBlock(payload, roleLabel)"):]
        block = block[:block.index("\n  function ", 10)]
        # Over the fields and the schema tree, not under them.
        assert block.index("_decoderResultLine(payload.result)") < block.index("_decoderFieldTable(payload.fields)")
        line = text[text.index("function _decoderResultLine(result)"):]
        line = line[:line.index("\n  function ", 10)]
        assert '"all PEs ok" : "profile installation failed"' in line and 'result.ok ? "ok" : "fail"' in line
        assert "innerHTML" not in line
    assert ".cc-sima-" not in _read("yggdrasim_common/gui_server/static/app.css")


# A ProfileInstallationResult with an errorResult (SGP.22 v3.1 section 2.5.6):
# bppCommandId 5, errorReason 12, and an EUICCResponse reporting the ISO 7816
# status word '9484' for the PE with identification 14 at offset 257. The
# notification address, ICCID and signature are synthetic.
_PIR_EUICC_RESPONSE = "3012A00E300C800300948481010E830201018100"
_PIR_ERROR_RESULT = "A11C80010581010C8214" + _PIR_EUICC_RESPONSE
_PIR_METADATA = (
    "BF2F258002017B81020780" + "0C0F" + b"smdpp.example.t".hex().upper() + "5A0A" + "98882143658709213243"
)
_PIR_DATA_BODY = "8008010000000000085D" + _PIR_METADATA + "060388370A" + "A21E" + _PIR_ERROR_RESULT
_PIR = (
    "BF3781" + f"{(len(_PIR_DATA_BODY) // 2 + 3 + 67):02X}"
    + "BF27" + f"{len(_PIR_DATA_BODY) // 2:02X}" + _PIR_DATA_BODY
    + "5F3740" + "AB" * 64
)


def test_sima_decoder_finds_the_response_inside_a_profile_installation_result() -> None:
    from SCP11.shared.sima_response import decode_sima_response, locate_sima_response

    data = bytes.fromhex(_PIR)
    located = locate_sima_response(data)
    assert located is not None
    assert located["result"] == "errorResult"
    assert (located["bpp_command_id"], located["error_reason"]) == (5, 12)
    assert located["sima_response"].hex().upper() == _PIR_EUICC_RESPONSE
    assert located["seq_number"] == 379 and located["notification_address"] == "smdpp.example.t"

    decoded = decode_sima_response(data)
    assert decoded["input_hex"] == _PIR_EUICC_RESPONSE and decoded["complete"] is True
    assert decoded["container"]["given_length"] == len(data)
    semantic = decoded["semantic"]
    assert semantic["ok"] is False and semantic["profile_installation_aborted"] is True
    assert semantic["pe_status"] == [{
        "status": 0x9484, "status_name": "status-word-9484", "identification": 14,
        "additional_information": None, "offset": 257,
    }]
    assert semantic["failure_cause"] == (
        "PE with identification 14: ISO 7816 status word '9484', at offset 257 of the PE; "
        "the profile installation was aborted"
    )

    # A bare EUICCResponse still decodes as before, without a container.
    bare = decode_sima_response(bytes.fromhex(_PIR_EUICC_RESPONSE))
    assert "container" not in bare and bare["semantic"]["failure_cause"] == semantic["failure_cause"]
    assert decode_sima_response(bytes.fromhex("3007A00530038001 00".replace(" ", "")))["semantic"]["failure_cause"] == ""


def test_sima_decoder_success_result_and_wrapped_result() -> None:
    from SCP11.shared.sima_response import locate_sima_response

    ok = "3007A0053003800100"
    success = "A2" + "14" + "A012" + "4F05A000000559" + "0409" + ok
    body = "8001AA" + success
    data = "BF27" + f"{len(body) // 2:02X}" + body
    for wrapped in (data, "A0" + f"{len(data) // 2:02X}" + data):
        located = locate_sima_response(bytes.fromhex(wrapped))
        assert located is not None and located["result"] == "successResult"
        assert located["aid_hex"] == "A000000559" and located["sima_response"].hex().upper() == ok


def test_sima_decoder_boundaries_on_a_result_container() -> None:
    from SCP11.shared.sima_response import decode_sima_response, locate_sima_response

    for raw in (b"", b"\xBF", bytes.fromhex("BF3705BF27"), bytes.fromhex("BF2A00"), bytes.fromhex("5F3700")):
        assert locate_sima_response(raw) is None or locate_sima_response(raw)["sima_response"] == b""
        decode_sima_response(raw)
    empty = decode_sima_response(bytes.fromhex("BF3703BF2700"))
    assert empty["container"]["result"] == "" and "carries no EUICCResponse" in empty["error"]


def test_context_decoder_names_the_result_codes_and_nests_the_response() -> None:
    from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

    registry = ensure_builtin_actions_loaded()
    context = registry.get("tool.decoder.context").dispatcher(None, input_text=_PIR, context="auto")

    def find(node, name):
        if isinstance(node, dict):
            if node.get("name") == name:
                return node
            for value in node.values():
                hit = find(value, name)
                if hit is not None:
                    return hit
        elif isinstance(node, list):
            for item in node:
                hit = find(item, name)
                if hit is not None:
                    return hit
        return None

    sima = find(context, "simaResponse")
    assert sima is not None and sima["valueHex"] == _PIR_EUICC_RESPONSE
    assert "ISO 7816 status word '9484'" in sima["decoded"]
    status = find(sima["children"], "status")
    assert status["number"] == 0x9484 and status["decoded"] == "status-word-9484"
    assert find(sima["children"], "identification")["value"] == 14
    assert find(sima["children"], "offset")["value"] == 257
    assert find(sima["children"], "profileInstallationAborted") is not None
    # What the SIMa action showed beside the response is in the same tree, by name.
    assert find(context, "bppCommandId")["decoded"] == "loadProfileElements"
    assert find(context, "errorReason")["decoded"] == "installFailedDueToPEProcessingError"
    assert find(context, "iccid")["decoded"] == "89881234567890122334"
    # And the outcome heads the payload.
    assert context["payload"]["result"] == {"ok": False, "text": sima["decoded"]}


def test_context_decoder_reads_a_bare_euicc_response_and_leaves_other_sequences_alone() -> None:
    from Tools.Asn1TlvDecode.context import decode_context_text, render_context_notation

    bare = decode_context_text(_PIR_EUICC_RESPONSE)
    payload = bare["payload"]
    assert bare["context"]["domain"] == "es10" and payload["title"] == "EUICCResponse"
    assert payload["result"]["ok"] is False and "status word '9484'" in payload["result"]["text"]
    assert payload["schema"]["children"][0]["name"] == "peStatus"
    assert any("by its structure" in note for note in payload["notes"])
    notation = render_context_notation(bare)
    assert "result: failed  -- PE with identification 14" in notation
    # With its status word, and under the ES10 context too; the raw context keeps the plain tree.
    assert decode_context_text(_PIR_EUICC_RESPONSE + "9000")["payload"]["title"] == "EUICCResponse"
    assert decode_context_text(_PIR_EUICC_RESPONSE, hint="es10")["payload"]["title"] == "EUICCResponse"
    assert decode_context_text(_PIR_EUICC_RESPONSE, hint="tlv")["payload"]["title"] == "BER-TLV object"
    ok = decode_context_text("3007A0053003800100")["payload"]
    assert ok["result"] == {"ok": True, "text": "all PEs ok"}
    assert "result: ok  -- all PEs ok" in render_context_notation(decode_context_text("3007A0053003800100"))
    # An X.509 name and a SEQUENCE that only starts like a response stay generic.
    for other in ("301F310B3009060355040613025858311030" + "0E060355040A0C074578616D706C65", "3007A0053003810100"):
        assert decode_context_text(other)["payload"]["title"] == "BER-TLV object"


def test_context_decoder_finds_the_response_where_the_schema_gives_no_reading() -> None:
    """Result data the schema refuses, or one inside an unnamed wrapper, is read by its tags like the retired action read it."""
    from SCP11.shared.sima_response import decode_sima_response
    from Tools.Asn1TlvDecode.context import decode_context_text, render_context_notation

    def tlv(tag: str, body: str) -> str:
        return tag + f"{len(body) // 2:02X}" + body

    success = tlv("A2", tlv("A0", "4F05A000000559" + "0409" + "3007A0053003800100"))
    failure = tlv("A2", tlv("A1", "800105" + "81010C" + tlv("82", _PIR_EUICC_RESPONSE)))
    for final, ok in ((success, True), (failure, False)):
        # A ProfileInstallationResultData without its mandatory members, alone and wrapped.
        data = tlv("BF27", "8001AA" + final)
        notifications = tlv("BF2B", tlv("A0", tlv("BF37", data + "5F3740" + "AB" * 64)))
        for wrapped in (data, tlv("A0", data), notifications):
            payload = decode_context_text(wrapped)["payload"]
            semantic = decode_sima_response(bytes.fromhex(wrapped))["semantic"]
            assert payload["result"]["ok"] is ok is semantic["ok"], wrapped
            assert payload["result"]["text"] == (semantic["failure_cause"] or "all PEs ok")
            assert "schemaType" not in payload
            labels = [entry["label"] for entry in payload["fields"]]
            assert labels[0] == "EUICCResponse" and "found by its tags" in payload["fields"][0]["meaning"]
            if not ok:
                named = {entry["label"]: entry["meaning"] for entry in payload["fields"]}
                assert named["bppCommandId"] == "loadProfileElements"
                assert named["errorReason"] == "installFailedDueToPEProcessingError"
        # The raw context reads no meaning into the tree.
        assert "result" not in decode_context_text(tlv("A0", data), hint="tlv")["payload"]
    notation = render_context_notation(decode_context_text(tlv("A0", tlv("BF27", "8001AA" + failure))))
    assert "result: failed  -- PE with identification 14" in notation
    assert "bppCommandId: 5  -- loadProfileElements" in notation


def test_context_decoder_reads_an_euicc_info2_the_schema_refuses_by_its_tags() -> None:
    """ipaMode and an empty iotSpecificInfo alone: no schema reading, the members by tag and the check instead."""
    from Tools.Asn1TlvDecode.context import decode_context_text

    payload = decode_context_text("BF2205900101B400")["payload"]
    assert payload["title"] == "EUICCInfo2" and "schemaType" not in payload
    fields = {entry["label"]: entry["value"] for entry in payload["fields"]}
    assert fields["LPA/IPA Mode"] == "IPAe active (1)"
    assert fields["IoT Specific Info / eCall Supported"] == "false"
    notes = payload["notes"]
    assert notes[0].startswith("Schema decode failed: EUICCInfo2")
    assert any(note.startswith("SGP.32 check WARN: Missing mandatory fields: Profile Version") for note in notes)
    assert "SGP.32 check WARN: IoT Specific Info is present, but IoT Version List is missing." in notes
    # The memberless request type no longer stands in for it; an empty request is still a request.
    assert decode_context_text("BF2200")["payload"]["schemaType"] == "GetEuiccInfo2Request"


def test_is_euicc_response_takes_only_the_whole_type() -> None:
    """TCA eUICC Profile Package V3.4.1 section 8.11: peStatus, then at most the abort flag and the message."""
    from SCP11.shared.sima_response import is_euicc_response

    accepted = (
        "3007A0053003800100",
        _PIR_EUICC_RESPONSE,
        "300DA00530038001018100" + "8202" + "4F4B",
        "300BA0053003800101" + "8202" + "4F4B",
        "300EA00C300A80010381010E83020101",
    )
    for raw in accepted:
        assert is_euicc_response(bytes.fromhex(raw)), raw
    refused = {
        "empty": "",
        "one byte": "30",
        "cut header": "3012A0",
        "over-claiming length": "30FFA00E300C8003009484",
        "truncated": _PIR_EUICC_RESPONSE[:-6],
        "trailing byte": _PIR_EUICC_RESPONSE + "00",
        "empty list": "3002A000",
        "no status": "3007A0053003810100",
        "empty status": "3006A00430028000",
        "abort flag with a value": "300AA00530038001008101FF",
        "message before the flag": "300DA0053003800101" + "82024F4B" + "8100",
        "status twice": "300AA0083006800100800100",
        "field out of order": "300AA0083006810100800100",
        "foreign field": "300AA0083006800100840100",
        "not a sequence": "A0053003800100",
        "x509 name": "301F310B3009060355040613025858311030" + "0E060355040A0C074578616D706C65",
    }
    for label, raw in refused.items():
        assert not is_euicc_response(bytes.fromhex(raw)), label
    assert not is_euicc_response(None)  # type: ignore[arg-type]


def _tlv(tag: str, value: bytes) -> bytes:
    from osmocom.tlv import bertlv_encode_len

    return bytes.fromhex(tag) + bertlv_encode_len(len(value)) + value


def _euicc_info2(*iot_members: bytes) -> str:
    """An EUICCInfo2 with synthetic values; ``iot_members`` are the SGP.32 members after the SGP.22 ones."""
    ski = _tlv("04", bytes.fromhex("81370F5125D0B1D408D4C3B232E6D25E795BEBFB"))
    members = (
        _tlv("81", bytes.fromhex("020301")) + _tlv("82", bytes.fromhex("020600")) + _tlv("83", bytes.fromhex("260116"))
        + _tlv("84", bytes.fromhex("81010882040002EC08830224DF")) + _tlv("85", bytes.fromhex("007FB6F3C1"))
        + _tlv("86", bytes.fromhex("110200")) + _tlv("87", bytes.fromhex("020300")) + _tlv("88", bytes.fromhex("029C"))
        + _tlv("A9", ski) + _tlv("AA", ski) + _tlv("99", bytes.fromhex("0640")) + _tlv("04", bytes.fromhex("FFFFFF"))
        + _tlv("0C", b"KN-DN-UP-0327") + _tlv("AF", _tlv("04", bytes.fromhex("030301")))
    )
    return _tlv("BF22", members + b"".join(iot_members)).hex().upper()


def test_context_decoder_carries_the_sgp32_check_of_an_euicc_info2() -> None:
    """An IoT eUICC's EUICCInfo2 gets the check as notes; a consumer one gets none."""
    from SCP03.logic.euicc_info2 import build_euicc_info2_validation_lines
    from Tools.Asn1TlvDecode.context import decode_context_text, render_context_notation

    ipa_mode = _tlv("90", b"\x01")
    versions = _tlv("A0", _tlv("04", bytes.fromhex("010200")))
    passed = ["SGP.32 check PASS: All required SGP.32 v1.2 fields are present."]

    full = _euicc_info2(ipa_mode, _tlv("B4", versions + _tlv("81", b"") + _tlv("82", b"")))
    payload = decode_context_text(full)["payload"]
    assert payload["schemaType"] == "EUICCInfo2" and payload["notes"] == passed
    notation = render_context_notation(decode_context_text(full))
    assert "note: SGP.32 check PASS" in notation
    # Every set rspCapability bit has its name, the two past the v2 list included.
    assert "deviceInfoExtensibilitySupport" in notation and "serviceSpecificDataSupport" in notation
    assert "[x]  4  bit 4" not in notation

    # ecallSupported and fallbackSupported are OPTIONAL NULLs (SGP.32 v1.3 section 5.9.2):
    # an eUICC with neither still passes.
    plain = _euicc_info2(ipa_mode, _tlv("B4", versions))
    assert (0, "SGP.32 Validation", "PASS") in build_euicc_info2_validation_lines(bytes.fromhex(plain))
    assert decode_context_text(plain)["payload"]["notes"] == passed

    # iotVersion carries at least one version: an empty list is the finding.
    bare = decode_context_text(_euicc_info2(ipa_mode, _tlv("B4", _tlv("A0", b""))))["payload"]
    assert bare["schemaType"] == "EUICCInfo2"
    assert bare["notes"] == ["SGP.32 check WARN: IoT Version List is empty; SGP.32 asks for at least one version."]

    # Neither ipaMode nor iotSpecificInfo: a consumer eUICC, and no check line.
    consumer = decode_context_text(_euicc_info2())["payload"]
    assert consumer["schemaType"] == "EUICCInfo2" and "notes" not in consumer
