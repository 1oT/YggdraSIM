# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Data fields the context decoder reads past their name.

The SMS TPDU of a CAT object with the secured packet in it, the PUT KEY data
field, the Key Information Template, the TERMINAL CAPABILITY template, the
SUCI of GET IDENTITY and an ES10 data field under secure messaging.
"""
from __future__ import annotations

import pytest

from Tools.Asn1TlvDecode import payload_readings as readings
from Tools.Asn1TlvDecode.context import decode_context_text, render_context_notation

COMMAND_PACKET = "0015" + "0D" + "0000" + "00" + "00" + "B00010" + "0000000001" + "00" + "A0A40000023F00"
DELIVER = "40" + "04812143" + "7F" + "F6" + "62114100000000" + "1A" + "027000" + COMMAND_PACKET


def _envelope(tpdu: str) -> str:
    body = "82028381" + "06038121F3" + f"8B{len(tpdu) // 2:02X}" + tpdu
    envelope = f"D1{len(body) // 2:02X}" + body
    return f"80C20000{len(envelope) // 2:02X}" + envelope


def _find(nodes: list[dict], name: str) -> dict | None:
    for node in nodes:
        if node.get("name") == name:
            return node
        hit = _find(node.get("children") or [], name)
        if hit is not None:
            return hit
    return None


# ----------------------------------------------------------------------
# SMS TPDU and the secured packet
# ----------------------------------------------------------------------


def test_tp_mti_table_is_the_clause_whole() -> None:
    """TS 23.040 V19 section 9.2.3.1: four values of the two bits, read by direction."""
    assert readings.TP_MTI_MOBILE_TERMINATED == {0: "SMS-DELIVER", 1: "SMS-SUBMIT-REPORT", 2: "SMS-STATUS-REPORT", 3: "Reserved"}
    assert readings.TP_MTI_MOBILE_ORIGINATED == {0: "SMS-DELIVER-REPORT", 1: "SMS-SUBMIT", 2: "SMS-COMMAND", 3: "Reserved"}
    assert readings.SECURED_SMS_ELEMENTS == {
        0x00: "Concatenated short messages, 8-bit reference number", 0x70: "Command Packet Identifier", 0x71: "Response Packet Identifier",
    }


def test_sms_pp_download_reads_the_tpdu_and_the_command_packet() -> None:
    pytest.importorskip("pySim.sms")
    out = decode_context_text(_envelope(DELIVER))
    nodes = out["exchanges"][0]["command"]["payload"]["nodes"]
    tpdu = _find(nodes, "SMS TPDU")
    assert tpdu is not None and tpdu["spec"] == "TS 23.040 v19 section 9.2.2"
    assert _find(nodes, "TP-MTI")["decoded"] == "SMS-DELIVER"
    assert _find(nodes, "Flags")["decoded"] == "TP-UDHI"
    assert _find(nodes, "TP-OA")["decoded"].startswith("1234 ")
    assert _find(nodes, "UDH 70")["decoded"] == "Command Packet Identifier"
    packet = _find(nodes, "Secured command packet")
    names = [child["name"] for child in packet["children"]]
    assert names[:4] == ["CPL", "CHL", "SPI", "SPI / integrity"] and names[-1] == "Secured data"
    assert _find(nodes, "TAR")["valueHex"] == "B00010"
    assert _find(nodes, "KID")["decoded"] == "00 (not used: the SPI asks for no RC, CC or DS)"
    notation = render_context_notation(out)
    assert "TAR = 'B00010'H" in notation and "Secured data = A0A40000023F00 (7 octets)" in notation


def test_send_short_message_and_the_envelope_answer_read_a_response_packet() -> None:
    pytest.importorskip("pySim.sms")
    response = "000C" + "0A" + "B00010" + "0000000001" + "00" + "00" + "029000"
    submit = "41" + "05" + "04812143" + "7F" + "F6" + f"{(3 + len(response) // 2):02X}" + "027100" + response
    proactive = "810301130082028183" + f"8B{len(submit) // 2:02X}" + submit
    fetch = f"D0{len(proactive) // 2:02X}" + proactive
    out = decode_context_text(f"> 80120000{len(fetch) // 2:02X}\n< {fetch} 9000")
    nodes = out["exchanges"][0]["response"]["payload"]["nodes"]
    assert _find(nodes, "TP-MTI")["decoded"] == "SMS-SUBMIT"
    assert _find(nodes, "TP-DA")["decoded"].startswith("1234 ")
    assert _find(nodes, "Status code")["decoded"] == "00 (PoR OK)"
    assert _find(nodes, "Additional response data")["valueHex"] == "029000"

    # The same packet as the user data an SMS-PP download answers with.
    answered = decode_context_text(f"> {_envelope(DELIVER)}\n< 027100{response} 9000")
    payload = answered["exchanges"][0]["response"]["payload"]
    assert payload["title"] == "ENVELOPE response: secured response packet"
    assert _find(payload["nodes"], "Status code")["decoded"] == "00 (PoR OK)"
    # An answer that names no response packet keeps the plain reading.
    plain = decode_context_text(f"> {_envelope(DELIVER)}\n< 0102 9000")
    assert plain["exchanges"][0]["response"]["payload"]["title"] == "ENVELOPE response data"


def test_tpdu_boundaries() -> None:
    pytest.importorskip("pySim.sms")
    full = bytes.fromhex(DELIVER)
    for raw in (b"", b"\x40", full[:4], full[:9]):
        assert readings.sms_tpdu_nodes(raw, mobile_terminated=True) is None or isinstance(readings.sms_tpdu_nodes(raw, mobile_terminated=True), list)
    # A type pySim's two classes do not read keeps its first octet named.
    status = readings.sms_tpdu_nodes(bytes.fromhex("0201020304"), mobile_terminated=True)
    assert [node["name"] for node in status] == ["TP-MTI", "TPDU"] and status[0]["decoded"] == "SMS-STATUS-REPORT"
    # A header that runs past the user data, and a packet cut short, are said instead of raised.
    assert readings.user_data_nodes(bytes.fromhex("05"), has_header=True)[0]["decoded"] == "the header length runs past the user data"
    cut = readings.user_data_nodes(bytes.fromhex("027000" + COMMAND_PACKET[:20]), has_header=True)
    assert cut[-1]["name"] == "Secured command packet" and "needs at least 16 octets" in cut[-1]["decoded"]
    assert readings.report_user_data_nodes(b"") is None and readings.report_user_data_nodes(bytes.fromhex("027000")) is None


# ----------------------------------------------------------------------
# GlobalPlatform keys
# ----------------------------------------------------------------------


def test_put_key_data_field_formats() -> None:
    """GPC v2.4 section 11.8.2.3: Format 1 with one-byte key types, Format 2 with 'FF xx' and two more fields."""
    basic = "30" + ("88" + "11" + "10" + "40" * 16 + "03" + "AABBCC") * 3
    fields = readings.put_key_fields(bytes.fromhex(basic))
    labels = [entry["label"] for entry in fields]
    assert labels[0] == "Key Version Number" and labels.count("Key 3 / Key Check Value") == 1
    assert fields[1]["value"] == "88" and fields[1]["meaning"].startswith("AES")
    assert fields[3]["value"] == "AABBCC" and len(fields) == 1 + 3 * 3

    extended = "31" + "FF88" + "11" + "10" + "41" * 16 + "03" + "DDEEFF" + "01" + "14" + "00"
    by_label = {entry["label"]: entry for entry in readings.put_key_fields(bytes.fromhex(extended))}
    assert by_label["Key 1 / Key Usage Qualifier"]["value"] == "14"
    assert by_label["Key 1 / Key Access Condition"]["value"] == "(none)"

    # The length 128 may come as '80' on one byte; a BER long form is read too.
    long_block = "30" + "A1" + "80" + "55" * 128 + "A0" + "8103" + "010001" + "00"
    assert len(readings.put_key_fields(bytes.fromhex(long_block))) == 6

    out = decode_context_text("80D80181" + f"{len(basic) // 2:02X}" + basic)
    payload = out["exchanges"][0]["command"]["payload"]
    assert payload["spec"] == "GPC v2.4 section 11.8.2.3" and payload["fields"][0]["label"] == "Key Version Number"
    for bad in ("", "30", "3088", "308811", "30881110", "30" + "88" + "11" + "10" + "40" * 16, "30" + "88" + "82" + "FFFF" + "00", "3000"):
        with pytest.raises(ValueError):
            readings.put_key_fields(bytes.fromhex(bad))
    # A data field that fits neither format is shown, not refused.
    broken = decode_context_text("80D8018102" + "3088")
    assert "not read as a key data field" in broken["exchanges"][0]["command"]["payload"]["fields"][1]["meaning"]


def test_key_information_template() -> None:
    """GPC v2.4 section 11.3.3.1: the basic and the extended Key Information Data structure."""
    assert readings.key_information_text(bytes.fromhex("01308810")) == (
        "key identifier 01, key version number 30: AES (16, 24 or 32-byte keys) ('88'), 16 byte(s)"
    )
    two = readings.key_information_text(bytes.fromhex("0170A180A003"))
    assert "256" not in two and two.count("byte(s)") == 2
    assert "256 byte(s) or more" in readings.key_information_text(bytes.fromhex("0170A100"))
    extended = readings.key_information_text(bytes.fromhex("0130FF880010" + "0114" + "00"))
    assert extended.endswith("key usage qualifier 14; key access condition not given")
    for bad in ("", "01", "013088", "01308810AA", "0130FF8800", "0130FF880010"):
        assert readings.key_information_text(bytes.fromhex(bad)) is None
    out = decode_context_text("> 80CA00E000\n< E012C00401308810C00402308810C00403308810 9000")
    nodes = out["exchanges"][0]["response"]["payload"]["nodes"]
    children = nodes[0]["children"]
    assert [child["name"] for child in children] == ["Key Information Data"] * 3
    assert children[1]["decoded"].startswith("key identifier 02, key version number 30")


# ----------------------------------------------------------------------
# TERMINAL CAPABILITY, GET IDENTITY, secure messaging
# ----------------------------------------------------------------------


def test_terminal_capability_tags_are_the_clause_whole() -> None:
    """TS 102 221 V18.4.0 section 11.1.19.2.0: five objects; '83' per SGP.22 v3.1 Table 7, '84' per SGP.32 v1.3 Table 6."""
    assert sorted(readings.TERMINAL_CAPABILITY_TAGS) == [0x80, 0x81, 0x82, 0x83, 0x84]
    assert len(readings.LPA_DEVICE_CAPABILITIES) == 8
    assert readings.LPA_DEVICE_CAPABILITIES[0].endswith("(LUId)") and readings.LPA_DEVICE_CAPABILITIES[7] == "LPR"
    template = "A910" + "8003013C0A" + "8100" + "820101" + "830107" + "840101"
    out = decode_context_text("80AA000012" + template)
    payload = out["exchanges"][0]["command"]["payload"]
    assert payload["title"] == "TERMINAL CAPABILITY"
    decoded = {child["tag"]: child["decoded"] for child in payload["nodes"][0]["children"]}
    assert decoded["80"] == "supply voltage class byte 01, 60 mA available, 1.0 MHz"
    assert decoded["81"] == "supported" and decoded["82"] == "UICC-CLF interface supported"
    assert decoded["83"].count(";") == 2 and "(LUId)" in decoded["83"] and "(LDSd)" in decoded["83"]
    assert decoded["84"] == "IPAd supported"
    # What the LPA and IPA shells send: IPAd alone, and its absence.
    assert _find(decode_context_text("80AA000005A903840101")["exchanges"][0]["command"]["payload"]["nodes"], readings.TERMINAL_CAPABILITY_TAGS[0x84])["decoded"] == "IPAd supported"
    assert _find(decode_context_text("80AA000005A903840100")["exchanges"][0]["command"]["payload"]["nodes"], readings.TERMINAL_CAPABILITY_TAGS[0x84])["decoded"] == "IPAd not supported"
    every = readings.terminal_capability_nodes(bytes.fromhex("A9038301FF"))
    assert every[0]["children"][0]["decoded"].count(";") == 7
    for bad in ("", "A9", "A903", "A90384", "8401", "A9038401", "A903840101FF"):
        assert readings.terminal_capability_nodes(bytes.fromhex(bad)) is None
    # A data field that is no 'A9' template keeps the plain tree.
    assert decode_context_text("80AA000003840101")["exchanges"][0]["command"]["payload"]["title"] == "Command data (BER-TLV)"


def test_get_identity_reads_the_suci() -> None:
    """TS 31.102 V19.5 section 7.5.2.1: four SUPI formats; the IMSI one is read field by field."""
    assert readings.SUCI_FORMATS == {
        0x01: "IMSI", 0x11: "Network Specific Identifier", 0x21: "Global Cable Identifier", 0x31: "Global Line Identifier",
    }
    suci = "A110" + "01" + "00F110" + "21F3" + "01" + "1B" + "0102030405060708"
    out = decode_context_text(f"> 0078000100\n< {suci} 9000")
    payload = out["exchanges"][0]["response"]["payload"]
    assert payload["title"] == "SUCI"
    fields = {entry["label"]: entry for entry in payload["fields"]}
    assert fields["SUPI format"]["meaning"] == "IMSI"
    assert fields["Home network identifier"]["meaning"] == "MCC 001, MNC 01"
    assert fields["Routing indicator"]["meaning"] == "123"
    assert fields["Protection scheme identifier"]["meaning"] == "Profile <A>"
    assert fields["Home network public key identifier"]["value"] == "1B" and fields["Scheme output"]["meaning"] == "8 byte(s)"
    nai = readings.suci_fields(bytes.fromhex("A1" + "0C" + "11" + b"type1.rid0@".hex()))
    assert nai[0]["meaning"] == "Network Specific Identifier" and nai[1]["meaning"] == "type1.rid0@"
    assert readings.suci_fields(bytes.fromhex("A1020100"))[1]["label"] == "SUCI value"
    assert readings.suci_fields(bytes.fromhex("A10199"))[0]["meaning"] == "not a format of this clause"
    for bad in ("", "A1", "A100", "A20101", "A1020100FF"):
        assert readings.suci_fields(bytes.fromhex(bad)) is None
    # A response that is no SUCI object keeps the plain tree.
    other = decode_context_text("> 0078000100\n< 8001FF 9000")
    assert other["exchanges"][0]["response"]["payload"]["title"] == "Response data (BER-TLV)"


def test_es10_data_under_secure_messaging_is_not_read_as_clear() -> None:
    """GPC Amd D v1.1.2 section 6.2.4: a C-MAC of 8 bytes follows the data field."""
    mac_only = decode_context_text("84E291000B" + "BF2D00" + "0102030405060708")
    payload = mac_only["exchanges"][0]["command"]["payload"]
    assert payload["schemaType"] == "ProfileInfoListRequest"
    assert payload["notes"][-1].endswith("not checked here: 0102030405060708.")
    hidden = decode_context_text("84E2910018" + "5A" * 16 + "0102030405060708")
    payload = hidden["exchanges"][0]["command"]["payload"]
    assert payload["title"] == "Protected command data" and "is not read as an ES10 object" in payload["notes"][0]
    # Without the secure-messaging bits nothing changes.
    clear = decode_context_text("80E2910003BF2D00")
    assert clear["exchanges"][0]["command"]["payload"]["schemaType"] == "ProfileInfoListRequest"
    assert "notes" not in clear["exchanges"][0]["command"]["payload"]


# ----------------------------------------------------------------------
# SCP11 (GlobalPlatform Amendment F)
# ----------------------------------------------------------------------


def test_parts_without_octets_carry_no_length() -> None:
    """A bit field of the SPI and a derived row are named parts; only whole octets show a length."""
    envelope = "80C2000036D1348202838106038121F38B2940048121437FF6621141000000001A02700000150D00000000B00010000000000100A0A40000023F00"
    tpdu = decode_context_text(envelope)["exchanges"][0]["command"]["payload"]["nodes"][0]["children"][2]
    parts = {node["name"]: node for node in tpdu["children"]}
    assert "length" not in parts["Flags"] and "valueHex" not in parts["Flags"]
    packet = {node["name"]: node for node in parts["Secured command packet"]["children"]}
    assert packet["SPI"]["length"] == 2 and packet["TAR"]["valueHex"] == "B00010"
    for name in ("SPI / integrity", "SPI / ciphering", "SPI / counter", "SPI / PoR", "SPI / PoR transport"):
        assert "length" not in packet[name], name


def _tlv(tag: str, body: str) -> str:
    return tag + f"{len(body) // 2:02X}" + body


def test_scp11_tables_are_the_amendment_whole() -> None:
    """GPC Amd F v1.2 Tables 6-2, 6-12, 6-14 and 6-17."""
    assert readings.SCP11_VARIANTS == {0: "SCP11b", 1: "SCP11a", 2: "RFU", 3: "SCP11c"}
    assert sorted(readings.SCP11_KEY_AGREEMENT_TAGS) == ["80", "81", "84", "90", "95"]
    assert sorted(readings.SCP11_KEY_USAGE_QUALIFIERS) == [0x1C, 0x34, 0x3C, 0x74]
    assert sorted(readings.SCP11_CERTIFICATE_TAGS) == ["42", "53", "5F20", "5F24", "5F25", "5F37", "73", "7F49", "93", "95", "BF20"]
    assert readings.SCP11_PUBLIC_KEY_TAGS == {"B0": "Public key - Q", "F0": "Key Parameter Reference"}
    assert readings.SCP11_CERTIFICATE_KEY_USAGE == {"82": "Digital signature verification", "0080": "Key agreement"}
    # Tables 6-20 and 6-24: an ephemeral card key under SCP11a and SCP11b, the static one under SCP11c.
    assert {kind: reading[1] for kind, reading in readings.SCP11_RESPONSES.items()} == {
        "scp11_internal_authenticate_response": "ePK.SD.ECKA",
        "scp11a_mutual_authenticate_response": "ePK.SD.ECKA",
        "scp11c_mutual_authenticate_response": "PK.SD.ECKA",
        "scp11_mutual_authenticate_response": "ePK.SD.ECKA (SCP11a) or PK.SD.ECKA (SCP11c)",
    }


def test_scp11_key_agreement_commands() -> None:
    crt = _tlv("A6", "90021101" + "95013C" + "800188" + "810110")
    key = _tlv("5F49", "04" + "11" * 64)
    answer = _tlv("5F49", "04" + "22" * 64) + _tlv("86", "33" * 16)
    mutual = decode_context_text(f"> 80821301{(len(crt) + len(key)) // 2:02X}{crt}{key}\n< {answer} 9000")
    exchange = mutual["exchanges"][0]
    # The INS of EXTERNAL AUTHENTICATE, told apart by P2 and the template.
    assert exchange["command"]["name"] == "MUTUAL AUTHENTICATE" and exchange["command"]["spec"] == "GPC Amd F v1.2 section 6.5"
    template = exchange["command"]["payload"]["nodes"][0]
    decoded = {child["tag"]: child["decoded"] for child in template["children"]}
    assert decoded["90"] == "SCP '11', SCP11a, no Host and Card ID in the key derivation"
    assert decoded["95"] == "secure messaging with C-MAC, R-MAC, and ENCRYPTION"
    assert decoded["80"].startswith("AES") and decoded["81"] == "16 byte(s)"
    assert exchange["command"]["payload"]["nodes"][1]["name"] == "ePK.OCE.ECKA"
    assert [node["name"] for node in exchange["response"]["payload"]["nodes"]] == ["ePK.SD.ECKA", "Receipt"]
    assert exchange["response"]["payload"]["spec"] == "GPC Amd F v1.2 Table 6-20"
    # Under SCP11c the answer holds the card's static key; a template that names no variant leaves both readings.
    static = _tlv("A6", "90021103" + "95013C" + "800188" + "810110")
    scp11c = decode_context_text(f"> 80821301{(len(static) + len(key)) // 2:02X}{static}{key}\n< {answer} 9000")
    assert [node["name"] for node in scp11c["exchanges"][0]["response"]["payload"]["nodes"]] == ["PK.SD.ECKA", "Receipt"]
    bare = _tlv("A6", "95013C")
    unnamed = decode_context_text(f"> 80821301{(len(bare) + len(key)) // 2:02X}{bare}{key}\n< {answer} 9000")
    assert unnamed["exchanges"][0]["response"]["payload"]["nodes"][0]["name"] == "ePK.SD.ECKA (SCP11a) or PK.SD.ECKA (SCP11c)"
    assert readings.scp11_variant(bytes.fromhex(static)) == "SCP11c" and readings.scp11_variant(b"") is None
    assert readings.scp11_variant(bytes.fromhex("A605")) is None and readings.scp11_variant(bytes.fromhex(bare)) is None
    # SCP03 keeps reading as before: P2 '00', no template.
    external = decode_context_text("8482330010" + "A1" * 16)
    assert external["exchanges"][0]["command"]["name"] == "EXTERNAL AUTHENTICATE"

    internal = decode_context_text(f"> 80881301{(len(crt) + len(key)) // 2:02X}{crt}{key}\n< {answer} 9000")
    assert internal["exchanges"][0]["command"]["name"] == "INTERNAL AUTHENTICATE"
    assert internal["exchanges"][0]["context"]["domain"] == "gp"
    assert internal["exchanges"][0]["response"]["payload"]["spec"] == "GPC Amd F v1.2 Table 6-24"
    header = {entry["label"]: entry["meaning"] for entry in internal["exchanges"][0]["command"]["header"] if entry["label"] in ("P1", "P2")}
    assert header == {"P1": "Key Version Number 13 of SK.SD.ECKA", "P2": "Key Identifier 01 of SK.SD.ECKA"}
    reserved = decode_context_text(f"80889381{(len(crt) + len(key)) // 2:02X}{crt}{key}")
    header = {entry["label"]: entry["meaning"] for entry in reserved["exchanges"][0]["command"]["header"] if entry["label"] in ("P1", "P2")}
    assert header["P1"] == "Key Version Number 13 of SK.SD.ECKA; bit 8 is RFU and is set" and header["P2"].endswith("bit 8 is RFU and is set")
    variants = {0x00: "SCP11b", 0x01: "SCP11a", 0x03: "SCP11c", 0x02: "RFU", 0x05: "SCP11a"}
    for parameters, name in variants.items():
        nodes = readings.scp11_key_agreement_nodes(bytes.fromhex(_tlv("A6", f"900211{parameters:02X}")))
        assert name in nodes[0]["children"][0]["decoded"]
    with_ids = readings.scp11_key_agreement_nodes(bytes.fromhex(_tlv("A6", "90021105" + "8402AABB")))
    assert "Host and Card ID in the key derivation" in with_ids[0]["children"][0]["decoded"]
    assert with_ids[0]["children"][1]["name"] == "HostID"
    for bad in ("", "A6", "A605", "A6039002", "A60390021101FF"):
        assert readings.scp11_key_agreement_nodes(bytes.fromhex(bad)) is None
    # 3GPP AUTHENTICATE keeps its own reading under the ISO class.
    assert decode_context_text("0088008100")["exchanges"][0]["context"]["domain"] == "auth"


def test_scp11_perform_security_operation_reads_the_certificate() -> None:
    public_key = _tlv("7F49", _tlv("B0", "04" + "AA" * 4) + _tlv("F0", "00"))
    body = (
        _tlv("93", "AB01") + _tlv("42", "112233") + _tlv("5F20", "445566") + _tlv("95", "0080")
        + _tlv("5F25", "20260101") + _tlv("5F24", "20301231") + public_key + _tlv("5F37", "AA" * 8)
    )
    certificate = _tlv("7F21", body)
    out = decode_context_text(f"802A1810{len(certificate) // 2:02X}{certificate}")
    exchange = out["exchanges"][0]
    assert exchange["command"]["name"] == "PERFORM SECURITY OPERATION"
    header = {entry["label"]: entry["meaning"] for entry in exchange["command"]["header"] if entry["label"] in ("P1", "P2")}
    assert header["P1"] == "Key Version Number 18 of PK.CA-KLOC.ECDSA; last command of this certificate"
    assert header["P2"] == "Key Identifier 10 of PK.CA-KLOC.ECDSA; last certificate"
    children = exchange["command"]["payload"]["nodes"][0]["children"]
    named = {child["name"]: child for child in children}
    assert named["Key Usage"]["decoded"] == "Key agreement"
    assert named["Effective Date"]["decoded"] == "2026-01-01" and named["Expiration Date"]["decoded"] == "2030-12-31"
    assert [part["name"] for part in named["Public Key"]["children"]] == ["Public key - Q", "Key Parameter Reference"]
    # Chaining: more commands for this certificate, more certificates after it.
    chained = decode_context_text("802A9890" + "04" + certificate[:8])
    header = {entry["label"]: entry["meaning"] for entry in chained["exchanges"][0]["command"]["header"] if entry["label"] in ("P1", "P2")}
    assert header["P1"].endswith("more command(s) follow for this certificate") and header["P2"].endswith("more certificate(s) follow")
    assert "not whole TLVs" in chained["exchanges"][0]["command"]["payload"]["fields"][0]["meaning"]
    for bad in ("", "7F21", "7F2105", "7F210393"):
        assert readings.scp11_certificate_nodes(bytes.fromhex(bad)) is None
