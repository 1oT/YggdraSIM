# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Input forms of the context decoder other than plain hex.

AT command lines, PEM, a JSON body, base64, identifiers in digits, an ATR, a
PC/SC return code and the EF content context. The rule under test beside the
readings themselves: a form takes an input only where the hex path refuses it
or names no domain, so nothing that decoded before reads differently.
"""
from __future__ import annotations

import base64
import datetime
import json
from pathlib import Path

import pytest

from Tools.Asn1TlvDecode import input_forms
from Tools.Asn1TlvDecode.context import DecodeError, decode_context_text, render_context_notation

# The simulator's own default ATR (SIMCARD.state.DEFAULT_SIM_ATR).
ATR = "3B9F96801FC78031A073BE21136743200718000001A5"
PROFILES = "BF2D14A012E3105A0A988802214365870921F39F700101"
IMSI_FILE = "080910100000000010"


def _fields(result: dict) -> dict[str, str]:
    return {str(entry["label"]): str(entry["value"]) for entry in result["payload"].get("fields", [])}


def _certificate() -> tuple[bytes, str, str]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.NameOID.COUNTRY_NAME, "XX"), x509.NameAttribute(x509.NameOID.COMMON_NAME, "eim.example.test")])
    start = datetime.datetime(2026, 1, 1)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
        .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=3650)).sign(key, hashes.SHA256())
    )
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
    ).decode()
    return (
        certificate.public_bytes(serialization.Encoding.DER),
        certificate.public_bytes(serialization.Encoding.PEM).decode(),
        private,
    )


# ----------------------------------------------------------------------
# AT command lines
# ----------------------------------------------------------------------


def test_restricted_command_table_is_the_clause_whole() -> None:
    """TS 27.007 V19.6 section 8.18: eight command codes, every other value reserved."""
    assert input_forms.RESTRICTED_SIM_COMMANDS == {
        176: "READ BINARY", 178: "READ RECORD", 192: "GET RESPONSE", 214: "UPDATE BINARY",
        220: "UPDATE RECORD", 242: "STATUS", 203: "RETRIEVE DATA", 219: "SET DATA",
    }
    for code, name in input_forms.RESTRICTED_SIM_COMMANDS.items():
        rewritten = input_forms.rewrite_at_lines(f"AT+CRSM={code},28423,0,0,9")
        assert rewritten is not None, name
        assert rewritten[0].splitlines() == ["@file 6F07", f"> 00{code:02X}000009"]
    assert input_forms.rewrite_at_lines("AT+CRSM=200,28423,0,0,9") is None


def test_generic_access_lines_become_exchanges() -> None:
    out = decode_context_text('AT+CSIM=14,"00A40004023F00"\n+CSIM: 4,"9000"\nOK')
    exchange = out["exchanges"][0]
    assert exchange["command"]["name"] == "SELECT FILE" and exchange["response"]["sw"]["sw"] == "9000"
    # +CGLA carries a session first; the echo without the AT prefix reads the same.
    rewritten = input_forms.rewrite_at_lines('+CGLA=1,14,"01A40004023F00"\n+CGLA: 4,"9000"')
    assert rewritten is not None and rewritten[0].splitlines() == ["> 01A40004023F00", "< 9000"]
    # A length that does not match the characters is said, not hidden.
    noted = decode_context_text('AT+CSIM=20,"00A40004023F00"\n+CSIM: 4,"9000"')
    assert noted["context"]["notes"] == ["+CSIM: <length> says 20 characters, the command has 14"]
    # The test command and a line that is no SIM access stay as they were: refused.
    for line in ("AT+CSIM=?", "AT+CFUN=1", 'AT+CSIM=14,"00A4000402ZZ00"'):
        assert input_forms.rewrite_at_lines(line) is None
        with pytest.raises(DecodeError):
            decode_context_text(line)


def test_restricted_access_names_the_file_without_a_select() -> None:
    """TS 27.007 V19.6 section 8.18 NOTE 1: the MT selects the file itself, so the line carries it."""
    out = decode_context_text(f'AT+CRSM=176,28423,0,0,9,,"7FFF"\n+CRSM: 144,0,"{IMSI_FILE}"\nOK')
    exchange = out["exchanges"][0]
    assert exchange["selectedFile"] == "6F07 under 7FFF"
    assert exchange["command"]["name"] == "READ BINARY"
    payload = exchange["response"]["payload"]
    assert payload["title"] == "EF 6F07 content"
    fields = {entry["label"]: entry for entry in payload["fields"]}
    assert fields["File"]["meaning"] == "from the file identifier of the AT command"
    assert fields["imsi"]["value"] == "001010000000001"
    # +CRLA puts the session before the command code; a write keeps its data.
    rewritten = input_forms.rewrite_at_lines('AT+CRLA=2,214,28486,0,0,2,"AABB"\n+CRLA: 144,0')
    assert rewritten is not None and rewritten[0].splitlines() == ["@file 6F46", "> 00D6000002AABB", "< 9000"]
    # A SELECT later in the trace takes the file back.
    later = decode_context_text(
        'AT+CRSM=176,28423,0,0,9\n+CRSM: 144,0,"' + IMSI_FILE + '"\n> 00A40004026F07\n< 9000\n> 00B0000009\n< ' + IMSI_FILE + " 9000"
    )
    last = {entry["label"]: entry for entry in later["exchanges"][2]["response"]["payload"]["fields"]}
    assert last["File"]["meaning"] == "from the last SELECT in the trace"


@pytest.mark.parametrize("line", [
    "", "AT+CRSM=", "AT+CRSM=abc", "AT+CRSM=176,99999,0,0,9", "AT+CRSM=176,28423,300,0,9", 'AT+CRSM=214,28423,0,0,2,"ABC"',
    "+CRSM: 144", "+CRSM: 300,0", '+CRSM: 144,0,"ABC"', "+CSIM: 4", 'AT+CSIM=14,"00A4"x,"00"', "AT+CGLA=1,14",
])
def test_malformed_at_lines_are_left_alone(line: str) -> None:
    assert input_forms.rewrite_at_lines(line) is None


# ----------------------------------------------------------------------
# PEM, JSON, base64
# ----------------------------------------------------------------------


def test_a_certificate_reads_from_der_pem_and_base64_and_a_key_is_never_echoed() -> None:
    der, pem, private = _certificate()
    for text in (der.hex(), pem, base64.b64encode(der).decode()):
        out = decode_context_text(text)
        assert out["context"]["domain"] == "x509"
        root = out["payload"]["schema"]
        assert root["kind"] == "certificate"
        rows = {row["name"]: row["value"] for row in root["children"]}
        assert rows["Subject"] == "CN=eim.example.test, C=XX" and rows["Serial Number"].startswith("07")
    # The raw context keeps the plain tree.
    assert decode_context_text(der.hex(), hint="tlv")["payload"]["title"] == "BER-TLV object"
    # A certificate with a byte after it is not one certificate, and not a TLV either.
    with pytest.raises(DecodeError):
        decode_context_text(der.hex() + "00")
    assert input_forms.certificate_reading(der + b"\x00") is None and input_forms.certificate_reading(der[:-1]) is None
    assert input_forms.certificate_reading(b"") is None and input_forms.certificate_reading(b"\x30") is None

    both = decode_context_text(pem + private + pem)
    children = both["payload"]["schema"]["children"]
    assert [child["name"] for child in children] == ["Certificate 1", "PRIVATE KEY", "Certificate 2"]
    assert children[1] == {"name": "PRIVATE KEY", "kind": "value", "value": "block left unread"}
    assert both["payload"]["title"] == "2 certificates in PEM"
    key_body = "".join(private.strip().splitlines()[1:-1])
    assert key_body[:24] not in json.dumps(both) and key_body[:24] not in both["notation"]
    # A block that is not base64 says so instead of raising.
    broken = decode_context_text("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----")
    assert broken["payload"]["schema"]["children"][0]["value"] == "block is not base64"


def test_base64_is_read_only_where_hex_is_not() -> None:
    encoded = base64.b64encode(bytes.fromhex(PROFILES)).decode()
    out = decode_context_text(encoded)
    assert out["inputForm"] == "base64" and out["inputHex"] == PROFILES
    assert out["payload"]["schemaType"] == "ProfileInfoListResponse"
    assert out["payload"]["notes"][-1] == "Read from base64: 23 byte(s)."
    # The same characters in hex are read as hex, as before.
    assert "inputForm" not in decode_context_text(PROFILES)
    # Base64 that is no TLV is refused like any other text, and so is a hex string of odd length.
    for text in (base64.b64encode(b"plain words, not a card object").decode(), "ABC", "zz"):
        with pytest.raises(DecodeError):
            decode_context_text(text)


def test_a_json_body_reads_its_base64_members() -> None:
    ski = "0414" + "11" * 20
    info1 = bytes.fromhex("BF2035" + "8203020301" + "A916" + ski + "AA16" + ski)
    body = {
        "transactionId": "0102030405060708",
        "euiccChallenge": base64.b64encode(bytes(16)).decode(),
        "euiccInfo1": base64.b64encode(info1).decode(),
        "header": {"functionExecutionStatus": {"status": "Executed-Success"}},
        "state": "Executed",
        "count": 2,
        "flags": [True, None],
    }
    out = decode_context_text(json.dumps(body))
    assert out["inputKind"] == "json" and out["payload"]["title"] == "JSON body with 1 RSP object"
    members = {child["name"]: child for child in out["payload"]["schema"]["children"]}
    # A member written in hex stays text; raw octets show as octets; the object is read by its member name.
    assert members["transactionId"] == {"name": "transactionId", "kind": "string", "value": "0102030405060708"}
    assert members["euiccChallenge"]["kind"] == "octets" and members["euiccChallenge"]["length"] == 16
    assert members["euiccInfo1 (EUICCInfo1)"]["children"][0]["name"] == "lowestSvn"
    assert members["header"]["children"][0]["children"][0]["value"] == "Executed-Success"
    # A word that happens to be base64 by its letters stays the word it is.
    assert members["state"] == {"name": "state", "kind": "string", "value": "Executed"}
    assert members["count"]["value"] == 2 and [child["kind"] for child in members["flags"]["children"]] == ["boolean", "null"]
    assert "lowestSvn = '020301'H (v2.3.1)" in out["notation"]
    # A JSON text without an RSP object, a list and broken JSON are not this decoder's.
    for text in ('{"name": "value"}', "[1, 2]", '{"euiccInfo1": '):
        with pytest.raises(DecodeError):
            decode_context_text(text)


def test_a_profile_package_is_read_by_its_elements() -> None:
    """A header, an akaParameter element and the end element; pySim's SAIP reader names them."""
    pytest.importorskip("pySim.esim.saip")
    package = (
        "a016800102810103830a00000000000000000000a500a600"
        "a435a0058000810101a12ca12a8001018101008210" + "aa" * 16 + "8310" + "bb" * 16
        + "aa07a0058000810102"
    )
    out = decode_context_text(package)
    assert out["inputKind"] == "profile" and out["payload"]["title"] == "Profile package: 3 profile elements"
    fields = {entry["label"]: entry for entry in out["payload"]["fields"]}
    assert fields["Profile package version"]["value"] == "2.3"
    assert [fields[f"PE {index}"]["value"] for index in (1, 2, 3)] == ["header", "akaParameter", "end"]
    assert fields["PE 2"]["meaning"] == "identification 1"
    # The raw context keeps the tree; a package cut short, or one that does not open with the header, is no package.
    assert decode_context_text(package, hint="tlv")["payload"]["title"] == "BER-TLV object"
    data = bytes.fromhex(package)
    for broken in (b"", data[:1], data[:10], data[24:], data[:-3]):
        assert input_forms.profile_package_reading(broken) is None


# ----------------------------------------------------------------------
# Identifiers, ATR, PC/SC
# ----------------------------------------------------------------------


def test_identifiers_in_digits() -> None:
    """EID check digits per SGP.29 v1.1 section 10, the ICCID check digit per E.118 section 6."""
    eid = decode_context_text("89049032123451234512345678901235")
    assert eid["payload"]["title"] == "EID"
    assert {entry["label"]: entry.get("meaning") for entry in eid["payload"]["fields"]}["Check digits"] == "correct"
    wrong = decode_context_text("89049032123451234512345678901236")
    assert "the remainder on division by 97 is 2, not 1" in wrong["notation"]
    # Building the check digits the way the clause says gives a number that verifies.
    body = "890490321234512345123456789012"
    check = 98 - int(body + "00") % 97
    assert decode_context_text(f"{body}{check:02d}")["payload"]["fields"][1]["meaning"] == "correct"

    iccid = decode_context_text("89882012345678901234")
    assert iccid["payload"]["title"] == "ICCID"
    meanings = {entry["label"]: entry.get("meaning") for entry in iccid["payload"]["fields"]}
    assert meanings["Major industry identifier"] == "telecommunication"
    assert meanings["Check digit"].startswith("not the Luhn digit") or meanings["Check digit"] == "correct"
    from pySim.utils import calculate_luhn

    good = "8988201234567890123" + str(calculate_luhn("8988201234567890123"))
    assert decode_context_text(good)["payload"]["fields"][2]["meaning"] == "correct"
    assert decode_context_text("8988201234567890123")["payload"]["title"] == "ICCID"

    imsi = decode_context_text("001010123456789")
    assert _fields(imsi)["MCC"] == "001" and imsi["payload"]["title"] == "IMSI"
    # Other lengths of digits are not identifiers.
    for digits in ("1234567", "12345678901234567", "1" * 33):
        with pytest.raises(DecodeError):
            decode_context_text(digits)


def test_atr_is_read_only_when_it_is_one_whole_atr() -> None:
    out = decode_context_text(ATR)
    assert out["inputKind"] == "atr" and out["payload"]["title"] == "Answer To Reset"
    fields = {entry["label"]: entry for entry in out["payload"]["fields"]}
    assert fields["TS"]["value"] == "3B" and fields["TS"]["meaning"] == "Direct Convention"
    assert fields["TD(2)"]["meaning"].startswith("Y(i+1) = 0001, Protocol T = 15")
    assert "correct checksum" in fields["TCK"]["value"]
    # Four bytes that also parse as an APDU of no known instruction.
    assert decode_context_text("3B021450")["inputKind"] == "atr"
    data = bytes.fromhex(ATR)
    for broken in (b"", data[:1], data[:5], data[:-1], data + b"\x00", data[:-1] + bytes([data[-1] ^ 0xFF]), b"\x3C" + data[1:]):
        assert input_forms.atr_reading(broken) is None
    with pytest.raises(DecodeError):
        decode_context_text(data[:-1].hex())


def test_pcsc_return_code_names_both_readings() -> None:
    pytest.importorskip("smartcard.scard")
    for text in ("0x80100068", "80100068", "80 10 00 68"):
        out = decode_context_text(text)
        assert out["inputKind"] == "pcsc"
        assert _fields(out)["Name"] == "SCARD_W_RESET_CARD" and _fields(out)["Code"] == "0x80100068"
        assert "TERMINAL PROFILE" in out["payload"]["notes"][0]
    # A code PC/SC does not define, a real TERMINAL PROFILE and an explicit context are read as before.
    assert decode_context_text("801000FE")["exchanges"][0]["command"]["name"] == "TERMINAL PROFILE"
    assert decode_context_text("8010000002FFFF")["exchanges"][0]["command"]["name"] == "TERMINAL PROFILE"
    assert decode_context_text("80100068", hint="apdu")["exchanges"][0]["command"]["name"] == "TERMINAL PROFILE"
    assert input_forms.pcsc_reading("") is None and input_forms.pcsc_reading("8010") is None


# ----------------------------------------------------------------------
# EF content context, and the rule that nothing else changes
# ----------------------------------------------------------------------


def test_ef_content_context_takes_the_file_on_the_first_line() -> None:
    out = decode_context_text(f"ADF_USIM/6F07\n{IMSI_FILE}", hint="ef")
    assert out["inputKind"] == "file" and out["payload"]["title"] == "EF 6F07 content"
    fields = {entry["label"]: entry for entry in out["payload"]["fields"]}
    assert fields["File"]["value"] == "6F07 under ADF_USIM" and fields["File"]["meaning"] == "from the first line of the input"
    assert fields["imsi"]["value"] == "001010000000001"
    assert decode_context_text("6f07\n08 09 10 10\n00 00 00 00 10", hint="ef")["byteCount"] == 9
    for text in ("6F07", "IMSI\n0809", "6F07\nnot hex", "6F0\n0809"):
        with pytest.raises(DecodeError):
            decode_context_text(text, hint="ef")


def test_inputs_the_hex_path_reads_into_a_domain_are_untouched() -> None:
    examples = {
        "00A4040007A0000000871002": "uicc",
        "> 80E2910003BF2D0000\n< " + PROFILES + " 9000": "es10",
        "80F24002024F0000": "gp",
        "8012000011": "cat",
    }
    for text, domain in examples.items():
        out = decode_context_text(text)
        assert out["exchanges"][0]["context"]["domain"] == domain
        assert "inputForm" not in out
    assert decode_context_text(PROFILES)["context"]["domain"] == "es10"
    assert decode_context_text("6A82")["inputKind"] == "sw"
    assert render_context_notation(decode_context_text("9000")).startswith("SW 9000")


# ----------------------------------------------------------------------
# TLS records and BIP channel data, read by the shared channel decoder
# ----------------------------------------------------------------------

# A ClientHello for eim.example.test in one record, and a fatal unknown_ca alert.
CLIENT_HELLO = bytes.fromhex(
    "160303005A010000560303202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "000004C02BC0230100002900000015001300001065696D2E6578616D706C652E74657374000A000400020017000D000400020403"
)
TLS_ALERT = bytes.fromhex("15030300020230")
# TS 102 223 v18.3 Table 9.4: OPEN CHANNEL, CLOSE CHANNEL, RECEIVE DATA, SEND DATA.
OPEN_CHANNEL, CLOSE_CHANNEL, RECEIVE_DATA, SEND_DATA = 0x40, 0x41, 0x42, 0x43


def _ctlv(tag: int, body: bytes) -> bytes:
    length = bytes([len(body)]) if len(body) < 0x80 else bytes([0x81, len(body)])
    return bytes([tag]) + length + body


def _fetch(command_type: int, *objects: bytes, channel: int = 1) -> str:
    # TS 102 223 v18.3 section 8.7: destination '21' to '27' is the channel with that identifier.
    body = _ctlv(0x81, bytes([1, command_type, 1])) + _ctlv(0x82, bytes([0x81, 0x20 + channel])) + b"".join(objects)
    proactive = _ctlv(0xD0, body)
    return f"> 80120000{len(proactive) & 0xFF:02X}\n< {proactive.hex()} 9000"


def _terminal_response(command_type: int, *objects: bytes) -> str:
    body = _ctlv(0x81, bytes([1, command_type, 1])) + _ctlv(0x82, b"\x82\x81") + _ctlv(0x83, b"\x00") + b"".join(objects)
    return f"> 80140000{len(body):02X}{body.hex()}\n< 9000"


def _channel_data(exchange: dict, side: str) -> dict:
    nodes = exchange[side]["payload"]["nodes"]
    if side == "response":
        nodes = nodes[0]["children"]
    return next(node for node in nodes if node["tag"] == "36")


def test_pasted_tls_records_are_read_by_the_channel_decoder() -> None:
    out = decode_context_text((CLIENT_HELLO + TLS_ALERT).hex())
    assert out["inputKind"] == "tls" and out["payload"]["title"] == "2 TLS records"
    hello, alert = out["payload"]["nodes"]
    assert hello["name"] == "TLS Handshake" and hello["decoded"].startswith("ClientHello sni=eim.example.test")
    notes = {child["name"]: child["decoded"] for child in hello["children"]}
    assert notes["version"] == "TLS 1.2" and "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" in notes["cipher suites"]
    assert (alert["name"], alert["decoded"]) == ("TLS Alert", "fatal unknown_ca")
    # A short record has the shape of an APDU of no known instruction; it is read as the record.
    assert decode_context_text(TLS_ALERT.hex())["inputKind"] == "tls"
    assert decode_context_text(TLS_ALERT.hex(), hint="apdu")["exchanges"][0]["context"]["domain"] == "unknown"
    # A record sent after the ChangeCipherSpec is named protected, not parsed.
    protected = decode_context_text("140303000101" + "1603030010" + "AA" * 16)["payload"]["nodes"][1]
    assert protected["children"][0]["name"] == "protected"


@pytest.mark.parametrize("raw", [
    b"", b"\x16", b"\x16\x03\x03\x00", b"\x16\x03\x03\x00\x00", b"\x16\x03\x03\x00\x05\x01", TLS_ALERT[:-1], TLS_ALERT + b"\x15",
    b"\x99\x03\x03\x00\x01\x00", b"\x16\x02\x00\x00\x01\x00", b"\x16\x03\x09\x00\x01\x00", b"\x16\x03\x03\xff\xff" + bytes(10),
])
def test_only_whole_records_count_as_a_tls_paste(raw: bytes) -> None:
    assert input_forms.whole_tls_records(raw) == 0 and input_forms.tls_reading(raw) is None


def test_channel_data_is_followed_as_one_stream_across_a_trace() -> None:
    trace = "\n".join([
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO[:50])),
        _terminal_response(SEND_DATA, _ctlv(0xB7, b"\xFF")),
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO[50:])),
        _terminal_response(SEND_DATA, _ctlv(0xB7, b"\xFF")),
        _fetch(RECEIVE_DATA, _ctlv(0xB7, b"\x07")),
        _terminal_response(RECEIVE_DATA, _ctlv(0xB6, TLS_ALERT), _ctlv(0xB7, b"\x00")),
    ])
    exchanges = decode_context_text(trace)["exchanges"]
    # Nothing completes in the first block: its octets stay in view, with what they wait for.
    first = _channel_data(exchanges[0], "response")
    assert "children" not in first and first["decoded"].startswith("50 byte(s)") and first["valueHex"] == CLIENT_HELLO[:50].hex().upper()
    second = _channel_data(exchanges[2], "response")["children"][0]
    assert second["decoded"].startswith("ClientHello sni=eim.example.test")
    assert {child["name"]: child["decoded"] for child in second["children"]}["reassembled"] == "from 2 data blocks"
    received = _channel_data(exchanges[5], "command")["children"][0]
    assert (received["name"], received["decoded"]) == ("TLS Alert", "fatal unknown_ca")
    # A channel starts afresh when OPEN CHANNEL assigns its identifier (the Channel status of the
    # TERMINAL RESPONSE, section 8.56): the cut record before it is not joined to what follows.
    fresh = "\n".join([
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO[:50])),
        _fetch(OPEN_CHANNEL),
        _terminal_response(OPEN_CHANNEL, _ctlv(0xB8, b"\x81\x00")),
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO[50:])),
    ])
    last = _channel_data(decode_context_text(fresh)["exchanges"][3], "response")
    assert all(node["name"] != "TLS Handshake" for node in last.get("children", []))
    # A request line is read the same way; what is no record, DNS message or HTTP line stays bytes.
    alone = decode_context_text(_fetch(SEND_DATA, _ctlv(0xB6, b"POST /gsma/rsp2/asn1 HTTP/1.1\r\nHost: eim.example.test\r\n\r\n")))
    http = _channel_data(alone["exchanges"][0], "response")["children"][0]
    assert (http["name"], http["decoded"]) == ("HTTP Request", "POST /gsma/rsp2/asn1")
    plain = decode_context_text(_fetch(SEND_DATA, _ctlv(0xB6, b"\x01\x02\x03\x04\x05\x06")))
    assert "children" not in _channel_data(plain["exchanges"][0], "response")
    # Outside a trace one block is read on its own.
    bare = _ctlv(0xD0, _ctlv(0x81, bytes([1, SEND_DATA, 1])) + _ctlv(0x82, b"\x81\x21") + _ctlv(0xB6, TLS_ALERT))
    for hint in ("auto", "cat"):
        assert "TLS Alert = fatal unknown_ca" in decode_context_text(bare.hex(), hint=hint)["notation"], hint


def test_each_channel_is_its_own_stream() -> None:
    """Two channels open at once: their blocks are not mixed, and closing one leaves the other's bytes."""
    trace = "\n".join([
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO[:50]), channel=1),
        _fetch(SEND_DATA, _ctlv(0xB6, TLS_ALERT), channel=2),
        _fetch(CLOSE_CHANNEL, channel=2),
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO[50:]), channel=1),
        _fetch(RECEIVE_DATA, _ctlv(0xB7, b"\x07"), channel=2),
        _terminal_response(RECEIVE_DATA, _ctlv(0xB6, TLS_ALERT), _ctlv(0xB7, b"\x00")),
    ])
    exchanges = decode_context_text(trace)["exchanges"]
    assert _channel_data(exchanges[0], "response")["decoded"].startswith("50 byte(s)")
    other = _channel_data(exchanges[1], "response")["children"]
    assert [(node["name"], node["decoded"]) for node in other] == [("TLS Alert", "fatal unknown_ca")]
    joined = _channel_data(exchanges[3], "response")["children"][0]
    assert joined["decoded"].startswith("ClientHello sni=eim.example.test")
    # The answer to RECEIVE DATA carries no channel: it belongs to the channel of the command before it.
    answer = _channel_data(exchanges[5], "command")["children"]
    assert [(node["name"], node["decoded"]) for node in answer] == [("TLS Alert", "fatal unknown_ca")]


def test_a_server_flight_is_read_across_receive_data_blocks() -> None:
    """ServerHello and Certificate come back in RECEIVE DATA answers cut below one record."""
    der, _pem, _private = _certificate()

    def vector(width: int, body: bytes) -> bytes:
        return len(body).to_bytes(width, "big") + body

    server_hello = b"\x02" + vector(3, bytes.fromhex("0303") + bytes(range(0x40, 0x60)) + vector(1, b"") + bytes.fromhex("C02B") + b"\x00")
    certificate = b"\x0B" + vector(3, vector(3, vector(3, der)))
    flight = b"\x16\x03\x03" + vector(2, server_hello) + b"\x16\x03\x03" + vector(2, certificate)
    lines = [_fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO)), _terminal_response(SEND_DATA, _ctlv(0xB7, b"\xFF"))]
    for start in range(0, len(flight), 200):
        chunk = flight[start:start + 200]
        lines.append(_fetch(RECEIVE_DATA, _ctlv(0xB7, bytes([len(chunk)]))))
        lines.append(_terminal_response(RECEIVE_DATA, _ctlv(0xB6, chunk), _ctlv(0xB7, b"\x00")))
    exchanges = decode_context_text("\n".join(lines))["exchanges"]
    first = _channel_data(exchanges[3], "command")["children"]
    assert first[0]["decoded"].startswith("ServerHello") and first[-1]["name"] == "continues"
    chosen = {child["name"]: child["decoded"] for child in first[0]["children"]}
    assert chosen["cipher suite"] == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    chain = _channel_data(exchanges[5], "command")["children"][0]
    parts = {child["name"]: child["decoded"] for child in chain["children"]}
    # The certificate is named once, by its subject, and the message says how many blocks it took.
    assert chain["decoded"].startswith("Certificate") and parts["certificate 1"] == "CN=eim.example.test,C=XX"
    assert parts["reassembled"] == "from 2 data blocks" and len(chain["children"]) == 2
    # A ServerHello that picks a suite the ClientHello did not offer keeps the decoder's mark.
    stray = b"\x02" + vector(3, bytes.fromhex("0303") + bytes(32) + vector(1, b"") + bytes.fromhex("009C") + b"\x00")
    marked = decode_context_text("\n".join([
        _fetch(SEND_DATA, _ctlv(0xB6, CLIENT_HELLO)),
        _fetch(RECEIVE_DATA, _ctlv(0xB7, b"\x30")),
        _terminal_response(RECEIVE_DATA, _ctlv(0xB6, b"\x16\x03\x03" + vector(2, stray)), _ctlv(0xB7, b"\x00")),
    ]))
    notes = _channel_data(marked["exchanges"][2], "command")["children"][0]["children"]
    assert any(str(child["decoded"]).endswith(("[warn]", "[fail]")) for child in notes), notes


# ----------------------------------------------------------------------
# The command line hands its text over as it is
# ----------------------------------------------------------------------


def test_the_command_line_reads_the_same_forms(tmp_path, monkeypatch) -> None:
    """`python -m Tools.Asn1TlvDecode --context`: a file, piped lines and one argument reach the same reader."""
    import io

    from Tools.Asn1TlvDecode.main import run_cli

    def run(argv: list[str], piped: str | None = None) -> str:
        if piped is not None:
            monkeypatch.setattr("sys.stdin", io.StringIO(piped))
        out = io.StringIO()
        assert run_cli(["--context", "--color", "never", *argv], stdout=out, stderr=io.StringIO()) == 0
        return out.getvalue()

    restricted = run([], piped='AT+CRSM=176,28423,0,0,9\n+CRSM: 144,0,"080910100000000010"\n')
    assert "READ BINARY" in restricted and "imsi: 001010000000001" in restricted
    content = run(["--domain", "ef"], piped="ADF_USIM/6F07\n080910100000000010\n")
    assert "File: 6F07 under ADF_USIM" in content and "imsi: 001010000000001" in content
    assert "Check digits: 35  -- correct" in run(["89049032123451234512345678901235"])
    assert "SCARD_W_RESET_CARD" in run(["0x80100068"])
    _der, pem, private = _certificate()
    saved = tmp_path / "leaf.pem"
    saved.write_text(pem + private, encoding="ascii")
    from_file = run(["--file", str(saved)])
    assert "eim.example.test" in from_file and "left unread" in from_file
    # The key block is named, never printed.
    assert private.splitlines()[1] not in from_file
    as_json = json.loads(run(["--format", "json", ATR]))
    assert as_json["inputKind"] == "atr"


# ----------------------------------------------------------------------
# One context list on every surface, and examples that decode
# ----------------------------------------------------------------------


def _page_tables() -> tuple[list[list[str]], list[dict]]:
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    source = (Path(__file__).resolve().parents[1] / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
    start = source.index("  var CC_DECODER_CONTEXTS = [")
    end = source.index("\n  ];\n", source.index("  var CC_DECODER_EXAMPLES = [")) + len("\n  ];\n")
    script = source[start:end] + "\nconsole.log(JSON.stringify([CC_DECODER_CONTEXTS, CC_DECODER_EXAMPLES]));"
    done = subprocess.run([node, "-e", script], capture_output=True, text=True, timeout=30, check=True)
    contexts, examples = json.loads(done.stdout)
    return contexts, examples


def test_the_context_list_is_the_same_on_every_surface() -> None:
    from SIMCARD.state import DEFAULT_SIM_ATR
    from Tools.Asn1TlvDecode import context as engine
    from Tools.Asn1TlvDecode import main as cli
    from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded

    assert DEFAULT_SIM_ATR.hex().upper() == ATR
    action = ensure_builtin_actions_loaded().get("tool.decoder.context")
    choices = list(next(field.choices for field in action.inputs if field.name == "context"))
    # The engine holds the set; the action, the command line and the page list it in one order.
    assert sorted(choices) == sorted(engine._HINTS) and len(choices) == len(set(choices))
    cli_source = Path(cli.__file__).read_text(encoding="utf-8")
    assert "choices=(" + ", ".join(f'"{choice}"' for choice in choices) + ")," in cli_source
    contexts, _examples = _page_tables()
    assert [value for value, _label in contexts] == choices
    assert dict(contexts)["ef"] == "EF content"


def test_every_panel_example_decodes() -> None:
    _contexts, examples = _page_tables()
    assert len(examples) >= 13
    for example in examples:
        out = decode_context_text(example["text"], hint=example.get("context", "auto"))
        assert out["notation"], example["label"]
    by_label = {example["label"]: example for example in examples}
    assert decode_context_text(by_label["Answer To Reset"]["text"])["inputKind"] == "atr"
    assert by_label["EF content, the file on the first line"]["context"] == "ef"
    bip = decode_context_text(by_label["BIP: a ClientHello cut across two SEND DATA blocks"]["text"])
    assert "reassembled = from 2 data blocks" in bip["notation"] and "TLS Alert = fatal unknown_ca" in bip["notation"]
    script = decode_context_text(by_label["Script: one command per row"]["text"])
    assert script["exchangeCount"] == 3 and all("response" not in exchange for exchange in script["exchanges"])
    crsm = decode_context_text(by_label["AT+CRSM read of EF.IMSI"]["text"])
    assert crsm["exchanges"][0]["response"]["payload"]["title"] == "EF 6F07 content"
