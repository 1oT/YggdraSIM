# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Input forms of the context decoder other than plain hex.

AT command lines that carry APDUs are rewritten into the command and response
lines the trace parser reads. A paste the hex path refuses is tried as PEM
blocks, a JSON body with base64 members (the ES9+ and ESipa JSON bindings), an
identifier written in digits, base64 and an ATR. A reading of the hex path
that names no domain (its plain BER tree, an instruction it does not know) may
be replaced by a certificate or an ATR when the whole input is one. Nothing
here takes an input the hex path already reads into a domain, with one
exception: four bytes that are a PC/SC return code, which name both readings.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any

# TS 27.007 V19.6 section 8.18: the commands +CRSM (and +CRLA, section 8.44)
# pass on to the card, by decimal code; every other value is reserved.
RESTRICTED_SIM_COMMANDS: dict[int, str] = {
    176: "READ BINARY",
    178: "READ RECORD",
    192: "GET RESPONSE",
    214: "UPDATE BINARY",
    220: "UPDATE RECORD",
    242: "STATUS",
    203: "RETRIEVE DATA",
    219: "SET DATA",
}

# The marker line the rewrite puts before a +CRSM command: the file the MT
# selects for it (TS 27.007 V19.6 section 8.18 NOTE 1).
FILE_MARKER = "@file"

_AT_LINE = re.compile(r"^\s*(?:AT)?\+(CSIM|CGLA|CRSM|CRLA)\s*([=:])\s*(.*?)\s*$", re.IGNORECASE)
_PEM_BLOCK = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.DOTALL)
_BASE64 = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_HEX_ONLY = re.compile(r"[0-9A-Fa-f]+")
_PCSC_CODE = re.compile(r"(?:0x)?(8010[0-9A-Fa-f]{4})", re.IGNORECASE)

# Lengths of the identifiers read from plain digits: IMSI, ICCID, EID.
_IMSI_DIGITS = 15
_ICCID_DIGITS = (19, 20)
_EID_DIGITS = 32


# ----------------------------------------------------------------------
# AT command lines
# ----------------------------------------------------------------------


def _split_parameters(text: str) -> list[str]:
    """The comma-separated parameters of an AT line, quotes removed; a comma inside quotes stays."""
    parameters: list[str] = []
    current: list[str] = []
    quoted = False
    for character in text:
        if character == '"':
            quoted = not quoted
            continue
        if character == "," and not quoted:
            parameters.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    parameters.append("".join(current).strip())
    return parameters


def _hex_parameter(text: str) -> str | None:
    compact = re.sub(r"\s", "", text)
    if len(compact) % 2 != 0 or _HEX_ONLY.fullmatch(compact) is None:
        return None
    return compact.upper()


def _generic_command(verb: str, parameters: list[str], notes: list[str]) -> list[str] | None:
    # +CSIM=<length>,<command>; +CGLA=<sessionid>,<length>,<command>.
    wanted = 2 if verb == "CSIM" else 3
    if len(parameters) != wanted:
        return None
    command = _hex_parameter(parameters[-1])
    if not command:
        return None
    if parameters[-2].isdigit() and int(parameters[-2]) != len(command):
        notes.append(f"+{verb}: <length> says {parameters[-2]} characters, the command has {len(command)}")
    return [f"> {command}"]


def _generic_response(verb: str, parameters: list[str], notes: list[str]) -> list[str] | None:
    # +CSIM: <length>,<response>; +CGLA: <length>,<response>.
    if len(parameters) != 2:
        return None
    response = _hex_parameter(parameters[1])
    if not response:
        return None
    if parameters[0].isdigit() and int(parameters[0]) != len(response):
        notes.append(f"+{verb}: <length> says {parameters[0]} characters, the response has {len(response)}")
    return [f"< {response}"]


def _restricted_command(verb: str, parameters: list[str], notes: list[str]) -> list[str] | None:
    # +CRSM=<command>[,<fileid>[,<P1>,<P2>,<P3>[,<data>[,<pathid>]]]]; +CRLA puts <sessionid> first.
    if verb == "CRLA":
        parameters = parameters[1:]
    if not parameters or not parameters[0].isdigit():
        return None
    code = int(parameters[0])
    if code not in RESTRICTED_SIM_COMMANDS:
        notes.append(f"+{verb}: command code {code} is reserved")
        return None
    numbers = parameters[1:5]
    if any(value and not value.isdigit() for value in numbers):
        return None
    file_id, p1, p2, p3 = ([int(value) if value else 0 for value in numbers] + [0, 0, 0, 0])[:4]
    if file_id > 0xFFFF or max(p1, p2, p3) > 0xFF:
        return None
    data = ""
    if len(parameters) > 5 and parameters[5]:
        data = _hex_parameter(parameters[5]) or ""
        if not data:
            return None
    path = ""
    if len(parameters) > 6 and parameters[6]:
        path = _hex_parameter(parameters[6]) or ""
    lines: list[str] = []
    if len(parameters) > 1 and parameters[1]:
        lines.append(f"{FILE_MARKER} {file_id:04X} {path}".rstrip())
    # The MT chooses the class byte; '00' stands for it here.
    lines.append(f"> 00{code:02X}{p1:02X}{p2:02X}{p3:02X}{data}")
    return lines


def _restricted_response(parameters: list[str]) -> list[str] | None:
    # +CRSM: <sw1>,<sw2>[,<response>]; +CRLA answers the same way.
    if len(parameters) < 2 or not parameters[0].isdigit() or not parameters[1].isdigit():
        return None
    sw1, sw2 = int(parameters[0]), int(parameters[1])
    if sw1 > 0xFF or sw2 > 0xFF:
        return None
    response = ""
    if len(parameters) > 2 and parameters[2]:
        response = _hex_parameter(parameters[2]) or ""
        if not response:
            return None
    return [f"< {response}{sw1:02X}{sw2:02X}"]


def rewrite_at_lines(text: str) -> tuple[str, list[str]] | None:
    """Rewrite the AT lines that carry APDUs as the trace parser's command and response lines.

    +CSIM, +CRSM, +CGLA and +CRLA (TS 27.007 V19.6 sections 8.17, 8.18, 8.43,
    8.44) are read, as a command with or without its AT prefix and as the
    answer the MT prints. Every other line is left as it is. Returns the text
    and what the rewrite noticed, or None when no line was rewritten.
    """
    lines: list[str] = []
    notes: list[str] = []
    rewritten = False
    for line in str(text or "").splitlines():
        match = _AT_LINE.match(line)
        if match is None:
            lines.append(line)
            continue
        verb = match.group(1).upper()
        parameters = _split_parameters(match.group(3))
        if match.group(2) == ":":
            converted = _restricted_response(parameters) if verb in ("CRSM", "CRLA") else _generic_response(verb, parameters, notes)
        elif verb in ("CRSM", "CRLA"):
            converted = _restricted_command(verb, parameters, notes)
        else:
            converted = _generic_command(verb, parameters, notes)
        if converted is None:
            lines.append(line)
            continue
        rewritten = True
        lines.extend(converted)
    if not rewritten:
        return None
    return "\n".join(lines), notes


# ----------------------------------------------------------------------
# Readings that are not an APDU or a TLV
# ----------------------------------------------------------------------


def _result(kind: str, domain: str, label: str, payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "inputKind": kind,
        "context": {"domain": domain, "label": label, "spec": payload.get("spec", ""), "summary": payload.get("title", "")},
        "payload": payload,
    }


def certificate_node(name: str, der: bytes) -> dict[str, Any]:
    """An X.509 certificate as the rows of ``SCP11.shared.certificate_view``; a block that is none shows why."""
    from SCP11.shared.certificate_view import certificate_rows

    rows = [
        {"name": row.label, "kind": "value", "value": row.value, "tone": row.tone, "indent": row.indent}
        for row in certificate_rows(der)
    ]
    return {"name": name, "kind": "certificate", "valueHex": der.hex().upper(), "length": len(der), "children": rows}


def _is_certificate(data: bytes) -> bool:
    """True when ``data`` is one DER certificate and nothing else."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    if len(data) < 4 or data[0] != 0x30:
        return False
    try:
        certificate = x509.load_der_x509_certificate(data)
        return certificate.public_bytes(Encoding.DER) == data
    except (ValueError, TypeError):
        return False


def certificate_reading(data: bytes) -> dict[str, Any] | None:
    """The reading of one DER certificate, or None when ``data`` is not exactly one."""
    from .context import _payload

    if not _is_certificate(data):
        return None
    payload = _payload(
        "x509", "X.509 certificate", "RFC 5280",
        schema=certificate_node("Certificate", data), schemaType="Certificate", schemaSource=[],
    )
    return _result("certificate", "x509", "X.509 certificate", payload)


def profile_package_reading(data: bytes) -> dict[str, Any] | None:
    """The profile elements of an unprotected profile package, or None when ``data`` is not one whole package.

    pySim's SAIP reader names the elements (TCA eUICC Profile Package
    V3.4.1); a package is taken only when it opens with the header element
    and every byte is read. The SAIP Tool is the place to read one element
    in full or to edit it.
    """
    from .context import _bcd_digits, _field, _payload

    if len(data) < 4 or data[0] != 0xA0:
        return None
    try:
        from pySim.esim.saip import ProfileElementSequence

        sequence = ProfileElementSequence.from_der(bytes(data))
    except ImportError:
        return None
    except Exception:  # noqa: BLE001 - asn1tools decode errors are library-specific; anything else is not a package
        return None
    elements = list(sequence.pe_list)
    if not elements or elements[0].type != "header":
        return None
    header = elements[0].decoded if isinstance(elements[0].decoded, dict) else {}
    fields = [_field("Profile package version", f"{header.get('major-version')}.{header.get('minor-version')}")]
    iccid = header.get("iccid")
    if isinstance(iccid, (bytes, bytearray)):
        fields.append(_field("ICCID", bytes(iccid).hex().upper(), _bcd_digits(bytes(iccid))))
    if header.get("profileType"):
        fields.append(_field("Profile type", str(header["profileType"])))
    for index, element in enumerate(elements, start=1):
        identification = getattr(element, "identification", None)
        fields.append(_field(f"PE {index}", str(element.type), "" if identification is None else f"identification {identification}"))
    title = f"Profile package: {len(elements)} profile element{'' if len(elements) == 1 else 's'}"
    payload = _payload(
        "saip", title, "TCA eUICC Profile Package V3.4.1", fields=fields,
        notes=["The elements are named here; the SAIP Tool reads one in full and edits it."],
    )
    return _result("profile", "saip", "eUICC profile package", payload)


def _read_pem(text: str) -> dict[str, Any] | None:
    from .context import _payload

    blocks = _PEM_BLOCK.findall(text)
    if not blocks:
        return None
    children: list[dict[str, Any]] = []
    certificates = 0
    for label, body in blocks:
        label = label.strip()
        if label not in ("CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"):
            # Key material and requests are not read here; a private key is never echoed.
            children.append({"name": label, "kind": "value", "value": "block left unread"})
            continue
        try:
            der = base64.b64decode(re.sub(r"\s", "", body), validate=True)
        except (binascii.Error, ValueError):
            children.append({"name": label, "kind": "value", "value": "block is not base64"})
            continue
        certificates += 1
        children.append(certificate_node(f"Certificate {certificates}", der))
    title = f"{certificates} certificate{'' if certificates == 1 else 's'} in PEM"
    root = children[0] if len(children) == 1 and certificates == 1 else {"name": "PEM", "kind": "sequence", "children": children}
    payload = _payload("x509", title, "RFC 5280", schema=root, schemaType="Certificate", schemaSource=[])
    return _result("pem", "x509", "X.509 certificate", payload)


def _json_node(name: str, value: Any, counts: dict[str, int]) -> dict[str, Any]:
    """A JSON member as a display node; a base64 string that is an RSP object is read as one."""
    from .context import decode_rsp_object

    if isinstance(value, dict):
        return {"name": name, "kind": "sequence", "children": [_json_node(str(key), item, counts) for key, item in value.items()]}
    if isinstance(value, list):
        return {"name": name, "kind": "list", "children": [_json_node(f"[{index}]", item, counts) for index, item in enumerate(value)]}
    if isinstance(value, bool):
        return {"name": name, "kind": "boolean", "value": value}
    if value is None:
        return {"name": name, "kind": "null"}
    if isinstance(value, (int, float)):
        return {"name": name, "kind": "integer", "value": value}
    text = str(value)
    compact = re.sub(r"\s", "", text)
    # A member written in hex (transactionId) stays text; base64 is tried on the rest.
    if compact and len(compact) % 4 == 0 and _BASE64.fullmatch(compact) and not _HEX_ONLY.fullmatch(compact):
        try:
            data = base64.b64decode(compact, validate=True)
        except (binascii.Error, ValueError):
            data = b""
        if data:
            reading = decode_rsp_object(data, type_hint=name)
            if reading is not None and isinstance(reading.get("schema"), dict):
                counts["objects"] += 1
                node = dict(reading["schema"])
                node["name"] = f"{name} ({reading.get('schemaType') or node.get('name')})"
                return node
            # A plain word of the right length is base64 by its letters alone; it stays text.
            if re.search(r"[0-9+/=]", compact):
                counts["octets"] += 1
                return {"name": name, "kind": "octets", "valueHex": data.hex().upper(), "length": len(data)}
    return {"name": name, "kind": "string", "value": text}


def _read_json(text: str) -> dict[str, Any] | None:
    from .context import _installation_result, _payload

    if not text.startswith("{"):
        return None
    try:
        body = json.loads(text)
    except ValueError:
        return None
    if not isinstance(body, dict) or not body:
        return None
    counts = {"objects": 0, "octets": 0}
    root = {"name": "JSON body", "kind": "sequence", "children": [_json_node(str(key), item, counts) for key, item in body.items()]}
    if counts["objects"] == 0:
        # A JSON text with no RSP object in it is not this decoder's to read.
        return None
    title = f"JSON body with {counts['objects']} RSP object{'' if counts['objects'] == 1 else 's'}"
    payload = _payload("rsp", title, "GSMA SGP.22 / SGP.32 JSON binding", schema=root, schemaType="JSON body", schemaSource=[])
    result = _installation_result(root)
    if result is not None:
        payload["result"] = result
    return _result("json", "es10", "GSMA RSP function body (JSON)", payload)


def _eid_fields(digits: str) -> list[dict[str, Any]]:
    from .context import _field

    # SGP.29 v1.1 section 10: the 32 digits as a decimal integer leave remainder 1 on division by 97.
    remainder = int(digits) % 97
    verdict = "correct" if remainder == 1 else f"wrong: the remainder on division by 97 is {remainder}, not 1"
    return [
        _field("EID", digits, "32 digits"),
        _field("Check digits", digits[-2:], verdict, spec="SGP.29 v1.1 section 10"),
    ]


def _iccid_fields(digits: str) -> list[dict[str, Any]]:
    from pySim.utils import calculate_luhn

    from .context import _field

    # E.118 (09/2025) section 6: the last digit is the Luhn parity check digit of the others.
    expected = str(calculate_luhn(digits[:-1]))
    if digits[-1] == expected:
        verdict = "correct"
    else:
        verdict = (
            f"not the Luhn digit of the first {len(digits) - 1} digits, which is {expected}; "
            f"if these {len(digits)} digits are written without a check digit, it would be {calculate_luhn(digits)}"
        )
    return [
        _field("ICCID", digits, f"{len(digits)} digits"),
        _field("Major industry identifier", digits[:2], "telecommunication" if digits[:2] == "89" else "not '89'", spec="E.118 (09/2025) section 6"),
        _field("Check digit", digits[-1], verdict, spec="E.118 (09/2025) section 6"),
    ]


def _imsi_fields(digits: str) -> list[dict[str, Any]]:
    from .context import _field

    # E.212 (06/2024) section 6.1: MCC, then an MNC of two or three digits, then the MSIN.
    return [
        _field("IMSI", digits, f"{len(digits)} digits"),
        _field("MCC", digits[:3], spec="E.212 (06/2024) section 6.1"),
        _field("MNC and MSIN", digits[3:], f"MNC {digits[3:5]} with MSIN {digits[5:]}, or MNC {digits[3:6]} with MSIN {digits[6:]}; the length of the MNC is the numbering plan's"),
    ]


def _read_identifier(text: str) -> dict[str, Any] | None:
    from .context import _payload

    digits = re.sub(r"[\s-]", "", text)
    if not digits.isdigit() or not digits.isascii():
        return None
    if len(digits) == _EID_DIGITS:
        title, fields = "EID", _eid_fields(digits)
    elif len(digits) in _ICCID_DIGITS:
        try:
            title, fields = "ICCID", _iccid_fields(digits)
        except ImportError:
            return None
    elif len(digits) == _IMSI_DIGITS:
        title, fields = "IMSI", _imsi_fields(digits)
    else:
        return None
    payload = _payload("identifier", title, "", fields=fields, notes=["Read as an identifier written in digits; the hex reading of the same characters is neither an APDU nor a TLV."])
    return _result("identifier", "id", "Identifier", payload)


def _read_base64(text: str, hint: str) -> dict[str, Any] | None:
    from .context import DecodeError, _standalone_payload

    compact = re.sub(r"\s", "", text)
    if len(compact) < 8 or len(compact) % 4 != 0 or _BASE64.fullmatch(compact) is None or _HEX_ONLY.fullmatch(compact):
        return None
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not data:
        return None
    try:
        result = _standalone_payload(data, hint)
    except DecodeError:
        return None
    payload = result.get("payload")
    if isinstance(payload, dict):
        payload["notes"] = list(payload.get("notes") or []) + [f"Read from base64: {len(data)} byte(s)."]
        refined = certificate_reading(data) if payload.get("title") == "BER-TLV object" else None
        if refined is not None:
            result = refined
    result["inputForm"] = "base64"
    result["inputHex"] = data.hex().upper()
    result["byteCount"] = len(data)
    return result


def atr_reading(data: bytes) -> dict[str, Any] | None:
    """The reading of an Answer To Reset, or None when ``data`` is not one complete ATR.

    The description is the admin shell's (``CardTransporter.describe_atr``,
    which follows TS 102 221 v18.4 section 6.3); an ATR it finds truncated,
    with trailing bytes or with a wrong checksum is not taken as one here.
    """
    from .context import _field, _payload

    if len(data) < 2 or data[0] not in (0x3B, 0x3F):
        return None
    try:
        from SCP03.transport.card import CardTransporter
    except ImportError:
        return None

    class _AtrOnly(CardTransporter):
        def __init__(self, atr: bytes) -> None:  # the transport itself is never opened
            self._atr_bytes = atr

        def get_atr_bytes(self) -> bytes:
            return self._atr_bytes

    lines = _AtrOnly(bytes(data)).describe_atr()
    if any(line.startswith("!") or "checksum mismatch" in line for line in lines):
        return None
    fields: list[dict[str, Any]] = []
    for line in lines:
        text = line.strip().lstrip("+").strip()
        if not text or set(text) == {"-"}:
            continue
        label, separator, meaning = text.partition("-->")
        name, equals, value = label.partition("=")
        if not equals and not separator:
            name, equals, value = label.partition(":")
        if equals and not name.strip().startswith("-") and "," not in name:
            fields.append(_field(name.strip(), value.strip(), meaning.strip() if separator else ""))
        elif fields:
            # A line under a byte belongs to that byte: it is added to what the byte means.
            detail = text.lstrip("- ").strip()
            previous = str(fields[-1].get("meaning") or "")
            fields[-1]["meaning"] = f"{previous}; {detail}" if previous else detail
    payload = _payload("atr", "Answer To Reset", "TS 102 221 v18.4 section 6.3", fields=fields)
    return _result("atr", "atr", "Answer To Reset", payload)


def channel_event_nodes(events: list[Any]) -> list[dict[str, Any]]:
    """Display nodes for what the BIP payload decoder reports: TLS records and handshake messages, DNS, HTTP.

    The reading is ``yggdrasim_common.bip_stream_decode``'s, the one decoder of
    channel payloads; this only lays its events out. A payload it leaves raw
    gives no node.
    """
    from yggdrasim_common import bip_stream_decode

    from .context import _part_node

    nodes: list[dict[str, Any]] = []
    for event in events:
        if event.kind == bip_stream_decode.KIND_RAW:
            continue
        name, _, detail = str(event.summary).partition(": ")
        # A note the decoder marks is shown with its mark: a ServerHello is judged against the ClientHello.
        children = [
            _part_node(note.label, b"", decoded=f"{note.value} [{note.tone}]" if note.tone in ("warn", "fail") else note.value)
            for note in event.notes
        ]
        for position, der in enumerate(event.certificates, 1):
            children.append(_part_node(f"certificate {position}", b"", decoded=_certificate_subject(der) or f"{len(der)} byte(s)"))
        if event.segments > 1:
            children.append(_part_node("reassembled", b"", decoded=f"from {event.segments} data blocks"))
        if event.truncated:
            children.append(_part_node("cut short", b"", decoded="the rest never arrived"))
        if event.encrypted:
            children.append(_part_node("protected", b"", decoded="sent after the ChangeCipherSpec; not decrypted"))
        nodes.append(_part_node(name, b"", decoded=detail or None, children=children or None))
    return nodes


def _certificate_subject(der: bytes) -> str:
    try:
        from cryptography import x509

        return x509.load_der_x509_certificate(der).subject.rfc4514_string()
    except (ImportError, ValueError, TypeError):
        return ""


def channel_payload_nodes(data: bytes, direction: str = "") -> list[dict[str, Any]]:
    """The reading of one block of BIP channel data on its own; nothing is carried to the next block."""
    from yggdrasim_common import bip_stream_decode

    return channel_event_nodes(bip_stream_decode.decode_payload(bytes(data or b""), direction))


def whole_tls_records(data: bytes) -> int:
    """How many TLS records ``data`` is, when it is whole records and nothing else; 0 otherwise.

    RFC 5246 section 6.2.1 forbids an empty fragment for every content type
    but application data, and a paste is held to that for all of them: five
    bytes with a zero length say too little to be called a record.
    """
    from yggdrasim_common import bip_stream_decode

    data = bytes(data or b"")
    position = 0
    count = 0
    while position < len(data):
        header = bip_stream_decode.peek_tls_record(data[position:])
        if header is None or not header.complete or header.length == 0:
            return 0
        position += header.total_length
        count += 1
    return count


def tls_reading(data: bytes) -> dict[str, Any] | None:
    """The reading of pasted TLS records (RFC 5246 section 6.2.1), or None."""
    from .context import _payload

    count = whole_tls_records(data)
    if count == 0:
        return None
    nodes = channel_payload_nodes(data)
    title = f"{count} TLS record{'' if count == 1 else 's'}"
    payload = _payload("tls", title, "RFC 5246 section 6.2.1", nodes=nodes)
    return _result("tls", "tls", "TLS record layer", payload)


def pcsc_reading(text: str) -> dict[str, Any] | None:
    """The reading of a PC/SC return code such as 0x80100068, or None.

    The names and messages are pyscard's, so the table is the installed PC/SC
    library's own. The same four bytes also parse as an APDU; the note says so.
    """
    from .context import _field, _payload

    match = _PCSC_CODE.fullmatch(re.sub(r"[\s:,-]", "", text))
    if match is None:
        return None
    code = int(match.group(1), 16)
    try:
        from smartcard import scard

        names = {
            getattr(scard, name) & 0xFFFFFFFF: name
            for name in dir(scard)
            if name.startswith(("SCARD_E_", "SCARD_W_", "SCARD_F_", "SCARD_P_")) and isinstance(getattr(scard, name), int)
        }
        name = names.get(code)
        message = str(scard.SCardGetErrorMessage(code)) if name else ""
    except (ImportError, AttributeError, TypeError, OverflowError):
        return None
    if not name:
        return None
    payload = _payload(
        "pcsc", "PC/SC return code", "",
        fields=[_field("Code", f"0x{code:08X}"), _field("Name", name), _field("Meaning", message)],
        notes=[f"As an APDU the same four bytes read CLA '80' INS '10' (TERMINAL PROFILE) with P2 '{code & 0xFF:02X}' and no profile."],
    )
    return _result("pcsc", "pcsc", "PC/SC return code", payload)


def read_refused(text: str, hint: str) -> dict[str, Any] | None:
    """A reading for text the hex path refused, or None when no other form fits it either."""
    from .context import _hex_bytes

    stripped = str(text or "").strip()
    if not stripped:
        return None
    for reader in (_read_pem, _read_json, _read_identifier):
        result = reader(stripped)
        if result is not None:
            return result
    result = _read_base64(stripped, hint)
    if result is not None:
        return result
    data = _hex_bytes(stripped)
    if not data:
        return None
    result = atr_reading(data) or tls_reading(data)
    if result is not None:
        result["inputHex"] = data.hex().upper()
        result["byteCount"] = len(data)
    return result
