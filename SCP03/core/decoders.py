# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""SCP03 response decoders: converts raw EF hex strings to structured Python dicts."""

import ipaddress
import json
from typing import Dict, Any, Iterable, List, Optional
from SCP03.core.utils import TlvParser
# ISO 7816-4 tables 17/18 as TS 102 221 §9.2.4 applies them. The SAIP decoder
# owns the two tables; a second hand-rolled copy here is how the live view and
# the profile view drifted apart.
from yggdrasim_common.uicc_access_rules import arr_access_mode_flags
from yggdrasim_common.gsm_alphabet import (
    ENCODING_GSM7_PACKED,
    ENCODING_UCS2_BE,
    decode_gsm7_packed as _decode_gsm7_packed,
    decode_gsm7_septets as _decode_gsm7_septets,
    decode_network_name_ie as _decode_network_name_ie_core,
)
from yggdrasim_common.service_table_names import (
    service_table_metadata,
    service_table_names,
)
from yggdrasim_common.uicc_access_rules import (
    STYLE_VERBOSE as _KEY_REFERENCE_STYLE,
    key_reference_name as _key_reference_name,
)

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend

    _CERT_BACKEND = default_backend()
except ImportError:
    x509 = None
    _CERT_BACKEND = None


# TS 102 221 v18.4 table 10.5 and TS 102 222 v17.1 table 1: the INS codes a
# command-header AM_DO (tags '81'-'8F', clause 9.2.2 / annex E.3.1) can name.
_ARR_COMMAND_INS_NAMES: Dict[int, str] = {
    0xA4: "SELECT FILE",
    0xF2: "STATUS",
    0xB0: "READ BINARY",
    0xD6: "UPDATE BINARY",
    0xB2: "READ RECORD",
    0xDC: "UPDATE RECORD",
    0xA2: "SEARCH RECORD",
    0x32: "INCREASE",
    0xCB: "RETRIEVE DATA",
    0xDB: "SET DATA",
    0x20: "VERIFY PIN",
    0x24: "CHANGE PIN",
    0x26: "DISABLE PIN",
    0x28: "ENABLE PIN",
    0x2C: "UNBLOCK PIN",
    0x04: "DEACTIVATE FILE",
    0x44: "ACTIVATE FILE",
    0x88: "AUTHENTICATE",
    0x89: "AUTHENTICATE",
    0x84: "GET CHALLENGE",
    0xAA: "TERMINAL CAPABILITY",
    0x10: "TERMINAL PROFILE",
    0xC2: "ENVELOPE",
    0x12: "FETCH",
    0x14: "TERMINAL RESPONSE",
    0x70: "MANAGE CHANNEL",
    0x73: "MANAGE SECURE CHANNEL",
    0x75: "TRANSACT DATA",
    0x76: "SUSPEND UICC",
    0xE0: "CREATE FILE",
    0xE4: "DELETE FILE",
    0xE6: "TERMINATE DF",
    0xE8: "TERMINATE EF",
    0xFE: "TERMINATE CARD USAGE",
    0xD4: "RESIZE FILE",
}

# TS 102 221 v18.4 table 9.4: usage qualifier bits of the CRT in an SC_DO.
_ARR_USAGE_QUALIFIER_BITS = (
    (0x80, "use verification / encipherment / external authentication"),
    (0x40, "use computation / decipherment / internal authentication"),
    (0x20, "use SM response"),
    (0x10, "use SM command"),
    (0x08, "use the PIN for verification"),
    (0x04, "use biometric user authentication"),
)

# GlobalPlatform SE Access Control v1.1 annex B table B-1. 'CA' and 'DB' are
# not GlobalPlatform tags; pySim's ara_m module carries them as PkgRefDO and
# PermArDO for device carrier-privilege rule sets.
_GP_SEAC_DO_NAMES: Dict[int, str] = {
    0x4F: "AID-REF-DO",
    0xC0: "AID-REF-DO (implicitly selected application)",
    0xC1: "DeviceAppID-REF-DO",
    0xD0: "APDU-AR-DO",
    0xD1: "NFC-AR-DO",
    0xDF20: "Response-Refresh-Tag-DO",
    0xDF21: "Response-ARAM-Config-DO",
    0xE1: "REF-DO",
    0xE2: "REF-AR-DO",
    0xE3: "AR-DO",
    0xE4: "Device-Config-DO",
    0xE5: "ARAM-Config-DO",
    0xE6: "Device-Interface-Version-DO",
    0xE7: "Block-DO",
    0xF0: "Command-Store-REF-AR-DO",
    0xF1: "Command-Delete",
    0xF2: "Command-Update-Refresh-Tag-DO",
    0xF3: "Command-Get",
    0xF4: "Command-Get-All",
    0xF5: "Command-Get-Next",
    0xF6: "Command-Get-Client-AIDs-DO",
    0xF7: "Command-Register-Client-AIDs-DO",
    0xF8: "Command-Get-Device-Config-DO",
    0xFF40: "Response-ALL-REF-AR-DO",
    0xFF50: "Response-AR-DO",
    0xFF70: "Response-ARAC-AID-DO",
    0xFF7F: "Response-Device-Config-DO",
    0xCA: "PKG-REF-DO (not a GlobalPlatform tag)",
    0xDB: "PERM-AR-DO (not a GlobalPlatform tag)",
}


def _arr_usage_qualifier_text(value: int) -> str:
    """Name the usage-qualifier bits per TS 102 221 v18.4 table 9.4."""
    if value == 0:
        return "verification requirement not used"
    names = [name for mask, name in _ARR_USAGE_QUALIFIER_BITS if value & mask]
    if value & 0x03:
        names.append("RFU bits set")
    return ", ".join(names)


def _arr_command_header_label(tag: int, value: bytes) -> str:
    """Describe a command-header AM_DO ('81'-'8F').

    TS 102 221 v18.4 clause 9.2.2 leaves the b4-b1 coding of the tag to
    ISO/IEC 7816-4; pySim's ``_AM_DO_CHDR`` reads them as CLA, INS, P1 and P2
    present flags, and the value holds those header bytes in that order.
    """
    fields = [
        name
        for bit, name in ((0x08, "CLA"), (0x04, "INS"), (0x02, "P1"), (0x01, "P2"))
        if tag & bit
    ]
    if len(value) != len(fields):
        raise ValueError(
            f"command-header DO {tag:02X} must contain {len(fields)} byte(s)"
        )
    header = dict(zip(fields, value))
    ins_name = None
    if "INS" in header:
        ins_name = _ARR_COMMAND_INS_NAMES.get(header["INS"])
    if fields == ["INS"]:
        description = value.hex().upper()
    else:
        description = " ".join(f"{name}={header[name]:02X}" for name in fields)
    if ins_name is not None:
        return f"{ins_name} (command header {description})"
    return f"Command header {description}"


def _decode_network_name_ie(value: bytes) -> Dict[str, Any]:
    """Decode a Network Name IE for the live decoded view.

    The shared reader (TS 24.008 v19.5 table 10.5.94) handles the coding
    scheme; this wrapper keeps the key names and the plain-ASCII fallback the
    live view has always emitted for a value whose extension bit is clear.
    """
    raw = bytes(value)
    if len(raw) == 0:
        return {"text": "", "encoding": "empty", "raw": ""}
    decoded = _decode_network_name_ie_core(raw)
    if decoded is None:
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError:
            text = ""
        if text and text.isprintable():
            return {
                "text": text,
                "encoding": "plain ASCII fallback",
                "raw": raw.hex().upper(),
            }
        return {
            "text": "",
            "encoding": "invalid Network Name IE (extension bit not set)",
            "raw": raw.hex().upper(),
        }
    output: Dict[str, Any] = {
        "text": decoded.text,
        "coding_scheme": decoded.coding_scheme,
        "add_country_initials": decoded.add_country_initials,
        "spare_bits": decoded.spare_bits,
        "raw": raw.hex().upper(),
    }
    if decoded.encoding == ENCODING_GSM7_PACKED:
        output["encoding"] = "GSM 7-bit packed"
    elif decoded.encoding == ENCODING_UCS2_BE:
        output["encoding"] = "UCS-2 big-endian"
    else:
        output["encoding"] = f"Reserved coding scheme ({decoded.coding_scheme})"
    if decoded.error is not None:
        if decoded.encoding == ENCODING_GSM7_PACKED:
            output["error"] = "Invalid GSM 7-bit payload or spare-bit count"
        elif decoded.error.startswith("invalid UCS-2"):
            output["error"] = "Invalid UCS-2 payload"
        else:
            output["error"] = "UCS-2 payload has an odd byte count"
    if decoded.note is not None:
        output["note"] = decoded.note
    return output


class AdvancedDecoders:
    @staticmethod
    def decode_ef_arr(data_hex: str, *, scope: str = "ef") -> list:
        """Decode EF.ARR access rule records from raw hex.

        A record is a sequence of AM_DO / SC_DO groups in the expanded format
        (TS 102 221 v18.4 clauses 9.2.6 and 9.2.7, annex E.3). An AM_DO is an
        AM byte (tag '80'), a command header (tags '81'-'8F') or a proprietary
        state machine (tag '9C'); the SC_DOs that follow are the conditions
        for those commands, with the CRT of table 9.3 naming the key
        reference and the usage qualifier of table 9.4.

        ``scope`` names the access-mode table the record is read with: an EF
        reads the low three bits as READ / UPDATE / APPEND, while MF, a DF and
        an ADF read them as DELETE FILE (child) / CREATE FILE (EF) / CREATE
        FILE (DF). The caller knows which, because the FCP that cites the
        record does; read without a referrer the EF table applies. With b8 set
        the AM byte's b7-b4 are proprietary (clause 9.2.5) and are not named.
        """
        if not data_hex:
            return ["Empty/Invalid Rule"]
        if data_hex.startswith("FF"):
            return ["Empty/Invalid Rule"]

        try:
            data = bytes.fromhex(data_hex)
        except Exception:
            return ["Hex Decode Error"]
        try:
            TlvParser.parse_padded(data)
        except ValueError as exc:
            return [f"ARR TLV Parse Error: {exc}"]

        def _items(raw: bytes):
            offset = 0
            while offset < len(raw):
                if all(octet == 0xFF for octet in raw[offset:]):
                    return
                tag_start = offset
                offset += 1
                if (raw[tag_start] & 0x1F) == 0x1F:
                    while raw[offset] & 0x80:
                        offset += 1
                    offset += 1
                tag = int.from_bytes(raw[tag_start:offset], "big")
                first_length = raw[offset]
                offset += 1
                if first_length < 0x80:
                    length = first_length
                else:
                    count = first_length & 0x7F
                    length = int.from_bytes(raw[offset : offset + count], "big")
                    offset += count
                value = raw[offset : offset + length]
                offset += length
                yield tag, value

        output = []
        current_am_str = ""

        def _auth_condition(value: bytes) -> str:
            sc_info = TlvParser.parse(value)
            key_ref = TlvParser.get_first(sc_info, 0x83)
            usage_qualifier = TlvParser.get_first(sc_info, 0x95)
            if usage_qualifier is not None and (
                not isinstance(usage_qualifier, bytes) or len(usage_qualifier) != 1
            ):
                raise ValueError(
                    "ARR authentication usage qualifier must contain one byte."
                )
            if isinstance(key_ref, bytes) and len(key_ref) == 1:
                ref_val = key_ref[0]
                suffix = ""
                if isinstance(usage_qualifier, bytes) and usage_qualifier != b"\x08":
                    suffix = (
                        f" [usage qualifier {usage_qualifier[0]:02X}: "
                        f"{_arr_usage_qualifier_text(usage_qualifier[0])}]"
                    )
                return (
                    _key_reference_name(ref_val, style=_KEY_REFERENCE_STYLE) + suffix
                )
            if key_ref is not None:
                raise ValueError(
                    "ARR authentication key reference must contain one byte."
                )
            return "Unknown authentication condition"

        def _security_condition(tag: int, value: bytes, depth: int = 0) -> str:
            if depth > TlvParser.DEFAULT_MAX_DEPTH:
                raise ValueError("ARR security-condition nesting is too deep.")
            if tag == 0x90:
                if value:
                    raise ValueError("ARR tag 90 must have zero length.")
                return "Always"
            if tag == 0x97:
                if value:
                    raise ValueError("ARR tag 97 must have zero length.")
                return "Never"
            if tag == 0xA4:
                return _auth_condition(value)
            operators = {0xA0: "OR", 0xA7: "NOT", 0xAF: "AND"}
            operator = operators.get(tag)
            if operator is not None:
                children = [
                    _security_condition(child_tag, child_value, depth + 1)
                    for child_tag, child_value in _items(value)
                ]
                if operator == "NOT" and len(children) != 1:
                    raise ValueError(
                        "ARR NOT condition must contain exactly one child."
                    )
                if operator in ("OR", "AND") and len(children) < 2:
                    raise ValueError(
                        f"ARR {operator} condition must contain at least two children."
                    )
                if operator == "NOT":
                    return f"NOT ({children[0]})"
                return f"{operator} ({', '.join(children)})"
            return f"SC-DO {tag:X} ({value.hex().upper()})"

        ignored_dos: List[str] = []
        for tag, value in _items(data):
            if tag == 0x80:
                if len(value) != 1:
                    return ["ARR Decode Error: access-mode DO must contain one byte"]
                am_byte = value[0]
                # Clause 9.2.5 / annex E.2.1: with b8 set, b7-b4 are proprietary
                # and no longer name DEACTIVATE / ACTIVATE / TERMINATE / DELETE.
                proprietary_high = bool(am_byte & 0x80)
                modes = [
                    name
                    for mask, name in arr_access_mode_flags(scope)
                    if am_byte & mask and (mask < 0x08 or not proprietary_high)
                ]
                if proprietary_high:
                    modes.append(f"Proprietary(0x{am_byte & 0xF8:02X})")
                current_am_str = (
                    "/".join(modes) if modes else f"Proprietary(0x{am_byte:02X})"
                )
                continue

            if 0x81 <= tag <= 0x8F:
                try:
                    current_am_str = _arr_command_header_label(tag, value)
                except ValueError as exc:
                    return [f"ARR Decode Error: {exc}"]
                continue

            if tag == 0x9C:
                # Annex E.3.1: proprietary state machine description.
                current_am_str = (
                    f"Proprietary state machine (AM_DO 9C {value.hex().upper()})"
                )
                continue

            if tag in (0x90, 0x97, 0xA4, 0xA0, 0xA7, 0xAF):
                if not current_am_str:
                    return [
                        f"ARR Decode Error: security condition {tag:X} "
                        "has no preceding access-mode DO"
                    ]
                try:
                    condition = _security_condition(tag, value)
                except ValueError as exc:
                    return [f"ARR Decode Error: {exc}"]
                output.append(f"{current_am_str}: {condition}")
                current_am_str = ""
                continue

            # Clause 9.2.4: a syntactically unknown AM/SC combination is
            # ignored by the terminal; report it rather than misattributing
            # the DOs around it.
            ignored_dos.append(f"{tag:02X} ({value.hex().upper()})")

        if current_am_str:
            output.append(
                f"ARR Decode Warning: {current_am_str} has no security condition"
            )
        for ignored in ignored_dos:
            output.append(f"ARR Decode Note: ignored unknown DO {ignored}")

        if len(output) > 0:
            return output
        return ["No Rules"]

    @staticmethod
    def decode_gp_seac_arf(data_hex: str) -> list:
        """Render a BER-TLV tree with the GlobalPlatform SE Access Control names.

        Tags are labelled per GP SEAC v1.1 annex B table B-1 (the ARA-M /
        ARA-C data objects). The PKCS#15 access rule files themselves (ACMF,
        ACRF, ACCF, GP SEAC v1.1 clause 7) are ASN.1 SEQUENCEs; their tags
        show as unnamed and ``decode_pkcs15_acrf`` / ``decode_pkcs15_accf``
        read those.
        """
        if not data_hex:
            return ["GP_SEAC: Empty/Invalid"]

        cleaned = data_hex.strip().upper()
        is_only_ff = True
        for c in cleaned:
            if c != "F":
                is_only_ff = False
                break
        if is_only_ff:
            return ["GP_SEAC: Empty/Invalid"]

        try:
            data = bytes.fromhex(cleaned)
        except Exception:
            return ["GP_SEAC: Hex Decode Error"]

        tag_names = _GP_SEAC_DO_NAMES

        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError as exc:
            return [f"GP_SEAC: TLV Parse Error: {exc}"]
        lines: List[str] = []

        def _tag_to_hex(tag: int) -> str:
            if tag <= 0xFF:
                return f"{tag:02X}"
            if tag <= 0xFFFF:
                return f"{tag:04X}"
            return f"{tag:X}"

        def _tag_label(tag: int) -> str:
            name = tag_names.get(tag)
            if name is not None:
                return name
            return "Unknown"

        def _short_hex(raw: bytes, max_chars: int = 96) -> str:
            hex_text = raw.hex().upper()
            is_short = False
            if len(hex_text) <= max_chars:
                is_short = True
            if is_short:
                return hex_text
            return hex_text[:max_chars] + "..."

        def _walk(node: Any, level: int) -> None:
            if isinstance(node, dict):
                for tag, val in node.items():
                    tag_hex = _tag_to_hex(tag)
                    label = _tag_label(tag)

                    is_dict = False
                    if isinstance(val, dict):
                        is_dict = True
                    if is_dict:
                        lines.append(f"{'  ' * level}{tag_hex} {label}")
                        _walk(val, level + 1)
                        continue

                    is_list = False
                    if isinstance(val, list):
                        is_list = True
                    if is_list:
                        lines.append(f"{'  ' * level}{tag_hex} {label} [{len(val)}]")
                        for item in val:
                            _walk({tag: item}, level + 1)
                        continue

                    is_bytes = False
                    if isinstance(val, bytes):
                        is_bytes = True
                    if is_bytes:
                        lines.append(
                            f"{'  ' * level}{tag_hex} {label}: {_short_hex(val)}"
                        )
                        continue

                    lines.append(f"{'  ' * level}{tag_hex} {label}: {val}")
                return

            is_list = False
            if isinstance(node, list):
                is_list = True
            if is_list:
                for item in node:
                    _walk(item, level)
                return

            lines.append(f"{'  ' * level}{node}")

        _walk(parsed, 0)
        if len(lines) == 0:
            return ["GP_SEAC: No TLV entries"]
        return lines

    @staticmethod
    def decode_ara_rulesets(data_hex: str) -> list:
        """
        Decode ARA-M / ARA-C GET DATA [All] payloads into compact ruleset lines.
        """
        if not data_hex:
            return ["ARA Rules: Empty/Invalid"]

        cleaned = data_hex.strip().upper()
        if len(cleaned) == 0:
            return ["ARA Rules: Empty/Invalid"]

        is_only_ff = True
        for char in cleaned:
            if char != "F":
                is_only_ff = False
                break
        if is_only_ff:
            return ["ARA Rules: Empty/Invalid"]

        try:
            raw = bytes.fromhex(cleaned)
        except Exception:
            return ["ARA Rules: Hex Decode Error"]

        try:
            # GP SE Access Control v1.1 tables 6-12 / 6-13 define 'E6' and
            # 'E7' as primitive data objects, so their b6 must not be read
            # as the X.690 §8.1.2.5 constructed bit.
            parsed = TlvParser.parse(
                raw, primitive_tags=TlvParser.GP_SE_ACCESS_CONTROL_PRIMITIVE_TAGS
            )
        except Exception:
            return ["ARA Rules: TLV Parse Error"]

        rule_nodes: List[Dict[int, Any]] = []

        def _as_dict(node: Any) -> Optional[Dict[int, Any]]:
            if isinstance(node, dict):
                return node
            if isinstance(node, bytes):
                try:
                    return TlvParser.parse(node)
                except Exception:
                    return None
            return None

        def _collect_rules(node: Any) -> None:
            if isinstance(node, dict):
                for tag, value in node.items():
                    if tag == 0xE2:
                        for item in TlvParser.as_list(value):
                            rule_dict = _as_dict(item)
                            if rule_dict is not None:
                                rule_nodes.append(rule_dict)
                        continue
                    _collect_rules(value)
                return
            if isinstance(node, list):
                for item in node:
                    _collect_rules(item)

        def _ascii_or_hex(value: Any) -> str:
            if not isinstance(value, bytes):
                return ""
            if len(value) == 0:
                return ""
            try:
                decoded = value.decode("ascii")
                return decoded if decoded.isprintable() else value.hex().upper()
            except Exception:
                return value.hex().upper()

        def _decode_apdu_rule(value: Any) -> str:
            if not isinstance(value, bytes):
                return ""
            if len(value) == 1:
                if value[0] == 0x00:
                    return "never"
                if value[0] == 0x01:
                    return "always"
                return value.hex().upper()
            if len(value) % 8 != 0:
                return value.hex().upper()
            filters = []
            offset = 0
            while offset < len(value):
                header = value[offset : offset + 4].hex().upper()
                mask = value[offset + 4 : offset + 8].hex().upper()
                filters.append(f"{header}/{mask}")
                offset += 8
            return "filter " + ", ".join(filters)

        def _decode_nfc_rule(value: Any) -> str:
            if not isinstance(value, bytes):
                return ""
            if len(value) != 1:
                return value.hex().upper()
            if value[0] == 0x00:
                return "never"
            if value[0] == 0x01:
                return "always"
            return value.hex().upper()

        _collect_rules(parsed)
        if len(rule_nodes) == 0:
            return ["ARA Rules: No rulesets returned"]

        output = []
        for idx, rule_node in enumerate(rule_nodes, start=1):
            ref_do = _as_dict(TlvParser.get_first(rule_node, 0xE1, {}))
            ar_do = _as_dict(TlvParser.get_first(rule_node, 0xE3, {}))
            if ref_do is None:
                ref_do = {}
            if ar_do is None:
                ar_do = {}

            parts = []

            # GP SEAC v1.1 table 6-3: an empty AID-REF-DO covers every applet
            # not named by a specific rule; 'C0' is the implicitly selected
            # application.
            aid_ref = TlvParser.get_first(ref_do, 0x4F)
            if isinstance(aid_ref, bytes) and len(aid_ref) > 0:
                parts.append(f"AID={aid_ref.hex().upper()}")
            elif 0x4F in ref_do:
                parts.append("AID=All (applets without a specific rule)")
            elif 0xC0 in ref_do:
                parts.append("AID=Implicit")

            # Table 6-4: 32 bytes is a SHA-256 hash, 20 bytes a SHA-1 hash
            # (deprecated) or an 'FF'-padded unique identifier; empty covers
            # every device application not named by a specific rule.
            dev_app_id = TlvParser.get_first(ref_do, 0xC1)
            if isinstance(dev_app_id, bytes) and len(dev_app_id) > 0:
                if len(dev_app_id) == 32:
                    id_kind = " (SHA-256)"
                elif len(dev_app_id) == 20:
                    id_kind = " (SHA-1 or unique identifier)"
                else:
                    id_kind = " (non-standard length)"
                parts.append(f"DeviceAppID={dev_app_id.hex().upper()}{id_kind}")
            elif 0xC1 in ref_do:
                parts.append("DeviceAppID=All (device applications without a specific rule)")

            pkg_ref = _ascii_or_hex(TlvParser.get_first(ref_do, 0xCA))
            if len(pkg_ref) > 0:
                parts.append(f"Package={pkg_ref}")

            apdu_rule = _decode_apdu_rule(TlvParser.get_first(ar_do, 0xD0))
            if len(apdu_rule) > 0:
                parts.append(f"APDU={apdu_rule}")

            nfc_rule = _decode_nfc_rule(TlvParser.get_first(ar_do, 0xD1))
            if len(nfc_rule) > 0:
                parts.append(f"NFC={nfc_rule}")

            perm_rule = TlvParser.get_first(ar_do, 0xDB)
            if isinstance(perm_rule, bytes) and len(perm_rule) > 0:
                parts.append(f"Permissions={perm_rule.hex().upper()}")

            if len(parts) == 0:
                parts.append("Empty")

            output.append(f"Ruleset {idx}: " + " | ".join(parts))

        return output

    @staticmethod
    def _pkcs15_path_text(path_node: Any) -> str:
        """Render a PKCS#15 ``Path`` (GP SEAC v1.1 clause 7.1.3).

        ``Path ::= SEQUENCE { path OCTET STRING, index INTEGER OPTIONAL,
        length [0] INTEGER OPTIONAL }``; index and length are present
        together or absent together.
        """
        if not isinstance(path_node, dict):
            return "N/A"
        path_oct = TlvParser.get_first(path_node, 0x04)
        if not isinstance(path_oct, bytes):
            return "N/A"
        text = path_oct.hex().upper() or "(empty)"
        index_oct = TlvParser.get_first(path_node, 0x02)
        length_oct = TlvParser.get_first(path_node, 0x80)
        if isinstance(index_oct, bytes) and index_oct:
            text += f" index={int.from_bytes(index_oct, 'big')}"
        if isinstance(length_oct, bytes) and length_oct:
            text += f" length={int.from_bytes(length_oct, 'big')}"
        return text

    @staticmethod
    def decode_pkcs15_acrf(data_hex: str) -> list:
        """Decode an Access Control Rules File (GP SEAC v1.1 clause 7.1.5).

        The file is a list of ``Rule ::= SEQUENCE { target Target,
        conditionsFile Path }`` with ``Target ::= CHOICE { aid [0] EXPLICIT
        AID, default [1] NULL, others [2] NULL }``, DER with implicit tags
        (clause 7.2), padded with 'FF' (clause 7.1.1).
        """
        if not data_hex:
            return ["PKCS15 ACRF: Empty/Invalid"]
        cleaned = data_hex.strip().upper()
        try:
            raw = bytes.fromhex(cleaned)
        except Exception:
            return ["PKCS15 ACRF: Hex Decode Error"]

        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return ["PKCS15 ACRF: Empty/Invalid"]

        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 ACRF: TLV Parse Error"]

        rules = [
            node
            for node in TlvParser.as_list(parsed.get(0x30))
            if isinstance(node, dict)
        ]
        if len(rules) == 0:
            return ["PKCS15 ACRF: No Rule Entries"]

        out: List[str] = []
        for idx, rule in enumerate(rules, start=1):
            target = "Target=Unknown"
            aid_choice = TlvParser.get_first(rule, 0xA0)
            if isinstance(aid_choice, dict):
                aid_oct = TlvParser.get_first(aid_choice, 0x04)
                if isinstance(aid_oct, bytes):
                    target = f"Target=AID {aid_oct.hex().upper() or '(empty)'}"
            elif 0x81 in rule:
                target = "Target=Default (implicitly selected applet)"
            elif 0x82 in rule:
                target = "Target=Others (applets without a specific rule)"
            accf_ref = AdvancedDecoders._pkcs15_path_text(
                TlvParser.get_first(rule, 0x30)
            )
            out.append(f"Rule {idx}: {target} | ACCF Ref={accf_ref}")

        return out

    @staticmethod
    def _pkcs15_permission_text(node: Any) -> Optional[str]:
        """Read an implicit ``[0] BOOLEAN`` permission (tag '80')."""
        flag = TlvParser.get_first(node, 0x80) if isinstance(node, dict) else None
        if not isinstance(flag, bytes) or len(flag) != 1:
            return None
        if flag[0] == 0x00:
            return "never"
        return "always"

    @staticmethod
    def decode_pkcs15_accf(data_hex: str) -> list:
        """Decode an Access Control Conditions File (GP SEAC v1.1 clause 7.1.6).

        Each ``Condition ::= SEQUENCE { deviceAppID OCTET STRING (SIZE(20|32))
        OPTIONAL, accessRules [0] SEQUENCE OF AccessRule OPTIONAL }``. An
        ``AccessRule`` is the CHOICE ``apduAccessRule [0]`` (``apduPermission
        [0] BOOLEAN`` or ``apduFilters [1] SEQUENCE OF OCTET STRING (SIZE(8))``)
        or ``nfcAccessRule [1]`` (``nfcPermission [0] BOOLEAN``). An empty file
        denies every device application; a condition without a DeviceAppID
        grants any device application. Missing rules follow table 7-4.
        """
        if not data_hex:
            return ["PKCS15 ACCF: Empty/Invalid"]
        cleaned = data_hex.strip().upper()
        try:
            raw = bytes.fromhex(cleaned)
        except Exception:
            return ["PKCS15 ACCF: Hex Decode Error"]

        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return ["PKCS15 ACCF: Empty (rules citing this file deny every device application)"]

        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 ACCF: TLV Parse Error"]

        conditions = [
            node
            for node in TlvParser.as_list(parsed.get(0x30))
            if isinstance(node, dict)
        ]
        if len(conditions) == 0:
            return ["PKCS15 ACCF: No Condition Entries"]

        out: List[str] = []
        for idx, condition in enumerate(conditions, start=1):
            parts: List[str] = []
            device_app_id = TlvParser.get_first(condition, 0x04)
            if isinstance(device_app_id, bytes) and len(device_app_id) > 0:
                if len(device_app_id) == 32:
                    id_kind = "SHA-256"
                elif len(device_app_id) == 20:
                    id_kind = "SHA-1 or unique identifier"
                else:
                    id_kind = "non-standard length"
                parts.append(f"DeviceAppID={device_app_id.hex().upper()} ({id_kind})")
            else:
                parts.append("DeviceAppID=Any device application")

            access_rules = TlvParser.get_first(condition, 0xA0)
            apdu_text: Optional[str] = None
            nfc_text: Optional[str] = None
            if isinstance(access_rules, dict):
                apdu_rule = TlvParser.get_first(access_rules, 0xA0)
                if isinstance(apdu_rule, dict):
                    apdu_text = AdvancedDecoders._pkcs15_permission_text(apdu_rule)
                    filters = TlvParser.get_first(apdu_rule, 0xA1)
                    if apdu_text is None and isinstance(filters, dict):
                        entries = [
                            f"{item[:4].hex().upper()}/{item[4:].hex().upper()}"
                            for item in TlvParser.as_list(filters.get(0x04))
                            if isinstance(item, bytes) and len(item) == 8
                        ]
                        apdu_text = "filter " + ", ".join(entries) if entries else "filter (none)"
                nfc_rule = TlvParser.get_first(access_rules, 0xA1)
                if isinstance(nfc_rule, dict):
                    nfc_text = AdvancedDecoders._pkcs15_permission_text(nfc_rule)

            rules_present = isinstance(access_rules, dict) and len(access_rules) > 0
            if apdu_text is None:
                if rules_present:
                    # Table 7-4 row 2 (v1.1): only an NFC rule present.
                    apdu_text = "never (default, no APDU rule)"
                else:
                    apdu_text = "always (default, no access rules)"
            if nfc_text is None:
                if rules_present and apdu_text.startswith("never"):
                    nfc_text = "never (default, APDU never)"
                else:
                    nfc_text = "always (default)"
            parts.append(f"APDU={apdu_text}")
            parts.append(f"NFC={nfc_text}")
            out.append(f"Condition {idx}: " + " | ".join(parts))
        return out

    @staticmethod
    def decode_cert_der(data: bytes) -> Optional[Dict[str, Any]]:
        """Parse DER-encoded X.509 certificate; return subject, issuer, validity or None."""
        if not data or len(data) < 4:
            return None
        if data[0] != 0x30:
            return None
        if x509 is None or _CERT_BACKEND is None:
            return {
                "raw_len": len(data),
                "note": "cryptography not available for full decode",
            }
        try:
            cert = x509.load_der_x509_certificate(data, _CERT_BACKEND)
            nb = getattr(cert, "not_valid_before_utc", None) or getattr(
                cert, "not_valid_before", None
            )
            na = getattr(cert, "not_valid_after_utc", None) or getattr(
                cert, "not_valid_after", None
            )
            return {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "not_valid_before": nb.isoformat() if nb else "",
                "not_valid_after": na.isoformat() if na else "",
                "serial": hex(cert.serial_number),
            }
        except Exception:
            return None

    @staticmethod
    def print_cplc(data: bytes) -> None:
        """Print a GET DATA '9F7F' response.

        The Card Production Life Cycle field layout is not part of the
        GlobalPlatform Card Specification held in the library, so only the
        tag, the length and the raw value are shown.
        """
        raw = bytes(data or b"")
        value = raw
        if raw[:2] == b"\x9f\x7f":
            try:
                parsed = TlvParser.parse(raw)
            except ValueError:
                parsed = {}
            candidate = TlvParser.get_first(parsed, 0x9F7F)
            if isinstance(candidate, bytes):
                value = candidate
        print("--- CPLC (GET DATA 9F7F) ---")
        print(f"    [Length]   {len(value)} bytes")
        print(f"    [Raw]      {value.hex().upper() or '(empty)'}")

    @staticmethod
    def decode_plmn_list(data_hex: str, record_size: int = 3) -> list:
        """Decode a PLMN list EF to a list of PLMN dicts (3GPP TS 31.102 §4.2.5).

        Each entry carries mcc, mnc, and optional Access Technology bitmask.
        """
        if not data_hex:
            return ["Empty List"]

        is_empty = True
        for c in data_hex:
            if c != "F":
                is_empty = False
        if is_empty:
            return ["Empty List"]

        try:
            data = bytes.fromhex(data_hex)
        except Exception:
            return ["PLMN Decode Error"]

        if record_size not in (3, 5):
            return ["PLMN Decode Error: record size must be 3 or 5 bytes"]
        if len(data) % record_size != 0:
            return [
                f"PLMN Decode Error: {len(data)} bytes is not a multiple "
                f"of the {record_size}-byte record size"
            ]

        entries = []
        for i in range(0, len(data), record_size):
            plmn_bytes = data[i : i + 3]
            if plmn_bytes == b"\xff\xff\xff":
                continue

            b1 = plmn_bytes[0]
            b2 = plmn_bytes[1]
            b3 = plmn_bytes[2]

            # TS 24.008 v19.5 table 10.5.3: MCC digits and MNC digits 1-2 are
            # BCD, MNC digit 3 is BCD or 'F' for a two-digit MNC. Anything
            # else is an abnormal entry; keep the raw octets and decode the
            # remaining records rather than hide the whole list.
            mcc_digits = (b1 & 0x0F, b1 >> 4, b2 & 0x0F)
            mnc3 = b2 >> 4
            mnc_digits = (b3 & 0x0F, b3 >> 4)
            if any(digit > 9 for digit in mcc_digits + mnc_digits):
                entries.append(
                    f"PLMN Decode Error: invalid BCD digit in record "
                    f"{i // record_size + 1} (raw {plmn_bytes.hex().upper()})"
                )
                continue
            if mnc3 > 9 and mnc3 != 0x0F:
                entries.append(
                    f"PLMN Decode Error: invalid MNC digit in record "
                    f"{i // record_size + 1} (raw {plmn_bytes.hex().upper()})"
                )
                continue

            mcc = "".join(str(digit) for digit in mcc_digits)
            mnc = "".join(str(digit) for digit in mnc_digits)
            if mnc3 != 0x0F:
                mnc = f"{mnc3}{mnc}"

            entry_str = f"MCC: {mcc}, MNC: {mnc}"

            if record_size == 5:
                act_bytes = int.from_bytes(data[i + 3 : i + 5], "big")
                acts = []
                if act_bytes & 0x8000:
                    acts.append("UTRAN")
                eutran_bits = act_bytes & 0x7000
                if eutran_bits in (0x4000, 0x7000):
                    acts.extend(["E-UTRAN WB-S1", "E-UTRAN NB-S1"])
                elif eutran_bits == 0x5000:
                    acts.append("E-UTRAN NB-S1")
                elif eutran_bits == 0x6000:
                    acts.append("E-UTRAN WB-S1")
                gsm_bits = act_bytes & 0x008C
                if gsm_bits in (0x0080, 0x008C):
                    acts.extend(["GSM", "EC-GSM-IoT"])
                elif gsm_bits == 0x0084:
                    acts.append("GSM")
                elif gsm_bits == 0x0088:
                    acts.append("EC-GSM-IoT")
                if act_bytes & 0x0040:
                    acts.append("GSM COMPACT")
                if act_bytes & 0x0020:
                    acts.append("cdma2000 HRPD")
                if act_bytes & 0x0010:
                    acts.append("cdma2000 1xRTT")
                if act_bytes & 0x0800:
                    acts.append("NG-RAN")
                if act_bytes & 0x0400:
                    acts.append("Satellite NG-RAN")
                if act_bytes & 0x0200:
                    acts.append("Satellite E-UTRAN WB-S1")
                if act_bytes & 0x0100:
                    acts.append("Satellite E-UTRAN NB-S1")

                if len(acts) > 0:
                    entry_str += f" | AcT: {', '.join(acts)}"
                if len(acts) == 0:
                    entry_str += " | AcT: None"

            entries.append(entry_str)

        if len(entries) > 0:
            return entries
        return ["No Valid Entries"]

    @staticmethod
    def decode_loci(data_hex: str) -> dict:
        """Decode EF.LOCI: Location Information (3GPP TS 31.102 §4.2.17).

        Returns TMSI, LAI components, update-status, and raw hex fallback.
        """
        try:
            data = bytes.fromhex(data_hex)
        except Exception:
            return {"Error": "LOCI Decode Error"}

        if len(data) != 11:
            return {"Error": f"Invalid LOCI Length ({len(data)})"}

        try:
            tmsi_raw = data[0:4]
            plmn_raw = data[4:7]
            plmn = "Not assigned"
            if plmn_raw != b"\xff\xff\xff":
                plmn = ContentDecoder._decode_plmn_bytes(plmn_raw)
                if plmn.startswith("Invalid"):
                    return {"Error": "LOCI contains an invalid PLMN BCD digit"}

            lac = int.from_bytes(data[7:9], "big")
            status_byte = data[10]
            status_value = status_byte & 0x07
            status_map = {
                0: "Updated",
                1: "Not Updated",
                2: "PLMN Not Allowed",
                3: "Location Area Not Allowed",
            }
            output = {
                "TMSI": tmsi_raw.hex().upper(),
                "TMSI Assigned": tmsi_raw != b"\xff\xff\xff\xff",
                "LAI": plmn,
                "LAC": lac,
                # TS 24.008 v19.5 table 10.5.3: 'FFFE' marks a deleted LAI and
                # '0000' on an inserted SIM/USIM is treated the same way.
                "LAC Deleted": lac in (0xFFFE, 0x0000),
                "RFU Byte": f"{data[9]:02X}",
                "Status": status_map.get(
                    status_value,
                    f"Reserved ({status_value})",
                ),
                "Status Byte": f"{status_byte:02X}",
            }
            warnings = []
            if data[9] != 0xFF:
                warnings.append("LOCI RFU byte is not FF")
            if status_byte & 0xF8:
                warnings.append("LOCI update-status RFU bits 4..8 are non-zero")
            if warnings:
                output["Warnings"] = warnings
            return output
        except Exception:
            return {"Error": "LOCI Decode Error"}

    @staticmethod
    def decode_psloci(data_hex: str) -> dict:
        """Decode the 14-byte EF.PSLOCI layout (3GPP TS 31.102 §4.2.23)."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return {"Error": "PSLOCI Hex Decode Error"}
        if len(data) != 14:
            return {"Error": f"Invalid PSLOCI Length ({len(data)}; expected 14)"}
        plmn_raw = data[7:10]
        plmn = "Not assigned"
        if plmn_raw != b"\xff\xff\xff":
            plmn = ContentDecoder._decode_plmn_bytes(plmn_raw)
            if plmn.startswith("Invalid"):
                return {"Error": plmn}
        status_byte = data[13]
        status_value = status_byte & 0x07
        status = {
            0: "Updated",
            1: "Not Updated",
            2: "PLMN Not Allowed",
            3: "Routing Area Not Allowed",
        }.get(status_value, f"Reserved ({status_value})")
        output = {
            "P-TMSI": data[0:4].hex().upper(),
            "P-TMSI Assigned": data[0:4] != b"\xff\xff\xff\xff",
            "P-TMSI Signature": data[4:7].hex().upper(),
            "RAI": {
                "PLMN": plmn,
                "LAC": f"{int.from_bytes(data[10:12], 'big'):04X}",
                "RAC": f"{data[12]:02X}",
            },
            "Status": status,
            "Status Byte": f"{status_byte:02X}",
        }
        if status_byte & 0xF8:
            output["Warning"] = "PSLOCI update-status RFU bits 4..8 are non-zero"
        return output

    @staticmethod
    def decode_epsloci(data_hex: str) -> dict:
        """Decode the 18-byte EF.EPSLOCI layout (3GPP TS 31.102 §4.2.91)."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return {"Error": "EPSLOCI Hex Decode Error"}
        if len(data) != 18:
            return {"Error": f"Invalid EPSLOCI Length ({len(data)}; expected 18)"}

        guti_raw = data[:12]
        guti_assigned = not all(octet == 0xFF for octet in guti_raw)
        guti_plmn = "Not assigned"
        if guti_assigned:
            if data[0] != 0x0B:
                return {
                    "Error": (
                        f"EPSLOCI GUTI length octet is {data[0]:02X}; expected 0B"
                    )
                }
            if data[1] != 0xF6:
                return {
                    "Error": (
                        f"EPSLOCI GUTI identity header is {data[1]:02X}; expected F6"
                    )
                }
            guti_plmn = ContentDecoder._decode_plmn_bytes(data[2:5])
            if guti_plmn.startswith("Invalid"):
                return {"Error": "EPSLOCI GUTI contains an invalid PLMN BCD digit"}

        tai_plmn = "Not assigned"
        if data[12:15] != b"\xff\xff\xff":
            tai_plmn = ContentDecoder._decode_plmn_bytes(data[12:15])
            if tai_plmn.startswith("Invalid"):
                return {"Error": "EPSLOCI TAI contains an invalid PLMN BCD digit"}

        status_value = data[17] & 0x07
        status = {
            0: "Updated",
            1: "Not Updated",
            2: "Roaming Not Allowed",
        }.get(status_value, f"Reserved ({status_value})")
        output = {
            "GUTI": {
                "Assigned": guti_assigned,
                "Length Octet": f"{data[0]:02X}",
                "Identity Header": f"{data[1]:02X}",
                "PLMN": guti_plmn,
                "MME Group ID": data[5:7].hex().upper(),
                "MME Code": f"{data[7]:02X}",
                "M-TMSI": data[8:12].hex().upper(),
            },
            "Last Visited TAI": {
                "PLMN": tai_plmn,
                "TAC": data[15:17].hex().upper(),
            },
            "Status": status,
            "Status Byte": f"{data[17]:02X}",
        }
        if data[17] & 0xF8:
            output["Warning"] = "EPS update-status RFU bits 4..8 are non-zero"
        return output

    @staticmethod
    def decode_ust(data_hex: str) -> dict:
        """Decode EF.UST: USIM Service Table bitfield (3GPP TS 31.102 v19.5 §4.2.8).

        Splits bits into active and not-set service lists over every byte the
        file carries, naming services n°1 to n°152 as the v19.5 table lists
        them, so the GUI can render a complete checklist.
        """
        # 3GPP TS 31.102 §4.2.8 -- USIM Service Table. Each bit is a
        # service flag; the file body is the bitmap. Operators asked to
        # see *not-set* services too so the GUI can render a checklist
        # style view (active vs. available-but-disabled) rather than
        # only reporting the active subset.
        if not data_hex:
            return {"error": "Empty", "active": [], "inactive": []}

        try:
            data = bytes.fromhex(data_hex)
        except Exception:
            return {"error": "UST Decode Error", "active": [], "inactive": []}

        try:
            # Keep the assigned service number intact: these bits decide
            # whether a dependent EF is valid, so an off-by-one label is
            # operationally misleading.
            return AdvancedDecoders._build_service_table(data, table="UST")
        except Exception:
            return {"error": "UST Decode Error", "active": [], "inactive": []}

    @staticmethod
    def decode_est(data_hex: str) -> dict:
        """Decode EF.EST: Enabled Services Table (3GPP TS 31.102 §4.2.47)."""
        try:
            data = bytes.fromhex(data_hex)
        except ValueError:
            return {
                "service_table": True,
                "table": "EST",
                "error": "EST Decode Error",
                "active": [],
                "inactive": [],
            }
        if not data:
            return {
                "service_table": True,
                "table": "EST",
                "error": "Empty",
                "active": [],
                "inactive": [],
            }
        result = AdvancedDecoders._build_service_table(data, table="EST")
        if any(data[1:]) or data[0] & 0xF8:
            result["Warning"] = "EF.EST has non-zero unassigned service bits"
        return result

    # ---- Service-table encoder (mock-update / staging) ----------------
    #
    # Operators asked for a way to *preview* what a UST / IST / generic
    # service-table EF body would look like after toggling individual
    # service flags, without having to push the new bytes to the card.
    # Pure local math: given a list of active service numbers and the
    # original byte length, build the matching bitmap so the GUI can
    # surface the resulting hex string for copy / inspection / feeding
    # into UPDATE BINARY.
    @staticmethod
    def encode_service_table(
        active_bits: Iterable[int],
        *,
        total_bytes: Optional[int] = None,
        current_hex: Optional[str] = None,
        table: Optional[str] = None,
    ) -> str:
        """Re-encode a service-table bitfield from an iterable of active bit positions.

        Uses *current_hex* to preserve the existing byte width when possible;
        falls back to *total_bytes* or the minimum width that covers all set bits.
        Naming a *table* ("UST", "IST", ...) reads that table's clause range
        from the shared name map: a service number the clause does not name is
        refused, and an auto-sized body covers the whole range rather than
        stopping at the highest set bit.
        """
        # Resolve the EF body length. ``total_bytes`` wins; otherwise
        # we infer it from the current hex (so callers staging an edit
        # on an existing EF can omit it). When neither is present we
        # auto-size to fit the highest set bit, which is the right
        # default for a fresh from-scratch encode.
        if total_bytes is not None:
            if isinstance(total_bytes, bool) or not isinstance(total_bytes, int):
                raise TypeError("total_bytes must be an integer.")
            if not 1 <= total_bytes <= 0xFFFF:
                raise ValueError("total_bytes must be in range 1..65535.")
        if total_bytes is None and current_hex is not None:
            cleaned = str(current_hex or "").replace(" ", "").replace(":", "")
            try:
                current_bytes = bytes.fromhex(cleaned)
            except ValueError as exc:
                raise ValueError(
                    f"current_hex is not valid hexadecimal: {exc}"
                ) from exc
            if len(current_bytes) == 0:
                raise ValueError("current_hex must contain at least one byte.")
            total_bytes = len(current_bytes)
        if isinstance(active_bits, (str, bytes, bytearray, memoryview)):
            raise TypeError(
                "active_bits must be an iterable of integer service numbers."
            )
        named_services: Dict[int, str] = {}
        if table is not None:
            named_services = service_table_names(table)
            if not named_services:
                raise ValueError(f"Unknown service table: {table!r}")
        normalized_bits = set()
        for raw_number in active_bits:
            if isinstance(raw_number, bool) or not isinstance(raw_number, int):
                raise TypeError("Service numbers must be positive integers.")
            service_number = raw_number
            if service_number < 1:
                raise ValueError("Service numbers must be at least 1.")
            if service_number > 0xFFFF * 8:
                raise ValueError("Service number exceeds the maximum EF size.")
            if named_services and service_number not in named_services:
                # Staging against a named table: setting a bit the clause does
                # not define would produce a body no terminal can read back.
                raise ValueError(
                    f"Service {service_number} is not defined in the "
                    f"{str(table).upper()} table."
                )
            normalized_bits.add(service_number)
        bits = sorted(normalized_bits)
        if total_bytes is None:
            if named_services:
                # A named table sizes to its whole clause range, so a
                # from-scratch encode leaves room for every service.
                highest = max(named_services)
            else:
                highest = bits[-1] if len(bits) > 0 else 1
            total_bytes = max(1, (highest + 7) // 8)
        buf = bytearray(int(total_bytes))
        for service_num in bits:
            byte_idx = (service_num - 1) // 8
            bit_idx = (service_num - 1) % 8
            if byte_idx >= len(buf):
                # Caller wants to set a service beyond the current
                # body -- extend the buffer rather than silently dropping
                # the bit. Cards reject oversized payloads at UPDATE
                # time, but for staging we want the operator to *see*
                # the resulting size before submitting.
                buf.extend(b"\x00" * (byte_idx + 1 - len(buf)))
            buf[byte_idx] |= 1 << bit_idx
        return buf.hex().upper()

    @staticmethod
    def _build_service_table(
        data: bytes,
        *,
        table: Optional[str] = None,
        name_map: Optional[Dict[int, str]] = None,
        table_name: str = "Service Table",
        full_name: Optional[str] = None,
        spec: Optional[str] = None,
    ) -> Dict[str, Any]:
        # Shared shape for UST / IST / EST / SST-style bitmap files.
        # Returns ``active`` and ``inactive`` lists in the same
        # ``"<n>: <name>"`` shape so the GUI can render both columns
        # with a single renderer. ``service_table`` is a sentinel the
        # frontend keys off to switch to the checklist layout.
        spec_names: Dict[int, str] = {}
        if table is not None:
            # One shared table per clause; the short operator labels stay the
            # displayed name and the clause wording rides along beside it.
            name_map = service_table_names(table)
            spec_names = service_table_names(table, style="spec")
            table_name = table
            metadata = service_table_metadata(table)
            if metadata is not None:
                full_name, spec = metadata
        active = []
        inactive = []
        active_spec_names = []
        total_bits = len(data) * 8
        for byte_idx, byte_val in enumerate(data):
            for bit_idx in range(8):
                service_num = (byte_idx * 8) + bit_idx + 1
                if name_map is not None:
                    name = name_map.get(service_num)
                    if name is None:
                        # Fall through to a generic placeholder so the
                        # operator still sees that bit X exists (helps
                        # diagnose oversized service tables on lab cards).
                        label = f"{service_num}: Service {service_num}"
                    else:
                        label = f"{service_num}: {name}"
                else:
                    label = f"{service_num}"
                is_set = bool(byte_val & (1 << bit_idx))
                if is_set:
                    active.append(label)
                    spec_name = spec_names.get(service_num)
                    if spec_name is not None:
                        active_spec_names.append(f"{service_num}: {spec_name}")
                else:
                    inactive.append(label)

        result: Dict[str, Any] = {
            "service_table": True,
            "table": table_name,
            "active_count": len(active),
            "inactive_count": len(inactive),
            "total_count": total_bits,
            "summary": f"{len(active)} of {total_bits} active",
            "active": active,
            "inactive": inactive,
            "raw": data.hex().upper(),
        }
        if full_name is not None:
            result["full_name"] = full_name
        if spec is not None:
            result["spec"] = spec
        if active_spec_names:
            # The clause wording for the services that are set, so an operator
            # reading a short label can check it against the specification.
            result["active_spec_names"] = active_spec_names
        return result


class ContentDecoder:
    _registry = {}

    @classmethod
    def init_registry(cls):
        """Populate the FID-to-decoder dispatch table on first access.

        Maps every supported elementary-file FID (string, upper-case) to the
        corresponding static decoder method on this class.
        """
        cls._registry = {
            "2FE2": cls.decode_iccid,
            "2F00": cls.decode_dir,
            "2F06": AdvancedDecoders.decode_ef_arr,
            "6F06": AdvancedDecoders.decode_ef_arr,
            "2F08": cls.decode_hex_chunks,
            "4300": cls.decode_pkcs15_acrf_json,
            "4310": cls.decode_pkcs15_accf_json,
            "4200": cls.decode_pkcs15_acm,
            "5031": cls.decode_pkcs15_odf,
            "5207": cls.decode_pkcs15_dodf,
            "2F05": cls.decode_language_indicators,
            "6F07": cls.decode_imsi,
            "6FAD": cls.decode_ad,
            "6F08": cls.decode_keys,
            "6F78": cls.decode_acc,
            "6F31": cls.decode_hpplmn,
            "6F38": AdvancedDecoders.decode_ust,
            "6F40": cls.decode_msisdn,
            "6F46": cls.decode_spn,
            "6F7B": AdvancedDecoders.decode_plmn_list,
            "6F60": lambda x: AdvancedDecoders.decode_plmn_list(x, record_size=5),
            "6F61": lambda x: AdvancedDecoders.decode_plmn_list(x, record_size=5),
            "6F62": lambda x: AdvancedDecoders.decode_plmn_list(x, record_size=5),
            "6FD9": AdvancedDecoders.decode_plmn_list,
            "6F7E": AdvancedDecoders.decode_loci,
            "6F73": AdvancedDecoders.decode_psloci,
            "6FE3": AdvancedDecoders.decode_epsloci,
            "6F42": cls.decode_sms_params,
            "6F3C": cls.decode_sms_record,
            "6F5B": lambda x: {"START-HFN": x},
            "6F5C": lambda x: {"Threshold": x},
            "6F05": cls.decode_language_indicators,
            "6F09": cls.decode_keys,
            "6F37": lambda x: {"ACM Max": x},
            "6F39": lambda x: {"ACM": x},
            "6F3E": lambda x: {"GID1": x},
            "6F3F": lambda x: {"GID2": x},
            "6F56": AdvancedDecoders.decode_est,
            "6F41": cls.decode_puct,
            "6FB7": cls.decode_ecc,
            "6F3A": cls.decode_adn_like_record,
            "6F3B": cls.decode_adn_like_record,
            "6F3D": cls.decode_ccp,
            "6F44": cls.decode_adn_like_record,
            "6F49": cls.decode_adn_like_record,
            # TS 31.102 v19.5 §4.2.44: EF.BDN carries the EF.ADN layout plus a
            # Comparison Method Pointer, so it is not an ADN-like record.
            "6F4D": cls.decode_bdn_record,
            "6F4F": cls.decode_ccp,
            "6FC7": cls.decode_adn_like_record,
            "6F43": cls.decode_smss,
            "6F47": cls.decode_smsr,
            "6FC5": cls.decode_pnn,
            "6FC6": cls.decode_opl,
            "6FCD": cls.decode_spdi,
            "6FE4": cls.decode_epsnsc,
            # TS 31.102 v19.5 §4.5.9: EF.PSISMSC holds a tag-80 URI object,
            # not a service-table bitmap.
            "6FE5": cls.decode_psismsc,
            "6FDA": cls.decode_gbanl,
            # TS 31.102 v19.5 §4.2.79: EF_GBABP sits at '6FD6' under ADF_USIM
            # (the ISIM copy is '6FD5', registered under the ISIM context).
            "6FD6": cls.decode_gbabp,
            "6FDD": cls.decode_nafkca,
            "6F45": cls.decode_cbmi_list,
            "6F48": cls.decode_cbmi_list,
            "6F50": cls.decode_cbmid_range_list,
            "6FEC": cls.decode_hex_chunks,
            "6FDE": cls.decode_utf8_or_hex,
            "6FDF": cls.decode_utf8_or_hex,
            "6FE2": cls.decode_utf8_or_hex,
            "6FE6": cls.decode_tlv_as_map,
            "6FE7": cls.decode_tlv_as_map,
            "6FE8": cls.decode_tlv_as_map,
            "6FED": cls.decode_utf8_or_hex,
            "6FEE": cls.decode_utf8_or_hex,
            "6FEF": cls.decode_utf8_or_hex,
            # TS 31.102 v19.5 §4.2.100 to §4.2.103: the three USAT Application
            # Pairing files and the Home ePDG Identifier, none of them text.
            "6FF0": cls.decode_ial,
            "6FF1": cls.decode_ips,
            "6FF2": cls.decode_ipd,
            "6FF3": cls.decode_epdgid,
            "6FF4": cls.decode_tlv_as_map,
            "6FF5": cls.decode_utf8_or_hex,
            "6FF6": cls.decode_tlv_as_map,
            "6FF7": cls.decode_utf8_or_hex,
            "6FF8": cls.decode_tlv_as_map,
            "6FF9": cls.decode_service_table_bits,
            "6FFA": cls.decode_tlv_as_map,
            "6FFC": cls.decode_tlv_as_map,
            "6FFD": cls.decode_hex_chunks,
            "6FFE": cls.decode_tlv_as_map,
        }

        cls._register_context_decoders()

    @classmethod
    def _register_context_decoders(cls):

        cls._registry["TELECOM/6F3A"] = cls.decode_adn_like_record
        cls._registry["TELECOM/6F3B"] = cls.decode_adn_like_record
        cls._registry["TELECOM/6F3C"] = cls.decode_sms_record
        # TS 51.011 v4.15 §10.5.4.1: '6F3D' is EF.CCP, a bearer-capability
        # record, not a dialling-number record.
        cls._registry["TELECOM/6F3D"] = cls.decode_ccp
        cls._registry["TELECOM/6F40"] = cls.decode_msisdn
        cls._registry["TELECOM/6F42"] = cls.decode_sms_params
        cls._registry["TELECOM/6F43"] = cls.decode_smss
        cls._registry["TELECOM/6F44"] = cls.decode_adn_like_record
        cls._registry["TELECOM/6F47"] = cls.decode_smsr
        cls._registry["TELECOM/6F49"] = cls.decode_adn_like_record
        cls._registry["TELECOM/6F4A"] = cls.decode_hex_chunks
        cls._registry["TELECOM/6F4B"] = cls.decode_hex_chunks
        cls._registry["TELECOM/6F4C"] = cls.decode_hex_chunks
        cls._registry["TELECOM/6F4E"] = cls.decode_hex_chunks
        cls._registry["TELECOM/6F4F"] = cls.decode_ccp

        # The legacy SIM EF.ECC under DF.GSM is transparent and consists of
        # consecutive three-byte codes. The USIM EF with the same FID is
        # linear-fixed and each record also carries alpha/category fields.
        cls._registry["GSM/6FB7"] = cls.decode_ecc_legacy
        # TS 51.011 v4.15 §10.3.1: EF.LP under DF.GSM holds one-byte CBS
        # language codes, unlike the two-byte EF.LI at the same FID under
        # ADF.USIM.
        cls._registry["GSM/6F05"] = cls.decode_lp_language_codes

        cls._registry["PHONEBOOK/4F22"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F23"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F24"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F30"] = cls.decode_tlv_as_map
        cls._registry["PHONEBOOK/4F38"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F40"] = cls.decode_utf8_or_hex
        cls._registry["PHONEBOOK/4F48"] = cls.decode_utf8_or_hex
        cls._registry["PHONEBOOK/4F50"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F58"] = cls.decode_adn_like_record
        cls._registry["PHONEBOOK/4F60"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F68"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F70"] = cls.decode_utf8_or_hex
        cls._registry["PHONEBOOK/4F78"] = cls.decode_utf8_or_hex
        cls._registry["PHONEBOOK/4F80"] = cls.decode_utf8_or_hex
        cls._registry["PHONEBOOK/4F88"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F90"] = cls.decode_hex_chunks
        cls._registry["PHONEBOOK/4F98"] = cls.decode_hex_chunks

        cls._registry["GRAPHICS/4F20"] = cls.decode_hex_chunks
        cls._registry["GRAPHICS/4F21"] = cls.decode_hex_chunks
        cls._registry["GRAPHICS/4F40"] = cls.decode_hex_chunks
        cls._registry["MULTIMEDIA/4F47"] = cls.decode_hex_chunks
        cls._registry["MULTIMEDIA/4F48"] = cls.decode_hex_chunks
        cls._registry["MMSS/4F20"] = cls.decode_hex_chunks
        cls._registry["MMSS/4F21"] = cls.decode_hex_chunks
        cls._registry["MMSS/4F22"] = cls.decode_hex_chunks

        cls._registry["MCS/4F01"] = cls.decode_service_table_bits
        cls._registry["MCS/4F02"] = cls.decode_tlv_as_map
        cls._registry["V2X/4F01"] = cls.decode_service_table_bits
        cls._registry["V2X/4F02"] = cls.decode_tlv_as_map
        cls._registry["V2X/4F03"] = cls.decode_tlv_as_map
        cls._registry["V2X/4F04"] = cls.decode_tlv_as_map
        cls._registry["A2X/4F01"] = cls.decode_service_table_bits
        cls._registry["A2X/4F02"] = cls.decode_tlv_as_map
        cls._registry["A2X/4F03"] = cls.decode_tlv_as_map
        cls._registry["A2X/4F04"] = cls.decode_tlv_as_map
        cls._registry["A2X/4F05"] = cls.decode_tlv_as_map
        cls._registry["A2X/4F06"] = cls.decode_tlv_as_map

        cls._registry["EAP/4F01"] = cls.decode_hex_chunks
        cls._registry["EAP/4F02"] = cls.decode_hex_chunks
        cls._registry["EAP/4F04"] = cls.decode_tlv_as_map
        cls._registry["EAP/4F20"] = cls.decode_hex_chunks
        cls._registry["EAP/4F21"] = cls.decode_hex_chunks
        cls._registry["EAP/4F22"] = cls.decode_utf8_or_hex
        cls._registry["EAP/6F01"] = cls.decode_utf8_or_hex
        cls._registry["EAP/6F02"] = cls.decode_tlv_as_map

        # ADF.ISIM file identifiers: TS 31.103 v19 §4.3 figure 4.1. The GBA
        # files sit at '6FD5'/'6FD7' here, not at the USIM '6FD6'/'6FDA'.
        cls._registry["ISIM/6F02"] = cls.decode_isim_tlv80_text
        cls._registry["ISIM/6F03"] = cls.decode_isim_tlv80_text
        cls._registry["ISIM/6F04"] = cls.decode_isim_tlv80_text
        cls._registry["ISIM/6F07"] = cls.decode_isim_ist
        cls._registry["ISIM/6F09"] = cls.decode_isim_pcscf
        cls._registry["ISIM/6F0A"] = cls.decode_tlv_as_map
        cls._registry["ISIM/6F0B"] = cls.decode_isim_imsdci
        cls._registry["ISIM/6FAD"] = cls.decode_isim_ad
        cls._registry["ISIM/6FD5"] = cls.decode_gbabp
        cls._registry["ISIM/6FD7"] = cls.decode_gbanl
        cls._registry["ISIM/6FE7"] = cls.decode_isim_tlv80_text
        cls._registry["ISIM/6FFA"] = cls.decode_isim_tlv80_text

        # DF.5GS ('5FC0') file identifiers: TS 31.102 v19.5 §4.4.11.2-§4.4.11.21.
        cls._registry["5GS/4F01"] = cls.decode_5gs_loci
        cls._registry["5GS/4F02"] = cls.decode_5gs_loci
        cls._registry["5GS/4F03"] = cls.decode_5gs_nsc
        cls._registry["5GS/4F04"] = cls.decode_5gs_nsc
        cls._registry["5GS/4F05"] = cls.decode_5gs_auth_keys
        cls._registry["5GS/4F06"] = cls.decode_5gs_uac_aic
        cls._registry["5GS/4F07"] = cls.decode_suci_calc_info
        cls._registry["5GS/4F08"] = cls.decode_opl5g
        cls._registry["5GS/4F09"] = cls.decode_supi_nai
        cls._registry["5GS/4F0A"] = cls.decode_routing_indicator
        cls._registry["5GS/4F0B"] = cls.decode_tlv_as_map
        cls._registry["5GS/4F0C"] = cls.decode_tn3gppsnn
        cls._registry["5GS/4F0D"] = cls.decode_hex_chunks
        cls._registry["5GS/4F0E"] = cls.decode_5gs_sor_cmci
        cls._registry["5GS/4F0F"] = cls.decode_dri
        cls._registry["5GS/4F10"] = cls.decode_5gs_edrx
        cls._registry["5GS/4F11"] = cls.decode_5g_nswo_conf
        cls._registry["5GS/4F15"] = cls.decode_mchpplmn
        cls._registry["5GS/4F16"] = cls.decode_kausf_derivation

        cls._registry["SNPN/4F01"] = cls.decode_hex_chunks
        cls._registry["SNPN/4F02"] = cls.decode_hex_chunks
        cls._registry["SAIP/4F01"] = cls.decode_tlv_as_map
        cls._registry["5G_PROSE/4F01"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F02"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F03"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F04"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F05"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F06"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F07"] = cls.decode_hex_chunks
        cls._registry["5G_PROSE/4F08"] = cls.decode_hex_chunks

    @staticmethod
    def _decode_bcd_digits(
        data: bytes,
        *,
        allow_dial_symbols: bool = True,
        inner_filler: str = "error",
    ) -> str:
        """Decode telephony BCD digit pairs, low nibble first.

        Digit values follow TS 24.008 v19.5 Table 10.5.118 ('A' = '*',
        'B' = '#', 'C'..'E' = 'a'..'c', 'F' = endmark). An 'F' before the
        last semi-octet is an error in a UICC file body, whose unused
        nibbles trail the digits (TS 102 221 v18.4 §13.2, TS 31.102 v19.5
        §4.4.2.3 Table 4.4), whereas an SM-TL address field ignores it and
        continues with the next semi-octet (TS 23.040 v19 §9.1.2.3);
        ``inner_filler`` selects the reading.
        """
        if inner_filler not in ("error", "skip"):
            raise ValueError("inner_filler must be 'error' or 'skip'.")
        symbols = {0x0A: "*", 0x0B: "#", 0x0C: "a", 0x0D: "b", 0x0E: "c"}
        nibbles: List[int] = []
        for byte_value in data:
            nibbles.append(byte_value & 0x0F)
            nibbles.append((byte_value >> 4) & 0x0F)
        output: List[str] = []
        for index, nibble in enumerate(nibbles):
            if nibble == 0x0F:
                if all(item == 0x0F for item in nibbles[index + 1 :]):
                    break
                if inner_filler == "skip":
                    continue
                raise ValueError("BCD filler appears before non-padding data.")
            if nibble <= 9:
                output.append(str(nibble))
            elif allow_dial_symbols and nibble in symbols:
                output.append(symbols[nibble])
            else:
                position = "low" if index % 2 == 0 else "high"
                raise ValueError(f"Invalid {position} BCD nibble 0x{nibble:X}.")
        return "".join(output)

    @staticmethod
    def _decode_plmn_bytes(
        plmn_bytes: bytes,
        *,
        allow_wildcard: bool = False,
    ) -> str:
        """Decode a three-byte PLMN to ``MCC-MNC`` (TS 24.008 v19.5 §10.5.1.3).

        Figure 10.5.3: octet 1 = MCC digit 2 | MCC digit 1, octet 2 = MNC
        digit 3 | MCC digit 3, octet 3 = MNC digit 2 | MNC digit 1. 'F' in
        the MNC digit 3 nibble marks a two-digit MNC.
        """
        if len(plmn_bytes) != 3:
            return f"Invalid PLMN length ({len(plmn_bytes)}; expected 3)"
        b1 = plmn_bytes[0]
        b2 = plmn_bytes[1]
        b3 = plmn_bytes[2]
        mcc_digits = (b1 & 0x0F, b1 >> 4, b2 & 0x0F)
        mnc3 = b2 >> 4
        mnc_digits = (b3 & 0x0F, b3 >> 4)
        valid_digits = set(range(10))
        if allow_wildcard:
            valid_digits.add(0x0D)
        if any(digit not in valid_digits for digit in mcc_digits + mnc_digits):
            return f"Invalid PLMN BCD ({plmn_bytes.hex().upper()})"
        if mnc3 not in valid_digits and mnc3 != 0x0F:
            return f"Invalid PLMN BCD ({plmn_bytes.hex().upper()})"
        def render_digit(digit):
            return "*" if digit == 0x0D else str(digit)

        mcc = "".join(render_digit(digit) for digit in mcc_digits)
        mnc = "".join(render_digit(digit) for digit in mnc_digits)
        # MNC digit 3 sits in octet 2 b8-b5 but is the last digit of a
        # three-digit MNC, so it is appended, not prepended.
        if mnc3 != 0x0F:
            mnc = f"{mnc}{render_digit(mnc3)}"
        return f"{mcc}-{mnc}"

    @staticmethod
    def _decode_alpha_identifier(data: bytes) -> tuple[str, str]:
        """Decode an alpha field per TS 102 221 v18.4 Annex A.

        A leading '80' byte introduces raw UCS2, '81' and '82' the two
        base-pointer forms; anything else is the GSM 7-bit default alphabet
        with bit 8 set to 0 (TS 23.038 v19 §6.2.1), 'FF' padded.
        """
        raw = bytes(data)
        if not raw or all(octet == 0xFF for octet in raw):
            return "", "empty"

        if raw[0] == 0x80:
            payload = raw[1:]
            # There is no character count in coding 0x80. Try the least
            # destructive interpretation first and remove only trailing FF
            # padding needed to obtain printable, well-formed UTF-16BE.
            max_padding = 0
            while (
                max_padding < len(payload)
                and payload[len(payload) - 1 - max_padding] == 0xFF
            ):
                max_padding += 1
            for padding_length in range(max_padding + 1):
                end = len(payload) - padding_length
                candidate = payload[:end]
                if len(candidate) % 2:
                    continue
                try:
                    text = candidate.decode("utf-16-be")
                except UnicodeDecodeError:
                    continue
                if text == "" or text.isprintable():
                    return text, "UCS-2"
            return raw.hex().upper(), "invalid/non-printable UCS-2"

        if raw[0] in (0x81, 0x82):
            header_size = 3 if raw[0] == 0x81 else 4
            if len(raw) < header_size:
                return raw.hex().upper(), "truncated compressed UCS-2 header"
            character_count = raw[1]
            payload_end = header_size + character_count
            if payload_end > len(raw):
                return (
                    raw.hex().upper(),
                    "truncated compressed UCS-2 character data",
                )
            trailer = raw[payload_end:]
            if any(octet != 0xFF for octet in trailer):
                return (
                    raw.hex().upper(),
                    "invalid compressed UCS-2 trailing data",
                )
            if raw[0] == 0x81:
                # Annex A item 2: byte 3 holds bits 15..8 of the base pointer
                # and bit 16 is zero, so the whole byte shifts left by seven;
                # masking its top bit folded every half-page from '4000'
                # upward (CJK at '4E00', for one) into the wrong block.
                base_pointer = raw[2] << 7
            else:
                base_pointer = int.from_bytes(raw[2:4], "big")

            output: List[str] = []
            for encoded in raw[header_size:payload_end]:
                if encoded & 0x80:
                    code_point = base_pointer + (encoded & 0x7F)
                    try:
                        output.append(chr(code_point))
                    except ValueError:
                        return raw.hex().upper(), "invalid compressed UCS-2 code point"
                    continue
                gsm_character = _decode_gsm7_septets([encoded])
                if gsm_character is None:
                    return (
                        raw.hex().upper(),
                        "invalid compressed UCS-2 GSM character",
                    )
                output.append(gsm_character)
            text = "".join(output)
            if text == "" or text.isprintable():
                return text, f"compressed UCS-2 (0x{raw[0]:02X})"
            return raw.hex().upper(), "compressed UCS-2 with non-printable characters"

        value = raw.rstrip(b"\xff")
        text = _decode_gsm7_septets(value)
        if text is not None and text.isprintable():
            return text, "GSM default alphabet"
        return raw.hex().upper(), "GSM/default alphabet (raw)"

    @staticmethod
    def decode_language_indicators(hex_str: str) -> dict:
        """Decode two-byte ISO 639 language codes: EF.PL and EF.LI.

        TS 102 221 v18.4 §13.3 (EF.PL, '2F05') and TS 31.102 v19.5 §4.2.1
        (EF.LI, '6F05' under ADF.USIM) code each character in the SMS
        default 7-bit alphabet with bit 8 set to 0; unused entries are
        'FF FF'.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) % 2 != 0:
                return {
                    "Error": f"Language indicator length must be even; got {len(data)} bytes",
                    "Raw": hex_str,
                }
            langs = []
            invalid = []
            for i in range(0, len(data), 2):
                chunk = data[i : i + 2]
                if chunk == b"\xff\xff":
                    continue
                language = _decode_gsm7_septets(chunk)
                if language is None or not language.isalpha():
                    invalid.append(chunk.hex().upper())
                    continue
                langs.append(language.lower())
            result = {"Preferred Languages": langs, "Raw": hex_str}
            if invalid:
                result["Invalid Entries"] = invalid
            return result
        except Exception:
            return {"Preferred Languages (Raw)": hex_str}

    # TS 23.038 v19 §5: CBS Data Coding Scheme language values, coding
    # group 0000 (German .. Polish, 'F' unspecified) and group 0010.
    _CBS_DCS_LANGUAGES: dict[int, str] = {
        0x00: "German",
        0x01: "English",
        0x02: "Italian",
        0x03: "French",
        0x04: "Spanish",
        0x05: "Dutch",
        0x06: "Swedish",
        0x07: "Danish",
        0x08: "Portuguese",
        0x09: "Finnish",
        0x0A: "Norwegian",
        0x0B: "Greek",
        0x0C: "Turkish",
        0x0D: "Hungarian",
        0x0E: "Polish",
        0x0F: "Language unspecified",
        0x20: "Czech",
        0x21: "Hebrew",
        0x22: "Arabic",
        0x23: "Russian",
        0x24: "Icelandic",
    }

    @classmethod
    def decode_lp_language_codes(cls, hex_str: str) -> dict:
        """Decode the SIM EF.LP one-byte language codes (TS 51.011 v4.15 §10.3.1).

        Each byte is a CBS Data Coding Scheme language value (TS 23.038
        v19 §5); 'FF' bytes are unused entries.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "EF.LP Hex Decode Error", "Raw": hex_str}
        languages: List[str] = []
        codes: List[str] = []
        for value in data:
            if value == 0xFF:
                continue
            codes.append(f"{value:02X}")
            name = cls._CBS_DCS_LANGUAGES.get(value)
            if name is None:
                if (value >> 4) in (0x02, 0x03):
                    name = f"Reserved GSM 7-bit language (0x{value:02X})"
                else:
                    name = f"Reserved (0x{value:02X})"
            languages.append(name)
        return {"Preferred Languages": languages, "Codes": codes, "Raw": hex_str}

    @staticmethod
    def decode_service_table_bits(hex_str: str) -> dict:
        """Decode a generic service-table EF to active / not-set service number lists.

        Used for EFs without a named-service map (e.g. EF.PSISMSC, V2X service tables).
        """
        # Generic anonymous service-table decoder used by EF_PSISMSC,
        # MCS / V2X / A2X service-table EFs, etc. Without a name map
        # the rows are pure service numbers, but the active/inactive
        # split still gives operators a checklist view in the GUI.
        try:
            data = bytes.fromhex(hex_str)
        except Exception:
            return {
                "service_table": True,
                "error": "Service Table (Raw)",
                "raw": hex_str,
                "active": [],
                "inactive": [],
            }
        return AdvancedDecoders._build_service_table(
            data,
            name_map=None,
            table_name="Service Table",
            full_name="Generic service table (no name map)",
        )

    @staticmethod
    def decode_cbmi_list(hex_str: str) -> dict:
        """Decode EF.CBMI: Cell Broadcast Message Identifier list (3GPP TS 31.102 §4.2.14).

        Returns a list of 16-bit message identifier integers.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) % 2 != 0:
                return {
                    "Error": f"CBMI length must be a multiple of 2 bytes; got {len(data)}",
                    "Raw": hex_str,
                }
            ids = []
            for i in range(0, len(data), 2):
                chunk = data[i : i + 2]
                if chunk == b"\xff\xff":
                    continue
                ids.append(int.from_bytes(chunk, "big"))
            return {"Message Identifiers": ids, "Raw": hex_str}
        except Exception:
            return {"CBMI (Raw)": hex_str}

    @staticmethod
    def decode_cbmid_range_list(hex_str: str) -> dict:
        """Decode EF.CBMIR: Cell Broadcast Message Identifier Range list (3GPP TS 31.102 §4.2.22).

        Returns a list of from/to range pairs.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) % 4 != 0:
                return {
                    "Error": f"CBMID range length must be a multiple of 4 bytes; got {len(data)}",
                    "Raw": hex_str,
                }
            ranges = []
            for i in range(0, len(data), 4):
                chunk = data[i : i + 4]
                if chunk == b"\xff\xff\xff\xff":
                    continue
                first = int.from_bytes(chunk[0:2], "big")
                last = int.from_bytes(chunk[2:4], "big")
                ranges.append(f"{first}-{last}")
            return {"Message Identifier Ranges": ranges, "Raw": hex_str}
        except Exception:
            return {"CBMID (Raw)": hex_str}

    @staticmethod
    def _context_tokens(context_path: Optional[str]) -> List[str]:
        if not context_path:
            return []
        raw = str(context_path).strip().upper().replace("\\", "/")
        if raw == "":
            return []
        parts = [p for p in raw.split("/") if p]
        out = []
        for p in parts:
            value = p.strip()
            if not value:
                continue
            out.append(value)
            normalized = value.replace("_", ".")
            if "." in normalized:
                leaf = normalized.rsplit(".", 1)[1]
                if leaf and leaf not in out:
                    out.append(leaf)
            for prefix in ("EF_", "DF_", "ADF_"):
                if value.startswith(prefix):
                    leaf = value[len(prefix) :]
                    if leaf and leaf not in out:
                        out.append(leaf)
        return out

    @classmethod
    def _resolve_handler(cls, fid_upper: str, context_path: Optional[str] = None):
        tokens = cls._context_tokens(context_path)
        for tok in reversed(tokens):
            key = f"{tok}/{fid_upper}"
            handler = cls._registry.get(key)
            if handler:
                return handler
        return cls._registry.get(fid_upper)

    @staticmethod
    def decode_spn(hex_str: str) -> dict:
        """Decode EF.SPN: Service Provider Name (3GPP TS 31.102 §4.2.12).

        Returns display-condition byte and the TS 102 221 alpha identifier.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "SPN Hex Decode Error"}
        if len(data) < 2 or all(octet == 0xFF for octet in data):
            return {"Error": "Empty or truncated SPN"}
        display_condition = data[0]
        name, encoding = ContentDecoder._decode_alpha_identifier(data[1:])
        output = {
            "SPN": name,
            "Encoding": encoding,
            "Display Condition": f"{display_condition:02X}",
            "Display Registered PLMN on HPLMN/SPDI PLMN": bool(
                display_condition & 0x01
            ),
            "Display SPN outside HPLMN/SPDI PLMN": not bool(display_condition & 0x02),
        }
        warnings = []
        if len(data) != 17:
            warnings.append(f"EF.SPN is {len(data)} bytes; expected 17")
        if display_condition & 0xFC:
            warnings.append("EF.SPN display-condition RFU bits 3..8 are non-zero")
        if warnings:
            output["Warnings"] = warnings
        return output

    @classmethod
    def decode_raw(
        cls, fid: str, hex_data: str, context_path: Optional[str] = None
    ) -> Any:
        """Look up the decoder for *fid* and return its raw Python output.

        Returns ``None`` when no decoder is registered for the given FID.
        """
        if not fid:
            return None
        fid_upper = str(fid).strip().upper().replace(" ", "")
        if fid_upper.startswith("0X"):
            fid_upper = fid_upper[2:]

        is_empty = False
        if not cls._registry:
            is_empty = True
        if is_empty:
            cls.init_registry()

        handler = cls._resolve_handler(fid_upper, context_path)
        if handler:
            try:
                return handler(hex_data)
            except Exception as exc:
                return {
                    "Error": f"{fid_upper} decoder failed: {exc}",
                }
        return None

    @classmethod
    def decode(
        cls, fid: str, hex_data: str, context_path: Optional[str] = None
    ) -> Optional[str]:
        """Decode *hex_data* for *fid* and return a JSON-serialisable string.

        Formats the raw decoder output as a pretty-printed JSON string;
        returns ``None`` when no decoder is registered.
        """
        raw = cls.decode_raw(fid, hex_data, context_path=context_path)
        if raw is None:
            return None

        is_list = False
        if isinstance(raw, list):
            is_list = True
        if is_list:
            return "\n".join(str(x) for x in raw)

        is_dict = False
        if isinstance(raw, dict):
            is_dict = True
        if is_dict:
            out_lines = []
            for k, v in raw.items():
                out_lines.append(f"{k}: {v}")
            return "\n".join(out_lines)

        return str(raw)

    @classmethod
    def decode_obj(
        cls, fid: str, hex_data: str, context_path: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Decode *hex_data* for *fid* and return the raw Python dict or list.

        Returns ``None`` when no decoder is registered for *fid*.
        """
        raw = cls.decode_raw(fid, hex_data, context_path=context_path)
        if raw is None:
            return None

        is_dict = False
        if isinstance(raw, dict):
            is_dict = True
        if is_dict:
            return raw

        is_list = False
        if isinstance(raw, list):
            is_list = True
        if is_list:
            return {"items": raw}

        return {"description": str(raw)}

    @staticmethod
    def decode_acc(hex_str: str) -> dict:
        """Decode EF.ACC: Access Control Class bitmask (3GPP TS 31.102 §4.2.15).

        Returns the 16-bit raw value and a list of class labels for each set bit.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) != 2:
                return {"Error": f"Invalid ACC Length ({len(data)}; expected 2)"}
            val = int.from_bytes(data, "big")
            classes = []
            for i in range(16):
                if i != 10 and val & (1 << i):
                    classes.append(str(i))
            output = {
                "Access Control Classes": classes,
                "Raw": data.hex().upper(),
            }
            if val & (1 << 10):
                output["Warning"] = "Reserved EF.ACC bit (byte 1, b3) is set"
            return output
        except Exception:
            return {"Error": "ACC Decode Error"}

    @staticmethod
    def decode_dir(hex_str: str) -> dict:
        """Decode an EF.DIR application template record (TS 102 221 v18.4 §13.1).

        Table 13.2: '61' template holding a mandatory '4F' AID of 1 to 16
        bytes and an optional '50' label coded per Annex A.
        """
        try:
            is_empty = True
            for c in hex_str:
                if c != "F":
                    is_empty = False
            if is_empty:
                return {"Error": "Empty Record"}

            data = bytes.fromhex(hex_str)
            if len(data) == 0:
                return {"Error": "Empty Data"}

            parsed = TlvParser.parse_padded(data)
            app_values = TlvParser.as_list(parsed.get(0x61))
            applications = []
            for app in app_values:
                inner = app
                if isinstance(app, bytes):
                    inner = TlvParser.parse(app)
                if not isinstance(inner, dict):
                    continue
                aid_value = TlvParser.get_first(inner, 0x4F, b"")
                label_value = TlvParser.get_first(inner, 0x50, b"")
                if not isinstance(aid_value, bytes):
                    continue
                aid = aid_value.hex().upper()
                if len(aid_value) not in range(1, 17):
                    applications.append(
                        {
                            "AID": aid,
                            "Error": f"Invalid AID length ({len(aid_value)}; expected 1..16)",
                        }
                    )
                    continue
                entry: Dict[str, Any] = {"AID": aid, "Label": ""}
                if isinstance(label_value, bytes) and label_value:
                    label, label_encoding = ContentDecoder._decode_alpha_identifier(
                        label_value
                    )
                    entry["Label"] = label
                    entry["Label Encoding"] = label_encoding
                if len(aid_value) < 5:
                    # TS 101 220 v19 §4: an AID opens with a five-byte RID.
                    entry["Warning"] = (
                        f"AID is {len(aid_value)} bytes; shorter than the 5-byte RID"
                    )
                applications.append(entry)
            if applications:
                result = {"Applications": applications}
                if len(applications) == 1:
                    result.update(applications[0])
                return result

            return {"Raw DIR Data": hex_str}
        except Exception as e:
            return {"Error": f"DIR Decode Error: {e}"}

    @staticmethod
    def decode_msisdn(hex_str: str) -> dict:
        """Decode EF.MSISDN: Mobile Station ISDN Number record (3GPP TS 31.102 §4.2.26).

        Returns alphanumeric-tag, TON/NPI, dialling digits, and capability/extension.
        """
        try:
            is_empty = True
            for c in hex_str:
                if c != "F":
                    is_empty = False
            if is_empty:
                return {"Error": "Empty Record"}

            data = bytes.fromhex(hex_str)
            if len(data) < 14:
                return {"Error": f"Invalid Length ({len(data)})"}

            footer_len = 14
            alpha_len = len(data) - footer_len

            alpha_id = ""
            alpha_encoding = ""
            if alpha_len > 0:
                alpha_id, alpha_encoding = ContentDecoder._decode_alpha_identifier(
                    data[:alpha_len]
                )

            footer = data[alpha_len:]
            number_len = footer[0]
            if number_len == 0xFF:
                return {"Error": "Empty Record"}
            if number_len < 1 or number_len > 11:
                return {"Error": f"Invalid BCD number length ({number_len})"}
            ton_npi = footer[1]
            bcd_octets = number_len - 1
            dial_num = ContentDecoder._decode_bcd_digits(footer[2 : 2 + bcd_octets])

            out_dict = {}
            if alpha_id != "":
                out_dict["Alpha ID"] = alpha_id
                out_dict["Alpha ID Encoding"] = alpha_encoding
            out_dict["Length of BCD Number"] = number_len
            out_dict["Dialing Number"] = dial_num
            out_dict["TON/NPI"] = f"{ton_npi:02X}"
            out_dict["TON"], out_dict["NPI"] = ContentDecoder._ton_npi_labels(ton_npi)
            out_dict["Capability/Configuration Identifier"] = f"{footer[12]:02X}"
            out_dict["Extension Record ID"] = f"{footer[13]:02X}"
            return out_dict
        except Exception as e:
            return {"Error": f"MSISDN Decode Error: {e}"}

    @staticmethod
    def decode_iccid(hex_str: str) -> dict:
        """Decode EF.ICCID: Integrated Circuit Card ID (ETSI TS 102 221 §13.2).

        Nibble-swaps each byte pair to recover the E.118 BCD-encoded serial number.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) != 10:
                return {"Error": f"Invalid ICCID Length ({len(data)}; expected 10)"}
            digits = ContentDecoder._decode_bcd_digits(
                data,
                allow_dial_symbols=False,
            )
            if not digits:
                return {"Error": "ICCID contains no digits"}
            output = {"iccid": digits, "digit_count": len(digits)}
            # ITU-T E.118 (09/2025) §6 fixes the PAN at 19 digits; TS 51.011
            # v4.15 §10.1.1 lets Phase 1 issuers keep 20.
            if len(digits) not in (19, 20):
                output["Warning"] = (
                    f"ICCID has {len(digits)} digits; E.118 specifies 19"
                )
            return output
        except Exception as exc:
            return {"Error": f"ICCID Decode Error: {exc}"}

    @staticmethod
    def decode_imsi(hex_str: str) -> dict:
        """Decode EF.IMSI (TS 31.102 v19.5 §4.2.2).

        Byte 1 counts the significant IMSI bytes that follow (up to 8);
        byte 2 is the Mobile Identity octet of TS 24.008 v19.5 §10.5.1.4:
        digit 1 in b8-b5, the odd/even indicator in b4 and the type of
        identity (001 = IMSI) in b3-b1. Unused nibbles are 'F'.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) != 9:
                return {"Error": f"Invalid IMSI Length ({len(data)}; expected 9)"}
            imsi_len = data[0]
            if not 1 <= imsi_len <= 8:
                return {
                    "Error": f"Invalid IMSI length octet ({imsi_len}; expected 1..8)"
                }
            identity = data[1]
            first_digit = (identity >> 4) & 0x0F
            if first_digit > 9:
                return {"Error": "Invalid first IMSI digit"}
            type_bits = identity & 0x07
            if type_bits != 0x01:
                return {"Error": f"Invalid IMSI identity type ({type_bits})"}
            odd_digit_count = bool(identity & 0x08)
            remaining = ContentDecoder._decode_bcd_digits(
                data[2 : 1 + imsi_len],
                allow_dial_symbols=False,
            )
            digits = str(first_digit) + remaining
            if len(digits) > 15:
                return {
                    "Error": f"Invalid IMSI digit count ({len(digits)}; maximum 15)"
                }
            if bool(len(digits) % 2) != odd_digit_count:
                return {"Error": "IMSI odd/even indicator does not match digit count"}
            output = {
                "imsi": digits,
                "digit_count": len(digits),
                "odd_digit_count": odd_digit_count,
                "length_octet": imsi_len,
            }
            warnings = []
            implied_digits = 2 * imsi_len - (1 if odd_digit_count else 2)
            if len(digits) != implied_digits:
                warnings.append(
                    f"Length of IMSI {imsi_len} implies {implied_digits} digits; "
                    f"found {len(digits)}"
                )
            if any(octet != 0xFF for octet in data[1 + imsi_len :]):
                warnings.append("Bytes after the significant IMSI bytes are not FF")
            if warnings:
                output["Warnings"] = warnings
            return output
        except Exception as exc:
            return {"Error": f"IMSI Decode Error: {exc}"}

    @staticmethod
    def decode_ad(hex_str: str) -> dict:
        """Decode EF.AD: Administrative Data (3GPP TS 31.102 §4.2.18).

        Returns the administrative mode code, MNC length, and raw AD bytes.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 3:
                return {
                    "Error": f"Invalid AD Length ({len(data)}; expected at least 3)"
                }
            mode = data[0]
            m_map = {
                0x00: "Normal operation",
                0x80: "Type approval operation",
                0x01: "Normal operation with specific facilities",
                0x81: "Type approval operation with specific facilities",
                0x02: "Maintenance (off-line)",
                0x04: "Cell test operation",
            }
            mode_str = m_map.get(mode, f"RFU (0x{mode:02X})")
            output = {
                "Administrative Mode": mode_str,
                "Mode Byte": f"{mode:02X}",
                "Additional Information": data[1:3].hex().upper(),
                "Raw": data.hex().upper(),
            }
            if mode & 0x02:
                # §4.2.18: with b2 of byte 1 set the two additional-information
                # bytes are ME manufacturer specific ("any value").
                output["Additional Information Meaning"] = "ME manufacturer specific"
            if mode & 0x01:
                feature_byte = data[2]
                output["Specific Facilities"] = {
                    "Ciphering Indicator": bool(feature_byte & 0x01),
                    "Operator CSG Entries Only": bool(feature_byte & 0x02),
                    "ProSe Public Safety": bool(feature_byte & 0x04),
                    "Extended DRX UICC Deactivation": bool(feature_byte & 0x08),
                    "5G ProSe Operator-managed Resources": bool(feature_byte & 0x10),
                }
            if len(data) >= 4:
                mnc_length = data[3] & 0x0F
                output["MNC Length"] = (
                    mnc_length
                    if mnc_length in (0, 2, 3)
                    else f"Reserved ({mnc_length})"
                )
                output["MNC Length Byte"] = f"{data[3]:02X}"
            else:
                output["Warning"] = "Legacy three-byte EF.AD has no MNC-length field"
            if len(data) > 4:
                output["Trailing RFU"] = data[4:].hex().upper()
            return output
        except Exception:
            return {"Error": "AD Decode Error"}

    # TS 24.008 v19.5 Table 10.5.118 and TS 23.040 v19 §9.1.2.5. Value 4 is
    # "dedicated access, short code" on the CS interface and "subscriber
    # number" in SM-TL; NPI 5/6 and 10 exist only in TS 23.040, 11 only in
    # TS 24.008.
    _TON_LABELS: dict[int, str] = {
        0: "Unknown",
        1: "International",
        2: "National",
        3: "Network Specific",
        4: "Subscriber Number (dedicated access, short code)",
        5: "Alphanumeric",
        6: "Abbreviated",
        7: "Reserved",
    }

    # An RP address carries the Called Party BCD Number of TS 24.008 v19.5
    # table 10.5.118 (TS 24.011 v19 §8.2.5.1, §8.2.5.2), which reserves 101
    # and 110 rather than naming them alphanumeric and abbreviated.
    _RP_TON_LABELS: dict[int, str] = {
        0: "Unknown",
        1: "International",
        2: "National",
        3: "Network Specific",
        4: "Dedicated access, short code",
        5: "Reserved",
        6: "Reserved",
        7: "Reserved for extension",
    }

    _NPI_LABELS: dict[int, str] = {
        0: "Unknown",
        1: "ISDN / E.164",
        3: "Data / X.121",
        4: "Telex / F.69",
        5: "Service Centre Specific",
        6: "Service Centre Specific",
        8: "National",
        9: "Private",
        10: "ERMES",
        11: "Reserved for CTS",
        15: "Reserved",
    }

    @classmethod
    def _ton_npi_labels(cls, ton_npi: int) -> tuple[str, str]:
        """Label a TON/NPI byte; 'FF' means the record holds no dialling number.

        TS 31.102 v19.5 §4.4.2.3: when the Dialling Number/SSC String does
        not contain a dialling number the ME sets the TON/NPI byte to 'FF'.
        """
        if ton_npi == 0xFF:
            return "Not present (FF)", "Not present (FF)"
        ton = (ton_npi >> 4) & 0x07
        npi = ton_npi & 0x0F
        return (
            cls._TON_LABELS.get(ton, f"Reserved ({ton})"),
            cls._NPI_LABELS.get(npi, f"Reserved ({npi})"),
        )

    # TS 23.040 v19 §9.2.3.9
    _TP_PID_LABELS: dict[int, str] = {
        0x00: "SME-to-SME protocol (no interworking)",
        0x20: "Implicit telematic device",
        0x21: "Telex",
        0x22: "Group 3 telefax",
        0x23: "Group 4 telefax",
        0x24: "Voice telephone",
        0x25: "ERMES",
        0x26: "National paging system",
        0x27: "Videotex",
        0x28: "Teletex, carrier unspecified",
        0x29: "Teletex, in PSPDN",
        0x2A: "Teletex, in CSPDN",
        0x2B: "Teletex, in analog PSTN",
        0x2C: "Teletex, in digital ISDN",
        0x2D: "UCI",
        0x30: "Message Handling Facility",
        0x31: "X.400",
        0x32: "Internet electronic mail",
        0x3F: "GSM/UMTS mobile station",
        0x40: "Short Message Type 0",
        0x41: "Replace Short Message Type 1",
        0x42: "Replace Short Message Type 2",
        0x43: "Replace Short Message Type 3",
        0x44: "Replace Short Message Type 4",
        0x45: "Replace Short Message Type 5",
        0x46: "Replace Short Message Type 6",
        0x47: "Replace Short Message Type 7",
        0x48: "Device Triggering Short Message",
        0x5E: "Enhanced Message Service (obsolete)",
        0x5F: "Return Call Message",
        0x7C: "ANSI-136 R-DATA",
        0x7D: "ME Data download",
        0x7E: "ME De-personalization Short Message",
        0x7F: "(U)SIM Data download",
    }

    @classmethod
    def _tp_pid_label(cls, tp_pid: int) -> str:
        """Name a TP-PID value per TS 23.040 v19 §9.2.3.9."""
        label = cls._TP_PID_LABELS.get(tp_pid)
        if label is not None:
            return label
        group = tp_pid & 0xC0
        if group == 0xC0:
            return "SC specific use"
        if group == 0x80:
            return "Reserved"
        if group == 0x40:
            return "Reserved"
        if tp_pid & 0x20:
            if 0x38 <= tp_pid <= 0x3E:
                return "Telematic device specific to the SC"
            return "Reserved telematic device"
        return "SME-to-SME protocol (SM-AL protocol identifier)"

    @classmethod
    def _decode_address_field(
        cls, raw: bytes, sc_addr: bool = False
    ) -> dict[str, object]:
        """Decode an SMS address field.

        Two different codings share this shape. An RP address -- the Service
        Centre address of EF.SMS and the TP-SCA of EF.SMSP -- is the
        RP-Originator / RP-Destination element of TS 24.011 v19 §8.2.5.1 and
        §8.2.5.2: the length octet counts the contents from the TON/NPI octet
        on, its value runs from 2 to 11, and octets 3 onward carry the Called
        Party BCD Number of TS 24.008 v19.5 §10.5.4.7, whose type-of-number
        table has no alphanumeric form. An SM-TL address (TP-DA, TP-OA) is
        TS 23.040 v19 §9.1.2.5: the length octet counts useful semi-octets and
        type-of-number 101 is alphanumeric GSM 7-bit. 0xFF in either case
        means the address is not set.
        """
        if len(raw) < 2:
            return {"raw": raw.hex().upper(), "error": "too short for address field"}

        addr_len = raw[0]
        if addr_len == 0xFF:
            return {"length": addr_len, "present": False, "call_number": ""}
        if addr_len == 0:
            return {"length": 0, "present": False, "call_number": ""}

        ton_npi = raw[1]
        ext = bool(ton_npi & 0x80)
        ton = (ton_npi >> 4) & 0x07
        npi = ton_npi & 0x0F

        if sc_addr:
            # TS 24.011 v19 §8.2.5.1 and §8.2.5.2 cap the length octet at 11:
            # the TON/NPI octet plus at most ten semi-octet pairs. EF.SMS
            # defers to the same element and puts its longest address at
            # "more than 18 address digits" (TS 31.102 v19.5 §4.2.25), which
            # the eleven-octet maximum covers. Checked before the buffer
            # length, because the value is out of spec however many octets
            # happen to follow it.
            if addr_len > 11:
                return {
                    "raw": raw.hex().upper(),
                    "error": (
                        f"declared SC address length {addr_len} exceeds the "
                        "maximum of 11"
                    ),
                }
            if addr_len > len(raw) - 1:
                return {
                    "raw": raw.hex().upper(),
                    "error": f"declared SC address length {addr_len} exceeds field",
                }
            address_octets = addr_len - 1
            digits_expected = address_octets * 2
        else:
            if addr_len > 20:
                return {
                    "raw": raw.hex().upper(),
                    "error": f"declared destination address has {addr_len} digits; maximum is 20",
                }
            address_octets = (addr_len + 1) // 2
            digits_expected = addr_len

        address_bytes = raw[2 : 2 + address_octets]
        if len(address_bytes) != address_octets:
            return {"raw": raw.hex().upper(), "error": "address field is truncated"}
        if ton == 5 and not sc_addr:
            # TS 23.040 v19 §9.1.2.5: alphanumeric addresses are packed GSM
            # 7-bit characters; the length still counts semi-octets. An RP
            # address takes the TS 24.008 v19.5 table 10.5.118 reading, where
            # type-of-number 101 is reserved and the digits stay BCD
            # (TS 24.011 v19 §8.2.5.2).
            character_count = (digits_expected * 4) // 7
            spare_bits = len(address_bytes) * 8 - character_count * 7
            text = None
            if 0 <= spare_bits < 8:
                text = _decode_gsm7_packed(address_bytes, spare_bits)
            if text is None:
                digits = address_bytes.hex().upper()
                encoding = "alphanumeric GSM 7-bit (raw)"
            else:
                digits = text
                encoding = "alphanumeric GSM 7-bit"
        else:
            try:
                digits = cls._decode_bcd_digits(address_bytes, inner_filler="skip")
            except ValueError as error:
                return {"raw": raw.hex().upper(), "error": str(error)}
            digits = digits[:digits_expected]
            encoding = "telephony BCD"

        return {
            "length": addr_len,
            "present": True,
            "call_number": digits,
            "encoding": encoding,
            "extension": ext,
            "extension_indicator": "no extension" if ext else "extension follows",
            "ton": (cls._RP_TON_LABELS if sc_addr else cls._TON_LABELS).get(
                ton, f"Reserved ({ton})"
            ),
            "npi": cls._NPI_LABELS.get(npi, f"Reserved ({npi})"),
            "ton_npi_raw": f"0x{ton_npi:02X}",
        }

    @classmethod
    def _decode_validity_period(cls, vp_byte: int) -> dict[str, object]:
        """Decode TP-Validity Period relative format per TS 23.040 §9.2.3.12."""
        if (
            isinstance(vp_byte, bool)
            or not isinstance(vp_byte, int)
            or not 0 <= vp_byte <= 0xFF
        ):
            raise ValueError("TP-Validity Period must be one byte.")
        if vp_byte <= 143:
            minutes = (vp_byte + 1) * 5
            return {"format": "relative (5-min steps)", "minutes": minutes}
        if vp_byte <= 167:
            minutes = 12 * 60 + (vp_byte - 143) * 30
            return {"format": "relative (30-min steps)", "minutes": minutes}
        if vp_byte <= 196:
            days = vp_byte - 166
            return {
                "format": "relative (days)",
                "days": days,
                "minutes": days * 24 * 60,
            }
        weeks = vp_byte - 192
        return {
            "format": "relative (weeks)",
            "weeks": weeks,
            "minutes": weeks * 7 * 24 * 60,
        }

    @staticmethod
    def _decode_tp_dcs(dcs: int) -> str:
        """Decode the TP-DCS coding group per 3GPP TS 23.038 §4."""
        alphabet_names = {
            0: "GSM 7-bit default alphabet",
            1: "8-bit data",
            2: "UCS-2",
            3: "reserved alphabet",
        }
        if (dcs & 0xC0) in (0x00, 0x40):
            alphabet = alphabet_names[(dcs >> 2) & 0x03]
            parts = [alphabet]
            if dcs & 0x20:
                parts.append("compressed")
            if dcs & 0x10:
                parts.append(f"message class {dcs & 0x03}")
            # TS 23.038 v19 §4 coding group 01xx codes bits 5..0 like group
            # 00xx and marks the message for deletion after reading.
            if (dcs & 0xC0) == 0x40:
                parts.append("marked for automatic deletion")
            return ", ".join(parts)
        group = dcs & 0xF0
        if group in (0xC0, 0xD0, 0xE0):
            alphabet = "UCS-2" if group == 0xE0 else "GSM 7-bit default alphabet"
            active = "active" if dcs & 0x08 else "inactive"
            indication = {
                0: "voicemail",
                1: "fax",
                2: "email",
                3: "other",
            }[dcs & 0x03]
            discard = "discard message" if group == 0xC0 else "store message"
            return f"message waiting ({indication}, {active}, {discard}, {alphabet})"
        if group == 0xF0:
            alphabet = "8-bit data" if dcs & 0x04 else "GSM 7-bit default alphabet"
            return f"{alphabet}, message class {dcs & 0x03}"
        return f"reserved/implementation-specific DCS group (0x{dcs:02X})"

    @classmethod
    def decode_sms_params(cls, hex_str: str) -> dict:
        """Decode EF.SMSP per 3GPP TS 31.102 v19.5 §4.2.27.

        Parses the Parameter Indicators bitmask, the two addresses, TP-PID,
        TP-DCS and TP-Validity Period into structured fields. TP-Destination
        Address is an SM-TL address field (TS 23.040 v19 §9.1.2.5) whose
        length octet counts semi-octets; TP-Service Centre Address is an RP
        address (TS 24.011 v19 §8.2.5.2) whose length octet counts the
        contents octets, which is why the two are read differently.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"SMS Params (Raw)": hex_str}

        if len(data) < 28:
            return {
                "Error": f"Invalid SMSP record length ({len(data)}; expected at least 28)",
                "SMS Params (Raw)": hex_str,
            }

        try:
            alpha_len = max(0, len(data) - 28)
            alpha = ""
            alpha_encoding = ""
            if alpha_len > 0:
                alpha, alpha_encoding = cls._decode_alpha_identifier(data[:alpha_len])

            p_ind = data[alpha_len]

            # Parameter Indicators -- inverted bitmask: each bit 0 = field
            # present, 1 = field absent. Bit 0 (LSB) = TP-DA, bit 1 =
            # TP-SCA, bit 2 = TP-PID, bit 3 = TP-DCS, bit 4 = TP-VP.
            pi_flags: dict[str, bool] = {}
            for idx, label in enumerate(
                (
                    "TP-Destination Address",
                    "TP-Service Centre Address",
                    "TP-Protocol Identifier",
                    "TP-Data Coding Scheme",
                    "TP-Validity Period",
                )
            ):
                pi_flags[label] = not bool(p_ind & (1 << idx))

            tp_da_raw = data[alpha_len + 1 : alpha_len + 13]
            sca_raw = data[alpha_len + 13 : alpha_len + 25]
            tp_pid = data[alpha_len + 25]
            tp_dcs = data[alpha_len + 26]
            tp_vp = data[alpha_len + 27]

            tp_da_present = pi_flags["TP-Destination Address"]
            sca_present = pi_flags["TP-Service Centre Address"]
            pid_present = pi_flags["TP-Protocol Identifier"]
            dcs_present = pi_flags["TP-Data Coding Scheme"]
            vp_present = pi_flags["TP-Validity Period"]

            tp_da = (
                cls._decode_address_field(tp_da_raw, sc_addr=False)
                if tp_da_present
                else {"present": False, "raw": tp_da_raw.hex().upper()}
            )
            sca = (
                cls._decode_address_field(sca_raw, sc_addr=True)
                if sca_present
                else {"present": False, "raw": sca_raw.hex().upper()}
            )
            vp_decoded: object = (
                cls._decode_validity_period(tp_vp)
                if vp_present
                else {"present": False, "raw": f"0x{tp_vp:02X}"}
            )

            pid_label = cls._tp_pid_label(tp_pid) if pid_present else ""
            dcs_label = cls._decode_tp_dcs(tp_dcs) if dcs_present else ""

            out: dict[str, object] = {
                "Parameter Indicators": {
                    "raw": f"0x{p_ind:02X}",
                    "flags": pi_flags,
                },
                "TP-Destination Address": tp_da,
                "Service Center Address": sca,
                "TP-PID": f"0x{tp_pid:02X}" if pid_present else "Not present",
                "TP-DCS": f"0x{tp_dcs:02X}" if dcs_present else "Not present",
                "TP-Validity Period": vp_decoded,
            }
            if pid_label:
                out["TP-PID Label"] = pid_label
            if dcs_label:
                out["TP-DCS Label"] = dcs_label
            warnings = []
            if (p_ind & 0xE0) != 0xE0:
                warnings.append("Parameter Indicator RFU bits 6..8 are not all one")
            absent_fields = (
                ("TP-Destination Address", tp_da_present, tp_da_raw),
                ("TP-Service Centre Address", sca_present, sca_raw),
                ("TP-Protocol Identifier", pid_present, bytes([tp_pid])),
                ("TP-Data Coding Scheme", dcs_present, bytes([tp_dcs])),
                ("TP-Validity Period", vp_present, bytes([tp_vp])),
            )
            for label, present, raw_field in absent_fields:
                if not present and any(octet != 0xFF for octet in raw_field):
                    warnings.append(f"{label} is marked absent but is not FF")
            if tp_da_present and tp_da.get("present") is False:
                warnings.append(
                    "TP-Destination Address is marked present but has no address"
                )
            if sca_present and sca.get("present") is False:
                warnings.append(
                    "TP-Service Centre Address is marked present but has no address"
                )
            if warnings:
                out["Warnings"] = warnings
            if alpha:
                out["Alpha ID"] = alpha
                out["Alpha ID Encoding"] = alpha_encoding
            return out
        except Exception:
            return {"SMS Params (Raw)": hex_str}

    @staticmethod
    def decode_puct(hex_str: str) -> dict:
        """Decode EF.PUCT: Price per Unit and Currency Table (3GPP TS 31.102 §4.2.13).

        Returns currency string, price-per-unit mantissa/exponent, and raw bytes.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 5:
                return {"PUCT (Raw)": hex_str}
            # §4.2.13: the three currency characters use the SMS default
            # 7-bit alphabet with bit 8 set to 0, not ISO 646.
            currency = _decode_gsm7_septets(data[0:3]) or ""
            if not currency.isprintable():
                currency = ""
            if currency == "":
                currency = data[0:3].hex().upper()
            eppu = (data[3] << 4) | (data[4] & 0x0F)
            exp_nibble = (data[4] >> 4) & 0x0F
            # TS 31.102 Figure 4.2.13: b5 is the sign and b6..b8
            # carry |EX| from least to most significant bit.
            sign = -1 if (exp_nibble & 0x01) else 1
            exponent = sign * ((exp_nibble >> 1) & 0x07)
            output = {
                "Currency": currency,
                "EPPU": eppu,
                "Exponent": exponent,
                "Price per Unit Formula": f"{eppu} * 10^{exponent}",
                "Raw": data.hex().upper(),
            }
            if len(data) != 5:
                output["Warning"] = f"EF.PUCT is {len(data)} bytes; expected 5"
            return output
        except Exception:
            return {"PUCT (Raw)": hex_str}

    @staticmethod
    def decode_ecc(hex_str: str) -> dict:
        """Decode EF.ECC: Emergency Call Codes (3GPP TS 31.102 §4.2.21).

        Returns a list of dicts with emergency code digits and category bitmask.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) == 0:
                return {"Emergency Codes": [], "Entries": []}
            if all(octet == 0xFF for octet in data):
                return {"Emergency Codes": [], "Entries": []}
            if len(data) < 4:
                return {
                    "Error": f"ECC record must be at least 4 bytes; got {len(data)}",
                    "Raw": hex_str,
                }
            # EF.ECC is linear fixed, so this decoder receives one record at
            # a time. A USIM record is code[3] + optional alpha + category[1];
            # interpreting every four bytes as another record corrupts any
            # alpha identifier whose length happens to make the record a
            # multiple of four.
            code_bytes = data[:3]
            digits = ContentDecoder._decode_bcd_digits(
                code_bytes,
                allow_dial_symbols=False,
            )
            if digits == "":
                return {
                    "Error": "ECC record does not contain an emergency code",
                    "Raw": hex_str,
                }
            entry = {"Code": digits}
            category_names = {
                0: "Police",
                1: "Ambulance",
                2: "Fire Brigade",
                3: "Marine Guard",
                4: "Mountain Rescue",
                5: "Manually Initiated eCall",
                6: "Automatically Initiated eCall",
            }
            alpha_bytes = data[3:-1]
            if alpha_bytes:
                alpha, alpha_encoding = ContentDecoder._decode_alpha_identifier(
                    alpha_bytes
                )
                if alpha:
                    entry["Alpha Identifier"] = alpha
                    entry["Alpha Identifier Encoding"] = alpha_encoding
            category = data[-1]
            entry["Service Category Raw"] = f"{category:02X}"
            entry["Service Categories"] = [
                name for bit, name in category_names.items() if category & (1 << bit)
            ]
            if category & 0x80:
                entry["Service Category Warning"] = "RFU bit 8 is set"
            return {"Emergency Codes": [digits], "Entries": [entry]}
        except Exception as exc:
            return {"Error": f"ECC Decode Error: {exc}", "Raw": hex_str}

    @staticmethod
    def decode_ecc_legacy(hex_str: str) -> dict:
        """Decode legacy SIM EF.ECC consecutive three-byte BCD entries."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "Legacy ECC Hex Decode Error"}
        if len(data) % 3:
            return {
                "Error": (
                    f"Legacy ECC length must be a multiple of 3 bytes; got {len(data)}"
                ),
                "Raw": hex_str,
            }
        entries = []
        try:
            for offset in range(0, len(data), 3):
                block = data[offset : offset + 3]
                if block == b"\xff\xff\xff":
                    continue
                digits = ContentDecoder._decode_bcd_digits(
                    block,
                    allow_dial_symbols=False,
                )
                if digits:
                    entries.append({"Code": digits})
        except ValueError as exc:
            return {"Error": f"Legacy ECC Decode Error: {exc}", "Raw": hex_str}
        return {
            "Emergency Codes": [entry["Code"] for entry in entries],
            "Entries": entries,
        }

    @staticmethod
    def decode_adn_like_record(hex_str: str) -> dict:
        """Decode an X+14 dialling-number record (TS 31.102 v19.5 §4.4.2.3).

        Shared by EF.ADN, EF.FDN, EF.SDN, EF.LND and EF.MBDN (TS 51.011
        v4.15 §10.5.1): alpha identifier, BCD length, TON/NPI, ten digit
        bytes, capability/configuration and extension record identifiers.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 14:
                return {"ADN-like (Raw)": hex_str}
            if all(octet == 0xFF for octet in data):
                return {"Error": "Empty ADN-like record"}
            alpha_len = len(data) - 14
            alpha = ""
            alpha_encoding = ""
            if alpha_len > 0:
                alpha, alpha_encoding = ContentDecoder._decode_alpha_identifier(
                    data[:alpha_len]
                )
            footer = data[alpha_len:]
            number_len = footer[0]
            ton_npi = footer[1]
            if number_len == 0xFF:
                return {"Error": "Empty ADN-like record"}
            if number_len > 11:
                return {"Error": f"Invalid BCD number length ({number_len})"}
            number_octets = max(0, number_len - 1)
            number_bcd = footer[2 : 2 + number_octets]
            ccp_id = footer[12]
            ext_id = footer[13]
            digits = ContentDecoder._decode_bcd_digits(number_bcd)
            ton_label, npi_label = ContentDecoder._ton_npi_labels(ton_npi)
            out = {
                "Length of BCD Number": number_len,
                "TON/NPI": f"{ton_npi:02X}",
                "TON": ton_label,
                "NPI": npi_label,
                "Dialing Number": digits,
                "Capability/Configuration Identifier": f"{ccp_id:02X}",
                "Ext Record ID": f"{ext_id:02X}",
            }
            if alpha:
                out["Alpha ID"] = alpha
                out["Alpha ID Encoding"] = alpha_encoding
            return out
        except Exception:
            return {"ADN-like (Raw)": hex_str}

    @staticmethod
    def decode_ccp(hex_str: str) -> dict:
        """Decode an EF.CCP or EF.ECCP record (TS 51.011 v4.15 §10.5.4.1, §10.5.4.2).

        The record holds a Bearer Capability information element without
        its IEI, so byte 1 is the element length; EF.CCP pads to 14 bytes
        with 'FF' in bytes 11 to 14, EF.ECCP to X >= 15 bytes.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "CCP Hex Decode Error", "Raw": hex_str}
        if len(data) == 0:
            return {"Error": "Empty CCP record", "Raw": hex_str}
        if all(octet == 0xFF for octet in data):
            return {"Bearer Capability": "", "Empty": True, "Raw": hex_str}
        ie_length = data[0]
        ie_bytes = data[1 : 1 + ie_length]
        output: dict[str, Any] = {
            "Bearer Capability Length": ie_length,
            "Bearer Capability": ie_bytes.hex().upper(),
            "Raw": hex_str,
        }
        warnings = []
        if len(ie_bytes) != ie_length:
            warnings.append(
                f"Bearer capability length {ie_length} exceeds the record"
            )
        if len(data) == 14 and ie_length > 9:
            warnings.append("EF.CCP bearer capability exceeds bytes 1 to 10")
        if any(octet != 0xFF for octet in data[1 + ie_length :]):
            warnings.append("Bytes after the bearer capability are not FF")
        if warnings:
            output["Warnings"] = warnings
        return output

    @staticmethod
    def decode_hpplmn(hex_str: str) -> dict:
        """Decode EF.HPPLMN (TS 31.102 v19.5 §4.2.6).

        One byte: '00' disables the higher-priority PLMN search, 'YZ' is
        (16Y+Z) multiples of the TS 23.122 interval n minutes (n hours for
        NB-IoT, EC-GSM-IoT and Cat-M1 devices, with a separate scale).
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "HPPLMN Hex Decode Error", "Raw": hex_str}
        if len(data) < 1:
            return {"Error": "Empty EF.HPPLMN", "Raw": hex_str}
        value = data[0]
        if value == 0:
            meaning = "No higher priority PLMN search attempts"
        else:
            meaning = f"{value} x n minutes (n per TS 23.122)"
        output = {"HPPLMN Search Interval": value, "Meaning": meaning}
        if len(data) != 1:
            output["Warning"] = f"EF.HPPLMN is {len(data)} bytes; expected 1"
        return output

    @staticmethod
    def decode_smss(hex_str: str) -> dict:
        """Decode EF.SMSS: SMS status (TS 31.102 v19.5 §4.2.28).

        Byte 1 is the last used TP-MR; byte 2 b1 = 0 means the memory
        capacity exceeded flag is set, b2..b8 are reserved and set to 1.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 2:
                return {"SMSS (Raw)": hex_str}
            output = {
                "Last Used TP-MR": data[0],
                "Memory Capacity Exceeded Flag": "set"
                if (data[1] & 0x01) == 0
                else "unset",
                "Raw": hex_str,
                "RFU": data[2:].hex().upper(),
            }
            warnings = []
            if (data[1] & 0xFE) != 0xFE:
                warnings.append("SMSS flag RFU bits 2..8 are not all one")
            if any(octet != 0xFF for octet in data[2:]):
                warnings.append("SMSS trailing RFU bytes are not FF")
            if warnings:
                output["Warnings"] = warnings
            return output
        except Exception:
            return {"SMSS (Raw)": hex_str}

    @classmethod
    def decode_sms_record(cls, hex_str: str) -> dict:
        """Decode one EF.SMS record (TS 31.102 v19.5 §4.2.25).

        Byte 1 is the status byte; the remainder opens with the
        TS-Service-Centre-Address and continues with the TPDU. That address
        is the RP-Originator / RP-Destination element of TS 24.011 v19
        §8.2.5.1 and §8.2.5.2, so its length octet counts the contents from
        the TON/NPI octet on, not the digits.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) == 0:
                return {"SMS": "Empty"}
            status = data[0]
            payload = data[1:]
            output: dict[str, Any] = {
                "Record Status": f"{status:02X}",
                "Record State": cls._decode_sms_status(status),
                "Direction": cls._sms_status_direction(status),
            }
            if (status & 0x01) == 0:
                output["TPDU (raw)"] = payload.hex().upper()
                return output
            sca_len = payload[0] if payload else 0
            if sca_len == 0:
                output["Service Centre Address"] = {"present": False, "length": 0}
                tpdu = payload[1:]
            elif sca_len == 0xFF or sca_len + 1 > len(payload):
                output["Service Centre Address"] = {
                    "present": False,
                    "raw": payload[:1].hex().upper(),
                }
                tpdu = payload[1:]
            else:
                output["Service Centre Address"] = cls._decode_address_field(
                    payload[: sca_len + 1], sc_addr=True
                )
                tpdu = payload[sca_len + 1 :]
            output["TPDU (raw)"] = tpdu.hex().upper()
            return output
        except Exception:
            return {"SMS Record (Raw)": hex_str}

    @staticmethod
    def _sms_status_direction(status: int) -> str:
        if (status & 0x01) == 0:
            return "free"
        if (status & 0x07) in (0x01, 0x03):
            return "MT"
        return "MO"

    @staticmethod
    def _decode_sms_status(status: int) -> str:
        """Name the EF.SMS status byte (TS 31.102 v19.5 §4.2.25).

        b1 = 0 is free space; b3b2b1 = 001 read, 011 to be read, 111 to be
        sent; xx101 is a sent message, with b5b4 telling whether a status
        report was requested, received and stored in EF.SMSR.
        """
        if (status & 0x01) == 0:
            return "Free"
        if (status & 0x07) == 0x01:
            return "Received Read"
        if (status & 0x07) == 0x03:
            return "Received Unread"
        if (status & 0x07) == 0x05:
            report_state = {
                0x00: "status report not requested",
                0x08: "status report requested, not yet received",
                0x10: "status report requested, received, not stored in EF.SMSR",
                0x18: "status report requested, received and stored in EF.SMSR",
            }[status & 0x18]
            return f"Stored Sent ({report_state})"
        if (status & 0x07) == 0x07:
            return "Stored Unsent"
        return "Unknown"

    @staticmethod
    def decode_smsr(hex_str: str) -> dict:
        """Decode an EF.SMSR record (TS 31.102 v19.5 §4.2.32).

        Byte 1 links the report to an EF.SMS record ('00' = empty record);
        bytes 2 to 30 hold the SMS-STATUS-REPORT TPDU, 'FF' padded.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 1:
                return {"SMSR (Raw)": hex_str}
            output = {
                "SMS Record Identifier": data[0],
                "Status Report TPDU": data[1:].hex().upper(),
            }
            if data[0] == 0:
                output["Empty"] = True
            return output
        except Exception:
            return {"SMSR (Raw)": hex_str}

    @staticmethod
    def decode_pnn(hex_str: str) -> dict:
        """Decode EF.PNN: PLMN Network Name record (3GPP TS 31.102 §4.2.58).

        Returns full-name and short-name strings decoded from TLV 0x43/0x45.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) == 0:
                return {"PNN": "Empty"}
            parsed = TlvParser.parse_padded(data)
            out = {"Raw": hex_str}
            for tag, label in ((0x43, "Full Name"), (0x45, "Short Name")):
                value = TlvParser.get_first(parsed, tag)
                if not isinstance(value, bytes):
                    continue
                decoded = _decode_network_name_ie(value)
                out[label] = decoded.get("text", "")
                out[f"{label} Details"] = decoded
            # TS 31.102 v19.5 §4.2.58: optional tag '80' carries PLMN Additional
            # Information for manual network selection, coded with one of the
            # UCS2 options of TS 31.101 (the '80'/'81'/'82' alpha forms).
            additional = TlvParser.get_first(parsed, 0x80)
            if isinstance(additional, bytes):
                text, encoding = ContentDecoder._decode_alpha_identifier(additional)
                out["PLMN Additional Information"] = text
                out["PLMN Additional Information Encoding"] = encoding
            return out
        except Exception:
            return {"PNN (Raw)": hex_str}

    @staticmethod
    def decode_opl(hex_str: str) -> dict:
        """Decode EF.OPL: Operator PLMN List record (3GPP TS 31.102 §4.2.59).

        Returns PLMN, LAC range, and PNN record number for each 8-byte record.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) < 8:
                return {
                    "Error": f"Invalid OPL record length ({len(data)}; expected at least 8)",
                    "Raw": hex_str,
                }
            if all(octet == 0xFF for octet in data):
                return {"OPL": "Empty"}
            plmn = ContentDecoder._decode_plmn_bytes(
                data[0:3],
                allow_wildcard=True,
            )
            if plmn.startswith("Invalid"):
                return {"Error": plmn, "Raw": hex_str}
            lac1 = int.from_bytes(data[3:5], "big")
            lac2 = int.from_bytes(data[5:7], "big")
            pnn_id = data[7]
            output = {
                "PLMN": plmn,
                "LAC Start": f"{lac1:04X}",
                "LAC End": f"{lac2:04X}",
                "PNN Record Identifier": pnn_id,
            }
            warnings = []
            # TS 31.102 v19.5 §4.2.59: '0000' in bytes 4-5 with 'FFFE' in
            # bytes 6-7 selects every LAC/TAC of the PLMN.
            if lac1 == 0x0000 and lac2 == 0xFFFE:
                output["LAC Range"] = "Entire range"
            elif lac1 == lac2:
                output["LAC Range"] = "Single value"
            if lac1 > lac2:
                warnings.append("LAC/TAC range start is greater than range end")
            if pnn_id == 0:
                output["PNN Source"] = "Other sources"
            elif pnn_id <= 0xFE:
                output["PNN Source"] = f"EF.PNN record {pnn_id}"
            else:
                warnings.append("PNN record identifier FF is reserved")
            if any(octet != 0xFF for octet in data[8:]):
                warnings.append("OPL trailing record bytes are not FF padding")
            if warnings:
                output["Warnings"] = warnings
            return output
        except Exception:
            return {"OPL (Raw)": hex_str}

    @staticmethod
    def decode_opl5g(hex_str: str) -> dict:
        """Decode an EF.OPL5G record (3GPP TS 31.102 §4.4.11.9)."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "OPL5G Hex Decode Error"}
        if len(data) < 10:
            return {
                "Error": (
                    f"Invalid OPL5G record length ({len(data)}; expected at least 10)"
                ),
                "Raw": hex_str,
            }
        if all(octet == 0xFF for octet in data):
            return {"OPL5G": "Empty"}

        plmn = ContentDecoder._decode_plmn_bytes(
            data[0:3],
            allow_wildcard=True,
        )
        if plmn.startswith("Invalid"):
            return {"Error": plmn, "Raw": hex_str}

        tac_start = int.from_bytes(data[3:6], "big")
        tac_end = int.from_bytes(data[6:9], "big")
        pnn_id = data[9]
        output = {
            "PLMN": plmn,
            "TAC Start": f"{tac_start:06X}",
            "TAC End": f"{tac_end:06X}",
            "PNN Record Identifier": pnn_id,
        }
        warnings = []
        # TS 31.102 v19.5 §4.4.11.9: '000000' in bytes 4-6 with 'FFFFFE' in
        # bytes 7-9 selects every TAC of the PLMN.
        if tac_start == 0x000000 and tac_end == 0xFFFFFE:
            output["TAC Range"] = "Entire range"
        elif tac_start == tac_end:
            output["TAC Range"] = "Single value"
        if tac_start > tac_end:
            warnings.append("TAC range start is greater than TAC range end")
        if pnn_id == 0:
            output["PNN Source"] = "Other sources"
        elif pnn_id <= 0xFE:
            output["PNN Source"] = f"EF.PNN record {pnn_id}"
        else:
            warnings.append("PNN record identifier FF is reserved")
        if any(octet != 0xFF for octet in data[10:]):
            warnings.append("OPL5G trailing record bytes are not FF padding")
        if warnings:
            output["Warnings"] = warnings
        return output

    @staticmethod
    def decode_spdi(hex_str: str) -> dict:
        """Decode EF.SPDI: Service Provider Display Information (3GPP TS 31.102 §4.2.66).

        Returns a list of PLMN strings from the 0xA3/0x80 TLV structure.
        """
        try:
            data = bytes.fromhex(hex_str)
            parsed = TlvParser.parse_padded(data)
            plmn_list = []
            a3 = TlvParser.get_first(parsed, 0xA3)
            if isinstance(a3, bytes):
                a3 = TlvParser.parse(a3)
            if not isinstance(a3, dict):
                return {
                    "Error": "SPDI does not contain an A3 service-provider template",
                    "Raw": hex_str,
                }
            sp_list = TlvParser.get_first(a3, 0x80)
            if isinstance(sp_list, bytes):
                if len(sp_list) % 3 != 0:
                    return {
                        "Error": f"SPDI PLMN list length is {len(sp_list)}; expected a multiple of 3",
                        "Raw": hex_str,
                    }
                for i in range(0, len(sp_list), 3):
                    chunk = sp_list[i : i + 3]
                    if chunk == b"\xff\xff\xff":
                        continue
                    decoded_plmn = ContentDecoder._decode_plmn_bytes(chunk)
                    if decoded_plmn.startswith("Invalid"):
                        return {"Error": decoded_plmn, "Raw": hex_str}
                    plmn_list.append(decoded_plmn)
            return {"Service Provider PLMN List": plmn_list, "Raw": hex_str}
        except Exception:
            return {"SPDI (Raw)": hex_str}

    @staticmethod
    def decode_epsnsc(hex_str: str) -> dict:
        """Decode EF.EPSNSC: EPS NAS Security Context (3GPP TS 31.102 §4.2.92).

        The record is one 'A0' template: '80' KSIasme, '81' K_ASME, '82' uplink
        NAS count, '83' downlink NAS count and '84' the selected NAS algorithms
        (value octet of the TS 24.301 §9.9.3.23 IE).
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "EPSNSC Hex Decode Error"}
        return ContentDecoder._decode_nas_security_context(data, system="EPS")

    @staticmethod
    def decode_gbanl(hex_str: str) -> dict:
        """Decode EF.GBANL: GBA NAF List (3GPP TS 31.102 §4.2.83, TS 31.103 §4.2.10).

        Each record is '80' NAF_ID followed by '81' B-TID. TS 33.220 §5.3.2
        builds NAF_Id as FQDN || Ua security protocol identifier, and Annex H.1
        fixes that identifier at five octets (organisation octet plus four).
        The B-TID is the NAI base64encode(RAND)@BSF_servers_domain_name of
        TS 33.220 §4.5.2, so it is rendered as text when printable.
        """
        try:
            data = bytes.fromhex(hex_str)
            parsed = TlvParser.parse_padded(data)
            naf = TlvParser.get_first(parsed, 0x80)
            b_tid = TlvParser.get_first(parsed, 0x81)
            out: Dict[str, Any] = {}
            if isinstance(naf, bytes):
                out["NAF_ID"] = naf.hex().upper()
                if len(naf) > 5:
                    fqdn_raw = naf[:-5]
                    ua_identifier = naf[-5:]
                    try:
                        fqdn = fqdn_raw.decode("utf-8")
                    except UnicodeDecodeError:
                        fqdn = ""
                    if fqdn and fqdn.isprintable():
                        out["NAF FQDN"] = fqdn
                    else:
                        out["NAF FQDN"] = fqdn_raw.hex().upper()
                    out["Ua Security Protocol Identifier"] = ua_identifier.hex().upper()
                    out["Ua Security Protocol Organization"] = (
                        ContentDecoder._ua_protocol_organization(ua_identifier[0])
                    )
                else:
                    out["Warning"] = (
                        "NAF_ID is not longer than the five-octet Ua security "
                        "protocol identifier"
                    )
            if isinstance(b_tid, bytes):
                text, encoding = ContentDecoder._utf8_or_hex_text(b_tid)
                out["B-TID"] = text
                out["B-TID Encoding"] = encoding
                out["B-TID Length"] = len(b_tid)
            return out
        except Exception:
            return {"Error": "GBANL Decode Error"}

    @staticmethod
    def decode_nafkca(hex_str: str) -> dict:
        """Decode EF.NAFKCA: NAF Key Centre Address (3GPP TS 31.102 §4.2.87).

        The ISIM copy at '6FDD' (TS 31.103 §4.2.11) has the same coding: one
        tag-'80' TLV per record carrying the UTF-8 FQDN of the NAF Key Centre.
        """
        try:
            data = bytes.fromhex(hex_str)
            parsed = TlvParser.parse_padded(data)
            val = TlvParser.get_first(parsed, 0x80)
            if isinstance(val, bytes):
                try:
                    decoded = val.decode("utf-8")
                except UnicodeDecodeError:
                    decoded = ""
                if decoded and not decoded.isprintable():
                    decoded = ""
                return {
                    "NAF Key Centre Address": decoded or val.hex().upper(),
                    "Encoding": "UTF-8" if decoded else "Raw hex",
                    "Raw": hex_str,
                }
            return {"NAFKCA (Raw)": hex_str}
        except Exception:
            return {"NAFKCA (Raw)": hex_str}

    @staticmethod
    def decode_isim_tlv80_text(hex_str: str) -> dict:
        """Decode a single tag-'80' UTF-8 text TLV.

        Shared by the ISIM files that carry one UTF-8 string per record or
        body: EF.IMPI (TS 31.103 §4.2.2), EF.DOMAIN (§4.2.3), EF.IMPU
        (§4.2.4), EF.UICCIARI (§4.2.16) and EF.WebRTCURI (§4.2.20).
        """
        try:
            data = bytes.fromhex(hex_str)
            parsed = TlvParser.parse_padded(data)
            val = TlvParser.get_first(parsed, 0x80)
            if isinstance(val, bytes):
                try:
                    text = val.decode("utf-8")
                except UnicodeDecodeError:
                    text = ""
                if text and text.isprintable():
                    return {
                        "Value": text.strip(),
                        "Encoding": "UTF-8",
                        "Raw Value": val.hex().upper(),
                    }
                return {
                    "Value": val.hex().upper(),
                    "Encoding": "Raw hex (invalid/non-printable UTF-8)",
                }
            return {"ISIM (Raw)": hex_str}
        except Exception:
            return {"ISIM (Raw)": hex_str}

    @staticmethod
    def decode_isim_ist(hex_str: str) -> dict:
        """Decode EF.IST: ISIM Service Table (3GPP TS 31.103 §4.2.7).

        Returns active and not-set service-number lists; mirrors UST layout.
        """
        # 3GPP TS 31.103 §4.2.7 -- ISIM Service Table. Mirrors the UST
        # split so operators see active *and* not-set services in the
        # decoded view.
        try:
            data = bytes.fromhex(hex_str)
        except Exception:
            return {
                "service_table": True,
                "table": "IST",
                "error": "IST (Raw)",
                "raw": hex_str,
                "active": [],
                "inactive": [],
            }

        return AdvancedDecoders._build_service_table(data, table="IST")

    @staticmethod
    def decode_isim_pcscf(hex_str: str) -> dict:
        """Decode EF.PCSCF: P-CSCF Address List (3GPP TS 31.103 §4.2.8).

        Returns a list of P-CSCF addresses extracted from TLV tag-0x80 records.
        """
        try:
            data = bytes.fromhex(hex_str)
            parsed = TlvParser.parse_padded(data)
            t80 = TlvParser.get_first(parsed, 0x80)
            if isinstance(t80, bytes) and len(t80) > 1:
                addr_type = t80[0]
                addr_raw = t80[1:]
                addr_type_map = {0x00: "FQDN", 0x01: "IPv4", 0x02: "IPv6"}
                if addr_type == 0x00:
                    try:
                        addr_text = addr_raw.decode("utf-8").strip()
                    except UnicodeDecodeError:
                        return {
                            "Error": "P-CSCF FQDN is not valid UTF-8",
                            "Raw": hex_str,
                        }
                    if not addr_text or not addr_text.isprintable():
                        return {
                            "Error": "P-CSCF FQDN is empty or non-printable",
                            "Raw": hex_str,
                        }
                elif addr_type in (0x01, 0x02):
                    expected = 4 if addr_type == 0x01 else 16
                    if len(addr_raw) != expected:
                        return {
                            "Error": f"P-CSCF {addr_type_map[addr_type]} address has {len(addr_raw)} bytes; expected {expected}",
                            "Raw": hex_str,
                        }
                    addr_text = str(ipaddress.ip_address(addr_raw))
                else:
                    addr_text = addr_raw.hex().upper()
                return {
                    "Address Type": addr_type_map.get(addr_type, f"0x{addr_type:02X}"),
                    "Address": addr_text,
                }
            return {"P-CSCF (Raw)": hex_str}
        except Exception:
            return {"P-CSCF (Raw)": hex_str}

    @staticmethod
    def decode_tlv_as_map(hex_str: str) -> dict:
        """Decode a generic BER-TLV hex blob into a nested tag-value map.

        Used for EFs that carry TLV structures without a dedicated decoder.
        """
        try:
            data = bytes.fromhex(hex_str)
            parsed = TlvParser.parse_padded(data)
            return {"TLV": ContentDecoder._tlv_to_obj(parsed)}
        except Exception:
            return {"Raw": hex_str}

    @staticmethod
    def _tlv_to_obj(node: Any) -> Any:
        if isinstance(node, dict):
            out = {}
            for k, v in node.items():
                out[f"{k:02X}" if isinstance(k, int) else str(k)] = (
                    ContentDecoder._tlv_to_obj(v)
                )
            return out
        if isinstance(node, list):
            return [ContentDecoder._tlv_to_obj(v) for v in node]
        if isinstance(node, bytes):
            return node.hex().upper()
        return node

    @staticmethod
    def decode_utf8_or_hex(hex_str: str) -> dict:
        try:
            data = bytes.fromhex(hex_str)
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                return {"Raw": hex_str, "Encoding": "Hex (invalid UTF-8)"}
            if text and not text.isprintable():
                return {"Raw": hex_str, "Encoding": "Hex (non-printable UTF-8)"}
            return {"Text": text.strip(), "Raw": hex_str, "Encoding": "UTF-8"}
        except Exception:
            return {"Raw": hex_str}

    @staticmethod
    def decode_hex_chunks(hex_str: str) -> dict:
        return {"Raw": hex_str}

    @staticmethod
    def _json_lines(title: str, obj: Dict[str, Any]) -> List[str]:
        lines = [f"{title}"]
        payload = json.dumps(obj, indent=2, ensure_ascii=True)
        for line in payload.splitlines():
            lines.append(line)
        return lines

    @staticmethod
    def _pkcs15_json_lines(file_id: str, body: Dict[str, Any]) -> List[str]:
        title = f"PKCS#15 {file_id} (JSON):"
        payload = {
            "schema": "pkcs15_decoder.v1",
            "file_id": file_id,
            "body": body,
        }
        return ContentDecoder._json_lines(title, payload)

    @staticmethod
    def _collect_octets(node: Any) -> List[bytes]:
        out: List[bytes] = []
        if isinstance(node, dict):
            for k, v in node.items():
                if k == 0x04:
                    if isinstance(v, bytes):
                        out.append(v)
                    if isinstance(v, list):
                        for item in v:
                            if isinstance(item, bytes):
                                out.append(item)
                out.extend(ContentDecoder._collect_octets(v))
            return out
        if isinstance(node, list):
            for item in node:
                out.extend(ContentDecoder._collect_octets(item))
        return out

    @staticmethod
    def decode_pkcs15_odf(hex_str: str) -> list:
        """Decode PKCS #15 EF.ODF: Object Directory File.

        Returns a list of PKCS-15 object-class dicts, each carrying the
        DER-encoded ObjectDirectoryFile path pointing to the respective EF.
        Neither PKCS #15 v1.1 nor ISO/IEC 7816-15 is in the specification
        library, so the class names below are the ones this decoder has
        always emitted and are unverified against a primary source; the tag
        values themselves are what the parsed records carry.
        """
        try:
            raw = bytes.fromhex(hex_str)
        except Exception:
            return ["PKCS15 ODF: Hex Decode Error"]
        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return ["PKCS15 ODF: Empty/Invalid"]
        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 ODF: TLV Parse Error"]
        odf_tag_map = {
            0xA0: "private_keys",
            0xA1: "public_keys",
            0xA4: "certificates",
            0xA5: "authentication_objects",
            0xA7: "data_objects",
            0xA8: "auth_keys",
            0xA9: "trust_points",
        }
        objects = []
        if isinstance(parsed, dict):
            for tag, val in parsed.items():
                entry_type = odf_tag_map.get(tag, f"tag_{tag:02X}")
                octets = ContentDecoder._collect_octets(val)
                paths = []
                refs = []
                for octet in octets:
                    if len(octet) == 2:
                        paths.append(octet.hex().upper())
                    else:
                        refs.append(octet.hex().upper())
                objects.append(
                    {
                        "entry_type": entry_type,
                        "paths": paths,
                        "references": refs,
                    }
                )
        body = {"objects": objects}
        return ContentDecoder._pkcs15_json_lines("ODF", body)

    @staticmethod
    def decode_pkcs15_dodf(hex_str: str) -> list:
        """Decode the PKCS #15 Data Object Directory File of the GlobalPlatform ARF.

        SE Access Control v1.1 §7.1.3: each oidDO entry ('A1') names an access
        control mechanism by a registered OID and carries the Path of its
        Access Control Main File; the OID decides whether the DeviceAppIDs are
        SHA-1 (DODF(1)) or SHA-256 (DODF(2)) hashes. The Annex C.3 example
        "A1 29 30 00 30 0F 0C 0D ... A1 14 30 12 06 0A <oid> 30 04 04 02 42 00"
        is the shape decoded here. PKCS #15 v1.1 itself is not in the library,
        so any other DataType shape falls back to a generic label/OID/path scan.
        """
        try:
            raw = bytes.fromhex(hex_str)
        except Exception:
            return ["PKCS15 DODF: Hex Decode Error"]
        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return ["PKCS15 DODF: Empty/Invalid"]
        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 DODF: TLV Parse Error"]

        entries: List[Dict[str, Any]] = []
        for oid_do in TlvParser.as_list(parsed.get(0xA1)):
            if not isinstance(oid_do, dict):
                continue
            # PKCS15Object {CommonObjectAttributes, CommonDataObjectAttributes,
            # [1] OidDO}: the two leading SEQUENCEs carry the label and the
            # informative applicationName (SE Access Control v1.1 §7.1.3).
            attribute_sets = [
                item
                for item in TlvParser.as_list(oid_do.get(0x30))
                if isinstance(item, dict)
            ]
            common_label = None
            if len(attribute_sets) > 0:
                common_label = TlvParser.get_first(attribute_sets[0], 0x0C)
            application_name = None
            if len(attribute_sets) > 1:
                application_name = TlvParser.get_first(attribute_sets[1], 0x0C)
            label, label_encoding = ContentDecoder._pkcs15_utf8_label(common_label)
            application_text, _ = ContentDecoder._pkcs15_utf8_label(application_name)
            type_attributes = TlvParser.get_first(oid_do, 0xA1)
            oid_do_body = None
            if isinstance(type_attributes, dict):
                oid_do_body = TlvParser.get_first(type_attributes, 0x30)
            oid_raw = None
            path_node = None
            if isinstance(oid_do_body, dict):
                oid_raw = TlvParser.get_first(oid_do_body, 0x06)
                path_node = TlvParser.get_first(oid_do_body, 0x30)
            oid_text = ContentDecoder._pkcs15_oid_text(oid_raw)
            path = ContentDecoder._pkcs15_path(path_node)
            entries.append(
                {
                    "label": label,
                    "label_encoding": label_encoding,
                    "application_name": application_text,
                    "oid_hex": oid_raw.hex().upper() if isinstance(oid_raw, bytes) else "",
                    "oid": oid_text,
                    "access_control_mechanism": ContentDecoder._SEAC_DODF_MECHANISMS.get(
                        oid_text, "Not a registered SE Access Control OID"
                    ),
                    "path": path.get("path", ""),
                    "path_index": path.get("index"),
                    "path_length": path.get("length"),
                }
            )
        if len(entries) == 0:
            entries = ContentDecoder._pkcs15_dodf_generic_entries(parsed)
        body = {"data_objects": entries}
        return ContentDecoder._pkcs15_json_lines("DODF", body)

    @staticmethod
    def _pkcs15_dodf_generic_entries(parsed: Dict[int, Any]) -> List[Dict[str, Any]]:
        """Label/OID/path scan for DODF shapes other than the ARF oidDO entry."""
        label = ""
        label_encoding = ""
        oid = ""
        label_vals = ContentDecoder._collect_tag_values(parsed, 0x0C)
        if len(label_vals) > 0:
            label, label_encoding = ContentDecoder._pkcs15_utf8_label(label_vals[0])
        oid_vals = ContentDecoder._collect_tag_values(parsed, 0x06)
        if len(oid_vals) > 0:
            oid = oid_vals[0].hex().upper()
        paths: List[str] = []
        for octet in ContentDecoder._collect_octets(parsed):
            if len(octet) == 2:
                candidate = octet.hex().upper()
                if candidate not in paths:
                    paths.append(candidate)
        entries: List[Dict[str, Any]] = []
        for path in paths:
            entries.append(
                {
                    "label": label,
                    "label_encoding": label_encoding,
                    "application_name": "",
                    "oid_hex": oid,
                    "oid": ContentDecoder._pkcs15_oid_text(
                        oid_vals[0] if len(oid_vals) > 0 else None
                    ),
                    "access_control_mechanism": "",
                    "path": path,
                    "path_index": None,
                    "path_length": None,
                }
            )
        return entries

    @staticmethod
    def _collect_tag_values(node: Any, tag: int) -> List[bytes]:
        values: List[bytes] = []
        if isinstance(node, dict):
            for key, value in node.items():
                if key == tag:
                    if isinstance(value, bytes):
                        values.append(value)
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, bytes):
                                values.append(item)
                values.extend(ContentDecoder._collect_tag_values(value, tag))
            return values
        if isinstance(node, list):
            for item in node:
                values.extend(ContentDecoder._collect_tag_values(item, tag))
        return values

    @staticmethod
    def _pkcs15_utf8_label(value: Any) -> tuple[str, str]:
        """Render a PKCS #15 UTF8String; non-printable input degrades to hex."""
        if not isinstance(value, bytes):
            return "", ""
        try:
            candidate = value.decode("utf-8")
        except UnicodeDecodeError:
            candidate = ""
        if candidate and candidate.isprintable():
            return candidate.strip(), "UTF-8"
        return value.hex().upper(), "Raw hex"

    @staticmethod
    def _pkcs15_oid_text(value: Any) -> str:
        """Dotted form of an OBJECT IDENTIFIER value, or "" when undecodable."""
        if not isinstance(value, bytes) or len(value) == 0:
            return ""
        # The SCP11 reader already implements X.690 §8.19; imported here so
        # the module-level import block stays untouched.
        from SCP11.shared.ber_tlv import decode_object_identifier

        try:
            return decode_object_identifier(value)
        except ValueError:
            return ""

    @staticmethod
    def _pkcs15_path(node: Any) -> Dict[str, Any]:
        """Decode Path ::= SEQUENCE { path OCTET STRING, index INTEGER OPTIONAL,
        length [0] INTEGER OPTIONAL } (SE Access Control v1.1 §7.1.3)."""
        result: Dict[str, Any] = {"path": "", "index": None, "length": None}
        if not isinstance(node, dict):
            return result
        path = TlvParser.get_first(node, 0x04)
        if isinstance(path, bytes):
            result["path"] = path.hex().upper()
        index = TlvParser.get_first(node, 0x02)
        if isinstance(index, bytes) and len(index) > 0:
            result["index"] = int.from_bytes(index, "big")
        length = TlvParser.get_first(node, 0x80)
        if isinstance(length, bytes) and len(length) > 0:
            result["length"] = int.from_bytes(length, "big")
        return result

    @staticmethod
    def decode_pkcs15_acm(hex_str: str) -> list:
        """Decode the Access Control Main File (GlobalPlatform SE Access Control v1.1 §7.1.4).

        AccessControlMainFile ::= SEQUENCE { refreshTag OCTET STRING (SIZE(8)),
        rulesFile Path }, so the body reads "30 L 04 08 <tag> 30 L 04 02 <path>"
        (Annex C.3 example: 30 10 04 08 01...08 30 04 04 02 43 00).
        """
        try:
            raw = bytes.fromhex(hex_str)
        except Exception:
            return ["PKCS15 ACM: Hex Decode Error"]
        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return ["PKCS15 ACM: Empty/Invalid"]
        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 ACM: TLV Parse Error"]
        values = [octet.hex().upper() for octet in ContentDecoder._collect_octets(parsed)]
        refresh_tag = ""
        rules_file: Dict[str, Any] = {"path": "", "index": None, "length": None}
        warnings: List[str] = []
        sequence = TlvParser.get_first(parsed, 0x30)
        if isinstance(sequence, dict):
            refresh_raw = TlvParser.get_first(sequence, 0x04)
            if isinstance(refresh_raw, bytes):
                refresh_tag = refresh_raw.hex().upper()
                if len(refresh_raw) != 8:
                    warnings.append(
                        f"refreshTag is {len(refresh_raw)} bytes; expected 8"
                    )
            else:
                warnings.append("refreshTag OCTET STRING is missing")
            rules_file = ContentDecoder._pkcs15_path(TlvParser.get_first(sequence, 0x30))
            if not rules_file["path"]:
                warnings.append("rulesFile Path is missing")
        else:
            warnings.append("ACMF body is not an AccessControlMainFile SEQUENCE")
        body: Dict[str, Any] = {
            "octet_strings": values,
            "acrf_path": rules_file["path"],
            "refresh_tag": refresh_tag,
            "rules_file": rules_file,
        }
        if warnings:
            body["warnings"] = warnings
        return ContentDecoder._pkcs15_json_lines("ACM", body)

    @staticmethod
    def decode_pkcs15_acrf_json(hex_str: str) -> list:
        """Decode the Access Control Rules File (GlobalPlatform SE Access Control v1.1 §7.1.5).

        The file is a list of Rule ::= SEQUENCE { target Target, conditionsFile
        Path }. Target is the CHOICE aid [0] EXPLICIT AID ("A0 L 04 L <aid>"),
        default [1] NULL ("81 00") or others [2] NULL ("82 00"), and the Path
        names the ACCF holding the conditions (Annex C.3 example:
        "30 08 81 00 30 04 04 02 43 80").
        """
        try:
            raw = bytes.fromhex(hex_str)
        except Exception:
            return ["PKCS15 ACRF: Hex Decode Error"]
        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return ["PKCS15 ACRF: Empty/Invalid"]
        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 ACRF: TLV Parse Error"]

        rules = [
            rule for rule in TlvParser.as_list(parsed.get(0x30)) if isinstance(rule, dict)
        ]
        entries: List[Dict[str, Any]] = []
        for idx, rule in enumerate(rules, start=1):
            target_type = "unknown"
            aid_ref = ""
            aid_target = TlvParser.get_first(rule, 0xA0)
            if isinstance(aid_target, dict):
                aid_octets = TlvParser.get_first(aid_target, 0x04)
                if isinstance(aid_octets, bytes):
                    aid_ref = aid_octets.hex().upper()
                    target_type = "aid"
            elif 0x81 in rule:
                target_type = "default"
            elif 0x82 in rule:
                target_type = "others"
            conditions = ContentDecoder._pkcs15_path(TlvParser.get_first(rule, 0x30))
            entries.append(
                {
                    "index": idx,
                    "target_type": target_type,
                    "aid_ref": aid_ref,
                    "accf_ref": conditions["path"],
                    "accf_index": conditions["index"],
                    "accf_length": conditions["length"],
                }
            )

        body: Dict[str, Any] = {"rules": entries}
        if len(rules) == 0:
            body["warnings"] = ["No Rule SEQUENCE found at the top level"]
        return ContentDecoder._pkcs15_json_lines("ACRF", body)

    @staticmethod
    def decode_pkcs15_accf_json(hex_str: str) -> list:
        """Decode the Access Control Conditions File (GlobalPlatform SE Access Control v1.1 §7.1.6).

        The file is a list of Condition ::= SEQUENCE { deviceAppID OCTET STRING
        (SIZE(20|32)) OPTIONAL, accessRules [0] AccessRules OPTIONAL }. An empty
        file denies every device application, a Condition without deviceAppID
        ("30 00") grants all of them, and a 20-byte DeviceAppID is a SHA-1 hash
        (DODF(1)) while a 32-byte one is SHA-256 (DODF(2)).
        """
        try:
            raw = bytes.fromhex(hex_str)
        except Exception:
            return ["PKCS15 ACCF: Hex Decode Error"]
        if len(raw) == 0 or all(octet == 0xFF for octet in raw):
            return [
                "PKCS15 ACCF: Empty/Invalid (an empty ACCF denies every device "
                "application, SE Access Control v1.1 §7.1.6)"
            ]
        try:
            parsed = TlvParser.parse_padded(raw)
        except Exception:
            return ["PKCS15 ACCF: TLV Parse Error"]

        conditions = [
            condition
            for condition in TlvParser.as_list(parsed.get(0x30))
            if isinstance(condition, dict)
        ]
        entries: List[Dict[str, Any]] = []
        for idx, condition in enumerate(conditions, start=1):
            entry: Dict[str, Any] = {
                "index": idx,
                "algo": "none",
                "hash_hex": "",
                "device_app_id": "",
                "applies_to_all_device_applications": True,
            }
            device_app_id = TlvParser.get_first(condition, 0x04)
            if isinstance(device_app_id, bytes):
                algo = "raw"
                if len(device_app_id) == 32:
                    algo = "sha256"
                if len(device_app_id) == 20:
                    algo = "sha1"
                entry["algo"] = algo
                entry["hash_hex"] = device_app_id.hex().upper()
                entry["device_app_id"] = device_app_id.hex().upper()
                entry["applies_to_all_device_applications"] = False
            access_rules = TlvParser.get_first(condition, 0xA0)
            if isinstance(access_rules, dict):
                entry["access_rules"] = ContentDecoder._pkcs15_access_rules(access_rules)
            entries.append(entry)
        body: Dict[str, Any] = {"condition_count": len(conditions), "entries": entries}
        if len(conditions) == 0:
            body["warnings"] = ["No Condition SEQUENCE found at the top level"]
        return ContentDecoder._pkcs15_json_lines("ACCF", body)

    @staticmethod
    def _pkcs15_access_rules(node: Dict[int, Any]) -> Dict[str, Any]:
        """Decode AccessRules (SE Access Control v1.1 §7.1.6, §7.2 ASN.1 module).

        With the module's IMPLICIT TAGS each CHOICE alternative keeps its own
        tag: apduAccessRule [0] wraps apduPermission [0] BOOLEAN ("80 01 xx") or
        apduFilters [1] SEQUENCE OF 8-byte OCTET STRING (4-byte header, 4-byte
        mask); nfcAccessRule [1] wraps nfcPermission [0] BOOLEAN. X.690 §8.2.2
        codes FALSE as a zero octet and TRUE as any non-zero octet.
        """
        result: Dict[str, Any] = {}
        apdu_rule = TlvParser.get_first(node, 0xA0)
        if isinstance(apdu_rule, dict):
            permission = TlvParser.get_first(apdu_rule, 0x80)
            if isinstance(permission, bytes):
                result["apdu_permission"] = any(permission)
            filters = TlvParser.get_first(apdu_rule, 0xA1)
            if isinstance(filters, dict):
                result["apdu_filters"] = [
                    {
                        "header": item[:4].hex().upper(),
                        "mask": item[4:].hex().upper(),
                    }
                    for item in TlvParser.as_list(filters.get(0x04))
                    if isinstance(item, bytes)
                ]
        nfc_rule = TlvParser.get_first(node, 0xA1)
        if isinstance(nfc_rule, dict):
            permission = TlvParser.get_first(nfc_rule, 0x80)
            if isinstance(permission, bytes):
                result["nfc_permission"] = any(permission)
        return result

    @staticmethod
    def decode_5gs_loci(hex_str: str) -> dict:
        """Decode EF.5GS3GPPLOCI / EF.5GSN3GPPLOCI (3GPP TS 31.102 §4.4.11.2, §4.4.11.3).

        Bytes 1-13 are octets 2-14 of a 5GS mobile identity IE holding a
        5G-GUTI (TS 24.501 §9.11.3.4 figure 9.11.3.4.1), bytes 14-19 the last
        visited registered TAI and byte 20 the 5GS update status (b3-b1).
        """
        try:
            data = bytes.fromhex(hex_str)
        except Exception:
            return {"Error": "5GS LOCI Hex Decode Error"}
        if len(data) != 20:
            return {"Error": f"Invalid 5GS LOCI Length ({len(data)}; expected 20)"}
        guti_raw = data[:13]
        guti_assigned = not all(octet == 0xFF for octet in guti_raw)
        guti_plmn = "Not assigned"
        if guti_assigned:
            identity_length = int.from_bytes(data[0:2], "big")
            if identity_length != 11:
                return {"Error": f"5GS GUTI length is {identity_length}; expected 11"}
            if data[2] != 0xF2:
                return {
                    "Error": f"5GS GUTI identity header is {data[2]:02X}; expected F2"
                }
            guti_plmn = ContentDecoder._decode_plmn_bytes(data[3:6])
            if guti_plmn.startswith("Invalid"):
                return {"Error": "5GS GUTI contains an invalid PLMN BCD digit"}
        tai_plmn = "Not assigned"
        if data[13:16] != b"\xff\xff\xff":
            tai_plmn = ContentDecoder._decode_plmn_bytes(data[13:16])
            if tai_plmn.startswith("Invalid"):
                return {"Error": "5GS TAI contains an invalid PLMN BCD digit"}
        status_value = data[19] & 0x07
        status = {
            0: "Updated",
            1: "Not Updated",
            2: "5U3 Roaming Not Allowed",
        }.get(status_value, f"Reserved ({status_value})")
        amf_set_pointer = int.from_bytes(data[7:9], "big")
        output = {
            "GUTI": {
                "Assigned": guti_assigned,
                "Length": int.from_bytes(data[0:2], "big"),
                "Identity Header": f"{data[2]:02X}",
                "PLMN": guti_plmn,
                "AMF Region ID": f"{data[6]:02X}",
                "AMF Set ID": amf_set_pointer >> 6,
                "AMF Pointer": amf_set_pointer & 0x3F,
                "AMF Set ID/Pointer": data[7:9].hex().upper(),
                "5G-TMSI": data[9:13].hex().upper(),
            },
            "Last Visited TAI": {
                "PLMN": tai_plmn,
                "TAC": data[16:19].hex().upper(),
            },
            "Status": status,
            "Status Byte": f"{data[19]:02X}",
        }
        if data[19] & 0xF8:
            output["Warning"] = "5GS update-status RFU bits 4..8 are non-zero"
        return output

    @staticmethod
    def decode_5gs_nsc(hex_str: str) -> dict:
        """Decode EF.5GS3GPPNSC / EF.5GSN3GPPNSC (3GPP TS 31.102 §4.4.11.4, §4.4.11.5).

        One 'A0' template per record: '80' ngKSI, '81' K_AMF, '82'/'83' uplink
        and downlink NAS counts, '84' selected 5G NAS algorithms (TS 24.501
        §9.11.3.34), '85' EPS NAS algorithms for use after mobility to EPS
        (TS 24.301 §9.9.3.23) and, in record 2 when service n°136 is available,
        '86' the PLMN.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "5GS NSC Hex Decode Error"}
        return ContentDecoder._decode_nas_security_context(data, system="5GS")

    @staticmethod
    def decode_5gs_auth_keys(hex_str: str) -> dict:
        """Decode EF.5GAUTHKEYS: 5G authentication keys (3GPP TS 31.102 §4.4.11.6).

        Tags '80' K_AUSF, '81' K_SEAF for 3GPP access, '82' K_SEAF for non-3GPP
        access, '83' SOR counter and '84' UE parameter update counter. A value
        part of 'FF...FF' means that no valid key or counter is stored.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "5GS Auth Keys Hex Decode Error"}
        out: Dict[str, Any] = {"Length": len(data), "Raw": data.hex().upper()}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            out["Status"] = "Empty"
            return out
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError:
            out["Error"] = "5G authentication keys are not a valid TLV sequence"
            return out
        warnings: List[str] = []
        key_labels = (
            (0x80, "K_AUSF"),
            (0x81, "K_SEAF (3GPP access)"),
            (0x82, "K_SEAF (non-3GPP access)"),
        )
        for tag, label in key_labels:
            value = TlvParser.get_first(parsed, tag)
            if not isinstance(value, bytes):
                warnings.append(f"{label} (tag {tag:02X}) is missing")
                continue
            entry: Dict[str, Any] = {
                "Value": value.hex().upper(),
                "Length": len(value),
                "Valid": len(value) > 0 and not all(octet == 0xFF for octet in value),
            }
            if len(value) not in (0, 32):
                entry["Warning"] = f"Key is {len(value)} bytes; expected 32"
            out[label] = entry
        counter_labels = ((0x83, "SOR Counter"), (0x84, "UE Parameter Update Counter"))
        for tag, label in counter_labels:
            value = TlvParser.get_first(parsed, tag)
            if not isinstance(value, bytes):
                warnings.append(f"{label} (tag {tag:02X}) is missing")
                continue
            if len(value) == 0 or all(octet == 0xFF for octet in value):
                out[label] = "No valid counter (FF-filled)"
                continue
            out[label] = int.from_bytes(value, "big")
            if len(value) != 2:
                warnings.append(f"{label} is {len(value)} bytes; expected 2")
        known_tags = {tag for tag, _ in key_labels} | {tag for tag, _ in counter_labels}
        unexpected = [f"{tag:02X}" for tag in parsed if tag not in known_tags]
        if unexpected:
            warnings.append("Unexpected tag(s): " + ", ".join(unexpected))
        if warnings:
            out["Warnings"] = warnings
        return out

    @staticmethod
    def decode_keys(hex_str: str) -> dict:
        """Decode EF.Keys / EF.KeysPS: KSI, CK and IK (3GPP TS 31.102 §4.2.3, §4.2.4).

        Byte 1 carries the key set identifier in b1-b3 with b4-b8 coded 0,
        bytes 2-17 the ciphering key CK and bytes 18-33 the integrity key IK.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "Keys Hex Decode Error"}
        out: Dict[str, Any] = {"Length": len(data), "Raw": data.hex().upper()}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            out["Status"] = "Empty"
            return out
        warnings: List[str] = []
        out["KSI"] = data[0] & 0x07
        if data[0] & 0xF8:
            warnings.append("KSI bits b4-b8 are not coded 0")
        out["CK"] = data[1:17].hex().upper()
        out["IK"] = data[17:33].hex().upper()
        if len(data) != 33:
            warnings.append(f"File is {len(data)} bytes; expected 33")
        if warnings:
            out["Warnings"] = warnings
        return out

    @staticmethod
    def decode_5gs_uac_aic(hex_str: str) -> dict:
        """Decode EF.UAC_AIC: Unified Access Control Access Identities Configuration (3GPP TS 31.102 §4.4.11.7).

        Returns the two assigned configuration flags and reports non-zero RFU bits.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "UAC_AIC Hex Decode Error"}
        if len(data) != 4:
            return {"Error": f"Invalid UAC_AIC Length ({len(data)}; expected 4)"}
        first = data[0]
        rfu = bytes([first & 0xFC]) + data[1:]
        output = {
            "Multimedia Priority Service": bool(first & 0x01),
            "Mission Critical Services": bool(first & 0x02),
            "Configuration Byte": f"{first:02X}",
            "RFU Bytes": rfu.hex().upper(),
            "Raw": data.hex().upper(),
        }
        if any(rfu):
            output["Warning"] = "One or more RFU bits are non-zero"
        return output

    @staticmethod
    def decode_routing_indicator(hex_str: str) -> dict:
        """Decode EF.RI: Routing Indicator (3GPP TS 31.102 §4.4.11.11).

        Returns the BCD digits from bytes 1..2 and exposes bytes 3..4 as RFU.
        """
        try:
            data = bytes.fromhex(hex_str)
            if len(data) != 4:
                return {
                    "Error": f"Invalid Routing Indicator Length ({len(data)}; expected 4)"
                }
            digits = ContentDecoder._decode_bcd_digits(
                data[:2],
                allow_dial_symbols=False,
            )
            if not 1 <= len(digits) <= 4:
                return {
                    "Error": f"Invalid Routing Indicator digit count ({len(digits)}; expected 1..4)"
                }
            output = {
                "Routing Indicator": digits,
                "Digit Count": len(digits),
                "RFU": data[2:].hex().upper(),
                "Raw": data.hex().upper(),
            }
            if data[2:] != b"\x00\x00":
                output["Warning"] = "RFU bytes are not 0000"
            return output
        except Exception as exc:
            return {"Error": f"Routing Indicator Decode Error: {exc}"}

    @staticmethod
    def decode_5gs_sor_cmci(hex_str: str) -> dict:
        """Decode EF.SOR-CMCI (3GPP TS 31.102 §4.4.11.15).

        Returns the optional tag-80 SOR-CMCI parameter object without assigning
        semantics to the TS 24.501 payload bytes.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "SOR-CMCI Hex Decode Error"}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"SOR-CMCI Rule Present": False, "Parameter Length": 0}
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError as exc:
            return {"Error": f"SOR-CMCI TLV Parse Error: {exc}"}
        unexpected_tags = [tag for tag in parsed if tag != 0x80]
        if unexpected_tags:
            rendered = ", ".join(f"{tag:X}" for tag in unexpected_tags)
            return {
                "Error": f"SOR-CMCI contains unexpected tag(s): {rendered}",
                "Raw": data.hex().upper(),
            }
        parameter_values = TlvParser.as_list(parsed.get(0x80))
        if len(parameter_values) == 0:
            return {
                "Error": "SOR-CMCI data does not contain tag 80",
                "Raw": data.hex().upper(),
            }
        if len(parameter_values) > 1:
            return {
                "Error": "SOR-CMCI data contains more than one tag-80 object",
                "Raw": data.hex().upper(),
            }
        parameters = parameter_values[0]
        if not isinstance(parameters, bytes):
            return {"Error": "SOR-CMCI tag 80 is not a primitive value"}
        return {
            "SOR-CMCI Rule Present": len(parameters) > 0,
            "Parameter Length": len(parameters),
            "Parameters": parameters.hex().upper(),
        }

    @staticmethod
    def decode_dri(hex_str: str) -> dict:
        """Decode EF.DRI: Disaster Roaming Information (3GPP TS 31.102 §4.4.11.17).

        Returns the fixed disaster-roaming indicators, wait-range bytes, and
        optional HPLMN-provided PLMN list.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "DRI Hex Decode Error"}
        if len(data) < 7:
            return {"Error": f"Invalid DRI Length ({len(data)}; expected at least 7)"}

        status = data[1]
        parameter_names = (
            "Disaster Roaming Wait Range",
            "Disaster Return Wait Range",
            "VPLMN List Applicability",
            "HPLMN PLMN List",
        )
        parameter_presence = {
            name: not bool(status & (1 << index))
            for index, name in enumerate(parameter_names)
        }
        output = {
            "Disaster Roaming Enabled": bool(data[0] & 0x01),
            "Enable Byte": f"{data[0]:02X}",
            "Parameter Indicator": f"{status:02X}",
            "Parameter Presence": parameter_presence,
            "Disaster Roaming Wait Range": data[2:4].hex().upper(),
            "Disaster Roaming Wait Range Decoded": ContentDecoder._decode_wait_range(
                data[2:4]
            ),
            "Disaster Return Wait Range": data[4:6].hex().upper(),
            "Disaster Return Wait Range Decoded": ContentDecoder._decode_wait_range(
                data[4:6]
            ),
            "VPLMN List Applicability": f"{data[6]:02X}",
            "HPLMN PLMN List": [],
            "Raw": data.hex().upper(),
        }
        warnings = []
        if data[0] & 0xFE:
            warnings.append("enable byte has non-zero RFU bits")
        if (status & 0xF0) != 0xF0:
            warnings.append("parameter-indicator RFU bits 5..8 are not all one")
        fixed_fields = (
            data[2:4],
            data[4:6],
            data[6:7],
        )
        for index, field in enumerate(fixed_fields):
            if not parameter_presence[parameter_names[index]] and any(
                octet != 0xFF for octet in field
            ):
                warnings.append(
                    f"{parameter_names[index]} is marked absent but is not FF"
                )

        suffix = data[7:]
        if suffix and not all(octet == 0xFF for octet in suffix):
            try:
                parsed = TlvParser.parse_padded(suffix)
            except ValueError as exc:
                return {"Error": f"DRI PLMN-list TLV Parse Error: {exc}"}
            unexpected_tags = [tag for tag in parsed if tag != 0x80]
            if unexpected_tags:
                rendered = ", ".join(f"{tag:X}" for tag in unexpected_tags)
                return {
                    "Error": f"DRI optional data contains unexpected tag(s): {rendered}"
                }
            plmn_values = TlvParser.as_list(parsed.get(0x80))
            if len(plmn_values) != 1 or not isinstance(plmn_values[0], bytes):
                return {"Error": "DRI optional data does not contain tag-80 PLMN list"}
            plmn_value = plmn_values[0]
            if len(plmn_value) % 3:
                return {
                    "Error": f"DRI HPLMN PLMN list length is {len(plmn_value)}; expected a multiple of 3"
                }
            plmns = []
            for offset in range(0, len(plmn_value), 3):
                encoded_plmn = plmn_value[offset : offset + 3]
                if encoded_plmn == b"\xff\xff\xff":
                    continue
                decoded_plmn = ContentDecoder._decode_plmn_bytes(encoded_plmn)
                if decoded_plmn.startswith("Invalid"):
                    return {"Error": decoded_plmn}
                plmns.append(decoded_plmn)
            output["HPLMN PLMN List"] = plmns
            if not parameter_presence["HPLMN PLMN List"]:
                warnings.append("HPLMN PLMN List is encoded but marked absent")
        elif parameter_presence["HPLMN PLMN List"]:
            warnings.append("HPLMN PLMN List is marked present but not encoded")
        if warnings:
            output["Warnings"] = warnings
        return output

    # TS 24.008 v19.5 §10.5.7.3 table 10.5.172: the GPRS timer unit in b8-b6.
    _GPRS_TIMER_UNITS: dict[int, tuple[str, int]] = {
        0: ("2 seconds", 2),
        1: ("1 minute", 60),
        2: ("1 decihour", 360),
    }

    @staticmethod
    def _decode_gprs_timer_octet(octet: int) -> Dict[str, Any]:
        """Decode one GPRS timer value octet (TS 24.008 v19.5 §10.5.7.3).

        Bits 5 to 1 are the binary timer value and bits 8 to 6 the unit: 000
        multiples of 2 seconds, 001 of 1 minute, 010 of a decihour, 111 the
        timer deactivated. Every other unit reads as multiples of 1 minute.
        """
        unit_code = (octet >> 5) & 0x07
        timer_value = octet & 0x1F
        if unit_code == 0x07:
            return {
                "raw": f"{octet:02X}",
                "unit": "deactivated",
                "value": timer_value,
                "text": "timer deactivated",
            }
        unit = ContentDecoder._GPRS_TIMER_UNITS.get(unit_code)
        if unit is None:
            # Table 10.5.172: any other unit is read as multiples of 1 minute.
            unit_name, unit_seconds = "1 minute", 60
            reserved = True
        else:
            unit_name, unit_seconds = unit
            reserved = False
        seconds = timer_value * unit_seconds
        decoded: Dict[str, Any] = {
            "raw": f"{octet:02X}",
            "unit": unit_name,
            "value": timer_value,
            "seconds": seconds,
            "text": f"{timer_value} × {unit_name} ({seconds} s)",
        }
        if reserved:
            decoded["note"] = (
                f"unit code {unit_code} is not defined; read as multiples of 1 minute"
            )
        return decoded

    @staticmethod
    def _decode_wait_range(field: bytes) -> Dict[str, Any]:
        """Decode a two-octet registration wait range (TS 24.501 v19.7 §9.11.3.84).

        EF.DRI stores the range from octet 3 of the IE onward (TS 31.102
        v19.5 §4.4.11.17), so the first octet is the minimum registration
        wait time and the second the maximum, each coded as octet 2 of the
        GPRS timer IE.
        """
        if len(field) != 2:
            return {"error": f"wait range must be two octets; got {len(field)}"}
        if field == b"\xff\xff":
            return {"present": False, "raw": "FFFF"}
        minimum = ContentDecoder._decode_gprs_timer_octet(field[0])
        maximum = ContentDecoder._decode_gprs_timer_octet(field[1])
        decoded: Dict[str, Any] = {
            "present": True,
            "raw": field.hex().upper(),
            "minimum": minimum,
            "maximum": maximum,
        }
        min_seconds = minimum.get("seconds")
        max_seconds = maximum.get("seconds")
        if isinstance(min_seconds, int) and isinstance(max_seconds, int):
            if min_seconds > max_seconds:
                decoded["warning"] = (
                    "minimum registration wait time exceeds the maximum"
                )
        return decoded

    @staticmethod
    def decode_bdn_record(hex_str: str) -> dict:
        """Decode one EF.BDN record (TS 31.102 v19.5 §4.2.44).

        The record is X+15 bytes: the X+14 EF.ADN layout followed by a
        Comparison Method Pointer naming a record of EF.CMI. Extension
        records live in EF.EXT4 and capability parameters in EF.CCP2, so the
        two identifier bytes are named for those files.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "BDN Hex Decode Error", "Raw": hex_str}
        if len(data) < 15:
            return {"Error": f"Invalid BDN record length ({len(data)}; minimum 15)"}
        if all(octet == 0xFF for octet in data):
            return {"Error": "Empty BDN record"}
        output = ContentDecoder.decode_adn_like_record(data[:-1].hex().upper())
        if "Error" in output or "ADN-like (Raw)" in output:
            return output
        output["Extension4 Record ID"] = output.pop("Ext Record ID", "")
        output["Capability/Configuration2 Record Identifier"] = output.pop(
            "Capability/Configuration Identifier", ""
        )
        output["Comparison Method Pointer"] = f"{data[-1]:02X}"
        return output

    @staticmethod
    def decode_psismsc(hex_str: str) -> dict:
        """Decode one EF.PSISMSC record (TS 31.102 v19.5 §4.5.9).

        The record holds a single URI TLV data object with tag '80' whose
        value is the SIP URI or tel URI of the SM-SC, encoded as a UTF-8
        octet string (IETF RFC 3261, RFC 3629).
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "PSISMSC Hex Decode Error", "Raw": hex_str}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"Error": "Empty PSISMSC record", "Raw": hex_str}
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError as exc:
            return {"Error": f"PSISMSC TLV Parse Error: {exc}", "Raw": hex_str}
        uri_value = TlvParser.get_first(parsed, 0x80)
        if not isinstance(uri_value, bytes):
            return {"Error": "PSISMSC record has no tag-80 URI object", "Raw": hex_str}
        try:
            uri = uri_value.decode("utf-8")
        except UnicodeDecodeError:
            return {"Error": "PSISMSC URI is not valid UTF-8", "Raw": hex_str}
        output: Dict[str, Any] = {"URI": uri, "Raw": data.hex().upper()}
        scheme = uri.split(":", 1)[0].lower() if ":" in uri else ""
        if scheme in ("sip", "sips", "tel"):
            output["URI Scheme"] = scheme
        else:
            output["Warnings"] = [
                "URI is neither a SIP URI nor a tel URI as §4.5.9 requires"
            ]
        return output

    @staticmethod
    def _decode_imei_value(value: bytes) -> Dict[str, Any]:
        """Read an IMEI or IMEISV octet string (TS 23.003 v19.7 §6.2.1, §6.2.2).

        The digits are semi-octets and an IMEI's unused final nibble is 'F'
        (TS 31.102 v19.5 §4.2.100), so an IMEI reads as 15 digits and an
        IMEISV as 16.
        """
        try:
            digits = ContentDecoder._decode_bcd_digits(
                value, allow_dial_symbols=False
            )
        except ValueError as exc:
            return {"raw": value.hex().upper(), "error": str(exc)}
        return {"raw": value.hex().upper(), "digits": digits, "length": len(digits)}

    @staticmethod
    def _decode_imei_tlv(hex_str: str, *, label: str, halves: int) -> dict:
        """Shared reader for the EF.IAL and EF.IPD pairing TLVs.

        Tag '80' carries an IMEI and tag '81' an IMEISV (TS 31.102 v19.5
        §4.2.100 and §4.2.102). ``halves`` is 2 for EF.IAL, whose value is a
        ``[lower][higher]`` range, and 1 for EF.IPD's single identity.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": f"{label} Hex Decode Error", "Raw": hex_str}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"Error": f"Empty {label} record", "Raw": hex_str}
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError as exc:
            return {"Error": f"{label} TLV Parse Error: {exc}", "Raw": hex_str}
        entries: List[Dict[str, Any]] = []
        warnings: List[str] = []
        for tag, identity in (
            (0x80, "IMEI"),
            (0x81, "IMEISV"),
        ):
            for value in TlvParser.as_list(parsed.get(tag)):
                if not isinstance(value, bytes):
                    continue
                entry: Dict[str, Any] = {"Identity Type": identity}
                if halves == 2:
                    if len(value) % 2:
                        warnings.append(
                            f"{identity} range has an odd length ({len(value)})"
                        )
                        entry["Raw"] = value.hex().upper()
                    else:
                        half = len(value) // 2
                        entry["Lower"] = ContentDecoder._decode_imei_value(value[:half])
                        entry["Higher"] = ContentDecoder._decode_imei_value(value[half:])
                else:
                    entry["Value"] = ContentDecoder._decode_imei_value(value)
                entries.append(entry)
        unexpected = [tag for tag in parsed if tag not in (0x80, 0x81)]
        if unexpected:
            warnings.append(
                "unexpected tag(s): " + ", ".join(f"{tag:02X}" for tag in unexpected)
            )
        if not entries:
            return {"Error": f"{label} record has no tag-80/81 object", "Raw": hex_str}
        output: Dict[str, Any] = {label: entries, "Raw": data.hex().upper()}
        if warnings:
            output["Warnings"] = warnings
        return output

    @staticmethod
    def decode_ial(hex_str: str) -> dict:
        """Decode one EF.IAL record: IMEI(SV) Allowed List (TS 31.102 v19.5 §4.2.100).

        Each record is one range TLV -- tag '80' for IMEI values, '81' for
        IMEISV -- whose value is the lower and then the higher bound; both
        bounds are inclusive, and an individual identity is a range whose
        two bounds are equal.
        """
        return ContentDecoder._decode_imei_tlv(hex_str, label="IMEI(SV) Ranges", halves=2)

    @staticmethod
    def decode_ipd(hex_str: str) -> dict:
        """Decode one EF.IPD record: IMEI(SV) of Pairing Device (TS 31.102 v19.5 §4.2.102)."""
        return ContentDecoder._decode_imei_tlv(hex_str, label="Pairing Identity", halves=1)

    @staticmethod
    def decode_ips(hex_str: str) -> dict:
        """Decode one EF.IPS record: IMEI(SV) Pairing Status (TS 31.102 v19.5 §4.2.101).

        Four bytes: bytes 1-2 spell "OK" or "KO" in the SMS default 7-bit
        alphabet with bit 8 set to zero, byte 3 links to a record of EF.IPD
        ('01' to 'FE') and byte 4 is reserved.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "IPS Hex Decode Error", "Raw": hex_str}
        if len(data) != 4:
            return {"Error": f"Invalid IPS record length ({len(data)}; expected 4)"}
        if all(octet == 0xFF for octet in data):
            return {"Error": "Empty IPS record", "Raw": hex_str}
        status_text = _decode_gsm7_septets(data[:2])
        status_map = {"OK": "pairing successful", "KO": "pairing not successful"}
        output: Dict[str, Any] = {
            "Status Raw": data[:2].hex().upper(),
            "Status": status_text if status_text is not None else "",
            "Status Meaning": status_map.get(status_text or "", "undefined status"),
            "EF.IPD Record Link": data[2],
            "RFU": f"{data[3]:02X}",
            "Raw": data.hex().upper(),
        }
        warnings = []
        if status_text not in status_map:
            warnings.append("status bytes are neither 'OK' nor 'KO'")
        if not 0x01 <= data[2] <= 0xFE:
            warnings.append(
                f"EF.IPD record link 0x{data[2]:02X} is outside '01' to 'FE'"
            )
        if warnings:
            output["Warnings"] = warnings
        return output

    # TS 31.102 v19.5 §4.2.103: the Home ePDG Identifier address-type octet.
    _EPDG_ADDRESS_TYPES: dict[int, str] = {0x00: "FQDN", 0x01: "IPv4", 0x02: "IPv6"}

    @staticmethod
    def decode_epdgid(hex_str: str) -> dict:
        """Decode EF.ePDGId: Home ePDG Identifier (TS 31.102 v19.5 §4.2.103).

        The file holds zero or more tag-'80' data objects, each an address
        type octet ('00' FQDN, '01' IPv4, '02' IPv6) followed by the address:
        a UTF-8 octet string for an FQDN, four octets for IPv4 and sixteen
        for IPv6.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "ePDG Identifier Hex Decode Error", "Raw": hex_str}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"Home ePDG Identifiers": [], "Empty": True, "Raw": hex_str}
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError as exc:
            return {"Error": f"ePDG Identifier TLV Parse Error: {exc}", "Raw": hex_str}
        identifiers: List[Dict[str, Any]] = []
        warnings: List[str] = []
        for value in TlvParser.as_list(parsed.get(0x80)):
            if not isinstance(value, bytes) or len(value) < 2:
                warnings.append("a tag-80 object is shorter than an address type")
                continue
            address_type = value[0]
            body = value[1:]
            entry: Dict[str, Any] = {
                "Address Type": ContentDecoder._EPDG_ADDRESS_TYPES.get(
                    address_type, f"Reserved (0x{address_type:02X})"
                )
            }
            if address_type == 0x00:
                try:
                    entry["Address"] = body.decode("utf-8")
                except UnicodeDecodeError:
                    entry["Address"] = body.hex().upper()
                    warnings.append("an ePDG FQDN is not valid UTF-8")
            elif address_type in (0x01, 0x02):
                expected = 4 if address_type == 0x01 else 16
                if len(body) != expected:
                    entry["Address"] = body.hex().upper()
                    warnings.append(
                        f"an ePDG {entry['Address Type']} address has {len(body)} "
                        f"bytes; expected {expected}"
                    )
                else:
                    entry["Address"] = str(ipaddress.ip_address(body))
            else:
                entry["Address"] = body.hex().upper()
            identifiers.append(entry)
        unexpected = [tag for tag in parsed if tag != 0x80]
        if unexpected:
            warnings.append(
                "unexpected tag(s): " + ", ".join(f"{tag:02X}" for tag in unexpected)
            )
        output: Dict[str, Any] = {
            "Home ePDG Identifiers": identifiers,
            "Raw": data.hex().upper(),
        }
        if warnings:
            output["Warnings"] = warnings
        return output

    # GlobalPlatform SE Access Control v1.1 §7.1.3: the registered oidDO
    # identifiers that mark a DODF as the ARF entry point.
    _SEAC_DODF_MECHANISMS = {
        "1.2.840.114283.200.1.1": "DODF(1): ACMF for SHA-1 DeviceAppIDs (deprecated)",
        "1.2.840.114283.200.1.2": "DODF(2): ACMF for SHA-256 DeviceAppIDs",
    }

    # TS 33.220 v19.1 Annex H.2: organisation octet of the Ua security
    # protocol identifier.
    _UA_PROTOCOL_ORGANIZATIONS = {
        0x00: "Default (unspecified protocol)",
        0x01: "3GPP",
        0x02: "3GPP2",
        0x03: "Open Mobile Alliance",
        0x04: "GSMA",
        0xFF: "Private range",
    }

    # TS 24.501 v19.7 Table 9.11.3.34.1 (5GS) and TS 24.301 v19.7
    # Table 9.9.3.23.1 (EPS): algorithm identifiers of the NAS security
    # algorithms IE.
    _NAS_ALGORITHM_NAMES = {
        "5GS": (
            {
                0: "5G-EA0 (null ciphering)",
                1: "128-5G-EA1",
                2: "128-5G-EA2",
                3: "128-5G-EA3",
                4: "5G-EA4",
                5: "5G-EA5",
                6: "5G-EA6",
                7: "5G-EA7",
            },
            {
                0: "5G-IA0 (null integrity)",
                1: "128-5G-IA1",
                2: "128-5G-IA2",
                3: "128-5G-IA3",
                4: "5G-IA4",
                5: "5G-IA5",
                6: "5G-IA6",
                7: "5G-IA7",
            },
        ),
        "EPS": (
            {
                0: "EEA0 (null ciphering)",
                1: "128-EEA1",
                2: "128-EEA2",
                3: "128-EEA3",
                4: "EEA4",
                5: "EEA5",
                6: "EEA6",
                7: "EEA7",
            },
            {
                0: "EIA0 (null integrity)",
                1: "128-EIA1",
                2: "128-EIA2",
                3: "128-EIA3",
                4: "EIA4",
                5: "EIA5",
                6: "EIA6",
                7: "EIA7",
            },
        ),
    }

    # TS 24.008 v19.5 Table 10.5.5.32, "S1 mode, NB-N1 mode, and WB-N1 mode"
    # eDRX cycle length duration per eDRX value.
    _EDRX_N1_CYCLE_SECONDS = {
        0: "5.12",
        1: "10.24",
        2: "20.48",
        3: "40.96",
        4: "61.44",
        5: "81.92",
        6: "102.4",
        7: "122.88",
        8: "143.36",
        9: "163.84",
        10: "327.68",
        11: "655.36",
        12: "1310.72",
        13: "2621.44",
        14: "5242.88",
        15: "10485.76",
    }

    # TS 33.501 v19.7 Annex C.1: SUPI protection scheme identifiers.
    _SUCI_PROTECTION_SCHEMES = {
        0x0: "null-scheme",
        0x1: "Profile <A>",
        0x2: "Profile <B>",
    }

    @staticmethod
    def _ua_protocol_organization(octet: int) -> str:
        known = ContentDecoder._UA_PROTOCOL_ORGANIZATIONS.get(octet)
        if known is not None:
            return known
        return f"Registered organisation 0x{octet:02X}"

    @staticmethod
    def _decode_nas_security_algorithms(octet: int, *, system: str) -> Dict[str, Any]:
        """Decode the value octet of a NAS security algorithms IE.

        5GS (TS 24.501 §9.11.3.34): ciphering in b8-b5, integrity in b4-b1,
        four bits each. EPS (TS 24.301 §9.9.3.23): ciphering in b7-b5,
        integrity in b3-b1, with b4 and b8 spare and coded zero.
        """
        ciphering_names, integrity_names = ContentDecoder._NAS_ALGORITHM_NAMES[system]
        if system == "EPS":
            ciphering = (octet >> 4) & 0x07
            integrity = octet & 0x07
            spare = octet & 0x88
        else:
            ciphering = (octet >> 4) & 0x0F
            integrity = octet & 0x0F
            spare = 0
        result: Dict[str, Any] = {
            "Ciphering": ciphering_names.get(ciphering, f"Reserved ({ciphering})"),
            "Integrity": integrity_names.get(integrity, f"Reserved ({integrity})"),
            "Raw": f"{octet:02X}",
        }
        if spare:
            result["Warning"] = "Spare bits b4/b8 are not coded zero"
        return result

    @staticmethod
    def _decode_nas_security_context(data: bytes, *, system: str) -> Dict[str, Any]:
        """Decode the 'A0' NAS security context template of EF.EPSNSC / EF.5GS*NSC.

        TS 31.102 v19.5 §4.2.92 (EPS) and §4.4.11.4 (5GS) share the layout;
        the 5GS template adds '85' (EPS algorithms after mobility) and '86'
        (PLMN of record 2 when service n°136 is available). §4.4.11.4 marks a
        stored 5GS context invalid when the record is 'FF'-filled, ngKSI is
        '07' or the K_AMF TLV length is '00'; §4.2.92 uses the same length rule
        for K_ASME.
        """
        is_eps = system == "EPS"
        ksi_label = "KSIasme" if is_eps else "ngKSI"
        key_label = "K_ASME" if is_eps else "K_AMF"
        out: Dict[str, Any] = {"Length": len(data), "Raw": data.hex().upper()}
        if len(data) == 0:
            out["Status"] = "Empty"
            return out
        if all(octet == 0xFF for octet in data):
            out["Status"] = "Invalid (record is FF-filled)"
            out["Valid"] = False
            return out
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError:
            out["Error"] = "NAS security context is not a valid TLV object"
            return out
        template = TlvParser.get_first(parsed, 0xA0)
        if not isinstance(template, dict):
            out["Error"] = "NAS security context does not start with tag A0"
            return out
        warnings: List[str] = []
        valid = True
        known_tags = {0x80, 0x81, 0x82, 0x83, 0x84}
        ksi_value = TlvParser.get_first(template, 0x80)
        if isinstance(ksi_value, bytes) and len(ksi_value) == 1:
            out[ksi_label] = ksi_value[0] & 0x07
            if ksi_value[0] & 0xF8:
                warnings.append(f"{ksi_label} bits b4-b8 are not coded 0")
            if not is_eps and (ksi_value[0] & 0x07) == 0x07:
                valid = False
                out["Status"] = "Invalid (ngKSI '07' marks no K_AMF available)"
        else:
            warnings.append(f"{ksi_label} (tag 80) is missing or not one byte")
        key_value = TlvParser.get_first(template, 0x81)
        if isinstance(key_value, bytes):
            out[key_label] = key_value.hex().upper()
            out[f"{key_label} Length"] = len(key_value)
            if len(key_value) == 0:
                valid = False
                out["Status"] = f"Invalid ({key_label} TLV length is 00)"
            elif len(key_value) != 32:
                warnings.append(f"{key_label} is {len(key_value)} bytes; expected 32")
        else:
            warnings.append(f"{key_label} (tag 81) is missing")
        for tag, label in ((0x82, "Uplink NAS Count"), (0x83, "Downlink NAS Count")):
            value = TlvParser.get_first(template, tag)
            if isinstance(value, bytes) and len(value) > 0:
                out[label] = int.from_bytes(value, "big")
                if len(value) != 4:
                    warnings.append(f"{label} is {len(value)} bytes; expected 4")
            else:
                warnings.append(f"{label} (tag {tag:02X}) is missing")
        algorithms = TlvParser.get_first(template, 0x84)
        if isinstance(algorithms, bytes) and len(algorithms) >= 1:
            out["NAS Security Algorithms"] = (
                ContentDecoder._decode_nas_security_algorithms(
                    algorithms[0], system=system
                )
            )
        else:
            warnings.append("Selected NAS algorithms (tag 84) are missing")
        if not is_eps:
            known_tags |= {0x85, 0x86}
            eps_algorithms = TlvParser.get_first(template, 0x85)
            if isinstance(eps_algorithms, bytes) and len(eps_algorithms) >= 1:
                out["EPS NAS Security Algorithms"] = (
                    ContentDecoder._decode_nas_security_algorithms(
                        eps_algorithms[0], system="EPS"
                    )
                )
            else:
                warnings.append("Selected EPS NAS algorithms (tag 85) are missing")
            plmn = TlvParser.get_first(template, 0x86)
            if isinstance(plmn, bytes):
                out["PLMN"] = ContentDecoder._decode_plmn_bytes(plmn)
        unexpected = [f"{tag:02X}" for tag in template if tag not in known_tags]
        if unexpected:
            warnings.append("Unexpected tag(s): " + ", ".join(unexpected))
        out["Valid"] = valid
        if warnings:
            out["Warnings"] = warnings
        return out

    @staticmethod
    def _iter_ber_tlvs(data: bytes) -> List[tuple[int, bytes]]:
        """Walk top-level definite-length TLVs without recursing into them.

        Used where a constructed tag carries a plain byte list rather than
        nested TLVs (EF.SUCI_Calc_Info 'A0'). Trailing 'FF' padding ends the
        walk; a truncated object raises ``ValueError``.
        """
        from SCP11.shared.ber_tlv import read_ber_tlv

        items: List[tuple[int, bytes]] = []
        offset = 0
        raw = bytes(data)
        while offset < len(raw):
            if all(octet == 0xFF for octet in raw[offset:]):
                break
            tag_bytes, value, _, offset = read_ber_tlv(raw, offset)
            items.append((int.from_bytes(tag_bytes, "big"), value))
        return items

    @staticmethod
    def _utf8_or_hex_text(value: bytes) -> tuple[str, str]:
        try:
            text = value.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and text.isprintable():
            return text, "UTF-8"
        return value.hex().upper(), "Raw hex"

    @staticmethod
    def decode_isim_ad(hex_str: str) -> dict:
        """Decode the ISIM EF.AD (3GPP TS 31.103 §4.2.5).

        Byte 1 is the UE operation mode, bytes 2-3 additional information and
        any further bytes RFU; unlike the USIM file there is no MNC-length byte.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "ISIM AD Hex Decode Error"}
        if len(data) < 3:
            return {
                "Error": f"Invalid ISIM AD length ({len(data)}; expected at least 3)"
            }
        modes = {
            0x00: "Normal operation",
            0x80: "Type approval operations",
            0x01: "Normal operation + specific facilities",
            0x81: "Type approval operations + specific facilities",
            0x02: "Maintenance (off line)",
        }
        mode = data[0]
        output: Dict[str, Any] = {
            "UE Operation Mode": modes.get(mode, f"RFU (0x{mode:02X})"),
            "Mode Byte": f"{mode:02X}",
            "Additional Information": data[1:3].hex().upper(),
            "Raw": data.hex().upper(),
        }
        if len(data) > 3:
            output["RFU"] = data[3:].hex().upper()
        return output

    @staticmethod
    def decode_gbabp(hex_str: str) -> dict:
        """Decode EF.GBABP: GBA bootstrapping parameters (3GPP TS 31.103 §4.2.9).

        Three length-prefixed fields: RAND (16 bytes), B-TID and key lifetime.
        RAND is rendered as hex; the B-TID (the NAI of TS 33.220 §4.5.2) and
        the lifetime are text when printable.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "GBABP Hex Decode Error"}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"GBABP": "Empty"}
        output: Dict[str, Any] = {"Length": len(data)}
        offset = 0
        for label in ("RAND", "B-TID", "Key Lifetime"):
            if offset >= len(data):
                output["Error"] = f"{label} length byte is missing"
                return output
            length = data[offset]
            offset += 1
            value = data[offset : offset + length]
            if len(value) < length:
                output["Error"] = f"{label} is truncated"
                return output
            offset += length
            if label == "RAND":
                output[label] = value.hex().upper()
            else:
                text, encoding = ContentDecoder._utf8_or_hex_text(value)
                output[label] = text
                output[f"{label} Encoding"] = encoding
            if label != "Key Lifetime":
                output[f"{label} Length"] = length
        if output.get("RAND Length") != 16:
            output["Warning"] = "RAND length is not 16"
        trailing = data[offset:]
        if trailing and any(octet != 0xFF for octet in trailing):
            output["Trailing Bytes"] = trailing.hex().upper()
        return output

    @staticmethod
    def decode_isim_imsdci(hex_str: str) -> dict:
        """Decode EF.IMSDCI: IMS Data Channel Indication (3GPP TS 31.103 §4.2.23)."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "IMSDCI Hex Decode Error"}
        if len(data) < 1:
            return {"Error": "Invalid IMSDCI length (0; expected 1)"}
        values = {
            0x00: "IMS data channel is not allowed",
            0x01: "Allowed, but not simultaneously with IMS session establishment",
            0x02: "Allowed, also simultaneously with IMS session establishment",
        }
        return {
            "IMS DC Establishment Indication": values.get(
                data[0], f"RFU (0x{data[0]:02X})"
            ),
            "Raw": data.hex().upper(),
        }

    @staticmethod
    def decode_suci_calc_info(hex_str: str) -> dict:
        """Decode EF.SUCI_Calc_Info (3GPP TS 31.102 §4.4.11.8).

        'A0' lists (protection scheme identifier, key index) byte pairs in
        priority order; a key index of 0 means no home network public key
        applies. 'A1' lists the keys as '80' identifier / '81' key pairs.
        Scheme identifiers follow TS 33.501 Annex C.1.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "SUCI_Calc_Info Hex Decode Error"}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"SUCI_Calc_Info": "Empty"}
        try:
            objects = ContentDecoder._iter_ber_tlvs(data)
        except ValueError as exc:
            return {"Error": f"SUCI_Calc_Info TLV Parse Error: {exc}"}
        schemes: List[Dict[str, Any]] = []
        keys: List[Dict[str, Any]] = []
        warnings: List[str] = []
        saw_scheme_list = False
        for tag, value in objects:
            if tag == 0xA0:
                saw_scheme_list = True
                if len(value) % 2:
                    warnings.append(
                        "Protection Scheme Identifier List has an odd byte count"
                    )
                for priority, offset in enumerate(range(0, len(value) - 1, 2), start=1):
                    identifier = value[offset]
                    scheme_id = identifier & 0x0F
                    entry: Dict[str, Any] = {
                        "Priority": priority,
                        "Scheme Identifier": scheme_id,
                        "Scheme": ContentDecoder._SUCI_PROTECTION_SCHEMES.get(
                            scheme_id, f"Reserved (0x{scheme_id:X})"
                        ),
                        "Key Index": value[offset + 1],
                    }
                    if identifier & 0xF0:
                        entry["Warning"] = "Scheme identifier RFU bits b5-b8 are not 0"
                    schemes.append(entry)
            elif tag == 0xA1:
                try:
                    key_objects = ContentDecoder._iter_ber_tlvs(value)
                except ValueError as exc:
                    return {"Error": f"Home Network Public Key List Parse Error: {exc}"}
                current: Optional[Dict[str, Any]] = None
                for key_tag, key_value in key_objects:
                    if key_tag == 0x80:
                        current = {
                            "Identifier": int.from_bytes(key_value, "big") if key_value else None,
                        }
                        keys.append(current)
                    elif key_tag == 0x81:
                        if current is None:
                            current = {"Identifier": None}
                            keys.append(current)
                        current["Public Key"] = key_value.hex().upper()
                        current["Key Length"] = len(key_value)
                        current = None
                    else:
                        warnings.append(f"Unexpected tag {key_tag:02X} in key list")
            else:
                warnings.append(f"Unexpected top-level tag {tag:02X}")
        if not saw_scheme_list:
            warnings.append("Protection Scheme Identifier List (tag A0) is missing")
        for scheme in schemes:
            key_index = scheme["Key Index"]
            if key_index and key_index > len(keys):
                warnings.append(
                    f"Key index {key_index} exceeds the {len(keys)} listed key(s)"
                )
        output: Dict[str, Any] = {
            "Protection Schemes": schemes,
            "Home Network Public Keys": keys,
            "Raw": data.hex().upper(),
        }
        if warnings:
            output["Warnings"] = warnings
        return output

    @staticmethod
    def decode_supi_nai(hex_str: str) -> dict:
        """Decode EF.SUPI_NAI (3GPP TS 31.102 §4.4.11.10).

        One TLV: '80' network specific identifier (RFC 7542 NAI, UTF-8),
        '81' global line identifier or '82' global cable identifier.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "SUPI_NAI Hex Decode Error"}
        if len(data) == 0 or all(octet == 0xFF for octet in data):
            return {"SUPI_NAI": "Empty"}
        try:
            parsed = TlvParser.parse_padded(data)
        except ValueError as exc:
            return {"Error": f"SUPI_NAI TLV Parse Error: {exc}"}
        labels = (
            (0x80, "Network Specific Identifier"),
            (0x81, "Global Line Identifier"),
            (0x82, "Global Cable Identifier"),
        )
        for tag, label in labels:
            value = TlvParser.get_first(parsed, tag)
            if not isinstance(value, bytes):
                continue
            text, encoding = ContentDecoder._utf8_or_hex_text(value)
            return {
                "SUPI Type": label,
                "SUPI": text,
                "Encoding": encoding,
                "Raw": data.hex().upper(),
            }
        return {
            "Error": "SUPI_NAI does not contain tag 80, 81 or 82",
            "Raw": data.hex().upper(),
        }

    @staticmethod
    def decode_tn3gppsnn(hex_str: str) -> dict:
        """Decode EF.TN3GPPSNN (3GPP TS 31.102 §4.4.11.13).

        Byte 1 counts the serving network name TLVs that follow; each is a
        tag-'80' UTF-8 string (the TS 33.501 §6.1.1.4 serving network name).
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "TN3GPPSNN Hex Decode Error"}
        if len(data) < 1:
            return {"Error": "Invalid TN3GPPSNN length (0; expected at least 1)"}
        count = data[0]
        remainder = data[1:]
        names: List[str] = []
        warnings: List[str] = []
        if remainder and not all(octet == 0xFF for octet in remainder):
            try:
                parsed = TlvParser.parse_padded(remainder)
            except ValueError as exc:
                return {"Error": f"TN3GPPSNN TLV Parse Error: {exc}"}
            for value in TlvParser.as_list(parsed.get(0x80)):
                if isinstance(value, bytes):
                    names.append(ContentDecoder._utf8_or_hex_text(value)[0])
            unexpected = [f"{tag:02X}" for tag in parsed if tag != 0x80]
            if unexpected:
                warnings.append("Unexpected tag(s): " + ", ".join(unexpected))
        if count == 0xFF:
            warnings.append("Count byte is FF")
        elif len(names) != count:
            warnings.append(
                f"Count byte says {count} name(s) but {len(names)} TLV(s) are encoded"
            )
        output: Dict[str, Any] = {
            "Count": count,
            "Serving Network Names": names,
            "Raw": data.hex().upper(),
        }
        if warnings:
            output["Warnings"] = warnings
        return output

    @staticmethod
    def decode_5gs_edrx(hex_str: str) -> dict:
        """Decode EF.5GSEDRX (3GPP TS 31.102 §4.4.11.18).

        Byte 1 flags the RAT (b1 NG-RAN, b3 satellite NG-RAN, other bits RFU);
        byte 2 carries the eDRX value in b4-b1 and the paging time window in
        b8-b5, coded as octet 3 of the TS 24.008 §10.5.5.32 Extended DRX
        parameters IE.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "5GSEDRX Hex Decode Error"}
        if len(data) < 2:
            return {"Error": f"Invalid 5GSEDRX length ({len(data)}; expected at least 2)"}
        rat = data[0]
        edrx_value = data[1] & 0x0F
        output: Dict[str, Any] = {
            "NG-RAN": bool(rat & 0x01),
            "Satellite NG-RAN": bool(rat & 0x04),
            "RAT Type Byte": f"{rat:02X}",
            "eDRX Value": edrx_value,
            "eDRX Cycle Length (N1 mode, seconds)": (
                ContentDecoder._EDRX_N1_CYCLE_SECONDS[edrx_value]
            ),
            "Paging Time Window": data[1] >> 4,
            "Raw": data.hex().upper(),
        }
        if rat & 0xFA:
            output["Warning"] = "RAT type RFU bits are not 0"
        return output

    @staticmethod
    def decode_5g_nswo_conf(hex_str: str) -> dict:
        """Decode EF.5GNSWO_CONF (3GPP TS 31.102 §4.4.11.19): '00' disabled, '01' enabled."""
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "5GNSWO_CONF Hex Decode Error"}
        if len(data) < 1:
            return {"Error": "Invalid 5GNSWO_CONF length (0; expected at least 1)"}
        values = {0x00: "Disabled", 0x01: "Enabled"}
        return {
            "5G NSWO Usage Indicator": values.get(data[0], f"RFU (0x{data[0]:02X})"),
            "Raw": data.hex().upper(),
        }

    @staticmethod
    def decode_mchpplmn(hex_str: str) -> dict:
        """Decode EF.MCHPPLMN (3GPP TS 31.102 §4.4.11.20).

        Byte 1 is the unsigned multiplier coefficient for the higher priority
        PLMN search via satellite NG-RAN; '00' means not defined.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "MCHPPLMN Hex Decode Error"}
        if len(data) < 1:
            return {"Error": "Invalid MCHPPLMN length (0; expected at least 1)"}
        coefficient: Any = data[0]
        if coefficient == 0:
            coefficient = "Not defined"
        return {"Multiplier Coefficient": coefficient, "Raw": data.hex().upper()}

    @staticmethod
    def decode_kausf_derivation(hex_str: str) -> dict:
        """Decode EF.KAUSF_DERIVATION (3GPP TS 31.102 §4.4.11.21).

        Byte 1 b1 selects the key used to derive K_AUSF in an SNPN: 0 EMSK,
        1 MSK; the remaining bits and any further bytes are RFU.
        """
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return {"Error": "KAUSF_DERIVATION Hex Decode Error"}
        if len(data) < 1:
            return {"Error": "Invalid KAUSF_DERIVATION length (0; expected at least 1)"}
        output: Dict[str, Any] = {
            "KAUSF Derivation in SNPN": "Use MSK" if data[0] & 0x01 else "Use EMSK",
            "Configuration Byte": f"{data[0]:02X}",
            "Raw": data.hex().upper(),
        }
        if data[0] & 0xFE:
            output["Warning"] = "Configuration byte RFU bits b2-b8 are not 0"
        if len(data) > 1:
            output["RFU"] = data[1:].hex().upper()
        return output
