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

"""CAP install sequence shared by SCP03 shell wizard 8 and the GUI action.

Builds INSTALL [for load], the LOAD blocks and INSTALL [for install and make
selectable] for a parsed CAP/IJC, sized either for an ISO transport or for
one SCP80 SMS per block, and renders the sequence as the script file both
shell runners read: ``#`` comments and one APDU per line. Also builds the
UICC System Specific Parameters object (ETSI TS 102 226 V19.0.0 clause
8.2.1.3.2.2) that grants a toolkit or file-access applet its ADF access.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from SCP03.core.cap import CapFileParser, CapParseResult

try:
    from SCP80.builder import OtaPacketBuilder

    SCP80_BUILDER_AVAIL = True
except ImportError:
    SCP80_BUILDER_AVAIL = False

# GPC v2.3.1 Table 11-56 lists Le '00' for LOAD over an ISO interface. The
# compact remote format (ETSI TS 102 226 V19.0.0 clause 5.1.1) is a T=0
# TPDU, CLA INS P1 P2 P3 Data, so an OTA script carries no Le.
ISO_LE_SUFFIX = "00"
ISO_LOAD_CHUNK_SIZE = 240
OTA_CIPHER_MODES = ("3DES", "AES")
# LOAD data octets per block when SCP80 is not importable: the builder's
# single-SMS ceiling at the 140-octet TP-UD default (98 for AES, 106 for
# 3DES) less the five TPDU header octets. The wizard tests pin these
# against ``OtaPacketBuilder.single_sms_payload_limit``.
OTA_LOAD_CHUNK_FALLBACK = {"AES": 93, "3DES": 101}
# ETSI TS 101 220 V19.0.0 Annex D Table D.1: the ISD's compact-format TAR is
# 00 00 00; a card may allocate its own, so the value is offered as a hint.
OTA_RUN_HINT = (
    "Run it from the SCP80 shell with: script <file>"
    " (set tar to the card's ISD TAR first, 000000 by ETSI TS 101 220 Annex D)"
)
ISO_RUN_HINT = "Run it from the SCP03 shell with: RUN <file>"
SCRIPT_SUFFIX = "_install.txt"


def encode_apdu_lc(data_len: int) -> str:
    """Lc as one octet, or the three-octet extended form above 255."""
    if data_len <= 0xFF:
        return f"{data_len:02X}"
    if data_len <= 0xFFFF:
        return f"00{data_len:04X}"
    raise ValueError("APDU data field exceeds extended length capability.")


def encode_ber_length(length: int) -> bytes:
    """BER definite length: one octet to 0x7F, then '81 xx' and '82 xx xx'."""
    if length < 0:
        raise ValueError("BER-TLV length cannot be negative.")
    if length <= 0x7F:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    if length <= 0xFFFF:
        return bytes([0x82]) + length.to_bytes(2, "big")
    raise ValueError("BER-TLV length exceeds two-byte definite length support.")


def normalize_cipher_mode(cipher_mode: str) -> str:
    """Canonical ``AES`` / ``3DES``, or ``ValueError`` for anything else."""
    mode = str(cipher_mode or "").strip().upper()
    if mode not in OTA_CIPHER_MODES:
        raise ValueError(f"OTA cipher mode must be one of: {', '.join(OTA_CIPHER_MODES)}.")
    return mode


def ota_load_chunk_size(cipher_mode: str) -> int:
    """LOAD data octets that keep one compact-format block inside one SMS."""
    mode = normalize_cipher_mode(cipher_mode)
    if SCP80_BUILDER_AVAIL:
        return OtaPacketBuilder.single_sms_payload_limit(mode) - 5
    return OTA_LOAD_CHUNK_FALLBACK[mode]


def default_script_path(cap_path: str) -> str:
    """``<stem>_install.txt`` next to the CAP/IJC."""
    directory = os.path.dirname(os.path.abspath(cap_path))
    stem, _extension = os.path.splitext(os.path.basename(cap_path))
    return os.path.join(directory, f"{stem}{SCRIPT_SUFFIX}")


def script_path_error(path: str) -> str | None:
    """Why a script destination cannot be written, or ``None`` when it can."""
    if len(path) == 0:
        return "Enter a file path."
    if os.path.isdir(path):
        return f"{path} is a directory; give a file name."
    parent = os.path.dirname(path) or "."
    if not os.path.isdir(parent):
        return f"Directory does not exist: {parent}"
    return None


# ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2: the UICC System Specific
# Parameters object 'EA' holds the toolkit parameters ('80'), their DAP
# ('C3'), the access parameters ('81') and the administrative access
# parameters ('82'); a 'CA' object beside an 'EA' object is answered with
# 6A80. Clause 8.2.1.3.2.2.2 grants a uicc.access.FileView applet file
# access only through the tag '81' entries, one for the shared UICC file
# system (empty AID) and one per ADF (AID of 5 to 16 octets).
TAG_APPLICATION_SPECIFIC = 0xC9
TAG_GP_SYSTEM_SPECIFIC = 0xEF
TAG_SIM_FILE_ACCESS = 0xCA
TAG_UICC_SYSTEM_SPECIFIC = 0xEA
TAG_UICC_TOOLKIT = 0x80
TAG_UICC_TOOLKIT_DAP = 0xC3
TAG_UICC_ACCESS = 0x81
TAG_UICC_ADMIN_ACCESS = 0x82
UICC_SYSTEM_PARAMETER_NAMES = {
    TAG_UICC_TOOLKIT: "UICC toolkit parameters",
    TAG_UICC_TOOLKIT_DAP: "UICC toolkit parameters DAP",
    TAG_UICC_ACCESS: "UICC access parameters",
    TAG_UICC_ADMIN_ACCESS: "UICC administrative access parameters",
}
# Clause 8.2.1.3.2.5.1: Access Domain Parameter '00' full access (no ADD),
# '02' UICC access mechanism (3-octet ADD), 'FF' no access (no ADD).
ADP_FULL_ACCESS = 0x00
ADP_UICC_ACCESS_MECHANISM = 0x02
ADP_NO_ACCESS = 0xFF
FULL_ACCESS_DOMAIN = bytes([ADP_FULL_ACCESS])
ADF_AID_MIN_LENGTH = 5
ADF_AID_MAX_LENGTH = 16
# Clause 8.2.1.3.2.2.1 field order with no resources: priority '01', no
# timers, menu text length and menu entry count '00' (so no position and
# identifier pairs), no channels, an empty MSL field, an empty TAR field,
# no services. The toolkit parameters are mandatory for an applet using
# uicc.toolkit.ToolkitInterface; without them no toolkit resource is
# reachable.
DEFAULT_UICC_TOOLKIT_PARAMETERS = bytes.fromhex("0100000000000000")
AID_LIST_NONE_WORDS = frozenset({"", "N", "NO", "NONE", "SKIP"})


def parse_aid_list(text: object) -> list[bytes]:
    """AIDs separated by commas or semicolons; ``N``, ``NONE`` or blank is none.

    Whitespace, ``:`` and ``-`` inside an AID are dropped and one ``0x``
    prefix is accepted. Each AID must be 5 to 16 octets (ETSI TS 102 226
    V19.0.0 clause 8.2.1.3.2.2.2).
    """
    raw = str(text or "").strip()
    if raw.upper() in AID_LIST_NONE_WORDS:
        return []
    aids: list[bytes] = []
    for token in raw.replace(";", ",").split(","):
        item = token.strip()
        if len(item) == 0:
            continue
        cleaned = "".join(item.split()).replace(":", "").replace("-", "")
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) % 2 != 0:
            raise ValueError(f"AID {item} must contain an even number of hex digits.")
        try:
            aid = bytes.fromhex(cleaned)
        except ValueError as error:
            raise ValueError(f"AID {item} contains non-hexadecimal characters.") from error
        if not ADF_AID_MIN_LENGTH <= len(aid) <= ADF_AID_MAX_LENGTH:
            raise ValueError(
                f"AID {item} is {len(aid)} bytes; an ADF AID is "
                f"{ADF_AID_MIN_LENGTH} to {ADF_AID_MAX_LENGTH} bytes."
            )
        aids.append(aid)
    return aids


def access_domain_entry(aid: bytes, access_domain: bytes) -> bytes:
    """One ``L(AID) AID L(AD) AD L(DAP) DAP`` entry with an empty DAP (clause 8.2.1.3.2.2.2)."""
    return bytes([len(aid)]) + aid + bytes([len(access_domain)]) + access_domain + b"\x00"


def build_access_parameters(
    tag: int, adf_aids: list[bytes], access_domain: bytes = FULL_ACCESS_DOMAIN
) -> bytes:
    """Tag '81' or '82' TLV: the shared UICC file system entry, then one entry per ADF."""
    value = access_domain_entry(b"", access_domain)
    for aid in adf_aids:
        value += access_domain_entry(bytes(aid), access_domain)
    return bytes([tag]) + encode_ber_length(len(value)) + value


def build_uicc_system_parameters(
    adf_aids: list[bytes],
    *,
    toolkit: bool = True,
    access_domain: bytes = FULL_ACCESS_DOMAIN,
) -> bytes:
    """The 'EA' TLV: the default toolkit parameters (unless declined) and tag '81'."""
    payload = b""
    if toolkit:
        payload += (
            bytes([TAG_UICC_TOOLKIT, len(DEFAULT_UICC_TOOLKIT_PARAMETERS)])
            + DEFAULT_UICC_TOOLKIT_PARAMETERS
        )
    payload += build_access_parameters(TAG_UICC_ACCESS, adf_aids, access_domain)
    return bytes([TAG_UICC_SYSTEM_SPECIFIC]) + encode_ber_length(len(payload)) + payload


def iter_tlvs(data: bytes) -> list[tuple[int, bytes]]:
    """``(tag, value)`` for each one-byte-tag BER-TLV; ``ValueError`` when one does not fit."""
    items: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise ValueError(f"truncated TLV header at offset {offset}")
        tag = data[offset]
        first = data[offset + 1]
        offset += 2
        if first <= 0x7F:
            length = first
        elif first in (0x81, 0x82):
            count = first & 0x7F
            if offset + count > len(data):
                raise ValueError(f"truncated TLV length at offset {offset}")
            length = int.from_bytes(data[offset : offset + count], "big")
            offset += count
        else:
            raise ValueError(f"unsupported BER length octet {first:02X} at offset {offset - 1}")
        if offset + length > len(data):
            raise ValueError(
                f"tag {tag:02X} claims {length} bytes but {len(data) - offset} remain"
            )
        items.append((tag, bytes(data[offset : offset + length])))
        offset += length
    return items


def _holds_tag(value: bytes, tag: int) -> bool:
    try:
        return any(inner_tag == tag for inner_tag, _inner in iter_tlvs(value))
    except ValueError:
        return False


def add_uicc_system_parameters(install_params: bytes, uicc_params: bytes) -> bytes:
    """Append an 'EA' object; refuse a second 'EA' or a 'CA' object (clause 8.2.1.3.2.2)."""
    try:
        objects = iter_tlvs(install_params)
    except ValueError as error:
        raise ValueError(f"install parameters are not a TLV list: {error}") from error
    for tag, value in objects:
        if tag == TAG_UICC_SYSTEM_SPECIFIC:
            raise ValueError(
                "install parameters already carry Tag EA; answer N to the ADF AID"
                " prompt or drop that EA object."
            )
        holds_ca = tag == TAG_SIM_FILE_ACCESS
        if tag == TAG_GP_SYSTEM_SPECIFIC and _holds_tag(value, TAG_SIM_FILE_ACCESS):
            holds_ca = True
        if holds_ca:
            raise ValueError(
                "install parameters carry Tag CA, which cannot coexist with Tag EA"
                " (ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2)."
            )
    return bytes(install_params) + bytes(uicc_params)


def describe_access_domain(access_domain: bytes) -> str:
    """The clause 8.2.1.3.2.5.1 reading of an Access Domain field."""
    if len(access_domain) == 0:
        return "access domain absent"
    adp = access_domain[0]
    add = access_domain[1:]
    if adp == ADP_FULL_ACCESS and len(add) == 0:
        return "access domain 00 (full access)"
    if adp == ADP_UICC_ACCESS_MECHANISM and len(add) == 3:
        return f"access domain 02 (UICC access mechanism, ADD {add.hex().upper()})"
    if adp == ADP_NO_ACCESS and len(add) == 0:
        return "access domain FF (no access)"
    return f"access domain {access_domain.hex().upper()}"


def describe_access_parameters(value: bytes) -> list[str]:
    """One line per clause 8.2.1.3.2.2.2 entry; the raw hex when the field does not parse."""
    lines: list[str] = []
    offset = 0
    try:
        while offset < len(value):
            aid_length = value[offset]
            offset += 1
            aid = value[offset : offset + aid_length]
            offset += aid_length
            domain_length = value[offset]
            offset += 1
            domain = value[offset : offset + domain_length]
            offset += domain_length
            dap_length = value[offset]
            offset += 1
            dap = value[offset : offset + dap_length]
            offset += dap_length
            if len(aid) != aid_length or len(domain) != domain_length or len(dap) != dap_length:
                raise ValueError("entry runs past the field")
            target = "UICC file system"
            if len(aid) > 0:
                target = f"ADF {aid.hex().upper()}"
            line = f"{target}: {describe_access_domain(domain)}"
            if len(dap) > 0:
                line += f", DAP {dap.hex().upper()}"
            lines.append(line)
    except (IndexError, ValueError):
        return [f"entries (not decoded): {value.hex().upper()}"]
    if len(lines) == 0:
        return ["no entries"]
    return lines


def describe_uicc_toolkit_parameters(value: bytes) -> str:
    """The clause 8.2.1.3.2.2.1 fields in order; the raw hex when the field is short."""
    try:
        priority = value[0]
        timers = value[1]
        text_length = value[2]
        menu_count = value[3]
        offset = 4
        menu = value[offset : offset + 2 * menu_count]
        if len(menu) != 2 * menu_count:
            raise ValueError("menu entries run past the field")
        offset += 2 * menu_count
        channels = value[offset]
        offset += 1
        msl_length = value[offset]
        offset += 1
        msl = value[offset : offset + msl_length]
        if len(msl) != msl_length:
            raise ValueError("MSL runs past the field")
        offset += msl_length
        tar_length = value[offset]
        offset += 1
        tars = value[offset : offset + tar_length]
        if len(tars) != tar_length:
            raise ValueError("TAR values run past the field")
        offset += tar_length
    except (IndexError, ValueError):
        return f"fields (not decoded): {value.hex().upper()}"
    parts = [
        f"priority {priority:02X}",
        f"timers {timers:02X}",
        f"menu text length {text_length:02X}",
        f"menu entries {menu_count:02X}",
    ]
    if len(menu) > 0:
        parts.append(f"menu position and identifier {menu.hex().upper()}")
    parts.append(f"channels {channels:02X}")
    parts.append("MSL none" if len(msl) == 0 else f"MSL {msl.hex().upper()}")
    parts.append("TAR none" if len(tars) == 0 else f"TAR {tars.hex().upper()}")
    if offset < len(value):
        parts.append(f"services {value[offset]:02X}")
    return ", ".join(parts)


def _describe_uicc_system_parameters(value: bytes) -> list[str]:
    try:
        inner = iter_tlvs(value)
    except ValueError:
        return [f"    (not decoded): {value.hex().upper()}"]
    lines: list[str] = []
    for tag, field in inner:
        name = UICC_SYSTEM_PARAMETER_NAMES.get(tag, f"tag {tag:02X}")
        length_hex = encode_ber_length(len(field)).hex().upper()
        if tag == TAG_UICC_TOOLKIT:
            lines.append(
                f"    80 {length_hex} {field.hex().upper()} -- {name}:"
                f" {describe_uicc_toolkit_parameters(field)}"
            )
        elif tag in (TAG_UICC_ACCESS, TAG_UICC_ADMIN_ACCESS):
            lines.append(f"    {tag:02X} {length_hex} -- {name} (clause 8.2.1.3.2.2.2)")
            for entry in describe_access_parameters(field):
                lines.append(f"      {entry}")
        else:
            lines.append(f"    {tag:02X} {length_hex} -- {name}: {field.hex().upper()}")
    return lines


def describe_install_params(install_params: bytes) -> list[str]:
    """Comment lines naming each install parameter object; never raises.

    The 'EA' object is decoded down to each ADF and its access domain so the
    script shows what the applet may touch; a field that does not parse is
    printed as hex.
    """
    if len(install_params) == 0:
        return ["Install parameters: none"]
    try:
        objects = iter_tlvs(install_params)
    except ValueError:
        return [f"Install parameters (not a TLV list): {install_params.hex().upper()}"]
    lines = ["Install parameters:"]
    has_uicc_parameters = False
    for tag, value in objects:
        length_hex = encode_ber_length(len(value)).hex().upper()
        if tag == TAG_APPLICATION_SPECIFIC:
            detail = "empty"
            if len(value) > 0:
                detail = value.hex().upper()
            lines.append(f"  C9 {length_hex} -- application specific parameters, {detail}")
        elif tag == TAG_GP_SYSTEM_SPECIFIC:
            lines.append(
                f"  EF {length_hex} -- GP system specific parameters: {value.hex().upper()}"
            )
        elif tag == TAG_SIM_FILE_ACCESS:
            lines.append(
                f"  CA {length_hex} -- SIM file access and toolkit parameters:"
                f" {value.hex().upper()}"
            )
        elif tag == TAG_UICC_SYSTEM_SPECIFIC:
            has_uicc_parameters = True
            lines.append(
                f"  EA {length_hex} -- UICC system specific parameters"
                " (ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2)"
            )
            lines.extend(_describe_uicc_system_parameters(value))
        else:
            lines.append(f"  {tag:02X} {length_hex} -- {value.hex().upper()}")
    if not has_uicc_parameters:
        lines.append(
            "  no EA object: a UICC toolkit or file-access applet gets no toolkit"
            " resources and no file access (ETSI TS 102 226 V19.0.0 clauses"
            " 8.2.1.3.2.2.1 and 8.2.1.3.2.2.2)"
        )
    return lines


@dataclass(frozen=True)
class InstallSequence:
    """The three-step install sequence for one CAP, ready to print or save."""

    package_aid: str
    applet_aid: str
    module_aid: str
    privileges: str
    install_params: str
    ota: bool
    cipher_mode: str
    chunk_size: int
    install_load_apdu: str
    load_apdus: tuple[str, ...]
    install_apdu_body: str

    @property
    def le_suffix(self) -> str:
        if self.ota:
            return ""
        return ISO_LE_SUFFIX

    @property
    def install_apdu(self) -> str:
        """INSTALL [for install and make selectable] as the script carries it."""
        return f"{self.install_apdu_body}{self.le_suffix}"

    @property
    def install_apdu_iso(self) -> str:
        """The same command in the ISO case 4 form the direct path transmits."""
        return f"{self.install_apdu_body}{ISO_LE_SUFFIX}"

    @property
    def apdus(self) -> tuple[str, ...]:
        return (self.install_load_apdu, *self.load_apdus, self.install_apdu)

    @property
    def run_hint(self) -> str:
        if self.ota:
            return OTA_RUN_HINT
        return ISO_RUN_HINT

    @property
    def format_summary(self) -> str:
        if self.ota:
            return (
                "SCP80 compact remote format (ETSI TS 102 226 V19.0.0 clause 5.1.1):"
                f" {self.cipher_mode} keyset, {self.chunk_size} LOAD data octets per SMS, no Le"
            )
        return (
            "ISO case 4 APDUs with Le '00' (GlobalPlatform Card Specification"
            f" v2.3.1 Table 11-56), {self.chunk_size} LOAD data octets per block"
        )


def build_install_load_apdu(package_aid: bytes, le_suffix: str) -> str:
    """INSTALL [for load]: the Load File AID, then empty SD AID, hash, params and token."""
    data = bytearray([len(package_aid)])
    data.extend(package_aid)
    data.extend(b"\x00\x00\x00\x00")
    return f"80E60200{encode_apdu_lc(len(data))}{data.hex().upper()}{le_suffix}"


def build_install_apdu_body(
    package_aid: bytes,
    module_aid: bytes,
    applet_aid: bytes,
    privileges: bytes,
    install_params: bytes,
) -> str:
    """INSTALL [for install and make selectable] (P1=0C) without its Le."""
    data = bytearray([len(package_aid)])
    data.extend(package_aid)
    data.append(len(module_aid))
    data.extend(module_aid)
    data.append(len(applet_aid))
    data.extend(applet_aid)
    data.append(len(privileges))
    data.extend(privileges)
    # GPC v2.3.1 Table 11-43: the Install Parameters field carries a BER
    # length; the token length '00' follows it.
    data.extend(encode_ber_length(len(install_params)))
    data.extend(install_params)
    data.append(0x00)
    return f"80E60C00{encode_apdu_lc(len(data))}{data.hex().upper()}"


def plan_install_sequence(
    parsed: CapParseResult,
    *,
    applet_aid_hex: str,
    module_aid_hex: str,
    privileges_hex: str,
    install_params_hex: str,
    ota: bool,
    cipher_mode: str = "AES",
) -> InstallSequence:
    """Plan the sequence; ``cipher_mode`` only sizes the OTA blocks."""
    package_aid = bytes(parsed.package_aid)
    applet_aid = bytes.fromhex(applet_aid_hex)
    module_aid = bytes.fromhex(module_aid_hex)
    privileges = bytes.fromhex(privileges_hex)
    install_params = bytes.fromhex(install_params_hex)

    mode = ""
    chunk_size = ISO_LOAD_CHUNK_SIZE
    le_suffix = ISO_LE_SUFFIX
    if ota:
        mode = normalize_cipher_mode(cipher_mode)
        chunk_size = ota_load_chunk_size(mode)
        le_suffix = ""

    chunks = CapFileParser.plan_load_chunks(parsed, chunk_size)
    load_apdus = []
    last_index = len(chunks) - 1
    for index, chunk in enumerate(chunks):
        p1 = 0x00
        if index >= last_index:
            p1 = 0x80
        p2 = index % 256
        payload = bytes(chunk.payload)
        load_apdus.append(
            f"80E8{p1:02X}{p2:02X}{len(payload):02X}{payload.hex().upper()}{le_suffix}"
        )

    return InstallSequence(
        package_aid=package_aid.hex().upper(),
        applet_aid=applet_aid.hex().upper(),
        module_aid=module_aid.hex().upper(),
        privileges=privileges.hex().upper(),
        install_params=install_params.hex().upper(),
        ota=ota,
        cipher_mode=mode,
        chunk_size=chunk_size,
        install_load_apdu=build_install_load_apdu(package_aid, le_suffix),
        load_apdus=tuple(load_apdus),
        install_apdu_body=build_install_apdu_body(
            package_aid, module_aid, applet_aid, privileges, install_params
        ),
    )


def render_install_script(plan: InstallSequence, cap_path: str) -> list[str]:
    """Script lines: a ``#`` header naming the CAP and the format, then the APDUs.

    ``script`` in the SCP80 shell and ``RUN`` in the SCP03 shell both drop
    ``#`` comments and take a bare hex line as one command, so the header
    travels with the sequence.
    """
    lines = [
        f"# Full CAP install sequence for {os.path.basename(cap_path)}",
        f"# Package AID {plan.package_aid}, applet AID {plan.applet_aid}",
        f"# {plan.format_summary}",
        f"# {plan.run_hint}",
        "# 1. INSTALL [for load]",
        plan.install_load_apdu,
        f"# 2. LOAD ({len(plan.load_apdus)} blocks)",
    ]
    lines.extend(plan.load_apdus)
    lines.append("# 3. INSTALL [for install and make selectable] (P1=0C)")
    for line in describe_install_params(bytes.fromhex(plan.install_params)):
        lines.append(f"#    {line}")
    lines.append(plan.install_apdu)
    return lines


def write_install_script(path: str, lines: list[str]) -> None:
    """Write the script; an ``OSError`` reaches the caller."""
    with open(path, "w", encoding="utf-8") as out:
        out.write("\n".join(lines) + "\n")
