# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SGP.32 eIM Configuration Data, ES10b.AddInitialEim and eUICCMemoryReset codecs.

EimConfigurationData (SGP.32 v1.3 §2.11.1.1.1), AddInitialEimRequest 'BF57'
(§5.9.4) and EuiccMemoryResetRequest 'BF64' (§5.9.5) are built here as bytes,
next to the two response decoders and the APDU sequence of one AddInitialEim
run: TERMINAL CAPABILITY declaring the IPAd, MANAGE CHANNEL, SELECT ISD-R, the
eUICCMemoryReset that clears the eIM Configuration Data, then the
AddInitialEim STORE DATA blocks. Nothing here reaches a card or a file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Sequence

from SCP11.shared.ber_tlv import encode_ber_length, read_ber_tlv, read_single_ber_tlv, retag_sequence
from yggdrasim_common.apdu_chunking import MAX_SHORT_APDU_DATA, cla_for_logical_channel, plan_chunked_apdus

EIM_ID_TYPES: dict[str, int] = {
    "eimIdTypeOid": 1,
    "eimIdTypeFqdn": 2,
    "eimIdTypeProprietary": 3,
}
EIM_ID_TYPE_NAMES: dict[int, str] = {code: name for name, code in EIM_ID_TYPES.items()}

# EimSupportedProtocol named bits, bit 0 first (SGP.32 v1.3 §2.11.1.1.1, §4.2).
EIM_SUPPORTED_PROTOCOL_BITS: tuple[str, ...] = (
    "eimRetrieveHttps",
    "eimRetrieveCoaps",
    "eimInjectHttps",
    "eimInjectCoaps",
    "eimProprietary",
)

# EuiccMemoryResetRequest resetOptions named bits, bit 0 first (SGP.32 v1.3 §5.9.5).
MEMORY_RESET_OPTION_BITS: tuple[str, ...] = (
    "deleteOperationalProfiles",
    "deleteFieldLoadedTestProfiles",
    "resetDefaultSmdpAddress",
    "deletePreLoadedTestProfiles",
    "deleteProvisioningProfiles",
    "resetEimConfigData",
    "resetImmediateEnableConfig",
)

# Every AddInitialEim run resets these first: §5.9.4 refuses the request with
# associatedEimAlreadyExists while any eIM Configuration Data is stored.
# Encodes as BF64 04 82 02 01 06; no Profile is deleted.
ADD_INITIAL_EIM_RESET_OPTIONS: tuple[str, ...] = (
    "resetEimConfigData",
    "resetImmediateEnableConfig",
)

KEY_FORM_CERTIFICATE = "certificate"
KEY_FORM_PUBLIC_KEY = "public_key"
KEY_FORMS: tuple[str, ...] = (KEY_FORM_CERTIFICATE, KEY_FORM_PUBLIC_KEY)

# §4.3: the eimId SHALL NOT exceed 128 bytes.
EIM_ID_MAX_OCTETS = 128
# §2.11.1.1.1: an eUICC handles counter values at least up to 8388607.
COUNTER_VALUE_GUARANTEED_MAX = 0x7FFFFF

# SGP.02 v4.2 §2.2.3.
ISD_R_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
# TS 102 221 v18.4 §11.1.19: template 'A9' carrying tag '84' (Table 11.20c),
# whose b1 declares the IPAd (SGP.32 v1.3 §3.8.2 Table 6). The eUICC enables
# the ES10 functions only after that declaration.
TERMINAL_CAPABILITY_IPAD = bytes.fromhex("80AA000005A903840101")
# TS 102 221 v18.4 §11.1.17: P2 '00' lets the UICC assign the channel, lowest
# free number first; no command can request a particular number on open.
MANAGE_CHANNEL_OPEN = bytes.fromhex("0070000001")
# The channel an AddInitialEim script runs on: the one MANAGE CHANNEL assigns
# when no other logical channel is open.
SCRIPT_LOGICAL_CHANNEL = 1

ADD_INITIAL_EIM_ERRORS: dict[int, str] = {
    1: "insufficientMemory",
    2: "associatedEimAlreadyExists",
    3: "ciPKUnknown",
    5: "invalidAssociationToken",
    6: "counterValueOutOfRange",
    7: "commandError",
    127: "undefinedError",
}
RESET_RESULTS: dict[int, str] = {
    0: "ok",
    1: "nothingToDelete",
    5: "catBusy",
    104: "ecallActive",
    127: "undefinedError",
}
RESET_EIM_RESULTS: dict[int, str] = {
    0: "ok",
    1: "nothingToDelete",
    2: "eimResetNotSupported",
    127: "undefinedError",
}
RESET_IMMEDIATE_ENABLE_CONFIG_RESULTS: dict[int, str] = {
    0: "ok",
    1: "resetIECNotSupported",
    127: "undefinedError",
}

_OID_TEXT = re.compile(r"^[0-2](\.(0|[1-9][0-9]*))+$")
_FQDN_LABEL = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class KeyData:
    """One eimPublicKeyData or trustedPublicKeyDataTls value.

    ``der`` is a DER Certificate for the certificate form and a DER
    SubjectPublicKeyInfo for the public-key form.
    """

    form: str
    der: bytes


@dataclass(frozen=True)
class EimConfigurationData:
    """The members of one EimConfigurationData; ``None`` leaves a member out."""

    eim_id: str | None
    eim_fqdn: str | None = None
    eim_id_type: int | None = None
    counter_value: int | None = None
    association_token: int | None = None
    eim_public_key_data: KeyData | None = None
    trusted_public_key_data_tls: KeyData | None = None
    eim_supported_protocol: tuple[str, ...] | None = None
    euicc_ci_pk_id: bytes | None = None
    indirect_profile_download: bool = False


@dataclass(frozen=True)
class ScriptStep:
    """One command APDU of an AddInitialEim run, with what it does."""

    label: str
    apdu: bytes

    @property
    def apdu_hex(self) -> str:
        return self.apdu.hex().upper()


@dataclass(frozen=True)
class AddInitialEimResult:
    """A decoded AddInitialEimResponse ('BF57')."""

    ok: bool
    entries: tuple[str, ...]
    error_code: int | None = None

    @property
    def error_name(self) -> str:
        if self.error_code is None:
            return ""
        return ADD_INITIAL_EIM_ERRORS.get(self.error_code, "unknown")


@dataclass(frozen=True)
class MemoryResetResult:
    """A decoded EuiccMemoryResetResponse ('BF64'); ``None`` marks an absent member."""

    reset_result: int | None
    reset_eim_result: int | None = None
    reset_immediate_enable_config_result: int | None = None

    @property
    def allows_add_initial_eim(self) -> bool:
        """False only when resetResult names an error; ok and nothingToDelete both clear the way."""
        return self.reset_result is None or self.reset_result in (0, 1)

    def describe(self) -> list[str]:
        lines: list[str] = []
        lines.append(_describe_result("resetResult", self.reset_result, RESET_RESULTS))
        if self.reset_eim_result is not None:
            lines.append(_describe_result("resetEimResult", self.reset_eim_result, RESET_EIM_RESULTS))
        if self.reset_immediate_enable_config_result is not None:
            lines.append(
                _describe_result(
                    "resetImmediateEnableConfigResult",
                    self.reset_immediate_enable_config_result,
                    RESET_IMMEDIATE_ENABLE_CONFIG_RESULTS,
                )
            )
        return lines


def _describe_result(label: str, value: int | None, names: dict[int, str]) -> str:
    if value is None:
        return f"{label}: absent"
    return f"{label}: {names.get(value, 'unknown')} ({value})"


def _tlv(tag: bytes, value: bytes) -> bytes:
    return bytes(tag) + encode_ber_length(len(value)) + bytes(value)


def encode_der_integer(value: int) -> bytes:
    """Return the contents octets of a DER INTEGER.

    X.690 (02/2021) §8.3.2-8.3.3: two's complement in the fewest octets, so
    128 needs a leading '00' and -1 is the single octet 'FF'.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"INTEGER value must be an int, got {type(value).__name__}.")
    magnitude = value if value >= 0 else ~value
    return value.to_bytes(magnitude.bit_length() // 8 + 1, "big", signed=True)


def decode_der_integer(contents: bytes) -> int:
    """Read the contents octets of an INTEGER as two's complement."""
    raw = bytes(contents or b"")
    if len(raw) == 0:
        raise ValueError("An INTEGER needs at least one contents octet.")
    return int.from_bytes(raw, "big", signed=True)


def encode_named_bit_string(names: Iterable[str], catalogue: Sequence[str]) -> bytes:
    """Return the contents octets of a named-bit BIT STRING under DER.

    The initial octet counts the unused bits of the last octet (X.690 (02/2021)
    §8.6.2.2), trailing 0 bits are removed (§11.2.2), and an empty value is
    the initial octet '00' alone (§8.6.2.3).
    """
    positions: set[int] = set()
    for name in names:
        try:
            positions.add(list(catalogue).index(name))
        except ValueError as error:
            raise ValueError(f"Unknown bit {name!r}; expected one of: {', '.join(catalogue)}.") from error
    if len(positions) == 0:
        return b"\x00"
    highest = max(positions)
    octets = bytearray(highest // 8 + 1)
    for position in positions:
        octets[position // 8] |= 0x80 >> (position % 8)
    return bytes([7 - highest % 8]) + bytes(octets)


def decode_named_bit_string(contents: bytes, catalogue: Sequence[str]) -> tuple[str, ...]:
    """Return the names of the bits set in BIT STRING contents octets."""
    raw = bytes(contents or b"")
    if len(raw) == 0:
        raise ValueError("A BIT STRING needs its initial octet.")
    unused = raw[0]
    if unused > 7 or (len(raw) == 1 and unused != 0):
        raise ValueError(f"BIT STRING initial octet {unused:02X} is not valid for {len(raw) - 1} octets.")
    total_bits = (len(raw) - 1) * 8 - unused
    names: list[str] = []
    for position in range(total_bits):
        if raw[1 + position // 8] & (0x80 >> (position % 8)):
            if position < len(catalogue):
                names.append(catalogue[position])
            else:
                names.append(f"bit{position}")
    return tuple(names)


def infer_eim_id_type(eim_id: str) -> int:
    """Return the EimIdType a text eimId reads as (SGP.32 v1.3 §4.3).

    Dotted-decimal text is an OID, a dotted host name an FQDN, anything else
    proprietary. The eimId stays a UTF8String whatever its type.
    """
    text = str(eim_id or "").strip()
    if _OID_TEXT.match(text) is not None:
        return EIM_ID_TYPES["eimIdTypeOid"]
    labels = text.rstrip(".").split(".")
    if (
        len(labels) >= 2
        and len(text) <= 253
        and all(_FQDN_LABEL.match(label) is not None for label in labels)
        and labels[-1].isdigit() is False
    ):
        return EIM_ID_TYPES["eimIdTypeFqdn"]
    return EIM_ID_TYPES["eimIdTypeProprietary"]


def _encode_key_data(key: KeyData, member: str) -> bytes:
    # AUTOMATIC TAGS give the CHOICE alternatives [0] SubjectPublicKeyInfo and
    # [1] Certificate, IMPLICIT: the context tag replaces the SEQUENCE tag.
    # The member's own [5] / [6] tag on the CHOICE stays explicit around it.
    if key.form == KEY_FORM_PUBLIC_KEY:
        tag = b"\xA0"
    elif key.form == KEY_FORM_CERTIFICATE:
        tag = b"\xA1"
    else:
        raise ValueError(f"{member}: unknown key form {key.form!r}; expected one of: {', '.join(KEY_FORMS)}.")
    try:
        return retag_sequence(tag, key.der)
    except ValueError as error:
        raise ValueError(f"{member} must hold one DER SEQUENCE: {error}") from error


def encode_eim_configuration_data(entry: EimConfigurationData) -> bytes:
    """Return one EimConfigurationData SEQUENCE ('30')."""
    parts: list[bytes] = []
    if entry.eim_id is not None:
        eim_id = entry.eim_id.encode("utf-8")
        if len(eim_id) == 0 or len(eim_id) > EIM_ID_MAX_OCTETS:
            raise ValueError(f"eimId must be 1..{EIM_ID_MAX_OCTETS} bytes of UTF-8, got {len(eim_id)}.")
        parts.append(_tlv(b"\x80", eim_id))
    if entry.eim_fqdn is not None:
        parts.append(_tlv(b"\x81", entry.eim_fqdn.encode("utf-8")))
    if entry.eim_id_type is not None:
        parts.append(_tlv(b"\x82", encode_der_integer(entry.eim_id_type)))
    if entry.counter_value is not None:
        parts.append(_tlv(b"\x83", encode_der_integer(entry.counter_value)))
    if entry.association_token is not None:
        parts.append(_tlv(b"\x84", encode_der_integer(entry.association_token)))
    if entry.eim_public_key_data is not None:
        parts.append(_tlv(b"\xA5", _encode_key_data(entry.eim_public_key_data, "eimPublicKeyData")))
    if entry.trusted_public_key_data_tls is not None:
        parts.append(
            _tlv(b"\xA6", _encode_key_data(entry.trusted_public_key_data_tls, "trustedPublicKeyDataTls"))
        )
    if entry.eim_supported_protocol is not None:
        parts.append(
            _tlv(b"\x87", encode_named_bit_string(entry.eim_supported_protocol, EIM_SUPPORTED_PROTOCOL_BITS))
        )
    if entry.euicc_ci_pk_id is not None:
        parts.append(_tlv(b"\x88", bytes(entry.euicc_ci_pk_id)))
    if entry.indirect_profile_download:
        parts.append(_tlv(b"\x89", b""))
    return _tlv(b"\x30", b"".join(parts))


def encode_add_initial_eim_request(entries: Sequence[EimConfigurationData]) -> bytes:
    """Return AddInitialEimRequest: 'BF57' { eimConfigurationDataList [0] SEQUENCE OF }."""
    if len(entries) == 0:
        raise ValueError("AddInitialEim needs at least one EimConfigurationData entry.")
    rows = b"".join(encode_eim_configuration_data(entry) for entry in entries)
    return _tlv(b"\xBF\x57", _tlv(b"\xA0", rows))


def encode_euicc_memory_reset_request(options: Iterable[str] = ADD_INITIAL_EIM_RESET_OPTIONS) -> bytes:
    """Return EuiccMemoryResetRequest: 'BF64' { resetOptions [2] BIT STRING }."""
    names = tuple(options)
    if len(names) == 0:
        raise ValueError("eUICCMemoryReset needs at least one reset option.")
    return _tlv(b"\xBF\x64", _tlv(b"\x82", encode_named_bit_string(names, MEMORY_RESET_OPTION_BITS)))


def add_initial_eim_problems(entries: Sequence[EimConfigurationData]) -> list[str]:
    """Return the §5.9.4 and §4.3 rules an AddInitialEim request breaks; empty when none.

    Each entry carries eimId, counterValue and eimPublicKeyData; an
    associationToken, when present, is -1 (the request for one); eimIds are
    unique within the request.
    """
    problems: list[str] = []
    if len(entries) == 0:
        problems.append("The request carries no EimConfigurationData entry.")
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        where = f"Entry {index + 1}"
        if entry.eim_id is None or len(entry.eim_id.strip()) == 0:
            problems.append(f"{where}: eimId is mandatory (SGP.32 v1.3 §5.9.4).")
        else:
            size = len(entry.eim_id.encode("utf-8"))
            if size > EIM_ID_MAX_OCTETS:
                problems.append(f"{where}: eimId is {size} bytes; at most {EIM_ID_MAX_OCTETS} (SGP.32 v1.3 §4.3).")
            if entry.eim_id in seen:
                problems.append(f"{where}: eimId {entry.eim_id!r} repeats an earlier entry.")
            seen.add(entry.eim_id)
        if entry.counter_value is None:
            problems.append(f"{where}: counterValue is mandatory (SGP.32 v1.3 §5.9.4).")
        elif entry.counter_value < 0:
            problems.append(f"{where}: counterValue {entry.counter_value} is negative.")
        if entry.eim_public_key_data is None:
            problems.append(f"{where}: eimPublicKey or eimCertificate is mandatory (SGP.32 v1.3 §5.9.4).")
        if entry.association_token is not None and entry.association_token != -1:
            problems.append(
                f"{where}: associationToken {entry.association_token} would be refused with "
                "invalidAssociationToken; only -1 requests one (SGP.32 v1.3 §5.9.4)."
            )
        if entry.eim_supported_protocol is not None:
            unknown = [name for name in entry.eim_supported_protocol if name not in EIM_SUPPORTED_PROTOCOL_BITS]
            if unknown:
                problems.append(f"{where}: unknown eimSupportedProtocol bit(s): {', '.join(unknown)}.")
        if entry.eim_id_type == EIM_ID_TYPES["eimIdTypeFqdn"] and entry.eim_fqdn is not None:
            # A card answers such an entry commandError and stores nothing.
            problems.append(
                f"{where}: eimFqdn SHALL NOT be provided when eimIdType is eimIdTypeFqdn; the eimId is the FQDN "
                "(SGP.32 v1.3 §2.11.1.1.1)."
            )
    return problems


def add_initial_eim_script(request: bytes) -> tuple[ScriptStep, ...]:
    """Return the APDUs of one AddInitialEim run, the eUICCMemoryReset first.

    SGP.32 v1.3 §3.8.2 and §3.8.4: TERMINAL CAPABILITY declaring the IPAd,
    then MANAGE CHANNEL and SELECT ISD-R on the new channel. The reset clears
    the eIM Configuration Data AddInitialEim requires to be absent, and both
    requests travel as ES10 STORE DATA on that channel; a request longer than
    255 bytes is split into numbered blocks (SGP.22 v3.1 §5.7.2).
    """
    payload = bytes(request)
    tag, _value, _raw = read_single_ber_tlv(payload)
    if tag != b"\xBF\x57":
        raise ValueError(f"Expected an AddInitialEimRequest 'BF57', got tag {tag.hex().upper()}.")
    channel = SCRIPT_LOGICAL_CHANNEL
    select_cla = cla_for_logical_channel(channel, base=0x00)
    store_cla = cla_for_logical_channel(channel, base=0x80)
    reset = encode_euicc_memory_reset_request(ADD_INITIAL_EIM_RESET_OPTIONS)
    steps: list[ScriptStep] = [
        ScriptStep("TERMINAL CAPABILITY: IPAd supported", TERMINAL_CAPABILITY_IPAD),
        ScriptStep("MANAGE CHANNEL: open, the card assigns the channel", MANAGE_CHANNEL_OPEN),
        ScriptStep(
            f"SELECT ISD-R on channel {channel}",
            bytes([select_cla, 0xA4, 0x04, 0x00, len(ISD_R_AID)]) + ISD_R_AID,
        ),
    ]
    reset_label = "STORE DATA: eUICCMemoryReset (" + ", ".join(ADD_INITIAL_EIM_RESET_OPTIONS) + ")"
    for block in plan_chunked_apdus(reset, cla=store_cla, ins=0xE2, p1_last=0x91):
        steps.append(ScriptStep(reset_label, block.apdu))
    blocks = plan_chunked_apdus(payload, cla=store_cla, ins=0xE2, p1_last=0x91)
    for block in blocks:
        label = "STORE DATA: AddInitialEim"
        if block.total > 1:
            label += f" block {block.index + 1}/{block.total}"
        steps.append(ScriptStep(label, block.apdu))
    return tuple(steps)


def add_initial_eim_single_apdu(request: bytes) -> ScriptStep:
    """The AddInitialEimRequest as one STORE DATA command on the script's channel.

    The same header as the last block of ``add_initial_eim_script`` (P1 '91',
    P2 '00') carries the whole request. Past 255 bytes the Lc is extended,
    '00' and two length bytes: the form ``plan_oversized_command`` of
    ``yggdrasim_common.apdu_chunking`` reads back and splits into exactly the
    script's blocks, so a console that chains it, or a reader and card that
    take extended-length commands, can send it as it stands.
    """
    payload = bytes(request)
    tag, _value, _raw = read_single_ber_tlv(payload)
    if tag != b"\xBF\x57":
        raise ValueError(f"Expected an AddInitialEimRequest 'BF57', got tag {tag.hex().upper()}.")
    if len(payload) > 0xFFFF:
        raise ValueError(f"The request is {len(payload)} bytes; an extended Lc carries at most 65535.")
    header = bytes([cla_for_logical_channel(SCRIPT_LOGICAL_CHANNEL, base=0x80), 0xE2, 0x91, 0x00])
    if len(payload) <= MAX_SHORT_APDU_DATA:
        return ScriptStep(f"STORE DATA: AddInitialEim in one APDU ({len(payload)} bytes)", header + bytes([len(payload)]) + payload)
    lc = b"\x00" + len(payload).to_bytes(2, "big")
    return ScriptStep(f"STORE DATA: AddInitialEim in one APDU ({len(payload)} bytes, extended Lc)", header + lc + payload)


def decode_add_initial_eim_response(data: bytes) -> AddInitialEimResult:
    """Decode AddInitialEimResponse (SGP.32 v1.3 §5.9.4).

    The [87] tag on the CHOICE is explicit; AUTOMATIC TAGS make the
    alternatives addInitialEimOk 'A0' and addInitialEimError '81'. An ok
    entry is associationToken '84' or addOk NULL '05'.
    """
    tag, value, _raw = read_single_ber_tlv(bytes(data or b""))
    if tag != b"\xBF\x57":
        raise ValueError(f"Expected an AddInitialEimResponse 'BF57', got tag {tag.hex().upper()}.")
    choice_tag, choice_value, _choice_raw = read_single_ber_tlv(value)
    if choice_tag == b"\x81":
        return AddInitialEimResult(ok=False, entries=(), error_code=decode_der_integer(choice_value))
    if choice_tag != b"\xA0":
        raise ValueError(f"AddInitialEimResponse holds tag {choice_tag.hex().upper()}, neither 'A0' nor '81'.")
    entries: list[str] = []
    offset = 0
    while offset < len(choice_value):
        item_tag, item_value, _item_raw, offset = read_ber_tlv(choice_value, offset)
        if item_tag == b"\x84":
            entries.append(f"associationToken {decode_der_integer(item_value)}")
        elif item_tag == b"\x05" and len(item_value) == 0:
            entries.append("addOk")
        else:
            raise ValueError(f"addInitialEimOk holds tag {item_tag.hex().upper()}, neither '84' nor '05'.")
    return AddInitialEimResult(ok=True, entries=tuple(entries))


def decode_euicc_memory_reset_response(data: bytes) -> MemoryResetResult:
    """Decode EuiccMemoryResetResponse (SGP.32 v1.3 §5.9.5).

    AUTOMATIC TAGS give resetResult '80', resetEimResult '81' and
    resetImmediateEnableConfigResult '82'. An empty 'BF64' leaves every
    member absent rather than failing.
    """
    tag, value, _raw = read_single_ber_tlv(bytes(data or b""))
    if tag != b"\xBF\x64":
        raise ValueError(f"Expected an EuiccMemoryResetResponse 'BF64', got tag {tag.hex().upper()}.")
    members: dict[bytes, int] = {}
    offset = 0
    while offset < len(value):
        item_tag, item_value, _item_raw, offset = read_ber_tlv(value, offset)
        if item_tag in (b"\x80", b"\x81", b"\x82"):
            members[item_tag] = decode_der_integer(item_value)
    return MemoryResetResult(
        reset_result=members.get(b"\x80"),
        reset_eim_result=members.get(b"\x81"),
        reset_immediate_enable_config_result=members.get(b"\x82"),
    )


def verify_add_initial_eim_request(request: bytes, entries: Sequence[EimConfigurationData]) -> None:
    """Re-read an encoded AddInitialEimRequest and check it carries ``entries``.

    Raises ``ValueError`` naming the first member that does not read back as
    given, so a request leaves the builder only after it has decoded.
    """
    tag, value, _raw = read_single_ber_tlv(bytes(request))
    if tag != b"\xBF\x57":
        raise ValueError(f"Request tag is {tag.hex().upper()}, not 'BF57'.")
    list_tag, list_value, _list_raw = read_single_ber_tlv(value)
    if list_tag != b"\xA0":
        raise ValueError(f"eimConfigurationDataList tag is {list_tag.hex().upper()}, not 'A0'.")
    rows: list[bytes] = []
    offset = 0
    while offset < len(list_value):
        row_tag, row_value, _row_raw, offset = read_ber_tlv(list_value, offset)
        if row_tag != b"\x30":
            raise ValueError(f"List entry {len(rows) + 1} has tag {row_tag.hex().upper()}, not '30'.")
        rows.append(row_value)
    if len(rows) != len(entries):
        raise ValueError(f"The request carries {len(rows)} entries, {len(entries)} were given.")
    for index, (row, entry) in enumerate(zip(rows, entries)):
        _verify_row(row, entry, f"Entry {index + 1}")


def _verify_row(row: bytes, entry: EimConfigurationData, where: str) -> None:
    members: dict[bytes, bytes] = {}
    order: list[int] = []
    offset = 0
    while offset < len(row):
        tag, value, _raw, offset = read_ber_tlv(row, offset)
        if tag in members:
            raise ValueError(f"{where}: member {tag.hex().upper()} appears twice.")
        members[tag] = value
        order.append(tag[0] & 0x1F)
    if order != sorted(order):
        raise ValueError(f"{where}: members are out of SEQUENCE order.")

    def expect(tag: bytes, wanted: bytes | None, member: str) -> None:
        got = members.get(tag)
        if wanted is None and got is not None:
            raise ValueError(f"{where}: {member} is present but was left out.")
        if wanted is not None and got != wanted:
            raise ValueError(f"{where}: {member} does not read back as given.")

    expect(b"\x80", None if entry.eim_id is None else entry.eim_id.encode("utf-8"), "eimId")
    expect(b"\x81", None if entry.eim_fqdn is None else entry.eim_fqdn.encode("utf-8"), "eimFqdn")
    expect(b"\x82", None if entry.eim_id_type is None else encode_der_integer(entry.eim_id_type), "eimIdType")
    expect(
        b"\x83",
        None if entry.counter_value is None else encode_der_integer(entry.counter_value),
        "counterValue",
    )
    expect(
        b"\x84",
        None if entry.association_token is None else encode_der_integer(entry.association_token),
        "associationToken",
    )
    for tag, key, member in (
        (b"\xA5", entry.eim_public_key_data, "eimPublicKeyData"),
        (b"\xA6", entry.trusted_public_key_data_tls, "trustedPublicKeyDataTls"),
    ):
        got = members.get(tag)
        if key is None:
            if got is not None:
                raise ValueError(f"{where}: {member} is present but was left out.")
            continue
        if got is None:
            raise ValueError(f"{where}: {member} is missing.")
        choice_tag, choice_value, _choice_raw = read_single_ber_tlv(got)
        wanted_tag = b"\xA1" if key.form == KEY_FORM_CERTIFICATE else b"\xA0"
        if choice_tag != wanted_tag:
            raise ValueError(f"{where}: {member} carries alternative {choice_tag.hex().upper()}.")
        rebuilt = b"\x30" + encode_ber_length(len(choice_value)) + choice_value
        if rebuilt != bytes(key.der):
            raise ValueError(f"{where}: {member} does not restore to the DER it was built from.")
    protocol = members.get(b"\x87")
    if entry.eim_supported_protocol is None:
        if protocol is not None:
            raise ValueError(f"{where}: eimSupportedProtocol is present but was left out.")
    else:
        if protocol is None:
            raise ValueError(f"{where}: eimSupportedProtocol is missing.")
        if set(decode_named_bit_string(protocol, EIM_SUPPORTED_PROTOCOL_BITS)) != set(entry.eim_supported_protocol):
            raise ValueError(f"{where}: eimSupportedProtocol does not read back as given.")
    expect(b"\x88", None if entry.euicc_ci_pk_id is None else bytes(entry.euicc_ci_pk_id), "euiccCiPKId")
    expect(b"\x89", b"" if entry.indirect_profile_download else None, "indirectProfileDownload")
