# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge wire protocol: framing, message types, and (de)serialisation for the HIL-Bridge IPC channel."""
from __future__ import annotations

import errno
import ipaddress
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

RSPRO_VERSION = 2

IPA_PROTO_OSMO = 0xEE
IPA_PROTO_CCM = 0xFE

IPA_EXT_RSPRO = 0x07

IPA_MSGT_PING = 0x00
IPA_MSGT_PONG = 0x01

GSMTAP_VERSION = 0x02
GSMTAP_HDR_LEN_WORDS = 4
GSMTAP_TYPE_SIM = 0x04
GSMTAP_SIM_APDU = 0x00
GSMTAP_SIM_ATR = 0x01
GSMTAP_UDP_PORT = 4729
GSMTAP_ARFCN_F_UPLINK = 0x4000
GSMTAP_COMPAT_NATIVE = "native"
GSMTAP_COMPAT_WIRESHARK44 = "wireshark44"
GSMTAP_COMPAT_MODES = frozenset(
    {
        GSMTAP_COMPAT_NATIVE,
        GSMTAP_COMPAT_WIRESHARK44,
    }
)

def _resolve_rspro_asn_path() -> Path:
    # Walk a short list of known locations so the schema is reachable in
    # both source checkouts (where the canonical copy lives in ``docs/``)
    # and installed wheels (where the schema is packaged next to this
    # module). The ``YGGDRASIM_RSPRO_ASN`` override is intentional: it
    # lets downstream packagers vendor the schema into a non-standard
    # layout without patching code.
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "RSPRO.asn",
        here.parents[2] / "docs" / "RSPRO.asn",
    ]
    override = os.environ.get("YGGDRASIM_RSPRO_ASN", "")
    if len(override) > 0:
        candidates.insert(0, Path(override))
    for candidate in candidates:
        if candidate.is_file() is True:
            return candidate
    # Fall back to the historical source-tree path; the real existence
    # check runs in ``load_rspro_codec`` and produces the user-visible
    # error message with the path that was tried last.
    return here.parents[2] / "docs" / "RSPRO.asn"


RSPRO_ASN_PATH = _resolve_rspro_asn_path()

COMPONENT_REMSIM_CLIENT = "remsimClient"
COMPONENT_REMSIM_SERVER = "remsimServer"
COMPONENT_REMSIM_BANKD = "remsimBankd"

RESULT_OK = "ok"

PROACTIVE_COMMAND_TAG = 0xD0
PROACTIVE_REFRESH_COMMAND_TYPE = 0x01
PROACTIVE_TLV_COMMAND_DETAILS = 0x81
PROACTIVE_TLV_DEVICE_IDENTITIES = 0x82
DEVICE_ID_UICC = 0x81
DEVICE_ID_TERMINAL = 0x82

REFRESH_MODE_INIT_FULL_FILE_CHANGE = "init-full-file-change"
REFRESH_MODE_FILE_CHANGE = "file-change"
REFRESH_MODE_INIT_FILE_CHANGE = "init-file-change"
REFRESH_MODE_INIT = "init"
REFRESH_MODE_UICC_RESET = "uicc-reset"
REFRESH_MODE_NAA_APPLICATION_RESET = "naa-application-reset"
REFRESH_MODE_NAA_SESSION_RESET = "naa-session-reset"
REFRESH_MODE_STEERING_OF_ROAMING = "steering-of-roaming"
REFRESH_MODE_STEERING_OF_ROAMING_IWLAN = "steering-of-roaming-iwlan"
REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE = "euicc-profile-state-change"
REFRESH_MODE_APPLICATION_UPDATE = "application-update"

REFRESH_MODE_QUALIFIERS: dict[str, int] = {
    REFRESH_MODE_INIT_FULL_FILE_CHANGE: 0x00,
    REFRESH_MODE_FILE_CHANGE: 0x01,
    REFRESH_MODE_INIT_FILE_CHANGE: 0x02,
    REFRESH_MODE_INIT: 0x03,
    REFRESH_MODE_UICC_RESET: 0x04,
    REFRESH_MODE_NAA_APPLICATION_RESET: 0x05,
    REFRESH_MODE_NAA_SESSION_RESET: 0x06,
    REFRESH_MODE_STEERING_OF_ROAMING: 0x07,
    REFRESH_MODE_STEERING_OF_ROAMING_IWLAN: 0x08,
    REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE: 0x09,
    REFRESH_MODE_APPLICATION_UPDATE: 0x0A,
}

PCAP_MAGIC_USEC = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_ETHERNET = 1
ETHERTYPE_IPV4 = 0x0800
UDP_PROTOCOL_NUMBER = 17
_GSMTAP_CAPTURE_SRC_MAC = bytes.fromhex("020000000001")
_GSMTAP_CAPTURE_DST_MAC = bytes.fromhex("020000000002")
_GSMTAP_CAPTURE_SRC_IP = bytes((127, 0, 0, 1))
_GSMTAP_CAPTURE_DST_IP = bytes((127, 0, 0, 1))

REFRESH_QUALIFIER_NAMES: dict[int, str] = {
    qualifier: mode_name for mode_name, qualifier in REFRESH_MODE_QUALIFIERS.items()
}

REFRESH_MODE_ALIASES: dict[str, str] = {
    "0": REFRESH_MODE_INIT_FULL_FILE_CHANGE,
    "full": REFRESH_MODE_INIT_FULL_FILE_CHANGE,
    "full-file-change": REFRESH_MODE_INIT_FULL_FILE_CHANGE,
    "full-file-change-notification": REFRESH_MODE_INIT_FULL_FILE_CHANGE,
    "1": REFRESH_MODE_FILE_CHANGE,
    "file": REFRESH_MODE_FILE_CHANGE,
    "file-change-notification": REFRESH_MODE_FILE_CHANGE,
    "2": REFRESH_MODE_INIT_FILE_CHANGE,
    "init-and-file-change": REFRESH_MODE_INIT_FILE_CHANGE,
    "initialize-and-file-change": REFRESH_MODE_INIT_FILE_CHANGE,
    "3": REFRESH_MODE_INIT,
    "initialization": REFRESH_MODE_INIT,
    "initialize": REFRESH_MODE_INIT,
    "4": REFRESH_MODE_UICC_RESET,
    "reset": REFRESH_MODE_UICC_RESET,
    "uicc": REFRESH_MODE_UICC_RESET,
    "uiccreset": REFRESH_MODE_UICC_RESET,
    "5": REFRESH_MODE_NAA_APPLICATION_RESET,
    "app-reset": REFRESH_MODE_NAA_APPLICATION_RESET,
    "application-reset": REFRESH_MODE_NAA_APPLICATION_RESET,
    "6": REFRESH_MODE_NAA_SESSION_RESET,
    "session-reset": REFRESH_MODE_NAA_SESSION_RESET,
    "7": REFRESH_MODE_STEERING_OF_ROAMING,
    "steering": REFRESH_MODE_STEERING_OF_ROAMING,
    "sor": REFRESH_MODE_STEERING_OF_ROAMING,
    "8": REFRESH_MODE_STEERING_OF_ROAMING_IWLAN,
    "iwlan": REFRESH_MODE_STEERING_OF_ROAMING_IWLAN,
    "steering-iwlan": REFRESH_MODE_STEERING_OF_ROAMING_IWLAN,
    "9": REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    "profile": REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    "profile-state": REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    "profile-state-change": REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    "euicc": REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE,
    "10": REFRESH_MODE_APPLICATION_UPDATE,
    "0a": REFRESH_MODE_APPLICATION_UPDATE,
    "application": REFRESH_MODE_APPLICATION_UPDATE,
    "app-update": REFRESH_MODE_APPLICATION_UPDATE,
}

TPDU_FLAGS_COMPLETE: dict[str, bool] = {
    "tpduHeaderPresent": False,
    "finalPart": True,
    "procByteContinueTx": False,
    "procByteContinueRx": False,
}


@dataclass(frozen=True, slots=True)
class IpaFrame:
    proto: int
    ext: int | None
    payload: bytes


class IpaFrameParser:
    """Incremental IPA parser for TCP streams."""

    def __init__(self) -> None:
        self._buffer = bytearray()

    def feed(self, data: bytes) -> list[IpaFrame]:
        """Feed raw bytes into the IPA framing buffer and return any complete IpaFrame objects."""
        frames: list[IpaFrame] = []
        self._buffer.extend(data)

        while True:
            if len(self._buffer) < 3:
                break

            length = int.from_bytes(self._buffer[0:2], byteorder="big")
            proto = self._buffer[2]

            if proto in (IPA_PROTO_OSMO, IPA_PROTO_CCM):
                total_length = length + 3
                if len(self._buffer) < total_length:
                    break
                if length < 1:
                    raise ValueError("Extended IPA frame length is too short.")
                ext = self._buffer[3]
                payload = bytes(self._buffer[4:total_length])
            else:
                total_length = length + 3
                if len(self._buffer) < total_length:
                    break
                ext = None
                payload = bytes(self._buffer[3:total_length])

            del self._buffer[:total_length]
            frames.append(IpaFrame(proto=proto, ext=ext, payload=payload))

        return frames


def build_ipa_frame(proto: int, payload: bytes = b"", ext: int | None = None) -> bytes:
    if ext is None:
        return struct.pack(">HB", len(payload) + 1, proto) + payload
    return struct.pack(">HBB", len(payload) + 1, proto, ext) + payload


def build_ipa_ping() -> bytes:
    return build_ipa_frame(IPA_PROTO_CCM, ext=IPA_MSGT_PING)


def build_ipa_pong() -> bytes:
    return build_ipa_frame(IPA_PROTO_CCM, ext=IPA_MSGT_PONG)


def ensure_bytes(value: bytes | bytearray | list[int] | tuple[int, ...]) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    return bytes(value)


def encode_ber_length(length: int) -> bytes:
    """Encode an integer length value into BER definite-form bytes."""
    if length < 0:
        raise ValueError("BER length must be non-negative.")
    if length < 0x80:
        return bytes((length,))
    if length <= 0xFF:
        return bytes((0x81, length))
    if length <= 0xFFFF:
        return bytes((0x82, (length >> 8) & 0xFF, length & 0xFF))
    raise ValueError("BER length exceeds two-octet support in HIL bridge helper.")


def build_simple_tlv(tag: int, value: bytes | bytearray | list[int] | tuple[int, ...]) -> bytes:
    value_bytes = ensure_bytes(value)
    return bytes((int(tag) & 0xFF,)) + encode_ber_length(len(value_bytes)) + value_bytes


def describe_refresh_mode(qualifier: int) -> str:
    return REFRESH_QUALIFIER_NAMES.get(int(qualifier) & 0xFF, f"qualifier-0x{int(qualifier) & 0xFF:02X}")


def normalize_refresh_mode(value: str | int) -> tuple[str, int]:
    """Map a refresh-mode name or integer to a (name, qualifier) tuple."""
    if isinstance(value, int):
        qualifier = int(value) & 0xFF
        return describe_refresh_mode(qualifier), qualifier

    text = str(value or "").strip().lower()
    if len(text) == 0:
        qualifier = REFRESH_MODE_QUALIFIERS[REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE]
        return REFRESH_MODE_EUICC_PROFILE_STATE_CHANGE, qualifier

    if text.startswith("0x"):
        qualifier = int(text, 16) & 0xFF
        return describe_refresh_mode(qualifier), qualifier

    if len(text) == 2:
        try:
            qualifier = int(text, 16) & 0xFF
        except ValueError:
            qualifier = -1
        if qualifier >= 0:
            return describe_refresh_mode(qualifier), qualifier

    canonical = REFRESH_MODE_ALIASES.get(text, text)
    if canonical not in REFRESH_MODE_QUALIFIERS:
        supported = ", ".join(sorted(REFRESH_MODE_QUALIFIERS.keys()))
        raise ValueError(f"Unsupported modem REFRESH mode '{value}'. Supported modes: {supported}")
    return canonical, REFRESH_MODE_QUALIFIERS[canonical]


def build_proactive_refresh_command(*, command_number: int, qualifier: int | str) -> bytes:
    """Build a REFRESH proactive command BER-TLV byte string for the given qualifier."""
    command_number_int = int(command_number) & 0xFF
    if command_number_int == 0:
        raise ValueError("Command number must be non-zero.")

    _mode_name, qualifier_value = normalize_refresh_mode(qualifier)
    command_details = build_simple_tlv(
        PROACTIVE_TLV_COMMAND_DETAILS,
        bytes((command_number_int, PROACTIVE_REFRESH_COMMAND_TYPE, qualifier_value)),
    )
    device_identities = build_simple_tlv(
        PROACTIVE_TLV_DEVICE_IDENTITIES,
        bytes((DEVICE_ID_UICC, DEVICE_ID_TERMINAL)),
    )
    proactive_body = command_details + device_identities
    return build_simple_tlv(PROACTIVE_COMMAND_TAG, proactive_body)


@lru_cache(maxsize=1)
def load_rspro_codec() -> Any:
    """Load and return the RSPRO ASN.1 codec module, or raise ImportError if unavailable."""
    try:
        import asn1tools
    except ImportError as exc:
        raise RuntimeError(
            "asn1tools is required for the HIL bridge. Install it in the active Python environment."
        ) from exc

    if RSPRO_ASN_PATH.exists() is False:
        raise FileNotFoundError(f"Missing vendored RSPRO schema: {RSPRO_ASN_PATH}")

    return asn1tools.compile_files([str(RSPRO_ASN_PATH)], codec="ber")


def decode_rspro_pdu(payload: bytes) -> dict[str, Any]:
    codec = load_rspro_codec()
    decoded = codec.decode("RsproPDU", payload)
    if isinstance(decoded, dict) is False:
        raise ValueError("Decoded RSPRO payload is not a mapping.")
    return decoded


def encode_rspro_pdu(pdu: dict[str, Any]) -> bytes:
    codec = load_rspro_codec()
    return ensure_bytes(codec.encode("RsproPDU", pdu))


def get_pdu_message_name(pdu: dict[str, Any]) -> str:
    message = pdu.get("msg")
    if isinstance(message, tuple) is False or len(message) != 2:
        raise ValueError("Invalid RSPRO PDU choice shape.")
    return str(message[0])


def get_pdu_message_body(pdu: dict[str, Any]) -> dict[str, Any]:
    """Extract and return the body dict from the inner RSPRO PDU choice tuple."""
    message = pdu.get("msg")
    if isinstance(message, tuple) is False or len(message) != 2:
        raise ValueError("Invalid RSPRO PDU choice shape.")
    body = message[1]
    if isinstance(body, dict) is False:
        raise ValueError("Invalid RSPRO PDU body shape.")
    return body


def get_pdu_tag(pdu: dict[str, Any]) -> int:
    return int(pdu.get("tag", 0))


def build_component_identity(
    component_type: str,
    *,
    name: str,
    software: str,
    sw_version: str,
) -> dict[str, Any]:
    """Build an RSPRO ComponentIdentity dict for a named component (RSPRO §4.2)."""
    return {
        "type": component_type,
        "name": name,
        "software": software,
        "swVersion": sw_version,
    }


def build_client_slot(client_id: int, slot_nr: int) -> dict[str, int]:
    return {
        "clientId": int(client_id),
        "slotNr": int(slot_nr),
    }


def build_bank_slot(bank_id: int, slot_nr: int) -> dict[str, int]:
    return {
        "bankId": int(bank_id),
        "slotNr": int(slot_nr),
    }


def build_ip_choice(host: str) -> tuple[str, bytes]:
    address = ipaddress.ip_address(host)
    if address.version == 4:
        return ("ipv4", address.packed)
    return ("ipv6", address.packed)


def build_rspro_pdu(tag: int, message_name: str, body: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": RSPRO_VERSION,
        "tag": int(tag),
        "msg": (message_name, body),
    }


def build_connect_client_res(
    *,
    tag: int,
    component_identity: dict[str, Any],
    result: str = RESULT_OK,
) -> dict[str, Any]:
    """Build an RSPRO connectClientRes PDU with the given tag and identity (RSPRO §4.4)."""
    return build_rspro_pdu(
        tag,
        "connectClientRes",
        {
            "identity": component_identity,
            "result": result,
        },
    )


def build_config_client_id_req(*, tag: int, client_slot: dict[str, Any]) -> dict[str, Any]:
    """Build an RSPRO configClientIdReq PDU carrying the client slot assignment."""
    return build_rspro_pdu(
        tag,
        "configClientIdReq",
        {
            "clientSlot": client_slot,
        },
    )


def build_config_client_bank_req(
    *,
    tag: int,
    bank_slot: dict[str, Any],
    bank_host: str,
    bank_port: int,
) -> dict[str, Any]:
    """Build an RSPRO configClientBankReq PDU assigning the bank slot to the client."""
    return build_rspro_pdu(
        tag,
        "configClientBankReq",
        {
            "bankSlot": bank_slot,
            "bankd": {
                "ip": build_ip_choice(bank_host),
                "port": int(bank_port),
            },
        },
    )


def build_config_client_bank_res(*, tag: int, result: str = RESULT_OK) -> dict[str, Any]:
    """Build an RSPRO configClientBankRes acknowledgement PDU."""
    return build_rspro_pdu(
        tag,
        "configClientBankRes",
        {
            "result": result,
        },
    )


def build_set_atr_req(*, tag: int, client_slot: dict[str, Any], atr: bytes) -> dict[str, Any]:
    """Build an RSPRO setAtrReq PDU carrying the ATR bytes for the named client slot."""
    return build_rspro_pdu(
        tag,
        "setAtrReq",
        {
            "slot": client_slot,
            "atr": ensure_bytes(atr),
        },
    )


def build_set_atr_res(*, tag: int, result: str = RESULT_OK) -> dict[str, Any]:
    """Build an RSPRO setAtrRes acknowledgement PDU."""
    return build_rspro_pdu(
        tag,
        "setAtrRes",
        {
            "result": result,
        },
    )


def build_tpdu_card_to_modem(
    *,
    tag: int,
    bank_slot: dict[str, Any],
    client_slot: dict[str, Any],
    data: bytes,
) -> dict[str, Any]:
    """Build an RSPRO tpduCardToModem PDU wrapping an R-APDU."""
    return build_rspro_pdu(
        tag,
        "tpduCardToModem",
        {
            "fromBankSlot": bank_slot,
            "toClientSlot": client_slot,
            "flags": dict(TPDU_FLAGS_COMPLETE),
            "data": ensure_bytes(data),
        },
    )


def build_reset_state_res(*, tag: int, result: str = RESULT_OK) -> dict[str, Any]:
    """Build an RSPRO resetStateRes acknowledgement PDU."""
    return build_rspro_pdu(
        tag,
        "resetStateRes",
        {
            "result": result,
        },
    )


def build_gsmtap_packet(payload: bytes, *, subtype: int, uplink: bool = False) -> bytes:
    """Wrap *payload* in a GSMTAP v2 header of the given *subtype* (GSMTAP §3.1)."""
    arfcn = GSMTAP_ARFCN_F_UPLINK if uplink else 0
    header = struct.pack(
        "!BBBBHbbIBBBB",
        GSMTAP_VERSION,
        GSMTAP_HDR_LEN_WORDS,
        GSMTAP_TYPE_SIM,
        0,
        arfcn,
        0,
        0,
        0,
        subtype,
        0,
        0,
        0,
    )
    return header + ensure_bytes(payload)


def build_simtrace_apdu_payload(
    command: bytes | bytearray | list[int] | tuple[int, ...],
    response: bytes | bytearray | list[int] | tuple[int, ...],
) -> bytes:
    """Build a SIMtrace2 APDU payload record from a C-APDU / R-APDU pair."""
    command_bytes = ensure_bytes(command)
    response_bytes = ensure_bytes(response)
    if len(command_bytes) == 0:
        raise ValueError("SIMtrace command APDU payload is empty.")
    if len(response_bytes) == 0:
        raise ValueError("SIMtrace response APDU payload is empty.")
    return command_bytes + response_bytes


def _ipv4_header_checksum(header: bytes) -> int:
    if len(header) % 2 != 0:
        raise ValueError("IPv4 header checksum input must be an even number of bytes.")
    total = 0
    for offset in range(0, len(header), 2):
        total += int.from_bytes(header[offset : offset + 2], byteorder="big")
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_capture_udp_ipv4_ethernet_frame(
    payload: bytes | bytearray | list[int] | tuple[int, ...],
    *,
    udp_port: int = GSMTAP_UDP_PORT,
) -> bytes:
    """Wrap a GSMTAP payload in a minimal UDP/IPv4/Ethernet frame for pcap capture."""
    payload_bytes = ensure_bytes(payload)
    udp_port_value = int(udp_port) & 0xFFFF
    udp_length = 8 + len(payload_bytes)
    ip_total_length = 20 + udp_length
    ipv4_header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_length,
        0,
        0,
        64,
        UDP_PROTOCOL_NUMBER,
        0,
        _GSMTAP_CAPTURE_SRC_IP,
        _GSMTAP_CAPTURE_DST_IP,
    )
    ipv4_checksum = _ipv4_header_checksum(ipv4_header_without_checksum)
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        ip_total_length,
        0,
        0,
        64,
        UDP_PROTOCOL_NUMBER,
        ipv4_checksum,
        _GSMTAP_CAPTURE_SRC_IP,
        _GSMTAP_CAPTURE_DST_IP,
    )
    udp_header = struct.pack(
        "!HHHH",
        udp_port_value,
        udp_port_value,
        udp_length,
        0,
    )
    ethernet_header = (
        _GSMTAP_CAPTURE_DST_MAC
        + _GSMTAP_CAPTURE_SRC_MAC
        + struct.pack("!H", ETHERTYPE_IPV4)
    )
    return ethernet_header + ipv4_header + udp_header + payload_bytes


PCAP_GLOBAL_HEADER_STRUCT = struct.Struct("<IHHIIII")
PCAP_PACKET_RECORD_STRUCT = struct.Struct("<IIII")


def build_pcap_global_header() -> bytes:
    """Return the 24-byte pcap global header (magic 0xA1B2C3D4, link-type ETHERNET)."""
    return PCAP_GLOBAL_HEADER_STRUCT.pack(
        PCAP_MAGIC_USEC,
        PCAP_VERSION_MAJOR,
        PCAP_VERSION_MINOR,
        0,
        0,
        PCAP_SNAPLEN,
        PCAP_LINKTYPE_ETHERNET,
    )


def build_pcap_packet_record(frame: bytes, seconds: int, microseconds: int) -> bytes:
    """Return a pcap packet record header prepended to *frame* with the given timestamp."""
    return PCAP_PACKET_RECORD_STRUCT.pack(
        int(seconds),
        max(0, int(microseconds)),
        len(frame),
        len(frame),
    ) + frame


@dataclass(slots=True)
class GsmtapPcapWriter:
    path: str
    udp_port: int = GSMTAP_UDP_PORT
    mirror_fifo_path: str = ""
    _handle: Any = field(default=None, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _fifo_fd: int | None = field(default=None, init=False, repr=False)
    _fifo_header_written: bool = field(default=False, init=False, repr=False)
    _fifo_disabled: bool = field(default=False, init=False, repr=False)

    def __post_init__(self) -> None:
        normalized_path = str(self.path or "").strip()
        if len(normalized_path) == 0:
            raise ValueError("GSMTAP pcap writer requires a target path.")
        target_path = Path(normalized_path)
        target_path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = target_path.open("wb")
        self._handle.write(build_pcap_global_header())
        self._handle.flush()
        self.mirror_fifo_path = str(self.mirror_fifo_path or "").strip()

    def close(self) -> None:
        """Flush and close the underlying pcap file handle."""
        handle = self._handle
        if handle is None:
            return
        self._handle = None
        handle.close()
        self._close_fifo_fd_locked()

    def write_gsmtap_packet(self, packet: bytes, *, timestamp: float | None = None) -> None:
        """Encode *packet* as a pcap record with a timestamp and write it to the file."""
        handle = self._handle
        if handle is None:
            return
        timestamp_value = time.time() if timestamp is None else float(timestamp)
        seconds = int(timestamp_value)
        microseconds = int(round((timestamp_value - seconds) * 1_000_000))
        if microseconds >= 1_000_000:
            seconds += 1
            microseconds -= 1_000_000
        frame = build_capture_udp_ipv4_ethernet_frame(packet, udp_port=self.udp_port)
        record_bytes = build_pcap_packet_record(frame, seconds, microseconds)
        with self._lock:
            current_handle = self._handle
            if current_handle is None:
                return
            current_handle.write(record_bytes)
            current_handle.flush()
            self._mirror_record_to_fifo_locked(record_bytes)

    def _mirror_record_to_fifo_locked(self, record_bytes: bytes) -> None:
        if self._fifo_disabled:
            return
        if len(self.mirror_fifo_path) == 0:
            return
        if self._fifo_fd is None:
            self._open_fifo_fd_locked()
        if self._fifo_fd is None:
            return
        if self._fifo_header_written is False:
            if self._try_fifo_write_locked(build_pcap_global_header()) is False:
                return
            self._fifo_header_written = True
        self._try_fifo_write_locked(record_bytes)

    def _open_fifo_fd_locked(self) -> None:
        try:
            fd = os.open(
                self.mirror_fifo_path,
                os.O_WRONLY | os.O_NONBLOCK,
            )
        except OSError as exc:
            if exc.errno in (errno.ENXIO, errno.ENOENT):
                return
            self._fifo_disabled = True
            return
        self._fifo_fd = fd
        self._fifo_header_written = False

    def _try_fifo_write_locked(self, payload: bytes) -> bool:
        fd = self._fifo_fd
        if fd is None:
            return False
        try:
            os.write(fd, payload)
            return True
        except BlockingIOError:
            return False
        except BrokenPipeError:
            self._close_fifo_fd_locked()
            return False
        except OSError as exc:
            if exc.errno == errno.EPIPE:
                self._close_fifo_fd_locked()
                return False
            self._fifo_disabled = True
            self._close_fifo_fd_locked()
            return False

    def _close_fifo_fd_locked(self) -> None:
        fd = self._fifo_fd
        if fd is None:
            return
        self._fifo_fd = None
        self._fifo_header_written = False
        try:
            os.close(fd)
        except OSError:
            pass


@dataclass(slots=True)
class GsmtapTap:
    host: str = "127.0.0.1"
    port: int = GSMTAP_UDP_PORT
    enabled: bool = True
    compat_mode: str = GSMTAP_COMPAT_NATIVE
    _socket: socket.socket | None = field(default=None, init=False, repr=False)
    capture_path: str = ""
    capture_mirror_fifo_path: str = ""
    _capture_writer: GsmtapPcapWriter | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.compat_mode not in GSMTAP_COMPAT_MODES:
            raise ValueError(f"Unsupported GSMTAP compatibility mode: {self.compat_mode}")
        normalized_capture_path = str(self.capture_path or "").strip()
        normalized_mirror_fifo_path = str(self.capture_mirror_fifo_path or "").strip()
        if len(normalized_capture_path) > 0:
            if len(normalized_mirror_fifo_path) == 0:
                normalized_mirror_fifo_path = str(
                    Path(normalized_capture_path).expanduser().with_suffix(".fifo")
                )
            self._capture_writer = GsmtapPcapWriter(
                path=normalized_capture_path,
                udp_port=self.port,
                mirror_fifo_path=normalized_mirror_fifo_path,
            )
        if self.enabled:
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def close(self) -> None:
        """Flush pending writes, close the capture writer, and tear down the IPA socket."""
        capture_writer = self._capture_writer
        if capture_writer is not None:
            capture_writer.close()
            self._capture_writer = None
        if self._socket is None:
            return
        self._socket.close()
        self._socket = None

    def _send_packet(self, packet: bytes) -> None:
        if self._socket is not None:
            self._socket.sendto(packet, (self.host, self.port))
        capture_writer = self._capture_writer
        if capture_writer is not None:
            capture_writer.write_gsmtap_packet(packet)

    def send_apdu(self, payload: bytes, *, uplink: bool) -> None:
        packet = build_gsmtap_packet(payload, subtype=GSMTAP_SIM_APDU, uplink=uplink)
        self._send_packet(packet)

    def mirror_exchange(self, command: bytes, response: bytes) -> None:
        """Capture a command/response APDU pair as a GSMTAP SIM-APDU pcap packet."""
        packet = build_gsmtap_packet(
            build_simtrace_apdu_payload(command, response),
            subtype=GSMTAP_SIM_APDU,
            uplink=True,
        )
        self._send_packet(packet)

    def send_atr(self, payload: bytes) -> None:
        if self.compat_mode == GSMTAP_COMPAT_WIRESHARK44:
            return
        packet = build_gsmtap_packet(payload, subtype=GSMTAP_SIM_ATR, uplink=False)
        self._send_packet(packet)
