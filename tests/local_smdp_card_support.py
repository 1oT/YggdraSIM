# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A scripted eUICC for Local SM-DP+ session tests: the card end of a whole profile load.

The card answers by what a command is, never by the label the session logs it
under, and it refuses the way ``PcscApduChannel.send`` reports a refusal. Three
traits a live SGP.32 eUICC showed are switches: ES10 enabled only behind the
IPAd declaration (GSMA SGP.32 v1.3 §3.8.2), GET DATA on the ECASD answered
'6D 00', and GetEID answered on the ISD-R (SGP.22 v3.1 §5.7.20). The card
derives the session keys of a load from its own EID (SGP.22 v3.1 §2.6.4.2),
so a test can tell which EID the SM-DP+ side used.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.x963kdf import X963KDF

from SCP11.shared.ber_tlv import encode_ber_length, read_ber_tlv

# SGP.26 v3.0.2 §3.2.1 Table 5 test eUICC.
TEST_EID = "89049032123451234512345678901235"
# SGP.02 v4.2 §2.2.3.
ISD_R_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000100")
ECASD_AID = bytes.fromhex("A0000005591010FFFFFFFF8900000200")
ISD_P_AID = bytes.fromhex("A0000005591010FFFFFFFF8900001200")
# Subject key identifier of the SGP.26 test CI, as the eUICC lists it.
TEST_CI_PKID = bytes.fromhex("F54172BDF98A95D65CBEB88A38A1C11D800A85C3")
DEFAULT_DP_ADDRESS = b"smdpplus2.smdpp.example.test"

INS_MANAGE_CHANNEL = 0x70
INS_SELECT = 0xA4
INS_TERMINAL_CAPABILITY = 0xAA
INS_GET_DATA = 0xCA
INS_STORE_DATA = 0xE2
INS_STATUS = 0xF2

SW_LOGICAL_CHANNEL_NOT_SUPPORTED = 0x6881
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_INS_NOT_SUPPORTED = 0x6D00
SW_FILE_NOT_FOUND = 0x6A82
SW_DATA_NOT_FOUND = 0x6A88


def tlv(tag_hex: str, value: bytes) -> bytes:
    return bytes.fromhex(tag_hex) + encode_ber_length(len(value)) + bytes(value)


def children(value: bytes) -> dict[bytes, bytes]:
    """The first value of each tag among the TLVs of *value*."""
    found: dict[bytes, bytes] = {}
    offset = 0
    while offset < len(value):
        tag, item, _raw, offset = read_ber_tlv(value, offset)
        found.setdefault(tag, item)
    return found


def header(data: bytes) -> tuple[bytes, int, int]:
    """Tag, declared length and header size of a TLV whose value may not be there.

    A segment of a Bound Profile Package can be the tag and length fields of
    a container alone (SGP.22 v3.1 §2.5.5), which a whole-TLV reader refuses.
    """
    size = 1
    if data[0] & 0x1F == 0x1F:
        while data[size] & 0x80:
            size += 1
        size += 1
    tag = bytes(data[:size])
    first = data[size]
    if first < 0x80:
        return tag, first, size + 1
    count = first & 0x7F
    return tag, int.from_bytes(data[size + 1 : size + 1 + count], "big"), size + 1 + count


def declares_ipad(command_data: bytes) -> bool:
    """True when a TERMINAL CAPABILITY data field declares the IPAd.

    Template 'A9' holding tag '84' (ETSI TS 102 221 v18.4 §11.1.19.2.4
    Table 11.20c), b1 of whose first byte is "IPAd supported" (GSMA SGP.32
    v1.3 §3.8.2 Table 6).
    """
    if len(command_data) < 2 or command_data[0] != 0xA9 or command_data[1] != len(command_data) - 2:
        return False
    capability = children(command_data[2:]).get(b"\x84", b"")
    return len(capability) >= 1 and bool(capability[0] & 0x01)


class ScriptedEuicc:
    """The card channel of one eUICC, down to a profile installed and its Notification."""

    def __init__(
        self,
        *,
        eid: str = TEST_EID,
        gates_es10: bool = True,
        ecasd_get_data: bool = False,
        es10_get_eid: bool = True,
        max_segment: int = 0,
    ) -> None:
        self.eid = eid
        self.gates_es10 = gates_es10
        self.ecasd_get_data = ecasd_get_data
        self.es10_get_eid = es10_get_eid
        # The longest '86' / '87' / '88' segment the card takes, 0 for any (SGP.22 v3.1 §2.5.3
        # Protected Profile Package: 1020 bytes is what an eUICC has to support).
        self.max_segment = max_segment
        self.refused_segments: list[int] = []
        # Every APDU and every whole ES10 payload the card was handed, in order.
        self.sent: list[bytes] = []
        self.labels: list[str] = []
        self.es10: list[bytes] = []
        self.resets = 0
        # What survives a reset.
        self.notifications: dict[int, bytes] = {}
        self.installed_iccid = b""
        self.enabled_iccid = b""
        self.session_keys: tuple[bytes, bytes, bytes] | None = None
        self._next_sequence = 0x0220
        self._power_on()

    def _power_on(self) -> None:
        self._ipad_declared = False
        # The application selected on each open logical channel; the basic channel is always open.
        self._selected: dict[int, bytes] = {0: b""}
        self._blocks = b""
        self._transaction_id = b""
        self._otsk: ec.EllipticCurvePrivateKey | None = None
        self._rsp_open = False
        self._a3_expected = -1
        self._a3_received = 0
        self._metadata_iccid = b""

    # -- the channel the session drives --------------------------------

    def send(self, apdu: bytes, log_name: str) -> bytes:
        command = bytes(apdu)
        self.sent.append(command)
        self.labels.append(log_name)
        instruction = command[1]
        data = command[5 : 5 + command[4]] if len(command) > 5 else b""
        # TS 102 221 v18.4 §10.1.1: the two low bits of a first-interindustry CLA name the logical channel.
        channel = command[0] & 0x03
        if instruction == INS_TERMINAL_CAPABILITY:
            if any(len(application) > 0 for application in self._selected.values()):
                self._refuse(SW_CONDITIONS_NOT_SATISFIED)
            self._ipad_declared = declares_ipad(data)
            return b""
        if instruction == INS_MANAGE_CHANNEL:
            return self._manage_channel(command[2], command[3])
        if instruction == INS_STATUS:
            return b""
        if channel not in self._selected:
            self._refuse(SW_LOGICAL_CHANNEL_NOT_SUPPORTED)
        if instruction == INS_SELECT:
            if data not in (ISD_R_AID, ECASD_AID):
                self._refuse(SW_FILE_NOT_FOUND)
            self._selected[channel] = data
            return tlv("6F", tlv("84", data))
        if instruction == INS_GET_DATA:
            return self._get_data(channel, command[2:4])
        if instruction == INS_STORE_DATA:
            self._require_es10(channel)
            self._blocks += data
            # GPC v2.4 §11.11.2.1 Table 11-89: P1 b8 = 1 marks the last block.
            if command[2] & 0x80 == 0:
                return b""
            payload, self._blocks = self._blocks, b""
            return self._es10(payload)
        raise AssertionError(f"the scripted eUICC knows no command {command.hex().upper()}")

    def send_chunked(
        self,
        cla: int,
        ins: int,
        p1: int,
        p2_start: int,
        payload: bytes,
        log_name: str,
        chunk_size: int = 250,
    ) -> bytes:
        self.labels.append(log_name)
        self._require_es10(cla & 0x03)
        return self._es10(bytes(payload))

    def reset(self) -> bool:
        self.resets += 1
        self._power_on()
        return True

    # -- what a test asks afterwards -----------------------------------

    def count(self, instruction: int) -> int:
        return sum(1 for command in self.sent if command[1] == instruction)

    def selected_aids(self) -> list[bytes]:
        return [command[5 : 5 + command[4]] for command in self.sent if command[1] == INS_SELECT]

    def es10_tags(self) -> list[str]:
        return [header(payload)[0].hex().upper() for payload in self.es10]

    # -- the card ------------------------------------------------------

    @staticmethod
    def _refuse(status_word: int) -> None:
        raise IOError(f"APDU Failed: {status_word:04X}")

    def _manage_channel(self, p1: int, p2: int) -> bytes:
        # TS 102 221 v18.4 §11.1.17: P1 '00' opens a channel the UICC
        # assigns, from the range 1 to 3 first, and answers its number;
        # P1 '80' closes the channel P2 names.
        if p1 == 0x00:
            for number in (1, 2, 3):
                if number not in self._selected:
                    self._selected[number] = b""
                    return bytes([number])
            self._refuse(SW_LOGICAL_CHANNEL_NOT_SUPPORTED)
        if p1 == 0x80 and p2 in (1, 2, 3) and p2 in self._selected:
            del self._selected[p2]
            return b""
        self._refuse(SW_CONDITIONS_NOT_SATISFIED)
        return b""

    def _require_es10(self, channel: int) -> None:
        # STORE DATA belongs to the ISD-R: on a channel where another
        # application is selected, or none, the instruction is unknown.
        if self._selected.get(channel) != ISD_R_AID:
            self._refuse(SW_INS_NOT_SUPPORTED)
        if self.gates_es10 and self._ipad_declared is False:
            self._refuse(SW_CONDITIONS_NOT_SATISFIED)

    def _get_data(self, channel: int, tag: bytes) -> bytes:
        if self._selected.get(channel) != ECASD_AID or self.ecasd_get_data is False:
            self._refuse(SW_INS_NOT_SUPPORTED)
        if tag == bytes.fromhex("005A"):
            return tlv("5A", bytes.fromhex(self.eid))
        if tag == bytes.fromhex("0042"):
            return tlv("42", bytes.fromhex(self.eid[:8]))
        self._refuse(SW_DATA_NOT_FOUND)
        return b""

    def _es10(self, payload: bytes) -> bytes:
        self.es10.append(payload)
        tag, declared, header_size = header(payload)
        name = tag.hex().upper()
        if name == "BF20":
            lists = tlv("A9", tlv("04", TEST_CI_PKID)) + tlv("AA", tlv("04", TEST_CI_PKID))
            return tlv("BF20", tlv("82", bytes.fromhex("020500")) + lists)
        if name == "BF3C":
            return tlv("BF3C", tlv("80", DEFAULT_DP_ADDRESS))
        if name == "BF2E":
            return tlv("BF2E", tlv("80", b"\xC4" * 16))
        if name == "BF38":
            return self._authenticate_server(payload[header_size:])
        if name == "BF21":
            return self._prepare_download()
        if name == "BF3E":
            if self.es10_get_eid is False:
                self._refuse(SW_DATA_NOT_FOUND)
            return tlv("BF3E", tlv("5A", bytes.fromhex(self.eid)))
        if name == "BF36":
            return self._initialise_secure_channel(payload[header_size:])
        if name in ("86", "87", "88") and self._rsp_open and 0 < self.max_segment < len(payload):
            self.refused_segments.append(len(payload))
            return self._refuse_segment(name)
        if name in ("A0", "A1", "A2", "87") and self._rsp_open:
            return b""
        if name == "88" and self._rsp_open:
            return self._store_metadata(payload[header_size:])
        if name == "A3" and self._rsp_open:
            self._a3_expected = declared
            self._a3_received = 0
            return b""
        if name == "86" and self._rsp_open:
            self._a3_received += len(payload)
            if self._a3_received < self._a3_expected:
                return b""
            return self._install()
        if name == "BF28":
            listed = b""
            for result in self.notifications.values():
                data = children(read_ber_tlv(result, 0)[1])[bytes.fromhex("BF27")]
                listed += tlv("BF2F", children(data)[bytes.fromhex("BF2F")])
            return tlv("BF28", tlv("A0", listed))
        if name == "BF2B":
            # A search criterion 'A0' names one sequence number; without one the whole list is returned.
            criterion = children(payload[header_size:]).get(b"\xA0")
            if criterion is None:
                return tlv("BF2B", tlv("A0", b"".join(self.notifications.values())))
            sequence = int.from_bytes(children(criterion)[b"\x80"], "big")
            return tlv("BF2B", tlv("A0", self.notifications.get(sequence, b"")))
        if name == "BF30":
            sequence = int.from_bytes(children(payload[header_size:])[b"\x80"], "big")
            known = self.notifications.pop(sequence, None)
            return tlv("BF30", tlv("80", b"\x00" if known is not None else b"\x01"))
        if name == "BF41":
            return self._cancel_session(payload[header_size:])
        if name == "BF31":
            target = children(children(payload[header_size:])[b"\xA0"])
            self.enabled_iccid = target.get(b"\x5A", b"")
            return tlv("BF31", tlv("80", b"\x00"))
        if name == "BF2D":
            return tlv("BF2D", tlv("A0", b""))
        if name in ("BF22", "BF43", "BF55", "BF56"):
            return tag + b"\x00"
        raise AssertionError(f"the scripted eUICC knows no ES10 payload {payload[:8].hex().upper()}")

    def _authenticate_server(self, request: bytes) -> bytes:
        # serverSigned1 leads the request: transactionId '80', euiccChallenge
        # '81', serverAddress '83', serverChallenge '84' (SGP.22 v3.1 §5.7.13).
        signed = children(children(request)[b"\x30"])
        self._transaction_id = signed[b"\x80"]
        euicc_signed1 = tlv(
            "30",
            tlv("80", self._transaction_id)
            + tlv("83", signed[b"\x83"])
            + tlv("84", signed[b"\x84"])
            + tlv("BF22", b""),
        )
        return tlv("BF38", tlv("A0", euicc_signed1 + tlv("5F37", b"\x33" * 64)))

    def _prepare_download(self) -> bytes:
        if len(self._transaction_id) == 0:
            self._refuse(SW_CONDITIONS_NOT_SATISFIED)
        self._otsk = ec.generate_private_key(ec.SECP256R1())
        otpk = self._otsk.public_key().public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        self._rsp_open = True
        euicc_signed2 = tlv("30", tlv("80", self._transaction_id) + tlv("5F49", otpk))
        return tlv("BF21", tlv("A0", euicc_signed2 + tlv("5F37", b"\x44" * 64)))

    def _initialise_secure_channel(self, request: bytes) -> bytes:
        # InitialiseSecureChannelRequest 'BF23': transactionId '80', the
        # Control Reference Template 'A6' with keyType '80', keyLen '81' and
        # hostId '84', then smdpOtpk '5F49' (SGP.22 v3.1 §5.5.1).
        if self._rsp_open is False or self._otsk is None:
            raise AssertionError("a Bound Profile Package arrived outside an RSP session")
        fields = children(children(request)[bytes.fromhex("BF23")])
        if fields[b"\x80"] != self._transaction_id:
            raise AssertionError("the Bound Profile Package names another transaction")
        template = children(fields[b"\xA6"])
        host_id = template[b"\x84"]
        eid = bytes.fromhex(self.eid)
        public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), fields[bytes.fromhex("5F49")])
        shared_secret = self._otsk.exchange(ec.ECDH(), public_key)
        # SGP.22 v3.1 §2.6.4.2: SharedInfo is the key type, the key length,
        # HostID-LV and EID-LV; Table 4c lays the key data out as the initial
        # MAC chaining value, S-ENC, S-MAC.
        shared_info = template[b"\x80"] + template[b"\x81"] + bytes([len(host_id)]) + host_id + bytes([len(eid)]) + eid
        key_length = template[b"\x81"][0]
        key_data = X963KDF(algorithm=hashes.SHA256(), length=3 * key_length, sharedinfo=shared_info).derive(shared_secret)
        self.session_keys = (
            key_data[key_length : 2 * key_length],
            key_data[2 * key_length :],
            key_data[:key_length],
        )
        return b""

    def _store_metadata(self, protected: bytes) -> bytes:
        # A MAC-only '88' TLV: the StoreMetadataRequest 'BF25' in clear, then the MAC.
        try:
            tag, request, _raw, _next = read_ber_tlv(protected, 0)
        except ValueError:
            return b""
        if tag == bytes.fromhex("BF25"):
            self._metadata_iccid = children(request).get(b"\x5A", self._metadata_iccid)
        return b""

    def _install(self) -> bytes:
        sequence = self._next_sequence
        self._next_sequence += 1
        metadata = (
            tlv("80", sequence.to_bytes(2, "big"))
            + tlv("81", bytes.fromhex("0780"))
            + tlv("0C", DEFAULT_DP_ADDRESS)
            + tlv("5A", self._metadata_iccid)
        )
        # ProfileInstallationResult 'BF37': the data 'BF27', then the eUICC
        # signature '5F37' beside it (SGP.22 v3.1 §2.5.6).
        data = (
            tlv("80", self._transaction_id)
            + tlv("BF2F", metadata)
            + tlv("06", bytes.fromhex("88370A"))
            + tlv("A2", tlv("A0", tlv("4F", ISD_P_AID) + tlv("04", bytes.fromhex("9000"))))
        )
        result = tlv("BF37", tlv("BF27", data) + tlv("5F37", b"\xAA" * 64))
        self.notifications[sequence] = result
        self.installed_iccid = self._metadata_iccid
        self._rsp_open = False
        return result

    def _refuse_segment(self, name: str) -> bytes:
        # ErrorResult 'A1': bppCommandId '80', errorReason bspStructureError(7) '81'
        # (SGP.22 v3.1 §2.5.6 Profile Installation Result). The command a '87' belongs
        # to is not tracked: the card reports configureISDP(1) for it.
        command = {"86": 5, "88": 2}.get(name, 1)
        data = (
            tlv("80", self._transaction_id)
            + tlv("BF2F", tlv("80", self._next_sequence.to_bytes(2, "big")) + tlv("81", bytes.fromhex("0780")))
            + tlv("06", bytes.fromhex("88370A"))
            + tlv("A2", tlv("A1", tlv("80", bytes([command])) + tlv("81", b"\x07")))
        )
        self._rsp_open = False
        return tlv("BF37", tlv("BF27", data) + tlv("5F37", b"\xAA" * 64))

    def _cancel_session(self, request: bytes) -> bytes:
        # CancelSessionResponse 'BF41': the signed Ok for the open session,
        # else invalidTransactionId (5) (SGP.22 v3.1 §5.7.14).
        fields = children(request)
        if self._rsp_open is False or fields.get(b"\x80") != self._transaction_id:
            return tlv("BF41", tlv("81", b"\x05"))
        self._rsp_open = False
        signed = tlv("30", tlv("80", self._transaction_id) + tlv("81", bytes.fromhex("88370A")) + tlv("82", fields[b"\x81"]))
        return tlv("BF41", tlv("A0", signed + tlv("5F37", b"\x55" * 64)))
