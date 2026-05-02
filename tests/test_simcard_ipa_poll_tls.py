"""Loopback coverage for the SGP.32 IPA-poll TLS client wrapper.

Drives an in-process memory-BIO TLS server so a TLS-1.2 handshake
completes without any real socket, then asserts:

* The first SEND DATA emitted begins with a TLS-1.2 ClientHello
  (ContentType=Handshake, message=0x01).
* The handshake reaches steady state (both sides report a usable
  cipher) once the toolkit drains the queue.
* ApplicationData decryption forwards each SGP.32 EuiccPackage TLV
  to the dispatcher, matching the plain-HTTP path's contract.
"""

from __future__ import annotations

import datetime
import os
import ssl
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from SIMCARD.state import SimCardState, SimEimEntry
from SIMCARD.toolkit import (
    CLOSE_CHANNEL_COMMAND,
    OPEN_CHANNEL_COMMAND,
    RECEIVE_DATA_COMMAND,
    SEND_DATA_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


SERVER_HOSTNAME = "loopback.eim.test"


def _generate_test_eim_cert() -> tuple[str, str, str]:
    """Mint a self-signed ECDSA P-256 cert for ``SERVER_HOSTNAME``.

    Returns ``(cert_path, key_path, ca_path)`` with the CA being the
    same self-signed cert (the loopback chain is depth-1).
    """

    priv = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_HOSTNAME)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=180))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(SERVER_HOSTNAME)]),
            critical=False,
        )
        .sign(priv, hashes.SHA256())
    )
    workdir = tempfile.mkdtemp(prefix="ipa_tls_loopback_")
    cert_path = os.path.join(workdir, "server.pem")
    key_path = os.path.join(workdir, "server.key.pem")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(
            priv.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return cert_path, key_path, cert_path


def _proactive_body_offset(payload: bytes) -> int:
    if payload[:1] != b"\xD0":
        return 0
    length_byte = payload[1]
    if length_byte < 0x80:
        return 2
    return 2 + (length_byte & 0x7F)


def _proactive_kind(payload: bytes) -> int:
    body = payload[_proactive_body_offset(payload):]
    # body = 81 03 cmd_num cmd_type qualifier ...
    return body[3]


def _command_number(payload: bytes) -> int:
    body = payload[_proactive_body_offset(payload):]
    return body[2]


def _extract_send_data_payload(payload: bytes) -> bytes:
    """Walk the proactive command body and return the channel data bytes.

    Handles BER short-form (length < 0x80) and long-form (0x81/0x82
    prefixes) length encoding because TLS handshake records routinely
    overflow the 127-byte short form ceiling.
    """

    body = payload[_proactive_body_offset(payload):]
    pos = 0
    while pos < len(body):
        tag_byte = body[pos]
        normalized_tag = tag_byte & 0x7F if (tag_byte & 0x80) else tag_byte
        pos += 1
        if pos >= len(body):
            break
        first_length_byte = body[pos]
        pos += 1
        if first_length_byte < 0x80:
            length = first_length_byte
        elif first_length_byte == 0x81 and pos < len(body):
            length = body[pos]
            pos += 1
        elif first_length_byte == 0x82 and pos + 1 < len(body):
            length = (body[pos] << 8) | body[pos + 1]
            pos += 2
        else:
            break
        if normalized_tag == 0x36:
            return body[pos : pos + length]
        pos += length
    return b""


def _build_open_channel_tr(command_number: int) -> bytes:
    return (
        tlv("81", bytes((command_number & 0xFF, OPEN_CHANNEL_COMMAND, 0x01)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((0x00,)))
        + tlv("38", bytes((0x81, 0x00)))
    )


def _build_send_data_tr(command_number: int) -> bytes:
    return (
        tlv("81", bytes((command_number & 0xFF, SEND_DATA_COMMAND, 0x01)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((0x00,)))
        + tlv("37", bytes((0x00,)))
    )


def _build_receive_data_tr(
    command_number: int,
    payload_bytes: bytes,
    *,
    remaining: int = 0,
) -> bytes:
    return (
        tlv("81", bytes((command_number & 0xFF, RECEIVE_DATA_COMMAND, 0x00)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((0x00,)))
        + tlv("36", bytes(payload_bytes))
        + tlv("37", bytes((int(remaining) & 0xFF,)))
    )


def _build_close_channel_tr(command_number: int) -> bytes:
    return (
        tlv("81", bytes((command_number & 0xFF, CLOSE_CHANNEL_COMMAND, 0x00)))
        + tlv("82", bytes((0x82, 0x81)))
        + tlv("83", bytes((0x00,)))
    )


class _LoopbackTlsServer:
    """Memory-BIO TLS-1.2 server used as the eIM stand-in.

    Receives every TLS record the simulator emits, replies with its
    own handshake / ApplicationData bytes, and yields ``response_bytes``
    once the handshake completes plus an ApplicationData record
    carrying ``response_payload``. The class only acts on bytes -- it
    has no awareness of BIP commands. The driver in the test pumps
    bytes between the simulator's SEND/RECEIVE DATA payloads and the
    server's BIOs.
    """

    def __init__(self, cert_path: str, key_path: str, response_payload: bytes) -> None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert_path, key_path)
        self._incoming = ssl.MemoryBIO()
        self._outgoing = ssl.MemoryBIO()
        self._sslobj = ctx.wrap_bio(self._incoming, self._outgoing, server_side=True)
        self._response_payload = bytes(response_payload)
        self._response_emitted = False
        self.handshake_complete = False
        self.received_app_bytes: bytes = b""

    def feed(self, data: bytes) -> None:
        if len(data) > 0:
            self._incoming.write(data)
        # Drive handshake / receive any ApplicationData.
        while True:
            if self.handshake_complete is False:
                try:
                    self._sslobj.do_handshake()
                    self.handshake_complete = True
                except ssl.SSLWantReadError:
                    return
            if self.handshake_complete:
                try:
                    chunk = self._sslobj.read(16384)
                except ssl.SSLWantReadError:
                    break
                except ssl.SSLZeroReturnError:
                    break
                if len(chunk) == 0:
                    break
                self.received_app_bytes += chunk
            if (
                self.handshake_complete
                and self._response_emitted is False
                and len(self.received_app_bytes) > 0
            ):
                self._sslobj.write(self._response_payload)
                self._response_emitted = True
            return

    def drain_outbound(self) -> bytes:
        return self._outgoing.read()


def _make_toolkit_with_tls_session(ca_path: str) -> ToolkitLogic:
    state = SimCardState(
        atr=b"",
        eid="89049032123451234512345678901234",
        iccid="8949000000000000001",
        imsi="999990000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )
    state.eim_entries = [
        SimEimEntry(
            eim_id="oid:1.2.3",
            eim_fqdn=SERVER_HOSTNAME,
            trusted_tls_public_key_data=_load_pem_as_der(ca_path),
        )
    ]
    toolkit_logic = ToolkitLogic(state)
    tk = toolkit_logic.state.toolkit
    tk.provide_imei = False
    tk.event_list = []
    tk.menu_items = []
    tk.menu_title = ""
    tk.poll_strategy = "timer"
    tk.timer_management_seconds = 30
    tk.timer_management_id = 1
    tk.timer_management_auto_rearm = False
    tk.ipa_poll_enabled = True
    tk.ipa_poll_eim_fqdn = SERVER_HOSTNAME
    tk.ipa_poll_eim_port = 443
    tk.ipa_poll_apn = "lab.test.apn"
    tk.ipa_poll_resolved_ip = "203.0.113.50"
    tk.ipa_poll_resolved_ip_family = 4
    tk.ipa_poll_alpha_id = ""
    tk.ipa_poll_request_payload = b"PING"
    tk.ipa_poll_tls_enabled = True
    tk.ipa_poll_buffer_size = 0x0400
    tk.ipa_poll_receive_size = 0xFA
    state.pending_fetch_queue.clear()
    return toolkit_logic


def _load_pem_as_der(pem_path: str) -> bytes:
    cert = x509.load_pem_x509_certificate(open(pem_path, "rb").read())
    return cert.public_bytes(serialization.Encoding.DER)


class _RecordingDispatcher:
    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def __call__(self, payload: bytes) -> tuple[bytes, int, int]:
        self.payloads.append(bytes(payload))
        return b"", 0x90, 0x00


class _TlsPipeModem:
    """Minimal STK fetch-loop that pipes SEND/RECEIVE DATA into the TLS server.

    The driver:

    * Reacts to OPEN CHANNEL by acking with a generic success TR (the
      simulator then synthesises a ClientHello and queues it as the
      next SEND DATA).
    * Forwards SEND DATA channel data into the loopback TLS server.
    * Drains the loopback server's outgoing BIO into a queue of TLS
      record bytes, slicing them into ``receive_size`` chunks for the
      next RECEIVE DATA TR.
    * Acks CLOSE CHANNEL with success.
    """

    def __init__(
        self,
        toolkit_logic: ToolkitLogic,
        server: _LoopbackTlsServer,
    ) -> None:
        self._tk = toolkit_logic
        self._server = server
        self._pending_inbound: bytes = b""
        self.send_data_payloads: list[bytes] = []
        self.receive_data_payloads: list[bytes] = []

    def drain(self, max_steps: int = 256) -> None:
        for _ in range(max_steps):
            queue = self._tk.state.pending_fetch_queue
            if len(queue) == 0 and len(self._tk.state.toolkit.active_proactive_command) == 0:
                return
            command, sw1, sw2 = self._tk.handle_fetch()
            if (sw1, sw2) != (0x90, 0x00) or len(command) == 0:
                return
            cmd_type = _proactive_kind(command)
            cmd_num = _command_number(command)
            if cmd_type == OPEN_CHANNEL_COMMAND:
                tr = _build_open_channel_tr(cmd_num)
            elif cmd_type == SEND_DATA_COMMAND:
                payload = _extract_send_data_payload(command)
                self.send_data_payloads.append(payload)
                self._server.feed(payload)
                outbound = self._server.drain_outbound()
                if len(outbound) > 0:
                    self._pending_inbound += outbound
                tr = _build_send_data_tr(cmd_num)
            elif cmd_type == RECEIVE_DATA_COMMAND:
                receive_size = max(
                    1, min(0xFF, int(self._tk.state.toolkit.ipa_poll_receive_size or 0xFA))
                )
                if len(self._pending_inbound) == 0:
                    outbound = self._server.drain_outbound()
                    if len(outbound) > 0:
                        self._pending_inbound += outbound
                chunk = self._pending_inbound[:receive_size]
                self._pending_inbound = self._pending_inbound[receive_size:]
                remaining = min(0xFF, len(self._pending_inbound))
                self.receive_data_payloads.append(chunk)
                tr = _build_receive_data_tr(cmd_num, chunk, remaining=remaining)
            elif cmd_type == CLOSE_CHANNEL_COMMAND:
                tr = _build_close_channel_tr(cmd_num)
            else:
                tr = (
                    tlv("81", bytes((cmd_num & 0xFF, cmd_type & 0xFF, 0x00)))
                    + tlv("82", bytes((0x82, 0x81)))
                    + tlv("83", bytes((0x00,)))
                )
            self._tk.handle_terminal_response(tr)


class IpaPollTlsLoopbackTests(unittest.TestCase):
    """Full SGP.32 IPA TLS-on-card cycle pinned against an ssl.SSLObject server."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.cert_path, cls.key_path, cls.ca_path = _generate_test_eim_cert()

    def test_first_send_data_carries_a_clienthello_record(self) -> None:
        toolkit_logic = _make_toolkit_with_tls_session(self.ca_path)
        toolkit_logic._queue_ipa_poll_sequence()

        server = _LoopbackTlsServer(self.cert_path, self.key_path, b"")
        modem = _TlsPipeModem(toolkit_logic, server)
        # Step the simulator just past OPEN CHANNEL so the TLS engine
        # gets created and the first SEND DATA chunk lands in the
        # queue.
        modem.drain(max_steps=4)

        self.assertGreaterEqual(len(modem.send_data_payloads), 1)
        first = modem.send_data_payloads[0]
        self.assertEqual(first[0], 0x16, "TLS Handshake content type")
        self.assertEqual(first[1:3], b"\x03\x01", "TLS legacy_record_version")
        self.assertEqual(first[5], 0x01, "ClientHello handshake type")

    def test_handshake_completes_and_application_payload_round_trips(self) -> None:
        toolkit_logic = _make_toolkit_with_tls_session(self.ca_path)
        eim_response = tlv("BF31", b"\x01\x02\x03")
        server = _LoopbackTlsServer(self.cert_path, self.key_path, eim_response)
        dispatcher = _RecordingDispatcher()
        toolkit_logic.set_eim_package_dispatcher(dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _TlsPipeModem(toolkit_logic, server)
        modem.drain()

        self.assertTrue(server.handshake_complete, "TLS server never finished handshake")
        self.assertEqual(server.received_app_bytes, b"PING")
        # The decrypted plaintext must have been dispatched as an
        # eIM package.
        self.assertEqual(dispatcher.payloads, [eim_response])
        self.assertEqual(
            toolkit_logic.state.toolkit.ipa_poll_tls_decrypted_payload,
            eim_response,
        )

    def test_tls_state_is_cleared_after_close_channel(self) -> None:
        toolkit_logic = _make_toolkit_with_tls_session(self.ca_path)
        eim_response = tlv("BF31", b"\x09")
        server = _LoopbackTlsServer(self.cert_path, self.key_path, eim_response)
        toolkit_logic.set_eim_package_dispatcher(_RecordingDispatcher())
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _TlsPipeModem(toolkit_logic, server)
        modem.drain()

        self.assertIsNone(toolkit_logic.state.toolkit.ipa_poll_tls_state)
        self.assertEqual(toolkit_logic.state.toolkit.ipa_poll_phase, "idle")
        self.assertGreaterEqual(toolkit_logic.state.toolkit.ipa_poll_cycle_count, 1)


if __name__ == "__main__":
    unittest.main()
