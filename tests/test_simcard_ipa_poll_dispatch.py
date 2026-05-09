"""SGP.32 §6.5 IPA dispatch on RECEIVE DATA terminal response.

Pins the in-card IPA contract: when an IPA-poll BIP cycle is in
flight (TIMER EXPIRATION -> OPEN CHANNEL -> SEND DATA -> RECEIVE
DATA -> CLOSE CHANNEL), the bytes the modem hands back via
RECEIVE DATA TR are the eIM's ESipa response. The simulator
parses zero or more EuiccPackages out of the payload (skipping
any HTTP envelope the modem leaves behind) and forwards each
one into ISD-R via the same dispatcher the modem itself would
hit through a CLA/INS=80/E2 STORE DATA chain.

If these tests pass, the simulator behaves as a real in-card IPA
when paired with the local eIM over BIP.
"""

from __future__ import annotations

import unittest
from typing import Any

from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    CLOSE_CHANNEL_COMMAND,
    OPEN_CHANNEL_COMMAND,
    RECEIVE_DATA_COMMAND,
    SEND_DATA_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _make_toolkit_with_ipa_session() -> ToolkitLogic:
    state = SimCardState(
        atr=b"",
        eid="89049032123451234512345678901234",
        iccid="8949000000000000001",
        imsi="999990000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )
    toolkit_logic = ToolkitLogic(state)
    toolkit_logic.state.toolkit.provide_imei = False
    toolkit_logic.state.toolkit.event_list = []
    toolkit_logic.state.toolkit.menu_items = []
    toolkit_logic.state.toolkit.menu_title = ""
    toolkit_logic.state.toolkit.poll_strategy = "timer"
    toolkit_logic.state.toolkit.timer_management_seconds = 30
    toolkit_logic.state.toolkit.timer_management_id = 1
    toolkit_logic.state.toolkit.timer_management_auto_rearm = False
    toolkit_logic.state.toolkit.ipa_poll_enabled = True
    toolkit_logic.state.toolkit.ipa_poll_eim_fqdn = "eim.example.test"
    toolkit_logic.state.toolkit.ipa_poll_eim_port = 443
    toolkit_logic.state.toolkit.ipa_poll_alpha_id = "eIM Poll"
    toolkit_logic.state.toolkit.ipa_poll_request_payload = b""
    # Pre-warm the resolved-IP cache so existing dispatch tests skip
    # the DNS-over-BIP leg and start the cycle on the eIM TCP bearer.
    # The DNS-phase wiring is exercised separately in
    # ``IpaPollDnsPhaseTests``.
    toolkit_logic.state.toolkit.ipa_poll_resolved_ip = "203.0.113.7"
    toolkit_logic.state.toolkit.ipa_poll_resolved_ip_family = 4
    # Stage-2 TLS path is exercised separately in
    # ``IpaPollTlsLoopbackTests``; the dispatch suite verifies the
    # SGP.32 envelope wiring against a plain-HTTP bearer where the
    # RECEIVE DATA payload is interpreted directly as eIM packages.
    toolkit_logic.state.toolkit.ipa_poll_tls_enabled = False
    toolkit_logic.state.pending_fetch_queue.clear()
    return toolkit_logic


def _proactive_body_offset(payload: bytes) -> int:
    """Return the offset inside ``payload`` where the body of the
    ``D0`` proactive command starts. Handles short-form (``D0 LL``)
    and long-form (``D0 81 LL`` / ``D0 82 LL LL``) BER length forms.
    """

    assert payload[:1] == b"\xD0", payload.hex()
    length_byte = payload[1]
    if length_byte < 0x80:
        return 2
    extra = length_byte & 0x7F
    return 2 + extra


def _proactive_kind(payload: bytes) -> int:
    body = payload[_proactive_body_offset(payload):]
    assert body[:1] == b"\x81", body.hex()
    inner = body[2 : 2 + body[1]]
    return inner[1]


def _command_number(payload: bytes) -> int:
    body = payload[_proactive_body_offset(payload):]
    inner = body[2 : 2 + body[1]]
    return inner[0]


def _build_open_channel_tr(command_number: int) -> bytes:
    command_details = tlv(
        "81",
        bytes((command_number & 0xFF, OPEN_CHANNEL_COMMAND, 0x00)),
    )
    device_identities = tlv("82", bytes((0x82, 0x81)))
    result = tlv("83", bytes((0x00,)))
    channel_status = tlv("38", bytes((0x81, 0x00)))
    return command_details + device_identities + result + channel_status


def _build_send_data_tr(command_number: int) -> bytes:
    command_details = tlv(
        "81",
        bytes((command_number & 0xFF, SEND_DATA_COMMAND, 0x01)),
    )
    device_identities = tlv("82", bytes((0x82, 0x81)))
    result = tlv("83", bytes((0x00,)))
    return command_details + device_identities + result


def _build_receive_data_tr(command_number: int, payload_bytes: bytes) -> bytes:
    command_details = tlv(
        "81",
        bytes((command_number & 0xFF, RECEIVE_DATA_COMMAND, 0x00)),
    )
    device_identities = tlv("82", bytes((0x82, 0x81)))
    result = tlv("83", bytes((0x00,)))
    channel_data = tlv("36", payload_bytes)
    channel_remaining = tlv("37", bytes((0x00,)))
    return command_details + device_identities + result + channel_data + channel_remaining


def _build_close_channel_tr(command_number: int) -> bytes:
    command_details = tlv(
        "81",
        bytes((command_number & 0xFF, CLOSE_CHANNEL_COMMAND, 0x00)),
    )
    device_identities = tlv("82", bytes((0x82, 0x81)))
    result = tlv("83", bytes((0x00,)))
    return command_details + device_identities + result


class _FakeModem:
    """Minimal STK fetch-and-respond loop driving the simulator's IPA-poll.

    Drains ``pending_fetch_queue`` until empty, replying with
    canned terminal responses. The eIM-side payload to return on
    RECEIVE DATA is set via ``set_eim_payload``.
    """

    def __init__(self, toolkit_logic: ToolkitLogic) -> None:
        self._tk = toolkit_logic
        self._eim_payloads: list[bytes] = []
        self.sent_payloads: list[bytes] = []
        self._receive_count: int = 0

    def set_eim_payload(self, payload: bytes) -> None:
        self._eim_payloads = [bytes(payload)]

    def set_eim_payload_sequence(self, payloads: list[bytes]) -> None:
        self._eim_payloads = [bytes(item) for item in payloads]

    def drain(self, max_steps: int = 64) -> None:
        steps = 0
        state = self._tk.state
        while steps < max_steps:
            steps += 1
            if len(state.pending_fetch_queue) == 0:
                if len(state.toolkit.active_proactive_command) == 0:
                    break
            command, sw1, sw2 = self._tk.handle_fetch()
            if (sw1, sw2) != (0x90, 0x00) or len(command) == 0:
                break
            cmd_type = _proactive_kind(command)
            cmd_num = _command_number(command)
            if cmd_type == OPEN_CHANNEL_COMMAND:
                tr = _build_open_channel_tr(cmd_num)
            elif cmd_type == SEND_DATA_COMMAND:
                send_data_fields = self._tk._parse_proactive_command(command)
                if send_data_fields is not None:
                    self.sent_payloads.append(
                        bytes(send_data_fields.get("channel_data", b"") or b"")
                    )
                tr = _build_send_data_tr(cmd_num)
            elif cmd_type == RECEIVE_DATA_COMMAND:
                if self._receive_count < len(self._eim_payloads):
                    payload = self._eim_payloads[self._receive_count]
                else:
                    payload = b""
                self._receive_count += 1
                tr = _build_receive_data_tr(cmd_num, payload)
            elif cmd_type == CLOSE_CHANNEL_COMMAND:
                tr = _build_close_channel_tr(cmd_num)
            else:
                tr = (
                    tlv("81", bytes((cmd_num & 0xFF, cmd_type & 0xFF, 0x00)))
                    + tlv("82", bytes((0x82, 0x81)))
                    + tlv("83", bytes((0x00,)))
                )
            self._tk.handle_terminal_response(tr)


class _RecordingDispatcher:
    """Stand-in for ``SgpLogic.handle_store_data``."""

    def __init__(self) -> None:
        self.payloads: list[bytes] = []

    def __call__(self, payload: bytes) -> tuple[bytes, int, int]:
        self.payloads.append(bytes(payload))
        return b"", 0x90, 0x00


class IpaPollDispatchTests(unittest.TestCase):
    """Round-trip RECEIVE DATA payload -> dispatcher fan-out."""

    def test_session_flag_set_on_open_and_cleared_on_close(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic._queue_ipa_poll_sequence()
        self.assertTrue(toolkit_logic.state.toolkit.ipa_poll_session_active)

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(b"")
        modem.drain()

        self.assertFalse(toolkit_logic.state.toolkit.ipa_poll_session_active)

    def test_eim_payload_dispatched_as_store_data(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        dispatcher = _RecordingDispatcher()
        toolkit_logic.set_eim_package_dispatcher(dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        # Two stacked SGP.32 EuiccPackages: the simulator's IPA must
        # forward each one into ISD-R.
        package_a = tlv("BF31", b"\x01\x02")
        package_b = tlv("BF57", b"")
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(package_a + package_b)
        modem.drain()

        self.assertEqual(dispatcher.payloads, [package_a, package_b])

    def test_dispatched_outer_tags_recorded_on_state(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.set_eim_package_dispatcher(_RecordingDispatcher())
        toolkit_logic._queue_ipa_poll_sequence()

        package_a = tlv("BF31", b"\x01")
        package_b = tlv("BF55", b"")
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(package_a + package_b)
        modem.drain()

        outer_tags = list(toolkit_logic.state.toolkit.ipa_poll_dispatched_packages)
        self.assertEqual(outer_tags, [bytes.fromhex("BF31"), bytes.fromhex("BF55")])

    def test_http_envelope_prefix_is_stripped_before_parsing(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        dispatcher = _RecordingDispatcher()
        toolkit_logic.set_eim_package_dispatcher(dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        body_tlv = tlv("BF31", b"\x01\x02\x03")
        http_envelope = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Length: " + str(len(body_tlv)).encode("ascii") + b"\r\n"
            b"\r\n"
        )
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(http_envelope + body_tlv)
        modem.drain()

        self.assertEqual(dispatcher.payloads, [body_tlv])

    def test_unknown_payload_is_ignored_without_raising(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        dispatcher = _RecordingDispatcher()
        toolkit_logic.set_eim_package_dispatcher(dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        # No SGP.32 outer tag in the payload.
        modem.set_eim_payload(b"\xDE\xAD\xBE\xEF")
        modem.drain()

        self.assertEqual(dispatcher.payloads, [])
        self.assertEqual(
            list(toolkit_logic.state.toolkit.ipa_poll_dispatched_packages),
            [],
        )

    def test_dispatcher_failure_does_not_break_remaining_packages(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()

        flaky_payloads: list[bytes] = []

        def _flaky(payload: bytes) -> tuple[bytes, int, int]:
            flaky_payloads.append(bytes(payload))
            if len(flaky_payloads) == 1:
                raise RuntimeError("simulated ISD-R reject")
            return b"", 0x90, 0x00

        toolkit_logic.set_eim_package_dispatcher(_flaky)
        toolkit_logic._queue_ipa_poll_sequence()

        package_a = tlv("BF31", b"\x01")
        package_b = tlv("BF57", b"")
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(package_a + package_b)
        modem.drain()

        self.assertEqual(flaky_payloads, [package_a, package_b])
        # Only the second package should have been recorded as
        # successfully dispatched.
        self.assertEqual(
            list(toolkit_logic.state.toolkit.ipa_poll_dispatched_packages),
            [bytes.fromhex("BF57")],
        )

    def test_no_dispatcher_keeps_state_quiet(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        # Default toolkit is built without a dispatcher in unit tests.
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(tlv("BF31", b"\x01"))
        modem.drain()

        self.assertEqual(
            list(toolkit_logic.state.toolkit.ipa_poll_dispatched_packages),
            [],
        )
        self.assertFalse(toolkit_logic.state.toolkit.ipa_poll_session_active)


class IpaPollEsipaShapeTests(unittest.TestCase):
    """SGP.32 §6.5.2 ESipa request/response shape pinning."""

    def test_default_send_data_carries_get_eim_package_request_bf4f(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic._queue_ipa_poll_sequence()

        send_data = next(
            cmd
            for cmd in toolkit_logic.state.pending_fetch_queue
            if _proactive_kind(cmd) == SEND_DATA_COMMAND
        )

        # BF4F GetEimPackageRequest with the EID under tag 5A.
        self.assertIn(b"\xBF\x4F", send_data)
        self.assertIn(b"\x5A\x10", send_data)
        # HTTP framing must declare a non-zero Content-Length.
        self.assertNotIn(b"Content-Length: 0", send_data)
        self.assertIn(b"X-Admin-Protocol: gsma/rsp/v2.2.0", send_data)

    def test_followup_send_data_carries_provide_eim_package_result_bf50(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()

        non_empty_response = bytes.fromhex("BF5103810100")

        def _dispatcher(_payload: bytes) -> tuple[bytes, int, int]:
            return non_empty_response, 0x90, 0x00

        toolkit_logic.set_eim_package_dispatcher(_dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(tlv("BF31", b"\x01"))
        modem.drain()

        # First SEND DATA = BF4F poll request, second SEND DATA = BF50 result.
        self.assertGreaterEqual(len(modem.sent_payloads), 2)
        self.assertIn(b"\xBF\x4F", modem.sent_payloads[0])
        self.assertIn(b"\xBF\x50", modem.sent_payloads[1])
        # The BF50 payload must wrap the dispatcher's BF51 response.
        self.assertIn(non_empty_response, modem.sent_payloads[1])

    def test_followup_is_not_emitted_when_dispatcher_returns_empty(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.set_eim_package_dispatcher(_RecordingDispatcher())
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(tlv("BF31", b"\x01"))
        modem.drain()

        # Only the initial GetEimPackageRequest was sent; no BF50.
        self.assertEqual(len(modem.sent_payloads), 1)
        self.assertNotIn(b"\xBF\x50", modem.sent_payloads[0])

    def test_dispatcher_forwards_full_sgp32_tag_range(self) -> None:
        """All SGP.32/SGP.22 tags the SGP layer handles must be IPA-routable.

        The IPA is a transparent forwarder for every BFxx tag
        ``SgpLogic.handle_store_data`` knows about. The allow-list
        is the only gatekeeper between the modem's RECEIVE DATA
        bytes and ISD-R; if it is too narrow, an eIM-side
        BoundProfilePackage / ImmediateEnable / EnableEmergency
        sequence silently drops on the floor.
        """

        toolkit_logic = _make_toolkit_with_ipa_session()
        dispatcher = _RecordingDispatcher()
        toolkit_logic.set_eim_package_dispatcher(dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        # Stack one of every supported eIM-side outer tag with a
        # tiny benign body. The dispatcher must call them all.
        tags = [
            "BF21", "BF25", "BF29", "BF2A", "BF2B",
            "BF31", "BF32", "BF33", "BF34", "BF36",
            "BF38", "BF45", "BF54", "BF57", "BF58",
            "BF59", "BF5A", "BF5B", "BF5C", "BF5D",
            "BF5E", "BF5F", "BF64", "BF65",
        ]
        modem.set_eim_payload(b"".join(tlv(tag, b"\x00") for tag in tags))
        modem.drain()

        seen = list(toolkit_logic.state.toolkit.ipa_poll_dispatched_packages)
        expected = [bytes.fromhex(tag) for tag in tags]
        self.assertEqual(seen, expected)

    def test_dispatch_failure_emits_bf50_error_choice(self) -> None:
        """SGP.32 §6.5.2.1 EimPackageResultErrorCode (CHOICE [0])."""

        toolkit_logic = _make_toolkit_with_ipa_session()

        def _failing_dispatcher(_payload: bytes) -> tuple[bytes, int, int]:
            return b"", 0x6A, 0x80  # invalidPackageFormat -> error code 1

        toolkit_logic.set_eim_package_dispatcher(_failing_dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(tlv("BF31", b"\x01"))
        modem.drain()

        # Follow-up SEND DATA carries BF50 with the 80 error CHOICE
        # (no BF51 success branch). SGP.32 §6.5.2.1 explicit tag:
        # 80 LL 30 03 02 01 XX = [0] SEQUENCE { INTEGER errorCode }.
        self.assertGreaterEqual(len(modem.sent_payloads), 2)
        followup = modem.sent_payloads[1]
        self.assertIn(b"\xBF\x50", followup)
        self.assertIn(b"\x80\x05\x30\x03\x02\x01\x01", followup)
        # No BF51 because there's no successful result this cycle.
        self.assertNotIn(b"\xBF\x51", followup)
        # Failure is captured in toolkit state.
        self.assertEqual(
            list(toolkit_logic.state.toolkit.ipa_poll_failed_packages),
            [(bytes.fromhex("BF31"), 1)],
        )

    def test_dispatcher_exception_maps_to_undefined_error_code_127(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()

        def _raising_dispatcher(_payload: bytes) -> tuple[bytes, int, int]:
            raise RuntimeError("boom")

        toolkit_logic.set_eim_package_dispatcher(_raising_dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(tlv("BF58", b"\x01"))
        modem.drain()

        self.assertGreaterEqual(len(modem.sent_payloads), 2)
        followup = modem.sent_payloads[1]
        self.assertIn(b"\x80\x05\x30\x03\x02\x01\x7F", followup)
        self.assertEqual(
            list(toolkit_logic.state.toolkit.ipa_poll_failed_packages),
            [(bytes.fromhex("BF58"), 127)],
        )

    def test_pending_notifications_piggyback_on_bf50(self) -> None:
        """SGP.22 §5.7.10 PendingNotification piggybacked into BF50."""

        toolkit_logic = _make_toolkit_with_ipa_session()
        success_payload = bytes.fromhex("BF5103810100")

        def _ok_dispatcher(_payload: bytes) -> tuple[bytes, int, int]:
            return success_payload, 0x90, 0x00

        toolkit_logic.set_eim_package_dispatcher(_ok_dispatcher)

        # Stage one already-pending notification on the eUICC. The
        # IPA must drain it into the BF50 follow-up so the eIM
        # sees it without a separate BF2B retrieve.
        from SIMCARD.state import SimNotificationEntry
        notification_payload = bytes.fromhex("BF2F03810100")
        toolkit_logic.state.notifications.append(
            SimNotificationEntry(
                seq_number=1,
                operation=1,
                address="rsp.example.com",
                iccid="89490000000000000001",
                payload=notification_payload,
            )
        )

        toolkit_logic._queue_ipa_poll_sequence()
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(tlv("BF31", b"\x01"))
        modem.drain()

        self.assertGreaterEqual(len(modem.sent_payloads), 2)
        followup = modem.sent_payloads[1]
        self.assertIn(b"\xBF\x50", followup)
        self.assertIn(b"\xBF\x51", followup)
        # BF2B retrieve-all wrapper around the staged BF2F
        # PendingNotification.
        self.assertIn(b"\xBF\x2B", followup)
        self.assertIn(notification_payload, followup)

    def test_followup_emitted_only_once_per_cycle(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        non_empty = bytes.fromhex("BF5103810100")

        def _dispatcher(_payload: bytes) -> tuple[bytes, int, int]:
            return non_empty, 0x90, 0x00

        toolkit_logic.set_eim_package_dispatcher(_dispatcher)
        toolkit_logic._queue_ipa_poll_sequence()

        modem = _FakeModem(toolkit_logic)
        # First RECEIVE DATA returns a package, second RECEIVE DATA
        # returns ANOTHER package -- the IPA must NOT inject a
        # third SEND/RECEIVE pair because it has already shipped
        # its result for this cycle.
        modem.set_eim_payload_sequence(
            [tlv("BF31", b"\x01"), tlv("BF31", b"\x02")]
        )
        modem.drain()

        bf50_count = sum(
            1 for payload in modem.sent_payloads if b"\xBF\x50" in payload
        )
        self.assertEqual(bf50_count, 1)
        # CLOSE CHANNEL TR must have torn down both the session
        # and the follow-up latch.
        self.assertFalse(toolkit_logic.state.toolkit.ipa_poll_session_active)
        self.assertFalse(toolkit_logic.state.toolkit.ipa_poll_followup_emitted)


def _build_open_channel_failure_tr(command_number: int) -> bytes:
    """ETSI TS 102 223 §6.6.27 OPEN CHANNEL TR with general result 0x20.

    0x20 = "Bearer Independent Protocol error" + 0x04 additional info
    "no service" -- the canonical failure mode when the modem cannot
    bring the cellular context up. Real terminals emit this when the
    APN is misconfigured or the radio is denied data service.
    """

    command_details = tlv(
        "81",
        bytes((command_number & 0xFF, OPEN_CHANNEL_COMMAND, 0x00)),
    )
    device_identities = tlv("82", bytes((0x82, 0x81)))
    result = tlv("83", bytes((0x20, 0x04)))
    return command_details + device_identities + result


def _build_dns_response_wire(
    transaction_id: int,
    *,
    qname: str,
    qtype: int,
    a_records: list[str] | None = None,
    aaaa_records: list[str] | None = None,
) -> bytes:
    """Encode a synthetic DNS answer mirroring what a public resolver returns."""

    import ipaddress
    import struct

    parts = [piece for piece in str(qname).strip(".").split(".") if len(piece) > 0]
    qname_wire = bytearray()
    for piece in parts:
        encoded = piece.encode("ascii")
        qname_wire.append(len(encoded))
        qname_wire.extend(encoded)
    qname_wire.append(0x00)
    qname_bytes = bytes(qname_wire)
    answers = b""
    record_count = 0
    if a_records:
        for ip in a_records:
            answers += b"\xc0\x0c" + struct.pack(
                ">HHIH", 1, 1, 60, 4
            ) + ipaddress.IPv4Address(ip).packed
            record_count += 1
    if aaaa_records:
        for ip in aaaa_records:
            answers += b"\xc0\x0c" + struct.pack(
                ">HHIH", 28, 1, 60, 16
            ) + ipaddress.IPv6Address(ip).packed
            record_count += 1
    header = struct.pack(
        ">HHHHHH", int(transaction_id) & 0xFFFF, 0x8180, 1, record_count, 0, 0
    )
    question = qname_bytes + struct.pack(">HH", int(qtype) & 0xFFFF, 1)
    return header + question + answers


def _decode_open_channel_tlvs(payload: bytes) -> dict[str, bytes]:
    """Walk the body of an OPEN CHANNEL D0 command into a tag-indexed dict.

    Returns a mapping from one-byte hex tags ("47", "3E", ...) to the
    raw value bytes. Keeps only the first occurrence per tag, which
    matches the layout reference IPA implementations emit.
    """

    body = payload[_proactive_body_offset(payload):]
    out: dict[str, bytes] = {}
    pos = 0
    while pos < len(body):
        tag_byte = body[pos]
        if tag_byte & 0x80:
            tag_byte &= 0x7F
        tag_hex = f"{tag_byte:02X}"
        pos += 1
        if pos >= len(body):
            break
        length = body[pos]
        pos += 1
        if pos + length > len(body):
            break
        if tag_hex not in out:
            out[tag_hex] = body[pos : pos + length]
        pos += length
    return out


class IpaPollDnsPhaseTests(unittest.TestCase):
    """SGP.32 DNS-over-BIP leg ahead of the eIM TCP bearer."""

    def test_dns_open_channel_uses_resolver_apn_and_ip(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.state.toolkit.ipa_poll_resolved_ip = ""
        toolkit_logic.state.toolkit.ipa_poll_apn = "lab.test.apn"
        toolkit_logic.state.toolkit.ipa_poll_dns_server = "8.8.8.8"
        toolkit_logic._queue_ipa_poll_sequence()

        first = bytes(toolkit_logic.state.pending_fetch_queue[0])
        self.assertEqual(_proactive_kind(first), OPEN_CHANNEL_COMMAND)
        tlvs = _decode_open_channel_tlvs(first)
        # APN must travel under tag 47 (Network Access Name), not 3E.
        self.assertIn("47", tlvs)
        self.assertEqual(
            tlvs["47"],
            b"\x03lab\x04test\x03apn",
        )
        # IPv4 destination of the resolver lives under tag 3E with type 0x21.
        self.assertIn("3E", tlvs)
        self.assertEqual(tlvs["3E"], bytes((0x21, 8, 8, 8, 8)))
        # Transport: UDP_REMOTE (0x01) on port 53.
        self.assertIn("3C", tlvs)
        self.assertEqual(tlvs["3C"], bytes((0x01, 0x00, 0x35)))

    def test_dns_phase_advances_through_query_recv_close_then_eim(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.state.toolkit.ipa_poll_resolved_ip = ""
        toolkit_logic.state.toolkit.ipa_poll_apn = "internet.apn"
        toolkit_logic._queue_ipa_poll_sequence()

        fqdn = toolkit_logic.state.toolkit.ipa_poll_eim_fqdn
        # AAAA reply has no records (NXDOMAIN-style empty answer is fine);
        # A reply carries the eIM IP that must end up cached.
        aaaa_id = int(toolkit_logic.state.toolkit.ipa_poll_dns_query_id) - 1
        a_id = int(toolkit_logic.state.toolkit.ipa_poll_dns_query_id)
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload_sequence(
            [
                _build_dns_response_wire(
                    aaaa_id, qname=fqdn, qtype=28, aaaa_records=[]
                ),
                _build_dns_response_wire(
                    a_id, qname=fqdn, qtype=1, a_records=["198.51.100.42"]
                ),
                # eIM phase RECEIVE DATA after the chain transitions.
                b"",
            ]
        )
        modem.drain(max_steps=128)

        self.assertEqual(
            toolkit_logic.state.toolkit.ipa_poll_resolved_ip,
            "198.51.100.42",
        )
        # The phase machine eventually returns to idle and the cycle counter ticks.
        self.assertEqual(toolkit_logic.state.toolkit.ipa_poll_phase, "idle")
        self.assertGreaterEqual(
            toolkit_logic.state.toolkit.ipa_poll_cycle_count, 1
        )

    def test_open_channel_failure_drains_followups(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.state.toolkit.ipa_poll_resolved_ip = ""
        toolkit_logic._queue_ipa_poll_sequence()
        # DNS leg queues OPEN + 2x SEND + TIMER(start) + 2x RECV + TIMER(stop)
        # + CLOSE = 8 commands. The TIMER MANAGEMENT pair gives the modem a
        # polling window between the final SEND DATA and the first RECEIVE
        # DATA so bytes from the network can land in the bearer buffer
        # before the eUICC asks for them; reference IPA cards do the same.
        self.assertEqual(len(toolkit_logic.state.pending_fetch_queue), 8)

        first = bytes(toolkit_logic.state.pending_fetch_queue[0])
        cmd_num = _command_number(first)
        # Pop OPEN out of the queue (FETCH would normally do this) and
        # feed the failure TR straight to the toolkit.
        toolkit_logic.state.pending_fetch_queue.pop(0)
        toolkit_logic.state.toolkit.active_proactive_command = first
        toolkit_logic.handle_terminal_response(
            _build_open_channel_failure_tr(cmd_num)
        )

        self.assertEqual(len(toolkit_logic.state.pending_fetch_queue), 0)
        self.assertFalse(toolkit_logic.state.toolkit.ipa_poll_session_active)
        self.assertEqual(toolkit_logic.state.toolkit.ipa_poll_phase, "idle")

    def test_eim_phase_open_channel_uses_resolved_ip_in_tag_3e(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        # Pre-warm cache so we go straight to eIM phase.
        toolkit_logic.state.toolkit.ipa_poll_resolved_ip = "198.51.100.42"
        toolkit_logic.state.toolkit.ipa_poll_apn = "operator.apn"
        toolkit_logic._queue_ipa_poll_sequence()

        first = bytes(toolkit_logic.state.pending_fetch_queue[0])
        self.assertEqual(_proactive_kind(first), OPEN_CHANNEL_COMMAND)
        tlvs = _decode_open_channel_tlvs(first)
        self.assertIn("47", tlvs)
        self.assertEqual(tlvs["47"], b"\x08operator\x03apn")
        self.assertIn("3E", tlvs)
        self.assertEqual(
            tlvs["3E"], bytes((0x21, 198, 51, 100, 42))
        )
        self.assertIn("3C", tlvs)
        self.assertEqual(tlvs["3C"], bytes((0x02, 0x01, 0xBB)))


class IpaPollBipDeviceIdentitiesTests(unittest.TestCase):
    """ETSI TS 102 223 §8.7 — SEND/RECEIVE/CLOSE follow-ups must
    address the channel id assigned by the OPEN CHANNEL TR (encoded
    as 0x20 + channel_id), not the generic terminal identifier
    (0x82). Modems otherwise return general result 0x3A / additional
    info 0x03 ("Channel identifier not valid").
    """

    @staticmethod
    def _device_identities_dest(payload: bytes) -> int:
        offset = _proactive_body_offset(payload)
        body = payload[offset:]
        # Skip the command details TLV (81 03 num type qual).
        cd_length = body[1]
        cursor = 2 + cd_length
        # Device identities TLV: tag 82, length 02, [src, dst].
        assert body[cursor] == 0x82
        assert body[cursor + 1] == 0x02
        return body[cursor + 3]

    @staticmethod
    def _build_open_channel_tr_with_channel_id(
        command_number: int,
        channel_id: int,
    ) -> bytes:
        command_details = tlv(
            "81",
            bytes((command_number & 0xFF, OPEN_CHANNEL_COMMAND, 0x00)),
        )
        device_identities = tlv("82", bytes((0x82, 0x81)))
        result = tlv("83", bytes((0x00,)))
        # Channel status byte 0: bit 7 = link active, bits 0..2 = ch id.
        channel_status = tlv("38", bytes((0x80 | (int(channel_id) & 0x07), 0x00)))
        return command_details + device_identities + result + channel_status

    def test_pending_send_recv_close_dest_byte_is_patched_on_open_success(
        self,
    ) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        # Use the cold-cache path so the queue contains the full DNS
        # follow-up batch (OPEN + 2x SEND + 2x RECV + CLOSE) when the
        # OPEN CHANNEL TR comes back. Channel 1 → dest byte 0x21.
        toolkit_logic.state.toolkit.ipa_poll_resolved_ip = ""
        toolkit_logic._queue_ipa_poll_sequence()

        open_payload = bytes(toolkit_logic.state.pending_fetch_queue[0])
        cmd_num = _command_number(open_payload)
        toolkit_logic.state.pending_fetch_queue.pop(0)
        toolkit_logic.state.toolkit.active_proactive_command = open_payload
        toolkit_logic.handle_terminal_response(
            self._build_open_channel_tr_with_channel_id(cmd_num, channel_id=1)
        )

        self.assertEqual(toolkit_logic.state.toolkit.open_channel_id, 1)
        # The post-TR sweep covers every BIP follow-up the cycle queued:
        # both the entries still pending in ``pending_fetch_queue`` and
        # the one auto-activated as ``active_proactive_command`` (the
        # next FETCH would consume that one verbatim).
        active = bytes(toolkit_logic.state.toolkit.active_proactive_command or b"")
        bip_payloads: list[bytes] = []
        if len(active) > 0 and _proactive_kind(active) in (
            SEND_DATA_COMMAND,
            RECEIVE_DATA_COMMAND,
            CLOSE_CHANNEL_COMMAND,
        ):
            bip_payloads.append(active)
        for entry in toolkit_logic.state.pending_fetch_queue:
            kind = _proactive_kind(entry)
            if kind in (
                SEND_DATA_COMMAND,
                RECEIVE_DATA_COMMAND,
                CLOSE_CHANNEL_COMMAND,
            ):
                bip_payloads.append(entry)
        self.assertGreaterEqual(len(bip_payloads), 3)
        for payload in bip_payloads:
            self.assertEqual(
                self._device_identities_dest(payload),
                0x21,
                msg=(
                    "BIP follow-up 0x"
                    f"{_proactive_kind(payload):02X} kept stale terminal dest byte"
                ),
            )

    def test_open_channel_failure_clears_open_channel_id(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.state.toolkit.open_channel_id = 4  # stale carry-over
        toolkit_logic._queue_ipa_poll_sequence()
        first = bytes(toolkit_logic.state.pending_fetch_queue[0])
        cmd_num = _command_number(first)
        toolkit_logic.state.pending_fetch_queue.pop(0)
        toolkit_logic.state.toolkit.active_proactive_command = first
        toolkit_logic.handle_terminal_response(
            _build_open_channel_failure_tr(cmd_num)
        )

        self.assertEqual(toolkit_logic.state.toolkit.open_channel_id, 0)

    def test_close_channel_response_clears_open_channel_id(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic._queue_ipa_poll_sequence()

        # Drive the cycle to completion; the close-channel TR resets
        # the channel id back to 0 so the next cycle starts clean.
        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(b"")
        modem.drain()

        self.assertEqual(toolkit_logic.state.toolkit.open_channel_id, 0)

    def test_channel_id_two_yields_dest_byte_0x22(self) -> None:
        toolkit_logic = _make_toolkit_with_ipa_session()
        toolkit_logic.state.toolkit.ipa_poll_resolved_ip = ""
        toolkit_logic._queue_ipa_poll_sequence()

        open_payload = bytes(toolkit_logic.state.pending_fetch_queue[0])
        cmd_num = _command_number(open_payload)
        toolkit_logic.state.pending_fetch_queue.pop(0)
        toolkit_logic.state.toolkit.active_proactive_command = open_payload
        toolkit_logic.handle_terminal_response(
            self._build_open_channel_tr_with_channel_id(cmd_num, channel_id=2)
        )

        self.assertEqual(toolkit_logic.state.toolkit.open_channel_id, 2)
        active = bytes(toolkit_logic.state.toolkit.active_proactive_command or b"")
        candidates: list[bytes] = []
        if len(active) > 0 and _proactive_kind(active) in (
            SEND_DATA_COMMAND,
            RECEIVE_DATA_COMMAND,
            CLOSE_CHANNEL_COMMAND,
        ):
            candidates.append(active)
        for entry in toolkit_logic.state.pending_fetch_queue:
            kind = _proactive_kind(entry)
            if kind in (
                SEND_DATA_COMMAND,
                RECEIVE_DATA_COMMAND,
                CLOSE_CHANNEL_COMMAND,
            ):
                candidates.append(entry)
        for entry in candidates:
            self.assertEqual(
                self._device_identities_dest(entry),
                0x22,
            )


class IpaPollApnFromBppTests(unittest.TestCase):
    """SAIP profile EF.ACL is the source of truth for the IPA-poll APN."""

    def test_extract_apn_from_ef_acl_returns_first_record(self) -> None:
        from SIMCARD.etsi_fs import _extract_apn_from_ef_acl

        # 1 APN, tag 0xDD length 0x0C "internet.apn".
        payload = b"\x01\xDD\x0Cinternet.apn"

        node = type(
            "FakeNode",
            (),
            {"data": payload, "fid": "6F57"},
        )()
        nodes = {"node-1": node}
        path_index = {("MF", "ADF.USIM", "EF.ACL"): "node-1"}
        self.assertEqual(
            _extract_apn_from_ef_acl(nodes, path_index),
            "internet.apn",
        )

    def test_extract_apn_returns_empty_when_record_missing(self) -> None:
        from SIMCARD.etsi_fs import _extract_apn_from_ef_acl

        self.assertEqual(_extract_apn_from_ef_acl({}, {}), "")


if __name__ == "__main__":
    unittest.main()
