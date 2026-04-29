"""SGP.32 §6.5 IPA-poll end-to-end against the real simulator engine.

Runs the full TIMER EXPIRATION -> OPEN CHANNEL -> SEND DATA ->
RECEIVE DATA -> CLOSE CHANNEL pipeline with the real
``SimulatedSimCardEngine`` and asserts that an eIM-shaped
``AddEim`` (BF58) ESipa payload delivered through RECEIVE DATA
lands as a new ``SimEimEntry`` in the simulator's ISD-R state.

Production cards do this through a TLS-terminated bearer; here
the modem is impersonated by a tiny in-test FETCH/TR loop. The
ESipa payload is the raw outer SGP.32 TLV the eIM would emit
once the modem stripped HTTP/TLS framing, which exercises the
exact dispatcher path the real eIM hits when the simulator is
plugged into the local eIM ESipa server.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.toolkit import (
    CLOSE_CHANNEL_COMMAND,
    OPEN_CHANNEL_COMMAND,
    RECEIVE_DATA_COMMAND,
    SEND_DATA_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _proactive_body_offset(payload: bytes) -> int:
    """Skip the ``D0`` BER tag + (short or long) length prefix."""
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


def _build_basic_tr(command_number: int, command_type: int, *extra: bytes) -> bytes:
    command_details = tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, 0x00)))
    device_identities = tlv("82", bytes((0x82, 0x81)))
    result = tlv("83", bytes((0x00,)))
    return command_details + device_identities + result + b"".join(extra)


def _build_open_channel_tr(command_number: int) -> bytes:
    return _build_basic_tr(
        command_number, OPEN_CHANNEL_COMMAND, tlv("38", bytes((0x81, 0x00)))
    )


def _build_send_data_tr(command_number: int) -> bytes:
    return _build_basic_tr(command_number, SEND_DATA_COMMAND)


def _build_receive_data_tr(command_number: int, payload: bytes) -> bytes:
    return _build_basic_tr(
        command_number,
        RECEIVE_DATA_COMMAND,
        tlv("36", payload),
        tlv("37", bytes((0x00,))),
    )


def _build_close_channel_tr(command_number: int) -> bytes:
    return _build_basic_tr(command_number, CLOSE_CHANNEL_COMMAND)


def _timer_expiration_envelope(timer_id: int) -> bytes:
    timer_id_tlv = tlv("A4", bytes((timer_id & 0xFF,)))
    timer_value_tlv = tlv("A5", bytes((0x00, 0x00, 0x00)))
    return tlv("D7", timer_id_tlv + timer_value_tlv)


def _build_add_eim_payload(
    *,
    eim_id: str,
    eim_fqdn: str,
    response_tag: str = "BF58",
) -> bytes:
    """Construct an SGP.32 AddEim TLV body the eIM would push.

    Mirrors ``SgpLogic._parse_add_eim_entries`` /
    ``_parse_eim_configuration_row``: outer ``BF58`` wrapper, ``A0``
    list, single ``30`` row carrying ``80`` (eim_id) and ``81``
    (eim_fqdn).
    """

    row = tlv("80", eim_id.encode("utf-8")) + tlv("81", eim_fqdn.encode("utf-8"))
    row_seq = tlv("30", row)
    list_field = tlv("A0", row_seq)
    return tlv(response_tag, list_field)


class _FakeModem:
    """Minimal STK fetch-and-respond loop wired to a real engine toolkit.

    Models a realistic eIM conversation: the first RECEIVE DATA in
    a BIP cycle returns the queued eIM payload (a EuiccPackage); any
    subsequent RECEIVE DATA in the same cycle returns the queued
    "ack" payload (mimicking the eIM's empty-body acknowledgement
    after the IPA's ProvideEimPackageResult).
    """

    def __init__(self, toolkit_logic: ToolkitLogic) -> None:
        self._tk = toolkit_logic
        self._eim_payloads: list[bytes] = []
        self.send_data_payloads: list[bytes] = []
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
            if (
                len(state.pending_fetch_queue) == 0
                and len(state.toolkit.active_proactive_command) == 0
            ):
                break
            command, sw1, sw2 = self._tk.handle_fetch()
            if (sw1, sw2) != (0x90, 0x00) or len(command) == 0:
                break
            cmd_type = _proactive_kind(command)
            cmd_num = _command_number(command)
            if cmd_type == OPEN_CHANNEL_COMMAND:
                tr = _build_open_channel_tr(cmd_num)
            elif cmd_type == SEND_DATA_COMMAND:
                fields = self._tk._parse_proactive_command(command)
                if fields is not None:
                    self.send_data_payloads.append(
                        bytes(fields.get("channel_data", b"") or b"")
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
                tr = _build_basic_tr(cmd_num, cmd_type)
            self._tk.handle_terminal_response(tr)


class IpaPollEngineLoopbackTests(unittest.TestCase):
    """End-to-end IPA-poll round-trip against the real simulator engine."""

    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        runtime_root = Path(self._temp_dir.name) / "runtime"
        runtime_root.mkdir(parents=True, exist_ok=True)
        eim_identity = Path(self._temp_dir.name) / "sim_eim_identity.json"
        eim_identity.write_text(
            json.dumps(
                {
                    "eim_id": "2.25.111111111111111111111111111111111111",
                    "eim_id_type": "oid",
                    "eim_fqdn": "engine.loopback.eim.test",
                    "counter_value": 0,
                    "association_token": -1,
                    "supported_protocol_bits": [0],
                }
            ),
            encoding="utf-8",
        )

        self._env_patch = mock.patch.dict(
            os.environ,
            {
                "YGGDRASIM_RUNTIME_ROOT": str(runtime_root),
                "YGGDRASIM_SIM_EUICC_STORE": str(
                    Path(self._temp_dir.name) / "euicc"
                ),
                "YGGDRASIM_SIM_PROFILE_STORE": str(
                    Path(self._temp_dir.name) / "profiles"
                ),
                "YGGDRASIM_SIM_EIM_IDENTITY": str(eim_identity),
                "YGGDRASIM_SIM_ISDR_CONFIG": "",
                "YGGDRASIM_SIM_QUIRKS": "",
            },
            clear=False,
        )
        self._env_patch.start()

        self.engine = SimulatedSimCardEngine()
        # Re-arm the IPA-poll defaults explicitly so the test does not
        # depend on the workspace ``isdr_config.json`` shape.
        toolkit = self.engine.state.toolkit
        toolkit.ipa_poll_enabled = True
        toolkit.ipa_poll_eim_fqdn = "engine.loopback.eim.test"
        toolkit.ipa_poll_eim_port = 443
        toolkit.ipa_poll_alpha_id = "eIM Poll"
        toolkit.ipa_poll_request_payload = b""
        # Skip the DNS-over-BIP leg by seeding the resolved-IP cache;
        # this loopback test exercises the eIM-side dispatch contract,
        # not the resolver state machine which has its own coverage in
        # ``IpaPollDnsPhaseTests``.
        toolkit.ipa_poll_resolved_ip = "203.0.113.7"
        toolkit.ipa_poll_resolved_ip_family = 4
        # Disable in-card TLS for the dispatcher loopback test -- the
        # contract under test is the SGP.32 envelope wiring, not the
        # TLS engine (which has its own targeted suite).
        toolkit.ipa_poll_tls_enabled = False
        toolkit.timer_management_seconds = 30
        toolkit.timer_management_id = 1
        toolkit.timer_management_auto_rearm = False
        self.engine.state.pending_fetch_queue.clear()

    def tearDown(self) -> None:
        self._env_patch.stop()
        self._temp_dir.cleanup()

    def test_d7_envelope_drives_full_ipa_poll_cycle(self) -> None:
        toolkit_logic = self.engine.toolkit
        baseline_eims = list(self.engine.state.eim_entries)

        # Modem reports D7 TIMER EXPIRATION as ENVELOPE; the
        # toolkit responds with the IPA-poll BIP burst.
        toolkit_logic.handle_envelope(
            _timer_expiration_envelope(1),
            fallback_handler=lambda _payload: (b"", 0x90, 0x00),
        )

        target_eim_id = "2.25.999000111222333444555666777888999000"
        target_fqdn = "ipa.poll.engine.loopback.example"
        eim_payload = _build_add_eim_payload(
            eim_id=target_eim_id, eim_fqdn=target_fqdn
        )

        modem = _FakeModem(toolkit_logic)
        modem.set_eim_payload(eim_payload)
        modem.drain()

        # The IPA dispatcher must have forwarded the BF58 payload
        # to ISD-R, which in turn produced a new SimEimEntry.
        new_entries = [
            entry
            for entry in self.engine.state.eim_entries
            if entry.eim_id == target_eim_id
        ]
        self.assertEqual(
            len(new_entries),
            1,
            f"AddEim payload should have produced one new eIM entry; "
            f"baseline={len(baseline_eims)}, current={len(self.engine.state.eim_entries)}",
        )
        self.assertEqual(new_entries[0].eim_fqdn, target_fqdn)

        # Toolkit bookkeeping must reflect the dispatched package.
        dispatched_tags = list(toolkit_logic.state.toolkit.ipa_poll_dispatched_packages)
        self.assertEqual(dispatched_tags, [bytes.fromhex("BF58")])

        # Session must be torn down at the end of the cycle.
        self.assertFalse(toolkit_logic.state.toolkit.ipa_poll_session_active)

        # SEND DATA must have carried *something*: at minimum the
        # default HTTP wrapper for the eIM endpoint.
        self.assertGreater(len(modem.send_data_payloads), 0)
        sent = b"".join(modem.send_data_payloads)
        self.assertIn(b"engine.loopback.eim.test", sent)

        # The first SEND DATA carries the GetEimPackageRequest
        # (BF4F) wrapped in HTTP framing.
        first_send = modem.send_data_payloads[0]
        self.assertIn(b"\xBF\x4F", first_send)

        # SGP.32 §6.5.2.1 ProvideEimPackageResult follow-up. After
        # the dispatcher consumed the eIM's BF58, the IPA must emit
        # a second SEND DATA carrying a BF50 envelope back to the
        # eIM with the per-package result.
        self.assertGreaterEqual(
            len(modem.send_data_payloads),
            2,
            "Follow-up SEND DATA carrying ProvideEimPackageResult must be emitted",
        )
        followup = modem.send_data_payloads[1]
        self.assertIn(b"\xBF\x50", followup)


if __name__ == "__main__":
    unittest.main()
