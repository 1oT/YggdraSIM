"""ETSI TS 102 223 / 3GPP TS 31.111 STK timer-management bring-up.

Pins the bootstrap proactive-command sequence the simulator emits
right after TERMINAL PROFILE so the modem is steered toward
TIMER EXPIRATION (D7) envelopes instead of the silent POLL INTERVAL
heartbeats. Without this loop the SGP.32 IPA-poll trigger never
fires, which previously kept the eIM poll silent on real hardware.

The tests cover:

* default ``poll_strategy`` (``timer``) emits TIMER MANAGEMENT START
  with the configured timer id / value and *no* POLL INTERVAL,
* explicit ``poll_interval`` strategy is the legacy escape hatch
  that brings POLL INTERVAL back unchanged,
* ``both`` strategy queues TIMER MANAGEMENT first, POLL INTERVAL
  second so the IPAE has a deterministic primary trigger,
* the auto-rearm hook re-enqueues TIMER MANAGEMENT START whenever
  a TIMER EXPIRATION (D7) envelope is delivered,
* auto-rearm honours ``timer_management_auto_rearm = False`` and
  the ``poll_strategy`` selector.
"""

from __future__ import annotations

import unittest

from SIMCARD.state import SimCardState
from SIMCARD.toolkit import (
    CLOSE_CHANNEL_COMMAND,
    OPEN_CHANNEL_COMMAND,
    POLL_INTERVAL_COMMAND,
    PROVIDE_LOCAL_INFORMATION_COMMAND,
    RECEIVE_DATA_COMMAND,
    SEND_DATA_COMMAND,
    TIMER_MANAGEMENT_COMMAND,
    ToolkitLogic,
)
from SIMCARD.utils import tlv


def _make_toolkit() -> ToolkitLogic:
    state = SimCardState(
        atr=b"",
        eid="89049032123451234512345678901234",
        iccid="8949000000000000001",
        imsi="999990000000001",
        default_dp_address="",
        root_ci_pkid=b"",
    )
    toolkit_logic = ToolkitLogic(state)
    # Strip optional bring-up triggers that would otherwise dilute
    # the assertions; this suite is only interested in the polling
    # dispatch. The IPA-poll trigger is also disabled by default so
    # the rearm-focused tests do not see the BIP burst -- the
    # ``TimerExpirationIpaPollTests`` class re-enables it explicitly.
    toolkit_logic.state.toolkit.provide_imei = False
    toolkit_logic.state.toolkit.event_list = []
    toolkit_logic.state.toolkit.menu_items = []
    toolkit_logic.state.toolkit.menu_title = ""
    toolkit_logic.state.toolkit.ipa_poll_enabled = False
    return toolkit_logic


def _proactive_kind(payload: bytes) -> tuple[int, int]:
    """Return ``(command_type, qualifier)`` from a D0 proactive frame."""
    assert payload[:1] == b"\xD0", payload.hex()
    body = payload[2:] if payload[1] < 0x80 else payload[3:]
    assert body[:1] == b"\x81", body.hex()
    inner = body[2 : 2 + body[1]]
    return inner[1], inner[2]


def _timer_value_bcd(seconds: int) -> bytes:
    hours = seconds // 3600
    remainder = seconds - hours * 3600
    minutes = remainder // 60
    secs = remainder - minutes * 60

    def _swap(value: int) -> int:
        units = value % 10
        tens = (value // 10) % 10
        return ((units & 0x0F) << 4) | (tens & 0x0F)

    return bytes((_swap(hours), _swap(minutes), _swap(secs)))


def _timer_expiration_envelope(timer_id: int, seconds: int = 0) -> bytes:
    return tlv(
        "D7",
        tlv("A4", bytes((timer_id,))) + tlv("A5", _timer_value_bcd(seconds)),
    )


class TimerManagementBootstrapTests(unittest.TestCase):
    """ETSI TS 102 223 §6.6.21 TIMER MANAGEMENT bootstrap."""

    def test_default_strategy_emits_timer_management_start(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_id = 1
        toolkit_logic.state.toolkit.poll_interval_seconds = 60

        commands = toolkit_logic._bootstrap_commands()

        kinds = [_proactive_kind(c) for c in commands]
        self.assertIn((TIMER_MANAGEMENT_COMMAND, 0x00), kinds)
        for command_type, _qualifier in kinds:
            self.assertNotEqual(command_type, POLL_INTERVAL_COMMAND)

    def test_default_strategy_encodes_timer_id_and_value(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 65
        toolkit_logic.state.toolkit.timer_management_id = 3

        commands = toolkit_logic._bootstrap_commands()
        timer_command = next(
            c for c in commands if _proactive_kind(c)[0] == TIMER_MANAGEMENT_COMMAND
        )

        # Timer Identifier TLV (24) + Timer Value TLV (25) must trail
        # the Command Details / Device Identities pair. Reference IPA
        # cards emit the comprehension-clear form so picky modems do
        # not reject the proactive command; the simulator now mirrors
        # that.
        self.assertIn(b"\x24\x01\x03", timer_command)
        self.assertIn(b"\x25\x03" + _timer_value_bcd(65), timer_command)
        self.assertEqual(toolkit_logic.state.toolkit.timer_table.get(3), 65)

    def test_poll_interval_strategy_keeps_legacy_path(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "poll_interval"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.poll_interval_seconds = 45

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        self.assertIn((POLL_INTERVAL_COMMAND, 0x00), kinds)
        for command_type, _qualifier in kinds:
            self.assertNotEqual(command_type, TIMER_MANAGEMENT_COMMAND)

    def test_both_strategy_orders_timer_before_poll_interval(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "both"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.poll_interval_seconds = 45

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        self.assertEqual(
            kinds,
            [(TIMER_MANAGEMENT_COMMAND, 0x00), (POLL_INTERVAL_COMMAND, 0x00)],
        )

    def test_off_strategy_emits_no_polling_command(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "off"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.poll_interval_seconds = 45

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        for command_type, _qualifier in kinds:
            self.assertNotEqual(command_type, TIMER_MANAGEMENT_COMMAND)
            self.assertNotEqual(command_type, POLL_INTERVAL_COMMAND)

    def test_provide_imei_is_still_emitted_alongside_timer(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.provide_imei = True
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30

        kinds = [_proactive_kind(c) for c in toolkit_logic._bootstrap_commands()]

        # Bootstrap order is fixed: PROVIDE LOCAL INFO -> menu/event ->
        # polling. Pin the contract so a future re-shuffle is caught.
        self.assertEqual(
            [k for k, _ in kinds],
            [PROVIDE_LOCAL_INFORMATION_COMMAND, TIMER_MANAGEMENT_COMMAND],
        )


class TimerExpirationAutoRearmTests(unittest.TestCase):
    """3GPP TS 31.111 §7.5.6 TIMER EXPIRATION re-arm."""

    def test_d7_envelope_triggers_rearm_when_enabled(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_id = 1
        toolkit_logic.state.toolkit.timer_management_auto_rearm = True
        # Bootstrap to consume the initial TIMER MANAGEMENT START.
        for command in toolkit_logic._bootstrap_commands():
            toolkit_logic._enqueue_command(command)
        toolkit_logic.state.pending_fetch_queue.clear()

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        queue = list(toolkit_logic.state.pending_fetch_queue)
        self.assertEqual(len(queue), 1)
        self.assertEqual(_proactive_kind(queue[0]), (TIMER_MANAGEMENT_COMMAND, 0x00))
        self.assertEqual(toolkit_logic.state.toolkit.timer_table.get(1), 30)

    def test_auto_rearm_disabled_keeps_queue_empty(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_auto_rearm = False
        toolkit_logic.state.pending_fetch_queue.clear()

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        self.assertEqual(list(toolkit_logic.state.pending_fetch_queue), [])

    def test_poll_interval_strategy_does_not_rearm_timer(self) -> None:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "poll_interval"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_auto_rearm = True
        toolkit_logic.state.pending_fetch_queue.clear()

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        self.assertEqual(list(toolkit_logic.state.pending_fetch_queue), [])


class TimerExpirationIpaPollTests(unittest.TestCase):
    """SGP.32 §3.5 IPA-poll BIP trigger pinned on D7 expiry."""

    def _make_logic(self, *, warm_resolved_ip: bool = True) -> ToolkitLogic:
        toolkit_logic = _make_toolkit()
        toolkit_logic.state.toolkit.poll_strategy = "timer"
        toolkit_logic.state.toolkit.timer_management_seconds = 30
        toolkit_logic.state.toolkit.timer_management_id = 1
        toolkit_logic.state.toolkit.timer_management_auto_rearm = True
        toolkit_logic.state.toolkit.ipa_poll_enabled = True
        toolkit_logic.state.toolkit.ipa_poll_eim_fqdn = "yggdrasim.eim.test.1ot.com"
        toolkit_logic.state.toolkit.ipa_poll_eim_port = 443
        toolkit_logic.state.toolkit.ipa_poll_apn = "internet.apn"
        toolkit_logic.state.toolkit.ipa_poll_dns_server = "8.8.8.8"
        toolkit_logic.state.toolkit.ipa_poll_alpha_id = ""
        toolkit_logic.state.toolkit.ipa_poll_request_payload = b""
        # The bringup tests pin the linear command queue from Stage 1;
        # disable in-card TLS so the eIM leg keeps emitting OPEN/SEND/
        # RECV/CLOSE up-front. Stage-2 TLS pumping has its own suite.
        toolkit_logic.state.toolkit.ipa_poll_tls_enabled = False
        if warm_resolved_ip:
            toolkit_logic.state.toolkit.ipa_poll_resolved_ip = "203.0.113.7"
            toolkit_logic.state.toolkit.ipa_poll_resolved_ip_family = 4
        else:
            toolkit_logic.state.toolkit.ipa_poll_resolved_ip = ""
            toolkit_logic.state.toolkit.ipa_poll_resolved_ip_family = 0
        toolkit_logic.state.pending_fetch_queue.clear()
        return toolkit_logic

    def test_d7_warm_cache_emits_eim_phase_then_rearm(self) -> None:
        # When a previous cycle already cached the eIM IP, the timer
        # expiry skips the DNS leg and ships the eIM
        # OPEN/SEND/TIMER(start)/RECV/TIMER(stop)/CLOSE straight away,
        # followed by the auto-rearm. The watchdog timer pair gives
        # the modem a polling window between SEND DATA and RECEIVE
        # DATA so the network response actually lands in the bearer
        # buffer before the eUICC issues RECEIVE DATA -- reference
        # IPA cards do the same and skipping it makes the modem
        # answer with general result 0x3A on every RECEIVE DATA.
        toolkit_logic = self._make_logic(warm_resolved_ip=True)

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        kinds = [_proactive_kind(c)[0] for c in toolkit_logic.state.pending_fetch_queue]
        self.assertEqual(
            kinds,
            [
                OPEN_CHANNEL_COMMAND,
                SEND_DATA_COMMAND,
                TIMER_MANAGEMENT_COMMAND,
                RECEIVE_DATA_COMMAND,
                TIMER_MANAGEMENT_COMMAND,
                CLOSE_CHANNEL_COMMAND,
                TIMER_MANAGEMENT_COMMAND,
            ],
        )

    def test_d7_cold_cache_emits_dns_leg_then_rearm(self) -> None:
        # Cold start: no resolved IP cached, so the IPA must first
        # open a UDP/53 bearer to the public resolver and exchange
        # DNS questions/answers before the eIM TCP/443 cycle even
        # gets queued. The DNS leg uses two SEND DATA + two RECEIVE
        # DATA commands (AAAA + A questions) interleaved with a
        # TIMER MANAGEMENT pair so the modem has time to receive the
        # DNS response from the network between the SEND burst and
        # the RECEIVE burst.
        toolkit_logic = self._make_logic(warm_resolved_ip=False)

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        kinds = [_proactive_kind(c)[0] for c in toolkit_logic.state.pending_fetch_queue]
        self.assertEqual(
            kinds,
            [
                OPEN_CHANNEL_COMMAND,
                SEND_DATA_COMMAND,
                SEND_DATA_COMMAND,
                TIMER_MANAGEMENT_COMMAND,
                RECEIVE_DATA_COMMAND,
                RECEIVE_DATA_COMMAND,
                TIMER_MANAGEMENT_COMMAND,
                CLOSE_CHANNEL_COMMAND,
                TIMER_MANAGEMENT_COMMAND,
            ],
        )

    def test_eim_open_channel_carries_resolved_ip_in_tag_3e(self) -> None:
        toolkit_logic = self._make_logic(warm_resolved_ip=True)
        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        open_channel = next(
            cmd
            for cmd in toolkit_logic.state.pending_fetch_queue
            if _proactive_kind(cmd)[0] == OPEN_CHANNEL_COMMAND
        )

        # Tag 3C: TCP_CLIENT_REMOTE (0x02) on port 443 (0x01BB).
        self.assertIn(b"\x3C\x03\x02\x01\xBB", open_channel)
        # Tag 3E: 0x21 IPv4 prefix + 4 bytes of "203.0.113.7".
        self.assertIn(b"\x3E\x05\x21\xCB\x00\x71\x07", open_channel)
        # Tag 47: APN, label-list encoded.
        self.assertIn(b"\x47\x0D\x08internet\x03apn", open_channel)
        # Alpha (05) is present-but-empty so the modem can label the
        # bearer in its UI without forcing user-visible text.
        self.assertIn(b"\x05\x00", open_channel)

    def test_dns_open_channel_targets_resolver_with_apn(self) -> None:
        toolkit_logic = self._make_logic(warm_resolved_ip=False)
        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        open_channel = next(
            cmd
            for cmd in toolkit_logic.state.pending_fetch_queue
            if _proactive_kind(cmd)[0] == OPEN_CHANNEL_COMMAND
        )

        # UDP_REMOTE on port 53.
        self.assertIn(b"\x3C\x03\x01\x00\x35", open_channel)
        # Resolver IPv4 = 8.8.8.8.
        self.assertIn(b"\x3E\x05\x21\x08\x08\x08\x08", open_channel)
        # APN under tag 47.
        self.assertIn(b"\x47\x0D\x08internet\x03apn", open_channel)

    def test_send_data_after_warm_cache_carries_eim_http_envelope(self) -> None:
        toolkit_logic = self._make_logic(warm_resolved_ip=True)
        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        send_data = next(
            cmd
            for cmd in toolkit_logic.state.pending_fetch_queue
            if _proactive_kind(cmd)[0] == SEND_DATA_COMMAND
        )

        self.assertIn(b"POST /gsma/rsp2/asn1 HTTP/1.1", send_data)
        self.assertIn(b"Host: yggdrasim.eim.test.1ot.com", send_data)
        self.assertIn(b"\x36", send_data)

    def test_custom_request_payload_overrides_default(self) -> None:
        toolkit_logic = self._make_logic(warm_resolved_ip=True)
        toolkit_logic.state.toolkit.ipa_poll_request_payload = b"\xCA\xFE\xBA\xBE"

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        send_data = next(
            cmd
            for cmd in toolkit_logic.state.pending_fetch_queue
            if _proactive_kind(cmd)[0] == SEND_DATA_COMMAND
        )
        self.assertIn(b"\x36\x04\xCA\xFE\xBA\xBE", send_data)

    def test_disabling_ipa_poll_keeps_only_rearm(self) -> None:
        toolkit_logic = self._make_logic()
        toolkit_logic.state.toolkit.ipa_poll_enabled = False

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        kinds = [_proactive_kind(c)[0] for c in toolkit_logic.state.pending_fetch_queue]
        self.assertEqual(kinds, [TIMER_MANAGEMENT_COMMAND])

    def test_missing_fqdn_skips_ipa_poll_but_keeps_rearm(self) -> None:
        toolkit_logic = self._make_logic()
        toolkit_logic.state.toolkit.ipa_poll_eim_fqdn = ""
        toolkit_logic.state.eim_entries = []

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        kinds = [_proactive_kind(c)[0] for c in toolkit_logic.state.pending_fetch_queue]
        self.assertEqual(kinds, [TIMER_MANAGEMENT_COMMAND])

    def test_falls_back_to_first_eim_entry_fqdn(self) -> None:
        from SIMCARD.state import SimEimEntry

        # Cold cache + no configured FQDN: the IPA resolves the FQDN
        # of the first eIM entry. The labels of that FQDN must show
        # up inside the DNS-question SEND DATA payloads, not inside
        # the OPEN CHANNEL TLVs (which now carry the resolver IP).
        toolkit_logic = self._make_logic(warm_resolved_ip=False)
        toolkit_logic.state.toolkit.ipa_poll_eim_fqdn = ""
        toolkit_logic.state.eim_entries = [
            SimEimEntry(
                eim_id="oid:1.2.3",
                eim_fqdn="lpa.test.example",
            )
        ]

        toolkit_logic._apply_timer_expiration(_timer_expiration_envelope(1))

        send_data_payloads = [
            cmd
            for cmd in toolkit_logic.state.pending_fetch_queue
            if _proactive_kind(cmd)[0] == SEND_DATA_COMMAND
        ]
        self.assertGreaterEqual(len(send_data_payloads), 2)
        joined = b"".join(send_data_payloads)
        self.assertIn(b"\x03lpa", joined)
        self.assertIn(b"\x04test", joined)
        self.assertIn(b"\x07example", joined)


if __name__ == "__main__":
    unittest.main()
