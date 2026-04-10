import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest import mock

from plugins import polling_plugin


class _DummyApduChannel:
    def __init__(self) -> None:
        self.reset_count = 0

    def exchange(self, apdu: bytes):
        return b"", 0x90, 0x00

    def reset(self) -> bool:
        self.reset_count += 1
        return True


class _FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += max(0.0, float(seconds))


class _DummyRelayTarget:
    def __init__(self, clock: _FakeClock) -> None:
        self._clock = clock
        self._last_timer_emit_at: float | None = None
        self._eim_poll_debug_enabled = False
        self.watchdog_pre_reset_calls = 0
        self.apdu_channel = _DummyApduChannel()
        self.state = SimpleNamespace(
            stk_open_channel_active=False,
            stk_poll_thread_attempt_limit=0,
            stk_poll_configured_targets=[],
            stk_poll_target_attempt_counts={},
            stk_polling_off=False,
            stk_poll_interval_seconds=0,
            stk_command_history=[],
            stk_generic_ack_history=[],
            stk_status_history=[],
            stk_flow_events=[],
            stk_timer_history=[],
            stk_open_channel_history=[],
            stk_open_channel_endpoint_history=[],
            stk_open_channel_dns_hint_history=[],
            stk_open_channel_failure_history=[],
            stk_dns_history=[],
            stk_tls_history=[],
            stk_alert_history=[],
            stk_network_history=[],
            stk_timers={},
            stk_trigger_history=[],
        )
        self.events: list[str] = []
        self.timer_emit_times: list[float] = []
        self.exchange_log_names: list[str] = []
        self.exchange_apdu_log_names: list[str] = []
        self.status_log_names: list[str] = []
        self.location_event_times: list[float] = []
        self.location_event_log_names: list[str] = []
        self.cached_poll_targets: list[str] = []
        self.live_bf55_entries: list[dict[str, str]] = []
        self.live_bf55_fetches = 0
        self.stk_init_calls = 0
        self._reset_eim_poll_debug_state = lambda: None
        self._record_eim_poll_event = lambda message: self.events.append(message)
        self._run_stateful_stk_initialization = self._run_stateful_stk_initialization_impl
        self._should_send_generic_location_status_event = lambda: False
        self._service_active_bip_session_if_ready = lambda log_name: False
        self._emit_due_stk_timer_expirations = self._emit_due_stk_timer_expirations_impl
        self._emit_stk_location_status_event = self._emit_stk_location_status_event_impl
        self._exchange_eim_poll_apdu = self._exchange_eim_poll_apdu_impl
        self._exchange_apdu = self._exchange_apdu_impl
        self._resolve_cached_poll_target_fqdns = lambda: list(self.cached_poll_targets)
        self._retrieve_es10b_data = self._retrieve_es10b_data_impl
        self._decode_eim_configuration_entries = (
            lambda response: list(self.live_bf55_entries)
        )
        self._run_watchdog_pre_reset = self._run_watchdog_pre_reset_impl
        self._queued_stk_pending_length = lambda: 0
        self._print_eim_poll_flow_summary = lambda: None
        self._close_stk_open_channel = lambda: None
        self._encode_der_length = lambda length: bytes([length])
        self.status_dns_queries: dict[str, list[str]] = {}

    def _emit_due_stk_timer_expirations_impl(
        self,
        log_prefix: str,
        force_all_active: bool = False,
        forced_timer_activation_counts: dict[int, int] | None = None,
        stimulus_counts: dict[str, int] | None = None,
    ) -> bool:
        if self._last_timer_emit_at == self._clock.now:
            return False
        self._last_timer_emit_at = self._clock.now
        self.timer_emit_times.append(self._clock.now)
        return True

    def _run_stateful_stk_initialization_impl(self) -> None:
        self.stk_init_calls += 1
        self.state.stk_event_list = []
        self.state.stk_poll_interval_seconds = 0
        self.state.stk_polling_off = False
        self.state.stk_last_proactive_command = b""
        self.state.stk_timers = {}
        self.state.stk_open_channel_active = False
        self.state.stk_open_channel_protocol = ""
        self.state.stk_open_channel_endpoint = ""
        self.state.stk_pending_channel_queue = []
        self.state.stk_pending_channel_data = b""
        self.state.stk_last_channel_data_sent = 0

    def _run_watchdog_pre_reset_impl(self) -> None:
        self.watchdog_pre_reset_calls += 1

    def _emit_stk_location_status_event_impl(
        self,
        log_name: str,
        *,
        event_label: str = "generic",
    ) -> tuple[int, int]:
        self.location_event_log_names.append(log_name)
        self.location_event_times.append(self._clock.now)
        self.events.append(f"{event_label} LOCATION STATUS emitted at {self._clock.now:.1f}s")
        return 0x90, 0x00

    def _exchange_eim_poll_apdu_impl(self, apdu: bytes, log_name: str):
        self.exchange_log_names.append(log_name)
        if "STATUS [" in log_name:
            self.status_log_names.append(log_name)
            for query_index, qname_value in enumerate(
                self.status_dns_queries.get(log_name, []),
                start=1,
            ):
                self.state.stk_dns_history.append(
                    "TX DNS Query: "
                    f"id=0x{len(self.state.stk_dns_history) + query_index:04X} "
                    f"qname={qname_value} type=A class=IN"
                )
        return b"", 0x90, 0x00

    def _exchange_apdu_impl(self, apdu: bytes, log_name: str):
        self.exchange_apdu_log_names.append(log_name)
        return b"", 0x90, 0x00

    def _retrieve_es10b_data_impl(self, payload: bytes, log_name: str) -> bytes:
        self.live_bf55_fetches += 1
        return b"\xBF\x55\x00"


class PollingPluginWatchdogTests(unittest.TestCase):
    def test_watchdog_keeps_timer_stimuli_active_during_post_status_loops(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        runtime = polling_plugin._RelayPollingRuntime(target)

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(polling_plugin.time, "sleep", side_effect=clock.sleep),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runtime.run_eim_status_watchdog(
                interval_seconds=1,
                timer_expiration_window_seconds=30,
                poll_attempts_per_fqdn=1,
                poll_attempt_post_status_loops=2,
            )

        self.assertEqual(
            target.status_log_names,
            [
                "EIM-POLL: STATUS [1]",
                "EIM-POLL: STATUS [2]",
                "EIM-POLL: STATUS [3]",
            ],
        )
        self.assertEqual(target.timer_emit_times, [0.0, 1.0, 2.0])
        self.assertIn(
            "Requested STATUS poll count reached; starting 2 post-target STATUS verification checks.",
            target.events,
        )
        self.assertIn(
            "Poll attempt target mode completed with idle post-target STATUS checks.",
            target.events,
        )

    def test_watchdog_runs_pre_reset_then_transport_reset_then_stk_init(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        runtime = polling_plugin._RelayPollingRuntime(target)

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(polling_plugin.time, "sleep", side_effect=clock.sleep),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runtime.run_eim_status_watchdog(
                interval_seconds=1,
                timer_expiration_window_seconds=0,
                poll_attempts_per_fqdn=3,
                poll_attempt_delay_seconds=1,
                poll_attempt_post_status_loops=1,
            )

        self.assertEqual(
            target.status_log_names,
            [
                "EIM-POLL: STATUS [1]",
                "EIM-POLL: STATUS [2]",
                "EIM-POLL: STATUS [3]",
                "EIM-POLL: STATUS [4]",
            ],
        )
        self.assertEqual(target.apdu_channel.reset_count, 1)
        self.assertEqual(target.watchdog_pre_reset_calls, 1)
        self.assertEqual(target.stk_init_calls, 1)
        self.assertIn(
            "Watchdog pre-reset sequence completed before poll sequencing.",
            target.events,
        )
        self.assertIn(
            "Card transport reset before watchdog.",
            target.events,
        )

    def test_watchdog_falls_back_to_transport_reset_when_pre_reset_callback_is_unavailable(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target._run_watchdog_pre_reset = None
        runtime = polling_plugin._RelayPollingRuntime(target)

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(polling_plugin.time, "sleep", side_effect=clock.sleep),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runtime.run_eim_status_watchdog(
                interval_seconds=1,
                timer_expiration_window_seconds=0,
                poll_attempts_per_fqdn=3,
                poll_attempt_delay_seconds=1,
                poll_attempt_post_status_loops=1,
            )

        self.assertEqual(target.apdu_channel.reset_count, 1)
        self.assertEqual(target.watchdog_pre_reset_calls, 0)
        self.assertEqual(target.stk_init_calls, 1)
        self.assertIn(
            "Card transport reset before watchdog.",
            target.events,
        )

    def test_watchdog_inserts_location_status_halfway_between_main_poll_attempts(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target._should_send_generic_location_status_event = lambda: True
        runtime = polling_plugin._RelayPollingRuntime(target)

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(polling_plugin.time, "sleep", side_effect=clock.sleep),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runtime.run_eim_status_watchdog(
                interval_seconds=1,
                timer_expiration_window_seconds=0,
                poll_attempts_per_fqdn=3,
                poll_attempt_delay_seconds=2,
                poll_attempt_post_status_loops=1,
            )

        self.assertEqual(
            target.status_log_names,
            [
                "EIM-POLL: STATUS [1]",
                "EIM-POLL: STATUS [2]",
                "EIM-POLL: STATUS [3]",
                "EIM-POLL: STATUS [4]",
            ],
        )
        self.assertEqual(
            target.location_event_log_names,
            [
                "EIM-POLL: INTERSTITIAL LOCATION STATUS [1->2]",
                "EIM-POLL: INTERSTITIAL LOCATION STATUS [2->3]",
            ],
        )
        self.assertEqual(target.location_event_times, [1.0, 3.0])
        self.assertIn(
            "LOCATION STATUS event armed; strict poll attempt mode will emit interstitial LOCATION STATUS stimuli between poll attempts.",
            target.events,
        )
        self.assertIn(
            "Interstitial LOCATION STATUS scheduled halfway before STATUS [2].",
            target.events,
        )
        self.assertIn(
            "Interstitial LOCATION STATUS scheduled halfway before STATUS [3].",
            target.events,
        )

    def test_watchdog_requires_per_target_dns_coverage_before_post_status_phase(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target._resolve_watchdog_poll_attempt_targets = lambda: [
            "eim2.esim.tst.1ot.mobi",
            "eim1.sm.1ot.com",
        ]
        target.status_dns_queries = {
            "EIM-POLL: STATUS [1]": ["eim1.sm.1ot.com", "eim1.sm.1ot.com"],
            "EIM-POLL: STATUS [2]": [
                "eim2.esim.tst.1ot.mobi",
                "eim2.esim.tst.1ot.mobi",
            ],
            "EIM-POLL: STATUS [3]": ["eim1.sm.1ot.com"],
            "EIM-POLL: STATUS [4]": ["eim2.esim.tst.1ot.mobi"],
        }
        runtime = polling_plugin._RelayPollingRuntime(target)

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(polling_plugin.time, "sleep", side_effect=clock.sleep),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            runtime.run_eim_status_watchdog(
                interval_seconds=1,
                timer_expiration_window_seconds=0,
                timer_window_explicit=True,
                poll_attempts_per_fqdn=2,
                poll_attempt_delay_seconds=1,
                poll_attempt_post_status_loops=1,
            )

        self.assertEqual(
            target.status_log_names,
            [
                "EIM-POLL: STATUS [1]",
                "EIM-POLL: STATUS [2]",
                "EIM-POLL: STATUS [3]",
                "EIM-POLL: STATUS [4]",
                "EIM-POLL: STATUS [5]",
            ],
        )
        self.assertIn(
            "Configured BF55 eIM targets: eim2.esim.tst.1ot.mobi, eim1.sm.1ot.com",
            target.events,
        )
        self.assertIn(
            "Per-target initiated poll coverage: "
            "eim2.esim.tst.1ot.mobi=2/2, eim1.sm.1ot.com=2/2",
            target.events,
        )
        self.assertEqual(
            target.state.stk_poll_target_attempt_counts,
            {
                "eim2.esim.tst.1ot.mobi": 2,
                "eim1.sm.1ot.com": 2,
            },
        )

    def test_watchdog_ends_after_stalled_per_target_coverage_when_timer_window_is_closed(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target._resolve_watchdog_poll_attempt_targets = lambda: [
            "eim2.esim.tst.1ot.mobi",
            "eim1.sm.1ot.com",
        ]
        runtime = polling_plugin._RelayPollingRuntime(target)
        rendered = io.StringIO()

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            mock.patch.object(polling_plugin.time, "sleep", side_effect=clock.sleep),
            contextlib.redirect_stdout(rendered),
        ):
            runtime.run_eim_status_watchdog(
                interval_seconds=1,
                timer_expiration_window_seconds=0,
                timer_window_explicit=True,
                poll_attempts_per_fqdn=2,
                poll_attempt_delay_seconds=1,
                poll_attempt_post_status_loops=1,
            )

        self.assertEqual(
            target.status_log_names,
            [
                "EIM-POLL: STATUS [1]",
                "EIM-POLL: STATUS [2]",
                "EIM-POLL: STATUS [3]",
            ],
        )
        self.assertIn(
            "timer stimulus window closed and per-target initiated poll coverage stalled",
            rendered.getvalue().lower(),
        )
        self.assertIn(
            "Timer stimulus window closed and per-target initiated poll coverage stalled "
            "at eim2.esim.tst.1ot.mobi=0/2, eim1.sm.1ot.com=0/2.",
            target.events,
        )

    def test_timer_window_extension_scales_with_configured_target_count(self) -> None:
        self.assertEqual(
            polling_plugin._resolve_effective_timer_expiration_window_seconds(
                55,
                4,
                15,
                poll_attempt_post_status_loops=2,
                configured_target_count=2,
                interval_seconds=5,
            ),
            (115, True),
        )

    def test_resolve_watchdog_targets_prefers_cached_snapshot_targets(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target.cached_poll_targets = [
            "eim1.sm.1ot.com",
            "EIM2.ESIM.TST.1OT.MOBI.",
            "eim1.sm.1ot.com",
        ]
        target.live_bf55_entries = [
            {"eim_fqdn": "should-not-be-read.example"},
        ]
        runtime = polling_plugin._RelayPollingRuntime(target)

        targets = runtime._resolve_watchdog_poll_attempt_targets()

        self.assertEqual(
            targets,
            [
                "eim1.sm.1ot.com",
                "eim2.esim.tst.1ot.mobi",
            ],
        )
        self.assertEqual(target.live_bf55_fetches, 0)
        self.assertIn(
            "Cached discovery snapshot provided configured poll targets.",
            target.events,
        )

    def test_resolve_watchdog_targets_falls_back_to_live_bf55_when_cache_empty(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target.live_bf55_entries = [
            {"eim_fqdn": "EIM2.ESIM.TST.1OT.MOBI."},
            {"eim_fqdn": "eim1.sm.1ot.com"},
        ]
        runtime = polling_plugin._RelayPollingRuntime(target)

        targets = runtime._resolve_watchdog_poll_attempt_targets()

        self.assertEqual(
            targets,
            [
                "eim2.esim.tst.1ot.mobi",
                "eim1.sm.1ot.com",
            ],
        )
        self.assertEqual(target.live_bf55_fetches, 1)

    def test_collect_initiated_poll_targets_since_deduplicates_same_target_within_status(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        runtime = polling_plugin._RelayPollingRuntime(target)
        target.state.stk_dns_history.extend(
            [
                "TX DNS Query: id=0x0001 qname=eim1.sm.1ot.com type=AAAA class=IN",
                "RX DNS Response: id=0x0001 qname=eim1.sm.1ot.com qd=1 an=0 ns=0 ar=0 rcode=0",
                "TX DNS Query: id=0x0002 qname=eim1.sm.1ot.com type=A class=IN",
                "RX DNS Response: id=0x0002 qname=eim1.sm.1ot.com qd=1 an=1 ns=0 ar=0 rcode=0 answers=A:194.29.54.4",
                "TX DNS Query: id=0x0003 qname=eim2.esim.tst.1ot.mobi type=A class=IN",
            ]
        )

        initiated_targets = runtime._collect_initiated_poll_targets_since(
            [
                "eim1.sm.1ot.com",
                "eim2.esim.tst.1ot.mobi",
            ],
            0,
        )

        self.assertEqual(
            initiated_targets,
            [
                "eim1.sm.1ot.com",
                "eim2.esim.tst.1ot.mobi",
            ],
        )

    def test_build_poll_threads_keeps_dns_bootstrap_variants_in_one_attempt(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        runtime = polling_plugin._RelayPollingRuntime(target)
        target.state.stk_network_history.extend(
            [
                "OPEN CHANNEL: udp, remote connection://8.8.8.8:53",
                "DNS: TX DNS Query: id=0x0001 qname=eim1.sm.1ot.com type=AAAA class=IN",
                "DNS: RX DNS Response: id=0x0001 qname=eim1.sm.1ot.com qd=1 an=0 ns=0 ar=0 rcode=0",
                "OPEN CHANNEL: udp, remote connection://8.8.8.8:53 dnsHint=eim1.sm.1ot.com",
                "DNS: TX DNS Query: id=0x0002 qname=eim1.sm.1ot.com type=A class=IN",
                "DNS: RX DNS Response: id=0x0002 qname=eim1.sm.1ot.com qd=1 an=1 ns=0 ar=0 rcode=0 answers=A:194.29.54.4",
                "OPEN CHANNEL: tcp, remote connection://194.29.54.4:443 dnsHint=eim1.sm.1ot.com",
                "TLS: TX TLS Record: Handshake",
            ]
        )

        threads = runtime._build_poll_threads()

        self.assertEqual(len(threads), 1)
        self.assertEqual(threads[0]["fqdn"], "eim1.sm.1ot.com")
        self.assertEqual(len(threads[0]["attempts"]), 1)
        self.assertEqual(
            sum(
                1
                for line in threads[0]["attempts"][0]["events"]
                if str(line).startswith("DNS: TX DNS Query:")
            ),
            2,
        )

    def test_timer_expiration_counter_is_logged_separately_from_timer_id(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target.state.stk_timers = {
            1: polling_plugin.StkTimerState(
                timer_id=1,
                active=True,
                expires_at_monotonic=1.0,
                last_identifier_tlv=b"\x24\x01\x01",
                last_value_tlv=b"\x25\x03\x21\x00\x00",
            ),
            2: polling_plugin.StkTimerState(
                timer_id=2,
                active=True,
                expires_at_monotonic=1.0,
                last_identifier_tlv=b"\x24\x01\x02",
                last_value_tlv=b"\x25\x03\x21\x00\x00",
            ),
        }
        runtime = polling_plugin._RelayPollingRuntime(target)
        rendered = io.StringIO()

        with (
            mock.patch.object(polling_plugin.time, "monotonic", side_effect=clock.monotonic),
            contextlib.redirect_stdout(rendered),
        ):
            polling_plugin._RelayPollingRuntime._emit_due_stk_timer_expirations(
                runtime,
                "EIM-POLL: TIMER EXPIRATION",
                force_all_active=True,
                stimulus_counts={"total": 0},
            )

        self.assertIn(
            "forcing TIMER EXPIRATION [1] for timer 1",
            rendered.getvalue(),
        )
        self.assertIn(
            "forcing TIMER EXPIRATION [2] for timer 2",
            rendered.getvalue(),
        )
        self.assertIn(
            "EIM-POLL: TIMER EXPIRATION [1] [timer 1]",
            target.exchange_log_names,
        )
        self.assertIn(
            "EIM-POLL: TIMER EXPIRATION [2] [timer 2]",
            target.exchange_log_names,
        )

    def test_data_available_log_name_is_normalized_without_recursive_growth(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target.state.stk_event_list = [0x09]
        target._queued_stk_pending_length = lambda: 127
        delattr(target, "_exchange_eim_poll_apdu")
        runtime = polling_plugin._RelayPollingRuntime(target)
        rendered = io.StringIO()

        with contextlib.redirect_stdout(rendered):
            sw1, sw2 = polling_plugin._RelayPollingRuntime._emit_stk_data_available_event(
                runtime,
                "EIM-POLL: TIMER EXPIRATION [2] [timer 1] "
                "[EVENT DOWNLOAD DATA AVAILABLE] [EVENT DOWNLOAD DATA AVAILABLE]",
                0x90,
                0x00,
            )

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(
            target.exchange_apdu_log_names,
            ["EIM-POLL: TIMER EXPIRATION [2] [timer 1] [DATA AVAILABLE]"],
        )
        self.assertIn(
            "sending EVENT DOWNLOAD DATA AVAILABLE (127 byte(s) buffered)",
            rendered.getvalue(),
        )
        self.assertNotIn(
            "[EVENT DOWNLOAD DATA AVAILABLE] [EVENT DOWNLOAD DATA AVAILABLE]",
            rendered.getvalue(),
        )

    def test_open_channel_logs_dns_hint_separately_from_endpoint(self) -> None:
        clock = _FakeClock()
        target = _DummyRelayTarget(clock)
        target.state.stk_dns_history.append(
            "TX DNS Query: id=0x0001 qname=eim2.esim.tst.1ot.mobi type=A class=IN"
        )
        target.state.stk_dns_history.append(
            "RX DNS Response: id=0x0001 qname=eim1.sm.1ot.com qd=1 an=1 ns=0 ar=0 rcode=0 answers=A:194.29.54.4"
        )
        target._close_stk_open_channel = lambda: None
        runtime = polling_plugin._RelayPollingRuntime(target)

        with mock.patch.object(
            polling_plugin.socket,
            "create_connection",
            return_value=SimpleNamespace(),
        ):
            runtime._open_stk_network_channel(
                {
                    "remote_address": "194.29.54.4",
                    "transport_port": 443,
                    "transport_protocol_type": 0x02,
                }
            )

        self.assertEqual(
            target.state.stk_open_channel_endpoint_history,
            ["tcp, remote connection://194.29.54.4:443"],
        )
        self.assertEqual(
            target.state.stk_open_channel_dns_hint_history,
            ["eim1.sm.1ot.com"],
        )
        self.assertIn(
            "dnsHint=eim1.sm.1ot.com",
            target.state.stk_open_channel_history[0],
        )
        self.assertNotIn(
            " fqdn=",
            target.state.stk_open_channel_history[0],
        )


if __name__ == "__main__":
    unittest.main()
