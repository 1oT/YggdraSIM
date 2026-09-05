# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Replaying a recorded APDU stream and diffing the responses.

The interesting behaviour is the variance policy: a response that is
card-generated differs on every run, so the replay must separate
"expected to move" from "regression".
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from yggdrasim_common.session_diff import Exchange
from yggdrasim_common.session_replay import (
    DEFAULT_VARIANCE_POLICY,
    STATUS_ONLY_POLICY,
    VariancePolicy,
    format_report,
    replay_exchanges,
    replay_recording,
)


class _ScriptedTransport:
    """Returns a queued (data, sw) per transmit call."""

    def __init__(self, responses: list[tuple[bytes, int]]) -> None:
        self._responses = list(responses)
        self.sent: list[bytes] = []

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        self.sent.append(bytes(apdu))
        if len(self._responses) == 0:
            return b"", 0x9000
        return self._responses.pop(0)


class _DeadTransport:
    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        raise OSError("card removed")


def _exchange(index: int, apdu: str, data: str, status: str) -> Exchange:
    return Exchange(
        index=index,
        apdu_hex=apdu,
        data_hex=data,
        status_hex=status,
        ok=status in ("9000", "9100"),
    )


class ReplayMatchingTests(unittest.TestCase):
    def test_identical_responses_produce_no_divergence(self) -> None:
        recorded = [_exchange(0, "00A40004023F00", "6229", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("6229"), 0x9000)])
        report = replay_exchanges(recorded, transport)
        self.assertTrue(report.matched)
        self.assertEqual(report.replayed_count, 1)
        self.assertEqual(transport.sent, [bytes.fromhex("00A40004023F00")])

    def test_changed_response_is_reported(self) -> None:
        recorded = [_exchange(0, "00A40004023F00", "6229", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("DEAD"), 0x9000)])
        report = replay_exchanges(recorded, transport)
        self.assertFalse(report.matched)
        self.assertEqual(len(report.divergences), 1)
        self.assertEqual(report.divergences[0].field, "response")

    def test_changed_status_is_reported(self) -> None:
        recorded = [_exchange(0, "00A40004023F00", "", "9000")]
        transport = _ScriptedTransport([(b"", 0x6A82)])
        report = replay_exchanges(recorded, transport)
        self.assertEqual([d.field for d in report.divergences], ["status"])
        self.assertEqual(report.divergences[0].replayed, "6A82")


class VariancePolicyTests(unittest.TestCase):
    def test_get_challenge_response_is_tolerated_by_default(self) -> None:
        # GET CHALLENGE returns fresh randomness every call.
        recorded = [_exchange(0, "0084000008", "0011223344556677", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("8899AABBCCDDEEFF"), 0x9000)])
        report = replay_exchanges(recorded, transport)
        self.assertTrue(report.matched)
        self.assertEqual(len(report.tolerated), 1)
        self.assertEqual(report.tolerated[0].field, "response")

    def test_status_change_is_still_a_regression_for_a_variable_command(self) -> None:
        recorded = [_exchange(0, "0084000008", "0011223344556677", "9000")]
        transport = _ScriptedTransport([(b"", 0x6F00)])
        report = replay_exchanges(recorded, transport)
        # The body may move; the status word may not.
        self.assertFalse(report.matched)
        self.assertEqual([d.field for d in report.divergences], ["status"])

    def test_status_only_policy_ignores_every_body(self) -> None:
        recorded = [_exchange(0, "00A40004023F00", "6229", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("FFFF"), 0x9000)])
        report = replay_exchanges(recorded, transport, policy=STATUS_ONLY_POLICY)
        self.assertTrue(report.matched)

    def test_masked_tlv_tag_hides_a_session_scoped_value(self) -> None:
        # Tag 80 carries a transaction id that changes per session; the
        # sibling tag 81 must still be compared.
        recorded = [_exchange(0, "80CA004000", "80020102" + "81020A0B", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("8002FFFF" + "81020A0B"), 0x9000)])
        policy = VariancePolicy(masked_tlv_tags=("80",))
        self.assertTrue(replay_exchanges(recorded, transport, policy=policy).matched)

    def test_masking_one_tag_does_not_hide_a_sibling_change(self) -> None:
        recorded = [_exchange(0, "80CA004000", "80020102" + "81020A0B", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("8002FFFF" + "8102DEAD"), 0x9000)])
        policy = VariancePolicy(masked_tlv_tags=("80",))
        report = replay_exchanges(recorded, transport, policy=policy)
        self.assertFalse(report.matched)

    def test_custom_matcher_can_accept_an_exchange_outright(self) -> None:
        recorded = [_exchange(0, "00A40004023F00", "6229", "9000")]
        transport = _ScriptedTransport([(bytes.fromhex("DEAD"), 0x6A82)])
        policy = VariancePolicy(custom_matcher=lambda left, right: True)
        self.assertTrue(replay_exchanges(recorded, transport, policy=policy).matched)


class ReplayRobustnessTests(unittest.TestCase):
    def test_transport_failure_is_counted_not_raised(self) -> None:
        recorded = [_exchange(0, "00A40004023F00", "6229", "9000")]
        report = replay_exchanges(recorded, _DeadTransport())
        self.assertEqual(report.transmit_errors, 1)
        self.assertFalse(report.matched)

    def test_malformed_recorded_apdu_is_skipped(self) -> None:
        recorded = [
            _exchange(0, "", "", "9000"),
            _exchange(1, "ODD", "", "9000"),
            _exchange(2, "00A40004023F00", "6229", "9000"),
        ]
        transport = _ScriptedTransport([(bytes.fromhex("6229"), 0x9000)])
        report = replay_exchanges(recorded, transport)
        self.assertEqual(report.replayed_count, 1)
        self.assertTrue(report.matched)

    def test_stop_on_divergence_halts_the_run(self) -> None:
        recorded = [
            _exchange(0, "00A40004023F00", "6229", "9000"),
            _exchange(1, "00A40004022FE2", "AA", "9000"),
        ]
        transport = _ScriptedTransport([(b"", 0x6A82), (bytes.fromhex("AA"), 0x9000)])
        report = replay_exchanges(recorded, transport, stop_on_divergence=True)
        self.assertEqual(report.replayed_count, 1)

    def test_masking_tolerates_malformed_tlv_bodies(self) -> None:
        from yggdrasim_common.session_replay import _mask_tlv_values

        for payload in ("", "80", "8020AA", "ZZ", "BF", "3080"):
            with self.subTest(payload=payload):
                self.assertIsInstance(_mask_tlv_values(payload, ("80",)), str)


class ReplayRecordingFileTests(unittest.TestCase):
    def _write_recording(self, exchanges: list[dict]) -> Path:
        path = Path(tempfile.mkdtemp()) / "session-example.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "yggdrasim_session_recording/1",
                    "apdu_trace": exchanges,
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_replays_a_recording_from_disk(self) -> None:
        path = self._write_recording(
            [
                {
                    "index": 0,
                    "apdu_hex": "00A40004023F00",
                    "response_data_hex": "6229",
                    "status_hex": "9000",
                }
            ]
        )
        transport = _ScriptedTransport([(bytes.fromhex("6229"), 0x9000)])
        report = replay_recording(path, transport)
        self.assertTrue(report.matched)
        self.assertEqual(report.source, str(path))
        self.assertIn("no divergences", format_report(report))

    def test_report_formatting_lists_divergences(self) -> None:
        path = self._write_recording(
            [
                {
                    "index": 0,
                    "apdu_hex": "00A40004023F00",
                    "response_data_hex": "6229",
                    "status_hex": "9000",
                }
            ]
        )
        transport = _ScriptedTransport([(bytes.fromhex("DEAD"), 0x9000)])
        text = format_report(replay_recording(path, transport))
        self.assertIn("divergences: 1", text)
        self.assertIn("recorded:", text)


class SimulatorReplayTests(unittest.TestCase):
    """A recording captured from the simulator replays against it cleanly."""

    def test_capture_then_replay_matches(self) -> None:
        from SIMCARD.connection import get_shared_engine

        engine = get_shared_engine()

        class _SimTransport:
            def transmit(self, apdu: bytes) -> tuple[bytes, int]:
                data, sw1, sw2 = engine.transmit(bytes(apdu))
                return bytes(data), (int(sw1) << 8) | int(sw2)

        transport = _SimTransport()
        commands = ["00A40004023F00", "00A40004022FE2", "00B0000000"]
        recorded: list[Exchange] = []
        for position, command in enumerate(commands):
            data, status = transport.transmit(bytes.fromhex(command))
            recorded.append(
                _exchange(position, command, data.hex().upper(), f"{status:04X}")
            )

        report = replay_exchanges(recorded, transport, policy=DEFAULT_VARIANCE_POLICY)
        self.assertTrue(
            report.matched,
            f"deterministic simulator replay diverged: {format_report(report)}",
        )


if __name__ == "__main__":
    unittest.main()
