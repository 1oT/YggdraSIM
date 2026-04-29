"""Regression tests for STK polling configuration in ``isdr_config.json``.

These pin the contract that operators can flip the proactive bring-up
strategy used by ``ToolkitLogic._bootstrap_commands`` purely through
the persisted ISDR config payload, without code edits.

References:
* ETSI TS 102 223 §6.6.21 (TIMER MANAGEMENT)
* ETSI TS 102 223 §6.6.5  (POLL INTERVAL)
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from SIMCARD.etsi_fs import build_default_state
from SIMCARD.euicc_store import apply_euicc_state_payload
from SIMCARD.isdr_config import load_isdr_config_into_state


class IsdrConfigToolkitWiringTests(unittest.TestCase):
    """Validate that the ``toolkit`` payload section is honoured."""

    def setUp(self) -> None:
        self.state = build_default_state()

    def _write_payload(self, payload: dict) -> str:
        handle = tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".json",
            delete=False,
            encoding="utf-8",
        )
        json.dump(payload, handle)
        handle.flush()
        handle.close()
        self.addCleanup(self._safe_unlink, handle.name)
        return handle.name

    @staticmethod
    def _safe_unlink(path: str) -> None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass

    def test_default_state_uses_timer_strategy(self) -> None:
        # SimToolkitState defaults must match the documented runtime
        # default of timer-based STK bring-up so that the modem sees
        # TIMER MANAGEMENT START + TIMER EXPIRATION envelopes (not
        # POLL INTERVAL) without any operator intervention.
        self.assertEqual(self.state.toolkit.poll_strategy, "timer")
        self.assertEqual(self.state.toolkit.timer_management_seconds, 30)
        self.assertEqual(self.state.toolkit.timer_management_id, 1)
        self.assertTrue(self.state.toolkit.timer_management_auto_rearm)

    def test_apply_payload_with_poll_interval_strategy(self) -> None:
        payload = {
            "toolkit": {
                "poll_strategy": "poll_interval",
                "poll_interval_seconds": 17,
            }
        }
        apply_euicc_state_payload(self.state, payload)
        self.assertEqual(self.state.toolkit.poll_strategy, "poll_interval")
        self.assertEqual(self.state.toolkit.poll_interval_seconds, 17)

    def test_apply_payload_with_timer_strategy_overrides(self) -> None:
        payload = {
            "toolkit": {
                "poll_strategy": "timer",
                "timer_management_seconds": 90,
                "timer_management_id": 4,
                "timer_management_auto_rearm": False,
            }
        }
        apply_euicc_state_payload(self.state, payload)
        self.assertEqual(self.state.toolkit.poll_strategy, "timer")
        self.assertEqual(self.state.toolkit.timer_management_seconds, 90)
        self.assertEqual(self.state.toolkit.timer_management_id, 4)
        self.assertFalse(self.state.toolkit.timer_management_auto_rearm)

    def test_apply_payload_clamps_timer_id_to_etsi_range(self) -> None:
        # ETSI TS 102 223 §6.6.21: Timer Identifier must be 1..8.
        payload = {"toolkit": {"timer_management_id": 0}}
        apply_euicc_state_payload(self.state, payload)
        self.assertEqual(self.state.toolkit.timer_management_id, 1)

        payload = {"toolkit": {"timer_management_id": 99}}
        apply_euicc_state_payload(self.state, payload)
        self.assertEqual(self.state.toolkit.timer_management_id, 8)

    def test_apply_payload_rejects_unknown_strategy(self) -> None:
        payload = {"toolkit": {"poll_strategy": "carrier-pigeon"}}
        apply_euicc_state_payload(self.state, payload)
        # Unknown values must leave the prior strategy untouched
        # rather than corrupt the state machine.
        self.assertEqual(self.state.toolkit.poll_strategy, "timer")

    def test_load_isdr_config_file_applies_toolkit_section(self) -> None:
        payload = {
            "eid": "89044045930000000000001492294428",
            "toolkit": {
                "poll_strategy": "both",
                "timer_management_seconds": 45,
                "poll_interval_seconds": 60,
            },
        }
        path = self._write_payload(payload)
        applied = load_isdr_config_into_state(path, self.state)
        self.assertTrue(applied)
        self.assertEqual(self.state.toolkit.poll_strategy, "both")
        self.assertEqual(self.state.toolkit.timer_management_seconds, 45)
        self.assertEqual(self.state.toolkit.poll_interval_seconds, 60)

    def test_off_strategy_disables_proactive_polling(self) -> None:
        payload = {"toolkit": {"poll_strategy": "off"}}
        apply_euicc_state_payload(self.state, payload)
        self.assertEqual(self.state.toolkit.poll_strategy, "off")

    def test_default_state_enables_ipa_poll_with_safe_fallbacks(self) -> None:
        # The default state must arm the SGP.32 §3.5 IPA-poll
        # trigger so a fresh workspace boots straight into a
        # functional bearer cycle. The FQDN starts empty so the
        # ToolkitLogic falls back to the eIM identity registry.
        self.assertTrue(self.state.toolkit.ipa_poll_enabled)
        self.assertEqual(self.state.toolkit.ipa_poll_eim_fqdn, "")
        self.assertEqual(self.state.toolkit.ipa_poll_eim_port, 443)
        self.assertEqual(self.state.toolkit.ipa_poll_transport_type, 0x02)
        self.assertGreaterEqual(self.state.toolkit.ipa_poll_receive_size, 1)
        self.assertLessEqual(self.state.toolkit.ipa_poll_receive_size, 0xFF)

    def test_apply_payload_with_ipa_poll_overrides(self) -> None:
        payload = {
            "toolkit": {
                "ipa_poll": {
                    "enabled": False,
                    "eim_fqdn": "lpa.test.example",
                    "eim_port": 8443,
                    "transport_type": 6,
                    "buffer_size": 2048,
                    "receive_size": 200,
                    "alpha_id": "Custom Poll",
                    "request_payload_hex": "DEADBEEF",
                }
            }
        }
        apply_euicc_state_payload(self.state, payload)
        self.assertFalse(self.state.toolkit.ipa_poll_enabled)
        self.assertEqual(self.state.toolkit.ipa_poll_eim_fqdn, "lpa.test.example")
        self.assertEqual(self.state.toolkit.ipa_poll_eim_port, 8443)
        self.assertEqual(self.state.toolkit.ipa_poll_transport_type, 0x06)
        self.assertEqual(self.state.toolkit.ipa_poll_buffer_size, 2048)
        self.assertEqual(self.state.toolkit.ipa_poll_receive_size, 200)
        self.assertEqual(self.state.toolkit.ipa_poll_alpha_id, "Custom Poll")
        self.assertEqual(self.state.toolkit.ipa_poll_request_payload, b"\xDE\xAD\xBE\xEF")

    def test_apply_payload_clamps_ipa_poll_port_and_receive_size(self) -> None:
        payload = {
            "toolkit": {
                "ipa_poll": {
                    "eim_port": 999999,
                    "receive_size": 999,
                }
            }
        }
        apply_euicc_state_payload(self.state, payload)
        self.assertLessEqual(self.state.toolkit.ipa_poll_eim_port, 0xFFFF)
        self.assertLessEqual(self.state.toolkit.ipa_poll_receive_size, 0xFF)

    def test_template_json_carries_toolkit_defaults(self) -> None:
        # Lightweight check that the workspace template stays in sync
        # with the runtime defaults; if this drifts new installs would
        # silently fall back to whatever shipped years ago.
        template_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "SIMCARD",
            "isdr_config_template.json",
        )
        with open(template_path, "r", encoding="utf-8") as handle:
            template = json.load(handle)
        self.assertIn("toolkit", template)
        toolkit = template["toolkit"]
        self.assertEqual(toolkit.get("poll_strategy"), "timer")
        self.assertIn("timer_management_seconds", toolkit)
        self.assertIn("timer_management_id", toolkit)
        self.assertIn("timer_management_auto_rearm", toolkit)


if __name__ == "__main__":
    unittest.main()
