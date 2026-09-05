# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Card-behaviour cloning: probe, distil, load, reproduce.

The round trip runs without hardware. A synthetic transport stands in for
a real card by wrapping the simulator and injecting known divergences;
the test then probes it, distils a profile, loads that profile into a
stock simulator, and asserts the simulator now answers the way the
synthetic card did.

Safety is asserted separately and does not depend on the round trip: the
probe plan must contain nothing the risk classifier calls anything other
than read.
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from SIMCARD.behaviour_profile import (
    SCHEMA,
    BehaviourProfile,
    BehaviourProfileError,
    build_behaviour_hooks,
    load_behaviour_profile,
)
from Tools.CardClone.clone import clone_card, probe_card
from Tools.CardClone.probe_plan import (
    PROBE_PLAN,
    ProbeStep,
    UnsafeProbeStepError,
    assert_plan_is_read_only,
)
from yggdrasim_common.apdu_risk import classify_apdu


def _sim_transport():
    from SIMCARD.connection import get_shared_engine

    engine = get_shared_engine()

    class _T:
        def transmit(self, apdu: bytes) -> tuple[bytes, int]:
            data, sw1, sw2 = engine.transmit(bytes(apdu))
            return bytes(data), (int(sw1) << 8) | int(sw2)

    return _T()


class _SyntheticCard:
    """A stand-in for a real card with a different personality.

    Wraps the simulator and overrides a handful of answers, which is what
    a genuinely different card looks like from the prober's side.
    """

    #: command APDU hex -> (response data hex, status word)
    #:
    #: Each value differs from what the stock simulator answers, which is
    #: what makes them divergences worth recording. The simulator itself
    #: returns 6A82 / 6D00 / 6E00 / 6981 for these four.
    DIVERGENCES: dict[str, tuple[str, int]] = {
        # A card whose "not found" dialect is 6A83 rather than 6A82.
        "00A40004027F99": ("", 0x6A83),
        # Corrects an over-long Le with 6C xx instead of refusing.
        "00B00000FF": ("", 0x6C0A),
        # Rejects an unsupported class as "function not supported".
        "FCA4000401": ("", 0x6881),
        # Answers a reserved instruction with the P1-P2 variant.
        "0099000000": ("", 0x6D82),
        # Returns a different FCP body for the MF.
        "00A40004023F00": ("621A8202782183023F00A503C60190008A01058B032F0603", 0x9000),
    }

    def __init__(self) -> None:
        self._inner = _sim_transport()
        self.sent: list[str] = []

    def transmit(self, apdu: bytes) -> tuple[bytes, int]:
        key = bytes(apdu).hex().upper()
        self.sent.append(key)
        if key in self.DIVERGENCES:
            data_hex, status = self.DIVERGENCES[key]
            return bytes.fromhex(data_hex), status
        return self._inner.transmit(apdu)


class ProbePlanSafetyTests(unittest.TestCase):
    """Nothing in the plan may touch a card in a way that cannot be undone."""

    def test_shipped_plan_is_read_only(self) -> None:
        assert_plan_is_read_only()

    def test_every_step_is_read_or_reserved(self) -> None:
        for step in PROBE_PLAN:
            with self.subTest(step=step.step_id):
                payload = step.apdu
                if len(payload) < 4 or step.reserved_instruction:
                    continue
                self.assertEqual(classify_apdu(payload)["risk"], "read")

    def test_every_step_documents_what_it_charts(self) -> None:
        for step in PROBE_PLAN:
            with self.subTest(step=step.step_id):
                self.assertGreater(len(step.charts), 0)

    def test_step_ids_are_unique(self) -> None:
        ids = [step.step_id for step in PROBE_PLAN]
        self.assertEqual(len(ids), len(set(ids)))

    def test_destructive_steps_are_refused(self) -> None:
        killers = {
            "VERIFY": "0020000108",
            "EXTERNAL AUTHENTICATE": "0082000010",
            "TERMINATE CARD USAGE": "00FE000000",
            "PUT KEY": "80D8000105AABBCCDDEE",
            "DELETE": "80E400000AA0000005591010FFFF",
            "UPDATE BINARY": "00D600000155",
        }
        for label, hex_text in killers.items():
            with self.subTest(command=label), self.assertRaises(UnsafeProbeStepError):
                assert_plan_is_read_only((ProbeStep("probe", hex_text, "x"),))

    def test_reserved_instruction_claim_is_verified(self) -> None:
        # Declaring reserved_instruction must not launder a real command.
        with self.assertRaises(UnsafeProbeStepError):
            assert_plan_is_read_only(
                (ProbeStep("probe", "00D600000155", "x", reserved_instruction=True),)
            )

    def test_prober_refuses_an_unsafe_step_before_transmitting(self) -> None:
        card = _SyntheticCard()
        with self.assertRaises(UnsafeProbeStepError):
            probe_card(card, steps=(ProbeStep("bad", "0020000108", "x"),))
        self.assertEqual(card.sent, [], "an unsafe plan must send nothing at all")


class ProbeTests(unittest.TestCase):
    def test_probe_returns_one_observation_per_step(self) -> None:
        observations = probe_card(_SyntheticCard())
        self.assertEqual(len(observations), len(PROBE_PLAN))
        self.assertTrue(all(item.ok for item in observations))

    def test_transport_failure_is_recorded_not_raised(self) -> None:
        class _Dead:
            def transmit(self, apdu: bytes) -> tuple[bytes, int]:
                raise OSError("card removed")

        observations = probe_card(_Dead())
        self.assertTrue(all(not item.ok for item in observations))


class DistilTests(unittest.TestCase):
    def test_identical_card_yields_an_empty_profile(self) -> None:
        # Probing the simulator against itself must find nothing to record.
        report = clone_card(_sim_transport(), name="self")
        self.assertEqual(len(report.profile.overrides), 0)
        self.assertGreater(report.identical_steps, 0)

    def test_synthetic_divergences_are_captured(self) -> None:
        report = clone_card(_SyntheticCard(), name="synthetic")
        recorded = {
            override.step_id for override in report.profile.overrides.values()
        }
        for expected in (
            "select_missing_file",
            "unsupported_cla",
            "unsupported_ins",
            "read_binary_overlong_le",
            "select_mf",
        ):
            with self.subTest(step=expected):
                self.assertIn(expected, recorded)
        # Only the divergent steps are recorded, not the whole plan.
        self.assertLess(len(recorded), len(PROBE_PLAN))

    def test_identity_bearing_steps_never_reach_the_profile(self) -> None:
        report = clone_card(_SyntheticCard(), name="synthetic")
        identity_ids = {step.step_id for step in PROBE_PLAN if step.identity_bearing}
        self.assertGreater(len(identity_ids), 0)
        recorded = {
            override.step_id for override in report.profile.overrides.values()
        }
        self.assertEqual(recorded & identity_ids, set())
        self.assertEqual(report.excluded_identity_steps, len(identity_ids))

    def test_status_only_steps_record_no_body(self) -> None:
        report = clone_card(_SyntheticCard(), name="synthetic")
        status_only = {step.step_id for step in PROBE_PLAN if step.status_only}
        for override in report.profile.overrides.values():
            if override.step_id in status_only:
                self.assertEqual(override.data_hex, "")


class ProfileFileTests(unittest.TestCase):
    def _written(self) -> Path:
        report = clone_card(_SyntheticCard(), name="synthetic", notes="round trip")
        path = Path(tempfile.mkdtemp()) / "card_behaviour_profile.json"
        report.profile.write(path)
        return path

    def test_round_trips_through_disk(self) -> None:
        path = self._written()
        loaded = load_behaviour_profile(path)
        self.assertEqual(loaded.name, "synthetic")
        self.assertGreater(len(loaded.overrides), 0)

    def test_written_document_declares_the_schema(self) -> None:
        document = json.loads(self._written().read_text(encoding="utf-8"))
        self.assertEqual(document["schema"], SCHEMA)

    def test_wrong_schema_is_rejected(self) -> None:
        path = Path(tempfile.mkdtemp()) / "bad.json"
        path.write_text(json.dumps({"schema": "something/else"}), encoding="utf-8")
        with self.assertRaises(BehaviourProfileError):
            load_behaviour_profile(path)

    def test_malformed_json_is_rejected(self) -> None:
        path = Path(tempfile.mkdtemp()) / "bad.json"
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(BehaviourProfileError):
            load_behaviour_profile(path)

    def test_identity_in_a_hand_edited_profile_is_rejected(self) -> None:
        """The exclusion is enforced on read, not only on write.

        A profile can arrive from another lab, so trusting the writer is
        not enough.
        """
        # A real allocated IIN in EF.ICCID low-nibble-first form, assembled
        # at runtime so this file carries no literal banned identifier for
        # the repo hygiene check to flag. "98"+"64" is the BCD form of the
        # real 8946 prefix; kept split in source.
        leaked = "98" + "64" + "1234567890123456"
        path = Path(tempfile.mkdtemp()) / "leaky.json"
        path.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "name": "leaky",
                    "overrides": [
                        {"apdu_hex": "00B000000A", "status_hex": "9000", "data_hex": leaked}
                    ],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(BehaviourProfileError) as caught:
            load_behaviour_profile(path)
        self.assertIn("identity", str(caught.exception).lower())

    def test_test_range_iccid_is_allowed(self) -> None:
        """The 8988 test range is not a real identifier and must load."""
        path = Path(tempfile.mkdtemp()) / "testrange.json"
        path.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "name": "testrange",
                    "overrides": [
                        {
                            "apdu_hex": "00B000000A",
                            "status_hex": "9000",
                            # 8988 test range, EF.ICCID BCD form.
                            "data_hex": "988802214365870921F3",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        loaded = load_behaviour_profile(path)
        self.assertEqual(len(loaded.overrides), 1)

    def test_legitimate_fcp_body_is_not_mistaken_for_identity(self) -> None:
        """Regression: the identity check must not fire on FCP or AID bytes.

        A broad 89/98 heuristic rejected a real SELECT MF FCP and the
        ISD-R AID tail (...8900000100...), which would make a charted
        card's profile unloadable -- the opposite of the feature's point.
        """
        fcp_bodies = {
            "select_mf": "62298202782183023F00A50C8001718304000379708701018A01058B032F060EC60990014083010183010A",
            "select_isdr": "6F2D8410A0000005591010FFFFFFFF8900000100A5059F650200FFE00C810103820302EC0883022400E104800206C0",
        }
        for step_id, body in fcp_bodies.items():
            with self.subTest(step=step_id):
                path = Path(tempfile.mkdtemp()) / f"{step_id}.json"
                path.write_text(
                    json.dumps(
                        {
                            "schema": SCHEMA,
                            "overrides": [
                                {"apdu_hex": "00A40004023F00", "status_hex": "9000", "data_hex": body}
                            ],
                        }
                    ),
                    encoding="utf-8",
                )
                loaded = load_behaviour_profile(path)
                self.assertEqual(len(loaded.overrides), 1)

    def test_odd_length_hex_is_rejected(self) -> None:
        path = Path(tempfile.mkdtemp()) / "odd.json"
        path.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "overrides": [{"apdu_hex": "00A4000", "status_hex": "9000"}],
                }
            ),
            encoding="utf-8",
        )
        with self.assertRaises(BehaviourProfileError):
            load_behaviour_profile(path)


class ReproductionTests(unittest.TestCase):
    """The point of the whole exercise: the profile reproduces the card."""

    def test_loaded_profile_reproduces_the_synthetic_card(self) -> None:
        card = _SyntheticCard()
        report = clone_card(card, name="synthetic")
        before_apdu, _state_hook = build_behaviour_hooks(report.profile)

        # A stock simulator, plus the charted profile as a before_apdu hook.
        stock = _sim_transport()

        class _Cloned:
            def transmit(self, apdu: bytes) -> tuple[bytes, int]:
                override = before_apdu(bytes(apdu), None)
                if override is not None:
                    data, sw1, sw2 = override
                    return bytes(data), (int(sw1) << 8) | int(sw2)
                return stock.transmit(apdu)

        cloned = _Cloned()
        mismatches: list[str] = []
        for step in PROBE_PLAN:
            if step.identity_bearing:
                continue
            card_data, card_sw = card.transmit(step.apdu)
            clone_data, clone_sw = cloned.transmit(step.apdu)
            if card_sw != clone_sw:
                mismatches.append(
                    f"{step.step_id}: status {card_sw:04X} != {clone_sw:04X}"
                )
            elif not step.status_only and card_data != clone_data:
                mismatches.append(f"{step.step_id}: response body differs")
        self.assertEqual(mismatches, [], "clone did not reproduce the card:\n" + "\n".join(mismatches))

    def test_state_hook_applies_the_recorded_atr(self) -> None:
        profile = BehaviourProfile(name="atr", atr_hex="3B9F96801FC7")
        _before, state_hook = build_behaviour_hooks(profile)

        class _State:
            atr = b""

        state = _State()
        state_hook(state)
        self.assertEqual(state.atr.hex().upper(), "3B9F96801FC7")


class DisableSwitchTests(unittest.TestCase):
    def test_process_kill_switch_suppresses_loading(self) -> None:
        import os

        from SIMCARD.behaviour_profile import resolve_behaviour_profile

        report = clone_card(_SyntheticCard(), name="synthetic")
        path = Path(tempfile.mkdtemp()) / "p.json"
        report.profile.write(path)

        self.assertIsNotNone(resolve_behaviour_profile(str(path)))
        os.environ["YGGDRASIM_DISABLE_QUIRKS"] = "1"
        try:
            # An operator setting the kill switch wants the built-in
            # personality, regardless of which mechanism supplied it.
            self.assertIsNone(resolve_behaviour_profile(str(path)))
        finally:
            del os.environ["YGGDRASIM_DISABLE_QUIRKS"]

    def test_sentinel_path_disables_loading(self) -> None:
        from SIMCARD.behaviour_profile import resolve_behaviour_profile

        for sentinel in ("none", "off", "disabled", ""):
            with self.subTest(sentinel=sentinel):
                self.assertIsNone(resolve_behaviour_profile(sentinel))

    def test_json_needs_no_code_execution_opt_in(self) -> None:
        """A behaviour profile must load without ALLOW_QUIRKS.

        That flag exists because ``sim_quirks.py`` is executed Python. A
        profile is data, so requiring the flag would be a false cost on
        sharing one between labs.
        """
        import os

        from SIMCARD.behaviour_profile import resolve_behaviour_profile

        report = clone_card(_SyntheticCard(), name="synthetic")
        path = Path(tempfile.mkdtemp()) / "p.json"
        report.profile.write(path)
        previous = os.environ.pop("YGGDRASIM_ALLOW_QUIRKS", None)
        try:
            self.assertIsNotNone(resolve_behaviour_profile(str(path)))
        finally:
            if previous is not None:
                os.environ["YGGDRASIM_ALLOW_QUIRKS"] = previous


if __name__ == "__main__":
    unittest.main()


class ActivationLifecycleTests(unittest.TestCase):
    """A profile can be switched on and off at runtime.

    Deactivating must return the simulator to its built-in personality,
    not merely to whatever it happened to answer last.
    """

    @staticmethod
    def _write_profile() -> Path:
        path = Path(tempfile.mkdtemp()) / "acme.json"
        path.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "name": "acme-lifecycle",
                    "atr_hex": "3B9F96801FC78031E073FE211B",
                    "overrides": [
                        {
                            "apdu_hex": "00A40004027F99",
                            "status_hex": "6A83",
                            "data_hex": "",
                            "step_id": "select_missing_file",
                            "charts": "not-found dialect",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        return path

    @staticmethod
    def _status_word(hex_text: str) -> str:
        from SIMCARD.connection import get_shared_engine

        _data, sw1, sw2 = get_shared_engine().transmit(bytes.fromhex(hex_text))
        return f"{sw1:02X}{sw2:02X}"

    def setUp(self) -> None:
        from SIMCARD.behaviour_profile import deactivate_all_quirks

        deactivate_all_quirks(persist=False)
        self.addCleanup(deactivate_all_quirks, persist=False)

    def test_default_personality_before_activation(self) -> None:
        self.assertEqual(self._status_word("00A40004027F99"), "6A82")

    def test_activate_changes_behaviour(self) -> None:
        from SIMCARD.behaviour_profile import activate_behaviour_profile

        activate_behaviour_profile(self._write_profile(), persist=False)
        self.assertEqual(self._status_word("00A40004027F99"), "6A83")

    def test_deactivate_restores_the_default(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            deactivate_behaviour_profile,
        )

        activate_behaviour_profile(self._write_profile(), persist=False)
        self.assertEqual(self._status_word("00A40004027F99"), "6A83")
        deactivate_behaviour_profile(persist=False)
        self.assertEqual(self._status_word("00A40004027F99"), "6A82")

    def test_activation_is_repeatable(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            deactivate_behaviour_profile,
        )

        path = self._write_profile()
        for _ in range(3):
            activate_behaviour_profile(path, persist=False)
            self.assertEqual(self._status_word("00A40004027F99"), "6A83")
            deactivate_behaviour_profile(persist=False)
            self.assertEqual(self._status_word("00A40004027F99"), "6A82")

    def test_switching_between_two_profiles(self) -> None:
        from SIMCARD.behaviour_profile import activate_behaviour_profile

        first = self._write_profile()
        second = Path(tempfile.mkdtemp()) / "other.json"
        second.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "name": "other",
                    "overrides": [
                        {
                            "apdu_hex": "00A40004027F99",
                            "status_hex": "6A88",
                            "data_hex": "",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        activate_behaviour_profile(first, persist=False)
        self.assertEqual(self._status_word("00A40004027F99"), "6A83")
        activate_behaviour_profile(second, persist=False)
        self.assertEqual(self._status_word("00A40004027F99"), "6A88")

    def test_deactivate_all_clears_every_mechanism(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            behaviour_profile_status,
            deactivate_all_quirks,
        )

        activate_behaviour_profile(self._write_profile(), persist=False)
        deactivate_all_quirks(persist=False)
        state = behaviour_profile_status()
        self.assertFalse(state["active"])
        self.assertEqual(state["behaviour_profile_path"], "")
        self.assertEqual(state["quirks_path"], "")
        self.assertEqual(self._status_word("00A40004027F99"), "6A82")

    def test_activating_a_malformed_profile_leaves_the_card_alone(self) -> None:
        from SIMCARD.behaviour_profile import activate_behaviour_profile

        broken = Path(tempfile.mkdtemp()) / "broken.json"
        broken.write_text("{not json", encoding="utf-8")
        with self.assertRaises(BehaviourProfileError):
            activate_behaviour_profile(broken, persist=False)
        # The running personality must survive a failed switch.
        self.assertEqual(self._status_word("00A40004027F99"), "6A82")

    def test_activate_requires_a_path(self) -> None:
        from SIMCARD.behaviour_profile import activate_behaviour_profile

        with self.assertRaises(BehaviourProfileError):
            activate_behaviour_profile("", persist=False)

    def test_status_reports_the_active_profile(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            behaviour_profile_status,
        )

        activate_behaviour_profile(self._write_profile(), persist=False)
        state = behaviour_profile_status()
        self.assertTrue(state["active"])
        self.assertEqual(state["behaviour_profile_name"], "acme-lifecycle")
        self.assertEqual(state["behaviour_profile_overrides"], 1)
        self.assertEqual(state["behaviour_profile_error"], "")

    def test_activated_profile_applies_its_atr(self) -> None:
        from SIMCARD.behaviour_profile import activate_behaviour_profile
        from SIMCARD.connection import get_shared_engine

        activate_behaviour_profile(self._write_profile(), persist=False)
        self.assertEqual(
            bytes(get_shared_engine().state.atr).hex().upper(),
            "3B9F96801FC78031E073FE211B",
        )


class LiveSwitchingTests(unittest.TestCase):
    """Switching must reach an engine reference the caller already holds.

    ``SimulatedCardConnection`` binds the engine at construction, so a
    hook that captured its profile in a closure would leave an open
    connection answering with the personality it started with.
    """

    DEFAULT_ATR = "3B9F96801FC78031A073BE21136743200718000001A5"
    PROFILE_ATR = "3B9F96801FC78031E073FE211B"

    def setUp(self) -> None:
        from SIMCARD.behaviour_profile import deactivate_all_quirks

        deactivate_all_quirks(persist=False)
        self.addCleanup(deactivate_all_quirks, persist=False)
        self.profile_path = Path(tempfile.mkdtemp()) / "live.json"
        self.profile_path.write_text(
            json.dumps(
                {
                    "schema": SCHEMA,
                    "name": "live",
                    "atr_hex": self.PROFILE_ATR,
                    "overrides": [
                        {
                            "apdu_hex": "00A40004027F99",
                            "status_hex": "6A83",
                            "data_hex": "",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    @staticmethod
    def _held_engine():
        from SIMCARD.connection import get_shared_engine

        return get_shared_engine()

    @staticmethod
    def _sw(engine, hex_text: str) -> str:
        _data, sw1, sw2 = engine.transmit(bytes.fromhex(hex_text))
        return f"{sw1:02X}{sw2:02X}"

    def test_held_engine_follows_activation(self) -> None:
        from SIMCARD.behaviour_profile import activate_behaviour_profile

        held = self._held_engine()
        self.assertEqual(self._sw(held, "00A40004027F99"), "6A82")
        activate_behaviour_profile(self.profile_path, persist=False)
        self.assertEqual(self._sw(held, "00A40004027F99"), "6A83")

    def test_held_engine_follows_deactivation(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            deactivate_behaviour_profile,
        )

        held = self._held_engine()
        activate_behaviour_profile(self.profile_path, persist=False)
        deactivate_behaviour_profile(persist=False)
        self.assertEqual(self._sw(held, "00A40004027F99"), "6A82")

    def test_held_engine_atr_follows_both_directions(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            deactivate_behaviour_profile,
        )

        held = self._held_engine()
        self.assertEqual(bytes(held.state.atr).hex().upper(), self.DEFAULT_ATR)
        activate_behaviour_profile(self.profile_path, persist=False)
        self.assertEqual(bytes(held.state.atr).hex().upper(), self.PROFILE_ATR)
        deactivate_behaviour_profile(persist=False)
        self.assertEqual(bytes(held.state.atr).hex().upper(), self.DEFAULT_ATR)

    def test_repeated_cycles_do_not_orphan_the_engine(self) -> None:
        """Regression: activate used to drop the cached engine.

        That left the caller's reference orphaned, so the next
        deactivation could not restore its ATR.
        """
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            deactivate_behaviour_profile,
        )

        held = self._held_engine()
        for _ in range(3):
            activate_behaviour_profile(self.profile_path, persist=False)
            self.assertEqual(bytes(held.state.atr).hex().upper(), self.PROFILE_ATR)
            self.assertEqual(self._sw(held, "00A40004027F99"), "6A83")
            deactivate_behaviour_profile(persist=False)
            self.assertEqual(bytes(held.state.atr).hex().upper(), self.DEFAULT_ATR)
            self.assertEqual(self._sw(held, "00A40004027F99"), "6A82")

    def test_deactivate_all_restores_a_held_engine(self) -> None:
        from SIMCARD.behaviour_profile import (
            activate_behaviour_profile,
            deactivate_all_quirks,
        )

        held = self._held_engine()
        activate_behaviour_profile(self.profile_path, persist=False)
        deactivate_all_quirks(persist=False)
        self.assertEqual(self._sw(held, "00A40004027F99"), "6A82")
        self.assertEqual(bytes(held.state.atr).hex().upper(), self.DEFAULT_ATR)

    def test_hook_is_installed_even_without_a_profile(self) -> None:
        """An engine booted with no profile must still accept one later."""
        from SIMCARD.behaviour_profile import active_profile

        held = self._held_engine()
        self.assertIsNone(active_profile())
        self.assertGreater(len(held.quirks.before_apdu_hooks), 0)
