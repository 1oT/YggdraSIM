# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Persona cards and the private-engine seam of the simulated eUICC.

Pins the baked snapshot (a reset restores the card byte for byte), the isolation of a private
engine from the environment, the persisted settings, the process-wide behaviour profile and
the plugins, the APDU observers and the STORE DATA extensions, all without any plugin present.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SIMCARD import behaviour_profile
from SIMCARD.behaviour_profile import BehaviourProfile
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.euicc_store import sync_euicc_store
from SIMCARD.persona import (
    EUICC_STORE_DIRNAME,
    ISDR_CONFIG_FILENAME,
    PersonaCard,
    PersonaError,
    build_persona_engine,
    card_fingerprint,
)
from SIMCARD.profile_store import sync_profiles_to_store
from SIMCARD.utils import tlv
from yggdrasim_common.card_backend import (
    SIM_BEHAVIOUR_PROFILE_ENV,
    SIM_EIM_IDENTITY_ENV,
    SIM_EUICC_STORE_ENV,
    SIM_ISDR_CONFIG_ENV,
    SIM_PROFILE_STORE_ENV,
    SIM_QUIRKS_ENV,
)

# SGP.22 test EID bodies (89049032...), one for the persona and one for the decoy settings.
PERSONA_EID = "89049032123451234512345678901235"
DECOY_EID = "89049032123451234512345678909999"
ISDR_SELECT = bytes.fromhex("00A4040010A0000005591010FFFFFFFF8900000100")


def _store_data(payload: bytes) -> bytes:
    return bytes([0x80, 0xE2, 0x91, 0x00, len(payload)]) + payload


def _write_persona(directory: Path, **extra: object) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / ISDR_CONFIG_FILENAME).write_text(
        json.dumps({"eid": PERSONA_EID, **extra}),
        encoding="utf-8",
    )
    return directory


def _tree(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


class PersonaCardTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = _write_persona(self.root / "persona")
        self.work = self.root / "work"

    def test_reset_restores_the_baked_card_byte_for_byte(self) -> None:
        card = PersonaCard(self.source, self.work)
        baked = card.fingerprint
        euicc_certificate = card.engine.sgp._current_euicc_certificate_der()
        card.engine.state.euicc_info.svn = bytes.fromhex("030100")
        sync_euicc_store(card.engine.state)
        self.assertNotEqual(card_fingerprint(card.engine), baked)

        card.reset()

        self.assertEqual(card_fingerprint(card.engine), baked)
        self.assertEqual(card.engine.sgp._current_euicc_certificate_der(), euicc_certificate)
        self.assertEqual(card.engine.state.eid, PERSONA_EID)
        self.assertEqual(card.generation, 1)

    def test_the_persona_directory_is_never_written(self) -> None:
        before = _tree(self.source)

        card = PersonaCard(self.source, self.work)
        card.engine.state.euicc_info.svn = bytes.fromhex("030100")
        sync_euicc_store(card.engine.state)
        card.reset()

        self.assertEqual(_tree(self.source), before)

    def test_strict_mode_and_held_ci_certificates_survive_a_reset(self) -> None:
        source = _write_persona(
            self.root / "strict",
            conformance_strict=True,
            ci_certificates_der_hex=["3003020100"],
        )
        card = PersonaCard(source, self.root / "strict-work")

        card.reset()

        self.assertIs(card.engine.state.conformance_strict, True)
        self.assertEqual(card.engine.state.ci_certificates, [bytes.fromhex("3003020100")])

    def test_settings_outside_the_persona_are_neither_read_nor_written(self) -> None:
        decoy = self.root / "decoy"
        decoy.mkdir()
        (decoy / "isdr_config.json").write_text(json.dumps({"eid": DECOY_EID}), encoding="utf-8")
        before = _tree(decoy)
        decoy_settings = {
            SIM_ISDR_CONFIG_ENV: str(decoy / "isdr_config.json"),
            SIM_EIM_IDENTITY_ENV: str(decoy / "eim_identity.json"),
            SIM_EUICC_STORE_ENV: str(decoy / "euicc_store"),
            SIM_PROFILE_STORE_ENV: str(decoy / "profiles"),
            SIM_QUIRKS_ENV: str(decoy / "sim_quirks.py"),
            SIM_BEHAVIOUR_PROFILE_ENV: str(decoy / "behaviour.json"),
        }
        with mock.patch.dict(os.environ, decoy_settings, clear=False):
            card = PersonaCard(self.source, self.work)
            card.reset()

        self.assertEqual(card.engine.state.eid, PERSONA_EID)
        self.assertEqual(_tree(decoy), before)
        self.assertTrue((self.work / "live" / EUICC_STORE_DIRNAME).is_dir())

    def test_the_process_wide_behaviour_profile_is_left_alone(self) -> None:
        live = BehaviourProfile(name="operator profile", atr_hex="3B00")
        previous = behaviour_profile.active_profile()
        behaviour_profile.set_active_profile(live)
        self.addCleanup(behaviour_profile.set_active_profile, previous)

        card = PersonaCard(self.source, self.work)

        self.assertIs(behaviour_profile.active_profile(), live)
        self.assertNotEqual(card.engine.get_atr(), bytes.fromhex("3B00"))

    def test_no_plugin_extends_a_private_engine(self) -> None:
        with mock.patch("SIMCARD.toolkit.extend_target_with_plugins") as extend:
            PersonaCard(self.source, self.work)
            extend.assert_not_called()
            SimulatedSimCardEngine(
                quirks_path="none",
                isdr_config_path=str(self.source / ISDR_CONFIG_FILENAME),
                euicc_store_root=str(self.root / "shared-store"),
                behaviour_profile_path="none",
            )
            extend.assert_called_once()

    def test_work_directory_inside_the_persona_is_refused(self) -> None:
        with self.assertRaises(PersonaError):
            PersonaCard(self.source, self.source / "work")
        with self.assertRaises(PersonaError):
            PersonaCard(self.source, self.source)

    def test_observers_and_extensions_follow_the_card_across_a_reset(self) -> None:
        card = PersonaCard(self.source, self.work)
        seen: list[bytes] = []
        card.add_apdu_observer(lambda command, result: seen.append(command))
        canned = (tlv("BF2E", tlv("80", b"\x42" * 16)), 0x90, 0x00)

        class _Challenge:
            def before_store_data(self, payload: bytes):
                return canned if payload == bytes.fromhex("BF2E00") else None

        card.register_store_data_extension(_Challenge())
        card.reset()
        connection = card.connection()

        connection.transmit(list(ISDR_SELECT))
        data, sw1, sw2 = connection.transmit(list(_store_data(bytes.fromhex("BF2E00"))))

        self.assertEqual((bytes(data), sw1, sw2), canned)
        self.assertEqual(seen, [ISDR_SELECT, _store_data(bytes.fromhex("BF2E00"))])

    def test_connection_reconnects_to_the_rebuilt_card(self) -> None:
        card = PersonaCard(self.source, self.work)
        connection = card.connection()
        connection.connect(protocol=2)
        connection.transmit(list(ISDR_SELECT))

        card.reset()
        _, sw1, sw2 = connection.transmit(list(ISDR_SELECT))

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(card.engine.state.current_protocol, 2)


class EngineSeamTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        _write_persona(self.root)
        self.engine = SimulatedSimCardEngine(
            quirks_path="none",
            isdr_config_path=str(self.root / ISDR_CONFIG_FILENAME),
            sim_eim_identity_path=str(self.root / "eim_identity.json"),
            euicc_store_root=str(self.root / EUICC_STORE_DIRNAME),
            behaviour_profile_path="none",
            private=True,
        )

    def test_observer_sees_the_answer_a_quirk_substituted(self) -> None:
        substituted = (b"", 0x6A, 0x82)
        self.engine.quirks.add_before_apdu(
            lambda command, state: substituted if command == ISDR_SELECT else None
        )
        seen: list[tuple[bytes, tuple[bytes, int, int]]] = []
        self.engine.add_apdu_observer(lambda command, result: seen.append((command, result)))

        self.assertEqual(self.engine.transmit(ISDR_SELECT), substituted)
        self.assertEqual(seen, [(ISDR_SELECT, substituted)])

    def test_a_raising_observer_does_not_disturb_the_card(self) -> None:
        def _broken(command: bytes, result: object) -> None:
            raise RuntimeError("observer failure")

        seen: list[bytes] = []
        self.engine.add_apdu_observer(_broken)
        self.engine.add_apdu_observer(_broken)
        self.engine.add_apdu_observer(lambda command, result: seen.append(command))

        with self.assertLogs("SIMCARD.engine", level="WARNING") as logs:
            _, sw1, sw2 = self.engine.transmit(ISDR_SELECT)

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(seen, [ISDR_SELECT])
        self.assertEqual(len(logs.records), 1)

    def test_store_data_extension_can_replace_the_answer(self) -> None:
        class _Replace:
            def after_store_data(self, payload: bytes, result):
                if payload == bytes.fromhex("BF2200"):
                    return (result[0], 0x6A, 0x80)
                return None

        self.engine.sgp.register_extension(_Replace())
        self.engine.transmit(ISDR_SELECT)

        info2, sw1, sw2 = self.engine.transmit(_store_data(bytes.fromhex("BF2200")))
        _, other_sw1, other_sw2 = self.engine.transmit(_store_data(bytes.fromhex("BF2000")))

        self.assertEqual((sw1, sw2), (0x6A, 0x80))
        self.assertTrue(info2.startswith(bytes.fromhex("BF22")))
        self.assertEqual((other_sw1, other_sw2), (0x90, 0x00))


class EmptiedProfileStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = _write_persona(Path(temporary.name))

    def test_a_store_never_written_is_seeded_with_the_built_in_profiles(self) -> None:
        engine = build_persona_engine(self.root)

        self.assertGreater(len(engine.state.profiles), 0)

    def test_a_card_emptied_of_profiles_stays_empty_after_a_rebuild(self) -> None:
        engine = build_persona_engine(self.root)
        engine.state.profiles = []
        sync_profiles_to_store(str(engine.state.profile_store_path), [])

        rebuilt = build_persona_engine(self.root)

        self.assertEqual(rebuilt.state.profiles, [])
        self.assertEqual(rebuilt.state.active_profile_aid, "")


if __name__ == "__main__":
    unittest.main()
