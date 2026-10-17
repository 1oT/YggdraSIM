# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Simulator-side follow-ups to the SCP03 GlobalPlatform / CAT spec audit.

Four surfaces are pinned here against the specification library:

* GP Card Spec v2.3.1 §11.5 INSTALL -- P1.b8 segmentation, the P2
  values of Table 11-40, and the Table 11-42 to 11-47 data fields with
  BER-coded parameter and token lengths.
* GPC v2.3.1 §11.4 GET STATUS -- Table 11-33 P1 subsets, Table 11-34 P2
  and the Table 11-36 / 11-37 response templates.
* ETSI TS 102 223 v18.3 §8.6 / §8.76 PROVIDE LOCAL INFORMATION battery
  state, tagged '63' / 'E3' per TS 101 220 v19 Table 7.23.
* 3GPP TS 31.102 v19.5 §4.2.2 EF.IMSI length octet and SGP.32 v1.3
  §5.9.18 GetEimConfigurationDataResponse, each decoded by the strict
  SCP03-side consumer.

The GlobalPlatform block drives the real ``GlobalPlatformManager``
command builders against the simulator engine over a transport shim, so
a divergence between the two sides fails here rather than on a card.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from SCP03.core.decoders import ContentDecoder
from SCP03.logic.gp import GlobalPlatformManager
from SCP03.logic.sgp32_decode import decode_eim_configuration_entries
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import build_default_state
from SIMCARD.sgp import SgpLogic
from SIMCARD.toolkit import PROVIDE_LOCAL_INFORMATION_COMMAND
from SIMCARD.utils import encode_imsi_ef, read_tlv, tlv

ELF_AID = bytes.fromhex("A0000001515350")
MODULE_AID = bytes.fromhex("A000000151535000")
APP_AID = bytes.fromhex("A000000151535001")
ISD_R_AID = "A0000005591010FFFFFFFF8900000100"
# GlobalPlatform Issuer Security Domain AID (GPC v2.3.1 §11.9): the
# simulator's MNO-SD, reported in the '40' subset as a Supplementary
# Security Domain.
MNO_SD_AID = bytes.fromhex("A000000151000000")


def _new_engine(tmp: tempfile.TemporaryDirectory) -> SimulatedSimCardEngine:
    store_root = Path(tmp.name) / "simcard"
    (store_root / "euicc").mkdir(parents=True, exist_ok=True)
    profile_store = store_root / "profile_store"
    profile_store.mkdir(parents=True, exist_ok=True)
    engine = SimulatedSimCardEngine(
        euicc_store_root=str(store_root),
        profile_store_path=str(profile_store),
    )
    engine.state.scp03_session.authenticated = True
    return engine


class _EngineSession:
    """Stand-in for the SCP03 session object the builders gate on."""

    is_authenticated = True


class _EngineTransport:
    """Transport shim that forwards manager APDUs to the simulator engine."""

    def __init__(self, engine: SimulatedSimCardEngine) -> None:
        self.engine = engine
        self.session = _EngineSession()
        self.sent: list[str] = []
        self.last_status: tuple[int, int] = (0x00, 0x00)

    def transmit(self, command: str, silent: bool = False) -> tuple[bytes, int, int]:
        del silent
        normalized = str(command).replace(" ", "").upper()
        self.sent.append(normalized)
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex(normalized))
        self.last_status = (sw1, sw2)
        return data, sw1, sw2


def _make_manager(engine: SimulatedSimCardEngine) -> GlobalPlatformManager:
    manager = GlobalPlatformManager.__new__(GlobalPlatformManager)
    manager.tp = _EngineTransport(engine)
    manager.raw_keys = {}
    manager.target_aid = bytes.fromhex(ISD_R_AID)
    manager.active_scp_protocol = "SCP03"
    return manager


def _registry_states(manager: GlobalPlatformManager, kind: str) -> dict[str, str]:
    data = manager.get_registry_data(kind)
    entries = data.get("entries", [])
    return {str(entry["aid"]): str(entry["state"]) for entry in entries}


def _tlv_children(value: bytes) -> list[tuple[bytes, bytes]]:
    children: list[tuple[bytes, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, child, _raw, offset = read_tlv(value, offset)
        children.append((tag, child))
    return children


def _registry_templates(response: bytes) -> list[list[tuple[bytes, bytes]]]:
    """Split a GET STATUS response into the child TLVs of each 'E3' template."""
    templates: list[list[tuple[bytes, bytes]]] = []
    for tag, value in _tlv_children(response):
        if tag != b"\xE3":
            raise AssertionError(f"unexpected registry tag {tag.hex().upper()}")
        templates.append(_tlv_children(value))
    return templates


class GpManagerAgainstSimulatorTests(unittest.TestCase):
    """The corrected SCP03 builders must complete a card-content lifecycle."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.engine = _new_engine(self._td)
        self.manager = _make_manager(self.engine)

    def tearDown(self) -> None:
        self._td.cleanup()

    def _load_package(self) -> None:
        self.manager.install_for_load(ELF_AID.hex(), ISD_R_AID)
        self.engine.transmit(bytes.fromhex("80E88000020102" + "00"))

    def test_load_install_make_selectable_status_lock_delete(self) -> None:
        self._load_package()
        packages = _registry_states(self.manager, "PACKAGES")
        self.assertEqual(packages.get(ELF_AID.hex().upper()), "LOADED")

        self.manager.install_app(
            ELF_AID.hex(),
            APP_AID.hex(),
            mod_aid_hex=MODULE_AID.hex(),
            privileges="00",
            params="C900",
            make_selectable=False,
        )
        applications = _registry_states(self.manager, "APPS")
        self.assertEqual(applications.get(APP_AID.hex().upper()), "INSTALLED")

        self.manager.install_make_selectable(APP_AID.hex(), privileges="00")
        applications = _registry_states(self.manager, "APPS")
        self.assertEqual(applications.get(APP_AID.hex().upper()), "SELECTABLE")

        # Table 11-4: b8 = 1 with b2b1 = 11 is LOCKED; '07' returns the
        # application to SELECTABLE.
        self.manager.set_status(APP_AID.hex(), 0x83, 0x40)
        applications = _registry_states(self.manager, "APPS")
        self.assertEqual(applications.get(APP_AID.hex().upper()), "LOCKED")

        self.manager.set_status(APP_AID.hex(), 0x07, 0x40)
        applications = _registry_states(self.manager, "APPS")
        self.assertEqual(applications.get(APP_AID.hex().upper()), "SELECTABLE")

        self.manager.delete_object(APP_AID.hex(), recursive=False)
        applications = _registry_states(self.manager, "APPS")
        self.assertNotIn(APP_AID.hex().upper(), applications)

    def test_install_extradition_and_registry_update_are_accepted(self) -> None:
        self._load_package()
        self.manager.install_app(
            ELF_AID.hex(),
            APP_AID.hex(),
            mod_aid_hex=MODULE_AID.hex(),
            privileges="00",
        )

        self.manager.install_extradition(APP_AID.hex(), ISD_R_AID)
        self.assertTrue(self.manager.tp.sent[-1].startswith("80E61000"))
        self.assertEqual(self.manager.tp.last_status, (0x90, 0x00))

        self.manager.install_registry_update(APP_AID.hex(), privileges="820000")
        self.assertTrue(self.manager.tp.sent[-1].startswith("80E64000"))
        self.assertEqual(self.manager.tp.last_status, (0x90, 0x00))
        target = next(
            app for app in self.engine.state.gp_apps if app.aid == APP_AID.hex().upper()
        )
        self.assertEqual(target.privileges, bytes.fromhex("820000"))

    def test_registry_response_uses_get_status_page_zero_only(self) -> None:
        self._load_package()
        data = self.manager.get_registry_data("PACKAGES")
        self.assertEqual(data["status"], "9000")
        self.assertEqual(data["pages"], 1)
        self.assertFalse(data["truncated"])


class GpInstallReferenceControlTests(unittest.TestCase):
    """GPC v2.3.1 §11.5.2.1 / §11.5.2.2 reference control parameters."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.engine = _new_engine(self._td)

    def tearDown(self) -> None:
        self._td.cleanup()

    @staticmethod
    def _lv(payload: bytes) -> bytes:
        return bytes([len(payload)]) + bytes(payload)

    def _install(self, p1: int, p2: int, body: bytes) -> tuple[bytes, int, int]:
        apdu = bytes([0x80, 0xE6, p1, p2, len(body)]) + body + b"\x00"
        return self.engine.transmit(apdu)

    def _load_body(self, *, params: bytes = b"", token: bytes = b"") -> bytes:
        return (
            self._lv(ELF_AID)
            + self._lv(bytes.fromhex(ISD_R_AID))
            + self._lv(b"")
            + _ber_lv(params)
            + _ber_lv(token)
        )

    def test_p1_b8_segments_the_command_data_field(self) -> None:
        body = self._load_body()
        # Table 11-41: P1.b8 = 1 means more INSTALL commands follow.
        _data, sw1, sw2 = self._install(0x82, 0x00, body[:4])
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self.engine.state.gp_install.pending_elf_aid, "")

        _data, sw1, sw2 = self._install(0x02, 0x00, body[4:])
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(
            self.engine.state.gp_install.pending_elf_aid,
            ELF_AID.hex().upper(),
        )

    def test_p2_beyond_the_combined_process_values_is_rejected(self) -> None:
        for p2 in (0x00, 0x01, 0x03):
            with self.subTest(p2=p2):
                _data, sw1, sw2 = self._install(0x02, p2, self._load_body())
                self.assertEqual((sw1, sw2), (0x90, 0x00))
        # Table 11-40 allows only '00', '01' and '03'; '80' used to be
        # read as the segmentation flag that lives in P1.
        _data, sw1, sw2 = self._install(0x02, 0x80, self._load_body())
        self.assertEqual((sw1, sw2), (0x6A, 0x86))

    def test_load_parameters_accept_the_three_ber_length_forms(self) -> None:
        for params in (b"\xC9\x00", b"\x00" * 128, b"\x00" * 200, b"\x00" * 300):
            with self.subTest(length=len(params)):
                body = self._load_body(params=params)
                apdu = (
                    bytes([0x80, 0xE6, 0x02, 0x00, 0x00])
                    + len(body).to_bytes(2, "big")
                    + body
                    + b"\x00\x00"
                )
                _data, sw1, sw2 = self.engine.transmit(apdu)
                self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_bare_80_length_is_the_literal_length_128(self) -> None:
        # Tables 11-42 to 11-46: "the length 128 may also be coded on
        # one byte as '80'".
        body = (
            self._lv(ELF_AID)
            + self._lv(bytes.fromhex(ISD_R_AID))
            + self._lv(b"")
            + b"\x80"
            + b"\x00" * 128
            + b"\x00"
        )
        apdu = bytes([0x80, 0xE6, 0x02, 0x00, len(body)]) + body + b"\x00"
        _data, sw1, sw2 = self.engine.transmit(apdu)
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_make_selectable_requires_the_two_leading_empty_lengths(self) -> None:
        self._install(0x02, 0x00, self._load_body())
        self.engine.transmit(bytes.fromhex("80E8800002010200"))
        install_body = (
            self._lv(ELF_AID)
            + self._lv(MODULE_AID)
            + self._lv(APP_AID)
            + self._lv(b"\x00")
            + _ber_lv(b"")
            + _ber_lv(b"")
        )
        self._install(0x04, 0x00, install_body)

        # Table 11-44 opens with two '00' length fields; the AID-first
        # shape the simulator used to expect is rejected.
        _data, sw1, sw2 = self._install(0x08, 0x00, self._lv(APP_AID) + b"\x01\x00\x00\x00")
        self.assertEqual((sw1, sw2), (0x6A, 0x80))

        body = b"\x00\x00" + self._lv(APP_AID) + b"\x01\x00" + b"\x00\x00"
        _data, sw1, sw2 = self._install(0x08, 0x00, body)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        target = next(
            app for app in self.engine.state.gp_apps if app.aid == APP_AID.hex().upper()
        )
        self.assertEqual(target.lifecycle_state, 0x07)

    def test_personalization_rejects_an_unknown_application(self) -> None:
        # Table 11-47: '00', '00', L/AID, '00', '00', '00'.
        body = b"\x00\x00" + self._lv(APP_AID) + b"\x00\x00\x00"
        _data, sw1, sw2 = self._install(0x20, 0x00, body)
        self.assertEqual((sw1, sw2), (0x6A, 0x82))

    def test_extradition_rejects_an_unknown_security_domain(self) -> None:
        body = (
            self._lv(bytes.fromhex("A0000005591010FFFFFFFF89DEADBEEF"))
            + b"\x00"
            + self._lv(APP_AID)
            + b"\x00"
            + _ber_lv(b"")
            + _ber_lv(b"")
        )
        _data, sw1, sw2 = self._install(0x10, 0x00, body)
        self.assertEqual((sw1, sw2), (0x6A, 0x88))


def _ber_lv(value: bytes) -> bytes:
    """Encode a GPC v2.3.1 parameters / token field with a BER length."""
    if len(value) <= 0x7F:
        return bytes([len(value)]) + value
    if len(value) <= 0xFF:
        return b"\x81" + bytes([len(value)]) + value
    return b"\x82" + len(value).to_bytes(2, "big") + value


class GpGetStatusSubsetTests(unittest.TestCase):
    """GPC v2.3.1 §11.4.2.1 Table 11-33 and §11.4.3.1 Tables 11-36 / 11-37."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.engine = _new_engine(self._td)
        load_body = (
            bytes([len(ELF_AID)])
            + ELF_AID
            + bytes([0x10])
            + bytes.fromhex(ISD_R_AID)
            + b"\x00\x00\x00"
        )
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x80, 0xE6, 0x02, 0x00, len(load_body)]) + load_body + b"\x00"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.engine.transmit(bytes.fromhex("80E8800002010200"))
        install_body = (
            bytes([len(ELF_AID)])
            + ELF_AID
            + bytes([len(MODULE_AID)])
            + MODULE_AID
            + bytes([len(APP_AID)])
            + APP_AID
            + b"\x01\x80"
            + b"\x00\x00"
        )
        _data, sw1, sw2 = self.engine.transmit(
            bytes([0x80, 0xE6, 0x0C, 0x00, len(install_body)]) + install_body + b"\x00"
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def tearDown(self) -> None:
        self._td.cleanup()

    def _get_status(self, p1: int, p2: int = 0x02, search: bytes = b"") -> tuple[bytes, int, int]:
        body = bytes([0x4F, len(search)]) + search
        apdu = bytes([0x80, 0xF2, p1, p2, len(body)]) + body + b"\x00"
        return self.engine.transmit(apdu)

    def test_p1_20_lists_load_files_without_their_modules(self) -> None:
        data, sw1, sw2 = self._get_status(0x20)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        templates = _registry_templates(data)
        self.assertEqual(len(templates), 1)
        tags = [tag for tag, _value in templates[0]]
        self.assertEqual(tags, [b"\x4F", bytes.fromhex("9F70")])
        self.assertEqual(dict(templates[0])[b"\x4F"], ELF_AID)

    def test_p1_10_lists_load_files_with_their_modules(self) -> None:
        data, sw1, sw2 = self._get_status(0x10)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        templates = _registry_templates(data)
        self.assertEqual(len(templates), 1)
        fields = templates[0]
        self.assertEqual([tag for tag, _value in fields], [b"\x4F", bytes.fromhex("9F70"), b"\x84"])
        self.assertEqual(dict(fields)[b"\x84"], MODULE_AID)

    def test_modules_are_not_top_level_registry_entries(self) -> None:
        for scope in (0x20, 0x10):
            with self.subTest(scope=scope):
                data, _sw1, _sw2 = self._get_status(scope)
                for fields in _registry_templates(data):
                    self.assertEqual(dict(fields)[b"\x4F"], ELF_AID)

    def test_application_entries_always_carry_three_privilege_bytes(self) -> None:
        data, sw1, sw2 = self._get_status(0x40)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        templates = _registry_templates(data)
        self.assertGreater(len(templates), 0)
        for fields in templates:
            mapping = dict(fields)
            self.assertIn(b"\xC5", mapping)
            self.assertEqual(len(mapping[b"\xC5"]), 3)
        installed = [f for f in templates if dict(f)[b"\x4F"] == APP_AID]
        self.assertEqual(len(installed), 1)
        self.assertEqual(dict(installed[0])[b"\xC5"], bytes.fromhex("800000"))

    def test_isd_subset_ignores_the_search_criteria(self) -> None:
        # §11.4.2.1: for P1 = '80' any search criteria are ignored.
        filtered, sw1, sw2 = self._get_status(0x80, search=bytes.fromhex("A0DEADBEEF00"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        unfiltered, _sw1, _sw2 = self._get_status(0x80)
        self.assertEqual(filtered, unfiltered)

    def test_aid_search_criterion_matches_on_a_prefix(self) -> None:
        data, sw1, sw2 = self._get_status(0x40, search=ELF_AID[:5])
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        aids = [dict(fields)[b"\x4F"] for fields in _registry_templates(data)]
        # §11.4.2.1: the '40' subset also reports the Supplementary Security
        # Domains, and the MNO-SD shares the GlobalPlatform RID with the test
        # application, so a five-byte prefix matches both.
        self.assertEqual(aids, [MNO_SD_AID, APP_AID])

        _data, sw1, sw2 = self._get_status(0x40, search=bytes.fromhex("D2760001"))
        self.assertEqual((sw1, sw2), (0x6A, 0x88))

    def test_get_next_occurrence_has_nothing_left_to_report(self) -> None:
        # Table 11-34 P2.b1 = 1; the simulator never answers '63 10',
        # so the follow-up read returns "referenced data not found".
        _data, sw1, sw2 = self._get_status(0x20, p2=0x03)
        self.assertEqual((sw1, sw2), (0x6A, 0x88))

    def test_deprecated_p2_b2_zero_still_returns_the_tlv_shape(self) -> None:
        tlv_form, _sw1, _sw2 = self._get_status(0x20, p2=0x02)
        legacy_form, sw1, sw2 = self._get_status(0x20, p2=0x00)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(legacy_form, tlv_form)

    def test_unsupported_subset_returns_6a86(self) -> None:
        _data, sw1, sw2 = self._get_status(0x99)
        self.assertEqual((sw1, sw2), (0x6A, 0x86))


class ProvideLocalInformationBatteryStateTests(unittest.TestCase):
    """TS 102 223 v18.3 §8.6 qualifier '0A' with the §8.76 Battery State object."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.engine = _new_engine(self._td)
        self.toolkit = self.engine.toolkit

    def tearDown(self) -> None:
        self._td.cleanup()

    def _terminal_response(self, command_number: int, qualifier: int, extra: bytes) -> bytes:
        payload = (
            tlv("81", bytes([command_number, PROVIDE_LOCAL_INFORMATION_COMMAND, qualifier]))
            + tlv("82", b"\x82\x81")
            + tlv("83", b"\x00")
            + extra
        )
        return bytes([0x80, 0x14, 0x00, 0x00, len(payload)]) + payload

    def _issue(self, qualifier: int) -> int:
        result = self.toolkit.queue_provide_local_information(qualifier=qualifier)
        self.toolkit.handle_fetch()
        return int(result["commandNumber"])

    def test_battery_state_latches_from_qualifier_0a_tag_63(self) -> None:
        command_number = self._issue(0x0A)
        response = self._terminal_response(command_number, 0x0A, tlv("63", b"\x04"))
        _data, sw1, sw2 = self.engine.transmit(response)
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(self.engine.state.toolkit.battery_state, 0x04)

    def test_comprehension_required_form_e3_is_accepted(self) -> None:
        command_number = self._issue(0x0A)
        response = self._terminal_response(command_number, 0x0A, tlv("E3", b"\x01"))
        self.engine.transmit(response)
        self.assertEqual(self.engine.state.toolkit.battery_state, 0x01)

    def test_retired_5c_tag_no_longer_latches_a_battery_state(self) -> None:
        # '5C' is RFU in TS 101 220 v19 Table 7.23 and never carried the
        # Battery State object.
        self.engine.state.toolkit.battery_state = 0x02
        command_number = self._issue(0x0A)
        response = self._terminal_response(command_number, 0x0A, tlv("5C", b"\x04"))
        self.engine.transmit(response)
        self.assertEqual(self.engine.state.toolkit.battery_state, 0x02)

    def test_access_technology_comes_from_the_3f_object(self) -> None:
        # §6.8.7: a qualifier '06' request is answered with the §8.61
        # Access Technology object, not with the qualifier byte.
        command_number = self._issue(0x06)
        response = self._terminal_response(command_number, 0x06, tlv("3F", b"\x03"))
        self.engine.transmit(response)
        self.assertEqual(self.engine.state.toolkit.access_technology, 0x03)

    def test_battery_qualifier_is_recorded_as_0a(self) -> None:
        command_number = self._issue(0x0A)
        self.engine.transmit(
            self._terminal_response(command_number, 0x0A, tlv("63", b"\x03"))
        )
        self.assertEqual(
            self.engine.state.toolkit.last_provide_local_information_qualifier,
            0x0A,
        )


class EfImsiLengthOctetTests(unittest.TestCase):
    """3GPP TS 31.102 v19.5 §4.2.2: byte 1 counts the significant IMSI bytes."""

    def test_length_octet_tracks_the_digit_count(self) -> None:
        cases = (
            ("001010000000001", 0x08),
            ("00101000000001", 0x08),
            ("0010100000001", 0x07),
            ("001010000001", 0x07),
            ("0010100001", 0x06),
        )
        for imsi, expected_length in cases:
            with self.subTest(imsi=imsi):
                encoded = encode_imsi_ef(imsi)
                self.assertEqual(len(encoded), 9)
                self.assertEqual(encoded[0], expected_length)

    def test_strict_decoder_round_trips_without_a_length_warning(self) -> None:
        for imsi in ("001010000000001", "00101000000001", "0010100000001"):
            with self.subTest(imsi=imsi):
                decoded = ContentDecoder.decode_imsi(encode_imsi_ef(imsi).hex())
                self.assertNotIn("Error", decoded)
                self.assertEqual(decoded["imsi"], imsi)
                self.assertEqual(decoded["digit_count"], len(imsi))
                self.assertEqual(decoded["length_octet"], (len(imsi) // 2) + 1)
                self.assertNotIn("Warnings", decoded)

    def test_hardcoded_length_octet_would_warn_on_a_short_imsi(self) -> None:
        # The pre-fix encoder wrote '08' for every IMSI; the strict
        # decoder now reports the mismatch between the length octet and
        # the digit count.
        short_imsi = "0010100000001"
        stale = bytearray(encode_imsi_ef(short_imsi))
        stale[0] = 0x08
        decoded = ContentDecoder.decode_imsi(bytes(stale).hex())
        self.assertEqual(decoded["imsi"], short_imsi)
        self.assertIn("Warnings", decoded)
        self.assertTrue(
            any("15 digits" in str(warning) for warning in decoded["Warnings"]),
            f"expected an implied-digit-count warning: {decoded}",
        )


class GetEimConfigurationDataListShapeTests(unittest.TestCase):
    """SGP.32 v1.3 §5.9.18: one 'A0' list holding every EimConfigurationData."""

    def setUp(self) -> None:
        self.state = build_default_state()
        self.logic = SgpLogic(self.state)

    def _response(self) -> bytes:
        response, sw1, sw2 = self.logic.handle_store_data(bytes.fromhex("BF5500"))
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        return response

    def test_single_a0_wraps_every_sequence_entry(self) -> None:
        response = self._response()
        root_tag, root_value, _raw, root_end = read_tlv(response, 0)
        self.assertEqual(root_tag, bytes.fromhex("BF55"))
        self.assertEqual(root_end, len(response))

        children = _tlv_children(root_value)
        self.assertEqual([tag for tag, _value in children], [b"\xA0"])
        rows = _tlv_children(children[0][1])
        self.assertGreater(len(rows), 0)
        self.assertEqual({tag for tag, _value in rows}, {b"\x30"})

    def test_strict_consumer_decodes_every_configured_eim(self) -> None:
        entries = decode_eim_configuration_entries(self._response())
        self.assertEqual(len(entries), len(self.state.eim_entries))
        decoded_ids = [str(entry.get("eim_id", "")) for entry in entries]
        for configured in self.state.eim_entries:
            self.assertIn(str(configured.eim_id), decoded_ids)

    def test_two_entries_share_one_list(self) -> None:
        first = self.state.eim_entries[0]
        second = type(first)(**{**vars(first), "eim_id": "second-eim.example.test"})
        self.state.eim_entries.append(second)

        response = self._response()
        _root_tag, root_value, _raw, _end = read_tlv(response, 0)
        children = _tlv_children(root_value)
        self.assertEqual(len(children), 1)
        self.assertEqual(len(_tlv_children(children[0][1])), 2)

        entries: list[dict[str, Any]] = decode_eim_configuration_entries(response)
        self.assertEqual(len(entries), 2)

    def test_empty_list_keeps_the_bare_bf55_envelope(self) -> None:
        self.state.eim_entries = []
        self.assertEqual(self._response(), bytes.fromhex("BF5500"))


if __name__ == "__main__":
    unittest.main()


class GpDeleteSpecTests(unittest.TestCase):
    """GPC v2.3.1 §11.2 DELETE: segmentation, P2 modes and the response data field."""

    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.engine = _new_engine(self._td)
        manager = _make_manager(self.engine)
        manager.install_for_load(ELF_AID.hex(), ISD_R_AID)
        self.engine.transmit(bytes.fromhex("80E88000020102" + "00"))
        manager.install_app(
            ELF_AID.hex(),
            APP_AID.hex(),
            mod_aid_hex=MODULE_AID.hex(),
            privileges="00",
            params="C900",
            make_selectable=False,
        )

    def tearDown(self) -> None:
        self._td.cleanup()

    @staticmethod
    def _body(aid: bytes) -> bytes:
        return b"\x4F" + bytes([len(aid)]) + aid

    def _delete(self, p1: int, p2: int, body: bytes) -> tuple[bytes, int, int]:
        apdu = bytes([0x80, 0xE4, p1, p2, len(body)]) + body + b"\x00"
        return self.engine.transmit(apdu)

    def test_response_carries_the_delete_confirmation_length(self) -> None:
        data, sw1, sw2 = self._delete(0x00, 0x00, self._body(APP_AID))

        # §11.2.3.1 Table 11-25: the length of the delete confirmation is
        # mandatory; with no Delegated Management receipt it is '00'.
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\x00")

    def test_p1_b8_holds_the_segment_until_the_last_component(self) -> None:
        body = self._body(APP_AID)

        first, sw1, sw2 = self._delete(0x80, 0x00, body[:3])

        # §11.2.2.1 Table 11-21: P1.b8 = 1 means more DELETE commands follow.
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(first, b"")

        data, sw1, sw2 = self._delete(0x00, 0x00, body[3:])

        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, b"\x00")

    def test_reserved_reference_control_bits_are_refused(self) -> None:
        # Table 11-21 leaves P1.b7..b1 RFU and Table 11-22 P2.b5..b1.
        self.assertEqual(self._delete(0x01, 0x00, self._body(APP_AID))[1:], (0x6A, 0x86))
        self.assertEqual(self._delete(0x00, 0x01, self._body(APP_AID))[1:], (0x6A, 0x86))

    def test_security_domain_forms_name_a_security_domain(self) -> None:
        # §11.2.2.3: P2.b7 (hierarchy) and P2.b6 (self-removal) address a
        # Security Domain, so an application AID is not found there.
        self.assertEqual(self._delete(0x00, 0x40, self._body(APP_AID))[1:], (0x6A, 0x82))
        self.assertEqual(self._delete(0x00, 0x20, self._body(APP_AID))[1:], (0x6A, 0x82))
