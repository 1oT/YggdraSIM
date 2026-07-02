# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import contextlib
import io
import sys
import tempfile
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


def _install_smartcard_stubs() -> None:
    if "smartcard" in sys.modules:
        return

    smartcard_module = types.ModuleType("smartcard")
    system_module = types.ModuleType("smartcard.System")
    card_connection_module = types.ModuleType("smartcard.CardConnection")
    atr_module = types.ModuleType("smartcard.ATR")

    class _CardConnection:
        T0_protocol = 0
        T1_protocol = 1
        RAW_protocol = 2

    class _Atr:
        def __init__(self, _raw):
            pass

        @staticmethod
        def getSupportedProtocols():
            return {"T=1": True}

    system_module.readers = lambda: []
    card_connection_module.CardConnection = _CardConnection
    atr_module.ATR = _Atr

    smartcard_module.System = system_module
    smartcard_module.CardConnection = card_connection_module
    smartcard_module.ATR = atr_module

    sys.modules["smartcard"] = smartcard_module
    sys.modules["smartcard.System"] = system_module
    sys.modules["smartcard.CardConnection"] = card_connection_module
    sys.modules["smartcard.ATR"] = atr_module


_install_smartcard_stubs()

import SCP80.builder as scp80_builder
import SCP80.config as scp80_config
import SCP80.crypto as scp80_crypto
import SCP80.transport as scp80_transport
from SCP80.utils import Utils


class DummyInventory:
    def __init__(self, *, namespace: dict | None = None, module_state: dict | None = None):
        self.namespace = namespace or {}
        self.module_state = module_state or {}
        self.namespace_writes: list[tuple[str, str, str, dict]] = []
        self.module_writes: list[tuple[str, dict]] = []

    def get_namespace(self, identity_kind: str, identity_value: str, namespace: str) -> dict:
        del identity_kind
        del identity_value
        del namespace
        return dict(self.namespace)

    def replace_namespace(
        self,
        identity_kind: str,
        identity_value: str,
        namespace: str,
        payload: dict,
    ) -> None:
        self.namespace_writes.append((identity_kind, identity_value, namespace, dict(payload)))

    def get_module_state(self, module_name: str) -> dict:
        del module_name
        return dict(self.module_state)

    def replace_module_state(self, module_name: str, payload: dict) -> None:
        self.module_writes.append((module_name, dict(payload)))


class DummyBuilderConfig:
    def __init__(self, values: dict[str, str] | None = None):
        self.values = dict(scp80_config.ConfigManager.DEFAULTS)
        self.values["kic"] = "0123456789ABCDEFFEDCBA9876543210"
        self.values["kid"] = "00112233445566778899AABBCCDDEEFF"
        if values is not None:
            self.values.update(values)
        self.increment_counter_calls = 0

    def get(self, key: str) -> str:
        return str(self.values.get(key, ""))

    def get_int(self, key: str) -> int:
        return int(str(self.values.get(key, "0")), 10)

    def increment_counter(self) -> None:
        self.increment_counter_calls += 1


class ConfigManagerTests(unittest.TestCase):
    def _make_manager(self) -> scp80_config.ConfigManager:
        manager = scp80_config.ConfigManager.__new__(scp80_config.ConfigManager)
        manager.file_path = Path(__file__).resolve()
        manager.data = dict(scp80_config.ConfigManager.DEFAULTS)
        manager.inventory = DummyInventory()
        manager.active_iccid = ""
        return manager

    def test_resolve_config_path_uses_runtime_dir(self) -> None:
        manager = self._make_manager()
        state_dir = Path(__file__).resolve().parents[1] / "state"
        with tempfile.TemporaryDirectory(dir=state_dir) as temp_dir:
            with mock.patch.object(scp80_config, "ensure_runtime_dir", return_value=temp_dir):
                resolved = manager._resolve_config_path()
        self.assertEqual(resolved, Path(temp_dir) / "ota_config.ini")

    def test_normalize_value_enforces_hex_and_range_rules(self) -> None:
        manager = self._make_manager()
        self.assertEqual(manager._normalize_value("concat_sms", "yes", strict=True), "ON")
        self.assertEqual(
            manager._normalize_value("tp_ud_max", "999", strict=False),
            scp80_config.ConfigManager.DEFAULTS["tp_ud_max"],
        )
        self.assertEqual(manager._normalize_value("cntr", "00 00 00 00 0A", strict=True), "000000000A")
        self.assertEqual(manager._normalize_value("pid", "7f", strict=True), "7F")
        self.assertEqual(manager._normalize_value("dcs", "f6", strict=True), "F6")
        with self.assertRaisesRegex(ValueError, "spi must be exactly 4 hex chars"):
            manager._normalize_value("spi", "AB", strict=True)
        with self.assertRaisesRegex(ValueError, "pid must be exactly 2 hex chars"):
            manager._normalize_value("pid", "1234", strict=True)
        with self.assertRaisesRegex(ValueError, "kic must be 8, 16, 24, 32 bytes"):
            manager._normalize_value("kic", "11" * 17, strict=True)
        self.assertEqual(manager._normalize_value("kid", "11" * 16, strict=True), "11" * 16)

    def test_set_rejects_unknown_keys(self) -> None:
        manager = self._make_manager()

        with self.assertRaisesRegex(ValueError, "Unknown SCP80 config key: nope"):
            manager.set("nope", "32")

    def test_set_updates_indicator_slots(self) -> None:
        manager = self._make_manager()

        manager.set("kic_indicator", "32")
        manager.set("kid_indicator", "32")

        self.assertEqual(manager.data["kic_indicator"], "32")
        self.assertEqual(manager.data["kid_indicator"], "32")

    def test_bind_iccid_profile_applies_inventory_payload(self) -> None:
        manager = self._make_manager()
        manager.inventory = DummyInventory(namespace={"spi": "A1B2", "concat_sms": "off"})

        payload = manager.bind_iccid_profile("89-01")

        self.assertEqual(payload["spi"], "A1B2")
        self.assertEqual(manager.active_iccid, "8901")
        self.assertEqual(manager.data["spi"], "A1B2")
        self.assertEqual(manager.data["concat_sms"], "OFF")

    def test_bind_iccid_profile_persists_new_profile_when_missing(self) -> None:
        manager = self._make_manager()
        manager.inventory = DummyInventory(namespace={})

        payload = manager.bind_iccid_profile("8901")

        self.assertEqual(payload, {})
        self.assertEqual(len(manager.inventory.namespace_writes), 1)

    def test_increment_counter_wraps_and_saves(self) -> None:
        manager = self._make_manager()
        save_calls: list[str] = []
        manager.save = lambda: save_calls.append("save")
        manager.data["cntr"] = "FFFFFFFFFF"

        manager.increment_counter()

        self.assertEqual(manager.data["cntr"], "0000000000")
        self.assertEqual(save_calls, ["save"])


class LegacyKeyMigrationTests(unittest.TestCase):
    """Lock the soft-compat behaviour for pre-rename SCP80 config keys.

    Pre-rename schema (unversioned ini files in the wild) carried:
      - ``key_enc`` / ``key_mac``: 16-byte session keys.
      - ``kic`` / ``kid``: 2-hex-char ETSI TS 102 225 §5.1.1 indicator bytes.
    Current schema renames the session keys to ``kic`` / ``kid`` and the
    indicators to ``kic_indicator`` / ``kid_indicator``. The loader must
    auto-migrate so existing on-disk records keep working without manual
    rewrites.
    """

    def _migrate(self, payload: dict) -> tuple:
        return scp80_config.ConfigManager._migrate_legacy_keys(payload)

    def test_key_enc_and_key_mac_route_to_kic_and_kid(self) -> None:
        legacy = {"key_enc": "AA" * 16, "key_mac": "BB" * 16}
        migrated, log = self._migrate(legacy)
        self.assertEqual(migrated.get("kic"), "AA" * 16)
        self.assertEqual(migrated.get("kid"), "BB" * 16)
        self.assertNotIn("key_enc", migrated)
        self.assertNotIn("key_mac", migrated)
        self.assertIn("key_enc -> kic", log)
        self.assertIn("key_mac -> kid", log)

    def test_two_char_kic_kid_route_to_indicator_slots(self) -> None:
        legacy = {"kic": "15", "kid": "15"}
        migrated, log = self._migrate(legacy)
        self.assertEqual(migrated.get("kic_indicator"), "15")
        self.assertEqual(migrated.get("kid_indicator"), "15")
        self.assertNotIn("kic", migrated)
        self.assertNotIn("kid", migrated)
        self.assertIn("kic -> kic_indicator", log)
        self.assertIn("kid -> kid_indicator", log)

    def test_full_legacy_payload_migrates_both_layers(self) -> None:
        legacy = {
            "kic": "12",
            "kid": "12",
            "key_enc": "11" * 16,
            "key_mac": "22" * 16,
        }
        migrated, log = self._migrate(legacy)
        self.assertEqual(migrated.get("kic_indicator"), "12")
        self.assertEqual(migrated.get("kid_indicator"), "12")
        self.assertEqual(migrated.get("kic"), "11" * 16)
        self.assertEqual(migrated.get("kid"), "22" * 16)
        self.assertEqual(len(log), 4)

    def test_modern_payload_passes_through_unchanged(self) -> None:
        modern = {
            "kic_indicator": "15",
            "kid_indicator": "15",
            "kic": "33" * 16,
            "kid": "44" * 16,
        }
        migrated, log = self._migrate(modern)
        self.assertEqual(migrated, modern)
        self.assertEqual(log, [])

    def test_legacy_indicator_does_not_overwrite_explicit_indicator(self) -> None:
        payload = {
            "kic": "15",
            "kic_indicator": "32",
        }
        migrated, _log = self._migrate(payload)
        self.assertEqual(migrated.get("kic_indicator"), "32")
        self.assertEqual(migrated.get("kic"), "15")

    def test_legacy_session_key_does_not_overwrite_explicit_kic(self) -> None:
        payload = {
            "key_enc": "AA" * 16,
            "kic": "BB" * 16,
        }
        migrated, _log = self._migrate(payload)
        self.assertEqual(migrated.get("kic"), "BB" * 16)
        self.assertNotIn("key_enc", migrated)


class CryptoEngineTests(unittest.TestCase):
    def test_algo_type_and_keyset_description(self) -> None:
        self.assertEqual(scp80_crypto.CryptoEngine.get_algo_type("02"), "AES")
        self.assertEqual(scp80_crypto.CryptoEngine.get_algo_type("ZZ"), "3DES2")
        self.assertIn("AES", scp80_crypto.CryptoEngine.describe_keyset("32"))
        self.assertIn("Keyset 3", scp80_crypto.CryptoEngine.describe_keyset("32"))

    def test_compute_pcntr_and_aes_primitives_are_deterministic(self) -> None:
        self.assertEqual(scp80_crypto.CryptoEngine.compute_pcntr(1, 8), 1)
        self.assertEqual(
            scp80_crypto.CryptoEngine.compute_cc("AES", bytes(16), b"").hex().upper(),
            "4387C14B46EF7E17",
        )
        self.assertEqual(
            scp80_crypto.CryptoEngine.encrypt_ct("AES", bytes(16), bytes(16)).hex().upper(),
            "66E94BD4EF8A2C3B884CFA59CA342B2E",
        )


class UtilsTests(unittest.TestCase):
    def test_hex_conversion_and_3des_key_padding(self) -> None:
        self.assertEqual(Utils.to_bytes("AA BB"), b"\xAA\xBB")
        self.assertEqual(Utils.to_hex(b"\xAA\xBB", space=True), "AA BB")
        self.assertEqual(len(Utils.pad_key_3des(b"\x11" * 16)), 24)
        with self.assertRaisesRegex(ValueError, "Invalid hex input"):
            Utils.to_bytes("XYZ")


class OtaPacketBuilderTests(unittest.TestCase):
    def test_ber_length_encoding_and_segment_estimation(self) -> None:
        self.assertEqual(scp80_builder.OtaPacketBuilder._encode_ber_length(0x7F), b"\x7F")
        self.assertEqual(scp80_builder.OtaPacketBuilder._encode_ber_length(0x80), b"\x81\x80")
        self.assertEqual(
            scp80_builder.OtaPacketBuilder.estimate_segment_count(8, "AES", max_tp_ud=140),
            1,
        )

    def test_wrap_sms_tpdu_uses_extended_form_when_needed(self) -> None:
        builder = scp80_builder.OtaPacketBuilder(DummyBuilderConfig())
        short_apdu = builder._wrap_sms_tpdu(b"\x01" * 8)
        self.assertTrue(short_apdu.startswith("80C20000"))
        with self.assertRaisesRegex(ValueError, "short-length capacity"):
            builder._wrap_sms_tpdu(b"\x01" * 300)
        extended_apdu = builder._wrap_sms_tpdu(b"\x01" * 300, allow_extended_apdu=True)
        self.assertTrue(extended_apdu.startswith("80C2000000"))

    def test_build_plan_single_segment(self) -> None:
        config = DummyBuilderConfig({"payload": "AA" * 10, "tp_ud_max": "140"})
        builder = scp80_builder.OtaPacketBuilder(config)

        plan = builder.build_plan()

        self.assertFalse(plan.is_concatenated)
        self.assertEqual(len(plan.apdus), 1)
        self.assertEqual(len(plan.reader_apdus), 1)
        self.assertEqual(plan.payload_hex, "AA" * 10)
        self.assertIn("02028281060280018B", plan.apdus[0].apdu_hex)
        self.assertNotIn("820283818B", plan.apdus[0].apdu_hex)
        self.assertIn("4005811250F341F62222222222222225027000", plan.apdus[0].apdu_hex)

    def test_build_plan_uses_configured_pid_and_dcs(self) -> None:
        config = DummyBuilderConfig({"payload": "AA" * 10, "pid": "7F", "dcs": "F5"})
        builder = scp80_builder.OtaPacketBuilder(config)

        plan = builder.build_plan()

        self.assertIn("4005811250F37FF52222222222222225027000", plan.apdus[0].apdu_hex)

    def test_build_plan_concatenated_and_build_rejects_single_apdu_api(self) -> None:
        config = DummyBuilderConfig(
            {
                "payload": "AA" * 120,
                "tp_ud_max": "20",
                "concat_sms": "ON",
            }
        )
        builder = scp80_builder.OtaPacketBuilder(config)

        plan = builder.build_plan()

        self.assertTrue(plan.is_concatenated)
        self.assertGreater(len(plan.apdus), 1)
        self.assertEqual(len(plan.reader_apdus), 1)
        self.assertIn("4005811250F341F6", plan.apdus[0].apdu_hex)
        with self.assertRaisesRegex(ValueError, "concatenated SMS"):
            builder.build()


class TransportTests(unittest.TestCase):
    def _make_transport(self, *, transport_mode: str = "reader") -> scp80_transport.Transport:
        transport = scp80_transport.Transport.__new__(scp80_transport.Transport)
        transport.cfg = DummyBuilderConfig({"transport": transport_mode, "reader_idx": "0"})
        transport.conn = None
        transport.active_protocol = None
        transport._stk_bootstrap_trace = []
        transport._stk_bootstrap_trace_printed = False
        return transport

    def test_decode_iccid_and_protocol_helpers(self) -> None:
        self.assertEqual(
            scp80_transport.Transport._decode_iccid_bytes(bytes.fromhex("981032547698103254F6")),
            "8901234567890123456",
        )
        self.assertFalse(scp80_transport.Transport._requires_extended_apdu("00A4040000"))
        self.assertEqual(
            scp80_transport.Transport._protocol_name(scp80_transport.CardConnection.T1_protocol),
            "T=1",
        )

    def test_get_protocol_summary_reads_atr_data(self) -> None:
        transport = self._make_transport()
        transport.conn = SimpleNamespace(getATR=lambda: [0x3B, 0x00])
        transport.active_protocol = scp80_transport.CardConnection.T1_protocol

        # ``PYSCRARD_AVAIL`` and ``ATR`` are bound at import time from the
        # ``smartcard`` package. Sibling SCP80 test files may install partial
        # stubs (missing ``smartcard.ATR``) before this module imports, which
        # leaves ``PYSCRARD_AVAIL=False`` and ``ATR=None`` cached on
        # ``SCP80.transport``. Force both flags to known values here so the
        # protocol-summary assertions do not depend on test ordering.
        with mock.patch.object(scp80_transport, "PYSCRARD_AVAIL", True), mock.patch.object(
            scp80_transport,
            "ATR",
            lambda data: SimpleNamespace(getSupportedProtocols=lambda: {"T=1": True, "raw": data}),
        ):
            summary = transport.get_protocol_summary()

        self.assertTrue(summary["available"])
        self.assertEqual(summary["atr_hex"], "3B00")
        self.assertTrue(summary["supports_t1"])
        self.assertEqual(summary["active_protocol"], "T=1")

    def test_recv_por_chains_fetches_until_terminal_status(self) -> None:
        transport = self._make_transport()
        calls: list[str] = []
        responses = iter(
            [
                (b"\xAA", 0x6102),
                (b"\xBB\xCC", 0x9000),
            ]
        )

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            calls.append(apdu_hex)
            return next(responses)

        transport.transmit = fake_transmit

        por = transport._recv_por(0x9101)

        self.assertEqual(por, b"\xAA\xBB\xCC")
        self.assertEqual(calls, ["8012000001", "00C0000002"])

    def test_decode_por_success_response_packet(self) -> None:
        por = bytes.fromhex(
            "D02E810301130082028183050086028001"
            "8B1D410005811250F341F613"
            "027100000E0AB00001000000FFFF0000019000"
        )

        decoded = scp80_transport.Transport.decode_por(por, 0x9130)

        self.assertTrue(decoded["valid"])
        self.assertEqual(decoded["status_code"], "00")
        self.assertEqual(decoded["status_meaning"], "PoR OK")
        self.assertEqual(decoded["tar"], "B00001")
        self.assertEqual(decoded["cntr"], "000000FFFF")
        self.assertEqual(decoded["pcntr"], "00")
        self.assertEqual(decoded["command_count"], 1)
        self.assertEqual(decoded["command_response"], "9000")
        self.assertEqual(decoded["command_sw"], "9000")
        self.assertEqual(decoded["fetch_sw"], "9130")

    def test_decode_por_error_response_packet(self) -> None:
        por = bytes.fromhex(
            "D02B810301130082028183050086028001"
            "8B1A410005811250F341F610"
            "027100000B0AB0000100000000000002"
        )

        decoded = scp80_transport.Transport.decode_por(por, "912D")

        self.assertTrue(decoded["valid"])
        self.assertEqual(decoded["status_code"], "02")
        self.assertEqual(decoded["status_meaning"], "CNTR low")
        self.assertEqual(decoded["tar"], "B00001")
        self.assertEqual(decoded["cntr"], "0000000000")
        self.assertEqual(decoded["pcntr"], "00")
        self.assertIsNone(decoded["command_count"])
        self.assertEqual(decoded["response_data"], "")
        self.assertEqual(decoded["fetch_sw"], "912D")

    def test_send_single_ota_apdu_reports_missing_por_on_plain_9000(self) -> None:
        transport = self._make_transport()
        calls: list[str] = []

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            calls.append(apdu_hex)
            return b"", 0x9000

        transport.transmit = fake_transmit

        result = transport._send_single_ota_apdu("80C2000000")

        self.assertTrue(result["delivered"])
        self.assertIn("No POR returned by card", str(result["error"]))
        self.assertEqual(calls, ["80C2000000"])

    def test_recv_por_acknowledges_fetched_send_short_message(self) -> None:
        transport = self._make_transport()
        calls: list[str] = []
        send_sms = bytes.fromhex(
            "D00C"
            "8103051300"
            "82028183"
            "8B0100"
        )

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            calls.append(apdu_hex)
            if apdu_hex.startswith("80120000"):
                return send_sms, 0x9000
            return b"", 0x9000

        transport.transmit = fake_transmit

        por = transport._recv_por(0x910E)

        self.assertEqual(por, send_sms)
        self.assertEqual(
            calls,
            [
                "801200000E",
                "801400000C810305130082028281030100",
            ],
        )

    def test_recv_por_does_not_ack_non_sms_proactive_command(self) -> None:
        transport = self._make_transport()
        calls: list[str] = []
        open_channel = bytes.fromhex(
            "D00C"
            "8103014003"
            "82028182"
            "350101"
        )

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            calls.append(apdu_hex)
            return open_channel, 0x9000

        transport.transmit = fake_transmit

        por = transport._recv_por(0x910E)

        self.assertEqual(por, open_channel)
        self.assertEqual(calls, ["801200000E"])

    def test_send_ota_sequence_print_mode_increments_counter(self) -> None:
        transport = self._make_transport(transport_mode="print")

        result = transport.send_ota_sequence(["A1B2", "C3D4"])

        self.assertTrue(result["delivered"])
        self.assertEqual(transport.cfg.increment_counter_calls, 1)

    def test_stk_bootstrap_closes_fetched_command_with_terminal_response(self) -> None:
        transport = self._make_transport()
        calls: list[str] = []
        display_text = bytes.fromhex(
            "D00D"
            "8103010500"
            "82028182"
            "8D020441"
        )

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            calls.append(apdu_hex)
            if len(calls) == 1:
                return b"", 0x910F
            if len(calls) == 2:
                return display_text, 0x9000
            return b"", 0x9000

        transport.transmit = fake_transmit

        transport._stk_bootstrap()

        self.assertEqual(
            calls,
            [
                "8010000015FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00",
                "801200000F",
                "801400000C810301050082028281030100",
            ],
        )
        self.assertFalse(transport._stk_bootstrap_trace_printed)
        self.assertEqual(
            [entry["label"] for entry in transport._stk_bootstrap_trace],
            ["TERMINAL PROFILE", "FETCH", "TERMINAL RESPONSE"],
        )

    def test_verbose_send_replays_silent_stk_bootstrap_trace_once(self) -> None:
        transport = self._make_transport(transport_mode="reader")
        transport._stk_bootstrap_trace = [
            {
                "label": "TERMINAL PROFILE",
                "apdu": "8010000001FF",
                "data": "",
                "sw": "9000",
            }
        ]
        transport._stk_bootstrap_trace_printed = False
        transmit_calls: list[str] = []

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            transmit_calls.append(apdu_hex)
            return b"\x01\x02", 0x9000

        transport._ensure_reader_protocol = lambda apdus, verbose=False: True
        transport.transmit = fake_transmit

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            result = transport.send_ota_sequence(["80C2000000"], verbose=True)

        self.assertTrue(result["delivered"])
        self.assertIn("[STK]", buffer.getvalue())
        self.assertIn("TERMINAL PROFILE", buffer.getvalue())
        self.assertTrue(transport._stk_bootstrap_trace_printed)
        self.assertEqual(transmit_calls, ["80C2000000"])

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            transport.send_ota_sequence(["80C2000000"], verbose=True)

        self.assertNotIn("[STK]", buffer.getvalue())

    def test_send_ota_sequence_reader_mode_reports_protocol_failure(self) -> None:
        transport = self._make_transport(transport_mode="reader")
        transport._ensure_reader_protocol = lambda apdus, verbose=False: False
        transport._requires_extended_apdu = lambda apdu_hex: True

        result = transport.send_ota_sequence(["AA" * 300])

        self.assertFalse(result["delivered"])
        self.assertIn("requires T=1", str(result["error"]))

    def test_send_ota_sequence_does_not_emit_fixed_me_response_after_por(self) -> None:
        transport = self._make_transport(transport_mode="reader")
        transmit_calls: list[tuple[str, dict]] = []

        def fake_transmit(apdu_hex: str, **kwargs):
            transmit_calls.append((apdu_hex, dict(kwargs)))
            return b"\x01\x02", 0x9000

        transport._ensure_reader_protocol = lambda apdus, verbose=False: True
        transport.transmit = fake_transmit

        result = transport.send_ota_sequence(["80C2000000"])

        self.assertTrue(result["delivered"])
        self.assertEqual(result["por"], "0102")
        self.assertEqual([call[0] for call in transmit_calls], ["80C2000000"])
        self.assertEqual(transport.cfg.increment_counter_calls, 1)

    def test_send_ota_sequence_surfaces_delivered_segment_warnings(self) -> None:
        transport = self._make_transport(transport_mode="reader")
        transmit_calls: list[str] = []

        def fake_transmit(apdu_hex: str, **kwargs):
            del kwargs
            transmit_calls.append(apdu_hex)
            return b"", 0x9000

        transport._ensure_reader_protocol = lambda apdus, verbose=False: True
        transport.transmit = fake_transmit

        result = transport.send_ota_sequence(["80C2000000"])

        self.assertTrue(result["delivered"])
        self.assertIn("No POR returned", str(result["error"]))
        self.assertEqual(transmit_calls, ["80C2000000"])


if __name__ == "__main__":
    unittest.main()
