from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from SIMCARD.auth import build_milenage_autn
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from SIMCARD.profile_store import load_profiles_from_store, sync_profiles_to_store
from SIMCARD.toolkit import CLOSE_CHANNEL_COMMAND, OPEN_CHANNEL_COMMAND, RECEIVE_DATA_COMMAND, SEND_DATA_COMMAND
from SIMCARD.utils import read_tlv, tlv
from SCP03.logic.security import AUTH_TEST_VECTOR


def _kc_from_expected_vectors() -> bytes:
    ck = bytes.fromhex(AUTH_TEST_VECTOR["CK"])
    ik = bytes.fromhex(AUTH_TEST_VECTOR["IK"])
    return bytes(
        left ^ right ^ third ^ fourth
        for left, right, third, fourth in zip(ck[:8], ck[8:], ik[:8], ik[8:])
    )


def _sres_from_expected_vectors() -> bytes:
    # c2 conversion per TS 33.102 Annex B.3: SRES = RES[0..31] XOR RES[32..63].
    res = bytes.fromhex(AUTH_TEST_VECTOR["RES"])
    return bytes(left ^ right for left, right in zip(res[:4], res[4:8]))


def _auth_payload(rand_hex: str, autn: bytes) -> bytes:
    rand = bytes.fromhex(rand_hex)
    return bytes((0x10,)) + rand + bytes((0x10,)) + bytes(autn)


def _fetch_command_details(fetch_data: bytes) -> tuple[int, int, int]:
    root_tag, root_value, _raw_tlv, _next_offset = read_tlv(fetch_data, 0)
    if root_tag != b"\xD0":
        raise AssertionError("Expected proactive command D0 envelope.")
    tag_bytes, value_bytes, _command_tlv, _command_next = read_tlv(root_value, 0)
    if tag_bytes not in (b"\x01", b"\x81"):
        raise AssertionError("Expected proactive command details TLV.")
    if len(value_bytes) != 3:
        raise AssertionError("Expected 3-byte command details value.")
    return value_bytes[0], value_bytes[1], value_bytes[2]


def _terminal_response_payload(fetch_data: bytes, *, result: int = 0x00, extra_tlvs: bytes = b"") -> bytes:
    command_number, command_type, qualifier = _fetch_command_details(fetch_data)
    return (
        tlv("81", bytes((command_number, command_type, qualifier)))
        + tlv("82", bytes.fromhex("8281"))
        + tlv("03", bytes((result & 0xFF,)))
        + bytes(extra_tlvs or b"")
    )


def _terminal_response_apdu(fetch_data: bytes, *, result: int = 0x00, extra_tlvs: bytes = b"") -> bytes:
    payload = _terminal_response_payload(fetch_data, result=result, extra_tlvs=extra_tlvs)
    return bytes([0x80, 0x14, 0x00, 0x00, len(payload)]) + payload


def _envelope_apdu(body: bytes) -> bytes:
    return bytes([0x80, 0xC2, 0x00, 0x00, len(body)]) + bytes(body)


def _location_status_envelope(location_information: bytes = bytes.fromhex("000101")) -> bytes:
    body = (
        tlv("99", b"\x03")
        + tlv("82", bytes.fromhex("8281"))
        + tlv("9B", b"\x00")
        + tlv("93", bytes(location_information))
    )
    return tlv("D6", body)


def _data_available_envelope(available_length: int) -> bytes:
    body = (
        tlv("99", b"\x09")
        + tlv("82", bytes.fromhex("8281"))
        + tlv("38", bytes.fromhex("8100"))
        + tlv("37", bytes((min(max(int(available_length), 1), 0xFF),)))
    )
    return tlv("D6", body)


def _extract_channel_data(fetch_data: bytes) -> bytes:
    root_tag, root_value, _raw_tlv, _next_offset = read_tlv(fetch_data, 0)
    if root_tag != b"\xD0":
        raise AssertionError("Expected proactive command D0 envelope.")
    offset = 0
    while offset < len(root_value):
        tag_bytes, value_bytes, _raw_tlv, offset = read_tlv(root_value, offset)
        if tag_bytes == b"\x36":
            return value_bytes
    return b""


def _build_dns_response(query: bytes, answer_ip: str) -> bytes:
    header = bytearray(query[:12])
    header[2] = 0x81
    header[3] = 0x80
    header[6:8] = (1).to_bytes(2, "big", signed=False)
    header[8:10] = (0).to_bytes(2, "big", signed=False)
    header[10:12] = (0).to_bytes(2, "big", signed=False)
    question = query[12:]
    answer_bytes = bytes(int(part) & 0xFF for part in answer_ip.split("."))
    answer = (
        bytes.fromhex("C00C")
        + bytes.fromhex("0001")
        + bytes.fromhex("0001")
        + (60).to_bytes(4, "big", signed=False)
        + bytes.fromhex("0004")
        + answer_bytes
    )
    return bytes(header) + question + answer


class SimCardAuthAndToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_root = Path(self._temp_dir.name)
        self.engine = SimulatedSimCardEngine(
            quirks_path=str(temp_root / "missing_quirks.py"),
            isdr_config_path=str(temp_root / "missing_isdr.json"),
            sim_eim_identity_path=str(temp_root / "missing_eim_identity.json"),
            euicc_store_root=str(temp_root / "euicc_store"),
            profile_store_path=str(temp_root / "profile_store"),
        )

    def tearDown(self) -> None:
        self._temp_dir.cleanup()

    def _drain_bootstrap(self) -> list[bytes]:
        proactive_commands: list[bytes] = []
        _data, sw1, sw2 = self.engine.transmit(bytes.fromhex("8010000001FF"))
        self.assertEqual(sw1, 0x91)
        while True:
            fetch_data, fetch_sw1, fetch_sw2 = self.engine.transmit(bytes([0x80, 0x12, 0x00, 0x00, sw2]))
            self.assertEqual((fetch_sw1, fetch_sw2), (0x90, 0x00))
            proactive_commands.append(fetch_data)
            _response_data, sw1, sw2 = self.engine.transmit(_terminal_response_apdu(fetch_data))
            if sw1 == 0x91:
                continue
            self.assertEqual((sw1, sw2), (0x90, 0x00))
            break
        return proactive_commands

    def test_default_profile_usim_auth_uses_milenage_vector(self) -> None:
        select_data, select_sw1, select_sw2 = self.engine.transmit(
            bytes.fromhex(f"00A4040010{USIM_AID}")
        )
        self.assertTrue(select_data.startswith(bytes.fromhex("62")))
        self.assertEqual((select_sw1, select_sw2), (0x90, 0x00))

        config = self.engine.state.profiles[0].auth_config
        self.assertIsNotNone(config)
        assert config is not None
        autn = build_milenage_autn(
            bytes(config.ki),
            bytes(config.opc),
            bytes.fromhex(AUTH_TEST_VECTOR["RAND"]),
            bytes(config.sqn),
            bytes(config.amf),
        )
        data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00880081")
            + bytes((len(_auth_payload(AUTH_TEST_VECTOR["RAND"], autn)),))
            + _auth_payload(AUTH_TEST_VECTOR["RAND"], autn)
        )

        expected = (
            b"\xDB\x08"
            + bytes.fromhex(AUTH_TEST_VECTOR["RES"])
            + b"\x10"
            + bytes.fromhex(AUTH_TEST_VECTOR["CK"])
            + b"\x10"
            + bytes.fromhex(AUTH_TEST_VECTOR["IK"])
            + b"\x08"
            + _kc_from_expected_vectors()
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, expected)

    def test_usim_auth_rejects_bad_mac(self) -> None:
        self.engine.transmit(bytes.fromhex(f"00A4040010{USIM_AID}"))
        config = self.engine.state.profiles[0].auth_config
        self.assertIsNotNone(config)
        assert config is not None
        autn = bytearray(
            build_milenage_autn(
                bytes(config.ki),
                bytes(config.opc),
                bytes.fromhex(AUTH_TEST_VECTOR["RAND"]),
                bytes(config.sqn),
                bytes(config.amf),
            )
        )
        autn[-1] ^= 0xFF
        data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex("00880081")
            + bytes((len(_auth_payload(AUTH_TEST_VECTOR["RAND"], bytes(autn))),))
            + _auth_payload(AUTH_TEST_VECTOR["RAND"], bytes(autn))
        )
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x98, 0x62))

    def test_run_gsm_algorithm_returns_sres_and_kc(self) -> None:
        data, sw1, sw2 = self.engine.transmit(
            bytes.fromhex(f"0088008010{AUTH_TEST_VECTOR['RAND']}")
        )
        self.assertEqual((sw1, sw2), (0x90, 0x00))
        self.assertEqual(data, _sres_from_expected_vectors() + _kc_from_expected_vectors())

    def test_terminal_profile_bootstrap_drains_profile_driven_queue(self) -> None:
        proactive_commands = self._drain_bootstrap()

        self.assertGreaterEqual(len(proactive_commands), 3)
        self.assertIn(bytes.fromhex("8103012601"), proactive_commands[0])
        self.assertTrue(any(bytes.fromhex("8103") in command and bytes((0x25,)) in command for command in proactive_commands))
        self.assertTrue(any(bytes.fromhex("990403090A12") in command for command in proactive_commands))

    def test_status_fetch_keeps_active_proactive_command_until_terminal_response(self) -> None:
        _data, profile_sw1, profile_sw2 = self.engine.transmit(bytes.fromhex("8010000001FF"))
        self.assertEqual(profile_sw1, 0x91)
        self.assertGreater(profile_sw2, 0)

        status_data, status_sw1, status_sw2 = self.engine.transmit(bytes.fromhex("80F2000000"))
        self.assertEqual(status_data, b"")
        self.assertEqual(status_sw1, 0x91)
        self.assertEqual(status_sw2, profile_sw2)

        fetch_data, fetch_sw1, fetch_sw2 = self.engine.transmit(bytes([0x80, 0x12, 0x00, 0x00, status_sw2]))
        self.assertEqual((fetch_sw1, fetch_sw2), (0x90, 0x00))

        repeated_status_data, repeated_status_sw1, repeated_status_sw2 = self.engine.transmit(bytes.fromhex("80F2000000"))
        self.assertEqual(repeated_status_data, b"")
        self.assertEqual(repeated_status_sw1, 0x91)
        self.assertEqual(repeated_status_sw2, len(fetch_data))

        _response_data, response_sw1, response_sw2 = self.engine.transmit(_terminal_response_apdu(fetch_data))
        self.assertEqual(response_sw1, 0x91)
        self.assertGreater(response_sw2, 0)

    def test_location_status_triggers_bip_dns_bootstrap_and_tcp_follow_up(self) -> None:
        self._drain_bootstrap()

        envelope_data, envelope_sw1, envelope_sw2 = self.engine.transmit(
            _envelope_apdu(_location_status_envelope())
        )
        self.assertEqual(envelope_data, b"")
        self.assertEqual(envelope_sw1, 0x91)
        self.assertGreater(envelope_sw2, 0)

        open_command_data, open_command_sw1, open_command_sw2 = self.engine.transmit(
            bytes([0x80, 0x12, 0x00, 0x00, envelope_sw2])
        )
        self.assertEqual((open_command_sw1, open_command_sw2), (0x90, 0x00))
        open_number, open_type, open_qualifier = _fetch_command_details(open_command_data)
        self.assertEqual(open_number, 5)
        self.assertEqual(open_type, OPEN_CHANNEL_COMMAND)
        self.assertEqual(open_qualifier, 0x00)
        self.assertIn(bytes.fromhex("3C03010035"), open_command_data)
        self.assertIn(bytes.fromhex("3E052108080808"), open_command_data)

        _open_response_data, open_response_sw1, open_response_sw2 = self.engine.transmit(
            _terminal_response_apdu(open_command_data)
        )
        self.assertEqual(open_response_sw1, 0x91)
        self.assertGreater(open_response_sw2, 0)

        send_command_data, send_command_sw1, send_command_sw2 = self.engine.transmit(
            bytes([0x80, 0x12, 0x00, 0x00, open_response_sw2])
        )
        self.assertEqual((send_command_sw1, send_command_sw2), (0x90, 0x00))
        _send_number, send_type, send_qualifier = _fetch_command_details(send_command_data)
        self.assertEqual(send_type, SEND_DATA_COMMAND)
        self.assertEqual(send_qualifier, 0x00)

        dns_query = _extract_channel_data(send_command_data)
        self.assertGreater(len(dns_query), 12)
        self.assertIn(b"yggdrasim", dns_query)
        self.assertIn(b"1ot", dns_query)

        send_response_apdu = _terminal_response_apdu(
            send_command_data,
            extra_tlvs=tlv("37", bytes((min(len(dns_query), 0xFF),))),
        )
        _send_response_data, send_response_sw1, send_response_sw2 = self.engine.transmit(send_response_apdu)
        self.assertEqual((_send_response_data, send_response_sw1, send_response_sw2), (b"", 0x90, 0x00))

        dns_response = _build_dns_response(dns_query, "194.29.54.4")
        data_available_data, data_available_sw1, data_available_sw2 = self.engine.transmit(
            _envelope_apdu(_data_available_envelope(len(dns_response)))
        )
        self.assertEqual(data_available_data, b"")
        self.assertEqual(data_available_sw1, 0x91)
        self.assertGreater(data_available_sw2, 0)

        receive_command_data, receive_command_sw1, receive_command_sw2 = self.engine.transmit(
            bytes([0x80, 0x12, 0x00, 0x00, data_available_sw2])
        )
        self.assertEqual((receive_command_sw1, receive_command_sw2), (0x90, 0x00))
        _receive_number, receive_type, receive_qualifier = _fetch_command_details(receive_command_data)
        self.assertEqual(receive_type, RECEIVE_DATA_COMMAND)
        self.assertEqual(receive_qualifier, 0x00)

        receive_response_apdu = _terminal_response_apdu(
            receive_command_data,
            extra_tlvs=tlv("36", dns_response) + tlv("37", b"\x00"),
        )
        _receive_response_data, receive_response_sw1, receive_response_sw2 = self.engine.transmit(
            receive_response_apdu
        )
        self.assertEqual(receive_response_sw1, 0x91)
        self.assertGreater(receive_response_sw2, 0)

        close_command_data, close_command_sw1, close_command_sw2 = self.engine.transmit(
            bytes([0x80, 0x12, 0x00, 0x00, receive_response_sw2])
        )
        self.assertEqual((close_command_sw1, close_command_sw2), (0x90, 0x00))
        _close_number, close_type, close_qualifier = _fetch_command_details(close_command_data)
        self.assertEqual(close_type, CLOSE_CHANNEL_COMMAND)
        self.assertEqual(close_qualifier, 0x00)

        _close_response_data, close_response_sw1, close_response_sw2 = self.engine.transmit(
            _terminal_response_apdu(close_command_data)
        )
        self.assertEqual(close_response_sw1, 0x91)
        self.assertGreater(close_response_sw2, 0)

        tcp_open_command_data, tcp_open_command_sw1, tcp_open_command_sw2 = self.engine.transmit(
            bytes([0x80, 0x12, 0x00, 0x00, close_response_sw2])
        )
        self.assertEqual((tcp_open_command_sw1, tcp_open_command_sw2), (0x90, 0x00))
        _tcp_open_number, tcp_open_type, tcp_open_qualifier = _fetch_command_details(tcp_open_command_data)
        self.assertEqual(tcp_open_type, OPEN_CHANNEL_COMMAND)
        self.assertEqual(tcp_open_qualifier, 0x00)
        self.assertIn(bytes.fromhex("3C030201BB"), tcp_open_command_data)
        self.assertIn(bytes.fromhex("3E0521C21D3604"), tcp_open_command_data)

    def test_verify_and_unblock_queries_use_stateful_retry_counters(self) -> None:
        self.engine.state.chv_references[0x01].enabled = True
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0020000100"))
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x63, 0xC3))

        wrong_pin = b"1111" + (b"\xFF" * 4)
        data, sw1, sw2 = self.engine.transmit(bytes([0x00, 0x20, 0x00, 0x01, 0x08]) + wrong_pin)
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x63, 0xC2))

        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("002C000100"))
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x63, 0xCA))

    def test_default_pin_status_probe_does_not_block_headless_attach(self) -> None:
        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0020000100"))
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

        data, sw1, sw2 = self.engine.transmit(bytes.fromhex("0020008100"))
        self.assertEqual(data, b"")
        self.assertEqual((sw1, sw2), (0x90, 0x00))

    def test_profile_store_round_trip_preserves_auth_config(self) -> None:
        store_path = Path(self._temp_dir.name) / "profile_store_roundtrip"
        sync_profiles_to_store(str(store_path), self.engine.state.profiles)
        loaded = load_profiles_from_store(str(store_path))
        self.assertGreaterEqual(len(loaded), 1)
        self.assertIsNotNone(loaded[0].auth_config)
        assert loaded[0].auth_config is not None
        self.assertEqual(loaded[0].auth_config.algorithm, "milenage")
        self.assertEqual(
            bytes(loaded[0].auth_config.ki).hex().upper(),
            AUTH_TEST_VECTOR["Ki"],
        )
        self.assertEqual(
            bytes(loaded[0].auth_config.opc).hex().upper(),
            AUTH_TEST_VECTOR["OPc"],
        )


if __name__ == "__main__":
    unittest.main()
