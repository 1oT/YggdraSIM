# SPDX-License-Identifier: GPL-3.0-or-later
"""Focused SCP03 secure-messaging and transport choreography regressions."""

from __future__ import annotations

import hmac

import pytest
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from SCP03.crypto.session import (
    Scp03ApduFormatError,
    Scp03Error,
    Scp03ResponseProtectionError,
    Scp03Session,
    parse_command_apdu,
)
from SCP03.transport.card import (
    ApduTransportError,
    ApduTransportPolicy,
    CardTransporter,
)
from SIMCARD.scp03 import Scp03CardLogic
from SIMCARD.state import SimCardState, SimScp03Session


S_ENC = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
S_MAC = bytes.fromhex("102132435465768798A9BACBDCEDFE0F")
S_RMAC = bytes.fromhex("2031425364758697A8B9CADBECFD0E1F")
CHAIN = bytes.fromhex("00102030405060708090A0B0C0D0E0F0")


def _cmac(key: bytes, payload: bytes) -> bytes:
    calculator = cmac.CMAC(algorithms.AES(key))
    calculator.update(payload)
    return calculator.finalize()


def _sim_state() -> SimCardState:
    return SimCardState(
        atr=bytes(33),
        eid="8904903200000000000000000000000000",
        iccid="89882012345678901234",
        imsi="001010000000001",
        default_dp_address="smdp.example.test",
        root_ci_pkid=bytes(20),
    )


def _session(
    *,
    security_level: int = 0x33,
    channel: int = 0,
) -> Scp03Session:
    session = Scp03Session({"kenc": S_ENC, "kmac": S_MAC, "dek": S_ENC})
    session.s_enc = S_ENC
    session.s_mac = S_MAC
    session.s_rmac = S_RMAC
    session.i_parameter = 0x60
    session.sec_level = security_level
    session.chaining_value = CHAIN
    session.bind_logical_channel(channel)
    session.is_authenticated = True
    session.ssc = 1
    return session


def _protected_response(
    session: Scp03Session,
    payload: bytes,
    *,
    sw1: int = 0x90,
    sw2: int = 0x00,
    encrypt: bool = False,
) -> bytes:
    protected = payload
    if encrypt and payload:
        assert session.last_encryption_counter is not None
        iv_input = bytearray(session.last_encryption_counter.to_bytes(16, "big"))
        iv_input[0] = 0x80
        iv_cipher = Cipher(algorithms.AES(S_ENC), modes.ECB()).encryptor()
        iv = iv_cipher.update(bytes(iv_input)) + iv_cipher.finalize()
        padded = session._pad80(payload)
        encryptor = Cipher(algorithms.AES(S_ENC), modes.CBC(iv)).encryptor()
        protected = encryptor.update(padded) + encryptor.finalize()
    rmac = _cmac(
        S_RMAC,
        session.chaining_value + protected + bytes([sw1, sw2]),
    )[:8]
    return protected + rmac


def test_command_apdu_parser_covers_short_and_extended_cases() -> None:
    cases = {
        "00A40000": (1, False, b"", None),
        "00B0000000": (2, False, b"", 256),
        "00D6000002AABB": (3, False, b"\xAA\xBB", None),
        "00D6000002AABB10": (4, False, b"\xAA\xBB", 16),
        "00B00000000100": (2, True, b"", 256),
        "00DA0000000002AABB": (3, True, b"\xAA\xBB", None),
        "00DA0000000002AABB0100": (4, True, b"\xAA\xBB", 256),
    }
    for apdu_hex, expected in cases.items():
        parsed = parse_command_apdu(bytes.fromhex(apdu_hex))
        assert (parsed.case, parsed.extended, parsed.data, parsed.le) == expected


@pytest.mark.parametrize(
    "apdu_hex",
    [
        "00",
        "00D6000002AA",
        "00D6000001AABBCC",
        "00DA00000000",
        "00DA0000000002AA",
        "00DA0000000001AA00",
    ],
)
def test_command_apdu_parser_rejects_malformed_or_trailing_data(
    apdu_hex: str,
) -> None:
    with pytest.raises(Scp03ApduFormatError):
        parse_command_apdu(bytes.fromhex(apdu_hex))


def test_authenticated_extended_apdu_fails_before_state_changes() -> None:
    session = _session()
    chain_before = session.chaining_value
    counter_before = session.ssc

    with pytest.raises(Scp03ApduFormatError, match="Extended-length"):
        session.wrap_apdu(list(bytes.fromhex("80DA0000000002AABB")))

    assert session.chaining_value == chain_before
    assert session.ssc == counter_before


def test_initialize_update_i_parameter_and_sequence_counter_are_consistent() -> None:
    session = Scp03Session({"kenc": S_ENC, "kmac": S_MAC, "dek": S_ENC})
    pseudo_random_without_counter = (
        b"\x00" * 10
        + bytes.fromhex("300370")
        + b"\x00" * 16
    )
    with pytest.raises(Scp03Error, match="sequence-counter presence"):
        session.derive_keys(b"\x00" * 8, pseudo_random_without_counter)

    reserved_response_mode = (
        b"\x00" * 10
        + bytes.fromhex("300340")
        + b"\x00" * 16
    )
    with pytest.raises(Scp03Error, match="invalid SCP03 i parameter"):
        session.derive_keys(b"\x00" * 8, reserved_response_mode)


def test_secure_messaging_cmac_excludes_logical_channel_from_mac_header() -> None:
    session = _session(security_level=0x01, channel=1)
    wrapped = bytes(session.wrap_apdu(list(bytes.fromhex("81CA006600"))))

    expected_full = _cmac(
        S_MAC,
        CHAIN + bytes.fromhex("84CA006608"),
    )
    assert wrapped == bytes.fromhex("85CA006608") + expected_full[:8] + b"\x00"
    assert session.chaining_value == expected_full


def test_secure_messaging_uses_further_cla_coding_on_channel_four() -> None:
    session = _session(security_level=0x01, channel=4)
    wrapped = bytes(session.wrap_apdu(list(bytes.fromhex("C0CA006600"))))

    expected_full = _cmac(S_MAC, CHAIN + bytes.fromhex("84CA006608"))
    assert wrapped == bytes.fromhex("E0CA006608") + expected_full[:8] + b"\x00"


def test_secure_channel_rejects_cross_channel_command_without_mutating_state() -> None:
    session = _session(channel=0)
    chain_before = session.chaining_value
    counter_before = session.ssc

    with pytest.raises(Scp03Error, match="targets channel 1"):
        session.wrap_apdu(list(bytes.fromhex("81CA006600")))

    assert session.chaining_value == chain_before
    assert session.ssc == counter_before


def test_authenticated_no_sm_session_still_rejects_cross_channel_command() -> None:
    session = _session(security_level=0x00, channel=0)

    with pytest.raises(Scp03Error, match="targets channel 1"):
        session.wrap_apdu(list(bytes.fromhex("01A4000000")))

    assert session.wrap_apdu(list(bytes.fromhex("00A4000000"))) == list(
        bytes.fromhex("00A4000000")
    )


def test_first_cenc_command_uses_counter_one_even_without_ext_auth_wrapper() -> None:
    session = _session()
    session.ssc = 0
    wrapped = bytes(session.wrap_apdu(list(bytes.fromhex("80E2800003112233"))))

    iv_encryptor = Cipher(algorithms.AES(S_ENC), modes.ECB()).encryptor()
    iv = iv_encryptor.update((1).to_bytes(16, "big")) + iv_encryptor.finalize()
    payload_encryptor = Cipher(algorithms.AES(S_ENC), modes.CBC(iv)).encryptor()
    expected_ciphertext = (
        payload_encryptor.update(session._pad80(bytes.fromhex("112233")))
        + payload_encryptor.finalize()
    )
    assert wrapped[5:-8] == expected_ciphertext
    assert session.last_encryption_counter == 1
    assert session.ssc == 2


def test_rmac_only_response_is_verified_in_constant_time(monkeypatch) -> None:
    session = _session(security_level=0x11)
    session.last_cmd_header = bytes.fromhex("80CA0066")
    payload = bytes.fromhex("112233")
    response = _protected_response(session, payload)
    calls: list[tuple[bytes, bytes]] = []
    original_compare = hmac.compare_digest

    def recording_compare(left: bytes, right: bytes) -> bool:
        calls.append((bytes(left), bytes(right)))
        return original_compare(left, right)

    monkeypatch.setattr("SCP03.crypto.session.hmac.compare_digest", recording_compare)

    assert session.unwrap_response(response, 0x90, 0x00) == payload
    assert calls == [(response[-8:], response[-8:])]


def test_renc_is_decrypted_only_after_rmac_over_ciphertext() -> None:
    session = _session(security_level=0x33)
    session.last_cmd_header = bytes.fromhex("80CA0066")
    session.last_encryption_counter = 7
    payload = bytes.fromhex("DEADBEEF010203")
    response = _protected_response(session, payload, encrypt=True)

    assert session.unwrap_response(response, 0x90, 0x00) == payload


def test_tampered_or_missing_rmac_fails_closed_and_invalidates_session() -> None:
    session = _session(security_level=0x11)
    session.last_cmd_header = bytes.fromhex("80CA0066")
    valid = _protected_response(session, b"abc")

    with pytest.raises(Scp03ResponseProtectionError, match="R-MAC verification"):
        session.unwrap_response(valid[:-1] + bytes([valid[-1] ^ 1]), 0x90, 0x00)
    assert session.is_authenticated is False
    assert session.s_enc is None
    assert session.s_mac is None
    assert session.s_rmac is None

    session = _session(security_level=0x11)
    session.last_cmd_header = bytes.fromhex("80CA0066")
    with pytest.raises(Scp03ResponseProtectionError, match="missing"):
        session.unwrap_response(b"", 0x90, 0x00)
    assert session.is_authenticated is False


def test_empty_success_response_still_requires_and_accepts_rmac() -> None:
    session = _session(security_level=0x11)
    session.last_cmd_header = bytes.fromhex("80E60000")
    response = _protected_response(session, b"")

    assert len(response) == 8
    assert session.unwrap_response(response, 0x90, 0x00) == b""


def test_error_response_cannot_smuggle_unprotected_data() -> None:
    session = _session(security_level=0x11)
    session.last_cmd_header = bytes.fromhex("80CA0066")

    assert session.unwrap_response(b"", 0x6A, 0x82) == b""
    with pytest.raises(Scp03ResponseProtectionError, match="unprotected data"):
        session.unwrap_response(b"untrusted", 0x6A, 0x82)


class _ScriptedConnection:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.responses = list(responses)
        self.calls: list[bytes] = []

    def transmit(self, command: list[int]) -> tuple[bytes, int, int]:
        self.calls.append(bytes(command))
        return self.responses.pop(0)


class _FailingConnection:
    def transmit(self, _command: list[int]) -> tuple[bytes, int, int]:
        raise OSError("reader disconnected")


class _ResetConnection:
    def __init__(self, *, fail_connect: bool = False) -> None:
        self.fail_connect = fail_connect
        self.disconnect_calls = 0
        self.connect_calls = 0

    def disconnect(self) -> None:
        self.disconnect_calls += 1

    def connect(self) -> None:
        self.connect_calls += 1
        if self.fail_connect:
            raise OSError("reset failed")


class _RecordingSession:
    def __init__(self, *, fail_unwrap: bool = False) -> None:
        self.is_authenticated = True
        self.authenticated_channel = 0
        self.fail_unwrap = fail_unwrap
        self.plain_commands: list[bytes] = []
        self.unwrap_calls: list[tuple[bytes, int, int]] = []
        self.reset_calls = 0

    @staticmethod
    def logical_channel_from_cla(cla: int) -> int:
        return 4 + (cla & 0x0F) if cla & 0x40 else cla & 0x03

    def wrap_apdu(self, apdu: list[int]) -> list[int]:
        command = bytes(apdu)
        self.plain_commands.append(command)
        return list(command + bytes([0xE0, len(self.plain_commands)]))

    @staticmethod
    def response_requires_rmac(sw1: int, _sw2: int) -> bool:
        return sw1 == 0x90

    def unwrap_response(self, data: bytes, sw1: int, sw2: int) -> bytes:
        self.unwrap_calls.append((bytes(data), sw1, sw2))
        if self.fail_unwrap:
            raise Scp03ResponseProtectionError("synthetic verification failure")
        return bytes(data).lower()

    def reset_state(self) -> None:
        self.reset_calls += 1
        self.is_authenticated = False


def _transporter(connection: _ScriptedConnection, session: object) -> CardTransporter:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.connection = connection
    transporter.session = session
    return transporter


def test_transport_wraps_and_unwraps_every_6c_and_get_response_exchange() -> None:
    connection = _ScriptedConnection(
        [
            (b"", 0x6C, 0x02),
            (b"", 0x61, 0x03),
            (b"", 0x6C, 0x02),
            (b"", 0x61, 0x01),
            (b"Z", 0x90, 0x00),
        ]
    )
    session = _RecordingSession()
    transporter = _transporter(connection, session)

    result = transporter.transmit_detailed(
        "00B0000000",
        policy=ApduTransportPolicy(capture_apdu_bytes=True),
    )

    assert result.as_tuple() == (b"z", 0x90, 0x00)
    assert session.plain_commands == [
        bytes.fromhex("00B0000000"),
        bytes.fromhex("00B0000002"),
        bytes.fromhex("00C0000003"),
        bytes.fromhex("00C0000002"),
        bytes.fromhex("00C0000001"),
    ]
    assert len(connection.calls) == len(session.plain_commands) == 5
    assert len(session.unwrap_calls) == 5
    assert [entry.phase for entry in result.trace] == [
        "command",
        "correct-le",
        "get-response",
        "correct-le",
        "get-response",
    ]
    assert result.trace[-1].response_verified is True
    assert result.trace[0].command_hex == "00B0000000"


def test_get_response_cla_preserves_channels_zero_through_nineteen() -> None:
    assert CardTransporter._get_response_cla(0x80) == 0x00
    assert CardTransporter._get_response_cla(0x83) == 0x03
    assert CardTransporter._get_response_cla(0xC0) == 0x40
    assert CardTransporter._get_response_cla(0xCF) == 0x4F


def test_transport_policy_can_disable_6c_retry_without_bypassing_wrapper() -> None:
    connection = _ScriptedConnection([(b"", 0x6C, 0x10)])
    session = _RecordingSession()
    transporter = _transporter(connection, session)

    result = transporter.transmit_detailed(
        "00B0000000",
        policy=ApduTransportPolicy(retry_wrong_length=False),
    )

    assert result.as_tuple() == (b"", 0x6C, 0x10)
    assert session.plain_commands == [bytes.fromhex("00B0000000")]
    assert len(session.unwrap_calls) == 1


def test_transport_policy_can_disable_get_response_without_bypassing_wrapper() -> None:
    connection = _ScriptedConnection([(b"PART", 0x61, 0x10)])
    session = _RecordingSession()
    transporter = _transporter(connection, session)

    result = transporter.transmit_detailed(
        "00B0000000",
        policy=ApduTransportPolicy(follow_response_data=False),
    )

    assert result.as_tuple() == (b"part", 0x61, 0x10)
    assert session.plain_commands == [bytes.fromhex("00B0000000")]
    assert len(session.unwrap_calls) == 1


def test_transport_maps_verification_failure_without_returning_wire_data() -> None:
    connection = _ScriptedConnection([(b"UNVERIFIED", 0x90, 0x00)])
    session = _RecordingSession(fail_unwrap=True)
    transporter = _transporter(connection, session)

    assert transporter.transmit("80CA006600", silent=True) == (b"", 0x6F, 0x00)
    assert transporter.last_error == "synthetic verification failure"
    assert transporter.last_trace[0].response_verified is False
    assert session.reset_calls == 1

    connection = _ScriptedConnection([(b"UNVERIFIED", 0x90, 0x00)])
    session = _RecordingSession(fail_unwrap=True)
    transporter = _transporter(connection, session)
    with pytest.raises(ApduTransportError) as caught:
        transporter.transmit_detailed("80CA006600")
    assert caught.value.cause_type == "Scp03ResponseProtectionError"


def test_transport_failure_after_wrapping_invalidates_uncertain_session() -> None:
    session = _RecordingSession()
    transporter = _transporter(_FailingConnection(), session)

    with pytest.raises(ApduTransportError, match="reader disconnected"):
        transporter.transmit_detailed("80CA006600")

    assert session.reset_calls == 1
    assert session.is_authenticated is False


@pytest.mark.parametrize(
    ("fail_connect", "expected_result"),
    [(False, True), (True, False)],
)
def test_physical_reset_always_invalidates_secure_session(
    fail_connect: bool,
    expected_result: bool,
) -> None:
    connection = _ResetConnection(fail_connect=fail_connect)
    session = _RecordingSession()
    transporter = CardTransporter.__new__(CardTransporter)
    transporter._connection = connection
    transporter.session = session

    assert transporter.reset() is expected_result
    assert session.reset_calls == 1
    assert session.is_authenticated is False
    assert connection.disconnect_calls == 1
    assert connection.connect_calls == 1


def test_replacing_underlying_connection_invalidates_secure_session() -> None:
    session = _RecordingSession()
    transporter = CardTransporter.__new__(CardTransporter)
    transporter._connection = object()
    transporter.session = session

    replacement = object()
    transporter.connection = replacement

    assert transporter.connection is replacement
    assert session.reset_calls == 1
    assert session.is_authenticated is False


@pytest.mark.parametrize("factory_fails", [False, True])
def test_connect_attempt_invalidates_existing_secure_session(
    monkeypatch,
    factory_fails: bool,
) -> None:
    session = _RecordingSession()
    transporter = CardTransporter.__new__(CardTransporter)
    transporter._connection = object()
    transporter.session = session

    def connection_factory(*_args, **_kwargs):
        if factory_fails:
            raise OSError("reader unavailable")
        return object()

    monkeypatch.setattr(
        "SCP03.transport.card.create_card_connection",
        connection_factory,
    )

    assert transporter.connect() is (not factory_fails)
    assert session.reset_calls >= 1
    assert session.is_authenticated is False


def test_secure_messaging_status_invalidates_session_with_result_metadata() -> None:
    connection = _ScriptedConnection([(b"", 0x69, 0x88)])
    session = _RecordingSession()
    transporter = _transporter(connection, session)

    result = transporter.transmit_detailed("80CA006600")

    assert result.as_tuple() == (b"", 0x69, 0x88)
    assert result.session_invalidated is True
    assert "6988" in (result.invalidation_reason or "")
    assert session.reset_calls == 1


def test_successful_select_on_bound_channel_invalidates_session() -> None:
    connection = _ScriptedConnection([(b"FCP", 0x90, 0x00)])
    session = _RecordingSession()
    transporter = _transporter(connection, session)

    result = transporter.transmit_detailed("00A4040000")

    assert result.session_invalidated is True
    assert "re-authentication" in (result.invalidation_reason or "")
    assert session.reset_calls == 1
    assert session.is_authenticated is False


def test_select_on_another_channel_does_not_invalidate_bound_session() -> None:
    connection = _ScriptedConnection([(b"FCP", 0x90, 0x00)])
    session = _RecordingSession()
    transporter = _transporter(connection, session)

    result = transporter.transmit_detailed("01A4040000")

    assert result.session_invalidated is False
    assert session.reset_calls == 0
    assert session.is_authenticated is True


def test_simulator_emits_rmac_for_empty_success_response() -> None:
    state = _sim_state()
    state.scp03_session = SimScp03Session(
        authenticated=True,
        security_level=0x11,
        chaining_value=CHAIN,
        ssc=2,
    )
    logic = Scp03CardLogic(state)
    logic._session_keys = {"s_enc": S_ENC, "s_mac": S_MAC, "s_rmac": S_RMAC}

    response = logic.wrap_response(b"", 0x90, 0x00)

    assert response == _cmac(S_RMAC, CHAIN + b"\x90\x00")[:8]
    assert logic.wrap_response(b"must-not-leak", 0x6A, 0x82) == b""


def test_simulator_advertises_its_rmac_and_renc_capabilities() -> None:
    logic = Scp03CardLogic(_sim_state())

    response, sw1, sw2 = logic.handle_initialize_update(0, b"\x01" * 8)

    assert (sw1, sw2) == (0x90, 0x00)
    assert response[11:13] == bytes.fromhex("0360")
    assert len(response) == 29


def test_simulator_terminates_secure_channel_after_bound_select_response() -> None:
    state = _sim_state()
    state.scp03_session = SimScp03Session(
        authenticated=True,
        security_level=0x11,
        chaining_value=CHAIN,
        ssc=2,
    )
    logic = Scp03CardLogic(state)
    logic._session_keys = {"s_enc": S_ENC, "s_mac": S_MAC, "s_rmac": S_RMAC}
    logic._authenticated_channel = 0
    logic._last_command_ins = 0xA4
    logic._last_command_channel = 0

    wire_response = logic.wrap_response(b"FCP", 0x90, 0x00)

    assert wire_response == (
        b"FCP" + _cmac(S_RMAC, CHAIN + b"FCP\x90\x00")[:8]
    )
    assert state.scp03_session.authenticated is False
    assert logic._session_keys == {}


def test_simulator_renc_response_round_trips_through_host_verifier() -> None:
    state = _sim_state()
    state.scp03_session = SimScp03Session(
        authenticated=True,
        security_level=0x33,
        chaining_value=CHAIN,
        ssc=8,
    )
    logic = Scp03CardLogic(state)
    logic._session_keys = {"s_enc": S_ENC, "s_mac": S_MAC, "s_rmac": S_RMAC}
    plaintext = b"simulated response"
    wire_response = logic.wrap_response(plaintext, 0x90, 0x00)

    host = _session(security_level=0x33)
    host.last_cmd_header = bytes.fromhex("80CA0066")
    host.last_encryption_counter = 7

    assert host.unwrap_response(wire_response, 0x90, 0x00) == plaintext
