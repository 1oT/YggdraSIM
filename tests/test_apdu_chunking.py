# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Block chaining for command APDUs whose data field exceeds a one-byte Lc.

The block geometry pinned here was read off an observed AddInitialEim
transfer: a 950-byte 'BF57' request leaving the host as 255 / 255 / 255 / 185
bytes with P1 '11' on every block but the last. The payload below is
synthetic filler of the same length -- no operator identifier from the
observed transfer reaches a tracked file.
"""

from __future__ import annotations

import pytest

from SCP03.interface.shell import ShellDispatcher
from yggdrasim_common.apdu_chunking import (
    MAX_SHORT_APDU_DATA,
    cla_for_logical_channel,
    is_complete_ber_tlv,
    logical_channel_from_cla,
    plan_chunked_apdus,
    plan_oversized_command,
)

#: SGP.32 v1.3 AddInitialEim request tag, long-form length '82 03 B1' = 945
#: value bytes (ITU-T X.690 §8.1.3.5), so 950 bytes in total.
ADD_INITIAL_EIM_VALUE_LENGTH = 945
PAYLOAD = (
    bytes.fromhex("BF578203B1")
    + bytes((index * 7 + 0x11) & 0xFF for index in range(ADD_INITIAL_EIM_VALUE_LENGTH))
)

#: SGP.22 v3.1 §5.7.2 Table 47 on logical channel 1 (TS 102 221 v18.4 §10.1.1).
EXPECTED_HEADERS = ["81E21100FF", "81E21101FF", "81E21102FF", "81E29103B9"]


def _headers(plan) -> list[str]:
    return [chunk.apdu_hex[:10] for chunk in plan]


def test_payload_geometry_matches_the_observed_transfer() -> None:
    assert len(PAYLOAD) == 950
    assert is_complete_ber_tlv(PAYLOAD) is True


@pytest.mark.parametrize(
    "line",
    [
        PAYLOAD,
        bytes.fromhex("81E29100") + PAYLOAD,
        bytes.fromhex("81E29100") + b"\x00" + len(PAYLOAD).to_bytes(2, "big") + PAYLOAD,
    ],
    ids=["bare-tlv", "header-plus-raw", "extended-lc"],
)
def test_every_input_shape_yields_the_same_block_sequence(line: bytes) -> None:
    plan = plan_oversized_command(line, default_cla=cla_for_logical_channel(1))

    assert _headers(plan) == EXPECTED_HEADERS
    assert [len(chunk.data) for chunk in plan] == [255, 255, 255, 185]
    assert b"".join(chunk.data for chunk in plan) == PAYLOAD
    # SGP.22 v3.1 §5.7.2 collects a longer response through the '61xx' chain,
    # so no block carries a trailing Le.
    assert [len(chunk.apdu) for chunk in plan] == [260, 260, 260, 190]


def test_blocks_split_by_size_and_not_on_tlv_boundaries() -> None:
    # SGP.22 v3.1 §2.5.5 sends "blocks of 255 bytes for the first blocks and
    # a last block that MAY be shorter"; only LoadBoundProfilePackage
    # (§5.7.6) additionally aligns a block to the BPP's own TLV boundaries.
    plan = plan_chunked_apdus(PAYLOAD, cla=0x81)

    assert [len(chunk.data) for chunk in plan] == [255, 255, 255, 185]
    assert plan[0].data == PAYLOAD[:255]
    assert plan[1].data == PAYLOAD[255:510]


@pytest.mark.parametrize(
    "line",
    [
        bytes.fromhex("80E2910003BF2B00"),
        bytes.fromhex("80E29100FF") + bytes(255),
        bytes.fromhex("80E29100FF") + bytes(255) + b"\x00",
        bytes.fromhex("00A40004023F00"),
    ],
    ids=["short-case-3", "full-255-block", "full-255-case-4", "select"],
)
def test_a_command_that_already_fits_is_left_alone(line: bytes) -> None:
    assert plan_oversized_command(line) is None


def test_an_instruction_without_block_chaining_is_never_fragmented() -> None:
    # Only STORE DATA and LOAD number their blocks in P1/P2 (GPC v2.3.1
    # Tables 11-57 and 11-89). An extended-length UPDATE BINARY still reaches
    # a card that declared support for one (TS 102 221 v18.4 §10.1.3).
    extended_update = bytes.fromhex("00D6000000") + b"\x02\x00" + bytes(512)

    assert plan_oversized_command(extended_update) is None


def test_a_multi_byte_tlv_tag_is_not_mistaken_for_a_command_header() -> None:
    # 'BF E2 71' is one three-byte tag: X.690 §8.1.2.4.2 continues while b8
    # is set, and 'BF' is no command class (GPC v2.3.1 Table 11-88), so the
    # 'E2' inside it must not be read as STORE DATA.
    tagged = bytes.fromhex("BFE271820190") + bytes(400)
    assert is_complete_ber_tlv(tagged) is True

    plan = plan_oversized_command(tagged, default_cla=0x80)

    # 3-byte tag + 3-byte length + 400 value bytes = 406, so 255 + 151.
    assert _headers(plan) == ["80E21100FF", "80E2910197"]
    assert b"".join(chunk.data for chunk in plan) == tagged


def test_block_numbers_run_sequentially_and_wrap_at_ff() -> None:
    # GPC v2.3.1 §11.6.2.2: P2 is "coded sequentially from '00' to 'FF'".
    plan = plan_chunked_apdus(bytes(255 * 258), chunk_size=255)

    assert len(plan) == 258
    assert plan[0].p2 == 0x00
    assert plan[255].p2 == 0xFF
    assert plan[256].p2 == 0x00


def test_p1_carries_the_data_field_bits_across_the_more_blocks_flag() -> None:
    # Table 11-89 splits P1 into b8 (more / last) and the data-structure bits
    # below it, so clearing b8 must leave the rest of the byte untouched.
    es10x = plan_chunked_apdus(bytes(300), p1_last=0x91)
    assert (es10x[0].p1, es10x[-1].p1) == (0x11, 0x91)

    update_metadata = plan_chunked_apdus(bytes(300), p1_last=0x90)
    assert (update_metadata[0].p1, update_metadata[-1].p1) == (0x10, 0x90)

    generic = plan_chunked_apdus(bytes(300), p1_last=0x80)
    assert (generic[0].p1, generic[-1].p1) == (0x00, 0x80)


def test_generic_globalplatform_store_data_coding_is_unchanged() -> None:
    plan = plan_chunked_apdus(
        bytes.fromhex("AB") * 300, cla=0x80, ins=0xE2, p1_last=0x80, chunk_size=240
    )

    assert _headers(plan) == ["80E20000F0", "80E280013C"]
    assert [len(chunk.apdu) for chunk in plan] == [245, 65]


def test_le_is_appended_only_when_a_caller_asks_for_it() -> None:
    # GPC v2.3.1 Table 11-88 calls for Le '00' when P1.b1 flags ISO case 4.
    plan = plan_chunked_apdus(bytes(300), p1_last=0x91, le=0x00)

    assert plan[0].apdu[-1] == 0x00
    assert [len(chunk.apdu) for chunk in plan] == [261, 51]


@pytest.mark.parametrize("size", [0, -1, 256])
def test_a_chunk_size_outside_the_short_apdu_range_is_refused(size: int) -> None:
    with pytest.raises(ValueError, match="short-APDU range"):
        plan_chunked_apdus(PAYLOAD, chunk_size=size)


def test_logical_channel_round_trips_through_the_class_byte() -> None:
    # TS 102 221 v18.4 §10.1.1: channels 0-3 in b2b1, 4-19 in the b7 = 1 form.
    assert [f"{cla_for_logical_channel(n):02X}" for n in (0, 1, 3, 4, 19)] == [
        "80",
        "81",
        "83",
        "C0",
        "CF",
    ]
    for channel in range(20):
        assert logical_channel_from_cla(cla_for_logical_channel(channel)) == channel

    with pytest.raises(ValueError, match="outside the range"):
        cla_for_logical_channel(20)


def test_incomplete_or_trailing_bytes_are_not_a_complete_tlv() -> None:
    assert is_complete_ber_tlv(PAYLOAD + b"\x00") is False
    assert is_complete_ber_tlv(PAYLOAD[:-1]) is False
    assert is_complete_ber_tlv(b"") is False
    assert is_complete_ber_tlv(b"\x80") is False
    # An indefinite length never reaches a card command.
    assert is_complete_ber_tlv(bytes.fromhex("A480") + bytes(4)) is False


class _RecordingTransport:
    """Card stand-in recording every APDU the shell hands it."""

    def __init__(self, statuses: list[tuple[int, int]] | None = None) -> None:
        self.sent: list[str] = []
        self.statuses = list(statuses or [])

    def transmit(self, apdu_hex: str, silent: bool = False) -> tuple[bytes, int, int]:
        self.sent.append(apdu_hex)
        if len(self.statuses) > 0:
            sw1, sw2 = self.statuses.pop(0)
        else:
            sw1, sw2 = 0x90, 0x00
        return b"", sw1, sw2


def _shell(transport: _RecordingTransport) -> ShellDispatcher:
    shell = ShellDispatcher.__new__(ShellDispatcher)
    shell.transport = transport
    return shell


def test_shell_wraps_a_bare_payload_on_the_channel_the_session_last_used() -> None:
    transport = _RecordingTransport()
    shell = _shell(transport)

    # The SELECT frames itself as a command APDU, so it sets the channel.
    shell._transmit_manual_apdu(
        bytes.fromhex("01A4040010A0000005591010FFFFFFFF8900000100"),
        "01A4040010A0000005591010FFFFFFFF8900000100",
    )
    shell._transmit_manual_apdu(PAYLOAD, PAYLOAD.hex().upper())

    assert shell._active_logical_channel == 1
    assert [line[:10] for line in transport.sent[1:]] == EXPECTED_HEADERS


def test_shell_stops_the_sequence_on_the_first_failing_block() -> None:
    transport = _RecordingTransport([(0x90, 0x00), (0x6A, 0x80)])
    shell = _shell(transport)

    _data, sw1, sw2 = shell._transmit_manual_apdu(PAYLOAD, PAYLOAD.hex().upper())

    assert (sw1, sw2) == (0x6A, 0x80)
    assert len(transport.sent) == 2


def test_shell_sends_a_command_that_fits_exactly_as_it_was_typed() -> None:
    transport = _RecordingTransport()
    shell = _shell(transport)
    typed = "80 CA 9F 7F 00"

    shell._transmit_manual_apdu(bytes.fromhex(typed.replace(" ", "")), typed)

    assert transport.sent == [typed]


def test_max_short_apdu_data_is_the_one_byte_lc_ceiling() -> None:
    assert MAX_SHORT_APDU_DATA == 0xFF


class _RecordingOtaTransport:
    """SCP80 reader stand-in returning the 16-bit status word that path uses."""

    def __init__(self, statuses: list[int] | None = None) -> None:
        self.sent: list[str] = []
        self.statuses = list(statuses or [])

    def transmit(self, apdu_hex: str) -> tuple[bytes, int]:
        self.sent.append(apdu_hex)
        status = self.statuses.pop(0) if len(self.statuses) > 0 else 0x9000
        return b"", status


def test_scp80_sendraw_chains_an_over_long_apdu() -> None:
    from SCP80.cli import OtaShell

    shell = OtaShell.__new__(OtaShell)
    shell.transport = _RecordingOtaTransport()

    shell.do_sendraw(PAYLOAD.hex().upper())

    assert [line[:10] for line in shell.transport.sent] == [
        header.replace("81E2", "80E2", 1) for header in EXPECTED_HEADERS
    ]
    assert "".join(line[10:] for line in shell.transport.sent) == PAYLOAD.hex().upper()


def test_scp80_sendraw_leaves_a_short_apdu_and_rejects_bad_hex() -> None:
    from SCP80.cli import OtaShell

    shell = OtaShell.__new__(OtaShell)
    shell.transport = _RecordingOtaTransport()

    shell.do_sendraw("00A4", "0004023F00")
    assert shell.transport.sent == ["00A40004023F00"]

    shell.do_sendraw("ZZZZ")
    assert shell.transport.sent == ["00A40004023F00"]


def test_scp80_sendraw_stops_on_the_first_failing_block() -> None:
    from SCP80.cli import OtaShell

    shell = OtaShell.__new__(OtaShell)
    shell.transport = _RecordingOtaTransport([0x9000, 0x6A80])

    shell.do_sendraw(PAYLOAD.hex().upper())

    assert len(shell.transport.sent) == 2


def test_scp11_console_chains_an_over_long_es10x_payload() -> None:
    from SCP11.live.console import ConsoleStyle, SCP11Console

    class _Channel:
        def __init__(self) -> None:
            self.sent: list[str] = []

        def send(self, apdu: bytes, log_name: str) -> bytes:
            self.sent.append(apdu.hex().upper())
            return bytes.fromhex("BF5705A003840178")

    class _Orchestrator:
        @staticmethod
        def _current_es10b_store_data_cla() -> int:
            return 0x81

    console = SCP11Console.__new__(SCP11Console)
    console.apdu_channel = _Channel()
    console.orchestrator = _Orchestrator()
    console._style = ConsoleStyle(
        header="", cyan="", green="", yellow="", red="", bold="", end=""
    )

    response = console._send_store_data_with_logical_fallback(
        PAYLOAD, "SET: AddInitialEim"
    )

    assert [line[:10] for line in console.apdu_channel.sent] == EXPECTED_HEADERS
    assert "".join(line[10:] for line in console.apdu_channel.sent) == PAYLOAD.hex().upper()
    assert response == bytes.fromhex("BF5705A003840178")
