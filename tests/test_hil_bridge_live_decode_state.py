# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import unittest

from SIMCARD.utils import read_tlv, tlv
from Tools.HilBridge.live_decode_state import (
    OPEN_CHANNEL_COMMAND,
    POLL_INTERVAL_COMMAND,
    RECEIVE_DATA_COMMAND,
    SEND_DATA_COMMAND,
    TIMER_MANAGEMENT_COMMAND,
    annotate_packet_summary,
    build_stateful_packet_annotations,
)
from Tools.HilBridge.live_decode_view import PacketSummary
from Tools.HilBridge.protocol import GSMTAP_SIM_APDU, build_gsmtap_packet


def _command_details(fetch_data: bytes) -> tuple[int, int, int]:
    root_tag, root_value, _raw_tlv, _next_offset = read_tlv(fetch_data, 0)
    if root_tag != b"\xD0":
        raise AssertionError("Expected proactive command payload.")
    tag_bytes, value_bytes, _raw_tlv, _next_offset = read_tlv(root_value, 0)
    if tag_bytes not in {b"\x01", b"\x81"}:
        raise AssertionError("Expected proactive command details TLV.")
    if len(value_bytes) != 3:
        raise AssertionError("Unexpected proactive command details length.")
    return int(value_bytes[0]), int(value_bytes[1]), int(value_bytes[2])


def _proactive_command(
    command_number: int,
    command_type: int,
    qualifier: int,
    extra_tlvs: bytes = b"",
) -> bytes:
    body = (
        tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, qualifier & 0xFF)))
        + tlv("82", bytes.fromhex("8182"))
        + bytes(extra_tlvs or b"")
    )
    return tlv("D0", body)


def _fetch_row(
    frame_number: int,
    proactive_payload: bytes,
    *,
    time_override_seconds: float | None = None,
) -> PacketSummary:
    command = bytes([0x80, 0x12, 0x00, 0x00, len(proactive_payload)]) + proactive_payload + bytes.fromhex("9000")
    return _summary_row(
        frame_number,
        command,
        time_override_seconds=time_override_seconds,
    )


def _terminal_response_row(
    frame_number: int,
    proactive_payload: bytes,
    *,
    result: int = 0x00,
    extra_tlvs: bytes = b"",
    time_override_seconds: float | None = None,
) -> PacketSummary:
    command_number, command_type, qualifier = _command_details(proactive_payload)
    body = (
        tlv("81", bytes((command_number, command_type, qualifier)))
        + tlv("82", bytes.fromhex("8281"))
        + tlv("03", bytes((result & 0xFF,)))
        + bytes(extra_tlvs or b"")
    )
    command = bytes([0x80, 0x14, 0x00, 0x00, len(body)]) + body + bytes.fromhex("9000")
    return _summary_row(
        frame_number,
        command,
        time_override_seconds=time_override_seconds,
    )


def _envelope_row(frame_number: int, envelope_body: bytes) -> PacketSummary:
    command = bytes([0x80, 0xC2, 0x00, 0x00, len(envelope_body)]) + envelope_body + bytes.fromhex("9000")
    return _summary_row(frame_number, command)


def _apdu_exchange_row(
    frame_number: int,
    command: bytes,
    response: bytes = bytes.fromhex("9000"),
    *,
    time_override_seconds: float | None = None,
) -> PacketSummary:
    return _summary_row(
        frame_number,
        bytes(command) + bytes(response),
        time_override_seconds=time_override_seconds,
    )


def _summary_row(
    frame_number: int,
    exchange_payload: bytes,
    *,
    time_override_seconds: float | None = None,
) -> PacketSummary:
    gsmtap_payload = build_gsmtap_packet(
        exchange_payload,
        subtype=GSMTAP_SIM_APDU,
        uplink=True,
    )
    time_seconds = (
        float(time_override_seconds)
        if time_override_seconds is not None
        else frame_number / 1000
    )
    return PacketSummary(
        number=frame_number,
        time_text=f"{time_seconds:.6f}",
        source="modem",
        destination="card",
        protocol="GSM SIM",
        length_text=str(len(exchange_payload)),
        info="APDU",
        udp_payload_hex=gsmtap_payload.hex().upper(),
    )


def _tls_client_hello_record(server_name: str) -> bytes:
    server_name_bytes = str(server_name or "").encode("ascii")
    server_name_entry = (
        bytes((0x00,))
        + len(server_name_bytes).to_bytes(2, "big", signed=False)
        + server_name_bytes
    )
    server_name_extension_value = (
        len(server_name_entry).to_bytes(2, "big", signed=False)
        + server_name_entry
    )
    extensions = (
        bytes.fromhex("0000")
        + len(server_name_extension_value).to_bytes(2, "big", signed=False)
        + server_name_extension_value
    )
    handshake_body = (
        bytes.fromhex("0303")
        + bytes(32)
        + bytes((0x00,))
        + bytes.fromhex("0002")
        + bytes.fromhex("1301")
        + bytes((0x01, 0x00))
        + len(extensions).to_bytes(2, "big", signed=False)
        + extensions
    )
    handshake_message = (
        bytes((0x01,))
        + len(handshake_body).to_bytes(3, "big", signed=False)
        + handshake_body
    )
    return (
        bytes((0x16, 0x03, 0x03))
        + len(handshake_message).to_bytes(2, "big", signed=False)
        + handshake_message
    )


class HilBridgeLiveDecodeStateTests(unittest.TestCase):
    @staticmethod
    def _open_channel_rows() -> tuple[PacketSummary, PacketSummary]:
        open_channel_payload = _proactive_command(
            1,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 1, 2, 3, 4))),
        )
        return (
            _fetch_row(1, open_channel_payload),
            _terminal_response_row(2, open_channel_payload),
        )

    def test_open_channel_session_annotations_follow_bip_flow(self) -> None:
        open_channel_payload = _proactive_command(
            1,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 1, 2, 3, 4))),
        )
        data_available_envelope = tlv(
            "D6",
            tlv("99", b"\x09")
            + tlv("82", bytes.fromhex("8281"))
            + tlv("38", bytes.fromhex("8100"))
            + tlv("37", b"\x05"),
        )
        receive_data_payload = _proactive_command(
            2,
            RECEIVE_DATA_COMMAND,
            0x00,
            tlv("B7", b"\x05"),
        )
        receive_terminal_response_extra = tlv("36", b"hello") + tlv("37", b"\x00")

        rows = [
            _fetch_row(1, open_channel_payload),
            _terminal_response_row(2, open_channel_payload),
            _envelope_row(3, data_available_envelope),
            _fetch_row(4, receive_data_payload),
            _terminal_response_row(
                5,
                receive_data_payload,
                extra_tlvs=receive_terminal_response_extra,
            ),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("CH1 OPEN", annotations[1].summary_suffix)
        self.assertIn("CH1 OPEN OK", annotations[2].summary_suffix)
        self.assertIn("CH1 DATA AVAILABLE 5B", annotations[3].summary_suffix)
        self.assertIn("CH1 RECEIVE 5B", annotations[4].summary_suffix)
        self.assertIn("CH1 RX 5B rem=0", annotations[5].summary_suffix)
        self.assertEqual(annotations[1].channel_session_id, 1)
        self.assertEqual(annotations[2].channel_session_id, 1)
        self.assertEqual(annotations[3].channel_session_id, 1)
        self.assertEqual(annotations[4].channel_session_id, 1)
        self.assertEqual(annotations[5].channel_session_id, 1)
        self.assertEqual(annotations[1].channel_number, 1)
        self.assertEqual(annotations[2].channel_number, 1)
        self.assertEqual(annotations[3].channel_number, 1)
        self.assertEqual(annotations[4].channel_number, 1)
        self.assertEqual(annotations[5].channel_number, 1)
        self.assertEqual(annotations[1].channel_poll_index, 1)
        self.assertEqual(annotations[2].channel_poll_index, 1)
        self.assertEqual(annotations[3].channel_poll_index, 1)
        self.assertEqual(annotations[4].channel_poll_index, 1)
        self.assertEqual(annotations[5].channel_poll_index, 1)
        self.assertEqual(annotations[5].active_channel_count, 1)
        self.assertIn("Channel Sessions", annotations[5].context_lines)
        self.assertTrue(any("CH1 / Channel 1 active" in line for line in annotations[5].context_lines))
        self.assertTrue(any("Poll occurrence: 1" in line for line in annotations[5].context_lines))

        decorated_row = annotate_packet_summary(rows[4], annotations[4])
        self.assertIn("CH1 RECEIVE 5B", decorated_row.info)

    def test_fs_and_unknown_apdus_are_not_nested_under_bip_channel_even_when_open(self) -> None:
        open_fetch, open_response = self._open_channel_rows()
        select_mf_row = _apdu_exchange_row(3, bytes.fromhex("00A40004023F00"))
        store_data_row = PacketSummary(
            number=4,
            time_text="0.004000",
            source="modem",
            destination="card",
            protocol="GSM SIM",
            length_text="0",
            info="STORE DATA",
        )

        annotations = build_stateful_packet_annotations(
            [open_fetch, open_response, select_mf_row, store_data_row]
        )

        self.assertIsNone(annotations[3].channel_session_id)
        self.assertIsNone(annotations[3].channel_number)
        self.assertIsNone(annotations[3].channel_poll_index)
        self.assertIn("FS MF SELECT", annotations[3].summary_suffix)
        self.assertIsNone(annotations[4].channel_session_id)
        self.assertIsNone(annotations[4].channel_number)
        self.assertIsNone(annotations[4].channel_poll_index)
        self.assertEqual(annotations[4].summary_suffix, "")

    def test_open_channel_summary_includes_network_access_name_when_present(self) -> None:
        apn_labels = b"\x03ims\x06apn123\x03com"
        open_channel_payload = _proactive_command(
            1,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("47", apn_labels)
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 10, 0, 0, 7))),
        )

        rows = [
            _fetch_row(1, open_channel_payload),
            _terminal_response_row(2, open_channel_payload),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("APN:ims.apn123.com", annotations[1].summary_suffix)
        self.assertIn("CH1 OPEN", annotations[1].summary_suffix)
        self.assertTrue(
            any("APN: ims.apn123.com" in line for line in annotations[1].context_lines),
            msg=f"Expected APN detail line in {annotations[1].context_lines!r}",
        )
        self.assertEqual(annotations[1].channel_session_id, 1)
        self.assertEqual(annotations[2].channel_session_id, 1)

    def test_data_available_envelope_uses_envelope_channel_number_when_session_drifted(self) -> None:
        first_open_payload = _proactive_command(
            1,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 1, 2, 3, 4))),
        )
        second_open_payload = _proactive_command(
            2,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 9, 8, 7, 6))),
        )
        first_channel_envelope = tlv(
            "D6",
            tlv("99", b"\x09")
            + tlv("82", bytes.fromhex("8281"))
            + tlv("38", bytes.fromhex("8101"))
            + tlv("37", b"\x07"),
        )

        rows = [
            _fetch_row(1, first_open_payload),
            _terminal_response_row(2, first_open_payload),
            _fetch_row(3, second_open_payload),
            _terminal_response_row(4, second_open_payload),
            _envelope_row(5, first_channel_envelope),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertEqual(annotations[1].channel_session_id, 1)
        self.assertEqual(annotations[3].channel_session_id, 2)
        self.assertEqual(
            annotations[5].channel_session_id,
            1,
            msg="Data-available envelope with channel_number=1 must route back to session 1, not to the most recently opened session 2.",
        )
        self.assertIn("CH1 DATA AVAILABLE 7B", annotations[5].summary_suffix)

    def test_data_available_envelope_parses_cr_cleared_tlv_tags(self) -> None:
        # Real cards may emit the ENVELOPE Event Download body using the
        # COMPREHENSION-TLV encoding with the CR bit cleared (0x19 / 0x17
        # / 0x18) instead of the CR-set variant (0x99 / 0x37 / 0x38). The
        # parser must understand both so the summary never falls back to
        # "EVENT 0x00".
        open_payload = _proactive_command(
            1,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 1, 2, 3, 4))),
        )
        cr_cleared_envelope = tlv(
            "D6",
            tlv("19", b"\x09")
            + tlv("82", bytes.fromhex("8281"))
            + tlv("18", bytes.fromhex("8101"))
            + tlv("17", b"\x0A"),
        )

        rows = [
            _fetch_row(1, open_payload),
            _terminal_response_row(2, open_payload),
            _envelope_row(3, cr_cleared_envelope),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("CH1 DATA AVAILABLE 10B", annotations[3].summary_suffix)
        self.assertEqual(annotations[3].channel_session_id, 1)

    def test_new_open_channel_force_closes_stale_session_from_previous_boot(self) -> None:
        first_open_fetch, first_open_response = self._open_channel_rows()
        second_open_payload = _proactive_command(
            3,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 9, 8, 7, 6))),
        )
        second_open_fetch = _fetch_row(5, second_open_payload)
        second_open_response = _terminal_response_row(6, second_open_payload)
        post_reboot_select = _apdu_exchange_row(7, bytes.fromhex("00A40004022F00"))

        annotations = build_stateful_packet_annotations(
            [
                first_open_fetch,
                first_open_response,
                second_open_fetch,
                second_open_response,
                post_reboot_select,
            ]
        )

        self.assertEqual(annotations[1].channel_session_id, 1)
        self.assertEqual(annotations[2].channel_session_id, 1)
        self.assertEqual(annotations[5].channel_session_id, 2)
        self.assertEqual(annotations[6].channel_session_id, 2)
        self.assertIsNone(annotations[7].channel_session_id)
        self.assertEqual(annotations[5].active_channel_count, 1)
        self.assertEqual(annotations[6].active_channel_count, 1)

    def test_timer_management_annotations_track_start_query_and_expiry(self) -> None:
        timer_start_payload = _proactive_command(
            1,
            TIMER_MANAGEMENT_COMMAND,
            0x00,
            tlv("24", b"\x01") + tlv("25", bytes.fromhex("000003")),
        )
        timer_query_payload = _proactive_command(
            2,
            TIMER_MANAGEMENT_COMMAND,
            0x01,
            tlv("24", b"\x01"),
        )
        timer_query_response = tlv("24", b"\x01") + tlv("25", bytes.fromhex("000002"))
        timer_expiration_envelope = tlv(
            "D7",
            tlv("82", bytes.fromhex("8281"))
            + tlv("24", b"\x01")
            + tlv("25", bytes.fromhex("000003")),
        )

        rows = [
            _fetch_row(1, timer_start_payload),
            _terminal_response_row(2, timer_start_payload),
            _fetch_row(3, timer_query_payload),
            _terminal_response_row(
                4,
                timer_query_payload,
                extra_tlvs=timer_query_response,
            ),
            _envelope_row(5, timer_expiration_envelope),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("T1 START 30s", annotations[1].summary_suffix)
        self.assertAlmostEqual(float(annotations[1].capture_time_seconds or 0.0), 0.001)
        self.assertEqual(len(annotations[1].active_timers), 1)
        self.assertEqual(annotations[1].active_timers[0].timer_id, 1)
        self.assertEqual(annotations[1].active_timers[0].remaining_seconds, 30)
        self.assertEqual(annotations[2].active_timer_count, 1)
        self.assertIn("T1 QUERY", annotations[3].summary_suffix)
        self.assertIn("T1 REM 20s", annotations[4].summary_suffix)
        self.assertEqual(annotations[4].active_timers[0].remaining_seconds, 20)
        self.assertIn("T1 EXPIRED 30s", annotations[5].summary_suffix)
        self.assertEqual(annotations[5].active_timer_count, 0)
        self.assertEqual(annotations[5].active_timers, ())
        self.assertTrue(any("Frame Events" == line for line in annotations[5].context_lines))

    def test_poll_interval_annotations_age_out_after_requested_duration(self) -> None:
        poll_interval_payload = _proactive_command(
            1,
            POLL_INTERVAL_COMMAND,
            0x00,
            tlv("84", bytes.fromhex("0101")),
        )
        poll_interval_response = tlv("84", bytes.fromhex("0101"))

        rows = [
            _fetch_row(1, poll_interval_payload),
            _terminal_response_row(
                2,
                poll_interval_payload,
                extra_tlvs=poll_interval_response,
            ),
            _apdu_exchange_row(2002, bytes.fromhex("80F2000000")),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("POLL INTERVAL 1s", annotations[1].summary_suffix)
        self.assertEqual(annotations[1].active_timer_count, 1)
        self.assertEqual(len(annotations[1].active_timers), 1)
        self.assertEqual(annotations[1].active_timers[0].display_label, "POLL")
        self.assertEqual(annotations[1].active_timers[0].remaining_seconds, 1)
        self.assertEqual(annotations[2].active_timer_count, 1)
        self.assertTrue(any("POLL active 1s" in line for line in annotations[2].context_lines))
        self.assertEqual(annotations[2002].active_timer_count, 0)
        self.assertEqual(annotations[2002].active_timers, ())

    def test_bip_payload_annotations_summarize_dns_query_and_response(self) -> None:
        open_fetch, open_response = self._open_channel_rows()
        dns_query = bytes.fromhex(
            "1234010000010000000000000365696D076578616D706C6504746573740000010001"
        )
        dns_response = bytes.fromhex(
            "1234818000010001000000000365696D076578616D706C6504746573740000010001"
            "C00C000100010000003C0004C0000235"
        )
        send_data_payload = _proactive_command(
            2,
            SEND_DATA_COMMAND,
            0x00,
            tlv("36", dns_query),
        )
        receive_data_payload = _proactive_command(
            3,
            RECEIVE_DATA_COMMAND,
            0x00,
            tlv("B7", bytes((len(dns_response),))),
        )
        receive_terminal_response_extra = tlv("36", dns_response) + tlv("37", b"\x00")

        rows = [
            open_fetch,
            open_response,
            _fetch_row(3, send_data_payload),
            _terminal_response_row(4, send_data_payload, extra_tlvs=tlv("37", b"\xff")),
            _fetch_row(5, receive_data_payload),
            _terminal_response_row(
                6,
                receive_data_payload,
                extra_tlvs=receive_terminal_response_extra,
            ),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("DNS Query:", annotations[3].summary_suffix)
        self.assertIn("qname=eim.example.test", annotations[3].summary_suffix)
        self.assertIn("DNS Response:", annotations[6].summary_suffix)
        self.assertIn("answers=A:192.0.2.53", annotations[6].summary_suffix)
        self.assertTrue(any("Last SEND summary: DNS Query:" in line for line in annotations[6].context_lines))
        self.assertTrue(any("Last RECEIVE summary: DNS Response:" in line for line in annotations[6].context_lines))

    def test_bip_payload_annotations_summarize_tls_handshakes(self) -> None:
        open_fetch, open_response = self._open_channel_rows()
        tls_client_hello = _tls_client_hello_record("tls.eim.example.test")
        tls_server_chain = bytes.fromhex("1603030008020000000B000000")
        send_data_payload = _proactive_command(
            2,
            SEND_DATA_COMMAND,
            0x00,
            tlv("36", tls_client_hello),
        )
        receive_data_payload = _proactive_command(
            3,
            RECEIVE_DATA_COMMAND,
            0x00,
            tlv("B7", bytes((len(tls_server_chain),))),
        )
        receive_terminal_response_extra = tlv("36", tls_server_chain) + tlv("37", b"\x00")

        rows = [
            open_fetch,
            open_response,
            _fetch_row(3, send_data_payload),
            _terminal_response_row(4, send_data_payload, extra_tlvs=tlv("37", b"\xff")),
            _fetch_row(5, receive_data_payload),
            _terminal_response_row(
                6,
                receive_data_payload,
                extra_tlvs=receive_terminal_response_extra,
            ),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertIn("TLS Handshake: ClientHello", annotations[3].summary_suffix)
        self.assertIn("sni=tls.eim.example.test", annotations[3].summary_suffix)
        self.assertIn("TLS Handshake: ServerHello", annotations[6].summary_suffix)
        self.assertIn("Certificate", annotations[6].summary_suffix)
        self.assertTrue(any("Last SEND summary: TLS Handshake: ClientHello" in line for line in annotations[6].context_lines))
        self.assertTrue(any("sni=tls.eim.example.test" in line for line in annotations[6].context_lines))
        self.assertTrue(any("Last RECEIVE summary: TLS Handshake: ServerHello" in line for line in annotations[6].context_lines))

    def test_etsi_file_annotations_track_selection_and_binary_reads(self) -> None:
        rows = [
            _apdu_exchange_row(1, bytes.fromhex("00A40004023F00")),
            _apdu_exchange_row(2, bytes.fromhex("00A40004022FE2")),
            _apdu_exchange_row(
                3,
                bytes.fromhex("00B000000A"),
                bytes.fromhex("898811111111111111129000"),
            ),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertFalse(annotations[1].state_event)
        self.assertIn("FS MF SELECT", annotations[1].summary_suffix)
        self.assertIn("FS MF/EF.ICCID SELECT", annotations[2].summary_suffix)
        self.assertIn("FS MF/EF.ICCID READ BINARY 10B @0", annotations[3].summary_suffix)
        self.assertIn("ETSI File Context", annotations[3].context_lines)
        self.assertTrue(
            any("Current selection: MF/EF.ICCID" in line for line in annotations[3].context_lines)
        )
        self.assertTrue(
            any("Recent op: READ BINARY MF/EF.ICCID 10B @0" in line for line in annotations[3].context_lines)
        )

    def test_etsi_file_trace_chain_explains_select_failure_context(self) -> None:
        rows = [
            _apdu_exchange_row(1, bytes.fromhex("00A40004023F00")),
            _apdu_exchange_row(2, bytes.fromhex("00A40004022F00")),
            _apdu_exchange_row(
                3,
                bytes.fromhex("00B2010400"),
                bytes.fromhex("0102039000"),
            ),
            _apdu_exchange_row(
                4,
                bytes.fromhex("00B2020400"),
                bytes.fromhex("0405069000"),
            ),
            _apdu_exchange_row(
                5,
                bytes.fromhex("00A4040010A0000000871002FF86FF112233445566"),
            ),
            _apdu_exchange_row(
                6,
                bytes.fromhex("00A40004022F00"),
                bytes.fromhex("6A82"),
            ),
        ]

        annotations = build_stateful_packet_annotations(rows)
        failed_select = annotations[6]

        self.assertEqual(failed_select.trace_group, "filesystem")
        self.assertEqual(failed_select.trace_operation, "SELECT")
        self.assertEqual(failed_select.trace_path, "MF/EF.DIR")
        self.assertEqual(failed_select.trace_status, "fail 6A82")
        self.assertEqual(failed_select.trace_parent_frame, 5)
        self.assertEqual(failed_select.trace_related_frames, (1, 2, 3, 4, 5, 6))
        self.assertIn("Current selection stayed MF/ADF.USIM", failed_select.trace_reason)
        self.assertIn("requested file resolved to MF/EF.DIR", failed_select.trace_reason)
        self.assertIn("outside active context MF/ADF.USIM", failed_select.trace_reason)
        self.assertTrue(
            any("outside active context MF/ADF.USIM" in line for line in failed_select.context_lines)
        )

    def test_decode_iccid_bytes_handles_even_and_odd_length_identifiers(self) -> None:
        from Tools.HilBridge.live_decode_state import _decode_iccid_bytes

        even_bytes = bytes.fromhex("89461111111111111112")
        self.assertEqual(_decode_iccid_bytes(even_bytes), "98641111111111111121")

        # 19-digit ICCID: digit 19 sits in the low nibble of byte 9, the
        # high nibble is the 0xF padding, producing a 0xF1 terminator.
        odd_bytes = bytes.fromhex("894611111111111111F1")
        self.assertEqual(_decode_iccid_bytes(odd_bytes), "9864111111111111111")

        too_short = bytes.fromhex("89461111")
        self.assertEqual(_decode_iccid_bytes(too_short), "")

        invalid_digit = bytes.fromhex("A9461111111111111112")
        self.assertEqual(_decode_iccid_bytes(invalid_digit), "")

    def test_ef_iccid_read_binary_populates_card_session_iccid(self) -> None:
        rows = [
            _apdu_exchange_row(1, bytes.fromhex("00A40004023F00")),
            _apdu_exchange_row(2, bytes.fromhex("00A40004022FE2")),
            _apdu_exchange_row(
                3,
                bytes.fromhex("00B000000A"),
                bytes.fromhex("894611111111111111129000"),
            ),
            _apdu_exchange_row(4, bytes.fromhex("00A40004023F00")),
        ]

        annotations = build_stateful_packet_annotations(rows)

        self.assertEqual(annotations[1].card_session_iccid, "98641111111111111121")
        self.assertEqual(annotations[3].card_session_iccid, "98641111111111111121")
        self.assertEqual(annotations[4].card_session_iccid, "98641111111111111121")
        self.assertEqual(annotations[1].card_session_index, 1)

    def test_card_session_iccid_resets_on_card_reset(self) -> None:
        first_open_fetch, first_open_response = self._open_channel_rows()
        read_ef_iccid_rows = [
            _apdu_exchange_row(3, bytes.fromhex("00A40004023F00")),
            _apdu_exchange_row(4, bytes.fromhex("00A40004022FE2")),
            _apdu_exchange_row(
                5,
                bytes.fromhex("00B000000A"),
                bytes.fromhex("894611111111111111129000"),
            ),
        ]
        refresh_payload = _proactive_command(2, 0x01, 0x04)
        refresh_rows = [
            _fetch_row(6, refresh_payload),
            _terminal_response_row(7, refresh_payload),
        ]
        second_session_rows = [
            _apdu_exchange_row(8, bytes.fromhex("00A40004023F00")),
            _apdu_exchange_row(9, bytes.fromhex("00A40004022FE2")),
            _apdu_exchange_row(
                10,
                bytes.fromhex("00B000000A"),
                bytes.fromhex("894622222222222222349000"),
            ),
        ]

        annotations = build_stateful_packet_annotations(
            [first_open_fetch, first_open_response]
            + read_ef_iccid_rows
            + refresh_rows
            + second_session_rows
        )

        self.assertEqual(annotations[1].card_session_index, 1)
        self.assertEqual(annotations[5].card_session_index, 1)
        self.assertEqual(annotations[5].card_session_iccid, "98641111111111111121")
        self.assertEqual(annotations[8].card_session_index, 2)
        self.assertEqual(annotations[10].card_session_index, 2)
        self.assertEqual(annotations[10].card_session_iccid, "98642222222222222243")
        self.assertEqual(annotations[1].card_session_iccid, "98641111111111111121")
        self.assertEqual(annotations[8].card_session_iccid, "98642222222222222243")

    def test_card_session_index_defaults_to_one_when_no_reset_detected(self) -> None:
        first_open_fetch, first_open_response = self._open_channel_rows()
        annotations = build_stateful_packet_annotations(
            [first_open_fetch, first_open_response]
        )
        self.assertEqual(annotations[1].card_session_index, 1)
        self.assertEqual(annotations[2].card_session_index, 1)
        self.assertEqual(annotations[1].card_session_reset_reason, "")
        self.assertEqual(annotations[2].card_session_reset_reason, "")

    def test_refresh_uicc_reset_bumps_card_session_index_on_next_frame(self) -> None:
        first_open_fetch, first_open_response = self._open_channel_rows()
        refresh_uicc_reset_payload = _proactive_command(
            2,
            0x01,
            0x04,
        )
        refresh_fetch = _fetch_row(3, refresh_uicc_reset_payload)
        refresh_response = _terminal_response_row(4, refresh_uicc_reset_payload)
        post_reset_select = _apdu_exchange_row(5, bytes.fromhex("00A40004022F00"))
        second_open_payload = _proactive_command(
            3,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 9, 8, 7, 6))),
        )
        second_open_fetch = _fetch_row(6, second_open_payload)
        second_open_response = _terminal_response_row(7, second_open_payload)

        annotations = build_stateful_packet_annotations(
            [
                first_open_fetch,
                first_open_response,
                refresh_fetch,
                refresh_response,
                post_reset_select,
                second_open_fetch,
                second_open_response,
            ]
        )

        self.assertEqual(annotations[1].card_session_index, 1)
        self.assertEqual(annotations[2].card_session_index, 1)
        self.assertEqual(annotations[3].card_session_index, 1)
        self.assertEqual(annotations[4].card_session_index, 1)
        self.assertEqual(annotations[5].card_session_index, 2)
        self.assertEqual(annotations[6].card_session_index, 2)
        self.assertEqual(annotations[7].card_session_index, 2)
        self.assertIn("REFRESH", annotations[5].card_session_reset_reason)
        self.assertIn("UICC Reset", annotations[5].card_session_reset_reason)
        self.assertIn("REFRESH", annotations[3].summary_suffix)
        self.assertIn("UICC Reset", annotations[3].summary_suffix)

    def test_refresh_file_change_notification_does_not_bump_card_session(self) -> None:
        first_open_fetch, first_open_response = self._open_channel_rows()
        refresh_file_change_payload = _proactive_command(
            2,
            0x01,
            0x01,
        )
        refresh_fetch = _fetch_row(3, refresh_file_change_payload)
        refresh_response = _terminal_response_row(4, refresh_file_change_payload)
        trailing_select = _apdu_exchange_row(5, bytes.fromhex("00A40004022F00"))

        annotations = build_stateful_packet_annotations(
            [
                first_open_fetch,
                first_open_response,
                refresh_fetch,
                refresh_response,
                trailing_select,
            ]
        )

        self.assertEqual(annotations[1].card_session_index, 1)
        self.assertEqual(annotations[3].card_session_index, 1)
        self.assertEqual(annotations[5].card_session_index, 1)
        self.assertEqual(annotations[5].card_session_reset_reason, "")
        self.assertIn("File Change Notification", annotations[3].summary_suffix)

    def test_idle_gap_longer_than_threshold_bumps_card_session(self) -> None:
        first_open_fetch, first_open_response = self._open_channel_rows()
        first_open_fetch = _summary_row(
            1,
            first_open_fetch.udp_payload_hex and bytes.fromhex(
                first_open_fetch.udp_payload_hex
            ),
            time_override_seconds=1.000,
        )
        # Re-synthesise with an explicit time anchor for the first two
        # frames so the idle gap comparison has a clean baseline.
        first_open_payload = _proactive_command(
            1,
            OPEN_CHANNEL_COMMAND,
            0x00,
            tlv("39", bytes.fromhex("0400"))
            + tlv("3C", bytes.fromhex("0201BB"))
            + tlv("3E", bytes((0x21, 1, 2, 3, 4))),
        )
        first_open_fetch = _fetch_row(
            1, first_open_payload, time_override_seconds=1.000
        )
        first_open_response = _terminal_response_row(
            2, first_open_payload, time_override_seconds=1.100
        )
        # Frame 3 arrives ~45 s later — well beyond the 30 s idle threshold —
        # so the tracker must treat it as the opening of Card Session 2.
        post_reboot_select = _apdu_exchange_row(
            3,
            bytes.fromhex("00A40004022F00"),
            time_override_seconds=46.100,
        )

        annotations = build_stateful_packet_annotations(
            [first_open_fetch, first_open_response, post_reboot_select]
        )

        self.assertEqual(annotations[1].card_session_index, 1)
        self.assertEqual(annotations[2].card_session_index, 1)
        self.assertEqual(annotations[3].card_session_index, 2)
        self.assertTrue(annotations[3].card_session_reset_reason.startswith("idle "))


if __name__ == "__main__":
    unittest.main()
