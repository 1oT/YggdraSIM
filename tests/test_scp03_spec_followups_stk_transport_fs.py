# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Follow-up spec items for the SCP03 STK, transport, PIN, validator and TLV layers.

Clauses were read from the library copies of ETSI TS 102 221 V18.4.0, ETSI
TS 102 223 V18.3.0, 3GPP TS 31.101 V19.0.0, 3GPP TS 31.102 V19.5.0, ITU-T
X.690 (02/2021) and GlobalPlatform Secure Element Access Control v1.1.0.10:

* TS 102 221 §11.2.2 / table 10.1: ENVELOPE Lc is one byte unless the card
  declares extended Lc and Le (§6.3.1 card-capabilities data object).
* TS 102 223 §6.8.18 / §8.56: GET CHANNEL STATUS with no channel open.
* TS 102 221 §7.3.1.1.4 step 4b: case-4 GET RESPONSE under T = 0 after a
  warning or application status, and §11.1.7.1's SEARCH RECORD carve-out.
* TS 102 221 §11.1.9.1.2 PIN retry counter, §11.1.11 table 11.16 DISABLE PIN
  P1, TS 31.101 §9.6 PIN value coding.
* TS 31.102 §4.2.2 EF_IMSI absence, §4.2.57 EF_NETPAR size, §4.4.11.4 /
  §4.4.11.5 5GS NAS security context records.
* TS 102 221 §9.2.7 EF_ARR access rule referencing.
* X.690 §8.1.2.5 and GlobalPlatform SE Access Control tables 6-12 / 6-13.
"""

from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from SCP03.config import Config
from SCP03.core.utils import TlvParser
from SCP03.logic.fs import FileSystemController
from SCP03.logic.profile_validator import (
    FileExpectation,
    export_default_policy_pack,
    parse_policy_pack,
    PolicyPackError,
)
from SCP03.logic.security import SecurityController
from SCP03.logic.stk import StkController
from SCP03.transport.card import CardTransporter


# TS 102 221 v18.4 annex D reference UICC ATR: TS '3B', T0 '97' (TA1 and TD1
# present, 7 historical bytes), TA1 '95', TD1 '80' (T = 0), TD2 '1F' (T = 15),
# TA3 '42', historical '80 31 A0 73 BE 21 15' and the check byte. The third
# card-capabilities byte '15' reads "No extended Lc and Le".
ATR_T0_NO_EXTENDED = bytes.fromhex("3B9795801F42" "8031A073BE2115" "00")
# The same ATR with that byte set to '55', i.e. ISO/IEC 7816-4 b7 declaring
# "Extended Lc and Le fields".
ATR_T0_EXTENDED = bytes.fromhex("3B9795801F42" "8031A073BE2155" "00")


class _ScriptedConnection:
    """A card that answers a fixed script and records the wire commands."""

    def __init__(
        self,
        responses: list[tuple[bytes, int, int]],
        *,
        atr: bytes = ATR_T0_NO_EXTENDED,
        protocol: int | None = None,
    ) -> None:
        self.responses = list(responses)
        self.calls: list[str] = []
        self._atr = list(atr)
        self._protocol = protocol

    def transmit(self, command):
        self.calls.append(bytes(command).hex().upper())
        if len(self.responses) == 0:
            raise AssertionError(f"Unexpected APDU: {bytes(command).hex().upper()}")
        data, sw1, sw2 = self.responses.pop(0)
        return list(data), sw1, sw2

    def getATR(self):
        return list(self._atr)

    def getProtocol(self):
        return self._protocol


def _transporter(connection: _ScriptedConnection) -> CardTransporter:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.connection = connection
    transporter.session = None
    transporter.verbose = False
    transporter.debug = False
    transporter.last_trace = ()
    transporter.last_error = None
    transporter.last_session_invalidation = None
    return transporter


class _StkTransport:
    """Minimal STK transport with a declarable extended-length capability."""

    def __init__(self, *, extended: bool = False) -> None:
        self.connection = _ScriptedConnection([])
        self.extended = extended
        self.sent: list[str] = []

    def supports_extended_length(self) -> bool:
        return self.extended


class EnvelopeLengthTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.2.2 with table 10.1 and the §6.3.1 declaration."""

    def test_short_body_uses_a_one_byte_lc(self) -> None:
        controller = StkController(_StkTransport())
        apdu = controller._build_envelope_apdu(b"\xAA" * 255)
        self.assertEqual(apdu[:5].hex().upper(), "80C2000" + "0FF")

    def test_body_above_255_is_refused_without_the_declaration(self) -> None:
        controller = StkController(_StkTransport(extended=False))
        with self.assertRaises(ValueError) as raised:
            controller._build_envelope_apdu(b"\xAA" * 256)
        self.assertIn("extended Lc and Le", str(raised.exception))

    def test_body_above_255_uses_the_extended_form_when_declared(self) -> None:
        controller = StkController(_StkTransport(extended=True))
        apdu = controller._build_envelope_apdu(b"\xAA" * 256)
        self.assertEqual(apdu[:7].hex().upper(), "80C2000000" + "0100")
        self.assertEqual(len(apdu), 7 + 256)

    def test_a_transport_without_the_accessor_refuses_the_extended_form(self) -> None:
        class _Bare:
            connection = None

        controller = StkController(_Bare())
        with self.assertRaises(ValueError):
            controller._build_envelope_apdu(b"\xAA" * 256)


class GetChannelStatusTests(unittest.TestCase):
    """ETSI TS 102 223 v18.3 §6.8.18 with the §8.56 Channel status coding."""

    def test_no_open_channel_answers_channel_identifier_zero(self) -> None:
        controller = StkController(_StkTransport())
        result, payload = controller._build_terminal_response_result_and_payload(
            0x44, 0x00, {}
        )
        self.assertEqual(result, StkController.GENERAL_RESULT_OK)
        # §8.56 byte 3 bits 1-3 = 0 means "No channel available"; byte 4 '00'
        # is "No further info can be given".
        self.assertEqual(payload.hex().upper(), "38020000")

    def test_an_open_channel_still_reports_channel_one(self) -> None:
        controller = StkController(_StkTransport())
        controller.state.open_channel_active = True
        _result, payload = controller._build_terminal_response_result_and_payload(
            0x44, 0x00, {}
        )
        self.assertEqual(payload.hex().upper(), "38028100")


class AtrCapabilityTests(unittest.TestCase):
    """TS 102 221 v18.4 §6.3.0 protocols and §6.3.1 card capabilities."""

    def test_atr_layout_splits_protocols_and_historical_bytes(self) -> None:
        protocols, historical = CardTransporter._atr_layout(ATR_T0_NO_EXTENDED)
        self.assertEqual(protocols, (0, 15))
        self.assertEqual(historical.hex().upper(), "8031A073BE2115")

    def test_a_truncated_atr_declares_nothing(self) -> None:
        self.assertEqual(CardTransporter._atr_layout(b"\x3B"), ((), b""))
        self.assertEqual(CardTransporter._atr_layout(b"\x3B\x97"), ((), b""))

    def test_active_protocol_prefers_the_reader(self) -> None:
        # pyscard reports the PC/SC mask: T0_protocol '01', T1_protocol '02'.
        transporter = _transporter(
            _ScriptedConnection([], atr=ATR_T0_NO_EXTENDED, protocol=0x02)
        )
        self.assertEqual(transporter.active_protocol, 1)

    def test_active_protocol_falls_back_to_a_single_offered_protocol(self) -> None:
        transporter = _transporter(_ScriptedConnection([], atr=ATR_T0_NO_EXTENDED))
        self.assertEqual(transporter.active_protocol, 0)

    def test_an_atr_offering_both_protocols_is_not_a_decision(self) -> None:
        # TS '3B', T0 '97', TA1 '95', TD1 '80' (T = 0, TD2 follows),
        # TD2 '31' (T = 1, TA3/TB3 follow), TA3 'FE', TB3 '00'.
        atr = bytes.fromhex("3B979580" "31FE00" "8031A073BE2115" "00")
        transporter = _transporter(_ScriptedConnection([], atr=atr))
        self.assertIsNone(transporter.active_protocol)

    def test_the_bundled_simulated_card_is_a_known_t0_card(self) -> None:
        """The default backend decides whether the §7.3.1.1.4 fetch is armed."""

        from SIMCARD.state import DEFAULT_SIM_ATR

        transporter = _transporter(_ScriptedConnection([], atr=DEFAULT_SIM_ATR))
        self.assertEqual(transporter.active_protocol, 0)
        # Its card-capabilities byte is '13', so no extended Lc and Le.
        self.assertFalse(transporter.supports_extended_length())

    def test_extended_length_follows_the_card_capabilities_object(self) -> None:
        self.assertFalse(
            _transporter(
                _ScriptedConnection([], atr=ATR_T0_NO_EXTENDED)
            ).supports_extended_length()
        )
        self.assertTrue(
            _transporter(
                _ScriptedConnection([], atr=ATR_T0_EXTENDED)
            ).supports_extended_length()
        )


class ApduCaseTests(unittest.TestCase):
    """TS 102 221 v18.4 table 10.2 cases of C-APDUs."""

    def test_each_case_is_recognised(self) -> None:
        cases = {
            "00A40004": 1,
            "00A4000402": 2,
            "00A40004023F00": 3,
            "00A40004023F0000": 4,
            "00A400040000023F00": 3,
            "00A400040000023F000000": 4,
        }
        for apdu_hex, expected in cases.items():
            with self.subTest(apdu=apdu_hex):
                self.assertEqual(
                    CardTransporter._apdu_case(bytes.fromhex(apdu_hex)), expected
                )

    def test_a_malformed_body_is_not_classified(self) -> None:
        self.assertEqual(CardTransporter._apdu_case(bytes.fromhex("00A4")), 0)
        self.assertEqual(
            CardTransporter._apdu_case(bytes.fromhex("00A40004023F0000AA")), 0
        )

    def test_step_4b_statuses(self) -> None:
        for sw1, sw2 in ((0x62, 0x83), (0x63, 0xC2), (0x91, 0x20), (0x9F, 0x10)):
            with self.subTest(sw=f"{sw1:02X}{sw2:02X}"):
                self.assertTrue(
                    CardTransporter._is_case4_pending_data_status(sw1, sw2)
                )
        for sw1, sw2 in ((0x90, 0x00), (0x6A, 0x82), (0x6D, 0x00), (0x61, 0x10)):
            with self.subTest(sw=f"{sw1:02X}{sw2:02X}"):
                self.assertFalse(
                    CardTransporter._is_case4_pending_data_status(sw1, sw2)
                )


class Case4PendingDataTests(unittest.TestCase):
    """TS 102 221 v18.4 §7.3.1.1.4 step 4b and §7.3.2.0."""

    CASE4 = "80E2910006AABBCCDDEEFF00"

    def test_t0_fetches_the_pending_data_and_keeps_the_warning(self) -> None:
        connection = _ScriptedConnection(
            [
                (b"", 0x62, 0x83),
                (bytes.fromhex("A1B2C3"), 0x90, 0x00),
            ],
            atr=ATR_T0_NO_EXTENDED,
            protocol=0x01,
        )
        result = _transporter(connection).transmit_detailed(self.CASE4)

        # TS 102 221 v18.4 table 10.5 lists GET RESPONSE with CLA '0X', so
        # the proprietary '80' of the original command is dropped.
        self.assertEqual(
            connection.calls,
            [self.CASE4, "00C0000000"],
        )
        self.assertEqual(result.data.hex().upper(), "A1B2C3")
        # The warning describes the command; the GET RESPONSE trailer does not
        # replace it.
        self.assertEqual((result.sw1, result.sw2), (0x62, 0x83))

    def test_t0_fetches_after_an_application_status(self) -> None:
        connection = _ScriptedConnection(
            [
                (b"", 0x91, 0x20),
                (bytes.fromhex("0102"), 0x90, 0x00),
            ],
            protocol=0x01,
        )
        result = _transporter(connection).transmit_detailed(self.CASE4)

        self.assertEqual(connection.calls[-1], "00C0000000")
        self.assertEqual(result.data.hex().upper(), "0102")
        self.assertEqual((result.sw1, result.sw2), (0x91, 0x20))

    def test_t1_returns_the_data_with_the_status(self) -> None:
        connection = _ScriptedConnection(
            [(bytes.fromhex("A1B2C3"), 0x62, 0x83)],
            protocol=0x02,
        )
        result = _transporter(connection).transmit_detailed(self.CASE4)

        self.assertEqual(connection.calls, [self.CASE4])
        self.assertEqual(result.data.hex().upper(), "A1B2C3")
        self.assertEqual((result.sw1, result.sw2), (0x62, 0x83))

    def test_a_case_3_command_is_left_alone(self) -> None:
        # VERIFY PIN is case 3, so its '63CX' is a result, not pending data.
        connection = _ScriptedConnection([(b"", 0x63, 0xC2)], protocol=0x01)
        result = _transporter(connection).transmit_detailed(
            "0020000108" "31323334FFFFFFFF"
        )

        self.assertEqual(len(connection.calls), 1)
        self.assertEqual((result.sw1, result.sw2), (0x63, 0xC2))

    def test_9000_is_not_pending_data(self) -> None:
        connection = _ScriptedConnection([(b"", 0x90, 0x00)], protocol=0x01)
        result = _transporter(connection).transmit_detailed(self.CASE4)

        self.assertEqual(len(connection.calls), 1)
        self.assertEqual((result.sw1, result.sw2), (0x90, 0x00))

    def test_a_61xx_chain_ending_in_a_warning_does_not_fetch_again(self) -> None:
        # Step 4b answers the case-4 command's own status; once the '61xx'
        # chain of step 4a runs, later statuses belong to a GET RESPONSE and
        # step 5 handles them under the case-2 rules.
        connection = _ScriptedConnection(
            [
                (b"", 0x61, 0x04),
                (bytes.fromhex("AABBCCDD"), 0x62, 0x83),
            ],
            protocol=0x01,
        )
        result = _transporter(connection).transmit_detailed(self.CASE4)

        self.assertEqual(connection.calls, [self.CASE4, "00C0000004"])
        self.assertEqual(result.data.hex().upper(), "AABBCCDD")
        self.assertEqual((result.sw1, result.sw2), (0x62, 0x83))

    def test_search_record_6282_skips_the_get_response(self) -> None:
        # §11.1.7.1: after '6282' the response is empty and the terminal
        # might not send the GET RESPONSE that step 4b otherwise calls for.
        connection = _ScriptedConnection([(b"", 0x62, 0x82)], protocol=0x01)
        result = _transporter(connection).transmit_detailed("00A2010402AABB00")

        self.assertEqual(connection.calls, ["00A2010402AABB00"])
        self.assertEqual((result.sw1, result.sw2), (0x62, 0x82))


class _PinTransport:
    def __init__(self, responses=None) -> None:
        self.commands: list[str] = []
        self.responses = dict(responses or {})

    def transmit(self, apdu: str, silent: bool = False):
        del silent
        command = str(apdu).strip().upper()
        self.commands.append(command)
        return self.responses.get(command, (b"", 0x90, 0x00))


class PinRetryCounterTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.9.1.2 and §11.1.9.3."""

    def test_the_query_is_a_case_1_apdu_with_no_lc(self) -> None:
        transport = _PinTransport({"00200001": (b"", 0x63, 0xC2)})
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            remaining = controller.get_pin_retry_counter("PIN1")

        self.assertEqual(transport.commands, ["00200001"])
        self.assertEqual(remaining, 2)
        self.assertIn("2 attempt(s) remaining", output.getvalue())

    def test_63c0_reports_a_blocked_pin(self) -> None:
        transport = _PinTransport({"00200001": (b"", 0x63, 0xC0)})
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            remaining = controller.get_pin_retry_counter("PIN1")

        self.assertEqual(remaining, 0)
        self.assertIn("Blocked", output.getvalue())

    def test_6983_reports_a_blocked_pin(self) -> None:
        transport = _PinTransport({"00200001": (b"", 0x69, 0x83)})
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(controller.get_pin_retry_counter("PIN1"), 0)

    def test_another_status_reports_no_count(self) -> None:
        transport = _PinTransport({"00200001": (b"", 0x6A, 0x88)})
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertIsNone(controller.get_pin_retry_counter("PIN1"))


class DisablePinReplacementTests(unittest.TestCase):
    """TS 102 221 v18.4 §11.1.11 table 11.16."""

    def test_p1_is_00_without_a_replacement(self) -> None:
        transport = _PinTransport()
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            controller.disable_pin("PIN1", "1234")

        self.assertEqual(transport.commands, ["0026000108" "31323334FFFFFFFF"])

    def test_the_universal_pin_reference_sets_b8_and_the_low_five_bits(self) -> None:
        transport = _PinTransport()
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            controller.disable_pin("PIN1", "1234", replacement_ref="UPIN")

        # b8 = 1 with the Universal PIN key reference '11' in b1-b5.
        self.assertEqual(transport.commands, ["0026910108" "31323334FFFFFFFF"])

    def test_a_reference_beyond_five_bits_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            SecurityController._disable_pin_p1(0x81)
        self.assertEqual(SecurityController._disable_pin_p1(None), 0x00)
        self.assertEqual(SecurityController._disable_pin_p1(0x11), 0x91)


class PinValueCodingTests(unittest.TestCase):
    """3GPP TS 31.101 v19 §9.6 with the TS 102 221 v18.4 table 9.3 references."""

    def test_a_pin_reference_takes_four_to_eight_decimal_digits(self) -> None:
        controller = SecurityController(_PinTransport())
        self.assertEqual(
            controller._pad_pin("1234", ref_byte=0x01), "31323334FFFFFFFF"
        )
        with self.assertRaises(ValueError):
            controller._pad_pin("123", ref_byte=0x01)
        with self.assertRaises(ValueError):
            controller._pad_pin("12A4", ref_byte=0x81)
        with self.assertRaises(ValueError):
            controller._pad_pin("abcd", ref_byte=0x11)

    def test_adm_references_stay_free_form(self) -> None:
        controller = SecurityController(_PinTransport())
        for ref_byte in (0x0A, 0x0E, 0x8A, 0x8E):
            with self.subTest(ref=f"{ref_byte:02X}"):
                self.assertEqual(
                    controller._pad_pin("ab", ref_byte=ref_byte), "6162FFFFFFFFFFFF"
                )

    def test_the_hex_path_is_not_restricted(self) -> None:
        transport = _PinTransport()
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()):
            controller.verify_pin("PIN1", "523D3BE7AD38DE19", pin_encoding="hex")

        self.assertEqual(transport.commands, ["0020000108" "523D3BE7AD38DE19"])

    def test_verify_pin_refuses_a_three_digit_application_pin(self) -> None:
        transport = _PinTransport()
        controller = SecurityController(transport)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            controller.verify_pin("PIN1", "123")

        self.assertEqual(transport.commands, [])
        self.assertIn("four digits", output.getvalue())


class _ValidatorFs:
    """A file system whose ``select`` answers from a fixed set of paths."""

    def __init__(self, present: set[str]) -> None:
        self.present = set(present)
        self.current_fcp: dict = {}
        self.selected: list[str] = []

    def select(self, path: str, silent: bool = False) -> bool:
        del silent
        self.selected.append(path)
        return path in self.present


class AbsentIfServiceTests(unittest.TestCase):
    """3GPP TS 31.102 v19.5 §4.2.2 with the validator's policy-pack contract."""

    def _validator(self, present: set[str]):
        from SCP03.logic.profile_validator import ProfileValidator

        validator = ProfileValidator.__new__(ProfileValidator)
        validator.fs = _ValidatorFs(present)
        validator.findings = []
        return validator

    def test_ef_imsi_carries_service_130(self) -> None:
        from SCP03.logic.profile_validator import ProfileValidator

        imsi = [
            expectation
            for expectation in ProfileValidator.USIM_EXPECTATIONS
            if expectation.path == "ADF_USIM/EF_IMSI"
        ]
        self.assertEqual(len(imsi), 1)
        self.assertEqual(imsi[0].absent_if_service, (130,))

    def test_a_present_file_fails_when_the_service_is_available(self) -> None:
        validator = self._validator({"ADF_USIM/EF_IMSI"})
        expectation = FileExpectation(
            "ADF_USIM/EF_IMSI", "EF", "Transparent", absent_if_service=(130,)
        )
        # Service 130 lives in byte 17 bit 2 of the USIM service table.
        service_bits = [0x00] * 16 + [0x02]

        with contextlib.redirect_stdout(io.StringIO()):
            validator._validate_group("USIM", (expectation,), service_bits)

        self.assertEqual(
            [(finding.severity, finding.path) for finding in validator.findings],
            [("FAIL", "ADF_USIM/EF_IMSI")],
        )

    def test_an_absent_file_passes_when_the_service_is_available(self) -> None:
        validator = self._validator(set())
        expectation = FileExpectation(
            "ADF_USIM/EF_IMSI", "EF", "Transparent", absent_if_service=(130,)
        )
        service_bits = [0x00] * 16 + [0x02]

        with contextlib.redirect_stdout(io.StringIO()):
            validator._validate_group("USIM", (expectation,), service_bits)

        self.assertEqual(validator.findings[0].severity, "PASS")

    def test_the_structure_check_runs_when_the_service_is_not_available(self) -> None:
        validator = self._validator(set())
        expectation = FileExpectation(
            "ADF_USIM/EF_IMSI", "EF", "Transparent", absent_if_service=(130,)
        )

        with contextlib.redirect_stdout(io.StringIO()):
            validator._validate_group("USIM", (expectation,), [0x00] * 17)

        self.assertEqual(validator.findings[0].severity, "FAIL")
        self.assertIn("Required file is missing", validator.findings[0].message)

    def test_the_field_round_trips_through_the_policy_pack(self) -> None:
        pack = export_default_policy_pack()
        parsed = parse_policy_pack(pack)
        imsi = [
            expectation
            for expectation in parsed["usim"]
            if expectation.path == "ADF_USIM/EF_IMSI"
        ][0]
        self.assertEqual(imsi.absent_if_service, (130,))

    def test_a_non_list_value_is_rejected(self) -> None:
        with self.assertRaises(PolicyPackError):
            parse_policy_pack(
                {
                    "groups": {
                        "usim": [
                            {
                                "path": "ADF_USIM/EF_IMSI",
                                "expected_type": "EF",
                                "expected_structure": "Transparent",
                                "absent_if_service": 130,
                            }
                        ]
                    }
                }
            )


class SpecDerivedSizeTests(unittest.TestCase):
    """3GPP TS 31.102 v19.5 §4.2.57 and §4.4.11.4 / §4.4.11.5."""

    def test_ef_netpar_is_a_minimum_of_46_bytes(self) -> None:
        from SCP03.logic.profile_validator import ProfileValidator

        netpar = [
            expectation
            for expectation in ProfileValidator.USIM_EXPECTATIONS
            if expectation.path == "ADF_USIM/EF_NETPAR"
        ][0]
        self.assertIsNone(netpar.size)
        self.assertEqual(netpar.min_size, 46)

    def test_the_nsc_records_are_a_minimum_of_57_bytes(self) -> None:
        from SCP03.logic.profile_validator import ProfileValidator

        for path in ("ADF_USIM/5GS/EF_5GS3GPPNSC", "ADF_USIM/5GS/EF_5GSN3GPPNSC"):
            with self.subTest(path=path):
                entries = [
                    expectation
                    for expectation in ProfileValidator.USIM_5GS_EXPECTATIONS
                    if expectation.path == path
                ]
                sized = [
                    entry for entry in entries if entry.min_record_length is not None
                ]
                self.assertEqual(len(sized), 1)
                self.assertEqual(sized[0].min_record_length, 57)
                self.assertIsNone(sized[0].record_length)
                counted = [
                    entry for entry in entries if entry.record_count is not None
                ]
                self.assertEqual(len(counted), 1)
                # §4.4.11.4: two records only when service n°136 is available.
                self.assertEqual(counted[0].record_count, 2)
                self.assertEqual(counted[0].service_any, (136,))


class _ArrTransport:
    """A card whose EF_ARR sits two DF levels above the selected EF."""

    def __init__(self, levels_up: int) -> None:
        self.levels_up = levels_up
        self.parent_selects = 0
        self.calls: list[str] = []

    def transmit(self, apdu: str, silent: bool = False):
        del silent
        command = str(apdu).strip().upper()
        self.calls.append(command)
        if command == "00A4030000":
            self.parent_selects += 1
            return b"", 0x90, 0x00
        if command == "00A40004026F06":
            if self.parent_selects >= self.levels_up:
                return b"", 0x90, 0x00
            return b"", 0x6A, 0x82
        return b"", 0x6A, 0x82


class ArrReferencingTests(unittest.TestCase):
    """ETSI TS 102 221 v18.4 §9.2.7 access rule referencing."""

    def _controller(self, transport) -> FileSystemController:
        controller = FileSystemController.__new__(FileSystemController)
        controller.tp = transport
        controller.current_fcp = {}
        return controller

    def test_the_current_df_is_tried_first(self) -> None:
        transport = _ArrTransport(levels_up=0)
        self.assertTrue(self._controller(transport)._select_referenced_arr("6F06"))
        self.assertEqual(transport.calls, ["00A40004026F06"])

    def test_the_search_walks_up_to_the_parent_dfs(self) -> None:
        transport = _ArrTransport(levels_up=2)
        self.assertTrue(self._controller(transport)._select_referenced_arr("6F06"))
        self.assertEqual(
            transport.calls,
            [
                "00A40004026F06",
                "00A4030000",
                "00A40004026F06",
                "00A4030000",
                "00A40004026F06",
            ],
        )

    def test_the_walk_ends_where_select_parent_fails(self) -> None:
        class _NoParent:
            def __init__(self) -> None:
                self.calls: list[str] = []

            def transmit(self, apdu: str, silent: bool = False):
                del silent
                self.calls.append(str(apdu).strip().upper())
                return b"", 0x6A, 0x82

        transport = _NoParent()
        self.assertFalse(self._controller(transport)._select_referenced_arr("6F06"))
        self.assertEqual(transport.calls, ["00A40004026F06", "00A4030000"])

    def test_the_walk_is_bounded(self) -> None:
        transport = _ArrTransport(levels_up=99)
        self.assertFalse(self._controller(transport)._select_referenced_arr("6F06"))
        self.assertEqual(
            transport.parent_selects, FileSystemController.ARR_PARENT_SEARCH_DEPTH
        )


class RecordScanLimitTests(unittest.TestCase):
    """The FCP record count bounds a record loop; '6A83' stops it otherwise."""

    def _controller(self, fcp: dict) -> FileSystemController:
        controller = FileSystemController.__new__(FileSystemController)
        controller.current_fcp = dict(fcp)
        return controller

    def test_a_known_record_count_bounds_the_loop(self) -> None:
        self.assertEqual(self._controller({"rec_count": 4})._record_scan_limit(), 4)

    def test_an_unknown_record_count_falls_back_to_the_hard_limit(self) -> None:
        self.assertEqual(self._controller({})._record_scan_limit(), 254)
        self.assertEqual(self._controller({"rec_count": 0})._record_scan_limit(), 254)

    def test_a_count_above_the_hard_limit_is_clamped(self) -> None:
        self.assertEqual(self._controller({"rec_count": 900})._record_scan_limit(), 254)

    def test_a_non_numeric_count_falls_back(self) -> None:
        self.assertEqual(
            self._controller({"rec_count": "many"})._record_scan_limit(), 254
        )


class ResizeFileModeTests(unittest.TestCase):
    """ETSI TS 102 222 v17.1 §6.10.2.0 table 16a."""

    class _Transport:
        def __init__(self) -> None:
            self.apdus: list[str] = []

        def transmit(self, apdu: str, silent: bool = False):
            del silent
            self.apdus.append(apdu)
            return b"", 0x90, 0x00

    def _controller(self):
        transport = self._Transport()
        controller = FileSystemController.__new__(FileSystemController)
        controller.tp = transport
        return controller, transport

    def test_mode_defaults_to_zero(self) -> None:
        controller, transport = self._controller()
        controller.resize_file("6203830200FF")
        self.assertEqual(transport.apdus, ["80D40000" "06" "6203830200FF"])

    def test_mode_1_reaches_p1(self) -> None:
        controller, transport = self._controller()
        controller.resize_file("6203830200FF", mode=FileSystemController.RESIZE_FILE_MODE_1)
        self.assertEqual(transport.apdus, ["80D40100" "06" "6203830200FF"])

    def test_an_rfu_mode_is_refused_before_transmit(self) -> None:
        controller, transport = self._controller()
        with self.assertRaises(ValueError):
            controller.resize_file("6203830200FF", mode=2)
        self.assertEqual(transport.apdus, [])


class SeedFidMergeTests(unittest.TestCase):
    """A workspace FID tree keeps its entries and gains the shipped seed's names."""

    def test_missing_seed_names_are_added_and_operator_entries_survive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "fids.txt"
            workspace.write_text(
                "USIM:7FF0:A0000000871002FF34FF0789312E30FF\n"
                " EF_OPERATOR:6F99\n",
                encoding="utf-8",
            )
            seed = Path(temp_dir) / "seed.txt"
            seed.write_text(
                "USIM:7F99\n"
                " EF_NEWFILE:6FAA\n",
                encoding="utf-8",
            )

            controller = FileSystemController.__new__(FileSystemController)
            with mock.patch.object(Config, "FIDS_FILE", str(workspace)):
                with mock.patch.object(
                    Config,
                    "shipped_fids_seed_path",
                    staticmethod(lambda: str(seed)),
                ):
                    mapping = controller._load_fid_map()

            # A name only the shipped seed knows becomes usable.
            self.assertEqual(mapping["EF_NEWFILE"], ["6FAA"])
            self.assertEqual(mapping["NEWFILE"], ["6FAA"])
            # The operator's own entry is untouched.
            self.assertEqual(mapping["EF_OPERATOR"], ["6F99"])
            # A name both files carry keeps its FIDs: the seed's '7F99' is
            # not appended, and the built-in defaults plus the workspace
            # candidates survive in order.
            self.assertEqual(
                mapping["USIM"],
                ["7FF0", "7FFF", "A0000000871002FF34FF0789312E30FF"],
            )

    def test_a_missing_seed_file_is_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            workspace = Path(temp_dir) / "fids.txt"
            workspace.write_text("USIM:7FF0\n", encoding="utf-8")

            controller = FileSystemController.__new__(FileSystemController)
            with mock.patch.object(Config, "FIDS_FILE", str(workspace)):
                with mock.patch.object(
                    Config,
                    "shipped_fids_seed_path",
                    staticmethod(lambda: str(Path(temp_dir) / "absent.txt")),
                ):
                    mapping = controller._load_fid_map()

            self.assertEqual(mapping["USIM"], ["7FF0", "7FFF"])


class GpSeAccessControlTlvTests(unittest.TestCase):
    """ITU-T X.690 §8.1.2.5 against GlobalPlatform SE Access Control v1.1."""

    PRIMITIVE = TlvParser.GP_SE_ACCESS_CONTROL_PRIMITIVE_TAGS

    def test_b6_set_tags_are_constructed_by_default(self) -> None:
        # X.690 §8.1.2.5 leaves no room for a primitive 'E6', so without the
        # opt-in the value is decoded as a nested stream and fails.
        result = TlvParser.parse_detailed(bytes.fromhex("E603010200"))
        self.assertFalse(result["complete"])

    def test_device_interface_version_do_decodes_with_the_opt_in(self) -> None:
        # Table 6-12: 'E6', length 3, version '01 02 00' for v1.2.0.
        parsed = TlvParser.parse(
            bytes.fromhex("E603010200"), primitive_tags=self.PRIMITIVE
        )
        self.assertEqual(parsed, {0xE6: bytes.fromhex("010200")})

    def test_block_do_decodes_with_the_opt_in(self) -> None:
        # Table 6-13: 'E7', length 3, two bytes of offset then one of length.
        parsed = TlvParser.parse(
            bytes.fromhex("E70300FF20"), primitive_tags=self.PRIMITIVE
        )
        self.assertEqual(parsed, {0xE7: bytes.fromhex("00FF20")})

    def test_the_response_refresh_tag_do_needs_no_opt_in(self) -> None:
        # Annex B table B-1 'DF 20' Response-Refresh-Tag-DO; b6 of 'DF' is 0,
        # so the multi-byte tag is already primitive. Annex C.1 uses the
        # refresh tag value '01 02 03 04 05 06 07 08'.
        parsed = TlvParser.parse(bytes.fromhex("DF20080102030405060708"))
        self.assertEqual(parsed, {0xDF20: bytes.fromhex("0102030405060708")})

    def test_the_constructed_access_rule_objects_are_unaffected(self) -> None:
        # 'E2' REF-AR-DO holding 'E1' REF-DO ('4F' AID-REF-DO) and 'E3' AR-DO,
        # with the Annex C AID form A0 00 00 01 51 01.
        encoded = bytes.fromhex("E20C" "E1084F06A00000015101" "E300")
        expected = {0xE2: {0xE1: {0x4F: bytes.fromhex("A00000015101")}, 0xE3: {}}}
        self.assertEqual(TlvParser.parse(encoded), expected)
        self.assertEqual(
            TlvParser.parse(encoded, primitive_tags=self.PRIMITIVE), expected
        )

    def test_the_opt_in_reaches_nested_levels(self) -> None:
        # 'E2' carrying a Block-DO alongside a REF-DO.
        parsed = TlvParser.parse(
            bytes.fromhex("E20F" "E1084F06A00000015101" "E703000102"),
            primitive_tags=self.PRIMITIVE,
        )
        self.assertEqual(
            parsed,
            {
                0xE2: {
                    0xE1: {0x4F: bytes.fromhex("A00000015101")},
                    0xE7: bytes.fromhex("000102"),
                }
            },
        )

    def test_the_opt_in_is_validated(self) -> None:
        with self.assertRaises(TypeError):
            TlvParser.parse(b"\x90\x00", primitive_tags=["E6"])
        with self.assertRaises(ValueError):
            TlvParser.parse(b"\x90\x00", primitive_tags=[-1])


if __name__ == "__main__":
    unittest.main()


class ManagePinVerbSurfaceTests(unittest.TestCase):
    """The MANAGE-PIN macro reaches the TS 102 221 §11.1.9 / §11.1.11 forms."""

    def _shell(self):
        return mock.Mock()

    def test_retries_action_queries_the_counter(self) -> None:
        from SCP03.interface.shell_wizards import ShellInteractiveWizards

        shell = self._shell()

        with mock.patch("builtins.print"):
            ShellInteractiveWizards.run_manage_pin_wizard(shell, "retries 01")

        shell.sec_ctrl.get_pin_retry_counter.assert_called_once_with("01")

    def test_disable_accepts_an_alternative_global_key_reference(self) -> None:
        from SCP03.interface.shell_wizards import ShellInteractiveWizards

        shell = self._shell()

        with mock.patch("builtins.print"):
            ShellInteractiveWizards.run_manage_pin_wizard(shell, "disable 01 1234 11")

        shell.sec_ctrl.disable_pin.assert_called_once_with(
            "01", "1234", "ascii", replacement_ref="11"
        )

    def test_disable_without_replacement_keeps_the_plain_form(self) -> None:
        from SCP03.interface.shell_wizards import ShellInteractiveWizards

        shell = self._shell()

        with mock.patch("builtins.print"):
            ShellInteractiveWizards.run_manage_pin_wizard(shell, "disable 01 1234")

        shell.sec_ctrl.disable_pin.assert_called_once_with(
            "01", "1234", "ascii", replacement_ref=""
        )


class UnblockPinDigitRuleTests(unittest.TestCase):
    """TS 31.101 v19 §9.6: an UNBLOCK PIN always carries eight decimal digits."""

    def setUp(self) -> None:
        from SCP03.logic.security import SecurityController

        self.sent: list[str] = []

        class _Transport:
            def transmit(_self, apdu: str, silent: bool = False):
                self.sent.append(apdu.upper())
                return b"", 0x90, 0x00

        self.controller = SecurityController(_Transport())

    def test_eight_digit_puk_is_accepted(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()):
            self.controller.unblock_pin("01", "12345678", "1234")

        # INS '2C', P2 the key reference, Lc '10': the eight-digit UNBLOCK PIN
        # then the new PIN padded with 'FF' (TS 102 221 v18.4 §11.1.13).
        self.assertEqual(self.sent, ["002C000110313233343536373831323334FFFFFFFF"])

    def test_short_puk_is_refused_before_transmit(self) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.controller.unblock_pin("01", "1234", "1234")

        self.assertEqual(self.sent, [])
        self.assertIn("eight digits", output.getvalue())


class UnwrittenRecordPaddingTests(unittest.TestCase):
    """TS 102 221 v18.4 §13.4: unused bytes in a record are set to 'FF'."""

    def test_a_record_of_padding_only_is_empty_not_malformed(self) -> None:
        from SCP03.core.utils import TlvParser

        # An EF_DIR record the card has never written reads back as padding.
        # 'FF' also starts the high-tag-number form, so a strict parse reads it
        # as a tag that never ends.
        self.assertEqual(TlvParser.parse_padded(b"\xFF" * 36), {})

    def test_padding_after_a_template_still_parses(self) -> None:
        from SCP03.core.utils import TlvParser

        record = bytes.fromhex("61184F10A0000000871002FF34FF0789312E30FF50045553494D") + b"\xFF" * 8
        parsed = TlvParser.parse_padded(record)

        self.assertIn(0x61, parsed)

    def test_a_truncated_template_is_still_refused(self) -> None:
        from SCP03.core.utils import TlvParser

        with self.assertRaises(ValueError):
            TlvParser.parse_padded(bytes.fromhex("6118") + b"\x4F")
