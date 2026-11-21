# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Specification pins for the SCP03 transport, utilities, security and validator modules.

Every vector below was read from the standards library: ETSI TS 102 221
v18.4 (Annex D ATR examples, Tables 10.3 and 10.5 class bytes, §11.1.17
MANAGE CHANNEL, §10.2.1 status words, Table 9.3 key references, Table 11.2
SELECT P2, §13 MF-level files), 3GPP TS 31.102 v19.5 (§7.1.2 AUTHENTICATE,
§4.2 USIM files), 3GPP TS 31.103 v19 (§4.2.7 EF_IST), 3GPP TS 35.207 v19
test set 1, 3GPP TS 33.102 v19.1 §6.8.1.2, 3GPP TS 51.011 v4.15 §9.2 and
§9.4.1, and ETSI TS 102 222 v17.1 Table 6.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from SCP03.core.utils import StatusWordTranslator
from SCP03.logic.profile_validator import (
    ProfileValidator,
    export_default_policy_pack,
    parse_policy_pack,
)
from SCP03.logic.security import SecurityController
from SCP03.transport.card import CardTransporter


# 3GPP TS 35.207 v19 §4.3 / §5.3 / §6.3 test set 1 (K, RAND, OP, SQN, AMF and
# the f1..f5* outputs). These are published algorithm test data, not secrets.
MILENAGE_K = "465B5CE8B199B49FAA5F0A2EE238A6BC"
MILENAGE_RAND = "23553CBE9637A89D218AE64DAE47BF35"
MILENAGE_OP = "CDC202D5123E20F62B6D676AC72CB318"
MILENAGE_OPC = "CD63CB71954A9F4E48A5994E37A02BAF"
MILENAGE_SQN = "FF9BB4D0B607"
MILENAGE_AMF = "B9B9"
MILENAGE_F1 = "4A9FFAC354DFAFB3"
MILENAGE_F2 = "A54211D5E3BA50BF"
MILENAGE_F3 = "B40BA9A3C58B2A05BBF0D987B21BF8CB"
MILENAGE_F4 = "F769BCD751044604127672711C6D3441"
MILENAGE_F5 = "AA689C648370"
MILENAGE_F5_STAR = "451E8BECA43B"


def _xor_hex(left: str, right: str) -> str:
    return bytes(a ^ b for a, b in zip(bytes.fromhex(left), bytes.fromhex(right))).hex().upper()


def _atr_with_tck(body_hex: str) -> bytes:
    """Append the check byte: TCK is the XOR of every byte from T0 to the last historical byte."""
    body = bytes.fromhex(body_hex)
    tck = 0
    for octet in body[1:]:
        tck ^= octet
    return body + bytes([tck])


def _transporter_for_atr(atr: bytes) -> CardTransporter:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.get_atr_bytes = lambda: atr
    return transporter


class _ScriptedConnection:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.responses = list(responses)
        self.calls: list[bytes] = []

    def transmit(self, command: list[int]) -> tuple[bytes, int, int]:
        self.calls.append(bytes(command))
        return self.responses.pop(0)


class _BoundSession:
    """Authenticated session bound to one logical channel, with pass-through wrapping."""

    def __init__(self, channel: int) -> None:
        self.is_authenticated = True
        self.authenticated_channel = channel
        self.reset_calls = 0

    @staticmethod
    def logical_channel_from_cla(cla: int) -> int:
        if cla & 0x40:
            return 4 + (cla & 0x0F)
        return cla & 0x03

    @staticmethod
    def wrap_apdu(apdu: list[int]) -> list[int]:
        return list(apdu)

    @staticmethod
    def response_requires_rmac(_sw1: int, _sw2: int) -> bool:
        return False

    @staticmethod
    def unwrap_response(data: bytes, _sw1: int, _sw2: int) -> bytes:
        return bytes(data)

    def reset_state(self) -> None:
        self.reset_calls += 1
        self.is_authenticated = False


def _transporter(connection: _ScriptedConnection, session: object) -> CardTransporter:
    transporter = CardTransporter.__new__(CardTransporter)
    transporter.connection = connection
    transporter.session = session
    return transporter


class AtrGlobalInterfaceByteTests(unittest.TestCase):
    """TS 102 221 v18.4 §6.3.3 and Annex D: where the global interface bytes sit."""

    def test_annex_d_example_1_reads_ta3_after_t15_as_clock_stop(self) -> None:
        # Annex D example 1: T0 '97', TA1 '95', TD1 '80', TD2 '1F', TA3 '42'.
        atr = _atr_with_tck("3B97958 01F428031A073BE2115".replace(" ", ""))
        lines = _transporter_for_atr(atr).describe_atr()
        rendered = "\n".join(lines)

        self.assertIn("Fi=512, Di=16", rendered)
        self.assertIn("TA(3) = 42 --> Clock stop: state L", rendered)
        self.assertIn("Class accepted by the card: (3G) B 3V", rendered)
        self.assertIn("Application selection: by full DF name", rendered)
        self.assertIn("BER-TLV data objects available in EF.DIR", rendered)
        self.assertIn("Short EF identifier supported", rendered)
        self.assertIn("Maximum number of logical channels: 6", rendered)
        self.assertIn("(correct checksum)", rendered)

    def test_annex_d_example_2_reads_ta3_as_ifsc_and_ta4_as_global(self) -> None:
        # Annex D example 2: TD2 'B1' (T = 1) makes TA3 the IFSC; TD3 '1F' makes
        # TA4 the first global interface byte.
        atr = _atr_with_tck("3B979580B1FE001F428031A073BE2117")
        rendered = "\n".join(_transporter_for_atr(atr).describe_atr())

        self.assertIn("TA(3) = FE --> IFSC is 254 bytes long", rendered)
        self.assertIn("TB(3) = 00 --> T = 1 block/character waiting integers", rendered)
        self.assertIn("TA(4) = 42 --> Clock stop: state L", rendered)
        self.assertNotIn("TA(3) = FE --> Clock stop", rendered)
        self.assertIn("Maximum number of logical channels: 8 or more", rendered)

    def test_annex_d_example_3_specific_mode_and_no_logical_channels(self) -> None:
        # Annex D example 3: TD1 '91' announces TA2 '81' (specific mode) and T = 1;
        # T7 '00' reads "No logical channels supported".
        atr = _atr_with_tck("3B979591 81B1FE001F428031A073BE2100".replace(" ", ""))
        rendered = "\n".join(_transporter_for_atr(atr).describe_atr())

        self.assertIn("TA(2) = 81", rendered)
        self.assertIn("TA(3) = FE --> IFSC is 254 bytes long", rendered)
        self.assertIn("TA(4) = 42 --> Clock stop: state L", rendered)
        self.assertIn("Logical channels: not supported", rendered)
        self.assertNotIn("Maximum number of logical channels", rendered)

    def test_first_tb_after_t15_decodes_table_6_7(self) -> None:
        # T0 '90': TA1 and TD1, no historical bytes; TD2 '3F': TA3 and TB3 with T = 15.
        atr = _atr_with_tck("3B9095803F4282")
        rendered = "\n".join(_transporter_for_atr(atr).describe_atr())

        self.assertIn("TB(3) = 82 --> Global interface parameters (TS 102 221 Table 6.7)", rendered)
        self.assertIn("eUICC-related functions supported (SGP.22 / SGP.32)", rendered)

    def test_tb_table_6_7_bit_assignments(self) -> None:
        low_impedance = CardTransporter._decode_global_interface_tb(3, 0x90)
        self.assertTrue(any("Low impedance drivers" in line for line in low_impedance))
        usb = CardTransporter._decode_global_interface_tb(3, 0xC0)
        self.assertTrue(any("Inter-Chip USB" in line for line in usb))
        secured_apdu = CardTransporter._decode_global_interface_tb(3, 0x8C)
        self.assertTrue(any("Secured APDU - Platform to Platform required" in line for line in secured_apdu))
        secure_channel = CardTransporter._decode_global_interface_tb(3, 0x88)
        self.assertTrue(any("Secure Channel supported" in line for line in secure_channel))
        lsi = CardTransporter._decode_global_interface_tb(3, 0x81)
        self.assertTrue(any("LSIs supported" in line for line in lsi))
        none = CardTransporter._decode_global_interface_tb(3, 0x00)
        self.assertTrue(any("No additional global interface parameters" in line for line in none))

    def test_ta1_decodes_di_64_from_table_6_6(self) -> None:
        rendered = "\n".join(CardTransporter._decode_ta1(0x97))
        self.assertIn("Fi=512, Di=64", rendered)


class GetResponseClassByteTests(unittest.TestCase):
    """TS 102 221 v18.4 Table 10.5 and TS 51.011 v4.15 §9.2 / §9.4.1."""

    def test_gsm_class_a0_is_kept_for_get_response(self) -> None:
        self.assertEqual(CardTransporter._get_response_cla(0xA0), 0xA0)
        self.assertEqual(CardTransporter._get_response_cla(0xA2), 0xA2)
        # Table 10.3: b4/b3 secure-messaging bits are not part of GET RESPONSE.
        self.assertEqual(CardTransporter._get_response_cla(0xAC), 0xA0)

    def test_uicc_classes_collapse_to_interindustry_coding(self) -> None:
        self.assertEqual(CardTransporter._get_response_cla(0x80), 0x00)
        self.assertEqual(CardTransporter._get_response_cla(0x84), 0x00)
        self.assertEqual(CardTransporter._get_response_cla(0x01), 0x01)
        self.assertEqual(CardTransporter._get_response_cla(0xC0), 0x40)

    def test_9f_on_a_gsm_command_fetches_with_class_a0(self) -> None:
        connection = _ScriptedConnection(
            [
                (b"", 0x9F, 0x03),
                (b"\x01\x02\x03", 0x90, 0x00),
            ]
        )
        transporter = _transporter(connection, None)

        result = transporter.transmit_detailed("A0A40000023F00")

        self.assertEqual(result.data, b"\x01\x02\x03")
        self.assertEqual((result.sw1, result.sw2), (0x90, 0x00))
        self.assertEqual(connection.calls[1], bytes.fromhex("A0C0000003"))


class ManageChannelSessionTerminationTests(unittest.TestCase):
    """GPC v2.3.1 §10.2.3 with TS 102 221 v18.4 §11.1.17 P1/P2 coding."""

    def test_closing_the_bound_channel_terminates_the_session(self) -> None:
        session = _BoundSession(channel=1)
        connection = _ScriptedConnection([(b"", 0x90, 0x00)])
        transporter = _transporter(connection, session)

        result = transporter.transmit_detailed("01708001")

        self.assertTrue(result.session_invalidated)
        self.assertIn("MANAGE CHANNEL", str(result.invalidation_reason))
        self.assertEqual(session.reset_calls, 1)

    def test_closing_another_channel_keeps_the_session(self) -> None:
        session = _BoundSession(channel=1)
        connection = _ScriptedConnection([(b"", 0x90, 0x00)])
        transporter = _transporter(connection, session)

        result = transporter.transmit_detailed("01708002")

        self.assertFalse(result.session_invalidated)
        self.assertEqual(session.reset_calls, 0)

    def test_failed_close_keeps_the_session(self) -> None:
        session = _BoundSession(channel=1)
        connection = _ScriptedConnection([(b"", 0x6A, 0x86)])
        transporter = _transporter(connection, session)

        result = transporter.transmit_detailed("01708001")

        self.assertFalse(result.session_invalidated)
        self.assertEqual(session.reset_calls, 0)


class StatusWordTableTests(unittest.TestCase):
    """TS 102 221 v18.4 §10.2.1 wording, plus TS 102 222, GP and TS 51.011 words."""

    def test_ts_102_221_tables_10_7_to_10_15(self) -> None:
        translate = StatusWordTranslator.translate
        self.assertEqual(translate(0x90, 0x00), "Success")
        self.assertTrue(translate(0x93, 0x00).startswith("SIM Application Toolkit is busy"))
        self.assertEqual(translate(0x62, 0x82), "End of file/record reached before reading Le bytes or unsuccessful search")
        self.assertEqual(translate(0x62, 0x85), "Selected file in termination state")
        self.assertEqual(translate(0x62, 0xF1), "More data available")
        self.assertEqual(translate(0x63, 0xF2), "More data expected and proactive command pending")
        self.assertEqual(translate(0x65, 0x81), "Memory problem")
        self.assertEqual(translate(0x6B, 0x00), "Wrong parameter(s) P1-P2")
        self.assertEqual(translate(0x69, 0x81), "Command incompatible with file structure")
        self.assertEqual(translate(0x69, 0x86), "Command not allowed (no EF selected)")
        self.assertTrue(translate(0x69, 0x89).startswith("Command not allowed - secure channel"))
        self.assertEqual(translate(0x6A, 0x84), "Not enough memory space")
        self.assertEqual(translate(0x6A, 0x87), "Lc inconsistent with P1 to P2")
        self.assertEqual(translate(0x98, 0x62), "Authentication error, application specific")
        self.assertEqual(translate(0x98, 0x64), "Minimum UICC suspension time is too long")

    def test_length_bearing_status_words(self) -> None:
        translate = StatusWordTranslator.translate
        # Table 10.7: '91 XX' is a literal length, no 256 convention.
        self.assertIn("16 bytes of proactive-command", translate(0x91, 0x10))
        self.assertIn("0 bytes of proactive-command", translate(0x91, 0x00))
        self.assertIn("data transfer session", translate(0x92, 0x01))
        # TS 51.011 v4.15 §9.4.1
        self.assertIn("Length 28 of the response data", translate(0x9F, 0x1C))
        self.assertIn("SIM data download error", translate(0x9E, 0x10))
        # Table 10.11: SW2 other than '00' is command dependent.
        self.assertIn("command dependent", translate(0x67, 0x05))
        self.assertIn("command dependent", translate(0x6F, 0x01))
        # Unchanged '61xx' / '6Cxx' conventions (TS 102 221 v18.4 §7.3.1.1.5).
        self.assertIn("256", translate(0x61, 0x00))
        self.assertIn("Correct length is 16", translate(0x6C, 0x10))

    def test_admin_globalplatform_and_gsm_status_words(self) -> None:
        translate = StatusWordTranslator.translate
        # TS 102 222 v17.1 Table 6
        self.assertEqual(translate(0x6A, 0x89), "File ID already exists")
        self.assertEqual(translate(0x6A, 0x8A), "DF name already exists")
        # GPC v2.3.1 Table 11-38 and Amendment D v1.1.2 Table 7-7
        self.assertIn("More data available", translate(0x63, 0x10))
        self.assertEqual(translate(0x63, 0x00), "Authentication of host cryptogram failed")
        # TS 51.011 v4.15 §9.4.4 / §9.4.5
        self.assertIn("pattern not found", translate(0x94, 0x04))
        self.assertIn("CHV", translate(0x98, 0x04))
        self.assertIn("CHV blocked", translate(0x98, 0x40))


class _RecordingTransport:
    def __init__(self, responses: list[tuple[bytes, int, int]]) -> None:
        self.responses = list(responses)
        self.commands: list[str] = []

    def transmit(self, apdu_hex: str, silent: bool = False) -> tuple[bytes, int, int]:
        self.commands.append(apdu_hex.upper())
        return self.responses.pop(0)


class AuthenticateCommandCodingTests(unittest.TestCase):
    """TS 31.102 v19.5 §7.1.2 command and response coding."""

    def test_gsm_context_data_field_carries_the_rand_length(self) -> None:
        rand = "00112233445566778899AABBCCDDEEFF"
        transport = _RecordingTransport(
            [(bytes.fromhex("04" + "A1A2A3A4" + "08" + "B1B2B3B4B5B6B7B8"), 0x90, 0x00)]
        )
        controller = SecurityController(transport)

        with redirect_stdout(io.StringIO()):
            controller.run_auth(rand)

        # Lc '11' = L1 ('10') + 16 bytes of RAND; P2 '80' = GSM context (Table 7.1.2-1).
        self.assertEqual(transport.commands, ["008800801110" + rand + "00"])

    def test_3g_context_apdu_matches_table_7_1_2_1(self) -> None:
        rand = "00112233445566778899AABBCCDDEEFF"
        autn = "FFEEDDCCBBAA99887766554433221100"
        apdu = SecurityController.build_usim_auth_apdu(rand, autn)
        self.assertEqual(apdu, "0088008122" + "10" + rand + "10" + autn + "00")

    def test_response_decoders_follow_7_1_2_1(self) -> None:
        decode = SecurityController._decode_auth_response_data
        res = "A54211D5E3BA50BF"
        success = decode(bytes.fromhex("DB08" + res + "10" + MILENAGE_F3 + "10" + MILENAGE_F4 + "08" + "EAE4BE823AF9A08B"))
        self.assertEqual(success["status"], "success")
        self.assertEqual(success["kc"], bytes.fromhex("EAE4BE823AF9A08B"))

        without_kc = decode(bytes.fromhex("DB08" + res + "10" + MILENAGE_F3 + "10" + MILENAGE_F4))
        self.assertNotIn("kc", without_kc)

        sync = decode(bytes.fromhex("DC0E" + "BA853F3C1233" + "0010C1DA38A75A31"))
        self.assertEqual(sync["status"], "synchronization_failure")
        self.assertEqual(len(sync["auts"]), 14)

        gsm = decode(bytes.fromhex("04A1A2A3A4" + "08B1B2B3B4B5B6B7B8"))
        self.assertEqual(gsm["status"], "gsm_success")
        self.assertEqual(gsm["sres"], bytes.fromhex("A1A2A3A4"))


class MilenageSpecVectorTests(unittest.TestCase):
    """TS 35.207 v19 test set 1 through the offline USIM validator."""

    def test_opc_and_successful_exchange_recover_the_spec_sqn(self) -> None:
        self.assertEqual(SecurityController.derive_opc(MILENAGE_K, MILENAGE_OP), MILENAGE_OPC)

        autn = _xor_hex(MILENAGE_SQN, MILENAGE_F5) + MILENAGE_AMF + MILENAGE_F1
        apdu = SecurityController.build_usim_auth_apdu(MILENAGE_RAND, autn)
        exchange = SecurityController.validate_offline_usim_auth_apdu(
            apdu, MILENAGE_K, op_hex=MILENAGE_OP
        )

        self.assertEqual(exchange.result, "success")
        self.assertEqual(exchange.recovered_sqn, MILENAGE_SQN)
        self.assertEqual(exchange.res, MILENAGE_F2)
        self.assertEqual(exchange.ck, MILENAGE_F3)
        self.assertEqual(exchange.ik, MILENAGE_F4)

    def test_sync_failure_conceals_sqn_with_f5_star(self) -> None:
        # TS 31.102 v19.5 §7.1.1.1: Conc(SQNms) = SQNms xor f5*(RAND).
        autn = _xor_hex(MILENAGE_SQN, MILENAGE_F5) + MILENAGE_AMF + MILENAGE_F1
        apdu = SecurityController.build_usim_auth_apdu(MILENAGE_RAND, autn)
        stored_sqn = "FF9BB4D0B608"
        exchange = SecurityController.validate_offline_usim_auth_apdu(
            apdu, MILENAGE_K, op_hex=MILENAGE_OP, current_sqn_hex=stored_sqn
        )

        self.assertEqual(exchange.result, "sync_failure")
        self.assertEqual(exchange.auts[:12], _xor_hex(stored_sqn, MILENAGE_F5_STAR))
        self.assertTrue(exchange.response_payload.startswith("DC0E"))

    def test_c3_conversion_of_spec_ck_ik(self) -> None:
        # TS 33.102 v19.1 §6.8.1.2: Kc = CK1 xor CK2 xor IK1 xor IK2.
        expected = _xor_hex(
            _xor_hex(MILENAGE_F3[:16], MILENAGE_F3[16:]),
            _xor_hex(MILENAGE_F4[:16], MILENAGE_F4[16:]),
        )
        self.assertEqual(SecurityController.derive_gsm_kc(MILENAGE_F3, MILENAGE_F4), expected)
        self.assertEqual(expected, "EAE4BE823AF9A08B")


class PinKeyReferenceTests(unittest.TestCase):
    """TS 102 221 v18.4 Table 9.3 key references."""

    def test_table_9_3_values(self) -> None:
        normalize = SecurityController._normalize_pin_ref
        self.assertEqual(normalize("PIN1"), 0x01)
        self.assertEqual(normalize("PIN-APP3"), 0x03)
        self.assertEqual(normalize("ADM1"), 0x0A)
        self.assertEqual(normalize("ADM5"), 0x0E)
        self.assertEqual(normalize("UPIN"), 0x11)
        self.assertEqual(normalize("PIN2"), 0x81)
        self.assertEqual(normalize("SECOND-PIN-APP2"), 0x82)
        self.assertEqual(normalize("ADM6"), 0x8A)
        self.assertEqual(normalize("ADM10"), 0x8E)
        self.assertEqual(normalize("0A"), 0x0A)


class SmartSelectTests(unittest.TestCase):
    """TS 102 221 v18.4 Table 11.2 P2 coding and §13.1 EF_DIR record padding."""

    def test_selects_by_aid_with_fcp_return_and_tolerates_ff_padding(self) -> None:
        # 3GPP USIM AID (TS 101 220 v19 Annex E RID 'A000000087', PIX '1002')
        # whose last byte is 'FF', so stripping trailing 'FF' would truncate it.
        aid = "A0000000871002FFFFFFFF890700FFFF"
        record = "6112" + "4F10" + aid + "FF" * 12
        transport = _RecordingTransport(
            [
                (b"", 0x90, 0x00),
                (b"", 0x90, 0x00),
                (bytes.fromhex(record), 0x90, 0x00),
                (b"", 0x90, 0x00),
            ]
        )
        controller = SecurityController(transport)

        with redirect_stdout(io.StringIO()):
            selected = controller._smart_select_app("USIM")

        self.assertTrue(selected)
        self.assertEqual(transport.commands[0], "00A40004023F00")
        self.assertEqual(transport.commands[1], "00A40004022F00")
        self.assertEqual(transport.commands[-1], "00A4040410" + aid)


class _FakeTransport:
    def __init__(self, fs: "_FakeFs") -> None:
        self.fs = fs

    def transmit(self, apdu_hex: str, silent: bool = False) -> tuple[bytes, int, int]:
        entry = self.fs.entries[self.fs.current_path_hint]
        upper = apdu_hex.upper()
        if upper == "00B0000000":
            return bytes.fromhex(entry.get("binary", "")), 0x90, 0x00
        if upper.startswith("00B2"):
            records = entry.get("records", [])
            number = int(upper[4:6], 16)
            if number < 1 or number > len(records):
                return b"", 0x6A, 0x83
            return bytes.fromhex(records[number - 1]), 0x90, 0x00
        raise AssertionError(f"unexpected APDU {apdu_hex}")


class _FakeFs:
    def __init__(self, entries: dict) -> None:
        self.entries = {key.upper(): value for key, value in entries.items()}
        self.current_path_hint = "MF"
        self.current_fid = "3F00"
        self.current_fcp: dict = {}
        self.tp = _FakeTransport(self)

    def select(self, target_path: str, silent: bool = False) -> bool:
        key = target_path.strip().upper()
        if key not in self.entries:
            return False
        entry = self.entries[key]
        self.current_path_hint = key
        self.current_fid = entry.get("fid", key)
        self.current_fcp = dict(entry["meta"])
        return True


def _meta(file_type: str, structure: str, size: int = 0, sfi: str | None = None, rec_len: int = 0, rec_count: int = 0) -> dict:
    return {
        "type": file_type,
        "structure": structure,
        "size": size,
        "rec_len": rec_len,
        "rec_count": rec_count,
        "sfi": sfi,
        "lcs": "05",
        "security": "8B036F0602",
    }


def _run(validator: ProfileValidator, scope: str):
    with redirect_stdout(io.StringIO()):
        return validator.run(scope=scope)


class ValidatorSpecAlignmentTests(unittest.TestCase):
    def _mf_entries(self, pl_size: int) -> dict:
        return {
            "MF": {"fid": "3F00", "meta": _meta("DF", "Tree")},
            "EF_PL": {"fid": "2F05", "meta": _meta("EF", "Transparent", size=pl_size, sfi="05")},
            "EF_ICCID": {"fid": "2FE2", "meta": _meta("EF", "Transparent", size=10)},
            "EF_DIR": {"fid": "2F00", "meta": _meta("EF", "Linear Fixed", sfi="1E")},
            "EF_UMPC": {"fid": "2F08", "meta": _meta("EF", "Transparent", size=5, sfi="08")},
        }

    def test_mf_without_ef_arr_is_not_a_failure(self) -> None:
        # TS 102 221 v18.4 Table 13.5: EF_ARR at MF level is optional.
        findings = _run(ProfileValidator(_FakeFs(self._mf_entries(pl_size=8))), "MF")
        failures = [finding.path for finding in findings if finding.severity == "FAIL"]
        self.assertEqual(failures, [])

    def test_ef_pl_accepts_2n_bytes_and_flags_below_minimum(self) -> None:
        # TS 102 221 v18.4 Table 13.4: file size 2n bytes.
        findings = _run(ProfileValidator(_FakeFs(self._mf_entries(pl_size=8))), "MF")
        pl = [finding for finding in findings if finding.path == "EF_PL"]
        self.assertEqual(pl[0].severity, "PASS")

        findings = _run(ProfileValidator(_FakeFs(self._mf_entries(pl_size=1))), "MF")
        pl = [finding for finding in findings if finding.path == "EF_PL"]
        self.assertEqual(pl[0].severity, "WARN")
        self.assertIn("expected at least 2", pl[0].message)

    def test_usim_hpplmn_is_checked_without_service_12_and_fdn_sms_spn_have_no_sfi(self) -> None:
        # UST bytes: service n°2 (byte 1 b2), n°10 (byte 2 b2), n°19 (byte 3 b3);
        # service n°12 (SMSP) is not available.
        entries = {
            "ADF_USIM": {"fid": "7FF0", "meta": _meta("DF", "Tree")},
            "ADF_USIM/EF_UST": {"fid": "6F38", "meta": _meta("EF", "Transparent", size=3, sfi="04"), "binary": "020204"},
            "ADF_USIM/EF_HPPLMN": {"fid": "6F31", "meta": _meta("EF", "Transparent", size=1, sfi="12"), "binary": "0A"},
            "ADF_USIM/EF_FDN": {
                "fid": "6F3B",
                "meta": _meta("EF", "Linear Fixed", rec_len=26, rec_count=1),
                "records": ["FF" * 26],
            },
            "ADF_USIM/EF_SMS": {
                "fid": "6F3C",
                "meta": _meta("EF", "Linear Fixed", rec_len=176, rec_count=1),
                "records": ["00" + "FF" * 175],
            },
            "ADF_USIM/EF_SPN": {"fid": "6F46", "meta": _meta("EF", "Transparent", size=17)},
        }
        findings = _run(ProfileValidator(_FakeFs(entries)), "USIM")

        hpplmn = [finding for finding in findings if finding.path == "ADF_USIM/EF_HPPLMN"]
        self.assertTrue(hpplmn, "EF_HPPLMN must be validated regardless of UST service n°12")
        self.assertEqual(hpplmn[0].severity, "PASS")
        for path in ("ADF_USIM/EF_FDN", "ADF_USIM/EF_SMS", "ADF_USIM/EF_SPN"):
            messages = [finding.message for finding in findings if finding.path == path]
            self.assertTrue(messages, path)
            self.assertFalse(any("sfi=" in message for message in messages), path)
        smsp = [finding for finding in findings if finding.path == "ADF_USIM/EF_SMSP"]
        self.assertEqual(smsp, [])

    def test_isim_without_ef_ist_is_not_a_failure(self) -> None:
        # TS 31.103 v19 §4.2.7: EF_IST is optional.
        # ``run`` validates the MF core group in every scope, so the MF-level
        # files are part of the fixture; the ISIM check is what this test pins.
        entries = dict(self._mf_entries(pl_size=2))
        entries.update({
            "ADF_ISIM": {"fid": "7FF1", "meta": _meta("DF", "Tree")},
            "ADF_ISIM/EF_IMPI": {"fid": "6F02", "meta": _meta("EF", "Transparent", size=12, sfi="02")},
            "ADF_ISIM/EF_IMPU": {"fid": "6F04", "meta": _meta("EF", "Linear Fixed", rec_len=20, rec_count=1, sfi="04")},
            "ADF_ISIM/EF_DOMAIN": {"fid": "6F03", "meta": _meta("EF", "Transparent", size=12, sfi="05")},
            "ADF_ISIM/EF_AD": {"fid": "6FAD", "meta": _meta("EF", "Transparent", size=4, sfi="03"), "binary": "00000000"},
            "ADF_ISIM/EF_ARR": {"fid": "6F06", "meta": _meta("EF", "Linear Fixed", sfi="06")},
        })
        findings = _run(ProfileValidator(_FakeFs(entries)), "ISIM")
        failures = [finding.path for finding in findings if finding.severity == "FAIL"]
        self.assertEqual(failures, [])
        ad = [finding for finding in findings if finding.path == "ADF_ISIM/EF_AD"]
        # 3+X bytes (TS 31.103 v19 §4.2.5): a 4-byte file is not a size warning.
        self.assertFalse(any("size=" in finding.message for finding in ad))

    def test_min_size_round_trips_through_the_policy_pack(self) -> None:
        parsed = parse_policy_pack(export_default_policy_pack())
        pl = [entry for entry in parsed["mf"] if entry.path == "EF_PL"][0]
        self.assertEqual(pl.min_size, 2)
        self.assertIsNone(pl.size)
        self.assertEqual(parsed["mf"], ProfileValidator.MF_EXPECTATIONS)


if __name__ == "__main__":
    unittest.main()
