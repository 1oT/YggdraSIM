# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""What the dissector decodes, asserted against real tshark output.

Assertions are field-level (``-T fields``) rather than whole-tree
goldens. A golden tree breaks on every tshark version bump for reasons
that have nothing to do with this dissector, whereas a field either
resolves to the expected value or it does not.

The capture is built once for the module: tshark process startup
dominates the runtime, and ``site-docs/internals/testing-guide.md`` caps
a module at 90 seconds of wall time.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.apdu_dissector_support import (
    AMBIGUOUS_EXCHANGE,
    BAD_TCK_ATR,
    STANDARD_ATR,
    TEST_ICCID,
    Exchange,
    decode_fields,
    decode_text,
    require_working_tshark,
    standard_corpus,
    swapped_bcd,
    write_capture,
)
from yggdrasim_common.apdu_risk import classify_apdu


class CatInstructionRiskNaming(unittest.TestCase):
    """The CAT proactive-loop instructions are named, not "unrecognised".

    FETCH, TERMINAL RESPONSE, ENVELOPE and TERMINAL PROFILE were absent
    from apdu_risk.py's table, so classify_apdu fell through to the
    "unrecognised instruction" default -- which surfaced in the
    dissector's risk-detail field as "unknown" on some of the commonest
    STK frames. They are write (the conservative default they already
    had), now named. Pure Python: no tshark needed.
    """

    def test_the_proactive_instructions_are_named(self) -> None:
        cases = {
            0x10: "TERMINAL PROFILE",
            0x12: "FETCH",
            0x14: "TERMINAL RESPONSE",
            0xC2: "ENVELOPE",
        }
        for ins, name in cases.items():
            result = classify_apdu(bytes([0x80, ins, 0x00, 0x00]))
            self.assertEqual(result["name"], name)
            self.assertNotEqual(result["name"], "unrecognised instruction")

    def test_they_stay_write_so_the_card_gate_is_unchanged(self) -> None:
        # Naming them must not loosen the MCP card gate or the prober:
        # they were write by default and stay write.
        for ins in (0x10, 0x12, 0x14, 0xC2):
            self.assertEqual(
                classify_apdu(bytes([0x80, ins, 0x00, 0x00]))["risk"], "write"
            )


class DecodeTestBase(unittest.TestCase):
    corpus: list[Exchange]
    capture: Path

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.corpus = standard_corpus()
        cls.capture = write_capture(
            Path(cls._directory.name) / "corpus.pcap",
            cls.corpus,
            atr=STANDARD_ATR,
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def rows(self, field_names: list[str]) -> list[list[str]]:
        return decode_fields(self.capture, field_names)


class EveryFrameDecodes(DecodeTestBase):
    def test_no_frame_is_dropped(self) -> None:
        """The instruction allowlist this replaces drops unknown INS values."""
        rows = self.rows(["frame.number", "yapdu.frame_kind"])
        self.assertEqual(len(rows), len(self.corpus) + 1, "one ATR plus the corpus")
        for row in rows:
            with self.subTest(frame=row[0]):
                self.assertIn(row[1], ("exchange", "ATR"))

    def test_the_atr_frame_is_recognised_as_an_atr(self) -> None:
        rows = self.rows(["frame.number", "yapdu.frame_kind"])
        self.assertEqual(rows[0][1], "ATR")

    def test_an_instruction_absent_from_the_tables_still_decodes(self) -> None:
        """0x80AB is deliberately not in _APDU_COMMANDS."""
        text = decode_text(self.capture, display_filter="yapdu.ins == 0xab")
        self.assertIn("INS_AB", text)
        self.assertIn("Status word: 9000", text)


class CommandHeaderDecoding(DecodeTestBase):
    def test_command_names_resolve(self) -> None:
        rows = self.rows(["yapdu.ins", "yapdu.command_name"])
        by_ins = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_ins.get("0xa4"), "SELECT")
        self.assertEqual(by_ins.get("0xc0"), "GET_RESPONSE")
        self.assertEqual(by_ins.get("0xb0"), "READ_BINARY")
        self.assertEqual(by_ins.get("0xd6"), "UPDATE_BINARY")

    def test_class_qualified_lookup_beats_the_bare_instruction(self) -> None:
        """0xE2 is STORE DATA under CLA 0x80, not the ETSI meaning."""
        text = decode_text(self.capture, display_filter="yapdu.ins == 0xe2")
        self.assertIn("STORE_DATA", text)
        # The defining specification is a filter-only field: naming the
        # standard under every command in a capture buries the decode.
        # Read it as a field rather than looking for it in the tree.
        sources = {
            row[0]: row[1]
            for row in self.rows(["yapdu.ins", "yapdu.command_source"])
            if len(row) > 1 and row[0]
        }
        self.assertIn("GlobalPlatform", sources.get("0xe2", ""))

    def test_iso_cases_are_classified(self) -> None:
        # Keyed by corpus label, not by command name: the corpus holds
        # two SELECTs of different cases on purpose, and a name-keyed
        # dict would silently keep only the last.
        cases = self.case_by_label()
        self.assertEqual(cases["select-adf-usim"], "4S")
        self.assertEqual(cases["get-response-fcp"], "2S")
        self.assertEqual(cases["update-binary"], "3S")
        self.assertEqual(cases["select-not-found"], "3S")
        self.assertEqual(cases["verify-case-1"], "1")

    def case_by_label(self) -> dict[str, str]:
        rows = self.rows(["yapdu.frame_kind", "yapdu.case"])
        exchanges = [row for row in rows if row and row[0] == "exchange"]
        return {
            self.corpus[index].label: row[1]
            for index, row in enumerate(exchanges)
            if len(row) > 1
        }

    def test_extended_length_is_detected(self) -> None:
        """An extended case 3 command must not read as case 2E.

        The case-hint table records UPDATE BINARY as 3S because that is
        what cards normally use. A 256-byte body forces the extended
        form, and the 2E reading of the same bytes produces a
        coincidental Le match, so only crediting the case family stops
        the wrong split from winning.
        """
        rows = self.rows(["yapdu.case", "yapdu.extended_length", "yapdu.lc"])
        extended = [row for row in rows if len(row) > 1 and row[1] == "True"]
        self.assertTrue(extended, "the extended-length exchange should be flagged")
        self.assertEqual(extended[0][0], "3E")
        self.assertEqual(extended[0][2], "256")

    def test_secure_messaging_is_read_from_the_class_byte(self) -> None:
        rows = self.rows(["yapdu.cla", "yapdu.cla.secure_messaging"])
        by_cla = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_cla.get("0x84"), "1")
        self.assertEqual(by_cla.get("0x00"), "0")

    def test_logical_channel_is_extracted(self) -> None:
        rows = self.rows(["yapdu.cla", "yapdu.cla.channel"])
        by_cla = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_cla.get("0x00"), "0")


class StatusWordDecoding(DecodeTestBase):
    def test_fixed_status_words_use_the_generated_table(self) -> None:
        text = decode_text(self.capture, display_filter="yapdu.sw == 0x6a82")
        self.assertIn("File not found", text)

    def test_the_61xx_family_reports_the_byte_count(self) -> None:
        """0x612B is not a table entry; SW2 is a length, not a code."""
        text = decode_text(self.capture, display_filter="yapdu.sw == 0x612b")
        self.assertIn("43 bytes available", text)

    def test_the_63cx_family_reports_the_retry_count(self) -> None:
        """Both readings of '63CX', told apart by the command half.

        ETSI TS 102 221 v18.4 clause 11.1.9.1.2: VERIFY PIN with an empty
        data field presents no PIN -- it reads the retry counter, and
        '63CX' is that counter. A modem asks it at bring-up, so calling
        the answer a failed verification made an ordinary probe read as a
        card that refused to authenticate. Clause 11.1.13.1.2 gives
        UNBLOCK PIN the same query form.
        """
        text = decode_text(self.capture, display_filter="yapdu.sw == 0x63c2")
        # The case-1 query and the 8-byte presentation both land here.
        self.assertIn("Retry counter: 2 attempts left", text)
        self.assertIn("Verification failed. 2 retries left", text)

    def test_the_retry_counter_query_names_itself_in_the_info_column(self) -> None:
        """The Info column is where an operator reads the trace.

        "VERIFY application PIN 1 (PIN1) -> 63C3 Verification failed" is
        what a rig's bring-up probe looked like; both halves now say it
        is a counter read (TS 102 221 v18.4 clauses 11.1.9.1.2, 11.1.13.1.2).
        """
        rows = decode_fields(self.capture, ["yapdu.ins", "_ws.col.info"])
        info_by_shape = [row[1] for row in rows if len(row) > 1 and row[0] == "0x20"]
        queries = [text for text in info_by_shape if "retry counter" in text]
        presentations = [text for text in info_by_shape if "retry counter" not in text]
        self.assertTrue(queries, info_by_shape)
        self.assertTrue(presentations, info_by_shape)

    def test_success_is_distinguished_from_failure(self) -> None:
        rows = self.rows(["yapdu.sw", "yapdu.sw_success"])
        by_sw = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_sw.get("0x9000"), "True")
        self.assertEqual(by_sw.get("0x6a82"), "False")
        self.assertEqual(by_sw.get("0x612b"), "True")

    def test_a_failed_verification_is_not_reported_as_success(self) -> None:
        """'63 CX' is a warning, and the command did not do what was asked.

        ISO/IEC 7816-4 clause 5.1.3 has four categories, and lumping the
        warnings in with normal processing made a failed PIN
        verification report "Succeeded: True" beside the text
        "Verification failed" -- and made a filter for failures miss
        every consumed retry and every blocked PIN on the card.
        """
        rows = self.rows(["yapdu.sw", "yapdu.sw_success"])
        by_sw = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_sw.get("0x63c2"), "False")

    def test_every_exchange_reports_a_status_word(self) -> None:
        """A body reader must not carry the status word away with it.

        The INITIALIZE UPDATE and FETCH readers each returned as soon as
        they had parsed their own structure, before the status word was
        added -- so every secure-channel opening and every FETCH in an
        SGP.32 trace was missing from `yapdu.sw != 0x9000`, the filter
        the documentation names for "every exchange the card did not
        accept", and showed a blank SW column in the bundled profile.
        """
        rows = self.rows(["yapdu.frame_kind", "yapdu.sw", "yapdu.command_name"])
        exchanges = [row for row in rows if row and row[0] == "exchange"]
        self.assertEqual(len(exchanges), len(self.corpus))
        missing = [row[2] for row in exchanges if not row[1]]
        self.assertEqual(missing, [], f"no status word on {missing}")

    def test_the_four_iso_categories_are_reported(self) -> None:
        rows = self.rows(["yapdu.sw", "yapdu.sw.category"])
        by_sw = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_sw.get("0x9000"), "normal")
        self.assertEqual(by_sw.get("0x63c2"), "warning")
        self.assertEqual(by_sw.get("0x6a82"), "checking error")


class RiskClassification(DecodeTestBase):
    """The risk field turns apdu_risk.py into a display filter."""

    def test_read_commands_are_classified_read(self) -> None:
        rows = self.rows(["yapdu.command_name", "yapdu.risk"])
        risks = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(risks.get("SELECT"), "1")
        self.assertEqual(risks.get("READ_BINARY"), "1")

    def test_write_commands_are_classified_write(self) -> None:
        rows = self.rows(["yapdu.command_name", "yapdu.risk"])
        risks = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(risks.get("UPDATE_BINARY"), "2")
        self.assertEqual(risks.get("STORE_DATA"), "2")

    def test_verify_is_destructive_because_it_burns_a_retry(self) -> None:
        rows = self.rows(["yapdu.command_name", "yapdu.risk"])
        risks = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(risks.get("VERIFY"), "3")

    def test_an_unknown_instruction_defaults_to_write(self) -> None:
        """apdu_risk.py: absence from the table is not evidence of safety."""
        rows = self.rows(["yapdu.ins", "yapdu.risk"])
        by_ins = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_ins.get("0xab"), "2")

    def test_destructive_commands_are_filterable(self) -> None:
        text = decode_text(self.capture, display_filter="yapdu.risk == 3")
        self.assertIn("VERIFY", text)
        # The expert item carries the reason from apdu_risk.py, which is
        # what tells an operator why the command is flagged.
        self.assertIn("consumes a PIN retry", text)
        self.assertIn("Severity level: Warning", text)


class SplitReporting(DecodeTestBase):
    def test_confidence_is_reported_for_every_exchange(self) -> None:
        rows = self.rows(["yapdu.frame_kind", "yapdu.split.confidence"])
        for row in rows:
            if len(row) > 1 and row[0] == "exchange":
                with self.subTest(row=row):
                    self.assertTrue(row[1], "every exchange reports a confidence")
                    self.assertGreaterEqual(int(row[1]), 0)

    def test_command_and_response_lengths_add_up(self) -> None:
        rows = self.rows(
            ["yapdu.frame_kind", "yapdu.split.command_len", "yapdu.split.response_len"]
        )
        exchanges = [row for row in rows if row[0] == "exchange"]
        self.assertEqual(len(exchanges), len(self.corpus))
        for index, row in enumerate(exchanges):
            entry = self.corpus[index]
            if entry.ambiguous:
                # No case hint exists for this instruction and both
                # readings are structurally valid, so an exact length is
                # not something the dissector can be held to. That the
                # ambiguity is reported is asserted in
                # AmbiguousSplitIsReported.
                continue
            with self.subTest(label=entry.label):
                self.assertEqual(int(row[1]), len(entry.command))
                self.assertEqual(int(row[2]), len(entry.response))

    def test_the_evidence_used_is_named(self) -> None:
        rows = self.rows(["yapdu.frame_kind", "yapdu.split.method"])
        methods = {row[1] for row in rows if row[0] == "exchange" and len(row) > 1}
        self.assertTrue(methods.issubset(
            {
                "case-hint",
                "case-family",
                "le-match",
                "sw-table",
                "sw-family",
                "requires-data",
                "structure",
            }
        ), methods)


class AtrDecoding(DecodeTestBase):
    def test_the_convention_byte_is_decoded(self) -> None:
        text = decode_text(self.capture, display_filter="yapdu.frame_kind == \"ATR\"")
        self.assertIn("direct convention", text)

    def test_interface_and_historical_bytes_are_broken_out(self) -> None:
        rows = self.rows(
            ["yapdu.frame_kind", "yapdu.atr.historical_count", "yapdu.atr.tck"]
        )
        atr_rows = [row for row in rows if row[0] == "ATR"]
        self.assertEqual(len(atr_rows), 1)
        self.assertEqual(atr_rows[0][1], "15")
        self.assertTrue(atr_rows[0][2], "a T=15 ATR carries a TCK")

    def test_the_check_byte_validates(self) -> None:
        rows = self.rows(["yapdu.frame_kind", "yapdu.atr.tck_valid"])
        atr_rows = [row for row in rows if row[0] == "ATR"]
        self.assertEqual(atr_rows[0][1], "True")

    def test_the_stock_dissector_is_not_fed_the_atr(self) -> None:
        """gsm_sim reads any payload as an APDU and invents a status word."""
        rows = decode_fields(
            self.capture, ["yapdu.frame_kind", "gsm_sim.apdu.ins"]
        )
        atr_rows = [row for row in rows if row[0] == "ATR"]
        self.assertEqual(len(atr_rows), 1)
        self.assertEqual(atr_rows[0][1], "", "gsm_sim must not decode an ATR")


class InfoColumn(DecodeTestBase):
    def test_the_info_column_summarises_the_exchange(self) -> None:
        rows = decode_fields(self.capture, ["_ws.col.Info"])
        joined = "\n".join(row[0] for row in rows if row)
        self.assertIn("SELECT", joined)
        self.assertIn("9000", joined)
        self.assertIn("ATR", joined)


class AmbiguousSplitIsReported(unittest.TestCase):
    """When the bytes do not decide, say so rather than guess quietly."""

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "ambiguous.pcap", [AMBIGUOUS_EXCHANGE]
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_the_frame_still_decodes(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.frame_kind"])
        self.assertEqual(rows[0][0], "exchange")

    def test_ambiguity_is_flagged(self) -> None:
        rows = decode_fields(
            self.capture, ["yapdu.split.ambiguous", "yapdu.split.confidence"]
        )
        self.assertEqual(rows[0][0], "True")
        self.assertLess(int(rows[0][1]), 100)

    def test_the_rejected_candidates_can_be_shown(self) -> None:
        text = decode_text(self.capture)
        self.assertIn("scored within 10 points", text)


class GsmClassByteIsDecoded(unittest.TestCase):
    """'AX' is channel- and SM-coded, not opaque.

    ETSI TS 102 221 table 10.3 lists three standard-channel classes --
    '0X', '8X' and 'AX' -- and gives all three the same shape: bits 4 and
    3 the secure-messaging indication, bits 2 and 1 the logical channel.
    'A0' is the class every GSM 11.11 command on a UICC carries, so
    treating the whole '90'-'BF' block as proprietary dropped the channel
    and the SM level from the oldest traffic in a trace. '90' and 'B0'
    are outside the table and stay opaque.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "gsm_class.pcap",
            [
                Exchange(bytes.fromhex("A0A40000023F00"), bytes.fromhex("9F0F")),
                Exchange(bytes.fromhex("A2B0000004"),
                         bytes.fromhex("11223344") + b"\x90\x00"),
                Exchange(bytes.fromhex("A4A40000023F00"), bytes.fromhex("9F0F")),
                Exchange(bytes.fromhex("90B0000004"),
                         bytes.fromhex("11223344") + b"\x90\x00"),
            ],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def rows(self) -> dict[str, list[str]]:
        decoded = decode_fields(
            self.capture,
            ["yapdu.cla", "yapdu.cla.channel", "yapdu.cla.secure_messaging"],
        )
        return {row[0]: row for row in decoded if row and row[0]}

    def test_the_gsm_class_reports_channel_zero(self) -> None:
        row = self.rows()["0xa0"]
        self.assertEqual(row[1], "0")
        self.assertEqual(row[2], "0")

    def test_a_logical_channel_is_read_from_the_low_bits(self) -> None:
        self.assertEqual(self.rows()["0xa2"][1], "2")

    def test_secure_messaging_is_read_from_bits_four_and_three(self) -> None:
        self.assertEqual(self.rows()["0xa4"][2], "1")

    def test_a_class_outside_the_table_stays_opaque(self) -> None:
        """'90' has no coding in table 10.3, so it reports none."""
        row = self.rows()["0x90"]
        self.assertEqual(row[1], "")
        self.assertEqual(row[2], "")


class BadAtrChecksum(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "badtck.pcap", [], atr=BAD_TCK_ATR
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_a_corrupted_check_byte_is_reported(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.atr.tck_valid"])
        self.assertEqual(rows[0][0], "False")

    def test_the_frame_is_still_decoded_as_an_atr(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.frame_kind"])
        self.assertEqual(rows[0][0], "ATR")


class StatusWordEdgeCases(unittest.TestCase):
    """Status words whose SW2 changes what SW1 means.

    Each of these was reported as its family's happy path: '61 00' as
    zero bytes waiting, '6C 00' as an instruction to send Le=0, '92 40'
    as a normal ending after 64 retries, and '9E XX' as nothing at all.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "status.pcap",
            [
                # 61 00: 256 bytes waiting, not zero.
                Exchange(bytes.fromhex("00A40004023F00"), bytes.fromhex("6100")),
                # 6C 00: retry with Le = 256.
                Exchange(bytes.fromhex("00B0000005"), bytes.fromhex("6C00")),
                # 92 40: a memory problem, not a retry count.
                Exchange(bytes.fromhex("00D6000002AABB"), bytes.fromhex("9240")),
                # 9E 1A: a SIM data download error carrying a length.
                Exchange(bytes.fromhex("80C2000005AABBCCDDEE"), bytes.fromhex("9E1A")),
                # 63 C0: no retries left, which is a blocked key.
                Exchange(bytes.fromhex("0020000108" + "00" * 8),
                         bytes.fromhex("63C0")),
            ],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def meanings(self) -> dict[str, str]:
        rows = decode_fields(self.capture, ["yapdu.sw", "yapdu.sw_meaning"])
        return {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}

    def test_sw2_zero_means_256_in_the_61xx_family(self) -> None:
        self.assertIn("256 bytes", self.meanings().get("0x6100", ""))

    def test_sw2_zero_means_256_in_the_6cxx_family(self) -> None:
        self.assertIn("Le = 256", self.meanings().get("0x6c00", ""))

    def test_9240_is_a_memory_problem_not_a_retry_count(self) -> None:
        """GSM 11.11 clause 9.4 splits '92': '0X' counts, '40' does not."""
        self.assertIn("Memory problem", self.meanings().get("0x9240", ""))

    def test_9240_is_classified_as_an_error(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.sw", "yapdu.sw_success"])
        by_sw = {row[0]: row[1] for row in rows if len(row) > 1 and row[0]}
        self.assertEqual(by_sw.get("0x9240"), "False")

    def test_9exx_is_described_as_a_download_error(self) -> None:
        self.assertIn("data download error", self.meanings().get("0x9e1a", ""))

    def test_63c0_says_the_key_is_blocked(self) -> None:
        self.assertIn("blocked", self.meanings().get("0x63c0", ""))


class CaseFourCommandsKeepTheirLe(unittest.TestCase):
    """A trailing Le is part of the command, not the response.

    Scoring the case hint as one string comparison made a hint of "3S"
    beat the true 4S reading by 20 points -- at confidence 100, with no
    ambiguity flag -- so an ES10b STORE DATA came out one byte short and
    its Le rendered as a one-byte response body.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls._directory = tempfile.TemporaryDirectory()
        cls.capture = write_capture(
            Path(cls._directory.name) / "case4.pcap",
            [
                Exchange(
                    bytes.fromhex("80E2910A0A") + bytes(range(10)) + b"\x00",
                    bytes.fromhex("9000"),
                ),
                Exchange(
                    bytes.fromhex("00D600000441424344") + b"\x00",
                    bytes.fromhex("9000"),
                ),
            ],
        )
        require_working_tshark(cls.capture)

    @classmethod
    def tearDownClass(cls) -> None:
        cls._directory.cleanup()

    def test_the_split_is_case_four(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.case"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["4S", "4S"])

    def test_the_le_is_present_rather_than_read_as_response_data(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.le", "yapdu.split.response_len"])
        for row in rows:
            with self.subTest(row=row):
                self.assertEqual(row[0], "0")
                self.assertEqual(row[1], "2")

    def test_the_command_body_is_not_a_byte_short(self) -> None:
        rows = decode_fields(self.capture, ["yapdu.split.command_len"])
        values = [row[0] for row in rows if row and row[0]]
        self.assertEqual(values, ["16", "10"])


class IccidRoundTrip(unittest.TestCase):
    """An odd-length ICCID must not break the decoder.

    Tools/EumDiag/dissector.lua divides the digit count by two and hands
    the result to a TvbRange, so a 19-digit ICCID either truncates or
    raises. The swapped-BCD helper here is the encoder side of the same
    problem.
    """

    def test_odd_length_iccid_survives_the_encoding(self) -> None:
        encoded = swapped_bcd(TEST_ICCID)
        self.assertEqual(len(encoded), 10)
        self.assertEqual(len(TEST_ICCID), 19)


if __name__ == "__main__":
    unittest.main()
