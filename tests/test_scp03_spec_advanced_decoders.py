# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Spec vectors for ``SCP03/core/decoders.py`` module helpers and ``AdvancedDecoders``.

Each case cites the clause it was read from:

* EF.ARR access rules -- TS 102 221 v18.4 clauses 9.2.2, 9.2.4, 9.2.5,
  tables 9.3 / 9.4 / 10.5, annex E.3.1; TS 102 222 v17.1 table 1.
* ARA-M data objects and ARF files -- GlobalPlatform SE Access Control v1.1
  tables 6-3, 6-4, 6-8, 6-9, 7-4, clauses 7.1.5 / 7.1.6, annex B table B-1.
* PLMN lists and location files -- TS 31.102 v19.5 clauses 4.2.5, 4.2.8,
  4.2.17, 4.2.23, 4.2.91; TS 24.008 v19.5 table 10.5.3; TS 24.301 v19.7
  figure 9.9.3.12.1.
* Network Name IE -- TS 24.008 v19.5 table 10.5.94; TS 23.038 v19
  clauses 6.2.1 and 6.2.1.1.
"""

from __future__ import annotations

import io
import unittest
from contextlib import redirect_stdout

from SCP03.core.decoders import (
    AdvancedDecoders,
    _decode_gsm7_packed,
    _decode_gsm7_septets,
    _decode_network_name_ie,
)


def _tlv(tag_hex: str, value_hex: str) -> str:
    value = bytes.fromhex(value_hex)
    return tag_hex + f"{len(value):02X}" + value_hex


def _pack_gsm7(septets: list[int]) -> bytes:
    packed = 0
    for index, septet in enumerate(septets):
        packed |= (septet & 0x7F) << (7 * index)
    byte_count = (7 * len(septets) + 7) // 8
    return packed.to_bytes(byte_count, "little")


class ArrAccessModeTests(unittest.TestCase):
    """TS 102 221 v18.4 clause 9.2.5 / annex E.2.1: b8 set makes b7-b4 proprietary."""

    def test_b8_set_does_not_name_the_high_bits(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("8001F19000"),
            ["READ/Proprietary(0xF0): Always"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("8001819000"),
            ["READ/Proprietary(0x80): Always"],
        )

    def test_b8_clear_keeps_naming_the_high_bits(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("8001789000"),
            ["DEACTIVATE/ACTIVATE/TERMINATE/DELETE_FILE: Always"],
        )


class ArrCommandHeaderTests(unittest.TestCase):
    """TS 102 221 v18.4 clause 9.2.2 / annex E.3.1: AM_DO tags '81'-'8F' and '9C'."""

    def test_cla_and_ins_header_is_decoded(self) -> None:
        # Tag '8C' = CLA and INS present; INS 'A4' is SELECT FILE (table 10.5).
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("8C0200A49000"),
            ["SELECT FILE (command header CLA=00 INS=A4): Always"],
        )

    def test_ins_only_header_names_admin_commands(self) -> None:
        # TS 102 222 v17.1 table 1: RESIZE FILE is INS 'D4'.
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("8401D49000"),
            ["RESIZE FILE (command header D4): Always"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("84013F9000"),
            ["Command header 3F: Always"],
        )

    def test_header_length_must_match_the_tag(self) -> None:
        decoded = AdvancedDecoders.decode_ef_arr("8C01A49000")
        self.assertEqual(len(decoded), 1)
        self.assertIn("command-header DO 8C must contain 2 byte(s)", decoded[0])

    def test_proprietary_state_machine_pairs_with_its_condition(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("9C0201029000"),
            ["Proprietary state machine (AM_DO 9C 0102): Always"],
        )

    def test_unknown_do_is_reported_instead_of_dropped(self) -> None:
        # Clause 9.2.4: the terminal ignores an unknown AM/SC combination.
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("80010190009901AA"),
            ["READ: Always", "ARR Decode Note: ignored unknown DO 99 (AA)"],
        )


class ArrSecurityConditionTests(unittest.TestCase):
    """TS 102 221 v18.4 tables 9.3 and 9.4."""

    def test_usage_qualifier_08_is_the_plain_pin_case(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A406830101950108"),
            ["READ: PIN1 (Application PIN 1)"],
        )

    def test_other_usage_qualifiers_are_named(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A406830101950100"),
            [
                "READ: PIN1 (Application PIN 1) "
                "[usage qualifier 00: verification requirement not used]"
            ],
        )
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A40683010A950180"),
            [
                "READ: ADM1 [usage qualifier 80: use verification / "
                "encipherment / external authentication]"
            ],
        )

    def test_rfu_key_references_are_named_as_rfu(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A406830109950108"),
            ["READ: RFU key reference (0x09)"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A406830112950108"),
            ["READ: RFU global key reference (0x12)"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A406830190950108"),
            ["READ: RFU local key reference (0x90)"],
        )

    def test_adm6_to_adm10_and_universal_pin(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A40683018E950108"),
            ["READ: ADM10"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_ef_arr("800101A406830111950108"),
            ["READ: Universal PIN"],
        )


class GpSeacDataObjectNameTests(unittest.TestCase):
    """GP SEAC v1.1 annex B table B-1."""

    def test_table_b1_names(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_gp_seac_arf("F100"),
            ["F1 Command-Delete"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_gp_seac_arf("FF4000"),
            ["FF40 Response-ALL-REF-AR-DO"],
        )
        self.assertEqual(
            AdvancedDecoders.decode_gp_seac_arf("C000"),
            ["C0 AID-REF-DO (implicitly selected application): "],
        )

    def test_tags_outside_the_spec_are_not_given_invented_names(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_gp_seac_arf("D201AA"),
            ["D2 Unknown: AA"],
        )


class AraRulesetTests(unittest.TestCase):
    """GP SEAC v1.1 tables 6-3, 6-4, 6-8, 6-9."""

    def test_empty_references_mean_all(self) -> None:
        ref_do = _tlv("E1", _tlv("4F", "") + _tlv("C1", ""))
        ar_do = _tlv("E3", _tlv("D0", "01") + _tlv("D1", "00"))
        payload = _tlv("FF40", _tlv("E2", ref_do + ar_do))
        decoded = AdvancedDecoders.decode_ara_rulesets(payload)
        self.assertEqual(len(decoded), 1)
        self.assertIn("AID=All (applets without a specific rule)", decoded[0])
        self.assertIn(
            "DeviceAppID=All (device applications without a specific rule)",
            decoded[0],
        )
        self.assertIn("APDU=always", decoded[0])
        self.assertIn("NFC=never", decoded[0])

    def test_device_app_id_length_names_the_hash(self) -> None:
        sha256 = "11" * 32
        ref_do = _tlv("E1", _tlv("4F", "A000000151") + _tlv("C1", sha256))
        ar_do = _tlv("E3", _tlv("D0", "00A40000FFFF0000"))
        payload = _tlv("FF40", _tlv("E2", ref_do + ar_do))
        decoded = AdvancedDecoders.decode_ara_rulesets(payload)
        self.assertIn(f"DeviceAppID={sha256.upper()} (SHA-256)", decoded[0])
        self.assertIn("APDU=filter 00A40000/FFFF0000", decoded[0])


class Pkcs15AcrfTests(unittest.TestCase):
    """GP SEAC v1.1 clause 7.1.5: Rule ::= SEQUENCE { target Target, conditionsFile Path }."""

    def test_aid_default_and_others_targets(self) -> None:
        aid_rule = _tlv("30", _tlv("A0", _tlv("04", "A000000151")) + _tlv("30", _tlv("04", "4310")))
        default_rule = _tlv("30", _tlv("81", "") + _tlv("30", _tlv("04", "4311")))
        others_rule = _tlv("30", _tlv("82", "") + _tlv("30", _tlv("04", "4312")))
        decoded = AdvancedDecoders.decode_pkcs15_acrf(aid_rule + default_rule + others_rule + "FFFF")
        self.assertEqual(
            decoded,
            [
                "Rule 1: Target=AID A000000151 | ACCF Ref=4310",
                "Rule 2: Target=Default (implicitly selected applet) | ACCF Ref=4311",
                "Rule 3: Target=Others (applets without a specific rule) | ACCF Ref=4312",
            ],
        )

    def test_path_index_and_length_are_shown(self) -> None:
        path = _tlv("30", _tlv("04", "4310") + _tlv("02", "00") + _tlv("80", "10"))
        rule = _tlv("30", _tlv("82", "") + path)
        decoded = AdvancedDecoders.decode_pkcs15_acrf(rule)
        self.assertEqual(decoded[0].split("ACCF Ref=")[1], "4310 index=0 length=16")


class Pkcs15AccfTests(unittest.TestCase):
    """GP SEAC v1.1 clause 7.1.6 and table 7-4."""

    def test_empty_file_denies_every_device_application(self) -> None:
        decoded = AdvancedDecoders.decode_pkcs15_accf("FFFF")
        self.assertIn("deny every device application", decoded[0])

    def test_condition_without_device_app_id_grants_any(self) -> None:
        self.assertEqual(
            AdvancedDecoders.decode_pkcs15_accf("3000"),
            [
                "Condition 1: DeviceAppID=Any device application | "
                "APDU=always (default, no access rules) | NFC=always (default)"
            ],
        )

    def test_explicit_apdu_and_nfc_permissions(self) -> None:
        digest = "22" * 32
        rules = _tlv("A0", _tlv("A0", _tlv("80", "FF")) + _tlv("A1", _tlv("80", "00")))
        condition = _tlv("30", _tlv("04", digest) + rules)
        decoded = AdvancedDecoders.decode_pkcs15_accf(condition)
        self.assertEqual(
            decoded,
            [f"Condition 1: DeviceAppID={digest} (SHA-256) | APDU=always | NFC=never"],
        )

    def test_apdu_filters_and_table_7_4_defaults(self) -> None:
        filters = _tlv("A0", _tlv("A0", _tlv("A1", _tlv("04", "00A40000FFFF0000"))))
        decoded = AdvancedDecoders.decode_pkcs15_accf(_tlv("30", filters))
        self.assertIn("APDU=filter 00A40000/FFFF0000", decoded[0])
        self.assertIn("NFC=always (default)", decoded[0])

        nfc_only = _tlv("A0", _tlv("A1", _tlv("80", "FF")))
        decoded = AdvancedDecoders.decode_pkcs15_accf(_tlv("30", nfc_only))
        self.assertIn("APDU=never (default, no APDU rule)", decoded[0])
        self.assertIn("NFC=always", decoded[0])

        apdu_never = _tlv("A0", _tlv("A0", _tlv("80", "00")))
        decoded = AdvancedDecoders.decode_pkcs15_accf(_tlv("30", apdu_never))
        self.assertIn("APDU=never", decoded[0])
        self.assertIn("NFC=never (default, APDU never)", decoded[0])


class PlmnListTests(unittest.TestCase):
    """TS 31.102 v19.5 clause 4.2.5 and TS 24.008 v19.5 table 10.5.3."""

    def test_abnormal_record_does_not_hide_the_rest(self) -> None:
        decoded = AdvancedDecoders.decode_plmn_list("0AF110" + "00F110", 3)
        self.assertEqual(len(decoded), 2)
        self.assertIn("invalid BCD digit in record 1 (raw 0AF110)", decoded[0])
        self.assertEqual(decoded[1], "MCC: 001, MNC: 01")

    def test_access_technology_bytes_follow_the_v19_5_layout(self) -> None:
        # Byte 4n: b8 UTRAN, b7-b5 E-UTRAN (table 4.2.5.1), b4 NG-RAN.
        decoded = AdvancedDecoders.decode_plmn_list("00F110" + "C800", 5)[0]
        self.assertIn("UTRAN", decoded)
        self.assertIn("E-UTRAN WB-S1", decoded)
        self.assertIn("E-UTRAN NB-S1", decoded)
        self.assertIn("NG-RAN", decoded)
        # Byte 5n: b8/b4/b3 GSM (table 4.2.5.2) -> '84' is GSM without EC-GSM-IoT.
        decoded = AdvancedDecoders.decode_plmn_list("00F110" + "0084", 5)[0]
        self.assertTrue(decoded.endswith("AcT: GSM"))


class LocationFileTests(unittest.TestCase):
    """TS 31.102 v19.5 clauses 4.2.17, 4.2.23, 4.2.91."""

    def test_loci_marks_a_deleted_lac(self) -> None:
        # TS 24.008 v19.5 table 10.5.3: 'FFFE' marks the LAI deleted.
        deleted = AdvancedDecoders.decode_loci("00000000" + "00F110" + "FFFE" + "FF" + "00")
        self.assertTrue(deleted["LAC Deleted"])
        live = AdvancedDecoders.decode_loci("00000000" + "00F110" + "0001" + "FF" + "00")
        self.assertFalse(live["LAC Deleted"])
        self.assertEqual(live["Status"], "Updated")

    def test_psloci_layout(self) -> None:
        decoded = AdvancedDecoders.decode_psloci(
            "01020304" + "AABBCC" + "00F110" + "0001" + "05" + "03"
        )
        self.assertEqual(decoded["P-TMSI"], "01020304")
        self.assertEqual(decoded["P-TMSI Signature"], "AABBCC")
        self.assertEqual(decoded["RAI"]["LAC"], "0001")
        self.assertEqual(decoded["RAI"]["RAC"], "05")
        self.assertEqual(decoded["Status"], "Routing Area Not Allowed")

    def test_epsloci_layout_follows_the_eps_mobile_identity(self) -> None:
        # TS 24.301 v19.7 figure 9.9.3.12.1: length, 'F6', PLMN, MME group,
        # MME code, M-TMSI; then TAI and the update status (010 = roaming not allowed).
        decoded = AdvancedDecoders.decode_epsloci(
            "0BF6" + "00F110" + "0001" + "02" + "00000001" + "00F110" + "0001" + "02"
        )
        self.assertEqual(decoded["GUTI"]["MME Group ID"], "0001")
        self.assertEqual(decoded["GUTI"]["MME Code"], "02")
        self.assertEqual(decoded["GUTI"]["M-TMSI"], "00000001")
        self.assertEqual(decoded["Last Visited TAI"]["TAC"], "0001")
        self.assertEqual(decoded["Status"], "Roaming Not Allowed")


class ServiceTableTests(unittest.TestCase):
    """TS 31.102 v19.5 clause 4.2.8 names services up to n°152."""

    def test_services_151_and_152_are_named(self) -> None:
        decoded = AdvancedDecoders.decode_ust("00" * 18 + "C0")
        self.assertEqual(
            decoded["active"],
            ["151: Operator-controlled-LSP-PLMN", "152: PeriodicSearchTimerNonLSP"],
        )


class NetworkNameTests(unittest.TestCase):
    """TS 24.008 v19.5 table 10.5.94 and TS 23.038 v19 clause 6.2.1."""

    def test_ucs2_ignores_the_spare_bit_count(self) -> None:
        decoded = _decode_network_name_ie(bytes.fromhex("93" + "00410042"))
        self.assertEqual(decoded["text"], "AB")
        self.assertNotIn("error", decoded)
        self.assertIn("note", decoded)

    def test_spare_bits_zero_carries_no_information(self) -> None:
        payload = _pack_gsm7([0x41, 0x42, 0x43])
        decoded = _decode_network_name_ie(b"\x80" + payload)
        self.assertEqual(decoded["text"], "ABC")
        self.assertEqual(decoded["note"], "spare-bit count not indicated; 3 trailing bit(s) ignored")

    def test_seven_spare_bits_may_carry_the_cr_padding(self) -> None:
        payload = _pack_gsm7([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x0D])
        self.assertEqual(len(payload), 7)
        self.assertEqual(_decode_gsm7_packed(payload, 7), "ABCDEFG")
        garbage = _pack_gsm7([0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x41])
        self.assertIsNone(_decode_gsm7_packed(garbage, 7))

    def test_escape_fallbacks(self) -> None:
        self.assertEqual(_decode_gsm7_septets([0x1B, 0x65]), "€")
        self.assertEqual(_decode_gsm7_septets([0x1B, 0x1B]), " ")
        self.assertEqual(_decode_gsm7_septets([0x41, 0x1B]), "A ")
        self.assertEqual(_decode_gsm7_septets([0x1B, 0x41]), "A")


class CplcPrintTests(unittest.TestCase):
    def test_print_cplc_unwraps_the_9f7f_tag(self) -> None:
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            AdvancedDecoders.print_cplc(bytes.fromhex("9F7F02AABB"))
        rendered = buffer.getvalue()
        self.assertIn("2 bytes", rendered)
        self.assertIn("AABB", rendered)


if __name__ == "__main__":
    unittest.main()
