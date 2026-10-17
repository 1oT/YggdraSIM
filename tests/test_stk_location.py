# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Location Information, PLMN coding and registration files of a simulated terminal."""
from __future__ import annotations

import random
import unittest

from yggdrasim_common.stk_location import (
    ACCESS_TECHNOLOGY_E_UTRAN,
    ACCESS_TECHNOLOGY_GSM,
    ACCESS_TECHNOLOGY_NG_RAN,
    ACCESS_TECHNOLOGY_UTRAN,
    access_technology_from_text,
    epsloci_with_identity,
    location_information,
    loci_with_identity,
    new_registration_identity,
    parse_location_information,
    parse_plmn_text,
    plmn_bytes,
    plmn_digits,
    psloci_with_identity,
    random_area,
    random_cell,
    rejection_location_information,
)

_TEST_PLMN = bytes.fromhex("00F110")  # 001/01


class PlmnCodingTests(unittest.TestCase):
    """TS 24.008 V19.5 §10.5.1.3, figure 10.5.3."""

    def test_two_and_three_digit_mnc(self) -> None:
        self.assertEqual(plmn_bytes("001", "01"), _TEST_PLMN)
        self.assertEqual(plmn_bytes("999", "99"), bytes.fromhex("99F999"))
        self.assertEqual(plmn_bytes("001", "001"), bytes.fromhex("001100"))

    def test_digits_round_trip(self) -> None:
        for mcc, mnc in (("001", "01"), ("999", "99"), ("001", "001")):
            with self.subTest(plmn=f"{mcc}/{mnc}"):
                self.assertEqual(plmn_digits(plmn_bytes(mcc, mnc)), (mcc, mnc))

    def test_operator_spellings(self) -> None:
        for text in ("001/01", "001-01", "00101"):
            with self.subTest(text=text):
                self.assertEqual(parse_plmn_text(text), ("001", "01"))
        with self.assertRaises(ValueError):
            parse_plmn_text("0010")


class LocationInformationTests(unittest.TestCase):
    """3GPP TS 31.111 V19.4.0 §8.19."""

    def test_geran_is_plmn_lac_cell(self) -> None:
        self.assertEqual(
            location_information(_TEST_PLMN, 0x0001, 0x0002, ACCESS_TECHNOLOGY_GSM),
            bytes.fromhex("00F110" "0001" "0002"),
        )

    def test_utran_adds_the_left_padded_rnc_id(self) -> None:
        self.assertEqual(
            location_information(_TEST_PLMN, 0x1234, 0x5678, ACCESS_TECHNOLOGY_UTRAN, rnc=0xABC),
            bytes.fromhex("00F110" "1234" "5678" "0ABC"),
        )

    def test_e_utran_eci_is_left_aligned_with_a_ones_nibble(self) -> None:
        # §8.19.3: MSB of the 28-bit ECI on the MSB of byte 8, the four least
        # significant bits of byte 11 set to 1.
        self.assertEqual(
            location_information(_TEST_PLMN, 0x0093, 0x370711E, ACCESS_TECHNOLOGY_E_UTRAN),
            bytes.fromhex("00F110" "0093" "370711EF"),
        )

    def test_ng_ran_has_a_three_byte_tac_and_a_left_aligned_nci(self) -> None:
        # §8.19.4: 24-bit TAC, 36-bit NCI ending on bit 4 of byte 13.
        self.assertEqual(
            location_information(_TEST_PLMN, 0x000102, 0x123456789, ACCESS_TECHNOLOGY_NG_RAN),
            bytes.fromhex("00F110" "000102" "123456789F"),
        )

    def test_values_parse_back(self) -> None:
        for rat, area, cell in (
            (ACCESS_TECHNOLOGY_GSM, 0x0001, 0x0002),
            (ACCESS_TECHNOLOGY_E_UTRAN, 0x0093, 0x370711E),
            (ACCESS_TECHNOLOGY_NG_RAN, 0x000102, 0x123456789),
        ):
            with self.subTest(rat=rat):
                value = location_information(_TEST_PLMN, area, cell, rat)
                self.assertEqual(parse_location_information(value, rat), (_TEST_PLMN, area, cell))

    def test_network_rejection_drops_the_cell(self) -> None:
        # §8.19.3 note: length '05' for E-UTRAN; §8.19.4 note 1: '03' for NG-RAN.
        self.assertEqual(
            rejection_location_information(_TEST_PLMN, 0x0093, ACCESS_TECHNOLOGY_E_UTRAN),
            bytes.fromhex("00F110" "0093"),
        )
        self.assertEqual(
            rejection_location_information(_TEST_PLMN, 0x000102, ACCESS_TECHNOLOGY_NG_RAN),
            _TEST_PLMN,
        )

    def test_drawn_areas_and_cells_fit_their_technology(self) -> None:
        rng = random.Random(7)
        for rat, bits in (
            (ACCESS_TECHNOLOGY_GSM, 16),
            (ACCESS_TECHNOLOGY_E_UTRAN, 28),
            (ACCESS_TECHNOLOGY_NG_RAN, 36),
        ):
            with self.subTest(rat=rat):
                cell = random_cell(rat, rng)
                self.assertLess(cell, 1 << bits)
                self.assertNotIn(cell, (0, (1 << bits) - 1))
        self.assertNotEqual(random_area(ACCESS_TECHNOLOGY_E_UTRAN, rng), 0)

    def test_access_technology_spellings(self) -> None:
        self.assertEqual(access_technology_from_text("lte"), ACCESS_TECHNOLOGY_E_UTRAN)
        self.assertEqual(access_technology_from_text("NR"), ACCESS_TECHNOLOGY_NG_RAN)
        self.assertEqual(access_technology_from_text("03"), ACCESS_TECHNOLOGY_UTRAN)
        with self.assertRaises(ValueError):
            access_technology_from_text("0D")


class RegistrationFileTests(unittest.TestCase):
    """TS 31.102 V19.5 §4.2.17, §4.2.23 and §4.2.91."""

    def setUp(self) -> None:
        self.identity = new_registration_identity(_TEST_PLMN, 0x0093, random.Random(7))

    def test_loci_keeps_the_rfu_byte_and_reads_updated(self) -> None:
        body = loci_with_identity(bytes.fromhex("FFFFFFFF99F9990001AA01"), self.identity)
        self.assertEqual(body[:4], self.identity.tmsi)
        self.assertEqual(body[4:9], _TEST_PLMN + bytes.fromhex("0093"))
        self.assertEqual(body[9:], bytes.fromhex("AA00"))

    def test_psloci_carries_the_rai(self) -> None:
        body = psloci_with_identity(bytes(14), self.identity)
        self.assertEqual(body[7:10], _TEST_PLMN)
        self.assertEqual(body[10:12], bytes.fromhex("0093"))
        self.assertEqual(body[12], self.identity.rac)
        self.assertEqual(body[13], 0x00)

    def test_epsloci_carries_the_guti_under_the_new_network(self) -> None:
        body = epsloci_with_identity(bytes(18), self.identity)
        self.assertEqual(body[:2], bytes.fromhex("0BF6"))
        self.assertEqual(body[2:5], _TEST_PLMN)
        self.assertEqual(body[12:17], _TEST_PLMN + bytes.fromhex("0093"))
        self.assertEqual(body[17], 0x00)

    def test_a_wrong_length_is_refused(self) -> None:
        with self.assertRaises(ValueError):
            loci_with_identity(bytes(10), self.identity)


if __name__ == "__main__":
    unittest.main()
