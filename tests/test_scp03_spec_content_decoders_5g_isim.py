# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Spec-vector coverage for the 5GS, ISIM, GBA and ARF decoders of ``ContentDecoder``.

Every vector is built from the layout tables of the cited clause:

* 3GPP TS 31.102 v19.5 §4.2.58 (PNN), §4.2.59 (OPL), §4.2.83 (GBANL),
  §4.2.92 (EPSNSC), §4.4.11.2 (5GS3GPPLOCI), §4.4.11.4 (5GS3GPPNSC),
  §4.4.11.6 (5GAUTHKEYS), §4.4.11.8 (SUCI_Calc_Info), §4.4.11.9 (OPL5G),
  §4.4.11.10 (SUPI_NAI), §4.4.11.13 (TN3GPPSNN), §4.4.11.18-§4.4.11.21.
* 3GPP TS 31.103 v19 §4.2.5 (AD), §4.2.7 (IST), §4.2.9 (GBABP), §4.2.23
  (IMSDCI) and the §4.3 file identifiers.
* 3GPP TS 24.501 v19.7 §9.11.3.34 and TS 24.301 v19.7 §9.9.3.23 (NAS
  security algorithms), TS 33.220 v19.1 Annex H (Ua security protocol
  identifier).
* GlobalPlatform SE Access Control v1.1 §7.1.3-§7.1.6 with the Annex C.3
  binary examples for ODF, DODF, ACMF, ACRF and ACCF.
"""

from __future__ import annotations

import json
import unittest

from SCP03.core.decoders import ContentDecoder


def tlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + bytes([len(value)]) + value


def json_body(lines: list) -> dict:
    return json.loads("\n".join(lines[1:]))["body"]


PLMN_001_01 = bytes.fromhex("00F110")
KEY_32 = bytes(range(0x40, 0x60))


def nas_context(*, system: str, ksi: int = 0x03, key: bytes = KEY_32) -> bytes:
    body = (
        tlv("80", bytes([ksi]))
        + tlv("81", key)
        + tlv("82", bytes.fromhex("00000010"))
        + tlv("83", bytes.fromhex("00000020"))
        + tlv("84", bytes([0x21]))
    )
    if system == "5GS":
        body += tlv("85", bytes([0x12])) + tlv("86", PLMN_001_01)
    return tlv("A0", body)


class NasSecurityContextTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.2.92 and §4.4.11.4 'A0' templates."""

    def test_epsnsc_decodes_ksi_counts_algorithms_and_kasme(self) -> None:
        decoded = ContentDecoder.decode_epsnsc(nas_context(system="EPS", ksi=5).hex())

        self.assertEqual(decoded["KSIasme"], 5)
        self.assertEqual(decoded["K_ASME"], KEY_32.hex().upper())
        self.assertEqual(decoded["K_ASME Length"], 32)
        self.assertEqual(decoded["Uplink NAS Count"], 16)
        self.assertEqual(decoded["Downlink NAS Count"], 32)
        # TS 24.301 v19.7 Table 9.9.3.23.1: b7-b5 = 010 -> 128-EEA2, b3-b1 = 001 -> 128-EIA1.
        self.assertEqual(decoded["NAS Security Algorithms"]["Ciphering"], "128-EEA2")
        self.assertEqual(decoded["NAS Security Algorithms"]["Integrity"], "128-EIA1")
        self.assertTrue(decoded["Valid"])
        self.assertNotIn("KSI / Header", decoded)

    def test_epsnsc_zero_length_kasme_is_invalid(self) -> None:
        decoded = ContentDecoder.decode_epsnsc(nas_context(system="EPS", key=b"").hex())

        self.assertFalse(decoded["Valid"])
        self.assertIn("length is 00", decoded["Status"])

    def test_5gs_nsc_decodes_5g_and_eps_algorithms_and_record_two_plmn(self) -> None:
        decoded = ContentDecoder.decode_5gs_nsc(nas_context(system="5GS").hex())

        self.assertEqual(decoded["ngKSI"], 3)
        self.assertEqual(decoded["K_AMF"], KEY_32.hex().upper())
        self.assertEqual(decoded["K_AMF Length"], 32)
        # TS 24.501 v19.7 Table 9.11.3.34.1: b8-b5 = 0010 -> 128-5G-EA2, b4-b1 = 0001 -> 128-5G-IA1.
        self.assertEqual(decoded["NAS Security Algorithms"]["Ciphering"], "128-5G-EA2")
        self.assertEqual(decoded["NAS Security Algorithms"]["Integrity"], "128-5G-IA1")
        self.assertEqual(decoded["EPS NAS Security Algorithms"]["Ciphering"], "128-EEA1")
        self.assertEqual(decoded["EPS NAS Security Algorithms"]["Integrity"], "128-EIA2")
        self.assertEqual(decoded["PLMN"], "001-01")
        self.assertTrue(decoded["Valid"])

    def test_5gs_nsc_invalid_markers(self) -> None:
        by_ksi = ContentDecoder.decode_5gs_nsc(nas_context(system="5GS", ksi=0x07).hex())
        by_fill = ContentDecoder.decode_5gs_nsc("FF" * 57)

        self.assertFalse(by_ksi["Valid"])
        self.assertIn("ngKSI '07'", by_ksi["Status"])
        self.assertFalse(by_fill["Valid"])

    def test_5g_auth_keys_report_validity_counters_and_key_bytes(self) -> None:
        body = (
            tlv("80", KEY_32)
            + tlv("81", KEY_32)
            + tlv("82", b"\xFF" * 32)
            + tlv("83", bytes.fromhex("0001"))
            + tlv("84", bytes.fromhex("FFFF"))
        )
        decoded = ContentDecoder.decode_5gs_auth_keys((body + b"\xFF" * 4).hex())

        self.assertEqual(decoded["K_AUSF"]["Length"], 32)
        self.assertTrue(decoded["K_AUSF"]["Valid"])
        self.assertTrue(decoded["K_SEAF (3GPP access)"]["Valid"])
        self.assertFalse(decoded["K_SEAF (non-3GPP access)"]["Valid"])
        self.assertEqual(decoded["SOR Counter"], 1)
        self.assertEqual(decoded["UE Parameter Update Counter"], "No valid counter (FF-filled)")
        self.assertEqual(decoded["K_AUSF"]["Value"], KEY_32.hex().upper())
        self.assertEqual(decoded["K_SEAF (non-3GPP access)"]["Value"], "FF" * 32)


class TelephonyFileTests(unittest.TestCase):

    def test_pnn_decodes_plmn_additional_information(self) -> None:
        # TS 31.102 v19.5 §4.2.58: tag '80' coded with a TS 31.101 UCS2 option.
        record = tlv("43", bytes([0x90]) + "Te".encode("utf-16-be")) + tlv(
            "80", bytes([0x80]) + "Ne".encode("utf-16-be")
        )
        decoded = ContentDecoder.decode_pnn(record.hex())

        self.assertEqual(decoded["Full Name"], "Te")
        self.assertEqual(decoded["PLMN Additional Information"], "Ne")
        self.assertEqual(decoded["PLMN Additional Information Encoding"], "UCS-2")

    def test_opl_and_opl5g_flag_the_entire_range_codings(self) -> None:
        # TS 31.102 v19.5 §4.2.59 '0000'/'FFFE' and §4.4.11.9 '000000'/'FFFFFE'.
        opl = ContentDecoder.decode_opl((PLMN_001_01 + bytes.fromhex("0000FFFE01")).hex())
        opl5g = ContentDecoder.decode_opl5g(
            (PLMN_001_01 + bytes.fromhex("000000FFFFFE01")).hex()
        )
        single = ContentDecoder.decode_opl((PLMN_001_01 + bytes.fromhex("12341234")).hex() + "01")

        self.assertEqual(opl["LAC Range"], "Entire range")
        self.assertEqual(opl5g["TAC Range"], "Entire range")
        self.assertEqual(single["LAC Range"], "Single value")

    def test_gbanl_splits_naf_id_into_fqdn_and_ua_protocol_identifier(self) -> None:
        # TS 33.220 v19.1 §5.3.2 NAF_Id = FQDN || Ua security protocol identifier;
        # Annex H.3 (0x01,0x00,0x00,0x00,0x02) is HTTP digest per TS 24.109.
        naf_id = b"naf.example.test" + bytes.fromhex("0100000002")
        decoded = ContentDecoder.decode_gbanl((tlv("80", naf_id) + tlv("81", b"tid1")).hex())

        self.assertEqual(decoded["NAF FQDN"], "naf.example.test")
        self.assertEqual(decoded["Ua Security Protocol Identifier"], "0100000002")
        self.assertEqual(decoded["Ua Security Protocol Organization"], "3GPP")
        self.assertEqual(decoded["B-TID"], "tid1")
        self.assertEqual(decoded["B-TID Encoding"], "UTF-8")
        self.assertEqual(decoded["B-TID Length"], 4)

    def test_5gs_loci_reserved_update_status_is_reported(self) -> None:
        encoded = "000B" + "F2" + "00F110" + "AA" + "BBCC" + "11223344" + "00F110" + "000001" + "03"
        decoded = ContentDecoder.decode_5gs_loci(encoded)

        self.assertEqual(decoded["Status"], "Reserved (3)")
        self.assertEqual(decoded["GUTI"]["AMF Set ID"], 0xBBCC >> 6)
        self.assertEqual(decoded["GUTI"]["AMF Pointer"], 0xBBCC & 0x3F)


class IsimFileTests(unittest.TestCase):

    def test_ist_service_22_is_named(self) -> None:
        decoded = ContentDecoder.decode_isim_ist("000020")

        self.assertEqual(decoded["active"], ["22: IMS Data Channel Indication"])

    def test_isim_ad_has_no_mnc_length_byte(self) -> None:
        decoded = ContentDecoder.decode_isim_ad("81000012")

        self.assertEqual(
            decoded["UE Operation Mode"], "Type approval operations + specific facilities"
        )
        self.assertEqual(decoded["Additional Information"], "0000")
        self.assertEqual(decoded["RFU"], "12")
        self.assertNotIn("Warning", decoded)

    def test_gbabp_decodes_rand_btid_and_lifetime(self) -> None:
        rand = bytes(range(16))
        encoded = (
            bytes([16]) + rand + bytes([5]) + b"btid1" + bytes([10]) + b"2026-01-01" + b"\xFF\xFF"
        )
        decoded = ContentDecoder.decode_gbabp(encoded.hex())

        self.assertEqual(decoded["RAND"], rand.hex().upper())
        self.assertEqual(decoded["RAND Length"], 16)
        self.assertEqual(decoded["B-TID"], "btid1")
        self.assertEqual(decoded["B-TID Encoding"], "UTF-8")
        self.assertEqual(decoded["B-TID Length"], 5)
        self.assertEqual(decoded["Key Lifetime"], "2026-01-01")

    def test_imsdci_values(self) -> None:
        self.assertEqual(
            ContentDecoder.decode_isim_imsdci("00")["IMS DC Establishment Indication"],
            "IMS data channel is not allowed",
        )
        self.assertIn("RFU", ContentDecoder.decode_isim_imsdci("07")["IMS DC Establishment Indication"])

    def test_isim_context_routes(self) -> None:
        ContentDecoder.init_registry()
        registry = ContentDecoder._registry

        self.assertIs(registry["ISIM/6FD5"], ContentDecoder.decode_gbabp)
        self.assertIs(registry["ISIM/6FD7"], ContentDecoder.decode_gbanl)
        self.assertIs(registry["ISIM/6FAD"], ContentDecoder.decode_isim_ad)
        self.assertIs(registry["ISIM/6FE7"], ContentDecoder.decode_isim_tlv80_text)
        self.assertIs(registry["ISIM/6F0A"], ContentDecoder.decode_tlv_as_map)
        self.assertIs(registry["ISIM/6F0B"], ContentDecoder.decode_isim_imsdci)
        self.assertIs(
            ContentDecoder._resolve_handler("6FAD", "MF/ADF.ISIM"),
            ContentDecoder.decode_isim_ad,
        )

    def test_usim_gbabp_routes_to_gbabp_decoder(self) -> None:
        # TS 31.102 v19.5 §4.2.79: EF_GBABP is '6FD6' under ADF_USIM; the ISIM
        # copy stays at 'ISIM/6FD5' (TS 31.103 v19 §4.2.9).
        ContentDecoder.init_registry()
        registry = ContentDecoder._registry

        self.assertIs(registry["6FD6"], ContentDecoder.decode_gbabp)
        self.assertIs(registry["ISIM/6FD5"], ContentDecoder.decode_gbabp)


class Df5gsFileTests(unittest.TestCase):

    def test_5gs_context_routes(self) -> None:
        ContentDecoder.init_registry()
        registry = ContentDecoder._registry

        self.assertIs(registry["5GS/4F07"], ContentDecoder.decode_suci_calc_info)
        self.assertIs(registry["5GS/4F09"], ContentDecoder.decode_supi_nai)
        self.assertIs(registry["5GS/4F0C"], ContentDecoder.decode_tn3gppsnn)
        self.assertIs(registry["5GS/4F10"], ContentDecoder.decode_5gs_edrx)
        self.assertIs(registry["5GS/4F11"], ContentDecoder.decode_5g_nswo_conf)
        self.assertIs(registry["5GS/4F15"], ContentDecoder.decode_mchpplmn)
        self.assertIs(registry["5GS/4F16"], ContentDecoder.decode_kausf_derivation)

    def test_suci_calc_info_lists_schemes_and_home_network_keys(self) -> None:
        key_a = bytes(range(32))
        key_b = bytes(range(32, 64))
        encoded = tlv("A0", bytes.fromhex("01010000")) + tlv(
            "A1",
            tlv("80", b"\x0A") + tlv("81", key_a) + tlv("80", b"\x0B") + tlv("81", key_b),
        )
        decoded = ContentDecoder.decode_suci_calc_info(encoded.hex())

        schemes = decoded["Protection Schemes"]
        self.assertEqual([entry["Scheme"] for entry in schemes], ["Profile <A>", "null-scheme"])
        self.assertEqual([entry["Key Index"] for entry in schemes], [1, 0])
        keys = decoded["Home Network Public Keys"]
        self.assertEqual([entry["Identifier"] for entry in keys], [10, 11])
        self.assertEqual(keys[1]["Public Key"], key_b.hex().upper())
        self.assertNotIn("Warnings", decoded)

    def test_suci_calc_info_flags_dangling_key_index(self) -> None:
        decoded = ContentDecoder.decode_suci_calc_info(tlv("A0", bytes.fromhex("0102")).hex())

        self.assertIn("Key index 2 exceeds the 0 listed key(s)", decoded["Warnings"])

    def test_supi_nai_identifier_types(self) -> None:
        nsi = ContentDecoder.decode_supi_nai(tlv("80", b"user@example.test").hex())
        gli = ContentDecoder.decode_supi_nai(tlv("81", b"gli.example.test").hex())

        self.assertEqual(nsi["SUPI Type"], "Network Specific Identifier")
        self.assertEqual(nsi["SUPI"], "user@example.test")
        self.assertEqual(gli["SUPI Type"], "Global Line Identifier")
        self.assertIn("Error", ContentDecoder.decode_supi_nai(tlv("83", b"x").hex()))

    def test_tn3gppsnn_counts_serving_network_names(self) -> None:
        names = [b"5G:mnc001.mcc001.3gppnetwork.org", b"5G:mnc999.mcc999.3gppnetwork.org"]
        encoded = bytes([2]) + tlv("80", names[0]) + tlv("80", names[1]) + b"\xFF\xFF"
        decoded = ContentDecoder.decode_tn3gppsnn(encoded.hex())
        mismatch = ContentDecoder.decode_tn3gppsnn((bytes([3]) + tlv("80", names[0])).hex())

        self.assertEqual(decoded["Count"], 2)
        self.assertEqual(decoded["Serving Network Names"], [name.decode() for name in names])
        self.assertNotIn("Warnings", decoded)
        self.assertIn("Count byte says 3 name(s) but 1 TLV(s) are encoded", mismatch["Warnings"])

    def test_single_byte_5gs_configuration_files(self) -> None:
        edrx = ContentDecoder.decode_5gs_edrx("0523")
        nswo = ContentDecoder.decode_5g_nswo_conf("01")
        multiplier = ContentDecoder.decode_mchpplmn("05")
        kausf = ContentDecoder.decode_kausf_derivation("01")

        self.assertTrue(edrx["NG-RAN"])
        self.assertTrue(edrx["Satellite NG-RAN"])
        self.assertEqual(edrx["eDRX Value"], 3)
        self.assertEqual(edrx["eDRX Cycle Length (N1 mode, seconds)"], "40.96")
        self.assertEqual(edrx["Paging Time Window"], 2)
        self.assertEqual(nswo["5G NSWO Usage Indicator"], "Enabled")
        self.assertEqual(multiplier["Multiplier Coefficient"], 5)
        self.assertEqual(
            ContentDecoder.decode_mchpplmn("00")["Multiplier Coefficient"], "Not defined"
        )
        self.assertEqual(kausf["KAUSF Derivation in SNPN"], "Use MSK")
        self.assertEqual(
            ContentDecoder.decode_kausf_derivation("00")["KAUSF Derivation in SNPN"],
            "Use EMSK",
        )
        self.assertIn("Warning", ContentDecoder.decode_5gs_edrx("0223"))


class AccessRuleFileTests(unittest.TestCase):
    """GlobalPlatform SE Access Control v1.1 Annex C.3 binary examples."""

    DODF_1 = (
        "A1293000300F0C0D4750205345204163632043746CA114301206 0A2A864886FC6B81480101"
        "3004040242 00"
    ).replace(" ", "")
    DODF_2 = (
        "A1293000300F0C0D4750205345204163632043746CA114301206 0A2A864886FC6B81480102"
        "3004040242 10"
    ).replace(" ", "")
    ACMF = "30100408010203040506070830040402 4300".replace(" ", "")
    ACRF = (
        "3008810030040402 4380"
        "3010A0080406A00000015101 30040402 4381"
        "3010A0080406A00000015102 30040402 4382"
        "3008820030040402 4383"
    ).replace(" ", "")
    ACCF = (
        "30160414" + "22" * 20
        + "30350414" + "33" * 20
        + "A01DA016A114040880F20000FFFFFFFF040880CA0000FFFF0000A103800100"
        + "3000"
    )

    def test_odf_lists_both_dodf_paths(self) -> None:
        body = json_body(ContentDecoder.decode_pkcs15_odf("A70630040402520 7A70630040402521 7".replace(" ", "")))

        self.assertEqual(body["objects"][0]["entry_type"], "data_objects")
        self.assertEqual(body["objects"][0]["paths"], ["5207", "5217"])

    def test_dodf_identifies_the_registered_arf_oids(self) -> None:
        first = json_body(ContentDecoder.decode_pkcs15_dodf(self.DODF_1))["data_objects"][0]
        second = json_body(ContentDecoder.decode_pkcs15_dodf(self.DODF_2))["data_objects"][0]

        self.assertEqual(first["oid"], "1.2.840.114283.200.1.1")
        self.assertIn("SHA-1", first["access_control_mechanism"])
        self.assertEqual(first["path"], "4200")
        self.assertEqual(first["application_name"], "GP SE Acc Ctl")
        self.assertEqual(first["oid_hex"], "2A864886FC6B81480101")
        self.assertEqual(second["oid"], "1.2.840.114283.200.1.2")
        self.assertIn("SHA-256", second["access_control_mechanism"])
        self.assertEqual(second["path"], "4210")

    def test_acmf_decodes_refresh_tag_and_any_rules_path(self) -> None:
        body = json_body(ContentDecoder.decode_pkcs15_acm(self.ACMF))
        other = json_body(ContentDecoder.decode_pkcs15_acm(self.ACMF[:-4] + "4310"))

        self.assertEqual(body["refresh_tag"], "0102030405060708")
        self.assertEqual(body["acrf_path"], "4300")
        self.assertEqual(body["rules_file"]["path"], "4300")
        self.assertEqual(other["acrf_path"], "4310")

    def test_acrf_decodes_every_rule_and_target_choice(self) -> None:
        rules = json_body(ContentDecoder.decode_pkcs15_acrf_json(self.ACRF))["rules"]

        self.assertEqual(len(rules), 4)
        self.assertEqual([rule["target_type"] for rule in rules], ["default", "aid", "aid", "others"])
        self.assertEqual(rules[1]["aid_ref"], "A00000015101")
        self.assertEqual([rule["accf_ref"] for rule in rules], ["4380", "4381", "4382", "4383"])

    def test_accf_decodes_conditions_hash_lengths_and_access_rules(self) -> None:
        entries = json_body(ContentDecoder.decode_pkcs15_accf_json(self.ACCF))["entries"]
        sha256 = json_body(ContentDecoder.decode_pkcs15_accf_json("30220420" + "00" * 32))["entries"]

        self.assertEqual(len(entries), 3)
        self.assertEqual(entries[0]["algo"], "sha1")
        self.assertFalse(entries[0]["applies_to_all_device_applications"])
        self.assertEqual(
            entries[1]["access_rules"]["apdu_filters"],
            [
                {"header": "80F20000", "mask": "FFFFFFFF"},
                {"header": "80CA0000", "mask": "FFFF0000"},
            ],
        )
        self.assertFalse(entries[1]["access_rules"]["nfc_permission"])
        self.assertTrue(entries[2]["applies_to_all_device_applications"])
        self.assertEqual(entries[2]["algo"], "none")
        self.assertEqual(sha256[0]["algo"], "sha256")

    def test_accf_permission_boolean_and_empty_file(self) -> None:
        # X.690 §8.2.2: a non-zero BOOLEAN octet is TRUE.
        condition = tlv("30", tlv("04", b"\x44" * 20) + tlv("A0", tlv("A0", tlv("80", b"\xFF"))))
        allow = json_body(ContentDecoder.decode_pkcs15_accf_json(condition.hex()))["entries"][0]
        empty = ContentDecoder.decode_pkcs15_accf_json("FFFF")

        self.assertTrue(allow["access_rules"]["apdu_permission"])
        self.assertIn("denies every device application", empty[0])


if __name__ == "__main__":
    unittest.main()
