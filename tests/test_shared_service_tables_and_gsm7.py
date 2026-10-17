# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Shared UICC service tables, GSM 7-bit alphabet and access-rule key references.

Pins the three modules under ``yggdrasim_common`` that the live decoded view
and the profile inspector now both read, plus the elementary-file routing and
the SMS address corrections that landed with them:

  * ``service_table_names`` -- USIM (TS 31.102 v19.5 §4.2.8), Enabled Services
    (§4.2.47), 5G ProSe (§4.4.13.2), ISIM (TS 31.103 v19 §4.2.7) and legacy SIM
    (TS 51.011 v4.15 §10.3.7) service names, with pySim used only as a
    cross-check that no service number drifted.
  * ``gsm_alphabet`` -- TS 23.038 v19 §6.2.1/§6.2.1.1 and the Network Name IE
    of TS 24.008 v19.5 §10.5.3.5a table 10.5.94.
  * ``uicc_access_rules`` -- TS 102 221 v18.4 table 9.3 key references.
"""

from __future__ import annotations

import unittest

from SCP03.core.decoders import AdvancedDecoders, ContentDecoder
from SCP03.core.decoders import _decode_network_name_ie as scp03_network_name_ie
from Tools.ProfilePackage.saip_asn1_decode import (
    _decode_network_name_ie as saip_network_name_ie,
    arr_key_reference_name,
)
from yggdrasim_common.gsm_alphabet import (
    GSM7_DEFAULT_ALPHABET,
    GSM7_EXTENSION_TABLE,
    decode_gsm7_packed,
    decode_gsm7_septets,
    decode_gsm7_unpacked,
    decode_network_name_ie,
)
from yggdrasim_common.service_table_names import (
    SERVICE_TABLE_KEYS,
    service_table_metadata,
    service_table_names,
)
from yggdrasim_common.uicc_access_rules import key_reference_name


def _pysim_maps() -> dict[str, dict[int, str]]:
    """Return pySim's service maps, or an empty dict when pySim is absent."""
    tables: dict[str, dict[int, str]] = {}
    try:
        from pySim import ts_31_102, ts_31_103, ts_51_011
    except Exception:
        return tables
    for key, module, attribute in (
        ("UST", ts_31_102, "EF_UST_map"),
        ("EST", ts_31_102, "EF_EST_map"),
        ("5G_PROSE_ST", ts_31_102, "EF_5G_PROSE_ST_map"),
        ("IST", ts_31_103, "EF_IST_map"),
        ("SST", ts_51_011, "EF_SST_map"),
    ):
        candidate = getattr(module, attribute, None)
        if isinstance(candidate, dict):
            tables[key] = {int(k): str(v) for k, v in candidate.items()}
    return tables


class SharedServiceTableTests(unittest.TestCase):
    """One clause-sourced copy of every service-bit table."""

    def test_every_table_covers_its_clause_range(self) -> None:
        expected = {
            "UST": (152, "USIM Service Table", "3GPP TS 31.102 §4.2.8"),
            "EST": (3, "Enabled Services Table", "3GPP TS 31.102 §4.2.47"),
            "IST": (22, "ISIM Service Table", "3GPP TS 31.103 §4.2.7"),
            "5G_PROSE_ST": (13, "5G ProSe Service Table", "3GPP TS 31.102 §4.4.13.2"),
            "SST": (59, "SIM Service Table", "3GPP TS 51.011 §10.3.7"),
        }
        self.assertEqual(set(SERVICE_TABLE_KEYS), set(expected))
        for key, (count, full_name, spec) in expected.items():
            names = service_table_names(key, style="spec")
            self.assertEqual(sorted(names), list(range(1, count + 1)), key)
            self.assertEqual(service_table_metadata(key), (full_name, spec), key)

    def test_unknown_table_has_no_names_or_metadata(self) -> None:
        self.assertEqual(service_table_names("does-not-exist"), {})
        self.assertIsNone(service_table_metadata("does-not-exist"))

    def test_accessor_returns_an_independent_copy(self) -> None:
        first = service_table_names("UST")
        first[1] = "scribbled"
        self.assertEqual(service_table_names("UST")[1], "Local Phone Book")

    def test_style_must_be_short_or_spec(self) -> None:
        with self.assertRaises(ValueError):
            service_table_names("UST", style="verbose")

    def test_short_labels_stay_the_shipped_operator_wording(self) -> None:
        short = service_table_names("UST")
        self.assertEqual(short[2], "FDN")
        self.assertEqual(short[1], "Local Phone Book")
        self.assertEqual(short[152], "PeriodicSearchTimerNonLSP")
        self.assertEqual(service_table_names("IST")[2], "GBA")

    def test_spec_style_carries_the_clause_wording(self) -> None:
        spec = service_table_names("UST", style="spec")
        self.assertEqual(spec[2], "Fixed Dialling Numbers (FDN)")
        self.assertEqual(spec[125], "SUCI calculation by the USIM")
        self.assertEqual(spec[139], "5G ProSe")
        self.assertEqual(spec[146], "Network Identifier for SNPN (NID)")
        self.assertEqual(
            service_table_names("IST", style="spec")[2],
            "Generic Bootstrapping Architecture (GBA)",
        )
        self.assertEqual(service_table_names("SST", style="spec")[38], "GPRS")
        self.assertEqual(
            service_table_names("5G_PROSE_ST", style="spec")[8],
            "UICC 5G ProSe direct communication usage information reporting",
        )


class PySimServiceNumberCrossCheckTests(unittest.TestCase):
    """pySim is a cross-check on the numbering, never the runtime source."""

    def setUp(self) -> None:
        self.pysim = _pysim_maps()
        if not self.pysim:
            self.skipTest("pySim not installed")

    def test_shared_tables_cover_every_pysim_service_number(self) -> None:
        for key, upstream in self.pysim.items():
            shared = service_table_names(key, style="spec")
            self.assertTrue(
                set(upstream) <= set(shared),
                f"{key}: pySim names services {sorted(set(upstream) - set(shared))} "
                "that the shared table does not",
            )

    def test_shared_tables_extend_past_pysim_where_the_clause_does(self) -> None:
        # pySim trails the current releases on the two tables that grew.
        self.assertGreater(len(service_table_names("UST")), len(self.pysim["UST"]))
        self.assertGreater(
            len(service_table_names("5G_PROSE_ST")), len(self.pysim["5G_PROSE_ST"])
        )
        for key in ("EST", "IST", "SST"):
            self.assertGreaterEqual(
                len(service_table_names(key)), len(self.pysim[key]), key
            )


class ServiceTableDecoderWiringTests(unittest.TestCase):
    """The shipped decoders read the shared tables."""

    def test_ust_keeps_its_short_labels_and_gains_the_clause_wording(self) -> None:
        decoded = AdvancedDecoders.decode_ust("02")
        self.assertEqual(decoded["active"], ["2: FDN"])
        self.assertEqual(decoded["active_spec_names"], ["2: Fixed Dialling Numbers (FDN)"])
        self.assertEqual(decoded["full_name"], "USIM Service Table")
        self.assertEqual(decoded["spec"], "3GPP TS 31.102 §4.2.8")
        self.assertIn("1: Local Phone Book", decoded["inactive"])

    def test_est_and_ist_report_the_same_shape(self) -> None:
        est = AdvancedDecoders.decode_est("01")
        self.assertEqual(est["table"], "EST")
        self.assertEqual(est["active"], ["1: Fixed Dialling Numbers (FDN)"])
        ist = ContentDecoder.decode_isim_ist("02")
        self.assertEqual(ist["table"], "IST")
        self.assertEqual(ist["active"], ["2: GBA"])
        self.assertEqual(
            ist["active_spec_names"], ["2: Generic Bootstrapping Architecture (GBA)"]
        )

    def test_encoder_without_a_table_keeps_its_original_sizing(self) -> None:
        self.assertEqual(AdvancedDecoders.encode_service_table([1, 2]), "03")
        self.assertEqual(
            AdvancedDecoders.encode_service_table([2], total_bytes=4), "02000000"
        )
        self.assertEqual(
            AdvancedDecoders.encode_service_table([9], current_hex="0000"), "0001"
        )

    def test_encoder_sizes_a_named_table_to_its_clause_range(self) -> None:
        # 152 USIM services need nineteen bytes, 22 ISIM services three.
        self.assertEqual(
            len(bytes.fromhex(AdvancedDecoders.encode_service_table([2], table="UST"))),
            19,
        )
        self.assertEqual(
            len(bytes.fromhex(AdvancedDecoders.encode_service_table([1], table="IST"))),
            3,
        )
        # An explicit width still wins, so an existing body keeps its size.
        self.assertEqual(
            AdvancedDecoders.encode_service_table([2], table="UST", total_bytes=2),
            "0200",
        )

    def test_encoder_refuses_a_service_the_clause_does_not_name(self) -> None:
        with self.assertRaises(ValueError):
            AdvancedDecoders.encode_service_table([153], table="UST")
        with self.assertRaises(ValueError):
            AdvancedDecoders.encode_service_table([4], table="EST")
        with self.assertRaises(ValueError):
            AdvancedDecoders.encode_service_table([1], table="no-such-table")

    def test_bits_past_the_named_range_still_surface(self) -> None:
        decoded = ContentDecoder.decode_isim_ist("000004")
        self.assertEqual(decoded["active"], ["19: XCAP configuration data"])
        decoded = ContentDecoder.decode_isim_ist("00000004")
        self.assertEqual(decoded["active"], ["27: Service 27"])
        self.assertNotIn("active_spec_names", decoded)


class Gsm7AlphabetTests(unittest.TestCase):
    """TS 23.038 v19 §6.2.1 and §6.2.1.1."""

    def test_table_shape(self) -> None:
        self.assertEqual(len(GSM7_DEFAULT_ALPHABET), 128)
        self.assertEqual(GSM7_DEFAULT_ALPHABET[0], "@")
        self.assertEqual(GSM7_DEFAULT_ALPHABET[0x1B], "\x1b")
        self.assertEqual(GSM7_EXTENSION_TABLE[0x65], "€")

    def test_escape_selects_the_extension_table(self) -> None:
        self.assertEqual(decode_gsm7_septets([0x1B, 0x65]), "€")
        self.assertEqual(decode_gsm7_septets([0x1B, 0x28]), "{")

    def test_unassigned_extension_falls_back_to_the_main_table(self) -> None:
        # Clause 6.2.1.1: a receiver shows the main-table character rather
        # than dropping the pair or failing the whole decode.
        self.assertEqual(decode_gsm7_septets([0x41, 0x1B, 0x42, 0x43]), "ABC")
        self.assertEqual(decode_gsm7_unpacked(bytes([0x41, 0x1B, 0x42])), None)

    def test_double_escape_and_trailing_escape_are_spaces(self) -> None:
        self.assertEqual(decode_gsm7_septets([0x1B, 0x1B]), " ")
        self.assertEqual(decode_gsm7_septets([0x41, 0x1B]), "A ")

    def test_septet_values_outside_the_alphabet_are_rejected(self) -> None:
        self.assertIsNone(decode_gsm7_septets([0x80]))

    def test_packed_unpacking_honours_the_spare_bit_count(self) -> None:
        # "ABCDEFG" is seven septets in seven octets, so seven spare bits.
        self.assertEqual(decode_gsm7_packed(bytes.fromhex("41E19058341E01"), 7), "ABCDEFG")
        self.assertEqual(decode_gsm7_packed(bytes.fromhex("C834"), 2), "Hi")
        # Eight septets fill eight octets exactly, so no bits are spare.
        self.assertEqual(
            decode_gsm7_packed(bytes.fromhex("41E19058341E91"), 0), "ABCDEFGH"
        )

    def test_a_spare_bit_count_that_cannot_hold_whole_septets_is_rejected(self) -> None:
        self.assertIsNone(decode_gsm7_packed(bytes.fromhex("C834"), 3))
        self.assertIsNone(decode_gsm7_packed(bytes.fromhex("41E19058341E01"), 3))
        self.assertIsNone(decode_gsm7_packed(b"\x00", 8))

    def test_a_carriage_return_may_pad_seven_spare_bits(self) -> None:
        # Table 10.5.94: 7 spare bits may carry the CR the network added to
        # reach the octet boundary, so the padding is not an error.
        self.assertIsNotNone(decode_gsm7_packed(bytes.fromhex("41E19058341E01"), 7))
        self.assertIsNone(decode_gsm7_packed(bytes.fromhex("41E19058341E31"), 7))


class NetworkNameIeTests(unittest.TestCase):
    """TS 24.008 v19.5 §10.5.3.5a table 10.5.94, shared by both call sites."""

    def test_extension_bit_must_be_set(self) -> None:
        self.assertIsNone(decode_network_name_ie(b"AB"))
        self.assertIsNone(decode_network_name_ie(b""))

    def test_coding_scheme_and_flags_come_from_octet_three(self) -> None:
        decoded = decode_network_name_ie(bytes([0x8F]) + bytes.fromhex("41E19058341E01"))
        assert decoded is not None
        self.assertEqual(decoded.coding_scheme, 0)
        self.assertTrue(decoded.add_country_initials)
        self.assertEqual(decoded.spare_bits, 7)
        self.assertEqual(decoded.text, "ABCDEFG")

    def test_spare_bit_count_is_ignored_for_ucs2(self) -> None:
        decoded = decode_network_name_ie(bytes([0x91]) + "Hi".encode("utf-16-be"))
        assert decoded is not None
        self.assertEqual(decoded.text, "Hi")
        self.assertEqual(decoded.note, "spare-bit count ignored for UCS-2")

    def test_both_call_sites_read_the_same_octets(self) -> None:
        ie = bytes([0x87]) + bytes.fromhex("41E19058341E01")
        live = scp03_network_name_ie(ie)
        inspector = saip_network_name_ie(ie)
        assert inspector is not None
        self.assertEqual(live["text"], "ABCDEFG")
        self.assertEqual(inspector["text"], "ABCDEFG")
        self.assertEqual(live["coding_scheme"], inspector["codingScheme"])
        self.assertEqual(live["spare_bits"], inspector["spareBits"])

    def test_each_call_site_keeps_its_own_key_names(self) -> None:
        ie = bytes([0x90]) + "Hi".encode("utf-16-be")
        live = scp03_network_name_ie(ie)
        inspector = saip_network_name_ie(ie)
        assert inspector is not None
        self.assertEqual(live["encoding"], "UCS-2 big-endian")
        self.assertEqual(inspector["encoding"], "ucs-2-be")
        self.assertIn("raw", live)
        self.assertIn("hex", inspector)

    def test_inspector_trims_the_record_filler(self) -> None:
        ie = bytes([0x87]) + bytes.fromhex("41E19058341E01") + b"\xff\xff"
        inspector = saip_network_name_ie(ie)
        assert inspector is not None
        self.assertEqual(inspector["text"], "ABCDEFG")

    def test_live_view_falls_back_to_plain_ascii(self) -> None:
        decoded = scp03_network_name_ie(b"Net A")
        self.assertEqual(decoded["text"], "Net A")
        self.assertEqual(decoded["encoding"], "plain ASCII fallback")


class AccessRuleKeyReferenceTests(unittest.TestCase):
    """TS 102 221 v18.4 table 9.3, in both label styles."""

    def test_compact_labels_match_the_inspector(self) -> None:
        for reference in range(256):
            self.assertEqual(
                key_reference_name(reference),
                arr_key_reference_name(reference),
                f"0x{reference:02X}",
            )

    def test_table_9_3_rows(self) -> None:
        self.assertEqual(key_reference_name(0x01), "PIN1")
        self.assertEqual(key_reference_name(0x08), "PIN Appl 8")
        self.assertEqual(key_reference_name(0x0A), "ADM1")
        self.assertEqual(key_reference_name(0x0E), "ADM5")
        self.assertEqual(key_reference_name(0x11), "Universal PIN")
        self.assertEqual(key_reference_name(0x81), "PIN2")
        self.assertEqual(key_reference_name(0x88), "Second PIN Appl 8")
        self.assertEqual(key_reference_name(0x8E), "ADM10")
        self.assertEqual(key_reference_name(0x09), "RFU (0x09)")
        self.assertEqual(key_reference_name(0x1E), "RFU global (0x1E)")
        self.assertEqual(key_reference_name(0x9E), "RFU local (0x9E)")
        self.assertEqual(key_reference_name(0x7F), "KeyRef(0x7F)")

    def test_verbose_labels_spell_the_application_out(self) -> None:
        self.assertEqual(
            key_reference_name(0x01, style="verbose"), "PIN1 (Application PIN 1)"
        )
        self.assertEqual(key_reference_name(0x02, style="verbose"), "Application PIN 2")
        self.assertEqual(
            key_reference_name(0x81, style="verbose"), "PIN2 (Application 1)"
        )
        self.assertEqual(
            key_reference_name(0x82, style="verbose"), "Second PIN (Application 2)"
        )
        self.assertEqual(key_reference_name(0x8A, style="verbose"), "ADM6")

    def test_style_is_validated(self) -> None:
        with self.assertRaises(ValueError):
            key_reference_name(0x01, style="loud")

    def test_the_live_arr_decoder_uses_the_verbose_style(self) -> None:
        # AM_DO '80 01 01' (READ) then the table 9.3 CRT for PIN Appl 1:
        # 'A4 06' over key reference '83 01 01' and usage qualifier '95 01 08'.
        record = AdvancedDecoders.decode_ef_arr("800101A406830101950108")
        self.assertEqual(record, ["READ: PIN1 (Application PIN 1)"])


class ElementaryFileRoutingTests(unittest.TestCase):
    """The files the routing table used to hand to a text or hex fallback."""

    def setUp(self) -> None:
        ContentDecoder.init_registry()

    def test_every_new_file_identifier_is_routed(self) -> None:
        expected = {
            "6F4D": "decode_bdn_record",
            "6FE5": "decode_psismsc",
            "6FF0": "decode_ial",
            "6FF1": "decode_ips",
            "6FF2": "decode_ipd",
            "6FF3": "decode_epdgid",
        }
        for fid, name in expected.items():
            self.assertEqual(ContentDecoder._registry[fid].__name__, name, fid)

    def test_bdn_record_carries_the_comparison_method_pointer(self) -> None:
        # TS 31.102 v19.5 §4.2.44: X+15 bytes, the EF.ADN layout plus byte X+15.
        record = "41424344" + "05" + "91" + "21436587092143658709" + "01" + "02" + "03"
        decoded = ContentDecoder.decode_bdn_record(record)
        self.assertEqual(decoded["Alpha ID"], "ABCD")
        self.assertEqual(decoded["Dialing Number"], "12345678")
        self.assertEqual(decoded["Capability/Configuration2 Record Identifier"], "01")
        self.assertEqual(decoded["Extension4 Record ID"], "02")
        self.assertEqual(decoded["Comparison Method Pointer"], "03")

    def test_bdn_rejects_a_record_shorter_than_the_clause_allows(self) -> None:
        self.assertIn("Error", ContentDecoder.decode_bdn_record("00" * 14))

    def test_psismsc_reads_the_tag_80_uri(self) -> None:
        # TS 31.102 v19.5 §4.5.9: a SIP URI or tel URI as a UTF-8 octet string.
        uri = b"sip:sc@example.test"
        record = bytes([0x80, len(uri)]) + uri
        decoded = ContentDecoder.decode_psismsc(record.hex().upper())
        self.assertEqual(decoded["URI"], "sip:sc@example.test")
        self.assertEqual(decoded["URI Scheme"], "sip")
        tel = b"tel:+15550123456"
        decoded = ContentDecoder.decode_psismsc(
            (bytes([0x80, len(tel)]) + tel).hex().upper()
        )
        self.assertEqual(decoded["URI Scheme"], "tel")

    def test_psismsc_flags_a_uri_of_another_scheme(self) -> None:
        other = b"http://example.test"
        decoded = ContentDecoder.decode_psismsc(
            (bytes([0x80, len(other)]) + other).hex().upper()
        )
        self.assertIn("Warnings", decoded)

    def test_ial_reads_an_inclusive_imei_range(self) -> None:
        # TS 31.102 v19.5 §4.2.100: tag '80' IMEI range, value [lower][higher].
        low = bytes.fromhex("21436587092143F5")
        high = bytes.fromhex("21436587092143F6")
        record = bytes([0x80, len(low) + len(high)]) + low + high
        decoded = ContentDecoder.decode_ial(record.hex().upper())
        entry = decoded["IMEI(SV) Ranges"][0]
        self.assertEqual(entry["Identity Type"], "IMEI")
        self.assertEqual(entry["Lower"]["digits"], "123456789012345")
        self.assertEqual(entry["Higher"]["digits"], "123456789012346")

    def test_ips_status_bytes_are_gsm7_ok_or_ko(self) -> None:
        # TS 31.102 v19.5 §4.2.101 detail 1 and detail 2.
        decoded = ContentDecoder.decode_ips("4F4B0100")
        self.assertEqual(decoded["Status"], "OK")
        self.assertEqual(decoded["Status Meaning"], "pairing successful")
        self.assertEqual(decoded["EF.IPD Record Link"], 1)
        decoded = ContentDecoder.decode_ips("4B4F0500")
        self.assertEqual(decoded["Status Meaning"], "pairing not successful")
        decoded = ContentDecoder.decode_ips("41420000")
        self.assertIn("Warnings", decoded)

    def test_ipd_reads_a_single_imeisv(self) -> None:
        # TS 31.102 v19.5 §4.2.102: tag '81' is an IMEISV, 16 digits.
        value = bytes.fromhex("2143658709214365")
        record = bytes([0x81, len(value)]) + value
        decoded = ContentDecoder.decode_ipd(record.hex().upper())
        entry = decoded["Pairing Identity"][0]
        self.assertEqual(entry["Identity Type"], "IMEISV")
        self.assertEqual(entry["Value"]["digits"], "1234567890123456")

    def test_epdgid_reads_every_address_type(self) -> None:
        # TS 31.102 v19.5 §4.2.103: '00' FQDN, '01' IPv4, '02' IPv6.
        fqdn = bytes([0x00]) + b"epdg.example.test"
        ipv4 = bytes([0x01, 192, 0, 2, 4])
        ipv6 = bytes([0x02]) + bytes.fromhex("20010DB8" + "00" * 11 + "01")
        body = b"".join(
            bytes([0x80, len(part)]) + part for part in (fqdn, ipv4, ipv6)
        )
        decoded = ContentDecoder.decode_epdgid(body.hex().upper())
        self.assertEqual(
            [entry["Address"] for entry in decoded["Home ePDG Identifiers"]],
            ["epdg.example.test", "192.0.2.4", "2001:db8::1"],
        )

    def test_epdgid_flags_a_short_ipv4_address(self) -> None:
        short = bytes([0x80, 0x03, 0x01, 192, 0])
        decoded = ContentDecoder.decode_epdgid(short.hex().upper())
        self.assertIn("Warnings", decoded)


class DisasterRoamingWaitRangeTests(unittest.TestCase):
    """TS 31.102 v19.5 §4.4.11.17 wait ranges over the TS 24.501 timer coding."""

    def test_wait_range_octets_use_the_gprs_timer_units(self) -> None:
        # TS 24.501 v19.7 §9.11.3.84: minimum then maximum, each coded as
        # octet 2 of the GPRS timer IE (TS 24.008 v19.5 §10.5.7.3).
        decoded = ContentDecoder.decode_dri("01F0" + "0105" + "2A4B" + "01")
        roaming = decoded["Disaster Roaming Wait Range Decoded"]
        self.assertEqual(roaming["minimum"]["unit"], "2 seconds")
        self.assertEqual(roaming["minimum"]["seconds"], 2)
        self.assertEqual(roaming["maximum"]["seconds"], 10)
        returning = decoded["Disaster Return Wait Range Decoded"]
        self.assertEqual(returning["minimum"]["unit"], "1 minute")
        self.assertEqual(returning["minimum"]["seconds"], 600)
        self.assertEqual(returning["maximum"]["unit"], "1 decihour")
        self.assertEqual(returning["maximum"]["seconds"], 3960)

    def test_unit_111_deactivates_the_timer(self) -> None:
        decoded = ContentDecoder._decode_gprs_timer_octet(0xE5)
        self.assertEqual(decoded["unit"], "deactivated")
        self.assertNotIn("seconds", decoded)

    def test_undefined_units_read_as_minutes(self) -> None:
        decoded = ContentDecoder._decode_gprs_timer_octet(0x65)
        self.assertEqual(decoded["unit"], "1 minute")
        self.assertEqual(decoded["seconds"], 300)
        self.assertIn("note", decoded)

    def test_an_absent_range_is_reported_as_absent(self) -> None:
        decoded = ContentDecoder.decode_dri("01F3" + "FFFF" + "FFFF" + "FF")
        self.assertFalse(decoded["Disaster Roaming Wait Range Decoded"]["present"])

    def test_an_inverted_range_is_flagged(self) -> None:
        decoded = ContentDecoder.decode_dri("01F0" + "4321" + "0105" + "01")
        self.assertIn("warning", decoded["Disaster Roaming Wait Range Decoded"])


class SmsAddressFieldTests(unittest.TestCase):
    """RP addresses (TS 24.011 v19) against SM-TL addresses (TS 23.040 v19)."""

    def test_rp_address_length_octet_counts_contents_and_caps_at_eleven(self) -> None:
        # TS 24.011 v19 §8.2.5.1 and §8.2.5.2: the length octet runs 2 to 11.
        # '08' covers the TON/NPI octet plus seven digit octets: 14 digits.
        decoded = ContentDecoder._decode_address_field(
            bytes.fromhex("08" + "91" + "21436587092143"), sc_addr=True
        )
        self.assertEqual(decoded["call_number"], "12345678901234")
        over_long = ContentDecoder._decode_address_field(
            bytes.fromhex("0C" + "91" + "2143658709214365870F"), sc_addr=True
        )
        self.assertIn("exceeds the maximum of 11", over_long["error"])

    def test_rp_address_has_no_alphanumeric_type_of_number(self) -> None:
        # TS 24.011 v19 §8.2.5.2 defers octets 3 onward to the Called Party
        # BCD Number of TS 24.008 v19.5 §10.5.4.7, whose table 10.5.118
        # reserves type-of-number 101 instead of naming it alphanumeric.
        # An RP address counts contents octets, so '03' covers TON/NPI + 'C834'.
        rp = ContentDecoder._decode_address_field(
            bytes.fromhex("03" + "D0" + "C834"), sc_addr=True
        )
        self.assertEqual(rp["ton"], "Reserved")
        self.assertEqual(rp["encoding"], "telephony BCD")
        # The same TON/NPI and payload read as an SM-TL address, whose length
        # octet counts semi-octets, stay alphanumeric.
        tp = ContentDecoder._decode_address_field(
            bytes.fromhex("04" + "D0" + "C834"), sc_addr=False
        )
        self.assertEqual(tp["ton"], "Alphanumeric")
        self.assertEqual(tp["call_number"], "Hi")

    def test_rp_type_of_number_labels_follow_ts_24_008(self) -> None:
        # 'C1': extension bit set, type of number 100, numbering plan 0001.
        raw = bytes.fromhex("03" + "C1" + "2143")
        decoded = ContentDecoder._decode_address_field(raw, sc_addr=True)
        self.assertEqual(decoded["ton"], "Dedicated access, short code")
        self.assertEqual(decoded["npi"], "ISDN / E.164")

    def test_sms_record_service_centre_address_is_an_rp_address(self) -> None:
        record = "01" + "08" + "91" + "21436587092143" + "0004"
        decoded = ContentDecoder.decode_sms_record(record)
        self.assertEqual(
            decoded["Service Centre Address"]["call_number"], "12345678901234"
        )
        self.assertEqual(decoded["TPDU (raw)"], "0004")

    def test_smsp_reads_its_two_addresses_with_different_length_rules(self) -> None:
        body = (
            "E0"
            + "0B" + "91" + "21436587092143658709"
            + "08" + "91" + "21436587092143" + "FFFFFF"
            + "000000"
        )
        decoded = ContentDecoder.decode_sms_params(body)
        # TP-DA's '0B' is eleven semi-octets; the TP-SCA's '08' is eight
        # contents octets, so the same eleven-byte field holds fourteen digits.
        self.assertEqual(decoded["TP-Destination Address"]["length"], 11)
        self.assertEqual(decoded["TP-Destination Address"]["call_number"], "12345678901")
        self.assertEqual(decoded["Service Center Address"]["length"], 8)
        self.assertEqual(
            decoded["Service Center Address"]["call_number"], "12345678901234"
        )


if __name__ == "__main__":
    unittest.main()
