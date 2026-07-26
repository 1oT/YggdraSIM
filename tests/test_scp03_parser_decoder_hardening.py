# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Adversarial and round-trip coverage for SCP03 protocol decoders."""

from __future__ import annotations

import pytest

from SCP03.core.decoders import AdvancedDecoders, ContentDecoder
from SCP03.core.utils import HexUtils, StatusWordTranslator, TlvParser
from SCP03.logic.euicc_info2 import (
    decode_named_bit_string as decode_euicc_named_bits,
)
from SCP03.logic.euicc_info2 import parse_tlv_nodes
from SCP03.logic.sgp32_decode import (
    collect_nested_tag_values,
    decode_bcd_digits,
    decode_eim_configuration_entries,
    decode_named_bit_string as decode_sgp32_named_bits,
)
from SIMCARD.utils import encode_iccid_ef, encode_imsi_ef, tlv


def _nested_tlv(depth: int, leaf: bytes | None = None) -> bytes:
    encoded = leaf if leaf is not None else tlv("04", b"")
    for _ in range(depth):
        encoded = tlv("A0", encoded)
    return encoded


def test_tlv_detailed_reports_valid_prefix_but_strict_api_rejects_it() -> None:
    malformed = bytes.fromhex("0401AA0402BB")

    detailed = TlvParser.parse_detailed(malformed)

    assert detailed["complete"] is False
    assert detailed["consumed"] == 3
    assert detailed["parsed"] == {0x04: b"\xAA"}
    assert "offset 3" in detailed["error"]
    with pytest.raises(ValueError, match="offset 3"):
        TlvParser.parse(malformed)


def test_hex_utils_accept_common_separators_without_erasing_embedded_prefixes() -> None:
    assert HexUtils.to_bytes(" 0X01:02\n03 ") == b"\x01\x02\x03"
    assert HexUtils.to_bytes("0x01-02_03") == b"\x01\x02\x03"
    assert HexUtils.to_bytes(memoryview(b"\x01\x02")) == b"\x01\x02"
    with pytest.raises(ValueError, match="only valid at the start"):
        HexUtils.to_bytes("010x02")
    with pytest.raises(TypeError, match="integers"):
        HexUtils.to_bytes([1, True])


@pytest.mark.parametrize(
    ("encoded", "message"),
    [
        ("0000", "reserved tag"),
        ("FF00", "non-minimal high-tag-number"),
        ("1F800100", "non-minimal high-tag-number"),
        ("1F1E00", "tag below 31"),
        ("9F81", "truncated multi-byte tag"),
        ("0480", "indefinite length"),
        ("04FF", "length octet 0xFF"),
        ("048101AA", "shorter than 128"),
        ("04820080", "leading zero"),
        ("04820100AA", "overruns"),
    ],
)
def test_tlv_parser_rejects_malformed_and_non_minimal_ber(
    encoded: str,
    message: str,
) -> None:
    result = TlvParser.parse_detailed(bytes.fromhex(encoded))
    assert result["complete"] is False
    assert message in result["error"]
    with pytest.raises(ValueError, match=message):
        TlvParser.parse(bytes.fromhex(encoded))


def test_tlv_parser_accepts_canonical_long_form_length() -> None:
    value = bytes(range(128))
    encoded = bytes.fromhex("048180") + value
    assert TlvParser.parse(encoded) == {0x04: value}


def test_tlv_parser_rejects_malformed_constructed_content() -> None:
    result = TlvParser.parse_detailed(bytes.fromhex("A0030402AA"))
    assert result["complete"] is False
    assert "constructed tag A0" in result["error"]
    assert result["parsed"] == {}


def test_tlv_parser_bounds_constructed_recursion() -> None:
    result = TlvParser.parse_detailed(_nested_tlv(12), max_depth=8)
    assert result["complete"] is False
    assert "maximum constructed nesting depth (8)" in result["error"]


def test_tlv_padded_parser_preserves_legitimate_final_ff_value() -> None:
    # OCTET STRING value is FF; only the second FF is fixed-record padding.
    encoded = bytes.fromhex("0401FFFF")
    assert TlvParser.parse_padded(encoded) == {0x04: b"\xFF"}
    with pytest.raises(ValueError):
        TlvParser.parse(encoded)


def test_tlv_padded_parser_rejects_non_padding_trailer_and_padding_only() -> None:
    with pytest.raises(ValueError):
        TlvParser.parse_padded(bytes.fromhex("0401AAFE"))
    with pytest.raises(ValueError):
        TlvParser.parse_padded(bytes.fromhex("FFFF"))
    with pytest.raises(TypeError, match="bytes-like"):
        TlvParser.parse_padded(3)  # type: ignore[arg-type]


def test_status_word_zero_lengths_mean_256_and_inputs_are_bytes() -> None:
    assert "256 bytes" in StatusWordTranslator.translate(0x61, 0x00)
    assert "256" in StatusWordTranslator.translate(0x6C, 0x00)
    assert "proactive-command" in StatusWordTranslator.translate(0x91, 0x10)
    with pytest.raises(ValueError, match="SW1"):
        StatusWordTranslator.translate(0x100, 0)
    with pytest.raises(TypeError, match="SW2"):
        StatusWordTranslator.translate(0x90, True)


@pytest.mark.parametrize(
    "encoded",
    [
        bytes.fromhex("BF"),
        bytes.fromhex("8102AA"),
        bytes.fromhex("048101AA"),
        bytes.fromhex("1F800100"),
        bytes.fromhex("0000"),
    ],
)
def test_sgp_tlv_node_parser_rejects_partial_or_noncanonical_input(
    encoded: bytes,
) -> None:
    with pytest.raises(ValueError, match="BER-TLV error at offset"):
        parse_tlv_nodes(encoded)


def test_sgp_tlv_node_parser_accepts_canonical_long_length() -> None:
    value = bytes(128)
    nodes = parse_tlv_nodes(bytes.fromhex("048180") + value)
    assert nodes == [(0x04, value, False)]


@pytest.mark.parametrize(
    "decoder",
    [decode_euicc_named_bits, decode_sgp32_named_bits],
)
def test_named_bit_string_rejects_invalid_unused_bits(decoder) -> None:
    with pytest.raises(ValueError, match="range 0..7"):
        decoder(bytes.fromhex("0880"), {0: "first"})
    with pytest.raises(ValueError, match="non-zero padding"):
        decoder(bytes.fromhex("0307"), {0: "first"})
    with pytest.raises(ValueError, match="Empty BIT STRING"):
        decoder(bytes.fromhex("01"), {0: "first"})


def test_sgp32_tbcd_filler_is_only_valid_in_final_high_nibble() -> None:
    assert decode_bcd_digits(bytes.fromhex("21F3")) == "123"
    assert decode_bcd_digits(bytes.fromhex("1F")) == "1F"
    assert decode_bcd_digits(bytes.fromhex("F121")) == "F121"


def test_sgp32_nested_collector_has_a_depth_limit() -> None:
    with pytest.raises(ValueError, match="nesting exceeds"):
        collect_nested_tag_values(
            _nested_tlv(40, leaf=tlv("81", b"\x01")),
            0x81,
        )


def test_gp_seac_rejects_malformed_tlv_and_does_not_duplicate_scalars() -> None:
    malformed = AdvancedDecoders.decode_gp_seac_arf("4F02AA")
    assert len(malformed) == 1
    assert "TLV Parse Error" in malformed[0]

    scalar = AdvancedDecoders.decode_gp_seac_arf("4F01AA")
    assert scalar == ["4F AID-REF-DO: AA"]


def test_generic_tlv_decoder_never_presents_a_partial_tree_as_valid() -> None:
    assert ContentDecoder.decode_tlv_as_map("0401AA0402BB") == {
        "Raw": "0401AA0402BB"
    }


def test_plmn_record_width_is_explicit_and_registry_uses_fid_semantics() -> None:
    three_byte_records = "00F110" * 5
    assert len(AdvancedDecoders.decode_plmn_list(three_byte_records, 3)) == 5

    with_act_records = "00F1108000" * 3
    direct = AdvancedDecoders.decode_plmn_list(with_act_records, 5)
    assert len(direct) == 3
    assert all("UTRAN" in entry for entry in direct)
    registered = ContentDecoder.decode_raw("6F60", with_act_records)
    assert registered == direct


def test_plmn_decoder_rejects_invalid_bcd_and_partial_records() -> None:
    assert "invalid BCD" in AdvancedDecoders.decode_plmn_list("0AF110", 3)[0]
    assert "not a multiple" in AdvancedDecoders.decode_plmn_list("00F110AA", 3)[0]


def test_location_fids_use_their_own_fixed_layouts() -> None:
    psloci = "FFFFFFFFFFFFFF" + "00F110" + "0001" + "01" + "01"
    epsloci = (
        "0BF6" + "00F110" + "0001" + "02" + "11223344"
        + "00F110" + "0001" + "00"
    )
    assert len(bytes.fromhex(psloci)) == 14
    assert len(bytes.fromhex(epsloci)) == 18
    assert ContentDecoder.decode_raw("6F73", psloci)["RAI"]["PLMN"] == "001-01"
    assert (
        ContentDecoder.decode_raw("6FE3", epsloci)["GUTI"]["M-TMSI"]
        == "11223344"
    )
    assert "Invalid PSLOCI Length" in ContentDecoder.decode_raw("6F73", "00")["Error"]


def test_iccid_and_imsi_decoders_roundtrip_standard_encoders() -> None:
    iccid = "8988000000000000001"
    imsi = "001010123456789"
    assert ContentDecoder.decode_iccid(encode_iccid_ef(iccid).hex())["iccid"] == iccid
    assert ContentDecoder.decode_imsi(encode_imsi_ef(imsi).hex())["imsi"] == imsi


def test_identity_decoders_reject_bad_bcd_length_and_parity() -> None:
    assert "Invalid ICCID Length" in ContentDecoder.decode_iccid("98")["Error"]
    invalid_iccid = bytearray(encode_iccid_ef("8988000000000000001"))
    invalid_iccid[0] = 0x9A
    assert "Invalid low BCD" in ContentDecoder.decode_iccid(invalid_iccid.hex())["Error"]

    invalid_imsi = bytearray(encode_imsi_ef("001010123456789"))
    invalid_imsi[1] ^= 0x08
    assert "odd/even" in ContentDecoder.decode_imsi(invalid_imsi.hex())["Error"]


def test_ad_decoder_uses_assigned_operation_modes_and_accepts_rfu_tail() -> None:
    assert ContentDecoder.decode_ad("80000003")["Administrative Mode"] == (
        "Type approval operation"
    )
    decoded = ContentDecoder.decode_ad("01001F020000")
    assert decoded["Administrative Mode"] == (
        "Normal operation with specific facilities"
    )
    assert decoded["Specific Facilities"]["Ciphering Indicator"] is True
    assert decoded["MNC Length"] == 2
    assert decoded["Trailing RFU"] == "0000"


def test_acc_decoder_does_not_report_reserved_bit_as_class_ten() -> None:
    decoded = ContentDecoder.decode_acc("0401")
    assert decoded["Access Control Classes"] == ["0"]
    assert "Reserved" in decoded["Warning"]


def test_msisdn_decoder_respects_declared_number_length() -> None:
    footer = bytes([3, 0x91]) + bytes.fromhex("2143") + bytes.fromhex("FF" * 8)
    footer += b"\xFF\xFF"
    assert len(footer) == 14
    decoded = ContentDecoder.decode_msisdn(footer.hex())
    assert decoded["Dialing Number"] == "1234"
    assert decoded["Length of BCD Number"] == 3


def test_smsp_validity_and_dcs_use_3gpp_semantics() -> None:
    assert ContentDecoder._decode_validity_period(0xFF)["weeks"] == 63
    assert ContentDecoder._decode_tp_dcs(0x00) == "GSM 7-bit default alphabet"
    assert "message class 0" in ContentDecoder._decode_tp_dcs(0x10)
    empty = ContentDecoder.decode_sms_params("FF" * 28)
    assert empty["TP-DCS"] == "Not present"
    assert empty["TP-Validity Period"]["present"] is False


def test_puct_exponent_uses_b5_for_sign_and_b6_to_b8_for_magnitude() -> None:
    decoded = ContentDecoder.decode_puct((b"EUR" + bytes.fromhex("1274")).hex())
    assert decoded["EPPU"] == 0x124
    assert decoded["Exponent"] == -3


def test_secret_bearing_decoders_never_echo_key_material() -> None:
    secret = "00112233445566778899AABBCCDDEEFF"
    decoded_values = [
        ContentDecoder.decode_sensitive_blob(secret),
        ContentDecoder.decode_epsnsc(secret),
        ContentDecoder.decode_5gs_nsc(secret),
        ContentDecoder.decode_5gs_auth_keys(secret),
    ]
    for decoded in decoded_values:
        assert secret not in str(decoded).upper()
        assert "redacted" in str(decoded).lower()


def test_5gs_loci_requires_and_decodes_the_20_byte_layout() -> None:
    encoded = (
        "000B" + "F2" + "00F110" + "AA" + "BBCC" + "11223344"
        + "00F110" + "000001" + "00"
    )
    assert len(bytes.fromhex(encoded)) == 20
    decoded = ContentDecoder.decode_5gs_loci(encoded)
    assert decoded["GUTI"]["PLMN"] == "001-01"
    assert decoded["GUTI"]["5G-TMSI"] == "11223344"
    assert decoded["Last Visited TAI"]["TAC"] == "000001"
    assert "Invalid 5GS LOCI Length" in ContentDecoder.decode_5gs_loci("00")["Error"]
    assert "expected 11" in ContentDecoder.decode_5gs_loci(
        "000A" + encoded[4:]
    )["Error"]


def test_opl_accepts_spec_defined_wildcard_digits_only_in_opl_records() -> None:
    encoded_plmn = bytes.fromhex("21DD43")
    assert ContentDecoder.decode_opl(
        (encoded_plmn + bytes.fromhex("0000FFFE01")).hex()
    )["PLMN"] == "12*-*34"
    assert ContentDecoder._decode_plmn_bytes(encoded_plmn).startswith("Invalid")
    padded = ContentDecoder.decode_opl(
        (encoded_plmn + bytes.fromhex("0000FFFE01FFFF")).hex()
    )
    assert padded["PNN Source"] == "EF.PNN record 1"


def test_spdi_accepts_only_valid_tlv_before_ff_record_padding() -> None:
    encoded = tlv("A3", tlv("80", bytes.fromhex("00F110"))) + b"\xFF\xFF"
    assert ContentDecoder.decode_spdi(encoded.hex())[
        "Service Provider PLMN List"
    ] == ["001-01"]


def test_plmn_with_act_uses_the_assigned_extended_access_technology_bits() -> None:
    plmn = "00F110"
    assert "EC-GSM-IoT" in AdvancedDecoders.decode_plmn_list(
        plmn + "0088",
        record_size=5,
    )[0]
    assert "GSM," not in AdvancedDecoders.decode_plmn_list(
        plmn + "0088",
        record_size=5,
    )[0]
    decoded = AdvancedDecoders.decode_plmn_list(
        plmn + "0F00",
        record_size=5,
    )[0]
    assert "NG-RAN" in decoded
    assert "Satellite NG-RAN" in decoded
    assert "Satellite E-UTRAN WB-S1" in decoded
    assert "Satellite E-UTRAN NB-S1" in decoded


def test_ust_labels_and_est_dispatch_follow_their_distinct_spec_tables() -> None:
    ust = AdvancedDecoders.decode_ust("20" + "00" * 14 + "02")
    assert ust["active"] == [
        "6: Barred Dialling Numbers (BDN)",
        "122: 5GS Mobility Management Information",
    ]

    est = ContentDecoder.decode_raw("6F56", "05")
    assert est["table"] == "EST"
    assert est["active"] == [
        "1: Fixed Dialling Numbers (FDN)",
        "3: APN Control List (ACL)",
    ]


def test_location_decoders_accept_standard_unassigned_default_patterns() -> None:
    loci = AdvancedDecoders.decode_loci("FFFFFFFFFFFFFF0000FF01")
    assert loci["LAI"] == "Not assigned"
    assert loci["TMSI Assigned"] is False
    assert loci["Status"] == "Not Updated"

    psloci = AdvancedDecoders.decode_psloci(
        "FFFFFFFFFFFFFFFFFFFF0000FF01"
    )
    assert psloci["RAI"]["PLMN"] == "Not assigned"
    assert psloci["P-TMSI Assigned"] is False
    assert psloci["Status"] == "Not Updated"

    reserved = AdvancedDecoders.decode_loci("0000000000F1100000FF04")
    assert reserved["Status"] == "Reserved (4)"


def test_5gs_opl_uses_six_octets_for_the_tac_range() -> None:
    decoded = ContentDecoder.decode_raw(
        "4F08",
        "21DD43" + "000000" + "FFFFFE" + "02",
        context_path="ADF.USIM/DF.5GS",
    )
    assert decoded["PLMN"] == "12*-*34"
    assert decoded["TAC Start"] == "000000"
    assert decoded["TAC End"] == "FFFFFE"
    assert decoded["PNN Source"] == "EF.PNN record 2"


def test_sor_and_dri_reject_ambiguous_extra_or_duplicate_objects() -> None:
    assert "unexpected tag" in ContentDecoder.decode_5gs_sor_cmci(
        "80008100"
    )["Error"]
    assert "does not contain tag-80" in ContentDecoder.decode_dri(
        "00FF" + "FF" * 5 + "80008000"
    )["Error"]


def test_eim_configuration_decoder_accepts_minimal_entry_without_walking_keys() -> None:
    response = tlv("BF55", tlv("A0", tlv("30", tlv("80", b"eim-1"))))
    assert decode_eim_configuration_entries(response) == [{"eim_id": "eim-1"}]


def test_arr_decoder_accepts_padding_but_rejects_truncation() -> None:
    assert AdvancedDecoders.decode_ef_arr("8001019000FFFF") == ["READ: Always"]
    malformed = AdvancedDecoders.decode_ef_arr("800101A4038302AA")
    assert len(malformed) == 1
    assert "ARR TLV Parse Error" in malformed[0]


def test_arr_decoder_uses_standard_key_references_and_boolean_cardinality() -> None:
    pin2 = AdvancedDecoders.decode_ef_arr("800101A406830181950108")
    assert pin2 == ["READ: PIN2 (Application 1)"]

    app_pin2 = AdvancedDecoders.decode_ef_arr("800101A406830102950108")
    assert app_pin2 == ["READ: Application PIN 2"]

    valid_or = AdvancedDecoders.decode_ef_arr("800101A00490009700")
    assert valid_or == ["READ: OR (Always, Never)"]

    invalid_or = AdvancedDecoders.decode_ef_arr("800101A0029000")
    assert "must contain at least two children" in invalid_or[0]


def test_arr_command_header_is_paired_with_its_security_condition() -> None:
    decoded = AdvancedDecoders.decode_ef_arr("840132A406830101950108")
    assert decoded == [
        "INCREASE (command header 32): PIN1 (Application PIN 1)"
    ]


def test_service_table_encoder_rejects_invalid_or_ambiguous_inputs() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        AdvancedDecoders.encode_service_table([0], total_bytes=1)
    with pytest.raises(TypeError, match="positive integers"):
        AdvancedDecoders.encode_service_table([True], total_bytes=1)
    with pytest.raises(TypeError, match="iterable of integer"):
        AdvancedDecoders.encode_service_table("12", total_bytes=1)
    with pytest.raises(ValueError, match="valid hexadecimal"):
        AdvancedDecoders.encode_service_table([1], current_hex="GG")


def test_context_decoder_resolution_accepts_dotted_and_windows_paths() -> None:
    encoded = "11F2FF19F1FF"
    expected = {
        "Emergency Codes": ["112", "911"],
        "Entries": [{"Code": "112"}, {"Code": "911"}],
    }
    assert ContentDecoder.decode_raw(
        "6FB7",
        encoded,
        context_path=r"MF\DF.GSM\EF.ECC",
    ) == expected


def test_alpha_identifier_supports_all_three_standard_ucs2_codings() -> None:
    assert ContentDecoder._decode_alpha_identifier(bytes.fromhex("800041FF")) == (
        "A",
        "UCS-2",
    )
    assert ContentDecoder._decode_alpha_identifier(bytes.fromhex("8102135395")) == (
        "Sক",
        "compressed UCS-2 (0x81)",
    )
    assert ContentDecoder._decode_alpha_identifier(
        bytes.fromhex("820505302D82D32D31")
    ) == ("-Բփ-1", "compressed UCS-2 (0x82)")


def test_spn_uses_uicc_alpha_identifier_coding() -> None:
    decoded = ContentDecoder.decode_spn("008000540065006C0065")
    assert decoded["SPN"] == "Tele"
    assert decoded["Encoding"] == "UCS-2"


def test_pnn_network_name_decodes_gsm_and_ucs2_coding_scheme_bits() -> None:
    ucs2_value = bytes([0x90]) + "Tele".encode("utf-16-be")
    encoded = tlv("43", ucs2_value).hex()
    decoded = ContentDecoder.decode_pnn(encoded)
    assert decoded["Full Name"] == "Tele"
    assert decoded["Full Name Details"]["coding_scheme"] == 1
    assert decoded["Full Name Details"]["encoding"] == "UCS-2 big-endian"


def test_ecc_usim_record_keeps_alpha_and_category_as_one_record() -> None:
    encoded = bytes.fromhex("11F2FF") + b"Police" + bytes([0x03])
    decoded = ContentDecoder.decode_ecc(encoded.hex())
    assert decoded["Emergency Codes"] == ["112"]
    assert decoded["Entries"][0]["Alpha Identifier"] == "Police"
    assert decoded["Entries"][0]["Service Categories"] == [
        "Police",
        "Ambulance",
    ]
    assert "at least 4 bytes" in ContentDecoder.decode_ecc("11F2FF")["Error"]


def test_dir_and_pcscf_decoders_handle_padding_and_ip_addresses() -> None:
    app = tlv(
        "61",
        tlv("4F", bytes.fromhex("A0000000871002")) + tlv("50", b"USIM"),
    )
    decoded_dir = ContentDecoder.decode_dir((app + b"\xFF\xFF").hex())
    assert decoded_dir["AID"] == "A0000000871002"
    assert decoded_dir["Label"] == "USIM"

    decoded_pcscf = ContentDecoder.decode_isim_pcscf("800501C0000201FFFF")
    assert decoded_pcscf == {
        "Address Type": "IPv4",
        "Address": "192.0.2.1",
    }


def test_gbanl_redacts_btid_value() -> None:
    decoded = ContentDecoder.decode_gbanl("80036E61668104DEADBEEF")
    assert decoded["B-TID"] == "<redacted>"
    assert decoded["B-TID Length"] == 4
    assert "DEADBEEF" not in str(decoded).upper()


def test_fixed_5g_decoders_validate_layout_and_reserved_bits() -> None:
    uac = ContentDecoder.decode_5gs_uac_aic("03000000")
    assert uac["Multimedia Priority Service"] is True
    assert uac["Mission Critical Services"] is True
    assert "Warning" not in uac
    assert "expected 4" in ContentDecoder.decode_5gs_uac_aic("03")["Error"]

    routing = ContentDecoder.decode_routing_indicator("21FF0000")
    assert routing["Routing Indicator"] == "12"
    assert routing["RFU"] == "0000"
    assert "Warning" not in routing
    assert "expected 4" in ContentDecoder.decode_routing_indicator("21FF")["Error"]


def test_sor_cmci_and_dri_use_their_defined_outer_layouts() -> None:
    sor = ContentDecoder.decode_5gs_sor_cmci("8002AABBFFFF")
    assert sor == {
        "SOR-CMCI Rule Present": True,
        "Parameter Length": 2,
        "Parameters": "AABB",
    }
    assert "TLV Parse Error" in ContentDecoder.decode_5gs_sor_cmci(
        "8002AA"
    )["Error"]

    dri = ContentDecoder.decode_dri("01F00102030401800300F110")
    assert dri["Disaster Roaming Enabled"] is True
    assert dri["HPLMN PLMN List"] == ["001-01"]
    assert dri["Parameter Presence"]["HPLMN PLMN List"] is True
