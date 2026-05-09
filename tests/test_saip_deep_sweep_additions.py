"""
Deep-sweep regression coverage for the newly registered SAIP EFs.

These tests verify that the pySim-aligned deep-sweep additions (FID
corrections, Rel-17/18 ProSe + 5MBS registrations, DF.HNB family,
EF.NID / EF.OCST / EF.RPLMNAcT) are routed through their semantic
decoders and surface the expected fields. They complement the
length-shape catalog invariant by exercising the actual byte layouts
described in TS 31.102.
"""

from __future__ import annotations

import pytest

from Tools.ProfilePackage.saip_asn1_decode import (
    _EF_KEY_TO_FID,
    _EF_KEY_TO_PARENT_TOKEN,
    _UST_SERVICE_NAMES,
    _ISIM_SERVICE_NAMES,
    _EST_SERVICE_NAMES,
    _decode_5gnswo_conf,
    _decode_5gs_loci,
    _decode_5gsedrx,
    _decode_5mbs_ue_config,
    _decode_ef_5gauthkeys,
    _decode_ef_5gs3gpp_nsc,
    _decode_ef_anl_record,
    _decode_ef_bcch,
    _decode_ef_arr,
    _decode_ef_cpbcch,
    _decode_ef_netpar,
    _decode_ef_v2xp_pc5,
    _decode_ef_v2xp_uu,
    _decode_generic_tlv_ef,
    _EF_IMPDF_TAGS,
    _EF_MCS_TAGS,
    _EF_PKCS15_ACRF_TAGS,
    _EF_PROSE_PROVISIONED_TAGS,
    _EF_URSP_TAGS,
    _EF_V2X_AUTHKEYS_TAGS,
    _EF_V2X_CERT_TAGS,
    _EF_V2X_CFG_TAGS,
    _EF_V2X_PRECFG_TAGS,
    _decode_ef_cc_counter,
    _decode_ef_cmi,
    _decode_ef_earfcn_list,
    _decode_ef_email_record,
    _decode_ef_fcsl,
    _decode_ef_gas_record,
    _decode_ef_grp_record,
    _decode_ef_iap_record,
    _decode_ef_mbparam,
    _decode_ef_mexe_st,
    _decode_ef_nafkca_list,
    _decode_ef_ota_keys,
    _decode_ef_ota_state,
    _decode_ef_phist,
    _decode_ef_psismsc,
    _decode_ef_psc,
    _decode_ef_puid,
    _decode_ef_scp80_counter,
    _decode_ef_scp11_key,
    _decode_ef_setup_menu_elements,
    _decode_ef_simlock_state,
    _decode_ef_sne_record,
    _decode_ef_threshold,
    _decode_ef_acsgl,
    _decode_ef_cnl,
    _decode_ef_csgt,
    _decode_ef_gbauapi,
    _decode_ef_hnbn,
    _decode_ef_imsdci,
    _decode_ef_locigprs,
    _decode_ef_nid,
    _decode_ef_ocsgl,
    _decode_ef_ocst,
    _decode_ef_rplmnact,
    _decode_ef_v2x_config,
    _decode_ef_mcs_config,
    _decode_5g_prose_tlv_ef,
    _decode_vgcs_vbs_subscription,
    _decode_vgcss_vbss_status,
    _5G_PROSE_U2URU_TAGS,
    _5G_PROSE_EU_TAGS,
    _decode_known_ef_payload,
)


class FidRegistrationTests:
    """FID mapping corrections (pySim-aligned)."""

    @staticmethod
    def test_5gsedrx_registered_at_4f10() -> None:
        assert _EF_KEY_TO_FID["ef-5gsedrx"] == "4F10"

    @staticmethod
    def test_5gnswo_registered_at_4f11() -> None:
        assert _EF_KEY_TO_FID["ef-5gnswo-conf"] == "4F11"

    @staticmethod
    def test_rel17_extras_registered() -> None:
        assert _EF_KEY_TO_FID["ef-cag"] == "4F0D"
        assert _EF_KEY_TO_FID["ef-sor-cmci"] == "4F0E"
        assert _EF_KEY_TO_FID["ef-dri"] == "4F0F"
        assert _EF_KEY_TO_FID["ef-mchpplmn"] == "4F15"
        assert _EF_KEY_TO_FID["ef-kausf-derivation"] == "4F16"

    @staticmethod
    def test_rel18_prose_registered() -> None:
        assert _EF_KEY_TO_FID["ef-5g-prose-u2uru"] == "4F07"
        assert _EF_KEY_TO_FID["ef-5g-prose-eu"] == "4F08"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-5g-prose-u2uru"] == "df-5gprose"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-5g-prose-eu"] == "df-5gprose"

    @staticmethod
    def test_rel18_5mbs_registered() -> None:
        assert _EF_KEY_TO_FID["ef-5mbsueconfig"] == "4F01"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-5mbsueconfig"] == "df-5mbsueconfig"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-5mbsusd"] == "df-5mbsueconfig"

    @staticmethod
    def test_hnb_family_registered() -> None:
        assert _EF_KEY_TO_FID["ef-acsgl"] == "4F81"
        assert _EF_KEY_TO_FID["ef-csgt"] == "4F82"
        assert _EF_KEY_TO_FID["ef-hnbn"] == "4F83"
        assert _EF_KEY_TO_FID["ef-ocsgl"] == "4F84"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-hnbn"] == "df-hnb"

    @staticmethod
    def test_nid_registered() -> None:
        assert _EF_KEY_TO_FID["ef-nid"] == "4F02"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-nid"] == "df-snpn"

    @staticmethod
    def test_adf_usim_extras_registered() -> None:
        assert _EF_KEY_TO_FID["ef-ocst"] == "6F02"
        assert _EF_KEY_TO_FID["ef-rplmnact"] == "6F65"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-ocst"] == "adf-usim"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-rplmnact"] == "adf-usim"

    @staticmethod
    def test_isim_gbauapi_imsdci_registered() -> None:
        assert _EF_KEY_TO_FID["ef-gbauapi"] == "6F0A"
        assert _EF_KEY_TO_FID["ef-imsdci"] == "6F0B"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-gbauapi"] == "adf-isim"
        assert _EF_KEY_TO_PARENT_TOKEN["ef-imsdci"] == "adf-isim"


class Loci5GsDecoderTests:
    """Fixed 20-byte 5GS LOCI frames."""

    SAMPLE_HEX = (
        # 5G-GUTI: PLMN 001-01 (00F110), AMF region AA, AMF set+pointer BBCC,
        # 5G-TMSI 11223344, RFU 00FFEE
        "00F110"
        "AA"
        "BBCC"
        "11223344"
        "00FFEE"
        # TAI: PLMN 001-01, TAC 000001
        "00F110"
        "000001"
        # 5GS update status: updated (0x00)
        "00"
    )

    def test_3gpp_loci_decodes_cleanly(self) -> None:
        decoded = _decode_5gs_loci(
            self.SAMPLE_HEX,
            format_name="5GS 3GPP Location Info",
            spec_reference="TS 31.102 §4.4.11.2",
        )
        assert decoded is not None
        assert decoded["length"] == 20
        assert decoded["guti"]["amfRegionId"] == "0xAA"
        assert decoded["guti"]["amfSetAndPointerHex"] == "BBCC"
        assert decoded["guti"]["tmsiHex"] == "11223344"
        assert decoded["tai"]["tac"] == 1
        assert decoded["updateStatus"]["label"] == "updated"

    def test_rejects_wrong_length(self) -> None:
        assert (
            _decode_5gs_loci(
                "00" * 10,
                format_name="",
                spec_reference="",
            )
            is None
        )


class Edrx5gsDecoderTests:
    def test_one_byte_edrx(self) -> None:
        decoded = _decode_5gsedrx("07")
        assert decoded is not None
        assert decoded["edrxValue"] == 7
        assert decoded["edrxRfuNibble"] == 0

    def test_two_byte_edrx_exposes_ptw(self) -> None:
        decoded = _decode_5gsedrx("0503")
        assert decoded is not None
        assert decoded["edrxValue"] == 5
        assert decoded["pagingTimeWindow"] == 3

    def test_rejects_invalid_length(self) -> None:
        assert _decode_5gsedrx("000102") is None


class Nswo5gDecoderTests:
    def test_enabled(self) -> None:
        decoded = _decode_5gnswo_conf("01")
        assert decoded is not None
        assert decoded["nswoEnabled"] is True
        assert decoded["summary"] == "NSWO enabled"

    def test_disabled(self) -> None:
        decoded = _decode_5gnswo_conf("00")
        assert decoded is not None
        assert decoded["nswoEnabled"] is False

    def test_rejects_wrong_length(self) -> None:
        assert _decode_5gnswo_conf("0102") is None


class Mbs5ueConfigDecoderTests:
    def test_xml_payload_decodes_cleanly(self) -> None:
        xml_text = b"<config/>"
        payload = bytes([0x80, len(xml_text)]) + xml_text
        decoded = _decode_5mbs_ue_config(payload.hex().upper())
        assert decoded is not None
        items = decoded["items"]
        assert len(items) == 1
        assert items[0]["decoded"] == "<config/>"


class McsV2xConfigDecoderTests:
    def test_mcs_config_surfaces_text_for_80(self) -> None:
        xml_text = b"<mcs/>"
        payload = bytes([0x80, len(xml_text)]) + xml_text
        decoded = _decode_ef_mcs_config(payload.hex().upper())
        assert decoded is not None
        assert decoded["items"][0]["decoded"] == "<mcs/>"

    def test_v2x_config_surfaces_text_for_80(self) -> None:
        xml_text = b"<v2x/>"
        payload = bytes([0x80, len(xml_text)]) + xml_text
        decoded = _decode_ef_v2x_config(payload.hex().upper())
        assert decoded is not None
        assert decoded["items"][0]["decoded"] == "<v2x/>"


class ProseRel18DecoderTests:
    def test_u2uru_decodes_small_int_timers(self) -> None:
        payload = bytes([0x85, 0x02, 0x00, 0x3C])
        decoded = _decode_5g_prose_tlv_ef(
            payload.hex().upper(),
            format_name="5G ProSe UE-to-UE Relay (User) Configuration",
            tag_names=_5G_PROSE_U2URU_TAGS,
        )
        assert decoded is not None
        items = decoded["items"]
        validity = next(i for i in items if i["tag"] == "85")
        assert validity["decoded"]["decimal"] == 60

    def test_eu_routes_through_shared_decoder(self) -> None:
        payload = bytes([0x92, 0x01, 0x05])
        decoded = _decode_5g_prose_tlv_ef(
            payload.hex().upper(),
            format_name="5G ProSe End-UE Configuration",
            tag_names=_5G_PROSE_EU_TAGS,
        )
        assert decoded is not None
        assert decoded["items"][0]["decoded"]["decimal"] == 5


class SnpnNidDecoderTests:
    def test_known_assignment_mode(self) -> None:
        decoded = _decode_ef_nid("00" + "0102030405")
        assert decoded is not None
        assert decoded["assignmentMode"]["label"].startswith("coordinated")
        assert decoded["nidHex"] == "0102030405"

    def test_self_assigned(self) -> None:
        decoded = _decode_ef_nid("01" + "FFEEDDCCBB")
        assert decoded is not None
        assert decoded["assignmentMode"]["label"] == "self-assigned"

    def test_rejects_wrong_length(self) -> None:
        assert _decode_ef_nid("0001") is None


class OcstDecoderTests:
    def test_sense_flag_parses(self) -> None:
        decoded = _decode_ef_ocst("01")
        assert decoded is not None
        assert decoded["senseEnabled"] is True

    def test_tlv_body_accepted(self) -> None:
        decoded = _decode_ef_ocst("00" + "8001AA")
        assert decoded is not None
        assert decoded["items"][0]["tag"] == "80"


class RplmnActDecoderTests:
    def test_single_record(self) -> None:
        decoded = _decode_ef_rplmnact("8000")
        assert decoded is not None
        assert len(decoded["entries"]) == 1

    def test_multiple_records(self) -> None:
        decoded = _decode_ef_rplmnact("80004000")
        assert decoded is not None
        assert len(decoded["entries"]) == 2

    def test_rejects_odd_length(self) -> None:
        assert _decode_ef_rplmnact("01") is None


class HnbFamilyDecoderTests:
    def test_hnbn_accepts_berTlv(self) -> None:
        payload = bytes([0x80, 0x03, 0x00, 0x41, 0x00])
        decoded = _decode_ef_hnbn(payload.hex().upper())
        assert decoded is not None
        assert decoded["items"][0]["tag"] == "80"

    def test_csgt_accepts_berTlv(self) -> None:
        payload = bytes([0x80, 0x05]) + b"hello"
        decoded = _decode_ef_csgt(payload.hex().upper())
        assert decoded is not None
        assert decoded["items"][0]["tag"] == "80"
        assert decoded["items"][0]["decoded"] == "hello"

    def test_acsgl_accepts_berTlv(self) -> None:
        payload = bytes([0x80, 0x03, 0x62, 0xF2, 0x10])
        decoded = _decode_ef_acsgl(payload.hex().upper())
        assert decoded is not None
        assert decoded["items"][0]["tag"] == "80"

    def test_ocsgl_accepts_berTlv(self) -> None:
        payload = bytes([0x80, 0x03, 0x62, 0xF2, 0x10])
        decoded = _decode_ef_ocsgl(payload.hex().upper())
        assert decoded is not None
        assert decoded["items"][0]["tag"] == "80"


class IsimExtraEfDecoderTests:
    """TS 31.103 §4.2.22 / §4.2.23 additions."""

    def test_gbauapi_splits_aid_and_naf_id(self) -> None:
        # 80 len innerAid(lenA,AID)(lenN,NAF)
        inner = bytes([0x05]) + bytes.fromhex("A000000087") + bytes([0x06]) + bytes.fromhex("DEADBEEF1122")
        tlv = bytes([0x80, len(inner)]) + inner
        decoded = _decode_ef_gbauapi(tlv.hex().upper())
        assert decoded is not None
        assert decoded["format"] == "EF.GBAUAPI"
        item = decoded["items"][0]
        assert item["tag"] == "80"
        assert item["decoded"]["aid"]["hex"] == "A000000087"
        assert item["decoded"]["naf_id"]["hex"] == "DEADBEEF1122"

    def test_imsdci_known_values(self) -> None:
        for byte, label in (
            (0x00, "ims_dc_not_allowed"),
            (0x01, "ims_dc_allowed_after_ims_session"),
            (0x02, "ims_dc_allowed_simultaneous_ims_session"),
        ):
            decoded = _decode_ef_imsdci(f"{byte:02X}")
            assert decoded is not None
            assert decoded["value"] == byte
            assert decoded["name"] == label

    def test_imsdci_reserved_value(self) -> None:
        decoded = _decode_ef_imsdci("FF")
        assert decoded is not None
        assert decoded["name"] == "reserved_0xFF"

    def test_imsdci_rejects_non_single_byte(self) -> None:
        assert _decode_ef_imsdci("0001") is None
        assert _decode_ef_imsdci("") is None


class LegacyGsmEfDecoderTests:
    """Promote former opaque EFs to semantic decoders (TS 51.011 §10.3)."""

    def test_locigprs_decodes_rai_and_status(self) -> None:
        decoded = _decode_ef_locigprs("ffffffffffffff22f8990000ff01")
        assert decoded is not None
        assert decoded["ptmsi"] == "FFFFFFFF"
        assert decoded["rai"]["plmn"] == "228-99"
        assert decoded["rauStatus"]["name"] == "not_updated"

    def test_locigprs_rejects_wrong_length(self) -> None:
        assert _decode_ef_locigprs("00" * 10) is None

    def test_cnl_records_parse_plmn(self) -> None:
        decoded = _decode_ef_cnl("62f210010203")
        assert decoded is not None
        record = decoded["records"][0]
        assert record["plmn"] == "262-01"
        assert record["networkSubset"] == 1
        assert record["serviceProviderId"] == 2
        assert record["corporateId"] == 3

    def test_cnl_rejects_misaligned_length(self) -> None:
        assert _decode_ef_cnl("0102030405") is None

    def test_vgcs_decodes_bcd_gid(self) -> None:
        decoded = _decode_vgcs_vbs_subscription("92f9ffff", format_name="VGCS Subscription")
        assert decoded is not None
        assert decoded["records"][0]["gid"] == "299"

    def test_vgcs_flags_free_slot(self) -> None:
        decoded = _decode_vgcs_vbs_subscription("ffffffff", format_name="VGCS Subscription")
        assert decoded is not None
        assert decoded["records"][0]["free"] is True

    def test_vgcss_flags_expose_active_subscriptions(self) -> None:
        decoded = _decode_vgcss_vbss_status("010000004540fc", format_name="VGCS Status")
        assert decoded is not None
        assert decoded["active"] == [1, 33, 35, 39, 47]

    def test_vgcss_rejects_wrong_length(self) -> None:
        assert _decode_vgcss_vbss_status("00", format_name="VGCS Status") is None


class ServiceTableBitMapTests:
    """Pin canonical TS 31.102 / TS 31.103 service-table assignments
    so a regression (hand-edit or stale generator output) is caught
    immediately. Key entries are picked from Rel-17/18 updates which
    are the most likely source of drift.
    """

    def test_ust_core_anchors(self) -> None:
        assert _UST_SERVICE_NAMES[1] == "Local Phone Book"
        assert _UST_SERVICE_NAMES[6] == "Barred Dialling Numbers (BDN)"
        assert _UST_SERVICE_NAMES[15] == "Cell Broadcast Message Identifier"
        assert _UST_SERVICE_NAMES[27] == "GSM Access"
        assert _UST_SERVICE_NAMES[38] == "GSM security context"
        assert _UST_SERVICE_NAMES[45] == "PLMN Network Name"

    def test_ust_5g_services_present(self) -> None:
        assert _UST_SERVICE_NAMES[122] == "5GS Mobility Management Information"
        assert _UST_SERVICE_NAMES[125] == "SUCI calculation by the USIM"
        assert _UST_SERVICE_NAMES[132] == "Support for URSP by USIM"
        assert _UST_SERVICE_NAMES[139] == "5G ProSe"
        assert _UST_SERVICE_NAMES[142] == "5G NSWO support"
        assert _UST_SERVICE_NAMES[145] == "K_AUSF derivation configuration"
        assert _UST_SERVICE_NAMES[146] == "Network Identifier for SNPN (NID)"

    def test_est_canonical(self) -> None:
        assert _EST_SERVICE_NAMES[1] == "Fixed Dialling Numbers (FDN)"
        assert _EST_SERVICE_NAMES[2] == "Barred Dialling Numbers (BDN)"
        assert _EST_SERVICE_NAMES[3] == "APN Control List (ACL)"

    def test_isim_rel18_additions(self) -> None:
        assert _ISIM_SERVICE_NAMES[20] == "WebRTC URI"
        assert _ISIM_SERVICE_NAMES[21] == "MuD and MiD configuration data"
        assert _ISIM_SERVICE_NAMES[22] == "IMS Data Channel indication"


class TelecomFixedCountersDecoderTests:
    """TS 31.102 §4.4.2.12.2-4 — PSC / CC / PUID."""

    def test_psc_counter(self) -> None:
        decoded = _decode_ef_psc("0000002A")
        assert decoded is not None
        assert decoded["synceCounter"] == 42

    def test_cc_counter(self) -> None:
        decoded = _decode_ef_cc_counter("0005")
        assert decoded is not None
        assert decoded["changeCounter"] == 5

    def test_puid_previous(self) -> None:
        decoded = _decode_ef_puid("0102")
        assert decoded is not None
        assert decoded["previousUid"] == 258

    def test_psc_rejects_wrong_length(self) -> None:
        assert _decode_ef_psc("00" * 8) is None


class FiveGSecurityContextDecoderTests:
    """TS 31.102 §4.4.11.4-6 — 5GS 3GPP NSC / 5GAUTHKEYS."""

    @staticmethod
    def _sample_nsc_record() -> str:
        inner = (
            "800105"
            + "8120" + ("CC" * 32)
            + "820400000001"
            + "830400000002"
            + "840112"
            + "850134"
        )
        return "A0" + "37" + inner

    def test_nsc_structure_and_algos(self) -> None:
        decoded = _decode_ef_5gs3gpp_nsc(
            self._sample_nsc_record(), format_name="NSC"
        )
        assert decoded is not None
        a0 = decoded["items"][0]
        sub_tags = {item["tag"]: item for item in a0["items"]}
        assert sub_tags["80"]["decoded"]["ngKSI"] == 5
        assert sub_tags["82"]["decoded"]["count"] == 1
        assert sub_tags["83"]["decoded"]["count"] == 2
        assert sub_tags["84"]["decoded"]["ciphering"] == 1
        assert sub_tags["84"]["decoded"]["integrity"] == 2
        assert sub_tags["85"]["decoded"]["ciphering"] == 3
        assert sub_tags["85"]["decoded"]["integrity"] == 4

    def test_5gauthkeys_contains_kausf_and_kseaf(self) -> None:
        payload = "80" + "20" + ("AA" * 32) + "81" + "20" + ("BB" * 32)
        decoded = _decode_ef_5gauthkeys(payload)
        assert decoded is not None
        tags = {item["tag"]: item for item in decoded["items"]}
        assert "80" in tags and tags["80"]["name"] == "K_AUSF"
        assert "81" in tags and tags["81"]["name"] == "K_SEAF"


class EarfcnListDecoderTests:
    """TS 31.102 §4.2.112 — EF.EARFCNList pySim regression vector."""

    _VECTOR = (
        "a01a8004000100008112000001100001000002100002000003100003"
    )

    def test_pysim_vector_parses(self) -> None:
        decoded = _decode_ef_earfcn_list(self._VECTOR)
        assert decoded is not None
        entry = decoded["items"][0]
        sub = {item["tag"]: item for item in entry["items"]}
        assert sub["80"]["decoded"]["earfcn"] == 65536
        points = sub["81"]["decoded"]["points"]
        assert points == [
            {"latitude": 1, "longitude": 1048577},
            {"latitude": 2, "longitude": 1048578},
            {"latitude": 3, "longitude": 1048579},
        ]


class CmiDecoderTests:
    """TS 51.011 §10.5.16 — EF.CMI record with GSM alpha tail."""

    def test_alpha_and_id(self) -> None:
        decoded = _decode_ef_cmi("48454C4C4FFFFFFF05")
        assert decoded is not None
        assert decoded["alphaId"]["text"]["text"] == "HELLO"
        assert decoded["comparisonMethodId"] == 5

    def test_rejects_too_short(self) -> None:
        assert _decode_ef_cmi("AA") is None


class DispatchRoutingTests:
    """Ensure the new tokens reach the right semantic decoder."""

    SAMPLE_LOCI_HEX = Loci5GsDecoderTests.SAMPLE_HEX

    def test_5gs3gpploci_routes_to_semantic_decoder(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-5gs3gpploci",
            fid=None,
            hex_clean=self.SAMPLE_LOCI_HEX,
        )
        assert decoded is not None
        assert decoded["format"] == "5GS 3GPP Location Info"
        assert "guti" in decoded

    def test_5gsedrx_routes_to_semantic_decoder(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-5gsedrx",
            fid=None,
            hex_clean="05",
        )
        assert decoded is not None
        assert decoded["format"] == "5GS eDRX Parameters"

    def test_5mbsueconfig_routes_to_semantic_decoder(self) -> None:
        payload = bytes([0x80, 0x05]) + b"hello"
        decoded = _decode_known_ef_payload(
            ef_key="ef-5mbsueconfig",
            fid=None,
            hex_clean=payload.hex().upper(),
        )
        assert decoded is not None
        assert decoded["format"] == "5MBS UE Pre-configuration"

    def test_hnbn_routes_to_semantic_decoder(self) -> None:
        payload = bytes([0x80, 0x02, 0x00, 0x41])
        decoded = _decode_known_ef_payload(
            ef_key="ef-hnbn",
            fid=None,
            hex_clean=payload.hex().upper(),
        )
        assert decoded is not None
        assert decoded["format"] == "Home NodeB Name"

    def test_nid_routes_to_semantic_decoder(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-nid",
            fid=None,
            hex_clean="000102030405",
        )
        assert decoded is not None
        assert decoded["format"] == "SNPN Network Identifier"

    def test_gbauapi_routes_to_semantic_decoder(self) -> None:
        inner = bytes([0x05]) + bytes.fromhex("A000000087") + bytes([0x04]) + bytes.fromhex("DEADBEEF")
        tlv = bytes([0x80, len(inner)]) + inner
        decoded = _decode_known_ef_payload(
            ef_key="ef-gbauapi",
            fid=None,
            hex_clean=tlv.hex().upper(),
        )
        assert decoded is not None
        assert decoded["format"] == "EF.GBAUAPI"

    def test_imsdci_routes_to_semantic_decoder(self) -> None:
        decoded = _decode_known_ef_payload(
            ef_key="ef-imsdci",
            fid=None,
            hex_clean="01",
        )
        assert decoded is not None
        assert decoded["format"] == "EF.IMSDCI"
        assert decoded["name"] == "ims_dc_allowed_after_ims_session"


class PhonebookAuxiliaryEfTests:
    """Round-2 Pass 1 — DF.PHONEBOOK administrative / auxiliary EFs."""

    @staticmethod
    def test_iap_pointer_map() -> None:
        decoded = _decode_ef_iap_record("01FF02FF")
        assert decoded is not None
        assert decoded["format"] == "Index Administration Phonebook"
        assert decoded["pointers"][0]["recordNumber"] == 1
        assert decoded["pointers"][1]["recordNumber"] is None
        assert decoded["pointers"][2]["recordNumber"] == 2

    @staticmethod
    def test_sne_alpha_string() -> None:
        decoded = _decode_ef_sne_record("416C696365FFFF", format_name="Second Name Entry")
        assert decoded is not None
        assert decoded["alpha"]["text"] == "Alice"

    @staticmethod
    def test_email_utf8() -> None:
        decoded = _decode_ef_email_record(
            "616C696365406578616D706C652E636F6DFFFF",
            format_name="EMAIL",
        )
        assert decoded is not None
        assert decoded["email"] == "alice@example.com"
        assert decoded["encoding"] == "utf-8"

    @staticmethod
    def test_gas_grouping_alpha() -> None:
        decoded = _decode_ef_gas_record("50726976617465FFFF")
        assert decoded is not None
        assert decoded["alpha"]["text"] == "Private"

    @staticmethod
    def test_grp_slot_decoding() -> None:
        decoded = _decode_ef_grp_record("0102FFFF")
        assert decoded is not None
        assert decoded["assignedGroups"] == [1, 2]

    @staticmethod
    def test_anl_alpha() -> None:
        decoded = _decode_ef_anl_record("416C69636500FFFF")
        assert decoded is not None
        assert isinstance(decoded["alpha"], dict)


class BcchDecoderTests:
    """Round-2 Pass 1 — EF.BCCH (TS 51.011 §10.3.25)."""

    @staticmethod
    def test_ba_list_bits() -> None:
        decoded = _decode_ef_bcch("80000000000000000000000000000001")
        assert decoded is not None
        assert decoded["baIndexes"] == [1, 128]
        assert decoded["length"] == 16

    @staticmethod
    def test_rejects_wrong_length() -> None:
        assert _decode_ef_bcch("8000") is None


class IsimCsgAndHostListDecoderTests:
    """Round-2 Pass 1 — NAFKCA / FCSL / PHist / PSISMSC BER-TLV decoders."""

    @staticmethod
    def test_nafkca_fqdn() -> None:
        decoded = _decode_ef_nafkca_list("80066E61662E636F")
        assert decoded is not None
        tag80 = decoded["items"][0]
        assert tag80["decoded"]["fqdn"] == "naf.co"

    @staticmethod
    def test_fcsl_plmn_csg_id() -> None:
        decoded = _decode_ef_fcsl("80072F3000F0000102")
        assert decoded is not None
        entry = decoded["items"][0]["decoded"]
        assert entry["plmn"] == "F20-003"
        assert entry["csgId"] == 0xF0000102

    @staticmethod
    def test_phist_hosts() -> None:
        decoded = _decode_ef_phist("8009686F73742E736174636F")
        assert decoded is not None
        assert decoded["items"][0]["decoded"]["fqdn"].startswith("host.")

    @staticmethod
    def test_psismsc_sip_uri() -> None:
        decoded = _decode_ef_psismsc("80117369703A736D7340696D732E6F70312E6E")
        assert decoded is not None
        assert decoded["items"][0]["decoded"]["fqdn"].startswith("sip:sms@")


class MailboxAndMenuDecoderTests:
    """Round-2 Pass 1 — mailbox / setup-menu / MExE service table."""

    @staticmethod
    def test_mbparam_voice_identifier() -> None:
        decoded = _decode_ef_mbparam("01766F696365")
        assert decoded is not None
        assert decoded["typeByte"] == "0x01"
        assert decoded["identifier"] == "voice"
        assert decoded["encoding"] == "utf-8"

    @staticmethod
    def test_setup_menu_alpha_id() -> None:
        decoded = _decode_ef_setup_menu_elements("85044D656E75")
        assert decoded is not None
        assert decoded["items"][0]["name"] == "Alpha Identifier"

    @staticmethod
    def test_mexe_st_bit_decoding() -> None:
        decoded = _decode_ef_mexe_st("07")
        assert decoded is not None
        services = [entry["service"] for entry in decoded["enabledServices"]]
        assert services == [1, 2, 3]


class OperatorControlEfDecoderTests:
    """Round-2 Pass 1 — SCP80 counter / SCP11 key / SIM lock / OTA state."""

    @staticmethod
    def test_scp80_counter() -> None:
        decoded = _decode_ef_scp80_counter("000123")
        assert decoded is not None
        assert decoded["counter"] == 0x000123

    @staticmethod
    def test_scp11_key_tlv() -> None:
        decoded = _decode_ef_scp11_key("800100810103")
        assert decoded is not None
        names = {item["name"] for item in decoded["items"]}
        assert {"Key Version Number", "Key Type"}.issubset(names)

    @staticmethod
    def test_simlock_state_enum() -> None:
        decoded = _decode_ef_simlock_state("01")
        assert decoded is not None
        assert decoded["state"] == "locked"

    @staticmethod
    def test_ota_state_enum() -> None:
        decoded = _decode_ef_ota_state("02")
        assert decoded is not None
        assert decoded["state"] == "in-progress"

    @staticmethod
    def test_ota_keys_tlv() -> None:
        decoded = _decode_ef_ota_keys("81040AAABBCC")
        assert decoded is not None
        assert decoded["items"][0]["name"] == "KID"


class LegacyNetworkParamsDecoderTests:
    """Round-2 Pass 2 — EF.NETPAR / EF.CPBCCH legacy GSM files."""

    @staticmethod
    def test_netpar_hplmn_search_period() -> None:
        decoded = _decode_ef_netpar("03000000")
        assert decoded is not None
        assert decoded["hplmnSearchPeriod"] == "18 minutes (3 * 6 min)"

    @staticmethod
    def test_netpar_no_search() -> None:
        decoded = _decode_ef_netpar("00000000")
        assert decoded is not None
        assert decoded["hplmnSearchPeriod"] == "no HPLMN search"

    @staticmethod
    def test_cpbcch_16_byte() -> None:
        decoded = _decode_ef_cpbcch("01" + "00" * 15)
        assert decoded is not None
        assert decoded["cpbcchIndexes"] == [8]

    @staticmethod
    def test_cpbcch_rejects_short() -> None:
        assert _decode_ef_cpbcch("0102") is None


class McsV2xProseTlvPromotionTests:
    """Round-2 Pass 2 — MCS / V2X / ProSe provisioned BER-TLV promotions."""

    @staticmethod
    def test_v2x_cfg_tag_named() -> None:
        decoded = _decode_generic_tlv_ef(
            "8001FF",
            format_name="V2X Configuration",
            spec_reference="TS 31.102 §4.4.14.3",
            tag_names=_EF_V2X_CFG_TAGS,
        )
        assert decoded is not None
        assert decoded["items"][0]["name"] == "V2X Services (bitmap)"

    @staticmethod
    def test_mcs_service_identifier_tag() -> None:
        decoded = _decode_generic_tlv_ef(
            "80026D63",
            format_name="MCS Root",
            spec_reference="TS 31.102 §4.4.13",
            tag_names=_EF_MCS_TAGS,
        )
        assert decoded is not None
        assert decoded["items"][0]["name"] == "MC Service Identifier"

    @staticmethod
    def test_prose_config_tag() -> None:
        decoded = _decode_generic_tlv_ef(
            "8001AA",
            format_name="ProSe PFSR",
            spec_reference="TS 31.102 §4.4.13.6",
            tag_names=_EF_PROSE_PROVISIONED_TAGS,
        )
        assert decoded is not None
        assert decoded["items"][0]["name"] == "ProSe Configuration"

    @staticmethod
    def test_ursp_rule_tag() -> None:
        decoded = _decode_generic_tlv_ef(
            "8002AABB",
            format_name="URSP",
            spec_reference="TS 31.102 §4.4.11.10",
            tag_names=_EF_URSP_TAGS,
        )
        assert decoded is not None
        assert decoded["items"][0]["name"] == "URSP Rule"


class ArrBooleanConditionDecoderTests:
    """Round-2 Pass 4 — EF.ARR boolean SC-DO templates (ISO 7816-4 §5.3.3)."""

    @staticmethod
    def test_simple_always_rule() -> None:
        decoded = _decode_ef_arr("8001019000")
        assert decoded is not None
        assert decoded["rules"][0]["condition"] == "Always"
        assert decoded["reference"].startswith("TS 102 221")

    @staticmethod
    def test_never_rule_terminate() -> None:
        decoded = _decode_ef_arr("8001409700")
        assert decoded is not None
        rule = decoded["rules"][0]
        assert rule["accessModes"] == ["TERMINATE"]
        assert rule["condition"] == "Never"

    @staticmethod
    def test_or_template_parses() -> None:
        # UPDATE (0x02) under OR(A4 PIN1) — single child to keep parse clean.
        inner = "A40683010195010880"
        outer = "A0" + f"{len(bytes.fromhex(inner)):02X}" + inner
        payload = "800102" + outer
        decoded = _decode_ef_arr(payload)
        assert decoded is not None
        rule = decoded["rules"][0]
        assert rule["operator"] == "OR"
        assert len(rule["children"]) >= 1

    @staticmethod
    def test_expanded_security_environment_tag() -> None:
        # A4 carrying 9E 01 05 (SE 5 reference) must surface in items.
        decoded = _decode_ef_arr("800101A4039E0105")
        assert decoded is not None
        items = decoded["rules"][0]["items"]
        tags = [item.get("tag") for item in items]
        assert "9E" in tags


class V2xpRel16PromotionTests:
    """Round-2 Pass 3 — EF.V2XP-Uu / EF.V2XP-PC5 BER-TLV promotions (TS 31.102 §4.6.5.4/5)."""

    @staticmethod
    def test_v2xp_uu_xml_value() -> None:
        decoded = _decode_ef_v2xp_uu("80043C78443E")
        assert decoded is not None
        assert decoded["items"][0]["decoded"] == "<xD>"

    @staticmethod
    def test_v2xp_pc5_xml_value() -> None:
        decoded = _decode_ef_v2xp_pc5("80053C786D6C3E")
        assert decoded is not None
        assert decoded["items"][0]["decoded"] == "<xml>"


class ThresholdDecoderTests:
    """Round-2 Pass 1 — EF.THRESHOLD corrected to 3 bytes (TS 31.102 §4.2.52)."""

    @staticmethod
    def test_three_byte_max_start() -> None:
        decoded = _decode_ef_threshold("800000")
        assert decoded is not None
        assert decoded["maxStart"] == 0x800000
        assert decoded["reference"] == "TS 31.102 §4.2.52"

    @staticmethod
    def test_rejects_one_byte() -> None:
        assert _decode_ef_threshold("05") is None


def _invoke_class_tests(cls: type) -> None:
    instance = cls()
    for name in dir(cls):
        if name.startswith("test_") is False:
            continue
        getattr(instance, name)()


@pytest.mark.parametrize(
    "klass",
    [
        FidRegistrationTests,
        Loci5GsDecoderTests,
        Edrx5gsDecoderTests,
        Nswo5gDecoderTests,
        Mbs5ueConfigDecoderTests,
        McsV2xConfigDecoderTests,
        ProseRel18DecoderTests,
        SnpnNidDecoderTests,
        OcstDecoderTests,
        RplmnActDecoderTests,
        HnbFamilyDecoderTests,
        IsimExtraEfDecoderTests,
        LegacyGsmEfDecoderTests,
        ServiceTableBitMapTests,
        TelecomFixedCountersDecoderTests,
        FiveGSecurityContextDecoderTests,
        EarfcnListDecoderTests,
        CmiDecoderTests,
        DispatchRoutingTests,
        PhonebookAuxiliaryEfTests,
        BcchDecoderTests,
        IsimCsgAndHostListDecoderTests,
        MailboxAndMenuDecoderTests,
        OperatorControlEfDecoderTests,
        LegacyNetworkParamsDecoderTests,
        McsV2xProseTlvPromotionTests,
        ArrBooleanConditionDecoderTests,
        V2xpRel16PromotionTests,
        ThresholdDecoderTests,
    ],
)
def test_deep_sweep_additions(klass: type) -> None:
    _invoke_class_tests(klass)
