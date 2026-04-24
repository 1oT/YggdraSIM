"""
Pure-Python ASN.1 / TLV decode helpers for tagged SAIP JSON.

This backend is used by the TRANSCODE-TUI inspector and intentionally avoids
imports from ``SCP03`` and ``pySim``. It combines:

- generic BER/DER decoding with universal ASN.1 type rendering,
- selected SAIP field decoders for BER-TLV payloads,
- common UICC EF payload decoders for transparent file content.
"""

from __future__ import annotations

from datetime import datetime
import ipaddress
import re
from typing import Any, Callable

from Tools.ProfilePackage.saip_json_codec import (
    _LEGACY_TAG_BYTES,
    _LEGACY_TAG_TUPLE,
    _TAG_BYTES,
    _TAG_TUPLE,
    _structural_data_keys,
    _value_first,
    base_pe_type,
    humanize_saip_display_name,
    humanize_saip_display_path,
)

ValueDecoder = Callable[[bytes], object | None]

_EF_KEY_TO_FID: dict[str, str] = {
    "adf-usim": "7FF0",
    "adf-isim": "7FF2",
    "adf-csim": "7FF3",
    "df-gsm": "7F20",
    "df-eap": "7F20",
    "df-pkcs15": "7F50",
    "df-gsm-access": "5F3B",
    "df-multimedia": "5F3B",
    "df-5gs": "5FC0",
    "df-saip": "5FD0",
    "df-snpn": "5FE0",
    "df-5gprose": "5FF0",
    # 5x20 Pass A — additional DF identifier tokens.
    "df-telecom": "7F10",
    "df-phonebook": "5F3A",
    "df-graphics": "5F50",
    "df-mms": "5F3D",
    "df-solsa": "5F70",
    "df-mexe": "5F3C",
    "df-wlan": "5F40",
    "df-hnb": "5F41",
    "df-oma-bcast": "5F60",
    "df-ecat": "5F80",
    "df-mcs": "5FA0",
    "df-mcptt": "5FA1",
    "df-mcvideo": "5FA2",
    "df-mcdata": "5FA3",
    "df-v2x": "5FA4",
    "df-prose": "5FA5",
    "df-iot": "5FA6",
    "df-5gprose-relay": "5FA7",
    "df-a2x": "5FA8",
    "df-hpsim": "5FA9",
    # 5x20 Pass B — additional ADF identifier tokens.
    "adf-hpsim": "7FF4",
    "adf-mcptt": "7FF5",
    "adf-mcvideo": "7FF6",
    "adf-mcdata": "7FF7",
    "adf-v2x": "7FF8",
    "adf-prose-ue": "7FF9",
    "adf-prose-relay": "7FFA",
    "adf-5gprose-relay": "7FFB",
    "adf-5gprose-disc": "7FFC",
    "adf-iot": "7FFD",
    "adf-dualimsi": "7FFE",
    "adf-cl": "7FFF",
    "adf-a2x": "7FE0",
    "adf-eap": "7FE1",
    "adf-test": "7FE2",
    "adf-snpn": "7FE3",
    "adf-orph": "7FE4",
    "adf-mcvdata": "7FE5",
    "adf-v2xrelay": "7FE6",
    "adf-a2xrelay": "7FE7",
    "ef-iccid": "2FE2",
    "ef-dir": "2F00",
    "ef-pl": "2F05",
    "ef-arr": "6F06",
    "ef-imsi": "6F07",
    "ef-keys": "6F08",
    "ef-ad": "6FAD",
    "ef-msisdn": "6F40",
    "ef-puct": "6F41",
    "ef-spn": "6F46",
    "ef-ust": "6F38",
    "ef-ust-service-table": "6F38",
    "ef-acc": "6F78",
    "ef-loci": "6F7E",
    "ef-psloci": "6F73",
    "ef-epsloci": "6FE3",
    "ef-hpplmn": "6F31",
    "ef-plmnwact": "6F60",
    "ef-oplmnwact": "6F61",
    "ef-hplmnwact": "6F62",
    "ef-fplmn": "6F7B",
    "ef-gid1": "6F3E",
    "ef-gid2": "6F3F",
    "ef-smsp": "6F42",
    "ef-smss": "6F43",
    "ef-sms": "6F3C",
    "ef-smsr": "6F47",
    "ef-cbmi": "6F45",
    "ef-cbmir": "6F50",
    "ef-cbmid": "6F48",
    "ef-sume": "6F54",
    # EF.THRESHOLD (TS 31.102 §4.2.52) lives at 6F5C. The legacy token
    # ``ef-s7`` for the same anchor is kept routed for backward
    # compatibility with older snapshots while ``ef-threshold`` is the
    # preferred pySim-aligned key.
    "ef-threshold": "6F5C",
    "ef-s7": "6F5C",
    "ef-start-hfn": "6F5B",
    "ef-est": "6F56",
    "ef-li": "6F05",
    "ef-acmax": "6F37",
    "ef-acm": "6F39",
    "ef-ecc": "6FB7",
    "ef-acl": "6F57",
    "ef-ccp1": "6F3D",
    "ef-ext1": "6F4A",
    "ef-ext2": "6F4B",
    "ef-ext3": "6F4C",
    "ef-ccp2": "6F4F",
    "ef-cmi": "6F58",
    "ef-ict": "6F82",
    "ef-oct": "6F83",
    "ef-adn": "6F3A",
    "ef-fdn": "6F3B",
    "ef-sdn": "6F49",
    "ef-lnd": "6F44",
    "ef-pnn": "6FC5",
    "ef-opl": "6FC6",
    "ef-spdi": "6FCD",
    "ef-ehplmn": "6FD9",
    "ef-ehplmnpi": "6FDB",
    "ef-epsnsc": "6FE4",
    "ef-hiddenkey": "6FC3",
    "ef-netpar": "6FC4",
    "ef-nia": "6FD3",
    "ef-lrplmnsi": "6FDC",
    "ef-nasconfig": "6FE8",
    "ef-pkcs15-odf": "5031",
    "ef-pkcs15-dodf": "5207",
    "ef-pkcs15-acm": "4200",
    "ef-pkcs15-acrf": "4300",
    "ef-pkcs15-accf": "4310",
    "ef-gbanl": "6FDA",
    "ef-nafkca": "6FDD",
    "ef-kc": "4F20",
    "ef-kcgprs": "4F52",
    "ef-cpbcch": "4F63",
    "ef-invscan": "4F64",
    "ef-impi": "6F02",
    "ef-domain": "6F03",
    "ef-impu": "6F04",
    "ef-ist": "6F07",
    "ef-ici": "6F80",
    "ef-oci": "6F81",
    "ef-keysPS": "6F09",
    "ef-pcscf": "6F09",
    # ISIM extras (TS 31.103 §4.2.22 / §4.2.23).
    "ef-gbauapi": "6F0A",
    "ef-imsdci": "6F0B",
    "ef-suci-calc-info-usim": "4F01",
    "ef-supinai": "4F09",
    # ADF.USIM housekeeping additions missing up until now
    # (pySim / TS 31.102 §4.4.2 / §4.4.3).
    "ef-ocst": "6F02",  # also collides with ISIM EF.IMPI; parent routing.
    "ef-rplmnact": "6F65",
    # 5x10 Pass A — 5G EFs (DF.5GS = 5FC0).
    "ef-5gs3gpploci": "4F01",
    "ef-5gsn3gpploci": "4F02",
    "ef-5gs3gppnsc": "4F03",
    "ef-5gsn3gppnsc": "4F04",
    "ef-5gauthkeys": "4F05",
    "ef-uac-aic": "4F06",
    "ef-5g-suci-calc-info": "4F07",
    "ef-opl5g": "4F08",
    "ef-routing-indicator": "4F0A",
    "ef-ursp": "4F0B",
    # 5x10 Pass C — 5G extras.
    "ef-tn3gppsnn": "4F0C",
    # Rel-17 additions (TS 31.102 §4.4.11.14-22). Previously
    # ``ef-5gsedrx`` / ``ef-5gnswo-conf`` were mis-mapped to 4F0D/4F0E
    # which is actually the territory of CAG / SOR-CMCI; pySim-aligned
    # FIDs restore the right anchors so live card dumps route to the
    # correct semantic decoders.
    "ef-cag": "4F0D",
    "ef-sor-cmci": "4F0E",
    "ef-dri": "4F0F",
    "ef-5gsedrx": "4F10",
    "ef-5gnswo-conf": "4F11",
    "ef-mchpplmn": "4F15",
    "ef-kausf-derivation": "4F16",
    # Rel-18 ProSe additions (TS 31.102 §4.4.13.8/§4.4.13.9, in DF.5G_ProSe).
    # These collide with ADF.USIM anchors at the bare FID level (4F07 is
    # also ``ef-5g-suci-calc-info`` under DF.5GS); parent-context routing
    # in the FID collision map disambiguates them.
    "ef-5g-prose-u2uru": "4F07",
    "ef-5g-prose-eu": "4F08",
    # Rel-18 5MBS (TS 31.102 §4.4.14.2, in DF.5MBSUECONFIG = 5FF1).
    "ef-5mbsueconfig": "4F01",
    # DF.SNPN (TS 31.102 §4.4.11.13, FID 5FE0). Collides with DF.5GS EFs
    # at the bare FID level; parent-token routing disambiguates.
    "ef-nid": "4F02",
    # DF.HNB (TS 31.102 §4.4.6, FID 5F50). Home NodeB file system.
    "ef-acsgl": "4F81",
    "ef-csgt": "4F82",
    "ef-hnbn": "4F83",
    "ef-ocsgl": "4F84",
    # 5x10 Pass B / D — DF.PHONEBOOK = 5F3A (under DF.TELECOM 7F10).
    "ef-pbr": "4F30",
    "ef-iap": "4F25",
    "ef-anr": "4F11",
    "ef-anra": "4F12",
    "ef-anrb": "4F13",
    "ef-anrc": "4F14",
    "ef-sne": "4F19",
    "ef-snea": "4F1A",
    "ef-sneb": "4F1B",
    "ef-email": "4F50",
    "ef-emailb": "4F51",
    "ef-gas": "4F4C",
    "ef-grp": "4F26",
    "ef-psc": "4F22",
    "ef-cc": "4F23",
    "ef-puid": "4F24",
    # 5x10 Pass C — additional 3GPP / legacy.
    "ef-phase": "6FAE",
    "ef-plmnsel": "6F30",
    "ef-bcch": "6F74",
    "ef-locigprs": "6F53",
    # TS 31.102 §4.2.x Rel-18: FDNURI=6FED, BDNURI=6FEE, SDNURI=6FEF. The
    # previous layout mis-anchored FDN at 6FEB and SDN at 6FEC (which is
    # actually EF.PWS), which in turn caused colliding tree-pane labels
    # such as "EF.SDN URI / EF.PWS" under ADF.USIM and broke parent-hint
    # disambiguation for live card dumps.
    "ef-fdnuri": "6FED",
    "ef-bdnuri": "6FEE",
    "ef-sdnuri": "6FEF",
    "ef-lnduri": "6FEA",
    # 5x10 Pass D — ISIM + multimedia extras.
    "ef-muddomain": "6FDF",
    "ef-pcscf-urn": "6F09",
    "ef-psismsc": "6FE5",
    "ef-uiccsi": "6FE6",
    "ef-ehuri": "6FE7",
    "ef-impdf": "6F27",
    "ef-nafkca-list": "6FDE",
    "ef-earfcnlist": "6FFD",
    # ``ef-fcst`` (Forbidden CSG List, SAIP-side token) and ``ef-phist``
    # (Provider Host List) are not anchored in TS 31.102 and previously
    # stomped on EF.BDNURI (6FEE) / EF.SDNURI (6FEF). They remain token-
    # routable via _decode_known_ef_payload but no longer pollute the
    # flat FID map. If a profile vendor assigns a concrete FID it should
    # go in its own vendor namespace.
    # TS 31.102 §4.2.96-§4.2.106 Rel-13/14/15 ADF.USIM singletons that
    # were missing from the FID map — needed so both token-based and
    # FID-based lookups route to their semantic decoders.
    "ef-pws": "6FEC",
    "ef-ips": "6FF1",
    "ef-vgcsca": "6FD4",
    "ef-epdgid": "6FF3",
    "ef-epdgselection": "6FF4",
    "ef-frompreferred": "6FF7",
    "ef-eaka": "6F01",
    # 5x20 Pass A — Mailbox / CF / VGCS / VBS / eMLPP / DCK / CNL family.
    "ef-mbdn": "6FC7",
    "ef-ext6": "6FC8",
    "ef-mbi": "6FC9",
    "ef-mwis": "6FCA",
    "ef-cfis": "6FCB",
    "ef-ext7": "6FCC",
    "ef-mbparam": "6FCE",
    "ef-cfis2": "6FE0",
    "ef-dck": "6F2C",
    "ef-cnl": "6F32",
    "ef-vgcs": "6FB1",
    "ef-vgcss": "6FB2",
    "ef-vbs": "6FB3",
    "ef-vbss": "6FB4",
    "ef-emlpp": "6FB5",
    "ef-aaem": "6FB6",
    "ef-anl": "6F2E",
    "ef-mexe-st": "6F3A",
    "ef-prose-pfsr": "4F30",
    "ef-vsuri": "6FE9",
    # 5x20 Pass B — CSIM (ADF.CSIM) EFs. Tokens namespaced as ``ef-csim-*``
    # because CDMA FIDs overlap USIM/ISIM FIDs when looked at in isolation.
    "ef-csim-spc": "6F20",
    "ef-csim-smscap": "6F21",
    "ef-csim-min": "6F22",
    "ef-csim-min1": "6F23",
    "ef-csim-accolc": "6F24",
    "ef-csim-imsi-t": "6F25",
    "ef-csim-home-sidnid": "6F26",
    "ef-csim-curr-sidnid": "6F27",
    "ef-csim-nam-lock": "6F28",
    "ef-csim-3gpd": "6F29",
    "ef-csim-hpplmnact": "6F2A",
    "ef-csim-prl": "6F30",
    "ef-csim-eprl": "6F4A",
    "ef-csim-namgam": "6F35",
    "ef-csim-mdn": "6F40",
    "ef-csim-plslpp": "6F46",
    "ef-csim-hrpdcap": "4F20",
    "ef-csim-ssci": "6F4E",
    "ef-csim-mlpl": "6F4F",
    "ef-csim-meruiid": "6F5D",
    # 5x20 Pass C — Specialized (ISIM + MCPTT + V2X + ProSe + MCS).
    "ef-prose-pfidg": "4F04",
    "ef-prose-pfddn": "4F05",
    "ef-v2x-cfg": "4F01",
    "ef-v2x-pre-cfg": "4F02",
    "ef-v2x-cert": "4F03",
    "ef-v2x-auth-keys": "4F04",
    "ef-mcs-root": "6FA0",
    "ef-mcptt-cfg": "6FA1",
    "ef-mcptt-sip": "6FA2",
    "ef-mcs-user-id": "6FA3",
    "ef-mcs-app-list": "6FA4",
    "ef-mcs-gms": "6FA5",
    "ef-mcs-cmsi": "6FA6",
    "ef-mcs-media-cfg": "6FA7",
    "ef-mcs-pub-id": "6FA8",
    "ef-mcs-profile": "6FA9",
    "ef-mcs-emergency": "6FAA",
    "ef-mcs-keyset": "6FAB",
    "ef-mcs-stat": "6FAC",
    "ef-mcs-sec-profile": "6FAF",
    # 5x20 Pass D — Operator / vendor extensions + auxiliary EFs.
    "ef-opcust1": "4F90",
    "ef-opcust2": "4F91",
    "ef-opcust3": "4F92",
    "ef-opcust4": "4F93",
    "ef-opcust5": "4F94",
    "ef-vendor1": "4F95",
    "ef-vendor2": "4F96",
    "ef-vendor3": "4F97",
    "ef-vendor4": "4F98",
    "ef-vendor5": "4F99",
    "ef-scp11key": "4F61",
    "ef-scp80ctr": "4F62",
    "ef-simlock-state": "4F67",
    "ef-ota-state": "4F68",
    "ef-ota-keys": "4F69",
    "ef-provconfig": "4F6A",
    "ef-selfservice": "4F6B",
    "ef-appconfig": "4F6C",
    "ef-acmp": "4F6D",
    "ef-tui": "4F6E",
}

_EXTRA_FID_NAMES = {
    "3F00": "MF",
    "7F10": "DF.TELECOM",
    "7F11": "DF.CD",
    "7FFF": "ADF.USIM",
    "5F3A": "DF.PHONEBOOK",
    "5F50": "DF.GRAPHICS",
    "6F20": "EF.KC",
    "6F30": "EF.PLMNSEL",
    "6F52": "EF.KCGPRS",
    "6F53": "EF.LOCIGPRS / EF.RMA",
    "6F74": "EF.BCCH",
    "6FAE": "EF.PHASE",
}


# ---------------------------------------------------------------------------
# Parent-context disambiguation for FID label lookup.
#
# Several FIDs legitimately coexist under different DF/ADF parents. The most
# visible case is 6F40 — ``EF.MSISDN`` under ADF.USIM/DF.TELECOM and
# ``EF.CSIM-MDN`` under ADF.CSIM. A flat FID -> name map combines both labels,
# which surfaces in the TRANSCODE tree pane as a garbled "MSISDN / CSIM-MDN"
# badge regardless of the actual parent. The maps below let callers scope the
# lookup to the parent DF/ADF they are currently decoding.
# ---------------------------------------------------------------------------

# Canonical parent DF/ADF token per ef-* key. Entries are deliberately
# explicit (instead of derived from the ef-key prefix) so that edge cases
# such as DF.TELECOM aliases and mixed USIM/ISIM EFs stay auditable.
_EF_KEY_TO_PARENT_TOKEN: dict[str, str] = {
    # MF-level housekeeping.
    "ef-iccid": "mf",
    "ef-dir": "mf",
    "ef-pl": "mf",
    # ADF.USIM (TS 31.102).
    "ef-imsi": "adf-usim",
    "ef-keys": "adf-usim",
    "ef-keysPS": "adf-usim",
    "ef-ad": "adf-usim",
    "ef-msisdn": "adf-usim",
    "ef-puct": "adf-usim",
    "ef-spn": "adf-usim",
    "ef-ust": "adf-usim",
    "ef-ust-service-table": "adf-usim",
    "ef-acc": "adf-usim",
    "ef-loci": "adf-usim",
    "ef-psloci": "adf-usim",
    "ef-epsloci": "adf-usim",
    "ef-hpplmn": "adf-usim",
    "ef-plmnwact": "adf-usim",
    "ef-oplmnwact": "adf-usim",
    "ef-hplmnwact": "adf-usim",
    "ef-fplmn": "adf-usim",
    "ef-gid1": "adf-usim",
    "ef-gid2": "adf-usim",
    "ef-smsp": "adf-usim",
    "ef-smss": "adf-usim",
    "ef-sms": "adf-usim",
    "ef-smsr": "adf-usim",
    "ef-cbmi": "adf-usim",
    "ef-cbmir": "adf-usim",
    "ef-cbmid": "adf-usim",
    "ef-sume": "adf-usim",
    "ef-s7": "adf-usim",
    "ef-threshold": "adf-usim",
    "ef-start-hfn": "adf-usim",
    "ef-pws": "adf-usim",
    "ef-ips": "adf-usim",
    "ef-vgcsca": "adf-usim",
    "ef-epdgid": "adf-usim",
    "ef-epdgselection": "adf-usim",
    "ef-frompreferred": "adf-usim",
    "ef-eaka": "adf-usim",
    "ef-est": "adf-usim",
    "ef-li": "adf-usim",
    "ef-acmax": "adf-usim",
    "ef-acm": "adf-usim",
    "ef-ecc": "adf-usim",
    "ef-acl": "adf-usim",
    "ef-ccp1": "adf-usim",
    "ef-ccp2": "adf-usim",
    "ef-cmi": "adf-usim",
    "ef-ict": "adf-usim",
    "ef-oct": "adf-usim",
    "ef-pnn": "adf-usim",
    "ef-opl": "adf-usim",
    "ef-spdi": "adf-usim",
    "ef-ehplmn": "adf-usim",
    "ef-ehplmnpi": "adf-usim",
    "ef-epsnsc": "adf-usim",
    "ef-hiddenkey": "adf-usim",
    "ef-netpar": "adf-usim",
    "ef-nia": "adf-usim",
    "ef-lrplmnsi": "adf-usim",
    "ef-nasconfig": "adf-usim",
    "ef-gbanl": "adf-usim",
    "ef-nafkca": "adf-usim",
    "ef-suci-calc-info-usim": "adf-usim",
    "ef-supinai": "adf-usim",
    "ef-ocst": "adf-usim",
    "ef-rplmnact": "adf-usim",
    "ef-mbdn": "adf-usim",
    "ef-ext6": "adf-usim",
    "ef-mbi": "adf-usim",
    "ef-mwis": "adf-usim",
    "ef-cfis": "adf-usim",
    "ef-ext7": "adf-usim",
    "ef-mbparam": "adf-usim",
    "ef-cfis2": "adf-usim",
    "ef-dck": "adf-usim",
    "ef-cnl": "adf-usim",
    "ef-vgcs": "adf-usim",
    "ef-vgcss": "adf-usim",
    "ef-vbs": "adf-usim",
    "ef-vbss": "adf-usim",
    "ef-emlpp": "adf-usim",
    "ef-aaem": "adf-usim",
    "ef-anl": "adf-usim",
    "ef-vsuri": "adf-usim",
    "ef-fdnuri": "adf-usim",
    "ef-bdnuri": "adf-usim",
    "ef-sdnuri": "adf-usim",
    "ef-lnduri": "adf-usim",
    "ef-earfcnlist": "adf-usim",
    # DF.TELECOM (TS 51.011 / TS 31.102 §4.4). The modern ADF.USIM hosts the
    # same tokens for legacy profiles, but DF.TELECOM is the authoritative
    # parent for the phonebook / SMS-related EFs that originate there.
    "ef-adn": "df-telecom",
    "ef-fdn": "df-telecom",
    "ef-sdn": "df-telecom",
    "ef-lnd": "df-telecom",
    "ef-ext1": "df-telecom",
    "ef-ext2": "df-telecom",
    "ef-ext3": "df-telecom",
    # DF.PHONEBOOK (under DF.TELECOM).
    "ef-pbr": "df-phonebook",
    "ef-iap": "df-phonebook",
    "ef-anr": "df-phonebook",
    "ef-anra": "df-phonebook",
    "ef-anrb": "df-phonebook",
    "ef-anrc": "df-phonebook",
    "ef-sne": "df-phonebook",
    "ef-snea": "df-phonebook",
    "ef-sneb": "df-phonebook",
    "ef-email": "df-phonebook",
    "ef-emailb": "df-phonebook",
    "ef-gas": "df-phonebook",
    "ef-grp": "df-phonebook",
    "ef-psc": "df-phonebook",
    "ef-cc": "df-phonebook",
    "ef-puid": "df-phonebook",
    # DF.GSM / DF.GSM-ACCESS (TS 51.011 legacy + TS 31.102 §4.4.2).
    "ef-kc": "df-gsm",
    "ef-kcgprs": "df-gsm",
    "ef-cpbcch": "df-gsm-access",
    "ef-invscan": "df-gsm-access",
    "ef-phase": "df-gsm-access",
    "ef-plmnsel": "df-gsm-access",
    "ef-bcch": "df-gsm-access",
    "ef-locigprs": "df-gsm-access",
    # DF.PKCS15.
    "ef-pkcs15-odf": "df-pkcs15",
    "ef-pkcs15-dodf": "df-pkcs15",
    "ef-pkcs15-acm": "df-pkcs15",
    "ef-pkcs15-acrf": "df-pkcs15",
    "ef-pkcs15-accf": "df-pkcs15",
    # DF.5GS (under ADF.USIM).
    "ef-5gs3gpploci": "df-5gs",
    "ef-5gsn3gpploci": "df-5gs",
    "ef-5gs3gppnsc": "df-5gs",
    "ef-5gsn3gppnsc": "df-5gs",
    "ef-5gauthkeys": "df-5gs",
    "ef-uac-aic": "df-5gs",
    "ef-5g-suci-calc-info": "df-5gs",
    "ef-opl5g": "df-5gs",
    "ef-routing-indicator": "df-5gs",
    "ef-ursp": "df-5gs",
    "ef-tn3gppsnn": "df-5gs",
    "ef-5gsedrx": "df-5gs",
    "ef-5gnswo-conf": "df-5gs",
    # Rel-17 DF.5GS additions (TS 31.102 §4.4.11.14-22).
    "ef-cag": "df-5gs",
    "ef-sor-cmci": "df-5gs",
    "ef-dri": "df-5gs",
    "ef-mchpplmn": "df-5gs",
    "ef-kausf-derivation": "df-5gs",
    # DF.5G_ProSe (under ADF.USIM, TS 31.102 §4.4.13).
    "ef-5g-prose-st": "df-5gprose",
    "ef-5g-prose-dd": "df-5gprose",
    "ef-5g-prose-dc": "df-5gprose",
    "ef-5g-prose-u2nru": "df-5gprose",
    "ef-5g-prose-ru": "df-5gprose",
    "ef-5g-prose-uir": "df-5gprose",
    "ef-5g-prose-u2uru": "df-5gprose",
    "ef-5g-prose-eu": "df-5gprose",
    # DF.SNPN (TS 31.102 §4.4.11.13) and DF.5MBSUECONFIG (TS 31.102 §4.4.14).
    "ef-pws-snpn": "df-snpn",
    "ef-nid": "df-snpn",
    "ef-5mbsueconfig": "df-5mbsueconfig",
    "ef-5mbsusd": "df-5mbsueconfig",
    # DF.HNB (TS 31.102 §4.4.6).
    "ef-acsgl": "df-hnb",
    "ef-csgt": "df-hnb",
    "ef-hnbn": "df-hnb",
    "ef-ocsgl": "df-hnb",
    # ADF.ISIM (TS 31.103).
    "ef-impi": "adf-isim",
    "ef-domain": "adf-isim",
    "ef-impu": "adf-isim",
    "ef-ist": "adf-isim",
    "ef-ici": "adf-isim",
    "ef-oci": "adf-isim",
    "ef-pcscf": "adf-isim",
    "ef-pcscf-urn": "adf-isim",
    "ef-muddomain": "adf-isim",
    "ef-psismsc": "adf-isim",
    "ef-uiccsi": "adf-isim",
    "ef-ehuri": "adf-isim",
    "ef-impdf": "adf-isim",
    "ef-nafkca-list": "adf-isim",
    "ef-gbauapi": "adf-isim",
    "ef-imsdci": "adf-isim",
    # ADF.CSIM (3GPP2 C.S0065).
    "ef-csim-spc": "adf-csim",
    "ef-csim-smscap": "adf-csim",
    "ef-csim-min": "adf-csim",
    "ef-csim-min1": "adf-csim",
    "ef-csim-accolc": "adf-csim",
    "ef-csim-imsi-t": "adf-csim",
    "ef-csim-home-sidnid": "adf-csim",
    "ef-csim-curr-sidnid": "adf-csim",
    "ef-csim-nam-lock": "adf-csim",
    "ef-csim-3gpd": "adf-csim",
    "ef-csim-hpplmnact": "adf-csim",
    "ef-csim-prl": "adf-csim",
    "ef-csim-eprl": "adf-csim",
    "ef-csim-namgam": "adf-csim",
    "ef-csim-mdn": "adf-csim",
    "ef-csim-plslpp": "adf-csim",
    "ef-csim-hrpdcap": "adf-csim",
    "ef-csim-ssci": "adf-csim",
    "ef-csim-mlpl": "adf-csim",
    "ef-csim-meruiid": "adf-csim",
    # ProSe / V2X / MCS application-specific EFs.
    "ef-prose-pfidg": "adf-prose-ue",
    "ef-prose-pfddn": "adf-prose-ue",
    "ef-prose-pfsr": "df-prose",
    "ef-v2x-cfg": "adf-v2x",
    "ef-v2x-pre-cfg": "adf-v2x",
    "ef-v2x-cert": "adf-v2x",
    "ef-v2x-auth-keys": "adf-v2x",
    "ef-mcs-root": "df-mcs",
    "ef-mcptt-cfg": "adf-mcptt",
    "ef-mcptt-sip": "adf-mcptt",
    "ef-mcs-user-id": "df-mcs",
    "ef-mcs-app-list": "df-mcs",
    "ef-mcs-gms": "df-mcs",
    "ef-mcs-cmsi": "df-mcs",
    "ef-mcs-media-cfg": "df-mcs",
    "ef-mcs-pub-id": "df-mcs",
    "ef-mcs-profile": "df-mcs",
    "ef-mcs-emergency": "df-mcs",
    "ef-mcs-keyset": "df-mcs",
    "ef-mcs-stat": "df-mcs",
    "ef-mcs-sec-profile": "df-mcs",
    # DF.MEXE (TS 51.011 §10.6).
    "ef-mexe-st": "df-mexe",
}

# Map SAIP profile-element ("section") types to their implicit parent
# DF/ADF token. Base PE types (as produced by ``base_pe_type``) are used so
# that duplicate PEs such as ``usim_2`` fold onto the same hint.
_PE_TYPE_TO_PARENT_TOKEN: dict[str, str] = {
    "mf": "mf",
    "usim": "adf-usim",
    "opt-usim": "adf-usim",
    "telecom": "df-telecom",
    "opt-telecom": "df-telecom",
    "phonebook": "df-phonebook",
    "gsm-access": "df-gsm-access",
    "df-5gs": "df-5gs",
    "df-5g-prose": "df-5gprose",
    "df-snpn": "df-snpn",
    "df-5mbsueconfig": "df-5mbsueconfig",
    "df-hnb": "df-hnb",
    "df-saip": "df-saip",
    "isim": "adf-isim",
    "opt-isim": "adf-isim",
    "csim": "adf-csim",
    "opt-csim": "adf-csim",
    "eap": "df-eap",
    "df-eap": "df-eap",
    "genericfilemanagement": "",
    "genericFileManagement": "",
}


def _parent_label_from_token(token: str | None) -> str | None:
    text = str(token or "").strip()
    if len(text) == 0:
        return None
    upper = text.upper()
    if upper.startswith("ADF-"):
        return "ADF." + upper[4:]
    if upper.startswith("DF-"):
        return "DF." + upper[3:]
    if upper == "MF":
        return "MF"
    return upper


def _ef_label_from_key(ef_key: str) -> str:
    return (
        ef_key.upper()
        .replace("ADF-", "ADF.")
        .replace("EF-", "EF.")
        .replace("DF-", "DF.")
    )


def _build_fid_parented_names() -> dict[str, list[tuple[str | None, str]]]:
    by_fid: dict[str, list[tuple[str | None, str]]] = {}
    for ef_key, fid in _EF_KEY_TO_FID.items():
        parent_token = _EF_KEY_TO_PARENT_TOKEN.get(ef_key)
        label = _ef_label_from_key(ef_key)
        entries = by_fid.setdefault(fid.upper(), [])
        for existing_parent, existing_label in entries:
            if existing_label == label and existing_parent == parent_token:
                break
        else:
            entries.append((parent_token, label))
    return by_fid


_FID_TO_PARENTED_NAMES: dict[str, list[tuple[str | None, str]]] = (
    _build_fid_parented_names()
)


def _build_fid_name_map() -> dict[str, str]:
    """
    Return a flat ``FID -> combined label`` map.

    For FIDs with a single candidate the label is returned verbatim. Colliding
    FIDs get a disambiguated label where each candidate carries its parent
    DF/ADF suffix (e.g. ``"EF.MSISDN (ADF.USIM) / EF.CSIM-MDN (ADF.CSIM)"``).
    ``_EXTRA_FID_NAMES`` entries are preserved for legacy callers that look up
    containers (MF/DF) directly.
    """

    mapping = dict(_EXTRA_FID_NAMES)
    for fid_hex, entries in _FID_TO_PARENTED_NAMES.items():
        if len(entries) == 0:
            continue
        if len(entries) == 1:
            _, label = entries[0]
            mapping[fid_hex] = label
            continue
        unique_parents = {parent for parent, _label in entries}
        parts: list[str] = []
        if len(unique_parents) <= 1:
            for _parent, label in entries:
                if label not in parts:
                    parts.append(label)
            mapping[fid_hex] = " / ".join(parts)
            continue
        for parent_token, label in entries:
            parent_label = _parent_label_from_token(parent_token)
            if parent_label is None:
                parts.append(label)
                continue
            parts.append(f"{label} ({parent_label})")
        mapping[fid_hex] = " / ".join(parts)
    # Preserve any legacy names whose FIDs aren't populated by ef-* tokens.
    for legacy_fid, legacy_name in _EXTRA_FID_NAMES.items():
        mapping.setdefault(legacy_fid, legacy_name)
    return mapping


_FID_TO_NAME = _build_fid_name_map()


def _normalize_parent_hint(hint: str | object | None) -> str | None:
    text = str(hint or "").strip()
    if len(text) == 0:
        return None
    base = base_pe_type(text).strip().lower()
    if len(base) == 0:
        base = text.lower()
    mapped = _PE_TYPE_TO_PARENT_TOKEN.get(base, base)
    if len(mapped) == 0:
        return None
    return mapped


def fid_candidates(fid_hex: str) -> list[tuple[str | None, str]]:
    """Return ``(parent_token, label)`` candidates for ``fid_hex``."""

    return list(_FID_TO_PARENTED_NAMES.get(str(fid_hex or "").upper(), ()))


# Reverse lookup: DF/ADF FID -> canonical parent token. Used by the GFM
# walker (and similar callers) to convert a SELECT target / filePath tail
# into a parent hint for subsequent file-ID resolution.
_DF_FID_TO_PARENT_TOKEN: dict[str, str] = {
    fid.upper(): token
    for token, fid in _EF_KEY_TO_FID.items()
    if token.startswith(("adf-", "df-"))
}
# MF itself maps onto the mf bucket.
_DF_FID_TO_PARENT_TOKEN.setdefault("3F00", "mf")


def parent_token_for_container_fid(fid_hex: str | None) -> str | None:
    """
    Resolve a container (DF/ADF/MF) FID to its canonical parent token.

    The returned token is the one used by :func:`fid_name` and the PE-type
    map, e.g. ``"adf-usim"`` for ``7FF0`` or ``"df-telecom"`` for ``7F10``.
    Returns ``None`` when the FID is not a recognised container.
    """

    text = str(fid_hex or "").strip().upper()
    if len(text) == 0:
        return None
    return _DF_FID_TO_PARENT_TOKEN.get(text)


def parent_token_from_file_path_hex(path_hex: str | None) -> str | None:
    """
    Pick the best parent-token hint from a SELECT / filePath hex string.

    The path is scanned tail-first, returning the nearest recognised DF/ADF
    container token. This lets GFM command renderers derive a parent hint
    from their current ``filePath`` without having to decode the whole
    sequence into segments.
    """

    text = str(path_hex or "").strip().replace(" ", "").replace("\n", "").upper()
    if len(text) == 0 or len(text) % 4 != 0:
        return None
    for offset in range(len(text) - 4, -1, -4):
        fid = text[offset : offset + 4]
        token = _DF_FID_TO_PARENT_TOKEN.get(fid)
        if token is not None:
            return token
    return None


def _resolve_ef_key_for_fid(
    fid_hex: str, parent_token: str | None
) -> str | None:
    """
    Pick the ef-* token matching ``fid_hex`` under ``parent_token``.

    Returns the single ef-* key whose parent-token equals ``parent_token``.
    If multiple ef-* keys share both the FID and the parent (e.g. the
    ``ef-ust`` / ``ef-ust-service-table`` alias at 6F38), the alphabetically
    first key is returned so dispatching remains deterministic. Returns
    ``None`` when the FID is unknown or no ef-* key matches the hint.
    """

    fid_upper = str(fid_hex or "").strip().upper()
    if len(fid_upper) == 0 or parent_token is None:
        return None
    candidates: list[str] = []
    for ef_key, fid in _EF_KEY_TO_FID.items():
        if fid.upper() != fid_upper:
            continue
        if _EF_KEY_TO_PARENT_TOKEN.get(ef_key) == parent_token:
            candidates.append(ef_key)
    if len(candidates) == 0:
        return None
    candidates.sort()
    return candidates[0]


def fid_name(fid_hex: str, *, parent_hint: str | None = None) -> str | None:
    """
    Resolve a FID to a human-readable label.

    ``parent_hint`` accepts either a PE section key (``"usim"``,
    ``"csim_2"``), a PE base type, or a DF/ADF token (``"adf-usim"``,
    ``"df-telecom"``). When set, the hint is used to pick the single matching
    ef-* label, avoiding the combined-collision fallback. When omitted, the
    combined label from :func:`_build_fid_name_map` is returned.
    """

    fid_upper = str(fid_hex or "").strip().upper()
    if len(fid_upper) == 0:
        return None
    hint_token = _normalize_parent_hint(parent_hint)
    entries = _FID_TO_PARENTED_NAMES.get(fid_upper)
    if entries is not None and hint_token is not None:
        matches = [label for parent, label in entries if parent == hint_token]
        if len(matches) == 1:
            return matches[0]
        if len(matches) > 1:
            return " / ".join(matches)
    return _FID_TO_NAME.get(fid_upper)

_UNIVERSAL_TAG_NAMES: dict[int, str] = {
    0: "EOC",
    1: "BOOLEAN",
    2: "INTEGER",
    3: "BIT STRING",
    4: "OCTET STRING",
    5: "NULL",
    6: "OBJECT IDENTIFIER",
    8: "EXTERNAL",
    9: "REAL",
    10: "ENUMERATED",
    12: "UTF8String",
    13: "RELATIVE-OID",
    16: "SEQUENCE",
    17: "SET",
    18: "NumericString",
    19: "PrintableString",
    20: "TeletexString",
    21: "VideotexString",
    22: "IA5String",
    23: "UTCTime",
    24: "GeneralizedTime",
    25: "GraphicString",
    26: "VisibleString",
    27: "GeneralString",
    28: "UniversalString",
    30: "BMPString",
}

# USIM Service Table (TS 31.102 §4.2.8). Canonical assignments mirror
# pySim's ``EF_UST_map`` so a live-card dump and a SAIP profile inspect
# annotate the same bit indices with the same service names. The earlier
# hand-curated map drifted from the spec (e.g. service 15 was labelled
# "Ignored" while TS 31.102 defines it as "Cell Broadcast Message
# Identifier") — keeping the pySim map verbatim avoids that drift.
_UST_SERVICE_NAMES: dict[int, str] = {
    1: "Local Phone Book",
    2: "Fixed Dialling Numbers (FDN)",
    3: "Extension 2",
    4: "Service Dialling Numbers (SDN)",
    5: "Extension3",
    6: "Barred Dialling Numbers (BDN)",
    7: "Extension4",
    8: "Outgoing Call Information (OCI and OCT)",
    9: "Incoming Call Information (ICI and ICT)",
    10: "Short Message Storage (SMS)",
    11: "Short Message Status Reports (SMSR)",
    12: "Short Message Service Parameters (SMSP)",
    13: "Advice of Charge (AoC)",
    14: "Capability Configuration Parameters 2 (CCP2)",
    15: "Cell Broadcast Message Identifier",
    16: "Cell Broadcast Message Identifier Ranges",
    17: "Group Identifier Level 1",
    18: "Group Identifier Level 2",
    19: "Service Provider Name",
    20: "User controlled PLMN selector with Access Technology",
    21: "MSISDN",
    22: "Image (IMG)",
    23: "Support of Localised Service Areas (SoLSA)",
    24: "Enhanced Multi-Level Precedence and Pre-emption Service",
    25: "Automatic Answer for eMLPP",
    26: "RFU",
    27: "GSM Access",
    28: "Data download via SMS-PP",
    29: "Data download via SMS-CB",
    30: "Call Control by USIM",
    31: "MO-SMS Control by USIM",
    32: "RUN AT COMMAND command",
    33: "shall be set to 1",
    34: "Enabled Services Table",
    35: "APN Control List (ACL)",
    36: "Depersonalisation Control Keys",
    37: "Co-operative Network List",
    38: "GSM security context",
    39: "CPBCCH Information",
    40: "Investigation Scan",
    41: "MexE",
    42: "Operator controlled PLMN selector with Access Technology",
    43: "HPLMN selector with Access Technology",
    44: "Extension 5",
    45: "PLMN Network Name",
    46: "Operator PLMN List",
    47: "Mailbox Dialling Numbers",
    48: "Message Waiting Indication Status",
    49: "Call Forwarding Indication Status",
    50: "Reserved and shall be ignored",
    51: "Service Provider Display Information",
    52: "Multimedia Messaging Service (MMS)",
    53: "Extension 8",
    54: "Call control on GPRS by USIM",
    55: "MMS User Connectivity Parameters",
    56: "Network's indication of alerting in the MS (NIA)",
    57: "VGCS Group Identifier List (EFVGCS and EFVGCSS)",
    58: "VBS Group Identifier List (EFVBS and EFVBSS)",
    59: "Pseudonym",
    60: "User Controlled PLMN selector for I-WLAN access",
    61: "Operator Controlled PLMN selector for I-WLAN access",
    62: "User controlled WSID list",
    63: "Operator controlled WSID list",
    64: "VGCS security",
    65: "VBS security",
    66: "WLAN Reauthentication Identity",
    67: "Multimedia Messages Storage",
    68: "Generic Bootstrapping Architecture (GBA)",
    69: "MBMS security",
    70: "Data download via USSD and USSD application mode",
    71: "Equivalent HPLMN",
    72: "Additional TERMINAL PROFILE after UICC activation",
    73: "Equivalent HPLMN Presentation Indication",
    74: "Last RPLMN Selection Indication",
    75: "OMA BCAST Smart Card Profile",
    76: "GBA-based Local Key Establishment Mechanism",
    77: "Terminal Applications",
    78: "Service Provider Name Icon",
    79: "PLMN Network Name Icon",
    80: "Connectivity Parameters for USIM IP connections",
    81: "Home I-WLAN Specific Identifier List",
    82: "I-WLAN Equivalent HPLMN Presentation Indication",
    83: "I-WLAN HPLMN Priority Indication",
    84: "I-WLAN Last Registered PLMN",
    85: "EPS Mobility Management Information",
    86: "Allowed CSG Lists and corresponding indications",
    87: "Call control on EPS PDN connection by USIM",
    88: "HPLMN Direct Access",
    89: "eCall Data",
    90: "Operator CSG Lists and corresponding indications",
    91: "Support for SM-over-IP",
    92: "Support of CSG Display Control",
    93: "Communication Control for IMS by USIM",
    94: "Extended Terminal Applications",
    95: "Support of UICC access to IMS",
    96: "Non-Access Stratum configuration by USIM",
    97: "PWS configuration by USIM",
    98: "RFU",
    99: "URI support by UICC",
    100: "Extended EARFCN support",
    101: "ProSe",
    102: "USAT Application Pairing",
    103: "Media Type support",
    104: "IMS call disconnection cause",
    105: "URI support for MO SHORT MESSAGE CONTROL",
    106: "ePDG configuration Information support",
    107: "ePDG configuration Information configured",
    108: "ACDC support",
    109: "MCPTT",
    110: "ePDG configuration Information for Emergency Service support",
    111: "ePDG configuration Information for Emergency Service configured",
    112: "eCall Data over IMS",
    113: "URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111",
    114: "From Preferred",
    115: "IMS configuration data",
    116: "TV configuration",
    117: "3GPP PS Data Off",
    118: "3GPP PS Data Off Service List",
    119: "V2X",
    120: "XCAP Configuration Data",
    121: "EARFCN list for MTC/NB-IOT UEs",
    122: "5GS Mobility Management Information",
    123: "5G Security Parameters",
    124: "Subscription identifier privacy support",
    125: "SUCI calculation by the USIM",
    126: "UAC Access Identities support",
    127: "Expect control plane-based Steering of Roaming information during initial registration in VPLMN",
    128: "Call control on PDU Session by USIM",
    129: "5GS Operator PLMN List",
    130: "Support for SUPI of type NSI or GLI or GCI",
    131: "3GPP PS Data Off separate Home and Roaming lists",
    132: "Support for URSP by USIM",
    133: "5G Security Parameters extended",
    134: "MuD and MiD configuration data",
    135: "Support for Trusted non-3GPP access networks by USIM",
    136: "Support for multiple records of NAS security context storage for multiple registration",
    137: "Pre-configured CAG information list",
    138: "SOR-CMCI storage in USIM",
    139: "5G ProSe",
    140: "Storage of disaster roaming information in USIM",
    141: "Pre-configured eDRX parameters",
    142: "5G NSWO support",
    143: "PWS configuration for SNPN in USIM",
    144: "Multiplier Coefficient for Higher Priority PLMN search via NG-RAN satellite access",
    145: "K_AUSF derivation configuration",
    146: "Network Identifier for SNPN (NID)",
}

# USIM Enabled Services Table (TS 31.102 §4.2.47). Aligned with pySim's
# ``EF_EST_map``.
_EST_SERVICE_NAMES: dict[int, str] = {
    1: "Fixed Dialling Numbers (FDN)",
    2: "Barred Dialling Numbers (BDN)",
    3: "APN Control List (ACL)",
}

# ISIM Service Table (TS 31.103 §4.2.7). Aligned with pySim's
# ``EF_IST_map``.
_ISIM_SERVICE_NAMES: dict[int, str] = {
    1: "P-CSCF address",
    2: "Generic Bootstrapping Architecture (GBA)",
    3: "HTTP Digest",
    4: "GBA-based Local Key Establishment Mechanism",
    5: "Support of P-CSCF discovery for IMS Local Break Out",
    6: "Short Message Storage (SMS)",
    7: "Short Message Status Reports (SMSR)",
    8: "Support for SM-over-IP including data download via SMS-PP as defined in TS 31.111",
    9: "Communication Control for IMS by ISIM",
    10: "Support of UICC access to IMS",
    11: "URI support by UICC",
    12: "Media Type support",
    13: "IMS call disconnection cause",
    14: "URI support for MO SHORT MESSAGE CONTROL",
    15: "MCPTT",
    16: "URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111",
    17: "From Preferred",
    18: "IMS configuration data",
    19: "XCAP Configuration Data",
    20: "WebRTC URI",
    21: "MuD and MiD configuration data",
    22: "IMS Data Channel indication",
}

_PLMN_WITH_ACT_KEYS = {
    "ef-plmnwact",
    "ef-oplmnwact",
    "ef-hplmnwact",
}

_APPLICATION_PRIVILEGE_FLAGS = [
    (0x800000, "security_domain", "Security Domain"),
    (0x400000, "dap_verification", "DAP Verification"),
    (0x200000, "delegated_management", "Delegated Management"),
    (0x100000, "card_lock", "Card Lock"),
    (0x080000, "card_terminate", "Card Terminate"),
    (0x040000, "card_reset", "Card Reset"),
    (0x020000, "cvm_management", "CVM Management"),
    (0x010000, "mandated_dap_verification", "Mandated DAP Verification"),
    (0x008000, "trusted_path", "Trusted Path"),
    (0x004000, "authorized_management", "Authorized Management"),
    (0x002000, "token_management", "Token Management"),
    (0x001000, "global_delete", "Global Delete"),
    (0x000800, "global_lock", "Global Lock"),
    (0x000400, "global_registry", "Global Registry"),
    (0x000200, "final_application", "Final Application"),
    (0x000100, "global_service", "Global Service"),
    (0x000080, "receipt_generation", "Receipt Generation"),
    (0x000040, "ciphered_load_file_data_block", "Ciphered Load File Data Block"),
    (0x000020, "contactless_activation", "Contactless Activation"),
    (0x000010, "contactless_self_activation", "Contactless Self-Activation"),
]

_LIFE_CYCLE_STATE_NAMES = {
    0x01: "Loaded",
    0x03: "Installed",
    0x07: "Selectable",
    0x0F: "Personalized",
    0x83: "Locked",
}

_KEY_USAGE_FLAGS = [
    (0x8000, "verification_encryption", "Verification / Encryption"),
    (0x4000, "computation_decipherment", "Computation / Decipherment"),
    (0x2000, "sm_response", "Secure Messaging Response"),
    (0x1000, "sm_command", "Secure Messaging Command"),
    (0x0800, "confidentiality", "Confidentiality"),
    (0x0400, "crypto_checksum", "Cryptographic Checksum"),
    (0x0200, "digital_signature", "Digital Signature"),
    (0x0100, "crypto_authorization", "Cryptographic Authorization"),
    (0x0080, "key_agreement", "Key Agreement"),
]

_KEY_ACCESS_NAMES = {
    0x00: "Security Domain and any associated application",
    0x01: "Security Domain only",
    0x02: "Any associated application but not the Security Domain",
    0xFF: "Not available",
}

_KEY_ID_COMMON_ROLES = {
    0x01: "ENC (common SCP02/SCP03 convention)",
    0x02: "MAC (common SCP02/SCP03 convention)",
    0x03: "DEK (common SCP02/SCP03 convention)",
}

_KEY_TYPE_NAMES = {
    0x80: "DES",
    0x85: "TLS-PSK",
    0x88: "AES",
    0x90: "HMAC-SHA1",
    0x91: "HMAC-SHA1-160",
    0xA0: "RSA Public Exponent",
    0xA1: "RSA Modulus (cleartext)",
    0xA2: "RSA Modulus",
}

_AID_FIELD_NAMES = {
    "adfAID",
    "aid",
    "applicationLoadPackageAID",
    "classAID",
    "dfName",
    "extraditeSecurityDomainAID",
    "instanceAID",
    "loadPackageAID",
    "securityDomainAID",
}

_PUK_KEY_REFERENCE_NAMES = {
    1: "pukAppl1",
    2: "pukAppl2",
    3: "pukAppl3",
    4: "pukAppl4",
    5: "pukAppl5",
    6: "pukAppl6",
    7: "pukAppl7",
    8: "pukAppl8",
    129: "secondPUKAppl1",
    130: "secondPUKAppl2",
    131: "secondPUKAppl3",
    132: "secondPUKAppl4",
    133: "secondPUKAppl5",
    134: "secondPUKAppl6",
    135: "secondPUKAppl7",
    136: "secondPUKAppl8",
}

_PROFILE_POLICY_RULE_NAMES = {
    0: "pprUpdateControl",
    1: "ppr1-disable-not-allowed",
    2: "ppr2-delete-not-allowed",
}

_MEMORY_LIMIT_FIELD_LABELS = {
    "nonVolatileCodeLimitC6": "Non-volatile code limit",
    "volatileDataLimitC7": "Volatile data limit",
    "nonVolatileDataLimitC8": "Non-volatile data limit",
}


# Wave A — OCTET STRING fields whose decoded view is a generic hex
# summary plus optional ASCII/BCD hints (``_summarize_binary_blob``).
# These match the encoder side in ``saip_asn1_encode.py`` via the
# ``_PASSTHROUGH_BYTES_FIELD_NAMES`` registration. Keep the two lists
# in sync — adding a field to one without the other breaks round-trip.
_PASSTHROUGH_BYTES_FIELD_NAMES = frozenset(
    {
        "volatileMemoryQuotaC7",
        "nonVolatileMemoryQuotaC8",
        "volatileReservedMemory",
        "nonVolatileReservedMemory",
        "cumulativeGrantedVolatileMemory",
        "cumulativeGrantedNonVolatileMemory",
        "globalServiceParameters",
        "implicitSelectionParameter",
        "ts102226SIMFileAccessToolkitParameter",
        "contactlessProtocolParameters",
        "userInteractionContactlessParameters",
        "uiccAccessApplicationSpecificParametersField",
        "uiccAdministrativeAccessApplicationSpecificParametersField",
        "applicationProviderIdentifier",
        "loadBlockObject",
        "restrictParameter",
        "content",
        "authenticationKey",
        "ssd",
        "hrpdAccessAuthenticationData",
        "simpleIPAuthenticationData",
        "mobileIPAuthenticationData",
        "version",
        "protocolParameterData",
        "pix",
    }
)

_AKA_ALGORITHM_ID_NAMES = {
    1: "milenage",
    2: "tuak",
    3: "usim-test-algorithm",
}


def _is_scalar(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _looks_like_hex(text: str) -> bool:
    stripped = str(text or "").strip().upper()
    if len(stripped) < 8:
        return False
    if len(stripped) % 2 != 0:
        return False
    return all(character in "0123456789ABCDEF" for character in stripped)


def _format_scalar(value: Any) -> str:
    if value is None:
        return "Present"
    if isinstance(value, bool):
        return "True" if value else "False"
    text = str(value).strip()
    if _looks_like_hex(text) and len(text) > 64:
        return f"{text[:32]}...{text[-24:]}"
    if len(text) > 120:
        return f"{text[:60]}...{text[-40:]}"
    return text


def _pad_key(name: str, key_width: int | None) -> str:
    if key_width is None:
        return name
    if len(name) >= key_width:
        return name
    return f"{name:<{key_width}}"


def _compute_key_width(value: dict[Any, Any]) -> int:
    width = 0
    for key in value.keys():
        width = max(width, len(str(key)))
    width = max(width, 18)
    width = min(width, 32)
    return width


def _format_block_header(name: str, indent: int, key_width: int | None = None) -> str:
    prefix = "  " * indent
    padded_name = _pad_key(name, key_width)
    return f"{prefix}| {padded_name}"


def _format_scalar_line(
    name: str | None,
    value: Any,
    indent: int,
    key_width: int | None = None,
) -> str:
    prefix = "  " * indent
    rendered_value = _format_scalar(value)
    if name is None:
        return f"{prefix}| {rendered_value}"
    padded_name = _pad_key(str(name), key_width)
    if key_width is None:
        return f"{prefix}| {padded_name:<28} : {rendered_value}"
    return f"{prefix}| {padded_name} : {rendered_value}"


def _format_inline_scalar_list(values: list[Any]) -> str | None:
    if len(values) == 0:
        return "[]"
    for value in values:
        if _is_scalar(value) is False:
            return None
    parts = [_format_scalar(value) for value in values]
    text = ", ".join(parts)
    if len(text) > 120:
        return None
    return f"[{text}]"


def _render_compact_value(
    value: Any,
    *,
    indent: int = 0,
    name: str | None = None,
    key_width: int | None = None,
) -> list[str]:
    if _is_scalar(value):
        return [_format_scalar_line(name, value, indent, key_width)]

    if isinstance(value, dict):
        if len(value) == 0:
            return [_format_scalar_line(name, "{}", indent, key_width)]
        lines: list[str] = []
        child_indent = indent
        if name is not None:
            lines.append(_format_block_header(name, indent, key_width))
            child_indent += 1
        child_width = _compute_key_width(value)
        for child_name, child_value in value.items():
            lines.extend(
                _render_compact_value(
                    child_value,
                    indent=child_indent,
                    name=str(child_name),
                    key_width=child_width,
                )
            )
        return lines

    if isinstance(value, list):
        inline = _format_inline_scalar_list(value)
        if inline is not None:
            return [_format_scalar_line(name, inline, indent, key_width)]
        if len(value) == 0:
            return [_format_scalar_line(name, "[]", indent, key_width)]
        lines = []
        child_indent = indent
        all_scalar = all(_is_scalar(item) for item in value)
        if name is not None:
            header_name = f"{name} ({len(value)})" if all_scalar else name
            lines.append(_format_block_header(header_name, indent, key_width))
            child_indent += 1
        for index, item in enumerate(value):
            item_name = None if all_scalar else f"[{index}]"
            lines.extend(
                _render_compact_value(
                    item,
                    indent=child_indent,
                    name=item_name,
                )
            )
        return lines

    return [_format_scalar_line(name, repr(value), indent, key_width)]


def _compact_decode_lines(lines: list[str]) -> list[str]:
    compacted: list[str] = []
    pending_blank = False
    for raw_line in lines:
        line = str(raw_line).rstrip()
        if len(line) == 0:
            if len(compacted) == 0:
                continue
            pending_blank = True
            continue
        if pending_blank:
            compacted.append("")
            pending_blank = False
        compacted.append(line)
    while compacted and compacted[-1] == "":
        compacted.pop()
    return compacted


def _compact_block(title: str, payload: Any) -> list[str]:
    return [title, *_render_compact_value(payload, indent=1)]


def _format_hits(hits: list[tuple[str, list[str]]]) -> str:
    lines_out: list[str] = []
    for index, (title, chunk) in enumerate(hits):
        if index > 0:
            lines_out.append("")
        lines_out.append(f"[{title}]")
        lines_out.extend(_compact_decode_lines(chunk))
    return "\n".join(lines_out).rstrip() + "\n"


def _swap_nibbles(hex_text: str) -> str:
    compact = re.sub(r"\s+", "", str(hex_text or "")).upper()
    if len(compact) % 2 != 0:
        raise ValueError("hex string has odd length")
    swapped: list[str] = []
    for index in range(0, len(compact), 2):
        swapped.append(compact[index + 1] + compact[index])
    return "".join(swapped)


def _decode_printable_ascii(value_bytes: bytes) -> str | None:
    if len(value_bytes) == 0:
        return ""
    try:
        decoded = value_bytes.decode("ascii")
    except UnicodeDecodeError:
        return None
    for character in decoded:
        if character < " " or character > "~":
            return None
    return decoded


# ---------------------------------------------------------------------------
# TS 31.102 Annex A alpha string decoder
#
# ADN/AAS/SMSP alpha identifiers share the same encoding scheme defined
# in TS 31.102 Annex A. The leading byte selects the encoding:
#
#   byte < 0x80   GSM 7-bit default alphabet, unpacked (one 7-bit
#                 character per octet, high bit clear). Upper half of
#                 the alphabet is reached via the 0x1B extension prefix.
#   byte == 0x80  UCS-2 BE encoded text in the remaining octets.
#   byte == 0x81  UCS-2 with 8-bit pointer to GSM default alphabet
#                 (single-byte language/length prefix + base pointer).
#   byte == 0x82  UCS-2 with full 16-bit base pointer.
#
# Filler octets are 0xFF and must be trimmed before interpretation.
# ---------------------------------------------------------------------------

_GSM7_DEFAULT_ALPHABET = (
    "@\u00a3$\u00a5\u00e8\u00e9\u00f9\u00ec\u00f2\u00c7\n\u00d8\u00f8\r\u00c5\u00e5"
    "\u0394_\u03a6\u0393\u039b\u03a9\u03a0\u03a8\u03a3\u0398\u039e\x1b\u00c6\u00e6\u00df\u00c9"
    " !\"#\u00a4%&'()*+,-./"
    "0123456789:;<=>?"
    "\u00a1ABCDEFGHIJKLMNO"
    "PQRSTUVWXYZ\u00c4\u00d6\u00d1\u00dc\u00a7"
    "\u00bfabcdefghijklmno"
    "pqrstuvwxyz\u00e4\u00f6\u00f1\u00fc\u00e0"
)

_GSM7_EXTENSION_TABLE = {
    0x0A: "\u000c",
    0x14: "^",
    0x28: "{",
    0x29: "}",
    0x2F: "\\",
    0x3C: "[",
    0x3D: "~",
    0x3E: "]",
    0x40: "|",
    0x65: "\u20ac",
}


def _decode_gsm7_default_alphabet(value_bytes: bytes) -> str | None:
    """Decode a TS 23.038 §6.2 GSM 7-bit default alphabet byte-per-character string."""

    out: list[str] = []
    index = 0
    while index < len(value_bytes):
        septet = value_bytes[index]
        if septet & 0x80:
            return None
        if septet == 0x1B:
            index += 1
            if index >= len(value_bytes):
                return None
            extension = _GSM7_EXTENSION_TABLE.get(value_bytes[index])
            if extension is None:
                return None
            out.append(extension)
        else:
            out.append(_GSM7_DEFAULT_ALPHABET[septet])
        index += 1
    return "".join(out)


def _decode_alpha_string_bytes(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """Decode a TS 31.102 Annex A alpha identifier into a typed payload.

    TS 31.102 only mandates that unused octets be set to ``0xFF``; it
    does not mandate whether the filler appears at the head or the
    tail of the fixed-width alpha block. Issuers are free to place the
    name anywhere inside the block. We therefore strip ``0xFF`` from
    both sides before interpreting the encoding leader byte.
    """

    if len(value_bytes) == 0:
        return None
    trimmed = value_bytes.strip(b"\xFF")
    if len(trimmed) == 0:
        return {
            "encoding": "filler",
            "text": "",
            "hex": value_bytes.hex().upper(),
        }
    leader = trimmed[0]
    if leader == 0x80:
        payload = trimmed[1:]
        if len(payload) % 2 != 0 or len(payload) == 0:
            return None
        try:
            text = payload.decode("utf-16-be")
        except UnicodeDecodeError:
            return None
        return {
            "encoding": "ucs-2-be",
            "text": text.rstrip("\x00"),
            "hex": value_bytes.hex().upper(),
        }
    if leader == 0x81:
        if len(trimmed) < 3:
            return None
        char_count = trimmed[1]
        base_pointer = trimmed[2] << 7
        payload = trimmed[3 : 3 + char_count]
        characters: list[str] = []
        for byte_value in payload:
            if byte_value & 0x80:
                characters.append(chr(base_pointer + (byte_value & 0x7F)))
            else:
                if byte_value < len(_GSM7_DEFAULT_ALPHABET):
                    characters.append(_GSM7_DEFAULT_ALPHABET[byte_value])
                else:
                    return None
        return {
            "encoding": "ucs-2-shift-81",
            "text": "".join(characters),
            "hex": value_bytes.hex().upper(),
        }
    if leader == 0x82:
        if len(trimmed) < 4:
            return None
        char_count = trimmed[1]
        base_pointer = (trimmed[2] << 8) | trimmed[3]
        payload = trimmed[4 : 4 + char_count]
        characters = []
        for byte_value in payload:
            if byte_value & 0x80:
                characters.append(chr(base_pointer + (byte_value & 0x7F)))
            else:
                if byte_value < len(_GSM7_DEFAULT_ALPHABET):
                    characters.append(_GSM7_DEFAULT_ALPHABET[byte_value])
                else:
                    return None
        return {
            "encoding": "ucs-2-shift-82",
            "text": "".join(characters),
            "hex": value_bytes.hex().upper(),
        }
    gsm_text = _decode_gsm7_default_alphabet(trimmed)
    if gsm_text is not None:
        return {
            "encoding": "gsm-7bit",
            "text": gsm_text,
            "hex": value_bytes.hex().upper(),
        }
    return None


def _decode_alpha_string_text(value_bytes: bytes) -> str:
    """Best-effort alpha-string to plain text (returns '' when undecodable)."""

    decoded = _decode_alpha_string_bytes(value_bytes)
    if decoded is None:
        return ""
    text_value = decoded.get("text")
    if isinstance(text_value, str):
        return text_value.strip("\x00").strip()
    return ""


# ---------------------------------------------------------------------------
# Network Name IE decoder (TS 24.008 §10.5.3.5a)
#
# EF.PNN (6FC5) stores one or two "Network Name" information elements per
# record (tag 0x43 full name, tag 0x45 short name). Each IE value is:
#
#   Octet 1: 1|CS CS|ACI|SB3 SB2 SB1 SB0
#     - bit 8 (1)      : extension indicator (always 1)
#     - bits 7-6 (CS)  : coding scheme
#                          00 = GSM 7-bit default alphabet (packed)
#                          01 = UCS-2 big endian
#                          others = reserved
#     - bit 5 (ACI)    : Add Country Initials (ME control flag)
#     - bits 4-1 (SB)  : spare bits in last octet (0..7)
#   Octets 2..n     : network name content
#
# The SIM may pad with ``0xFF`` octets when the stored value is shorter
# than the EF record length; trim those before decoding.
# ---------------------------------------------------------------------------


def _decode_gsm7_packed(
    value_bytes: bytes,
    *,
    spare_bits: int = 0,
) -> str | None:
    """Unpack a GSM 7-bit packed octet stream into GSM default-alphabet text."""

    if len(value_bytes) == 0:
        return ""
    buffer = 0
    bits_in_buffer = 0
    septets: list[int] = []
    for byte_value in value_bytes:
        buffer |= byte_value << bits_in_buffer
        bits_in_buffer += 8
        while bits_in_buffer >= 7:
            septets.append(buffer & 0x7F)
            buffer >>= 7
            bits_in_buffer -= 7
    if spare_bits > 0 and len(septets) > 0:
        septets = septets[:-1] if bits_in_buffer == 0 else septets
    characters: list[str] = []
    skip_next = False
    for index, septet in enumerate(septets):
        if skip_next:
            skip_next = False
            continue
        if septet == 0x1B:
            if index + 1 < len(septets):
                ext = _GSM7_EXTENSION_TABLE.get(septets[index + 1])
                if ext is not None:
                    characters.append(ext)
                skip_next = True
                continue
            characters.append(" ")
            continue
        if septet < len(_GSM7_DEFAULT_ALPHABET):
            characters.append(_GSM7_DEFAULT_ALPHABET[septet])
            continue
        return None
    return "".join(characters)


def _decode_network_name_ie(value_bytes: bytes) -> dict[str, object] | None:
    """Decode a TS 24.008 §10.5.3.5a Network Name IE value."""

    trimmed = bytes(value_bytes).rstrip(b"\xFF")
    if len(trimmed) == 0:
        return None
    header = trimmed[0]
    if (header & 0x80) == 0:
        return None
    coding_scheme = (header >> 5) & 0x03
    add_country_initials = bool(header & 0x08)
    spare_bits = header & 0x07
    payload = trimmed[1:]
    decoded: dict[str, object] = {
        "codingScheme": coding_scheme,
        "addCountryInitials": add_country_initials,
        "spareBits": spare_bits,
        "hex": value_bytes.hex().upper(),
    }
    if coding_scheme == 0:
        text = _decode_gsm7_packed(payload, spare_bits=spare_bits)
        decoded["encoding"] = "gsm-7bit-packed"
        decoded["text"] = text if isinstance(text, str) else ""
        if text is None:
            decoded["text"] = ""
            decoded["note"] = "payload contained invalid GSM 7-bit septets"
        return decoded
    if coding_scheme == 1:
        if len(payload) % 2 != 0:
            return None
        try:
            text = payload.decode("utf-16-be")
        except UnicodeDecodeError:
            return None
        decoded["encoding"] = "ucs-2-be"
        decoded["text"] = text.rstrip("\x00")
        return decoded
    decoded["encoding"] = f"reserved (CS={coding_scheme})"
    decoded["text"] = ""
    decoded["note"] = "reserved coding scheme; raw payload preserved"
    return decoded


def _tlv_value_decoder_network_name(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """Per-tag decoder for TS 24.008 Network Name IE payloads.

    Spec-correct PNN records always begin with the Network Name IE
    header byte (bit 8 set). Some roundtrip encoders — including the
    in-repo ``encode_ef_pnn_record`` shortcut — emit plain text without
    that prefix. Prefer the spec-anchored decode and fall back to a
    strict printable-ASCII reading so both on-card and synthesised
    payloads hydrate correctly.
    """

    ie_decoded = _decode_network_name_ie(value_bytes)
    if ie_decoded is not None:
        return ie_decoded
    trimmed = bytes(value_bytes).rstrip(b"\xFF").rstrip(b"\x00")
    ascii_text = _decode_printable_ascii(trimmed)
    if ascii_text in (None, ""):
        return None
    return {
        "encoding": "plain-ascii",
        "text": ascii_text,
        "hex": value_bytes.hex().upper(),
    }


def _looks_like_bcd_bytes(value_bytes: bytes) -> bool:
    if len(value_bytes) == 0:
        return False
    for byte_value in value_bytes:
        low = byte_value & 0x0F
        high = (byte_value >> 4) & 0x0F
        if low > 9 and low != 0x0F:
            return False
        if high > 9 and high != 0x0F:
            return False
    return True


def _decode_bcd_digits(value_bytes: bytes) -> str:
    digits: list[str] = []
    for byte_value in value_bytes:
        low = byte_value & 0x0F
        high = (byte_value >> 4) & 0x0F
        if low != 0x0F:
            digits.append(str(low))
        if high != 0x0F:
            digits.append(str(high))
    return "".join(digits)


def _hex_from_tagged_bytes(value: Any) -> str | None:
    if isinstance(value, dict) is False:
        return None
    if set(_structural_data_keys(value)) != {_TAG_BYTES}:
        return None
    text = str(_value_first(value, _TAG_BYTES, _LEGACY_TAG_BYTES)).strip()
    compact = re.sub(r"\s+", "", text)
    if re.fullmatch(r"[0-9A-Fa-f]*", compact) is None:
        return None
    if len(compact) % 2 != 0:
        return None
    return compact.upper()


def _hex_from_scalar_value(value: Any) -> str | None:
    if isinstance(value, str) is False:
        return None
    compact = re.sub(r"\s+", "", str(value or ""))
    if len(compact) == 0 or len(compact) % 2 != 0:
        return None
    if re.fullmatch(r"[0-9A-Fa-f]+", compact) is None:
        return None
    return compact.upper()


def _bytes_from_scalar_value(value: Any) -> bytes | None:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value < 0:
            return None
        length = max(1, (int(value).bit_length() + 7) // 8)
        return int(value).to_bytes(length, "big", signed=False)
    hex_clean = _hex_from_scalar_value(value)
    if hex_clean is None:
        return None
    try:
        return bytes.fromhex(hex_clean)
    except ValueError:
        return None


def _summary_with_label(code: str, label: str | None) -> str:
    if label is None or label == "":
        return code
    return f"{code} ({label})"


def _summary_with_list(code: str, items: list[str], *, limit: int = 3) -> str:
    if len(items) == 0:
        return code
    preview = ", ".join(items[:limit])
    if len(items) > limit:
        preview += f", ... (+{len(items) - limit})"
    return f"{code} ({preview})"


def _decode_iccid(hex_clean: str) -> dict[str, object] | None:
    try:
        iccid = _swap_nibbles(hex_clean).rstrip("F")
    except ValueError:
        return None
    return {
        "iccid": iccid,
        "encoding": "BCD swapped nibbles",
        "digitCount": len(iccid),
    }


def _decode_imsi(hex_clean: str) -> dict[str, object] | None:
    if len(hex_clean) < 4:
        return None
    try:
        digit_length = (int(hex_clean[0:2], 16) * 2) - 1
        swapped = _swap_nibbles(hex_clean[2:]).rstrip("F")
        if len(swapped) < 1:
            return None
        odd_even = (int(swapped[0], 16) >> 3) & 0x01
        if odd_even == 0:
            digit_length -= 1
        imsi = swapped[1:]
        if digit_length > 0 and digit_length <= len(imsi):
            imsi = imsi[:digit_length]
        return {
            "imsi": imsi,
            "digitCount": len(imsi),
            "oddDigitCount": odd_even == 1,
        }
    except Exception:
        return None


def _decode_plmn_hex(plmn_hex: str) -> str | None:
    compact = re.sub(r"\s+", "", str(plmn_hex or "")).upper()
    if len(compact) != 6:
        return None
    if compact == "FFFFFF":
        return None
    mcc = compact[1] + compact[0] + compact[3]
    mnc = compact[5] + compact[4] + compact[2]
    return f"{mcc}-{mnc.rstrip('F')}"


def _decode_access_technologies(act_hex: str) -> list[str]:
    compact = re.sub(r"\s+", "", str(act_hex or "")).upper()
    if len(compact) != 4:
        return []
    act_bits = int(compact, 16)
    technologies: set[str] = set()
    if act_bits & 0x8000:
        technologies.add("UTRAN")
    eutran_bits = act_bits & 0x7000
    if eutran_bits in (0x4000, 0x7000):
        technologies.add("E-UTRAN WB-S1")
        technologies.add("E-UTRAN NB-S1")
    elif eutran_bits == 0x5000:
        technologies.add("E-UTRAN NB-S1")
    elif eutran_bits == 0x6000:
        technologies.add("E-UTRAN WB-S1")
    gsm_bits = act_bits & 0x008C
    if gsm_bits in (0x0080, 0x008C):
        technologies.add("GSM")
        technologies.add("EC-GSM-IoT")
    elif gsm_bits == 0x0084:
        technologies.add("GSM")
    elif gsm_bits == 0x0086:
        technologies.add("EC-GSM-IoT")
    if act_bits & 0x0020:
        technologies.add("cdma2000 HRPD")
    if act_bits & 0x0010:
        technologies.add("cdma2000 1xRTT")
    if act_bits & 0x0008:
        technologies.add("NG-RAN")
    if act_bits & 0x0040:
        technologies.add("GSM COMPACT")
    return sorted(technologies)


def _decode_plmn_list(hex_clean: str, *, with_act: bool) -> dict[str, object] | None:
    if len(hex_clean) == 0:
        return None
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    step = 5 if with_act else 3
    if len(raw) < step or len(raw) % step != 0:
        return None
    entries: list[dict[str, object]] = []
    for offset in range(0, len(raw), step):
        plmn_bytes = raw[offset : offset + 3]
        if plmn_bytes == b"\xFF\xFF\xFF":
            continue
        entry: dict[str, object] = {
            "plmn": _decode_plmn_hex(plmn_bytes.hex().upper()) or plmn_bytes.hex().upper(),
        }
        if with_act:
            entry["act"] = _decode_access_technologies(raw[offset + 3 : offset + 5].hex().upper())
        entries.append(entry)
    return {
        "entries": entries,
        "entryCount": len(entries),
        "encoding": "PLMN list with AcT" if with_act else "PLMN list",
    }


def _decode_two_byte_language_records(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or len(raw) % 2 != 0:
        return None
    languages: list[str] = []
    for offset in range(0, len(raw), 2):
        record = raw[offset : offset + 2]
        if record == b"\xFF\xFF":
            continue
        try:
            languages.append(record.decode("ascii"))
        except UnicodeDecodeError:
            languages.append(record.hex().upper())
    return {
        "languages": languages,
        "recordCount": len(languages),
    }


def _decode_service_table(hex_clean: str, service_names: dict[int, str]) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    active: list[str] = []
    for byte_index, byte_value in enumerate(raw):
        for bit_index in range(8):
            if byte_value & (1 << bit_index):
                service_number = (byte_index * 8) + bit_index + 1
                service_name = service_names.get(service_number, f"Service {service_number}")
                active.append(f"{service_number}: {service_name}")
    return {
        "activeServices": active,
        "activeCount": len(active),
    }


def _decode_ust(hex_clean: str) -> dict[str, object] | None:
    return _decode_service_table(hex_clean, _UST_SERVICE_NAMES)


def _decode_est(hex_clean: str) -> dict[str, object] | None:
    return _decode_service_table(hex_clean, _EST_SERVICE_NAMES)


def _decode_start_hfn(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 6:
        return None
    return {
        "startCs": int.from_bytes(raw[:3], "big", signed=False),
        "startPs": int.from_bytes(raw[3:], "big", signed=False),
        "hex": hex_clean,
    }


def _decode_ef_dir_record(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={
            "61": "Application Template",
            "4F": "Application Identifier",
            "50": "Application Label",
            "51": "File Reference",
            "52": "Command APDU",
            "53": "Discretionary Data",
            "73": "Discretionary Template",
            "5F50": "URL",
        },
        value_decoders={
            "4F": _decode_application_identifier,
            "50": lambda value_bytes: _decode_printable_ascii(value_bytes) or value_bytes.hex().upper(),
            "51": lambda value_bytes: _decode_path_bytes(
                value_bytes,
                format_name="File reference",
                empty_summary="MF",
            ),
            "5F50": lambda value_bytes: _decode_printable_ascii(value_bytes) or value_bytes.hex().upper(),
        },
    )
    if len(items) == 0:
        return None
    if "parseErrorOffset" in items[-1]:
        return None
    return {
        "items": items,
        "recordType": "EF.DIR application template",
    }


def _decode_acc(hex_clean: str) -> dict[str, object] | None:
    try:
        value = int(hex_clean, 16)
    except ValueError:
        return None
    classes: list[str] = []
    for index in range(16):
        if value & (1 << index):
            classes.append(str(index))
    return {
        "accessControlClasses": classes,
        "raw": hex_clean,
    }


def _decode_spn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SPN (TS 31.102 §4.2.12 — Service Provider Name).

    Byte layout:
      [0]    display condition byte (bit0 HPLMN-required, bit1 hide-in-OPLMN)
      [1..]  alpha identifier (TS 31.102 Annex A: GSM-7 default or UCS-2)

    The alpha identifier is decoded via the Annex A helper so UCS-2
    leaders (0x80/0x81/0x82) are handled correctly instead of being
    passed through a lenient UTF-8 decode that silently drops bytes.
    """

    if len(hex_clean) < 2:
        return None
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    display_condition = raw[0]
    name_bytes = raw[1:]
    alpha = _decode_alpha_string_bytes(name_bytes)
    provider_name = ""
    encoding = None
    if alpha is not None:
        text_value = alpha.get("text")
        if isinstance(text_value, str):
            provider_name = text_value.strip("\x00").strip()
        encoding_value = alpha.get("encoding")
        if isinstance(encoding_value, str):
            encoding = encoding_value
    decoded: dict[str, object] = {
        "serviceProviderName": provider_name,
        "displayCondition": f"0x{display_condition:02X}",
        "displayInHplmnRequired": (display_condition & 0x01) == 0,
        "hideInOplmnIfEquivalentPlmn": (display_condition & 0x02) != 0,
    }
    if encoding is not None:
        decoded["alphaEncoding"] = encoding
    return decoded


def _decode_loci(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 11:
        return None
    lai = _decode_plmn_hex(raw[4:7].hex().upper())
    status_map = {
        0: "Updated",
        1: "Not Updated",
        2: "PLMN not allowed",
        3: "Location area not allowed",
    }
    return {
        "tmsi": raw[0:4].hex().upper(),
        "lai": lai or raw[4:7].hex().upper(),
        "lac": f"{int.from_bytes(raw[7:9], 'big'):04X}",
        "status": status_map.get(raw[10] & 0x03, f"0x{raw[10]:02X}"),
    }


def _decode_msisdn(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 14:
        return None
    alpha_len = max(0, len(raw) - 14)
    alpha = _decode_alpha_string_text(raw[:alpha_len])
    footer = raw[alpha_len:]
    number_len = footer[0]
    ton_npi = footer[1]
    digits = _decode_bcd_digits(footer[2:12])
    if number_len > 1:
        digits = digits[: (number_len - 1) * 2]
    decoded: dict[str, object] = {
        "number": digits,
        "tonNpi": f"0x{ton_npi:02X}",
        "extensionRecordIdentifier": f"0x{footer[13]:02X}",
    }
    if alpha != "":
        decoded["alphaIdentifier"] = alpha
    return decoded


def _decode_pnn_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PNN (TS 31.102 §4.2.58 — PLMN Network Name).

    Tag 0x43 ("Full name for network") and tag 0x45 ("Short name for
    network") both carry a Network Name IE per TS 24.008 §10.5.3.5a
    (not plain ASCII). The decoder dispatches both tags through
    ``_decode_network_name_ie`` so GSM 7-bit packed and UCS-2 forms are
    surfaced as text in the same record.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={
            "43": "Full name",
            "45": "Short name",
        },
        value_decoders={
            "43": _tlv_value_decoder_network_name,
            "45": _tlv_value_decoder_network_name,
        },
    )
    decoded: dict[str, object] = {
        "format": "PLMN Network Name",
        "items": items,
    }
    for item in items:
        tag = str(item.get("tag") or "")
        value = item.get("decoded")
        if isinstance(value, dict) is False:
            continue
        text_value = value.get("text")
        if isinstance(text_value, str) is False:
            continue
        if tag == "43":
            decoded["fullName"] = text_value
        if tag == "45":
            decoded["shortName"] = text_value
    return decoded


def _decode_opl_record(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 8:
        return None
    plmn = _decode_plmn_hex(raw[0:3].hex().upper())
    return {
        "format": "Operator PLMN List record",
        "plmn": plmn or raw[0:3].hex().upper(),
        "lacStart": f"{int.from_bytes(raw[3:5], 'big'):04X}",
        "lacEnd": f"{int.from_bytes(raw[5:7], 'big'):04X}",
        "pnnRecordIdentifier": raw[7],
    }


def _walk_rendered_tlv_items(items: list[dict[str, object]]):
    for item in items:
        yield item
        nested = item.get("items")
        if isinstance(nested, list):
            yield from _walk_rendered_tlv_items(nested)


def _decode_spdi(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={
            "A3": "Service provider display information",
            "80": "PLMN list",
        },
        value_decoders={
            "80": lambda value_bytes: _decode_plmn_list(value_bytes.hex().upper(), with_act=False),
        },
    )
    plmns: list[str] = []
    for item in _walk_rendered_tlv_items(items):
        if item.get("tag") != "80":
            continue
        decoded_list = item.get("decoded")
        if isinstance(decoded_list, dict) is False:
            continue
        entries = decoded_list.get("entries")
        if isinstance(entries, list) is False:
            continue
        for entry in entries:
            if isinstance(entry, dict) is False:
                continue
            plmn = entry.get("plmn")
            if isinstance(plmn, str):
                plmns.append(plmn)
    return {
        "format": "Service Provider Display Information",
        "serviceProviderPlmnList": plmns,
        "items": items,
    }


def _decode_eps_nas_security_context(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "EPS NAS security context",
        "raw": hex_clean,
    }
    decoded["ksiHeader"] = f"0x{raw[0]:02X}"
    if len(raw) >= 17:
        decoded["kasmeFirst16Bytes"] = raw[1:17].hex().upper()
    if len(raw) > 17:
        decoded["remainder"] = raw[17:].hex().upper()
    return decoded


def _strip_trailing_ff_padding(value_bytes: bytes) -> bytes:
    trimmed = value_bytes
    while len(trimmed) > 0 and trimmed[-1] == 0xFF:
        trimmed = trimmed[:-1]
    return trimmed


def _decoded_ber_items_from_hex(hex_clean: str) -> list[dict[str, object]] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    trimmed = _strip_trailing_ff_padding(raw)
    if len(trimmed) == 0:
        return None
    decoded = _decode_generic_asn1_blob(trimmed)
    if decoded is None:
        return None
    items = decoded.get("items")
    if isinstance(items, list) is False or len(items) == 0:
        return None
    return items


def _collect_ber_octet_string_hex(items: list[dict[str, object]]) -> list[str]:
    values: list[str] = []
    for item in _walk_rendered_tlv_items(items):
        if item.get("tagHex") != "04":
            continue
        raw = item.get("raw")
        if isinstance(raw, str):
            values.append(raw)
    return values


def _first_ber_decoded_text(items: list[dict[str, object]], tag_hex: str) -> str | None:
    for item in _walk_rendered_tlv_items(items):
        if item.get("tagHex") != tag_hex:
            continue
        decoded = item.get("decoded")
        if isinstance(decoded, str):
            return decoded
        raw = item.get("raw")
        if isinstance(raw, str):
            return raw
    return None


def _decode_pkcs15_odf(hex_clean: str) -> dict[str, object] | None:
    items = _decoded_ber_items_from_hex(hex_clean)
    if items is None:
        return None
    entry_type_map = {
        "A0": "private_keys",
        "A1": "public_keys",
        "A4": "certificates",
        "A5": "authentication_objects",
        "A7": "data_objects",
        "A8": "auth_keys",
        "A9": "trust_points",
    }
    objects: list[dict[str, object]] = []
    for item in items:
        entry_type = entry_type_map.get(str(item.get("tagHex") or ""), str(item.get("tagHex") or "entry"))
        nested = item.get("items")
        octets: list[str] = []
        if isinstance(nested, list):
            octets = _collect_ber_octet_string_hex(nested)
        paths = [octet for octet in octets if len(octet) == 4]
        references = [octet for octet in octets if len(octet) != 4]
        objects.append(
            {
                "entryType": entry_type,
                "paths": paths,
                "references": references,
            }
        )
    return {
        "format": "PKCS#15 Object Directory File",
        "objectCount": len(objects),
        "objects": objects,
    }


def _decode_pkcs15_dodf(hex_clean: str) -> dict[str, object] | None:
    items = _decoded_ber_items_from_hex(hex_clean)
    if items is None:
        return None
    label = _first_ber_decoded_text(items, "0C")
    oid = _first_ber_decoded_text(items, "06")
    paths: list[str] = []
    for octet in _collect_ber_octet_string_hex(items):
        if len(octet) != 4:
            continue
        if octet not in paths:
            paths.append(octet)
    data_objects = []
    for path in paths:
        entry: dict[str, object] = {"path": path}
        if label not in (None, ""):
            entry["label"] = label
        if oid not in (None, ""):
            entry["oid"] = oid
        data_objects.append(entry)
    return {
        "format": "PKCS#15 Data Object Directory File",
        "dataObjects": data_objects,
    }


def _decode_pkcs15_acm(hex_clean: str) -> dict[str, object] | None:
    items = _decoded_ber_items_from_hex(hex_clean)
    if items is None:
        return None
    octets = _collect_ber_octet_string_hex(items)
    decoded: dict[str, object] = {
        "format": "PKCS#15 Access Control Main File",
        "octetStrings": octets,
    }
    for octet in octets:
        if len(octet) == 4:
            decoded["acrfPath"] = octet
            break
    return decoded


def _decode_pkcs15_accf(hex_clean: str) -> dict[str, object] | None:
    items = _decoded_ber_items_from_hex(hex_clean)
    if items is None:
        return None
    entries: list[dict[str, object]] = []
    for index, octet in enumerate(_collect_ber_octet_string_hex(items), start=1):
        algorithm = "raw"
        if len(octet) == 64:
            algorithm = "sha256"
        elif len(octet) == 40:
            algorithm = "sha1"
        entries.append(
            {
                "index": index,
                "algorithm": algorithm,
                "hashHex": octet,
            }
        )
    return {
        "format": "PKCS#15 Access Control Conditions File",
        "entries": entries,
    }


def _decode_sms_status_reports(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    return {
        "recordIdentifier": raw[0],
        "statusReportTpdu": raw[1:].hex().upper(),
    }


def _decode_tlv80_text(hex_clean: str, *, format_name: str, field_name: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    direct_text = None
    try:
        direct_text = raw.decode("utf-8").strip()
    except UnicodeDecodeError:
        direct_text = None
    if direct_text not in (None, "") and raw[:1] != b"\x80":
        key_name = field_name[0].lower() + field_name[1:]
        return {
            "format": format_name,
            key_name: direct_text,
            "raw": hex_clean,
        }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": field_name},
        value_decoders={"80": _tlv_value_decoder_text},
    )
    text_value = None
    for item in items:
        if item.get("tag") != "80":
            continue
        decoded = item.get("decoded")
        if isinstance(decoded, str):
            text_value = decoded
            break
    decoded: dict[str, object] = {
        "format": format_name,
        "items": items,
    }
    if text_value not in (None, ""):
        decoded[field_name[0].lower() + field_name[1:]] = text_value
    return decoded


def _decode_pcscf_address(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "P-CSCF address"},
    )
    payload = None
    for item in items:
        if item.get("tag") != "80":
            continue
        raw_value = item.get("raw")
        if isinstance(raw_value, str):
            try:
                payload = bytes.fromhex(raw_value)
            except ValueError:
                payload = None
            break
    if payload is None or len(payload) < 2:
        return {
            "format": "ISIM P-CSCF address",
            "items": items,
        }
    address_type = payload[0]
    address_value = payload[1:]
    type_names = {
        0x00: "FQDN",
        0x01: "IPv4",
        0x02: "IPv6",
    }
    decoded: dict[str, object] = {
        "format": "ISIM P-CSCF address",
        "items": items,
        "addressType": type_names.get(address_type, f"0x{address_type:02X}"),
    }
    try:
        if address_type == 0x00:
            # TS 23.003 FQDNs are ASCII (RFC 1035). Use a strict ASCII
            # decode so malformed byte sequences surface as raw hex
            # rather than being silently masked by ``ignore``.
            text = address_value.decode("ascii").strip("\x00").strip()
            if text == "":
                decoded["rawAddress"] = address_value.hex().upper()
            else:
                decoded["address"] = text
        elif address_type == 0x01 and len(address_value) == 4:
            decoded["address"] = str(ipaddress.IPv4Address(address_value))
        elif address_type == 0x02 and len(address_value) == 16:
            decoded["address"] = str(ipaddress.IPv6Address(address_value))
        else:
            decoded["rawAddress"] = address_value.hex().upper()
    except (UnicodeDecodeError, ipaddress.AddressValueError):
        decoded["rawAddress"] = address_value.hex().upper()
    return decoded


def _decode_gbanl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.GBANL (TS 31.102 §4.2.80 — GBA NAF List).

    Tag 0x80 carries the opaque NAF ID (binary per 3GPP TS 33.220); tag
    0x81 carries the B-TID, which TS 33.220 defines as a URI-encoded
    UTF-8 string. Declare per-tag typing so the B-TID surfaces as text
    and the NAF ID stays raw.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={
            "80": "NAF ID",
            "81": "B-TID",
        },
        value_decoders={
            "81": _tlv_value_decoder_text,
        },
    )
    decoded: dict[str, object] = {
        "format": "GBA NAF List",
        "items": items,
    }
    for item in items:
        tag = str(item.get("tag") or "")
        raw_value = item.get("raw")
        if isinstance(raw_value, str) is False:
            continue
        if tag == "80":
            decoded["nafId"] = raw_value
        if tag == "81":
            decoded_value = item.get("decoded")
            if isinstance(decoded_value, str):
                decoded["bTid"] = decoded_value
            else:
                decoded["bTid"] = raw_value
    return decoded


def _decode_nafkca(hex_clean: str) -> dict[str, object] | None:
    return _decode_tlv80_text(
        hex_clean,
        format_name="NAF Key Centre Address",
        field_name="Address",
    )


def _decode_ehplmn_presentation_indication(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    mapping = {
        0x00: "no_preference",
        0x01: "display_highest_prio_only",
        0x02: "display_all",
    }
    return {
        "format": "Equivalent HPLMN presentation indication",
        "presentationIndication": mapping.get(raw[0], f"0x{raw[0]:02X}"),
        "raw": hex_clean,
    }


def _decode_group_identifier(
    hex_clean: str,
    *,
    format_name: str,
) -> dict[str, object] | None:
    """Decode EF.GID1 / EF.GID2 (TS 31.102 §4.2.10/§4.2.11).

    Fully operator-defined binary identifier; we expose raw bytes, the
    count of non-padding octets (0xFF filler convention) and a hex
    summary. ASCII inference is not spec-defined for GID payloads and
    is intentionally omitted.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    content = raw.rstrip(b"\xFF")
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
        "contentLength": len(content),
        "summary": raw.hex().upper(),
    }
    if len(content) < len(raw):
        decoded["paddingHex"] = raw[len(content) :].hex().upper()
    return decoded


def _decode_cbmi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CBMI / EF.CBMID (TS 31.102 §4.2.14/§4.2.77).

    Fixed-length list of 2-byte Cell Broadcast Message Identifier codes.
    ``0xFFFF`` marks an unused slot.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or len(raw) % 2 != 0:
        return None
    entries: list[dict[str, object]] = []
    active_codes: list[int] = []
    for offset in range(0, len(raw), 2):
        code = int.from_bytes(raw[offset : offset + 2], "big", signed=False)
        item: dict[str, object] = {
            "index": offset // 2,
            "hex": raw[offset : offset + 2].hex().upper(),
            "unused": code == 0xFFFF,
        }
        if code != 0xFFFF:
            item["code"] = code
            active_codes.append(code)
        entries.append(item)
    return {
        "format": "Cell Broadcast Message Identifier list",
        "hex": raw.hex().upper(),
        "entryCount": len(entries),
        "activeCount": len(active_codes),
        "entries": entries,
        "activeCodes": active_codes,
        "summary": ", ".join(str(code) for code in active_codes) if active_codes else "no active codes",
    }


def _decode_cbmir(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CBMIR (TS 31.102 §4.2.22).

    Fixed-length list of 4-byte range entries: ``lower(2) || upper(2)``
    big-endian. ``FFFFFFFF`` marks an unused slot.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or len(raw) % 4 != 0:
        return None
    ranges: list[dict[str, object]] = []
    active_ranges: list[dict[str, int]] = []
    for offset in range(0, len(raw), 4):
        lower = int.from_bytes(raw[offset : offset + 2], "big", signed=False)
        upper = int.from_bytes(raw[offset + 2 : offset + 4], "big", signed=False)
        item: dict[str, object] = {
            "index": offset // 4,
            "hex": raw[offset : offset + 4].hex().upper(),
            "unused": lower == 0xFFFF and upper == 0xFFFF,
        }
        if item["unused"] is False:
            item["lower"] = lower
            item["upper"] = upper
            active_ranges.append({"lower": lower, "upper": upper})
        ranges.append(item)
    return {
        "format": "Cell Broadcast Message Identifier Range list",
        "hex": raw.hex().upper(),
        "entryCount": len(ranges),
        "activeCount": len(active_ranges),
        "entries": ranges,
        "summary": (
            ", ".join(f"{r['lower']}-{r['upper']}" for r in active_ranges)
            if active_ranges
            else "no active ranges"
        ),
    }


def _decode_ici_oci_record(
    hex_clean: str,
    *,
    format_name: str,
    trailer_fields: tuple[tuple[str, int], ...] = (),
) -> dict[str, object] | None:
    """Decode an ICI (6F80) / OCI (6F81) record (TS 31.102 §4.2.36/§4.2.37).

    Each record starts with an ADN-like block (alphaIdentifier + 14-byte
    footer) followed by fixed-length trailer fields. For OCI:
    date+duration+linkTimer; for ICI: date+duration+status+linkTimer.
    We decode the prefix via ``_decode_adn_like_record`` and expose the
    remaining bytes both as structured trailer fields and as ``trailerHex``
    for verbatim re-encoding.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    trailer_length = sum(width for _, width in trailer_fields)
    if len(raw) < 14 + trailer_length:
        return None
    adn_part = raw[: len(raw) - trailer_length]
    trailer = raw[len(raw) - trailer_length :]
    adn_decoded = _decode_adn_like_record(adn_part.hex())
    if isinstance(adn_decoded, dict) is False:
        return None
    decoded: dict[str, object] = {
        "format": format_name,
        **adn_decoded,
        "trailerHex": trailer.hex().upper(),
    }
    offset = 0
    trailer_decoded: dict[str, object] = {}
    for field_name, field_width in trailer_fields:
        block = trailer[offset : offset + field_width]
        offset += field_width
        trailer_decoded[field_name] = block.hex().upper()
    if len(trailer_decoded) > 0:
        decoded["trailerFields"] = trailer_decoded
    return decoded


def _decode_extension_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.EXT1/EXT2/EXT3 (TS 31.102 §4.2.38).

    Each record is a 13-byte triplet: record type (1 byte), extension
    data (11 bytes, padded 0xFF), identifier (1 byte).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 13:
        return None
    record_type = raw[0]
    extension_data = raw[1:12]
    identifier = raw[12]
    type_names = {
        0x00: "Not used",
        0x01: "Called party sub-address",
        0x02: "Additional data",
        0x03: "Called party sub-address + additional data",
    }
    return {
        "format": "Extension record",
        "hex": raw.hex().upper(),
        "recordType": f"0x{record_type:02X}",
        "recordTypeName": type_names.get(record_type, "reserved/operator-specific"),
        "extensionDataHex": extension_data.hex().upper(),
        "identifier": f"0x{identifier:02X}",
        "summary": f"{type_names.get(record_type, f'type 0x{record_type:02X}')} -> id 0x{identifier:02X}",
    }


def _decode_ccp_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CCP1 / EF.CCP2 (TS 31.102 §4.2.41 / §4.2.42).

    Capability Configuration Parameters records are 15-byte blocks of
    Bearer Capability encoded per 3GPP TS 27.007. We expose hex + length
    since the BC format is operator-specific at the higher bytes.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 15:
        return None
    return {
        "format": "Capability Configuration Parameters record",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "bearerCapabilityPrefix": f"0x{raw[0]:02X}",
        "bearerCapabilityHex": raw.hex().upper(),
        "summary": f"BC prefix 0x{raw[0]:02X}",
    }


def _decode_usim_keys_record(
    hex_clean: str,
    *,
    format_name: str,
) -> dict[str, object] | None:
    """Decode EF.KEYS / EF.KEYSPS (TS 31.102 §4.2.3 / §4.2.4).

    33-byte block: KSI (1) + CK (16) + IK (16).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 33:
        return None
    ksi = raw[0]
    ciphering_key = raw[1:17]
    integrity_key = raw[17:33]
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "ksi": f"0x{ksi:02X}",
        "ksiDecimal": int(ksi),
        "cipheringKeyHex": ciphering_key.hex().upper(),
        "integrityKeyHex": integrity_key.hex().upper(),
        "summary": f"KSI 0x{ksi:02X}",
    }


def _decode_gsm_kc_record(
    hex_clean: str,
    *,
    format_name: str,
) -> dict[str, object] | None:
    """Decode EF.KC / EF.KCGPRS (TS 51.011 §10.3.13 / §10.3.15).

    9-byte block: Kc (8 bytes) + CKSN (1 byte, low 3 bits valid).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 9:
        return None
    kc = raw[:8]
    cksn_byte = raw[8]
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "kcHex": kc.hex().upper(),
        "cksn": cksn_byte & 0x07,
        "cksnRaw": f"0x{cksn_byte:02X}",
        "summary": f"Kc {kc.hex().upper()} / CKSN {cksn_byte & 0x07}",
    }


def _decode_hidden_key(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.HIDDENKEY (TS 31.102 §4.2.20).

    Layout: attempt counter (1 byte) + hidden key (8 bytes) = 9 bytes.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 9:
        return None
    attempts = raw[0]
    key_bytes = raw[1:]
    return {
        "format": "Hidden Key",
        "hex": raw.hex().upper(),
        "attemptsRemaining": int(attempts),
        "attemptsRaw": f"0x{attempts:02X}",
        "hiddenKeyHex": key_bytes.hex().upper(),
        "summary": f"{attempts} attempts remaining",
    }


def _decode_opaque_ef(
    hex_clean: str,
    *,
    format_name: str,
) -> dict[str, object] | None:
    """Generic fallback for EFs with no well-documented structure.

    Surfaces raw bytes, length and a hex summary. The encoder is a hex
    passthrough that keeps the content byte-exact. ASCII inference is
    not performed here: for EFs where the spec leaves the inner layout
    opaque, text rendering would be context-blind fluff and could
    mislead operators into thinking the field is a textual value.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
        "summary": raw.hex().upper(),
    }


# ---------------------------------------------------------------------------
# Opaque-passthrough EF catalog (Wave B).
#
# Every key in this table is covered by ``_decode_opaque_ef`` on read and
# ``encode_ef_opaque`` on write. The format_name is cosmetic — it shows up
# as ``format`` in the decoded view and in error traces from the round-trip
# encoder. The label is keyed by the verbatim EF member name from the SAIP
# ASN.1 schema (``PE_Definitions-<spec>.asn``).
#
# Spec cross-reference for each group:
#   PE-CD            - TS 102 220 / TS 102 221 card description files
#   PE-CSIM          - 3GPP2 C.S0065 (CSIM mandatory)
#   PE-OPT-CSIM      - 3GPP2 C.S0065 (CSIM optional)
#   PE-DF-5GS        - TS 31.102 §4.4.11 (5GS)
#   PE-DF-5GPROSE    - TS 31.102 §4.4.11.12 (5G ProSe)
#   PE-DF-SNPN       - TS 31.102 §4.4.11.13 (SNPN)
#   PE-EAP           - TS 102 310 (UICC EAP framework)
#   PE-IoT / PE-OPT-IoT - TS 31.102 IoT annex
#   PE-MF            - TS 102 221 master file
#   PE-OPT-ISIM      - TS 31.103
#   PE-OPT-USIM      - TS 31.102
#   PE-PHONEBOOK     - TS 31.102 §4.4.2
#   PE-TELECOM       - TS 31.102 §4.2 (DF.TELECOM)
#   PE-USIM          - TS 31.102
#
# Upgrading any single entry to a real semantic decoder is done by (a)
# adding an explicit clause to ``_decode_known_ef_payload`` above the
# opaque catalog lookup, and (b) pointing the dispatcher entry in
# ``saip_asn1_encode.py`` at the new encoder. The catalog itself stays
# untouched so that unfinished upgrades don't regress round-trip coverage.
_OPAQUE_PASSTHROUGH_EF_CATALOG: dict[str, str] = {
    # PE-CD (TS 102 220 / SAIP Annex D).
    "ef-launchpad": "CD Launchpad",
    "ef-icon": "Icon",
    # PE-CSIM (3GPP2 C.S0065).
    "ef-call-count": "CSIM Call Count",
    "ef-imsi-m": "CSIM IMSI-M",
    "ef-imsi-t": "CSIM IMSI-T",
    "ef-tmsi": "CSIM TMSI",
    "ef-ah": "CSIM Analog Home",
    "ef-aop": "CSIM Analog Operational Parameters",
    "ef-aloc": "CSIM Analog Location",
    "ef-cdmahome": "CSIM CDMA Home",
    "ef-znregi": "CSIM Zone-based Registration",
    "ef-snregi": "CSIM SID/NID-based Registration",
    "ef-distregi": "CSIM Distance-based Registration",
    "ef-accolc": "CSIM Access Overload Class",
    "ef-term": "CSIM Terminal Capability",
    "ef-acp": "CSIM Access Channel Parameters",
    "ef-prl": "CSIM Preferred Roaming List",
    "ef-ruimid": "CSIM R-UIM ID",
    "ef-csim-st": "CSIM Service Table",
    "ef-spc": "CSIM Service Programming Code",
    "ef-otapaspc": "CSIM OTAPA Service Programming Code",
    "ef-namlock": "CSIM NAM Lock",
    "ef-ota": "CSIM OTA Parameters",
    "ef-sp": "CSIM Service Preferences",
    "ef-esn-meid-me": "CSIM ESN/MEID-ME",
    "ef-usgind": "CSIM Usage Indicator",
    "ef-max-prl": "CSIM Max PRL",
    "ef-spcs": "CSIM SPC Status",
    "ef-mecrp": "CSIM ME-Specific Crypto",
    "ef-home-tag": "CSIM Home Tag",
    "ef-group-tag": "CSIM Group Tag",
    "ef-specific-tag": "CSIM Specific Tag",
    "ef-call-prompt": "CSIM Call Prompt",
    # PE-DF-5GPROSE (TS 31.102 §4.4.11.12, §4.4.13 Rel-17/18).
    "ef-5g-prose-st": "5G ProSe Service Table",
    "ef-5g-prose-dd": "5G ProSe Direct Discovery",
    "ef-5g-prose-dc": "5G ProSe Direct Communication",
    "ef-5g-prose-u2nru": "5G ProSe UE-to-Network Relay (User)",
    "ef-5g-prose-ru": "5G ProSe Relay UE",
    "ef-5g-prose-uir": "5G ProSe UE ID Remote",
    # Rel-18 ProSe additions (TS 31.102 §4.4.13.8 / §4.4.13.9).
    "ef-5g-prose-u2uru": "5G ProSe UE-to-UE Relay (User)",
    "ef-5g-prose-eu": "5G ProSe End UE",
    # Rel-18 5MBS (TS 31.102 §4.4.14).
    "ef-5mbsueconfig": "5MBS UE Pre-configuration",
    "ef-5mbsusd": "5MBS User Service Description",
    # PE-DF-5GS (TS 31.102 §4.4.11).
    "ef-suci-calc-info": "5GS SUCI Calculation Info",
    "ef-cag": "5GS Closed Access Group",
    "ef-sor-cmci": "5GS SoR-CMCI",
    "ef-dri": "5GS Disaster Roaming Information",
    "ef-mchpplmn": "5GS Manual Configurable HPPLMN",
    "ef-kausf-derivation": "5GS KAUSF Derivation",
    # PE-DF-SNPN (TS 31.102 §4.4.11.13).
    "ef-pws-snpn": "SNPN PWS",
    "ef-nid": "SNPN Network Identifier",
    # ADF.USIM extras (TS 31.102 §4.4.2 / §4.4.3).
    "ef-ocst": "Operator Controlled Signal Threshold",
    "ef-rplmnact": "RPLMN Last used Access Technology",
    # DF.HNB (TS 31.102 §4.4.6 — Home NodeB).
    "ef-acsgl": "Allowed CSG Lists",
    "ef-csgt": "CSG Types",
    "ef-hnbn": "Home NodeB Name",
    "ef-ocsgl": "Operator CSG Lists",
    # PE-EAP (TS 102 310).
    "ef-eapkeys": "EAP Keys",
    "ef-eapstatus": "EAP Status",
    "ef-ps": "EAP Pseudonym",
    "ef-curid": "EAP Current ID",
    "ef-reid": "EAP Re-authentication ID",
    "ef-realm": "EAP Realm",
    # PE-IoT (TS 31.102 IoT).
    "ef-umpc": "UICC Max Power Consumption",
    "ef-imsi": "USIM IMSI",
    "ef-arr-usim": "ARR (USIM)",
    "ef-threshold": "Threshold",
    # PE-OPT-CSIM (3GPP2 C.S0065).
    "ef-ssci": "CSIM SSCI",
    "ef-ssfc": "CSIM SSFC",
    "ef-mdn": "CSIM MDN",
    "ef-me3gpdopc": "CSIM ME 3GPD Operating Capability",
    "ef-3gpdopm": "CSIM 3GPD Operating Mode",
    "ef-sipcap": "CSIM SIP Capabilities",
    "ef-mipcap": "CSIM MIP Capabilities",
    "ef-sipupp": "CSIM SIP User Profile Parameters",
    "ef-mipupp": "CSIM MIP User Profile Parameters",
    "ef-sipsp": "CSIM SIP Status Parameters",
    "ef-mipsp": "CSIM MIP Status Parameters",
    "ef-sippapss": "CSIM SIP PAP SS",
    "ef-puzl": "CSIM Preferred User Zone List",
    "ef-maxpuzl": "CSIM Max PUZL",
    "ef-hrpdcap": "CSIM HRPD Capability",
    "ef-hrpdupp": "CSIM HRPD User Profile Parameters",
    "ef-csspr": "CSIM CSSPR",
    "ef-atc": "CSIM Access Terminal Class",
    "ef-eprl": "CSIM Extended PRL",
    "ef-bcsmscfg": "CSIM Broadcast SMS Config",
    "ef-bcsmspref": "CSIM Broadcast SMS Preferences",
    "ef-bcsmstable": "CSIM Broadcast SMS Table",
    "ef-bcsmsp": "CSIM Broadcast SMS Parameters",
    "ef-bakpara": "CSIM BAK Parameters",
    "ef-upbakpara": "CSIM Updated BAK Parameters",
    "ef-mmsn": "CSIM/USIM MMS Notifications",
    "ef-ext8": "CSIM/USIM Extension 8",
    "ef-mmsicp": "CSIM/USIM MMS Issuer Connectivity Parameters",
    "ef-mmsup": "CSIM/USIM MMS User Parameters",
    "ef-mmsucp": "CSIM/USIM MMS User Connectivity Parameters",
    "ef-auth-capability": "CSIM Authentication Capability",
    "ef-3gcik": "CSIM 3G CIK",
    "ef-cdmacnl": "CSIM CDMA Co-operative Network List",
    "ef-sf-euimid": "CSIM Short Form EUIMID",
    "ef-hidden-key": "CSIM Hidden Key",
    "ef-lcsver": "CSIM LCS Version",
    "ef-lcscp": "CSIM LCS Client Profile",
    "ef-ext5": "CSIM/USIM Extension 5",
    "ef-applabels": "CSIM Application Labels",
    "ef-model": "CSIM Device Model",
    "ef-rc": "CSIM Root Certificate",
    "ef-smscap": "CSIM SMS Capability",
    "ef-mipflags": "CSIM MIP Flags",
    "ef-3gpduppext": "CSIM 3GPD UPP Extension",
    "ef-ipv6cap": "CSIM IPv6 Capability",
    "ef-tcpconfig": "CSIM TCP Config",
    "ef-dgc": "CSIM Data Generic Configuration",
    "ef-wapbrowsercp": "CSIM WAP Browser Connection Parameters",
    "ef-wapbrowserbm": "CSIM WAP Browser Bookmarks",
    "ef-mmsconfig": "CSIM MMS Config",
    "ef-jdl": "CSIM Java Download List",
    # PE-OPT-ISIM (TS 31.103).
    "ef-gbabp": "ISIM/USIM GBA Bootstrapping Parameters",
    "ef-uicciari": "ISIM/USIM UICC IARI",
    "ef-frompreferred": "ISIM/USIM From Preferred",
    "ef-imsconfigdata": "ISIM/USIM IMS Configuration Data",
    "ef-xcapconfigdata": "ISIM/USIM XCAP Configuration Data",
    "ef-webrtcuri": "ISIM WebRTC URI",
    "ef-mudmidconfigdata": "ISIM/USIM MuD/MID Configuration Data",
    # TS 31.103 §4.2.22 / §4.2.23.
    "ef-gbauapi": "ISIM GBA_U_API Access Control",
    "ef-imsdci": "ISIM IMS Data Channel Indication",
    # PE-OPT-IoT (TS 31.102 IoT annex).
    "ef-supi-nai": "IoT SUPI NAI",
    # PE-OPT-USIM (TS 31.102).
    "ef-bdn": "USIM Barred Dialling Numbers",
    "ef-ext4": "USIM Extension 4",
    "ef-vgcsca": "USIM VGCS Ciphering Algorithm",
    "ef-vbsca": "USIM VBS Ciphering Algorithm",
    "ef-msk": "USIM MBMS Service Key",
    "ef-muk": "USIM MBMS User Key",
    "ef-spni": "USIM Service Provider Name Icon",
    "ef-pnni": "USIM PLMN Network Name Icon",
    "ef-ncp-ip": "USIM Network Connection Parameters (IP)",
    "ef-ufc": "USIM UE Functionality Configuration",
    "ef-pws": "USIM Public Warning System",
    "ef-bdnuri": "USIM BDN URI",
    "ef-ial": "USIM IMEI(SV) Association List",
    "ef-ips": "USIM IP Settings",
    "ef-ipd": "USIM IP Data",
    "ef-epdgid": "USIM ePDG Identifier",
    "ef-epdgselection": "USIM ePDG Selection Information",
    "ef-epdgidem": "USIM ePDG Identifier Emergency",
    "ef-epdgselectionem": "USIM ePDG Selection Information Emergency",
    "ef-3gpppsdataoff": "USIM 3GPP PS Data Off",
    "ef-3gpppsdataoffservicelist": "USIM 3GPP PS Data Off Service List",
    "ef-eaka": "USIM EAP-AKA Authentication Context",
    # PE-PHONEBOOK (TS 31.102 §4.4.2).
    "ef-aas": "Phonebook Additional Alpha String",
    "ef-pbc": "Phonebook Control",
    "ef-puri": "Phonebook URI",
    "ef-uid": "Phonebook Unique Identifier",
    # PE-TELECOM (TS 31.102 §4.2 / DF.TELECOM).
    "ef-rma": "TELECOM RMA",
    "ef-ice-dn": "TELECOM ICE Dialling Numbers",
    "ef-ice-ff": "TELECOM ICE Free Format",
    "ef-img": "TELECOM Image",
    "ef-iidf": "TELECOM Image Instance Data File",
    "ef-ice-graphics": "TELECOM ICE Graphics",
    "ef-launch-scws": "TELECOM Launch SCWS",
    "ef-mml": "TELECOM Multimedia Messages List",
    "ef-mmdf": "TELECOM Multimedia Data File",
    "ef-mlpl": "TELECOM MMS List Preferred",
    "ef-mspl": "TELECOM MMS Sender Preferred",
    "ef-mmssmode": "TELECOM MMS Storage Mode",
    "ef-mst": "TELECOM Multimedia Service Table",
    "ef-mcs-config": "TELECOM MCS Configuration",
    "ef-vst": "TELECOM V2X Service Table",
    "ef-v2x-config": "TELECOM V2X Configuration",
    "ef-v2xp-pc5": "TELECOM V2X PC5 Parameters",
    "ef-v2xp-Uu": "TELECOM V2X Uu Parameters",
}


def _lookup_opaque_passthrough_ef(ef_key: str) -> str | None:
    """Return the opaque format label for ``ef_key`` if it is catalogued.

    The decoder normalises tokens to lowercase ``ef-*`` form; the catalog
    is keyed verbatim against ``PE_Definitions-*.asn`` so the lookup is
    case-sensitive for the suffix of the key (see ``ef-v2xp-Uu``). We
    therefore try the verbatim key first and fall back to a
    case-insensitive sweep for operator convenience.
    """

    token = str(ef_key or "").strip()
    if token == "":
        return None
    label = _OPAQUE_PASSTHROUGH_EF_CATALOG.get(token)
    if label is not None:
        return label
    token_lower = token.lower()
    for key, value in _OPAQUE_PASSTHROUGH_EF_CATALOG.items():
        if key.lower() == token_lower:
            return value
    return None


def opaque_passthrough_ef_keys() -> tuple[str, ...]:
    """Return the sorted tuple of EF keys covered by the opaque catalog."""

    return tuple(sorted(_OPAQUE_PASSTHROUGH_EF_CATALOG))


def _decode_one_byte_indicator(
    hex_clean: str,
    *,
    format_name: str,
    value_map: dict[int, str] | None = None,
) -> dict[str, object] | None:
    """Decode a single-byte indicator EF (ef-nia / ef-lrplmnsi / ef-invscan)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    byte_value = raw[0]
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": raw.hex().upper(),
        "decimal": int(byte_value),
        "byte": f"0x{byte_value:02X}",
    }
    if value_map is not None:
        name = value_map.get(byte_value)
        if name is not None:
            decoded["name"] = name
            decoded["summary"] = f"{name} (0x{byte_value:02X})"
        else:
            decoded["summary"] = f"0x{byte_value:02X}"
    else:
        decoded["summary"] = f"0x{byte_value:02X}"
    return decoded


def _decode_nasconfig(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.NASCONFIG (TS 31.102 §4.2.96) — BER-TLV stream."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    tag_names = {
        "80": "NAS Signalling Priority",
        "81": "NAS Signalling Low Priority",
        "82": "Override NAS Signalling Low Priority",
        "83": "Extended Access Barring",
        "84": "Timer T3245 Behaviour",
        "85": "Override Timer T3245",
        "86": "Timer T3346 Behaviour",
    }
    int_decoders: dict[str, ValueDecoder] = {
        tag: _tlv_value_decoder_small_int for tag in tag_names
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=tag_names,
        value_decoders=int_decoders,
    )
    return {
        "format": "NAS Configuration",
        "hex": raw.hex().upper(),
        "items": items,
    }


def _decode_suci_calc_info(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SUCI_Calc_Info (TS 31.102 Annex N) — BER-TLV."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    tag_names = {
        "A0": "Protection Scheme Identifier list",
        "A1": "Home Network Public Key list",
        "80": "Protection Scheme Identifier",
        "81": "Home Network Public Key Identifier",
        "82": "Home Network Public Key",
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=tag_names,
        value_decoders={
            "80": _tlv_value_decoder_small_int,
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "SUCI Calculation Information",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_supinai(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SUPI_NAI (TS 31.102 §4.4.11.4).

    Contains a UTF-8 NAI string wrapped in TLV ``80 LL ...``.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "SUPI as NAI",
        "hex": raw.hex().upper(),
        "length": len(raw),
    }
    if raw[0] == 0x80 and len(raw) >= 2:
        nai_length = raw[1]
        if 2 + nai_length <= len(raw):
            nai_bytes = raw[2 : 2 + nai_length]
            try:
                nai_text = nai_bytes.decode("utf-8")
            except UnicodeDecodeError:
                nai_text = ""
            if nai_text != "":
                decoded["nai"] = nai_text
                decoded["summary"] = nai_text
                return decoded
    decoded["summary"] = raw.hex().upper()
    return decoded


def _decode_routing_indicator(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.Routing_Indicator (TS 31.102 §4.4.11.8).

    Layout (4 bytes big-endian, but RI digits are BCD nibbles):
    - byte[0..1] = Routing Indicator (up to 4 BCD digits, unused nibbles 0xF)
    - byte[2]    = Protection Scheme Flag + padding
    - byte[3]    = Reserved (0xFF when unused)
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 4:
        return None
    ri_digits = _decode_bcd_digits(raw[:2])
    flag_byte = raw[2]
    decoded: dict[str, object] = {
        "format": "5G Routing Indicator",
        "hex": raw.hex().upper(),
        "routingIndicator": ri_digits,
        "flagByte": f"0x{flag_byte:02X}",
        "flagByteDecimal": int(flag_byte),
        "reservedByte": f"0x{raw[3]:02X}",
        "summary": f"RI={ri_digits or '-'} flag=0x{flag_byte:02X}",
    }
    return decoded


def _decode_uac_aic(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.UAC_AIC (TS 31.102 §4.4.11.6).

    4-byte access-identities bitmap: one bit per access identity (0..31).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 4:
        return None
    active_ids: list[int] = []
    for byte_index, byte_value in enumerate(raw):
        for bit_index in range(8):
            if (byte_value >> bit_index) & 0x01:
                active_ids.append(byte_index * 8 + bit_index)
    return {
        "format": "UAC Access Identities Configuration",
        "hex": raw.hex().upper(),
        "accessIdentities": active_ids,
        "summary": (
            "AI=" + ",".join(str(i) for i in active_ids)
            if active_ids
            else "no access identities"
        ),
    }


def _decode_opl5g_record(hex_clean: str) -> dict[str, object] | None:
    """Decode an EF.OPL5G record (TS 31.102 §4.4.11.11).

    Layout: PLMN(3) + TAC_start(3) + TAC_end(3) + PNN_record(1) = 10 bytes.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 10:
        return None
    plmn_hex = raw[:3].hex().upper()
    tac_start = int.from_bytes(raw[3:6], "big", signed=False)
    tac_end = int.from_bytes(raw[6:9], "big", signed=False)
    pnn_id = raw[9]
    return {
        "format": "5G Operator PLMN List record",
        "hex": raw.hex().upper(),
        "plmnHex": plmn_hex,
        "tacStart": tac_start,
        "tacEnd": tac_end,
        "pnnRecordId": int(pnn_id),
        "summary": f"PLMN {plmn_hex} TAC {tac_start}-{tac_end} -> PNN {pnn_id}",
    }


def _decode_pcscf_urn(hex_clean: str) -> dict[str, object] | None:
    """Decode a P-CSCF URN record (reuses the ISIM P-CSCF decoder format)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    return _decode_pcscf_address(hex_clean)


# ---------------------------------------------------------------------------
# EF.GBAUAPI / EF.IMSDCI (TS 31.103 §4.2.22 / §4.2.23).
#
# EF.GBAUAPI carries linear-fixed records with a single BER-TLV ``80`` entry
# whose value is an inner struct ``<len><AID> <len><NAF_ID>``. The length
# prefixes are 1-byte unsigned integers (pySim shortcut — AIDs / NAF IDs are
# always <128 bytes). EF.IMSDCI is a single byte enumerating whether the
# terminal may establish IMS data channels.


_EF_IMSDCI_VALUES: dict[int, str] = {
    0x00: "ims_dc_not_allowed",
    0x01: "ims_dc_allowed_after_ims_session",
    0x02: "ims_dc_allowed_simultaneous_ims_session",
}


def _decode_ef_gbauapi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.GBAUAPI (TS 31.103 §4.2.22)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None

    def _value_decoder(payload: bytes) -> dict[str, object]:
        result: dict[str, object] = {"hex": payload.hex().upper()}
        pos = 0
        if pos < len(payload):
            aid_len = payload[pos]
            pos += 1
            aid = payload[pos : pos + aid_len]
            pos += aid_len
            result["aid"] = {
                "length": aid_len,
                "hex": aid.hex().upper(),
            }
        if pos < len(payload):
            naf_len = payload[pos]
            pos += 1
            naf = payload[pos : pos + naf_len]
            pos += naf_len
            result["naf_id"] = {
                "length": naf_len,
                "hex": naf.hex().upper(),
            }
        if pos < len(payload):
            result["trailer_hex"] = payload[pos:].hex().upper()
        return result

    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "AppletNafAccessControl"},
        value_decoders={"80": _value_decoder},
    )
    return {
        "format": "EF.GBAUAPI",
        "reference": "TS 31.103 §4.2.22",
        "hex": hex_clean.upper(),
        "items": items,
    }


def _decode_ef_imsdci(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IMSDCI (TS 31.103 §4.2.23)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    value = raw[0]
    return {
        "format": "EF.IMSDCI",
        "reference": "TS 31.103 §4.2.23",
        "hex": hex_clean.upper(),
        "value": value,
        "name": _EF_IMSDCI_VALUES.get(value, f"reserved_0x{value:02X}"),
    }


# ---------------------------------------------------------------------------
# Wave C Pass A — semantic decoders for DF.5GS / DF.5G_ProSe / DF.SNPN /
# ADF.USIM ePDG EFs.
#
# Coverage (20 EFs, TS 31.102 §4.2 / §4.4.11 / §4.4.12 / §4.4.13):
#   ef-5g-prose-st        (§4.4.13.2)  service table
#   ef-5g-prose-dd        (§4.4.13.3)  BER-TLV direct discovery config
#   ef-5g-prose-dc        (§4.4.13.4)  BER-TLV direct comm config
#   ef-5g-prose-u2nru     (§4.4.13.5)  BER-TLV UE-to-network relay (user)
#   ef-5g-prose-ru        (§4.4.13.6)  BER-TLV remote UE config
#   ef-5g-prose-uir       (§4.4.13.7)  BER-TLV usage-info reporting
#   ef-pws-snpn           (§4.4.12.2)  1-byte flags
#   ef-suci-calc-info     (§4.4.11.8)  BER-TLV (routed to existing helper)
#   ef-supi-nai           (§4.4.11.10) TLV 80/81/82 (routed via _decode_supinai)
#   ef-cag                (§4.4.11.14) opaque-by-spec (annotated)
#   ef-sor-cmci           (§4.4.11.15) opaque-by-spec (annotated)
#   ef-dri                (§4.4.11.17) 7-byte struct
#   ef-mchpplmn           (§4.4.11.20) PLMN triples
#   ef-kausf-derivation   (§4.4.11.18) 1 byte flags + rfu
#   ef-ipd                (§4.2.99)    opaque (IP address list)
#   ef-ips                (§4.2.100)   4-byte pairing-status record
#   ef-epdgid             (§4.2.103)   TLV 80 { type + address }
#   ef-epdgidem           (§4.2.103)   TLV 80 { type + address }
#   ef-epdgselection      (§4.2.104)   TLV 80 { (plmn,prio,fmt)* }
#   ef-epdgselectionem    (§4.2.104)   TLV 80 { (plmn,prio,fmt)* }
#
# Every decoder returns a dict containing a ``hex`` field with the
# verbatim payload bytes so that ``encode_ef_opaque`` (the default
# round-trip encoder) can still reproduce the content byte-exact. The
# semantic fields are additive — edits happen through the raw ``hex``
# key for now; richer in-place editing is a follow-up wave.


_5G_PROSE_ST_SERVICES: dict[int, str] = {
    1: "ProSe Direct Discovery",
    2: "ProSe Direct Communication",
    3: "UE-to-Network Relay (User)",
    4: "Remote UE (5G ProSe L3 UE-to-network relay)",
    5: "Usage Information Reporting",
    6: "UE-to-UE Relay UE (Rel-18)",
    7: "End UE (Rel-18)",
}


def _decode_5g_prose_service_table(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.5G_PROSE_ST (TS 31.102 §4.4.13.2).

    Service table bitmap. Service N is bit ``(N-1) mod 8`` of byte
    ``(N-1) // 8``. A service is enabled when the bit is set to 1.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    services: list[dict[str, object]] = []
    active: list[int] = []
    for byte_index, byte_value in enumerate(raw):
        for bit_index in range(8):
            service_number = byte_index * 8 + bit_index + 1
            enabled = bool((byte_value >> bit_index) & 0x01)
            label = _5G_PROSE_ST_SERVICES.get(service_number)
            service_row: dict[str, object] = {
                "service": service_number,
                "enabled": enabled,
            }
            if label is not None:
                service_row["name"] = label
            services.append(service_row)
            if enabled is True:
                active.append(service_number)
    summary_parts: list[str] = []
    for number in active:
        name = _5G_PROSE_ST_SERVICES.get(number)
        if name is None:
            summary_parts.append(f"#{number}")
        else:
            summary_parts.append(f"#{number} ({name})")
    return {
        "format": "5G ProSe Service Table",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "activeServices": active,
        "services": services,
        "summary": (
            "active: " + ", ".join(summary_parts)
            if len(summary_parts) > 0
            else "no services active"
        ),
    }


_5G_PROSE_DD_TAGS: dict[str, str] = {
    "A0": "ProSe direct-discovery configuration",
    "80": "Served by NG-RAN",
    "81": "Not served by NG-RAN",
    "82": "ProSe identifiers",
    "83": "ProSe ID to default destination L2 ID",
    "84": "Group member discovery parameters",
    "85": "Validity timer",
    "86": "ProSe direct-discovery UE ID",
    "87": "HPLMN 5G DDNMF address",
}


_5G_PROSE_DC_TAGS: dict[str, str] = {
    "A0": "ProSe direct-communication configuration",
    "80": "Served by NG-RAN",
    "81": "Not served by NG-RAN",
    "85": "Validity timer",
    "87": "Privacy configuration",
    "88": "Direct communication in NR PC5",
    "89": "Application-to-path preference mapping rules",
    "91": "ProSe ID to NR Tx profile mapping rules",
}


_5G_PROSE_U2NRU_TAGS: dict[str, str] = {
    "A0": "ProSe UE-to-network relay UE configuration",
    "80": "Served by NG-RAN",
    "81": "Not served by NG-RAN",
    "85": "Validity timer",
    "8A": "ProSe ID to default destination L2 ID",
    "8B": "RXC info list",
    "8C": "5QI to PC5 QoS parameters mapping rules",
    "8D": "ProSe ID to application server address mapping rules",
    "8E": "User info ID for discovery",
    "92": "Privacy timer",
    "93": "5G PKKMF address information",
}


_5G_PROSE_RU_TAGS: dict[str, str] = {
    "A0": "ProSe remote-UE configuration",
    "80": "Served by NG-RAN",
    "81": "Not served by NG-RAN",
    "85": "Validity timer",
    "8B": "RXC info list",
    "8E": "User info ID for discovery",
    "8F": "Default destination L2 IDs",
    "90": "N3IWF selection info for 5G ProSe L3 remote UE",
    "92": "Privacy timer",
    "93": "5G PKKMF address information",
}


_5G_PROSE_UIR_TAGS: dict[str, str] = {
    "A0": "ProSe usage-information reporting configuration",
    "85": "Validity timer",
    "94": "Collection period",
    "95": "Reporting window",
    "96": "Reporting indicators",
    "97": "5G DDNMF CTF address for uploading",
}


# Rel-18 ProSe UE-to-UE Relay (User) — TS 31.102 §4.4.13.8, tag set
# mirrors U2NRU but adds the U2U-specific RSC list / L2 ID mapping.
_5G_PROSE_U2URU_TAGS: dict[str, str] = {
    "A0": "ProSe UE-to-UE relay UE configuration",
    "80": "Served by NG-RAN",
    "81": "Not served by NG-RAN",
    "85": "Validity timer",
    "8A": "ProSe ID to default destination L2 ID",
    "8B": "RXC info list",
    "8C": "5QI to PC5 QoS parameters mapping rules",
    "8D": "ProSe ID to application server address mapping rules",
    "8E": "User info ID for discovery",
    "92": "Privacy timer",
    "93": "5G PKKMF address information",
    "98": "U2U RSC list",
    "99": "U2U default destination L2 ID mapping",
}


# Rel-18 ProSe End-UE — TS 31.102 §4.4.13.9, derived from pySim U2URu
# / remote-UE tag aliases. Shares most anchors with RU.
_5G_PROSE_EU_TAGS: dict[str, str] = {
    "A0": "ProSe end-UE configuration",
    "80": "Served by NG-RAN",
    "81": "Not served by NG-RAN",
    "85": "Validity timer",
    "8B": "RXC info list",
    "8E": "User info ID for discovery",
    "8F": "Default destination L2 IDs",
    "90": "N3IWF selection info for end UE",
    "92": "Privacy timer",
    "93": "5G PKKMF address information",
    "98": "U2U RSC list",
}


_5G_PROSE_SMALL_INT_TAGS = frozenset({"85", "92", "94", "95"})


def _decode_5g_prose_tlv_ef(
    hex_clean: str,
    *,
    format_name: str,
    tag_names: dict[str, str],
) -> dict[str, object] | None:
    """Decode a 5G-ProSe BER-TLV EF (common skeleton for DD/DC/U2NRU/RU/UIR).

    Tags 85 (Validity timer), 92 (Privacy timer), 94 (Collection period)
    and 95 (Reporting window) carry spec-typed integer durations per
    TS 24.554 / TS 24.555. Remaining tags carry binary identifiers or
    address records that are kept as raw hex.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    declared_small_ints = {
        tag: _tlv_value_decoder_small_int
        for tag in tag_names
        if tag in _5G_PROSE_SMALL_INT_TAGS
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=tag_names,
        value_decoders=declared_small_ints if declared_small_ints else None,
    )
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


# ---------------------------------------------------------------------------
# Round-2 Pass 2 — generic BER-TLV promotion for MCS / V2X / ProSe-provisioned
# and ISIM ancillary EFs. These EFs are specified as BER-TLV containers by
# their respective 3GPP clauses without an exhaustive tag enumeration, so
# we surface the TLV boundaries + any known-tag names and leave the payload
# bytes themselves as raw hex until issuer-specific decoders are layered on.
# ---------------------------------------------------------------------------


def _decode_generic_tlv_ef(
    hex_clean: str,
    *,
    format_name: str,
    spec_reference: str,
    tag_names: dict[str, str] | None = None,
    value_decoders: dict[str, ValueDecoder] | None = None,
) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=tag_names if tag_names is not None else {},
        value_decoders=value_decoders,
    )
    # If the stream parser did not surface a single successfully decoded TLV
    # we have nothing useful to show beyond the raw blob; surrender so the
    # caller can fall through to the spec-opaque annotated wrapper. Without
    # this guard a malformed payload would report "length=N, items=[parseError]"
    # and shadow the more informative opaque summary.
    parsed_ok = any(
        not (isinstance(entry, dict) and entry.get("parseErrorOffset") is not None)
        for entry in items
    )
    if not parsed_ok:
        return None
    return {
        "format": format_name,
        "reference": spec_reference,
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_V2X_CFG_TAGS: dict[str, str] = {
    "80": "V2X Services (bitmap)",
    "81": "V2X PLMN List",
    "82": "V2X Authentication",
    "83": "V2X PC5 Configuration",
    "84": "V2X Uu Configuration",
    "85": "V2X Privacy Timer",
    "A0": "V2X Service Authorization",
}


_EF_V2X_PRECFG_TAGS: dict[str, str] = {
    "80": "Pre-configured V2X PC5 Parameters",
    "81": "Pre-configured V2X Uu Parameters",
    "82": "Pre-configured V2X Privacy Timer",
}


_EF_V2X_CERT_TAGS: dict[str, str] = {
    "80": "V2X Certificate",
    "81": "V2X Certificate Chain",
    "82": "V2X Certificate Validity",
}


_EF_V2X_AUTHKEYS_TAGS: dict[str, str] = {
    "80": "V2X Authentication Key",
    "81": "V2X Key Lifetime",
    "82": "V2X Key Reference",
}


_EF_MCS_TAGS: dict[str, str] = {
    "80": "MC Service Identifier",
    "81": "MC User Profile",
    "82": "MC Configuration Data",
    "83": "MC Service Authorization",
    "84": "MC Security Profile",
    "85": "MC Key Material",
    "A0": "MC Service Descriptor",
    "A1": "MC Group Descriptor",
}


def _tlv_value_decoder_utf8_text(value_bytes: bytes) -> str | None:
    """Decode a BER-TLV value as UTF-8 text.

    TS 24.483 carries MC configuration and profile data as XML strings
    and the TS 31.102 §4.4.13 MCPTT User Profile is likewise UTF-8
    encoded. Returns ``None`` when the bytes cannot be interpreted as
    UTF-8 so the caller falls back to the raw hex form.
    """

    if len(value_bytes) == 0:
        return None
    try:
        text = value_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None
    for character in text:
        if character < " " and character not in ("\t", "\n", "\r"):
            return None
    return text


# Per-tag value decoders for the MCS / MCPTT family. Tag 0x80 is defined
# as the MC Service Identifier (a SIP URI / MCPTT ID per TS 24.483 §6.2)
# and tags 0x81 / 0x82 carry UTF-8 encoded user-profile and configuration
# XML documents. Tags 0x83 / 0x84 / 0x85 are binary security material
# and must stay opaque to avoid context-blind fluff.
_EF_MCS_VALUE_DECODERS: dict[str, ValueDecoder] = {
    "80": _tlv_value_decoder_utf8_text,
    "81": _tlv_value_decoder_utf8_text,
    "82": _tlv_value_decoder_utf8_text,
}


_EF_PROSE_PROVISIONED_TAGS: dict[str, str] = {
    "80": "ProSe Configuration",
    "81": "ProSe Direct Discovery Parameters",
    "82": "ProSe Direct Communication Parameters",
    "83": "ProSe PC5 Radio Parameters",
    "A0": "ProSe Discovery Filter",
}


_EF_URSP_TAGS: dict[str, str] = {
    "80": "URSP Rule",
    "81": "Route Selection Descriptor",
    "82": "Traffic Descriptor",
    "A0": "URSP Rule Sequence",
}


_EF_IMPDF_TAGS: dict[str, str] = {
    "80": "IMPU Entry",
    "81": "PDF Identifier",
    "A0": "IMPU Record",
}


_EF_PKCS15_ACRF_TAGS: dict[str, str] = {
    "A0": "AuthObject Directory",
    "A1": "DataObject Directory",
    "A2": "CertObject Directory",
    "A3": "KeyObject Directory",
    "30": "Directory Entry",
}


def _decode_ef_netpar(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.NETPAR (TS 51.011 §10.3.14) — Network Parameters.

    Legacy 4-byte record structure: HPLMN search period (1 byte BCD
    encoded as multiples of 6 minutes per TS 22.011 §3.2) plus 3
    reserved bytes retained for backwards-compat.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    hplmn_period_byte = raw[0]
    reserved = raw[1:]
    if hplmn_period_byte == 0x00:
        search_desc = "no HPLMN search"
    else:
        minutes = hplmn_period_byte * 6
        search_desc = f"{minutes} minutes ({hplmn_period_byte} * 6 min)"
    return {
        "format": "Network Parameters",
        "reference": "TS 51.011 §10.3.14",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "hplmnSearchPeriodByte": f"0x{hplmn_period_byte:02X}",
        "hplmnSearchPeriod": search_desc,
        "reservedHex": reserved.hex().upper() if len(reserved) > 0 else "",
    }


def _decode_ef_cpbcch(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CPBCCH (TS 51.011 §10.3.30) — Compressed PBCCH information.

    16-byte bitmap of compressed PBCCH ARFCNs; structure mirrors
    EF.BCCH. Bit-ordering per TS 51.011: byte 1 bit 8 = CB index 1.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 16:
        return None
    indexes: list[int] = []
    for byte_index, byte in enumerate(raw):
        for bit in range(7, -1, -1):
            if byte & (1 << bit):
                indexes.append(byte_index * 8 + (8 - bit))
    return {
        "format": "Compressed PBCCH information",
        "reference": "TS 51.011 §10.3.30",
        "hex": raw.hex().upper(),
        "length": 16,
        "cpbcchBitCount": len(indexes),
        "cpbcchIndexes": indexes,
    }


def _decode_pws_snpn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PWS_SNPN (TS 31.102 §4.4.12.2).

    Single-byte bitmap:
      bit 0 — ignore all PWS in subscribed SNPNs
      bit 1 — ignore all PWS in non-subscribed SNPNs
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    flags = raw[0]
    ignore_subscribed = bool(flags & 0x01)
    ignore_non_subscribed = bool(flags & 0x02)
    labels: list[str] = []
    if ignore_subscribed is True:
        labels.append("ignore PWS in subscribed SNPNs")
    if ignore_non_subscribed is True:
        labels.append("ignore PWS in non-subscribed SNPNs")
    return {
        "format": "PWS configuration in SNPNs",
        "hex": raw.hex().upper(),
        "length": 1,
        "rawByte": f"0x{flags:02X}",
        "ignorePwsInSubscribedSnpns": ignore_subscribed,
        "ignorePwsInNonSubscribedSnpns": ignore_non_subscribed,
        "summary": ", ".join(labels) if len(labels) > 0 else "no PWS suppression",
    }


def _decode_ef_dri(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.DRI (TS 31.102 §4.4.11.17 — Disaster Roaming Information).

    7-byte structure:
      [0]   disaster roaming enabled (0x00/0x01)
      [1]   parameters indicator status (bit0 roamingWaitRange,
            bit1 returnWaitRange, bit2 applicabilityIndicator)
      [2-3] roaming wait range (uint16 BE, minutes)
      [4-5] return wait range (uint16 BE, minutes)
      [6]   applicability indicator
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 7:
        return None
    enabled_byte = raw[0]
    indicator = raw[1]
    roaming_wait = int.from_bytes(raw[2:4], "big", signed=False)
    return_wait = int.from_bytes(raw[4:6], "big", signed=False)
    applicability = raw[6]
    indicator_flags: list[str] = []
    if indicator & 0x01:
        indicator_flags.append("roamingWaitRange")
    if indicator & 0x02:
        indicator_flags.append("returnWaitRange")
    if indicator & 0x04:
        indicator_flags.append("applicabilityIndicator")
    return {
        "format": "Disaster Roaming Information",
        "hex": raw.hex().upper(),
        "length": 7,
        "disasterRoamingEnabled": bool(enabled_byte & 0x01),
        "disasterRoamingEnabledByte": f"0x{enabled_byte:02X}",
        "parametersIndicator": f"0x{indicator:02X}",
        "parametersIndicatorFlags": indicator_flags,
        "roamingWaitRangeMinutes": roaming_wait,
        "returnWaitRangeMinutes": return_wait,
        "applicabilityIndicator": f"0x{applicability:02X}",
        "summary": (
            f"enabled={bool(enabled_byte & 0x01)} "
            f"roamWait={roaming_wait}min returnWait={return_wait}min "
            f"app=0x{applicability:02X}"
        ),
    }


def _decode_ef_mchpplmn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MCHPPLMN (TS 31.102 §4.4.11.20 — Manual Configurable HPPLMN).

    Content is a concatenation of 3-byte encoded PLMN identifiers. Unused
    slots are filled with 0xFFFFFF.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or (len(raw) % 3) != 0:
        return None
    entries: list[dict[str, object]] = []
    active: list[str] = []
    for index in range(0, len(raw), 3):
        plmn_hex = raw[index : index + 3].hex().upper()
        if plmn_hex == "FFFFFF":
            entries.append({"index": index // 3, "plmn": None, "raw": plmn_hex})
            continue
        decoded_plmn = _decode_plmn_hex(plmn_hex)
        entries.append(
            {
                "index": index // 3,
                "plmn": decoded_plmn,
                "raw": plmn_hex,
            }
        )
        if decoded_plmn is not None:
            active.append(decoded_plmn)
    return {
        "format": "Manual Configurable HPPLMN",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "entries": entries,
        "activePlmns": active,
        "summary": ", ".join(active) if len(active) > 0 else "no PLMNs provisioned",
    }


def _decode_kausf_derivation(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.KAUSF_DERIVATION (TS 31.102 §4.4.11.18).

    Layout: 1 byte of K_AUSF derivation configuration flags followed by
    RFU octets. Only ``use_msk`` (bit 0) is defined.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    flag_byte = raw[0]
    use_msk = bool(flag_byte & 0x01)
    return {
        "format": "K_AUSF Derivation Configuration",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "configByte": f"0x{flag_byte:02X}",
        "useMsk": use_msk,
        "rfuHex": raw[1:].hex().upper() if len(raw) > 1 else "",
        "summary": f"useMsk={'yes' if use_msk else 'no'}",
    }


_5GS_UPDATE_STATUS_LABELS: dict[int, str] = {
    0x00: "updated",
    0x01: "not updated",
    0x02: "PLMN not allowed",
    0x03: "roaming not allowed in this tracking area",
}


def _decode_5gs_loci(
    hex_clean: str,
    *,
    format_name: str,
    spec_reference: str,
) -> dict[str, object] | None:
    """Decode EF.5GS3GPPLOCI / EF.5GSN3GPPLOCI (TS 31.102 §4.4.11.2 / §4.4.11.3).

    Fixed 20-byte layout:

        [0..12]  5G-GUTI (13 bytes; TS 24.501 §9.11.3.4 — PLMN 3 || AMF
                 Region ID 1 || AMF Set ID/Pointer 2 || 5G-TMSI 4 ||
                 RFU padding 3)
        [13..15] Last visited registered TAI — PLMN (BCD, swapped)
        [16..18] Last visited registered TAI — TAC
        [19]     5GS update status (TS 24.501 §9.11.3.2)
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 20:
        return None
    guti = raw[:13]
    guti_plmn = _decode_plmn_hex(guti[0:3].hex().upper())
    amf_region_id = guti[3]
    amf_set_pointer = guti[4:6]
    tmsi = guti[6:10]
    guti_rfu = guti[10:13]
    tai_plmn = _decode_plmn_hex(raw[13:16].hex().upper())
    tac = raw[16:19]
    status_byte = raw[19]
    status_label = _5GS_UPDATE_STATUS_LABELS.get(status_byte & 0x07)
    decoded: dict[str, object] = {
        "format": format_name,
        "specReference": spec_reference,
        "hex": raw.hex().upper(),
        "length": len(raw),
        "guti": {
            "hex": guti.hex().upper(),
            "plmn": guti_plmn,
            "plmnRaw": guti[0:3].hex().upper(),
            "amfRegionId": f"0x{amf_region_id:02X}",
            "amfSetAndPointerHex": amf_set_pointer.hex().upper(),
            "tmsiHex": tmsi.hex().upper(),
            "rfuHex": guti_rfu.hex().upper(),
        },
        "tai": {
            "hex": raw[13:19].hex().upper(),
            "plmn": tai_plmn,
            "plmnRaw": raw[13:16].hex().upper(),
            "tacHex": tac.hex().upper(),
            "tac": int.from_bytes(tac, "big"),
        },
        "updateStatus": {
            "byte": f"0x{status_byte:02X}",
            "value": status_byte & 0x07,
            "label": status_label if status_label is not None else "reserved",
        },
    }
    return decoded


def _decode_5gsedrx(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.5GSEDRX (TS 31.102 §4.4.11.19).

    Layout per TS 24.501 §9.11.3.26 (Extended DRX parameters):

        [0]  low nibble  — eDRX value (paging cycle)
             high nibble — RFU
        [1]  Paging Time Window (optional, absent on 1-byte files)
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) not in (1, 2):
        return None
    edrx_value = raw[0] & 0x0F
    rfu_nibble = (raw[0] >> 4) & 0x0F
    decoded: dict[str, object] = {
        "format": "5GS eDRX Parameters",
        "specReference": "TS 31.102 §4.4.11.19",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "edrxByte": f"0x{raw[0]:02X}",
        "edrxValue": edrx_value,
        "edrxRfuNibble": rfu_nibble,
    }
    if len(raw) == 2:
        ptw = raw[1] & 0x0F
        ptw_rfu = (raw[1] >> 4) & 0x0F
        decoded["pagingTimeWindowByte"] = f"0x{raw[1]:02X}"
        decoded["pagingTimeWindow"] = ptw
        decoded["pagingTimeWindowRfuNibble"] = ptw_rfu
    return decoded


def _decode_5gnswo_conf(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.5GNSWO_CONF (TS 31.102 §4.4.11.22).

    Single byte:
        bit 0 — 5G NSWO usage status (0 = disabled, 1 = enabled)
        bits 1..7 — RFU
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    flag = raw[0]
    enabled = bool(flag & 0x01)
    return {
        "format": "5G NSWO Configuration",
        "specReference": "TS 31.102 §4.4.11.22",
        "hex": raw.hex().upper(),
        "length": 1,
        "configByte": f"0x{flag:02X}",
        "nswoEnabled": enabled,
        "rfuBits": (flag >> 1) & 0x7F,
        "summary": "NSWO enabled" if enabled is True else "NSWO disabled",
    }


_EF_5MBS_UE_CONFIG_TAGS: dict[str, str] = {
    "80": "5MBS UE configuration data",
}


def _decode_5mbs_ue_config(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.5MBSUECONFIG (TS 31.102 §4.4.14.2).

    BER-TLV wrapper carrying a 5MBS UE pre-configuration XML/UTF-8
    document in tag 0x80.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {"80": _tlv_value_decoder_text}
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_5MBS_UE_CONFIG_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": "5MBS UE Pre-configuration",
        "specReference": "TS 31.102 §4.4.14.2",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_ips_record(hex_clean: str) -> dict[str, object] | None:
    """Decode an EF.IPS record (TS 31.102 §4.2.100 / §4.2.103 per release).

    4-byte record per pySim schema:
      [0..1] status flag (ASCII "00" / "FF" padded text)
      [2]    link to EF.IPD record id
      [3]    RFU
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 4:
        return None
    status_bytes = raw[:2]
    link = raw[2]
    rfu = raw[3]
    status_text: str | None
    try:
        status_text = status_bytes.decode("ascii").rstrip("\x00").rstrip()
    except UnicodeDecodeError:
        status_text = None
    status_field: object
    if status_text is None or any((b < 0x20 or b > 0x7E) for b in status_bytes):
        status_field = status_bytes.hex().upper()
    else:
        status_field = status_text
    return {
        "format": "IMEI(SV) Pairing Status",
        "hex": raw.hex().upper(),
        "length": 4,
        "status": status_field,
        "linkToEfIpd": int(link),
        "rfu": f"0x{rfu:02X}",
        "summary": f"status={status_field!r} link={int(link)}",
    }


_NID_ASSIGNMENT_MODE_LABELS: dict[int, str] = {
    0x00: "coordinated assignment (option 1)",
    0x01: "self-assigned",
    0x02: "coordinated assignment (option 2)",
}


def _decode_ef_nid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.NID (TS 31.102 §4.4.11.13.2 — SNPN Network Identifier).

    6-byte record:
        [0]     assignment mode (TS 23.003 §28.16.3)
        [1..5]  NID value (11-digit identifier packed per TS 23.003)
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 6:
        return None
    mode = raw[0]
    label = _NID_ASSIGNMENT_MODE_LABELS.get(mode)
    nid_bytes = raw[1:6]
    return {
        "format": "SNPN Network Identifier",
        "specReference": "TS 31.102 §4.4.11.13.2",
        "hex": raw.hex().upper(),
        "length": 6,
        "assignmentMode": {
            "byte": f"0x{mode:02X}",
            "value": mode,
            "label": label if label is not None else "reserved",
        },
        "nidHex": nid_bytes.hex().upper(),
    }


def _decode_ef_ocst(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.OCST (TS 31.102 §4.4.3 — Operator Controlled Signal Threshold).

    Layout: 1 byte 'sense' flag (bit 0) followed by BER-TLV data. The
    enclosed TLV stream carries per-access-technology threshold entries.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    sense = raw[0]
    sense_enabled = bool(sense & 0x01)
    tlv_items = _decode_field_ber_tlv_stream(
        raw[1:],
        tag_names={},
    ) if len(raw) > 1 else []
    return {
        "format": "Operator Controlled Signal Threshold",
        "specReference": "TS 31.102 §4.4.3",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "senseByte": f"0x{sense:02X}",
        "senseEnabled": sense_enabled,
        "tlvHex": raw[1:].hex().upper(),
        "items": tlv_items,
    }


def _decode_ef_rplmnact(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.RPLMNAcT (TS 31.102 §4.2.42 — RPLMN Access Technology).

    Linear-fixed record of 2-byte access-technology stacks per registered
    PLMN, each byte pair re-using the EF.PLMNwAcT AcT bitmap.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or (len(raw) % 2) != 0:
        return None
    entries: list[dict[str, object]] = []
    for offset in range(0, len(raw), 2):
        chunk = raw[offset : offset + 2]
        act_hex = chunk.hex().upper()
        entries.append(
            {
                "hex": act_hex,
                "accessTechnologies": _decode_access_technologies(act_hex),
            }
        )
    return {
        "format": "RPLMN Last used Access Technology",
        "specReference": "TS 31.102 §4.2.42",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "entries": entries,
    }


_EF_HNBN_TAGS: dict[str, str] = {
    "80": "Home NodeB name",
}


def _decode_ef_hnbn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.HNBN (TS 31.102 §4.4.6.4 — Home NodeB Name).

    BER-TLV wrapper. Tag 0x80 carries a UCS-2 string per TS 23.003.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {"80": _tlv_value_decoder_alpha_string}
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_HNBN_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": "Home NodeB Name",
        "specReference": "TS 31.102 §4.4.6.4",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_CSGT_TAGS: dict[str, str] = {
    "89": "Text CSG type",
    "80": "Graphics CSG type URI",
    "81": "Graphics CSG type EF-IMG record",
}


def _decode_ef_csgt(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CSGT (TS 31.102 §4.4.6.3 — CSG Types).

    BER-TLV collection. Tag 0x89 carries UCS-2, tag 0x80 a UTF-8 URI,
    tag 0x81 a single-octet EF.IMG record reference.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {
        "89": _tlv_value_decoder_alpha_string,
        "80": _tlv_value_decoder_text,
        "81": _tlv_value_decoder_small_int,
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_CSGT_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": "CSG Types",
        "specReference": "TS 31.102 §4.4.6.3",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_ACSGL_TAGS: dict[str, str] = {
    "A0": "CSG list entry",
    "80": "PLMN",
    "81": "CSG information",
    "82": "CSG display indicator",
}


def _tlv_value_decoder_plmn(value_bytes: bytes) -> dict[str, object]:
    """Primitive value decoder for 3-byte PLMN tuples (swapped nibbles)."""

    if len(value_bytes) != 3:
        return {"hex": value_bytes.hex().upper()}
    plmn = _decode_plmn_hex(value_bytes.hex().upper())
    return {"hex": value_bytes.hex().upper(), "plmn": plmn}


def _decode_ef_acsgl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ACSGL (TS 31.102 §4.4.6.2 — Allowed CSG Lists)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_ACSGL_TAGS,
        value_decoders={
            # TS 31.102 §4.4.6.2 — 80 is a 3-byte PLMN; 82 is a 1-byte
            # CSG display indicator. 81 is a nested CSG-information TLV
            # whose inner layout is operator-defined — keep it raw.
            "80": _tlv_value_decoder_plmn,
            "82": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "Allowed CSG Lists",
        "specReference": "TS 31.102 §4.4.6.2",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_ocsgl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.OCSGL (TS 31.102 §4.4.6.5 — Operator CSG Lists).

    Re-uses the ACSGL tag table; the only difference is the display-
    indicator tag (0x82) appears inside the operator list.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_ACSGL_TAGS,
        value_decoders={
            "80": _tlv_value_decoder_plmn,
            "82": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "Operator CSG Lists",
        "specReference": "TS 31.102 §4.4.6.5",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_ipd_opaque(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IPD (TS 31.102 §4.2.99 — IP Data).

    TS 31.102 §4.2.99 leaves the inner layout to the profile/operator
    (Greedy bytes with no mandated text encoding). We surface raw hex
    and a byte summary only — ASCII rendering here would be context-
    blind fluff and is intentionally omitted.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    return {
        "format": "USIM IP Data",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "specReference": "TS 31.102 §4.2.99",
        "summary": raw.hex().upper(),
    }


_EPDG_ADDRESS_TYPE_NAMES: dict[int, str] = {
    0x00: "FQDN",
    0x01: "IPv4",
    0x02: "IPv6",
}


def _decode_ef_epdgid(
    hex_clean: str,
    *,
    format_name: str = "Home ePDG Identifier",
) -> dict[str, object] | None:
    """Decode EF.ePDGId / EF.ePDGIdEm (TS 31.102 §4.2.103).

    Wrapper TLV ``80 LL { type(1) | address(LL-1) }``.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
    }
    if len(raw) < 3 or raw[0] != 0x80:
        decoded["summary"] = raw.hex().upper()
        return decoded
    value_length = raw[1]
    if value_length < 1 or 2 + value_length > len(raw):
        decoded["summary"] = raw.hex().upper()
        return decoded
    type_byte = raw[2]
    address_bytes = raw[3 : 2 + value_length]
    address_type = _EPDG_ADDRESS_TYPE_NAMES.get(type_byte, f"0x{type_byte:02X}")
    decoded["addressType"] = address_type
    decoded["addressTypeCode"] = int(type_byte)
    address_text: str | None = None
    if type_byte == 0x00:
        try:
            address_text = address_bytes.decode("utf-8")
        except UnicodeDecodeError:
            address_text = None
    elif type_byte == 0x01 and len(address_bytes) == 4:
        address_text = ".".join(str(b) for b in address_bytes)
    elif type_byte == 0x02 and len(address_bytes) == 16:
        parts = [address_bytes[i : i + 2].hex() for i in range(0, 16, 2)]
        address_text = ":".join(parts)
    if address_text is not None:
        decoded["address"] = address_text
        decoded["summary"] = f"{address_type}: {address_text}"
    else:
        decoded["addressHex"] = address_bytes.hex().upper()
        decoded["summary"] = f"{address_type}: {address_bytes.hex().upper()}"
    return decoded


_EPDG_FQDN_FORMAT_NAMES: dict[int, str] = {
    0x00: "operator_identified",
    0x01: "location_based",
}


def _decode_ef_epdgselection(
    hex_clean: str,
    *,
    format_name: str = "ePDG Selection Information",
) -> dict[str, object] | None:
    """Decode EF.ePDGSelection / EF.ePDGSelectionEm (TS 31.102 §4.2.104).

    Wrapper TLV ``80 LL { [plmn(3) + priority(2 BE) + fqdn_format(1)] * N }``.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
    }
    if len(raw) < 2 or raw[0] != 0x80:
        decoded["summary"] = raw.hex().upper()
        return decoded
    value_length = raw[1]
    if 2 + value_length > len(raw):
        decoded["summary"] = raw.hex().upper()
        return decoded
    body = raw[2 : 2 + value_length]
    if (len(body) % 6) != 0:
        decoded["summary"] = raw.hex().upper()
        decoded["items"] = body.hex().upper()
        return decoded
    entries: list[dict[str, object]] = []
    summary_parts: list[str] = []
    for index in range(0, len(body), 6):
        plmn_hex = body[index : index + 3].hex().upper()
        priority = int.from_bytes(body[index + 3 : index + 5], "big", signed=False)
        fmt_byte = body[index + 5]
        fmt_name = _EPDG_FQDN_FORMAT_NAMES.get(fmt_byte, f"0x{fmt_byte:02X}")
        plmn = _decode_plmn_hex(plmn_hex)
        row: dict[str, object] = {
            "plmnHex": plmn_hex,
            "priority": priority,
            "fqdnFormat": fmt_name,
            "fqdnFormatCode": int(fmt_byte),
        }
        if plmn is not None:
            row["plmn"] = plmn
        entries.append(row)
        plmn_display = plmn if plmn is not None else plmn_hex
        summary_parts.append(f"{plmn_display}:{priority}({fmt_name})")
    decoded["entries"] = entries
    decoded["summary"] = (
        ", ".join(summary_parts) if len(summary_parts) > 0 else "empty selection list"
    )
    return decoded


# ---------------------------------------------------------------------------
# Wave C Pass B — ADF.USIM optional / shared ISIM-USIM EF decoders.
#
# Coverage (20 EFs, TS 31.102 §4.2 / §4.4.2):
#   ef-bdn                routed to _decode_adn_like_record (§4.4.2.3)
#   ef-bdnuri             routed to _decode_uri_record (§4.4.2.4)
#   ef-ext4               routed to _decode_extension_record (§4.2.35)
#   ef-ext5               routed to _decode_extension_record (§4.2.82)
#   ef-ext8               routed to _decode_extension_record (§4.2.82)
#   ef-vgcsca             2-byte record per VGCS group (§4.2.77)
#   ef-vbsca              2-byte record per VBS group (§4.2.79)
#   ef-msk                MBMS Service Key list record (§4.2.80)
#   ef-muk                MBMS User Key BER-TLV record (§4.2.81)
#   ef-ufc                UE Functionality Configuration (§4.2.88)
#   ef-pws                USIM PWS configuration (§4.2.96)
#   ef-umpc               UICC Max Power Consumption (TS 102 221 §13.1)
#   ef-eaka               enhanced AKA support (§4.2.114)
#   ef-frompreferred      From Preferred (§4.2.106)
#   ef-3gpppsdataoff      3GPP PS Data Off (§4.2.92)
#   ef-3gpppsdataoffservicelist PS Data Off service list record (§4.2.93)
#   ef-ial                IMEI(SV) Association List (§4.2.102)
#   ef-ncp-ip             Network Connectivity Parameters for IP (§4.2.90)
#   ef-spni               Service Provider Name Icon (§4.2.73)
#   ef-pnni               PLMN Network Name Icon (§4.2.74)


def _decode_ef_pws(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PWS (TS 31.102 §4.2.96).

    1-byte flags:
      bit 0 — ignore PWS in HPLMN and equivalent
      bit 1 — ignore PWS in VPLMN
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    flags = raw[0]
    ignore_hplmn = bool(flags & 0x01)
    ignore_vplmn = bool(flags & 0x02)
    labels: list[str] = []
    if ignore_hplmn is True:
        labels.append("ignore PWS in HPLMN and equivalent")
    if ignore_vplmn is True:
        labels.append("ignore PWS in VPLMN")
    return {
        "format": "Public Warning System Configuration",
        "hex": raw.hex().upper(),
        "length": 1,
        "rawByte": f"0x{flags:02X}",
        "ignorePwsInHplmnAndEquivalent": ignore_hplmn,
        "ignorePwsInVplmn": ignore_vplmn,
        "summary": ", ".join(labels) if len(labels) > 0 else "no PWS suppression",
    }


def _decode_ef_ufc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.UFC (TS 31.102 §4.2.88).

    1-byte bitmap of optional UE functionality capabilities. Bit 0 is
    currently assigned to "TS 24.008 / USIM service configuration".
    Remaining bits are RFU and surfaced for editing.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    flag_byte = raw[0]
    bits: list[dict[str, object]] = []
    for bit_index in range(8):
        bits.append(
            {
                "bit": bit_index,
                "set": bool((flag_byte >> bit_index) & 0x01),
            }
        )
    return {
        "format": "UE Functionality Configuration",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "configByte": f"0x{flag_byte:02X}",
        "rfuHex": raw[1:].hex().upper() if len(raw) > 1 else "",
        "bits": bits,
        "summary": f"config=0x{flag_byte:02X}",
    }


def _decode_ef_umpc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.UMPC (TS 102 221 §13.1 — UICC Max Power Consumption).

    2-byte record:
      [0] maximum current (units of 1 mA when byte < 0xFF; 0xFF = undefined)
      [1] t_op: activation / deactivation duration (units of 2 ms)
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 2:
        return None
    max_current = raw[0]
    t_op = raw[1]
    return {
        "format": "UICC Max Power Consumption",
        "hex": raw.hex().upper(),
        "length": 2,
        "maxCurrentByte": f"0x{max_current:02X}",
        "maxCurrentMilliAmps": None if max_current == 0xFF else int(max_current),
        "tOpByte": f"0x{t_op:02X}",
        "tOpMilliseconds": int(t_op) * 2,
        "summary": (
            f"I_max={max_current} mA, t_op={t_op * 2} ms"
            if max_current != 0xFF
            else f"I_max=undefined, t_op={t_op * 2} ms"
        ),
    }


def _decode_ef_single_bit_flag(
    hex_clean: str,
    *,
    format_name: str,
    flag_name: str,
    summary_true: str,
    summary_false: str,
) -> dict[str, object] | None:
    """Shared 1-byte flag decoder (bit 0 = semantic flag, other bits RFU)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    flag_byte = raw[0]
    active = bool(flag_byte & 0x01)
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": 1,
        "rawByte": f"0x{flag_byte:02X}",
        flag_name: active,
        "summary": summary_true if active is True else summary_false,
    }


def _decode_ef_eaka(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.eAKA (TS 31.102 §4.2.114)."""

    return _decode_ef_single_bit_flag(
        hex_clean,
        format_name="Enhanced AKA Support",
        flag_name="enhancedSqnCalculationSupported",
        summary_true="enhanced SQN calculation supported",
        summary_false="legacy SQN calculation",
    )


def _decode_ef_from_preferred(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.FromPreferred (TS 31.102 §4.2.106)."""

    return _decode_ef_single_bit_flag(
        hex_clean,
        format_name="From Preferred",
        flag_name="fromPreferred",
        summary_true="from-preferred flag set",
        summary_false="from-preferred flag cleared",
    )


def _decode_ef_3gpp_ps_data_off(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.3GPPPSDATAOFF (TS 31.102 §4.2.92)."""

    return _decode_ef_single_bit_flag(
        hex_clean,
        format_name="3GPP PS Data Off",
        flag_name="psDataOffEnabled",
        summary_true="PS Data Off enabled",
        summary_false="PS Data Off disabled",
    )


def _decode_ef_3gpp_ps_data_off_service_list(
    hex_clean: str,
) -> dict[str, object] | None:
    """Decode EF.3GPPPSDATAOFFservicelist (TS 31.102 §4.2.93).

    Single-record payload: 1-byte service-activation bitmap. Each bit
    flags exemption of one standardised 3GPP PS service (voice,
    video, SMS, ...) from the PS-Data-Off policy. Bit assignment is
    operator-specific per TS 31.102 — we surface the raw byte and
    per-bit states for editing.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    bits: list[dict[str, object]] = []
    for byte_index, byte_value in enumerate(raw):
        for bit_index in range(8):
            service_number = byte_index * 8 + bit_index + 1
            bits.append(
                {
                    "service": service_number,
                    "exempt": bool((byte_value >> bit_index) & 0x01),
                }
            )
    active = [row["service"] for row in bits if row["exempt"] is True]
    return {
        "format": "3GPP PS Data Off Service List",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "bits": bits,
        "exemptServices": active,
        "summary": (
            "exempt services: " + ", ".join(f"#{n}" for n in active)
            if len(active) > 0
            else "no services exempt"
        ),
    }


def _decode_ef_cipher_algo_record(
    hex_clean: str,
    *,
    format_name: str,
) -> dict[str, object] | None:
    """Decode a 2-byte VGCSCA / VBSCA record (TS 31.102 §4.2.77 / §4.2.79).

    Layout:
      [0] alg_v_ki_1 — ciphering algorithm indicator for V_KI #1
      [1] alg_v_ki_2 — ciphering algorithm indicator for V_KI #2
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 2:
        return None
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": 2,
        "algVKi1": f"0x{raw[0]:02X}",
        "algVKi2": f"0x{raw[1]:02X}",
        "summary": f"alg(V_KI1)=0x{raw[0]:02X} alg(V_KI2)=0x{raw[1]:02X}",
    }


def _decode_ef_msk_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MSK record (TS 31.102 §4.2.80).

    Layout:
      [0..2]  key_domain_id
      [3]     num_msk_id
      [4..]   msk_id[num_msk_id] = { msk_id (4 BE) + timestamp_counter (4 BE) }
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 4:
        return None
    key_domain = raw[:3].hex().upper()
    num_msk_id = raw[3]
    entries: list[dict[str, object]] = []
    cursor = 4
    for _ in range(num_msk_id):
        if cursor + 8 > len(raw):
            break
        msk_id = int.from_bytes(raw[cursor : cursor + 4], "big", signed=False)
        ts_counter = int.from_bytes(
            raw[cursor + 4 : cursor + 8], "big", signed=False
        )
        entries.append(
            {
                "mskId": msk_id,
                "timestampCounter": ts_counter,
            }
        )
        cursor += 8
    return {
        "format": "MBMS Service Key List",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "keyDomainId": key_domain,
        "numMskId": int(num_msk_id),
        "entries": entries,
        "trailingHex": raw[cursor:].hex().upper() if cursor < len(raw) else "",
        "summary": (
            f"domain={key_domain} #keys={num_msk_id}"
        ),
    }


_EF_MUK_TAGS: dict[str, str] = {
    "A0": "MUK ID",
    "80": "MUK_Idr (UE)",
    "82": "MUK_Idi (network)",
    "81": "Timestamp counter",
}


def _decode_ef_muk_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MUK record (TS 31.102 §4.2.81).

    BER-TLV record with an A0 wrapper containing 80 (MUK_Idr) and 82
    (MUK_Idi) identifiers, plus a sibling 81 tag carrying the
    timestamp counter.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MUK_TAGS,
        value_decoders={
            # Timestamp counter is a small integer; identifiers are
            # opaque key material and must not be text-inferred.
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "MBMS User Key",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_IAL_TAGS: dict[str, str] = {
    "A0": "IMEI(SV) Association record",
    "80": "IMEI(SV)",
    "81": "Validity indicator",
}


def _tlv_value_decoder_imei_sv(value_bytes: bytes) -> dict[str, object]:
    """Primitive decoder for IMEI / IMEISV BCD payloads.

    TS 3GPP TS 23.003 §6.2 stores IMEI (15 digits) and IMEISV (16 digits)
    as half-octet swapped BCD. 8 bytes = 16 half-octets; the upper nibble
    of the first byte is a length indicator for IMEI and is 0x0 for
    IMEISV per TS 31.102. We handle both shapes by swapping and trimming
    trailing ``F`` padding.
    """

    if len(value_bytes) == 0:
        return {"hex": value_bytes.hex().upper()}
    swapped = _swap_nibbles(value_bytes.hex().upper()).rstrip("F")
    digits_only = "".join(ch for ch in swapped if ch.isdigit())
    shape = "IMEISV" if len(digits_only) == 16 else "IMEI" if len(digits_only) == 15 else "unknown"
    return {
        "hex": value_bytes.hex().upper(),
        "shape": shape,
        "digits": digits_only,
    }


def _decode_ef_ial_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IAL (TS 31.102 §4.2.102 — IMEI(SV) Association List)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_IAL_TAGS,
        value_decoders={
            # IMEI(SV) is stored as BCD with optional length nibble.
            # Validity indicator is a small flag.
            "80": _tlv_value_decoder_imei_sv,
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "IMEI(SV) Association List",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_NCP_IP_TAGS: dict[str, str] = {
    "80": "Access Point Name",
    "81": "Login",
    "82": "Password",
    "83": "Data destination address / prefix",
    "84": "Bearer description",
}


def _decode_ef_ncp_ip_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.NCP-IP (TS 31.102 §4.2.90 — Network Connectivity Parameters).

    BER-TLV collection with APN, login, password, address/prefix, and
    bearer description tags (TS 31.111 style).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_NCP_IP_TAGS,
        value_decoders={
            # APN, login, address/prefix are UTF-8 text per TS 31.111.
            # Password is intentionally left opaque.
            "80": _tlv_value_decoder_text,
            "81": _tlv_value_decoder_text,
            "83": _tlv_value_decoder_text,
        },
    )
    return {
        "format": "Network Connectivity Parameters (IP)",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_ICON_DISPLAY_CONDITION_NAMES: dict[int, str] = {
    0x00: "display icon only when operator name is not available",
    0x01: "display icon and operator name",
}


def _decode_ef_icon_indicator(
    hex_clean: str,
    *,
    format_name: str,
) -> dict[str, object] | None:
    """Decode EF.SPNI / EF.PNNI (TS 31.102 §4.2.73 / §4.2.74).

    2-byte record:
      [0] display condition byte (0x00 = icon-only, 0x01 = icon+name)
      [1] EF.IMG record number (0 = no icon associated)
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 2:
        return None
    display_byte = raw[0]
    record_number = raw[1]
    display_name = _ICON_DISPLAY_CONDITION_NAMES.get(
        display_byte, f"0x{display_byte:02X}"
    )
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": 2,
        "displayConditionByte": f"0x{display_byte:02X}",
        "displayCondition": display_name,
        "imgRecordNumber": int(record_number),
        "summary": (
            f"{display_name}, EF.IMG#{record_number}"
            if record_number != 0
            else f"{display_name}, no icon"
        ),
    }


# ---------------------------------------------------------------------------
# Wave C Pass C — ADF.ISIM + DF.MULTIMEDIA + MCS + MMS EF decoders.
#
# Coverage (20 EFs, TS 31.103 / TS 31.102 §4.6 / TS 51.011 §10.3.5x):
#   ef-gbabp             TS 31.103 §4.2.9  (GBA Bootstrapping Params)
#   ef-uicciari          TS 31.103 §4.2.16 (UICC IARI list)
#   ef-imsconfigdata     TS 31.103 §4.2.18 (IMS Config Data)
#   ef-xcapconfigdata    TS 31.103 §4.2.19 (XCAP Config Data)
#   ef-webrtcuri         TS 31.103 §4.2.20 (WebRTC URI)
#   ef-mudmidconfigdata  TS 31.103 §4.2.21 (MuD/MiD Config Data)
#   ef-mml               TS 31.102 §4.6.3.1 (MM Messages List)
#   ef-mmdf              TS 31.102 §4.6.3.2 (MM Messages Data)
#   ef-mst               TS 31.102 §4.6.4.1 (MCS Service Table)
#   ef-mlpl              TS 31.102 §4.6.3.3 (MMS List Preferred)
#   ef-mspl              TS 31.102 §4.6.3.4 (MMS Sender Preferred)
#   ef-mmssmode          TS 31.102 §4.6.3.5 (MMS Storage Mode)
#   ef-mmsicp            TS 51.011 §10.3.53 (MMS Issuer Conn Params)
#   ef-mmsn              TS 51.011 §10.3.51 (MMS Notifications)
#   ef-mmsucp            TS 51.011 §10.3.55 (MMS User Conn Params)
#   ef-mmsup             TS 51.011 §10.3.54 (MMS User Preferences)
#   ef-mmsconfig         3GPP2 C.S0023 §3.4.59 (CSIM MMS Config)
#   ef-hrpdcap           3GPP2 C.S0023 §3.4.43 (HRPD Capability)
#   ef-hrpdupp           3GPP2 C.S0023 §3.4.44 (HRPD User Profile)
#   ef-spc               3GPP2 C.S0023 §3.4.39 (Service Programming Code)


def _decode_lv_triple(
    raw: bytes,
    *,
    names: tuple[str, str, str],
) -> dict[str, object] | None:
    """Parse three consecutive length/value fields from ``raw``.

    Used by EF.GBABP (TS 31.103 §4.2.9): rand / b_tid / key_lifetime
    are all 1-byte length prefixed.
    """

    cursor = 0
    decoded: dict[str, object] = {}
    for field_name in names:
        if cursor >= len(raw):
            return None
        value_len = raw[cursor]
        cursor += 1
        if cursor + value_len > len(raw):
            return None
        decoded[field_name] = raw[cursor : cursor + value_len].hex().upper()
        decoded[f"{field_name}Length"] = int(value_len)
        cursor += value_len
    decoded["trailingHex"] = raw[cursor:].hex().upper() if cursor < len(raw) else ""
    return decoded


def _decode_ef_gbabp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.GBABP (TS 31.103 §4.2.9 / TS 31.102 §4.2.79)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 3:
        return None
    triple = _decode_lv_triple(
        raw, names=("rand", "bTid", "keyLifetime"),
    )
    if triple is None:
        return None
    return {
        "format": "GBA Bootstrapping Parameters",
        "hex": raw.hex().upper(),
        "length": len(raw),
        **triple,
    }


_EF_UICCIARI_TAGS: dict[str, str] = {
    "80": "IARI (UTF-8)",
}


def _decode_ef_uicciari(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.UICCIARI (TS 31.103 §4.2.16)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_UICCIARI_TAGS,
        value_decoders={"80": _tlv_value_decoder_text},
    )
    return {
        "format": "UICC IARI",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_WEBRTCURI_TAGS: dict[str, str] = {
    "80": "WebRTC URI (UTF-8)",
}


def _decode_ef_webrtcuri(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.WebRTCURI (TS 31.103 §4.2.20)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_WEBRTCURI_TAGS,
        value_decoders={"80": _tlv_value_decoder_text},
    )
    return {
        "format": "WebRTC URI",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_IMSCONFIGDATA_TAGS: dict[str, str] = {
    "80": "Encoding",
    "81": "Configuration Data",
}


def _decode_ef_imsconfigdata(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IMSConfigData (TS 31.103 §4.2.18 / TS 31.102 §4.4.11.10)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_IMSCONFIGDATA_TAGS,
        value_decoders={"80": _tlv_value_decoder_small_int},
    )
    return {
        "format": "IMS Configuration Data",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_MUDMID_TAGS: dict[str, str] = {
    "80": "Encoding",
    "81": "Configuration Data",
}


def _decode_ef_mudmidconfigdata(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MuDMiDConfigData (TS 31.103 §4.2.21)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MUDMID_TAGS,
        value_decoders={"80": _tlv_value_decoder_small_int},
    )
    return {
        "format": "MuD/MiD Configuration Data",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_XCAPCONFIG_TAGS: dict[str, str] = {
    "80": "XCAP Config DO",
    "A0": "XCAP Connection Parameters Policy",
    "A1": "XCAP Connection Parameters Policy Part",
    "81": "Access / AccessForXCAP",
    "82": "Application Name / #XCAP Conn Param Policy",
    "83": "Provider ID",
    "84": "URI",
    "85": "XCAP Authentication User Name",
    "86": "XCAP Authentication Password",
    "87": "XCAP Authentication Type",
    "88": "Address Type",
    "89": "Address",
    "8A": "PDP Authentication Type",
    "8B": "PDP Authentication Name",
    "8C": "PDP Authentication Secret",
}


def _decode_ef_xcapconfigdata(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.XCAPConfigData (TS 31.103 §4.2.19)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_XCAPCONFIG_TAGS,
        value_decoders={
            # Text fields per TS 31.103 §4.2.19 (UTF-8 URIs, usernames,
            # application names). Password tag (86) is intentionally
            # left opaque.
            "82": _tlv_value_decoder_text,
            "83": _tlv_value_decoder_text,
            "84": _tlv_value_decoder_text,
            "85": _tlv_value_decoder_text,
            "87": _tlv_value_decoder_small_int,
            "88": _tlv_value_decoder_small_int,
            "89": _tlv_value_decoder_text,
            "8A": _tlv_value_decoder_small_int,
            "8B": _tlv_value_decoder_text,
        },
    )
    return {
        "format": "XCAP Configuration Data",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_MMDF_TAGS: dict[str, str] = {
    "80": "Multimedia Message content chunk",
    "81": "Content type",
    "82": "Subject",
    "83": "From",
    "84": "To",
    "85": "Date",
    "A0": "Multimedia Message data object",
}


def _decode_ef_mmdf(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMDF (TS 31.102 §4.6.3.2) as free-form BER-TLV."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MMDF_TAGS,
        value_decoders={
            # Content type, subject, from, to, date are text per spec
            # TS 31.102 §4.6.3.2.
            "81": _tlv_value_decoder_text,
            "82": _tlv_value_decoder_text,
            "83": _tlv_value_decoder_text,
            "84": _tlv_value_decoder_text,
            "85": _tlv_value_decoder_text,
        },
    )
    return {
        "format": "Multimedia Messages Data File",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_MML_TAGS: dict[str, str] = {
    "A0": "Multimedia message list entry",
    "80": "Message reference",
    "81": "Message size",
    "82": "Timestamp",
    "83": "Flags",
}


def _decode_ef_mml(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MML (TS 31.102 §4.6.3.1) as free-form BER-TLV."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MML_TAGS,
        value_decoders={
            # Message reference and size are small integers; timestamp
            # and flags are spec-opaque and stay as ``raw`` hex.
            "80": _tlv_value_decoder_small_int,
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "Multimedia Messages List",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_MST_SERVICE_NAMES: dict[int, str] = {
    1: "MCPTT UE configuration data",
    2: "MCPTT User profile data",
    3: "MCS Group configuration data",
    4: "MCPTT Service configuration data",
    5: "MCS UE initial configuration data",
    6: "MCData UE configuration data",
    7: "MCData user profile data",
    8: "MCData service configuration data",
    9: "MCVideo UE configuration data",
    10: "MCVideo user profile data",
    11: "MCVideo service configuration data",
}


def _decode_ef_mst(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MST (TS 31.102 §4.6.4.1 — MCS Service Table)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    table = _decode_service_table(hex_clean, _EF_MST_SERVICE_NAMES)
    if table is None:
        return None
    return {
        "format": "MCS Service Table",
        "hex": raw.hex().upper(),
        "length": len(raw),
        **table,
    }


_EF_MLPL_TAGS: dict[str, str] = {
    "80": "MMS issuer connectivity profile alphanumeric name",
    "81": "Reference to EF.MMSICP",
}


def _decode_ef_mlpl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MLPL (TS 31.102 §4.6.3.3 — MMS List Preferred)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MLPL_TAGS,
        value_decoders={
            "80": _tlv_value_decoder_text,
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "MMS Issuer Connectivity Preferred List",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_MSPL_TAGS: dict[str, str] = {
    "80": "MMS user preferences profile alphanumeric name",
    "81": "Reference to EF.MMSUP",
}


def _decode_ef_mspl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MSPL (TS 31.102 §4.6.3.4 — MMS Sender Preferred)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MSPL_TAGS,
        value_decoders={
            "80": _tlv_value_decoder_text,
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "MMS User Preferences Preferred List",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_mmssmode(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMS Storage Mode (TS 31.102 §4.6.3.5).

    Single-byte flag: 0x01 = storage in UICC enabled, 0x00 = disabled.
    """

    return _decode_ef_single_bit_flag(
        hex_clean,
        format_name="MMS Storage Mode",
        flag_name="mmsStorageEnabled",
        summary_true="MMS storage on UICC enabled",
        summary_false="MMS storage on UICC disabled",
    )


_EF_MMSICP_TAGS: dict[str, str] = {
    "80": "MMS Implementation (WAP bit)",
    "81": "MMS Relay Server",
    "82": "Interface to CN",
    "83": "Gateway",
}


def _decode_ef_mmsicp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMSICP (TS 51.011 §10.3.53)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MMSICP_TAGS,
        value_decoders={
            "80": _tlv_value_decoder_small_int,
            "81": _tlv_value_decoder_text,
            "82": _tlv_value_decoder_small_int,
            "83": _tlv_value_decoder_text,
        },
    )
    return {
        "format": "MMS Issuer Connectivity Parameters",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_mmsn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMSN record (TS 51.011 §10.3.51).

    Layout per record (length N >= 4):
      [0..1]  MMS status
      [2]     MMS implementation (0x80 WAP per Annex K.1)
      [3..N-2] MMS notification content
      [N-1]   extension record identifier
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 4:
        return None
    mms_status = raw[:2].hex().upper()
    mms_impl = raw[2]
    ext_rec = raw[-1]
    notif = raw[3:-1]
    return {
        "format": "MMS Notification",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "mmsStatusHex": mms_status,
        "mmsImplementationByte": f"0x{mms_impl:02X}",
        "mmsImplementationWap": bool(mms_impl & 0x01),
        "mmsNotificationHex": notif.hex().upper(),
        "extensionRecordIdentifier": f"0x{ext_rec:02X}",
    }


def _decode_ef_mmsucp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMSUCP (TS 51.011 §10.3.55).

    Spec leaves the content opaque (proprietary to the MMS user agent);
    we surface it as spec-annotated opaque.
    """

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="MMS User Connectivity Parameters",
        spec_reference="TS 51.011 §10.3.55",
        summary_prefix="MMSUCP",
    )


_EF_MMSUP_TAGS: dict[str, str] = {
    "80": "MMS Implementation (WAP bit)",
    "81": "User preference profile name",
    "82": "User preference info",
}


def _decode_ef_mmsup(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMSUP (TS 51.011 §10.3.54 — MMS User Preferences)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MMSUP_TAGS,
        value_decoders={
            "80": _tlv_value_decoder_small_int,
            "81": _tlv_value_decoder_text,
        },
    )
    return {
        "format": "MMS User Preferences",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_mmsconfig(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MMSConfig (CSIM MMS Config — 3GPP2 C.S0023)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="CSIM MMS Configuration",
        spec_reference="3GPP2 C.S0023 §3.4.59",
        summary_prefix="MMSCONFIG",
    )


def _decode_ef_hrpdcap(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.HRPDcap (3GPP2 C.S0023 — HRPD Capability)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="HRPD Capability",
        spec_reference="3GPP2 C.S0023 §3.4.43",
        summary_prefix="HRPDCAP",
    )


def _decode_ef_hrpdupp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.HRPDupp (3GPP2 C.S0023 — HRPD User Profile Parameters)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="HRPD User Profile Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.44",
        summary_prefix="HRPDUPP",
    )


def _decode_ef_spc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SPC (3GPP2 C.S0023 — Service Programming Code)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Service Programming Code",
        spec_reference="3GPP2 C.S0023 §3.4.39",
        summary_prefix="SPC",
    )


# ---------------------------------------------------------------------------
# Wave C Pass D — ADF.CSIM / OPT-CSIM core EF decoders.
#
# Coverage (20 EFs, 3GPP2 C.S0023 / C.S0065):
#   ef-csim-st          C.S0065 §5.2.28  (CSIM Service Table)
#   ef-accolc           C.S0023 §3.4.20  (Access Overload Class)
#   ef-mipcap           C.S0023 §3.4.36  (MIP Capabilities)
#   ef-ipv6cap          C.S0023 §3.4.45  (IPv6 Capability)
#   ef-smscap           C.S0023 §3.4.38  (SMS Capability)
#   ef-sipcap           C.S0023 §3.4.46  (SIP Capability)
#   ef-3gcik            C.S0023 §3.4.40  (3G CIK)
#   ef-imsi-m           C.S0023 §3.4.8   (IMSI-M)
#   ef-imsi-t           C.S0023 §3.4.9   (IMSI-T)
#   ef-ruimid           C.S0023 §3.4.41  (R-UIM ID)
#   ef-sf-euimid        C.S0023 §3.4.42  (Short Form EUIMID)
#   ef-esn-meid-me      C.S0023 §3.4.48  (ESN/MEID-ME)
#   ef-mdn              C.S0023 §3.4.7   (Mobile Directory Number)
#   ef-prl              C.S0023 §3.4.24  (Preferred Roaming List)
#   ef-eprl             C.S0023 §3.4.25  (Extended PRL)
#   ef-cdmahome         C.S0023 §3.4.27  (CDMA Home SID/NID)
#   ef-home-tag         C.S0023 §3.4.22  (Home Tag)
#   ef-group-tag        C.S0023 §3.4.21  (Group Tag)
#   ef-specific-tag     C.S0023 §3.4.23  (Specific Tag)
#   ef-tmsi             C.S0023 §3.4.17  (TMSI)


# CSIM Service Table names per 3GPP2 C.S0065 v2.0 §5.2.28 (partial — the
# catalog is operator-extensible; numeric fallbacks cover entries not
# explicitly named).
_CSIM_SERVICE_NAMES: dict[int, str] = {
    1: "Local phone book",
    2: "Fixed dialling numbers (FDN)",
    3: "Short message storage (SMS)",
    4: "HRPD",
    5: "Enhanced phone book (EPB)",
    6: "Multi-media domain support",
    7: "SF_EUIMID-based EUIMID",
    8: "MEID support",
    9: "Extension 1",
    10: "Extension 2",
    11: "Preferred roaming list (PRL)",
    12: "Extended PRL (EPRL)",
    13: "Over-the-air provisioning (OTA)",
    14: "Home tag",
    15: "Group tag",
    16: "Specific tag",
    17: "CDMA Home",
    18: "SMS parameters",
    19: "Voice mail service",
    20: "Data service options (DSO)",
    21: "3G Cellular Identification Key (3GCIK)",
    22: "Mobile IP (MIP)",
    23: "SIP",
    24: "IPv6 capability",
    25: "Root certificate",
    26: "Roaming indicator (RI)",
    27: "Service preferences (SP)",
    28: "Call prompt",
    29: "Call count",
}


def _decode_ef_csim_st(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CSIM-ST (3GPP2 C.S0065 §5.2.28)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    table = _decode_service_table(hex_clean, _CSIM_SERVICE_NAMES)
    if table is None:
        return None
    return {
        "format": "CSIM Service Table",
        "hex": raw.hex().upper(),
        "length": len(raw),
        **table,
    }


def _decode_ef_accolc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ACCOLC (3GPP2 C.S0023 §3.4.20).

    Single-byte field: access overload class in the lower nibble
    (0x00 - 0x0F). Upper nibble is reserved / 0x0.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    value = raw[0]
    accolc = value & 0x0F
    return {
        "format": "Access Overload Class",
        "hex": raw.hex().upper(),
        "length": 1,
        "rawByte": f"0x{value:02X}",
        "accolc": int(accolc),
        "reservedNibble": f"0x{(value >> 4) & 0x0F:X}",
        "summary": f"ACCOLC={accolc}",
    }


def _decode_ef_csim_1byte_cap(
    hex_clean: str,
    *,
    format_name: str,
    flag_map: dict[int, str],
    summary_prefix: str,
) -> dict[str, object] | None:
    """Decode a CSIM 1-byte capability bitmap (MIP/IPv6/SMS/SIP caps)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    value = raw[0]
    bits: list[dict[str, object]] = []
    active: list[str] = []
    for bit_index in range(8):
        label = flag_map.get(bit_index)
        set_flag = bool((value >> bit_index) & 0x01)
        bits.append(
            {
                "bit": bit_index,
                "name": label if label is not None else f"RFU{bit_index}",
                "set": set_flag,
            }
        )
        if set_flag is True and label is not None:
            active.append(label)
    return {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": 1,
        "rawByte": f"0x{value:02X}",
        "bits": bits,
        "enabled": active,
        "summary": (
            f"{summary_prefix}: {', '.join(active)}"
            if len(active) > 0
            else f"{summary_prefix}: none"
        ),
    }


def _decode_ef_mipcap(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MIPCAP (3GPP2 C.S0023 §3.4.36 — MIP Capabilities)."""

    return _decode_ef_csim_1byte_cap(
        hex_clean,
        format_name="MIP Capabilities",
        flag_map={
            0: "Simple IP",
            1: "Mobile IPv4",
            2: "Mobile IPv6",
        },
        summary_prefix="MIP",
    )


def _decode_ef_ipv6cap(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IPV6CAP (3GPP2 C.S0023 §3.4.45 — IPv6 Capability)."""

    return _decode_ef_csim_1byte_cap(
        hex_clean,
        format_name="IPv6 Capability",
        flag_map={
            0: "IPv6 supported",
            1: "Dual-stack supported",
        },
        summary_prefix="IPv6",
    )


def _decode_ef_smscap(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SMSCAP (3GPP2 C.S0023 §3.4.38 — SMS Capability)."""

    return _decode_ef_csim_1byte_cap(
        hex_clean,
        format_name="SMS Capability",
        flag_map={
            0: "Point-to-point SMS",
            1: "Broadcast SMS",
            2: "Enhanced SMS",
        },
        summary_prefix="SMS",
    )


def _decode_ef_sipcap(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SIPCAP (3GPP2 C.S0023 §3.4.46 — SIP Capability)."""

    return _decode_ef_csim_1byte_cap(
        hex_clean,
        format_name="SIP Capability",
        flag_map={
            0: "SIP UA",
            1: "Simple IP dormant",
            2: "SIP MWI",
        },
        summary_prefix="SIP",
    )


def _decode_ef_3gcik(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.3GCIK (3GPP2 C.S0023 §3.4.40)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="3G Cellular Identification Key",
        spec_reference="3GPP2 C.S0023 §3.4.40",
        summary_prefix="3GCIK",
    )


def _decode_ef_imsi_m(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IMSI-M (3GPP2 C.S0023 §3.4.8)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="IMSI-M",
        spec_reference="3GPP2 C.S0023 §3.4.8",
        summary_prefix="IMSI-M",
    )


def _decode_ef_imsi_t(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IMSI-T (3GPP2 C.S0023 §3.4.9)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="IMSI-T",
        spec_reference="3GPP2 C.S0023 §3.4.9",
        summary_prefix="IMSI-T",
    )


def _decode_ef_ruimid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.RUIMID (3GPP2 C.S0023 §3.4.41 — R-UIM ID)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="R-UIM ID",
        spec_reference="3GPP2 C.S0023 §3.4.41",
        summary_prefix="RUIMID",
    )


def _decode_ef_sf_euimid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SF-EUIMID (3GPP2 C.S0023 §3.4.42)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Short Form EUIMID",
        spec_reference="3GPP2 C.S0023 §3.4.42",
        summary_prefix="SF-EUIMID",
    )


def _decode_ef_esn_meid_me(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ESN-MEID-ME (3GPP2 C.S0023 §3.4.48)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="ESN / MEID ME",
        spec_reference="3GPP2 C.S0023 §3.4.48",
        summary_prefix="ESN-MEID-ME",
    )


def _decode_ef_mdn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MDN (3GPP2 C.S0023 §3.4.7 — Mobile Directory Number).

    Per C.S0023, each record is: 1-byte mdn-length + BCD-encoded digits
    padded with 0xF. BCD bytes are low-nibble-first (digit N then
    digit N+1). We surface both the raw bytes and the decoded MDN
    string.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    mdn_len = raw[0]
    digits: list[str] = []
    for byte_value in raw[1:]:
        low_nibble = byte_value & 0x0F
        high_nibble = (byte_value >> 4) & 0x0F
        if low_nibble <= 9:
            digits.append(str(low_nibble))
        elif low_nibble == 0xF:
            break
        if high_nibble <= 9:
            digits.append(str(high_nibble))
        elif high_nibble == 0xF:
            break
    mdn = "".join(digits)
    if 0 < mdn_len <= len(mdn):
        mdn = mdn[: int(mdn_len)]
    return {
        "format": "Mobile Directory Number (CSIM)",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "mdnLength": int(mdn_len),
        "mdn": mdn,
        "paddingHex": raw[1:].hex().upper(),
        "summary": f"MDN={mdn}" if mdn != "" else "MDN empty",
    }


def _decode_ef_prl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PRL (3GPP2 C.S0023 §3.4.24 — Preferred Roaming List)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Preferred Roaming List",
        spec_reference="3GPP2 C.S0023 §3.4.24",
        summary_prefix="PRL",
    )


def _decode_ef_eprl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.EPRL (3GPP2 C.S0023 §3.4.25 — Extended PRL)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Extended Preferred Roaming List",
        spec_reference="3GPP2 C.S0023 §3.4.25",
        summary_prefix="EPRL",
    )


def _decode_ef_cdmahome(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CDMAHOME (3GPP2 C.S0023 §3.4.27 — CDMA Home SID/NID)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="CDMA Home SID/NID",
        spec_reference="3GPP2 C.S0023 §3.4.27",
        summary_prefix="CDMAHOME",
    )


def _decode_ef_home_tag(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.Home-Tag (3GPP2 C.S0023 §3.4.22)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Home Tag",
        spec_reference="3GPP2 C.S0023 §3.4.22",
        summary_prefix="Home tag",
    )


def _decode_ef_group_tag(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.Group-Tag (3GPP2 C.S0023 §3.4.21)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Group Tag",
        spec_reference="3GPP2 C.S0023 §3.4.21",
        summary_prefix="Group tag",
    )


def _decode_ef_specific_tag(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.Specific-Tag (3GPP2 C.S0023 §3.4.23)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Specific Tag",
        spec_reference="3GPP2 C.S0023 §3.4.23",
        summary_prefix="Specific tag",
    )


def _decode_ef_csim_tmsi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.TMSI (3GPP2 C.S0023 §3.4.17 — CSIM TMSI)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="CSIM TMSI",
        spec_reference="3GPP2 C.S0023 §3.4.17",
        summary_prefix="CSIM TMSI",
    )


# ---------------------------------------------------------------------------
# Wave C Pass E — DF.TELECOM / DF.PHONEBOOK / ICE / DF.V2X / EAP EF decoders.
#
# Coverage (20 EFs, TS 31.102 §4.4.2/§4.4.3/§4.6.1/§4.6.5 + TS 102 310):
#   ef-aas              TS 31.102 §4.4.2.13 (Additional Alpha String)
#   ef-pbc              TS 31.102 §4.4.2.5  (Phonebook Control)
#   ef-puri             TS 31.102 §4.4.2.17 (Phonebook URI)
#   ef-uid              TS 31.102 §4.4.2.14 (Phonebook Unique Identifier)
#   ef-ice-dn           TS 31.102 §4.4.3.3  (ICE Dialling Numbers)
#   ef-ice-ff           TS 31.102 §4.4.3.4  (ICE Free Format)
#   ef-ice-graphics     TS 31.102 §4.4.3.5  (ICE Graphics)
#   ef-icon             TS 31.102 §4.6.1.1  (Icon)
#   ef-img              TS 31.102 §4.6.1.2  (Image)
#   ef-iidf             TS 31.102 §4.6.1.3  (Image Instance Data File)
#   ef-launch-scws      TS 31.102 §4.4.8    (Launch SCWS)
#   ef-launchpad        Operator Launchpad  (vendor-specific)
#   ef-mcs-config       TS 31.102 §4.6.4.2  (MCS Configuration)
#   ef-v2x-config       TS 31.102 §4.6.5.3  (V2X Configuration)
#   ef-v2xp-Uu          TS 31.102 §4.6.5.4  (V2X Uu Parameters)
#   ef-v2xp-pc5         TS 31.102 §4.6.5.5  (V2X PC5 Parameters)
#   ef-vst              TS 31.102 §4.6.5.2  (V2X Service Table)
#   ef-curid            TS 102 310 §5.2.2   (EAP Current ID)
#   ef-ps               TS 102 310 §5.2.2   (EAP Pseudonym)
#   ef-realm            TS 102 310 §5.2.2   (EAP Realm)


_EF_AAS_TAGS: dict[str, str] = {
    "80": "Additional Alpha String (UCS-2/GSM)",
}


def _decode_ef_aas(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.AAS (TS 31.102 §4.4.2.13).

    Tag 0x80 carries a TS 31.102 Annex A alpha string (GSM 7-bit or
    UCS-2 depending on the leading byte). Declare the per-tag decoder
    so the editor surfaces the decoded label instead of raw bytes.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_AAS_TAGS,
        value_decoders={"80": _tlv_value_decoder_alpha_string},
    )
    return {
        "format": "Phonebook Additional Alpha String",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_pbc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PBC (TS 31.102 §4.4.2.5 — Phonebook Control).

    Per TS 31.102, each record contains a single-byte control flag
    followed by record-metadata (hidden/private markers). We expose
    the control byte and its flag bits.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    control = raw[0]
    bits = [
        {
            "bit": 0,
            "name": "hiddenEntry",
            "set": bool(control & 0x01),
        },
        {
            "bit": 1,
            "name": "inUse",
            "set": bool(control & 0x02),
        },
    ]
    return {
        "format": "Phonebook Control",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "controlByte": f"0x{control:02X}",
        "bits": bits,
        "trailingHex": raw[1:].hex().upper(),
    }


def _decode_ef_puri(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PURI (TS 31.102 §4.4.2.17 — Phonebook URI)."""

    return _decode_uri_record(
        hex_clean,
        format_name="Phonebook URI",
        spec_reference="TS 31.102 §4.4.2.17",
    )


def _decode_ef_uid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.UID (TS 31.102 §4.4.2.14 — Phonebook Unique Identifier).

    Content is a 2-byte big-endian integer UID per record.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 2:
        return None
    uid_value = int.from_bytes(raw[:2], "big", signed=False)
    return {
        "format": "Phonebook Unique Identifier",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "uid": uid_value,
        "uidHex": raw[:2].hex().upper(),
        "trailingHex": raw[2:].hex().upper(),
    }


def _decode_ef_ice_dn(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ICE-DN (TS 31.102 §4.4.3.3 — ICE Dialling Numbers).

    Layout matches EF.ADN: alpha identifier + BCD dialling information.
    We wrap the ADN-like record with ``hex`` + ``length`` so downstream
    consumers can roundtrip the record through
    ``encode_decoded_roundtrip_ef_content``.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    adn = _decode_adn_like_record(hex_clean)
    if adn is None:
        return None
    return {
        "format": "ICE Dialling Number",
        "hex": raw.hex().upper(),
        "length": len(raw),
        **adn,
    }


def _decode_ef_ice_ff(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ICE-FF (TS 31.102 §4.4.3.4 — ICE Free Format).

    The free-format byte stream is opaque per spec; we surface it as
    annotated opaque.
    """

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="ICE Free Format",
        spec_reference="TS 31.102 §4.4.3.4",
        summary_prefix="ICE-FF",
    )


def _decode_ef_ice_graphics(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ICE-Graphics (TS 31.102 §4.4.3.5)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="ICE Graphics",
        spec_reference="TS 31.102 §4.4.3.5",
        summary_prefix="ICE-Graphics",
    )


def _decode_ef_icon(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ICON (TS 31.102 §4.6.1.1)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Icon",
        spec_reference="TS 31.102 §4.6.1.1",
        summary_prefix="Icon",
    )


def _decode_ef_img(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IMG (TS 31.102 §4.6.1.2 — Image Instance Record).

    Layout per record: number of actual images (1B) + per-image
    structure (width 1B, height 1B, image coding 1B, offset 2B,
    length 2B, instance EF FID 2B). We expose the metadata and the
    raw bytes per image slot.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    num_images = raw[0]
    images: list[dict[str, object]] = []
    cursor = 1
    while cursor + 9 <= len(raw):
        slot = raw[cursor : cursor + 9]
        images.append(
            {
                "widthPixels": int(slot[0]),
                "heightPixels": int(slot[1]),
                "imageCoding": f"0x{slot[2]:02X}",
                "offsetHex": slot[3:5].hex().upper(),
                "lengthBytes": int.from_bytes(
                    slot[5:7], "big", signed=False,
                ),
                "instanceFileId": slot[7:9].hex().upper(),
            }
        )
        cursor += 9
    return {
        "format": "Image Instance Record",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "numImages": int(num_images),
        "images": images,
        "trailingHex": raw[cursor:].hex().upper(),
    }


def _decode_ef_iidf(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IIDF (TS 31.102 §4.6.1.3 — Image Instance Data File)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Image Instance Data File",
        spec_reference="TS 31.102 §4.6.1.3",
        summary_prefix="IIDF",
    )


def _decode_ef_launch_scws(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.LAUNCH-SCWS (TS 31.102 §4.4.8)."""

    return _decode_uri_record(
        hex_clean,
        format_name="Launch SCWS URL",
        spec_reference="TS 31.102 §4.4.8 / TS 102 588",
    )


def _decode_ef_launchpad(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.LAUNCHPAD (vendor/operator-specific)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Operator Launchpad",
        spec_reference="Operator-specific (CD Launchpad)",
        summary_prefix="Launchpad",
    )


_EF_MCS_CONFIG_TAGS: dict[str, str] = {
    "80": "MCPTT UE configuration data",
    "81": "MCPTT user profile data",
    "82": "MCS group configuration data",
    "83": "MCPTT service configuration data",
    "84": "MCS UE initial configuration data",
    "85": "MCData UE configuration data",
    "86": "MCData user profile data",
    "87": "MCData service configuration data",
    "88": "MCVideo UE configuration data",
    "89": "MCVideo user profile data",
    "8A": "MCVideo service configuration data",
}


def _decode_ef_mcs_config(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MCS_CONFIG (TS 31.102 §4.6.4.2).

    All MCS / MCPTT / MCData / MCVideo configuration tags carry
    XML / UTF-8 text blobs per 3GPP TS 24.484 / TS 24.481. The value
    decoders surface a printable rendering when the blob is UTF-8
    clean and fall back to raw hex otherwise.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {
        tag: _tlv_value_decoder_text
        for tag in ("80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "8A")
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_MCS_CONFIG_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": "MCS Configuration",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_V2X_CONFIG_TAGS: dict[str, str] = {
    "80": "V2X configuration data",
}


def _decode_ef_v2x_config(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.V2X_CONFIG (TS 31.102 §4.6.5.3).

    V2X configuration data tag 0x80 carries a UTF-8 XML blob per
    TS 31.102 §4.6.5.3 (profile configuration document). The value
    decoder surfaces a printable rendering when it parses cleanly.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {"80": _tlv_value_decoder_text}
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_V2X_CONFIG_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": "V2X Configuration",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_v2xp_uu(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.V2XP-Uu (TS 31.102 §4.6.5.4).

    BER-TLV container; tag 0x80 carries the V2X Uu configuration
    document as UTF-8. When the XML blob parses cleanly the value is
    surfaced as text; otherwise the raw hex is preserved.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {"80": _tlv_value_decoder_text}
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "V2X Uu configuration data"},
        value_decoders=value_decoders,
    )
    if len(items) == 0:
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="V2X Uu Parameters",
            spec_reference="TS 31.102 §4.6.5.4",
            summary_prefix="V2XP-Uu",
        )
    return {
        "format": "V2X Uu Parameters",
        "reference": "TS 31.102 §4.6.5.4",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_v2xp_pc5(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.V2XP-PC5 (TS 31.102 §4.6.5.5).

    BER-TLV container; tag 0x80 carries the V2X PC5 configuration
    document as UTF-8. Falls back to spec-annotated opaque summary if
    the TLV parse fails.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    value_decoders: dict[str, ValueDecoder] = {"80": _tlv_value_decoder_text}
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "V2X PC5 configuration data"},
        value_decoders=value_decoders,
    )
    if len(items) == 0:
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="V2X PC5 Parameters",
            spec_reference="TS 31.102 §4.6.5.5",
            summary_prefix="V2XP-PC5",
        )
    return {
        "format": "V2X PC5 Parameters",
        "reference": "TS 31.102 §4.6.5.5",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


# V2X service table names (TS 31.102 §4.6.5.2). The bitmap grows with
# successive releases; we cover the canonical Rel-15/16/17 entries and
# fall back to numeric labels for unknown bits.
_EF_VST_SERVICE_NAMES: dict[int, str] = {
    # TS 31.102 Rel-18 §4.6.5.2. Byte 0 is the "Coding of V2X data"
    # indicator ('00' XML per TS 24.385, '01' per TS 24.588); services
    # n°1..n°3 live in byte 1+.
    1: "V2X configuration data",
    2: "V2X policy configuration data over PC5",
    3: "V2X policy configuration data over Uu",
}


_EF_VST_CODING_NAMES: dict[int, str] = {
    0x00: "XML (TS 24.385)",
    0x01: "TS 24.588",
}


def _decode_ef_vst(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.VST (TS 31.102 Rel-18 §4.6.5.2 — V2X Service Table).

    Byte 0 is the ``Coding of V2X data`` indicator (reused by EFs in
    DF.V2X); bytes 1.. are the service-table bitmap proper.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    coding_byte = raw[0]
    coding_label = _EF_VST_CODING_NAMES.get(
        coding_byte, f"Reserved (0x{coding_byte:02X})"
    )
    service_bytes = raw[1:]
    active_services: list[dict[str, object]] = []
    active_lines: list[str] = []
    for byte_index, byte_value in enumerate(service_bytes):
        for bit_index in range(8):
            if byte_value & (1 << bit_index):
                service_number = (byte_index * 8) + bit_index + 1
                name = _EF_VST_SERVICE_NAMES.get(
                    service_number, f"Service {service_number}"
                )
                active_services.append(
                    {"number": service_number, "name": name}
                )
                active_lines.append(f"{service_number}: {name}")
    return {
        "format": "V2X Service Table",
        "reference": "TS 31.102 Rel-18 §4.6.5.2",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "codingOfV2xData": {
            "hex": f"{coding_byte:02X}",
            "name": coding_label,
        },
        "services": active_services,
        "activeServices": active_lines,
        "activeCount": len(active_lines),
    }


_EF_EAP_CURID_TAGS: dict[str, str] = {
    "80": "EAP Current ID (UTF-8)",
}


def _decode_ef_eap_curid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CURID (TS 102 310 §5.2.2 — EAP Current ID)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_EAP_CURID_TAGS,
        value_decoders={"80": _tlv_value_decoder_text},
    )
    return {
        "format": "EAP Current ID",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_EAP_PS_TAGS: dict[str, str] = {
    "80": "EAP Pseudonym (UTF-8)",
}


def _decode_ef_eap_ps(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PS (TS 102 310 §5.2.2 — EAP Pseudonym)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_EAP_PS_TAGS,
        value_decoders={"80": _tlv_value_decoder_text},
    )
    return {
        "format": "EAP Pseudonym",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EF_EAP_REALM_TAGS: dict[str, str] = {
    "80": "EAP Realm (UTF-8)",
}


def _decode_ef_eap_realm(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.REALM (TS 102 310 §5.2.2 — EAP Realm)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_EAP_REALM_TAGS,
        value_decoders={"80": _tlv_value_decoder_text},
    )
    return {
        "format": "EAP Realm",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


# ---------------------------------------------------------------------------
# Wave D Pass A — EAP / USIM / TELECOM / common residual EF decoders.
#
# Coverage (20 EFs):
#   ef-imsi             TS 31.102 §4.2.2   (USIM IMSI, wraps _decode_imsi
#                                            with hex/length for roundtrip)
#   ef-arr-usim         TS 102 221 §9.4    (Access Rule Reference)
#   ef-threshold        TS 31.102 §4.4.3.7 (Threshold)
#   ef-eapkeys          TS 102 310 §5.2.2  (EAP MSK/EMSK)
#   ef-eapstatus        TS 102 310 §5.2.2  (EAP Status)
#   ef-reid             TS 102 310 §5.2.2  (EAP Re-authentication ID)
#   ef-model            3GPP2 C.S0023 §3.4.61 (Device Model, ASCII)
#   ef-call-count       3GPP2 C.S0023 §3.4.72 (Call Count, 2-byte BE)
#   ef-call-prompt      3GPP2 C.S0023 §3.4.55 (Call Prompt, 1-byte flag)
#   ef-applabels        3GPP2 C.S0023 §3.4.60 (CSIM App Labels)
#   ef-auth-capability  3GPP2 C.S0023 §3.4.51 (Authentication Capability)
#   ef-acp              3GPP2 C.S0023 §3.4.11 (Access Channel Parameters)
#   ef-atc              3GPP2 C.S0023 §3.4.14 (Access Terminal Class)
#   ef-namlock          3GPP2 C.S0065 §5.2.?  (NAM Lock)
#   ef-usgind           3GPP2 C.S0023 §3.4.67 (Usage Indicator)
#   ef-dgc              3GPP2 C.S0023 §3.4.57 (Data Generic Configuration)
#   ef-term             3GPP2 C.S0023 §3.4.68 (Terminal Capability)
#   ef-hidden-key       3GPP2 C.S0023 §3.4.75 (Hidden Key)
#   ef-csspr            3GPP2 C.S0023 §3.4.37 (CSSPR)
#   ef-rma              TS 31.102          (Operator RMA / vendor-specific)


def _decode_ef_imsi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IMSI (TS 31.102 §4.2.2).

    Wraps :func:`_decode_imsi` with ``hex`` + ``length`` so the record
    roundtrips cleanly through ``encode_decoded_roundtrip_ef_content``.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    inner = _decode_imsi(hex_clean)
    if inner is None:
        return None
    return {
        "format": "USIM IMSI",
        "hex": raw.hex().upper(),
        "length": len(raw),
        **inner,
    }


_EF_ARR_USIM_TAGS: dict[str, str] = {
    "A4": "Access Rule Reference",
    "80": "Access Mode",
    "81": "Key Reference",
    "82": "Command Header",
    "83": "SCP03 AM",
    "84": "Condition",
    "A0": "AM + SC pair",
    "A1": "Always condition",
    "A7": "Never condition",
    "90": "Always",
    "97": "Never",
}


def _decode_ef_arr_usim(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ARR (TS 102 221 §9.4 — Access Rule Reference)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_ARR_USIM_TAGS,
        value_decoders={
            # Access mode and key reference bytes are small integers per
            # TS 102 221 §9.4; the rest of the ARR sub-tags carry
            # opaque structural data (command headers, conditions) that
            # must not be rendered as text.
            "80": _tlv_value_decoder_small_int,
            "81": _tlv_value_decoder_small_int,
        },
    )
    return {
        "format": "Access Rule Reference (USIM)",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_threshold(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.THRESHOLD (TS 31.102 §4.2.52).

    3-byte transparent file carrying the maximum value of STARTCS or
    STARTPS (lifetime bound for the AKA ciphering/integrity keys, see
    TS 33.102). Unused nibbles are coded ``F``; decoding surfaces both
    the raw hex and the integer value for operator tooling.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 3:
        return None
    value = int.from_bytes(raw, "big")
    return {
        "format": "Maximum START value",
        "reference": "TS 31.102 §4.2.52",
        "hex": raw.hex().upper(),
        "length": 3,
        "maxStart": value,
        "summary": f"max_start=0x{value:06X}",
    }


_EF_EAPKEYS_TAGS: dict[str, str] = {
    "80": "MSK (Master Session Key)",
    "81": "EMSK (Extended MSK)",
}


def _decode_ef_eapkeys(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.EAPKEYS (TS 102 310 §5.2.2)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(raw, tag_names=_EF_EAPKEYS_TAGS)
    return {
        "format": "EAP Keys",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_EAP_STATUS_CODES: dict[int, str] = {
    0x00: "No authentication started",
    0x01: "Authentication started",
    0x02: "Authentication completed successfully",
    0x03: "Authentication failed",
}


def _decode_ef_eapstatus(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.EAPSTATUS (TS 102 310 §5.2.2 — single status octet)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    value = raw[0]
    return {
        "format": "EAP Status",
        "hex": raw.hex().upper(),
        "length": 1,
        "statusByte": f"0x{value:02X}",
        "statusLabel": _EAP_STATUS_CODES.get(
            int(value), f"Reserved/RFU (0x{value:02X})",
        ),
    }


_EF_REID_TAGS: dict[str, str] = {
    "80": "Re-authentication ID (UTF-8)",
}


def _decode_ef_reid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.REID (TS 102 310 §5.2.2 — EAP Re-authentication ID).

    Tag 0x80 is a UTF-8 Re-authentication ID per RFC 5216; declare the
    text decoder so the editor renders the identity directly.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_REID_TAGS,
        value_decoders={"80": _tlv_value_decoder_text},
    )
    return {
        "format": "EAP Re-authentication ID",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_model(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MODEL (3GPP2 C.S0023 §3.4.61 — ASCII device model)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    ascii_text = _decode_printable_ascii(raw.rstrip(b"\x00").rstrip(b"\xFF"))
    decoded: dict[str, object] = {
        "format": "Device Model",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "specReference": "3GPP2 C.S0023 §3.4.61",
    }
    if ascii_text not in (None, ""):
        decoded["model"] = ascii_text
        decoded["summary"] = f"model={ascii_text}"
    return decoded


def _decode_ef_call_count(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CALL-COUNT (3GPP2 C.S0023 §3.4.72).

    Two-byte big-endian call counter (upper bound 0xFFFF).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 2:
        return None
    count = int.from_bytes(raw, "big", signed=False)
    return {
        "format": "Call Count",
        "hex": raw.hex().upper(),
        "length": 2,
        "callCount": count,
        "specReference": "3GPP2 C.S0023 §3.4.72",
        "summary": f"callCount={count}",
    }


def _decode_ef_call_prompt(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CALL-PROMPT (3GPP2 C.S0023 §3.4.55).

    Single-byte flag: 0x01 enables call-prompt prompting, 0x00 disables.
    """

    return _decode_ef_single_bit_flag(
        hex_clean,
        format_name="Call Prompt",
        flag_name="callPromptEnabled",
        summary_true="Call prompt enabled",
        summary_false="Call prompt disabled",
    )


def _decode_ef_applabels(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.APPLABELS (3GPP2 C.S0023 §3.4.60)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="CSIM Application Labels",
        spec_reference="3GPP2 C.S0023 §3.4.60",
        summary_prefix="AppLabels",
    )


def _decode_ef_auth_capability(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.Auth-Capability (3GPP2 C.S0023 §3.4.51)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Authentication Capability",
        spec_reference="3GPP2 C.S0023 §3.4.51",
        summary_prefix="AuthCap",
    )


def _decode_ef_acp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ACP (3GPP2 C.S0023 §3.4.11 — Access Channel Params)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Access Channel Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.11",
        summary_prefix="ACP",
    )


def _decode_ef_atc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ATC (3GPP2 C.S0023 §3.4.14 — Access Terminal Class)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Access Terminal Class",
        spec_reference="3GPP2 C.S0023 §3.4.14",
        summary_prefix="ATC",
    )


def _decode_ef_namlock(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.NAMLOCK (3GPP2 C.S0065 — NAM Lock state)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="NAM Lock",
        spec_reference="3GPP2 C.S0065 §5.2.33",
        summary_prefix="NAMLOCK",
    )


def _decode_ef_usgind(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.USGIND (3GPP2 C.S0023 §3.4.67 — Usage Indicator)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Usage Indicator",
        spec_reference="3GPP2 C.S0023 §3.4.67",
        summary_prefix="UsgInd",
    )


def _decode_ef_dgc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.DGC (3GPP2 C.S0023 §3.4.57 — Data Generic Config)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Data Generic Configuration",
        spec_reference="3GPP2 C.S0023 §3.4.57",
        summary_prefix="DGC",
    )


def _decode_ef_term(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.TERM (3GPP2 C.S0023 §3.4.68 — Terminal Capability)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Terminal Capability (CSIM)",
        spec_reference="3GPP2 C.S0023 §3.4.68",
        summary_prefix="Term",
    )


def _decode_ef_hidden_key(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.Hidden-Key (3GPP2 C.S0023 §3.4.75)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Hidden Key",
        spec_reference="3GPP2 C.S0023 §3.4.75",
        summary_prefix="HiddenKey",
    )


def _decode_ef_csspr(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CSSPR (3GPP2 C.S0023 §3.4.37)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="CSSPR",
        spec_reference="3GPP2 C.S0023 §3.4.37",
        summary_prefix="CSSPR",
    )


def _decode_ef_rma(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.RMA (TS 31.102 — operator/vendor-specific RMA data)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Remote Management Application",
        spec_reference="TS 31.102 (vendor-specific RMA)",
        summary_prefix="RMA",
    )


# ---------------------------------------------------------------------------
# Wave D Pass B — CSIM MIP / SIP / BCSMS / 3GPD / WAP / OTA decoders.
#
# Coverage (20 EFs) — all CSIM-side structures whose layout is defined by
# 3GPP2 specs but whose inner layout is operator/device-specific. They are
# surfaced via :func:`_decode_spec_opaque_ef` which provides a formal
# "format + specReference + hex" triple so the TUI shows a semantic label
# (shadowing the generic opaque catalog) while preserving byte-exact
# roundtrip.

def _decode_ef_3gpdopm(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.3GPDOPM (3GPP2 C.S0023 §3.4.45)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="3GPD Operating Mode",
        spec_reference="3GPP2 C.S0023 §3.4.45",
        summary_prefix="3GPDOPM",
    )


def _decode_ef_3gpduppext(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.3GPDUPPExt (3GPP2 C.S0023 §3.4.77)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="3GPD UPP Extension",
        spec_reference="3GPP2 C.S0023 §3.4.77",
        summary_prefix="3GPDUPPExt",
    )


def _decode_ef_bcsmscfg(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.BCSMSCFG (3GPP2 C.S0023 §3.4.47)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Broadcast SMS Configuration",
        spec_reference="3GPP2 C.S0023 §3.4.47",
        summary_prefix="BCSMSCfg",
    )


def _decode_ef_bcsmsp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.BCSMSP (3GPP2 C.S0023 §3.4.48)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Broadcast SMS Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.48",
        summary_prefix="BCSMSP",
    )


def _decode_ef_bcsmspref(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.BCSMSPref (3GPP2 C.S0023 §3.4.49)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Broadcast SMS Preferences",
        spec_reference="3GPP2 C.S0023 §3.4.49",
        summary_prefix="BCSMSPref",
    )


def _decode_ef_bcsmstable(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.BCSMSTable (3GPP2 C.S0023 §3.4.50)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Broadcast SMS Table",
        spec_reference="3GPP2 C.S0023 §3.4.50",
        summary_prefix="BCSMSTable",
    )


def _decode_ef_me3gpdopc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ME3GPDOPC (3GPP2 C.S0023 §3.4.46)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="ME 3GPD Operating Capability",
        spec_reference="3GPP2 C.S0023 §3.4.46",
        summary_prefix="ME3GPDOPC",
    )


def _decode_ef_mecrp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MECRP (3GPP2 C.S0023 §3.4.63)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="ME-Specific Crypto",
        spec_reference="3GPP2 C.S0023 §3.4.63",
        summary_prefix="MECRP",
    )


def _decode_ef_mipflags(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MIPFlags (3GPP2 C.S0023 §3.4.27)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="MIP Flags",
        spec_reference="3GPP2 C.S0023 §3.4.27",
        summary_prefix="MIPFlags",
    )


def _decode_ef_mipsp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MIPSP (3GPP2 C.S0023 §3.4.28)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="MIP Status Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.28",
        summary_prefix="MIPSP",
    )


def _decode_ef_mipupp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MIPUPP (3GPP2 C.S0023 §3.4.29)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="MIP User Profile Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.29",
        summary_prefix="MIPUPP",
    )


def _decode_ef_sippapss(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SIPPAPSS (3GPP2 C.S0023 §3.4.31)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="SIP PAP Supplementary Services",
        spec_reference="3GPP2 C.S0023 §3.4.31",
        summary_prefix="SIPPAPSS",
    )


def _decode_ef_sipsp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SIPSP (3GPP2 C.S0023 §3.4.32)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="SIP Status Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.32",
        summary_prefix="SIPSP",
    )


def _decode_ef_sipupp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SIPUPP (3GPP2 C.S0023 §3.4.33)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="SIP User Profile Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.33",
        summary_prefix="SIPUPP",
    )


def _decode_ef_ota(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.OTA (3GPP2 C.S0023 §3.4.78 — OTA Parameters)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="OTA Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.78",
        summary_prefix="OTA",
    )


def _decode_ef_otapaspc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.OTAPASPC (3GPP2 C.S0023 §3.4.79)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="OTAPA Service Programming Code",
        spec_reference="3GPP2 C.S0023 §3.4.79",
        summary_prefix="OTAPASPC",
    )


def _decode_ef_sp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SP (3GPP2 C.S0023 §3.4.21 — Service Preferences)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Service Preferences",
        spec_reference="3GPP2 C.S0023 §3.4.21",
        summary_prefix="SP",
    )


def _decode_ef_tcpconfig(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.TCPCONFIG (3GPP2 C.S0023 §3.4.76)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="TCP Configuration",
        spec_reference="3GPP2 C.S0023 §3.4.76",
        summary_prefix="TCPConfig",
    )


def _decode_ef_wapbrowserbm(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.WAPBrowserBM (3GPP2 C.S0023 §3.4.73)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="WAP Browser Bookmarks",
        spec_reference="3GPP2 C.S0023 §3.4.73",
        summary_prefix="WAPBM",
    )


def _decode_ef_wapbrowsercp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.WAPBrowserCP (3GPP2 C.S0023 §3.4.74)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="WAP Browser Connection Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.74",
        summary_prefix="WAPCP",
    )


# ---------------------------------------------------------------------------
# Wave D Pass C — CSIM / 3GPP2 legacy analog + registration + PUZL/PRL/LCS.
#
# Final 19 opaque entries. Each one is promoted via
# :func:`_decode_spec_opaque_ef` because:
#
#   * the outer record layout is spec-fixed but,
#   * the inner interpretation is operator- or device-specific (no bit
#     decomposition is mandated by 3GPP2).
#
# Promotion gives the TUI a stable, spec-anchored label instead of the
# generic "Opaque ..." catalog fallback while preserving byte-exact
# roundtrip via the ``hex`` / ``length`` fields.

def _decode_ef_ah(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.AH (3GPP2 C.S0023 §3.4.4 — Analog Home)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Analog Home",
        spec_reference="3GPP2 C.S0023 §3.4.4",
        summary_prefix="AH",
    )


def _decode_ef_aloc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ALOC (3GPP2 C.S0023 §3.4.5 — Analog Location)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Analog Location",
        spec_reference="3GPP2 C.S0023 §3.4.5",
        summary_prefix="ALOC",
    )


def _decode_ef_aop(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.AOP (3GPP2 C.S0023 §3.4.6)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Analog Operational Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.6",
        summary_prefix="AOP",
    )


def _decode_ef_bakpara(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.BAKPARA (3GPP2 C.S0023 §3.4.53 — BAK Parameters)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="BAK Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.53",
        summary_prefix="BAKPARA",
    )


def _decode_ef_cdmacnl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CDMACNL (3GPP2 C.S0023 §3.4.17)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="CDMA Co-operative Network List",
        spec_reference="3GPP2 C.S0023 §3.4.17",
        summary_prefix="CDMACNL",
    )


def _decode_ef_distregi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.DISTREGI (3GPP2 C.S0023 §3.4.16)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Distance-based Registration",
        spec_reference="3GPP2 C.S0023 §3.4.16",
        summary_prefix="DistRegi",
    )


def _decode_ef_jdl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.JDL (3GPP2 C.S0023 §3.4.64 — Java Download List)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Java Download List",
        spec_reference="3GPP2 C.S0023 §3.4.64",
        summary_prefix="JDL",
    )


def _decode_ef_lcscp(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.LCSCP (3GPP2 C.S0023 §3.4.65 — LCS Client Profile)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="LCS Client Profile",
        spec_reference="3GPP2 C.S0023 §3.4.65",
        summary_prefix="LCSCP",
    )


def _decode_ef_lcsver(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.LCSVER (3GPP2 C.S0023 §3.4.66 — LCS Version)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="LCS Version",
        spec_reference="3GPP2 C.S0023 §3.4.66",
        summary_prefix="LCSVER",
    )


def _decode_ef_max_prl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MaxPRL (3GPP2 C.S0023 §3.4.22 — Maximum PRL)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Maximum PRL",
        spec_reference="3GPP2 C.S0023 §3.4.22",
        summary_prefix="MaxPRL",
    )


def _decode_ef_maxpuzl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MaxPUZL (3GPP2 C.S0023 §3.4.42 — Maximum PUZL)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Maximum PUZL",
        spec_reference="3GPP2 C.S0023 §3.4.42",
        summary_prefix="MaxPUZL",
    )


def _decode_ef_puzl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PUZL (3GPP2 C.S0023 §3.4.41)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Preferred User Zone List",
        spec_reference="3GPP2 C.S0023 §3.4.41",
        summary_prefix="PUZL",
    )


def _decode_ef_rc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.RC (3GPP2 C.S0023 §3.4.44 — Root Certificate)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Root Certificate",
        spec_reference="3GPP2 C.S0023 §3.4.44",
        summary_prefix="RC",
    )


def _decode_ef_snregi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SNREGI (3GPP2 C.S0023 §3.4.15)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="SID/NID-based Registration",
        spec_reference="3GPP2 C.S0023 §3.4.15",
        summary_prefix="SNREGI",
    )


def _decode_ef_spcs(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SPCS (3GPP2 C.S0023 §3.4.25 — SPC Status)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="SPC Status",
        spec_reference="3GPP2 C.S0023 §3.4.25",
        summary_prefix="SPCS",
    )


def _decode_ef_ssci(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SSCI (3GPP2 C.S0023 §3.4.38)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Short Message Service Call Indicator",
        spec_reference="3GPP2 C.S0023 §3.4.38",
        summary_prefix="SSCI",
    )


def _decode_ef_ssfc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SSFC (3GPP2 C.S0023 §3.4.39)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="SS Feature Code",
        spec_reference="3GPP2 C.S0023 §3.4.39",
        summary_prefix="SSFC",
    )


def _decode_ef_upbakpara(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.UPBAKPARA (3GPP2 C.S0023 §3.4.54)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Updated BAK Parameters",
        spec_reference="3GPP2 C.S0023 §3.4.54",
        summary_prefix="UPBAKPARA",
    )


def _decode_ef_znregi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ZNREGI (3GPP2 C.S0023 §3.4.18 — Zone-based Registration)."""

    return _decode_spec_opaque_ef(
        hex_clean,
        format_name="Zone-based Registration",
        spec_reference="3GPP2 C.S0023 §3.4.18",
        summary_prefix="ZNREGI",
    )


def _decode_spec_opaque_ef(
    hex_clean: str,
    *,
    format_name: str,
    spec_reference: str,
    summary_prefix: str | None = None,
) -> dict[str, object] | None:
    """Pass-through decoder for EFs whose inner layout is left opaque by spec.

    Identical to ``_decode_opaque_ef`` but annotated with the formal
    specification citation so operators see that the format is opaque
    by design rather than "not yet decoded".

    The payload is surfaced as raw hex plus a length-based summary.
    Opportunistic ASCII previews are intentionally NOT emitted: these
    EFs are defined as opaque by their respective specifications and
    any printable-byte rendering would be context-blind fluff.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
        "specReference": spec_reference,
    }
    if summary_prefix is not None:
        decoded["summary"] = f"{summary_prefix} ({len(raw)} bytes)"
    else:
        decoded["summary"] = raw.hex().upper()
    return decoded


_URI_SCHEME_RE = re.compile(r"^([a-zA-Z][a-zA-Z0-9+\-.]*):")
_URI_AUTHORITY_RE = re.compile(
    r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+\-.]*)://"
    r"(?:(?P<userinfo>[^@/?#]*)@)?"
    r"(?P<host>\[[^\]]+\]|[^:/?#]+)"
    r"(?::(?P<port>[0-9]+))?"
    r"(?P<path>/[^?#]*)?"
    r"(?:\?(?P<query>[^#]*))?"
    r"(?:#(?P<fragment>.*))?$"
)
# ``tel:`` / ``sip:`` / ``sips:`` / ``urn:`` do not use the ``//`` authority
# separator; we still extract the opaque part for operator diagnostics.
_URI_OPAQUE_RE = re.compile(
    r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+\-.]*):(?P<opaque>[^#?]*)"
    r"(?:\?(?P<query>[^#]*))?(?:#(?P<fragment>.*))?$"
)


def _classify_uri_text(uri_text: str) -> dict[str, object]:
    """Best-effort RFC 3986 split of a URI string.

    Surfaces ``scheme``, ``authority`` components (userinfo / host / port)
    or the ``opaque`` part for non-authority schemes (``tel:``, ``sip:``,
    ``urn:``). If the string does not match the spec-compliant grammar we
    still record ``rfc3986Compliant: False`` so the edit-decoded TUI can
    highlight malformed URIs rather than silently rendering them as text.
    """

    fields: dict[str, object] = {}
    scheme_match = _URI_SCHEME_RE.match(uri_text)
    if scheme_match is None:
        fields["rfc3986Compliant"] = False
        return fields
    scheme_lower = scheme_match.group(1).lower()
    fields["scheme"] = scheme_lower
    authority_match = _URI_AUTHORITY_RE.match(uri_text)
    if authority_match is not None:
        userinfo = authority_match.group("userinfo")
        host = authority_match.group("host") or ""
        port = authority_match.group("port")
        path = authority_match.group("path") or ""
        query = authority_match.group("query")
        fragment = authority_match.group("fragment")
        fields["host"] = host
        if userinfo is not None:
            fields["userinfo"] = userinfo
        if port is not None:
            fields["port"] = int(port)
        if path != "":
            fields["path"] = path
        if query is not None:
            fields["query"] = query
        if fragment is not None:
            fields["fragment"] = fragment
        fields["rfc3986Compliant"] = True
    else:
        opaque_match = _URI_OPAQUE_RE.match(uri_text)
        if opaque_match is not None:
            opaque = opaque_match.group("opaque") or ""
            query = opaque_match.group("query")
            fragment = opaque_match.group("fragment")
            fields["opaque"] = opaque
            if query is not None:
                fields["query"] = query
            if fragment is not None:
                fields["fragment"] = fragment
            fields["rfc3986Compliant"] = True
        else:
            fields["rfc3986Compliant"] = False
    if "%" in uri_text:
        try:
            from urllib.parse import unquote

            fields["percentDecoded"] = unquote(uri_text)
        except Exception:  # pragma: no cover - defensive
            pass
    return fields


def _decode_uri_record(
    hex_clean: str,
    *,
    format_name: str,
    spec_reference: str | None = None,
) -> dict[str, object] | None:
    """Decode an 80-tagged UTF-8 URI record (EF.FDN_URI / SDN_URI / LND_URI /
    EHURI / TN3GPPSNN / similar).

    Per TS 31.102 §4.2.71 and cross-referenced EFs, the payload is a single
    BER-TLV ``80 LL <utf-8 bytes>`` record. Round-4 Pass 2 adds RFC 3986
    decomposition (scheme / authority / path / query / fragment) and
    percent-decoding so the edit-decoded TUI can validate URI payloads
    instead of displaying them as opaque text.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": raw.hex().upper(),
        "length": len(raw),
    }
    if spec_reference is not None:
        decoded["reference"] = spec_reference
    if raw[0] == 0x80 and len(raw) >= 2:
        uri_length = raw[1]
        if 2 + uri_length <= len(raw):
            try:
                uri_text = raw[2 : 2 + uri_length].decode("utf-8")
            except UnicodeDecodeError:
                uri_text = ""
            if uri_text != "":
                decoded["uri"] = uri_text
                decoded["summary"] = uri_text
                decoded.update(_classify_uri_text(uri_text))
                return decoded
    decoded["summary"] = raw.hex().upper()
    return decoded


def _decode_mwis_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MWIS (TS 31.102 §4.2.62). A record is 5 bytes:
    indication byte (voicemail/fax/email/other bitmap) + 4 counters.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 5:
        return None
    indicator = raw[0]
    return {
        "format": "Message Waiting Indication Status",
        "hex": raw.hex().upper(),
        "indicatorByte": f"0x{indicator:02X}",
        "voicemailWaiting": bool(indicator & 0x01),
        "faxWaiting": bool(indicator & 0x02),
        "emailWaiting": bool(indicator & 0x04),
        "otherWaiting": bool(indicator & 0x08),
        "voicemailCount": int(raw[1]),
        "faxCount": int(raw[2]),
        "emailCount": int(raw[3]),
        "otherCount": int(raw[4]),
    }


def _decode_mbi_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MBI (TS 31.102 §4.2.61). Each record is a profile of
    mailbox identifiers — typically 4 bytes (voicemail / fax / email / other).
    Expose the raw bytes plus each slot.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    slot_names = ("voicemail", "fax", "email", "other")
    slots: dict[str, int] = {}
    for index, byte_value in enumerate(raw):
        slot_name = slot_names[index] if index < len(slot_names) else f"slot{index}"
        slots[slot_name] = int(byte_value)
    return {
        "format": "Mailbox Identifier",
        "hex": raw.hex().upper(),
        "slots": slots,
        "summary": ",".join(f"{k}={v}" for k, v in slots.items()),
    }


def _decode_cfis_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CFIS (TS 31.102 §4.2.64). Record shape is 16 bytes:
    MSP_number(1) + CF_indication(1) + alpha-id segment + dialling number.
    The TS defines the layout in detail; we keep the first two bytes as
    semantic fields and expose the rest as ``tailHex`` for round-trip.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 2:
        return None
    msp = raw[0]
    indicator = raw[1]
    return {
        "format": "Call Forwarding Indication Status",
        "hex": raw.hex().upper(),
        "mspNumber": int(msp),
        "cfIndicator": f"0x{indicator:02X}",
        "voiceForwardActive": bool(indicator & 0x01),
        "faxForwardActive": bool(indicator & 0x02),
        "dataForwardActive": bool(indicator & 0x04),
        "smsForwardActive": bool(indicator & 0x08),
        "tailHex": raw[2:].hex().upper(),
    }


def _decode_emlpp_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.eMLPP (TS 31.102 §4.2.76). 2 bytes: supported priority
    levels bitmap + fast-call-setup priority level bitmap. Some profiles
    pad with a reserved byte.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 2:
        return None
    supported = raw[0]
    fast_cs = raw[1]
    supported_levels = [i for i in range(8) if (supported >> i) & 0x01]
    fast_levels = [i for i in range(8) if (fast_cs >> i) & 0x01]
    decoded: dict[str, object] = {
        "format": "eMLPP Priority Information",
        "hex": raw.hex().upper(),
        "supportedPriorityLevels": supported_levels,
        "fastCallSetupLevels": fast_levels,
    }
    if len(raw) > 2:
        decoded["trailerHex"] = raw[2:].hex().upper()
    return decoded


def _decode_aaem_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.AAeM (TS 31.102 §4.2.77). 1 byte bitmap: for each
    priority level, a bit indicating whether automatic answer is enabled.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    byte_value = raw[0]
    enabled = [i for i in range(8) if (byte_value >> i) & 0x01]
    decoded: dict[str, object] = {
        "format": "Automatic Answer for eMLPP",
        "hex": raw.hex().upper(),
        "aaEnabledLevels": enabled,
    }
    if len(raw) > 1:
        decoded["trailerHex"] = raw[1:].hex().upper()
    return decoded


def _decode_dck_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.DCK (TS 31.102 §4.2.71). 16 bytes = 4 × 4-byte
    depersonalization control keys (network / network subset / SP / corporate).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 16:
        return None
    return {
        "format": "Depersonalization Control Keys",
        "hex": raw.hex().upper(),
        "networkKey": raw[0:4].hex().upper(),
        "networkSubsetKey": raw[4:8].hex().upper(),
        "serviceProviderKey": raw[8:12].hex().upper(),
        "corporateKey": raw[12:16].hex().upper(),
    }


_LOCIGPRS_RAU_STATUS: dict[int, str] = {
    0: "updated",
    1: "not_updated",
    2: "plmn_not_allowed",
    3: "routing_area_not_allowed",
}


def _decode_ef_locigprs(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.LOCIGPRS (TS 51.011 §10.3.33 / TS 31.102 §4.2.23).

    14 bytes: PTMSI (4) || PTMSI signature (3) || RAI (6) || RAU status (1 enum).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 14:
        return None
    rai = raw[7:13]
    plmn_hex = rai[0:3].hex().upper()
    rau_status = raw[13]
    return {
        "format": "GPRS Location Information",
        "reference": "TS 51.011 §10.3.33",
        "hex": raw.hex().upper(),
        "ptmsi": raw[0:4].hex().upper(),
        "ptmsiSignature": raw[4:7].hex().upper(),
        "rai": {
            "hex": rai.hex().upper(),
            "plmn": _decode_plmn_hex(plmn_hex),
            "lac": rai[3:5].hex().upper(),
            "rac": rai[5:6].hex().upper(),
        },
        "rauStatus": {
            "value": rau_status,
            "name": _LOCIGPRS_RAU_STATUS.get(rau_status, f"reserved_0x{rau_status:02X}"),
        },
    }


def _decode_ef_cnl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CNL (TS 51.011 §10.3.30).

    Linear-fixed records of 6 bytes: PLMN (3) || network subset (1)
    || service provider id (1) || corporate id (1).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or len(raw) % 6 != 0:
        return None
    records: list[dict[str, object]] = []
    for offset in range(0, len(raw), 6):
        chunk = raw[offset : offset + 6]
        plmn_hex = chunk[0:3].hex().upper()
        records.append({
            "hex": chunk.hex().upper(),
            "plmn": _decode_plmn_hex(plmn_hex),
            "networkSubset": chunk[3],
            "serviceProviderId": chunk[4],
            "corporateId": chunk[5],
        })
    return {
        "format": "Co-operative Network List",
        "reference": "TS 51.011 §10.3.30",
        "hex": raw.hex().upper(),
        "records": records,
    }


def _decode_vgcs_vbs_subscription(hex_clean: str, *, format_name: str) -> dict[str, object] | None:
    """Decode EF.VGCS / EF.VBS (TS 51.011 §10.3.20 / §10.3.22).

    Transparent-record file, 4-byte records containing the right-padded
    BCD Group Identifier. A value of 0xFFFFFFFF flags a free slot.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or len(raw) % 4 != 0:
        return None
    records: list[dict[str, object]] = []
    for offset in range(0, len(raw), 4):
        chunk = raw[offset : offset + 4]
        if chunk == b"\xff\xff\xff\xff":
            records.append({
                "hex": "FFFFFFFF",
                "gid": None,
                "free": True,
            })
            continue
        digits = []
        for byte in chunk:
            low = byte & 0x0F
            high = (byte >> 4) & 0x0F
            if low == 0x0F:
                break
            digits.append(str(low))
            if high == 0x0F:
                break
            digits.append(str(high))
        records.append({
            "hex": chunk.hex().upper(),
            "gid": "".join(digits) or None,
            "free": False,
        })
    return {
        "format": format_name,
        "reference": "TS 51.011 §10.3.20/§10.3.22",
        "hex": raw.hex().upper(),
        "records": records,
    }


def _decode_ef_psc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PSC (TS 31.102 §4.4.2.12.2). 4-byte big-endian sync counter."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 4:
        return None
    return {
        "format": "Phonebook Synchronization Counter",
        "reference": "TS 31.102 §4.4.2.12.2",
        "hex": raw.hex().upper(),
        "synceCounter": int.from_bytes(raw, "big"),
    }


def _decode_ef_cc_counter(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CC (TS 31.102 §4.4.2.12.3). 2-byte big-endian change counter."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 2:
        return None
    return {
        "format": "Phonebook Change Counter",
        "reference": "TS 31.102 §4.4.2.12.3",
        "hex": raw.hex().upper(),
        "changeCounter": int.from_bytes(raw, "big"),
    }


def _decode_ef_puid(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PUID (TS 31.102 §4.4.2.12.4). 2-byte big-endian previous UID."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 2:
        return None
    return {
        "format": "Previous UID",
        "reference": "TS 31.102 §4.4.2.12.4",
        "hex": raw.hex().upper(),
        "previousUid": int.from_bytes(raw, "big"),
    }


# ---------------------------------------------------------------------------
# Round-2 Pass 1 — phonebook administrative + auxiliary EFs.
#
# These records all originate from DF.PHONEBOOK (TS 31.102 §4.4.2). Their
# shapes are dictated by EF.PBR and are profile-dependent in their exact
# widths, so the decoders validate the byte-level structure and surface a
# typed view without re-asserting width constraints the PBR already owns.
# ---------------------------------------------------------------------------


def _decode_ef_iap_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.IAP (TS 31.102 §4.4.2.2) — Index Administration Phonebook.

    Each record is a sequence of record-pointer bytes, one byte per Type1
    file referenced from EF.PBR. ``0xFF`` indicates "no entry", any other
    value is a 1-based record number in the paired Type1 EF.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    pointers: list[dict[str, object]] = []
    for idx, byte in enumerate(raw):
        pointers.append({
            "slot": idx,
            "hex": f"{byte:02X}",
            "recordNumber": None if byte == 0xFF else int(byte),
        })
    return {
        "format": "Index Administration Phonebook",
        "reference": "TS 31.102 §4.4.2.2",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "pointers": pointers,
    }


def _decode_ef_sne_record(
    hex_clean: str, *, format_name: str = "Second Name Entry"
) -> dict[str, object] | None:
    """Decode EF.SNE / SNEA / SNEB (TS 31.102 §4.4.2.10).

    Type 2 second-name entries carry an alpha string only. Unused bytes
    are ``0xFF`` per TS 31.102 Annex A; the field width is fixed by
    EF.PBR and is not re-asserted here.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    alpha = _decode_alpha_string_bytes(raw)
    return {
        "format": format_name,
        "reference": "TS 31.102 §4.4.2.10",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "alpha": alpha,
    }


def _decode_ef_email_record(
    hex_clean: str, *, format_name: str = "EMAIL"
) -> dict[str, object] | None:
    """Decode EF.EMAIL / EMAILB (TS 31.102 §4.4.2.13).

    Type 2 email records carry an ASCII/UTF-8 encoded address with
    trailing ``0xFF`` padding. An optional trailing ADN record pointer
    (1 byte) is carried when EF.PBR declares the file as Type 1.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    trimmed = raw.rstrip(b"\xff")
    text = ""
    encoding = "ascii"
    if len(trimmed) > 0:
        try:
            text = trimmed.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            text_candidate = _decode_printable_ascii(trimmed)
            if text_candidate is not None:
                text = text_candidate
                encoding = "ascii"
            else:
                text = ""
                encoding = "unknown"
    return {
        "format": format_name,
        "reference": "TS 31.102 §4.4.2.13",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "encoding": encoding,
        "email": text,
    }


def _decode_ef_gas_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.GAS (TS 31.102 §4.4.2.15) — Grouping Alpha String."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    alpha = _decode_alpha_string_bytes(raw)
    return {
        "format": "Grouping Alpha String",
        "reference": "TS 31.102 §4.4.2.15",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "alpha": alpha,
    }


def _decode_ef_grp_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.GRP (TS 31.102 §4.4.2.3) — Phonebook Groups.

    Each record maps one ADN entry to up to ``N`` GAS group IDs (``N``
    fixed by EF.PBR). Each byte holds a 1-based GAS record reference or
    ``0xFF`` when the slot is unused.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    slots: list[dict[str, object]] = []
    for idx, byte in enumerate(raw):
        slots.append({
            "slot": idx,
            "hex": f"{byte:02X}",
            "gasRecord": None if byte == 0xFF else int(byte),
        })
    assigned = [slot["gasRecord"] for slot in slots if slot["gasRecord"] is not None]
    return {
        "format": "Phonebook Groups",
        "reference": "TS 31.102 §4.4.2.3",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "slots": slots,
        "assignedGroups": assigned,
    }


def _decode_ef_anl_record(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.ANL (TS 31.102 §4.2.85) — Aggregated Name List.

    Linear-fixed alpha-string records; PBR owns the width. Used as a
    shared name pool for other phonebook references.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    alpha = _decode_alpha_string_bytes(raw)
    return {
        "format": "Aggregated Name List",
        "reference": "TS 31.102 §4.2.85",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "alpha": alpha,
    }


# ---------------------------------------------------------------------------
# Round-2 Pass 1 — legacy GSM / broadcast EFs.
# ---------------------------------------------------------------------------


def _decode_ef_bcch(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.BCCH (TS 51.011 §10.3.25).

    16 transparent octets. Each of the 128 bits maps to a BA (BCCH
    Allocation) list entry. Bit ordering follows TS 51.011: byte 1 bit
    8 is BA index 1.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 16:
        return None
    ba_indexes: list[int] = []
    for byte_index, byte in enumerate(raw):
        for bit in range(7, -1, -1):
            if byte & (1 << bit):
                ba = byte_index * 8 + (8 - bit)
                ba_indexes.append(ba)
    return {
        "format": "Broadcast Control Channel",
        "reference": "TS 51.011 §10.3.25",
        "hex": raw.hex().upper(),
        "length": 16,
        "baListBitCount": len(ba_indexes),
        "baIndexes": ba_indexes,
    }


# ---------------------------------------------------------------------------
# Round-2 Pass 1 — ISIM / GBA / CSG helpers.
# ---------------------------------------------------------------------------


_EF_NAFKCA_LIST_TAGS: dict[str, str] = {
    "80": "NAF Key Centre Address (FQDN)",
    "81": "NAF Key Centre Address (IP)",
    "A0": "NAF Key Centre Entry",
}


def _decode_nafkca_entry_value(payload: bytes) -> dict[str, object]:
    if len(payload) == 0:
        return {"hex": payload.hex().upper()}
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return {"hex": payload.hex().upper()}
    return {"hex": payload.hex().upper(), "fqdn": text}


def _decode_ef_nafkca_list(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.NAFKCA-List (TS 31.102 §4.2.91) — NAF Key Centre List."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_NAFKCA_LIST_TAGS,
        value_decoders={"80": _decode_nafkca_entry_value},
    )
    return {
        "format": "NAF Key Centre List",
        "reference": "TS 31.102 §4.2.91",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_forbidden_csg_value(payload: bytes) -> dict[str, object]:
    if len(payload) < 3:
        return {"hex": payload.hex().upper()}
    plmn_hex = payload[0:3].hex().upper()
    decoded = {
        "hex": payload.hex().upper(),
        "plmn": _decode_plmn_hex(plmn_hex),
    }
    if len(payload) >= 7:
        csg_id = int.from_bytes(payload[3:7], "big")
        decoded["csgId"] = csg_id
    return decoded


def _decode_ef_fcsl(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.FCSL / EF.FCSGL (TS 31.102 §4.2.73) — Forbidden CSG List."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "Forbidden CSG Entry"},
        value_decoders={"80": _decode_forbidden_csg_value},
    )
    return {
        "format": "Forbidden CSG List",
        "reference": "TS 31.102 §4.2.73",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_phist(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PHist (TS 31.102 §4.2.94) — Provider Host List.

    BER-TLV stream; tag ``80`` carries UTF-8 host FQDN entries.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "Provider Host"},
        value_decoders={"80": _decode_nafkca_entry_value},
    )
    return {
        "format": "Provider Host List",
        "reference": "TS 31.102 §4.2.94",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


# ---------------------------------------------------------------------------
# Round-2 Pass 1 — mailbox, SMSC, MExE service table.
# ---------------------------------------------------------------------------


def _decode_ef_mbparam(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MBParam (TS 31.102 §4.2.70) — Mailbox Parameters.

    Variable-length transparent file composed of a 1-byte type byte
    followed by a mailbox identifier string (UTF-8 or ASCII). Trailing
    ``0xFF`` bytes are treated as padding.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    type_byte = raw[0]
    tail = raw[1:].rstrip(b"\xff")
    text = ""
    encoding = "ascii"
    if len(tail) > 0:
        try:
            text = tail.decode("utf-8")
            encoding = "utf-8"
        except UnicodeDecodeError:
            fallback = _decode_printable_ascii(tail)
            if fallback is not None:
                text = fallback
                encoding = "ascii"
            else:
                text = ""
                encoding = "unknown"
    return {
        "format": "Mailbox Parameters",
        "reference": "TS 31.102 §4.2.70",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "typeByte": f"0x{type_byte:02X}",
        "identifier": text,
        "encoding": encoding,
    }


def _decode_ef_psismsc(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PSISMSC (TS 31.103 §4.2.18) — Public Service Identity SMSC.

    BER-TLV stream carrying SIP URI entries (tag ``80``, UTF-8) for the
    SMSC associated with the IMPI/IMPU.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "Public Service Identity SMSC"},
        value_decoders={"80": _decode_nafkca_entry_value},
    )
    return {
        "format": "Public Service Identity SMSC",
        "reference": "TS 31.103 §4.2.18",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_MEXE_ST_SERVICE_NAMES: dict[int, str] = {
    1: "Discretionary Security",
    2: "MExE CCM File Auxiliary",
    3: "Operator Root CA Storage",
    4: "Administrator Root CA Storage",
    5: "Third-party Root CA Storage",
    6: "Trusted Third Party Root CA Storage",
}


def _decode_ef_mexe_st(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.MExE-ST (TS 31.102 §4.4.10.1) — MExE Service Table.

    Packed bit-map (service N at byte ``(N-1)//8`` bit ``(N-1)%8``).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    enabled: list[dict[str, object]] = []
    for byte_index, byte in enumerate(raw):
        for bit in range(8):
            if byte & (1 << bit):
                service_num = byte_index * 8 + bit + 1
                enabled.append({
                    "service": service_num,
                    "name": _MEXE_ST_SERVICE_NAMES.get(
                        service_num, f"service_{service_num}"
                    ),
                })
    return {
        "format": "MExE Service Table",
        "reference": "TS 31.102 §4.4.10.1",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "enabledServices": enabled,
    }


# ---------------------------------------------------------------------------
# Round-2 Pass 1 — operator / vendor control primitives.
# ---------------------------------------------------------------------------


def _decode_ef_scp80_counter(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SCP80 Counter — 3-byte big-endian counter (ETSI TS 102 225)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 3:
        return None
    return {
        "format": "SCP80 Counter",
        "reference": "ETSI TS 102 225 §5.1.1",
        "hex": raw.hex().upper(),
        "length": 3,
        "counter": int.from_bytes(raw, "big"),
    }


_SIM_LOCK_STATES: dict[int, str] = {
    0x00: "unlocked",
    0x01: "locked",
    0x02: "personalised",
    0xFF: "not set",
}


def _decode_ef_simlock_state(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SIM Lock State — 1-byte enum."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    byte = raw[0]
    return {
        "format": "SIM Lock State",
        "hex": raw.hex().upper(),
        "length": 1,
        "stateByte": f"0x{byte:02X}",
        "state": _SIM_LOCK_STATES.get(byte, f"reserved_0x{byte:02X}"),
    }


_OTA_STATES: dict[int, str] = {
    0x00: "idle",
    0x01: "pending",
    0x02: "in-progress",
    0x03: "completed",
    0x04: "failed",
    0xFF: "not set",
}


def _decode_ef_ota_state(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.OTA State — 1-byte enum (operator convention)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    byte = raw[0]
    return {
        "format": "OTA State",
        "hex": raw.hex().upper(),
        "length": 1,
        "stateByte": f"0x{byte:02X}",
        "state": _OTA_STATES.get(byte, f"reserved_0x{byte:02X}"),
    }


_OTA_KEY_TAGS: dict[str, str] = {
    "80": "KIC",
    "81": "KID",
    "82": "KIK",
    "83": "Counter",
    "84": "Key Reference",
}


def _decode_ef_ota_keys(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.OTA Keys — BER-TLV keyset (ETSI TS 102 225/226)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(raw, tag_names=_OTA_KEY_TAGS)
    return {
        "format": "OTA Keys",
        "reference": "ETSI TS 102 225/226",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


_SCP11_KEY_TAGS: dict[str, str] = {
    "80": "Key Version Number",
    "81": "Key Type",
    "82": "Key Length",
    "83": "Key Reference",
    "84": "Key Value",
    "A6": "Key Parameter",
}


def _decode_ef_scp11_key(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SCP11 Key — BER-TLV key reference (GlobalPlatform Amd.F)."""

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(raw, tag_names=_SCP11_KEY_TAGS)
    return {
        "format": "SCP11 Key",
        "reference": "GlobalPlatform Amd.F",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_setup_menu_elements(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.SetUp Menu Elements (ETSI TS 102 223 / TS 31.111 §5.4.1).

    BER-TLV proactive "SET UP MENU" payload. Top-level COMPREHENSION-TLV
    tags (``85`` Alpha Identifier, ``8F`` Item, ``9E`` Icon Identifier,
    ``17`` Item Text Attribute List) are typed; unknown tags pass
    through raw.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    tag_names = {
        "85": "Alpha Identifier",
        "8F": "Item",
        "9E": "Icon Identifier",
        "17": "Item Text Attribute List",
        "18": "Item Icon Identifier List",
        "19": "Next Action Indicator",
    }
    items = _decode_field_ber_tlv_stream(raw, tag_names=tag_names)
    return {
        "format": "SetUp Menu Elements",
        "reference": "ETSI TS 102 223 §6.6.7 / TS 31.111 §5.4.1",
        "hex": raw.hex().upper(),
        "length": len(raw),
        "items": items,
    }


def _decode_ef_5gauthkeys(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.5GAUTHKEYS (TS 31.102 §4.4.11.6).

    BER-TLV stream with tag 80 (K_AUSF) and 81 (K_SEAF), each carrying
    greedy key bytes.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names={"80": "K_AUSF", "81": "K_SEAF"},
    )
    return {
        "format": "5G Authentication Keys",
        "reference": "TS 31.102 §4.4.11.6",
        "hex": raw.hex().upper(),
        "items": items,
    }


_EF_5GS3GPPNSC_TAGS: dict[str, str] = {
    "A0": "5GS NAS Security Context",
    "80": "ngKSI",
    "81": "K_AMF",
    "82": "Uplink NAS Count",
    "83": "Downlink NAS Count",
    "84": "Selected NAS Algorithms",
    "85": "Selected EPS Algorithms",
}


def _decode_ef_5gs3gpp_nsc(hex_clean: str, *, format_name: str) -> dict[str, object] | None:
    """Decode EF.5GS3GPPNSC / EF.5GSN3GPPNSC (TS 31.102 §4.4.11.4/§4.4.11.5).

    Linear-fixed records. Each record is an ``A0`` constructed BER-TLV
    wrapping nested primitive tags ``80..85``. ``80`` is a single-byte
    ngKSI; ``81`` is a 32-byte K_AMF; ``82`` / ``83`` are 4-byte NAS
    counters; ``84`` / ``85`` are nibble pairs (ciphering / integrity).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None

    def _decode_ngksi(payload: bytes) -> dict[str, object]:
        if len(payload) == 1:
            return {"hex": payload.hex().upper(), "ngKSI": payload[0]}
        return {"hex": payload.hex().upper()}

    def _decode_nas_count(payload: bytes) -> dict[str, object]:
        if len(payload) == 4:
            return {"hex": payload.hex().upper(), "count": int.from_bytes(payload, "big")}
        return {"hex": payload.hex().upper()}

    def _decode_algo_pair(payload: bytes) -> dict[str, object]:
        if len(payload) == 1:
            byte = payload[0]
            return {
                "hex": payload.hex().upper(),
                "ciphering": (byte >> 4) & 0x0F,
                "integrity": byte & 0x0F,
            }
        return {"hex": payload.hex().upper()}

    value_decoders: dict[str, ValueDecoder] = {
        "80": _decode_ngksi,
        "82": _decode_nas_count,
        "83": _decode_nas_count,
        "84": _decode_algo_pair,
        "85": _decode_algo_pair,
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_5GS3GPPNSC_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": format_name,
        "reference": "TS 31.102 §4.4.11.4/§4.4.11.5",
        "hex": raw.hex().upper(),
        "items": items,
    }


_EF_EARFCN_LIST_TAGS: dict[str, str] = {
    "A0": "EARFCN List Entry",
    "80": "EARFCN",
    "81": "Geographical Area",
    "90": "GAD Point",
}


def _decode_ef_earfcn_list(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.EARFCNList (TS 31.102 §4.2.112).

    Sequence of ``A0`` wrappers; each entry carries one ``80`` EARFCN
    (Int32ub) and one or more ``81`` geographical-area blocks. Each area
    is a concatenation of 6-byte GAD points (lat/lon as Int24 signed).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None

    def _decode_earfcn(payload: bytes) -> dict[str, object]:
        if len(payload) == 4:
            return {"hex": payload.hex().upper(), "earfcn": int.from_bytes(payload, "big")}
        return {"hex": payload.hex().upper()}

    def _decode_area(payload: bytes) -> dict[str, object]:
        if len(payload) == 0 or len(payload) % 6 != 0:
            return {"hex": payload.hex().upper()}
        points: list[dict[str, int]] = []
        for offset in range(0, len(payload), 6):
            chunk = payload[offset : offset + 6]
            lat = int.from_bytes(chunk[0:3], "big", signed=True)
            lon = int.from_bytes(chunk[3:6], "big", signed=True)
            points.append({"latitude": lat, "longitude": lon})
        return {"hex": payload.hex().upper(), "points": points}

    value_decoders: dict[str, ValueDecoder] = {
        "80": _decode_earfcn,
        "81": _decode_area,
    }
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=_EF_EARFCN_LIST_TAGS,
        value_decoders=value_decoders,
    )
    return {
        "format": "EARFCN List",
        "reference": "TS 31.102 §4.2.112",
        "hex": raw.hex().upper(),
        "items": items,
    }


def _decode_ef_cmi(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.CMI (TS 51.011 §10.5.16).

    Linear-fixed record. Each record is ``<alpha_id:N-1>|<comparison_method_id:1>``
    where the alpha identifier is GSM 03.38 7-bit right-padded. The
    record length comes from the transparent record boundary; we cannot
    infer the record length from a single payload so we split the trailer
    (last byte) as ``comparisonMethodId`` and the remainder as alpha id.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 2:
        return None
    alpha_id = raw[:-1]
    cmid = raw[-1]
    alpha = _decode_alpha_string_bytes(alpha_id.rstrip(b"\xff"))
    return {
        "format": "Comparison Method Information",
        "reference": "TS 51.011 §10.5.16",
        "hex": raw.hex().upper(),
        "alphaId": {
            "hex": alpha_id.hex().upper(),
            "text": alpha,
        },
        "comparisonMethodId": cmid,
    }


def _decode_vgcss_vbss_status(hex_clean: str, *, format_name: str) -> dict[str, object] | None:
    """Decode EF.VGCSS / EF.VBSS (TS 51.011 §10.3.21 / §10.3.23).

    7-byte transparent file. 50 service-indicator flags packed in the
    first 6 bytes and a half of the seventh; the remaining bits are
    reserved (0xFF).
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 7:
        return None
    flags: list[int] = []
    for byte in raw:
        bits_lsb_first = [(byte >> bit) & 0x01 for bit in range(8)]
        flags.extend(bits_lsb_first)
    subscription_flags = flags[:50]
    return {
        "format": format_name,
        "reference": "TS 51.011 §10.3.21/§10.3.23",
        "hex": raw.hex().upper(),
        "flags": subscription_flags,
        "active": [idx for idx, bit in enumerate(subscription_flags, start=1) if bit],
    }


def _decode_phonebook_pbr(hex_clean: str) -> dict[str, object] | None:
    """Decode EF.PBR (TS 31.102 §4.4.2.1) — BER-TLV of tagged TLV entries
    listing phonebook EFs (type 1: type1Tag, type 2: type2Tag, etc.).

    The constructed A8/A9/AA wrappers carry nested primitive tags C0..CB,
    each of which holds a 2-byte File Identifier. Declare the FID
    decoder so the editor shows both the FID and its catalogued name.
    """

    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    tag_names = {
        "A8": "Type 1 entries (tagged)",
        "A9": "Type 2 entries",
        "AA": "Type 3 entries",
        "C0": "ADN reference",
        "C1": "IAP reference",
        "C2": "EXT1 reference",
        "C3": "SNE reference",
        "C4": "ANR reference",
        "C5": "PBC reference",
        "C6": "GRP reference",
        "C7": "AAS reference",
        "C8": "GAS reference",
        "C9": "UID reference",
        "CA": "EMAIL reference",
        "CB": "CCP1 reference",
    }
    fid_tags = ("C0", "C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "CA", "CB")
    items = _decode_field_ber_tlv_stream(
        raw,
        tag_names=tag_names,
        value_decoders={tag: _tlv_value_decoder_file_id for tag in fid_tags},
    )
    return {
        "format": "Phonebook Reference",
        "hex": raw.hex().upper(),
        "items": items,
    }


def _decode_isim_service_table(hex_clean: str) -> dict[str, object] | None:
    decoded = _decode_service_table(hex_clean, _ISIM_SERVICE_NAMES)
    if decoded is None:
        return None
    decoded["format"] = "ISIM service table"
    return decoded


def _decode_three_byte_counter(
    hex_clean: str,
    *,
    format_name: str,
    field_name: str,
) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 3:
        return None
    return {
        "format": format_name,
        field_name: int.from_bytes(raw, "big"),
        "raw": hex_clean,
    }


def _decode_apn_control_list(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 1:
        return None
    decoded: dict[str, object] = {
        "format": "Access Point Name Control List",
        "apnCount": raw[0],
        "raw": hex_clean,
    }
    tlv_bytes = _strip_trailing_ff_padding(raw[1:])
    if len(tlv_bytes) > 0:
        decoded["tlvBytes"] = tlv_bytes.hex().upper()
    return decoded


def _decode_adn_like_record(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 14:
        return None
    alpha_len = len(raw) - 14
    alpha = _decode_alpha_string_text(raw[:alpha_len])
    footer = raw[alpha_len:]
    number_len = footer[0]
    ton_npi = footer[1]
    digits = _decode_bcd_digits(footer[2:12])
    if number_len > 1:
        digits = digits[: (number_len - 1) * 2]
    decoded: dict[str, object] = {
        "number": digits,
        "numberLength": number_len,
        "tonNpi": f"0x{ton_npi:02X}",
        "extensionRecordIdentifier": f"0x{footer[13]:02X}",
    }
    if alpha != "":
        decoded["alphaIdentifier"] = alpha
    return decoded


def _decode_sms_record(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    status = raw[0]
    state_map = {
        0x00: "Free",
        0x01: "Received read",
        0x03: "Received unread",
        0x05: "Stored sent",
        0x07: "Stored unsent",
    }
    return {
        "recordStatus": f"0x{status:02X}",
        "recordState": state_map.get(status & 0x07, "Unknown"),
        "tpduHex": raw[1:].hex().upper(),
    }


def _decode_smss(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 2:
        return None
    return {
        "lastUsedTpMr": raw[0],
        "memoryCapacityExceeded": (raw[1] & 0x01) == 0,
        "raw": hex_clean,
    }


def _decode_smsp(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 12:
        return None
    alpha_len = max(0, len(raw) - 28)
    alpha = _decode_alpha_string_text(raw[:alpha_len])
    if alpha_len + 28 > len(raw):
        return None
    return {
        "parameterIndicators": f"0x{raw[alpha_len]:02X}",
        "tpDestinationAddress": raw[alpha_len + 1 : alpha_len + 13].hex().upper(),
        "serviceCenterAddress": raw[alpha_len + 13 : alpha_len + 25].hex().upper(),
        "tpPid": f"0x{raw[alpha_len + 25]:02X}",
        "tpDcs": f"0x{raw[alpha_len + 26]:02X}",
        "tpValidity": f"0x{raw[alpha_len + 27]:02X}",
        **({"alphaIdentifier": alpha} if alpha != "" else {}),
    }


def _decode_ad(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0:
        return None
    mode_map = {
        0x00: "Normal",
        0x01: "Type Approval",
        0x02: "Normal/Internal",
        0x04: "Normal/Internal",
        0x80: "Proprietary",
    }
    return {
        "administrativeMode": mode_map.get(raw[0], f"0x{raw[0]:02X}"),
        "raw": hex_clean,
    }


def _decode_puct(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) < 5:
        return None
    currency = _decode_printable_ascii(raw[0:3]) or raw[0:3].hex().upper()
    eppu = (raw[3] << 4) | (raw[4] & 0x0F)
    exp_nibble = (raw[4] >> 4) & 0x0F
    sign = -1 if (exp_nibble & 0x08) else 1
    exponent = sign * (exp_nibble & 0x07)
    return {
        "currency": currency,
        "eppu": eppu,
        "exponent": exponent,
        "pricePerUnitFormula": f"{eppu} * 10^{exponent}",
    }


def _decode_ecc(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    codes: list[str] = []
    for offset in range(0, len(raw), 3):
        block = raw[offset : offset + 3]
        if len(block) < 3:
            break
        if block == b"\xFF\xFF\xFF":
            continue
        digits = _decode_bcd_digits(block)
        if digits != "":
            codes.append(digits)
    return {
        "emergencyCodes": codes,
        "entryCount": len(codes),
    }


def _decode_hpplmn_search_interval(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) != 1:
        return None
    return {
        "interval": raw[0],
        "raw": hex_clean,
    }


def _decode_arr_access_modes(value_bytes: bytes) -> list[str]:
    if len(value_bytes) == 0:
        return []
    access_byte = value_bytes[0]
    flags = [
        (0x01, "READ"),
        (0x02, "UPDATE"),
        (0x04, "APPEND"),
        (0x08, "DEACTIVATE"),
        (0x10, "ACTIVATE"),
        (0x40, "TERMINATE"),
    ]
    modes = [name for mask, name in flags if access_byte & mask]
    if len(modes) == 0:
        modes.append(f"Proprietary(0x{access_byte:02X})")
    return modes


def _decode_arr_security_condition(value_bytes: bytes) -> dict[str, object] | None:
    """Decode the contents of an AuthTemplate (tag A4) per ISO 7816-4 §5.3.3.

    Recognises all standard SC-DOs used by TS 102 221 EF.ARR records:
    tag 83 (Key reference), 95 (Usage qualifier), 80 (AM), 9C (Crypto
    Mechanism ID), 9E (Security Environment ID), plus the structural
    condition templates (A0 OR, A7 NOT, AF AND).
    """

    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names={
            "80": "Access Mode",
            "83": "Key reference",
            "95": "Usage qualifier",
            "9C": "Crypto mechanism",
            "9E": "Security environment",
        },
        value_decoders={
            "83": _tlv_value_decoder_small_int,
            "95": _tlv_value_decoder_small_int,
            "9C": _tlv_value_decoder_small_int,
            "9E": _tlv_value_decoder_small_int,
        },
    )
    key_reference = None
    usage_qualifier = None
    for item in items:
        tag = item.get("tag")
        raw = str(item.get("raw") or "")
        if tag == "83" and len(raw) == 2:
            try:
                key_reference = int(raw, 16)
            except ValueError:
                key_reference = None
        elif tag == "95" and len(raw) == 2:
            try:
                usage_qualifier = int(raw, 16)
            except ValueError:
                usage_qualifier = None
    condition = "Unknown"
    if key_reference == 0x01:
        condition = "PIN1"
    elif key_reference == 0x02:
        condition = "PIN2"
    elif key_reference == 0x0A:
        condition = "ADM1"
    elif key_reference == 0x0B:
        condition = "ADM2"
    elif key_reference == 0x81:
        condition = "PIN1 (Global)"
    elif key_reference == 0x82:
        condition = "PIN2 (Global)"
    elif key_reference is not None and 0x0A <= key_reference <= 0x1F:
        condition = f"ADM(0x{key_reference:02X})"
    elif key_reference is not None:
        condition = f"KeyRef(0x{key_reference:02X})"
    payload: dict[str, object] = {
        "condition": condition,
        "items": items,
    }
    if usage_qualifier is not None:
        payload["usageQualifier"] = f"0x{usage_qualifier:02X}"
    return payload


def _decode_arr_boolean_condition(
    value_bytes: bytes, *, operator: str
) -> dict[str, object]:
    """Decode a constructed boolean SC-DO (tag A0 OR / A7 NOT / AF AND)."""

    children: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(value_bytes):
        parsed = _parse_ber_tlv_item(value_bytes, cursor)
        if parsed is None:
            break
        item, cursor = parsed
        tag = str(item["tag"])
        nested = item["valueBytes"]
        if tag == "A4":
            child = _decode_arr_security_condition(nested)
            if child is not None:
                children.append(child)
            continue
        if tag == "A0":
            children.append(_decode_arr_boolean_condition(nested, operator="OR"))
            continue
        if tag == "A7":
            children.append(_decode_arr_boolean_condition(nested, operator="NOT"))
            continue
        if tag == "AF":
            children.append(_decode_arr_boolean_condition(nested, operator="AND"))
            continue
        if tag == "90":
            children.append({"condition": "Always"})
            continue
        if tag == "97":
            children.append({"condition": "Never"})
            continue
        children.append({"tag": tag, "raw": nested.hex().upper()})
    return {"operator": operator, "children": children}


def _decode_ef_arr(hex_clean: str) -> dict[str, object] | None:
    try:
        raw = bytes.fromhex(hex_clean)
    except ValueError:
        return None
    if len(raw) == 0 or all(byte_value == 0xFF for byte_value in raw):
        return None
    cursor = 0
    current_modes: list[str] = []
    rules: list[dict[str, object]] = []
    while cursor < len(raw):
        parsed = _parse_ber_tlv_item(raw, cursor)
        if parsed is None:
            return {
                "format": "EF.ARR access rules",
                "rules": rules,
                "parseErrorOffset": cursor,
                "remaining": raw[cursor:].hex().upper(),
            }
        item, cursor = parsed
        tag = str(item["tag"])
        value_bytes = item["valueBytes"]
        if tag == "80":
            current_modes = _decode_arr_access_modes(value_bytes)
            continue
        if tag == "90":
            rules.append({"accessModes": list(current_modes), "condition": "Always"})
            continue
        if tag == "97":
            rules.append({"accessModes": list(current_modes), "condition": "Never"})
            continue
        if tag == "84":
            command = value_bytes.hex().upper()
            command_rule: dict[str, object] = {"commandHeader": command}
            if len(current_modes) > 0:
                command_rule["accessModes"] = list(current_modes)
            rules.append(command_rule)
            continue
        if tag == "A4":
            condition = _decode_arr_security_condition(value_bytes)
            rule: dict[str, object] = {"accessModes": list(current_modes)}
            if condition is not None:
                rule.update(condition)
            rules.append(rule)
            continue
        if tag in {"A0", "A7", "AF"}:
            operator_map = {"A0": "OR", "A7": "NOT", "AF": "AND"}
            decoded_compound = _decode_arr_boolean_condition(
                value_bytes, operator=operator_map[tag]
            )
            rule = {"accessModes": list(current_modes)}
            rule.update(decoded_compound)
            rules.append(rule)
            continue
    if len(rules) == 0:
        return None
    summary_parts: list[str] = []
    for rule in rules[:4]:
        modes = "/".join(rule.get("accessModes", []))
        if "condition" in rule:
            summary_parts.append(f"{modes}: {rule['condition']}")
        elif "operator" in rule:
            summary_parts.append(
                f"{modes}: {rule['operator']}({len(rule.get('children', []))})"
            )
        elif "commandHeader" in rule:
            summary_parts.append(f"{modes}: command {rule['commandHeader']}")
    return {
        "format": "EF.ARR access rules",
        "reference": "TS 102 221 §9.4 / ISO 7816-4 §5.3.3",
        "ruleCount": len(rules),
        "rules": rules,
        "summary": "; ".join(summary_parts),
    }


def _tuple_payload_items(value: Any) -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(value, list) is False:
        return out
    for item in value:
        if isinstance(item, tuple) and len(item) == 2:
            tag_name = str(item[0] or "").strip()
            if len(tag_name) == 0:
                continue
            out.append((tag_name, item[1]))
            continue
        if isinstance(item, list) and len(item) == 2:
            tag_name = str(item[0] or "").strip()
            if len(tag_name) == 0:
                continue
            out.append((tag_name, item[1]))
            continue
        if isinstance(item, dict) is False:
            continue
        if set(_structural_data_keys(item)) != {_TAG_TUPLE}:
            continue
        inner = _value_first(item, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
        if isinstance(inner, list) is False or len(inner) < 2:
            continue
        tag_name = str(inner[0] or "").strip()
        if len(tag_name) == 0:
            continue
        out.append((tag_name, inner[1]))
    return out


def _bytes_from_tagged_or_raw(value: Any) -> bytes | None:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    hex_tagged = _hex_from_tagged_bytes(value)
    if hex_tagged is not None:
        return bytes.fromhex(hex_tagged)
    hex_scalar = _hex_from_scalar_value(value)
    if hex_scalar is not None:
        return bytes.fromhex(hex_scalar)
    return None


def _int_from_scalar_or_text(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        text = str(value or "").strip()
        if len(text) == 0:
            return None
        if text.isdigit():
            return int(text)
    return None


def _record_layout_from_descriptor_payload(
    descriptor_payload: Any,
) -> tuple[int | None, int | None, int | None]:
    if isinstance(descriptor_payload, dict) is False:
        return (None, None, None)
    descriptor_bytes = _bytes_from_tagged_or_raw(descriptor_payload.get("fileDescriptor"))
    file_descriptor = None
    if descriptor_bytes is not None:
        file_descriptor = _decode_file_descriptor(descriptor_bytes)
    record_length = None
    record_count = None
    if isinstance(file_descriptor, dict):
        record_length = file_descriptor.get("recordLength")
        record_count = file_descriptor.get("numberOfRecords")
        if isinstance(record_length, int) is False:
            record_length = None
        if isinstance(record_count, int) is False:
            record_count = None
    file_size_bytes = _bytes_from_tagged_or_raw(descriptor_payload.get("efFileSize"))
    file_size = None
    if file_size_bytes is not None and len(file_size_bytes) > 0:
        file_size = int.from_bytes(file_size_bytes, "big", signed=False)
    if file_size is None and isinstance(record_length, int) and isinstance(record_count, int):
        file_size = record_length * record_count
    return (record_length, record_count, file_size)


def _decode_arr_records_from_descriptor_and_chunks(
    descriptor_payload: Any,
    fill_chunks: list[tuple[int, bytes]],
) -> dict[int, dict[str, object]]:
    record_length, record_count, file_size = _record_layout_from_descriptor_payload(
        descriptor_payload
    )
    if isinstance(record_length, int) is False or record_length <= 0:
        return {}
    if len(fill_chunks) == 0:
        return {}
    max_end = 0
    for offset_value, content_bytes in fill_chunks:
        end_offset = int(offset_value) + len(content_bytes)
        if end_offset > max_end:
            max_end = end_offset
    buffer_size = max(int(file_size or 0), max_end)
    if buffer_size <= 0:
        return {}
    raw = bytearray(b"\xFF" * buffer_size)
    for offset_value, content_bytes in fill_chunks:
        start_offset = max(0, int(offset_value))
        end_offset = start_offset + len(content_bytes)
        if end_offset > len(raw):
            raw.extend(b"\xFF" * (end_offset - len(raw)))
        raw[start_offset:end_offset] = content_bytes
    if isinstance(record_count, int) and record_count > 0:
        total_records = int(record_count)
    else:
        total_records = len(raw) // record_length
        if len(raw) % record_length != 0:
            total_records += 1
    out: dict[int, dict[str, object]] = {}
    for record_number in range(1, total_records + 1):
        start_offset = (record_number - 1) * record_length
        end_offset = start_offset + record_length
        if start_offset >= len(raw):
            break
        record_bytes = bytes(raw[start_offset:end_offset])
        decoded = _decode_ef_arr(record_bytes.hex())
        if decoded is None:
            continue
        out[record_number] = decoded
    return out


def describe_arr_record_from_file_value(
    file_value: Any,
    *,
    record_number: int,
) -> str | None:
    if isinstance(record_number, int) is False or record_number <= 0:
        return None
    descriptor_payload = None
    fill_chunks: list[tuple[int, bytes]] = []
    current_offset = 0
    for tag_name, payload in _tuple_payload_items(file_value):
        if tag_name == "fileDescriptor" and isinstance(payload, dict):
            descriptor_payload = payload
            continue
        if tag_name == "fillFileOffset":
            offset_value = _int_from_scalar_or_text(payload)
            if offset_value is not None:
                current_offset = int(offset_value)
            continue
        if tag_name != "fillFileContent":
            continue
        content_bytes = _bytes_from_tagged_or_raw(payload)
        if content_bytes is None:
            continue
        fill_chunks.append((current_offset, content_bytes))
        current_offset += len(content_bytes)
    decoded_records = _decode_arr_records_from_descriptor_and_chunks(
        descriptor_payload,
        fill_chunks,
    )
    decoded_record = decoded_records.get(int(record_number))
    if isinstance(decoded_record, dict) is False:
        return None
    summary = str(decoded_record.get("summary", "") or "").strip()
    if len(summary) == 0:
        return None
    return summary


def describe_arr_record_from_section(
    section_value: Any,
    *,
    record_number: int,
) -> str | None:
    if isinstance(section_value, dict) is False:
        return None
    return describe_arr_record_from_file_value(
        section_value.get("ef-arr"),
        record_number=record_number,
    )


def describe_arr_record_from_gfm_section(
    section_value: Any,
    *,
    context_path: list[int] | tuple[int, ...],
    record_number: int,
) -> str | None:
    if isinstance(section_value, dict) is False:
        return None
    normalized_context = tuple(int(part) for part in context_path)
    if len(normalized_context) == 0 or normalized_context[0] != 0x3F00:
        return None
    arr_fid = 0x2F06
    if len(normalized_context) > 1:
        arr_fid = 0x6F06
    arr_path = tuple(list(normalized_context) + [arr_fid])
    groups = section_value.get("fileManagementCMD")
    if isinstance(groups, list) is False:
        return None
    descriptor_payload = None
    fill_chunks: list[tuple[int, bytes]] = []
    current_path = [0x3F00]
    for group in groups:
        if isinstance(group, list) is False:
            continue
        group_path = list(current_path)
        current_file_path: tuple[int, ...] | None = None
        current_fill_offset = 0
        for tag_name, payload in _tuple_payload_items(group):
            if tag_name == "filePath":
                raw_path = _bytes_from_tagged_or_raw(payload)
                if raw_path is None or len(raw_path) % 2 != 0:
                    group_path = [0x3F00]
                    current_file_path = None
                    current_fill_offset = 0
                    continue
                relative_path: list[int] = []
                for offset_value in range(0, len(raw_path), 2):
                    relative_path.append(
                        int.from_bytes(raw_path[offset_value : offset_value + 2], "big", signed=False)
                    )
                group_path = [0x3F00] + relative_path
                current_file_path = None
                current_fill_offset = 0
                continue
            if tag_name == "createFCP" and isinstance(payload, dict):
                file_id_bytes = _bytes_from_tagged_or_raw(payload.get("fileID"))
                if file_id_bytes is None or len(file_id_bytes) != 2:
                    current_file_path = None
                    continue
                current_file_path = tuple(
                    list(group_path)
                    + [int.from_bytes(file_id_bytes, "big", signed=False)]
                )
                if current_file_path == arr_path:
                    descriptor_payload = payload
                descriptor_bytes = _bytes_from_tagged_or_raw(payload.get("fileDescriptor"))
                descriptor = None
                if descriptor_bytes is not None:
                    descriptor = _decode_file_descriptor(descriptor_bytes)
                if isinstance(descriptor, dict) and descriptor.get("fileType") == "df":
                    group_path = list(current_file_path)
                continue
            if tag_name == "fillFileOffset":
                offset_value = _int_from_scalar_or_text(payload)
                if offset_value is not None:
                    current_fill_offset = int(offset_value)
                continue
            if tag_name != "fillFileContent":
                continue
            if current_file_path != arr_path:
                continue
            content_bytes = _bytes_from_tagged_or_raw(payload)
            if content_bytes is None:
                continue
            fill_chunks.append((current_fill_offset, content_bytes))
            current_fill_offset += len(content_bytes)
        current_path = list(group_path)
    decoded_records = _decode_arr_records_from_descriptor_and_chunks(
        descriptor_payload,
        fill_chunks,
    )
    decoded_record = decoded_records.get(int(record_number))
    if isinstance(decoded_record, dict) is False:
        return None
    summary = str(decoded_record.get("summary", "") or "").strip()
    if len(summary) == 0:
        return None
    return summary


def _decode_known_ef_payload(
    *,
    ef_key: str | None,
    fid: str | None,
    hex_clean: str,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    token = str(ef_key or "").strip().lower()
    fid_upper = str(fid or "").strip().upper()
    # ``parent_hint`` is optional; when supplied (either as a PE section key
    # like ``"usim"``/``"csim_2"`` or an explicit DF/ADF token) it is used to
    # pick the canonical ``ef-*`` key for FIDs that collide across parents.
    # Without the hint the dispatcher falls back to the ef_key / FID pair and
    # the flat collision label, which is correct for most SAIP-side flows.
    hint_token = _normalize_parent_hint(parent_hint)
    if token == "" and fid_upper != "" and hint_token is not None:
        token = _resolve_ef_key_for_fid(fid_upper, hint_token) or ""

    # Token-namespaced groups first (FIDs within these groups commonly
    # collide with unrelated EFs under ADF.USIM/DF.5GS/etc, so the token
    # wins when present).
    # Wave C Pass D — semantic CSIM tokens carved out before the generic
    # ``ef-csim-*`` opaque fallback below.
    if token == "ef-csim-st":
        return _decode_ef_csim_st(hex_clean)
    if token.startswith("ef-csim-"):
        # 3GPP2 C.S0065 §5.2 covers the CSIM EF family. Without per-EF
        # semantic decoders we surface annotated spec-opaques so the tree
        # pane shows "CSIM XYZ" + the 3GPP2 reference rather than a bare
        # hex blob. Individual decoders (ef-csim-st, ef-csim-imsi-m, etc.)
        # still short-circuit higher up in the dispatcher.
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name=f"CSIM {token[len('ef-csim-'):].upper()}",
            spec_reference="3GPP2 C.S0065 §5.2 (CSIM)",
            summary_prefix=f"CSIM-{token[len('ef-csim-'):].upper()}",
        )
    if token.startswith("ef-opcust"):
        # Operator-custom tokens are vendor-defined and carry no 3GPP /
        # ETSI spec reference; keep them as generic opaques.
        return _decode_opaque_ef(
            hex_clean, format_name=f"Operator Custom {token[len('ef-opcust'):]}"
        )
    if token.startswith("ef-vendor"):
        return _decode_opaque_ef(
            hex_clean, format_name=f"Vendor Custom {token[len('ef-vendor'):]}"
        )
    # NOTE: The ef-prose-*/ef-v2x-*/ef-mexe-st/ef-scp11key/ef-scp80ctr/
    # ef-simlock-state/ef-ota-state/ef-ota-keys/ef-provconfig/ef-selfservice/
    # ef-appconfig/ef-acmp/ef-tui tokens were previously short-circuited to
    # _decode_opaque_ef here, which shadowed the semantic decoders added in
    # Round-2 Pass 1 / Pass 2 further down in this dispatcher. The semantic
    # branches at ``ef-mexe-st`` / ``ef-prose-pfidg`` / ``ef-scp11key`` etc
    # now win; fall through so they can fire.

    if token == "ef-iccid" or fid_upper == "2FE2":
        return _decode_iccid(hex_clean)
    if token == "ef-dir" or fid_upper == "2F00":
        return _decode_ef_dir_record(hex_clean)
    if token == "ef-arr" or fid_upper in {"2F06", "6F06"}:
        return _decode_ef_arr(hex_clean)
    if token == "ef-pl" or fid_upper == "2F05":
        return _decode_two_byte_language_records(hex_clean)
    if token == "ef-li" or fid_upper == "6F05":
        return _decode_two_byte_language_records(hex_clean)
    if token == "ef-impi":
        return _decode_tlv80_text(hex_clean, format_name="ISIM private user identity", field_name="Identity")
    if token == "ef-domain":
        return _decode_tlv80_text(hex_clean, format_name="ISIM home network domain", field_name="Domain")
    if token == "ef-impu":
        return _decode_tlv80_text(hex_clean, format_name="ISIM public user identity", field_name="Identity")
    if token == "ef-ist":
        return _decode_isim_service_table(hex_clean)
    if token == "ef-pcscf":
        return _decode_pcscf_address(hex_clean)
    if token == "ef-imsi" or fid_upper == "6F07":
        return _decode_ef_imsi(hex_clean)
    if token == "ef-ad" or fid_upper == "6FAD":
        return _decode_ad(hex_clean)
    if token == "ef-pnn" or fid_upper == "6FC5":
        return _decode_pnn_record(hex_clean)
    if token == "ef-opl" or fid_upper == "6FC6":
        return _decode_opl_record(hex_clean)
    if token == "ef-spdi" or fid_upper == "6FCD":
        return _decode_spdi(hex_clean)
    if token == "ef-epsnsc" or fid_upper == "6FE4":
        return _decode_eps_nas_security_context(hex_clean)
    if token == "ef-ust" or fid_upper == "6F38":
        return _decode_ust(hex_clean)
    if token == "ef-est" or fid_upper == "6F56":
        return _decode_est(hex_clean)
    if token == "ef-start-hfn" or fid_upper == "6F5B":
        return _decode_start_hfn(hex_clean)
    if token == "ef-sms" or fid_upper == "6F3C":
        return _decode_sms_record(hex_clean)
    if token == "ef-smsp" or fid_upper == "6F42":
        return _decode_smsp(hex_clean)
    if token == "ef-smss" or fid_upper == "6F43":
        return _decode_smss(hex_clean)
    if token == "ef-smsr" or fid_upper == "6F47":
        return _decode_sms_status_reports(hex_clean)
    if token == "ef-acmax" or fid_upper == "6F37":
        return _decode_three_byte_counter(
            hex_clean,
            format_name="Accumulated call meter maximum",
            field_name="acmMax",
        )
    if token == "ef-acm" or fid_upper == "6F39":
        return _decode_three_byte_counter(
            hex_clean,
            format_name="Accumulated call meter",
            field_name="acm",
        )
    if token == "ef-acc" or fid_upper == "6F78":
        return _decode_acc(hex_clean)
    if token in {"ef-adn", "ef-fdn", "ef-sdn"} or fid_upper in {"6F3A", "6F3B", "6F49"}:
        return _decode_adn_like_record(hex_clean)
    if token == "ef-spn" or fid_upper == "6F46":
        return _decode_spn(hex_clean)
    if token == "ef-msisdn" or fid_upper == "6F40":
        return _decode_msisdn(hex_clean)
    if token == "ef-puct" or fid_upper == "6F41":
        return _decode_puct(hex_clean)
    if token == "ef-ecc" or fid_upper == "6FB7":
        return _decode_ecc(hex_clean)
    if token == "ef-hpplmn" or fid_upper == "6F31":
        return _decode_hpplmn_search_interval(hex_clean)
    if token == "ef-acl" or fid_upper == "6F57":
        return _decode_apn_control_list(hex_clean)
    if token == "ef-ict" or fid_upper == "6F82":
        return _decode_three_byte_counter(
            hex_clean,
            format_name="Incoming call timer",
            field_name="accumulatedCallTimer",
        )
    if token == "ef-oct" or fid_upper == "6F83":
        return _decode_three_byte_counter(
            hex_clean,
            format_name="Outgoing call timer",
            field_name="accumulatedCallTimer",
        )
    if token == "ef-ehplmn" or fid_upper == "6FD9":
        return _decode_plmn_list(hex_clean, with_act=False)
    if token == "ef-ehplmnpi" or fid_upper == "6FDB":
        return _decode_ehplmn_presentation_indication(hex_clean)
    if token == "ef-gbanl" or fid_upper == "6FDA":
        return _decode_gbanl(hex_clean)
    if token == "ef-nafkca" or fid_upper == "6FDD":
        return _decode_nafkca(hex_clean)
    if token == "ef-pkcs15-odf" or fid_upper == "5031":
        return _decode_pkcs15_odf(hex_clean)
    if token == "ef-pkcs15-dodf" or fid_upper == "5207":
        return _decode_pkcs15_dodf(hex_clean)
    if token == "ef-pkcs15-acm" or fid_upper == "4200":
        return _decode_pkcs15_acm(hex_clean)
    if token == "ef-pkcs15-accf" or fid_upper == "4310":
        return _decode_pkcs15_accf(hex_clean)
    if token in _PLMN_WITH_ACT_KEYS or fid_upper in {"6F60", "6F61", "6F62"}:
        return _decode_plmn_list(hex_clean, with_act=True)
    if token == "ef-fplmn" or fid_upper == "6F7B":
        return _decode_plmn_list(hex_clean, with_act=False)
    if token in {"ef-loci", "ef-psloci", "ef-epsloci"}:
        return _decode_loci(hex_clean)
    if fid_upper in {"6F7E", "6F73", "6FE3"}:
        return _decode_loci(hex_clean)
    if token == "ef-gid1" or fid_upper == "6F3E":
        return _decode_group_identifier(hex_clean, format_name="Group Identifier Level 1")
    if token == "ef-gid2" or fid_upper == "6F3F":
        return _decode_group_identifier(hex_clean, format_name="Group Identifier Level 2")
    if token == "ef-cbmi" or fid_upper == "6F45":
        return _decode_cbmi(hex_clean)
    if token == "ef-cbmid" or fid_upper == "6F48":
        return _decode_cbmi(hex_clean)
    if token == "ef-cbmir" or fid_upper == "6F50":
        return _decode_cbmir(hex_clean)
    if token == "ef-lnd" or fid_upper == "6F44":
        return _decode_adn_like_record(hex_clean)
    if token == "ef-ici" or fid_upper == "6F80":
        return _decode_ici_oci_record(
            hex_clean,
            format_name="Incoming Call Information",
            trailer_fields=(
                ("dateAndTime", 7),
                ("callDuration", 3),
                ("callStatus", 1),
                ("linkTimer", 2),
            ),
        )
    if token == "ef-oci" or fid_upper == "6F81":
        return _decode_ici_oci_record(
            hex_clean,
            format_name="Outgoing Call Information",
            trailer_fields=(
                ("dateAndTime", 7),
                ("callDuration", 3),
                ("linkTimer", 2),
            ),
        )
    if token in {"ef-ext1", "ef-ext2", "ef-ext3"} or fid_upper in {"6F4A", "6F4B", "6F4C"}:
        return _decode_extension_record(hex_clean)
    if token in {"ef-ccp1", "ef-ccp2"} or fid_upper in {"6F3D", "6F4F"}:
        return _decode_ccp_record(hex_clean)
    if token == "ef-cmi" or fid_upper == "6F58":
        decoded = _decode_ef_cmi(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Comparison Method Information",
            spec_reference="TS 51.011 §10.3.35 / TS 31.102 §4.2.83",
            summary_prefix="CMI",
        )
    if token == "ef-keys" or fid_upper == "6F08":
        return _decode_usim_keys_record(hex_clean, format_name="USIM CS ciphering/integrity keys")
    if token == "ef-keysPS" or fid_upper == "6F09":
        return _decode_usim_keys_record(hex_clean, format_name="USIM PS ciphering/integrity keys")
    if token == "ef-kc" or fid_upper == "4F20":
        return _decode_gsm_kc_record(hex_clean, format_name="Kc ciphering key")
    if token == "ef-kcgprs" or fid_upper == "4F52":
        return _decode_gsm_kc_record(hex_clean, format_name="KcGPRS ciphering key")
    if token == "ef-hiddenkey" or fid_upper == "6FC3":
        return _decode_hidden_key(hex_clean)
    if token == "ef-netpar" or fid_upper == "6FC4":
        decoded = _decode_ef_netpar(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Network Parameters",
            spec_reference="TS 31.102 §4.2.31",
        )
    if token == "ef-nia" or fid_upper == "6FD3":
        return _decode_one_byte_indicator(
            hex_clean,
            format_name="Network Indicator for Authentication",
        )
    if token == "ef-lrplmnsi" or fid_upper == "6FDC":
        return _decode_one_byte_indicator(
            hex_clean,
            format_name="Last RPLMN Selection Indication",
            value_map={0x00: "not indicated", 0x01: "indicated"},
        )
    if token == "ef-nasconfig" or fid_upper == "6FE8":
        return _decode_nasconfig(hex_clean)
    if token == "ef-sume" or fid_upper == "6F54":
        decoded = _decode_ef_setup_menu_elements(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="SetUp Menu Elements",
            spec_reference="ETSI TS 102 223 §8.x / TS 31.102 §4.2.34",
        )
    if token in {"ef-s7", "ef-threshold"} or fid_upper == "6F5C":
        decoded = _decode_ef_threshold(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Maximum START value",
            spec_reference="TS 31.102 §4.2.52",
            summary_prefix="THRESHOLD",
        )
    if token == "ef-suci-calc-info-usim" or fid_upper == "4F01":
        return _decode_suci_calc_info(hex_clean)
    if token == "ef-supinai" or fid_upper == "4F09":
        return _decode_supinai(hex_clean)
    if token == "ef-pkcs15-acrf" or fid_upper == "4300":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="PKCS#15 ACRF",
            spec_reference="ETSI TS 102 221 §10.1.1 / PKCS#15 §6.5",
            tag_names=_EF_PKCS15_ACRF_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="PKCS#15 ACRF",
            spec_reference="ETSI TS 102 221 §10.1.1 / PKCS#15 §6.5",
            summary_prefix="PKCS15-ACRF",
        )
    if token == "ef-cpbcch" or fid_upper == "4F63":
        decoded = _decode_ef_cpbcch(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Compressed PBCCH information",
            spec_reference="TS 51.011 §10.4.9 / TS 31.102 §4.4.4.3",
            summary_prefix="CPBCCH",
        )
    if token == "ef-invscan" or fid_upper == "4F64":
        return _decode_one_byte_indicator(
            hex_clean,
            format_name="Invert Scan",
            value_map={0x00: "not inverted", 0x01: "inverted"},
        )
    # 5x10 Pass A — 5G EFs in DF.5GS.
    # Token-based routing first (FIDs 4F01/4F07 also used in ADF.USIM).
    if token == "ef-5gs3gpploci":
        return _decode_5gs_loci(
            hex_clean,
            format_name="5GS 3GPP Location Info",
            spec_reference="TS 31.102 §4.4.11.2",
        )
    if token == "ef-5gsn3gpploci" or fid_upper == "4F02":
        return _decode_5gs_loci(
            hex_clean,
            format_name="5GS non-3GPP Location Info",
            spec_reference="TS 31.102 §4.4.11.3",
        )
    if token == "ef-5gs3gppnsc" or fid_upper == "4F03":
        decoded = _decode_ef_5gs3gpp_nsc(
            hex_clean, format_name="5GS 3GPP NAS Security Context"
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="5GS 3GPP NAS Security Context",
            spec_reference="TS 31.102 §4.4.11.4",
        )
    if token == "ef-5gsn3gppnsc" or fid_upper == "4F04":
        decoded = _decode_ef_5gs3gpp_nsc(
            hex_clean, format_name="5GS non-3GPP NAS Security Context"
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="5GS non-3GPP NAS Security Context",
            spec_reference="TS 31.102 §4.4.11.5",
        )
    if token == "ef-5gauthkeys" or fid_upper == "4F05":
        decoded = _decode_ef_5gauthkeys(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="5G Authentication Keys",
            spec_reference="TS 31.102 §4.4.11.6",
        )
    if token == "ef-uac-aic" or fid_upper == "4F06":
        return _decode_uac_aic(hex_clean)
    if token == "ef-5g-suci-calc-info":
        return _decode_suci_calc_info(hex_clean)
    if token == "ef-opl5g" or fid_upper == "4F08":
        return _decode_opl5g_record(hex_clean)
    if token == "ef-routing-indicator" or fid_upper == "4F0A":
        return _decode_routing_indicator(hex_clean)
    if token == "ef-ursp" or fid_upper == "4F0B":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="UE Route Selection Policy",
            spec_reference="TS 31.102 §4.4.11.10 / TS 24.526",
            tag_names=_EF_URSP_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="UE Route Selection Policy",
            spec_reference="TS 31.102 §4.4.11.10 / TS 24.526",
            summary_prefix="URSP",
        )
    # 5x10 Pass C — 5G extras.
    if token == "ef-tn3gppsnn" or fid_upper == "4F0C":
        return _decode_uri_record(
            hex_clean,
            format_name="Trusted non-3GPP SSID",
            spec_reference="TS 31.102 §4.4.11.11",
        )
    # Rel-17 FIDs 4F10 / 4F11 collide with DF.PHONEBOOK ANR anchors;
    # the previous pre-fix 4F0D / 4F0E anchors also collide with
    # CAG / SOR-CMCI. Token routing only so callers must supply the
    # correct parent-aware ef-key; FID-only live dumps resolve through
    # the parent-hint threading elsewhere.
    if token == "ef-5gsedrx":
        return _decode_5gsedrx(hex_clean)
    if token == "ef-5gnswo-conf":
        return _decode_5gnswo_conf(hex_clean)
    # Wave C Pass A — DF.5GS / DF.5G_ProSe / DF.SNPN / ADF.USIM ePDG.
    # Token-first routing (FIDs in these DFs collide with ADF.USIM).
    if token == "ef-5g-prose-st":
        return _decode_5g_prose_service_table(hex_clean)
    if token == "ef-5g-prose-dd":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe Direct Discovery Configuration",
            tag_names=_5G_PROSE_DD_TAGS,
        )
    if token == "ef-5g-prose-dc":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe Direct Communication Configuration",
            tag_names=_5G_PROSE_DC_TAGS,
        )
    if token == "ef-5g-prose-u2nru":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe UE-to-Network Relay (User) Configuration",
            tag_names=_5G_PROSE_U2NRU_TAGS,
        )
    if token == "ef-5g-prose-ru":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe Remote UE Configuration",
            tag_names=_5G_PROSE_RU_TAGS,
        )
    if token == "ef-5g-prose-uir":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe Usage-Information Reporting Configuration",
            tag_names=_5G_PROSE_UIR_TAGS,
        )
    # Rel-18 ProSe additions (TS 31.102 §4.4.13.8 / §4.4.13.9). Token-
    # only routing — the bare FID collides with DF.5GS anchors.
    if token == "ef-5g-prose-u2uru":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe UE-to-UE Relay (User) Configuration",
            tag_names=_5G_PROSE_U2URU_TAGS,
        )
    if token == "ef-5g-prose-eu":
        return _decode_5g_prose_tlv_ef(
            hex_clean,
            format_name="5G ProSe End-UE Configuration",
            tag_names=_5G_PROSE_EU_TAGS,
        )
    # Rel-18 5MBS UE pre-configuration (TS 31.102 §4.4.14.2).
    if token == "ef-5mbsueconfig":
        return _decode_5mbs_ue_config(hex_clean)
    # EF.5MBSUSD (TS 31.102 §4.4.14.3). Content is an MBMS USD object
    # whose exact layout is not fully enumerated in 31.102; expose a
    # spec-anchored opaque shell so the editor still surfaces a
    # human-readable label and spec reference.
    if token == "ef-5mbsusd":
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="5MBS User Service Description",
            spec_reference="TS 31.102 §4.4.14.3",
            summary_prefix="5MBS USD",
        )
    if token == "ef-pws-snpn":
        return _decode_pws_snpn(hex_clean)
    # DF.SNPN (TS 31.102 §4.4.11.13). FID 4F02 collides with DF.5GS
    # EF.5GSN3GPPLOCI; token routing takes precedence.
    if token == "ef-nid":
        return _decode_ef_nid(hex_clean)
    # ADF.USIM additions (TS 31.102 §4.4.2 / §4.4.3). 6F02 also hosts
    # ISIM EF.IMPI, so we stay token-anchored here.
    if token == "ef-ocst":
        return _decode_ef_ocst(hex_clean)
    if token == "ef-rplmnact" or fid_upper == "6F65":
        return _decode_ef_rplmnact(hex_clean)
    # DF.HNB (TS 31.102 §4.4.6 — Home NodeB files).
    if token == "ef-acsgl" or fid_upper == "4F81":
        return _decode_ef_acsgl(hex_clean)
    if token == "ef-csgt" or fid_upper == "4F82":
        return _decode_ef_csgt(hex_clean)
    if token == "ef-hnbn" or fid_upper == "4F83":
        return _decode_ef_hnbn(hex_clean)
    if token == "ef-ocsgl" or fid_upper == "4F84":
        return _decode_ef_ocsgl(hex_clean)
    if token == "ef-suci-calc-info":
        return _decode_suci_calc_info(hex_clean)
    if token == "ef-supi-nai":
        return _decode_supinai(hex_clean)
    if token == "ef-cag":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="Pre-configured CAG Information List",
            spec_reference="TS 31.102 §4.4.11.14",
            tag_names={
                "80": "CAG-ID",
                "81": "CAG Validity Information",
                "82": "CAG Indicator (manual selection only)",
                "A0": "CAG Entry",
            },
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Pre-configured CAG Information List",
            spec_reference="TS 31.102 §4.4.11.14",
            summary_prefix="CAG list",
        )
    if token == "ef-sor-cmci":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="SoR Connected-Mode Control Information",
            spec_reference="TS 31.102 §4.4.11.15",
            tag_names={
                "80": "SoR-CMCI Validity",
                "81": "SoR-CMCI Counter",
                "82": "Secured Packet",
                "A0": "SoR-CMCI Entry",
            },
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="SoR Connected-Mode Control Information",
            spec_reference="TS 31.102 §4.4.11.15",
            summary_prefix="SoR-CMCI",
        )
    if token == "ef-dri":
        return _decode_ef_dri(hex_clean)
    if token == "ef-mchpplmn":
        return _decode_ef_mchpplmn(hex_clean)
    if token == "ef-kausf-derivation":
        return _decode_kausf_derivation(hex_clean)
    if token == "ef-ipd":
        return _decode_ef_ipd_opaque(hex_clean)
    if token == "ef-ips":
        return _decode_ef_ips_record(hex_clean)
    if token == "ef-epdgid":
        return _decode_ef_epdgid(
            hex_clean,
            format_name="Home ePDG Identifier",
        )
    if token == "ef-epdgidem":
        return _decode_ef_epdgid(
            hex_clean,
            format_name="Emergency ePDG Identifier",
        )
    if token == "ef-epdgselection":
        return _decode_ef_epdgselection(
            hex_clean,
            format_name="ePDG Selection Information",
        )
    if token == "ef-epdgselectionem":
        return _decode_ef_epdgselection(
            hex_clean,
            format_name="Emergency ePDG Selection Information",
        )
    # Wave C Pass B — ADF.USIM optional / ISIM-USIM shared EFs.
    if token == "ef-bdn":
        return _decode_adn_like_record(hex_clean)
    # ``ef-bdnuri`` is dispatched with spec_reference further down (Round-3
    # Pass 1 FID-map correction aligned it with 6FEE). Do not short-circuit
    # here or we would emit URI records without the §-reference.
    if token == "ef-ext4":
        return _decode_extension_record(hex_clean)
    if token == "ef-ext5":
        return _decode_extension_record(hex_clean)
    if token == "ef-ext8":
        return _decode_extension_record(hex_clean)
    if token == "ef-vgcsca":
        return _decode_ef_cipher_algo_record(
            hex_clean,
            format_name="VGCS Ciphering Algorithm",
        )
    if token == "ef-vbsca":
        return _decode_ef_cipher_algo_record(
            hex_clean,
            format_name="VBS Ciphering Algorithm",
        )
    if token == "ef-msk":
        return _decode_ef_msk_record(hex_clean)
    if token == "ef-muk":
        return _decode_ef_muk_record(hex_clean)
    if token == "ef-ufc":
        return _decode_ef_ufc(hex_clean)
    if token == "ef-pws":
        return _decode_ef_pws(hex_clean)
    if token == "ef-umpc":
        return _decode_ef_umpc(hex_clean)
    if token == "ef-eaka":
        return _decode_ef_eaka(hex_clean)
    if token == "ef-frompreferred":
        return _decode_ef_from_preferred(hex_clean)
    if token == "ef-3gpppsdataoff":
        return _decode_ef_3gpp_ps_data_off(hex_clean)
    if token == "ef-3gpppsdataoffservicelist":
        return _decode_ef_3gpp_ps_data_off_service_list(hex_clean)
    if token == "ef-ial":
        return _decode_ef_ial_record(hex_clean)
    if token == "ef-ncp-ip":
        return _decode_ef_ncp_ip_record(hex_clean)
    if token == "ef-spni":
        return _decode_ef_icon_indicator(
            hex_clean,
            format_name="Service Provider Name Icon",
        )
    if token == "ef-pnni":
        return _decode_ef_icon_indicator(
            hex_clean,
            format_name="PLMN Network Name Icon",
        )
    # Wave C Pass C — ADF.ISIM / DF.MULTIMEDIA / DF.MCS / MMS family.
    if token == "ef-gbabp":
        return _decode_ef_gbabp(hex_clean)
    if token == "ef-uicciari":
        return _decode_ef_uicciari(hex_clean)
    if token == "ef-imsconfigdata":
        return _decode_ef_imsconfigdata(hex_clean)
    if token == "ef-xcapconfigdata":
        return _decode_ef_xcapconfigdata(hex_clean)
    if token == "ef-webrtcuri":
        return _decode_ef_webrtcuri(hex_clean)
    if token == "ef-mudmidconfigdata":
        return _decode_ef_mudmidconfigdata(hex_clean)
    if token == "ef-mml":
        return _decode_ef_mml(hex_clean)
    if token == "ef-mmdf":
        return _decode_ef_mmdf(hex_clean)
    if token == "ef-mst":
        return _decode_ef_mst(hex_clean)
    if token == "ef-mlpl":
        return _decode_ef_mlpl(hex_clean)
    if token == "ef-mspl":
        return _decode_ef_mspl(hex_clean)
    if token == "ef-mmssmode":
        return _decode_ef_mmssmode(hex_clean)
    if token == "ef-mmsicp":
        return _decode_ef_mmsicp(hex_clean)
    if token == "ef-mmsn":
        return _decode_ef_mmsn(hex_clean)
    if token == "ef-mmsucp":
        return _decode_ef_mmsucp(hex_clean)
    if token == "ef-mmsup":
        return _decode_ef_mmsup(hex_clean)
    if token == "ef-mmsconfig":
        return _decode_ef_mmsconfig(hex_clean)
    if token == "ef-hrpdcap":
        return _decode_ef_hrpdcap(hex_clean)
    if token == "ef-hrpdupp":
        return _decode_ef_hrpdupp(hex_clean)
    if token == "ef-spc":
        return _decode_ef_spc(hex_clean)
    # Wave C Pass D — ADF.CSIM / OPT-CSIM core.
    if token == "ef-csim-st":
        return _decode_ef_csim_st(hex_clean)
    if token == "ef-accolc":
        return _decode_ef_accolc(hex_clean)
    if token == "ef-mipcap":
        return _decode_ef_mipcap(hex_clean)
    if token == "ef-ipv6cap":
        return _decode_ef_ipv6cap(hex_clean)
    if token == "ef-smscap":
        return _decode_ef_smscap(hex_clean)
    if token == "ef-sipcap":
        return _decode_ef_sipcap(hex_clean)
    if token == "ef-3gcik":
        return _decode_ef_3gcik(hex_clean)
    if token == "ef-imsi-m":
        return _decode_ef_imsi_m(hex_clean)
    if token == "ef-imsi-t":
        return _decode_ef_imsi_t(hex_clean)
    if token == "ef-ruimid":
        return _decode_ef_ruimid(hex_clean)
    if token == "ef-sf-euimid":
        return _decode_ef_sf_euimid(hex_clean)
    if token == "ef-esn-meid-me":
        return _decode_ef_esn_meid_me(hex_clean)
    if token == "ef-mdn":
        return _decode_ef_mdn(hex_clean)
    if token == "ef-prl":
        return _decode_ef_prl(hex_clean)
    if token == "ef-eprl":
        return _decode_ef_eprl(hex_clean)
    if token == "ef-cdmahome":
        return _decode_ef_cdmahome(hex_clean)
    if token == "ef-home-tag":
        return _decode_ef_home_tag(hex_clean)
    if token == "ef-group-tag":
        return _decode_ef_group_tag(hex_clean)
    if token == "ef-specific-tag":
        return _decode_ef_specific_tag(hex_clean)
    if token == "ef-tmsi":
        return _decode_ef_csim_tmsi(hex_clean)
    # Wave C Pass E — DF.TELECOM / DF.PHONEBOOK / ICE / DF.V2X / EAP.
    if token == "ef-aas":
        return _decode_ef_aas(hex_clean)
    if token == "ef-pbc":
        return _decode_ef_pbc(hex_clean)
    if token == "ef-puri":
        return _decode_ef_puri(hex_clean)
    if token == "ef-uid":
        return _decode_ef_uid(hex_clean)
    if token == "ef-ice-dn":
        return _decode_ef_ice_dn(hex_clean)
    if token == "ef-ice-ff":
        return _decode_ef_ice_ff(hex_clean)
    if token == "ef-ice-graphics":
        return _decode_ef_ice_graphics(hex_clean)
    if token == "ef-icon":
        return _decode_ef_icon(hex_clean)
    if token == "ef-img":
        return _decode_ef_img(hex_clean)
    if token == "ef-iidf":
        return _decode_ef_iidf(hex_clean)
    if token == "ef-launch-scws":
        return _decode_ef_launch_scws(hex_clean)
    if token == "ef-launchpad":
        return _decode_ef_launchpad(hex_clean)
    if token == "ef-mcs-config":
        return _decode_ef_mcs_config(hex_clean)
    if token == "ef-v2x-config":
        return _decode_ef_v2x_config(hex_clean)
    if token == "ef-v2xp-uu":
        return _decode_ef_v2xp_uu(hex_clean)
    if token == "ef-v2xp-pc5":
        return _decode_ef_v2xp_pc5(hex_clean)
    if token == "ef-vst":
        return _decode_ef_vst(hex_clean)
    if token == "ef-curid":
        return _decode_ef_eap_curid(hex_clean)
    if token == "ef-ps":
        return _decode_ef_eap_ps(hex_clean)
    if token == "ef-realm":
        return _decode_ef_eap_realm(hex_clean)
    # Wave D Pass A — EAP / USIM / TELECOM / common residual EFs.
    if token == "ef-arr-usim":
        return _decode_ef_arr_usim(hex_clean)
    if token == "ef-threshold":
        return _decode_ef_threshold(hex_clean)
    if token == "ef-eapkeys":
        return _decode_ef_eapkeys(hex_clean)
    if token == "ef-eapstatus":
        return _decode_ef_eapstatus(hex_clean)
    if token == "ef-reid":
        return _decode_ef_reid(hex_clean)
    if token == "ef-model":
        return _decode_ef_model(hex_clean)
    if token == "ef-call-count":
        return _decode_ef_call_count(hex_clean)
    if token == "ef-call-prompt":
        return _decode_ef_call_prompt(hex_clean)
    if token == "ef-applabels":
        return _decode_ef_applabels(hex_clean)
    if token == "ef-auth-capability":
        return _decode_ef_auth_capability(hex_clean)
    if token == "ef-acp":
        return _decode_ef_acp(hex_clean)
    if token == "ef-atc":
        return _decode_ef_atc(hex_clean)
    if token == "ef-namlock":
        return _decode_ef_namlock(hex_clean)
    if token == "ef-usgind":
        return _decode_ef_usgind(hex_clean)
    if token == "ef-dgc":
        return _decode_ef_dgc(hex_clean)
    if token == "ef-term":
        return _decode_ef_term(hex_clean)
    if token == "ef-hidden-key":
        return _decode_ef_hidden_key(hex_clean)
    if token == "ef-csspr":
        return _decode_ef_csspr(hex_clean)
    if token == "ef-rma":
        return _decode_ef_rma(hex_clean)
    # Wave D Pass B — CSIM MIP/SIP/BCSMS/3GPD/WAP/OTA annotated opaque EFs.
    if token == "ef-3gpdopm":
        return _decode_ef_3gpdopm(hex_clean)
    if token == "ef-3gpduppext":
        return _decode_ef_3gpduppext(hex_clean)
    if token == "ef-bcsmscfg":
        return _decode_ef_bcsmscfg(hex_clean)
    if token == "ef-bcsmsp":
        return _decode_ef_bcsmsp(hex_clean)
    if token == "ef-bcsmspref":
        return _decode_ef_bcsmspref(hex_clean)
    if token == "ef-bcsmstable":
        return _decode_ef_bcsmstable(hex_clean)
    if token == "ef-me3gpdopc":
        return _decode_ef_me3gpdopc(hex_clean)
    if token == "ef-mecrp":
        return _decode_ef_mecrp(hex_clean)
    if token == "ef-mipflags":
        return _decode_ef_mipflags(hex_clean)
    if token == "ef-mipsp":
        return _decode_ef_mipsp(hex_clean)
    if token == "ef-mipupp":
        return _decode_ef_mipupp(hex_clean)
    if token == "ef-sippapss":
        return _decode_ef_sippapss(hex_clean)
    if token == "ef-sipsp":
        return _decode_ef_sipsp(hex_clean)
    if token == "ef-sipupp":
        return _decode_ef_sipupp(hex_clean)
    if token == "ef-ota":
        return _decode_ef_ota(hex_clean)
    if token == "ef-otapaspc":
        return _decode_ef_otapaspc(hex_clean)
    if token == "ef-sp":
        return _decode_ef_sp(hex_clean)
    if token == "ef-tcpconfig":
        return _decode_ef_tcpconfig(hex_clean)
    if token == "ef-wapbrowserbm":
        return _decode_ef_wapbrowserbm(hex_clean)
    if token == "ef-wapbrowsercp":
        return _decode_ef_wapbrowsercp(hex_clean)
    # Wave D Pass C — CDMA legacy / analog / registration / PUZL / PRL / LCS.
    if token == "ef-ah":
        return _decode_ef_ah(hex_clean)
    if token == "ef-aloc":
        return _decode_ef_aloc(hex_clean)
    if token == "ef-aop":
        return _decode_ef_aop(hex_clean)
    if token == "ef-bakpara":
        return _decode_ef_bakpara(hex_clean)
    if token == "ef-cdmacnl":
        return _decode_ef_cdmacnl(hex_clean)
    if token == "ef-distregi":
        return _decode_ef_distregi(hex_clean)
    if token == "ef-jdl":
        return _decode_ef_jdl(hex_clean)
    if token == "ef-lcscp":
        return _decode_ef_lcscp(hex_clean)
    if token == "ef-lcsver":
        return _decode_ef_lcsver(hex_clean)
    if token == "ef-max-prl":
        return _decode_ef_max_prl(hex_clean)
    if token == "ef-maxpuzl":
        return _decode_ef_maxpuzl(hex_clean)
    if token == "ef-puzl":
        return _decode_ef_puzl(hex_clean)
    if token == "ef-rc":
        return _decode_ef_rc(hex_clean)
    if token == "ef-snregi":
        return _decode_ef_snregi(hex_clean)
    if token == "ef-spcs":
        return _decode_ef_spcs(hex_clean)
    if token == "ef-ssci":
        return _decode_ef_ssci(hex_clean)
    if token == "ef-ssfc":
        return _decode_ef_ssfc(hex_clean)
    if token == "ef-upbakpara":
        return _decode_ef_upbakpara(hex_clean)
    if token == "ef-znregi":
        return _decode_ef_znregi(hex_clean)
    # 5x10 Pass B / D — Phonebook EFs (DF.PHONEBOOK / DF.TELECOM).
    if token == "ef-pbr" or fid_upper == "4F30":
        return _decode_phonebook_pbr(hex_clean)
    if token == "ef-iap" or fid_upper == "4F25":
        decoded = _decode_ef_iap_record(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Index Administration Phonebook",
            spec_reference="TS 31.102 §4.4.2.2",
        )
    if token == "ef-anr" or fid_upper == "4F11":
        return _decode_adn_like_record(hex_clean)
    if token == "ef-anra" or fid_upper == "4F12":
        return _decode_adn_like_record(hex_clean)
    if token == "ef-anrb" or fid_upper == "4F13":
        return _decode_adn_like_record(hex_clean)
    if token == "ef-anrc" or fid_upper == "4F14":
        return _decode_adn_like_record(hex_clean)
    if token == "ef-sne" or fid_upper == "4F19":
        decoded = _decode_ef_sne_record(hex_clean, format_name="Second Name Entry")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Second Name Entry",
            spec_reference="TS 31.102 §4.4.2.5",
        )
    if token == "ef-snea" or fid_upper == "4F1A":
        decoded = _decode_ef_sne_record(hex_clean, format_name="Second Name Entry A")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Second Name Entry A",
            spec_reference="TS 31.102 §4.4.2.5",
        )
    if token == "ef-sneb" or fid_upper == "4F1B":
        decoded = _decode_ef_sne_record(hex_clean, format_name="Second Name Entry B")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Second Name Entry B",
            spec_reference="TS 31.102 §4.4.2.5",
        )
    if token == "ef-email" or fid_upper == "4F50":
        decoded = _decode_ef_email_record(hex_clean, format_name="EMAIL")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="EMAIL",
            spec_reference="TS 31.102 §4.4.2.13",
        )
    if token == "ef-emailb" or fid_upper == "4F51":
        decoded = _decode_ef_email_record(hex_clean, format_name="EMAIL B")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="EMAIL B",
            spec_reference="TS 31.102 §4.4.2.13",
        )
    if token == "ef-gas" or fid_upper == "4F4C":
        decoded = _decode_ef_gas_record(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Grouping Alpha String",
            spec_reference="TS 31.102 §4.4.2.8",
        )
    if token == "ef-grp" or fid_upper == "4F26":
        decoded = _decode_ef_grp_record(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Phonebook Groups",
            spec_reference="TS 31.102 §4.4.2.3",
        )
    if token == "ef-psc" or fid_upper == "4F22":
        decoded = _decode_ef_psc(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Phonebook Synchronization Counter",
            spec_reference="TS 31.102 §4.4.2.12",
            summary_prefix="PSC",
        )
    if token == "ef-cc" or fid_upper == "4F23":
        decoded = _decode_ef_cc_counter(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Phonebook Change Counter",
            spec_reference="TS 31.102 §4.4.2.13",
            summary_prefix="CC",
        )
    if token == "ef-puid" or fid_upper == "4F24":
        decoded = _decode_ef_puid(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Previous UID",
            spec_reference="TS 31.102 §4.4.2.14",
            summary_prefix="PUID",
        )
    # 5x10 Pass C — Additional 3GPP / legacy.
    if token == "ef-phase" or fid_upper == "6FAE":
        return _decode_one_byte_indicator(
            hex_clean,
            format_name="Phase Identification",
            value_map={
                0x00: "phase 1",
                0x02: "phase 2",
                0x03: "phase 2+",
            },
        )
    if token == "ef-plmnsel" or fid_upper == "6F30":
        return _decode_plmn_list(hex_clean, with_act=False)
    if token == "ef-bcch" or fid_upper == "6F74":
        decoded = _decode_ef_bcch(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Broadcast Control Channel",
            spec_reference="TS 51.011 §10.2.23 / TS 31.102 §4.4.4",
            summary_prefix="BCCH",
        )
    if token == "ef-locigprs" or fid_upper == "6F53":
        decoded = _decode_ef_locigprs(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="GPRS Location Information",
            spec_reference="TS 51.011 §10.3.29 / TS 31.102 §4.2.23",
            summary_prefix="LOCIGPRS",
        )
    # SAIP vendor-side tokens must be resolved via ``token`` alone before the
    # FID-based URI dispatches fire, because legacy test fixtures (and older
    # profiles) still pass 6FEE/6FEF alongside ``ef-fcst`` / ``ef-phist``.
    if token == "ef-fcst":
        decoded = _decode_ef_fcsl(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Forbidden CSG List",
            spec_reference="TS 31.102 §4.4.6.6",
        )
    if token == "ef-phist":
        decoded = _decode_ef_phist(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Provider Host List",
            spec_reference="TS 31.102 §4.2.99",
        )
    if token == "ef-fdnuri" or fid_upper == "6FED":
        return _decode_uri_record(
            hex_clean,
            format_name="EF.FDN URI",
            spec_reference="TS 31.102 §4.2.71",
        )
    if token == "ef-bdnuri" or fid_upper == "6FEE":
        return _decode_uri_record(
            hex_clean,
            format_name="EF.BDN URI",
            spec_reference="TS 31.102 §4.2.72",
        )
    if token == "ef-sdnuri" or fid_upper == "6FEF":
        return _decode_uri_record(
            hex_clean,
            format_name="EF.SDN URI",
            spec_reference="TS 31.102 §4.2.73",
        )
    if token == "ef-lnduri" or fid_upper == "6FEA":
        return _decode_uri_record(
            hex_clean,
            format_name="EF.LND URI",
            spec_reference="TS 31.102 §4.2.70",
        )
    # 5x10 Pass D — ISIM + multimedia extras.
    if token == "ef-pcscf-urn":
        return _decode_pcscf_urn(hex_clean)
    if token == "ef-muddomain" or fid_upper == "6FDF":
        return _decode_uri_record(
            hex_clean,
            format_name="Management URI Domain",
            spec_reference="TS 31.102 §4.4.11.17 / RFC 8520",
        )
    if token == "ef-psismsc" or fid_upper == "6FE5":
        decoded = _decode_ef_psismsc(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Public Service Identity SMSC",
            spec_reference="TS 31.103 §4.2.16 / TS 31.102 §4.4.11.8",
            summary_prefix="PSISMSC",
        )
    if token == "ef-uiccsi" or fid_upper == "6FE6":
        return _decode_uri_record(
            hex_clean,
            format_name="UICC SIP Instance ID",
            spec_reference="TS 31.103 §4.2.20",
        )
    if token == "ef-ehuri" or fid_upper == "6FE7":
        return _decode_uri_record(
            hex_clean,
            format_name="ISIM Extended URI",
            spec_reference="TS 31.103 §4.2.21",
        )
    if token == "ef-impdf" or fid_upper == "6F27":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="IMS PDF / IMPU table",
            spec_reference="TS 31.103 §4.2.11",
            tag_names=_EF_IMPDF_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="IMS PDF / IMPU table",
            spec_reference="TS 31.103 §4.2.11",
            summary_prefix="IMPDF",
        )
    if token == "ef-nafkca-list" or fid_upper == "6FDE":
        decoded = _decode_ef_nafkca_list(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="NAF Key Centre List",
            spec_reference="TS 31.102 §4.4.10 / TS 33.220",
            summary_prefix="NAFKCA",
        )
    if token == "ef-gbauapi" or fid_upper == "6F0A":
        decoded = _decode_ef_gbauapi(hex_clean)
        if decoded is not None:
            return decoded
    if token == "ef-imsdci" or fid_upper == "6F0B":
        decoded = _decode_ef_imsdci(hex_clean)
        if decoded is not None:
            return decoded
        # TS 31.103 §4.2.23 mandates a 1-byte record. Anything else is either
        # padding/invalid data or a multi-record blob captured from a shell
        # dump; expose an annotated opaque so the tree pane keeps the ISIM
        # label rather than silently dropping to the generic catalog.
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="ISIM IMS Data Channel Indication",
            spec_reference="TS 31.103 §4.2.23",
            summary_prefix="IMSDCI",
        )
    if token == "ef-earfcnlist" or fid_upper == "6FFD":
        decoded = _decode_ef_earfcn_list(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="EARFCN List",
            spec_reference="TS 31.102 §4.4.12 / TS 36.101",
            summary_prefix="EARFCN",
        )
    # ``ef-fcst`` / ``ef-phist`` are already dispatched near the top of this
    # function (token-only) to avoid colliding with EF.BDNURI / EF.SDNURI.
    # 5x20 Pass A — Mailbox / CF / VGCS / VBS / eMLPP / DCK / CNL family.
    if token == "ef-mbdn" or fid_upper == "6FC7":
        return _decode_adn_like_record(hex_clean)
    if token == "ef-ext6" or fid_upper == "6FC8":
        return _decode_extension_record(hex_clean)
    if token == "ef-mbi" or fid_upper == "6FC9":
        return _decode_mbi_record(hex_clean)
    if token == "ef-mwis" or fid_upper == "6FCA":
        return _decode_mwis_record(hex_clean)
    if token == "ef-cfis" or fid_upper == "6FCB":
        return _decode_cfis_record(hex_clean)
    if token == "ef-ext7" or fid_upper == "6FCC":
        return _decode_extension_record(hex_clean)
    if token == "ef-mbparam" or fid_upper == "6FCE":
        decoded = _decode_ef_mbparam(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Mailbox Parameters",
            spec_reference="TS 31.102 §4.2.62",
            summary_prefix="MBPARAM",
        )
    if token == "ef-cfis2" or fid_upper == "6FE0":
        return _decode_cfis_record(hex_clean)
    if token == "ef-dck" or fid_upper == "6F2C":
        return _decode_dck_record(hex_clean)
    if token == "ef-cnl" or fid_upper == "6F32":
        decoded = _decode_ef_cnl(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Cooperative Network List",
            spec_reference="TS 51.011 §10.3.23 / TS 31.102 §4.2.8",
            summary_prefix="CNL",
        )
    if token == "ef-vgcs" or fid_upper == "6FB1":
        decoded = _decode_vgcs_vbs_subscription(hex_clean, format_name="VGCS Subscription")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="VGCS Subscription",
            spec_reference="TS 51.011 §10.3.25 / TS 31.102 §4.2.22",
            summary_prefix="VGCS",
        )
    if token == "ef-vgcss" or fid_upper == "6FB2":
        decoded = _decode_vgcss_vbss_status(hex_clean, format_name="VGCS Status")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="VGCS Status",
            spec_reference="TS 51.011 §10.3.26 / TS 31.102 §4.2.23",
            summary_prefix="VGCSS",
        )
    if token == "ef-vbs" or fid_upper == "6FB3":
        decoded = _decode_vgcs_vbs_subscription(hex_clean, format_name="VBS Subscription")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="VBS Subscription",
            spec_reference="TS 51.011 §10.3.27 / TS 31.102 §4.2.24",
            summary_prefix="VBS",
        )
    if token == "ef-vbss" or fid_upper == "6FB4":
        decoded = _decode_vgcss_vbss_status(hex_clean, format_name="VBS Status")
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="VBS Status",
            spec_reference="TS 51.011 §10.3.28 / TS 31.102 §4.2.25",
            summary_prefix="VBSS",
        )
    if token == "ef-emlpp" or fid_upper == "6FB5":
        return _decode_emlpp_record(hex_clean)
    if token == "ef-aaem" or fid_upper == "6FB6":
        return _decode_aaem_record(hex_clean)
    if token == "ef-anl" or fid_upper == "6F2E":
        decoded = _decode_ef_anl_record(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="Aggregated Name List",
            spec_reference="TS 31.102 §4.4.2.15",
            summary_prefix="ANL",
        )
    if token == "ef-mexe-st":
        decoded = _decode_ef_mexe_st(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="MExE Service Table",
            spec_reference="TS 51.011 §10.4.16 / TS 23.057",
            summary_prefix="MExE-ST",
        )
    if token == "ef-prose-pfsr":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="ProSe PFSR",
            spec_reference="TS 31.102 §4.4.13.6 / TS 24.334",
            tag_names=_EF_PROSE_PROVISIONED_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="ProSe PFSR",
            spec_reference="TS 31.102 §4.4.13.6 / TS 24.334",
        )
    if token == "ef-vsuri" or fid_upper == "6FE9":
        return _decode_uri_record(
            hex_clean,
            format_name="Voicemail Server URI",
            spec_reference="TS 31.102 §4.2.68",
        )
    # 5x20 Pass B — CSIM EFs are now dispatched via the annotated
    # ``ef-csim-*`` branch earlier in this function (Round-4 Pass 1).
    # 5x20 Pass C — Specialized (ISIM/MCPTT/V2X/ProSe/MCS).
    if token == "ef-prose-pfidg":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="ProSe PFIDG",
            spec_reference="TS 31.102 §4.4.13.6 / TS 24.334",
            tag_names=_EF_PROSE_PROVISIONED_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="ProSe PFIDG",
            spec_reference="TS 31.102 §4.4.13.6 / TS 24.334",
        )
    if token == "ef-prose-pfddn":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="ProSe PFDDN",
            spec_reference="TS 31.102 §4.4.13.6 / TS 24.334",
            tag_names=_EF_PROSE_PROVISIONED_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="ProSe PFDDN",
            spec_reference="TS 31.102 §4.4.13.6 / TS 24.334",
        )
    if token == "ef-v2x-cfg":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="V2X Configuration",
            spec_reference="TS 31.102 §4.4.14.3",
            tag_names=_EF_V2X_CFG_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="V2X Configuration",
            spec_reference="TS 31.102 §4.4.14.3",
        )
    if token == "ef-v2x-pre-cfg":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="V2X Pre-configuration",
            spec_reference="TS 31.102 §4.4.14.4",
            tag_names=_EF_V2X_PRECFG_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="V2X Pre-configuration",
            spec_reference="TS 31.102 §4.4.14.4",
        )
    if token == "ef-v2x-cert":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="V2X Certificate",
            spec_reference="TS 31.102 §4.4.14.5",
            tag_names=_EF_V2X_CERT_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="V2X Certificate",
            spec_reference="TS 31.102 §4.4.14.5",
        )
    if token == "ef-v2x-auth-keys":
        decoded = _decode_generic_tlv_ef(
            hex_clean,
            format_name="V2X Auth Keys",
            spec_reference="TS 31.102 §4.4.14.6",
            tag_names=_EF_V2X_AUTHKEYS_TAGS,
        )
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="V2X Auth Keys",
            spec_reference="TS 31.102 §4.4.14.6",
        )
    # MCS / MCPTT family (TS 31.102 §4.4.13 / TS 24.483). All variants share
    # the same tag vocabulary and spec reference; the block below delegates
    # to ``_decode_generic_tlv_ef`` and, on malformed payloads, surfaces an
    # annotated spec-opaque wrapper so the tree-pane still shows the format
    # name + §4.4.13 pointer.
    _MCS_FAMILY = (
        ("ef-mcs-root",        "6FA0", "MCS Root",              "MCS-ROOT"),
        ("ef-mcptt-cfg",       "6FA1", "MCPTT Configuration",   "MCPTT-CFG"),
        ("ef-mcptt-sip",       "6FA2", "MCPTT SIP",             "MCPTT-SIP"),
        ("ef-mcs-user-id",     "6FA3", "MCS User ID",           "MCS-UID"),
        ("ef-mcs-app-list",    "6FA4", "MCS Application List",  "MCS-APPS"),
        ("ef-mcs-gms",         "6FA5", "MCS GMS",               "MCS-GMS"),
        ("ef-mcs-cmsi",        "6FA6", "MCS CMSI",              "MCS-CMSI"),
        ("ef-mcs-media-cfg",   "6FA7", "MCS Media Config",      "MCS-MEDIA"),
        ("ef-mcs-pub-id",      "6FA8", "MCS Public ID",         "MCS-PUB"),
        ("ef-mcs-profile",     "6FA9", "MCS Profile",           "MCS-PROF"),
        ("ef-mcs-emergency",   "6FAA", "MCS Emergency",         "MCS-EMR"),
        ("ef-mcs-keyset",      "6FAB", "MCS Key Set",           "MCS-KEYS"),
        ("ef-mcs-stat",        "6FAC", "MCS Stat",              "MCS-STAT"),
        ("ef-mcs-sec-profile", "6FAF", "MCS Security Profile",  "MCS-SEC"),
    )
    for _mcs_token, _mcs_fid, _mcs_label, _mcs_prefix in _MCS_FAMILY:
        if token == _mcs_token or fid_upper == _mcs_fid:
            decoded = _decode_generic_tlv_ef(
                hex_clean,
                format_name=_mcs_label,
                spec_reference="TS 31.102 §4.4.13 / TS 24.483",
                tag_names=_EF_MCS_TAGS,
                value_decoders=_EF_MCS_VALUE_DECODERS,
            )
            if decoded is not None:
                return decoded
            return _decode_spec_opaque_ef(
                hex_clean,
                format_name=_mcs_label,
                spec_reference="TS 31.102 §4.4.13 / TS 24.483",
                summary_prefix=_mcs_prefix,
            )
    # 5x20 Pass D — Operator / vendor / SCP80/SCP11 extensions.
    if token.startswith("ef-opcust"):
        return _decode_opaque_ef(
            hex_clean, format_name=f"Operator Custom {token[len('ef-opcust'):]}"
        )
    if token.startswith("ef-vendor"):
        return _decode_opaque_ef(
            hex_clean, format_name=f"Vendor Custom {token[len('ef-vendor'):]}"
        )
    if token == "ef-scp11key":
        decoded = _decode_ef_scp11_key(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="SCP11 Key",
            spec_reference="GlobalPlatform Card Spec Amd F (SCP11)",
            summary_prefix="SCP11-KEY",
        )
    if token == "ef-scp80ctr":
        decoded = _decode_ef_scp80_counter(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="SCP80 Counter",
            spec_reference="ETSI TS 102 225 / 102 226 (SCP80)",
            summary_prefix="SCP80-CTR",
        )
    if token == "ef-simlock-state":
        decoded = _decode_ef_simlock_state(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="SIM Lock State",
            spec_reference="TS 22.022 / SAIP Annex D",
            summary_prefix="SIMLOCK",
        )
    if token == "ef-ota-state":
        decoded = _decode_ef_ota_state(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="OTA State",
            spec_reference="ETSI TS 102 226 / SAIP Annex D",
            summary_prefix="OTA-STATE",
        )
    if token == "ef-ota-keys":
        decoded = _decode_ef_ota_keys(hex_clean)
        if decoded is not None:
            return decoded
        return _decode_spec_opaque_ef(
            hex_clean,
            format_name="OTA Keys",
            spec_reference="ETSI TS 102 225 / 102 226",
            summary_prefix="OTA-KEYS",
        )
    # ``ef-provconfig``, ``ef-selfservice``, ``ef-appconfig``, ``ef-acmp``,
    # ``ef-tui`` are vendor-specific SAIP tokens with no 3GPP / ETSI spec
    # reference; keep them as generic opaques so the tree pane does not
    # claim a fabricated §-reference.
    if token == "ef-provconfig":
        return _decode_opaque_ef(hex_clean, format_name="Provisioning Config")
    if token == "ef-selfservice":
        return _decode_opaque_ef(hex_clean, format_name="Self Service Config")
    if token == "ef-appconfig":
        return _decode_opaque_ef(hex_clean, format_name="Application Config")
    if token == "ef-acmp":
        return _decode_opaque_ef(hex_clean, format_name="ACMP")
    if token == "ef-tui":
        return _decode_opaque_ef(hex_clean, format_name="TUI Config")
    # Wave B: opaque-passthrough catalog for every remaining PE-referenced
    # EF that has no bespoke decoder. Lookup is case-insensitive; the
    # catalog owns the human-readable format label. Upgrading any single
    # key to a bespoke decoder is done by adding a dedicated ``if token ==
    # ...`` clause above this block.
    opaque_label = _lookup_opaque_passthrough_ef(token)
    if opaque_label is not None:
        return _decode_opaque_ef(hex_clean, format_name=opaque_label)
    return None


def _decode_oid(value_bytes: bytes) -> str | None:
    if len(value_bytes) == 0:
        return None
    first = value_bytes[0]
    parts = [str(first // 40), str(first % 40)]
    current = 0
    for byte_value in value_bytes[1:]:
        current = (current << 7) | (byte_value & 0x7F)
        if byte_value & 0x80:
            continue
        parts.append(str(current))
        current = 0
    if current != 0:
        return None
    return ".".join(parts)


def _decode_generalized_time(value_bytes: bytes) -> str | None:
    text = _decode_printable_ascii(value_bytes)
    if text is None:
        return None
    formats = ("%Y%m%d%H%M%SZ", "%Y%m%d%H%M%S.%fZ")
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).isoformat() + "Z"
        except ValueError:
            continue
    return text


def _decode_utc_time(value_bytes: bytes) -> str | None:
    text = _decode_printable_ascii(value_bytes)
    if text is None:
        return None
    try:
        return datetime.strptime(text, "%y%m%d%H%M%SZ").isoformat() + "Z"
    except ValueError:
        return text


def _try_decode_nested_ber(value_bytes: bytes) -> list[dict[str, object]] | None:
    decoded = _decode_generic_asn1_blob(value_bytes)
    if decoded is None:
        return None
    items = decoded.get("items")
    if isinstance(items, list):
        return items
    return None


def _decode_universal_primitive(tag_number: int, value_bytes: bytes) -> object | None:
    if tag_number == 1:
        if len(value_bytes) != 1:
            return None
        return value_bytes[0] != 0
    if tag_number in (2, 10):
        if len(value_bytes) == 0:
            return 0
        return int.from_bytes(value_bytes, "big", signed=True)
    if tag_number == 3:
        if len(value_bytes) == 0:
            return {"unusedBits": 0, "payloadHex": ""}
        decoded: dict[str, object] = {
            "unusedBits": value_bytes[0],
            "payloadHex": value_bytes[1:].hex().upper(),
        }
        if value_bytes[0] == 0:
            embedded = _try_decode_nested_ber(value_bytes[1:])
            if embedded is not None:
                decoded["embeddedAsn1"] = embedded
        return decoded
    if tag_number == 4:
        decoded = {
            "hex": value_bytes.hex().upper(),
        }
        # OCTET STRING in generic ASN.1 is frequently key material, digests,
        # or opaque payloads. Single- or two-byte "printable" coincidences
        # surface misleading ``ascii`` fields on key bytes and counters, so
        # require at least 3 fully printable bytes before hinting ASCII.
        if len(value_bytes) >= 3:
            ascii_text = _decode_printable_ascii(value_bytes)
            if ascii_text not in (None, ""):
                decoded["ascii"] = ascii_text
        embedded = _try_decode_nested_ber(value_bytes)
        if embedded is not None:
            decoded["embeddedAsn1"] = embedded
        return decoded
    if tag_number == 5:
        return "NULL"
    if tag_number == 6:
        return _decode_oid(value_bytes)
    if tag_number == 12:
        try:
            return value_bytes.decode("utf-8")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    if tag_number in (18, 19, 20, 21, 22, 25, 26, 27):
        # Numeric / Printable / Teletex / Videotex / IA5 / Graphic /
        # Visible / General strings are ASCII-class per X.680. Use a
        # strict decode so byte sequences that violate the ASN.1 type
        # surface as raw hex rather than being silently masked.
        try:
            return value_bytes.decode("ascii")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    if tag_number == 23:
        return _decode_utc_time(value_bytes)
    if tag_number == 24:
        return _decode_generalized_time(value_bytes)
    if tag_number == 28:
        try:
            return value_bytes.decode("utf-32-be")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    if tag_number == 30:
        try:
            return value_bytes.decode("utf-16-be")
        except UnicodeDecodeError:
            return value_bytes.hex().upper()
    return None


def _tag_class_name(raw_value: int) -> str:
    mapping = {
        0: "universal",
        1: "application",
        2: "context",
        3: "private",
    }
    return mapping.get(raw_value, f"class-{raw_value}")


def _render_tag_name(tag_class: str, tag_number: int) -> str:
    if tag_class == "universal":
        return _UNIVERSAL_TAG_NAMES.get(tag_number, f"UNIVERSAL {tag_number}")
    if tag_class == "application":
        return f"APPLICATION {tag_number}"
    if tag_class == "context":
        return f"[{tag_number}]"
    return f"PRIVATE {tag_number}"


def _parse_tag_identifier(data: bytes, offset: int) -> tuple[str, int, bool, bytes, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    offset += 1
    tag_bytes = bytearray([first])
    tag_class = _tag_class_name((first >> 6) & 0x03)
    constructed = (first & 0x20) != 0
    tag_number = first & 0x1F
    if tag_number != 0x1F:
        return (tag_class, tag_number, constructed, bytes(tag_bytes), offset)
    tag_number = 0
    while offset < len(data):
        byte_value = data[offset]
        offset += 1
        tag_bytes.append(byte_value)
        tag_number = (tag_number << 7) | (byte_value & 0x7F)
        if (byte_value & 0x80) == 0:
            return (tag_class, tag_number, constructed, bytes(tag_bytes), offset)
    return None


def _parse_ber_length(data: bytes, offset: int) -> tuple[int | None, bool, int] | None:
    if offset >= len(data):
        return None
    first = data[offset]
    offset += 1
    if first == 0x80:
        return (None, True, offset)
    if (first & 0x80) == 0:
        return (first, False, offset)
    octet_count = first & 0x7F
    if octet_count == 0 or offset + octet_count > len(data):
        return None
    return (int.from_bytes(data[offset : offset + octet_count], "big"), False, offset + octet_count)


def _parse_ber_stream(
    data: bytes,
    offset: int,
    *,
    allow_eoc: bool,
    depth: int,
) -> tuple[list[dict[str, object]], int] | None:
    if depth > 24:
        raise ValueError("ASN.1 nesting depth exceeds 24 levels")
    items: list[dict[str, object]] = []
    while offset < len(data):
        if allow_eoc and offset + 2 <= len(data) and data[offset : offset + 2] == b"\x00\x00":
            return (items, offset + 2)
        parsed_tag = _parse_tag_identifier(data, offset)
        if parsed_tag is None:
            return None
        tag_class, tag_number, constructed, tag_bytes, value_offset = parsed_tag
        parsed_length = _parse_ber_length(data, value_offset)
        if parsed_length is None:
            return None
        length_value, indefinite, content_offset = parsed_length
        item: dict[str, object] = {
            "tag": _render_tag_name(tag_class, tag_number),
            "class": tag_class,
            "tagNumber": tag_number,
            "constructed": constructed,
            "tagHex": tag_bytes.hex().upper(),
        }
        if indefinite:
            if constructed is False:
                return None
            item["length"] = "indefinite"
            parsed_children = _parse_ber_stream(
                data,
                content_offset,
                allow_eoc=True,
                depth=depth + 1,
            )
            if parsed_children is None:
                return None
            children, next_offset = parsed_children
            item["items"] = children
            items.append(item)
            offset = next_offset
            continue
        if length_value is None:
            return None
        if content_offset + length_value > len(data):
            return None
        value_bytes = data[content_offset : content_offset + length_value]
        item["length"] = length_value
        if constructed:
            parsed_children = _parse_ber_stream(
                value_bytes,
                0,
                allow_eoc=False,
                depth=depth + 1,
            )
            if parsed_children is not None:
                item["items"] = parsed_children[0]
            else:
                item["raw"] = value_bytes.hex().upper()
        else:
            item["raw"] = value_bytes.hex().upper()
            decoded_value = None
            if tag_class == "universal":
                # Universal-class primitives carry a spec-mandated
                # interpretation (INTEGER / OCTET STRING / OID / …). For
                # context / application / private classes there is no
                # universal rule, so we surface only ``raw`` and let the
                # containing decoder declare an interpretation when the
                # specification calls for one.
                decoded_value = _decode_universal_primitive(tag_number, value_bytes)
            if decoded_value is not None:
                item["decoded"] = decoded_value
        items.append(item)
        offset = content_offset + length_value
    return (items, offset)


def _decode_generic_asn1_blob(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    try:
        parsed = _parse_ber_stream(value_bytes, 0, allow_eoc=False, depth=0)
    except ValueError:
        return None
    if parsed is None:
        return None
    items, end_offset = parsed
    if end_offset != len(value_bytes) or len(items) == 0:
        return None
    return {
        "format": "BER/DER",
        "items": items,
    }


def _decode_small_integer(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0 or len(value_bytes) > 4:
        return None
    return {
        "hex": value_bytes.hex().upper(),
        "decimal": int.from_bytes(value_bytes, "big"),
    }


def _decode_network_access_name(value_bytes: bytes) -> str:
    labels: list[str] = []
    cursor = 0
    while cursor < len(value_bytes):
        label_length = value_bytes[cursor]
        cursor += 1
        if label_length == 0:
            break
        label_bytes = value_bytes[cursor : cursor + label_length]
        cursor += label_length
        try:
            labels.append(label_bytes.decode("ascii"))
        except UnicodeDecodeError:
            labels.append(label_bytes.hex().upper())
    return ".".join(labels)


def _decode_other_address(value_bytes: bytes) -> dict[str, object] | str:
    if len(value_bytes) == 0:
        return value_bytes.hex().upper()
    address_type = value_bytes[0]
    address_value = value_bytes[1:]
    decoded: dict[str, object] = {
        "type": f"0x{address_type:02X}",
        "rawAddress": address_value.hex().upper(),
    }
    try:
        if address_type == 0x21 and len(address_value) == 4:
            decoded["address"] = str(ipaddress.IPv4Address(address_value))
        elif address_type == 0x57 and len(address_value) == 16:
            decoded["address"] = str(ipaddress.IPv6Address(address_value))
    except ipaddress.AddressValueError:
        pass
    return decoded


def _describe_bearer_description(value_bytes: bytes) -> dict[str, object]:
    description = {
        "raw": value_bytes.hex().upper(),
        "bytes": [f"0x{byte_value:02X}" for byte_value in value_bytes],
    }
    if len(value_bytes) > 0:
        description["bearerType"] = f"0x{value_bytes[0]:02X}"
    return description


def _describe_transport_level(value_bytes: bytes) -> dict[str, object]:
    if len(value_bytes) < 3:
        return {"raw": value_bytes.hex().upper()}
    port = int.from_bytes(value_bytes[1:3], "big")
    decoded = {
        "protocol": f"0x{value_bytes[0]:02X}",
        "port": port,
    }
    if len(value_bytes) > 3:
        decoded["parameters"] = value_bytes[3:].hex().upper()
    return decoded


def _parse_ber_tlv_item(data: bytes, offset: int) -> tuple[dict[str, object], int] | None:
    if offset >= len(data):
        return None
    tag_start = offset
    first = data[offset]
    offset += 1
    if (first & 0x1F) == 0x1F:
        while offset < len(data):
            current = data[offset]
            offset += 1
            if (current & 0x80) == 0:
                break
        else:
            return None
    tag_bytes = data[tag_start:offset]
    if offset >= len(data):
        return None
    length_first = data[offset]
    offset += 1
    if length_first == 0x80:
        return None
    if (length_first & 0x80) == 0:
        value_length = length_first
    else:
        length_len = length_first & 0x7F
        if length_len == 0 or offset + length_len > len(data):
            return None
        value_length = int.from_bytes(data[offset : offset + length_len], "big")
        offset += length_len
    end_offset = offset + value_length
    if end_offset > len(data):
        return None
    tag_hex = tag_bytes.hex().upper()
    return (
        {
            "tag": tag_hex,
            "constructed": (tag_bytes[0] & 0x20) != 0,
            "valueBytes": data[offset:end_offset],
            "length": value_length,
        },
        end_offset,
    )


# ---------------------------------------------------------------------------
# Per-tag primitive value decoders.
#
# These small helpers let EF decoders declare, per BER-TLV tag, how the
# primitive value should be interpreted. Previous revisions of
# ``_decode_field_ber_tlv_stream`` used a context-blind opportunistic
# fallback (try ASCII, then a small-integer guess). That produced
# misleading ``decoded`` fields for key material, counters, bit-maps and
# other binary payloads where ASCII rendering has no spec basis.
#
# Callers now opt in explicitly via ``value_decoders={tag: <helper>}``.
# Anything not declared stays as ``raw`` hex only.

def _tlv_value_decoder_text(value_bytes: bytes) -> str | None:
    """Per-tag decoder for spec-typed text fields (URI / label / identity)."""

    return _decode_printable_ascii(value_bytes) or None


def _tlv_value_decoder_small_int(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """Per-tag decoder for spec-typed small-integer fields (<= 4 bytes)."""

    if 1 <= len(value_bytes) <= 4:
        return _decode_small_integer(value_bytes)
    return None


def _tlv_value_decoder_oid(value_bytes: bytes) -> str | None:
    """Per-tag decoder for universal OID values (tag 0x06)."""

    return _decode_oid(value_bytes)


def _tlv_value_decoder_bcd_digits(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """Per-tag decoder for spec-typed BCD-encoded digit strings."""

    if len(value_bytes) == 0 or _looks_like_bcd_bytes(value_bytes) is False:
        return None
    digits = _decode_bcd_digits(value_bytes)
    if digits == "":
        return None
    return {"digits": digits}


def _tlv_value_decoder_file_id(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """Per-tag decoder for 2-byte File Identifier references.

    Used by EFs that carry 2-byte FID references inside BER-TLV values
    (EF.PBR, EF.PSISMSC, EF.GBABP lookups, etc.). The raw hex already
    conveys the identifier, but the editor also benefits from the
    human-readable FID name when one is catalogued.
    """

    if len(value_bytes) != 2:
        return None
    fid_hex = value_bytes.hex().upper()
    decoded: dict[str, object] = {"fid": fid_hex}
    name = fid_name(fid_hex)
    if name is not None:
        decoded["name"] = name
    return decoded


def _tlv_value_decoder_alpha_string(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """Per-tag decoder for TS 31.102 Annex A alpha strings.

    Used by BER-TLV EFs whose value field carries an alpha identifier
    encoded per ``TS 31.102`` Annex A (GSM 7-bit default / UCS-2 BE /
    UCS-2 with base pointer / UCS-2 with extension table). Returns a
    dict carrying both the decoded text and the detected encoding so
    the editor can show which scheme the card is using.
    """

    decoded = _decode_alpha_string_bytes(value_bytes)
    if decoded is None:
        return None
    return decoded


def _decode_field_ber_tlv_stream(
    value_bytes: bytes,
    *,
    tag_names: dict[str, str],
    force_primitive_tags: set[str] | None = None,
    value_decoders: dict[str, ValueDecoder] | None = None,
    default_primitive_type: str = "opaque",
) -> list[dict[str, object]]:
    """Parse a BER-TLV byte stream into a list of tagged items.

    ``default_primitive_type`` controls how primitive values are
    interpreted when no per-tag ``value_decoders`` entry is declared:

    ``"opaque"`` (default, strict)
        Only emit a ``decoded`` field when the caller declared one via
        ``value_decoders``. Universal OID (tag ``06``) is always
        decoded because the interpretation is mandated by the BER
        standard itself. Any other primitive surfaces only ``raw``.

    ``"opportunistic"`` (legacy)
        Preserves the historic fallback: try printable ASCII, then
        :func:`_decode_small_integer`. Intended only for callers that
        pre-date the per-tag migration and rely on the opportunistic
        output shape.
    """

    force_primitive = set(force_primitive_tags or set())
    if default_primitive_type not in ("opaque", "opportunistic"):
        raise ValueError(
            f"unknown default_primitive_type: {default_primitive_type!r}"
        )
    out: list[dict[str, object]] = []
    cursor = 0
    while cursor < len(value_bytes):
        parsed = _parse_ber_tlv_item(value_bytes, cursor)
        if parsed is None:
            out.append({"parseErrorOffset": cursor, "remaining": value_bytes[cursor:].hex().upper()})
            break
        item, cursor = parsed
        tag_hex = str(item["tag"])
        child_bytes = item["valueBytes"]
        constructed = bool(item["constructed"]) and tag_hex not in force_primitive
        rendered: dict[str, object] = {
            "tag": tag_hex,
            "name": tag_names.get(tag_hex, tag_hex),
            "length": int(item["length"]),
        }
        if constructed:
            rendered["items"] = _decode_field_ber_tlv_stream(
                child_bytes,
                tag_names=tag_names,
                force_primitive_tags=force_primitive,
                value_decoders=value_decoders,
                default_primitive_type=default_primitive_type,
            )
            out.append(rendered)
            continue
        rendered["raw"] = child_bytes.hex().upper()
        custom_decoder = None
        if value_decoders is not None:
            custom_decoder = value_decoders.get(tag_hex)
        decoded_value: object | None = None
        if custom_decoder is not None:
            decoded_value = custom_decoder(child_bytes)
        elif tag_hex == "06":
            decoded_value = _decode_oid(child_bytes)
        elif default_primitive_type == "opportunistic":
            ascii_text = _decode_printable_ascii(child_bytes)
            if ascii_text not in (None, ""):
                decoded_value = ascii_text
            else:
                decoded_value = _decode_small_integer(child_bytes)
        if decoded_value is not None:
            rendered["decoded"] = decoded_value
        out.append(rendered)
    return out


def _scp_name(scp_value: int) -> str | None:
    mapping = {
        0x80: "SCP80",
        0x82: "SCP02",
        0x02: "SCP02",
        0x03: "SCP03",
    }
    return mapping.get(scp_value)


def _decode_flag_octets(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    set_bits: list[int] = []
    bit_index = 0
    for byte_value in reversed(value_bytes):
        for mask in range(8):
            if ((byte_value >> mask) & 0x01) == 0x01:
                set_bits.append(bit_index)
            bit_index += 1
    set_bits.sort(reverse=True)
    return {"hex": value_bytes.hex().upper(), "setBits": set_bits}


def _decode_application_privileges(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    privilege_value = int.from_bytes(value_bytes, "big", signed=False)
    active_ids: list[str] = []
    active_privileges: list[str] = []
    for mask_value, privilege_id, privilege_name in _APPLICATION_PRIVILEGE_FLAGS:
        if privilege_value & mask_value:
            active_ids.append(privilege_id)
            active_privileges.append(privilege_name)
    hex_value = value_bytes.hex().upper()
    return {
        "format": "GlobalPlatform application privileges",
        "hex": hex_value,
        "summary": _summary_with_list(f"0x{hex_value}", active_privileges),
        "activePrivilegeIds": active_ids,
        "activePrivileges": active_privileges,
    }


def _decode_life_cycle_state(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    state_value = value_bytes[0]
    state_name = _LIFE_CYCLE_STATE_NAMES.get(state_value, "Unknown")
    code = f"0x{state_value:02X}"
    return {
        "format": "GlobalPlatform life cycle state",
        "code": code,
        "summary": _summary_with_label(code, None if state_name == "Unknown" else state_name),
        "state": state_name,
    }


def _decode_key_usage_qualifier(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0 or len(value_bytes) > 2:
        return None
    normalized_bytes = value_bytes
    if len(normalized_bytes) == 1:
        normalized_bytes = normalized_bytes + b"\x00"
    usage_value = int.from_bytes(normalized_bytes, "big", signed=False)
    active_ids: list[str] = []
    active_usages: list[str] = []
    for mask_value, usage_id, usage_name in _KEY_USAGE_FLAGS:
        if usage_value & mask_value:
            active_ids.append(usage_id)
            active_usages.append(usage_name)
    normalized_hex = normalized_bytes.hex().upper()
    return {
        "format": "GlobalPlatform key usage qualifier",
        "hex": value_bytes.hex().upper(),
        "normalizedHex": normalized_hex,
        "summary": _summary_with_list(f"0x{normalized_hex}", active_usages),
        "activeUsageIds": active_ids,
        "activeUsages": active_usages,
    }


def _decode_key_access(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    access_value = value_bytes[0]
    access_name = _KEY_ACCESS_NAMES.get(access_value, "Unknown")
    code = f"0x{access_value:02X}"
    return {
        "format": "GlobalPlatform key access",
        "code": code,
        "summary": _summary_with_label(code, None if access_name == "Unknown" else access_name),
        "access": access_name,
    }


def _decode_key_identifier(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    key_id = value_bytes[0]
    role_name = _KEY_ID_COMMON_ROLES.get(key_id)
    decoded: dict[str, object] = {
        "format": "GlobalPlatform key identifier",
        "hex": value_bytes.hex().upper(),
        "decimal": key_id,
        "summary": _summary_with_label(f"0x{key_id:02X}", role_name),
    }
    if role_name is not None:
        decoded["commonRole"] = role_name
    return decoded


def _decode_key_version_number(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    kvn_value = value_bytes[0]
    reserved_for = None
    if 0x01 <= kvn_value <= 0x0F:
        reserved_for = "SCP80"
    elif kvn_value == 0x11:
        reserved_for = "DAP according to ETSI TS 102 226"
    elif 0x20 <= kvn_value <= 0x2F:
        reserved_for = "SCP02"
    elif 0x30 <= kvn_value <= 0x3F:
        reserved_for = "SCP03"
    elif kvn_value == 0xFF:
        reserved_for = "ISD with SCP02 without SCP80 support"
    decoded: dict[str, object] = {
        "format": "GlobalPlatform key version number",
        "hex": value_bytes.hex().upper(),
        "decimal": kvn_value,
        "summary": _summary_with_label(f"0x{kvn_value:02X}", reserved_for),
    }
    if reserved_for is not None:
        decoded["reservedFor"] = reserved_for
    return decoded


def _decode_key_counter_value(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    return {
        "format": "GlobalPlatform key counter value",
        "hex": value_bytes.hex().upper(),
        "decimal": decimal_value,
        "summary": f"{decimal_value} (0x{value_bytes.hex().upper()})",
    }


def _decode_key_type(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    key_type_value = value_bytes[0]
    key_type_name = _KEY_TYPE_NAMES.get(key_type_value, "Unknown")
    code = f"0x{key_type_value:02X}"
    return {
        "format": "GlobalPlatform key type",
        "hex": value_bytes.hex().upper(),
        "summary": _summary_with_label(code, None if key_type_name == "Unknown" else key_type_name),
        "type": key_type_name,
    }


def _decode_pin_puk_retry_counter(value: Any) -> dict[str, object] | None:
    packed_value = None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if value < 0 or value > 0xFF:
            return None
        packed_value = value
    else:
        value_bytes = _bytes_from_scalar_value(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        packed_value = value_bytes[0]
    max_attempts = (packed_value >> 4) & 0x0F
    remaining_attempts = packed_value & 0x0F
    hex_value = f"{packed_value:02X}"
    return {
        "format": "PIN/PUK retry counters",
        "hex": hex_value,
        "decimal": packed_value,
        "maxAttempts": max_attempts,
        "remainingAttempts": remaining_attempts,
        "summary": f"{remaining_attempts} remaining of {max_attempts} (0x{hex_value})",
    }


def _decode_puk_key_reference(value: Any) -> dict[str, object] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        reference_value = value
    else:
        value_bytes = _bytes_from_scalar_value(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        reference_value = int.from_bytes(value_bytes, "big", signed=False)
    if reference_value < 0:
        return None
    reference_name = _PUK_KEY_REFERENCE_NAMES.get(reference_value)
    return {
        "format": "PUK key reference",
        "decimal": reference_value,
        "referenceName": reference_name or "Unknown",
        "summary": _summary_with_label(str(reference_value), reference_name),
    }


def _decode_pin_puk_adm_key_reference(value: Any) -> dict[str, object] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        reference_value = value
    else:
        value_bytes = _bytes_from_scalar_value(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        reference_value = int.from_bytes(value_bytes, "big", signed=False)
    decoded: dict[str, object] = {
        "format": "PIN/PUK/ADM key reference",
        "decimal": reference_value,
    }
    if 1 <= reference_value <= 8:
        slot_index = reference_value
        decoded["slotIndex"] = slot_index
        decoded["pinName"] = f"pinAppl{slot_index}"
        decoded["pukName"] = f"pukAppl{slot_index}"
        decoded["summary"] = f"{reference_value} (PIN/PUK slot {slot_index})"
        return decoded
    if 129 <= reference_value <= 136:
        slot_index = reference_value - 128
        decoded["slotIndex"] = slot_index
        decoded["pinName"] = f"secondPINAppl{slot_index}"
        decoded["pukName"] = f"secondPUKAppl{slot_index}"
        decoded["summary"] = f"{reference_value} (secondary PIN/PUK slot {slot_index})"
        return decoded
    if 10 <= reference_value <= 14:
        decoded["admName"] = f"adm{reference_value - 9}"
        decoded["summary"] = f"{reference_value} ({decoded['admName']})"
        return decoded
    if 138 <= reference_value <= 142:
        decoded["admName"] = f"adm{reference_value - 132}"
        decoded["summary"] = f"{reference_value} ({decoded['admName']})"
        return decoded
    decoded["summary"] = str(reference_value)
    return decoded


def _decode_pin_attributes(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    decoded: dict[str, object] = {
        "format": "PIN attributes",
        "hex": value_bytes.hex().upper(),
        "decimal": value_bytes[0],
        "summary": f"0x{value_bytes[0]:02X}",
    }
    flags = _decode_flag_octets(value_bytes)
    if flags is not None:
        decoded["setBits"] = flags["setBits"]
    return decoded


def _decode_fill_file_offset(value: Any) -> dict[str, object] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        decimal_value = value
    else:
        value_bytes = _bytes_from_scalar_value(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    if decimal_value < 0:
        return None
    hex_value = f"{decimal_value:X}"
    if len(hex_value) % 2 != 0:
        hex_value = f"0{hex_value}"
    hex_value = hex_value.zfill(4)
    return {
        "format": "File content offset",
        "decimal": decimal_value,
        "hex": hex_value,
        "summary": f"{decimal_value} (0x{hex_value})",
    }


def _decode_pin_secret_value(value_bytes: bytes) -> dict[str, object] | None:
    """Decode a PIN/PUK value per ETSI TS 102 221 §9.2.

    PIN/PUK secrets are strictly 4–8 ASCII digits (0x30..0x39) followed
    by 0xFF filler octets to pad the record to 8 bytes. BCD is not a
    legal on-card representation, so no BCD inference is performed —
    that would be context-blind fluff that misreads random-looking
    key material as a digit string.
    """

    if len(value_bytes) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "PIN/PUK value",
        "reference": "ETSI TS 102 221 §9.2",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    content_bytes = value_bytes.rstrip(b"\xFF")
    padding_bytes = value_bytes[len(content_bytes) :]
    if len(padding_bytes) > 0:
        decoded["paddingHex"] = padding_bytes.hex().upper()
    ascii_text = _decode_printable_ascii(content_bytes)
    if ascii_text not in (None, "") and ascii_text.isdigit():
        decoded["digits"] = ascii_text
        decoded["summary"] = ascii_text
        return decoded
    # Non-digit content violates §9.2 — surface the raw hex rather than
    # fabricate a text rendering of unrelated bytes.
    decoded["summary"] = value_bytes.hex().upper()
    return decoded


def _decode_profile_iccid(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    digits = value_bytes.hex().upper().rstrip("F")
    if re.fullmatch(r"[0-9]+", digits) is None:
        return None
    return {
        "format": "Profile ICCID",
        "hex": value_bytes.hex().upper(),
        "iccid": digits,
        "digitCount": len(digits),
        "summary": digits,
    }


def _decode_key_data(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    return {
        "format": "Security domain key material",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "keySizeBits": len(value_bytes) * 8,
        "summary": f"{len(value_bytes) * 8}-bit key material",
    }


def _decode_application_identifier(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    aid_hex = value_bytes.hex().upper()
    decoded: dict[str, object] = {
        "format": "Application Identifier",
        "aid": aid_hex,
        "length": len(value_bytes),
    }
    if len(value_bytes) >= 5:
        decoded["rid"] = aid_hex[:10]
        if len(value_bytes) > 5:
            decoded["pix"] = aid_hex[10:]
            decoded["summary"] = f"{aid_hex} (RID {aid_hex[:10]}, PIX {aid_hex[10:]})"
        else:
            decoded["summary"] = f"{aid_hex} (RID {aid_hex[:10]})"
    else:
        decoded["summary"] = aid_hex
    return decoded


def _decode_pin_status_template_do(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    if value_bytes[0] in {0x83, 0x90, 0x95}:
        items = _decode_field_ber_tlv_stream(
            value_bytes,
            tag_names={
                "83": "Key Reference",
                "90": "PIN status bytes",
                "95": "Usage Qualifier",
            },
            value_decoders={
                "83": lambda child_bytes: _decode_pin_puk_adm_key_reference(child_bytes),
                "90": _decode_flag_octets,
                "95": _decode_flag_octets,
            },
        )
        if len(items) > 0 and "parseErrorOffset" not in items[-1]:
            return {
                "format": "PIN status template DO",
                "items": items,
            }
    decoded: dict[str, object] = {
        "format": "PIN status template DO",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    if len(value_bytes) >= 1:
        status_bytes = value_bytes[:-1] if len(value_bytes) > 1 else value_bytes
        decoded["statusBytes"] = status_bytes.hex().upper()
        status_flags = _decode_flag_octets(status_bytes)
        if status_flags is not None:
            decoded["statusBits"] = status_flags["setBits"]
    if len(value_bytes) >= 2:
        key_reference = _decode_pin_puk_adm_key_reference(value_bytes[-1])
        if key_reference is not None:
            decoded["keyReference"] = key_reference
    if len(value_bytes) == 2:
        decoded["summary"] = (
            f"status 0x{value_bytes[0]:02X}, ref {int(value_bytes[1])}"
        )
    else:
        decoded["summary"] = value_bytes.hex().upper()
    return decoded


def _decode_lcsi(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) != 1:
        return None
    lcsi = value_bytes[0]
    state_name = None
    if lcsi == 0x00:
        state_name = "no_information"
    elif lcsi == 0x01:
        state_name = "creation"
    elif lcsi == 0x03:
        state_name = "initialization"
    elif lcsi & 0x05 == 0x05:
        state_name = "operational_activated"
    elif lcsi & 0x05 == 0x04:
        state_name = "operational_deactivated"
    elif lcsi & 0xC0 == 0xC0:
        state_name = "termination"
    return {
        "format": "Life Cycle Status Integer",
        "hex": value_bytes.hex().upper(),
        "state": state_name or "unknown",
        "summary": _summary_with_label(f"0x{lcsi:02X}", state_name),
    }


def _decode_ef_file_size(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    return {
        "format": "EF file size",
        "hex": value_bytes.hex().upper(),
        "decimal": decimal_value,
        "summary": f"{decimal_value} byte(s) (0x{value_bytes.hex().upper()})",
    }


def _decode_minimum_security_level(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    decoded: dict[str, object] = {
        "format": "Minimum security level",
        "hex": value_bytes.hex().upper(),
        "decimal": value_bytes[0],
        "summary": f"0x{value_bytes[0]:02X}",
    }
    flags = _decode_flag_octets(value_bytes)
    if flags is not None:
        decoded["setBits"] = flags["setBits"]
    return decoded


def _decode_mac_length(value: Any) -> dict[str, object] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        mac_length = value
    else:
        value_bytes = _bytes_from_scalar_value(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        mac_length = int.from_bytes(value_bytes, "big", signed=False)
    if mac_length < 0:
        return None
    return {
        "format": "MAC length",
        "decimal": mac_length,
        "summary": f"{mac_length} byte(s)",
    }


def _decode_profile_policy_rules(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "Profile policy rules",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    flags = _decode_flag_octets(value_bytes)
    if flags is None:
        decoded["summary"] = value_bytes.hex().upper()
        return decoded
    set_bits = list(flags.get("setBits", []))
    decoded["setBits"] = set_bits
    active_policies: list[str] = []
    for bit_index in set_bits:
        active_policies.append(_PROFILE_POLICY_RULE_NAMES.get(bit_index, f"bit{bit_index}"))
    decoded["activePolicies"] = active_policies
    if len(active_policies) == 0:
        decoded["summary"] = "none"
    else:
        decoded["summary"] = ", ".join(active_policies)
    return decoded


def _decode_memory_limit_field(field_name: str | None, value: Any) -> dict[str, object] | None:
    key = str(field_name or "").strip()
    format_name = _MEMORY_LIMIT_FIELD_LABELS.get(key)
    if format_name is None:
        return None
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    return {
        "format": format_name,
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "decimal": decimal_value,
        "summary": f"{decimal_value} byte(s)",
    }


def _decode_aka_algorithm_id(value: Any) -> dict[str, object] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        algorithm_id = value
    else:
        value_bytes = _bytes_from_scalar_value(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        algorithm_id = int.from_bytes(value_bytes, "big", signed=False)
    algorithm_name = _AKA_ALGORITHM_ID_NAMES.get(algorithm_id)
    return {
        "format": "AKA algorithm identifier",
        "decimal": algorithm_id,
        "algorithm": algorithm_name or "unknown",
        "summary": _summary_with_label(str(algorithm_id), algorithm_name),
    }


def _decode_aka_option_octet(value: Any, *, format_name: str) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 1:
        return None
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": value_bytes.hex().upper(),
        "decimal": value_bytes[0],
        "summary": f"0x{value_bytes[0]:02X}",
    }
    flags = _decode_flag_octets(value_bytes)
    if flags is not None:
        decoded["setBits"] = flags["setBits"]
    return decoded


def _decode_aka_secret_material(value: Any, *, format_name: str) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    return {
        "format": format_name,
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "keySizeBits": len(value_bytes) * 8,
        "summary": f"{len(value_bytes) * 8}-bit value",
    }


def _decode_aka_counter_field(value: Any, *, format_name: str) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0:
        return None
    decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    return {
        "format": format_name,
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "decimal": decimal_value,
        "summary": f"{decimal_value} (0x{value_bytes.hex().upper()})",
    }


def _decode_rotation_constants(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) != 5:
        return None
    decoded: dict[str, object] = {
        "format": "Milenage rotation constants",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    for index, byte_value in enumerate(value_bytes, start=1):
        decoded[f"r{index}"] = byte_value
    decoded["summary"] = ", ".join(f"r{index}={value_bytes[index - 1]}" for index in range(1, 6))
    return decoded


def _decode_xoring_constants(value: Any) -> dict[str, object] | None:
    value_bytes = _bytes_from_scalar_value(value)
    if value_bytes is None or len(value_bytes) == 0 or len(value_bytes) % 16 != 0:
        return None
    decoded: dict[str, object] = {
        "format": "Milenage XOR constants",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "blockCount": len(value_bytes) // 16,
    }
    for index, offset in enumerate(range(0, len(value_bytes), 16), start=1):
        decoded[f"c{index}"] = value_bytes[offset : offset + 16].hex().upper()
    decoded["summary"] = f"{decoded['blockCount']} block(s)"
    return decoded


def _fid_name_from_hex(
    fid_hex: str,
    *,
    parent_hint: str | None = None,
) -> str | None:
    return fid_name(fid_hex, parent_hint=parent_hint)


def _parent_hint_from_path(
    *,
    pe_section_key: str | None,
    last_ef_key: str | None,
) -> str | None:
    """
    Derive a parent DF/ADF token from the current walker state.

    When ``last_ef_key`` is a known ef-* token, its authored parent wins
    because it pinpoints the exact file. Otherwise the PE section type is
    consulted. Returns ``None`` when no useful hint is available (e.g.
    ``genericFileManagement`` sections where the parent DF is tracked via
    in-stream SELECT commands and must be supplied explicitly).
    """

    if last_ef_key is not None:
        hint_from_ef = _EF_KEY_TO_PARENT_TOKEN.get(str(last_ef_key).strip().lower())
        if hint_from_ef is not None and len(hint_from_ef) > 0:
            return hint_from_ef
    if pe_section_key is not None:
        base = base_pe_type(str(pe_section_key))
        hint_from_pe = _PE_TYPE_TO_PARENT_TOKEN.get(base)
        if hint_from_pe is not None and len(hint_from_pe) > 0:
            return hint_from_pe
    return None


def _decode_file_identifier(
    value_bytes: bytes,
    *,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    if len(value_bytes) != 2:
        return None
    fid_hex = value_bytes.hex().upper()
    resolved_name = _fid_name_from_hex(fid_hex, parent_hint=parent_hint)
    decoded: dict[str, object] = {
        "format": "File Identifier",
        "hex": fid_hex,
        "decimal": int.from_bytes(value_bytes, "big", signed=False),
    }
    if resolved_name is not None:
        decoded["name"] = resolved_name
        decoded["summary"] = _summary_with_label(fid_hex, resolved_name)
    else:
        decoded["summary"] = fid_hex
    candidates = fid_candidates(fid_hex)
    if len(candidates) > 1 and parent_hint is not None:
        hint_token = _normalize_parent_hint(parent_hint)
        if hint_token is not None:
            for candidate_parent, _label in candidates:
                if candidate_parent is not None and candidate_parent == hint_token:
                    decoded["parent"] = _parent_label_from_token(candidate_parent)
                    break
    return decoded


def _decode_security_attributes_referenced(
    value_bytes: bytes,
    *,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "Referenced security attributes",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    if len(value_bytes) == 1:
        decoded["recordNumber"] = value_bytes[0]
        decoded["arrFileId"] = "implicit"
        decoded["summary"] = f"implicit EF.ARR record {value_bytes[0]}"
        return decoded
    if len(value_bytes) == 3:
        fid_hex = value_bytes[:2].hex().upper()
        decoded["arrFileId"] = fid_hex
        resolved_name = _fid_name_from_hex(fid_hex, parent_hint=parent_hint)
        if resolved_name is not None:
            decoded["arrFileName"] = resolved_name
        decoded["recordNumber"] = value_bytes[2]
        if resolved_name is not None:
            decoded["summary"] = f"{resolved_name} record {value_bytes[2]}"
        else:
            decoded["summary"] = f"{fid_hex} record {value_bytes[2]}"
        return decoded
    decoded["summary"] = value_bytes.hex().upper()
    return decoded


def _decode_path_bytes(
    value_bytes: bytes,
    *,
    format_name: str,
    empty_summary: str,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    if len(value_bytes) == 0:
        decoded["independentFile"] = True
        decoded["summary"] = empty_summary
        return decoded
    if len(value_bytes) % 2 != 0:
        decoded["summary"] = value_bytes.hex().upper()
        return decoded
    segments: list[dict[str, object]] = []
    summary_parts: list[str] = []
    for offset in range(0, len(value_bytes), 2):
        fid_hex = value_bytes[offset : offset + 2].hex().upper()
        segment: dict[str, object] = {"fid": fid_hex}
        resolved_name = _fid_name_from_hex(fid_hex, parent_hint=parent_hint)
        if resolved_name is not None:
            segment["name"] = resolved_name
            summary_parts.append(resolved_name)
        else:
            summary_parts.append(fid_hex)
        segments.append(segment)
    decoded["segments"] = segments
    decoded["summary"] = " / ".join(summary_parts)
    return decoded


def _decode_link_path(
    value_bytes: bytes,
    *,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    return _decode_path_bytes(
        value_bytes,
        format_name="Link path",
        empty_summary="independent file",
        parent_hint=parent_hint,
    )


def _decode_file_path(
    value_bytes: bytes,
    *,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    return _decode_path_bytes(
        value_bytes,
        format_name="File path",
        empty_summary="MF",
        parent_hint=parent_hint,
    )


def _decode_special_file_information(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) != 1:
        return None
    byte_value = value_bytes[0]
    decoded: dict[str, object] = {
        "format": "Special file information",
        "hex": value_bytes.hex().upper(),
        "decimal": byte_value,
        "highUpdateActivity": (byte_value & 0x80) != 0,
        "readAndUpdateWhenDeactivated": (byte_value & 0x40) != 0,
    }
    flags = _decode_flag_octets(value_bytes)
    if flags is not None:
        decoded["setBits"] = flags["setBits"]
    decoded["summary"] = (
        "high update activity"
        if decoded["highUpdateActivity"]
        else "low update activity"
    )
    return decoded


def _decode_fill_pattern(value_bytes: bytes, *, repeat_pattern: bool) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    format_name = "Repeat pattern" if repeat_pattern else "Fill pattern"
    decoded: dict[str, object] = {
        "format": format_name,
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    if len(value_bytes) == 1:
        decoded["byteValue"] = f"0x{value_bytes[0]:02X}"
    # SAIP ``fillPattern`` / ``repeatPattern`` are intentionally opaque byte
    # sequences — typically 0xFF padding, 0x00 zero-fill, or a vendor marker.
    # Historic builds attempted an ASCII decode here which would yield
    # false-positive strings (e.g. "hello" because the test profile happened
    # to use ASCII). Only surface a printable form when the pattern is long
    # enough to be meaningful and every byte is printable — that way a
    # profile that really contains ASCII test data still lights up, but
    # random-looking padding never does.
    if len(value_bytes) >= 3:
        ascii_text = _decode_printable_ascii(value_bytes)
        if ascii_text not in (None, "") and len(ascii_text) == len(value_bytes):
            decoded["ascii"] = ascii_text
            decoded["summary"] = ascii_text
    if "summary" not in decoded:
        decoded["summary"] = value_bytes.hex().upper()
    return decoded


def _decode_file_details(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) != 1:
        return None
    byte_value = value_bytes[0]
    coding_name = "DER coding" if byte_value == 0x01 else None
    decoded: dict[str, object] = {
        "format": "BER-TLV file details",
        "hex": value_bytes.hex().upper(),
        "decimal": byte_value,
    }
    if coding_name is not None:
        decoded["coding"] = coding_name
        decoded["summary"] = _summary_with_label(f"0x{byte_value:02X}", coding_name)
    else:
        decoded["summary"] = f"0x{byte_value:02X}"
    return decoded


def _decode_tar_value(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "Toolkit Application Reference",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "summary": value_bytes.hex().upper(),
    }
    if len(value_bytes) == 3:
        decoded["tar"] = value_bytes.hex().upper()
    return decoded


def _decode_access_domain(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    decoded: dict[str, object] = {
        "format": "Access domain",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "summary": value_bytes.hex().upper(),
        "bytes": [f"0x{byte_value:02X}" for byte_value in value_bytes],
    }
    if len(value_bytes) >= 3 and value_bytes[0] == 0x02 and value_bytes[1] == len(value_bytes) - 2:
        decoded["berInteger"] = int.from_bytes(value_bytes[2:], "big", signed=False)
    return decoded


def _decode_short_efid(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return {
            "format": "Short EF Identifier",
            "supported": False,
            "summary": "No SFI supported",
        }
    if len(value_bytes) != 1:
        return None
    raw_value = value_bytes[0]
    sfi = raw_value >> 3
    low_bits = raw_value & 0x07
    valid_encoding = low_bits == 0
    decoded: dict[str, object] = {
        "format": "Short EF Identifier",
        "hex": value_bytes.hex().upper(),
        "supported": True,
        "sfi": sfi,
        "reservedLowBits": f"0b{low_bits:03b}",
        "validEncoding": valid_encoding,
    }
    if valid_encoding:
        decoded["summary"] = f"SFI {sfi}"
    else:
        decoded["summary"] = f"SFI {sfi} with non-zero low bits"
    return decoded


def _decode_file_descriptor(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) < 2:
        return None
    descriptor_byte = value_bytes[0]
    shareable = bool(descriptor_byte & 0x40)
    if descriptor_byte & 0x3F == 0x39:
        file_type = "working_ef"
        structure = "ber_tlv"
    else:
        file_type = {
            0: "working_ef",
            1: "internal_ef",
            7: "df",
        }.get((descriptor_byte >> 3) & 0x07, "unknown")
        structure = {
            0: "no_info_given",
            1: "transparent",
            2: "linear_fixed",
            6: "cyclic",
        }.get(descriptor_byte & 0x07, "unknown")
    decoded: dict[str, object] = {
        "format": "ETSI TS 102 221 file descriptor",
        "hex": value_bytes.hex().upper(),
        "shareable": shareable,
        "fileType": file_type,
        "structure": structure,
        "descriptorCodingByte": f"0x{value_bytes[1]:02X}",
        "summary": f"{'shareable' if shareable else 'non-shareable'} {file_type} / {structure}",
    }
    if len(value_bytes) >= 4:
        decoded["recordLength"] = int.from_bytes(value_bytes[2:4], "big", signed=False)
    if len(value_bytes) >= 5:
        decoded["numberOfRecords"] = value_bytes[4]
    if "recordLength" in decoded and "numberOfRecords" in decoded:
        decoded["derivedFileSize"] = decoded["recordLength"] * decoded["numberOfRecords"]
    return decoded


def _decode_connectivity_parameters(value_bytes: bytes) -> dict[str, object]:
    tag_names = {
        "A0": "Transport / Remote Parameters",
        "A1": "Bearer / Access Parameters",
        "06": "Object Identifier",
        "35": "Bearer Description",
        "39": "Buffer Size",
        "3C": "Transport Level",
        "3E": "Other Address",
        "47": "Network Access Name",
        "81": "Parameter 81",
        "82": "Parameter 82",
    }
    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names=tag_names,
        force_primitive_tags={"35", "39", "3C", "3E", "47"},
        value_decoders={
            "35": _describe_bearer_description,
            "39": _decode_small_integer,
            "3C": _describe_transport_level,
            "3E": _decode_other_address,
            "47": _decode_network_access_name,
            "81": _decode_small_integer,
            "82": _decode_small_integer,
        },
    )
    return {
        "format": "BER-TLV",
        "items": items,
    }


def _decode_sd_install_scp(value_bytes: bytes) -> dict[str, object] | None:
    if len(value_bytes) == 0:
        return None
    scp_value = value_bytes[0]
    decoded: dict[str, object] = {
        "scp": f"0x{scp_value:02X}",
    }
    scp_name = _scp_name(scp_value)
    if scp_name is not None:
        decoded["scpName"] = scp_name
    if len(value_bytes) > 1:
        decoded["i"] = f"0x{value_bytes[1]:02X}"
    return decoded


def _decode_sd_install_parameters(value_bytes: bytes) -> dict[str, object]:
    tag_names = {
        "81": "UICC SCP",
        "82": "Accept extradite applications and load files to SD",
        "83": "Accept delete of associated SD",
        "84": "Life cycle transition to personalized",
        "86": "CASD capability information",
        "87": "Accept extradite associated applications and load files",
    }
    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names=tag_names,
        value_decoders={
            "81": _decode_sd_install_scp,
            "82": _decode_flag_octets,
            "83": _decode_flag_octets,
            "84": _decode_flag_octets,
            "86": _decode_flag_octets,
            "87": _decode_flag_octets,
        },
    )
    return {
        "format": "BER-TLV",
        "items": items,
    }


def _decode_uicc_toolkit_parameters(value_bytes: bytes) -> dict[str, object]:
    decoded: dict[str, object] = {
        "format": "ETSI TS 102 226 toolkit app specific parameters",
        "rawHex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    try:
        offset = 0
        if offset >= len(value_bytes):
            return decoded
        access_domain_length = value_bytes[offset]
        offset += 1
        if offset + access_domain_length > len(value_bytes):
            raise ValueError("invalid access domain length")
        access_domain = value_bytes[offset : offset + access_domain_length]
        offset += access_domain_length
        if offset + 4 > len(value_bytes):
            raise ValueError("missing toolkit fixed header")
        priority_level = value_bytes[offset]
        offset += 1
        max_num_of_timers = value_bytes[offset]
        offset += 1
        max_text_length = value_bytes[offset]
        offset += 1
        menu_entry_count = value_bytes[offset]
        offset += 1
        menu_entries: list[dict[str, int]] = []
        for _ in range(menu_entry_count):
            if offset + 2 > len(value_bytes):
                raise ValueError("truncated toolkit menu entry")
            menu_entries.append(
                {
                    "id": value_bytes[offset],
                    "position": value_bytes[offset + 1],
                }
            )
            offset += 2
        if offset >= len(value_bytes):
            raise ValueError("missing channel count")
        max_num_of_channels = value_bytes[offset]
        offset += 1
        if offset >= len(value_bytes):
            raise ValueError("missing MSL length")
        msl_length = value_bytes[offset]
        offset += 1
        if offset + msl_length > len(value_bytes):
            raise ValueError("invalid MSL length")
        msl_value_bytes = value_bytes[offset : offset + msl_length]
        offset += msl_length
        if offset >= len(value_bytes):
            raise ValueError("missing TAR length")
        tar_data_length = value_bytes[offset]
        offset += 1
        if offset + tar_data_length > len(value_bytes):
            raise ValueError("invalid TAR length")
        tar_end = offset + tar_data_length
        if tar_data_length % 3 != 0:
            raise ValueError("TAR values must be 3-byte aligned")
        tar_values: list[str] = []
        while offset < tar_end:
            tar_values.append(value_bytes[offset : offset + 3].hex().upper())
            offset += 3
        trailing_padding = b""
        if offset != len(value_bytes):
            trailing_padding = value_bytes[offset:]
            if any(byte_value != 0x00 for byte_value in trailing_padding):
                raise ValueError("invalid non-zero toolkit trailing bytes")
        decoded.update(
            {
                "accessDomain": access_domain.hex().upper(),
                "priorityLevelOfToolkitAppInstance": priority_level,
                "maxNumberOfTimers": max_num_of_timers,
                "maxTextLengthForMenuEntry": max_text_length,
                "menuEntries": menu_entries,
                "maxNumberOfChannels": max_num_of_channels,
                "minimumSecurityLevelRaw": msl_value_bytes.hex().upper(),
                "tarValues": tar_values,
            }
        )
        if len(msl_value_bytes) >= 1:
            decoded["minimumSecurityLevelInferred"] = f"0x{msl_value_bytes[-1]:02X}"
            decoded["minimumSecurityLevelDecimal"] = msl_value_bytes[-1]
        if len(tar_values) > 0:
            decoded["tarInferred"] = tar_values[0]
        if len(trailing_padding) > 0:
            decoded["trailingPadding"] = trailing_padding.hex().upper()
        return decoded
    except Exception:
        decoded["bytes"] = [f"0x{byte_value:02X}" for byte_value in value_bytes]
        for index in range(0, max(0, len(value_bytes) - 2)):
            if value_bytes[index] == 0x02 and value_bytes[index + 1] == 0x01:
                decoded["minimumSecurityLevelInferred"] = f"0x{value_bytes[index + 2]:02X}"
                decoded["minimumSecurityLevelDecimal"] = value_bytes[index + 2]
                break
        tar_index = value_bytes.find(bytes.fromhex("B20100"))
        if tar_index != -1:
            decoded["tarInferred"] = value_bytes[tar_index : tar_index + 3].hex().upper()
        return decoded


_RESTRICT_PARAMETER_BITS: dict[int, str] = {
    0x01: "Restrict Open Personalisation",
    0x02: "Restrict Contactless Self-Activation",
}


def _decode_restrict_parameter(value_bytes: bytes) -> dict[str, object] | None:
    """SAIP §8.6.6 / GlobalPlatform Card Spec Amd F §A.4 — single-byte
    bitmap governing the Security Domain ``openPersoData`` behaviour.

    Only the two standards-assigned bits are labelled; all remaining bits
    are marked RFU so misconfigured profiles surface unambiguously in the
    edit-decoded TUI.
    """

    if len(value_bytes) != 1:
        return None
    mask = value_bytes[0]
    active = [name for bit, name in _RESTRICT_PARAMETER_BITS.items() if mask & bit]
    rfu_bits = mask & ~(0x01 | 0x02)
    decoded: dict[str, object] = {
        "format": "Restrict Parameter",
        "reference": "SAIP §8.6.6 / GlobalPlatform Amd F §A.4",
        "hex": value_bytes.hex().upper(),
        "length": 1,
        "bitmap": f"0x{mask:02X}",
        "activeRestrictions": active,
        "rfuBitsMask": f"0x{rfu_bits:02X}",
        "summary": (
            f"0x{mask:02X} -> {', '.join(active) if active else 'no restrictions'}"
        ),
    }
    if rfu_bits != 0:
        decoded["rfuBitsSet"] = True
    return decoded


_GP_MEMORY_QUOTA_FIELD_LABELS: dict[str, str] = {
    "volatileMemoryQuotaC7": "GP Amd A volatile memory quota (C7)",
    "nonVolatileMemoryQuotaC8": "GP Amd A non-volatile memory quota (C8)",
    "volatileReservedMemory": "GP Amd A volatile reserved memory",
    "nonVolatileReservedMemory": "GP Amd A non-volatile reserved memory",
    "cumulativeGrantedVolatileMemory": "GP Amd C cumulative granted volatile memory",
    "cumulativeGrantedNonVolatileMemory": "GP Amd C cumulative granted non-volatile memory",
}


def _decode_gp_memory_quota_field(
    field_name: str,
    value_bytes: bytes,
) -> dict[str, object] | None:
    """GlobalPlatform Amd A §5.1.2 / Amd C — ``ApplicationSystemParameters``
    memory quota fields.

    Each entry is a 2..4 byte network-byte-order unsigned integer giving
    the quota (or reservation) in bytes. Surface both the hex form and
    the decoded decimal value so the editor can display the quota at a
    glance without dropping the round-trip hex.
    """

    label = _GP_MEMORY_QUOTA_FIELD_LABELS.get(field_name)
    if label is None:
        return None
    if len(value_bytes) < 2 or len(value_bytes) > 4:
        return None
    decimal_value = int.from_bytes(value_bytes, "big", signed=False)
    return {
        "format": label,
        "reference": "GlobalPlatform Card Spec Amd A §5.1.2 / Amd C",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "decimal": decimal_value,
        "summary": f"{decimal_value} byte(s)",
    }


_ACCESS_DOMAIN_DOMAIN_LABELS: dict[int, str] = {
    0x00: "Full access to the UICC file system",
    0x02: "Access granted to CHV references (3G/UICC)",
    0xFF: "No access to the UICC file system",
}


def _decode_access_domain_record(value_bytes: bytes) -> dict[str, object]:
    """Decode a single TS 102 226 §8.2.1.3.2.2 Access Domain record.

    The first byte is the Access Domain identifier. When ``0x02`` follows
    a 4-byte CHV reference bitmap so the decoder surfaces both the raw
    bytes and the well-known label. Unknown identifiers are flagged but
    still round-trip via the ``hex`` field.
    """

    record: dict[str, object] = {
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    if len(value_bytes) == 0:
        record["summary"] = "empty access domain"
        return record
    domain_byte = value_bytes[0]
    label = _ACCESS_DOMAIN_DOMAIN_LABELS.get(
        domain_byte, f"Proprietary / RFU (0x{domain_byte:02X})"
    )
    record["domainByte"] = f"0x{domain_byte:02X}"
    record["domainLabel"] = label
    tail = value_bytes[1:]
    if len(tail) > 0:
        record["parameters"] = tail.hex().upper()
    if domain_byte == 0x02 and len(tail) == 4:
        record["chvReferenceBitmap"] = tail.hex().upper()
    record["summary"] = label
    return record


def _decode_ts102226_sim_file_access_toolkit_parameter(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """TS 102 226 §8.2.1.3.2.3 / TS 51.011 clause A.1.2.3 — combined SIM
    Toolkit Application + SIM File Access parameters.

    Structure::

        1 byte  : length N1 of SIM Toolkit Application Parameters
        N1 bytes: SIM Toolkit Application Parameters (opaque)
        1 byte  : length N2 of SIM File Access Parameters
        N2 bytes: SIM File Access Parameters (opaque)

    The inner payloads carry vendor-specific sub-fields so the decoder
    surfaces them as hex blobs with their declared length. When the outer
    structure does not parse cleanly, return ``None`` so the caller can
    fall back to the opaque blob view instead of emitting a misleading
    partial decode.
    """

    if len(value_bytes) < 2:
        return None
    try:
        offset = 0
        toolkit_length = value_bytes[offset]
        offset += 1
        if offset + toolkit_length > len(value_bytes):
            return None
        toolkit_payload = value_bytes[offset : offset + toolkit_length]
        offset += toolkit_length
        if offset >= len(value_bytes):
            return None
        file_access_length = value_bytes[offset]
        offset += 1
        if offset + file_access_length > len(value_bytes):
            return None
        file_access_payload = value_bytes[offset : offset + file_access_length]
        offset += file_access_length
    except IndexError:
        return None
    trailing = value_bytes[offset:]
    decoded: dict[str, object] = {
        "format": "TS 102 226 SIM File Access & Toolkit Application parameters",
        "reference": "TS 102 226 §8.2.1.3.2.3 / TS 51.011 Annex A.1.2.3",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "simToolkitApplicationParameters": {
            "length": toolkit_length,
            "hex": toolkit_payload.hex().upper(),
        },
        "simFileAccessParameters": {
            "length": file_access_length,
            "hex": file_access_payload.hex().upper(),
        },
    }
    if len(trailing) > 0:
        decoded["trailingBytes"] = trailing.hex().upper()
    decoded["summary"] = (
        f"toolkit={toolkit_length} B, fileAccess={file_access_length} B"
    )
    return decoded


def _decode_uicc_access_application_specific_parameters(
    value_bytes: bytes,
    *,
    administrative: bool,
) -> dict[str, object] | None:
    """TS 102 226 §8.2.1.3.2.2 — UICC access application-specific
    parameters (regular and administrative variants).

    Structure (same for both variants)::

        1 byte   : length N of the UICC File System Access Domain payload
        N bytes  : Access Domain record (see :func:`_decode_access_domain_record`)

    When a trailing length + access-domain pair is present (some vendor
    profiles concatenate a second Access Domain record for DAP / shared
    access), decode it as an additional record rather than dropping the
    bytes on the floor.
    """

    if len(value_bytes) == 0:
        return None
    try:
        offset = 0
        records: list[dict[str, object]] = []
        while offset < len(value_bytes):
            record_length = value_bytes[offset]
            offset += 1
            if offset + record_length > len(value_bytes):
                return None
            record_bytes = value_bytes[offset : offset + record_length]
            offset += record_length
            record = _decode_access_domain_record(record_bytes)
            record["declaredLength"] = record_length
            records.append(record)
    except IndexError:
        return None
    if len(records) == 0:
        return None
    label = (
        "UICC administrative access application-specific parameters"
        if administrative
        else "UICC access application-specific parameters"
    )
    summary_parts = [
        str(record.get("domainLabel") or record.get("summary") or "?")
        for record in records
    ]
    return {
        "format": label,
        "reference": "TS 102 226 §8.2.1.3.2.2",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "accessDomainRecords": records,
        "summary": " | ".join(summary_parts) if summary_parts else label,
    }


def _decode_application_provider_identifier(value_bytes: bytes) -> dict[str, object] | None:
    """SAIP §2.8.2 — ``applicationProviderIdentifier`` is an ASN.1
    OBJECT IDENTIFIER octet string. Surface the OID dotted form so the
    edit-decoded TUI can display the provider arc (e.g. GSMA eUICC arc).
    """

    if len(value_bytes) == 0:
        return None
    oid = _decode_oid(value_bytes)
    decoded: dict[str, object] = {
        "format": "Application Provider OID",
        "reference": "SAIP §2.8.2",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
    }
    if oid is not None:
        decoded["oid"] = oid
        decoded["summary"] = oid
    else:
        decoded["summary"] = value_bytes.hex().upper()
    return decoded


_GLOBAL_SERVICE_BITS: dict[int, str] = {
    0x80: "Global PIN",
    0x40: "Universal PIN",
    0x20: "Secure messaging",
    0x10: "OMA DM",
    0x08: "Application selection assisted",
    0x04: "Data object management (DOR)",
    0x02: "Reserved bit 1",
    0x01: "Reserved bit 0",
}


def _decode_global_service_parameters(value_bytes: bytes) -> dict[str, object] | None:
    """SAIP §2.6.3 — single-byte bitmap of global services supported by the
    profile. Map each set bit to the service name per Table 2-6."""

    if len(value_bytes) != 1:
        return None
    mask = value_bytes[0]
    active = [name for bit, name in _GLOBAL_SERVICE_BITS.items() if mask & bit]
    return {
        "format": "Global Service Parameters",
        "reference": "SAIP §2.6.3 Table 2-6",
        "hex": value_bytes.hex().upper(),
        "length": 1,
        "bitmap": f"0x{mask:02X}",
        "activeServices": active,
        "summary": f"0x{mask:02X} -> {', '.join(active) if active else 'none'}",
    }


def _decode_implicit_selection_parameter(value_bytes: bytes) -> dict[str, object] | None:
    """GlobalPlatform Card Spec Amd A §A.3 — single-byte implicit selection
    parameter. bit8 distinguishes default application vs. explicit AID
    selection, bits 1-5 carry the channel mask."""

    if len(value_bytes) != 1:
        return None
    value = value_bytes[0]
    default_selected = bool(value & 0x80)
    channel_mask = value & 0x1F
    return {
        "format": "Implicit Selection Parameter",
        "reference": "GlobalPlatform Card Spec Amd A §A.3",
        "hex": value_bytes.hex().upper(),
        "length": 1,
        "defaultSelected": default_selected,
        "channelMask": f"0x{channel_mask:02X}",
        "summary": (
            f"default={default_selected}, channels=0x{channel_mask:02X}"
        ),
    }


def _decode_contactless_protocol_parameters(value_bytes: bytes) -> dict[str, object] | None:
    """GlobalPlatform Card Spec Amd C §5 — BER-TLV wrapping NFC contactless
    protocol data (AID, protocol type, routing)."""

    if len(value_bytes) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names={
            "80": "Contactless Protocol Type",
            "81": "Contactless Protocol Parameters",
            "82": "Application Selector AID",
            "83": "ATS / ATR Profile",
            "A0": "Group Entry",
        },
    )
    parsed_ok = any(
        not (isinstance(entry, dict) and entry.get("parseErrorOffset") is not None)
        for entry in items
    )
    if not parsed_ok:
        return None
    return {
        "format": "Contactless Protocol Parameters",
        "reference": "GlobalPlatform Card Spec Amd C §5",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "items": items,
    }


def _decode_user_interaction_contactless_parameters(
    value_bytes: bytes,
) -> dict[str, object] | None:
    """GlobalPlatform Card Spec Amd C §6 — User interaction parameters.

    Structure is a BER-TLV stream carrying the contactless user-interaction
    fields: display required flag, CREL application AID, display-content
    policies, application name, icon reference and localised labels.
    Unknown tags are preserved as raw hex so downstream tooling still sees
    every byte.
    """

    if len(value_bytes) == 0:
        return None
    items = _decode_field_ber_tlv_stream(
        value_bytes,
        tag_names={
            "80": "Display Required Indicator",
            "81": "CREL Application AID",
            "82": "Application Display Name",
            "83": "Application Icon Reference",
            "84": "Display Message (LID)",
            "85": "Contactless Off Display Message",
            "A0": "User Interaction Group",
        },
        value_decoders={
            "82": _tlv_value_decoder_text,
            "84": _tlv_value_decoder_text,
            "85": _tlv_value_decoder_text,
        },
    )
    parsed_ok = any(
        not (isinstance(entry, dict) and entry.get("parseErrorOffset") is not None)
        for entry in items
    )
    if not parsed_ok:
        return None
    return {
        "format": "User Interaction Contactless Parameters",
        "reference": "GlobalPlatform Card Spec Amd C §6",
        "hex": value_bytes.hex().upper(),
        "length": len(value_bytes),
        "items": items,
    }


def _decode_special_field(
    field_name: str | None,
    value_bytes: bytes,
    *,
    parent_hint: str | None = None,
) -> dict[str, object] | None:
    key = str(field_name or "").strip()
    if key == "iccid":
        return _decode_profile_iccid(value_bytes)
    if key == "pol":
        return _decode_profile_policy_rules(value_bytes)
    if key == "connectivityParameters":
        return _decode_connectivity_parameters(value_bytes)
    if key == "applicationSpecificParametersC9":
        return _decode_sd_install_parameters(value_bytes)
    if key == "uiccToolkitApplicationSpecificParametersField":
        return _decode_uicc_toolkit_parameters(value_bytes)
    if key == "pinStatusTemplateDO":
        return _decode_pin_status_template_do(value_bytes)
    if key == "applicationProviderIdentifier":
        decoded = _decode_application_provider_identifier(value_bytes)
        if decoded is not None:
            return decoded
    if key == "globalServiceParameters":
        decoded = _decode_global_service_parameters(value_bytes)
        if decoded is not None:
            return decoded
    if key == "implicitSelectionParameter":
        decoded = _decode_implicit_selection_parameter(value_bytes)
        if decoded is not None:
            return decoded
    if key == "contactlessProtocolParameters":
        decoded = _decode_contactless_protocol_parameters(value_bytes)
        if decoded is not None:
            return decoded
    if key == "userInteractionContactlessParameters":
        decoded = _decode_user_interaction_contactless_parameters(value_bytes)
        if decoded is not None:
            return decoded
    if key == "restrictParameter":
        decoded = _decode_restrict_parameter(value_bytes)
        if decoded is not None:
            return decoded
    if key in _GP_MEMORY_QUOTA_FIELD_LABELS:
        decoded = _decode_gp_memory_quota_field(key, value_bytes)
        if decoded is not None:
            return decoded
    if key == "ts102226SIMFileAccessToolkitParameter":
        decoded = _decode_ts102226_sim_file_access_toolkit_parameter(value_bytes)
        if decoded is not None:
            return decoded
    if key == "uiccAccessApplicationSpecificParametersField":
        decoded = _decode_uicc_access_application_specific_parameters(
            value_bytes,
            administrative=False,
        )
        if decoded is not None:
            return decoded
    if key == "uiccAdministrativeAccessApplicationSpecificParametersField":
        decoded = _decode_uicc_access_application_specific_parameters(
            value_bytes,
            administrative=True,
        )
        if decoded is not None:
            return decoded
    if key == "fileID":
        return _decode_file_identifier(value_bytes, parent_hint=parent_hint)
    if key == "securityAttributesReferenced":
        return _decode_security_attributes_referenced(
            value_bytes,
            parent_hint=parent_hint,
        )
    if key == "filePath":
        return _decode_file_path(value_bytes, parent_hint=parent_hint)
    if key == "linkPath":
        return _decode_link_path(value_bytes, parent_hint=parent_hint)
    if key == "specialFileInformation":
        return _decode_special_file_information(value_bytes)
    if key == "fillPattern":
        return _decode_fill_pattern(value_bytes, repeat_pattern=False)
    if key == "repeatPattern":
        return _decode_fill_pattern(value_bytes, repeat_pattern=True)
    if key == "fileDetails":
        return _decode_file_details(value_bytes)
    if key == "algorithmOptions":
        return _decode_aka_option_octet(value_bytes, format_name="AKA algorithm options")
    if key == "key":
        return _decode_aka_secret_material(value_bytes, format_name="AKA secret key material")
    if key == "opc":
        return _decode_aka_secret_material(value_bytes, format_name="AKA operator variant key")
    if key == "authCounterMax":
        return _decode_aka_counter_field(value_bytes, format_name="AKA authentication counter max")
    if key == "rotationConstants":
        return _decode_rotation_constants(value_bytes)
    if key == "xoringConstants":
        return _decode_xoring_constants(value_bytes)
    if key == "fileDescriptor":
        return _decode_file_descriptor(value_bytes)
    if key == "efFileSize":
        return _decode_ef_file_size(value_bytes)
    if key == "shortEFID":
        return _decode_short_efid(value_bytes)
    if key == "lcsi":
        return _decode_lcsi(value_bytes)
    if key == "minimumSecurityLevel":
        return _decode_minimum_security_level(value_bytes)
    if key == "sqnOptions":
        return _decode_aka_option_octet(value_bytes, format_name="SQN options")
    if key == "sqnDelta":
        return _decode_aka_counter_field(value_bytes, format_name="SQN delta")
    if key == "sqnAgeLimit":
        return _decode_aka_counter_field(value_bytes, format_name="SQN age limit")
    if key == "sqnInit":
        return _decode_aka_counter_field(value_bytes, format_name="SQN initial value")
    if key == "tarList":
        return _decode_tar_value(value_bytes)
    if key in {
        "uiccAccessDomain",
        "uiccAdminAccessDomain",
        "adfAccessDomain",
        "adfAdminAccessDomain",
    }:
        return _decode_access_domain(value_bytes)
    memory_limit = _decode_memory_limit_field(key, value_bytes)
    if memory_limit is not None:
        return memory_limit
    if key == "keyData":
        return _decode_key_data(value_bytes)
    if key in {"pinValue", "pukValue"}:
        return _decode_pin_secret_value(value_bytes)
    if key in _AID_FIELD_NAMES:
        return _decode_application_identifier(value_bytes)
    if key in _PASSTHROUGH_BYTES_FIELD_NAMES:
        return _summarize_binary_blob(value_bytes)
    return None


def _decode_scalar_special_field(field_name: str | None, value: Any) -> dict[str, object] | None:
    key = str(field_name or "").strip()
    if key == "applicationPrivileges":
        return _decode_application_privileges(value)
    if key == "lifeCycleState":
        return _decode_life_cycle_state(value)
    if key == "algorithmID":
        return _decode_aka_algorithm_id(value)
    if key == "numberOfKeccak":
        return _decode_aka_counter_field(value, format_name="TUAK Keccak iterations")
    if key == "pol":
        return _decode_profile_policy_rules(value)
    if key == "pinAttributes":
        return _decode_pin_attributes(value)
    if key in {"maxNumOfAttemps-retryNumLeft", "maxNumOfAttempts-retryNumLeft"}:
        return _decode_pin_puk_retry_counter(value)
    if key == "macLength":
        return _decode_mac_length(value)
    memory_limit = _decode_memory_limit_field(key, value)
    if memory_limit is not None:
        return memory_limit
    if key == "fillFileOffset":
        return _decode_fill_file_offset(value)
    if key == "unblockingPINReference":
        return _decode_puk_key_reference(value)
    if key == "keyReference":
        return _decode_pin_puk_adm_key_reference(value)
    if key == "keyUsageQualifier":
        return _decode_key_usage_qualifier(value)
    if key == "keyAccess":
        return _decode_key_access(value)
    if key == "keyIdentifier":
        return _decode_key_identifier(value)
    if key == "keyVersionNumber":
        return _decode_key_version_number(value)
    if key == "keyCounterValue":
        return _decode_key_counter_value(value)
    if key == "keyType":
        return _decode_key_type(value)
    return None


def _try_decode_x509_certificate(value_bytes: bytes) -> dict[str, object] | None:
    try:
        from cryptography import x509
    except ImportError:
        return None
    try:
        certificate = x509.load_der_x509_certificate(value_bytes)
    except Exception:
        return None
    not_before = getattr(certificate, "not_valid_before_utc", None) or getattr(
        certificate,
        "not_valid_before",
        None,
    )
    not_after = getattr(certificate, "not_valid_after_utc", None) or getattr(
        certificate,
        "not_valid_after",
        None,
    )
    decoded = {
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "serialNumber": hex(certificate.serial_number),
    }
    if not_before is not None:
        decoded["notBefore"] = not_before.isoformat()
    if not_after is not None:
        decoded["notAfter"] = not_after.isoformat()
    return decoded


def _summarize_binary_blob(
    value_bytes: bytes,
    *,
    infer_text: bool = False,
    infer_bcd: bool = False,
) -> dict[str, object]:
    """Summarise an opaque binary field.

    Historical revisions always attempted an ASCII decode and a BCD
    nibble decode in addition to the ``length`` + ``hex`` pair. That
    rendered key material (``authenticationKey`` / ``ssd`` / SCP
    parameters) with misleading ASCII or BCD text whenever the random
    byte pattern happened to match the heuristic.

    Inference is now strictly opt-in:

    * ``infer_text=True``  — caller has spec evidence the field is
      text (UTF-8 / ASCII identifier, e.g. ``applicationLabel``).
    * ``infer_bcd=True``   — caller has spec evidence the field is
      BCD-encoded digits (e.g. ``dialledNumber``).
    """

    summary: dict[str, object] = {
        "length": len(value_bytes),
        "hex": value_bytes.hex().upper(),
    }
    if infer_text:
        ascii_text = _decode_printable_ascii(value_bytes)
        if ascii_text not in (None, ""):
            summary["ascii"] = ascii_text
    if infer_bcd and _looks_like_bcd_bytes(value_bytes):
        digits = _decode_bcd_digits(value_bytes)
        if digits != "":
            summary["bcdDigits"] = digits
    return summary


def _filesystem_hint(pe_base: str) -> str | None:
    mapping: dict[str, str] = {
        "telecom": "MF/TELECOM",
        "phonebook": "MF/TELECOM/PHONEBOOK",
        "graphics": "MF/TELECOM/GRAPHICS",
        "multimedia": "MF/TELECOM/MULTIMEDIA",
        "mmss": "MF/TELECOM/MMSS",
        "cd": "MF/CD",
        "df-5gs": "MF/USIM/5GS",
        "df-snpn": "MF/USIM/SNPN",
        "df-saip": "MF/USIM/SAIP",
        "df-5gprose": "MF/USIM/5G_PROSE",
        "eap": "MF/USIM/EAP",
        "isim": "MF/ISIM",
        "opt-isim": "MF/ISIM",
        "mcs": "MF/USIM/MCS",
        "v2x": "MF/USIM/V2X",
        "a2x": "MF/USIM/A2X",
        # 5x20 Pass C — additional PE filesystem hints.
        "usim": "MF/USIM",
        "opt-usim": "MF/USIM",
        "csim": "MF/CSIM",
        "opt-csim": "MF/CSIM",
        "opt-eap": "MF/USIM/EAP",
        "cdmaParameter": "MF/CSIM",
        "gsm-access": "MF/USIM/GSM-ACCESS",
        "wlan": "MF/USIM/WLAN",
        "df-wlan": "MF/USIM/WLAN",
        "df-prose": "MF/USIM/PROSE",
        "df-iot": "MF/USIM/IOT",
        "df-hnb": "MF/USIM/HNB",
        "df-mcs": "MF/USIM/MCS",
        "df-mcptt": "MF/USIM/MCPTT",
        "df-mcvideo": "MF/USIM/MCVIDEO",
        "df-mcdata": "MF/USIM/MCDATA",
        "df-v2x": "MF/USIM/V2X",
        "df-a2x": "MF/USIM/A2X",
        "df-telecom": "MF/TELECOM",
        "df-phonebook": "MF/TELECOM/PHONEBOOK",
        "df-graphics": "MF/TELECOM/GRAPHICS",
        "df-mms": "MF/TELECOM/MMS",
        "df-solsa": "MF/USIM/SOLSA",
        "df-mexe": "MF/TELECOM/MEXE",
        "df-oma-bcast": "MF/USIM/OMA-BCAST",
        "df-ecat": "MF/USIM/ECAT",
        "df-5gprose-relay": "MF/USIM/5G_PROSE_RELAY",
        "df-hpsim": "MF/HPSIM",
        "adf-hpsim": "MF/ADF_HPSIM",
        "adf-mcptt": "MF/ADF_MCPTT",
        "adf-mcvideo": "MF/ADF_MCVIDEO",
        "adf-mcdata": "MF/ADF_MCDATA",
        "adf-v2x": "MF/ADF_V2X",
        "adf-prose-ue": "MF/ADF_PROSE_UE",
        "adf-prose-relay": "MF/ADF_PROSE_RELAY",
        "adf-5gprose-relay": "MF/ADF_5G_PROSE_RELAY",
        "adf-5gprose-disc": "MF/ADF_5G_PROSE_DISC",
        "adf-iot": "MF/ADF_IOT",
        "adf-dualimsi": "MF/ADF_DUALIMSI",
        "adf-cl": "MF/ADF_CL",
        "adf-a2x": "MF/ADF_A2X",
        "adf-eap": "MF/ADF_EAP",
        "adf-test": "MF/ADF_TEST",
        "adf-snpn": "MF/ADF_SNPN",
        "adf-orph": "MF/ADF_ORPH",
        "application": "MF/APP",
        "rfm": "RFM",
        "securityDomain": "GP_SD",
        "akaParameter": "MF/USIM",
        "cdma": "MF/CSIM",
    }
    return mapping.get(pe_base)


def _fid_for_ef_key(pe_section_key: str, ef_key: str) -> str | None:
    pe_base = base_pe_type(pe_section_key)
    if ef_key == "ef-arr":
        if pe_base == "mf":
            return "2F06"
        return "6F06"
    return _EF_KEY_TO_FID.get(ef_key)


def _last_non_index_token(path_tail: list[str]) -> str | None:
    for token in reversed(path_tail):
        text = str(token)
        if text.startswith("["):
            continue
        if text == "fillFileContent":
            continue
        return text
    return None


def _format_hit_title(
    pe_section_key: str,
    path_tail: list[str],
    *,
    fallback: str,
) -> str:
    section_label = humanize_saip_display_name(pe_section_key)
    path_tokens = list(path_tail)
    if len(path_tokens) > 0:
        if str(path_tokens[0]).strip() == str(pe_section_key).strip():
            path_tokens = path_tokens[1:]
    path_label = humanize_saip_display_path(path_tokens)
    if path_label is None:
        path_label = fallback
    return f"{section_label} :: {path_label}"


def _updated_sequence_fid(current_fid: str | None, child: Any) -> str | None:
    if isinstance(child, dict) is False:
        return current_fid
    keys_structural = set(_structural_data_keys(child))
    if keys_structural != {_TAG_TUPLE}:
        return current_fid
    inner = _value_first(child, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
    if isinstance(inner, list) is False or len(inner) < 2:
        return current_fid
    tag = str(inner[0])
    payload = inner[1]
    if tag == "filePath":
        return None
    if tag != "createFCP":
        return current_fid
    if isinstance(payload, dict) is False:
        return None
    file_id = payload.get("fileID")
    if isinstance(file_id, dict) is False:
        return None
    file_id_hex = _hex_from_tagged_bytes(file_id)
    if file_id_hex is None:
        return None
    return file_id_hex.upper()


def _decode_one_blob(
    hex_clean: str,
    *,
    pe_section_key: str,
    path_tail: list[str],
    last_ef_key: str | None,
    last_fid: str | None,
) -> list[str]:
    value_bytes = bytes.fromhex(hex_clean)
    field_name = _last_non_index_token(path_tail)
    fid = str(last_fid or "").strip().upper() or None
    ef_guess = last_ef_key
    if ef_guess is None and field_name is not None and field_name.startswith("ef-"):
        ef_guess = field_name
    if fid is None and ef_guess is not None:
        fid = _fid_for_ef_key(pe_section_key, ef_guess)

    parent_hint = _parent_hint_from_path(
        pe_section_key=pe_section_key,
        last_ef_key=ef_guess,
    )

    blocks: list[str] = []
    known_ef = None
    if "fillFileContent" in path_tail or (field_name is not None and field_name.startswith("ef-")):
        known_ef = _decode_known_ef_payload(
            ef_key=ef_guess,
            fid=fid,
            hex_clean=hex_clean,
            parent_hint=parent_hint,
        )
    if known_ef is not None:
        blocks.extend(_compact_block("EF payload", known_ef))
    field_semantics = _decode_special_field(
        field_name,
        value_bytes,
        parent_hint=parent_hint,
    )
    if field_semantics is None:
        field_semantics = _decode_scalar_special_field(field_name, value_bytes)
    if field_semantics is not None:
        if len(blocks) > 0:
            blocks.append("")
        blocks.extend(_compact_block("Field semantics", field_semantics))

    certificate = _try_decode_x509_certificate(value_bytes)
    if certificate is not None:
        if len(blocks) > 0:
            blocks.append("")
        blocks.extend(_compact_block("X.509 certificate", certificate))

    generic_asn1 = _decode_generic_asn1_blob(value_bytes)
    if generic_asn1 is not None:
        if len(blocks) > 0:
            blocks.append("")
        blocks.extend(_compact_block("ASN.1 / BER", generic_asn1))

    if len(blocks) == 0:
        blocks.extend(_compact_block("Binary summary", _summarize_binary_blob(value_bytes)))
    return blocks


def _walk(
    value: Any,
    pe_section_key: str,
    path_tail: list[str],
    last_ef_key: str | None,
    last_fid: str | None,
    out: list[tuple[str, list[str]]],
    max_hits: int | None,
) -> None:
    if max_hits is not None and len(out) >= max_hits:
        return

    if isinstance(value, dict):
        keys_structural = set(_structural_data_keys(value))
        if keys_structural == {_TAG_BYTES}:
            hx = _hex_from_tagged_bytes(value)
            if hx is None:
                return
            lines = _decode_one_blob(
                hx,
                pe_section_key=pe_section_key,
                path_tail=path_tail,
                last_ef_key=last_ef_key,
                last_fid=last_fid,
            )
            if len(lines) > 0:
                out.append(
                    (
                        _format_hit_title(
                            pe_section_key,
                            path_tail,
                            fallback="(bytes)",
                        ),
                        lines,
                    )
                )
            return

        if keys_structural == {_TAG_TUPLE}:
            inner = _value_first(value, _TAG_TUPLE, _LEGACY_TAG_TUPLE)
            if isinstance(inner, list) and len(inner) >= 2:
                tag = inner[0]
                payload = inner[1]
                if tag == "fillFileContent":
                    _walk(
                        payload,
                        pe_section_key,
                        path_tail + ["fillFileContent"],
                        last_ef_key,
                        last_fid,
                        out,
                        max_hits,
                    )
                    return
                _walk(
                    payload,
                    pe_section_key,
                    path_tail + [str(tag)],
                    last_ef_key,
                    last_fid,
                    out,
                    max_hits,
                )
            return

        for key, child in value.items():
            key_text = str(key)
            if key_text.startswith("__ygg_"):
                continue
            next_ef = last_ef_key
            if key_text.startswith("ef-"):
                next_ef = key_text
            next_fid = last_fid
            if next_ef is not None and next_ef != last_ef_key:
                next_fid = _fid_for_ef_key(pe_section_key, next_ef)
            _walk(child, pe_section_key, path_tail + [key_text], next_ef, next_fid, out, max_hits)
        return

    if isinstance(value, list):
        sequence_fid = last_fid
        for index, child in enumerate(value):
            sequence_fid = _updated_sequence_fid(sequence_fid, child)
            _walk(
                child,
                pe_section_key,
                path_tail + [f"[{index}]"],
                last_ef_key,
                sequence_fid,
                out,
                max_hits,
            )
        return

    field_name = _last_non_index_token(path_tail)
    scalar_semantics = _decode_scalar_special_field(field_name, value)
    if scalar_semantics is None:
        return
    lines = _compact_block("Field semantics", scalar_semantics)
    out.append(
        (
            _format_hit_title(
                pe_section_key,
                path_tail,
                fallback="(value)",
            ),
            lines,
        )
    )


def build_profile_asn1_report(
    tagged_document: dict[str, Any],
    *,
    max_sections: int | None = None,
    max_hits_per_doc: int | None = None,
) -> str:
    """
    Produce plain-text decode lines for the TRANSCODE bottom panel.

    Expects a JSON-loaded root object (``intro`` / ``sections`` / meta).
    """
    sections = tagged_document.get("sections")
    if isinstance(sections, dict) is False:
        return "No sections object - cannot decode."

    hits: list[tuple[str, list[str]]] = []
    count_sections = 0
    for section_key, section_value in sections.items():
        if max_sections is not None and count_sections >= max_sections:
            break
        count_sections += 1
        sk = str(section_key)
        _walk(section_value, sk, [sk], None, None, hits, max_hits_per_doc)

    if len(hits) == 0:
        return (
            "No decodable tagged bytes or recognized field semantics found. Select a tagged "
            "hex value or open a profile containing EF fill content, BER/DER fields, "
            "certificate payloads, or known GlobalPlatform security domain fields."
        )

    if max_hits_per_doc is not None and len(hits) > max_hits_per_doc:
        visible = hits[:max_hits_per_doc]
        return _format_hits(visible).rstrip() + (
            f"\n\n[truncated: {len(hits)} hits, showing {max_hits_per_doc}]\n"
        )
    return _format_hits(hits)


def build_inspector_report_for_subtree(
    subtree: Any,
    pe_section_key: str,
    *,
    focus_path_hint: list[str] | None = None,
    last_ef_key: str | None = None,
    max_hits: int | None = None,
) -> str:
    """
    Decode tagged ``hex`` / ``__ygg_saip_bytes__`` values under a JSON subtree.

    This path is pure-Python and does not import ``SCP03`` or ``pySim``.
    """
    hits: list[tuple[str, list[str]]] = []
    path_tail = ["selection"]
    if focus_path_hint:
        path_tail = list(focus_path_hint)
    _walk(subtree, pe_section_key, path_tail, last_ef_key, None, hits, max_hits)
    if len(hits) == 0:
        if isinstance(subtree, dict):
            visible = [
                str(key)
                for key in subtree.keys()
                if str(key).startswith("__ygg_") is False and str(key) != "label"
            ]
            sample = ", ".join(visible[:10])
            suffix = " ..." if len(visible) > 10 else ""
            return (
                f"Plain object ({len(visible)} key(s)); no ASN.1-tagged bytes below.\n"
                f"Keys: {sample}{suffix}"
            )
        if isinstance(subtree, list):
            return (
                f"Plain list ({len(subtree)} item(s)); no ASN.1-tagged bytes below."
            )
        return ""
    return _format_hits(hits)
