# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Service-bit-table names for the UICC service tables the toolchain decodes.

One copy of the USIM, Enabled-Services, 5G ProSe, ISIM and legacy SIM service
tables, read from the clause text rather than restated per call site. Each
table carries the clause wording plus the short operator labels the live view
and the profile inspector have shipped, so a caller picks a style instead of
keeping a second dictionary.
"""

from __future__ import annotations

from typing import Final

# TS 31.102 v19.5 §4.2.8 -- EF.UST, services n°1 to n°152.
UST_SPEC_NAMES: Final[dict[int, str]] = {
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
    33: "shall be set to '1'",
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
    109: "Mission Critical Services",
    110: "ePDG configuration Information for Emergency Service support",
    111: "ePDG configuration Information for Emergency Service configured",
    112: "eCall Data over IMS",
    113: "URI support for SMS-PP DOWNLOAD as defined in TS 31.111",
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
    127: "Control plane-based steering of UE in VPLMN",
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
    145: "KAUSF derivation configuration",
    146: "Network Identifier for SNPN (NID)",
    147: "5MBS UE pre-configuration",
    148: "UE configured for using \"Operator controlled signal threshold per access technology\"",
    149: "A2X",
    150: "IMS Data Channel Indication",
    151: "Operator-controlled-LSP-PLMN",
    152: "PeriodicSearchTimerNonLSP",
}

# Operator labels the GUI checklist and the pinned tests read; every
# other service number falls back to the clause wording above.
UST_SHORT_LABELS: Final[dict[int, str]] = {
    2: "FDN",
    5: "Extension 3",
    7: "Extension 4",
    23: "Localised Service Areas (SoLSA)",
    24: "Enhanced Multi-Level Precedence and Pre-emption",
    32: "RUN AT COMMAND",
    33: "Reserved (shall be set)",
    50: "Reserved (ignore)",
    56: "Network indication of alerting (NIA)",
    57: "VGCS Group Identifier List",
    58: "VBS Group Identifier List",
    60: "User controlled PLMN selector for I-WLAN",
    61: "Operator controlled PLMN selector for I-WLAN",
    76: "GBA-based Local Key Establishment",
    86: "Allowed CSG Lists and indications",
    90: "Operator CSG Lists and indications",
    91: "SM-over-IP",
    92: "CSG Display Control",
    95: "UICC access to IMS",
    96: "NAS configuration by USIM",
    106: "ePDG configuration information support",
    107: "ePDG configuration information configured",
    110: "Emergency ePDG configuration support",
    111: "Emergency ePDG configuration configured",
    113: "URI support for SMS-PP DOWNLOAD",
    121: "EARFCN list for MTC/NB-IoT UEs",
    127: "Control-plane steering of UE in VPLMN",
    130: "SUPI of type NSI, GLI, or GCI",
    131: "Separate Home/Roaming 3GPP PS Data Off lists",
    132: "URSP by USIM",
    135: "Trusted non-3GPP access networks by USIM",
    136: "Multiple NAS security-context records",
    140: "Disaster roaming information in USIM",
    144: "Higher-priority PLMN multiplier for satellite NG-RAN",
    148: "Operator-controlled signal threshold per access technology",
}

# TS 31.102 v19.5 §4.2.47 -- EF.EST, services n°1 to n°3.
EST_SPEC_NAMES: Final[dict[int, str]] = {
    1: "Fixed Dialling Numbers (FDN)",
    2: "Barred Dialling Numbers (BDN)",
    3: "APN Control List (ACL)",
}

# TS 31.102 v19.5 §4.4.13.2 -- EF.5G_PROSE_ST, services n°1 to n°13.
PROSE_5G_SPEC_NAMES: Final[dict[int, str]] = {
    1: "5G ProSe configuration data for direct discovery",
    2: "5G ProSe configuration data for direct communication",
    3: "5G ProSe configuration data for UE-to-network relay UE",
    4: "5G ProSe configuration data for remote UE",
    5: "5G ProSe configuration data for usage information reporting",
    6: "5G ProSe configuration data for UE-to-UE relay UE",
    7: "5G ProSe configuration data for end UE",
    8: "UICC 5G ProSe direct communication usage information reporting",
    9: "5G ProSe configuration data for multi-hop UE-to-network relay UE",
    10: "5G ProSe configuration data for intermediate UE-to-network relay UE",
    11: "5G ProSe configuration data for multi-hop remote UE",
    12: "5G ProSe configuration data for multi-hop UE-to-UE relay UE",
    13: "5G ProSe configuration data for multi-hop UE-to-UE end UE",
}

# TS 31.103 v19 §4.2.7 -- EF.IST, services n°1 to n°22.
IST_SPEC_NAMES: Final[dict[int, str]] = {
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
    15: "Mission Critical Services",
    16: "URI support for SMS-PP DOWNLOAD as defined in 3GPP TS 31.111",
    17: "From Preferred",
    18: "IMS configuration data",
    19: "XCAP Configuration Data",
    20: "WebRTC URI",
    21: "MuD and MiD configuration data",
    22: "IMS Data Channel Indication",
}

# Short ISIM labels the live view has shipped; the rest fall back to
# the clause wording above.
IST_SHORT_LABELS: Final[dict[int, str]] = {
    2: "GBA",
    4: "GBA-based Local Key Establishment",
    5: "P-CSCF discovery for IMS Local Break Out",
    6: "SMS",
    7: "SMSR",
    8: "SM-over-IP via SMS-PP",
    9: "Communication Control for IMS",
    10: "UICC access to IMS",
    14: "URI support for MO SMS CONTROL",
    16: "URI support for SMS-PP DOWNLOAD",
    19: "XCAP configuration data",
    21: "MuD/MiD configuration data",
}

# TS 51.011 v4.15 §10.3.7 -- EF.SST, services n°1 to n°59. Two bits per
# service (allocated / activated), unlike the one-bit USIM tables.
SST_SPEC_NAMES: Final[dict[int, str]] = {
    1: "CHV1 disable function",
    2: "Abbreviated Dialling Numbers (ADN)",
    3: "Fixed Dialling Numbers (FDN)",
    4: "Short Message Storage (SMS)",
    5: "Advice of Charge (AoC)",
    6: "Capability Configuration Parameters (CCP)",
    7: "PLMN selector",
    8: "RFU",
    9: "MSISDN",
    10: "Extension1",
    11: "Extension2",
    12: "SMS Parameters",
    13: "Last Number Dialled (LND)",
    14: "Cell Broadcast Message Identifier",
    15: "Group Identifier Level 1",
    16: "Group Identifier Level 2",
    17: "Service Provider Name",
    18: "Service Dialling Numbers (SDN)",
    19: "Extension3",
    20: "RFU",
    21: "VGCS Group Identifier List (EFVGCS and EFVGCSS)",
    22: "VBS Group Identifier List (EFVBS and EFVBSS)",
    23: "enhanced Multi-Level Precedence and Pre-emption Service",
    24: "Automatic Answer for eMLPP",
    25: "Data download via SMS-CB",
    26: "Data download via SMS-PP",
    27: "Menu selection",
    28: "Call control",
    29: "Proactive SIM",
    30: "Cell Broadcast Message Identifier Ranges",
    31: "Barred Dialling Numbers (BDN)",
    32: "Extension4",
    33: "De-personalization Control Keys",
    34: "Co-operative Network List",
    35: "Short Message Status Reports",
    36: "Network's indication of alerting in the MS",
    37: "Mobile Originated Short Message control by SIM",
    38: "GPRS",
    39: "Image (IMG)",
    40: "SoLSA (Support of Local Service Area)",
    41: "USSD string data object supported in Call Control",
    42: "RUN AT COMMAND command",
    43: "User controlled PLMN Selector with Access Technology",
    44: "Operator controlled PLMN Selector with Access Technology",
    45: "HPLMN Selector with Access Technology",
    46: "CPBCCH Information",
    47: "Investigation Scan",
    48: "Extended Capability Configuration Parameters",
    49: "MExE",
    50: "Reserved and shall be ignored",
    51: "PLMN Network Name",
    52: "Operator PLMN List",
    53: "Mailbox Dialling Numbers",
    54: "Message Waiting Indication Status",
    55: "Call Forwarding Indication Status",
    56: "Service Provider Display Information",
    57: "Multimedia Messaging Service (MMS)",
    58: "Extension 8",
    59: "MMS User Connectivity Parameters",
}

# EF.EST ships the clause wording unchanged, so it carries no alias map.
EST_SHORT_LABELS: Final[dict[int, str]] = {}


# Table key -> (full name, clause citation, clause wording, short labels).
_TABLES: Final[dict[str, tuple[str, str, dict[int, str], dict[int, str]]]] = {
    "UST": (
        "USIM Service Table",
        "3GPP TS 31.102 \u00a74.2.8",
        UST_SPEC_NAMES,
        UST_SHORT_LABELS,
    ),
    "EST": (
        "Enabled Services Table",
        "3GPP TS 31.102 \u00a74.2.47",
        EST_SPEC_NAMES,
        EST_SHORT_LABELS,
    ),
    "IST": (
        "ISIM Service Table",
        "3GPP TS 31.103 \u00a74.2.7",
        IST_SPEC_NAMES,
        IST_SHORT_LABELS,
    ),
    "5G_PROSE_ST": (
        "5G ProSe Service Table",
        "3GPP TS 31.102 \u00a74.4.13.2",
        PROSE_5G_SPEC_NAMES,
        {},
    ),
    "SST": (
        "SIM Service Table",
        "3GPP TS 51.011 \u00a710.3.7",
        SST_SPEC_NAMES,
        {},
    ),
}

SERVICE_TABLE_KEYS: Final[tuple[str, ...]] = tuple(_TABLES)


def service_table_names(table: str, *, style: str = "short") -> dict[int, str]:
    """Return a fresh service-number to name map for ``table``.

    ``style`` is ``"short"`` for the operator labels the GUI and the shipped
    decoders read, or ``"spec"`` for the clause wording verbatim. An unknown
    table name returns an empty dict so a caller can treat it as "no map".
    """
    entry = _TABLES.get(str(table).upper())
    if entry is None:
        return {}
    _, _, spec_names, short_labels = entry
    if style == "spec":
        return dict(spec_names)
    if style != "short":
        raise ValueError("style must be 'short' or 'spec'.")
    merged = dict(spec_names)
    merged.update(short_labels)
    return merged


def service_table_metadata(table: str) -> tuple[str, str] | None:
    """Return ``(full name, clause citation)`` for ``table``, or ``None``."""
    entry = _TABLES.get(str(table).upper())
    if entry is None:
        return None
    return entry[0], entry[1]
