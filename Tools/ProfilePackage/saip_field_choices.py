# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Value choices for the members of a SAIP profile element.

A member whose values a specification enumerates gets a list, a member whose
bits carry meanings gets a bit editor, and a member the profile itself holds
candidates for (the AIDs it creates) gets suggestions. Each table cites the
clause it was read from. Where the specification leaves room (private-use
key types, application-specific life cycle states) the editor still takes
any value the ASN.1 type allows.

``annotate`` adds a ``widget`` to the nodes of a ``saip_structure_edit``
projection:

* ``{"kind": "select", "choices": [{"value", "label"}], "other": bool}``
* ``{"kind": "suggest", "choices": [...]}``: free entry with suggestions
* ``{"kind": "bits", "width": n, "integer": bool, "fields": [...]}``: each
  field has ``byte``, ``shift``, ``mask``, ``label`` and either ``options``
  (a list) or nothing (a check box for one bit, a number for several)
* ``{"kind": "file_descriptor"}``: the TS 102 221 file descriptor byte
* ``{"kind": "access_domain", "parameters", "keys"}``: TS 102 226 access domain
* ``{"kind": "card", "title"}``: a member a typed card of the element edits;
  the fields name it and point at the card
* ``{"kind": "flag"}`` for a NULL member, ``{"kind": "check"}`` for a BOOLEAN
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from .saip_security_domain_edit import KEY_TYPE_LABELS

Choice = dict[str, str]


def _choices(pairs: Iterable[tuple[str, str]]) -> list[Choice]:
    return [{"value": value, "label": label} for value, label in pairs]


# GP Card Spec v2.3.1 §11.1.1 Table 11-4 (page 147): application life cycle.
# b4-b7 of a SELECTABLE application are its own; LOCKED sets b8 over the
# state it locks.
_APPLICATION_LIFE_CYCLE = _choices((
    ("03", "INSTALLED"),
    ("07", "SELECTABLE"),
    ("83", "LOCKED"),
))

# GP Card Spec v2.3.1 §11.1.1 Table 11-5 (page 147): security domain life cycle.
_SECURITY_DOMAIN_LIFE_CYCLE = _choices((
    ("03", "INSTALLED"),
    ("07", "SELECTABLE"),
    ("0F", "PERSONALIZED"),
    ("83", "LOCKED"),
))


def _bit(byte: int, mask: int, label: str) -> dict[str, Any]:
    return {"byte": byte, "shift": (mask & -mask).bit_length() - 1, "mask": 1, "label": label}


# GP Card Spec v2.3.1 §11.1.2 Tables 11-7 to 11-9 (page 149): privileges on
# three bytes. DAP Verification and Delegated Management are Security Domain
# privileges, Mandated DAP Verification sets the DAP Verification bits too.
_PRIVILEGES: list[dict[str, Any]] = [
    _bit(0, 0x80, "Security Domain"),
    _bit(0, 0x40, "DAP Verification (with Security Domain)"),
    _bit(0, 0x20, "Delegated Management (with Security Domain)"),
    _bit(0, 0x10, "Card Lock"),
    _bit(0, 0x08, "Card Terminate"),
    _bit(0, 0x04, "Card Reset"),
    _bit(0, 0x02, "CVM Management"),
    _bit(0, 0x01, "Mandated DAP Verification (with DAP Verification)"),
    _bit(1, 0x80, "Trusted Path"),
    _bit(1, 0x40, "Authorized Management"),
    _bit(1, 0x20, "Token Management"),
    _bit(1, 0x10, "Global Delete"),
    _bit(1, 0x08, "Global Lock"),
    _bit(1, 0x04, "Global Registry"),
    _bit(1, 0x02, "Final Application"),
    _bit(1, 0x01, "Global Service"),
    _bit(2, 0x80, "Receipt Generation"),
    _bit(2, 0x40, "Ciphered Load File Data Block"),
    _bit(2, 0x20, "Contactless Activation"),
    _bit(2, 0x10, "Contactless Self-Activation"),
    _bit(2, 0x08, "Self-Removal"),
]

# GP Card Spec v2.3.1 §11.1.9 (page 156): the key usage qualifier values
# GlobalPlatform uses (the attribute is deprecated; a card may ignore it).
_KEY_USAGE = _choices((
    ("14", "C-MAC"),
    ("24", "R-MAC"),
    ("34", "C-MAC + R-MAC"),
    ("18", "C-ENC"),
    ("28", "R-ENC"),
    ("38", "C-ENC + R-ENC"),
    ("48", "C-DEK"),
    ("88", "R-DEK"),
    ("C8", "C-DEK + R-DEK"),
    ("82", "PK.SD.AUT"),
    ("42", "SK.SD.AUT"),
    ("81", "Token"),
    ("44", "Receipt"),
    ("84", "DAP"),
))

# GP Card Spec v2.3.1 §11.1.10 Table 11-19 (page 157): key access conditions.
_KEY_ACCESS = _choices((
    ("00", "Security Domain and any associated application"),
    ("01", "Security Domain only"),
    ("02", "Associated applications, not the Security Domain"),
    ("FF", "Not available"),
))

# GP Card Spec v2.3.1 §11.1.8 Table 11-16 (pages 154-155), one table with
# the Security Domain card.
_KEY_TYPE = [{"value": f"{value:02X}", "label": label} for value, label in sorted(KEY_TYPE_LABELS.items())]

# ETSI TS 102 221 v18.4 §11.1.1.4.9 Table 11.7b (page 99): life cycle status
# integer. b2 of the operational states is free; the values offered clear it.
_LCSI = _choices((
    ("01", "Creation state"),
    ("03", "Initialization state"),
    ("05", "Operational state, activated"),
    ("04", "Operational state, deactivated"),
    ("0C", "Termination state"),
))

# ETSI TS 101 220 V19.0.0 Annex D Table D.1 (page 27): the TARs allocated to
# remote file management applications.
_RFM_TARS = _choices((
    ("B00000", "UICC shared file system, compact format"),
    ("B00001", "ADF, compact format"),
    ("B00010", "SIM file system, compact format"),
    ("B00120", "UICC shared file system, expanded format"),
    ("B00130", "SIM file system, expanded format"),
    ("B00140", "ADF, expanded format"),
))

# TCA SAIP v3.4.1 §8.5.1 (page 53): PINAttributes; b4-b8 are RFU.
_PIN_ATTRIBUTES: list[dict[str, Any]] = [
    _bit(0, 0x01, "PIN enabled"),
    _bit(0, 0x02, "PIN can be changed"),
    _bit(0, 0x04, "PIN state change allowed"),
]

# TCA SAIP v3.4.1 §8.5.1 (page 52): maxNumOfAttemps-retryNumLeft, the
# maximum number of attempts in b8-b5 and the retries left in b4-b1.
_ATTEMPTS: list[dict[str, Any]] = [
    {"byte": 0, "shift": 4, "mask": 0x0F, "label": "Maximum attempts"},
    {"byte": 0, "shift": 0, "mask": 0x0F, "label": "Retries left"},
]

# TCA SAIP v3.4.1 §8.4.2 (page 48): algorithmOptions; the sizes apply to
# TUAK (RES also to the USIM test algorithm), b8 is RFU.
_ALGORITHM_OPTIONS: list[dict[str, Any]] = [
    {"byte": 0, "shift": 0, "mask": 0x07, "label": "RES size",
     "options": [[0, "32 bits"], [1, "64 bits"], [2, "128 bits"], [3, "256 bits"]]},
    {"byte": 0, "shift": 3, "mask": 0x07, "label": "MAC-A and MAC-S size",
     "options": [[0, "64 bits"], [1, "128 bits"], [2, "256 bits"]]},
    {"byte": 0, "shift": 6, "mask": 0x01, "label": "CK and IK size",
     "options": [[0, "128 bits"], [1, "256 bits"]]},
]

# TCA SAIP v3.4.1 §8.4.2 (page 49): sqnOptions; a set bit turns the feature
# off, b5-b8 are RFU.
_SQN_OPTIONS: list[dict[str, Any]] = [
    _bit(0, 0x01, "Anonymity key not used"),
    _bit(0, 0x02, "SQN wrap-around not allowed"),
    _bit(0, 0x04, "SQN delta not used"),
    _bit(0, 0x08, "SQN age limit not used"),
]


# ETSI TS 102 221 v18.4 §11.1.1.4.8 (page 98): a Fcp shortEFID absent takes
# the SFI from the file ID, present and empty says the file has none, one
# byte carries it in b8-b4; an SFI is 1 to 30 (§8.3, page 61).
_SHORT_EFID = [{"value": "", "label": "No SFI (empty)"}] + [
    {"value": f"{sfi << 3:02X}", "label": f"SFI {sfi}"} for sfi in range(1, 31)
]

# ETSI TS 102 225 V19.0.0 §5.1.1 (page 13): the first octet of the SPI, the
# coding ETSI TS 102 226 V19.0.0 §8.2.1.3.2.4.2 gives the Minimum SPI1 MSL
# data. A PE-RFM minimumSecurityLevel is that one byte (TCA SAIP v3.4.1
# §8.8, page 64).
_MINIMUM_SPI1: list[dict[str, Any]] = [
    {"byte": 0, "shift": 0, "mask": 0x03, "label": "Integrity",
     "options": [[0, "None"], [1, "Redundancy check"], [2, "Cryptographic checksum"],
                 [3, "Digital signature (reserved)"]]},
    {"byte": 0, "shift": 2, "mask": 0x01, "label": "Ciphering",
     "options": [[0, "None"], [1, "Ciphering"]]},
    {"byte": 0, "shift": 3, "mask": 0x03, "label": "Counter",
     "options": [[0, "No counter"], [1, "Counter, not checked"],
                 [2, "Counter higher than the receiver's"], [3, "Counter one higher than the receiver's"]]},
]

# ETSI TS 102 226 V19.0.0 §8.2.1.3.2.5 (pages 29-30): an access domain is the
# parameter byte, then for the UICC access mechanism three bytes of the keys
# whose access rules apply (SE ID 01 rules of ETSI TS 102 221).
_ACCESS_DOMAIN_PARAMETERS = [
    {"value": "00", "label": "Full access to the file system", "data_length": 0},
    {"value": "02", "label": "UICC access mechanism", "data_length": 3},
    {"value": "FF", "label": "No access to the file system", "data_length": 0},
]
_ACCESS_DOMAIN_KEYS: list[dict[str, Any]] = (
    [_bit(0, 1 << bit, f"Application PIN {bit + 1}") for bit in range(8)]
    + [_bit(1, 1 << bit, f"ADM{bit + 1}") for bit in range(8)]
    + [_bit(2, 0x01, "ADM9"), _bit(2, 0x02, "ADM10"), _bit(2, 0x04, "ALWAYS"),
       _bit(2, 0x08, "Local PIN (ADF only)")]
)

_ACCESS_DOMAIN_MEMBERS = frozenset({
    "uiccAccessDomain", "uiccAdminAccessDomain", "adfAccessDomain", "adfAdminAccessDomain",
})


def _mapping_options() -> list[Choice]:
    from .saip_aka_mapping import mapping_option_catalog

    return [{"value": row["hex"].upper(), "label": row["label"]} for row in mapping_option_catalog()]


def profile_aids(document: Mapping[str, Any]) -> list[Choice]:
    """The AIDs a profile names, each labelled by where it comes from.

    The ADFs the profile creates come first (``list_adf_bindings``), then every
    ApplicationIdentifier member its elements hold.
    """
    from .saip_json_codec import base_pe_type
    from .saip_rfm_edit import list_adf_bindings
    from .saip_structure_edit import SaipStructureError, present_leaves

    labels: dict[str, str] = {}
    for row in list_adf_bindings(dict(document)):
        aid = str(row.get("aid_hex") or "").upper()
        if aid:
            labels.setdefault(aid, str(row.get("adf") or "ADF"))
    for key, section in (document.get("sections") or {}).items():
        if not isinstance(section, dict):
            continue
        try:
            leaves = present_leaves(section, base_pe_type(str(key)))
        except SaipStructureError:
            continue
        for path, node, value in leaves:
            if node.get("display") != "ApplicationIdentifier" or not isinstance(value, (bytes, bytearray)):
                continue
            aid = bytes(value).hex().upper()
            if len(value) == 0 or not any(value):
                continue
            where = "/".join(str(step) for step in path)
            labels.setdefault(aid, f"{key} {where}")
    return [{"value": aid, "label": label} for aid, label in labels.items()]


# TCA SAIP v3.4.1 Annex A OIDs (page 112): the versions of one file-system
# template share the arc 2.23.143.1.2.n and add a version arc.
_TEMPLATE_ARCS = ["2", "23", "143", "1", "2"]


def template_choices(current_oid: str) -> list[Choice]:
    """Every version pySim carries of the template ``current_oid`` belongs to."""
    import inspect

    from pySim.esim.saip import templates

    arcs = str(current_oid or "").split(".")
    if len(arcs) < 6 or arcs[:5] != _TEMPLATE_ARCS:
        return []
    family = ".".join(arcs[:6])
    found: dict[str, str] = {}
    for candidate in vars(templates).values():
        if not inspect.isclass(candidate) or not issubclass(candidate, templates.ProfileTemplate):
            continue
        oid = str(getattr(candidate, "oid", "") or "")
        if oid == family or oid.startswith(family + "."):
            version = "1" if oid == family else oid.rsplit(".", 1)[1]
            found[oid] = f"version {version} ({candidate.__name__})"
    return [{"value": oid, "label": found[oid]} for oid in sorted(found, key=lambda oid: [int(arc) for arc in oid.split(".")])]


def _bits(width: int, fields: list[dict[str, Any]], *, integer: bool = False) -> dict[str, Any]:
    return {"kind": "bits", "width": width, "integer": integer, "fields": fields}


def _select(choices: list[Choice], *, other: bool = True) -> dict[str, Any]:
    return {"kind": "select", "choices": choices, "other": other}


def _in_key_list(path: Sequence[Any]) -> bool:
    return bool(path) and path[0] == "keyList"


def widget_for(
    node: Mapping[str, Any],
    pe_type: str,
    *,
    aids: Sequence[Choice] = (),
    templates: Sequence[Choice] = (),
) -> dict[str, Any] | None:
    """The widget for one projected node, or ``None`` for a plain field."""
    kind = node.get("kind")
    name = str(node.get("name") or "")
    path = list(node.get("path") or [])
    if pe_type == "securityDomain" and path == ["sdPersoData"]:
        # The SD personalisation data card edits these records whole: the raw
        # DGI bytes, a placeholder inside a record, the decoded DGI blocks.
        return {"kind": "card", "title": "SD personalisation data"}
    if kind == "null":
        return {"kind": "flag"}
    if kind == "boolean":
        return {"kind": "check"}
    if kind not in ("octets", "integer", "enumerated", "oid"):
        return None
    if kind == "integer":
        if name == "pinAttributes":
            return _bits(1, _PIN_ATTRIBUTES, integer=True)
        if name == "maxNumOfAttemps-retryNumLeft":
            return _bits(1, _ATTEMPTS, integer=True)
    if kind in ("integer", "enumerated") and node.get("named_values"):
        return _select(
            [{"value": str(number), "label": f"{label} ({number})"} for label, number in node["named_values"]],
            other=kind == "integer",
        )
    if kind == "oid" and name == "templateID" and templates:
        return _select(list(templates))
    if kind != "octets":
        return None
    if node.get("type") == "ApplicationIdentifier" and aids:
        return {"kind": "suggest", "choices": list(aids)}
    if name == "lifeCycleState":
        table = _SECURITY_DOMAIN_LIFE_CYCLE if pe_type == "securityDomain" else _APPLICATION_LIFE_CYCLE
        return _select(table)
    if name == "applicationPrivileges":
        widget = _bits(3, _PRIVILEGES)
        if pe_type == "securityDomain":
            # A security domain's privileges read as a grid of chips with the
            # held ones lit; every other bit field keeps one flag per row.
            widget["layout"] = "grid"
        return widget
    if _in_key_list(path) and name == "keyUsageQualifier":
        return _select(_KEY_USAGE)
    if _in_key_list(path) and name == "keyAccess":
        return _select(_KEY_ACCESS)
    if _in_key_list(path) and name == "keyType":
        return _select(_KEY_TYPE)
    if name == "lcsi":
        return _select(_LCSI)
    if name == "shortEFID":
        return {**_select(_SHORT_EFID, other=False), "absent_label": "SFI from the file ID (not set)"}
    if pe_type == "rfm" and name == "minimumSecurityLevel":
        return _bits(1, _MINIMUM_SPI1)
    if name in _ACCESS_DOMAIN_MEMBERS:
        return {"kind": "access_domain", "parameters": _ACCESS_DOMAIN_PARAMETERS, "keys": _ACCESS_DOMAIN_KEYS}
    if name == "fileDescriptor":
        return {"kind": "file_descriptor"}
    if pe_type == "rfm" and len(path) >= 2 and path[-2] == "tarList":
        return {"kind": "suggest", "choices": _RFM_TARS}
    if name == "algorithmOptions":
        return _bits(1, _ALGORITHM_OPTIONS)
    if name == "sqnOptions":
        return _bits(1, _SQN_OPTIONS)
    if name == "mappingOptions":
        return _select(_mapping_options(), other=False)
    return None


def annotate(
    tree: dict[str, Any],
    pe_type: str,
    *,
    aids: Sequence[Choice] = (),
    templates: Sequence[Choice] = (),
) -> None:
    """Attach a ``widget`` to every node of ``tree`` that has one."""
    stack = [tree]
    while stack:
        node = stack.pop()
        stack.extend(node.get("children") or [])
        widget = widget_for(node, pe_type, aids=aids, templates=templates)
        if widget is not None:
            node["widget"] = widget


__all__ = ["annotate", "profile_aids", "template_choices", "widget_for"]
