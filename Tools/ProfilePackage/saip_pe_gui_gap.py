# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SAIP profile-element coverage vs Command Center GUI dispatch.

The browser workbench classifies each PE in
``yggdrasim_common/gui_server/static/app.js`` (``saipRenderPeDetail`` /
``saipEditorBuildPeDetail`` chain). This module unions the PE vocabulary
surfaced elsewhere in the tree (diff labels, simulator ``_SECTION_SPECS``,
quick-add constructors) and prints which tier each PE lands in.

Run (repo root)::

    python3 -m Tools.ProfilePackage.saip_pe_gui_gap

Update :func:`classify_pe_gui_tier` when the static dispatch changes.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from typing import Iterable

_FILE_TEMPLATE_PE: frozenset[str] = frozenset(
    {
        "usim",
        "opt-usim",
        "optusim",
        "isim",
        "opt-isim",
        "optisim",
        "csim",
        "opt-csim",
        "optcsim",
        "mf",
        "telecom",
        "df-telecom",
        "phonebook",
        "df-phonebook",
        "df-5gs",
        "df-saip",
        "df-snpn",
        "df-5gprose",
        "gsm-access",
        "cd",
        "iot",
        "opt-iot",
        "ssim",
    },
)

_SECURITY_DOMAIN_PE: frozenset[str] = frozenset(
    {
        "securitydomain",
        "mno-sd",
        "mnosd",
        "ssd",
        "isdr",
        "isdp",
    },
)

_TYPED_CARD_PE: frozenset[str] = frozenset(
    {
        "pincodes",
        "pukcodes",
        "akaparameter",
        "genericfilemanagement",
        "gfm",
        "rfm",
        "application",
        "end",
    },
)

_NONSTANDARD_SPARSE_PE: frozenset[str] = frozenset({"nonstandard"})

_SPARSE_CARD_PE: frozenset[str] = frozenset(
    {
        "cdmaparameter",
        "eap",
        "ssimeaptlsparameters",
    },
)

_GAP_NOTES: dict[str, str] = {
    "securitydomain_ssd": "GUI normalises this quick-add key to the ``ssd`` dispatch branch.",
    "profileheader": "GUI normalises legacy ``profileHeader`` to ``header`` before dispatch.",
    "isdr": "Role variant of ``securityDomain`` — root security domain, not a separate PE type.",
    "isdp": "Role variant of ``securityDomain`` — MNO-SD, not a separate PE type.",
    "optusim": "Alias normalised to ``opt-usim``.",
    "optisim": "Alias normalised to ``opt-isim``.",
    "optcsim": "Alias normalised to ``opt-csim``.",
    "df-telecom": "Alias for ``telecom`` parent key.",
    "df-phonebook": "Alias for ``phonebook`` parent key.",
    "gfm": "Alias for ``genericFileManagement``.",
    "ssim": "PE-SSIM requires pySim ASN.1 schema ≥ v3.4 (Profile Interop TS V3.4 §8.3.4.9).",
    "ssimeaptlsparameters": "PE-SSIM-EAPTLSParameters requires pySim ASN.1 schema ≥ v3.4 (§8.4.4).",
}


def _normalise_gui_pe_type(pe_type: str) -> str:
    t = str(pe_type or "").strip().lower()
    if t == "profileheader":
        return "header"
    if t == "securitydomain_ssd":
        return "ssd"
    return t


def classify_pe_gui_tier(pe_type: str) -> str:
    """Return a dispatch bucket label mirroring ``app.js`` (lower-case ``t``)."""
    t = _normalise_gui_pe_type(pe_type)
    if t == "header":
        return "profile_header_only"
    if t in _FILE_TEMPLATE_PE:
        return "filesystem_template_catalog_no_pe_decoded_panel"
    if t in _SECURITY_DOMAIN_PE:
        return "security_domain_cards_wizard"
    if t in _NONSTANDARD_SPARSE_PE:
        return "nonstandard_sparse_card_untyped_section_wizard"
    if t in _TYPED_CARD_PE:
        return "typed_summary_cards_wizard"
    if t in _SPARSE_CARD_PE:
        return "sparse_identity_card_section_wizard"
    return "untyped_card_catchall_wizard_plus_decoded_panel"


def _canonical_base_pe(section_key: str) -> str:
    text = str(section_key or "").strip()
    if len(text) == 0:
        return ""
    match = re.match(r"^(?P<base>[A-Za-z][A-Za-z0-9-]*?)(?:_\d+)?$", text)
    if match is None:
        return text
    return match.group("base")


_QUICK_ADD_MENU_KEYS: frozenset[str] = frozenset(
    {
        "header",
        "end",
        "mf",
        "telecom",
        "cd",
        "phonebook",
        "gsm-access",
        "df-5gs",
        "eap",
        "df-saip",
        "df-snpn",
        "df-5gprose",
        "pinCodes",
        "pukCodes",
        "securityDomain",
        "securityDomain_ssd",
        "application",
        "nonStandard",
        "usim",
        "opt-usim",
        "isim",
        "opt-isim",
        "csim",
        "opt-csim",
        "iot",
        "opt-iot",
        "akaParameter",
        "cdmaParameter",
        "rfm",
        "genericFileManagement",
        # ssim / ssimEaptls deferred — pySim schema v3.4+
    },
)


_NOT_STANDARD_PE: frozenset[str] = frozenset(
    {
        # Vocabulary entries that do not correspond to any PE
        # in the Profile Interop TS V3.4.1 ``ProfileElement ::= CHOICE``.
        "5gauthparameter",
        "5gAuthParameter",
        "5gnasparameter",
        "5gNasParameter",
        "applicationmanagement",
        "applicationManagement",
        "df-eap",
        "df-tetra",
        "df-wlan",
        "ram",
        "ssimeaptls",
        "ssimEaptls",
        "umts",
        "wlan",
    },
)


def known_pe_types_union() -> set[str]:
    """Union vocabulary keys from diff labels, simulator specs, and quick-add."""
    from Tools.ProfilePackage.saip_profile_diff import _SECTION_LABELS
    from SIMCARD.saip_profile import _SECTION_SPECS

    keys: set[str] = set()
    keys.update(str(k) for k in _SECTION_LABELS.keys())
    keys.update(str(k) for k in _SECTION_SPECS.keys())
    keys.update(_QUICK_ADD_MENU_KEYS)
    keys.update(
        {
            "rfm",
            "isdr",
            "isdp",
            "profileHeader",
            "ssim",
            "ssimEapTLSParameters",
        },
    )
    canonical = {_canonical_base_pe(k) for k in keys if len(_canonical_base_pe(k)) > 0}
    canonical.difference_update(_NOT_STANDARD_PE)
    return canonical


def tier_summary_rows() -> list[tuple[str, str, str]]:
    """Return sorted ``(pe_type, tier, note)`` rows for every known PE base."""
    rows: list[tuple[str, str, str]] = []
    for pe in sorted(known_pe_types_union()):
        tier = classify_pe_gui_tier(pe)
        note = _GAP_NOTES.get(pe.lower(), "")
        rows.append((pe, tier, note))
    return rows


def print_report(stream: Iterable[str] | None = None) -> None:
    out = sys.stdout if stream is None else stream
    by_tier: dict[str, list[str]] = defaultdict(list)
    for pe, tier, _note in tier_summary_rows():
        by_tier[tier].append(pe)
    out.write("SAIP PE type → Command Center GUI tier\n")
    out.write("(tiers mirror static/app.js PE detail dispatch.)\n\n")
    for tier in sorted(by_tier.keys()):
        out.write(f"[{tier}]\n")
        for pe in sorted(by_tier[tier]):
            out.write(f"  - {pe}\n")
        out.write("\n")
    out.write("--- vocabulary-only bases (no duplicate *_N suffixes) ---\n")
    for pe, tier, note in tier_summary_rows():
        line = f"{pe:28}  {tier}"
        if len(note) > 0:
            line += f"  # {note}"
        out.write(line + "\n")


def main() -> None:
    print_report()


if __name__ == "__main__":
    main()
