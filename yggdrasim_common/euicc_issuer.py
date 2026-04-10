from __future__ import annotations

from typing import Any


KNOWN_EUICC_ISSUER_PREFIXES: dict[str, str] = {
    "89033023": "Thales",
    "89033024": "IDEMIA",
    "89034011": "Valid",
    "89041030": "STMicroelectronics",
    "89043051": "NXP",
    "89043052": "NXP",
    "89044045": "Kigen",
    "89044047": "Truphone",
    "89049032": "Giesecke+Devrient",
    "89049038": "Giesecke+Devrient",
    "89049044": "sysmocom",
    "89086001": "Hengbao",
    "89086029": "Wuhan Tianyu",
}


def normalize_issuer_digits(value: Any) -> str:
    raw_text = str(value or "").strip()
    digits = []
    for char in raw_text:
        if char.isdigit():
            digits.append(char)
    return "".join(digits)


def infer_ecasd_issuer_identity(issuer_number: Any) -> dict[str, str]:
    normalized = normalize_issuer_digits(issuer_number)
    if len(normalized) == 0:
        return {
            "issuer_number": "",
            "issuer_prefix": "",
            "issuer_name": "",
        }

    for prefix in sorted(KNOWN_EUICC_ISSUER_PREFIXES.keys(), key=len, reverse=True):
        if normalized.startswith(prefix):
            return {
                "issuer_number": normalized,
                "issuer_prefix": prefix,
                "issuer_name": KNOWN_EUICC_ISSUER_PREFIXES[prefix],
            }

    return {
        "issuer_number": normalized,
        "issuer_prefix": normalized[:8],
        "issuer_name": "",
    }


def infer_ecasd_issuer_from_eid(eid_value: Any) -> dict[str, str]:
    normalized_eid = normalize_issuer_digits(eid_value)
    if len(normalized_eid) < 8:
        return infer_ecasd_issuer_identity("")
    return infer_ecasd_issuer_identity(normalized_eid[:8])


def format_ecasd_issuer_display(issuer_name: Any, issuer_number: Any) -> str:
    normalized_name = str(issuer_name or "").strip()
    normalized_number = normalize_issuer_digits(issuer_number)
    if len(normalized_name) > 0 and len(normalized_number) > 0:
        return f"{normalized_name} ({normalized_number})"
    if len(normalized_name) > 0:
        return normalized_name
    if len(normalized_number) > 0:
        return normalized_number
    return "(unknown)"
