# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Deterministic helpers for generating structurally-valid ICCID / IMSI values
on demand. Used to back the ``AUTO`` / ``RANDOM`` sentinel in
``NEW-PROFILE`` / ``NEW-TEMPLATE`` placeholder assignments.

ICCID structure: 19 digits + Luhn check digit (ITU-T E.118, SGP.22 Annex A).
IMSI structure: 3-digit MCC + 2/3-digit MNC + MSIN, 15 digits total
(3GPP TS 23.003, SGP.22 Annex A).
"""

from __future__ import annotations

import re
import secrets


_AUTO_SENTINELS = frozenset({"AUTO", "RANDOM", "RAND"})

_DIGIT_RE = re.compile(r"^\d+$")


def is_auto_sentinel(raw_value: str) -> bool:
    cleaned = str(raw_value or "").strip().upper()
    return cleaned in _AUTO_SENTINELS


def _random_digit_string(length: int, *, rng: "secrets.SystemRandom | None" = None) -> str:
    generator = rng
    if generator is None:
        generator = secrets.SystemRandom()
    return "".join(str(generator.randrange(0, 10)) for _ in range(length))


def _luhn_check_digit(digits: str) -> int:
    if _DIGIT_RE.fullmatch(digits) is None:
        raise ValueError("Luhn input must contain decimal digits only.")
    running_total = 0
    reverse_digits = digits[::-1]
    for index, digit_char in enumerate(reverse_digits):
        digit_value = int(digit_char)
        if index % 2 == 0:
            digit_value *= 2
            if digit_value > 9:
                digit_value -= 9
        running_total += digit_value
    return (10 - (running_total % 10)) % 10


def generate_random_iccid(
    prefix: str | None = None,
    *,
    rng: "secrets.SystemRandom | None" = None,
) -> str:
    """
    Build a 20-digit ICCID with a valid Luhn check digit.

    ``prefix`` may be used to force the first N digits (issuer-identifier
    number, country code, ...). It must be decimal and at most 19 digits.
    """
    prefix_text = str(prefix or "").strip()
    if len(prefix_text) > 19:
        raise ValueError("ICCID prefix must be at most 19 digits.")
    if len(prefix_text) > 0 and _DIGIT_RE.fullmatch(prefix_text) is None:
        raise ValueError("ICCID prefix must contain decimal digits only.")
    pad_length = 19 - len(prefix_text)
    body = prefix_text + _random_digit_string(pad_length, rng=rng)
    return body + str(_luhn_check_digit(body))


def generate_random_imsi(
    mcc: str | None = None,
    mnc: str | None = None,
    *,
    length: int = 15,
    rng: "secrets.SystemRandom | None" = None,
) -> str:
    """
    Build a plausible IMSI with optional MCC / MNC anchoring.

    Defaults: MCC ``001`` (test network), MNC ``01``, MSIN generated randomly.
    """
    effective_length = int(length)
    if effective_length not in (14, 15):
        raise ValueError("IMSI length must be 14 or 15 digits.")
    mcc_text = str(mcc or "001").strip()
    mnc_text = str(mnc or "01").strip()
    if _DIGIT_RE.fullmatch(mcc_text) is None or len(mcc_text) != 3:
        raise ValueError("IMSI MCC must contain exactly three decimal digits.")
    if _DIGIT_RE.fullmatch(mnc_text) is None or len(mnc_text) not in (2, 3):
        raise ValueError("IMSI MNC must contain two or three decimal digits.")
    msin_length = effective_length - len(mcc_text) - len(mnc_text)
    if msin_length <= 0:
        raise ValueError("IMSI length too short to fit the requested MCC/MNC.")
    msin = _random_digit_string(msin_length, rng=rng)
    return mcc_text + mnc_text + msin


def resolve_auto_value(
    placeholder_name: str,
    raw_value: str,
    *,
    rng: "secrets.SystemRandom | None" = None,
) -> str:
    """
    Translate an ``AUTO`` / ``RANDOM`` sentinel into a concrete value for the
    given placeholder. Non-sentinel values are returned unchanged.
    """
    if is_auto_sentinel(raw_value) is False:
        return raw_value
    upper_name = str(placeholder_name or "").strip().upper()
    if upper_name == "ICCID":
        return generate_random_iccid(rng=rng)
    if upper_name == "IMSI":
        return generate_random_imsi(rng=rng)
    raise ValueError(
        f"AUTO / RANDOM is only supported for ICCID / IMSI (got {placeholder_name!r})."
    )


def resolve_auto_assignments(
    assignments: dict[str, str],
    *,
    rng: "secrets.SystemRandom | None" = None,
) -> tuple[dict[str, str], list[str]]:
    """
    Walk a placeholder ``name -> value`` mapping and expand any AUTO / RANDOM
    sentinels. Returns the resolved mapping plus a list of human-readable
    expansion summaries suitable for shell output.
    """
    resolved: dict[str, str] = {}
    summaries: list[str] = []
    for raw_name, raw_value in assignments.items():
        if is_auto_sentinel(str(raw_value)):
            value = resolve_auto_value(raw_name, str(raw_value), rng=rng)
            summaries.append(f"{raw_name} auto-generated -> {value}")
            resolved[raw_name] = value
            continue
        resolved[raw_name] = str(raw_value)
    return resolved, summaries
