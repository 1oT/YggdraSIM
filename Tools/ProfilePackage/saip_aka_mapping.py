# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""PE-AKAParameter ``algoConfiguration`` CHOICE switch.

TCA SAIP v3.4.1 §8.4.2 / 3GPP TS 31.102 §7.1.2 model the AKA configuration of a
NAA as a CHOICE between two alternatives:

* ``algoParameter``    -- algorithm-id plus algorithm-specific keys
                         (MILENAGE / TUAK / USIM Test).
* ``mappingParameter`` -- reuse another NAA's authentication
                         configuration via that NAA's instance AID
                         and a one-byte ``mappingOptions``.

The operator-facing toggle in the editor uses this module so the CHOICE
flips cleanly between the two branches without losing the algorithm
payload when the operator switches back. A session document holds the
CHOICE as a ``(alternative, payload)`` tuple with ``bytes`` members, which
is what the writers produce; the readers also accept the JSON transport
form (``__ygg_saip_tuple__`` / ``__ygg_saip_bytes__``).
"""

from __future__ import annotations

import copy
import re
from typing import Any


_HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


_TAG_TUPLE = "__ygg_saip_tuple__"
_LEGACY_TAG_TUPLE = "@"
_TAG_BYTES = "__ygg_saip_bytes__"
_LEGACY_TAG_BYTES = "hex"


# TCA SAIP v3.4.1 §8.4.2 (page 49): ``mappingOptions`` carries one 2-bit value
# in b3-b2 naming the SQN parameters and values the NAA takes from the
# application ``mappingSource`` references; every other bit is RFU.
# algorithmID, algorithmOptions, key, opc, rotationConstants, xoringConstants
# and numberOfKeccak are always shared when the mapping is used.
_MAPPING_SQN_MASK = 0x06
_MAPPING_SQN_MODES: tuple[tuple[int, str, str], ...] = (
    (0x00, "share-no-sqn", "Do not share SQN parameters or values"),
    (0x02, "share-sqn-init-and-parameters", "Share sqnInit, sqnOptions, sqnDelta and sqnAgeLimit"),
    (0x04, "share-sqn-parameters", "Share sqnOptions, sqnDelta and sqnAgeLimit"),
    (0x06, "share-sqn-parameters-and-array", "Share sqnOptions, sqnDelta, sqnAgeLimit and the SQN array"),
)


def mapping_option_catalog() -> list[dict[str, Any]]:
    """The four ``mappingOptions`` values with their names and meanings."""
    return [
        {"name": name, "hex": f"{value:02X}", "label": label}
        for value, name, label in _MAPPING_SQN_MODES
    ]


def _strip_separators(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def _hex_from_tagged(value: Any) -> str | None:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if isinstance(value, dict) is False:
        return None
    for key in (_TAG_BYTES, _LEGACY_TAG_BYTES):
        if key in value:
            raw = value.get(key)
            if isinstance(raw, str):
                return raw.strip().upper()
    return None


def _unwrap_tuple(value: Any) -> tuple[str, Any] | None:
    if isinstance(value, (tuple, list)) and len(value) == 2 and isinstance(value[0], str):
        return (value[0], value[1])
    if isinstance(value, dict) is False:
        return None
    for key in (_TAG_TUPLE, _LEGACY_TAG_TUPLE):
        if key in value:
            payload = value.get(key)
            if isinstance(payload, list) and len(payload) >= 2:
                tag = payload[0]
                if isinstance(tag, str):
                    return (tag, payload[1])
    return None


def _normalise_aid(value: Any) -> str:
    text = _strip_separators(value)
    if len(text) == 0:
        raise ValueError("mappingSource AID is empty.")
    if _HEX_RE.fullmatch(text) is None:
        raise ValueError(f"mappingSource AID is not hexadecimal: {value!r}")
    if len(text) % 2 != 0:
        raise ValueError(
            f"mappingSource AID has odd nibble count ({len(text)}); "
            "AIDs are 5..16 whole bytes (ISO 7816-4 §8.2.1).",
        )
    aid_bytes = len(text) // 2
    if aid_bytes < 5 or aid_bytes > 16:
        raise ValueError(
            f"mappingSource AID length {aid_bytes} bytes is out of range "
            "(ISO 7816-4 §8.2.1: RID 5 + PIX 0..11).",
        )
    return text.upper()


def _mapping_mode(value: int) -> tuple[str, str]:
    for mode_value, name, label in _MAPPING_SQN_MODES:
        if mode_value == value & _MAPPING_SQN_MASK:
            return (name, label)
    return ("", "")


def _normalise_mapping_options(
    value: Any,
    *,
    flags: list[str] | None,
) -> str:
    """One ``mappingOptions`` byte from explicit hex or a single mode name."""
    text = _strip_separators(value) if value is not None else ""
    if len(text) > 0:
        if _HEX_RE.fullmatch(text) is None:
            raise ValueError(f"mappingOptions is not hexadecimal: {value!r}")
        if len(text) != 2:
            raise ValueError(
                f"mappingOptions must be exactly 1 byte (2 hex digits); got "
                f"{len(text)} digit(s).",
            )
        if flags is not None and len(list(flags)) > 0:
            raise ValueError(
                "supply mappingOptions hex OR a mode name, not both.",
            )
        if int(text, 16) & ~_MAPPING_SQN_MASK & 0xFF:
            raise ValueError(
                f"mappingOptions {text.upper()} sets RFU bits; only b3-b2 carry a "
                "value (TCA SAIP v3.4.1 §8.4.2).",
            )
        return text.upper()
    if flags is None:
        return "00"
    if isinstance(flags, (list, tuple)) is False:
        raise ValueError("flags must be a list holding one mapping mode name.")
    names = [str(raw or "").strip() for raw in flags if str(raw or "").strip()]
    if len(set(names)) > 1:
        raise ValueError("the mapping modes exclude each other; name one.")
    if not names:
        return "00"
    by_name = {name: mode_value for mode_value, name, _label in _MAPPING_SQN_MODES}
    if names[0] not in by_name:
        raise ValueError(
            f"unknown mapping mode {names[0]!r}; allowed: "
            + ", ".join(name for _value, name, _label in _MAPPING_SQN_MODES),
        )
    return f"{by_name[names[0]]:02X}"


def get_choice(pe_value: dict[str, Any]) -> dict[str, Any]:
    """Return the current ``algoConfiguration`` CHOICE projection.

    Output keys::

        {"choice": "algoParameter" | "mappingParameter" | "absent",
         "algorithm_id": <int | None>,
         "mapping_source_aid_hex": <str>,
         "mapping_options_hex": <str>,
         "mapping_options_flags": [<flag-name>, ...]}

    ``mapping_options_flags`` holds the one SQN-sharing mode ``mappingOptions``
    names, also given as ``mapping_options_mode`` with its label.
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-AKAParameter value must be a dict.")
    node = pe_value.get("algoConfiguration")
    tagged = _unwrap_tuple(node)
    if tagged is None:
        return {
            "choice": "absent",
            "algorithm_id": None,
            "mapping_source_aid_hex": "",
            "mapping_options_hex": "",
            "mapping_options_flags": [],
        }
    tag, payload = tagged
    if tag == "algoParameter":
        algo_id: int | None = None
        if isinstance(payload, dict):
            raw = payload.get("algorithmID")
            if isinstance(raw, int) and isinstance(raw, bool) is False:
                algo_id = int(raw)
        return {
            "choice": "algoParameter",
            "algorithm_id": algo_id,
            "mapping_source_aid_hex": "",
            "mapping_options_hex": "",
            "mapping_options_flags": [],
        }
    if tag == "mappingParameter":
        aid_hex = ""
        opt_hex = "00"
        if isinstance(payload, dict):
            aid_hex = _hex_from_tagged(payload.get("mappingSource")) or ""
            opt_hex = _hex_from_tagged(payload.get("mappingOptions")) or "00"
        try:
            opt_int = int(opt_hex, 16)
        except ValueError:
            opt_int = 0
        mode, label = _mapping_mode(opt_int)
        return {
            "choice": "mappingParameter",
            "algorithm_id": None,
            "mapping_source_aid_hex": aid_hex.upper(),
            "mapping_options_hex": opt_hex.upper(),
            "mapping_options_flags": [mode] if mode else [],
            "mapping_options_mode": mode,
            "mapping_options_label": label,
        }
    return {
        "choice": "absent",
        "algorithm_id": None,
        "mapping_source_aid_hex": "",
        "mapping_options_hex": "",
        "mapping_options_flags": [],
    }


def set_mapping_parameter(
    pe_value: dict[str, Any],
    *,
    mapping_source_aid: Any,
    mapping_options_hex: Any = None,
    mapping_options_flags: list[str] | None = None,
    preserve_algo_payload: bool = True,
) -> dict[str, Any]:
    """Switch ``algoConfiguration`` to ``mappingParameter`` in place.

    ``preserve_algo_payload=True`` stashes the previous
    ``algoParameter`` payload under the synthetic key
    ``"_ygg_algo_parameter_stash"`` on the PE so that flipping back to
    ``algoParameter`` later can restore the operator's edits without
    forcing a re-entry. The stash key is dropped on encode by the SAIP
    codec since it is not part of the schema.
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-AKAParameter value must be a dict.")
    aid_hex = _normalise_aid(mapping_source_aid)
    opt_hex = _normalise_mapping_options(
        mapping_options_hex, flags=mapping_options_flags,
    )
    if preserve_algo_payload:
        existing = _unwrap_tuple(pe_value.get("algoConfiguration"))
        if existing is not None and existing[0] == "algoParameter":
            pe_value["_ygg_algo_parameter_stash"] = copy.deepcopy(existing[1])
    pe_value["algoConfiguration"] = (
        "mappingParameter",
        {
            "mappingOptions": bytes.fromhex(opt_hex),
            "mappingSource": bytes.fromhex(aid_hex),
        },
    )
    return {
        "choice": "mappingParameter",
        "mapping_source_aid_hex": aid_hex,
        "mapping_options_hex": opt_hex,
    }


def set_algo_parameter(
    pe_value: dict[str, Any],
    *,
    algorithm_id: int | None = None,
    restore_stash_if_present: bool = True,
) -> dict[str, Any]:
    """Switch ``algoConfiguration`` to ``algoParameter`` in place.

    When ``restore_stash_if_present`` is true and a prior
    ``mappingParameter`` toggle stashed the previous algoParameter
    payload, the stash is restored verbatim. Otherwise an empty
    payload is emitted with the supplied ``algorithm_id`` (or no
    ``algorithmID`` at all when it is ``None``).
    """
    if isinstance(pe_value, dict) is False:
        raise ValueError("PE-AKAParameter value must be a dict.")
    payload: dict[str, Any] = {}
    stash = pe_value.pop("_ygg_algo_parameter_stash", None)
    if restore_stash_if_present and isinstance(stash, dict):
        payload = copy.deepcopy(stash)
    if algorithm_id is not None:
        payload["algorithmID"] = int(algorithm_id)
    pe_value["algoConfiguration"] = ("algoParameter", payload)
    return {
        "choice": "algoParameter",
        "algorithm_id": payload.get("algorithmID"),
    }


__all__ = [
    "get_choice",
    "mapping_option_catalog",
    "set_algo_parameter",
    "set_mapping_parameter",
]
