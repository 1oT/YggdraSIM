# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""PE-AKAParameter ``algoConfiguration`` CHOICE switch.

TCA SAIP §A.2 / 3GPP TS 31.102 §7.1.2 model the AKA configuration of a
NAA as a CHOICE between two alternatives:

* ``algoParameter``    — algorithm-id plus algorithm-specific keys
                         (MILENAGE / TUAK / USIM Test).
* ``mappingParameter`` — reuse another NAA's authentication
                         configuration via that NAA's instance AID
                         and a one-byte mapping-options bitmask.

The operator-facing toggle in the editor uses this module so the
underlying tagged-tuple flips cleanly between the two CHOICE branches
without losing the algorithm payload when the operator switches back.
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


# Mapping-options bitmask layout per TCA SAIP §A.2 ``MappingOptions``:
# the eight bits select which AKA outputs are inherited from the
# referenced NAA. The names below are the TCA-defined member names; we
# expose them as a stable catalog so the GUI can render labelled
# checkboxes without the editor having to know the bit positions.
_MAPPING_OPTION_BITS: tuple[tuple[int, str], ...] = (
    (0x80, "share-K"),
    (0x40, "share-OPc"),
    (0x20, "share-rotationConstants"),
    (0x10, "share-xoringConstants"),
    (0x08, "share-sqnInit"),
    (0x04, "share-sqnDelta"),
    (0x02, "share-sqnAgeLimit"),
    (0x01, "share-authCounterMax"),
)


def mapping_option_catalog() -> list[dict[str, Any]]:
    """Catalog of mapping-option flags for the GUI checkbox group."""
    return [
        {"name": name, "bit_mask": bit_mask, "hex": f"{bit_mask:02X}"}
        for bit_mask, name in _MAPPING_OPTION_BITS
    ]


def _strip_separators(value: Any) -> str:
    return re.sub(r"\s+|0x|0X|-|:", "", str(value or ""))


def _tagged_bytes(hex_value: str) -> dict[str, str]:
    return {_TAG_BYTES: hex_value.upper()}


def _hex_from_tagged(value: Any) -> str | None:
    if isinstance(value, dict) is False:
        return None
    for key in (_TAG_BYTES, _LEGACY_TAG_BYTES):
        if key in value:
            raw = value.get(key)
            if isinstance(raw, str):
                return raw.strip().upper()
    return None


def _unwrap_tuple(value: Any) -> tuple[str, Any] | None:
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


def _wrap_tuple(field_name: str, value: Any) -> dict[str, Any]:
    return {_TAG_TUPLE: [str(field_name), value]}


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


def _normalise_mapping_options(
    value: Any,
    *,
    flags: list[str] | None,
) -> str:
    """Normalise either an explicit hex byte or a flag-name list into a 1-byte hex string."""
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
                "supply mappingOptions hex OR flags list, not both.",
            )
        return text.upper()
    if flags is None:
        # Default: every bit cleared. The GUI flips bits via the
        # checkbox group; an empty toggle means "use only the AID
        # reference, no parameter inheritance".
        return "00"
    if isinstance(flags, (list, tuple)) is False:
        raise ValueError("flags must be a list of mapping-option names.")
    by_name = {name: bit_mask for bit_mask, name in _MAPPING_OPTION_BITS}
    accumulator = 0
    seen: set[str] = set()
    for raw in flags:
        name = str(raw or "").strip()
        if len(name) == 0:
            continue
        if name in seen:
            continue
        seen.add(name)
        if name not in by_name:
            raise ValueError(
                f"unknown mapping-option flag {name!r}; allowed: "
                + ", ".join(label for _bit, label in _MAPPING_OPTION_BITS),
            )
        accumulator |= by_name[name]
    return f"{accumulator & 0xFF:02X}"


def get_choice(pe_value: dict[str, Any]) -> dict[str, Any]:
    """Return the current ``algoConfiguration`` CHOICE projection.

    Output keys::

        {"choice": "algoParameter" | "mappingParameter" | "absent",
         "algorithm_id": <int | None>,
         "mapping_source_aid_hex": <str>,
         "mapping_options_hex": <str>,
         "mapping_options_flags": [<flag-name>, ...]}

    The flags list is decoded from ``mappingOptions`` against the
    bitmap catalog so the GUI can render the checkbox group directly.
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
        flags: list[str] = []
        try:
            opt_int = int(opt_hex, 16)
        except ValueError:
            opt_int = 0
        for bit_mask, name in _MAPPING_OPTION_BITS:
            if opt_int & bit_mask:
                flags.append(name)
        return {
            "choice": "mappingParameter",
            "algorithm_id": None,
            "mapping_source_aid_hex": aid_hex.upper(),
            "mapping_options_hex": opt_hex.upper(),
            "mapping_options_flags": flags,
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
    pe_value["algoConfiguration"] = _wrap_tuple(
        "mappingParameter",
        {
            "mappingOptions": _tagged_bytes(opt_hex),
            "mappingSource": _tagged_bytes(aid_hex),
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
    pe_value["algoConfiguration"] = _wrap_tuple("algoParameter", payload)
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
