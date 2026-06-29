# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Scaffold a brand-new SAIP ProfileElement sequence from a curated preset.

Presets are ordered lists of ``menu_id`` strings drawn from
``saip_pe_quick_add.list_pe_quick_add_rows``. Every preset begins with the
``header`` PE and terminates with the ``end`` PE, as mandated by
SGP.22 / SGP.32 and SAIP v2.3+.

The module is intentionally small and side-effect free: it only produces a
decoded document (``intro`` + ``sections`` shape) compatible with
``saip_json_codec.build_profile_sequence_from_document``.
"""

from __future__ import annotations

import json
import re
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .saip_json_codec import (
    build_decoded_document_from_sequence,
    ensure_workspace_pysim_on_path,
)
from .saip_pe_quick_add import _factory_map, list_pe_quick_add_rows


_DEFAULT_PRESET_ID = "USIM"

_USER_PRESETS_FILENAME = ".yggdrasim_saip_presets.json"

_PRESET_ID_RE = re.compile(r"^[A-Z][A-Z0-9_\-]*$")


@dataclass(frozen=True)
class ProfilePreset:
    preset_id: str
    description: str
    menu_ids: tuple[str, ...]
    source: str = "builtin"


@dataclass(frozen=True)
class PresetDiff:
    preset_a_id: str
    preset_b_id: str
    only_in_a: tuple[str, ...]
    only_in_b: tuple[str, ...]
    common: tuple[str, ...]
    order_changed: bool


_PROFILE_PRESETS: "OrderedDict[str, ProfilePreset]" = OrderedDict()


def _register_preset(preset: ProfilePreset) -> None:
    _PROFILE_PRESETS[preset.preset_id] = preset


_register_preset(
    ProfilePreset(
        preset_id="MINIMAL",
        description="Profile header + end only. Smallest encodable PE-Sequence.",
        menu_ids=("header", "end"),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="BASIC-MF",
        description="Header + MF + end. Adds EF.ICCID / EF.DIR / EF.ARR shells at the MF.",
        menu_ids=("header", "mf", "end"),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="USIM",
        description=(
            "Header + MF + PIN/PUK codes + ADF.USIM (mandatory) + optional "
            "USIM files + MILENAGE AKA parameter + end."
        ),
        menu_ids=(
            "header",
            "mf",
            "pinCodes",
            "pukCodes",
            "usim",
            "opt-usim",
            "akaParameter",
            "end",
        ),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="USIM-ISIM",
        description=(
            "Header + MF + PIN/PUK codes + USIM (+ optional) + ISIM (+ optional) "
            "+ MILENAGE AKA parameter + end."
        ),
        menu_ids=(
            "header",
            "mf",
            "pinCodes",
            "pukCodes",
            "usim",
            "opt-usim",
            "isim",
            "opt-isim",
            "akaParameter",
            "end",
        ),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="FULL",
        description=(
            "Header + MF + PIN/PUK codes + DF.TELECOM + USIM (+ optional) "
            "+ ISIM (+ optional) + MILENAGE AKA parameter + end."
        ),
        menu_ids=(
            "header",
            "mf",
            "pinCodes",
            "pukCodes",
            "telecom",
            "usim",
            "opt-usim",
            "isim",
            "opt-isim",
            "akaParameter",
            "end",
        ),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="IOT",
        description=(
            "IoT Minimal Profile: Header + IoT scaffold + PIN codes "
            "+ MILENAGE AKA parameter + MNO-SD + end. "
            "Per SAIP V3.4.1 Annex G IoT Minimal Profile example."
        ),
        menu_ids=(
            "header",
            "iot",
            "pinCodes",
            "akaParameter",
            "securityDomain",
            "end",
        ),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="CSIM",
        description=(
            "CDMA profile: Header + MF + CSIM (+ optional) "
            "+ CDMA CAVE parameter + end."
        ),
        menu_ids=(
            "header",
            "mf",
            "csim",
            "opt-csim",
            "cdmaParameter",
            "end",
        ),
    )
)

_register_preset(
    ProfilePreset(
        preset_id="FULL-EXTENDED",
        description=(
            "Header + MF + PIN/PUK codes + DF.TELECOM + USIM (+ optional) "
            "+ ISIM (+ optional) + DF.PHONEBOOK + GSM-ACCESS + DF.5GS "
            "+ DF.EAP + MILENAGE AKA parameter + end."
        ),
        menu_ids=(
            "header",
            "mf",
            "pinCodes",
            "pukCodes",
            "telecom",
            "usim",
            "opt-usim",
            "isim",
            "opt-isim",
            "phonebook",
            "gsm-access",
            "df-5gs",
            "eap",
            "akaParameter",
            "end",
        ),
    )
)


def list_profile_presets() -> list[ProfilePreset]:
    """Return all registered ``ProfilePreset`` objects in definition order."""
    return [preset for preset in _PROFILE_PRESETS.values()]


def default_preset_id() -> str:
    """Return the identifier of the default preset (currently ``"USIM"``)."""
    return _DEFAULT_PRESET_ID


def normalize_preset_id(raw_preset_id: str | None) -> str:
    """Normalise a preset identifier string; falls back to the default when empty.

    Raises ``ValueError`` when ``raw_preset_id`` is non-empty but not a
    known preset key.
    """
    candidate = str(raw_preset_id or "").strip().upper()
    if len(candidate) == 0:
        return _DEFAULT_PRESET_ID
    if candidate in _PROFILE_PRESETS:
        return candidate
    known = ", ".join(_PROFILE_PRESETS.keys())
    raise ValueError(
        f"Unknown profile preset {raw_preset_id!r}. Known presets: {known}."
    )


def get_preset(preset_id: str) -> ProfilePreset:
    """Resolve a preset identifier to its ``ProfilePreset`` data object."""
    normalized = normalize_preset_id(preset_id)
    return _PROFILE_PRESETS[normalized]


def _menu_id_descriptions() -> dict[str, str]:
    table: dict[str, str] = {}
    for menu_id, _title, hint in list_pe_quick_add_rows():
        table[str(menu_id)] = str(hint)
    return table


def describe_menu_id(menu_id: str) -> str:
    """Return the hint string for a PE quick-add ``menu_id``, or empty string."""
    table = _menu_id_descriptions()
    return table.get(str(menu_id), "")


_PLACEHOLDER_CARRIERS: dict[str, tuple[str, ...]] = {
    "ICCID": ("header", "mf"),
    "IMSI": ("usim", "opt-usim", "isim", "opt-isim"),
}


def list_preset_placeholders(preset_id: str) -> list[str]:
    """
    Enumerate typed placeholders (ICCID / IMSI) that a preset can inject.

    Only returns placeholder names for which the preset carries at least one
    compatible section so the UX never advertises a placeholder that would
    raise at injection time.
    """
    preset = get_preset(preset_id)
    section_set = set(preset.menu_ids)
    supported: list[str] = []
    for placeholder_name, carrier_sections in _PLACEHOLDER_CARRIERS.items():
        if any(section in section_set for section in carrier_sections):
            supported.append(placeholder_name)
    return supported


def describe_preset(preset_id: str) -> dict[str, Any]:
    """Return a serialisable dict describing a preset for display in the GUI wizard.

    Includes ``preset_id``, ``description``, ``source``, ``pe_count``,
    ``menu_ids``, per-PE ``pes`` entries, and resolved ``placeholders``.
    """
    preset = get_preset(preset_id)
    menu_table = _menu_id_descriptions()
    pe_entries: list[dict[str, str]] = []
    for menu_id in preset.menu_ids:
        pe_entries.append(
            {
                "menu_id": menu_id,
                "description": menu_table.get(menu_id, ""),
            }
        )
    return {
        "preset_id": preset.preset_id,
        "description": preset.description,
        "source": preset.source,
        "pe_count": len(preset.menu_ids),
        "menu_ids": list(preset.menu_ids),
        "pes": pe_entries,
        "placeholders": list_preset_placeholders(preset.preset_id),
    }


def diff_presets(preset_a_id: str, preset_b_id: str) -> PresetDiff:
    """Compare two presets and return a ``PresetDiff`` describing PE-level differences.

    Reports which ``menu_ids`` are exclusive to each preset, which are
    shared, and whether their relative order differs.
    """
    preset_a = get_preset(preset_a_id)
    preset_b = get_preset(preset_b_id)
    set_a = set(preset_a.menu_ids)
    set_b = set(preset_b.menu_ids)
    only_a = tuple(menu_id for menu_id in preset_a.menu_ids if menu_id not in set_b)
    only_b = tuple(menu_id for menu_id in preset_b.menu_ids if menu_id not in set_a)
    common_a = [menu_id for menu_id in preset_a.menu_ids if menu_id in set_b]
    common_b = [menu_id for menu_id in preset_b.menu_ids if menu_id in set_a]
    order_changed = common_a != common_b
    return PresetDiff(
        preset_a_id=preset_a.preset_id,
        preset_b_id=preset_b.preset_id,
        only_in_a=only_a,
        only_in_b=only_b,
        common=tuple(common_a),
        order_changed=order_changed,
    )


_KNOWN_MENU_ID_SET = frozenset(
    menu_id for menu_id, _title, _hint in list_pe_quick_add_rows()
)


def _validate_menu_id_structure(
    preset_id: str,
    menu_ids: tuple[str, ...],
) -> None:
    """
    Sanity checks that do not require the pySim factory table. Used by the
    user-preset loader so users can bootstrap presets before pySim is
    available in the environment.
    """
    if len(menu_ids) < 2:
        raise ValueError(
            f"Preset {preset_id!r} must list at least 'header' and 'end' menu ids."
        )
    if menu_ids[0] != "header":
        raise ValueError(
            f"Preset {preset_id!r} must start with 'header' (got {menu_ids[0]!r})."
        )
    if menu_ids[-1] != "end":
        raise ValueError(
            f"Preset {preset_id!r} must end with 'end' (got {menu_ids[-1]!r})."
        )
    for menu_id in menu_ids:
        if menu_id not in _KNOWN_MENU_ID_SET:
            raise ValueError(
                f"Preset {preset_id!r} references unknown PE menu id {menu_id!r}."
            )


def _validate_menu_id_factories(
    preset_id: str,
    menu_ids: tuple[str, ...],
) -> None:
    """
    Stricter check that additionally asserts a pySim factory exists for every
    referenced ``menu_id``. Used at scaffold time once pySim is loaded.
    """
    _validate_menu_id_structure(preset_id, menu_ids)
    factories = _factory_map()
    for menu_id in menu_ids:
        if menu_id not in factories:
            raise ValueError(
                f"Preset {preset_id!r} references unknown PE menu id {menu_id!r}."
            )


def _normalize_user_preset_id(raw_preset_id: str) -> str:
    candidate = str(raw_preset_id or "").strip().upper()
    if _PRESET_ID_RE.fullmatch(candidate) is None:
        raise ValueError(
            f"User preset id {raw_preset_id!r} must match [A-Z][A-Z0-9_-]*."
        )
    return candidate


def _coerce_user_preset(
    raw_preset_id: str,
    raw_payload: Any,
) -> ProfilePreset:
    if isinstance(raw_payload, dict) is False:
        raise ValueError(
            f"User preset {raw_preset_id!r} payload must be an object with "
            f"'menu_ids' and optional 'description'."
        )
    preset_id = _normalize_user_preset_id(raw_preset_id)
    raw_menu_ids = raw_payload.get("menu_ids")
    if isinstance(raw_menu_ids, list) is False:
        raise ValueError(
            f"User preset {preset_id!r} requires a 'menu_ids' list."
        )
    menu_ids_tuple: tuple[str, ...] = tuple(str(item) for item in raw_menu_ids)
    _validate_menu_id_structure(preset_id, menu_ids_tuple)
    description = str(raw_payload.get("description") or "User-defined preset.")
    return ProfilePreset(
        preset_id=preset_id,
        description=description,
        menu_ids=menu_ids_tuple,
        source="user",
    )


def load_user_presets(config_path: Path) -> list[ProfilePreset]:
    """
    Read user-defined presets from a JSON config file. Missing files yield
    an empty list. The file must contain either a ``{preset_id: {...}}``
    mapping or a ``{"presets": {...}}`` object.
    """
    if config_path is None:
        return []
    candidate = Path(config_path)
    if candidate.exists() is False:
        return []
    raw_text = candidate.read_text(encoding="utf-8")
    payload = json.loads(raw_text)
    if isinstance(payload, dict) is False:
        raise ValueError(
            f"User preset file {candidate} must contain a JSON object at root."
        )
    preset_map = payload
    nested = payload.get("presets")
    if isinstance(nested, dict):
        preset_map = nested
    out: list[ProfilePreset] = []
    for raw_preset_id, raw_payload in preset_map.items():
        out.append(_coerce_user_preset(str(raw_preset_id), raw_payload))
    return out


def register_user_presets(presets: list[ProfilePreset]) -> list[str]:
    """
    Merge ``presets`` into the module registry. Returns the list of preset
    ids that were registered. Raises ``ValueError`` for any invalid entry.
    """
    registered: list[str] = []
    for preset in presets:
        if isinstance(preset, ProfilePreset) is False:
            raise ValueError("register_user_presets expects ProfilePreset instances.")
        _validate_menu_id_structure(preset.preset_id, preset.menu_ids)
        _PROFILE_PRESETS[preset.preset_id] = preset
        registered.append(preset.preset_id)
    return registered


def default_user_presets_path() -> Path:
    """Return the default path for the user-local presets JSON file (``~/`` based)."""
    return Path.home() / _USER_PRESETS_FILENAME


def build_scaffold_profile_document(
    preset_id: str,
    workspace_root: Path,
) -> dict[str, Any]:
    """
    Build a freshly scaffolded decoded document for the requested preset.

    Returned document matches the ``all_pe`` layout produced by
    ``SaipToolBridge.build_decoded_dump_document``, so it is directly usable by
    ``build_placeholder_template_document`` and
    ``build_profile_sequence_from_document``.
    """
    preset = get_preset(preset_id)
    ensure_workspace_pysim_on_path(Path(workspace_root))

    from pySim.esim.saip import ProfileElementSequence

    factories = _factory_map()
    pes = ProfileElementSequence()
    pes.pe_list = []

    for menu_id in preset.menu_ids:
        if menu_id not in factories:
            raise ValueError(
                f"Preset {preset.preset_id!r} references unknown PE menu id {menu_id!r}."
            )
        constructor = factories[menu_id]
        new_pe = constructor()
        if hasattr(new_pe, "_post_decode"):
            new_pe._post_decode()
        new_pe.pe_sequence = pes
        pes.pe_list.append(new_pe)

    try:
        pes._process_pelist()
        pes.renumber_identification()
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise ValueError(
            f"Failed to initialize PE sequence for preset {preset.preset_id!r}: {detail}"
        ) from error

    intro_lines = [
        f"Scaffolded profile for preset '{preset.preset_id}' "
        f"({len(pes.pe_list)} PEs)"
    ]
    return build_decoded_document_from_sequence(pes, intro_lines=intro_lines)


def build_scaffold_profile_document_from_menu_ids(
    preset_label: str,
    menu_ids: tuple[str, ...],
    workspace_root: Path,
) -> dict[str, Any]:
    """
    Same semantics as ``build_scaffold_profile_document`` but takes an explicit
    menu-id tuple. Used by the wizard when the user customises the PE list.
    """
    ensure_workspace_pysim_on_path(Path(workspace_root))
    _validate_menu_id_factories(preset_label, menu_ids)

    from pySim.esim.saip import ProfileElementSequence

    factories = _factory_map()
    pes = ProfileElementSequence()
    pes.pe_list = []

    for menu_id in menu_ids:
        new_pe = factories[menu_id]()
        if hasattr(new_pe, "_post_decode"):
            new_pe._post_decode()
        new_pe.pe_sequence = pes
        pes.pe_list.append(new_pe)

    try:
        pes._process_pelist()
        pes.renumber_identification()
    except Exception as error:
        detail = str(error).strip() or error.__class__.__name__
        raise ValueError(
            f"Failed to initialize PE sequence for custom preset "
            f"{preset_label!r}: {detail}"
        ) from error

    intro_lines = [
        f"Scaffolded profile for custom preset '{preset_label}' "
        f"({len(pes.pe_list)} PEs)"
    ]
    return build_decoded_document_from_sequence(pes, intro_lines=intro_lines)
