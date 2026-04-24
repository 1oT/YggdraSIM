"""
Tag-granular provisioning wizard for SAIP ``akaParameter`` profile elements.

The wizard is authored as a small pure-functional core so the shell, the
TRANSCODE-TUI and unit tests can drive it without a common UI layer. Each
logical AKA field is expressed as an independent "step" to satisfy the repo
rule that interactive wizards are split per tag.

The core purposely defers to ``pySim.esim.saip.ProfileElementAKA`` setter
helpers (``set_milenage``, ``set_tuak``, ``set_xor3g``) for the underlying
``algoConfiguration`` shape, so the emitted DER tracks the pySim
templates used by production cards.

Covered fields:

* ``algorithm``       -> algorithmID + shape of ``algoConfiguration``
* ``key``             -> Ki (MILENAGE/TUAK/XOR-3G)
* ``opc``             -> OPc (MILENAGE) / TOPc (TUAK) / ignored (XOR-3G)
* ``numberOfKeccak``  -> TUAK-only Keccak iteration count
* ``authCounterMax``  -> optional 3-byte AKA counter ceiling
* ``sqnInit``         -> optional 6-byte SQN seed, broadcast to 32 slots
"""

from __future__ import annotations

import copy
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any

from .saip_json_codec import (
    _TAG_BYTES,
    _LEGACY_TAG_BYTES,
    base_pe_type,
    build_decoded_document_from_sequence,
    build_profile_sequence_from_document,
    ensure_workspace_pysim_on_path,
)


AKA_ALGORITHM_IDS: dict[str, int] = {
    "milenage": 1,
    "tuak": 2,
    "xor-3g": 3,
    "usim-test-algorithm": 3,
}


_ALGO_ID_TO_CANONICAL: dict[int, str] = {
    1: "milenage",
    2: "tuak",
    3: "xor-3g",
}


def aka_algorithm_choices() -> list[tuple[str, str, str]]:
    """
    Ordered wizard choices for the ``algorithm`` step: ``(id, label, hint)``.
    ``id`` values are stable for tests and keybindings.
    """
    return [
        ("milenage", "MILENAGE", "3GPP TS 35.206 (Ki 16 bytes, OPc 16 bytes)"),
        ("tuak", "TUAK", "3GPP TS 35.231 (Ki 16 or 32 bytes, TOPc 32 bytes)"),
        (
            "xor-3g",
            "XOR-3G (USIM test algorithm)",
            "3GPP TS 34.108 (Ki 16 bytes, OPc unused)",
        ),
    ]


def normalize_algorithm(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in AKA_ALGORITHM_IDS:
        if normalized == "usim-test-algorithm":
            return "xor-3g"
        return normalized
    raise ValueError(
        "algorithm must be one of: "
        + ", ".join(sorted(set(AKA_ALGORITHM_IDS.keys())))
    )


def _compact_hex(value: Any, *, label: str) -> str:
    text = re.sub(r"\s+", "", str(value or ""))
    text = text.replace(":", "").replace("-", "").replace("_", "")
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    if len(text) == 0:
        return ""
    if re.fullmatch(r"[0-9a-fA-F]+", text) is None:
        raise ValueError(f"{label} must be hexadecimal.")
    if len(text) % 2 != 0:
        raise ValueError(f"{label} must have even-length hex.")
    return text.upper()


def _require_hex_bytes(
    value: Any,
    *,
    label: str,
    allowed_byte_lengths: tuple[int, ...],
) -> bytes:
    hex_text = _compact_hex(value, label=label)
    if len(hex_text) == 0:
        raise ValueError(f"{label} must not be empty.")
    raw = bytes.fromhex(hex_text)
    if len(raw) not in allowed_byte_lengths:
        expected_list = ", ".join(str(n) for n in allowed_byte_lengths)
        raise ValueError(
            f"{label} must be exactly {expected_list} bytes (got {len(raw)})."
        )
    return raw


def _optional_hex_bytes(
    value: Any,
    *,
    label: str,
    allowed_byte_lengths: tuple[int, ...],
) -> bytes | None:
    hex_text = _compact_hex(value, label=label)
    if len(hex_text) == 0:
        return None
    raw = bytes.fromhex(hex_text)
    if len(raw) not in allowed_byte_lengths:
        expected_list = ", ".join(str(n) for n in allowed_byte_lengths)
        raise ValueError(
            f"{label} must be exactly {expected_list} bytes (got {len(raw)})."
        )
    return raw


def validate_key_for_algorithm(algorithm: str, key_hex: Any) -> bytes:
    algo = normalize_algorithm(algorithm)
    if algo == "tuak":
        return _require_hex_bytes(key_hex, label="key", allowed_byte_lengths=(16, 32))
    return _require_hex_bytes(key_hex, label="key", allowed_byte_lengths=(16,))


def validate_opc_for_algorithm(algorithm: str, opc_hex: Any) -> bytes:
    algo = normalize_algorithm(algorithm)
    if algo == "xor-3g":
        return b""
    if algo == "tuak":
        return _require_hex_bytes(opc_hex, label="opc", allowed_byte_lengths=(32,))
    return _require_hex_bytes(opc_hex, label="opc", allowed_byte_lengths=(16,))


def validate_number_of_keccak(value: Any) -> int:
    if value is None:
        return 1
    if isinstance(value, bool):
        raise ValueError("numberOfKeccak must be an integer.")
    if isinstance(value, int):
        normalized = int(value)
    else:
        text = str(value or "").strip()
        if len(text) == 0:
            return 1
        if text.isdigit() is False:
            raise ValueError("numberOfKeccak must be a decimal integer.")
        normalized = int(text)
    if normalized < 1 or normalized > 0xFF:
        raise ValueError("numberOfKeccak must be in [1, 255].")
    return normalized


def validate_auth_counter_max(value: Any) -> bytes | None:
    return _optional_hex_bytes(
        value,
        label="authCounterMax",
        allowed_byte_lengths=(3,),
    )


def validate_sqn_init_seed(value: Any) -> bytes | None:
    return _optional_hex_bytes(
        value,
        label="sqnInit",
        allowed_byte_lengths=(6,),
    )


def aka_wizard_steps(algorithm: str | None = None) -> list[dict[str, Any]]:
    """
    Ordered, tag-granular step descriptors. When ``algorithm`` is ``None``,
    the full step list is returned. When supplied, TUAK-specific steps are
    pruned for MILENAGE / XOR-3G so the prompt sequence stays minimal.
    """
    algo = None
    if algorithm is not None:
        algo = normalize_algorithm(algorithm)
    steps: list[dict[str, Any]] = [
        {
            "key": "algorithm",
            "title": "Select AKA algorithm",
            "required": True,
            "hint": "MILENAGE / TUAK / XOR-3G",
        },
        {
            "key": "key",
            "title": "Enter Ki (authentication key)",
            "required": True,
            "hint": "32 hex chars for MILENAGE/XOR-3G, 32 or 64 for TUAK",
        },
        {
            "key": "opc",
            "title": "Enter OPc / TOPc",
            "required": algo != "xor-3g",
            "hint": "32 hex chars (MILENAGE) or 64 (TUAK); ignored for XOR-3G",
        },
        {
            "key": "numberOfKeccak",
            "title": "TUAK Keccak iteration count",
            "required": False,
            "tuak_only": True,
            "hint": "Decimal in [1, 255]; defaults to 1",
        },
        {
            "key": "authCounterMax",
            "title": "Authentication counter ceiling",
            "required": False,
            "hint": "Optional 6 hex chars (3 bytes); blank keeps default",
        },
        {
            "key": "sqnInit",
            "title": "SQN init seed",
            "required": False,
            "hint": "Optional 12 hex chars (6 bytes); broadcast to 32 slots",
        },
    ]
    if algo is None or algo == "tuak":
        return steps
    return [step for step in steps if step.get("tuak_only") is not True]


def _algo_parameter_to_decoded(
    algorithm: str,
    *,
    key: bytes,
    opc: bytes,
    number_of_keccak: int | None,
    auth_counter_max: bytes | None,
) -> tuple[str, dict[str, Any]]:
    algo = normalize_algorithm(algorithm)
    if algo == "milenage":
        payload: dict[str, Any] = {
            "algorithmID": 1,
            "algorithmOptions": b"\x00",
            "key": key,
            "opc": opc,
        }
        if auth_counter_max is not None:
            payload["authCounterMax"] = bytes(auth_counter_max)
        return ("algoParameter", payload)
    if algo == "tuak":
        keccak_value = 1 if number_of_keccak is None else int(number_of_keccak)
        payload = {
            "algorithmID": 2,
            "algorithmOptions": b"\x00",
            "key": key,
            "opc": opc,
            "numberOfKeccak": keccak_value,
        }
        if auth_counter_max is not None:
            payload["authCounterMax"] = bytes(auth_counter_max)
        return ("algoParameter", payload)
    payload = {
        "algorithmID": 3,
        "algorithmOptions": b"\x00",
        "key": key,
        "opc": b"",
    }
    return ("algoParameter", payload)


def _existing_aka_section_keys(document: dict[str, Any]) -> list[str]:
    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Document 'sections' must be an object.")
    return [
        section_key
        for section_key in sections.keys()
        if base_pe_type(str(section_key)) == "akaParameter"
    ]


def _hex_from_tagged(value: Any) -> str:
    if isinstance(value, dict):
        for tag in (_TAG_BYTES, _LEGACY_TAG_BYTES):
            if tag in value:
                return str(value[tag] or "").strip().upper()
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex().upper()
    if isinstance(value, str):
        return _compact_hex(value, label="hex")
    return ""


def read_aka_configuration(
    document: dict[str, Any],
    section_key: str,
) -> dict[str, Any]:
    """
    Project the current ``akaParameter`` section into a flat dictionary
    that mirrors the wizard step keys. Missing optional fields return
    empty strings, which the wizard treats as "leave unchanged".
    """
    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Document 'sections' must be an object.")
    if section_key not in sections:
        raise ValueError(f"Unknown profile element key: {section_key!r}")
    if base_pe_type(str(section_key)) != "akaParameter":
        raise ValueError(
            f"Section {section_key!r} is not an akaParameter PE."
        )

    decoded = sections[section_key]
    result: dict[str, Any] = {
        "algorithm": "",
        "key": "",
        "opc": "",
        "numberOfKeccak": "",
        "authCounterMax": "",
        "sqnInit": "",
    }

    algo_config = decoded.get("algoConfiguration") if isinstance(decoded, dict) else None
    choice_name: Any = None
    payload: Any = None
    if isinstance(algo_config, tuple) and len(algo_config) == 2:
        choice_name, payload = algo_config[0], algo_config[1]
    elif isinstance(algo_config, list) and len(algo_config) == 2:
        choice_name, payload = algo_config[0], algo_config[1]
    elif isinstance(algo_config, dict) and "@" in algo_config:
        algo_list = algo_config.get("@")
        if isinstance(algo_list, list) and len(algo_list) == 2:
            choice_name, payload = algo_list[0], algo_list[1]

    if choice_name == "algoParameter" and isinstance(payload, dict):
        algo_id = int(payload.get("algorithmID", 0) or 0)
        canonical = _ALGO_ID_TO_CANONICAL.get(algo_id, "")
        result["algorithm"] = canonical
        result["key"] = _hex_from_tagged(payload.get("key"))
        result["opc"] = _hex_from_tagged(payload.get("opc"))
        keccak_value = payload.get("numberOfKeccak")
        if isinstance(keccak_value, int):
            result["numberOfKeccak"] = str(keccak_value)
        elif isinstance(keccak_value, (bytes, bytearray)) and len(keccak_value) == 1:
            result["numberOfKeccak"] = str(int(bytes(keccak_value)[0]))
        else:
            keccak_hex = _hex_from_tagged(keccak_value)
            if len(keccak_hex) == 2:
                result["numberOfKeccak"] = str(int(keccak_hex, 16))
        result["authCounterMax"] = _hex_from_tagged(payload.get("authCounterMax"))

    sqn_init = decoded.get("sqnInit") if isinstance(decoded, dict) else None
    if isinstance(sqn_init, list) and len(sqn_init) > 0:
        seed_hex = _hex_from_tagged(sqn_init[0])
        if len(seed_hex) > 0 and all(
            _hex_from_tagged(entry) == seed_hex for entry in sqn_init
        ):
            result["sqnInit"] = seed_hex

    return result


def _resolve_aka_pe(pes: Any, section_index: int) -> Any:
    try:
        pe = pes.pe_list[section_index]
    except IndexError as exc:
        raise ValueError(
            f"Profile element index {section_index} out of range."
        ) from exc
    if str(getattr(pe, "type", "")).strip() != "akaParameter":
        raise ValueError(
            f"Profile element at index {section_index} is not akaParameter."
        )
    return pe


def apply_aka_configuration(
    document: dict[str, Any],
    workspace_root: Path,
    *,
    section_key: str,
    algorithm: str,
    key_hex: Any,
    opc_hex: Any = "",
    number_of_keccak: Any = None,
    auth_counter_max_hex: Any = "",
    sqn_init_hex: Any = "",
) -> dict[str, Any]:
    """
    Validate the wizard inputs, rebuild the target ``akaParameter`` PE in
    place, and re-emit the document via the same pySim pipeline used by
    encode/decode so downstream DER encoding stays consistent.
    """
    ensure_workspace_pysim_on_path(workspace_root)

    algo = normalize_algorithm(algorithm)
    key_bytes = validate_key_for_algorithm(algo, key_hex)
    opc_bytes = validate_opc_for_algorithm(algo, opc_hex)
    keccak_value = None
    if algo == "tuak":
        keccak_value = validate_number_of_keccak(number_of_keccak)
    auth_counter_bytes = validate_auth_counter_max(auth_counter_max_hex)
    sqn_seed_bytes = validate_sqn_init_seed(sqn_init_hex)

    sections = document.get("sections", {})
    if isinstance(sections, dict) is False:
        raise ValueError("Document 'sections' must be an object.")
    if section_key not in sections:
        raise ValueError(f"Unknown profile element key: {section_key!r}")
    if base_pe_type(str(section_key)) != "akaParameter":
        raise ValueError(
            f"Section {section_key!r} is not an akaParameter PE."
        )

    section_index = list(sections.keys()).index(section_key)

    pes = build_profile_sequence_from_document(document, workspace_root)
    pe = _resolve_aka_pe(pes, section_index)

    decoded = pe.decoded
    if isinstance(decoded, dict) is False:
        decoded = OrderedDict()
        pe.decoded = decoded

    decoded["algoConfiguration"] = _algo_parameter_to_decoded(
        algo,
        key=key_bytes,
        opc=opc_bytes,
        number_of_keccak=keccak_value,
        auth_counter_max=auth_counter_bytes,
    )

    if sqn_seed_bytes is not None:
        decoded["sqnInit"] = [bytes(sqn_seed_bytes) for _ in range(32)]

    pes._process_pelist()
    pes.renumber_identification()

    out_document = build_decoded_document_from_sequence(
        pes,
        intro_lines=_intro_lines_for(document),
    )
    _copy_document_meta(document, out_document)
    return out_document


def _intro_lines_for(document: dict[str, Any]) -> list[str]:
    intro = document.get("intro", [])
    if isinstance(intro, list):
        return list(intro)
    return [str(intro)]


def _copy_document_meta(
    source_document: dict[str, Any],
    target_document: dict[str, Any],
) -> None:
    from .saip_json_codec import _DOCUMENT_META_KEYS

    for meta_key in _DOCUMENT_META_KEYS:
        if meta_key in source_document:
            target_document[meta_key] = copy.deepcopy(source_document[meta_key])


def first_aka_section_key(document: dict[str, Any]) -> str | None:
    """
    Convenience helper for shells that want to operate on the first (or
    only) akaParameter PE in the profile.
    """
    aka_keys = _existing_aka_section_keys(document)
    if len(aka_keys) == 0:
        return None
    return aka_keys[0]


def list_aka_sections(document: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Summarise every ``akaParameter`` PE in the document without mutating it.

    The returned list is ordered to follow document order and each entry is
    a flat dict with:

    * ``section_key``       ordinal PE key (``akaParameter``, ``akaParameter-2``, ...)
    * ``index``              zero-based index into ``document['sections']``
    * ``algorithm``          canonical algorithm id (``milenage`` / ``tuak`` / ``xor-3g``) or ``""``
    * ``key_bytes``          Ki byte length (0 when absent or undecodable)
    * ``opc_bytes``          OPc / TOPc byte length (0 when absent)
    * ``number_of_keccak``   integer value or ``0`` when not applicable
    * ``auth_counter_max``   hex string ("" when absent)
    * ``sqn_init_present``   ``True`` when a 32-slot sqnInit was embedded

    Shells and tests get everything they need to render a compact table
    without duplicating the decode logic from ``read_aka_configuration``.
    """
    keys = _existing_aka_section_keys(document)
    if len(keys) == 0:
        return []
    section_list = list(document.get("sections", {}).keys())
    summaries: list[dict[str, Any]] = []
    for section_key in keys:
        snapshot = read_aka_configuration(document, section_key)
        decoded = document["sections"].get(section_key, {})
        sqn_init_present = False
        sqn_init_value = decoded.get("sqnInit") if isinstance(decoded, dict) else None
        if isinstance(sqn_init_value, list) and len(sqn_init_value) > 0:
            sqn_init_present = True
        key_hex = snapshot.get("key", "")
        opc_hex = snapshot.get("opc", "")
        keccak_text = snapshot.get("numberOfKeccak", "")
        try:
            keccak_int = int(keccak_text) if len(keccak_text) > 0 else 0
        except ValueError:
            keccak_int = 0
        summaries.append(
            {
                "section_key": section_key,
                "index": section_list.index(section_key),
                "algorithm": snapshot.get("algorithm", ""),
                "key_bytes": len(key_hex) // 2,
                "opc_bytes": len(opc_hex) // 2,
                "number_of_keccak": keccak_int,
                "auth_counter_max": snapshot.get("authCounterMax", ""),
                "sqn_init_present": sqn_init_present,
            }
        )
    return summaries


def randomize_aka_values(
    algorithm: str,
    *,
    randbytes: Any = None,
    include_number_of_keccak: bool = True,
    include_auth_counter_max: bool = False,
    include_sqn_init_seed: bool = False,
) -> dict[str, Any]:
    """
    Produce deterministic wizard-shaped values for the selected algorithm.

    The helper is intentionally stateless: callers inject ``randbytes`` so
    unit tests can pin the output, while the default path goes through
    ``secrets.token_bytes`` for cryptographically-random development keys.
    The returned dict uses the same keys as :func:`aka_wizard_steps` so
    it can be splatted directly into :func:`apply_aka_configuration`.

    The helper does **not** touch SQN state unless ``include_sqn_init_seed``
    is set, because a random SQN seed on a production profile would
    invalidate replay protection mid-session.
    """
    algo = normalize_algorithm(algorithm)
    source = randbytes
    if source is None:
        import secrets

        source = secrets.token_bytes
    result: dict[str, Any] = {
        "algorithm": algo,
        "key_hex": source(16).hex().upper(),
        "opc_hex": "",
        "number_of_keccak": None,
        "auth_counter_max_hex": "",
        "sqn_init_hex": "",
    }
    if algo == "tuak":
        result["key_hex"] = source(32).hex().upper()
        result["opc_hex"] = source(32).hex().upper()
        if include_number_of_keccak:
            # Keccak iteration count is a 1-byte profile parameter; default to 1
            # because higher values simply add latency on the simulator side.
            raw_byte = source(1)
            value = int(raw_byte[0]) if len(raw_byte) > 0 else 1
            if value < 1:
                value = 1
            if value > 0xFF:
                value = 0xFF
            result["number_of_keccak"] = value
    elif algo == "milenage":
        result["opc_hex"] = source(16).hex().upper()
    # XOR-3G leaves opc empty by design.
    if include_auth_counter_max:
        result["auth_counter_max_hex"] = source(3).hex().upper()
    if include_sqn_init_seed:
        result["sqn_init_hex"] = source(6).hex().upper()
    return result
