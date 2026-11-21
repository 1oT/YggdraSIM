# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Compiled GSMA RSP schemas for schema-aware ES10 decoding.

The SGP.22 module is pySim's v2 text, which the pinned fork gives the two
names SGP.32 imports from it, ``OperatorId`` and ``VendorSpecificExtension``
(``upstream_patches/osmocom-pysim-rsp-operatorid/``). The SGP.32 v1.3 module
is the copy the specification library unpacked under
``docs/tel-docs/converted/_assets/SGP.32-v1.3/``; the two are compiled
together. Everything degrades to ``None``: a missing pySim, a missing
asset or a compile error leaves the generic BER tree as the fallback.

The SGP.22 v3.1 module of the pinned pySim (``pySim.esim.rsp.asn1_v3``,
``upstream_patches/osmocom-pysim-rsp-v3-module/``) is a second
specification. It cannot join the compile above: it is a second
``RSPDefinitions``, and SGP.32 v1.3 imports names from the v2 one that v3.1
dropped. It answers for the type names the first specification lacks -- the
types v3.1 added (``EuiccConfiguredData``, ``LoadRpmPackage``,
``CheckProgress``, ...) -- and first for ``EUICCInfo1`` and
``StoreMetadataRequest``, whose v3.1 members the v2 text does not carry and
whose v3.1 definition decodes a v2 encoding as well. Every other type decodes
as before.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

_LOCK = threading.Lock()
# "parsed" keeps asn1tools' parse tree of the joint compile: the DER codec drops
# the named bits and named numbers a display needs (RspCapability, ProfileState).
_CACHE: dict[str, Any] = {
    "loaded": False, "spec": None, "parsed": None, "error": "", "modules": [],
    "v3": None, "v3Parsed": None, "v3Error": "",
}
_V3_MODULE = "SGP.22 v3.1 (pySim rsp_v3)"
# v3.1 adds members on tags v2 leaves unused and renames svn and OperatorID, so its
# definition reads a v2 encoding of these as well and keeps the v3 members.
_V31_FIRST = frozenset({"EUICCInfo1", "StoreMetadataRequest"})


def _sgp32_asset_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    return root / "docs" / "tel-docs" / "converted" / "_assets" / "SGP.32-v1.3" / "SGP.32-v1.3.asn1"


def _read_rsp_schema_text() -> str:
    """Return the concatenated RSP ASN.1 files shipped by the resolved pySim."""
    from importlib import resources

    # Explicit encoding, unlike pySim's own reader: a Windows console locale
    # would otherwise decode the UTF-8 files as cp1252.
    directory = resources.files("pySim.esim").joinpath("asn1").joinpath("rsp")
    texts = [entry.read_text(encoding="utf-8") for entry in directory.iterdir() if entry.name.endswith(".asn")]
    return "\n".join(texts) + "\n"


def _parsed_lookup(parsed: dict[str, Any], type_name: str, module_name: str) -> tuple[dict[str, Any] | None, str]:
    """A type's parse-tree entry, following IMPORTS the way asn1tools resolves names."""
    for _ in range(8):
        module = parsed.get(module_name) or {}
        definition = (module.get("types") or {}).get(type_name)
        if isinstance(definition, dict):
            return definition, module_name
        source = next((name for name, names in (module.get("imports") or {}).items() if type_name in names), None)
        if source is None or source not in parsed:
            return None, module_name
        module_name = source
    return None, module_name


def _flattened_members(members: list[Any]) -> list[dict[str, Any]]:
    """Components with extension addition groups opened, as asn1tools' flatten does."""
    flat: list[dict[str, Any]] = []
    for item in members:
        for entry in item if isinstance(item, list) else [item]:
            if isinstance(entry, dict):
                flat.append(entry)
    return flat


def _compile_text(asn1tools: Any, text: str) -> tuple[Any, dict[str, Any]]:
    """parse_string and compile_dict (compile_string's two steps), keeping the parse tree."""
    parsed = asn1tools.parse_string(text)
    return asn1tools.compile_dict(parsed, codec="der"), parsed


def _compile() -> None:
    try:
        import asn1tools
    except Exception as error:  # noqa: BLE001 - optional dependency chain
        _CACHE.update(loaded=True, spec=None, error=f"{type(error).__name__}: {error}")
        return
    try:
        sgp22_text = _read_rsp_schema_text()
    except Exception as error:  # noqa: BLE001 - pySim schema files unavailable
        _CACHE.update(loaded=True, spec=None, error=f"{type(error).__name__}: {error}")
        return
    modules = ["SGP.22 v2 (pySim RSPDefinitions)"]
    texts = [sgp22_text]
    asset = _sgp32_asset_path()
    if asset.is_file():
        try:
            texts.append(asset.read_text(encoding="utf-8", errors="replace"))
            modules.append("SGP.32 v1.3 (library asset)")
        except OSError:
            pass
    try:
        spec, parsed = _compile_text(asn1tools, "\n".join(texts))
        skipped = ""
    except Exception as error:  # noqa: BLE001 - asn1tools compile errors are library-specific
        if len(texts) == 1:
            _CACHE.update(loaded=True, spec=None, error=f"{type(error).__name__}: {error}", modules=[])
            return
        # The SGP.32 asset is the optional half; keep SGP.22 alone if it
        # was the addition that failed.
        try:
            spec, parsed = _compile_text(asn1tools, texts[0])
        except Exception as inner:  # noqa: BLE001
            _CACHE.update(loaded=True, spec=None, error=f"{type(inner).__name__}: {inner}", modules=[])
            return
        modules = modules[:1]
        skipped = f"SGP.32 module skipped: {type(error).__name__}: {error}"
    _CACHE.update(loaded=True, spec=spec, parsed=parsed, error=skipped, modules=modules)


# pySim.esim.rsp.asn1_v3 compiles these paths below pySim/esim/asn1/ with
# compile_asn1_paths; the same text is compiled here to keep its parse tree,
# which holds the named bits and numbers the DER codec drops.
_V3_PATHS = ("rsp/PKIX1Explicit88.asn", "rsp/PKIX1Implicit88.asn", "saip", "rsp_v3")


def _read_pysim_asn1(paths: tuple[str, ...]) -> str:
    """The text pySim's compile_asn1_paths concatenates for ``paths``."""
    from importlib import resources

    root = resources.files("pySim.esim").joinpath("asn1")
    text = ""
    for path in paths:
        entry = root.joinpath(path)
        if entry.is_dir():
            files = sorted((item for item in entry.iterdir() if item.name.endswith(".asn")), key=lambda item: item.name)
        else:
            files = [entry]
        for item in files:
            text += item.read_text(encoding="utf-8") + "\n"
    return text


def _compile_v3() -> None:
    """Load pySim's SGP.22 v3.1 module when the resolved pySim carries one."""
    try:
        from pySim.esim import rsp as pysim_rsp
    except Exception as error:  # noqa: BLE001 - optional dependency chain
        _CACHE.update(v3=None, v3Error=f"{type(error).__name__}: {error}")
        return
    # The module text decides: reading pySim's attribute form of asn1_v3 would compile it.
    try:
        text = _read_pysim_asn1(_V3_PATHS)
    except OSError:
        _CACHE.update(v3=None, v3Error="the resolved pySim has no SGP.22 v3.1 module")
        return
    try:
        import asn1tools

        spec, parsed = _compile_text(asn1tools, text)
    except Exception as error:  # noqa: BLE001 - asn1tools compile errors are library-specific
        own_error = f"{type(error).__name__}: {error}"
    else:
        _CACHE.update(v3=spec, v3Parsed=parsed, v3Error="")
        return
    # pySim's own compile still decodes; only the named values of v3.1 types are lost. The
    # pinned fork has the function rsp.asn1_v3(), the version under review a module attribute.
    try:
        accessor = getattr(pysim_rsp, "asn1_v3", None)
        if accessor is None:
            raise AttributeError("the resolved pySim has no SGP.22 v3.1 module")
        v3 = accessor() if callable(accessor) else accessor
        _CACHE.update(v3=v3, v3Error=f"compiled by pySim without a parse tree ({own_error})")
    except Exception as error:  # noqa: BLE001 - asn1tools compile errors are library-specific
        _CACHE.update(v3=None, v3Error=f"{type(error).__name__}: {error}")


def rsp_specification() -> Any | None:
    """Return the compiled asn1tools specification, or None when unavailable."""
    with _LOCK:
        if not _CACHE["loaded"]:
            _compile()
            _compile_v3()
        return _CACHE["spec"]


def _v3_specification() -> Any | None:
    rsp_specification()
    with _LOCK:
        return _CACHE["v3"]


def rsp_specification_status() -> dict[str, Any]:
    """Describe what is compiled, for the decoder's provenance block."""
    spec = rsp_specification()
    v3 = _v3_specification()
    v3_only = 0
    if v3 is not None:
        v3_only = sum(1 for name in _v3_rsp_types(v3) if spec is None or _resolve_type(spec, name) is None)
    with _LOCK:
        modules = list(_CACHE["modules"])
        if v3 is not None:
            modules.append(_V3_MODULE)
        return {
            "available": spec is not None or v3 is not None,
            "modules": modules,
            "error": str(_CACHE["error"] or ""),
            "typeCount": (len(spec.types) if spec is not None else 0) + v3_only,
            "v3Error": str(_CACHE["v3Error"] or ""),
        }


# asn1tools removes a type name that two modules both declare from the flat
# ``types`` table and keeps it only under ``modules``; SGP.32 redeclares
# several SGP.22 types (ProfileInfoListResponse among them), so lookups try
# the flat table first and then the modules, IoT module first because its
# redeclarations are supersets of the SGP.22 ones.
_MODULE_PREFERENCE = ("SGP32Definitions", "RSPDefinitions")


def _resolve_type(spec: Any, type_name: str) -> Any | None:
    flat = spec.types.get(type_name)
    if flat is not None:
        return flat
    modules = getattr(spec, "modules", {}) or {}
    for module_name in _MODULE_PREFERENCE:
        module_types = modules.get(module_name) or {}
        if type_name in module_types:
            return module_types[type_name]
    for module_types in modules.values():
        if type_name in module_types:
            return module_types[type_name]
    return None


def _v3_rsp_types(v3: Any) -> dict[str, Any]:
    # The v3.1 compile also carries the PKIX and SAIP modules it imports from;
    # only its RSPDefinitions types answer here.
    return (getattr(v3, "modules", {}) or {}).get("RSPDefinitions") or {}


def _compiled_type(type_name: str) -> tuple[Any, bool] | None:
    """The compiled type and whether it came from the v3.1 module.

    ``_V31_FIRST`` types come from the v3.1 module when there is one; every other
    type from the joint compile first.
    """
    if type_name in _V31_FIRST:
        v3 = _v3_specification()
        compiled = _v3_rsp_types(v3).get(type_name) if v3 is not None else None
        if compiled is not None:
            return compiled, True
    spec = rsp_specification()
    if spec is not None:
        compiled = _resolve_type(spec, type_name)
        if compiled is not None:
            return compiled, False
    v3 = _v3_specification()
    if v3 is not None:
        compiled = _v3_rsp_types(v3).get(type_name)
        if compiled is not None:
            return compiled, True
    return None


def has_type(type_name: str) -> bool:
    return _compiled_type(type_name) is not None


def type_source(type_name: str) -> list[str]:
    """Name the modules behind the specification that decodes ``type_name``."""
    found = _compiled_type(type_name)
    if found is None:
        return []
    if found[1]:
        return [_V3_MODULE]
    with _LOCK:
        return list(_CACHE["modules"])


def decode_type(type_name: str, data: bytes) -> Any:
    """Decode ``data`` as ``type_name``; raises when the spec or type is missing."""
    if rsp_specification() is None and _v3_specification() is None:
        raise RuntimeError("RSP ASN.1 specification is not compiled")
    found = _compiled_type(type_name)
    if found is None:
        raise KeyError(type_name)
    return found[0].decode(data)


def decode_type_strict(type_name: str, data: bytes) -> Any:
    """Decode ``data`` as ``type_name`` only when the type reads all of it.

    asn1tools ignores bytes after the value, and reads an extensible CHOICE
    whose tag matches no alternative (the RSP modules are EXTENSIBILITY
    IMPLIED) as ``(None, None)`` instead of failing. Both are a mismatch
    here, so of two types sharing an outer tag -- IpaEuiccDataRequest
    (SGP.32 v1.3 §2.11.1.2) and IpaEuiccDataResponse (§2.11.2.2) are both
    'BF52' -- the one the content does not fit is never chosen.
    """
    if rsp_specification() is None and _v3_specification() is None:
        raise RuntimeError("RSP ASN.1 specification is not compiled")
    found = _compiled_type(type_name)
    if found is None:
        raise KeyError(type_name)
    value, length = found[0].decode_with_length(data)
    if length != len(data):
        raise ValueError(f"{type_name} ends after {length} of {len(data)} bytes")
    if isinstance(value, tuple) and value == (None, None):
        raise ValueError(f"{type_name}: the tag matches no CHOICE alternative")
    return value


def encode_type(type_name: str, value: Any) -> bytes:
    """DER of ``value`` as ``type_name``; raises when the spec or type is missing."""
    found = _compiled_type(type_name)
    if found is None:
        raise KeyError(type_name)
    return bytes(found[0].encode(value))


def type_tree(type_name: str) -> Any | None:
    """The asn1tools codec type of ``type_name``, for walking a decoded value.

    Its members carry their name, their BER tag (``tag``) and the name of the
    type they reference (``type_name``); None when the type is not compiled.
    """
    found = _compiled_type(type_name)
    return found[0].type if found is not None else None


def named_values(type_name: str = "", *, owner: str = "", member: str = "") -> dict[int, str]:
    """The named numbers of an INTEGER or the named bits of a BIT STRING, value -> name.

    ``type_name`` is a referenced type (``ProfileState``, ``RspCapability``);
    a type written inline is found as ``member`` of the type ``owner``
    (``IpaCapabilities`` and ``ipaFeatures``). Empty when the joint compile
    kept no parse tree or the type names no values.
    """
    rsp_specification()
    with _LOCK:
        trees = [tree for tree in (_CACHE["parsed"], _CACHE["v3Parsed"]) if tree]
    names: dict[int, str] = {}
    # The joint compile names first; a later version adds bits and numbers it
    # lacks (SGP.22 v3.1 RspCapability goes past the v2 testProfileSupport(3)).
    for parsed in trees:
        definition = _parsed_type(parsed, type_name) if type_name else None
        if definition is None and owner and member:
            holder = _parsed_type(parsed, owner) or {}
            for entry in _flattened_members(holder.get("members") or []):
                if entry.get("name") == member:
                    definition = entry
                    break
        for number, name in _value_names(definition).items():
            names.setdefault(number, name)
    later = _LATER_TYPE_NAMES.get(type_name)
    if later:
        for number, name in named_values(later).items():
            names.setdefault(number, name)
    return names


# A type a later version renamed: the bits it added sit under the new name.
# SGP.22 v3.1 section 4.3 defines EuiccRspCapability where the v2 text has
# RspCapability, with deviceInfoExtensibilitySupport(4) marked as supported
# from v2.2.2 and serviceSpecificDataSupport(5) from v2.4.0.
_LATER_TYPE_NAMES: dict[str, str] = {"RspCapability": "EuiccRspCapability"}


# Built-in type names of the parse tree; any other ``type`` is a reference.
ASN1_KEYWORDS = frozenset(
    {
        "SEQUENCE", "SET", "SEQUENCE OF", "SET OF", "CHOICE", "ExplicitTag", "RECURSIVE",
        "OCTET STRING", "BIT STRING", "INTEGER", "BOOLEAN", "NULL", "ENUMERATED", "REAL",
        "OBJECT IDENTIFIER", "RELATIVE-OID", "UTF8String", "IA5String", "PrintableString",
        "VisibleString", "NumericString", "BMPString", "TeletexString", "UniversalString",
        "GeneralString", "GraphicString", "ObjectDescriptor", "GeneralizedTime", "UTCTime",
        "DATE", "TIME-OF-DAY", "DATE-TIME", "ANY", "ANY DEFINED BY",
    }
)


def parse_tree_for(type_name: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str]:
    """The parse tree ``type_name`` was compiled from, its entry there and its module.

    (None, None, "") when that compile kept no parse tree, which is the case for
    pySim's own SGP.22 v3.1 compile when the text could not be read here.
    """
    found = _compiled_type(type_name)
    if found is None:
        return None, None, ""
    with _LOCK:
        tree = _CACHE["v3Parsed"] if found[1] else _CACHE["parsed"]
    if not tree:
        return None, None, ""
    module = str(getattr(found[0], "module_name", "") or "")
    entry = ((tree.get(module) or {}).get("types") or {}).get(type_name) or _parsed_type(tree, type_name)
    definition, module = resolve_definition(tree, entry, module)
    return tree, definition, module


def resolve_definition(tree: dict[str, Any], definition: Any, module_name: str = "") -> tuple[dict[str, Any] | None, str]:
    """Follow a type reference to the entry that carries the structure or the named values."""
    for _ in range(32):
        if not isinstance(definition, dict):
            return None, module_name
        if any(key in definition for key in ("members", "element", "named-numbers", "named-bits")):
            return definition, module_name
        type_name = str(definition.get("type") or "")
        if not type_name or type_name in ASN1_KEYWORDS:
            return definition, module_name
        target, found_module = _parsed_lookup(tree, type_name, module_name) if module_name else (None, module_name)
        if target is None:
            target, found_module = _parsed_type(tree, type_name), module_name
        if target is None:
            return definition, module_name
        definition, module_name = target, found_module
    return definition if isinstance(definition, dict) else None, module_name


def members_of(definition: Any) -> dict[str, dict[str, Any]]:
    """The members of a SEQUENCE, SET or CHOICE entry by name, extension additions included."""
    if not isinstance(definition, dict):
        return {}
    return {str(entry["name"]): entry for entry in _flattened_members(definition.get("members") or []) if entry.get("name")}


def definition_values(definition: Any, type_name: str = "") -> dict[int, str]:
    """The named numbers or bits of a parse-tree entry, value -> name.

    A referenced type's names are completed from the other parse tree, which a
    later version may give more of (SGP.22 v3.1 against the v2 text).
    """
    names = _value_names(definition)
    if type_name:
        for number, name in named_values(type_name).items():
            names.setdefault(number, name)
    return names


def _parsed_type(parsed: dict[str, Any], type_name: str) -> dict[str, Any] | None:
    ordered = [name for name in _MODULE_PREFERENCE if name in parsed]
    ordered += [name for name in parsed if name not in ordered]
    for module_name in ordered:
        definition = ((parsed.get(module_name) or {}).get("types") or {}).get(type_name)
        if isinstance(definition, dict):
            return definition
    return None


def _value_names(definition: dict[str, Any] | None) -> dict[int, str]:
    if not isinstance(definition, dict):
        return {}
    names: dict[int, str] = {}
    numbers = definition.get("named-numbers")
    if isinstance(numbers, dict):
        for name, number in numbers.items():
            if isinstance(number, int):
                names[number] = str(name)
    for entry in definition.get("named-bits") or []:
        # The parser keeps each named bit as a (name, number text) pair.
        try:
            name, number = entry
            names[int(number)] = str(name)
        except (TypeError, ValueError):
            continue
    return names
