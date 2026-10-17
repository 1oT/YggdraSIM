# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Compiled GSMA RSP schemas for schema-aware ES10 decoding.

The SGP.22 module comes from pySim (v2 text plus the v3.1 metadata
supplement applied by ``SCP11.rsp_v3_schema``); the SGP.32 v1.3 module is
the copy the specification library unpacked under
``docs/tel-docs/converted/_assets/SGP.32-v1.3/``. SGP.32 imports
``OperatorId`` from the SGP.22 module, a type SGP.22 v3.1 declares
(ASN.1 module, page 438 of the v3.1 text) and the pySim v2 text does not,
so that one declaration is appended before both modules are compiled
together. Everything degrades to ``None``: a missing pySim, a missing
asset or a compile error leaves the generic BER tree as the fallback.
"""

from __future__ import annotations

import re
import threading
from pathlib import Path
from typing import Any

# SGP.22 v3.1 ASN.1 module (page 438). Comments dropped, structure kept.
_SGP22_V3_OPERATOR_ID = """
OperatorId ::= SEQUENCE {
   mccMnc OCTET STRING (SIZE(3)),
   gid1 OCTET STRING OPTIONAL,
   gid2 OCTET STRING OPTIONAL
}
"""

_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {"loaded": False, "spec": None, "error": "", "modules": []}


def _sgp32_asset_path() -> Path:
    root = Path(__file__).resolve().parents[2]
    return root / "docs" / "tel-docs" / "converted" / "_assets" / "SGP.32-v1.3" / "SGP.32-v1.3.asn1"


def _supplement_operator_id(schema_text: str) -> str:
    """Append ``OperatorId`` to the SGP.22 module when the text lacks it."""
    if re.search(r"^\s*OperatorId\s*::=", schema_text, re.M):
        return schema_text
    end_index = schema_text.rstrip().rfind("END")
    if end_index < 0:
        return schema_text
    return schema_text[:end_index] + _SGP22_V3_OPERATOR_ID + "\n" + schema_text[end_index:]


def _compile() -> None:
    try:
        import asn1tools
        from SCP11.rsp_v3_schema import apply_v3_metadata_supplement, read_rsp_schema_text
    except Exception as error:  # noqa: BLE001 - optional dependency chain
        _CACHE.update(loaded=True, spec=None, error=f"{type(error).__name__}: {error}")
        return
    try:
        sgp22_text = _supplement_operator_id(apply_v3_metadata_supplement(read_rsp_schema_text()))
    except Exception as error:  # noqa: BLE001 - pySim schema files unavailable
        _CACHE.update(loaded=True, spec=None, error=f"{type(error).__name__}: {error}")
        return
    modules = ["SGP.22 (pySim RSPDefinitions with the v3.1 supplements)"]
    texts = [sgp22_text]
    asset = _sgp32_asset_path()
    if asset.is_file():
        try:
            texts.append(asset.read_text(encoding="utf-8", errors="replace"))
            modules.append("SGP.32 v1.3 (library asset)")
        except OSError:
            pass
    try:
        spec = asn1tools.compile_string("\n".join(texts), codec="der")
    except Exception as error:  # noqa: BLE001 - asn1tools compile errors are library-specific
        if len(texts) > 1:
            # The SGP.32 asset is the optional half; keep SGP.22 alone if it
            # was the addition that failed.
            try:
                spec = asn1tools.compile_string(texts[0], codec="der")
                modules = modules[:1]
                _CACHE.update(
                    loaded=True,
                    spec=spec,
                    error=f"SGP.32 module skipped: {type(error).__name__}: {error}",
                    modules=modules,
                )
                return
            except Exception as inner:  # noqa: BLE001
                error = inner
        _CACHE.update(loaded=True, spec=None, error=f"{type(error).__name__}: {error}", modules=[])
        return
    _CACHE.update(loaded=True, spec=spec, error="", modules=modules)


def rsp_specification() -> Any | None:
    """Return the compiled asn1tools specification, or None when unavailable."""
    with _LOCK:
        if not _CACHE["loaded"]:
            _compile()
        return _CACHE["spec"]


def rsp_specification_status() -> dict[str, Any]:
    """Describe what is compiled, for the decoder's provenance block."""
    spec = rsp_specification()
    with _LOCK:
        return {
            "available": spec is not None,
            "modules": list(_CACHE["modules"]),
            "error": str(_CACHE["error"] or ""),
            "typeCount": len(spec.types) if spec is not None else 0,
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


def has_type(type_name: str) -> bool:
    spec = rsp_specification()
    return spec is not None and _resolve_type(spec, type_name) is not None


def decode_type(type_name: str, data: bytes) -> Any:
    """Decode ``data`` as ``type_name``; raises when the spec or type is missing."""
    spec = rsp_specification()
    if spec is None:
        raise RuntimeError("RSP ASN.1 specification is not compiled")
    compiled = _resolve_type(spec, type_name)
    if compiled is None:
        raise KeyError(type_name)
    return compiled.decode(data)
