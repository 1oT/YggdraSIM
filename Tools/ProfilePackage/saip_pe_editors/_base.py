"""
Base class and shared helpers for the PE editor widgets.

Every PE editor follows the same contract:

1.  The host TUI builds the editor with ``read_only=True`` and a default
    placeholder PE value at compose time.
2.  When the JSON cursor lands on a PE root (or an outline node that
    points at the PE root), the host calls
    ``editor.bind_pe(pe_key, pe_value)`` with the section key
    (``"pinCodes_2"``) and the live JSON dict for that section.
3.  The widget converts the raw SAIP JSON into a form-friendly model
    inside ``set_pe_value()`` and pushes the form widgets accordingly.
4.  When the operator changes a form field, the widget rebuilds a
    SAIP-shaped JSON dict and emits ``PeEditorChanged`` with the new
    value. The host splices it back into the editor document at
    ``document["sections"][pe_key]``.

Editors must be completely decoupled from the host TUI: no imports from
``saip_transcode_tui`` and no reliance on the host's bridge object.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from textual.containers import Vertical
from textual.message import Message


# ---------------------------------------------------------------------------
# SAIP JSON tag markers
#
# The JSON document uses these synthetic keys so that ASN.1 OCTET STRING
# leaves and tagged-tuple alternatives survive a JSON round-trip. They
# match the constants in ``saip_json_codec.py`` but are duplicated here to
# avoid importing the codec module from every editor file.
# ---------------------------------------------------------------------------
_TAG_BYTES = "__ygg_saip_bytes__"
_LEGACY_TAG_BYTES = "hex"
_TAG_TUPLE = "__ygg_saip_tuple__"
_LEGACY_TAG_TUPLE = "@"

_HEX_REGEX = re.compile(r"^[0-9A-Fa-f]+$")


def hex_from_tagged_bytes(value: Any) -> str | None:
    """Return uppercase hex from a SAIP tagged-bytes object.

    Accepts either ``{"__ygg_saip_bytes__": "AABB..."}`` or the legacy
    ``{"hex": "AABB..."}``. Returns ``None`` for anything else.
    """
    if isinstance(value, dict) is False:
        return None
    for key in (_TAG_BYTES, _LEGACY_TAG_BYTES):
        if key in value:
            raw = value.get(key)
            if isinstance(raw, str):
                compact = raw.strip().upper()
                if len(compact) == 0:
                    return ""
                if _HEX_REGEX.fullmatch(compact) is None:
                    return None
                return compact
    return None


def tagged_bytes(hex_value: str) -> dict[str, str]:
    """Wrap a hex string into a SAIP tagged-bytes dict."""
    compact = re.sub(r"\s+", "", str(hex_value or "")).upper()
    return {_TAG_BYTES: compact}


def tagged_tuple(field_name: str, value: Any) -> dict[str, Any]:
    """Wrap ``(field_name, value)`` into a SAIP tagged-tuple dict."""
    return {_TAG_TUPLE: [str(field_name), value]}


def unwrap_tagged_tuple(value: Any) -> tuple[str, Any] | None:
    """Return ``(field_name, payload)`` for a SAIP tagged-tuple dict."""
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


_BASE_PE_KEY_REGEX = re.compile(r"^(?P<base>[A-Za-z][A-Za-z0-9-]*?)(?:_\d+)?$")


def base_pe_type_for_section_key(pe_section_key: str) -> str:
    """Strip the trailing ``_<n>`` suffix from a PE section key.

    Mirrors ``saip_json_codec.base_pe_type`` without forcing a runtime
    import of the codec module. Returns the input unchanged when the
    pattern does not match.
    """
    text = str(pe_section_key or "").strip()
    if len(text) == 0:
        return ""
    match = _BASE_PE_KEY_REGEX.match(text)
    if match is None:
        return text
    return match.group("base")


def pe_header_member_key(pe_section_key: str) -> str:
    """Return the SAIP header member key for ``pe_section_key``.

    SAIP PE dictionaries always carry the header under
    ``<base>-Header`` (e.g. ``"pin-Header"``, ``"sd-Header"``,
    ``"usim-header"``). The helper trims duplicated PEs and converts
    ``camelCase`` bases to the dashed form used in the JSON.
    """
    base = base_pe_type_for_section_key(pe_section_key)
    if len(base) == 0:
        return "header"
    canonical = _PE_HEADER_KEYS.get(base)
    if canonical is not None:
        return canonical
    # Fall through: convert "akaParameter" -> "aka-header".
    short = re.sub(r"[A-Z]", lambda m: m.group(0).lower(), base)
    short = short.split("-")[0]
    return f"{short}-header"


_PE_HEADER_KEYS: dict[str, str] = {
    "header": "profile-header",
    "mf": "mf-header",
    "cd": "cd-header",
    "telecom": "telecom-header",
    "phonebook": "phonebook-header",
    "gsm-access": "gsm-access-header",
    "usim": "usim-header",
    "opt-usim": "opt-usim-header",
    "isim": "isim-header",
    "opt-isim": "opt-isim-header",
    "csim": "csim-header",
    "opt-csim": "opt-csim-header",
    "eap": "eap-header",
    "df-5gs": "df-5gs-header",
    "df-saip": "df-saip-header",
    "df-snpn": "df-snpn-header",
    "df-5gprose": "df-5gprose-header",
    "rfm": "rfm-header",
    "application": "app-header",
    "akaParameter": "aka-header",
    "akaParameter2": "aka-header",
    "akaParameter3": "aka-header",
    "akaParameter4": "aka-header",
    "akaParameter5": "aka-header",
    "pinCodes": "pin-Header",
    "pukCodes": "puk-Header",
    "securityDomain": "sd-Header",
    "genericFileManagement": "genericFileManagement-header",
    "end": "end-header",
}


def header_value_from_pe(pe_value: Any) -> dict[str, Any] | None:
    """Find the ``*-header`` / ``*-Header`` entry inside a PE dict."""
    if isinstance(pe_value, dict) is False:
        return None
    for key, value in pe_value.items():
        if isinstance(key, str) and key.lower().endswith("header"):
            if isinstance(value, dict):
                return value
    return None


def header_member_key_from_pe(pe_value: Any) -> str | None:
    if isinstance(pe_value, dict) is False:
        return None
    for key in pe_value.keys():
        if isinstance(key, str) and key.lower().endswith("header"):
            return key
    return None


def rebuild_pe_with_header(
    pe_value: dict[str, Any],
    *,
    header_member_key: str,
    header_payload: dict[str, Any],
) -> dict[str, Any]:
    """Return a copy of ``pe_value`` with its header replaced.

    Preserves the original member ordering -- the header is updated in
    place if present, otherwise inserted at the start. Other members
    are deep-copied so the caller can mutate the result without
    affecting the source document.
    """
    new_pe: dict[str, Any] = {}
    found = False
    for key, value in pe_value.items():
        if isinstance(key, str) and key.lower().endswith("header"):
            new_pe[header_member_key] = copy.deepcopy(header_payload)
            found = True
            continue
        new_pe[key] = copy.deepcopy(value)
    if found is False:
        new_pe = {header_member_key: copy.deepcopy(header_payload), **new_pe}
    return new_pe


# ---------------------------------------------------------------------------
# Editor base
# ---------------------------------------------------------------------------


class PeEditorChanged(Message):
    """Emitted whenever a PE editor produces a new replacement value."""

    def __init__(
        self,
        editor: "BasePeEditor",
        *,
        pe_section_key: str,
        new_value: dict[str, Any],
        summary: str,
    ) -> None:
        super().__init__()
        self.editor = editor
        self.pe_section_key = str(pe_section_key or "").strip()
        self.new_value = new_value
        self.summary = str(summary or "").strip()


class BasePeEditor(Vertical):
    """Abstract parent for every PE-specific editor widget.

    Subclasses override ``compose_editor`` to declare their form widgets
    and ``rebuild_form`` to push a fresh PE value into the form.
    """

    DEFAULT_NOTE: str = ""
    PE_TYPE_LABEL: str = "Profile element"

    class Changed(PeEditorChanged):
        """Re-export so callers can ``query`` for ``BasePeEditor.Changed``."""

    def __init__(
        self,
        *,
        pe_section_key: str = "",
        pe_value: dict[str, Any] | None = None,
        read_only: bool = False,
        id: str | None = None,
        classes: str | None = None,
    ) -> None:
        super().__init__(id=id, classes=classes)
        self._pe_section_key = str(pe_section_key or "").strip()
        self._pe_value: dict[str, Any] = (
            copy.deepcopy(pe_value) if isinstance(pe_value, dict) else {}
        )
        self._read_only = bool(read_only)
        self._suppress_emit = False

    # ------------------------------------------------------------------
    # Public API used by the TUI host
    # ------------------------------------------------------------------

    @property
    def pe_section_key(self) -> str:
        return self._pe_section_key

    @property
    def pe_base_type(self) -> str:
        return base_pe_type_for_section_key(self._pe_section_key)

    @property
    def read_only(self) -> bool:
        return self._read_only

    def set_read_only(self, read_only: bool) -> None:
        self._read_only = bool(read_only)
        if self.is_mounted:
            self._enter_suppress_window()
            try:
                self.rebuild_form()
            finally:
                self._schedule_clear_suppress()

    def bind_pe(self, pe_section_key: str, pe_value: Any) -> None:
        """Refresh the form for a new PE selection."""
        self._pe_section_key = str(pe_section_key or "").strip()
        self._pe_value = copy.deepcopy(pe_value) if isinstance(pe_value, dict) else {}
        if self.is_mounted:
            self._enter_suppress_window()
            try:
                self.rebuild_form()
            finally:
                self._schedule_clear_suppress()

    def _enter_suppress_window(self) -> None:
        self._suppress_emit = True

    def _schedule_clear_suppress(self) -> None:
        # Defer clearing until Textual drains the queued ``Input.Changed`` /
        # ``Checkbox.Changed`` events triggered by ``rebuild_form``. Without
        # this, the very first programmatic populate fires a "Changed"
        # cascade that the host treats as a real edit, which then rewrites
        # the JSON editor and drops the cursor selection.
        self.call_after_refresh(self._clear_suppress_emit)

    def _clear_suppress_emit(self) -> None:
        self._suppress_emit = False

    def current_value(self) -> dict[str, Any]:
        """Return the current PE value as a fresh deep-copy."""
        return copy.deepcopy(self._pe_value)

    # ------------------------------------------------------------------
    # Subclass hooks
    # ------------------------------------------------------------------

    def rebuild_form(self) -> None:
        """Push ``self._pe_value`` into the form widgets.

        Subclasses must override.
        """
        raise NotImplementedError

    def emit_change(self, summary: str = "") -> None:
        """Emit ``Changed`` with the current PE value."""
        if self._suppress_emit or self._read_only:
            return
        self.post_message(
            self.Changed(
                self,
                pe_section_key=self._pe_section_key,
                new_value=self.current_value(),
                summary=summary or "",
            )
        )

    # ------------------------------------------------------------------
    # Mount lifecycle
    # ------------------------------------------------------------------

    def on_mount(self) -> None:
        self._enter_suppress_window()
        try:
            self.rebuild_form()
        finally:
            self._schedule_clear_suppress()


def register_pe_editor(
    registry: dict[str, type[BasePeEditor]],
    pe_base_type: str,
    editor_class: type[BasePeEditor],
) -> None:
    """Register ``editor_class`` for ``pe_base_type`` in ``registry``."""
    key = str(pe_base_type or "").strip()
    if len(key) == 0:
        raise ValueError("pe_base_type must be non-empty")
    registry[key] = editor_class


__all__ = [
    "BasePeEditor",
    "PeEditorChanged",
    "base_pe_type_for_section_key",
    "hex_from_tagged_bytes",
    "header_member_key_from_pe",
    "header_value_from_pe",
    "pe_header_member_key",
    "rebuild_pe_with_header",
    "register_pe_editor",
    "tagged_bytes",
    "tagged_tuple",
    "unwrap_tagged_tuple",
]
