"""
SAIP profile-element structured editors.

Each ``PE-*`` family that the ``saip_transcode_tui`` decoded pane is asked
to render gets a dedicated Textual widget here instead of being dumped as
raw JSON. The widgets work directly on the SAIP-decoded JSON dictionaries
that ``saip_json_codec.build_decoded_document_from_sequence`` produces and
emit ``PeEditorChanged`` messages with a *replacement* dict that the TUI
splices back into the editor document at ``["sections", <pe_key>]``.

Public surface
--------------

* ``PE_EDITOR_REGISTRY`` maps a normalized PE base type (``base_pe_type``
  output, e.g. ``"pinCodes"``, ``"akaParameter"``, ``"securityDomain"``,
  ``"usim"``, ``"isim"``…) to the editor class that knows how to render
  it. The TUI looks up by the *base* of the PE key so duplicate PEs
  (``pinCodes_2``, ``genericFileManagement_3`` …) all hit the same editor.
* ``BasePeEditor`` is the abstract parent. It owns the shared ``Changed``
  message, the read-only flag, and the ``set_pe_value`` / ``current_value``
  contract.
* ``ApplicationsView`` and ``FileSystemView`` are top-of-tree readers that
  walk a full ``document["sections"]`` mapping and render application /
  filesystem summaries (the right-most column of the reference UI).

The editors deliberately do not depend on anything in ``saip_transcode_tui``
— the host wires them up by importing ``PE_EDITOR_REGISTRY`` and listening
for ``BasePeEditor.Changed``.
"""

from __future__ import annotations

from ._applications import ApplicationsView
from ._aka import AkaParameterEditor
from ._base import (
    BasePeEditor,
    PeEditorChanged,
    base_pe_type_for_section_key,
    pe_header_member_key,
    rebuild_pe_with_header,
    register_pe_editor,
)
from ._filesystem import FileSystemView
from ._generic import GenericPeEditor
from ._header import PeHeaderForm
from ._naa import (
    NaaPeEditor,
    TelecomPeEditor,
)
from ._pin import (
    PinCodesEditor,
    PukCodesEditor,
)
from ._security_domain import SecurityDomainEditor


PE_EDITOR_REGISTRY: dict[str, type[BasePeEditor]] = {}


def _register_default_editors() -> None:
    register_pe_editor(PE_EDITOR_REGISTRY, "pinCodes", PinCodesEditor)
    register_pe_editor(PE_EDITOR_REGISTRY, "pukCodes", PukCodesEditor)
    register_pe_editor(PE_EDITOR_REGISTRY, "akaParameter", AkaParameterEditor)
    register_pe_editor(PE_EDITOR_REGISTRY, "securityDomain", SecurityDomainEditor)
    register_pe_editor(PE_EDITOR_REGISTRY, "telecom", TelecomPeEditor)
    for naa_key in ("usim", "opt-usim", "isim", "opt-isim", "csim", "opt-csim"):
        register_pe_editor(PE_EDITOR_REGISTRY, naa_key, NaaPeEditor)
    # ``GenericPeEditor`` is used as the fallback for every PE that does
    # not have a custom editor — it surfaces the SAIP header and lists
    # the PE members so the operator at least sees a structured shape
    # instead of the raw JSON dump.


_register_default_editors()


def lookup_pe_editor(pe_section_key: str) -> type[BasePeEditor] | None:
    """Return the editor registered for the *base* of ``pe_section_key``.

    Returns ``None`` when no editor is registered. Callers should fall
    back to the read-only ``GenericPeEditor`` when they want every PE
    selection to surface a structured form, regardless of registration
    coverage.
    """
    base = base_pe_type_for_section_key(pe_section_key)
    return PE_EDITOR_REGISTRY.get(base)


__all__ = [
    "AkaParameterEditor",
    "ApplicationsView",
    "BasePeEditor",
    "FileSystemView",
    "GenericPeEditor",
    "NaaPeEditor",
    "PeEditorChanged",
    "PeHeaderForm",
    "PE_EDITOR_REGISTRY",
    "PinCodesEditor",
    "PukCodesEditor",
    "SecurityDomainEditor",
    "TelecomPeEditor",
    "base_pe_type_for_section_key",
    "lookup_pe_editor",
    "pe_header_member_key",
    "rebuild_pe_with_header",
    "register_pe_editor",
]
