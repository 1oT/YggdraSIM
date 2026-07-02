# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Action registry and spec dataclasses.

This module defines three building blocks:

* :class:`ActionField` — one form field on an action (name, kind, required,
  default, help, enum choices, placeholder).
* :class:`ActionSpec`  — everything the UI needs to render a card and
  everything the API needs to dispatch the call.
* :class:`ActionRegistry` — singleton-like container with idempotent
  :meth:`register` so subsystem modules can self-register safely.

The registry is intentionally small. It is not a plugin system; the GUI
only exposes actions that ship with the project. Dispatchers use lazy
imports so nothing from SCP03 / SCP11 / eim_local is loaded until the
action actually fires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Optional


FieldKind = str
# Known values used by the UI renderer:
#   "string"     : plain text input
#   "hex"        : hex input, coerced to uppercase + space-stripped
#   "int"        : numeric input, with optional min/max
#   "bool"       : checkbox
#   "enum"       : <select> backed by ``choices``
#   "text"       : multi-line <textarea>
#   "reader"     : PC/SC reader picker (populated from /api/live/readers)
#   "path"       : filesystem file picker (open-file dialog)
#   "directory"  : filesystem directory picker (open-folder dialog)
#   "save_path"  : filesystem save-as picker (save-file dialog)
#
# All of "path", "directory", "save_path" are stored as plain strings by
# the backend; ``coerce_input`` treats them as ``string``. The distinction
# exists purely so the frontend can wire a native file-picker.


@dataclass(frozen=True)
class ActionField:
    """One input field on an action form."""

    name: str
    label: str
    kind: FieldKind = "string"
    required: bool = False
    default: Optional[Any] = None
    help: str = ""
    placeholder: str = ""
    choices: Optional[list[str]] = None
    secret: bool = False
    multiline: bool = False
    # Minimum / maximum for numeric inputs; ignored otherwise.
    min_value: Optional[int] = None
    max_value: Optional[int] = None

    def to_schema(self) -> dict[str, Any]:
        """Return a JSON-serialisable schema dict describing this action parameter."""
        data: dict[str, Any] = {
            "name": self.name,
            "label": self.label,
            "kind": self.kind,
            "required": self.required,
            "help": self.help,
            "placeholder": self.placeholder,
            "secret": self.secret,
            "multiline": self.multiline,
        }
        if self.default is not None:
            data["default"] = self.default
        if self.choices is not None:
            data["choices"] = list(self.choices)
        if self.min_value is not None:
            data["min_value"] = self.min_value
        if self.max_value is not None:
            data["max_value"] = self.max_value
        return data


OutputKind = str
# Known values, used by the UI renderer:
#   "json"       : pretty-printed JSON card
#   "table"      : header + rows (list of dicts)
#   "tree"       : recursive nested-list tree
#   "fcp"        : FCP + payload view (for SCP03 file reads)
#   "hex"        : raw hex dump
#   "log_stream" : WebSocket streamed {level, message, ...} events
#   "markdown"   : multiline text rendered as <pre>


Dispatcher = Callable[..., Any]
"""Dispatchers return a plain dict for ``run``, or an async generator of
events for ``stream``. The registry does not enforce signature — the
routes adapter validates at dispatch time.
"""


@dataclass
class ActionContext:
    """Handle passed to dispatchers.

    Provides access to the active card session manager, the event-loop
    (for background-thread → asyncio bridging in streaming actions), and
    a structured cancel flag. Dispatchers should not reach into FastAPI
    internals — anything they need lives on this context.
    """

    session_id: Optional[str] = None
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ActionSpec:
    """Declarative description of a single Command Center action."""

    id: str
    subsystem: str
    title: str
    description: str
    inputs: tuple[ActionField, ...] = ()
    output_kind: OutputKind = "json"
    dispatcher: Optional[Dispatcher] = None
    requires_card: bool = False
    # ``requires_auth`` signals that the dispatcher will reject calls
    # made without a live, authenticated GlobalPlatform secure session
    # (typically because the card returns 69 82 / 69 85 — "security
    # status not satisfied" — for any command that crosses the SCP
    # secure-messaging envelope). The GUI uses this flag to gate the
    # Run button behind an authentication prompt so operators don't
    # submit an ``scp03.install_*`` / ``scp03.put_key`` form only to
    # have it bounce on the first APDU. Backend dispatchers still
    # enforce the invariant themselves (``_require_auth_session``) —
    # the flag is a UX hint, never a security boundary.
    requires_auth: bool = False
    streams: bool = False
    tags: tuple[str, ...] = ()

    def to_schema(self) -> dict[str, Any]:
        """Return a JSON-serialisable schema dict describing this action."""
        return {
            "id": self.id,
            "subsystem": self.subsystem,
            "title": self.title,
            "description": self.description,
            "output_kind": self.output_kind,
            "inputs": [field.to_schema() for field in self.inputs],
            "requires_card": self.requires_card,
            "requires_auth": self.requires_auth,
            "streams": self.streams,
            "tags": list(self.tags),
        }


class ActionRegistry:
    """In-memory registry. Eager registration, idempotent by id."""

    def __init__(self) -> None:
        self._specs: dict[str, ActionSpec] = {}

    def register(self, spec: ActionSpec) -> ActionSpec:
        """Register *fn* as the handler for *action_id*."""
        existing = self._specs.get(spec.id)
        if existing is spec:
            return spec
        if existing is not None and _equivalent_action_spec(existing, spec):
            return existing
        if existing is not None:
            # Same id from a different ActionSpec → developer error. We
            # raise rather than silently overwrite so the tests catch it.
            raise ValueError(f"action id already registered: {spec.id!r}")
        self._specs[spec.id] = spec
        return spec

    def get(self, action_id: str) -> ActionSpec:
        if action_id not in self._specs:
            raise KeyError(f"unknown action: {action_id!r}")
        return self._specs[action_id]

    def has(self, action_id: str) -> bool:
        return action_id in self._specs

    def all(self) -> list[ActionSpec]:
        return sorted(self._specs.values(), key=lambda spec: (spec.subsystem, spec.title))

    def by_subsystem(self) -> dict[str, list[ActionSpec]]:
        """Return all registered actions grouped by subsystem name."""
        groups: dict[str, list[ActionSpec]] = {}
        for spec in self.all():
            groups.setdefault(spec.subsystem, []).append(spec)
        for values in groups.values():
            values.sort(key=lambda entry: entry.title)
        return groups

    def clear(self) -> None:
        """Only used in tests."""
        self._specs.clear()


_REGISTRY = ActionRegistry()


def _dispatcher_identity(dispatcher: Optional[Dispatcher]) -> tuple[str, str] | None:
    if dispatcher is None:
        return None
    return (
        str(getattr(dispatcher, "__module__", "")),
        str(getattr(dispatcher, "__qualname__", repr(dispatcher))),
    )


def _equivalent_action_spec(left: ActionSpec, right: ActionSpec) -> bool:
    """Return whether two specs expose the same action contract.

    During GUI startup a failed or interrupted module import can leave a
    few already-created specs in the process-wide registry. If the module is
    imported again, Python creates fresh dataclass and dispatcher objects even
    though the public action contract is unchanged. Treat that as idempotent,
    while still rejecting genuinely conflicting duplicate IDs.
    """
    if left.to_schema() != right.to_schema():
        return False
    if tuple(left.inputs) != tuple(right.inputs):
        return False
    return _dispatcher_identity(left.dispatcher) == _dispatcher_identity(right.dispatcher)


def get_registry() -> ActionRegistry:
    """Return the process-wide registry singleton."""
    return _REGISTRY


def ensure_builtin_actions_loaded() -> ActionRegistry:
    """Import all bundled action modules so they register themselves.

    Called lazily by the HTTP/WS routes on first access. Each submodule
    is wrapped in a try/except so a broken optional backend (e.g. missing
    ``pyscard``) doesn't hide the whole catalogue.
    """
    import importlib
    import logging

    log = logging.getLogger("yggdrasim.gui.actions")
    modules = (
        "yggdrasim_common.gui_server.actions.tools",
        "yggdrasim_common.gui_server.actions.scp03",
        "yggdrasim_common.gui_server.actions.scp11",
        "yggdrasim_common.gui_server.actions.scp11_live",
        "yggdrasim_common.gui_server.actions.scp11_local",
        "yggdrasim_common.gui_server.actions.eim_local",
        "yggdrasim_common.gui_server.actions.hil",
        "yggdrasim_common.gui_server.actions.card_bridge",
        "yggdrasim_common.gui_server.actions.saip",
        "yggdrasim_common.gui_server.actions.simcard",
        "yggdrasim_common.gui_server.actions.suci",
        "yggdrasim_common.gui_server.actions.scp80",
        "yggdrasim_common.gui_server.actions.akma",
        "yggdrasim_common.gui_server.actions.yggdracore",
    )
    for module_name in modules:
        try:
            importlib.import_module(module_name)
        except Exception as load_error:  # noqa: BLE001 — surface every failure mode
            log.warning(
                "action module failed to load: %s (%s: %s)",
                module_name,
                type(load_error).__name__,
                load_error,
            )
    return _REGISTRY


def coerce_input(field_spec: ActionField, raw: Any) -> Any:
    """Normalize a single form value according to its declared ``kind``.

    The HTTP router uses this before calling the dispatcher so every
    dispatcher receives typed kwargs. Missing-but-required fields raise
    ``ValueError`` with a field-scoped message.
    """
    if raw is None or (isinstance(raw, str) and len(raw.strip()) == 0):
        if field_spec.required:
            raise ValueError(f"{field_spec.name}: required field is empty")
        if field_spec.default is not None:
            return field_spec.default
        return None

    kind = field_spec.kind
    if kind in ("string", "text", "reader", "path", "directory", "save_path"):
        return str(raw)
    if kind == "hex":
        cleaned = str(raw).replace(" ", "").replace(":", "").strip().upper()
        if len(cleaned) == 0:
            if field_spec.required:
                raise ValueError(f"{field_spec.name}: hex string is empty")
            return ""
        if len(cleaned) % 2 != 0:
            raise ValueError(f"{field_spec.name}: hex string has odd length")
        for char in cleaned:
            if char not in "0123456789ABCDEF":
                raise ValueError(f"{field_spec.name}: non-hex character {char!r}")
        return cleaned
    if kind == "int":
        try:
            value = int(str(raw), 0)
        except ValueError as err:
            raise ValueError(f"{field_spec.name}: not an integer: {raw!r}") from err
        if field_spec.min_value is not None and value < field_spec.min_value:
            raise ValueError(f"{field_spec.name}: below minimum {field_spec.min_value}")
        if field_spec.max_value is not None and value > field_spec.max_value:
            raise ValueError(f"{field_spec.name}: above maximum {field_spec.max_value}")
        return value
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        lowered = str(raw).strip().lower()
        if lowered in ("true", "1", "yes", "on"):
            return True
        if lowered in ("false", "0", "no", "off", ""):
            return False
        raise ValueError(f"{field_spec.name}: cannot interpret {raw!r} as bool")
    if kind == "enum":
        value = str(raw)
        if field_spec.choices is not None and value not in field_spec.choices:
            allowed = ", ".join(field_spec.choices)
            raise ValueError(f"{field_spec.name}: must be one of [{allowed}]")
        return value
    # Unknown kind → pass through verbatim.
    return raw


def coerce_inputs(spec: ActionSpec, payload: dict[str, Any]) -> dict[str, Any]:
    """Coerce an entire payload against ``spec.inputs``.

    Unknown keys are ignored silently; missing required keys raise.
    """
    coerced: dict[str, Any] = {}
    for field_spec in spec.inputs:
        raw = payload.get(field_spec.name)
        coerced[field_spec.name] = coerce_input(field_spec, raw)
    return coerced
