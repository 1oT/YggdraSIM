# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Interactive editor for the YGGDRASIM_* environment flag registry.

Launched from the top-level launcher via the ``[E]`` menu entry. The
editor groups flags by category, displays current values plus source
(unset / process env / persisted), and lets operators set, clear, or
reset individual entries. Persistent changes are written by
:mod:`yggdrasim_common.env_flags` to either the runtime-root state
file or the per-user home file depending on each flag's persistence
scope.

The launcher injects its :class:`Colors` palette and the
``clear_screen`` / ``pause`` helpers when it calls :func:`run`, so this
module does not import ``main.main`` at all. Doing so would be
problematic in practice because ``main/main.py`` is executed as
``__main__`` and ``main/`` is not a proper Python package at runtime.
Keeping the theme dependencies explicit also leaves this module
trivially unit-testable with a stub colour palette.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Optional

from yggdrasim_common import env_flags


# ---------------------------------------------------------------------------
# Theme / helper injection
# ---------------------------------------------------------------------------

_colors: Any = None
_clear_screen: Optional[Callable[[], None]] = None
_pause: Optional[Callable[[], None]] = None


def _attach_helpers(
    colors: Any,
    clear_screen_callable: Callable[[], None],
    pause_callable: Callable[[], None],
) -> None:
    """Store references to the launcher's theme + blocking helpers.

    The launcher calls this once via :func:`run`. Split out so tests can
    drive the editor with a stub palette / capture helpers without
    depending on ``main.main`` at import time.
    """
    global _colors, _clear_screen, _pause
    _colors = colors
    _clear_screen = clear_screen_callable
    _pause = pause_callable


def _color(name: str) -> str:
    if _colors is None:
        return ""
    return getattr(_colors, name, "")


def _cls() -> None:
    if _clear_screen is None:
        return
    _clear_screen()


def _wait() -> None:
    if _pause is None:
        return
    _pause()


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------

def _format_source_marker(source_text: str) -> str:
    text = str(source_text or "").strip()
    lowered = text.lower()
    if lowered.startswith("unset"):
        return f"{_color('WHITE')}{text}{_color('ENDC')}"
    if "persisted" in lowered:
        return f"{_color('GREEN')}{text}{_color('ENDC')}"
    return f"{_color('CYAN')}{text}{_color('ENDC')}"


def _format_value_preview(flag: env_flags.EnvFlag, value_text: str, *, max_width: int = 44) -> str:
    value = str(value_text or "")
    if len(value) == 0:
        return f"{_color('WHITE')}<unset>{_color('ENDC')}"
    if flag.kind == env_flags.KIND_BOOL_TOGGLE:
        if value.strip().lower() in ("1", "true", "yes", "on"):
            return f"{_color('GREEN')}on ({value}){_color('ENDC')}"
        if value.strip().lower() in ("0", "false", "no", "off"):
            return f"{_color('BROWN')}off ({value}){_color('ENDC')}"
    if len(value) <= max_width:
        return value
    return value[: max_width - 1] + "…"


def _render_header(title: str) -> None:
    _cls()
    print(f"{_color('HEADER')}=== {title} ==={_color('ENDC')}\n")


def _render_category_index() -> list[str]:
    ordered: list[str] = list(env_flags.CATEGORY_ORDER)
    _render_header("Environment Flags")
    print("Persistent overrides live next to the runtime state; home-scoped flags")
    print("(currently only YGGDRASIM_RUNTIME_ROOT) are saved in ~/.yggdrasim.")
    print("Session-only flags (YGGDRASIM_FLAVOR) are applied for the current run")
    print("and not written to disk.\n")
    for index, category in enumerate(ordered, start=1):
        flag_count = len(env_flags.flags_by_category(category))
        set_count = 0
        for flag in env_flags.flags_by_category(category):
            if len(env_flags.get_flag_value(flag)) > 0:
                set_count += 1
        marker = f"{set_count}/{flag_count} set"
        print(f"  {_color('CYAN')}[{index}]{_color('ENDC')} {category} ({marker})")
    print("")
    print(f"  {_color('WHITE')}[X]{_color('ENDC')} Dump all active flags as shell export lines")
    print(f"  {_color('WHITE')}[R]{_color('ENDC')} Reset every persisted override")
    print(f"  {_color('WHITE')}[Q]{_color('ENDC')} Return to main menu")
    return ordered


def _render_applies_marker(flag: env_flags.EnvFlag) -> str:
    if flag.applies == env_flags.APPLIES_STARTUP:
        return f"{_color('WARNING')}relaunch{_color('ENDC')}"
    return f"{_color('CYAN')}runtime{_color('ENDC')}"


def _render_persistence_marker(flag: env_flags.EnvFlag) -> str:
    if flag.persist_scope == env_flags.PERSIST_SESSION:
        return f"{_color('BROWN')}session-only{_color('ENDC')}"
    if flag.persist_scope == env_flags.PERSIST_HOME:
        return f"{_color('HEADER')}persist: home{_color('ENDC')}"
    return f"{_color('GREEN')}persist: runtime{_color('ENDC')}"


def _render_category_detail(category: str) -> list[env_flags.EnvFlag]:
    flags = env_flags.flags_by_category(category)
    _render_header(f"Environment Flags — {category}")
    if len(flags) == 0:
        print(f"{_color('WARNING')}(no flags registered in this category){_color('ENDC')}")
        return list(flags)
    for index, flag in enumerate(flags, start=1):
        current_value = env_flags.get_flag_value(flag)
        source_text = env_flags.get_flag_source(flag)
        value_preview = _format_value_preview(flag, current_value)
        sensitive_marker = ""
        if flag.sensitive:
            sensitive_marker = f" {_color('FAIL')}[sensitive]{_color('ENDC')}"
        print(f"  {_color('CYAN')}[{index}]{_color('ENDC')} {flag.name}{sensitive_marker}")
        print(f"      {flag.summary}")
        print(f"      Value  : {value_preview}")
        print(f"      Source : {_format_source_marker(source_text)}")
        print(f"      Scope  : {_render_persistence_marker(flag)}   "
              f"Applies: {_render_applies_marker(flag)}")
        print("")
    print(f"  {_color('WHITE')}[Q]{_color('ENDC')} Back to categories")
    return list(flags)


# ---------------------------------------------------------------------------
# Flag edit workflow
# ---------------------------------------------------------------------------

def _confirm_sensitive(flag: env_flags.EnvFlag) -> bool:
    if flag.sensitive is False:
        return True
    print(f"\n{_color('FAIL')}[!] {flag.name} is security-sensitive.{_color('ENDC')}")
    if len(flag.notes) > 0:
        print(f"    {flag.notes}")
    confirm = input("Type Y to continue, anything else to cancel: ").strip().upper()
    return confirm in ("Y", "YES")


def _validate_for_kind(flag: env_flags.EnvFlag, raw_value: str) -> tuple[bool, str, str]:
    value = str(raw_value or "").strip()
    if len(value) == 0:
        return True, "", ""
    if flag.kind == env_flags.KIND_CHOICE:
        if value not in flag.choices:
            return False, value, (
                f"must be one of: {', '.join(flag.choices)}"
            )
        return True, value, ""
    if flag.kind == env_flags.KIND_INT:
        try:
            int(value, 10)
        except ValueError:
            return False, value, "must be an integer"
        return True, value, ""
    if flag.kind == env_flags.KIND_FLOAT:
        try:
            float(value)
        except ValueError:
            return False, value, "must be a number"
        return True, value, ""
    if flag.kind == env_flags.KIND_PATH:
        expanded = os.path.expanduser(value)
        return True, expanded, ""
    return True, value, ""


def _prompt_new_value(flag: env_flags.EnvFlag) -> tuple[str, bool]:
    """Prompt the user for a new value.

    Returns ``(value, is_cancel)`` where ``is_cancel=True`` means the
    user aborted the edit. An empty ``value`` + ``is_cancel=False``
    means "clear the flag".
    """
    if flag.kind == env_flags.KIND_BOOL_TOGGLE:
        current = env_flags.get_flag_value(flag).strip().lower()
        if current in ("1", "true", "yes", "on"):
            state_label = "on"
        elif current in ("0", "false", "no", "off"):
            state_label = "off"
        else:
            state_label = "unset"
        print(
            f"\nCurrent state: {state_label}. "
            "Enter [on], [off], [clear], or [cancel]: "
        )
        raw = input("> ").strip().lower()
        if raw in ("cancel", "c", "q", "quit"):
            return "", True
        if raw in ("clear", "unset", ""):
            return "", False
        if raw in ("on", "1", "true", "yes"):
            return flag.bool_on_value, False
        if raw in ("off", "0", "false", "no"):
            return flag.bool_off_value, False
        print(f"{_color('FAIL')}[!] Not understood; leaving the flag unchanged.{_color('ENDC')}")
        return "", True
    if flag.kind == env_flags.KIND_CHOICE:
        print(f"\nChoices: {', '.join(flag.choices)}")
        raw = input(
            f"Enter new value [blank=clear, 'cancel' to abort] (current "
            f"{env_flags.get_flag_value(flag) or '<unset>'}): "
        ).strip()
        if raw.lower() in ("cancel", "c", "quit", "q"):
            return "", True
        return raw, False
    current_value = env_flags.get_flag_value(flag)
    hint = flag.default_hint or "<built-in default>"
    raw = input(
        f"\nEnter new value [blank=clear, 'cancel' to abort] "
        f"(current: {current_value or '<unset>'}, default: {hint}): "
    ).strip()
    if raw.lower() in ("cancel", "c", "quit", "q"):
        return "", True
    return raw, False


def _edit_flag(flag: env_flags.EnvFlag) -> None:
    while True:
        _render_header(f"{flag.name}")
        print(f"Category   : {flag.category}")
        print(f"Kind       : {flag.kind}")
        print(f"Applies    : {_render_applies_marker(flag)}")
        print(f"Persistence: {_render_persistence_marker(flag)}")
        print(f"Sensitive  : {'yes' if flag.sensitive else 'no'}")
        current_value = env_flags.get_flag_value(flag)
        print(f"Current    : {_format_value_preview(flag, current_value, max_width=200)}")
        print(f"Source     : {_format_source_marker(env_flags.get_flag_source(flag))}")
        print(f"Default    : {flag.default_hint or '(consumer built-in default)'}")
        if flag.kind == env_flags.KIND_CHOICE:
            print(f"Choices    : {', '.join(flag.choices)}")
        print("")
        print(flag.description)
        if len(flag.notes) > 0:
            print("")
            print(f"{_color('WARNING')}Notes:{_color('ENDC')} {flag.notes}")
        print("")
        print(f"  {_color('CYAN')}[S]{_color('ENDC')} Set / change value")
        print(f"  {_color('CYAN')}[C]{_color('ENDC')} Clear value")
        if flag.persist_scope != env_flags.PERSIST_SESSION:
            print(f"  {_color('CYAN')}[T]{_color('ENDC')} Set for this session only (do not persist)")
        print(f"  {_color('WHITE')}[Q]{_color('ENDC')} Back")
        choice = input("\nSelect action: ").strip().upper()
        if choice in ("Q", ""):
            return
        if choice == "S":
            if _confirm_sensitive(flag) is False:
                print(f"\n{_color('WARNING')}[*] Change cancelled.{_color('ENDC')}")
                _wait()
                continue
            new_raw, cancelled = _prompt_new_value(flag)
            if cancelled:
                continue
            is_valid, normalized, error_text = _validate_for_kind(flag, new_raw)
            if is_valid is False:
                print(f"\n{_color('FAIL')}[!] Invalid value: {error_text}.{_color('ENDC')}")
                _wait()
                continue
            env_flags.set_flag_value(flag, normalized, persist=True)
            if len(normalized) == 0:
                print(f"\n{_color('GREEN')}[+] {flag.name} cleared.{_color('ENDC')}")
            else:
                print(f"\n{_color('GREEN')}[+] {flag.name} set to {normalized}.{_color('ENDC')}")
            if flag.applies == env_flags.APPLIES_STARTUP:
                print(f"    {_color('WARNING')}Note:{_color('ENDC')} relaunch YggdraSIM for full effect.")
            _wait()
            continue
        if choice == "C":
            env_flags.clear_flag_value(flag, persist=True)
            print(f"\n{_color('GREEN')}[+] {flag.name} cleared.{_color('ENDC')}")
            _wait()
            continue
        if choice == "T" and flag.persist_scope != env_flags.PERSIST_SESSION:
            if _confirm_sensitive(flag) is False:
                print(f"\n{_color('WARNING')}[*] Change cancelled.{_color('ENDC')}")
                _wait()
                continue
            new_raw, cancelled = _prompt_new_value(flag)
            if cancelled:
                continue
            is_valid, normalized, error_text = _validate_for_kind(flag, new_raw)
            if is_valid is False:
                print(f"\n{_color('FAIL')}[!] Invalid value: {error_text}.{_color('ENDC')}")
                _wait()
                continue
            env_flags.set_flag_value(flag, normalized, persist=False)
            if len(normalized) == 0:
                print(f"\n{_color('GREEN')}[+] {flag.name} cleared for this session.{_color('ENDC')}")
            else:
                print(f"\n{_color('GREEN')}[+] {flag.name} set to {normalized} for this session only.{_color('ENDC')}")
            _wait()
            continue
        print(f"\n{_color('FAIL')}[!] Invalid selection.{_color('ENDC')}")
        _wait()


# ---------------------------------------------------------------------------
# Category / export / reset handlers
# ---------------------------------------------------------------------------

def _browse_category(category: str) -> None:
    while True:
        flags = _render_category_detail(category)
        if len(flags) == 0:
            _wait()
            return
        choice = input("\nSelect flag number, or Q to go back: ").strip().upper()
        if choice in ("Q", ""):
            return
        try:
            selected_index = int(choice, 10)
        except ValueError:
            print(f"\n{_color('FAIL')}[!] Not a number.{_color('ENDC')}")
            _wait()
            continue
        if selected_index < 1 or selected_index > len(flags):
            print(f"\n{_color('FAIL')}[!] Out of range.{_color('ENDC')}")
            _wait()
            continue
        _edit_flag(flags[selected_index - 1])


def _dump_export_lines() -> None:
    _render_header("Active Flags — Shell Export Lines")
    lines = env_flags.dump_export_lines()
    if len(lines) == 0:
        print(f"{_color('WHITE')}(no YGGDRASIM_* variables currently set){_color('ENDC')}")
    else:
        print(
            "Paste into your shell profile, a systemd unit's "
            "Environment= lines, or a .env file:\n"
        )
        for line in lines:
            print(line)
    _wait()


def _reset_all() -> None:
    _render_header("Reset Persisted Overrides")
    print(f"{_color('WARNING')}[!] This clears every persisted YGGDRASIM_* override.{_color('ENDC')}")
    print("    Session-only flags (e.g. YGGDRASIM_FLAVOR) are not touched.")
    print("    Process env values set via --flags or before launch are preserved")
    print("    unless you also clear them from the current session.\n")
    confirm = input("Type Y to wipe persistent overrides, anything else to cancel: ").strip().upper()
    if confirm not in ("Y", "YES"):
        print(f"\n{_color('WARNING')}[*] Reset cancelled.{_color('ENDC')}")
        _wait()
        return
    clear_session_choice = input(
        "Also pop matching values from the current process env? [y/N]: "
    ).strip().lower()
    clear_session = clear_session_choice in ("y", "yes")
    removed = env_flags.reset_all_persisted(clear_session=clear_session)
    print(f"\n{_color('GREEN')}[+] Cleared {removed} persisted override(s).{_color('ENDC')}")
    if clear_session:
        print("    Current-session values were also cleared for persistable flags.")
    _wait()


# ---------------------------------------------------------------------------
# Public entry point used by main.main
# ---------------------------------------------------------------------------

def run(
    colors: Any,
    clear_screen_callable: Callable[[], None],
    pause_callable: Callable[[], None],
) -> None:
    """Open the environment-flag editor.

    Parameters
    ----------
    colors:
        Object exposing ``HEADER`` / ``CYAN`` / ``GREEN`` / ``WARNING`` /
        ``FAIL`` / ``BROWN`` / ``WHITE`` / ``BOLD`` / ``ENDC`` ANSI
        escape sequences. Pass :class:`main.main.Colors` from the
        launcher; pass any stub with the same attributes from tests.
    clear_screen_callable:
        Zero-arg function that clears the terminal screen.
    pause_callable:
        Zero-arg function that blocks for a single Enter press. Used
        between sub-screens so users can read the last line of output
        before the next clear.
    """
    _attach_helpers(colors, clear_screen_callable, pause_callable)
    while True:
        categories = _render_category_index()
        choice = input("\nSelect category: ").strip().upper()
        if choice in ("Q", ""):
            return
        if choice == "X":
            _dump_export_lines()
            continue
        if choice == "R":
            _reset_all()
            continue
        try:
            selected_index = int(choice, 10)
        except ValueError:
            print(f"\n{_color('FAIL')}[!] Invalid selection.{_color('ENDC')}")
            _wait()
            continue
        if selected_index < 1 or selected_index > len(categories):
            print(f"\n{_color('FAIL')}[!] Out of range.{_color('ENDC')}")
            _wait()
            continue
        _browse_category(categories[selected_index - 1])
