# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the SCP03 authentication-gate system.

Background
----------
Mutation-class SCP03 actions (PUT KEY / INSTALL [for …] / SET STATUS /
DELETE / STORE DATA / UPDATE BINARY / UPDATE RECORD / fs_create_file /
fs_delete_file / fs_resize / fs_lifecycle / fs_search_record /
fs_suspend_uicc / export_keybag) cross the SCP secure-messaging envelope
and the card will short-circuit them with ``69 82`` (security status not
satisfied) unless the active session has first run an ``AUTHENTICATE``
round. Operator request verbatim:

    "There are also a number of commands that require authentication to
    run, such as install commands, when you press these you should first
    be prompted to provide authentication details that shall be passed
    to the card before the install commands etc"

The pass adds three layers:

* ``ActionSpec.requires_auth`` — opt-in flag surfaced through
  ``/api/actions``. Backend dispatchers enforce it independently via
  ``_require_auth_session``; the spec flag is a UX hint so the GUI can
  intercept before the inline form opens.
* Backend — ``scp03.auth_scp03`` / ``scp03.auth_scp02`` accept optional
  ``kvn`` / ``enc_key`` / ``mac_key`` / ``dek_key`` overrides and a
  sibling ``scp03.auth_status`` spec reports session auth state without
  touching the card.
* Frontend — per-tab ``authStatus`` cache, ``scp03EnsureAuthed`` gate,
  ``scp03GateOpen`` click wrapper, auth-prompt popout, ``69 82``
  auto-invalidation in the shared run helper.

These tests pin each layer against static contract checks so a refactor
can't silently regress any piece.
"""

from __future__ import annotations

from pathlib import Path

from yggdrasim_common.gui_server.actions import scp03 as scp03_actions
from yggdrasim_common.gui_server.actions.registry import get_registry


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Backend: spec flags + registry wiring.
# ----------------------------------------------------------------------


_EXPECTED_AUTH_GATED = frozenset({
    "scp03.set_status",
    "scp03.lock",
    "scp03.unlock",
    "scp03.delete",
    "scp03.store_data",
    "scp03.update_binary",
    "scp03.update_record",
    "scp03.export_keybag",
    "scp03.put_key",
    "scp03.install_cap",
    "scp03.install_app",
    "scp03.install_make_selectable",
    "scp03.install_extradition",
    "scp03.install_personalization",
    "scp03.install_registry_update",
    "scp03.fs_create_file",
    "scp03.fs_delete_file",
    "scp03.fs_resize",
    "scp03.fs_lifecycle",
    "scp03.fs_search_record",
    "scp03.fs_suspend_uicc",
})


def test_requires_auth_flag_matches_expected_set() -> None:
    """Every destructive / mutation dispatcher opts in; nothing else does.

    Guards against drift: if an operator adds a new ``_dispatch_install_…``
    variant without setting ``requires_auth=True`` the card will reject
    the first APDU with ``69 82`` and the GUI won't prompt — classic
    "why did my install silently fail" ticket.
    """
    reg = get_registry()
    observed = {
        spec.id for spec in reg.all()
        if spec.subsystem.upper() == "SCP03" and spec.requires_auth
    }
    assert observed == _EXPECTED_AUTH_GATED, (
        "unexpected requires_auth drift on SCP03:\n"
        f"  added: {sorted(observed - _EXPECTED_AUTH_GATED)}\n"
        f"  removed: {sorted(_EXPECTED_AUTH_GATED - observed)}"
    )


def test_auth_specs_themselves_are_not_gated() -> None:
    """The AUTH actions bootstrap the session — gating them would deadlock."""
    for name in ("AUTH_SCP03_SPEC", "AUTH_SCP02_SPEC", "AUTH_STATUS_SPEC"):
        spec = getattr(scp03_actions, name)
        assert spec.requires_auth is False, name


def test_auth_status_spec_registered_and_idempotent() -> None:
    """``scp03.auth_status`` is the observational probe used for tab rehydrate.

    Must be card-free (``requires_card=False``) so the poll doesn't
    compete with a live scan for the PC/SC handle, and must be callable
    with nothing more than a ``session_id`` input.
    """
    spec = get_registry().get("scp03.auth_status")
    assert spec is not None, "scp03.auth_status missing from registry"
    assert spec.requires_card is False
    assert spec.requires_auth is False
    input_names = [f.name for f in spec.inputs]
    assert "session_id" in input_names


def test_auth_specs_expose_key_override_fields() -> None:
    """SCP03/SCP02 AUTH forms carry kvn + enc/mac/dek override inputs.

    The override fields are marked ``secret=True`` so the popout masks
    them like a password input; if that flips to ``False`` operators
    risk shoulder-surfing a live keyset.
    """
    for name in ("AUTH_SCP03_SPEC", "AUTH_SCP02_SPEC"):
        spec = getattr(scp03_actions, name)
        fields = {f.name: f for f in spec.inputs}
        for key_field in ("kvn", "enc_key", "mac_key", "dek_key"):
            assert key_field in fields, f"{name} missing {key_field}"
        for secret_field in ("enc_key", "mac_key", "dek_key"):
            assert fields[secret_field].secret is True, (
                f"{name}.{secret_field} must be marked secret=True"
            )


def test_schema_exposes_requires_auth_flag() -> None:
    """The public ``/api/actions`` schema surfaces ``requires_auth``.

    The frontend gate relies on this — a missing key would mean
    ``scp03ActionRequiresAuth`` always returns false and the popout
    never opens.
    """
    spec = get_registry().get("scp03.install_cap")
    assert spec is not None
    schema = spec.to_schema()
    assert schema.get("requires_auth") is True


# ----------------------------------------------------------------------
# Frontend: app.js static contract.
# ----------------------------------------------------------------------


def test_app_js_defines_auth_gate_helpers() -> None:
    """The auth-gate surface ships as a cohesive helper cluster.

    We intentionally check by literal function-definition prefix so a
    rename (e.g. to ``scp03CheckAuthState``) trips the test and the
    author has to update ``scp03RunActionWithOutput`` and all ribbon
    wraps in the same pass.
    """
    js = _read("app.js")
    for fragment in (
        "function scp03LookupActionSpec(",
        "function scp03ActionRequiresAuth(",
        "function scp03HasLiveAuth(",
        "function scp03UpdateTabAuthFromResponse(",
        "function scp03ClearTabAuth(",
        "async function scp03RefreshTabAuthStatus(",
        "function scp03BuildAuthPromptPopout(",
        "function scp03EnsureAuthed(",
        "function scp03GateOpen(",
        "function scp03LookupTabForSessionId(",
    ):
        assert fragment in js, f"missing auth helper: {fragment}"


def test_tab_state_seeds_authstatus() -> None:
    """New tabs initialise ``authStatus`` so the gate check never trips on null."""
    js = _read("app.js")
    assert "authStatus:" in js
    assert "authenticated: false" in js
    assert "overridesApplied:" in js


def test_run_action_wrapper_clears_auth_on_6982() -> None:
    """Every dispatched action flushes the cache on ``69 82``.

    Without this clear, a card cold-reset (or reader-bar probe, or
    SGP.32 bulk traffic that trips SM) between the gate check and the
    actual APDU would leave ``authStatus.authenticated`` stuck at
    ``true`` — every subsequent click would loop on the same 6982.
    """
    js = _read("app.js")
    assert "scp03RunActionWithOutput" in js
    assert "69 82" in js or "69\\s?82" in js or "6982" in js
    assert "scp03ClearTabAuth(tab)" in js


def test_gate_open_wires_into_ribbon_buttons() -> None:
    """Ribbon handlers for auth-gated actions route through ``scp03GateOpen``.

    If a wrap is dropped the button bypasses the popout and drops
    straight to the legacy inline form — the card will then bounce the
    first APDU and the operator sees a confusing mid-flow error.
    """
    js = _read("app.js")
    ribbon_gated_ids = (
        "scp03.set_status",
        "scp03.lock",
        "scp03.unlock",
        "scp03.delete",
        "scp03.store_data",
        "scp03.update_binary",
        "scp03.update_record",
        "scp03.put_key",
        "scp03.install_cap",
        "scp03.install_app",
        "scp03.install_make_selectable",
        "scp03.install_extradition",
        "scp03.install_personalization",
        "scp03.install_registry_update",
        "scp03.export_keybag",
    )
    for action_id in ribbon_gated_ids:
        assert f'scp03GateOpen(tab, "{action_id}"' in js, (
            f"missing scp03GateOpen wrap for {action_id}"
        )


def test_gate_open_wires_into_fs_action_bar() -> None:
    """The contextual FS-admin strip also routes through the gate."""
    js = _read("app.js")
    fs_gated_ids = (
        "scp03.fs_create_file",
        "scp03.fs_delete_file",
        "scp03.fs_resize",
        "scp03.fs_lifecycle",
        "scp03.fs_search_record",
        "scp03.fs_suspend_uicc",
    )
    for action_id in fs_gated_ids:
        assert f'scp03GateOpen(tab, "{action_id}"' in js, (
            f"missing scp03GateOpen wrap for {action_id}"
        )


def test_session_header_exposes_auth_chip() -> None:
    """The active-session header advertises the auth state.

    Gives the operator a glanceable "yes I'm authed / no I'm not"
    signal without opening the ribbon, which matters because the
    popout-based workflow keeps the ribbon mostly offscreen.
    """
    js = _read("app.js")
    assert "auth: not authenticated" in js
    assert "cc-chip-ok" in js
    assert "cc-chip-warn" in js


def test_rehydrate_clears_auth_state() -> None:
    """Tabs loaded from ``localStorage`` start unauthenticated.

    The backend session is torn down on page reload (no persistence),
    so any cached ``authStatus.authenticated=true`` would be a lie —
    the next action would 6982 without prompting. We reset explicitly
    during hydration instead of hoping the default struct stays
    consistent with ``scp03CreateEmptyTab``.
    """
    js = _read("app.js")
    assert "scp03HydrateTabFromPersisted" in js
    assert "scp03ClearTabAuth(tab);" in js


def test_logout_clears_auth_state() -> None:
    """Logout flushes ``authStatus`` so the next click re-prompts."""
    js = _read("app.js")
    assert "scp03.logout" in js
    assert "scp03ClearTabAuth(tab);" in js


def test_auth_chip_refresh_is_surgical_not_full_repaint() -> None:
    """The auth flow must NOT rebuild the entire tab body.

    Earlier iterations called ``renderScp03Tabs`` after a successful
    authenticate to refresh the "authenticated" chip. That rebuild
    orphaned whatever tree / breadcrumb / popout click closure was
    mid-flight at the time, and subsequent ``replaceChild`` calls on
    the stale refs died with ``HierarchyRequestError: The new child
    element contains the parent``. The in-place chip updater
    (``scp03RefreshAuthChip``) mutates just the chip node and leaves
    the rest of the session panel untouched, sidestepping the orphan
    problem entirely. Pinning the contract here so a future "simpler"
    rewrite doesn't slip back to the nuclear rerender.
    """
    js = _read("app.js")
    assert "function scp03RefreshAuthChip(" in js
    # scp03RerenderActiveTabBody must delegate to the chip updater,
    # not to the whole-tab rerender.
    assert "scp03RefreshAuthChip()" in js


def test_replace_child_sites_guarded_against_hierarchy_error() -> None:
    """Surviving ``replaceChild`` calls wrap in try/catch.

    Any remaining in-place DOM swap (ribbon repaint, breadcrumb
    refresh) can still race with a stale ref — guard with a
    try/catch that falls back to the safe full repaint so the UI
    never dead-locks in an orphaned state.
    """
    js = _read("app.js")
    # The two named fallback patterns — both route to renderScp03Tabs
    # on a catch so the tab body is guaranteed consistent even if the
    # targeted swap fails.
    assert "oldRibbon.parentNode.replaceChild(fresh, oldRibbon)" in js
    assert "oldCrumb.parentNode.replaceChild(fresh, oldCrumb)" in js
    # Both sites must live inside a try/catch that rerenders the tab.
    fragments_with_guard = js.count("renderScp03Tabs(tabBar, tabBody);\n    }")
    # Expect at least two guarded catches — one per replaceChild site.
    assert fragments_with_guard >= 2, (
        "expected at least two renderScp03Tabs fallbacks after replaceChild guards; "
        f"found {fragments_with_guard}"
    )
