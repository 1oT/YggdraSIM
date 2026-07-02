# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Regression tests for the left-nav taxonomy tree + SCP03 scope split.

Background
----------
The first-pass Command Center nav rendered every backend subsystem as
a flat alphabetised list. SCP03 alone carries 76 actions spanning the
ETSI file system, GlobalPlatform registry, install / key management,
eUICC telemetry and admin — one click landed the operator on a single
workbench with the whole kitchen sink exposed. Operator request
verbatim:

    "we shall split the current structure a bit. On the left side
     panel we should have this nested structure:
       Card Administration
         Filesystem (SCP03 ETSI Filesystem/NAA)
         Applications (SCP03 Global Platform)
         Over-the-Air (SCP80)
       eSIM (SCP11) [Management / Local SMDP+ / Local eIM]
       Tools [SAIP Tool / Offline Tools]
       Environment [Configuration]
     Here we separate the Filesystem from the Application section
     within the SCP03 module to offload the cognitive information
     density a bit"

Pass landed:

* Frontend-only ``CC_NAV_TREE`` — a GUI taxonomy decoupled from the
  backend subsystem list. Each leaf targets either a backend
  ``subsystem`` (optionally with a ``scope``) or an inspect view.
  Groups remember their open/closed state via localStorage so the
  tree doesn't reset across reloads.
* ``openCommandSubsystem(subsystem, { scope, leafId, stub })`` so
  SCP03 can be entered twice with different scopes from two different
  nav leaves sharing the same session tabs.
* ``renderScp03Workbench(container, actions, { scope })`` persists
  scope on ``commandState.scp03Workbench.scope``; ``scp03BuildRibbon``
  filters ribbon tabs by scope; ``scp03BuildActiveSessionPanel`` hides
  the FS tree + FCP preview in Applications mode to match the label.

All tests are static-bundle contracts against ``app.js`` / ``app.css``
— the nav is pure frontend and live browser behaviour is covered
separately by the Playwright smoke lane. Pinning the contract here
keeps the taxonomy from regressing silently during future refactors.
"""

from __future__ import annotations

import re
from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# CC_NAV_TREE shape
# ----------------------------------------------------------------------


def test_cc_nav_tree_defined_with_required_groups() -> None:
    """All four primary operator-facing groups must be registered."""
    js = _read("app.js")
    assert "var CC_NAV_TREE = [" in js
    # Each group header is declared with a label — pin the four the
    # operator asked for plus the Advanced escape hatch so the backend
    # subsystems we don't prominently surface stay reachable.
    for label in (
        '"Card Administration"',
        '"eSIM (SCP11)"',
        '"Tools"',
        '"Environment"',
        '"Advanced"',
    ):
        assert "label: " + label in js, "missing nav group label " + label


def test_scp03_is_split_into_filesystem_and_applications() -> None:
    """SCP03 appears under two leaves with distinct scopes."""
    js = _read("app.js")
    # Filesystem leaf — scope: "filesystem".
    assert 'id: "leaf-scp03-filesystem"' in js
    assert re.search(
        r'leaf-scp03-filesystem[\s\S]{0,400}?scope: "filesystem"',
        js,
    ), "Filesystem leaf must carry scope=filesystem"
    # Applications leaf — scope: "applications".
    assert 'id: "leaf-scp03-applications"' in js
    assert re.search(
        r'leaf-scp03-applications[\s\S]{0,400}?scope: "applications"',
        js,
    ), "Applications leaf must carry scope=applications"


def test_scp11_family_grouped_under_esim() -> None:
    """The SCP11-adjacent surfaces sit under eSIM (SCP11)."""
    js = _read("app.js")
    for expected_label in ('"Management"', '"Local SMDP+"', '"Local eIM"'):
        assert "label: " + expected_label in js, "missing eSIM leaf label " + expected_label
    assert re.search(r'leaf-esim-live[\s\S]{0,400}?subsystem: "eSIM Management"', js)
    assert re.search(r'leaf-esim-local-smdp[\s\S]{0,400}?subsystem: "SCP11 Local"', js)
    assert re.search(r'leaf-esim-local-eim[\s\S]{0,400}?subsystem: "Local eIM"', js)
    assert "leaf-esim-test" not in js
    assert 'subsystem: "eSIM Test"' not in js


def test_tools_group_hosts_saip_and_offline_tools() -> None:
    """SAIP Tool stays separate while non-card tools share one module."""
    js = _read("app.js")
    assert re.search(r'leaf-tool-saip[\s\S]{0,400}?subsystem: "SAIP"', js)
    assert re.search(r'leaf-tool-offline[\s\S]{0,400}?subsystem: "Offline Tools"', js)
    assert "leaf-tool-suci" not in js
    assert 'subsystem: "SUCI Tool"' not in js


def test_environment_group_routes_to_configuration_inspect_view() -> None:
    """Environment > Configuration lights up the env_flags inspect view."""
    js = _read("app.js")
    assert re.search(
        r'leaf-env-config[\s\S]{0,400}?inspectView: "env_flags"',
        js,
    ), "Configuration leaf must route to the env_flags view"


def test_advanced_group_preserves_hil_simcard_and_registry() -> None:
    """Advanced keeps the historically-flat subsystems reachable."""
    js = _read("app.js")
    # HIL + SIMCARD backend subsystems must not become orphaned.
    assert re.search(r'leaf-adv-hil[\s\S]{0,400}?subsystem: "HIL"', js)
    assert re.search(r'leaf-adv-simcard[\s\S]{0,400}?subsystem: "SIMCARD"', js)
    # Registry browser + Raw shell inspect views migrate into Advanced
    # so the primary sidebar isn't cluttered with engine-level probes.
    assert re.search(r'leaf-adv-registry[\s\S]{0,400}?inspectView: "registry"', js)
    assert re.search(r'leaf-adv-terminal[\s\S]{0,400}?inspectView: "terminal"', js)


# ----------------------------------------------------------------------
# Render + click plumbing
# ----------------------------------------------------------------------


def test_nav_tree_renderer_builds_groups_and_leaves() -> None:
    """``renderCommandNav`` walks ``CC_NAV_TREE`` (not the flat catalogue)."""
    js = _read("app.js")
    # The renderer must iterate the tree constant, not the catalogue
    # Object.keys sort it used to do.
    render_block = js.split("function renderCommandNav(catalogue) {", 1)[1].split("\n  }\n", 1)[0]
    assert "CC_NAV_TREE.forEach" in render_block
    # Leaves must carry the data attributes the click dispatcher reads.
    assert 'data-cc-leaf-id' in render_block
    assert 'data-cc-subsystem' in render_block
    assert 'data-cc-scope' in render_block
    assert 'data-cc-view' in render_block


def test_nav_group_collapse_state_persists() -> None:
    """Collapse/expand state is written back to localStorage."""
    js = _read("app.js")
    assert "_ccNavGroupStoredState" in js
    assert "_ccNavGroupRememberState" in js
    assert 'yggdrasim:cc-nav:' in js


def test_wire_command_center_routes_leaf_clicks_with_scope() -> None:
    """Nav-leaf clicks pass scope + leafId into ``openCommandSubsystem``."""
    js = _read("app.js")
    wire = js.split("function wireCommandCenter()", 1)[1].split(
        "function readerBarBootstrap()",
        1,
    )[0]
    # The dispatcher must read the scope + leaf attributes and route
    # inspect-only leaves through ``showView`` instead of the CC view.
    assert 'data-cc-scope' in wire
    assert 'data-cc-leaf-id' in wire
    assert 'data-cc-view' in wire
    assert "ccOpenInspectView(inspectView" in wire
    assert "showView(viewName)" in js
    assert 'openCommandSubsystem(subsystem' in wire


def test_open_command_subsystem_accepts_options_and_carries_scope() -> None:
    """Scope flows from the nav leaf all the way to the workbench."""
    js = _read("app.js")
    # The function signature must accept a second options argument.
    assert re.search(r"function openCommandSubsystem\(subsystem, options\)", js)
    # Scope is stored on the command state so rerenders can read it.
    assert "commandState.activeScope = scope;" in js
    # renderCommandSubsystem must receive the scope.
    assert re.search(
        r"renderCommandSubsystem\(subsystem, \{ scope: scope, leaf: leaf, stub: stub \}\)",
        js,
    )


def test_scp03_workbench_receives_and_stores_scope() -> None:
    """``renderScp03Workbench`` persists scope to ``scp03Workbench.scope``."""
    js = _read("app.js")
    assert re.search(r"function renderScp03Workbench\(container, actions, options\)", js)
    # Stored on workbench state + surfaced to CSS via data attribute.
    assert "commandState.scp03Workbench.scope = scope;" in js
    assert 'wb.setAttribute("data-scp03-scope", scope);' in js


# ----------------------------------------------------------------------
# Ribbon filtering + panel layout per scope
# ----------------------------------------------------------------------


def test_ribbon_tabs_filtered_by_scope() -> None:
    """Filesystem/Applications scopes drop unrelated ribbon tabs."""
    js = _read("app.js")
    # Filesystem scope retains navigation / diagnostics / APDU / admin
    # but drops the GP-heavy tabs (auth / registry / install / eUICC).
    assert re.search(
        r'if \(scope === "filesystem"\) \{[\s\S]*?\["home", "inspect", "apdu", "admin"\]',
        js,
    )
    # Applications scope retains GP + admin but drops the FS tree
    # selectors (home / inspect).
    assert re.search(
        r'else if \(scope === "applications"\) \{[\s\S]*?\["auth", "registry", "install", "euicc", "apdu", "admin"\]',
        js,
    )
    # Applications mode defaults the primary ribbon tab to Auth (that
    # is the first thing operators do in that surface).
    assert 'activeId = scope === "applications" ? "auth" : "home";' in js


def test_applications_scope_hides_tree_and_preview() -> None:
    """Applications view skips rendering the FS tree + FCP preview."""
    js = _read("app.js")
    # The gate around the scan-layout block must read the scope.
    assert 'if (scope !== "applications") {' in js
    # And render a hint-card in the Applications branch explaining
    # where the tree went.
    assert 'cc-apps-hint' in js


def test_session_header_exposes_scope_chip() -> None:
    """Each SCP03 session header shows which scope is active."""
    js = _read("app.js")
    assert 'cc-chip-scope' in js
    assert '"scope: filesystem"' in js
    assert '"scope: applications"' in js
    assert '"scope: all"' in js


# ----------------------------------------------------------------------
# CSS contract
# ----------------------------------------------------------------------


def test_css_styles_nested_nav_groups_and_scope_chip() -> None:
    """The nested nav + scope chip have dedicated styles."""
    css = _read("app.css")
    for selector in (
        ".cc-nav-group",
        ".cc-nav-group-header",
        ".cc-nav-caret",
        ".cc-nav-children",
        "#command-center-nav .cc-nav-leaf",
        "#command-center-nav .cc-nav-leaf.is-stub",
        ".cc-chip-scope",
        ".cc-apps-hint",
        ".cc-stub-card",
    ):
        assert selector in css, "missing CSS selector " + selector
    # The caret flips open via the group's ``is-open`` class.
    assert ".cc-nav-group.is-open > .cc-nav-group-header .cc-nav-caret" in css
    assert ".cc-nav-group.is-open > .cc-nav-children" in css
