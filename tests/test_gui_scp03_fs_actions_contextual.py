# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Static assertions for the contextual FS-Admin action bar.

Background
----------
Operators asked for the FS-Admin actions (CREATE FILE / DELETE /
RESIZE / Lifecycle / SEARCH RECORD / SUSPEND UICC) to move out of
the SCP03 ribbon's "Files" tab and down into the file preview next
to the ``fid:`` badge — **and** to be gated by the selected-file
kind so an operator cannot, for example, try to CREATE FILE while
staring at an EF leaf (CREATE FILE is issued under a DF per
ETSI TS 102 222 §6.3).

This test is a pure static-bundle pin — it never boots the GUI.
It guards against silent refactors that would:

  * lose the per-kind gating matrix (``scp03FsActionAvailability``);
  * drop the contextual action bar from the FCP header
    (``scp03BuildFsActionBar`` no longer referenced by
    ``renderFcpResult``);
  * quietly re-add the retired "Files" ribbon tab;
  * strip the CSS tokens that carry the disabled / danger styling.

Assertions hit HTML / CSS / JS source strings directly rather than
going through ``TestClient``, so they run in <100 ms and don't
require ``httpx`` in the test environment.
"""

from __future__ import annotations

from pathlib import Path


STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"


def _read(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# Frontend helpers (JS)
# ----------------------------------------------------------------------


def test_classifier_helper_present() -> None:
    """``scp03ClassifyFile`` maps a read_selected payload to a kind."""
    js = _read("app.js")
    assert "function scp03ClassifyFile(data)" in js, \
        "classifier helper missing — the action bar cannot gate without it"
    # Every canonical kind the action matrix branches on must be
    # emitted by the classifier, otherwise the matrix lookup silently
    # falls through to "unknown" and every action stays disabled.
    for kind in ('"df"', '"application"', '"transparent"', '"linear"', '"cyclic"', '"unknown"'):
        assert kind in js, f"classifier no longer emits {kind} — matrix will desync"


def test_availability_matrix_present() -> None:
    """``scp03FsActionAvailability`` returns the per-kind availability map."""
    js = _read("app.js")
    assert "function scp03FsActionAvailability(kind)" in js, \
        "availability helper missing — the action bar cannot gate without it"
    # The six action slots must all be present in the returned object —
    # if one is dropped the UI renders a button with no gating data.
    for key in ("create:", "delete:", "resize:", "activate:", "deactivate:",
                "terminate:", "searchRecord:", "suspend:"):
        assert key in js, f"availability matrix missing slot {key!r}"


def test_action_bar_builder_present() -> None:
    """``scp03BuildFsActionBar`` is wired into the FCP renderer."""
    js = _read("app.js")
    assert "function scp03BuildFsActionBar(tab, data)" in js, \
        "action bar builder missing"
    assert "scp03BuildFsActionBar(tab, data)" in js, \
        "renderFcpResult no longer calls the action bar builder"


def test_render_fcp_result_accepts_tab() -> None:
    """``renderFcpResult`` gains the optional tab parameter."""
    js = _read("app.js")
    assert "function renderFcpResult(data, container, tab)" in js, \
        "renderFcpResult signature regressed — action bar cannot wire handlers"
    # The cached-repaint call site (cc-scan-preview restore on remount)
    # must still hand over the tab so the action bar shows up on first
    # paint of a switched-back-to tab.
    assert "renderFcpResult(tab.previewCache, preview, tab);" in js
    # The read-selected flow was rewritten (optimistic cache + recovery
    # + retry), so it now renders ``first.data`` / ``second.data`` /
    # cached entries rather than a single ``resp.data`` reference. The
    # contract the action bar cares about is "a tab is threaded through
    # on every render path" — verify each ``renderFcpResult(...)`` call
    # outside the generic dispatch passes a tab.
    for call in (
        "renderFcpResult(first.data, previewEl, tab);",
        "renderFcpResult(second.data, previewEl, tab);",
        "renderFcpResult(cached.data, previewEl, tab);",
    ):
        assert call in js, \
            f"read-selected flow no longer threads tab through: missing {call!r}"


# ----------------------------------------------------------------------
# Ribbon retirement — "Files" tab is gone.
# ----------------------------------------------------------------------


def test_files_ribbon_tab_removed() -> None:
    """The legacy "Files" ribbon tab is retired."""
    js = _read("app.js")
    # The literal descriptor that used to mount the fsAdminGroup into
    # the ribbon must no longer appear. A greppable check is enough —
    # the only other way "files" shows up in the ribbon is a typo we'd
    # want to catch anyway.
    assert '{ id: "files",    label: "Files",      groups: [fsAdminGroup] }' not in js, \
        "Files ribbon tab re-appeared — actions must stay contextual"
    # And the fsAdminGroup factory call must not reappear either.
    assert 'fsAdminGroup = scp03MakeRibbonGroup(' not in js, \
        "fsAdminGroup ribbon factory re-appeared — group should be gone"


def test_fs_wizard_entrypoints_preserved() -> None:
    """The wizards themselves survive — only the entry point moved."""
    js = _read("app.js")
    for entry in (
        "async function scp03ShowFsCreateFile(tab)",
        "async function scp03ShowFsDeleteFile(tab)",
        "async function scp03ShowFsResize(tab)",
        "async function scp03ShowFsLifecycle(tab)",
        "async function scp03ShowFsSearchRecord(tab)",
        "async function scp03ShowFsSuspendUicc(tab)",
    ):
        assert entry in js, f"FS wizard retired: {entry!r}"


# ----------------------------------------------------------------------
# Gating matrix contract — the cases operators asked about explicitly.
# ----------------------------------------------------------------------


def test_gating_rules_match_operator_expectations() -> None:
    """Sanity check on the matrix: operators called out two rules.

    1. "When I press an EF I cant create a file from there but need
       to select MF/DF/ADF etc" → CREATE must be disabled for every
       EF kind and enabled for every DF kind.

    2. "I cant update record on a transparent file" → SEARCH RECORD
       (and by extension record-scoped reads) must be disabled for
       transparent EFs.

    Both rules are verified by reading the matrix source — we pin
    the exact branches so a future refactor can't accidentally flip
    the sign.
    """
    js = _read("app.js")

    # Rule 1 — DF branch enables CREATE.
    df_branch_idx = js.index('if (kind === "df")')
    df_branch_end = js.index("return matrix;", df_branch_idx)
    df_branch = js[df_branch_idx:df_branch_end]
    assert "matrix.create = { enabled: true," in df_branch, \
        "DF branch no longer enables CREATE FILE"

    # Rule 1 — transparent branch disables CREATE.
    transp_idx = js.index('if (kind === "transparent")')
    transp_end = js.index("return matrix;", transp_idx)
    transp_branch = js[transp_idx:transp_end]
    assert "matrix.create = { enabled: false," in transp_branch, \
        "transparent EF branch must disable CREATE FILE"

    # Rule 2 — transparent branch disables SEARCH RECORD.
    assert "matrix.searchRecord = { enabled: false," in transp_branch, \
        "SEARCH RECORD must be disabled on transparent EFs"

    # Linear / cyclic branch enables SEARCH RECORD (both structures
    # share the same branch so one pin covers both).
    record_idx = js.index('if (kind === "linear" || kind === "cyclic")')
    record_end = js.index("return matrix;", record_idx)
    record_branch = js[record_idx:record_end]
    assert "matrix.searchRecord = { enabled: true," in record_branch, \
        "linear/cyclic branch must enable SEARCH RECORD"
    # Linear / cyclic must *not* allow CREATE either.
    assert "matrix.create = { enabled: false," in record_branch, \
        "linear/cyclic branch must disable CREATE FILE"


# ----------------------------------------------------------------------
# CSS contract
# ----------------------------------------------------------------------


def test_css_tokens_for_action_bar_present() -> None:
    css = _read("app.css")
    for selector in (
        ".cc-fs-actions",
        ".cc-fs-actions-group",
        ".cc-fs-action-btn",
        ".cc-fs-action-btn.is-danger",
        ".cc-fs-action-btn.is-disabled",
        ".cc-fs-kind.cc-fs-kind--df",
        ".cc-fs-kind.cc-fs-kind--transparent",
        ".cc-fs-actions-group--card",
    ):
        assert selector in css, f"CSS missing selector: {selector}"


# ----------------------------------------------------------------------
# Update wiring — the FCP contextual bar exposes file administration.
# Data mutation lives next to the transparent body / record hex so the
# selected path, record number, and bytes are inferred by the tool.
# ----------------------------------------------------------------------


def test_availability_matrix_exposes_update_slot() -> None:
    """``avail.update`` is the new gating slot for UPDATE BINARY/RECORD."""
    js = _read("app.js")
    # The slot exists in the default matrix.
    assert "update: { enabled: false, reason: \"\", apdu: \"\" }," in js, \
        "availability matrix lost the new ``update`` slot"

    # Transparent EFs must enable update with apdu='binary'.
    transp_idx = js.index('if (kind === "transparent")')
    transp_end = js.index("return matrix;", transp_idx)
    transp_branch = js[transp_idx:transp_end]
    assert 'matrix.update = { enabled: true, apdu: "binary"' in transp_branch, \
        "transparent EF must enable UPDATE BINARY"

    # Linear / cyclic must enable update with apdu='record'.
    record_idx = js.index('if (kind === "linear" || kind === "cyclic")')
    record_end = js.index("return matrix;", record_idx)
    record_branch = js[record_idx:record_end]
    assert 'matrix.update = { enabled: true, apdu: "record"' in record_branch, \
        "linear/cyclic EF must enable UPDATE RECORD"

    # DF / ADF / unknown branches must keep update disabled — UPDATE is
    # an EF-only operation per ETSI TS 102 221 §11.1.5 / §11.1.6.
    for guard in (
        'if (kind === "df")',
        'if (kind === "application")',
    ):
        idx = js.index(guard)
        end = js.index("return matrix;", idx)
        branch = js[idx:end]
        assert "matrix.update = { enabled: false," in branch, \
            f"{guard} branch must keep UPDATE disabled (EF-only)"


def test_action_bar_does_not_render_update_button() -> None:
    """The contextual action bar no longer exposes the data-update action."""
    js = _read("app.js")
    bar_idx = js.index("function scp03BuildFsActionBar(tab, data)")
    bar_end = js.index("function renderFcpResult(data, container, tab)", bar_idx)
    bar_body = js[bar_idx:bar_end]

    assert 'label: "Update",' not in bar_body
    assert "scp03ShowFsUpdate(tab, info.kind)" not in bar_body

    create_pos = js.index('group.appendChild(createBtn);')
    lifecycle_pos = js.index('group.appendChild(lifecycleBtn);')
    search_pos = js.index('group.appendChild(searchBtn);')
    assert create_pos < lifecycle_pos < search_pos, \
        "Lifecycle/Search ordering drifted in the file action group"


def test_payload_update_buttons_infer_path_record_and_hex() -> None:
    """Transparent bodies and records carry their own update buttons."""
    js = _read("app.js")
    assert "function scp03BuildPayloadUpdateButton(options)" in js
    assert "cc-payload-update-btn" in js

    transparent_idx = js.index("function renderTransparentPayload(payload)")
    transparent_end = js.index("function scp03IsRecordTerminator", transparent_idx)
    transparent_body = js[transparent_idx:transparent_end]
    for token in (
        'mode: "binary"',
        "tab: sourceMeta && sourceMeta.tab ? sourceMeta.tab : null",
        "path: sourceMeta && sourceMeta.path ? String(sourceMeta.path) : \"\"",
        "hex: payload.hex || \"\"",
        "scp03StageOpenUpdateBinary(tab, rawHex, pathText)",
    ):
        assert token in transparent_body or token in js

    record_idx = js.index("function renderSingleRecord(rec, payload)")
    record_end = js.index("function renderDecodedBlock(decoded, meta, options)", record_idx)
    record_body = js[record_idx:record_end]
    for token in (
        "cc-record-actions",
        'mode: "record"',
        "record: Number(rec.record_number || 0)",
        "hex: rec.hex || \"\"",
        "scp03StageOpenUpdateRecord(tab, rawHex, recordNo, pathText)",
    ):
        assert token in record_body or token in js

    helper_idx = js.index("function scp03StageOpenUpdateBinary")
    helper_end = js.index("function scp03StageOpenUpdateRecord", helper_idx)
    helper_body = js[helper_idx:helper_end]
    assert 'document.getElementById("cc-fs-wiz-path")' in helper_body
    assert 'document.getElementById("cc-fs-wiz-hex_data")' in helper_body


def test_fs_update_wizards_present() -> None:
    """Router + branch wizards must exist and call the right action IDs."""
    js = _read("app.js")
    for entry in (
        "function scp03ShowFsUpdate(tab, kind)",
        "async function scp03ShowFsUpdateBinary(tab)",
        "async function scp03ShowFsUpdateRecord(tab, kind)",
    ):
        assert entry in js, f"missing UPDATE wizard entry: {entry!r}"

    # The router maps kind → wizard via a literal table so a transparent
    # EF gets UPDATE BINARY and a linear / cyclic EF gets UPDATE RECORD.
    # We pin the table shape here so a future refactor that swaps wizards
    # gets caught.
    router_idx = js.index("function scp03ShowFsUpdate(tab, kind)")
    router_end = js.index("// ASCII mirror for hex payload fields.", router_idx)
    router_body = js[router_idx:router_end]
    assert "transparent: scp03ShowFsUpdateBinary," in router_body, \
        "router lost the transparent → UPDATE BINARY mapping"
    assert "linear: scp03ShowFsUpdateRecord," in router_body, \
        "router lost the linear → UPDATE RECORD mapping"
    assert "cyclic: scp03ShowFsUpdateRecord," in router_body, \
        "router lost the cyclic → UPDATE RECORD mapping"

    # Each wizard must dispatch the matching backend action.
    bin_idx = js.index("async function scp03ShowFsUpdateBinary(tab)")
    bin_end = js.index("// FS — UPDATE RECORD (00DC) wizard", bin_idx)
    bin_body = js[bin_idx:bin_end]
    assert '"scp03.update_binary"' in bin_body, \
        "UPDATE BINARY wizard no longer dispatches scp03.update_binary"
    # Operator-friendly ergonomics: ASCII mirror, default path, hex_data
    # field, offset hex parsing.
    assert "scp03AttachHexAsciiMirror" in bin_body
    assert "scp03FsPickFromSelection(tab)" in bin_body
    assert 'name="hex_data"' not in bin_body  # using helper, not a raw input attr
    assert 'inputs.hex_data' in bin_body

    rec_idx = js.index("async function scp03ShowFsUpdateRecord(tab, kind)")
    rec_end = js.index("// FS — lifecycle wizard", rec_idx)
    rec_body = js[rec_idx:rec_end]
    assert '"scp03.update_record"' in rec_body, \
        "UPDATE RECORD wizard no longer dispatches scp03.update_record"
    # The wizard must validate the record number client-side before
    # bouncing through the network — operators were getting opaque
    # "invalid record" backend errors otherwise.
    assert "Record must be a positive integer." in rec_body
    assert "Record out of range (1..254)" in rec_body


def test_fs_update_wizards_invalidate_preview_cache() -> None:
    """After a write succeeds the preview cache must be busted.

    Otherwise the next click on the same tree row would re-render the
    *old* body from cache and operators would think the update silently
    failed even though SW=9000 came back.
    """
    js = _read("app.js")
    bin_idx = js.index("async function scp03ShowFsUpdateBinary(tab)")
    bin_end = js.index("// FS — UPDATE RECORD (00DC) wizard", bin_idx)
    rec_idx = js.index("async function scp03ShowFsUpdateRecord(tab, kind)")
    rec_end = js.index("// FS — lifecycle wizard", rec_idx)
    for body in (js[bin_idx:bin_end], js[rec_idx:rec_end]):
        assert "delete tab.previewCache;" in body, \
            "UPDATE wizard must clear the FCP cache so the next read re-fetches"
