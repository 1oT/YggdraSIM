# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Every GUI action that changes a card, or deletes from an outside database, asks before it runs.

An action asks when its form carries a ``confirm`` field or the action is
tagged ``destructive`` (the page then adds a required acknowledgement to
every form it builds for it). Until this list was written, Deliver to card,
Set status, the install actions, the Local SM-DP+ profile and metadata
actions, the Local eIM's direct card commands and the OTA sends ran as soon
as Run was pressed. Two buttons run actions without a form, so the page
asks there itself: Deliver now on the Local eIM page and the sending
buttons of the Over-the-Air inspector.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from yggdrasim_common.gui_server.actions.registry import ensure_builtin_actions_loaded, get_registry

_REPO = Path(__file__).resolve().parents[1]

# Card-changing actions: each must ask.
MUST_ASK = (
    # Applications and File system (SCP03)
    "scp03.set_status", "scp03.lock", "scp03.unlock", "scp03.delete", "scp03.store_data",
    "scp03.update_binary", "scp03.update_record", "scp03.put_key", "scp03.install_cap",
    "scp03.install_app", "scp03.install_make_selectable", "scp03.install_extradition",
    "scp03.install_personalization", "scp03.install_registry_update", "scp03.enable_profile",
    "scp03.disable_profile", "scp03.delete_profile", "scp03.fs_create_file", "scp03.fs_delete_file",
    "scp03.fs_resize", "scp03.fs_lifecycle", "scp03.fs_suspend_uicc",
    # Over-the-Air
    "scp80.send", "scp80.ota_smart", "scp80.run_script",
    # eSIM Management
    "scp11_live.set_smdp", "scp11_live.enable_profile", "scp11_live.disable_profile",
    "scp11_live.delete_profile", "scp11_live.reset_card", "scp11_live.remove_notification",
    "scp11_live.clear_notifications", "scp11_live.set_pol", "scp11_live.store_metadata",
    "scp11_live.eim_download", "scp11_live.eim_listen", "scp11_live.download_profile",
    "scp11_live.flow", "scp11_live.add_initial_eim",
    # Local SM-DP+
    "scp11_local.enable_profile", "scp11_local.disable_profile", "scp11_local.delete_profile",
    "scp11_local.load_profile", "scp11_local.store_metadata", "scp11_local.update_metadata",
    "scp11_local.store_metadata_custom", "scp11_local.store_metadata_custom_all",
    # Local eIM
    "eim_local.enable_profile", "eim_local.disable_profile", "eim_local.delete_profile",
    "eim_local.store_metadata", "eim_local.update_metadata", "eim_local.load_profile",
    "eim_local.euicc_memory_reset", "eim_local.isdr_add_initial_eim", "eim_local.add_initial_eim",
    "eim_local.load_eim_package", "eim_local.deliver", "eim_local.associate",
    "eim_local.associate_handover",
    # Offline Tools
    "tool.eim_builder.send",
    # YggdraCore: deletions in the Open5GS database the bridge points at
    "yggdracore.open5gs_remove", "yggdracore.open5gs_purge_yggdrasim",
)

# Card actions left without a question, and why.
NOT_ASKED = {
    "scp03.send_apdu": "the raw APDU console: every command is typed by hand",
    "scp80.send_raw": "the raw APDU button of the OTA inspector, the same console",
    "scp03.reset": "a card reset changes nothing the card stores",
    "scp80.reset_connection": "a transport reset changes nothing the card stores",
}


@pytest.fixture(scope="module")
def registry():
    ensure_builtin_actions_loaded()
    return get_registry()


def _asks(spec) -> bool:
    has_confirm = any("confirm" in str(field.name) for field in (spec.inputs or ()))
    return has_confirm or "destructive" in tuple(spec.tags or ())


@pytest.mark.parametrize("action_id", MUST_ASK)
def test_card_changing_action_asks_before_it_runs(registry, action_id: str) -> None:
    spec = registry.get(action_id)
    assert spec is not None, f"{action_id} is not registered"
    assert _asks(spec), f"{action_id} runs without a confirm field or the destructive tag"


@pytest.mark.parametrize("action_id", sorted(NOT_ASKED))
def test_card_actions_left_unasked_are_the_named_ones(registry, action_id: str) -> None:
    spec = registry.get(action_id)
    assert spec is not None, f"{action_id} is not registered"
    assert not _asks(spec), f"{action_id} asks now: move it to MUST_ASK"


def test_the_lists_do_not_overlap() -> None:
    assert not set(MUST_ASK) & set(NOT_ASKED)
    assert len(MUST_ASK) == len(set(MUST_ASK))


def test_the_page_asks_before_the_buttons_that_run_without_a_form() -> None:
    command_center = (_REPO / "gui_frontend" / "src" / "js" / "command-center.js").read_text(encoding="utf-8")
    local_eim_page = (_REPO / "gui_frontend" / "src" / "js" / "local-eim-page.js").read_text(encoding="utf-8")
    assert "function ccWriteConfirmStrip(" in command_center
    # The OTA inspector: Send OTA, Smart OTA and Script go through the question.
    for action_id in ("scp80.send", "scp80.ota_smart", "scp80.run_script"):
        start = command_center.index('runOtaAction("' + action_id + '"')
        window = command_center[max(0, start - 900):start]
        assert "askBeforeOtaSend(" in window, f"{action_id} is sent without the question"
    # Raw APDU stays the raw console.
    raw = command_center.index('runOtaAction("scp80.send_raw"')
    assert "askBeforeOtaSend(" not in command_center[raw - 400:raw]
    # The Local eIM page: Deliver now asks, naming the reader, and delivers to that reader.
    start = local_eim_page.index('lepButton("Deliver now (IPAd)"')
    block = local_eim_page[start:start + 1500]
    assert "ccWriteConfirmStrip(" in block
    assert "deliver(reader)" in block
    assert 'setAttribute("data-armed", "1")' in block
