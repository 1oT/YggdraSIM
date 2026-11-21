# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""The GUI "Install script" action writes the file SCP03 shell wizard 8 writes.

``scp03.build_install_script`` plans the CAP install sequence without a
card and saves it as the ``#``-commented, one-APDU-per-line script that the
SCP80 shell's ``script`` and the SCP03 shell's ``RUN`` read. Wizard 8 uses
the same builder, so the two surfaces must write the same bytes.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
from unittest.mock import patch

import pytest
from test_scp03_wizard_apdu_builders import _write_ijc

from SCP03.core import install_script
from SCP03.interface.wizards import InteractiveWizards
from yggdrasim_common.gui_server.actions import scp03 as scp03_actions
from yggdrasim_common.gui_server.actions.registry import (
    ActionContext,
    ensure_builtin_actions_loaded,
    get_registry,
)

STATIC = Path(__file__).resolve().parents[1] / "yggdrasim_common" / "gui_server" / "static"
PACKAGE_AID = bytes.fromhex("F000000001")
APPLET_AID = bytes.fromhex("F00000000101")
ACTION_ID = "scp03.build_install_script"
USIM_AID = "A0000000871002FFFFFFFF8988000001"
# ETSI TS 102 226 V19.0.0 clause 8.2.1.3.2.2: tag 80 toolkit parameters
# (clause 8.2.1.3.2.2.1, priority 01 and no resources) and tag 81 access
# parameters (clause 8.2.1.3.2.2.2: the UICC file system entry, then the ADF).
TOOLKIT_80 = "8008" + "0100000000000000"
ACCESS_81_USIM = "8118" + "00" + "0100" + "00" + "10" + USIM_AID + "0100" + "00"
EA_USIM = "EA24" + TOOLKIT_80 + ACCESS_81_USIM


def _build(**inputs):
    return scp03_actions._dispatch_build_install_script(ActionContext(), **inputs)


@pytest.fixture
def ijc_path(tmp_path: Path) -> Path:
    return _write_ijc(tmp_path, PACKAGE_AID, APPLET_AID, method_payload=bytes(range(256)) * 2)


def test_spec_needs_neither_card_nor_auth() -> None:
    ensure_builtin_actions_loaded()
    spec = get_registry().get(ACTION_ID)
    assert spec is not None
    assert spec.requires_card is False
    assert spec.requires_auth is False
    fields = {field.name: field for field in spec.inputs}
    assert fields["cap_path"].kind == "path"
    assert fields["output_path"].kind == "save_path"
    assert fields["transport"].choices == ["ota", "iso"]
    assert fields["ota_cipher"].choices == ["AES", "3DES"]
    assert fields["overwrite"].kind == "bool"
    assert fields["adf_aids"].kind == "string"
    assert fields["adf_aids"].required is False
    assert fields["uicc_toolkit"].kind == "bool"
    assert fields["uicc_toolkit"].default is True


def test_ota_script_is_byte_identical_to_wizard_8(ijc_path: Path) -> None:
    gui_target = ijc_path.parent / "gui_install.txt"
    result = _build(
        cap_path=str(ijc_path), transport="ota", ota_cipher="AES", output_path=str(gui_target)
    )
    assert result["written"] is True
    assert result["script_path"] == str(gui_target)

    wizard_target = ijc_path.parent / "wizard_install.txt"
    # app_aid, mod_aid, priv, adf_aids, run_b, raw_p, ota, algo, save, save_path
    answers = iter(["", "", "", "N", "N", "", "Y", "2", "Y", str(wizard_target)])
    with patch("builtins.input", lambda _prompt="": next(answers)):
        with contextlib.redirect_stdout(io.StringIO()):
            InteractiveWizards.build_install_apdu(None, str(ijc_path), None)

    assert gui_target.read_bytes() == wizard_target.read_bytes()
    assert result["script"] == gui_target.read_text(encoding="utf-8")
    commands = [line for line in result["script"].splitlines() if not line.startswith("#")]
    assert commands == result["apdus"]
    assert result["block_count"] == len(result["apdus"]) - 2
    assert result["chunk_size"] == install_script.ota_load_chunk_size("AES")
    assert result["cipher_mode"] == "AES"
    assert result["package_aid"] == PACKAGE_AID.hex().upper()
    assert result["applet_aid"] == APPLET_AID.hex().upper()
    assert result["module_aid"] == APPLET_AID.hex().upper()
    assert "script <file>" in result["run_hint"]


def test_adf_aids_write_the_same_ea_object_as_wizard_8(ijc_path: Path) -> None:
    gui_target = ijc_path.parent / "gui_usim.txt"
    result = _build(cap_path=str(ijc_path), adf_aids=USIM_AID, output_path=str(gui_target))
    assert result["install_params"] == "C900" + EA_USIM
    assert result["uicc_system_parameters"] == EA_USIM
    assert result["adf_aids"] == [USIM_AID]
    assert f"ADF {USIM_AID}: access domain 00 (full access)" in result["script"]

    wizard_target = ijc_path.parent / "wizard_usim.txt"
    # app_aid, mod_aid, priv, adf_aids, adf_toolkit, run_b, raw_p, ota, algo,
    # save, save_path
    answers = iter(["", "", "", USIM_AID, "", "N", "", "Y", "2", "Y", str(wizard_target)])
    with patch("builtins.input", lambda _prompt="": next(answers)):
        with contextlib.redirect_stdout(io.StringIO()):
            InteractiveWizards.build_install_apdu(None, str(ijc_path), None)
    assert gui_target.read_bytes() == wizard_target.read_bytes()


def test_the_toolkit_switch_drops_tag_80(ijc_path: Path) -> None:
    result = _build(cap_path=str(ijc_path), adf_aids=USIM_AID, uicc_toolkit=False)
    assert result["install_params"] == "C900" + "EA1A" + ACCESS_81_USIM
    result = _build(cap_path=str(ijc_path), adf_aids=USIM_AID, uicc_toolkit="false")
    assert result["install_params"] == "C900" + "EA1A" + ACCESS_81_USIM


def test_blank_adf_aids_leave_the_parameters_alone(ijc_path: Path) -> None:
    result = _build(cap_path=str(ijc_path), adf_aids="  ", uicc_toolkit=True)
    assert result["install_params"] == "C900"
    assert result["uicc_system_parameters"] == ""
    assert result["adf_aids"] == []
    assert "no EA object" in result["script"]


def test_adf_aids_reject_a_second_ea_and_a_bad_aid(ijc_path: Path) -> None:
    with pytest.raises(ValueError, match="already carry Tag EA"):
        _build(cap_path=str(ijc_path), adf_aids=USIM_AID, install_params="C900EA0481020000")
    with pytest.raises(ValueError, match="cannot coexist with Tag EA"):
        _build(cap_path=str(ijc_path), adf_aids=USIM_AID, install_params="EF04CA020100")
    with pytest.raises(ValueError, match="5 to 16 bytes"):
        _build(cap_path=str(ijc_path), adf_aids="A000")


def test_3des_sizes_blocks_for_the_wider_cipher_block(ijc_path: Path) -> None:
    result = _build(cap_path=str(ijc_path), transport="ota", ota_cipher="3DES")
    assert result["chunk_size"] == install_script.ota_load_chunk_size("3DES")
    assert result["written"] is False
    assert "3DES keyset" in result["script"]
    limit = install_script.ota_load_chunk_size("3DES") + 5
    for apdu in result["apdus"][1:-1]:
        assert len(bytes.fromhex(apdu)) <= limit, apdu


def test_iso_script_keeps_le_and_names_the_scp03_runner(ijc_path: Path) -> None:
    result = _build(cap_path=str(ijc_path), transport="iso")
    assert result["chunk_size"] == install_script.ISO_LOAD_CHUNK_SIZE
    assert result["cipher_mode"] == ""
    for apdu in result["apdus"]:
        raw = bytes.fromhex(apdu)
        assert len(raw) - 6 == raw[4], apdu
    assert "RUN <file>" in result["script"]
    assert "Table 11-56" in result["script"]


def test_blank_output_path_builds_without_writing(ijc_path: Path) -> None:
    before = sorted(ijc_path.parent.iterdir())
    result = _build(cap_path=str(ijc_path))
    assert result["written"] is False
    assert result["script_path"] == ""
    assert result["script"].startswith("# Full CAP install sequence for ")
    assert sorted(ijc_path.parent.iterdir()) == before


def test_existing_file_is_kept_unless_overwrite_is_set(ijc_path: Path) -> None:
    target = ijc_path.parent / "keep.txt"
    target.write_text("old\n", encoding="utf-8")
    kept = _build(cap_path=str(ijc_path), output_path=str(target))
    assert kept["written"] is False
    assert "kept" in kept["note"]
    assert target.read_text(encoding="utf-8") == "old\n"
    replaced = _build(cap_path=str(ijc_path), output_path=str(target), overwrite=True)
    assert replaced["written"] is True
    assert target.read_text(encoding="utf-8") == replaced["script"]


def test_bad_inputs_are_reported_as_value_errors(ijc_path: Path) -> None:
    with pytest.raises(ValueError, match="Directory does not exist"):
        _build(cap_path=str(ijc_path), output_path=str(ijc_path.parent / "missing" / "x.txt"))
    with pytest.raises(ValueError, match="transport"):
        _build(cap_path=str(ijc_path), transport="sms")
    with pytest.raises(ValueError, match="cipher"):
        _build(cap_path=str(ijc_path), ota_cipher="RC4")
    with pytest.raises(ValueError, match="not found"):
        _build(cap_path=str(ijc_path.parent / "absent.ijc"))


def test_ribbon_button_and_form_reach_the_bundle() -> None:
    js = (STATIC / "app.js").read_text(encoding="utf-8")
    assert "function scp03ShowBuildInstallScript(tab)" in js
    assert f'"{ACTION_ID}"' in js
    assert 'label: "Install script"' in js
    assert 'name: "adf_aids"' in js
    assert 'name: "uicc_toolkit"' in js
    assert 'scp03AttachPathPicker(outInput, "save")' in js


def test_path_pickers_are_inserted_where_the_input_stood() -> None:
    """``attachPathPicker`` moves the input into the row it returns.

    Replacing the input under its new parent asked that row to replace a
    child of itself (HierarchyRequestError), which detached the CAP path
    field and left the form without its output container. Every SCP03
    form now goes through one helper that inserts the row in place.
    """
    src = (
        Path(__file__).resolve().parents[1]
        / "gui_frontend" / "src" / "js" / "command-center.js"
    ).read_text(encoding="utf-8")
    assert "function scp03AttachPathPicker(input, mode)" in src
    assert src.count("= attachPathPicker(") == 1
    assert "parent.insertBefore(wrapped, next)" in src
    assert src.count("scp03AttachPathPicker(") >= 7
