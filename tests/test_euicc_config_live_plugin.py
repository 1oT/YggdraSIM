# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Contract tests for the live eUICC-configuration plugin.

Two kinds of test live here. The GUI static-flavor contract and the absent
plugin behaviour always run and are safe when the (gitignored) plugin is not
installed. The plugin-behaviour tests import ``plugins.euicc_config_live`` and
skip cleanly when it is absent, so CI without the plugin stays green while a
developer checkout with it exercises the surfaces, gates, and cert confinement.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_APP_JS = _REPO_ROOT / "yggdrasim_common" / "gui_server" / "static" / "app.js"

try:
    import plugins.euicc_config_live  # noqa: F401

    _PLUGIN_PRESENT = True
except Exception:  # noqa: BLE001 - plugin is optional and gitignored
    _PLUGIN_PRESENT = False

_requires_plugin = pytest.mark.skipif(
    not _PLUGIN_PRESENT, reason="euicc_config_live plugin not installed"
)


class _EnvScope:
    """Isolate card/access env flags for one test."""

    def __init__(self, **overrides: "str | None") -> None:
        self._overrides = overrides
        self._saved: dict[str, "str | None"] = {}

    def __enter__(self) -> "_EnvScope":
        for name, value in self._overrides.items():
            self._saved[name] = os.environ.get(name)
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        return self

    def __exit__(self, *exc_info: object) -> None:
        for name, value in self._saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


# --- always-run contracts ------------------------------------------------


def test_app_js_declares_euicc_config_flavor() -> None:
    js = _APP_JS.read_text(encoding="utf-8")
    assert "euicc_config: {" in js
    assert '"SGP.32 eUICC Configuration (live)"' in js
    assert 'id.indexOf(".euicc_config_live.") !== -1' in js
    assert 'return "euicc_config"' in js
    assert "euicc_config: groups[2]" in js


def test_gate_closed_contributes_no_euicc_actions_through_the_real_seam() -> None:
    """With plugin loading hard-locked, the GUI plugin seam adds no euicc actions.

    Exercises ``extend_target_with_plugins`` (the seam ``get_registry`` uses),
    so the absence contract is pinned regardless of whether the gitignored
    plugin happens to be on disk in this checkout.
    """
    from yggdrasim_common import plugin_runtime
    from yggdrasim_common.gui_server.actions.registry import ActionRegistry

    registry = ActionRegistry()
    with _EnvScope(
        **{
            plugin_runtime._ALLOW_PLUGINS_ENV: None,
            plugin_runtime._DISALLOW_PLUGINS_ENV: "1",
        }
    ):
        plugin_runtime.reset_plugin_manager_for_tests()
        try:
            plugin_runtime.extend_target_with_plugins(registry)
        finally:
            plugin_runtime.reset_plugin_manager_for_tests()

    euicc = [spec for spec in registry.all() if spec.id.startswith("plugin.euicc_config_live.")]
    assert euicc == []


# --- plugin-behaviour (skipped when the plugin is absent) ----------------


@_requires_plugin
def test_builders_encode_expected_tags() -> None:
    from plugins.euicc_config_live.verbs import (
        build_execute_fallback_payload,
        build_get_euicc_data_payload,
        build_return_from_fallback_payload,
        build_set_default_dp_address_payload,
    )

    assert build_get_euicc_data_payload("5A").hex().upper() == "BF3E035C015A"
    assert build_get_euicc_data_payload("").hex().upper() == "BF3E035C015A"
    assert build_execute_fallback_payload(False).hex().upper() == "BF5D03800100"
    assert build_execute_fallback_payload(True).hex().upper() == "BF5D038001FF"
    assert build_return_from_fallback_payload(False).hex().upper() == "BF5E03800100"
    dp = build_set_default_dp_address_payload("smdp.example.test").hex().upper()
    assert dp.startswith("BF3F") and dp.endswith("736D64702E6578616D706C652E74657374")


@_requires_plugin
def test_builder_input_guards_reject_bad_input() -> None:
    from plugins.euicc_config_live.verbs import (
        EuiccVerbError,
        build_get_euicc_data_payload,
        build_set_default_dp_address_payload,
    )

    for bad in ("zz", "5"):
        with pytest.raises(EuiccVerbError):
            build_get_euicc_data_payload(bad)
    for bad in ("", "x" * 129):
        with pytest.raises(EuiccVerbError):
            build_set_default_dp_address_payload(bad)


@_requires_plugin
def test_register_plugins_uses_private_capability_never_mcp_extensions() -> None:
    from plugins.euicc_config_live import register_plugins

    seen: dict[str, object] = {}

    class _Manager:
        def register_capability(self, name: str, provider: object) -> None:
            seen[name] = provider

    register_plugins(_Manager())
    assert list(seen) == ["yggdrasim.euicc.live_config.v1"]
    assert "mcp_extensions" not in seen


@_requires_plugin
def test_action_specs_group_under_esim_management_with_unique_suffixes() -> None:
    from plugins.euicc_config_live.provider import EuiccConfigProvider

    specs = EuiccConfigProvider().action_specs()
    assert {spec.subsystem for spec in specs} == {"eSIM Management"}
    assert all(spec.id.startswith("plugin.euicc_config_live.") for spec in specs)
    consolidated_read_filter = {
        "get_certs", "get_eim_config", "get_rat", "status", "scan",
        "discover", "get_eid", "list_profiles", "euicc_info1", "euicc_info2",
    }
    suffixes = [spec.id.rsplit(".", 1)[-1] for spec in specs]
    assert not [s for s in suffixes if s in consolidated_read_filter]


@_requires_plugin
def test_extend_target_registers_actions_and_rejects_conflicting_id() -> None:
    from dataclasses import replace

    from yggdrasim_common.gui_server.actions.registry import ActionRegistry
    from plugins.euicc_config_live.provider import EuiccConfigProvider

    provider = EuiccConfigProvider()
    registry = ActionRegistry()
    provider.extend_target(registry)
    euicc = registry.by_subsystem().get("eSIM Management", [])
    assert len(euicc) == len(provider.action_specs())

    # Re-applying the same provider is idempotent (equivalent specs).
    provider.extend_target(registry)
    assert len(registry.by_subsystem().get("eSIM Management", [])) == len(euicc)

    # A different spec sharing an id is a developer error and must raise.
    clash = replace(euicc[0], title="Different Title")
    with pytest.raises(ValueError):
        registry.register(clash)


@_requires_plugin
def test_memory_reset_requires_confirm_flags_and_matching_eid() -> None:
    from plugins.euicc_config_live.service import EuiccConfigService
    from plugins.euicc_config_live.verbs import EuiccVerbError

    class _Session:
        def __init__(self) -> None:
            self.reset_args = None

        def get_eid(self) -> str:
            return "89000000TESTEID"

        def euicc_memory_reset(self, *, options: dict) -> bytes:
            self.reset_args = options
            return bytes.fromhex("BF6403800100")

    service = EuiccConfigService(session=_Session())
    flags = {"delete_operational_profiles": True}
    for kwargs in (
        {"options": flags, "confirm": False, "eid_echo": "89000000TESTEID"},
        {"options": {}, "confirm": True, "eid_echo": "89000000TESTEID"},
        {"options": flags, "confirm": True, "eid_echo": "WRONGEID"},
    ):
        with pytest.raises(EuiccVerbError):
            service.euicc_memory_reset(**kwargs)

    ok = service.euicc_memory_reset(options=flags, confirm=True, eid_echo="89000000testeid")
    assert ok["ok"] is True
    assert ok["eid"] == "89000000TESTEID"


@_requires_plugin
def test_cert_selection_is_confined_and_excludes_real_identity_fixture() -> None:
    from plugins.euicc_config_live.service import EuiccConfigService
    from plugins.euicc_config_live.verbs import EuiccVerbError

    class _Record:
        def __init__(self, path: str, cn: str, subject: str) -> None:
            self.certificate_path = path
            self.subject_cn = cn
            self.subject = subject
            self.ski = "AABBCCDD"
            self.curve = "NIST"
            self.source = "local_eim_dir"
            self.role = "signing"

    yggdra = _Record("/certs/CERT_S_EIM_YGGDRASIM_NIST.der", "yggdrasim.eim.test.1ot.com",
                     "CN=yggdrasim.eim.test.1ot.com")
    real = _Record("/certs/CERT.EIM.FIRST.TEST.der", "eim1.sm.1ot.com",
                   "C=EE,ST=Harjumaa,L=Tallinn,CN=eim1.sm.1ot.com")
    non_eim = _Record("/certs/CERT_S_SM_DPauth_VARO_SIG_NIST.der", "TEST SM-DP+",
                      "CN=TEST SM-DP+")

    class _Store:
        def signing_records(self) -> list:
            return [yggdra, real, non_eim]

    class _Session:
        _eim_cert_store = _Store()

    service = EuiccConfigService(session=_Session())
    rows = service.list_signing_certificates()["rows"]
    refs = [row["cert_ref"] for row in rows]
    assert refs == ["CERT_S_EIM_YGGDRASIM_NIST.der"]  # real-identity + non-eIM vectors excluded

    assert service._resolve_cert_path(_Session(), "") == ""
    # Exact match on basename or CN resolves; partial refs and excluded/unknown ones raise.
    assert service._resolve_cert_path(_Session(), "CERT_S_EIM_YGGDRASIM_NIST.der") == yggdra.certificate_path
    assert service._resolve_cert_path(_Session(), "yggdrasim.eim.test.1ot.com") == yggdra.certificate_path
    for bad in ("yggdrasim", "CERT.EIM.FIRST.TEST", "TEST SM-DP+", "no-such-cert"):
        with pytest.raises(EuiccVerbError):
            service._resolve_cert_path(_Session(), bad)


@_requires_plugin
def test_shell_install_is_idempotent_and_does_not_clobber_core_verb() -> None:
    from plugins.euicc_config_live.service import EuiccConfigService
    from plugins.euicc_config_live.shell_verbs import install_shell_verbs

    class _Shell:
        def __init__(self) -> None:
            self.session = object()
            self._commands: dict = {"EUICC-MEMORY-RESET": lambda arg="": None}
            self._command_docs: dict = {}
            self._plugin_localized_help_rows: list = []

    shell = _Shell()
    core_verb = shell._commands["EUICC-MEMORY-RESET"]
    service = EuiccConfigService(session=shell.session)
    install_shell_verbs(shell, service)
    install_shell_verbs(shell, service)  # idempotent
    assert "EUICC-GET-CERTS" in shell._commands
    assert "EUICC-MEMORY-RESET-LIVE" in shell._commands
    assert shell._commands["EUICC-MEMORY-RESET"] is core_verb


@_requires_plugin
def test_mcp_tools_refuse_when_gates_are_closed() -> None:
    from plugins.euicc_config_live.provider import EuiccConfigProvider

    class _CaptureMcp:
        def __init__(self) -> None:
            self.tools: dict = {}

        def tool(self):
            def _decorator(fn):
                self.tools[fn.__name__] = fn
                return fn

            return _decorator

    mcp = _CaptureMcp()
    EuiccConfigProvider().register(mcp)

    # Card access disabled: a read tool refuses without reaching a card.
    with _EnvScope(YGGDRASIM_MCP_ALLOW_CARD=None, YGGDRASIM_MCP_ACCESS=None):
        payload = json.loads(mcp.tools["euicc_get_certs"]())
        assert "Card access is disabled" in payload["error"]

    # Card enabled but read-only: a write tool refuses without reaching a card.
    with _EnvScope(YGGDRASIM_MCP_ALLOW_CARD="1", YGGDRASIM_MCP_ACCESS=None):
        payload = json.loads(mcp.tools["euicc_set_default_dp"](address="smdp.example.test"))
        assert "read-only" in payload["error"]
