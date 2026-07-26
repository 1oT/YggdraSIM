# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Contracts for the shipped MCP server.

The ``mcp`` dependency is an optional extra, so these tests stub the
FastMCP surface and exercise the module offline. The point of interest is
the card-access gate: an MCP client is usually an autonomous agent, and a
stray APDU can exhaust a PIN/PUK counter or block an ADM key.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import json
import re
import sys
import tomllib
import types
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_NAME = "Tools.YggdraMCP.server"


class _StubAnnotations:
    """Stand-in for mcp.types.ToolAnnotations, recording the hints given."""

    def __init__(self, **hints) -> None:
        self.hints = hints


class _StubContext:
    """Stand-in for the injected FastMCP Context."""


def _call(result):
    """Run a tool result, awaiting it when the tool is async."""

    if inspect.iscoroutine(result):
        return asyncio.run(result)
    return result


class _StubMCP:
    """Records tool registrations instead of serving them."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.tools: dict[str, object] = {}
        self.resources: dict[str, object] = {}
        self.prompts: dict[str, object] = {}

    def tool(self, *_args, **_kwargs):
        def decorate(func):
            self.tools[func.__name__] = func
            return func

        return decorate

    def resource(self, uri: str, **_kwargs):
        def decorate(func):
            self.resources[uri] = func
            return func

        return decorate

    def prompt(self, *_args, **_kwargs):
        def decorate(func):
            self.prompts[func.__name__] = func
            return func

        return decorate

    def run(self, **_kwargs):  # pragma: no cover - must never run in tests
        raise AssertionError("mcp.run() must not be called from the test suite")


@pytest.fixture()
def server(monkeypatch: pytest.MonkeyPatch):
    """Import the server module against a stubbed FastMCP."""

    fastmcp = types.ModuleType("mcp.server.fastmcp")
    fastmcp.FastMCP = _StubMCP
    fastmcp.Context = _StubContext
    mcp_types = types.ModuleType("mcp.types")
    mcp_types.ToolAnnotations = _StubAnnotations
    server_pkg = types.ModuleType("mcp.server")
    server_pkg.fastmcp = fastmcp
    root = types.ModuleType("mcp")
    root.server = server_pkg
    root.types = mcp_types

    monkeypatch.setitem(sys.modules, "mcp", root)
    monkeypatch.setitem(sys.modules, "mcp.types", mcp_types)
    monkeypatch.setitem(sys.modules, "mcp.server", server_pkg)
    monkeypatch.setitem(sys.modules, "mcp.server.fastmcp", fastmcp)
    monkeypatch.delitem(sys.modules, MODULE_NAME, raising=False)
    monkeypatch.delenv("YGGDRASIM_MCP_ALLOW_CARD", raising=False)
    monkeypatch.delenv("YGGDRASIM_MCP_ALLOW_DESTRUCTIVE", raising=False)

    module = importlib.import_module(MODULE_NAME)
    yield module
    sys.modules.pop(MODULE_NAME, None)


def test_card_access_is_denied_by_default(server, monkeypatch) -> None:
    assert server.card_access_allowed() is False
    payload = json.loads(_call(server.pcsc_transmit("00A4040000")))
    assert "Card access is disabled" in payload["error"]
    assert server.CARD_ACCESS_ENV in payload["error"]


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
def test_card_access_opt_in_values(server, monkeypatch, value: str) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, value)
    assert server.card_access_allowed() is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "maybe"])
def test_card_access_stays_closed_for_anything_else(server, monkeypatch, value: str) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, value)
    assert server.card_access_allowed() is False


def test_opting_in_gets_past_the_gate(server, monkeypatch) -> None:
    """With the opt-in set, refusal must come from hardware, not the gate."""

    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    payload = json.loads(_call(server.pcsc_transmit("00A4040000")))
    # No reader or no pyscard on a CI host; either way the gate is behind us.
    assert "Card access is disabled" not in payload.get("error", "")


def test_read_only_tools_never_consult_the_card_gate(server) -> None:
    """A denied card gate must not degrade the decode surface."""

    assert server.card_access_allowed() is False
    parsed = json.loads(server.apdu_parse("00A404000CA0000005591010FFFFFFFF8900000100"))
    assert parsed.get("error") is None
    assert json.loads(server.status_word_lookup("9000"))["meaning"].startswith("Success")


def test_registered_tools_cover_the_documented_surface(server) -> None:
    registered = set(server.mcp.tools)
    expected = {
        "validate_identifier",
        "apdu_parse",
        "status_word_lookup",
        "ber_tlv_lookup",
        "spec_section_lookup",
        "scan_identifiers",
        "aide_registry_lookup",
        "pcsc_list_readers",
        "pcsc_transmit",
        "saip_lint",
        "asn1_decode",
        "sgp32_decode",
        "bpp_segment",
        "session_diff",
        "card_bridge_transmit",
        "apdu_risk",
        "plugin_status",
        "saip_diff",
        "metadata_lint",
        "eim_package_lint",
        "runtime_status",
        "shell_run",
    }
    assert expected <= registered, expected - registered


def test_saip_lint_reports_a_missing_file_cleanly(server, tmp_path: Path) -> None:
    payload = json.loads(server.saip_lint(str(tmp_path / "absent.der")))
    assert "No such file" in payload["error"]


def test_saip_lint_refuses_a_workbook_without_traceback(server, tmp_path: Path) -> None:
    workbook = tmp_path / "operator-profile.xlsx"
    workbook.write_bytes(b"PK\x03\x04stub")
    payload = json.loads(server.saip_lint(str(workbook)))
    assert "error" in payload
    assert "SAIP package" in payload["error"]


def test_packaging_ships_the_server_behind_an_optional_extra() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = data["project"]
    assert "Tools.YggdraMCP" in data["tool"]["setuptools"]["packages"]["find"]["include"]
    assert project["optional-dependencies"]["mcp"], "mcp extra must declare a dependency"
    assert project["scripts"]["yggdrasim-mcp"].endswith(":mcp_server")
    # The extra is opt-in: no base or full install may drag the server in.
    for name in ("full", "clean", "saip"):
        for requirement in project["optional-dependencies"].get(name, []):
            assert not requirement.startswith("mcp"), (name, requirement)
    assert not any(item.startswith("mcp") for item in project["dependencies"])


def test_reviewed_package_manifest_lists_the_server() -> None:
    manifest = json.loads(
        (REPO_ROOT / "scripts" / "release" / "python-packages.json").read_text(
            encoding="utf-8"
        )
    )
    assert "Tools.YggdraMCP" in manifest["packages"]


def test_console_script_explains_a_missing_extra(monkeypatch, capsys) -> None:
    """Without the extra the entry point must hint, not raise."""

    import yggdrasim_common.console_scripts as scripts

    def _boom(module_name: str, attribute_name: str) -> int:
        raise ImportError("No module named 'mcp'")

    monkeypatch.setattr(scripts, "_invoke", _boom)
    assert scripts.mcp_server() == 1
    assert "pip install 'yggdrasim[mcp]'" in capsys.readouterr().err


def test_asn1_decode_returns_a_named_recursive_tree(server) -> None:
    payload = json.loads(server.asn1_decode("BF2006800101810101"))
    assert payload["format"] == "BER/DER TLV"
    assert payload["items"][0]["tag"] == "BF20"
    assert payload["items"][0]["name"] == "EUICC_INFO_1"
    # Nested children resolve too, which is what ber_tlv_lookup cannot do.
    assert payload["items"][0]["items"]


@pytest.mark.parametrize("bad", ["", "zz", "0x"])
def test_asn1_decode_rejects_bad_hex_without_raising(server, bad: str) -> None:
    assert "error" in json.loads(server.asn1_decode(bad))


def test_asn1_decode_falls_back_to_apdu_interpretation(server) -> None:
    """decode_bytes tries TLV then APDU, so a valid APDU is not an error."""

    payload = json.loads(server.asn1_decode("BF2012800101"))
    assert "error" not in payload
    assert payload["apdu"]["cla"] == "BF"


def test_asn1_decode_reports_input_that_is_neither_tlv_nor_apdu(server) -> None:
    payload = json.loads(server.asn1_decode("BF20FF"))
    assert "error" in payload
    assert "length" in payload["error"].lower()


def test_sgp32_decode_rejects_an_unknown_kind(server) -> None:
    payload = json.loads(server.sgp32_decode("wishful", "00"))
    assert "error" in payload
    assert "rat_rules" in payload["known"]


def test_sgp32_decode_dispatches_to_the_shared_decoders(server) -> None:
    payload = json.loads(server.sgp32_decode("rat_rules", "BF2B00"))
    assert payload.get("kind") == "rat_rules" or "error" in payload


def test_bpp_segment_follows_annex_m(server) -> None:
    from tests.test_scp11_orchestrator import wrap_tlv

    bf23 = wrap_tlv("BF23", wrap_tlv("80", b"\x10" * 16))
    bpp = wrap_tlv(
        "BF36",
        bf23
        + wrap_tlv("A0", wrap_tlv("87", b"\xAA"))
        + wrap_tlv("A1", wrap_tlv("88", b"\x01" * 8)),
    )
    payload = json.loads(server.bpp_segment(bpp.hex()))
    assert payload["segment_count"] == 4
    assert [item["tag"] for item in payload["segments"]] == ["BF36", "A0", "A1", "88"]


def test_bpp_segment_reports_a_bad_root_tag(server) -> None:
    payload = json.loads(server.bpp_segment("BF3803BF230100"))
    assert "root tag" in payload["error"]


def test_session_diff_tool_matches_the_library(server, tmp_path: Path) -> None:
    import yaml

    def _write(name: str, entries: list[dict]) -> Path:
        path = tmp_path / f"{name}.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "schema": "yggdrasim_session_recording/v1",
                    "apdu_trace": [dict(e, index=i) for i, e in enumerate(entries)],
                }
            ),
            encoding="utf-8",
        )
        return path

    base = [{"apdu_hex": "00A40004023F00", "status_hex": "9000", "response_data_hex": ""}]
    changed = [{"apdu_hex": "00A40004023F00", "status_hex": "6A82", "response_data_hex": ""}]
    payload = json.loads(
        server.session_diff(str(_write("l", base)), str(_write("r", changed)))
    )
    assert payload["identical"] is False
    assert payload["counts"]["status"] == 1


def test_session_diff_tool_reports_a_missing_file(server, tmp_path: Path) -> None:
    payload = json.loads(server.session_diff(str(tmp_path / "a.yaml"), str(tmp_path / "b.yaml")))
    assert "error" in payload


def test_card_bridge_transmit_is_gated_like_local_card_access(server) -> None:
    """A remote relay reaches further than the local reader, not less far."""

    assert server.card_access_allowed() is False
    payload = json.loads(
        _call(server.card_bridge_transmit("http://127.0.0.1:8642/apdu", "00A4040000"))
    )
    assert "Card access is disabled" in payload["error"]


def test_card_bridge_transmit_validates_its_url(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    payload = json.loads(_call(server.card_bridge_transmit("127.0.0.1:8642", "00A4040000")))
    assert "http(s) URL" in payload["error"]


def test_card_bridge_transmit_validates_its_apdu(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    for bad in ("zz", ""):
        payload = json.loads(
            _call(server.card_bridge_transmit("http://127.0.0.1:8642/apdu", bad))
        )
        assert "error" in payload


def test_resources_expose_the_reference_tables(server) -> None:
    registered = set(server.mcp.resources)
    assert registered == {
        "yggdrasim://reference/status-words",
        "yggdrasim://reference/ber-tlv-tags",
        "yggdrasim://reference/spec-sections",
        "yggdrasim://reference/test-identifier-ranges",
    }
    words = json.loads(server.status_word_table())
    assert words["9000"].startswith("Success")
    tags = json.loads(server.ber_tlv_tag_table())
    assert "BF20" in tags
    assert json.loads(server.spec_section_table())
    assert json.loads(server.test_identifier_table())


def test_every_resource_returns_valid_json(server) -> None:
    for uri, provider in server.mcp.resources.items():
        json.loads(provider()), uri


def test_prompts_are_registered_and_render(server) -> None:
    assert set(server.mcp.prompts) == {
        "triage_failed_profile_download",
        "explain_apdu_exchange",
        "review_profile_package",
    }
    rendered = server.triage_failed_profile_download("stuck at BF36")
    assert "stuck at BF36" in rendered
    assert "session_diff" in rendered
    # A prompt with no argument must still render, not crash.
    assert server.explain_apdu_exchange()
    assert server.review_profile_package()


def test_prompts_only_reference_tools_that_exist(server) -> None:
    """A prompt naming a tool that was renamed away would misdirect an agent."""

    registered = set(server.mcp.tools)
    known_words = registered | {"the", "a", "and"}
    for name, prompt in server.mcp.prompts.items():
        text = prompt()
        for candidate in re.findall(r"\b([a-z][a-z0-9_]{4,})\(", text):
            assert candidate in known_words, f"{name} references unknown {candidate}()"


def test_prompts_carry_no_operator_specifics(server) -> None:
    """Generic workflows ship here; operator specifics belong in a plugin."""

    for prompt in server.mcp.prompts.values():
        words = set(re.findall(r"[a-z0-9.]+", prompt().lower()))
        for leak in ("1ot", "sm.1ot", "prod", "staging", "internal"):
            assert leak not in words


# --------------------------------------------------------------------------
# Private extension hook
# --------------------------------------------------------------------------


class _Provider:
    """Minimal well-behaved mcp_extensions provider."""

    def __init__(self, *, health=None, register=None) -> None:
        self.registered_with = None
        if health is not None:
            self.health = health
        if register is not None:
            self.register = register
        elif register is None and not hasattr(self, "register"):
            self.register = self._register

    def _register(self, server) -> None:
        self.registered_with = server

        @server.prompt()
        def house_triage() -> str:
            return "operator specific"


def _patch_capability(monkeypatch, provider, errors=None):
    import yggdrasim_common.plugin_runtime as runtime

    monkeypatch.setattr(runtime, "get_capability", lambda name: provider)
    monkeypatch.setattr(runtime, "plugin_load_errors", lambda: dict(errors or {}))


def test_absent_plugin_leaves_the_server_fully_usable(server, monkeypatch) -> None:
    """The contract: the core must run with no plugin installed."""

    _patch_capability(monkeypatch, None)
    report = server.load_plugin_extensions()
    assert report["registered"] is False
    assert report["errors"] == {}
    assert "apdu_parse" in server.mcp.tools


def test_a_plugin_can_add_a_prompt(server, monkeypatch) -> None:
    provider = _Provider()
    _patch_capability(monkeypatch, provider)
    report = server.load_plugin_extensions()
    assert report["registered"] is True
    assert provider.registered_with is server.mcp
    assert "house_triage" in server.mcp.prompts


def test_a_raising_plugin_is_reported_not_propagated(server, monkeypatch) -> None:
    def _boom(_server):
        raise RuntimeError("plugin exploded")

    _patch_capability(monkeypatch, _Provider(register=_boom))
    report = server.load_plugin_extensions()
    assert report["registered"] is False
    assert "plugin exploded" in report["errors"]["register"]


def test_a_plugin_declaring_itself_unavailable_is_skipped(server, monkeypatch) -> None:
    provider = _Provider(
        health=lambda: {"actions_available": False, "dependency_issues": ["no openpyxl"]}
    )
    _patch_capability(monkeypatch, provider)
    report = server.load_plugin_extensions()
    assert report["registered"] is False
    assert "no openpyxl" in report["errors"]["health"]
    assert provider.registered_with is None


def test_a_plugin_with_a_raising_health_check_is_skipped(server, monkeypatch) -> None:
    def _boom():
        raise RuntimeError("probe failed")

    provider = _Provider(health=_boom)
    _patch_capability(monkeypatch, provider)
    report = server.load_plugin_extensions()
    assert report["registered"] is False
    assert "probe failed" in report["errors"]["health"]
    assert provider.registered_with is None


def test_a_provider_without_register_is_a_contract_error(server, monkeypatch) -> None:
    class Bare:
        pass

    _patch_capability(monkeypatch, Bare())
    report = server.load_plugin_extensions()
    assert report["registered"] is False
    assert "register(mcp)" in report["errors"]["contract"]


def test_loader_surfaces_plugin_import_errors(server, monkeypatch) -> None:
    _patch_capability(monkeypatch, None, errors={"acme_pack": "ImportError: no module"})
    report = server.load_plugin_extensions()
    assert report["errors"]["acme_pack"] == "ImportError: no module"


def test_plugin_loading_is_opt_in_and_hard_lockable(monkeypatch) -> None:
    """Plugins are executable code from the runtime root, so default off."""

    from yggdrasim_common.plugin_runtime import _plugin_loading_allowed

    monkeypatch.delenv("YGGDRASIM_ALLOW_PLUGINS", raising=False)
    monkeypatch.delenv("YGGDRASIM_DISALLOW_PLUGINS", raising=False)
    assert _plugin_loading_allowed() is False

    monkeypatch.setenv("YGGDRASIM_ALLOW_PLUGINS", "1")
    assert _plugin_loading_allowed() is True

    # The hard lock wins over the opt-in, whatever else is set.
    monkeypatch.setenv("YGGDRASIM_DISALLOW_PLUGINS", "1")
    assert _plugin_loading_allowed() is False


def test_the_documented_provider_shape_actually_registers(server, monkeypatch) -> None:
    """Runs the exact class shape published in the plugin-contract doc."""

    class OperatorMcpExtensions:
        def health(self) -> dict:
            return {"actions_available": True, "dependency_issues": []}

        def register(self, mcp) -> None:
            @mcp.prompt()
            def house_profile_review(file_path: str = "") -> str:
                return f"Review {file_path} against the house profile rules ..."

            @mcp.tool()
            def operator_plmn_lookup(mccmnc: str) -> str:
                return json.dumps({"mccmnc": mccmnc})

    _patch_capability(monkeypatch, OperatorMcpExtensions())
    report = server.load_plugin_extensions()

    assert report["registered"] is True, report
    assert "house_profile_review" in server.mcp.prompts
    assert "operator_plmn_lookup" in server.mcp.tools
    assert server.mcp.prompts["house_profile_review"]("x.der").startswith("Review x.der")


# --------------------------------------------------------------------------
# Risk classification and the destructive tier
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "apdu, risk",
    [
        ("00A40004023F00", "read"),      # SELECT
        ("00B0000010", "read"),          # READ BINARY
        ("00B2010410", "read"),          # READ RECORD
        ("80F2400000", "read"),          # GET STATUS
        ("00D6000004AABBCCDD", "write"), # UPDATE BINARY
        ("80E60C001A", "write"),         # INSTALL
        ("0020000108AABBCCDDEEFF0011", "destructive"),  # VERIFY: burns a retry
        ("002C000110" + "AA" * 16, "destructive"),      # RESET RETRY COUNTER
        ("80D8000010" + "BB" * 16, "destructive"),      # PUT KEY
        ("80E400000A", "destructive"),   # DELETE
        ("80F040000101", "destructive"), # SET STATUS
    ],
)
def test_apdu_risk_classification(server, apdu: str, risk: str) -> None:
    assert server.classify_apdu(bytes.fromhex(apdu))["risk"] == risk


def test_unknown_instruction_is_treated_as_write_not_read(server) -> None:
    """An instruction the table has not seen is not evidence it is safe."""

    verdict = server.classify_apdu(bytes.fromhex("00770000"))
    assert verdict["risk"] == "write"
    assert "unrecognised" in verdict["name"]


def test_store_data_carrying_memory_reset_escalates_to_destructive(server) -> None:
    plain = server.classify_apdu(bytes.fromhex("80E2910005AABBCCDDEE"))
    reset = server.classify_apdu(bytes.fromhex("80E2910005BF340400AA"))
    assert plain["risk"] == "write"
    assert reset["risk"] == "destructive"


def test_a_short_apdu_classifies_without_raising(server) -> None:
    assert server.classify_apdu(b"\x00")["risk"] == "unknown"


def test_destructive_needs_its_own_opt_in(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    assert server.card_access_allowed() is True
    assert server.destructive_allowed() is False

    payload = json.loads(_call(server.pcsc_transmit("0020000108" + "AA" * 8)))
    assert "irreversible" in payload["error"]
    assert server.DESTRUCTIVE_ENV in payload["error"]


def test_destructive_opt_in_alone_does_not_open_the_card(server, monkeypatch) -> None:
    """The second flag must not be a way around the first."""

    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    assert server.destructive_allowed() is False
    payload = json.loads(_call(server.pcsc_transmit("00A40004023F00")))
    assert "Card access is disabled" in payload["error"]


def test_reads_pass_the_destructive_gate(server, monkeypatch) -> None:
    """The middle tier must leave ordinary read work usable."""

    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    payload = json.loads(_call(server.pcsc_transmit("00A40004023F00")))
    assert "irreversible" not in payload.get("error", "")
    assert "Card access is disabled" not in payload.get("error", "")


def test_card_bridge_transmit_honours_the_destructive_tier(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    payload = json.loads(
        _call(
            server.card_bridge_transmit(
                "http://127.0.0.1:8642/apdu", "80E400000A"
            )
        )
    )
    assert "irreversible" in payload["error"]


def test_apdu_risk_reports_without_touching_a_card(server) -> None:
    assert server.card_access_allowed() is False
    payload = json.loads(server.apdu_risk("0020000108" + "AA" * 8))
    assert payload["risk"] == "destructive"
    assert payload["would_be_sent"] is False
    assert payload["card_access_enabled"] is False


def test_apdu_risk_tracks_the_gates(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    payload = json.loads(server.apdu_risk("80E400000A"))
    assert payload["would_be_sent"] is True
    assert payload["destructive_enabled"] is True


# --------------------------------------------------------------------------
# Elicitation confirmation
# --------------------------------------------------------------------------


class _Elicited:
    def __init__(self, action: str, proceed: bool = False) -> None:
        self.action = action
        self.data = type("D", (), {"proceed": proceed})()


class _Ctx:
    def __init__(self, result=None, raises: Exception | None = None) -> None:
        self.result = result
        self.raises = raises
        self.messages: list[str] = []

    async def elicit(self, message: str, schema):
        self.messages.append(message)
        if self.raises is not None:
            raise self.raises
        return self.result


def test_declining_the_prompt_sends_nothing(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    ctx = _Ctx(_Elicited("decline"))
    payload = json.loads(
        _call(server.pcsc_transmit("80E400000A", ctx=ctx))
    )
    assert "Declined at confirmation prompt" in payload["error"]
    assert "DELETE" in ctx.messages[0]
    assert "cannot be undone" in ctx.messages[0]


def test_cancelling_the_prompt_sends_nothing(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    payload = json.loads(
        _call(server.pcsc_transmit("80E400000A", ctx=_Ctx(_Elicited("cancel"))))
    )
    assert "Declined at confirmation prompt" in payload["error"]


def test_accepting_the_prompt_proceeds_past_confirmation(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    payload = json.loads(
        _call(
            server.pcsc_transmit("80E400000A", ctx=_Ctx(_Elicited("accept", True)))
        )
    )
    # Past the prompt; refusal now comes from hardware, not from policy.
    assert "Declined at confirmation prompt" not in payload.get("error", "")


def test_reads_are_never_interrupted_by_a_prompt(server, monkeypatch) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    ctx = _Ctx(_Elicited("decline"))
    _call(server.pcsc_transmit("00A40004023F00", ctx=ctx))
    assert ctx.messages == []


def test_a_client_without_elicitation_falls_back_to_the_env_gates(
    server, monkeypatch
) -> None:
    """Elicitation is optional in MCP, so its absence must not break the tool."""

    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    ctx = _Ctx(raises=RuntimeError("client does not support elicitation"))
    payload = json.loads(_call(server.pcsc_transmit("80E400000A", ctx=ctx)))
    assert "Declined at confirmation prompt" not in payload.get("error", "")


def test_confirmation_never_asks_for_a_secret(server) -> None:
    """Secrets go in by path, never through an elicitation prompt.

    The MCP SDK scopes in-band elicitation to non-sensitive data, and an
    agent client may answer a prompt itself: a fabricated PIN would consume
    a real retry counter.
    """

    source = (REPO_ROOT / "Tools" / "YggdraMCP" / "server.py").read_text(encoding="utf-8")
    confirm = source.split("async def _confirm_destructive", 1)[1].split("\ndef ", 1)[0]
    for forbidden in ("pin", "puk", "adm", "password", "secret", "passphrase"):
        assert forbidden not in confirm.lower(), forbidden
    assert "proceed" in confirm


# --------------------------------------------------------------------------
# scan_identifiers: the IPv4 rule must not drown real leaks in citations
# --------------------------------------------------------------------------


def _ip_rule(server):
    return next(e for e in server.REAL_IDENTIFIER_PATTERNS if "IP" in e["name"])


def _reported(server, text: str) -> list[str]:
    rule = _ip_rule(server)
    keep = rule.get("filter")
    return [
        m.group()
        for m in rule["regex"].finditer(text)
        if keep is None or keep(m, text)
    ]


@pytest.mark.parametrize(
    "text, value",
    [
        ('smsc = "93.184.216.34"', "93.184.216.34"),
        ("relay host 8.8.8.8 configured", "8.8.8.8"),
        # Prose between a spec marker and an address must not suppress it.
        ("TS 102 221 and 8.8.8.8", "8.8.8.8"),
    ],
)
def test_routable_addresses_are_reported(server, text: str, value: str) -> None:
    assert value in _reported(server, text)


@pytest.mark.parametrize(
    "text",
    [
        "3GPP TS 31.102 §4.4.11.9 EF.OPL5G",       # section sign
        "# TS 33.501 \\u00a76.1.1.4 canonical SN-name",  # escaped section sign
        "INSTALL [for load] (GPCS 11.5.2.3.1)",          # five-part clause
        "Per Table 4.2.20.1, each cyclic record",        # table reference
        '"package_version": "2.1.2.1"',                  # version field
        "GPC_CardSpecification_v2.3.1.49_PublicRvw.pdf",  # version in a filename
        "ETSI TS 102 221 §§4.4.11.2-4.4.11.5", # clause range
        '"2.5.4.3": "commonName"',                       # X.500 OID
        '"2.5.29.35": "authorityKeyIdentifier"',         # X.509 extension OID
    ],
)
def test_citations_and_oids_are_not_reported(server, text: str) -> None:
    assert _reported(server, text) == []


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.5.4.7", "192.168.1.20", "172.16.0.9", "169.254.1.1",
     "0.0.0.0", "255.255.255.255", "224.0.0.251", "100.64.0.1",
     "192.0.2.10", "198.51.100.7", "203.0.113.9"],
)
def test_non_routable_and_documentation_ranges_are_not_reported(server, address: str) -> None:
    """Loopback, private, link-local, multicast, CGNAT and RFC 5737 are not leaks."""

    assert _reported(server, f"addr = {address}") == []


def test_the_tracked_tree_reports_no_address_leaks(server) -> None:
    """The rule is only useful if a clean tree is quiet."""

    import subprocess

    files = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, cwd=REPO_ROOT
    ).stdout.split()
    assert files, "expected a git checkout"
    # This file deliberately carries routable addresses as true-positive
    # fixtures, and the SGP.26 certificate corpus is upstream test material.
    skip = {"uv.lock", "tests/test_mcp_server.py"}
    noisy: list[str] = []
    for name in files:
        if name in skip or name.startswith("SCP11/SGP.26_test_Certs"):
            continue
        try:
            text = (REPO_ROOT / name).read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for value in _reported(server, text):
            noisy.append(f"{name}: {value}")
    assert noisy == [], noisy[:10]


# --------------------------------------------------------------------------
# Plugin gating: absent means unusable, present means usable
# --------------------------------------------------------------------------


def _reset_extension_state(server) -> None:
    server._EXTENSION_STATE.clear()


def test_plugin_status_reports_nothing_when_no_extension_is_present(
    server, monkeypatch
) -> None:
    _reset_extension_state(server)
    _patch_capability(monkeypatch, None)
    payload = json.loads(server.plugin_status())
    assert payload["extensions_active"] is False
    assert payload["plugin_tools"] == []
    assert "No plugin extensions are registered" in payload["note"]


def test_plugin_status_names_the_tools_an_extension_added(server, monkeypatch) -> None:
    _reset_extension_state(server)
    _patch_capability(monkeypatch, _Provider())
    payload = json.loads(server.plugin_status())
    assert payload["extensions_active"] is True
    assert payload["capability"] == server.MCP_EXTENSION_CAPABILITY


def test_a_workbook_is_refused_differently_without_a_plugin(server, monkeypatch, tmp_path) -> None:
    """Absent plugin: the agent must be told it cannot proceed."""

    _reset_extension_state(server)
    _patch_capability(monkeypatch, None)
    book = tmp_path / "operator.xlsx"
    book.write_bytes(b"PK\x03\x04stub")
    payload = json.loads(server.saip_lint(str(book)))
    assert payload["plugin_available"] is False
    assert "no Excel-to-SAIP generator plugin is loaded" in payload["error"]


def test_a_workbook_points_at_the_plugin_tool_when_present(server, monkeypatch, tmp_path) -> None:
    """Present plugin: the agent must be told how to proceed."""

    class Converting(_Provider):
        workbook_tool = "workbook_to_saip"

        def _register(self, srv):
            @srv.tool()
            def workbook_to_saip(file_path: str) -> str:
                return "{}"

            @srv.tool()
            def unrelated_tool() -> str:
                return "{}"

    _reset_extension_state(server)
    _patch_capability(monkeypatch, Converting())
    book = tmp_path / "operator.xlsx"
    book.write_bytes(b"PK\x03\x04stub")
    payload = json.loads(server.saip_lint(str(book)))
    assert payload["plugin_available"] is True
    # The declared converter leads, so the agent is not left guessing.
    assert payload["plugin_tools"][0] == "workbook_to_saip"
    assert "unrelated_tool" in payload["plugin_tools"]


def test_workbook_gate_covers_every_spreadsheet_suffix(server, monkeypatch, tmp_path) -> None:
    _reset_extension_state(server)
    _patch_capability(monkeypatch, None)
    for suffix in (".xlsx", ".xlsm", ".xls", ".ods"):
        book = tmp_path / f"book{suffix}"
        book.write_bytes(b"PK\x03\x04stub")
        payload = json.loads(server.saip_lint(str(book)))
        assert payload.get("plugin_available") is False, suffix


def test_extension_loading_is_idempotent(server, monkeypatch) -> None:
    """Every caller must see the same state, not re-register tools."""

    _reset_extension_state(server)
    provider = _Provider()
    _patch_capability(monkeypatch, provider)
    first = server.ensure_plugin_extensions()
    second = server.ensure_plugin_extensions()
    assert first["registered"] is True
    assert second == first


# --------------------------------------------------------------------------
# Tier 1: stateless wrappers over existing path-in / data-out APIs
# --------------------------------------------------------------------------

_PACKAGE = "Tools/ProfilePackage/transcode/example_test_profile.transcode.json"
_METADATA = "SCP11/local_access/profile/metadata/default_profile_metadata.json"
_EIM = "SCP11/eim_local/eim_packages/templates/template_eim_package_request.json"


def test_saip_diff_reports_no_change_against_itself(server) -> None:
    payload = json.loads(server.saip_diff(_PACKAGE, _PACKAGE))
    assert payload["identical"] is True
    assert payload["counts"]["total"] == 0


def test_saip_diff_pinpoints_a_single_changed_node(server, tmp_path: Path) -> None:
    original = (REPO_ROOT / _PACKAGE).read_text(encoding="utf-8")
    modified = tmp_path / "modified.transcode.json"
    modified.write_text(
        original.replace("89880811111111111112", "89880811111111119999"),
        encoding="utf-8",
    )
    payload = json.loads(server.saip_diff(str(REPO_ROOT / _PACKAGE), str(modified)))
    assert payload["identical"] is False
    assert payload["counts"]["changed"] == 1
    assert payload["entries"][0]["path"] == "sections.header.iccid"


def test_saip_diff_reports_a_missing_side(server, tmp_path: Path) -> None:
    payload = json.loads(server.saip_diff(_PACKAGE, str(tmp_path / "absent.json")))
    assert "No such file" in payload["error"]


def test_saip_diff_routes_a_workbook_through_the_plugin_gate(server, monkeypatch, tmp_path) -> None:
    """A workbook is not a package on either side of the diff."""

    _reset_extension_state(server)
    _patch_capability(monkeypatch, None)
    book = tmp_path / "operator.xlsx"
    book.write_bytes(b"PK\x03\x04stub")
    payload = json.loads(server.saip_diff(_PACKAGE, str(book)))
    assert payload["plugin_available"] is False


def test_metadata_lint_reports_the_encoded_lengths(server) -> None:
    payload = json.loads(server.metadata_lint(_METADATA))
    assert payload["store_metadata_len"] > 0
    assert payload["update_metadata_len"] > 0
    # A relative path is resolved against the runtime metadata directory, so
    # the wrapper resolves first and confirms the requested file was linted.
    assert "warning" not in payload


def test_metadata_lint_reports_a_missing_file(server, tmp_path: Path) -> None:
    payload = json.loads(server.metadata_lint(str(tmp_path / "absent.json")))
    assert "No such file" in payload["error"]


def test_eim_package_lint_accepts_a_real_package(server) -> None:
    payload = json.loads(server.eim_package_lint(_EIM))
    assert payload["ok"] is True
    assert payload["package_type"] == "eim_package_request"
    assert payload["errors"] == []


def test_eim_package_lint_rejects_a_non_eim_document(server) -> None:
    payload = json.loads(server.eim_package_lint(_PACKAGE))
    assert payload["ok"] is False
    assert any("package_type" in e for e in payload["errors"])


def test_upstream_debug_logging_is_quietened(server) -> None:
    """Loading one package emitted over 140 KB of pySim DEBUG to stderr."""

    import logging

    for name in ("pySim", "osmocom", "construct"):
        assert logging.getLogger(name).level >= logging.WARNING, name


# --------------------------------------------------------------------------
# Tier 3: read-only service state
# --------------------------------------------------------------------------


def test_runtime_status_reports_the_runtime_and_flavor(server) -> None:
    payload = json.loads(server.runtime_status())
    assert payload["runtime_root"]
    assert payload["flavor"]
    assert set(payload["services"]) == {"hil_bridge", "remote_lab"}


def test_runtime_status_says_when_a_service_is_not_running(server) -> None:
    payload = json.loads(server.runtime_status())
    hil = payload["services"]["hil_bridge"]
    assert hil["running"] is False
    assert "not running" in hil.get("note", "")


def test_runtime_status_never_leaks_a_rig_token(server, monkeypatch, tmp_path) -> None:
    """A rig token reaching the model would be a credential disclosure."""

    import yggdrasim_common.remote_lab.registry as registry

    secret = tmp_path / "rig.token"
    secret.write_text("s3cret-rig-token", encoding="utf-8")
    device = {
        "id": "bench-a",
        "name": "Bench A",
        "auth": {"token_file": str(secret), "scheme": "bearer"},
        "agent_host": "127.0.0.1",
    }
    monkeypatch.setattr(registry, "list_devices", lambda: [
        {**device, "auth": {"scheme": "bearer", "token_present": True}},
    ])
    rendered = server.runtime_status()
    assert "s3cret-rig-token" not in rendered
    assert str(secret) not in rendered
    assert json.loads(rendered)["services"]["remote_lab"]["count"] == 1


def test_runtime_status_survives_an_unreadable_registry(server, monkeypatch) -> None:
    import yggdrasim_common.remote_lab.registry as registry

    def _boom():
        raise RuntimeError("registry is corrupt")

    monkeypatch.setattr(registry, "list_devices", _boom)
    payload = json.loads(server.runtime_status())
    assert "registry is corrupt" in payload["services"]["remote_lab"]["note"]


def test_runtime_status_is_read_only(server) -> None:
    """It reports service state; it must not offer lifecycle control."""

    source = (REPO_ROOT / "Tools" / "YggdraMCP" / "server.py").read_text(encoding="utf-8")
    body = source.split("def runtime_status(", 1)[1].split("\n@mcp.tool", 1)[0]
    for forbidden in ("subprocess", "Popen", ".start(", ".stop(", "kill", "terminate"):
        assert forbidden not in body, forbidden


# --------------------------------------------------------------------------
# Tier 2: gated shell batch execution
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command, risk",
    [
        ("INFO", "read"), ("LINT", "read"), ("TREE", "read"), ("USE p.der", "read"),
        ("GENERATE-BATCH t.json r.csv out/", "write"), ("DELETE x", "destructive"),
        ("SET-TOKEN a b", "write"), ("DIFF-TUI", "interactive"),
        ("NEW-PROFILE-WIZARD", "interactive"), ("WATCH-SIMCARD", "interactive"),
        ("RM -rf /", "unknown"), ("", "empty"),
    ],
)
def test_shell_command_classification(server, command: str, risk: str) -> None:
    assert server.classify_shell_command(command, "profile_package")["risk"] == risk


def test_classification_sets_do_not_overlap(server) -> None:
    """A verb in two sets would make its treatment depend on check order."""

    spec = server._SHELLS["profile_package"]
    read, write, interactive = spec.read, spec.write, spec.interactive
    assert not (read & write)
    assert not (read & interactive)
    assert not (write & interactive)


def test_no_write_verb_is_classified_as_read(server) -> None:
    """A misfiled verb would run unguarded."""

    mutating_prefixes = ("GENERATE", "IMPORT", "APPLY", "NEW-", "SET", "REMOVE",
                         "RENAME", "DELETE", "RETOKENI", "PROVISION", "RANDOMIZE")
    for verb in server._SHELLS["profile_package"].read:
        assert not verb.startswith(mutating_prefixes), verb


def test_write_verbs_are_refused_without_the_opt_in(server, monkeypatch) -> None:
    monkeypatch.delenv(server.SHELL_WRITE_ENV, raising=False)
    payload = json.loads(server.shell_run("profile_package", "GENERATE-BATCH a b c; EXIT"))
    assert server.SHELL_WRITE_ENV in payload["error"]
    assert payload["risk"] == "write"


def test_interactive_verbs_are_always_refused(server, monkeypatch) -> None:
    """A TUI has no terminal in a batch and would hang until timeout."""

    monkeypatch.setenv(server.SHELL_WRITE_ENV, "1")
    payload = json.loads(server.shell_run("profile_package", "DIFF-TUI; EXIT"))
    assert "interactive" in payload["error"]


def test_unknown_verbs_are_refused_rather_than_passed_through(server, monkeypatch) -> None:
    monkeypatch.setenv(server.SHELL_WRITE_ENV, "1")
    payload = json.loads(server.shell_run("profile_package", "RM -rf /; EXIT"))
    assert "not a recognised verb" in payload["error"]


def test_a_refused_verb_anywhere_blocks_the_whole_batch(server, monkeypatch) -> None:
    """Refusal must precede execution; a later write must not run either."""

    monkeypatch.delenv(server.SHELL_WRITE_ENV, raising=False)
    monkeypatch.delenv(server.DESTRUCTIVE_ENV, raising=False)
    payload = json.loads(server.shell_run("profile_package", "INFO; DELETE x; EXIT"))
    assert payload["verb"] == "DELETE"
    assert "output" not in payload


def test_empty_batch_is_rejected(server) -> None:
    assert "No commands given" in json.loads(server.shell_run("profile_package", "  ;  "))["error"]


def test_relative_path_arguments_are_flagged(server) -> None:
    """The shell resolves relative paths against its own directories."""

    payload = json.loads(server.shell_run("profile_package", "USE some/profile.der; EXIT"))
    assert "Relative path argument" in payload["warning"]
    assert "absolute paths" in payload["warning"]


def test_absolute_paths_are_not_flagged(server, tmp_path) -> None:
    package = tmp_path / "p.der"
    package.write_bytes(b"\\x00")
    payload = json.loads(server.shell_run("profile_package", f"USE {package}; EXIT"))
    assert "warning" not in payload


def test_shell_output_carries_no_ansi_escapes(server, tmp_path) -> None:
    """The shell paints its output; colour codes are noise to a caller."""

    payload = json.loads(server.shell_run("profile_package", "HELP; EXIT"))
    assert "\\x1b[" not in payload["output"]
    assert payload["output"]


def test_card_driving_shells_are_not_exposed(server) -> None:
    """SCP03 opens a PC/SC reader during startup, before any verb runs."""

    registered = set(server.mcp.tools)
    for forbidden in ("scp03_run", "scp11_run", "scp80_run", "profile_package_run"):
        assert forbidden not in registered


# --------------------------------------------------------------------------
# Card-driving shells
# --------------------------------------------------------------------------


def _all_env_off(monkeypatch, server) -> None:
    for name in (server.CARD_ACCESS_ENV, server.DESTRUCTIVE_ENV, server.SHELL_WRITE_ENV):
        monkeypatch.delenv(name, raising=False)


@pytest.mark.parametrize("shell", ["scp03", "scp11_local_access"])
def test_card_shells_refuse_before_starting_the_process(server, monkeypatch, shell) -> None:
    """These connect to a reader during startup, so even HELP touches hardware."""

    _all_env_off(monkeypatch, server)
    payload = json.loads(server.shell_run(shell, "HELP; EXIT"))
    assert payload["drives_a_card"] is True
    assert server.CARD_ACCESS_ENV in payload["error"]
    assert "output" not in payload


@pytest.mark.parametrize("verb", ["RUN evil.txt", "SCRIPT batch.txt"])
def test_command_file_verbs_are_always_refused(server, monkeypatch, verb) -> None:
    """These execute a file, so nothing inside ever reaches the verb gate."""

    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    monkeypatch.setenv(server.SHELL_WRITE_ENV, "1")
    payload = json.loads(server.shell_run("scp03", f"{verb}; EXIT"))
    assert "executes a file of commands" in payload["error"]


def test_secret_bearing_verbs_are_always_refused(server, monkeypatch) -> None:
    """A tool argument reaches the model provider; a Ki must not."""

    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.setenv(server.DESTRUCTIVE_ENV, "1")
    monkeypatch.setenv(server.SHELL_WRITE_ENV, "1")
    payload = json.loads(server.shell_run("scp03", "DERIVE-OPC AABB CCDD; EXIT"))
    assert "key material as an argument" in payload["error"]


@pytest.mark.parametrize(
    "shell, command",
    [
        ("scp03", "INSTALL-CAP applet.cap"),
        ("scp03", "EXPORT-KEYBAG keys.json"),
        ("scp03", "STORE-DATA AABB"),
        ("scp11_local_access", "DELETE-PROFILE 1"),
        ("scp11_local_access", "PROFILE-RESET"),
    ],
)
def test_destructive_card_verbs_need_their_own_opt_in(
    server, monkeypatch, shell: str, command: str
) -> None:
    monkeypatch.setenv(server.CARD_ACCESS_ENV, "1")
    monkeypatch.delenv(server.DESTRUCTIVE_ENV, raising=False)
    payload = json.loads(server.shell_run(shell, f"{command}; EXIT"))
    assert payload["risk"] == "destructive"
    assert server.DESTRUCTIVE_ENV in payload["error"]


def test_every_shell_classifies_its_verbs_consistently(server) -> None:
    """A verb in two sets would make its treatment depend on check order."""

    for name, spec in server._SHELLS.items():
        sets = {
            "read": spec.read,
            "write": spec.write,
            "destructive": spec.destructive,
            "interactive": spec.interactive,
        }
        for left, first in sets.items():
            for right, second in sets.items():
                if left < right:
                    assert not (first & second), f"{name}: {left} overlaps {right}"


def test_no_shell_readmits_a_command_file_or_secret_verb(server) -> None:
    """A shell spec must not route RUN, SCRIPT, or a Ki-bearing verb back in."""

    for name, spec in server._SHELLS.items():
        runnable = spec.read | spec.write | spec.destructive
        assert not (runnable & server._COMMAND_FILE_VERBS), name
        assert not (runnable & server._SECRET_ARGUMENT_VERBS), name


def test_card_shells_are_marked_as_such(server) -> None:
    assert server._SHELLS["scp03"].card is True
    assert server._SHELLS["scp11_local_access"].card is True
    assert server._SHELLS["profile_package"].card is False


def test_unknown_shell_is_rejected_with_the_known_list(server) -> None:
    payload = json.loads(server.shell_run("scp99", "HELP; EXIT"))
    assert "Unknown shell" in payload["error"]
    assert set(payload["known"]) == set(server._SHELLS)
