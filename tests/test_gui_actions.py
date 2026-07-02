# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for the Command Center action framework (R2-004 Phase C).

Covers:

* The typed-input coercion helpers (no FastAPI needed).
* The in-memory session manager (no hardware needed).
* The four bundled action specs register themselves on import.
* The HTTP router: catalogue listing, per-action run, streaming gate,
  auth gate, and unknown-action handling (FastAPI optional — skipped
  in environments that did not install the ``gui`` extra).
"""

from __future__ import annotations

import asyncio
import importlib
import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from yggdrasim_common.gui_server import sessions as sessions_module
from yggdrasim_common.gui_server.actions.registry import (
    ActionField,
    ActionRegistry,
    ActionSpec,
    coerce_input,
    coerce_inputs,
    ensure_builtin_actions_loaded,
    get_registry,
)


# ----------------------------------------------------------------------
# Coercion helpers
# ----------------------------------------------------------------------


class TestCoerceInput:
    def test_string_passthrough(self) -> None:
        field = ActionField(name="x", label="x")
        assert coerce_input(field, "hello") == "hello"

    def test_hex_normalises_case_and_strips_whitespace(self) -> None:
        field = ActionField(name="apdu", label="apdu", kind="hex")
        assert coerce_input(field, " 80 e2 ab cd ") == "80E2ABCD"

    def test_hex_rejects_odd_length(self) -> None:
        field = ActionField(name="apdu", label="apdu", kind="hex")
        with pytest.raises(ValueError):
            coerce_input(field, "80E")

    def test_hex_rejects_non_hex(self) -> None:
        field = ActionField(name="apdu", label="apdu", kind="hex")
        with pytest.raises(ValueError):
            coerce_input(field, "80ZZ")

    def test_int_accepts_hex_prefix(self) -> None:
        field = ActionField(name="count", label="count", kind="int")
        assert coerce_input(field, "0x10") == 16

    def test_int_respects_min(self) -> None:
        field = ActionField(name="count", label="count", kind="int", min_value=1)
        with pytest.raises(ValueError):
            coerce_input(field, "0")

    def test_bool_truthy(self) -> None:
        field = ActionField(name="flag", label="flag", kind="bool")
        assert coerce_input(field, "yes") is True
        assert coerce_input(field, "on") is True
        assert coerce_input(field, True) is True

    def test_bool_falsy(self) -> None:
        field = ActionField(name="flag", label="flag", kind="bool")
        assert coerce_input(field, "no") is False
        assert coerce_input(field, False) is False

    def test_empty_optional_bool_yields_none(self) -> None:
        # An optional field with no default and no input becomes None,
        # before bool coercion even runs.
        field = ActionField(name="flag", label="flag", kind="bool")
        assert coerce_input(field, "") is None
        assert coerce_input(field, None) is None

    def test_empty_optional_bool_with_default_returns_default(self) -> None:
        field = ActionField(name="flag", label="flag", kind="bool", default=False)
        assert coerce_input(field, None) is False

    def test_enum_rejects_unknown_choice(self) -> None:
        field = ActionField(name="mode", label="mode", kind="enum", choices=["a", "b"])
        with pytest.raises(ValueError):
            coerce_input(field, "c")

    def test_missing_required_raises(self) -> None:
        field = ActionField(name="x", label="x", required=True)
        with pytest.raises(ValueError):
            coerce_input(field, None)

    def test_missing_optional_uses_default(self) -> None:
        field = ActionField(name="count", label="count", kind="int", default=7)
        assert coerce_input(field, None) == 7


class TestCoerceInputs:
    def _spec(self) -> ActionSpec:
        return ActionSpec(
            id="demo.test",
            subsystem="demo",
            title="t",
            description="d",
            inputs=(
                ActionField(name="host", label="host", required=True),
                ActionField(name="port", label="port", kind="int", default=443),
                ActionField(name="tls", label="tls", kind="bool", default=True),
            ),
        )

    def test_happy_path(self) -> None:
        out = coerce_inputs(
            self._spec(),
            {"host": "a.example.com", "port": "8443", "tls": "false"},
        )
        assert out == {"host": "a.example.com", "port": 8443, "tls": False}

    def test_missing_required_raises(self) -> None:
        with pytest.raises(ValueError):
            coerce_inputs(self._spec(), {"port": "443"})

    def test_unknown_keys_are_silently_dropped(self) -> None:
        out = coerce_inputs(self._spec(), {"host": "h", "ignored": "x"})
        assert "ignored" not in out


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------


class TestActionRegistry:
    def test_scoped_register_is_idempotent_same_spec(self) -> None:
        registry = ActionRegistry()
        spec = ActionSpec(id="demo.a", subsystem="demo", title="a", description="d")
        registry.register(spec)
        registry.register(spec)  # same object — no-op
        assert registry.has("demo.a")
        assert len(registry.all()) == 1

    def test_register_is_idempotent_for_equivalent_reimported_spec(self) -> None:
        registry = ActionRegistry()

        def _make_dispatcher():
            def _dispatch(ctx):
                return {"ok": True}

            _dispatch.__module__ = "demo.actions"
            _dispatch.__qualname__ = "_dispatch"
            return _dispatch

        first = ActionSpec(
            id="demo.a",
            subsystem="demo",
            title="a",
            description="d",
            dispatcher=_make_dispatcher(),
        )
        second = ActionSpec(
            id="demo.a",
            subsystem="demo",
            title="a",
            description="d",
            dispatcher=_make_dispatcher(),
        )

        registry.register(first)
        returned = registry.register(second)

        assert returned is first
        assert registry.get("demo.a") is first
        assert len(registry.all()) == 1

    def test_register_duplicate_id_raises(self) -> None:
        registry = ActionRegistry()
        registry.register(ActionSpec(id="demo.a", subsystem="demo", title="a", description=""))
        with pytest.raises(ValueError):
            registry.register(ActionSpec(id="demo.a", subsystem="other", title="other", description=""))

    def test_by_subsystem_groups_and_sorts(self) -> None:
        registry = ActionRegistry()
        registry.register(ActionSpec(id="b.two", subsystem="B", title="T2", description=""))
        registry.register(ActionSpec(id="a.one", subsystem="A", title="T1", description=""))
        groups = registry.by_subsystem()
        assert list(groups.keys()) == ["A", "B"]

    def test_bundled_actions_register_on_load(self) -> None:
        registry = ensure_builtin_actions_loaded()
        ids = {spec.id for spec in registry.all()}
        assert "scp03.scan" in ids
        assert "scp03.read_selected" in ids
        assert "scp11.download_profile" in ids
        assert "eim_local.hotfolder_campaign" in ids

    def test_expanded_command_center_actions_register(self) -> None:
        registry = ensure_builtin_actions_loaded()
        ids = {spec.id for spec in registry.all()}
        expected = {
            # Engine-panel wraps
            "tool.tlv.decode",
            "tool.asn1_tlv.decode",
            "tool.sw.lookup",
            "tool.euicc_info2.decode",
            "tool.sima_response.decode",
            "tool.saip.lint",
            "tool.eim.lint",
            "tool.gsma.codes",
            "suci.status",
            "suci.generate_key",
            "simcard.tuak_derive_topc",
            # Session-based SCP03 extensions
            "scp03.select",
            "scp03.list_apps",
            "scp03.close_session",
            # Eim-local helpers
            "eim_local.list_fixtures",
            "eim_local.hotfolder_metadata",
            "eim_local.issue_package",
            # Local SM-DP+ helpers
            "scp11_local.import_certificate",
        }
        missing = expected - ids
        assert not missing, f"missing registered actions: {sorted(missing)}"

    def test_offline_tools_collect_non_card_actions(self) -> None:
        registry = ensure_builtin_actions_loaded()
        offline_ids = {spec.id for spec in registry.by_subsystem().get("Offline Tools", [])}
        expected = {
            "tool.tlv.decode",
            "tool.asn1_tlv.decode",
            "tool.sw.lookup",
            "tool.euicc_info2.decode",
            "tool.sima_response.decode",
            "tool.saip.lint",
            "tool.eim.lint",
            "tool.gsma.codes",
            "suci.status",
            "suci.use_key_file",
            "suci.set_tool_command",
            "suci.generate_key",
            "suci.dump_pub_key",
            "simcard.tuak_derive_topc",
        }
        assert expected.issubset(offline_ids)
        assert get_registry().get("simcard.quirks_status").subsystem == "SIMCARD"
        assert get_registry().get("simcard.profile_store_list").subsystem == "SIMCARD"

    def test_eim_load_package_exposes_cert_override(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import eim_local
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        registry = ensure_builtin_actions_loaded()
        spec = registry.get("eim_local.load_eim_package")
        fields = {field.name: field for field in spec.inputs}

        assert fields["package_path"].kind == "path"
        assert fields["package_path"].required is True
        assert fields["cert_path"].kind == "path"
        assert fields["cert_path"].required is False

        calls: list[tuple[str, str]] = []

        class FakeSession:
            def load_eim_package_to_isdr(
                self,
                package_path: str = "",
                cert_path: str = "",
            ) -> dict[str, object]:
                calls.append((package_path, cert_path))
                return {
                    "package_path": package_path,
                    "package_type": "add_eim",
                    "selected_cert_path": cert_path,
                }

        monkeypatch.setattr(eim_local, "_build_eim_session", lambda: FakeSession())

        result = eim_local._dispatch_load_eim_package(
            ActionContext(),
            package_path="/tmp/package.json",
            cert_path="/tmp/cert.pem",
        )

        assert calls == [("/tmp/package.json", "/tmp/cert.pem")]
        assert result["cert_path"] == "/tmp/cert.pem"
        assert result["report"]["selected_cert_path"] == "/tmp/cert.pem"

    def test_local_smdp_import_certificate_copies_to_persistent_store(
        self,
        tmp_path,
        monkeypatch,
    ) -> None:
        from SCP11.local_access import config as config_module
        from SCP11.local_access import session as session_module
        from yggdrasim_common.gui_server.actions import scp11_local
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        certs_dir = tmp_path / "Workspace" / "LocalSMDPP" / "certs"
        source_dir = tmp_path / "source"
        source_dir.mkdir()
        cert_path = source_dir / "CERT.DPauth.ECDSA.der"
        key_path = source_dir / "SK.DPauth.ECDSA.pem"
        cert_path.write_bytes(b"certificate")
        key_path.write_bytes(b"private-key")

        class FakeConfig:
            def __init__(self, **kwargs):
                self.CERTS_DIR = str(certs_dir)

        class FakeSession:
            def __init__(self, cfg, apdu_channel=None):
                self.cfg = cfg
                self.apdu_channel = apdu_channel

            def list_local_smdp_certificate_inventory(self):
                return {
                    "auth_records": [
                        {"certificate_path": str(certs_dir / "SM-DP+" / "SM_DPauth" / cert_path.name)}
                    ],
                    "pb_records": [],
                    "selected_auth": {
                        "certificate_path": str(certs_dir / "SM-DP+" / "SM_DPauth" / cert_path.name)
                    },
                    "selected_pb": None,
                }

        monkeypatch.setattr(config_module, "LocalAccessConfig", FakeConfig)
        monkeypatch.setattr(session_module, "LocalIsdrSession", FakeSession)

        result = scp11_local._dispatch_import_certificate(
            ActionContext(),
            certificate_path=str(cert_path),
            private_key_path=str(key_path),
            certificate_role="DPauth",
            root_ci_pkid="F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
            server_address="local.example.test",
        )

        target_dir = certs_dir / "SM-DP+" / "SM_DPauth"
        target_cert = target_dir / cert_path.name
        target_key = target_dir / key_path.name
        metadata = json.loads(Path(result["metadata_path"]).read_text(encoding="utf-8"))

        assert target_cert.read_bytes() == b"certificate"
        assert target_key.read_bytes() == b"private-key"
        assert result["certificate_path"] == str(target_cert)
        assert result["private_key_path"] == str(target_key)
        assert metadata["role"] == "auth"
        assert metadata["private_key_path"] == key_path.name
        assert metadata["server_address"] == "local.example.test"
        assert result["inventory"]["selected_auth"]["certificate_path"] == str(target_cert)

    def test_third_slice_actions_register(self) -> None:
        """Every SCP11-live and HIL action must be in the catalogue."""
        registry = ensure_builtin_actions_loaded()
        ids = {spec.id for spec in registry.all()}
        expected = {
            # SCP11 live read-only wraps
            "scp11_live.get_eid",
            "scp11_live.list_profiles",
            "scp11_live.get_smdp",
            "scp11_live.list_notifications",
            "scp11_live.euicc_info2",
            # HIL supervisor surfaces
            "hil.supervisor_status",
            "hil.bridge_status",
            "hil.watch_supervisor",
            "hil.decode_snapshot",
            "hil.session_start",
            "hil.session_stop",
        }
        missing = expected - ids
        assert not missing, f"missing third-slice actions: {sorted(missing)}"

    def test_scp11_live_actions_declare_reader_input(self) -> None:
        """Each live action must take an optional 'reader' field."""
        registry = ensure_builtin_actions_loaded()
        for action_id in (
            "scp11_live.get_eid",
            "scp11_live.list_profiles",
            "scp11_live.get_smdp",
            "scp11_live.list_notifications",
            "scp11_live.euicc_info2",
        ):
            spec = registry.get(action_id)
            field_names = {f.name for f in spec.inputs}
            assert "reader" in field_names, f"{action_id} missing reader input"
            reader_field = next(f for f in spec.inputs if f.name == "reader")
            assert reader_field.required is False
            assert reader_field.kind == "reader"
            assert spec.requires_card is True
            assert spec.streams is False

    def test_scp11_live_eim_download_form_is_reader_only(self) -> None:
        registry = ensure_builtin_actions_loaded()
        spec = registry.get("scp11_live.eim_download")
        field_names = [field.name for field in spec.inputs]

        assert field_names == ["reader"]
        assert spec.streams is True
        assert spec.output_kind == "log_stream"
        assert "confirm checkbox" not in spec.description

    def test_scp11_live_eim_poll_form_has_no_confirm(self) -> None:
        registry = ensure_builtin_actions_loaded()
        spec = registry.get("scp11_live.eim_poll")
        field_names = [field.name for field in spec.inputs]

        assert field_names == ["reader", "arguments"]
        assert spec.streams is True
        assert spec.output_kind == "log_stream"

    def test_scp11_live_euicc_info2_lines_preserve_shared_tuple_order(self) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live

        response = bytes.fromhex(
            "BF228192810302030182030206008303260116840D81010882040002EC08830224"
            "DF8505007FB6F3C1860311020087030203008802029CA916041481370F5125D0B1D4"
            "08D4C3B232E6D25E795BEBFBAA16041481370F5125D0B1D408D4C3B232E6D25E795BEBFB"
            "990206400403FFFFFF0C0D4B4E2D444E2D55502D30333237AF050403030301900101"
            "B40BA005040301020081008200"
        )

        rows = scp11_live._build_euicc_info2_lines(response)

        assert {"label": "IPA Mode", "value": "Mode 1 active (1)", "indent": 0} in rows
        assert {"label": "IoT Specific Info", "value": "true", "indent": 0} in rows
        assert {"label": "eCall Supported", "value": "true", "indent": 1} in rows
        assert {"label": "Fallback Supported", "value": "true", "indent": 1} in rows

    def test_scp11_live_get_certs_lines_include_full_der_hex(self) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live

        eum = bytes.fromhex("3003020101")
        euicc = bytes.fromhex("3003020102")
        response = (
            bytes.fromhex("BF56")
            + bytes([len(eum) + len(euicc) + 4])
            + bytes.fromhex("A5")
            + bytes([len(eum)])
            + eum
            + bytes.fromhex("A6")
            + bytes([len(euicc)])
            + euicc
        )

        rows = scp11_live._build_certs_lines(response)

        assert {"label": "EUM Certificate", "value": "Present (5 B)", "indent": 0} in rows
        assert {"label": "EUM Certificate DER Hex", "value": eum.hex().upper(), "indent": 1} in rows
        assert {"label": "eUICC Certificate", "value": "Present (5 B)", "indent": 0} in rows
        assert {"label": "eUICC Certificate DER Hex", "value": euicc.hex().upper(), "indent": 1} in rows

    def test_scp11_live_stream_uses_console_command_policy(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live

        calls: list[tuple[str, str, str]] = []

        class DummyConsole:
            _commands = {"DOWNLOAD": object()}

            def _execute_command(self, command: str, argument: str) -> bool:
                calls.append(("execute", command, argument))
                return True

            def _cmd_eim_download(self, argument: str) -> bool:
                calls.append(("handler", "_cmd_eim_download", argument))
                return True

        monkeypatch.setattr(
            scp11_live,
            "_build_console",
            lambda reader_index: (DummyConsole(), object()),
        )

        async def collect_events() -> list[dict[str, object]]:
            events: list[dict[str, object]] = []
            async for event in scp11_live._stream_console(
                0,
                "_cmd_eim_download",
                argument="",
                connect_first=False,
                command_name="DOWNLOAD",
                done_message="done",
            ):
                events.append(event)
            return events

        events = asyncio.run(collect_events())

        assert calls == [("execute", "DOWNLOAD", "")]
        assert events[-1] == {"level": "done", "message": "done", "ok": True}

    def test_scp11_live_build_console_injects_profile_provider(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live

        @dataclass(frozen=True)
        class FakeConfig:
            READER_INDEX: int = 0

        class FakeOrchestrator:
            def __init__(self, *, cfg, apdu_channel, profile_provider=None):
                self.cfg = cfg
                self.apdu_channel = apdu_channel
                self.profile_provider = profile_provider

        class FakeConsole:
            def __init__(self, client):
                self.client = client

        provider = object()
        channel = object()

        modules = {
            "config": SimpleNamespace(SGPConfig=FakeConfig),
            "console": SimpleNamespace(SCP11Console=FakeConsole),
            "factory": SimpleNamespace(build_profile_provider=lambda cfg: provider),
            "orchestrator": SimpleNamespace(SGP22Orchestrator=FakeOrchestrator),
        }
        monkeypatch.setattr(scp11_live, "_provider_module", lambda name: modules[name])
        monkeypatch.setattr(scp11_live, "_build_apdu_channel", lambda reader_index: channel)

        console, built_channel = scp11_live._build_console(2)

        assert built_channel is channel
        assert console.client.profile_provider is provider
        assert console.client.orchestrator.profile_provider is provider
        assert console.client.cfg.READER_INDEX == 2

    def test_hil_watch_supervisor_is_streaming(self) -> None:
        registry = ensure_builtin_actions_loaded()
        spec = registry.get("hil.watch_supervisor")
        assert spec.streams is True
        assert spec.dispatcher is not None
        assert spec.output_kind == "log_stream"
        field_names = {f.name for f in spec.inputs}
        assert {"interval_ms", "cycles"}.issubset(field_names)

    def test_download_profile_is_streaming_without_dispatcher(self) -> None:
        spec = get_registry().get("scp11.download_profile")
        assert spec.streams is True
        assert spec.dispatcher is None  # delegates to /api/flows/download-profile


# ----------------------------------------------------------------------
# Offline-tool dispatchers (pure-function; no hardware, no asn1crypto)
# ----------------------------------------------------------------------


class TestEngineToolDispatchers:
    """Exercise the offline decoder/reference actions end to end.

    These dispatchers are deliberately side-effect free — they wrap the
    same helpers that back ``/api/tools/*``. Running them here guards
    against accidental drift between the two surfaces.
    """

    def _ctx(self):
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        return ActionContext()

    def test_tlv_decode_returns_tree_shape(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.tlv.decode")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"hex": "6F 05 84 03 AA BB CC"}),
        )
        assert result["complete"] is True
        assert result["input_length"] == 7
        assert result["nodes"][0]["tag_hex"] == "6F"
        # Nested constructed tag 84
        inner = result["nodes"][0]["children"][0]
        assert inner["tag_hex"] == "84"
        assert inner["value_hex"] == "AABBCC"

    def test_tlv_decode_rejects_bad_hex(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.tlv.decode")
        with pytest.raises(ValueError):
            spec.dispatcher(self._ctx(), **coerce_inputs(spec, {"hex": "not-hex"}))

    def test_asn1_tlv_decode_returns_tag_registry_result(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.asn1_tlv.decode")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"hex_text": "BF 22 03 81 01 02"}),
        )
        assert result["format"] == "BER/DER TLV"
        assert result["complete"] is True
        assert result["items"][0]["tag"] == "BF22"
        assert result["items"][0]["name"] == "EUICC_INFO_2"
        assert "asn1Notation" in result

    def test_sima_response_decode_returns_semantic_result(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.sima_response.decode")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"hex": "30 07 A0 05 30 03 80 01 00"}),
        )

        assert result["format"] == "SIMa response"
        assert result["complete"] is True
        assert result["semantic"]["choice"] == "successResult"
        assert result["semantic"]["result_code"] == 0
        assert result["nodes"][0]["label"] == "simaResponse"
        assert "successResult.resultCode=0" in result["formatted"]

    def test_sw_lookup_happy_path(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.sw.lookup")
        result = spec.dispatcher(self._ctx(), **coerce_inputs(spec, {"sw": "9000"}))
        assert result["sw_hex"] == "9000"
        assert result["sw1"] == 0x90 and result["sw2"] == 0x00
        assert isinstance(result["description"], str) and len(result["description"]) > 0

    def test_sw_lookup_rejects_wrong_length(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.sw.lookup")
        with pytest.raises(ValueError):
            spec.dispatcher(self._ctx(), **coerce_inputs(spec, {"sw": "90"}))

    def test_gsma_codes_returns_expected_tables(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.gsma.codes")
        result = spec.dispatcher(self._ctx(), **coerce_inputs(spec, {}))
        assert "tables" in result and "order" in result
        # Every ordered key must be present in the tables dict.
        assert set(result["order"]).issubset(result["tables"].keys())
        assert "download_error" in result["tables"]

    def test_eim_lint_rejects_non_json(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.eim.lint")
        with pytest.raises(ValueError):
            spec.dispatcher(
                self._ctx(),
                **coerce_inputs(spec, {"document_json": "not-json"}),
            )

    def test_eim_lint_requires_json_object_root(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("tool.eim.lint")
        with pytest.raises(ValueError):
            spec.dispatcher(
                self._ctx(),
                **coerce_inputs(spec, {"document_json": "[]"}),
            )


# ----------------------------------------------------------------------
# SCP03 reader binding helpers — no hardware, fake PC/SC enumeration.
# ----------------------------------------------------------------------


class TestScp03ReaderBinding:
    def test_default_reader_binding_uses_first_pcsc_reader(self, monkeypatch) -> None:
        import sys
        import types

        from yggdrasim_common.gui_server.actions import scp03 as scp03_mod

        class FakeReader:
            def __init__(self, name: str) -> None:
                self.name = name

            def __str__(self) -> str:
                return self.name

        system_mod = types.ModuleType("smartcard.System")
        system_mod.readers = lambda: [FakeReader("Reader A"), FakeReader("Reader B")]
        smartcard_mod = types.ModuleType("smartcard")
        smartcard_mod.__path__ = []
        smartcard_mod.System = system_mod
        monkeypatch.setitem(sys.modules, "smartcard", smartcard_mod)
        monkeypatch.setitem(sys.modules, "smartcard.System", system_mod)

        assert scp03_mod._resolve_reader_binding("") == (0, "Reader A")
        assert scp03_mod._resolve_reader_index("") == 0

    def test_named_reader_binding_uses_matching_pcsc_reader(self, monkeypatch) -> None:
        import sys
        import types

        from yggdrasim_common.gui_server.actions import scp03 as scp03_mod

        class FakeReader:
            def __init__(self, name: str) -> None:
                self.name = name

            def __str__(self) -> str:
                return self.name

        system_mod = types.ModuleType("smartcard.System")
        system_mod.readers = lambda: [FakeReader("Reader A"), FakeReader("Reader B")]
        smartcard_mod = types.ModuleType("smartcard")
        smartcard_mod.__path__ = []
        smartcard_mod.System = system_mod
        monkeypatch.setitem(sys.modules, "smartcard", smartcard_mod)
        monkeypatch.setitem(sys.modules, "smartcard.System", system_mod)

        assert scp03_mod._resolve_reader_binding("Reader B") == (1, "Reader B")
        assert scp03_mod._resolve_reader_index("Reader B") == 1


# ----------------------------------------------------------------------
# SCP03 close_session is the one session-manipulating action that can
# run without hardware — it's idempotent on unknown ids.
# ----------------------------------------------------------------------


class TestScp03CloseSessionDispatcher:
    def test_close_unknown_session_is_idempotent(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("scp03.close_session")
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        result = spec.dispatcher(
            ActionContext(),
            **coerce_inputs(spec, {"session_id": "nonexistent"}),
        )
        assert result == {"session_id": "nonexistent", "closed": False}

    def test_close_session_rejects_blank_id(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("scp03.close_session")
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        with pytest.raises(ValueError):
            spec.dispatcher(
                ActionContext(),
                **coerce_inputs(spec, {"session_id": "   "}),
            )


# ----------------------------------------------------------------------
# scp03.read_selected — payload shape
# ----------------------------------------------------------------------


class _FakeTransporter:
    """Tiny programmable stand-in for SCP03 CardTransporter.

    Consumes pre-scripted ``transmit`` responses in order. Tests must
    provide exactly as many responses as APDUs they expect the
    dispatcher to send; any extra transmit call raises so a regression
    that over-reads is caught loudly.
    """

    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def transmit(self, apdu_hex, silent=False):  # noqa: D401 — mimic prod signature
        self.sent.append(apdu_hex)
        if len(self._responses) == 0:
            raise AssertionError(
                f"_FakeTransporter ran out of scripted responses "
                f"(unexpected APDU: {apdu_hex})"
            )
        return self._responses.pop(0)


class _FakeFs:
    def __init__(self, fid="6F07", fcp=None):
        self.current_fid = fid
        self.current_fcp = dict(fcp or {})


class TestScp03ReadPayload:
    """Cover the three body branches of ``_read_payload_for_file``.

    These exercise the logic the GUI relies on when a user clicks a node
    in the scan tree: transparent files must return decoded + hex;
    record-oriented files must enumerate every record (both hex and
    decoded); DF/MF should return ``kind='none'`` and not transmit any
    READ BINARY / READ RECORD APDUs.
    """

    def test_transparent_includes_decoded_and_hex(self) -> None:
        from yggdrasim_common.gui_server.actions import scp03 as scp03_mod

        transporter = _FakeTransporter(
            responses=[(b"\x10\x20\x30\x40", 0x90, 0x00)],
        )
        fs = _FakeFs(fid="6F07", fcp={"structure": "Transparent"})

        payload = scp03_mod._read_payload_for_file(
            transporter, fs, "transparent", path="MF/ADF_USIM/EF_IMSI"
        )

        assert payload["kind"] == "transparent"
        assert payload["ok"] is True
        assert payload["sw"] == "9000"
        assert payload["hex"] == "10203040"
        assert payload["length"] == 4
        # decoded may be None (no decoder match) or a dict, but the key
        # MUST be present so the frontend can branch on it consistently.
        assert "decoded" in payload
        assert transporter.sent == ["00B0000000"]

    def test_records_enumerates_until_not_found(self) -> None:
        from yggdrasim_common.gui_server.actions import scp03 as scp03_mod

        transporter = _FakeTransporter(
            responses=[
                (b"\xDE\xAD\xBE\xEF", 0x90, 0x00),  # record 1 — non-empty
                (b"\xFF\xFF\xFF\xFF", 0x90, 0x00),  # record 2 — empty sentinel
                (b"", 0x6A, 0x83),                   # record 3 — not found
            ],
        )
        fs = _FakeFs(fid="6F3B", fcp={"structure": "Linear Fixed", "rec_len": 4})

        payload = scp03_mod._read_payload_for_file(
            transporter, fs, "linear fixed", path="MF/ADF_USIM/EF_FPLMN"
        )

        assert payload["kind"] == "records"
        assert payload["rec_len"] == 4
        assert payload["record_count"] == 3
        assert payload["non_empty_count"] == 1
        assert payload["stop_reason"] == "record_not_found"

        records = payload["records"]
        assert records[0]["record_number"] == 1
        assert records[0]["ok"] is True
        assert records[0]["hex"] == "DEADBEEF"
        assert records[0]["empty"] is False
        assert "decoded" in records[0]

        assert records[1]["record_number"] == 2
        assert records[1]["empty"] is True
        assert records[1]["decoded"] is None

        assert records[2]["record_number"] == 3
        assert records[2]["ok"] is False
        assert records[2]["sw"] == "6A83"

        # Must have read with the FCP-reported Le (0x04) for records 1-3.
        assert transporter.sent == [
            "00B2010404",
            "00B2020404",
            "00B2030404",
        ]

    def test_cyclic_also_routed_to_records(self) -> None:
        from yggdrasim_common.gui_server.actions import scp03 as scp03_mod

        transporter = _FakeTransporter(
            responses=[(b"", 0x6A, 0x83)],
        )
        fs = _FakeFs(fid="6F13", fcp={"structure": "Cyclic", "rec_len": 8})

        payload = scp03_mod._read_payload_for_file(
            transporter, fs, "cyclic", path="MF/ADF_USIM/EF_CYCLIC"
        )

        assert payload["kind"] == "records"
        assert payload["rec_len"] == 8
        assert payload["non_empty_count"] == 0
        assert payload["stop_reason"] == "record_not_found"
        # Only one transmit before we hit the 0x6A terminator.
        assert transporter.sent == ["00B2010408"]

    def test_directory_returns_none_without_transmit(self) -> None:
        from yggdrasim_common.gui_server.actions import scp03 as scp03_mod

        transporter = _FakeTransporter(responses=[])
        fs = _FakeFs(fid="7FFF", fcp={"structure": "DF"})

        payload = scp03_mod._read_payload_for_file(
            transporter, fs, "df", path="MF/ADF_USIM"
        )

        assert payload["kind"] == "none"
        assert "No binary payload" in payload["note"]
        assert transporter.sent == []


# ----------------------------------------------------------------------
# HIL bridge dispatchers (no hardware, no network)
# ----------------------------------------------------------------------


class TestHilSupervisorHelpers:
    """Cover the pure helpers that underpin ``hil.*`` dispatchers.

    These never touch PC/SC, never spawn tshark, and must be safe to run
    on a developer laptop with no HIL rig attached.
    """

    def test_summary_lines_renders_known_fields(self) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        state = {
            "status": "running",
            "reason": "usb-attached",
            "usbPresent": True,
            "usbSource": "udev",
            "bridgeRunning": True,
            "bridgePid": 4242,
            "bridgePort": 8900,
            "remsimClientEnabled": True,
            "remsimClientRunning": False,
            "remsimClientPid": 0,
            "readerIndex": 1,
            "readerName": "Identiv uTrust 3720F",
        }
        lines = hil_mod._summary_lines_from_state(state)
        keys = {line["key"] for line in lines}
        assert {
            "Status", "Reason", "USB present", "USB source",
            "Bridge running", "Bridge pid", "Bridge port",
            "REMSIM client", "Reader index",
        }.issubset(keys)
        reader_row = next(line for line in lines if line["key"] == "Reader index")
        assert "Identiv" in reader_row["value"]
        assert "1" in reader_row["value"]

    def test_summary_lines_omits_unset_optional_keys(self) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        lines = hil_mod._summary_lines_from_state({"status": "idle", "usbPresent": False})
        keys = {line["key"] for line in lines}
        assert "Status" in keys and "USB present" in keys
        # Optional fields must not appear when empty/zero.
        assert "Bridge pid" not in keys
        assert "REMSIM client" not in keys
        assert "Reader index" not in keys

    def test_diff_state_reports_initial_and_changed_fields(self) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        assert hil_mod._diff_state({}, {"status": "x"}) == ["initial snapshot"]
        diff = hil_mod._diff_state(
            {"status": "stopped", "usbPresent": False, "bridgePid": 0},
            {"status": "running", "usbPresent": True, "bridgePid": 1234},
        )
        # Each tracked-and-changed field must appear in the diff list.
        joined = " | ".join(diff)
        assert "status" in joined and "usbPresent" in joined and "bridgePid" in joined

    def test_diff_state_ignores_untracked_fields(self) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        diff = hil_mod._diff_state(
            {"status": "running"},
            {"status": "running", "someNewField": "noise"},
        )
        assert diff == []

    def test_service_options_carry_remote_card_environment(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import yggdrasim_common.card_backend as card_backend_mod
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        monkeypatch.setenv("YGGDRASIM_CARD_RELAY_URL", "http://127.0.0.1:8642/apdu")
        monkeypatch.setenv("YGGDRASIM_CARD_RELAY_TOKEN_FILE", "/tmp/card.token")
        monkeypatch.setattr(runtime_mod, "read_supervisor_state", lambda: {})
        monkeypatch.setattr(
            runtime_mod,
            "guess_bridge_python_executable",
            lambda _state, *, fallback: "/opt/ygg/bin/python3",
        )
        monkeypatch.setattr(
            runtime_mod,
            "extract_remsim_extra_args_from_supervisor_state",
            lambda _state: (),
        )
        monkeypatch.setattr(runtime_mod, "resolve_card_trace_enabled", lambda: False)
        monkeypatch.setattr(card_backend_mod, "get_card_backend", lambda: "reader")
        monkeypatch.setattr(card_backend_mod, "get_sim_isdr_config_path", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_quirks_path", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_eim_identity_path", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_euicc_store_root", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_profile_store_path", lambda: "")

        options = hil_mod._build_hil_bridge_service_options()

        assert options.remote_card_url == "http://127.0.0.1:8642/apdu"
        assert options.remote_card_token_file == "/tmp/card.token"

    def test_service_options_accept_reader_name_override(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import yggdrasim_common.card_backend as card_backend_mod
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        monkeypatch.setattr(runtime_mod, "read_supervisor_state", lambda: {"readerIndex": 7})
        monkeypatch.setattr(
            runtime_mod,
            "guess_bridge_python_executable",
            lambda _state, *, fallback: fallback,
        )
        monkeypatch.setattr(
            runtime_mod,
            "extract_remsim_extra_args_from_supervisor_state",
            lambda _state: (),
        )
        monkeypatch.setattr(runtime_mod, "resolve_card_trace_enabled", lambda: False)
        monkeypatch.setattr(card_backend_mod, "get_card_backend", lambda: "reader")
        monkeypatch.setattr(card_backend_mod, "get_sim_isdr_config_path", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_quirks_path", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_eim_identity_path", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_euicc_store_root", lambda: "")
        monkeypatch.setattr(card_backend_mod, "get_sim_profile_store_path", lambda: "")

        options = hil_mod._build_hil_bridge_service_options(
            reader_index="",
            reader_name="Reader B",
        )

        assert options.reader_index == 7
        assert options.reader_name == "Reader B"


class TestHilDispatchers:
    def _ctx(self):
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        return ActionContext()

    def test_supervisor_status_handles_missing_state_file(self, monkeypatch) -> None:
        """When no state file exists the dispatcher must still return a
        complete shape (no KeyError / no 500). The frontend branches on
        ``state_exists``."""
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        monkeypatch.setattr(
            hil_mod,
            "_load_supervisor_snapshot",
            lambda: {
                "state_path": "/tmp/does-not-exist/hil_supervisor.json",
                "state_exists": False,
                "state_mtime": 0.0,
                "state": {},
            },
        )
        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.supervisor_status")
        result = spec.dispatcher(self._ctx(), **coerce_inputs(spec, {}))
        assert result["state_exists"] is False
        assert result["state_mtime"] == 0.0
        assert isinstance(result["lines"], list) and len(result["lines"]) >= 1
        # Pretty label must include the missing-state hint.
        labels = [line["value"] for line in result["lines"]]
        assert any("supervisor" in value.lower() for value in labels)

    def test_supervisor_status_renders_lines_when_state_present(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        monkeypatch.setattr(
            hil_mod,
            "_load_supervisor_snapshot",
            lambda: {
                "state_path": "/tmp/hil_supervisor.json",
                "state_exists": True,
                "state_mtime": 1234567890.0,
                "state": {
                    "status": "running",
                    "usbPresent": True,
                    "bridgeRunning": True,
                    "bridgePid": 42,
                },
            },
        )
        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.supervisor_status")
        result = spec.dispatcher(self._ctx(), **coerce_inputs(spec, {}))
        assert result["state_exists"] is True
        assert result["state_mtime"] == 1234567890.0
        assert result["raw"]["bridgePid"] == 42
        status_row = next(line for line in result["lines"] if line["key"] == "Status")
        assert status_row["value"] == "running"

    def test_bridge_status_wraps_errors(self, monkeypatch) -> None:
        """A missing relay must surface as ``ok=False`` with the error
        captured — never as an uncaught exception."""
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        def _raise():
            raise FileNotFoundError("hil_bridge_card_relay.json")

        # The module imports ``read_bridge_status`` inside the dispatcher,
        # so patch on the runtime module (imported lazily).
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        monkeypatch.setattr(runtime_mod, "read_bridge_status", _raise)
        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.bridge_status")
        result = spec.dispatcher(self._ctx(), **coerce_inputs(spec, {}))
        assert result["ok"] is False
        assert "FileNotFoundError" in result["error"]
        assert result["raw"] == {}

    def test_bridge_status_returns_payload_on_success(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        monkeypatch.setattr(
            runtime_mod,
            "read_bridge_status",
            lambda: {"reader": "sim", "apdu_client": "connected"},
        )
        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.bridge_status")
        result = spec.dispatcher(self._ctx(), **coerce_inputs(spec, {}))
        assert result["ok"] is True
        assert result["error"] == ""
        assert result["raw"]["reader"] == "sim"

    def test_service_control_stop_clears_default_runtime_marker(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server import lifecycle
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            runtime_mod,
            "stop_user_service",
            lambda service_name: calls.append(("stop", service_name)),
        )
        monkeypatch.setattr(
            runtime_mod,
            "clear_card_relay_state",
            lambda: calls.append(("clear", "relay")),
        )
        monkeypatch.setattr(
            runtime_mod,
            "clear_supervisor_state",
            lambda: calls.append(("clear", "supervisor")),
        )
        monkeypatch.setattr(
            runtime_mod,
            "query_user_service_state",
            lambda service_name: {
                "serviceName": service_name,
                "activeState": "inactive",
            },
        )
        monkeypatch.setattr(
            lifecycle,
            "unregister_gui_service",
            lambda service_name: calls.append(("unregister", service_name)),
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.service_control")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"action": "stop", "confirm": True}),
        )

        assert result["ok"] is True
        assert ("stop", runtime_mod.DEFAULT_SERVICE_NAME) in calls
        assert ("clear", "relay") in calls
        assert ("clear", "supervisor") in calls

    def test_session_stop_clears_default_runtime_marker(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server import lifecycle
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(
            runtime_mod,
            "stop_user_service",
            lambda service_name: calls.append(("stop", service_name)),
        )
        monkeypatch.setattr(
            runtime_mod,
            "clear_card_relay_state",
            lambda: calls.append(("clear", "relay")),
        )
        monkeypatch.setattr(
            runtime_mod,
            "clear_supervisor_state",
            lambda: calls.append(("clear", "supervisor")),
        )
        monkeypatch.setattr(
            runtime_mod,
            "query_user_service_state",
            lambda service_name: {
                "serviceName": service_name,
                "activeState": "inactive",
            },
        )
        monkeypatch.setattr(
            lifecycle,
            "unregister_gui_service",
            lambda service_name: calls.append(("unregister", service_name)),
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.session_stop")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"confirm": True}),
        )

        assert result["ok"] is True
        assert ("stop", runtime_mod.DEFAULT_SERVICE_NAME) in calls
        assert ("clear", "relay") in calls
        assert ("clear", "supervisor") in calls

    def test_remote_capture_sync_ignores_stopped_tunnel(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import card_bridge as cb
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        monkeypatch.setattr(
            cb,
            "_load_remote_rig_state",
            lambda: {
                "ssh_target": "pi@example.test",
                "ssh_tunnel_pid": 0,
                "remote_gsmtap_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
            },
        )
        monkeypatch.setattr(
            hil_mod.subprocess,
            "run",
            lambda *_args, **_kwargs: (_ for _ in ()).throw(
                AssertionError("stopped tunnel should not probe remote capture")
            ),
        )

        result = hil_mod._sync_remote_decode_capture_if_available()

        assert result["configured"] is True
        assert result["ok"] is False
        assert "tunnel" in result["error"]

    def test_session_start_ignores_stale_remote_capture_when_tunnel_stopped(self, monkeypatch, tmp_path) -> None:
        from yggdrasim_common.gui_server.actions import card_bridge as cb
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        capture_path = tmp_path / "live_capture.pcap"
        calls = {}
        monkeypatch.setattr(
            cb,
            "_load_remote_rig_state",
            lambda: {
                "ssh_target": "pi@example.test",
                "ssh_tunnel_pid": 0,
                "remote_gsmtap_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
            },
        )
        monkeypatch.setattr(
            hil_mod,
            "_default_decode_capture_path",
            lambda: str(capture_path),
        )
        monkeypatch.setattr(
            runtime_mod,
            "query_user_service_state",
            lambda service_name: {"activeState": "inactive", "serviceName": service_name},
        )
        monkeypatch.setattr(runtime_mod, "read_supervisor_state", lambda: {})

        def _ensure_service(
            *,
            gsmtap_enabled=True,
            gsmtap_capture_path="",
            reader_index=None,
            reader_name=None,
        ):
            calls["ensure"] = {
                "gsmtap_enabled": gsmtap_enabled,
                "gsmtap_capture_path": gsmtap_capture_path,
                "reader_index": reader_index,
                "reader_name": reader_name,
            }
            return "/tmp/yggdrasim-hil-supervisor.service", False, "yggdrasim-hil-supervisor.service"

        def _activate_service(*, active_before, needs_restart, service_name):
            calls["activate"] = {
                "active_before": active_before,
                "needs_restart": needs_restart,
                "service_name": service_name,
            }
            return {"apduUrl": "http://127.0.0.1:9998/apdu", "reader": "local"}

        monkeypatch.setattr(hil_mod, "_ensure_hil_bridge_user_service", _ensure_service)
        monkeypatch.setattr(hil_mod, "_activate_hil_bridge_service", _activate_service)

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.session_start")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {"mode": "decoded", "reader_name": "Reader A", "reader_index": ""},
            ),
        )

        assert result["ok"] is True
        assert result["mode"] == "decoded"
        assert result["reader_name"] == "Reader A"
        assert result["status"]["reader"] == "local"
        assert calls["ensure"] == {
            "gsmtap_enabled": True,
            "gsmtap_capture_path": str(capture_path),
            "reader_index": "",
            "reader_name": "Reader A",
        }
        assert calls["activate"] == {
            "active_before": False,
            "needs_restart": False,
            "service_name": "yggdrasim-hil-supervisor.service",
        }

    def test_session_start_prepares_decoded_service(self, monkeypatch, tmp_path) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import yggdrasim_common.hil_bridge_runtime as runtime_mod

        capture_path = tmp_path / "live_capture.pcap"
        calls = {}

        monkeypatch.setattr(
            hil_mod,
            "_default_decode_capture_path",
            lambda: str(capture_path),
        )
        monkeypatch.setattr(
            runtime_mod,
            "query_user_service_state",
            lambda service_name: {"activeState": "inactive", "serviceName": service_name},
        )
        monkeypatch.setattr(runtime_mod, "read_supervisor_state", lambda: {})
        monkeypatch.setattr(
            hil_mod,
            "_sync_remote_decode_capture_if_available",
            lambda: {"configured": False, "ok": False},
        )

        def _ensure_service(
            *,
            gsmtap_enabled=True,
            gsmtap_capture_path="",
            reader_index=None,
            reader_name=None,
        ):
            calls["ensure"] = {
                "gsmtap_enabled": gsmtap_enabled,
                "gsmtap_capture_path": gsmtap_capture_path,
                "reader_index": reader_index,
                "reader_name": reader_name,
            }
            return "/tmp/yggdrasim-hil-supervisor.service", False, "yggdrasim-hil-supervisor.service"

        def _activate_service(*, active_before, needs_restart, service_name):
            calls["activate"] = {
                "active_before": active_before,
                "needs_restart": needs_restart,
                "service_name": service_name,
            }
            return {"apduUrl": "http://127.0.0.1:9998/apdu", "reader": "test"}

        monkeypatch.setattr(hil_mod, "_ensure_hil_bridge_user_service", _ensure_service)
        monkeypatch.setattr(hil_mod, "_activate_hil_bridge_service", _activate_service)

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.session_start")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"mode": "decoded"}),
        )

        assert result["ok"] is True
        assert result["mode"] == "decoded"
        assert result["capture_path"] == str(capture_path)
        assert result["gsmtap_enabled"] is True
        assert result["status"]["apduUrl"].endswith("/apdu")
        assert calls["ensure"] == {
            "gsmtap_enabled": True,
            "gsmtap_capture_path": str(capture_path),
            "reader_index": "",
            "reader_name": "",
        }
        assert calls["activate"] == {
            "active_before": False,
            "needs_restart": False,
            "service_name": "yggdrasim-hil-supervisor.service",
        }

    def test_session_start_attaches_remote_capture_when_available(self, monkeypatch, tmp_path) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        capture_path = tmp_path / "remote_live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        monkeypatch.setattr(
            hil_mod,
            "_sync_remote_decode_capture_if_available",
            lambda: {
                "configured": True,
                "ok": True,
                "capture_path": str(capture_path),
                "remote_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
                "copied": True,
            },
        )
        monkeypatch.setattr(
            hil_mod,
            "_ensure_hil_bridge_user_service",
            lambda **_kwargs: (_ for _ in ()).throw(AssertionError("local service should not start")),
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.session_start")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(spec, {"mode": "decoded"}),
        )

        assert result["ok"] is True
        assert result["mode"] == "remote"
        assert result["capture_source"] == "remote"
        assert result["capture_path"] == str(capture_path)
        assert result["note"] == "Attached to remote HIL GSMTAP capture."

    def test_context_tree_payload_splits_ota_sms_sms_and_voice_groups(self) -> None:
        from Tools.HilBridge.live_decode_view import PacketSummary
        from yggdrasim_common.gui_server.actions import hil as hil_mod

        def row(number: int, info: str) -> PacketSummary:
            return PacketSummary(
                number=number,
                time_text=f"0.{number:06d}",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info=info,
                udp_payload_hex="AA55",
            )

        context_tree = hil_mod._build_context_tree_payload(
            [
                row(1, "ENVELOPE (SMS-PP DOWNLOAD)"),
                row(2, "SMS-DELIVER TPDU"),
                row(3, "STK SET UP CALL"),
                row(4, "TERMINAL RESPONSE"),
            ],
            {},
        )

        groups = [
            (item["label"], item["frame_count"])
            for item in context_tree
            if item["kind"] == "group"
        ]
        assert groups == [
            ("OTA SMS", 1),
            ("SMS", 1),
            ("Voice", 1),
            ("STK", 1),
        ]

    def test_decode_snapshot_uses_existing_decode_helpers(self, monkeypatch, tmp_path) -> None:
        from Tools.HilBridge.live_decode_view import PacketSummary
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import Tools.HilBridge.live_decode_state as state_mod
        import Tools.HilBridge.live_decode_view as view_mod

        importlib.import_module("Tools.HilBridge.live_decode_tui")
        capture_path = tmp_path / "live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        sample_row = PacketSummary(
            number=7,
            time_text="0.000000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="FETCH",
            udp_payload_hex="AA55",
        )
        sample_annotation = SimpleNamespace(
            frame_number=7,
            summary_suffix="STK OPEN CHANNEL",
            context_lines=("poll 1",),
            active_channel_count=1,
            active_timer_count=0,
            active_timers=(),
            capture_time_seconds=None,
            channel_session_id=1,
            channel_number=1,
            channel_poll_index=1,
            state_event=True,
            card_session_index=1,
            card_session_reset_reason="",
            card_session_iccid="",
        )

        monkeypatch.setattr(
            hil_mod,
            "_resolve_decode_capture_path",
            lambda capture_path=None: str(capture_path),
        )
        monkeypatch.setattr(view_mod, "resolve_tshark_binary", lambda: "/usr/bin/tshark")
        monkeypatch.setattr(
            view_mod,
            "read_packet_summaries",
            lambda *_args, **_kwargs: ([sample_row], ""),
        )
        monkeypatch.setattr(
            view_mod,
            "read_packet_detail",
            lambda *_args, **_kwargs: ("Frame 7\n  Protocol: GSM SIM", ""),
        )
        monkeypatch.setattr(
            view_mod,
            "read_packet_hex",
            lambda *_args, **_kwargs: ("0000  AA 55", ""),
        )
        monkeypatch.setattr(
            view_mod,
            "read_packet_field_ranges",
            lambda *_args, **_kwargs: (
                [
                    {
                        "name": "gsm_sim.apdu",
                        "label": "APDU: AA 55",
                        "start": 0,
                        "end": 2,
                        "size": 2,
                        "depth": 1,
                    }
                ],
                "",
            ),
        )
        monkeypatch.setattr(
            state_mod,
            "build_stateful_packet_annotations",
            lambda *_args, **_kwargs: {7: sample_annotation},
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.decode_snapshot")
        limit_field = next(field for field in spec.inputs if field.name == "limit")
        assert limit_field.default == 5000
        assert limit_field.max_value == 5000
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {
                    "capture_path": str(capture_path),
                    "selected_frame": "7",
                    "limit": "10",
                },
            ),
        )

        assert result["ok"] is True
        assert result["capture_path"] == str(capture_path)
        assert result["row_count"] == 1
        assert result["selected_frame"] == 7
        assert result["rows"][0]["info"] == "FETCH"
        assert "STK OPEN CHANNEL" in result["rows"][0]["annotated_info"]
        assert result["annotations"]["7"]["channel_poll_index"] == 1
        assert [
            (item["kind"], item["depth"], item.get("label"), item.get("frame_number"))
            for item in result["context_tree"]
        ] == [
            ("poll_group", 0, "Poll", None),
            ("poll", 1, "Poll 1", None),
            ("poll_target", 2, "Target 1", None),
            ("session", 3, "DNS", None),
            ("frame", 4, None, 7),
        ]
        assert result["detail"].startswith("Frame 7")
        assert result["bytes"].startswith("0000")
        assert result["detail_ranges"][0]["name"] == "gsm_sim.apdu"

    def test_decode_snapshot_incremental_annotations_use_full_context(self, monkeypatch, tmp_path) -> None:
        from Tools.HilBridge.live_decode_view import PacketSummary
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import Tools.HilBridge.live_decode_state as state_mod
        import Tools.HilBridge.live_decode_view as view_mod

        capture_path = tmp_path / "live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        rows = [
            PacketSummary(
                number=1,
                time_text="0.000001",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info="SELECT",
                udp_payload_hex="AA55",
            ),
            PacketSummary(
                number=2,
                time_text="0.000002",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info="FETCH",
                udp_payload_hex="AA55",
            ),
            PacketSummary(
                number=3,
                time_text="0.000003",
                source="127.0.0.1",
                destination="127.0.0.1",
                protocol="GSM SIM",
                length_text="80",
                info="READ BINARY",
                udp_payload_hex="AA55",
            ),
        ]
        summary_after_frames: list[int | None] = []
        annotation_row_numbers: list[int] = []

        def fake_read_packet_summaries(*_args, **kwargs):
            summary_after_frames.append(kwargs.get("after_frame"))
            return rows, ""

        def fake_build_annotations(annotation_rows, **_kwargs):
            annotation_row_numbers.extend(int(row.number) for row in annotation_rows)
            return {
                3: SimpleNamespace(
                    frame_number=3,
                    summary_suffix="FS MF/EF READ BINARY",
                    context_lines=("FS MF/EF",),
                    active_channel_count=0,
                    active_timer_count=0,
                    active_timers=(),
                    capture_time_seconds=None,
                    channel_session_id=None,
                    channel_number=None,
                    channel_poll_index=None,
                    state_event=True,
                    card_session_index=1,
                    card_session_reset_reason="",
                    card_session_iccid="",
                )
            }

        monkeypatch.setattr(
            hil_mod,
            "_resolve_decode_capture_path",
            lambda capture_path=None: str(capture_path),
        )
        monkeypatch.setattr(view_mod, "resolve_tshark_binary", lambda: "/usr/bin/tshark")
        monkeypatch.setattr(view_mod, "read_packet_summaries", fake_read_packet_summaries)
        monkeypatch.setattr(
            state_mod,
            "build_stateful_packet_annotations",
            fake_build_annotations,
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.decode_snapshot")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {
                    "capture_path": str(capture_path),
                    "include_detail": False,
                    "include_annotations": True,
                    "after_frame": "2",
                    "context_after_frame": "1",
                    "limit": "10",
                },
            ),
        )

        assert summary_after_frames == [None]
        assert annotation_row_numbers == [1, 2, 3]
        assert [row["number"] for row in result["rows"]] == [3]
        assert "1" not in result["annotations"]
        assert "2" in result["annotations"]
        assert result["annotations"]["3"]["summary_suffix"] == "FS MF/EF READ BINARY"
        context_frames = [
            item["frame_number"]
            for item in result["context_tree"]
            if item["kind"] == "frame"
        ]
        assert context_frames == [2, 3]
        assert any(
            item["kind"] == "group" and item["label"] == "ETSI FS"
            for item in result["context_tree"]
        )
        assert result["incremental"] is True
        assert result["after_frame"] == 2

    def test_decode_snapshot_uses_remote_rig_capture_when_available(self, monkeypatch, tmp_path) -> None:
        from Tools.HilBridge.live_decode_view import PacketSummary
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import Tools.HilBridge.live_decode_state as state_mod
        import Tools.HilBridge.live_decode_view as view_mod

        capture_path = tmp_path / "remote_live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        sample_row = PacketSummary(
            number=3,
            time_text="0.000000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="SELECT",
            udp_payload_hex="AA55",
        )

        monkeypatch.setattr(
            hil_mod,
            "_sync_remote_decode_capture_if_available",
            lambda: {
                "configured": True,
                "ok": True,
                "capture_path": str(capture_path),
                "remote_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
                "copied": True,
            },
        )
        monkeypatch.setattr(view_mod, "resolve_tshark_binary", lambda: "/usr/bin/tshark")
        monkeypatch.setattr(
            view_mod,
            "read_packet_summaries",
            lambda *_args, **_kwargs: ([sample_row], ""),
        )
        monkeypatch.setattr(
            state_mod,
            "build_stateful_packet_annotations",
            lambda *_args, **_kwargs: {},
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.decode_snapshot")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {
                    "include_detail": False,
                    "limit": "10",
                },
            ),
        )

        assert result["ok"] is True
        assert result["capture_source"] == "remote"
        assert result["capture_path"] == str(capture_path)
        assert result["remote_capture"]["remote_capture_path"].endswith("live_capture.pcap")
        assert result["rows"][0]["info"] == "SELECT"

    def test_decode_snapshot_can_skip_detail(self, monkeypatch, tmp_path) -> None:
        from Tools.HilBridge.live_decode_view import PacketSummary
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import Tools.HilBridge.live_decode_state as state_mod
        import Tools.HilBridge.live_decode_view as view_mod

        capture_path = tmp_path / "live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        sample_row = PacketSummary(
            number=7,
            time_text="0.000000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="FETCH",
            udp_payload_hex="AA55",
        )
        detail_calls = []
        hex_calls = []

        monkeypatch.setattr(
            hil_mod,
            "_resolve_decode_capture_path",
            lambda capture_path=None: str(capture_path),
        )
        monkeypatch.setattr(view_mod, "resolve_tshark_binary", lambda: "/usr/bin/tshark")
        monkeypatch.setattr(
            view_mod,
            "read_packet_summaries",
            lambda *_args, **_kwargs: ([sample_row], ""),
        )
        monkeypatch.setattr(
            view_mod,
            "read_packet_detail",
            lambda *_args, **_kwargs: detail_calls.append(True) or ("", ""),
        )
        monkeypatch.setattr(
            view_mod,
            "read_packet_hex",
            lambda *_args, **_kwargs: hex_calls.append(True) or ("", ""),
        )
        monkeypatch.setattr(
            view_mod,
            "read_packet_field_ranges",
            lambda *_args, **_kwargs: detail_calls.append("ranges") or ([], ""),
        )
        monkeypatch.setattr(
            state_mod,
            "build_stateful_packet_annotations",
            lambda *_args, **_kwargs: {},
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.decode_snapshot")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {
                    "capture_path": str(capture_path),
                    "selected_frame": "7",
                    "include_detail": False,
                    "limit": "10",
                },
            ),
        )

        assert result["ok"] is True
        assert result["include_detail"] is False
        assert result["selected_frame"] == 7
        assert result["detail"] == ""
        assert result["bytes"] == ""
        assert result["detail_ranges"] == []
        assert detail_calls == []
        assert hex_calls == []

    def test_decode_snapshot_exposes_raw_apdu_directions(self, monkeypatch, tmp_path) -> None:
        from Tools.HilBridge.live_decode_view import PacketSummary
        from Tools.HilBridge.protocol import (
            GSMTAP_SIM_APDU,
            build_gsmtap_packet,
            build_simtrace_apdu_payload,
        )
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import Tools.HilBridge.live_decode_state as state_mod
        import Tools.HilBridge.live_decode_view as view_mod

        capture_path = tmp_path / "live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        udp_payload_hex = build_gsmtap_packet(
            build_simtrace_apdu_payload(
                bytes.fromhex("00A40000023F00"),
                bytes.fromhex("9000"),
            ),
            subtype=GSMTAP_SIM_APDU,
            uplink=True,
        ).hex().upper()
        sample_row = PacketSummary(
            number=7,
            time_text="0.000000",
            source="127.0.0.1",
            destination="127.0.0.1",
            protocol="GSM SIM",
            length_text="80",
            info="SELECT",
            udp_payload_hex=udp_payload_hex,
        )

        monkeypatch.setattr(
            hil_mod,
            "_resolve_decode_capture_path",
            lambda capture_path=None: str(capture_path),
        )
        monkeypatch.setattr(view_mod, "resolve_tshark_binary", lambda: "/usr/bin/tshark")
        monkeypatch.setattr(
            view_mod,
            "read_packet_summaries",
            lambda *_args, **_kwargs: ([sample_row], ""),
        )
        monkeypatch.setattr(
            state_mod,
            "build_stateful_packet_annotations",
            lambda *_args, **_kwargs: {},
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.decode_snapshot")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {
                    "capture_path": str(capture_path),
                    "include_detail": False,
                    "limit": "10",
                },
            ),
        )

        row = result["rows"][0]
        assert row["gsmtap_uplink"] is True
        assert row["apdu_command_hex"] == "00A40000023F00"
        assert row["apdu_response_hex"] == "9000"

    def test_decode_snapshot_skips_tshark_when_capture_unchanged(self, monkeypatch, tmp_path) -> None:
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        import Tools.HilBridge.live_decode_view as view_mod

        capture_path = tmp_path / "live_capture.pcap"
        capture_path.write_bytes(b"0" * 64)
        stat_result = capture_path.stat()
        summary_calls = []

        monkeypatch.setattr(
            hil_mod,
            "_resolve_decode_capture_path",
            lambda capture_path=None: str(capture_path),
        )
        monkeypatch.setattr(view_mod, "resolve_tshark_binary", lambda: "/usr/bin/tshark")
        monkeypatch.setattr(
            view_mod,
            "read_packet_summaries",
            lambda *_args, **_kwargs: summary_calls.append(True) or ([], ""),
        )

        ensure_builtin_actions_loaded()
        spec = get_registry().get("hil.decode_snapshot")
        result = spec.dispatcher(
            self._ctx(),
            **coerce_inputs(
                spec,
                {
                    "capture_path": str(capture_path),
                    "include_detail": False,
                    "known_capture_size": str(stat_result.st_size),
                    "known_capture_mtime": str(stat_result.st_mtime),
                },
            ),
        )

        assert result["ok"] is True
        assert result["not_modified"] is True
        assert result["rows"] == []
        assert summary_calls == []


class TestHilWatchSupervisorStream:
    """Exercise the async generator so we catch shape regressions without
    wiring up a FastAPI websocket client."""

    def test_emits_start_cycle_and_done_events(self, monkeypatch) -> None:
        import asyncio
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        monkeypatch.setattr(
            hil_mod,
            "_load_supervisor_snapshot",
            lambda: {
                "state_path": "/tmp/hil_supervisor.json",
                "state_exists": True,
                "state_mtime": 1.0,
                "state": {"status": "idle", "usbPresent": False},
            },
        )

        async def _drive():
            events = []
            async for event in hil_mod._dispatch_watch_supervisor(
                ActionContext(),
                interval_ms=100,
                cycles=2,
            ):
                events.append(event)
            return events

        events = asyncio.run(_drive())
        assert len(events) == 4  # start + 2 cycles + done
        assert events[0]["level"] == "info"
        assert "starting supervisor watcher" in events[0]["message"]
        assert events[1]["level"] == "info" and "cycle 1/2" in events[1]["message"]
        assert events[2]["level"] == "info" and "cycle 2/2" in events[2]["message"]
        assert events[-1]["level"] == "done"
        assert "final_state" in events[-1]

    def test_floors_interval_and_cycles(self, monkeypatch) -> None:
        """interval_ms < 100 must clamp to 100; cycles <= 0 must clamp to 1."""
        import asyncio
        from yggdrasim_common.gui_server.actions import hil as hil_mod
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        monkeypatch.setattr(
            hil_mod,
            "_load_supervisor_snapshot",
            lambda: {
                "state_path": "/tmp/hil_supervisor.json",
                "state_exists": False,
                "state_mtime": 0.0,
                "state": {},
            },
        )

        async def _drive():
            events = []
            async for event in hil_mod._dispatch_watch_supervisor(
                ActionContext(),
                interval_ms=0,
                cycles=0,
            ):
                events.append(event)
            return events

        events = asyncio.run(_drive())
        # Clamped to 1 cycle: expect start + 1 cycle + done = 3 events.
        assert len(events) == 3
        assert "interval_ms=100" in events[0]["message"]
        assert "cycles=1" in events[0]["message"]


# ----------------------------------------------------------------------
# SCP11 live helpers (pure decoders — no reader, no orchestrator)
# ----------------------------------------------------------------------


class TestScp11LiveDecoders:
    """Exercise the pure TLV-decoding helpers that back the SCP11 live
    actions. These never touch PC/SC; they just process bytes."""

    def test_swap_nibbles_handles_empty_and_odd(self) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod

        assert live_mod._swap_nibbles("") == ""
        assert live_mod._swap_nibbles("98") == "89"
        # BCD ICCID sample with 0xF padding nibble preserved as swap+strip.
        out = live_mod._swap_nibbles("9814203201654321F7")
        assert isinstance(out, str) and len(out) > 0

    def test_strip_ansi_removes_escape_sequences(self) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod

        text = "\x1b[31mRED\x1b[0m normal"
        assert live_mod._strip_ansi(text) == "RED normal"

    def test_decode_profile_entry_parses_e3_payload(self) -> None:
        """Feed a minimal E3 ProfileInfo TLV and check the decoded row."""
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod

        # Hand-assembled BER-TLV:
        #   5A 0A 98 14 20 32 01 65 43 21 F7 00  — ICCID (BCD)
        #   9F70 01 01                           — state = 0x01 (ENABLED)
        #   95 01 02                             — class = 0x02 (OPER)
        #   90 04 54 45 53 54                    — nickname 'TEST'
        iccid_tlv = bytes.fromhex("5A0A98142032016543 21F700".replace(" ", ""))
        state_tlv = bytes.fromhex("9F700101")
        class_tlv = bytes.fromhex("950102")
        name_tlv = bytes.fromhex("900454455354")
        body = iccid_tlv + state_tlv + class_tlv + name_tlv

        row = live_mod._decode_profile_entry(body)
        assert row["state"] == "ENABLED"
        assert row["profile_class"] == "OPER"
        assert row["nickname"] == "TEST"
        assert len(row["iccid"]) > 0
        assert len(row["iccid_raw_hex"]) > 0

    def test_decode_profile_entry_disabled_state(self) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod

        # state = 0x00 → DISABLED, class defaults to OPER when tag absent.
        iccid_tlv = bytes.fromhex("5A0A98142032016543 21F700".replace(" ", ""))
        state_tlv = bytes.fromhex("9F700100")
        row = live_mod._decode_profile_entry(iccid_tlv + state_tlv)
        assert row["state"] == "DISABLED"
        assert row["profile_class"] == "OPER"

    def test_decode_profile_entry_rejects_unparsable_bytes(self) -> None:
        """Gracefully degrade on junk: no exception, raw_hex preserved."""
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod

        junk = bytes.fromhex("DEADBEEF")
        row = live_mod._decode_profile_entry(junk)
        # Either fully decoded (TlvParser tolerates short inputs) or raw-hex
        # fallback; both are acceptable — the contract is "never raise".
        assert isinstance(row, dict)
        assert "iccid" in row

    def test_scan_dispatch_uses_start_snapshot_bootstrap(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        calls: list[str] = []

        class Profile:
            iccid = "8988000000000000001"
            aid = "A0000005591010FFFFFFFF8900001200"
            state = "ENABLED"
            profile_class = "OPER"
            nickname = "Primary"

        class Console:
            def _collect_snapshot(self):
                raise AssertionError("raw snapshot collector should not run")

            def _collect_start_snapshot(self):
                calls.append("start")
                return SimpleNamespace(
                    eid="89049032111100000000000000000001",
                    issuer_number="89049032",
                    issuer_name="TestIssuer",
                    profiles=[Profile()],
                    notification_count=1,
                    euicc_info2_summary={"profile_version": "v2.3.1 (020301)"},
                    eim_summary={
                        "entries": [
                            {
                                "eim_fqdn": "eim.example.test",
                                "eim_id": "1.3.6.1.4.1.53375.1.5.1.1",
                            }
                        ]
                    },
                    configured_decoded={
                        "default_smdp": "smdp.example.test",
                        "root_smds_primary": "root-smds.example.test",
                    },
                )

        def fake_run_console_callable(reader_index, work, *, connect_first=True):
            assert reader_index == 3
            assert connect_first is False
            return work(Console()), "trace"

        monkeypatch.setattr(live_mod, "_resolve_reader_index", lambda reader: 3)
        monkeypatch.setattr(live_mod, "_run_console_callable", fake_run_console_callable)

        result = live_mod._dispatch_scan(ActionContext(), reader="Reader A")

        assert calls == ["start"]
        assert result["reader_index"] == 3
        assert result["snapshot"]["eid"] == "89049032111100000000000000000001"
        assert result["snapshot"]["profiles"][0]["aid"] == "A0000005591010FFFFFFFF8900001200"
        assert result["snapshot"]["configured_decoded"]["default_smdp"] == "smdp.example.test"
        assert result["trace"] == "trace"


class TestScp80ReaderBinding:
    def test_show_config_uses_selected_reader_for_protocol_summary(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import scp80 as scp80_mod
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        class DummyConfig:
            def __init__(self) -> None:
                self.data = {
                    "transport": "reader",
                    "reader_idx": "0",
                    "counter": "1",
                    "kic": "15",
                    "kid": "15",
                }
                self.active_iccid = ""
                self.file_path = Path("/tmp/ota_config.ini")

            def get(self, key: str) -> str:
                return str(self.data.get(key, ""))

        class DummyTransport:
            def __init__(self, config: DummyConfig) -> None:
                self.config = config
                self.disconnected = False

            def get_protocol_summary(self) -> dict[str, object]:
                return {
                    "available": True,
                    "active_protocol": "T=1",
                    "reader_idx": self.config.data["reader_idx"],
                }

            def disconnect(self) -> None:
                self.disconnected = True

        config = DummyConfig()
        monkeypatch.setattr(scp80_mod, "_load_config", lambda: config)
        monkeypatch.setattr(
            scp80_mod,
            "_build_transport",
            lambda active_config: DummyTransport(active_config),
        )
        monkeypatch.setattr(
            scp80_mod,
            "_resolve_reader_index_from_name",
            lambda reader_name: 2 if reader_name == "Reader B" else -1,
        )

        result = scp80_mod._dispatch_show_config(ActionContext(), reader="Reader B")

        assert result["reader_index"] == 2
        assert result["reader_name"] == "Reader B"
        assert config.data["reader_idx"] == "2"
        assert result["protocol"]["reader_idx"] == "2"


class TestScp11LiveRegistration:
    """Every live action must declare the short-lived (not streaming),
    card-requiring contract — otherwise the frontend routes it wrong."""

    def test_all_live_actions_are_short_lived_with_card(self) -> None:
        ensure_builtin_actions_loaded()
        live_ids = (
            "scp11_live.get_eid",
            "scp11_live.list_profiles",
            "scp11_live.get_smdp",
            "scp11_live.list_notifications",
            "scp11_live.euicc_info2",
        )
        for action_id in live_ids:
            spec = get_registry().get(action_id)
            assert spec.streams is False, f"{action_id} must not stream"
            assert spec.requires_card is True, f"{action_id} must require a card"
            assert spec.dispatcher is not None, f"{action_id} missing dispatcher"
            assert spec.subsystem == "eSIM Management"

    def test_get_metadata_target_is_optional_all_profiles_default(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("scp11_live.get_metadata")
        target = next(field for field in spec.inputs if field.name == "target")
        assert target.required is False
        assert target.default == ""
        assert "ALL" in target.help
        assert "ISD-P AID" in target.help

    def test_read_metadata_action_is_get_all_worded(self) -> None:
        ensure_builtin_actions_loaded()
        spec = get_registry().get("scp11_live.read_metadata")
        assert spec.title == "Get all profile metadata"

    def test_get_metadata_blank_target_dispatches_all_profiles(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.actions import scp11_live as live_mod
        from yggdrasim_common.gui_server.actions.registry import ActionContext

        class Entry:
            iccid = "8988000000000000001"
            aid = "A0000005591010FFFFFFFF8900001100"
            state = "ENABLED"
            profile_class = "OPER"
            nickname = "Primary"
            service_provider = "Example"
            profile_name = "Example Profile"
            profile_policy_rules_hex = ""
            additional_fields: list[tuple[str, str]] = []

        class Console:
            def _collect_profile_metadata(self) -> list[Entry]:
                return [Entry()]

        def fake_run_console_callable(reader_index, work):
            return work(Console()), "trace"

        monkeypatch.setattr(live_mod, "_resolve_reader_index", lambda reader: 0)
        monkeypatch.setattr(live_mod, "_run_console_callable", fake_run_console_callable)

        result = live_mod._dispatch_get_metadata(ActionContext(), reader="", target="")

        assert result["mode"] == "all"
        assert result["target"] == "ALL"
        assert result["count"] == 1
        assert result["rows"][0]["aid"] == "A0000005591010FFFFFFFF8900001100"


# ----------------------------------------------------------------------
# Session manager
# ----------------------------------------------------------------------


class TestSessionManager:
    def test_open_and_claim(self) -> None:
        mgr = sessions_module.SessionManager()
        closed: list[int] = []
        session = mgr.open(
            kind="demo",
            handle={"value": 42},
            close=lambda: closed.append(1),
        )
        assert mgr.has(session.id)
        assert mgr.claim(session.id) == {"value": 42}
        assert closed == []

    def test_close_invokes_closer(self) -> None:
        mgr = sessions_module.SessionManager()
        flag: list[int] = []
        session = mgr.open(kind="demo", handle=None, close=lambda: flag.append(1))
        assert mgr.close(session.id) is True
        assert flag == [1]
        assert not mgr.has(session.id)

    def test_idle_reap_closes_expired_sessions(self) -> None:
        mgr = sessions_module.SessionManager(default_idle_timeout_s=0.0)
        closed: list[int] = []
        mgr.open(kind="demo", handle=None, close=lambda: closed.append(1))
        count = mgr.reap_idle()
        assert count == 1
        assert closed == [1]

    def test_cap_evicts_oldest(self) -> None:
        mgr = sessions_module.SessionManager(max_sessions=2, default_idle_timeout_s=600)
        closed: list[str] = []
        first = mgr.open(kind="a", handle=None, close=lambda: closed.append("first"))
        mgr.open(kind="b", handle=None, close=lambda: closed.append("second"))
        mgr.open(kind="c", handle=None, close=lambda: closed.append("third"))
        assert not mgr.has(first.id)
        assert closed == ["first"]


# ----------------------------------------------------------------------
# GUI lifecycle cleanup
# ----------------------------------------------------------------------


class TestGuiLifecycle:
    def test_cleanup_closes_sessions_and_registered_subprocess(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server import lifecycle

        lifecycle._reset_for_tests()
        sessions_module.get_manager().close_all()
        closed: list[str] = []
        sessions_module.get_manager().open(
            kind="demo",
            handle=None,
            close=lambda: closed.append("session"),
        )

        class FakeProcess:
            pid = 12345

            def __init__(self) -> None:
                self.running = True

            def poll(self):
                return None if self.running else 0

            def wait(self, timeout=None):
                self.running = False
                return 0

        signals: list[int] = []
        fake = FakeProcess()
        monkeypatch.setattr(
            lifecycle,
            "_send_process_signal",
            lambda process, signum: signals.append(signum),
        )
        lifecycle.register_gui_subprocess("demo", fake)

        summary = lifecycle.cleanup_gui_runtime(
            stop_external_services=True,
            include_default_hil_service=False,
        )

        assert closed == ["session"]
        assert summary["closed_sessions"] == 1
        assert summary["terminated_processes"][0]["pid"] == 12345
        assert summary["terminated_processes"][0]["status"] == "terminated"
        assert len(signals) == 1

    def test_cleanup_stops_registered_and_default_hil_services(self, monkeypatch) -> None:
        from yggdrasim_common import hil_bridge_runtime
        from yggdrasim_common.gui_server import lifecycle

        lifecycle._reset_for_tests()
        stopped: list[str] = []
        cleared: list[str] = []

        monkeypatch.setattr(
            hil_bridge_runtime,
            "query_user_service_state",
            lambda service_name: {
                "serviceName": service_name,
                "activeState": "active",
            },
        )
        monkeypatch.setattr(
            hil_bridge_runtime,
            "stop_user_service",
            lambda service_name: stopped.append(service_name),
        )
        monkeypatch.setattr(
            hil_bridge_runtime,
            "clear_card_relay_state",
            lambda: cleared.append("relay"),
        )
        monkeypatch.setattr(
            hil_bridge_runtime,
            "clear_supervisor_state",
            lambda: cleared.append("supervisor"),
        )

        lifecycle.register_gui_service("custom-hil.service")
        summary = lifecycle.cleanup_gui_runtime(
            stop_external_services=True,
            include_default_hil_service=True,
        )

        assert "custom-hil.service" in stopped
        assert hil_bridge_runtime.DEFAULT_SERVICE_NAME in stopped
        assert cleared == ["relay", "supervisor"]
        assert {row["status"] for row in summary["services"]} == {"stopped"}

    def test_shutdown_adapter_requests_external_cleanup(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server import app as app_module
        from yggdrasim_common.gui_server import lifecycle

        calls: list[dict[str, bool]] = []
        monkeypatch.setattr(
            lifecycle,
            "cleanup_gui_runtime",
            lambda **kwargs: calls.append(dict(kwargs)) or {
                "closed_sessions": 0,
                "terminated_processes": [],
                "services": [],
            },
        )

        app_module._cleanup_gui_runtime_on_shutdown(include_default_hil_service=True)

        assert calls == [{
            "stop_external_services": True,
            "include_default_hil_service": True,
            "include_card_bridge_state": True,
        }]

    def test_create_app_registers_shutdown_cleanup(self, monkeypatch) -> None:
        try:
            import fastapi  # noqa: F401
        except ImportError:
            pytest.skip("FastAPI not installed")

        from yggdrasim_common.gui_server import app as app_module
        from yggdrasim_common.gui_server.config import GuiServerConfig, MODE_DESKTOP

        calls: list[bool] = []
        monkeypatch.setattr(
            app_module,
            "_cleanup_gui_runtime_on_shutdown",
            lambda *, include_default_hil_service: calls.append(include_default_hil_service),
        )

        app = app_module.create_app(
            GuiServerConfig(
                mode=MODE_DESKTOP,
                host="127.0.0.1",
                port=0,
                token="x" * 32,
            )
        )

        shutdown_handlers = getattr(getattr(app, "router", None), "on_shutdown", [])
        assert len(shutdown_handlers) >= 1
        shutdown_handlers[-1]()
        assert calls == [True]


# ----------------------------------------------------------------------
# HTTP / WS — only when the GUI stack is present
# ----------------------------------------------------------------------


_FASTAPI_AVAILABLE = True
try:  # pragma: no cover — the import itself is under test
    import fastapi as _fastapi  # noqa: F401
    import starlette as _starlette  # noqa: F401
except ImportError:
    _FASTAPI_AVAILABLE = False


_needs_gui_stack = pytest.mark.skipif(
    not _FASTAPI_AVAILABLE,
    reason="FastAPI / Starlette not installed — gui extra missing.",
)


def _build_test_app(token: str = "test-token"):
    from fastapi import FastAPI
    from yggdrasim_common.gui_server.routes import actions as actions_routes

    app = FastAPI()
    app.state.gui_token = token
    app.include_router(actions_routes.router)
    return app


def _make_client(token: str = "test-token"):
    from fastapi.testclient import TestClient

    return TestClient(_build_test_app(token))


@_needs_gui_stack
class TestCatalogueRoute:
    def test_catalogue_lists_all_bundled_specs(self) -> None:
        with _make_client() as client:
            resp = client.get("/api/actions")
        assert resp.status_code == 200
        payload = resp.json()
        assert payload["count"] >= 4
        flat_ids = []
        for group in payload["subsystems"].values():
            for entry in group:
                flat_ids.append(entry["id"])
        assert "scp03.scan" in flat_ids
        assert "scp11.download_profile" in flat_ids


@_needs_gui_stack
class TestRunRoute:
    def test_unknown_action_returns_404(self) -> None:
        with _make_client() as client:
            resp = client.post("/api/actions/does.not.exist/run", json={"inputs": {}})
        assert resp.status_code == 404

    def test_streaming_action_refuses_sync_run(self) -> None:
        with _make_client() as client:
            resp = client.post(
                "/api/actions/scp11.download_profile/run",
                json={"inputs": {}},
            )
        assert resp.status_code == 400
        assert "streaming" in resp.json()["detail"].lower()

    def test_read_selected_rejects_missing_session(self) -> None:
        with _make_client() as client:
            resp = client.post(
                "/api/actions/scp03.read_selected/run",
                json={"inputs": {"session_id": "deadbeef", "path": "MF"}},
            )
        # The dispatcher should surface a clean 200 with ok=False rather
        # than 500, because "unknown session" is a user-input error.
        assert resp.status_code == 200
        body = resp.json()
        assert body["ok"] is False
        assert "deadbeef" in (body.get("error") or "")

    def test_validation_error_surfaces_as_422(self) -> None:
        with _make_client() as client:
            resp = client.post(
                "/api/actions/scp03.read_selected/run",
                json={"inputs": {}},  # both required fields missing
            )
        assert resp.status_code == 422

    def test_missing_file_surfaces_without_server_traceback(self, monkeypatch) -> None:
        from yggdrasim_common.gui_server.routes import actions as actions_routes

        def _missing_file(ctx):
            return {"ok": True}

        async def _raise_missing_file(spec, ctx, coerced):
            raise FileNotFoundError("not a file: /tmp/missing.saip")

        registry = ActionRegistry()
        registry.register(
            ActionSpec(
                id="demo.missing_file",
                subsystem="demo",
                title="Missing file",
                description="exercise FileNotFoundError handling",
                dispatcher=_missing_file,
            )
        )
        monkeypatch.setattr(actions_routes, "ensure_builtin_actions_loaded", lambda: registry)
        monkeypatch.setattr(actions_routes, "_invoke_dispatcher", _raise_missing_file)

        response = asyncio.run(
            actions_routes.run_action(
                "demo.missing_file",
                actions_routes.RunRequest(inputs={}),
            )
        )

        assert response.ok is False
        assert response.action_id == "demo.missing_file"
        assert "not a file" in (response.error or "")


@_needs_gui_stack
class TestStreamingGate:
    def test_external_endpoint_closes_with_policy_violation(self) -> None:
        # ``scp11.download_profile`` is streaming but has no dispatcher —
        # it delegates to /api/flows/download-profile. Connecting to the
        # generic streaming route should fail fast with an 'external-endpoint'
        # reason. We just assert the connection is torn down.
        with _make_client() as client:
            with pytest.raises(Exception):
                with client.websocket_connect(
                    "/api/actions/scp11.download_profile/stream?t=test-token"
                ) as ws:
                    ws.receive_text()

    def test_unauthenticated_ws_rejected(self) -> None:
        with _make_client() as client:
            with pytest.raises(Exception):
                with client.websocket_connect(
                    "/api/actions/eim_local.hotfolder_campaign/stream"
                ) as ws:
                    ws.receive_text()


@_needs_gui_stack
class TestSessionsRoutes:
    def test_list_sessions_is_json(self) -> None:
        with _make_client() as client:
            resp = client.get("/api/sessions")
        assert resp.status_code == 200
        body = resp.json()
        assert "count" in body and "sessions" in body

    def test_close_unknown_session_returns_404(self) -> None:
        with _make_client() as client:
            resp = client.delete("/api/sessions/does-not-exist")
        assert resp.status_code == 404
