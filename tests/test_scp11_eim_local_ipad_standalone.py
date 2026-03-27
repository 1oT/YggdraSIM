import contextlib
import io
import unittest
from types import SimpleNamespace

from SCP11.eim_local.ipad_standalone import (
    LocalizedIPAdRunner,
    LocalizedRelayApduChannel,
    StandaloneDependencyError,
    build_default_session,
)


class _FakeSession:
    def __init__(self) -> None:
        self.cfg = SimpleNamespace(READER_INDEX=0)
        self.state = SimpleNamespace(session_open=True)
        self.audit_events: list[dict[str, object]] = []
        self.close_calls = 0

    def close_session(self) -> None:
        self.close_calls += 1
        self.state.session_open = False

    def _read_card_eid_safe(self) -> str:
        return "89049032000000000000000000000001"

    def _resolve_runtime_smdp_address(self, _: dict[str, object]) -> str:
        return ""

    def record_poll_audit_event(self, **kwargs) -> None:
        self.audit_events.append(kwargs)


class _FakeBridge:
    def __init__(self) -> None:
        self.eim_base_url = "https://127.0.0.1:18443"
        self.smdp_base_url = "https://127.0.0.1:19443"
        self.smdp_fqdn = "yggdrasim.smdpp.test.1ot.com"
        self.start_calls = 0
        self.reset_calls = 0
        self.flow = ""
        self.flow_run_id = ""
        self.eid = ""

    def start(self) -> None:
        self.start_calls += 1

    def reset_runtime_state(self) -> None:
        self.reset_calls += 1

    def set_flow_context(self, flow: str, flow_run_id: str = "", eid: str = "") -> None:
        self.flow = flow
        self.flow_run_id = flow_run_id
        self.eid = eid

    def status_payload(self) -> dict[str, object]:
        return {
            "queue_index": 2,
            "pending_package_path": "fixtures/020_profile.json",
            "ack_count": 3,
        }


class _FakeApduChannel:
    def __init__(self) -> None:
        self.close_calls = 0
        self.raw_apdu_logging = True
        self.raw_logging_updates: list[bool] = []
        self.send_calls: list[tuple[str, bytes]] = []
        self.exchange_calls: list[tuple[str, bytes]] = []

    def close(self) -> None:
        self.close_calls += 1

    def set_raw_apdu_logging(self, enabled: bool) -> None:
        self.raw_apdu_logging = bool(enabled)
        self.raw_logging_updates.append(bool(enabled))

    def get_raw_apdu_logging(self) -> bool:
        return bool(self.raw_apdu_logging)

    def send(self, apdu: bytes, log_name: str) -> bytes:
        self.send_calls.append((log_name, bytes(apdu)))
        return b"\x90\x00"

    def exchange(self, apdu: bytes, log_name: str):
        self.exchange_calls.append((log_name, bytes(apdu)))
        return b"", 0x90, 0x00


class _FakeOrchestrator:
    def __init__(self) -> None:
        self.apdu_channel = _FakeApduChannel()
        self.matching_ids: list[str] = []

    def run_eim_poll(self, matching_id: str = "") -> None:
        self.matching_ids.append(matching_id)


class _BrokenOrchestrator:
    def __init__(self) -> None:
        self.apdu_channel = _FakeApduChannel()

    def run_eim_poll(self, matching_id: str = "") -> None:
        _ = matching_id
        raise RuntimeError("ip-ad failed")


class LocalizedIPAdStandaloneTests(unittest.TestCase):
    def test_build_default_session_exposes_standalone_contract(self) -> None:
        session = build_default_session(
            reader_index=4,
            eid_hint="890490320000000000000000000000FF",
            smdp_address="local.smdp.test",
        )

        self.assertEqual(int(session.cfg.READER_INDEX), 4)
        self.assertEqual(session._read_card_eid_safe(), "890490320000000000000000000000FF")
        self.assertEqual(session._resolve_runtime_smdp_address({}), "local.smdp.test")
        session.record_poll_audit_event(flow="ipad_test", success=True)
        self.assertEqual(len(session.audit_events), 1)

    def test_runner_requires_explicit_runtime_hooks_in_standalone_mode(self) -> None:
        session = build_default_session()
        runner = LocalizedIPAdRunner(session=session)

        with self.assertRaisesRegex(StandaloneDependencyError, "bridge_factory is required"):
            runner.run("live")

    def test_localized_relay_apdu_channel_prefixes_server_roles(self) -> None:
        raw_channel = _FakeApduChannel()
        channel = LocalizedRelayApduChannel(raw_channel)

        channel.send(b"\x00", "EIM: RelayPackage [poll=1 package=1]")
        channel.send(b"\x00", "AUTH: AuthenticateServer")
        channel.exchange(b"\x00", "DOWNLOAD: PrepareDownload")

        self.assertEqual(raw_channel.send_calls[0][0], "[eIM] EIM: RelayPackage [poll=1 package=1]")
        self.assertEqual(raw_channel.send_calls[1][0], "[SM-DP+] AUTH: AuthenticateServer")
        self.assertEqual(raw_channel.exchange_calls[0][0], "[SM-DP+] DOWNLOAD: PrepareDownload")

    def test_localized_relay_apdu_channel_emits_concise_role_summary_when_raw_logging_disabled(self) -> None:
        raw_channel = _FakeApduChannel()
        raw_channel.set_raw_apdu_logging(False)
        channel = LocalizedRelayApduChannel(raw_channel)

        with contextlib.redirect_stdout(io.StringIO()) as output:
            channel.send(b"\x00", "EIM: RelayPackage [poll=1 package=1]")
            channel.exchange(b"\x00", "AUTH: AuthenticateServer")

        rendered = output.getvalue()
        self.assertIn("[eIM] EIM: RelayPackage [poll=1 package=1]", rendered)
        self.assertIn("[SM-DP+] AUTH: AuthenticateServer", rendered)
        self.assertNotIn("-> len=", rendered)
        self.assertNotIn("SW 9000", rendered)

    def test_runner_uses_injected_bridge_and_orchestrator(self) -> None:
        session = _FakeSession()
        bridge = _FakeBridge()
        orchestrator = _FakeOrchestrator()
        emitted: list[str] = []
        captured_loader_args: dict[str, object] = {}

        def loader(profile_name: str, loaded_bridge, loaded_session, loaded_cfg):
            captured_loader_args["profile_name"] = profile_name
            captured_loader_args["bridge"] = loaded_bridge
            captured_loader_args["session"] = loaded_session
            captured_loader_args["cfg"] = loaded_cfg
            return orchestrator

        runner = LocalizedIPAdRunner(
            session=session,
            bridge_factory=lambda _: bridge,
            orchestrator_loader=loader,
            emit=emitted.append,
        )
        result = runner.run("live", matching_id="MID-1", debug=False)

        self.assertEqual(session.close_calls, 1)
        self.assertGreaterEqual(bridge.start_calls, 1)
        self.assertEqual(bridge.reset_calls, 1)
        self.assertEqual(bridge.flow, "ipad_live")
        self.assertEqual(bridge.eid, "89049032000000000000000000000001")
        self.assertEqual(captured_loader_args["profile_name"], "live")
        self.assertIs(captured_loader_args["bridge"], bridge)
        self.assertIs(captured_loader_args["session"], session)
        self.assertIs(captured_loader_args["cfg"], session.cfg)
        self.assertEqual(orchestrator.matching_ids, ["MID-1"])
        self.assertEqual(orchestrator.apdu_channel.close_calls, 1)
        self.assertEqual(orchestrator.apdu_channel.raw_logging_updates, [False, True])
        self.assertEqual(len(session.audit_events), 1)
        self.assertTrue(bool(session.audit_events[0]["success"]))
        self.assertEqual(session.audit_events[0]["flow"], "ipad_live")
        self.assertEqual(result.profile_name, "live")
        self.assertEqual(result.matching_id, "MID-1")
        self.assertEqual(result.ack_count, 3)
        self.assertEqual(result.pending_package_path, "fixtures/020_profile.json")
        self.assertTrue(any("Active path: IPAd" in line for line in emitted))
        self.assertTrue(any("SIM <-> IPAd <-> eIM/SM-DP+" in line for line in emitted))
        self.assertTrue(any("Localized IPAd (LIVE)" in line for line in emitted))
        self.assertTrue(any("mode=concise" in line for line in emitted))
        self.assertTrue(any("Localized IPAd run completed." in line for line in emitted))

    def test_runner_records_failed_audit_event_and_closes_transport(self) -> None:
        session = _FakeSession()
        bridge = _FakeBridge()
        orchestrator = _BrokenOrchestrator()

        runner = LocalizedIPAdRunner(
            session=session,
            bridge_factory=lambda _: bridge,
            orchestrator_loader=lambda *_: orchestrator,
        )

        with self.assertRaisesRegex(RuntimeError, "ip-ad failed"):
            runner.run("test", matching_id="MID-ERR", debug=True)

        self.assertEqual(orchestrator.apdu_channel.close_calls, 1)
        self.assertEqual(orchestrator.apdu_channel.raw_logging_updates, [True, True])
        self.assertEqual(len(session.audit_events), 1)
        self.assertFalse(bool(session.audit_events[0]["success"]))
        self.assertEqual(session.audit_events[0]["flow"], "ipad_test")
        self.assertEqual(session.audit_events[0]["matching_id"], "MID-ERR")


if __name__ == "__main__":
    unittest.main()
