# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Tests for ``yggdrasim_common.gui_server.actions.card_bridge`` (CB-4 backend).

Coverage:

* ``card_bridge.status`` reports unconfigured / configured / token
  fingerprint without leaking the raw token.
* ``card_bridge.probe`` reaches a stub bridge and returns
  ``ok=True`` with latency + ATR + fingerprint.
* ``card_bridge.probe`` distinguishes auth-required-but-rejected,
  unreachable, and ``auth-disabled-non-loopback`` postures.
* ``card_bridge.probe`` falls back to configured URL when the form
  leaves ``url`` blank, and obeys ``use_configured=False`` to skip
  the fallback.
* The action specs are registered in the global registry under the
  expected ids.
"""

from __future__ import annotations

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from unittest import mock

import pytest

from yggdrasim_common.card_backend import (
    CARD_RELAY_TOKEN_ENV,
    CARD_RELAY_TOKEN_FILE_ENV,
    CARD_RELAY_URL_ENV,
)
from yggdrasim_common.card_bridge_auth import fingerprint as _fingerprint
from yggdrasim_common.gui_server.actions import card_bridge as cb
from yggdrasim_common.gui_server.actions.registry import ActionContext, get_registry


def _make_handler(
    *,
    require_token: str = "",
    status_status: int = 200,
    status_payload: dict[str, Any] | None = None,
    ping_status: int = 200,
    reset_status: int = 200,
    reset_payload: dict[str, Any] | None = None,
    post_log: list[dict[str, Any]] | None = None,
):
    class _Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args, **_kwargs):
            return

        def _authorized(self) -> bool:
            if len(require_token) == 0:
                return True
            presented = self.headers.get("Authorization") or ""
            if presented == f"Bearer {require_token}":
                return True
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{\"error\":\"unauthorised\"}")
            return False

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/ping":
                self.send_response(ping_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                if 200 <= ping_status < 300:
                    self.wfile.write(b"{\"ok\":true}")
                return
            if self.path == "/status":
                if self._authorized() is False:
                    return
                self.send_response(status_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                payload = status_payload or {}
                self.wfile.write(json.dumps(payload).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

        def do_POST(self) -> None:  # noqa: N802
            content_length = int(self.headers.get("Content-Length", "0") or "0")
            body = self.rfile.read(content_length)
            try:
                parsed = json.loads(body.decode("utf-8")) if body else {}
            except json.JSONDecodeError:
                parsed = {}
            if post_log is not None:
                post_log.append({"path": self.path, "body": parsed})
            if self.path == "/card/reset":
                if self._authorized() is False:
                    return
                self.send_response(reset_status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                payload = reset_payload or {
                    "status": "reset",
                    "reader": "Stub Reader",
                    "atr": "3B00",
                    "reset": {"mode": "pcsc-reconnect-unpower"},
                }
                self.wfile.write(json.dumps(payload).encode("utf-8"))
                return
            self.send_response(404)
            self.end_headers()

    return _Handler


class _StubBridge:
    def __init__(self, **handler_kwargs: Any) -> None:
        handler = _make_handler(**handler_kwargs)
        try:
            self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        except PermissionError as error:
            raise unittest.SkipTest(
                f"loopback sockets are unavailable in this environment: {error}"
            ) from error
        self.thread = threading.Thread(
            target=self.server.serve_forever,
            kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.thread.start()

    @property
    def url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2.0)


class _EnvSandbox:
    """Snapshot/restore the relay-related env vars per test.

    Also redirects ``YGGDRASIM_RUNTIME_ROOT`` to a fresh tempdir so the
    marker-file branch in ``card_backend._resolve_card_relay_url``
    cannot surface state from a sibling test (the daemon stack writes
    its own marker, but on a hot CI runner those tempdirs can outlive
    the test that created them).
    """

    def __init__(self) -> None:
        self._snapshot: dict[str, str | None] = {}
        self._runtime_root: str | None = None

    def __enter__(self):
        import os as _os
        import tempfile

        for key in (
            CARD_RELAY_URL_ENV,
            CARD_RELAY_TOKEN_ENV,
            CARD_RELAY_TOKEN_FILE_ENV,
            "YGGDRASIM_RUNTIME_ROOT",
        ):
            self._snapshot[key] = _os.environ.get(key)
            _os.environ.pop(key, None)
        self._runtime_root = tempfile.mkdtemp(prefix="ygg-cb-actions-")
        _os.environ["YGGDRASIM_RUNTIME_ROOT"] = self._runtime_root
        return self

    def __exit__(self, *_):
        import os as _os
        import shutil

        for key, value in self._snapshot.items():
            if value is None:
                _os.environ.pop(key, None)
            else:
                _os.environ[key] = value
        if self._runtime_root is not None:
            shutil.rmtree(self._runtime_root, ignore_errors=True)


class CardBridgeActionRegistrationTests(unittest.TestCase):
    def test_status_spec_registered(self) -> None:
        spec = get_registry().get("card_bridge.status")
        self.assertIsNotNone(spec)
        self.assertEqual(spec.subsystem, "Card Bridge")
        self.assertFalse(spec.requires_card)

    def test_probe_spec_registered(self) -> None:
        spec = get_registry().get("card_bridge.probe")
        self.assertIsNotNone(spec)
        # Inputs must include url + token + use_configured.
        names = {field.name for field in spec.inputs}
        self.assertEqual(names, {"url", "token", "use_configured"})
        token_field = next(field for field in spec.inputs if field.name == "token")
        self.assertTrue(token_field.secret)

    def test_remote_rig_specs_registered(self) -> None:
        expected = {
            "card_bridge.local_start",
            "card_bridge.local_stop",
            "card_bridge.remote_rig_start",
            "card_bridge.remote_rig_stop",
            "card_bridge.remote_rig_tunnel_start",
            "card_bridge.remote_rig_tunnel_stop",
            "card_bridge.remote_rig_sync_token",
            "card_bridge.remote_rig_install_service",
            "card_bridge.remote_rig_service",
            "card_bridge.remote_rig_status",
        }
        registered = {spec.id for spec in get_registry().all()}
        self.assertTrue(expected.issubset(registered))
        for action_id in expected - {
            "card_bridge.local_start",
            "card_bridge.local_stop",
            "card_bridge.remote_rig_tunnel_stop",
        }:
            input_names = {field.name for field in get_registry().get(action_id).inputs}
            self.assertIn("ssh_path", input_names, msg=action_id)


class CardBridgeStatusTests(unittest.TestCase):
    def test_status_unconfigured(self) -> None:
        with _EnvSandbox():
            payload = cb._dispatch_status(ActionContext())
        self.assertFalse(payload["configured"])
        self.assertEqual(payload["url"], "")
        self.assertFalse(payload["has_token"])
        self.assertIn("not configured", payload["summary"].lower())

    def test_status_configured_with_raw_token(self) -> None:
        with _EnvSandbox():
            import os as _os

            _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:8642/apdu"
            _os.environ[CARD_RELAY_TOKEN_ENV] = "secret-token-1"
            payload = cb._dispatch_status(ActionContext())
        self.assertTrue(payload["configured"])
        self.assertEqual(payload["url"], "http://127.0.0.1:8642/apdu")
        self.assertEqual(payload["base_url"], "http://127.0.0.1:8642")
        self.assertTrue(payload["has_token"])
        self.assertEqual(payload["token_source"], "env-raw")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("secret-token-1"))
        self.assertNotIn("secret-token-1", json.dumps(payload))

    def test_status_configured_with_token_file(self) -> None:
        import tempfile as _tmp

        with _EnvSandbox():
            with _tmp.NamedTemporaryFile("w", delete=False) as handle:
                handle.write("from-file-token")
                token_path = handle.name
            try:
                import os as _os

                _os.environ[CARD_RELAY_URL_ENV] = "http://127.0.0.1:8642/apdu"
                _os.environ[CARD_RELAY_TOKEN_FILE_ENV] = token_path
                payload = cb._dispatch_status(ActionContext())
            finally:
                _os.unlink(token_path)
        self.assertTrue(payload["has_token"])
        self.assertEqual(payload["token_source"], "env-file")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("from-file-token"))


@pytest.mark.usefixtures("require_loopback_socket")
class CardBridgeProbeTests(unittest.TestCase):
    def test_probe_no_url_returns_helpful_reason(self) -> None:
        with _EnvSandbox():
            payload = cb._dispatch_probe(ActionContext())
        self.assertFalse(payload["ok"])
        self.assertIn("no URL", payload["reason"])

    def test_probe_explicit_url_no_token_required(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "127.0.0.1",
                "atrHex": "3b9f96804fe7828031a073be211367",
                "reader": "Stub Reader",
                "auditEnabled": True,
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["url"], bridge.url)
        self.assertEqual(payload["auth_posture"], "no-token-required")
        self.assertEqual(payload["atr_hex"], "3B9F96804FE7828031A073BE211367")
        self.assertGreater(payload["ping_latency_ms"], 0.0)
        self.assertGreater(payload["status_latency_ms"], 0.0)
        self.assertTrue(payload["audit_enabled"])

    def test_probe_token_accepted(self) -> None:
        bridge = _StubBridge(
            require_token="match-me",
            status_payload={
                "authRequired": True,
                "tokenFingerprint": _fingerprint("match-me"),
                "host": "127.0.0.1",
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    token="match-me",
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["auth_posture"], "token-accepted")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("match-me"))
        self.assertTrue(payload["fingerprint_match"])

    def test_probe_token_rejected(self) -> None:
        bridge = _StubBridge(require_token="real")
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    token="wrong",
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status_status"], 401)
        self.assertEqual(payload["auth_posture"], "token-rejected")

    def test_probe_unreachable_url(self) -> None:
        with _EnvSandbox():
            payload = cb._dispatch_probe(
                ActionContext(),
                url="http://127.0.0.1:1/apdu",
                use_configured=False,
            )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["ping_status"] if "ping_status" in payload else 0, 0)
        # Reason is a transport error class string.
        self.assertTrue(len(payload["reason"]) > 0)

    def test_probe_auth_disabled_non_loopback_flagged(self) -> None:
        bridge = _StubBridge(
            status_payload={
                "authRequired": False,
                "host": "192.0.2.5",
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["auth_posture"], "auth-disabled-non-loopback")

    def test_probe_falls_back_to_configured_url(self) -> None:
        bridge = _StubBridge(
            status_payload={"authRequired": False, "host": "127.0.0.1"}
        )
        try:
            with _EnvSandbox():
                import os as _os

                _os.environ[CARD_RELAY_URL_ENV] = bridge.url
                payload = cb._dispatch_probe(ActionContext())  # blank inputs
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertTrue(payload["used_configured_url"])


class RemoteRigActionHelperTests(unittest.TestCase):
    def test_detached_subprocess_kwargs_use_posix_session_by_default(self) -> None:
        from unittest.mock import patch

        with patch.object(cb.os, "name", "posix"):
            self.assertEqual(cb._detached_subprocess_kwargs(), {"start_new_session": True})

    def test_detached_subprocess_kwargs_use_windows_process_group_without_console(
        self,
    ) -> None:
        from unittest.mock import patch

        with patch.object(cb.os, "name", "nt"):
            with patch.object(cb.subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True):
                with patch.object(
                    cb,
                    "hidden_window_subprocess_kwargs",
                    return_value={"creationflags": 0x08000000},
                ):
                    self.assertEqual(
                        cb._detached_subprocess_kwargs(),
                        {"creationflags": 0x08000000 | 512},
                    )

    def test_detached_subprocess_kwargs_keep_windows_process_group_fallback(
        self,
    ) -> None:
        from unittest.mock import patch

        with patch.object(cb.os, "name", "nt"):
            with patch.object(cb.subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True):
                with patch.object(
                    cb,
                    "hidden_window_subprocess_kwargs",
                    return_value={},
                ):
                    self.assertEqual(
                        cb._detached_subprocess_kwargs(),
                        {"creationflags": 512},
                    )

    def test_remote_rig_state_updates_are_atomic_under_concurrency(self) -> None:
        from pathlib import Path

        failures: list[BaseException] = []
        worker_count = 6
        reader_count = 2
        barrier = threading.Barrier(worker_count + reader_count + 1)

        def _writer(worker_index: int) -> None:
            try:
                barrier.wait()
                for sequence in range(20):
                    cb._write_remote_rig_state({
                        f"worker_{worker_index}": sequence,
                    })
            except BaseException as error:  # noqa: BLE001
                failures.append(error)

        def _reader() -> None:
            try:
                barrier.wait()
                for _ in range(100):
                    if cb._load_remote_rig_state().get("base") is not True:
                        raise AssertionError("reader observed incomplete state")
            except BaseException as error:  # noqa: BLE001
                failures.append(error)

        with _EnvSandbox():
            cb._write_remote_rig_state({"base": True})
            threads = [
                threading.Thread(target=_writer, args=(index,))
                for index in range(worker_count)
            ]
            threads.extend(
                threading.Thread(target=_reader)
                for _ in range(reader_count)
            )
            for thread in threads:
                thread.start()
            barrier.wait()
            for thread in threads:
                thread.join(timeout=10.0)

            state = cb._load_remote_rig_state()
            state_path = Path(cb._remote_rig_state_path())
            disk_state = json.loads(state_path.read_text(encoding="utf-8"))
            temporary_files = list(
                state_path.parent.glob(f".{state_path.name}.*.tmp")
            )

        self.assertEqual(failures, [])
        self.assertTrue(all(thread.is_alive() is False for thread in threads))
        self.assertEqual(state, disk_state)
        self.assertEqual(temporary_files, [])
        for index in range(worker_count):
            self.assertEqual(state.get(f"worker_{index}"), 19)

    def test_publish_local_card_relay_marker_configures_status_action(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tempdir:
            token_path = Path(tempdir) / "bridge.token"
            token_path.write_text("local-relay-token\n", encoding="utf-8")
            with _EnvSandbox():
                marker = cb._publish_local_card_relay_marker(
                    port=8642,
                    token_file=str(token_path),
                    reader="Reader A",
                    atr="3b00",
                )
                payload = cb._dispatch_status(ActionContext())

        self.assertTrue(marker["ok"])
        self.assertTrue(payload["configured"])
        self.assertEqual(payload["url"], "http://127.0.0.1:8642/apdu")
        self.assertEqual(payload["token_source"], "marker")
        self.assertEqual(payload["token_fingerprint"], _fingerprint("local-relay-token"))
        self.assertNotIn("local-relay-token", json.dumps(payload))

    def test_relay_marker_lifecycle_does_not_import_linux_hil_runtime(self) -> None:
        import sys
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tempdir:
            token_path = Path(tempdir) / "bridge.token"
            token_path.write_text("local-relay-token\n", encoding="utf-8")
            with _EnvSandbox(), patch.dict(
                sys.modules,
                {"yggdrasim_common.hil_bridge_runtime": None},
            ):
                marker = cb._publish_local_card_relay_marker(
                    port=8642,
                    token_file=str(token_path),
                    reader="Reader A",
                    atr="3b00",
                )
                self.assertTrue(Path(marker["marker_path"]).is_file())
                cb._clear_local_card_relay_marker()
                self.assertFalse(Path(marker["marker_path"]).exists())

    def test_local_stop_clears_runtime_relay_marker(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tempdir:
            token_path = Path(tempdir) / "bridge.token"
            token_path.write_text("local-relay-token\n", encoding="utf-8")
            with _EnvSandbox():
                cb._publish_local_card_relay_marker(
                    port=8642,
                    token_file=str(token_path),
                    reader="Reader A",
                    atr="3b00",
                )
                cb._write_remote_rig_state({
                    "remote_gsmtap_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
                })
                before = cb._dispatch_status(ActionContext())
                with patch.object(cb, "_find_local_card_bridge_listener_pid", return_value=0):
                    payload = cb._dispatch_local_stop(ActionContext(), confirm=True)
                after = cb._dispatch_status(ActionContext())
                state = cb._load_remote_rig_state()

        self.assertTrue(before["configured"])
        self.assertEqual(payload["status"], "missing-pid")
        self.assertFalse(after["configured"])
        self.assertEqual(state.get("remote_gsmtap_capture_path"), "")

    def test_tunnel_stop_clears_runtime_relay_marker(self) -> None:
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as tempdir:
            token_path = Path(tempdir) / "bridge.token"
            token_path.write_text("local-relay-token\n", encoding="utf-8")
            with _EnvSandbox():
                cb._publish_local_card_relay_marker(
                    port=8642,
                    token_file=str(token_path),
                    reader="Reader A",
                    atr="3b00",
                )
                cb._write_remote_rig_state({
                    "remote_gsmtap_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
                })
                before = cb._dispatch_status(ActionContext())
                payload = cb._dispatch_tunnel_stop(ActionContext(), confirm=True)
                after = cb._dispatch_status(ActionContext())
                state = cb._load_remote_rig_state()

        self.assertTrue(before["configured"])
        self.assertEqual(payload["status"], "missing-pid")
        self.assertFalse(after["configured"])
        self.assertEqual(state.get("remote_gsmtap_capture_path"), "")

    def test_remote_hil_stop_clears_runtime_relay_marker_on_success(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tempdir:
            token_path = Path(tempdir) / "bridge.token"
            token_path.write_text("local-relay-token\n", encoding="utf-8")
            with _EnvSandbox():
                cb._publish_local_card_relay_marker(
                    port=8642,
                    token_file=str(token_path),
                    reader="Reader A",
                    atr="3b00",
                )
                cb._write_remote_rig_state({
                    "remote_gsmtap_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
                })
                before = cb._dispatch_status(ActionContext())
                with patch.object(
                    cb,
                    "_run_ssh_command",
                    return_value={
                        "ok": True,
                        "returncode": 0,
                        "stdout": "",
                        "stderr": "",
                    },
                ):
                    payload = cb._dispatch_remote_service_control(
                        ActionContext(),
                        ssh_target="pi@example.test",
                        action="stop",
                        confirm=True,
                    )
                after = cb._dispatch_status(ActionContext())
                state = cb._load_remote_rig_state()

        self.assertTrue(before["configured"])
        self.assertTrue(payload["ok"])
        self.assertFalse(after["configured"])
        self.assertEqual(state.get("remote_gsmtap_capture_path"), "")

    def test_local_stop_terminates_discovered_card_bridge_listener(self) -> None:
        from unittest.mock import patch

        calls: list[int] = []

        def _terminate(pid: int):
            calls.append(pid)
            if pid == 0:
                return {"ok": False, "pid": 0, "status": "missing-pid"}
            return {"ok": True, "pid": pid, "status": "terminated"}

        with _EnvSandbox():
            cb._write_remote_rig_state({
                "local_card_bridge_pid": 0,
                "local_card_bridge_port": 8642,
            })
            with patch.object(cb, "_find_local_card_bridge_listener_pid", return_value=4242):
                with patch.object(cb, "_terminate_process_group", side_effect=_terminate):
                    payload = cb._dispatch_local_stop(ActionContext(), confirm=True)
            state = cb._load_remote_rig_state()

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["discovered_pid"], 4242)
        self.assertEqual(calls, [0, 4242])
        self.assertEqual(state.get("local_card_bridge_pid"), 0)
        self.assertFalse(state.get("local_card_bridge_external"))

    def test_card_bridge_listener_command_matching_is_specific(self) -> None:
        self.assertTrue(cb._cmdline_is_card_bridge(["python", "-m", "Tools.CardBridge"]))
        self.assertTrue(cb._cmdline_is_card_bridge(["python", "-m", "Tools.CardBridge.server"]))
        self.assertTrue(cb._cmdline_is_card_bridge(["/usr/bin/yggdrasim-card-bridge"]))
        self.assertFalse(cb._cmdline_is_card_bridge(["python", "-m", "http.server"]))

    def test_local_start_uses_shared_pcsc_mode_for_gui_bridge(self) -> None:
        from unittest.mock import patch

        class _RunningProcess:
            pid = 4343

            def poll(self):
                return None

        with _EnvSandbox():
            with patch.object(cb.subprocess, "Popen", return_value=_RunningProcess()):
                with patch.object(cb.time, "sleep", lambda _seconds: None):
                    payload = cb._dispatch_local_start(
                        ActionContext(),
                        port=8642,
                        reader_index=0,
                        confirm=True,
                    )
            state = cb._load_remote_rig_state()

        self.assertTrue(payload["ok"])
        command = state.get("local_card_bridge_command", [])
        self.assertIn("--pcsc-share-mode", command)
        flag_index = command.index("--pcsc-share-mode")
        self.assertEqual(command[flag_index + 1], "shared")

    def test_local_start_reuses_reachable_existing_bridge(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        bridge = _StubBridge(
            status_payload={
                "reader": "Reader A",
                "atrHex": "3B00",
                "card": "available",
            }
        )
        try:
            _host, port = bridge.server.server_address
            with tempfile.TemporaryDirectory() as tempdir:
                token_path = Path(tempdir) / "bridge.token"
                with _EnvSandbox():
                    with patch.object(cb.subprocess, "Popen", side_effect=AssertionError):
                        payload = cb._dispatch_local_start(
                            ActionContext(),
                            port=port,
                            token_file=str(token_path),
                            reuse_existing=True,
                            restart=True,
                            confirm=True,
                        )
                    state = cb._load_remote_rig_state()
        finally:
            bridge.close()

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertTrue(payload["already_running"])
        self.assertTrue(payload["external"])
        self.assertEqual(payload["reader"], "Reader A")
        self.assertEqual(payload["atr"], "3B00")
        self.assertEqual(state.get("local_card_bridge_pid"), 0)
        self.assertTrue(state.get("local_card_bridge_external"))
        self.assertEqual(state.get("local_card_bridge_port"), port)

    def test_local_start_remembers_reused_bridge_pid_from_status(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        bridge = _StubBridge(
            status_payload={
                "pid": 4242,
                "reader": "Reader A",
                "atrHex": "3B00",
                "card": "available",
            }
        )
        try:
            _host, port = bridge.server.server_address
            with tempfile.TemporaryDirectory() as tempdir:
                token_path = Path(tempdir) / "bridge.token"
                with _EnvSandbox():
                    with patch.object(cb.subprocess, "Popen", side_effect=AssertionError):
                        payload = cb._dispatch_local_start(
                            ActionContext(),
                            port=port,
                            token_file=str(token_path),
                            reuse_existing=True,
                            restart=True,
                            confirm=True,
                        )
                    state = cb._load_remote_rig_state()
        finally:
            bridge.close()

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["pid"], 4242)
        self.assertEqual(state.get("local_card_bridge_pid"), 4242)
        self.assertTrue(state.get("local_card_bridge_external"))

    def test_reset_local_card_bridge_refreshes_pcsc_handle(self) -> None:
        import tempfile
        from pathlib import Path

        posts: list[dict[str, Any]] = []
        bridge = _StubBridge(
            require_token="reset-token",
            reset_payload={
                "status": "reset",
                "reader": "Reader A",
                "atr": "3B00",
                "reset": {"mode": "pcsc-reconnect-unpower"},
            },
            post_log=posts,
        )
        try:
            _host, port = bridge.server.server_address
            with tempfile.TemporaryDirectory() as tempdir:
                token_path = Path(tempdir) / "bridge.token"
                token_path.write_text("reset-token\n", encoding="utf-8")
                with _EnvSandbox():
                    payload = cb._reset_local_card_bridge(
                        port=port,
                        token_file=str(token_path),
                    )
        finally:
            bridge.close()

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["reader"], "Reader A")
        self.assertEqual(payload["atr"], "3B00")
        self.assertEqual(payload["reset"]["mode"], "pcsc-reconnect-unpower")
        self.assertEqual(posts[0]["path"], "/card/reset")
        self.assertEqual(posts[0]["body"]["sessionId"], "remote-rig-start")

    def test_remote_rig_status_marks_external_reachable_bridge_running(self) -> None:
        bridge = _StubBridge(status_payload={"card": "available", "atrHex": "3B00"})
        try:
            _host, port = bridge.server.server_address
            with _EnvSandbox():
                cb._write_remote_rig_state({
                    "local_card_bridge_pid": 0,
                    "local_card_bridge_port": port,
                })
                payload = cb._dispatch_remote_rig_status(ActionContext())
        finally:
            bridge.close()

        self.assertTrue(payload["state"]["local_card_bridge_running"])
        self.assertTrue(payload["state"]["local_card_bridge_reachable"])

    def test_remote_rig_status_discovers_card_bridge_listener_pid(self) -> None:
        from unittest.mock import patch

        bridge = _StubBridge(status_payload={"card": "available", "atrHex": "3B00"})
        try:
            _host, port = bridge.server.server_address
            with _EnvSandbox():
                cb._write_remote_rig_state({
                    "local_card_bridge_pid": 0,
                    "local_card_bridge_port": port,
                })
                with patch.object(cb, "_find_local_card_bridge_listener_pid", return_value=5252):
                    payload = cb._dispatch_remote_rig_status(ActionContext())
                state = cb._load_remote_rig_state()
        finally:
            bridge.close()

        self.assertTrue(payload["state"]["local_card_bridge_running"])
        self.assertEqual(payload["state"]["local_card_bridge_pid"], 5252)
        self.assertEqual(state.get("local_card_bridge_pid"), 5252)
        self.assertTrue(state.get("local_card_bridge_external"))

    def test_remote_hil_runtime_status_reports_modem_path_readiness(self) -> None:
        from unittest.mock import patch

        stdout = json.dumps(
            {
                "supervisor": {
                    "status": "running",
                    "reason": "SIMtrace2 present; bridge and REMSIM client children are active.",
                    "usbPresent": True,
                    "bridgeRunning": True,
                    "remsimClientEnabled": True,
                    "remsimClientRunning": True,
                },
                "bridge_status": {
                    "controlConnected": True,
                    "bankdConnected": True,
                },
            }
        )
        with patch.object(
            cb,
            "_run_ssh_command",
            return_value={"ok": True, "returncode": 0, "stdout": stdout, "stderr": ""},
        ):
            payload = cb._remote_hil_runtime_status(
                ssh_target="pi@rpi-host",
                remote_workdir="~/YggdraSIM",
                remote_python="~/YggdraSIM/.venv/bin/python",
            )

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertTrue(payload["modem_path_ready"])
        self.assertTrue(payload["usb_present"])
        self.assertTrue(payload["bridge_running"])
        self.assertTrue(payload["remsim_client_running"])
        self.assertTrue(payload["control_connected"])
        self.assertTrue(payload["bankd_connected"])

    def test_remote_hil_runtime_status_marks_missing_remsim_binary(self) -> None:
        from unittest.mock import patch

        stdout = json.dumps(
            {
                "supervisor": {
                    "reason": "REMSIM client failed to start: [Errno 2] No such file or directory: 'osmo-remsim-client-st2'",
                    "usbPresent": True,
                    "bridgeRunning": True,
                    "remsimClientEnabled": True,
                    "remsimClientRunning": False,
                    "remsimClientCommand": ["osmo-remsim-client-st2"],
                },
                "bridge_status": {
                    "controlConnected": False,
                    "bankdConnected": False,
                },
            }
        )
        with patch.object(
            cb,
            "_run_ssh_command",
            return_value={"ok": True, "returncode": 0, "stdout": stdout, "stderr": ""},
        ):
            payload = cb._remote_hil_runtime_status(ssh_target="pi@rpi-host")

        self.assertFalse(payload["modem_path_ready"])
        self.assertTrue(payload["remsim_binary_missing"])
        self.assertEqual(payload["remsim_binary"], "osmo-remsim-client-st2")

    def test_remote_remsim_binary_status_resolves_path(self) -> None:
        from unittest.mock import patch

        with patch.object(
            cb,
            "_run_ssh_command",
            return_value={
                "ok": True,
                "returncode": 0,
                "stdout": "/usr/local/bin/osmo-remsim-client-st2\n",
                "stderr": "",
            },
        ):
            payload = cb._remote_remsim_binary_status(
                ssh_target="pi@rpi-host",
                remsim_binary="osmo-remsim-client-st2",
            )

        self.assertTrue(payload["ok"])
        self.assertEqual(
            payload["resolved_remsim_binary"],
            "/usr/local/bin/osmo-remsim-client-st2",
        )

    def test_remote_hil_preflight_accepts_full_frozen_runtime(self) -> None:
        from unittest.mock import patch

        preflight = {
            "ok": True,
            "runtime_kind": "frozen-full",
            "runtime_executable": "/home/pi/.local/bin/yggdrasim",
            "resolved_workdir": "/home/pi",
            "systemctl_user": True,
            "pyudev": False,
            "lsusb": "/usr/bin/lsusb",
            "supervisor_command": [
                "/home/pi/.local/bin/yggdrasim",
                "--yggdrasim-internal-entry",
                "hil-supervisor",
                "--",
            ],
            "note": "Remote HIL runtime ready (frozen-full).",
        }
        with patch.object(
            cb,
            "_run_ssh_command",
            return_value={
                "ok": True,
                "returncode": 0,
                "stdout": json.dumps(preflight),
                "stderr": "",
            },
        ):
            payload = cb._remote_hil_dependency_preflight(
                ssh_target="pi@rpi-host",
            )

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["runtime_kind"], "frozen-full")
        self.assertEqual(payload["resolved_remote_python"], "")
        self.assertEqual(payload["supervisor_command"][-3:], [
            "--yggdrasim-internal-entry",
            "hil-supervisor",
            "--",
        ])

    def test_remote_hil_preflight_reports_python_prerequisite_without_python(self) -> None:
        from unittest.mock import patch

        stdout = "\n".join(
            [
                "YGG_PREF_V1",
                "ok=0",
                "runtime_kind=frozen-full",
                "runtime_executable=/home/pi/.local/bin/yggdrasim",
                "resolved_workdir=/home/pi",
                "systemctl_user=1",
                "pyudev=1",
                "lsusb=/usr/bin/lsusb",
                "note=Python 3 is required for remote HIL dependency and readiness diagnostics.",
            ]
        )
        with patch.object(
            cb,
            "_run_ssh_command",
            return_value={
                "ok": True,
                "returncode": 0,
                "stdout": stdout,
                "stderr": "",
            },
        ):
            payload = cb._remote_hil_dependency_preflight(
                ssh_target="pi@rpi-host",
            )

        self.assertFalse(payload["ok"])
        self.assertIn("Python 3", payload["note"])
        self.assertEqual(
            payload["supervisor_command"][0],
            "/home/pi/.local/bin/yggdrasim",
        )

    def test_ssh_tunnel_command_forwards_card_and_gui_ports(self) -> None:
        command = cb._build_ssh_tunnel_command(
            ssh_target="pi@rpi-host",
            local_card_port=8642,
            remote_card_port=8642,
            local_gui_port=27854,
            remote_gui_port=27854,
            identity_file="/home/user/.ssh/id_ed25519",
        )
        self.assertEqual(command[0], "ssh")
        self.assertIn("-R", command)
        self.assertIn("8642:127.0.0.1:8642", command)
        self.assertIn("-L", command)
        self.assertIn("27854:127.0.0.1:27854", command)
        self.assertEqual(command[-1], "pi@rpi-host")
        self.assertIn("-i", command)

    def test_ssh_tunnel_command_can_skip_gui_forward(self) -> None:
        command = cb._build_ssh_tunnel_command(
            ssh_target="pi@rpi-host",
            local_card_port=8642,
            remote_card_port=8642,
            local_gui_port=27854,
            remote_gui_port=27854,
            forward_gui=False,
        )
        self.assertIn("-R", command)
        self.assertIn("8642:127.0.0.1:8642", command)
        self.assertNotIn("-L", command)
        self.assertNotIn("27854:127.0.0.1:27854", command)

    def test_explicit_windows_openssh_path_is_one_argv_element(self) -> None:
        from unittest.mock import patch

        ssh_path = r"C:\Windows\System32\OpenSSH\ssh.exe"
        identity_path = r"C:\Users\Lab User\.ssh\id_ed25519"
        with patch.object(
            cb.shutil,
            "which",
            return_value=ssh_path,
        ) as which:
            command = cb._ssh_base_command(
                ssh_target="operator@lab-host",
                identity_file=identity_path,
                ssh_path=f'"{ssh_path}"',
            )

        self.assertEqual(command[0], ssh_path)
        self.assertEqual(command[-1], "operator@lab-host")
        self.assertEqual(command[command.index("-i") + 1], identity_path)
        which.assert_called_once_with(ssh_path)

    def test_windows_openssh_is_discovered_under_system_root(self) -> None:
        from unittest.mock import call, patch

        expected = r"C:\Windows\System32\OpenSSH\ssh.exe"
        with patch.dict(
            cb.os.environ,
            {"SystemRoot": r"C:\Windows"},
            clear=True,
        ):
            with patch.object(cb.os, "name", "nt"):
                with patch.object(
                    cb.shutil,
                    "which",
                    side_effect=[None, expected],
                ) as which:
                    resolved = cb._resolve_ssh_binary()

        self.assertEqual(resolved, expected)
        self.assertEqual(which.call_args_list, [call("ssh"), call(expected)])

    def test_ssh_executable_rejects_control_characters_before_lookup(self) -> None:
        from unittest.mock import patch

        with patch.object(cb.shutil, "which") as which:
            with self.assertRaisesRegex(ValueError, "control characters"):
                cb._resolve_ssh_binary("ssh\n--unexpected")

        which.assert_not_called()

    def test_missing_ssh_client_returns_actionable_result(self) -> None:
        from unittest.mock import patch

        with patch.object(cb.shutil, "which", return_value=None):
            with patch.object(cb.subprocess, "run") as run:
                payload = cb._run_ssh_command(
                    ssh_target="operator@lab-host",
                    remote_command="true",
                )

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["returncode"], 127)
        self.assertIn("OpenSSH client", payload["stderr"])
        self.assertIn("SSH executable", payload["stderr"])
        run.assert_not_called()

    def test_ssh_timeout_returns_structured_failure(self) -> None:
        from unittest.mock import patch

        with patch.object(cb.shutil, "which", return_value="/usr/bin/ssh"):
            with patch.object(
                cb.subprocess,
                "run",
                side_effect=cb.subprocess.TimeoutExpired(["ssh"], 3),
            ):
                payload = cb._run_ssh_command(
                    ssh_target="operator@lab-host",
                    remote_command="true",
                    timeout_seconds=3,
                )

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["returncode"], 124)
        self.assertEqual(payload["stderr"], "SSH command timed out after 3 seconds.")

    def test_remote_hil_unit_contains_remote_card_flags(self) -> None:
        unit_text = cb._render_remote_hil_unit(
            remote_workdir="~/YggdraSIM",
            remote_python="~/YggdraSIM/.venv/bin/python",
            remote_card_url="http://127.0.0.1:8642/apdu",
            remote_token_file="~/.config/yggdrasim/hil/remote-card-8642.token",
            remsim_binary="/usr/local/bin/osmo-remsim-client-st2",
            usb_vidpid="1d50:60e3",
            hil_port=9997,
            apdu_timeout_ms=30000,
        )
        self.assertIn("WorkingDirectory=%h/YggdraSIM", unit_text)
        self.assertIn("ExecStart=%h/YggdraSIM/.venv/bin/python", unit_text)
        self.assertNotIn("ExecStart=~/", unit_text)
        self.assertIn("--remote-card-url http://127.0.0.1:8642/apdu", unit_text)
        self.assertIn(
            "--remote-card-token-file %h/.config/yggdrasim/hil/remote-card-8642.token",
            unit_text,
        )
        self.assertIn("--remsim-binary /usr/local/bin/osmo-remsim-client-st2", unit_text)
        self.assertIn("--usb-vidpid 1d50:60e3", unit_text)
        self.assertIn("--apdu-timeout-ms 30000", unit_text)
        self.assertIn(
            "--gsmtap-capture-path %h/YggdraSIM/state/hil_termshark/live_capture.pcap",
            unit_text,
        )

    def test_remote_hil_unit_forwards_simtrace_reset_knobs(self) -> None:
        unit_text = cb._render_remote_hil_unit(
            remote_workdir="~/YggdraSIM",
            remote_python="~/YggdraSIM/.venv/bin/python",
            simtrace_reset="auto",
            uhubctl_binary="~/bin/uhubctl",
            uhubctl_location="1-1",
            uhubctl_port="2",
        )
        self.assertIn("--simtrace-reset auto", unit_text)
        self.assertIn("--uhubctl-binary %h/bin/uhubctl", unit_text)
        self.assertIn("--uhubctl-location 1-1", unit_text)
        self.assertIn("--uhubctl-port 2", unit_text)

    def test_remote_hil_unit_omits_unset_simtrace_reset_knobs(self) -> None:
        # Unset leaves the remote supervisor on its own default
        # (usb-reset) and keeps the unit stable across reinstalls.
        with mock.patch.dict("os.environ", {}, clear=True):
            unit_text = cb._render_remote_hil_unit(
                remote_workdir="~/YggdraSIM",
                remote_python="~/YggdraSIM/.venv/bin/python",
            )
        self.assertNotIn("--simtrace-reset", unit_text)
        self.assertNotIn("--uhubctl", unit_text)

    def test_remote_hil_unit_rejects_an_unknown_reset_mode(self) -> None:
        # A bogus mode must never render a unit the remote supervisor
        # would refuse to start.
        with mock.patch.dict("os.environ", {}, clear=True):
            unit_text = cb._render_remote_hil_unit(
                remote_workdir="~/YggdraSIM",
                remote_python="~/YggdraSIM/.venv/bin/python",
                simtrace_reset="power-cycle-please",
            )
        self.assertNotIn("--simtrace-reset", unit_text)

    def test_remote_hil_unit_falls_back_to_the_local_environment(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {
                "YGGDRASIM_HIL_SIMTRACE_RESET": "port-power",
                "YGGDRASIM_HIL_UHUBCTL_LOCATION": "2-1",
            },
            clear=True,
        ):
            unit_text = cb._render_remote_hil_unit(
                remote_workdir="~/YggdraSIM",
                remote_python="~/YggdraSIM/.venv/bin/python",
            )
        self.assertIn("--simtrace-reset port-power", unit_text)
        self.assertIn("--uhubctl-location 2-1", unit_text)

    def test_remote_hil_unit_accepts_frozen_supervisor_command(self) -> None:
        unit_text = cb._render_remote_hil_unit(
            remote_workdir="/home/pi",
            remote_python="",
            supervisor_command=[
                "/home/pi/.local/bin/yggdrasim",
                "--yggdrasim-internal-entry",
                "hil-supervisor",
                "--",
            ],
            remote_card_url="http://127.0.0.1:8642/apdu",
        )

        self.assertIn(
            "ExecStart=/home/pi/.local/bin/yggdrasim "
            "--yggdrasim-internal-entry hil-supervisor -- ",
            unit_text,
        )
        self.assertNotIn(" -m Tools.HilBridge.supervisor", unit_text)

    def test_sync_token_uses_ssh_stdin_without_returning_raw_token(self) -> None:
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as tempdir:
            token_path = Path(tempdir) / "bridge.token"
            token_path.write_text("secret-token-value\n", encoding="utf-8")
            calls = []

            def _fake_run(command, **kwargs):
                calls.append((command, kwargs))

                class _Completed:
                    returncode = 0
                    stdout = ""
                    stderr = ""

                return _Completed()

            with patch.object(cb.subprocess, "run", _fake_run):
                payload = cb._dispatch_sync_token(
                    ActionContext(),
                    ssh_target="pi@rpi-host",
                    local_token_file=str(token_path),
                    remote_token_file="~/.config/yggdrasim/hil/remote-card-8642.token",
                    confirm=True,
                )

        self.assertTrue(payload["ok"])
        self.assertNotIn("secret-token-value", json.dumps(payload))
        self.assertEqual(payload["token_fingerprint"], _fingerprint("secret-token-value"))
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[-2], "pi@rpi-host")
        self.assertIn("cat >", command[-1])
        self.assertIn("$HOME/.config/yggdrasim/hil/remote-card-8642.token", command[-1])
        self.assertNotIn("\\\\", command[-1])
        self.assertEqual(kwargs["input"], "secret-token-value\n")

    def test_frontend_profiles_and_actions_propagate_ssh_executable(self) -> None:
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        source_html = (root / "gui_frontend" / "src" / "index.html").read_text(
            encoding="utf-8"
        )
        source_js = (
            root / "gui_frontend" / "src" / "js" / "core.js"
        ).read_text(encoding="utf-8")

        self.assertIn('id="cb-rig-ssh-path"', source_html)
        self.assertIn('"cb-rig-ssh-path"', source_js)
        self.assertIn(
            'ssh_path: cbRigPayloadValue(payload, "cb-rig-ssh-path")',
            source_js,
        )
        self.assertGreaterEqual(source_js.count("ssh_path: cfg.ssh_path"), 8)

    def test_tunnel_start_reports_immediate_ssh_failure(self) -> None:
        from unittest.mock import patch

        class _ExitedProcess:
            pid = 4242
            returncode = 255

            def poll(self):
                return self.returncode

        with _EnvSandbox():
            with patch.object(cb.subprocess, "Popen", return_value=_ExitedProcess()):
                with patch.object(cb.time, "sleep", lambda _seconds: None):
                    payload = cb._dispatch_tunnel_start(
                        ActionContext(),
                        ssh_target="pi@rpi-host",
                        local_card_port=8642,
                        remote_card_port=8642,
                        forward_gui=False,
                        confirm=True,
                    )
            state = cb._load_remote_rig_state()

        self.assertFalse(payload["ok"])
        self.assertEqual(payload["pid"], 4242)
        self.assertEqual(payload["returncode"], 255)
        self.assertEqual(state.get("ssh_tunnel_pid"), 0)

    def test_remote_rig_start_orchestrates_background_setup(self) -> None:
        from contextlib import ExitStack
        from unittest.mock import patch

        status_payload = {
            "ok": True,
            "lines": [],
            "state": {
                "local_card_bridge_running": True,
                "ssh_tunnel_running": True,
                "remote_service": {"ActiveState": "active", "SubState": "running"},
            },
        }
        with _EnvSandbox(), ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_hil_dependency_preflight",
                    return_value={
                        "ok": True,
                        "resolved_workdir": "~/YggdraSIM",
                        "resolved_remote_python": "~/YggdraSIM/.venv/bin/python",
                        "supervisor_command": [
                            "~/YggdraSIM/.venv/bin/python",
                            "-m",
                            "Tools.HilBridge.supervisor",
                        ],
                        "note": "preflight",
                    },
                )
            )
            start_local = stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_local_start",
                    return_value={"ok": True, "note": "local"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_wait_for_local_card_bridge",
                    return_value={
                        "ok": True,
                        "token_file": "/tmp/bridge.token",
                        "token_fingerprint": "abcdef",
                        "reader": "Reader A",
                        "atr": "3B00",
                        "note": "verified",
                    },
                )
            )
            reset = stack.enter_context(
                patch.object(
                    cb,
                    "_reset_local_card_bridge",
                    return_value={
                        "ok": True,
                        "token_file": "/tmp/bridge.token",
                        "token_fingerprint": "abcdef",
                        "reader": "Reader A",
                        "atr": "3B00",
                        "note": "reset",
                    },
                )
            )
            tunnel = stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_tunnel_start",
                    return_value={"ok": True, "note": "tunnel"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_card_ping",
                    return_value={"ok": True, "note": "ping"},
                )
            )
            sync = stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_sync_token",
                    return_value={
                        "ok": True,
                        "token_fingerprint": "abcdef",
                        "note": "sync",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_card_status",
                    return_value={
                        "ok": True,
                        "reader": "Reader A",
                        "atr": "3B00",
                        "note": "status",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_remsim_binary_status",
                    return_value={
                        "ok": True,
                        "resolved_remsim_binary": "/usr/bin/osmo-remsim-client-st2",
                        "note": "remsim",
                    },
                )
            )
            install = stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_install_remote_service",
                    return_value={"ok": True, "note": "service"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_wait_for_remote_hil_ready",
                    return_value={"ok": True, "modem_path_ready": True, "note": "hil"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_remote_rig_status",
                    return_value=status_payload,
                )
            )
            payload = cb._dispatch_remote_rig_start(
                ActionContext(),
                ssh_target="pi@rpi-host",
                ssh_path="/opt/openssh/bin/ssh",
                reader_index=0,
                local_card_port=8642,
                remote_card_port=8642,
                confirm=True,
            )

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertTrue(start_local.call_args.kwargs["reuse_existing"])
        self.assertEqual(reset.call_args.kwargs["token_file"], "/tmp/bridge.token")
        self.assertEqual(
            [step["name"] for step in payload["steps"]],
            [
                # Coordination comes first: no point preparing a host that
                # someone else has already reserved through its agent.
                "host_bench_check",
                "rpi_hil_preflight",
                "rpi_remsim_binary",
                # Before the URL, the token path and the unit are derived
                # from it: a rig serving its own card on the wanted port
                # means the tunnel can never own it.
                "rpi_port_free",
                "pc_bridge_start",
                "pc_bridge_verify",
                "pc_bridge_reset",
                "ssh_tunnel_start",
                "rpi_bridge_ping",
                "token_sync",
                "rpi_bridge_status",
                "rpi_hil_service",
                "rpi_hil_ready",
                # Last: a modem already powered when the rig came up has
                # nothing to re-read, so it is told to look again only
                # once the path that feeds it works.
                "modem_sim_refresh",
            ],
        )
        self.assertFalse(tunnel.call_args.kwargs["forward_gui"])
        self.assertEqual(
            tunnel.call_args.kwargs["ssh_path"],
            "/opt/openssh/bin/ssh",
        )
        self.assertEqual(sync.call_args.kwargs["local_token_file"], "/tmp/bridge.token")
        self.assertEqual(sync.call_args.kwargs["ssh_path"], "/opt/openssh/bin/ssh")
        self.assertEqual(install.call_args.kwargs["remote_workdir"], "~/YggdraSIM")
        self.assertEqual(
            install.call_args.kwargs["ssh_path"],
            "/opt/openssh/bin/ssh",
        )
        self.assertEqual(
            install.call_args.kwargs["remote_python"],
            "~/YggdraSIM/.venv/bin/python",
        )
        self.assertEqual(
            install.call_args.kwargs["remsim_binary"],
            "/usr/bin/osmo-remsim-client-st2",
        )

    def test_remote_rig_stop_tears_down_remote_tunnel_and_local_bridge(self) -> None:
        from contextlib import ExitStack
        from unittest.mock import patch

        calls: list[str] = []
        status_payload = {
            "ok": True,
            "lines": [],
            "state": {
                "local_card_bridge_running": False,
                "ssh_tunnel_running": False,
            },
        }

        def _remote_service(*_args, **kwargs):
            calls.append("remote")
            self.assertEqual(kwargs["action"], "stop")
            self.assertEqual(kwargs["ssh_path"], "/opt/openssh/bin/ssh")
            self.assertTrue(kwargs["confirm"])
            return {"ok": True, "note": "remote stopped"}

        def _tunnel_stop(*_args, **_kwargs):
            calls.append("tunnel")
            return {"ok": True, "status": "terminated", "note": "tunnel stopped"}

        def _local_stop(*_args, **_kwargs):
            calls.append("local")
            return {"ok": False, "status": "missing-pid", "note": "already stopped"}

        with _EnvSandbox(), ExitStack() as stack:
            cb._write_remote_rig_state({
                "ssh_target": "pi@rpi-host",
                "identity_file": "/tmp/key",
                "ssh_path": "/opt/openssh/bin/ssh",
                "local_gui_port": 27854,
                "remote_workdir": "~/YggdraSIM",
                "remote_python": "~/YggdraSIM/.venv/bin/python",
                "remote_gsmtap_capture_path": "~/YggdraSIM/state/hil_termshark/live_capture.pcap",
            })
            stack.enter_context(patch.object(cb, "_dispatch_remote_service_control", side_effect=_remote_service))
            stack.enter_context(patch.object(cb, "_dispatch_tunnel_stop", side_effect=_tunnel_stop))
            stack.enter_context(patch.object(cb, "_dispatch_local_stop", side_effect=_local_stop))
            stack.enter_context(patch.object(cb, "_dispatch_remote_rig_status", return_value=status_payload))
            payload = cb._dispatch_remote_rig_stop(ActionContext(), confirm=True)
            state = cb._load_remote_rig_state()

        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(calls, ["remote", "tunnel", "local"])
        self.assertEqual(
            [step["name"] for step in payload["steps"]],
            ["rpi_hil_service_stop", "ssh_tunnel_stop", "pc_bridge_stop"],
        )
        self.assertTrue(payload["steps"][2]["ok"])
        self.assertEqual(state.get("remote_gsmtap_capture_path"), "")

    def test_remote_rig_start_stops_when_pc_bridge_reset_fails(self) -> None:
        from contextlib import ExitStack
        from unittest.mock import patch

        status_payload = {
            "ok": True,
            "lines": [],
            "state": {"local_card_bridge_running": True},
        }
        with _EnvSandbox(), ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_hil_dependency_preflight",
                    return_value={
                        "ok": True,
                        "resolved_workdir": "~/YggdraSIM",
                        "resolved_remote_python": "~/YggdraSIM/.venv/bin/python",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_remsim_binary_status",
                    return_value={
                        "ok": True,
                        "resolved_remsim_binary": "/usr/bin/osmo-remsim-client-st2",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_local_start",
                    return_value={"ok": True, "note": "local"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_wait_for_local_card_bridge",
                    return_value={
                        "ok": True,
                        "token_file": "/tmp/bridge.token",
                        "reader": "Reader A",
                        "atr": "3B00",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_reset_local_card_bridge",
                    return_value={
                        "ok": False,
                        "status_code": 503,
                        "note": "PC Card Bridge reset failed.",
                    },
                )
            )
            stack.enter_context(
                patch.object(cb, "_dispatch_tunnel_start", side_effect=AssertionError)
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_remote_rig_status",
                    return_value=status_payload,
                )
            )
            payload = cb._dispatch_remote_rig_start(
                ActionContext(),
                ssh_target="pi@rpi-host",
                reader_index=0,
                local_card_port=8642,
                remote_card_port=8642,
                confirm=True,
            )

        self.assertFalse(payload["ok"], msg=str(payload))
        self.assertEqual(payload["steps"][-1]["name"], "pc_bridge_reset")
        self.assertIn("reset", payload["note"].lower())

    def test_remote_rig_start_stops_when_remsim_binary_is_missing(self) -> None:
        from contextlib import ExitStack
        from unittest.mock import patch

        status_payload = {
            "ok": True,
            "lines": [],
            "state": {
                "local_card_bridge_running": True,
                "ssh_tunnel_running": True,
                "remote_service": {"ActiveState": "active", "SubState": "running"},
            },
        }
        with _EnvSandbox(), ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_hil_dependency_preflight",
                    return_value={
                        "ok": True,
                        "resolved_workdir": "~/YggdraSIM",
                        "resolved_remote_python": "~/YggdraSIM/.venv/bin/python",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_local_start",
                    return_value={"ok": True, "note": "local"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_wait_for_local_card_bridge",
                    return_value={
                        "ok": True,
                        "token_file": "/tmp/bridge.token",
                        "reader": "Reader A",
                        "atr": "3B00",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_reset_local_card_bridge",
                    return_value={
                        "ok": True,
                        "token_file": "/tmp/bridge.token",
                        "reader": "Reader A",
                        "atr": "3B00",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_tunnel_start",
                    return_value={"ok": True, "note": "tunnel"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_card_ping",
                    return_value={"ok": True, "note": "ping"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_sync_token",
                    return_value={"ok": True, "note": "sync"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_card_status",
                    return_value={"ok": True, "note": "status"},
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_remote_remsim_binary_status",
                    return_value={
                        "ok": False,
                        "remsim_binary": "osmo-remsim-client-st2",
                        "note": "Remote REMSIM binary not found.",
                    },
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_install_remote_service",
                    side_effect=AssertionError,
                )
            )
            stack.enter_context(
                patch.object(
                    cb,
                    "_dispatch_remote_rig_status",
                    return_value=status_payload,
                )
            )
            payload = cb._dispatch_remote_rig_start(
                ActionContext(),
                ssh_target="pi@rpi-host",
                reader_index=0,
                local_card_port=8642,
                remote_card_port=8642,
                confirm=True,
            )

        self.assertFalse(payload["ok"], msg=str(payload))
        self.assertEqual(payload["steps"][-1]["name"], "rpi_remsim_binary")
        self.assertIn("REMSIM", payload["note"])

    def test_probe_apdu_suffix_stripped(self) -> None:
        bridge = _StubBridge(
            status_payload={"authRequired": False, "host": "127.0.0.1"}
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url + "/apdu",
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertTrue(payload["ok"], msg=str(payload))
        self.assertEqual(payload["url"], bridge.url)

    def test_probe_does_not_leak_token_in_response(self) -> None:
        bridge = _StubBridge(
            require_token="should-not-appear",
            status_payload={
                "authRequired": True,
                "tokenFingerprint": _fingerprint("should-not-appear"),
            },
        )
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    token="should-not-appear",
                    use_configured=False,
                )
        finally:
            bridge.close()
        serialised = json.dumps(payload)
        self.assertNotIn("should-not-appear", serialised)
        self.assertIn(_fingerprint("should-not-appear"), serialised)

    def test_probe_ping_failure_short_circuits(self) -> None:
        bridge = _StubBridge(ping_status=503)
        try:
            with _EnvSandbox():
                payload = cb._dispatch_probe(
                    ActionContext(),
                    url=bridge.url,
                    use_configured=False,
                )
        finally:
            bridge.close()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload.get("ping_status"), 503)
        # status_status must not be reported because we never reach /status.
        self.assertNotIn("status_status", payload)


if __name__ == "__main__":
    unittest.main()


def test_the_readiness_wait_outlasts_the_supervisors_own_retry() -> None:
    """A wait shorter than the retry it waits on can never succeed.

    The supervisor pauses 15 s between bridge restarts whenever a remote
    card is configured, so a 14 s readiness wait reported a failure for
    every rig that happened to be mid-retry, including ones that came up
    moments later.
    """
    from Tools.HilBridge.supervisor import (
        DEFAULT_REMOTE_CARD_RESTART_BACKOFF_SECONDS,
    )
    from yggdrasim_common.gui_server.actions.card_bridge import (
        _REMOTE_HIL_READY_TIMEOUT_SECONDS,
    )

    assert (
        _REMOTE_HIL_READY_TIMEOUT_SECONDS
        > DEFAULT_REMOTE_CARD_RESTART_BACKOFF_SECONDS * 2
    )


def test_the_remote_card_url_and_token_follow_the_chosen_port() -> None:
    """A default pinned to one port outranks the port actually chosen.

    The rig is then handed one port's URL with another port's token and
    fails authentication in a loop until the relay locks the peer out.
    """
    from yggdrasim_common.gui_server.actions.card_bridge import (
        INSTALL_REMOTE_SERVICE_SPEC,
        REMOTE_RIG_START_SPEC,
        SYNC_TOKEN_SPEC,
    )

    # Install RPi HIL service is its own button, so a fixed default there
    # writes a unit for one port against a bridge serving another.
    for spec in (REMOTE_RIG_START_SPEC, INSTALL_REMOTE_SERVICE_SPEC, SYNC_TOKEN_SPEC):
        fields = {field.name: field for field in spec.inputs}
        for name in ("remote_card_url", "remote_token_file"):
            if name not in fields:
                continue
            assert not str(fields[name].default or ""), (
                f"{spec.id}.{name} must have no default so the port-derived "
                "value wins"
            )


def test_the_operator_token_never_lands_in_a_rigs_own_bridge_namespace() -> None:
    """A Card Bridge owns ``card_bridge/<port>.token`` for the bridge it serves.

    Writing the operator's token there replaces the rig's own credential:
    its lab agent then authenticates to its own bridge with somebody
    else's token, 401s, and is rate-limited out of its own card while
    every health field still reads ok.
    """
    from yggdrasim_common.gui_server.actions.card_bridge import (
        _DEFAULT_REMOTE_TOKEN_FILE,
        _normalize_remote_card_token_path,
        _remote_card_token_path,
    )

    cases = {
        "~/.config/yggdrasim/card_bridge/8642.token": (
            "~/.config/yggdrasim/hil/remote-card-8642.token"
        ),
        "/home/esim/.config/yggdrasim/card_bridge/8908.token": (
            "/home/esim/.config/yggdrasim/hil/remote-card-8908.token"
        ),
        # Punctuation must not carry a path past the rewrite.
        "~/.config/yggdrasim/card_bridge//8642.token": (
            "~/.config/yggdrasim/hil/remote-card-8642.token"
        ),
        "~/.config/yggdrasim/./card_bridge/8642.token": (
            "~/.config/yggdrasim/hil/remote-card-8642.token"
        ),
    }
    for given, expected in cases.items():
        assert _normalize_remote_card_token_path(given) == expected

    # The rewrite is idempotent, and the paths the action itself produces
    # already sit outside the namespace, so they pass through untouched.
    for path in (
        _DEFAULT_REMOTE_TOKEN_FILE,
        _remote_card_token_path(8642),
        _remote_card_token_path(8908),
        _remote_card_token_path("8801"),
        "~/.config/yggdrasim/hil/remote-card-8642.token",
    ):
        assert _normalize_remote_card_token_path(path) == path
    assert _normalize_remote_card_token_path("") == ""
    assert _normalize_remote_card_token_path(None) == ""


def test_a_legacy_token_path_from_saved_state_is_rewritten_not_refused() -> None:
    """The rig marker carries the path the previous default wrote.

    Saved state outlives the default that produced it, so the legacy value
    comes back on the next start. Refusing it would strand every host set
    up by the older release; the sync rewrites it and proceeds.
    """
    import tempfile
    from pathlib import Path

    from yggdrasim_common.gui_server.actions import card_bridge as cb

    with tempfile.TemporaryDirectory() as tmp:
        local = Path(tmp) / "local.token"
        local.write_text("operator-token\n", encoding="utf-8")
        with mock.patch.object(cb, "_run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "returncode": 0, "stdout": "", "stderr": ""}
            payload = cb._dispatch_sync_token(
                mock.MagicMock(),
                ssh_target="esim@rig.example.test",
                local_token_file=str(local),
                remote_token_file="~/.config/yggdrasim/card_bridge/8642.token",
                confirm=True,
            )

    assert payload["remote_token_file"] == (
        "~/.config/yggdrasim/hil/remote-card-8642.token"
    )
    assert ssh.call_count == 1
    remote_command = ssh.call_args.kwargs["remote_command"]
    assert "card_bridge" not in remote_command
    assert "hil/remote-card-8642.token" in remote_command
    assert "operator-token" not in json.dumps(payload)


def test_the_rendered_unit_reads_the_same_path_the_sync_writes() -> None:
    """A unit pointing at the old path would read a file nothing writes."""
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    unit_text = cb._render_remote_hil_unit(
        remote_workdir="~/YggdraSIM",
        remote_python="~/YggdraSIM/.venv/bin/python",
        remote_card_url="http://127.0.0.1:8908/apdu",
        remote_token_file="~/.config/yggdrasim/card_bridge/8908.token",
        remsim_binary="/usr/bin/osmo-remsim-client-st2",
        usb_vidpid="1d50:60e3",
        hil_port=9997,
        apdu_timeout_ms=30000,
    )
    assert "card_bridge" not in unit_text
    assert (
        "--remote-card-token-file %h/.config/yggdrasim/hil/remote-card-8908.token"
        in unit_text
    )


def test_a_recorded_token_path_for_another_port_is_discarded() -> None:
    """The bridge names its token after the port it serves.

    A marker written when the bridge ran on one port survives a move to
    another, and reading it hands out a token the running bridge never
    had. An operator's own path carries no port and is kept.
    """
    from yggdrasim_common.gui_server.actions.card_bridge import (
        _local_token_file_for_port,
    )

    assert _local_token_file_for_port(8908, "~/.config/yggdrasim/card_bridge/8642.token") == ""
    assert _local_token_file_for_port(8908, "/x/card_bridge/8642.token") == ""
    kept = "~/.config/yggdrasim/card_bridge/8908.token"
    assert _local_token_file_for_port(8908, kept) == kept
    assert _local_token_file_for_port(8908, "~/my-own.token") == "~/my-own.token"
    assert _local_token_file_for_port(8908, "") == ""
    assert _local_token_file_for_port(8908, None) == ""


def test_the_sync_reads_and_writes_the_token_for_the_ports_in_use() -> None:
    """Blank fields must resolve to the ports the session runs on.

    A fallback pinned to one port reads that port's token and ships it to
    a rig dialling another, which authenticates in a loop until the relay
    locks the peer out.
    """
    from yggdrasim_common.card_bridge_auth import default_token_file_for_port
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    written = []
    for port, value in ((8642, "wrong-port-token"), (8908, "right-port-token")):
        path = default_token_file_for_port(port)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value + "\n", encoding="utf-8")
        written.append(path)
    try:
        with mock.patch.object(cb, "_run_ssh_command") as ssh:
            ssh.return_value = {
                "ok": True,
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            }
            payload = cb._dispatch_sync_token(
                mock.MagicMock(),
                ssh_target="esim@rig.example.test",
                local_card_port=8908,
                remote_card_port=8908,
                confirm=True,
            )
    finally:
        for path in written:
            path.unlink(missing_ok=True)

    assert payload["token_fingerprint"] == _fingerprint("right-port-token")
    assert payload["remote_token_file"] == (
        "~/.config/yggdrasim/hil/remote-card-8908.token"
    )
    assert ssh.call_args.kwargs["stdin_text"] == "right-port-token\n"


def test_moving_the_bridge_port_never_leaves_the_old_ports_token_behind() -> None:
    """The rig marker merges, so a key left out keeps the previous value.

    A session on one port recorded its token file; the next session moved
    the bridge to another port and rewrote only the port, so the marker
    then paired a live port with a dead port's token and every reader
    that trusted it authenticated with the wrong credential.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    cb._write_remote_rig_state({
        "local_card_bridge_port": 8642,
        "local_card_bridge_token_file": (
            "/home/example/.config/yggdrasim/card_bridge/8642.token"
        ),
    })

    class _Process:
        pid = 4242

        def poll(self):
            return None

    with mock.patch.object(cb.subprocess, "Popen", return_value=_Process()):
        with mock.patch.object(cb.time, "sleep", lambda _s: None):
            payload = cb._dispatch_local_start(
                mock.MagicMock(),
                port=8908,
                reader_index=0,
                reuse_existing=False,
                confirm=True,
            )

    assert payload["ok"] is True
    state = cb._load_remote_rig_state()
    assert state["local_card_bridge_port"] == 8908
    assert "8642" not in str(state["local_card_bridge_token_file"])


def test_a_failed_start_never_tears_down_the_running_session_first() -> None:
    """Restart-in-place is bought with the lease tolerance, not a pre-stop.

    Stopping the remote session before the local preconditions made every
    unrelated failure destructive: five early returns and two raises sit
    between that point and the restart, so a start that aborted at, say,
    the local bridge left the rig stopped when it had been streaming.
    The 409 tolerance alone restores in-place restarts, and costs nothing
    when the start fails.
    """
    import inspect

    from yggdrasim_common.gui_server.actions import card_bridge as cb

    source = inspect.getsource(cb._dispatch_remote_rig_start)
    reset_at = source.index('"pc_bridge_reset"')
    service_at = source.index('"rpi_hil_service"')

    # Nothing may stop the remote service before the local path is proven.
    stop_calls = [
        line.strip()
        for line in source[:reset_at].splitlines()
        if 'action="stop"' in line
    ]
    assert stop_calls == [], (
        "a start must not stop the running session before it knows the "
        f"local card path works: {stop_calls}"
    )
    # The only service control in the start is the restart, and it comes
    # after the card path is verified.
    assert reset_at < service_at


def test_a_card_held_by_another_consumer_does_not_abandon_the_start() -> None:
    """The reset only refreshes a PC/SC handle.

    The rig's own supervisor claims the lease later and names the holder
    when it cannot, which is the authoritative gate. Failing the whole
    start at the reset replaced that message with a vaguer one.
    """
    from yggdrasim_common.gui_server.actions.card_bridge import (
        _tolerate_foreign_card_lease,
    )

    refused = {
        "ok": False,
        "port": 8908,
        "status_code": 409,
        "error": "reset returned HTTP 409: The card is leased by another consumer.",
        "note": "PC Card Bridge reset failed.",
    }
    tolerated = _tolerate_foreign_card_lease(refused)
    assert tolerated["ok"] is True
    assert tolerated["status"] == "skipped"
    assert "leased by another consumer" in tolerated["note"]

    # Every other failure still stops the start.
    for code in (0, 401, 404, 500, 503):
        hard = {**refused, "status_code": code}
        assert _tolerate_foreign_card_lease(hard)["ok"] is False, code
    assert _tolerate_foreign_card_lease({**refused, "status_code": "nonsense"})["ok"] is False

    # A successful reset is returned untouched.
    good = {"ok": True, "port": 8908, "status": "reset", "atr": "3B9F"}
    assert _tolerate_foreign_card_lease(good) is good


def test_the_rendered_unit_does_not_close_a_boot_ordering_cycle() -> None:
    """A unit WantedBy=default.target must not also be After=default.target.

    That names its own successor as a predecessor; systemd breaks the cycle
    by dropping a start job, silently and only at the next boot. The rig's
    Card Bridge unit carries the same rule in a comment after the cycle
    once left the lab agent dead after a reboot, and the GUI-rendered HIL
    unit reintroduced it.
    """
    from yggdrasim_common.gui_server.actions.card_bridge import (
        _render_remote_hil_unit,
    )

    unit_text = _render_remote_hil_unit(
        remote_workdir="~/YggdraSIM",
        remote_python="~/YggdraSIM/.venv/bin/python",
        remote_card_url="http://127.0.0.1:8908/apdu",
        remote_token_file="",
        remsim_binary="/usr/bin/osmo-remsim-client-st2",
        usb_vidpid="1d50:60e3",
        hil_port=9997,
        apdu_timeout_ms=30000,
    )

    wanted = [
        line.strip()
        for line in unit_text.splitlines()
        if line.strip().startswith("WantedBy=")
    ]
    ordered_after = {
        target.strip()
        for line in unit_text.splitlines()
        if line.strip().startswith("After=")
        for target in line.strip()[len("After=") :].split()
    }
    assert wanted, "the unit must still install itself somewhere"
    for line in wanted:
        for target in line[len("WantedBy=") :].split():
            assert target not in ordered_after, (
                f"{target} is both what installs the unit and what it waits "
                "for -- that is the ordering cycle systemd resolves by "
                "dropping the start job"
            )


def test_a_bridge_on_the_right_port_but_the_wrong_reader_is_not_adopted() -> None:
    """Answering on the port is not the same as serving the requested card.

    The reuse branch returned before reader_name was used for anything, so
    a bridge left bound to another reader was adopted, never restarted,
    and its card reset -- handing the rig, the SIMtrace2 and the modem the
    wrong card while every start step still reported success.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    assert cb._reader_selection_matches("Broadcom", "Broadcom Corp 58200 [Contacted] 00 00")
    assert cb._reader_selection_matches("broadcom", "Broadcom Corp 58200 [Contacted] 00 00")
    # No reader named means any reader is what was asked for.
    assert cb._reader_selection_matches("", "Gemalto PC Twin Reader (016BF80B) 00 00")
    assert not cb._reader_selection_matches("Broadcom", "Gemalto PC Twin Reader (016BF80B) 00 00")

    running = {
        "ok": True,
        "port": 8908,
        "reader": "Gemalto PC Twin Reader (016BF80B) 00 00",
        "token_file": "/tmp/t.token",
    }
    with mock.patch.object(cb, "_wait_for_local_card_bridge", return_value=running):
        with mock.patch.object(cb, "_pid_is_running", return_value=False):
            result = cb._dispatch_local_start(
                mock.MagicMock(),
                port=8908,
                reader_name="Broadcom",
                reuse_existing=True,
                confirm=True,
            )

    # Reported rather than raised: a raise out of a dispatcher makes the
    # action route drop the rig-start's whole step list.
    assert result["ok"] is False
    assert "not the requested" in str(result.get("error"))
    assert result["reader"] == "Gemalto PC Twin Reader (016BF80B) 00 00"


def test_stopping_the_bridge_drops_this_guis_claim_on_the_port() -> None:
    """The marker merges, so an ownership key outlives what it described.

    Shutdown read the mere presence of those keys as "this GUI owns a
    bridge here" and stopped whatever was listening on that port next --
    including one an operator started by hand to keep a rig streaming.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    cb._write_remote_rig_state({
        "local_card_bridge_pid": 4242,
        "local_card_bridge_port": 8908,
        "local_card_bridge_log": "/tmp/bridge.log",
        "local_card_bridge_command": ["python", "-m", "Tools.CardBridge"],
        "local_card_bridge_external": False,
    })
    with mock.patch.object(
        cb,
        "_terminate_local_card_bridge_for_state",
        return_value={"ok": True, "status": "stopped"},
    ):
        cb._dispatch_local_stop(mock.MagicMock(), confirm=True)

    state = cb._load_remote_rig_state()
    for key in (
        "local_card_bridge_pid",
        "local_card_bridge_port",
        "local_card_bridge_log",
        "local_card_bridge_command",
    ):
        assert not state.get(key), f"{key} still claims a bridge after a stop"


def test_a_bridge_this_gui_only_adopted_is_never_hunted_down_by_port() -> None:
    """A recorded pid is the only thing the GUI may stop for a bridge it adopted.

    Falling back to "terminate whatever holds the port" ends a Card Bridge
    somebody else runs, and the rig streaming through it loses the card.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    adopted = {
        "local_card_bridge_pid": 0,
        "local_card_bridge_port": 8908,
        "local_card_bridge_external": True,
    }
    with mock.patch.object(cb, "_find_local_card_bridge_listener_pid") as finder:
        result = cb._terminate_local_card_bridge_for_state(adopted)
    assert finder.call_count == 0, "an adopted bridge must not be hunted by port"
    assert "adopted" in str(result.get("note", ""))

    # One this GUI started is still cleaned up when its pid is already gone.
    owned = {
        "local_card_bridge_pid": 0,
        "local_card_bridge_port": 8908,
        "local_card_bridge_external": False,
    }
    with mock.patch.object(
        cb, "_find_local_card_bridge_listener_pid", return_value=0
    ) as finder:
        cb._terminate_local_card_bridge_for_state(owned)
    assert finder.call_count == 1


def test_a_cleared_marker_port_reads_as_none_recorded_not_as_an_error() -> None:
    """A stop writes 0 to drop this GUI's claim on the port.

    0 is not a port, so coercing it raises rather than falling back, and
    the next stop died with "port out of range: 0" before doing anything.
    A falsy record means no port was recorded, not an invalid one.
    """
    from yggdrasim_common.gui_server.actions.card_bridge import (
        _DEFAULT_CARD_PORT,
        _recorded_card_port,
    )

    for empty in ({}, {"local_card_bridge_port": 0}, {"local_card_bridge_port": None},
                  {"local_card_bridge_port": ""}):
        assert _recorded_card_port(empty) == _DEFAULT_CARD_PORT, empty
    assert _recorded_card_port({"local_card_bridge_port": 8908}) == 8908
    assert _recorded_card_port({"local_card_bridge_port": "8908"}) == 8908


def test_stopping_twice_in_a_row_succeeds() -> None:
    """The second stop used to fail on the marker the first one wrote.

    Clearing the port claim is what keeps shutdown from adopting somebody
    else's bridge, so the cleared value has to be readable by everything
    that reads it back -- including the next stop.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    cb._write_remote_rig_state({
        "local_card_bridge_pid": 0,
        "local_card_bridge_port": 8908,
        "local_card_bridge_external": False,
    })
    with mock.patch.object(cb, "_find_local_card_bridge_listener_pid", return_value=0):
        cb._dispatch_local_stop(mock.MagicMock(), confirm=True)
        # The second call reads back the marker the first one wrote. It
        # used to raise ValueError("port out of range: 0") before doing
        # anything, so the action failed rather than reporting a no-op.
        second = cb._dispatch_local_stop(mock.MagicMock(), confirm=True)

    assert isinstance(second, dict)
    assert "port out of range" not in str(second.get("error") or "")
    assert not cb._load_remote_rig_state().get("local_card_bridge_port")


def test_a_rig_serving_its_own_card_on_that_port_is_named_not_guessed() -> None:
    """The default remote port is the one a rig's own Card Bridge uses.

    The reverse tunnel then cannot own it, so the rig reaches its own
    bridge with the operator's token and the start dies on
    "could not authenticate" -- which describes the symptom and hides the
    collision. sshd on the port is our own tunnel and fine.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    def _listening(*addresses):
        return {
            "ok": True,
            "returncode": 0,
            "stdout": "\n".join(addresses),
            "stderr": "",
        }

    # The rig's own Card Bridge holds the default port, so the tunnel
    # takes another one rather than the start failing later on a token.
    with mock.patch.object(
        cb, "_run_ssh_command", return_value=_listening("127.0.0.1:8642", "0.0.0.0:22")
    ):
        moved = cb._choose_free_remote_card_port(
            ssh_target="esim@rig.example.test", preferred_port=8642
        )
    assert moved["ok"] is True
    assert moved["port"] != 8642
    assert moved["moved_from"] == 8642
    assert "its own Card Bridge" in moved["note"]

    # A free preferred port is kept.
    with mock.patch.object(
        cb, "_run_ssh_command", return_value=_listening("127.0.0.1:8642", "0.0.0.0:22")
    ):
        kept = cb._choose_free_remote_card_port(
            ssh_target="esim@rig.example.test", preferred_port=8908
        )
    assert kept["ok"] is True and kept["port"] == 8908 and "moved_from" not in kept

    # Everything taken is a refusal that names the ports.
    busy = ["127.0.0.1:8642"] + [
        f"127.0.0.1:{port}" for port in cb._REMOTE_CARD_PORT_FALLBACKS
    ]
    with mock.patch.object(cb, "_run_ssh_command", return_value=_listening(*busy)):
        stuck = cb._choose_free_remote_card_port(
            ssh_target="esim@rig.example.test", preferred_port=8642
        )
    assert stuck["ok"] is False and "8642" in stuck["note"]

    # A probe that cannot run must not block a start.
    with mock.patch.object(
        cb,
        "_run_ssh_command",
        return_value={"ok": False, "returncode": 255, "stdout": "", "stderr": "down"},
    ):
        unknown = cb._choose_free_remote_card_port(
            ssh_target="esim@rig.example.test", preferred_port=8642
        )
    assert unknown["ok"] is True and unknown["port"] == 8642


def test_the_start_checks_the_remote_port_before_it_trusts_the_tunnel() -> None:
    """Checked after the tunnel starts and before anything uses it."""
    import inspect

    from yggdrasim_common.gui_server.actions import card_bridge as cb

    source = inspect.getsource(cb._dispatch_remote_rig_start)
    free_at = source.index('"rpi_port_free"')
    tunnel_at = source.index('"ssh_tunnel_start"')
    status_at = source.index('"rpi_bridge_status"')
    assert free_at < tunnel_at < status_at, (
        "the port has to be settled before the tunnel binds it and before "
        "the URL, token path and unit are derived from it -- and before "
        "the steps whose failure it would otherwise be blamed for"
    )


def test_shutdown_stops_the_rig_before_taking_away_its_card() -> None:
    """Closing the GUI takes away the Card Bridge the rig streams from.

    Its supervisor holds the operator's card lease and drives a REMSIM
    client, and both outlive this process. Stopping only the local halves
    left the rig running against a card that was gone -- holding a lease
    nothing would release, and colliding with the next session. Nothing on
    the rig clears that by itself and nothing in the GUI could reach it
    afterwards, which is why it has to happen here, first.
    """
    from unittest import mock

    from yggdrasim_common.gui_server import lifecycle
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    cb._write_remote_rig_state({
        "ssh_target": "esim@rig.example.test",
        "service_name": "yggdrasim-hil-supervisor.service",
        "ssh_tunnel_pid": 4242,
        "local_card_bridge_pid": 4243,
        "local_card_bridge_port": 8908,
        "local_card_bridge_external": False,
    })

    calls = []
    with mock.patch.object(
        cb, "_dispatch_remote_service_control",
        lambda *a, **k: calls.append(("remote", k.get("action"))) or {"ok": True},
    ):
        with mock.patch.object(
            cb, "_dispatch_tunnel_stop",
            lambda *a, **k: calls.append(("tunnel", None)) or {"ok": True},
        ):
            with mock.patch.object(
                cb, "_dispatch_local_stop",
                lambda *a, **k: calls.append(("bridge", None)) or {"ok": True},
            ):
                lifecycle._stop_card_bridge_runtime_state()

    assert ("remote", "stop") in calls, "the rig's service must be stopped too"
    # The rig first: it is the one that cannot be reached afterwards.
    assert calls.index(("remote", "stop")) < calls.index(("bridge", None))


def test_shutdown_leaves_a_rig_alone_when_none_was_configured() -> None:
    """No ssh target means no rig of ours to stop."""
    from unittest import mock

    from yggdrasim_common.gui_server import lifecycle
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    cb._write_remote_rig_state({
        "ssh_target": "",
        "ssh_tunnel_pid": 0,
        "local_card_bridge_pid": 0,
        "local_card_bridge_port": 0,
        "local_card_bridge_log": "",
        "local_card_bridge_command": [],
    })

    with mock.patch.object(cb, "_dispatch_remote_service_control") as remote:
        lifecycle._stop_card_bridge_runtime_state()
    assert remote.call_count == 0


def test_every_stream_start_reboots_the_rigs_simtrace2() -> None:
    """The board keeps card-emulation state across a session otherwise.

    Locally the supervisor clears it before each bridge generation
    (``_reset_device_before_session``), which a restart of the process
    always reaches because no bridge child is running yet. The rig gets
    the same treatment only as long as the start path *restarts* its
    unit: a plain ``systemctl --user start`` against an already-active
    unit is a no-op, the supervisor keeps running, and the SIMtrace2
    carries the previous session's state into the new one.
    """
    import inspect

    from yggdrasim_common.gui_server.actions import card_bridge as cb

    install = inspect.getsource(cb._dispatch_install_remote_service)
    assert "systemctl --user restart" in install
    assert "systemctl --user start " not in install

    start = inspect.getsource(cb._dispatch_remote_rig_start)
    # Whichever branch the start takes -- installing the unit or driving
    # an installed one -- it has to end in a restart.
    assert "start_now=True" in start
    assert 'action="restart"' in start
    assert 'action="start"' not in start


def test_the_rendered_unit_never_disables_the_pre_session_reset() -> None:
    """An unset knob leaves the supervisor on its own default.

    ``--simtrace-reset off`` and ``--no-simtrace-reset`` both turn the
    reset off for good, and a unit is reinstalled on every start, so one
    of those reaching the ExecStart line would silently retire the
    clean-board guarantee for that rig.
    """
    from yggdrasim_common.gui_server.actions import card_bridge as cb

    unit = cb._render_remote_hil_unit(
        remote_workdir="/home/esim/YggdraSIM",
        remote_python="/home/esim/YggdraSIM/.venv/bin/python",
        service_name="yggdrasim-hil-supervisor.service",
        remote_card_url="http://127.0.0.1:8908/apdu",
        remote_token_file="/home/esim/.config/yggdrasim/hil/remote-card-8908.token",
    )
    assert "--no-simtrace-reset" not in unit
    assert "--simtrace-reset off" not in unit

    # An explicit mode is passed through, including the VBUS cycle that
    # also clears the card itself.
    powered = cb._render_remote_hil_unit(
        remote_workdir="/home/esim/YggdraSIM",
        remote_python="/home/esim/YggdraSIM/.venv/bin/python",
        simtrace_reset="port-power",
        uhubctl_location="1-1",
        uhubctl_port="2",
    )
    assert "--simtrace-reset port-power" in powered
    assert "--uhubctl-location 1-1" in powered
    assert "--uhubctl-port 2" in powered
