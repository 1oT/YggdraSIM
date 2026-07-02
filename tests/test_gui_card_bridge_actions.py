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
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
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

    def test_detached_subprocess_kwargs_use_windows_process_group(self) -> None:
        from unittest.mock import patch

        with patch.object(cb.os, "name", "nt"):
            with patch.object(cb.subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True):
                self.assertEqual(cb._detached_subprocess_kwargs(), {"creationflags": 512})

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
                remote_python="~/YggdraSIM/python/bin/python",
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

    def test_remote_hil_unit_contains_remote_card_flags(self) -> None:
        unit_text = cb._render_remote_hil_unit(
            remote_workdir="~/YggdraSIM",
            remote_python="~/YggdraSIM/.venv/bin/python",
            remote_card_url="http://127.0.0.1:8642/apdu",
            remote_token_file="~/.config/yggdrasim/card_bridge/8642.token",
            remsim_binary="/usr/local/bin/osmo-remsim-client-st2",
            usb_vidpid="1d50:60e3",
            hil_port=9997,
            apdu_timeout_ms=30000,
        )
        self.assertIn("WorkingDirectory=%h/YggdraSIM", unit_text)
        self.assertIn("ExecStart=%h/YggdraSIM/.venv/bin/python", unit_text)
        self.assertNotIn("ExecStart=~/", unit_text)
        self.assertIn("--remote-card-url http://127.0.0.1:8642/apdu", unit_text)
        self.assertIn("--remote-card-token-file %h/.config/yggdrasim/card_bridge/8642.token", unit_text)
        self.assertIn("--remsim-binary /usr/local/bin/osmo-remsim-client-st2", unit_text)
        self.assertIn("--usb-vidpid 1d50:60e3", unit_text)
        self.assertIn("--apdu-timeout-ms 30000", unit_text)
        self.assertIn(
            "--gsmtap-capture-path %h/YggdraSIM/state/hil_termshark/live_capture.pcap",
            unit_text,
        )

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
                    remote_token_file="~/.config/yggdrasim/card_bridge/8642.token",
                    confirm=True,
                )

        self.assertTrue(payload["ok"])
        self.assertNotIn("secret-token-value", json.dumps(payload))
        self.assertEqual(payload["token_fingerprint"], _fingerprint("secret-token-value"))
        self.assertEqual(len(calls), 1)
        command, kwargs = calls[0]
        self.assertEqual(command[-2], "pi@rpi-host")
        self.assertIn("cat >", command[-1])
        self.assertEqual(kwargs["input"], "secret-token-value\n")

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
                "pc_bridge_start",
                "pc_bridge_verify",
                "pc_bridge_reset",
                "ssh_tunnel_start",
                "rpi_bridge_ping",
                "token_sync",
                "rpi_bridge_status",
                "rpi_remsim_binary",
                "rpi_hil_service",
                "rpi_hil_ready",
            ],
        )
        self.assertFalse(tunnel.call_args.kwargs["forward_gui"])
        self.assertEqual(sync.call_args.kwargs["local_token_file"], "/tmp/bridge.token")
        self.assertEqual(install.call_args.kwargs["remote_workdir"], "~/YggdraSIM")
        self.assertEqual(
            install.call_args.kwargs["remote_python"],
            "~/YggdraSIM/python/bin/python",
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
                "local_gui_port": 27854,
                "remote_workdir": "~/YggdraSIM",
                "remote_python": "~/YggdraSIM/python/bin/python",
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
