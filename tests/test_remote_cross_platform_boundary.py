# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Portable Remote Lab/CardBridge dependency and transport contracts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any
from urllib import request as urllib_request

import pytest


_ROOT = Path(__file__).resolve().parents[1]


def test_clean_desktop_remote_stack_does_not_import_local_hil(
    tmp_path: Path,
) -> None:
    """The Windows/macOS client path must not pull in Linux HIL modules."""

    script = textwrap.dedent(
        """
        import builtins
        import json
        from pathlib import Path

        blocked = {
            "pyudev",
            "Tools.HilBridge.supervisor",
            "yggdrasim_common.hil_bridge_runtime",
        }
        attempts = []
        original_import = builtins.__import__

        def guarded_import(name, *args, **kwargs):
            if any(name == item or name.startswith(item + ".") for item in blocked):
                attempts.append(name)
                raise ImportError("blocked clean dependency: " + name)
            return original_import(name, *args, **kwargs)

        builtins.__import__ = guarded_import

        from Tools.CardBridge import server
        from yggdrasim_common.gui_server.actions import card_bridge
        from yggdrasim_common.gui_server.routes import remote_lab
        from yggdrasim_common.remote_lab import client, registry

        marker = card_bridge._publish_local_card_relay_marker(
            port=8642,
            token_file="portable.token",
        )
        marker_path = Path(marker["marker_path"])
        assert marker_path.is_file()
        card_bridge._clear_local_card_relay_marker()
        assert not marker_path.exists()
        print(json.dumps({
            "attempts": attempts,
            "modules": [
                server.__name__,
                card_bridge.__name__,
                remote_lab.__name__,
                client.__name__,
                registry.__name__,
            ],
        }))
        """
    )
    env = dict(os.environ)
    env["YGGDRASIM_RUNTIME_ROOT"] = str(tmp_path)
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["attempts"] == []
    assert len(payload["modules"]) == 5


def test_missing_ssh_client_returns_actionable_structured_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.gui_server.actions import card_bridge

    monkeypatch.setattr(card_bridge.shutil, "which", lambda _candidate: None)
    result = card_bridge._run_ssh_command(
        ssh_target="operator@lab.example.test",
        remote_command="true",
        ssh_path="missing-openssh-client",
    )
    assert result["ok"] is False
    assert result["returncode"] == 127
    assert result["command"] == []
    assert "SSH executable was not found" in result["stderr"]


def test_remote_remsim_discovery_never_checks_the_desktop_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yggdrasim_common.gui_server.actions import card_bridge

    calls: list[dict[str, Any]] = []

    def fake_ssh(**kwargs: Any) -> dict[str, Any]:
        calls.append(dict(kwargs))
        return {
            "ok": True,
            "returncode": 0,
            "stdout": "/usr/bin/osmo-remsim-client-st2\n",
            "stderr": "",
            "command": ["ssh"],
        }

    def reject_local_lookup(candidate: str) -> str | None:
        if "remsim" in str(candidate):
            raise AssertionError("REMSIM was looked up on the desktop host")
        return None

    monkeypatch.setattr(card_bridge, "_run_ssh_command", fake_ssh)
    monkeypatch.setattr(card_bridge.shutil, "which", reject_local_lookup)
    result = card_bridge._remote_remsim_binary_status(
        ssh_target="operator@lab.example.test",
        ssh_path="ssh",
        remsim_binary="osmo-remsim-client-st2",
    )
    assert result["ok"] is True
    assert result["resolved_remsim_binary"] == "/usr/bin/osmo-remsim-client-st2"
    assert len(calls) == 1
    assert "command -v" in calls[0]["remote_command"]
    assert "osmo-remsim-client-st2" in calls[0]["remote_command"]


def test_clean_bundle_keeps_portable_relay_and_excludes_local_hil() -> None:
    spec = (_ROOT / "yggdrasim_main.spec").read_text(encoding="utf-8")
    assert '"Tools.HilBridge.apdu_relay"' in spec
    assert '"Tools.HilBridge.pcsc"' in spec
    assert '"Tools.HilBridge.supervisor"' in spec
    assert '"yggdrasim_common.hil_bridge_runtime"' in spec
    assert '"pyudev"' in spec
    assert "if INCLUDE_HIL is False:" in spec


def test_apdu_relay_can_bind_and_answer_on_ipv6_loopback() -> None:
    from Tools.HilBridge.apdu_relay import (
        ApduRelayConfig,
        HilBridgeApduRelayService,
    )

    service = HilBridgeApduRelayService(
        ApduRelayConfig(host="::1", port=0),
        exchange_callback=lambda _apdu, **_kwargs: (b"", 0x90, 0x00),
        status_callback=lambda: {"status": "ok"},
    )
    try:
        try:
            service.start()
        except OSError as exc:
            pytest.skip(f"IPv6 loopback is unavailable on this host: {exc}")
        assert service.base_url.startswith("http://[::1]:")
        opener = urllib_request.build_opener(urllib_request.ProxyHandler({}))
        with opener.open(service.base_url + "/ping", timeout=5) as response:
            assert response.status == 200
            assert response.read() == b"pong\n"
    finally:
        service.stop()
