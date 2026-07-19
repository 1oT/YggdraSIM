# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Focused regression coverage for runtime privacy boundaries."""
from __future__ import annotations

import base64
import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from SCP11.eim_local.response_logger import EimResponseLogger
from Tools.HilBridge.live_decode_view import (
    MAX_PDML_DEPTH,
    MAX_PDML_TEXT_CHARS,
    parse_packet_field_ranges,
)
from yggdrasim_common.gui_server.action_security import scrub_action_result
from yggdrasim_common.gui_server import auth as gui_auth
from yggdrasim_common.secure_files import (
    assert_private_file,
    atomic_write_bytes,
    ensure_private_directory,
    harden_private_tree,
    read_bounded_private_file,
    read_bounded_regular_file,
)


def test_gui_app_constructs_without_posix_only_stdlib_modules() -> None:
    code = textwrap.dedent(
        """
        import builtins

        real_import = builtins.__import__
        blocked = {"fcntl", "termios", "resource"}

        def guarded_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name.split(".", 1)[0] in blocked:
                raise ImportError(name)
            return real_import(name, globals, locals, fromlist, level)

        builtins.__import__ = guarded_import

        from yggdrasim_common.gui_server.app import create_app
        from yggdrasim_common.gui_server.config import GuiServerConfig
        from yggdrasim_common.gui_server.routes.health import _rss_mib
        from yggdrasim_common.gui_server.routes.host_shell import get_capabilities
        from yggdrasim_common.gui_server.routes.terminal import list_modules

        config = GuiServerConfig(
            mode="desktop",
            host="127.0.0.1",
            port=0,
            token="x" * 32,
        )
        app = create_app(config)
        assert len(app.routes) > 0
        assert isinstance(_rss_mib(), float)
        assert list_modules()["supported"] is False
        assert get_capabilities()["supported"] is False
        """
    )
    subprocess.run(
        [sys.executable, "-c", code],
        cwd=Path(__file__).resolve().parents[1],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode assertion")
def test_private_helpers_override_permissive_umask(tmp_path: Path) -> None:
    old_umask = os.umask(0)
    try:
        private_dir = ensure_private_directory(tmp_path / "private")
        private_file = atomic_write_bytes(private_dir / "secret.bin", b"secret")
    finally:
        os.umask(old_umask)
    assert stat.S_IMODE(private_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(private_file.stat().st_mode) == 0o600
    assert assert_private_file(private_file) == private_file


def test_atomic_no_overwrite_preserves_existing_file(tmp_path: Path) -> None:
    target = atomic_write_bytes(tmp_path / "value.bin", b"first")
    with pytest.raises(FileExistsError):
        atomic_write_bytes(target, b"second", overwrite=False)
    assert target.read_bytes() == b"first"


def test_bounded_reader_rejects_links_and_oversized_files(tmp_path: Path) -> None:
    target = atomic_write_bytes(tmp_path / "value.bin", b"12345")
    with pytest.raises(ValueError, match="exceeds"):
        read_bounded_regular_file(target, 4)
    link = tmp_path / "value-link.bin"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(OSError):
        read_bounded_regular_file(link, 10)


@pytest.mark.skipif(os.name == "nt", reason="POSIX path-swap mechanics")
def test_private_reader_uses_descriptor_that_passed_permission_check(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    target = atomic_write_bytes(tmp_path / "signing-key.pem", b"trusted-private-bytes")
    replacement = atomic_write_bytes(tmp_path / "replacement.pem", b"replacement-bytes")
    displaced = tmp_path / "signing-key.opened"
    real_open = os.open
    swapped = False

    def open_then_swap(path, flags, *args, **kwargs):
        nonlocal swapped
        descriptor = real_open(path, flags, *args, **kwargs)
        if Path(path) == target and not swapped:
            swapped = True
            target.rename(displaced)
            replacement.rename(target)
        return descriptor

    monkeypatch.setattr("yggdrasim_common.secure_files.os.open", open_then_swap)
    assert read_bounded_private_file(target, 1024) == b"trusted-private-bytes"
    assert target.read_bytes() == b"replacement-bytes"


def test_private_tree_migration_rejects_links(tmp_path: Path) -> None:
    private_tree = tmp_path / "private"
    private_tree.mkdir()
    target = tmp_path / "outside.bin"
    target.write_bytes(b"not part of the private tree")
    link = private_tree / "linked.bin"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(OSError):
        harden_private_tree(private_tree)


@pytest.mark.skipif(os.name == "nt", reason="POSIX mode assertion")
def test_assert_private_file_rejects_public_mode(tmp_path: Path) -> None:
    target = tmp_path / "public.bin"
    target.write_bytes(b"secret")
    target.chmod(0o644)
    with pytest.raises(PermissionError):
        assert_private_file(target)


def test_eim_response_log_is_private_rotatable_and_minimised(
    tmp_path: Path,
) -> None:
    path = tmp_path / "private" / "responses.jsonl"
    logger = EimResponseLogger(str(path))
    logger.append_event({
        "action": "poll",
        "success": True,
        "package_path": "/private/operator/profile.der",
        "transaction_id_hex": "DEADBEEF",
        "eid": "89049032000000000000000000000001",
        "response_preview_hex": "CAFEBABE",
        "error_message": "private failure detail",
        "details": {
            "payload_hex": "A1B2",
            "retry_count": 2,
        },
    })
    row = json.loads(path.read_text(encoding="utf-8"))
    assert row["package_name"] == "profile.der"
    assert row["transaction_id_hex_id"]
    assert row["eid_id"]
    assert row["details"] == {"retry_count": 2}
    serialised = json.dumps(row)
    for secret in (
        "/private/operator",
        "DEADBEEF",
        "89049032000000000000000000000001",
        "CAFEBABE",
        "A1B2",
        "private failure detail",
    ):
        assert secret not in serialised
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_eim_response_log_rotates_at_budget(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from SCP11.eim_local import response_logger

    monkeypatch.setattr(response_logger, "_MAX_LOG_BYTES", 120)
    path = tmp_path / "responses.jsonl"
    logger = response_logger.EimResponseLogger(str(path))
    logger.append_event({"action": "first", "success": True})
    logger.append_event({"action": "second", "success": True})
    assert path.is_file()
    assert Path(f"{path}.1").is_file()


def test_action_result_scrubber_removes_known_secret_outputs() -> None:
    assert scrub_action_result(
        "scp03.derive_opc",
        {"ki": "11" * 16, "op": "22" * 16, "opc": "33" * 16},
    ) == {
        "opc": "33" * 16,
        "secret_outputs_redacted": ["ki", "op"],
    }
    private = scrub_action_result(
        "saip.ssim_eaptls_inspect",
        {"kind": "private_key", "der_hex": "DEADBEEF", "metadata": {}},
    )
    assert "der_hex" not in private
    assert private["secret_outputs_redacted"] == ["der_hex"]


def test_card_session_close_purges_scoped_raw_apdu_capture() -> None:
    from yggdrasim_common.apdu_recorder import ApduExchange, get_recorder
    from yggdrasim_common.gui_server.sessions import SessionManager

    scope = "security-test-reader"
    recorder = get_recorder()
    recorder.clear()
    recorder.enable_raw_capture(
        scope,
        ttl_seconds=30,
        consent="I_UNDERSTAND_RAW_APDU_SECRETS",
    )
    recorder.record(
        ApduExchange(
            ts=0.0,
            source=scope,
            apdu_hex="002000010431323334",
            data_hex="A1B2",
            sw_hex="9000",
            elapsed_ms=0.1,
            scope=scope,
            payload_redacted=False,
            raw_capture=True,
        )
    )
    assert recorder.snapshot(scope=scope)

    manager = SessionManager()
    session = manager.open(
        kind="scp03",
        handle={},
        close=lambda: None,
        metadata={"reader_name": scope},
    )
    assert manager.close(session.id) is True
    assert recorder.raw_capture_enabled(scope) is False
    assert recorder.snapshot(scope=scope) == []
    recorder.record(
        ApduExchange(
            ts=1.0,
            source=scope,
            apdu_hex="002000010431323334",
            data_hex="A1B2",
            sw_hex="9000",
            elapsed_ms=0.1,
            scope=scope,
            payload_redacted=False,
            raw_capture=True,
        )
    )
    after_revoke = recorder.snapshot(scope=scope)
    assert len(after_revoke) == 1
    assert after_revoke[0].payload_redacted is True
    assert after_revoke[0].apdu_hex == "00200001"
    assert after_revoke[0].data_hex == ""
    recorder.clear()


def test_identified_action_inputs_are_declared_secret() -> None:
    from yggdrasim_common.gui_server.actions.saip import (
        OPEN_UPLOAD_SPEC,
        SSIM_EAPTLS_INSPECT_SPEC,
        SSIM_EAPTLS_MATCH_PAIR_SPEC,
    )
    from yggdrasim_common.gui_server.actions.scp03 import (
        DERIVE_OPC_SPEC,
        MANAGE_PIN_SPEC,
        PUT_KEY_SPEC,
    )
    from yggdrasim_common.gui_server.actions.simcard import (
        TUAK_DERIVE_TOPC_SPEC,
    )

    expected = {
        DERIVE_OPC_SPEC.id: {"ki", "op"},
        MANAGE_PIN_SPEC.id: {"pin", "new_pin", "puk"},
        PUT_KEY_SPEC.id: {"enc_key", "mac_key", "dek_key"},
        TUAK_DERIVE_TOPC_SPEC.id: {"top", "key"},
        SSIM_EAPTLS_INSPECT_SPEC.id: {"pem_or_der"},
        SSIM_EAPTLS_MATCH_PAIR_SPEC.id: {"private_key"},
        OPEN_UPLOAD_SPEC.id: {"content_base64"},
    }
    for spec in (
        DERIVE_OPC_SPEC,
        MANAGE_PIN_SPEC,
        PUT_KEY_SPEC,
        TUAK_DERIVE_TOPC_SPEC,
        SSIM_EAPTLS_INSPECT_SPEC,
        SSIM_EAPTLS_MATCH_PAIR_SPEC,
        OPEN_UPLOAD_SPEC,
    ):
        secret_names = {field.name for field in spec.inputs if field.secret}
        assert expected[spec.id] <= secret_names


def test_websocket_auth_uses_header_protocol_not_query_string() -> None:
    class _Socket:
        headers = {
            "sec-websocket-protocol": "yggdrasim, bearer.secret-token",
        }
        query_params = {"t": "query-token"}

    socket = _Socket()
    assert gui_auth.websocket_bearer(socket) == "secret-token"
    assert gui_auth.websocket_accept_protocol(socket) == "yggdrasim"

    socket.headers = {}
    assert gui_auth.websocket_bearer(socket) == ""


def test_csp_disallows_eval_and_cross_origin_websockets() -> None:
    csp = gui_auth._CSP_HEADER.decode("ascii")
    assert "unsafe-eval" not in csp
    assert "connect-src 'self'" in csp
    assert "connect-src 'self' ws:" not in csp


def test_pdml_parser_rejects_dtd_depth_and_oversized_input() -> None:
    assert parse_packet_field_ranges(
        '<!DOCTYPE pdml [<!ENTITY x "boom">]><pdml>&x;</pdml>'
    ) == []
    delayed_dtd = (
        "<!--"
        + ("x" * 5000)
        + '--><!DOCTYPE pdml [<!ENTITY x "boom">]><pdml>&x;</pdml>'
    )
    assert parse_packet_field_ranges(delayed_dtd) == []
    nested = "<field>" * (MAX_PDML_DEPTH + 2) + "</field>" * (
        MAX_PDML_DEPTH + 2
    )
    assert parse_packet_field_ranges(nested) == []
    assert parse_packet_field_ranges(" " * (MAX_PDML_TEXT_CHARS + 1)) == []


def test_saip_upload_size_cap_is_checked_before_decode(monkeypatch) -> None:
    from yggdrasim_common.gui_server.actions import saip

    monkeypatch.setattr(saip, "_MAX_SAIP_UPLOAD_BASE64_CHARS", 8)
    with pytest.raises(ValueError, match="64 MiB"):
        saip._dispatch_open_package_upload(
            ctx=None,
            filename="profile.der",
            content_base64=base64.b64encode(b"01234567").decode("ascii"),
        )


def test_saip_upload_directory_is_removed_with_session(
    monkeypatch,
    tmp_path: Path,
) -> None:
    from yggdrasim_common.gui_server.actions import saip
    from yggdrasim_common.gui_server.sessions import get_manager

    captured: dict[str, Path] = {}
    manager = get_manager()

    def _fake_open(_ctx, *, path):
        captured["path"] = Path(path)
        session = manager.open(
            kind="saip",
            handle={"source_path": str(path)},
            close=lambda: None,
        )
        return {"session_id": session.id, "source_path": str(path)}

    monkeypatch.setattr(saip, "_dispatch_open_package", _fake_open)
    monkeypatch.setattr(saip.tempfile, "gettempdir", lambda: str(tmp_path))
    response = saip._dispatch_open_package_upload(
        ctx=None,
        filename="../../profile.der",
        content_base64=base64.b64encode(b"profile").decode("ascii"),
    )
    upload_path = captured["path"]
    assert upload_path.name == "profile.der"
    assert upload_path.read_bytes() == b"profile"
    if os.name != "nt":
        assert stat.S_IMODE(upload_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(upload_path.parent.stat().st_mode) == 0o700
    assert response["source_path"] == "upload:profile.der"
    assert manager.close(response["session_id"]) is True
    assert not upload_path.parent.exists()
