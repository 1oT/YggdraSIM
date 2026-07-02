# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Unit tests for ``Tools.EumDiag``.

Covers:

* :class:`SessionKeyBundle` validation (hex discipline, length checks,
  uppercase normalisation).
* Repository round-trip through atomic JSON write / load with the
  right file-mode (0o600 on POSIX).
* Constant-time comparison helper.
* ``tshark_runner`` argv assembly and env injection.
* CLI ``store-keys`` and ``inject-keys`` argparse wiring (tshark
  invocation is patched so the tests never require tshark).
* CLI refuses to proceed when key inputs are incomplete or the pcap
  is missing.
"""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from Tools.EumDiag.main import run_cli
from Tools.EumDiag.session_keys import (
    SessionKeyBundle,
    SessionKeyError,
    SessionKeyRepository,
    SESSION_KEYS_ENV_VAR,
    load_repository,
    write_repository_atomic,
)
from Tools.EumDiag.tshark_runner import (
    build_tshark_invocation,
    ensure_tshark_on_path,
    TsharkMissingError,
)


_ENC_HEX = "00112233445566778899AABBCCDDEEFF"
_MAC_HEX = "0123456789ABCDEF0123456789ABCDEF"
_DEK_HEX = "FEDCBA9876543210FEDCBA9876543210"


class SessionKeyBundleTests(unittest.TestCase):
    def test_from_hex_normalises_case_and_validates_length(self) -> None:
        bundle = SessionKeyBundle.from_hex(
            iccid="8988000000000000aaaa",
            shs_enc=_ENC_HEX.lower(),
            shs_mac=_MAC_HEX,
            dek=_DEK_HEX,
            comment="case=12345",
        )
        self.assertEqual(bundle.iccid, "8988000000000000AAAA")
        self.assertEqual(bundle.shs_enc_hex, _ENC_HEX.upper())
        self.assertEqual(bundle.shs_mac_hex, _MAC_HEX.upper())
        self.assertEqual(bundle.dek_hex, _DEK_HEX.upper())
        self.assertEqual(bundle.comment, "case=12345")

    def test_from_hex_rejects_wrong_length(self) -> None:
        with self.assertRaises(SessionKeyError):
            SessionKeyBundle.from_hex(
                iccid="8900",
                shs_enc="00" * 8,
                shs_mac=_MAC_HEX,
            )
        with self.assertRaises(SessionKeyError):
            SessionKeyBundle.from_hex(
                iccid="8900",
                shs_enc=_ENC_HEX,
                shs_mac="00" * 15,
            )

    def test_from_hex_rejects_non_hex(self) -> None:
        with self.assertRaises(SessionKeyError):
            SessionKeyBundle.from_hex(
                iccid="8900",
                shs_enc="00" * 14 + "GG",
                shs_mac=_MAC_HEX,
            )

    def test_from_hex_rejects_empty_iccid(self) -> None:
        with self.assertRaises(SessionKeyError):
            SessionKeyBundle.from_hex(
                iccid="",
                shs_enc=_ENC_HEX,
                shs_mac=_MAC_HEX,
            )

    def test_optional_dek_is_dropped_from_serialization_when_empty(self) -> None:
        bundle = SessionKeyBundle.from_hex(
            iccid="8900",
            shs_enc=_ENC_HEX,
            shs_mac=_MAC_HEX,
        )
        payload = bundle.to_json_dict()
        self.assertNotIn("dek_hex", payload)
        self.assertNotIn("comment", payload)

    def test_matches_secret_is_case_insensitive_and_constant_time(self) -> None:
        bundle = SessionKeyBundle.from_hex(
            iccid="8900",
            shs_enc=_ENC_HEX,
            shs_mac=_MAC_HEX,
        )
        self.assertTrue(
            bundle.matches_secret(
                shs_enc_hex=_ENC_HEX.lower(),
                shs_mac_hex=_MAC_HEX.lower(),
            )
        )
        self.assertFalse(
            bundle.matches_secret(
                shs_enc_hex=_MAC_HEX,
                shs_mac_hex=_ENC_HEX,
            )
        )


class SessionKeyRepositoryTests(unittest.TestCase):
    def test_duplicate_iccid_rejected(self) -> None:
        bundle_a = SessionKeyBundle.from_hex(
            iccid="8900",
            shs_enc=_ENC_HEX,
            shs_mac=_MAC_HEX,
        )
        bundle_b = SessionKeyBundle.from_hex(
            iccid="8900",
            shs_enc=_MAC_HEX,
            shs_mac=_ENC_HEX,
        )
        with self.assertRaises(SessionKeyError):
            SessionKeyRepository.from_bundles([bundle_a, bundle_b])

    def test_round_trip_json(self) -> None:
        bundle = SessionKeyBundle.from_hex(
            iccid="89880012345678901234",
            shs_enc=_ENC_HEX,
            shs_mac=_MAC_HEX,
            dek=_DEK_HEX,
            comment="server-case-42",
        )
        repo = SessionKeyRepository.from_bundles([bundle])
        payload = repo.to_json_dict()
        text = json.dumps(payload)
        restored = SessionKeyRepository.from_json_dict(json.loads(text))
        self.assertEqual(restored.bundles[0], bundle)

    def test_atomic_write_sets_mode_0600_on_posix(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "sub" / "session-keys.json"
            repo = SessionKeyRepository.from_bundles(
                [
                    SessionKeyBundle.from_hex(
                        iccid="8900ABCDEF",
                        shs_enc=_ENC_HEX,
                        shs_mac=_MAC_HEX,
                    )
                ]
            )
            written = write_repository_atomic(repo, target)
            self.assertTrue(written.is_file())
            if os.name == "posix":
                mode = stat.S_IMODE(written.stat().st_mode)
                self.assertEqual(mode, 0o600)
            reloaded = load_repository(written)
            self.assertEqual(reloaded.lookup("8900ABCDEF").shs_enc_hex, _ENC_HEX)

    def test_lookup_returns_none_on_unknown(self) -> None:
        repo = SessionKeyRepository.from_bundles(
            [
                SessionKeyBundle.from_hex(
                    iccid="AAAA",
                    shs_enc=_ENC_HEX,
                    shs_mac=_MAC_HEX,
                )
            ]
        )
        self.assertIsNone(repo.lookup("BBBB"))

    def test_repository_json_rejects_wrong_format_tag(self) -> None:
        with self.assertRaises(SessionKeyError):
            SessionKeyRepository.from_json_dict(
                {"format": "other/v1", "entries": {}}
            )

    def test_load_repository_warns_on_world_readable_permissions(self) -> None:
        if os.name != "posix":
            self.skipTest("permission bits only meaningful on POSIX")
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "loose.json"
            repo = SessionKeyRepository.from_bundles(
                [
                    SessionKeyBundle.from_hex(
                        iccid="8900F00D",
                        shs_enc=_ENC_HEX,
                        shs_mac=_MAC_HEX,
                    )
                ]
            )
            write_repository_atomic(repo, target)
            os.chmod(target, 0o644)
            from Tools.EumDiag import session_keys as sk_mod
            with self.assertLogs(sk_mod._LOGGER, level="WARNING") as logs:
                load_repository(target)
        self.assertTrue(
            any("group/other-visible" in msg for msg in logs.output),
            f"expected permission warning, got {logs.output!r}",
        )


class TsharkRunnerTests(unittest.TestCase):
    def test_build_invocation_sets_env_and_command_order(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pcap = Path(td) / "capture.pcapng"
            pcap.write_bytes(b"\x00" * 16)
            keys = Path(td) / "session-keys.json"
            keys.write_text("{}", "utf-8")
            dissector = Path(td) / "dissector.lua"
            dissector.write_text("-- stub --", "utf-8")
            invocation = build_tshark_invocation(
                pcap_path=pcap,
                keys_path=keys,
                dissector_path=dissector,
                tshark_binary="tshark",
                extra_args=("-Y", "http"),
                existing_env={"PATH": "/usr/bin"},
            )
            self.assertEqual(invocation.command[0], "tshark")
            self.assertEqual(invocation.command[1], "-X")
            self.assertTrue(
                invocation.command[2].startswith("lua_script:"),
                invocation.command,
            )
            self.assertEqual(invocation.command[3], "-r")
            self.assertEqual(invocation.command[4], str(pcap.resolve()))
            self.assertIn("-Y", invocation.command)
            self.assertEqual(invocation.env[SESSION_KEYS_ENV_VAR], str(keys.resolve()))

    def test_ensure_tshark_raises_when_missing(self) -> None:
        with patch("shutil.which", return_value=None):
            with self.assertRaises(TsharkMissingError):
                ensure_tshark_on_path("does-not-exist-tshark")


class CliTests(unittest.TestCase):
    def test_store_keys_writes_repository(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "keys.json"
            rc = run_cli(
                [
                    "--workspace-root",
                    td,
                    "store-keys",
                    "--iccid",
                    "89880012345678901234",
                    "--shs-enc",
                    _ENC_HEX,
                    "--shs-mac",
                    _MAC_HEX,
                    "--keys-out",
                    str(out),
                ]
            )
            self.assertEqual(rc, 0)
            self.assertTrue(out.is_file())
            repo = load_repository(out)
            self.assertIsNotNone(repo.lookup("89880012345678901234"))

    def test_store_keys_rejects_missing_shs_enc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rc = run_cli(
                [
                    "--workspace-root",
                    td,
                    "store-keys",
                    "--iccid",
                    "8900",
                    "--shs-mac",
                    _MAC_HEX,
                ]
            )
            self.assertEqual(rc, 2)

    def test_inject_keys_runs_tshark_when_pcap_exists(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pcap = Path(td) / "capture.pcapng"
            pcap.write_bytes(b"\x00" * 32)
            out = Path(td) / "keys.json"

            class _FakeResult:
                returncode = 0

            with patch(
                "Tools.EumDiag.main.run_tshark",
                return_value=_FakeResult(),
            ) as mock_run:
                rc = run_cli(
                    [
                        "--workspace-root",
                        td,
                        "inject-keys",
                        "--iccid",
                        "8900",
                        "--shs-enc",
                        _ENC_HEX,
                        "--shs-mac",
                        _MAC_HEX,
                        "--keys-out",
                        str(out),
                        "--pcap",
                        str(pcap),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertTrue(out.is_file())
            self.assertEqual(mock_run.call_count, 1)

    def test_inject_keys_fails_when_pcap_missing(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            rc = run_cli(
                [
                    "--workspace-root",
                    td,
                    "inject-keys",
                    "--iccid",
                    "8900",
                    "--shs-enc",
                    _ENC_HEX,
                    "--shs-mac",
                    _MAC_HEX,
                    "--pcap",
                    str(Path(td) / "missing.pcapng"),
                ]
            )
            self.assertEqual(rc, 3)

    def test_inject_keys_reports_missing_tshark(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            pcap = Path(td) / "c.pcapng"
            pcap.write_bytes(b"\x00" * 8)
            def _raise(invocation, **kwargs):
                raise TsharkMissingError("tshark not found")

            with patch("Tools.EumDiag.main.run_tshark", side_effect=_raise):
                rc = run_cli(
                    [
                        "--workspace-root",
                        td,
                        "inject-keys",
                        "--iccid",
                        "8900",
                        "--shs-enc",
                        _ENC_HEX,
                        "--shs-mac",
                        _MAC_HEX,
                        "--pcap",
                        str(pcap),
                    ]
                )
            self.assertEqual(rc, 4)
