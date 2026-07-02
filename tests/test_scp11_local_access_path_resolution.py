# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

import unittest

from SCP11.local_access.config import LocalAccessConfig
from SCP11.local_access.session import LocalIsdrSession


class _DummyApduChannel:
    def send(self, _apdu: bytes, _log_name: str) -> bytes:
        return b""


class LocalAccessPathResolutionTests(unittest.TestCase):
    def test_repo_relative_path_is_not_joined_with_base_dir(self) -> None:
        cfg = LocalAccessConfig()
        session = LocalIsdrSession(cfg=cfg, apdu_channel=_DummyApduChannel())
        resolved = session._normalize_user_path(
            "SCP11/eim_local/certs/eim/CERT.EIM.pem",
            base_dir=cfg.CERTS_DIR,
        )
        self.assertIn("/Workspace/LocalEIM/certs/eim/CERT.EIM.pem", resolved)
        self.assertNotIn("/certs/SCP11/eim_local", resolved)

    def test_unknown_relative_path_keeps_base_dir_resolution(self) -> None:
        cfg = LocalAccessConfig()
        session = LocalIsdrSession(cfg=cfg, apdu_channel=_DummyApduChannel())
        resolved = session._normalize_user_path(
            "not_a_repo_root_entry/child.bin",
            base_dir=cfg.CERTS_DIR,
        )
        self.assertIn("/certs/not_a_repo_root_entry/child.bin", resolved)


if __name__ == "__main__":
    unittest.main()
