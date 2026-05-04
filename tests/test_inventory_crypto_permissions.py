"""Regression tests for POSIX permission handling in
``yggdrasim_common.inventory_crypto.write_secret_file_bytes``.

A naive implementation would let the atomic tmp-sibling inherit the
process umask (typically ``022``); the plaintext fallback path would
then leave inventory secrets world-readable for the microsecond between
``write_bytes`` and ``os.replace``. The implementation chmods the tmp
file to ``0600`` before the replace so the final file lands with the
expected permissions on every shell/umask combination.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path

from yggdrasim_common.inventory_crypto import (
    InventoryCryptoManager,
    write_secret_file_bytes,
)


@unittest.skipUnless(os.name == "posix", "0600 chmod is a POSIX-only concern")
class InventoryCryptoPermissionTests(unittest.TestCase):
    def test_plaintext_fallback_lands_with_0600(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "inventory_crypto.json"
            # Manager points at an on-disk config we fully control; default
            # config disables encryption so the write goes down the
            # plaintext fallback path we want to exercise.
            manager = InventoryCryptoManager(str(config_path))
            self.assertFalse(manager.write_encryption_enabled())

            target = Path(temp_dir) / "secret.json"
            previous_umask = os.umask(0o022)
            try:
                write_secret_file_bytes(
                    target,
                    b'{"token": "abc"}',
                    crypto_manager=manager,
                )
            finally:
                os.umask(previous_umask)
            self.assertTrue(target.is_file())
            file_mode = stat.S_IMODE(target.stat().st_mode)
            # After ``os.replace`` the permissions of the tmp sibling are
            # preserved, so the final file must be owner-rw-only.
            self.assertEqual(file_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
