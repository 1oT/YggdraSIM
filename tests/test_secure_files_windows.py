# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Windows-safe regression coverage for private secret-file ACLs."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from yggdrasim_common.secure_files import (
    _WINDOWS_TRUSTED_BUILTIN_SIDS,
    _private_windows_sddl,
    _windows_sid_is_trusted,
    assert_private_file,
    atomic_write_bytes,
    ensure_private_directory,
)


@pytest.mark.parametrize(
    ("candidate_sid", "expected"),
    [
        ("S-1-test-current-user", True),
        ("S-1-5-18", True),
        ("S-1-5-32-544", True),
        ("S-1-1-0", False),
        ("S-1-5-11", False),
    ],
)
def test_windows_private_owner_policy_only_accepts_trusted_principals(
    candidate_sid: str,
    expected: bool,
) -> None:
    trusted_sids = ("S-1-test-current-user", *_WINDOWS_TRUSTED_BUILTIN_SIDS)
    assert _windows_sid_is_trusted(
        candidate_sid,
        trusted_sids,
        equal_sid=lambda left, right: left == right,
    ) is expected


def test_private_windows_sddl_inherits_only_for_directories() -> None:
    sid = "S-1-test-current-user"
    directory_sddl = _private_windows_sddl(sid, is_directory=True)
    file_sddl = _private_windows_sddl(sid, is_directory=False)

    assert directory_sddl == (
        "D:P"
        "(A;OICI;FA;;;SY)"
        "(A;OICI;FA;;;BA)"
        f"(A;OICI;FA;;;{sid})"
    )
    assert file_sddl == (
        "D:P"
        "(A;;FA;;;SY)"
        "(A;;FA;;;BA)"
        f"(A;;FA;;;{sid})"
    )


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL assertion")
def test_private_helpers_apply_verifiable_windows_dacl(tmp_path: Path) -> None:
    private_dir = ensure_private_directory(tmp_path / "private")
    private_file = atomic_write_bytes(private_dir / "secret.bin", b"secret")
    assert assert_private_file(private_file) == private_file


@pytest.mark.skipif(os.name != "nt", reason="native Windows ACL assertion")
def test_private_directory_keeps_existing_child_accessible(tmp_path: Path) -> None:
    private_dir = tmp_path / "private"
    child_dir = private_dir / "state"
    marker = child_dir / "marker.json"
    child_dir.mkdir(parents=True)
    marker.write_text("{}", encoding="utf-8")

    ensure_private_directory(private_dir)

    assert marker.read_text(encoding="utf-8") == "{}"
    assert assert_private_file(marker) == marker
    marker.unlink()
    child_dir.rmdir()

    inherited_child = private_dir / "new-state"
    inherited_marker = inherited_child / "marker.json"
    inherited_child.mkdir()
    inherited_marker.write_text("{}", encoding="utf-8")
    assert inherited_marker.read_text(encoding="utf-8") == "{}"
    assert assert_private_file(inherited_marker) == inherited_marker
    inherited_marker.unlink()
    inherited_child.rmdir()
