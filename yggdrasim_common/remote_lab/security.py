# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Bearer-token helpers for Remote Lab control and session APIs."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from yggdrasim_common.card_bridge_auth import generate_token, write_token_file


HASH_PREFIX = "sha256:"


def hash_token(token: str) -> str:
    cleaned = str(token or "").strip()
    if len(cleaned) == 0:
        raise ValueError("token must be non-empty")
    return HASH_PREFIX + hashlib.sha256(cleaned.encode("utf-8")).hexdigest()


def verify_token(presented: str, token_hash: str) -> bool:
    token = str(presented or "").strip()
    stored = str(token_hash or "").strip().lower()
    if len(token) == 0 or not stored.startswith(HASH_PREFIX):
        return False
    actual = hash_token(token).lower()
    return hmac.compare_digest(actual.encode("ascii"), stored.encode("ascii"))


def read_token_file(path: str | Path) -> str:
    resolved = Path(path).expanduser().resolve()
    return resolved.read_text(encoding="utf-8").strip()


def write_new_token_file(path: str | Path) -> tuple[str, Path]:
    token = generate_token()
    return token, write_token_file(Path(path).expanduser(), token)
