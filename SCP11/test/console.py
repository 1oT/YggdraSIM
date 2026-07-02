# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility console."""
from __future__ import annotations

from SCP11.live import console as _impl
from SCP11.live.console import *  # noqa: F401,F403


_encode_length = _impl._encode_length
_build_tlv = _impl._build_tlv


class SCP11Console(_impl.SCP11Console):
    def _hil_bridge_warning_text(self) -> str:
        return hil_bridge_warning_text()
