# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility crypto engine."""
from __future__ import annotations

import sys

from SCP11.live import crypto_engine as _impl
from SCP11.live.crypto_engine import *  # noqa: F401,F403


sys.modules[__name__] = _impl
