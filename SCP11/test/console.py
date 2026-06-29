# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility console."""
from __future__ import annotations

import sys

from SCP11.live import console as _impl
from SCP11.live.console import *  # noqa: F401,F403


sys.modules[__name__] = _impl
