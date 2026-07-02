# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility config.

The relay test entrypoint uses the same runtime configuration as the live
relay. Test certificate material is no longer selected implicitly.
"""
from __future__ import annotations

import sys

from SCP11.live import config as _impl
from SCP11.live.config import *  # noqa: F401,F403


sys.modules[__name__] = _impl
