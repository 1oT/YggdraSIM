# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility entrypoint."""
from __future__ import annotations

import sys

from SCP11.live import main as _impl
from SCP11.live.main import SCP11StartupError, SGP22Client, entry


__all__ = ["SCP11StartupError", "SGP22Client", "entry"]
sys.modules[__name__] = _impl
