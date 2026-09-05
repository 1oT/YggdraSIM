# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility models."""
from __future__ import annotations

import sys

from SCP11.live import models as _impl


sys.modules[__name__] = _impl
