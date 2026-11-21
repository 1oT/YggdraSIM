# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP11-relay entry point: alias of the eSIM management relay module ``SCP11.live.main``."""
from __future__ import annotations

import sys

from SCP11.live import main as _impl

sys.modules[__name__] = _impl
