# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP11 test compatibility eIM package helpers."""
from __future__ import annotations

import sys

from SCP11.live import eim_packages as _impl


__all__ = list(_impl.__all__)
sys.modules[__name__] = _impl
