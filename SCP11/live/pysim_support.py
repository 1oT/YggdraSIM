# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Alias of the shared SCP11 pySim support (``SCP11.pysim_support``) under the live namespace."""
from __future__ import annotations

import sys

from SCP11 import pysim_support as _impl

sys.modules[__name__] = _impl
