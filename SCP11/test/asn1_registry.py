# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test compatibility ASN.1 registry."""
from __future__ import annotations

import sys

from SCP11.live import asn1_registry as _impl
from SCP11.live.asn1_registry import *  # noqa: F401,F403


sys.modules[__name__] = _impl
