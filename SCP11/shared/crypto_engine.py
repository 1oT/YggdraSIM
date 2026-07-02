# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 shared crypto engine: common ECIES and AES-GCM primitives shared across session variants."""
try:
    from ..crypto_engine import *
except ImportError:
    from SCP11.crypto_engine import *
