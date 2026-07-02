# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay profile providers: remote ES9+ and local-file delivery."""
try:
    from ..providers import *
except ImportError:
    from SCP11.providers import *
