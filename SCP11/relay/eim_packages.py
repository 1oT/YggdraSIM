# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11-relay eIM package store: bound profile package resolver for compatibility delivery."""
try:
    from ..eim_packages import *
except ImportError:
    from SCP11.eim_packages import *
