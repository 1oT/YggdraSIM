# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Entry point: ``python -m Tools.CardBridge``."""

from __future__ import annotations

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
