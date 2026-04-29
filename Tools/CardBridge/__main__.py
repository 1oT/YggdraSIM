"""Entry point: ``python -m Tools.CardBridge``."""

from __future__ import annotations

import sys

from .server import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
