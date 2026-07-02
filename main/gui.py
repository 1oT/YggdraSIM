# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import sys
from collections.abc import Sequence


def _load_run_cli():
    try:
        from main.main import run_cli
    except ImportError:
        from main import run_cli  # type: ignore
    return run_cli


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not any(arg in ("--gui", "--web-server") for arg in args):
        args.insert(0, "--gui")
    return int(_load_run_cli()(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
