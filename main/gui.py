# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from __future__ import annotations

import sys
from collections.abc import Sequence

from yggdrasim_common.frozen_dispatch import (
    dispatch_internal_entry,
    install_missing_standard_streams,
)


def _load_run_cli():
    try:
        from main.main import run_cli
    except ImportError:
        from main import run_cli  # type: ignore
    return run_cli


def main(argv: Sequence[str] | None = None) -> int:
    """Desktop GUI entry of the windowed executable and ``pythonw -m main.gui``.

    Both start with no console, so ``sys.stdin``, ``sys.stdout`` and
    ``sys.stderr`` are ``None`` and the first write to one raises
    ``AttributeError``: the plugin-loading notice, then uvicorn's logging
    setup, which calls ``sys.stdout.isatty()``. The streams are repaired
    before ``main.main`` is imported, as in ``console_scripts.gui``.
    """
    install_missing_standard_streams()
    args = list(sys.argv[1:] if argv is None else argv)
    internal_exit = dispatch_internal_entry(args)
    if internal_exit is not None:
        return int(internal_exit)
    if not any(arg in ("--gui", "--web-server") for arg in args):
        args.insert(0, "--gui")
    return int(_load_run_cli()(args) or 0)


if __name__ == "__main__":
    sys.exit(main())
