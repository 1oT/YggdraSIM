# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

from .main import run_standalone
from yggdrasim_common.quit_control import QuitAllRequested


if __name__ == "__main__":
    try:
        run_standalone()
    except QuitAllRequested:
        raise SystemExit(0)
