# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""
Shared quit control for interactive YggdraSIM shells.
"""

from __future__ import annotations


class QuitAllRequested(BaseException):
    """Exit the current shell stack and return directly to the terminal."""


def quit_all() -> None:
    raise QuitAllRequested()
