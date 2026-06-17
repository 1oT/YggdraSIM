# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""POSIX PTY bridge for Milestone B-2 (interactive CLI modules).

The GUI launches a registered CLI module — e.g. ``python -m SCP03`` —
inside a pseudo-terminal so the existing interactive shells
(``yggdrasim`` main menu, SCP03 shell, etc.) can run unmodified. The
caller is responsible for wiring the PTY to a transport (a FastAPI
WebSocket in ``routes/terminal.py`` at the moment) and for enforcing
authentication *before* spawning anything.

Design notes
------------

* The PTY is intentionally the only subprocess surface the GUI
  exposes. Nothing here calls ``shell=True`` or accepts user-supplied
  argv.
* Module names are matched against
  :data:`yggdrasim_common.registry.CLI_MODULES` — the allow-list is
  the same one the launcher help prints, so the GUI cannot spawn
  anything the CLI cannot.
* Windows is not supported in this iteration. The :func:`is_supported`
  helper allows the route layer to fail fast with a clear error
  instead of hanging on ``import pty``.
* Sizing (rows/cols) is communicated out-of-band through
  :meth:`PtySession.resize` so operators can make the terminal
  bigger / fullscreen without restarting the child.
"""

from __future__ import annotations

import asyncio
import errno
import fcntl
import os
import signal
import struct
import sys
import termios
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional


_DEFAULT_ROWS = 30
_DEFAULT_COLS = 120


def is_supported() -> bool:
    """Return ``True`` on POSIX systems where ``pty`` is importable.

    Windows will land via ``pywinpty`` in a follow-up; the current
    implementation relies on the stdlib ``pty`` module which only
    exists on Linux/macOS/*BSD.
    """
    return sys.platform != "win32"


def is_allowed_module(module_name: str) -> bool:
    """Match *module_name* against :data:`CLI_MODULES` case-sensitively."""
    from yggdrasim_common.registry import CLI_MODULES

    return module_name in CLI_MODULES


@dataclass
class PtyStartSpec:
    """Parameters consumed by :class:`PtySession.spawn`.

    Kept as a dataclass so the route handler can build it cleanly from
    the incoming WebSocket query string (or handshake payload).
    """

    module: str
    extra_args: tuple[str, ...] = ()
    rows: int = _DEFAULT_ROWS
    cols: int = _DEFAULT_COLS
    cwd: Optional[str] = None
    env: Optional[dict[str, str]] = None


class PtySession:
    """Spawn a child Python module in a PTY and pipe bytes asynchronously.

    Usage::

        session = PtySession()
        await session.spawn(spec)
        async for chunk in session.output():
            ...
        session.send(b"ENV\r\n")
        await session.close()

    The class is deliberately small; it does not interpret ANSI,
    translate encodings, or touch the byte stream. xterm.js on the
    frontend owns the rendering.
    """

    def __init__(self, *, max_read_bytes: int = 4096) -> None:
        self._pid: int = -1
        self._master_fd: int = -1
        self._max_read_bytes = int(max_read_bytes)
        self._closed = False
        self._reader_lock = asyncio.Lock()

    # -- properties ----------------------------------------------------

    @property
    def pid(self) -> int:
        return self._pid

    @property
    def closed(self) -> bool:
        return self._closed

    # -- lifecycle -----------------------------------------------------

    async def spawn(self, spec: PtyStartSpec) -> None:
        """Fork a child running ``python -m <module>`` inside a new PTY.

        Raises
        ------
        RuntimeError
            If the platform lacks PTY support.
        ValueError
            If the requested module is not in the allow-list.
        """
        if not is_supported():
            raise RuntimeError("PTY bridge is not supported on this platform.")
        if not is_allowed_module(spec.module):
            raise ValueError(f"module not in CLI allow-list: {spec.module!r}")

        import pty  # imported lazily so non-POSIX import paths are clean.

        argv = [sys.executable, "-m", spec.module, *spec.extra_args]
        env = dict(os.environ)
        if spec.env:
            env.update(spec.env)
        # Force unbuffered stdout so the PTY surfaces prompts promptly
        # even when the child forgets to flush.
        env.setdefault("PYTHONUNBUFFERED", "1")

        pid, master_fd = pty.fork()
        if pid == 0:
            # --- child -------------------------------------------------
            try:
                if spec.cwd:
                    os.chdir(spec.cwd)
                os.execvpe(argv[0], argv, env)
            except Exception as error:  # pragma: no cover
                sys.stderr.write(f"exec failed: {error}\n")
                os._exit(1)
            # Unreachable.
            os._exit(0)

        # --- parent ---------------------------------------------------
        self._pid = int(pid)
        self._master_fd = int(master_fd)
        _set_nonblocking(self._master_fd)
        self.resize(spec.rows, spec.cols)

    def resize(self, rows: int, cols: int) -> None:
        """Forward TIOCSWINSZ to the child so curses-style UIs redraw."""
        if self._master_fd < 0:
            return
        rows = max(1, int(rows))
        cols = max(1, int(cols))
        try:
            winsize = struct.pack("HHHH", rows, cols, 0, 0)
            fcntl.ioctl(self._master_fd, termios.TIOCSWINSZ, winsize)
        except OSError:
            # Resizing a dying PTY is harmless.
            pass

    def send(self, data: bytes) -> int:
        """Write raw bytes to the PTY master. Returns bytes actually written."""
        if self._master_fd < 0 or self._closed:
            return 0
        try:
            return os.write(self._master_fd, data)
        except OSError as error:
            if error.errno in (errno.EIO, errno.EBADF, errno.EPIPE):
                self._closed = True
                return 0
            raise

    async def read_once(self, *, timeout: float = 0.25) -> Optional[bytes]:
        """Read up to ``max_read_bytes`` from the PTY, or ``None`` on timeout/EOF.

        Uses :meth:`asyncio.AbstractEventLoop.run_in_executor` to hop
        off the event loop thread, which keeps ``os.read`` (a blocking
        syscall) from stalling other WebSocket clients.
        """
        if self._master_fd < 0 or self._closed:
            return None

        loop = asyncio.get_running_loop()
        async with self._reader_lock:
            try:
                chunk = await asyncio.wait_for(
                    loop.run_in_executor(None, _safe_read, self._master_fd, self._max_read_bytes),
                    timeout=max(0.01, float(timeout)),
                )
            except asyncio.TimeoutError:
                return b""
        if chunk is None:
            self._closed = True
        return chunk

    async def close(self) -> None:
        """Signal the child and reap it without leaking the master FD."""
        self._closed = True
        if self._pid > 0:
            try:
                os.kill(self._pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            # Give the child a brief window to exit cleanly, then escalate.
            await asyncio.sleep(0.15)
            try:
                os.waitpid(self._pid, os.WNOHANG)
            except ChildProcessError:
                pass
            try:
                os.kill(self._pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self._pid, 0)
            except ChildProcessError:
                pass
            self._pid = -1

        if self._master_fd >= 0:
            try:
                os.close(self._master_fd)
            except OSError:
                pass
            self._master_fd = -1


# -- module helpers ------------------------------------------------------


def _set_nonblocking(fd: int) -> None:
    flags = fcntl.fcntl(fd, fcntl.F_GETFL)
    fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)


def _safe_read(fd: int, max_bytes: int) -> Optional[bytes]:
    """Read synchronously from *fd*, returning ``b""`` if no data is ready
    and ``None`` on EOF. Used by :meth:`PtySession.read_once`.
    """
    try:
        data = os.read(fd, max_bytes)
    except BlockingIOError:
        return b""
    except OSError as error:
        if error.errno in (errno.EIO, errno.EBADF):
            return None
        raise
    if len(data) == 0:
        return None
    return data


StreamCallback = Callable[[bytes], Awaitable[None]]
