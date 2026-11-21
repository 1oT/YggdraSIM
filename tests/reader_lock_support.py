# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""A second process for the reader-lock tests (``yggdrasim_common.reader_locks``).

:class:`OtherProcess` takes a reader's lock in another Python process and
keeps it until told to let go; :func:`probe` tries once from another process
and reports what it met. Both are given the lock directory on the command
line, so the child never depends on its HOME.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
READER = "HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00"
CONSOLE_HOLDER = "DOWNLOAD in the eSIM Management console"

# argv: directory, reader, mode ("long" / "short": hold until a stdin line;
# "try": one attempt, optionally waiting) and the holder or the wait.
_SCRIPT = r"""
import json, sys
from pathlib import Path
from yggdrasim_common import reader_locks

directory, reader, mode = sys.argv[1], sys.argv[2], sys.argv[3]
reader_locks._DIRECTORY = Path(directory)
if mode == "try":
    wait_s = float(sys.argv[4]) if len(sys.argv) > 4 else 0.0
    try:
        hold = reader_locks.acquire(reader, "probe", wait_s=wait_s)
    except reader_locks.ReaderBusyError as busy:
        print(json.dumps({"busy": str(busy), "holder": busy.holder}), flush=True)
    else:
        print(json.dumps({"held": hold.guarded}), flush=True)
        hold.release()
    sys.exit(0)
hold = reader_locks.acquire(reader, sys.argv[4], long_running=(mode == "long"))
print("held", flush=True)
sys.stdin.readline()
hold.release()
print("released", flush=True)
"""


class OtherProcess:
    """Another process holding a reader until :meth:`release`."""

    def __init__(self, directory: Path, reader: str = READER, *, long_running: bool, holder: str = CONSOLE_HOLDER) -> None:
        self.process = subprocess.Popen(
            [sys.executable, "-c", _SCRIPT, str(directory), reader, "long" if long_running else "short", holder],
            cwd=REPO_ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline().strip()
        assert line == "held", line

    @property
    def pid(self) -> int:
        return self.process.pid

    def release(self) -> None:
        self.process.stdin.write("\n")
        self.process.stdin.flush()
        assert self.process.stdout.readline().strip() == "released"
        self.process.wait(timeout=10)

    def kill(self) -> None:
        self.process.kill()
        self.process.wait(timeout=10)

    def close(self) -> None:
        if self.process.poll() is None:
            self.kill()
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()


def probe(directory: Path, reader: str = READER, wait_s: float = 0.0) -> dict:
    """One attempt from another process: {"held": True} or {"busy": ..., "holder": ...}."""
    completed = subprocess.run(
        [sys.executable, "-c", _SCRIPT, str(directory), reader, "try", str(wait_s)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout.strip().splitlines()[-1])
