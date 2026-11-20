# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""One holder per card reader across processes.

Two programs on one PC/SC reader are two masters on one card: the SCP11
transport resets the card when it connects and powers it down when it lets
go, and the HIL bridge resets it for every modem session. The program still
talking then gets SCARD_W_RESET_CARD (0x80100068), and an exclusive connect
gets SCARD_E_SHARING_VIOLATION (0x8010000B). :mod:`yggdrasim_common.reader_claims`
keeps the GUI's own operations apart; this module keeps processes apart:
the eSIM Management console in a terminal, the GUI, the HIL bridge and the
MCP server take a
reader's lock before they open it.

The lock is a file under ``~/.yggdrasim/run/reader-locks`` held with
``flock`` (``msvcrt.locking`` on Windows), so the kernel frees it when the
holding process ends, crashed or not. A record beside it names the holder
for the refusal. Holds are re-entrant within a process: a call nested in
another on the same reader shares the one lock. A holder that runs until
stopped (a continuous console command, the HIL bridge, an MCP card session)
is refused at once; any
other is waited for. Where no lock can be taken (no writable directory, no
locking call), a hold says so once on stderr and the work goes ahead
unguarded.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

try:
    import fcntl
except ImportError:
    fcntl = None  # type: ignore[assignment]
try:
    import msvcrt
except ImportError:
    msvcrt = None  # type: ignore[assignment]

#: How long a hold waits for a short holder in another process.
SHORT_HOLD_WAIT_S = 60.0
_RETRY_INTERVAL_S = 0.2
# A holder writes its record just after it takes the lock; a waiter that
# lands in between reads once more before naming "another process".
_RECORD_SETTLE_S = 0.05
_UNKNOWN_HOLDER = "another process"

#: Tests point this at a scratch directory; None is the per-user default.
_DIRECTORY: Path | None = None


class ReaderBusyError(RuntimeError):
    """The reader is held by another operation or another process."""

    def __init__(self, reader: str, holder: str, since: float) -> None:
        self.reader = reader
        self.holder = holder
        self.since = since
        stamp = time.strftime("%H:%M:%S", time.localtime(since))
        named = repr(reader) if reader else "the default reader"
        super().__init__(f"reader busy: {holder} has held {named} since {stamp}")


@dataclass(frozen=True)
class HolderRecord:
    """Who holds a reader in another process."""

    holder: str
    pid: int
    since: float
    long_running: bool

    def describe(self) -> str:
        return f"{self.holder} (pid {self.pid})" if self.pid > 0 else self.holder


class _Shared:
    """This process's lock on one reader, shared by its nested holds."""

    __slots__ = ("fd", "record_path", "count")

    def __init__(self, fd: int, record_path: Path) -> None:
        self.fd = fd
        self.record_path = record_path
        self.count = 1


# Only readers this process holds or is taking right now, so neither
# outgrows the holds in flight.
_HELD: dict[str, _Shared] = {}
_ACQUIRING: set[str] = set()
_STATE = threading.Condition()
_WARNED = False


class ReaderHold:
    """One hold on a reader; :meth:`release` gives it back, once."""

    __slots__ = ("reader", "_shared", "_released")

    def __init__(self, reader: str, shared: _Shared | None) -> None:
        self.reader = reader
        self._shared = shared
        self._released = False

    @property
    def guarded(self) -> bool:
        """False for a hold that took no lock: no reader name, or no locking here."""
        return self._shared is not None

    def release(self) -> None:
        with _STATE:
            if self._released:
                return
            self._released = True
            shared = self._shared
            if shared is None:
                return
            shared.count -= 1
            if shared.count > 0:
                return
            if _HELD.get(self.reader) is shared:
                del _HELD[self.reader]
            _drop(shared)
            _STATE.notify_all()


def lock_directory() -> Path:
    """Where the reader locks live: one directory per user, whatever the runtime root."""
    if _DIRECTORY is not None:
        return Path(_DIRECTORY)
    return Path.home() / ".yggdrasim" / "run" / "reader-locks"


def acquire(
    reader: str,
    holder: str,
    *,
    long_running: bool = False,
    wait_s: float = SHORT_HOLD_WAIT_S,
    on_wait: Callable[[HolderRecord | None], None] | None = None,
) -> ReaderHold:
    """Hold *reader* for *holder* until the returned hold is released.

    A reader this process already holds is shared at once. One another
    process holds is waited for up to *wait_s*, unless that holder runs until
    stopped; either refusal raises :class:`ReaderBusyError` naming the holder.
    *on_wait* is called once, with the holder's record, when a wait starts.
    *long_running* goes into this hold's record for the processes that come
    after. An empty reader name holds nothing.
    """
    key = str(reader or "").strip()
    if len(key) == 0:
        return ReaderHold(key, None)
    with _STATE:
        while True:
            shared = _HELD.get(key)
            if shared is not None:
                shared.count += 1
                return ReaderHold(key, shared)
            if key not in _ACQUIRING:
                _ACQUIRING.add(key)
                break
            _STATE.wait()
    taken: _Shared | None = None
    try:
        taken = _take(key, str(holder or _UNKNOWN_HOLDER), bool(long_running), float(wait_s), on_wait)
    finally:
        with _STATE:
            _ACQUIRING.discard(key)
            if taken is not None:
                _HELD[key] = taken
            _STATE.notify_all()
    return ReaderHold(key, taken)


@contextmanager
def held(
    reader: str,
    holder: str,
    *,
    long_running: bool = False,
    wait_s: float = SHORT_HOLD_WAIT_S,
    on_wait: Callable[[HolderRecord | None], None] | None = None,
) -> Iterator[ReaderHold]:
    """Hold *reader* for the body of a ``with`` block."""
    hold = acquire(reader, holder, long_running=long_running, wait_s=wait_s, on_wait=on_wait)
    try:
        yield hold
    finally:
        hold.release()


def holder_of(reader: str) -> HolderRecord | None:
    """Who holds *reader* in another process; None when it is free or held here.

    Takes no hold: when the reader is free, the probe locks and unlocks at once.
    """
    key = str(reader or "").strip()
    if len(key) == 0 or _locking_call_missing():
        return None
    with _STATE:
        if key in _HELD:
            return None
    lock_path, record_path = _paths(key)
    try:
        fd = os.open(lock_path, os.O_RDWR)
    except OSError:
        return None
    try:
        try:
            free = _try_lock(fd)
        except OSError:
            return None
        if free:
            _unlock(fd)
            return None
        record = _other_holder(record_path)
        if record is None:
            return HolderRecord(_UNKNOWN_HOLDER, 0, time.time(), False)
        return record
    finally:
        os.close(fd)


def _take(
    key: str,
    holder: str,
    long_running: bool,
    wait_s: float,
    on_wait: Callable[[HolderRecord | None], None] | None,
) -> _Shared | None:
    if _locking_call_missing():
        _warn_unguarded("no file locking call on this platform")
        return None
    lock_path, record_path = _paths(key)
    try:
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError as error:
        _warn_unguarded(f"{lock_path.parent}: {error.strerror or error}")
        return None
    deadline = time.monotonic() + max(0.0, wait_s)
    waiting = False
    try:
        while True:
            try:
                locked = _try_lock(fd)
            except OSError as error:
                _warn_unguarded(f"{lock_path}: {error.strerror or error}")
                os.close(fd)
                return None
            if locked:
                _write_record(record_path, HolderRecord(holder, os.getpid(), time.time(), long_running))
                return _Shared(fd, record_path)
            other = _other_holder(record_path)
            remaining = deadline - time.monotonic()
            if (other is not None and other.long_running) or remaining <= 0:
                if other is None:
                    raise ReaderBusyError(key, _UNKNOWN_HOLDER, time.time())
                raise ReaderBusyError(key, other.describe(), other.since)
            if waiting is False:
                waiting = True
                if on_wait is not None:
                    on_wait(other)
            time.sleep(min(_RETRY_INTERVAL_S, remaining))
    except BaseException:
        os.close(fd)
        raise


def _paths(key: str) -> tuple[Path, Path]:
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    stem = re.sub(r"[^A-Za-z0-9]+", "-", key).strip("-")[:40] or "reader"
    directory = lock_directory()
    return directory / f"{stem}-{digest}.lock", directory / f"{stem}-{digest}.json"


def _locking_call_missing() -> bool:
    return fcntl is None and msvcrt is None


def _try_lock(fd: int) -> bool:
    """Take the lock without blocking; False while another process has it."""
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    # msvcrt locks a byte range and reports a held range as a plain OSError.
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError:
        return False
    return True


def _unlock(fd: int) -> None:
    if fcntl is not None:
        fcntl.flock(fd, fcntl.LOCK_UN)
        return
    os.lseek(fd, 0, os.SEEK_SET)
    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)


def _drop(shared: _Shared) -> None:
    """Delete the record, then unlock: a later holder's record is never the one deleted."""
    try:
        shared.record_path.unlink()
    except OSError:
        pass
    try:
        _unlock(shared.fd)
    except OSError:
        pass
    try:
        os.close(shared.fd)
    except OSError:
        pass


def _write_record(path: Path, record: HolderRecord) -> None:
    payload = json.dumps(
        {
            "holder": record.holder,
            "pid": record.pid,
            "since": record.since,
            "long_running": record.long_running,
        }
    )
    scratch = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    try:
        with open(scratch, "w", encoding="utf-8") as handle:
            handle.write(payload)
        os.replace(scratch, path)
    except OSError:
        # The lock is held either way; a refusal then names "another process".
        try:
            scratch.unlink()
        except OSError:
            pass


def _read_record(path: Path) -> HolderRecord | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if isinstance(data, dict) is False:
        return None
    try:
        return HolderRecord(
            holder=str(data["holder"]),
            pid=int(data["pid"]),
            since=float(data["since"]),
            long_running=bool(data["long_running"]),
        )
    except (KeyError, TypeError, ValueError):
        return None


def _other_holder(record_path: Path) -> HolderRecord | None:
    """The record of the process holding the lock; None when it cannot be named."""
    record = _read_record(record_path)
    if record is None:
        time.sleep(_RECORD_SETTLE_S)
        record = _read_record(record_path)
    if record is None or record.pid == os.getpid() or _pid_alive(record.pid) is False:
        # A record left by a holder that died names nobody: the lock now
        # belongs to whoever took it after, before it wrote its own.
        return None
    return record


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _warn_unguarded(reason: str) -> None:
    global _WARNED
    with _STATE:
        if _WARNED:
            return
        _WARNED = True
    print(
        f"[!] reader locks unavailable ({reason}); other YggdraSIM processes are not kept off the reader.",
        file=sys.stderr,
    )
