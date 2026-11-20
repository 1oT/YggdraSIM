# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""One card operation at a time per reader, within this process.

Card actions started from the GUI run on worker threads, and an SCP11 action
opens its own PC/SC connection and powers the card down when it lets go of it
(SCARD_UNPOWER_CARD), so two operations overlapping on one reader cut each
other off. An operation claims its reader for as long as it runs. A claim held
by a short operation is waited for; one held by a long-running operation (a
stream, a profile download) is refused at once with the holder's name, since
its end is not in sight. The claims cover operations, not open sessions: an
SCP03 session between two commands holds no claim.

A plugin that drives a card outside the action routes takes the same claim
with :func:`held`.

A claim on a local PC/SC reader also takes the reader's lock across
processes (:mod:`yggdrasim_common.reader_locks`), so a console command in a terminal, the
HIL bridge or an MCP card session holding it is refused or waited for the
same way, and they in turn see the GUI's operation by name.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field, replace

from yggdrasim_common import reader_locks
from yggdrasim_common.reader_locks import ReaderBusyError

#: How long a claim waits for a short operation on the same reader.
SHORT_HOLD_WAIT_S = reader_locks.SHORT_HOLD_WAIT_S

__all__ = [
    "SHORT_HOLD_WAIT_S",
    "ReaderBusyError",
    "claim",
    "claimed_readers",
    "held",
    "is_local_reader",
    "reader_key",
    "release",
]


@dataclass(frozen=True)
class _Claim:
    holder: str
    since: float
    long_running: bool
    token: object = field(default_factory=object)
    process_hold: reader_locks.ReaderHold | None = None


# Only readers held right now, so the map never outgrows the operations in flight.
_CLAIMS: dict[str, _Claim] = {}
_CHANGED = threading.Condition()


def reader_key(reader_name: str) -> str:
    """The key a reader name is claimed under.

    With the SIM backend every connection reaches the simulated card whatever
    reader it names, so there is one key. Otherwise no name is the reader the
    action resolvers pick by default: the first PC/SC reader.
    """
    from yggdrasim_common.card_backend import SIMULATED_READER_NAME, is_simulated_card_backend

    if is_simulated_card_backend():
        return SIMULATED_READER_NAME
    name = str(reader_name or "").strip()
    if len(name) > 0:
        return name
    try:
        from smartcard.System import readers as list_pcsc_readers

        found = list(list_pcsc_readers() or [])
    except Exception:  # noqa: BLE001 -- without an enumeration the default stays unnamed.
        return ""
    return str(found[0]) if len(found) > 0 else ""


def claim(reader: str, holder: str, *, long_running: bool = False, wait_s: float = SHORT_HOLD_WAIT_S) -> object:
    """Claim *reader* for *holder*; return the token :func:`release` takes.

    Waits up to *wait_s* for a short operation that holds it. A long-running
    holder, or a wait that runs out, raises :class:`ReaderBusyError`.
    """
    key = str(reader or "").strip()
    deadline = time.monotonic() + max(0.0, float(wait_s))
    with _CHANGED:
        while key in _CLAIMS:
            current = _CLAIMS[key]
            remaining = deadline - time.monotonic()
            if current.long_running or remaining <= 0:
                raise ReaderBusyError(key, current.holder, current.since)
            _CHANGED.wait(remaining)
        entry = _Claim(holder=str(holder), since=time.time(), long_running=bool(long_running))
        _CLAIMS[key] = entry
    # The in-process claim is registered first, so a second operation of
    # this process waits above rather than racing this one for the lock.
    try:
        process_hold = _hold_across_processes(key, entry.holder, entry.long_running, deadline)
    except BaseException:
        with _CHANGED:
            if _CLAIMS.get(key) is entry:
                del _CLAIMS[key]
                _CHANGED.notify_all()
        raise
    if process_hold is not None:
        with _CHANGED:
            _CLAIMS[key] = replace(entry, process_hold=process_hold)
    return entry.token


def release(reader: str, token: object) -> None:
    """Give a claim back; a token that no longer holds the reader changes nothing."""
    key = str(reader or "").strip()
    with _CHANGED:
        current = _CLAIMS.get(key)
        if current is not None and current.token is token:
            del _CLAIMS[key]
            if current.process_hold is not None:
                current.process_hold.release()
            _CHANGED.notify_all()


def _hold_across_processes(
    key: str, holder: str, long_running: bool, deadline: float
) -> reader_locks.ReaderHold | None:
    """The other-processes half of a claim, for a local PC/SC reader only.

    The simulated card and a Remote Lab reader are in no local reader, so
    they take no lock; the far end of a Remote Lab binding keeps its own lease.
    """
    if len(key) == 0 or is_local_reader(key) is False:
        return None
    return reader_locks.acquire(
        key,
        f"{holder} in the GUI",
        long_running=long_running,
        wait_s=max(0.0, deadline - time.monotonic()),
    )


def is_local_reader(key: str) -> bool:
    """True for a local PC/SC reader: not the simulated card, not a Remote Lab binding."""
    from yggdrasim_common.card_backend import SIMULATED_READER_NAME
    from yggdrasim_common.remote_readers import lookup_remote_reader

    if key == SIMULATED_READER_NAME:
        return False
    return lookup_remote_reader(key) is None


@contextmanager
def held(reader: str, holder: str, *, long_running: bool = False, wait_s: float = SHORT_HOLD_WAIT_S) -> Iterator[None]:
    """Hold *reader* for the body of a ``with`` block."""
    token = claim(reader, holder, long_running=long_running, wait_s=wait_s)
    try:
        yield
    finally:
        release(reader, token)


def claimed_readers() -> dict[str, str]:
    """The readers held now, each with its holder."""
    with _CHANGED:
        return {key: entry.holder for key, entry in _CLAIMS.items()}
