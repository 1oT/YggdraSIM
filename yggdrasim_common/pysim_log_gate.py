# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""pySim secure-channel log lines: DEBUG only under the global debug flag.

pySim logs the SCP02 / SCP03 key derivations, MACs and wraps at DEBUG
through ``PySimLogger``, whose handler prints each record to stdout, and
``pySim.log`` sets the root logger to DEBUG on import. ``PySimLogger.get``
attaches its handler to every logger it is asked for, and
``pySim.global_platform`` and ``pySim.global_platform.scp`` both ask; the
pinned pySim prints a record once however many of those handlers it reaches
(``upstream_patches/osmocom-pysim-log-duplicate-handlers/``). Showing DEBUG
lines only under ``YGGDRASIM_GLOBAL_DEBUG`` is YggdraSIM's own choice.
"""

from __future__ import annotations

import logging
import threading

from yggdrasim_common.process_debug import is_global_debug_enabled

SECURE_CHANNEL_LOGGERS = ("pySim.global_platform", "pySim.global_platform.scp")
_PRINT_HANDLER = "_PySimLogHandler"
# Two threads installing at once could give one handler two gates.
_INSTALL_LOCK = threading.Lock()


class PySimLogGateMismatch(RuntimeError):
    """pySim would print a secure-channel record more than once."""


class _PySimSecureChannelGate(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return record.levelno >= logging.INFO or is_global_debug_enabled()


def _print_handlers(logger: logging.Logger) -> list[logging.Handler]:
    return [handler for handler in logger.handlers if type(handler).__name__ == _PRINT_HANDLER]


def _probe_prints() -> int:
    """How often pySim would print an INFO record of the innermost logger.

    The record is walked the way propagation walks it, root handlers skipped,
    and each handler whose filters pass it emits it through a throwaway
    handler of the same class whose callback only counts: nothing is printed,
    stdout is never touched, and an INFO record is outside the debug gate, so
    the answer does not depend on the flag another thread may be setting.
    """
    record = logging.LogRecord(
        SECURE_CHANNEL_LOGGERS[-1], logging.INFO, __file__, 0, "yggdrasim log gate probe", None, None
    )
    calls: list[str] = []
    logger: logging.Logger | None = logging.getLogger(SECURE_CHANNEL_LOGGERS[-1])
    while logger is not None and logger.name != "root":
        for handler in _print_handlers(logger):
            if not handler.filter(record):
                continue
            try:
                counter = type(handler)(log_callback=lambda message, _record: calls.append(message))
            except TypeError as error:
                raise PySimLogGateMismatch(
                    f"pySim's print handler on {logger.name} cannot be probed: {error}"
                ) from error
            counter.emit(record)
        logger = logger.parent if logger.propagate else None
    return len(calls)


def install_pysim_secure_channel_log_gate() -> bool:
    """Gate pySim's print handlers on the secure-channel loggers.

    Each handler gets a filter that drops every record below INFO while
    ``YGGDRASIM_GLOBAL_DEBUG`` is off. The flag is read per record, so
    ``--debug`` and ``--log`` take effect on the next line. Call it after
    importing ``pySim.global_platform.scp``; handlers created by a later
    import are not covered. A pySim without the print handlers (older
    releases) has nothing to gate and passes the probe as it is.

    A probe record is run through the gated handlers; a record that would
    print more than once -- a pySim without
    ``upstream_patches/osmocom-pysim-log-duplicate-handlers/`` -- raises
    :class:`PySimLogGateMismatch`.

    Returns ``True`` when this call added a filter and ``False`` when every
    handler already had one or there was none.
    """
    with _INSTALL_LOCK:
        added = False
        for name in SECURE_CHANNEL_LOGGERS:
            for handler in _print_handlers(logging.getLogger(name)):
                if any(isinstance(existing, _PySimSecureChannelGate) for existing in handler.filters):
                    continue
                handler.addFilter(_PySimSecureChannelGate())
                added = True
        prints = _probe_prints()
        if prints > 1:
            raise PySimLogGateMismatch(
                f"a record on {SECURE_CHANNEL_LOGGERS[-1]} would print {prints} times "
                "through pySim's handlers; the pinned pySim (hampushellsberg-dev/pysim) prints it "
                "once, see upstream_patches/osmocom-pysim-log-duplicate-handlers/"
            )
        return added
