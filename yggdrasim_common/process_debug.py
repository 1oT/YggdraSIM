# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Process debug helpers: thread-dump signal handler and memory-usage reporter for long-running daemon processes."""
import argparse
import contextlib
import os
import sys
import warnings


GLOBAL_DEBUG_ENV = "YGGDRASIM_GLOBAL_DEBUG"

_TRUE_VALUES = {"1", "true", "yes", "y", "on", "debug", "verbose"}
_FALSE_VALUES = {"0", "false", "no", "n", "off"}


def _parse_bool_text(value: str, default: bool = False) -> bool:
    normalized = str(value or "").strip().lower()
    if len(normalized) == 0:
        return bool(default)
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    return bool(default)


def is_global_debug_enabled(default: bool = False) -> bool:
    return _parse_bool_text(os.environ.get(GLOBAL_DEBUG_ENV, ""), default=default)


def set_global_debug(enabled: bool) -> None:
    """Set the global debug flag and persist it across sessions.

    The persistence path is controlled by the ``EnvFlag.persist_scope`` of
    ``YGGDRASIM_GLOBAL_DEBUG`` (currently ``PERSIST_FILE``, which writes to
    ``<runtime_root>/state/env_overrides.json``). The import is lazy to
    avoid adding a hard dependency from every early-import consumer.
    """
    value = "1" if bool(enabled) else "0"
    os.environ[GLOBAL_DEBUG_ENV] = value
    try:
        from yggdrasim_common import env_flags
    except ImportError:
        return
    flag = env_flags.get_flag(GLOBAL_DEBUG_ENV)
    if flag is not None:
        env_flags.set_flag_value(flag, value, persist=True)


def add_debug_argument(
    parser: argparse.ArgumentParser,
    *,
    help_text: str = "Enable verbose debug output.",
) -> None:
    """Add a `--debug` argument group to *parser* with process diagnostic flags."""
    parser.add_argument(
        "--debug",
        "--verbose",
        dest="debug",
        action="store_true",
        help=help_text,
    )


def debug_print(message: str, *, stream=None) -> None:
    """
    Emit ``message`` to ``stream`` (default ``sys.stdout``) only when the
    global debug flag is on. Used for verbose transport / TLS / request
    traces that would otherwise clutter the operator surface during
    nominal runs. When the flag flips back to off the same call site
    becomes silent without needing a conditional wrapper at the caller.
    """
    if is_global_debug_enabled() is False:
        return
    target = stream if stream is not None else sys.stdout
    try:
        target.write(f"{message}\n")
        flush = getattr(target, "flush", None)
        if callable(flush):
            flush()
    except Exception:
        return


@contextlib.contextmanager
def suppress_noisy_crypto_warnings():
    """
    Silence ``CryptographyDeprecationWarning`` emissions while loading
    test / legacy PEM certificates (e.g. CI roots with non-positive
    serials). When global debug is on the warnings are left intact so
    the operator still sees them during troubleshooting. Any import
    failure is treated as a no-op so older/newer cryptography releases
    do not break the call site.
    """
    if is_global_debug_enabled():
        yield
        return
    try:
        from cryptography.utils import CryptographyDeprecationWarning
    except Exception:
        yield
        return
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", CryptographyDeprecationWarning)
        yield


def install_noisy_warning_filters() -> None:
    """
    Install process-wide ``warnings.filterwarnings`` rules that silence
    known-noisy third-party deprecations (currently only
    ``CryptographyDeprecationWarning`` triggered by test-CA PEMs with
    non-positive serials). Entry-point wrappers should call this once
    after ``set_global_debug`` has been resolved. When debug is on the
    call is a no-op so the operator still sees the warnings during
    troubleshooting. Safe to call repeatedly; ``filterwarnings`` is
    idempotent for identical patterns.
    """
    if is_global_debug_enabled():
        return
    try:
        from cryptography.utils import CryptographyDeprecationWarning
    except Exception:
        return
    warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
