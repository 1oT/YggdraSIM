import argparse
import os


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
    os.environ[GLOBAL_DEBUG_ENV] = "1" if bool(enabled) else "0"


def add_debug_argument(
    parser: argparse.ArgumentParser,
    *,
    help_text: str = "Enable verbose debug output.",
) -> None:
    parser.add_argument(
        "--debug",
        "--verbose",
        dest="debug",
        action="store_true",
        help=help_text,
    )
