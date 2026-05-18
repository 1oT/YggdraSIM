# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Polling plugin support: shared timer and event-queue primitives for plugins that drive periodic background tasks."""
from __future__ import annotations

from typing import Any

from .plugin_runtime import get_capability


POLLING_CAPABILITY_NAME = "polling"
POLLING_PLUGIN_MISSING_MESSAGE = (
    "Polling capability is not installed. Place a plugin that registers the "
    "'polling' capability under plugins/ to enable IPAD/IPAE/POLL flows."
)


def has_polling_plugin() -> bool:
    return get_capability(POLLING_CAPABILITY_NAME) is not None


def require_polling_plugin() -> Any:
    capability = get_capability(POLLING_CAPABILITY_NAME)
    if capability is None:
        raise RuntimeError(POLLING_PLUGIN_MISSING_MESSAGE)
    return capability


def dispatch_poll_method(target: Any, method_name: str, *args: Any, **kwargs: Any) -> Any:
    capability = require_polling_plugin()
    dispatcher = getattr(capability, "dispatch_poll_method", None)
    if callable(dispatcher) is False:
        raise RuntimeError("Polling capability does not expose dispatch_poll_method().")
    return dispatcher(target, method_name, *args, **kwargs)


def dispatch_poll_command(
    surface: str,
    command_name: str,
    target: Any,
    argument: str,
) -> Any:
    """Dispatch a poll command to the registered polling plugin."""
    capability = require_polling_plugin()
    handler = getattr(capability, "handle_command", None)
    if callable(handler) is False:
        raise RuntimeError("Polling capability does not expose handle_command().")
    return handler(
        surface=str(surface or "").strip().lower(),
        command_name=str(command_name or "").strip().upper(),
        target=target,
        argument=str(argument or ""),
    )


def parse_eim_local_ipae_options(argument: str = "") -> dict[str, Any]:
    capability = require_polling_plugin()
    parser = getattr(capability, "parse_eim_local_ipae_options", None)
    if callable(parser) is False:
        raise RuntimeError("Polling capability does not expose parse_eim_local_ipae_options().")
    return parser(str(argument or ""))


def parse_eim_local_ipae_args(argument: str = "") -> tuple[int, int, bool]:
    """Parse IPA-E argument strings for the eIM-local IPAE handler."""
    options = parse_eim_local_ipae_options(argument)
    return (
        int(options.get("poll_attempts_per_fqdn", 1) or 1),
        int(options.get("timer_expiration_window_seconds", 30) or 0),
        bool(options.get("debug", False)),
    )
