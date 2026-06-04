# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 test Command Center actions.

Programmatic mirror of :mod:`yggdrasim_common.gui_server.actions.scp11_live`
that reroutes every dispatcher at the provider-import layer so the same
code path runs under the ``SCP11.test`` (SGP.26 test CA) flavour. No
dispatcher logic is duplicated — each mirrored spec wraps the live
dispatcher inside a ``_use_provider("test")`` context so the contextvar
in ``scp11_live`` swaps ``SCP11.live.*`` imports to ``SCP11.test.*`` for
the duration of that call.

Every live spec is cloned. The ``id`` prefix becomes ``scp11_test.``,
the ``subsystem`` label becomes ``eSIM Test``, tags gain a ``test``
marker, and a ``(test CA)`` suffix is appended to the title so the
Command Center sidebar clearly separates live from test flows.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from dataclasses import replace
from typing import Any, AsyncIterator, Callable

from . import scp11_live as _live
from .registry import ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.scp11_test")


_LIVE_SUBSYSTEM_LABEL = "eSIM Live"
_TEST_SUBSYSTEM_LABEL = "eSIM Test"
_LIVE_ID_PREFIX = "scp11_live."
_TEST_ID_PREFIX = "scp11_test."


def _wrap_sync(dispatcher: Callable[..., Any]) -> Callable[..., Any]:
    """Run a synchronous live dispatcher with the test provider pinned."""

    def _runner(*args: Any, **kwargs: Any) -> Any:
        with _live._use_provider("test"):
            return dispatcher(*args, **kwargs)

    _runner.__name__ = f"{dispatcher.__name__}__test"
    _runner.__doc__ = dispatcher.__doc__
    return _runner


def _wrap_async_generator(dispatcher: Callable[..., AsyncIterator[Any]]) -> Callable[..., Any]:
    """Wrap a streaming dispatcher so the provider override spans the whole stream."""

    async def _runner(*args: Any, **kwargs: Any) -> AsyncIterator[Any]:
        token = _live._PROVIDER_PACKAGE.set("test")
        try:
            async for event in dispatcher(*args, **kwargs):
                yield event
        finally:
            _live._PROVIDER_PACKAGE.reset(token)

    _runner.__name__ = f"{dispatcher.__name__}__test"
    _runner.__doc__ = dispatcher.__doc__
    return _runner


def _wrap_dispatcher(dispatcher: Callable[..., Any]) -> Callable[..., Any]:
    """Dispatch-kind aware wrapper: pick sync vs async-generator path."""
    if inspect.isasyncgenfunction(dispatcher):
        return _wrap_async_generator(dispatcher)
    if asyncio.iscoroutinefunction(dispatcher):
        # Currently no coroutine dispatchers in scp11_live, but stay safe.
        async def _coro_runner(*args: Any, **kwargs: Any) -> Any:
            token = _live._PROVIDER_PACKAGE.set("test")
            try:
                return await dispatcher(*args, **kwargs)
            finally:
                _live._PROVIDER_PACKAGE.reset(token)

        _coro_runner.__name__ = f"{dispatcher.__name__}__test"
        _coro_runner.__doc__ = dispatcher.__doc__
        return _coro_runner
    return _wrap_sync(dispatcher)


def _mirror_spec(source: ActionSpec) -> ActionSpec:
    """Clone a live spec into its eSIM Test twin."""
    new_id = source.id
    if new_id.startswith(_LIVE_ID_PREFIX):
        new_id = _TEST_ID_PREFIX + new_id[len(_LIVE_ID_PREFIX):]
    else:
        new_id = _TEST_ID_PREFIX + new_id

    new_title = str(source.title or "").strip()
    if len(new_title) == 0:
        new_title = new_id
    if "(test CA)" not in new_title and "(test)" not in new_title.lower():
        new_title = f"{new_title} (test CA)"

    new_subsystem = source.subsystem
    if str(source.subsystem or "").strip() == _LIVE_SUBSYSTEM_LABEL:
        new_subsystem = _TEST_SUBSYSTEM_LABEL

    new_tags = tuple(source.tags or ())
    if "test" not in new_tags:
        new_tags = new_tags + ("test",)

    wrapped = _wrap_dispatcher(source.dispatcher)

    return replace(
        source,
        id=new_id,
        title=new_title,
        subsystem=new_subsystem,
        dispatcher=wrapped,
        tags=new_tags,
    )


def _register_test_mirrors() -> int:
    """Register an ``scp11_test.*`` spec for every live spec that exists."""
    registry = get_registry()
    live_specs = [spec for spec in registry.all() if spec.id.startswith(_LIVE_ID_PREFIX)]
    if len(live_specs) == 0:
        _LOGGER.warning(
            "scp11_test mirror found zero scp11_live specs — "
            "did scp11_live fail to import first?"
        )
    count = 0
    for spec in live_specs:
        if registry.has(_TEST_ID_PREFIX + spec.id[len(_LIVE_ID_PREFIX):]):
            continue
        try:
            registry.register(_mirror_spec(spec))
            count += 1
        except Exception as error:  # noqa: BLE001
            _LOGGER.warning(
                "scp11_test mirror failed for %s: %s",
                spec.id,
                error,
            )
    return count


_REGISTERED_COUNT = _register_test_mirrors()
