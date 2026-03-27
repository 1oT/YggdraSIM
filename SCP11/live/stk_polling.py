from __future__ import annotations

from yggdrasim_common.polling_plugin_support import install_poll_method_stubs


class LiveStkPollingMixin:
    """Optional relay polling mixin backed by the polling plugin."""


install_poll_method_stubs(LiveStkPollingMixin)
