# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""SCP11-relay data models: ES2+/ES9+ request/response dataclasses for the compatibility namespace."""

from SCP11 import models as _impl
from SCP11.shared.compat_exports import reexport_public


__all__ = reexport_public(_impl, globals())
