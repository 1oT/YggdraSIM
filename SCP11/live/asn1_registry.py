# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Alias of the shared SCP11 ASN.1 registry (``SCP11.asn1_registry``) under the live namespace."""
from __future__ import annotations

import sys

from SCP11 import asn1_registry as _impl

sys.modules[__name__] = _impl
