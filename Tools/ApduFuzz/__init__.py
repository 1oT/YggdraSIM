"""
APDU mutation fuzzer for physical eUICC vulnerability research.

This package deliberately sits behind a hard safety gate. Running it
against the wrong card can permanently brick a production UICC (some
vendors refuse to re-enter VPP training on reader disconnects during
a post-INSTALL flow, others panic on BER-TLV length mismatches in
proprietary tags). See :mod:`Tools.ApduFuzz.safety` for the required
opt-in tokens and ICCID/IMSI whitelist semantics.

Public surface:

* :mod:`Tools.ApduFuzz.mutators` — stateless mutation strategies.
* :mod:`Tools.ApduFuzz.corpus`   — loader for known-good APDU
  sequences (simulator session recordings).
* :mod:`Tools.ApduFuzz.safety`   — gate validation, crash-dump
  directories, per-IMSI allow-lists.
* :mod:`Tools.ApduFuzz.runner`   — PC/SC or HIL-bridge driven replay.
* :mod:`Tools.ApduFuzz.main`     — CLI entry point.
"""

from __future__ import annotations

__all__ = [
    "mutators",
    "corpus",
    "safety",
    "runner",
    "main",
]
