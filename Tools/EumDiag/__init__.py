"""
EUM diagnostics "God-Mode" — Lua/tshark BPP dissector + key injection.

This package ships three cooperating pieces:

* :mod:`Tools.EumDiag.session_keys` — strongly-typed container for
  GSMA SGP.22 session keys (ShS-ENC, ShS-MAC, optional DEK) plus
  atomic write to a sidecar JSON file.
* ``dissector.lua`` — a Wireshark/tshark Lua script that loads the
  sidecar at startup and annotates BF36 Bound Profile Package
  frames with decrypted TLV subtrees.
* :mod:`Tools.EumDiag.tshark_runner` — subprocess wrapper that spawns
  tshark against a PCAP with the dissector and the correct
  environment.

The Python side is import-safe on hosts without tshark; only the CLI
"decode" path attempts to invoke the external binary. BPP pay-load
crypto in Python leans on pySim when available — we do not reimplement
AES-128-CBC / CMAC here just to satisfy a fallback.

See ``site-docs/subsystems/eum-diag.md`` (added in this pass) for the
EUM operator workflow.
"""

from __future__ import annotations

__all__ = [
    "session_keys",
    "tshark_runner",
    "main",
]
