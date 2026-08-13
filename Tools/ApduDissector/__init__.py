# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Deep APDU dissection for Wireshark and tshark.

The Lua dissector under ``lua/`` decodes the GSMTAP SIM frames the HIL
bridge mirrors on UDP 4729, down through BER-TLV, file-control templates
and elementary-file contents. This package locates it, builds tshark
invocations around it, and installs it into the Wireshark GUI.
"""
