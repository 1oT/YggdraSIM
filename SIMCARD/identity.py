# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""GET IDENTITY (CLA=80 INS=78) handler -- USIM-side SUCI calculation.

TS 31.102 §7.1.2.4 defines GET IDENTITY:

    CLA   = '80'
    INS   = '78'
    P1    = '00'
    P2    = identity-context (0x01 = SUCI)
    Lc    = optional command parameters (currently unused)
    Le    = '00' (return up to 256 bytes)

Response data is the SUCI as defined in TS 24.501 §9.11.3.4 (the
mobile-identity IE contents starting at octet 1, no outer length).

Scheme selection:

* The simulator walks EF.SUCI_Calc_Info's priority list top-down,
  picks the first entry whose protection scheme it supports
  (currently null, Profile A, Profile B), looks up the matching HN
  public key in the same EF, and uses it.
* If EF.SUCI_Calc_Info is empty or no entry matches, the simulator
  falls back to the null scheme. Real cards are required to support
  the null scheme as a fallback.
"""

from __future__ import annotations

from SIMCARD.state import SimCardState
from SIMCARD.suci import (
    ProtectionScheme,
    build_suci_from_imsi,
    decode_ef_suci_calc_info,
)


P2_SUCI_CALCULATION = 0x01


class IdentityLogic:
    """Implements the GET IDENTITY APDU.

    Owned by the engine alongside :class:`AuthLogic`. The class holds
    no mutable state of its own; everything it needs comes from the
    shared :class:`SimCardState` and the file-system handle.
    """

    def __init__(self, state: SimCardState, file_system: object) -> None:
        self.state = state
        self.fs = file_system

    def handle_get_identity(self, p1: int, p2: int, data: bytes) -> tuple[bytes, int, int]:
        """Handle the GET IDENTITY command and return the EID or ICCID per the P1 selector."""
        if int(p1) & 0xFF != 0x00:
            return b"", 0x6A, 0x86
        if int(p2) & 0xFF != P2_SUCI_CALCULATION:
            return b"", 0x6A, 0x86
        imsi = self._active_imsi()
        if len(imsi) == 0:
            return b"", 0x69, 0x85
        mnc_length = self._active_mnc_length()
        scheme, hn_key = self._select_scheme()
        routing_indicator = self._active_routing_indicator()
        try:
            suci = build_suci_from_imsi(
                imsi=imsi,
                mnc_length=mnc_length,
                routing_indicator=routing_indicator,
                protection_scheme=scheme,
                home_network_public_key=hn_key,
            )
        except (ValueError, NotImplementedError):
            return b"", 0x69, 0x85
        return suci, 0x90, 0x00

    def _active_imsi(self) -> str:
        # Prefer the active profile's IMSI; fall back to the
        # state-level IMSI for the pre-profile bring-up case.
        active_aid = str(self.state.active_profile_aid or "").strip().upper()
        for profile in self.state.profiles:
            if str(profile.aid or "").strip().upper() == active_aid:
                if len(profile.imsi or "") > 0:
                    return str(profile.imsi).strip()
        return str(self.state.imsi or "").strip()

    def _active_mnc_length(self) -> int:
        node = self._find_node(("MF", "ADF.USIM", "EF.AD"))
        if node is not None:
            data = bytes(getattr(node, "data", b"") or b"")
            if len(data) >= 4:
                # EF.AD octet 4 lower nibble = MNC length per TS 31.102 §4.2.18.
                value = data[3] & 0x0F
                if value in (2, 3):
                    return value
        return 2

    def _active_routing_indicator(self) -> str:
        node = self._find_node(("MF", "ADF.USIM", "DF.5GS", "EF.ROUTING-INDICATOR"))
        if node is None:
            return "0"
        data = bytes(getattr(node, "data", b"") or b"")
        digits: list[str] = []
        for byte in data[:2]:
            low = byte & 0x0F
            high = (byte >> 4) & 0x0F
            if low == 0xF:
                break
            digits.append(str(low))
            if high == 0xF:
                break
            digits.append(str(high))
        return "".join(digits) if len(digits) > 0 else "0"

    def _select_scheme(self):
        node = self._find_node(("MF", "ADF.USIM", "DF.5GS", "EF.SUCI_Calc_Info"))
        if node is None:
            return ProtectionScheme.NULL, None
        info = decode_ef_suci_calc_info(bytes(getattr(node, "data", b"") or b""))
        for _, scheme, key_id in sorted(info.priority_list, key=lambda item: item[0]):
            if scheme == ProtectionScheme.NULL:
                return ProtectionScheme.NULL, None
            for key in info.public_keys:
                if key.key_identifier == key_id and key.protection_scheme == scheme:
                    return scheme, key
        # Empty / unmatched priority list -> null scheme fallback.
        return ProtectionScheme.NULL, None

    def _find_node(self, path: tuple[str, ...]):
        if hasattr(self.fs, "find_node_by_path") is False:
            return None
        return self.fs.find_node_by_path(path)


__all__ = ["IdentityLogic", "P2_SUCI_CALCULATION"]
