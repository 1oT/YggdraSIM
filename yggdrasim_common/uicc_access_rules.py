# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Access rules of ETSI TS 102 221 v18.4 clause 9.2: access modes and key references.

Table 9.3 maps the one-byte key reference of an EF.ARR security-condition CRT
(tag '83') onto the PIN it names. Two views ship: the compact labels the
profile inspector prints, and the spelled-out labels the live decoded view
prints beside a usage qualifier.

Clause 9.2.2 makes the access-mode byte file dependent, so the bit table that
names its operations travels with the scope of the file whose FCP references
the record.
"""

from __future__ import annotations

from typing import Final

STYLE_SHORT: Final[str] = "short"
STYLE_VERBOSE: Final[str] = "verbose"

# §9.2.2: the top four bits mean the same for both file kinds; the low three do
# not. A record does not say which kind it governs -- the file whose FCP
# references it does -- so the caller passes the scope. pySim carries the same
# two tables and picks the EF one unconditionally, because its shell reads a
# record without knowing the referrer.
ARR_SCOPE_EF: Final[str] = "ef"
ARR_SCOPE_DF: Final[str] = "df"

_ARR_ACCESS_MODE_FLAGS_EF: tuple[tuple[int, str], ...] = (
    (0x01, "READ"),
    (0x02, "UPDATE"),
    (0x04, "APPEND"),
    (0x08, "DEACTIVATE"),
    (0x10, "ACTIVATE"),
    (0x20, "TERMINATE"),
    (0x40, "DELETE_FILE"),
)

_ARR_ACCESS_MODE_FLAGS_DF: tuple[tuple[int, str], ...] = (
    (0x01, "DELETE_CHILD"),
    (0x02, "CREATE_EF"),
    (0x04, "CREATE_DF"),
    (0x08, "DEACTIVATE"),
    (0x10, "ACTIVATE"),
    (0x20, "TERMINATE"),
    (0x40, "DELETE_FILE"),
)


def arr_access_mode_flags(scope: str) -> tuple[tuple[int, str], ...]:
    """Return the access-mode bit table governing ``scope`` (§9.2.2)."""
    if str(scope or "").strip().lower() == ARR_SCOPE_DF:
        return _ARR_ACCESS_MODE_FLAGS_DF
    return _ARR_ACCESS_MODE_FLAGS_EF


def key_reference_name(key_reference: int, *, style: str = STYLE_SHORT) -> str:
    """Name a key reference per TS 102 221 v18.4 table 9.3.

    '01'-'08' are PIN Appl 1 to 8 ('01' being PIN1), '0A'-'0E' ADM1 to ADM5,
    '11' the Universal PIN, '81'-'88' Second PIN Appl 1 to 8 ('81' being
    PIN2) and '8A'-'8E' ADM6 to ADM10; '09', '89', '12'-'1E' and '90'-'9E'
    are RFU. ``style`` picks between the inspector's compact labels and the
    spelled-out labels of the live decoded view.
    """
    if style not in (STYLE_SHORT, STYLE_VERBOSE):
        raise ValueError("style must be 'short' or 'verbose'.")
    verbose = style == STYLE_VERBOSE
    if key_reference == 0x01:
        return "PIN1 (Application PIN 1)" if verbose else "PIN1"
    if 0x02 <= key_reference <= 0x08:
        if verbose:
            return f"Application PIN {key_reference}"
        return f"PIN Appl {key_reference}"
    if 0x0A <= key_reference <= 0x0E:
        return f"ADM{key_reference - 0x09}"
    if key_reference == 0x11:
        return "Universal PIN"
    if key_reference == 0x81:
        return "PIN2 (Application 1)" if verbose else "PIN2"
    if 0x82 <= key_reference <= 0x88:
        application = key_reference - 0x80
        if verbose:
            return f"Second PIN (Application {application})"
        return f"Second PIN Appl {application}"
    if 0x8A <= key_reference <= 0x8E:
        return f"ADM{key_reference - 0x84}"
    if key_reference in (0x09, 0x89):
        if verbose:
            return f"RFU key reference (0x{key_reference:02X})"
        return f"RFU (0x{key_reference:02X})"
    if 0x12 <= key_reference <= 0x1E:
        if verbose:
            return f"RFU global key reference (0x{key_reference:02X})"
        return f"RFU global (0x{key_reference:02X})"
    if 0x90 <= key_reference <= 0x9E:
        if verbose:
            return f"RFU local key reference (0x{key_reference:02X})"
        return f"RFU local (0x{key_reference:02X})"
    return f"KeyRef(0x{key_reference:02X})"
