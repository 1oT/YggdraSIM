# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 utility helpers: hex/byte conversion, TAR formatting, and response status parsing."""
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

import binascii

from yggdrasim_common.cli_theme import ThemedColorsMeta as _ThemedColorsMeta


class Colors(metaclass=_ThemedColorsMeta):
    """ANSI terminal colours read from the active CLI theme."""

    _ROLE_MAP = {
        "HEADER": "HEADER",
        "BLUE": "BLUE",
        "CYAN": "CYAN",
        "GREEN": "GREEN",
        "WARNING": "WARNING",
        "FAIL": "FAIL",
    }

    @staticmethod
    def _hex_to_ansi(hex_color):
        hex_value = hex_color.lstrip("#")
        red = int(hex_value[0:2], 16)
        green = int(hex_value[2:4], 16)
        blue = int(hex_value[4:6], 16)
        return f"\033[38;2;{red};{green};{blue}m"


class Utils:
    @staticmethod
    def to_bytes(hex_str: str) -> bytes:
        normalized = "".join(str(hex_str).split())
        try:
            return binascii.unhexlify(normalized)
        except binascii.Error as exc:
            raise ValueError(
                f"Invalid hex input ({len(normalized)} chars): {normalized}"
            ) from exc

    @staticmethod
    def to_hex(data: bytes, space: bool = False) -> str:
        s = data.hex().upper()
        if space:
            return " ".join(s[i : i + 2] for i in range(0, len(s), 2))
        return s

    @staticmethod
    def pad_key_3des(key: bytes) -> bytes:
        return key if len(key) == 24 else key + key[:8]
