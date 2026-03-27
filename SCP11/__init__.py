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
# Copyright (c) 2026 Hampus Hellsberg and contributors
# -----------------------------------------------------------------------------

__all__ = [
    "SGPConfig",
    "SGP22Orchestrator",
]


def __getattr__(name):
    if name == "SGPConfig":
        from .live.config import SGPConfig
        return SGPConfig
    if name == "SGP22Orchestrator":
        from .live.orchestrator import SGP22Orchestrator
        return SGP22Orchestrator
    raise AttributeError(name)
