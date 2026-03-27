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

from yggdrasim_common.quit_control import QuitAllRequested

def _load_live_main ():
    try:
        from .live.main import SCP11StartupError, SGP22Client, entry
    except ImportError:
        from SCP11.live.main import SCP11StartupError, SGP22Client, entry
    return SCP11StartupError, SGP22Client, entry


def entry ():
    _, _, live_entry =_load_live_main ()
    live_entry ()


if __name__ == "__main__":
    startup_error_cls, _, live_entry =_load_live_main ()
    try:
        live_entry ()
    except QuitAllRequested:
        raise SystemExit(0)
    except startup_error_cls as error:
        print (f"\n[STARTUP ERROR] {error}")