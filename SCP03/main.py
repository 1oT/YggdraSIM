# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP03 package entry point."""
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

import sys
import os

from yggdrasim_common.process_debug import (
    add_debug_argument,
    is_global_debug_enabled,
    set_global_debug,
)
from yggdrasim_common.quit_control import QuitAllRequested


current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)


def _build_dispatcher(reader_name: str = ""):
    try:
        from SCP03.interface.shell import ShellDispatcher
    except ImportError as e:
        print(f"Critical Import Error: {e}")
        print(
            "Ensure you are running this from the correct directory or that 'SCP03' is strictly a subdirectory."
        )
        sys.exit(1)
    try:
        dispatcher = ShellDispatcher(reader_name=reader_name)
    except RuntimeError as error:
        # A reader that does not resolve (a typo, or a Remote Lab rig that is
        # not connected) is a clean startup failure, never a fallback to
        # whatever card sits in the first reader.
        print(f"[SCP03] {error}")
        raise SystemExit(2) from error
    if is_global_debug_enabled():
        dispatcher.debug_mode = True
        try:
            dispatcher.transport.debug = True
        except Exception:
            pass
    return dispatcher


def run_script(file_path):
    """Execute a scripted SCP03 session from the supplied script file path."""
    try:
        app = _build_dispatcher()
        app.run_script(file_path)
    except KeyboardInterrupt:
        print("\n[SCP03] Script execution terminated by user.")
    except Exception as e:
        print(f"\n[SCP03] Fatal Error: {e}")


def run_report_wizard():
    """Run the FS report wizard against the active card and write output."""
    from SCP03.interface.shell_wizards import ShellInteractiveWizards

    try:
        app = _build_dispatcher()
        ShellInteractiveWizards.run_fs_report_wizard(app)
    except KeyboardInterrupt:
        print("\n[SCP03] Report wizard terminated by user.")
    except Exception as e:
        print(f"\n[SCP03] Fatal Error: {e}")


def entry(reader_name: str = ""):
    """
    Public entry point.
    The high-level wrapper should import this function to start the module.
    Example:
        import SCP03.main as scp03_feature
        scp03_feature.entry()
    """
    try:
        app = _build_dispatcher(reader_name=reader_name)
        app.run()
    except KeyboardInterrupt:
        print("\n[SCP03] Session terminated by user.")
    except Exception as e:
        print(f"\n[SCP03] Fatal Error: {e}")


def entry_cmd(cmd_line: str, yaml_out: str = None, reader_name: str = ""):
    """
    Non-interactive entry: run semicolon-separated commands and optionally write output to YAML.
    Example: entry_cmd("AUTH-SD; LIST", "report.yaml")
    """
    try:
        app = _build_dispatcher(reader_name=reader_name)
        app.run_commands(cmd_line, yaml_out=yaml_out)
    except KeyboardInterrupt:
        print("\n[SCP03] Interrupted.")
    except Exception as e:
        print(f"\n[SCP03] Fatal Error: {e}")
        raise


def entry_stdin(yaml_out: str = None, reader_name: str = ""):
    """Start an interactive SCP03 shell session reading commands from stdin."""
    command_lines = []
    for raw_line in sys.stdin.read().splitlines():
        command_text = str(raw_line or "").strip()
        if len(command_text) == 0:
            continue
        if command_text.startswith("#"):
            continue
        command_lines.append(command_text)
    entry_cmd("; ".join(command_lines), yaml_out=yaml_out, reader_name=reader_name)


def run_standalone():
    """Parse CLI arguments, establish the transport, and dispatch to the chosen run mode."""
    import argparse

    parser = argparse.ArgumentParser(description="YggdraSIM SCP03 Admin Shell")
    parser.add_argument(
        "--cmd", type=str, help="Semicolon-separated commands (non-interactive)"
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read newline-separated commands from stdin (non-interactive)",
    )
    parser.add_argument("--out", type=str, help="Output YAML file for --cmd")
    parser.add_argument(
        "--reader",
        type=str,
        default="",
        help=(
            "Reader to open: an exact PC/SC reader name, or a Remote Lab reader "
            "name (\"Remote Lab: <device>\") connected from the GUI. Default: the first PC/SC reader."
        ),
    )
    add_debug_argument(
        parser,
        help_text="Enable verbose debug output for this SCP03 session.",
    )
    args = parser.parse_args()
    set_global_debug(bool(getattr(args, "debug", False)))
    reader_name = str(getattr(args, "reader", "") or "")
    if args.cmd:
        entry_cmd(args.cmd, yaml_out=args.out, reader_name=reader_name)
        return
    if args.stdin:
        entry_stdin(yaml_out=args.out, reader_name=reader_name)
        return
    entry(reader_name=reader_name)


if __name__ == "__main__":
    try:
        run_standalone()
    except QuitAllRequested:
        raise SystemExit(0)
