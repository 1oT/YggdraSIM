import argparse
import sys
from pathlib import Path

from yggdrasim_common.quit_control import QuitAllRequested

try:
    from .shell import SuciToolShell
except ImportError:
    from Tools.SuciTool.shell import SuciToolShell


def entry() -> None:
    workspace_root = Path(__file__).resolve().parents[2]
    shell = SuciToolShell(workspace_root=workspace_root)
    shell.run()


def entry_cmd(cmd_line: str) -> None:
    workspace_root = Path(__file__).resolve().parents[2]
    shell = SuciToolShell(workspace_root=workspace_root)
    shell.run_commands(cmd_line)


def entry_stdin() -> None:
    command_lines: list[str] = []
    for raw_line in sys.stdin.read().splitlines():
        command_text = str(raw_line or "").strip()
        if len(command_text) == 0:
            continue
        if command_text.startswith("#"):
            continue
        command_lines.append(command_text)
    entry_cmd("; ".join(command_lines))


def run_standalone() -> None:
    parser = argparse.ArgumentParser(description="YggdraSIM SUCI Tool")
    parser.add_argument(
        "--cmd",
        type=str,
        help="Semicolon-separated commands for non-interactive execution",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read newline-separated commands from stdin for non-interactive execution",
    )
    args = parser.parse_args()
    if args.cmd:
        entry_cmd(args.cmd)
        return
    if args.stdin:
        entry_stdin()
        return
    entry()


if __name__ == "__main__":
    try:
        run_standalone()
    except QuitAllRequested:
        raise SystemExit(0)
