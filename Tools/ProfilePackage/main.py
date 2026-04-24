import argparse
import sys
from pathlib import Path

from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.runtime_paths import bundle_root, runtime_root

try:
    from .shell import ProfilePackageShell
except ImportError:
    from Tools.ProfilePackage.shell import ProfilePackageShell


def _shell_roots() -> tuple[Path, Path]:
    return Path(runtime_root()).resolve(), Path(bundle_root()).resolve()


def entry() -> None:
    workspace_root, bundle_root_path = _shell_roots()
    shell = ProfilePackageShell(
        workspace_root=workspace_root,
        bundle_root_path=bundle_root_path,
    )
    shell.run()


def entry_cmd(cmd_line: str) -> None:
    workspace_root, bundle_root_path = _shell_roots()
    shell = ProfilePackageShell(
        workspace_root=workspace_root,
        bundle_root_path=bundle_root_path,
    )
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
    parser = argparse.ArgumentParser(description="YggdraSIM SAIP Tool")
    add_debug_argument(
        parser,
        help_text="Accept the global debug flag for wrapper and batch compatibility.",
    )
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
    parser.add_argument(
        "--inspect",
        "--transcode-tui",
        dest="inspect",
        action="store_true",
        help="Open split-pane JSON/DER INSPECT UI (Textual; lazy-loaded)",
    )
    parser.add_argument(
        "--profile",
        type=str,
        default="",
        help="Profile path for --inspect (same resolution rules as USE)",
    )
    args = parser.parse_args()
    set_global_debug(bool(getattr(args, "debug", False)))
    if args.cmd:
        entry_cmd(args.cmd)
        return
    if args.stdin:
        entry_stdin()
        return
    if args.inspect:
        workspace_root, bundle_root_path = _shell_roots()
        shell = ProfilePackageShell(
            workspace_root=workspace_root,
            bundle_root_path=bundle_root_path,
        )
        profile_text = str(args.profile or "").strip()
        if len(profile_text) > 0:
            shell.bridge.set_input_file(profile_text)
        shell._cmd_inspect("")
        return
    entry()


if __name__ == "__main__":
    try:
        run_standalone()
    except QuitAllRequested:
        raise SystemExit(0)
