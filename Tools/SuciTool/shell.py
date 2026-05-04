from pathlib import Path
from typing import Callable

from yggdrasim_common.quit_control import quit_all
from yggdrasim_common.nord_palette import NORD
from .tool import SuciCommandResult, SuciKeyToolBridge


class ShellStyle:
    """SUCI tool shell colour roles, anchored to Nord."""

    HEADER = NORD.HEADER
    BLUE = NORD.BLUE
    CYAN = NORD.CYAN
    GREEN = NORD.GREEN
    WARNING = NORD.WARNING
    FAIL = NORD.FAIL
    BOLD = NORD.BOLD
    END = NORD.RESET


class SuciToolShell:
    def __init__(self, workspace_root: Path) -> None:
        self.bridge = SuciKeyToolBridge(workspace_root=workspace_root)
        self.prompt = f"\n{ShellStyle.BLUE}[SUCI Tool] > {ShellStyle.END}"
        self._commands: dict[str, Callable[[str], None]] = {
            "DUMP": self._cmd_dump,
            "EXIT": self._cmd_exit,
            "GENERATE": self._cmd_generate,
            "HELP": self._cmd_help,
            "PWD": self._cmd_pwd,
            "QA": self._cmd_quit_all,
            "Q": self._cmd_exit,
            "QUIT": self._cmd_exit,
            "STATUS": self._cmd_status,
            "TOOL": self._cmd_tool,
            "USE": self._cmd_use,
        }

    def run(self) -> None:
        self._print_banner()
        while True:
            try:
                raw_line = input(self.prompt).strip()
            except KeyboardInterrupt:
                print("")
                continue
            except EOFError:
                print("")
                return

            if len(raw_line) == 0:
                continue

            self._exec_line(raw_line)

    def run_commands(self, cmd_line: str) -> None:
        self._print_banner()
        for raw_command in str(cmd_line or "").split(";"):
            command_text = raw_command.strip()
            if len(command_text) == 0:
                continue
            try:
                self._exec_line(command_text)
            except SystemExit:
                break

    def _print_banner(self) -> None:
        print(f"{ShellStyle.HEADER}=== SUCI Key Tool ==={ShellStyle.END}")
        print(
            f"{ShellStyle.CYAN}[*] SUCI key generation and public key export shell.{ShellStyle.END}"
        )
        print(
            f"{ShellStyle.CYAN}[*] Workspace root: {self.bridge.workspace_root}{ShellStyle.END}"
        )
        self._cmd_status("")

    def _exec_line(self, raw_line: str) -> None:
        parts = raw_line.split(None, 1)
        command = parts[0].upper()
        argument = ""
        if len(parts) > 1:
            argument = parts[1]

        if command not in self._commands:
            print(f"{ShellStyle.FAIL}[-] Unknown command: {command}{ShellStyle.END}")
            return

        try:
            self._commands[command](argument)
        except SystemExit:
            raise
        except Exception as error:
            print(f"{ShellStyle.FAIL}[-] {error}{ShellStyle.END}")

    def _print_result(self, result: SuciCommandResult) -> None:
        if len(result.stdout.strip()) > 0:
            print(result.stdout.rstrip())

        if len(result.stderr.strip()) > 0:
            print(f"{ShellStyle.WARNING}{result.stderr.rstrip()}{ShellStyle.END}")

        if result.returncode == 0:
            print(f"{ShellStyle.GREEN}[+] Command completed successfully.{ShellStyle.END}")
            return

        print(
            f"{ShellStyle.FAIL}[-] suci-keytool exited with code {result.returncode}.{ShellStyle.END}"
        )

    def _cmd_help(self, _arg: str) -> None:
        print(f"\n{ShellStyle.BOLD}SUCI Tool commands:{ShellStyle.END}")
        print("  Context:")
        print("    Use this shell to generate SUCI key pairs and export public keys for USIM / 5GS provisioning flows.")
        print("    Start by selecting a key file with `USE`, then generate or dump the public key from that file.")
        print("    Supported curves are `secp256r1` and `curve25519`.")
        print("")
        print("  Typical workflow:")
        print("    1. USE tests/demo_suci.key")
        print("    2. GENERATE SECP256R1")
        print("    3. DUMP")
        print("    4. DUMP COMPRESSED")
        print("")
        print("  USE <key_file>             Select active SUCI key file inside workspace.")
        print("  STATUS                     Show the active key file selection.")
        print("  TOOL [command]             Show or override the suci-keytool executable command.")
        print("  GENERATE <SECP256R1|CURVE25519>")
        print("                             Run `generate-key --curve ...`.")
        print("  DUMP [COMPRESSED]          Run `dump-pub-key` and optionally `--compressed`.")
        print("  PWD                        Print current workspace root and selected key file.")
        print("  EXIT / Q                   Leave the SUCI Tool shell.")
        print("  QA                         Leave the SUCI Tool shell and exit YggdraSIM.")
        print("")
        print("  Examples:")
        print("    USE tests/demo_suci.key")
        print("    GENERATE CURVE25519")
        print("    DUMP")
        print("    DUMP COMPRESSED")

    def _cmd_status(self, _arg: str) -> None:
        print(f"{ShellStyle.CYAN}[*] {self.bridge.describe_status()}{ShellStyle.END}")

    def _cmd_pwd(self, _arg: str) -> None:
        print(f"Workspace: {self.bridge.workspace_root}")
        key_file = self.bridge.current_key_file
        if key_file is None:
            print("Key file: (not selected)")
            return
        print(f"Key file: {key_file}")

    def _cmd_tool(self, arg: str) -> None:
        if len(arg.strip()) == 0:
            print(
                f"{ShellStyle.CYAN}[*] Tool command: "
                f"{self.bridge.describe_tool_command()}{ShellStyle.END}"
            )
            return

        tokens = self.bridge.set_tool_command(arg)
        print(f"{ShellStyle.GREEN}[+] Tool command set to: {' '.join(tokens)}{ShellStyle.END}")

    def _cmd_use(self, arg: str) -> None:
        selected = self.bridge.set_key_file(arg)
        print(f"{ShellStyle.GREEN}[+] Active key file: {selected}{ShellStyle.END}")

    def _cmd_generate(self, arg: str) -> None:
        curve = arg.strip().lower()
        if curve not in ("secp256r1", "curve25519"):
            raise ValueError("Usage: GENERATE <SECP256R1|CURVE25519>")
        result = self.bridge.run_current(["generate-key", "--curve", curve])
        self._print_result(result)

    def _cmd_dump(self, arg: str) -> None:
        raw_arg = arg.strip().upper()
        command = ["dump-pub-key"]
        if len(raw_arg) > 0:
            if raw_arg not in ("COMPRESSED", "--COMPRESSED"):
                raise ValueError("Usage: DUMP [COMPRESSED]")
            command.append("--compressed")
        result = self.bridge.run_current(command)
        self._print_result(result)

    def _cmd_exit(self, _arg: str) -> None:
        raise SystemExit(0)

    def _cmd_quit_all(self, _arg: str) -> None:
        quit_all()
