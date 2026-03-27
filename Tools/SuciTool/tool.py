import os
import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence


@dataclass
class SuciCommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


class SuciKeyToolBridge:
    def __init__(
        self,
        workspace_root: Path,
        runner: Optional[Callable[[Sequence[str]], subprocess.CompletedProcess[str]]] = None,
        tool_command: Optional[Sequence[str]] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.runner = runner or self._run_subprocess
        self._tool_command = list(tool_command) if tool_command is not None else None
        self.current_key_file: Optional[Path] = None

    def set_key_file(self, path_text: str) -> Path:
        resolved_path = self.resolve_path(path_text, must_exist=False)
        if resolved_path.exists() and resolved_path.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {resolved_path}")
        self.current_key_file = resolved_path
        return resolved_path

    def get_key_file(self) -> Path:
        if self.current_key_file is None:
            raise ValueError("No SUCI key file selected. Use USE <path> first.")
        return self.current_key_file

    def set_tool_command(self, command_text: str) -> list[str]:
        tokens = shlex.split(command_text.strip())
        if len(tokens) == 0:
            raise ValueError("Tool command cannot be empty.")
        self._tool_command = tokens
        return list(self._tool_command)

    def get_tool_command(self) -> list[str]:
        if self._tool_command is not None:
            return list(self._tool_command)

        configured_value = os.environ.get("YGGDRASIM_SUCI_TOOL", "").strip()
        if len(configured_value) > 0:
            self._tool_command = shlex.split(configured_value)
            return list(self._tool_command)

        for candidate in ("suci-keytool.py", "suci-keytool"):
            resolved_binary = shutil.which(candidate)
            if resolved_binary is not None:
                self._tool_command = [resolved_binary]
                return list(self._tool_command)

        raise RuntimeError(
            "suci-keytool was not found. Install pySim suci-keytool or set YGGDRASIM_SUCI_TOOL."
        )

    def describe_status(self) -> str:
        key_file = "(not selected)"
        if self.current_key_file is not None:
            key_file = self._display_path(self.current_key_file)
        return f"Active key file: {key_file}"

    def describe_tool_command(self) -> str:
        try:
            return " ".join(self.get_tool_command())
        except Exception as error:
            return f"unavailable ({error})"

    def _display_path(self, path_value: Path) -> str:
        path_obj = Path(path_value)
        try:
            return path_obj.relative_to(self.workspace_root).as_posix()
        except ValueError:
            return str(path_obj)

    def resolve_path(self, path_text: str, must_exist: bool = False) -> Path:
        raw_value = str(path_text or "").strip()
        if len(raw_value) == 0:
            raise ValueError("Path cannot be empty.")

        candidate_path = Path(raw_value)
        if candidate_path.is_absolute() is False:
            candidate_path = self.workspace_root / candidate_path

        resolved_path = candidate_path.resolve()
        if self._is_within_workspace(resolved_path) is False:
            raise ValueError(f"Path is outside workspace root: {resolved_path}")

        if must_exist and resolved_path.exists() is False:
            raise FileNotFoundError(f"Path not found: {resolved_path}")

        return resolved_path

    def run_current(self, args: Sequence[str]) -> SuciCommandResult:
        return self.run(self.get_key_file(), args)

    def run(self, key_file: Path, args: Sequence[str]) -> SuciCommandResult:
        resolved_key_file = self.resolve_path(str(key_file), must_exist=False)
        if resolved_key_file.exists() and resolved_key_file.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {resolved_key_file}")

        command = self.get_tool_command()
        command.extend(["--key-file", str(resolved_key_file)])
        for arg in args:
            command.append(str(arg))

        completed = self.runner(command)
        return SuciCommandResult(
            command=list(command),
            returncode=int(completed.returncode),
            stdout=str(completed.stdout or ""),
            stderr=str(completed.stderr or ""),
        )

    @staticmethod
    def _run_subprocess(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command),
            check=False,
            capture_output=True,
            text=True,
        )

    def _is_within_workspace(self, resolved_path: Path) -> bool:
        try:
            resolved_path.relative_to(self.workspace_root)
        except ValueError:
            return False
        return True
