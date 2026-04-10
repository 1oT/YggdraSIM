import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional, Sequence

from yggdrasim_common.runtime_paths import remap_legacy_workspace_relative
from .saip_json_codec import transcode_sidecar_paths

_DEFAULT_TOOL_TIMEOUT_SECONDS = 60
_TOOL_TIMEOUT_ENV = "YGGDRASIM_SAIP_TOOL_TIMEOUT_SECONDS"


@dataclass
class SaipCommandResult:
    command: list[str]
    returncode: int
    stdout: str
    stderr: str


def _repo_root_from_saip_module() -> Path:
    """Resolve YggdraSIM tree root from this file (.../Tools/ProfilePackage/saip_tool.py)."""
    return Path(__file__).resolve().parents[2]


def _describe_exception_chain(error: BaseException) -> str:
    parts: list[str] = []
    current: BaseException | None = error
    while current is not None:
        text = str(current).strip() or current.__class__.__name__
        if len(parts) == 0 or parts[-1] != text:
            parts.append(text)
        next_error = getattr(current, "__cause__", None)
        if isinstance(next_error, BaseException):
            current = next_error
            continue
        break
    return " | ".join(parts)


def _parse_timeout_seconds(raw_value: object) -> int:
    try:
        parsed = int(str(raw_value or "").strip())
    except Exception:
        return _DEFAULT_TOOL_TIMEOUT_SECONDS
    if parsed <= 0:
        return _DEFAULT_TOOL_TIMEOUT_SECONDS
    return parsed


class SaipToolBridge:
    _HEX_INPUT_SUFFIXES = {".hex", ".txt"}
    _RAW_INPUT_PATH_FLAGS = {
        "--applet-file": True,
        "--output-dir": False,
        "--output-file": False,
        "--output-prefix": False,
        "--pe-file": False,
    }

    def __init__(
        self,
        workspace_root: Path,
        runner: Optional[Callable[[Sequence[str]], subprocess.CompletedProcess[str]]] = None,
        tool_command: Optional[Sequence[str]] = None,
        config_path: Optional[Path] = None,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve()
        self.runner = runner if runner is not None else self._run_subprocess
        self.command_timeout_seconds = _parse_timeout_seconds(
            os.environ.get(_TOOL_TIMEOUT_ENV, _DEFAULT_TOOL_TIMEOUT_SECONDS)
        )
        self._tool_command = list(tool_command) if tool_command is not None else None
        self.config_path = (
            Path(config_path).resolve()
            if config_path is not None
            else (self.workspace_root / "Workspace" / "SAIP" / "saip_tool_config.json")
        )
        self.default_profile_dir = self.workspace_root / "Workspace" / "SAIP" / "profile"
        self.default_transcode_dir = self.workspace_root / "Workspace" / "SAIP" / "transcode"
        self.current_input_file: Optional[Path] = None
        self._load_config()
        self._seed_tree_if_missing(
            self.workspace_root / "Tools" / "ProfilePackage" / "profile",
            self.default_profile_dir,
        )
        self._seed_tree_if_missing(
            self.workspace_root / "Tools" / "ProfilePackage" / "examples",
            self.workspace_root / "Workspace" / "SAIP" / "examples",
        )
        self.default_profile_dir.mkdir(parents=True, exist_ok=True)
        self.default_transcode_dir.mkdir(parents=True, exist_ok=True)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

    def set_input_file(self, path_text: str) -> Path:
        resolved_path = self.resolve_input_path(path_text, must_exist=True)
        if resolved_path.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {resolved_path}")
        self.current_input_file = resolved_path
        return resolved_path

    def set_default_profile_dir(self, path_text: str) -> Path:
        resolved_path = self.resolve_workspace_path(path_text, must_exist=False)
        resolved_path.mkdir(parents=True, exist_ok=True)
        self.default_profile_dir = resolved_path
        self._save_config()
        return resolved_path

    def set_default_transcode_dir(self, path_text: str) -> Path:
        resolved_path = self.resolve_workspace_path(path_text, must_exist=False)
        resolved_path.mkdir(parents=True, exist_ok=True)
        self.default_transcode_dir = resolved_path
        self._save_config()
        return resolved_path

    def list_default_profiles(self) -> list[Path]:
        if self.default_profile_dir.exists() is False or self.default_profile_dir.is_dir() is False:
            return []

        profiles: list[Path] = []
        for entry in sorted(self.default_profile_dir.iterdir(), key=lambda item: item.name.lower()):
            if entry.is_file() is False:
                continue
            if entry.name.startswith("."):
                continue
            if self.is_transcode_sidecar(entry):
                continue
            profiles.append(entry.resolve())
        return profiles

    @staticmethod
    def _seed_tree_if_missing(source_dir: Path, target_dir: Path) -> None:
        source = Path(source_dir).resolve()
        target = Path(target_dir).resolve()
        if source == target:
            return
        if source.exists() is False or source.is_dir() is False:
            return
        target.mkdir(parents=True, exist_ok=True)
        for current_root, dir_names, file_names in os.walk(source):
            relative_root = Path(current_root).resolve().relative_to(source)
            destination_root = target / relative_root
            destination_root.mkdir(parents=True, exist_ok=True)
            for directory_name in dir_names:
                (destination_root / directory_name).mkdir(parents=True, exist_ok=True)
            for file_name in file_names:
                source_file = Path(current_root) / file_name
                target_file = destination_root / file_name
                if target_file.exists():
                    continue
                shutil.copy2(source_file, target_file)

    @staticmethod
    def is_transcode_sidecar(path_value: Path) -> bool:
        name = Path(path_value).name.lower()
        return (
            name.endswith(".transcode.json")
            or name.endswith(".transcode.der")
            or name.endswith(".transcode.txt")
        )

    def resolve_transcode_sidecar_paths(self, source_profile_path: Path) -> tuple[Path, Path, Path]:
        return transcode_sidecar_paths(
            source_profile_path,
            transcode_root=self.default_transcode_dir,
            source_root=self.default_profile_dir,
        )

    def get_input_file(self) -> Path:
        if self.current_input_file is None:
            raise ValueError("No profile package selected. Use USE <path> first.")
        return self.current_input_file

    def set_tool_command(self, command_text: str) -> list[str]:
        tokens = shlex.split(command_text.strip())
        if len(tokens) == 0:
            raise ValueError("Tool command cannot be empty.")
        self._tool_command = tokens
        return list(self._tool_command)

    def get_tool_command(self) -> list[str]:
        if self._tool_command is not None:
            return list(self._tool_command)

        configured_value = os.environ.get("YGGDRASIM_SAIP_TOOL", "").strip()
        if len(configured_value) > 0:
            self._tool_command = shlex.split(configured_value)
            return list(self._tool_command)

        for candidate in ("saip-tool.py", "saip-tool"):
            resolved_binary = shutil.which(candidate)
            if resolved_binary is not None:
                self._tool_command = [resolved_binary]
                return list(self._tool_command)

        seen_script: set[Path] = set()
        for base in (self.workspace_root, _repo_root_from_saip_module()):
            bundled_script = (base / "pysim" / "contrib" / "saip-tool.py").resolve()
            if bundled_script in seen_script:
                continue
            seen_script.add(bundled_script)
            if bundled_script.is_file():
                self._tool_command = [sys.executable, str(bundled_script)]
                return list(self._tool_command)

        raise RuntimeError(
            "saip-tool was not found. Install pySim saip-tool, set YGGDRASIM_SAIP_TOOL, "
            "or keep the vendored tree at <YggdraSIM>/pysim/contrib/saip-tool.py "
            f"(checked under workspace {self.workspace_root} and module root {_repo_root_from_saip_module()})."
        )

    def describe_status(self) -> str:
        current_file = "(not selected)"
        if self.current_input_file is not None:
            current_file = self._display_path(self.current_input_file)
        transcode_dir = self._display_path(self.default_transcode_dir)
        return f"Active profile: {current_file} | Transcode dir: {transcode_dir}"

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

    def display_path(self, path_value: Path) -> str:
        return self._display_path(path_value)

    def resolve_path(self, path_text: str, must_exist: bool = False) -> Path:
        return self.resolve_workspace_path(path_text, must_exist=must_exist)

    def _normalize_missing_leading_slash_input_path(
        self,
        raw_value: str,
        *,
        must_exist: bool,
    ) -> str:
        normalized = str(raw_value or "").strip()
        if must_exist is False:
            return normalized
        if normalized.startswith(os.sep) or normalized.startswith("~"):
            return normalized
        if normalized.startswith("home/") is False:
            return normalized

        workspace_candidate = (self.workspace_root / normalized).resolve()
        if workspace_candidate.exists():
            return normalized

        absolute_candidate = Path(os.sep + normalized).expanduser().resolve()
        if absolute_candidate.exists():
            return str(absolute_candidate)
        return normalized

    def resolve_input_path(self, path_text: str, must_exist: bool = False) -> Path:
        raw_value = str(path_text or "").strip()
        if len(raw_value) == 0:
            raise ValueError("Path cannot be empty.")
        raw_value = self._normalize_missing_leading_slash_input_path(
            raw_value,
            must_exist=must_exist,
        )
        if Path(raw_value).expanduser().is_absolute() is False:
            raw_value = remap_legacy_workspace_relative(raw_value)

        candidate_path = Path(raw_value).expanduser()
        if candidate_path.is_absolute() is False:
            has_relative_components = any(
                marker in raw_value for marker in ("/", os.sep)
            ) or raw_value.startswith(".")
            if has_relative_components is False:
                default_candidate = self.default_profile_dir / candidate_path
                resolved_default_candidate = default_candidate.resolve()
                if must_exist is False or resolved_default_candidate.exists():
                    return resolved_default_candidate
            candidate_path = self.workspace_root / candidate_path

        resolved_path = candidate_path.resolve()
        if must_exist and resolved_path.exists() is False:
            raise FileNotFoundError(f"Path not found: {resolved_path}")
        return resolved_path

    def resolve_workspace_path(self, path_text: str, must_exist: bool = False) -> Path:
        raw_value = str(path_text or "").strip()
        if len(raw_value) == 0:
            raise ValueError("Path cannot be empty.")
        if Path(raw_value).expanduser().is_absolute() is False:
            raw_value = remap_legacy_workspace_relative(raw_value)

        candidate_path = Path(raw_value).expanduser()
        if candidate_path.is_absolute() is False:
            candidate_path = self.workspace_root / candidate_path

        resolved_path = candidate_path.resolve()
        if self._is_within_workspace(resolved_path) is False:
            raise ValueError(f"Path is outside workspace root: {resolved_path}")

        if must_exist and resolved_path.exists() is False:
            raise FileNotFoundError(f"Path not found: {resolved_path}")

        return resolved_path

    def run_current(self, args: Sequence[str]) -> SaipCommandResult:
        return self.run(self.get_input_file(), args)

    def run(self, input_file: Path, args: Sequence[str]) -> SaipCommandResult:
        resolved_input = self.resolve_input_path(str(input_file), must_exist=True)
        if resolved_input.is_dir():
            raise IsADirectoryError(f"Expected a file, got directory: {resolved_input}")

        prepared_input = self._prepare_input_for_tool(resolved_input)
        command = self.get_tool_command()
        command.append(str(prepared_input))
        for arg in args:
            command.append(str(arg))

        completed = self.runner(command)
        return SaipCommandResult(
            command=list(command),
            returncode=int(completed.returncode),
            stdout=str(completed.stdout or ""),
            stderr=str(completed.stderr or ""),
        )

    def build_decoded_dump_document(self, mode: str) -> dict:
        resolved_input = self.resolve_input_path(str(self.get_input_file()), must_exist=True)
        prepared_input = self._prepare_input_for_tool(resolved_input)
        pysim_root = self.workspace_root / "pysim"
        if pysim_root.exists() is False:
            raise RuntimeError(f"Local pySim source tree not found: {pysim_root}")

        pysim_root_text = str(pysim_root)
        if pysim_root_text not in sys.path:
            sys.path.insert(0, pysim_root_text)

        from pySim.esim.saip import ProfileElementSequence

        try:
            pes = ProfileElementSequence.from_der(prepared_input.read_bytes())
        except Exception as error:
            detail = _describe_exception_chain(error)
            raise ValueError(
                f"Profile decode failed for {resolved_input}: {detail}"
            ) from error
        document: dict[str, object] = {
            "intro": [f"Read {len(pes.pe_list)} PEs from file '{prepared_input}'"],
            "sections": {},
        }
        sections: dict[str, object] = {}
        counts: dict[str, int] = {}

        def unique_key(base_key: str) -> str:
            key_text = str(base_key or "section").strip() or "section"
            current_count = counts.get(key_text, 0) + 1
            counts[key_text] = current_count
            if current_count == 1:
                return key_text
            return f"{key_text}_{current_count}"

        if mode == "all_pe":
            for pe in pes:
                sections[unique_key(pe.type)] = pe.decoded
        elif mode == "all_pe_by_type":
            for pe_type, pe_list in pes.pe_by_type.items():
                sections[unique_key(pe_type)] = [pe.decoded for pe in pe_list]
        elif mode == "all_pe_by_naa":
            for naa_name, naa_instances in pes.pes_by_naa.items():
                for index, naa_instance in enumerate(naa_instances):
                    sections[unique_key(f"{naa_name}{index}")] = [
                        {
                            "type": pe.type,
                            "decoded": pe.decoded,
                        }
                        for pe in naa_instance
                    ]
        else:
            raise ValueError(f"Unsupported decoded dump mode: {mode}")

        document["sections"] = sections
        return document

    def normalize_raw_arguments(self, tokens: Sequence[str]) -> list[str]:
        normalized: list[str] = []
        index = 0
        while index < len(tokens):
            token = str(tokens[index])
            if "=" in token:
                flag_name, raw_value = token.split("=", 1)
                if flag_name in self._RAW_INPUT_PATH_FLAGS:
                    must_exist = self._RAW_INPUT_PATH_FLAGS[flag_name]
                    resolver = self.resolve_input_path
                    if must_exist is False:
                        resolver = self.resolve_workspace_path
                    resolved_path = resolver(raw_value, must_exist=must_exist)
                    normalized.append(f"{flag_name}={resolved_path}")
                else:
                    normalized.append(token)
                index += 1
                continue

            normalized.append(token)
            if token in self._RAW_INPUT_PATH_FLAGS:
                must_exist = self._RAW_INPUT_PATH_FLAGS[token]
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(f"Missing value for {token}.")
                resolver = self.resolve_input_path
                if must_exist is False:
                    resolver = self.resolve_workspace_path
                resolved_path = resolver(str(tokens[next_index]), must_exist=must_exist)
                normalized.append(str(resolved_path))
                index += 2
                continue

            index += 1

        return normalized

    def _pysim_source_dirs(self) -> list[Path]:
        """Directories that contain the `pySim` package (vendored trees under .../pysim)."""
        roots: list[Path] = []
        seen: set[Path] = set()
        for base in (self.workspace_root, _repo_root_from_saip_module()):
            candidate = (base / "pysim").resolve()
            if candidate.is_dir() is False:
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            roots.append(candidate)
        return roots

    def _subprocess_env_with_pysim(self) -> dict[str, str]:
        env = dict(os.environ)
        pysim_dirs = self._pysim_source_dirs()
        if len(pysim_dirs) == 0:
            return env
        prepend = os.pathsep.join(str(item) for item in pysim_dirs)
        existing = str(env.get("PYTHONPATH", "") or "").strip()
        if len(existing) == 0:
            env["PYTHONPATH"] = prepend
            return env
        parts = existing.split(os.pathsep)
        filtered = [item for item in pysim_dirs if str(item) not in parts]
        if len(filtered) == 0:
            return env
        extra = os.pathsep.join(str(item) for item in filtered)
        env["PYTHONPATH"] = extra + os.pathsep + existing
        return env

    def _run_subprocess(self, command: Sequence[str]) -> subprocess.CompletedProcess[str]:
        normalized_command = list(command)
        try:
            return subprocess.run(
                normalized_command,
                check=False,
                capture_output=True,
                text=True,
                env=self._subprocess_env_with_pysim(),
                timeout=self.command_timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            stdout_text = getattr(error, "stdout", None)
            if stdout_text is None:
                stdout_text = getattr(error, "output", "")
            stderr_text = getattr(error, "stderr", "")
            if isinstance(stdout_text, bytes):
                stdout_text = stdout_text.decode("utf-8", "replace")
            if isinstance(stderr_text, bytes):
                stderr_text = stderr_text.decode("utf-8", "replace")
            timeout_message = (
                f"saip-tool timed out after {self.command_timeout_seconds}s while "
                "decoding or processing the profile."
            )
            detail = _describe_exception_chain(error)
            if len(detail) > 0:
                timeout_message += f" {detail}"
            if len(str(stderr_text).strip()) > 0:
                timeout_message += f"\n{str(stderr_text).strip()}"
            return subprocess.CompletedProcess(
                normalized_command,
                124,
                stdout=str(stdout_text),
                stderr=timeout_message,
            )

    def _prepare_input_for_tool(self, resolved_input: Path) -> Path:
        if resolved_input.suffix.lower() not in self._HEX_INPUT_SUFFIXES:
            return resolved_input

        text_payload = resolved_input.read_text(encoding="utf-8")
        normalized_hex = "".join(text_payload.split()).upper()
        if len(normalized_hex) == 0:
            raise ValueError(f"Hex input file is empty: {resolved_input}")

        for character in normalized_hex:
            if character not in "0123456789ABCDEF":
                raise ValueError(
                    f"Hex input file contains non-hex characters: {resolved_input}"
                )

        if len(normalized_hex) % 2 != 0:
            raise ValueError(f"Hex input file has odd-length payload: {resolved_input}")

        binary_payload = bytes.fromhex(normalized_hex)
        cache_dir = self.workspace_root / ".profilepackage-cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(resolved_input.as_posix().encode("utf-8") + binary_payload).hexdigest()
        cache_path = cache_dir / f"{resolved_input.stem}-{digest[:16]}.der"
        cache_path.write_bytes(binary_payload)
        return cache_path

    def _is_within_workspace(self, resolved_path: Path) -> bool:
        try:
            resolved_path.relative_to(self.workspace_root)
        except ValueError:
            return False
        return True

    def _load_config(self) -> None:
        if self.config_path.exists() is False:
            return

        try:
            payload = json.loads(self.config_path.read_text(encoding="utf-8"))
        except Exception:
            return

        profile_dir_value = str(payload.get("default_profile_dir", "")).strip()
        if len(profile_dir_value) > 0:
            try:
                self.default_profile_dir = self.resolve_workspace_path(profile_dir_value, must_exist=False)
            except Exception:
                pass

        transcode_dir_value = str(payload.get("default_transcode_dir", "")).strip()
        if len(transcode_dir_value) > 0:
            try:
                self.default_transcode_dir = self.resolve_workspace_path(
                    transcode_dir_value, must_exist=False
                )
            except Exception:
                pass

    def _save_config(self) -> None:
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            relative_profile_dir = self.default_profile_dir.relative_to(self.workspace_root)
            stored_profile_dir = relative_profile_dir.as_posix()
        except ValueError:
            stored_profile_dir = str(self.default_profile_dir)

        try:
            relative_transcode_dir = self.default_transcode_dir.relative_to(self.workspace_root)
            stored_transcode_dir = relative_transcode_dir.as_posix()
        except ValueError:
            stored_transcode_dir = str(self.default_transcode_dir)

        payload = {
            "default_profile_dir": stored_profile_dir,
            "default_transcode_dir": stored_transcode_dir,
        }
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
