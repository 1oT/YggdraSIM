import atexit
import ast
import copy
import ipaddress
import json
import os
import re
import shlex
from pathlib import Path
from typing import Callable, Optional

import yaml

from yggdrasim_common.progress import progress_session
from yggdrasim_common.quit_control import quit_all
from yggdrasim_common.nord_palette import NORD
from .saip_asn1_decode import _FID_TO_NAME, fid_name as _fid_name_lookup
from .lint_engine import SaipProfileLinter
from .saip_profile_scaffold import (
    build_scaffold_profile_document,
    build_scaffold_profile_document_from_menu_ids,
    default_preset_id,
    default_user_presets_path,
    describe_preset,
    diff_presets,
    get_preset,
    list_preset_placeholders,
    list_profile_presets,
    load_user_presets,
    normalize_preset_id,
    register_user_presets,
)
from .saip_profile_randomizer import (
    resolve_auto_assignments,
)
from .saip_profile_template import (
    apply_placeholder_overrides_to_loaded_document,
    batch_output_stem,
    build_placeholder_template_document,
    extract_template_placeholder_names,
    load_batch_placeholder_records,
    parse_placeholder_assignment_tokens,
    validate_batch_record_assignments,
)
from .saip_token_sidecar import (
    TokenSidecarError,
    build_sidecar_from_template,
    candidate_sidecar_paths,
    count_token_references,
    default_sidecar_path_for,
    first_available_sidecar,
    list_token_definitions,
    load_sidecar,
    merge_sidecar_into_template,
    parse_token_value_argument,
    remove_token_definition,
    rename_token_in_template,
    retokenise_template_lengths,
    set_token_definition,
    template_has_unresolved_placeholders,
    write_sidecar,
)
from .saip_profile_wizard import (
    NewProfileWizard,
    WizardAborted,
    resolve_default_scaffold_output_path,
)
from .saip_tool import SaipCommandResult, SaipToolBridge

try:
    import readline
except ImportError:
    readline = None


_PROFILE_POLICY_RULE_NAMES = {
    0: "pprUpdateControl",
    1: "ppr1-disable-not-allowed",
    2: "ppr2-delete-not-allowed",
}

_MEMORY_LIMIT_FIELD_LABELS = {
    "nonVolatileCodeLimitC6": "Non-volatile code limit",
    "volatileDataLimitC7": "Volatile data limit",
    "nonVolatileDataLimitC8": "Non-volatile data limit",
}

_AKA_ALGORITHM_ID_NAMES = {
    1: "milenage",
    2: "tuak",
    3: "usim-test-algorithm",
}

class ShellStyle:
    """SAIP profile-package shell colour roles, anchored to Nord."""

    HEADER = NORD.HEADER
    BLUE = NORD.BLUE
    CYAN = NORD.CYAN
    GREEN = NORD.GREEN
    WARNING = NORD.WARNING
    FAIL = NORD.FAIL
    BOLD = NORD.BOLD
    END = NORD.RESET


class ProfilePackageShell:
    _LINT_USAGE = (
        "Usage: LINT [STRICT] [METADATA <path>] [PROFILE <name>] "
        "[GATE <prefixes>] [FAIL-CODES <codes>] [MIN-SCORE <n>] "
        "[FAIL-ON-WARN] [ENFORCE] [> output_file]"
    )
    _LINT_PROFILE_PRESETS: dict[str, dict[str, object]] = {
        "STRICT-FS": {
            "strict": True,
            "gate_prefixes": ["YRL-FIL"],
            "min_score": 90,
            "fail_on_warn": True,
            "description": "Aggressive file-definition gate (YRL-FIL; best for profile authoring).",
        },
        "RELEASE-GATE": {
            "strict": True,
            "gate_prefixes": [
                "YRL-FIL",
                "YRL-JCA",
                "YRL-JCI",
                "YRL-DEP",
                "YRL-SVC",
                "YRL-SEQ",
            ],
            "min_score": 85,
            "fail_on_warn": False,
            "description": "Balanced release gate: filesystem, apps, PE order, mandatory services, sequence shape.",
        },
        "RELAXED-CI": {
            "strict": False,
            "gate_prefixes": ["YRL-FIL", "YRL-JCA"],
            "min_score": 70,
            "fail_on_warn": False,
            "description": "CI smoke gate with lower score threshold (file + application load rules).",
        },
    }

    def __init__(
        self,
        workspace_root: Path,
        bundle_root_path: Path | None = None,
    ) -> None:
        self.bridge = SaipToolBridge(
            workspace_root=workspace_root,
            bundle_root_path=bundle_root_path,
        )
        self._history_file = Path.home() / ".yggdrasim_saip_history"
        self._startup_profiles = self.bridge.list_default_profiles()
        self.prompt = f"\n{ShellStyle.BLUE}[SAIP Tool] > {ShellStyle.END}"
        self._commands: dict[str, Callable[[str], None]] = {
            "CHECK": self._cmd_check,
            "DUMP": self._cmd_dump,
            "ENCODE-JSON": self._cmd_encode_json,
            "EXIT": self._cmd_exit,
            "EXTRACT-APPS": self._cmd_extract_apps,
            "GENERATE-BATCH": self._cmd_generate_batch,
            "GENERATE-PROFILE": self._cmd_generate_profile,
            "GENERATE-TEMPLATE": self._cmd_generate_template,
            "DIFF": self._cmd_diff,
            "DIFF-TUI": self._cmd_diff_tui,
            "HELP": self._cmd_help,
            "INFO": self._cmd_info,
            "INSPECT": self._cmd_inspect,
            "LINT": self._cmd_lint,
            "APPLY-TEMPLATE": self._cmd_apply_template,
            "APPLY-TOKENS": self._cmd_apply_tokens,
            "EXPORT-TOKENS": self._cmd_export_tokens,
            "LIST-TOKENS": self._cmd_list_tokens,
            "ADD-TOKEN": self._cmd_add_token,
            "SET-TOKEN": self._cmd_set_token,
            "REMOVE-TOKEN": self._cmd_remove_token,
            "RENAME-TOKEN": self._cmd_rename_token,
            "RETOKENISE-LENGTHS": self._cmd_retokenise_lengths,
            "RETOKENIZE-LENGTHS": self._cmd_retokenise_lengths,
            "TOKENS": self._cmd_tokens,
            "DIFF-PRESET": self._cmd_diff_preset,
            "NEW-PROFILE": self._cmd_new_profile,
            "NEW-PROFILE-WIZARD": self._cmd_new_profile_wizard,
            "NEW-TEMPLATE": self._cmd_new_template,
            "OPEN": self._cmd_open,
            "PRESETS": self._cmd_presets,
            "PREVIEW-PRESET": self._cmd_preview_preset,
            "LIST-AKA": self._cmd_list_aka,
            "PROVISION-AKA": self._cmd_provision_aka,
            "RANDOMIZE-AKA": self._cmd_randomize_aka,
            "WIZARD": self._cmd_new_profile_wizard,
            "PWD": self._cmd_pwd,
            "PROFILE-DIR": self._cmd_profile_dir,
            "QA": self._cmd_quit_all,
            "Q": self._cmd_exit,
            "QUIT": self._cmd_exit,
            "RAW": self._cmd_raw,
            "REMOVE-NAA": self._cmd_remove_naa,
            "SPLIT": self._cmd_split,
            "STATUS": self._cmd_status,
            "TOOL": self._cmd_tool,
            "TUI": self._cmd_inspect,
            "TRANSCODE-DIR": self._cmd_transcode_dir,
            "TRANSCODE-TUI": self._cmd_inspect,
            "TREE": self._cmd_tree,
            "USE": self._cmd_use,
            "WATCH-SIMCARD": self._cmd_watch_simcard,
        }
        self._setup_readline()
        self._auto_select_single_startup_profile()
        self._input_fn: Callable[[str], str] = input
        self._loaded_user_preset_ids: list[str] = []
        self._load_user_presets_from_home()

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
        had_error = False
        for raw_command in str(cmd_line or "").split(";"):
            command_text = raw_command.strip()
            if len(command_text) == 0:
                continue
            try:
                succeeded = self._exec_line(command_text)
                if succeeded is False:
                    had_error = True
            except SystemExit as error:
                exit_code = error.code if isinstance(error.code, int) else 0
                if exit_code not in (0, None):
                    raise
                break
        if had_error:
            raise SystemExit(1)

    def _print_banner(self) -> None:
        print(f"{ShellStyle.HEADER}=== SAIP Tool ==={ShellStyle.END}")
        print(
            f"{ShellStyle.CYAN}[*] Inspection and editing shell for SAIP workflows.{ShellStyle.END}"
        )
        print(
            f"{ShellStyle.CYAN}[*] Workspace root: {self.bridge.workspace_root}{ShellStyle.END}"
        )
        print(
            f"{ShellStyle.CYAN}[*] Default profile dir: {self.bridge.default_profile_dir}{ShellStyle.END}"
        )
        print(
            f"{ShellStyle.CYAN}[*] Default transcode dir: {self.bridge.default_transcode_dir}{ShellStyle.END}"
        )
        if len(self._startup_profiles) == 0:
            print(f"{ShellStyle.WARNING}[*] Profiles in default dir: (none found){ShellStyle.END}")
        else:
            print(f"{ShellStyle.CYAN}[*] Profiles in default dir:{ShellStyle.END}")
            for profile_path in self._startup_profiles:
                print(f"    - {profile_path.name}")
        if self.bridge.current_input_file is not None:
            print(
                f"{ShellStyle.GREEN}[*] Auto-selected sole profile from default folder: "
                f"{self.bridge.current_input_file.name}{ShellStyle.END}"
            )
        self._cmd_status("")

    def _auto_select_single_startup_profile(self) -> None:
        if len(self._startup_profiles) != 1:
            return

        try:
            self.bridge.current_input_file = self._startup_profiles[0]
        except Exception:
            self.bridge.current_input_file = None

    def _load_user_presets_from_home(self) -> None:
        config_path = default_user_presets_path()
        try:
            user_presets = load_user_presets(config_path)
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            print(
                f"{ShellStyle.WARNING}[*] Skipped user presets at {config_path}: "
                f"{detail}{ShellStyle.END}"
            )
            return

        if len(user_presets) == 0:
            return

        try:
            registered_ids = register_user_presets(user_presets)
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            print(
                f"{ShellStyle.WARNING}[*] User presets at {config_path} rejected: "
                f"{detail}{ShellStyle.END}"
            )
            return

        self._loaded_user_preset_ids = list(registered_ids)
        joined_ids = ", ".join(registered_ids)
        print(
            f"{ShellStyle.CYAN}[*] Loaded {len(registered_ids)} user preset(s): "
            f"{joined_ids}{ShellStyle.END}"
        )

    def _setup_readline(self) -> None:
        if readline is None:
            return

        try:
            if self._history_file.exists():
                readline.read_history_file(str(self._history_file))
            readline.set_history_length(1000)
        except Exception:
            pass

        atexit.register(self._save_history)
        readline.set_completer(self._completer)
        readline.set_completer_delims(" \t\n")

        if readline.__doc__ is not None and "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

        try:
            readline.parse_and_bind("set show-all-if-ambiguous on")
        except Exception:
            pass

    def _save_history(self) -> None:
        if readline is None:
            return

        try:
            readline.write_history_file(str(self._history_file))
        except Exception:
            pass

    def _completer(self, text: str, state: int) -> Optional[str]:
        if readline is None:
            return None

        line_buffer = readline.get_line_buffer().lstrip()
        if " " not in line_buffer:
            options = [
                f"{command} "
                for command in sorted(self._commands.keys())
                if command.startswith(text.upper())
            ]
            if state < len(options):
                return options[state]
            return None

        parts = line_buffer.split(None, 1)
        command = parts[0].upper()
        argument_text = ""
        if len(parts) > 1:
            argument_text = parts[1]

        options = self._completion_options_for(command, argument_text)

        if state < len(options):
            return options[state]
        return None

    _SLOT_PATH = "path"
    _SLOT_TOKEN_NAME = "token_name"
    _SLOT_PRESET = "preset"
    _SLOT_FLAG_SET: dict[str, tuple[str, ...]] = {
        "REMOVE-TOKEN": ("--dry-run", "--no-backup"),
        "RENAME-TOKEN": ("--dry-run", "--no-backup"),
        "RETOKENISE-LENGTHS": ("--dry-run", "--no-backup"),
        "RETOKENIZE-LENGTHS": ("--dry-run", "--no-backup"),
        "APPLY-TOKENS": ("OVERWRITE",),
    }

    _TOKEN_CMD_POSITIONAL_SHAPE: dict[str, tuple[str, ...]] = {
        "LIST-TOKENS": (_SLOT_PATH,),
        "ADD-TOKEN": (_SLOT_PATH, _SLOT_TOKEN_NAME),
        "SET-TOKEN": (_SLOT_PATH, _SLOT_TOKEN_NAME),
        "REMOVE-TOKEN": (_SLOT_PATH, _SLOT_TOKEN_NAME),
        "RENAME-TOKEN": (_SLOT_PATH, _SLOT_TOKEN_NAME, _SLOT_TOKEN_NAME, _SLOT_PATH),
        "RETOKENISE-LENGTHS": (_SLOT_PATH, _SLOT_PATH),
        "RETOKENIZE-LENGTHS": (_SLOT_PATH, _SLOT_PATH),
        "EXPORT-TOKENS": (_SLOT_PATH, _SLOT_PATH),
        "APPLY-TOKENS": (_SLOT_PATH, _SLOT_PATH, _SLOT_PATH),
        "ENCODE-JSON": (_SLOT_PATH, _SLOT_PATH),
        "GENERATE-TEMPLATE": (_SLOT_PATH,),
        "GENERATE-PROFILE": (_SLOT_PATH, _SLOT_PATH),
        "GENERATE-BATCH": (_SLOT_PATH, _SLOT_PATH, _SLOT_PATH),
        "DIFF": (_SLOT_PATH, _SLOT_PATH),
        "DIFF-TUI": (_SLOT_PATH, _SLOT_PATH),
        "TRANSCODE-DIR": (_SLOT_PATH,),
    }

    def _completion_options_for(
        self,
        command: str,
        argument_text: str,
    ) -> list[str]:
        if command == "TOKENS":
            return self._complete_tokens_namespace(argument_text)
        if command in ("USE", "OPEN"):
            return self._complete_path_token(argument_text)
        if command == "PROFILE-DIR":
            return self._complete_path_token(argument_text, directories_only=True)
        if command == "HELP":
            trailing = argument_text.split(" ")[-1].upper() if argument_text else ""
            topics = ("TOKENS", "TEMPLATE", "EDIT", "LINT", "TOPICS")
            return [
                f"{topic} " for topic in topics if topic.startswith(trailing)
            ]
        if command in (
            "NEW-PROFILE",
            "NEW-TEMPLATE",
            "NEW-PROFILE-WIZARD",
            "WIZARD",
            "APPLY-TEMPLATE",
            "PREVIEW-PRESET",
            "DIFF-PRESET",
            "PRESETS",
        ):
            return self._complete_scaffold_token(command, argument_text)
        if command in self._TOKEN_CMD_POSITIONAL_SHAPE:
            return self._complete_by_shape(command, argument_text)
        return []

    def _complete_tokens_namespace(self, argument_text: str) -> list[str]:
        tokens = argument_text.split(" ")
        if len(tokens) <= 1:
            trailing = tokens[-1].upper() if tokens else ""
            return [
                f"{sub} "
                for sub in sorted(set(self._TOKEN_SUBCOMMANDS.keys()))
                if sub.startswith(trailing)
            ]
        sub = tokens[0].upper()
        handler_name = self._TOKEN_SUBCOMMANDS.get(sub)
        if handler_name is None:
            return []
        flat_aliases = {
            "_cmd_list_tokens": "LIST-TOKENS",
            "_cmd_add_token": "ADD-TOKEN",
            "_cmd_set_token": "SET-TOKEN",
            "_cmd_remove_token": "REMOVE-TOKEN",
            "_cmd_rename_token": "RENAME-TOKEN",
            "_cmd_retokenise_lengths": "RETOKENISE-LENGTHS",
            "_cmd_export_tokens": "EXPORT-TOKENS",
            "_cmd_apply_tokens": "APPLY-TOKENS",
        }
        flat = flat_aliases.get(handler_name)
        if flat is None:
            return []
        residual = " ".join(tokens[1:])
        return self._complete_by_shape(flat, residual)

    def _complete_by_shape(
        self,
        command: str,
        argument_text: str,
    ) -> list[str]:
        shape = self._TOKEN_CMD_POSITIONAL_SHAPE.get(command, ())
        if len(shape) == 0:
            return []

        flags = self._SLOT_FLAG_SET.get(command, ())
        raw_tokens = argument_text.split(" ") if argument_text else [""]
        trailing_unfinished = not argument_text.endswith(" ")
        seen_tokens = [tok for tok in raw_tokens if len(tok) > 0]
        if trailing_unfinished is True and len(raw_tokens) > 0:
            trailing_token = raw_tokens[-1]
            positional = [
                tok for tok in seen_tokens[:-1]
                if tok not in flags
            ]
        else:
            trailing_token = ""
            positional = [
                tok for tok in seen_tokens
                if tok not in flags
            ]

        slot_index = len(positional)
        slot_kind = shape[slot_index] if slot_index < len(shape) else None

        if trailing_token.startswith("--"):
            return [
                f"{flag} "
                for flag in flags
                if flag.startswith(trailing_token)
            ]

        options: list[str] = []
        if slot_kind == self._SLOT_PATH:
            options.extend(self._complete_path_token(trailing_token))
        elif slot_kind == self._SLOT_TOKEN_NAME:
            if len(positional) >= 1:
                options.extend(
                    self._complete_token_names(
                        positional[0],
                        trailing_token,
                    )
                )

        for flag in flags:
            if flag.startswith(trailing_token):
                options.append(f"{flag} ")
        return options

    def _complete_token_names(
        self,
        file_token: str,
        prefix: str,
    ) -> list[str]:
        if len(file_token) == 0:
            return []
        loaded: dict | None = None
        candidates: list[Path] = []
        try:
            candidates.append(
                self.bridge.resolve_workspace_path(file_token, must_exist=False)
            )
        except Exception:
            pass
        try:
            candidates.append(self.bridge.default_profile_dir / file_token)
        except Exception:
            pass
        for candidate in candidates:
            if candidate.exists() is False or candidate.is_file() is False:
                continue
            try:
                raw = candidate.read_text(encoding="utf-8")
                loaded = json.loads(raw)
                break
            except Exception:
                continue
        if isinstance(loaded, dict) is False:
            return []
        defs = loaded.get("__ygg_token_defs__", {})
        if isinstance(defs, dict) is False:
            return []
        return [f"{name} " for name in sorted(defs.keys()) if name.startswith(prefix)]

    def _complete_scaffold_token(
        self,
        command: str,
        argument_text: str,
    ) -> list[str]:
        trailing_token = ""
        if argument_text.endswith(" ") is False:
            parts = argument_text.rsplit(" ", 1)
            if len(parts) == 2:
                trailing_token = parts[1]
            else:
                trailing_token = argument_text
        upper_token = trailing_token.upper()

        if trailing_token.startswith("PRESET=") or upper_token.startswith("PRESET="):
            prefix_upper = trailing_token.split("=", 1)[1].upper()
            return [
                f"PRESET={preset.preset_id} "
                for preset in list_profile_presets()
                if preset.preset_id.startswith(prefix_upper)
            ]

        if command in ("PRESETS", "PREVIEW-PRESET", "DIFF-PRESET", "APPLY-TEMPLATE"):
            if command == "APPLY-TEMPLATE":
                return self._complete_path_token(argument_text)
            if len(argument_text) > 0 and " " in argument_text.strip():
                prefix_upper = trailing_token.upper()
            else:
                prefix_upper = upper_token
            return [
                f"{preset.preset_id} "
                for preset in list_profile_presets()
                if preset.preset_id.startswith(prefix_upper)
            ]

        if command in ("NEW-PROFILE", "NEW-TEMPLATE"):
            placeholder_keys = ("ICCID", "IMSI", "PRESET", "VERIFY")
            if len(trailing_token) > 0 and "=" not in trailing_token:
                matches = [
                    f"{keyword}="
                    for keyword in placeholder_keys
                    if keyword.startswith(upper_token)
                ]
                if len(matches) > 0:
                    return matches
            if trailing_token.upper().startswith("VERIFY="):
                return ["VERIFY=ON ", "VERIFY=OFF "]
            if trailing_token.upper().startswith("ICCID=") or trailing_token.upper().startswith("IMSI="):
                return [
                    f"{trailing_token.split('=', 1)[0].upper()}=AUTO ",
                ]
            return self._complete_path_token(argument_text)

        if command in ("NEW-PROFILE-WIZARD", "WIZARD"):
            prefix_upper = trailing_token.upper()
            return [
                f"PRESET={preset.preset_id} "
                for preset in list_profile_presets()
                if preset.preset_id.startswith(prefix_upper)
            ]

        return []

    def _complete_path_token(self, token_text: str, directories_only: bool = False) -> list[str]:
        raw_text = token_text or ""
        expanded_text = os.path.expanduser(raw_text)
        is_absolute = expanded_text.startswith(os.sep)
        has_path_separator = "/" in expanded_text or os.sep in expanded_text

        if len(expanded_text) == 0:
            search_dir = self.bridge.default_profile_dir
            prefix = ""
            render_base = ""
        elif is_absolute:
            candidate = Path(expanded_text)
            if raw_text.endswith(os.sep):
                search_dir = candidate
                prefix = ""
            else:
                search_dir = candidate.parent
                prefix = candidate.name
            render_base = str(search_dir)
        elif has_path_separator:
            candidate = Path(expanded_text)
            if raw_text.endswith("/"):
                search_dir = (self.bridge.workspace_root / candidate).resolve()
                prefix = ""
                render_base = raw_text.rstrip("/")
            else:
                search_dir = (self.bridge.workspace_root / candidate.parent).resolve()
                prefix = candidate.name
                render_base = candidate.parent.as_posix()
                if render_base == ".":
                    render_base = ""
        else:
            search_dir = self.bridge.default_profile_dir
            prefix = expanded_text
            render_base = ""

        if search_dir.exists() is False or search_dir.is_dir() is False:
            return []

        matches: list[str] = []
        for entry in sorted(search_dir.iterdir(), key=lambda item: item.name.lower()):
            if entry.name.startswith(prefix) is False:
                continue
            if directories_only and entry.is_dir() is False:
                continue
            if directories_only is False and entry.is_file():
                if self.bridge.is_transcode_sidecar(entry):
                    continue
            completed = entry.name
            if len(render_base) > 0:
                completed = f"{render_base}/{entry.name}"
            if entry.is_dir():
                completed += "/"
            matches.append(completed)
        return matches

    def _print_result(self, result: SaipCommandResult) -> None:
        if len(result.stdout.strip()) > 0:
            rendered_stdout = self._render_result_stdout(result)
            print(rendered_stdout.rstrip())

        if len(result.stderr.strip()) > 0:
            print(f"{ShellStyle.WARNING}{result.stderr.rstrip()}{ShellStyle.END}")

        if result.returncode == 0:
            print(f"{ShellStyle.GREEN}[+] Command completed successfully.{ShellStyle.END}")
            return

        print(
            f"{ShellStyle.FAIL}[-] saip-tool exited with code {result.returncode}.{ShellStyle.END}"
        )

    def _render_result_stdout(self, result: SaipCommandResult) -> str:
        if self._is_decoded_dump(result) is False:
            return result.stdout

        formatted = self._format_decoded_dump_output(result.stdout)
        if formatted is None:
            return result.stdout
        return formatted

    @staticmethod
    def _is_decoded_dump(result: SaipCommandResult) -> bool:
        command = [str(part) for part in result.command]
        has_dump = False
        has_decoded = False
        for part in command:
            if part == "dump":
                has_dump = True
            if part == "--dump-decoded":
                has_decoded = True
        return has_dump and has_decoded

    def _format_decoded_dump_output(self, stdout: str) -> str | None:
        parsed_output = self._parse_decoded_dump_sections(stdout)
        if parsed_output is None:
            return None

        intro_lines, sections = parsed_output

        rendered: list[str] = []
        for line in intro_lines:
            if len(line.strip()) > 0:
                rendered.append(f"{ShellStyle.CYAN}[*] {line.strip()}{ShellStyle.END}")

        for title, body_text in sections:
            rendered.append("")
            rendered.append(
                f"{ShellStyle.HEADER}=== {title.upper()} ==={ShellStyle.END}"
            )
            if len(body_text) == 0:
                rendered.append(f"{ShellStyle.WARNING}| (empty){ShellStyle.END}")
                continue

            try:
                parsed = ast.literal_eval(body_text)
            except Exception:
                rendered.append(body_text)
                continue

            rendered.extend(self._render_named_value(None, parsed, 0))

        return "\n".join(rendered)

    def _parse_decoded_dump_sections(self, stdout: str) -> tuple[list[str], list[tuple[str, str]]] | None:
        lines = stdout.splitlines()
        if len(lines) == 0:
            return None

        section_marker = "=" * 10
        intro_lines: list[str] = []
        sections: list[tuple[str, str]] = []
        current_title = ""
        current_body: list[str] = []

        for line in lines:
            stripped = line.strip()
            if stripped.startswith(section_marker):
                if len(current_title) > 0:
                    sections.append((current_title, "\n".join(current_body).strip()))
                    current_body = []
                current_title = stripped.strip("=").strip()
                continue

            if len(current_title) == 0:
                intro_lines.append(line)
                continue

            current_body.append(line)

        if len(current_title) > 0:
            sections.append((current_title, "\n".join(current_body).strip()))

        if len(sections) == 0:
            return None

        return intro_lines, sections

    def _build_structured_decoded_dump(self, stdout: str) -> dict | None:
        parsed_output = self._parse_decoded_dump_sections(stdout)
        if parsed_output is None:
            return None

        intro_lines, sections = parsed_output
        document: dict[str, object] = {
            "intro": [line.strip() for line in intro_lines if len(line.strip()) > 0],
            "sections": {},
        }
        section_map: dict[str, object] = {}
        section_counts: dict[str, int] = {}

        for title, body_text in sections:
            section_key = self._make_unique_section_key(title, section_counts)
            if len(body_text) == 0:
                section_map[section_key] = None
                continue

            try:
                parsed = ast.literal_eval(body_text)
            except Exception:
                section_map[section_key] = body_text
                continue

            section_map[section_key] = self._normalize_dump_value(parsed)

        document["sections"] = section_map
        return document

    def _make_unique_section_key(self, title: str, section_counts: dict[str, int]) -> str:
        base_key = str(title).strip() or "section"
        seen_count = section_counts.get(base_key, 0) + 1
        section_counts[base_key] = seen_count
        if seen_count == 1:
            return base_key
        return f"{base_key}_{seen_count}"

    def _normalize_dump_value(self, value, parent_key: str | None = None):
        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, bytearray):
            return bytes(value).hex()

        if isinstance(value, dict):
            normalized: dict[str, object] = {}
            for key, item in value.items():
                key_text = str(key)
                next_parent_key = key_text
                if parent_key == "eUICC-Mandatory-services":
                    next_parent_key = parent_key
                decoded_special = None
                if not str(parent_key or "").endswith(":decoded"):
                    decoded_special = self._decode_special_field(key_text, item)
                if decoded_special is not None:
                    normalized[key_text] = {
                        "raw": self._normalize_dump_value(item, parent_key=next_parent_key),
                        "decoded": self._normalize_dump_value(
                            decoded_special,
                            parent_key=f"{key_text}:decoded",
                        ),
                    }
                    continue
                normalized[key_text] = self._normalize_dump_value(item, parent_key=next_parent_key)
            return normalized

        if isinstance(value, list):
            return [self._normalize_dump_value(item, parent_key=parent_key) for item in value]

        if isinstance(value, tuple):
            if len(value) == 2 and isinstance(value[0], str):
                return {
                    "kind": value[0],
                    "value": self._normalize_dump_value(value[1], parent_key=str(value[0])),
                }
            return [self._normalize_dump_value(item, parent_key=parent_key) for item in value]

        if self._is_scalar(value):
            if value is None and parent_key == "eUICC-Mandatory-services":
                return True
            return value

        return str(value)

    def _render_named_value(self, name, value, indent: int, key_width: int | None = None) -> list[str]:
        decoded_special = self._decode_special_field(name, value)
        if decoded_special is not None:
            return self._render_special_field(
                name,
                value,
                decoded_special,
                indent,
                key_width=key_width,
            )

        if isinstance(value, dict):
            return self._render_mapping(name, value, indent, key_width=key_width)

        if isinstance(value, tuple):
            return self._render_tuple(name, value, indent, key_width=key_width)

        if isinstance(value, list):
            return self._render_list(name, value, indent, key_width=key_width)

        return [self._format_scalar_line(name, value, indent, key_width=key_width)]

    def _render_special_field(
        self,
        name,
        value,
        decoded_value,
        indent: int,
        key_width: int | None = None,
    ) -> list[str]:
        if name is None:
            return self._render_named_value(None, decoded_value, indent, key_width=key_width)

        if self._is_scalar(value):
            lines = [self._format_scalar_line(name, value, indent, key_width=key_width)]
            lines.append(self._format_block_header("decoded", indent + 1))
            lines.extend(self._render_named_value(None, decoded_value, indent + 2))
            return lines

        lines = [self._format_block_header(str(name), indent, key_width=key_width)]
        child_key_width = self._compute_key_width({"raw": "", "decoded": ""})
        lines.extend(
            self._render_named_value(
                "raw",
                value,
                indent + 1,
                key_width=child_key_width,
            )
        )
        lines.extend(
            self._render_named_value(
                "decoded",
                decoded_value,
                indent + 1,
                key_width=child_key_width,
            )
        )
        return lines

    def _decode_special_field(self, name, value):
        field_name = str(name or "")
        if field_name == "iccid":
            return self._decode_profile_iccid(value)
        if field_name == "algorithmID":
            return self._decode_aka_algorithm_id(value)
        if field_name == "numberOfKeccak":
            return self._decode_aka_counter_field(value, "TUAK Keccak iterations")
        if field_name == "pol":
            return self._decode_profile_policy_rules(value)
        if field_name == "connectivityParameters":
            return self._decode_connectivity_parameters(value)
        if field_name == "sdPersoData":
            return self._decode_sd_perso_data(value)
        if field_name == "uiccToolkitApplicationSpecificParametersField":
            return self._decode_uicc_toolkit_parameters(value)
        if field_name == "applicationSpecificParametersC9":
            return self._decode_sd_install_parameters(value)
        if field_name == "pinStatusTemplateDO":
            return self._decode_pin_status_template_do(value)
        if field_name == "fileID":
            return self._decode_file_identifier(value)
        if field_name == "securityAttributesReferenced":
            return self._decode_security_attributes_referenced(value)
        if field_name == "filePath":
            return self._decode_file_path(value)
        if field_name == "linkPath":
            return self._decode_link_path(value)
        if field_name == "specialFileInformation":
            return self._decode_special_file_information(value)
        if field_name == "fillPattern":
            return self._decode_fill_pattern(value, "Fill pattern")
        if field_name == "repeatPattern":
            return self._decode_fill_pattern(value, "Repeat pattern")
        if field_name == "fileDetails":
            return self._decode_file_details(value)
        if field_name == "algorithmOptions":
            return self._decode_aka_option_octet(value, "AKA algorithm options")
        if field_name == "key":
            return self._decode_aka_secret_material(value, "AKA secret key material")
        if field_name == "opc":
            return self._decode_aka_secret_material(value, "AKA operator variant key")
        if field_name == "authCounterMax":
            return self._decode_aka_counter_field(value, "AKA authentication counter max")
        if field_name == "rotationConstants":
            return self._decode_rotation_constants(value)
        if field_name == "xoringConstants":
            return self._decode_xoring_constants(value)
        if field_name == "fileDescriptor":
            return self._decode_file_descriptor(value)
        if field_name == "efFileSize":
            return self._decode_ef_file_size(value)
        if field_name == "shortEFID":
            return self._decode_short_efid(value)
        if field_name == "lcsi":
            return self._decode_lcsi(value)
        if field_name == "minimumSecurityLevel":
            return self._decode_minimum_security_level(value)
        if field_name == "sqnOptions":
            return self._decode_aka_option_octet(value, "SQN options")
        if field_name == "sqnDelta":
            return self._decode_aka_counter_field(value, "SQN delta")
        if field_name == "sqnAgeLimit":
            return self._decode_aka_counter_field(value, "SQN age limit")
        if field_name == "sqnInit":
            return self._decode_sqn_init_list(value)
        if field_name == "tarList":
            return self._decode_tar_list(value)
        if field_name in {
            "uiccAccessDomain",
            "uiccAdminAccessDomain",
            "adfAccessDomain",
            "adfAdminAccessDomain",
        }:
            return self._decode_access_domain(value)
        memory_limit = self._decode_memory_limit_field(field_name, value)
        if memory_limit is not None:
            return memory_limit
        if field_name == "keyData":
            return self._decode_key_data(value)
        if field_name in {"pinValue", "pukValue"}:
            return self._decode_pin_secret_value(value)
        if field_name in {
            "adfAID",
            "applicationLoadPackageAID",
            "classAID",
            "dfName",
            "instanceAID",
            "loadPackageAID",
            "securityDomainAID",
        }:
            return self._decode_application_identifier(value)
        if field_name == "applicationPrivileges":
            return self._decode_application_privileges(value)
        if field_name == "lifeCycleState":
            return self._decode_life_cycle_state(value)
        if field_name == "pinAttributes":
            return self._decode_pin_attributes(value)
        if field_name in {"maxNumOfAttemps-retryNumLeft", "maxNumOfAttempts-retryNumLeft"}:
            return self._decode_pin_puk_retry_counter(value)
        if field_name == "macLength":
            return self._decode_mac_length(value)
        if field_name == "fillFileOffset":
            return self._decode_fill_file_offset(value)
        if field_name == "unblockingPINReference":
            return self._decode_puk_key_reference(value)
        if field_name == "keyReference":
            return self._decode_pin_puk_adm_key_reference(value)
        if field_name == "keyUsageQualifier":
            return self._decode_key_usage_qualifier(value)
        if field_name == "keyAccess":
            return self._decode_key_access(value)
        if field_name == "keyIdentifier":
            return self._decode_key_identifier(value)
        if field_name == "keyVersionNumber":
            return self._decode_key_version_number(value)
        if field_name == "keyCounterValue":
            return self._decode_key_counter_value(value)
        if field_name == "keyType":
            return self._decode_key_type(value)
        return None

    def _decode_connectivity_parameters(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None:
            return None

        tag_names = {
            "A0": "Transport / Remote Parameters",
            "A1": "Bearer / Access Parameters",
            "06": "Object Identifier",
            "35": "Bearer Description",
            "47": "Network Access Name",
            "81": "Parameter 81",
            "82": "Parameter 82",
        }
        parsed_items = self._decode_ber_tlv_stream(value_bytes, tag_names=tag_names)
        if len(parsed_items) == 0:
            return None
        return {"format": "BER-TLV", "items": parsed_items}

    def _decode_sd_install_parameters(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None:
            return None

        tag_names = {
            "81": "UICC SCP",
            "82": "Accept extradite applications and load files to SD",
            "83": "Accept delete of associated SD",
            "84": "Life cycle transition to personalized",
            "86": "CASD capability information",
            "87": "Accept extradite associated applications and load files",
        }
        items = self._decode_ber_tlv_stream(value_bytes, tag_names=tag_names)
        if len(items) == 0:
            return None

        for item in items:
            if item.get("tag") != "81":
                continue
            raw_hex = str(item.get("raw", ""))
            if len(raw_hex) != 4:
                continue
            scp_value = int(raw_hex[:2], 16)
            i_value = int(raw_hex[2:], 16)
            item["decoded"] = {
                "scp": f"0x{scp_value:02X}",
                "scpName": self._scp_name(scp_value),
                "i": f"0x{i_value:02X}",
            }
        for item in items:
            if item.get("tag") not in ("82", "83", "84", "86", "87"):
                continue
            raw_hex = str(item.get("raw", ""))
            if len(raw_hex) == 0:
                continue
            decoded_flags = self._decode_flag_octets(bytes.fromhex(raw_hex))
            if decoded_flags is not None:
                item["decoded"] = decoded_flags

        return {"format": "BER-TLV", "items": items}

    def _decode_uicc_toolkit_parameters(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None:
            return None

        decoded: dict[str, object] = {
            "length": len(value_bytes),
            "rawHex": value_bytes.hex(),
        }
        parsed = self._parse_uicc_toolkit_parameters(value_bytes)
        if parsed is not None:
            decoded.update(parsed)
            return decoded

        decoded["bytes"] = [f"0x{byte_value:02X}" for byte_value in value_bytes]
        msl_value, tar_value = self._extract_toolkit_msl_and_tar(value_bytes)
        if msl_value is not None:
            decoded["minimumSecurityLevelInferred"] = f"0x{msl_value:02X}"
            decoded["minimumSecurityLevelDecimal"] = msl_value
        if tar_value is not None:
            decoded["tarInferred"] = tar_value.hex()
        return decoded

    def _decode_sd_perso_data(self, value):
        hex_values = self._value_to_hex_strings(value)
        if len(hex_values) == 0:
            return None

        decoded_entries: list[object] = []
        entry_index = 1
        top_level_tag_names = {
            "84": "Transport Parameters",
            "85": "Security / Address Container",
            "86": "Security Parameters",
            "89": "Remote Endpoint",
            "8A": "Host / Address",
            "8B": "Remote Identifier",
            "8C": "Remote Path",
        }
        nested_tag_names = {
            "85": {
                "84": "Transport Parameters",
                "85": "Remote Identifier Block",
                "86": "Security Parameters",
                "89": "Remote Endpoint",
            },
            "84": {
                "01": "Parameter 01",
                "02": "Parameter 02",
                "35": "Bearer Description",
                "39": "Buffer Size",
                "3C": "Transport Level",
                "3E": "Other Address",
            },
            "86": {
                "00": "Parameter 00",
                "20": "Parameter 20",
            },
            "89": {
                "8A": "Host / Address",
                "8B": "Remote Identifier",
                "8C": "Remote Path",
            },
        }
        nested_decoder_maps = {
            "85": {
                "85": self._decode_length_prefixed_identifier_block,
            },
            "84": {
                "01": self._decode_compact_binary_value,
                "02": self._decode_compact_binary_value,
            },
            "86": {
                "00": self._decode_compact_binary_value,
                "20": self._decode_compact_binary_value,
            },
        }
        for hex_value in hex_values:
            entry_bytes = self._value_to_bytes(hex_value)
            if entry_bytes is None:
                continue
            dgi_items = self._decode_dgi_stream(
                entry_bytes,
                tag_names=top_level_tag_names,
                nested_tag_names=nested_tag_names,
                nested_decoder_maps=nested_decoder_maps,
            )
            if len(dgi_items) == 0:
                continue
            decoded_entries.append(
                {
                    "record": entry_index,
                    "format": "DGI",
                    "items": dgi_items,
                }
            )
            entry_index += 1

        if len(decoded_entries) == 0:
            return None
        return decoded_entries

    def _decode_dgi_stream(
        self,
        data: bytes,
        tag_names: dict[str, str] | None = None,
        nested_tag_names: dict[str, dict[str, str]] | None = None,
        nested_decoder_maps: dict[str, dict[str, Callable[[bytes], object | None]]] | None = None,
    ) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        offset = 0
        while offset + 3 <= len(data):
            tag_bytes = data[offset : offset + 2]
            offset += 2
            if offset >= len(data):
                break

            length_octet = data[offset]
            offset += 1
            if length_octet == 0xFF:
                if offset + 2 > len(data):
                    break
                length_value = int.from_bytes(data[offset : offset + 2], "big", signed=False)
                offset += 2
            else:
                length_value = length_octet

            value_end = offset + length_value
            if value_end > len(data):
                break

            value_bytes = data[offset:value_end]
            offset = value_end
            items.append(
                {
                    "dgi": tag_bytes.hex(),
                    "length": length_value,
                    "raw": value_bytes.hex(),
                    "decoded": self._decode_simple_tlv_payload(
                        value_bytes,
                        tag_names=tag_names,
                        nested_tag_names=nested_tag_names,
                        nested_decoder_maps=nested_decoder_maps,
                    ),
                }
            )

        return items

    def _decode_simple_tlv_payload(
        self,
        data: bytes,
        tag_names: dict[str, str] | None = None,
        nested_tag_names: dict[str, dict[str, str]] | None = None,
        custom_decoder_map: dict[str, Callable[[bytes], object | None]] | None = None,
        nested_decoder_maps: dict[str, dict[str, Callable[[bytes], object | None]]] | None = None,
    ):
        items = self._parse_simple_tlv_stream(data)
        if items is None or len(items) == 0:
            ascii_value = self._decode_printable_ascii(data)
            if ascii_value is not None:
                return {"ascii": ascii_value}
            return data.hex()

        decoded_items: list[dict[str, object]] = []
        for tag_value, value_bytes in items:
            tag_hex = f"{tag_value:02X}"
            item: dict[str, object] = {
                "tag": tag_hex,
                "length": len(value_bytes),
                "raw": value_bytes.hex(),
            }
            if tag_names is not None and tag_hex in tag_names:
                item["name"] = tag_names[tag_hex]

            if tag_value in (0x35, 0x39, 0x3C, 0x3E, 0x47):
                description = self._decode_stk_value(tag_value, value_bytes)
                if description is not None:
                    item["decoded"] = description
            else:
                if custom_decoder_map is not None:
                    custom_decoder = custom_decoder_map.get(tag_hex)
                    if custom_decoder is not None:
                        custom_decoded = custom_decoder(value_bytes)
                        if custom_decoded is not None:
                            item["decoded"] = custom_decoded
                            decoded_items.append(item)
                            continue
                child_tag_names = None
                if nested_tag_names is not None:
                    child_tag_names = nested_tag_names.get(tag_hex)
                child_decoder_map = None
                if nested_decoder_maps is not None:
                    child_decoder_map = nested_decoder_maps.get(tag_hex)
                nested = self._decode_simple_tlv_payload(
                    value_bytes,
                    tag_names=child_tag_names,
                    nested_tag_names=nested_tag_names,
                    custom_decoder_map=child_decoder_map,
                    nested_decoder_maps=nested_decoder_maps,
                )
                if nested != value_bytes.hex():
                    item["decoded"] = nested
                else:
                    ascii_value = self._decode_printable_ascii(value_bytes)
                    if ascii_value is not None:
                        item["ascii"] = ascii_value

            decoded_items.append(item)

        return decoded_items

    def _parse_simple_tlv_stream(self, data: bytes) -> list[tuple[int, bytes]] | None:
        items: list[tuple[int, bytes]] = []
        offset = 0
        while offset < len(data):
            if offset + 2 > len(data):
                return None
            tag_value = data[offset]
            length_value = data[offset + 1]
            offset += 2
            value_end = offset + length_value
            if value_end > len(data):
                return None
            items.append((tag_value, data[offset:value_end]))
            offset = value_end
        return items

    def _decode_ber_tlv_stream(
        self,
        data: bytes,
        tag_names: dict[str, str] | None = None,
    ) -> list[dict[str, object]]:
        items: list[dict[str, object]] = []
        offset = 0
        while offset < len(data):
            item, next_offset = self._parse_ber_tlv_item(data, offset)
            if item is None or next_offset <= offset:
                break
            item["name"] = self._ber_tag_name(item["tag"], tag_names=tag_names)
            value_bytes = bytes(item.pop("_value_bytes"))
            if item["tag"] in ("35", "39", "3C", "3E", "47"):
                item["constructed"] = False
            if item["constructed"]:
                item["items"] = self._decode_ber_tlv_stream(value_bytes, tag_names=tag_names)
            else:
                item["raw"] = value_bytes.hex()
                decoded_value = self._decode_ber_tlv_value(item["tag"], value_bytes)
                if decoded_value is not None:
                    item["decoded"] = decoded_value
                else:
                    ascii_value = self._decode_printable_ascii(value_bytes)
                    if ascii_value is not None:
                        item["ascii"] = ascii_value
            items.append(item)
            offset = next_offset
        return items

    def _parse_ber_tlv_item(self, data: bytes, offset: int) -> tuple[dict[str, object] | None, int]:
        if offset >= len(data):
            return None, offset

        tag_start = offset
        first_tag_octet = data[offset]
        offset += 1
        while first_tag_octet & 0x1F == 0x1F and offset < len(data):
            next_octet = data[offset]
            offset += 1
            if next_octet & 0x80 == 0:
                break

        tag_end = offset
        if offset >= len(data):
            return None, tag_start

        length_octet = data[offset]
        offset += 1
        if length_octet & 0x80:
            length_octet_count = length_octet & 0x7F
            if length_octet_count == 0 or offset + length_octet_count > len(data):
                return None, tag_start
            length_value = int.from_bytes(
                data[offset : offset + length_octet_count],
                "big",
                signed=False,
            )
            offset += length_octet_count
        else:
            length_value = length_octet

        value_end = offset + length_value
        if value_end > len(data):
            return None, tag_start

        tag_bytes = data[tag_start:tag_end]
        if len(tag_bytes) == 0:
            return None, tag_start
        return (
            {
                "tag": tag_bytes.hex().upper(),
                "constructed": bool(tag_bytes[0] & 0x20),
                "length": length_value,
                "_value_bytes": data[offset:value_end],
            },
            value_end,
        )

    def _decode_ber_tlv_value(self, tag: str, value_bytes: bytes):
        upper_tag = tag.upper()
        if upper_tag == "35":
            return self._describe_bearer_description(value_bytes)
        if upper_tag == "39" and len(value_bytes) == 2:
            return int.from_bytes(value_bytes, "big", signed=False)
        if upper_tag == "47":
            return self._decode_network_access_name(value_bytes)
        if upper_tag == "3C":
            return self._describe_transport_level(value_bytes)
        if upper_tag == "3E":
            return self._decode_other_address(value_bytes)
        if upper_tag == "06":
            dotted_oid = self._decode_oid(value_bytes)
            if dotted_oid is not None:
                return dotted_oid
        if upper_tag in ("81", "82") and len(value_bytes) <= 4:
            return {
                "hex": value_bytes.hex(),
                "decimal": int.from_bytes(value_bytes, "big", signed=False),
            }
        return None

    def _decode_stk_value(self, tag_value: int, value_bytes: bytes):
        if tag_value == 0x35:
            return self._describe_bearer_description(value_bytes)
        if tag_value == 0x39 and len(value_bytes) == 2:
            return int.from_bytes(value_bytes, "big", signed=False)
        if tag_value == 0x3C:
            return self._describe_transport_level(value_bytes)
        if tag_value == 0x3E:
            return self._decode_other_address(value_bytes)
        if tag_value == 0x47:
            return self._decode_network_access_name(value_bytes)
        return None

    def _decode_flag_octets(self, value_bytes: bytes) -> dict[str, object] | None:
        if len(value_bytes) == 0:
            return None
        set_bits: list[int] = []
        bit_index = 0
        for byte_value in reversed(value_bytes):
            for mask in range(8):
                if ((byte_value >> mask) & 0x01) == 0x01:
                    set_bits.append(bit_index)
                bit_index += 1
        set_bits.sort(reverse=True)
        return {
            "hex": value_bytes.hex(),
            "setBits": set_bits,
        }

    def _decode_compact_binary_value(self, value_bytes: bytes) -> dict[str, object] | None:
        if len(value_bytes) == 0:
            return {
                "hex": "",
                "empty": True,
            }
        if len(value_bytes) > 4:
            return None
        return {
            "hex": value_bytes.hex(),
            "decimal": int.from_bytes(value_bytes, "big", signed=False),
            "bytes": [f"0x{byte_value:02X}" for byte_value in value_bytes],
        }

    def _decode_length_prefixed_identifier_block(self, value_bytes: bytes) -> dict[str, object] | None:
        if len(value_bytes) < 1:
            return None
        identifier_length = value_bytes[0]
        if identifier_length == 0 or 1 + identifier_length > len(value_bytes):
            return None
        identifier_bytes = value_bytes[1 : 1 + identifier_length]
        identifier_ascii = self._decode_printable_ascii(identifier_bytes)
        if identifier_ascii is None:
            return None
        decoded: dict[str, object] = {
            "format": "Length-prefixed identifier block",
            "identifierLength": identifier_length,
            "identifierAscii": identifier_ascii,
        }
        trailer_bytes = value_bytes[1 + identifier_length :]
        if len(trailer_bytes) > 0:
            decoded["trailerHex"] = trailer_bytes.hex()
            decoded["trailerBytes"] = [f"0x{byte_value:02X}" for byte_value in trailer_bytes]
        return decoded

    def _decode_application_privileges(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None

        privilege_value = int.from_bytes(value_bytes, "big", signed=False)
        privilege_flags = [
            (0x800000, "security_domain", "Security Domain"),
            (0x400000, "dap_verification", "DAP Verification"),
            (0x200000, "delegated_management", "Delegated Management"),
            (0x100000, "card_lock", "Card Lock"),
            (0x080000, "card_terminate", "Card Terminate"),
            (0x040000, "card_reset", "Card Reset"),
            (0x020000, "cvm_management", "CVM Management"),
            (0x010000, "mandated_dap_verification", "Mandated DAP Verification"),
            (0x008000, "trusted_path", "Trusted Path"),
            (0x004000, "authorized_management", "Authorized Management"),
            (0x002000, "token_management", "Token Management"),
            (0x001000, "global_delete", "Global Delete"),
            (0x000800, "global_lock", "Global Lock"),
            (0x000400, "global_registry", "Global Registry"),
            (0x000200, "final_application", "Final Application"),
            (0x000100, "global_service", "Global Service"),
            (0x000080, "receipt_generation", "Receipt Generation"),
            (0x000040, "ciphered_load_file_data_block", "Ciphered Load File Data Block"),
            (0x000020, "contactless_activation", "Contactless Activation"),
            (0x000010, "contactless_self_activation", "Contactless Self-Activation"),
        ]
        active_privileges: list[str] = []
        active_ids: list[str] = []
        for mask_value, privilege_id, privilege_name in privilege_flags:
            if privilege_value & mask_value:
                active_ids.append(privilege_id)
                active_privileges.append(privilege_name)
        return {
            "format": "GlobalPlatform application privileges",
            "hex": value_bytes.hex(),
            "activePrivilegeIds": active_ids,
            "activePrivileges": active_privileges,
        }

    def _decode_life_cycle_state(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None

        state_value = value_bytes[0]
        state_names = {
            0x01: "Loaded",
            0x03: "Installed",
            0x07: "Selectable",
            0x0F: "Personalized",
            0x83: "Locked",
        }
        return {
            "format": "GlobalPlatform life cycle state",
            "code": f"0x{state_value:02X}",
            "state": state_names.get(state_value, "Unknown"),
        }

    def _decode_key_usage_qualifier(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0 or len(value_bytes) > 2:
            return None

        normalized_bytes = value_bytes
        if len(normalized_bytes) == 1:
            normalized_bytes = normalized_bytes + b"\x00"
        usage_value = int.from_bytes(normalized_bytes, "big", signed=False)
        usage_flags = [
            (0x8000, "verification_encryption", "Verification / Encryption"),
            (0x4000, "computation_decipherment", "Computation / Decipherment"),
            (0x2000, "sm_response", "Secure Messaging Response"),
            (0x1000, "sm_command", "Secure Messaging Command"),
            (0x0800, "confidentiality", "Confidentiality"),
            (0x0400, "crypto_checksum", "Cryptographic Checksum"),
            (0x0200, "digital_signature", "Digital Signature"),
            (0x0100, "crypto_authorization", "Cryptographic Authorization"),
            (0x0080, "key_agreement", "Key Agreement"),
        ]
        active_ids: list[str] = []
        active_flags: list[str] = []
        for mask_value, usage_id, usage_name in usage_flags:
            if usage_value & mask_value:
                active_ids.append(usage_id)
                active_flags.append(usage_name)
        return {
            "format": "GlobalPlatform key usage qualifier",
            "hex": value_bytes.hex(),
            "normalizedHex": normalized_bytes.hex(),
            "activeUsageIds": active_ids,
            "activeUsages": active_flags,
        }

    def _decode_key_access(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None

        access_value = value_bytes[0]
        access_names = {
            0x00: "Security Domain and any associated application",
            0x01: "Security Domain only",
            0x02: "Any associated application but not the Security Domain",
            0xFF: "Not available",
        }
        return {
            "format": "GlobalPlatform key access",
            "code": f"0x{access_value:02X}",
            "access": access_names.get(access_value, "Unknown"),
        }

    def _decode_key_identifier(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None

        key_id = value_bytes[0]
        common_roles = {
            0x01: "ENC (common SCP02/SCP03 convention)",
            0x02: "MAC (common SCP02/SCP03 convention)",
            0x03: "DEK (common SCP02/SCP03 convention)",
        }
        decoded: dict[str, object] = {
            "hex": value_bytes.hex(),
            "decimal": key_id,
        }
        role_name = common_roles.get(key_id)
        if role_name is not None:
            decoded["commonRole"] = role_name
        return decoded

    def _decode_key_version_number(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None

        kvn_value = value_bytes[0]
        decoded: dict[str, object] = {
            "hex": value_bytes.hex(),
            "decimal": kvn_value,
        }
        if 0x01 <= kvn_value <= 0x0F:
            decoded["reservedFor"] = "SCP80"
        elif kvn_value == 0x11:
            decoded["reservedFor"] = "DAP according to ETSI TS 102 226"
        elif 0x20 <= kvn_value <= 0x2F:
            decoded["reservedFor"] = "SCP02"
        elif 0x30 <= kvn_value <= 0x3F:
            decoded["reservedFor"] = "SCP03"
        elif kvn_value == 0xFF:
            decoded["reservedFor"] = "ISD with SCP02 without SCP80 support"
        return decoded

    def _decode_key_counter_value(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        return {
            "hex": value_bytes.hex(),
            "decimal": int.from_bytes(value_bytes, "big", signed=False),
        }

    def _decode_key_type(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None

        key_type_value = value_bytes[0]
        key_type_names = {
            0x80: "DES",
            0x85: "TLS-PSK",
            0x88: "AES",
            0x90: "HMAC-SHA1",
            0x91: "HMAC-SHA1-160",
            0xA0: "RSA Public Exponent",
            0xA1: "RSA Modulus (cleartext)",
            0xA2: "RSA Modulus",
        }
        return {
            "hex": value_bytes.hex(),
            "type": key_type_names.get(key_type_value, "Unknown"),
        }

    def _decode_pin_puk_retry_counter(self, value):
        packed_value = None
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            if value < 0 or value > 0xFF:
                return None
            packed_value = value
        else:
            value_bytes = self._value_to_bytes(value)
            if value_bytes is None or len(value_bytes) != 1:
                return None
            packed_value = value_bytes[0]
        max_attempts = (packed_value >> 4) & 0x0F
        remaining_attempts = packed_value & 0x0F
        return {
            "format": "PIN/PUK retry counters",
            "hex": f"{packed_value:02x}",
            "decimal": packed_value,
            "maxAttempts": max_attempts,
            "remainingAttempts": remaining_attempts,
            "summary": f"{remaining_attempts} remaining of {max_attempts} (0x{packed_value:02X})",
        }

    def _decode_pin_puk_adm_key_reference(self, value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            reference_value = value
        else:
            value_bytes = self._value_to_bytes(value)
            if value_bytes is None or len(value_bytes) == 0:
                return None
            reference_value = int.from_bytes(value_bytes, "big", signed=False)
        decoded: dict[str, object] = {
            "format": "PIN/PUK/ADM key reference",
            "decimal": reference_value,
        }
        if 1 <= reference_value <= 8:
            slot_index = reference_value
            decoded["slotIndex"] = slot_index
            decoded["pinName"] = f"pinAppl{slot_index}"
            decoded["pukName"] = f"pukAppl{slot_index}"
        elif 129 <= reference_value <= 136:
            slot_index = reference_value - 128
            decoded["slotIndex"] = slot_index
            decoded["pinName"] = f"secondPINAppl{slot_index}"
            decoded["pukName"] = f"secondPUKAppl{slot_index}"
        elif 10 <= reference_value <= 14:
            decoded["admName"] = f"adm{reference_value - 9}"
        elif 138 <= reference_value <= 142:
            decoded["admName"] = f"adm{reference_value - 132}"
        return decoded

    def _decode_puk_key_reference(self, value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            reference_value = value
        else:
            value_bytes = self._value_to_bytes(value)
            if value_bytes is None or len(value_bytes) == 0:
                return None
            reference_value = int.from_bytes(value_bytes, "big", signed=False)
        mapping = {
            1: "pukAppl1",
            2: "pukAppl2",
            3: "pukAppl3",
            4: "pukAppl4",
            5: "pukAppl5",
            6: "pukAppl6",
            7: "pukAppl7",
            8: "pukAppl8",
            129: "secondPUKAppl1",
            130: "secondPUKAppl2",
            131: "secondPUKAppl3",
            132: "secondPUKAppl4",
            133: "secondPUKAppl5",
            134: "secondPUKAppl6",
            135: "secondPUKAppl7",
            136: "secondPUKAppl8",
        }
        return {
            "format": "PUK key reference",
            "decimal": reference_value,
            "referenceName": mapping.get(reference_value, "Unknown"),
        }

    def _decode_pin_attributes(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        decoded = {
            "format": "PIN attributes",
            "hex": value_bytes.hex(),
            "decimal": value_bytes[0],
        }
        flag_info = self._decode_flag_octets(value_bytes)
        if flag_info is not None:
            decoded["setBits"] = flag_info.get("setBits")
        return decoded

    def _decode_fill_file_offset(self, value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            decimal_value = value
        else:
            value_bytes = self._value_to_bytes(value)
            if value_bytes is None or len(value_bytes) == 0:
                return None
            decimal_value = int.from_bytes(value_bytes, "big", signed=False)
        if decimal_value < 0:
            return None
        hex_value = f"{decimal_value:X}"
        if len(hex_value) % 2 != 0:
            hex_value = f"0{hex_value}"
        hex_value = hex_value.zfill(4)
        return {
            "format": "File content offset",
            "decimal": decimal_value,
            "hex": hex_value.lower(),
        }

    def _decode_pin_status_template_do(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded: dict[str, object] = {
            "format": "PIN status template DO",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        if len(value_bytes) >= 1:
            status_bytes = value_bytes[:-1] if len(value_bytes) > 1 else value_bytes
            decoded["statusBytes"] = status_bytes.hex()
            flag_info = self._decode_flag_octets(status_bytes)
            if flag_info is not None:
                decoded["statusBits"] = flag_info.get("setBits")
        if len(value_bytes) >= 2:
            key_reference = self._decode_pin_puk_adm_key_reference(value_bytes[-1])
            if key_reference is not None:
                decoded["keyReference"] = key_reference
        return decoded

    def _decode_pin_secret_value(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded: dict[str, object] = {
            "format": "PIN/PUK value",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        content_bytes = value_bytes.rstrip(b"\xFF")
        padding_bytes = value_bytes[len(content_bytes) :]
        if len(padding_bytes) > 0:
            decoded["paddingHex"] = padding_bytes.hex()
        ascii_text = self._decode_printable_ascii(content_bytes)
        if ascii_text not in (None, ""):
            decoded["ascii"] = ascii_text
            if ascii_text.isdigit():
                decoded["digits"] = ascii_text
        return decoded

    def _decode_profile_iccid(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        digits = value_bytes.hex().upper().rstrip("F")
        if re.fullmatch(r"[0-9]+", digits) is None:
            return None
        return {
            "format": "Profile ICCID",
            "hex": value_bytes.hex(),
            "iccid": digits,
            "digitCount": len(digits),
        }

    def _decode_key_data(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        return {
            "format": "Security domain key material",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
            "keySizeBits": len(value_bytes) * 8,
        }

    def _decode_application_identifier(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        aid_hex = value_bytes.hex()
        decoded: dict[str, object] = {
            "format": "Application Identifier",
            "aid": aid_hex,
            "length": len(value_bytes),
        }
        if len(value_bytes) >= 5:
            decoded["rid"] = aid_hex[:10]
            if len(value_bytes) > 5:
                decoded["pix"] = aid_hex[10:]
        return decoded

    def _decode_minimum_security_level(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        decoded = {
            "format": "Minimum security level",
            "hex": value_bytes.hex(),
            "decimal": value_bytes[0],
        }
        flag_info = self._decode_flag_octets(value_bytes)
        if flag_info is not None:
            decoded["setBits"] = flag_info.get("setBits")
        return decoded

    def _decode_mac_length(self, value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            mac_length = value
        else:
            value_bytes = self._value_to_bytes(value)
            if value_bytes is None or len(value_bytes) == 0:
                return None
            mac_length = int.from_bytes(value_bytes, "big", signed=False)
        if mac_length < 0:
            return None
        return {
            "format": "MAC length",
            "decimal": mac_length,
        }

    def _decode_profile_policy_rules(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded = {
            "format": "Profile policy rules",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        flag_info = self._decode_flag_octets(value_bytes)
        if flag_info is None:
            return decoded
        set_bits = list(flag_info.get("setBits", []))
        decoded["setBits"] = set_bits
        active_policies: list[str] = []
        for bit_index in set_bits:
            active_policies.append(_PROFILE_POLICY_RULE_NAMES.get(bit_index, f"bit{bit_index}"))
        decoded["activePolicies"] = active_policies
        return decoded

    def _decode_memory_limit_field(self, field_name, value):
        key_text = str(field_name or "").strip()
        format_name = _MEMORY_LIMIT_FIELD_LABELS.get(key_text)
        if format_name is None:
            return None
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        return {
            "format": format_name,
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
            "decimal": int.from_bytes(value_bytes, "big", signed=False),
        }

    def _decode_aka_algorithm_id(self, value):
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            algorithm_id = value
        else:
            value_bytes = self._value_to_bytes(value)
            if value_bytes is None or len(value_bytes) == 0:
                return None
            algorithm_id = int.from_bytes(value_bytes, "big", signed=False)
        return {
            "format": "AKA algorithm identifier",
            "decimal": algorithm_id,
            "algorithm": _AKA_ALGORITHM_ID_NAMES.get(algorithm_id, "unknown"),
        }

    def _decode_aka_option_octet(self, value, format_name):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        decoded = {
            "format": format_name,
            "hex": value_bytes.hex(),
            "decimal": value_bytes[0],
        }
        flag_info = self._decode_flag_octets(value_bytes)
        if flag_info is not None:
            decoded["setBits"] = flag_info.get("setBits")
        return decoded

    def _decode_aka_secret_material(self, value, format_name):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        return {
            "format": format_name,
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
            "keySizeBits": len(value_bytes) * 8,
        }

    def _decode_aka_counter_field(self, value, format_name):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        return {
            "format": format_name,
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
            "decimal": int.from_bytes(value_bytes, "big", signed=False),
        }

    def _decode_rotation_constants(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 5:
            return None
        decoded = {
            "format": "Milenage rotation constants",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        for index, byte_value in enumerate(value_bytes, start=1):
            decoded[f"r{index}"] = byte_value
        return decoded

    def _decode_xoring_constants(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0 or len(value_bytes) % 16 != 0:
            return None
        decoded = {
            "format": "Milenage XOR constants",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
            "blockCount": len(value_bytes) // 16,
        }
        for index, offset in enumerate(range(0, len(value_bytes), 16), start=1):
            decoded[f"c{index}"] = value_bytes[offset : offset + 16].hex()
        return decoded

    def _fid_name_from_hex(self, fid_hex, parent_hint=None):
        resolved = _fid_name_lookup(str(fid_hex or ""), parent_hint=parent_hint)
        if resolved is not None:
            return resolved
        return _FID_TO_NAME.get(str(fid_hex or "").upper())

    def _decode_file_identifier(self, value, parent_hint=None):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 2:
            return None
        fid_hex = value_bytes.hex().upper()
        decoded = {
            "format": "File Identifier",
            "hex": value_bytes.hex(),
            "decimal": int.from_bytes(value_bytes, "big", signed=False),
        }
        fid_name = self._fid_name_from_hex(fid_hex, parent_hint=parent_hint)
        if fid_name is not None:
            decoded["name"] = fid_name
        return decoded

    def _decode_security_attributes_referenced(self, value, parent_hint=None):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded = {
            "format": "Referenced security attributes",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        if len(value_bytes) == 1:
            decoded["recordNumber"] = value_bytes[0]
            decoded["arrFileId"] = "implicit"
            return decoded
        if len(value_bytes) == 3:
            fid_hex = value_bytes[:2].hex().upper()
            decoded["arrFileId"] = fid_hex
            fid_name = self._fid_name_from_hex(fid_hex, parent_hint=parent_hint)
            if fid_name is not None:
                decoded["arrFileName"] = fid_name
            decoded["recordNumber"] = value_bytes[2]
        return decoded

    def _decode_path_value(self, value, format_name, empty_summary, parent_hint=None):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None:
            return None
        decoded = {
            "format": format_name,
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        if len(value_bytes) == 0:
            decoded["independentFile"] = True
            decoded["summary"] = empty_summary
            return decoded
        if len(value_bytes) % 2 != 0:
            return decoded
        segments: list[dict[str, object]] = []
        for offset in range(0, len(value_bytes), 2):
            fid_hex = value_bytes[offset : offset + 2].hex().upper()
            segment: dict[str, object] = {"fid": fid_hex}
            fid_name = self._fid_name_from_hex(fid_hex, parent_hint=parent_hint)
            if fid_name is not None:
                segment["name"] = fid_name
            segments.append(segment)
        decoded["segments"] = segments
        return decoded

    def _decode_link_path(self, value, parent_hint=None):
        return self._decode_path_value(
            value,
            "Link path",
            "independent file",
            parent_hint=parent_hint,
        )

    def _decode_file_path(self, value, parent_hint=None):
        return self._decode_path_value(
            value,
            "File path",
            "MF",
            parent_hint=parent_hint,
        )

    def _decode_special_file_information(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        byte_value = value_bytes[0]
        decoded = {
            "format": "Special file information",
            "hex": value_bytes.hex(),
            "decimal": byte_value,
            "highUpdateActivity": (byte_value & 0x80) != 0,
            "readAndUpdateWhenDeactivated": (byte_value & 0x40) != 0,
        }
        flag_info = self._decode_flag_octets(value_bytes)
        if flag_info is not None:
            decoded["setBits"] = flag_info.get("setBits")
        return decoded

    def _decode_fill_pattern(self, value, format_name):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded = {
            "format": format_name,
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        if len(value_bytes) == 1:
            decoded["byteValue"] = f"0x{value_bytes[0]:02X}"
        ascii_text = self._decode_printable_ascii(value_bytes)
        if ascii_text not in (None, ""):
            decoded["ascii"] = ascii_text
        return decoded

    def _decode_file_details(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        decoded = {
            "format": "BER-TLV file details",
            "hex": value_bytes.hex(),
            "decimal": value_bytes[0],
        }
        if value_bytes[0] == 0x01:
            decoded["coding"] = "DER coding"
        return decoded

    def _decode_sqn_init_list(self, value):
        if isinstance(value, list) is False:
            return self._decode_aka_counter_field(value, "SQN initial value")
        decoded_items: list[dict[str, object]] = []
        for item in value:
            decoded = self._decode_aka_counter_field(item, "SQN initial value")
            if decoded is not None:
                decoded_items.append(decoded)
        if len(decoded_items) == 0:
            return None
        return decoded_items

    def _decode_tar_value(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded = {
            "format": "Toolkit Application Reference",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
        }
        if len(value_bytes) == 3:
            decoded["tar"] = value_bytes.hex()
        return decoded

    def _decode_tar_list(self, value):
        if isinstance(value, list) is False:
            single = self._decode_tar_value(value)
            if single is None:
                return None
            return [single]
        decoded_items: list[dict[str, object]] = []
        for item in value:
            decoded = self._decode_tar_value(item)
            if decoded is not None:
                decoded_items.append(decoded)
        if len(decoded_items) == 0:
            return None
        return decoded_items

    def _decode_access_domain(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        decoded: dict[str, object] = {
            "format": "Access domain",
            "hex": value_bytes.hex(),
            "length": len(value_bytes),
            "bytes": [f"0x{byte_value:02X}" for byte_value in value_bytes],
        }
        if len(value_bytes) >= 3 and value_bytes[0] == 0x02 and value_bytes[1] == len(value_bytes) - 2:
            decoded["berInteger"] = int.from_bytes(value_bytes[2:], "big", signed=False)
        return decoded

    def _decode_lcsi(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) != 1:
            return None
        lcsi = value_bytes[0]
        state_name = "unknown"
        if lcsi == 0x00:
            state_name = "no_information"
        elif lcsi == 0x01:
            state_name = "creation"
        elif lcsi == 0x03:
            state_name = "initialization"
        elif lcsi & 0x05 == 0x05:
            state_name = "operational_activated"
        elif lcsi & 0x05 == 0x04:
            state_name = "operational_deactivated"
        elif lcsi & 0xC0 == 0xC0:
            state_name = "termination"
        return {
            "format": "Life Cycle Status Integer",
            "hex": value_bytes.hex(),
            "state": state_name,
        }

    def _decode_ef_file_size(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) == 0:
            return None
        return {
            "format": "EF file size",
            "hex": value_bytes.hex(),
            "decimal": int.from_bytes(value_bytes, "big", signed=False),
        }

    def _decode_short_efid(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None:
            return None
        if len(value_bytes) == 0:
            return {
                "format": "Short EF Identifier",
                "supported": False,
            }
        if len(value_bytes) != 1:
            return None
        raw_value = value_bytes[0]
        return {
            "format": "Short EF Identifier",
            "hex": value_bytes.hex(),
            "supported": True,
            "sfi": raw_value >> 3,
            "reservedLowBits": raw_value & 0x07,
            "validEncoding": (raw_value & 0x07) == 0,
        }

    def _decode_file_descriptor(self, value):
        value_bytes = self._value_to_bytes(value)
        if value_bytes is None or len(value_bytes) < 2:
            return None
        descriptor_byte = value_bytes[0]
        shareable = bool(descriptor_byte & 0x40)
        if descriptor_byte & 0x3F == 0x39:
            file_type = "working_ef"
            structure = "ber_tlv"
        else:
            file_type = {
                0: "working_ef",
                1: "internal_ef",
                7: "df",
            }.get((descriptor_byte >> 3) & 0x07, "unknown")
            structure = {
                0: "no_info_given",
                1: "transparent",
                2: "linear_fixed",
                6: "cyclic",
            }.get(descriptor_byte & 0x07, "unknown")
        decoded: dict[str, object] = {
            "format": "ETSI TS 102 221 file descriptor",
            "hex": value_bytes.hex(),
            "shareable": shareable,
            "fileType": file_type,
            "structure": structure,
            "descriptorCodingByte": f"0x{value_bytes[1]:02X}",
        }
        if len(value_bytes) >= 4:
            decoded["recordLength"] = int.from_bytes(value_bytes[2:4], "big", signed=False)
        if len(value_bytes) >= 5:
            decoded["numberOfRecords"] = value_bytes[4]
        if "recordLength" in decoded and "numberOfRecords" in decoded:
            decoded["derivedFileSize"] = decoded["recordLength"] * decoded["numberOfRecords"]
        return decoded

    def _parse_uicc_toolkit_parameters(self, value_bytes: bytes) -> dict[str, object] | None:
        try:
            offset = 0
            if offset >= len(value_bytes):
                return None
            access_domain_length = value_bytes[offset]
            offset += 1
            if offset + access_domain_length > len(value_bytes):
                return None
            access_domain = value_bytes[offset : offset + access_domain_length]
            offset += access_domain_length

            if offset + 4 > len(value_bytes):
                return None
            priority_level = value_bytes[offset]
            offset += 1
            max_num_of_timers = value_bytes[offset]
            offset += 1
            max_text_length = value_bytes[offset]
            offset += 1
            menu_entry_count = value_bytes[offset]
            offset += 1

            menu_entries: list[dict[str, int]] = []
            for _ in range(menu_entry_count):
                if offset + 2 > len(value_bytes):
                    return None
                menu_entries.append(
                    {
                        "id": value_bytes[offset],
                        "position": value_bytes[offset + 1],
                    }
                )
                offset += 2

            if offset >= len(value_bytes):
                return None
            max_num_of_channels = value_bytes[offset]
            offset += 1

            if offset >= len(value_bytes):
                return None
            msl_length = value_bytes[offset]
            offset += 1
            if offset + msl_length > len(value_bytes):
                return None
            msl_value_bytes = value_bytes[offset : offset + msl_length]
            offset += msl_length

            if offset >= len(value_bytes):
                return None
            tar_data_length = value_bytes[offset]
            offset += 1
            tar_values: list[str] = []
            if offset + tar_data_length > len(value_bytes):
                return None
            tar_end = offset + tar_data_length
            if tar_data_length % 3 != 0:
                return None
            while offset < tar_end:
                tar_values.append(value_bytes[offset : offset + 3].hex())
                offset += 3

            trailing_padding = b""
            if offset != len(value_bytes):
                trailing_padding = value_bytes[offset:]
                if any(byte_value != 0x00 for byte_value in trailing_padding):
                    return None
                offset = len(value_bytes)

            if offset != len(value_bytes):
                return None
        except Exception:
            return None

        decoded: dict[str, object] = {
            "format": "ETSI TS 102 226 toolkit app specific parameters",
            "accessDomain": access_domain.hex(),
            "priorityLevelOfToolkitAppInstance": priority_level,
            "maxNumberOfTimers": max_num_of_timers,
            "maxTextLengthForMenuEntry": max_text_length,
            "menuEntries": menu_entries,
            "maxNumberOfChannels": max_num_of_channels,
            "minimumSecurityLevelRaw": msl_value_bytes.hex(),
            "tarValues": tar_values,
        }
        if len(msl_value_bytes) >= 1:
            decoded["minimumSecurityLevelInferred"] = f"0x{msl_value_bytes[-1]:02X}"
            decoded["minimumSecurityLevelDecimal"] = msl_value_bytes[-1]
        if len(tar_values) > 0:
            decoded["tarInferred"] = tar_values[0]
        if len(trailing_padding) > 0:
            decoded["trailingPadding"] = trailing_padding.hex()
        return decoded

    def _extract_toolkit_msl_and_tar(self, value_bytes: bytes) -> tuple[int | None, bytes | None]:
        msl_value = None
        if len(value_bytes) >= 3:
            for index in range(0, len(value_bytes) - 2):
                if value_bytes[index] == 0x02 and value_bytes[index + 1] == 0x01:
                    msl_value = value_bytes[index + 2]
                    break
        tar_index = value_bytes.find(bytes.fromhex("b20100"))
        if tar_index == -1:
            return msl_value, None
        return msl_value, value_bytes[tar_index : tar_index + 3]

    def _value_to_bytes(self, value) -> bytes | None:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, bool):
            return None
        if isinstance(value, int):
            if value < 0:
                return None
            length = max(1, (int(value).bit_length() + 7) // 8)
            return int(value).to_bytes(length, "big", signed=False)
        if isinstance(value, str):
            compact = value.strip()
            if len(compact) < 2 or len(compact) % 2 != 0:
                return None
            for character in compact.upper():
                if character not in "0123456789ABCDEF":
                    return None
            try:
                return bytes.fromhex(compact)
            except ValueError:
                return None
        return None

    def _value_to_hex_strings(self, value) -> list[str]:
        if isinstance(value, str):
            compact = value.strip()
            if self._looks_like_hex(compact):
                return [compact]
            return []
        if isinstance(value, bytes):
            return [value.hex()]
        if isinstance(value, bytearray):
            return [bytes(value).hex()]
        if isinstance(value, list):
            hex_values: list[str] = []
            for item in value:
                hex_values.extend(self._value_to_hex_strings(item))
            return hex_values
        return []

    def _decode_printable_ascii(self, value_bytes: bytes) -> str | None:
        if len(value_bytes) == 0:
            return None
        try:
            decoded = value_bytes.decode("ascii")
        except UnicodeDecodeError:
            return None
        for character in decoded:
            if ord(character) < 0x20 or ord(character) > 0x7E:
                return None
        return decoded

    def _decode_network_access_name(self, value_bytes: bytes) -> str:
        if len(value_bytes) == 0:
            return "(empty)"
        labels: list[str] = []
        offset = 0
        while offset < len(value_bytes):
            label_length = value_bytes[offset]
            offset += 1
            if label_length == 0:
                break
            label_end = offset + label_length
            if label_end > len(value_bytes):
                return value_bytes.hex()
            label_bytes = value_bytes[offset:label_end]
            try:
                labels.append(label_bytes.decode("ascii"))
            except UnicodeDecodeError:
                return value_bytes.hex()
            offset = label_end
        if len(labels) == 0:
            return value_bytes.hex()
        return ".".join(labels)

    def _describe_bearer_description(self, value_bytes: bytes) -> dict[str, object] | str:
        if len(value_bytes) == 0:
            return "(empty)"
        bearer_type = value_bytes[0]
        bearer_names = {
            0x01: "CSD",
            0x02: "GPRS",
            0x03: "Default bearer",
            0x04: "Local link",
        }
        decoded = {
            "type": f"0x{bearer_type:02X}",
            "typeName": bearer_names.get(bearer_type, "Unknown"),
        }
        if len(value_bytes) > 1:
            decoded["parameters"] = value_bytes[1:].hex()
        return decoded

    def _describe_transport_level(self, value_bytes: bytes) -> dict[str, object] | str:
        if len(value_bytes) != 3:
            return value_bytes.hex()
        protocol_type = value_bytes[0]
        port_number = int.from_bytes(value_bytes[1:], "big", signed=False)
        protocol_names = {
            0x01: "UDP, remote connection",
            0x02: "TCP, remote connection",
            0x03: "TCP, local connection",
            0x04: "UDP, local connection",
        }
        return {
            "protocol": f"0x{protocol_type:02X}",
            "protocolName": protocol_names.get(protocol_type, "Unknown"),
            "port": port_number,
        }

    def _decode_other_address(self, value_bytes: bytes) -> dict[str, object] | str:
        if len(value_bytes) < 2:
            return value_bytes.hex()
        address_type = value_bytes[0]
        address_value = value_bytes[1:]
        type_names = {
            0x21: "IPv4",
            0x57: "IPv6",
        }
        decoded: dict[str, object] = {
            "type": f"0x{address_type:02X}",
            "typeName": type_names.get(address_type, "Unknown"),
        }
        try:
            if address_type == 0x21 and len(address_value) == 4:
                decoded["address"] = str(ipaddress.IPv4Address(address_value))
            elif address_type == 0x57 and len(address_value) == 16:
                decoded["address"] = str(ipaddress.IPv6Address(address_value))
            else:
                decoded["rawAddress"] = address_value.hex()
        except ipaddress.AddressValueError:
            decoded["rawAddress"] = address_value.hex()
        return decoded

    def _decode_oid(self, value_bytes: bytes) -> str | None:
        if len(value_bytes) == 0:
            return None

        first_value = value_bytes[0]
        if first_value < 40:
            arcs = [0, first_value]
        elif first_value < 80:
            arcs = [1, first_value - 40]
        else:
            arcs = [2, first_value - 80]
        current_value = 0
        for octet in value_bytes[1:]:
            current_value = (current_value << 7) | (octet & 0x7F)
            if octet & 0x80 == 0:
                arcs.append(current_value)
                current_value = 0
        if current_value != 0:
            return None
        return ".".join(str(arc) for arc in arcs)

    def _ber_tag_name(
        self,
        tag: str,
        tag_names: dict[str, str] | None = None,
    ) -> str:
        if tag_names is not None and tag in tag_names:
            return tag_names[tag]
        default_names = {
            "35": "Bearer Description",
            "39": "Buffer Size",
            "3C": "Transport Level",
            "3E": "Other Address",
            "47": "Network Access Name",
            "06": "Object Identifier",
            "81": "Tag 81",
            "82": "Tag 82",
            "A0": "Constructed A0",
            "A1": "Constructed A1",
        }
        return default_names.get(tag, f"Tag {tag}")

    def _scp_name(self, scp_value: int) -> str:
        scp_names = {
            0x80: "SCP80",
            0x02: "SCP02",
            0x03: "SCP03",
        }
        return scp_names.get(scp_value, "Unknown")

    def _render_mapping(
        self,
        name,
        value: dict,
        indent: int,
        key_width: int | None = None,
    ) -> list[str]:
        lines: list[str] = []
        if name is not None:
            lines.append(self._format_block_header(name, indent, key_width=key_width))
            indent += 1

        key_width = self._compute_key_width(value)
        for key, item in value.items():
            lines.extend(self._render_named_value(str(key), item, indent, key_width=key_width))

        if len(lines) == 0:
            lines.append(self._format_scalar_line(name, "(empty)", indent))
        return lines

    def _render_tuple(self, name, value: tuple, indent: int, key_width: int | None = None) -> list[str]:
        if len(value) == 2 and isinstance(value[0], str):
            kind = value[0]
            payload = value[1]
            if self._is_scalar(payload):
                return [
                    self._format_scalar_line(
                        name,
                        f"{kind} | {self._format_scalar(payload)}",
                        indent,
                        key_width=key_width,
                    )
                ]

            lines = [self._format_scalar_line(name, kind, indent, key_width=key_width)]
            lines.extend(self._render_named_value(None, payload, indent + 1))
            return lines

        return self._render_list(name, list(value), indent)

    def _render_list(self, name, value: list, indent: int, key_width: int | None = None) -> list[str]:
        if len(value) == 0:
            return [self._format_scalar_line(name, "(empty)", indent, key_width=key_width)]

        simple_items = True
        for item in value:
            if self._is_scalar(item) is False:
                simple_items = False
                break

        if simple_items:
            joined = ", ".join(self._format_scalar(item) for item in value)
            return [self._format_scalar_line(name, joined, indent, key_width=key_width)]

        lines: list[str] = []
        if name is not None:
            lines.append(self._format_block_header(name, indent, key_width=key_width))
            indent += 1

        entry_key_width = len(f"[{len(value)}]")
        entry_index = 1
        for item in value:
            if isinstance(item, tuple) and len(item) == 2 and isinstance(item[0], str):
                lines.extend(self._render_named_value(item[0], item[1], indent))
            else:
                lines.append(
                    self._format_block_header(
                        f"[{entry_index}]",
                        indent,
                        key_width=entry_key_width,
                    )
                )
                lines.extend(self._render_named_value(None, item, indent + 1))
                entry_index += 1

        return lines

    @staticmethod
    def _is_scalar(value) -> bool:
        return isinstance(value, (str, int, float, bool)) or value is None

    def _compute_key_width(self, value: dict) -> int:
        width = 0
        for key in value.keys():
            width = max(width, len(str(key)))
        width = max(width, 18)
        width = min(width, 32)
        return width

    def _format_block_header(self, name: str, indent: int, key_width: int | None = None) -> str:
        prefix = "  " * indent
        padded_name = self._pad_key(name, key_width)
        if key_width is None:
            return f"{ShellStyle.CYAN}{prefix}| {name}{ShellStyle.END}"
        return f"{ShellStyle.CYAN}{prefix}| {padded_name}{ShellStyle.END}"

    def _pad_key(self, name: str, key_width: int | None) -> str:
        if key_width is None:
            return name
        if len(name) >= key_width:
            return name
        return f"{name:<{key_width}}"

    def _format_scalar_line(self, name, value, indent: int, key_width: int | None = None) -> str:
        prefix = "  " * indent
        rendered_value = self._format_scalar(value)
        if name is None:
            return f"{prefix}| {rendered_value}"
        padded_name = self._pad_key(str(name), key_width)
        if key_width is None:
            return f"{prefix}| {padded_name:<28} : {rendered_value}"
        return f"{prefix}| {padded_name} : {rendered_value}"

    def _format_scalar(self, value) -> str:
        if value is None:
            return "Present"

        if isinstance(value, bool):
            if value:
                return "True"
            return "False"

        text = str(value)
        compact = text.strip()
        if self._looks_like_hex(compact) and len(compact) > 64:
            return f"{compact[:32]}...{compact[-24:]}"
        if len(compact) > 120:
            return f"{compact[:60]}...{compact[-40:]}"
        return compact

    @staticmethod
    def _looks_like_hex(value: str) -> bool:
        if len(value) < 8:
            return False
        if len(value) % 2 != 0:
            return False
        for character in value.upper():
            if character not in "0123456789ABCDEF":
                return False
        return True

    @staticmethod
    def _strip_ansi(text: str) -> str:
        return re.sub(r"\x1B\[[0-9;]*[A-Za-z]", "", text)

    def _parse_output_redirection(self, arg: str) -> tuple[list[str], Path | None]:
        normalized_arg = arg.replace(">", " > ")
        tokens = shlex.split(normalized_arg.strip())
        if ">" not in tokens:
            return tokens, None

        if tokens.count(">") != 1:
            raise ValueError("Usage: DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]")

        redirect_index = tokens.index(">")
        if redirect_index == len(tokens) - 1:
            raise ValueError("Usage: DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]")

        if len(tokens) > redirect_index + 2:
            raise ValueError("Usage: DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]")

        try:
            output_path = self.bridge.resolve_workspace_path(
                tokens[redirect_index + 1],
                must_exist=False,
            )
        except ValueError as error:
            message = str(error)
            if "outside workspace root" in message:
                raise ValueError(
                    "Output redirection is workspace-confined. "
                    "Use a relative path under the project root, for example "
                    "`reports/decoded_dump.txt`."
                ) from error
            raise
        return tokens[:redirect_index], output_path

    def _write_output_file(
        self,
        output_path: Path,
        rendered_stdout: str,
        structured_dump: dict | None = None,
        artifact_label: str = "Dump",
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if structured_dump is not None:
            if output_path.suffix.lower() == ".json":
                serialized = json.dumps(structured_dump, indent=2, ensure_ascii=False)
                output_format = "JSON"
            else:
                serialized = yaml.safe_dump(
                    structured_dump,
                    allow_unicode=True,
                    sort_keys=False,
                    default_flow_style=False,
                )
                output_format = "YAML"
            output_path.write_text(serialized, encoding="utf-8")
            print(
                f"{ShellStyle.GREEN}[+] {artifact_label} written to: {output_path} "
                f"({output_format}){ShellStyle.END}"
            )
            return

        plain_text = self._strip_ansi(rendered_stdout)
        output_path.write_text(plain_text, encoding="utf-8")
        print(f"{ShellStyle.GREEN}[+] {artifact_label} written to: {output_path}{ShellStyle.END}")

    def _parse_lint_output_redirection(self, arg: str) -> tuple[list[str], Path | None]:
        normalized_arg = arg.replace(">", " > ")
        tokens = shlex.split(normalized_arg.strip())
        if ">" not in tokens:
            return tokens, None

        if tokens.count(">") != 1:
            raise ValueError("Usage: LINT [STRICT] [METADATA <path>] [> output_file]")

        redirect_index = tokens.index(">")
        if redirect_index == len(tokens) - 1:
            raise ValueError("Usage: LINT [STRICT] [METADATA <path>] [> output_file]")

        if len(tokens) > redirect_index + 2:
            raise ValueError("Usage: LINT [STRICT] [METADATA <path>] [> output_file]")

        try:
            output_path = self.bridge.resolve_workspace_path(
                tokens[redirect_index + 1],
                must_exist=False,
            )
        except ValueError as error:
            message = str(error)
            if "outside workspace root" in message:
                raise ValueError(
                    "Output redirection is workspace-confined. "
                    "Use a relative path under the project root, for example "
                    "`reports/profile_lint.yaml`."
                ) from error
            raise
        return tokens[:redirect_index], output_path

    def _exec_line(self, raw_line: str) -> bool:
        parts = raw_line.split(None, 1)
        command = parts[0].upper()
        argument = ""
        if len(parts) > 1:
            argument = parts[1]

        if command not in self._commands:
            print(f"{ShellStyle.FAIL}[-] Unknown command: {command}{ShellStyle.END}")
            return False

        try:
            self._commands[command](argument)
            return True
        except SystemExit:
            raise
        except Exception as error:
            message = str(error).strip() or error.__class__.__name__
            print(f"{ShellStyle.FAIL}[-] {message}{ShellStyle.END}")
            return False

    def _cmd_help(self, arg: str) -> None:
        topic = str(arg or "").strip().upper()
        if topic in ("TOKENS", "TOKEN"):
            self._cmd_help_tokens("")
            return
        if topic in ("TEMPLATE", "TEMPLATES"):
            self._cmd_help_template("")
            return
        if topic in ("EDIT", "EDITOR", "DECODED-EDIT"):
            self._cmd_help_edit("")
            return
        if topic in ("LINT",):
            self._cmd_lint("HELP")
            return
        if topic in ("TOPICS", "SUBTOPICS"):
            self._cmd_help_topics_list()
            return
        print(f"\n{ShellStyle.BOLD}SAIP Tool commands:{ShellStyle.END}")
        print("  Context:")
        print("    Use this shell to inspect and manipulate SAIP / UPP profile package inputs through `saip-tool`.")
        print(
            "    Use `OPEN` to browse for a profile and jump directly into the editor, "
            "or `USE` if you only want to select the active file without launching the TUI."
        )
        print("    Output locations for write operations remain workspace-confined.")
        print("")
        print("  Typical workflow:")
        print("    1. OPEN")
        print("    2. INFO")
        print("    3. TREE")
        print("    4. DUMP ALL DECODED")
        print("    5. CHECK")
        print("    6. LINT STRICT > reports/profile_lint.yaml")
        print("")
        print("  OPEN [file]                Open the terminal profile picker and launch the editor.")
        print("                             If a file is provided, select it first and then launch the editor.")
        print("                             The picker remembers the last browse directory and works over SSH.")
        print("  USE <file>                 Select active input UPP/DER file. Absolute paths are allowed for input.")
        print("                             Bare filenames are looked up in the default profile dir first.")
        print("                             `.txt` and `.hex` inputs are treated as hex-encoded DER and converted automatically.")
        print("  STATUS                     Show the active profile selection and transcode output directory.")
        print("  PROFILE-DIR [dir]          Show or set the default profile directory used by `USE` and tab completion.")
        print("  TRANSCODE-DIR [dir]        Show or set the default INSPECT save directory.")
        print("  TOOL [command]             Show or override the saip-tool executable command.")
        print("  INFO [APPS]                Run `info` and optionally include `--apps`.")
        print("  TREE                       Run `tree`.")
        print("  CHECK                      Run `check`.")
        print("  LINT [options] [> output_file]")
        print("                             Run profile linting across SAIP structure,")
        print("                             mandatory services, AID integrity, APDU/hex sanity, and metadata coherence.")
        print("                             For detailed lint options run: LINT HELP")
        print("                             For preset gate profiles run: LINT PROFILES")
        print("  DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]")
        print("                             Run `dump` using all_pe, all_pe_by_type, or all_pe_by_naa.")
        print("                             Use `>` to write a workspace-confined structured dump file.")
        print("                             Decoded dumps write YAML by default, or JSON when the path ends in `.json`.")
        print("  INSPECT                    Open a split Textual UI: JSON outline + editor (left) and DER hex (right);")
        print("                             F3 inserts blank PE blocks from pySim templates (before end PE).")
        print("                             Bottom split: left = live selection/whole-profile decode (F4),")
        print("                             right = live lint; F7 cycles theme (saved). JSON↔DER uses nearest { }/[ ] value.")
        print("                             Full-terminal layout using terminal-native styling; Ctrl+S or F2 save, Ctrl+Q quit.")
        print("  TUI                        Short alias for INSPECT.")
        print("                             Legacy alias: TRANSCODE-TUI.")
        print("  ENCODE-JSON <in.json> <out.der>")
        print("                             Build DER from tagged SAIP JSON (same schema as INSPECT).")
        print("                             Optional root __ygg_token_defs__ names {token} (default) or [token]")
        print("                             when __ygg_placeholder_style__ is bracket; use inside hex / __ygg_saip_ph__.")
        print("  PRESETS [preset_id]        List built-in / user presets, or show detail for one preset.")
        print("                             Detail view lists every PE with a short hint and which typed")
        print("                             placeholders (ICCID, IMSI) the preset supports. User presets load")
        print("                             from ~/.yggdrasim_saip_presets.json on shell startup.")
        print("  PREVIEW-PRESET <preset_id> Render the scaffold PE-sequence as an ASCII tree without")
        print("                             writing any file. Useful before calling NEW-PROFILE / NEW-TEMPLATE.")
        print("  DIFF-PRESET <a> <b>        Show menu_id additions, removals, and ordering delta between two")
        print("                             presets (handy when deriving a house-style variant).")
        print("  DIFF <profile_a> <profile_b> [NO-VALUES]")
        print("                             Side-by-side diff of two SAIP profiles. Each file may be a")
        print("                             transcode JSON, a simulator profile_image.json manifest, or a raw")
        print("                             SAIP DER. DER decode requires pySim; JSON works stand-alone. Prints")
        print("                             a grep-able report with +/-/~/> tags and colored coloring.")
        print("  DIFF-TUI <profile_a> <profile_b>")
        print("                             Same as DIFF but renders the result in a Textual side-by-side tree")
        print("                             with n/N to cycle diffs and v to toggle value display. Requires the")
        print("                             `textual` extra (install with `pip install textual`).")
        print("  WATCH-SIMCARD [STORE <dir>] [POLL <s>] [MAX <n>] [LAUNCHER <template>]")
        print("                             Tail the simulator profile-store directory and auto-launch a TUI")
        print("                             for every new ICCID that lands (e.g. after a SGP.26 ES9+ download).")
        print("                             Default store is the simulator default; default launcher is the SAIP")
        print("                             diff TUI. Template tokens: {iccid} and {profile_path}.")
        print("  NEW-TEMPLATE [out.json] [PRESET=<name>] [ICCID=<digits|AUTO>] [IMSI=<digits|AUTO>]")
        print("                             Scaffold a brand-new tagged JSON template from a preset PE sequence")
        print("                             (no active profile required). Omitting the output path writes to")
        print("                             <profile-dir>/scaffold-<preset>-<timestamp>.json. Use PRESETS to")
        print("                             list available PE skeletons (MINIMAL, BASIC-MF, USIM, ...).")
        print("                             ICCID / IMSI placeholder injection follows GENERATE-TEMPLATE rules;")
        print("                             pass ICCID=AUTO or IMSI=AUTO for Luhn-valid auto-generation.")
        print("  NEW-PROFILE [out.der] [PRESET=<name>] [ICCID=<digits|AUTO>] [IMSI=<digits|AUTO>] [VERIFY]")
        print("                             Scaffold a brand-new DER profile from a preset PE sequence, without")
        print("                             requiring USE first. Omitting the output path auto-generates a")
        print("                             timestamped filename in the current profile-dir. VERIFY round-trips")
        print("                             the produced DER and prints a PE summary. On success the new DER")
        print("                             becomes the active input for INSPECT / DUMP / TREE / LINT.")
        print("  NEW-PROFILE-WIZARD (alias: WIZARD)")
        print("                             Tag-granular interactive wizard. Walks preset selection, optional PE")
        print("                             drops, typed placeholders (with AUTO support), format and path")
        print("                             selection, then review before writing.")
        print("  LIST-AKA                   Read-only summary of every akaParameter PE in the active")
        print("                             profile, including algorithm, Ki/OPc byte length, Keccak count,")
        print("                             authCounterMax, and whether a 32-slot sqnInit seed is present.")
        print("  PROVISION-AKA <out.der | IN-PLACE> [ALGORITHM=..] [KI=..] [OPC=..] [NUMBER-OF-KECCAK=..]")
        print("                             [AUTH-COUNTER-MAX=..] [SQN-INIT=..]")
        print("                             Tag-granular AKA provisioning. With only the output path it walks")
        print("                             the interactive wizard. Passing one or more NAME=VALUE overrides")
        print("                             switches to non-interactive mode (scripts / tests). IN-PLACE")
        print("                             targets the currently-selected input file.")
        print("  RANDOMIZE-AKA <out.der | IN-PLACE> [ALGORITHM=..] [INCLUDE-AUTH-COUNTER-MAX]")
        print("                             [INCLUDE-SQN-INIT]")
        print("                             Dev-only helper. Generates Ki (and OPc/TOPc plus numberOfKeccak")
        print("                             for TUAK) via secrets.token_bytes and applies them to the first")
        print("                             akaParameter PE. authCounterMax / sqnInit are skipped unless")
        print("                             explicitly included so replay-protection stays predictable.")
        print("  APPLY-TEMPLATE <template.json> <out.der> [ICCID=<digits|AUTO>] [IMSI=<digits|AUTO>] [VERIFY]")
        print("                             Materialise a tagged JSON template into a DER profile with typed")
        print("                             overrides. Mirrors GENERATE-PROFILE but with wizard-aware verbs.")
        print("  GENERATE-TEMPLATE <out.json> [ICCID=<digits>] [IMSI=<digits>]")
        print("                             Export the active profile as tagged JSON and optionally inject")
        print("                             typed placeholders for common fields. ICCID injects {ICCID}")
        print("                             in header.iccid and {ICCID_EF} in EF.ICCID; IMSI injects")
        print("                             {IMSI} in EF.IMSI. Custom tokens can still be added manually.")
        print("  GENERATE-PROFILE <template.json> <out.der> [NAME=value ...]")
        print("                             Build DER from a tagged JSON template with placeholder overrides.")
        print("                             ICCID=<digits> derives ICCID + ICCID_EF automatically;")
        print("                             IMSI=<digits> derives EF.IMSI bytes. Unknown tokens are")
        print("                             treated as raw hex overrides for manual placeholders.")
        print("  GENERATE-BATCH <template.json> <data_file> <out_dir>")
        print("                             Generate one DER profile per record from CSV / JSON / JSONL / YAML.")
        print("                             Each record must map placeholder names 1:1 to template tokens.")
        print("                             CSV headers or object keys become placeholder names directly.")
        print("                             Quote ICCID / IMSI values in JSON/YAML to preserve leading zeros.")
        print("  TOKENS <LIST|ADD|SET|REMOVE|RENAME|RETOKENISE-LENGTHS|EXPORT|APPLY|HELP> ...")
        print("                             Unified placeholder-token namespace. Flat aliases")
        print("                             (LIST-TOKENS, ADD-TOKEN, SET-TOKEN, REMOVE-TOKEN,")
        print("                             RENAME-TOKEN, RETOKENISE-LENGTHS, EXPORT-TOKENS,")
        print("                             APPLY-TOKENS) remain valid. Destructive commands")
        print("                             (REMOVE / RENAME / RETOKENISE-LENGTHS) accept")
        print("                             --dry-run and write <file>.bak by default. Full")
        print("                             reference: HELP TOKENS.")
        print("  SPLIT [output_prefix]      Run `split`.")
        print("  EXTRACT-APPS [dir] [CAP|IJC]")
        print("                             Run `extract-apps`.")
        print("  REMOVE-NAA <USIM|ISIM|CSIM> <output_file>")
        print("                             Run `remove-naa`.")
        print("  RAW <subcommand args...>   Pass a raw saip-tool subcommand after the input file.")
        print("  PWD                        Print current workspace root and selected input file.")
        print("  EXIT / Q                   Leave the SAIP Tool shell.")
        print("  QA                         Leave the SAIP Tool shell and exit YggdraSIM.")
        print("")
        print("  Examples:")
        print("    PROFILE-DIR Workspace/SAIP/profile")
        print("    TRANSCODE-DIR Workspace/SAIP/transcode")
        print("    USE reference_test_profile.txt")
        print("    DUMP ALL DECODED")
        print("    DUMP ALL DECODED > reports/decoded_dump.yaml")
        print("    DUMP ALL DECODED > reports/decoded_dump.json")
        print("    INSPECT")
        print("    ENCODE-JSON reports/saip_tagged.json reports/rebuilt.der")
        print("    PRESETS")
        print("    PRESETS USIM")
        print("    PREVIEW-PRESET USIM-ISIM")
        print("    DIFF-PRESET USIM FULL")
        print("    NEW-TEMPLATE reports/scaffold_template.json PRESET=USIM ICCID=89882000000000000012 IMSI=001010000000001")
        print("    NEW-TEMPLATE PRESET=MINIMAL")
        print("    NEW-PROFILE reports/scaffold_profile.der PRESET=MINIMAL")
        print("    NEW-PROFILE PRESET=USIM ICCID=AUTO IMSI=AUTO VERIFY")
        print("    LIST-AKA")
        print("    PROVISION-AKA reports/milenage.der ALGORITHM=milenage KI=00112233445566778899AABBCCDDEEFF OPC=000102030405060708090A0B0C0D0E0F")
        print("    PROVISION-AKA IN-PLACE ALGORITHM=tuak KI=" + "AA" * 32 + " OPC=" + "BB" * 32)
        print("    RANDOMIZE-AKA reports/dev_profile.der ALGORITHM=tuak INCLUDE-AUTH-COUNTER-MAX")
        print("    NEW-PROFILE-WIZARD")
        print("    APPLY-TEMPLATE reports/scaffold_template.json reports/apply_out.der ICCID=AUTO VERIFY")
        print("    GENERATE-TEMPLATE reports/profile_template.json ICCID=89882000000000000012 IMSI=001010000000001")
        print("    GENERATE-PROFILE reports/profile_template.json reports/profile.der ICCID=89882000000000000012")
        print("    GENERATE-BATCH reports/profile_template.json Workspace/SAIP/examples/saip_batch_data_template.yaml reports/generated_profiles")
        print("    EXPORT-TOKENS reports/profile_template.json")
        print("    APPLY-TOKENS reports/imported_template.json reports/imported_template.tokens.json")
        print("    LIST-TOKENS reports/profile_template.json")
        print("    ADD-TOKEN reports/profile_template.json KI DEADBEEFCAFED00DBABE0123456789AB")
        print("    SET-TOKEN reports/profile_template.json FILL '{\"zero_len\":16}'")
        print("    RENAME-TOKEN reports/profile_template.json ICCID ICC_PRIMARY")
        print("    RETOKENISE-LENGTHS reports/profile_template.json")
        print("    LINT")
        print("    LINT STRICT")
        print("    LINT HELP")
        print("    LINT PROFILES")
        print("    LINT PROFILE STRICT-FS")
        print("    LINT PROFILE RELEASE-GATE ENFORCE")
        print("    LINT METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json")
        print("    LINT GATE YRL-FIL,YRL-SVC")
        print("    LINT GATE YRL-FIL MIN-SCORE 90 FAIL-ON-WARN")
        print("    LINT GATE YRL-FIL,YRL-JCA ENFORCE > reports/profile_lint.json")
        print("    LINT STRICT METADATA Workspace/LocalSMDPP/profile/metadata/default_profile_metadata.json > reports/profile_lint.yaml")
        print("    EXTRACT-APPS tests/saip_apps IJC")
        print("    RAW extract-pe --pe-file tests/header.der --identification 4")
        print("")
        print(f"  {ShellStyle.BOLD}Subtopic help:{ShellStyle.END}")
        print("    HELP TOKENS    Placeholder tokens, sidecars, derived lengths, safety flags")
        print("    HELP TEMPLATE  Template authoring lifecycle: new/edit/generate/batch")
        print("    HELP EDIT      SAIP TUI shortcuts, decoded viewer, preview mode")
        print("    HELP LINT      Lint options, presets, gate suites (alias for LINT HELP)")
        print("    HELP TOPICS    Show this list again")
        print("    See also: guides/TEMPLATE_AND_TOKENS.md for the authoring walkthrough.")

    def _cmd_help_topics_list(self) -> None:
        print(f"\n{ShellStyle.BOLD}HELP subtopics:{ShellStyle.END}")
        print("  HELP            Full command surface (this list)")
        print("  HELP TOKENS     Token definition + sidecar commands")
        print("  HELP TEMPLATE   Template authoring workflow")
        print("  HELP EDIT       Profile editing in the SAIP TUI")
        print("  HELP LINT       Lint modes, gates, reports")
        print("")

    def _cmd_help_tokens(self, _arg: str) -> None:
        print(f"\n{ShellStyle.BOLD}Placeholder tokens -- reference{ShellStyle.END}")
        print("  Tokens let a SAIP JSON template carry symbolic values that resolve at build time.")
        print("  Definitions live at the document root under __ygg_token_defs__ and __ygg_placeholder_style__.")
        print("  Syntax:")
        print("    {NAME}   content expansion -- replaces with the resolved bytes")
        print("    {#NAME}  derived BER-TLV length of NAME (short form 0x00-0x7F, long form 0x81..0x84)")
        print("    [NAME] / [#NAME] are accepted when __ygg_placeholder_style__ is 'bracket'")
        print("")
        print("  Token value forms:")
        print("    hex string                   literal bytes, e.g. 89881111111111111112")
        print('    {"hex":"FF"}                 same, JSON object form')
        print('    {"zero_len":10}              a fixed-length block of 0x00 octets')
        print('    {"pattern_hex":"FF","byte_len":4}')
        print("                                 repeated pattern until byte_len is reached")
        print("")
        print(f"  {ShellStyle.BOLD}Commands (flat form -- still available){ShellStyle.END}")
        print("    LIST-TOKENS <file.json>                   Show defs with per-token ref counts")
        print("    ADD-TOKEN <file.json> <NAME> <VALUE>      Add a new def (fails if NAME exists)")
        print("    SET-TOKEN <file.json> <NAME> <VALUE>      Add or overwrite a def")
        print("    REMOVE-TOKEN <file.json> <NAME> [--dry-run] [--no-backup]")
        print("                                              Delete a def; prompts if still referenced")
        print("    RENAME-TOKEN <file.json> <OLD> <NEW> [<out.json>] [--dry-run] [--no-backup]")
        print("                                              Rename a def; offers to rewrite {OLD}/{#OLD}")
        print("    RETOKENISE-LENGTHS <template.json> [<out.json>] [--dry-run] [--no-backup]")
        print("                                              Rewrite <len>{NAME} → {#NAME}{NAME}")
        print("    EXPORT-TOKENS <template.json> [<sidecar.json>]")
        print("                                              Extract defs + style into a reusable sidecar")
        print("    APPLY-TOKENS <template.json> <sidecar.json> [<out.json>] [OVERWRITE]")
        print("                                              Merge a sidecar into a template")
        print("")
        print(f"  {ShellStyle.BOLD}Namespace form (discoverable via TAB){ShellStyle.END}")
        print("    TOKENS LIST <file.json>")
        print("    TOKENS ADD <file.json> <NAME> <VALUE>")
        print("    TOKENS SET <file.json> <NAME> <VALUE>")
        print("    TOKENS REMOVE <file.json> <NAME> [--dry-run] [--no-backup]")
        print("    TOKENS RENAME <file.json> <OLD> <NEW> [<out.json>] [--dry-run] [--no-backup]")
        print("    TOKENS RETOKENISE-LENGTHS <template.json> [<out.json>] [--dry-run] [--no-backup]")
        print("    TOKENS EXPORT <template.json> [<sidecar.json>]")
        print("    TOKENS APPLY <template.json> <sidecar.json> [<out.json>] [OVERWRITE]")
        print("    TOKENS HELP   (shortcut for this screen)")
        print("")
        print(f"  {ShellStyle.BOLD}Safety flags{ShellStyle.END}")
        print("    --dry-run     Show what the command would do, without writing anything.")
        print("    --no-backup   Skip the automatic .bak file when overwriting in place.")
        print("                  REMOVE / RENAME / RETOKENISE-LENGTHS write <file>.bak by default")
        print("                  whenever they overwrite their source document.")
        print("")
        print(f"  {ShellStyle.BOLD}Examples{ShellStyle.END}")
        print("    EXPORT-TOKENS reports/profile_template.json")
        print("    TOKENS LIST reports/profile_template.json")
        print("    TOKENS ADD reports/profile_template.json KI DEADBEEFCAFED00DBABE0123456789AB")
        print("    TOKENS SET reports/profile_template.json FILL '{\"zero_len\":16}'")
        print("    TOKENS RENAME reports/profile_template.json ICCID ICC_PRIMARY --dry-run")
        print("    TOKENS RETOKENISE-LENGTHS reports/profile_template.json --dry-run")
        print("    APPLY-TOKENS reports/imported_template.json reports/imported_template.tokens.json")
        print("")
        print("  See also: HELP TEMPLATE, guides/TEMPLATE_AND_TOKENS.md")

    def _cmd_help_template(self, _arg: str) -> None:
        print(f"\n{ShellStyle.BOLD}Template authoring -- reference{ShellStyle.END}")
        print("  A template is a tagged SAIP JSON document with __ygg_token_defs__ at the root.")
        print("  Authored tokens can be filled at build time, per record, or in the TUI.")
        print("")
        print(f"  {ShellStyle.BOLD}Author (pick one){ShellStyle.END}")
        print("    NEW-TEMPLATE [out.json] [PRESET=<name>] [ICCID=<digits|AUTO>] [IMSI=<digits|AUTO>]")
        print("                                  Scaffold a brand-new template from a preset PE sequence.")
        print("    NEW-PROFILE-WIZARD (WIZARD)  Tag-granular wizard; writes template or DER.")
        print("    GENERATE-TEMPLATE <out.json> [ICCID=<digits>] [IMSI=<digits>]")
        print("                                  Dump the active profile as tagged JSON with placeholder")
        print("                                  hints pre-injected for ICCID / IMSI.")
        print("")
        print(f"  {ShellStyle.BOLD}Edit / manage tokens{ShellStyle.END}")
        print("    HELP TOKENS                   Token reference (flat + namespace form)")
        print("    INSPECT / TUI                 Open the SAIP TUI (Ctrl+K token manager, Ctrl+R preview)")
        print("")
        print(f"  {ShellStyle.BOLD}Build / materialise{ShellStyle.END}")
        print("    APPLY-TEMPLATE <template.json> <out.der> [ICCID=..] [IMSI=..] [VERIFY]")
        print("                                  Materialise a template into a DER profile.")
        print("    GENERATE-PROFILE <template.json> <out.der> [NAME=value ...]")
        print("                                  Build a DER with free-form token overrides.")
        print("    GENERATE-BATCH <template.json> <data_file> <out_dir>")
        print("                                  One DER per record (CSV/JSON/JSONL/YAML).")
        print("")
        print(f"  {ShellStyle.BOLD}Sidecar lifecycle{ShellStyle.END}")
        print("    EXPORT-TOKENS template.json                # → template.tokens.json")
        print("    APPLY-TOKENS  template.json template.tokens.json   # merges defs back in")
        print("    On OPEN/USE the shell detects unresolved placeholders and offers to load")
        print("    a matching *.tokens.json sidecar interactively.")
        print("")
        print(f"  {ShellStyle.BOLD}Template mode + lint{ShellStyle.END}")
        print("    When a template has unresolved placeholders the lint harness enters template")
        print("    mode: FAIL/WARN findings that involve placeholder-bearing paths are demoted")
        print("    to INFO, and an INFO banner lists the unresolved tokens plus the exact")
        print("    APPLY-TOKENS command to materialise them.")
        print("")
        print("  See also: HELP TOKENS, HELP EDIT, guides/TEMPLATE_AND_TOKENS.md")

    def _cmd_help_edit(self, _arg: str) -> None:
        print(f"\n{ShellStyle.BOLD}Profile editing -- reference{ShellStyle.END}")
        print("  INSPECT (alias TUI) launches a Textual editor with JSON outline + DER hex +")
        print("  live lint + a read-only decoded viewer. All mutations re-encode DER on save (Ctrl+S).")
        print("  The decoded pane is a pure viewer in v1 -- structured field / service-table /")
        print("  raw-hex editing has moved to the V2 GUI (see guides/ARCHITECTURE.md).")
        print("")
        print(f"  {ShellStyle.BOLD}Global shortcuts{ShellStyle.END}")
        print("    Ctrl+S / F2      Save, re-encode, refresh JSON / DER / lint")
        print("    Ctrl+Q           Quit the TUI")
        print("    Ctrl+F           Focus the outline search")
        print("    Ctrl+L           Run lint on the current buffer")
        print("    F1               Keybind help")
        print("")
        print(f"  {ShellStyle.BOLD}Profile editing{ShellStyle.END}")
        print("    Ctrl+T           Tree action menu for the selected node")
        print("    Ctrl+A           Add a file under the selected FS/DF")
        print("    F3               Profile-element insert picker")
        print("    F11 / F12        Insert a PE after / before the selection")
        print("    Ctrl+↑ / Ctrl+↓  Move the selected PE up / down")
        print("    Ctrl+D           Remove the selected PE")
        print("    Ctrl+Y / P / B   Copy / paste-after / paste-before the PE clipboard")
        print("")
        print(f"  {ShellStyle.BOLD}Decoded viewer (read-only in v1){ShellStyle.END}")
        print("    The decoded pane follows the JSON cursor and renders the decoded payload")
        print("    for the selected field using the structured / service-table / raw-hex")
        print("    builders in Tools/ProfilePackage/saip_decoded_edit.py. No keybind commits")
        print("    back -- edits happen in the JSON editor and re-encode on Ctrl+S. Per-field")
        print("    decoded editing (previously Ctrl+E / Ctrl+Enter) is carved out to the V2 GUI.")
        print("")
        print(f"  {ShellStyle.BOLD}Templates + tokens{ShellStyle.END}")
        print("    Ctrl+K           Open the in-TUI token manager (list / add / rename /")
        print("                     set-value / delete). Rewrite-references confirmation")
        print("                     mirrors the shell RENAME-TOKEN flow.")
        print("    Ctrl+R           Toggle the resolved preview -- read-only view with every")
        print("                     {NAME}/{#NAME} expanded using the current defs. Banner")
        print("                     lists any unresolved tokens.")
        print("    Ctrl+Alt+N/P     Jump cursor to the next / previous placeholder. The HUD")
        print("                     strip above the editor summarises count, derived-length")
        print("                     companions, and how many remain unresolved.")
        print("")
        print(f"  {ShellStyle.BOLD}Views and panes{ShellStyle.END}")
        print("    F4               Inspect left mode (selection vs whole profile)")
        print("    F5 / F6          Cycle right pane / toggle outline pane")
        print("    F7               Cycle the color theme")
        print("    F8 / F9          Cycle bottom-left / bottom-right panes")
        print("    F10              Pane layout menu")
        print("")
        print("  See also: HELP TOKENS, HELP TEMPLATE, guides/TEMPLATE_AND_TOKENS.md")

    def _cmd_status(self, _arg: str) -> None:
        print(f"{ShellStyle.CYAN}[*] {self.bridge.describe_status()}{ShellStyle.END}")

    def _cmd_pwd(self, _arg: str) -> None:
        print(f"Workspace: {self.bridge.workspace_root}")
        current_file = self.bridge.current_input_file
        if current_file is None:
            print("Input: (not selected)")
            return
        print(f"Input: {current_file}")

    def _cmd_tool(self, arg: str) -> None:
        if len(arg.strip()) == 0:
            print(
                f"{ShellStyle.CYAN}[*] Tool command: "
                f"{self.bridge.describe_tool_command()}{ShellStyle.END}"
            )
            return

        tokens = self.bridge.set_tool_command(arg)
        print(f"{ShellStyle.GREEN}[+] Tool command set to: {' '.join(tokens)}{ShellStyle.END}")

    def _cmd_profile_dir(self, arg: str) -> None:
        if len(arg.strip()) == 0:
            print(f"{ShellStyle.CYAN}[*] Default profile dir: {self.bridge.default_profile_dir}{ShellStyle.END}")
            return

        selected = self.bridge.set_default_profile_dir(arg)
        self._startup_profiles = self.bridge.list_default_profiles()
        if len(self._startup_profiles) == 1:
            self.bridge.current_input_file = self._startup_profiles[0]
        print(f"{ShellStyle.GREEN}[+] Default profile dir set to: {selected}{ShellStyle.END}")
        if len(self._startup_profiles) > 0:
            print(f"{ShellStyle.CYAN}[*] Profiles in default dir:{ShellStyle.END}")
            for profile_path in self._startup_profiles:
                print(f"    - {profile_path.name}")
        if len(self._startup_profiles) == 1:
            print(
                f"{ShellStyle.GREEN}[+] Auto-loaded profile: "
                f"{self.bridge.current_input_file.name}{ShellStyle.END}"
            )

    def _cmd_transcode_dir(self, arg: str) -> None:
        if len(arg.strip()) == 0:
            print(
                f"{ShellStyle.CYAN}[*] Default transcode dir: "
                f"{self.bridge.default_transcode_dir}{ShellStyle.END}"
            )
            return

        selected = self.bridge.set_default_transcode_dir(arg)
        print(
            f"{ShellStyle.GREEN}[+] Default transcode dir set to: "
            f"{selected}{ShellStyle.END}"
        )

    def _cmd_use(self, arg: str) -> None:
        selected = self.bridge.set_input_file(arg)
        print(f"{ShellStyle.GREEN}[+] Active profile package: {selected}{ShellStyle.END}")
        self._maybe_prompt_for_token_sidecar(Path(selected))

    def _cmd_open(self, arg: str) -> None:
        if len(arg.strip()) > 0:
            self._cmd_use(arg)
            self._cmd_inspect("")
            return
        try:
            from .saip_open_picker_tui import pick_saip_profile_path_tui
        except ImportError as error:
            detail = str(error).strip() or error.__class__.__name__
            raise RuntimeError(
                f"OPEN needs Textual for the terminal picker: {detail}"
            ) from error
        try:
            selected = pick_saip_profile_path_tui(self.bridge)
        except RuntimeError as error:
            detail = str(error).strip() or error.__class__.__name__
            raise RuntimeError(
                f"{detail} Use OPEN <file> or USE <file> when the terminal picker cannot start."
            ) from error
        if selected is None:
            print(f"{ShellStyle.WARNING}[*] File selection cancelled.{ShellStyle.END}")
            return
        selected_path = self.bridge.set_input_file(str(selected))
        print(f"{ShellStyle.GREEN}[+] Active profile package: {selected_path}{ShellStyle.END}")
        self._maybe_prompt_for_token_sidecar(Path(selected_path))
        self._cmd_inspect("")

    def _maybe_prompt_for_token_sidecar(self, profile_path: Path) -> None:
        """Detect unresolved placeholders on JSON templates and offer sidecar merge.

        Runs only for ``.json`` inputs. When the template carries variable
        placeholders without matching ``__ygg_token_defs__`` entries, the
        user is walked through either loading the on-disk
        ``<stem>.tokens.json`` (if present) or supplying a custom sidecar
        path.
        """

        try:
            candidate = Path(profile_path)
        except (TypeError, ValueError):
            return
        suffix = candidate.suffix.lower()
        if suffix != ".json":
            return
        if candidate.is_file() is False:
            return
        try:
            raw_text = candidate.read_text(encoding="utf-8")
            loaded = json.loads(raw_text)
        except (OSError, json.JSONDecodeError):
            return
        if isinstance(loaded, dict) is False:
            return
        placeholder_names = sorted(extract_template_placeholder_names(loaded))
        if len(placeholder_names) == 0:
            return
        unresolved = template_has_unresolved_placeholders(loaded)
        if len(unresolved) == 0:
            return

        print(
            f"{ShellStyle.WARNING}[*] Template carries variable placeholders without defs: "
            f"{', '.join(unresolved)}{ShellStyle.END}"
        )
        sidecar_candidate = first_available_sidecar(candidate)
        if sidecar_candidate is None:
            tried = ", ".join(path.name for path in candidate_sidecar_paths(candidate))
            print(
                f"{ShellStyle.CYAN}[*] No token sidecar found (looked for: "
                f"{tried}). Provide one via APPLY-TOKENS or edit "
                f"__ygg_token_defs__ directly.{ShellStyle.END}"
            )
            return

        print(
            f"{ShellStyle.CYAN}[*] Token sidecar detected: "
            f"{sidecar_candidate}{ShellStyle.END}"
        )
        try:
            answer = self._input_fn(
                f"{ShellStyle.BLUE}[?] Merge sidecar into {candidate.name} "
                f"(in-place edit) [y/N]: {ShellStyle.END}"
            )
        except EOFError:
            print("")
            return
        answer_text = str(answer or "").strip().lower()
        if answer_text not in ("y", "yes"):
            print(
                f"{ShellStyle.CYAN}[*] Sidecar not loaded. Run APPLY-TOKENS "
                f"{candidate.name} {sidecar_candidate.name} to merge later.{ShellStyle.END}"
            )
            return
        try:
            sidecar = load_sidecar(sidecar_candidate)
            summaries = merge_sidecar_into_template(loaded, sidecar, overwrite=False)
        except TokenSidecarError as error:
            print(f"{ShellStyle.FAIL}[-] Sidecar merge failed: {error}{ShellStyle.END}")
            return
        try:
            candidate.write_text(
                json.dumps(loaded, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
        except OSError as error:
            print(
                f"{ShellStyle.FAIL}[-] Could not write merged template: "
                f"{error}{ShellStyle.END}"
            )
            return
        print(
            f"{ShellStyle.GREEN}[+] Merged {sidecar_candidate.name} into "
            f"{candidate.name}{ShellStyle.END}"
        )
        for summary in summaries:
            print(f"    - {summary}")
        still_unresolved = template_has_unresolved_placeholders(loaded)
        if len(still_unresolved) > 0:
            print(
                f"{ShellStyle.WARNING}[*] Still unresolved: "
                f"{', '.join(still_unresolved)}{ShellStyle.END}"
            )

    def _cmd_inspect(self, _arg: str) -> None:
        try:
            self.bridge.get_input_file()
        except ValueError as exc:
            print(f"{ShellStyle.FAIL}[-] {exc}{ShellStyle.END}")
        except Exception as exc:
            detail = str(exc).strip() or exc.__class__.__name__
            print(f"{ShellStyle.FAIL}[-] INSPECT failed: {detail}{ShellStyle.END}")
            print(
                f"{ShellStyle.WARNING}[*] Select a profile with OPEN or USE <file> first.{ShellStyle.END}"
            )
            return

        try:
            from .saip_transcode_tui import run_saip_transcode_tui

            run_saip_transcode_tui(self.bridge)
        except ImportError as exc:
            detail = str(exc).lower()
            if "textual" in detail:
                print(
                    f"{ShellStyle.FAIL}[-] Textual is required for INSPECT "
                    f"(pip install textual): {exc}{ShellStyle.END}"
                )
            elif "pysim" in detail:
                print(
                    f"{ShellStyle.FAIL}[-] INSPECT needs pySim. Install the PyPI "
                    f"wheel (pip install pySim) or clone the upstream tree at "
                    f"{self.bridge.workspace_root / 'pysim'} "
                    f"(git clone https://gitlab.com/osmocom/pysim.git pysim): "
                    f"{exc}{ShellStyle.END}"
                )
            else:
                print(f"{ShellStyle.FAIL}[-] INSPECT import failed: {exc}{ShellStyle.END}")
        except ValueError as exc:
            print(f"{ShellStyle.FAIL}[-] {exc}{ShellStyle.END}")

    def _cmd_transcode_tui(self, _arg: str) -> None:
        self._cmd_inspect(_arg)

    def _cmd_encode_json(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        if len(tokens) != 2:
            raise ValueError("Usage: ENCODE-JSON <input.json> <output.der>")

        from .saip_json_codec import (
            dejsonify_document,
            encode_der_from_document,
            ensure_workspace_pysim_on_path,
        )

        input_path = self.bridge.resolve_workspace_path(tokens[0], must_exist=True)
        output_path = self.bridge.resolve_workspace_path(tokens[1], must_exist=False)
        ensure_workspace_pysim_on_path(self.bridge.workspace_root)
        raw_text = input_path.read_text(encoding="utf-8")
        loaded = json.loads(raw_text)
        if isinstance(loaded, dict) is False:
            raise ValueError("Root JSON value must be an object.")
        document = dejsonify_document(loaded)
        der = encode_der_from_document(document, self.bridge.workspace_root)
        output_path.write_bytes(der)
        print(
            f"{ShellStyle.GREEN}[+] Wrote {len(der)} bytes DER to {output_path}{ShellStyle.END}"
        )

    def _split_preset_and_placeholder_tokens(
        self,
        tokens: list[str],
    ) -> tuple[str, list[str], bool]:
        preset_id = default_preset_id()
        verify_flag = False
        remaining: list[str] = []
        for raw_token in tokens:
            token_text = str(raw_token or "").strip()
            if len(token_text) == 0:
                continue
            upper_token = token_text.upper()
            if upper_token.startswith("PRESET="):
                preset_id = normalize_preset_id(token_text.split("=", 1)[1])
                continue
            if upper_token.startswith("VERIFY="):
                verify_flag = self._parse_on_off_flag(token_text.split("=", 1)[1])
                continue
            if upper_token == "VERIFY":
                verify_flag = True
                continue
            remaining.append(token_text)
        return preset_id, remaining, verify_flag

    @staticmethod
    def _looks_like_scaffold_keyword(raw_token: str) -> bool:
        cleaned = str(raw_token or "").strip()
        if len(cleaned) == 0:
            return False
        if "=" in cleaned:
            keyword = cleaned.split("=", 1)[0].upper()
            return keyword in {"PRESET", "VERIFY", "ICCID", "IMSI"}
        return cleaned.upper() == "VERIFY"

    @staticmethod
    def _parse_on_off_flag(raw_value: str) -> bool:
        cleaned = str(raw_value or "").strip().upper()
        if cleaned in ("1", "ON", "TRUE", "YES", "Y"):
            return True
        if cleaned in ("0", "OFF", "FALSE", "NO", "N", ""):
            return False
        raise ValueError(
            f"Expected on/off boolean token (got {raw_value!r})."
        )

    def _resolve_scaffold_output_path(
        self,
        first_token: str | None,
        preset_id: str,
        extension: str,
    ) -> Path:
        if first_token is not None and len(first_token.strip()) > 0:
            return self.bridge.resolve_workspace_path(first_token, must_exist=False)
        default_dir = self.bridge.default_profile_dir
        candidate = resolve_default_scaffold_output_path(
            preset_id,
            extension,
            default_dir,
        )
        return self.bridge.resolve_workspace_path(
            str(candidate),
            must_exist=False,
        )

    def _expand_auto_placeholder_values(
        self,
        assignments: dict[str, str],
    ) -> dict[str, str]:
        resolved, auto_summaries = resolve_auto_assignments(assignments)
        if len(auto_summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] AUTO value expansion:{ShellStyle.END}")
            for summary in auto_summaries:
                print(f"    - {summary}")
        return resolved

    def _cmd_presets(self, arg: str) -> None:
        cleaned = str(arg or "").strip()
        if len(cleaned) == 0:
            self._render_presets_overview()
            return
        tokens = shlex.split(cleaned)
        if len(tokens) > 1:
            raise ValueError(
                "Usage: PRESETS [preset_id]. Provide at most one preset id."
            )
        self._render_preset_detail(tokens[0])

    def _render_presets_overview(self) -> None:
        presets = list_profile_presets()
        default_id = default_preset_id()
        print(f"{ShellStyle.HEADER}=== Profile presets ==={ShellStyle.END}")
        for preset in presets:
            marker = ""
            if preset.preset_id == default_id:
                marker = f" {ShellStyle.GREEN}(default){ShellStyle.END}"
            origin_tag = ""
            if preset.source != "builtin":
                origin_tag = f" {ShellStyle.CYAN}[{preset.source}]{ShellStyle.END}"
            print(
                f"  {ShellStyle.BOLD}{preset.preset_id}{ShellStyle.END}{marker}"
                f"{origin_tag}"
            )
            print(f"    {preset.description}")
            pe_list_text = " -> ".join(preset.menu_ids)
            print(f"    PEs: {pe_list_text}")
        print(
            f"\n{ShellStyle.CYAN}[*] Detail view: PRESETS <id> "
            f"(e.g. PRESETS USIM){ShellStyle.END}"
        )

    def _render_preset_detail(self, raw_preset_id: str) -> None:
        description = describe_preset(raw_preset_id)
        preset_id = description["preset_id"]
        print(
            f"{ShellStyle.HEADER}=== Preset detail: "
            f"{preset_id} ==={ShellStyle.END}"
        )
        print(f"  Source:      {description['source']}")
        print(f"  Description: {description['description']}")
        print(f"  PE count:    {description['pe_count']}")
        placeholders = description["placeholders"]
        if len(placeholders) == 0:
            placeholder_text = "(none)"
        else:
            placeholder_text = ", ".join(placeholders)
        print(f"  Typed placeholders: {placeholder_text}")
        print("  PE sequence:")
        for index, entry in enumerate(description["pes"], start=1):
            menu_id = entry["menu_id"]
            hint = entry["description"]
            print(f"    {index:2d}. {menu_id:<24}  {hint}")

    def _cmd_preview_preset(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) == 0:
            raise ValueError("Usage: PREVIEW-PRESET <preset_id>")
        if len(tokens) > 1:
            raise ValueError(
                "PREVIEW-PRESET accepts a single preset id. "
                "Use DIFF-PRESET to compare two presets."
            )
        preset = get_preset(tokens[0])
        print(
            f"{ShellStyle.HEADER}=== Preview: {preset.preset_id} ==={ShellStyle.END}"
        )
        print(f"  {preset.description}")
        print("")
        print("  ProfileElementSequence")
        for index, menu_id in enumerate(preset.menu_ids):
            is_last = index == len(preset.menu_ids) - 1
            branch = "└── " if is_last else "├── "
            print(f"  {branch}[{index + 1:02d}] {menu_id}")
        placeholders = list_preset_placeholders(preset.preset_id)
        print("")
        if len(placeholders) == 0:
            print("  Typed placeholders: (none)")
        else:
            print(
                f"  Typed placeholders available: {', '.join(placeholders)}"
            )
        print(
            f"\n{ShellStyle.CYAN}[*] No files written. "
            f"Run NEW-PROFILE / NEW-TEMPLATE to materialise.{ShellStyle.END}"
        )

    def _cmd_diff_preset(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) != 2:
            raise ValueError("Usage: DIFF-PRESET <preset_a> <preset_b>")
        diff = diff_presets(tokens[0], tokens[1])
        print(
            f"{ShellStyle.HEADER}=== Preset diff: "
            f"{diff.preset_a_id} vs {diff.preset_b_id} ==={ShellStyle.END}"
        )
        print(
            f"  Only in {diff.preset_a_id}: "
            f"{', '.join(diff.only_in_a) if len(diff.only_in_a) > 0 else '(none)'}"
        )
        print(
            f"  Only in {diff.preset_b_id}: "
            f"{', '.join(diff.only_in_b) if len(diff.only_in_b) > 0 else '(none)'}"
        )
        print(
            f"  Common:       "
            f"{', '.join(diff.common) if len(diff.common) > 0 else '(none)'}"
        )
        if diff.order_changed is True:
            print(
                f"  {ShellStyle.WARNING}[!] Common PEs differ in order between "
                f"presets.{ShellStyle.END}"
            )

    def _cmd_diff(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        show_values = True
        files: list[str] = []
        for token in tokens:
            if token.upper() in ("--NO-VALUES", "NO-VALUES"):
                show_values = False
                continue
            files.append(token)
        if len(files) != 2:
            raise ValueError(
                "Usage: DIFF <profile_a> <profile_b> [NO-VALUES]\n"
                "       Accepts transcode JSON, SIMCARD profile manifests, or SAIP DER."
            )
        from .saip_diff_engine import diff_saip_documents, format_diff_text
        from .saip_diff_loader import (
            SaipDiffLoadError,
            load_two_profile_documents,
        )

        path_a = Path(os.path.expanduser(files[0])).resolve()
        path_b = Path(os.path.expanduser(files[1])).resolve()
        try:
            loaded_a, loaded_b = load_two_profile_documents(
                path_a,
                path_b,
                workspace_root=self.bridge.workspace_root,
            )
        except SaipDiffLoadError as error:
            print(f"{ShellStyle.FAIL}[-] DIFF load failed: {error}{ShellStyle.END}")
            return
        summary = diff_saip_documents(loaded_a.document, loaded_b.document)
        print(
            f"{ShellStyle.HEADER}=== SAIP diff ==={ShellStyle.END}\n"
            f"  A: {loaded_a.source_path}  [{loaded_a.shape}]\n"
            f"  B: {loaded_b.source_path}  [{loaded_b.shape}]"
        )
        if summary.is_empty is True:
            print(f"{ShellStyle.GREEN}[+] No differences detected.{ShellStyle.END}")
            return
        rendered = format_diff_text(summary, show_values=show_values)
        for raw_line in rendered.splitlines():
            if raw_line.startswith("#"):
                print(f"{ShellStyle.CYAN}{raw_line}{ShellStyle.END}")
                continue
            if raw_line.startswith("+ "):
                print(f"{ShellStyle.GREEN}{raw_line}{ShellStyle.END}")
                continue
            if raw_line.startswith("- "):
                print(f"{ShellStyle.FAIL}{raw_line}{ShellStyle.END}")
                continue
            if raw_line.startswith("~ "):
                print(f"{ShellStyle.WARNING}{raw_line}{ShellStyle.END}")
                continue
            if raw_line.startswith("> "):
                print(f"{ShellStyle.BLUE}{raw_line}{ShellStyle.END}")
                continue
            print(raw_line)

    def _cmd_watch_simcard(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        forwarded: list[str] = []
        poll_interval = 2.0
        max_arrivals = 0
        store_root_override = ""
        launcher_template = ""
        index = 0
        while index < len(tokens):
            token = tokens[index]
            upper_token = token.upper()
            if upper_token == "POLL" and index + 1 < len(tokens):
                poll_interval = float(tokens[index + 1])
                index += 2
                continue
            if upper_token == "MAX" and index + 1 < len(tokens):
                max_arrivals = int(tokens[index + 1])
                index += 2
                continue
            if upper_token == "STORE" and index + 1 < len(tokens):
                store_root_override = tokens[index + 1]
                index += 2
                continue
            if upper_token == "LAUNCHER" and index + 1 < len(tokens):
                launcher_template = tokens[index + 1]
                index += 2
                continue
            if upper_token == "HELP":
                print(
                    "Usage: WATCH-SIMCARD [STORE <dir>] [POLL <seconds>] "
                    "[MAX <n>] [LAUNCHER <template>]\n"
                    "       Tails the simulator profile store and spawns a launcher\n"
                    "       when a new ICCID lands. Default launcher opens the profile\n"
                    "       in the profile-package shell (USE; INFO; TREE; EXIT).\n"
                    "       LAUNCHER template placeholders: {iccid}, {profile},\n"
                    "       {profile_path}, {profile_dir}, {manifest}, {python}.\n"
                    "       MAX <n> exits after N arrivals (0 = run until Ctrl+C)."
                )
                return
            forwarded.append(token)
            index += 1

        from .simcard_watch import run_cli as watch_run_cli

        cli_args: list[str] = []
        if len(store_root_override) > 0:
            cli_args.extend(["--store-root", store_root_override])
        cli_args.extend(
            [
                "--workspace-root",
                str(self.bridge.workspace_root),
                "--poll-interval",
                str(poll_interval),
                "--max-arrivals",
                str(max_arrivals),
            ]
        )
        if len(launcher_template) > 0:
            cli_args.extend(["--launcher", launcher_template])
        cli_args.extend(forwarded)

        return_code = watch_run_cli(cli_args)
        if return_code not in (0, 130):
            print(
                f"{ShellStyle.FAIL}[-] WATCH-SIMCARD exited with status "
                f"{return_code}.{ShellStyle.END}"
            )

    def _cmd_diff_tui(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) != 2:
            raise ValueError(
                "Usage: DIFF-TUI <profile_a> <profile_b>\n"
                "       Opens a Textual side-by-side diff view. Requires the `textual` extra."
            )
        from .saip_diff_tui import run_cli

        return_code = run_cli(
            [tokens[0], tokens[1], "--workspace-root", str(self.bridge.workspace_root)]
        )
        if return_code != 0:
            print(
                f"{ShellStyle.FAIL}[-] DIFF-TUI exited with status "
                f"{return_code}.{ShellStyle.END}"
            )

    def _cmd_new_template(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        first_token: str | None = None
        rest_tokens: list[str] = list(tokens)
        if len(tokens) > 0 and self._looks_like_scaffold_keyword(tokens[0]) is False:
            first_token = tokens[0]
            rest_tokens = tokens[1:]
        preset_id, placeholder_tokens, _verify_flag = (
            self._split_preset_and_placeholder_tokens(rest_tokens)
        )

        output_path = self._resolve_scaffold_output_path(
            first_token,
            preset_id,
            "json",
        )
        assignments_raw = parse_placeholder_assignment_tokens(placeholder_tokens)
        assignments = self._expand_auto_placeholder_values(assignments_raw)

        document = build_scaffold_profile_document(
            preset_id,
            self.bridge.workspace_root,
        )
        tagged, summaries = build_placeholder_template_document(document, assignments)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(tagged, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            f"{ShellStyle.GREEN}[+] Scaffolded {preset_id} template written to: "
            f"{output_path}{ShellStyle.END}"
        )
        if len(summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] Placeholder injection summary:{ShellStyle.END}")
            for summary in summaries:
                print(f"    - {summary}")

    def _cmd_new_profile(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        first_token: str | None = None
        rest_tokens: list[str] = list(tokens)
        if len(tokens) > 0 and self._looks_like_scaffold_keyword(tokens[0]) is False:
            first_token = tokens[0]
            rest_tokens = tokens[1:]
        preset_id, placeholder_tokens, verify_flag = (
            self._split_preset_and_placeholder_tokens(rest_tokens)
        )

        output_path = self._resolve_scaffold_output_path(
            first_token,
            preset_id,
            "der",
        )
        assignments_raw = parse_placeholder_assignment_tokens(placeholder_tokens)
        assignments = self._expand_auto_placeholder_values(assignments_raw)

        self._materialise_scaffold_der(
            preset_id=preset_id,
            menu_ids=None,
            assignments=assignments,
            output_path=output_path,
            verify=verify_flag,
        )

    def _materialise_scaffold_der(
        self,
        preset_id: str,
        menu_ids: tuple[str, ...] | None,
        assignments: dict[str, str],
        output_path: Path,
        verify: bool,
    ) -> None:
        from .saip_json_codec import (
            encode_der_from_document,
            ensure_workspace_pysim_on_path,
        )

        if menu_ids is None:
            document = build_scaffold_profile_document(
                preset_id,
                self.bridge.workspace_root,
            )
        else:
            document = build_scaffold_profile_document_from_menu_ids(
                preset_id,
                menu_ids,
                self.bridge.workspace_root,
            )

        ensure_workspace_pysim_on_path(self.bridge.workspace_root)
        if len(assignments) > 0:
            from .saip_json_codec import dejsonify_document

            tagged, summaries = build_placeholder_template_document(document, assignments)
            encode_document = dejsonify_document(tagged)
        else:
            summaries = []
            encode_document = document

        der = encode_der_from_document(encode_document, self.bridge.workspace_root)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(der)
        print(
            f"{ShellStyle.GREEN}[+] Scaffolded {preset_id} profile ({len(der)} bytes DER) "
            f"written to: {output_path}{ShellStyle.END}"
        )
        if len(summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] Placeholder override summary:{ShellStyle.END}")
            for summary in summaries:
                print(f"    - {summary}")

        self.bridge.current_input_file = output_path
        print(
            f"{ShellStyle.CYAN}[*] Active input set to scaffolded profile: "
            f"{output_path.name}{ShellStyle.END}"
        )

        if verify is True:
            self._verify_scaffolded_der(output_path)

    def _verify_scaffolded_der(self, der_path: Path) -> None:
        try:
            from .saip_json_codec import ensure_workspace_pysim_on_path

            ensure_workspace_pysim_on_path(self.bridge.workspace_root)
            from pySim.esim.saip import ProfileElementSequence

            der_bytes = der_path.read_bytes()
            pes = ProfileElementSequence.from_der(der_bytes)
            pe_count = len(pes.pe_list)
            type_tally: dict[str, int] = {}
            for pe in pes.pe_list:
                key = str(pe.type)
                type_tally[key] = type_tally.get(key, 0) + 1
            tally_parts = [f"{name}={count}" for name, count in type_tally.items()]
            print(
                f"{ShellStyle.GREEN}[+] VERIFY: decoded {pe_count} PEs -> "
                f"{', '.join(tally_parts)}{ShellStyle.END}"
            )
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            print(
                f"{ShellStyle.FAIL}[-] VERIFY failed to round-trip "
                f"{der_path.name}: {detail}{ShellStyle.END}"
            )

    def _cmd_apply_template(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) < 2:
            raise ValueError(
                "Usage: APPLY-TEMPLATE <template.json> <out.der> "
                "[ICCID=<digits>] [IMSI=<digits>] [VERIFY]"
            )

        from .saip_json_codec import (
            dejsonify_document,
            encode_der_from_document,
            ensure_workspace_pysim_on_path,
        )

        template_path = self.bridge.resolve_workspace_path(tokens[0], must_exist=True)
        output_path = self.bridge.resolve_workspace_path(tokens[1], must_exist=False)
        _preset_id, override_tokens, verify_flag = (
            self._split_preset_and_placeholder_tokens(tokens[2:])
        )
        assignments_raw = parse_placeholder_assignment_tokens(override_tokens)
        assignments = self._expand_auto_placeholder_values(assignments_raw)

        ensure_workspace_pysim_on_path(self.bridge.workspace_root)
        raw_text = template_path.read_text(encoding="utf-8")
        loaded = json.loads(raw_text)
        if isinstance(loaded, dict) is False:
            raise ValueError("Template root JSON value must be an object.")
        summaries = apply_placeholder_overrides_to_loaded_document(loaded, assignments)
        document = dejsonify_document(loaded)
        der = encode_der_from_document(document, self.bridge.workspace_root)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(der)
        print(
            f"{ShellStyle.GREEN}[+] Wrote {len(der)} bytes DER to "
            f"{output_path}{ShellStyle.END}"
        )
        if len(summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] Placeholder override summary:{ShellStyle.END}")
            for summary in summaries:
                print(f"    - {summary}")

        self.bridge.current_input_file = output_path
        print(
            f"{ShellStyle.CYAN}[*] Active input set to materialised profile: "
            f"{output_path.name}{ShellStyle.END}"
        )

        if verify_flag is True:
            self._verify_scaffolded_der(output_path)

    def _cmd_export_tokens(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) < 1 or len(tokens) > 2:
            raise ValueError(
                "Usage: EXPORT-TOKENS <template.json> [<sidecar.json>]"
            )
        template_path = self.bridge.resolve_workspace_path(tokens[0], must_exist=True)
        if len(tokens) == 2:
            sidecar_path = self.bridge.resolve_workspace_path(
                tokens[1], must_exist=False
            )
        else:
            sidecar_path = default_sidecar_path_for(template_path)

        raw_text = template_path.read_text(encoding="utf-8")
        try:
            loaded = json.loads(raw_text)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Template {template_path.name} is not valid JSON: {error}"
            ) from error
        try:
            payload = build_sidecar_from_template(
                loaded,
                source_label=template_path.name,
            )
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error

        defs = payload.get("__ygg_token_defs__", {})
        if isinstance(defs, dict) is False:
            defs = {}
        style = str(payload.get("__ygg_placeholder_style__", "brace"))
        write_sidecar(
            sidecar_path,
            style=style,
            token_defs=defs,
            source_label=template_path.name,
        )
        print(
            f"{ShellStyle.GREEN}[+] Wrote {len(defs)} token defs to "
            f"{sidecar_path}{ShellStyle.END}"
        )
        placeholder_names = sorted(extract_template_placeholder_names(loaded))
        if len(placeholder_names) > 0:
            print(
                f"{ShellStyle.CYAN}[*] Template placeholders: "
                f"{', '.join(placeholder_names)}{ShellStyle.END}"
            )
        unresolved = template_has_unresolved_placeholders(loaded)
        if len(unresolved) > 0:
            print(
                f"{ShellStyle.WARNING}[*] Placeholders without defs in template: "
                f"{', '.join(unresolved)}{ShellStyle.END}"
            )

    def _cmd_apply_tokens(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) < 2 or len(tokens) > 4:
            raise ValueError(
                "Usage: APPLY-TOKENS <template.json> <sidecar.json> "
                "[<output.json>] [OVERWRITE]"
            )
        overwrite_flag = False
        positional: list[str] = []
        for token in tokens:
            token_text = str(token or "").strip()
            if token_text.upper() == "OVERWRITE":
                overwrite_flag = True
                continue
            positional.append(token_text)
        if len(positional) < 2:
            raise ValueError(
                "APPLY-TOKENS requires at least <template.json> <sidecar.json>."
            )

        template_path = self.bridge.resolve_workspace_path(
            positional[0], must_exist=True
        )
        sidecar_path = self.bridge.resolve_workspace_path(
            positional[1], must_exist=True
        )
        if len(positional) == 3:
            output_path = self.bridge.resolve_workspace_path(
                positional[2], must_exist=False
            )
        else:
            output_path = template_path

        raw_text = template_path.read_text(encoding="utf-8")
        try:
            loaded = json.loads(raw_text)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Template {template_path.name} is not valid JSON: {error}"
            ) from error
        if isinstance(loaded, dict) is False:
            raise ValueError("Template root JSON value must be an object.")

        try:
            sidecar = load_sidecar(sidecar_path)
            summaries = merge_sidecar_into_template(
                loaded,
                sidecar,
                overwrite=overwrite_flag,
            )
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(loaded, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            f"{ShellStyle.GREEN}[+] Merged sidecar {sidecar_path.name} into "
            f"{output_path.name}{ShellStyle.END}"
        )
        for summary in summaries:
            print(f"    - {summary}")
        unresolved = template_has_unresolved_placeholders(loaded)
        if len(unresolved) > 0:
            print(
                f"{ShellStyle.WARNING}[*] Remaining placeholders without defs: "
                f"{', '.join(unresolved)}{ShellStyle.END}"
            )
        else:
            print(
                f"{ShellStyle.CYAN}[*] All template placeholders now have defs.{ShellStyle.END}"
            )

    _TOKEN_SUBCOMMANDS: dict[str, str] = {
        "LIST": "_cmd_list_tokens",
        "ADD": "_cmd_add_token",
        "SET": "_cmd_set_token",
        "REMOVE": "_cmd_remove_token",
        "DELETE": "_cmd_remove_token",
        "RENAME": "_cmd_rename_token",
        "RETOKENISE-LENGTHS": "_cmd_retokenise_lengths",
        "RETOKENIZE-LENGTHS": "_cmd_retokenise_lengths",
        "RETOKENISE": "_cmd_retokenise_lengths",
        "RETOKENIZE": "_cmd_retokenise_lengths",
        "EXPORT": "_cmd_export_tokens",
        "EXPORT-SIDECAR": "_cmd_export_tokens",
        "APPLY": "_cmd_apply_tokens",
        "APPLY-SIDECAR": "_cmd_apply_tokens",
        "HELP": "_cmd_help_tokens",
    }

    def _cmd_tokens(self, arg: str) -> None:
        """Unified TOKENS namespace dispatcher.

        Usage: TOKENS <subcommand> [<args>...]

        Subcommand aliases keep every flat command (``LIST-TOKENS``,
        ``ADD-TOKEN``, ...) working verbatim -- this namespace is purely a
        discoverability layer.
        """

        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) == 0:
            self._cmd_help_tokens("")
            return
        sub = tokens[0].upper()
        handler_name = self._TOKEN_SUBCOMMANDS.get(sub)
        if handler_name is None:
            names = ", ".join(sorted(set(self._TOKEN_SUBCOMMANDS.keys())))
            raise ValueError(
                f"Unknown TOKENS subcommand: {sub}. "
                f"Known subcommands: {names}. Try TOKENS HELP."
            )
        handler = getattr(self, handler_name)
        rest = " ".join(shlex.quote(t) for t in tokens[1:])
        handler(rest)

    def _load_token_host_document(self, raw_path: str) -> tuple[Path, dict]:
        """Resolve ``raw_path``, load its JSON, validate it is an object."""

        path = self.bridge.resolve_workspace_path(raw_path, must_exist=True)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as error:
            raise ValueError(f"Cannot read {path}: {error}") from error
        try:
            loaded = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"{path.name} is not valid JSON: {error}"
            ) from error
        if isinstance(loaded, dict) is False:
            raise ValueError(
                f"{path.name}: root JSON value must be an object."
            )
        return path, loaded

    def _write_token_host_document(
        self,
        output_path: Path,
        document: dict,
        *,
        backup: bool = False,
    ) -> Path | None:
        """Write ``document`` to ``output_path``.

        When ``backup`` is true and ``output_path`` already exists, the old
        contents are copied to ``output_path.with_suffix(output_path.suffix + '.bak')``
        before the new content is written. Returns the backup path (or
        ``None`` if no backup was created).
        """

        output_path.parent.mkdir(parents=True, exist_ok=True)
        backup_path: Path | None = None
        if backup is True and output_path.exists():
            try:
                original = output_path.read_bytes()
            except OSError as error:
                raise ValueError(
                    f"Cannot create backup for {output_path}: {error}"
                ) from error
            backup_path = output_path.with_suffix(output_path.suffix + ".bak")
            backup_path.write_bytes(original)
        output_path.write_text(
            json.dumps(document, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return backup_path

    @staticmethod
    def _extract_flag(tokens: list[str], flag: str) -> tuple[list[str], bool]:
        """Return (tokens-minus-flag, flag_present)."""

        filtered: list[str] = []
        present = False
        for token in tokens:
            if token == flag:
                present = True
                continue
            filtered.append(token)
        return filtered, present

    def _cmd_list_tokens(self, arg: str) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) != 1:
            raise ValueError("Usage: LIST-TOKENS <template_or_sidecar.json>")
        path, loaded = self._load_token_host_document(tokens[0])
        try:
            defs = list_token_definitions(loaded)
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error
        style = str(loaded.get("__ygg_placeholder_style__", "brace")).strip() or "brace"
        print(
            f"{ShellStyle.CYAN}[*] Tokens in {path.name} "
            f"(style='{style}', {len(defs)} entries){ShellStyle.END}"
        )
        if len(defs) == 0:
            print("    (no __ygg_token_defs__ entries)")
            return
        name_width = max(len(name) for name in defs.keys())
        for name in sorted(defs.keys()):
            refs = count_token_references(loaded, name)
            value = defs[name]
            if isinstance(value, dict):
                value_repr = json.dumps(value, ensure_ascii=False)
            else:
                value_repr = str(value)
            print(
                f"    {name.ljust(name_width)}  content={refs['content']:>3} "
                f"length={refs['length']:>3}  {value_repr}"
            )

    def _cmd_add_token(self, arg: str) -> None:
        self._run_token_set_command(arg, allow_overwrite=False, verb="ADD-TOKEN")

    def _cmd_set_token(self, arg: str) -> None:
        self._run_token_set_command(arg, allow_overwrite=True, verb="SET-TOKEN")

    def _run_token_set_command(
        self,
        arg: str,
        *,
        allow_overwrite: bool,
        verb: str,
    ) -> None:
        tokens = shlex.split(str(arg or "").strip())
        if len(tokens) != 3:
            raise ValueError(
                f"Usage: {verb} <file.json> <NAME> <VALUE>\n"
                "       VALUE may be a hex string (e.g. 89881111111111111112)\n"
                "       or a JSON object (e.g. '{\"zero_len\":10}')."
            )
        path, loaded = self._load_token_host_document(tokens[0])
        name_arg = tokens[1]
        value_arg = tokens[2]
        try:
            value = parse_token_value_argument(value_arg)
            created, previous = set_token_definition(
                loaded,
                name_arg,
                value,
                overwrite=allow_overwrite,
            )
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error

        if created is False and allow_overwrite is False:
            raise ValueError(
                f"Token {name_arg!r} already exists. Use SET-TOKEN to replace."
            )

        self._write_token_host_document(path, loaded)
        if created:
            print(
                f"{ShellStyle.GREEN}[+] Added token {name_arg} to {path.name}"
                f"{ShellStyle.END}"
            )
        else:
            prev_repr = json.dumps(previous, ensure_ascii=False) if previous is not None else "<unset>"
            print(
                f"{ShellStyle.GREEN}[+] Updated token {name_arg} in {path.name}"
                f"{ShellStyle.END}"
            )
            print(f"    previous value: {prev_repr}")
        remaining = count_token_references(loaded, name_arg)
        if remaining["total"] > 0:
            print(
                f"    references in this file: "
                f"content={remaining['content']} length={remaining['length']}"
            )

    def _cmd_remove_token(self, arg: str) -> None:
        raw_tokens = shlex.split(str(arg or "").strip())
        raw_tokens, dry_run = self._extract_flag(raw_tokens, "--dry-run")
        raw_tokens, no_backup = self._extract_flag(raw_tokens, "--no-backup")
        if len(raw_tokens) != 2:
            raise ValueError(
                "Usage: REMOVE-TOKEN <file.json> <NAME> [--dry-run] [--no-backup]"
            )
        path, loaded = self._load_token_host_document(raw_tokens[0])
        try:
            refs = count_token_references(loaded, raw_tokens[1])
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error
        if refs["total"] > 0:
            print(
                f"{ShellStyle.WARNING}[*] {raw_tokens[1]} has "
                f"{refs['content']} content and {refs['length']} length "
                f"reference(s) in {path.name}.{ShellStyle.END}"
            )
            if dry_run is False:
                try:
                    confirm = self._input_fn(
                        f"{ShellStyle.BLUE}[?] Remove anyway (references become "
                        f"unresolved) [y/N]: {ShellStyle.END}"
                    )
                except EOFError:
                    print("")
                    return
                if str(confirm or "").strip().lower() not in ("y", "yes"):
                    print(
                        f"{ShellStyle.CYAN}[*] REMOVE-TOKEN cancelled.{ShellStyle.END}"
                    )
                    return
        try:
            removed = remove_token_definition(loaded, raw_tokens[1])
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error
        if removed is None:
            print(
                f"{ShellStyle.WARNING}[*] Token {raw_tokens[1]} not found in "
                f"{path.name}.{ShellStyle.END}"
            )
            return
        removed_repr = (
            json.dumps(removed, ensure_ascii=False)
            if isinstance(removed, dict)
            else str(removed)
        )
        if dry_run:
            print(
                f"{ShellStyle.CYAN}[*] Dry-run: would remove token "
                f"{raw_tokens[1]} from {path.name}{ShellStyle.END}"
            )
            print(f"    previous value: {removed_repr}")
            if refs["total"] > 0:
                print(
                    f"    {refs['content']} content + {refs['length']} length "
                    "reference(s) would be left unresolved."
                )
            return
        backup_path = self._write_token_host_document(
            path, loaded, backup=not no_backup,
        )
        print(
            f"{ShellStyle.GREEN}[+] Removed token {raw_tokens[1]} from "
            f"{path.name}{ShellStyle.END}"
        )
        print(f"    previous value: {removed_repr}")
        if backup_path is not None:
            print(f"    backup written to {backup_path.name}")

    def _cmd_rename_token(self, arg: str) -> None:
        raw_tokens = shlex.split(str(arg or "").strip())
        raw_tokens, dry_run = self._extract_flag(raw_tokens, "--dry-run")
        raw_tokens, no_backup = self._extract_flag(raw_tokens, "--no-backup")
        if len(raw_tokens) < 3 or len(raw_tokens) > 4:
            raise ValueError(
                "Usage: RENAME-TOKEN <file.json> <OLD> <NEW> [<output.json>] "
                "[--dry-run] [--no-backup]"
            )
        path, loaded = self._load_token_host_document(raw_tokens[0])
        old_name = raw_tokens[1]
        new_name = raw_tokens[2]
        if len(raw_tokens) == 4:
            output_path = self.bridge.resolve_workspace_path(
                raw_tokens[3], must_exist=False
            )
        else:
            output_path = path

        try:
            refs = count_token_references(loaded, old_name)
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error
        rewrite = refs["total"] > 0
        if refs["total"] == 0:
            rewrite = False
        else:
            print(
                f"{ShellStyle.CYAN}[*] {old_name} has {refs['content']} content "
                f"and {refs['length']} length reference(s) in {path.name}."
                f"{ShellStyle.END}"
            )
            if dry_run:
                rewrite = True
            else:
                try:
                    confirm = self._input_fn(
                        f"{ShellStyle.BLUE}[?] Auto-rewrite all references "
                        f"{{{old_name}}} → {{{new_name}}} (and {{#{old_name}}} → "
                        f"{{#{new_name}}}) [Y/n]: {ShellStyle.END}"
                    )
                except EOFError:
                    print("")
                    return
                answer = str(confirm or "").strip().lower()
                rewrite = answer in ("", "y", "yes")

        try:
            summary = rename_token_in_template(
                loaded,
                old_name,
                new_name,
                rewrite_references=rewrite,
            )
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error
        if summary["renamed_def"] is False:
            print(
                f"{ShellStyle.WARNING}[*] Token {old_name} not found in "
                f"{path.name}.{ShellStyle.END}"
            )
            return

        if dry_run:
            if rewrite:
                print(
                    f"{ShellStyle.CYAN}[*] Dry-run: would rename {old_name} → "
                    f"{new_name} in {output_path.name}, rewriting "
                    f"{summary['content_refs']} content + "
                    f"{summary['length_refs']} length reference(s)."
                    f"{ShellStyle.END}"
                )
                for ref_path in summary["paths"]:
                    print(f"    - {ref_path}")
            else:
                print(
                    f"{ShellStyle.CYAN}[*] Dry-run: would rename {old_name} → "
                    f"{new_name} in {output_path.name}. No references to "
                    f"rewrite.{ShellStyle.END}"
                )
            return

        backup_path = self._write_token_host_document(
            output_path,
            loaded,
            backup=(output_path == path and not no_backup),
        )
        if rewrite:
            print(
                f"{ShellStyle.GREEN}[+] Renamed {old_name} → {new_name} and "
                f"rewrote {summary['content_refs']} content + "
                f"{summary['length_refs']} length reference(s).{ShellStyle.END}"
            )
            for ref_path in summary["paths"]:
                print(f"    - {ref_path}")
        elif refs["total"] > 0:
            print(
                f"{ShellStyle.WARNING}[*] Renamed {old_name} → {new_name} in "
                f"__ygg_token_defs__. References left untouched -- they now "
                f"point to an undefined token.{ShellStyle.END}"
            )
        else:
            print(
                f"{ShellStyle.GREEN}[+] Renamed {old_name} → {new_name} in "
                f"{output_path.name} (no references to rewrite){ShellStyle.END}"
            )
        if backup_path is not None:
            print(f"    backup written to {backup_path.name}")

    def _cmd_retokenise_lengths(self, arg: str) -> None:
        raw_tokens = shlex.split(str(arg or "").strip())
        raw_tokens, dry_run = self._extract_flag(raw_tokens, "--dry-run")
        raw_tokens, no_backup = self._extract_flag(raw_tokens, "--no-backup")
        if len(raw_tokens) < 1 or len(raw_tokens) > 2:
            raise ValueError(
                "Usage: RETOKENISE-LENGTHS <template.json> [<output.json>] "
                "[--dry-run] [--no-backup]"
            )
        path, loaded = self._load_token_host_document(raw_tokens[0])
        if len(raw_tokens) == 2:
            output_path = self.bridge.resolve_workspace_path(
                raw_tokens[1], must_exist=False
            )
        else:
            output_path = path
        try:
            report = retokenise_template_lengths(loaded)
        except TokenSidecarError as error:
            raise ValueError(str(error)) from error
        if report["rewrites"] == 0:
            print(
                f"{ShellStyle.CYAN}[*] No <length>{{NAME}} patterns matched "
                f"the current __ygg_token_defs__.{ShellStyle.END}"
            )
            if len(report["skipped"]) > 0:
                print(
                    f"    Inspected {len(report['skipped'])} candidate pair(s); "
                    f"none matched the expected BER-TLV length."
                )
            return
        if dry_run:
            print(
                f"{ShellStyle.CYAN}[*] Dry-run: would rewrite "
                f"{report['rewrites']} <length>{{NAME}} pair(s) into "
                f"{{#NAME}}{{NAME}} in {output_path.name}{ShellStyle.END}"
            )
            for touched in report["paths"]:
                print(f"    - {touched}")
            if len(report["skipped"]) > 0:
                print(
                    f"    Would skip {len(report['skipped'])} candidate(s) "
                    "where the prefix did not match the BER-TLV length."
                )
            return
        backup_path = self._write_token_host_document(
            output_path,
            loaded,
            backup=(output_path == path and not no_backup),
        )
        print(
            f"{ShellStyle.GREEN}[+] Rewrote {report['rewrites']} "
            f"<length>{{NAME}} pair(s) into {{#NAME}}{{NAME}} in "
            f"{output_path.name}{ShellStyle.END}"
        )
        for touched in report["paths"]:
            print(f"    - {touched}")
        if len(report["skipped"]) > 0:
            print(
                f"{ShellStyle.CYAN}[*] Skipped {len(report['skipped'])} "
                f"candidate pair(s) where the prefix did not match the "
                f"BER-TLV length of the matching token.{ShellStyle.END}"
            )
        if backup_path is not None:
            print(f"    backup written to {backup_path.name}")

    def _cmd_new_profile_wizard(self, _arg: str) -> None:
        wizard = NewProfileWizard(
            workspace_root=self.bridge.workspace_root,
            default_output_dir=self.bridge.default_profile_dir,
            input_fn=self._input_fn,
        )
        try:
            decision = wizard.run()
        except WizardAborted as error:
            detail = str(error).strip() or "aborted"
            print(f"{ShellStyle.WARNING}[*] Wizard cancelled: {detail}{ShellStyle.END}")
            return

        assignments = self._expand_auto_placeholder_values(
            dict(decision.placeholders)
        )

        if decision.output_format == "der":
            self._materialise_scaffold_der(
                preset_id=decision.preset_id,
                menu_ids=decision.menu_ids,
                assignments=assignments,
                output_path=decision.output_path,
                verify=decision.verify,
            )
            return

        document = build_scaffold_profile_document_from_menu_ids(
            decision.preset_id,
            decision.menu_ids,
            self.bridge.workspace_root,
        )
        tagged, summaries = build_placeholder_template_document(document, assignments)
        declared_tokens = getattr(decision, "token_defs", {}) or {}
        if len(declared_tokens) > 0:
            if isinstance(tagged, dict) is False:
                raise RuntimeError(
                    "Scaffold template document is not a dict; cannot inject token defs."
                )
            tagged["__ygg_token_defs__"] = dict(declared_tokens)
            tagged["__ygg_placeholder_style__"] = getattr(
                decision, "placeholder_style", "brace"
            )
        decision.output_path.parent.mkdir(parents=True, exist_ok=True)
        decision.output_path.write_text(
            json.dumps(tagged, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            f"{ShellStyle.GREEN}[+] Wizard wrote {decision.preset_id} template to: "
            f"{decision.output_path}{ShellStyle.END}"
        )
        if len(summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] Placeholder injection summary:{ShellStyle.END}")
            for summary in summaries:
                print(f"    - {summary}")
        if len(declared_tokens) > 0:
            print(
                f"{ShellStyle.CYAN}[*] Declared token defs: "
                f"{', '.join(sorted(declared_tokens.keys()))} "
                f"(style={getattr(decision, 'placeholder_style', 'brace')}){ShellStyle.END}"
            )

    def _prompt_line(self, prompt_text: str, *, default: str = "") -> str:
        # Thin wrapper around ``self._input_fn`` that surfaces a default value
        # in-line and always returns a trimmed string. Kept private so wizard
        # prompts remain consistent with the rest of the shell.
        banner = prompt_text
        if len(default) > 0:
            banner = f"{prompt_text} [{default}]"
        response = self._input_fn(f"{banner}: ").strip()
        if len(response) == 0:
            return default
        return response

    def _prompt_aka_algorithm(self, current: str) -> str:
        from .saip_aka_wizard import aka_algorithm_choices, normalize_algorithm

        print(f"{ShellStyle.CYAN}[*] AKA algorithm:{ShellStyle.END}")
        for index, (choice_id, label, hint) in enumerate(aka_algorithm_choices(), start=1):
            print(f"    {index}. {label} ({choice_id}) -- {hint}")
        default_value = current if len(current) > 0 else "milenage"
        while True:
            raw = self._prompt_line("Algorithm (id or number)", default=default_value)
            if raw.isdigit():
                index = int(raw)
                choices = aka_algorithm_choices()
                if 1 <= index <= len(choices):
                    return choices[index - 1][0]
                print(f"{ShellStyle.FAIL}[-] Selection out of range.{ShellStyle.END}")
                continue
            try:
                return normalize_algorithm(raw)
            except ValueError as error:
                print(f"{ShellStyle.FAIL}[-] {error}{ShellStyle.END}")

    def _prompt_aka_section_key(self, document: dict) -> str:
        from .saip_aka_wizard import first_aka_section_key
        from .saip_json_codec import base_pe_type
        from .saip_pe_quick_add import insert_blank_pe_for_menu_id

        sections = document.get("sections", {})
        aka_keys = [
            section_key
            for section_key in sections.keys()
            if base_pe_type(str(section_key)) == "akaParameter"
        ]
        if len(aka_keys) == 0:
            print(
                f"{ShellStyle.WARNING}[*] Profile has no akaParameter PE. "
                f"Inserting a blank one before the end marker.{ShellStyle.END}"
            )
            new_document = insert_blank_pe_for_menu_id(
                document,
                self.bridge.workspace_root,
                menu_id="akaParameter",
            )
            document.clear()
            document.update(new_document)
            return first_aka_section_key(document) or "akaParameter"
        if len(aka_keys) == 1:
            return aka_keys[0]
        print(f"{ShellStyle.CYAN}[*] Multiple akaParameter PEs present:{ShellStyle.END}")
        for index, section_key in enumerate(aka_keys, start=1):
            print(f"    {index}. {section_key}")
        while True:
            raw = self._prompt_line("Select PE by number", default="1")
            if raw.isdigit():
                index = int(raw)
                if 1 <= index <= len(aka_keys):
                    return aka_keys[index - 1]
            print(f"{ShellStyle.FAIL}[-] Selection out of range.{ShellStyle.END}")

    def _parse_aka_inline_kvs(self, tokens: list[str]) -> dict[str, str]:
        # Accept NAME=VALUE tokens in any order. Empty values are allowed to
        # signal "leave field default / blank". Unknown keys raise ValueError
        # so typos are surfaced immediately instead of silently ignored.
        allowed = {
            "ALGORITHM",
            "KI",
            "OPC",
            "NUMBER-OF-KECCAK",
            "KECCAK",
            "AUTH-COUNTER-MAX",
            "SQN-INIT",
        }
        result: dict[str, str] = {}
        for token in tokens:
            if "=" not in token:
                raise ValueError(
                    f"Expected NAME=VALUE for AKA override, got: {token!r}"
                )
            name, _, value = token.partition("=")
            key = name.strip().upper()
            if key == "KECCAK":
                key = "NUMBER-OF-KECCAK"
            if key not in allowed:
                raise ValueError(
                    "Unknown AKA override: "
                    f"{name!r}. Expected one of ALGORITHM, KI, OPC, "
                    "NUMBER-OF-KECCAK, AUTH-COUNTER-MAX, SQN-INIT."
                )
            result[key] = value.strip()
        return result

    def _cmd_list_aka(self, _arg: str) -> None:
        # Read-only summary of every akaParameter PE in the active profile.
        # Intended as a quick inventory before running PROVISION-AKA so the
        # operator knows which section_key to target when multiple PEs are
        # present.
        from .saip_aka_wizard import list_aka_sections

        document = self.bridge.build_decoded_dump_document("all_pe")
        summaries = list_aka_sections(document)
        if len(summaries) == 0:
            print(
                f"{ShellStyle.WARNING}[*] Profile contains no akaParameter PE.{ShellStyle.END}"
            )
            return
        print(f"{ShellStyle.CYAN}[*] akaParameter PEs:{ShellStyle.END}")
        header = f"    {'#':<3} {'section_key':<18} {'algorithm':<10} {'Ki':<4} {'OPc':<4} {'keccak':<7} {'authCntMax':<12} {'sqnInit':<8}"
        print(header)
        for index, entry in enumerate(summaries, start=1):
            algo = entry.get("algorithm", "") or "?"
            auth_ctr = entry.get("auth_counter_max", "") or "-"
            sqn_present = "present" if entry.get("sqn_init_present") else "-"
            print(
                f"    {index:<3} {entry.get('section_key',''):<18} "
                f"{algo:<10} {entry.get('key_bytes',0):<4} "
                f"{entry.get('opc_bytes',0):<4} "
                f"{entry.get('number_of_keccak',0):<7} "
                f"{auth_ctr:<12} {sqn_present:<8}"
            )

    def _run_aka_provision_flow(
        self,
        *,
        output_path: Path,
        overrides: dict[str, str],
        interactive: bool,
    ) -> None:
        from .saip_aka_wizard import (
            aka_wizard_steps,
            apply_aka_configuration,
            read_aka_configuration,
            validate_auth_counter_max,
            validate_key_for_algorithm,
            validate_number_of_keccak,
            validate_opc_for_algorithm,
            validate_sqn_init_seed,
        )
        from .saip_json_codec import encode_der_from_document

        document = self.bridge.build_decoded_dump_document("all_pe")
        if interactive is True:
            section_key = self._prompt_aka_section_key(document)
        else:
            from .saip_aka_wizard import first_aka_section_key

            section_key = first_aka_section_key(document)
            if section_key is None:
                raise ValueError(
                    "Active profile has no akaParameter PE; "
                    "run LIST-AKA or use the interactive PROVISION-AKA wizard first."
                )
        current = read_aka_configuration(document, section_key)

        algorithm = overrides.get("ALGORITHM") or ""
        if len(algorithm) == 0:
            if interactive is True:
                algorithm = self._prompt_aka_algorithm(current.get("algorithm", ""))
            else:
                fallback = current.get("algorithm", "")
                if len(fallback) == 0:
                    raise ValueError(
                        "ALGORITHM= is required when the target PE has no algorithm set."
                    )
                algorithm = fallback
        else:
            from .saip_aka_wizard import normalize_algorithm

            algorithm = normalize_algorithm(algorithm)

        def _resolve_required(
            override_key: str,
            current_key: str,
            prompt_label: str,
            validator,
        ) -> str:
            override_value = overrides.get(override_key)
            if override_value is not None:
                validator(algorithm, override_value) if override_key in {"KI", "OPC"} else validator(override_value)
                return override_value
            if interactive is False:
                fallback = current.get(current_key, "")
                if len(fallback) == 0:
                    raise ValueError(
                        f"{override_key}= is required when the target PE has no {current_key} set."
                    )
                if override_key in {"KI", "OPC"}:
                    validator(algorithm, fallback)
                else:
                    validator(fallback)
                return fallback
            while True:
                raw = self._prompt_line(prompt_label, default=current.get(current_key, ""))
                try:
                    if override_key in {"KI", "OPC"}:
                        validator(algorithm, raw)
                    else:
                        validator(raw)
                    return raw
                except ValueError as error:
                    print(f"{ShellStyle.FAIL}[-] {error}{ShellStyle.END}")

        key_hex = _resolve_required(
            "KI",
            "key",
            "Ki (authentication key, hex)",
            validate_key_for_algorithm,
        )

        opc_hex = ""
        if algorithm != "xor-3g":
            opc_hex = _resolve_required(
                "OPC",
                "opc",
                "OPc / TOPc (hex)",
                validate_opc_for_algorithm,
            )

        keccak_value: int | None = None
        if algorithm == "tuak":
            override_value = overrides.get("NUMBER-OF-KECCAK")
            if override_value is not None:
                keccak_value = validate_number_of_keccak(override_value)
            elif interactive is False:
                fallback = current.get("numberOfKeccak", "1") or "1"
                keccak_value = validate_number_of_keccak(fallback)
            else:
                while True:
                    raw = self._prompt_line(
                        "numberOfKeccak (1..255)",
                        default=current.get("numberOfKeccak", "1") or "1",
                    )
                    try:
                        keccak_value = validate_number_of_keccak(raw)
                        break
                    except ValueError as error:
                        print(f"{ShellStyle.FAIL}[-] {error}{ShellStyle.END}")

        def _resolve_optional_hex(
            override_key: str,
            current_key: str,
            prompt_label: str,
            validator,
        ) -> str:
            override_value = overrides.get(override_key)
            if override_value is not None:
                validator(override_value)
                return override_value
            if interactive is False:
                return ""
            while True:
                raw = self._prompt_line(prompt_label, default=current.get(current_key, ""))
                try:
                    validator(raw)
                    return raw
                except ValueError as error:
                    print(f"{ShellStyle.FAIL}[-] {error}{ShellStyle.END}")

        auth_counter_hex = _resolve_optional_hex(
            "AUTH-COUNTER-MAX",
            "authCounterMax",
            "authCounterMax (6 hex chars, blank to keep default)",
            validate_auth_counter_max,
        )
        sqn_seed_hex = _resolve_optional_hex(
            "SQN-INIT",
            "sqnInit",
            "sqnInit seed (12 hex chars, blank to keep default)",
            validate_sqn_init_seed,
        )

        try:
            new_document = apply_aka_configuration(
                document,
                self.bridge.workspace_root,
                section_key=section_key,
                algorithm=algorithm,
                key_hex=key_hex,
                opc_hex=opc_hex,
                number_of_keccak=keccak_value,
                auth_counter_max_hex=auth_counter_hex,
                sqn_init_hex=sqn_seed_hex,
            )
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            raise ValueError(f"Failed to apply AKA configuration: {detail}") from error

        der = encode_der_from_document(new_document, self.bridge.workspace_root)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(der)
        print(
            f"{ShellStyle.GREEN}[+] Provisioned {algorithm} AKA on "
            f"{section_key} and wrote {len(der)} bytes to {output_path}{ShellStyle.END}"
        )
        steps_summary = aka_wizard_steps(algorithm)
        step_keys = ", ".join(step["key"] for step in steps_summary)
        print(f"{ShellStyle.CYAN}[*] Applied steps: {step_keys}{ShellStyle.END}")

    def _cmd_provision_aka(self, arg: str) -> None:
        # Tag-granular AKA provisioning. By default walks the interactive
        # wizard and writes to <output.der>. Accepts IN-PLACE to target the
        # active input DER (requires USE/OPEN to have chosen a real file),
        # and NAME=VALUE overrides to drive a non-interactive run that is
        # safe to paste into scripts or tests.
        from .saip_aka_wizard import aka_wizard_steps  # noqa: F401 (keeps the wizard import path warm)

        tokens = shlex.split(arg.strip())
        if len(tokens) == 0:
            raise ValueError(
                "Usage: PROVISION-AKA <output.der | IN-PLACE> [ALGORITHM=..] [KI=..] "
                "[OPC=..] [NUMBER-OF-KECCAK=..] [AUTH-COUNTER-MAX=..] [SQN-INIT=..]"
            )

        target_token = tokens[0]
        override_tokens = tokens[1:]
        if target_token.upper() == "IN-PLACE":
            current_input = self.bridge.current_input_file
            if current_input is None:
                raise ValueError(
                    "PROVISION-AKA IN-PLACE requires an active input file; run USE / OPEN first."
                )
            output_path = current_input
        else:
            output_path = self.bridge.resolve_workspace_path(target_token, must_exist=False)

        overrides = self._parse_aka_inline_kvs(override_tokens)
        interactive = len(overrides) == 0
        self._run_aka_provision_flow(
            output_path=output_path,
            overrides=overrides,
            interactive=interactive,
        )

    def _cmd_randomize_aka(self, arg: str) -> None:
        # Dev-only helper. Generates a random Ki / OPc (and TUAK-specific
        # numberOfKeccak when the algorithm is TUAK) using secrets.token_bytes
        # and applies them to the selected akaParameter PE. The helper
        # intentionally leaves authCounterMax and sqnInit untouched unless
        # the caller opts in with INCLUDE-AUTH-COUNTER-MAX / INCLUDE-SQN-INIT
        # so the replay-protection envelope stays predictable.
        from .saip_aka_wizard import (
            first_aka_section_key,
            normalize_algorithm,
            randomize_aka_values,
        )

        tokens = shlex.split(arg.strip())
        if len(tokens) == 0:
            raise ValueError(
                "Usage: RANDOMIZE-AKA <output.der | IN-PLACE> [ALGORITHM=milenage|tuak|xor-3g] "
                "[INCLUDE-AUTH-COUNTER-MAX] [INCLUDE-SQN-INIT]"
            )

        target_token = tokens[0]
        remaining = tokens[1:]
        include_auth = False
        include_sqn = False
        algorithm_override = ""
        for raw_token in remaining:
            upper = raw_token.upper()
            if upper == "INCLUDE-AUTH-COUNTER-MAX":
                include_auth = True
                continue
            if upper == "INCLUDE-SQN-INIT":
                include_sqn = True
                continue
            if "=" in raw_token:
                name, _, value = raw_token.partition("=")
                if name.strip().upper() == "ALGORITHM":
                    algorithm_override = value.strip()
                    continue
            raise ValueError(f"Unknown RANDOMIZE-AKA option: {raw_token!r}")

        if target_token.upper() == "IN-PLACE":
            current_input = self.bridge.current_input_file
            if current_input is None:
                raise ValueError(
                    "RANDOMIZE-AKA IN-PLACE requires an active input file; run USE / OPEN first."
                )
            output_path = current_input
        else:
            output_path = self.bridge.resolve_workspace_path(target_token, must_exist=False)

        document = self.bridge.build_decoded_dump_document("all_pe")
        section_key = first_aka_section_key(document)
        if section_key is None:
            raise ValueError(
                "Active profile has no akaParameter PE; run PROVISION-AKA interactively first."
            )

        from .saip_aka_wizard import read_aka_configuration

        snapshot = read_aka_configuration(document, section_key)
        if len(algorithm_override) == 0:
            algorithm = snapshot.get("algorithm", "")
            if len(algorithm) == 0:
                algorithm = "milenage"
        else:
            algorithm = algorithm_override
        algorithm = normalize_algorithm(algorithm)

        randomised = randomize_aka_values(
            algorithm,
            include_auth_counter_max=include_auth,
            include_sqn_init_seed=include_sqn,
        )

        overrides: dict[str, str] = {
            "ALGORITHM": randomised["algorithm"],
            "KI": randomised["key_hex"],
        }
        if len(randomised["opc_hex"]) > 0:
            overrides["OPC"] = randomised["opc_hex"]
        if randomised.get("number_of_keccak") is not None:
            overrides["NUMBER-OF-KECCAK"] = str(randomised["number_of_keccak"])
        if include_auth and len(randomised["auth_counter_max_hex"]) > 0:
            overrides["AUTH-COUNTER-MAX"] = randomised["auth_counter_max_hex"]
        if include_sqn and len(randomised["sqn_init_hex"]) > 0:
            overrides["SQN-INIT"] = randomised["sqn_init_hex"]

        self._run_aka_provision_flow(
            output_path=output_path,
            overrides=overrides,
            interactive=False,
        )
        print(
            f"{ShellStyle.WARNING}[*] RANDOMIZE-AKA uses secrets.token_bytes; "
            f"treat the resulting DER as development-only key material.{ShellStyle.END}"
        )

    def _cmd_generate_template(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        if len(tokens) == 0:
            raise ValueError(
                "Usage: GENERATE-TEMPLATE <output.json> [ICCID=<digits>] [IMSI=<digits>]"
            )

        self.bridge.get_input_file()
        output_path = self.bridge.resolve_workspace_path(tokens[0], must_exist=False)
        assignments = parse_placeholder_assignment_tokens(tokens[1:])
        document = self.bridge.build_decoded_dump_document("all_pe")
        tagged, summaries = build_placeholder_template_document(document, assignments)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(tagged, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        print(
            f"{ShellStyle.GREEN}[+] Template JSON written to: {output_path}{ShellStyle.END}"
        )
        if len(summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] Placeholder injection summary:{ShellStyle.END}")
            for summary in summaries:
                print(f"    - {summary}")

    def _cmd_generate_profile(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        if len(tokens) < 2:
            raise ValueError(
                "Usage: GENERATE-PROFILE <template.json> <output.der> [NAME=value ...]"
            )

        from .saip_json_codec import (
            dejsonify_document,
            encode_der_from_document,
            ensure_workspace_pysim_on_path,
        )

        template_path = self.bridge.resolve_workspace_path(tokens[0], must_exist=True)
        output_path = self.bridge.resolve_workspace_path(tokens[1], must_exist=False)
        assignments = parse_placeholder_assignment_tokens(tokens[2:])
        ensure_workspace_pysim_on_path(self.bridge.workspace_root)
        raw_text = template_path.read_text(encoding="utf-8")
        loaded = json.loads(raw_text)
        if isinstance(loaded, dict) is False:
            raise ValueError("Root JSON value must be an object.")
        summaries = apply_placeholder_overrides_to_loaded_document(loaded, assignments)
        document = dejsonify_document(loaded)
        der = encode_der_from_document(document, self.bridge.workspace_root)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(der)
        print(
            f"{ShellStyle.GREEN}[+] Wrote {len(der)} bytes DER to {output_path}{ShellStyle.END}"
        )
        if len(summaries) > 0:
            print(f"{ShellStyle.CYAN}[*] Placeholder override summary:{ShellStyle.END}")
            for summary in summaries:
                print(f"    - {summary}")

    def _cmd_generate_batch(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        if len(tokens) != 3:
            raise ValueError(
                "Usage: GENERATE-BATCH <template.json> <data_file> <output_dir>"
            )

        from .saip_json_codec import (
            dejsonify_document,
            encode_der_from_document,
            ensure_workspace_pysim_on_path,
        )

        template_path = self.bridge.resolve_workspace_path(tokens[0], must_exist=True)
        data_path = self.bridge.resolve_workspace_path(tokens[1], must_exist=True)
        output_dir = self.bridge.resolve_workspace_path(tokens[2], must_exist=False)
        raw_text = template_path.read_text(encoding="utf-8")
        loaded_template = json.loads(raw_text)
        if isinstance(loaded_template, dict) is False:
            raise ValueError("Root JSON value must be an object.")

        records = load_batch_placeholder_records(data_path)
        if len(records) == 0:
            raise ValueError("Batch data file did not contain any records.")

        template_placeholders = extract_template_placeholder_names(loaded_template)
        if len(template_placeholders) == 0:
            raise ValueError("Template does not contain any placeholders.")
        token_defs_raw = loaded_template.get("__ygg_token_defs__", {})
        template_token_defs: dict = {}
        if isinstance(token_defs_raw, dict):
            template_token_defs = dict(token_defs_raw)

        validated_records: list[tuple[str, dict[str, str]]] = []
        for record in records:
            try:
                assignments = validate_batch_record_assignments(
                    record.values,
                    template_placeholders=template_placeholders,
                    template_token_defs=template_token_defs,
                )
            except Exception as error:
                raise ValueError(f"{record.label}: {error}") from error
            validated_records.append((record.label, assignments))

        ensure_workspace_pysim_on_path(self.bridge.workspace_root)
        output_dir.mkdir(parents=True, exist_ok=True)
        used_output_names: set[str] = set()
        generated_paths: list[Path] = []

        # Determinate sweep -- batch record count is known up front.
        # The sticky footer shows which record is being materialised
        # so large generations (hundreds of profiles) have visible
        # progress. Inactive on piped invocations.
        total_records = len(validated_records)
        with progress_session(
            "SAIP batch generate", total=total_records
        ) as bar:
            for index, (label, assignments) in enumerate(validated_records, start=1):
                bar.advance(f"record {index}/{total_records} · {label}")
                loaded = copy.deepcopy(loaded_template)
                try:
                    apply_placeholder_overrides_to_loaded_document(loaded, assignments)
                    document = dejsonify_document(loaded)
                    der = encode_der_from_document(document, self.bridge.workspace_root)
                except Exception as error:
                    raise ValueError(f"{label}: {error}") from error

                base_stem = batch_output_stem(assignments, index=index)
                candidate_name = f"{base_stem}.der"
                suffix_index = 2
                while candidate_name in used_output_names:
                    candidate_name = f"{base_stem}_{suffix_index}.der"
                    suffix_index += 1
                used_output_names.add(candidate_name)
                output_path = output_dir / candidate_name
                output_path.write_bytes(der)
                generated_paths.append(output_path)

        print(
            f"{ShellStyle.GREEN}[+] Generated {len(generated_paths)} DER profiles in {output_dir}{ShellStyle.END}"
        )
        for path in generated_paths:
            print(f"    - {path.name}")

    def _cmd_info(self, arg: str) -> None:
        command = ["info"]
        if arg.strip().upper() in ("APPS", "--APPS"):
            command.append("--apps")
        result = self.bridge.run_current(command)
        self._print_result(result)

    def _cmd_tree(self, _arg: str) -> None:
        result = self.bridge.run_current(["tree"])
        self._print_result(result)

    def _cmd_check(self, _arg: str) -> None:
        result = self.bridge.run_current(["check"])
        self._print_result(result)

    def _cmd_dump(self, arg: str) -> None:
        mode = "all_pe"
        decoded = False
        mapping = {
            "ALL": "all_pe",
            "ALL_PE": "all_pe",
            "NAA": "all_pe_by_naa",
            "ALL_PE_BY_NAA": "all_pe_by_naa",
            "TYPE": "all_pe_by_type",
            "ALL_PE_BY_TYPE": "all_pe_by_type",
        }

        tokens, output_path = self._parse_output_redirection(arg)
        for token in tokens:
            upper_token = token.strip().upper()
            if upper_token in ("DECODED", "--DECODED"):
                decoded = True
                continue
            if upper_token in mapping:
                mode = mapping[upper_token]
                continue
            raise ValueError("Usage: DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]")

        command = ["dump"]
        if decoded:
            command.append("--dump-decoded")
        command.append(mode)
        result = self.bridge.run_current(command)
        rendered_stdout = ""
        structured_dump = None
        if len(result.stdout.strip()) > 0:
            rendered_stdout = self._render_result_stdout(result)
            if decoded:
                try:
                    structured_dump = self._normalize_dump_value(
                        self.bridge.build_decoded_dump_document(mode)
                    )
                except Exception:
                    structured_dump = self._build_structured_decoded_dump(result.stdout)

        if output_path is not None:
            self._write_output_file(output_path, rendered_stdout, structured_dump=structured_dump)

        if output_path is None and len(rendered_stdout) > 0:
            print(rendered_stdout.rstrip())

        if len(result.stderr.strip()) > 0:
            print(f"{ShellStyle.WARNING}{result.stderr.rstrip()}{ShellStyle.END}")

        if result.returncode == 0:
            print(f"{ShellStyle.GREEN}[+] Command completed successfully.{ShellStyle.END}")
            return

        print(
            f"{ShellStyle.FAIL}[-] saip-tool exited with code {result.returncode}.{ShellStyle.END}"
        )

    def _render_lint_report(self, report: dict) -> str:
        profile_text = str(report.get("profile", "unknown"))
        strict_text = bool(report.get("strict", False))
        score_text = int(report.get("score", 0))
        summary = report.get("summary", {})
        pass_count = int(summary.get("pass", 0))
        warn_count = int(summary.get("warn", 0))
        fail_count = int(summary.get("fail", 0))
        info_count = int(summary.get("info", 0))
        metadata_path = report.get("metadata_path")

        lines: list[str] = []
        lines.append(f"{ShellStyle.HEADER}=== PROFILE LINT REPORT ==={ShellStyle.END}")
        lines.append(f"{ShellStyle.CYAN}[*] Profile: {profile_text}{ShellStyle.END}")
        lines.append(f"{ShellStyle.CYAN}[*] Strict mode: {strict_text}{ShellStyle.END}")
        if metadata_path is not None:
            lines.append(f"{ShellStyle.CYAN}[*] Metadata: {metadata_path}{ShellStyle.END}")
        lines.append(f"{ShellStyle.CYAN}[*] Score: {score_text}/100{ShellStyle.END}")
        lines.append(f"{ShellStyle.GREEN}PASS{ShellStyle.END}: {pass_count}")
        lines.append(f"{ShellStyle.WARNING}WARN{ShellStyle.END}: {warn_count}")
        lines.append(f"{ShellStyle.FAIL}FAIL{ShellStyle.END}: {fail_count}")
        lines.append(f"{ShellStyle.BLUE}INFO{ShellStyle.END}: {info_count}")
        lint_profile = report.get("lint_profile")
        if lint_profile is not None:
            lines.append(f"{ShellStyle.CYAN}[*] Profile preset: {lint_profile}{ShellStyle.END}")
        gate = report.get("gate")
        if isinstance(gate, dict):
            lines.append("")
            lines.append(f"{ShellStyle.BOLD}Gate:{ShellStyle.END}")
            gate_passed = bool(gate.get("passed", False))
            gate_status = "PASS"
            gate_color = ShellStyle.GREEN
            if gate_passed is False:
                gate_status = "FAIL"
                gate_color = ShellStyle.FAIL
            lines.append(f"  status: {gate_color}{gate_status}{ShellStyle.END}")
            lines.append(f"  triggers: {int(gate.get('trigger_count', 0))}")
            thresholds = gate.get("thresholds", {})
            if isinstance(thresholds, dict):
                lines.append(f"  min_score: {thresholds.get('min_score')}")
                lines.append(f"  fail_on_warn: {thresholds.get('fail_on_warn')}")
                lines.append(f"  fail_prefixes: {thresholds.get('fail_prefixes')}")
                lines.append(f"  fail_codes: {thresholds.get('fail_codes')}")

        findings = report.get("findings", [])
        if isinstance(findings, list):
            if len(findings) > 0:
                lines.append("")
                lines.append(f"{ShellStyle.BOLD}Findings:{ShellStyle.END}")
                first_rendered_finding = True
                for finding in findings:
                    if isinstance(finding, dict) is False:
                        continue
                    if first_rendered_finding is False:
                        lines.append("")
                    severity = str(finding.get("severity", "INFO"))
                    color = ShellStyle.CYAN
                    if severity == "PASS":
                        color = ShellStyle.GREEN
                    if severity == "WARN":
                        color = ShellStyle.WARNING
                    if severity == "FAIL":
                        color = ShellStyle.FAIL
                    if severity == "INFO":
                        color = ShellStyle.BLUE
                    code = str(finding.get("code", ""))
                    path = str(finding.get("path", ""))
                    message = str(finding.get("message", ""))
                    spec = str(finding.get("spec", ""))
                    recommendation = str(finding.get("recommendation", "")).strip()
                    evidence = finding.get("evidence")
                    lines.append(f"{color}[{severity}]{ShellStyle.END} {code} | {path} | {spec}")
                    lines.append(f"    {message}")
                    if recommendation not in ("", "None.", "None"):
                        lines.append(f"    Recommendation: {recommendation}")
                    if evidence is not None:
                        if isinstance(evidence, (dict, list)):
                            evidence_text = json.dumps(evidence, ensure_ascii=True, sort_keys=True)
                        else:
                            evidence_text = str(evidence)
                        lines.append(f"    Evidence: {evidence_text}")
                    first_rendered_finding = False
        return "\n".join(lines)

    def _load_lint_metadata(self, metadata_path: str) -> tuple[dict, Path]:
        resolved_path = self.bridge.resolve_workspace_path(metadata_path, must_exist=True)
        suffix = resolved_path.suffix.lower()
        raw_text = resolved_path.read_text(encoding="utf-8")
        if suffix == ".json":
            payload = json.loads(raw_text)
        else:
            payload = yaml.safe_load(raw_text)
        if isinstance(payload, dict) is False:
            raise ValueError("Metadata payload must decode to a dictionary.")
        return payload, resolved_path

    def _print_lint_help(self) -> None:
        print(f"{ShellStyle.BOLD}LINT options:{ShellStyle.END}")
        print(f"  {self._LINT_USAGE}")
        print("  STRICT")
        print("      Escalate selected warning classes to FAIL.")
        print("  METADATA <path>")
        print("      Attach profile metadata for ICCID/MCC/MNC coherence checks.")
        print("  PROFILE <name>")
        print("      Apply a preset gate profile. See `LINT PROFILES`.")
        print("  GATE <prefixes>")
        print("      Comma-separated YRL rule ID prefixes, e.g. YRL-FIL,YRL-SVC (see lint_rule_ids).")
        print("  FAIL-CODES <codes>")
        print("      Comma-separated explicit rule IDs to gate on.")
        print("  MIN-SCORE <n>")
        print("      Minimum score threshold (0..100).")
        print("  FAIL-ON-WARN")
        print("      Consider WARN findings as gate triggers.")
        print("  ENFORCE")
        print("      Exit with status code 2 if gate fails (CI use).")
        print("  Examples:")
        print("      LINT PROFILE STRICT-FS")
        print("      LINT PROFILE RELEASE-GATE ENFORCE")
        print("      LINT GATE YRL-FIL,YRL-JCA MIN-SCORE 90 > reports/profile_lint.json")

    def _print_lint_profiles(self) -> None:
        print(f"{ShellStyle.BOLD}LINT preset profiles:{ShellStyle.END}")
        for profile_name in sorted(self._LINT_PROFILE_PRESETS.keys()):
            preset = self._LINT_PROFILE_PRESETS[profile_name]
            strict_text = bool(preset.get("strict", False))
            min_score = preset.get("min_score")
            fail_on_warn = bool(preset.get("fail_on_warn", False))
            prefixes = preset.get("gate_prefixes", [])
            description = str(preset.get("description", "")).strip()
            print(f"  {profile_name}")
            print(f"    strict={strict_text}, min_score={min_score}, fail_on_warn={fail_on_warn}")
            print(f"    gate_prefixes={prefixes}")
            if description != "":
                print(f"    {description}")

    def _resolve_lint_profile(self, profile_name: str) -> dict[str, object]:
        normalized_name = str(profile_name or "").strip().upper()
        if normalized_name == "":
            raise ValueError("PROFILE requires a preset name. Use `LINT PROFILES`.")
        if normalized_name not in self._LINT_PROFILE_PRESETS:
            known_profiles = ", ".join(sorted(self._LINT_PROFILE_PRESETS.keys()))
            raise ValueError(f"Unknown lint profile '{normalized_name}'. Known profiles: {known_profiles}")
        return dict(self._LINT_PROFILE_PRESETS[normalized_name])

    def _cmd_lint(self, arg: str) -> None:
        tokens, output_path = self._parse_lint_output_redirection(arg)
        if len(tokens) == 1:
            first_token = str(tokens[0]).strip().upper()
            if first_token in ("HELP", "--HELP", "-H"):
                self._print_lint_help()
                return
            if first_token in ("PROFILES", "LIST-PROFILES"):
                self._print_lint_profiles()
                return

        strict_mode = False
        metadata_payload: dict | None = None
        metadata_path: Path | None = None
        gate_prefixes: list[str] = []
        gate_codes: list[str] = []
        min_score: int | None = None
        fail_on_warn = False
        enforce = False
        lint_profile_name: str | None = None

        index = 0
        while index < len(tokens):
            token = tokens[index].strip().upper()
            if token == "STRICT":
                strict_mode = True
                index += 1
                continue
            if token == "FAIL-ON-WARN":
                fail_on_warn = True
                index += 1
                continue
            if token == "ENFORCE":
                enforce = True
                index += 1
                continue
            if token == "METADATA":
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(self._LINT_USAGE)
                metadata_payload, metadata_path = self._load_lint_metadata(tokens[next_index])
                index += 2
                continue
            if token == "PROFILE":
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(self._LINT_USAGE)
                resolved_profile = self._resolve_lint_profile(tokens[next_index])
                lint_profile_name = str(tokens[next_index]).strip().upper()
                strict_mode = bool(resolved_profile.get("strict", strict_mode))
                min_score_value = resolved_profile.get("min_score")
                if isinstance(min_score_value, int):
                    min_score = min_score_value
                fail_on_warn = bool(resolved_profile.get("fail_on_warn", fail_on_warn))
                preset_prefixes = resolved_profile.get("gate_prefixes", [])
                if isinstance(preset_prefixes, list):
                    gate_prefixes = [str(item).strip().upper() for item in preset_prefixes if str(item).strip() != ""]
                index += 2
                continue
            if token == "GATE":
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(self._LINT_USAGE)
                raw_prefixes = str(tokens[next_index]).strip()
                parsed_prefixes = [item.strip().upper() for item in raw_prefixes.split(",") if item.strip() != ""]
                if len(parsed_prefixes) == 0:
                    raise ValueError("GATE requires at least one prefix, e.g. GATE YRL-FIL,YRL-SVC")
                gate_prefixes = parsed_prefixes
                index += 2
                continue
            if token == "FAIL-CODES":
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(self._LINT_USAGE)
                raw_codes = str(tokens[next_index]).strip()
                parsed_codes = [item.strip().upper() for item in raw_codes.split(",") if item.strip() != ""]
                if len(parsed_codes) == 0:
                    raise ValueError(
                        "FAIL-CODES requires at least one rule ID, e.g. FAIL-CODES YRL-UST-001,YRL-JCA-010"
                    )
                gate_codes = parsed_codes
                index += 2
                continue
            if token == "MIN-SCORE":
                next_index = index + 1
                if next_index >= len(tokens):
                    raise ValueError(self._LINT_USAGE)
                raw_score = str(tokens[next_index]).strip()
                try:
                    parsed_score = int(raw_score)
                except ValueError as error:
                    raise ValueError("MIN-SCORE must be an integer between 0 and 100.") from error
                if parsed_score < 0 or parsed_score > 100:
                    raise ValueError("MIN-SCORE must be between 0 and 100.")
                min_score = parsed_score
                index += 2
                continue
            raise ValueError(self._LINT_USAGE)

        decoded_document = self.bridge.build_decoded_dump_document("all_pe")
        check_result = self.bridge.run_current(["check"])
        current_profile = self.bridge.get_input_file()
        linter = SaipProfileLinter(strict=strict_mode)
        report_obj = linter.lint_decoded_document(
            decoded_document=decoded_document,
            profile_label=str(current_profile),
            check_return_code=check_result.returncode,
            check_stderr=check_result.stderr,
            metadata=metadata_payload,
            metadata_path=str(metadata_path) if metadata_path is not None else None,
        )
        if min_score is not None or fail_on_warn or len(gate_prefixes) > 0 or len(gate_codes) > 0:
            linter.evaluate_gate(
                report=report_obj,
                min_score=min_score,
                fail_on_warn=fail_on_warn,
                fail_prefixes=gate_prefixes,
                fail_codes=gate_codes,
            )
        report_dict = report_obj.to_dict()
        if lint_profile_name is not None:
            report_dict["lint_profile"] = lint_profile_name
        rendered_report = self._render_lint_report(report_dict)

        if output_path is not None:
            self._write_output_file(
                output_path=output_path,
                rendered_stdout=rendered_report,
                structured_dump=report_dict,
                artifact_label="Lint report",
            )

        print(rendered_report.rstrip())
        gate_data = report_dict.get("gate")
        if enforce and isinstance(gate_data, dict):
            if bool(gate_data.get("passed", False)) is False:
                raise SystemExit(2)

    def _cmd_split(self, arg: str) -> None:
        command = ["split"]
        raw_value = arg.strip()
        if len(raw_value) > 0:
            output_prefix = self.bridge.resolve_path(raw_value, must_exist=False)
            command.extend(["--output-prefix", str(output_prefix)])
        result = self.bridge.run_current(command)
        self._print_result(result)

    def _cmd_extract_apps(self, arg: str) -> None:
        parts = arg.split()
        command = ["extract-apps"]
        if len(parts) > 0:
            output_dir = self.bridge.resolve_path(parts[0], must_exist=False)
            command.extend(["--output-dir", str(output_dir)])
        if len(parts) > 1:
            output_format = parts[1].strip().lower()
            if output_format not in ("cap", "ijc"):
                raise ValueError("Usage: EXTRACT-APPS [output_dir] [CAP|IJC]")
            command.extend(["--format", output_format])
        if len(parts) > 2:
            raise ValueError("Usage: EXTRACT-APPS [output_dir] [CAP|IJC]")
        result = self.bridge.run_current(command)
        self._print_result(result)

    def _cmd_remove_naa(self, arg: str) -> None:
        parts = arg.split()
        if len(parts) != 2:
            raise ValueError("Usage: REMOVE-NAA <USIM|ISIM|CSIM> <output_file>")

        naa_type = parts[0].strip().lower()
        if naa_type not in ("usim", "isim", "csim"):
            raise ValueError("Usage: REMOVE-NAA <USIM|ISIM|CSIM> <output_file>")

        output_file = self.bridge.resolve_path(parts[1], must_exist=False)
        result = self.bridge.run_current(
            ["remove-naa", "--output-file", str(output_file), "--naa-type", naa_type]
        )
        self._print_result(result)

    def _cmd_raw(self, arg: str) -> None:
        tokens = shlex.split(arg.strip())
        if len(tokens) == 0:
            raise ValueError("Usage: RAW <subcommand args...>")
        normalized_tokens = self.bridge.normalize_raw_arguments(tokens)
        result = self.bridge.run_current(normalized_tokens)
        self._print_result(result)

    def _cmd_exit(self, _arg: str) -> None:
        raise SystemExit(0)

    def _cmd_quit_all(self, _arg: str) -> None:
        quit_all()
