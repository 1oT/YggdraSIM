import atexit
import ast
import ipaddress
import json
import os
import re
import shlex
from pathlib import Path
from typing import Callable, Optional

import yaml

from yggdrasim_common.quit_control import quit_all
from .lint_engine import SaipProfileLinter
from .saip_tool import SaipCommandResult, SaipToolBridge

try:
    import readline
except ImportError:
    readline = None


class ShellStyle:
    HEADER = "\033[38;2;95;220;203m"
    BLUE = "\033[38;2;138;167;255m"
    CYAN = "\033[38;2;147;247;255m"
    GREEN = "\033[38;2;141;255;141m"
    WARNING = "\033[38;2;255;240;143m"
    FAIL = "\033[38;2;255;154;154m"
    BOLD = "\033[1m"
    END = "\033[0m"


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

    def __init__(self, workspace_root: Path) -> None:
        self.bridge = SaipToolBridge(workspace_root=workspace_root)
        self._history_file = Path.home() / ".yggdrasim_saip_history"
        self._startup_profiles = self.bridge.list_default_profiles()
        self.prompt = f"\n{ShellStyle.BLUE}[SAIP Tool] > {ShellStyle.END}"
        self._commands: dict[str, Callable[[str], None]] = {
            "CHECK": self._cmd_check,
            "DUMP": self._cmd_dump,
            "ENCODE-JSON": self._cmd_encode_json,
            "EXIT": self._cmd_exit,
            "EXTRACT-APPS": self._cmd_extract_apps,
            "HELP": self._cmd_help,
            "INFO": self._cmd_info,
            "LINT": self._cmd_lint,
            "OPEN": self._cmd_use,
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
            "TRANSCODE-DIR": self._cmd_transcode_dir,
            "TRANSCODE-TUI": self._cmd_transcode_tui,
            "TREE": self._cmd_tree,
            "USE": self._cmd_use,
        }
        self._setup_readline()
        self._auto_select_single_startup_profile()

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

        options: list[str] = []
        if command in ("USE", "OPEN"):
            options = self._complete_path_token(argument_text)
        elif command == "PROFILE-DIR":
            options = self._complete_path_token(argument_text, directories_only=True)

        if state < len(options):
            return options[state]
        return None

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
        if field_name == "connectivityParameters":
            return self._decode_connectivity_parameters(value)
        if field_name == "sdPersoData":
            return self._decode_sd_perso_data(value)
        if field_name == "uiccToolkitApplicationSpecificParametersField":
            return self._decode_uicc_toolkit_parameters(value)
        if field_name == "applicationSpecificParametersC9":
            return self._decode_sd_install_parameters(value)
        if field_name == "applicationPrivileges":
            return self._decode_application_privileges(value)
        if field_name == "lifeCycleState":
            return self._decode_life_cycle_state(value)
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

    def _cmd_help(self, _arg: str) -> None:
        print(f"\n{ShellStyle.BOLD}SAIP Tool commands:{ShellStyle.END}")
        print("  Context:")
        print("    Use this shell to inspect and manipulate SAIP / UPP profile package inputs through `saip-tool`.")
        print("    Start by selecting an input file with `USE`, then run read-oriented commands like `INFO`, `TREE`, `CHECK`, or `DUMP`.")
        print("    Output locations for write operations remain workspace-confined.")
        print("")
        print("  Typical workflow:")
        print("    1. USE /path/to/profile.der")
        print("    2. INFO")
        print("    3. TREE")
        print("    4. DUMP ALL DECODED")
        print("    5. CHECK")
        print("    6. LINT STRICT > reports/profile_lint.yaml")
        print("")
        print("  USE <file>                 Select active input UPP/DER file. Absolute paths are allowed for input.")
        print("                             Bare filenames are looked up in the default profile dir first.")
        print("                             `.txt` and `.hex` inputs are treated as hex-encoded DER and converted automatically.")
        print("  STATUS                     Show the active profile selection and transcode output directory.")
        print("  PROFILE-DIR [dir]          Show or set the default profile directory used by `USE` and tab completion.")
        print("  TRANSCODE-DIR [dir]        Show or set the default TRANSCODE-TUI save directory.")
        print("  TOOL [command]             Show or override the saip-tool executable command.")
        print("  INFO [APPS]                Run `info` and optionally include `--apps`.")
        print("  TREE                       Run `tree`.")
        print("  CHECK                      Run `check`.")
        print("  LINT [options] [> output_file]")
        print("                             Run comprehensive profile linting across SAIP structure,")
        print("                             mandatory services, AID integrity, APDU/hex sanity, and metadata coherence.")
        print("                             For detailed lint options run: LINT HELP")
        print("                             For preset gate profiles run: LINT PROFILES")
        print("  DUMP [ALL|TYPE|NAA] [DECODED] [> output_file]")
        print("                             Run `dump` using all_pe, all_pe_by_type, or all_pe_by_naa.")
        print("                             Use `>` to write a workspace-confined structured dump file.")
        print("                             Decoded dumps write YAML by default, or JSON when the path ends in `.json`.")
        print("  TRANSCODE-TUI              Open a split Textual UI: JSON outline + editor (left) and DER hex (right);")
        print("                             F3 inserts blank PE blocks from pySim templates (before end PE).")
        print("                             Bottom split: left = live selection/whole-profile decode (F4),")
        print("                             right = live lint; F7 cycles theme (saved). JSON↔DER uses nearest { }/[ ] value.")
        print("                             Full-terminal layout using terminal-native styling; Ctrl+S or F2 save, Ctrl+Q quit.")
        print("  ENCODE-JSON <in.json> <out.der>")
        print("                             Build DER from tagged SAIP JSON (same schema as TRANSCODE-TUI).")
        print("                             Optional root __ygg_token_defs__ names {token} (default) or [token]")
        print("                             when __ygg_placeholder_style__ is bracket; use inside hex / __ygg_saip_ph__.")
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
        print("    PROFILE-DIR Tools/ProfilePackage/profile")
        print("    TRANSCODE-DIR Tools/ProfilePackage/transcode")
        print("    USE reference_test_profile.txt")
        print("    DUMP ALL DECODED")
        print("    DUMP ALL DECODED > reports/decoded_dump.yaml")
        print("    DUMP ALL DECODED > reports/decoded_dump.json")
        print("    TRANSCODE-TUI")
        print("    ENCODE-JSON reports/saip_tagged.json reports/rebuilt.der")
        print("    LINT")
        print("    LINT STRICT")
        print("    LINT HELP")
        print("    LINT PROFILES")
        print("    LINT PROFILE STRICT-FS")
        print("    LINT PROFILE RELEASE-GATE ENFORCE")
        print("    LINT METADATA SCP11/local_access/profile/metadata/default_profile_metadata.json")
        print("    LINT GATE YRL-FIL,YRL-SVC")
        print("    LINT GATE YRL-FIL MIN-SCORE 90 FAIL-ON-WARN")
        print("    LINT GATE YRL-FIL,YRL-JCA ENFORCE > reports/profile_lint.json")
        print("    LINT STRICT METADATA SCP11/local_access/profile/metadata/default_profile_metadata.json > reports/profile_lint.yaml")
        print("    EXTRACT-APPS tests/saip_apps IJC")
        print("    RAW extract-pe --pe-file tests/header.der --identification 4")

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

    def _cmd_transcode_tui(self, _arg: str) -> None:
        try:
            self.bridge.get_input_file()
        except ValueError as exc:
            print(f"{ShellStyle.FAIL}[-] {exc}{ShellStyle.END}")
            print(
                f"{ShellStyle.WARNING}[*] Select a profile with USE <file> first.{ShellStyle.END}"
            )
            return

        try:
            from .saip_transcode_tui import run_saip_transcode_tui

            run_saip_transcode_tui(self.bridge)
        except ImportError as exc:
            detail = str(exc).lower()
            if "textual" in detail:
                print(
                    f"{ShellStyle.FAIL}[-] Textual is required for TRANSCODE-TUI "
                    f"(pip install textual): {exc}{ShellStyle.END}"
                )
            elif "pysim" in detail:
                print(
                    f"{ShellStyle.FAIL}[-] TRANSCODE-TUI needs the vendored pySim tree "
                    f"under {self.bridge.workspace_root / 'pysim'} (or install pySim): "
                    f"{exc}{ShellStyle.END}"
                )
            else:
                print(f"{ShellStyle.FAIL}[-] TRANSCODE-TUI import failed: {exc}{ShellStyle.END}")
        except ValueError as exc:
            print(f"{ShellStyle.FAIL}[-] {exc}{ShellStyle.END}")

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
