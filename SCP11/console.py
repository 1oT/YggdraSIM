# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP11 operator console: interactive REPL exposing ES2+/ES9+ commands and profile lifecycle operations."""
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

"""Canonical SCP11 console shell.

This is the ``canonical`` SCP11 console/CLI entry point for YggdraSIM v1.
``SCP11/live/console.py`` carries the relay console used by both the live
entrypoint and the ``SCP11.test`` compatibility path. Audit item
``SCP11-P1-02`` tracks splitting this module into ``console_cli``,
``console_tls_probe``, and ``console_state`` post v1.
"""

import atexit
import hashlib
import os
import shutil
import socket
import ssl
import sys
from urllib.parse import urlparse
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from yggdrasim_common.hil_bridge_runtime import hil_bridge_warning_text
from yggdrasim_common.quit_control import quit_all
from yggdrasim_common.euicc_issuer import (
    format_ecasd_issuer_display,
    infer_ecasd_issuer_from_eid,
)
from SCP11.shared.gsma_error_codes import describe_sgp22_notification_sent_result
from SCP11.shared.profile_targeting import resolve_profile_target_identifier
from SCP11.shared.tls_helpers import create_introspection_context

try:
    from SCP03.core.utils import TlvParser
except Exception:
    TlvParser = None

try:
    from SCP03.config import Config as SCP03Config
except Exception:
    SCP03Config = None

from SCP11.shared.device_inventory_support import EidInventoryNamespace

try:
    from SCP03.logic.euicc_info2 import build_euicc_info2_detail_lines
except Exception:
    build_euicc_info2_detail_lines = None

try:
    from SCP03.logic.sgp32_decode import decode_eim_configuration_entries
    from SCP03.logic.sgp32_decode import decode_euicc_info1_summary
    from SCP03.logic.sgp32_decode import decode_get_certs_response
    from SCP03.logic.sgp32_decode import decode_notifications_response
    from SCP03.logic.sgp32_decode import decode_rat_rules
except Exception:
    decode_eim_configuration_entries = None
    decode_euicc_info1_summary = None
    decode_get_certs_response = None
    decode_notifications_response = None
    decode_rat_rules = None

try:
    import readline
except ImportError:
    readline = None


def _encode_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _build_tlv(tag: bytes, value: bytes) -> bytes:
    return tag + _encode_length(len(value)) + value


@dataclass
class ProfileRow:
    iccid: str
    state: str
    profile_class: str
    nickname: str
    aid: str


@dataclass
class ProfileMetadataView:
    iccid: str
    aid: str
    state: str
    profile_class: str
    nickname: str
    service_provider: str
    profile_name: str
    profile_policy_rules_hex: str


@dataclass
class CommandSpec:
    name: str
    usage: str
    description: str
    handler: Callable[[str], bool]
    scaffold: bool


@dataclass
class CardSnapshot:
    eid: str
    issuer_number: str
    issuer_name: str
    configured_raw: bytes
    configured_decoded: Dict[str, Any]
    profiles: List[ProfileRow]


@dataclass
class ConsoleStyle:
    header: str
    cyan: str
    green: str
    yellow: str
    red: str
    bold: str
    end: str


def _hex_to_ansi(hex_color: str) -> str:
    hex_value = hex_color.lstrip("#")
    red = int(hex_value[0:2], 16)
    green = int(hex_value[2:4], 16)
    blue = int(hex_value[4:6], 16)
    return f"\033[38;2;{red};{green};{blue}m"


class SCP11Console:
    """Interactive SCP11 command shell with persistent card session."""
    TAG_ENABLE_PROFILE = 0xBF31
    TAG_DISABLE_PROFILE = 0xBF32
    TAG_DELETE_PROFILE = 0xBF33
    TAG_REMOVE_NOTIFICATION = 0xBF30
    TAG_RESULT = 0x80
    TAG_CTX_0 = 0xA0
    TAG_AID = 0x4F
    TAG_ICCID = 0x5A
    MODULE_STATE_NAME = "scp11_relay_config"
    DEFAULT_AID_REGISTRY_PATH = (
        getattr(SCP03Config, "AID_FILE", "")
        or os.path.normpath(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "Workspace", "SCP03", "aid.txt")
        )
    )
    HELP_USAGE_WIDTH = 31

    def __init__(self, client: Any):
        self.client = client
        self.cfg = client.cfg
        self.apdu_channel = client.apdu_channel
        self.orchestrator = client.orchestrator
        self.current_smdp_address = self.cfg.RSP_SERVER_URL
        self.current_es9_base_url = self.cfg.ES9_BASE_URL
        self.current_es9_verify_tls = self.cfg.ES9_VERIFY_TLS
        self.current_es9_ca_bundle_path = self.cfg.ES9_CA_BUNDLE_PATH
        self.current_eid = ""
        self._inventory = EidInventoryNamespace("scp11")
        self._apply_module_state_profile()
        self._es9_auto_derived = False
        self._style = self._build_style()
        self._commands: Dict[str, CommandSpec] = {}
        self._primary_commands: List[str] = []
        self._history_file = ""
        self._help_pane_locked = False
        self._help_pane_rows = 0
        self._terminal_rows = 0
        self._pane_two_col = False
        self._pane_left_width = 0
        self._pane_gutter = 0
        self._latest_snapshot: Optional[CardSnapshot] = None
        self._aid_registry = self._load_aid_registry()
        self._register_commands()
        self._setup_readline()

    def run(self) -> None:
        """Start the interactive operator REPL for this SCP11 session variant."""
        try:
            self._initialize_session()
            self._activate_locked_help_pane_if_supported()
            self._print_start_snapshot()
            if self._help_pane_locked is False:
                self._print_help()
        except Exception as error:
            self._deactivate_locked_help_pane()
            raise RuntimeError(f"SCP11 session initialization failed: {error}") from error

        try:
            while True:
                try:
                    raw_line = input(
                        f"\n{self._style.header}[SCP11] > {self._style.end}"
                    ).strip()
                except KeyboardInterrupt:
                    print("\n[*] Exiting SCP11 shell.")
                    break
                except EOFError:
                    print("\n[*] Exiting SCP11 shell.")
                    break

                keep_running = self._run_command_line(raw_line)
                if keep_running is False:
                    break
        finally:
            self._deactivate_locked_help_pane()

    def run_commands(self, cmd_line: str) -> None:
        """Execute a semicolon-delimited list of operator commands non-interactively."""
        try:
            self._initialize_session()
        except Exception as error:
            raise RuntimeError(f"SCP11 session initialization failed: {error}") from error
        try:
            for raw_command in self._split_batch_commands(cmd_line):
                keep_running = self._run_command_line(raw_command, show_help_on_unknown=False)
                if keep_running is False:
                    break
        finally:
            self._deactivate_locked_help_pane()

    @staticmethod
    def _split_batch_commands(cmd_line: str) -> list[str]:
        commands: list[str] = []
        for raw_command in str(cmd_line or "").split(";"):
            command_text = str(raw_command or "").strip()
            if len(command_text) == 0:
                continue
            commands.append(command_text)
        return commands

    def _run_command_line(self, raw_line: str, show_help_on_unknown: bool = True) -> bool:
        if len(str(raw_line or "").strip()) == 0:
            return True
        command, argument = self._split_command(raw_line)
        command_upper = command.upper()
        if command_upper not in self._commands:
            print(f"[!] Unknown command: {command}")
            if show_help_on_unknown:
                if self._help_pane_locked:
                    print("[*] Help pane is pinned in the top half.")
                    self._refresh_locked_help_pane()
                else:
                    self._print_help()
            return True
        handler = self._commands[command_upper].handler
        return handler(argument)

    def _activate_locked_help_pane_if_supported(self) -> None:
        if self._locked_help_pane_requested() is False:
            return
        if sys.stdout.isatty() is False:
            return

        term_name = os.environ.get("TERM", "")
        if len(term_name.strip()) == 0:
            return
        if term_name.lower() == "dumb":
            return

        size = shutil.get_terminal_size(fallback=(120, 40))
        rows = size.lines
        if rows < 24:
            return

        self._help_pane_locked = True
        self._terminal_rows = rows
        self._help_pane_rows = rows // 2
        if self._help_pane_rows < 10:
            self._help_pane_rows = 10

        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()
        self._refresh_locked_help_pane()
        self._set_lower_scroll_region()

    def _locked_help_pane_requested(self) -> bool:
        raw_value = os.environ.get("SCP11_PINNED_HELP", "")
        normalized = raw_value.strip().lower()
        if normalized in ["1", "true", "yes", "on"]:
            return True
        return False

    def _deactivate_locked_help_pane(self) -> None:
        if self._help_pane_locked is False:
            return
        sys.stdout.write("\033[r")
        sys.stdout.flush()
        self._help_pane_locked = False

    def _set_lower_scroll_region(self) -> None:
        if self._help_pane_locked is False:
            return
        lower_start = self._help_pane_rows + 1
        sys.stdout.write(f"\033[{lower_start};{self._terminal_rows}r")
        sys.stdout.write(f"\033[{lower_start};1H")
        sys.stdout.flush()

    def _refresh_locked_help_pane(self) -> None:
        if self._help_pane_locked is False:
            return

        size = shutil.get_terminal_size(fallback=(120, 40))
        self._terminal_rows = size.lines
        self._help_pane_rows = self._terminal_rows // 2
        if self._help_pane_rows < 10:
            self._help_pane_rows = 10

        width = size.columns
        lines = self._build_locked_help_lines(width=width, max_lines=self._help_pane_rows)

        sys.stdout.write("\0337")
        sys.stdout.write("\033[r")
        for index in range(self._help_pane_rows):
            row = index + 1
            text = ""
            if index < len(lines):
                text = lines[index]
            clipped = text[:width]
            padded = clipped.ljust(width)
            rendered = self._colorize_pinned_line(padded)
            sys.stdout.write(f"\033[{row};1H{rendered}")
        self._set_lower_scroll_region()
        sys.stdout.write("\0338")
        sys.stdout.flush()

    def _build_locked_help_lines(self, width: int, max_lines: int) -> List[str]:
        left_lines: List[str] = []
        left_lines.append("SCP11 Command Pane")
        left_lines.append("-" * 74)
        left_lines.append("Core SCP11:")
        for usage, description in self._get_core_help_rows():
            left_lines.append(f"  {usage:<{self.HELP_USAGE_WIDTH}} {description}")
        left_lines.append("")
        left_lines.append("SGP.22 / SGP.32:")
        for usage, description in self._get_extended_help_rows():
            left_lines.append(f"  {usage:<{self.HELP_USAGE_WIDTH}} {description}")

        if width < 120:
            self._pane_two_col = False
            self._pane_left_width = 0
            self._pane_gutter = 0
            if len(left_lines) > max_lines:
                clipped: List[str] = left_lines[: max_lines - 1]
                clipped.append("  ... use HELP to refresh this pane")
                return clipped
            return left_lines

        gutter = 2
        left_width = width // 2
        if left_width < 64:
            left_width = 64
        right_width = width - left_width - gutter
        if right_width < 28:
            right_width = 28
            left_width = width - right_width - gutter
        self._pane_two_col = True
        self._pane_left_width = left_width
        self._pane_gutter = gutter

        right_lines = self._build_snapshot_pane_lines(right_width)
        if len(left_lines) > max_lines:
            left_lines = left_lines[: max_lines - 1] + ["  ... use HELP to refresh this pane"]
        if len(right_lines) > max_lines:
            right_lines = right_lines[: max_lines - 1] + ["... run SCAN to refresh"]

        merged: List[str] = []
        for index in range(max_lines):
            left = ""
            right = ""
            if index < len(left_lines):
                left = left_lines[index][:left_width].ljust(left_width)
            else:
                left = " " * left_width
            if index < len(right_lines):
                right = right_lines[index][:right_width]
            merged.append(f"{left}{' ' * gutter}{right}")
        return merged

    def _colorize_pinned_line(self, line: str) -> str:
        if self._style.end == "":
            return line

        if self._pane_two_col is False:
            return self._colorize_left_pane_text(line)

        left = line[: self._pane_left_width]
        middle = line[self._pane_left_width : self._pane_left_width + self._pane_gutter]
        right = line[self._pane_left_width + self._pane_gutter :]
        colored_left = self._colorize_left_pane_text(left)
        colored_right = self._colorize_right_pane_text(right)
        return f"{colored_left}{middle}{colored_right}"

    def _colorize_left_pane_text(self, text: str) -> str:
        stripped = text.strip()
        if len(stripped) == 0:
            return text

        if stripped.startswith("SCP11 Command Pane"):
            return f"{self._style.bold}{self._style.header}{text}{self._style.end}"
        if stripped.startswith("Core SCP11:") or stripped.startswith("SGP.22 / SGP.32:"):
            return f"{self._style.bold}{self._style.cyan}{text}{self._style.end}"
        if stripped.startswith("---"):
            return f"{self._style.header}{text}{self._style.end}"

        if text.startswith("  "):
            min_len = 2 + self.HELP_USAGE_WIDTH
            if len(text) >= min_len:
                usage = text[2 : 2 + self.HELP_USAGE_WIDTH]
                description = text[2 + self.HELP_USAGE_WIDTH :]
                return (
                    f"  {self._style.green}{usage}{self._style.end}"
                    f"{self._style.cyan}{description}{self._style.end}"
                )
            return f"{self._style.cyan}{text}{self._style.end}"

        return text

    def _colorize_right_pane_text(self, text: str) -> str:
        stripped = text.strip()
        if len(stripped) == 0:
            return text

        if stripped.startswith("Session Snapshot") or stripped.startswith("Profiles on Card:"):
            return f"{self._style.bold}{self._style.header}{text}{self._style.end}"
        if stripped.startswith("---"):
            return f"{self._style.header}{text}{self._style.end}"
        if stripped.startswith("ENABLED"):
            return f"{self._style.green}{text}{self._style.end}"
        if stripped.startswith("DISABLED"):
            return f"{self._style.yellow}{text}{self._style.end}"

        if ":" in text:
            lead_len = len(text) - len(text.lstrip(" "))
            lead = text[:lead_len]
            content = text[lead_len:]
            key, value = content.split(":", 1)
            return (
                f"{lead}{self._style.yellow}{key}:{self._style.end}"
                f"{self._style.cyan}{value}{self._style.end}"
            )
        return f"{self._style.cyan}{text}{self._style.end}"

    def _build_snapshot_pane_lines(self, width: int) -> List[str]:
        lines: List[str] = []
        lines.append("Session Snapshot")
        lines.append("-" * min(width, 38))

        snapshot = self._latest_snapshot
        if snapshot is None:
            lines.append("(snapshot not loaded)")
            return lines

        default_smdp = snapshot.configured_decoded.get("default_smdp", "")
        root_smds_primary = snapshot.configured_decoded.get("root_smds_primary", "")
        root_smds_additional = snapshot.configured_decoded.get("root_smds_additional", [])

        if len(default_smdp) == 0:
            default_smdp = "(not present)"
        if len(root_smds_primary) == 0:
            root_smds_primary = "(not present)"
        additional_smds = "(none)"
        if len(root_smds_additional) > 0:
            additional_smds = ", ".join(root_smds_additional)

        eid_value = snapshot.eid
        if len(eid_value) == 0:
            eid_value = "(unavailable)"
        issuer_value = format_ecasd_issuer_display(snapshot.issuer_name, snapshot.issuer_number)
        key_width = 19
        lines.append(f"{'EID':<{key_width}}: {eid_value}")
        lines.append(f"{'Issuer (eCASD)':<{key_width}}: {issuer_value}")
        lines.append(f"{'Card Default SM-DP+':<{key_width}}: {default_smdp}")
        lines.append(f"{'Root SM-DS':<{key_width}}: {root_smds_primary}")
        lines.append(f"{'Additional SM-DS':<{key_width}}: {additional_smds}")
        lines.append(f"{'Active Flow Target':<{key_width}}: {self.current_smdp_address}")
        lines.append(f"{'Active ES9 URL':<{key_width}}: {self.current_es9_base_url}")
        lines.append("")
        lines.append("Profiles on Card:")
        lines.append("State    Class ICCID                Nickname")
        lines.append("-" * min(width, 48))

        if len(snapshot.profiles) == 0:
            lines.append("(none decoded)")
            return lines

        max_profile_rows = 6
        profile_count = len(snapshot.profiles)
        shown = snapshot.profiles[:max_profile_rows]
        for row in shown:
            nickname_width = width - 37
            if nickname_width < 8:
                nickname_width = 8
            lines.append(
                f"{row.state:<8} {row.profile_class:<5} {row.iccid:<20} {row.nickname[:nickname_width]:<{nickname_width}}"
            )
            aid_alias = self._resolve_alias_for_aid(row.aid)
            if aid_alias is None:
                lines.append(f"  AID: {row.aid[: max(0, width - 7)]}")
            else:
                aid_text = f"{row.aid} ({aid_alias})"
                lines.append(f"  AID: {aid_text[: max(0, width - 7)]}")
        if profile_count > max_profile_rows:
            lines.append(f"... {profile_count - max_profile_rows} more profiles")
        return lines

    def _initialize_session(self) -> None:
        print(f"{self._style.cyan}[*] Connecting and loading SCP11 credentials...{self._style.end}")
        self.orchestrator._phase_connect()
        self.orchestrator._phase_load_credentials()
        print(f"{self._style.green}[+] SCP11 session initialized.{self._style.end}")

    def _print_start_snapshot(self, announce_when_pinned: bool = False) -> None:
        snapshot = self._collect_snapshot()
        self._latest_snapshot = snapshot

        if self._help_pane_locked:
            self._refresh_locked_help_pane()
            if announce_when_pinned:
                print("[*] Snapshot refreshed in pinned pane.")
            return

        print(f"\n{self._style.header}{'=' * 74}{self._style.end}")
        print(f"{self._style.bold}SCP11 Session Ready{self._style.end}")
        print(f"{self._style.header}{'=' * 74}{self._style.end}")
        print(
            f"EID:                "
            f"{self._style.cyan}{snapshot.eid if len(snapshot.eid) > 0 else '(unavailable)'}{self._style.end}"
        )
        print(
            f"Issuer (eCASD):     "
            f"{self._style.cyan}"
            f"{format_ecasd_issuer_display(snapshot.issuer_name, snapshot.issuer_number)}"
            f"{self._style.end}"
        )

        default_smdp = snapshot.configured_decoded.get("default_smdp", "")
        root_smds_primary = snapshot.configured_decoded.get("root_smds_primary", "")
        root_smds_additional = snapshot.configured_decoded.get("root_smds_additional", [])

        if len(default_smdp) == 0:
            default_smdp = "(not present)"
        if len(root_smds_primary) == 0:
            root_smds_primary = "(not present)"
        if len(root_smds_additional) == 0:
            additional_smds = "(none)"
        else:
            additional_smds = ", ".join(root_smds_additional)

        print(f"Card Default SM-DP+: {self._style.cyan}{default_smdp}{self._style.end}")
        print(f"Root SM-DS:          {self._style.cyan}{root_smds_primary}{self._style.end}")
        print(f"Additional SM-DS:    {self._style.cyan}{additional_smds}{self._style.end}")
        print(f"Active Flow Target:  {self._style.cyan}{self.current_smdp_address}{self._style.end}")
        print(f"Active ES9 Base URL: {self._style.cyan}{self.current_es9_base_url}{self._style.end}")
        self._print_profiles_table(snapshot.profiles, title="Profiles on Card")
        warning_text = hil_bridge_warning_text()
        if len(warning_text) > 0:
            print(f"{self._style.yellow}[!] {warning_text}{self._style.end}")

    def _print_help(self) -> None:
        print(f"\n{self._style.bold}{self._style.header}eSIM Relay Command Groups{self._style.end}")
        print(f"\n{self._style.cyan}--- Session & Utilities ---{self._style.end}")
        core_rows = self._get_core_help_rows()
        self._print_help_rows(core_rows)

        print(f"\n{self._style.header}--- SGP.22 / SGP.32 Operations ---{self._style.end}")
        extended_rows = self._get_extended_help_rows()
        self._print_help_rows(extended_rows)

    def _get_core_help_rows(self) -> List[Tuple[str, str]]:
        return [
            ("HELP", "Show command list"),
            ("SCAN", "Refresh card snapshot"),
            ("GET-EID", "Read and decode EID value"),
            ("STATUS", "Decode EuiccConfiguredData fields"),
            ("LIST", "List profiles with metadata"),
            ("GET-SMDP", "Show card default SM-DP+ and SM-DS roots"),
            ("SET-SMDP <address>", "Set default SM-DP+ address on card"),
            ("GET-ES9", "Show active ES9 base URL in tool"),
            ("SET-ES9 [--persist] <url>", "Set active ES9 base URL in tool"),
            ("SET-ES9-TLS [--persist] <on|off>", "Set ES9 TLS verification mode"),
            ("SET-ES9-CA [--persist] <pemPath|NONE>", "Set ES9 CA bundle path for TLS verification"),
            ("ES9-CERT-INFO", "Inspect ES9 server TLS certificate and trust status"),
            ("VERIFY-SCP11 [matchingId]", "Run SCP11 auth verification only"),
            ("FLOW [matchingId]", "Run SCP11 flow with active SM-DP+ target"),
            ("DOWNLOAD-AC <activation>", "Parse activation code and run FLOW"),
            ("EXIT", "Leave SCP11 shell"),
            ("QA", "Leave SCP11 shell and exit YggdraSIM"),
        ]

    def _get_extended_help_rows(self) -> List[Tuple[str, str]]:
        return [
            ("GET-EUICC-INFO1", "ES10a.GetEuiccInfo1"),
            ("GET-EUICC-INFO2", "ES10a.GetEuiccInfo2"),
            ("GET-RAT", "ES10b.GetRAT"),
            ("GET-NOTIFICATIONS", "ES10b.RetrieveNotificationsList"),
            ("REMOVE-NOTIFICATION <seq>", "ES10b.RemoveNotificationFromList"),
            ("ENABLE-PROFILE <id|aid|alias>", "ES10c.EnableProfile"),
            ("DISABLE-PROFILE <id|aid|alias>", "ES10c.DisableProfile"),
            ("DELETE-PROFILE <id|aid|alias>", "ES10c.DeleteProfile"),
            ("AIDS", "List AID aliases loaded from Admin registry"),
            ("READ-METADATA [22|32]", "Read profile metadata from GetProfilesInfo"),
            ("GET-POL <id|aid|alias>", "Read profilePolicyRules (PPR) from metadata"),
            ("SET-POL <id|aid|alias> <hex>", "Guarded profile policy update placeholder"),
            ("GET-METADATA <id|aid|alias>", "Read metadata for one profile"),
            ("STORE-METADATA <id|aid|alias> <hex>", "Guarded profile metadata update placeholder"),
            ("GET-CERTS", "ES10b.GetCerts"),
            ("GET-EIM-CONFIG", "ES10b.GetEimConfigurationData (SGP.32)"),
            ("EIM-DISCOVER", "SGP.32 eIM capability discovery"),
            ("EIM-AUTHENTICATE [matchingId]", "SGP.32/SGP.22 authentication phase"),
            ("EIM-DOWNLOAD [matchingId]", "SGP.32 eIM poll and relay flow"),
        ]

    def _split_command(self, line: str) -> Tuple[str, str]:
        parts = line.split(maxsplit=1)
        if len(parts) == 1:
            return parts[0], ""
        return parts[0], parts[1].strip()

    def _register_commands(self) -> None:
        self._add_command("HELP", "HELP", "Show command list", self._cmd_help, aliases=["H", "?"])
        self._add_command("SCAN", "SCAN", "Refresh card snapshot", self._cmd_scan, aliases=["INFO"])
        self._add_command("GET-EID", "GET-EID", "Read and decode EID value", self._cmd_get_eid)
        self._add_command("STATUS", "STATUS", "Decode EuiccConfiguredData fields", self._cmd_status)
        self._add_command("LIST", "LIST", "List profile metadata", self._cmd_list)
        self._add_command("GET-SMDP", "GET-SMDP", "Show default SM-DP+ values", self._cmd_get_smdp)
        self._add_command("GET-ES9", "GET-ES9", "Show active ES9 base URL", self._cmd_get_es9)
        self._add_command(
            "SET-ES9",
            "SET-ES9 [--persist] <url>",
            "Set active ES9 base URL",
            self._cmd_set_es9,
        )
        self._add_command(
            "SET-ES9-TLS",
            "SET-ES9-TLS [--persist] <on|off>",
            "Set ES9 TLS verification mode",
            self._cmd_set_es9_tls,
        )
        self._add_command(
            "SET-ES9-CA",
            "SET-ES9-CA [--persist] <pemPath|NONE>",
            "Set ES9 CA bundle path",
            self._cmd_set_es9_ca,
        )
        self._add_command(
            "ES9-CERT-INFO",
            "ES9-CERT-INFO",
            "Inspect ES9 TLS certificate",
            self._cmd_es9_cert_info,
        )
        self._add_command(
            "SET-SMDP",
            "SET-SMDP <address>",
            "Set default SM-DP+ address on card",
            self._cmd_set_smdp,
        )
        self._add_command(
            "VERIFY-SCP11",
            "VERIFY-SCP11 [matchingId]",
            "Run SCP11 auth verification only",
            self._cmd_verify_scp11,
        )
        self._add_command("FLOW", "FLOW [matchingId]", "Run SCP11 flow", self._cmd_flow)
        self._add_command(
            "DOWNLOAD-AC",
            "DOWNLOAD-AC <activation>",
            "Parse activation code and run FLOW",
            self._cmd_download_activation_code,
        )
        self._add_command("EXIT", "EXIT", "Leave SCP11 shell", self._cmd_exit, aliases=["QUIT", "Q"])
        self._add_command("QA", "QA", "Leave SCP11 shell and exit YggdraSIM", self._cmd_quit_all)

        self._add_command("GET-EUICC-INFO1", "GET-EUICC-INFO1", "ES10a.GetEuiccInfo1", self._cmd_get_euicc_info1)
        self._add_command("GET-EUICC-INFO2", "GET-EUICC-INFO2", "ES10a.GetEuiccInfo2", self._cmd_get_euicc_info2)
        self._add_command("GET-RAT", "GET-RAT", "ES10b.GetRAT", self._cmd_get_rat)
        self._add_command(
            "GET-NOTIFICATIONS",
            "GET-NOTIFICATIONS",
            "ES10b.RetrieveNotificationsList",
            self._cmd_get_notifications,
        )
        self._add_command(
            "REMOVE-NOTIFICATION",
            "REMOVE-NOTIFICATION <seq>",
            "ES10b.RemoveNotificationFromList",
            self._cmd_remove_notification,
        )
        self._add_command("ENABLE-PROFILE", "ENABLE-PROFILE <iccid-or-aid>", "ES10c.EnableProfile", self._cmd_enable_profile)
        self._add_command(
            "DISABLE-PROFILE",
            "DISABLE-PROFILE <iccid-or-aid>",
            "ES10c.DisableProfile",
            self._cmd_disable_profile,
        )
        self._add_command(
            "DELETE-PROFILE",
            "DELETE-PROFILE <iccid-or-aid>",
            "ES10c.DeleteProfile",
            self._cmd_delete_profile,
        )
        self._add_command("AIDS", "AIDS", "List AID aliases loaded from Admin registry", self._cmd_aids)
        self._add_command("READ-METADATA", "READ-METADATA [22|32]", "Read metadata", self._cmd_read_metadata)
        self._add_command("GET-POL", "GET-POL <id|aid|alias>", "Read profile policy", self._cmd_get_pol)
        self._add_command("SET-POL", "SET-POL <id|aid|alias> <hex>", "Guarded POL update", self._cmd_set_pol)
        self._add_command("GET-METADATA", "GET-METADATA <id|aid|alias>", "Read profile metadata", self._cmd_get_metadata)
        self._add_command(
            "STORE-METADATA",
            "STORE-METADATA <id|aid|alias> <hex>",
            "Guarded metadata update",
            self._cmd_store_metadata,
        )
        self._add_command("GET-CERTS", "GET-CERTS", "ES10b.GetCerts", self._cmd_get_certs)
        self._add_command(
            "GET-EIM-CONFIG",
            "GET-EIM-CONFIG",
            "ES10b.GetEimConfigurationData (SGP.32)",
            self._cmd_get_eim_config,
        )
        self._add_command("EIM-DISCOVER", "EIM-DISCOVER", "SGP.32 eIM capability discovery", self._cmd_eim_discover)
        self._add_command(
            "EIM-AUTHENTICATE",
            "EIM-AUTHENTICATE [matchingId]",
            "SGP.32/SGP.22 authentication phase",
            self._cmd_eim_authenticate,
        )
        self._add_command(
            "EIM-DOWNLOAD",
            "EIM-DOWNLOAD [matchingId]",
            "SGP.32 eIM poll and relay flow",
            self._cmd_eim_download,
        )

    def _add_command(
        self,
        name: str,
        usage: str,
        description: str,
        handler: Callable[[str], bool],
        aliases: Optional[List[str]] = None,
    ) -> None:
        spec = CommandSpec(
            name=name,
            usage=usage,
            description=description,
            handler=handler,
            scaffold=False,
        )
        self._commands[name] = spec
        self._primary_commands.append(name)

        if aliases is not None:
            for alias in aliases:
                self._commands[alias] = spec

    def _cmd_help(self, _: str) -> bool:
        if self._help_pane_locked:
            self._refresh_locked_help_pane()
            print("[*] Help pane refreshed (pinned on top half).")
        else:
            self._print_help()
        return True

    def _cmd_scan(self, _: str) -> bool:
        self._print_start_snapshot(announce_when_pinned=True)
        return True

    def _cmd_get_eid(self, _: str) -> bool:
        eid = self._get_eid()
        if len(eid) == 0:
            print("[*] EID: (unavailable)")
            return True
        print(f"[*] EID: {eid}")
        return True

    def _cmd_status(self, _: str) -> bool:
        self._print_configured_status()
        return True

    def _cmd_list(self, _: str) -> bool:
        self._print_profiles()
        return True

    def _cmd_get_smdp(self, _: str) -> bool:
        self._get_smdp_address()
        return True

    def _cmd_set_smdp(self, argument: str) -> bool:
        self._set_smdp_address(argument)
        return True

    def _cmd_get_es9(self, _: str) -> bool:
        self._print_es9_base_url()
        return True

    def _cmd_set_es9(self, argument: str) -> bool:
        tokens = argument.strip().split()
        if len(tokens) == 0:
            print("[!] Usage: SET-ES9 [--persist] <https://host[:port][/base]>")
            return True

        persist = False
        url_tokens: List[str] = []
        for token in tokens:
            if token == "--persist":
                persist = True
                continue
            url_tokens.append(token)

        if len(url_tokens) != 1:
            print("[!] Usage: SET-ES9 [--persist] <https://host[:port][/base]>")
            return True

        url_text = url_tokens[0]
        if url_text.lower().startswith("http://") is False and url_text.lower().startswith("https://") is False:
            print("[!] ES9 URL must start with http:// or https://")
            return True

        set_ok = self._set_es9_base_url(url_text, source="manual")
        if set_ok is False:
            return True

        if persist:
            self._persist_es9_base_url(self.current_es9_base_url)
        return True

    def _cmd_set_es9_tls(self, argument: str) -> bool:
        tokens = argument.strip().split()
        if len(tokens) == 0:
            print("[!] Usage: SET-ES9-TLS [--persist] <on|off>")
            return True

        persist = False
        mode_tokens: List[str] = []
        for token in tokens:
            if token == "--persist":
                persist = True
                continue
            mode_tokens.append(token)

        if len(mode_tokens) != 1:
            print("[!] Usage: SET-ES9-TLS [--persist] <on|off>")
            return True

        value = mode_tokens[0].strip().lower()
        if value in ["on", "true", "1", "yes"]:
            enabled = True
        elif value in ["off", "false", "0", "no"]:
            enabled = False
        else:
            print("[!] TLS mode must be on|off.")
            return True

        set_ok = self._set_es9_tls_verify(enabled)
        if set_ok is False:
            return True

        if persist:
            self._persist_es9_verify_tls(self.current_es9_verify_tls)
        return True

    def _cmd_set_es9_ca(self, argument: str) -> bool:
        tokens = argument.strip().split()
        if len(tokens) == 0:
            print("[!] Usage: SET-ES9-CA [--persist] <pemPath|NONE>")
            return True

        persist = False
        path_tokens: List[str] = []
        for token in tokens:
            if token == "--persist":
                persist = True
                continue
            path_tokens.append(token)

        if len(path_tokens) != 1:
            print("[!] Usage: SET-ES9-CA [--persist] <pemPath|NONE>")
            return True

        ca_input = path_tokens[0].strip()
        if ca_input.upper() == "NONE":
            ca_input = ""

        set_ok = self._set_es9_ca_bundle_path(ca_input)
        if set_ok is False:
            return True

        if persist:
            self._persist_es9_ca_bundle_path(self.current_es9_ca_bundle_path)
        return True

    def _cmd_es9_cert_info(self, _: str) -> bool:
        self._print_es9_cert_info()
        return True

    def _cmd_flow(self, argument: str) -> bool:
        self._run_full_flow(argument)
        return True

    def _cmd_verify_scp11(self, argument: str) -> bool:
        matching_id = argument.strip()
        self._verify_scp11_authentication(matching_id=matching_id)
        return True

    def _cmd_download_activation_code(self, argument: str) -> bool:
        self._download_activation_code(argument)
        return True

    def _cmd_exit(self, _: str) -> bool:
        self._save_history()
        print(f"{self._style.cyan}[*] Session closed.{self._style.end}")
        return False

    def _cmd_quit_all(self, _: str) -> bool:
        self._save_history()
        print(f"{self._style.cyan}[*] Session closed.{self._style.end}")
        quit_all()

    def _cmd_scaffold(self, command_name: str) -> bool:
        print(
            f"{self._style.yellow}[*] {command_name} is scaffolded and reserved for upcoming "
            f"SGP.22/SGP.32 expansion.{self._style.end}"
        )
        print(f"{self._style.yellow}[*] Keep using SCAN / STATUS / LIST / FLOW for now.{self._style.end}")
        return True

    def _cmd_get_euicc_info1(self, _: str) -> bool:
        self._run_retrieve_command("GetEuiccInfo1", bytes.fromhex("BF2000"), root_tag=0xBF20)
        return True

    def _cmd_get_euicc_info2(self, _: str) -> bool:
        self._run_retrieve_command("GetEuiccInfo2", bytes.fromhex("BF2200"), root_tag=0xBF22)
        return True

    def _cmd_get_rat(self, _: str) -> bool:
        self._run_retrieve_command("GetRAT", bytes.fromhex("BF4300"), root_tag=0xBF43)
        return True

    def _cmd_get_notifications(self, _: str) -> bool:
        self._run_retrieve_command("RetrieveNotificationsList", bytes.fromhex("BF2B00"), root_tag=0xBF2B)
        return True

    def _cmd_remove_notification(self, argument: str) -> bool:
        seq_text = argument.strip()
        if len(seq_text) == 0:
            print("[!] Usage: REMOVE-NOTIFICATION <seq>")
            return True

        seq_value = self._parse_integer_value(seq_text)
        if seq_value is None:
            print("[!] Sequence number must be decimal or hex (prefix 0x).")
            return True
        if seq_value < 0:
            print("[!] Sequence number must be non-negative.")
            return True

        payload = self._build_remove_notification_payload(seq_value)
        self._execute_result_command(
            title=f"RemoveNotificationFromList seq={seq_value}",
            payload=payload,
            result_outer_tag=self.TAG_REMOVE_NOTIFICATION,
        )
        return True

    def _cmd_enable_profile(self, argument: str) -> bool:
        self._run_profile_state_command(
            identifier=argument.strip(),
            func_tag=self.TAG_ENABLE_PROFILE,
            action_label="EnableProfile",
            command_name="ENABLE-PROFILE",
        )
        return True

    def _cmd_disable_profile(self, argument: str) -> bool:
        self._run_profile_state_command(
            identifier=argument.strip(),
            func_tag=self.TAG_DISABLE_PROFILE,
            action_label="DisableProfile",
            command_name="DISABLE-PROFILE",
        )
        return True

    def _cmd_delete_profile(self, argument: str) -> bool:
        self._run_profile_state_command(
            identifier=argument.strip(),
            func_tag=self.TAG_DELETE_PROFILE,
            action_label="DeleteProfile",
            command_name="DELETE-PROFILE",
        )
        return True

    def _cmd_aids(self, _: str) -> bool:
        self._print_aid_registry()
        return True

    def _cmd_read_metadata(self, argument: str) -> bool:
        _ = argument
        entries = self._collect_profile_metadata()
        print(f"\n{self._style.bold}[+] Profile Metadata Summary{self._style.end}")
        if len(entries) == 0:
            print("    | (No metadata entries)")
            return True

        print("ICCID                 AID / Alias                               State     Class  PPR")
        print("-" * 104)
        for entry in entries:
            aid_alias = self._resolve_alias_for_aid(entry.aid)
            aid_display = entry.aid
            if aid_alias is not None:
                aid_display = f"{entry.aid} ({aid_alias})"
            ppr_display = entry.profile_policy_rules_hex
            if len(ppr_display) == 0:
                ppr_display = "-"
            print(
                f"{entry.iccid:<20} {aid_display[:40]:<40} {entry.state:<9} "
                f"{entry.profile_class:<6} {ppr_display}"
            )
        return True

    def _cmd_get_pol(self, argument: str) -> bool:
        target = argument.strip()
        if len(target) == 0:
            print("[!] Usage: GET-POL <id|aid|alias>")
            return True

        metadata = self._find_profile_metadata(target)
        if metadata is None:
            print(f"{self._style.red}[!] Profile target not found: {target}{self._style.end}")
            return True

        print(f"\n{self._style.bold}[+] Profile Policy Rules{self._style.end}")
        print(f"    | ICCID               : {metadata.iccid}")
        print(f"    | AID                 : {metadata.aid}")
        if len(metadata.profile_policy_rules_hex) == 0:
            print("    | PPR Raw             : (not present)")
            print("    | Decoded             : none")
            return True

        decoded = self._decode_ppr_ids(metadata.profile_policy_rules_hex)
        print(f"    | PPR Raw             : {metadata.profile_policy_rules_hex}")
        print(f"    | Decoded             : {decoded}")
        return True

    def _cmd_set_pol(self, argument: str) -> bool:
        parts = argument.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("[!] Usage: SET-POL <id|aid|alias> <polHex>")
            return True
        target = parts[0]
        pol_hex = parts[1].strip().upper()
        if self._is_hex(pol_hex) is False:
            print("[!] POL payload must be valid hex.")
            return True
        print(f"{self._style.yellow}[*] SET-POL requested for target: {target}{self._style.end}")
        self._print_guarded_provisioning_message()
        return True

    def _cmd_get_metadata(self, argument: str) -> bool:
        target = argument.strip()
        if len(target) == 0:
            print("[!] Usage: GET-METADATA <id|aid|alias>")
            return True

        metadata = self._find_profile_metadata(target)
        if metadata is None:
            print(f"{self._style.red}[!] Profile target not found: {target}{self._style.end}")
            return True

        print(f"\n{self._style.bold}[+] Profile Metadata{self._style.end}")
        print(f"    | ICCID               : {metadata.iccid}")
        aid_alias = self._resolve_alias_for_aid(metadata.aid)
        aid_display = metadata.aid
        if aid_alias is not None:
            aid_display = f"{metadata.aid} ({aid_alias})"
        print(f"    | AID                 : {aid_display}")
        print(f"    | State               : {metadata.state}")
        print(f"    | Profile Class       : {metadata.profile_class}")
        print(f"    | Nickname            : {metadata.nickname}")
        print(f"    | Service Provider    : {metadata.service_provider}")
        print(f"    | Profile Name        : {metadata.profile_name}")
        ppr_display = metadata.profile_policy_rules_hex
        if len(ppr_display) == 0:
            ppr_display = "(not present)"
        print(f"    | Profile Policy Rules: {ppr_display}")
        return True

    def _cmd_store_metadata(self, argument: str) -> bool:
        parts = argument.strip().split(maxsplit=1)
        if len(parts) < 2:
            print("[!] Usage: STORE-METADATA <id|aid|alias> <metadataHex>")
            return True
        metadata_hex = parts[1].strip().upper()
        if self._is_hex(metadata_hex) is False:
            print("[!] Metadata payload must be valid hex.")
            return True
        target = parts[0]
        print(f"{self._style.yellow}[*] STORE-METADATA requested for target: {target}{self._style.end}")
        self._print_guarded_provisioning_message()
        return True

    def _cmd_get_certs(self, _: str) -> bool:
        self._run_retrieve_command("GetCerts", bytes.fromhex("BF5600"), root_tag=0xBF56)
        return True

    def _cmd_get_eim_config(self, _: str) -> bool:
        self._run_retrieve_command("GetEimConfigurationData", bytes.fromhex("BF5500"), root_tag=0xBF55)
        return True

    def _cmd_eim_discover(self, _: str) -> bool:
        print(f"{self._style.cyan}[*] Running SGP.32 discovery retrieval sequence...{self._style.end}")
        self._cmd_get_eim_config("")
        self._cmd_get_certs("")
        self._cmd_get_rat("")
        self._cmd_get_notifications("")
        return True

    def _cmd_eim_authenticate(self, argument: str) -> bool:
        matching_id = argument.strip()
        print(f"{self._style.cyan}[*] Running authentication phase only...{self._style.end}")
        try:
            self.orchestrator._phase_connect()
            self.orchestrator._bootstrap_es10b_logical_channel()
            self.orchestrator._phase_load_credentials()
            auth_seed = self.orchestrator._phase_authentication_seed(
                matching_id=matching_id,
                smdp_address=self.current_smdp_address,
            )
            self.orchestrator._phase_authenticate_server(auth_seed, matching_id=matching_id)
        except Exception as error:
            print(f"{self._style.red}[!] EIM-AUTHENTICATE failed: {error}{self._style.end}")
            return True

        transaction_id_hex = self.orchestrator.state.transaction_id.hex().upper()
        if len(transaction_id_hex) == 0:
            transaction_id_hex = "(not available)"
        print(f"{self._style.green}[+] Authentication phase completed.{self._style.end}")
        print(f"[*] Transaction ID: {transaction_id_hex}")
        return True

    def _cmd_eim_download(self, argument: str) -> bool:
        matching_id = argument.strip()
        if "$" in matching_id:
            parsed = self._parse_activation_code(matching_id)
            if parsed is not None:
                print(
                    f"{self._style.yellow}[*] Activation code detected. Redirecting to DOWNLOAD-AC flow.{self._style.end}"
                )
                self._download_activation_code(matching_id)
                return True
        print(f"{self._style.cyan}[*] Running eIM poll and relay flow...{self._style.end}")
        try:
            self.orchestrator.run_eim_poll(matching_id=matching_id)
        except Exception as error:
            print(f"{self._style.red}[!] EIM-DOWNLOAD failed: {error}{self._style.end}")
            return True
        reached_server = bool(
            getattr(self.orchestrator, "_last_eim_poll_reached_server", False)
        )
        if reached_server:
            print(f"{self._style.green}[+] eIM poll flow completed.{self._style.end}")
        else:
            print(
                f"{self._style.yellow}[*] eIM poll flow completed without reaching any configured "
                f"eIM server.{self._style.end}"
            )
        return True

    def _collect_snapshot(self) -> CardSnapshot:
        eid = self._get_eid()
        self.current_eid = eid
        issuer_identity = infer_ecasd_issuer_from_eid(eid)
        configured_raw = self._get_configured_addresses_raw()
        configured_decoded = self._decode_euicc_configured_data(configured_raw)
        profiles = self._fetch_profiles()

        inventory_profile = self._inventory.load(eid)
        inventory_target_loaded = False
        inventory_es9_loaded = False
        if len(eid) > 0 and len(inventory_profile) > 0:
            inventory_target_loaded, inventory_es9_loaded = self._apply_inventory_profile(inventory_profile)

        card_default_smdp = configured_decoded.get("default_smdp", "")
        if len(card_default_smdp) > 0:
            if inventory_target_loaded is False:
                self.current_smdp_address = card_default_smdp
            if inventory_es9_loaded is False:
                self._apply_es9_autoderive_from_card(card_default_smdp)
        else:
            if inventory_es9_loaded is False:
                self._warn_es9_placeholder_without_card_default()

        return CardSnapshot(
            eid=eid,
            issuer_number=str(issuer_identity.get("issuer_number", "")).strip(),
            issuer_name=str(issuer_identity.get("issuer_name", "")).strip(),
            configured_raw=configured_raw,
            configured_decoded=configured_decoded,
            profiles=profiles,
        )

    def _get_eid(self) -> str:
        try:
            payload = _build_tlv(bytes.fromhex("BF3E"), _build_tlv(bytes.fromhex("5C"), bytes.fromhex("5A")))
            apdu = self._build_store_data_apdu(payload)
            response = self.apdu_channel.send(apdu, "GET: EID")
            parsed = self._parse_tlv_simple(response)
            root_value = self._first_bytes(parsed.get(0xBF3E))
            if root_value is None:
                return response.hex().upper()
            inner = self._parse_tlv_simple(root_value)
            eid_value = self._first_bytes(inner.get(0x5A))
            if eid_value is None:
                return response.hex().upper()
            return eid_value.hex().upper()
        except Exception as error:
            print(f"{self._style.red}[!] Could not read EID: {error}{self._style.end}")
            return ""

    def _get_configured_addresses_raw(self) -> bytes:
        try:
            payload = bytes.fromhex("BF3C00")
            apdu = self._build_store_data_apdu(payload)
            response = self.apdu_channel.send(apdu, "GET: EuiccConfiguredData")
            return response
        except Exception as error:
            print(f"{self._style.red}[!] Could not read EuiccConfiguredData: {error}{self._style.end}")
            return b""

    def _get_smdp_address(self) -> None:
        raw_data = self._get_configured_addresses_raw()
        decoded = self._decode_euicc_configured_data(raw_data)

        default_smdp = decoded.get("default_smdp", "")
        root_smds_primary = decoded.get("root_smds_primary", "")
        root_smds_additional = decoded.get("root_smds_additional", [])

        print(f"\n{self._style.bold}--- Card Configured Addresses ---{self._style.end}")
        if len(default_smdp) > 0:
            print(f"{self._style.green}[+] Default SM-DP+: {default_smdp}{self._style.end}")
        else:
            print("[*] Default SM-DP+: (not present)")

        if len(root_smds_primary) > 0:
            print(f"{self._style.green}[+] Root SM-DS: {root_smds_primary}{self._style.end}")
        else:
            print("[*] Root SM-DS: (not present)")

        if len(root_smds_additional) == 0:
            print("[*] Additional Root SM-DS: (none)")
        else:
            for index, value in enumerate(root_smds_additional, start=1):
                print(f"{self._style.green}[+] Additional Root SM-DS #{index}: {value}{self._style.end}")

        print(f"[*] Raw EuiccConfiguredData: {raw_data.hex().upper()}")

    def _print_configured_status(self) -> None:
        raw_data = self._get_configured_addresses_raw()
        decoded = self._decode_euicc_configured_data(raw_data)

        print(f"\n{self._style.bold}=== STATUS: EuiccConfiguredData ==={self._style.end}")
        print(f"Active FLOW target: {self.current_smdp_address}")
        print(f"Active ES9 base URL: {self.current_es9_base_url}")

        default_smdp = decoded.get("default_smdp", "")
        root_smds_primary = decoded.get("root_smds_primary", "")
        root_smds_additional = decoded.get("root_smds_additional", [])
        allowed_ci_pkids = decoded.get("allowed_ci_pkid", [])

        if len(default_smdp) > 0:
            print(f"SM-DP+ (default):       {default_smdp}")
        else:
            print("SM-DP+ (default):       (not present)")

        if len(root_smds_primary) > 0:
            print(f"SM-DS (root):           {root_smds_primary}")
        else:
            print("SM-DS (root):           (not present)")

        if len(root_smds_additional) == 0:
            print("SM-DS (additional):     (none)")
        else:
            for index, value in enumerate(root_smds_additional, start=1):
                print(f"SM-DS (additional #{index}): {value}")

        if len(allowed_ci_pkids) == 0:
            print("Allowed CI PKID values: (none)")
        else:
            for index, value in enumerate(allowed_ci_pkids, start=1):
                print(f"Allowed CI PKID #{index}: {value}")

        print(f"Raw EuiccConfiguredData: {raw_data.hex().upper()}")

    def _set_smdp_address(self, address: str) -> None:
        address_text = address.strip()
        if len(address_text) == 0:
            print("[!] Usage: SET-SMDP <fqdn-or-address>")
            return

        try:
            encoded_address = address_text.encode("utf-8")
            inner = _build_tlv(bytes.fromhex("80"), encoded_address)
            payload = _build_tlv(bytes.fromhex("BF3F"), inner)
            apdu = self._build_store_data_apdu(payload)
            response = self.apdu_channel.send(apdu, "SET: Default SM-DP+ Address")
            print(
                f"{self._style.green}[+] Default SM-DP+ APDU response: "
                f"{response.hex().upper()}{self._style.end}"
            )
            verified_raw = self._get_configured_addresses_raw()
            verified = self._decode_euicc_configured_data(verified_raw)
            card_default_smdp = str(verified.get("default_smdp", "")).strip()
            if len(card_default_smdp) == 0:
                self.current_smdp_address = address_text
                self._persist_inventory_profile()
                print(
                    f"{self._style.yellow}[*] Could not verify updated card SM-DP+ value. "
                    f"Active target kept as requested: {self.current_smdp_address}{self._style.end}"
                )
                return
            self.current_smdp_address = card_default_smdp
            self._persist_inventory_profile()
            if card_default_smdp == address_text:
                print(
                    f"{self._style.green}[+] Card default SM-DP+ verified as: "
                    f"{self.current_smdp_address}{self._style.end}"
                )
                return
            print(
                f"{self._style.yellow}[*] Card default SM-DP+ remains: "
                f"{card_default_smdp}{self._style.end}"
            )
            print(
                f"{self._style.yellow}[*] Requested value was not persisted on card: "
                f"{address_text}{self._style.end}"
            )
        except Exception as error:
            print(f"{self._style.red}[!] Failed to set SM-DP+ address: {error}{self._style.end}")

    def _print_es9_base_url(self) -> None:
        print(f"[*] Active ES9 base URL: {self.current_es9_base_url}")
        tls_mode = "ON"
        if self.current_es9_verify_tls is False:
            tls_mode = "OFF"
        print(f"[*] ES9 TLS verify: {tls_mode}")
        ca_path = self.current_es9_ca_bundle_path
        if len(ca_path.strip()) == 0:
            ca_path = "(system trust store)"
        print(f"[*] ES9 CA bundle: {ca_path}")
        if self._is_placeholder_es9_url(self.current_es9_base_url):
            print(f"{self._style.yellow}[*] Warning: ES9 base URL still points to placeholder host.{self._style.end}")

    def _print_es9_cert_info(self) -> None:
        parsed = urlparse(self.current_es9_base_url)
        hostname = parsed.hostname
        port = parsed.port
        if port is None:
            if parsed.scheme.lower() == "https":
                port = 443
            else:
                port = 80

        if hostname is None or len(hostname.strip()) == 0:
            print(f"{self._style.red}[!] Invalid ES9 URL: {self.current_es9_base_url}{self._style.end}")
            return

        print(f"\n{self._style.bold}=== ES9 TLS Certificate Info ==={self._style.end}")
        print(f"Endpoint: {hostname}:{port}")
        print(f"URL:      {self.current_es9_base_url}")

        verify_ok, verify_error = self._probe_es9_tls_verify(hostname, port)
        if verify_ok:
            print(f"{self._style.green}[+] TLS verify result: PASS{self._style.end}")
        else:
            print(f"{self._style.red}[-] TLS verify result: FAIL{self._style.end}")
            print(f"    Reason: {verify_error}")

        cert_der = self._fetch_server_leaf_certificate(hostname, port)
        if cert_der is None:
            print(f"{self._style.red}[!] Could not fetch server certificate details.{self._style.end}")
            return

        cert_dict = self._decode_leaf_certificate_dict(hostname, port)
        fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
        print(f"Leaf SHA256: {fingerprint}")

        if cert_dict is None:
            print("[*] Leaf certificate parsed in binary form only.")
            return

        subject = cert_dict.get("subject")
        issuer = cert_dict.get("issuer")
        not_before = cert_dict.get("notBefore", "")
        not_after = cert_dict.get("notAfter", "")
        san = cert_dict.get("subjectAltName", [])

        print(f"Subject:    {self._format_x509_name(subject)}")
        print(f"Issuer:     {self._format_x509_name(issuer)}")
        if len(not_before) > 0:
            print(f"Not Before: {not_before}")
        if len(not_after) > 0:
            print(f"Not After:  {not_after}")

        dns_names: List[str] = []
        for entry in san:
            if isinstance(entry, tuple) and len(entry) == 2:
                if str(entry[0]).upper() == "DNS":
                    dns_names.append(str(entry[1]))
        if len(dns_names) > 0:
            joined = ", ".join(dns_names[:8])
            print(f"SAN DNS:    {joined}")

    def _probe_es9_tls_verify(self, hostname: str, port: int) -> Tuple[bool, str]:
        context = ssl.create_default_context()
        if len(self.current_es9_ca_bundle_path.strip()) > 0:
            try:
                context = ssl.create_default_context(cafile=self.current_es9_ca_bundle_path)
            except Exception as error:
                return False, f"invalid CA bundle ({error})"

        try:
            with socket.create_connection((hostname, port), timeout=8) as tcp_socket:
                with context.wrap_socket(tcp_socket, server_hostname=hostname):
                    pass
        except Exception as error:
            return False, str(error)
        return True, ""

    def _fetch_server_leaf_certificate(self, hostname: str, port: int) -> Optional[bytes]:
        context = create_introspection_context(caller="SCP11.console/fetch_leaf")
        try:
            with socket.create_connection((hostname, port), timeout=8) as tcp_socket:
                with context.wrap_socket(tcp_socket, server_hostname=hostname) as tls_socket:
                    return tls_socket.getpeercert(binary_form=True)
        except Exception as error:
            print(f"{self._style.red}[!] TLS fetch failed: {error}{self._style.end}")
            return None

    def _decode_leaf_certificate_dict(self, hostname: str, port: int) -> Optional[Dict[str, Any]]:
        context = create_introspection_context(caller="SCP11.console/decode_leaf")
        try:
            with socket.create_connection((hostname, port), timeout=8) as tcp_socket:
                with context.wrap_socket(tcp_socket, server_hostname=hostname) as tls_socket:
                    cert = tls_socket.getpeercert()
                    if isinstance(cert, dict):
                        return cert
                    return None
        except Exception:
            return None

    def _format_x509_name(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, tuple) is False:
            return str(value)
        parts: List[str] = []
        for item in value:
            if isinstance(item, tuple) is False:
                continue
            for pair in item:
                if isinstance(pair, tuple) and len(pair) == 2:
                    parts.append(f"{pair[0]}={pair[1]}")
        return ", ".join(parts)

    def _set_es9_base_url(self, base_url: str, source: str) -> bool:
        normalized = base_url.strip().rstrip("/")
        if len(normalized) == 0:
            print("[!] ES9 base URL cannot be empty.")
            return False

        provider = self.orchestrator.profile_provider
        if hasattr(provider, "set_base_url") is False:
            print(
                f"{self._style.yellow}[*] Active provider does not support runtime ES9 URL updates.{self._style.end}"
            )
            print(f"[*] Requested ES9 base URL was: {normalized}")
            return False

        try:
            provider.set_base_url(normalized)
            self.current_es9_base_url = normalized
            if source == "manual":
                self._persist_inventory_profile()
            if source == "auto":
                print(
                    f"{self._style.green}[+] Auto-derived ES9 base URL from card SM-DP+: "
                    f"{normalized}{self._style.end}"
                )
            else:
                print(f"{self._style.green}[+] Active ES9 base URL set to: {normalized}{self._style.end}")
            if self._is_placeholder_es9_url(self.current_es9_base_url):
                print(f"{self._style.yellow}[*] Warning: placeholder ES9 host still configured.{self._style.end}")
            return True
        except Exception as error:
            print(f"{self._style.red}[!] Failed to set ES9 base URL: {error}{self._style.end}")
            return False

    def _set_es9_tls_verify(self, enabled: bool) -> bool:
        provider = self.orchestrator.profile_provider
        if hasattr(provider, "set_verify_tls") is False:
            print(
                f"{self._style.yellow}[*] Active provider does not support ES9 TLS mode updates.{self._style.end}"
            )
            return False
        try:
            provider.set_verify_tls(enabled)
            self.current_es9_verify_tls = enabled
            self._persist_inventory_profile()
            mode = "ON"
            if enabled is False:
                mode = "OFF"
            print(f"{self._style.green}[+] ES9 TLS verification is now: {mode}{self._style.end}")
            return True
        except Exception as error:
            print(f"{self._style.red}[!] Failed to set ES9 TLS mode: {error}{self._style.end}")
            return False

    def _set_es9_ca_bundle_path(self, path: str) -> bool:
        provider = self.orchestrator.profile_provider
        if hasattr(provider, "set_ca_bundle_path") is False:
            print(
                f"{self._style.yellow}[*] Active provider does not support ES9 CA bundle updates.{self._style.end}"
            )
            return False
        try:
            provider.set_ca_bundle_path(path)
            self.current_es9_ca_bundle_path = path.strip()
            self._persist_inventory_profile()
            if len(self.current_es9_ca_bundle_path) == 0:
                print(f"{self._style.green}[+] ES9 CA bundle cleared (using system trust store).{self._style.end}")
            else:
                print(
                    f"{self._style.green}[+] ES9 CA bundle set to: "
                    f"{self.current_es9_ca_bundle_path}{self._style.end}"
                )
            return True
        except Exception as error:
            print(f"{self._style.red}[!] Failed to set ES9 CA bundle: {error}{self._style.end}")
            return False

    def _persist_es9_base_url(self, base_url: str) -> None:
        escaped_url = base_url.replace("\\", "\\\\").replace('"', '\\"')
        self._persist_config_line("ES9_BASE_URL: str =", f'"{escaped_url}"', "ES9_BASE_URL")

    def _persist_es9_verify_tls(self, enabled: bool) -> None:
        literal = "True"
        if enabled is False:
            literal = "False"
        self._persist_config_line("ES9_VERIFY_TLS: bool =", literal, "ES9_VERIFY_TLS")

    def _persist_es9_ca_bundle_path(self, path: str) -> None:
        escaped_path = path.replace("\\", "\\\\").replace('"', '\\"')
        self._persist_config_line("ES9_CA_BUNDLE_PATH: str =", f'"{escaped_path}"', "ES9_CA_BUNDLE_PATH")

    def _inventory_payload(self) -> Dict[str, Any]:
        return {
            "smdp_address": self.current_smdp_address,
            "es9_base_url": self.current_es9_base_url,
            "es9_verify_tls": bool(self.current_es9_verify_tls),
            "es9_ca_bundle_path": self.current_es9_ca_bundle_path,
        }

    def _apply_inventory_profile(self, profile: Dict[str, Any]) -> Tuple[bool, bool]:
        provider = self.orchestrator.profile_provider
        target_loaded = False
        es9_loaded = False

        stored_target = str(profile.get("smdp_address", "")).strip()
        if len(stored_target) > 0:
            self.current_smdp_address = stored_target
            target_loaded = True

        stored_url = str(profile.get("es9_base_url", "")).strip().rstrip("/")
        if len(stored_url) > 0:
            self.current_es9_base_url = stored_url
            if hasattr(provider, "set_base_url"):
                try:
                    provider.set_base_url(stored_url)
                except Exception:
                    pass
            es9_loaded = True

        if "es9_verify_tls" in profile:
            stored_verify_tls = bool(profile.get("es9_verify_tls"))
            self.current_es9_verify_tls = stored_verify_tls
            if hasattr(provider, "set_verify_tls"):
                try:
                    provider.set_verify_tls(stored_verify_tls)
                except Exception:
                    pass

        if "es9_ca_bundle_path" in profile:
            stored_ca_bundle_path = str(profile.get("es9_ca_bundle_path", "")).strip()
            self.current_es9_ca_bundle_path = stored_ca_bundle_path
            if hasattr(provider, "set_ca_bundle_path"):
                try:
                    provider.set_ca_bundle_path(stored_ca_bundle_path)
                except Exception:
                    pass

        return target_loaded, es9_loaded

    def _persist_inventory_profile(self) -> None:
        if len(self.current_eid) == 0:
            return
        self._inventory.replace(self.current_eid, self._inventory_payload())

    def _apply_module_state_profile(self) -> None:
        try:
            payload = self._inventory.store.get_module_state(self.MODULE_STATE_NAME)
        except Exception:
            return
        if isinstance(payload, dict) is False or len(payload) == 0:
            return
        self._apply_inventory_profile(payload)

    def _persist_config_line(self, key_prefix: str, literal_value: str, human_key: str) -> None:
        if len(self.current_eid) > 0:
            self._persist_inventory_profile()
            print(
                f"{self._style.green}[+] Persisted {human_key} in SCP11 inventory "
                f"for EID {self.current_eid}{self._style.end}"
            )
            return
        _ = key_prefix
        _ = literal_value
        try:
            self._inventory.store.replace_module_state(
                self.MODULE_STATE_NAME,
                self._inventory_payload(),
            )
        except Exception as error:
            print(f"{self._style.red}[!] Failed writing SCP11 runtime state: {error}{self._style.end}")
            return

        print(f"{self._style.green}[+] Persisted {human_key} in SCP11 runtime state{self._style.end}")

    def _apply_es9_autoderive_from_card(self, card_default_smdp: str) -> None:
        if self._is_placeholder_es9_url(self.current_es9_base_url) is False:
            return
        if len(card_default_smdp.strip()) == 0:
            return

        derived_url = self._as_https_url(card_default_smdp)
        if len(derived_url) == 0:
            return

        set_ok = self._set_es9_base_url(derived_url, source="auto")
        if set_ok:
            self._es9_auto_derived = True

    def _warn_es9_placeholder_without_card_default(self) -> None:
        if self._is_placeholder_es9_url(self.current_es9_base_url) is False:
            return
        if self._es9_auto_derived:
            return
        print(
            f"{self._style.yellow}[*] ES9 base URL is placeholder and card has no default SM-DP+ to derive from."
            f"{self._style.end}"
        )
        print(
            f"{self._style.yellow}[*] Use SET-ES9 [--persist] <url> or persist a default relay profile in runtime state."
            f"{self._style.end}"
        )

    def _print_profiles(self) -> None:
        rows = self._fetch_profiles()
        self._print_profiles_table(rows, title="Profiles on Card")

    def _fetch_profiles(self) -> List[ProfileRow]:
        try:
            response = self._fetch_profiles_raw()
            rows = self._decode_profiles(response)
            return rows
        except Exception as error:
            print(f"{self._style.red}[!] Failed to list profiles: {error}{self._style.end}")
            return []

    def _fetch_profiles_raw(self) -> bytes:
        payload = bytes.fromhex("BF2D00")
        apdu = self._build_store_data_apdu(payload)
        response = self.apdu_channel.send(apdu, "GET: ProfilesInfo")
        return response

    def _print_profiles_table(self, rows: List[ProfileRow], title: str) -> None:
        print(f"\n{title}:")
        if len(rows) == 0:
            print("[*] No profile metadata decoded from response.")
            return

        print("State     Class  ICCID                 Nickname                  AID / Alias")
        print("-" * 112)
        for row in rows:
            aid_alias = self._resolve_alias_for_aid(row.aid)
            aid_display = row.aid
            if aid_alias is not None:
                aid_display = f"{row.aid} ({aid_alias})"
            print(
                f"{row.state:<9} {row.profile_class:<6} {row.iccid:<20} "
                f"{row.nickname[:24]:<24} {aid_display[:44]}"
            )

    def _run_full_flow(self, matching_id: str) -> None:
        effective_matching_id = matching_id.strip()
        try:
            print(f"[*] Active Flow Target: {self.current_smdp_address}")
            print(f"[*] Active ES9 Base URL: {self.current_es9_base_url}")
            self.orchestrator.run_flow(
                matching_id=effective_matching_id,
                smdp_address=self.current_smdp_address,
            )
        except Exception as error:
            print(f"{self._style.red}[!] FLOW failed: {error}{self._style.end}")

    def _verify_scp11_authentication(self, matching_id: str) -> None:
        print(f"\n{self._style.bold}=== VERIFY-SCP11 ==={self._style.end}")
        checks: List[Tuple[str, bool, str]] = []

        connect_ok = False
        credentials_ok = False
        challenge_ok = False
        authenticate_ok = False
        transaction_ok = False
        signature_ok = False

        try:
            self.orchestrator._phase_connect()
            self.orchestrator._bootstrap_es10b_logical_channel()
            connect_ok = True
            checks.append(("Connect / select ISD-R", True, "ok"))
        except Exception as error:
            checks.append(("Connect / select ISD-R", False, str(error)))

        auth_seed: Optional[Dict[str, Any]] = None
        if connect_ok:
            try:
                self.orchestrator._phase_load_credentials()
                credentials_ok = True
                checks.append(("Load SCP11 credentials", True, "ok"))
            except Exception as error:
                checks.append(("Load SCP11 credentials", False, str(error)))

        if connect_ok and credentials_ok:
            try:
                auth_seed = self.orchestrator._phase_authentication_seed(
                    matching_id=matching_id,
                    smdp_address=self.current_smdp_address,
                )
                challenge_len = len(self.orchestrator.state.card_challenge)
                challenge_ok = challenge_len == 16
                if challenge_ok:
                    checks.append(("Get eUICC challenge", True, f"len={challenge_len}"))
                else:
                    checks.append(("Get eUICC challenge", False, f"unexpected len={challenge_len}"))
            except Exception as error:
                checks.append(("Get eUICC challenge", False, str(error)))

        if connect_ok and credentials_ok and challenge_ok and auth_seed is not None:
            try:
                self.orchestrator._phase_authenticate_server(auth_seed, matching_id=matching_id)
                authenticate_ok = True
                checks.append(("AuthenticateServer exchange", True, "ok"))
            except Exception as error:
                checks.append(("AuthenticateServer exchange", False, str(error)))

        if authenticate_ok:
            transaction_ok = len(self.orchestrator.state.transaction_id) > 0
            signature_ok = len(self.orchestrator.state.euicc_signature1) > 0
            checks.append(
                (
                    "Transaction ID captured",
                    transaction_ok,
                    self.orchestrator.state.transaction_id.hex().upper() if transaction_ok else "missing",
                )
            )
            checks.append(
                (
                    "euiccSignature1 captured",
                    signature_ok,
                    f"len={len(self.orchestrator.state.euicc_signature1)}" if signature_ok else "missing",
                )
            )

        print("Check                                Result   Details")
        print("-" * 72)
        for title, passed, details in checks:
            status = "PASS"
            status_color = self._style.green
            if passed is False:
                status = "FAIL"
                status_color = self._style.red
            print(
                f"{title:<36} {status_color}{status:<6}{self._style.end} "
                f"{details}"
            )

        overall = connect_ok and credentials_ok and challenge_ok and authenticate_ok and transaction_ok and signature_ok
        if overall:
            print(f"{self._style.green}[+] VERIFY-SCP11: PASS (authenticated SCP11 path confirmed){self._style.end}")
            return
        print(f"{self._style.red}[-] VERIFY-SCP11: FAIL (see failed checkpoints above){self._style.end}")

    def _download_activation_code(self, activation_code: str) -> None:
        code = activation_code.strip()
        if len(code) == 0:
            print("[!] Usage: DOWNLOAD-AC <activation_code>")
            return

        parsed = self._parse_activation_code(code)
        if parsed is None:
            print("[!] Invalid activation code format.")
            print("[*] Expected format includes '$' and at least server+matchingId parts.")
            return

        server_address, matching_id = parsed
        print(f"[*] Parsed activation code server: {server_address}")
        print(f"[*] Parsed activation code matchingId: {matching_id}")
        self.current_smdp_address = server_address
        derived_es9_base_url = self._as_https_url(server_address)
        if len(derived_es9_base_url) > 0:
            set_ok = self._set_es9_base_url(derived_es9_base_url, source="activation")
            if set_ok is False:
                print(
                    f"{self._style.red}[!] Could not switch ES9 base URL to activation code target: "
                    f"{derived_es9_base_url}{self._style.end}"
                )
                return
        self._run_full_flow(matching_id)

    def _run_retrieve_command(self, title: str, payload: bytes, root_tag: Optional[int]) -> None:
        try:
            apdu = self._build_store_data_apdu(payload)
            response = self.apdu_channel.send(apdu, f"GET: {title}")
        except Exception as error:
            print(f"{self._style.red}[!] {title} failed: {error}{self._style.end}")
            return

        print(f"\n{self._style.bold}[+] {title}{self._style.end}")
        if len(response) == 0:
            print("    | (Empty)")
            return

        if title == "RetrieveNotificationsList":
            self._print_notifications_list_compact(response)
            return
        if title == "GetEuiccInfo1":
            self._print_euicc_info1_compact(response)
            return
        if title == "GetEuiccInfo2":
            self._print_euicc_info2_compact(response)
            return
        if title == "GetRAT":
            self._print_rat_compact(response)
            return
        if title == "GetCerts":
            self._print_get_certs_compact(response)
            return
        if title == "GetEimConfigurationData":
            self._print_eim_configuration_compact(response)
            return

        self._print_tlv_tree_bytes(response, indent=1, parent_tag=root_tag)

    def _run_profile_state_command(
        self,
        identifier: str,
        func_tag: int,
        action_label: str,
        command_name: str,
    ) -> None:
        if len(identifier) == 0:
            print(f"[!] Usage: {command_name} <iccid-or-aid>")
            return

        resolved = self._resolve_profile_target(identifier)
        if resolved is None:
            print(f"{self._style.red}[!] Could not resolve profile: {identifier}{self._style.end}")
            print("[*] Run LIST and use ICCID or AID from output.")
            return

        target_metadata = self._find_profile_metadata(identifier)
        if func_tag == self.TAG_ENABLE_PROFILE:
            self._run_enable_profile_state_command(resolved, target_metadata)
            return
        if func_tag == self.TAG_DISABLE_PROFILE:
            self._run_disable_profile_state_command(resolved, target_metadata)
            return
        if func_tag == self.TAG_DELETE_PROFILE:
            self._run_delete_profile_state_command(resolved, target_metadata)
            return
        self._execute_profile_state_command(resolved, func_tag, action_label)

    def _execute_result_command(self, title: str, payload: bytes, result_outer_tag: int) -> bool:
        try:
            response = self._send_result_store_data(payload, f"CMD: {title}")
        except Exception as error:
            print(f"{self._style.red}[!] {title} failed: {error}{self._style.end}")
            return False

        result_code = self._extract_result_code(response, result_outer_tag)
        should_trigger_sync = result_outer_tag != self.TAG_REMOVE_NOTIFICATION
        if result_code is None:
            print(f"{self._style.green}[+] {title}: success (no explicit result code).{self._style.end}")
            if len(response) > 0:
                print(f"[*] Raw response: {response.hex().upper()}")
            if should_trigger_sync:
                self._sync_notifications_after_success(response)
            return True

        if result_code == 0:
            print(f"{self._style.green}[+] {title}: success.{self._style.end}")
            if should_trigger_sync:
                self._sync_notifications_after_success(response)
            return True

        if result_outer_tag == self.TAG_REMOVE_NOTIFICATION:
            error_text = describe_sgp22_notification_sent_result(int(result_code))
            print(
                f"{self._style.red}[-] {title} failed, code 0x{result_code:02X}: "
                f"{error_text} [SGP.22 ES10b]{self._style.end}"
            )
            return False

        error_map: Dict[int, str] = {
            1: "Profile Not Found",
            2: "Already in requested state",
            3: "Invalid input parameter",
            7: "Command structure error",
            127: "Undefined error",
        }
        error_text = "Unknown error"
        if result_code in error_map:
            error_text = error_map[result_code]
        print(f"{self._style.red}[-] {title} failed, code 0x{result_code:02X}: {error_text}{self._style.end}")
        return False

    def _execute_profile_state_command(
        self,
        resolved: Tuple[int, str],
        func_tag: int,
        action_label: str,
    ) -> bool:
        tag_type, value_hex = resolved
        target_type = "ICCID"
        if tag_type == self.TAG_AID:
            target_type = "AID"
        print(f"{self._style.cyan}[*] {action_label}: {target_type}={value_hex}{self._style.end}")
        payload = self._build_profile_command_payload(func_tag, tag_type, value_hex)
        return self._execute_result_command(
            title=action_label,
            payload=payload,
            result_outer_tag=func_tag,
        )

    def _run_enable_profile_state_command(
        self,
        resolved: Tuple[int, str],
        target_metadata: Optional[ProfileMetadataView],
    ) -> None:
        if target_metadata is None:
            self._execute_profile_state_command(resolved, self.TAG_ENABLE_PROFILE, "EnableProfile")
            return

        if target_metadata.state.upper() == "ENABLED":
            print(f"{self._style.green}[+] EnableProfile: target is already enabled.{self._style.end}")
            return

        profiles = self._collect_profile_metadata()
        active_profile = self._find_enabled_profile(profiles, exclude_profile=target_metadata)
        if active_profile is not None:
            if self._allow_auto_disable_for_enable(active_profile, target_metadata) is False:
                return
            print(
                f"{self._style.yellow}[*] EnableProfile: auto-disabling active profile "
                f"{self._describe_profile_metadata(active_profile)}.{self._style.end}"
            )
            if self._execute_profile_state_command(
                self._profile_metadata_to_resolved(active_profile),
                self.TAG_DISABLE_PROFILE,
                "DisableProfile",
            ) is False:
                return

        self._execute_profile_state_command(resolved, self.TAG_ENABLE_PROFILE, "EnableProfile")

    def _run_disable_profile_state_command(
        self,
        resolved: Tuple[int, str],
        target_metadata: Optional[ProfileMetadataView],
    ) -> None:
        if target_metadata is not None:
            if target_metadata.state.upper() != "ENABLED":
                print(f"{self._style.green}[+] DisableProfile: target is already disabled.{self._style.end}")
                return
        self._execute_profile_state_command(resolved, self.TAG_DISABLE_PROFILE, "DisableProfile")

    def _run_delete_profile_state_command(
        self,
        resolved: Tuple[int, str],
        target_metadata: Optional[ProfileMetadataView],
    ) -> None:
        if target_metadata is None:
            self._execute_profile_state_command(resolved, self.TAG_DELETE_PROFILE, "DeleteProfile")
            return

        if target_metadata.state.upper() == "ENABLED":
            profiles = self._collect_profile_metadata()
            replacement = self._find_replacement_profile_for_delete(profiles, target_metadata)
            if replacement is None:
                print(
                    f"{self._style.red}[!] DeleteProfile: target is enabled and no replacement profile "
                    f"is available to switch to first.{self._style.end}"
                )
                return
            print(
                f"{self._style.yellow}[*] DeleteProfile: target is enabled, auto-switching to "
                f"{self._describe_profile_metadata(replacement)} first.{self._style.end}"
            )
            if self._run_enable_profile_sequence_for_metadata(replacement) is False:
                return

        self._execute_profile_state_command(resolved, self.TAG_DELETE_PROFILE, "DeleteProfile")

    def _run_enable_profile_sequence_for_metadata(self, target_metadata: ProfileMetadataView) -> bool:
        resolved = self._profile_metadata_to_resolved(target_metadata)
        if target_metadata.state.upper() == "ENABLED":
            print(
                f"{self._style.green}[+] EnableProfile: replacement target is already enabled "
                f"({self._describe_profile_metadata(target_metadata)}).{self._style.end}"
            )
            return True

        profiles = self._collect_profile_metadata()
        active_profile = self._find_enabled_profile(profiles, exclude_profile=target_metadata)
        if active_profile is not None:
            if self._allow_auto_disable_for_enable(active_profile, target_metadata) is False:
                return False
            print(
                f"{self._style.yellow}[*] EnableProfile: auto-disabling active profile "
                f"{self._describe_profile_metadata(active_profile)}.{self._style.end}"
            )
            if self._execute_profile_state_command(
                self._profile_metadata_to_resolved(active_profile),
                self.TAG_DISABLE_PROFILE,
                "DisableProfile",
            ) is False:
                return False
        return self._execute_profile_state_command(resolved, self.TAG_ENABLE_PROFILE, "EnableProfile")

    def _allow_auto_disable_for_enable(
        self,
        active_profile: ProfileMetadataView,
        target_metadata: Optional[ProfileMetadataView],
    ) -> bool:
        if self._profile_disable_not_allowed(active_profile) is False:
            return True
        target_description = "requested target"
        if target_metadata is not None:
            target_description = self._describe_profile_metadata(target_metadata)
        print(
            f"{self._style.red}[!] EnableProfile: guarded mode refused to auto-disable active profile "
            f"{self._describe_profile_metadata(active_profile)} because its PPR advertises "
            f"ppr1-disable-not-allowed.{self._style.end}"
        )
        print(
            "    Use a rollback-enabled profile switch path, or move the active profile "
            f"away from {target_description} in the modem before retrying."
        )
        return False

    def _profile_disable_not_allowed(self, entry: Optional[ProfileMetadataView]) -> bool:
        if entry is None:
            return False
        decoded = self._decode_ppr_ids(str(getattr(entry, "profile_policy_rules_hex", "") or ""))
        return "ppr1-disable-not-allowed" in decoded

    def _find_enabled_profile(
        self,
        profiles: List[ProfileMetadataView],
        exclude_profile: Optional[ProfileMetadataView] = None,
    ) -> Optional[ProfileMetadataView]:
        for entry in profiles:
            if exclude_profile is not None:
                if self._profile_metadata_matches(entry, exclude_profile):
                    continue
            if entry.state.upper() == "ENABLED":
                return entry
        return None

    def _find_replacement_profile_for_delete(
        self,
        profiles: List[ProfileMetadataView],
        target_profile: ProfileMetadataView,
    ) -> Optional[ProfileMetadataView]:
        disabled_candidates = []
        enabled_candidates = []
        for entry in profiles:
            if self._profile_metadata_matches(entry, target_profile):
                continue
            if entry.state.upper() == "ENABLED":
                enabled_candidates.append(entry)
                continue
            disabled_candidates.append(entry)
        if len(enabled_candidates) > 0:
            return enabled_candidates[0]
        if len(disabled_candidates) == 0:
            return None
        disabled_candidates.sort(
            key=lambda entry: (
                self._profile_replacement_priority(entry),
                entry.iccid,
                entry.aid,
            )
        )
        return disabled_candidates[0]

    def _profile_replacement_priority(self, entry: ProfileMetadataView) -> int:
        class_rank = {"OPER": 0, "PROV": 1, "TEST": 2}
        return class_rank.get(entry.profile_class.upper(), 3)

    def _profile_metadata_to_resolved(self, entry: ProfileMetadataView) -> Tuple[int, str]:
        if len(entry.aid) > 0:
            return self.TAG_AID, entry.aid.upper()
        return self.TAG_ICCID, self._encode_iccid_for_command(entry.iccid)

    def _profile_metadata_matches(self, left: ProfileMetadataView, right: ProfileMetadataView) -> bool:
        left_aid = left.aid.strip().upper()
        right_aid = right.aid.strip().upper()
        if len(left_aid) > 0 and len(right_aid) > 0:
            return left_aid == right_aid
        return left.iccid.strip().upper() == right.iccid.strip().upper()

    def _describe_profile_metadata(self, entry: ProfileMetadataView) -> str:
        alias = self._resolve_alias_for_aid(entry.aid)
        if alias is not None:
            return f"{entry.iccid} ({alias})"
        if len(entry.iccid) > 0:
            return entry.iccid
        return entry.aid

    def _sync_notifications_after_success(self, response: bytes) -> None:
        orchestrator = self.orchestrator
        if orchestrator is None:
            return
        sync_method = getattr(orchestrator, "_sync_pending_notifications", None)
        if callable(sync_method) is False:
            return
        try:
            sync_method(response)
        except Exception as error:
            print(f"{self._style.yellow}[*] Notification sync skipped ({error}).{self._style.end}")

    def _build_profile_command_payload(self, func_tag: int, tag_type: int, value_hex: str) -> bytes:
        value_bytes = bytes.fromhex(value_hex)
        id_tlv = _build_tlv(bytes([tag_type]), value_bytes)
        if func_tag == self.TAG_DELETE_PROFILE:
            return _build_tlv(func_tag.to_bytes(2, "big"), id_tlv)
        ctx_tlv = _build_tlv(bytes([self.TAG_CTX_0]), id_tlv)
        refresh_required_tlv = _build_tlv(bytes.fromhex("81"), bytes.fromhex("00"))
        inner = ctx_tlv + refresh_required_tlv
        return _build_tlv(func_tag.to_bytes(2, "big"), inner)

    def _build_remove_notification_payload(self, seq_value: int) -> bytes:
        seq_bytes = self._encode_positive_asn1_integer(seq_value)
        seq_tlv = _build_tlv(bytes.fromhex("80"), seq_bytes)
        return _build_tlv(self.TAG_REMOVE_NOTIFICATION.to_bytes(2, "big"), seq_tlv)

    @staticmethod
    def _encode_positive_asn1_integer(value: int) -> bytes:
        if value < 0:
            raise ValueError("ASN.1 INTEGER value must be non-negative.")
        byte_length = max(1, (value.bit_length() + 7) // 8)
        encoded = value.to_bytes(byte_length, "big")
        if encoded[0] & 0x80:
            return b"\x00" + encoded
        return encoded

    def _extract_result_code(self, response: bytes, result_outer_tag: int) -> Optional[int]:
        if len(response) == 0:
            return None

        parsed = self._parse_tlv_simple(response)
        outer_payload = b""
        if result_outer_tag in parsed:
            value = parsed[result_outer_tag]
            if isinstance(value, bytes):
                outer_payload = value
            elif isinstance(value, list):
                if len(value) > 0 and isinstance(value[0], bytes):
                    outer_payload = value[0]

        if len(outer_payload) == 0:
            if self.TAG_RESULT not in parsed:
                return None
            direct_value = parsed[self.TAG_RESULT]
            if isinstance(direct_value, bytes):
                return int.from_bytes(direct_value, "big")
            return None

        outer_parsed = self._parse_tlv_simple(outer_payload)
        if self.TAG_RESULT not in outer_parsed:
            return None
        result_value = outer_parsed[self.TAG_RESULT]
        if isinstance(result_value, bytes):
            return int.from_bytes(result_value, "big")
        if isinstance(result_value, list):
            if len(result_value) > 0 and isinstance(result_value[0], bytes):
                return int.from_bytes(result_value[0], "big")
        return None

    def _resolve_profile_target(self, identifier: str) -> Optional[Tuple[int, str]]:
        return resolve_profile_target_identifier(
            identifier,
            tag_aid=self.TAG_AID,
            tag_iccid=self.TAG_ICCID,
            resolve_aid_from_alias=self._resolve_aid_from_alias,
            is_hex=self._is_hex,
            extract_decimal_iccid=self._extract_decimal_iccid,
            encode_iccid_for_command=self._encode_iccid_for_command,
            fetch_profiles=self._fetch_profiles,
        )

    def _resolve_aid_from_alias(self, alias: str) -> Optional[str]:
        if alias in self._aid_registry:
            return self._aid_registry[alias]
        return None

    def _resolve_alias_for_aid(self, aid_hex: str) -> Optional[str]:
        target = aid_hex.strip().upper()
        for alias, aid_value in self._aid_registry.items():
            if aid_value == target:
                return alias
        return None

    def _print_aid_registry(self) -> None:
        print(f"\n{self._style.bold}--- Admin AID Registry ---{self._style.end}")
        if len(self._aid_registry) == 0:
            print("[*] No aliases loaded.")
            return
        for alias, aid in sorted(self._aid_registry.items()):
            print(f"{alias:<12} {aid}")

    def _load_aid_registry(self) -> Dict[str, str]:
        registry: Dict[str, str] = {}
        path = self.DEFAULT_AID_REGISTRY_PATH
        if os.path.exists(path) is False:
            return registry

        try:
            with open(path, "r", encoding="utf-8") as aid_file:
                for line in aid_file:
                    clean_line = line.split("#", 1)[0].strip()
                    if len(clean_line) == 0:
                        continue
                    if ":" not in clean_line:
                        continue

                    left, right = clean_line.split(":", 1)
                    alias = left.strip().upper()
                    aid_hex = right.strip().upper()
                    if len(alias) == 0:
                        continue
                    if self._is_hex(aid_hex) is False:
                        continue
                    registry[alias] = aid_hex
        except Exception as error:
            print(f"{self._style.red}[!] Failed to load shared AID registry: {error}{self._style.end}")
        return registry

    def _extract_decimal_iccid(self, value: str) -> Optional[str]:
        digits = ""
        for char in value:
            if char.isdigit():
                digits += char
                continue
            return None
        if len(digits) < 18:
            return None
        return digits

    def _encode_iccid_for_command(self, iccid_digits: str) -> str:
        padded = iccid_digits
        if len(padded) % 2 != 0:
            padded += "F"

        output = ""
        index = 0
        while index < len(padded):
            first = padded[index]
            second = padded[index + 1]
            output += second + first
            index += 2
        return output

    def _parse_integer_value(self, text: str) -> Optional[int]:
        raw = text.strip().lower()
        if len(raw) == 0:
            return None

        try:
            if raw.startswith("0x"):
                return int(raw, 16)
            return int(raw, 10)
        except ValueError:
            return None

    def _is_hex(self, value: str) -> bool:
        if len(value) == 0:
            return False
        if len(value) % 2 != 0:
            return False
        try:
            bytes.fromhex(value)
        except ValueError:
            return False
        return True

    def _print_tlv_tree_bytes(self, data: bytes, indent: int, parent_tag: Optional[int]) -> None:
        if indent > 6:
            print(f"{'    ' * indent}| ...")
            return
        nodes = self._parse_tlv_nodes(data)
        if len(nodes) == 0:
            print(f"{'    ' * indent}| {data.hex().upper()}")
            return

        for tag, value, is_constructed in nodes:
            label = self._resolve_tag_name(tag, parent_tag)
            prefix = "    " * indent
            if is_constructed:
                print(f"{prefix}| {self._style.cyan}{label}{self._style.end}")
                self._print_tlv_tree_bytes(value, indent + 1, tag)
                continue

            display = self._decode_scalar_value(tag, value)
            print(f"{prefix}| {self._style.cyan}{label:<24}{self._style.end}: {display}")

    def _parse_tlv_nodes(self, data: bytes) -> List[Tuple[int, bytes, bool]]:
        nodes: List[Tuple[int, bytes, bool]] = []
        index = 0
        while index < len(data):
            tag, index_after_tag, constructed = self._read_tag(data, index)
            if index_after_tag <= index:
                break
            length, length_size = self._decode_length(data, index_after_tag)
            if length_size == 0:
                break
            value_start = index_after_tag + length_size
            value_end = value_start + length
            if value_end > len(data):
                break
            value = data[value_start:value_end]
            nodes.append((tag, value, constructed))
            index = value_end
        return nodes

    def _read_tag(self, data: bytes, offset: int) -> Tuple[int, int, bool]:
        if offset >= len(data):
            return 0, offset, False
        first = data[offset]
        tag_value = first
        index = offset + 1
        constructed = (first & 0x20) != 0

        if (first & 0x1F) == 0x1F:
            while index < len(data):
                octet = data[index]
                tag_value = (tag_value << 8) | octet
                index += 1
                if (octet & 0x80) == 0:
                    break
        return tag_value, index, constructed

    def _decode_scalar_value(self, tag: int, value: bytes) -> str:
        ascii_safe = True
        for byte in value:
            if byte < 0x20 or byte > 0x7E:
                ascii_safe = False
                break

        if ascii_safe:
            text = value.decode("ascii", "ignore").strip()
            if len(text) > 0:
                return text

        if tag in [0x80, 0x81, 0x82]:
            return self._decode_text_or_hex(value)
        return self._short_display_hex(value.hex().upper())

    def _resolve_tag_name(self, tag: int, parent_tag: Optional[int]) -> str:
        if parent_tag == 0xBF3C:
            if tag == 0x80:
                return "SM-DP+ Address"
            if tag == 0x81:
                return "Root SM-DS Address"
            if tag == 0x82:
                return "Additional Root SM-DS"
            if tag == 0xA2:
                return "Additional Root SM-DS List"
            if tag == 0x83:
                return "Allowed CI PKID"
            if tag == 0x84:
                return "CI List"
            if tag == 0xA4:
                return "CI List"

        if parent_tag == 0xBF2B:
            if tag == 0xA0:
                return "Notification List"
            if tag == 0x81:
                return "Notifications List Error"
            if tag == 0xA2:
                return "eUICC Package Result List"

        if parent_tag == 0xBF55:
            if tag == 0xA0:
                return "eIM Configuration Data List"

        known: Dict[int, str] = {
            0x5A: "EID/ICCID",
            0x4F: "AID",
            0xBF20: "EuiccInfo1",
            0xBF22: "EuiccInfo2",
            0xBF3C: "EuiccConfiguredData",
            0xBF43: "RAT (Rules Authorisation Table)",
            0xBF2B: "NotificationsList",
            0xBF55: "EimConfigurationData",
            0xBF56: "GetCertsResponse",
            0x90: "Nickname",
            0x91: "Service Provider",
            0x92: "Profile Name",
            0x95: "Profile Class",
            0x9F70: "State",
        }
        if tag in known:
            return known[tag]
        return f"{tag:02X}"

    def _build_style(self) -> ConsoleStyle:
        use_color = True
        if sys.stdout.isatty() is False:
            use_color = False

        if SCP03Config is not None and use_color:
            colors = SCP03Config.Colors
            return ConsoleStyle(
                header=colors.MINT,
                cyan=colors.CYAN,
                green=colors.GREEN,
                yellow=colors.WARNING,
                red=colors.FAIL,
                bold=colors.BOLD,
                end=colors.ENDC,
            )

        if use_color:
            return ConsoleStyle(
                header=_hex_to_ansi("#8FBCBB"),
                cyan=_hex_to_ansi("#88C0D0"),
                green=_hex_to_ansi("#A3BE8C"),
                yellow=_hex_to_ansi("#EBCB8B"),
                red=_hex_to_ansi("#BF616A"),
                bold="\033[1m",
                end="\033[0m",
            )

        return ConsoleStyle(header="", cyan="", green="", yellow="", red="", bold="", end="")

    def _setup_readline(self) -> None:
        if readline is None:
            return

        self._history_file = os.path.join(os.path.expanduser("~"), ".yggdrasim_scp11_history")
        try:
            if os.path.exists(self._history_file):
                readline.read_history_file(self._history_file)
            readline.set_history_length(1000)
        except Exception:
            pass

        atexit.register(self._save_history)
        readline.set_completer(self._completer)
        readline.set_completer_delims(" \t\n")

        has_libedit = False
        if readline.__doc__ is not None and "libedit" in readline.__doc__:
            has_libedit = True

        if has_libedit:
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
        if len(self._history_file) == 0:
            return
        try:
            readline.write_history_file(self._history_file)
        except Exception:
            pass

    def _completer(self, text: str, state: int) -> Optional[str]:
        if readline is None:
            return None

        line_buffer = readline.get_line_buffer().lstrip()
        if " " not in line_buffer:
            options: List[str] = []
            typed = text.upper()
            for command in self._primary_commands:
                if command.startswith(typed):
                    options.append(command)
            if state >= len(options):
                return None
            if len(options) == 1:
                return options[state] + " "
            return options[state]
        return None

    def _parse_activation_code(self, activation_code: str) -> Optional[Tuple[str, str]]:
        if "$" not in activation_code:
            return None
        parts = activation_code.split("$")
        if len(parts) < 3:
            return None
        server_address = parts[1].strip()
        matching_id = parts[2].strip()
        if len(server_address) == 0:
            return None
        if len(matching_id) == 0:
            return None
        return server_address, matching_id

    def _as_https_url(self, value: str) -> str:
        cleaned = value.strip()
        if len(cleaned) == 0:
            return ""
        lowered = cleaned.lower()
        if lowered.startswith("http://") or lowered.startswith("https://"):
            return cleaned.rstrip("/")
        return f"https://{cleaned.rstrip('/')}"

    def _is_placeholder_es9_url(self, value: str) -> bool:
        lowered = value.strip().lower()
        if len(lowered) == 0:
            return True
        if "rsp.example.com" in lowered:
            return True
        if "example.com" in lowered:
            return True
        return False

    def _send_result_store_data(self, payload: bytes, log_name: str) -> bytes:
        orchestrator = getattr(self, "orchestrator", None)
        orchestrator_sender = getattr(orchestrator, "_send_es10b_store_data", None)
        if callable(orchestrator_sender):
            try:
                return orchestrator_sender(payload, log_name, allow_stk_retry=True)
            except TypeError:
                return orchestrator_sender(payload, log_name)
        apdu = self._build_store_data_apdu(payload)
        return self.apdu_channel.send(apdu, log_name)

    def _build_store_data_apdu(self, payload: bytes, p1: int = 0x91, p2: int = 0x00, cla: int = 0x80) -> bytes:
        if len(payload) > 255:
            raise ValueError("Payload too long for single APDU. Use chunking path for large payloads.")
        return bytes([cla, 0xE2, p1, p2, len(payload)]) + payload

    def _decode_euicc_configured_data(self, raw_data: bytes) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "default_smdp": "",
            "root_smds_primary": "",
            "root_smds_additional": [],
            "allowed_ci_pkid": [],
        }
        if len(raw_data) == 0:
            return result

        parsed = self._parse_tlv_simple(raw_data)
        root_value = b""
        if 0xBF3C in parsed:
            bf3c_value = parsed[0xBF3C]
            if isinstance(bf3c_value, list):
                if len(bf3c_value) > 0 and isinstance(bf3c_value[0], bytes):
                    root_value = bf3c_value[0]
            elif isinstance(bf3c_value, bytes):
                root_value = bf3c_value
        else:
            root_value = raw_data

        inner = self._parse_tlv_simple(root_value)

        default_values = self._extract_text_values(inner, 0x80)
        if len(default_values) > 0:
            result["default_smdp"] = default_values[0]

        primary_smds_values = self._extract_text_values(inner, 0x81)
        if len(primary_smds_values) > 0:
            result["root_smds_primary"] = primary_smds_values[0]

        additional_smds_values: List[str] = []
        additional_smds_values.extend(self._extract_text_values(inner, 0x82))
        additional_smds_values.extend(self._extract_nested_additional_smds(inner))
        result["root_smds_additional"] = self._dedupe_preserving_order(additional_smds_values)

        pkid_values = self._extract_text_values(inner, 0x83)
        result["allowed_ci_pkid"] = self._dedupe_preserving_order(pkid_values)
        return result

    def _extract_nested_additional_smds(self, parsed_tlv: Dict[int, Any]) -> List[str]:
        output: List[str] = []
        if 0xA2 not in parsed_tlv:
            return output

        values = parsed_tlv[0xA2]
        blobs: List[bytes] = []
        if isinstance(values, list):
            for item in values:
                if isinstance(item, bytes):
                    blobs.append(item)
        elif isinstance(values, bytes):
            blobs.append(values)

        for blob in blobs:
            nested = self._parse_tlv_simple(blob)
            nested_values = self._extract_text_values(nested, 0x82)
            if len(nested_values) > 0:
                output.extend(nested_values)
            else:
                output.append(self._decode_text_or_hex(blob))
        return output

    def _extract_text_values(self, parsed_tlv: Dict[int, Any], tag: int) -> List[str]:
        if tag not in parsed_tlv:
            return []

        raw_values = parsed_tlv[tag]
        normalized: List[bytes] = []
        if isinstance(raw_values, list):
            for item in raw_values:
                if isinstance(item, bytes):
                    normalized.append(item)
        elif isinstance(raw_values, bytes):
            normalized.append(raw_values)

        output: List[str] = []
        for value in normalized:
            output.append(self._decode_text_or_hex(value))
        return output

    def _decode_text_or_hex(self, value: bytes) -> str:
        try:
            text = value.decode("utf-8", "ignore")
        except Exception:
            return value.hex().upper()

        clean_text = text.replace("\x00", "").strip()
        if len(clean_text) == 0:
            return value.hex().upper()
        for char in clean_text:
            code = ord(char)
            if code < 0x20 or code > 0x7E:
                return value.hex().upper()
        return clean_text

    def _print_guarded_provisioning_message(self) -> None:
        print(
            f"{self._style.yellow}[-] Not executed: operation requires authenticated provisioning context."
            f"{self._style.end}"
        )
        print("    Required preconditions:")
        print("    | 1) SCP11 channel and ES10b server authentication established")
        print("    | 2) Matching eIM/profile trust context")
        print("    | 3) Provisioning flow support enabled for metadata/POL operations")

    def _collect_profile_metadata(self) -> List[ProfileMetadataView]:
        raw_data = self._fetch_profiles_raw()
        if len(raw_data) == 0:
            return []
        rows = self._decode_profile_metadata_rows(raw_data)
        return rows

    def _find_profile_metadata(self, identifier: str) -> Optional[ProfileMetadataView]:
        target = identifier.strip().upper()
        if len(target) == 0:
            return None

        entries = self._collect_profile_metadata()
        for entry in entries:
            if entry.iccid.upper() == target:
                return entry
            if entry.aid.upper() == target:
                return entry
            alias = self._resolve_alias_for_aid(entry.aid)
            if alias is None:
                continue
            if alias == target:
                return entry

        resolved = self._resolve_profile_target(identifier)
        if resolved is None:
            return None
        tag_type, value_hex = resolved
        for entry in entries:
            if tag_type == self.TAG_AID:
                if entry.aid.upper() == value_hex.upper():
                    return entry
                continue
            if tag_type == self.TAG_ICCID:
                if self._encode_iccid_for_command(entry.iccid).upper() == value_hex.upper():
                    return entry
        return None

    def _decode_profile_metadata_rows(self, raw_data: bytes) -> List[ProfileMetadataView]:
        rows: List[ProfileMetadataView] = []
        index = 0
        while index < len(raw_data):
            if raw_data[index] != 0xE3:
                index += 1
                continue

            length, length_size = self._decode_length(raw_data, index + 1)
            if length_size == 0:
                break

            value_start = index + 1 + length_size
            value_end = value_start + length
            if value_end > len(raw_data):
                break

            blob = raw_data[value_start:value_end]
            parsed = self._parse_tlv_simple(blob)
            row = self._profile_metadata_from_parsed(parsed)
            if row is not None:
                rows.append(row)
            index = value_end
        return rows

    def _profile_metadata_from_parsed(self, parsed: Dict[int, Any]) -> Optional[ProfileMetadataView]:
        iccid_bytes = self._get_tag(parsed, 0x5A)
        if not isinstance(iccid_bytes, bytes):
            return None

        iccid = self._swap_nibbles(iccid_bytes.hex().upper())

        aid = ""
        aid_bytes = self._get_tag(parsed, 0x4F) or self._get_tag(parsed, 0xA0)
        if isinstance(aid_bytes, bytes):
            aid = aid_bytes.hex().upper()

        state = "DISABLED"
        state_bytes = self._get_tag(parsed, 0x9F70)
        if isinstance(state_bytes, bytes):
            state_value = int.from_bytes(state_bytes, "big")
            if state_value == 1:
                state = "ENABLED"

        profile_class = "OPER"
        class_bytes = self._get_tag(parsed, 0x95)
        if isinstance(class_bytes, bytes):
            class_value = int.from_bytes(class_bytes, "big")
            class_map = {0: "TEST", 1: "PROV", 2: "OPER"}
            profile_class = class_map.get(class_value, "OPER")

        nickname = self._decode_optional_text(self._get_tag(parsed, 0x90))
        service_provider = self._decode_optional_text(self._get_tag(parsed, 0x91))
        profile_name = self._decode_optional_text(self._get_tag(parsed, 0x92))

        ppr_hex = ""
        ppr_bytes = self._get_tag(parsed, 0x99)
        if isinstance(ppr_bytes, bytes):
            ppr_hex = ppr_bytes.hex().upper()

        return ProfileMetadataView(
            iccid=iccid,
            aid=aid,
            state=state,
            profile_class=profile_class,
            nickname=nickname,
            service_provider=service_provider,
            profile_name=profile_name,
            profile_policy_rules_hex=ppr_hex,
        )

    def _decode_optional_text(self, value: Any) -> str:
        if not isinstance(value, bytes):
            return ""
        decoded = self._decode_text_or_hex(value)
        if len(decoded) == 0:
            return ""
        return decoded

    def _decode_ppr_ids(self, ppr_hex: str) -> str:
        if len(ppr_hex) < 4:
            return "unknown"
        try:
            raw = bytes.fromhex(ppr_hex)
        except ValueError:
            return "invalid"
        if len(raw) < 2:
            return "unknown"

        unused_bits = raw[0]
        payload = raw[1:]
        if len(payload) == 0:
            return "none"

        labels: List[str] = []
        bit_index = 0
        for byte_index, byte_value in enumerate(payload):
            for mask_bit in range(7, -1, -1):
                is_last_byte = byte_index == len(payload) - 1
                if is_last_byte:
                    if mask_bit < unused_bits:
                        continue
                is_set = ((byte_value >> mask_bit) & 0x01) == 0x01
                if is_set:
                    if bit_index == 0:
                        labels.append("pprUpdateControl")
                    elif bit_index == 1:
                        labels.append("ppr1-disable-not-allowed")
                    elif bit_index == 2:
                        labels.append("ppr2-delete-not-allowed")
                    else:
                        labels.append(f"bit{bit_index}")
                bit_index += 1
        if len(labels) == 0:
            return "none"
        return ", ".join(labels)

    def _print_euicc_info1_compact(self, response: bytes) -> None:
        if decode_euicc_info1_summary is None:
            self._print_tlv_tree_bytes(response, indent=1, parent_tag=0xBF20)
            return

        summary = decode_euicc_info1_summary(response)
        if len(summary) == 0:
            self._print_tlv_tree_bytes(response, indent=1, parent_tag=0xBF20)
            return

        svn = str(summary.get("svn", "")).strip()
        if len(svn) > 0:
            print(f"    | SVN                  : {svn}")
        print(f"    | CI PK Verify Entries  : {summary.get('ci_pk_verify_entries', 0)}")
        print(f"    | CI PK Sign Entries    : {summary.get('ci_pk_sign_entries', 0)}")

    def _print_euicc_info2_compact(self, response: bytes) -> None:
        if build_euicc_info2_detail_lines is None:
            print(f"    | Raw response          : {self._short_display_hex(response.hex().upper(), 120)}")
            return

        for indent_level, label, value in build_euicc_info2_detail_lines(response):
            prefix = "    | "
            if indent_level > 0:
                prefix = "    | " + ("  " * indent_level)
            print(f"{prefix}{label:<20}: {value}")

    def _print_rat_compact(self, response: bytes) -> None:
        if decode_rat_rules is None:
            self._print_tlv_tree_bytes(response, indent=1, parent_tag=0xBF43)
            return

        rules = decode_rat_rules(response)
        print(f"    | Rules                : {len(rules)}")
        if len(rules) == 0:
            return

        first_rule = rules[0]
        if "pprIdsRaw" in first_rule:
            print(f"    | PPR IDs Raw          : {first_rule['pprIdsRaw']}")
        if "pprIds" in first_rule:
            print(f"    | PPR IDs Meaning      : {first_rule['pprIds']}")
        operators = first_rule.get("allowedOperators", [])
        print(f"    | Allowed Operators    : {len(operators) if isinstance(operators, list) else 0}")
        if isinstance(operators, list) and len(operators) > 0:
            operator = operators[0]
            details = []
            if "mccMnc" in operator:
                details.append(f"mccMnc={operator['mccMnc']}")
            if "gid1" in operator:
                details.append(f"gid1={operator['gid1']}")
            if "gid2" in operator:
                details.append(f"gid2={operator['gid2']}")
            print(f"    | First Operator       : {', '.join(details)}")
        if "pprFlagsRaw" in first_rule:
            print(f"    | PPR Flags Raw        : {first_rule['pprFlagsRaw']}")
        if "pprFlags" in first_rule:
            print(f"    | PPR Flags Meaning    : {first_rule['pprFlags']}")

    def _print_get_certs_compact(self, response: bytes) -> None:
        if decode_get_certs_response is None:
            print(f"    | Raw response          : {self._short_display_hex(response.hex().upper(), 120)}")
            return

        decoded = decode_get_certs_response(response)
        if len(decoded) == 0:
            print(f"    | Raw response          : {self._short_display_hex(response.hex().upper(), 120)}")
            return
        if "error" in decoded:
            print(f"    | Result               : {decoded['error']}")
            return

        eum = decoded.get("eumCertificate", b"")
        euicc = decoded.get("euiccCertificate", b"")
        print(f"    | EUM Certificate      : {'Present' if isinstance(eum, bytes) and len(eum) > 0 else 'Absent'}")
        print(f"    | eUICC Certificate    : {'Present' if isinstance(euicc, bytes) and len(euicc) > 0 else 'Absent'}")
        if isinstance(eum, bytes) and len(eum) > 0:
            print(f"    | EUM Cert Bytes       : {len(eum)}")
            print(f"    | EUM Cert DER Hex     : {eum.hex().upper()}")
        if isinstance(euicc, bytes) and len(euicc) > 0:
            print(f"    | eUICC Cert Bytes     : {len(euicc)}")
            print(f"    | eUICC Cert DER Hex   : {euicc.hex().upper()}")

    def _print_eim_configuration_compact(self, response: bytes) -> None:
        if self.orchestrator is None or decode_eim_configuration_entries is None:
            self._print_tlv_tree_bytes(response, indent=1, parent_tag=0xBF55)
            return

        entries = decode_eim_configuration_entries(response)
        print(f"    | eIM Entries           : {len(entries)}")
        if len(entries) == 0:
            return

        first = entries[0]
        fqdn = str(first.get("eim_fqdn", "")).strip()
        eim_id = str(first.get("eim_id", "")).strip()
        if len(fqdn) > 0:
            print(f"    | First eIM FQDN        : {fqdn}")
        if len(eim_id) > 0:
            print(f"    | First eIM ID          : {eim_id}")

    def _first_bytes(self, value: Any) -> Optional[bytes]:
        if isinstance(value, bytes):
            return value
        if isinstance(value, list):
            if len(value) == 0:
                return None
            if isinstance(value[0], bytes):
                return value[0]
        return None

    def _print_help_rows(self, rows: List[Tuple[str, str]]) -> None:
        for usage, description in rows:
            print(f"  {usage:<{self.HELP_USAGE_WIDTH}} {description}")

    def _print_notifications_list_compact(self, response: bytes) -> None:
        if decode_notifications_response is None:
            print("    | Notification Entries : (Empty)")
            return

        decoded = decode_notifications_response(response)
        notifications = decoded.get("notifications", [])
        package_results = decoded.get("package_results", [])
        error_text = str(decoded.get("error", "")).strip()
        if len(error_text) > 0:
            print(f"    | Result               : {error_text}")
            return

        print(f"    | Notification Entries : {len(notifications)}")
        if len(package_results) > 0:
            print(f"    | Package Results      : {len(package_results)}")
        if len(notifications) == 0:
            return

        first = notifications[0]
        if "seqNumber" in first:
            print(f"    | Seq Number           : {first['seqNumber']}")
        if "operation" in first:
            print(f"    | Operation            : {first['operation']}")
        if "notificationAddress" in first:
            print(f"    | Server/FQDN          : {first['notificationAddress']}")
        if "iccid" in first:
            print(f"    | ICCID                : {first['iccid']}")

    def _short_display_hex(self, text: str, max_len: int = 64) -> str:
        if len(text) <= max_len:
            return text
        return text[:max_len] + "..."

    def _count_tag_recursive(self, data: bytes, wanted_tag: int) -> int:
        count = 0
        nodes = self._parse_tlv_nodes(data)
        for tag, value, is_constructed in nodes:
            if tag == wanted_tag:
                count += 1
            if is_constructed:
                count += self._count_tag_recursive(value, wanted_tag)
        return count

    def _collect_tag_recursive(self, data: bytes, wanted_tag: int) -> List[bytes]:
        collected: List[bytes] = []
        nodes = self._parse_tlv_nodes(data)
        for tag, value, is_constructed in nodes:
            if tag == wanted_tag:
                collected.append(value)
            if is_constructed:
                nested = self._collect_tag_recursive(value, wanted_tag)
                for entry in nested:
                    collected.append(entry)
        return collected

    def _dedupe_preserving_order(self, values: List[str]) -> List[str]:
        seen: Dict[str, bool] = {}
        output: List[str] = []
        for value in values:
            if value in seen:
                continue
            seen[value] = True
            output.append(value)
        return output

    def _decode_profiles(self, raw_data: bytes) -> List[ProfileRow]:
        if TlvParser is None:
            return self._decode_profiles_with_local_parser(raw_data)
        return self._decode_profiles_with_tlv_parser(raw_data)

    def _decode_profiles_with_tlv_parser(self, raw_data: bytes) -> List[ProfileRow]:
        rows: List[ProfileRow] = []
        index = 0
        while index < len(raw_data):
            if raw_data[index] != 0xE3:
                index += 1
                continue

            length, length_size = self._decode_length(raw_data, index + 1)
            if length_size == 0:
                break

            value_start = index + 1 + length_size
            value_end = value_start + length
            if value_end > len(raw_data):
                break

            blob = raw_data[value_start:value_end]
            row = self._decode_single_profile(blob)
            if row is not None:
                rows.append(row)
            index = value_end
        return rows

    def _decode_single_profile(self, blob: bytes) -> Optional[ProfileRow]:
        parsed = TlvParser.parse(blob)
        return self._profile_row_from_parsed(parsed)

    def _decode_profiles_with_local_parser(self, raw_data: bytes) -> List[ProfileRow]:
        rows: List[ProfileRow] = []
        index = 0
        while index < len(raw_data):
            if raw_data[index] != 0xE3:
                index += 1
                continue

            length, length_size = self._decode_length(raw_data, index + 1)
            if length_size == 0:
                break

            value_start = index + 1 + length_size
            value_end = value_start + length
            if value_end > len(raw_data):
                break

            blob = raw_data[value_start:value_end]
            parsed = self._parse_tlv_simple(blob)
            row = self._profile_row_from_parsed(parsed)
            if row is not None:
                rows.append(row)
            index = value_end
        return rows

    def _profile_row_from_parsed(self, parsed: Dict[int, Any]) -> Optional[ProfileRow]:
        aid_bytes = self._get_tag(parsed, 0x4F) or self._get_tag(parsed, 0xA0)
        iccid_bytes = self._get_tag(parsed, 0x5A)
        state_bytes = self._get_tag(parsed, 0x9F70, b"\x00")
        class_bytes = self._get_tag(parsed, 0x95, b"\x02")
        name_bytes = self._get_tag(parsed, 0x90) or self._get_tag(parsed, 0x92) or self._get_tag(parsed, 0x91)

        if iccid_bytes is None:
            return None

        if isinstance(aid_bytes, bytes):
            aid = aid_bytes.hex().upper()
        else:
            aid = ""

        if isinstance(iccid_bytes, bytes):
            iccid_raw = iccid_bytes.hex().upper()
        else:
            iccid_raw = ""
        iccid = self._swap_nibbles(iccid_raw)

        if isinstance(state_bytes, bytes):
            state_value = int.from_bytes(state_bytes, "big")
        else:
            state_value = 0
        state = "ENABLED" if state_value == 1 else "DISABLED"

        if isinstance(class_bytes, bytes):
            class_value = int.from_bytes(class_bytes, "big")
        else:
            class_value = 2
        class_map = {0: "TEST", 1: "PROV", 2: "OPER"}
        profile_class = class_map.get(class_value, "OPER")

        nickname = "Unknown"
        if isinstance(name_bytes, bytes):
            try:
                nickname = name_bytes.decode("utf-8", "ignore").strip()
            except Exception:
                nickname = name_bytes.hex().upper()
        if nickname == "Unknown" and len(iccid) > 0:
            nickname = f"ICCID-{iccid[-4:]}"

        return ProfileRow(
            iccid=iccid,
            state=state,
            profile_class=profile_class,
            nickname=nickname,
            aid=aid,
        )

    def _get_tag(self, parsed: Dict[int, Any], tag: int, default: Any = None) -> Any:
        if TlvParser is not None:
            return TlvParser.get_first(parsed, tag, default)

        if tag not in parsed:
            return default
        value = parsed[tag]
        if isinstance(value, list):
            if len(value) == 0:
                return default
            return value[0]
        return value

    def _parse_tlv_simple(self, data: bytes) -> Dict[int, Any]:
        parsed: Dict[int, Any] = {}
        index = 0
        while index < len(data):
            tag = data[index]
            index += 1

            if (tag & 0x1F) == 0x1F:
                if index >= len(data):
                    break
                tag = (tag << 8) | data[index]
                index += 1
                while index < len(data):
                    octet = data[index]
                    if (octet & 0x80) == 0:
                        break
                    tag = (tag << 8) | octet
                    index += 1

            if index >= len(data):
                break

            length, length_size = self._decode_length(data, index)
            if length_size == 0:
                break
            index += length_size

            value_end = index + length
            if value_end > len(data):
                break
            value = data[index:value_end]
            index = value_end

            if tag in parsed:
                existing = parsed[tag]
                if isinstance(existing, list):
                    existing.append(value)
                else:
                    parsed[tag] = [existing, value]
            else:
                parsed[tag] = value

        return parsed

    def _decode_length(self, data: bytes, offset: int) -> Tuple[int, int]:
        if offset >= len(data):
            return 0, 0
        first = data[offset]
        if first < 0x80:
            return first, 1
        count = first & 0x7F
        if count == 0:
            return 0, 0
        end = offset + 1 + count
        if end > len(data):
            return 0, 0
        return int.from_bytes(data[offset + 1 : end], "big"), 1 + count

    def _swap_nibbles(self, text: str) -> str:
        output = []
        i = 0
        while i < len(text):
            if i + 1 < len(text):
                output.append(text[i + 1] + text[i])
            else:
                output.append(text[i])
            i += 2
        return "".join(output).replace("F", "")
