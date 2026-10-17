# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SCP80 CLI: operator-facing shell for OTA session setup, script dispatch, and response decoding."""
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

import atexit
import os
import re
import sys
from contextlib import contextmanager
from typing import Iterator

from yggdrasim_common.apdu_chunking import plan_oversized_command
from yggdrasim_common.command_log import run_with_command_log
from yggdrasim_common.process_debug import is_global_debug_enabled
from yggdrasim_common.quit_control import quit_all

if __package__:
    from .config import ConfigManager
    from .builder import OtaPacketBuilder
    from .transport import Transport
    from .crypto import CryptoEngine
    from .utils import Colors, Utils
else:
    from config import ConfigManager
    from builder import OtaPacketBuilder
    from transport import Transport
    from crypto import CryptoEngine
    from utils import Colors, Utils

try:
    # Imported by package name. Putting ``SCP03/`` itself on the path
    # would shadow the top-level ``main``, ``core`` and ``logic`` names
    # for the whole process.
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    from SCP03.core.decoders import ContentDecoder
    from SCP03.logic.fs import FileSystemController

    SCP03_AVAIL = True
except ImportError:
    SCP03_AVAIL = False

try:
    import readline
except ImportError:
    readline = None

APP_NAME = "YggdraSIM OTA Simulator"
VERSION = "2.6.0"


class SmartDecoder:
    def __init__(self):
        if SCP03_AVAIL:
            ContentDecoder.init_registry()
            self.fid_lookup = {}
            for name, fids in FileSystemController.DEFAULT_MAP.items():
                if isinstance(fids, list):
                    for f in fids:
                        self.fid_lookup[f] = name
                else:
                    self.fid_lookup[fids] = name

    def sniff_context(self, full_apdu: str):
        """Walk a raw APDU hex string to infer the selected FID and Le from SELECT/READ patterns."""
        idx = 0
        current_fid = None
        last_le = 0
        s = full_apdu.upper().replace(" ", "")
        try:
            while idx < len(s):
                if idx + 8 > len(s):
                    break
                ins = int(s[idx + 2 : idx + 4], 16)
                idx += 8
                lc = 0
                le = 0
                if idx + 2 <= len(s):
                    next_byte = int(s[idx : idx + 2], 16)
                    if ins == 0xA4:
                        lc = next_byte
                        idx += 2
                        if idx + (lc * 2) <= len(s):
                            current_fid = s[idx : idx + (lc * 2)]
                            idx += lc * 2
                        else:
                            break
                    elif ins in [0xD6, 0xDC]:
                        lc = next_byte
                        idx += 2 + (lc * 2)
                    elif ins in [0xB0, 0xB2]:
                        le = next_byte
                        idx += 2
                        last_le = le
                    else:
                        if idx + 2 == len(s):
                            le = next_byte
                            idx += 2
                            last_le = le
                        else:
                            lc = next_byte
                            idx += 2 + (lc * 2)
                else:
                    break
        except Exception:
            pass
        return current_fid, last_le

    @staticmethod
    def _extract_command_payload(le, por_hex, por_info=None):
        if le <= 0:
            return ""
        if isinstance(por_info, dict):
            if not por_info.get("valid"):
                return ""
            if por_info.get("status_code") != "00":
                return ""
            command_response = (
                str(por_info.get("command_response") or "").strip().upper()
            )
            if len(command_response) == 0:
                return ""
            command_sw = por_info.get("command_sw")
            response_body = command_response
            if command_sw is not None:
                sw_text = str(command_sw or "").strip().upper()
                if sw_text != "9000":
                    return ""
                if response_body.endswith(sw_text):
                    response_body = response_body[: -len(sw_text)]
            elif int(por_info.get("command_count") or 0) == 1:
                return ""
            needed = le * 2
            if len(response_body) < needed:
                return ""
            return response_body[-needed:]

        if por_hex.strip().upper().startswith("D0"):
            return ""
        if len(por_hex) >= (le * 2):
            return por_hex[-(le * 2) :]
        return ""

    def try_decode(self, fid, le, por_hex, por_info=None):
        """Attempt to decode a successful PoR command payload and print a summary."""
        if not SCP03_AVAIL or not por_hex:
            return
        payload = self._extract_command_payload(le, por_hex, por_info)

        if fid and payload:
            fid_name = self.fid_lookup.get(fid, fid)
            decoded = ContentDecoder.decode(fid, payload)
            if decoded:
                print(f"{Colors.CYAN}--- Decoded ({fid_name}) ---{Colors.ENDC}")
                for line in decoded.strip().split("\n"):
                    print(f"    {Colors.GREEN}{line}{Colors.ENDC}")


class OtaShell:
    def __init__(self):
        self.config = ConfigManager()
        self.builder = OtaPacketBuilder(self.config)
        self.transport = Transport(self.config)
        self.history_file = os.path.expanduser("~/.scp80_history")
        self.decoder = SmartDecoder()
        self.last_command_ok = True
        self.current_iccid = ""
        self.global_debug = is_global_debug_enabled()

    def _bind_inventory_profile(self, iccid: str, announce: bool = True) -> bool:
        normalized_iccid = "".join(ch for ch in str(iccid or "") if ch.isdigit())
        if len(normalized_iccid) == 0:
            return False
        payload = self.config.bind_iccid_profile(normalized_iccid)
        self.current_iccid = normalized_iccid
        if announce:
            if isinstance(payload, dict) and len(payload) > 0:
                print(
                    f"{Colors.GREEN}[+] Loaded SCP80 inventory profile for ICCID "
                    f"{normalized_iccid}.{Colors.ENDC}"
                )
            else:
                print(
                    f"{Colors.CYAN}[*] Seeded SCP80 inventory profile for ICCID "
                    f"{normalized_iccid} using current defaults.{Colors.ENDC}"
                )
        return True

    def _refresh_inventory_from_reader(self, announce: bool = True) -> bool:
        iccid = ""
        try:
            iccid = self.transport.read_iccid()
        except Exception as e:
            if announce:
                print(f"{Colors.FAIL}[!] Could not read ICCID: {e}{Colors.ENDC}")
            return False
        if len(iccid) == 0:
            if announce:
                print(
                    f"{Colors.WARNING}[*] ICCID not available from current reader session.{Colors.ENDC}"
                )
            return False
        return self._bind_inventory_profile(iccid, announce=announce)

    def _bind_print_profile(self, announce: bool = True) -> bool:
        sentinel = ConfigManager.PRINT_ICCID_SENTINEL
        payload = self.config.bind_iccid_profile(sentinel)
        self.current_iccid = sentinel
        if announce:
            if isinstance(payload, dict) and len(payload) > 0:
                print(
                    f"{Colors.GREEN}[+] PRINT mode: loaded isolated SCP80 profile "
                    f"for ICCID <{sentinel}>.{Colors.ENDC}"
                )
            else:
                print(
                    f"{Colors.CYAN}[*] PRINT mode: seeded isolated SCP80 profile "
                    f"for ICCID <{sentinel}> using current defaults.{Colors.ENDC}"
                )
        return True

    def _apply_transport_state(self, announce: bool = True) -> None:
        transport_mode = self.config.get("transport")
        if transport_mode == "reader":
            try:
                self.transport.connect(
                    verbose=bool(getattr(self, "global_debug", False))
                )
            except Exception as e:
                if announce:
                    print(f"{Colors.FAIL}[!] Reader connect failed: {e}{Colors.ENDC}")
            self._refresh_inventory_from_reader(announce=announce)
            return
        try:
            self.transport.disconnect()
        except Exception:
            pass
        self._bind_print_profile(announce=announce)

    def _prompt_tag(self) -> str:
        if self.config.get("transport") == "reader":
            return "READER"
        return "PRINT"

    @staticmethod
    def _normalize_script_hex_line(line: str) -> str:
        line_body = line.split("#", 1)[0]
        match = re.match(r"^\s*([0-9A-Fa-f][0-9A-Fa-f\s]*)", line_body)
        if match is None:
            return ""
        return "".join(match.group(1).split())

    # Verbs _process_line resolves before the do_<name> lookup; the
    # completer lists them beside the do_ handlers.
    BUILTIN_COMMANDS = ("admin", "exit", "q", "qa", "quit")
    FLAG_COMMANDS = ("build", "reset", "send")
    SET_VALUE_CHOICES = {
        "transport": ConfigManager.TRANSPORT_MODES,
        "concat_sms": ("ON", "OFF"),
    }

    def _setup_readline(self) -> None:
        if readline is None:
            return
        try:
            if os.path.exists(self.history_file):
                readline.read_history_file(self.history_file)
            readline.set_history_length(1000)
        except OSError:
            pass
        # The admin hand-back runs this again to take the completer back
        # from the SCP03 shell; the exit-time save is registered once.
        if not getattr(self, "_history_saver_registered", False):
            atexit.register(self._save_history)
            self._history_saver_registered = True
        readline.set_completer(self._completer)
        readline.set_completer_delims(" \t\n")
        if readline.__doc__ is not None and "libedit" in readline.__doc__:
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")
        try:
            readline.parse_and_bind("set show-all-if-ambiguous on")
        except Exception:
            # Optional on every readline flavour; a substitute module that
            # rejects the variable still completes on Tab.
            pass

    def _save_history(self) -> None:
        if readline is None:
            return
        try:
            readline.write_history_file(self.history_file)
        except OSError:
            pass

    def _command_names(self) -> list[str]:
        names = set(self.BUILTIN_COMMANDS)
        for attribute in dir(self):
            if attribute.startswith("do_") and callable(getattr(self, attribute, None)):
                names.add(attribute[3:])
        return sorted(names)

    def _set_key_names(self) -> list[str]:
        names = set(self.config.data.keys())
        for alias in self.SET_KEY_ALIASES:
            # The pre-rename spellings still dispatch but are not offered.
            if alias in ConfigManager.LEGACY_KEY_RENAMES:
                continue
            names.add(alias)
        return sorted(names)

    def _known_iccids(self) -> list[str]:
        """ICCIDs the device inventory has seen, for ``iccid`` completion."""
        inventory = getattr(self.config, "inventory", None)
        list_identities = getattr(inventory, "list_identities", None)
        if not callable(list_identities):
            return []
        try:
            rows = list_identities("iccid")
        except Exception:
            # A completer has no error channel: an unreadable inventory
            # collapses to "no candidates".
            return []
        iccids = []
        for row in rows:
            value = str(row.get("identity_value", "")) if isinstance(row, dict) else ""
            if len(value) > 0 and value.isdigit():
                iccids.append(value)
        return sorted(set(iccids))

    @staticmethod
    def _complete_path(token_text: str) -> list[str]:
        """Grow a typed path prefix into the matching files and directories."""
        expanded = os.path.expanduser(token_text)
        directory, prefix = os.path.split(expanded)
        search_dir = directory if len(directory) > 0 else "."
        try:
            entries = sorted(os.listdir(search_dir), key=str.lower)
        except OSError:
            return []
        matches = []
        for name in entries:
            if not name.startswith(prefix):
                continue
            if len(prefix) == 0 and name.startswith("."):
                continue
            completed = os.path.join(directory, name) if len(directory) > 0 else name
            if os.path.isdir(os.path.join(search_dir, name)):
                matches.append(completed + os.sep)
            else:
                matches.append(completed + " ")
        return matches

    def _completion_options_for(self, command: str, argument_text: str) -> list[str]:
        raw_tokens = argument_text.split(" ")
        trailing = raw_tokens[-1]
        preceding = [token for token in raw_tokens[:-1] if len(token) > 0]
        if command == "set":
            if len(preceding) == 0:
                typed = trailing.lower()
                return [f"{name} " for name in self._set_key_names() if name.startswith(typed)]
            if len(preceding) == 1:
                key = preceding[0].lower()
                key = self.SET_KEY_ALIASES.get(key, key)
                typed = trailing.lower()
                return [
                    f"{choice} "
                    for choice in self.SET_VALUE_CHOICES.get(key, ())
                    if choice.lower().startswith(typed)
                ]
            return []
        if command == "script" and len(preceding) == 0:
            return self._complete_path(trailing)
        if command == "iccid" and len(preceding) == 0:
            return [f"{iccid} " for iccid in self._known_iccids() if iccid.startswith(trailing)]
        if command in self.FLAG_COMMANDS and trailing.startswith("-"):
            if "-v".startswith(trailing) and "-v" not in preceding:
                return ["-v "]
        return []

    def _completer(self, text: str, state: int) -> str | None:
        if readline is None:
            return None
        # readline asks for state 0, 1, 2, ... per Tab press; the candidate
        # list (an inventory query or a directory listing) is built once.
        if state == 0:
            line_buffer = readline.get_line_buffer().lstrip()
            if " " not in line_buffer:
                typed = text.lower()
                self._completion_matches = [
                    f"{name} " for name in self._command_names() if name.startswith(typed)
                ]
            else:
                command, _, argument_text = line_buffer.partition(" ")
                self._completion_matches = self._completion_options_for(
                    command.lower(), argument_text
                )
        matches = getattr(self, "_completion_matches", [])
        if state < len(matches):
            return matches[state]
        return None

    def run(self):
        """Start the interactive SCP80 CLI REPL, handling OS-specific readline setup."""
        is_nt = False
        if os.name == "nt":
            is_nt = True

        if is_nt:
            os.system("cls")

        is_posix = False
        if os.name != "nt":
            is_posix = True

        if is_posix:
            os.system("clear")

        print(f"{Colors.HEADER}")
        print(r" __   __               _               ____ ___ __  __ ")
        print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print(r"      |___/  |___/                                     ")
        print(r"                    ___ _____  _    ")
        print(r"                   / _ \_   _|/ \   ")
        print(r"                  | | | || | / _ \  ")
        print(r"                  | |_| || |/ ___ \ ")
        print(r"                   \___/ |_/_/   \_" + "\\")
        print("")
        print("=== Remote File Management & Over-The-Air Payload Generator ===")
        print(" Authored and maintained by Hampus Hellsberg for 1oT OÜ")
        print(f"{Colors.ENDC}")

        self._setup_readline()

        self._apply_transport_state(announce=True)

        while True:
            try:
                mode = self._prompt_tag()

                line = input(f"\n{Colors.CYAN}[{mode}]{Colors.ENDC} > ").strip()

                is_empty = False
                if not line:
                    is_empty = True

                if is_empty:
                    continue

                self._save_history()

                processed = self._process_line(line)

                is_processed = False
                if processed:
                    is_processed = True

                is_failed = False
                if not is_processed:
                    is_failed = True

                if is_failed:
                    break

            except EOFError:
                print("\nExiting...")
                self._process_line("quit")
                break

            except KeyboardInterrupt:
                print(
                    "\nUse 'quit' to leave the SCP80 shell or 'qa' to exit YggdraSIM."
                )
                continue

            except Exception as e:
                print(f"{Colors.FAIL}Error: {e}{Colors.ENDC}")

    def run_commands(self, cmd_line: str) -> None:
        """Execute a semicolon-delimited list of CLI commands non-interactively."""
        for raw_command in str(cmd_line or "").split(";"):
            command_text = str(raw_command or "").strip()
            if len(command_text) == 0:
                continue
            keep_running = self._process_line(command_text)
            if not keep_running:
                break

    def _process_line(self, line: str) -> bool:
        """Run one OTA shell line; one carrying ``--log <file>`` runs under a command log."""
        keep_running = run_with_command_log(
            line,
            self._process_command_line,
            shell="SCP80",
            refused=None,
            debug=self._command_log_debug,
        )
        if keep_running is None:
            # Refused: the command did not run, so a script stops here.
            self.last_command_ok = False
            return True
        return keep_running

    @contextmanager
    def _command_log_debug(self) -> Iterator[None]:
        """Verbose build / send / reset for a ``--log`` command, as the global debug flag gives."""
        previous = bool(getattr(self, "global_debug", False))
        self.global_debug = True
        try:
            yield
        finally:
            self.global_debug = previous

    def _process_command_line(self, line: str) -> bool:
        self.last_command_ok = True
        cmd_parts = line.split()
        if not cmd_parts:
            return True
        cmd = cmd_parts[0].lower()
        args = cmd_parts[1:]

        is_admin = False
        if cmd == "admin":
            is_admin = True

        if is_admin:
            self._run_scp03_tool()
            return True
        if cmd == "qa":
            self.config.save()
            self.transport.disconnect()
            quit_all()
        if cmd in ["quit", "exit", "q"]:
            self.config.save()
            self.transport.disconnect()
            return False
        if hasattr(self, f"do_{cmd}"):
            getattr(self, f"do_{cmd}")(*args)
        elif all(c in "0123456789ABCDEFabcdef " for c in line):
            self.do_ota(line)
        else:
            print(f"{Colors.FAIL}Unknown command or invalid hex.{Colors.ENDC}")
        return True

    def do_history(self, *args):
        if not readline:
            return
        for i in range(1, readline.get_current_history_length() + 1):
            print(f"{i:4}: {readline.get_history_item(i)}")

    def do_show(self, *args):
        """Print the current ICCID, keyset, and transport configuration."""
        print(f"{Colors.CYAN}--- Configuration ---{Colors.ENDC}")
        if len(self.current_iccid) > 0:
            print(f"{'iccid':<14}: {self.current_iccid}")
        hidden = ["header", "cla", "sender"]
        # KIc/KID print in full; describe_keyset on the *_indicator fields
        # names the algorithm and keyset the two keys belong to.
        indicator_keys = ["kic_indicator", "kid_indicator"]
        for k, v in self.config.data.items():
            if k in hidden:
                continue
            if k in indicator_keys:
                val = CryptoEngine.describe_keyset(v)
            else:
                val = v
            print(f"{k:<14}: {val}")
        self._print_reader_protocol_caveat()
        print(f"{Colors.CYAN}---------------------{Colors.ENDC}")

    SET_KEY_ALIASES = {
        "counter": "cntr",
        "kic_identifier": "kic_indicator",
        "kid_identifier": "kid_indicator",
        "key_enc": "kic",
        "key_mac": "kid",
    }

    def do_set(self, *args):
        """Set a runtime configuration key-value pair (persisted in the OTA config)."""
        if len(args) < 2:
            print("Usage: set <k> <v>")
            return
        raw_key = args[0].lower()
        key = self.SET_KEY_ALIASES.get(raw_key, raw_key)
        # Hex values are joined without spaces so "AA BB" reads as one field;
        # a reader name keeps its spaces ("Remote Lab: Site A").
        value = " ".join(args[1:]) if key == "reader_name" else "".join(args[1:])
        previous_transport = self.config.get("transport")
        try:
            self.config.set(key, value)
            self.config.save()
            print(f"{Colors.GREEN}[+] {key} updated.{Colors.ENDC}")
        except ValueError as e:
            print(f"{Colors.FAIL}[!] {e}{Colors.ENDC}")
            return
        if key == "transport":
            new_transport = self.config.get("transport")
            if new_transport != previous_transport:
                self._apply_transport_state(announce=True)

    def do_iccid(self, *args):
        """Select the active ICCID for OTA operations; refreshes from the reader when no argument is given."""
        if len(args) == 0:
            if self.config.get("transport") == "reader":
                self._refresh_inventory_from_reader(announce=True)
                return
            if len(self.current_iccid) > 0:
                print(
                    f"{Colors.CYAN}[*] Active ICCID: {self.current_iccid}{Colors.ENDC}"
                )
                return
            print("Usage: iccid <decimal-iccid>")
            return
        iccid = "".join(ch for ch in str(args[0]) if ch.isdigit())
        if len(iccid) == 0:
            print(f"{Colors.FAIL}[!] ICCID must contain digits only.{Colors.ENDC}")
            return
        self._bind_inventory_profile(iccid, announce=True)

    @staticmethod
    def _override_payload_from_args(args) -> str:
        payload_parts = []
        for arg in args:
            if arg == "-v":
                continue
            payload_parts.append(arg)
        return "".join(payload_parts)

    def _print_build_plan(self, plan):
        if len(plan.apdus) == 1:
            print(f"APDU: {plan.apdus[0].apdu_hex}")
            return
        print(f"APDUs ({len(plan.apdus)} concatenated SMS segments):")
        for apdu in plan.apdus:
            print(f"  [{apdu.index + 1}/{apdu.total}] {apdu.apdu_hex}")
        if self.config.get("transport") == "reader" and len(plan.reader_apdus) > 0:
            print("  [reader] Direct reader mode sends one reassembled ENVELOPE APDU.")
            print(f"  [reader] {plan.reader_apdus[0]}")
            self._print_reader_protocol_caveat(multipart_required=True)

    def _print_reader_protocol_caveat(self, multipart_required: bool = False):
        if self.config.get("transport") != "reader":
            return
        info = self.transport.get_protocol_summary()
        if not info.get("available"):
            return
        if multipart_required and info.get("supports_t1"):
            return
        atr_hex = info.get("atr_hex") or "Unknown"
        active_protocol = info.get("active_protocol") or "UNKNOWN"
        if info.get("supports_t1"):
            print(
                f"{Colors.CYAN}[reader]{Colors.ENDC} ATR advertises T=1. Active protocol: {active_protocol}."
            )
            return
        print(
            f"{Colors.WARNING}[caveat]{Colors.ENDC} Current ATR does not advertise T=1. Active protocol: {active_protocol}."
        )
        print(f"{Colors.WARNING}[caveat]{Colors.ENDC} ATR: {atr_hex}")
        if multipart_required:
            print(
                f"{Colors.WARNING}[caveat]{Colors.ENDC} Multipart SCP80 in reader mode will require an extended ENVELOPE and is expected to fail on this path."
            )

    def _plan_apdu_list_for_transport(self, plan):
        is_reader = self.config.get("transport") == "reader"
        if is_reader and plan.is_concatenated and len(plan.reader_apdus) > 0:
            return plan.reader_apdus
        return [apdu.apdu_hex for apdu in plan.apdus]

    def do_build(self, *args):
        """Build the SCP80 OTA envelope for the active payload and print the APDU hex without sending."""
        verbose = bool(getattr(self, "global_debug", False)) or "-v" in args
        override_payload = self._override_payload_from_args(args)
        try:
            payload_override = None
            if len(override_payload) > 0:
                payload_override = override_payload
            plan = self.builder.build_plan(
                verbose=verbose, override_payload=payload_override
            )
            self._print_build_plan(plan)
        except Exception as e:
            print(f"Error: {e}")

    def do_send(self, *args):
        """Build and send the SCP80 OTA envelope, then print the POR response."""
        verbose = bool(getattr(self, "global_debug", False)) or "-v" in args
        try:
            override_payload = self._override_payload_from_args(args)
            payload_override = None
            if len(override_payload) > 0:
                payload_override = override_payload
            plan = self.builder.build_plan(
                verbose=verbose, override_payload=payload_override
            )
            if plan.is_concatenated:
                self._print_reader_protocol_caveat(multipart_required=True)
            result = self.transport.send_ota_sequence(
                self._plan_apdu_list_for_transport(plan), verbose=verbose
            )
            self.last_command_ok = bool(result.get("delivered"))
            self._print_result(result)
            por = result.get("por")
            payload_for_decode = getattr(
                plan,
                "payload_hex",
                payload_override or self.config.get("payload") or "",
            )
            if por and payload_for_decode:
                fid, le = self.decoder.sniff_context(payload_for_decode)
                self.decoder.try_decode(fid, le, por, result.get("por_decoded"))
        except Exception as e:
            self.last_command_ok = False
            print(f"{Colors.FAIL}Send Error: {e}{Colors.ENDC}")

    def do_sendraw(self, *args):
        """Transmit a raw APDU unwrapped, chaining an over-long data field into blocks."""
        if not args:
            return
        apdu_hex = "".join("".join(args).split())
        try:
            raw = Utils.to_bytes(apdu_hex)
        except ValueError as error:
            print(f"{Colors.FAIL}Invalid hex: {error}{Colors.ENDC}")
            return

        plan = plan_oversized_command(raw)
        if plan is None:
            self.transport.transmit(apdu_hex)
            return

        print(
            f"{Colors.CYAN}[*] {len(raw)} bytes exceed a short APDU; "
            f"chaining {len(plan)} blocks.{Colors.ENDC}"
        )
        for chunk in plan:
            _data, sw = self.transport.transmit(chunk.apdu_hex)
            if (int(sw) >> 8) not in (0x90, 0x61):
                print(
                    f"{Colors.FAIL}[-] Block {chunk.index + 1}/{chunk.total} failed: "
                    f"{int(sw):04X}; remaining blocks not sent.{Colors.ENDC}"
                )
                return

    def do_reset(self, *args):
        verbose = bool(getattr(self, "global_debug", False)) or "-v" in args
        self.transport.reset_connection(verbose=verbose)
        if self.config.get("transport") == "reader":
            self._refresh_inventory_from_reader(announce=True)

    def do_script(self, *args):
        """Execute a file of CLI commands line-by-line via ``run_commands``."""
        if not args:
            print("Usage: script <file>")
            return
        if not os.path.exists(args[0]):
            print("File not found")
            return
        print(f"{Colors.CYAN}[*] Executing script: {args[0]}{Colors.ENDC}")
        with open(args[0], "r", encoding="utf-8") as f:
            for line in f:
                normalized_line = self._normalize_script_hex_line(line)
                if len(normalized_line) == 0:
                    continue
                print(f"{Colors.BOLD}> {normalized_line}{Colors.ENDC}")
                if not self._process_line(normalized_line):
                    break
                if not self.last_command_ok:
                    print(
                        f"{Colors.FAIL}[!] Script aborted: OTA delivery failed and the counter was not advanced.{Colors.ENDC}"
                    )
                    break

    def do_ota(self, *args):
        """Wrap a raw APDU hex string in an SCP80 OTA envelope and transmit it."""
        raw_apdu = "".join("".join(args).split())
        fid, le = self.decoder.sniff_context(raw_apdu)

        try:
            verbose = bool(getattr(self, "global_debug", False))
            plan = self.builder.build_plan(verbose=verbose, override_payload=raw_apdu)
            if plan.is_concatenated:
                self._print_reader_protocol_caveat(multipart_required=True)
            result = self.transport.send_ota_sequence(
                self._plan_apdu_list_for_transport(plan), verbose=verbose
            )
            self.last_command_ok = bool(result.get("delivered"))
            self._print_result(result)

            por = result.get("por")
            if por:
                self.decoder.try_decode(fid, le, por, result.get("por_decoded"))

                if len(por) >= 4:
                    sw_in_por = por[-4:]
                    if sw_in_por.startswith("6C"):
                        correct_le = sw_in_por[2:]
                        self._handle_wrong_length(raw_apdu, correct_le)

        except Exception as e:
            self.last_command_ok = False
            print(f"{Colors.FAIL}OTA Error: {e}{Colors.ENDC}")

    def _handle_wrong_length(self, original_apdu, correct_le):
        print(
            f"{Colors.WARNING}[?] Target indicates wrong length. Correct Le: 0x{correct_le}{Colors.ENDC}"
        )
        q = (
            input(
                f"{Colors.WARNING}[?] Resend with Le={correct_le}? [Y/n] > {Colors.ENDC}"
            )
            .strip()
            .lower()
        )
        if q in ["", "y", "yes"]:
            new_apdu = self._reconstruct_apdu(original_apdu, correct_le)
            print(f"{Colors.CYAN}[*] Retrying with: {new_apdu}{Colors.ENDC}")
            self.do_ota(new_apdu)

    def _reconstruct_apdu(self, apdu_hex, new_le):

        idx = 0
        last_cmd_start = 0
        s = apdu_hex.upper()
        has_lc = False
        lc = 0

        while idx < len(s):
            last_cmd_start = idx
            if idx + 8 > len(s):
                break
            ins = int(s[idx + 2 : idx + 4], 16)
            idx += 8

            if idx >= len(s):
                break

            byte_val = int(s[idx : idx + 2], 16)

            has_lc = False

            if ins in [0xA4, 0xD6, 0xDC, 0x20, 0x24, 0x26, 0x28, 0x2C]:
                has_lc = True

            if has_lc:
                lc = byte_val
                idx += 2 + (lc * 2)

                if idx < len(s):
                    if idx + 2 == len(s):
                        idx += 2
            else:
                idx += 2

        last_cmd = s[last_cmd_start:]

        # Whether a trailing Le byte is present follows from the Lc actually
        # parsed for the final command, not from the total length's parity --
        # an even-length Lc payload makes the parity test wrong in both
        # directions (truncating case 3, doubling Le on case 4).
        expected_without_le = 8 + (2 + lc * 2 if has_lc else 0)
        if len(last_cmd) > expected_without_le:
            return s[:-2] + new_le
        return s + new_le

    def _print_result(self, result):
        sw = result.get("sw")
        por = result.get("por")
        error = result.get("error")
        segment_count = result.get("segment_count")
        failed_segment = result.get("failed_segment")
        if segment_count is not None:
            if segment_count > 1:
                print(
                    f"{Colors.CYAN}[SMS]{Colors.ENDC} Concatenated sequence with {segment_count} segments."
                )
        if por:
            print(f"{Colors.BLUE}[<--]{Colors.ENDC} {por} {sw}")
            self._print_por_decoded(result.get("por_decoded"))
        else:
            print(f"{Colors.BLUE}[<--]{Colors.ENDC} {sw}")
        if failed_segment is not None:
            print(f"{Colors.FAIL}[!] Failed at segment {failed_segment}.{Colors.ENDC}")
        if error:
            print(f"{Colors.FAIL}[!] {error}{Colors.ENDC}")

    def _print_por_decoded(self, por_info):
        if not por_info:
            return
        if por_info.get("status_code") == "00":
            command_sw = por_info.get("command_sw")
            if command_sw is None or str(command_sw).upper() == "9000":
                return
        if not por_info.get("valid"):
            error = por_info.get("error")
            if error:
                print(f"{Colors.WARNING}[POR]{Colors.ENDC} decode unavailable: {error}")
            return
        status_code = por_info.get("status_code") or "??"
        status_meaning = por_info.get("status_meaning") or "Unknown"
        parts = [
            f"{status_meaning} ({status_code})",
            f"TAR {por_info.get('tar')}",
            f"CNTR {por_info.get('cntr')}",
            f"PCNTR {por_info.get('pcntr')}",
        ]
        command_count = por_info.get("command_count")
        if command_count is not None:
            parts.append(f"commands {command_count}")
        command_sw = por_info.get("command_sw")
        command_response = por_info.get("command_response")
        if command_sw:
            parts.append(f"response {command_sw}")
        elif command_response:
            parts.append(f"response {command_response}")
        fetch_sw = por_info.get("fetch_sw")
        if fetch_sw:
            parts.append(f"fetch SW {fetch_sw}")
        print(
            f"{Colors.CYAN}[POR]{Colors.ENDC} "
            + ", ".join(str(part) for part in parts if part)
        )

    def do_help(self, *args):
        """Print the command reference for the interactive SCP80 CLI."""
        print("Commands:")
        print("  <hex string>    - Direct OTA wrap and send")
        print("  ota <hex>       - Explicit OTA wrap and send")
        print("  iccid [value]   - Read or bind ICCID-specific inventory profile")
        print("  script <file>   - Execute commands from file")
        print("  history         - Show command history")
        print("  set <k> <v>     - Update parameter")
        print("  send [-v] [hex] - Send configured or inline payload")
        print("  build [-v] [hex]- View OTA APDU or multipart sequence")
        print("  show            - View parameters")
        print("  sendraw <hex>   - Send raw APDU (no OTA)")
        print("  reset [-v]      - Re-initialize STK")
        print("  quit            - Exit SCP80 shell")
        print("  qa              - Exit YggdraSIM")
        print("  <cmd> --log <f> - Run one command verbose and append its output to file <f>")
        print("")
        print("Config keys:")
        print("  kic             - SCP80 ciphering key material")
        print("  kid             - SCP80 integrity key material")
        print("  kic_indicator   - KIc command-packet indicator byte")
        print("  kid_indicator   - KID command-packet indicator byte")
        print("  kic_identifier  - Alias for kic_indicator")
        print("  kid_identifier  - Alias for kid_indicator")
        print("  pid             - SMS TP-PID byte")
        print("  dcs             - SMS TP-DCS byte")
        print("  concat_sms      - ON or OFF automatic concatenation")
        print("  tp_ud_max       - Per-segment TP-UD ceiling (8-140)")

    def _run_scp03_tool(self):
        print(f"{Colors.HEADER}=== Switching to SCP03 Admin Shell ==={Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Releasing Card Reader...{Colors.ENDC}")

        has_transport = False
        if self.transport:
            has_transport = True

        if has_transport:
            try:
                self.transport.disconnect()
            except Exception:
                pass

        try:
            print(f"{Colors.CYAN}[*] Starting SCP03 Module...{Colors.ENDC}")
            import sys
            import importlib
            import os

            current_dir = os.path.dirname(os.path.abspath(__file__))
            root_path = os.path.abspath(os.path.join(current_dir, ".."))

            is_missing_path = False
            if root_path not in sys.path:
                is_missing_path = True

            if is_missing_path:
                sys.path.insert(0, root_path)

            import SCP03.main as scp03_entry

            importlib.reload(scp03_entry)

            scp03_entry.entry()

        except SystemExit:
            is_nt = False
            if os.name == "nt":
                is_nt = True

            if is_nt:
                os.system("cls")

            if not is_nt:
                os.system("clear")

        except ImportError as e:
            print(f"{Colors.FAIL}[!] Import Error: {e}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[!] SCP03 Tool Crashed: {e}{Colors.ENDC}")

        print(f"{Colors.HEADER}")
        print(r" __   __               _               ____ ___ __  __ ")
        print(r" \ \ / /__ _  __ _  __| | _ __  __ _  / ___|_ _|  \/  |")
        print(r"  \ V / _` | / _` |/ _` || '__|/ _` | \___ \| || |\/| |")
        print(r"   | | (_| || (_| | (_| || |  | (_| |  ___) | || |  | |")
        print(r"   |_|\__, | \__, |\__,_||_|   \__,_| |____/___|_|  |_|")
        print(r"      |___/  |___/                                     ")
        print(r"                   ___ _____ / \  ")
        print(r"                  / _ \_   _/ _ \ ")
        print(r"                 | | | || |/ ___ \ ")
        print(r"                 | |_| || / ___  \ ")
        print(r"                  \___/ |_/_/   \_" + "\\")
        print("")
        print("=== Remote File Management & Over-The-Air Payload Generator ===")
        print(" Authored and maintained by Hampus Hellsberg for 1oT OÜ")
        print(f"{Colors.ENDC}")

        print(f"\n{Colors.HEADER}=== Returning to SCP80 OTA Tool ==={Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Re-acquiring Card Reader...{Colors.ENDC}")

        try:
            is_reader_mode = False
            if self.config.get("transport") == "reader":
                is_reader_mode = True

            if is_reader_mode:
                self.transport.connect(
                    verbose=bool(getattr(self, "global_debug", False))
                )
                print(f"{Colors.GREEN}[+] Card Reader Re-connected.{Colors.ENDC}")

        except Exception as e:
            print(f"{Colors.FAIL}[!] Failed to reconnect reader: {e}{Colors.ENDC}")

        self._setup_readline()

    def run_standalone():
        """Entry point for switching from other modules."""
        if __package__:
            from .cli import OtaShell
        else:
            from cli import OtaShell

        try:
            shell = OtaShell()
            shell.run()
        except Exception as e:
            print(f"[-] SCP80 Execution Error: {e}")
