import argparse
import atexit
import os
import re
import shlex
import shutil
import sys
import textwrap
from typing import Any, List, Optional

from yggdrasim_common.quit_control import quit_all, QuitAllRequested
from yggdrasim_common.process_debug import (
    add_debug_argument,
    is_global_debug_enabled,
    set_global_debug,
)
from yggdrasim_common.card_backend import trigger_card_relay_modem_refresh
from yggdrasim_common.hil_bridge_runtime import hil_bridge_warning_text
from yggdrasim_common.session_recording import ShellSessionRecorder
from yggdrasim_common.structured_output import dump_structured_payload
from SCP11.shared.discovery_snapshot import render_consolidated_discovery_snapshot

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
    WHITE = "\033[38;2;247;252;255m"
    BOLD = "\033[1m"
    END = "\033[0m"


_COMMANDS = (
    "CERTS",
    "SMDP-CERTS",
    "DISCOVER",
    "EXPLAIN-LAST",
    "INFO",
    "LOAD-PROFILE",
    "ENABLE-PROFILE",
    "DISABLE-PROFILE",
    "DELETE-PROFILE",
    "REFRESH-MODEM",
    "ENABLE",
    "DISABLE",
    "DELETE",
    "MODEM-REFRESH",
    "STORE-METADATA",
    "STORE-METADATA-CUSTOM",
    "STORE-METADATA-CUSTOM-ALL",
    "UPDATE-METADATA",
    "PROFILE",
    "PROFILE-CLEAR",
    "METADATA",
    "METADATA-LINT",
    "METADATA-CLEAR",
    "RECORD",
    "EXPORT-KEYBAG",
    "STATUS",
    "HELP",
    "EXIT",
    "QA",
)

_COMMAND_ALIASES = {
    "SMDP-CERTS": "CERTS",
    "INFO": "DISCOVER",
    "ENABLE": "ENABLE-PROFILE",
    "DISABLE": "DISABLE-PROFILE",
    "DELETE": "DELETE-PROFILE",
    "MODEM-REFRESH": "REFRESH-MODEM",
    "PROFILE-RESET": "PROFILE-CLEAR",
    "METADATA-RESET": "METADATA-CLEAR",
    "QUIT": "EXIT",
    "Q": "EXIT",
}

_COMMAND_DOCS = {
    "CERTS": {
        "usage": "CERTS [--json|--yaml]",
        "summary": "Show local SM-DP+ certificate inventory and current selection.",
    },
    "DISCOVER": {
        "usage": "DISCOVER",
        "summary": "Run the shared SCP11 SGP.22/SGP.32 discovery snapshot.",
    },
    "EXPLAIN-LAST": {
        "usage": "EXPLAIN-LAST [--json|--yaml]",
        "summary": "Explain the last local SCP11 command state, selections, and response payloads.",
    },
    "STATUS": {
        "usage": "STATUS",
        "summary": "Show the current Local SMDPP session state and active targets.",
    },
    "LOAD-PROFILE": {
        "usage": "LOAD-PROFILE [path]",
        "summary": "Run one-shot open, prepare, load, and close for the active profile.",
    },
    "ENABLE-PROFILE": {
        "usage": "ENABLE-PROFILE <id>",
        "summary": "Enable the target profile and auto-disable the current active profile.",
    },
    "DISABLE-PROFILE": {
        "usage": "DISABLE-PROFILE <id>",
        "summary": "Disable a profile by ICCID, AID, or alias.",
    },
    "DELETE-PROFILE": {
        "usage": "DELETE-PROFILE <id>",
        "summary": "Delete a profile by ICCID, AID, or alias.",
    },
    "REFRESH-MODEM": {
        "usage": "REFRESH-MODEM [mode]",
        "summary": "Queue a proactive REFRESH toward the attached modem via the active HIL bridge.",
    },
    "STORE-METADATA": {
        "usage": "STORE-METADATA [path]",
        "summary": "Encode BF25 from metadata JSON and send it to the card.",
    },
    "UPDATE-METADATA": {
        "usage": "UPDATE-METADATA [path]",
        "summary": "Encode BF2A from metadata JSON and send it to the card.",
    },
    "STORE-METADATA-CUSTOM": {
        "usage": "STORE-METADATA-CUSTOM <tag> [path]",
        "summary": "Send one enabled custom metadata tag row.",
    },
    "STORE-METADATA-CUSTOM-ALL": {
        "usage": "STORE-METADATA-CUSTOM-ALL [path]",
        "summary": "Send all enabled custom metadata tag rows.",
    },
    "PROFILE": {
        "usage": "PROFILE [path]",
        "summary": "Show or set the active profile override path.",
    },
    "PROFILE-CLEAR": {
        "usage": "PROFILE-CLEAR",
        "summary": "Clear the active profile override path.",
    },
    "METADATA": {
        "usage": "METADATA [path]",
        "summary": "Show or set the active metadata JSON file.",
    },
    "METADATA-LINT": {
        "usage": "METADATA-LINT [path] [--json|--yaml]",
        "summary": "Validate metadata JSON, ASN.1 encodes, and enabled custom rows.",
    },
    "METADATA-CLEAR": {
        "usage": "METADATA-CLEAR",
        "summary": "Clear the active metadata override path.",
    },
    "RECORD": {
        "usage": "RECORD [STATUS|START [outputPath]|STOP [outputPath]|CANCEL]",
        "summary": "Capture replayable shell commands plus the underlying APDU trace.",
    },
    "EXPORT-KEYBAG": {
        "usage": "EXPORT-KEYBAG [path.keys.json] [label]",
        "summary": "Dump derived SCP11c BSP keys (S-ENC / S-MAC / mac-chain) for pcap-paired offline replay.",
    },
    "HELP": {
        "usage": "HELP [command]",
        "summary": "Show grouped canonical commands or help for one command.",
    },
    "EXIT": {
        "usage": "EXIT",
        "summary": "Leave the Local SMDPP shell.",
    },
    "QA": {
        "usage": "QA",
        "summary": "Leave the Local SMDPP shell and exit YggdraSIM.",
    },
}


class LocalAccessStartupError(RuntimeError):
    """Readable startup failure for the local SCP11 access shell."""


def _load_local_runtime():
    try:
        from .config import LocalAccessConfig
        from .session import LocalIsdrSession
    except ImportError:
        from SCP11.local_access.config import LocalAccessConfig
        from SCP11.local_access.session import LocalIsdrSession
    return LocalAccessConfig, LocalIsdrSession


class LocalAccessShell:
    """Minimal interactive shell for local SCP11 bring-up."""

    def __init__(self):
        config_cls, session_cls = _load_local_runtime()
        self._session_cls = session_cls
        self.cfg = config_cls()
        self.session = None
        self._global_debug = is_global_debug_enabled()
        self._recorder = ShellSessionRecorder(
            shell_name="scp11_local_access",
            module_entry_point="python -m SCP11.local_access",
        )
        self._history_file = os.path.join(
            os.path.expanduser("~"), ".yggdrasim_local_scp11_history"
        )

    def _setup_readline(self) -> None:
        if readline is None:
            return
        try:
            if os.path.exists(self._history_file):
                readline.read_history_file(self._history_file)
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
        if readline is None or len(self._history_file) == 0:
            return
        try:
            readline.write_history_file(self._history_file)
        except Exception:
            pass

    def _completer(self, text: str, state: int) -> Optional[str]:
        if readline is None:
            return None
        line_buffer = readline.get_line_buffer().lstrip()
        if " " in line_buffer and not line_buffer.startswith(" "):
            first = line_buffer.split(None, 1)[0].upper()
            if first in _COMMANDS and first in (
                "LOAD-PROFILE",
                "ENABLE-PROFILE",
                "DISABLE-PROFILE",
                "DELETE-PROFILE",
                "ENABLE",
                "DISABLE",
                "DELETE",
                "STORE-METADATA",
                "STORE-METADATA-CUSTOM",
                "STORE-METADATA-CUSTOM-ALL",
                "UPDATE-METADATA",
                "PROFILE",
                "METADATA",
                "METADATA-LINT",
            ):
                return None
        typed = (text or "").upper()
        options: List[str] = [c for c in _COMMANDS if c.startswith(typed)]
        if state >= len(options):
            return None
        if len(options) == 1:
            return options[state] + " "
        return options[state]

    def _build_session(self) -> None:
        if self.session is not None:
            return
        try:
            self.session = self._session_cls(cfg=self.cfg)
        except Exception as error:
            raise LocalAccessStartupError(
                f"Local SCP11 transport initialization failed: {error}"
            ) from error
        if self._global_debug:
            self._set_transport_debug(True)

    @staticmethod
    def _extract_debug_flag(arguments: list[str]) -> tuple[list[str], bool]:
        filtered: list[str] = []
        debug = False
        for argument in arguments:
            normalized = str(argument or "").strip().lower()
            if normalized in ("--debug", "-d"):
                debug = True
                continue
            filtered.append(argument)
        return filtered, debug

    def _set_transport_debug(self, enabled: bool) -> Optional[bool]:
        if self.session is None:
            return None
        apdu_channel = getattr(self.session, "apdu_channel", None)
        setter = getattr(apdu_channel, "set_raw_apdu_logging", None)
        getter = getattr(apdu_channel, "get_raw_apdu_logging", None)
        if callable(setter) is False:
            return None
        previous: Optional[bool] = None
        if callable(getter):
            current = getter()
            if current is not None:
                previous = bool(current)
        setter(bool(enabled))
        return previous

    def _restore_transport_debug(self, previous: Optional[bool]) -> None:
        if previous is None or self.session is None:
            return
        apdu_channel = getattr(self.session, "apdu_channel", None)
        setter = getattr(apdu_channel, "set_raw_apdu_logging", None)
        if callable(setter):
            setter(bool(previous))

    @staticmethod
    def _render_command_line(command: str, arguments: list[str]) -> str:
        normalized_command = str(command or "").strip()
        if len(normalized_command) == 0:
            return ""
        tokens = [normalized_command]
        for argument in arguments:
            text = str(argument or "").strip()
            if len(text) == 0:
                continue
            tokens.append(text)
        return shlex.join(tokens)

    def _print_record_status(self) -> None:
        status = self._recorder.status_payload()
        state = "active" if status.get("active") else "idle"
        print(f"[*] Recorder status: {state}")
        print(f"    entry      : {status.get('module_entry_point', '-')}")
        pending_path = str(status.get("pending_output_path", "") or "").strip()
        print(f"    output     : {pending_path or '-'}")
        print(f"    commands   : {status.get('command_count', 0)}")
        print(f"    apdus      : {status.get('apdu_count', 0)}")
        started_at = str(status.get("started_at_utc", "") or "").strip()
        print(f"    started_at : {started_at or '-'}")
        last_export = str(status.get("last_export_path", "") or "").strip()
        if len(last_export) > 0:
            print(f"    last_file  : {last_export}")

    def _cmd_record(self, arguments: list[str]) -> None:
        parts = [str(value or "").strip() for value in arguments if len(str(value or "").strip()) > 0]
        if len(parts) == 0 or parts[0].upper() == "STATUS":
            self._print_record_status()
            return
        action = parts[0].upper()
        output_path = " ".join(parts[1:]).strip()
        if action == "START":
            target_path = self._recorder.start(output_path=output_path)
            print("[+] Recording started.")
            print(f"    output   : {target_path}")
            print("    capture  : shell commands + APDU trace")
            print("    format   : YAML by default, JSON when outputPath ends with .json")
            return
        if action == "STOP":
            if self._recorder.is_active() is False:
                print("[*] Recording is not active.")
                self._print_record_status()
                return
            target_path, payload = self._recorder.stop(output_path=output_path)
            summary = payload.get("summary", {})
            print("[+] Recording saved.")
            print(f"    file     : {target_path}")
            print(f"    commands : {summary.get('command_count', 0)}")
            print(f"    apdus    : {summary.get('apdu_count', 0)}")
            return
        if action == "CANCEL":
            if self._recorder.is_active() is False:
                print("[*] Recording is not active.")
                return
            self._recorder.cancel()
            print("[+] Recording cancelled. Discarded in-memory command/APDU capture.")
            return
        raise ValueError("Usage: RECORD [STATUS|START [outputPath]|STOP [outputPath]|CANCEL]")

    def _cmd_export_keybag(self, arguments: list[str]) -> None:
        """Dump the last-derived SCP11c BSP keys into a HIL keybag JSON.

        The snapshot is populated by
        `LocalSmdppSession._snapshot_session_bsp` whenever a BSP is
        constructed (LOAD-PROFILE and custom A3 generation paths). If
        the fields are empty the operator is asked to run
        `LOAD-PROFILE` (or any profile command that opens a BSP-bound
        channel) first.
        """
        out_path = "scp11c_session.keys.json"
        label = "scp11c-local"
        if len(arguments) > 0:
            candidate_path = str(arguments[0] or "").strip()
            if len(candidate_path) > 0:
                out_path = candidate_path
        if len(arguments) > 1:
            candidate_label = str(arguments[1] or "").strip()
            if len(candidate_label) > 0:
                label = candidate_label

        if self.session is None:
            raise RuntimeError("Local SCP11 session is not initialized; cannot export keybag.")

        state = self.session.state
        s_enc_hex = str(getattr(state, "last_bsp_s_enc_hex", "") or "").strip()
        s_mac_hex = str(getattr(state, "last_bsp_s_mac_hex", "") or "").strip()
        if len(s_enc_hex) == 0 or len(s_mac_hex) == 0:
            raise RuntimeError(
                "No SCP11c BSP keys captured yet. Run LOAD-PROFILE first so the "
                "session derives BSP S-ENC / S-MAC, then retry EXPORT-KEYBAG."
            )

        mac_chain_hex = str(getattr(state, "last_bsp_mac_chain_hex", "") or "00" * 16)
        block_nr = int(getattr(state, "last_bsp_block_nr", 0) or 0)
        aid_hex = str(getattr(state, "last_bsp_aid_hex", "") or "").strip().upper()

        try:
            from Tools.HilBridge.scp_keybag_export import (
                KeybagExportEntry,
                write_keybag_file,
            )
        except ImportError as error:
            raise RuntimeError(f"Keybag exporter unavailable: {error}")

        entry = KeybagExportEntry(
            label=label,
            protocol="scp11c",
            s_enc_hex=s_enc_hex,
            s_mac_hex=s_mac_hex,
            s_rmac_hex=s_mac_hex,
            match_aid_hex=aid_hex,
            initial_ssc=block_nr,
            initial_chaining_hex=mac_chain_hex,
        )

        written_path = write_keybag_file(out_path, [entry], merge_existing=True)
        suffix = ""
        if len(aid_hex) > 0:
            suffix = f" aid={aid_hex}"
        print(f"[+] Keybag written: {written_path} label={label}{suffix}")
        print("    Pair with a sibling .pcap (rename to <pcap>.keys.json) for offline HIL replay.")

    def _finalize_recording_on_exit(self) -> None:
        if self._recorder.is_active() is False:
            return
        try:
            target_path, payload = self._recorder.stop()
        except Exception as error:
            self._recorder.cancel()
            print(f"[-] Could not save active recording: {error}")
            return
        summary = payload.get("summary", {})
        print("[*] Active recording auto-saved on shell exit.")
        print(f"    file     : {target_path}")
        print(f"    commands : {summary.get('command_count', 0)}")
        print(f"    apdus    : {summary.get('apdu_count', 0)}")

    @staticmethod
    def _hex_preview(value: bytes, max_chars: int = 48) -> str:
        if len(value) == 0:
            return "-"
        encoded = value.hex().upper()
        if len(encoded) <= max_chars:
            return encoded
        return f"{encoded[:max_chars]}..."

    @staticmethod
    def _compress_length_runs(lengths: List[int]) -> str:
        if len(lengths) == 0:
            return "-"
        parts: List[str] = []
        current = int(lengths[0])
        count = 1
        for value in lengths[1:]:
            if int(value) == current:
                count += 1
                continue
            if count == 1:
                parts.append(str(current))
            else:
                parts.append(f"{count}x{current}")
            current = int(value)
            count = 1
        if count == 1:
            parts.append(str(current))
        else:
            parts.append(f"{count}x{current}")
        return " + ".join(parts)

    @staticmethod
    def _parse_length_list(lengths_text: str) -> List[int]:
        lengths: List[int] = []
        for item in str(lengths_text).split(","):
            text = item.strip()
            if len(text) == 0:
                continue
            try:
                lengths.append(int(text))
            except ValueError:
                continue
        return lengths

    @staticmethod
    def _first_overlap_label(overlap_text: str) -> str:
        cleaned = str(overlap_text or "").strip()
        if len(cleaned) == 0:
            return ""
        return cleaned.split(",", 1)[0].strip()

    @staticmethod
    def _last_overlap_label(overlap_text: str) -> str:
        cleaned = str(overlap_text or "").strip()
        if len(cleaned) == 0:
            return ""
        parts = [part.strip() for part in cleaned.split(",") if len(part.strip()) > 0]
        while len(parts) > 0 and parts[-1] == "...":
            parts.pop()
        if len(parts) == 0:
            return ""
        return parts[-1]

    @staticmethod
    def _short_debug_path(path_text: str) -> str:
        cleaned = str(path_text or "").strip().rstrip("/")
        if len(cleaned) == 0:
            return "-"
        base = os.path.basename(cleaned)
        if len(base) > 0:
            return base
        return cleaned

    @staticmethod
    def _extract_output_mode(arguments: list[str]) -> tuple[list[str], str]:
        filtered: list[str] = []
        output_mode = "text"
        for argument in arguments:
            normalized = str(argument or "").strip().lower()
            if normalized not in ("--json", "--yaml"):
                filtered.append(argument)
                continue
            requested_mode = "json" if normalized == "--json" else "yaml"
            if output_mode not in ("text", requested_mode):
                raise ValueError("Choose only one structured output mode: --json or --yaml.")
            output_mode = requested_mode
        return filtered, output_mode

    @staticmethod
    def _print_structured_payload(payload: Any, output_mode: str) -> None:
        print(dump_structured_payload(payload, output_mode=output_mode))

    @staticmethod
    def _payload_summary(value: bytes, *, max_chars: int = 96) -> dict[str, Any]:
        raw_value = bytes(value or b"")
        return {
            "present": len(raw_value) > 0,
            "len": len(raw_value),
            "preview_hex": LocalAccessShell._hex_preview(raw_value, max_chars=max_chars),
        }

    def _build_metadata_lint_payload(self, metadata_path: str = "") -> dict[str, Any]:
        report = dict(self.session.lint_metadata(metadata_path=metadata_path))
        store_metadata_der = self.session.encode_metadata_asn1(override_path=metadata_path)
        report["store_metadata_tag_hex"] = "BF25"
        report["store_metadata_preview_hex"] = self._hex_preview(
            store_metadata_der,
            max_chars=120,
        )
        update_error = str(report.get("update_metadata_error", "") or "").strip()
        if len(update_error) == 0:
            update_metadata_der = self.session.encode_update_metadata_asn1(
                override_path=metadata_path
            )
            report["update_metadata_tag_hex"] = "BF2A"
            report["update_metadata_preview_hex"] = self._hex_preview(
                update_metadata_der,
                max_chars=120,
            )
        else:
            report["update_metadata_tag_hex"] = "BF2A"
            report["update_metadata_preview_hex"] = "-"
        custom_rows = self.session.load_enabled_custom_metadata_entries(
            override_path=metadata_path
        )
        report["enabled_custom_rows"] = [
            {
                "tag_hex": str(row.get("tag_hex", "")).upper(),
                "path": str(row.get("path", "")).strip(),
                "source_key": str(row.get("source_key", "")).strip(),
            }
            for row in custom_rows
        ]
        return report

    def _build_last_operation_report(self) -> dict[str, Any]:
        if self.session is None:
            return {
                "session_initialized": False,
                "reason": "session object is not initialized",
            }

        state = self.session.state
        resolved_profile = ""
        resolved_profile_error = ""
        try:
            resolved_profile = self.session.resolve_profile_path()
        except Exception as error:
            resolved_profile_error = str(error)
        resolved_metadata = ""
        resolved_metadata_error = ""
        try:
            resolved_metadata = self.session.resolve_metadata_path()
        except Exception as error:
            resolved_metadata_error = str(error)

        return {
            "session_initialized": True,
            "session": {
                "session_open": bool(state.session_open),
                "isdr_selected": bool(state.isdr_selected),
                "active_eid": self.session.current_eid or "",
                "transaction_id_hex": state.transaction_id.hex().upper(),
                "card_challenge_hex": state.card_challenge.hex().upper(),
                "server_challenge_hex": state.server_challenge.hex().upper(),
                "load_notifications_synced": bool(state.load_notifications_synced),
            },
            "selection": {
                "allowed_ci_pkids": list(state.allowed_ci_pkids),
                "selected_ci_pkid": state.selected_ci_pkid,
                "auth_certificate_path": state.selected_auth_certificate_path,
                "auth_private_key_path": state.selected_auth_private_key_path,
                "auth_selection_reason": state.selected_auth_certificate_reason,
                "pb_certificate_path": state.selected_pb_certificate_path,
                "pb_private_key_path": state.selected_pb_private_key_path,
                "pb_selection_reason": state.selected_pb_certificate_reason,
                "local_smdp_address": state.selected_local_smdp_address,
            },
            "targets": {
                "profile_override_path": state.profile_override_path,
                "resolved_profile_path": resolved_profile,
                "resolved_profile_error": resolved_profile_error,
                "metadata_override_path": state.metadata_override_path,
                "resolved_metadata_path": resolved_metadata,
                "resolved_metadata_error": resolved_metadata_error,
            },
            "responses": {
                "select_isdr": self._payload_summary(state.select_response),
                "euicc_info1": self._payload_summary(state.euicc_info1),
                "configured_data": self._payload_summary(state.configured_data),
                "authenticate_server_request": self._payload_summary(
                    state.authenticate_server_request
                ),
                "authenticate_server_response": self._payload_summary(
                    state.authenticate_server_response
                ),
                "euicc_signed1": self._payload_summary(state.euicc_signed1),
                "euicc_signature1": self._payload_summary(state.euicc_signature1),
                "prepare_download_response": self._payload_summary(
                    state.prepare_download_response
                ),
                "last_load_bpp_response": self._payload_summary(
                    state.last_load_bpp_response
                ),
                "cancel_session_response": self._payload_summary(
                    state.cancel_session_response
                ),
            },
            "bpp": {
                "command_descriptions": list(state.bpp_command_descriptions),
                "protected_command_descriptions": list(
                    state.upp_protected_command_descriptions
                ),
                "layout_summary": self._summarize_bpp_layout_lines(
                    list(state.last_bpp_layout_lines)
                ),
                "crypto_summary": self._summarize_bpp_crypto_lines(
                    list(state.last_bpp_crypto_debug_lines)
                ),
                "debug_artifacts": {
                    "pre_bsp_payload_bin_path": state.last_pre_bsp_payload_bin_path,
                    "pre_bsp_payload_hex_path": state.last_pre_bsp_payload_hex_path,
                },
            },
        }

    def _print_last_operation_report(self, payload: dict[str, Any]) -> None:
        if payload.get("session_initialized") is False:
            print("[*] No local SCP11 session state is available yet.")
            reason = str(payload.get("reason", "")).strip()
            if len(reason) > 0:
                print(f"    reason: {reason}")
            return

        session = payload.get("session", {})
        selection = payload.get("selection", {})
        targets = payload.get("targets", {})
        responses = payload.get("responses", {})
        bpp = payload.get("bpp", {})

        print("\n--- Local SCP11 Explain Last ---")
        print(f"Session open          : {'yes' if session.get('session_open') else 'no'}")
        print(f"ISD-R selected        : {'yes' if session.get('isdr_selected') else 'no'}")
        print(f"Active EID            : {session.get('active_eid') or '-'}")
        print(f"Transaction ID        : {session.get('transaction_id_hex') or '-'}")
        print(f"Card challenge        : {session.get('card_challenge_hex') or '-'}")
        print(f"Server challenge      : {session.get('server_challenge_hex') or '-'}")
        print(
            f"Notifications synced  : {'yes' if session.get('load_notifications_synced') else 'no'}"
        )
        print(f"Allowed CI PKIDs      : {', '.join(selection.get('allowed_ci_pkids', [])) or '-'}")
        print(f"Selected CI PKID      : {selection.get('selected_ci_pkid') or '-'}")
        print(f"Auth certificate      : {selection.get('auth_certificate_path') or '-'}")
        print(f"Auth selection rule   : {selection.get('auth_selection_reason') or '-'}")
        print(f"PB certificate        : {selection.get('pb_certificate_path') or '-'}")
        print(f"PB selection rule     : {selection.get('pb_selection_reason') or '-'}")
        print(f"Local SM-DP+ address  : {selection.get('local_smdp_address') or '-'}")
        print(f"Resolved profile      : {targets.get('resolved_profile_path') or '-'}")
        if targets.get("resolved_profile_error"):
            print(f"Profile resolution err: {targets.get('resolved_profile_error')}")
        print(f"Resolved metadata     : {targets.get('resolved_metadata_path') or '-'}")
        if targets.get("resolved_metadata_error"):
            print(f"Metadata resolution err: {targets.get('resolved_metadata_error')}")
        print("Response digests      :")
        for key, row in responses.items():
            label = key.replace("_", " ")
            preview = row.get("preview_hex", "-")
            size = int(row.get("len", 0))
            print(f"  - {label:<28} {size:>5} bytes  {preview}")
        command_rows = bpp.get("command_descriptions", [])
        if isinstance(command_rows, list) and len(command_rows) > 0:
            print("BPP commands          :")
            for line in command_rows:
                print(f"  - {line}")
        protected_rows = bpp.get("protected_command_descriptions", [])
        if isinstance(protected_rows, list) and len(protected_rows) > 0:
            print("Protected commands    :")
            for line in protected_rows:
                print(f"  - {line}")
        layout_rows = bpp.get("layout_summary", [])
        if isinstance(layout_rows, list) and len(layout_rows) > 0:
            print("BPP layout summary    :")
            for line in layout_rows:
                print(f"  - {line}")
        crypto_rows = bpp.get("crypto_summary", [])
        if isinstance(crypto_rows, list) and len(crypto_rows) > 0:
            print("BPP crypto summary    :")
            for line in crypto_rows:
                print(f"  - {line}")
        debug_artifacts = bpp.get("debug_artifacts", {})
        if isinstance(debug_artifacts, dict):
            bin_path = str(debug_artifacts.get("pre_bsp_payload_bin_path", "")).strip()
            hex_path = str(debug_artifacts.get("pre_bsp_payload_hex_path", "")).strip()
            if len(bin_path) > 0 or len(hex_path) > 0:
                print("Debug artifacts       :")
                if len(bin_path) > 0:
                    print(f"  - pre_bsp_payload_bin: {bin_path}")
                if len(hex_path) > 0:
                    print(f"  - pre_bsp_payload_hex: {hex_path}")

    @staticmethod
    def _summarize_bpp_layout_lines(lines: List[str]) -> List[str]:
        summary: List[str] = []
        a3_header = ""
        a3_lengths: List[int] = []
        a3_ranges: List[tuple[int, int]] = []
        a3_first_overlap = ""
        a3_last_overlap = ""
        a3_member_re = re.compile(
            r"^A3\[(?P<index>\d+)\] len=(?P<length>\d+) "
            r"plaintext\[(?P<start>\d+):(?P<end>\d+)\]"
            r"(?: overlaps (?P<overlap>.*))?$"
        )
        for line in lines:
            if " total=" in line and " memberLengths=[" in line and line.endswith("]"):
                prefix, lengths_text = line.split(" memberLengths=[", 1)
                lengths = LocalAccessShell._parse_length_list(lengths_text[:-1])
                compact_lengths = LocalAccessShell._compress_length_runs(lengths)
                if prefix.startswith("A3 "):
                    a3_header = f"{prefix} lengths={compact_lengths}"
                else:
                    summary.append(f"{prefix} lengths={compact_lengths}")
                continue
            if line.startswith(("A0[", "A1[", "A2[")):
                continue
            if line.startswith("A3["):
                match = a3_member_re.match(line)
                if match is not None:
                    a3_lengths.append(int(match.group("length")))
                    a3_ranges.append((int(match.group("start")), int(match.group("end"))))
                    overlap = str(match.group("overlap") or "").strip()
                    if len(overlap) > 0:
                        if len(a3_first_overlap) == 0:
                            a3_first_overlap = overlap
                        a3_last_overlap = overlap
                continue
            summary.append(line)
        if len(a3_header) > 0:
            if len(a3_ranges) > 0:
                plain_total = sum(end - start for start, end in a3_ranges)
                first_start = a3_ranges[0][0]
                last_end = a3_ranges[-1][1]
                a3_header += f" plaintext={plain_total} [{first_start}:{last_end}]"
            elif len(a3_lengths) > 0:
                a3_header += f" plaintext={sum(a3_lengths)}"
            summary.append(a3_header)
            first_label = LocalAccessShell._first_overlap_label(a3_first_overlap)
            last_label = LocalAccessShell._last_overlap_label(a3_last_overlap)
            if len(first_label) > 0 and len(last_label) > 0:
                summary.append(f"A3 overlap span={first_label} -> {last_label}")
        return summary

    @staticmethod
    def _summarize_bpp_crypto_lines(lines: List[str]) -> List[str]:
        summary: List[str] = []
        a3_plain_lengths: List[int] = []
        a3_protected_lengths: List[int] = []
        a3_protected_value_lengths: List[int] = []
        a3_tags: List[str] = []
        block_start = ""
        block_end = ""
        mac_start = ""
        mac_end = ""
        pre_bsp_re = re.compile(
            r"^Pre-BSP payload bin=(?P<bin>\S+) hex=(?P<hex>\S+) sha256=(?P<sha>[0-9A-F]+)$"
        )
        a3_chunk_re = re.compile(
            r"^A3\[(?P<index>\d+)\] plain=(?P<plain>\d+) plain_sha256=[0-9A-F]+ "
            r"protected=(?P<protected>\d+) protected_tag=(?P<tag>[0-9A-F?]+) "
            r"protected_value=(?P<protected_value>\d+) block_nr=(?P<block_before>\d+)->(?P<block_after>\d+) "
            r"mac_chain=(?P<mac_before>[0-9A-F]+)->(?P<mac_after>[0-9A-F]+)"
            r"(?: plaintext\[(?P<start>\d+):(?P<end>\d+)\](?: overlaps (?P<overlap>.*))?)?$"
        )
        for line in lines:
            if line.startswith("Pre-BSP payload "):
                match = pre_bsp_re.match(line)
                if match is None:
                    summary.append(line)
                    continue
                summary.append(
                    "Pre-BSP payload "
                    f"bin={LocalAccessShell._short_debug_path(match.group('bin'))} "
                    f"hex={LocalAccessShell._short_debug_path(match.group('hex'))} "
                    f"sha256={match.group('sha')}"
                )
                continue
            if line.startswith("A3["):
                match = a3_chunk_re.match(line)
                if match is None:
                    continue
                a3_plain_lengths.append(int(match.group("plain")))
                a3_protected_lengths.append(int(match.group("protected")))
                a3_protected_value_lengths.append(int(match.group("protected_value")))
                a3_tags.append(str(match.group("tag")))
                if len(block_start) == 0:
                    block_start = str(match.group("block_before"))
                block_end = str(match.group("block_after"))
                if len(mac_start) == 0:
                    mac_start = str(match.group("mac_before"))
                mac_end = str(match.group("mac_after"))
                continue
            summary.append(line)
        if len(a3_plain_lengths) == 0:
            return summary
        summary.append(
            "A3 chunks="
            f"{len(a3_plain_lengths)} "
            f"plain={LocalAccessShell._compress_length_runs(a3_plain_lengths)} "
            f"({sum(a3_plain_lengths)}) "
            f"protected={LocalAccessShell._compress_length_runs(a3_protected_lengths)} "
            f"({sum(a3_protected_lengths)})"
        )
        protected_value_summary = LocalAccessShell._compress_length_runs(a3_protected_value_lengths)
        unique_tags = sorted(set(a3_tags))
        tag_summary = ",".join(unique_tags)
        chain_line = f"A3 protected_value={protected_value_summary}"
        if len(block_start) > 0 and len(block_end) > 0:
            chain_line += f" block_nr={block_start}->{block_end}"
        if len(tag_summary) > 0:
            chain_line += f" tag={tag_summary}"
        if len(mac_start) > 0 and len(mac_end) > 0:
            chain_line += f" mac_chain={mac_start}->{mac_end}"
        summary.append(chain_line)
        return summary

    @staticmethod
    def _short_text(value: str, max_len: int = 64) -> str:
        cleaned = str(value or "").strip()
        if len(cleaned) <= max_len:
            return cleaned
        return cleaned[:max_len] + "..."

    @staticmethod
    def _format_error_message(error: BaseException) -> str:
        return str(error).strip() or error.__class__.__name__

    def _print_profile_state_response(self, action_label: str, response: bytes) -> None:
        print(f"[+] {action_label} completed. Last response: {len(response)} bytes.")
        if len(response) > 0:
            print(f"    {self._hex_preview(response, max_chars=80)}")

    def _queue_modem_refresh(self, action_label: str, mode: str = "") -> None:
        try:
            payload = trigger_card_relay_modem_refresh(
                mode=mode,
                source=f"scp11-local:{action_label}",
            )
        except Exception as error:
            print(f"[*] {action_label}: modem REFRESH queue failed ({error}).")
            return
        if payload is None:
            return
        status = str(payload.get("status", "queued") or "queued")
        mode_name = str(payload.get("mode", "") or "")
        print(
            f"[*] {action_label}: modem REFRESH {status} "
            f"({mode_name or 'euicc-profile-state-change'})."
        )

    def _safe_collect_profile_metadata(self) -> List[Any]:
        if self.session is None:
            return []
        try:
            return list(self.session.collect_profile_metadata())
        except Exception as error:
            print(f"[*] Profile metadata lookup unavailable: {error}")
            return []

    def _find_profile_metadata(self, entries: List[Any], identifier: str) -> Optional[Any]:
        target = identifier.strip().upper()
        if len(target) == 0:
            return None

        for entry in entries:
            iccid = str(getattr(entry, "iccid", "")).strip().upper()
            aid = str(getattr(entry, "aid", "")).strip().upper()
            if iccid == target or aid == target:
                return entry

        if self.session is None:
            return None
        resolved = self.session.resolve_profile_target(identifier)
        if resolved is None:
            return None
        target_tag, value_hex = resolved
        target_tag_hex = target_tag.hex().upper()
        for entry in entries:
            aid = str(getattr(entry, "aid", "")).strip().upper()
            iccid = str(getattr(entry, "iccid", "")).strip()
            if target_tag_hex == "4F" and aid == value_hex.upper():
                return entry
            if target_tag_hex == "5A":
                encoded_iccid = self.session.resolve_profile_target(iccid)
                if encoded_iccid == resolved:
                    return entry
        return None

    @staticmethod
    def _profile_metadata_matches(left: Any, right: Any) -> bool:
        left_aid = str(getattr(left, "aid", "")).strip().upper()
        right_aid = str(getattr(right, "aid", "")).strip().upper()
        if len(left_aid) > 0 and len(right_aid) > 0:
            return left_aid == right_aid
        return str(getattr(left, "iccid", "")).strip().upper() == str(getattr(right, "iccid", "")).strip().upper()

    def _find_enabled_profile(self, entries: List[Any], exclude_profile: Optional[Any] = None) -> Optional[Any]:
        for entry in entries:
            if exclude_profile is not None and self._profile_metadata_matches(entry, exclude_profile):
                continue
            if str(getattr(entry, "state", "")).strip().upper() == "ENABLED":
                return entry
        return None

    def _allow_auto_disable_for_enable(self, active_profile: Any, target_profile: Optional[Any]) -> bool:
        if self._profile_disable_not_allowed(active_profile) is False:
            return True
        target_description = "requested target"
        if target_profile is not None:
            target_description = self._describe_profile_metadata(target_profile)
        print(
            "[!] EnableProfile: guarded mode refused to auto-disable active profile "
            f"{self._describe_profile_metadata(active_profile)} because its PPR advertises "
            "ppr1-disable-not-allowed."
        )
        print(
            "    Use a rollback-enabled profile switch path, or move the active profile "
            f"away from {target_description} in the modem before retrying."
        )
        return False

    @staticmethod
    def _profile_disable_not_allowed(entry: Any) -> bool:
        ppr_hex = str(getattr(entry, "profile_policy_rules_hex", "") or "").strip()
        if len(ppr_hex) < 4:
            return False
        try:
            raw = bytes.fromhex(ppr_hex)
        except ValueError:
            return False
        if len(raw) < 2:
            return False
        unused_bits = int(raw[0])
        payload = raw[1:]
        if len(payload) == 0:
            return False
        bit_index = 0
        for byte_index, byte_value in enumerate(payload):
            for mask_bit in range(7, -1, -1):
                if byte_index == len(payload) - 1 and mask_bit < unused_bits:
                    continue
                is_set = ((byte_value >> mask_bit) & 0x01) == 0x01
                if bit_index == 1 and is_set:
                    return True
                bit_index += 1
        return False

    @staticmethod
    def _profile_metadata_identifier(entry: Any) -> str:
        aid = str(getattr(entry, "aid", "")).strip().upper()
        if len(aid) > 0:
            return aid
        return str(getattr(entry, "iccid", "")).strip()

    @staticmethod
    def _describe_profile_metadata(entry: Any) -> str:
        iccid = str(getattr(entry, "iccid", "")).strip()
        nickname = str(getattr(entry, "nickname", "")).strip()
        profile_name = str(getattr(entry, "profile_name", "")).strip()
        if len(nickname) > 0 and len(iccid) > 0:
            return f"{iccid} ({nickname})"
        if len(profile_name) > 0 and len(iccid) > 0:
            return f"{iccid} ({profile_name})"
        if len(iccid) > 0:
            return iccid
        return str(getattr(entry, "aid", "")).strip().upper()

    def _print_info_shield(self) -> None:
        line = "=" * 74
        key_width = 19
        print(f"\n{ShellStyle.HEADER}{line}{ShellStyle.END}")
        print(f"{ShellStyle.BOLD}Local SMDPP Ready{ShellStyle.END}")
        print(f"{ShellStyle.HEADER}{line}{ShellStyle.END}")
        print(
            f"{'Cert Directory':<{key_width}}: "
            f"{ShellStyle.CYAN}{self.cfg.CERTS_DIR}{ShellStyle.END}"
        )
        print(
            f"{'Profile Directory':<{key_width}}: "
            f"{ShellStyle.CYAN}{self.cfg.PROFILE_DIR}{ShellStyle.END}"
        )
        print(
            f"{'Debug Directory':<{key_width}}: "
            f"{ShellStyle.CYAN}{self.cfg.DEBUG_DIR}{ShellStyle.END}"
        )
        print(
            f"{'Metadata Directory':<{key_width}}: "
            f"{ShellStyle.CYAN}{self.cfg.METADATA_DIR}{ShellStyle.END}"
        )
        print(
            f"{'SGP.26 Bundle':<{key_width}}: "
            f"{ShellStyle.CYAN}{self.cfg.SGP26_VALID_CERT_DIR}{ShellStyle.END}"
        )
        if self.session is not None:
            active_eid = self.session.current_eid or "-"
            print(
                f"{'EID':<{key_width}}: "
                f"{ShellStyle.CYAN}{active_eid}{ShellStyle.END}"
            )
            try:
                resolved_profile = self.session.resolve_profile_path()
            except Exception as error:
                resolved_profile = f"error: {error}"
            try:
                resolved_metadata = self.session.resolve_metadata_path()
            except Exception as error:
                resolved_metadata = f"error: {error}"
            profile_value = resolved_profile or "-"
            metadata_value = resolved_metadata or "(derived from profile)"
            print(
                f"{'Active Profile':<{key_width}}: "
                f"{ShellStyle.CYAN}{profile_value}{ShellStyle.END}"
            )
            print(
                f"{'Active Metadata':<{key_width}}: "
                f"{ShellStyle.CYAN}{metadata_value}{ShellStyle.END}"
            )
        warning_text = hil_bridge_warning_text()
        if len(warning_text) > 0:
            print(f"{ShellStyle.WARNING}[!] {warning_text}{ShellStyle.END}")
        print(f"{ShellStyle.HEADER}{line}{ShellStyle.END}")

    def _print_load_success_banner(self, response: bytes) -> None:
        line = "=" * 74
        transaction_id = "-"
        if self.session is not None and len(self.session.state.transaction_id) > 0:
            transaction_id = self.session.state.transaction_id.hex().upper()
        resolved_profile = "-"
        if self.session is not None:
            try:
                resolved_profile = self.session.resolve_profile_path()
            except Exception:
                resolved_profile = "-"

        print(f"\n{line}")
        print("PROFILE LOAD SUCCESS")
        print(line)
        print(f"Transaction ID : {transaction_id}")
        print(f"Profile path   : {resolved_profile}")
        print(f"Last response  : {len(response)} bytes")
        if len(response) > 0:
            print(f"Response head  : {self._hex_preview(response, max_chars=80)}")
        print(line)

    def _print_status(self) -> None:
        if self.session is None:
            print("[*] Session object not initialized.")
            return

        state = self.session.state
        print("\n--- Local SCP11 Status ---")
        print(f"ISD-R selected: {'yes' if state.isdr_selected else 'no'}")
        print(f"Session open: {'yes' if state.session_open else 'no'}")
        print(f"Active EID: {self.session.current_eid or '-'}")
        print(f"Transaction ID: {state.transaction_id.hex().upper() if state.transaction_id else '-'}")
        print(f"Card challenge: {state.card_challenge.hex().upper() if state.card_challenge else '-'}")
        print(f"Server challenge: {state.server_challenge.hex().upper() if state.server_challenge else '-'}")
        print(f"Allowed CI PKIDs: {', '.join(state.allowed_ci_pkids) if state.allowed_ci_pkids else '-'}")
        print(f"Selected CI PKID: {state.selected_ci_pkid or '-'}")
        print(f"Auth certificate: {state.selected_auth_certificate_path or '-'}")
        print(f"Auth private key: {state.selected_auth_private_key_path or '-'}")
        print(f"Auth reason: {state.selected_auth_certificate_reason or '-'}")
        print(f"PB certificate: {state.selected_pb_certificate_path or '-'}")
        print(f"PB private key: {state.selected_pb_private_key_path or '-'}")
        print(f"PB reason: {state.selected_pb_certificate_reason or '-'}")
        print(f"Local SM-DP+ address: {state.selected_local_smdp_address or '-'}")
        try:
            resolved_profile = self.session.resolve_profile_path()
        except Exception as error:
            resolved_profile = f"error: {error}"
        print(f"Profile override: {state.profile_override_path or '-'}")
        print(f"Resolved profile: {resolved_profile or '-'}")
        try:
            resolved_metadata = self.session.resolve_metadata_path()
        except Exception as error:
            resolved_metadata = f"error: {error}"
        print(f"Metadata override: {state.metadata_override_path or '-'}")
        print(f"Resolved metadata: {resolved_metadata or '-'}")
        if state.prepare_download_response:
            print(f"PrepareDownload response: {len(state.prepare_download_response)} bytes")
        else:
            print("PrepareDownload response: -")

    def _cmd_load_profile(self, arguments: list[str]) -> None:
        profile_path = " ".join(arguments).strip() if arguments else ""
        try:
            response = self.session.run_load_profile_chain(profile_path=profile_path)
        except Exception:
            self._print_last_bpp_layout()
            raise
        self._print_last_bpp_layout()
        self._print_load_success_banner(response)

    def _cmd_enable_profile(self, arguments: list[str]) -> None:
        identifier = " ".join(arguments).strip()
        if len(identifier) == 0:
            raise ValueError("Usage: ENABLE-PROFILE <iccid-or-aid-or-alias>")
        profiles = self._safe_collect_profile_metadata()
        target_metadata = self._find_profile_metadata(profiles, identifier)
        if target_metadata is not None:
            if str(getattr(target_metadata, "state", "")).strip().upper() == "ENABLED":
                print("[+] EnableProfile: target is already enabled.")
                return
            active_profile = self._find_enabled_profile(profiles, exclude_profile=target_metadata)
            if active_profile is not None:
                if self._allow_auto_disable_for_enable(active_profile, target_metadata) is False:
                    return
                print(
                    "[*] EnableProfile: auto-disabling active profile "
                    f"{self._describe_profile_metadata(active_profile)}."
                )
                disable_response = self.session.disable_profile(
                    self._profile_metadata_identifier(active_profile)
                )
                self._print_profile_state_response("DisableProfile", disable_response)
        response = self.session.enable_profile(identifier)
        self._print_profile_state_response("EnableProfile", response)
        self._queue_modem_refresh("EnableProfile")

    def _cmd_disable_profile(self, arguments: list[str]) -> None:
        identifier = " ".join(arguments).strip()
        if len(identifier) == 0:
            raise ValueError("Usage: DISABLE-PROFILE <iccid-or-aid-or-alias>")
        profiles = self._safe_collect_profile_metadata()
        target_metadata = self._find_profile_metadata(profiles, identifier)
        if target_metadata is not None:
            if str(getattr(target_metadata, "state", "")).strip().upper() != "ENABLED":
                print("[+] DisableProfile: target is already disabled.")
                return
        response = self.session.disable_profile(identifier)
        self._print_profile_state_response("DisableProfile", response)
        self._queue_modem_refresh("DisableProfile")

    def _cmd_delete_profile(self, arguments: list[str]) -> None:
        identifier = " ".join(arguments).strip()
        if len(identifier) == 0:
            raise ValueError("Usage: DELETE-PROFILE <iccid-or-aid-or-alias>")
        profiles = self._safe_collect_profile_metadata()
        target_metadata = self._find_profile_metadata(profiles, identifier)
        if target_metadata is not None:
            if str(getattr(target_metadata, "state", "")).strip().upper() == "ENABLED":
                print("[*] DeleteProfile: deleting enabled target directly (local override).")
        response = self.session.delete_profile(identifier)
        self._print_profile_state_response("DeleteProfile", response)
        self._queue_modem_refresh("DeleteProfile")

    def _cmd_refresh_modem(self, arguments: list[str]) -> None:
        mode = " ".join(arguments).strip()
        self._queue_modem_refresh("RefreshModem", mode=mode)

    def _cmd_store_metadata(self, arguments: list[str]) -> None:
        metadata_path = " ".join(arguments).strip()
        response = self.session.store_metadata(metadata_path=metadata_path)
        print(f"[+] StoreMetadata completed. Last response: {len(response)} bytes.")
        if len(response) > 0:
            print(f"    {self._hex_preview(response, max_chars=80)}")

    def _cmd_store_metadata_custom(self, arguments: list[str]) -> None:
        if len(arguments) == 0:
            raise ValueError("Usage: STORE-METADATA-CUSTOM <tagHex> [metadata-json-path]")
        custom_tag = arguments[0].strip()
        metadata_path = " ".join(arguments[1:]).strip()
        response = self.session.store_metadata_custom(
            custom_tag_hex=custom_tag,
            metadata_path=metadata_path,
        )
        print(f"[+] StoreMetadata custom completed. Last response: {len(response)} bytes.")
        if len(response) > 0:
            print(f"    {self._hex_preview(response, max_chars=80)}")

    def _cmd_store_metadata_custom_all(self, arguments: list[str]) -> None:
        metadata_path = " ".join(arguments).strip()
        responses = self.session.store_metadata_custom_all(metadata_path=metadata_path)
        print(f"[+] StoreMetadata custom-all completed: {len(responses)} command(s).")
        for tag_hex, response in responses:
            print(f"    [{tag_hex}] {len(response)} bytes")
            if len(response) > 0:
                print(f"      {self._hex_preview(response, max_chars=80)}")

    def _cmd_update_metadata(self, arguments: list[str]) -> None:
        metadata_path = " ".join(arguments).strip()
        response = self.session.update_metadata(metadata_path=metadata_path)
        print(f"[+] UpdateMetadata completed. Last response: {len(response)} bytes.")
        if len(response) > 0:
            print(f"    {self._hex_preview(response, max_chars=80)}")

    def _cmd_discover(self) -> None:
        snapshot = self.session.discover_card()
        render_consolidated_discovery_snapshot(
            snapshot,
            header_color=ShellStyle.HEADER,
            end_color=ShellStyle.END,
        )
        profiles_decode_error = str(snapshot.get("profiles_decode_error", "") or "").strip()
        if len(profiles_decode_error) > 0:
            print(f"[-] Profile metadata decode failed: {profiles_decode_error}")
        configured_decode_error = str(snapshot.get("configured_decode_error", "") or "").strip()
        if len(configured_decode_error) > 0:
            print(f"[-] eUICC configured-data decode failed: {configured_decode_error}")

    def _cmd_explain_last(self, arguments: list[str]) -> None:
        filtered_arguments, output_mode = self._extract_output_mode(arguments)
        if len(filtered_arguments) > 0:
            raise ValueError("Usage: EXPLAIN-LAST [--json|--yaml]")
        payload = self._build_last_operation_report()
        if output_mode != "text":
            self._print_structured_payload(payload, output_mode)
            return
        self._print_last_operation_report(payload)

    def _cmd_certs(self, arguments: list[str]) -> None:
        filtered_arguments, output_mode = self._extract_output_mode(arguments)
        if len(filtered_arguments) > 0:
            raise ValueError("Usage: CERTS [--json|--yaml]")
        report = self.session.list_local_smdp_certificate_inventory()
        if output_mode != "text":
            self._print_structured_payload(report, output_mode)
            return

        allowed = report.get("allowed_ci_pkids", [])
        allowed_text = ", ".join(str(value) for value in allowed) if isinstance(allowed, list) and len(allowed) > 0 else "-"
        print("\n[+] Local SM-DP+ Certificate Inventory")
        print(f"    | Allowed CI PKIDs     : {allowed_text}")
        selected_auth = report.get("selected_auth")
        if isinstance(selected_auth, dict):
            print(f"    | Selected DPauth Cert : {selected_auth.get('certificate_path', '-')}")
            print(f"    | Selected DPauth Key  : {selected_auth.get('private_key_path', '-')}")
            print(f"    | Selected DPauth Mode : {selected_auth.get('selection_reason', '-')}")
            server_address = str(selected_auth.get("server_address", "")).strip()
            if len(server_address) > 0:
                print(f"    | Local SM-DP+ Address : {server_address}")
        else:
            print("    | Selected DPauth Cert : -")
        selected_pb = report.get("selected_pb")
        if isinstance(selected_pb, dict):
            print(f"    | Selected DPpb Cert   : {selected_pb.get('certificate_path', '-')}")
            print(f"    | Selected DPpb Key    : {selected_pb.get('private_key_path', '-')}")
            print(f"    | Selected DPpb Mode   : {selected_pb.get('selection_reason', '-')}")
        else:
            print("    | Selected DPpb Cert   : -")

        auth_records = report.get("auth_records", [])
        pb_records = report.get("pb_records", [])
        print(f"    | DPauth Candidates    : {len(auth_records) if isinstance(auth_records, list) else 0}")
        print(f"    | DPpb Candidates      : {len(pb_records) if isinstance(pb_records, list) else 0}")

    def _print_last_bpp_layout(self) -> None:
        if self.session is None:
            return
        lines = self._summarize_bpp_layout_lines(list(self.session.state.last_bpp_layout_lines))
        if len(lines) == 0:
            return
        print("[*] Local BPP layout:")
        for line in lines:
            print(f"    {line}")
        crypto_lines = self._summarize_bpp_crypto_lines(
            list(self.session.state.last_bpp_crypto_debug_lines)
        )
        if len(crypto_lines) == 0:
            return
        print("[*] Local BPP crypto debug:")
        for line in crypto_lines:
            print(f"    {line}")

    def _cmd_profile(self, arguments: list[str]) -> None:
        if len(arguments) == 0:
            resolved_path = self.session.resolve_profile_path()
            if len(resolved_path) == 0:
                print("[*] No default profile file is present in the profile directory.")
                return
            print(f"[+] Active profile file: {resolved_path}")
            return

        override_path = " ".join(arguments).strip()
        resolved_path = self.session.set_profile_override_path(override_path)
        print(f"[+] Profile override set: {resolved_path}")

    def _cmd_profile_clear(self) -> None:
        self.session.clear_profile_override_path()
        print("[+] Profile override cleared.")

    def _cmd_metadata(self, arguments: list[str]) -> None:
        if len(arguments) == 0:
            resolved_path = self.session.resolve_metadata_path()
            if len(resolved_path) == 0:
                print("[*] No default metadata JSON file is present in the metadata directory.")
                return
            print(f"[+] Active metadata file: {resolved_path}")
            return

        override_path = " ".join(arguments).strip()
        resolved_path = self.session.set_metadata_override_path(override_path)
        print(f"[+] Metadata override set: {resolved_path}")

    def _cmd_metadata_lint(self, arguments: list[str]) -> None:
        filtered_arguments, output_mode = self._extract_output_mode(arguments)
        metadata_path = " ".join(filtered_arguments).strip()
        report = self._build_metadata_lint_payload(metadata_path=metadata_path)
        if output_mode != "text":
            self._print_structured_payload(report, output_mode)
            return
        print("[+] Metadata lint passed.")
        print(f"    file: {report.get('metadata_path', '-')}")
        print(f"    StoreMetadataRequest len: {report.get('store_metadata_len', 0)}")
        print(f"    StoreMetadataRequest hex: {report.get('store_metadata_preview_hex', '-')}")
        update_error = str(report.get("update_metadata_error", "") or "")
        if len(update_error) == 0:
            print(f"    UpdateMetadataRequest len: {report.get('update_metadata_len', 0)}")
            print(f"    UpdateMetadataRequest hex: {report.get('update_metadata_preview_hex', '-')}")
        else:
            print(f"    UpdateMetadataRequest: not encodable ({update_error})")
        custom_tags = report.get("enabled_custom_tags", [])
        if isinstance(custom_tags, list) and len(custom_tags) > 0:
            print(f"    enabled custom tags: {', '.join(str(v) for v in custom_tags)}")
        else:
            print("    enabled custom tags: (none)")
        duplicates = report.get("duplicate_enabled_custom_tags", {})
        if isinstance(duplicates, dict) and len(duplicates) > 0:
            print("    [!] duplicate enabled custom tags detected:")
            for tag_hex, paths in duplicates.items():
                path_line = ", ".join(str(v) for v in paths)
                print(f"      - {tag_hex}: {path_line}")

    def _cmd_metadata_clear(self) -> None:
        self.session.clear_metadata_override_path()
        print("[+] Metadata override cleared.")

    @staticmethod
    def _terminal_width() -> int:
        width = shutil.get_terminal_size((120, 20)).columns
        if width < 80:
            return 80
        return width

    @staticmethod
    def _canonical_command(command: str) -> str:
        lookup = str(command or "").strip().upper()
        if len(lookup) == 0:
            return ""
        return _COMMAND_ALIASES.get(lookup, lookup)

    @staticmethod
    def _command_usage(command: str) -> str:
        doc = _COMMAND_DOCS.get(command, {})
        usage = str(doc.get("usage", "")).strip()
        if len(usage) > 0:
            return usage
        return command

    def _show_command_help(self, command: str) -> None:
        canonical = self._canonical_command(command)
        doc = _COMMAND_DOCS.get(canonical)
        if doc is None:
            print(f"[-] No help entry for command: {command}")
            return
        aliases: list[str] = []
        for alias, target in _COMMAND_ALIASES.items():
            if target == canonical:
                aliases.append(alias)
        print(f"\n[{canonical}]")
        print(f"  Usage   : {self._command_usage(canonical)}")
        print(f"  Summary : {doc.get('summary', '')}")
        if len(aliases) > 0:
            print(f"  Aliases : {', '.join(sorted(aliases))}")

    @staticmethod
    def _render_help_grid(rows: list[str], width: int) -> list[str]:
        if len(rows) == 0:
            return []
        if len(rows) < 4 or width < 96:
            return [f"  {row}" for row in rows]
        gap = 4
        column_count = 2
        column_width = max(24, int((width - gap) / column_count) - 2)
        split_index = (len(rows) + 1) // 2
        left_rows = rows[:split_index]
        right_rows = rows[split_index:]
        rendered_lines: list[str] = []
        for index, left_row in enumerate(left_rows):
            left_block = textwrap.wrap(
                left_row,
                width=column_width,
                break_long_words=False,
                break_on_hyphens=False,
            )
            if len(left_block) == 0:
                left_block = [left_row]
            right_block: list[str] = []
            if index < len(right_rows):
                right_block = textwrap.wrap(
                    right_rows[index],
                    width=column_width,
                    break_long_words=False,
                    break_on_hyphens=False,
                )
                if len(right_block) == 0:
                    right_block = [right_rows[index]]
            line_count = max(len(left_block), len(right_block))
            for line_index in range(line_count):
                left_text = ""
                right_text = ""
                if line_index < len(left_block):
                    left_text = left_block[line_index]
                if line_index < len(right_block):
                    right_text = right_block[line_index]
                if len(right_text) == 0:
                    rendered_lines.append(f"  {left_text}")
                    continue
                rendered_lines.append(f"  {left_text:<{column_width}}{' ' * gap}{right_text}")
        return rendered_lines

    def _print_help_section(
        self,
        title: str,
        color: str,
        command_names: list[str],
        alias_note: str = "",
    ) -> None:
        if len(command_names) == 0:
            return
        print(f"{color}--- {title} ---{ShellStyle.END}")
        labels = [self._command_usage(name) for name in command_names]
        for line in self._render_help_grid(labels, self._terminal_width()):
            print(line)
        if len(alias_note.strip()) > 0:
            wrapped_note = textwrap.wrap(
                alias_note.strip(),
                width=max(48, self._terminal_width() - 4),
                break_long_words=False,
                break_on_hyphens=False,
            )
            for line in wrapped_note:
                print(f"    {line}")
        print("")

    def _cmd_help(self, arguments: Optional[list[str]] = None) -> None:
        parts = list(arguments or [])
        if len(parts) > 0:
            self._show_command_help(" ".join(parts))
            return

        print(f"\n{ShellStyle.BOLD}{ShellStyle.HEADER}Local SMDPP Command Groups{ShellStyle.END}")
        print("  Use HELP <command> for usage and alias details.")
        print("  Add --debug to card-facing commands for full raw APDU hex tracing.")
        print("  Use --yaml when you want structured output without defaulting to JSON.")
        print("  Use RECORD START/STOP to capture replayable commands plus APDU trace to file.")
        print("  Canonical command names are listed here; compatibility aliases still resolve.\n")

        self._print_help_section(
            "Session & Discovery",
            ShellStyle.CYAN,
            ["CERTS", "DISCOVER", "EXPLAIN-LAST", "STATUS", "LOAD-PROFILE"],
            alias_note="Aliases: SMDP-CERTS -> CERTS, INFO -> DISCOVER",
        )
        self._print_help_section(
            "Profile State Management",
            ShellStyle.HEADER,
            ["ENABLE-PROFILE", "DISABLE-PROFILE", "DELETE-PROFILE", "REFRESH-MODEM"],
            alias_note="Aliases: ENABLE, DISABLE, DELETE, MODEM-REFRESH",
        )
        self._print_help_section(
            "Metadata / ASN.1 Runtime",
            ShellStyle.BLUE,
            [
                "STORE-METADATA",
                "UPDATE-METADATA",
                "STORE-METADATA-CUSTOM",
                "STORE-METADATA-CUSTOM-ALL",
                "METADATA",
                "METADATA-LINT",
                "METADATA-CLEAR",
            ],
        )
        self._print_help_section(
            "File Selection",
            ShellStyle.WARNING,
            ["PROFILE", "PROFILE-CLEAR"],
        )
        self._print_help_section(
            "Shell",
            ShellStyle.WHITE,
            ["RECORD", "HELP", "EXIT", "QA"],
            alias_note="Aliases: QUIT, Q -> EXIT",
        )

    def run(self) -> None:
        self._build_session()
        self._setup_readline()
        self._print_info_shield()
        self._cmd_help()
        try:
            while True:
                try:
                    raw_line = input(
                        f"\n{ShellStyle.HEADER}[Local SMDPP] > {ShellStyle.END}"
                    ).strip()
                except EOFError:
                    raw_line = "EXIT"
                except KeyboardInterrupt:
                    print("")
                    raw_line = "EXIT"

                if len(raw_line) == 0:
                    continue

                parts = raw_line.split()
                command = parts[0].upper()
                arguments = parts[1:]

                try:
                    keep_running = self._execute_command(
                        command,
                        arguments,
                        raw_command=raw_line,
                        source="interactive",
                    )
                    if keep_running is False:
                        return
                except Exception as error:
                    print(f"[-] {self._format_error_message(error)}")
        finally:
            self._finalize_recording_on_exit()

    def run_commands(self, cmd_line: str) -> None:
        self._build_session()
        had_error = False
        try:
            for raw_command in self._split_batch_commands(cmd_line):
                parts = raw_command.split()
                if len(parts) == 0:
                    continue
                command = parts[0].upper()
                arguments = parts[1:]
                try:
                    keep_running = self._execute_command(
                        command,
                        arguments,
                        raw_command=raw_command,
                        source="batch",
                    )
                except QuitAllRequested:
                    raise
                except Exception as error:
                    had_error = True
                    print(f"[-] {self._format_error_message(error)}")
                    continue
                if keep_running is False:
                    break
        finally:
            self._finalize_recording_on_exit()
        if had_error:
            raise SystemExit(1)

    @staticmethod
    def _split_batch_commands(cmd_line: str) -> list[str]:
        commands: list[str] = []
        for raw_command in str(cmd_line or "").split(";"):
            command_text = str(raw_command or "").strip()
            if len(command_text) == 0:
                continue
            commands.append(command_text)
        return commands

    def _execute_command(
        self,
        command: str,
        arguments: list[str],
        *,
        raw_command: str = "",
        source: str = "interactive",
    ) -> bool:
        command = str(command or "").strip().upper()
        canonical_command = self._canonical_command(command)
        filtered_arguments, debug = self._extract_debug_flag(arguments)
        command_record: Optional[dict[str, Any]] = None
        if canonical_command != "RECORD":
            issued_command = str(raw_command or "").strip()
            if len(issued_command) == 0:
                issued_command = self._render_command_line(command, arguments)
            replay_command = self._render_command_line(
                canonical_command or command,
                filtered_arguments,
            )
            command_record = self._recorder.begin_command(
                raw_command=issued_command,
                canonical_command=canonical_command or command,
                replay_command=replay_command,
                debug_enabled=debug,
                source=source,
            )
        previous_debug = None
        if debug:
            previous_debug = self._set_transport_debug(True)
        try:
            if canonical_command == "CERTS":
                self._cmd_certs(filtered_arguments)
            elif canonical_command == "DISCOVER":
                self._cmd_discover()
            elif canonical_command == "EXPLAIN-LAST":
                self._cmd_explain_last(filtered_arguments)
            elif canonical_command == "LOAD-PROFILE":
                self._cmd_load_profile(filtered_arguments)
            elif canonical_command == "ENABLE-PROFILE":
                self._cmd_enable_profile(filtered_arguments)
            elif canonical_command == "DISABLE-PROFILE":
                self._cmd_disable_profile(filtered_arguments)
            elif canonical_command == "DELETE-PROFILE":
                self._cmd_delete_profile(filtered_arguments)
            elif canonical_command == "REFRESH-MODEM":
                self._cmd_refresh_modem(filtered_arguments)
            elif canonical_command == "STORE-METADATA":
                self._cmd_store_metadata(filtered_arguments)
            elif canonical_command == "UPDATE-METADATA":
                self._cmd_update_metadata(filtered_arguments)
            elif canonical_command == "STORE-METADATA-CUSTOM":
                self._cmd_store_metadata_custom(filtered_arguments)
            elif canonical_command == "STORE-METADATA-CUSTOM-ALL":
                self._cmd_store_metadata_custom_all(filtered_arguments)
            elif canonical_command == "PROFILE":
                self._cmd_profile(filtered_arguments)
            elif canonical_command == "PROFILE-CLEAR":
                self._cmd_profile_clear()
            elif canonical_command == "METADATA":
                self._cmd_metadata(filtered_arguments)
            elif canonical_command == "METADATA-LINT":
                self._cmd_metadata_lint(filtered_arguments)
            elif canonical_command == "METADATA-CLEAR":
                self._cmd_metadata_clear()
            elif canonical_command == "RECORD":
                self._cmd_record(filtered_arguments)
            elif canonical_command == "EXPORT-KEYBAG":
                self._cmd_export_keybag(filtered_arguments)
            elif canonical_command == "STATUS":
                self._print_status()
            elif canonical_command == "HELP":
                self._cmd_help(filtered_arguments)
            elif canonical_command == "QA":
                self._close_session_quietly()
                print("[*] Leaving local SCP11 shell.")
                quit_all()
            elif canonical_command == "EXIT":
                self._close_session_quietly()
                print("[*] Leaving local SCP11 shell.")
                if command_record is not None:
                    self._recorder.finish_command(command_record, success=True)
                    command_record = None
                return False
            else:
                print(f"[-] Unknown command: {command}")
                if command_record is not None:
                    self._recorder.finish_command(
                        command_record,
                        success=False,
                        error=f"Unknown command: {command}",
                    )
                    command_record = None
                return True
            if command_record is not None:
                self._recorder.finish_command(command_record, success=True)
                command_record = None
            return True
        except QuitAllRequested:
            if command_record is not None:
                self._recorder.finish_command(command_record, success=True)
                command_record = None
            raise
        except Exception as error:
            if command_record is not None:
                self._recorder.finish_command(
                    command_record,
                    success=False,
                    error=str(error),
                )
                command_record = None
            raise
        finally:
            self._restore_transport_debug(previous_debug)

    def _close_session_quietly(self) -> None:
        if self.session is None:
            return
        if self.session.state.session_open is False:
            return
        try:
            self.session.close_session()
        except Exception:
            pass


def entry() -> None:
    shell = LocalAccessShell()
    shell.run()


def entry_cmd(cmd_line: str) -> None:
    shell = LocalAccessShell()
    shell.run_commands(cmd_line)


def _append_keybag_dump_command(cmd_line: str, dump_path: str) -> str:
    """Append an EXPORT-KEYBAG invocation to a shell batch.

    Used by the `--dump-keybag` CLI convenience so operators can pair
    a non-interactive run (`--cmd "LOAD-PROFILE"`) with an automatic
    keybag dump without chaining the commands themselves.
    """
    normalized_dump = str(dump_path or "").strip()
    if len(normalized_dump) == 0:
        return cmd_line
    quoted_path = shlex.quote(normalized_dump)
    trailing_command = f"EXPORT-KEYBAG {quoted_path}"
    base = str(cmd_line or "").strip().rstrip(";").strip()
    if len(base) == 0:
        return trailing_command
    return f"{base}; {trailing_command}"


def _read_stdin_command_text() -> str:
    commands: list[str] = []
    for raw_line in sys.stdin.read().splitlines():
        command_text = str(raw_line or "").strip()
        if len(command_text) == 0:
            continue
        if command_text.startswith("#"):
            continue
        commands.append(command_text)
    return "; ".join(commands)


def entry_stdin() -> None:
    entry_cmd(_read_stdin_command_text())


def run_standalone() -> None:
    parser = argparse.ArgumentParser(description="SCP11 local SM-DP+ shell")
    add_debug_argument(
        parser,
        help_text="Enable verbose debug output for this local SCP11 session.",
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
        "--dump-keybag",
        dest="dump_keybag",
        type=str,
        default=None,
        help=(
            "After running the requested command batch, append EXPORT-KEYBAG "
            "<PATH> so the derived SCP11c BSP keys land in a pcap-paired "
            "keybag JSON for offline HIL replay."
        ),
    )
    args = parser.parse_args()
    set_global_debug(bool(getattr(args, "debug", False)))
    keybag_path = str(getattr(args, "dump_keybag", "") or "").strip()
    if args.cmd:
        cmd_line = args.cmd
        if len(keybag_path) > 0:
            cmd_line = _append_keybag_dump_command(cmd_line, keybag_path)
        entry_cmd(cmd_line)
        return
    if args.stdin:
        base_cmd = _read_stdin_command_text()
        if len(keybag_path) > 0:
            base_cmd = _append_keybag_dump_command(base_cmd, keybag_path)
        entry_cmd(base_cmd)
        return
    if len(keybag_path) > 0:
        entry_cmd(_append_keybag_dump_command("", keybag_path))
        return
    entry()


if __name__ == "__main__":
    try:
        run_standalone()
    except QuitAllRequested:
        sys.exit(0)
    except LocalAccessStartupError as error:
        print(f"[STARTUP ERROR] {error}")
        sys.exit(1)
