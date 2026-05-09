# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""eIM-local shell: operator REPL for the local eIM simulator exposing IPA-poll, package delivery, and audit commands."""
import argparse
import atexit
import os
import shlex
import shutil
import sys
import textwrap
from typing import Any, Callable, Optional

from yggdrasim_common.plugin_runtime import ensure_plugins_loaded, extend_target_with_plugins
from yggdrasim_common.process_debug import (
    add_debug_argument,
    is_global_debug_enabled,
    set_global_debug,
)
from yggdrasim_common.card_backend import trigger_card_relay_modem_refresh
from yggdrasim_common.hil_bridge_runtime import hil_bridge_warning_text
from yggdrasim_common.quit_control import quit_all, QuitAllRequested
from yggdrasim_common.session_recording import ShellSessionRecorder
from yggdrasim_common.structured_output import dump_structured_payload
from yggdrasim_common.nord_palette import NORD
from SCP11.shared.discovery_snapshot import (
    render_card_overview_snapshot,
    render_consolidated_discovery_snapshot,
)
from SCP11.shared.profile_actions import (
    ProfileActionAdapter,
    run_delete_profile as shared_run_delete_profile,
    run_disable_profile as shared_run_disable_profile,
    run_enable_profile as shared_run_enable_profile,
)

try:
    import readline
except ImportError:
    readline = None

try:
    from SCP03.logic.sgp32_decode import decode_eim_configuration_entries
except Exception:
    decode_eim_configuration_entries = None

from .config import EimLocalConfig
from .eim_package_codec import resolve_package_runtime_hints
from .session import EimLocalSession
from yggdrasim_common.polling_plugin_support import (
    dispatch_poll_command,
    dispatch_poll_method,
    has_polling_plugin,
    parse_eim_local_ipae_args,
)
from SCP11.shared.gsma_error_codes import (
    SGP22_DOWNLOAD_ERROR_CODE,
    SGP22_ES10B_PROFILE_STATE_RESULT,
    SGP22_PROFILE_INSTALLATION_RESULT_REASON,
    SGP32_EIM_PACKAGE_ERROR,
    SGP32_EIM_PACKAGE_RESULT_ERROR,
    SGP32_PROFILE_DOWNLOAD_ERROR_REASON,
)


class ShellStyle:
    """eIM-local shell colour roles, sourced from the Nord palette."""

    HEADER = NORD.HEADER
    BLUE = NORD.BLUE
    CYAN = NORD.CYAN
    GREEN = NORD.GREEN
    RED = NORD.RED
    WARNING = NORD.WARNING
    WHITE = NORD.WHITE
    BOLD = NORD.BOLD
    END = NORD.RESET


class EimLocalStartupError(RuntimeError):
    """Readable startup failure for eIM local shell."""


class EimLocalShell:
    def __init__(self) -> None:
        self.cfg = EimLocalConfig()
        self.session = EimLocalSession(cfg=self.cfg)
        self._global_debug = is_global_debug_enabled()
        self._cached_poll_target_fqdns: list[str] = []
        if self._global_debug:
            self._set_transport_debug(True)
        self._poll_bridge: Any = None
        self._recorder = ShellSessionRecorder(
            shell_name="scp11_eim_local",
            module_entry_point="python -m SCP11.eim_local",
        )
        self._history_file = os.path.join(
            os.path.expanduser("~"),
            ".yggdrasim_eim_local_history",
        )
        self._commands: dict[str, Callable[[str], None]] = {
            "HELP": self._cmd_help,
            "PATHS": self._cmd_paths,
            "RECORD": self._cmd_record,
            "STATUS": self._cmd_status,
            "LIST": self._cmd_list_profiles,
            "SCAN": self._cmd_scan,
            "DISCOVER": self._cmd_discover,
            "LOAD-PROFILE": self._cmd_load_profile,
            "ENABLE-PROFILE": self._cmd_enable_profile,
            "DISABLE-PROFILE": self._cmd_disable_profile,
            "DELETE-PROFILE": self._cmd_delete_profile,
            "REFRESH-MODEM": self._cmd_refresh_modem,
            "PROFILE": self._cmd_profile,
            "PROFILE-CLEAR": self._cmd_profile_clear,
            "METADATA": self._cmd_metadata,
            "METADATA-CLEAR": self._cmd_metadata_clear,
            "METADATA-LINT": self._cmd_metadata_lint,
            "STORE-METADATA": self._cmd_store_metadata,
            "UPDATE-METADATA": self._cmd_update_metadata,
            "GET-EIM-CONFIG": self._cmd_get_eim_config,
            "DELETE-EIM": self._cmd_delete_eim,
            "EUICC-MEMORY-RESET": self._cmd_euicc_memory_reset,
            "ISDR-GET-EIM-CONFIG": self._cmd_isdr_get_eim_config,
            "ISDR-DELETE-EIM": self._cmd_isdr_delete_eim,
            "IPAD-DISCOVER": self._cmd_ipad_discover,
            "IPAD-LIVE": self._cmd_ipad_live,
            "IPAD-TEST": self._cmd_ipad_test,
            "IPAE-AUTHENTICATE": self._cmd_ipae_authenticate,
            "IPAE-DOWNLOAD": self._cmd_ipae_download,
            "HANDOVER-SET": self._cmd_handover_set,
            "HANDOVER-STATUS": self._cmd_handover_status,
            "EIM-PACKAGE": self._cmd_eim_package,
            "EIM-PACKAGE-CLEAR": self._cmd_eim_package_clear,
            "EIM-PACKAGE-LINT": self._cmd_eim_package_lint,
            "EIM-PACKAGE-EXPLAIN": self._cmd_eim_package_explain,
            "EIM-PACKAGE-ISSUE": self._cmd_eim_package_issue,
            "EIM-PACKAGE-ISSUE-ALL": self._cmd_eim_package_issue_all,
            "EIM-CERTS": self._cmd_eim_certs,
            "HOTFOLDER": self._cmd_hotfolder,
            "HOTFOLDER-CLEAR": self._cmd_hotfolder_clear,
            "HOTFOLDER-LIST": self._cmd_hotfolder_list,
            "HOTFOLDER-POLL": self._cmd_hotfolder_poll,
            "HOTFOLDER-FETCH": self._cmd_hotfolder_fetch,
            "POLL-CAMPAIGN": self._cmd_poll_campaign,
            "POLL-EXPORT": self._cmd_poll_export,
            "POLL-AGGREGATE": self._cmd_poll_aggregate,
            "ADD-INITIAL-EIM": self._cmd_add_initial_eim,
            "ADD-EIM": self._cmd_add_eim,
            "ISDR-ADD-INITIAL-EIM": self._cmd_isdr_add_initial_eim,
            "ISDR-ADD-EIM": self._cmd_isdr_add_eim,
            "LOAD-EIM-PACKAGE": self._cmd_load_eim_package,
            "EIM-ACKNOWLEDGE": self._cmd_eim_acknowledge,
            "ERROR-CODES": self._cmd_error_codes,
            "ERROR-CODE-SET": self._cmd_error_code_set,
            "COUNTERS": self._cmd_counters,
            "COUNTER": self._cmd_counter,
            "NOTIF-HYGIENE": self._cmd_notification_hygiene,
            "RESP-LOG": self._cmd_response_log,
            "RESP-LOG-FILTER": self._cmd_response_log_filter,
            "RESP-LOG-CLEAR": self._cmd_response_log_clear,
            "QA": self._cmd_quit_all,
            "EXIT": self._cmd_exit,
        }
        # Aliases harmonised with eSIM Live / Test / Local SMDP+. Keep
        # in sync with SCP11/local_access/main.py::_COMMAND_ALIASES so
        # the same shorthand works across all four shells.
        self._command_aliases: dict[str, str] = {
            "INFO": "SCAN",
            "EIM-DISCOVER": "DISCOVER",
            "ENABLE": "ENABLE-PROFILE",
            "DISABLE": "DISABLE-PROFILE",
            "DELETE": "DELETE-PROFILE",
            "MODEM-REFRESH": "REFRESH-MODEM",
            "GET-METADATA": "METADATA",
            "EIM-ACK": "EIM-ACKNOWLEDGE",
            "ISDR-PACKAGE": "LOAD-EIM-PACKAGE",
            "ISDR-LOAD-PACKAGE": "LOAD-EIM-PACKAGE",
            "RESPONSE-LOG": "RESP-LOG",
            "ISDR-EUICC-MEMORY-RESET": "EUICC-MEMORY-RESET",
            "QUIT": "EXIT",
            "Q": "EXIT",
            "?": "HELP",
        }
        self._command_docs: dict[str, dict[str, Any]] = {
            "HELP": {
                "usage": "HELP [command]",
                "summary": "Show grouped help or command-specific usage.",
                "examples": ["HELP", "HELP HOTFOLDER-FETCH", "HELP ERROR-CODE-SET"],
            },
            "PATHS": {
                "usage": "PATHS",
                "summary": "Show Direct Auth, IPAd polling, IPAe polling, and localized bridge endpoints.",
                "examples": ["PATHS"],
            },
            "RECORD": {
                "usage": "RECORD [STATUS|START [outputPath]|STOP [outputPath]|CANCEL]",
                "summary": "Capture replayable shell commands plus the underlying APDU trace.",
                "examples": [
                    "RECORD STATUS",
                    "RECORD START reports/eim_session.yaml",
                    "RECORD STOP",
                ],
            },
            "STATUS": {"usage": "STATUS", "summary": "Show current runtime/session state.", "examples": ["STATUS"]},
            "LIST": {"usage": "LIST", "summary": "List known profile aliases (AID registry) for profile state commands.", "examples": ["LIST"]},
            "SCAN": {
                "usage": "SCAN",
                "summary": "Quick card overview (EID / issuer / SM-DP+ / SM-DS / eIM / profiles). INFO is an alias.",
                "examples": ["SCAN", "INFO"],
            },
            "DISCOVER": {
                "usage": "DISCOVER",
                "summary": "Full SGP.32 consolidated discovery dump (EID + EuiccConfiguredData + ES10 reads + GetCerts).",
                "examples": ["DISCOVER", "EIM-DISCOVER"],
            },
            "LOAD-PROFILE": {"usage": "LOAD-PROFILE [profilePath]", "summary": "Run PrepareDownload + profile load chain.", "examples": ["LOAD-PROFILE", "LOAD-PROFILE Workspace/LocalEIM/profile/test_profile.txt"]},
            "ENABLE-PROFILE": {"usage": "ENABLE-PROFILE <iccid|aid|alias>", "summary": "Enable profile by ICCID, AID, or alias.", "examples": ["ENABLE-PROFILE ISDP1", "ENABLE-PROFILE 8904903200000000000F"]},
            "DISABLE-PROFILE": {"usage": "DISABLE-PROFILE <iccid|aid|alias>", "summary": "Disable profile by ICCID, AID, or alias.", "examples": ["DISABLE-PROFILE ISDP1"]},
            "DELETE-PROFILE": {"usage": "DELETE-PROFILE <iccid|aid|alias>", "summary": "Delete profile by ICCID, AID, or alias.", "examples": ["DELETE-PROFILE ISDP1"]},
            "REFRESH-MODEM": {
                "usage": "REFRESH-MODEM [mode]",
                "summary": "Queue a proactive REFRESH toward the attached modem via the active HIL bridge.",
                "examples": ["REFRESH-MODEM", "REFRESH-MODEM euicc-profile-state-change", "REFRESH-MODEM uicc-reset"],
            },
            "PROFILE": {"usage": "PROFILE [profilePath]", "summary": "Show active profile target or set override path.", "examples": ["PROFILE", "PROFILE test_profile.txt"]},
            "PROFILE-CLEAR": {"usage": "PROFILE-CLEAR", "summary": "Clear profile override path.", "examples": ["PROFILE-CLEAR"]},
            "METADATA": {"usage": "METADATA [metadataPath]", "summary": "Show active metadata target or set override path.", "examples": ["METADATA", "METADATA default_profile_metadata.json"]},
            "METADATA-CLEAR": {"usage": "METADATA-CLEAR", "summary": "Clear metadata override path.", "examples": ["METADATA-CLEAR"]},
            "METADATA-LINT": {"usage": "METADATA-LINT [metadataPath]", "summary": "Validate metadata JSON and derived encoding feasibility.", "examples": ["METADATA-LINT"]},
            "STORE-METADATA": {"usage": "STORE-METADATA [metadataPath]", "summary": "Encode/send StoreMetadata APDU flow from JSON.", "examples": ["STORE-METADATA"]},
            "UPDATE-METADATA": {"usage": "UPDATE-METADATA [metadataPath]", "summary": "Encode/send UpdateMetadata APDU flow from JSON.", "examples": ["UPDATE-METADATA"]},
            "GET-EIM-CONFIG": {"usage": "GET-EIM-CONFIG", "summary": "Send standalone BF55 GetEimConfigurationData command.", "examples": ["GET-EIM-CONFIG"]},
            "DELETE-EIM": {"usage": "DELETE-EIM <eimId>", "summary": "Send BF59 DeleteEim request for target eIM ID.", "examples": ["DELETE-EIM 2.25.311782205282738360923618091971140414400"]},
            "EUICC-MEMORY-RESET": {
                "usage": "EUICC-MEMORY-RESET [packagePath]",
                "summary": "Run template-driven ES10c eUICCMemoryReset directly on ISD-R.",
                "examples": [
                    "EUICC-MEMORY-RESET",
                    "EUICC-MEMORY-RESET Workspace/LocalEIM/eim_packages/templates/template_euicc_memory_reset.json",
                ],
            },
            "ISDR-GET-EIM-CONFIG": {"usage": "ISDR-GET-EIM-CONFIG", "summary": "Decode/report live BF55 eIM rows from the card.", "examples": ["ISDR-GET-EIM-CONFIG"]},
            "ISDR-DELETE-EIM": {"usage": "ISDR-DELETE-EIM <eimId>", "summary": "Delete target eIM and print decoded post-state.", "examples": ["ISDR-DELETE-EIM 2.25.311782205282738360923618091971140414400"]},
            "IPAD-DISCOVER": {"usage": "IPAD-DISCOVER [packagePath]", "summary": "Run IPAd discovery and optional package selection.", "examples": ["IPAD-DISCOVER"]},
            "IPAD-LIVE": {
                "usage": "IPAD-LIVE [matchingId] [--debug]",
                "summary": "Run localized IPAd polling through the SCP11 live orchestrator and local bridge.",
                "examples": ["IPAD-LIVE", "IPAD-LIVE EIM-FIRST-TEST", "IPAD-LIVE --debug"],
            },
            "IPAD-TEST": {
                "usage": "IPAD-TEST [matchingId] [--debug]",
                "summary": "Run localized IPAd polling through the SCP11 test orchestrator and local bridge.",
                "examples": ["IPAD-TEST", "IPAD-TEST EIM-FIRST-TEST", "IPAD-TEST --debug"],
            },
            "IPAE-AUTHENTICATE": {"usage": "IPAE-AUTHENTICATE [matchingId]", "summary": "Seed handover context with transactionId.", "examples": ["IPAE-AUTHENTICATE", "IPAE-AUTHENTICATE EIM-TEST-001"]},
            "IPAE-DOWNLOAD": {"usage": "IPAE-DOWNLOAD [profilePath] [matchingId]", "summary": "Run handover-linked download/load profile sequence.", "examples": ["IPAE-DOWNLOAD", "IPAE-DOWNLOAD test_profile.txt EIM-TEST-001"]},
            "HANDOVER-SET": {"usage": "HANDOVER-SET <transactionIdHex> [matchingId]", "summary": "Manually seed handover context.", "examples": ["HANDOVER-SET 01020304AABBCCDD MID-1"]},
            "HANDOVER-STATUS": {"usage": "HANDOVER-STATUS [--json|--yaml]", "summary": "Print the current handover context.", "examples": ["HANDOVER-STATUS", "HANDOVER-STATUS --yaml"]},
            "EIM-PACKAGE": {"usage": "EIM-PACKAGE [packagePath]", "summary": "Show active package or set package override.", "examples": ["EIM-PACKAGE", "EIM-PACKAGE default_eim_package.json"]},
            "EIM-PACKAGE-CLEAR": {"usage": "EIM-PACKAGE-CLEAR", "summary": "Clear eIM package override path.", "examples": ["EIM-PACKAGE-CLEAR"]},
            "EIM-PACKAGE-LINT": {"usage": "EIM-PACKAGE-LINT [packagePath] [--strict-exec] [--json|--yaml]", "summary": "Run detailed package lint + spec checks.", "examples": ["EIM-PACKAGE-LINT", "EIM-PACKAGE-LINT --strict-exec", "EIM-PACKAGE-LINT --yaml"]},
            "EIM-PACKAGE-EXPLAIN": {"usage": "EIM-PACKAGE-EXPLAIN [packagePath] [--strict-exec] [--json|--yaml]", "summary": "Explain runtime hints, spec checks, and signing-cert selection for a package.", "examples": ["EIM-PACKAGE-EXPLAIN", "EIM-PACKAGE-EXPLAIN --strict-exec", "EIM-PACKAGE-EXPLAIN Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json --yaml"]},
            "EIM-PACKAGE-ISSUE": {"usage": "EIM-PACKAGE-ISSUE [packagePath]", "summary": "Issue one package based on package_type.", "examples": ["EIM-PACKAGE-ISSUE"]},
            "EIM-PACKAGE-ISSUE-ALL": {"usage": "EIM-PACKAGE-ISSUE-ALL [directory]", "summary": "Issue all JSON package files in directory.", "examples": ["EIM-PACKAGE-ISSUE-ALL", "EIM-PACKAGE-ISSUE-ALL Workspace/LocalEIM/eim_packages"]},
            "EIM-CERTS": {"usage": "EIM-CERTS [--json|--yaml] [packagePath] [certPath]", "summary": "List signing cert inventory and preview the auto-selected match for the card.", "examples": ["EIM-CERTS", "EIM-CERTS --json", "EIM-CERTS --yaml", "EIM-CERTS Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json"]},
            "HOTFOLDER": {"usage": "HOTFOLDER [directory]", "summary": "Show active hotfolder or set hotfolder override.", "examples": ["HOTFOLDER", "HOTFOLDER Workspace/LocalEIM/eim_packages/hotfolder"]},
            "HOTFOLDER-CLEAR": {"usage": "HOTFOLDER-CLEAR", "summary": "Clear hotfolder override path.", "examples": ["HOTFOLDER-CLEAR"]},
            "HOTFOLDER-LIST": {"usage": "HOTFOLDER-LIST [directory] [--json|--yaml]", "summary": "Preview the effective poll queue (fixed fixtures + hotfolder) without issuing.", "examples": ["HOTFOLDER-LIST", "HOTFOLDER-LIST --json", "HOTFOLDER-LIST --yaml", "HOTFOLDER-LIST Workspace/LocalEIM/eim_packages/hotfolder --json"]},
            "HOTFOLDER-POLL": {"usage": "HOTFOLDER-POLL [directory] [--json|--yaml]", "summary": "Return effective poll metadata for harnesses.", "examples": ["HOTFOLDER-POLL", "HOTFOLDER-POLL --yaml"]},
            "HOTFOLDER-FETCH": {"usage": "HOTFOLDER-FETCH [directory] [--json|--yaml]", "summary": "Issue the effective poll queue in deterministic order.", "examples": ["HOTFOLDER-FETCH", "HOTFOLDER-FETCH --json", "HOTFOLDER-FETCH --yaml"]},
            "POLL-CAMPAIGN": {"usage": "POLL-CAMPAIGN [cycles] [intervalMs] [hotfolderDir] [--until-empty] [--max-cycles <n>] [--json|--yaml]", "summary": "Run the effective poll queue campaign (fixed fixtures + hotfolder) and issue one package per cycle.", "examples": ["POLL-CAMPAIGN", "POLL-CAMPAIGN 10 1000", "POLL-CAMPAIGN --until-empty --max-cycles 50 --json", "POLL-CAMPAIGN --yaml"]},
            "POLL-EXPORT": {"usage": "POLL-EXPORT [cycles] [intervalMs] [hotfolderDir] [--until-empty] [--max-cycles <n>] [outputPath]", "summary": "Run poll campaign and export JSON report file.", "examples": ["POLL-EXPORT", "POLL-EXPORT --until-empty --max-cycles 200", "POLL-EXPORT 20 250 reports/my_campaign.json"]},
            "POLL-AGGREGATE": {"usage": "POLL-AGGREGATE [reportsDir] [--json|--yaml] [--export [outputPath]]", "summary": "Aggregate exported poll campaign reports.", "examples": ["POLL-AGGREGATE", "POLL-AGGREGATE reports --json", "POLL-AGGREGATE reports --yaml", "POLL-AGGREGATE reports --export reports/aggregate.json"]},
            "ADD-INITIAL-EIM": {"usage": "ADD-INITIAL-EIM [package|isdr] [certPath] [packagePath]", "summary": "Issue AddInitialEim using package or ISDR mode, with card-aware cert auto-selection when certPath is omitted.", "examples": ["ADD-INITIAL-EIM isdr", "ADD-INITIAL-EIM package Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json"]},
            "ADD-EIM": {"usage": "ADD-EIM [package|isdr] [certPath] [packagePath]", "summary": "Issue AddEim using package or ISDR mode, with card-aware cert auto-selection when certPath is omitted.", "examples": ["ADD-EIM package", "ADD-EIM package Workspace/LocalEIM/eim_packages/templates/template_add_eim.json"]},
            "ISDR-ADD-INITIAL-EIM": {"usage": "ISDR-ADD-INITIAL-EIM [certPath] [packagePath]", "summary": "Validate AddInitialEim directly on-card, with package-through-local-auth when packagePath is supplied.", "examples": ["ISDR-ADD-INITIAL-EIM /path/to/local_eim_signing_cert.pem", "ISDR-ADD-INITIAL-EIM Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json"]},
            "ISDR-ADD-EIM": {"usage": "ISDR-ADD-EIM [certPath] [packagePath]", "summary": "Validate AddEim directly on-card, with package-through-local-auth when packagePath is supplied.", "examples": ["ISDR-ADD-EIM /path/to/local_eim_signing_cert.pem", "ISDR-ADD-EIM Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json"]},
            "LOAD-EIM-PACKAGE": {"usage": "LOAD-EIM-PACKAGE [packagePath] [certPath]", "summary": "Execute a card-facing package directly toward ISD-R, bypassing poll/hotfolder routing.", "examples": ["LOAD-EIM-PACKAGE Workspace/LocalEIM/eim_packages/fake_eim_add_eim_package.json", "LOAD-EIM-PACKAGE Workspace/LocalEIM/eim_packages/templates/template_add_initial_eim.json /path/to/local_eim_signing_cert.pem"]},
            "EIM-ACKNOWLEDGE": {"usage": "EIM-ACKNOWLEDGE [transactionIdHex] [matchingId]", "summary": "Close pending eIM operations and sync notifications.", "examples": ["EIM-ACKNOWLEDGE", "EIM-ACKNOWLEDGE 01020304AABBCCDD MID-1"]},
            "ERROR-CODES": {"usage": "ERROR-CODES [SGP.02|SGP.22|SGP.32|ALL]", "summary": "List known GSMA error code tables.", "examples": ["ERROR-CODES", "ERROR-CODES SGP.32"]},
            "ERROR-CODE-SET": {"usage": "ERROR-CODE-SET <family> <code|name> [packagePath]", "summary": "Apply resolved symbolic/numeric error code into package JSON.", "examples": ["ERROR-CODE-SET sgp32_profile_download_error_reason ecallActive", "ERROR-CODE-SET sgp32_eim_package_result_error 1 Workspace/LocalEIM/eim_packages/templates/template_provide_eim_package_result.json"]},
            "COUNTERS": {"usage": "COUNTERS", "summary": "List persisted counters by eIM ID.", "examples": ["COUNTERS"]},
            "COUNTER": {"usage": "COUNTER <eimId> [set <n>] | COUNTER set <n>", "summary": "Inspect or override next counter value.", "examples": ["COUNTER 2.25.311782205282738360923618091971140414400", "COUNTER 2.25.311782205282738360923618091971140414400 set 1", "COUNTER set 1"]},
            "NOTIF-HYGIENE": {"usage": "NOTIF-HYGIENE [maxPending]", "summary": "Drain/check pending notifications threshold.", "examples": ["NOTIF-HYGIENE", "NOTIF-HYGIENE 0"]},
            "RESP-LOG": {"usage": "RESP-LOG [n] [--json|--yaml]", "summary": "Show last n response log entries.", "examples": ["RESP-LOG", "RESP-LOG 50", "RESP-LOG --yaml"]},
            "RESP-LOG-FILTER": {"usage": "RESP-LOG-FILTER <query> [n] [--json|--yaml]", "summary": "Filter response log entries by txid/matchingId/path/action.", "examples": ["RESP-LOG-FILTER MID-1", "RESP-LOG-FILTER 01020304 100", "RESP-LOG-FILTER MID-1 --yaml"]},
            "RESP-LOG-CLEAR": {"usage": "RESP-LOG-CLEAR", "summary": "Clear response log JSONL file.", "examples": ["RESP-LOG-CLEAR"]},
            "QA": {"usage": "QA", "summary": "Exit shell and leave YggdraSIM immediately.", "examples": ["QA"]},
            "EXIT": {"usage": "EXIT", "summary": "Exit shell and close session if open.", "examples": ["EXIT"]},
        }
        self._plugin_path_sections: list[dict[str, Any]] = []
        self._plugin_localized_help_rows: list[tuple[str, str]] = []
        extend_target_with_plugins(self)

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

    def _save_history(self) -> None:
        if readline is None:
            return
        try:
            readline.write_history_file(self._history_file)
        except Exception:
            pass

    def _completer(self, text: str, state: int) -> Optional[str]:
        typed = (text or "").upper()
        options = [name for name in self._commands if name.startswith(typed)]
        options = sorted(set(options))
        if state >= len(options):
            return None
        if len(options) == 1:
            return options[state] + " "
        return options[state]

    def _canonical_command(self, command: str) -> str:
        lookup = str(command or "").strip().upper()
        if len(lookup) == 0:
            return ""
        if lookup in self._command_aliases:
            return self._command_aliases[lookup]
        return lookup

    def _show_command_help(self, command: str) -> None:
        canonical = self._canonical_command(command)
        doc = self._command_docs.get(canonical)
        if doc is None:
            print(f"[-] No help entry for command: {command}")
            return
        aliases: list[str] = []
        for alias, target in self._command_aliases.items():
            if target == canonical:
                aliases.append(alias)
        print(f"\n[{canonical}]")
        print(f"  Usage   : {doc.get('usage', canonical)}")
        print(f"  Summary : {doc.get('summary', '')}")
        if len(aliases) > 0:
            print(f"  Aliases : {', '.join(sorted(aliases))}")
        examples = doc.get("examples", [])
        if isinstance(examples, list) and len(examples) > 0:
            print("  Examples:")
            for example in examples:
                print(f"    - {example}")

    def _help_row(self, label: str, command_key: str) -> tuple[str, str]:
        doc = self._command_docs.get(command_key, {})
        return (label, str(doc.get("summary", "")).strip())

    @staticmethod
    def _extract_output_mode_tokens(tokens: list[str]) -> tuple[list[str], str]:
        filtered: list[str] = []
        output_mode = "text"
        for token in tokens:
            normalized = str(token or "").strip().lower()
            if normalized not in ("--json", "--yaml"):
                filtered.append(token)
                continue
            requested_mode = "json" if normalized == "--json" else "yaml"
            if output_mode not in ("text", requested_mode):
                raise ValueError("Choose only one structured output mode: --json or --yaml.")
            output_mode = requested_mode
        return filtered, output_mode

    def _parse_output_mode_argument(self, argument: str = "") -> tuple[list[str], str]:
        return self._extract_output_mode_tokens(shlex.split(argument or ""))

    @staticmethod
    def _print_structured_payload(payload: Any, output_mode: str) -> None:
        print(dump_structured_payload(payload, output_mode=output_mode))

    def _parse_package_report_argument(self, argument: str = "") -> tuple[str, bool, str]:
        tokens, output_mode = self._parse_output_mode_argument(argument)
        filtered_tokens: list[str] = []
        strict_exec = False
        for token in tokens:
            if str(token).strip().lower() == "--strict-exec":
                strict_exec = True
                continue
            filtered_tokens.append(token)
        return " ".join(filtered_tokens).strip(), strict_exec, output_mode

    def _render_eim_package_lint_report(self, report: dict[str, Any]) -> None:
        print(f"[+] eIM package lint: {'ok' if report.get('ok') else 'failed'}")
        print(f"    file: {report.get('package_path', '-')}")
        print(f"    type: {report.get('package_type', '-')}")
        print(f"    version: {report.get('package_version', '-')}")
        print(f"    additional_tlvs: {report.get('additional_tlv_count', 0)}")
        print(f"    optional_tlvs: {report.get('optional_tlv_count', 0)}")
        print(
            "    spec_compliance: "
            f"{report.get('spec_passed', 0)} passed, {report.get('spec_failed', 0)} failed"
        )
        spec_checks = report.get("spec_checks", [])
        if isinstance(spec_checks, list) and len(spec_checks) > 0:
            print("    spec checks:")
            for row in spec_checks:
                status = str(row.get("status", "")).upper()
                check_name = str(row.get("check", ""))
                detail = str(row.get("detail", ""))
                print(f"      [{status}] {check_name}")
                if len(detail) > 0:
                    print(f"             {detail}")
        for warning in report.get("warnings", []):
            print(f"    [warn] {warning}")
        errors = report.get("errors", [])
        for error in errors:
            print(f"    [error] {error}")

    def _build_eim_package_explain_payload(
        self,
        package_path: str = "",
        *,
        strict_exec: bool = False,
    ) -> dict[str, Any]:
        resolved_path = self.session.resolve_eim_package_path(override_path=package_path)
        document = self.session.load_eim_package_document(package_path)
        lint_report = self.session.lint_eim_package(
            package_path=package_path,
            strict_executable=strict_exec,
        )
        runtime_hints = resolve_package_runtime_hints(document)
        certificate_preview = self.session.preview_eim_signing_certificate(
            package_path=resolved_path
        )
        identity = self.session.identity_summary()
        return {
            "package": {
                "path": resolved_path,
                "type": str(lint_report.get("package_type", "")).strip(),
                "version": str(lint_report.get("package_version", "")).strip(),
                "strict_executable": bool(strict_exec),
                "command_tag_hex": str(document.get("command_tag_hex", "")).strip().upper(),
            },
            "runtime_hints": runtime_hints,
            "signing_certificate": certificate_preview,
            "identity_defaults": {
                "eim_id": identity.get("eim_id", ""),
                "eim_fqdn": identity.get("eim_fqdn", ""),
                "default_matching_id": identity.get("default_matching_id", ""),
                "eim_endpoint": identity.get("eim_endpoint", ""),
                "smdp_address": identity.get("smdp_address", ""),
            },
            "lint": lint_report,
        }

    def _render_eim_package_explain_text(self, payload: dict[str, Any]) -> None:
        package = payload.get("package", {})
        runtime_hints = payload.get("runtime_hints", {})
        signing_certificate = payload.get("signing_certificate", {})
        identity_defaults = payload.get("identity_defaults", {})
        lint_report = payload.get("lint", {})

        print("[+] eIM package explain")
        print(f"    file        : {package.get('path', '-')}")
        print(f"    type        : {package.get('type', '-')}")
        print(f"    version     : {package.get('version', '-')}")
        print(f"    strict_exec : {'yes' if package.get('strict_executable') else 'no'}")
        command_tag = str(package.get("command_tag_hex", "")).strip()
        if len(command_tag) > 0:
            print(f"    command_tag : {command_tag}")
        print("    runtime hints:")
        print(f"      matching_id       : {runtime_hints.get('matching_id', '-') or '-'}")
        print(f"      transaction_id    : {runtime_hints.get('transaction_id_hex', '-') or '-'}")
        print(f"      profile_path      : {runtime_hints.get('profile_path', '-') or '-'}")
        print(f"      cert_der_path     : {runtime_hints.get('cert_der_path', '-') or '-'}")
        print(f"      smdp_address      : {runtime_hints.get('smdp_address', '-') or '-'}")
        print(f"      bip_endpoint      : {runtime_hints.get('bip_endpoint', '-') or '-'}")
        print("    cert selection:")
        print(f"      selected_path     : {signing_certificate.get('path', '-') or '-'}")
        print(f"      private_key_path  : {signing_certificate.get('private_key_path', '-') or '-'}")
        print(f"      rule              : {signing_certificate.get('reason', '-') or '-'}")
        root_ci_pkids = signing_certificate.get("root_ci_pkids", [])
        if isinstance(root_ci_pkids, list) and len(root_ci_pkids) > 0:
            print(f"      root_ci_pkids     : {', '.join(str(value) for value in root_ci_pkids)}")
        preferred_ci_pkids = signing_certificate.get("preferred_ci_pkids", [])
        if isinstance(preferred_ci_pkids, list) and len(preferred_ci_pkids) > 0:
            print(f"      preferred_ci_pkids: {', '.join(str(value) for value in preferred_ci_pkids)}")
        print("    identity defaults:")
        print(f"      eim_id            : {identity_defaults.get('eim_id', '-') or '-'}")
        print(f"      eim_fqdn          : {identity_defaults.get('eim_fqdn', '-') or '-'}")
        print(f"      default_matchingId: {identity_defaults.get('default_matching_id', '-') or '-'}")
        self._render_eim_package_lint_report(lint_report)

    @staticmethod
    def _render_help_row(
        label: str,
        summary: str,
        *,
        command_width: int = 40,
        summary_width: int = 38,
    ) -> list[str]:
        command_text = str(label or "").strip()
        summary_text = str(summary or "").strip()
        if len(summary_text) == 0:
            return [f"  {command_text}"]
        wrapped_summary = textwrap.wrap(summary_text, width=summary_width)
        if len(wrapped_summary) == 0:
            wrapped_summary = [summary_text]
        if len(command_text) > command_width:
            lines = [f"  {command_text}"]
            detail_prefix = "  " + (" " * command_width) + " "
            for line in wrapped_summary:
                lines.append(f"{detail_prefix}{line}")
            return lines
        lines = [f"  {command_text:<{command_width}} {wrapped_summary[0]}"]
        detail_prefix = "  " + (" " * command_width) + " "
        for line in wrapped_summary[1:]:
            lines.append(f"{detail_prefix}{line}")
        return lines

    def _print_help_section(
        self,
        title: str,
        color: str,
        rows: list[tuple[str, str]],
    ) -> None:
        if len(rows) == 0:
            return
        print(f"{color}--- {title} ---{ShellStyle.END}")
        if len(rows) >= 6 and self._terminal_width() >= 120:
            for line in self._render_help_grid(rows):
                print(line)
            print("")
            return
        for label, summary in rows:
            for line in self._render_help_row(label, summary):
                print(line)
        print("")

    @staticmethod
    def _terminal_width() -> int:
        width = shutil.get_terminal_size((120, 20)).columns
        if width < 80:
            return 80
        return width

    def _render_help_grid(self, rows: list[tuple[str, str]]) -> list[str]:
        width = self._terminal_width()
        gap = 4
        column_count = 2
        column_width = max(28, int((width - gap) / column_count) - 2)
        split_index = (len(rows) + 1) // 2
        left_rows = rows[:split_index]
        right_rows = rows[split_index:]
        rendered_lines: list[str] = []
        for index, left_row in enumerate(left_rows):
            left_block = self._render_help_grid_block(left_row, column_width)
            right_block: list[str] = []
            if index < len(right_rows):
                right_block = self._render_help_grid_block(right_rows[index], column_width)
            line_count = max(len(left_block), len(right_block))
            for line_index in range(line_count):
                left_text = ""
                right_text = ""
                if line_index < len(left_block):
                    left_text = left_block[line_index]
                if line_index < len(right_block):
                    right_text = right_block[line_index]
                if len(right_text) == 0:
                    rendered_lines.append(left_text)
                    continue
                rendered_lines.append(f"{left_text:<{column_width}}{' ' * gap}{right_text}")
        return rendered_lines

    @staticmethod
    def _render_help_grid_block(row: tuple[str, str], width: int) -> list[str]:
        label, summary = row
        inner_width = max(18, width - 2)
        label_lines = textwrap.wrap(
            str(label).strip(),
            width=inner_width,
            break_long_words=False,
            break_on_hyphens=False,
        )
        if len(label_lines) == 0:
            label_lines = [str(label).strip()]
        summary_lines = textwrap.wrap(
            str(summary).strip(),
            width=max(18, inner_width - 2),
            break_long_words=False,
            break_on_hyphens=False,
        )
        lines = [f"  {label_lines[0]}"]
        for extra in label_lines[1:]:
            lines.append(f"  {extra}")
        if len(summary_lines) > 0:
            lines.append(f"    {summary_lines[0]}")
            for extra in summary_lines[1:]:
                lines.append(f"    {extra}")
        return lines

    def _print_banner(self) -> None:
        line = "=" * 86
        print(f"\n{ShellStyle.HEADER}{line}{ShellStyle.END}")
        print(f"{ShellStyle.BOLD}Local eIM Shell Ready{ShellStyle.END}")
        warning_text = hil_bridge_warning_text()
        if len(warning_text) > 0:
            print(f"{ShellStyle.WARNING}[!] {warning_text}{ShellStyle.END}")
        print(f"{ShellStyle.HEADER}{line}{ShellStyle.END}")
        print(f"{ShellStyle.CYAN}--- Directories ---{ShellStyle.END}")
        print(f"  Profile directory : {self.cfg.PROFILE_DIR}")
        print(f"  Metadata directory: {self.cfg.METADATA_DIR}")
        print(f"  eIM package dir   : {self.cfg.EIM_PACKAGES_DIR}")
        print(f"  eIM templates dir : {self.cfg.EIM_PACKAGE_TEMPLATES_DIR}")
        print(f"  eIM fixtures dir  : {self.cfg.EIM_POLL_FIXTURES_DIR}")
        print(f"  eIM->eSIM fixtures: {self.cfg.EIM_POLL_EIM_TO_ESIM_DIR}")
        print(f"  eSIM->eIM fixtures: {self.cfg.EIM_POLL_ESIM_TO_EIM_DIR}")
        print(f"  eIM hotfolder dir : {self.cfg.EIM_HOTFOLDER_DIR}")
        print(f"  eIM cert dir      : {self.cfg.EIM_CERTS_DIR}")
        print(f"  eIM identity file : {self.cfg.EIM_IDENTITY_FILE}")
        print(f"  Runtime state file: {self.cfg.EIM_RUNTIME_STATE_FILE}")
        print(f"  Response log file : {self.cfg.EIM_RESPONSE_LOG_FILE}")
        print("")
        print(f"{ShellStyle.GREEN}--- Endpoints ---{ShellStyle.END}")
        identity = self.session.identity_summary()
        print(f"  BIP endpoint (eIM) : {identity.get('eim_endpoint', self.cfg.EIM_BIP_ENDPOINT)}")
        print(f"  BIP endpoint (DP+) : {identity.get('smdpp_endpoint', self.cfg.SMDPP_BIP_ENDPOINT)}")
        print(f"  Activation SM-DP+  : {identity.get('smdp_address', self.cfg.SMDPP_BIP_ENDPOINT)}")
        print("  Routing mode       : runtime-managed interception")
        try:
            active_profile = self.session.resolve_profile_path()
        except Exception as error:
            active_profile = f"error: {error}"
        try:
            active_metadata = self.session.resolve_metadata_path()
        except Exception as error:
            active_metadata = f"error: {error}"
        try:
            active_package = self.session.resolve_eim_package_path()
        except Exception as error:
            active_package = f"error: {error}"
        try:
            active_hotfolder = self.session.resolve_hotfolder_path()
        except Exception as error:
            active_hotfolder = f"error: {error}"
        active_cert = self.session.eim_state.selected_eim_certificate_path or "-"
        next_hotfolder_package = "-"
        hotfolder_preview_rows: list[dict[str, Any]] = []
        if isinstance(active_hotfolder, str) and active_hotfolder.startswith("error:") is False:
            try:
                hotfolder_preview_rows = self.session.list_hotfolder_preview(hotfolder_dir=active_hotfolder)
                if len(hotfolder_preview_rows) > 0:
                    next_hotfolder_package = str(hotfolder_preview_rows[0].get("path", "")).strip() or "-"
            except Exception:
                next_hotfolder_package = "-"
                hotfolder_preview_rows = []
        print("")
        print(f"{ShellStyle.WARNING}--- Current Target Files ---{ShellStyle.END}")
        print(f"  Profile target      : {self._format_target_value(active_profile)}")
        print(f"  Metadata target     : {self._format_target_value(active_metadata)}")
        print(f"  eIM package target  : {self._format_target_value(active_package)}")
        print(f"  Hotfolder target    : {self._format_target_value(active_hotfolder)}")
        print(f"  Poll queue next file: {self._format_target_value(next_hotfolder_package)}")
        print(f"  eIM cert target     : {self._format_target_value(active_cert)}")
        print(f"  eIM identity file   : {self._format_target_value(identity.get('identity_file', '-'))}")
        print(f"  eIM ID              : {self._format_target_value(identity.get('eim_id', '-'))}")
        print(f"  eIM FQDN            : {self._format_target_value(identity.get('eim_fqdn', '-'))}")
        print(f"  eIM signing cert    : {self._format_target_value(identity.get('eim_public_key_cert_path', '-'))}")
        print(f"  eIM TLS cert        : {self._format_target_value(identity.get('trusted_tls_cert_path', '-'))}")
        print(f"  eIM TLS key         : {self._format_target_value(identity.get('tls_private_key_path', '-'))}")
        print("")
        print(f"{ShellStyle.CYAN}--- Poll Session Queue Preview ---{ShellStyle.END}")
        if isinstance(active_hotfolder, str) and active_hotfolder.lower().startswith("error:"):
            print(f"  {self._format_target_value(active_hotfolder)}")
        elif len(hotfolder_preview_rows) == 0:
            print(f"  {self._format_target_value('-')} (empty)")
        else:
            for row in hotfolder_preview_rows:
                order = int(row.get("order", 0))
                package_type = str(row.get("package_type", "")).strip() or "-"
                path_text = str(row.get("path", "")).strip()
                name = os.path.basename(path_text) if len(path_text) > 0 else "-"
                session_source = str(row.get("session_source", "")).strip() or "-"
                queue_source = str(row.get("queue_source", "")).strip() or "-"
                print(
                    f"  {order:>2}. {name}  [{package_type}]  "
                    f"origin={session_source} order={queue_source}"
                )
        print(f"{ShellStyle.HEADER}{line}{ShellStyle.END}")

    def _hex_preview(self, payload: bytes, max_chars: int = 80) -> str:
        if len(payload) == 0:
            return "-"
        text = payload.hex().upper()
        if len(text) <= max_chars:
            return text
        return f"{text[:max_chars]}..."

    def _queue_modem_refresh(self, action_label: str, mode: str = "") -> None:
        try:
            payload = trigger_card_relay_modem_refresh(
                mode=mode,
                source=f"scp11-eim-local:{action_label}",
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

    def _format_target_value(self, value: Any) -> str:
        text = str(value or "").strip()
        if len(text) == 0:
            text = "-"
        if text == "-":
            return f"{ShellStyle.WARNING}{text}{ShellStyle.END}"
        if text.lower().startswith("error:"):
            return f"{ShellStyle.RED}{text}{ShellStyle.END}"
        return text

    def _print_selected_eim_certificate(self) -> None:
        summary = self.session.selected_eim_certificate_summary()
        print(f"    cert_path : {summary.get('path') or '-'}")
        print(f"    cert_rule : {summary.get('reason') or '-'}")
        root_ci_pkids = summary.get("root_ci_pkids", [])
        if isinstance(root_ci_pkids, list) and len(root_ci_pkids) > 0:
            print(f"    cert_ci   : {', '.join(str(value) for value in root_ci_pkids)}")
        private_key_path = str(summary.get("private_key_path", "") or "").strip()
        if len(private_key_path) > 0:
            print(f"    cert_key  : {private_key_path}")

    # Bridge / orchestrator lifecycle is installed by the polling plugin
    # via ``PollingCapability.extend_target`` (see
    # ``plugins/polling/shell_lifecycle.py``). When the plugin is absent
    # every IPAD / IPAE / PATHS-bridge-section code path that tries to
    # reach a bridge must fail loudly, so we keep tiny stubs here that
    # either raise or return neutral placeholders.

    def _stop_poll_bridge(self) -> None:
        return

    def _close_shell_session_if_open(self) -> None:
        state = getattr(self.session, "state", None)
        if bool(getattr(state, "session_open", False)) is False:
            return
        close_session = getattr(self.session, "close_session", None)
        if callable(close_session) is False:
            return
        close_session()

    def _bridge_status_payload(self) -> dict[str, Any]:
        # Fallback stub — the polling plugin overrides this with the
        # real bridge status through ``extend_target``. Absent plugin ⇒
        # STATUS / PATHS print ``-`` / ``no``.
        return {}

    def _ensure_poll_bridge(self, reset_runtime: bool = True) -> Any:
        raise RuntimeError(
            "Localized polling bridge is provided by the polling plugin and "
            "is not available in this build."
        )

    def _close_network_runtime(self, orchestrator: Any) -> None:
        if orchestrator is None:
            return
        close_open_channel = getattr(orchestrator, "_close_stk_open_channel", None)
        if callable(close_open_channel):
            try:
                close_open_channel()
            except Exception:
                pass

    def _configure_localized_bridge_profile_provider(self, profile_provider: Any) -> Any:
        return profile_provider

    def _load_network_orchestrator(self, profile_name: str) -> Any:
        raise RuntimeError(
            "Networked orchestrator with localized bridge is provided by the "
            "polling plugin and is not available in this build."
        )

    def _cmd_paths(self, _: str = "") -> None:
        identity = self.session.identity_summary()
        bridge_status = self._bridge_status_payload()
        dns_endpoint = (
            f"{bridge_status.get('bind_host', '-')}:{bridge_status.get('dns_port', '-')}"
        )
        eim_base_url = str(bridge_status.get("eim_base_url", "") or "").strip()
        smdp_base_url = str(bridge_status.get("smdp_base_url", "") or "").strip()
        eim_endpoint = "-"
        smdp_endpoint = "-"
        if len(eim_base_url) > 0:
            eim_endpoint = f"{eim_base_url}/gsma/rsp2/asn1"
        if len(smdp_base_url) > 0:
            smdp_endpoint = f"{smdp_base_url}/gsma/rsp2/es9plus"
        print("\n--- Localized Path Families ---")
        print("1. Direct Auth")
        print("   flow      : Local SCP11 authenticate -> card command -> close session")
        print("   purpose   : Direct ISD-R validation without eIM / SM-DP+ polling")
        print("2. IPAd Polling")
        print("   live cmd  : IPAD-LIVE [matchingId] [--debug]")
        print("   test cmd  : IPAD-TEST [matchingId] [--debug]")
        print("   route     : SIM <-> IPAd <-> eIM/SM-DP+")
        print("   transport : Host-side HTTPS client is pinned to the localized bridge")
        for section in self._plugin_path_sections:
            title = str(section.get("title", "")).strip()
            if len(title) > 0:
                print(title)
            for line in section.get("lines", []):
                print(str(line))
        print("")
        print("--- Bridge Endpoints ---")
        print(f"bridge started : {'yes' if bridge_status.get('started') else 'no'}")
        print(f"dns endpoint   : {dns_endpoint}")
        print(f"eIM endpoint   : {eim_endpoint}")
        print(f"SM-DP+ endpoint: {smdp_endpoint}")
        print(f"eIM FQDN       : {identity.get('eim_fqdn', '-')}")
        print(f"SM-DP+ FQDN    : {bridge_status.get('smdp_fqdn', identity.get('smdp_address', '-'))}")

    @staticmethod
    def _looks_like_json_path(path_text: str) -> bool:
        return str(path_text or "").strip().lower().endswith(".json")

    def _decode_eim_entries(self, response: bytes) -> list[dict[str, Any]]:
        if decode_eim_configuration_entries is None or len(response) == 0:
            return []
        try:
            decoded = decode_eim_configuration_entries(response)
        except Exception:
            return []
        if isinstance(decoded, list) is False:
            return []
        return decoded

    def _set_cached_poll_target_fqdns(self, targets: list[str]) -> None:
        cached_targets: list[str] = []
        for fqdn_value in targets:
            normalized_fqdn = str(fqdn_value).strip()
            if len(normalized_fqdn) == 0:
                continue
            if normalized_fqdn in cached_targets:
                continue
            cached_targets.append(normalized_fqdn)
        self._cached_poll_target_fqdns = cached_targets

    def _cache_poll_target_fqdns_from_entries(
        self,
        entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        targets: list[str] = []
        for entry in entries:
            if isinstance(entry, dict) is False:
                continue
            fqdn_value = str(entry.get("eim_fqdn", "")).strip()
            if len(fqdn_value) == 0:
                continue
            targets.append(fqdn_value)
        self._set_cached_poll_target_fqdns(targets)
        return entries

    def _cache_poll_target_fqdns_from_eim_response(
        self,
        response: bytes,
    ) -> list[dict[str, Any]]:
        entries = self._decode_eim_entries(response)
        return self._cache_poll_target_fqdns_from_entries(entries)

    def _cache_poll_target_fqdns_from_discovery_snapshot(
        self,
        snapshot: dict[str, Any],
    ) -> None:
        if isinstance(snapshot, dict) is False:
            self._invalidate_poll_target_cache()
            return
        response = snapshot.get("eim_configuration", b"")
        if isinstance(response, bytearray):
            response = bytes(response)
        if isinstance(response, bytes) is False:
            self._invalidate_poll_target_cache()
            return
        self._cache_poll_target_fqdns_from_eim_response(response)

    def _resolve_cached_poll_target_fqdns(self) -> list[str]:
        return list(self._cached_poll_target_fqdns)

    def _invalidate_poll_target_cache(self) -> None:
        self._cached_poll_target_fqdns = []

    def _print_command_response(self, label: str, response: bytes, transport: str = "") -> None:
        print(f"[+] {label} completed ({len(response)} bytes).")
        if len(transport.strip()) > 0:
            print(f"    transport: {transport}")
        print(f"    response : {self._hex_preview(response, 120)}")

    def _print_eim_configuration_report(
        self,
        response: bytes,
        title: str = "GetEimConfigurationData",
    ) -> list[dict[str, Any]]:
        print(f"[+] {title} ({len(response)} bytes).")
        print(f"    response : {self._hex_preview(response, 120)}")
        entries = self._decode_eim_entries(response)
        print(f"    eIM rows : {len(entries)}")
        for index, entry in enumerate(entries[:5], start=1):
            eim_id = str(entry.get("eim_id", "")).strip() or "-"
            fqdn = str(entry.get("eim_fqdn", "")).strip() or "-"
            counter_value = str(entry.get("counter_value", "")).strip() or "-"
            print(
                f"    [{index}] eimId={eim_id} "
                f"fqdn={fqdn} counter={counter_value}"
            )
        if len(entries) > 5:
            print(f"    ... +{len(entries) - 5} additional row(s)")
        return entries

    def _print_post_eim_configuration_snapshot(
        self,
        title: str = "ISDR post-state GetEimConfigurationData",
    ) -> list[dict[str, Any]]:
        response = self.session.get_eim_configuration_data()
        self._cache_poll_target_fqdns_from_eim_response(response)
        return self._print_eim_configuration_report(response, title=title)

    def _resolve_isdr_add_package_path(
        self,
        package_path: str,
        expected_types: tuple[str, ...],
    ) -> str:
        resolved_path = self.session.resolve_eim_package_path(override_path=package_path)
        document = self.session.load_eim_package_document(override_path=resolved_path)
        package_type = str(document.get("package_type", "")).strip().lower()
        if package_type not in expected_types:
            expected_text = ", ".join(expected_types)
            raise ValueError(
                f"Package type '{package_type or '-'}' is invalid for this command. "
                f"Expected one of: {expected_text}."
            )
        return resolved_path

    def _parse_isdr_add_args(
        self,
        argument: str,
        expected_types: tuple[str, ...],
        usage: str,
    ) -> tuple[str, str, str]:
        parts = shlex.split(argument)
        if len(parts) == 0:
            return (
                "package_isdr",
                "",
                self._resolve_isdr_add_package_path("", expected_types),
            )
        if len(parts) == 1:
            token = parts[0].strip()
            if self._looks_like_json_path(token):
                return (
                    "package_isdr",
                    "",
                    self._resolve_isdr_add_package_path(token, expected_types),
                )
            return "isdr", token, ""
        if len(parts) != 2:
            raise ValueError(usage)
        cert_path = parts[0].strip()
        package_path = self._resolve_isdr_add_package_path(parts[1].strip(), expected_types)
        return "package_isdr", cert_path, package_path

    def _parse_load_eim_package_args(self, argument: str) -> tuple[str, str]:
        parts = shlex.split(argument)
        if len(parts) > 2:
            raise ValueError("Usage: LOAD-EIM-PACKAGE [packagePath] [certPath]")
        package_path = ""
        cert_path = ""
        if len(parts) > 0:
            package_path = parts[0].strip()
        if len(parts) > 1:
            cert_path = parts[1].strip()
        return package_path, cert_path

    def _default_euicc_memory_reset_package_path(self) -> str:
        return self.session.resolve_eim_package_path(
            override_path=(
                "Workspace/LocalEIM/eim_packages/templates/"
                "template_euicc_memory_reset.json"
            )
        )

    def _parse_euicc_memory_reset_args(self, argument: str) -> str:
        parts = shlex.split(argument)
        if len(parts) > 1:
            raise ValueError("Usage: EUICC-MEMORY-RESET [packagePath]")
        if len(parts) == 0:
            resolved_path = self._default_euicc_memory_reset_package_path()
        else:
            resolved_path = self.session.resolve_eim_package_path(override_path=parts[0].strip())
        document = self.session.load_eim_package_document(override_path=resolved_path)
        package_type = str(document.get("package_type", "")).strip().lower()
        if package_type != "euicc_memory_reset":
            raise ValueError(
                f"Package type '{package_type or '-'}' is invalid for EUICC-MEMORY-RESET. "
                "Expected euicc_memory_reset."
            )
        return resolved_path

    def _cmd_help(self, argument: str = "") -> None:
        command_name = argument.strip().upper()
        if len(command_name) > 0:
            self._show_command_help(command_name)
            return
        print(f"\n{ShellStyle.BOLD}{ShellStyle.HEADER}Local eIM Command Groups{ShellStyle.END}")
        print("  Use HELP <command> for full usage, examples, and alias information.")
        print("  Add --debug to card-facing commands for full raw APDU hex tracing.")
        print("  Use --yaml when you want structured output without defaulting to JSON.")
        print("  Use RECORD START/STOP to capture replayable commands plus APDU trace to file.")
        print("  Canonical command names are listed here; legacy aliases still resolve.\n")

        local_flow_rows = [
            self._help_row("DISCOVER", "DISCOVER"),
            self._help_row("LIST", "LIST"),
            self._help_row("LOAD-PROFILE [path]", "LOAD-PROFILE"),
            self._help_row("ENABLE-PROFILE <id>", "ENABLE-PROFILE"),
            self._help_row("DISABLE-PROFILE <id>", "DISABLE-PROFILE"),
            self._help_row("DELETE-PROFILE <id>", "DELETE-PROFILE"),
            self._help_row("REFRESH-MODEM [mode]", "REFRESH-MODEM"),
            self._help_row("STORE-METADATA [path]", "STORE-METADATA"),
            self._help_row("UPDATE-METADATA [path]", "UPDATE-METADATA"),
        ]
        override_rows = [
            self._help_row("PROFILE [path]", "PROFILE"),
            self._help_row("PROFILE-CLEAR", "PROFILE-CLEAR"),
            self._help_row("METADATA [path]", "METADATA"),
            self._help_row("METADATA-CLEAR", "METADATA-CLEAR"),
            self._help_row("METADATA-LINT [path]", "METADATA-LINT"),
        ]
        localized_rows = [
            self._help_row("PATHS", "PATHS"),
            self._help_row("IPAD-DISCOVER [package]", "IPAD-DISCOVER"),
            self._help_row("IPAD-LIVE [matchingId] [--debug]", "IPAD-LIVE"),
            self._help_row("IPAD-TEST [matchingId] [--debug]", "IPAD-TEST"),
            self._help_row("IPAE-AUTHENTICATE [matchingId]", "IPAE-AUTHENTICATE"),
            self._help_row("IPAE-DOWNLOAD [profile] [matchingId]", "IPAE-DOWNLOAD"),
        ]
        localized_rows.extend(list(self._plugin_localized_help_rows))
        localized_rows.extend(
            [
                self._help_row("HANDOVER-SET <txidHex> [matchingId]", "HANDOVER-SET"),
                self._help_row("HANDOVER-STATUS [--yaml]", "HANDOVER-STATUS"),
            ]
        )
        package_rows = [
            self._help_row("EIM-PACKAGE [path]", "EIM-PACKAGE"),
            self._help_row("EIM-PACKAGE-CLEAR", "EIM-PACKAGE-CLEAR"),
            self._help_row("EIM-PACKAGE-LINT [path] [--strict-exec]", "EIM-PACKAGE-LINT"),
            self._help_row("EIM-PACKAGE-EXPLAIN [path] [--yaml]", "EIM-PACKAGE-EXPLAIN"),
            self._help_row("EIM-PACKAGE-ISSUE [path]", "EIM-PACKAGE-ISSUE"),
            self._help_row("EIM-PACKAGE-ISSUE-ALL [dir]", "EIM-PACKAGE-ISSUE-ALL"),
            self._help_row("EIM-CERTS [--json|--yaml] [pkg] [cert]", "EIM-CERTS"),
            self._help_row("ADD-INITIAL-EIM [mode] [cert] [pkg]", "ADD-INITIAL-EIM"),
            self._help_row("ADD-EIM [mode] [cert] [pkg]", "ADD-EIM"),
            self._help_row("GET-EIM-CONFIG", "GET-EIM-CONFIG"),
            self._help_row("DELETE-EIM <eimId>", "DELETE-EIM"),
            self._help_row("EUICC-MEMORY-RESET [pkg]", "EUICC-MEMORY-RESET"),
            self._help_row("ISDR-GET-EIM-CONFIG", "ISDR-GET-EIM-CONFIG"),
            self._help_row("ISDR-DELETE-EIM <eimId>", "ISDR-DELETE-EIM"),
            self._help_row("ISDR-ADD-INITIAL-EIM [cert] [pkg]", "ISDR-ADD-INITIAL-EIM"),
            self._help_row("ISDR-ADD-EIM [cert] [pkg]", "ISDR-ADD-EIM"),
            self._help_row("LOAD-EIM-PACKAGE [pkg] [cert]", "LOAD-EIM-PACKAGE"),
            self._help_row("EIM-ACKNOWLEDGE [txid] [mid]", "EIM-ACKNOWLEDGE"),
        ]
        queue_rows = [
            self._help_row("HOTFOLDER [dir]", "HOTFOLDER"),
            self._help_row("HOTFOLDER-CLEAR", "HOTFOLDER-CLEAR"),
            self._help_row("HOTFOLDER-LIST [dir] [--json|--yaml]", "HOTFOLDER-LIST"),
            self._help_row("HOTFOLDER-POLL [dir] [--yaml]", "HOTFOLDER-POLL"),
            self._help_row("HOTFOLDER-FETCH [dir] [--json|--yaml]", "HOTFOLDER-FETCH"),
            self._help_row("POLL-CAMPAIGN [cycles] [intervalMs] [...] [--yaml]", "POLL-CAMPAIGN"),
            self._help_row("POLL-EXPORT [cycles] [intervalMs] [...] [out]", "POLL-EXPORT"),
            self._help_row("POLL-AGGREGATE [dir] [--json|--yaml] [--export ...]", "POLL-AGGREGATE"),
        ]
        diagnostic_rows = [
            self._help_row("STATUS", "STATUS"),
            self._help_row("NOTIF-HYGIENE [maxPending]", "NOTIF-HYGIENE"),
            self._help_row("COUNTERS", "COUNTERS"),
            self._help_row("COUNTER <eimId> [set <n>]", "COUNTER"),
            self._help_row("ERROR-CODES [spec]", "ERROR-CODES"),
            self._help_row("ERROR-CODE-SET <family> <code> [path]", "ERROR-CODE-SET"),
            self._help_row("RESP-LOG [n] [--json|--yaml]", "RESP-LOG"),
            self._help_row("RESP-LOG-FILTER <query> [n] [--json|--yaml]", "RESP-LOG-FILTER"),
            self._help_row("RESP-LOG-CLEAR", "RESP-LOG-CLEAR"),
        ]
        shell_rows = [
            self._help_row("RECORD [STATUS|START|STOP|CANCEL] [path]", "RECORD"),
            self._help_row("HELP [command]", "HELP"),
            self._help_row("EXIT", "EXIT"),
            self._help_row("QA", "QA"),
        ]

        self._print_help_section("Local Profile Flow", ShellStyle.CYAN, local_flow_rows)
        self._print_help_section("Targets & Overrides", ShellStyle.BLUE, override_rows)
        self._print_help_section("Localized Routing & Handover", ShellStyle.GREEN, localized_rows)
        self._print_help_section("eIM Packages & ISD-R", ShellStyle.WARNING, package_rows)
        self._print_help_section("Queue Campaigns", ShellStyle.CYAN, queue_rows)
        self._print_help_section("Diagnostics & Runtime", ShellStyle.BLUE, diagnostic_rows)
        self._print_help_section("Shell", ShellStyle.WHITE, shell_rows)

    def _cmd_status(self, _: str = "") -> None:
        state = self.session.state
        eim_state = self.session.eim_state
        print("\n--- Local eIM Status ---")
        print(f"Session open        : {'yes' if state.session_open else 'no'}")
        print(f"ISD-R selected      : {'yes' if state.isdr_selected else 'no'}")
        print(
            "Transaction ID      : "
            + (state.transaction_id.hex().upper() if len(state.transaction_id) > 0 else "-")
        )
        print(f"BIP routing mode    : {eim_state.bip_routing_mode}")
        print(f"BIP role            : {eim_state.current_bip_role}")
        print(f"BIP endpoint        : {eim_state.current_bip_endpoint}")
        print(f"Intercepted target  : {eim_state.last_intercepted_target or '-'}")
        print(f"Intercept reason    : {eim_state.last_intercept_reason or '-'}")
        print(f"eIM cert path       : {eim_state.selected_eim_certificate_path or '-'}")
        print(f"eIM package override: {eim_state.eim_package_override_path or '-'}")
        print(f"Hotfolder override  : {eim_state.hotfolder_override_path or '-'}")
        print(f"Pending operations  : {len(self.session.pending_operations())}")
        bridge_status = self._bridge_status_payload()
        dns_endpoint = (
            f"{bridge_status.get('bind_host', '-')}:{bridge_status.get('dns_port', '-')}"
        )
        print(f"Bridge started      : {'yes' if bridge_status.get('started') else 'no'}")
        print(
            "Bridge endpoints    : "
            f"dns={dns_endpoint} "
            f"eim={bridge_status.get('eim_base_url', '-')} "
            f"smdp={bridge_status.get('smdp_base_url', '-')}"
        )
        runtime_state = self.session.runtime_state_summary()
        identity = self.session.identity_summary()
        print(f"eIM identity file  : {identity.get('identity_file', '-')}")
        print(f"eIM display name   : {identity.get('display_name', '-')}")
        print(f"eIM ID             : {identity.get('eim_id', '-')}")
        print(f"eIM ID type        : {identity.get('eim_id_type', '-')}")
        print(f"eIM FQDN           : {identity.get('eim_fqdn', '-')}")
        print(f"Default matchingId : {identity.get('default_matching_id', '-')}")
        print(f"eIM endpoint       : {identity.get('eim_endpoint', '-')}")
        print(f"SM-DP+ endpoint    : {identity.get('smdpp_endpoint', '-')}")
        print(f"SM-DP+ address     : {identity.get('smdp_address', '-')}")
        print(f"eIM signing cert   : {identity.get('eim_public_key_cert_path', '-')}")
        print(f"eIM TLS cert       : {identity.get('trusted_tls_cert_path', '-')}")
        print(f"eIM TLS key        : {identity.get('tls_private_key_path', '-')}")
        print(f"eUICC CI PKId      : {identity.get('euicc_ci_pk_id', '-')}")
        print(f"Legacy state file   : {runtime_state.get('state_file', '-')}")
        print(f"Response log file   : {runtime_state.get('response_log_file', '-')}")
        print(f"Poll audit DB file  : {runtime_state.get('poll_audit_db_file', '-')}")
        counter_map = runtime_state.get("counter_by_eim_id", {})
        if isinstance(counter_map, dict):
            print(f"Tracked counters    : {len(counter_map)}")
            for eim_id in sorted(counter_map.keys()):
                print(f"  - {eim_id}: next={counter_map.get(eim_id)}")
        handover = self.session.handover_context()
        print(f"Handover txid       : {handover.get('transaction_id_hex', '-')}")
        print(f"Handover matchingId : {handover.get('matching_id', '-')}")
        print(f"Handover source     : {handover.get('source', '-')}")

    def _cmd_discover(self, _: str = "") -> None:
        snapshot = self.session.discover_card()
        self._cache_poll_target_fqdns_from_discovery_snapshot(snapshot)
        render_consolidated_discovery_snapshot(
            snapshot,
            header_color=ShellStyle.HEADER,
            end_color=ShellStyle.END,
        )

    def _cmd_scan(self, _: str = "") -> None:
        """Quick card overview — header data only.

        Mirrors the ``SCAN`` (and ``INFO`` alias) behaviour of eSIM Live /
        Test / Local SMDP+: EID, eCASD issuer, default SM-DP+, root SM-DS,
        eIM entries, and the profile inventory. Skips the heavy ES10
        reads (``GetRAT`` / ``RetrieveNotificationsList`` / ``GetCerts``)
        that ``DISCOVER`` performs so refreshing the header card after a
        profile switch stays cheap.
        """
        snapshot = self.session.collect_quick_overview()
        self._cache_poll_target_fqdns_from_discovery_snapshot(snapshot)
        render_card_overview_snapshot(
            snapshot,
            header_title="Local eIM Session Ready",
            header_color=ShellStyle.HEADER,
            accent_color=ShellStyle.CYAN,
            end_color=ShellStyle.END,
            profile_table_title="Profiles on Card",
        )
        warning_text = hil_bridge_warning_text()
        if len(warning_text) > 0:
            print(f"{ShellStyle.WARNING}[!] {warning_text}{ShellStyle.END}")

    def _cmd_load_profile(self, argument: str = "") -> None:
        response = self.session.run_load_profile_chain(profile_path=argument.strip())
        print(f"[+] LOAD-PROFILE completed ({len(response)} bytes).")
        print(f"    {self._hex_preview(response)}")

    def _cmd_list_profiles(self, _: str = "") -> None:
        aliases = self.session.list_profile_aliases()
        if len(aliases) == 0:
            print("[*] No profile aliases found in AID registry.")
            print("[*] You can still use ICCID or AID directly with ENABLE/DISABLE/DELETE.")
            return
        print(f"[+] Known profile aliases ({len(aliases)}):")
        for row in aliases:
            alias = str(row.get("alias", "")).strip() or "-"
            aid = str(row.get("aid", "")).strip() or "-"
            print(f"    - {alias:<16} -> {aid}")

    def _safe_collect_profile_metadata(self) -> list[Any]:
        """Read profile metadata for ENABLE / DISABLE / DELETE auto-routing.

        Returns an empty list if the card read or the decoder fails — the
        shared helpers fall back to the raw identifier in that case so
        the operator still gets a clean error from the card if their
        identifier is bogus.
        """
        try:
            raw = self.session.get_profiles_info()
            return list(self.session.decode_profile_metadata_rows(raw))
        except Exception:
            return []

    @staticmethod
    def _profile_metadata_identifier(entry: Any) -> str:
        iccid = str(getattr(entry, "iccid", "") or "").strip()
        if len(iccid) > 0:
            return iccid
        aid = str(getattr(entry, "aid", "") or "").strip()
        if len(aid) > 0:
            return aid
        return str(getattr(entry, "nickname", "") or "").strip()

    @staticmethod
    def _describe_profile_metadata(entry: Any) -> str:
        nickname = str(getattr(entry, "nickname", "") or "").strip()
        iccid = str(getattr(entry, "iccid", "") or "").strip()
        if len(nickname) > 0 and len(iccid) > 0:
            return f"{nickname} (ICCID {iccid})"
        if len(iccid) > 0:
            return f"ICCID {iccid}"
        if len(nickname) > 0:
            return nickname
        aid = str(getattr(entry, "aid", "") or "").strip()
        if len(aid) > 0:
            return f"AID {aid}"
        return "(unknown profile)"

    def _build_profile_action_adapter(self) -> ProfileActionAdapter:
        """Wire the local-eIM session into the shared profile-action helpers.

        Same shape as ``LocalAccessShell._build_profile_action_adapter``;
        the eIM-local shell historically had no auto-disable logic and
        no PPR1 guard, so adopting the shared adapter brings it to
        parity with eSIM Live / Test / Local SMDP+ in one move.
        """
        return ProfileActionAdapter(
            enable_profile=lambda target: self._invoke_profile_state_command(
                "EnableProfile",
                lambda: self.session.enable_profile(target),
            ),
            disable_profile=lambda target: self._invoke_profile_state_command(
                "DisableProfile",
                lambda: self.session.disable_profile(target),
            ),
            delete_profile=lambda target: self._invoke_profile_state_command(
                "DeleteProfile",
                lambda: self.session.delete_profile(target),
            ),
            policy_allow_auto_disable=None,
            modem_refresh=self._queue_modem_refresh,
            describe_profile=self._describe_profile_metadata,
            profile_identifier=self._profile_metadata_identifier,
        )

    def _invoke_profile_state_command(
        self,
        action_label: str,
        callback: Callable[[], bytes],
    ) -> bytes:
        try:
            response = callback()
        except Exception as error:
            print(f"[!] {action_label} failed: {error}")
            return b""
        print(f"[+] {action_label} completed ({len(response)} bytes).")
        print(f"    {self._hex_preview(response)}")
        return response if isinstance(response, (bytes, bytearray)) else b""

    def _cmd_enable_profile(self, argument: str = "") -> None:
        identifier = argument.strip()
        if len(identifier) == 0:
            raise ValueError("Usage: ENABLE-PROFILE <iccid|aid|alias>")
        shared_run_enable_profile(
            self._build_profile_action_adapter(),
            self._safe_collect_profile_metadata(),
            identifier,
        )

    def _cmd_disable_profile(self, argument: str = "") -> None:
        identifier = argument.strip()
        if len(identifier) == 0:
            raise ValueError("Usage: DISABLE-PROFILE <iccid|aid|alias>")
        shared_run_disable_profile(
            self._build_profile_action_adapter(),
            self._safe_collect_profile_metadata(),
            identifier,
        )

    def _cmd_delete_profile(self, argument: str = "") -> None:
        identifier = argument.strip()
        if len(identifier) == 0:
            raise ValueError("Usage: DELETE-PROFILE <iccid|aid|alias>")
        shared_run_delete_profile(
            self._build_profile_action_adapter(),
            self._safe_collect_profile_metadata(),
            identifier,
        )

    def _cmd_refresh_modem(self, argument: str = "") -> None:
        self._queue_modem_refresh("RefreshModem", mode=argument.strip())

    def _cmd_profile(self, argument: str = "") -> None:
        path_text = argument.strip()
        if len(path_text) == 0:
            print(f"[+] Active profile: {self.session.resolve_profile_path()}")
            return
        print(f"[+] Profile override: {self.session.set_profile_override_path(path_text)}")

    def _cmd_profile_clear(self, _: str = "") -> None:
        self.session.clear_profile_override_path()
        print("[+] Profile override cleared.")

    def _cmd_metadata(self, argument: str = "") -> None:
        path_text = argument.strip()
        if len(path_text) == 0:
            print(f"[+] Active metadata: {self.session.resolve_metadata_path()}")
            return
        print(f"[+] Metadata override: {self.session.set_metadata_override_path(path_text)}")

    def _cmd_metadata_clear(self, _: str = "") -> None:
        self.session.clear_metadata_override_path()
        print("[+] Metadata override cleared.")

    def _cmd_metadata_lint(self, argument: str = "") -> None:
        report = self.session.lint_metadata(metadata_path=argument.strip())
        print("[+] Metadata lint passed.")
        print(f"    file: {report.get('metadata_path', '-')}")
        print(f"    StoreMetadata len: {report.get('store_metadata_len', 0)}")
        update_error = str(report.get("update_metadata_error", "") or "")
        if len(update_error) == 0:
            print(f"    UpdateMetadata len: {report.get('update_metadata_len', 0)}")
        else:
            print(f"    UpdateMetadata: not encodable ({update_error})")

    def _cmd_store_metadata(self, argument: str = "") -> None:
        response = self.session.store_metadata(metadata_path=argument.strip())
        print(f"[+] StoreMetadata completed ({len(response)} bytes).")
        print(f"    {self._hex_preview(response)}")

    def _cmd_update_metadata(self, argument: str = "") -> None:
        response = self.session.update_metadata(metadata_path=argument.strip())
        print(f"[+] UpdateMetadata completed ({len(response)} bytes).")
        print(f"    {self._hex_preview(response)}")

    def _cmd_get_eim_config(self, _: str = "") -> None:
        response = self.session.get_eim_configuration_data()
        self._cache_poll_target_fqdns_from_eim_response(response)
        self._print_eim_configuration_report(response)

    def _cmd_delete_eim(self, argument: str = "") -> None:
        eim_id = argument.strip()
        if len(eim_id) == 0:
            raise ValueError("Usage: DELETE-EIM <eimId>")
        response = self.session.delete_eim(eim_id)
        self._print_command_response("DeleteEim", response)
        self._invalidate_poll_target_cache()

    def _cmd_isdr_get_eim_config(self, _: str = "") -> None:
        response = self.session.get_eim_configuration_data()
        self._cache_poll_target_fqdns_from_eim_response(response)
        self._print_eim_configuration_report(
            response,
            title="ISDR GetEimConfigurationData",
        )

    def _cmd_isdr_delete_eim(self, argument: str = "") -> None:
        eim_id = argument.strip()
        if len(eim_id) == 0:
            raise ValueError("Usage: ISDR-DELETE-EIM <eimId>")
        response = self.session.delete_eim(eim_id)
        self._print_command_response(
            "ISDR DeleteEim",
            response,
            transport="direct_card",
        )
        self._invalidate_poll_target_cache()
        self._print_post_eim_configuration_snapshot()

    def _cmd_ipad_discover(self, argument: str = "") -> None:
        # Always safe — pure ASN.1 GetEimPackage exchange; no bridge needed.
        sequence = self.session.ipad_discover(package_path=argument.strip())
        for title, response in sequence:
            print(f"\n[IPAd] {title}")
            print(f"    | Bytes: {len(response)}")
            print(f"    | HEX  : {self._hex_preview(response, 120)}")

    def _cmd_ipae_authenticate(self, argument: str = "") -> None:
        handover = self.session.ipae_authenticate(matching_id=argument.strip())
        print("[+] IPAe authentication seeded.")
        print(f"    transactionId: {handover.transaction_id.hex().upper()}")
        print(f"    matchingId   : {handover.matching_id or '-'}")

    def _cmd_ipae_download(self, argument: str = "") -> None:
        parts = argument.split()
        profile_path = ""
        matching_id = ""
        if len(parts) >= 1:
            profile_path = parts[0]
        if len(parts) >= 2:
            matching_id = parts[1]
        response = self.session.ipae_download(profile_path=profile_path, matching_id=matching_id)
        print("[+] IPAe download flow completed with handover transaction.")
        print(f"    bytes: {len(response)}")
        print(f"    head : {self._hex_preview(response)}")

    # IPAD-LIVE / IPAD-TEST are installed by the polling plugin. When
    # the plugin is absent the command table still has neutral fallback
    # stubs that surface a clear error, keeping the shell runnable
    # without exposing bridge internals.

    def _cmd_ipad_live(self, argument: str = "") -> None:
        raise RuntimeError(
            "IPAD-LIVE requires the polling plugin (plugins/polling/). "
            "Install it or use IPAE-AUTHENTICATE + IPAE-DOWNLOAD instead."
        )

    def _cmd_ipad_test(self, argument: str = "") -> None:
        raise RuntimeError(
            "IPAD-TEST requires the polling plugin (plugins/polling/). "
            "Install it or use IPAE-AUTHENTICATE + IPAE-DOWNLOAD instead."
        )

    @staticmethod
    def _parse_localized_ipae_args(argument: str = "") -> tuple[int, int, bool]:
        return parse_eim_local_ipae_args(argument)

    def _run_localized_ipae(self, profile_name: str, argument: str = "") -> None:
        dispatch_poll_method(self, "_run_localized_ipae", profile_name, argument)

    def _cmd_ipae_live(self, argument: str = "") -> None:
        dispatch_poll_command("scp11.eim_local", "IPAE-LIVE", self, argument)

    def _cmd_ipae_test(self, argument: str = "") -> None:
        dispatch_poll_command("scp11.eim_local", "IPAE-TEST", self, argument)

    def _cmd_poll_campaign(self, argument: str = "") -> None:
        parts, output_mode = self._parse_output_mode_argument(argument)
        until_empty = False
        max_cycles = None
        filtered: list[str] = []
        index = 0
        while index < len(parts):
            part = parts[index]
            if part.strip().lower() == "--until-empty":
                until_empty = True
                index += 1
                continue
            if part.strip().lower() == "--max-cycles":
                if index + 1 >= len(parts):
                    raise ValueError("POLL-CAMPAIGN --max-cycles requires an integer value.")
                max_cycles = int(parts[index + 1], 10)
                index += 2
                continue
            filtered.append(part)
            index += 1
        cycles = 10
        interval_ms = 1000
        hotfolder_dir = ""
        if len(filtered) > 0:
            cycles = int(filtered[0], 10)
        if len(filtered) > 1:
            interval_ms = int(filtered[1], 10)
        if len(filtered) > 2:
            hotfolder_dir = " ".join(filtered[2:]).strip()
        report = self.session.poll_hotfolder_campaign(
            cycles=cycles,
            interval_ms=interval_ms,
            hotfolder_dir=hotfolder_dir,
            until_empty=until_empty,
            max_cycles=max_cycles,
        )
        if output_mode != "text":
            self._print_structured_payload(report, output_mode)
            return
        rows = report.get("rows", [])
        if isinstance(rows, list) is False:
            rows = []
        summary = report.get("summary", {})
        print(f"[+] POLL-CAMPAIGN completed: {len(rows)} cycle(s).")
        print(
            f"[*] Summary: issued={summary.get('issued_cycles', 0)} "
            f"no_package={summary.get('no_package_cycles', 0)} "
            f"errors={summary.get('error_cycles', 0)} "
            f"stop={summary.get('stop_reason', '-')}"
        )
        self._print_poll_campaign_rows(rows)

    # Short codes for well-known SGP.32 eIM package types. Anything not
    # in this map falls through verbatim so we never silently alias an
    # unexpected category.
    _POLL_CAMPAIGN_TYPE_CODES = {
        "profile_download_trigger_request": "trigger_req",
        "provide_eim_package_result": "eim_result",
        "eim_acknowledgements": "ack",
        "eim_configuration_data": "eim_cfg",
        "remove_eim_configuration_data": "eim_cfg_rm",
        "rollback_profile": "rollback",
        "enable_profile": "enable",
        "disable_profile": "disable",
        "delete_profile": "delete",
        "list_profile_info": "list_info",
        "set_nickname": "nickname",
    }

    def _compact_poll_campaign_type(self, kind: str) -> str:
        normalized = str(kind or "").strip()
        if len(normalized) == 0:
            return "-"
        return self._POLL_CAMPAIGN_TYPE_CODES.get(normalized, normalized)

    def _poll_campaign_common_base(self, rows: list[dict[str, Any]]) -> str:
        paths: list[str] = []
        for row in rows:
            if isinstance(row, dict) is False:
                continue
            candidate = str(row.get("issued_file", "") or "").strip()
            if len(candidate) == 0:
                continue
            paths.append(candidate)
        if len(paths) == 0:
            return ""
        if len(paths) == 1:
            return os.path.dirname(paths[0])
        try:
            return os.path.commonpath(paths)
        except ValueError:
            return ""

    def _print_poll_campaign_rows(self, rows: list[dict[str, Any]]) -> None:
        if len(rows) == 0:
            return
        base_path = self._poll_campaign_common_base(rows)
        if len(base_path) > 0:
            print(f"[*] Base: {base_path}")
        cycle_width = max(2, len(str(len(rows))))
        for row in rows:
            cycle = int(row.get("cycle", 0))
            cycle_cell = f"{cycle:>{cycle_width}}"
            issued = bool(row.get("issued", False))
            error_text = str(row.get("error", "")).strip()
            if issued:
                kind_code = self._compact_poll_campaign_type(str(row.get("issued_type", "")))
                length = int(row.get("issued_result_len", 0))
                file_path = str(row.get("issued_file", "") or "-")
                if len(base_path) > 0 and file_path.startswith(base_path + os.sep):
                    file_path = file_path[len(base_path) + 1:]
                print(f"    {cycle_cell}  {kind_code:<11}  {length:>4}B  {file_path}")
            else:
                code = row.get("eim_result_code")
                name = str(row.get("eim_result_name", "")).strip() or "-"
                code_text = "-" if code is None else str(code)
                print(f"    {cycle_cell}  {'no-package':<11}  {'':>4}   result={code_text} ({name})")
            if len(error_text) > 0:
                print(f"    {' ' * cycle_width}  [error] {error_text}")

    def _cmd_poll_export(self, argument: str = "") -> None:
        parts = argument.split()
        until_empty = False
        max_cycles = None
        filtered: list[str] = []
        index = 0
        while index < len(parts):
            part = parts[index]
            if part.strip().lower() == "--until-empty":
                until_empty = True
                index += 1
                continue
            if part.strip().lower() == "--max-cycles":
                if index + 1 >= len(parts):
                    raise ValueError("POLL-EXPORT --max-cycles requires an integer value.")
                max_cycles = int(parts[index + 1], 10)
                index += 2
                continue
            filtered.append(part)
            index += 1
        cycles = 10
        interval_ms = 1000
        hotfolder_dir = ""
        output_path = ""
        if len(filtered) > 0:
            maybe_int = False
            try:
                cycles = int(filtered[0], 10)
                maybe_int = True
            except ValueError:
                maybe_int = False
            if maybe_int:
                if len(filtered) > 1:
                    interval_ms = int(filtered[1], 10)
                if len(filtered) > 2:
                    hotfolder_dir = filtered[2]
                if len(filtered) > 3:
                    output_path = " ".join(filtered[3:]).strip()
            else:
                hotfolder_dir = filtered[0]
                if len(filtered) > 1:
                    output_path = " ".join(filtered[1:]).strip()
        report = self.session.poll_hotfolder_campaign(
            cycles=cycles,
            interval_ms=interval_ms,
            hotfolder_dir=hotfolder_dir,
            until_empty=until_empty,
            max_cycles=max_cycles,
        )
        saved_path = self.session.export_campaign_report(report, output_path=output_path)
        summary = report.get("summary", {})
        print("[+] Poll campaign exported.")
        print(f"    file : {saved_path}")
        print(
            f"    stats: cycles={report.get('executed_cycles', 0)} "
            f"issued={summary.get('issued_cycles', 0)} "
            f"errors={summary.get('error_cycles', 0)} "
            f"stop={summary.get('stop_reason', '-')}"
        )

    def _cmd_poll_aggregate(self, argument: str = "") -> None:
        parts, output_mode = self._parse_output_mode_argument(argument)
        do_export = False
        export_path = ""
        filtered: list[str] = []
        index = 0
        while index < len(parts):
            part = parts[index]
            lowered = part.strip().lower()
            if lowered == "--export":
                do_export = True
                if index + 1 < len(parts):
                    candidate = parts[index + 1].strip()
                    if candidate.startswith("--") is False:
                        export_path = candidate
                        index += 2
                        continue
                index += 1
                continue
            filtered.append(part)
            index += 1
        reports_dir = ""
        if len(filtered) > 0:
            reports_dir = " ".join(filtered).strip()
        report = self.session.aggregate_campaign_reports(reports_dir=reports_dir)
        if do_export:
            saved = self.session.export_aggregate_campaign_report(report, output_path=export_path)
            report["exported_path"] = saved
        if output_mode != "text":
            self._print_structured_payload(report, output_mode)
            return
        print("[+] Poll campaign aggregate:")
        print(f"    directory      : {report.get('reports_dir', '-')}")
        print(f"    campaign_count : {report.get('campaign_count', 0)}")
        print(f"    total_cycles   : {report.get('total_cycles', 0)}")
        print(f"    issued_cycles  : {report.get('total_issued_cycles', 0)}")
        print(f"    error_cycles   : {report.get('total_error_cycles', 0)}")
        stop_map = report.get("stop_reason_counts", {})
        if isinstance(stop_map, dict) and len(stop_map) > 0:
            print("    stop_reasons   :")
            for key in sorted(stop_map.keys()):
                print(f"      - {key}: {stop_map[key]}")
        if do_export:
            print(f"    exported_path  : {report.get('exported_path', '-')}")

    def _cmd_handover_set(self, argument: str = "") -> None:
        parts = argument.split()
        if len(parts) == 0:
            raise ValueError("Usage: HANDOVER-SET <transactionIdHex> [matchingId]")
        transaction_hex = parts[0]
        matching_id = ""
        if len(parts) > 1:
            matching_id = parts[1]
        handover = self.session.set_handover_transaction(transaction_hex, matching_id=matching_id)
        print("[+] Handover transaction updated.")
        print(f"    transactionId: {handover.transaction_id.hex().upper()}")
        print(f"    matchingId   : {handover.matching_id or '-'}")

    def _cmd_handover_status(self, argument: str = "") -> None:
        filtered_tokens, output_mode = self._parse_output_mode_argument(argument)
        if len(filtered_tokens) > 0:
            raise ValueError("Usage: HANDOVER-STATUS [--json|--yaml]")
        payload = self.session.handover_context()
        if output_mode != "text":
            self._print_structured_payload(payload, output_mode)
            return
        print("[+] Handover context")
        print(f"    transactionId: {payload.get('transaction_id_hex', '-') or '-'}")
        print(f"    matchingId   : {payload.get('matching_id', '-') or '-'}")
        print(f"    profile_path : {payload.get('profile_path', '-') or '-'}")
        print(f"    policy       : {payload.get('notification_policy', '-') or '-'}")
        print(f"    source       : {payload.get('source', '-') or '-'}")

    def _cmd_eim_package(self, argument: str = "") -> None:
        path_text = argument.strip()
        if len(path_text) == 0:
            print(f"[+] Active eIM package: {self.session.resolve_eim_package_path()}")
            return
        print(f"[+] eIM package override: {self.session.set_eim_package_override_path(path_text)}")

    def _cmd_eim_package_clear(self, _: str = "") -> None:
        self.session.clear_eim_package_override_path()
        print("[+] eIM package override cleared.")

    def _cmd_eim_package_lint(self, argument: str = "") -> None:
        package_path, strict_exec, output_mode = self._parse_package_report_argument(
            argument
        )
        report = self.session.lint_eim_package(package_path=package_path, strict_executable=strict_exec)
        if output_mode != "text":
            self._print_structured_payload(report, output_mode)
        else:
            self._render_eim_package_lint_report(report)
        errors = report.get("errors", [])
        if len(errors) > 0:
            raise RuntimeError("eIM package lint reported errors.")

    def _cmd_eim_package_explain(self, argument: str = "") -> None:
        package_path, strict_exec, output_mode = self._parse_package_report_argument(
            argument
        )
        payload = self._build_eim_package_explain_payload(
            package_path=package_path,
            strict_exec=strict_exec,
        )
        if output_mode != "text":
            self._print_structured_payload(payload, output_mode)
            return
        self._render_eim_package_explain_text(payload)

    def _cmd_eim_package_issue(self, argument: str = "") -> None:
        package_path = argument.strip()
        package_file, package_type, result_len = self.session.issue_eim_package_file(package_path=package_path)
        print("[+] eIM package issued.")
        print(f"    file: {package_file}")
        print(f"    type: {package_type}")
        print(f"    result_len: {result_len}")

    def _cmd_eim_package_issue_all(self, argument: str = "") -> None:
        target_dir = argument.strip()
        results = self.session.issue_all_eim_package_files(package_dir=target_dir)
        print(f"[+] Issued {len(results)} package file(s).")
        for package_file, package_type, result_len in results:
            if result_len < 0:
                print(f"    - {package_type:<18} {'FAIL':>5}       {package_file}")
            else:
                print(f"    - {package_type:<18} {result_len:>5} bytes  {package_file}")

    def _cmd_eim_certs(self, argument: str = "") -> None:
        filtered_parts, output_mode = self._parse_output_mode_argument(argument)
        if len(filtered_parts) > 2:
            raise ValueError("Usage: EIM-CERTS [--json|--yaml] [packagePath] [certPath]")
        package_path = ""
        cert_path = ""
        if len(filtered_parts) > 0:
            first = filtered_parts[0].strip()
            if self._looks_like_json_path(first):
                package_path = first
            else:
                cert_path = first
        if len(filtered_parts) > 1:
            second = filtered_parts[1].strip()
            if len(package_path) == 0 and self._looks_like_json_path(second):
                package_path = second
            elif len(cert_path) == 0:
                cert_path = second
            else:
                package_path = second
        payload = self.session.list_eim_certificate_inventory(
            package_path=package_path,
            cert_path=cert_path,
        )
        if output_mode != "text":
            self._print_structured_payload(payload, output_mode)
            return
        print(f"[+] eIM signing certificate inventory ({payload.get('count', 0)} candidate(s)).")
        card_allowed = payload.get("card_allowed_ci_pkids", [])
        if isinstance(card_allowed, list) and len(card_allowed) > 0:
            print(f"    card_ci   : {', '.join(str(value) for value in card_allowed)}")
        else:
            print("    card_ci   : -")
        selected = payload.get("selected", {})
        if isinstance(selected, dict):
            print(f"    selected  : {selected.get('path', '-') or '-'}")
            print(f"    rule      : {selected.get('reason', '-') or '-'}")
            selected_ci = selected.get("root_ci_pkids", [])
            if isinstance(selected_ci, list) and len(selected_ci) > 0:
                print(f"    selected_ci: {', '.join(str(value) for value in selected_ci)}")
        rows = payload.get("rows", [])
        if isinstance(rows, list) is False or len(rows) == 0:
            return
        for index, row in enumerate(rows[:12], start=1):
            path = str(row.get("path", "")).strip() or "-"
            source = str(row.get("source", "")).strip() or "-"
            curve = str(row.get("curve", "")).strip() or "-"
            root_ci = row.get("root_ci_pkids", [])
            root_text = "-"
            if isinstance(root_ci, list) and len(root_ci) > 0:
                root_text = ",".join(str(value) for value in root_ci)
            print(f"    [{index}] source={source} curve={curve} ci={root_text}")
            print(f"         {path}")

    def _cmd_hotfolder(self, argument: str = "") -> None:
        path_text = argument.strip()
        if len(path_text) == 0:
            print(f"[+] Active hotfolder: {self.session.resolve_hotfolder_path()}")
            return
        print(f"[+] Hotfolder override: {self.session.set_hotfolder_override_path(path_text)}")

    def _cmd_hotfolder_clear(self, _: str = "") -> None:
        self.session.clear_hotfolder_override_path()
        print("[+] Hotfolder override cleared.")

    def _cmd_hotfolder_list(self, argument: str = "") -> None:
        filtered_parts, output_mode = self._parse_output_mode_argument(argument)
        target_dir = " ".join(filtered_parts).strip()
        rows = self.session.list_hotfolder_preview(hotfolder_dir=target_dir)
        if output_mode != "text":
            payload = {
                "hotfolder_dir": self.session.resolve_hotfolder_path(override_path=target_dir),
                "count": len(rows),
                "rows": rows,
            }
            self._print_structured_payload(payload, output_mode)
            return
        if len(rows) == 0:
            print("[*] Effective poll queue is empty.")
            return
        print(f"[+] Effective poll queue preview ({len(rows)} file(s)):")
        for row in rows:
            order = int(row.get("order", 0))
            queue_order = int(row.get("queue_order", 0))
            queue_source = str(row.get("queue_source", "")).strip()
            session_source = str(row.get("session_source", "")).strip() or "-"
            package_type = str(row.get("package_type", "")).strip() or "-"
            txid = str(row.get("transaction_id_hex", "")).strip() or "-"
            matching_id = str(row.get("matching_id", "")).strip() or "-"
            queue_id = row.get("queue_id")
            path = str(row.get("path", "")).strip()
            error_text = str(row.get("error", "")).strip()
            queue_id_text = "-"
            if isinstance(queue_id, int) and queue_id > 0:
                queue_id_text = str(queue_id)
            print(
                f"    {order:>2}. origin={session_source:<22} order={queue_order:<12} "
                f"source={queue_source:<28} "
                f"qid={queue_id_text:<8} type={package_type:<36} txid={txid:<34} mid={matching_id}"
            )
            print(f"        {path}")
            if len(error_text) > 0:
                print(f"        [error] {error_text}")

    def _cmd_hotfolder_poll(self, argument: str = "") -> None:
        filtered_parts, output_mode = self._parse_output_mode_argument(argument)
        target_dir = " ".join(filtered_parts).strip()
        payload = self.session.hotfolder_poll_metadata(hotfolder_dir=target_dir)
        if output_mode != "text":
            self._print_structured_payload(payload, output_mode)
            return
        print("[+] Hotfolder poll metadata")
        print(f"    hotfolder_dir   : {payload.get('hotfolder_dir', '-')}")
        print(f"    queue_count     : {payload.get('queue_count', 0)}")
        print(f"    eim_result_code : {payload.get('eim_result_code', '-')}")
        print(f"    eim_result_name : {payload.get('eim_result_name', '-')}")
        print(f"    response_tlv_hex: {payload.get('response_tlv_hex', '-')}")

    def _cmd_hotfolder_fetch(self, argument: str = "") -> None:
        filtered_parts, output_mode = self._parse_output_mode_argument(argument)
        target_dir = " ".join(filtered_parts).strip()
        poll_meta = self.session.hotfolder_poll_response_meta(hotfolder_dir=target_dir)
        eim_result_code = poll_meta.get("eim_result_code")
        if eim_result_code == self.cfg.EIM_NO_PACKAGE_RESULT_CODE:
            response_tlv_hex = str(poll_meta.get("response_tlv_hex", "")).strip().upper()
            self.session.issue_hotfolder_packages(hotfolder_dir=target_dir)
            if output_mode != "text":
                payload = {
                    "hotfolder_dir": self.session.resolve_hotfolder_path(override_path=target_dir),
                    "summary": {
                        "total": 0,
                        "success": 0,
                        "failure": 0,
                        "no_package_result": True,
                    },
                    "result": {
                        "eim_result_code": eim_result_code,
                        "eim_result_name": poll_meta.get("eim_result_name"),
                        "response_tlv_hex": response_tlv_hex,
                    },
                    "rows": [],
                }
                self._print_structured_payload(payload, output_mode)
                return
            print("[*] Effective poll queue is empty.")
            print("[*] eIM response to card: noEimPackageAvailable(1) per SGP.32 GetEimPackageResponse.")
            if len(response_tlv_hex) > 0:
                print(f"    TLV: {response_tlv_hex}")
            return
        results = self.session.issue_hotfolder_packages(hotfolder_dir=target_dir)
        summary = self.session.summarize_issue_results(results)
        if output_mode != "text":
            rows: list[dict[str, Any]] = []
            for package_file, package_type, result_len in results:
                rows.append(
                    {
                        "file": package_file,
                        "type": package_type,
                        "result_len": int(result_len),
                        "success": int(result_len) >= 0 and str(package_type).startswith("error:") is False,
                    }
                )
            payload = {
                "hotfolder_dir": self.session.resolve_hotfolder_path(override_path=target_dir),
                "summary": summary,
                "rows": rows,
            }
            self._print_structured_payload(payload, output_mode)
            return
        print(f"[+] Effective poll queue fetched {len(results)} package file(s).")
        print(
            f"[*] Summary: total={summary.get('total', 0)} "
            f"success={summary.get('success', 0)} "
            f"failure={summary.get('failure', 0)}"
        )
        for package_file, package_type, result_len in results:
            if result_len < 0:
                print(f"    - {package_type:<24} {'FAIL':>5}       {package_file}")
            else:
                print(f"    - {package_type:<24} {result_len:>5} bytes  {package_file}")

    def _cmd_add_initial_eim(self, argument: str = "") -> None:
        source_mode, cert, package = self._parse_add_eim_args(argument)
        response = self.session.add_initial_eim(
            cert_path=cert,
            package_path=package,
            source_mode=source_mode,
        )
        print(f"[+] AddInitialEim completed ({len(response)} bytes).")
        print(f"    {self._hex_preview(response)}")
        self._print_selected_eim_certificate()
        self._invalidate_poll_target_cache()

    def _cmd_add_eim(self, argument: str = "") -> None:
        source_mode, cert, package = self._parse_add_eim_args(argument)
        response = self.session.add_eim(
            cert_path=cert,
            package_path=package,
            source_mode=source_mode,
        )
        print(f"[+] AddEim completed ({len(response)} bytes).")
        print(f"    {self._hex_preview(response)}")
        self._print_selected_eim_certificate()
        self._invalidate_poll_target_cache()

    def _cmd_isdr_add_initial_eim(self, argument: str = "") -> None:
        source_mode, cert, package = self._parse_isdr_add_args(
            argument,
            expected_types=("add_initial_eim", "addinitialeim"),
            usage="Usage: ISDR-ADD-INITIAL-EIM [certPath] [packagePath]",
        )
        response = self.session.add_initial_eim(
            cert_path=cert,
            package_path=package,
            source_mode=source_mode,
        )
        transport = "local_auth" if source_mode == "isdr" else "local_auth + package"
        self._print_command_response(
            "ISDR AddInitialEim",
            response,
            transport=transport,
        )
        self._print_selected_eim_certificate()
        self._invalidate_poll_target_cache()
        self._print_post_eim_configuration_snapshot()

    def _cmd_isdr_add_eim(self, argument: str = "") -> None:
        source_mode, cert, package = self._parse_isdr_add_args(
            argument,
            expected_types=("add_eim", "addeim"),
            usage="Usage: ISDR-ADD-EIM [certPath] [packagePath]",
        )
        response = self.session.add_eim(
            cert_path=cert,
            package_path=package,
            source_mode=source_mode,
        )
        transport = "local_auth" if source_mode == "isdr" else "local_auth + package"
        self._print_command_response(
            "ISDR AddEim",
            response,
            transport=transport,
        )
        self._print_selected_eim_certificate()
        self._invalidate_poll_target_cache()
        self._print_post_eim_configuration_snapshot()

    def _cmd_euicc_memory_reset(self, argument: str = "") -> None:
        package_path = self._parse_euicc_memory_reset_args(argument)
        response = self.session.euicc_memory_reset(package_path=package_path)
        self._print_command_response(
            "ISDR eUICCMemoryReset",
            response,
            transport="isdr_store_data",
        )
        print(f"    package   : {package_path}")
        self._queue_modem_refresh("eUICCMemoryReset")
        self._invalidate_poll_target_cache()
        self._print_post_eim_configuration_snapshot(
            title="ISDR post-reset GetEimConfigurationData",
        )

    def _cmd_load_eim_package(self, argument: str = "") -> None:
        package_path, cert_path = self._parse_load_eim_package_args(argument)
        report = self.session.load_eim_package_to_isdr(
            package_path=package_path,
            cert_path=cert_path,
        )
        print("[+] LOAD-EIM-PACKAGE completed.")
        print(f"    file      : {report.get('package_path', '-')}")
        print(f"    type      : {report.get('package_type', '-')}")
        print(f"    path      : {report.get('execution_path', '-')}")
        print(f"    transport : {report.get('transport', '-')}")
        print(f"    bytes     : {report.get('result_len', 0)}")
        print(f"    response  : {report.get('response_preview_hex', '-')}")
        print(f"    cert_path : {report.get('selected_cert_path', '-') or '-'}")
        print(f"    cert_rule : {report.get('selected_cert_reason', '-') or '-'}")
        selected_ci = report.get("selected_cert_root_ci_pkids", [])
        if isinstance(selected_ci, list) and len(selected_ci) > 0:
            print(f"    cert_ci   : {', '.join(str(value) for value in selected_ci)}")
        package_type = str(report.get("package_type", "")).strip().lower()
        if package_type in (
            "add_initial_eim",
            "addinitialeim",
            "add_eim",
            "addeim",
            "euicc_memory_reset",
        ):
            self._invalidate_poll_target_cache()
            self._print_post_eim_configuration_snapshot()

    def _cmd_eim_acknowledge(self, argument: str = "") -> None:
        parts = argument.split()
        txid = ""
        matching_id = ""
        if len(parts) > 0:
            txid = parts[0]
        if len(parts) > 1:
            matching_id = parts[1]
        closed = self.session.acknowledge_eim_operations(
            transaction_id_hex=txid,
            matching_id=matching_id,
        )
        print(f"[+] eIM acknowledge completed. closed={closed}")

    def _cmd_error_codes(self, argument: str = "") -> None:
        target = argument.strip().upper()
        if len(target) == 0:
            target = "ALL"

        tables: list[tuple[str, dict[int, str]]] = []
        if target in ("ALL", "SGP.22", "SGP22"):
            tables.append(("SGP.22 DownloadErrorCode", SGP22_DOWNLOAD_ERROR_CODE))
            tables.append(("SGP.22 ES10b ProfileState Result", SGP22_ES10B_PROFILE_STATE_RESULT))
            tables.append(
                ("SGP.22 ProfileInstallationResultErrorReason", SGP22_PROFILE_INSTALLATION_RESULT_REASON)
            )
        if target in ("ALL", "SGP.32", "SGP32"):
            tables.append(("SGP.32 GetEimPackage eimPackageError", SGP32_EIM_PACKAGE_ERROR))
            tables.append(
                ("SGP.32 ProvideEimPackageResult eimPackageResultErrorCode", SGP32_EIM_PACKAGE_RESULT_ERROR)
            )
            tables.append(
                ("SGP.32 ProfileDownloadTriggerResult profileDownloadErrorReason", SGP32_PROFILE_DOWNLOAD_ERROR_REASON)
            )
        if target in ("ALL", "SGP.02", "SGP02"):
            tables.append(("SGP.02 mapped to profile installation semantics", SGP22_PROFILE_INSTALLATION_RESULT_REASON))

        if len(tables) == 0:
            raise ValueError("Usage: ERROR-CODES [SGP.02|SGP.22|SGP.32|ALL]")

        for title, mapping in tables:
            print(f"\n[{title}]")
            for code in sorted(mapping.keys()):
                name = mapping.get(code, "unknown")
                print(f"  {code:>3} -> {name}")

    def _cmd_error_code_set(self, argument: str = "") -> None:
        parts = argument.split()
        if len(parts) < 2:
            raise ValueError(
                "Usage: ERROR-CODE-SET <family> <code> [packagePath]\n"
                "Families: sgp32_eim_package_result_error | "
                "sgp32_profile_download_error_reason | sgp22_profile_state_result"
            )
        family = parts[0].strip()
        code_value = parts[1].strip()
        package_path = ""
        if len(parts) > 2:
            package_path = parts[2].strip()
        payload = self.session.set_error_code_in_package(
            family=family,
            code_value=code_value,
            package_path=package_path,
        )
        print("[+] ERROR-CODE-SET applied.")
        print(f"    file   : {payload.get('package_path', '-')}")
        print(f"    family : {payload.get('family', '-')}")
        print(f"    code   : {payload.get('resolved_name', '-')} [{payload.get('resolved_code', '-')}]")
        for path_text in payload.get("updated_paths", []):
            print(f"    updated: {path_text}")

    def _cmd_counters(self, _: str = "") -> None:
        runtime_state = self.session.runtime_state_summary()
        counter_map = runtime_state.get("counter_by_eim_id", {})
        if isinstance(counter_map, dict) is False or len(counter_map) == 0:
            print("[*] No counters tracked yet.")
            return
        print("[+] Tracked eIM counters:")
        for eim_id in sorted(counter_map.keys()):
            print(f"    - {eim_id}: next={counter_map.get(eim_id)}")

    def _cmd_counter(self, argument: str = "") -> None:
        parts = argument.split()
        if len(parts) == 0:
            identity = self.session.identity_summary()
            default_id = str(identity.get("eim_id", "")).strip()
            if len(default_id) == 0:
                default_id = "default"
            eim_id, value = self.session.get_counter_value(default_id)
            print(f"[+] Counter next value: eimId={eim_id} next={value}")
            print("[*] Usage: COUNTER <eimId> [set <n>]")
            print("[*] Shortcut: COUNTER set <n>  (uses active identity eim_id)")
            return
        if len(parts) == 2 and parts[0].strip().lower() == "set":
            try:
                next_value = int(parts[1].strip(), 10)
            except ValueError:
                raise ValueError("COUNTER set value must be a positive integer.")
            if next_value <= 0:
                raise ValueError("COUNTER set value must be a positive integer.")
            identity = self.session.identity_summary()
            target_eim_id = str(identity.get("eim_id", "")).strip()
            if len(target_eim_id) == 0:
                target_eim_id = "default"
            _, value = self.session.set_counter_value(target_eim_id, next_value)
            print(f"[+] Counter override applied: eimId={target_eim_id} next={value}")
            return
        eim_id = parts[0].strip()
        if len(parts) == 1:
            _, value = self.session.get_counter_value(eim_id)
            print(f"[+] Counter next value: eimId={eim_id} next={value}")
            return
        if len(parts) == 3 and parts[1].strip().lower() == "set":
            try:
                next_value = int(parts[2].strip(), 10)
            except ValueError:
                raise ValueError("COUNTER set value must be a positive integer.")
            if next_value <= 0:
                raise ValueError("COUNTER set value must be a positive integer.")
            _, value = self.session.set_counter_value(eim_id, next_value)
            print(f"[+] Counter override applied: eimId={eim_id} next={value}")
            return
        raise ValueError("Usage: COUNTER <eimId> [set <n>] | COUNTER set <n>")

    def _parse_add_eim_args(self, argument: str) -> tuple[str, str, str]:
        parts = shlex.split(argument)
        if len(parts) == 0:
            return "package", "", ""
        source_mode = "package"
        first = parts[0].strip().lower()
        cert = ""
        package = ""
        if first in ("package", "pkg", "json", "isdr", "handshake"):
            if first in ("isdr", "handshake"):
                source_mode = "isdr"
            else:
                source_mode = "package"
            if len(parts) == 1:
                return source_mode, "", ""
            if len(parts) == 2:
                token = parts[1].strip()
                if self._looks_like_json_path(token):
                    return source_mode, "", token
                return source_mode, token, ""
            if len(parts) > 3:
                raise ValueError("Usage: ADD-INITIAL-EIM [package|isdr] [certPath] [packageJson]")
            cert = parts[1]
            package = parts[2]
            return source_mode, cert, package
        if len(parts) == 1:
            token = parts[0].strip()
            if self._looks_like_json_path(token):
                return source_mode, "", token
            return source_mode, token, ""
        cert = parts[0]
        package = parts[1]
        return source_mode, cert, package

    def _cmd_notification_hygiene(self, argument: str = "") -> None:
        max_pending = None
        value = argument.strip()
        if len(value) > 0:
            max_pending = int(value)
        pending = self.session.enforce_notification_hygiene(max_pending=max_pending)
        print(f"[+] Notification hygiene check passed. pending={pending}")

    def _cmd_response_log(self, argument: str = "") -> None:
        tokens, output_mode = self._parse_output_mode_argument(argument)
        raw = " ".join(tokens).strip()
        limit = 25
        if len(raw) > 0:
            limit = int(raw, 10)
        rows = self.session.read_response_log(limit=limit)
        if len(rows) == 0:
            print(f"[*] Response log file: {self.session.response_log_path()}")
            print("[*] No response log entries yet.")
            return
        if output_mode != "text":
            payload = {
                "response_log_file": self.session.response_log_path(),
                "count": len(rows),
                "rows": rows,
            }
            self._print_structured_payload(payload, output_mode)
            return
        print(f"[*] Response log file: {self.session.response_log_path()}")
        self._print_structured_payload(rows, "yaml")

    def _cmd_response_log_filter(self, argument: str = "") -> None:
        parts, output_mode = self._parse_output_mode_argument(argument)
        if len(parts) == 0:
            raise ValueError("Usage: RESP-LOG-FILTER <query> [limit] [--json|--yaml]")
        query = parts[0].strip()
        limit = 50
        if len(parts) > 1:
            limit = int(parts[1].strip(), 10)
        rows = self.session.filter_response_log(query=query, limit=limit)
        if len(rows) == 0:
            print(f"[*] Response log file: {self.session.response_log_path()}")
            print(f"[*] Filter query: {query}")
            print("[*] No matching response log entries.")
            return
        if output_mode != "text":
            payload = {
                "response_log_file": self.session.response_log_path(),
                "query": query,
                "count": len(rows),
                "rows": rows,
            }
            self._print_structured_payload(payload, output_mode)
            return
        print(f"[*] Response log file: {self.session.response_log_path()}")
        print(f"[*] Filter query: {query}")
        self._print_structured_payload(rows, "yaml")

    def _cmd_response_log_clear(self, _: str = "") -> None:
        count = self.session.clear_response_log()
        print(f"[+] Response log cleared. removed_lines={count}")

    def _cmd_exit(self, _: str = "") -> None:
        self._stop_poll_bridge()
        if self.session.state.session_open:
            try:
                self.session.close_session()
            except Exception:
                pass
        raise SystemExit(0)

    def _cmd_quit_all(self, _: str = "") -> None:
        self._stop_poll_bridge()
        if self.session.state.session_open:
            try:
                self.session.close_session()
            except Exception:
                pass
        quit_all()

    @staticmethod
    def _split_batch_commands(cmd_line: str) -> list[str]:
        commands: list[str] = []
        for raw_command in str(cmd_line or "").split(";"):
            command_text = str(raw_command or "").strip()
            if len(command_text) == 0:
                continue
            commands.append(command_text)
        return commands

    @staticmethod
    def _commands_with_internal_debug_flags() -> set[str]:
        return {
            "IPAD-LIVE",
            "IPAD-TEST",
            "IPAE-LIVE",
            "IPAE-TEST",
        }

    @staticmethod
    def _strip_debug_flag_from_argument(argument: str) -> tuple[str, bool]:
        tokens = shlex.split(argument or "")
        filtered_tokens: list[str] = []
        debug = False
        for token in tokens:
            normalized = str(token or "").strip().lower()
            if normalized in ("--debug", "-d"):
                debug = True
                continue
            filtered_tokens.append(str(token))
        if len(filtered_tokens) == 0:
            return "", debug
        return shlex.join(filtered_tokens), debug

    def _set_transport_debug(self, enabled: bool) -> Optional[bool]:
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
        if previous is None:
            return
        apdu_channel = getattr(self.session, "apdu_channel", None)
        setter = getattr(apdu_channel, "set_raw_apdu_logging", None)
        if callable(setter):
            setter(bool(previous))

    @staticmethod
    def _render_command_line(command: str, argument: str = "") -> str:
        normalized_command = str(command or "").strip()
        normalized_argument = str(argument or "").strip()
        if len(normalized_command) == 0:
            return ""
        if len(normalized_argument) == 0:
            return normalized_command
        return f"{normalized_command} {normalized_argument}"

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

    def _cmd_record(self, argument: str = "") -> None:
        parts = shlex.split(argument or "")
        if len(parts) == 0 or parts[0].strip().upper() == "STATUS":
            self._print_record_status()
            return
        action = parts[0].strip().upper()
        output_path = ""
        if len(parts) > 1:
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

    def _execute_command_line(self, raw_line: str, *, source: str = "interactive") -> bool:
        parts = str(raw_line or "").strip().split(maxsplit=1)
        if len(parts) == 0:
            return True
        command = parts[0].upper()
        argument = ""
        if len(parts) > 1:
            argument = parts[1].strip()
        canonical_command = self._canonical_command(command)
        debug = False
        previous_debug = None
        if canonical_command not in self._commands_with_internal_debug_flags():
            argument, debug = self._strip_debug_flag_from_argument(argument)
            if debug:
                previous_debug = self._set_transport_debug(True)
        command_record: Optional[dict[str, Any]] = None
        if canonical_command != "RECORD":
            command_record = self._recorder.begin_command(
                raw_command=str(raw_line or "").strip(),
                canonical_command=canonical_command or command,
                replay_command=self._render_command_line(canonical_command or command, argument),
                debug_enabled=debug,
                source=source,
            )
        handler = self._commands.get(canonical_command)
        if handler is None:
            print(f"[-] Unknown command: {command}")
            candidates = [name for name in sorted(self._commands.keys()) if name.startswith(command[:3])]
            if len(candidates) > 0:
                print(f"[*] Did you mean: {', '.join(candidates[:6])}")
            print("[*] Use HELP or HELP <command>.")
            if command_record is not None:
                self._recorder.finish_command(
                    command_record,
                    success=False,
                    error=f"Unknown command: {command}",
                )
            self._restore_transport_debug(previous_debug)
            return True
        try:
            handler(argument)
        except SystemExit:
            if command_record is not None:
                self._recorder.finish_command(command_record, success=True)
                command_record = None
            print("[*] Leaving eIM local shell.")
            return False
        except QuitAllRequested:
            if command_record is not None:
                self._recorder.finish_command(command_record, success=True)
                command_record = None
            raise
        except ValueError as error:
            if command_record is not None:
                self._recorder.finish_command(
                    command_record,
                    success=False,
                    error=str(error),
                )
                command_record = None
            print(f"[-] {error}")
            self._show_command_help(canonical_command or command)
            return True
        except Exception as error:
            if command_record is not None:
                self._recorder.finish_command(
                    command_record,
                    success=False,
                    error=str(error),
                )
                command_record = None
            print(f"[-] {error}")
            return True
        finally:
            self._restore_transport_debug(previous_debug)
        if command_record is not None:
            self._recorder.finish_command(command_record, success=True)
        return True

    def run(self) -> None:
        """Start the interactive eIM-local operator REPL."""
        self._setup_readline()
        self._print_banner()
        self._cmd_help()
        try:
            while True:
                try:
                    raw_line = input(
                        f"\n{ShellStyle.HEADER}[Local eIM] > {ShellStyle.END}"
                    ).strip()
                except EOFError:
                    raw_line = "EXIT"
                except KeyboardInterrupt:
                    print("")
                    raw_line = "EXIT"

                if len(raw_line) == 0:
                    continue
                keep_running = self._execute_command_line(raw_line, source="interactive")
                if keep_running is False:
                    return
        finally:
            self._finalize_recording_on_exit()

    def run_commands(self, cmd_line: str) -> None:
        """Execute a semicolon-delimited command string non-interactively."""
        try:
            for raw_command in self._split_batch_commands(cmd_line):
                keep_running = self._execute_command_line(raw_command, source="batch")
                if keep_running is False:
                    break
        finally:
            self._finalize_recording_on_exit()


def entry() -> None:
    ensure_plugins_loaded()
    shell = EimLocalShell()
    shell.run()


def entry_cmd(cmd_line: str) -> None:
    ensure_plugins_loaded()
    shell = EimLocalShell()
    shell.run_commands(cmd_line)


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
    """Start the eIM-local shell as a standalone process entry point."""
    ensure_plugins_loaded()
    parser = argparse.ArgumentParser(description="SCP11 local eIM shell")
    add_debug_argument(
        parser,
        help_text="Enable verbose debug output for this local eIM session.",
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
    args = parser.parse_args()
    set_global_debug(bool(getattr(args, "debug", False)))
    if args.cmd:
        entry_cmd(args.cmd)
        return
    if args.stdin:
        entry_stdin()
        return
    shell = EimLocalShell()
    shell.run()


if __name__ == "__main__":
    try:
        run_standalone()
    except QuitAllRequested:
        sys.exit(0)
    except EimLocalStartupError as error:
        print(f"[STARTUP ERROR] {error}")
        sys.exit(1)
