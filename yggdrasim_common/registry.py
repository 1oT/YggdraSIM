# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""Plugin registry: maps capability tokens to provider callables and enforces single-registration invariants."""
# -----------------------------------------------------------------------------
# YggdraSIM code registry: locate entry points, classes, and callables without
# walking the tree. Symbols resolve via importlib (lazy; nothing heavy at import).
#
# Usage (editable-installed, or repository root on sys.path):
#   from yggdrasim_common.registry import get, search, resolve, REPO_ROOT
#   fn = get("main.launcher.scp03")
#   for key, target in search("orchestrator"):
#       print(key, "->", target)
#
# Extend SYMBOL_REGISTRY when you add stable public APIs worth discovering.
# -----------------------------------------------------------------------------

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from typing import Any, Callable, Iterator

REPO_ROOT: Path = Path(__file__).resolve().parent.parent

# Human-oriented map: short name -> one-line description.
SUBSYSTEMS: dict[str, str] = {
    "main": "Top-level menu launcher, path setup, and in-process dispatch to SCP03/80/11/Tools.",
    "SCP03": "GlobalPlatform-style admin shell, card transport, TLV/CAP decoders, SGP.22 helpers.",
    "SCP80": "OTA SMS-SC / CAT-TP style scripting and smart decoding.",
    "SCP11": "Thin facade; live SGP.22 types re-exported from SCP11.live.",
    "SCP11.live": "eSIM management relay: orchestrator, PC/SC or relay APDU, ES9+, STK/proactive handling.",
    "SCP11.relay": "Compatibility SCP11 entry point built on direct PC/SC.",
    "SCP11.local_access": "Local ISD-R / metadata codec / certificate helpers for on-card flows.",
    "SCP11.eim_local": "eIM-local package authoring, hotfolders, handover, and direct-card tooling.",
    "SCP11.shared": "Cross-flavour crypto, transport helpers, ASN.1 registry, GSMA error codes.",
    "Tools.CardBridge": "Loopback PC/SC-to-HTTP APDU bridge for SSH-forwarded remote-card workflows.",
    "Tools.ProfilePackage": "SAIP / UPP shell, saip-tool bridge, lint engine, JSON↔DER transcode.",
    "Tools.SuciTool": "SUCI-related helper shell.",
    "gui_server": "Optional universal GUI layer: FastAPI API + pywebview desktop window + headless lab server.",
    "tests": "pytest modules under tests/ (not registered as symbols; discover by filename).",
    "pysim": "Optional on-disk pySim checkout (upstream osmocom, gitignored). Clone https://gitlab.com/osmocom/pysim.git when the SAIP ASN.1 compile / SCP11-local flows are needed; prefer Tools.ProfilePackage for SAIP glue.",
}

# Runnable packages (python -m … after editable install, or from repo root).
CLI_MODULES: list[str] = [
    "SCP03",
    "SCP80",
    "SCP11",
    "SCP11.live",
    "SCP11.relay",
    "SCP11.local_access",
    "SCP11.eim_local",
    "Tools.CardBridge",
    "Tools.ProfilePackage",
    "Tools.SuciTool",
]

# registry_key -> "dotted.module.path:AttributeName"
SYMBOL_REGISTRY: dict[str, str] = {
    # --- main launcher (main/main.py) ---
    "main.launcher.menu": "main.main:main_menu",
    "main.launcher.setup_paths": "main.main:setup_paths",
    "main.launcher.scp03": "main.main:run_scp03",
    "main.launcher.scp03_script": "main.main:run_scp03_script",
    "main.launcher.scp03_report": "main.main:run_scp03_report",
    "main.launcher.scp03_cmd": "main.main:run_scp03_cmd",
    "main.launcher.scp80": "main.main:run_scp80",
    "main.launcher.scp80_script": "main.main:run_scp80_script",
    "main.launcher.scp11_live": "main.main:run_scp11_live",
    "main.launcher.scp11_local": "main.main:run_scp11_local",
    "main.launcher.scp11_eim_local": "main.main:run_scp11_eim_local",
    "main.launcher.profile_package": "main.main:run_profile_package",
    "main.launcher.suci_tool": "main.main:run_suci_tool",
    "main.colors": "main.main:Colors",
    # --- SCP03 ---
    "scp03.entry": "SCP03.main:entry",
    "scp03.entry_cmd": "SCP03.main:entry_cmd",
    "scp03.run_standalone": "SCP03.main:run_standalone",
    "scp03.run_script": "SCP03.main:run_script",
    "scp03.shell.dispatcher": "SCP03.interface.shell:ShellDispatcher",
    "scp03.commands.registry": "SCP03.interface.commands:CommandRegistry",
    "scp03.wizards": "SCP03.interface.wizards:InteractiveWizards",
    "scp03.help_menu": "SCP03.interface.help_menu:HelpMenu",
    "scp03.guides": "SCP03.interface.guides:ShellGuides",
    "scp03.transport.card": "SCP03.transport.card:CardTransporter",
    "scp03.logic.gp": "SCP03.logic.gp:GlobalPlatformManager",
    "scp03.logic.security": "SCP03.logic.security:SecurityController",
    "scp03.logic.fs": "SCP03.logic.fs:FileSystemController",
    "scp03.logic.sgp22": "SCP03.logic.sgp22:Sgp22Manager",
    "scp03.logic.euicc_info2.build_detail": "SCP03.logic.euicc_info2:build_euicc_info2_detail_lines",
    "scp03.logic.euicc_info2.build_validation": "SCP03.logic.euicc_info2:build_euicc_info2_validation_lines",
    "scp03.logic.profile_validator": "SCP03.logic.profile_validator:ProfileValidator",
    "scp03.core.decoders.advanced": "SCP03.core.decoders:AdvancedDecoders",
    "scp03.core.decoders.content": "SCP03.core.decoders:ContentDecoder",
    "scp03.core.cap.parser": "SCP03.core.cap:CapFileParser",
    "scp03.core.utils.hex": "SCP03.core.utils:HexUtils",
    "scp03.core.utils.tlv": "SCP03.core.utils:TlvParser",
    "scp03.core.utils.sw": "SCP03.core.utils:StatusWordTranslator",
    # --- SCP80 ---
    "scp80.run_standalone": "SCP80.main:run_standalone",
    "scp80.cli.shell": "SCP80.cli:OtaShell",
    "scp80.cli.decoder": "SCP80.cli:SmartDecoder",
    "scp80.builder": "SCP80.builder:OtaPacketBuilder",
    "scp80.crypto": "SCP80.crypto:CryptoEngine",
    "scp80.transport": "SCP80.transport:Transport",
    # --- SCP11 package root (lazy exports) ---
    "scp11.config": "SCP11.live.config:SGPConfig",
    "scp11.orchestrator": "SCP11.live.orchestrator:SGP22Orchestrator",
    # --- SCP11 live ---
    "scp11.live.entry": "SCP11.live.main:entry",
    "scp11.live.orchestrator": "SCP11.live.orchestrator:SGP22Orchestrator",
    "scp11.live.config": "SCP11.live.config:SGPConfig",
    "scp11.live.console": "SCP11.live.console:SCP11Console",
    "scp11.live.transport.pcsc": "SCP11.live.transport:PcscApduChannel",
    "scp11.live.transport.sgp22": "SCP11.live.transport:SGP22Transport",
    "scp11.live.factory.apdu": "SCP11.live.factory:build_apdu_channel",
    "scp11.live.factory.profile": "SCP11.live.factory:build_profile_provider",
    "scp11.live.es9_client": "SCP11.live.es9_client:Es9LikeClient",
    "scp11.live.crypto_engine": "SCP11.live.crypto_engine:CryptoEngine",
    "scp11.live.payload_builder": "SCP11.live.payload_builder:PayloadBuilder",
    "scp11.live.asn1_registry": "SCP11.live.asn1_registry:ASN1Registry",
    "scp11.live.eim_packages": "SCP11.live.eim_packages:ParsedEimPackage",
    # --- SCP11 relay ---
    "scp11.relay.entry": "SCP11.relay.main:entry",
    "scp11.relay.orchestrator": "SCP11.relay.orchestrator:SGP22Orchestrator",
    "scp11.relay.console": "SCP11.relay.console:SCP11Console",
    "scp11.relay.factory.apdu": "SCP11.relay.factory:build_apdu_channel",
    # --- SCP11 local access ---
    "scp11.local_access.entry": "SCP11.local_access.main:entry",
    "scp11.local_access.session": "SCP11.local_access.session:LocalIsdrSession",
    "scp11.local_access.config": "SCP11.local_access.config:LocalAccessConfig",
    "scp11.local_access.metadata.build_store": "SCP11.local_access.metadata_codec:build_store_metadata_request_payload",
    "scp11.local_access.metadata.build_update": "SCP11.local_access.metadata_codec:build_update_metadata_request_payload",
    "scp11.local_access.payload_diff": "SCP11.local_access.payload_diff:build_tlv_ranges",
    "scp11.local_access.cert_store": "SCP11.local_access.cert_store:LocalSgp26CertStore",
    # --- SCP11 eim local ---
    "scp11.eim_local.entry": "SCP11.eim_local.main:entry",
    "scp11.eim_local.session": "SCP11.eim_local.session:EimLocalSession",
    "scp11.eim_local.package_lint": "SCP11.eim_local.eim_package_codec:lint_eim_package_document",
    "scp11.eim_local.handover_context": "SCP11.eim_local.models:EimHandoverContext",
    # --- SCP11 shared ---
    "scp11.shared.crypto_engine": "SCP11.shared.crypto_engine:CryptoEngine",
    "scp11.shared.payload_builder": "SCP11.shared.payload_builder:PayloadBuilder",
    "scp11.transport.sgp22": "SCP11.transport:SGP22Transport",
    "scp11.asn1_registry": "SCP11.asn1_registry:ASN1Registry",
    "scp11.shared.gsma_es10b_results": "SCP11.shared.gsma_error_codes:SGP22_ES10B_PROFILE_STATE_RESULT",
    "scp11.pysim_support.decode_rsp": "SCP11.pysim_support:decode_rsp_type",
    "scp11.pysim_support.caki": "SCP11.pysim_support:get_certificate_authority_key_identifier",
    # --- Tools.ProfilePackage (SAIP) ---
    "tools.profile.entry": "Tools.ProfilePackage.main:entry",
    "tools.profile.entry_cmd": "Tools.ProfilePackage.main:entry_cmd",
    "tools.profile.run_standalone": "Tools.ProfilePackage.main:run_standalone",
    "tools.profile.shell": "Tools.ProfilePackage.shell:ProfilePackageShell",
    "tools.profile.saip_bridge": "Tools.ProfilePackage.saip_tool:SaipToolBridge",
    "tools.profile.linter": "Tools.ProfilePackage.lint_engine:SaipProfileLinter",
    "tools.profile.json.encode_der": "Tools.ProfilePackage.saip_json_codec:encode_der_from_document",
    "tools.profile.json.parse": "Tools.ProfilePackage.saip_json_codec:parse_editor_json",
    "tools.profile.json.document_pretty": "Tools.ProfilePackage.saip_json_codec:document_to_pretty_json",
    "tools.profile.json.build_pes": "Tools.ProfilePackage.saip_json_codec:build_profile_sequence_from_document",
    "tools.profile.transcode_tui": "Tools.ProfilePackage.saip_transcode_tui:run_saip_transcode_tui",
    # --- Tools.SuciTool ---
    "tools.suci.entry": "Tools.SuciTool.main:entry",
    "tools.suci.entry_cmd": "Tools.SuciTool.main:entry_cmd",
    "tools.suci.run_standalone": "Tools.SuciTool.main:run_standalone",
    # --- Universal GUI (optional) ---
    # These targets only resolve when the `gui` / `gui-server` extra is
    # installed (fastapi + uvicorn, plus pywebview for desktop mode).
    # They are listed here for discoverability; importing them without
    # the extra raises ModuleNotFoundError.
    "gui.config.build_desktop": "yggdrasim_common.gui_server.config:build_desktop_config",
    "gui.config.build_server": "yggdrasim_common.gui_server.config:build_web_server_config",
    "gui.config.dataclass": "yggdrasim_common.gui_server.config:GuiServerConfig",
    "gui.auth.rate_limiter": "yggdrasim_common.gui_server.auth:FailureRateLimiter",
    "gui.app.run_desktop": "yggdrasim_common.gui_server.app:run_desktop",
    "gui.app.run_web_server": "yggdrasim_common.gui_server.app:run_web_server",
    "gui.app.create_app": "yggdrasim_common.gui_server.app:create_app",
    "gui.actions.registry": "yggdrasim_common.gui_server.actions.registry:get_registry",
    "gui.actions.load_builtins": "yggdrasim_common.gui_server.actions.registry:ensure_builtin_actions_loaded",
    "gui.sessions.manager": "yggdrasim_common.gui_server.sessions:get_manager",
}


def ensure_repo_on_path() -> Path:
    """Prepend REPO_ROOT to sys.path if missing (idempotent)."""
    root_text = str(REPO_ROOT)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    return REPO_ROOT


def resolve(qualified: str) -> Any:
    """
    Import ``module.path:Attribute`` and return the attribute.

    Raises
    ------
    ValueError
        If qualified name does not contain exactly one ':' separator.
    """
    if qualified.count(":") != 1:
        raise ValueError(f"Expected 'module.path:Attribute', got {qualified!r}")
    module_name, attr_name = qualified.split(":", 1)
    module = importlib.import_module(module_name)
    return getattr(module, attr_name)


def get(symbol_key: str) -> Any:
    """Resolve a SYMBOL_REGISTRY key (lazy import)."""
    ensure_repo_on_path()
    if symbol_key not in SYMBOL_REGISTRY:
        available = "\n  ".join(sorted(SYMBOL_REGISTRY.keys())[:40])
        raise KeyError(
            f"Unknown registry key {symbol_key!r}. "
            f"Try search() or list_keys(). Sample keys:\n  {available}\n  ..."
        )
    return resolve(SYMBOL_REGISTRY[symbol_key])


def search(query: str) -> list[tuple[str, str]]:
    """Case-insensitive substring match over registry keys and targets."""
    needle = query.casefold().strip()
    if len(needle) == 0:
        return sorted(SYMBOL_REGISTRY.items())

    hits: list[tuple[str, str]] = []
    for key, target in SYMBOL_REGISTRY.items():
        if needle in key.casefold() or needle in target.casefold():
            hits.append((key, target))
    hits.sort(key=lambda item: item[0])
    return hits


def list_keys(prefix: str = "") -> list[str]:
    """Return sorted registry keys, optionally filtered by prefix."""
    keys = sorted(SYMBOL_REGISTRY.keys())
    if len(prefix) == 0:
        return keys
    p = prefix.casefold()
    return [key for key in keys if key.casefold().startswith(p)]


def iter_subsystems() -> Iterator[tuple[str, str]]:
    """Yield (name, description) from SUBSYSTEMS in sorted order."""
    for name in sorted(SUBSYSTEMS.keys()):
        yield name, SUBSYSTEMS[name]


def describe_cli_modules() -> str:
    """One block of text listing suggested ``python -m`` invocations."""
    lines = [
        "python -m <module>  (after pip install -e /path/to/YggdraSIM, or from repo root)",
        "",
    ]
    for name in CLI_MODULES:
        lines.append(f"  python -m {name}")
    return "\n".join(lines)


# Optional typing hook for callers that want Callable[..., Any]
RegistryCallable = Callable[..., Any]


def _smoke_test(sample_keys: tuple[str, ...]) -> None:
    ensure_repo_on_path()
    for key in sample_keys:
        obj = get(key)
        print(f"OK  {key} -> {type(obj).__name__}")


if __name__ == "__main__":
    _smoke_test(
        (
            "main.launcher.menu",
            "scp03.entry",
            "scp11.live.orchestrator",
            "tools.profile.saip_bridge",
        )
    )
    print()
    print(describe_cli_modules())
