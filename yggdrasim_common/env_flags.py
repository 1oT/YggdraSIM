"""Single-source-of-truth registry for YGGDRASIM_* runtime flags.

The suite honours a family of ``YGGDRASIM_*`` environment variables that
sit at the boundary between build-time posture (``YGGDRASIM_FLAVOR``),
runtime paths (``YGGDRASIM_RUNTIME_ROOT``), security gates (TLS, demo
keys, plugins, quirks), and module-specific knobs (HIL bridge, SAIP /
SUCI tool locators, session recording caps).

Prior to this module each flag was defined where it was consumed. That
is correct from a layering standpoint but leaves operators chasing env
names through the tree. The :data:`FLAG_REGISTRY` below centralises the
visible contract without moving consumer code: each consumer still owns
the semantics; this registry only advertises the *surface*.

Two responsibilities live here:

1. A typed registry (:class:`EnvFlag`, :data:`FLAG_REGISTRY`) usable by
   the launcher UI, documentation tooling, and tests.
2. A small persistence layer that stores user-chosen overrides on disk
   and re-applies them to ``os.environ`` on the next process start.

The persistence file lives under ``runtime_path("state",
"env_overrides.json")`` to match the card-backend persistence pattern.
A second file under ``~/.yggdrasim/env_overrides.json`` is read only as
a fallback for flags that cannot meaningfully live inside the runtime
root (specifically ``YGGDRASIM_RUNTIME_ROOT`` itself — selecting it
would create a chicken-and-egg with the path resolver). The per-flag
``persist_scope`` controls which file each override is written to.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import time
from dataclasses import dataclass, field
from typing import Any, Final


_LOGGER = logging.getLogger(__name__)


# Category ordering matches the menu layout; keep stable so muscle
# memory stays valid across releases.
CATEGORY_RUNTIME: Final[str] = "Build / runtime"
CATEGORY_CARD_BACKEND: Final[str] = "Card backend"
CATEGORY_SIM_BEHAVIOUR: Final[str] = "Simulator behaviour"
CATEGORY_PLUGINS: Final[str] = "Plugins"
CATEGORY_DEMO_KEYS: Final[str] = "Demo keys gate"
CATEGORY_SCP11_TLS: Final[str] = "SCP11 TLS"
CATEGORY_SCP11_DECODE: Final[str] = "SCP11 local SAIP decode"
CATEGORY_DEBUG: Final[str] = "Debug"
CATEGORY_HIL_BRIDGE: Final[str] = "HIL bridge"
CATEGORY_TOOLS: Final[str] = "External tool locators"
CATEGORY_SESSION: Final[str] = "Session recording"
CATEGORY_GUI: Final[str] = "Universal GUI (R2-004)"


CATEGORY_ORDER: Final[tuple[str, ...]] = (
    CATEGORY_RUNTIME,
    CATEGORY_CARD_BACKEND,
    CATEGORY_SIM_BEHAVIOUR,
    CATEGORY_PLUGINS,
    CATEGORY_DEMO_KEYS,
    CATEGORY_SCP11_TLS,
    CATEGORY_SCP11_DECODE,
    CATEGORY_DEBUG,
    CATEGORY_HIL_BRIDGE,
    CATEGORY_TOOLS,
    CATEGORY_SESSION,
    CATEGORY_GUI,
)


# Kind labels. Kept as bare strings rather than Enum so the registry can
# be dumped to JSON without custom encoders.
KIND_BOOL_TOGGLE: Final[str] = "bool_toggle"
KIND_CHOICE: Final[str] = "choice"
KIND_PATH: Final[str] = "path"
KIND_INT: Final[str] = "int"
KIND_FLOAT: Final[str] = "float"
KIND_STRING: Final[str] = "string"


# Persistence scope markers.
PERSIST_FILE: Final[str] = "persist"
PERSIST_HOME: Final[str] = "persist_home"
PERSIST_SESSION: Final[str] = "session"


# When a flag applies: "runtime" (picked up on next consumer call) vs
# "startup" (read once near process entry; full effect requires relaunch).
APPLIES_RUNTIME: Final[str] = "runtime"
APPLIES_STARTUP: Final[str] = "startup"


_SOURCE_UNSET: Final[str] = "unset (default)"
_SOURCE_ENV: Final[str] = "process env"
_SOURCE_PERSISTED_RUNTIME: Final[str] = "persisted (runtime root)"
_SOURCE_PERSISTED_HOME: Final[str] = "persisted (home)"


@dataclass(frozen=True)
class EnvFlag:
    """One row in the env-flag registry.

    ``name`` is the variable name (e.g. ``YGGDRASIM_GLOBAL_DEBUG``).
    ``kind`` drives how the UI prompts for values and how persisted
    values are validated on load. ``applies`` documents whether editing
    the flag in the running process is enough or whether it requires
    relaunching to fully take effect.

    Attributes
    ----------
    name:
        The env variable name.
    category:
        One of the ``CATEGORY_*`` constants; drives menu grouping.
    summary:
        One-line description used in list views.
    description:
        Multi-line description shown in the detail view.
    kind:
        One of the ``KIND_*`` constants.
    choices:
        For ``KIND_CHOICE`` flags, the permitted values (shown verbatim).
    bool_on_value / bool_off_value:
        For ``KIND_BOOL_TOGGLE``, the exact strings to write for on/off
        so consumers that parse truthy/falsy strings match.
    default_hint:
        Human-readable description of the default behaviour when unset.
    applies:
        ``APPLIES_RUNTIME`` or ``APPLIES_STARTUP``.
    sensitive:
        Security-sensitive flags (insecure TLS, demo keys, disabling
        quirks gate, disallow plugins) prompt for confirmation.
    persist_scope:
        ``PERSIST_FILE`` → state/env_overrides.json in runtime root.
        ``PERSIST_HOME`` → ~/.yggdrasim/env_overrides.json, used for
        flags that cannot live inside the runtime root (currently only
        ``YGGDRASIM_RUNTIME_ROOT`` itself).
        ``PERSIST_SESSION`` → never persisted; session-only.
    notes:
        Extra free-form text, usually about caveats.
    """

    name: str
    category: str
    summary: str
    description: str
    kind: str
    choices: tuple[str, ...] = field(default_factory=tuple)
    bool_on_value: str = "1"
    bool_off_value: str = ""
    default_hint: str = ""
    applies: str = APPLIES_RUNTIME
    sensitive: bool = False
    persist_scope: str = PERSIST_FILE
    notes: str = ""


FLAG_REGISTRY: Final[tuple[EnvFlag, ...]] = (
    # --- Build / runtime ------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_FLAVOR",
        category=CATEGORY_RUNTIME,
        summary="Force build flavor (clean / full / source)",
        description=(
            "Overrides the auto-detected build flavor. The flavor controls\n"
            "whether HIL bridge code is bundled and which optional extras\n"
            "are considered available. Normally set automatically by the\n"
            "build stamp or inferred from the runtime environment."
        ),
        kind=KIND_CHOICE,
        choices=("clean", "full", "source"),
        default_hint="auto-detect (frozen build → clean; source checkout → source)",
        applies=APPLIES_STARTUP,
        persist_scope=PERSIST_SESSION,
        notes="Session-only: export this in your shell profile to pin it across launches.",
    ),
    EnvFlag(
        name="YGGDRASIM_RUNTIME_ROOT",
        category=CATEGORY_RUNTIME,
        summary="Force the writable runtime root",
        description=(
            "Forces the writable runtime root (plugins/, state/, Workspace/).\n"
            "Useful for frozen builds that need to write somewhere other\n"
            "than the bundle dir, or for test harnesses that isolate runs."
        ),
        kind=KIND_PATH,
        default_hint="source checkout: repo root. Frozen build: YggdraSIM-data next to the exe, else ~/YggdraSIM-data.",
        applies=APPLIES_STARTUP,
        persist_scope=PERSIST_HOME,
        notes="Persisted to ~/.yggdrasim/env_overrides.json so the override survives across runs without creating a chicken-and-egg with the runtime resolver.",
    ),

    # --- Card backend ---------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_CARD_BACKEND",
        category=CATEGORY_CARD_BACKEND,
        summary="Force reader vs simulated SIM",
        description=(
            "Selects whether card-facing modules use the physical PC/SC\n"
            "reader or the simulated SIM backend. The [C] Card Backend\n"
            "menu also writes card_backend.json for this selection; this\n"
            "env flag is the runtime override that wins over that file."
        ),
        kind=KIND_CHOICE,
        choices=("reader", "sim"),
        default_hint="reader unless the saved selection picks sim",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_CARD_RELAY_URL",
        category=CATEGORY_CARD_BACKEND,
        summary="Remote HIL card-relay URL",
        description=(
            "When set, card-facing modules route APDUs through a remote\n"
            "HIL relay (HTTP POST to the listed URL) instead of opening a\n"
            "local PC/SC channel. Leave unset for normal local operation."
        ),
        kind=KIND_STRING,
        default_hint="unset (no relay) — local PC/SC or simulator",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SIM_QUIRKS",
        category=CATEGORY_CARD_BACKEND,
        summary="Override the simulated-SIM quirks file",
        description=(
            "Absolute path to a Python quirks override file consumed by\n"
            "the simulated SIM backend. The file is imported (and must\n"
            "therefore be trusted); see YGGDRASIM_ALLOW_QUIRKS for the\n"
            "hard gate. Leave unset to use the workspace default.\n"
            "Set to the sentinel 'none' (case-insensitive; also accepts\n"
            "'off' / 'disabled') to skip the workspace default and boot\n"
            "with an empty quirks registry, no allow-gate required. See\n"
            "also YGGDRASIM_DISABLE_QUIRKS for a process-wide kill switch."
        ),
        kind=KIND_PATH,
        default_hint="Workspace/SIMCARD/sim_quirks.py (reseeded from template on first run)",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SIM_ISDR_CONFIG",
        category=CATEGORY_CARD_BACKEND,
        summary="Override the simulated-ISD-R personality JSON",
        description=(
            "Absolute path to a JSON file that seeds the simulated ISD-R\n"
            "personality (EID, ATR shape, baseline EF_DIR, etc.). Leave\n"
            "unset to use the workspace default config."
        ),
        kind=KIND_PATH,
        default_hint="Workspace/SIMCARD/isdr_config.json",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SIM_EIM_IDENTITY",
        category=CATEGORY_CARD_BACKEND,
        summary="Override the simulated default BF55 eIM identity",
        description=(
            "Absolute path to a JSON file that defines the simulated\n"
            "card's default BF55 eIM identity used on first boot."
        ),
        kind=KIND_PATH,
        default_hint="Workspace/SIMCARD/eim_identity.json",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SIM_EUICC_STORE",
        category=CATEGORY_CARD_BACKEND,
        summary="Override the simulated eUICC store root",
        description=(
            "Directory root for persistent EID-scoped simulated eUICC\n"
            "state (profile metadata, NVRAM-like blobs, etc.). Leave\n"
            "unset to use the workspace default location."
        ),
        kind=KIND_PATH,
        default_hint="Workspace/SIMCARD/euicc_store",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SIM_PROFILE_STORE",
        category=CATEGORY_CARD_BACKEND,
        summary="Override the simulated profile artifact directory",
        description=(
            "Directory for persisted simulated-profile artifacts. When\n"
            "unset, a per-EID directory is derived under the eUICC\n"
            "store root for the active EID."
        ),
        kind=KIND_PATH,
        default_hint="derived per-EID under the eUICC store root",
        applies=APPLIES_RUNTIME,
    ),

    # --- Simulator behaviour -------------------------------------------
    EnvFlag(
        name="YGGDRASIM_ALLOW_QUIRKS",
        category=CATEGORY_SIM_BEHAVIOUR,
        summary="Allow loading Python quirks files",
        description=(
            "Hard gate for executing arbitrary Python quirks files in\n"
            "SIMCARD/quirks.py. Must be truthy (1/true/yes/on) before the\n"
            "simulator will import a quirks override — this keeps us\n"
            "from silently executing attacker-controlled code."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → quirks files are refused",
        applies=APPLIES_RUNTIME,
        sensitive=True,
        notes="Flipping on enables arbitrary-code execution via the referenced quirks file. Only enable when the file is trusted.",
    ),
    EnvFlag(
        name="YGGDRASIM_DISABLE_QUIRKS",
        category=CATEGORY_SIM_BEHAVIOUR,
        summary="Kill switch for simulator quirks",
        description=(
            "When set truthy (1/true/yes/on) the simulator skips quirks\n"
            "loading entirely and boots with an empty registry. This is\n"
            "orthogonal to YGGDRASIM_ALLOW_QUIRKS and always wins,\n"
            "regardless of the path configured via YGGDRASIM_SIM_QUIRKS.\n"
            "Use for CI / sandboxed runs where the simulator must never\n"
            "import external Python. The same effect can be achieved per\n"
            "path with YGGDRASIM_SIM_QUIRKS=none."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → quirks are loaded per YGGDRASIM_ALLOW_QUIRKS",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SIM_DEBUG_FAULTS",
        category=CATEGORY_SIM_BEHAVIOUR,
        summary="Log simulator fault-injection decisions verbosely",
        description=(
            "When set to 1 the simulator prints a stderr note every time\n"
            "a fault/quirk decision is taken. Handy when chasing why a\n"
            "test card returns an unexpected SW."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → quiet",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_ENABLE_TUAK",
        category=CATEGORY_SIM_BEHAVIOUR,
        summary="Enable TUAK auth algorithm in the simulator",
        description=(
            "Turns on TUAK (3GPP TS 35.231) alongside MILENAGE in the\n"
            "simulated AKA pipeline. Off by default because TUAK is not\n"
            "wired through the simulator's default quirks."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → MILENAGE only",
        applies=APPLIES_RUNTIME,
    ),

    # --- Plugins --------------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_ALLOW_PLUGINS",
        category=CATEGORY_PLUGINS,
        summary="Tri-state plugin opt-in / opt-out",
        description=(
            "Tri-state knob controlling plugin loading. Plugins load by\n"
            "default since the loader-default flip; this flag is kept for\n"
            "back-compat.\n"
            "  1 / true / yes / on  → explicit opt-in (redundant)\n"
            "  0 / false / no / off → opt-out (plugins refused)\n"
            "  unset                → default-on"
        ),
        kind=KIND_CHOICE,
        choices=("1", "0"),
        default_hint="unset → plugins load",
        applies=APPLIES_STARTUP,
        notes="Plugin loading happens at module-import time of main.py; changing this flag in a running process does not retroactively load/unload plugins.",
    ),
    EnvFlag(
        name="YGGDRASIM_DISALLOW_PLUGINS",
        category=CATEGORY_PLUGINS,
        summary="Hard-lock: refuse every plugin",
        description=(
            "Hard-lock. Refuses every plugin even when ALLOW_PLUGINS=1\n"
            "is also set. Intended for attestation / CI / air-gapped\n"
            "deployments where no out-of-tree code may execute."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → plugins may load",
        applies=APPLIES_STARTUP,
        sensitive=True,
    ),

    # --- Demo keys gate -------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_ALLOW_DEMO_KEYS",
        category=CATEGORY_DEMO_KEYS,
        summary="Silence the SCP03 / SCP80 demo-keys warning",
        description=(
            "When set truthy, SCP03 and SCP80 stop emitting the banner\n"
            "that warns a known-demo key set is being used. Use only\n"
            "when running against lab cards that you know carry demo\n"
            "keying material."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → banner is printed when demo keys are detected",
        applies=APPLIES_RUNTIME,
        sensitive=True,
    ),
    EnvFlag(
        name="YGGDRASIM_REQUIRE_NON_DEMO_KEYS",
        category=CATEGORY_DEMO_KEYS,
        summary="Fail fast when demo keys are loaded",
        description=(
            "When truthy, SCP03 and SCP80 raise a RuntimeError at config\n"
            "load time if a known-demo key set is detected. Prevents\n"
            "deployments from accidentally using demo material against\n"
            "real cards."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → demo keys only emit a warning",
        applies=APPLIES_RUNTIME,
    ),

    # --- SCP11 TLS ------------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_SCP11_ALLOW_INSECURE_TLS",
        category=CATEGORY_SCP11_TLS,
        summary="Allow unpinned SCP11 ES9 request traffic",
        description=(
            "Opt-in to unpinned request-time TLS for SCP11 relay ES9\n"
            "traffic. Triggers a one-shot stderr warning per caller and\n"
            "is refused when REQUIRE_PINNED_TLS is also set. Only for\n"
            "dev boxes running against SGP.26 test vectors."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → unpinned request traffic is refused",
        applies=APPLIES_RUNTIME,
        sensitive=True,
    ),
    EnvFlag(
        name="YGGDRASIM_SCP11_REQUIRE_PINNED_TLS",
        category=CATEGORY_SCP11_TLS,
        summary="Hard-lock: refuse unpinned SCP11 request traffic",
        description=(
            "Hard-lock for SCP11 relay ES9 request traffic. Refuses\n"
            "every unpinned connection even when ALLOW_INSECURE_TLS=1\n"
            "is also set."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → opt-in still possible",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION",
        category=CATEGORY_SCP11_TLS,
        summary="Hard-lock: refuse TOFU chain reads",
        description=(
            "Hard-lock for the read-only TOFU chain probe used to\n"
            "auto-learn trust anchors on first contact. Use when no new\n"
            "anchor may be learned at runtime (attestation / air-gapped)\n"
            "and pre-seed anchors manually under SCP11/<tree>/certs."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → auto-learn allowed",
        applies=APPLIES_RUNTIME,
    ),

    # --- SCP11 local SAIP decode ---------------------------------------
    EnvFlag(
        name="YGGDRASIM_SCP11_SAIP_DECODE_TIMEOUT_SECONDS",
        category=CATEGORY_SCP11_DECODE,
        summary="Extend the SAIP decode timeout for LocalSMDPP",
        description=(
            "Timeout (seconds) for the full SAIP decode inside the\n"
            "Local SMDPP shell. Very large profiles can need more than\n"
            "the default budget."
        ),
        kind=KIND_FLOAT,
        default_hint="unset → built-in default (see SCP11/local_access/session.py)",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SCP11_ALLOW_FULL_SAIP_DECODE",
        category=CATEGORY_SCP11_DECODE,
        summary="Allow expensive full SAIP decode on LocalSMDPP profiles",
        description=(
            "Permits the expensive full SAIP decode path in the Local\n"
            "SMDPP shell. Off by default because the compact decode is\n"
            "sufficient for most workflows and faster."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → compact decode only",
        applies=APPLIES_RUNTIME,
    ),

    # --- Debug ----------------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_GLOBAL_DEBUG",
        category=CATEGORY_DEBUG,
        summary="Enable verbose debug across modules",
        description=(
            "Promotes debug output to a process-global default. The\n"
            "wrapper --debug flag sets this too; setting it here without\n"
            "--debug enables debug for modules launched from the menu."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → per-module debug stays opt-in",
        applies=APPLIES_RUNTIME,
    ),

    # --- HIL bridge -----------------------------------------------------
    EnvFlag(
        name="YGGDRASIM_HIL_CAPTURE_INTERFACE",
        category=CATEGORY_HIL_BRIDGE,
        summary="Network interface Wireshark / tshark listen on",
        description=(
            "Loopback interface fed to Wireshark / tshark for the HIL\n"
            "bridge GSMTAP capture. On macOS the platform default is\n"
            "lo0; on Linux it is lo."
        ),
        kind=KIND_STRING,
        default_hint="lo0 on macOS, lo elsewhere",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_HIL_WIRESHARK_BIN",
        category=CATEGORY_HIL_BRIDGE,
        summary="Explicit Wireshark binary path",
        description=(
            "Path to the Wireshark binary used by the HIL bridge\n"
            "raw+Wireshark view when it cannot be found on PATH."
        ),
        kind=KIND_PATH,
        default_hint="shutil.which('wireshark')",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_HIL_TERMSHARK_BIN",
        category=CATEGORY_HIL_BRIDGE,
        summary="Explicit termshark binary path",
        description=(
            "Path to the termshark binary used by the HIL bridge\n"
            "decoded-view start mode when it cannot be found on PATH."
        ),
        kind=KIND_PATH,
        default_hint="shutil.which('termshark')",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_HIL_TERMSHARK_WARMUP_SECONDS",
        category=CATEGORY_HIL_BRIDGE,
        summary="Warm-up delay before starting the bridge after termshark",
        description=(
            "Seconds to wait for termshark to reach 'listening' before\n"
            "the HIL bridge starts. Clamped to [0.0, 10.0]. Raise when\n"
            "termshark is slow to bind on a loaded host."
        ),
        kind=KIND_FLOAT,
        default_hint="2.0",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_HIL_TUI_TERM",
        category=CATEGORY_HIL_BRIDGE,
        summary="Override the TERM value used by the HIL live-decode TUI",
        description=(
            "Overrides the TERM detection inside the HIL bridge live\n"
            "decode TUI. Useful when the outer terminal advertises a\n"
            "TERM value the TUI's renderer does not support."
        ),
        kind=KIND_STRING,
        default_hint="auto-detect (prefers screen-256color / tmux-256color / xterm-256color)",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_RSPRO_ASN",
        category=CATEGORY_HIL_BRIDGE,
        summary="Override the RSPRO ASN.1 module path",
        description=(
            "Path to a custom pycrate-generated RSPRO ASN.1 module used\n"
            "by the HIL bridge REMSIM protocol. Only needed when running\n"
            "against a non-standard RSPRO schema."
        ),
        kind=KIND_PATH,
        default_hint="built-in module shipped with Tools/HilBridge",
        applies=APPLIES_RUNTIME,
    ),

    # --- External tool locators ----------------------------------------
    EnvFlag(
        name="YGGDRASIM_SAIP_TOOL",
        category=CATEGORY_TOOLS,
        summary="Explicit saip-tool binary or command",
        description=(
            "Explicit command used to invoke pySim's saip-tool. Accepts\n"
            "either an absolute path to the binary or a full command\n"
            "line like 'python -m pySim.esim.saip_tool'."
        ),
        kind=KIND_STRING,
        default_hint="shutil.which('saip-tool')",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SAIP_TOOL_TIMEOUT_SECONDS",
        category=CATEGORY_TOOLS,
        summary="Default timeout for saip-tool subprocess calls",
        description=(
            "Timeout (seconds) applied when the SAIP tool shell spawns\n"
            "saip-tool. Raise for very large profiles or very slow hosts."
        ),
        kind=KIND_FLOAT,
        default_hint="built-in default (see Tools/ProfilePackage/saip_tool.py)",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SAIP_TOOL_CACHE_MAX_BYTES",
        category=CATEGORY_TOOLS,
        summary="Cap for the on-disk SAIP tool decode cache",
        description=(
            "Maximum size in bytes for the SAIP tool's persistent\n"
            "decode cache. Older entries are evicted once the cap is\n"
            "reached. Set to 0 to disable caching."
        ),
        kind=KIND_INT,
        default_hint="built-in default (see Tools/ProfilePackage/saip_tool.py)",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SUCI_TOOL",
        category=CATEGORY_TOOLS,
        summary="Explicit suci-keytool binary or command",
        description=(
            "Explicit command used to invoke pySim's suci-keytool.\n"
            "Accepts either an absolute path or a full command line\n"
            "like 'python -m suci_keytool'."
        ),
        kind=KIND_STRING,
        default_hint="shutil.which('suci-keytool')",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_SUCI_TIMEOUT",
        category=CATEGORY_TOOLS,
        summary="Default timeout for suci-keytool subprocess calls",
        description=(
            "Timeout (seconds) for the SUCI key tool's subprocess\n"
            "invocations. Keep generous for slow hosts."
        ),
        kind=KIND_FLOAT,
        default_hint="built-in default (see Tools/SuciTool/tool.py)",
        applies=APPLIES_RUNTIME,
    ),
    EnvFlag(
        name="YGGDRASIM_EUM_SESSION_KEYS",
        category=CATEGORY_TOOLS,
        summary="Path to the EUM session keys JSON repository",
        description=(
            "Path to the external JSON file holding session keying\n"
            "material used by the EUM diagnostics Lua dissector."
        ),
        kind=KIND_PATH,
        default_hint="unset → no session key material available",
        applies=APPLIES_RUNTIME,
    ),

    # --- Session recording ---------------------------------------------
    EnvFlag(
        name="YGGDRASIM_SESSION_APDU_TRACE_CAP",
        category=CATEGORY_SESSION,
        summary="Soft cap on APDU events per session recording",
        description=(
            "Soft ceiling on APDU events retained in a shell session\n"
            "recording. Events beyond the cap are dropped with a\n"
            "one-shot warning so long recordings do not balloon."
        ),
        kind=KIND_INT,
        default_hint="50000",
        applies=APPLIES_RUNTIME,
    ),

    # --- Universal GUI (R2-004) ----------------------------------------
    EnvFlag(
        name="YGGDRASIM_GUI_HOST",
        category=CATEGORY_GUI,
        summary="Desktop GUI bind host",
        description=(
            "Override the bind host for `yggdrasim --gui`. Defaults to\n"
            "127.0.0.1 so the surface stays on loopback. On Linux / macOS\n"
            "an operator can set this to 127.0.0.7 for loopback isolation\n"
            "(keeps the GUI away from the shared 127.0.0.1 alias). The\n"
            "CLI flag --host wins over this value."
        ),
        kind=KIND_STRING,
        default_hint="127.0.0.1",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_PORT",
        category=CATEGORY_GUI,
        summary="Desktop GUI bind port",
        description=(
            "Override the bind port for `yggdrasim --gui`. Defaults to\n"
            "27853 which is clear of every other loopback claim in the\n"
            "suite (4729/8080/9997/15353/18443/19443/44215). If the\n"
            "configured port is busy, desktop mode falls back to an\n"
            "OS-assigned ephemeral port."
        ),
        kind=KIND_INT,
        default_hint="27853",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_SERVER_HOST",
        category=CATEGORY_GUI,
        summary="Remote lab GUI bind host",
        description=(
            "Override the bind host for `yggdrasim --web-server`.\n"
            "Default is 0.0.0.0 so a remote operator can reach the lab;\n"
            "the safer posture is 127.0.0.1 plus SSH tunnelling. See\n"
            "V2_UNIVERSAL_GUI_PLAN.md §9 for the runbook."
        ),
        kind=KIND_STRING,
        default_hint="0.0.0.0 (SSH-tunnel-friendly: prefer 127.0.0.1)",
        applies=APPLIES_STARTUP,
        sensitive=True,
        notes="Binding 0.0.0.0 exposes the API beyond loopback; keep TLS or SSH tunnelling documented as non-optional.",
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_SERVER_PORT",
        category=CATEGORY_GUI,
        summary="Remote lab GUI bind port",
        description=(
            "Override the bind port for `yggdrasim --web-server`.\n"
            "Default 27854. Unlike desktop mode, server mode refuses to\n"
            "fall back to an ephemeral port — operators rely on a stable\n"
            "URL."
        ),
        kind=KIND_INT,
        default_hint="27854",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_TOKEN",
        category=CATEGORY_GUI,
        summary="Bearer token for the GUI API (inline)",
        description=(
            "Literal bearer-token value used by --gui / --web-server\n"
            "when neither --token-file nor YGGDRASIM_GUI_TOKEN_FILE is\n"
            "supplied. Must be >= 32 characters for --web-server. The\n"
            "file-based sources are preferred because this variable is\n"
            "visible to anyone who can read the process environment."
        ),
        kind=KIND_STRING,
        default_hint="unset → auto-generated for --gui, rejected for --web-server",
        applies=APPLIES_STARTUP,
        sensitive=True,
        persist_scope=PERSIST_SESSION,
        notes="Session-scoped. Never persisted. Operator's responsibility to rotate.",
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_TOKEN_FILE",
        category=CATEGORY_GUI,
        summary="Path to a bearer-token file for the GUI API",
        description=(
            "Absolute path to a file whose contents are used as the\n"
            "bearer token. The file must be `chmod 600` on POSIX; the\n"
            "GUI loader refuses group- or world-readable files."
        ),
        kind=KIND_PATH,
        default_hint="unset",
        applies=APPLIES_STARTUP,
        sensitive=True,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_TLS_CERT",
        category=CATEGORY_GUI,
        summary="TLS certificate path for --web-server",
        description=(
            "PEM-encoded TLS server certificate. Paired with\n"
            "YGGDRASIM_GUI_TLS_KEY. When both are set the server binds\n"
            "HTTPS; without them the operator must tunnel (SSH) or use\n"
            "--tls-self-signed for a one-time local pair."
        ),
        kind=KIND_PATH,
        default_hint="unset (plain HTTP unless --tls-self-signed is passed)",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_TLS_KEY",
        category=CATEGORY_GUI,
        summary="TLS private key path for --web-server",
        description=(
            "PEM-encoded TLS private key matching\n"
            "YGGDRASIM_GUI_TLS_CERT. Must be `chmod 600` on POSIX."
        ),
        kind=KIND_PATH,
        default_hint="unset",
        applies=APPLIES_STARTUP,
        sensitive=True,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_ALLOW_ORIGIN",
        category=CATEGORY_GUI,
        summary="Additional CORS origin(s) for --web-server",
        description=(
            "Comma-separated list of origins permitted to call the GUI\n"
            "API. Defaults to deny-all (same-origin only). Wildcards\n"
            "('*') are refused so a misconfiguration cannot silently\n"
            "open the surface."
        ),
        kind=KIND_STRING,
        default_hint="unset → deny-all (same-origin SPA only)",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_IDLE_SECONDS",
        category=CATEGORY_GUI,
        summary="WebSocket idle cutoff for GUI shell sessions",
        description=(
            "Seconds of no WebSocket traffic before an interactive shell\n"
            "session is disconnected. Default 1800 (30 minutes). Set to\n"
            "0 to disable (not recommended for --web-server)."
        ),
        kind=KIND_INT,
        default_hint="1800",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_PATH_ALLOWLIST",
        category=CATEGORY_GUI,
        summary="Extra path roots the GUI is permitted to read",
        description=(
            "Colon-separated (POSIX) / semicolon-separated (Windows)\n"
            "list of absolute path roots the GUI's path-taking\n"
            "endpoints may read from. Always includes the runtime root,\n"
            "the eUICC store root, and the current working directory."
        ),
        kind=KIND_STRING,
        default_hint="unset → runtime root + eUICC store + CWD",
        applies=APPLIES_STARTUP,
    ),
    EnvFlag(
        name="YGGDRASIM_GUI_WEBVIEW_DEBUG",
        category=CATEGORY_GUI,
        summary="Open the pywebview dev tools on --gui launch",
        description=(
            "When truthy, the pywebview window is created with its\n"
            "debug menu / dev tools enabled. Useful during frontend\n"
            "development; leave off for normal operation."
        ),
        kind=KIND_BOOL_TOGGLE,
        default_hint="unset → dev tools closed",
        applies=APPLIES_STARTUP,
    ),
)


_FLAG_BY_NAME: Final[dict[str, EnvFlag]] = {flag.name: flag for flag in FLAG_REGISTRY}


def iter_flags() -> tuple[EnvFlag, ...]:
    """Return a frozen tuple of registered flags in declaration order."""
    return FLAG_REGISTRY


def flags_by_category(category: str) -> tuple[EnvFlag, ...]:
    """Return all flags registered under ``category`` in declaration order."""
    target = str(category or "").strip()
    result: list[EnvFlag] = []
    for flag in FLAG_REGISTRY:
        if flag.category == target:
            result.append(flag)
    return tuple(result)


def get_flag(name: str) -> EnvFlag | None:
    """Return the registered flag with ``name``, or ``None`` when unknown."""
    return _FLAG_BY_NAME.get(str(name or "").strip())


def is_registered_flag(name: str) -> bool:
    return str(name or "").strip() in _FLAG_BY_NAME


# ---------------------------------------------------------------------------
# Persistence layer
# ---------------------------------------------------------------------------
_RUNTIME_OVERRIDES_REL: Final[tuple[str, ...]] = ("state", "env_overrides.json")
_HOME_OVERRIDES_REL: Final[tuple[str, str]] = (".yggdrasim", "env_overrides.json")


def _home_overrides_path() -> str:
    return os.path.join(os.path.expanduser("~"), *_HOME_OVERRIDES_REL)


def _runtime_overrides_path() -> str:
    # Local import: runtime_paths pulls in filesystem side effects we
    # want to keep out of the module-import path for callers who only
    # need the registry (e.g. documentation generation).
    from .runtime_paths import runtime_path
    return runtime_path(*_RUNTIME_OVERRIDES_REL)


def _read_overrides_file(path_text: str) -> dict[str, Any]:
    normalized = str(path_text or "").strip()
    if len(normalized) == 0:
        return {}
    if os.path.isfile(normalized) is False:
        return {}
    try:
        with open(normalized, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as decode_error:
        _quarantine_corrupt_overrides(normalized, decode_error)
        return {}
    except OSError as io_error:
        _LOGGER.warning(
            "env_flags: could not read %s (%s); using empty overrides.",
            normalized,
            io_error,
        )
        return {}
    if isinstance(payload, dict) is False:
        return {}
    return dict(payload)


def _quarantine_corrupt_overrides(settings_path: str, decode_error: json.JSONDecodeError) -> None:
    sidecar_path = f"{settings_path}.corrupt.{int(time.time())}"
    try:
        shutil.move(settings_path, sidecar_path)
    except OSError as move_error:
        _LOGGER.error(
            "env_flags: %s is corrupt (%s) and could not be renamed aside (%s); "
            "empty overrides will be used until the file is repaired.",
            settings_path,
            decode_error,
            move_error,
        )
        return
    _LOGGER.warning(
        "env_flags: %s was unparseable (%s); moved to %s.",
        settings_path,
        decode_error,
        sidecar_path,
    )


def _write_overrides_file(path_text: str, payload: dict[str, Any]) -> None:
    normalized = str(path_text or "").strip()
    if len(normalized) == 0:
        raise OSError("env_flags: empty overrides path")
    directory = os.path.dirname(normalized)
    if len(directory) > 0:
        os.makedirs(directory, exist_ok=True)
    with open(normalized, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def _filter_to_registered(payload: dict[str, Any]) -> dict[str, str]:
    """Drop keys that aren't registered flags; coerce values to stripped strings."""
    cleaned: dict[str, str] = {}
    for raw_key, raw_value in payload.items():
        key = str(raw_key or "").strip()
        if is_registered_flag(key) is False:
            continue
        cleaned[key] = str(raw_value if raw_value is not None else "").strip()
    return cleaned


def load_persisted_overrides() -> dict[str, str]:
    """Return the merged persisted overrides (home file + runtime file).

    Home-scoped overrides win over runtime-scoped ones for the same key
    so ``YGGDRASIM_RUNTIME_ROOT`` cannot be redirected by a file that
    lives inside a runtime root the caller may no longer use.
    """
    runtime_payload = _filter_to_registered(_read_overrides_file(_runtime_overrides_path()))
    home_payload = _filter_to_registered(_read_overrides_file(_home_overrides_path()))
    merged: dict[str, str] = {}
    merged.update(runtime_payload)
    merged.update(home_payload)
    return merged


def _persist_flag_value(flag: EnvFlag, value: str) -> None:
    """Write ``value`` to the correct persistence file for ``flag``.

    A blank ``value`` removes the key from the file. Session-scoped
    flags raise to keep the contract obvious for callers.
    """
    if flag.persist_scope == PERSIST_SESSION:
        raise ValueError(f"env_flags: {flag.name} is session-only and cannot be persisted.")
    if flag.persist_scope == PERSIST_HOME:
        target_path = _home_overrides_path()
    else:
        target_path = _runtime_overrides_path()
    payload = _read_overrides_file(target_path)
    if isinstance(payload, dict) is False:
        payload = {}
    normalized_value = str(value or "").strip()
    if len(normalized_value) == 0:
        payload.pop(flag.name, None)
    else:
        payload[flag.name] = normalized_value
    _write_overrides_file(target_path, payload)


def apply_persisted_env_overrides() -> dict[str, str]:
    """Copy persisted overrides into ``os.environ`` for unset flags.

    Called once near process entry so consumers that read environment
    variables on demand (e.g. ``get_flavor``) see the persisted value.
    A flag already present in ``os.environ`` at call time wins, so
    command-line overrides (``--card-backend sim``) and explicit
    ``VAR=... python`` invocations keep their priority.

    Returns the dict of overrides that were actually applied.
    """
    applied: dict[str, str] = {}
    overrides = load_persisted_overrides()
    for flag_name, value in overrides.items():
        normalized_value = str(value or "").strip()
        if len(normalized_value) == 0:
            continue
        existing = str(os.environ.get(flag_name, "") or "")
        if len(existing) > 0:
            continue
        os.environ[flag_name] = normalized_value
        applied[flag_name] = normalized_value
    return applied


def get_flag_value(flag: EnvFlag) -> str:
    """Return the current process-environment value for ``flag``."""
    return str(os.environ.get(flag.name, "") or "")


def get_flag_source(flag: EnvFlag) -> str:
    """Describe where the current value came from.

    Distinguishes between an unset variable, a process-level value set
    by argparse/CLI, and a value that matches what the persistence
    files would have applied.
    """
    current = get_flag_value(flag)
    if len(current) == 0:
        return _SOURCE_UNSET
    if flag.persist_scope == PERSIST_SESSION:
        return _SOURCE_ENV
    home_overrides = _filter_to_registered(_read_overrides_file(_home_overrides_path()))
    runtime_overrides = _filter_to_registered(_read_overrides_file(_runtime_overrides_path()))
    if flag.persist_scope == PERSIST_HOME:
        persisted = home_overrides.get(flag.name, "")
    else:
        persisted = runtime_overrides.get(flag.name, "")
    if len(persisted) > 0 and persisted == current.strip():
        if flag.persist_scope == PERSIST_HOME:
            return _SOURCE_PERSISTED_HOME
        return _SOURCE_PERSISTED_RUNTIME
    return _SOURCE_ENV


def set_flag_value(flag: EnvFlag, value: str, *, persist: bool = True) -> str:
    """Set ``flag`` to ``value`` in ``os.environ`` and optionally persist it.

    ``value`` is stripped; a blank value clears the flag (removes it
    from ``os.environ`` and the persistence file). ``persist=False``
    applies the value for the current process only.
    """
    normalized_value = str(value or "").strip()
    if len(normalized_value) == 0:
        os.environ.pop(flag.name, None)
    else:
        os.environ[flag.name] = normalized_value
    if persist is False:
        return normalized_value
    if flag.persist_scope == PERSIST_SESSION:
        return normalized_value
    try:
        _persist_flag_value(flag, normalized_value)
    except OSError as io_error:
        _LOGGER.warning(
            "env_flags: could not persist %s (%s: %s).",
            flag.name,
            io_error.__class__.__name__,
            io_error,
        )
    return normalized_value


def clear_flag_value(flag: EnvFlag, *, persist: bool = True) -> None:
    """Clear ``flag`` from ``os.environ`` and (optionally) from disk."""
    set_flag_value(flag, "", persist=persist)


def reset_all_persisted(*, clear_session: bool = False) -> int:
    """Remove every persisted override.

    ``clear_session`` also pops each persistable flag from ``os.environ``
    in the current process so the reset is visible immediately without
    relaunching. Session-only flags are never touched.

    Returns the number of entries removed from the persistence files.
    """
    removed = 0
    for path_func in (_runtime_overrides_path, _home_overrides_path):
        target_path = path_func()
        payload = _read_overrides_file(target_path)
        if isinstance(payload, dict) is False or len(payload) == 0:
            continue
        removed += len(payload)
        try:
            _write_overrides_file(target_path, {})
        except OSError as io_error:
            _LOGGER.warning(
                "env_flags: could not clear %s (%s: %s).",
                target_path,
                io_error.__class__.__name__,
                io_error,
            )
    if clear_session:
        for flag in FLAG_REGISTRY:
            if flag.persist_scope == PERSIST_SESSION:
                continue
            os.environ.pop(flag.name, None)
    return removed


def dump_export_lines() -> list[str]:
    """Return a list of POSIX ``export`` lines for every currently-set flag.

    Useful for dumping the active configuration into a shell profile or
    systemd Environment= lines. Values are quoted conservatively.
    """
    lines: list[str] = []
    for flag in FLAG_REGISTRY:
        value = get_flag_value(flag)
        if len(value) == 0:
            continue
        quoted = value.replace("'", "'\\''")
        lines.append(f"export {flag.name}='{quoted}'")
    return lines
