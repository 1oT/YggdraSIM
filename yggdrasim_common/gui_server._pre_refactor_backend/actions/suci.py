# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""SUCI Tool Command Center actions.

Wraps the ``Tools.SuciTool`` shell surface into structured actions. The
underlying ``SuciKeyToolBridge`` calls the external ``suci-keytool``
binary — operators must have it installed (``YGGDRASIM_SUCI_TOOL`` env
var, or ``suci-keytool`` on ``$PATH``).

Actions registered:

* ``suci.status``          — report active key file + tool command.
* ``suci.use_key_file``    — select the active SUCI key file.
* ``suci.set_tool_command``— override the ``suci-keytool`` binary path.
* ``suci.generate_key``    — run ``suci-keytool ... generate-key --curve``.
* ``suci.dump_pub_key``    — run ``suci-keytool ... dump-pub-key``,
  with optional ``--compressed``.

All dispatchers instantiate a fresh ``SuciKeyToolBridge`` rooted at the
runtime workspace root so repeated calls don't share mutable state.
Key-file state intentionally lives only for the duration of a single
request — the GUI passes the active key file through the ``key_file``
input on every generate / dump call.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from yggdrasim_common.runtime_paths import runtime_root

from .registry import ActionContext, ActionField, ActionSpec, get_registry


_LOGGER = logging.getLogger("yggdrasim.gui.actions.suci")

_last_key_file: str | None = None


def _resolve_key_file(explicit: str | None) -> str:
    if explicit and explicit.strip():
        return explicit.strip()
    if _last_key_file:
        return _last_key_file
    raise ValueError("no key file selected — run 'Use key file' first or provide a path.")


def _build_bridge() -> Any:
    from Tools.SuciTool.tool import SuciKeyToolBridge

    return SuciKeyToolBridge(workspace_root=Path(runtime_root()).resolve())


def _result_to_dict(result: Any) -> dict[str, Any]:
    """Normalise a ``SuciCommandResult`` to a plain dict."""
    return {
        "command": list(getattr(result, "command", []) or []),
        "returncode": int(getattr(result, "returncode", 1) or 1),
        "stdout": str(getattr(result, "stdout", "") or ""),
        "stderr": str(getattr(result, "stderr", "") or ""),
    }


# ----------------------------------------------------------------------
# Dispatchers
# ----------------------------------------------------------------------


def _dispatch_status(ctx: ActionContext) -> dict[str, Any]:
    bridge = _build_bridge()
    current_key = bridge.current_key_file
    lines: list[dict[str, str]] = []
    lines.append({"key": "Workspace root", "value": str(bridge.workspace_root)})
    lines.append({"key": "Active key file", "value": str(current_key) if current_key else "(not selected)"})
    lines.append({"key": "Tool command", "value": bridge.describe_tool_command()})
    return {
        "workspace_root": str(bridge.workspace_root),
        "current_key_file": str(current_key) if current_key else "",
        "tool_command": bridge.describe_tool_command(),
        "lines": lines,
    }


def _dispatch_use_key_file(
    ctx: ActionContext,
    *,
    key_file: Any = None,
) -> dict[str, Any]:
    global _last_key_file
    key_file_s = str(key_file or "").strip()
    if len(key_file_s) == 0:
        raise ValueError("key_file is required.")
    bridge = _build_bridge()
    resolved = bridge.set_key_file(key_file_s)
    _last_key_file = str(resolved)
    return {
        "ok": True,
        "key_file": str(resolved),
        "note": f"active key file set to {resolved}.",
    }


def _dispatch_set_tool_command(
    ctx: ActionContext,
    *,
    command: Any = None,
) -> dict[str, Any]:
    command_s = str(command or "").strip()
    if len(command_s) == 0:
        raise ValueError("command is required (e.g. /usr/local/bin/suci-keytool).")
    bridge = _build_bridge()
    tokens = bridge.set_tool_command(command_s)
    return {
        "ok": True,
        "tool_command": " ".join(tokens),
        "tokens": tokens,
        "note": f"tool command set to {' '.join(tokens)}.",
    }


def _dispatch_generate_key(
    ctx: ActionContext,
    *,
    key_file: Any = None,
    curve: Any = None,
) -> dict[str, Any]:
    global _last_key_file
    key_file_s = _resolve_key_file(str(key_file or "") if key_file else "")
    curve_s = str(curve or "").strip().lower()
    if curve_s not in ("secp256r1", "curve25519"):
        raise ValueError("curve must be 'secp256r1' or 'curve25519'.")
    bridge = _build_bridge()
    resolved_key = bridge.set_key_file(key_file_s)
    _last_key_file = str(resolved_key)
    result = bridge.run_current(["generate-key", "--curve", curve_s])
    payload = _result_to_dict(result)
    payload["ok"] = payload["returncode"] == 0
    payload["key_file"] = str(resolved_key)
    payload["curve"] = curve_s
    if payload["ok"]:
        payload["note"] = f"generated {curve_s} key at {resolved_key}."
    else:
        payload["note"] = f"suci-keytool exited with code {payload['returncode']}."
    return payload


def _parse_pub_key_output(stdout: str) -> dict[str, str]:
    """Extract curve name and public-key hex from suci-keytool stdout."""
    result: dict[str, str] = {}
    for line in stdout.splitlines():
        stripped = line.strip()
        if ":" in stripped and not stripped.startswith(" ") and not stripped.startswith("-"):
            key, _, value = stripped.partition(":")
            key_lower = key.strip().lower().replace(" ", "_")
            result[key_lower] = value.strip()
    if "public_key" not in result:
        for token in stdout.split():
            token = token.strip().upper()
            if len(token) >= 64 and all(c in "0123456789ABCDEF" for c in token):
                result["public_key_hex"] = token
                break
    return result


def _dispatch_dump_pub_key(
    ctx: ActionContext,
    *,
    key_file: Any = None,
    compressed: Any = None,
) -> dict[str, Any]:
    key_file_s = _resolve_key_file(str(key_file or "") if key_file else "")
    compressed_b = bool(compressed)
    bridge = _build_bridge()
    resolved_key = bridge.set_key_file(key_file_s)
    command = ["dump-pub-key"]
    if compressed_b:
        command.append("--compressed")
    result = bridge.run_current(command)
    payload = _result_to_dict(result)
    payload["ok"] = payload["returncode"] == 0
    payload["key_file"] = str(resolved_key)
    payload["compressed"] = compressed_b
    if payload["ok"]:
        parsed = _parse_pub_key_output(payload["stdout"])
        payload["public_key_hex"] = parsed.get("public_key_hex", "")
        payload["curve"] = parsed.get("curve", "")
        payload["note"] = f"public key ({payload['curve']}): {payload['public_key_hex'][:32]}…" if payload["public_key_hex"] else "public key dumped; see stdout."
    else:
        payload["public_key_hex"] = ""
        payload["curve"] = ""
        payload["note"] = f"suci-keytool exited with code {payload['returncode']}."
    return payload


# ----------------------------------------------------------------------
# Spec registration
# ----------------------------------------------------------------------


STATUS_SPEC = ActionSpec(
    id="suci.status",
    subsystem="SUCI Tool",
    title="Status",
    description=(
        "Report the workspace root, the currently selected SUCI key file, "
        "and the resolved ``suci-keytool`` command."
    ),
    inputs=(),
    output_kind="key_value_lines",
    dispatcher=_dispatch_status,
    requires_card=False,
    tags=("suci", "status"),
)


USE_KEY_FILE_SPEC = ActionSpec(
    id="suci.use_key_file",
    subsystem="SUCI Tool",
    title="Use key file",
    description=(
        "Select the active SUCI key file. The path is validated to be "
        "inside the workspace root; it does not need to exist yet."
    ),
    inputs=(
        ActionField(
            name="key_file",
            label="Key file path",
            kind="path",
            required=True,
            placeholder="tests/demo_suci.key",
            help="Path to the SUCI key file (relative paths are resolved against the workspace root).",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_use_key_file,
    requires_card=False,
    tags=("suci", "key", "select"),
)


SET_TOOL_COMMAND_SPEC = ActionSpec(
    id="suci.set_tool_command",
    subsystem="SUCI Tool",
    title="Set suci-keytool command",
    description=(
        "Override the binary invocation used to call suci-keytool. "
        "Accepts a full command with arguments (quoted via shlex)."
    ),
    inputs=(
        ActionField(
            name="command",
            label="Tool command",
            kind="string",
            required=True,
            placeholder="/usr/local/bin/suci-keytool",
            help="Full executable path or command line for suci-keytool.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_set_tool_command,
    requires_card=False,
    tags=("suci", "tool", "config"),
)


GENERATE_KEY_SPEC = ActionSpec(
    id="suci.generate_key",
    subsystem="SUCI Tool",
    title="Generate SUCI key",
    description=(
        "Run ``suci-keytool ... generate-key --curve <name>`` against "
        "the selected key file. Supported curves: secp256r1, curve25519. "
        "Leave 'key_file' empty to reuse the last file set via 'Use key file'."
    ),
    inputs=(
        ActionField(
            name="key_file",
            label="Key file path",
            kind="path",
            required=False,
            placeholder="(reuse last) tests/demo_suci.key",
            help="Target key file; leave blank to reuse the last selected file.",
        ),
        ActionField(
            name="curve",
            label="Curve",
            kind="enum",
            required=True,
            choices=["secp256r1", "curve25519"],
            help="Curve passed to suci-keytool's --curve argument.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_generate_key,
    requires_card=False,
    tags=("suci", "generate", "key"),
)


DUMP_PUB_KEY_SPEC = ActionSpec(
    id="suci.dump_pub_key",
    subsystem="SUCI Tool",
    title="Dump public key",
    description=(
        "Run ``suci-keytool ... dump-pub-key`` on the selected key file. "
        "Enable the 'compressed' flag to emit the short-form (SEC1 "
        "compressed) encoding used for USIM / 5GS provisioning. "
        "Leave 'key_file' empty to reuse the last file set via 'Use key file'."
    ),
    inputs=(
        ActionField(
            name="key_file",
            label="Key file path",
            kind="path",
            required=False,
            help="Source key file; leave blank to reuse the last selected file.",
        ),
        ActionField(
            name="compressed",
            label="Compressed",
            kind="bool",
            required=False,
            default=False,
            help="Pass --compressed to emit the short-form public key.",
        ),
    ),
    output_kind="json",
    dispatcher=_dispatch_dump_pub_key,
    requires_card=False,
    tags=("suci", "dump", "pub-key"),
)


get_registry().register(STATUS_SPEC)
get_registry().register(USE_KEY_FILE_SPEC)
get_registry().register(SET_TOOL_COMMAND_SPEC)
get_registry().register(GENERATE_KEY_SPEC)
get_registry().register(DUMP_PUB_KEY_SPEC)
