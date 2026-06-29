# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Standalone Card Bridge daemon.

Reuses :class:`Tools.HilBridge.pcsc.PcscCardChannel` to open a local
reader and :class:`Tools.HilBridge.apdu_relay.HilBridgeApduRelayService`
to publish the APDU exchange over HTTP. Adds:

* CLI argument parsing.
* Bearer token bootstrap — generates a token if none was supplied,
  writes it to a 0600 file under ``~/.config/yggdrasim/card_bridge``,
  and echoes only the fingerprint on stdout.
* Default loopback bind, refusal to bind anything else without a
  token (defence-in-depth on top of the relay service's own check).
* Signal handling so ``SIGINT`` / ``SIGTERM`` shut the bridge down
  cleanly and release the card.
* Optional structured audit logging (header-only by default).

The module is import-safe: ``PcscCardChannel`` is only instantiated
inside :func:`run_card_bridge`, so unit tests can swap in a fake
channel without dragging in pyscard.
"""

from __future__ import annotations

import argparse
import inspect
import logging
import os
import signal
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from Tools.HilBridge.apdu_relay import (
    ApduRelayConfig,
    DEFAULT_AUDIT_LOGGER_NAME,
    HilBridgeApduRelayService,
)
from Tools.HilBridge.pcsc import (
    APDU_TIMEOUT_ENV,
    DEFAULT_APDU_TIMEOUT_MS,
    PCSC_SHARE_MODE_SHARED,
    PCSC_SHARE_MODES,
    resolve_apdu_timeout_ms,
)
from yggdrasim_common.card_bridge_auth import (
    default_token_file_for_port,
    fingerprint as token_fingerprint,
    generate_token,
    is_loopback_host,
    read_token_file,
    write_token_file,
)

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8642
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_RUNTIME = 3


class CardBridgeError(RuntimeError):
    """Raised when the bridge cannot start or run to completion."""


@dataclass
class CardBridgeConfig:
    """Resolved configuration for one Card Bridge invocation.

    Filled in by :func:`build_config_from_args` after CLI parsing and
    consulted by :func:`run_card_bridge`. Held as a mutable dataclass
    rather than ``frozen=True`` so unit tests can patch a fake
    ``card_channel_factory`` in without rebuilding the whole record.
    """

    host: str = DEFAULT_BIND_HOST
    port: int = DEFAULT_BIND_PORT
    reader_index: int = 0
    reader_name: str = ""
    auth_token: str = ""
    token_file: Path | None = None
    token_file_was_written: bool = False
    audit_enabled: bool = False
    audit_full_apdu: bool = False
    audit_logger_name: str = DEFAULT_AUDIT_LOGGER_NAME
    apdu_timeout_ms: int = DEFAULT_APDU_TIMEOUT_MS
    pcsc_share_mode: str = PCSC_SHARE_MODE_SHARED
    card_channel_factory: Callable[..., Any] | None = field(
        default=None, repr=False
    )


def _default_pcsc_channel_factory(
    reader_index: int,
    reader_name: str,
    pcsc_share_mode: str = PCSC_SHARE_MODE_SHARED,
) -> Any:
    """Build a real :class:`PcscCardChannel`. Imported lazily for testability."""
    from Tools.HilBridge.pcsc import PcscCardChannel

    return PcscCardChannel(
        reader_index=reader_index,
        reader_name=reader_name,
        share_mode=pcsc_share_mode,
    )


def _build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="yggdrasim-card-bridge",
        description=(
            "Publish a locally attached PC/SC reader over a loopback HTTP "
            "endpoint, intended for SSH-tunnelled remote access. See "
            "guides/CARD_BRIDGE_GUIDE.md for the full operator workflow."
        ),
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_BIND_HOST,
        help=(
            "Bind interface. Defaults to 127.0.0.1; binding any other "
            "address requires --token / --token-file and is intended only "
            "for setups behind a TLS-terminating reverse proxy."
        ),
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_BIND_PORT,
        help=f"TCP port to listen on (default: {DEFAULT_BIND_PORT}).",
    )
    parser.add_argument(
        "--reader-index",
        type=int,
        default=0,
        help="Index of the PC/SC reader to publish (default: 0).",
    )
    parser.add_argument(
        "--reader-name",
        default="",
        help="Substring match for the PC/SC reader name (overrides --reader-index).",
    )
    parser.add_argument(
        "--token-file",
        default="",
        help=(
            "Path to a 0600-mode file containing a bearer token. If the "
            "file does not exist a fresh token is generated and written "
            "to it. When omitted the bridge writes the token under "
            "${XDG_CONFIG_HOME:-~/.config}/yggdrasim/card_bridge/<port>.token."
        ),
    )
    parser.add_argument(
        "--no-token",
        action="store_true",
        help=(
            "Run without a bearer token (loopback bind only). Provided "
            "for parity with the historical HilBridge marker workflow; "
            "the bridge refuses to start in this mode if --host is not "
            "loopback."
        ),
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help=(
            "Emit a structured audit record per APDU exchange (header "
            "bytes + status word, never the data payload)."
        ),
    )
    parser.add_argument(
        "--audit-full-apdu",
        action="store_true",
        help=(
            "DANGEROUS — also log the full APDU and response hex. PIN "
            "material rides through here; only enable for forensic work "
            "on test cards. Implies --audit."
        ),
    )
    parser.add_argument(
        "--audit-logger-name",
        default=DEFAULT_AUDIT_LOGGER_NAME,
        help="Name of the Python logger that receives audit records.",
    )
    parser.add_argument(
        "--apdu-timeout-ms",
        type=int,
        default=None,
        help=(
            "Maximum PC/SC APDU wait time in milliseconds "
            f"(default from {APDU_TIMEOUT_ENV}, fallback {DEFAULT_APDU_TIMEOUT_MS})."
        ),
    )
    parser.add_argument(
        "--pcsc-share-mode",
        choices=PCSC_SHARE_MODES,
        default=PCSC_SHARE_MODE_SHARED,
        help=(
            "PC/SC sharing mode for the local reader. Defaults to shared "
            "so GUI reader probes do not block Card Bridge startup; use "
            "exclusive when no other local process may touch the reader."
        ),
    )
    return parser


def _resolve_token(args: argparse.Namespace) -> tuple[str, Path | None, bool]:
    """Resolve the bearer token according to the CLI semantics.

    Returns ``(token, token_file, file_was_written)``.

    Resolution order:

    1. ``--no-token`` → empty token, no file. Caller must guarantee
       loopback bind, which is checked downstream.
    2. ``--token-file`` exists → read it.
    3. ``--token-file`` set but missing → generate, write, return.
    4. Neither → generate, write to the conventional path for the port.
    """
    if args.no_token is True:
        return "", None, False

    candidate_path: Path | None = None
    if len(str(args.token_file or "").strip()) > 0:
        candidate_path = Path(str(args.token_file).strip()).expanduser().resolve()
    else:
        candidate_path = default_token_file_for_port(int(args.port))

    if candidate_path.is_file() is True:
        try:
            existing = read_token_file(candidate_path)
        except OSError as exc:
            raise CardBridgeError(
                f"Cannot read token file {candidate_path}: {exc}"
            ) from exc
        if len(existing) == 0:
            raise CardBridgeError(
                f"Token file {candidate_path} is empty. Delete it or supply a "
                f"different --token-file path."
            )
        return existing, candidate_path, False

    fresh = generate_token()
    written_path = write_token_file(candidate_path, fresh)
    return fresh, written_path, True


def build_config_from_args(args: argparse.Namespace) -> CardBridgeConfig:
    if int(args.port) <= 0 or int(args.port) > 65535:
        raise CardBridgeError(f"Invalid TCP port: {args.port!r}")

    token, token_file, written = _resolve_token(args)

    if is_loopback_host(args.host) is False and len(token) == 0:
        raise CardBridgeError(
            f"Refusing to bind {args.host!r}:{args.port} without a bearer "
            f"token. Drop --no-token, supply --token-file, or bind to a "
            f"loopback address (127.0.0.1) and route remote access via SSH "
            f"LocalForward."
        )

    audit_enabled = bool(args.audit) or bool(args.audit_full_apdu)
    return CardBridgeConfig(
        host=str(args.host or DEFAULT_BIND_HOST).strip(),
        port=int(args.port),
        reader_index=int(args.reader_index),
        reader_name=str(args.reader_name or "").strip(),
        auth_token=token,
        token_file=token_file,
        token_file_was_written=written,
        audit_enabled=audit_enabled,
        audit_full_apdu=bool(args.audit_full_apdu),
        audit_logger_name=str(args.audit_logger_name or DEFAULT_AUDIT_LOGGER_NAME).strip()
        or DEFAULT_AUDIT_LOGGER_NAME,
        apdu_timeout_ms=resolve_apdu_timeout_ms(
            getattr(args, "apdu_timeout_ms", None)
        ),
        pcsc_share_mode=str(args.pcsc_share_mode or PCSC_SHARE_MODE_SHARED),
    )


def _transmit_with_optional_timeout(
    channel: Any,
    apdu: bytes,
    *,
    timeout_ms: int,
) -> tuple[bytes, int, int]:
    transmit = getattr(channel, "transmit")
    try:
        signature = inspect.signature(transmit)
    except (TypeError, ValueError):
        data, sw1, sw2 = transmit(bytes(apdu))
    else:
        if "timeout_ms" in signature.parameters:
            data, sw1, sw2 = transmit(bytes(apdu), timeout_ms=timeout_ms)
        else:
            data, sw1, sw2 = transmit(bytes(apdu))
    return bytes(data), int(sw1), int(sw2)


def _build_card_channel(config: CardBridgeConfig) -> Any:
    factory = config.card_channel_factory or _default_pcsc_channel_factory
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):
        return factory(config.reader_index, config.reader_name, config.pcsc_share_mode)

    parameters = tuple(signature.parameters.values())
    accepts_varargs = any(
        parameter.kind == inspect.Parameter.VAR_POSITIONAL
        for parameter in parameters
    )
    positional_count = sum(
        1
        for parameter in parameters
        if parameter.kind
        in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
        )
    )
    if accepts_varargs or positional_count >= 3:
        return factory(config.reader_index, config.reader_name, config.pcsc_share_mode)
    return factory(config.reader_index, config.reader_name)


def _emit_startup_banner(
    config: CardBridgeConfig,
    relay: HilBridgeApduRelayService,
    *,
    reader_label: str,
    atr_hex: str,
    output: Any,
) -> None:
    """Print the human-readable startup summary.

    The full token never appears here — operators reconcile via the
    fingerprint and the on-disk file path. ``output`` is parameterised
    so tests can capture the lines without touching real stdout.
    """
    banner_lines: list[str] = []
    banner_lines.append("=" * 72)
    banner_lines.append("YggdraSIM Card Bridge — ready")
    banner_lines.append("=" * 72)
    banner_lines.append(f"  reader     : {reader_label}")
    banner_lines.append(f"  ATR        : {atr_hex or '(unknown)'}")
    banner_lines.append(f"  apdu URL   : {relay.apdu_url}")
    banner_lines.append(f"  status URL : {relay.status_url}")
    if len(config.auth_token) > 0:
        banner_lines.append(f"  token      : <redacted, fingerprint {token_fingerprint(config.auth_token)}>")
        if config.token_file is not None:
            verb = "written" if config.token_file_was_written else "loaded"
            banner_lines.append(f"  token file : {config.token_file}  ({verb}, mode 0600)")
    else:
        banner_lines.append("  token      : (none — loopback only)")
    if config.audit_enabled is True:
        marker = " (FULL APDU + response — captures PINs!)" if config.audit_full_apdu else ""
        banner_lines.append(f"  audit log  : enabled via logger '{config.audit_logger_name}'{marker}")
    if is_loopback_host(config.host) is True:
        banner_lines.append(
            "  ssh tunnel : rig$ ssh -fN -L "
            f"{config.port}:127.0.0.1:{config.port} <reader-host>"
        )
        banner_lines.append(
            "               or reader-host$ ssh -fN -R "
            f"{config.port}:127.0.0.1:{config.port} <rig-host>"
        )
    else:
        banner_lines.append(
            f"  remote use : non-loopback bind {config.host}:{config.port} — TLS termination is your responsibility"
        )
    # Self-documenting copy-paste template for the rig side. Pairs the
    # SSH tunnel above with the matching ``yggdrasim-hil-bridge`` flags
    # so the operator can drop the line straight into the rig shell.
    token_file_hint = (
        str(config.token_file) if config.token_file is not None else "<token-file>"
    )
    banner_lines.append(
        "  rig flags  : --remote-card-url http://127.0.0.1:"
        f"{config.port}/apdu --remote-card-token-file {token_file_hint}"
    )
    banner_lines.append("=" * 72)
    for line in banner_lines:
        print(line, file=output)
    output.flush()


def run_card_bridge(
    config: CardBridgeConfig,
    *,
    output: Any | None = None,
    stop_event: threading.Event | None = None,
) -> int:
    """Open the local card, start the relay, and block until shutdown.

    Returns a process exit code. Designed to be callable from a unit
    test by passing in a pre-set ``stop_event`` so the function returns
    instead of waiting on a signal handler.
    """
    if output is None:
        output = sys.stdout
    if stop_event is None:
        stop_event = threading.Event()

    channel = _build_card_channel(config)

    try:
        channel.connect()
    except Exception as connect_error:
        raise CardBridgeError(
            f"Cannot open PC/SC reader: {connect_error}"
        ) from connect_error

    state = {
        "reader_label": str(getattr(channel, "reader_label", "") or "PC/SC reader"),
        "atr_hex": "",
    }

    def refresh_card_state() -> None:
        state["reader_label"] = str(getattr(channel, "reader_label", "") or "PC/SC reader")
        try:
            atr_value = channel.get_atr()
            if isinstance(atr_value, (bytes, bytearray)):
                state["atr_hex"] = bytes(atr_value).hex().upper()
            else:
                state["atr_hex"] = bytes(atr_value).hex().upper()
        except Exception:
            state["atr_hex"] = ""

    refresh_card_state()

    def exchange_callback(apdu: bytes, *, session_id: str = "") -> tuple[bytes, int, int]:
        del session_id
        return _transmit_with_optional_timeout(
            channel,
            bytes(apdu),
            timeout_ms=config.apdu_timeout_ms,
        )

    def status_callback() -> dict[str, Any]:
        return {
            "pid": os.getpid(),
            "reader": state["reader_label"],
            "atr": state["atr_hex"],
            "card": "available" if len(state["atr_hex"]) > 0 else "unknown",
            "apduTimeoutMs": int(config.apdu_timeout_ms),
        }

    def card_reset_callback(*, session_id: str = "") -> dict[str, Any]:
        del session_id
        reset_method = getattr(channel, "reset_card", None)
        reset_payload: dict[str, Any] = {}
        if callable(reset_method):
            maybe_payload = reset_method()
            if isinstance(maybe_payload, dict):
                reset_payload = dict(maybe_payload)
        else:
            reconnect_method = getattr(channel, "reconnect", None)
            if callable(reconnect_method):
                reconnect_method()
                reset_payload = {"mode": "reconnect"}
            else:
                channel.disconnect()
                channel.connect()
                reset_payload = {"mode": "disconnect-connect"}
        refresh_card_state()
        return {
            "status": "reset",
            "reader": state["reader_label"],
            "atr": state["atr_hex"],
            "reset": reset_payload,
        }

    relay = HilBridgeApduRelayService(
        ApduRelayConfig(
            host=config.host,
            port=config.port,
            enabled=True,
            auth_token=config.auth_token,
            audit_enabled=config.audit_enabled,
            audit_full_apdu=config.audit_full_apdu,
            audit_logger_name=config.audit_logger_name,
        ),
        exchange_callback=exchange_callback,
        status_callback=status_callback,
        card_reset_callback=card_reset_callback,
    )

    try:
        relay.start()
    except Exception as start_error:
        try:
            channel.disconnect()
        except Exception:
            pass
        raise CardBridgeError(f"Cannot start relay: {start_error}") from start_error

    _emit_startup_banner(
        config, relay, reader_label=state["reader_label"], atr_hex=state["atr_hex"], output=output
    )

    try:
        stop_event.wait()
    finally:
        try:
            relay.stop()
        except Exception:
            pass
        try:
            channel.disconnect()
        except Exception:
            pass

    return EXIT_OK


def _install_signal_handlers(stop_event: threading.Event) -> None:
    """Hook SIGINT / SIGTERM so ctrl-C and `kill <pid>` shut down cleanly."""

    def _on_signal(signum, _frame) -> None:
        del signum
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            # ValueError fires when called from a non-main thread (e.g.
            # in some test harnesses); OSError on platforms that
            # don't support the signal. Either way the caller can
            # still set ``stop_event`` directly.
            pass


def main(argv: list[str] | None = None) -> int:
    parser = _build_argument_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else EXIT_USAGE

    logging.basicConfig(
        level=os.environ.get("YGGDRASIM_CARD_BRIDGE_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    try:
        config = build_config_from_args(args)
    except CardBridgeError as exc:
        print(f"card-bridge: {exc}", file=sys.stderr)
        return EXIT_USAGE

    stop_event = threading.Event()
    _install_signal_handlers(stop_event)

    try:
        return run_card_bridge(config, stop_event=stop_event)
    except CardBridgeError as exc:
        print(f"card-bridge: {exc}", file=sys.stderr)
        return EXIT_RUNTIME
