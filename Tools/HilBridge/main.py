# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge package entry point."""
from __future__ import annotations

import argparse
import logging
import signal
import threading
from typing import Any

from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested

from .pcsc import APDU_TIMEOUT_ENV, PcscBridgeError, PcscCardChannel, resolve_apdu_timeout_ms
from .protocol import GSMTAP_COMPAT_MODES, GSMTAP_COMPAT_NATIVE
from .router import CARD_TRACE_ENV, BridgeConfig, HilBridgeServer, resolve_card_trace_enabled


def add_bridge_runtime_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_list_readers: bool = True,
) -> None:
    """Add HIL-Bridge runtime argparse arguments to *parser*."""
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Listen address for the TCP bridge")
    parser.add_argument("--port", type=int, default=9997, help="Listen port for both control and bankd sockets")
    parser.add_argument(
        "--advertise-host",
        type=str,
        default="127.0.0.1",
        help="IPv4/IPv6 address advertised back to osmo-remsim-client-st2 for the bankd socket",
    )
    parser.add_argument(
        "--apdu-relay-host",
        type=str,
        default="127.0.0.1",
        help="Bind address for the local APDU relay used by other YggdraSIM modules.",
    )
    parser.add_argument(
        "--apdu-relay-port",
        type=int,
        default=0,
        help="Bind port for the local APDU relay. Use 0 to auto-select a free port.",
    )
    parser.add_argument("--no-apdu-relay", action="store_true", help="Disable the local APDU relay side-channel")
    parser.add_argument("--reader-index", type=int, default=0, help="PC/SC reader index to use")
    parser.add_argument(
        "--reader-name",
        "--reader",
        dest="reader_name",
        type=str,
        default="",
        help="Case-insensitive substring match for the PC/SC reader name",
    )
    parser.add_argument(
        "--remote-card-url",
        type=str,
        default="",
        help=(
            "Stream APDUs from a remote 'yggdrasim-card-bridge' instance "
            "(e.g. http://127.0.0.1:8642/apdu after opening an SSH "
            "LocalForward from the rig, or a RemoteForward from the "
            "reader host). When set, the "
            "local --reader-index / --reader-name flags are ignored. "
            "Mirrors the YGGDRASIM_HIL_REMOTE_CARD_URL environment variable."
        ),
    )
    parser.add_argument(
        "--remote-card-token-file",
        type=str,
        default="",
        help=(
            "Path to a 0600-mode bearer-token file matching the token "
            "the remote 'yggdrasim-card-bridge' wrote on startup. "
            "Mirrors YGGDRASIM_HIL_REMOTE_CARD_TOKEN_FILE."
        ),
    )
    parser.add_argument(
        "--apdu-timeout-ms",
        type=int,
        default=None,
        help=(
            "Maximum APDU wait time in milliseconds for HIL card traffic "
            f"(default from {APDU_TIMEOUT_ENV}, fallback 5000)."
        ),
    )
    if include_list_readers:
        parser.add_argument("--list-readers", action="store_true", help="List available PC/SC readers and exit")
    parser.add_argument("--client-id", type=int, default=0, help="Client ID assigned to the modem slot")
    parser.add_argument("--client-slot", type=int, default=0, help="Client slot number assigned to the modem slot")
    parser.add_argument("--bank-id", type=int, default=1, help="Synthetic bank ID exposed to the client")
    parser.add_argument("--bank-slot", type=int, default=0, help="Synthetic bank slot exposed to the client")
    parser.add_argument("--bridge-name", type=str, default="yggdrasim-hil-bridge", help="RSPRO identity name")
    parser.add_argument(
        "--bridge-software",
        type=str,
        default="YggdraSIM HIL bridge",
        help="RSPRO software identity string",
    )
    parser.add_argument("--bridge-version", type=str, default="0.1", help="RSPRO software version string")
    parser.add_argument("--gsmtap-host", type=str, default="127.0.0.1", help="GSMTAP UDP destination host")
    parser.add_argument("--gsmtap-port", type=int, default=4729, help="GSMTAP UDP destination port")
    parser.add_argument(
        "--gsmtap-capture-path",
        type=str,
        default="",
        help="Optional local pcap path that receives mirrored GSMTAP packets without interface capture.",
    )
    parser.add_argument(
        "--gsmtap-capture-mirror-fifo-path",
        type=str,
        default="",
        help=(
            "Optional named pipe that mirrors the pcap stream for live tshark consumption. "
            "Created on demand; the writer drops packets while no reader is attached."
        ),
    )
    parser.add_argument(
        "--gsmtap-compat",
        type=str,
        default=GSMTAP_COMPAT_NATIVE,
        choices=sorted(GSMTAP_COMPAT_MODES),
        help="GSMTAP compatibility mode. Use wireshark44 for legacy Wireshark SIM dissectors.",
    )
    parser.add_argument("--no-gsmtap", action="store_true", help="Disable GSMTAP Wireshark mirroring")
    parser.add_argument(
        "--card-trace",
        action="store_true",
        default=resolve_card_trace_enabled(),
        help=(
            "Log every APDU at the physical-card boundary. "
            f"Can also be enabled with {CARD_TRACE_ENV}=1."
        ),
    )


def build_bridge_config_from_args(args: argparse.Namespace) -> BridgeConfig:
    """Build the bridge runtime config dict from parsed argparse namespace."""
    return BridgeConfig(
        listen_host=str(args.host),
        listen_port=int(args.port),
        advertise_host=str(args.advertise_host),
        apdu_relay_host=str(args.apdu_relay_host),
        apdu_relay_port=int(args.apdu_relay_port),
        apdu_relay_enabled=not bool(args.no_apdu_relay),
        reader_index=int(args.reader_index),
        reader_name=str(args.reader_name or ""),
        remote_card_url=str(getattr(args, "remote_card_url", "") or "").strip(),
        remote_card_token_file=str(
            getattr(args, "remote_card_token_file", "") or ""
        ).strip(),
        apdu_timeout_ms=resolve_apdu_timeout_ms(
            getattr(args, "apdu_timeout_ms", None)
        ),
        client_id=int(args.client_id),
        client_slot=int(args.client_slot),
        bank_id=int(args.bank_id),
        bank_slot=int(args.bank_slot),
        bridge_name=str(args.bridge_name),
        bridge_software=str(args.bridge_software),
        bridge_version=str(args.bridge_version),
        gsmtap_host=str(args.gsmtap_host),
        gsmtap_port=int(args.gsmtap_port),
        gsmtap_enabled=not bool(args.no_gsmtap),
        gsmtap_compat_mode=str(args.gsmtap_compat),
        gsmtap_capture_path=str(args.gsmtap_capture_path or "").strip(),
        gsmtap_capture_mirror_fifo_path=str(
            getattr(args, "gsmtap_capture_mirror_fifo_path", "") or ""
        ).strip(),
        card_trace_enabled=bool(getattr(args, "card_trace", False)),
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="YggdraSIM hardware-in-the-loop SIM bridge")
    add_debug_argument(
        parser,
        help_text="Enable verbose bridge logging.",
    )
    add_bridge_runtime_arguments(parser, include_list_readers=True)
    return parser


def _configure_logging(debug_enabled: bool) -> None:
    level = logging.DEBUG if debug_enabled else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _format_signal_name(signum: int) -> str:
    try:
        return signal.Signals(signum).name
    except (ValueError, TypeError):
        return str(int(signum))


def build_stop_signal_handler(
    stop_event: threading.Event,
    *,
    logger: logging.Logger | None = None,
):
    """Return a signal handler function that gracefully stops the bridge server."""
    active_logger = logger or logging.getLogger(__name__)

    def _request_stop(signum: int, _frame: Any) -> None:
        active_logger.info("Bridge received %s; shutting down", _format_signal_name(signum))
        stop_event.set()

    return _request_stop


def _install_stop_signal_handlers(stop_event: threading.Event) -> None:
    handler = build_stop_signal_handler(stop_event)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)


def run_bridge_server(server: HilBridgeServer) -> int:
    """Start the HIL-Bridge server and block until it is stopped."""
    stop_event = threading.Event()
    _install_stop_signal_handlers(stop_event)
    try:
        server.serve_forever(stop_event=stop_event)
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Bridge interrupted; shutting down")
    finally:
        server.close()
    return 0


def run_standalone() -> int:
    """Parse CLI arguments and run the HIL-Bridge in standalone mode."""
    parser = _build_parser()
    args = parser.parse_args()
    debug_enabled = bool(getattr(args, "debug", False))
    set_global_debug(debug_enabled)
    _configure_logging(debug_enabled)

    if args.list_readers:
        try:
            readers = PcscCardChannel.list_reader_names()
        except PcscBridgeError as exc:
            raise SystemExit(str(exc)) from exc

        if len(readers) == 0:
            print("No PC/SC readers detected.")
            return 0

        for index, reader_name in enumerate(readers):
            print(f"{index}: {reader_name}")
        return 0

    config = build_bridge_config_from_args(args)

    server = HilBridgeServer(config)
    return run_bridge_server(server)


def entry() -> int:
    return run_standalone()


if __name__ == "__main__":
    try:
        raise SystemExit(run_standalone())
    except QuitAllRequested:
        raise SystemExit(0)
