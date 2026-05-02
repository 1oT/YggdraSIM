from __future__ import annotations

import argparse
import logging
import signal
import threading
from typing import Any

from yggdrasim_common.process_debug import add_debug_argument, set_global_debug
from yggdrasim_common.quit_control import QuitAllRequested

from .pcsc import PcscBridgeError, PcscCardChannel
from .protocol import GSMTAP_COMPAT_MODES, GSMTAP_COMPAT_NATIVE
from .router import BridgeConfig, HilBridgeServer


def add_bridge_runtime_arguments(
    parser: argparse.ArgumentParser,
    *,
    include_list_readers: bool = True,
) -> None:
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


def build_bridge_config_from_args(args: argparse.Namespace) -> BridgeConfig:
    return BridgeConfig(
        listen_host=str(args.host),
        listen_port=int(args.port),
        advertise_host=str(args.advertise_host),
        apdu_relay_host=str(args.apdu_relay_host),
        apdu_relay_port=int(args.apdu_relay_port),
        apdu_relay_enabled=not bool(args.no_apdu_relay),
        reader_index=int(args.reader_index),
        reader_name=str(args.reader_name or ""),
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
