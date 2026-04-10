import argparse
import sys

from yggdrasim_common.plugin_runtime import ensure_plugins_loaded
from yggdrasim_common.process_debug import (
    add_debug_argument,
    is_global_debug_enabled,
    set_global_debug,
)
from yggdrasim_common.quit_control import QuitAllRequested
from yggdrasim_common.card_backend import is_simulated_card_backend

class SCP11StartupError(RuntimeError):
    """Readable SCP11 startup failure."""


def _load_runtime_components():
    try:
        from .config import SGPConfig
        from .console import SCP11Console
        from .factory import build_apdu_channel, build_profile_provider
        from .models import TRANSPORT_MODE_PCSC
        from .orchestrator import SGP22Orchestrator
    except ImportError:
        from SCP11.live.config import SGPConfig
        from SCP11.live.console import SCP11Console
        from SCP11.live.factory import build_apdu_channel, build_profile_provider
        from SCP11.live.models import TRANSPORT_MODE_PCSC
        from SCP11.live.orchestrator import SGP22Orchestrator
    return (
        SGPConfig,
        SCP11Console,
        build_apdu_channel,
        build_profile_provider,
        TRANSPORT_MODE_PCSC,
        SGP22Orchestrator,
    )


class SGP22Client:
    """Live-certificate SCP11 relay entrypoint."""

    def __init__(self):
        (
            config_cls,
            console_cls,
            build_apdu_channel,
            build_profile_provider,
            transport_mode_pcsc,
            orchestrator_cls,
        ) = _load_runtime_components()
        self._console_cls = console_cls
        self._build_apdu_channel = build_apdu_channel
        self._build_profile_provider = build_profile_provider
        self._transport_mode_pcsc = transport_mode_pcsc
        self._orchestrator_cls = orchestrator_cls
        self.cfg = config_cls()
        self.apdu_channel = None
        self.profile_provider = None
        self.orchestrator = None
        self.startup_warnings = []

    def _raise_startup_error(self, heading, lines):
        message = [heading]
        for line in lines:
            message.append(f"  - {line}")
        raise SCP11StartupError("\n".join(message))

    def _run_startup_preflight(self):
        errors, warnings = self.cfg.collect_startup_diagnostics()

        if self.cfg.TRANSPORT_MODE == self._transport_mode_pcsc and not is_simulated_card_backend():
            try:
                from smartcard.System import readers
            except Exception as error:
                errors.append(f"Unable to load PC/SC reader support: {error}")
            else:
                reader_list = readers()
                if len(reader_list) == 0:
                    errors.append("No smart card readers found for PC/SC transport.")
                elif self.cfg.READER_INDEX >= len(reader_list):
                    errors.append(
                        f"READER_INDEX {self.cfg.READER_INDEX} is out of range. Detected readers: {len(reader_list)}."
                    )

        if errors:
            combined = list(errors)
            if warnings:
                combined.append("Warnings detected:")
                combined.extend(warnings)
            self._raise_startup_error("SCP11 live startup preflight failed.", combined)

        self.startup_warnings = warnings

    def _build_runtime(self):
        if self.orchestrator is not None:
            return

        try:
            self.apdu_channel = self._build_apdu_channel(self.cfg)
        except Exception as error:
            raise SCP11StartupError(f"SCP11 live transport initialization failed: {error}") from error
        self._apply_global_debug()

        try:
            self.profile_provider = self._build_profile_provider(self.cfg)
        except Exception as error:
            raise SCP11StartupError(f"SCP11 live backend initialization failed: {error}") from error

        self.orchestrator = self._orchestrator_cls(
            cfg=self.cfg,
            apdu_channel=self.apdu_channel,
            profile_provider=self.profile_provider,
        )

    def _apply_global_debug(self) -> None:
        setter = getattr(self.apdu_channel, "set_raw_apdu_logging", None)
        if callable(setter):
            setter(bool(is_global_debug_enabled()))

    def _print_startup_warnings(self):
        return

    def run_flow(self):
        try:
            self._run_startup_preflight()
            self._build_runtime()
            self._print_startup_warnings()
            self.orchestrator.run_flow()
        except SCP11StartupError:
            raise
        except Exception as error:
            print(f"\n[CRITICAL ERROR] {error}")
            sys.exit(1)

    def run_shell(self):
        self._run_startup_preflight()
        self._build_runtime()
        self._print_startup_warnings()
        console = self._console_cls(self)
        console.run()

    def run_commands(self, cmd_line: str):
        self._run_startup_preflight()
        self._build_runtime()
        self._print_startup_warnings()
        console = self._console_cls(self)
        console.run_commands(cmd_line)


def entry() -> None:
    ensure_plugins_loaded()
    parser = argparse.ArgumentParser(description="SCP11 live relay orchestration shell")
    add_debug_argument(
        parser,
        help_text="Enable verbose debug output for this SCP11 live session.",
    )
    parser.add_argument(
        "--flow",
        action="store_true",
        help="Run one-shot SCP11 live relay flow instead of interactive shell",
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

    client = SGP22Client()
    if args.flow:
        client.run_flow()
        return
    if args.cmd:
        client.run_commands(args.cmd)
        return
    if args.stdin:
        command_lines = []
        for raw_line in sys.stdin.read().splitlines():
            command_text = str(raw_line or "").strip()
            if len(command_text) == 0:
                continue
            if command_text.startswith("#"):
                continue
            command_lines.append(command_text)
        client.run_commands("; ".join(command_lines))
        return
    client.run_shell()


if __name__ == "__main__":
    try:
        entry()
    except QuitAllRequested:
        sys.exit(0)
    except SCP11StartupError as error:
        print(f"\n[STARTUP ERROR] {error}")
        sys.exit(1)
