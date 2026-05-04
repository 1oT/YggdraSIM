from __future__ import annotations

import shlex
from typing import Callable

from yggdrasim_common.quit_control import quit_all

from SCP03.config import Config
from SCP03.logic.stk import StkController


class StkShell:
    def __init__(self, transport, debug: bool = False) -> None:
        self.controller = StkController(transport, debug=debug)
        self._commands: dict[str, Callable[[str], bool]] = {
            "HELP": self._cmd_help,
            "INIT": self._cmd_init,
            "RESET": self._cmd_init,
            "APDU": self._cmd_apdu,
            "SMS": self._cmd_sms,
            "SMS-PP": self._cmd_sms,
            "QUEUE": self._cmd_queue,
            "DATA": self._cmd_data,
            "EVENT": self._cmd_event,
            "CALL": self._cmd_call,
            "LOCATION": self._cmd_location,
            "STATE": self._cmd_state,
            "HISTORY": self._cmd_history,
            "DEBUG": self._cmd_debug,
            "VERBOSE": self._cmd_debug,
            "EXIT": self._cmd_exit,
            "BACK": self._cmd_exit,
            "Q": self._cmd_exit,
            "QA": self._cmd_quit_all,
        }

    def _prompt(self) -> str:
        suffix = "IDLE"
        if self.controller.state.initialized:
            suffix = "READY"
        if self.controller.state.open_channel_active:
            suffix = "OPEN"
        return f"\n{Config.Colors.CYAN}[STK:{suffix}] > {Config.Colors.ENDC}"

    def _print_banner(self) -> None:
        print(f"\n{Config.Colors.HEADER}=== SCP03 STK Subsystem ==={Config.Colors.ENDC}")
        print("Running plain APDU STK bootstrap and event-download simulation on the active reader.")
        print("Use HELP for commands, EXIT to return to the SCP03 shell.")

    def _print_help(self, _arg: str = "") -> bool:
        print("\nCommands:")
        print("  INIT / RESET            - Reset session state and run STK terminal-profile bootstrap.")
        print("  APDU <hex>              - Send a raw APDU and auto-handle any proactive chain.")
        print("  SMS <tpdu_hex>          - Send an ENVELOPE (SMS-PP DOWNLOAD) using the provided TPDU.")
        print("  QUEUE <hex>             - Queue virtual channel data for later RECEIVE DATA.")
        print("  DATA [hex]              - Optionally queue bytes, then emit EVENT DOWNLOAD DATA AVAILABLE.")
        print("  EVENT <name|hex> [tlvs] - Send a generic EVENT DOWNLOAD envelope with optional extra TLVs.")
        print("  CALL CONNECTED [tlvs]   - Convenience wrapper for EVENT CALL-CONNECTED.")
        print("  CALL DISCONNECTED [tlvs]- Convenience wrapper for EVENT CALL-DISCONNECTED.")
        print("  LOCATION [status] [loc] - Emit LOCATION STATUS with optional status byte and location hex.")
        print("  STATE                   - Show current STK/virtual-channel state.")
        print("  HISTORY                 - Show recent proactive commands, triggers, and flow events.")
        print("  DEBUG / VERBOSE         - Toggle raw STK APDU logging.")
        print("  EXIT / BACK / Q         - Return to the SCP03 shell.")
        print("  QA                      - Exit YggdraSIM entirely.")
        print("")
        print("Event names:")
        print("  MT-CALL, CALL-CONNECTED, CALL-DISCONNECTED, LOCATION-STATUS,")
        print("  USER-ACTIVITY, IDLE-SCREEN, LANGUAGE-SELECTION, BROWSER-TERMINATION,")
        print("  DATA-AVAILABLE, CHANNEL-STATUS, ACCESS-TECHNOLOGY-CHANGE")
        return True

    def _print_state(self) -> None:
        print(f"\n{Config.Colors.HEADER}--- STK State ---{Config.Colors.ENDC}")
        for line in self.controller.format_state_lines():
            print(f"  {line}")

    def _print_history(self) -> None:
        print(f"\n{Config.Colors.HEADER}--- STK History ---{Config.Colors.ENDC}")
        for line in self.controller.format_history_lines():
            print(f"  {line}")

    def _print_new_activity(self, before_commands: int, before_flow: int) -> None:
        new_commands = self.controller.state.command_history[before_commands:]
        new_flow = self.controller.state.flow_events[before_flow:]
        if len(new_commands) > 0:
            print(f"{Config.Colors.CYAN}[*] Proactive chain:{Config.Colors.ENDC}")
            for item in new_commands:
                print(f"    {item}")
        if len(new_flow) > 0:
            print(f"{Config.Colors.CYAN}[*] Flow notes:{Config.Colors.ENDC}")
            for item in new_flow:
                print(f"    {item}")

    def _run_exchange(
        self,
        label: str,
        action: Callable[[], tuple[bytes, int, int]],
    ) -> bool:
        before_commands = len(self.controller.state.command_history)
        before_flow = len(self.controller.state.flow_events)
        data, sw1, sw2 = action()
        print(f"{Config.Colors.GREEN}[+] {label}: {sw1:02X}{sw2:02X}{Config.Colors.ENDC}")
        if len(data) > 0:
            print(f"    Data: {data.hex().upper()}")
        self._print_new_activity(before_commands, before_flow)
        return True

    def _run_init(self) -> bool:
        before_commands = len(self.controller.state.command_history)
        before_flow = len(self.controller.state.flow_events)
        self.controller.initialize()
        print(f"{Config.Colors.GREEN}[+] STK initialized.{Config.Colors.ENDC}")
        self._print_new_activity(before_commands, before_flow)
        return True

    def _cmd_help(self, arg: str = "") -> bool:
        return self._print_help(arg)

    def _cmd_init(self, _arg: str = "") -> bool:
        return self._run_init()

    def _cmd_apdu(self, arg: str) -> bool:
        cleaned = str(arg or "").strip()
        if len(cleaned) == 0:
            print(f"{Config.Colors.FAIL}[-] Usage: APDU <hex>{Config.Colors.ENDC}")
            return False
        return self._run_exchange("APDU", lambda: self.controller.send_apdu(cleaned))

    def _cmd_sms(self, arg: str) -> bool:
        tpdu_hex = str(arg or "").strip()
        if len(tpdu_hex) == 0:
            print(f"{Config.Colors.FAIL}[-] Usage: SMS <tpdu_hex>{Config.Colors.ENDC}")
            return False
        return self._run_exchange("SMS-PP DOWNLOAD", lambda: self.controller.send_sms_pp(tpdu_hex))

    def _cmd_queue(self, arg: str) -> bool:
        payload_hex = str(arg or "").strip()
        if len(payload_hex) == 0:
            print(f"{Config.Colors.FAIL}[-] Usage: QUEUE <hex>{Config.Colors.ENDC}")
            return False
        queued_total = self.controller.queue_channel_data(payload_hex)
        print(
            f"{Config.Colors.GREEN}[+] Queued channel data. "
            f"Pending bytes: {queued_total}{Config.Colors.ENDC}"
        )
        return True

    def _cmd_data(self, arg: str) -> bool:
        payload_hex = str(arg or "").strip()
        if len(payload_hex) > 0:
            queued_total = self.controller.queue_channel_data(payload_hex)
            print(
                f"{Config.Colors.CYAN}[*] Queued channel data before DATA AVAILABLE. "
                f"Pending bytes: {queued_total}{Config.Colors.ENDC}"
            )
        return self._run_exchange(
            "EVENT DOWNLOAD DATA AVAILABLE",
            self.controller.send_data_available_event,
        )

    def _cmd_event(self, arg: str) -> bool:
        parts = shlex.split(str(arg or "").strip())
        if len(parts) == 0:
            print(f"{Config.Colors.FAIL}[-] Usage: EVENT <name|hex> [extra_tlvs_hex]{Config.Colors.ENDC}")
            return False
        event_token = parts[0]
        extra_tlvs = ""
        if len(parts) > 1:
            extra_tlvs = "".join(parts[1:])
        return self._run_exchange(
            f"EVENT DOWNLOAD {event_token.upper()}",
            lambda: self.controller.send_event(event_token, extra_tlvs_hex=extra_tlvs),
        )

    def _cmd_call(self, arg: str) -> bool:
        parts = shlex.split(str(arg or "").strip())
        if len(parts) == 0:
            print(
                f"{Config.Colors.FAIL}[-] Usage: CALL CONNECTED|DISCONNECTED [extra_tlvs_hex]"
                f"{Config.Colors.ENDC}"
            )
            return False
        mode = parts[0].strip().upper()
        extra_tlvs = ""
        if len(parts) > 1:
            extra_tlvs = "".join(parts[1:])
        if mode == "CONNECTED":
            return self._run_exchange(
                "CALL CONNECTED",
                lambda: self.controller.simulate_call_connected(extra_tlvs_hex=extra_tlvs),
            )
        if mode == "DISCONNECTED":
            return self._run_exchange(
                "CALL DISCONNECTED",
                lambda: self.controller.simulate_call_disconnected(extra_tlvs_hex=extra_tlvs),
            )
        print(f"{Config.Colors.FAIL}[-] CALL expects CONNECTED or DISCONNECTED.{Config.Colors.ENDC}")
        return False

    def _cmd_location(self, arg: str) -> bool:
        parts = shlex.split(str(arg or "").strip())
        status_value = 0x00
        location_hex = ""
        if len(parts) > 0:
            raw_status = parts[0].strip()
            try:
                status_value = int(raw_status, 16)
            except ValueError:
                print(f"{Config.Colors.FAIL}[-] LOCATION status must be hex, e.g. 00.{Config.Colors.ENDC}")
                return False
        if len(parts) > 1:
            location_hex = "".join(parts[1:])
        return self._run_exchange(
            "LOCATION STATUS",
            lambda: self.controller.send_location_status(status_value=status_value, location_hex=location_hex),
        )

    def _cmd_state(self, _arg: str = "") -> bool:
        self._print_state()
        return True

    def _cmd_history(self, _arg: str = "") -> bool:
        self._print_history()
        return True

    def _cmd_debug(self, _arg: str = "") -> bool:
        new_value = not bool(self.controller.debug)
        self.controller.set_debug(new_value)
        state = "ON" if new_value else "OFF"
        print(f"{Config.Colors.WARNING}[*] STK debug logging is now {state}.{Config.Colors.ENDC}")
        return True

    def _cmd_exit(self, _arg: str = "") -> bool:
        raise SystemExit(0)

    def _cmd_quit_all(self, _arg: str = "") -> bool:
        quit_all()
        return True

    def _maybe_auto_initialize(self, first_command: str = "") -> None:
        if self.controller.state.initialized:
            return
        token = str(first_command or "").strip().upper()
        if token in ("", "HELP", "INIT", "RESET"):
            return
        self._run_init()

    def _exec_line(self, raw_line: str) -> bool:
        stripped = str(raw_line or "").strip()
        if len(stripped) == 0:
            return True
        if stripped.startswith("#"):
            return True
        parts = stripped.split(None, 1)
        command = parts[0].upper()
        argument = ""
        if len(parts) > 1:
            argument = parts[1]
        handler = self._commands.get(command)
        if handler is None:
            print(f"{Config.Colors.FAIL}[-] Unknown STK command: {command}{Config.Colors.ENDC}")
            return False
        try:
            return bool(handler(argument))
        except SystemExit:
            raise
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            print(f"{Config.Colors.FAIL}[-] {detail}{Config.Colors.ENDC}")
            return False

    def run_commands(self, cmd_line: str) -> None:
        commands = [chunk.strip() for chunk in str(cmd_line or "").split(";") if len(chunk.strip()) > 0]
        first_command = ""
        if len(commands) > 0:
            first_command = commands[0].split(None, 1)[0].upper()
        self._print_banner()
        self._maybe_auto_initialize(first_command)
        had_error = False
        for command_text in commands:
            try:
                succeeded = self._exec_line(command_text)
                if succeeded is False:
                    had_error = True
            except SystemExit as error:
                exit_code = error.code if isinstance(error.code, int) else 0
                if exit_code not in (0, None):
                    raise
                break
        if had_error:
            raise SystemExit(1)

    def run(self) -> None:
        self._print_banner()
        try:
            self._run_init()
        except Exception as error:
            detail = str(error).strip() or error.__class__.__name__
            print(f"{Config.Colors.FAIL}[-] Initial STK bootstrap failed: {detail}{Config.Colors.ENDC}")
        while True:
            try:
                line = input(self._prompt()).strip()
            except KeyboardInterrupt:
                print("\nType 'EXIT' to return to the SCP03 shell.")
                continue
            except EOFError:
                print("")
                return
            self._exec_line(line)
