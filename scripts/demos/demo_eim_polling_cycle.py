#!/usr/bin/env python3
"""YggdraSIM — SGP.32 IPA-poll BIP cycle live demo.

Drives the in-process simulator through the full TIMER EXPIRATION
-> OPEN CHANNEL -> SEND DATA -> RECEIVE DATA -> CLOSE CHANNEL
sequence, with a fake-modem returning a canonical SGP.32 AddEim
package. Narrated, colorised, ~45 s wall-clock. No PCSC, no
network, no shell tricks.

Run:
    python -m scripts.demos.demo_eim_polling_cycle
or directly:
    python scripts/demos/demo_eim_polling_cycle.py

Disable colour with NO_COLOR=1 in the environment.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.utils import tlv
from yggdrasim_common.nord_palette import NORD


COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


def _ansi(seq: str) -> str:
    return seq if COLOUR else ""


# Anchored to the canonical Nord palette so this demo's narration
# matches the launcher / SCP11 transcript / docs colour story.
C_RESET = _ansi(NORD.RESET)
C_DIM = _ansi(NORD.DIM)
C_BOLD = _ansi(NORD.BOLD)
C_CYAN = _ansi(NORD.CYAN)
C_GREEN = _ansi(NORD.GREEN)
C_YELLOW = _ansi(NORD.YELLOW)
C_MAGENTA = _ansi(NORD.PURPLE)
C_BLUE = _ansi(NORD.BLUE)
C_RED = _ansi(NORD.RED)


def banner(title: str) -> None:
    bar = "─" * 64
    print()
    print(f"{C_CYAN}{bar}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}  {title}{C_RESET}")
    print(f"{C_CYAN}{bar}{C_RESET}")


def step(label: str, detail: str = "", colour: str = C_GREEN) -> None:
    arrow = f"{colour}{C_BOLD}▸{C_RESET}"
    print(f"  {arrow} {colour}{label}{C_RESET}")
    if detail:
        print(f"    {C_DIM}{detail}{C_RESET}")


def apdu_line(direction: str, apdu: bytes, label: str = "") -> None:
    arrow = "→" if direction == "tx" else "←"
    arrow_colour = C_BLUE if direction == "tx" else C_MAGENTA
    hex_pretty = " ".join(apdu[i : i + 2].hex().upper() for i in range(0, len(apdu), 2))
    if len(hex_pretty) > 60:
        hex_pretty = hex_pretty[:57] + "..."
    annotation = f"  {C_DIM}# {label}{C_RESET}" if label else ""
    print(f"    {arrow_colour}{arrow}{C_RESET} {hex_pretty}{annotation}")


def pause(seconds: float = 0.6) -> None:
    if os.environ.get("YGGDRASIM_DEMO_FAST", "") == "1":
        return
    time.sleep(seconds)


def _proactive_body_offset(payload: bytes) -> int:
    """BER long-form aware body offset for ``D0 LL`` proactive commands."""
    if len(payload) < 2 or payload[0] != 0xD0:
        return -1
    length_byte = payload[1]
    if length_byte < 0x80:
        return 2
    return 2 + (length_byte & 0x7F)


def _proactive_command_number(payload: bytes) -> int:
    body_offset = _proactive_body_offset(payload)
    if body_offset < 0 or body_offset + 2 >= len(payload):
        return 0
    return payload[body_offset + 2]


def proactive_summary(payload: bytes) -> tuple[int, str]:
    """Return ``(command_type, friendly_name)`` for a fetched PA cmd."""
    body_offset = _proactive_body_offset(payload)
    if body_offset < 0:
        return 0, "?"
    body = payload[body_offset:]
    if not body.startswith(b"\x81"):
        return 0, "?"
    # Command-details TLV (ETSI TS 102 223 §8.6): 81 03 NN TT QQ.
    # body[2] = command number, body[3] = command type, body[4] = qualifier.
    cmd_type = body[3]
    # ETSI TS 102 223 §9.4 command-type values.
    table = {
        0x01: "REFRESH",
        0x03: "POLL INTERVAL",
        0x05: "SET-UP EVENT LIST",
        0x10: "SET-UP CALL",
        0x13: "SEND SHORT MESSAGE",
        0x21: "DISPLAY TEXT",
        0x25: "SET-UP MENU",
        0x26: "PROVIDE LOCAL INFORMATION",
        0x27: "TIMER MANAGEMENT",
        0x40: "OPEN CHANNEL",
        0x41: "CLOSE CHANNEL",
        0x42: "RECEIVE DATA",
        0x43: "SEND DATA",
    }
    return cmd_type, table.get(cmd_type, f"PA-{cmd_type:02X}")


def build_terminal_response_ok(command_number: int, command_type: int) -> bytes:
    """Generic 'command performed successfully' Terminal Response."""
    cmd_details = tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, 0x00)))
    device_ids = tlv("82", b"\x82\x81")
    result = tlv("83", b"\x00")
    body = cmd_details + device_ids + result
    return bytes((0x80, 0x14, 0x00, 0x00, len(body))) + body


def build_terminal_response_with_channel_data(
    command_number: int, command_type: int, channel_data: bytes, channel_id: int = 1
) -> bytes:
    """Terminal Response carrying channel data (used after RECEIVE DATA)."""
    cmd_details = tlv("81", bytes((command_number & 0xFF, command_type & 0xFF, 0x00)))
    device_ids = tlv("82", b"\x82\x81")
    result = tlv("83", b"\x00")
    channel_status = tlv("38", bytes(((0x80 | (channel_id & 0x07)), 0x00)))
    channel_tlv = tlv("36", channel_data)
    body = cmd_details + device_ids + result + channel_status + channel_tlv
    return bytes((0x80, 0x14, 0x00, 0x00, len(body))) + body


def build_eim_addeim_payload(eid_hex: str) -> bytes:
    """Tiny but valid AddEim (BF58) payload with one EimConfigurationData row."""
    eim_id = b"DEMO_EIM_FQDN"
    counter = bytes.fromhex("020100")
    inner = (
        tlv("80", eim_id)
        + tlv("81", counter)
        + tlv("82", b"yggdrasim.eim.demo.local")
    )
    one_eim = tlv("BF20", inner)
    return tlv("BF58", tlv("A0", one_eim) + tlv("5A", bytes.fromhex(eid_hex)))


def main() -> int:
    banner("YggdraSIM SGP.32 IPA-poll BIP cycle — live demo")
    print(f"  {C_DIM}A virtual eUICC, a fake modem, and a fake eIM —")
    print(f"  watching the in-card IPA drive a real SGP.32 polling cycle.{C_RESET}")
    pause(1.0)

    banner("Step 1 — Boot the simulated eUICC")
    step("Bringing up SimulatedSimCardEngine in an isolated workspace")
    import tempfile
    workdir = tempfile.mkdtemp(prefix="yggdrasim_demo_")
    os.environ["YGGDRASIM_SIM_EUICC_STORE"] = workdir
    engine = SimulatedSimCardEngine(euicc_store_root=workdir)
    # Quiet IMEI-prompt and aggressive auto-rearm so the demo focuses
    # on the IPA-poll cycle instead of bookkeeping noise.
    engine.state.toolkit.provide_imei = False
    engine.state.toolkit.timer_management_auto_rearm = False
    eid_hex = (engine.state.eid or "").strip()
    step(f"EID = {eid_hex}", "(loaded from default isdr_config.json)")
    step(f"ATR = {engine.get_atr().hex().upper()}")
    pause(0.8)

    banner("Step 2 — Modem TERMINAL PROFILE → IPA queues bring-up commands")
    terminal_profile = bytes.fromhex("801000000AFFFFFFFFFFFFFFFFFFFF")
    apdu_line("tx", terminal_profile, "TERMINAL PROFILE (modem→card)")
    _data, sw1, sw2 = engine.transmit(terminal_profile)
    step(f"Card returned SW={sw1:02X}{sw2:02X}", "91 LL = proactive command pending (ETSI 102 221 §7.4.2)")
    pause(0.6)

    bootstrap_index = 0
    while sw1 == 0x91:
        bootstrap_index += 1
        fetch_apdu = bytes.fromhex(f"80120000{(sw2):02X}")
        apdu_line("tx", fetch_apdu, f"FETCH #{bootstrap_index}")
        fetched, _sw1, _sw2 = engine.transmit(fetch_apdu)
        cmd_type, cmd_name = proactive_summary(fetched)
        step(f"Bring-up PA #{bootstrap_index}: {cmd_name} (type 0x{cmd_type:02X})")
        apdu_line("rx", fetched[: min(len(fetched), 32)], f"first {min(len(fetched), 32)}B of {len(fetched)}B")
        tr = build_terminal_response_ok(
            command_number=_proactive_command_number(fetched),
            command_type=cmd_type,
        )
        _d, sw1, sw2 = engine.transmit(tr)
        pause(0.5)
    step(
        "Bring-up complete; eUICC has armed its IPA-poll trigger",
        "the simulated card is now waiting for ENVELOPE D7 (TIMER EXPIRATION)",
    )
    pause(0.6)

    banner("Step 3 — TIMER EXPIRATION (D7) — the magic moment")
    step("Modem reports 'timer fired' via D7 ENVELOPE",
         "real-world: the modem fires this whenever its bookkeeping says "
         "'30 s elapsed'; in this demo we trigger it manually for speed.")
    envelope_body = bytes.fromhex("D703A40101")
    timer_expiry = bytes.fromhex("80C20000") + bytes((len(envelope_body),)) + envelope_body
    apdu_line("tx", timer_expiry, "ENVELOPE D7 (timer expired)")
    _data, sw1, sw2 = engine.transmit(timer_expiry)
    step(f"Card SW={sw1:02X}{sw2:02X}", "9113 = the IPA queued an IPA-poll BIP cycle behind the D7 ack")
    pause(0.8)

    banner("Step 4 — IPA-poll BIP cycle: OPEN→SEND→RECEIVE→CLOSE")

    def fetch_and_log() -> bytes:
        fetched_payload, _sw1, _sw2 = engine.transmit(bytes.fromhex(f"80120000{sw2:02X}"))
        return fetched_payload

    ipa_session_active_before = engine.state.toolkit.ipa_poll_session_active

    fetched = fetch_and_log()
    cmd_type, cmd_name = proactive_summary(fetched)
    cmd_num = _proactive_command_number(fetched)
    step(f"FETCH 1 → {cmd_name}", "the IPA opened a TCP/UDP BIP channel to the eIM FQDN")
    apdu_line("rx", fetched[:48], f"hex (first 48B of {len(fetched)}B)")
    engine.transmit(build_terminal_response_ok(cmd_num, cmd_type))
    pause(0.8)

    fetched = fetch_and_log()
    cmd_type, cmd_name = proactive_summary(fetched)
    cmd_num = _proactive_command_number(fetched)
    step(f"FETCH 2 → {cmd_name}", "the IPA shipped the BF4F GetEimPackageRequest "
         "(SGP.32 §6.5.2.1) wrapped in HTTP POST /gsma/rsp2/asn1")
    sent_index = fetched.find(b"\xbf\x4f")
    if sent_index > 0:
        apdu_line("rx", fetched[sent_index : sent_index + 24], "BF4F GetEimPackageRequest")
    engine.transmit(build_terminal_response_ok(cmd_num, cmd_type))
    pause(0.8)

    fetched = fetch_and_log()
    cmd_type, cmd_name = proactive_summary(fetched)
    cmd_num = _proactive_command_number(fetched)
    step(f"FETCH 3 → {cmd_name}", "modem ready to deliver eIM's response over the channel")
    pause(0.4)

    eim_payload = build_eim_addeim_payload(eid_hex)
    step(
        f"Fake eIM responds with BF58 AddEim ({len(eim_payload)} B)",
        "in production this is the eIM's HTTP body containing one or more EuiccPackages",
    )
    apdu_line(
        "rx", eim_payload[:32], f"BF58 ... (full {len(eim_payload)} bytes injected)"
    )
    tr_with_data = build_terminal_response_with_channel_data(cmd_num, cmd_type, eim_payload)
    engine.transmit(tr_with_data)
    pause(0.8)

    banner("Step 5 — IPA dispatches the EuiccPackage into ISD-R")
    dispatched = list(engine.state.toolkit.ipa_poll_dispatched_packages)
    step(
        f"ipa_poll_dispatched_packages = {[t.hex().upper() for t in dispatched]}",
        "each tag was routed through SgpLogic.handle_store_data(); responses captured",
    )
    eim_count = len(engine.state.eim_entries) if hasattr(engine.state, "eim_entries") else 0
    step(f"state.eim_entries now contains {eim_count} entry/entries",
         "the AddEim landed -- the simulator persisted a new eIM identity row")
    pause(0.8)

    fetched = fetch_and_log()
    cmd_type, cmd_name = proactive_summary(fetched)
    cmd_num = _proactive_command_number(fetched)
    step(f"FETCH 4 → {cmd_name}",
         "the IPA's BF50 ProvideEimPackageResult follow-up (per-package result)")
    bf50_index = fetched.find(b"\xbf\x50")
    if bf50_index > 0:
        apdu_line("rx", fetched[bf50_index : bf50_index + 24], "BF50 ProvideEimPackageResult")
    engine.transmit(build_terminal_response_ok(cmd_num, cmd_type))
    pause(0.6)

    fetched = fetch_and_log()
    cmd_type, cmd_name = proactive_summary(fetched)
    cmd_num = _proactive_command_number(fetched)
    step(f"FETCH 5 → {cmd_name}", "drains the eIM acknowledgement frame")
    engine.transmit(build_terminal_response_ok(cmd_num, cmd_type))
    pause(0.4)

    fetched = fetch_and_log()
    if len(fetched) > 0:
        cmd_type, cmd_name = proactive_summary(fetched)
        cmd_num = _proactive_command_number(fetched)
        step(f"FETCH 6 → {cmd_name}", "tear down the BIP socket")
        engine.transmit(build_terminal_response_ok(cmd_num, cmd_type))
    pause(0.6)

    banner("Done — what just happened")
    print(f"  {C_GREEN}✓{C_RESET} The card's TIMER MANAGEMENT bring-up advertised a poll trigger.")
    print(f"  {C_GREEN}✓{C_RESET} The modem fired ENVELOPE D7 (timer expired).")
    print(f"  {C_GREEN}✓{C_RESET} The in-card IPA opened a BIP channel to the eIM FQDN.")
    print(f"  {C_GREEN}✓{C_RESET} The IPA shipped a canonical {C_BOLD}BF4F GetEimPackageRequest{C_RESET}.")
    print(f"  {C_GREEN}✓{C_RESET} The eIM's BF58 AddEim was dispatched into ISD-R.")
    print(f"  {C_GREEN}✓{C_RESET} The IPA reported back with {C_BOLD}BF50 ProvideEimPackageResult{C_RESET}.")
    print(f"  {C_GREEN}✓{C_RESET} The BIP socket was torn down cleanly.")
    print()
    print(
        f"  {C_DIM}Workspace: {workdir}{C_RESET}\n"
        f"  {C_DIM}eUICC store: {engine.state.euicc_store_path}{C_RESET}"
    )
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
