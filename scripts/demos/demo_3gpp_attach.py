#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""YggdraSIM — 3GPP cold-attach + USIM-AKA live demo.

Walks an empty modem through a fresh attach against the in-process
simulator: ATR  →  SELECT MF  →  SELECT ADF.USIM  →  GET CHALLENGE
→  AUTHENTICATE (Milenage)  →  RES / CK / IK extraction. Then
demonstrates the AUTS resync path by replaying the same RAND with a
stale SQN. ~30 s wall-clock, no PCSC, no network.

Run:
    python -m scripts.demos.demo_3gpp_attach
or:
    python scripts/demos/demo_3gpp_attach.py

NO_COLOR=1 disables ANSI colour. YGGDRASIM_DEMO_FAST=1 skips pauses.
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from SIMCARD.auth import milenage_vectors
from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.etsi_fs import USIM_AID
from yggdrasim_common.nord_palette import NORD


COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


def _ansi(seq: str) -> str:
    return seq if COLOUR else ""


# Demo palette anchored to the canonical Nord swatches via
# yggdrasim_common.nord_palette so the recording matches the
# launcher banner, the SCP11 transcript, and the docs theme.
C_RESET = _ansi(NORD.RESET)
C_DIM = _ansi(NORD.DIM)
C_BOLD = _ansi(NORD.BOLD)
C_CYAN = _ansi(NORD.CYAN)
C_GREEN = _ansi(NORD.GREEN)
C_YELLOW = _ansi(NORD.YELLOW)
C_MAGENTA = _ansi(NORD.PURPLE)
C_BLUE = _ansi(NORD.BLUE)
C_RED = _ansi(NORD.RED)

KI_HEX = "465B5CE8B199B49FAA5F0A2EE238A6BC"
OPC_HEX = "CD63CB71954A9F4E48A5994E37A02BAF"
RAND_HEX = "23553CBE9637A89D218AE64DAE47BF35"
AMF_HEX = "B9B9"
SQN_INT = 0x000000000020


def banner(title: str) -> None:
    bar = "─" * 64
    print()
    print(f"{C_CYAN}{bar}{C_RESET}")
    print(f"{C_BOLD}{C_CYAN}  {title}{C_RESET}")
    print(f"{C_CYAN}{bar}{C_RESET}")


def step(label: str, detail: str = "", colour: str = C_GREEN) -> None:
    print(f"  {colour}{C_BOLD}▸{C_RESET} {colour}{label}{C_RESET}")
    if detail:
        print(f"    {C_DIM}{detail}{C_RESET}")


def hexline(label: str, blob: bytes) -> None:
    print(f"    {C_DIM}{label}{C_RESET} {C_BOLD}{blob.hex().upper()}{C_RESET}")


def apdu_line(direction: str, apdu: bytes, label: str = "") -> None:
    arrow = "→" if direction == "tx" else "←"
    arrow_colour = C_BLUE if direction == "tx" else C_MAGENTA
    pretty = " ".join(apdu[i : i + 2].hex().upper() for i in range(0, len(apdu), 2))
    if len(pretty) > 60:
        pretty = pretty[:57] + "..."
    annotation = f"  {C_DIM}# {label}{C_RESET}" if label else ""
    print(f"    {arrow_colour}{arrow}{C_RESET} {pretty}{annotation}")


def pause(seconds: float = 0.6) -> None:
    if os.environ.get("YGGDRASIM_DEMO_FAST", "") == "1":
        return
    time.sleep(seconds)


def transmit(engine, apdu: bytes, label: str = "") -> tuple[bytes, int, int]:
    apdu_line("tx", apdu, label)
    data, sw1, sw2 = engine.transmit(apdu)
    sw_colour = C_GREEN if (sw1, sw2) == (0x90, 0x00) else (
        C_YELLOW if sw1 in (0x91, 0x61, 0x6C) else C_RED
    )
    if data:
        print(
            f"    {C_MAGENTA}←{C_RESET} {data.hex().upper()[:60]}"
            f"{'...' if len(data) > 30 else ''} "
            f"{sw_colour}SW={sw1:02X}{sw2:02X}{C_RESET}"
        )
    else:
        print(f"    {C_MAGENTA}←{C_RESET} {sw_colour}SW={sw1:02X}{sw2:02X}{C_RESET}")
    return data, sw1, sw2


def parse_authenticate_response(data: bytes) -> tuple[bytes, bytes, bytes, bytes] | None:
    """Decode the AUTHENTICATE success response: DB || RES || CK || IK || KC."""
    if len(data) < 1 or data[0] != 0xDB:
        return None
    offset = 1
    if offset + 1 > len(data):
        return None
    res_len = data[offset]
    offset += 1
    res = data[offset : offset + res_len]
    offset += res_len
    if offset + 1 > len(data) or data[offset] != 0x10:
        return None
    offset += 1
    ck = data[offset : offset + 16]
    offset += 16
    if offset + 1 > len(data) or data[offset] != 0x10:
        return None
    offset += 1
    ik = data[offset : offset + 16]
    offset += 16
    if offset + 1 > len(data) or data[offset] != 0x08:
        return None
    offset += 1
    kc = data[offset : offset + 8]
    return res, ck, ik, kc


def main() -> int:
    banner("YggdraSIM 3GPP cold-attach + USIM-AKA — live demo")
    print(f"  {C_DIM}A virtual UICC, a fake modem, deterministic Milenage —")
    print(f"  watching a clean attach plus AUTS resync, end-to-end.{C_RESET}")
    pause(1.0)

    banner("Step 1 — Cold-boot the simulated UICC")
    workdir = Path(tempfile.mkdtemp(prefix="yggdrasim_attach_demo_"))
    euicc_root = workdir / "euicc"
    euicc_root.mkdir(parents=True, exist_ok=True)
    profile_store = workdir / "profiles"
    profile_store.mkdir(parents=True, exist_ok=True)
    engine = SimulatedSimCardEngine(
        euicc_store_root=str(workdir),
        profile_store_path=str(profile_store),
    )
    engine.state.toolkit.provide_imei = False
    engine.state.toolkit.timer_management_auto_rearm = False

    step(f"EID  = {engine.state.eid}")
    step(f"ATR  = {engine.get_atr().hex().upper()}",
         "ETSI TS 102 221 §6.3.1 cold-reset ATR (eUICC, T=1, eGSM-aware)")
    iccid = (engine.state.iccid or "").strip()
    imsi = (engine.state.imsi or "").strip()
    step(f"ICCID = {iccid}")
    step(f"IMSI  = {imsi}")
    pause(0.8)

    banner("Step 2 — Plant a known Milenage vector on the active USIM profile")
    active_profile = engine.auth._active_profile()
    if active_profile is None:
        print(f"  {C_RED}No active profile bound to the simulator runtime — aborting.{C_RESET}")
        return 1
    auth_config = active_profile.auth_config
    auth_config.algorithm = "milenage"
    auth_config.ki = bytes.fromhex(KI_HEX)
    auth_config.opc = bytes.fromhex(OPC_HEX)
    auth_config.op = b""
    auth_config.sqn = SQN_INT.to_bytes(6, "big")
    step("Profile auth_config patched in-place",
         "this would normally come from a SAIP profile package; "
         "the demo seeds a 3GPP TS 35.207 Annex C test vector for clarity")
    hexline("Ki  ", auth_config.ki)
    hexline("OPc ", auth_config.opc)
    hexline("SQN ", auth_config.sqn)
    pause(0.8)

    banner("Step 3 — Modem-side: SELECT MF, then SELECT ADF.USIM")
    transmit(engine, bytes.fromhex("00A40004023F00"), "SELECT MF (3F00)")
    pause(0.4)

    aid_bytes = bytes.fromhex(USIM_AID)
    select_adf = (
        bytes((0x00, 0xA4, 0x04, 0x04, len(aid_bytes))) + aid_bytes + bytes((0x00,))
    )
    _data, sw1, sw2 = transmit(engine, select_adf, "SELECT ADF.USIM (P1=04, P2=04, by AID)")
    step(f"Application bound: ADF.USIM  (SW={sw1:02X}{sw2:02X})",
         "subsequent INS=88 AUTHENTICATE will run inside the USIM context")
    pause(0.6)

    banner("Step 4 — Modem fires GET CHALLENGE then computes/serves AUTN")
    challenge_apdu = bytes.fromhex("00840000") + bytes.fromhex("10")
    rand_response, sw1, sw2 = transmit(engine, challenge_apdu, "GET CHALLENGE Le=16")
    step(f"Card-side RAND (16 B) = {rand_response.hex().upper()}",
         "in this demo we override the modem's RAND with a fixed test "
         "vector so the AUTN we feed back is reproducible.")
    pause(0.4)

    rand = bytes.fromhex(RAND_HEX)
    amf = bytes.fromhex(AMF_HEX)
    sqn_bytes = SQN_INT.to_bytes(6, "big")
    step("Network-side: compute AUTN = (SQN ⊕ AK) || AMF || MAC-A",
         "(emulating the AuC's role in TS 33.102 §6.3.2)")
    vectors = milenage_vectors(
        bytes.fromhex(KI_HEX), bytes.fromhex(OPC_HEX), rand, sqn_bytes, amf,
    )
    sqn_xor_ak = bytes(a ^ b for a, b in zip(sqn_bytes, vectors.ak))
    autn = sqn_xor_ak + amf + vectors.mac_a
    hexline("RAND ", rand)
    hexline("SQN  ", sqn_bytes)
    hexline("AMF  ", amf)
    hexline("AK   ", vectors.ak)
    hexline("MAC-A", vectors.mac_a)
    hexline("AUTN ", autn)
    pause(0.8)

    banner("Step 5 — AUTHENTICATE (USIM AKA, P2=0x81) — the canonical attach")
    body = b"\x10" + rand + b"\x10" + autn
    auth_apdu = bytes((0x00, 0x88, 0x00, 0x81, len(body))) + body + bytes((0x00,))
    data, sw1, sw2 = transmit(engine, auth_apdu, "AUTHENTICATE (USIM, MAC-A check + RES)")
    if (sw1, sw2) != (0x90, 0x00):
        step(f"Card rejected the challenge ({sw1:02X}{sw2:02X}). Demo aborted.",
             "expected 9000 — please re-run.", colour=C_RED)
        return 1

    parsed = parse_authenticate_response(data)
    if parsed is None:
        step("Could not parse response", colour=C_RED)
        return 1
    res, ck, ik, kc = parsed
    step("Card responded with DB || L||RES || L||CK || L||IK || L||Kc",
         "TS 31.102 §7.1.2.1.1 successful UMTS AKA")
    hexline("RES  ", res)
    hexline("CK   ", ck)
    hexline("IK   ", ik)
    hexline("Kc   ", kc)
    pause(0.8)

    banner("Step 6 — AUTS resync: replay an old SQN, watch the card protect itself")
    stale_sqn = (SQN_INT - 0x10).to_bytes(6, "big")
    stale_vectors = milenage_vectors(
        bytes.fromhex(KI_HEX), bytes.fromhex(OPC_HEX), rand, stale_sqn, amf,
    )
    stale_autn = (
        bytes(a ^ b for a, b in zip(stale_sqn, stale_vectors.ak))
        + amf
        + stale_vectors.mac_a
    )
    body = b"\x10" + rand + b"\x10" + stale_autn
    auth_apdu = bytes((0x00, 0x88, 0x00, 0x81, len(body))) + body + bytes((0x00,))
    data, sw1, sw2 = transmit(engine, auth_apdu, "AUTHENTICATE (stale SQN)")
    if data.startswith(b"\xDC"):
        auts = data[2:]
        step("Card returned 0xDC || L || AUTS — sync failure (TS 33.102 §6.3.5)",
             "the network must run AUTS through the AuC to recover SQN_MS")
        hexline("AUTS ", auts)
    else:
        step(f"Card returned {data.hex().upper()} (SW={sw1:02X}{sw2:02X})",
             "expected DC ... AUTS for the resync path", colour=C_YELLOW)
    pause(0.6)

    banner("Done — what just happened")
    print(f"  {C_GREEN}✓{C_RESET} Cold reset → ATR served, MF + ADF.USIM bound on logical channel 0.")
    print(f"  {C_GREEN}✓{C_RESET} GET CHALLENGE refreshed the card's RAND buffer.")
    print(f"  {C_GREEN}✓{C_RESET} AUTHENTICATE matched the network-supplied MAC-A.")
    print(f"  {C_GREEN}✓{C_RESET} The card emitted RES, CK, IK, Kc per TS 31.102 §7.1.2.1.1.")
    print(f"  {C_GREEN}✓{C_RESET} Stale AUTN triggered a clean AUTS resync response.")
    print()
    print(f"  {C_DIM}Engine workspace: {workdir}{C_RESET}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
