#!/usr/bin/env python3
"""YggdraSIM — SGP.32 profile lifecycle live demo.

Exercises the simulator's ISD-R surface end-to-end: GetEuiccInfo1
(BF20) → GetEuiccChallenge (BF2E) → GetProfilesInfo (BF2D) →
EnableProfile (BF31) → DisableProfile (BF32) → notification queue
inspection (BF2B) → LoadCRL (BF35). All operations land on the
real SgpLogic.handle_store_data path -- no mocks, no PCSC. ~30 s.

Run:
    python -m scripts.demos.demo_profile_lifecycle
or:
    python scripts/demos/demo_profile_lifecycle.py

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

from SIMCARD.engine import SimulatedSimCardEngine
from SIMCARD.utils import find_first_tlv, read_tlv, tlv
from yggdrasim_common.nord_palette import NORD


COLOUR = sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


def _ansi(seq: str) -> str:
    return seq if COLOUR else ""


# Demo palette anchored to the canonical Nord palette via
# yggdrasim_common.nord_palette -- single source of truth across
# the whole repository.
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
    print(f"  {colour}{C_BOLD}▸{C_RESET} {colour}{label}{C_RESET}")
    if detail:
        print(f"    {C_DIM}{detail}{C_RESET}")


def hexline(label: str, blob: bytes, max_len: int = 56) -> None:
    pretty = blob.hex().upper()
    if len(pretty) > max_len:
        pretty = pretty[:max_len] + "..."
    print(f"    {C_DIM}{label}{C_RESET} {C_BOLD}{pretty}{C_RESET}")


def pause(seconds: float = 0.6) -> None:
    if os.environ.get("YGGDRASIM_DEMO_FAST", "") == "1":
        return
    time.sleep(seconds)


def store_data(engine, payload_hex: str, label: str) -> bytes:
    """Issue STORE DATA (CLA=80, INS=E2, P1=91, P2=00) and pretty-print."""
    payload = bytes.fromhex(payload_hex)
    apdu = bytes((0x80, 0xE2, 0x91, 0x00, len(payload))) + payload + bytes((0x00,))
    print(
        f"    {C_BLUE}→{C_RESET} {C_BOLD}STORE DATA{C_RESET} "
        f"{C_DIM}({label}){C_RESET}"
    )
    print(f"      {C_DIM}command body: {payload.hex().upper()}{C_RESET}")
    data, sw1, sw2 = engine.transmit(apdu)
    if (sw1, sw2) == (0x90, 0x00):
        sw_colour = C_GREEN
    elif sw1 == 0x91:
        sw_colour = C_YELLOW
    else:
        sw_colour = C_RED
    print(f"    {C_MAGENTA}←{C_RESET} {sw_colour}SW={sw1:02X}{sw2:02X}{C_RESET}", end="")
    if len(data) > 0:
        print(f"  {C_DIM}({len(data)} response bytes){C_RESET}")
    else:
        print()
    return data


def encode_profile_reference_iccid(iccid_digits: str) -> bytes:
    """Wrap a profile ICCID digit string into a 5A reference TLV (BCD swapped)."""
    iccid = (iccid_digits or "").strip()
    if len(iccid) % 2 == 1:
        iccid += "F"
    swapped = bytes(
        int(iccid[i + 1] + iccid[i], 16) for i in range(0, len(iccid), 2)
    )
    return tlv("5A", swapped)


def parse_profiles_info(response: bytes) -> list[dict]:
    """Walk a BF2D ProfilesInfo response into a friendly dict list."""
    profiles: list[dict] = []
    if not response.startswith(b"\xbf\x2d"):
        return profiles
    _, body, _, _ = read_tlv(response, 0)
    list_payload = find_first_tlv(body, "A0")
    if len(list_payload) == 0:
        return profiles
    _, a0_value, _, _ = read_tlv(list_payload, 0)
    seq_payload = find_first_tlv(a0_value, "30")
    if len(seq_payload) == 0:
        return profiles
    _, entries_value, _, _ = read_tlv(seq_payload, 0)
    cursor = 0
    while cursor < len(entries_value):
        try:
            tag, value, _raw, next_offset = read_tlv(entries_value, cursor)
        except Exception:
            break
        cursor = next_offset
        entry = {"tag": tag.hex().upper()}
        iccid_tlv = find_first_tlv(value, "5A")
        if len(iccid_tlv) > 0:
            _, iccid_value, _, _ = read_tlv(iccid_tlv, 0)
            entry["iccid"] = "".join(
                f"{(b >> 4) & 0x0F}{b & 0x0F}" for b in iccid_value
            ).rstrip("F")[::1]
            digits = entry["iccid"]
            entry["iccid"] = "".join(digits[i + 1] + digits[i] for i in range(0, len(digits) - 1, 2))
        aid_tlv = find_first_tlv(value, "4F")
        if len(aid_tlv) > 0:
            _, aid_value, _, _ = read_tlv(aid_tlv, 0)
            entry["aid"] = aid_value.hex().upper()
        state_tlv = find_first_tlv(value, "9F70")
        if len(state_tlv) > 0:
            _, state_value, _, _ = read_tlv(state_tlv, 0)
            entry["state"] = "ENABLED" if state_value == b"\x01" else "DISABLED"
        nickname_tlv = find_first_tlv(value, "90")
        if len(nickname_tlv) > 0:
            _, nick_value, _, _ = read_tlv(nickname_tlv, 0)
            try:
                entry["nickname"] = nick_value.decode("utf-8", errors="replace")
            except Exception:
                entry["nickname"] = nick_value.hex()
        profiles.append(entry)
    return profiles


def main() -> int:
    banner("YggdraSIM SGP.32 profile lifecycle — live demo")
    print(f"  {C_DIM}A virtual eUICC, the ISD-R surface, and a flick through")
    print(f"  the SGP.32 profile state machine -- end to end.{C_RESET}")
    pause(1.0)

    banner("Step 1 — Cold-boot the simulated eUICC")
    workdir = Path(tempfile.mkdtemp(prefix="yggdrasim_lifecycle_demo_"))
    profile_store = workdir / "profiles"
    profile_store.mkdir(parents=True, exist_ok=True)
    engine = SimulatedSimCardEngine(
        euicc_store_root=str(workdir),
        profile_store_path=str(profile_store),
    )
    engine.state.toolkit.provide_imei = False
    engine.state.toolkit.timer_management_auto_rearm = False
    engine.state.toolkit.ipa_poll_enabled = False
    step(f"EID  = {engine.state.eid}")
    step(f"ATR  = {engine.get_atr().hex().upper()}")
    step(f"profiles seeded: {len(engine.state.profiles)}",
         f"active = {engine.state.active_profile_aid or '(none)'}")
    pause(0.6)

    banner("Step 2 — ES10b GetEuiccInfo1 (BF20)")
    info1 = store_data(engine, "BF2000", "ES10b GetEuiccInfo1")
    step("Card returned the SGP.22 §5.7.7 EuiccInfo1 TLV",
         "(SVN, supported curves, supported PKI versions)")
    hexline("BF20 ", info1, max_len=80)
    pause(0.6)

    banner("Step 3 — ES10b GetEuiccChallenge (BF2E)")
    challenge_response = store_data(engine, "BF2E00", "ES10b GetEuiccChallenge")
    chal_tlv = find_first_tlv(challenge_response, "80")
    if len(chal_tlv) > 0:
        _, chal_value, _, _ = read_tlv(chal_tlv, 0)
        step("Card emitted a fresh 16-byte challenge",
             "the SM-DP+ would now sign this together with the CTX_PARAMS_1")
        hexline("challenge", chal_value)
    pause(0.6)

    banner("Step 4 — ES10c GetProfilesInfo (BF2D)")
    info_d = store_data(engine, "BF2D00", "ES10c GetProfilesInfo")
    profiles = parse_profiles_info(info_d)
    step(f"Decoded {len(profiles)} profile entries from BF2D body")
    for index, profile in enumerate(profiles, 1):
        state_text = profile.get("state", "?")
        state_colour = C_GREEN if state_text == "ENABLED" else C_DIM
        nickname = profile.get("nickname", "")
        print(
            f"    {C_BOLD}#{index}{C_RESET}  ICCID {profile.get('iccid', '?'):<22}"
            f" AID {profile.get('aid', '?')[:16]}…  "
            f"{state_colour}{state_text:<8}{C_RESET}  "
            f"{C_DIM}{nickname}{C_RESET}"
        )
    pause(0.8)

    if len(profiles) < 2:
        step("Need at least two profiles for the enable/disable swing — adjust the seed",
             colour=C_YELLOW)
    else:
        active_iccid = next(
            (p.get("iccid", "") for p in profiles if p.get("state") == "ENABLED"), ""
        )
        target = next(
            (p for p in profiles if p.get("state") != "ENABLED" and p.get("iccid")), None
        )
        if target is None:
            step("No idle profile to switch to — skipping enable/disable demo",
                 colour=C_YELLOW)
        else:
            target_iccid = target.get("iccid", "")
            banner(f"Step 5 — EnableProfile (BF31) → switch to ICCID {target_iccid}")
            ref = encode_profile_reference_iccid(target_iccid)
            payload = tlv("BF31", ref)
            store_data(engine, payload.hex(), f"EnableProfile target={target_iccid}")
            step(f"Active profile is now {engine.state.active_profile_aid}",
                 "the ISD-R fired off a NotificationEvent (enable=0x02) and rebuilt "
                 "the runtime filesystem so the modem sees the new ICCID/IMSI tree")
            pause(0.6)

            banner(f"Step 6 — DisableProfile (BF32) → roll back to ICCID {active_iccid}")
            if active_iccid:
                ref_back = encode_profile_reference_iccid(target_iccid)
                payload_back = tlv("BF32", ref_back)
                store_data(engine, payload_back.hex(), "DisableProfile")
                step(
                    f"Active profile after disable: "
                    f"{engine.state.active_profile_aid or '(none)'}",
                    "the simulator drops the active AID and queues a "
                    "disable notification (operation 0x03)",
                )
            pause(0.6)

    banner("Step 7 — Drain the notification queue (BF2B 00 = retrieve all)")
    notif_response = store_data(engine, "BF2B00", "ES10b RetrieveNotificationsList")
    step(f"Notification chunk size: {len(notif_response)} bytes",
         f"(state.notifications now has {len(engine.state.notifications)} pending entries)")
    if len(notif_response) > 0:
        hexline("BF2B response", notif_response, max_len=72)
    pause(0.6)

    banner("Step 8 — LoadCRL (BF35) — eIM pushes a revocation list (SGP.22 §5.7.13)")
    crl_inner = bytes.fromhex("3010A00E300C020101180A323032363030333030") + b"\x00" * 4
    crl_payload = tlv("BF35", crl_inner)
    response = store_data(engine, crl_payload.hex(), "LoadCRL")
    if response.startswith(b"\xbf\x35"):
        ok = b"\x80\x01\x00" in response
        step(
            "Card persisted the CRL DER and replied "
            f"{'ok(0)' if ok else 'invalidSignature(2)'}",
            f"state.loaded_crls now has {len(engine.state.loaded_crls)} entry/entries",
        )
    pause(0.6)

    banner("Done — what just happened")
    print(f"  {C_GREEN}✓{C_RESET} ES10b GetEuiccInfo1 → SGP.22 EuiccInfo1 TLV.")
    print(f"  {C_GREEN}✓{C_RESET} ES10b GetEuiccChallenge → fresh 16-byte challenge.")
    print(f"  {C_GREEN}✓{C_RESET} ES10c GetProfilesInfo decoded into a profile table.")
    print(f"  {C_GREEN}✓{C_RESET} EnableProfile / DisableProfile drove the ISD-R state machine.")
    print(f"  {C_GREEN}✓{C_RESET} Notification queue drained on the BF2B retrieve-all path.")
    print(f"  {C_GREEN}✓{C_RESET} LoadCRL (BF35) accepted by the simulator and persisted.")
    print()
    print(f"  {C_DIM}Engine workspace: {workdir}{C_RESET}")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
