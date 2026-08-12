# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Recover SCP03 / SCP11c plaintext ahead of a Wireshark decode.

Wireshark's Lua binding exposes no AES, no CMAC and no hash. A dissector
written in it therefore cannot decrypt a secure-messaging APDU, no matter
how many keys it is handed -- which is the defect
``Tools/EumDiag/dissector.lua`` has today: it loads a session-key bundle,
prints it, and never uses it.

So the decryption happens here, in Python, using the engine that already
does it for the terminal decode view
(:class:`Tools.HilBridge.scp_replay.ScpReplayEngine`), and the result is
written to a sidecar file the Lua reads. The dissector then re-runs its
whole decode over the plaintext, so a ciphered ES10b STORE DATA renders
as a full ES10b tree.

Each entry carries the on-wire *ciphered* command so the Lua can check it
matches the frame in front of it. The Lua cannot hash, so this is how a
sidecar built from a different capture is caught: it contributes nothing
rather than attributing plaintext to the wrong frame.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .tshark_runner import (
    DEFAULT_TSHARK_BINARY,
    GSMTAP_DECODE_RULE,
    ensure_tshark_on_path,
)

SIDECAR_FORMAT = "yggdrasim-apdu-sidecar/v1"

#: ISO/IEC 7816-4 clause 5.4.1: CLA bit 3 marks secure messaging.
SECURE_MESSAGING_CLA_BIT = 0x04


class SidecarError(RuntimeError):
    """Raised when a sidecar cannot be built."""


@dataclass
class SidecarSummary:
    """What a sidecar build produced."""

    path: Path
    frames_examined: int = 0
    frames_wrapped: int = 0
    frames_recovered: int = 0
    mac_failures: int = 0
    notes: list[str] = field(default_factory=list)

    def describe(self) -> str:
        lines = [
            f"sidecar: {self.path}",
            f"  frames examined:  {self.frames_examined}",
            f"  secure messaging: {self.frames_wrapped}",
            f"  recovered:        {self.frames_recovered}",
        ]
        if self.mac_failures:
            lines.append(f"  MAC failures:     {self.mac_failures}")
        lines.extend(f"  note: {note}" for note in self.notes)
        return "\n".join(lines)


def read_frames(
    pcap_path: Path,
    *,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
) -> list[tuple[int, bytes]]:
    """Return ``(frame_number, gsmtap_payload)`` in capture order.

    Frame numbers come from tshark itself, so they line up with what the
    dissector will see when the same capture is read back.
    """
    binary = ensure_tshark_on_path(tshark_binary)
    try:
        completed = subprocess.run(
            [
                binary,
                "-r",
                str(Path(pcap_path).resolve()),
                "-T",
                "fields",
                "-e",
                "frame.number",
                "-e",
                "udp.payload",
                "-E",
                "separator=/t",
                "-E",
                "occurrence=f",
                "-d",
                GSMTAP_DECODE_RULE,
            ],
            capture_output=True,
            text=True,
            timeout=300.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise SidecarError(f"could not read {pcap_path}: {error}") from error
    if completed.returncode != 0:
        raise SidecarError(
            f"tshark exited {completed.returncode}: {completed.stderr.strip()[:400]}"
        )

    frames: list[tuple[int, bytes]] = []
    for line in completed.stdout.splitlines():
        if "\t" not in line:
            continue
        number_text, _, payload_text = line.partition("\t")
        payload_text = payload_text.strip().replace(":", "")
        if not payload_text:
            continue
        try:
            frames.append((int(number_text), bytes.fromhex(payload_text)))
        except ValueError:
            continue
    return frames


def split_exchange(payload: bytes) -> tuple[bytes, bytes] | None:
    """Split a SIMtrace SIM-APDU record into command and response.

    Only the secure-messaging case matters here, and it is the easy one:
    a wrapped command is always case 3 from the transport's point of
    view, because the MAC makes the body mandatory. That is the same
    reasoning ``live_decode_state._parse_exchange_from_udp_payload_hex``
    uses for its secure-messaging branch.
    """
    if len(payload) < 7:
        return None
    if (payload[0] & SECURE_MESSAGING_CLA_BIT) == 0:
        return None
    lc = payload[4]
    if lc == 0:
        if len(payload) < 7:
            return None
        extended = int.from_bytes(payload[5:7], "big")
        command_length = 7 + extended
    else:
        command_length = 5 + lc
    if len(payload) < command_length + 2:
        return None
    return payload[:command_length], payload[command_length:]


def _extract_gsmtap_payload(frame: bytes) -> bytes:
    """Strip the GSMTAP header from a SIM APDU frame."""
    from Tools.HilBridge.protocol import GSMTAP_SIM_APDU, GSMTAP_TYPE_SIM

    if len(frame) < 16:
        return b""
    if frame[2] != GSMTAP_TYPE_SIM:
        return b""
    if frame[12] != GSMTAP_SIM_APDU:
        return b""
    header_length = max(int(frame[1]) * 4, 16)
    if len(frame) < header_length:
        return b""
    return frame[header_length:]


def build_sidecar(
    *,
    pcap_path: Path,
    keybag_path: Path,
    output_path: Path,
    tshark_binary: str = DEFAULT_TSHARK_BINARY,
) -> SidecarSummary:
    """Decrypt every secure-messaging exchange and write the sidecar."""
    from Tools.HilBridge.scp_replay import (
        KeybagError,
        ScpReplayEngine,
        UnwrapContext,
        load_keybag,
    )

    try:
        sessions = load_keybag(str(keybag_path))
    except KeybagError as error:
        raise SidecarError(str(error)) from error
    if not sessions:
        raise SidecarError(f"{keybag_path} declares no sessions")

    engine = ScpReplayEngine(sessions)
    summary = SidecarSummary(path=Path(output_path))
    entries: dict[str, dict[str, object]] = {}

    for frame_number, frame in read_frames(pcap_path, tshark_binary=tshark_binary):
        summary.frames_examined += 1
        payload = _extract_gsmtap_payload(frame)
        if not payload:
            continue
        split = split_exchange(payload)
        if split is None:
            continue
        command, response = split
        summary.frames_wrapped += 1

        # The engine is order-sensitive: it advances an SSC and a MAC
        # chain per exchange, so frames must be fed in capture order and
        # exactly once.
        context = UnwrapContext(
            frame_number=frame_number,
            card_session_index=1,
            current_aid_hex="",
        )
        try:
            recovered = engine.try_unwrap_bytes(context, command, response)
        except (ValueError, RuntimeError) as error:
            summary.notes.append(f"frame {frame_number}: {error}")
            continue
        if recovered is None:
            continue
        if not recovered.mac_ok:
            summary.mac_failures += 1
        if not recovered.command_plaintext and not recovered.response_plaintext:
            continue

        summary.frames_recovered += 1
        entries[str(frame_number)] = {
            "command_hex": command.hex().upper(),
            "command_plaintext": recovered.command_plaintext.hex().upper(),
            "response_plaintext": recovered.response_plaintext.hex().upper(),
            "session_label": recovered.matched_label,
            "mac_ok": bool(recovered.mac_ok),
        }

    document = {"format": SIDECAR_FORMAT, "frames": entries}
    target = Path(output_path)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except OSError as error:
        raise SidecarError(f"could not write {target}: {error}") from error
    return summary


def autodiscover_sidecar(pcap_path: Path) -> Path | None:
    """Find a sidecar sitting beside *pcap_path*, if there is one."""
    base = Path(pcap_path)
    for candidate in (
        base.with_suffix(base.suffix + ".sidecar.json"),
        base.with_suffix(".sidecar.json"),
    ):
        if candidate.is_file():
            return candidate
    return None


def autodiscover_keybag(pcap_path: Path) -> Path | None:
    """Find a keybag beside *pcap_path*, reusing the HIL bridge's rule."""
    from Tools.HilBridge.scp_replay import try_autodiscover_sidecar_keybag

    found = try_autodiscover_sidecar_keybag(str(pcap_path))
    if found:
        return Path(found)
    return None


__all__ = [
    "SIDECAR_FORMAT",
    "SidecarError",
    "SidecarSummary",
    "autodiscover_keybag",
    "autodiscover_sidecar",
    "build_sidecar",
    "read_frames",
    "split_exchange",
]
