# -----------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# Copyright (c) 2026 1oT OE. Authored by Hampus Hellsberg.
# -----------------------------------------------------------------------------

"""Helpers that turn live SCP03 / SCP11c session state into keybag JSON.

These helpers are called from the SCP shells after a successful
`INITIALIZE UPDATE / EXTERNAL AUTHENTICATE` pair (SCP03) or a completed
SCP11c BSP derivation. The produced JSON is designed to sit next to the
paired pcap so the offline review TUI picks it up automatically.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from typing import Any


@dataclass(frozen=True, slots=True)
class KeybagExportEntry:
    """In-memory representation of one keybag session prior to write."""

    label: str
    protocol: str
    s_enc_hex: str
    s_mac_hex: str
    s_rmac_hex: str = ""
    match_aid_hex: str = ""
    match_card_session_index: int | None = None
    match_first_frame: int | None = None
    initial_ssc: int = 0
    initial_chaining_hex: str = "00" * 16


def entry_from_scp03_session(
    session: Any,
    *,
    label: str = "scp03-live",
    match_aid_hex: str = "",
    match_card_session_index: int | None = None,
    match_first_frame: int | None = None,
) -> KeybagExportEntry:
    """Extract S-ENC / S-MAC / S-RMAC from an `Scp03Session`.

    The `Scp03Session` fields (`s_enc`, `s_mac`, `s_rmac`) are populated
    during `derive_keys`; if any are missing we raise so the caller knows
    the session was never fully authenticated.
    """
    if getattr(session, "is_authenticated", False) is False:
        raise RuntimeError(
            "Cannot export keybag entry: SCP03 session is not authenticated yet."
        )
    s_enc = bytes(getattr(session, "s_enc", b"") or b"")
    s_mac = bytes(getattr(session, "s_mac", b"") or b"")
    s_rmac = bytes(getattr(session, "s_rmac", b"") or b"")
    if len(s_enc) == 0 or len(s_mac) == 0:
        raise RuntimeError(
            "Cannot export keybag entry: derived S-ENC / S-MAC are empty."
        )
    return KeybagExportEntry(
        label=str(label or "scp03-live"),
        protocol="scp03",
        s_enc_hex=s_enc.hex().upper(),
        s_mac_hex=s_mac.hex().upper(),
        s_rmac_hex=(s_rmac.hex().upper() if len(s_rmac) > 0 else s_mac.hex().upper()),
        match_aid_hex=_normalize_match_aid(match_aid_hex),
        match_card_session_index=match_card_session_index,
        match_first_frame=match_first_frame,
        initial_ssc=int(getattr(session, "ssc", 0) or 0),
        initial_chaining_hex=(
            bytes(getattr(session, "chaining_value", b"\x00" * 16) or b"\x00" * 16)
            .hex()
            .upper()
        ),
    )


def entry_from_scp11_bsp(
    bsp_session: Any,
    *,
    label: str = "scp11c-live",
    match_aid_hex: str = "",
    match_card_session_index: int | None = None,
    match_first_frame: int | None = None,
) -> KeybagExportEntry:
    """Extract S-ENC / S-MAC from a pySim BSP session.

    The live SCP11 orchestrator keeps a pySim BSP instance with two
    sub-objects: `c_algo` (SCP03-style AES-CBC encryption) and `m_algo`
    (AES-CMAC for MAC). Both carry a `s_enc` / `s_mac` field after the
    handshake. R-MAC is derived from the same MAC key.
    """
    c_algo = getattr(bsp_session, "c_algo", None)
    m_algo = getattr(bsp_session, "m_algo", None)
    if c_algo is None or m_algo is None:
        raise RuntimeError(
            "Cannot export keybag entry: BSP session is missing c_algo/m_algo."
        )
    s_enc = bytes(getattr(c_algo, "s_enc", b"") or b"")
    s_mac = bytes(getattr(m_algo, "s_mac", b"") or b"")
    if len(s_enc) == 0 or len(s_mac) == 0:
        raise RuntimeError(
            "Cannot export keybag entry: BSP session has no derived S-ENC / S-MAC."
        )
    mac_chain = bytes(getattr(m_algo, "mac_chain", b"\x00" * 16) or b"\x00" * 16)
    if len(mac_chain) != 16:
        mac_chain = (mac_chain + (b"\x00" * 16))[:16]
    return KeybagExportEntry(
        label=str(label or "scp11c-live"),
        protocol="scp11c",
        s_enc_hex=s_enc.hex().upper(),
        s_mac_hex=s_mac.hex().upper(),
        s_rmac_hex=s_mac.hex().upper(),
        match_aid_hex=_normalize_match_aid(match_aid_hex),
        match_card_session_index=match_card_session_index,
        match_first_frame=match_first_frame,
        initial_ssc=int(getattr(c_algo, "block_nr", 0) or 0),
        initial_chaining_hex=mac_chain.hex().upper(),
    )


def build_keybag_document(entries: list[KeybagExportEntry]) -> dict[str, Any]:
    sessions: list[dict[str, Any]] = []
    for entry in entries:
        session_dict: dict[str, Any] = {
            "label": str(entry.label or ""),
            "protocol": str(entry.protocol or "scp03"),
            "keys": {
                "s_enc": str(entry.s_enc_hex or ""),
                "s_mac": str(entry.s_mac_hex or ""),
            },
            "initial_state": {
                "ssc": int(entry.initial_ssc),
                "chaining_value": str(entry.initial_chaining_hex or "00" * 16),
            },
        }
        if len(str(entry.s_rmac_hex or "")) > 0:
            session_dict["keys"]["s_rmac"] = str(entry.s_rmac_hex)
        match_dict: dict[str, Any] = {}
        if len(str(entry.match_aid_hex or "")) > 0:
            match_dict["aid"] = str(entry.match_aid_hex)
        if entry.match_card_session_index is not None:
            match_dict["card_session_index"] = int(entry.match_card_session_index)
        if entry.match_first_frame is not None:
            match_dict["first_frame"] = int(entry.match_first_frame)
        if len(match_dict) > 0:
            session_dict["match"] = match_dict
        sessions.append(session_dict)
    return {"version": 1, "sessions": sessions}


def write_keybag_file(
    destination_path: str,
    entries: list[KeybagExportEntry],
    *,
    merge_existing: bool = True,
) -> str:
    """Serialize `entries` to a keybag JSON on disk.

    When `merge_existing` is True and `destination_path` already exists,
    the existing sessions are preserved and new entries are appended. The
    JSON file is written in UTF-8 with 2-space indentation so it stays
    human-reviewable after a handshake dump.
    """
    normalized_path = str(destination_path or "").strip()
    if len(normalized_path) == 0:
        raise ValueError("destination_path is empty.")
    expanded_path = os.path.abspath(os.path.expanduser(normalized_path))
    parent_directory = os.path.dirname(expanded_path)
    if len(parent_directory) > 0 and os.path.isdir(parent_directory) is False:
        os.makedirs(parent_directory, exist_ok=True)
    combined_sessions: list[dict[str, Any]] = []
    if merge_existing and os.path.isfile(expanded_path):
        try:
            with open(expanded_path, "rb") as handle:
                existing_document = json.loads(handle.read().decode("utf-8"))
            if isinstance(existing_document, dict):
                existing_sessions = existing_document.get("sessions", [])
                if isinstance(existing_sessions, list):
                    combined_sessions.extend(
                        entry for entry in existing_sessions if isinstance(entry, dict)
                    )
        except Exception:
            # If the existing file is unreadable we refuse to clobber it
            # and instead raise so the operator can decide how to resolve.
            raise RuntimeError(
                f"Existing keybag at {expanded_path} could not be parsed for merge."
            )
    new_document = build_keybag_document(entries)
    combined_sessions.extend(new_document.get("sessions", []))
    merged_document = {"version": 1, "sessions": combined_sessions}
    with open(expanded_path, "wb") as handle:
        handle.write(
            json.dumps(merged_document, indent=2, sort_keys=False).encode("utf-8")
        )
    return expanded_path


def _normalize_match_aid(aid_text: str) -> str:
    return str(aid_text or "").strip().upper().replace(" ", "").replace(":", "")
