from __future__ import annotations

from contextlib import contextmanager, nullcontext
import json
import math
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path

from Tools.HilBridge.live_decode_state import (
    ActiveTimerSnapshot,
    StatefulFrameAnnotation,
    annotate_packet_summary,
    build_stateful_packet_annotations,
)
from Tools.HilBridge.live_decode_view import (
    DEFAULT_DECODE_RULE,
    PacketSummary,
    _file_size,
    read_packet_detail,
    read_packet_hex,
    read_packet_summaries,
)
from Tools.HilBridge.scp_replay import (
    KeybagLoadSummary,
    ScpReplayEngine,
    load_keybag_safe,
    try_autodiscover_sidecar_keybag,
)

_PANE_NAMES = ("summary", "detail", "bytes")
_DEFAULT_SUMMARY_HEIGHT = 14
_DEFAULT_DETAIL_WIDTH = 56
_SUMMARY_VIEW_CONTEXT = "context"
_SUMMARY_VIEW_POLL = "poll"
_SUMMARY_VIEW_FLAT = "flat"
_SUMMARY_VIEW_ORDER = (
    _SUMMARY_VIEW_CONTEXT,
    _SUMMARY_VIEW_POLL,
    _SUMMARY_VIEW_FLAT,
)
# F4 rotates only between the two interactive views the user actually
# wants to toggle between. The dedicated poll-cycle view is still a valid
# summary_view_mode value (so persisted preferences / explicit configs
# keep working) but it is no longer visited by the cycle action.
_SUMMARY_VIEW_CYCLE = (
    _SUMMARY_VIEW_CONTEXT,
    _SUMMARY_VIEW_FLAT,
)
_POLL_CYCLE_IDLE_GAP_SECONDS = 5.0
_POLL_CYCLE_MAX_HIGHLIGHT_TOKENS = 4
# Bounded queue for rows buffered while ingest is paused. 5k at typical
# APDU sizes is ~2 MB, which is well within reason for a stuck-pause
# scenario. Once the cap is hit we drop the oldest row and bump the
# dropped counter so the operator can see that the paused window is
# outrunning what the UI can absorb.
_PAUSED_QUEUE_HARD_CAP_DEFAULT = 5000
# Rolling window used to compute the live-stream packet rate. If the
# rate exceeds _AUTO_PAUSE_HINT_RATE_THRESHOLD over at least
# _AUTO_PAUSE_HINT_WINDOW_SECONDS and the user has not touched F2, the
# status line advertises the pause key at most once per
# _AUTO_PAUSE_HINT_COOLDOWN_SECONDS so we don't spam a packet storm.
_AUTO_PAUSE_HINT_RATE_THRESHOLD = 50
_AUTO_PAUSE_HINT_WINDOW_SECONDS = 3.0
_AUTO_PAUSE_HINT_COOLDOWN_SECONDS = 30.0
# Filename marker injected between the auto-generated timestamp and
# the extension when we clip the exported trace to the displayed
# context (editcap clip path).
_PAUSED_TRACE_FILENAME_MARKER = "_paused"
_DEFAULT_THEME_NAME = "nord"
_THEME_CYCLE = [
    "textual-ansi",
    "textual-dark",
    "nord",
    "dracula",
    "catppuccin-mocha",
    "tokyo-night",
    "gruvbox",
    "solarized-dark",
    "rose-pine",
    "textual-light",
    "solarized-light",
    "catppuccin-latte",
]


@dataclass(frozen=True, slots=True)
class PaneVisibility:
    summary: bool = True
    detail: bool = True
    bytes: bool = True


@dataclass(frozen=True, slots=True)
class TuiLayoutPreferences:
    visibility: PaneVisibility
    summary_height: int
    detail_width: int
    summary_view_mode: str = _SUMMARY_VIEW_CONTEXT
    theme_name: str = _DEFAULT_THEME_NAME
    last_export_directory: str = ""
    last_capture_open_directory: str = ""


@dataclass(frozen=True, slots=True)
class _ChannelSessionContextLabel:
    kind: str = ""
    fqdn: str = ""


def count_visible_panes(visibility: PaneVisibility) -> int:
    return int(bool(visibility.summary)) + int(bool(visibility.detail)) + int(bool(visibility.bytes))


def toggled_pane_visibility(visibility: PaneVisibility, pane_name: str) -> PaneVisibility:
    normalized_name = str(pane_name or "").strip().lower()
    if normalized_name not in _PANE_NAMES:
        raise ValueError(f"unknown pane: {normalized_name}")
    if getattr(visibility, normalized_name) and count_visible_panes(visibility) <= 1:
        return visibility
    return replace(
        visibility,
        **{normalized_name: not bool(getattr(visibility, normalized_name))},
    )


def visible_pane_order(visibility: PaneVisibility) -> tuple[str, ...]:
    ordered: list[str] = []
    for pane_name in _PANE_NAMES:
        if bool(getattr(visibility, pane_name)):
            ordered.append(pane_name)
    return tuple(ordered)


def default_tui_layout_preferences() -> TuiLayoutPreferences:
    return TuiLayoutPreferences(
        visibility=PaneVisibility(summary=True, detail=False, bytes=True),
        summary_height=_DEFAULT_SUMMARY_HEIGHT,
        detail_width=_DEFAULT_DETAIL_WIDTH,
        summary_view_mode=_SUMMARY_VIEW_CONTEXT,
        theme_name=_DEFAULT_THEME_NAME,
        last_export_directory="",
        last_capture_open_directory="",
    )


def _normalize_summary_view_mode(view_mode: str) -> str:
    normalized_view_mode = str(view_mode or "").strip().lower()
    aliases = {
        "tree": _SUMMARY_VIEW_CONTEXT,
        "context-tree": _SUMMARY_VIEW_CONTEXT,
        "context_tree": _SUMMARY_VIEW_CONTEXT,
        "flat-list": _SUMMARY_VIEW_FLAT,
        "flat_list": _SUMMARY_VIEW_FLAT,
        "chronological": _SUMMARY_VIEW_FLAT,
        "packet-list": _SUMMARY_VIEW_FLAT,
        "packet_list": _SUMMARY_VIEW_FLAT,
        "wireshark": _SUMMARY_VIEW_FLAT,
        "tshark": _SUMMARY_VIEW_FLAT,
        "poll-cycle": _SUMMARY_VIEW_POLL,
        "poll_cycle": _SUMMARY_VIEW_POLL,
        "polls": _SUMMARY_VIEW_POLL,
        "polling": _SUMMARY_VIEW_POLL,
    }
    normalized_view_mode = aliases.get(normalized_view_mode, normalized_view_mode)
    if normalized_view_mode in _SUMMARY_VIEW_ORDER:
        return normalized_view_mode
    return _SUMMARY_VIEW_CONTEXT


def _summary_view_title(view_mode: str) -> str:
    normalized_view_mode = _normalize_summary_view_mode(view_mode)
    if normalized_view_mode == _SUMMARY_VIEW_FLAT:
        return "Flat packet list"
    if normalized_view_mode == _SUMMARY_VIEW_POLL:
        return "Poll cycles"
    return "Context tree"


def _summary_view_cycle_hint(view_mode: str) -> str:
    normalized_view_mode = _normalize_summary_view_mode(view_mode)
    if normalized_view_mode == _SUMMARY_VIEW_FLAT:
        return "F4 cycle view · arrows browse frames"
    if normalized_view_mode == _SUMMARY_VIEW_POLL:
        return "F4 cycle view · Space toggle poll"
    return "F4 cycle view · Space toggle group"


def _normalize_theme_name(theme_name: str) -> str:
    normalized_theme_name = str(theme_name or "").strip().lower()
    aliases = {
        "ansi": "textual-ansi",
        "dark": "textual-dark",
        "light": "textual-light",
        "tokyonight": "tokyo-night",
    }
    normalized_theme_name = aliases.get(normalized_theme_name, normalized_theme_name)
    if normalized_theme_name in _THEME_CYCLE:
        return normalized_theme_name
    return _DEFAULT_THEME_NAME


def _next_theme_name(current_theme_name: str) -> str:
    normalized_theme_name = _normalize_theme_name(current_theme_name)
    if normalized_theme_name in _THEME_CYCLE:
        current_index = _THEME_CYCLE.index(normalized_theme_name)
        return _THEME_CYCLE[(current_index + 1) % len(_THEME_CYCLE)]
    return _THEME_CYCLE[0]


_LIGHT_THEME_NAMES = frozenset({
    "textual-light",
    "solarized-light",
    "catppuccin-latte",
})

_SUMMARY_GROUP_ORDER = (
    "Channels",
    "STK",
    "ETSI FS",
    "Timer",
    "eUICC",
    "Authentication",
    "Other APDU",
)

_SUMMARY_BIP_MARKERS = (
    "DATA AVAILABLE",
    "CHANNEL STATUS",
    "OPEN CHANNEL",
    "SEND DATA",
    "RECEIVE DATA",
    "GET CHANNEL STATUS",
)

_SUMMARY_STK_MARKERS = (
    "FETCH",
    "FETCH PENDING",
    "TERMINAL PROFILE",
    "TERMINAL CAPABILITY",
    "TERMINAL RESPONSE",
    "ENVELOPE",
    "SET UP MENU",
    "SET UP EVENT LIST",
    "EVENT DOWNLOAD",
    "POLL INTERVAL",
    "POLL OFF",
    "MORE TIME",
    "REFRESH",
    "PROVIDE LOCAL INFORMATION",
    "LOCATION STATUS",
    "ACCESS TECHNOLOGY CHANGE",
    "NETWORK SEARCH MODE CHANGE",
)

_SUMMARY_FS_MARKERS = (
    "SELECT",
    "READ BINARY",
    "READ RECORD",
    "SEARCH RECORD",
    "UPDATE BINARY",
    "UPDATE RECORD",
    "GET RESPONSE",
    "STATUS",
)

_SUMMARY_EUICC_MARKERS = (
    "EUICC",
    "ISD-R",
    "ECASD",
    "GETEIM",
    "GET EIM",
    "GETEUICC",
    "GET EUICC",
    "EID",
    "SCP11",
    "STORE DATA",
    "GET DATA",
    "INITIALIZE UPDATE",
    "EXTERNAL AUTHENTICATE",
    "PROFILE",
    "SM-DP+",
    "EIM",
)

_SUMMARY_AUTHENTICATION_MARKERS = (
    "VERIFY",
    "VERIFY CHV",
    "CHV",
    "AUTHENTICATE",
    "AUTHENTICATION",
    "INTERNAL AUTHENTICATE",
    "RUN GSM ALGORITHM",
    "RUN GSM ALGORITHM / AUTHENTICATE",
    "GET CHALLENGE",
    "CHANGE CHV",
    "ENABLE CHV",
    "DISABLE CHV",
    "UNBLOCK CHV",
    "MSE",
    "PSO",
)


@dataclass(frozen=True, slots=True)
class TuiThemePalette:
    frame: str
    primary: str
    secondary: str
    endpoint: str
    protocol: str
    waiting: str
    error: str
    bip: str
    stk: str
    fs: str
    timer: str
    euicc: str
    security: str
    other: str
    context: str


def _theme_palette(theme_name: str) -> TuiThemePalette:
    """Return the Nord-aligned palette for ``theme_name``.

    Both branches now sit on the canonical Nord wheel
    (https://www.nordtheme.com/docs/colors-and-palettes); the light
    branch reaches for the deeper Frost / Polar Night swatches that
    stay legible on a pale background, while the dark branch keeps
    the brighter Frost + Aurora accents that pop against the slate
    Polar Night canvas.
    """
    normalized_theme_name = _normalize_theme_name(theme_name)
    if normalized_theme_name in _LIGHT_THEME_NAMES:
        return TuiThemePalette(
            frame="#5E81AC",      # frost-deep -- primary brand stroke
            primary="#2E3440",    # polar-night-0 -- body text
            secondary="#4C566A",  # polar-night-3 -- dim text
            endpoint="#5E81AC",   # frost-deep
            protocol="#A3BE8C",   # aurora-green
            waiting="#4C566A",
            error="#BF616A",      # aurora-red
            bip="#5E81AC",
            stk="#D08770",        # aurora-orange
            fs="#A3BE8C",
            timer="#BF616A",
            euicc="#B48EAD",      # aurora-purple
            security="#B48EAD",
            other="#4C566A",
            context="#A3BE8C",
        )
    return TuiThemePalette(
        frame="#D08770",          # aurora-orange -- warm window chrome
        primary="#ECEFF4",        # snow-2 -- body text
        secondary="#9AA5B1",      # snow-tinted dim
        endpoint="#88C0D0",       # frost-cyan
        protocol="#A3BE8C",
        waiting="#9AA5B1",
        error="#BF616A",
        bip="#88C0D0",
        stk="#EBCB8B",            # aurora-yellow
        fs="#A3BE8C",
        timer="#BF616A",
        euicc="#B48EAD",
        security="#B48EAD",
        other="#81A1C1",          # frost-blue
        context="#A3BE8C",
    )


def _summary_primary_text(row: PacketSummary, annotation: StatefulFrameAnnotation | None) -> str:
    if annotation is not None:
        summary_suffix = _summary_display_label_text(annotation.summary_suffix)
        if len(summary_suffix) > 0:
            return summary_suffix
    info_text = _summary_display_label_text(row.info)
    if len(info_text) > 0:
        return info_text
    protocol_text = _normalized_summary_label_text(row.protocol)
    if len(protocol_text) > 0:
        return protocol_text
    return "APDU"


def _summary_channel_context(annotation: StatefulFrameAnnotation | None) -> str | None:
    if annotation is None:
        return None
    channel_session_id = getattr(annotation, "channel_session_id", None)
    if channel_session_id is not None:
        return f"CH{int(channel_session_id)}"
    summary_suffix = str(annotation.summary_suffix or "").strip()
    match = re.search(r"\bCH\d+\b", summary_suffix)
    if match is None:
        return None
    channel_label = match.group(0)
    for raw_line in annotation.context_lines:
        stripped = str(raw_line or "").strip()
        if stripped.startswith(f"{channel_label} "):
            return stripped
    return channel_label


def _summary_timer_context(annotation: StatefulFrameAnnotation | None) -> str | None:
    if annotation is None:
        return None
    summary_suffix = str(annotation.summary_suffix or "").strip()
    match = re.search(r"\bT\d+\b", summary_suffix)
    if match is None:
        return None
    return match.group(0)


def _summary_fs_context(annotation: StatefulFrameAnnotation | None) -> str | None:
    if annotation is None:
        return None
    summary_suffix = str(annotation.summary_suffix or "").strip()
    if summary_suffix.startswith("FS ") is False:
        return None
    fs_parts = summary_suffix.split()
    if len(fs_parts) < 2:
        return "MF"
    return fs_parts[1]


def _summary_stk_context(annotation: StatefulFrameAnnotation | None) -> str | None:
    if annotation is None:
        return None
    summary_suffix = str(annotation.summary_suffix or "").strip()
    if summary_suffix.startswith("STK ") is False:
        return None
    return summary_suffix[4:].split(" | ", 1)[0].strip() or "Proactive"


def _summary_grouping_text(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> str:
    parts: list[str] = []
    if annotation is not None:
        summary_suffix = str(annotation.summary_suffix or "").strip()
        if len(summary_suffix) > 0:
            parts.append(summary_suffix)
    info_text = str(row.info or "").strip()
    if len(info_text) > 0:
        parts.append(info_text)
    protocol_text = str(row.protocol or "").strip()
    if len(protocol_text) > 0:
        parts.append(protocol_text)
    return " | ".join(parts).upper()


def _summary_matches_marker(summary_text: str, markers: tuple[str, ...]) -> bool:
    for marker in markers:
        if marker in summary_text:
            return True
    return False


def _summary_group_name(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> str:
    if _summary_channel_session_id(row, annotation) is not None:
        return "Channels"
    fs_context = _summary_fs_context(annotation)
    if fs_context is not None:
        return "ETSI FS"
    timer_context = _summary_timer_context(annotation)
    if timer_context is not None:
        return "Timer"
    stk_context = _summary_stk_context(annotation)
    if stk_context is not None:
        return "STK"
    summary_text = _summary_grouping_text(row, annotation)
    # ISO/IEC 7816-4 MANAGE CHANNEL (INS=0x70) advertises itself in
    # the tshark info column as "MANAGE CHANNEL Operation=Open
    # Channel ...", whose "OPEN CHANNEL" substring would otherwise
    # match the STK BIP marker below and bucket the frame into
    # "Channels". MANAGE CHANNEL carries no `channel_session_id`
    # (it *is* the channel-open primitive, not a BIP lifecycle
    # event), so the frame would fall into the unbound-channel tail
    # and render as an uncategorised top-level row. In practice the
    # modem brackets STK proactive activity with these APDUs, so we
    # weave them into the STK group ahead of any BIP / marker scan.
    if "MANAGE CHANNEL" in summary_text:
        return "STK"
    if _summary_matches_marker(summary_text, _SUMMARY_BIP_MARKERS):
        return "Channels"
    if _summary_matches_marker(summary_text, _SUMMARY_STK_MARKERS):
        return "STK"
    if _summary_matches_marker(summary_text, _SUMMARY_FS_MARKERS):
        return "ETSI FS"
    if _summary_matches_marker(summary_text, _SUMMARY_EUICC_MARKERS):
        return "eUICC"
    if _summary_matches_marker(summary_text, _SUMMARY_AUTHENTICATION_MARKERS):
        return "Authentication"
    return "Other APDU"


def _summary_row_is_status_apdu(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> bool:
    suffix_upper = ""
    if annotation is not None:
        suffix_upper = str(annotation.summary_suffix or "").upper()
    if "FETCH PENDING" in suffix_upper:
        return True
    if suffix_upper.startswith("FS ") and " STATUS" in suffix_upper:
        return True
    info_upper = str(row.info or "").strip().upper()
    if info_upper == "STATUS":
        return True
    if info_upper.startswith("STATUS "):
        return True
    udp_hex = str(row.udp_payload_hex or "").strip().upper()
    if len(udp_hex) >= 8:
        try:
            raw_bytes = bytes.fromhex(udp_hex)
        except ValueError:
            raw_bytes = b""
        if len(raw_bytes) >= 4:
            header_word_count = int(raw_bytes[1])
            header_byte_count = max(header_word_count, 1) * 4
            apdu_offset = header_byte_count
            if len(raw_bytes) >= apdu_offset + 2:
                ins_byte = raw_bytes[apdu_offset + 1]
                if int(ins_byte) == 0xF2:
                    return True
    return False


def _summary_row_capture_seconds(row: PacketSummary) -> float | None:
    time_text = str(row.time_text or "").strip()
    if len(time_text) == 0:
        return None
    try:
        return float(time_text)
    except ValueError:
        return None


def _assign_poll_group_indices(
    rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> dict[int, int]:
    assignments: dict[int, int] = {}
    if len(rows) == 0:
        return assignments
    poll_index = 0
    previous_capture_seconds: float | None = None
    previous_was_status = False
    for row in rows:
        annotation = annotations.get(int(row.number))
        is_status = _summary_row_is_status_apdu(row, annotation)
        capture_seconds = _summary_row_capture_seconds(row)
        start_new_poll = False
        if poll_index == 0:
            start_new_poll = True
        elif is_status and not previous_was_status:
            start_new_poll = True
        elif (
            previous_capture_seconds is not None
            and capture_seconds is not None
            and (capture_seconds - previous_capture_seconds) >= _POLL_CYCLE_IDLE_GAP_SECONDS
        ):
            start_new_poll = True
        if start_new_poll:
            poll_index += 1
        assignments[int(row.number)] = poll_index
        previous_was_status = is_status
        if capture_seconds is not None:
            previous_capture_seconds = capture_seconds
    return assignments


def _summary_poll_cycle_key(poll_index: int) -> str:
    return f"poll:{int(poll_index)}"


def _summary_poll_cycle_endpoint(summary_upper: str) -> str:
    match = re.search(r"CH\d+\s+OPEN\s+([^\s|]+)", summary_upper)
    if match is None:
        return ""
    endpoint_text = match.group(1).strip()
    if len(endpoint_text) == 0:
        return ""
    return endpoint_text


def _summary_poll_cycle_highlight_tokens(
    rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> list[str]:
    ordered_tokens: list[str] = []
    seen_tokens: set[str] = set()
    endpoint_token: str | None = None
    for row in rows:
        annotation = annotations.get(int(row.number))
        suffix_upper = ""
        if annotation is not None:
            suffix_upper = str(annotation.summary_suffix or "").upper()
        info_upper = str(row.info or "").upper()
        candidates: list[str] = []
        if "OPEN CHANNEL" in suffix_upper or "OPEN CHANNEL" in info_upper:
            candidates.append("OPEN")
            if endpoint_token is None:
                extracted_endpoint = _summary_poll_cycle_endpoint(suffix_upper)
                if len(extracted_endpoint) > 0:
                    endpoint_token = extracted_endpoint
        if "CLOSE CHANNEL" in suffix_upper or "CLOSE CHANNEL" in info_upper:
            candidates.append("CLOSE")
        if (
            re.search(r"CH\d+\s+SEND\b", suffix_upper) is not None
            or "SEND DATA" in info_upper
        ):
            candidates.append("SEND")
        if (
            re.search(r"CH\d+\s+RECEIVE\b", suffix_upper) is not None
            or re.search(r"CH\d+\s+RX\b", suffix_upper) is not None
            or "RECEIVE DATA" in info_upper
        ):
            candidates.append("RECV")
        if "REFRESH" in suffix_upper or "REFRESH" in info_upper:
            candidates.append("REFRESH")
        if "POLL INTERVAL" in suffix_upper or "POLL INTERVAL" in info_upper:
            candidates.append("POLL-INT")
        if re.search(r"\bT\d+\s+START\b", suffix_upper) is not None:
            candidates.append("TIMER")
        if suffix_upper.startswith("FS ") and " STATUS" not in suffix_upper:
            candidates.append("FS")
        if "FETCH" in info_upper and "OPEN" not in suffix_upper:
            candidates.append("FETCH")
        for token in candidates:
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            ordered_tokens.append(token)
            if len(ordered_tokens) >= _POLL_CYCLE_MAX_HIGHLIGHT_TOKENS:
                break
        if len(ordered_tokens) >= _POLL_CYCLE_MAX_HIGHLIGHT_TOKENS:
            break
    if endpoint_token is not None and len(ordered_tokens) > 0:
        for index, token in enumerate(ordered_tokens):
            if token == "OPEN":
                ordered_tokens[index] = f"OPEN {endpoint_token}"
                break
    if len(ordered_tokens) == 0:
        ordered_tokens.append("idle")
    return ordered_tokens


def _summary_poll_cycle_title(poll_index: int, highlight_tokens: list[str]) -> str:
    base_label = f"Poll {int(poll_index)}"
    if len(highlight_tokens) == 0:
        return base_label
    highlight_text = " · ".join(highlight_tokens)
    return f"{base_label} · {highlight_text}"


def _summary_channel_session_id(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> int | None:
    if annotation is not None:
        channel_session_id = getattr(annotation, "channel_session_id", None)
        if channel_session_id is not None:
            try:
                return int(channel_session_id)
            except Exception:
                return None
    summary_text = _summary_grouping_text(row, annotation)
    match = re.search(r"\bCH(\d+)\b", summary_text)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except Exception:
        return None


def _summary_channel_number(annotation: StatefulFrameAnnotation | None) -> int | None:
    if annotation is None:
        return None
    channel_number = getattr(annotation, "channel_number", None)
    if channel_number is not None:
        try:
            return int(channel_number)
        except Exception:
            return None
    channel_session_id = getattr(annotation, "channel_session_id", None)
    if channel_session_id is None:
        return None
    try:
        return int(channel_session_id)
    except Exception:
        return None


def _summary_channel_number_key(channel_number: int) -> str:
    return f"Channels::CH{int(channel_number)}"


def _summary_channel_poll_index(annotation: StatefulFrameAnnotation | None) -> int | None:
    if annotation is None:
        return None
    channel_poll_index = getattr(annotation, "channel_poll_index", None)
    if channel_poll_index is None:
        return None
    try:
        return int(channel_poll_index)
    except Exception:
        return None


def _summary_channel_session_key(session_id: int) -> str:
    return f"Channels::SESSION{int(session_id)}"


def _summary_expand_key(node_data: object) -> str:
    if isinstance(node_data, dict) is False:
        return ""
    expand_key = str(node_data.get("expand_key", "") or "").strip()
    if len(expand_key) > 0:
        return expand_key
    return str(node_data.get("group_name", "") or "").strip()


def _summary_partition_channel_rows(
    rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> tuple[list[tuple[int, list[PacketSummary]]], list[PacketSummary]]:
    session_rows_by_id: dict[int, list[PacketSummary]] = {}
    initially_unbound_rows: list[PacketSummary] = []
    for row in rows:
        annotation = annotations.get(int(row.number))
        session_id = _summary_channel_session_id(row, annotation)
        if session_id is None:
            initially_unbound_rows.append(row)
            continue
        session_bucket = session_rows_by_id.setdefault(int(session_id), [])
        session_bucket.append(row)
    # Derive OPEN->CLOSE frame ranges from the already-tagged rows and use
    # them to reassign any still-unbound rows (typically ENVELOPE Event
    # Download Data Available frames whose channel number could not be
    # parsed, or any channel-classified row that lost its CHn tag). This
    # implements the "packet number between OPEN and CLOSE CHANNEL belongs
    # to that context" rule that matches how the user reads the capture.
    session_frame_ranges: list[tuple[int, int, int]] = []
    for session_id, session_rows in session_rows_by_id.items():
        if len(session_rows) == 0:
            continue
        frame_numbers = [int(row.number) for row in session_rows]
        session_frame_ranges.append(
            (min(frame_numbers), max(frame_numbers), int(session_id))
        )
    residual_unbound_rows: list[PacketSummary] = []
    for row in initially_unbound_rows:
        resolved_session_id = _summary_session_id_from_frame_range(
            int(row.number), session_frame_ranges
        )
        if resolved_session_id is None:
            residual_unbound_rows.append(row)
            continue
        session_bucket = session_rows_by_id.setdefault(int(resolved_session_id), [])
        session_bucket.append(row)
    for session_id, session_rows in session_rows_by_id.items():
        session_rows.sort(key=lambda row: int(row.number))
    ordered_sessions = sorted(
        session_rows_by_id.items(),
        key=lambda item: int(item[1][0].number) if len(item[1]) > 0 else int(item[0]),
    )
    return (ordered_sessions, residual_unbound_rows)


def _summary_session_id_from_frame_range(
    frame_number: int,
    session_frame_ranges: list[tuple[int, int, int]],
) -> int | None:
    best_match: int | None = None
    best_span = 0
    for start_frame, end_frame, session_id in session_frame_ranges:
        if frame_number < int(start_frame):
            continue
        if frame_number > int(end_frame):
            continue
        current_span = int(end_frame) - int(start_frame)
        if best_match is None or current_span < best_span:
            best_match = int(session_id)
            best_span = current_span
    return best_match


def _summary_partition_channel_number_rows(
    rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> tuple[list[tuple[int, list[PacketSummary]]], list[PacketSummary]]:
    channel_rows_by_number: dict[int, list[PacketSummary]] = {}
    unbound_rows: list[PacketSummary] = []
    for row in rows:
        annotation = annotations.get(int(row.number))
        channel_number = _summary_channel_number(annotation)
        if channel_number is None:
            unbound_rows.append(row)
            continue
        channel_bucket = channel_rows_by_number.setdefault(int(channel_number), [])
        channel_bucket.append(row)
    ordered_channels = sorted(
        channel_rows_by_number.items(),
        key=lambda item: int(item[1][0].number) if len(item[1]) > 0 else int(item[0]),
    )
    return (ordered_channels, unbound_rows)


def _summary_channel_session_open_row(
    session_id: int,
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> PacketSummary | None:
    for row in session_rows:
        annotation = annotations.get(int(row.number))
        summary_text = _summary_grouping_text(row, annotation)
        if f"CH{int(session_id)} OPEN" in summary_text and "OPEN CHANNEL" in summary_text:
            return row
    return session_rows[0] if len(session_rows) > 0 else None


def _summary_channel_session_close_text(
    session_id: int,
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> str:
    for row in reversed(session_rows):
        annotation = annotations.get(int(row.number))
        summary_text = _summary_grouping_text(row, annotation)
        if f"CH{int(session_id)} CLOSED" in summary_text:
            return "CLOSED"
        if f"CH{int(session_id)} CLOSE FAIL" in summary_text:
            return "CLOSE FAIL"
        if f"CH{int(session_id)} CLOSE" in summary_text or "CLOSE CHANNEL" in summary_text:
            return "CLOSE"
    return ""


def _summary_channel_session_fqdn(
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> str:
    return _summary_channel_session_context_label(session_rows, annotations).fqdn


def _summary_channel_session_context_label(
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> _ChannelSessionContextLabel:
    latest_label = _ChannelSessionContextLabel()
    latest_fqdn_by_kind: dict[str, str] = {}
    for row in session_rows:
        annotation = annotations.get(int(row.number))
        label = _summary_row_channel_session_context_label(row, annotation)
        if len(label.kind) == 0:
            continue
        if len(label.fqdn) > 0:
            latest_fqdn_by_kind[label.kind] = label.fqdn
            latest_label = label
            continue
        fallback_fqdn = latest_fqdn_by_kind.get(label.kind, "")
        latest_label = _ChannelSessionContextLabel(label.kind, fallback_fqdn)
    return latest_label


def _summary_channel_session_text_label(search_text: str) -> _ChannelSessionContextLabel:
    normalized = _normalized_summary_label_text(search_text)
    if len(normalized) == 0:
        return _ChannelSessionContextLabel()
    lowered = normalized.lower()
    if any(
        marker in lowered
        for marker in ("tls handshake:", "tls record:", "tls alert:", "clienthello", "serverhello", "sni=")
    ):
        return _ChannelSessionContextLabel(
            "TLS",
            _summary_channel_session_match_fqdn(
                normalized,
                patterns=(
                    r"\bsni=([A-Za-z0-9._-]+(?::\d+)?)",
                    r"\bserver_name=([A-Za-z0-9._-]+(?::\d+)?)",
                    r"\bserver name(?: indication)?:\s*([A-Za-z0-9._-]+(?::\d+)?)",
                ),
            ),
        )
    if any(
        marker in lowered
        for marker in ("dns query:", "dns response:", "http request:", "http response:", "qname=", "host=", "authority=")
    ):
        return _ChannelSessionContextLabel(
            "eIM",
            _summary_channel_session_match_fqdn(
                normalized,
                patterns=(
                    r"\bqname=([A-Za-z0-9._-]+(?::\d+)?)",
                    r"\bhost=([A-Za-z0-9._-]+(?::\d+)?)",
                    r"\bauthority=([A-Za-z0-9._-]+(?::\d+)?)",
                    r"\bhost:\s*([A-Za-z0-9._-]+(?::\d+)?)",
                    r"\b:authority:\s*([A-Za-z0-9._-]+(?::\d+)?)",
                ),
            ),
        )
    return _ChannelSessionContextLabel()


def _summary_channel_session_match_fqdn(search_text: str, *, patterns: tuple[str, ...]) -> str:
    for pattern in patterns:
        match = re.search(pattern, search_text, flags=re.IGNORECASE)
        if match is None:
            continue
        normalized_fqdn = _normalize_session_fqdn(str(match.group(1) or ""))
        if len(normalized_fqdn) > 0:
            return normalized_fqdn
    return ""


def _normalize_session_fqdn(candidate: str) -> str:
    normalized = str(candidate or "").strip().strip(".,;)]")
    if len(normalized) == 0:
        return ""
    if ":" in normalized and normalized.count(":") == 1:
        host_text, port_text = normalized.rsplit(":", 1)
        if len(host_text) > 0 and port_text.isdigit():
            normalized = host_text
    normalized = normalized.strip().strip(".").lower()
    if len(normalized) == 0 or "." not in normalized:
        return ""
    return normalized


def _summary_row_channel_session_context_label(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> _ChannelSessionContextLabel:
    search_texts = [
        _normalized_summary_label_text(getattr(annotation, "summary_suffix", "")),
        _normalized_summary_label_text(row.info),
    ]
    for search_text in search_texts:
        label = _summary_channel_session_text_label(search_text)
        if len(label.kind) > 0:
            return label
    return _ChannelSessionContextLabel()


def _summary_channel_session_row_context_labels(
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> dict[int, _ChannelSessionContextLabel]:
    raw_labels_by_frame: dict[int, _ChannelSessionContextLabel] = {}
    default_fqdn_by_kind: dict[str, str] = {}
    for row in session_rows:
        annotation = annotations.get(int(row.number))
        label = _summary_row_channel_session_context_label(row, annotation)
        raw_labels_by_frame[int(row.number)] = label
        if len(label.kind) > 0 and len(label.fqdn) > 0 and label.kind not in default_fqdn_by_kind:
            default_fqdn_by_kind[label.kind] = label.fqdn
    normalized_labels_by_frame: dict[int, _ChannelSessionContextLabel] = {}
    for row in session_rows:
        label = raw_labels_by_frame.get(int(row.number), _ChannelSessionContextLabel())
        if len(label.kind) == 0:
            normalized_labels_by_frame[int(row.number)] = _ChannelSessionContextLabel()
            continue
        normalized_labels_by_frame[int(row.number)] = _ChannelSessionContextLabel(
            label.kind,
            label.fqdn or default_fqdn_by_kind.get(label.kind, ""),
        )
    return normalized_labels_by_frame


def _summary_partition_channel_session_context_rows(
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> tuple[list[tuple[_ChannelSessionContextLabel, list[PacketSummary]]], list[PacketSummary]]:
    row_context_labels = _summary_channel_session_row_context_labels(session_rows, annotations)
    context_rows_by_label: dict[_ChannelSessionContextLabel, list[PacketSummary]] = {}
    ordered_context_labels: list[_ChannelSessionContextLabel] = []
    context_first_index: dict[_ChannelSessionContextLabel, int] = {}
    unbound_rows: list[PacketSummary] = []
    for row in session_rows:
        context_label = row_context_labels.get(int(row.number), _ChannelSessionContextLabel())
        if len(context_label.kind) == 0:
            unbound_rows.append(row)
            continue
        context_bucket = context_rows_by_label.setdefault(context_label, [])
        if len(context_bucket) == 0:
            context_first_index[context_label] = len(ordered_context_labels)
            ordered_context_labels.append(context_label)
        context_bucket.append(row)
    ordered_context_labels.sort(
        key=lambda context_label: (
            _summary_channel_session_context_rank(context_label),
            context_first_index.get(context_label, 0),
        )
    )
    return (
        [(context_label, context_rows_by_label[context_label]) for context_label in ordered_context_labels],
        unbound_rows,
    )


def _summary_channel_session_context_rank(context_label: _ChannelSessionContextLabel) -> int:
    normalized_kind = str(context_label.kind or "").strip().upper()
    if normalized_kind == "TLS":
        return 0
    if normalized_kind == "EIM":
        return 1
    if len(normalized_kind) == 0:
        return 99
    return 2


def _summary_channel_session_context_title(context_label: _ChannelSessionContextLabel) -> str:
    if len(context_label.kind) == 0:
        return "Session"
    if len(context_label.fqdn) > 0:
        return f"{context_label.kind} - {context_label.fqdn}"
    return context_label.kind


def _summary_channel_session_title(
    session_id: int,
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> str:
    if len(session_rows) == 0:
        return f"Poll {int(session_id)}"
    session_occurrence = _summary_channel_session_occurrence(
        session_id,
        session_rows,
        annotations,
    )
    logical_poll_index = _summary_channel_logical_poll_index(
        session_occurrence,
        fallback_index=int(session_id),
    )
    return _summary_channel_poll_title(logical_poll_index)


def _summary_channel_session_occurrence(
    session_id: int,
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> int | None:
    open_row = _summary_channel_session_open_row(session_id, session_rows, annotations)
    ordered_rows = list(session_rows)
    if open_row is not None:
        ordered_rows = [open_row, *[row for row in session_rows if row is not open_row]]
    for row in ordered_rows:
        annotation = annotations.get(int(row.number))
        session_occurrence = _summary_channel_poll_index(annotation)
        if session_occurrence is None:
            continue
        return int(session_occurrence)
    return None


def _summary_channel_logical_poll_index(
    session_occurrence: int | None,
    *,
    fallback_index: int,
) -> int:
    effective_occurrence = fallback_index
    if session_occurrence is not None:
        effective_occurrence = int(session_occurrence)
    effective_occurrence = max(1, int(effective_occurrence))
    return ((effective_occurrence - 1) // 2) + 1


def _summary_channel_poll_key(channel_number: int, poll_index: int) -> str:
    return f"{_summary_channel_number_key(channel_number)}::POLL{int(poll_index)}"


def _summary_group_poll_key(poll_index: int) -> str:
    return f"Channels::POLL{int(poll_index)}"


def _summary_poll_top_level_key(poll_index: int) -> str:
    return f"POLL::{int(poll_index)}"


def _summary_card_session_key(card_session_index: int) -> str:
    return f"CARDSESSION::{int(card_session_index)}"


def _summary_card_session_title(
    card_session_index: int,
    reset_reason: str,
    iccid: str = "",
) -> str:
    parts: list[str] = [f"Card Session {int(card_session_index)}"]
    normalized_iccid = str(iccid or "").strip()
    if len(normalized_iccid) > 0:
        parts.append(f"[{normalized_iccid}]")
    normalized_reason = str(reset_reason or "").strip()
    if len(normalized_reason) > 0:
        parts.append(normalized_reason)
    return " - ".join(parts)


def _summary_partition_rows_by_card_session(
    rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> tuple[
    list[tuple[int, list[PacketSummary]]],
    dict[int, str],
    dict[int, str],
]:
    # Walk the rows once in capture order, grouping by card_session_index
    # (defaults to 1 when an annotation is missing or the field is unset
    # on legacy traces). We also surface the reset reason recorded on
    # the first frame of each new session and the ICCID backfilled onto
    # every frame of the session so the wrapper can be captioned with
    # both pieces.
    rows_by_session: dict[int, list[PacketSummary]] = {}
    ordered_session_indices: list[int] = []
    reset_reasons: dict[int, str] = {}
    iccids: dict[int, str] = {}
    for row in rows:
        annotation = annotations.get(int(row.number))
        card_session_index = int(
            getattr(annotation, "card_session_index", 1) or 1
        )
        if card_session_index not in rows_by_session:
            rows_by_session[card_session_index] = []
            ordered_session_indices.append(card_session_index)
        rows_by_session[card_session_index].append(row)
        reason_text = str(
            getattr(annotation, "card_session_reset_reason", "") or ""
        ).strip()
        if (
            len(reason_text) > 0
            and card_session_index not in reset_reasons
        ):
            reset_reasons[card_session_index] = reason_text
        iccid_text = str(
            getattr(annotation, "card_session_iccid", "") or ""
        ).strip()
        if (
            len(iccid_text) > 0
            and card_session_index not in iccids
        ):
            iccids[card_session_index] = iccid_text
    ordered_session_indices.sort()
    return (
        [(idx, rows_by_session[idx]) for idx in ordered_session_indices],
        reset_reasons,
        iccids,
    )


def _summary_channel_poll_title(poll_index: int) -> str:
    return f"Poll {int(poll_index)}"


def _summary_poll_top_level_title(poll_index: int, poll_fqdn: str) -> str:
    base_title = _summary_channel_poll_title(int(poll_index))
    normalized_fqdn = str(poll_fqdn or "").strip()
    if len(normalized_fqdn) == 0:
        return base_title
    return f"{base_title} - {normalized_fqdn}"


_SESSION_ENDPOINT_APN_PATTERN = re.compile(
    r"OPEN\s+(?P<transport>[\w-]+)://(?P<endpoint>\S+?)(?:\s+APN:(?P<apn>\S+))?(?:\s*\||\s*$)",
    re.IGNORECASE,
)
_SESSION_ENDPOINT_PORT_PATTERN = re.compile(r":(?P<port>\d+)(?:/|$)")

_SESSION_ROLE_DNS = "DNS"
_SESSION_ROLE_EIM = "eIM"
_SESSION_ROLE_UNKNOWN = "Session"

_DNS_ENDPOINT_PORTS: frozenset[int] = frozenset({53})
_EIM_ENDPOINT_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})


def _extract_session_endpoint_apn_and_transport(
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> tuple[str, str, str]:
    # The OPEN CHANNEL request row's summary suffix carries the full BIP
    # target ("OPEN tcp-client-remote://IP:PORT APN:<name>"). Parse it
    # directly so the session label can show the concrete transport
    # endpoint together with the APN it is bound to, and so that the
    # caller can classify the session (DNS vs eIM) from the transport
    # scheme rather than from chronological ordering.
    for row in session_rows:
        annotation = annotations.get(int(row.number))
        summary_text = str(getattr(annotation, "summary_suffix", "") or "")
        if "OPEN " not in summary_text.upper():
            continue
        match = _SESSION_ENDPOINT_APN_PATTERN.search(summary_text)
        if match is None:
            continue
        endpoint = str(match.group("endpoint") or "").strip().strip("/")
        apn = str(match.group("apn") or "").strip()
        transport = str(match.group("transport") or "").strip()
        if len(endpoint) > 0:
            return endpoint, apn, transport
    return "", "", ""


def _extract_session_endpoint_and_apn(
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> tuple[str, str]:
    endpoint_text, apn_text, _transport = _extract_session_endpoint_apn_and_transport(
        session_rows, annotations
    )
    return endpoint_text, apn_text


def _session_port_from_endpoint(endpoint_text: str) -> int | None:
    normalized = str(endpoint_text or "").strip()
    if len(normalized) == 0:
        return None
    match = _SESSION_ENDPOINT_PORT_PATTERN.search(normalized)
    if match is None:
        return None
    try:
        return int(match.group("port"))
    except (TypeError, ValueError):
        return None


def _classify_session_role(endpoint_text: str, transport_text: str) -> str:
    # Port wins over transport: a UDP session on :443 still counts as an
    # eIM endpoint, and TCP on :53 is still a DNS endpoint. Anything that
    # doesn't match either rule falls through to the UDP/TCP heuristic.
    port = _session_port_from_endpoint(endpoint_text)
    if port is not None:
        if port in _DNS_ENDPOINT_PORTS:
            return _SESSION_ROLE_DNS
        if port in _EIM_ENDPOINT_PORTS:
            return _SESSION_ROLE_EIM
    transport = str(transport_text or "").strip().lower()
    if transport.startswith("udp"):
        return _SESSION_ROLE_DNS
    if transport.startswith("tcp"):
        return _SESSION_ROLE_EIM
    return _SESSION_ROLE_UNKNOWN


def _summary_poll_session_title(
    role: str,
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
) -> str:
    endpoint_text, apn_text = _extract_session_endpoint_and_apn(
        session_rows, annotations
    )
    parts: list[str] = [str(role or "").strip() or _SESSION_ROLE_UNKNOWN]
    if len(endpoint_text) > 0:
        parts.append(endpoint_text)
    if len(apn_text) > 0:
        parts.append(apn_text)
    return " - ".join(parts)


def _summary_poll_role_for_occurrence(global_occurrence: int) -> str:
    # Legacy helper kept for backwards compatibility. The partitioner no
    # longer relies on occurrence parity to classify sessions; port /
    # transport now drive the role. The ordering-based rule is still used
    # as a last-resort fallback when the OPEN CHANNEL payload is missing
    # and neither port nor transport can be parsed.
    if int(global_occurrence) % 2 == 0:
        return _SESSION_ROLE_EIM
    return _SESSION_ROLE_DNS


def _summary_partition_poll_rows_with_labels(
    session_buckets: list[tuple[int, list[PacketSummary]]],
    annotations: dict[int, StatefulFrameAnnotation],
) -> list[tuple[int, list[tuple[int, str, list[PacketSummary]]]]]:
    # Chronologically order sessions by first frame, then pair them into
    # polls using the role derived from the OPEN CHANNEL endpoint. A DNS
    # session starts a new poll; a following eIM session joins that poll;
    # any other sequence (orphan DNS, orphan eIM, unknown transport) is
    # promoted into a standalone poll so the tree never silently mislabels
    # a TLS/eIM endpoint as "DNS" just because its sibling was missed.
    ordered_session_buckets = sorted(
        list(session_buckets),
        key=lambda item: (
            int(item[1][0].number) if len(item[1]) > 0 else int(item[0])
        ),
    )
    session_records: list[tuple[int, str, list[PacketSummary]]] = []
    fallback_occurrence = 0
    for session_id, session_rows in ordered_session_buckets:
        fallback_occurrence += 1
        endpoint_text, _apn_text, transport_text = (
            _extract_session_endpoint_apn_and_transport(session_rows, annotations)
        )
        role = _classify_session_role(endpoint_text, transport_text)
        if role == _SESSION_ROLE_UNKNOWN:
            role = _summary_poll_role_for_occurrence(fallback_occurrence)
        session_records.append((int(session_id), role, list(session_rows)))

    ordered_polls: list[tuple[int, list[tuple[int, str, list[PacketSummary]]]]] = []
    current_poll: list[tuple[int, str, list[PacketSummary]]] = []
    current_has_dns = False
    current_has_eim = False
    poll_index = 0

    def _flush_current_poll() -> None:
        nonlocal current_poll, current_has_dns, current_has_eim, poll_index
        if len(current_poll) == 0:
            return
        poll_index += 1
        poll_sessions: list[tuple[int, str, list[PacketSummary]]] = []
        for session_id, role_title, session_rows in current_poll:
            session_title = _summary_poll_session_title(
                role_title, session_rows, annotations
            )
            poll_sessions.append(
                (int(session_id), str(session_title), list(session_rows))
            )
        ordered_polls.append((int(poll_index), poll_sessions))
        current_poll = []
        current_has_dns = False
        current_has_eim = False

    for session_id, role, session_rows in session_records:
        if role == _SESSION_ROLE_DNS:
            # A second DNS without an intervening eIM, or a DNS after an
            # orphan eIM, means the prior poll is already done. Close it
            # before opening a fresh one so the new DNS always anchors its
            # own poll.
            if len(current_poll) > 0:
                _flush_current_poll()
            current_poll.append((int(session_id), role, list(session_rows)))
            current_has_dns = True
        elif role == _SESSION_ROLE_EIM:
            if current_has_dns and not current_has_eim:
                # Valid DNS -> eIM pair: attach the eIM leg and close the
                # poll now that both halves are accounted for.
                current_poll.append((int(session_id), role, list(session_rows)))
                current_has_eim = True
                _flush_current_poll()
            else:
                # Orphan eIM (duplicate, or arrived without a preceding
                # DNS). Flush whatever was pending and emit the eIM as
                # its own poll so the label still reads "eIM - ..."
                # rather than being silently mispaired.
                if len(current_poll) > 0:
                    _flush_current_poll()
                current_poll.append((int(session_id), role, list(session_rows)))
                current_has_eim = True
                _flush_current_poll()
        else:
            if len(current_poll) > 0:
                _flush_current_poll()
            current_poll.append((int(session_id), role, list(session_rows)))
            _flush_current_poll()
    _flush_current_poll()
    return ordered_polls


def _resolve_poll_fqdn(
    poll_sessions: list[tuple[int, str, list[PacketSummary]]],
    annotations: dict[int, StatefulFrameAnnotation],
) -> str:
    # Prefer the DNS session's resolved qname, then fall back to any
    # session's observed FQDN (TLS SNI, HTTP host, etc.). Both halves of a
    # poll almost always share the same target host, so returning the
    # first non-empty candidate is correct.
    for _session_id, _session_title, session_rows in poll_sessions:
        candidate = _summary_channel_session_fqdn(session_rows, annotations)
        if len(candidate) > 0:
            return candidate
    return ""


def _summary_channel_session_role_title(
    session_occurrence: int | None,
    session_rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
    *,
    fallback_index: int,
) -> str:
    effective_occurrence = fallback_index
    if session_occurrence is not None:
        effective_occurrence = int(session_occurrence)
    base_title = "DNS Lookup"
    if int(effective_occurrence) % 2 == 0:
        base_title = "eIM"
    session_fqdn = _summary_channel_session_fqdn(session_rows, annotations)
    if len(session_fqdn) > 0:
        return f"{base_title} - {session_fqdn}"
    return base_title


def _summary_partition_channel_poll_rows(
    session_buckets: list[tuple[int, list[PacketSummary]]],
    annotations: dict[int, StatefulFrameAnnotation],
) -> list[tuple[int, list[tuple[int, str, list[PacketSummary]]]]]:
    poll_sessions_by_index: dict[int, list[tuple[int, int, str, list[PacketSummary]]]] = {}
    ordered_poll_indices: list[int] = []
    fallback_occurrence = 0
    for session_id, session_rows in session_buckets:
        session_occurrence = _summary_channel_session_occurrence(
            session_id,
            session_rows,
            annotations,
        )
        effective_occurrence = session_occurrence
        if effective_occurrence is None:
            fallback_occurrence += 1
            effective_occurrence = fallback_occurrence
        else:
            effective_occurrence = int(effective_occurrence)
            fallback_occurrence = max(fallback_occurrence, effective_occurrence)
        logical_poll_index = _summary_channel_logical_poll_index(
            effective_occurrence,
            fallback_index=fallback_occurrence,
        )
        session_title = _summary_channel_session_role_title(
            effective_occurrence,
            session_rows,
            annotations,
            fallback_index=fallback_occurrence,
        )
        if logical_poll_index not in poll_sessions_by_index:
            ordered_poll_indices.append(int(logical_poll_index))
            poll_sessions_by_index[int(logical_poll_index)] = []
        poll_sessions_by_index[int(logical_poll_index)].append(
            (
                int(effective_occurrence),
                int(session_id),
                session_title,
                list(session_rows),
            )
        )
    ordered_polls: list[tuple[int, list[tuple[int, str, list[PacketSummary]]]]] = []
    for poll_index in ordered_poll_indices:
        poll_sessions = list(poll_sessions_by_index.get(int(poll_index), []))
        poll_sessions.sort(key=lambda entry: int(entry[0]))
        ordered_polls.append(
            (
                int(poll_index),
                [
                    (int(session_id), str(session_title), list(session_rows))
                    for _occurrence, session_id, session_title, session_rows in poll_sessions
                ],
            )
        )
    return ordered_polls


def _summary_partition_group_poll_rows(
    session_buckets: list[tuple[int, list[PacketSummary]]],
    annotations: dict[int, StatefulFrameAnnotation],
) -> list[tuple[int, list[tuple[int, str, list[PacketSummary]]]]]:
    # Collapsed variant used after the "Channel N" layer was dropped from the
    # Channels context tree. Sessions are ordered chronologically by their
    # first frame so that the sequential global occurrence counter pairs the
    # DNS-Lookup / eIM sessions in the order they were actually observed on
    # the wire, regardless of which channel number happened to carry them.
    ordered_session_buckets = sorted(
        list(session_buckets),
        key=lambda item: (
            int(item[1][0].number) if len(item[1]) > 0 else int(item[0])
        ),
    )
    poll_sessions_by_index: dict[int, list[tuple[int, int, str, list[PacketSummary]]]] = {}
    ordered_poll_indices: list[int] = []
    for occurrence_index, (session_id, session_rows) in enumerate(
        ordered_session_buckets, start=1
    ):
        global_occurrence = int(occurrence_index)
        logical_poll_index = ((global_occurrence - 1) // 2) + 1
        role_title = _summary_channel_session_role_title(
            global_occurrence,
            session_rows,
            annotations,
            fallback_index=global_occurrence,
        )
        channel_number: int | None = None
        for row in session_rows:
            annotation = annotations.get(int(row.number))
            resolved_channel_number = _summary_channel_number(annotation)
            if resolved_channel_number is not None:
                channel_number = int(resolved_channel_number)
                break
        if channel_number is None:
            session_title = role_title
        else:
            session_title = f"{role_title} (CH{int(channel_number)})"
        if logical_poll_index not in poll_sessions_by_index:
            ordered_poll_indices.append(int(logical_poll_index))
            poll_sessions_by_index[int(logical_poll_index)] = []
        poll_sessions_by_index[int(logical_poll_index)].append(
            (
                int(global_occurrence),
                int(session_id),
                str(session_title),
                list(session_rows),
            )
        )
    ordered_polls: list[tuple[int, list[tuple[int, str, list[PacketSummary]]]]] = []
    for poll_index in ordered_poll_indices:
        poll_sessions = list(poll_sessions_by_index.get(int(poll_index), []))
        poll_sessions.sort(key=lambda entry: int(entry[0]))
        ordered_polls.append(
            (
                int(poll_index),
                [
                    (int(session_id), str(session_title), list(session_rows))
                    for _occurrence, session_id, session_title, session_rows in poll_sessions
                ],
            )
        )
    return ordered_polls


def _summary_channel_session_context_key(
    session_id: int,
    context_label: _ChannelSessionContextLabel,
) -> str:
    kind_text = str(context_label.kind or "").strip().lower() or "unknown"
    fqdn_text = str(context_label.fqdn or "").strip().lower()
    return f"{_summary_channel_session_key(session_id)}::CTX::{kind_text}::{fqdn_text}"


def _summary_channel_title(channel_number: int) -> str:
    return f"Channel {int(channel_number)}"


def _summary_base_info_text(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> str | None:
    info_text = _normalized_summary_label_text(row.info)
    if len(info_text) == 0:
        return None
    if annotation is None:
        return info_text
    suffix = _normalized_summary_label_text(annotation.summary_suffix)
    if len(suffix) == 0:
        return info_text
    if info_text == suffix:
        return None
    if info_text.endswith(suffix):
        prefix = info_text[: len(info_text) - len(suffix)].rstrip()
        if prefix.endswith("|"):
            prefix = prefix[:-1].rstrip()
        if len(prefix) > 0:
            return prefix
        return None
    return info_text


def _normalized_summary_label_text(value: object) -> str:
    normalized = str(value or "").strip()
    if len(normalized) == 0:
        return ""
    normalized = re.sub(r"\s+", " ", normalized)
    normalized = re.sub(r"\s*\|\s*", " | ", normalized)
    return normalized.strip()


def _summary_display_label_text(value: object) -> str:
    normalized = _normalized_summary_label_text(value)
    if len(normalized) == 0:
        return ""
    cleaned_parts: list[str] = []
    for raw_part in normalized.split(" | "):
        cleaned_part = re.sub(r"^CH\d+\s+", "", str(raw_part or "").strip())
        cleaned_part = cleaned_part.strip()
        if len(cleaned_part) == 0:
            continue
        cleaned_parts.append(cleaned_part)
    return " | ".join(cleaned_parts)


def _summary_display_time_text(row: PacketSummary) -> str:
    wall_time_text = str(getattr(row, "wall_time_text", "") or "").strip()
    if len(wall_time_text) > 0:
        return wall_time_text
    return str(row.time_text or "").strip()


def _is_hidden_transport_endpoint(value: str) -> bool:
    normalized = str(value or "").strip().lower()
    if len(normalized) == 0:
        return True
    return normalized in {
        "127.0.0.1",
        "::1",
        "localhost",
        "ip6-localhost",
        "localhost.localdomain",
    }


def _packet_route_text(row: PacketSummary) -> str | None:
    source_text = _normalized_summary_label_text(row.source)
    destination_text = _normalized_summary_label_text(row.destination)
    if len(source_text) == 0 or len(destination_text) == 0:
        return None
    if source_text == destination_text:
        return None
    if _is_hidden_transport_endpoint(source_text) and _is_hidden_transport_endpoint(destination_text):
        return None
    return _normalized_summary_label_text(f"{source_text} -> {destination_text}")


def _summary_secondary_text(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
) -> str | None:
    base_info = _summary_base_info_text(row, annotation)
    if base_info is not None:
        return base_info
    route_text = _packet_route_text(row)
    if route_text is not None:
        return route_text
    protocol_text = str(row.protocol or "").strip()
    if len(protocol_text) > 0 and protocol_text.upper() != "GSM SIM":
        return protocol_text
    return None


def _summary_visible_text_parts(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
    *,
    show_expert_details: bool,
) -> tuple[str, str | None]:
    primary_text = _summary_primary_text(row, annotation)
    secondary_text = _summary_secondary_text(row, annotation)
    if show_expert_details:
        return (primary_text, secondary_text)
    if secondary_text is not None:
        return (secondary_text, None)
    return (primary_text, None)


def _summary_group_color(group_name: str, palette: TuiThemePalette) -> str:
    return {
        "Channels": palette.bip,
        "BIP": palette.bip,
        "STK": palette.stk,
        "ETSI FS": palette.fs,
        "Timer": palette.timer,
        "eUICC": palette.euicc,
        "Authentication": palette.security,
        "Security": palette.security,
        "Other APDU": palette.other,
    }.get(str(group_name or "").strip(), palette.primary)


def _summary_group_style(group_name: str, palette: TuiThemePalette) -> str:
    return f"bold {_summary_group_color(group_name, palette)}"


def _summary_context_style(group_name: str, palette: TuiThemePalette) -> str:
    return f"dim {_summary_group_color(group_name, palette)}"


def _summary_selection_cursor_target(frame_node, expanded_group_names: set[str]):
    target_node = frame_node
    current_node = frame_node
    while current_node is not None:
        parent_node = getattr(current_node, "parent", None)
        if parent_node is None:
            break
        expand_key = _summary_expand_key(getattr(parent_node, "data", None))
        if len(expand_key) > 0 and expand_key not in expanded_group_names:
            target_node = parent_node
        current_node = parent_node
    return target_node


def _summary_highlighted_frame_number(tree_widget, highlighted_node) -> int | None:
    cursor_node = getattr(tree_widget, "cursor_node", None)
    if cursor_node is not None and cursor_node is not highlighted_node:
        return None
    node_data = getattr(highlighted_node, "data", None)
    if isinstance(node_data, dict) is False:
        return None
    frame_number = node_data.get("frame_number")
    if isinstance(frame_number, int) is False:
        return None
    return int(frame_number)


def _summary_highlighted_node_key(tree_widget, highlighted_node) -> str | None:
    # Returns a stable expand_key for any non-frame tree node (poll / channel
    # session / STK / FS / Card Session wrapper, etc). Frame leaves are
    # intentionally ignored here; their identity is already tracked via
    # _selected_frame_number. When the incoming highlight event is stale
    # (cursor has already moved elsewhere), None is returned so the caller
    # skips the update.
    cursor_node = getattr(tree_widget, "cursor_node", None)
    if cursor_node is not None and cursor_node is not highlighted_node:
        return None
    node_data = getattr(highlighted_node, "data", None)
    if isinstance(node_data, dict) is False:
        return None
    if isinstance(node_data.get("frame_number"), int):
        return None
    expand_key = _summary_expand_key(node_data)
    if len(expand_key) == 0:
        return None
    return expand_key


def _collect_summary_tree_header_nodes(tree_widget) -> dict[str, object]:
    # Walk the Tree after _populate_summary_tree has rebuilt the structure
    # and index every non-frame node by its expand_key. The result is used
    # to reposition the cursor on the exact same header (Poll N / DNS /
    # eIM / Card Session wrapper) the user was browsing before the
    # throttled rebuild replaced the node instances.
    header_nodes: dict[str, object] = {}
    root = getattr(tree_widget, "root", None)
    if root is None:
        return header_nodes
    stack: list[object] = list(getattr(root, "children", []) or [])
    while len(stack) > 0:
        node = stack.pop()
        node_data = getattr(node, "data", None)
        if isinstance(node_data, dict):
            if isinstance(node_data.get("frame_number"), int) is False:
                expand_key = _summary_expand_key(node_data)
                if len(expand_key) > 0 and expand_key not in header_nodes:
                    header_nodes[expand_key] = node
        children = getattr(node, "children", []) or []
        if len(children) > 0:
            stack.extend(list(children))
    return header_nodes


def _move_summary_cursor_to_node_key(
    tree_widget,
    header_nodes: dict[str, object],
    node_key: str | None,
    *,
    should_scroll: bool = False,
) -> bool:
    # Mirrors _move_summary_selection_cursor but targets a non-frame
    # header node identified by its expand_key. Used to pin the cursor
    # to whichever Poll / Session / Card Session wrapper the user was
    # browsing so a live refresh doesn't yank it back to the top row.
    if node_key is None:
        return False
    key_text = str(node_key or "").strip()
    if len(key_text) == 0:
        return False
    target_node = header_nodes.get(key_text)
    if target_node is None:
        return False
    move_cursor = getattr(tree_widget, "move_cursor", None)
    if callable(move_cursor) is False:
        return False

    def _invoke_move_cursor() -> bool:
        try:
            move_cursor(target_node, animate=False)
        except TypeError:
            try:
                move_cursor(target_node)
            except Exception:
                return False
        except Exception:
            return False
        return True

    if should_scroll is False:
        with _suppress_tree_scroll_side_effects(tree_widget):
            if _invoke_move_cursor() is False:
                return False
        return True

    if _invoke_move_cursor() is False:
        return False
    scroll_to_node = getattr(tree_widget, "scroll_to_node", None)
    if callable(scroll_to_node):
        try:
            scroll_to_node(target_node, animate=False)
        except TypeError:
            try:
                scroll_to_node(target_node)
            except Exception:
                pass
        except Exception:
            pass
    return True


@contextmanager
def _suppress_tree_scroll_side_effects(tree_widget):
    # Textual's Tree.move_cursor always routes through scroll_to_node →
    # scroll_to_line → scroll_to_region, and scroll_to_region defers the
    # actual scroll until after the next screen refresh (immediate=False).
    # That means a naive capture-restore of scroll_y around move_cursor is
    # a no-op: Textual scrolls later. Monkey-patching scroll_to_region to
    # a null Offset for the duration of move_cursor cleanly neutralises
    # every internal scroll path at the source, with no deferred surprise
    # for the user's viewport.
    original_scroll_to_region = getattr(tree_widget, "scroll_to_region", None)
    original_scroll_to_line = getattr(tree_widget, "scroll_to_line", None)
    original_scroll_to_node = getattr(tree_widget, "scroll_to_node", None)

    def _noop_scroll_to_region(*_args, **_kwargs):
        try:
            from textual.geometry import Offset as _Offset

            return _Offset(0, 0)
        except Exception:
            return None

    def _noop(*_args, **_kwargs) -> None:
        return None

    try:
        if callable(original_scroll_to_region):
            tree_widget.scroll_to_region = _noop_scroll_to_region  # type: ignore[attr-defined]
        if callable(original_scroll_to_line):
            tree_widget.scroll_to_line = _noop  # type: ignore[attr-defined]
        if callable(original_scroll_to_node):
            tree_widget.scroll_to_node = _noop  # type: ignore[attr-defined]
        yield
    finally:
        if callable(original_scroll_to_region):
            try:
                tree_widget.scroll_to_region = original_scroll_to_region  # type: ignore[attr-defined]
            except Exception:
                pass
        if callable(original_scroll_to_line):
            try:
                tree_widget.scroll_to_line = original_scroll_to_line  # type: ignore[attr-defined]
            except Exception:
                pass
        if callable(original_scroll_to_node):
            try:
                tree_widget.scroll_to_node = original_scroll_to_node  # type: ignore[attr-defined]
            except Exception:
                pass


def _move_summary_selection_cursor(
    tree_widget,
    frame_nodes: dict[int, object],
    selected_frame_number: int | None,
    expanded_group_names: set[str],
    *,
    should_scroll: bool = True,
) -> bool:
    if selected_frame_number is None:
        return False
    frame_node = frame_nodes.get(int(selected_frame_number))
    if frame_node is None:
        return False
    target_node = _summary_selection_cursor_target(
        frame_node,
        expanded_group_names,
    )
    move_cursor = getattr(tree_widget, "move_cursor", None)
    if callable(move_cursor) is False:
        return False

    def _invoke_move_cursor() -> bool:
        try:
            move_cursor(target_node, animate=False)
        except TypeError:
            try:
                move_cursor(target_node)
            except Exception:
                return False
        except Exception:
            return False
        return True

    if should_scroll is False:
        with _suppress_tree_scroll_side_effects(tree_widget):
            if _invoke_move_cursor() is False:
                return False
        return True

    if _invoke_move_cursor() is False:
        return False
    scroll_to_node = getattr(tree_widget, "scroll_to_node", None)
    if callable(scroll_to_node):
        try:
            scroll_to_node(target_node, animate=False)
        except TypeError:
            try:
                scroll_to_node(target_node)
            except Exception:
                pass
        except Exception:
            pass
    return True


def _capture_summary_tree_scroll_offset(tree_widget) -> tuple[float, float] | None:
    try:
        scroll_x = float(getattr(tree_widget, "scroll_x", 0.0) or 0.0)
        scroll_y = float(getattr(tree_widget, "scroll_y", 0.0) or 0.0)
    except Exception:
        return None
    return (scroll_x, scroll_y)


def _restore_summary_tree_scroll_offset(tree_widget, offset: tuple[float, float] | None) -> None:
    if offset is None:
        return
    scroll_to = getattr(tree_widget, "scroll_to", None)
    if callable(scroll_to) is False:
        return
    try:
        scroll_to(x=offset[0], y=offset[1], animate=False)
    except TypeError:
        try:
            scroll_to(x=offset[0], y=offset[1])
        except Exception:
            return
    except Exception:
        return


def _apply_summary_tree_expand_state_change(
    expanded_group_names: set[str],
    node_data: object,
    *,
    expanded: bool,
    sync_inflight: bool,
) -> bool:
    if sync_inflight:
        return False
    expand_key = _summary_expand_key(node_data)
    if len(expand_key) == 0:
        return False
    if expanded:
        expanded_group_names.add(expand_key)
        return True
    expanded_group_names.discard(expand_key)
    return True


def _summary_tree_batch_update_context(tree_widget):
    app = getattr(tree_widget, "app", None)
    batch_update = getattr(app, "batch_update", None)
    if callable(batch_update):
        try:
            return batch_update()
        except Exception:
            return nullcontext()
    return nullcontext()


def _classify_queued_row_bucket(row) -> str:
    # Maps a PacketSummary to a short bucket label used in the paused
    # status suffix so operators can see whether the backlog is APDU
    # heavy, STK heavy, or bearer noise. Short labels keep the status
    # line readable when several buckets are active simultaneously.
    protocol_text = str(getattr(row, "protocol", "") or "").strip()
    info_text = str(getattr(row, "info", "") or "").strip()
    combined = f"{protocol_text} {info_text}".lower()
    if len(combined.strip()) == 0:
        return "OTHER"
    if "sat" in combined or "stk" in combined or "proactive" in combined or " bip" in f" {combined}":
        return "STK"
    if "apdu" in combined or "sim" in combined or "uicc" in combined or "gsmtap" in combined:
        return "APDU"
    if "dns" in combined:
        return "DNS"
    if "tls" in combined or "ssl" in combined:
        return "TLS"
    if "http" in combined:
        return "HTTP"
    if "tcp" in combined:
        return "TCP"
    if "udp" in combined:
        return "UDP"
    fallback = protocol_text if len(protocol_text) > 0 else info_text
    fallback_token = fallback.strip().split(" ", 1)[0] if len(fallback) > 0 else "OTHER"
    return fallback_token.upper()[:6] or "OTHER"


def _format_duration_text(seconds: float) -> str:
    # Compact hh/mm/ss formatting suitable for the single-line status
    # bar. Keeps the common case short ("4s", "2m 14s") and falls back
    # to full hours for very long pauses.
    total_seconds = max(0, int(seconds))
    if total_seconds < 60:
        return f"{total_seconds}s"
    minutes, remainder_seconds = divmod(total_seconds, 60)
    if minutes < 60:
        return f"{minutes}m {remainder_seconds:02d}s"
    hours, remainder_minutes = divmod(minutes, 60)
    return f"{hours}h {remainder_minutes:02d}m {remainder_seconds:02d}s"


def _reset_capture_runtime_state(app_like) -> None:
    app_like._capture_generation += 1
    app_like._last_capture_size = -1
    app_like._last_error = ""
    app_like._latest_capture_time_seconds = None
    app_like._latest_capture_monotonic = None
    app_like._base_rows = []
    app_like._rows = []
    app_like._state_annotations = {}
    app_like._interesting_frame_numbers = []
    app_like._summary_tree_frame_nodes = {}
    if hasattr(app_like, "_summary_tree_header_nodes"):
        app_like._summary_tree_header_nodes = {}
    app_like._summary_tree_expanded_groups = set()
    app_like._selected_frame_number = None
    app_like._displayed_selected_frame_number = None
    if hasattr(app_like, "_highlighted_node_key"):
        app_like._highlighted_node_key = None
    app_like._last_parse_completed_monotonic = None
    app_like._last_parse_row_count = 0
    app_like._requested_detail_frame = None
    app_like._detail_cache.clear()
    app_like._bytes_cache.clear()
    app_like._displayed_detail_key = None
    app_like._displayed_bytes_key = None
    app_like._refresh_inflight = False
    app_like._detail_inflight = False
    app_like._follow_tail = True
    if hasattr(app_like, "_live_seen_keys"):
        app_like._live_seen_keys = set()
    if hasattr(app_like, "_live_next_frame_number"):
        app_like._live_next_frame_number = 1
    if hasattr(app_like, "_live_stream_delivered_count"):
        app_like._live_stream_delivered_count = 0
    if hasattr(app_like, "_live_stream_last_rx_monotonic"):
        app_like._live_stream_last_rx_monotonic = None
    if hasattr(app_like, "_summary_rebuild_pending"):
        app_like._summary_rebuild_pending = False
    if hasattr(app_like, "_summary_rebuild_pending_scroll"):
        app_like._summary_rebuild_pending_scroll = False
    if hasattr(app_like, "_last_summary_rebuild_monotonic"):
        app_like._last_summary_rebuild_monotonic = 0.0
    if hasattr(app_like, "_ingest_paused"):
        app_like._ingest_paused = False
    if hasattr(app_like, "_paused_live_rows"):
        app_like._paused_live_rows = []
    if hasattr(app_like, "_ingest_pause_generation"):
        app_like._ingest_pause_generation = int(getattr(app_like, "_ingest_pause_generation", 0)) + 1
    if hasattr(app_like, "_paused_queue_dropped"):
        app_like._paused_queue_dropped = 0
    if hasattr(app_like, "_paused_queue_high_water_mark"):
        app_like._paused_queue_high_water_mark = 0
    if hasattr(app_like, "_paused_queue_protocol_counts"):
        app_like._paused_queue_protocol_counts = {}
    if hasattr(app_like, "_pause_event_count"):
        app_like._pause_event_count = 0
    if hasattr(app_like, "_pause_total_duration_seconds"):
        app_like._pause_total_duration_seconds = 0.0
    if hasattr(app_like, "_pause_started_monotonic"):
        app_like._pause_started_monotonic = None
    if hasattr(app_like, "_auto_pause_hint_samples"):
        app_like._auto_pause_hint_samples = []
    if hasattr(app_like, "_auto_pause_hint_last_emitted_monotonic"):
        app_like._auto_pause_hint_last_emitted_monotonic = None
    if hasattr(app_like, "_clear_capture_view_confirm_deadline"):
        app_like._clear_capture_view_confirm_deadline = 0.0
    if hasattr(app_like, "_force_clip_next_save"):
        app_like._force_clip_next_save = False


def _detail_tree_indent_width(raw_line: str) -> int:
    normalized = str(raw_line or "").replace("\t", "    ")
    return len(normalized) - len(normalized.lstrip(" "))


def _detail_tree_is_expert_line(raw_line: str) -> bool:
    stripped = str(raw_line or "").strip()
    if len(stripped) == 0:
        return False
    lowered = stripped.lower()
    return lowered.startswith("[expert") or lowered.startswith("expert info") or lowered.startswith("[malformed packet")


def _filter_detail_tree_lines(detail_lines: list[str], *, show_expert_details: bool) -> list[str]:
    if show_expert_details:
        return [str(raw_line or "").rstrip("\n") for raw_line in detail_lines]
    filtered_lines: list[str] = []
    hidden_indent: int | None = None
    for raw_line in detail_lines:
        normalized_line = str(raw_line or "").rstrip("\n")
        indent_width = _detail_tree_indent_width(normalized_line)
        if hidden_indent is not None:
            if indent_width > hidden_indent:
                continue
            hidden_indent = None
        if _detail_tree_is_expert_line(normalized_line):
            hidden_indent = indent_width
            continue
        filtered_lines.append(normalized_line)
    return filtered_lines


def _hil_decode_keybind_help_text() -> str:
    return "\n".join(
        (
            "F1          Show keybinds",
            "F2          Pause / resume packet ingest",
            "Ctrl+F2    Pause / resume and discard queued rows",
            "F3          Cycle theme",
            "F4          Cycle summary view",
            "F5          Toggle summary pane",
            "F6          Toggle follow-tail",
            "F7 / ]      Jump next state event",
            "[           Jump previous state event",
            "F8          Toggle decoded pane",
            "Ctrl+F8    Toggle expert details",
            "F9          Toggle bytes pane",
            "F10         Open pane layout menu",
            "F11         Export trace snapshot",
            "Shift+F11  Export clipped to current context",
            "Ctrl+F11   Clear current view",
            "F12         Open capture file",
            "Ctrl+F12   Restore live capture",
            "Tab         Cycle pane focus",
            "Left/Right  Collapse/expand tree nodes",
            "Space       Toggle current detail tree node",
            "Ctrl+Space Toggle all children in detail tree",
            "End         Jump to tail",
            "Q / Ctrl+Q  Quit",
            "Esc         Close this help",
        )
    )


def _tui_layout_preferences_path(capture_path: str) -> Path:
    normalized_capture_path = str(capture_path or "").strip()
    if len(normalized_capture_path) == 0:
        return Path.cwd() / "state" / "hil_termshark" / "live_decode_tui_layout.json"
    return Path(normalized_capture_path).expanduser().resolve().parent / "live_decode_tui_layout.json"


def _normalize_directory_preference(directory_path: str | Path) -> str:
    normalized_directory_path = str(directory_path or "").strip()
    if len(normalized_directory_path) == 0:
        return ""
    return str(Path(normalized_directory_path).expanduser().resolve())


def load_tui_layout_preferences(capture_path: str) -> TuiLayoutPreferences:
    defaults = default_tui_layout_preferences()
    target_path = _tui_layout_preferences_path(capture_path)
    if target_path.is_file() is False:
        return defaults
    try:
        with open(target_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except Exception:
        return defaults
    if isinstance(payload, dict) is False:
        return defaults
    raw_visibility = payload.get("visibility", {})
    summary_visible = defaults.visibility.summary
    detail_visible = defaults.visibility.detail
    bytes_visible = defaults.visibility.bytes
    if isinstance(raw_visibility, dict):
        summary_visible = bool(raw_visibility.get("summary", summary_visible))
        detail_visible = bool(raw_visibility.get("detail", detail_visible))
        bytes_visible = bool(raw_visibility.get("bytes", bytes_visible))
    visibility = PaneVisibility(
        summary=summary_visible,
        detail=detail_visible,
        bytes=bytes_visible,
    )
    if count_visible_panes(visibility) <= 0:
        visibility = defaults.visibility
    try:
        summary_height = int(payload.get("summary_height", defaults.summary_height))
    except Exception:
        summary_height = defaults.summary_height
    try:
        detail_width = int(payload.get("detail_width", defaults.detail_width))
    except Exception:
        detail_width = defaults.detail_width
    summary_view_mode = _normalize_summary_view_mode(
        payload.get("summary_view_mode", defaults.summary_view_mode)
    )
    theme_name = _normalize_theme_name(
        payload.get("theme_name", defaults.theme_name)
    )
    last_export_directory = _normalize_directory_preference(
        payload.get("last_export_directory", defaults.last_export_directory)
    )
    last_capture_open_directory = _normalize_directory_preference(
        payload.get("last_capture_open_directory", defaults.last_capture_open_directory)
    )
    summary_height = max(6, summary_height)
    detail_width = max(28, detail_width)
    return TuiLayoutPreferences(
        visibility=visibility,
        summary_height=summary_height,
        detail_width=detail_width,
        summary_view_mode=summary_view_mode,
        theme_name=theme_name,
        last_export_directory=last_export_directory,
        last_capture_open_directory=last_capture_open_directory,
    )


def save_tui_layout_preferences(capture_path: str, preferences: TuiLayoutPreferences) -> None:
    target_path = _tui_layout_preferences_path(capture_path)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    visibility = preferences.visibility
    if count_visible_panes(visibility) <= 0:
        visibility = default_tui_layout_preferences().visibility
    normalized_last_export_directory = _normalize_directory_preference(
        preferences.last_export_directory
    )
    normalized_last_capture_open_directory = _normalize_directory_preference(
        preferences.last_capture_open_directory
    )
    payload = {
        "visibility": {
            "summary": bool(visibility.summary),
            "detail": bool(visibility.detail),
            "bytes": bool(visibility.bytes),
        },
        "summary_height": max(6, int(preferences.summary_height)),
        "detail_width": max(28, int(preferences.detail_width)),
        "summary_view_mode": _normalize_summary_view_mode(preferences.summary_view_mode),
        "theme_name": _normalize_theme_name(preferences.theme_name),
        "last_export_directory": normalized_last_export_directory,
        "last_capture_open_directory": normalized_last_capture_open_directory,
    }
    temporary_path = target_path.with_suffix(f"{target_path.suffix}.tmp")
    with open(temporary_path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(temporary_path, target_path)


def _normalized_view_text(text: str, placeholder: str) -> str:
    normalized_text = str(text or "")
    if len(normalized_text.strip()) == 0:
        normalized_text = str(placeholder or "")
    if normalized_text.endswith("\n") is False:
        normalized_text += "\n"
    return normalized_text


def _pane_display_name(pane_name: str) -> str:
    normalized_name = str(pane_name or "").strip().lower()
    return {
        "summary": "Summary",
        "detail": "Decoded",
        "bytes": "Bytes",
    }.get(normalized_name, normalized_name)


def _measured_extent(widget, axis_name: str) -> int:
    region = getattr(widget, "region", None)
    if region is not None:
        try:
            value = int(getattr(region, axis_name))
        except Exception:
            value = 0
        if value > 0:
            return value
    size = getattr(widget, "size", None)
    if size is not None:
        try:
            value = int(getattr(size, axis_name))
        except Exception:
            value = 0
        if value > 0:
            return value
    return 0


def _terminfo_supports(term_name: str) -> bool:
    normalized_term = str(term_name or "").strip()
    if len(normalized_term) == 0:
        return False
    infocmp_binary = shutil.which("infocmp")
    if infocmp_binary is None:
        return normalized_term in {
            "screen-256color",
            "tmux-256color",
            "xterm-256color",
            "xterm",
        }
    try:
        completed = subprocess.run(
            [infocmp_binary, normalized_term],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=1,
        )
    except Exception:
        return False
    return completed.returncode == 0


def _preferred_textual_term_value() -> str:
    override_term = str(os.environ.get("YGGDRASIM_HIL_TUI_TERM", "") or "").strip()
    if len(override_term) > 0:
        return override_term
    current_term = str(os.environ.get("TERM", "") or "").strip()
    normalized_current = current_term.lower()
    if len(current_term) > 0 and normalized_current != "dumb":
        if _terminfo_supports(current_term):
            return current_term
        return current_term
    if len(str(os.environ.get("TMUX", "") or "").strip()) > 0:
        for candidate in ("tmux-256color", "screen-256color"):
            if _terminfo_supports(candidate):
                return candidate
    if len(str(os.environ.get("STY", "") or "").strip()) > 0:
        if _terminfo_supports("screen-256color"):
            return "screen-256color"
    for candidate in ("xterm-256color", "xterm"):
        if _terminfo_supports(candidate):
            return candidate
    if len(current_term) > 0 and normalized_current != "dumb":
        return current_term
    return "xterm"


def _saved_trace_directory(capture_path: str) -> Path:
    normalized_capture_path = str(capture_path or "").strip()
    if len(normalized_capture_path) == 0:
        return Path.cwd() / "state" / "hil_termshark" / "saved_traces"
    return Path(normalized_capture_path).expanduser().resolve().parent / "saved_traces"


def _preferred_saved_trace_directory(capture_path: str, last_export_directory: str = "") -> Path:
    normalized_last_export_directory = _normalize_directory_preference(last_export_directory)
    if len(normalized_last_export_directory) > 0:
        return Path(normalized_last_export_directory)
    return _saved_trace_directory(capture_path)


def _display_path_text(path: Path) -> str:
    candidate = Path(path).expanduser().resolve()
    try:
        return str(candidate.relative_to(Path.cwd().resolve()))
    except Exception:
        return str(candidate)


def _capture_picker_initial_directory(capture_path: str, last_open_directory: str = "") -> Path:
    normalized_last_open_directory = _normalize_directory_preference(last_open_directory)
    if len(normalized_last_open_directory) > 0:
        return Path(normalized_last_open_directory)
    normalized_capture_path = str(capture_path or "").strip()
    if len(normalized_capture_path) == 0:
        return Path.cwd()
    candidate = Path(normalized_capture_path).expanduser()
    if candidate.exists() and candidate.is_dir():
        return candidate.resolve()
    return candidate.resolve().parent


def _capture_file_picker_supported() -> bool:
    if len(str(os.environ.get("DISPLAY", "") or "").strip()) > 0:
        return True
    if len(str(os.environ.get("WAYLAND_DISPLAY", "") or "").strip()) > 0:
        return True
    return False


def _normalize_selected_capture_path(path_text: str) -> Path | None:
    normalized_text = str(path_text or "").strip()
    if len(normalized_text) == 0:
        return None
    candidate = Path(normalized_text).expanduser().resolve()
    if candidate.is_file() is False:
        raise FileNotFoundError(f"Selected capture file does not exist: {candidate}")
    return candidate


def _run_capture_picker_command(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except Exception as exc:
        raise RuntimeError(f"Failed to launch desktop file picker: {exc}") from exc
    if completed.returncode != 0:
        stderr_text = str(completed.stderr or "").strip()
        if len(stderr_text) == 0:
            return None
        raise RuntimeError(stderr_text)
    selected_path = str(completed.stdout or "").strip()
    if len(selected_path) == 0:
        return None
    return selected_path


def pick_capture_file_path(capture_path: str = "", last_open_directory: str = "") -> Path | None:
    if _capture_file_picker_supported() is False:
        raise RuntimeError("No desktop display is available for the native file picker.")
    initial_directory = _capture_picker_initial_directory(
        capture_path,
        last_open_directory,
    )
    capture_filter_glob = "*.pcap *.pcapng *.cap *.trace"
    picker_command: list[str] | None = None
    if shutil.which("zenity") is not None:
        picker_command = [
            "zenity",
            "--file-selection",
            "--title=Open capture file",
            f"--filename={str(initial_directory)}/",
            "--file-filter=Capture files | *.pcap *.pcapng *.cap *.trace",
            "--file-filter=All files | *",
        ]
    elif shutil.which("qarma") is not None:
        picker_command = [
            "qarma",
            "--file-selection",
            "--title=Open capture file",
            f"--filename={str(initial_directory)}/",
            "--file-filter=Capture files | *.pcap *.pcapng *.cap *.trace",
            "--file-filter=All files | *",
        ]
    elif shutil.which("yad") is not None:
        picker_command = [
            "yad",
            "--file-selection",
            "--title=Open capture file",
            f"--filename={str(initial_directory)}/",
            "--file-filter=Capture files | *.pcap *.pcapng *.cap *.trace",
            "--file-filter=All files | *",
        ]
    elif shutil.which("kdialog") is not None:
        picker_command = [
            "kdialog",
            "--title",
            "Open capture file",
            "--getopenfilename",
            str(initial_directory),
            f"Capture files ({capture_filter_glob})",
        ]
    if picker_command is not None:
        selected_path = _run_capture_picker_command(picker_command)
        if selected_path is not None:
            return _normalize_selected_capture_path(selected_path)
        return None
    python_executable = str(sys.executable or "").strip()
    if len(python_executable) > 0:
        tkinter_script = (
            "import sys\n"
            "import tkinter as tk\n"
            "from tkinter import filedialog\n"
            "root = tk.Tk()\n"
            "root.withdraw()\n"
            "path = filedialog.askopenfilename(\n"
            "    title='Open capture file',\n"
            "    initialdir=sys.argv[1],\n"
            "    filetypes=[('Capture files', '*.pcap *.pcapng *.cap *.trace'), ('All files', '*')],\n"
            ")\n"
            "root.update()\n"
            "root.destroy()\n"
            "print(path)\n"
        )
        selected_path = _run_capture_picker_command(
            [
                python_executable,
                "-c",
                tkinter_script,
                str(initial_directory),
            ]
        )
        if selected_path is not None:
            return _normalize_selected_capture_path(selected_path)
    raise RuntimeError(
        "No supported desktop file picker is available. Install zenity, qarma, yad, kdialog, or Tk support."
    )


def _default_saved_trace_name(capture_path: str, *, marker_suffix: str = "") -> str:
    source_path = Path(str(capture_path or "").strip()).expanduser()
    suffix = str(source_path.suffix or ".pcap")
    stem = str(source_path.stem or "live_capture")
    timestamp_text = time.strftime("%Y%m%d_%H%M%S")
    normalized_marker = str(marker_suffix or "").strip()
    if len(normalized_marker) > 0 and normalized_marker.startswith("_") is False:
        normalized_marker = f"_{normalized_marker}"
    return f"{stem}_{timestamp_text}{normalized_marker}{suffix}"


def _deduplicate_trace_target_path(target_path: Path) -> Path:
    normalized_target = Path(target_path).expanduser().resolve()
    if normalized_target.exists() is False:
        return normalized_target
    suffix = str(normalized_target.suffix or "")
    stem = str(normalized_target.stem or normalized_target.name or "trace")
    duplicate_index = 1
    while True:
        candidate = normalized_target.with_name(f"{stem}_{duplicate_index:02d}{suffix}")
        if candidate.exists() is False:
            return candidate
        duplicate_index += 1


def _default_saved_trace_path(
    capture_path: str,
    last_export_directory: str = "",
    *,
    marker_suffix: str = "",
) -> Path:
    return _preferred_saved_trace_directory(
        capture_path, last_export_directory
    ) / _default_saved_trace_name(capture_path, marker_suffix=marker_suffix)


def _resolve_trace_target_path(
    capture_path: str,
    target_path: str | Path,
    *,
    marker_suffix: str = "",
) -> Path:
    raw_target_path = str(target_path or "").strip()
    if len(raw_target_path) == 0:
        raise ValueError("Export path must not be empty.")
    requested_path = Path(raw_target_path).expanduser()
    if requested_path.is_absolute() is False:
        requested_path = Path.cwd() / requested_path
    treat_as_directory = (
        raw_target_path.endswith(os.sep)
        or raw_target_path.endswith("/")
        or raw_target_path.endswith("\\")
        or (requested_path.exists() and requested_path.is_dir())
        or (requested_path.exists() is False and len(str(requested_path.suffix or "").strip()) == 0)
    )
    if treat_as_directory:
        requested_path = requested_path / _default_saved_trace_name(
            capture_path, marker_suffix=marker_suffix
        )
    return requested_path.resolve()


def _resolve_wireshark_tool_binary(tool_name: str, tshark_binary: str = "") -> str:
    # Generic helper used by the editcap and capinfos resolvers. Prefer
    # a sibling next to the configured tshark binary (so a bundled /
    # portable Wireshark install takes precedence) and fall back to the
    # first occurrence on PATH. Returns an empty string when nothing is
    # resolvable.
    normalized_tool = str(tool_name or "").strip()
    if len(normalized_tool) == 0:
        return ""
    preferred = str(tshark_binary or "").strip()
    if len(preferred) > 0:
        tshark_path = Path(preferred).expanduser()
        is_windows_tshark = tshark_path.suffix.lower() == ".exe"
        sibling_name = f"{normalized_tool}.exe" if is_windows_tshark else normalized_tool
        sibling_candidate = tshark_path.parent / sibling_name
        try:
            if sibling_candidate.is_file() and os.access(sibling_candidate, os.X_OK):
                return str(sibling_candidate)
        except OSError:
            pass
    resolved = shutil.which(normalized_tool)
    if resolved is not None:
        return resolved
    return ""


def resolve_editcap_binary(tshark_binary: str = "") -> str:
    # editcap ships alongside tshark in every Wireshark install, so the
    # safest resolution is: prefer the sibling next to the tshark binary
    # the TUI was started with, then fall back to the one on PATH. An
    # empty return means the caller must error out cleanly.
    return _resolve_wireshark_tool_binary("editcap", tshark_binary)


def resolve_capinfos_binary(tshark_binary: str = "") -> str:
    # capinfos is used for a pre-flight packet-count probe before we
    # hand a clip range to editcap. Missing capinfos is not fatal: the
    # caller falls back to letting editcap surface its own range error.
    return _resolve_wireshark_tool_binary("capinfos", tshark_binary)


def _count_pcap_packets(source_path: Path, tshark_binary: str = "") -> int:
    # Pre-flight probe used to clamp the editcap clip range before we
    # hand it a value that exceeds the real packet count on disk. Uses
    # `capinfos -M -c` which prints a single `Number of packets = N`
    # line in machine-readable mode. Returns -1 if the probe could not
    # be executed or parsed.
    capinfos_binary = resolve_capinfos_binary(tshark_binary)
    if len(capinfos_binary) == 0:
        return -1
    try:
        completed = subprocess.run(
            [capinfos_binary, "-M", "-c", str(source_path)],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1
    if completed.returncode != 0:
        return -1
    stdout_text = (completed.stdout or b"").decode("utf-8", errors="replace")
    for raw_line in stdout_text.splitlines():
        cleaned_line = str(raw_line or "").strip()
        if len(cleaned_line) == 0:
            continue
        lowered = cleaned_line.lower()
        if "number of packets" not in lowered:
            continue
        if "=" in cleaned_line:
            _, _, rhs = cleaned_line.rpartition("=")
        else:
            _, _, rhs = cleaned_line.rpartition(":")
        digits = "".join(ch for ch in rhs if ch.isdigit())
        if len(digits) == 0:
            continue
        try:
            return int(digits)
        except ValueError:
            continue
    return -1


def _save_pcap_subset_via_editcap(
    *,
    source_path: Path,
    target_path: Path,
    packet_count: int,
    tshark_binary: str,
) -> None:
    editcap_binary = resolve_editcap_binary(tshark_binary)
    if len(editcap_binary) == 0:
        raise RuntimeError(
            "editcap binary is required to export the paused context snapshot. "
            "Install the Wireshark / tshark suite so editcap is available on PATH."
        )
    command = [
        editcap_binary,
        "-r",
        str(source_path),
        str(target_path),
        f"1-{int(packet_count)}",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"editcap binary not found at {editcap_binary!r}: {exc}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"editcap timed out while extracting packets 1-{int(packet_count)}: {exc}"
        ) from exc
    if completed.returncode != 0:
        error_text = (completed.stderr or b"").decode("utf-8", errors="replace").strip()
        lowered_error_text = error_text.lower()
        range_hint_keywords = (
            "record number",
            "out of range",
            "out of bounds",
            "exceeds",
            "greater than",
            "not enough",
            "too large",
        )
        if any(keyword in lowered_error_text for keyword in range_hint_keywords):
            detail = error_text if len(error_text) > 0 else "range mismatch"
            raise RuntimeError(
                f"editcap clip range 1-{int(packet_count)} is out of range for the source "
                f"capture (detail: {detail}). The on-disk pcap has fewer packets than the "
                "displayed context; re-open the capture or resume ingest before exporting."
            )
        if len(error_text) == 0:
            error_text = f"editcap exited with status {completed.returncode}"
        raise RuntimeError(
            f"editcap failed to extract packets 1-{int(packet_count)}: {error_text}"
        )


def save_live_capture_trace(
    capture_path: str,
    *,
    target_path: str | Path = "",
    packet_count: int | None = None,
    tshark_binary: str = "",
    filename_marker: str | None = None,
) -> Path:
    # packet_count > 0 truncates the exported file to the first N packets
    # using editcap. This is the "save only what's in the context"
    # behaviour exercised when the TUI is paused: _base_rows is frozen
    # while FIFO and pcap keep growing, so a raw copy would leak the
    # queued (not-yet-ingested) packets into the snapshot. packet_count
    # of None / 0 keeps the legacy full-file copy used in non-paused
    # exports.
    #
    # filename_marker, when non-empty, is inserted between the stem /
    # timestamp and the extension for the default target name. Callers
    # who pass an explicit target filename keep full control; this only
    # affects the auto-generated name. Passing None falls back to
    # _PAUSED_TRACE_FILENAME_MARKER whenever packet_count > 0 so paused
    # snapshots get a discoverable filename without extra plumbing.
    normalized_capture_path = str(capture_path or "").strip()
    if len(normalized_capture_path) == 0:
        raise ValueError("Live capture path is not configured.")
    source_path = Path(normalized_capture_path).expanduser().resolve()
    if source_path.is_file() is False:
        raise FileNotFoundError(f"Live capture file is missing: {source_path}")
    if source_path.stat().st_size <= 0:
        raise ValueError("Live capture file is empty.")
    effective_packet_count: int | None = None
    if packet_count is not None and int(packet_count) > 0:
        effective_packet_count = int(packet_count)
        probed_count = _count_pcap_packets(source_path, tshark_binary=tshark_binary)
        if probed_count == 0:
            raise RuntimeError(
                "Source capture contains no packets. Paused snapshot would produce an "
                "empty file; waiting for the first packet before exporting."
            )
        if probed_count > 0 and effective_packet_count > probed_count:
            effective_packet_count = probed_count
    resolved_marker = filename_marker
    if resolved_marker is None:
        if effective_packet_count is not None:
            resolved_marker = _PAUSED_TRACE_FILENAME_MARKER
        else:
            resolved_marker = ""
    if len(str(target_path or "").strip()) == 0:
        resolved_target_path = _default_saved_trace_path(
            str(source_path),
            marker_suffix=resolved_marker,
        )
    else:
        resolved_target_path = _resolve_trace_target_path(
            str(source_path),
            target_path,
            marker_suffix=resolved_marker,
        )
    final_target_path = _deduplicate_trace_target_path(resolved_target_path)
    final_target_path.parent.mkdir(parents=True, exist_ok=True)
    if effective_packet_count is not None:
        _save_pcap_subset_via_editcap(
            source_path=source_path,
            target_path=final_target_path,
            packet_count=effective_packet_count,
            tshark_binary=tshark_binary,
        )
    else:
        shutil.copy2(source_path, final_target_path)
    return final_target_path


def _handle_tree_arrow_key(tree_widget, key: str) -> bool:
    normalized_key = str(key or "").strip().lower()
    if normalized_key not in {"left", "right"}:
        return False
    current_node = getattr(tree_widget, "cursor_node", None)
    if current_node is None:
        return False
    child_nodes = tuple(getattr(current_node, "children", ()) or ())
    if normalized_key == "right":
        if len(child_nodes) == 0:
            return False
        expand = getattr(current_node, "expand", None)
        if callable(expand) is False:
            return False
        try:
            expand()
        except Exception:
            return False
        return True
    if len(child_nodes) > 0 and bool(getattr(current_node, "is_expanded", False)):
        collapse = getattr(current_node, "collapse", None)
        if callable(collapse) is False:
            return False
        try:
            collapse()
        except Exception:
            return False
        return True
    parent_node = getattr(current_node, "parent", None)
    root_node = getattr(tree_widget, "root", None)
    if parent_node is None or parent_node is root_node:
        return False
    collapse = getattr(parent_node, "collapse", None)
    if callable(collapse):
        try:
            collapse()
        except Exception:
            pass
    move_cursor = getattr(tree_widget, "move_cursor", None)
    if callable(move_cursor):
        try:
            move_cursor(parent_node, animate=False)
        except TypeError:
            try:
                move_cursor(parent_node)
            except Exception:
                pass
        except Exception:
            pass
    return True


def _tree_subtree_fully_expanded(node) -> bool:
    child_nodes = tuple(getattr(node, "children", ()) or ())
    if len(child_nodes) == 0:
        return True
    if bool(getattr(node, "is_expanded", False)) is False:
        return False
    for child_node in child_nodes:
        if _tree_subtree_fully_expanded(child_node) is False:
            return False
    return True


def _set_tree_subtree_expanded(node, expanded: bool) -> None:
    child_nodes = tuple(getattr(node, "children", ()) or ())
    if len(child_nodes) == 0:
        return
    if expanded:
        expand = getattr(node, "expand", None)
        if callable(expand):
            expand()
        for child_node in child_nodes:
            _set_tree_subtree_expanded(child_node, True)
        return
    for child_node in child_nodes:
        _set_tree_subtree_expanded(child_node, False)
    collapse = getattr(node, "collapse", None)
    if callable(collapse):
        collapse()


def _toggle_tree_subtree(node) -> bool:
    child_nodes = tuple(getattr(node, "children", ()) or ())
    if len(child_nodes) == 0:
        return False
    expand_subtree = _tree_subtree_fully_expanded(node) is False
    _set_tree_subtree_expanded(node, expand_subtree)
    return True


def _append_summary_timestamp_text(text, row: PacketSummary, *, palette: TuiThemePalette) -> None:
    display_time_text = _summary_display_time_text(row)
    if len(display_time_text) > 0:
        text.append(f"  {display_time_text}", style=palette.primary)


def _summary_tree_leaf_label(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
    *,
    group_name: str,
    palette: TuiThemePalette,
    show_expert_details: bool,
):
    from rich.text import Text
    primary_text, secondary_text = _summary_visible_text_parts(
        row,
        annotation,
        show_expert_details=show_expert_details,
    )
    text = Text()
    text.append(f"#{int(row.number):>4}", style=f"bold {palette.frame}")
    _append_summary_timestamp_text(text, row, palette=palette)
    text.append("  ")
    primary_style = palette.primary
    if show_expert_details is False:
        primary_style = _summary_group_color(group_name, palette)
    text.append(primary_text, style=primary_style)
    if secondary_text is not None:
        text.append("  · ", style=f"dim {palette.secondary}")
        text.append(secondary_text, style=_summary_context_style(group_name, palette))
    return text


def _summary_flat_leaf_label(
    row: PacketSummary,
    annotation: StatefulFrameAnnotation | None,
    *,
    palette: TuiThemePalette,
    show_expert_details: bool,
):
    from rich.text import Text
    text = Text()
    text.append(f"#{int(row.number):>4}", style=f"bold {palette.frame}")
    _append_summary_timestamp_text(text, row, palette=palette)
    length_text = str(row.length_text or "").strip()
    if len(length_text) > 0:
        text.append(f"  {length_text}B", style=f"dim {palette.secondary}")
    # Flat chronological view deliberately ignores annotation suffixes;
    # they belong in the context and poll views. Showing the raw info
    # text keeps "what did the card see" recoverable when an operator
    # disables stateful decoding or hits an annotation bug.
    primary_text = _summary_display_label_text(row.info)
    protocol_text = _normalized_summary_label_text(row.protocol)
    if len(primary_text) == 0:
        primary_text = protocol_text or "Packet"
    text.append("  ")
    primary_style = palette.primary
    if show_expert_details is False:
        primary_style = palette.protocol
    text.append(primary_text, style=primary_style)
    secondary_parts: list[str] = []
    route_text = _packet_route_text(row)
    if route_text is not None:
        secondary_parts.append(route_text)
    if len(protocol_text) > 0 and protocol_text.upper() not in {"GSM SIM", "GSMTAP"}:
        secondary_parts.append(protocol_text)
    if len(secondary_parts) > 0:
        text.append("  · ", style=f"dim {palette.secondary}")
        text.append(" · ".join(secondary_parts), style=f"dim {palette.secondary}")
    return text


def _populate_summary_tree(
    tree_widget,
    rows: list[PacketSummary],
    annotations: dict[int, StatefulFrameAnnotation],
    *,
    view_mode: str,
    selected_frame_number: int | None,
    expanded_group_names: set[str],
    palette: TuiThemePalette,
    show_expert_details: bool,
) -> dict[int, object]:
    from rich.text import Text
    normalized_view_mode = _normalize_summary_view_mode(view_mode)
    tree_widget.show_root = False
    root = tree_widget.root
    root.remove_children()
    root.expand()
    frame_nodes: dict[int, object] = {}
    if len(rows) == 0:
        waiting_label = "Waiting for packet summaries before building the context tree."
        if normalized_view_mode == _SUMMARY_VIEW_FLAT:
            waiting_label = "Waiting for packet summaries before building the flat packet list."
        elif normalized_view_mode == _SUMMARY_VIEW_POLL:
            waiting_label = "Waiting for packet summaries before building the poll cycle view."
        root.add(
            Text(waiting_label, style=f"dim {palette.waiting}"),
            allow_expand=False,
        )
        return frame_nodes

    if normalized_view_mode == _SUMMARY_VIEW_FLAT:
        for row in rows:
            annotation = annotations.get(int(row.number))
            frame_node = root.add(
                _summary_flat_leaf_label(
                    row,
                    annotation,
                    palette=palette,
                    show_expert_details=show_expert_details,
                ),
                data={
                    "kind": "frame",
                    "frame_number": int(row.number),
                },
                allow_expand=False,
            )
            frame_nodes[int(row.number)] = frame_node
        return frame_nodes

    if normalized_view_mode == _SUMMARY_VIEW_POLL:
        poll_assignments = _assign_poll_group_indices(rows, annotations)
        rows_by_poll: dict[int, list[PacketSummary]] = {}
        poll_order: list[int] = []
        for row in rows:
            poll_index = int(poll_assignments.get(int(row.number), 1))
            if poll_index not in rows_by_poll:
                rows_by_poll[poll_index] = []
                poll_order.append(poll_index)
            rows_by_poll[poll_index].append(row)
        for poll_index in poll_order:
            poll_rows = rows_by_poll[poll_index]
            highlight_tokens = _summary_poll_cycle_highlight_tokens(poll_rows, annotations)
            poll_title = _summary_poll_cycle_title(poll_index, highlight_tokens)
            poll_key = _summary_poll_cycle_key(poll_index)
            poll_should_expand = (
                poll_key in expanded_group_names
                or poll_index == poll_order[-1]
            )
            poll_node = root.add(
                Text.assemble(
                    (poll_title, f"bold {palette.frame}"),
                    (f" ({len(poll_rows)} frames)", f"dim {palette.secondary}"),
                ),
                data={
                    "kind": "poll_cycle",
                    "poll_index": int(poll_index),
                    "expand_key": poll_key,
                },
                expand=bool(poll_should_expand),
            )
            for row in poll_rows:
                annotation = annotations.get(int(row.number))
                frame_node = poll_node.add(
                    _summary_flat_leaf_label(
                        row,
                        annotation,
                        palette=palette,
                        show_expert_details=show_expert_details,
                    ),
                    data={
                        "kind": "frame",
                        "frame_number": int(row.number),
                        "poll_index": int(poll_index),
                        "expand_key": poll_key,
                    },
                    allow_expand=False,
                )
                frame_nodes[int(row.number)] = frame_node
        return frame_nodes

    def _render_context_section(
        parent_node,
        section_rows: list[PacketSummary],
        key_prefix: str,
    ) -> None:
        grouped_rows_local: dict[str, list[PacketSummary]] = {}
        for section_row in section_rows:
            section_annotation = annotations.get(int(section_row.number))
            group_name_local = _summary_group_name(section_row, section_annotation)
            group_bucket_local = grouped_rows_local.setdefault(group_name_local, [])
            group_bucket_local.append(section_row)

        # Render every channel Poll at the section's top level. The
        # legacy "Channels" wrapper is dropped entirely so the tree
        # reads: Poll 1 - FQDN -> DNS - IP - APN / eIM - IP - APN,
        # with STK, ETSI FS, Timer, etc. appearing as siblings below
        # the polls. When a key_prefix is supplied (multiple card
        # sessions), every expand_key is scoped so collapsing Poll 1
        # in Card Session 1 doesn't collapse Poll 1 in Card Session 2.
        channel_group_rows = grouped_rows_local.get("Channels", [])
        poll_buckets: list[
            tuple[int, list[tuple[int, str, list[PacketSummary]]]]
        ] = []
        unbound_channel_rows: list[PacketSummary] = []
        if len(channel_group_rows) > 0:
            session_buckets, unbound_channel_rows = _summary_partition_channel_rows(
                channel_group_rows,
                annotations,
            )
            poll_buckets = _summary_partition_poll_rows_with_labels(
                session_buckets,
                annotations,
            )
        for poll_index, poll_sessions in poll_buckets:
            poll_frame_count = 0
            for _session_id, _session_title, session_rows in poll_sessions:
                poll_frame_count += len(session_rows)
            poll_key = f"{key_prefix}{_summary_poll_top_level_key(poll_index)}"
            poll_fqdn = _resolve_poll_fqdn(poll_sessions, annotations)
            poll_title = _summary_poll_top_level_title(poll_index, poll_fqdn)
            poll_node = parent_node.add(
                Text.assemble(
                    (poll_title, f"bold {palette.bip}"),
                    (f" ({poll_frame_count} frames)", f"dim {palette.secondary}"),
                ),
                data={
                    "kind": "poll",
                    "group_name": "Channels",
                    "expand_key": poll_key,
                    "poll_index": int(poll_index),
                },
                expand=(poll_key in expanded_group_names),
            )
            for session_id, session_title, session_rows in poll_sessions:
                session_key = (
                    f"{key_prefix}{_summary_channel_session_key(session_id)}"
                )
                session_node = poll_node.add(
                    Text.assemble(
                        (session_title, f"bold {palette.bip}"),
                        (f" ({len(session_rows)} frames)", f"dim {palette.secondary}"),
                    ),
                    data={
                        "kind": "session",
                        "group_name": "Channels",
                        "expand_key": session_key,
                        "session_id": int(session_id),
                        "poll_index": int(poll_index),
                    },
                    expand=(session_key in expanded_group_names),
                )
                for session_row in session_rows:
                    session_annotation = annotations.get(int(session_row.number))
                    frame_node = session_node.add(
                        _summary_tree_leaf_label(
                            session_row,
                            session_annotation,
                            group_name="Channels",
                            palette=palette,
                            show_expert_details=show_expert_details,
                        ),
                        data={
                            "kind": "frame",
                            "frame_number": int(session_row.number),
                            "group_name": "Channels",
                            "expand_key": session_key,
                            "session_id": int(session_id),
                            "poll_index": int(poll_index),
                        },
                        allow_expand=False,
                    )
                    frame_nodes[int(session_row.number)] = frame_node

        ordered_groups = [
            group for group in _SUMMARY_GROUP_ORDER if group in grouped_rows_local
        ]
        ordered_groups.extend(
            group for group in grouped_rows_local if group not in ordered_groups
        )
        for group_name in ordered_groups:
            if group_name == "Channels":
                continue
            group_rows = grouped_rows_local.get(group_name, [])
            total_count = len(group_rows)
            group_expand_key = f"{key_prefix}{group_name}"
            group_node = parent_node.add(
                Text.assemble(
                    (group_name, _summary_group_style(group_name, palette)),
                    (f" ({total_count})", f"dim {palette.secondary}"),
                ),
                data={
                    "kind": "group",
                    "group_name": group_name,
                    "expand_key": group_expand_key,
                },
                expand=(group_expand_key in expanded_group_names),
            )
            for row in group_rows:
                annotation = annotations.get(int(row.number))
                frame_node = group_node.add(
                    _summary_tree_leaf_label(
                        row,
                        annotation,
                        group_name=group_name,
                        palette=palette,
                        show_expert_details=show_expert_details,
                    ),
                    data={
                        "kind": "frame",
                        "frame_number": int(row.number),
                        "group_name": group_name,
                        "expand_key": group_expand_key,
                    },
                    allow_expand=False,
                )
                frame_nodes[int(row.number)] = frame_node

        # Truly unassignable channel frames (no enclosing OPEN/CLOSE
        # range after the finalize_annotations frame-range fallback)
        # are rendered at the tail of the section so they remain
        # visible without resurrecting the "Channels" wrapper node.
        for row in unbound_channel_rows:
            if int(row.number) in frame_nodes:
                continue
            annotation = annotations.get(int(row.number))
            frame_node = parent_node.add(
                _summary_tree_leaf_label(
                    row,
                    annotation,
                    group_name="Channels",
                    palette=palette,
                    show_expert_details=show_expert_details,
                ),
                data={
                    "kind": "frame",
                    "frame_number": int(row.number),
                    "group_name": "Channels",
                },
                allow_expand=False,
            )
            frame_nodes[int(row.number)] = frame_node

    # Partition rows by card session index so a card reset (REFRESH
    # with reset qualifier, long idle gap) lifts every pre-reboot
    # Poll / STK / FS group into its own top-level "Card Session N"
    # wrapper and keeps the post-reboot traffic under a sibling
    # wrapper. When only one session is present we skip the wrapper
    # so the tree stays identical to the pre-reset layout.
    (
        card_session_rows,
        card_session_reasons,
        card_session_iccids,
    ) = _summary_partition_rows_by_card_session(rows, annotations)
    if len(card_session_rows) <= 1:
        if len(card_session_rows) == 0:
            _render_context_section(root, rows, "")
        else:
            _render_context_section(root, card_session_rows[0][1], "")
        return frame_nodes

    for card_session_index, session_rows_subset in card_session_rows:
        session_key = _summary_card_session_key(card_session_index)
        session_reason = card_session_reasons.get(int(card_session_index), "")
        session_iccid = card_session_iccids.get(int(card_session_index), "")
        session_title = _summary_card_session_title(
            card_session_index, session_reason, session_iccid
        )
        wrapper_node = root.add(
            Text.assemble(
                (session_title, f"bold {palette.timer}"),
                (f" ({len(session_rows_subset)} frames)", f"dim {palette.secondary}"),
            ),
            data={
                "kind": "card_session",
                "expand_key": session_key,
                "card_session_index": int(card_session_index),
            },
            expand=(session_key in expanded_group_names)
            or int(card_session_index) == int(card_session_rows[-1][0]),
        )
        _render_context_section(
            wrapper_node,
            session_rows_subset,
            f"{session_key}/",
        )
    return frame_nodes


def run_live_decode_tui(
    capture_path: str,
    *,
    service_name: str,
    capture_filter: str,
    startup_state: dict[str, object] | None = None,
    tshark_binary: str = "",
    decode_rule: str = DEFAULT_DECODE_RULE,
    mirror_fifo_path: str = "",
    live_capture: bool = True,
    keybag_path: str = "",
) -> None:
    # When `live_capture` is False the TUI opens the pcap in offline
    # review mode: no FIFO is created, no `tshark -i` subprocess is
    # spawned, and Ctrl+F12 "Restore live capture" becomes a no-op.
    # `keybag_path` optionally points at a sibling JSON file carrying
    # SCP03/SCP11c session-key material used by the annotator to render
    # plaintext alongside ciphered APDUs (see scp_replay module).
    previous_term = os.environ.get("TERM")
    previous_colorterm = os.environ.get("COLORTERM")
    os.environ["TERM"] = _preferred_textual_term_value()
    try:
        from textual import events
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.screen import ModalScreen
        from rich.markup import escape
        from rich.text import Text
        from textual.widgets import Button, Input, OptionList, RichLog, Static, Tree
        from textual.widgets.option_list import Option
    except Exception as exc:
        raise RuntimeError(f"Textual is not available for the HIL decode TUI: {exc}") from exc

    def _detail_indent_width(raw_line: str) -> int:
        return _detail_tree_indent_width(raw_line)

    def _render_detail_tree_label(raw_line: str, palette: TuiThemePalette) -> Text:
        normalized = str(raw_line or "").replace("\t", "    ").rstrip()
        stripped = normalized.strip()
        if len(stripped) == 0:
            return Text("")
        if stripped.startswith("Decoded view load error:"):
            return Text(stripped, style=f"bold {palette.error}")
        if stripped.startswith("Loading ") or stripped.startswith("Waiting "):
            return Text(stripped, style=f"dim {palette.waiting}")
        if normalized[:1] != " ":
            return Text(stripped, style=f"bold {palette.primary}")
        visible = normalized.lstrip(" ")
        if ":" in visible:
            key_text, remainder = visible.split(":", 1)
            key_style = f"bold {palette.bip}"
            emphasized_keys = {
                "Frame",
                "Instruction",
                "Status Word",
                "Source",
                "Destination",
                "Protocol",
                "Arrival Time",
                "Epoch Arrival Time",
                "UTC Arrival Time",
                "Encapsulation type",
                "Source Address",
                "Destination Address",
                "Source Port",
                "Destination Port",
            }
            if key_text in emphasized_keys:
                key_style = f"bold {palette.frame}"
            text = Text()
            text.append(f"{key_text}:", style=key_style)
            if len(remainder) > 0:
                text.append(remainder, style=palette.primary)
            return text
        if visible.startswith("[") and visible.endswith("]"):
            return Text(visible, style=f"bold {palette.other}")
        return Text(visible, style=palette.primary)

    def _append_detail_tree_lines(
        parent_node,
        detail_lines: list[str],
        *,
        palette: TuiThemePalette,
    ) -> list[object]:
        stack: list[tuple[int, object]] = [(-1, parent_node)]
        top_level_nodes: list[object] = []
        for raw_line in detail_lines:
            indent_width = _detail_indent_width(raw_line)
            while len(stack) > 1 and indent_width <= stack[-1][0]:
                stack.pop()
            current_parent = stack[-1][1]
            node = current_parent.add(_render_detail_tree_label(raw_line, palette))
            if current_parent is parent_node:
                top_level_nodes.append(node)
            stack.append((indent_width, node))
        return top_level_nodes

    def _populate_detail_tree(
        tree_widget: Tree,
        raw_text: str,
        *,
        context_lines: tuple[str, ...] = (),
        palette: TuiThemePalette,
        show_expert_details: bool = True,
    ) -> None:
        tree_widget.show_root = False
        root = tree_widget.root
        root.remove_children()
        root.expand()

        focus_node = None

        normalized_context_lines = [
            str(raw_line or "").rstrip("\n")
            for raw_line in context_lines
            if len(str(raw_line or "").strip()) > 0
        ]
        if len(normalized_context_lines) > 0:
            context_root = root.add(Text("State Context", style=f"bold {palette.context}"))
            _ = _append_detail_tree_lines(
                context_root,
                normalized_context_lines,
                palette=palette,
            )
            context_root.expand()
            focus_node = context_root

        detail_lines = [
            str(raw_line or "").rstrip("\n")
            for raw_line in str(raw_text or "").splitlines()
            if len(str(raw_line or "").strip()) > 0
        ]
        detail_lines = _filter_detail_tree_lines(
            detail_lines,
            show_expert_details=show_expert_details,
        )
        if len(detail_lines) == 0 and show_expert_details is False:
            detail_lines = ["Expert details are hidden for the decoded tree."]
        if len(detail_lines) == 0:
            detail_lines = ["Waiting for packet selection before loading decoded fields."]
        top_level_nodes = _append_detail_tree_lines(root, detail_lines, palette=palette)
        for node in top_level_nodes:
            if len(node.children) > 0:
                node.collapse()
        if focus_node is None and len(top_level_nodes) > 0:
            focus_node = top_level_nodes[0]
        if focus_node is not None:
            tree_widget.move_cursor(focus_node, animate=False)

    def _render_hex_rich_text(raw_line: str, palette: TuiThemePalette) -> Text:
        normalized = str(raw_line or "").rstrip()
        stripped = normalized.strip()
        if len(stripped) == 0:
            return Text("")
        if stripped.startswith("Byte view load error:"):
            return Text(stripped, style=f"bold {palette.error}")
        if stripped.startswith("Loading ") or stripped.startswith("Waiting "):
            return Text(stripped, style=f"dim {palette.waiting}")
        parts = stripped.split(None, 1)
        if len(parts) == 2 and len(parts[0]) in {4, 8} and all(
            character in "0123456789abcdefABCDEF" for character in parts[0]
        ):
            offset_text = parts[0]
            remainder = parts[1]
            hex_text = remainder
            ascii_text = ""
            if "   " in remainder:
                candidate_hex, candidate_ascii = remainder.rsplit("   ", 1)
                if len(str(candidate_ascii).strip()) > 0:
                    hex_text = candidate_hex.rstrip()
                    ascii_text = candidate_ascii
            text = Text()
            text.append(offset_text, style=f"bold {palette.frame}")
            if len(hex_text) > 0:
                text.append(" ")
                text.append(hex_text, style=palette.bip)
            if len(ascii_text) > 0:
                text.append("   ")
                text.append(ascii_text, style=f"dim {palette.secondary}")
            return text
        return Text(stripped, style=palette.primary)

    def _replace_log_contents(log_widget: RichLog, raw_text: str, renderer) -> None:
        log_widget.clear()
        for raw_line in str(raw_text or "").splitlines():
            log_widget.write(renderer(raw_line))
        scroll_home = getattr(log_widget, "scroll_home", None)
        if callable(scroll_home):
            try:
                scroll_home(animate=False)
            except TypeError:
                try:
                    scroll_home()
                except Exception:
                    pass
            except Exception:
                pass


    def _format_duration_clock(total_seconds: int | float) -> str:
        normalized_seconds = max(0, int(total_seconds or 0))
        hours = normalized_seconds // 3600
        minutes = (normalized_seconds % 3600) // 60
        seconds = normalized_seconds % 60
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"

    def _format_live_timer_snapshot(
        snapshot: ActiveTimerSnapshot,
        extra_elapsed_seconds: float = 0.0,
    ) -> str:
        remaining_seconds = _live_timer_remaining_seconds(snapshot, extra_elapsed_seconds)
        timer_label = str(getattr(snapshot, "display_label", "") or "").strip()
        if len(timer_label) == 0:
            timer_label = f"T{int(snapshot.timer_id)}"
        return f"{timer_label} {_format_duration_clock(remaining_seconds)}"

    def _live_timer_remaining_seconds(
        snapshot: ActiveTimerSnapshot,
        extra_elapsed_seconds: float = 0.0,
    ) -> int:
        return max(
            0,
            int(math.ceil(float(snapshot.remaining_seconds) - max(0.0, float(extra_elapsed_seconds or 0.0)))),
        )

    def _render_timer_summary(
        snapshots: tuple[ActiveTimerSnapshot, ...],
        extra_elapsed_seconds: float = 0.0,
        *,
        prefix: str,
    ) -> str:
        if len(snapshots) == 0:
            return ""
        visible = [
            _format_live_timer_snapshot(snapshot, extra_elapsed_seconds)
            for snapshot in snapshots[:3]
            if _live_timer_remaining_seconds(snapshot, extra_elapsed_seconds) > 0
        ]
        hidden_count = sum(
            1
            for snapshot in snapshots
            if _live_timer_remaining_seconds(snapshot, extra_elapsed_seconds) > 0
        ) - len(visible)
        if hidden_count > 0:
            visible.append(f"+{hidden_count} more")
        if len(visible) == 0:
            return ""
        return f"{prefix}{', '.join(visible)}"

    class PaneLayoutPicker(ModalScreen[str | None]):
        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
        ]

        def __init__(self, visibility: PaneVisibility) -> None:
            super().__init__()
            self._visibility = visibility

        def compose(self) -> ComposeResult:
            options = []
            for pane_name in _PANE_NAMES:
                label = _pane_display_name(pane_name)
                current_state = "Shown" if bool(getattr(self._visibility, pane_name)) else "Hidden"
                target_state = "Hide" if current_state == "Shown" else "Show"
                options.append(
                    Option(
                        f"{label} -> {target_state}  [dim](current: {current_state})[/dim]",
                        id=f"pane:{pane_name}:toggle",
                    )
                )
            options.append(Option("Reset default layout", id="reset"))
            with Vertical(id="pane_picker_shell"):
                yield Static("Pane layout")
                yield Static(
                    "[dim]Resize with mouse drag handles. Enter confirm · Esc close[/dim]"
                )
                yield OptionList(*options, id="pane_opts")

        def on_mount(self) -> None:
            self.query_one("#pane_opts", OptionList).focus()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            option_id = event.option_id
            if option_id is None:
                self.dismiss(None)
                return
            self.dismiss(str(option_id))

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class TraceSavePicker(ModalScreen[str | None]):
        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
            Binding("enter", "submit_form", "Save", show=False, priority=True),
        ]

        def __init__(self, capture_path: str, last_export_directory: str = "") -> None:
            super().__init__()
            self._capture_path = str(capture_path or "")
            self._last_export_directory = str(last_export_directory or "")
            self._suggested_path_text = _display_path_text(
                _default_saved_trace_path(
                    self._capture_path,
                    self._last_export_directory,
                )
            )

        def compose(self) -> ComposeResult:
            source_text = _display_path_text(Path(self._capture_path)) if len(self._capture_path.strip()) > 0 else "(unknown)"
            with Vertical(id="trace_save_shell"):
                yield Static("Save trace snapshot")
                yield Static(f"[dim]Source capture: {escape(source_text)}[/dim]")
                yield Static(
                    "[dim]Edit the export file path or point at a directory. Enter saves · Esc closes.[/dim]"
                )
                yield Input(value=self._suggested_path_text, id="trace_save_path")
                yield Static("", id="trace_save_error")
                with Horizontal(id="trace_save_buttons"):
                    yield Button("Cancel", id="trace_save_cancel")
                    yield Button("Save trace", id="trace_save_apply", variant="primary")

        def on_mount(self) -> None:
            self.query_one("#trace_save_path", Input).focus()

        def _set_error(self, text: str) -> None:
            self.query_one("#trace_save_error", Static).update(
                f"[bold red]{escape(str(text or '').strip())}[/bold red]"
            )

        def _collect_result(self) -> str:
            widget = self.query_one("#trace_save_path", Input)
            value = str(widget.value or "").strip()
            if len(value) == 0:
                raise ValueError("Export path must not be empty.")
            widget.value = value
            return value

        def _submit_form(self) -> None:
            try:
                result = self._collect_result()
            except ValueError as exc:
                self._set_error(str(exc))
                return
            self.dismiss(result)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = str(event.button.id or "").strip()
            if button_id == "trace_save_cancel":
                self.dismiss(None)
                return
            if button_id == "trace_save_apply":
                self._submit_form()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            del event
            self._submit_form()

        def action_submit_form(self) -> None:
            self._submit_form()

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class CaptureOpenPicker(ModalScreen[str | None]):
        BINDINGS = [
            Binding("escape", "cancel_pick", "Close", priority=True),
            Binding("enter", "submit_form", "Open", show=False, priority=True),
        ]

        def __init__(self, capture_path: str) -> None:
            super().__init__()
            self._capture_path = str(capture_path or "")

        def compose(self) -> ComposeResult:
            current_capture_text = "(unknown)"
            if len(self._capture_path.strip()) > 0:
                current_capture_text = _display_path_text(Path(self._capture_path))
            with Vertical(id="capture_open_shell"):
                yield Static("Open capture file")
                yield Static(f"[dim]Current capture: {escape(current_capture_text)}[/dim]")
                yield Static(
                    "[dim]Enter a capture file path if no desktop picker is available. Enter opens · Esc closes.[/dim]"
                )
                yield Input(value=str(self._capture_path or ""), id="capture_open_path")
                yield Static("", id="capture_open_error")
                with Horizontal(id="capture_open_buttons"):
                    yield Button("Cancel", id="capture_open_cancel")
                    yield Button("Open capture", id="capture_open_apply", variant="primary")

        def on_mount(self) -> None:
            self.query_one("#capture_open_path", Input).focus()

        def _set_error(self, text: str) -> None:
            self.query_one("#capture_open_error", Static).update(
                f"[bold red]{escape(str(text or '').strip())}[/bold red]"
            )

        def _collect_result(self) -> str:
            widget = self.query_one("#capture_open_path", Input)
            value = str(widget.value or "").strip()
            if len(value) == 0:
                raise ValueError("Capture file path must not be empty.")
            widget.value = value
            return value

        def _submit_form(self) -> None:
            try:
                result = self._collect_result()
            except ValueError as exc:
                self._set_error(str(exc))
                return
            self.dismiss(result)

        def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = str(event.button.id or "").strip()
            if button_id == "capture_open_cancel":
                self.dismiss(None)
                return
            if button_id == "capture_open_apply":
                self._submit_form()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            del event
            self._submit_form()

        def action_submit_form(self) -> None:
            self._submit_form()

        def action_cancel_pick(self) -> None:
            self.dismiss(None)

    class KeybindHelpScreen(ModalScreen[None]):
        BINDINGS = [
            Binding("escape", "close_help", "Close", priority=True),
            Binding("f1", "close_help", "Close", show=False, priority=True),
        ]

        def compose(self) -> ComposeResult:
            with Vertical(id="keybind_help_shell"):
                yield Static("HIL Decode TUI Keybinds")
                yield Static(
                    "[dim]F1 or Esc closes this help.[/dim]"
                )
                yield Static(
                    escape(_hil_decode_keybind_help_text()),
                    id="keybind_help_body",
                )

        def action_close_help(self) -> None:
            self.dismiss(None)

    class DragHandle(Static):
        def on_mouse_down(self, event: events.MouseDown) -> None:
            handle_id = self.id or ""
            app = self.app
            if hasattr(app, "_begin_split_drag") is False:
                return
            self.capture_mouse()
            app._begin_split_drag(
                handle_id,
                int(event.screen_x or 0),
                int(event.screen_y or 0),
            )
            event.stop()

        def on_mouse_move(self, event: events.MouseMove) -> None:
            app = self.app
            if hasattr(app, "_continue_split_drag") is False:
                return
            if getattr(app, "_drag_state", None) is None:
                return
            app._continue_split_drag(
                int(event.screen_x or 0),
                int(event.screen_y or 0),
            )
            event.stop()

        def on_mouse_up(self, event: events.MouseUp) -> None:
            app = self.app
            if hasattr(app, "_end_split_drag"):
                app._end_split_drag()
            self.release_mouse()
            event.stop()

    class HilDecodeApp(App):
        TITLE = "HIL Terminal Decode"
        SUB_TITLE = "Mode 3 live APDU TUI"

        BINDINGS = [
            Binding("ctrl+q", "quit_view", "Quit", priority=True),
            Binding("q", "quit_view", "Quit", show=False, priority=True),
            Binding("tab", "cycle_focus", "Next pane", show=False, priority=True),
            Binding("f1", "show_keybinds", "Keybinds", priority=True),
            Binding("f2", "toggle_ingest_pause", "Pause ingest", priority=True),
            Binding(
                "ctrl+f2",
                "toggle_ingest_pause_discard",
                "Pause / discard queue",
                show=False,
                priority=True,
            ),
            Binding("f3", "cycle_theme", "Theme", priority=True),
            Binding("f4", "cycle_summary_view", "View", priority=True),
            Binding("f5", "toggle_summary_pane", "Summary", priority=True),
            Binding("f6", "toggle_follow_tail", "Follow tail", priority=True),
            Binding("f7", "jump_next_state_event", "State hop", priority=True),
            Binding("f8", "toggle_detail_pane", "Decoded", priority=True),
            Binding("ctrl+f8", "toggle_expert_detail_lines", "Expert details", show=False, priority=True),
            Binding("f9", "toggle_bytes_pane", "Bytes", priority=True),
            Binding("f10", "open_pane_layout_menu", "Pane menu", priority=True),
            Binding("f11", "save_trace_snapshot", "Export trace", priority=True),
            Binding(
                "shift+f11",
                "save_trace_snapshot_clipped",
                "Export clipped",
                show=False,
                priority=True,
            ),
            Binding("ctrl+f11", "clear_capture_view", "Clear view", show=False, priority=True),
            Binding("f12", "open_capture_file", "Open capture", priority=True),
            Binding("ctrl+f12", "restore_live_capture", "Live capture", show=False, priority=True),
            Binding("ctrl+space", "toggle_detail_subtree", "Detail subtree", show=False, priority=True),
            Binding("[", "jump_prev_state_event", "Prev state", show=False, priority=True),
            Binding("]", "jump_next_state_event", "Next state", show=False, priority=True),
            Binding("end", "jump_tail", "Tail", show=False, priority=True),
        ]

        CSS = """
        Screen {
            layout: vertical;
            height: 100%;
            width: 100%;
            background: $surface;
        }
        #chrome {
            width: 100%;
            height: 1fr;
            min-height: 0;
            background: $surface;
            padding: 0;
        }
        #chrome_title {
            height: 1;
            padding: 0 1;
            background: $panel;
            color: $text;
            border-bottom: solid $primary;
        }
        #chrome_title.paused-banner {
            background: $warning;
            color: $text;
            border-bottom: solid $warning;
        }
        #body {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        #upper {
            width: 100%;
            height: 14;
            min-height: 0;
        }
        #summary_col {
            width: 100%;
            height: 100%;
            min-height: 0;
        }
        #bottom_row {
            width: 100%;
            height: 1fr;
            min-height: 0;
        }
        #detail_col {
            width: 1fr;
            min-width: 30;
            height: 100%;
            min-height: 0;
        }
        #bytes_col {
            width: 1fr;
            min-width: 30;
            height: 100%;
            min-height: 0;
        }
        .pane-caption {
            height: 1;
            padding: 0 1;
            background: $panel;
            color: $text;
            text-style: bold;
        }
        .drag-handle {
            background: $panel;
        }
        #detail_handle {
            width: 2;
            min-width: 2;
            height: 100%;
        }
        #bottom_handle {
            height: 1;
            min-height: 1;
            width: 100%;
        }
        .pane-body {
            width: 100%;
            height: 1fr;
            min-height: 0;
            border: solid $primary;
            color: $text;
            background: $surface;
        }
        #status_line {
            height: 1;
            padding: 0 1;
            border-top: solid $primary;
            background: $panel;
            color: $text;
        }
        #status_line.error-state {
            border-top: solid $error;
            color: $error;
            text-style: bold;
        }
        PaneLayoutPicker, TraceSavePicker, CaptureOpenPicker, KeybindHelpScreen {
            align: center middle;
        }
        #pane_picker_shell {
            width: 72;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            border: thick $primary;
            background: $surface;
        }
        #pane_opts {
            width: 100%;
            height: 1fr;
            min-height: 6;
            margin-top: 1;
            border: solid $primary;
            background: $surface;
        }
        #trace_save_shell {
            width: 88;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            border: thick $primary;
            background: $surface;
        }
        #trace_save_path {
            width: 100%;
            margin-top: 1;
        }
        #trace_save_error {
            min-height: 1;
            margin-top: 1;
        }
        #trace_save_buttons {
            width: 100%;
            height: auto;
            margin-top: 1;
            align-horizontal: right;
        }
        #capture_open_shell {
            width: 88;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            border: thick $primary;
            background: $surface;
        }
        #keybind_help_shell {
            width: 76;
            height: auto;
            max-height: 90%;
            padding: 1 2;
            border: thick $primary;
            background: $surface;
        }
        #keybind_help_body {
            margin-top: 1;
            border: solid $primary;
            padding: 1 2;
            width: 100%;
            height: auto;
            color: $text;
            background: $surface;
        }
        #capture_open_path {
            width: 100%;
            margin-top: 1;
        }
        #capture_open_error {
            min-height: 1;
            margin-top: 1;
        }
        #capture_open_buttons {
            width: 100%;
            height: auto;
            margin-top: 1;
            align-horizontal: right;
        }
        Input {
            border: solid $primary;
            background: $surface;
            color: $text;
        }
        Input:focus {
            border: tall $accent;
        }
        Input > .input--cursor {
            color: $surface;
            background: $primary;
        }
        Input > .input--selection {
            color: $text;
            background: $accent;
        }
        Input > .input--placeholder,
        Input > .input--suggestion {
            color: #4C566A;
        }
        Button {
            min-width: 14;
            margin-left: 1;
            border: solid $panel;
            background: $panel;
            color: $text;
        }
        Button:hover,
        Button:focus {
            border: solid $accent;
            background: $primary;
            color: $surface;
        }
        Button.-primary {
            border: solid $primary;
            background: $primary;
            color: $surface;
            text-style: bold;
        }
        Button.-primary:hover,
        Button.-primary:focus {
            border: solid $accent;
            background: $accent;
            color: $surface;
        }
        #summary_tree {
            color: $text;
            background: $surface;
        }
        #summary_tree > .tree--guides,
        #summary_tree > .tree--guides-hover {
            color: #4C566A;
        }
        #summary_tree > .tree--guides-selected {
            color: $accent;
        }
        #summary_tree > .tree--cursor {
            color: $surface;
            background: $primary;
            text-style: bold;
        }
        #summary_tree > .tree--highlight-line {
            background: $panel;
        }
        #summary_tree:focus > .tree--guides,
        #summary_tree:focus > .tree--guides-hover,
        #summary_tree:focus > .tree--guides-selected {
            color: $primary;
        }
        #detail_view, #bytes_view {
            color: $text;
            background: $surface;
        }
        #detail_view > .tree--guides,
        #detail_view > .tree--guides-hover {
            color: #4C566A;
        }
        #detail_view > .tree--guides-selected {
            color: $accent;
        }
        #detail_view > .tree--cursor {
            color: $surface;
            background: $primary;
            text-style: bold;
        }
        #detail_view > .tree--highlight-line {
            background: $panel;
        }
        #detail_view:focus > .tree--guides,
        #detail_view:focus > .tree--guides-hover,
        #detail_view:focus > .tree--guides-selected {
            color: $primary;
        }
        """

        def __init__(self) -> None:
            super().__init__()
            layout_preferences = load_tui_layout_preferences(capture_path)
            self._capture_path = str(capture_path or "")
            self._live_capture_path = str(capture_path or "")
            self._service_name = str(service_name or "").strip()
            self._capture_filter = str(capture_filter or "").strip()
            self._startup_state = startup_state
            self._tshark_binary = str(tshark_binary or "")
            self._decode_rule = str(decode_rule or DEFAULT_DECODE_RULE)
            self._visibility = layout_preferences.visibility
            self._base_rows: list[PacketSummary] = []
            self._rows: list[PacketSummary] = []
            self._state_annotations: dict[int, StatefulFrameAnnotation] = {}
            self._interesting_frame_numbers: list[int] = []
            self._summary_tree_frame_nodes: dict[int, object] = {}
            self._summary_tree_header_nodes: dict[str, object] = {}
            self._summary_tree_expanded_groups: set[str] = set()
            self._summary_tree_sync_inflight = False
            self._highlighted_node_key: str | None = None
            self._summary_view_mode = _normalize_summary_view_mode(layout_preferences.summary_view_mode)
            self._theme_name = _normalize_theme_name(layout_preferences.theme_name)
            self._selected_frame_number: int | None = None
            self._displayed_selected_frame_number: int | None = None
            self._last_parse_completed_monotonic: float | None = None
            self._last_parse_row_count: int = 0
            self._detail_cache: dict[int, str] = {}
            self._bytes_cache: dict[int, str] = {}
            self._follow_tail = True
            self._show_expert_detail_lines = True
            self._last_capture_size = -1
            self._last_error = ""
            self._latest_capture_time_seconds: float | None = None
            self._latest_capture_monotonic: float | None = None
            self._summary_height = int(layout_preferences.summary_height)
            self._detail_width = int(layout_preferences.detail_width)
            self._last_trace_export_directory = str(layout_preferences.last_export_directory or "").strip()
            self._last_capture_open_directory = str(layout_preferences.last_capture_open_directory or "").strip()
            self._drag_state: dict[str, int] | None = None
            self._refresh_inflight = False
            self._detail_inflight = False
            self._capture_generation = 0
            self._requested_detail_frame: int | None = None
            self._displayed_detail_key: tuple[int | None, str, str, tuple[str, ...]] | None = None
            self._displayed_bytes_key: tuple[int | None, str, str] | None = None
            self._shutdown_event = threading.Event()
            self._mirror_fifo_path = str(mirror_fifo_path or "").strip()
            self._live_capture_mode = bool(live_capture)
            self._keybag_path = str(keybag_path or "").strip()
            # Auto-discover a sibling `<pcap>.keys.json` when the operator
            # did not pass one explicitly. This makes the common case
            # ("keybag lives next to the pcap") zero-config.
            if len(self._keybag_path) == 0 and bool(live_capture) is False:
                self._keybag_path = str(
                    try_autodiscover_sidecar_keybag(self._capture_path) or ""
                ).strip()
            self._keybag_summary: KeybagLoadSummary = KeybagLoadSummary(
                session_count=0,
                source_path=self._keybag_path,
            )
            self._replay_engine: ScpReplayEngine | None = None
            if len(self._keybag_path) > 0:
                self._keybag_summary = load_keybag_safe(self._keybag_path)
                if self._keybag_summary.session_count > 0:
                    try:
                        from Tools.HilBridge.scp_replay import (
                            load_keybag as _load_keybag_strict,
                        )
                        self._replay_engine = ScpReplayEngine(
                            _load_keybag_strict(self._keybag_path)
                        )
                    except Exception as engine_exc:
                        self._keybag_summary = KeybagLoadSummary(
                            session_count=0,
                            source_path=self._keybag_path,
                            error_text=f"Replay engine init failed: {engine_exc}",
                        )
                        self._replay_engine = None
            self._live_stream = None
            self._live_stream_started = False
            self._live_stream_disabled = bool(live_capture) is False
            self._live_stream_disabled_reason = (
                "offline review (no live capture)"
                if bool(live_capture) is False
                else ""
            )
            self._live_seen_keys: set[tuple[str, str, str, str]] = set()
            self._live_next_frame_number = 1
            self._live_stream_delivered_count = 0
            self._live_stream_last_rx_monotonic: float | None = None
            self._live_stream_start_deadline: float = 0.0
            self._summary_rebuild_pending: bool = False
            self._summary_rebuild_pending_scroll: bool = False
            self._last_summary_rebuild_monotonic: float = 0.0
            self._summary_rebuild_throttle_seconds: float = 0.5
            self._ingest_paused: bool = False
            self._paused_live_rows: list[PacketSummary] = []
            self._ingest_pause_generation: int = 0
            self._paused_queue_cap: int = _PAUSED_QUEUE_HARD_CAP_DEFAULT
            self._paused_queue_dropped: int = 0
            self._paused_queue_high_water_mark: int = 0
            self._paused_queue_protocol_counts: dict[str, int] = {}
            self._pause_event_count: int = 0
            self._pause_total_duration_seconds: float = 0.0
            self._pause_started_monotonic: float | None = None
            self._auto_pause_hint_samples: list[tuple[float, int]] = []
            self._auto_pause_hint_last_emitted_monotonic: float | None = None
            self._clear_capture_view_confirm_deadline: float = 0.0
            self._force_clip_next_save: bool = False

        def compose(self) -> ComposeResult:
            yield Static(
                (
                    "HIL Decode TUI · Browse frames in the summary pane · F1 keybinds · "
                    "F2 pause (Ctrl+F2 discard) · F3 cycle theme · "
                    "F4 cycle summary view · "
                    "Tab switches pane focus · F5/F8/F9 show-hide panes · F6 follow tail · "
                    "F7 state hop · F10 pane menu · F11 export (Shift+F11 clipped) · "
                    "Ctrl+F11 clear view · F12 open capture · Ctrl+Q quits"
                ),
                id="chrome_title",
            )
            with Vertical(id="chrome"):
                with Vertical(id="body"):
                    with Vertical(id="upper"):
                        with Vertical(id="summary_col"):
                            yield Static("", id="summary_caption", classes="pane-caption")
                            yield Tree(
                                "Packet context tree",
                                id="summary_tree",
                                classes="pane-body",
                            )
                    yield DragHandle("", id="bottom_handle", classes="drag-handle")
                    with Horizontal(id="bottom_row"):
                        with Vertical(id="detail_col"):
                            yield Static("", id="detail_caption", classes="pane-caption")
                            yield Tree(
                                "Decoded packet",
                                id="detail_view",
                                classes="pane-body",
                            )
                        yield DragHandle("", id="detail_handle", classes="drag-handle")
                        with Vertical(id="bytes_col"):
                            yield Static("", id="bytes_caption", classes="pane-caption")
                            yield RichLog(
                                id="bytes_view",
                                classes="pane-body pretty-log-pane",
                                auto_scroll=False,
                                wrap=False,
                                max_lines=None,
                                highlight=False,
                            )
                yield Static("", id="status_line")

        def on_mount(self) -> None:
            self._apply_theme_preference()
            summary_tree = self.query_one("#summary_tree", Tree)
            summary_tree.show_root = False
            summary_tree.root.expand()
            self._set_detail_views(
                "Waiting for packet selection before loading decoded fields.",
                "Waiting for packet selection before loading the byte view.",
            )
            self._refresh_chrome_title()
            self._refresh_captions()
            self._apply_pane_layout()
            self._refresh_status_line()
            self.call_after_refresh(self._apply_split_sizes)
            self.call_after_refresh(self._ensure_valid_focus)
            self.set_interval(0.35, self._schedule_summary_refresh)
            self.set_interval(0.35, self._tick_status_refresh)
            self.set_interval(0.15, self._drain_live_stream_tick)
            self.set_interval(1.0, self._ensure_live_stream_started)
            self.call_after_refresh(self._schedule_summary_refresh)
            self.call_after_refresh(self._ensure_live_stream_started)

        def on_unmount(self) -> None:
            self._shutdown_event.set()
            self._stop_live_stream()

        def action_quit_view(self) -> None:
            self.exit()

        def action_show_keybinds(self) -> None:
            self.push_screen(KeybindHelpScreen())

        def action_toggle_detail_subtree(self) -> None:
            focused_widget = self.focused
            focused_widget_id = str(getattr(focused_widget, "id", "") or "").strip()
            if focused_widget_id != "detail_view":
                return
            current_node = getattr(focused_widget, "cursor_node", None)
            if current_node is None:
                return
            _toggle_tree_subtree(current_node)

        def action_cycle_focus(self) -> None:
            ordered_panes = visible_pane_order(self._visibility)
            if len(ordered_panes) == 0:
                return
            widget_by_pane = {
                "summary": self._summary_widget(),
                "detail": self._detail_widget(),
                "bytes": self._bytes_widget(),
            }
            focused_widget = self.focused
            focused_pane = None
            for pane_name, widget in widget_by_pane.items():
                if focused_widget is widget:
                    focused_pane = pane_name
                    break
            if focused_pane not in ordered_panes:
                widget_by_pane[ordered_panes[0]].focus()
                return
            current_index = ordered_panes.index(focused_pane)
            next_pane = ordered_panes[(current_index + 1) % len(ordered_panes)]
            widget_by_pane[next_pane].focus()

        def on_key(self, event: events.Key) -> None:
            normalized_key = str(getattr(event, "key", "") or "").strip().lower()
            if normalized_key not in {"left", "right"}:
                return
            focused_widget = self.focused
            focused_widget_id = str(getattr(focused_widget, "id", "") or "").strip()
            if focused_widget_id not in {"summary_tree", "detail_view"}:
                return
            if _handle_tree_arrow_key(focused_widget, normalized_key) is False:
                return
            prevent_default = getattr(event, "prevent_default", None)
            if callable(prevent_default):
                try:
                    prevent_default()
                except Exception:
                    pass
            stop = getattr(event, "stop", None)
            if callable(stop):
                try:
                    stop()
                except Exception:
                    pass

        def action_cycle_theme(self) -> None:
            self._theme_name = _next_theme_name(self._theme_name)
            applied_theme = self._apply_theme_preference()
            self._refresh_summary_tree_visual(scroll=False)
            self._schedule_detail_refresh()
            self._refresh_chrome_title()
            self._refresh_captions()
            self._save_layout_preferences()
            self._refresh_status_line(message=f"Theme switched to {applied_theme}.", error=False)

        def action_cycle_summary_view(self) -> None:
            normalized_current_mode = _normalize_summary_view_mode(self._summary_view_mode)
            if normalized_current_mode in _SUMMARY_VIEW_CYCLE:
                current_index = _SUMMARY_VIEW_CYCLE.index(normalized_current_mode)
                next_index = (current_index + 1) % len(_SUMMARY_VIEW_CYCLE)
            else:
                # Poll view (or any mode outside the cycle) bounces back to
                # the first entry of the cycle rather than silently rotating
                # off into a view F4 was not meant to expose.
                next_index = 0
            self._summary_view_mode = _SUMMARY_VIEW_CYCLE[next_index]
            # User-triggered view switches bypass the rebuild throttle;
            # otherwise an immediate F4 after the first refresh paints
            # nothing until the throttle window elapses, which made the
            # flat chronological list look broken.
            self._refresh_summary_tree_visual(scroll=self._follow_tail, force=True)
            self._refresh_captions()
            self._save_layout_preferences()
            self._refresh_status_line(
                message=f"Summary view switched to {_summary_view_title(self._summary_view_mode).lower()}.",
                error=False,
            )
            if bool(self._visibility.summary):
                self._summary_widget().focus()

        def action_toggle_follow_tail(self) -> None:
            self._follow_tail = not self._follow_tail
            if self._follow_tail:
                self.action_jump_tail()
                return
            self._refresh_status_line()

        def action_toggle_ingest_pause(self) -> None:
            # F2 pauses ingestion of newly decoded rows without cutting
            # off the capture. While paused the tshark FIFO is still
            # drained (so the writer side never blocks) and every new
            # packet is buffered in _paused_live_rows. The pcap re-parse
            # worker is short-circuited in _schedule_summary_refresh so
            # the user can browse a stable tree during a packet storm.
            # On resume the queued rows are applied in a single batch
            # and a fresh pcap refresh is triggered to reconcile any
            # frames that slipped in before the live stream primed.
            self._set_ingest_paused(not self._ingest_paused, discard_on_resume=False)

        def action_toggle_ingest_pause_discard(self) -> None:
            # Ctrl+F2 pauses like F2 does, but on resume it drops the
            # queued rows instead of replaying them. Matches the
            # workflow where the operator paused specifically to freeze
            # context and is fine letting the stream catch up on its
            # own.
            self._set_ingest_paused(not self._ingest_paused, discard_on_resume=True)

        def _set_ingest_paused(
            self,
            should_pause: bool,
            *,
            discard_on_resume: bool,
        ) -> None:
            next_state = bool(should_pause)
            if next_state == self._ingest_paused:
                return
            self._ingest_paused = next_state
            # Bump the pause generation on both entry and exit so any
            # parse / detail worker that was already running at the
            # moment the user toggled can safely detect the transition
            # and drop its result. Without this an in-flight worker
            # that wakes up after the toggle could leak stale rows
            # into _base_rows (entry race) or drop rows we actually
            # wanted (exit race).
            self._ingest_pause_generation = int(self._ingest_pause_generation) + 1
            if self._ingest_paused:
                self._pause_event_count += 1
                self._pause_started_monotonic = time.monotonic()
                self._auto_pause_hint_last_emitted_monotonic = None
                self._refresh_status_line()
                self._refresh_captions()
                self._refresh_chrome_title()
                return
            started_monotonic = self._pause_started_monotonic
            if started_monotonic is not None:
                self._pause_total_duration_seconds += max(
                    0.0, time.monotonic() - float(started_monotonic)
                )
            self._pause_started_monotonic = None
            queued_rows = list(self._paused_live_rows)
            queued_protocol_counts = dict(self._paused_queue_protocol_counts)
            self._paused_live_rows = []
            self._paused_queue_protocol_counts = {}
            self._paused_queue_high_water_mark = 0
            drained_count = len(queued_rows)
            if bool(discard_on_resume):
                discard_text = ""
                if drained_count > 0:
                    discard_text = (
                        f" | discarded {drained_count} queued packet(s) on resume"
                    )
                self._refresh_status_line(
                    message=f"Ingest resumed{discard_text}",
                    error=False,
                )
            else:
                if drained_count > 0:
                    self._live_stream_delivered_count += drained_count
                    self._apply_live_stream_additions(queued_rows)
            del queued_protocol_counts
            self._schedule_summary_refresh()
            if bool(discard_on_resume) is False:
                self._refresh_status_line()
            self._refresh_captions()
            self._refresh_chrome_title()

        def action_jump_tail(self) -> None:
            if len(self._rows) == 0:
                self._follow_tail = True
                self._refresh_status_line()
                return
            self._select_frame_number(
                int(self._rows[-1].number),
                scroll=True,
                focus_summary=True,
            )

        def _jump_state_event(self, direction: int) -> None:
            if len(self._interesting_frame_numbers) == 0:
                self._refresh_status_line(
                    message="No stateful SAT/channel/timer frames captured yet.",
                    error=False,
                )
                return
            target_frame_number = None
            wrapped = False
            current_frame_number = self._selected_frame_number
            if current_frame_number is None:
                if direction >= 0:
                    target_frame_number = int(self._interesting_frame_numbers[0])
                else:
                    target_frame_number = int(self._interesting_frame_numbers[-1])
            elif direction >= 0:
                for candidate in self._interesting_frame_numbers:
                    if int(candidate) > int(current_frame_number):
                        target_frame_number = int(candidate)
                        break
                if target_frame_number is None:
                    target_frame_number = int(self._interesting_frame_numbers[0])
                    wrapped = True
            else:
                for candidate in reversed(self._interesting_frame_numbers):
                    if int(candidate) < int(current_frame_number):
                        target_frame_number = int(candidate)
                        break
                if target_frame_number is None:
                    target_frame_number = int(self._interesting_frame_numbers[-1])
                    wrapped = True
            self._select_frame_number(
                int(target_frame_number),
                scroll=True,
                message=self._state_jump_message(int(target_frame_number), wrapped=wrapped),
            )

        def action_jump_next_state_event(self) -> None:
            self._jump_state_event(1)

        def action_jump_prev_state_event(self) -> None:
            self._jump_state_event(-1)

        def action_toggle_summary_pane(self) -> None:
            self._toggle_pane("summary")

        def action_toggle_detail_pane(self) -> None:
            self._toggle_pane("detail")

        def action_toggle_expert_detail_lines(self) -> None:
            self._show_expert_detail_lines = not self._show_expert_detail_lines
            self._refresh_summary_tree_visual(scroll=False)
            self._refresh_captions()
            detail_mode = "shown" if self._show_expert_detail_lines else "hidden"
            self._refresh_status_line(message=f"Summary expert details {detail_mode}.", error=False)

        def action_toggle_bytes_pane(self) -> None:
            self._toggle_pane("bytes")

        def action_open_pane_layout_menu(self) -> None:
            self.push_screen(
                PaneLayoutPicker(self._visibility),
                callback=self._on_pane_layout_choice,
            )

        def action_save_trace_snapshot(self) -> None:
            self._force_clip_next_save = False
            self._open_trace_save_picker()

        def action_save_trace_snapshot_clipped(self) -> None:
            # Shift+F11 forces the editcap clip path regardless of the
            # current pause state. Lets the operator freeze the export
            # to the currently displayed row count even while ingest is
            # still active (useful when demo recording or bug-bundling
            # a specific window of a noisy live capture).
            if len(self._base_rows) == 0:
                self._refresh_status_line(
                    message="No packets in context to clip. Load a capture before exporting.",
                    error=True,
                )
                return
            self._force_clip_next_save = True
            self._open_trace_save_picker()

        def _open_trace_save_picker(self) -> None:
            if len(str(self._capture_path or "").strip()) == 0:
                self._refresh_status_line(
                    message="No capture is loaded to export.",
                    error=True,
                )
                return
            self.push_screen(
                TraceSavePicker(
                    self._capture_path,
                    self._last_trace_export_directory,
                ),
                callback=self._on_trace_save_choice,
            )

        def action_clear_capture_view(self) -> None:
            if len(str(self._capture_path or "").strip()) == 0 and len(self._rows) == 0:
                self._refresh_status_line(
                    message="Capture view is already cleared.",
                    error=False,
                )
                return
            # When ingest is paused with non-empty queue, discarding the
            # capture view would also silently throw away the buffered
            # rows the operator paused specifically to inspect. Require
            # a confirming second press within five seconds so a stray
            # Ctrl+F11 can't blow the context away.
            if self._ingest_paused and len(self._paused_live_rows) > 0:
                now_monotonic = time.monotonic()
                confirm_deadline = float(self._clear_capture_view_confirm_deadline or 0.0)
                if now_monotonic > confirm_deadline:
                    self._clear_capture_view_confirm_deadline = now_monotonic + 5.0
                    queued = int(len(self._paused_live_rows))
                    self._refresh_status_line(
                        message=(
                            f"Paused with {queued} queued packet(s). Press Ctrl+F11 again "
                            "within 5s to discard and clear view."
                        ),
                        error=True,
                    )
                    return
                self._clear_capture_view_confirm_deadline = 0.0
            self._capture_path = ""
            _reset_capture_runtime_state(self)
            self._set_detail_views(
                "Waiting for packet selection before loading decoded fields.",
                "Waiting for packet selection before loading the byte view.",
            )
            self._refresh_captions()
            self._rebuild_summary_view()
            self._refresh_chrome_title()
            self._refresh_status_line(
                message="Capture view cleared. F12 opens a capture. Ctrl+F12 restores live capture.",
                error=False,
            )

        def action_open_capture_file(self) -> None:
            try:
                selected_path = pick_capture_file_path(
                    self._capture_path,
                    last_open_directory=self._last_capture_open_directory,
                )
            except RuntimeError:
                self.push_screen(
                    CaptureOpenPicker(self._capture_path),
                    callback=self._on_open_capture_choice,
                )
                return
            except Exception as exc:
                self._refresh_status_line(
                    message=f"Open capture failed: {exc}",
                    error=True,
                )
                return
            if selected_path is None:
                return
            self._remember_capture_open_directory(selected_path.parent)
            self._switch_capture_path(
                str(selected_path),
                message=f"Opened capture: {_display_path_text(selected_path)}",
                remembered_open_directory=str(selected_path.parent),
            )

        def action_restore_live_capture(self) -> None:
            if self._live_capture_mode is False:
                self._refresh_status_line(
                    message=(
                        "Offline review: no live capture to restore. "
                        "F12 opens another pcap."
                    ),
                    error=True,
                )
                return
            if len(str(self._live_capture_path or "").strip()) == 0:
                self._refresh_status_line(
                    message="Live capture path is not configured.",
                    error=True,
                )
                return
            self._switch_capture_path(
                self._live_capture_path,
                message=f"Restored live capture: {_display_path_text(Path(self._live_capture_path))}",
            )

        def _on_open_capture_choice(self, choice: str | None) -> None:
            if choice is None:
                return
            try:
                selected_path = _normalize_selected_capture_path(str(choice or ""))
            except Exception as exc:
                self._refresh_status_line(
                    message=f"Open capture failed: {exc}",
                    error=True,
                )
                return
            if selected_path is None:
                return
            self._remember_capture_open_directory(selected_path.parent)
            self._switch_capture_path(
                str(selected_path),
                message=f"Opened capture: {_display_path_text(selected_path)}",
                remembered_open_directory=str(selected_path.parent),
            )

        def _on_trace_save_choice(self, choice: str | None) -> None:
            force_clip_requested = bool(self._force_clip_next_save)
            self._force_clip_next_save = False
            if choice is None:
                return
            # While ingest is paused the pcap on disk keeps growing past
            # what the tree shows, and the FIFO queue holds the rest.
            # Clamp the exported snapshot to the currently-displayed
            # context (_base_rows) so the saved file matches what the
            # operator is actually looking at. Shift+F11 sets
            # _force_clip_next_save so the same clipping applies even
            # when ingest is still live.
            packet_count: int | None = None
            clip_reason = ""
            if self._ingest_paused and len(self._base_rows) > 0:
                packet_count = int(len(self._base_rows))
                clip_reason = "paused context"
            elif force_clip_requested and len(self._base_rows) > 0:
                packet_count = int(len(self._base_rows))
                clip_reason = "clipped"
            try:
                saved_path = save_live_capture_trace(
                    self._capture_path,
                    target_path=str(choice or ""),
                    packet_count=packet_count,
                    tshark_binary=self._tshark_binary,
                )
            except Exception as exc:
                self._refresh_status_line(
                    message=f"Trace export failed: {exc}",
                    error=True,
                )
                return
            self._last_trace_export_directory = _normalize_directory_preference(saved_path.parent)
            self._save_layout_preferences()
            if packet_count is None:
                status_message = f"Trace snapshot saved: {_display_path_text(saved_path)}"
            else:
                status_message = (
                    f"Trace snapshot saved ({clip_reason} \u00b7 {packet_count} packets): "
                    f"{_display_path_text(saved_path)}"
                )
            self._refresh_status_line(
                message=status_message,
                error=False,
            )

        def _remember_capture_open_directory(self, directory_path: str | Path) -> None:
            self._last_capture_open_directory = _normalize_directory_preference(directory_path)
            self._save_layout_preferences()

        def _switch_capture_path(
            self,
            capture_path_text: str,
            *,
            message: str | None = None,
            remembered_open_directory: str = "",
        ) -> None:
            selected_path = _normalize_selected_capture_path(capture_path_text)
            if selected_path is None:
                raise ValueError("Capture file path must not be empty.")
            self._capture_path = str(selected_path)
            loaded_preferences = load_tui_layout_preferences(self._capture_path)
            self._summary_view_mode = _normalize_summary_view_mode(loaded_preferences.summary_view_mode)
            self._theme_name = _normalize_theme_name(loaded_preferences.theme_name)
            self._last_trace_export_directory = str(loaded_preferences.last_export_directory or "").strip()
            normalized_remembered_open_directory = _normalize_directory_preference(remembered_open_directory)
            if len(normalized_remembered_open_directory) > 0:
                self._last_capture_open_directory = normalized_remembered_open_directory
            else:
                self._last_capture_open_directory = str(loaded_preferences.last_capture_open_directory or "").strip()
            self._apply_theme_preference()
            self._refresh_chrome_title()
            _reset_capture_runtime_state(self)
            self._set_detail_views(
                "Loading decoded fields...",
                "Loading byte view...",
            )
            self._refresh_captions()
            self._rebuild_summary_view()
            self._schedule_summary_refresh()
            if message is None:
                self._refresh_status_line()
                return
            self._refresh_status_line(message=message, error=False)

        def _on_pane_layout_choice(self, choice: str | None) -> None:
            if choice is None:
                return
            normalized_choice = str(choice or "").strip().lower()
            if normalized_choice == "reset":
                defaults = default_tui_layout_preferences()
                self._visibility = defaults.visibility
                self._summary_height = int(defaults.summary_height)
                self._detail_width = int(defaults.detail_width)
                self._summary_view_mode = _normalize_summary_view_mode(defaults.summary_view_mode)
                self._theme_name = _normalize_theme_name(defaults.theme_name)
                self._apply_theme_preference()
                self._apply_pane_layout()
                self._refresh_chrome_title()
                self._refresh_captions()
                self._refresh_summary_tree_visual(scroll=False)
                self._schedule_detail_refresh()
                self._save_layout_preferences()
                self._refresh_status_line(message="Pane layout reset to defaults.", error=False)
                return
            if normalized_choice.startswith("pane:") is False:
                self._refresh_status_line(message=f"Unknown pane layout choice: {choice}", error=True)
                return
            parts = normalized_choice.split(":")
            if len(parts) != 3:
                self._refresh_status_line(message=f"Invalid pane layout choice: {choice}", error=True)
                return
            _prefix, pane_name, action_name = parts
            if action_name != "toggle":
                self._refresh_status_line(message=f"Unsupported pane layout choice: {choice}", error=True)
                return
            self._toggle_pane(pane_name)

        def _toggle_pane(self, pane_name: str) -> None:
            current_visibility = self._visibility
            next_visibility = toggled_pane_visibility(current_visibility, pane_name)
            if next_visibility == current_visibility and bool(getattr(current_visibility, pane_name, False)):
                self._refresh_status_line(
                    message="At least one pane must remain visible.",
                    error=True,
                )
                return
            self._visibility = next_visibility
            self._apply_pane_layout()
            self._save_layout_preferences()
            state_label = "shown" if bool(getattr(self._visibility, pane_name)) else "hidden"
            self._refresh_status_line(
                message=f"{_pane_display_name(pane_name)} pane {state_label}.",
                error=False,
            )

        def _apply_pane_layout(self) -> None:
            upper = self.query_one("#upper", Vertical)
            bottom_handle = self.query_one("#bottom_handle", DragHandle)
            bottom_row = self.query_one("#bottom_row", Horizontal)
            detail_col = self.query_one("#detail_col", Vertical)
            detail_handle = self.query_one("#detail_handle", DragHandle)
            bytes_col = self.query_one("#bytes_col", Vertical)

            summary_visible = bool(self._visibility.summary)
            detail_visible = bool(self._visibility.detail)
            bytes_visible = bool(self._visibility.bytes)
            any_bottom_visible = detail_visible or bytes_visible

            upper.display = summary_visible
            bottom_handle.display = summary_visible and any_bottom_visible
            bottom_row.display = any_bottom_visible
            detail_col.display = detail_visible
            bytes_col.display = bytes_visible
            detail_handle.display = detail_visible and bytes_visible

            self._apply_split_sizes()
            self._ensure_valid_focus()
            self._refresh_captions()

        def _apply_split_sizes(self) -> None:
            try:
                body = self.query_one("#body", Vertical)
                upper = self.query_one("#upper", Vertical)
                bottom_row = self.query_one("#bottom_row", Horizontal)
                detail_col = self.query_one("#detail_col", Vertical)
                bytes_col = self.query_one("#bytes_col", Vertical)
            except Exception:
                return

            summary_visible = bool(self._visibility.summary)
            detail_visible = bool(self._visibility.detail)
            bytes_visible = bool(self._visibility.bytes)
            any_bottom_visible = detail_visible or bytes_visible

            if summary_visible and any_bottom_visible:
                body_height = _measured_extent(body, "height")
                if body_height > 0:
                    total_height = max(body_height, 14)
                    max_summary_height = max(6, total_height - 8)
                    min_summary_height = min(10, max_summary_height)
                    self._summary_height = max(
                        min_summary_height,
                        min(max_summary_height, int(self._summary_height or _DEFAULT_SUMMARY_HEIGHT)),
                    )
                    upper.styles.height = self._summary_height
                else:
                    upper.styles.height = max(
                        6,
                        int(self._summary_height or _DEFAULT_SUMMARY_HEIGHT),
                    )
                bottom_row.styles.height = "1fr"
            elif summary_visible:
                upper.styles.height = "1fr"
            else:
                upper.styles.height = 0

            if detail_visible and bytes_visible:
                bottom_width = _measured_extent(bottom_row, "width")
                if bottom_width > 0:
                    total_width = max(bottom_width, 72)
                    max_detail_width = max(28, total_width - 28)
                    min_detail_width = min(40, max_detail_width)
                    self._detail_width = max(
                        min_detail_width,
                        min(max_detail_width, int(self._detail_width or _DEFAULT_DETAIL_WIDTH)),
                    )
                    detail_col.styles.width = self._detail_width
                else:
                    detail_col.styles.width = max(
                        28,
                        int(self._detail_width or _DEFAULT_DETAIL_WIDTH),
                    )
                bytes_col.styles.width = "1fr"
            else:
                detail_col.styles.width = "1fr"
                bytes_col.styles.width = "1fr"

        def on_resize(self) -> None:
            self._apply_split_sizes()

        def _begin_split_drag(self, handle_id: str, sx: int, sy: int) -> None:
            if handle_id not in {"bottom_handle", "detail_handle"}:
                return
            summary_height = self._summary_height
            detail_width = self._detail_width
            try:
                summary_height = max(6, int(self.query_one("#upper", Vertical).region.height))
            except Exception:
                pass
            try:
                detail_width = max(28, int(self.query_one("#detail_col", Vertical).region.width))
            except Exception:
                pass
            self._drag_state = {
                "handle_id": handle_id,
                "sx": sx,
                "sy": sy,
                "summary_height": summary_height,
                "detail_width": detail_width,
            }

        def _continue_split_drag(self, sx: int, sy: int) -> None:
            if self._drag_state is None:
                return
            dx = sx - self._drag_state["sx"]
            dy = sy - self._drag_state["sy"]
            handle_id = str(self._drag_state["handle_id"])
            if handle_id == "bottom_handle":
                total_height = max(int(self.query_one("#body", Vertical).size.height or 0), 14)
                max_summary_height = max(6, total_height - 8)
                min_summary_height = min(10, max_summary_height)
                self._summary_height = max(
                    min_summary_height,
                    min(
                        max_summary_height,
                        int(self._drag_state["summary_height"]) + dy,
                    ),
                )
            elif handle_id == "detail_handle":
                total_width = max(int(self.query_one("#bottom_row", Horizontal).size.width or 0), 72)
                max_detail_width = max(28, total_width - 28)
                min_detail_width = min(40, max_detail_width)
                self._detail_width = max(
                    min_detail_width,
                    min(
                        max_detail_width,
                        int(self._drag_state["detail_width"]) + dx,
                    ),
                )
            self._apply_split_sizes()

        def _end_split_drag(self) -> None:
            if self._drag_state is not None:
                self._save_layout_preferences()
            self._drag_state = None

        def _current_layout_preferences(self) -> TuiLayoutPreferences:
            visibility = self._visibility
            if count_visible_panes(visibility) <= 0:
                visibility = default_tui_layout_preferences().visibility
            return TuiLayoutPreferences(
                visibility=visibility,
                summary_height=max(6, int(self._summary_height or _DEFAULT_SUMMARY_HEIGHT)),
                detail_width=max(28, int(self._detail_width or _DEFAULT_DETAIL_WIDTH)),
                summary_view_mode=_normalize_summary_view_mode(self._summary_view_mode),
                theme_name=_normalize_theme_name(self._theme_name),
                last_export_directory=_normalize_directory_preference(self._last_trace_export_directory),
                last_capture_open_directory=_normalize_directory_preference(self._last_capture_open_directory),
            )

        def _rebuild_state_annotations(self) -> None:
            self._state_annotations = {}
            self._interesting_frame_numbers = []
            if len(self._base_rows) == 0:
                return
            # The replay engine is stateful (SSC / chaining_value advance on
            # every wrap). A full rebuild must restart from the keybag to
            # keep counters aligned with frame order, so we rebuild the
            # engine instance instead of reusing the partially-advanced one.
            fresh_engine: ScpReplayEngine | None = None
            if self._replay_engine is not None and len(self._keybag_path) > 0:
                try:
                    from Tools.HilBridge.scp_replay import (
                        load_keybag as _load_keybag_strict,
                    )
                    fresh_engine = ScpReplayEngine(
                        _load_keybag_strict(self._keybag_path)
                    )
                except Exception:
                    fresh_engine = None
            try:
                self._state_annotations = build_stateful_packet_annotations(
                    self._base_rows,
                    replay_engine=fresh_engine,
                )
            except Exception:
                self._state_annotations = {}
                self._interesting_frame_numbers = []
                return
            if fresh_engine is not None:
                self._replay_engine = fresh_engine
            self._interesting_frame_numbers = sorted(
                int(frame_number)
                for frame_number, annotation in self._state_annotations.items()
                if bool(getattr(annotation, "state_event", False))
            )

        def _decorate_summary_rows(self, rows: list[PacketSummary]) -> list[PacketSummary]:
            decorated_rows: list[PacketSummary] = []
            for row in rows:
                annotation = self._state_annotations.get(int(row.number))
                decorated_rows.append(annotate_packet_summary(row, annotation))
            return decorated_rows

        def _latest_state_annotation(self) -> StatefulFrameAnnotation | None:
            if len(self._base_rows) == 0:
                return None
            latest_frame_number = int(self._base_rows[-1].number)
            return self._state_annotations.get(latest_frame_number)

        def _selected_summary_row(self) -> PacketSummary | None:
            if self._selected_frame_number is None:
                return None
            target_frame_number = int(self._selected_frame_number)
            for row in self._rows:
                if int(row.number) == target_frame_number:
                    return row
            return None

        def _live_timer_elapsed_seconds(self) -> float:
            latest_state = self._latest_state_annotation()
            if latest_state is None:
                return 0.0
            if len(latest_state.active_timers) == 0:
                return 0.0
            if self._capture_path != self._live_capture_path:
                return 0.0
            if self._latest_capture_time_seconds is None or self._latest_capture_monotonic is None:
                return 0.0
            capture_time_seconds = latest_state.capture_time_seconds
            if capture_time_seconds is None:
                return 0.0
            if abs(float(capture_time_seconds) - float(self._latest_capture_time_seconds)) > 1e-9:
                return 0.0
            return max(0.0, time.monotonic() - float(self._latest_capture_monotonic))

        def _live_active_timer_snapshots(self) -> tuple[ActiveTimerSnapshot, ...]:
            latest_state = self._latest_state_annotation()
            if latest_state is None:
                return ()
            if len(latest_state.active_timers) == 0:
                return ()
            extra_elapsed_seconds = self._live_timer_elapsed_seconds()
            visible_snapshots: list[ActiveTimerSnapshot] = []
            for snapshot in latest_state.active_timers:
                if _live_timer_remaining_seconds(snapshot, extra_elapsed_seconds) <= 0:
                    continue
                visible_snapshots.append(snapshot)
            return tuple(visible_snapshots)

        def _live_active_timer_count(self) -> int:
            return len(self._live_active_timer_snapshots())

        def _active_timer_summary_text(self, *, prefix: str) -> str:
            visible_snapshots = self._live_active_timer_snapshots()
            if len(visible_snapshots) == 0:
                return ""
            return _render_timer_summary(
                visible_snapshots,
                self._live_timer_elapsed_seconds(),
                prefix=prefix,
            )

        def _state_event_count(self) -> int:
            return len(self._interesting_frame_numbers)

        def _state_jump_message(self, frame_number: int, *, wrapped: bool) -> str:
            prefix = "Wrapped to" if wrapped else "Jumped to"
            annotation = self._state_annotations.get(int(frame_number))
            summary_suffix = ""
            if annotation is not None:
                summary_suffix = str(annotation.summary_suffix or "").strip()
            if len(summary_suffix) == 0:
                return f"{prefix} state frame #{int(frame_number)}."
            return f"{prefix} state frame #{int(frame_number)} · {summary_suffix}"

        def _selected_state_context_lines(self) -> tuple[str, ...]:
            if self._selected_frame_number is None:
                return ()
            annotation = self._state_annotations.get(int(self._selected_frame_number))
            if annotation is None:
                return ()
            return annotation.context_lines

        def _select_frame_number(
            self,
            frame_number: int,
            *,
            scroll: bool = True,
            message: str | None = None,
            focus_summary: bool = False,
        ) -> None:
            if len(self._rows) == 0:
                return
            target_frame_number = int(frame_number)
            if any(int(row.number) == target_frame_number for row in self._rows) is False:
                return
            self._selected_frame_number = target_frame_number
            if target_frame_number == int(self._rows[-1].number):
                self._follow_tail = True
            else:
                self._follow_tail = False
            self._sync_summary_selection(scroll=scroll)
            self._schedule_detail_refresh()
            self._refresh_captions()
            if message is None:
                self._refresh_status_line()
            else:
                self._refresh_status_line(message=message, error=False)
            if focus_summary and bool(self._visibility.summary):
                self._summary_widget().focus()

        def _save_layout_preferences(self) -> None:
            try:
                save_tui_layout_preferences(
                    self._capture_path,
                    self._current_layout_preferences(),
                )
            except Exception:
                return

        def _ensure_valid_focus(self) -> None:
            ordered_panes = visible_pane_order(self._visibility)
            if len(ordered_panes) == 0:
                return
            focused_widget = self.focused
            visible_widgets = {
                "summary": self._summary_widget(),
                "detail": self._detail_widget(),
                "bytes": self._bytes_widget(),
            }
            if focused_widget in visible_widgets.values():
                for pane_name in ordered_panes:
                    if visible_widgets[pane_name] is focused_widget:
                        return
            visible_widgets[ordered_panes[0]].focus()

        def _detail_widget(self) -> Tree:
            return self.query_one("#detail_view", Tree)

        def _bytes_widget(self) -> RichLog:
            return self.query_one("#bytes_view", RichLog)

        def _active_palette(self) -> TuiThemePalette:
            return _theme_palette(self._theme_name)

        def _apply_theme_preference(self) -> str:
            requested_theme = _normalize_theme_name(self._theme_name)
            for candidate_theme in (requested_theme, _DEFAULT_THEME_NAME, "textual-ansi"):
                try:
                    self.theme = candidate_theme
                except Exception:
                    continue
                self._theme_name = candidate_theme
                return candidate_theme
            self._theme_name = requested_theme
            return requested_theme

        def _refresh_chrome_title(self) -> None:
            body_text = (
                "HIL Decode TUI · Browse frames in the summary pane · "
                f"F1 keybinds · F2 pause (Ctrl+F2 discard) · F3 cycle theme ({self._theme_name}) · "
                "F4 cycle summary view · Tab switches pane focus · F5/F8/F9 show-hide panes · "
                "F6 follow tail · F7 state hop · F10 pane menu · "
                "F11 export (Shift+F11 clipped) · Ctrl+F11 clear view · "
                "F12 open capture · Ctrl+Q quits"
            )
            try:
                chrome_widget = self.query_one("#chrome_title", Static)
            except Exception:
                return
            if self._ingest_paused:
                palette = self._active_palette()
                banner = Text()
                queued = int(len(self._paused_live_rows))
                banner.append(
                    f"[PAUSED · {queued} queued] ",
                    style=f"bold reverse {palette.timer}",
                )
                banner.append(body_text)
                chrome_widget.update(banner)
                chrome_widget.add_class("paused-banner")
                return
            chrome_widget.remove_class("paused-banner")
            chrome_widget.update(body_text)

        def _refresh_captions(self) -> None:
            palette = self._active_palette()
            selected_text = "-"
            selected_wall_time_text = ""
            if self._selected_frame_number is not None:
                selected_text = str(self._selected_frame_number)
            selected_row = self._selected_summary_row()
            if selected_row is not None:
                selected_wall_time_text = str(getattr(selected_row, "wall_time_text", "") or "").strip()
            latest_state = self._latest_state_annotation()
            state_event_count = self._state_event_count()
            summary_view_title = _summary_view_title(self._summary_view_mode)
            summary_view_hint = _summary_view_cycle_hint(self._summary_view_mode)
            live_active_timer_count = self._live_active_timer_count()
            summary_caption = Text()
            if self._ingest_paused:
                queued = int(len(self._paused_live_rows))
                dropped = int(self._paused_queue_dropped)
                badge_text = f"[PAUSED · {queued} queued"
                if dropped > 0:
                    badge_text += f" · {dropped} dropped"
                badge_text += "] "
                summary_caption.append(
                    badge_text,
                    style=f"bold reverse {palette.timer}",
                )
            summary_caption.append(
                f"{summary_view_title} · {len(self._rows)} packet(s) · "
                f"{state_event_count} state event(s) · "
                f"{'follow tail' if self._follow_tail else 'manual browse'}",
                style=palette.primary,
            )
            if latest_state is not None:
                summary_caption.append(
                    f" · {latest_state.active_channel_count} channel(s) active",
                    style=f"bold {palette.bip}",
                )
                timer_count_style = palette.secondary
                if live_active_timer_count > 0:
                    timer_count_style = palette.timer
                summary_caption.append(
                    f" · {live_active_timer_count} timer(s) active",
                    style=f"bold {timer_count_style}",
                )
            timer_summary = self._active_timer_summary_text(prefix="")
            if len(timer_summary) > 0:
                summary_caption.append(" · timers ", style=f"bold {palette.timer}")
                summary_caption.append(timer_summary, style=f"bold {palette.timer}")
            expert_detail_text = "expert details on" if self._show_expert_detail_lines else "protocol summaries only"
            summary_caption.append(
                f" · {summary_view_hint} · F5 hide/show",
                style=f"dim {palette.secondary}",
            )
            summary_caption.append(
                f" · {expert_detail_text} · Ctrl+F8 toggle",
                style=f"dim {palette.secondary}",
            )
            selected_time_suffix = ""
            if len(selected_wall_time_text) > 0:
                selected_time_suffix = f" · {selected_wall_time_text}"
            detail_caption = (
                f"Decoded tree · frame #{selected_text}{selected_time_suffix} · "
                f"Space toggle · Ctrl+Space all · F8 hide/show"
            )
            bytes_caption = f"Bytes · frame #{selected_text}{selected_time_suffix} · F9 hide/show"
            self.query_one("#summary_caption", Static).update(summary_caption)
            self.query_one("#detail_caption", Static).update(detail_caption)
            self.query_one("#bytes_caption", Static).update(bytes_caption)

        def _refresh_status_line(self, message: str | None = None, *, error: bool | None = None) -> None:
            status_widget = self.query_one("#status_line", Static)
            if message is None:
                message = self._build_status_text()
                error = "failed" in message.lower() or (
                    len(self._rows) == 0 and len(str(self._last_error or "").strip()) > 0
                )
            if bool(error):
                status_widget.add_class("error-state")
            else:
                status_widget.remove_class("error-state")
            status_widget.update(str(message or ""))

        def _capture_label_text(self) -> str:
            normalized_capture_path = str(self._capture_path or "").strip()
            if len(normalized_capture_path) == 0:
                return "-"
            try:
                return Path(normalized_capture_path).expanduser().resolve().name or normalized_capture_path
            except Exception:
                return normalized_capture_path

        def _build_status_text(self) -> str:
            if len(str(self._capture_path or "").strip()) == 0:
                return "View cleared | F12 open capture | Ctrl+F12 restore live capture"
            file_size = _file_size(self._capture_path)
            latest_state = self._latest_state_annotation()
            state_event_count = self._state_event_count()
            live_active_timer_count = self._live_active_timer_count()
            if isinstance(self._startup_state, dict):
                startup_error = str(self._startup_state.get("error", "") or "").strip()
                if len(startup_error) > 0:
                    return f"Bridge start failed: {startup_error}"
                if bool(self._startup_state.get("activation_complete", False)) is False:
                    return (
                        "Bridge warm-up in progress | "
                        f"Capture file {max(0, file_size)} bytes"
                    )
            if len(self._rows) == 0:
                if len(str(self._last_error or "").strip()) > 0:
                    return (
                        f"Capture pending | File {max(0, file_size)} bytes | "
                        f"tshark: {self._last_error}"
                    )
                if file_size >= 24:
                    return f"Capture armed | Waiting for APDUs | File {file_size} bytes"
                return "Waiting for bridge-owned capture file..."
            state_suffix = ""
            if latest_state is not None:
                timer_summary = self._active_timer_summary_text(prefix=" | Countdown ")
                state_suffix = (
                    f" | State frames {state_event_count}"
                    f" | Channels {latest_state.active_channel_count}"
                    f" | Timers {live_active_timer_count}"
                    f"{timer_summary}"
                )
            elif state_event_count > 0:
                state_suffix = (
                    f" | State frames {state_event_count}"
                )
            parse_age_suffix = self._parse_age_status_suffix(file_size)
            live_stream_suffix = self._live_stream_status_suffix()
            ingest_pause_suffix = self._ingest_pause_status_suffix()
            replay_suffix = self._scp_replay_status_suffix()
            return (
                f"Packets {len(self._rows)} | "
                f"Selected #{self._selected_frame_number if self._selected_frame_number is not None else '-'} | "
                f"Capture {self._capture_label_text()} | "
                f"File {max(0, file_size)} bytes{parse_age_suffix} | "
                f"View {_summary_view_title(self._summary_view_mode)} | "
                f"{'follow tail' if self._follow_tail else 'manual browse'} | "
                f"Service {self._service_name} | Filter {self._capture_filter}"
                f"{live_stream_suffix}"
                f"{ingest_pause_suffix}"
                f"{replay_suffix}"
                f"{state_suffix}"
            )

        def _scp_replay_status_suffix(self) -> str:
            if self._replay_engine is not None:
                snapshot_count = int(self._keybag_summary.session_count)
                unwrapped = sum(
                    int(entry.get("command_count", 0) or 0)
                    for entry in self._replay_engine.runtime_snapshots()
                )
                return f" | keybag {snapshot_count} sess ({unwrapped} unwrapped)"
            error_text = str(
                getattr(self._keybag_summary, "error_text", "") or ""
            ).strip()
            if len(error_text) > 0:
                trimmed = error_text[:70]
                return f" | keybag error: {trimmed}"
            if len(str(self._keybag_path or "").strip()) > 0:
                return " | keybag empty"
            return ""

        def _ingest_pause_status_suffix(self) -> str:
            if self._ingest_paused is False:
                return ""
            queued = int(len(self._paused_live_rows))
            parts: list[str] = ["F2 resume"]
            elapsed_text = self._ingest_pause_elapsed_text()
            if len(elapsed_text) > 0:
                parts.append(elapsed_text)
            parts.append(f"{queued} queued")
            if int(self._paused_queue_dropped) > 0:
                parts.append(f"{int(self._paused_queue_dropped)} dropped")
            if int(self._paused_queue_high_water_mark) > queued and int(self._paused_queue_high_water_mark) > 0:
                parts.append(f"peak {int(self._paused_queue_high_water_mark)}")
            breakdown_text = self._paused_queue_protocol_breakdown_text()
            if len(breakdown_text) > 0:
                parts.append(breakdown_text)
            joined = " \u00b7 ".join(parts)
            return f" | paused ({joined})"

        def _ingest_pause_elapsed_text(self) -> str:
            started = self._pause_started_monotonic
            if started is None:
                return ""
            elapsed_seconds = max(0.0, time.monotonic() - float(started))
            if elapsed_seconds < 1.0:
                return ""
            return _format_duration_text(elapsed_seconds)

        def _paused_queue_protocol_breakdown_text(self, *, max_buckets: int = 4) -> str:
            counts = dict(self._paused_queue_protocol_counts or {})
            if len(counts) == 0:
                return ""
            ranked = sorted(
                counts.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )
            limited = ranked[:max_buckets]
            breakdown_parts = [f"{label}:{count}" for label, count in limited if int(count) > 0]
            if len(breakdown_parts) == 0:
                return ""
            if len(ranked) > max_buckets:
                breakdown_parts.append("…")
            return " ".join(breakdown_parts)

        def pause_telemetry_snapshot(self) -> dict[str, int | float]:
            # Exposed as a plain dict so tests and higher-level tooling
            # can sample counters without reaching into private state.
            return {
                "pause_event_count": int(self._pause_event_count),
                "pause_total_duration_seconds": float(self._pause_total_duration_seconds),
                "pause_currently_active": bool(self._ingest_paused),
                "pause_generation": int(self._ingest_pause_generation),
                "paused_queue_size": int(len(self._paused_live_rows)),
                "paused_queue_high_water_mark": int(self._paused_queue_high_water_mark),
                "paused_queue_dropped": int(self._paused_queue_dropped),
            }

        def _parse_age_status_suffix(self, file_size: int) -> str:
            if self._refresh_inflight:
                return " | parsing..."
            if self._last_parse_completed_monotonic is None:
                return ""
            age_seconds = max(0.0, time.monotonic() - float(self._last_parse_completed_monotonic))
            pending_bytes = 0
            if file_size > 0 and file_size > self._last_capture_size:
                pending_bytes = int(file_size - max(0, self._last_capture_size))
            if pending_bytes > 0:
                return f" | +{pending_bytes}B pending | last parse {age_seconds:.1f}s ago"
            return f" | parsed {age_seconds:.1f}s ago"

        def _live_stream_status_suffix(self) -> str:
            if self._live_capture_mode is False:
                return " | offline review"
            fifo_path = str(self._mirror_fifo_path or "").strip()
            if len(fifo_path) == 0:
                try:
                    fifo_path = self._resolve_live_stream_fifo_path()
                except Exception:
                    fifo_path = ""
            if len(fifo_path) == 0:
                return ""
            if self._live_stream_disabled:
                reason = str(self._live_stream_disabled_reason or "").strip()
                if len(reason) > 0:
                    return f" | live: off ({reason[:60]})"
                return " | live: off"
            stream = self._live_stream
            if stream is None or self._live_stream_started is False:
                return " | live: starting"
            delivered = int(self._live_stream_delivered_count)
            if delivered == 0:
                return " | live: idle (0 delivered)"
            last_rx = self._live_stream_last_rx_monotonic
            if last_rx is None:
                return f" | live: up ({delivered} delivered)"
            age_seconds = max(0.0, time.monotonic() - float(last_rx))
            return f" | live: up ({delivered} delivered, last {age_seconds:.1f}s)"

        def _summary_widget(self) -> Tree:
            return self.query_one("#summary_tree", Tree)

        def _schedule_summary_refresh(self) -> None:
            if self._shutdown_event.is_set():
                return
            if self._refresh_inflight:
                return
            if self._ingest_paused:
                # Do not spin up a tshark re-parse worker while ingest is
                # paused. The pcap file keeps growing on disk; the post-
                # resume refresh picks up every missed frame in a single
                # pass via action_toggle_ingest_pause.
                return
            normalized_capture_path = str(self._capture_path or "").strip()
            if len(normalized_capture_path) == 0:
                self._last_error = ""
                self._refresh_captions()
                self._refresh_status_line()
                return
            current_size = _file_size(normalized_capture_path)
            if (
                current_size >= 0
                and current_size == self._last_capture_size
                and len(self._rows) > 0
            ):
                self._refresh_captions()
                self._refresh_status_line()
                return
            if self._live_stream_is_primary_source():
                self._refresh_captions()
                self._refresh_status_line()
                return
            self._refresh_inflight = True
            capture_generation = int(self._capture_generation)
            pre_parse_size = int(current_size)
            if self._summary_refresh_worker_available():
                worker = threading.Thread(
                    target=self._summary_refresh_worker,
                    args=(
                        capture_generation,
                        normalized_capture_path,
                        pre_parse_size,
                    ),
                    daemon=True,
                )
                worker.start()
                return
            self._run_summary_refresh_inline(
                capture_generation,
                normalized_capture_path,
                pre_parse_size,
            )

        def _live_stream_is_primary_source(self) -> bool:
            if self._live_stream is None:
                return False
            if self._live_stream_started is False:
                return False
            try:
                stream_alive = bool(self._live_stream.is_alive())
            except Exception:
                stream_alive = False
            if stream_alive is False:
                return False
            if int(self._live_stream_delivered_count) <= 0:
                return False
            if len(self._rows) == 0:
                return False
            last_rx = self._live_stream_last_rx_monotonic
            if last_rx is None:
                return False
            recency_seconds = max(0.0, time.monotonic() - float(last_rx))
            return recency_seconds <= 5.0

        def _summary_refresh_worker_available(self) -> bool:
            try:
                return bool(getattr(self, "is_running", False))
            except Exception:
                return False

        def _run_summary_refresh_inline(
            self,
            capture_generation: int,
            capture_path_text: str,
            pre_parse_size: int,
        ) -> None:
            try:
                rows, error_text = read_packet_summaries(
                    capture_path_text,
                    tshark_binary=self._tshark_binary,
                    decode_rule=self._decode_rule,
                )
            except Exception as exc:
                self._refresh_inflight = False
                self._last_error = f"Summary refresh failed: {exc}"
                self._refresh_status_line()
                return
            try:
                self._apply_summary_refresh(
                    rows,
                    error_text,
                    pre_parse_size=pre_parse_size,
                    capture_generation=capture_generation,
                )
            except Exception as exc:
                self._refresh_inflight = False
                self._last_error = f"Summary UI refresh failed: {exc}"
                self._refresh_status_line()

        def _summary_refresh_worker(
            self,
            capture_generation: int,
            capture_path_text: str,
            pre_parse_size: int,
        ) -> None:
            try:
                rows, error_text = read_packet_summaries(
                    capture_path_text,
                    tshark_binary=self._tshark_binary,
                    decode_rule=self._decode_rule,
                )
            except Exception as exc:
                try:
                    self.call_from_thread(
                        self._handle_summary_refresh_worker_error,
                        int(capture_generation),
                        f"Summary refresh failed: {exc}",
                    )
                except Exception:
                    self._refresh_inflight = False
                return
            try:
                self.call_from_thread(
                    self._apply_summary_refresh_from_worker,
                    int(capture_generation),
                    list(rows),
                    str(error_text or ""),
                    int(pre_parse_size),
                )
            except Exception:
                self._refresh_inflight = False

        def _handle_summary_refresh_worker_error(
            self,
            capture_generation: int,
            error_text: str,
        ) -> None:
            self._refresh_inflight = False
            if self._shutdown_event.is_set():
                return
            if int(capture_generation) != int(self._capture_generation):
                return
            self._last_error = str(error_text or "").strip()
            self._refresh_status_line()

        def _apply_summary_refresh_from_worker(
            self,
            capture_generation: int,
            rows: list[PacketSummary],
            error_text: str,
            pre_parse_size: int,
        ) -> None:
            try:
                self._apply_summary_refresh(
                    rows,
                    error_text,
                    pre_parse_size=int(pre_parse_size),
                    capture_generation=int(capture_generation),
                )
            except Exception as exc:
                self._refresh_inflight = False
                self._last_error = f"Summary UI refresh failed: {exc}"
                self._refresh_status_line()

        def _merge_polling_rows_with_live_tail(
            self,
            polling_rows: list[PacketSummary],
        ) -> list[PacketSummary]:
            polling_list = list(polling_rows)
            existing_rows = list(self._base_rows or [])
            if len(existing_rows) == 0:
                return polling_list
            polling_keys: set[tuple[str, str, str, str]] = set()
            for row in polling_list:
                try:
                    polling_keys.add(self._live_row_key(row))
                except Exception:
                    continue
            live_tail: list[PacketSummary] = []
            next_number = len(polling_list) + 1
            for row in existing_rows:
                try:
                    row_key = self._live_row_key(row)
                except Exception:
                    continue
                if row_key in polling_keys:
                    continue
                if int(row.number) != next_number:
                    renumbered = PacketSummary(
                        number=next_number,
                        time_text=row.time_text,
                        source=row.source,
                        destination=row.destination,
                        protocol=row.protocol,
                        length_text=row.length_text,
                        info=row.info,
                        wall_time_text=row.wall_time_text,
                        udp_payload_hex=row.udp_payload_hex,
                    )
                else:
                    renumbered = row
                live_tail.append(renumbered)
                polling_keys.add(row_key)
                next_number += 1
            if len(live_tail) == 0:
                return polling_list
            return polling_list + live_tail

        def _apply_summary_refresh(
            self,
            rows: list[PacketSummary],
            error_text: str,
            *,
            pre_parse_size: int | None = None,
            capture_generation: int | None = None,
        ) -> None:
            self._refresh_inflight = False
            if self._shutdown_event.is_set():
                return
            if capture_generation is not None and int(capture_generation) != int(self._capture_generation):
                return
            if self._ingest_paused:
                # Worker completed inside a pause window (started just
                # before the user hit F2). Discard the parsed rows; the
                # on-resume refresh will re-parse the updated pcap.
                return
            if pre_parse_size is None:
                current_size = _file_size(self._capture_path)
            else:
                current_size = int(pre_parse_size)
            if 0 <= current_size < self._last_capture_size:
                self._base_rows = []
                self._rows = []
                self._state_annotations = {}
                self._summary_tree_frame_nodes = {}
                self._summary_tree_header_nodes = {}
                self._selected_frame_number = None
                self._displayed_selected_frame_number = None
                self._highlighted_node_key = None
                self._latest_capture_time_seconds = None
                self._latest_capture_monotonic = None
                self._summary_tree_expanded_groups = set()
                self._detail_cache.clear()
                self._bytes_cache.clear()
                self._paused_live_rows = []
                self._paused_queue_dropped = 0
                self._paused_queue_high_water_mark = 0
                self._paused_queue_protocol_counts = {}
                self._auto_pause_hint_samples = []
            self._last_capture_size = current_size
            self._last_error = str(error_text or "").strip()
            previous_selected = self._selected_frame_number
            self._base_rows = self._merge_polling_rows_with_live_tail(rows)
            self._rebuild_state_annotations()
            previous_row_count = len(self._rows)
            self._rows = self._decorate_summary_rows(self._base_rows)
            if len(self._rows) == 0:
                self._latest_capture_time_seconds = None
                self._latest_capture_monotonic = None
                self._selected_frame_number = None
                self._rebuild_summary_view()
                self._set_detail_views(
                    "Waiting for packet selection before loading decoded fields.",
                    "Waiting for packet selection before loading the byte view.",
                )
                self._refresh_captions()
                self._refresh_status_line()
                self._seed_live_stream_from_base_rows()
                return
            if previous_selected is None and self._selected_frame_number is None:
                self._selected_frame_number = int(self._rows[-1].number)
            elif previous_selected is not None:
                if any(int(row.number) == int(previous_selected) for row in self._rows):
                    self._selected_frame_number = int(previous_selected)
                else:
                    self._selected_frame_number = int(self._rows[-1].number)
            del previous_row_count
            latest_state = self._latest_state_annotation()
            if latest_state is not None and latest_state.capture_time_seconds is not None:
                self._latest_capture_time_seconds = float(latest_state.capture_time_seconds)
                self._latest_capture_monotonic = time.monotonic()
            else:
                self._latest_capture_time_seconds = None
                self._latest_capture_monotonic = None
            self._refresh_summary_tree_visual(scroll=self._follow_tail)
            self._refresh_captions()
            self._schedule_detail_refresh()
            self._refresh_status_line()
            self._last_parse_completed_monotonic = time.monotonic()
            self._last_parse_row_count = len(self._rows)
            self._seed_live_stream_from_base_rows()

        def _tick_status_refresh(self) -> None:
            if self._shutdown_event.is_set():
                return
            try:
                self._flush_pending_summary_tree_rebuild()
            except Exception:
                pass
            try:
                self._refresh_status_line()
                self._refresh_captions()
            except Exception:
                pass

        def _resolve_live_stream_fifo_path(self) -> str:
            # Offline-review mode must never synthesise a sidecar FIFO
            # next to an archived pcap. Skipping here also keeps the
            # status line honest about why no live stream is running.
            if self._live_capture_mode is False:
                return ""
            configured_path = str(self._mirror_fifo_path or "").strip()
            if len(configured_path) > 0:
                return configured_path
            capture_path_text = str(self._capture_path or "").strip()
            if len(capture_path_text) == 0:
                return ""
            return str(Path(capture_path_text).expanduser().with_suffix(".fifo"))

        def _ensure_live_stream_started(self) -> None:
            if self._shutdown_event.is_set():
                return
            if self._live_stream_started:
                return
            if self._live_stream_disabled:
                return
            if self._live_capture_mode is False:
                self._live_stream_disabled = True
                self._live_stream_disabled_reason = (
                    "offline review (no live capture)"
                )
                return
            now = time.monotonic()
            if now < self._live_stream_start_deadline:
                return
            fifo_path = self._resolve_live_stream_fifo_path()
            if len(fifo_path) == 0:
                self._live_stream_start_deadline = now + 1.0
                return
            try:
                from Tools.HilBridge.live_tshark_stream import (
                    LiveTsharkStream,
                    LiveTsharkStreamOptions,
                )
            except Exception as exc:
                self._live_stream_disabled = True
                self._live_stream_disabled_reason = f"import failed: {exc}"
                return
            stream = LiveTsharkStream(
                LiveTsharkStreamOptions(
                    fifo_path=fifo_path,
                    tshark_binary=self._tshark_binary or "tshark",
                    decode_rule=self._decode_rule,
                )
            )
            try:
                started = stream.start()
            except Exception as exc:
                self._live_stream_start_deadline = now + 2.0
                self._live_stream_disabled_reason = f"start raised: {exc}"
                return
            if started is False:
                self._live_stream_start_deadline = now + 2.0
                self._live_stream_disabled_reason = (
                    stream.error_text() or "tshark live start returned False"
                )
                return
            self._live_stream = stream
            self._live_stream_started = True
            self._live_stream_disabled_reason = ""

        def _stop_live_stream(self) -> None:
            stream = self._live_stream
            if stream is None:
                self._live_stream_started = False
                return
            self._live_stream = None
            self._live_stream_started = False
            try:
                stream.stop(timeout=1.0)
            except Exception:
                pass
            if self._shutdown_event.is_set() is False:
                self._live_stream_start_deadline = time.monotonic() + 2.0

        def _live_row_key(
            self,
            row: PacketSummary,
        ) -> tuple[str, str, str, str]:
            primary_time = str(row.epoch_time_text or "").strip()
            if len(primary_time) == 0:
                primary_time = str(row.wall_time_text or "").strip()
            if len(primary_time) == 0:
                primary_time = str(row.time_text or "").strip()
            return (
                primary_time,
                str(row.length_text or ""),
                str(row.info or ""),
                str(row.udp_payload_hex or ""),
            )

        def _seed_live_stream_from_base_rows(self) -> None:
            if self._live_stream is None:
                return
            self._live_seen_keys = {self._live_row_key(row) for row in self._base_rows}
            if len(self._base_rows) > 0:
                highest_number = max(int(row.number) for row in self._base_rows)
                self._live_next_frame_number = highest_number + 1
            else:
                self._live_next_frame_number = 1

        def _drain_live_stream_tick(self) -> None:
            if self._shutdown_event.is_set():
                return
            stream = self._live_stream
            if stream is None:
                return
            if stream.is_alive() is False:
                self._stop_live_stream()
                return
            try:
                drained_rows = stream.drain()
            except Exception:
                drained_rows = []
            if len(drained_rows) == 0:
                return
            newly_added: list[PacketSummary] = []
            for row in drained_rows:
                key = self._live_row_key(row)
                if key in self._live_seen_keys:
                    continue
                self._live_seen_keys.add(key)
                normalized_number = int(self._live_next_frame_number)
                self._live_next_frame_number = normalized_number + 1
                if int(row.number) != normalized_number:
                    remapped = PacketSummary(
                        number=normalized_number,
                        time_text=row.time_text,
                        source=row.source,
                        destination=row.destination,
                        protocol=row.protocol,
                        length_text=row.length_text,
                        info=row.info,
                        wall_time_text=row.wall_time_text,
                        udp_payload_hex=row.udp_payload_hex,
                    )
                else:
                    remapped = row
                newly_added.append(remapped)
            if len(newly_added) == 0:
                return
            now_monotonic = time.monotonic()
            self._live_stream_last_rx_monotonic = now_monotonic
            self._record_ingest_rate_sample(now_monotonic, len(newly_added))
            if self._ingest_paused:
                # Keep draining the FIFO so tshark isn't blocked writing
                # into a full pipe, but divert the rows into the pause
                # queue instead of touching _base_rows / state / tree.
                # _live_stream_delivered_count is intentionally left
                # alone so the status line separates "queued while
                # paused" from "delivered to view". The caption badge
                # is updated by the periodic status tick so we do not
                # thrash the DOM for every FIFO batch while paused.
                for row in newly_added:
                    self._enqueue_paused_row(row)
                self._refresh_status_line()
                return
            self._maybe_emit_auto_pause_hint()
            self._live_stream_delivered_count += len(newly_added)
            self._apply_live_stream_additions(newly_added)

        def _enqueue_paused_row(self, row) -> None:
            # Enforces the hard cap on the pause queue so an unattended
            # long pause can't OOM the process. Drops oldest-first (FIFO
            # semantics) and bumps the drop counter so the operator can
            # see queue overflow in both the status line and the paused
            # badge.
            hard_cap = int(self._paused_queue_cap or 0)
            if hard_cap <= 0:
                hard_cap = _PAUSED_QUEUE_HARD_CAP_DEFAULT
            while len(self._paused_live_rows) >= hard_cap:
                dropped_row = self._paused_live_rows.pop(0)
                self._paused_queue_dropped += 1
                dropped_bucket = _classify_queued_row_bucket(dropped_row)
                current_count = int(
                    self._paused_queue_protocol_counts.get(dropped_bucket, 0)
                )
                if current_count <= 1:
                    self._paused_queue_protocol_counts.pop(dropped_bucket, None)
                else:
                    self._paused_queue_protocol_counts[dropped_bucket] = current_count - 1
            self._paused_live_rows.append(row)
            current_size = len(self._paused_live_rows)
            if current_size > int(self._paused_queue_high_water_mark):
                self._paused_queue_high_water_mark = current_size
            bucket_label = _classify_queued_row_bucket(row)
            previous = int(self._paused_queue_protocol_counts.get(bucket_label, 0))
            self._paused_queue_protocol_counts[bucket_label] = previous + 1

        def _record_ingest_rate_sample(self, now_monotonic: float, sample_count: int) -> None:
            if sample_count <= 0:
                return
            window_seconds = float(_AUTO_PAUSE_HINT_WINDOW_SECONDS)
            cutoff = float(now_monotonic) - max(1.0, window_seconds * 2.0)
            self._auto_pause_hint_samples.append((float(now_monotonic), int(sample_count)))
            self._auto_pause_hint_samples = [
                sample for sample in self._auto_pause_hint_samples if sample[0] >= cutoff
            ]

        def _maybe_emit_auto_pause_hint(self) -> None:
            if self._ingest_paused:
                return
            samples = list(self._auto_pause_hint_samples)
            if len(samples) == 0:
                return
            window_seconds = float(_AUTO_PAUSE_HINT_WINDOW_SECONDS)
            if window_seconds <= 0.0:
                return
            now_monotonic = time.monotonic()
            active_samples = [
                sample for sample in samples if sample[0] >= now_monotonic - window_seconds
            ]
            if len(active_samples) == 0:
                return
            oldest_ts = float(active_samples[0][0])
            span_seconds = max(0.001, now_monotonic - oldest_ts)
            total_packets = sum(int(count) for _, count in active_samples)
            if span_seconds < min(1.0, window_seconds * 0.5):
                return
            rate_per_second = float(total_packets) / float(span_seconds)
            if rate_per_second < float(_AUTO_PAUSE_HINT_RATE_THRESHOLD):
                return
            last_emitted = self._auto_pause_hint_last_emitted_monotonic
            cooldown_seconds = float(_AUTO_PAUSE_HINT_COOLDOWN_SECONDS)
            if (
                last_emitted is not None
                and cooldown_seconds > 0.0
                and (now_monotonic - float(last_emitted)) < cooldown_seconds
            ):
                return
            self._auto_pause_hint_last_emitted_monotonic = now_monotonic
            try:
                self._refresh_status_line(
                    message=(
                        f"High ingest rate ({rate_per_second:.0f} pkt/s). "
                        "Press F2 to pause or Ctrl+F2 to pause and discard on resume."
                    ),
                    error=False,
                )
            except Exception:
                pass

        def _apply_live_stream_additions(
            self,
            new_rows: list[PacketSummary],
        ) -> None:
            if len(new_rows) == 0:
                return
            self._base_rows = list(self._base_rows) + list(new_rows)
            self._rebuild_state_annotations()
            self._rows = self._decorate_summary_rows(self._base_rows)
            if self._selected_frame_number is None and len(self._rows) > 0:
                self._selected_frame_number = int(self._rows[-1].number)
            latest_state = self._latest_state_annotation()
            if latest_state is not None and latest_state.capture_time_seconds is not None:
                self._latest_capture_time_seconds = float(latest_state.capture_time_seconds)
                self._latest_capture_monotonic = time.monotonic()
            self._refresh_summary_tree_visual(scroll=self._follow_tail)
            self._refresh_captions()
            self._refresh_status_line()
            self._schedule_detail_refresh()

        def _rebuild_summary_view(self) -> None:
            # Ignore transient highlight callbacks while repopulating the tree.
            preserved_expanded_groups = set(self._summary_tree_expanded_groups)
            self._summary_tree_sync_inflight = True
            try:
                tree_widget = self._summary_widget()
                self._summary_tree_frame_nodes = _populate_summary_tree(
                    tree_widget,
                    self._base_rows,
                    self._state_annotations,
                    view_mode=self._summary_view_mode,
                    selected_frame_number=self._selected_frame_number,
                    expanded_group_names=preserved_expanded_groups,
                    palette=self._active_palette(),
                    show_expert_details=self._show_expert_detail_lines,
                )
                self._summary_tree_header_nodes = _collect_summary_tree_header_nodes(
                    tree_widget
                )
                self._summary_tree_expanded_groups = preserved_expanded_groups
            finally:
                self._summary_tree_sync_inflight = False

        def _refresh_summary_tree_visual(self, *, scroll: bool, force: bool = False) -> None:
            self._request_summary_tree_rebuild(scroll=scroll, force=force)

        def _request_summary_tree_rebuild(self, *, scroll: bool, force: bool = False) -> None:
            now = time.monotonic()
            throttle_window = float(self._summary_rebuild_throttle_seconds or 0.0)
            if (
                force is False
                and throttle_window > 0.0
                and self._last_summary_rebuild_monotonic > 0.0
                and (now - self._last_summary_rebuild_monotonic) < throttle_window
            ):
                self._summary_rebuild_pending = True
                if bool(scroll):
                    self._summary_rebuild_pending_scroll = True
                return
            self._summary_rebuild_pending = False
            self._summary_rebuild_pending_scroll = False
            self._last_summary_rebuild_monotonic = now
            self._render_summary_tree_now(scroll=scroll)

        def _flush_pending_summary_tree_rebuild(self) -> None:
            if self._summary_rebuild_pending is False:
                return
            now = time.monotonic()
            throttle_window = float(self._summary_rebuild_throttle_seconds or 0.0)
            if (
                throttle_window > 0.0
                and self._last_summary_rebuild_monotonic > 0.0
                and (now - self._last_summary_rebuild_monotonic) < throttle_window
            ):
                return
            scroll_request = bool(self._summary_rebuild_pending_scroll)
            self._summary_rebuild_pending = False
            self._summary_rebuild_pending_scroll = False
            self._last_summary_rebuild_monotonic = now
            self._render_summary_tree_now(scroll=scroll_request)

        def _render_summary_tree_now(self, *, scroll: bool) -> None:
            tree_widget = self._summary_widget()
            preserved_scroll_offset: tuple[float, float] | None = (
                _capture_summary_tree_scroll_offset(tree_widget)
            )
            selection_target_changed = (
                self._selected_frame_number != self._displayed_selected_frame_number
            )
            with _summary_tree_batch_update_context(tree_widget):
                self._rebuild_summary_view()
                self._sync_summary_selection(
                    scroll=selection_target_changed,
                    selection_target_changed=selection_target_changed,
                )
            if bool(scroll):
                self._scroll_summary_tree_to_tail(tree_widget)
            elif selection_target_changed is False:
                _restore_summary_tree_scroll_offset(tree_widget, preserved_scroll_offset)
            self._displayed_selected_frame_number = self._selected_frame_number

        def _scroll_summary_tree_to_tail(self, tree_widget) -> None:
            if len(self._rows) == 0:
                return
            tail_frame_number = int(self._rows[-1].number)
            tail_node = self._summary_tree_frame_nodes.get(tail_frame_number)
            if tail_node is None:
                return
            scroll_to_node = getattr(tree_widget, "scroll_to_node", None)
            if callable(scroll_to_node) is False:
                return
            try:
                scroll_to_node(tail_node, animate=False)
            except TypeError:
                try:
                    scroll_to_node(tail_node)
                except Exception:
                    return
            except Exception:
                return

        def _sync_summary_selection(
            self,
            *,
            scroll: bool,
            selection_target_changed: bool = True,
        ) -> None:
            expected_generation = int(self._capture_generation)
            expected_selected_frame = self._selected_frame_number
            expected_node_key = self._highlighted_node_key
            should_scroll_to_cursor = bool(scroll) or bool(selection_target_changed)

            def _apply_cursor_sync() -> bool:
                # When the user's last navigation target was a header
                # node (Poll / Channel Session / Card Session wrapper /
                # group), pin the cursor to that node by its stable
                # expand_key. The frame-number path only runs when no
                # header key is active or when the header can no longer
                # be resolved in the freshly rebuilt tree.
                if self._highlighted_node_key is not None:
                    header_moved = _move_summary_cursor_to_node_key(
                        self._summary_widget(),
                        self._summary_tree_header_nodes,
                        self._highlighted_node_key,
                        should_scroll=should_scroll_to_cursor,
                    )
                    if header_moved is True:
                        return True
                return _move_summary_selection_cursor(
                    self._summary_widget(),
                    self._summary_tree_frame_nodes,
                    self._selected_frame_number,
                    self._summary_tree_expanded_groups,
                    should_scroll=should_scroll_to_cursor,
                )

            self._summary_tree_sync_inflight = True
            try:
                moved = _apply_cursor_sync()
            finally:
                self._summary_tree_sync_inflight = False
            if moved is False:
                return
            if bool(scroll):
                return

            def _reapply_cursor_sync_after_refresh() -> None:
                if self._shutdown_event.is_set():
                    return
                if int(self._capture_generation) != expected_generation:
                    return
                if self._selected_frame_number != expected_selected_frame:
                    return
                if self._highlighted_node_key != expected_node_key:
                    return
                self._summary_tree_sync_inflight = True
                try:
                    _apply_cursor_sync()
                finally:
                    self._summary_tree_sync_inflight = False

            self.call_after_refresh(_reapply_cursor_sync_after_refresh)

        def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
            if event.control.id != "summary_tree":
                return
            if self._summary_tree_sync_inflight:
                return
            frame_number = _summary_highlighted_frame_number(event.control, event.node)
            if frame_number is None:
                # Non-frame node (Poll / Session / Group / Card Session
                # wrapper). Persist the expand_key so the next throttled
                # rebuild can reposition the cursor on the exact same
                # header instead of letting Textual drop it back to the
                # first visible row. Do not touch _selected_frame_number
                # here so the detail / bytes panes keep showing the last
                # real frame the user inspected.
                node_key = _summary_highlighted_node_key(event.control, event.node)
                if node_key is not None:
                    self._highlighted_node_key = node_key
                    self._refresh_captions()
                    self._refresh_status_line()
                return
            self._selected_frame_number = frame_number
            self._highlighted_node_key = None
            if len(self._rows) > 0 and frame_number == int(self._rows[-1].number):
                self._follow_tail = True
            else:
                self._follow_tail = False
            self._schedule_detail_refresh()
            self._refresh_captions()
            self._refresh_status_line()

        def on_tree_node_expanded(self, event: Tree.NodeExpanded) -> None:
            if event.control.id != "summary_tree":
                return
            _apply_summary_tree_expand_state_change(
                self._summary_tree_expanded_groups,
                getattr(event.node, "data", None),
                expanded=True,
                sync_inflight=self._summary_tree_sync_inflight,
            )

        def on_tree_node_collapsed(self, event: Tree.NodeCollapsed) -> None:
            if event.control.id != "summary_tree":
                return
            _apply_summary_tree_expand_state_change(
                self._summary_tree_expanded_groups,
                getattr(event.node, "data", None),
                expanded=False,
                sync_inflight=self._summary_tree_sync_inflight,
            )

        def _schedule_detail_refresh(self) -> None:
            frame_number = self._selected_frame_number
            self._requested_detail_frame = frame_number
            if frame_number is None:
                self._set_detail_views(
                    "Waiting for packet selection before loading decoded fields.",
                    "Waiting for packet selection before loading the byte view.",
                )
                return
            cached_detail = self._detail_cache.get(frame_number)
            cached_bytes = self._bytes_cache.get(frame_number)
            if cached_detail is not None and cached_bytes is not None:
                self._set_detail_views(cached_detail, cached_bytes)
                return
            self._set_detail_views("Loading decoded fields...", "Loading byte view...")
            if self._detail_inflight:
                return
            self._detail_inflight = True
            worker = threading.Thread(
                target=self._detail_refresh_worker,
                args=(self._capture_generation, self._capture_path, frame_number),
                daemon=True,
            )
            worker.start()

        def _detail_refresh_worker(self, capture_generation: int, capture_path_text: str, frame_number: int) -> None:
            detail_text, detail_error = read_packet_detail(
                capture_path_text,
                frame_number,
                tshark_binary=self._tshark_binary,
                decode_rule=self._decode_rule,
            )
            bytes_text, bytes_error = read_packet_hex(
                capture_path_text,
                frame_number,
                tshark_binary=self._tshark_binary,
                decode_rule=self._decode_rule,
            )
            try:
                self.call_from_thread(
                    self._apply_detail_refresh,
                    int(capture_generation),
                    int(frame_number),
                    str(detail_text or ""),
                    str(bytes_text or ""),
                    str(detail_error or "").strip(),
                    str(bytes_error or "").strip(),
                )
            except Exception:
                self._detail_inflight = False
                return

        def _apply_detail_refresh(
            self,
            capture_generation: int,
            frame_number: int,
            detail_text: str,
            bytes_text: str,
            detail_error: str,
            bytes_error: str,
        ) -> None:
            self._detail_inflight = False
            if self._shutdown_event.is_set():
                return
            if int(capture_generation) != int(self._capture_generation):
                return
            normalized_detail = str(detail_text or "")
            normalized_bytes = str(bytes_text or "")
            if len(detail_error) > 0 and len(normalized_detail.strip()) == 0:
                normalized_detail = f"Decoded view load error: {detail_error}"
            if len(bytes_error) > 0 and len(normalized_bytes.strip()) == 0:
                normalized_bytes = f"Byte view load error: {bytes_error}"
            self._detail_cache[frame_number] = normalized_detail
            self._bytes_cache[frame_number] = normalized_bytes
            if self._selected_frame_number == frame_number:
                self._set_detail_views(normalized_detail, normalized_bytes)
            requested_frame = self._requested_detail_frame
            if requested_frame is None or requested_frame == frame_number:
                self._refresh_status_line()
                return
            cached_detail = self._detail_cache.get(requested_frame)
            cached_bytes = self._bytes_cache.get(requested_frame)
            if cached_detail is not None and cached_bytes is not None:
                if self._selected_frame_number == requested_frame:
                    self._set_detail_views(cached_detail, cached_bytes)
                self._refresh_status_line()
                return
            self._detail_inflight = True
            worker = threading.Thread(
                target=self._detail_refresh_worker,
                args=(self._capture_generation, self._capture_path, requested_frame),
                daemon=True,
            )
            worker.start()

        def _set_detail_views(self, detail_text: str, bytes_text: str) -> None:
            detail_view = self._detail_widget()
            bytes_view = self._bytes_widget()
            palette = self._active_palette()
            normalized_detail = _normalized_view_text(
                detail_text,
                "Waiting for packet selection before loading decoded fields.",
            )
            normalized_bytes = _normalized_view_text(
                bytes_text,
                "Waiting for packet selection before loading the byte view.",
            )
            context_lines = self._selected_state_context_lines()
            detail_key = (
                self._selected_frame_number,
                self._theme_name,
                normalized_detail,
                context_lines,
            )
            if self._displayed_detail_key != detail_key:
                _populate_detail_tree(
                    detail_view,
                    normalized_detail,
                    context_lines=context_lines,
                    palette=palette,
                    show_expert_details=True,
                )
                self._displayed_detail_key = detail_key
            bytes_key = (
                self._selected_frame_number,
                self._theme_name,
                normalized_bytes,
            )
            if self._displayed_bytes_key != bytes_key:
                _replace_log_contents(
                    bytes_view,
                    normalized_bytes,
                    lambda raw_line: _render_hex_rich_text(raw_line, palette),
                )
                self._displayed_bytes_key = bytes_key

    app = HilDecodeApp()
    try:
        app.run()
    finally:
        if previous_term is None:
            os.environ.pop("TERM", None)
        else:
            os.environ["TERM"] = previous_term
        if previous_colorterm is None:
            os.environ.pop("COLORTERM", None)
        else:
            os.environ["COLORTERM"] = previous_colorterm
