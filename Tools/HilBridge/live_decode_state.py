# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge live-decode state: accumulates captured APDU frames and maintains the decoded protocol tree for the TUI."""
from __future__ import annotations

from dataclasses import dataclass, replace
import ipaddress
import math
import re

from SIMCARD.utils import read_tlv
from Tools.HilBridge.live_decode_view import PacketSummary
from Tools.HilBridge.protocol import GSMTAP_SIM_APDU, GSMTAP_TYPE_SIM
from Tools.HilBridge.scp_replay import (
    ScpReplayEngine,
    SECURE_MESSAGING_CLA_BIT,
    UnwrapContext,
)

FETCH_INS = 0x12
TERMINAL_RESPONSE_INS = 0x14
SELECT_INS = 0xA4
READ_BINARY_INS = 0xB0
READ_RECORD_INS = 0xB2
ENVELOPE_INS = 0xC2
GET_RESPONSE_INS = 0xC0
UPDATE_BINARY_INS = 0xD6
UPDATE_RECORD_INS = 0xDC
STATUS_INS = 0xF2

OPEN_CHANNEL_COMMAND = 0x40
CLOSE_CHANNEL_COMMAND = 0x41
RECEIVE_DATA_COMMAND = 0x42
SEND_DATA_COMMAND = 0x43
GET_CHANNEL_STATUS_COMMAND = 0x44
TIMER_MANAGEMENT_COMMAND = 0x27
POLL_INTERVAL_COMMAND = 0x03
POLL_OFF_COMMAND = 0x04

_POLL_INTERVAL_TIMER_ID = 0

_PROACTIVE_COMMAND_NAMES = {
    OPEN_CHANNEL_COMMAND: "OPEN CHANNEL",
    CLOSE_CHANNEL_COMMAND: "CLOSE CHANNEL",
    RECEIVE_DATA_COMMAND: "RECEIVE DATA",
    SEND_DATA_COMMAND: "SEND DATA",
    GET_CHANNEL_STATUS_COMMAND: "GET CHANNEL STATUS",
    TIMER_MANAGEMENT_COMMAND: "TIMER MANAGEMENT",
    0x05: "SET UP EVENT LIST",
    POLL_INTERVAL_COMMAND: "POLL INTERVAL",
    POLL_OFF_COMMAND: "POLL OFF",
    0x01: "REFRESH",
    0x02: "MORE TIME",
    0x26: "PROVIDE LOCAL INFORMATION",
}

_EVENT_NAMES = {
    0x03: "LOCATION STATUS",
    0x09: "DATA AVAILABLE",
    0x0A: "CHANNEL STATUS",
    0x0B: "ACCESS TECHNOLOGY CHANGE",
    0x0F: "NETWORK SEARCH MODE CHANGE",
}

_KNOWN_FILE_PATHS = {
    "3F00": ("MF",),
    "2F00": ("MF", "EF.DIR"),
    "2FE2": ("MF", "EF.ICCID"),
    "7F10": ("MF", "DF.TELECOM"),
    "7F20": ("MF", "DF.GSM"),
    "7FF0": ("MF", "ADF.USIM"),
    "6F07": ("MF", "ADF.USIM", "EF.IMSI"),
    "6FAD": ("MF", "ADF.USIM", "EF.AD"),
    "7FF2": ("MF", "ADF.ISIM"),
    "6F02": ("MF", "ADF.ISIM", "EF.IMPI"),
}

_KNOWN_AID_PATHS = {
    "A0000000871002FF86FF112233445566": ("MF", "ADF.USIM"),
    "A0000000871004FF86FF112233445566": ("MF", "ADF.ISIM"),
    "A0000005591010FFFFFFFF8900000100": ("MF", "ISD-R"),
    "A0000005591010FFFFFFFF8900000200": ("MF", "ECASD"),
    "A000000151000000": ("MF", "MNO-SD"),
}


@dataclass(frozen=True, slots=True)
class ParsedApduExchange:
    command: bytes
    response: bytes
    ins: int
    response_data: bytes
    sw1: int
    sw2: int


@dataclass(frozen=True, slots=True)
class StatefulFrameAnnotation:
    frame_number: int
    summary_suffix: str = ""
    context_lines: tuple[str, ...] = ()
    active_channel_count: int = 0
    active_timer_count: int = 0
    active_timers: tuple["ActiveTimerSnapshot", ...] = ()
    capture_time_seconds: float | None = None
    channel_session_id: int | None = None
    channel_number: int | None = None
    channel_poll_index: int | None = None
    state_event: bool = False
    trace_group: str = ""
    trace_label: str = ""
    trace_operation: str = ""
    trace_path: str = ""
    trace_status: str = ""
    trace_parent_frame: int | None = None
    trace_related_frames: tuple[int, ...] = ()
    trace_reason: str = ""
    # card_session_index tags every frame with a monotonically increasing
    # session ordinal. Each detected card reset (REFRESH proactive command
    # with a reset qualifier, or a long idle gap suggesting a reboot)
    # starts a new session, so pre- and post-reboot traffic can be
    # rendered under separate top-level nodes in the TUI.
    card_session_index: int = 1
    # card_session_reset_reason is populated on the single frame that
    # triggers a session bump, so the TUI can render a small caption
    # ("REFRESH UICC Reset", "idle 32s", etc.) next to the new session.
    card_session_reset_reason: str = ""
    # card_session_iccid is backfilled by `finalize_annotations` on every
    # frame that belongs to a session whose EF.ICCID has been read at
    # least once. Empty string means "not yet observed in this session".
    card_session_iccid: str = ""


@dataclass(frozen=True, slots=True)
class ActiveTimerSnapshot:
    timer_id: int
    configured_seconds: int
    remaining_seconds: int
    display_label: str = ""


@dataclass(slots=True)
class _ChannelSessionState:
    session_id: int
    protocol: str
    endpoint: str
    network_access_name: str = ""
    channel_number: int | None = None
    poll_index: int | None = None
    status: str = "pending-open"
    open_request_frame: int | None = None
    open_response_frame: int | None = None
    close_frame: int | None = None
    last_send_frame: int | None = None
    last_receive_frame: int | None = None
    last_event_frame: int | None = None
    last_send_summary: str = ""
    last_receive_summary: str = ""
    poll_count: int = 0
    current_poll_index: int | None = None


@dataclass(slots=True)
class _TimerState:
    timer_id: int
    active: bool = False
    value_seconds: int = 0
    observed_remaining_seconds: int = 0
    observed_at_seconds: float | None = None
    start_frame: int | None = None
    query_frame: int | None = None
    stop_frame: int | None = None
    expiration_frame: int | None = None
    last_qualifier: int = 0
    display_label: str = ""
    auto_expire: bool = False


@dataclass(slots=True)
class _PendingProactiveState:
    command_type: int
    qualifier: int
    frame_number: int
    session_id: int | None = None
    poll_index: int | None = None
    timer_id: int | None = None


@dataclass(frozen=True, slots=True)
class _FileTraceEvent:
    frame_number: int
    operation_text: str
    path_text: str
    status: str


def annotate_packet_summary(row: PacketSummary, annotation: StatefulFrameAnnotation | None) -> PacketSummary:
    """Annotate a single packet summary line with decoded APDU or ATR information."""
    if annotation is None:
        return row
    suffix = str(annotation.summary_suffix or "").strip()
    if len(suffix) == 0:
        return row
    base_info = str(row.info or "").strip()
    if len(base_info) == 0:
        updated_info = suffix
    else:
        updated_info = f"{base_info} | {suffix}"
    return replace(row, info=updated_info)


def build_stateful_packet_annotations(
    rows: list[PacketSummary],
    *,
    replay_engine: ScpReplayEngine | None = None,
) -> dict[int, StatefulFrameAnnotation]:
    """Process a batch of packet summaries and return stateful decoded annotations."""
    tracker = LiveDecodeStateTracker(replay_engine=replay_engine)
    annotations: dict[int, StatefulFrameAnnotation] = {}
    ordered_rows = sorted(rows, key=lambda row: int(row.number))
    for row in ordered_rows:
        annotations[int(row.number)] = tracker.consume_row(row)
    return tracker.finalize_annotations(annotations)


_REFRESH_PROACTIVE_COMMAND = 0x01
# REFRESH qualifier values per ETSI TS 102 223 §6.6.1 that imply the
# UICC/NAA was reset. The TUI treats any of these as a session boundary.
# Qualifier 0x01 "File Change Notification" is intentionally excluded
# because it does not reset the card.
_REFRESH_RESET_QUALIFIERS: frozenset[int] = frozenset(
    {0x00, 0x02, 0x03, 0x04, 0x05, 0x06}
)
_REFRESH_QUALIFIER_NAMES: dict[int, str] = {
    0x00: "NAA Initialization and Full File Change Notification",
    0x01: "File Change Notification",
    0x02: "NAA Initialization and File Change Notification",
    0x03: "NAA Initialization",
    0x04: "UICC Reset",
    0x05: "NAA Application Reset",
    0x06: "NAA Session Reset",
    0x07: "Steering of Roaming",
}
# An idle gap in the capture (no APDU exchanges) longer than this many
# seconds is treated as evidence of a card power-cycle / re-read, and the
# next observed frame opens a new card session. 30 s is aggressive enough
# to catch a deliberate reboot while staying well clear of normal poll
# cadences (5-15 s on the live traces we've seen).
_CARD_SESSION_IDLE_GAP_SECONDS = 30.0
_MAX_FILE_TRACE_EVENTS = 12


class LiveDecodeStateTracker:
    def __init__(
        self,
        *,
        replay_engine: ScpReplayEngine | None = None,
    ) -> None:
        self._replay_engine = replay_engine
        # Last AID seen on a successful SELECT-by-AID. Used by the replay
        # engine to pick the right keybag entry when multiple sessions share
        # the same `card_session_index` but talk to different applets.
        self._current_aid_hex: str = ""
        self._next_session_id = 1
        self._sessions: dict[int, _ChannelSessionState] = {}
        self._channel_occurrence_by_number: dict[int, int] = {}
        self._timers: dict[int, _TimerState] = {}
        self._active_session_id: int | None = None
        self._pending_session_id: int | None = None
        self._pending_proactive: _PendingProactiveState | None = None
        self._current_file_path: tuple[str, ...] = ("MF",)
        self._current_file_kind = "mf"
        self._recent_file_operations: list[str] = []
        self._recent_file_trace_events: list[_FileTraceEvent] = []
        # Card-session tracking. The counter starts at 1; every detected
        # reset increments it. `_pending_card_session_bump_reason` is set
        # when we need the *next* frame to open a new session (the REFRESH
        # TERMINAL RESPONSE itself still belongs to the closing session).
        self._card_session_index: int = 1
        self._pending_card_session_bump_reason: str = ""
        # `_card_session_frame_starts` maps each session index to the
        # first frame number that landed in it; the TUI uses this to
        # label top-level session nodes when finalizing annotations.
        self._card_session_frame_starts: dict[int, int] = {1: 0}
        self._card_session_reset_reasons: dict[int, str] = {1: ""}
        # Each session keeps its own ICCID. The value is populated when
        # the terminal issues a successful READ BINARY on EF.ICCID while
        # that session is active; the new-session bump resets the slot.
        self._card_session_iccids: dict[int, str] = {1: ""}
        self._last_row_time_seconds: float | None = None

    def finalize_annotations(
        self,
        annotations: dict[int, StatefulFrameAnnotation],
    ) -> dict[int, StatefulFrameAnnotation]:
        """Complete any pending multi-packet decode state and return the final annotation list."""
        occurrence_by_channel: dict[int, int] = {}
        ordered_sessions = sorted(
            self._sessions.values(),
            key=lambda session: (
                int(session.open_request_frame or 0),
                int(session.session_id),
            ),
        )
        for session in ordered_sessions:
            effective_channel_number = self._effective_channel_number(session)
            occurrence_by_channel[effective_channel_number] = (
                occurrence_by_channel.get(effective_channel_number, 0) + 1
            )
            session.poll_index = int(occurrence_by_channel[effective_channel_number])
        finalized: dict[int, StatefulFrameAnnotation] = {}
        for frame_number, annotation in annotations.items():
            card_session_index = int(
                getattr(annotation, "card_session_index", 1) or 1
            )
            session_iccid = self._card_session_iccids.get(card_session_index, "")
            session_id = getattr(annotation, "channel_session_id", None)
            if session_id is None:
                finalized[int(frame_number)] = replace(
                    annotation,
                    card_session_iccid=str(session_iccid or ""),
                )
                continue
            session = self._sessions.get(int(session_id))
            if session is None:
                finalized[int(frame_number)] = replace(
                    annotation,
                    card_session_iccid=str(session_iccid or ""),
                )
                continue
            finalized[int(frame_number)] = replace(
                annotation,
                channel_number=self._effective_channel_number(session),
                channel_poll_index=session.poll_index,
                card_session_iccid=str(session_iccid or ""),
            )
        return finalized

    def card_session_index(self) -> int:
        return int(self._card_session_index)

    def card_session_frame_starts(self) -> dict[int, int]:
        # Shallow copy so callers cannot mutate internal state.
        return dict(self._card_session_frame_starts)

    def card_session_reset_reasons(self) -> dict[int, str]:
        return dict(self._card_session_reset_reasons)

    def card_session_iccids(self) -> dict[int, str]:
        return dict(self._card_session_iccids)

    def _queue_card_session_bump(self, reason: str) -> None:
        # The REFRESH exchange itself is still part of the closing
        # session. We only store the reason here; the counter is
        # actually incremented on the next frame that arrives.
        normalized_reason = str(reason or "").strip()
        if len(normalized_reason) == 0:
            return
        self._pending_card_session_bump_reason = normalized_reason

    def _apply_pending_card_session_bump(self, frame_number: int) -> str:
        if len(self._pending_card_session_bump_reason) == 0:
            return ""
        reason = self._pending_card_session_bump_reason
        self._pending_card_session_bump_reason = ""
        self._card_session_index = int(self._card_session_index) + 1
        self._card_session_frame_starts[self._card_session_index] = int(frame_number)
        self._card_session_reset_reasons[self._card_session_index] = reason
        self._card_session_iccids[self._card_session_index] = ""
        # A fresh card session cannot carry channel state across: the
        # card was reset, so any still-open BIP sessions are invalid.
        self._force_close_stale_sessions_on_card_reset()
        self._reset_file_trace_context()
        return reason

    def _detect_and_apply_idle_gap_bump(
        self,
        frame_number: int,
        frame_time_seconds: float | None,
    ) -> str:
        if frame_time_seconds is None:
            return ""
        last_seconds = self._last_row_time_seconds
        if last_seconds is None:
            return ""
        gap = float(frame_time_seconds) - float(last_seconds)
        if gap < _CARD_SESSION_IDLE_GAP_SECONDS:
            return ""
        reason = f"idle {int(gap)}s"
        self._card_session_index = int(self._card_session_index) + 1
        self._card_session_frame_starts[self._card_session_index] = int(frame_number)
        self._card_session_reset_reasons[self._card_session_index] = reason
        self._card_session_iccids[self._card_session_index] = ""
        self._force_close_stale_sessions_on_card_reset()
        self._reset_file_trace_context()
        return reason

    def _force_close_stale_sessions_on_card_reset(self) -> None:
        # After a card reset, no channel session can remain active.
        # Flag any pending/active sessions as "closed-on-reset" and clear
        # the current pointers so fresh OPEN CHANNEL traffic starts clean.
        for session in self._sessions.values():
            if session.status in ("pending-open", "active"):
                session.status = "closed-on-reset"
        self._active_session_id = None
        self._pending_session_id = None

    def _reset_file_trace_context(self) -> None:
        self._current_file_path = ("MF",)
        self._current_file_kind = "mf"
        self._recent_file_operations = []
        self._recent_file_trace_events = []

    def _trace_frames_from_meta(self, frame_meta: dict[str, object]) -> tuple[int, ...]:
        raw_frames = frame_meta.get("trace_related_frames", ())
        if isinstance(raw_frames, (list, tuple)) is False:
            return ()
        frames: list[int] = []
        seen: set[int] = set()
        for raw_frame in raw_frames:
            try:
                frame_number = int(raw_frame)
            except (TypeError, ValueError):
                continue
            if frame_number <= 0 or frame_number in seen:
                continue
            frames.append(frame_number)
            seen.add(frame_number)
        return tuple(frames)

    def channel_session_frame_ranges(self) -> list[tuple[int, int, int]]:
        # Expose the observed OPEN->CLOSE frame windows so higher layers
        # (the TUI, specifically) can fall back to range-based resolution
        # when a frame lacks an explicit channel-session tag. The tuple is
        # (start_frame, end_frame, session_id); end_frame is clamped to
        # the sentinel 2_000_000_000 when the session is still open.
        """Return a list of (start_frame, end_frame) pairs for each APDU session in the capture."""
        ranges: list[tuple[int, int, int]] = []
        for session in self._sessions.values():
            start_frame = session.open_request_frame
            if start_frame is None:
                continue
            end_frame = session.close_frame
            if end_frame is None:
                end_frame = 2_000_000_000
            ranges.append(
                (int(start_frame), int(end_frame), int(session.session_id))
            )
        ranges.sort(key=lambda entry: (entry[0], entry[2]))
        return ranges

    def _effective_channel_number(self, session: _ChannelSessionState) -> int:
        channel_number = getattr(session, "channel_number", None)
        if channel_number is not None:
            return int(channel_number)
        return int(session.session_id)

    def _assign_session_channel_number(self, session_id: int | None, channel_number: int | None) -> None:
        if session_id is None or channel_number is None:
            return
        session = self._sessions.get(int(session_id))
        if session is None:
            return
        if session.channel_number is None:
            self._channel_occurrence_by_number[int(channel_number)] = (
                self._channel_occurrence_by_number.get(int(channel_number), 0) + 1
            )
            if session.poll_index is None:
                session.poll_index = int(self._channel_occurrence_by_number[int(channel_number)])
        session.channel_number = int(channel_number)

    def consume_row(self, row: PacketSummary) -> StatefulFrameAnnotation:
        """Consume one summary row dict and advance the decode-state machine."""
        frame_number = int(row.number)
        frame_time_seconds = _parse_capture_time_seconds(row.time_text)
        self._row_time_seconds = frame_time_seconds
        # Apply any pending session bump (e.g. from a previous REFRESH
        # terminal response) *before* we classify the current frame, so
        # the first post-reset packet already belongs to the new session.
        frame_reset_reason = self._apply_pending_card_session_bump(frame_number)
        # Long idle gaps also signal a likely power-cycle / re-read. We
        # only trigger this on the frame *after* the silence, not on the
        # last frame of the previous session.
        gap_reset_reason = self._detect_and_apply_idle_gap_bump(
            frame_number, frame_time_seconds
        )
        if frame_reset_reason == "" and gap_reset_reason != "":
            frame_reset_reason = gap_reset_reason
        summary_parts: list[str] = []
        frame_lines: list[str] = []
        frame_meta: dict[str, object] = {"state_event": False}

        exchange = _parse_exchange_from_udp_payload_hex(row.udp_payload_hex)
        if exchange is not None:
            if exchange.ins == FETCH_INS:
                self._handle_fetch(frame_number, exchange, summary_parts, frame_lines, frame_meta)
            elif exchange.ins == TERMINAL_RESPONSE_INS:
                self._handle_terminal_response(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == SELECT_INS:
                self._handle_file_select(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == READ_BINARY_INS:
                self._handle_file_read_binary(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == READ_RECORD_INS:
                self._handle_file_read_record(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == ENVELOPE_INS:
                self._handle_envelope(frame_number, exchange, summary_parts, frame_lines, frame_meta)
            elif exchange.ins == GET_RESPONSE_INS:
                self._handle_file_get_response(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == UPDATE_BINARY_INS:
                self._handle_file_update_binary(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == UPDATE_RECORD_INS:
                self._handle_file_update_record(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            elif exchange.ins == STATUS_INS:
                self._handle_status(
                    frame_number,
                    exchange,
                    summary_parts,
                    frame_lines,
                    frame_meta,
                )
            self._try_scp_replay_unwrap(
                frame_number,
                exchange,
                summary_parts,
                frame_lines,
            )

        context_lines = tuple(self._build_context_lines(frame_lines, frame_time_seconds))
        channel_session_id = self._frame_channel_session_id(row, exchange, summary_parts)
        trace_parent_frame = frame_meta.get("trace_parent_frame")
        if not isinstance(trace_parent_frame, int):
            trace_parent_frame = None
        trace_related_frames = self._trace_frames_from_meta(frame_meta)
        # Record the frame's capture time so the next call can evaluate
        # the idle-gap heuristic; even FETCH-less packets update this.
        if frame_time_seconds is not None:
            self._last_row_time_seconds = float(frame_time_seconds)
        return StatefulFrameAnnotation(
            frame_number=frame_number,
            summary_suffix=" | ".join(summary_parts),
            context_lines=context_lines,
            active_channel_count=self._active_channel_count(),
            active_timer_count=self._active_timer_count(frame_time_seconds),
            active_timers=self._active_timer_snapshots(frame_time_seconds),
            capture_time_seconds=frame_time_seconds,
            channel_session_id=channel_session_id,
            state_event=bool(frame_meta.get("state_event", False)),
            trace_group=str(frame_meta.get("trace_group", "") or ""),
            trace_label=str(frame_meta.get("trace_label", "") or ""),
            trace_operation=str(frame_meta.get("trace_operation", "") or ""),
            trace_path=str(frame_meta.get("trace_path", "") or ""),
            trace_status=str(frame_meta.get("trace_status", "") or ""),
            trace_parent_frame=trace_parent_frame,
            trace_related_frames=trace_related_frames,
            trace_reason=str(frame_meta.get("trace_reason", "") or ""),
            card_session_index=int(self._card_session_index),
            card_session_reset_reason=str(frame_reset_reason or ""),
        )

    def _handle_fetch(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        command_type, qualifier, fields = _parse_proactive_command(exchange.response_data)
        if command_type is None:
            return
        frame_meta["state_event"] = True
        command_name = _proactive_command_name(command_type)
        summary_parts.append(f"STK {command_name}")

        pending_state = _PendingProactiveState(
            command_type=command_type,
            qualifier=qualifier,
            frame_number=frame_number,
        )

        if command_type == _REFRESH_PROACTIVE_COMMAND:
            # REFRESH is the clearest in-band signal of a card reset.
            # Capture the qualifier text so the next session's heading
            # can carry it (e.g. "Card Session 2 - REFRESH UICC Reset").
            # The actual bump is queued only after the terminal acks the
            # REFRESH successfully, so both the fetch and its response
            # stay in the closing session.
            qualifier_name = _REFRESH_QUALIFIER_NAMES.get(
                int(qualifier), f"qualifier 0x{int(qualifier):02X}"
            )
            summary_parts.append(f"REFRESH {qualifier_name}")
            frame_lines.append(
                f"REFRESH requested: {qualifier_name} (qualifier 0x{int(qualifier):02X})."
            )

        if command_type == OPEN_CHANNEL_COMMAND:
            self._force_close_stale_sessions_before_new_open(frame_number)
            session = self._allocate_channel_session(fields, frame_number)
            self._pending_session_id = session.session_id
            pending_state.session_id = session.session_id
            pending_state.poll_index = self._start_session_poll(session.session_id)
            frame_meta["channel_poll_index"] = pending_state.poll_index
            summary_target = (
                f"{_protocol_label(session.protocol)}://{session.endpoint}"
            )
            apn_suffix = ""
            if len(session.network_access_name) > 0:
                apn_suffix = f" APN:{session.network_access_name}"
            summary_parts.append(
                f"CH{session.session_id} OPEN {summary_target}{apn_suffix}"
            )
            frame_lines.append(
                f"OPEN CHANNEL requested for CH{session.session_id} -> {summary_target}"
            )
            if len(session.network_access_name) > 0:
                frame_lines.append(
                    f"  APN: {session.network_access_name}"
                )
        elif command_type == CLOSE_CHANNEL_COMMAND:
            session_id = self._current_session_id()
            pending_state.session_id = session_id
            if session_id is not None:
                session = self._sessions.get(session_id)
                if session is not None:
                    session.status = "closing"
                    session.close_frame = frame_number
                pending_state.poll_index = self._start_session_poll(session_id)
                frame_meta["channel_poll_index"] = pending_state.poll_index
            if session_id is None:
                summary_parts.append("CHANNEL close requested")
                frame_lines.append("CLOSE CHANNEL requested without a known active session.")
            else:
                summary_parts.append(f"CH{session_id} CLOSE")
                frame_lines.append(f"CLOSE CHANNEL requested for CH{session_id}.")
        elif command_type == SEND_DATA_COMMAND:
            session_id = self._current_session_id()
            pending_state.session_id = session_id
            if session_id is not None:
                pending_state.poll_index = self._start_session_poll(session_id)
                frame_meta["channel_poll_index"] = pending_state.poll_index
            payload = bytes(fields.get("channel_data", b"") or b"")
            payload_summaries = _summarize_channel_payload(payload)
            payload_summary_text = _compact_payload_summary(payload_summaries)
            if session_id is not None:
                session = self._sessions.get(session_id)
                if session is not None:
                    session.last_send_frame = frame_number
                    session.last_send_summary = payload_summary_text
            if session_id is None:
                summary_parts.append(f"SEND DATA {len(payload)}B")
                frame_lines.append(f"SEND DATA proactive command observed with {len(payload)} byte(s).")
            else:
                summary_parts.append(f"CH{session_id} SEND {len(payload)}B")
                frame_lines.append(
                    f"SEND DATA proactive command observed for CH{session_id} with {len(payload)} byte(s)."
                )
            if len(payload_summary_text) > 0:
                summary_parts.append(payload_summary_text)
                for payload_summary in payload_summaries:
                    frame_lines.append(f"Payload summary: {payload_summary}")
        elif command_type == RECEIVE_DATA_COMMAND:
            session_id = self._current_session_id()
            pending_state.session_id = session_id
            if session_id is not None:
                pending_state.poll_index = self._start_session_poll(session_id)
                frame_meta["channel_poll_index"] = pending_state.poll_index
            requested_length = int(fields.get("channel_data_length", 0) or 0)
            if session_id is None:
                summary_parts.append(f"RECEIVE DATA {requested_length}B")
                frame_lines.append(
                    f"RECEIVE DATA proactive command observed for {requested_length} byte(s)."
                )
            else:
                summary_parts.append(f"CH{session_id} RECEIVE {requested_length}B")
                frame_lines.append(
                    f"RECEIVE DATA proactive command observed for CH{session_id}, request {requested_length} byte(s)."
                )
        elif command_type == GET_CHANNEL_STATUS_COMMAND:
            session_id = self._current_session_id()
            pending_state.session_id = session_id
            if session_id is not None:
                pending_state.poll_index = self._start_session_poll(session_id)
                frame_meta["channel_poll_index"] = pending_state.poll_index
            if session_id is None:
                frame_lines.append("GET CHANNEL STATUS observed without a known session.")
            else:
                summary_parts.append(f"CH{session_id} STATUS")
                frame_lines.append(f"GET CHANNEL STATUS observed for CH{session_id}.")
        elif command_type == TIMER_MANAGEMENT_COMMAND:
            timer_id = _extract_timer_id(fields)
            pending_state.timer_id = timer_id
            timer_state = self._ensure_timer_state(timer_id)
            timer_state.last_qualifier = qualifier
            if qualifier == 0x00:
                timer_state.active = True
                timer_state.value_seconds = _decode_timer_value_seconds(
                    bytes(fields.get("timer_value", b"") or b"")
                )
                timer_state.observed_remaining_seconds = int(timer_state.value_seconds)
                timer_state.observed_at_seconds = self._current_row_time_seconds()
                timer_state.start_frame = frame_number
                timer_state.expiration_frame = None
                timer_state.stop_frame = None
                summary_parts.append(f"T{timer_id} START {timer_state.value_seconds}s")
                frame_lines.append(
                    f"TIMER MANAGEMENT start observed for timer {timer_id}, value {timer_state.value_seconds}s."
                )
            elif qualifier == 0x01:
                timer_state.query_frame = frame_number
                summary_parts.append(f"T{timer_id} QUERY")
                frame_lines.append(f"TIMER MANAGEMENT query observed for timer {timer_id}.")
            elif qualifier == 0x02:
                timer_state.active = False
                timer_state.observed_remaining_seconds = 0
                timer_state.observed_at_seconds = self._current_row_time_seconds()
                timer_state.stop_frame = frame_number
                summary_parts.append(f"T{timer_id} STOP")
                frame_lines.append(f"TIMER MANAGEMENT stop observed for timer {timer_id}.")
            else:
                summary_parts.append(f"T{timer_id} QUAL 0x{qualifier:02X}")
                frame_lines.append(
                    f"TIMER MANAGEMENT qualifier 0x{qualifier:02X} observed for timer {timer_id}."
                )
        elif command_type == POLL_INTERVAL_COMMAND:
            poll_interval_seconds = int(fields.get("duration_seconds", 0) or 0)
            pending_state.timer_id = _POLL_INTERVAL_TIMER_ID
            timer_state = self._ensure_timer_state(
                _POLL_INTERVAL_TIMER_ID,
                display_label="POLL",
                auto_expire=True,
            )
            timer_state.last_qualifier = qualifier
            if poll_interval_seconds > 0:
                timer_state.active = True
                timer_state.value_seconds = poll_interval_seconds
                timer_state.observed_remaining_seconds = poll_interval_seconds
                timer_state.observed_at_seconds = self._current_row_time_seconds()
                timer_state.start_frame = frame_number
                timer_state.query_frame = None
                timer_state.stop_frame = None
                timer_state.expiration_frame = None
                summary_parts.append(f"POLL INTERVAL {poll_interval_seconds}s")
                frame_lines.append(
                    f"POLL INTERVAL requested terminal polling every {poll_interval_seconds}s."
                )
            else:
                summary_parts.append("POLL INTERVAL")
                frame_lines.append(
                    "POLL INTERVAL proactive command observed without a valid duration."
                )
        elif command_type == POLL_OFF_COMMAND:
            pending_state.timer_id = _POLL_INTERVAL_TIMER_ID
            timer_state = self._ensure_timer_state(
                _POLL_INTERVAL_TIMER_ID,
                display_label="POLL",
                auto_expire=True,
            )
            timer_state.last_qualifier = qualifier
            timer_state.active = False
            timer_state.observed_remaining_seconds = 0
            timer_state.observed_at_seconds = self._current_row_time_seconds()
            timer_state.stop_frame = frame_number
            summary_parts.append("POLL OFF")
            frame_lines.append("POLL OFF disabled the active terminal polling cadence.")

        self._pending_proactive = pending_state

    def _handle_terminal_response(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        command_body = _extract_command_body(exchange.command)
        response_fields = _parse_terminal_response_body(command_body)
        pending_state = self._pending_proactive
        if pending_state is None:
            return
        frame_meta["state_event"] = True

        result_code = int(response_fields.get("result_code", 0x00) or 0x00)
        result_ok = _result_succeeded(result_code)

        if pending_state.command_type == OPEN_CHANNEL_COMMAND:
            session_id = pending_state.session_id
            frame_meta["channel_poll_index"] = pending_state.poll_index
            if session_id is not None:
                self._assign_session_channel_number(
                    session_id,
                    response_fields.get("channel_number"),
                )
                session = self._sessions.get(session_id)
                if session is not None:
                    session.open_response_frame = frame_number
                    if result_ok:
                        session.status = "active"
                        self._active_session_id = session_id
                        self._pending_session_id = None
                        summary_parts.append(f"CH{session_id} OPEN OK")
                        frame_lines.append(f"Terminal accepted OPEN CHANNEL for CH{session_id}.")
                    else:
                        session.status = "open-failed"
                        self._pending_session_id = None
                        summary_parts.append(f"CH{session_id} OPEN FAIL 0x{result_code:02X}")
                        frame_lines.append(
                            f"Terminal rejected OPEN CHANNEL for CH{session_id} with result 0x{result_code:02X}."
                        )
        elif pending_state.command_type == CLOSE_CHANNEL_COMMAND:
            session_id = pending_state.session_id
            frame_meta["channel_poll_index"] = pending_state.poll_index
            if session_id is None:
                summary_parts.append(f"CLOSE TR 0x{result_code:02X}")
            else:
                session = self._sessions.get(session_id)
                if session is not None and result_ok:
                    session.status = "closed"
                    session.close_frame = frame_number
                if self._active_session_id == session_id and result_ok:
                    self._active_session_id = None
                if self._pending_session_id == session_id:
                    self._pending_session_id = None
                if result_ok:
                    summary_parts.append(f"CH{session_id} CLOSED")
                    frame_lines.append(f"Terminal confirmed CLOSE CHANNEL for CH{session_id}.")
                else:
                    summary_parts.append(f"CH{session_id} CLOSE FAIL 0x{result_code:02X}")
                    frame_lines.append(
                        f"Terminal rejected CLOSE CHANNEL for CH{session_id} with result 0x{result_code:02X}."
                    )
        elif pending_state.command_type == SEND_DATA_COMMAND:
            session_id = pending_state.session_id
            frame_meta["channel_poll_index"] = pending_state.poll_index
            available_length = int(response_fields.get("channel_length", 0) or 0)
            if session_id is None:
                summary_parts.append(f"SEND TR 0x{result_code:02X}")
            else:
                if result_ok:
                    summary_parts.append(f"CH{session_id} SEND OK rem={available_length}")
                else:
                    summary_parts.append(f"CH{session_id} SEND FAIL 0x{result_code:02X}")
                frame_lines.append(
                    f"Terminal response for CH{session_id} SEND DATA carried result 0x{result_code:02X}."
                )
        elif pending_state.command_type == RECEIVE_DATA_COMMAND:
            session_id = pending_state.session_id
            frame_meta["channel_poll_index"] = pending_state.poll_index
            channel_data = bytes(response_fields.get("channel_data", b"") or b"")
            remaining_length = int(response_fields.get("channel_length", 0) or 0)
            payload_summaries = _summarize_channel_payload(channel_data)
            payload_summary_text = _compact_payload_summary(payload_summaries)
            if session_id is not None:
                session = self._sessions.get(session_id)
                if session is not None:
                    session.last_receive_frame = frame_number
                    session.last_receive_summary = payload_summary_text
            if session_id is None:
                summary_parts.append(f"RECEIVE TR {len(channel_data)}B rem={remaining_length}")
                frame_lines.append(
                    f"Terminal returned {len(channel_data)} byte(s) for RECEIVE DATA with {remaining_length} byte(s) remaining."
                )
            else:
                summary_parts.append(f"CH{session_id} RX {len(channel_data)}B rem={remaining_length}")
                frame_lines.append(
                    f"Terminal returned {len(channel_data)} byte(s) for CH{session_id} RECEIVE DATA with {remaining_length} byte(s) remaining."
                )
            if len(payload_summary_text) > 0:
                summary_parts.append(payload_summary_text)
                for payload_summary in payload_summaries:
                    frame_lines.append(f"Payload summary: {payload_summary}")
        elif pending_state.command_type == GET_CHANNEL_STATUS_COMMAND:
            session_id = pending_state.session_id
            frame_meta["channel_poll_index"] = pending_state.poll_index
            if session_id is None:
                summary_parts.append(f"CHANNEL STATUS 0x{result_code:02X}")
            else:
                summary_parts.append(f"CH{session_id} STATUS 0x{result_code:02X}")
                frame_lines.append(
                    f"Terminal responded to GET CHANNEL STATUS for CH{session_id} with result 0x{result_code:02X}."
                )
        elif pending_state.command_type == TIMER_MANAGEMENT_COMMAND:
            timer_id = pending_state.timer_id
            if timer_id is not None:
                timer_state = self._timers.get(timer_id)
                if timer_state is not None and pending_state.qualifier == 0x01:
                    timer_state.query_frame = frame_number
                timer_value = bytes(response_fields.get("timer_value", b"") or b"")
                remaining_seconds = _decode_timer_value_seconds(timer_value)
                if pending_state.qualifier == 0x01 and len(timer_value) == 3:
                    if timer_state is not None:
                        timer_state.observed_remaining_seconds = int(remaining_seconds)
                        timer_state.observed_at_seconds = self._current_row_time_seconds()
                    summary_parts.append(f"T{timer_id} REM {remaining_seconds}s")
                    frame_lines.append(
                        f"Terminal reported timer {timer_id} remaining value {remaining_seconds}s."
                    )
                elif result_ok is False:
                    summary_parts.append(f"T{timer_id} FAIL 0x{result_code:02X}")
                    frame_lines.append(
                        f"Terminal rejected TIMER MANAGEMENT for timer {timer_id} with result 0x{result_code:02X}."
                    )
        elif pending_state.command_type == POLL_INTERVAL_COMMAND:
            poll_interval_seconds = int(response_fields.get("duration_seconds", 0) or 0)
            timer_state = self._timers.get(_POLL_INTERVAL_TIMER_ID)
            if result_ok:
                if timer_state is not None and poll_interval_seconds > 0:
                    timer_state.active = True
                    timer_state.value_seconds = poll_interval_seconds
                    timer_state.observed_remaining_seconds = poll_interval_seconds
                    timer_state.observed_at_seconds = self._current_row_time_seconds()
                    frame_lines.append(
                        f"Terminal accepted POLL INTERVAL with cadence {poll_interval_seconds}s."
                    )
                elif timer_state is not None:
                    frame_lines.append("Terminal accepted POLL INTERVAL.")
            else:
                if timer_state is not None:
                    timer_state.active = False
                    timer_state.observed_remaining_seconds = 0
                    timer_state.observed_at_seconds = self._current_row_time_seconds()
                    timer_state.stop_frame = frame_number
                summary_parts.append(f"POLL INTERVAL FAIL 0x{result_code:02X}")
                frame_lines.append(
                    f"Terminal rejected POLL INTERVAL with result 0x{result_code:02X}."
                )
        elif pending_state.command_type == POLL_OFF_COMMAND:
            timer_state = self._timers.get(_POLL_INTERVAL_TIMER_ID)
            if result_ok:
                if timer_state is not None:
                    timer_state.active = False
                    timer_state.observed_remaining_seconds = 0
                    timer_state.observed_at_seconds = self._current_row_time_seconds()
                    timer_state.stop_frame = frame_number
                frame_lines.append("Terminal accepted POLL OFF.")
            else:
                summary_parts.append(f"POLL OFF FAIL 0x{result_code:02X}")
                frame_lines.append(
                    f"Terminal rejected POLL OFF with result 0x{result_code:02X}."
                )
        elif pending_state.command_type == _REFRESH_PROACTIVE_COMMAND:
            # The terminal acknowledged (or rejected) a REFRESH request.
            # Only trigger a card-session bump when the qualifier is one
            # of the UICC/NAA reset variants AND the terminal accepted
            # the command. The fetch + this response remain in the
            # closing session; the next frame opens the new session.
            qualifier_value = int(pending_state.qualifier)
            qualifier_name = _REFRESH_QUALIFIER_NAMES.get(
                qualifier_value, f"qualifier 0x{qualifier_value:02X}"
            )
            if result_ok:
                summary_parts.append(f"REFRESH OK {qualifier_name}")
                frame_lines.append(
                    f"Terminal accepted REFRESH ({qualifier_name})."
                )
                if qualifier_value in _REFRESH_RESET_QUALIFIERS:
                    self._queue_card_session_bump(f"REFRESH {qualifier_name}")
            else:
                summary_parts.append(
                    f"REFRESH FAIL 0x{result_code:02X} {qualifier_name}"
                )
                frame_lines.append(
                    f"Terminal rejected REFRESH ({qualifier_name}) with result 0x{result_code:02X}."
                )

        self._pending_proactive = None

    def _try_scp_replay_unwrap(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
    ) -> None:
        """Offer ciphered APDU pairs to the replay engine and fold lines back in.

        Called once per parsed APDU exchange. The check is cheap: if no
        engine is configured or the CLA secure-messaging bit is clear the
        call returns immediately without mutating tracker state.
        """
        engine = self._replay_engine
        if engine is None:
            return
        if len(exchange.command) == 0:
            return
        if (int(exchange.command[0]) & SECURE_MESSAGING_CLA_BIT) == 0:
            return
        context = UnwrapContext(
            frame_number=int(frame_number),
            card_session_index=int(self._card_session_index),
            current_aid_hex=str(self._current_aid_hex or ""),
        )
        try:
            result = engine.try_unwrap_exchange(
                bytes(exchange.command),
                bytes(exchange.response),
                context=context,
            )
        except Exception as engine_exc:
            frame_lines.append(
                f"SCP replay: engine error ({engine_exc}) — ciphered APDU left wrapped."
            )
            return
        if result is None:
            return
        summary_parts.append(f"SCP replay OK ({result.matched_label})")
        frame_lines.extend(str(line) for line in result.lines)

    def _handle_envelope(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        command_body = _extract_command_body(exchange.command)
        event_fields = _parse_event_download(command_body)
        if event_fields is not None:
            frame_meta["state_event"] = True
            event_code = int(event_fields.get("event_code", 0) or 0)
            event_name = _event_name(event_code)
            if event_code == 0x09:
                available_length = int(event_fields.get("channel_length", 0) or 0)
                envelope_channel_number = event_fields.get("channel_number")
                session_id = self._resolve_session_id_for_channel_event(
                    envelope_channel_number,
                )
                if session_id is not None:
                    self._assign_session_channel_number(
                        session_id,
                        envelope_channel_number,
                    )
                    session = self._sessions.get(session_id)
                    if session is not None:
                        session.last_event_frame = frame_number
                    summary_parts.append(f"CH{session_id} DATA AVAILABLE {available_length}B")
                    frame_lines.append(
                        f"DATA AVAILABLE envelope observed for CH{session_id} with {available_length} byte(s)."
                    )
                else:
                    summary_parts.append(f"DATA AVAILABLE {available_length}B")
                    frame_lines.append(
                        f"DATA AVAILABLE envelope observed with {available_length} byte(s)."
                    )
            else:
                summary_parts.append(event_name)
                frame_lines.append(f"Event download observed: {event_name}.")
            return

        timer_fields = _parse_timer_expiration_download(command_body)
        if timer_fields is None:
            return

        frame_meta["state_event"] = True
        timer_id = _extract_timer_id(timer_fields)
        timer_state = self._timers.get(timer_id)
        if timer_state is None:
            timer_state = _TimerState(timer_id=timer_id)
            self._timers[timer_id] = timer_state
        timer_state.active = False
        timer_state.observed_remaining_seconds = 0
        timer_state.observed_at_seconds = self._current_row_time_seconds()
        timer_state.expiration_frame = frame_number
        timer_value = bytes(timer_fields.get("timer_value", b"") or b"")
        expired_seconds = _decode_timer_value_seconds(timer_value)
        if expired_seconds > 0:
            summary_parts.append(f"T{timer_id} EXPIRED {expired_seconds}s")
            frame_lines.append(
                f"TIMER EXPIRATION envelope observed for timer {timer_id}, value {expired_seconds}s."
            )
            return
        summary_parts.append(f"T{timer_id} EXPIRED")
        frame_lines.append(f"TIMER EXPIRATION envelope observed for timer {timer_id}.")

    def _handle_status(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        if exchange.sw1 != 0x91:
            self._handle_file_status(
                frame_number,
                exchange,
                summary_parts,
                frame_lines,
                frame_meta,
            )
            return
        frame_meta["state_event"] = True
        summary_parts.append(f"FETCH PENDING {exchange.sw2}B")
        frame_lines.append(
            f"STATUS response announced {exchange.sw2} byte(s) of proactive data pending on FETCH."
        )

    def _current_file_parent_path(self) -> tuple[str, ...]:
        if len(self._current_file_path) <= 1:
            return ("MF",)
        if self._current_file_kind == "ef":
            return self._current_file_path[:-1]
        return self._current_file_path

    def _set_current_file_path(self, path: tuple[str, ...]) -> None:
        normalized_path = tuple(path) if len(path) > 0 else ("MF",)
        self._current_file_path = normalized_path
        self._current_file_kind = _path_kind(normalized_path)

    def _resolve_select_path(self, selector: bytes) -> tuple[str, ...]:
        if len(selector) == 0:
            return self._current_file_path
        if len(selector) > 2:
            aid_hex = selector.hex().upper()
            return _KNOWN_AID_PATHS.get(aid_hex, ("MF", f"AID {aid_hex}"))
        fid_hex = selector.hex().upper()
        known_path = _KNOWN_FILE_PATHS.get(fid_hex)
        if known_path is not None:
            return known_path
        return self._current_file_parent_path() + (f"FID {fid_hex}",)

    def _file_trace_chain(self, frame_number: int) -> tuple[int, ...]:
        frames: list[int] = []
        seen: set[int] = set()
        window_start = max(
            0,
            len(self._recent_file_trace_events) - (_MAX_FILE_TRACE_EVENTS - 1),
        )
        for event in self._recent_file_trace_events[window_start:]:
            event_frame = int(event.frame_number)
            if event_frame <= 0 or event_frame in seen:
                continue
            frames.append(event_frame)
            seen.add(event_frame)
        if frame_number > 0 and frame_number not in seen:
            frames.append(int(frame_number))
        return tuple(frames)

    def _file_trace_parent_frame(self) -> int | None:
        for event in reversed(self._recent_file_trace_events):
            event_frame = int(event.frame_number)
            if event_frame > 0:
                return event_frame
        return None

    def _remember_file_operation(
        self,
        operation_text: str,
        *,
        frame_number: int | None = None,
        path_text: str = "",
        status: str = "",
    ) -> None:
        normalized = str(operation_text or "").strip()
        if len(normalized) == 0:
            return
        self._recent_file_operations.append(normalized)
        if len(self._recent_file_operations) > 6:
            self._recent_file_operations = self._recent_file_operations[-6:]
        if frame_number is None:
            return
        frame_number_i = int(frame_number)
        if frame_number_i <= 0:
            return
        self._recent_file_trace_events.append(
            _FileTraceEvent(
                frame_number=frame_number_i,
                operation_text=normalized,
                path_text=str(path_text or "").strip(),
                status=str(status or "").strip(),
            )
        )
        if len(self._recent_file_trace_events) > _MAX_FILE_TRACE_EVENTS:
            self._recent_file_trace_events = self._recent_file_trace_events[
                -_MAX_FILE_TRACE_EVENTS:
            ]

    def _record_file_trace(
        self,
        frame_number: int,
        frame_meta: dict[str, object],
        *,
        operation_text: str,
        operation: str,
        path_text: str,
        status: str,
        reason: str = "",
    ) -> None:
        normalized_operation = str(operation_text or "").strip()
        if len(normalized_operation) == 0:
            return
        frame_meta["trace_group"] = "filesystem"
        frame_meta["trace_label"] = normalized_operation
        frame_meta["trace_operation"] = str(operation or "").strip()
        frame_meta["trace_path"] = str(path_text or "").strip()
        frame_meta["trace_status"] = str(status or "").strip()
        frame_meta["trace_parent_frame"] = self._file_trace_parent_frame()
        frame_meta["trace_related_frames"] = self._file_trace_chain(frame_number)
        frame_meta["trace_reason"] = str(reason or "").strip()
        self._remember_file_operation(
            normalized_operation,
            frame_number=frame_number,
            path_text=path_text,
            status=status,
        )

    def _select_failure_reason(self, selected_path: tuple[str, ...]) -> str:
        current_text = _path_text(self._current_file_path)
        selected_text = _path_text(selected_path)
        context_path = self._current_file_parent_path()
        context_text = _path_text(context_path)
        if _path_is_under(selected_path, context_path) is False:
            return (
                f"Current selection stayed {current_text}; requested file resolved to "
                f"{selected_text}, outside active context {context_text}."
            )
        return f"Current selection stayed {current_text}; requested file resolved to {selected_text}."

    def _handle_file_select(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        selector = _extract_command_body(exchange.command)
        selected_path = self._resolve_select_path(selector)
        selected_text = _path_text(selected_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        previous_text = _path_text(self._current_file_path)
        # Track AID context for the replay engine. ETSI TS 102 221 §11.1.1
        # specifies SELECT P1 bit 0x04 = "select by DF name" (AID). When the
        # select is successful the AID becomes the current applet context
        # for any subsequent secure-messaging traffic.
        if (
            len(exchange.command) >= 3
            and (int(exchange.command[2]) & 0x04) == 0x04
            and _apdu_succeeded(exchange.sw1, exchange.sw2)
            and len(selector) > 0
        ):
            self._current_aid_hex = selector.hex().upper()
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            self._set_current_file_path(selected_path)
            summary_parts.append(f"FS {selected_text} SELECT")
            frame_lines.append(f"SELECT updated the ETSI file context to {selected_text}.")
            if exchange.sw1 in {0x61, 0x9F} and exchange.sw2 > 0:
                frame_lines.append(
                    f"SELECT announced {exchange.sw2} response byte(s) pending on GET RESPONSE."
                )
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"Frame {frame_number}: SELECT {selected_text}",
                operation="SELECT",
                path_text=selected_text,
                status="ok",
                reason=f"Current selection changed from {previous_text} to {selected_text}.",
            )
            return
        summary_parts.append(f"FS {selected_text} SELECT FAIL {sw_text}")
        failure_reason = self._select_failure_reason(selected_path)
        frame_lines.append(f"SELECT failed for {selected_text} with status word {sw_text}.")
        frame_lines.append(f"  {failure_reason}")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"Frame {frame_number}: SELECT {selected_text} FAIL {sw_text}",
            operation="SELECT",
            path_text=selected_text,
            status=f"fail {sw_text}",
            reason=failure_reason,
        )

    def _handle_file_read_binary(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        if len(exchange.command) < 4:
            return
        offset = ((int(exchange.command[2]) & 0x7F) << 8) | int(exchange.command[3])
        target_text = _path_text(self._current_file_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            byte_count = len(exchange.response_data)
            summary_parts.append(f"FS {target_text} READ BINARY {byte_count}B @{offset}")
            frame_lines.append(
                f"READ BINARY returned {byte_count} byte(s) from {target_text} at offset {offset}."
            )
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"READ BINARY {target_text} {byte_count}B @{offset}",
                operation="READ BINARY",
                path_text=target_text,
                status="ok",
                reason=f"READ BINARY used current selection {target_text}.",
            )
            # ETSI TS 102.221 §13.2: EF.ICCID is 10 bytes of swapped-
            # nibble BCD at offset 0. Capture it for the current card
            # session so the TUI can label the session wrapper.
            if (
                len(self._current_file_path) > 0
                and self._current_file_path[-1] == "EF.ICCID"
                and offset == 0
                and byte_count >= 10
            ):
                iccid_text = _decode_iccid_bytes(bytes(exchange.response_data[:10]))
                if len(iccid_text) > 0:
                    self._card_session_iccids[self._card_session_index] = iccid_text
                    frame_lines.append(f"  ICCID decoded: {iccid_text}")
            return
        summary_parts.append(f"FS {target_text} READ BINARY FAIL {sw_text}")
        frame_lines.append(f"READ BINARY failed for {target_text} with status word {sw_text}.")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"READ BINARY {target_text} FAIL {sw_text}",
            operation="READ BINARY",
            path_text=target_text,
            status=f"fail {sw_text}",
            reason=f"READ BINARY used current selection {target_text}.",
        )

    def _handle_file_read_record(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        if len(exchange.command) < 3:
            return
        record_number = int(exchange.command[2])
        target_text = _path_text(self._current_file_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            byte_count = len(exchange.response_data)
            summary_parts.append(f"FS {target_text} READ RECORD R{record_number} {byte_count}B")
            frame_lines.append(
                f"READ RECORD returned {byte_count} byte(s) from {target_text}, record {record_number}."
            )
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"READ RECORD {target_text} R{record_number} {byte_count}B",
                operation="READ RECORD",
                path_text=target_text,
                status="ok",
                reason=f"READ RECORD used current selection {target_text}.",
            )
            return
        summary_parts.append(f"FS {target_text} READ RECORD FAIL {sw_text}")
        frame_lines.append(f"READ RECORD failed for {target_text} with status word {sw_text}.")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"READ RECORD {target_text} FAIL {sw_text}",
            operation="READ RECORD",
            path_text=target_text,
            status=f"fail {sw_text}",
            reason=f"READ RECORD used current selection {target_text}.",
        )

    def _handle_file_update_binary(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        if len(exchange.command) < 4:
            return
        payload = _extract_command_body(exchange.command)
        offset = ((int(exchange.command[2]) & 0x7F) << 8) | int(exchange.command[3])
        target_text = _path_text(self._current_file_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            summary_parts.append(f"FS {target_text} UPDATE BINARY {len(payload)}B @{offset}")
            frame_lines.append(
                f"UPDATE BINARY wrote {len(payload)} byte(s) to {target_text} at offset {offset}."
            )
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"UPDATE BINARY {target_text} {len(payload)}B @{offset}",
                operation="UPDATE BINARY",
                path_text=target_text,
                status="ok",
                reason=f"UPDATE BINARY used current selection {target_text}.",
            )
            return
        summary_parts.append(f"FS {target_text} UPDATE BINARY FAIL {sw_text}")
        frame_lines.append(f"UPDATE BINARY failed for {target_text} with status word {sw_text}.")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"UPDATE BINARY {target_text} FAIL {sw_text}",
            operation="UPDATE BINARY",
            path_text=target_text,
            status=f"fail {sw_text}",
            reason=f"UPDATE BINARY used current selection {target_text}.",
        )

    def _handle_file_update_record(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        if len(exchange.command) < 3:
            return
        payload = _extract_command_body(exchange.command)
        record_number = int(exchange.command[2])
        target_text = _path_text(self._current_file_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            summary_parts.append(f"FS {target_text} UPDATE RECORD R{record_number} {len(payload)}B")
            frame_lines.append(
                f"UPDATE RECORD wrote {len(payload)} byte(s) to {target_text}, record {record_number}."
            )
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"UPDATE RECORD {target_text} R{record_number} {len(payload)}B",
                operation="UPDATE RECORD",
                path_text=target_text,
                status="ok",
                reason=f"UPDATE RECORD used current selection {target_text}.",
            )
            return
        summary_parts.append(f"FS {target_text} UPDATE RECORD FAIL {sw_text}")
        frame_lines.append(f"UPDATE RECORD failed for {target_text} with status word {sw_text}.")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"UPDATE RECORD {target_text} FAIL {sw_text}",
            operation="UPDATE RECORD",
            path_text=target_text,
            status=f"fail {sw_text}",
            reason=f"UPDATE RECORD used current selection {target_text}.",
        )

    def _handle_file_get_response(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        target_text = _path_text(self._current_file_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            byte_count = len(exchange.response_data)
            summary_parts.append(f"FS {target_text} GET RESPONSE {byte_count}B")
            frame_lines.append(f"GET RESPONSE returned {byte_count} byte(s) for {target_text}.")
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"GET RESPONSE {target_text} {byte_count}B",
                operation="GET RESPONSE",
                path_text=target_text,
                status="ok",
                reason=f"GET RESPONSE used current selection {target_text}.",
            )
            return
        summary_parts.append(f"FS {target_text} GET RESPONSE FAIL {sw_text}")
        frame_lines.append(f"GET RESPONSE failed for {target_text} with status word {sw_text}.")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"GET RESPONSE {target_text} FAIL {sw_text}",
            operation="GET RESPONSE",
            path_text=target_text,
            status=f"fail {sw_text}",
            reason=f"GET RESPONSE used current selection {target_text}.",
        )

    def _handle_file_status(
        self,
        frame_number: int,
        exchange: ParsedApduExchange,
        summary_parts: list[str],
        frame_lines: list[str],
        frame_meta: dict[str, object],
    ) -> None:
        target_text = _path_text(self._current_file_path)
        sw_text = _status_word_text(exchange.sw1, exchange.sw2)
        if _apdu_succeeded(exchange.sw1, exchange.sw2):
            byte_count = len(exchange.response_data)
            summary_parts.append(f"FS {target_text} STATUS {byte_count}B")
            frame_lines.append(f"STATUS returned {byte_count} byte(s) for {target_text}.")
            self._record_file_trace(
                frame_number,
                frame_meta,
                operation_text=f"STATUS {target_text} {byte_count}B",
                operation="STATUS",
                path_text=target_text,
                status="ok",
                reason=f"STATUS used current selection {target_text}.",
            )
            return
        summary_parts.append(f"FS {target_text} STATUS FAIL {sw_text}")
        frame_lines.append(f"STATUS failed for {target_text} with status word {sw_text}.")
        self._record_file_trace(
            frame_number,
            frame_meta,
            operation_text=f"STATUS {target_text} FAIL {sw_text}",
            operation="STATUS",
            path_text=target_text,
            status=f"fail {sw_text}",
            reason=f"STATUS used current selection {target_text}.",
        )

    def _allocate_channel_session(
        self,
        fields: dict[str, object],
        frame_number: int,
    ) -> _ChannelSessionState:
        session_id = self._next_session_id
        self._next_session_id += 1
        protocol_name = _transport_protocol_name(
            int(fields.get("transport_protocol_type", 0) or 0)
        )
        endpoint = _channel_endpoint(fields)
        session = _ChannelSessionState(
            session_id=session_id,
            protocol=protocol_name,
            endpoint=endpoint,
            network_access_name=str(fields.get("network_access_name", "") or "").strip(),
            open_request_frame=frame_number,
        )
        self._sessions[session_id] = session
        return session

    def _current_session_id(self) -> int | None:
        if self._active_session_id is not None:
            return self._active_session_id
        if self._pending_session_id is not None:
            return self._pending_session_id
        return None

    def _resolve_session_id_for_channel_event(
        self,
        envelope_channel_number: object | None,
    ) -> int | None:
        # ETSI TS 102.223 envelope Event Download frames carry the channel
        # number they pertain to. Prefer that channel-scoped lookup over the
        # globally current session so that data-available events always pin
        # to the correct BIP transport even when several channels overlap or
        # the active session was cycled since the envelope was queued.
        target_channel_number: int | None = None
        if envelope_channel_number is not None:
            try:
                target_channel_number = int(envelope_channel_number)
            except (TypeError, ValueError):
                target_channel_number = None
        if target_channel_number is not None:
            matching_session_ids: list[int] = []
            for session in self._sessions.values():
                if self._effective_channel_number(session) != int(target_channel_number):
                    continue
                if session.status in {"pending-open", "active", "closing"}:
                    matching_session_ids.append(int(session.session_id))
            if len(matching_session_ids) > 0:
                return max(matching_session_ids)
            for session in reversed(list(self._sessions.values())):
                if self._effective_channel_number(session) == int(target_channel_number):
                    return int(session.session_id)
        return self._current_session_id()

    def _force_close_stale_sessions_before_new_open(self, frame_number: int) -> None:
        stale_session_ids: list[int] = []
        if self._active_session_id is not None:
            stale_session_ids.append(int(self._active_session_id))
        if (
            self._pending_session_id is not None
            and int(self._pending_session_id) not in stale_session_ids
        ):
            stale_session_ids.append(int(self._pending_session_id))
        for session_id in stale_session_ids:
            session = self._sessions.get(int(session_id))
            if session is None:
                continue
            if session.status in {"closed", "open-failed"}:
                continue
            session.status = "closed-implicit"
            if session.close_frame is None:
                session.close_frame = int(frame_number)
        self._active_session_id = None
        self._pending_session_id = None

    def _start_session_poll(self, session_id: int | None) -> int | None:
        if session_id is None:
            return None
        session = self._sessions.get(int(session_id))
        if session is None:
            return None
        session.poll_count += 1
        session.current_poll_index = int(session.poll_count)
        return int(session.current_poll_index)

    def _current_session_poll_index(self, session_id: int | None) -> int | None:
        if session_id is None:
            return None
        session = self._sessions.get(int(session_id))
        if session is None:
            return None
        if session.current_poll_index is None:
            return None
        return int(session.current_poll_index)

    def _frame_channel_session_id(
        self,
        row: PacketSummary,
        exchange: ParsedApduExchange | None,
        summary_parts: list[str],
    ) -> int | None:
        summary_text = " | ".join(
            str(part or "").strip()
            for part in summary_parts
            if len(str(part or "").strip()) > 0
        )
        match = re.search(r"\bCH(\d+)\b", summary_text)
        if match is not None:
            try:
                return int(match.group(1))
            except Exception:
                return None
        # Only BIP-related rows receive a channel session id. Plain file-system
        # APDUs (SELECT, READ *, UPDATE *, GET RESPONSE, STATUS/FS ...) are
        # grouped as "ETSI FS" regardless of any residual session state so that
        # post-reboot traffic cannot be nested under a stale open channel.
        return None

    def _frame_channel_poll_index(
        self,
        row: PacketSummary,
        exchange: ParsedApduExchange | None,
        summary_parts: list[str],
        frame_meta: dict[str, object],
        channel_session_id: int | None,
    ) -> int | None:
        explicit_poll_index = frame_meta.get("channel_poll_index")
        if isinstance(explicit_poll_index, int):
            return int(explicit_poll_index)
        if channel_session_id is None:
            return None
        if exchange is None:
            return self._current_session_poll_index(channel_session_id)
        if exchange.ins in {
            SELECT_INS,
            READ_BINARY_INS,
            READ_RECORD_INS,
            GET_RESPONSE_INS,
            UPDATE_BINARY_INS,
            UPDATE_RECORD_INS,
        }:
            return self._current_session_poll_index(channel_session_id)
        if exchange.ins == STATUS_INS and any(
            str(part or "").strip().startswith("FS ") for part in summary_parts
        ):
            return self._current_session_poll_index(channel_session_id)
        info_text = str(row.info or "").strip().upper()
        if len(info_text) == 0:
            return None
        if info_text.startswith("FETCH"):
            return None
        if info_text.startswith("ENVELOPE"):
            return self._current_session_poll_index(channel_session_id)
        if info_text.startswith("TERMINAL RESPONSE"):
            return None
        return self._current_session_poll_index(channel_session_id)

    def _ensure_timer_state(
        self,
        timer_id: int,
        *,
        display_label: str = "",
        auto_expire: bool = False,
    ) -> _TimerState:
        timer_state = self._timers.get(int(timer_id))
        if timer_state is None:
            timer_state = _TimerState(
                timer_id=int(timer_id),
                display_label=str(display_label or ""),
                auto_expire=bool(auto_expire),
            )
            self._timers[int(timer_id)] = timer_state
            return timer_state
        if len(str(display_label or "").strip()) > 0:
            timer_state.display_label = str(display_label or "").strip()
        if bool(auto_expire):
            timer_state.auto_expire = True
        return timer_state

    def _timer_is_visible(
        self,
        timer_state: _TimerState,
        frame_time_seconds: float | None,
    ) -> bool:
        if timer_state.active is False:
            return False
        if timer_state.auto_expire is False:
            return True
        return _timer_remaining_seconds(timer_state, frame_time_seconds) > 0

    def _active_channel_count(self) -> int:
        total = 0
        for session in self._sessions.values():
            if session.status in {"pending-open", "active", "closing"}:
                total += 1
        return total

    def _active_timer_count(self, frame_time_seconds: float | None = None) -> int:
        total = 0
        for timer_state in self._timers.values():
            if self._timer_is_visible(timer_state, frame_time_seconds):
                total += 1
        return total

    def _current_row_time_seconds(self) -> float | None:
        return getattr(self, "_row_time_seconds", None)

    def _active_timer_snapshots(self, frame_time_seconds: float | None) -> tuple[ActiveTimerSnapshot, ...]:
        snapshots: list[ActiveTimerSnapshot] = []
        for timer_id in sorted(self._timers):
            timer_state = self._timers[timer_id]
            if self._timer_is_visible(timer_state, frame_time_seconds) is False:
                continue
            snapshots.append(
                ActiveTimerSnapshot(
                    timer_id=int(timer_state.timer_id),
                    configured_seconds=int(timer_state.value_seconds),
                    remaining_seconds=_timer_remaining_seconds(timer_state, frame_time_seconds),
                    display_label=str(timer_state.display_label or ""),
                )
            )
        return tuple(snapshots)

    def _build_context_lines(self, frame_lines: list[str], frame_time_seconds: float | None) -> list[str]:
        lines: list[str] = []
        if len(frame_lines) > 0:
            lines.append("Frame Events")
            for line in frame_lines:
                lines.append(f"  {line}")

        if len(self._recent_file_operations) > 0 or self._current_file_path != ("MF",):
            lines.append("ETSI File Context")
            lines.append(f"  Current selection: {_path_text(self._current_file_path)}")
            for operation_text in self._recent_file_operations[-4:]:
                lines.append(f"  Recent op: {operation_text}")

        recent_sessions = list(self._sessions.values())[-4:]
        if len(recent_sessions) > 0:
            lines.append("Channel Sessions")
            for session in recent_sessions:
                effective_channel_number = self._effective_channel_number(session)
                session_label = (
                    f"CH{session.session_id} / Channel {effective_channel_number} {session.status} "
                    f"{_protocol_label(session.protocol)}://{session.endpoint}"
                )
                lines.append(f"  {session_label}")
                if len(session.network_access_name) > 0:
                    lines.append(f"    APN: {session.network_access_name}")
                if session.poll_index is not None:
                    lines.append(f"    Poll occurrence: {session.poll_index}")
                if session.open_request_frame is not None:
                    lines.append(f"    Open request frame: {session.open_request_frame}")
                if session.open_response_frame is not None:
                    lines.append(f"    Open response frame: {session.open_response_frame}")
                if session.last_send_frame is not None:
                    lines.append(f"    Last SEND DATA frame: {session.last_send_frame}")
                if len(session.last_send_summary) > 0:
                    lines.append(f"    Last SEND summary: {session.last_send_summary}")
                if session.last_receive_frame is not None:
                    lines.append(f"    Last RECEIVE DATA frame: {session.last_receive_frame}")
                if len(session.last_receive_summary) > 0:
                    lines.append(f"    Last RECEIVE summary: {session.last_receive_summary}")
                if session.last_event_frame is not None:
                    lines.append(f"    Last event frame: {session.last_event_frame}")
                if session.close_frame is not None:
                    lines.append(f"    Close frame: {session.close_frame}")

        active_timer_snapshots = self._active_timer_snapshots(frame_time_seconds)
        if len(active_timer_snapshots) > 0:
            lines.append("Active Timers")
            timer_state_by_id = {
                int(timer_state.timer_id): timer_state
                for timer_state in self._timers.values()
                if self._timer_is_visible(timer_state, frame_time_seconds)
            }
            for timer_snapshot in active_timer_snapshots:
                timer_state = timer_state_by_id.get(int(timer_snapshot.timer_id))
                if timer_state is None:
                    continue
                timer_label = _timer_display_label(
                    timer_state.timer_id,
                    timer_state.display_label,
                )
                lines.append(
                    f"  {timer_label} active {timer_state.value_seconds}s "
                    f"remaining {_format_duration_clock(timer_snapshot.remaining_seconds)} "
                    f"(qualifier 0x{timer_state.last_qualifier:02X})"
                )
                if timer_state.start_frame is not None:
                    lines.append(f"    Start frame: {timer_state.start_frame}")
                if timer_state.query_frame is not None:
                    lines.append(f"    Last query frame: {timer_state.query_frame}")

        return lines


def _parse_exchange_from_udp_payload_hex(udp_payload_hex: str) -> ParsedApduExchange | None:
    normalized_hex = str(udp_payload_hex or "").strip()
    if len(normalized_hex) == 0:
        return None
    try:
        gsmtap_packet = bytes.fromhex(normalized_hex)
    except ValueError:
        return None
    apdu_payload = _extract_apdu_payload(gsmtap_packet)
    if len(apdu_payload) < 7:
        return None
    cla = int(apdu_payload[0])
    ins = int(apdu_payload[1])
    if ins in {
        FETCH_INS,
        READ_BINARY_INS,
        READ_RECORD_INS,
        STATUS_INS,
        GET_RESPONSE_INS,
    }:
        command_length = 5
    elif ins in {
        TERMINAL_RESPONSE_INS,
        SELECT_INS,
        ENVELOPE_INS,
        UPDATE_BINARY_INS,
        UPDATE_RECORD_INS,
    }:
        command_length = _case_three_command_length(apdu_payload)
    elif (cla & SECURE_MESSAGING_CLA_BIT) == SECURE_MESSAGING_CLA_BIT:
        # Secure-messaging wrapping adds 8 bytes of MAC (plus optional
        # encrypted body) to the original APDU. The outer APDU is always
        # case 3 from T=0 transport's perspective, so it is safe to derive
        # the command length from Lc without needing to know the inner INS.
        command_length = _case_three_command_length(apdu_payload)
    else:
        return None
    if command_length is None:
        return None
    if len(apdu_payload) < command_length + 2:
        return None
    command = bytes(apdu_payload[:command_length])
    response = bytes(apdu_payload[command_length:])
    if len(response) < 2:
        return None
    return ParsedApduExchange(
        command=command,
        response=response,
        ins=ins,
        response_data=response[:-2],
        sw1=int(response[-2]),
        sw2=int(response[-1]),
    )


def _extract_apdu_payload(gsmtap_packet: bytes) -> bytes:
    if len(gsmtap_packet) < 16:
        return b""
    if int(gsmtap_packet[2]) != GSMTAP_TYPE_SIM:
        return b""
    if int(gsmtap_packet[12]) != GSMTAP_SIM_APDU:
        return b""
    header_words = int(gsmtap_packet[1] or 0)
    header_length = header_words * 4
    if header_length < 16:
        header_length = 16
    if len(gsmtap_packet) < header_length:
        return b""
    return bytes(gsmtap_packet[header_length:])


def _case_three_command_length(apdu_payload: bytes) -> int | None:
    if len(apdu_payload) < 5:
        return None
    lc = int(apdu_payload[4])
    if lc != 0:
        command_length = 5 + lc
        if len(apdu_payload) < command_length + 2:
            return None
        return command_length
    if len(apdu_payload) < 7:
        return None
    extended_length = int.from_bytes(apdu_payload[5:7], "big", signed=False)
    command_length = 7 + extended_length
    if len(apdu_payload) < command_length + 2:
        return None
    return command_length


def _extract_command_body(command: bytes) -> bytes:
    if len(command) <= 5:
        return b""
    lc = int(command[4])
    if lc != 0:
        end_offset = 5 + lc
        if end_offset <= len(command):
            return bytes(command[5:end_offset])
        return b""
    if len(command) < 7:
        return b""
    extended_length = int.from_bytes(command[5:7], "big", signed=False)
    end_offset = 7 + extended_length
    if end_offset <= len(command):
        return bytes(command[7:end_offset])
    return b""


def _parse_proactive_command(payload: bytes) -> tuple[int | None, int, dict[str, object]]:
    fields: dict[str, object] = {}
    try:
        root_tag, root_value, _raw_tlv, _next_offset = read_tlv(bytes(payload or b""), 0)
    except ValueError:
        return None, 0, fields
    if root_tag != b"\xD0":
        return None, 0, fields
    command_type: int | None = None
    qualifier = 0
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, value_bytes, raw_tlv, offset = read_tlv(root_value, offset)
        except ValueError:
            break
        if tag_bytes in (b"\x01", b"\x81") and len(value_bytes) == 3:
            command_type = int(value_bytes[1])
            qualifier = int(value_bytes[2])
            fields["command_details_tlv"] = raw_tlv
            continue
        if tag_bytes == b"\x36":
            fields["channel_data"] = value_bytes
            continue
        if tag_bytes == b"\x39" and len(value_bytes) == 2:
            fields["buffer_size"] = int.from_bytes(value_bytes, "big", signed=False)
            continue
        if tag_bytes in (b"\x24", b"\xA4") and len(value_bytes) > 0:
            fields["timer_identifier_value"] = value_bytes
            continue
        if tag_bytes in (b"\x25", b"\xA5") and len(value_bytes) == 3:
            fields["timer_value"] = value_bytes
            continue
        if tag_bytes == b"\x47":
            fields["network_access_name"] = _decode_network_access_name(value_bytes)
            continue
        if tag_bytes == b"\x3C" and len(value_bytes) == 3:
            fields["transport_protocol_type"] = int(value_bytes[0])
            fields["transport_port"] = int.from_bytes(value_bytes[1:], "big", signed=False)
            continue
        if tag_bytes == b"\x3E":
            fields["remote_address"] = _decode_other_address(value_bytes)
            continue
        if tag_bytes == b"\x99":
            fields["event_list"] = [int(value) for value in value_bytes]
            continue
        if tag_bytes == b"\x84" and len(value_bytes) > 0:
            duration_seconds = _decode_duration_seconds(value_bytes)
            fields["duration_seconds"] = duration_seconds
            fields["poll_interval_seconds"] = duration_seconds
            continue
        if tag_bytes == b"\xB7" and len(value_bytes) > 0:
            fields["channel_data_length"] = int(value_bytes[0])
    return command_type, qualifier, fields


_EVENT_LIST_TAGS: tuple[bytes, ...] = (b"\x19", b"\x99")
_CHANNEL_STATUS_TAGS: tuple[bytes, ...] = (b"\x18", b"\x38", b"\x98", b"\xB8")
_CHANNEL_DATA_LENGTH_TAGS: tuple[bytes, ...] = (b"\x17", b"\x37", b"\x97", b"\xB7")


def _parse_terminal_response_body(payload: bytes) -> dict[str, object]:
    fields: dict[str, object] = {}
    offset = 0
    while offset < len(payload):
        try:
            tag_bytes, value_bytes, _raw_tlv, offset = read_tlv(payload, offset)
        except ValueError:
            break
        if tag_bytes == b"\x03" and len(value_bytes) > 0:
            fields["result_code"] = int(value_bytes[0])
            continue
        if tag_bytes == b"\x36":
            fields["channel_data"] = value_bytes
            continue
        if tag_bytes in _CHANNEL_DATA_LENGTH_TAGS and len(value_bytes) > 0:
            fields["channel_length"] = int(value_bytes[0])
            continue
        if tag_bytes in _CHANNEL_STATUS_TAGS:
            fields["channel_status"] = value_bytes
            fields["channel_number"] = _decode_channel_status_channel_number(value_bytes)
            continue
        if tag_bytes in (b"\x24", b"\xA4") and len(value_bytes) > 0:
            fields["timer_identifier_value"] = value_bytes
            continue
        if tag_bytes in (b"\x25", b"\xA5") and len(value_bytes) == 3:
            fields["timer_value"] = value_bytes
            continue
        if tag_bytes == b"\x84" and len(value_bytes) > 0:
            duration_seconds = _decode_duration_seconds(value_bytes)
            fields["duration_seconds"] = duration_seconds
            fields["poll_interval_seconds"] = duration_seconds
    return fields


def _parse_event_download(payload: bytes) -> dict[str, object] | None:
    try:
        root_tag, root_value, _raw_tlv, _next_offset = read_tlv(bytes(payload or b""), 0)
    except ValueError:
        return None
    if root_tag != b"\xD6":
        return None
    fields: dict[str, object] = {}
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, value_bytes, _raw_tlv, offset = read_tlv(root_value, offset)
        except ValueError:
            break
        # ETSI TS 101.220 COMPREHENSION-TLV tags may arrive with the CR
        # (comprehension required) bit either set or cleared, and some
        # implementations additionally mark a tag as constructed. Accept
        # each of the permitted encodings for the fields we care about so
        # that live captures from real cards always resolve to a concrete
        # event code / channel status, not a silent default of 0x00.
        if tag_bytes in _EVENT_LIST_TAGS and len(value_bytes) > 0:
            fields["event_code"] = int(value_bytes[0])
            continue
        if tag_bytes in _CHANNEL_DATA_LENGTH_TAGS and len(value_bytes) > 0:
            fields["channel_length"] = int(value_bytes[0])
            continue
        if tag_bytes in _CHANNEL_STATUS_TAGS:
            fields["channel_status"] = value_bytes
            fields["channel_number"] = _decode_channel_status_channel_number(value_bytes)
    return fields


def _decode_channel_status_channel_number(value_bytes: bytes) -> int | None:
    if len(value_bytes) == 0:
        return None
    first_byte = int(value_bytes[0])
    channel_number = first_byte & 0x07
    if 1 <= channel_number <= 7:
        return channel_number
    channel_number = first_byte & 0x0F
    if 1 <= channel_number <= 7:
        return channel_number
    return None


def _parse_timer_expiration_download(payload: bytes) -> dict[str, object] | None:
    try:
        root_tag, root_value, _raw_tlv, _next_offset = read_tlv(bytes(payload or b""), 0)
    except ValueError:
        return None
    if root_tag != b"\xD7":
        return None
    fields: dict[str, object] = {}
    offset = 0
    while offset < len(root_value):
        try:
            tag_bytes, value_bytes, _raw_tlv, offset = read_tlv(root_value, offset)
        except ValueError:
            break
        if tag_bytes in (b"\x24", b"\xA4") and len(value_bytes) > 0:
            fields["timer_identifier_value"] = value_bytes
            continue
        if tag_bytes in (b"\x25", b"\xA5") and len(value_bytes) == 3:
            fields["timer_value"] = value_bytes
    return fields


def _summarize_channel_payload(payload: bytes) -> list[str]:
    if len(payload) == 0:
        return []
    dns_query = _try_decode_dns_query(payload)
    if len(dns_query) > 0:
        return [dns_query]
    dns_response = _try_decode_dns_response(payload)
    if len(dns_response) > 0:
        return [dns_response]
    tls_summaries = _try_decode_tls_records(payload)
    if len(tls_summaries) > 0:
        return tls_summaries
    http_summary = _try_decode_http_message(payload)
    if len(http_summary) > 0:
        return [http_summary]
    return []


def _compact_payload_summary(payload_summaries: list[str]) -> str:
    if len(payload_summaries) == 0:
        return ""
    if len(payload_summaries) == 1:
        return str(payload_summaries[0]).strip()
    visible_items = [str(item).strip() for item in payload_summaries[:2] if len(str(item).strip()) > 0]
    if len(visible_items) == 0:
        return ""
    compact = "; ".join(visible_items)
    remaining = len(payload_summaries) - len(visible_items)
    if remaining > 0:
        compact += f"; +{remaining} more"
    return compact


def _dns_record_type_name(record_type: int) -> str:
    return {
        0x0001: "A",
        0x0005: "CNAME",
        0x001C: "AAAA",
    }.get(int(record_type), f"0x{int(record_type):04X}")


def _decode_dns_name(value_bytes: bytes, offset: int) -> tuple[str, int]:
    if offset < 0 or offset >= len(value_bytes):
        raise ValueError("DNS name offset is out of bounds.")
    labels: list[str] = []
    current_offset = offset
    next_offset = offset
    jumped = False
    visited_offsets: set[int] = set()
    while current_offset < len(value_bytes):
        length_value = value_bytes[current_offset]
        if length_value == 0:
            current_offset += 1
            if jumped is False:
                next_offset = current_offset
            return ".".join(labels), next_offset
        if (length_value & 0xC0) == 0xC0:
            if current_offset + 1 >= len(value_bytes):
                raise ValueError("DNS compression pointer is truncated.")
            pointer_offset = ((length_value & 0x3F) << 8) | value_bytes[current_offset + 1]
            if pointer_offset in visited_offsets:
                raise ValueError("DNS compression pointer loop detected.")
            if pointer_offset >= len(value_bytes):
                raise ValueError("DNS compression pointer is out of bounds.")
            if jumped is False:
                next_offset = current_offset + 2
            visited_offsets.add(pointer_offset)
            current_offset = pointer_offset
            jumped = True
            continue
        if (length_value & 0xC0) != 0:
            raise ValueError("Unsupported DNS label encoding.")
        current_offset += 1
        label_end = current_offset + length_value
        if label_end > len(value_bytes):
            raise ValueError("DNS label exceeds payload length.")
        label_bytes = value_bytes[current_offset:label_end]
        labels.append(label_bytes.decode("ascii"))
        current_offset = label_end
    raise ValueError("DNS name did not terminate.")


def _parse_dns_question(value_bytes: bytes, offset: int) -> tuple[dict[str, object], int]:
    qname_value, cursor = _decode_dns_name(value_bytes, offset)
    if cursor + 4 > len(value_bytes):
        raise ValueError("DNS question is truncated.")
    query_type = int.from_bytes(value_bytes[cursor:cursor + 2], "big", signed=False)
    query_class = int.from_bytes(value_bytes[cursor + 2:cursor + 4], "big", signed=False)
    return {
        "qname": qname_value,
        "query_type": query_type,
        "query_class": query_class,
    }, cursor + 4


def _parse_dns_resource_record(value_bytes: bytes, offset: int) -> tuple[dict[str, object], int]:
    record_name, cursor = _decode_dns_name(value_bytes, offset)
    if cursor + 10 > len(value_bytes):
        raise ValueError("DNS resource record header is truncated.")
    record_type = int.from_bytes(value_bytes[cursor:cursor + 2], "big", signed=False)
    record_class = int.from_bytes(value_bytes[cursor + 2:cursor + 4], "big", signed=False)
    ttl_value = int.from_bytes(value_bytes[cursor + 4:cursor + 8], "big", signed=False)
    record_length = int.from_bytes(value_bytes[cursor + 8:cursor + 10], "big", signed=False)
    record_data_offset = cursor + 10
    record_data_end = record_data_offset + record_length
    if record_data_end > len(value_bytes):
        raise ValueError("DNS resource record data is truncated.")
    record_data = value_bytes[record_data_offset:record_data_end]
    record_value = record_data.hex().upper()
    if record_type == 0x0001 and len(record_data) == 4:
        record_value = ".".join(str(octet) for octet in record_data)
    elif record_type == 0x001C and len(record_data) == 16:
        record_value = str(ipaddress.IPv6Address(record_data))
    elif record_type == 0x0005:
        record_value, _ = _decode_dns_name(value_bytes, record_data_offset)
    return {
        "name": record_name,
        "record_type": record_type,
        "record_class": record_class,
        "ttl_seconds": ttl_value,
        "value": record_value,
    }, record_data_end


def _try_decode_dns_query(value_bytes: bytes) -> str:
    if len(value_bytes) < 17:
        return ""
    flags = int.from_bytes(value_bytes[2:4], "big", signed=False)
    if (flags & 0x8000) != 0:
        return ""
    question_count = int.from_bytes(value_bytes[4:6], "big", signed=False)
    answer_count = int.from_bytes(value_bytes[6:8], "big", signed=False)
    authority_count = int.from_bytes(value_bytes[8:10], "big", signed=False)
    if question_count != 1 or answer_count != 0 or authority_count != 0:
        return ""
    try:
        question, _ = _parse_dns_question(value_bytes, 12)
    except Exception:
        return ""
    query_type = int(question.get("query_type", 0) or 0)
    query_class = int(question.get("query_class", 0) or 0)
    type_name = {
        0x0001: "A",
        0x001C: "AAAA",
    }.get(query_type, f"0x{query_type:04X}")
    class_name = {
        0x0001: "IN",
    }.get(query_class, f"0x{query_class:04X}")
    query_id = int.from_bytes(value_bytes[0:2], "big", signed=False)
    query_name = str(question.get("qname", "")).strip()
    if len(query_name) == 0:
        return ""
    return (
        f"DNS Query: id=0x{query_id:04X} "
        f"qname={query_name} type={type_name} class={class_name}"
    )


def _try_decode_dns_response(value_bytes: bytes) -> str:
    if len(value_bytes) < 12:
        return ""
    flags = int.from_bytes(value_bytes[2:4], "big", signed=False)
    if (flags & 0x8000) == 0:
        return ""
    question_count = int.from_bytes(value_bytes[4:6], "big", signed=False)
    answer_count = int.from_bytes(value_bytes[6:8], "big", signed=False)
    authority_count = int.from_bytes(value_bytes[8:10], "big", signed=False)
    additional_count = int.from_bytes(value_bytes[10:12], "big", signed=False)
    query_id = int.from_bytes(value_bytes[0:2], "big", signed=False)
    response_code = flags & 0x000F
    question_name = ""
    answer_summaries: list[str] = []
    try:
        offset = 12
        for question_index in range(question_count):
            question, offset = _parse_dns_question(value_bytes, offset)
            if question_index == 0:
                question_name = str(question.get("qname", "")).strip()
        for _ in range(min(answer_count, 6)):
            answer_record, offset = _parse_dns_resource_record(value_bytes, offset)
            record_type_name = _dns_record_type_name(int(answer_record.get("record_type", 0) or 0))
            record_value = str(answer_record.get("value", "")).strip()
            if len(record_value) == 0:
                continue
            answer_summaries.append(f"{record_type_name}:{record_value}")
    except Exception:
        question_name = ""
        answer_summaries = []
    summary_text = f"DNS Response: id=0x{query_id:04X}"
    if len(question_name) > 0:
        summary_text += f" qname={question_name}"
    summary_text += (
        f" qd={question_count} an={answer_count} "
        f"ns={authority_count} ar={additional_count} rcode={response_code}"
    )
    if len(answer_summaries) > 0:
        summary_text += f" answers={','.join(answer_summaries)}"
    return summary_text


def _try_decode_tls_records(value_bytes: bytes) -> list[str]:
    summaries: list[str] = []
    offset = 0
    while offset + 5 <= len(value_bytes):
        record_type = value_bytes[offset]
        major_version = value_bytes[offset + 1]
        record_length = int.from_bytes(value_bytes[offset + 3:offset + 5], "big", signed=False)
        record_end = offset + 5 + record_length
        if major_version != 0x03:
            return []
        if record_end > len(value_bytes):
            return []
        record_payload = value_bytes[offset + 5:record_end]
        record_name = _tls_record_type_name(record_type)
        if record_type == 0x16:
            handshake_summaries = _decode_tls_handshake_messages(record_payload)
            if len(handshake_summaries) == 0:
                summaries.append(f"TLS Record: {record_name} ({record_length} byte(s))")
            else:
                summaries.extend(handshake_summaries)
        elif record_type == 0x15 and len(record_payload) >= 2:
            alert_level = record_payload[0]
            alert_description = record_payload[1]
            summaries.append(
                "TLS Alert: "
                f"{_tls_alert_level_name(alert_level)} "
                f"{_tls_alert_description_name(alert_description)}"
            )
        else:
            summaries.append(f"TLS Record: {record_name} ({record_length} byte(s))")
        offset = record_end
    if offset == 0:
        return []
    return summaries


def _decode_tls_handshake_messages(value_bytes: bytes) -> list[str]:
    summaries: list[str] = []
    offset = 0
    while offset + 4 <= len(value_bytes):
        handshake_type = value_bytes[offset]
        handshake_length = int.from_bytes(value_bytes[offset + 1:offset + 4], "big", signed=False)
        next_offset = offset + 4 + handshake_length
        if next_offset > len(value_bytes):
            return summaries
        handshake_name = _tls_handshake_type_name(handshake_type)
        handshake_summary = f"TLS Handshake: {handshake_name}"
        if handshake_type == 0x01:
            server_name = _decode_tls_client_hello_server_name(value_bytes[offset + 4:next_offset])
            if len(server_name) > 0:
                handshake_summary += f" sni={server_name}"
        handshake_summary += f" ({handshake_length} byte(s))"
        summaries.append(handshake_summary)
        offset = next_offset
    return summaries


def _decode_tls_client_hello_server_name(handshake_body: bytes) -> str:
    if len(handshake_body) < 34:
        return ""
    cursor = 34
    session_id_length = int(handshake_body[cursor])
    cursor += 1
    session_id_end = cursor + session_id_length
    if session_id_end > len(handshake_body):
        return ""
    cursor = session_id_end
    if cursor + 2 > len(handshake_body):
        return ""
    cipher_suites_length = int.from_bytes(handshake_body[cursor:cursor + 2], "big", signed=False)
    cursor += 2
    cipher_suites_end = cursor + cipher_suites_length
    if cipher_suites_end > len(handshake_body):
        return ""
    cursor = cipher_suites_end
    if cursor >= len(handshake_body):
        return ""
    compression_methods_length = int(handshake_body[cursor])
    cursor += 1
    compression_methods_end = cursor + compression_methods_length
    if compression_methods_end > len(handshake_body):
        return ""
    cursor = compression_methods_end
    if cursor + 2 > len(handshake_body):
        return ""
    extensions_length = int.from_bytes(handshake_body[cursor:cursor + 2], "big", signed=False)
    cursor += 2
    extensions_end = cursor + extensions_length
    if extensions_end > len(handshake_body):
        return ""
    while cursor + 4 <= extensions_end:
        extension_type = int.from_bytes(handshake_body[cursor:cursor + 2], "big", signed=False)
        extension_length = int.from_bytes(handshake_body[cursor + 2:cursor + 4], "big", signed=False)
        cursor += 4
        extension_end = cursor + extension_length
        if extension_end > extensions_end:
            return ""
        if extension_type == 0x0000:
            server_name = _decode_tls_server_name_extension(handshake_body[cursor:extension_end])
            if len(server_name) > 0:
                return server_name
        cursor = extension_end
    return ""


def _decode_tls_server_name_extension(extension_value: bytes) -> str:
    if len(extension_value) < 5:
        return ""
    server_name_list_length = int.from_bytes(extension_value[0:2], "big", signed=False)
    server_name_list_end = 2 + server_name_list_length
    if server_name_list_end > len(extension_value):
        return ""
    cursor = 2
    while cursor + 3 <= server_name_list_end:
        name_type = int(extension_value[cursor])
        name_length = int.from_bytes(extension_value[cursor + 1:cursor + 3], "big", signed=False)
        cursor += 3
        name_end = cursor + name_length
        if name_end > server_name_list_end:
            return ""
        if name_type == 0x00:
            return _normalize_tls_server_name(extension_value[cursor:name_end])
        cursor = name_end
    return ""


def _normalize_tls_server_name(raw_name: bytes) -> str:
    try:
        normalized_name = raw_name.decode("ascii")
    except Exception:
        return ""
    normalized_name = normalized_name.strip().strip(".").lower()
    if len(normalized_name) == 0:
        return ""
    return normalized_name


def _tls_record_type_name(record_type: int) -> str:
    return {
        0x14: "ChangeCipherSpec",
        0x15: "Alert",
        0x16: "Handshake",
        0x17: "ApplicationData",
    }.get(int(record_type), f"0x{int(record_type):02X}")


def _tls_handshake_type_name(handshake_type: int) -> str:
    return {
        0x01: "ClientHello",
        0x02: "ServerHello",
        0x0B: "Certificate",
        0x0C: "ServerKeyExchange",
        0x0D: "CertificateRequest",
        0x0E: "ServerHelloDone",
        0x10: "ClientKeyExchange",
        0x14: "Finished",
    }.get(int(handshake_type), f"0x{int(handshake_type):02X}")


def _tls_alert_level_name(level: int) -> str:
    return {
        0x01: "warning",
        0x02: "fatal",
    }.get(int(level), f"0x{int(level):02X}")


def _tls_alert_description_name(description: int) -> str:
    return {
        0x0A: "unexpected_message",
        0x2A: "bad_certificate",
    }.get(int(description), f"0x{int(description):02X}")


def _try_decode_http_message(value_bytes: bytes) -> str:
    if len(value_bytes) < 8:
        return ""
    try:
        preview_text = value_bytes[:512].decode("iso-8859-1")
    except Exception:
        return ""
    first_line = str(preview_text.splitlines()[0] if len(preview_text.splitlines()) > 0 else "").strip()
    if len(first_line) == 0:
        return ""
    http_methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
    if any(first_line.startswith(f"{method} ") for method in http_methods) and " HTTP/" in first_line:
        parts = first_line.split()
        if len(parts) >= 2:
            return f"HTTP Request: {parts[0]} {parts[1]}"
    if first_line.startswith("HTTP/"):
        parts = first_line.split(None, 2)
        if len(parts) >= 2:
            if len(parts) >= 3:
                return f"HTTP Response: {parts[1]} {parts[2]}"
            return f"HTTP Response: {parts[1]}"
    return ""


def _parse_capture_time_seconds(time_text: str) -> float | None:
    normalized = str(time_text or "").strip()
    if len(normalized) == 0:
        return None
    try:
        return float(normalized)
    except Exception:
        pass
    if ":" in normalized:
        parts = normalized.split(":")
        if 2 <= len(parts) <= 3:
            try:
                numeric_parts = [float(part) for part in parts]
            except Exception:
                numeric_parts = []
            if len(numeric_parts) == len(parts):
                if len(numeric_parts) == 2:
                    minutes, seconds = numeric_parts
                    return (minutes * 60.0) + seconds
                hours, minutes, seconds = numeric_parts
                return (hours * 3600.0) + (minutes * 60.0) + seconds
    return None


def _format_duration_clock(total_seconds: int) -> str:
    normalized_seconds = max(0, int(total_seconds or 0))
    hours = normalized_seconds // 3600
    minutes = (normalized_seconds % 3600) // 60
    seconds = normalized_seconds % 60
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _timer_display_label(timer_id: int, display_label: str = "") -> str:
    normalized_label = str(display_label or "").strip()
    if len(normalized_label) > 0:
        return normalized_label
    return f"T{int(timer_id)}"


def _timer_remaining_seconds(timer_state: _TimerState, at_seconds: float | None) -> int:
    if timer_state.observed_at_seconds is not None:
        baseline_remaining = int(timer_state.observed_remaining_seconds)
    else:
        baseline_remaining = int(timer_state.value_seconds or 0)
    if timer_state.active is False:
        return max(0, baseline_remaining)
    observed_at_seconds = timer_state.observed_at_seconds
    if at_seconds is None or observed_at_seconds is None:
        return max(0, baseline_remaining)
    elapsed_seconds = max(0.0, float(at_seconds) - float(observed_at_seconds))
    if elapsed_seconds <= 0.0:
        return max(0, baseline_remaining)
    return max(0, int(math.ceil(float(baseline_remaining) - elapsed_seconds)))


def _path_text(path: tuple[str, ...]) -> str:
    normalized = [str(part or "").strip() for part in tuple(path or ()) if len(str(part or "").strip()) > 0]
    if len(normalized) == 0:
        return "MF"
    return "/".join(normalized)


def _path_is_under(path: tuple[str, ...], parent_path: tuple[str, ...]) -> bool:
    if len(parent_path) == 0:
        return True
    if len(path) < len(parent_path):
        return False
    return tuple(path[:len(parent_path)]) == tuple(parent_path)


def _path_kind(path: tuple[str, ...]) -> str:
    if len(path) == 0:
        return "mf"
    leaf = str(path[-1] or "").strip().upper()
    if leaf == "MF":
        return "mf"
    if leaf.startswith("ADF.") or leaf in {"ISD-R", "ECASD", "MNO-SD"} or leaf.startswith("AID "):
        return "adf"
    if leaf.startswith("DF."):
        return "df"
    return "ef"


def _status_word_text(sw1: int, sw2: int) -> str:
    return f"{int(sw1) & 0xFF:02X}{int(sw2) & 0xFF:02X}"


def _apdu_succeeded(sw1: int, sw2: int) -> bool:
    del sw2
    if int(sw1) in {0x90, 0x91, 0x9F, 0x61, 0x62, 0x63}:
        return True
    return False


def _channel_endpoint(fields: dict[str, object]) -> str:
    remote_address = str(fields.get("remote_address", "") or "").strip()
    remote_port = int(fields.get("transport_port", 0) or 0)
    if len(remote_address) > 0 and remote_port > 0:
        return f"{remote_address}:{remote_port}"
    if len(remote_address) > 0:
        return remote_address
    if remote_port > 0:
        return str(remote_port)
    return "unknown"


def _decode_network_access_name(value_bytes: bytes) -> str:
    parts: list[str] = []
    offset = 0
    while offset < len(value_bytes):
        label_length = int(value_bytes[offset])
        offset += 1
        if label_length <= 0:
            break
        label_end = offset + label_length
        if label_end > len(value_bytes):
            break
        label = value_bytes[offset:label_end]
        offset = label_end
        parts.append(label.decode("ascii", "ignore"))
    return ".".join(part for part in parts if len(part) > 0)


def _decode_other_address(value_bytes: bytes) -> str:
    if len(value_bytes) == 5 and int(value_bytes[0]) == 0x21:
        return ".".join(str(part) for part in value_bytes[1:])
    if len(value_bytes) == 17 and int(value_bytes[0]) == 0x57:
        hex_groups = [value_bytes[index : index + 2].hex() for index in range(1, 17, 2)]
        return ":".join(hex_groups)
    return ""


def _extract_timer_id(fields: dict[str, object]) -> int:
    timer_identifier = bytes(fields.get("timer_identifier_value", b"") or b"")
    if len(timer_identifier) == 0:
        return 1
    return int(timer_identifier[0]) & 0xFF


def _decode_timer_value_seconds(value_bytes: bytes) -> int:
    if len(value_bytes) != 3:
        return 0
    hours = _decode_bcd(value_bytes[0])
    minutes = _decode_bcd(value_bytes[1])
    seconds = _decode_bcd(value_bytes[2])
    return max(0, (hours * 3600) + (minutes * 60) + seconds)


def _decode_duration_seconds(value_bytes: bytes) -> int:
    if len(value_bytes) != 2:
        return 0
    time_unit = int(value_bytes[0]) & 0xFF
    time_interval = int(value_bytes[1]) & 0xFF
    if time_interval <= 0:
        return 0
    if time_unit == 0x00:
        return time_interval * 60
    if time_unit == 0x01:
        return time_interval
    if time_unit == 0x02:
        return int(math.ceil(float(time_interval) / 10.0))
    return 0


def _decode_bcd(value: int) -> int:
    return ((int(value) & 0x0F) * 10) + ((int(value) >> 4) & 0x0F)


def _decode_iccid_bytes(iccid_bytes: bytes) -> str:
    # ETSI TS 102.221 §13.2 / 3GPP TS 51.011: EF.ICCID stores the ICCID
    # as up to 20 BCD digits across 10 bytes, with swapped nibbles.
    # Each byte `b` encodes digit1 = (b & 0x0F) first, digit2 = (b >> 4)
    # second. A trailing 0xF nibble marks the end of a 19-digit ICCID.
    digits: list[str] = []
    for raw_byte in iccid_bytes:
        low_nibble = int(raw_byte) & 0x0F
        high_nibble = (int(raw_byte) >> 4) & 0x0F
        if low_nibble == 0xF:
            break
        if low_nibble > 9:
            return ""
        digits.append(str(low_nibble))
        if high_nibble == 0xF:
            break
        if high_nibble > 9:
            return ""
        digits.append(str(high_nibble))
    if len(digits) < 18 or len(digits) > 20:
        return ""
    return "".join(digits)


def _transport_protocol_name(protocol_type: int) -> str:
    return {
        0x01: "UDP REMOTE",
        0x02: "TCP CLIENT REMOTE",
        0x03: "TCP SERVER",
        0x04: "UDP LOCAL",
    }.get(int(protocol_type) & 0xFF, f"0x{int(protocol_type) & 0xFF:02X}")


def _proactive_command_name(command_type: int) -> str:
    return _PROACTIVE_COMMAND_NAMES.get(int(command_type), f"0x{int(command_type):02X}")


def _event_name(event_code: int) -> str:
    return _EVENT_NAMES.get(int(event_code), f"EVENT 0x{int(event_code):02X}")


def _result_succeeded(result_code: int) -> bool:
    if int(result_code) in {0x00, 0x01}:
        return True
    return False


def _protocol_label(protocol_name: str) -> str:
    return str(protocol_name or "").strip().lower().replace(" ", "-")
