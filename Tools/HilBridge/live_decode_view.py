# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
"""HIL-Bridge live-decode view: scrollable Rich panel rendering the current decoded APDU tree."""
from __future__ import annotations

import csv
import curses
import io
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree

DEFAULT_DECODE_RULE = "udp.port==4729,gsmtap"
SUMMARY_REFRESH_SECONDS = 0.35


@dataclass(frozen=True, slots=True)
class PacketSummary:
    number: int
    time_text: str
    source: str
    destination: str
    protocol: str
    length_text: str
    info: str
    wall_time_text: str = ""
    udp_payload_hex: str = ""
    epoch_time_text: str = ""


@dataclass(slots=True)
class _ViewerState:
    rows: list[PacketSummary] = field(default_factory=list)
    selected_index: int = 0
    summary_offset: int = 0
    detail_offset: int = 0
    bytes_offset: int = 0
    active_pane: str = "summary"
    follow_tail: bool = True
    last_capture_size: int = -1
    last_refresh_at: float = 0.0
    last_error: str = ""
    detail_cache: dict[int, str] = field(default_factory=dict)
    bytes_cache: dict[int, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _PaneSpec:
    kind: str
    title: str
    y: int
    height: int


def resolve_tshark_binary(preferred_path: str = "") -> str:
    """Locate the tshark binary on PATH and return its absolute path."""
    preferred = str(preferred_path or "").strip()
    if len(preferred) > 0:
        if os.path.isfile(preferred):
            return preferred
        resolved_preferred = shutil.which(preferred)
        if resolved_preferred is not None:
            return resolved_preferred
    resolved = shutil.which("tshark")
    if resolved is None:
        return ""
    return resolved


def build_summary_command(
    capture_path: str,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
    frame_filter: str = "",
) -> list[str]:
    """Build the tshark command-line args list for the packet-summary view."""
    command = [
        str(tshark_binary or "tshark"),
        "-r",
        str(capture_path or ""),
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "_ws.col.Time",
        "-e",
        "frame.time_epoch",
        "-e",
        "_ws.col.Source",
        "-e",
        "_ws.col.Destination",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Length",
        "-e",
        "_ws.col.Info",
        "-e",
        "udp.payload",
    ]
    normalized_filter = str(frame_filter or "").strip()
    if len(normalized_filter) > 0:
        command.extend(["-Y", normalized_filter])
    command.extend(["-d", str(decode_rule or DEFAULT_DECODE_RULE)])
    return command


def build_packet_detail_command(
    capture_path: str,
    frame_number: int,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> list[str]:
    """Build the tshark command-line args list for the packet-detail view."""
    frame_number_int = int(frame_number)
    frame_filter = f"(frame.number >= {frame_number_int}) and (frame.number < {frame_number_int + 1})"
    return [
        str(tshark_binary or "tshark"),
        "-r",
        str(capture_path or ""),
        "-V",
        "-Y",
        frame_filter,
        "-d",
        str(decode_rule or DEFAULT_DECODE_RULE),
    ]


def build_packet_hex_command(
    capture_path: str,
    frame_number: int,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> list[str]:
    """Build the tshark command-line args list for the packet hex-dump view."""
    frame_number_int = int(frame_number)
    frame_filter = f"(frame.number >= {frame_number_int}) and (frame.number < {frame_number_int + 1})"
    return [
        str(tshark_binary or "tshark"),
        "-r",
        str(capture_path or ""),
        "-x",
        "-Y",
        frame_filter,
        "-d",
        str(decode_rule or DEFAULT_DECODE_RULE),
    ]


def build_packet_field_range_command(
    capture_path: str,
    frame_number: int,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> list[str]:
    """Build the tshark command-line args list for selected-frame PDML ranges."""
    frame_number_int = int(frame_number)
    frame_filter = f"(frame.number >= {frame_number_int}) and (frame.number < {frame_number_int + 1})"
    return [
        str(tshark_binary or "tshark"),
        "-r",
        str(capture_path or ""),
        "-T",
        "pdml",
        "-Y",
        frame_filter,
        "-d",
        str(decode_rule or DEFAULT_DECODE_RULE),
    ]


def parse_summary_output(output_text: str) -> list[PacketSummary]:
    """Parse a list of raw summary output lines into structured packet-summary dicts."""
    rows: list[PacketSummary] = []
    reader = csv.reader(
        io.StringIO(str(output_text or "")),
        delimiter="\t",
        quotechar='"',
    )
    for raw_row in reader:
        if len(raw_row) == 0:
            continue
        padded = list(raw_row[:9])
        while len(padded) < 9:
            padded.append("")
        number_text = str(padded[0] or "").strip()
        if len(number_text) == 0:
            continue
        try:
            frame_number = int(number_text)
        except Exception:
            continue
        wall_time_text = ""
        epoch_time_text = ""
        source_index = 2
        destination_index = 3
        protocol_index = 4
        length_index = 5
        info_index = 6
        payload_index = 7
        if len(raw_row) >= 9:
            epoch_time_text = str(padded[2] or "").strip()
            wall_time_text = _format_wall_clock_text(epoch_time_text)
            source_index = 3
            destination_index = 4
            protocol_index = 5
            length_index = 6
            info_index = 7
            payload_index = 8
        rows.append(
            PacketSummary(
                number=frame_number,
                time_text=str(padded[1] or "").strip(),
                source=str(padded[source_index] or "").strip(),
                destination=str(padded[destination_index] or "").strip(),
                protocol=str(padded[protocol_index] or "").strip(),
                length_text=str(padded[length_index] or "").strip(),
                info=str(padded[info_index] or "").strip(),
                wall_time_text=wall_time_text,
                udp_payload_hex=str(padded[payload_index] or "").strip().replace(":", "").upper(),
                epoch_time_text=epoch_time_text,
            )
        )
    return rows


def parse_packet_field_ranges(pdml_text: str) -> list[dict[str, object]]:
    """Parse tshark PDML field byte ranges for Wireshark-style highlighting."""
    normalized = str(pdml_text or "").strip()
    if len(normalized) == 0:
        return []
    try:
        root = ElementTree.fromstring(normalized)
    except ElementTree.ParseError:
        return []

    ranges: list[dict[str, object]] = []

    def _walk(node: ElementTree.Element, depth: int) -> None:
        tag = _xml_local_name(node.tag)
        if tag in {"proto", "field"}:
            parsed = _pdml_node_range(node, depth)
            if parsed is not None:
                ranges.append(parsed)
            next_depth = depth + 1 if tag == "field" else depth
        else:
            next_depth = depth
        for child in list(node):
            _walk(child, next_depth)

    _walk(root, 0)
    ranges.sort(
        key=lambda item: (
            int(item.get("start", 0) or 0),
            int(item.get("size", 0) or 0),
            str(item.get("name", "") or ""),
        )
    )
    return ranges


def _xml_local_name(tag: str) -> str:
    text = str(tag or "")
    if "}" in text:
        return text.rsplit("}", 1)[1]
    return text


def _pdml_node_range(node: ElementTree.Element, depth: int) -> dict[str, object] | None:
    attrs = dict(node.attrib or {})
    if str(attrs.get("hide", "")).lower() == "yes":
        return None
    try:
        start = int(str(attrs.get("pos", "")).strip())
        size = int(str(attrs.get("size", "")).strip())
    except (TypeError, ValueError):
        return None
    if start < 0 or size <= 0:
        return None
    name = str(attrs.get("name", "") or "").strip()
    show = str(attrs.get("show", "") or "").strip()
    showname = str(attrs.get("showname", "") or "").strip()
    value = str(attrs.get("value", "") or "").strip()
    label = showname or (f"{name}: {show}" if name and show else name or show)
    return {
        "name": name,
        "label": label,
        "show": show,
        "value": value.upper(),
        "start": start,
        "end": start + size,
        "size": size,
        "depth": max(0, int(depth or 0)),
    }


def _format_wall_clock_text(epoch_text: str) -> str:
    normalized_epoch = str(epoch_text or "").strip()
    if len(normalized_epoch) == 0:
        return ""
    try:
        epoch_seconds = float(normalized_epoch)
    except Exception:
        return ""
    try:
        timestamp = datetime.fromtimestamp(epoch_seconds)
    except Exception:
        return ""
    milliseconds = int(timestamp.microsecond / 1000)
    return f"{timestamp:%H:%M:%S}.{milliseconds:03d}"


def _local_tshark_config_home(capture_path: str) -> str:
    normalized_path = str(capture_path or "").strip()
    if len(normalized_path) == 0:
        config_root = Path.cwd() / "state" / "hil_termshark" / "tshark_cfg"
    else:
        config_root = Path(normalized_path).expanduser().resolve().parent / "tshark_cfg"
    wireshark_root = config_root / "wireshark"
    wireshark_root.mkdir(parents=True, exist_ok=True)
    return str(config_root)


def _streaming_tshark_command(command: list[str]) -> list[str]:
    normalized_command = list(command)
    try:
        read_index = normalized_command.index("-r")
    except ValueError:
        return normalized_command
    if read_index + 1 >= len(normalized_command):
        return normalized_command
    normalized_command[read_index + 1] = "-"
    return normalized_command


def _run_tshark_text_command(
    command: list[str],
    *,
    timeout_seconds: float = 10.0,
    capture_path: str = "",
) -> tuple[str, str]:
    normalized_capture_path = str(capture_path or "").strip()
    prepared_command = list(command)
    environment = dict(os.environ)
    stdin_handle = None
    stdin_stream = subprocess.DEVNULL
    if len(normalized_capture_path) > 0:
        prepared_command = _streaming_tshark_command(prepared_command)
        try:
            environment["XDG_CONFIG_HOME"] = _local_tshark_config_home(normalized_capture_path)
        except Exception:
            pass
        try:
            stdin_handle = open(normalized_capture_path, "rb")
        except Exception as exc:
            return ("", str(exc))
        stdin_stream = stdin_handle
    try:
        completed = subprocess.run(
            prepared_command,
            capture_output=True,
            text=True,
            timeout=max(1.0, float(timeout_seconds or 10.0)),
            check=False,
            env=environment,
            stdin=stdin_stream,
        )
    except Exception as exc:
        if stdin_handle is not None:
            try:
                stdin_handle.close()
            except Exception:
                pass
        return ("", str(exc))
    if stdin_handle is not None:
        try:
            stdin_handle.close()
        except Exception:
            pass
    stdout_text = str(completed.stdout or "")
    stderr_text = str(completed.stderr or "").strip()
    if completed.returncode != 0 and len(stdout_text.strip()) == 0:
        return ("", stderr_text or f"tshark exited with code {completed.returncode}")
    return (stdout_text, stderr_text)


def read_packet_summaries(
    capture_path: str,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
    after_frame: int | None = None,
) -> tuple[list[PacketSummary], str]:
    """Read packet summaries from the active capture source and return a list of dicts."""
    normalized_path = str(capture_path or "").strip()
    if len(normalized_path) == 0:
        return ([], "Missing capture path.")
    target_path = Path(normalized_path)
    if target_path.is_file() is False:
        return ([], "")
    if target_path.stat().st_size <= 24:
        return ([], "")
    frame_filter = ""
    if after_frame is not None and after_frame > 0:
        frame_filter = f"frame.number > {int(after_frame)}"
    stdout_text, stderr_text = _run_tshark_text_command(
        build_summary_command(
            normalized_path,
            tshark_binary=tshark_binary,
            decode_rule=decode_rule,
            frame_filter=frame_filter,
        ),
        capture_path=normalized_path,
    )
    return (parse_summary_output(stdout_text), stderr_text)


def read_packet_detail(
    capture_path: str,
    frame_number: int,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> tuple[str, str]:
    """Read the full decoded detail for the packet at *index* and return a dict."""
    return _run_tshark_text_command(
        build_packet_detail_command(
            capture_path,
            frame_number,
            tshark_binary=tshark_binary,
            decode_rule=decode_rule,
        ),
        capture_path=capture_path,
    )


def read_packet_hex(
    capture_path: str,
    frame_number: int,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> tuple[str, str]:
    """Read the raw hex dump for the packet at *index* and return a string."""
    return _run_tshark_text_command(
        build_packet_hex_command(
            capture_path,
            frame_number,
            tshark_binary=tshark_binary,
            decode_rule=decode_rule,
        ),
        capture_path=capture_path,
    )


def read_packet_field_ranges(
    capture_path: str,
    frame_number: int,
    *,
    tshark_binary: str = "tshark",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> tuple[list[dict[str, object]], str]:
    """Read selected-frame PDML and return field byte ranges."""
    stdout_text, stderr_text = _run_tshark_text_command(
        build_packet_field_range_command(
            capture_path,
            frame_number,
            tshark_binary=tshark_binary,
            decode_rule=decode_rule,
        ),
        capture_path=capture_path,
    )
    return (parse_packet_field_ranges(stdout_text), stderr_text)


def _clip_text(text: str, width: int) -> str:
    available = max(0, int(width or 0))
    if available <= 0:
        return ""
    normalized = str(text or "").replace("\t", "    ")
    if len(normalized) <= available:
        return normalized
    if available <= 3:
        return normalized[:available]
    return normalized[: available - 3] + "..."


def _file_size(path_text: str) -> int:
    normalized_path = str(path_text or "").strip()
    if len(normalized_path) == 0:
        return -1
    try:
        return int(os.path.getsize(normalized_path))
    except Exception:
        return -1


def _summary_row_text(row: PacketSummary, width: int) -> str:
    time_text = _clip_text(_summary_display_time_text(row), 12)
    protocol_text = _clip_text(row.protocol, 12)
    length_text = _clip_text(row.length_text, 6)
    route_text = ""
    if width >= 96:
        visible_route_text = _summary_route_text(row)
        if len(visible_route_text) > 0:
            route_text = _clip_text(visible_route_text, 26)
    prefix_parts = [f"{row.number:>5}", f"{time_text:<12}"]
    if len(route_text) > 0:
        prefix_parts.append(f"{route_text:<26}")
    prefix_parts.append(f"{protocol_text:<12}")
    prefix_parts.append(f"{length_text:>6}")
    prefix = " ".join(prefix_parts)
    remainder_width = max(0, width - len(prefix) - 1)
    info_text = _clip_text(row.info, remainder_width)
    if len(info_text) == 0:
        return prefix
    return f"{prefix} {info_text}"


def _summary_display_time_text(row: PacketSummary) -> str:
    wall_time_text = str(getattr(row, "wall_time_text", "") or "").strip()
    if len(wall_time_text) > 0:
        return wall_time_text
    return str(row.time_text or "").strip()


def _summary_route_text(row: PacketSummary) -> str:
    source_text = str(row.source or "").strip()
    destination_text = str(row.destination or "").strip()
    if len(source_text) == 0 or len(destination_text) == 0:
        return ""
    if source_text == destination_text:
        return ""
    if _is_hidden_transport_endpoint(source_text) and _is_hidden_transport_endpoint(destination_text):
        return ""
    return f"{source_text} -> {destination_text}"


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


class _Palette:
    CAPTION = 1
    BORDER = 2
    TEXT = 3
    MUTED = 4
    SELECTED = 5
    ACCENT = 6
    WARNING = 7
    SECTION = 8
    ACTIVE_CAPTION = 9


def _init_palette() -> None:
    curses.start_color()
    curses.use_default_colors()
    if curses.COLORS >= 256:
        curses.init_pair(_Palette.CAPTION, 254, 239)
        curses.init_pair(_Palette.BORDER, 110, 235)
        curses.init_pair(_Palette.TEXT, 255, 235)
        curses.init_pair(_Palette.MUTED, 250, 235)
        curses.init_pair(_Palette.SELECTED, 235, 223)
        curses.init_pair(_Palette.ACCENT, 110, 235)
        curses.init_pair(_Palette.WARNING, 174, 235)
        curses.init_pair(_Palette.SECTION, 255, 239)
        curses.init_pair(_Palette.ACTIVE_CAPTION, 223, 239)
        return
    curses.init_pair(_Palette.CAPTION, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(_Palette.BORDER, curses.COLOR_CYAN, -1)
    curses.init_pair(_Palette.TEXT, curses.COLOR_WHITE, -1)
    curses.init_pair(_Palette.MUTED, curses.COLOR_CYAN, -1)
    curses.init_pair(_Palette.SELECTED, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    curses.init_pair(_Palette.ACCENT, curses.COLOR_CYAN, -1)
    curses.init_pair(_Palette.WARNING, curses.COLOR_RED, -1)
    curses.init_pair(_Palette.SECTION, curses.COLOR_WHITE, curses.COLOR_BLUE)
    curses.init_pair(_Palette.ACTIVE_CAPTION, curses.COLOR_YELLOW, curses.COLOR_BLUE)


def _safe_addstr(window, y: int, x: int, text: str, attributes: int = 0) -> None:
    try:
        window.addstr(int(y), int(x), str(text or ""), attributes)
    except curses.error:
        return


def _draw_box(window, y: int, x: int, height: int, width: int, title: str, *, active: bool) -> None:
    if height < 3 or width < 4:
        return
    attr_border = curses.color_pair(_Palette.BORDER)
    attr_caption = curses.color_pair(_Palette.ACTIVE_CAPTION if active else _Palette.CAPTION) | curses.A_BOLD
    for current_x in range(x + 1, x + width - 1):
        _safe_addstr(window, y, current_x, "-", attr_border)
        _safe_addstr(window, y + height - 1, current_x, "-", attr_border)
    for current_y in range(y + 1, y + height - 1):
        _safe_addstr(window, current_y, x, "|", attr_border)
        _safe_addstr(window, current_y, x + width - 1, "|", attr_border)
    _safe_addstr(window, y, x, "+", attr_border)
    _safe_addstr(window, y, x + width - 1, "+", attr_border)
    _safe_addstr(window, y + height - 1, x, "+", attr_border)
    _safe_addstr(window, y + height - 1, x + width - 1, "+", attr_border)
    caption_text = f" {str(title or '').strip()} "
    available = max(0, width - 4)
    _safe_addstr(window, y, x + 2, _clip_text(caption_text, available), attr_caption)
    fill_attr = curses.color_pair(_Palette.TEXT)
    blank_line = " " * max(0, width - 2)
    for current_y in range(y + 1, y + height - 1):
        _safe_addstr(window, current_y, x + 1, blank_line, fill_attr)


def _draw_summary_rows(window, y: int, x: int, height: int, width: int, state: _ViewerState) -> None:
    if height <= 0 or width <= 0:
        return
    if len(state.rows) == 0:
        _safe_addstr(
            window,
            y,
            x,
            _clip_text("Waiting for GSMTAP packets...", width),
            curses.color_pair(_Palette.MUTED),
        )
        return
    visible_rows = max(1, height)
    max_offset = max(0, len(state.rows) - visible_rows)
    state.summary_offset = max(0, min(state.summary_offset, max_offset))
    if state.selected_index < state.summary_offset:
        state.summary_offset = state.selected_index
    if state.selected_index >= state.summary_offset + visible_rows:
        state.summary_offset = state.selected_index - visible_rows + 1
    start = state.summary_offset
    end = min(len(state.rows), start + visible_rows)
    for screen_row, row_index in enumerate(range(start, end)):
        row = state.rows[row_index]
        attributes = curses.color_pair(_Palette.TEXT)
        if row_index == state.selected_index:
            attributes = curses.color_pair(_Palette.SELECTED) | curses.A_BOLD
        _safe_addstr(
            window,
            y + screen_row,
            x,
            _clip_text(_summary_row_text(row, width), width),
            attributes,
        )


def _render_detail_line(window, y: int, x: int, width: int, raw_line: str) -> None:
    if width <= 0:
        return
    normalized = str(raw_line or "").replace("\t", "    ")
    stripped = normalized.strip()
    if len(stripped) == 0:
        return
    if normalized[:1] not in (" ",):
        _safe_addstr(window, y, x, _clip_text(stripped, width), curses.color_pair(_Palette.SECTION) | curses.A_BOLD)
        return
    if ":" in stripped:
        indent_width = len(normalized) - len(normalized.lstrip(" "))
        indent_text = " " * min(indent_width, max(0, width - 1))
        key_text, remainder = stripped.split(":", 1)
        _safe_addstr(window, y, x, indent_text, curses.color_pair(_Palette.MUTED))
        cursor_x = x + len(indent_text)
        available = max(0, width - len(indent_text))
        key_segment = _clip_text(f"{key_text}:", available)
        _safe_addstr(window, y, cursor_x, key_segment, curses.color_pair(_Palette.ACCENT) | curses.A_BOLD)
        cursor_x += len(key_segment)
        remainder_text = _clip_text(remainder.strip(), max(0, x + width - cursor_x))
        if len(remainder_text) > 0 and cursor_x < x + width:
            _safe_addstr(window, y, cursor_x, f" {remainder_text}", curses.color_pair(_Palette.TEXT))
        return
    _safe_addstr(window, y, x, _clip_text(normalized, width), curses.color_pair(_Palette.TEXT))


def _render_hex_line(window, y: int, x: int, width: int, raw_line: str) -> None:
    if width <= 0:
        return
    normalized = str(raw_line or "").rstrip()
    stripped = normalized.strip()
    if len(stripped) == 0:
        return
    parts = stripped.split(None, 1)
    if len(parts) == 2 and len(parts[0]) in {4, 8}:
        offset_text = parts[0]
        rest_text = parts[1]
        _safe_addstr(window, y, x, _clip_text(offset_text, width), curses.color_pair(_Palette.ACCENT) | curses.A_BOLD)
        remaining_width = max(0, width - len(offset_text) - 1)
        if remaining_width > 0:
            _safe_addstr(
                window,
                y,
                x + len(offset_text),
                f" {_clip_text(rest_text, remaining_width)}",
                curses.color_pair(_Palette.TEXT),
            )
        return
    _safe_addstr(window, y, x, _clip_text(stripped, width), curses.color_pair(_Palette.TEXT))


def _draw_scrolled_text(
    window,
    y: int,
    x: int,
    height: int,
    width: int,
    raw_text: str,
    scroll_offset: int,
    *,
    renderer,
) -> int:
    lines = str(raw_text or "").splitlines()
    if len(lines) == 0:
        return 0
    visible_rows = max(1, height)
    max_offset = max(0, len(lines) - visible_rows)
    normalized_offset = max(0, min(scroll_offset, max_offset))
    start = normalized_offset
    end = min(len(lines), start + visible_rows)
    for screen_row, line_index in enumerate(range(start, end)):
        renderer(window, y + screen_row, x, width, lines[line_index])
    return normalized_offset


def _selected_frame_number(state: _ViewerState) -> int | None:
    if len(state.rows) == 0:
        return None
    if state.selected_index < 0 or state.selected_index >= len(state.rows):
        return None
    return int(state.rows[state.selected_index].number)


def _selected_detail_text(
    capture_path: str,
    state: _ViewerState,
    *,
    tshark_binary: str,
    decode_rule: str,
) -> str:
    frame_number = _selected_frame_number(state)
    if frame_number is None:
        return "No packet selected."
    cached = state.detail_cache.get(frame_number)
    if cached is not None:
        return cached
    detail_text, error_text = read_packet_detail(
        capture_path,
        frame_number,
        tshark_binary=tshark_binary,
        decode_rule=decode_rule,
    )
    if len(str(error_text or "").strip()) > 0 and len(str(detail_text or "").strip()) == 0:
        detail_text = f"Decode load error: {error_text}"
        state.last_error = str(error_text or "").strip()
    state.detail_cache[frame_number] = detail_text
    return detail_text


def _selected_hex_text(
    capture_path: str,
    state: _ViewerState,
    *,
    tshark_binary: str,
    decode_rule: str,
) -> str:
    frame_number = _selected_frame_number(state)
    if frame_number is None:
        return "No packet selected."
    cached = state.bytes_cache.get(frame_number)
    if cached is not None:
        return cached
    hex_text, error_text = read_packet_hex(
        capture_path,
        frame_number,
        tshark_binary=tshark_binary,
        decode_rule=decode_rule,
    )
    if len(str(error_text or "").strip()) > 0 and len(str(hex_text or "").strip()) == 0:
        hex_text = f"Hex load error: {error_text}"
        state.last_error = str(error_text or "").strip()
    state.bytes_cache[frame_number] = hex_text
    return hex_text


def _status_text(
    capture_path: str,
    state: _ViewerState,
    startup_state: dict[str, object] | None,
) -> str:
    file_size = _file_size(capture_path)
    selected = _selected_frame_number(state)
    if isinstance(startup_state, dict):
        error_text = str(startup_state.get("error", "") or "").strip()
        if len(error_text) > 0:
            return f"Bridge start failed: {error_text}"
        if bool(startup_state.get("activation_complete", False)) is False:
            return f"Bridge warm-up in progress | Capture file {max(0, file_size)} bytes"
    if len(state.rows) == 0:
        if file_size >= 24:
            return f"Capture armed | Waiting for APDUs | File {file_size} bytes"
        return "Waiting for bridge-owned capture file..."
    follow_text = "follow tail" if state.follow_tail else "manual browse"
    return (
        f"Packets {len(state.rows)} | "
        f"Selected #{selected if selected is not None else '-'} | "
        f"File {max(0, file_size)} bytes | "
        f"{follow_text}"
    )


def _compute_pane_specs(height: int, active_pane: str) -> list[_PaneSpec]:
    total_height = max(0, int(height or 0))
    body_height = max(0, total_height - 2)
    if body_height >= 15:
        summary_height = max(4, body_height // 4)
        bytes_height = max(4, body_height // 4)
        detail_height = body_height - summary_height - bytes_height
        while detail_height < 4 and summary_height > 4:
            summary_height -= 1
            detail_height += 1
        while detail_height < 4 and bytes_height > 4:
            bytes_height -= 1
            detail_height += 1
        if detail_height < 4:
            detail_height = 4
            remaining = max(0, body_height - detail_height)
            summary_height = max(4, remaining // 2)
            bytes_height = max(4, remaining - summary_height)
        top_y = 1
        detail_y = top_y + summary_height
        bytes_y = detail_y + detail_height
        return [
            _PaneSpec("summary", "Summary", top_y, summary_height),
            _PaneSpec("detail", "Decoded", detail_y, detail_height),
            _PaneSpec("bytes", "Bytes", bytes_y, body_height - summary_height - detail_height),
        ]
    if body_height >= 8:
        summary_height = max(4, min(6, body_height // 2))
        content_height = body_height - summary_height
        content_kind = "bytes" if active_pane == "bytes" else "detail"
        content_title = "Bytes" if content_kind == "bytes" else "Decoded"
        return [
            _PaneSpec("summary", "Summary", 1, summary_height),
            _PaneSpec(content_kind, content_title, 1 + summary_height, content_height),
        ]
    if body_height >= 3:
        pane_kind = active_pane
        if pane_kind not in {"summary", "detail", "bytes"}:
            pane_kind = "summary"
        pane_title = {
            "summary": "Summary",
            "detail": "Decoded",
            "bytes": "Bytes",
        }[pane_kind]
        return [
            _PaneSpec(pane_kind, pane_title, 1, body_height),
        ]
    return []


def _refresh_state(
    capture_path: str,
    state: _ViewerState,
    *,
    tshark_binary: str,
    decode_rule: str,
    force: bool = False,
) -> None:
    current_time =time.monotonic()
    if force is False and current_time - state.last_refresh_at < SUMMARY_REFRESH_SECONDS:
        return
    state.last_refresh_at = current_time
    current_size = _file_size(capture_path)
    if current_size < state.last_capture_size:
        state.rows = []
        state.selected_index = 0
        state.summary_offset = 0
        state.detail_offset = 0
        state.bytes_offset = 0
        state.detail_cache.clear()
        state.bytes_cache.clear()
    if force is False and current_size == state.last_capture_size and len(state.rows) > 0:
        return
    previous_frame = _selected_frame_number(state)
    rows, error_text = read_packet_summaries(
        capture_path,
        tshark_binary=tshark_binary,
        decode_rule=decode_rule,
    )
    state.last_capture_size = current_size
    if len(str(error_text or "").strip()) > 0:
        state.last_error = str(error_text or "").strip()
    if len(rows) == 0:
        state.rows = []
        state.selected_index = 0
        return
    state.rows = rows
    if state.follow_tail:
        state.selected_index = len(rows) - 1
    elif previous_frame is not None:
        for index, row in enumerate(rows):
            if row.number == previous_frame:
                state.selected_index = index
                break
        else:
            state.selected_index = min(state.selected_index, len(rows) - 1)
    else:
        state.selected_index = min(state.selected_index, len(rows) - 1)


def run_live_decode_view(
    capture_path: str,
    *,
    service_name: str,
    capture_filter: str,
    startup_state: dict[str, object] | None = None,
    tshark_binary: str = "",
    decode_rule: str = DEFAULT_DECODE_RULE,
) -> None:
    """Start the live-decode view, connecting to the bridge and entering the display loop."""
    resolved_tshark = resolve_tshark_binary(tshark_binary)
    if len(resolved_tshark) == 0:
        raise RuntimeError("tshark is not available for the terminal decode viewer.")
    state = _ViewerState()

    def _run(stdscr) -> None:
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(120)
        _init_palette()
        stdscr.bkgd(" ", curses.color_pair(_Palette.TEXT))
        while True:
            _refresh_state(
                capture_path,
                state,
                tshark_binary=resolved_tshark,
                decode_rule=decode_rule,
            )
            height, width = stdscr.getmaxyx()
            stdscr.erase()
            header_text = _clip_text(
                f" HIL Terminal Decode | Service {service_name} | Filter {capture_filter} ",
                max(0, width),
            )
            _safe_addstr(stdscr, 0, 0, header_text.ljust(max(0, width)), curses.color_pair(_Palette.CAPTION) | curses.A_BOLD)
            pane_specs = _compute_pane_specs(height, state.active_pane)
            for pane in pane_specs:
                _draw_box(
                    stdscr,
                    pane.y,
                    0,
                    pane.height,
                    width,
                    pane.title,
                    active=state.active_pane == pane.kind,
                )
            detail_text = _selected_detail_text(
                capture_path,
                state,
                tshark_binary=resolved_tshark,
                decode_rule=decode_rule,
            )
            bytes_text = _selected_hex_text(
                capture_path,
                state,
                tshark_binary=resolved_tshark,
                decode_rule=decode_rule,
            )
            for pane in pane_specs:
                if pane.kind == "summary":
                    _draw_summary_rows(
                        stdscr,
                        pane.y + 1,
                        1,
                        pane.height - 2,
                        width - 2,
                        state,
                    )
                    continue
                if pane.kind == "detail":
                    state.detail_offset = _draw_scrolled_text(
                        stdscr,
                        pane.y + 1,
                        1,
                        pane.height - 2,
                        width - 2,
                        detail_text,
                        state.detail_offset,
                        renderer=_render_detail_line,
                    )
                    continue
                if pane.kind == "bytes":
                    state.bytes_offset = _draw_scrolled_text(
                        stdscr,
                        pane.y + 1,
                        1,
                        pane.height - 2,
                        width - 2,
                        bytes_text,
                        state.bytes_offset,
                        renderer=_render_hex_line,
                    )
            footer_text = _clip_text(
                _status_text(capture_path, state, startup_state),
                max(0, width),
            )
            footer_attr = curses.color_pair(_Palette.WARNING if "failed" in footer_text.lower() else _Palette.MUTED)
            _safe_addstr(stdscr, height - 1, 0, footer_text.ljust(max(0, width)), footer_attr | curses.A_BOLD)
            if len(pane_specs) >= 3:
                help_text = "Arrows/j/k browse | Tab focus | PgUp/PgDn scroll | End follow | q quit"
            elif len(pane_specs) == 2:
                help_text = "Arrows/j/k browse | Tab switches Summary/Decoded/Bytes | q quit"
            else:
                help_text = "Tab switches Summary/Decoded/Bytes | q quit"
            if width > len(help_text) + 2 and height > 2:
                _safe_addstr(stdscr, height - 1, max(0, width - len(help_text) - 1), help_text, curses.color_pair(_Palette.ACCENT))
            stdscr.refresh()
            key = stdscr.getch()
            if key == -1 or key == curses.KEY_RESIZE:
                continue
            if key in (ord("q"), ord("Q")):
                return
            if key == 9:
                if state.active_pane == "summary":
                    state.active_pane = "detail"
                elif state.active_pane == "detail":
                    state.active_pane = "bytes"
                else:
                    state.active_pane = "summary"
                continue
            if state.active_pane == "summary":
                previous_frame = _selected_frame_number(state)
                summary_pane_height = 0
                for pane in pane_specs:
                    if pane.kind == "summary":
                        summary_pane_height = pane.height
                        break
                summary_page_step = max(1, summary_pane_height - 2)
                if key in (curses.KEY_UP, ord("k")) and state.selected_index > 0:
                    state.selected_index -= 1
                    state.follow_tail = False
                elif key in (curses.KEY_DOWN, ord("j")) and state.selected_index + 1 < len(state.rows):
                    state.selected_index += 1
                    state.follow_tail = state.selected_index == len(state.rows) - 1
                elif key == curses.KEY_PPAGE and len(state.rows) > 0:
                    state.selected_index = max(0, state.selected_index - summary_page_step)
                    state.follow_tail = False
                elif key == curses.KEY_NPAGE and len(state.rows) > 0:
                    state.selected_index = min(len(state.rows) - 1, state.selected_index + summary_page_step)
                    state.follow_tail = state.selected_index == len(state.rows) - 1
                elif key in (curses.KEY_END, ord("G")) and len(state.rows) > 0:
                    state.selected_index = len(state.rows) - 1
                    state.follow_tail = True
                elif key in (curses.KEY_HOME, ord("g")) and len(state.rows) > 0:
                    state.selected_index = 0
                    state.follow_tail = False
                current_frame = _selected_frame_number(state)
                if previous_frame != current_frame:
                    state.detail_offset = 0
                    state.bytes_offset = 0
                continue
            detail_pane_height = 0
            bytes_pane_height = 0
            for pane in pane_specs:
                if pane.kind == "detail":
                    detail_pane_height = pane.height
                elif pane.kind == "bytes":
                    bytes_pane_height = pane.height
            if state.active_pane == "detail":
                if key in (curses.KEY_UP, ord("k")):
                    state.detail_offset = max(0, state.detail_offset - 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    state.detail_offset += 1
                elif key == curses.KEY_PPAGE:
                    state.detail_offset = max(0, state.detail_offset - max(1, detail_pane_height - 3))
                elif key == curses.KEY_NPAGE:
                    state.detail_offset += max(1, detail_pane_height - 3)
                elif key in (curses.KEY_HOME, ord("g")):
                    state.detail_offset = 0
                continue
            if state.active_pane == "bytes":
                if key in (curses.KEY_UP, ord("k")):
                    state.bytes_offset = max(0, state.bytes_offset - 1)
                elif key in (curses.KEY_DOWN, ord("j")):
                    state.bytes_offset += 1
                elif key == curses.KEY_PPAGE:
                    state.bytes_offset = max(0, state.bytes_offset - max(1, bytes_pane_height - 3))
                elif key == curses.KEY_NPAGE:
                    state.bytes_offset += max(1, bytes_pane_height - 3)
                elif key in (curses.KEY_HOME, ord("g")):
                    state.bytes_offset = 0

    curses.wrapper(_run)
