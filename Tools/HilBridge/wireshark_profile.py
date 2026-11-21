# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Wireshark profile for HIL captures: filter buttons and coloring for the two GSMTAP views.

The bridge (or SIMtrace2) sends GSMTAP antenna 0 and the modem-side DIAG
mirror antenna 1, both on UDP 4729. Wireshark 4.4 hands SIM and log GSMTAP
frames to their dissectors before it builds the GSMTAP tree, so neither
``gsmtap`` nor ``gsmtap.antenna`` matches them; the filters read the antenna
byte from the UDP payload instead. The TLS alert button and colour read the
stock ``tls`` fields, which the APDU dissector fills by handing a whole alert
record to Wireshark's TLS dissector; unlike a ``yapdu`` field they compile in
a Wireshark without that dissector. The STK button reads the stock
``gsm_sim`` fields for the same reason; the APDU dissector keeps them filled
unless its "Also run the stock GSM SIM dissector" preference is switched
off. The colouring rules use the Catppuccin Mocha palette: every GSMTAP
row on the dark base, the text colour by the kind of exchange (session,
read, write, authentication, toolkit, ATR, warning and error status
words), with the modem side, modem notes and TLS failures set apart by
their ground. A Qt style sheet in the same palette covers the rest of
the window (menus, toolbars, the detail and bytes panes). It is opt-in,
because without it Wireshark keeps the desktop's own Qt palette:
``python -m Tools.HilBridge.wireshark_profile --stylesheet <profile>``
writes it, and from then on the launcher passes the file with
``-stylesheet=`` (Wireshark has no setting for it) and keeps it current.
The files written into the profile
each open with a marker line; a file without that marker -- one Wireshark
or the operator has rewritten -- is left alone. Nothing here raises: a
profile that cannot be prepared is reported as "" and Wireshark starts the
way it did before.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

MANAGED_MARKER = "# Managed by YggdraSIM (HIL profile v1). Delete this line to keep your own edits."

SIM_SIDE_FILTER = "udp.port == 4729 && udp.payload[13:1] == 00"
MODEM_SIDE_FILTER = "udp.port == 4729 && udp.payload[13:1] == 01"
MODEM_NOTES_FILTER = "gsmtap_log"
MODEM_CUT_FILTER = "gsmtap_log.level >= 7"
EXCHANGES_FILTER = "udp.port == 4729 && !gsmtap_log"
# ETSI TS 102 221 V18.4.0 clause 14.6: a CAT terminal sends TERMINAL PROFILE,
# ENVELOPE, FETCH and TERMINAL RESPONSE (clause 14.6.3) and polls with STATUS
# in idle mode (clause 14.6.2); Table 10.5 codes them '10', 'C2', '12', '14'
# and 'F2'. '91 XX' (clause 10.2.1.1 Table 10.7), '62 F2' and '63 F2' (clause
# 10.2.1.3 Table 10.9) announce a proactive command in the answer to any
# command, so the exchange each FETCH follows is shown too; '93 00' answers an
# ENVELOPE only (clause 14.6.6). BIP needs no term of its own: OPEN CHANNEL,
# CLOSE CHANNEL, RECEIVE DATA and SEND DATA are proactive commands (ETSI TS
# 102 223 V18.3.0 clauses 6.4.27-6.4.30), the Data available and Channel
# status events ENVELOPEs (clauses 7.5.10, 7.5.11). Stock gsm_sim reads an
# ATR record as an APDU (a T0 byte '12' as FETCH), so payload byte 12, the
# GSMTAP sub-type, must be 00.
STK_FILTER = (
    "udp.port == 4729 && udp.payload[12:1] == 00"
    " && (gsm_sim.apdu.ins in {0x10, 0x12, 0x14, 0xc2, 0xf2}"
    " || gsm_sim.apdu.sw in {0x9100..0x91ff, 0x62f2, 0x63f2})"
)
TLS_ALERTS_FILTER = "tls.alert_message"
# A fatal alert (RFC 5246 clause 7.2, AlertLevel 2) or a certificate alert
# sent at any level: RFC 5246 clause 7.2 41-46 and 48, RFC 6066 clause 9
# 111, 113 and 114, RFC 8446 clause 6 116. TLS 1.2 leaves the level of most
# certificate alerts to the sender. An encrypted alert has no readable
# level or description, so the end-of-session close_notify stays uncoloured.
TLS_FAILURE_FILTER = (
    "tls.alert_message.level == 2"
    " || tls.alert_message.desc in {41..46, 48, 111, 113, 114, 116}"
)

FILTER_BUTTONS: tuple[tuple[str, str, str], ...] = (
    ("SIM side", SIM_SIDE_FILTER, "Bridge or SIMtrace2 frames, GSMTAP antenna 0"),
    ("Modem side", MODEM_SIDE_FILTER, "Modem DIAG mirror frames and notes, GSMTAP antenna 1"),
    ("Modem notes", MODEM_NOTES_FILTER, "NULL holds, PPS and cut exchanges from the modem log"),
    ("Modem cuts", MODEM_CUT_FILTER, "Exchanges a reset cut short before their status word"),
    ("Exchanges", EXCHANGES_FILTER, "APDU and ATR frames from both sides"),
    ("STK", STK_FILTER, "Toolkit and BIP exchanges, STATUS polls and every answer announcing a proactive command"),
    ("TLS alerts", TLS_ALERTS_FILTER, "TLS alerts on a BIP channel, named when sent in the clear"),
)

# Catppuccin Mocha (the GUI's ``catppuccin-mocha`` theme uses the same
# values): every GSMTAP row sits on a dark ground and its text colour says
# what kind of exchange it is.
_BASE = "#1e1e2e"
_MANTLE = "#181825"
_SURFACE = "#313244"
_CRUST = "#11111b"
_TEXT = "#cdd6f4"
_RED = "#f38ba8"
_PEACH = "#fab387"
_YELLOW = "#f9e2af"
_GREEN = "#a6e3a1"
_TEAL = "#94e2d5"
_BLUE = "#89b4fa"
_LAVENDER = "#b4befe"
_MAUVE = "#cba6f7"

# An APDU exchange as stock gsm_sim reads it; payload byte 12, the GSMTAP
# sub-type, keeps ATR records out (see STK_FILTER).
_APDU = "udp.port == 4729 && udp.payload[12:1] == 00"
ATR_FILTER = "udp.port == 4729 && udp.payload[12:1] == 01"
# ETSI TS 102 221 V18.4.0 clause 10.2.1: '90 00', '91 XX' and '92 XX' end
# a command normally (Table 10.7), '93 00' postpones it (Table 10.8), and
# '62 XX' and '63 XX' are warnings (Table 10.9). '61 XX' and '6C XX' carry
# a length for the next command, and stock gsm_sim reads '9E XX' and
# '9F XX' as a normal ending too, so those are left uncoloured; every
# other status word is an error.
STATUS_WARNING_FILTER = f"{_APDU} && gsm_sim.apdu.sw in {{0x6200..0x63ff}}"
STATUS_ERROR_FILTER = (
    f"{_APDU} && gsm_sim.apdu.sw"
    " && !(gsm_sim.apdu.sw in {0x9000..0x93ff, 0x9e00..0x9fff, 0x6100..0x63ff, 0x6c00..0x6cff})"
)
# The instruction bytes of ETSI TS 102 221 V18.4.0 Table 10.5 that
# STK_FILTER does not take, grouped by what the command does: session
# (SELECT FILE, MANAGE CHANNEL, TERMINAL CAPABILITY, SUSPEND UICC,
# EXCHANGE CAPABILITIES, MANAGE LSI), read (READ BINARY, READ RECORD,
# SEARCH RECORD, RETRIEVE DATA, GET IDENTITY, GET RESPONSE), write (UPDATE
# BINARY, UPDATE RECORD, INCREASE, SET DATA, DEACTIVATE FILE, ACTIVATE
# FILE) and authentication (the five PIN commands, AUTHENTICATE, GET
# CHALLENGE, MANAGE SECURE CHANNEL, TRANSACT DATA). The instructions the
# APDU dissector's command table names beside them join the same groups:
# GET DATA with the reads; PUT DATA, PUT KEY, STORE DATA, CREATE FILE,
# DELETE, INSTALL, LOAD and SET STATUS with the writes; INITIALIZE UPDATE
# and EXTERNAL AUTHENTICATE with the authentication commands.
SESSION_FILTER = f"{_APDU} && gsm_sim.apdu.ins in {{0xa4, 0x70, 0xaa, 0x76, 0x7a, 0x7c}}"
READ_FILTER = f"{_APDU} && gsm_sim.apdu.ins in {{0xb0, 0xb2, 0xa2, 0xcb, 0x78, 0xc0, 0xca}}"
WRITE_FILTER = (
    f"{_APDU} && gsm_sim.apdu.ins in"
    " {0xd6, 0xdc, 0x32, 0xdb, 0x04, 0x44, 0xda, 0xd8, 0xe2, 0xe0, 0xe4, 0xe6, 0xe8, 0xf0}"
)
AUTH_FILTER = (
    f"{_APDU} && gsm_sim.apdu.ins in"
    " {0x20, 0x24, 0x26, 0x28, 0x2c, 0x88, 0x89, 0x84, 0x73, 0x75, 0x50, 0x82}"
)
GSMTAP_FILTER = "udp.port == 4729"


def _rgb16(colour: str) -> tuple[int, int, int]:
    """A ``#rrggbb`` colour as the 16-bit channels a colorfilters line takes."""
    value = int(colour.lstrip("#"), 16)
    return (((value >> 16) & 0xFF) * 257, ((value >> 8) & 0xFF) * 257, (value & 0xFF) * 257)


# (name, filter, background, foreground); Wireshark colours a row with the
# first rule that matches. A TLS failure and an error status word keep
# their colour on the modem side too; the last rule keeps every other
# GSMTAP row off the light defaults appended after it.
COLOR_RULES: tuple[tuple[str, str, tuple[int, int, int], tuple[int, int, int]], ...] = tuple(
    (name, expression, _rgb16(background), _rgb16(foreground))
    for name, expression, background, foreground in (
        ("YggdraSIM TLS failure", TLS_FAILURE_FILTER, _RED, _CRUST),
        ("YggdraSIM modem cut", MODEM_CUT_FILTER, _SURFACE, _RED),
        ("YggdraSIM modem note", MODEM_NOTES_FILTER, _MANTLE, _YELLOW),
        ("YggdraSIM status error", STATUS_ERROR_FILTER, _BASE, _RED),
        ("YggdraSIM status warning", STATUS_WARNING_FILTER, _BASE, _PEACH),
        ("YggdraSIM modem side", MODEM_SIDE_FILTER, _SURFACE, _LAVENDER),
        ("YggdraSIM ATR", ATR_FILTER, _BASE, _TEAL),
        ("YggdraSIM toolkit", STK_FILTER, _BASE, _MAUVE),
        ("YggdraSIM session", SESSION_FILTER, _BASE, _BLUE),
        ("YggdraSIM read", READ_FILTER, _BASE, _GREEN),
        ("YggdraSIM write", WRITE_FILTER, _BASE, _PEACH),
        ("YggdraSIM authentication", AUTH_FILTER, _BASE, _YELLOW),
        ("YggdraSIM GSMTAP", GSMTAP_FILTER, _BASE, _TEXT),
    )
)

STYLESHEET_FILE_NAME = "yggdrasim.qss"
STYLESHEET_MARKER = f"/* {MANAGED_MARKER[2:]} */"

# ProtoTree is Wireshark's packet-detail tree. Its rows take their ground
# from the application palette, which a style sheet does not change, so
# they are named here; the packet list is left to the colouring rules.
_STYLESHEET_RULES = f"""\
QWidget {{ background-color: {_BASE}; color: {_TEXT}; selection-background-color: #45475a; selection-color: {_TEXT}; }}
QMainWindow, QDialog, QStatusBar, QToolBar, QMenuBar {{ background-color: {_MANTLE}; }}
QMenuBar::item:selected, QMenu::item:selected {{ background-color: {_SURFACE}; }}
QMenu {{ background-color: {_MANTLE}; border: 1px solid {_SURFACE}; }}
QToolTip {{ background-color: {_SURFACE}; color: {_TEXT}; border: 1px solid #45475a; }}
QHeaderView::section {{ background-color: {_MANTLE}; color: #a6adc8; border: 0; border-right: 1px solid {_SURFACE}; padding: 1px 3px; }}
QTreeView, QAbstractScrollArea {{ background-color: {_BASE}; alternate-background-color: {_MANTLE}; }}
QLineEdit, QComboBox, QSpinBox, QTextEdit, QPlainTextEdit {{ background-color: {_SURFACE}; border: 1px solid #45475a; }}
QPushButton, QToolButton {{ background-color: {_MANTLE}; border: 0; padding: 2px 4px; }}
QPushButton:hover, QToolButton:hover {{ background-color: {_SURFACE}; }}
QToolButton:checked, QToolButton:pressed {{ background-color: #45475a; }}
QScrollBar {{ background-color: {_MANTLE}; }}
QScrollBar::handle {{ background-color: #45475a; }}
QScrollBar::handle:hover {{ background-color: #585b70; }}
QScrollBar::add-line, QScrollBar::sub-line {{ background: none; border: 0; }}
QSplitter::handle {{ background-color: {_MANTLE}; }}
QTabBar::tab {{ background-color: {_MANTLE}; padding: 3px 8px; }}
QTabBar::tab:selected {{ background-color: {_SURFACE}; }}
ProtoTree::item {{ background-color: {_BASE}; color: {_TEXT}; }}
ProtoTree::item:selected {{ background-color: #45475a; color: {_TEXT}; }}
"""

GLOBAL_COLORFILTERS_PATHS = (
    "/usr/share/wireshark/colorfilters",
    "/usr/local/share/wireshark/colorfilters",
)


def wireshark_personal_config_dir(environ: Any = None) -> Path:
    """Wireshark's personal configuration directory on Linux.

    ``WIRESHARK_CONFIG_DIR`` wins; an existing legacy ``~/.wireshark`` is
    used before ``$XDG_CONFIG_HOME/wireshark`` (``~/.config/wireshark``).
    """
    source = environ if environ is not None else os.environ
    override = str(source.get("WIRESHARK_CONFIG_DIR", "") or "").strip()
    if len(override) > 0:
        return Path(override).expanduser()
    home = Path(str(source.get("HOME", "") or "") or Path.home()).expanduser()
    legacy = home / ".wireshark"
    if legacy.is_dir():
        return legacy
    xdg = str(source.get("XDG_CONFIG_HOME", "") or "").strip()
    base = Path(xdg).expanduser() if len(xdg) > 0 else home / ".config"
    return base / "wireshark"


def render_filter_buttons() -> str:
    lines = [MANAGED_MARKER]
    for label, expression, comment in FILTER_BUTTONS:
        lines.append(f'"TRUE","{label}","{expression}","{comment}"')
    return "\n".join(lines) + "\n"


def render_colorfilters(global_rules: str = "") -> str:
    """Our rules first, then the global defaults, which a profile file would otherwise replace."""
    lines = [MANAGED_MARKER]
    for name, expression, background, foreground in COLOR_RULES:
        bg = ",".join(str(channel) for channel in background)
        fg = ",".join(str(channel) for channel in foreground)
        lines.append(f"@{name}@{expression}@[{bg}][{fg}]")
    for line in str(global_rules or "").splitlines():
        if line.startswith("@") or line.startswith("!@"):
            lines.append(line)
    return "\n".join(lines) + "\n"


def render_stylesheet() -> str:
    return STYLESHEET_MARKER + "\n" + _STYLESHEET_RULES


def hil_wireshark_stylesheet_args(profile: str, *, config_dir: Path | None = None) -> list[str]:
    """``-stylesheet=<file>`` for the profile's style sheet, or nothing.

    One token: Wireshark reads its own options before Qt takes this one,
    and a separate file name is refused as a second capture file. A file
    the operator emptied is not passed, which is how to keep the desktop's
    own look.
    """
    name = str(profile or "").strip()
    if len(name) == 0:
        return []
    try:
        root = config_dir if config_dir is not None else wireshark_personal_config_dir()
        path = root / "profiles" / name / STYLESHEET_FILE_NAME
        if path.is_file() is False or path.stat().st_size == 0:
            return []
    except OSError:
        return []
    return [f"-stylesheet={path}"]


def _read_global_colorfilters() -> str:
    for candidate in GLOBAL_COLORFILTERS_PATHS:
        try:
            return Path(candidate).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""


def _write_managed(path: Path, content: str) -> bool:
    """Write *content* unless the file exists without the marker; True when it holds our content."""
    if path.exists():
        current = path.read_text(encoding="utf-8", errors="replace")
        if current.splitlines()[:1] != content.splitlines()[:1]:
            return False
        if current == content:
            return True
    staging = path.with_name(f".{path.name}.yggdrasim")
    staging.write_text(content, encoding="utf-8")
    os.replace(staging, path)
    return True


def ensure_hil_wireshark_profile(
    profile: str,
    *,
    config_dir: Path | None = None,
    global_colorfilters: str | None = None,
) -> str:
    """Prepare *profile* and return its name, or "" when Wireshark should start without ``-C``."""
    name = str(profile or "").strip()
    # "Default" lives in the configuration root, not under profiles/, and
    # holds the operator's own files; a path separator is not a name.
    if len(name) == 0 or name.lower() == "default" or name in (".", "..") or "/" in name or "\\" in name:
        return ""
    try:
        root = config_dir if config_dir is not None else wireshark_personal_config_dir()
        profile_dir = root / "profiles" / name
        profile_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return ""
    rules = _read_global_colorfilters() if global_colorfilters is None else global_colorfilters
    for file_name, content in (
        ("dfilter_buttons", render_filter_buttons()),
        ("colorfilters", render_colorfilters(rules)),
        (STYLESHEET_FILE_NAME, render_stylesheet()),
    ):
        try:
            # The style sheet is opt-in: kept current once it is there.
            if file_name == STYLESHEET_FILE_NAME and (profile_dir / file_name).exists() is False:
                continue
            _write_managed(profile_dir / file_name, content)
        except OSError:
            # The profile exists, so -C still works; it just lacks this file.
            continue
    return name


def enable_hil_wireshark_stylesheet(profile: str, *, config_dir: Path | None = None) -> str:
    """Write the style sheet into *profile* and return its path, or "" when it could not be written."""
    name = ensure_hil_wireshark_profile(profile, config_dir=config_dir)
    if len(name) == 0:
        return ""
    try:
        root = config_dir if config_dir is not None else wireshark_personal_config_dir()
        path = root / "profiles" / name / STYLESHEET_FILE_NAME
        if _write_managed(path, render_stylesheet()) is False:
            return ""
    except OSError:
        return ""
    return str(path)


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Prepare a Wireshark profile for HIL captures.")
    parser.add_argument("--stylesheet", metavar="PROFILE", required=True, help="write the Qt style sheet into PROFILE")
    arguments = parser.parse_args(argv)
    path = enable_hil_wireshark_stylesheet(arguments.stylesheet)
    if len(path) == 0:
        print(f"Could not write the style sheet into profile {arguments.stylesheet!r}.")
        return 1
    print(f"{path}\nStart Wireshark with: -C {arguments.stylesheet} -stylesheet={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
