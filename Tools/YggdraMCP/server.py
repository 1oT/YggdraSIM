# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""YggdraSIM domain MCP server: APDU, TLV, spec, identifier, and PC/SC tools.

Run ``yggdrasim-mcp`` (installed) or ``python -m Tools.YggdraMCP.server``.
Requires the ``mcp`` extra.

Tools are read-only by default. Anything that drives a physical card is
gated behind ``YGGDRASIM_MCP_ALLOW_CARD``: an MCP client is usually an
autonomous agent, and an unsupervised APDU can exhaust a PIN/PUK retry
counter or block an ADM key, which is not recoverable.
"""

import json
import logging
import os
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations
from pydantic import BaseModel, Field

_LOGGER = logging.getLogger(__name__)

# pySim logs the construction of every file in a profile at DEBUG. Loading one
# package emits well over a hundred kilobytes, which reaches the client as
# noise on stderr and buries anything that matters. Quieten the upstream
# loggers, overridable when actually debugging a decode.
for _noisy in ("pySim", "osmocom", "construct"):
    logging.getLogger(_noisy).setLevel(
        os.environ.get("YGGDRASIM_MCP_UPSTREAM_LOG_LEVEL", "WARNING").upper()
    )

#: Lookup and decode tools: no side effects, same answer every time.
READ_ONLY = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
#: Reads a path from the local filesystem, but changes nothing.
READS_FILES = ToolAnnotations(readOnlyHint=True, idempotentHint=True, openWorldHint=False)
#: Touches hardware or a network peer without changing it.
PROBES_WORLD = ToolAnnotations(readOnlyHint=True, idempotentHint=False, openWorldHint=True)
#: Drives a real card. Not read-only, not idempotent, not undoable.
TOUCHES_CARD = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=True,
    idempotentHint=False,
    openWorldHint=True,
)

mcp = FastMCP("yggdrasim")

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

CARD_ACCESS_ENV = "YGGDRASIM_MCP_ALLOW_CARD"
DESTRUCTIVE_ENV = "YGGDRASIM_MCP_ALLOW_DESTRUCTIVE"

_TRUTHY = ("1", "true", "yes", "on")


def _env_on(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in _TRUTHY


def card_access_allowed() -> bool:
    """Whether tools that transmit to a physical card are enabled."""

    return _env_on(CARD_ACCESS_ENV)


def destructive_allowed() -> bool:
    """Whether irreversible APDUs may be sent.

    Separate from :func:`card_access_allowed` on purpose. Reads are the bulk
    of useful agent work and are safe; the operations below cannot be undone
    on real hardware, so they need their own deliberate opt-in.
    """

    return card_access_allowed() and _env_on(DESTRUCTIVE_ENV)


# INS -> (risk class, name). ``destructive`` means irreversible on a real
# card: a consumed retry counter never comes back, a terminated card never
# wakes up. ``write`` mutates but is normally recoverable by writing again.
_APDU_RISK: dict[int, tuple[str, str]] = {
    0x20: ("destructive", "VERIFY (consumes a PIN retry)"),
    0x24: ("destructive", "CHANGE REFERENCE DATA"),
    0x26: ("destructive", "DISABLE VERIFICATION REQUIREMENT"),
    0x28: ("destructive", "ENABLE VERIFICATION REQUIREMENT"),
    0x2C: ("destructive", "RESET RETRY COUNTER (consumes a PUK retry)"),
    0xD8: ("destructive", "PUT KEY"),
    0xE4: ("destructive", "DELETE"),
    0xF0: ("destructive", "SET STATUS (can lock or terminate the card)"),
    0x04: ("destructive", "DEACTIVATE FILE"),
    0xD6: ("write", "UPDATE BINARY"),
    0xDC: ("write", "UPDATE RECORD"),
    0xE0: ("write", "CREATE FILE"),
    0xE2: ("write", "STORE DATA"),
    0xE6: ("write", "INSTALL"),
    0xE8: ("write", "LOAD"),
    0x44: ("write", "ACTIVATE FILE"),
    0xA4: ("read", "SELECT"),
    0xB0: ("read", "READ BINARY"),
    0xB2: ("read", "READ RECORD"),
    0xC0: ("read", "GET RESPONSE"),
    0xCA: ("read", "GET DATA"),
    0xF2: ("read", "GET STATUS"),
}


def classify_apdu(payload: bytes) -> dict[str, Any]:
    """Classify one command APDU as read, write, or destructive.

    Unknown instructions are reported as ``write`` rather than ``read``: an
    instruction this table has not seen is not evidence that it is safe.
    """

    if len(payload) < 2:
        return {"risk": "unknown", "ins": "", "name": "APDU too short to classify"}
    ins = payload[1]
    risk, name = _APDU_RISK.get(ins, ("write", "unrecognised instruction"))
    # STORE DATA carries ES10b profile operations, including memory reset and
    # profile deletion, so its payload decides the real risk.
    if ins == 0xE2 and b"\xBF\x34" in payload[:16]:
        risk, name = "destructive", "STORE DATA (eUICC memory reset)"
    return {"risk": risk, "ins": f"{ins:02X}", "name": name}


def _apdu_refusal(verdict: dict[str, Any]) -> str | None:
    """Return a refusal payload when this APDU may not be sent, else None."""

    if not card_access_allowed():
        return _card_access_denied()
    if verdict["risk"] == "destructive" and not destructive_allowed():
        return json.dumps(
            {
                "error": (
                    f"Refused: {verdict['name']} is irreversible on a real card. "
                    f"Set {DESTRUCTIVE_ENV}=1 as well to permit it."
                ),
                "ins": verdict["ins"],
                "risk": verdict["risk"],
                "hint": (
                    "Retry counters do not reset and a terminated card does not "
                    "recover. Use a throwaway test card before enabling this."
                ),
            }
        )
    return None


async def _confirm_destructive(ctx: Any, verdict: dict[str, Any], target: str) -> str | None:
    """Ask a human before an irreversible APDU. Returns a refusal or None.

    Defence in depth, never the only guard: elicitation is an optional client
    capability, and an agent client may answer it without asking anyone. The
    environment gates above are what actually hold.
    """

    if ctx is None or verdict["risk"] != "destructive":
        return None
    elicit = getattr(ctx, "elicit", None)
    if not callable(elicit):
        return None

    class Confirm(BaseModel):
        proceed: bool = Field(description="Send this irreversible command to the card?")

    message = (
        f"About to send {verdict['name']} (INS {verdict['ins']}) to {target}. "
        "This cannot be undone. Proceed?"
    )
    try:
        result = await elicit(message=message, schema=Confirm)
    except Exception as exc:  # noqa: BLE001
        # A client without elicitation support must not become a hard failure.
        _LOGGER.info("elicitation unavailable (%s); relying on env gates", exc)
        return None
    if getattr(result, "action", "") != "accept" or not getattr(
        getattr(result, "data", None), "proceed", False
    ):
        return json.dumps(
            {"error": "Declined at confirmation prompt; nothing was sent to the card."}
        )
    return None


def _card_access_denied() -> str:
    return json.dumps(
        {
            "error": (
                "Card access is disabled. This tool transmits to a physical "
                f"card; set {CARD_ACCESS_ENV}=1 to enable it."
            ),
            "hint": (
                "Leave it unset when an agent drives this server unattended. "
                "A wrong APDU can exhaust a PIN/PUK counter or block an ADM key."
            ),
        }
    )

# ---------------------------------------------------------------------------
# Static data extracted from the repo
# ---------------------------------------------------------------------------

STATUS_WORDS: dict[int, str] = {
    0x9000: "Success",
    0x6100: "More data available",
    0x6283: "Selected file invalidated",
    0x6300: "Authentication failed",
    0x6310: "More data available (GET STATUS continuation)",
    0x6400: "State of non-volatile memory unchanged",
    0x6700: "Wrong length",
    0x6881: "Logical channel not supported",
    0x6882: "Secure messaging not supported",
    0x6982: "Security status not satisfied",
    0x6983: "Authentication method blocked",
    0x6984: "Referenced data invalidated",
    0x6985: "Conditions of use not satisfied",
    0x6A80: "Incorrect parameters in data field",
    0x6A81: "Function not supported",
    0x6A82: "File not found / Applet not found",
    0x6A83: "Record not found",
    0x6A84: "Not enough memory space in file",
    0x6A86: "Incorrect parameters P1-P2",
    0x6A88: "Referenced data not found",
    0x6D00: "Instruction code not supported or invalid",
    0x6E00: "Class not supported",
    0x6F00: "Unknown error / No precise diagnosis",
}

BER_TLV_TAGS: dict[int, str] = {
    0xBF20: "EuiccInfo1 (SGP.22 §5.7.16)",
    0xBF22: "EuiccInfo2 (SGP.22 §5.7.17)",
    0xBF2B: "NotificationsList (SGP.22 §5.7.24)",
    0xBF2D: "GetProfilesInfo (SGP.22 §5.7.20)",
    0xBF31: "EnableProfile (SGP.22 §5.7.21)",
    0xBF32: "DisableProfile (SGP.22 §5.7.22)",
    0xBF33: "DeleteProfile (SGP.22 §5.7.23)",
    0xBF3C: "EuiccConfiguredData (SGP.22 §5.7.18)",
    0xBF3E: "ProfileInfo (SGP.22 §5.7.19)",
    0xBF43: "RAT / Rules Authorisation Table (SGP.22 §5.7.16)",
    0xBF55: "EimConfigurationData (SGP.32 §6.5)",
    0xBF56: "GetCertsResponse (SGP.22 §5.7.32)",
    0x80: "Result (profile operation result code)",
    0x4F: "AID (Application Identifier -- ISO 7816-5)",
    0x5A: "ICCID (Integrated Circuit Card ID -- ETSI TS 102 221)",
    0x9F70: "ProfileState (SGP.22 §5.7.19)",
    0x90: "Nickname (profile nickname)",
    0x91: "ServiceProviderName",
    0x92: "ProfileName",
    0x95: "ProfileClass",
    0xA0: "Context-0 (SGP.22 first-level context tag)",
    0xA1: "Context-1 (SGP.22 second-level context tag)",
    0xA9: "Context-9 (EuiccInfo1 sub-structure)",
    0xAA: "Context-10 (EuiccInfo1 sub-structure)",
}

TEST_IDENTIFIER_RANGES: dict[str, dict[str, Any]] = {
    "mccmnc": {
        "pattern": re.compile(r"^(00[1-9]|999)\s*/\s*\d{2,3}$"),
        "description": "Test PLMN MCC/MNC per 3GPP TS 23.003 §2.2 (001/01, 999/99)",
        "example": "001/01",
    },
    "iccid": {
        "pattern": re.compile(r"^8988\d{15,16}$"),
        "description": "Test ICCID per ITU-T E.118 'Universal' test range (8988 prefix)",
        "example": "8988201234567890123",
    },
    "imsi": {
        "pattern": re.compile(r"^00101\d{9,10}$"),
        "description": "Test IMSI using test MCC 001 MNC 01",
        "example": "001010000000001",
    },
    "eid": {
        "pattern": re.compile(r"^89049032\d{23}$"),
        "description": "Test EID per SGP.22 §A.2 (89049032 prefix + 23 digits)",
        "example": "89049032123456789012345678901234",
    },
}

# A dotted quad is only a leak when it is routable and is not a spec clause.
# Spec section numbers are numerically valid IPv4 addresses, so matching on
# shape alone reports thousands of spec citations as if they were hosts.
#
# The negative lookarounds stop a longer dotted chain yielding a false quad:
# without them a five-part clause number yields a quad from its first four.
_IPV4_CANDIDATE = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])"
)

# Ranges that cannot identify a real-world host: loopback, RFC 1918 private,
# link-local, CGNAT, multicast, unspecified, broadcast, and the RFC 5737
# documentation ranges this rule exists to steer people towards.
_NON_ROUTABLE_IPV4 = re.compile(
    r"""^(?:
          0\.
        | 10\.
        | 127\.
        | 169\.254\.
        | 172\.(?:1[6-9]|2\d|3[01])\.
        | 192\.168\.
        | 192\.0\.2\.
        | 198\.51\.100\.
        | 203\.0\.113\.
        | 100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.
        | (?:22[4-9]|23\d)\.
        | 255\.255\.255\.255$
    )""",
    re.VERBOSE,
)

# A citation marker immediately before the match. Covers a section sign both
# literally and as a "\\u00a7" escape, spec and table references, and version
# strings such as "v2.3.1.49" or a "package_version" field.
_SPEC_CITATION_BEFORE = re.compile(
    "(?:\u00a7"
    "|\\\\u00a"
    "|\\bTS\\b|\\bGPCS?\\b|\\bSGP\\b|\\bETSI\\b|\\bISO\\b|\\b3GPP\\b"
    "|\\bclause\\b|\\bsection\\b|\\bAnnex\\b|\\bTable\\b|\\bFigure\\b"
    "|version|(?<![A-Za-z0-9])v"
    # Digits and dots may sit between the marker and the match, so a section
    # range written as two clause numbers joined by a dash is recognised. Any
    # letter breaks the run, so an address after prose stays reportable.
    ")[\\s.:\"'_\\-\\d]*$",
    re.IGNORECASE,
)

# Object identifier arcs. An OID is a valid dotted quad numerically, and the
# X.500 and ISO arcs below are the ones this tree actually carries, so a quad
# inside them is a certificate OID rather than a host address.
_OID_ARC = re.compile(r"^(?:0\.|1\.[023]\.|2\.(?:5|16|23)\.)")


def _is_public_ipv4_leak(match: "re.Match[str]", content: str) -> bool:
    """Whether a dotted quad is a routable address rather than a citation."""

    value = match.group()
    if _NON_ROUTABLE_IPV4.match(value) or _OID_ARC.match(value):
        return False
    preceding = content[max(0, match.start() - 24) : match.start()]
    return _SPEC_CITATION_BEFORE.search(preceding) is None


REAL_IDENTIFIER_PATTERNS: list[dict[str, Any]] = [
    {"name": "Real SE MCC 240", "regex": re.compile(r"240\s*/\s*\d{2,3}"), "fix": "Use 001/01 (test PLMN per 3GPP TS 23.003 §2.2)"},
    {"name": "Real NO MCC 242", "regex": re.compile(r"242\s*/\s*\d{2,3}"), "fix": "Use 001/01 (test PLMN per 3GPP TS 23.003 §2.2)"},
    {"name": "Real EE MCC 248", "regex": re.compile(r"248\s*/\s*\d{2,3}"), "fix": "Use 001/01 (test PLMN per 3GPP TS 23.003 §2.2)"},
    {"name": "Real SE IIN 8946", "regex": re.compile(r"8946\d{14,15}"), "fix": "Use 8988 prefix (ITU-T E.118 test range)"},
    {"name": "Real NO IIN 8937", "regex": re.compile(r"8937\d{14,15}"), "fix": "Use 8988 prefix (ITU-T E.118 test range)"},
    {
        "name": "Real non-RFC 5737 IP",
        "regex": _IPV4_CANDIDATE,
        "filter": _is_public_ipv4_leak,
        "fix": "Use 192.0.2.0/24, 198.51.100.0/24, or 203.0.113.0/24 (RFC 5737)",
    },
]

BANNED_PHRASES: list[str] = [
    "Phase 1", "Phase 2", "Phase 3", "Phase 4", "Phase 5", "Phase 6", "Phase 7",
    "MVP", "next iteration", "future iteration", "next sprint",
    "future-roadmap", "internal sprint", "handoff",
    "Let me", "Let's", "We'll", "I'll", "I've",
    "Feel free to", "As we mentioned", "Now we", "Here we", "Above we", "Below we",
    "It is worth noting", "In a nutshell", "To sum up",
    "Out of the box", "Under the hood", "Behind the scenes", "Deep dive", "First-class",
    "Robust", "Seamless", "Comprehensive", "Powerful", "Cutting-edge",
    "Production-ready", "Battle-tested", "Industry-leading", "Best-in-class", "Enterprise-grade",
    "Carefully crafted", "Thoughtfully", "Elegantly", "The magic", "Secret sauce", "Rich set",
    "Crucial", "Imperative", "Paramount", "Cornerstone", "Hallmark",
    "Delve", "Leverage", "Harness",
]

SPEC_SECTIONS: dict[str, dict[str, str]] = {
    "SGP.22": {
        "url": "GSMA SGP.22 (Consumer RSP)",
        "key_sections": "§2.4 ES10b interface, §2.5 ES10c interface, §3.1 Profile states, §5.7 ES10 command set, §A.2 Test EID",
    },
    "SGP.32": {
        "url": "GSMA SGP.32 (IoT RSP)",
        "key_sections": "§3 IPA architecture, §4 eIM interface, §6.5 EIM configuration, §7 ESipa commands",
    },
    "SGP.02": {
        "url": "GSMA SGP.02 (M2M RSP)",
        "key_sections": "§2 Architecture, §3 ISD-R/ISD-P roles, §4 Profile download",
    },
    "TS 102 221": {
        "url": "ETSI TS 102 221 (UICC)",
        "key_sections": "§7 File system, §8 Security, §11 File types, §13.1 SELECT, §13.2 READ BINARY, §13.3 UPDATE BINARY, §13.4 READ RECORD",
    },
    "TS 102 222": {
        "url": "ETSI TS 102 222 (Admin commands)",
        "key_sections": "§5 CREATE FILE, §6 DELETE FILE, §7 TERMINATE DF/EF, §8 RESIZE FILE",
    },
    "TS 102 223": {
        "url": "ETSI TS 102 223 (SIM Toolkit)",
        "key_sections": "§6 Proactive commands, §7 Envelope, §8 Terminal response, §9 Event download",
    },
    "TS 102 225": {
        "url": "ETSI TS 102 225 (Secured Packet)",
        "key_sections": "§5 Secured packet structure, §6 Command/Response SPI encoding",
    },
    "TS 102 226": {
        "url": "ETSI TS 102 226 (Remote APDU for UICC)",
        "key_sections": "§5 RAM commands, §6 RFM commands, §7 Access control",
    },
    "TS 31.102": {
        "url": "3GPP TS 31.102 (USIM)",
        "key_sections": "§4 EF structure, §5 EF definitions (IMSI, LOCI, ACC, etc.), §7 USIM security",
    },
    "TS 33.501": {
        "url": "3GPP TS 33.501 (5G Security)",
        "key_sections": "§6.1 5G AKA, §6.2 EAP-AKA', §C.3 SUCI calculation",
    },
    "TS 35.206": {
        "url": "3GPP TS 35.206 (Milenage)",
        "key_sections": "§3 Algorithm, §4 Test vectors, §5 OPC derivation",
    },
    "TS 35.231": {
        "url": "3GPP TS 35.231 (TUAK)",
        "key_sections": "§3 Algorithm, §4 Test vectors",
    },
    "GPC v2.3.1": {
        "url": "GlobalPlatform Card Specification v2.3.1",
        "key_sections": "§11 Security domains, §11.8 INSTALL, §11.9 LOAD, §11.11 DELETE, §11.12 SET STATUS, §E SCP03",
    },
    "ISO 7816-4": {
        "url": "ISO/IEC 7816-4 (APDU)",
        "key_sections": "§5 APDU structure, §5.1.3 Status words, §6 Logical channels, §7 Secure messaging",
    },
}

# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------


@mcp.tool(annotations=READ_ONLY)
def validate_identifier(identifier_type: str, value: str) -> str:
    """Check whether an ICCID, IMSI, EID, IMEI, or PLMN value uses the correct
    test range per GSMA/3GPP/ITU-T reserved test values.

    identifier_type: one of iccid, imsi, eid, imei, mccmnc.
    """
    identifier_type = identifier_type.lower().strip()
    if identifier_type not in TEST_IDENTIFIER_RANGES:
        return json.dumps({"valid": False, "error": f"Unknown identifier type '{identifier_type}'. Known: {list(TEST_IDENTIFIER_RANGES)}."})

    entry = TEST_IDENTIFIER_RANGES[identifier_type]
    if entry["pattern"].match(value.strip()):
        return json.dumps({"valid": True, "description": entry["description"], "example": entry["example"]})

    return json.dumps({"valid": False, "description": entry["description"], "example": entry["example"], "hint": f"The provided value does not match the required test range for {identifier_type}."})


@mcp.tool(annotations=READ_ONLY)
def apdu_parse(hex_apdu: str) -> str:
    """Parse a hex APDU string into CLA, INS, P1, P2, Lc, Data, Le fields
    per ISO 7816-4 §5.1.

    Accepts space-separated or compact hex (e.g. '00 A4 04 00' or '00A40400').
    """
    clean = hex_apdu.strip().replace(" ", "").replace(":", "").replace("0x", "")
    try:
        raw = bytes.fromhex(clean)
    except ValueError:
        return json.dumps({"error": "Invalid hex input."})

    if len(raw) < 4:
        return json.dumps({"error": "APDU must be at least 4 bytes (CLA+INS+P1+P2)."})

    result: dict[str, Any] = {
        "CLA": f"0x{raw[0]:02X}",
        "INS": f"0x{raw[1]:02X}",
        "P1": f"0x{raw[2]:02X}",
        "P2": f"0x{raw[3]:02X}",
    }

    pos = 4
    if len(raw) > pos + 1 and len(raw) > 5:
        if raw[pos] != 0:
            lc = raw[pos]
            pos += 1
            result["Lc"] = lc
            if pos + lc <= len(raw):
                result["Data"] = raw[pos : pos + lc].hex().upper()
                pos += lc
            else:
                result["Data"] = raw[pos:].hex().upper() + " [truncated]"
                pos = len(raw)

    if pos < len(raw):
        result["Le"] = f"0x{raw[pos]:02X}" if len(raw) - pos == 1 else raw[pos:].hex().upper()

    if result["INS"] == "0xA4":
        result["command"] = "SELECT"
    elif result["INS"] == "0xB0":
        result["command"] = "READ BINARY"
    elif result["INS"] == "0xB2":
        result["command"] = "READ RECORD"
    elif result["INS"] == "0xD6":
        result["command"] = "UPDATE BINARY"
    elif result["INS"] == "0xDC":
        result["command"] = "UPDATE RECORD"
    elif result["INS"] == "0xE2":
        result["command"] = "STORE DATA (GP)"
    elif result["INS"] == "0xF2":
        result["command"] = "GET STATUS (GP)"
    elif result["INS"] == "0xE0":
        result["command"] = "CREATE FILE (ETSI)"
    elif result["INS"] == "0xE4":
        result["command"] = "DELETE FILE (ETSI)"
    elif result["INS"] == "0x82":
        result["command"] = "EXTERNAL AUTHENTICATE (GP)"
    elif result["INS"] == "0x50":
        result["command"] = "INITIALIZE UPDATE (GP)"
    elif result["INS"] == "0xD8":
        result["command"] = "PUT KEY (GP)"
    elif result["INS"] == "0xF0":
        result["command"] = "SET STATUS (GP)"
    elif result["INS"] == "0x70":
        result["command"] = "MANAGE CHANNEL (ISO)"
    elif result["INS"] == "0xC0":
        result["command"] = "GET RESPONSE (ISO)"

    if result["CLA"] == "0x80":
        result["channel"] = "GlobalPlatform"
    elif result["CLA"] == "0x00":
        result["channel"] = "ISO basic (logical channel 0)"
    elif (raw[0] & 0xFC) == 0x00:
        result["channel"] = f"ISO logical channel {raw[0] & 0x03}"
    elif (raw[0] & 0xF0) == 0x80:
        result["channel"] = "GlobalPlatform / secure messaging"

    return json.dumps(result, indent=2)


@mcp.tool(annotations=READ_ONLY)
def status_word_lookup(sw: str) -> str:
    """Return the human-readable meaning of an ISO 7816-4 / GlobalPlatform
    status word (e.g. '9000', '6A82', '6985').
    """
    sw = sw.strip().replace(" ", "").replace("0x", "").upper()
    try:
        sw_int = int(sw, 16)
    except ValueError:
        return json.dumps({"error": f"Invalid status word: '{sw}'. Provide a 2-byte hex value like '9000'."})

    sw1 = (sw_int >> 8) & 0xFF
    sw2 = sw_int & 0xFF

    if sw_int in STATUS_WORDS:
        meaning = STATUS_WORDS[sw_int]
    elif sw1 == 0x61:
        meaning = f"Success. {sw2} bytes of data available to read."
    elif sw1 == 0x6C:
        meaning = f"Wrong Le length. Correct length is {sw2}."
    elif sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        retries = sw2 & 0x0F
        meaning = f"Verification failed. {retries} retries remaining."
    else:
        meaning = "Unknown status word."

    return json.dumps({"SW1": f"0x{sw1:02X}", "SW2": f"0x{sw2:02X}", "meaning": meaning})


@mcp.tool(annotations=READ_ONLY)
def ber_tlv_lookup(tag: str) -> str:
    """Look up a BER-TLV tag by hex value and return its name and spec reference.
    Covers SGP.22 context tags (0xBF20-0xBF56), ISO/GP tags (0x4F, 0x5A, 0x80),
    and profile-level context tags (0xA0-0xA1, 0xA9-0xAA).
    """
    tag = tag.strip().replace(" ", "").replace("0x", "").upper()
    try:
        tag_int = int(tag, 16)
    except ValueError:
        return json.dumps({"error": f"Invalid tag hex: '{tag}'."})

    if tag_int in BER_TLV_TAGS:
        return json.dumps({"tag": f"0x{tag_int:04X}" if tag_int > 0xFF else f"0x{tag_int:02X}", "name": BER_TLV_TAGS[tag_int]})

    return json.dumps({"tag": f"0x{tag_int:04X}" if tag_int > 0xFF else f"0x{tag_int:02X}", "name": "Unknown tag -- not in YggdraSIM BER-TLV registry."})


@mcp.tool(annotations=READ_ONLY)
def spec_section_lookup(spec_id: str) -> str:
    """Return a summary of a specification and its key sections.
    Known specs: SGP.02, SGP.22, SGP.32, TS 102 221-226, TS 31.102,
    TS 33.501, TS 35.206, TS 35.231, GPC v2.3.1, ISO 7816-4.
    """
    spec_id = spec_id.strip()
    for key, info in SPEC_SECTIONS.items():
        if spec_id.upper() == key.upper():
            return json.dumps({"spec": key, "full_name": info["url"], "key_sections": info["key_sections"]})

    return json.dumps({"error": f"Spec '{spec_id}' not found. Known: {list(SPEC_SECTIONS)}."})


@mcp.tool(annotations=READS_FILES)
def scan_identifiers(file_path: str) -> str:
    """Scan a source file for potential real-world identifier leaks.
    Checks for: real MCC/MNC, non-test ICCID IINs, public IPs outside RFC 5737,
    and internal phase labels or banned AI-prose phrases.

    file_path: relative to the repo root (e.g. 'SCP03/logic/sgp22.py').
    """
    target = (REPO_ROOT / file_path).resolve()
    if not target.is_file():
        return json.dumps({"error": f"File not found: {target}"})

    try:
        content = target.read_text(encoding="utf-8")
    except Exception as exc:
        return json.dumps({"error": f"Cannot read file: {exc}"})

    findings: list[dict[str, Any]] = []

    for entry in REAL_IDENTIFIER_PATTERNS:
        keep = entry.get("filter")
        for match in entry["regex"].finditer(content):
            if keep is not None and not keep(match, content):
                continue
            ctx_start = max(0, match.start() - 40)
            ctx_end = min(len(content), match.end() + 40)
            findings.append({"type": "identifier_leak", "rule": entry["name"], "match": match.group(), "fix": entry["fix"], "context": content[ctx_start:ctx_end]})

    for phrase in BANNED_PHRASES:
        for match in re.finditer(re.escape(phrase), content, re.IGNORECASE):
            ctx_start = max(0, match.start() - 30)
            ctx_end = min(len(content), match.end() + 30)
            findings.append({"type": "banned_phrase", "phrase": phrase, "context": content[ctx_start:ctx_end]})

    return json.dumps({"file": file_path, "findings_count": len(findings), "findings": findings[:50]}, indent=2)


@mcp.tool(annotations=READ_ONLY)
def aide_registry_lookup(query: str) -> str:
    """Look up an AID (Application Identifier) in the YggdraSIM AID registry.
    Returns the role and hex bytes of matching entries.

    query: partial name or hex AID (e.g. 'ISDR', 'A0000005591010').
    """
    aid_path = REPO_ROOT / "SCP03" / "seeds" / "aid.txt"
    if not aid_path.is_file():
        return json.dumps({"error": "AID registry file not found."})

    matches: list[dict[str, str]] = []
    query_upper = query.strip().upper()
    try:
        for line in aid_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or ":" not in line:
                continue
            name, aid_hex = line.split(":", 1)
            if query_upper in name.upper() or query_upper in aid_hex.upper():
                matches.append({"name": name, "aid": aid_hex})
    except Exception as exc:
        return json.dumps({"error": f"Error reading AID registry: {exc}"})

    if not matches:
        return json.dumps({"query": query, "matches": [], "hint": "No match. Known AIDs include: ISDR, ISDP0-5, ECASD, ARAM, ARAC, MNOSD."})

    return json.dumps({"query": query, "matches": matches}, indent=2)


# ---------------------------------------------------------------------------
# PC/SC hardware bridge (pyscard, optional)
# ---------------------------------------------------------------------------

_PCSC_TRANSMIT_TIMEOUT_MS = 5000


def _load_pcsc() -> tuple[Any, Any, Any]:
    """Lazy-load pyscard. Returns (readers_fn, SCARD_SHARE_EXCLUSIVE, ExclusiveConnectCardConnection)."""
    try:
        from smartcard.System import readers as _readers
        from smartcard.scard import SCARD_SHARE_EXCLUSIVE
    except ImportError as exc:
        raise RuntimeError(
            "pyscard is not installed. Install it with: pip install pyscard"
        ) from exc

    try:
        from smartcard.ExclusiveConnectCardConnection import ExclusiveConnectCardConnection
    except ImportError:
        ExclusiveConnectCardConnection = None

    return _readers, SCARD_SHARE_EXCLUSIVE, ExclusiveConnectCardConnection


@mcp.tool(annotations=PROBES_WORLD)
def pcsc_list_readers() -> str:
    """List all available PC/SC smart card readers connected to this machine.
    Returns reader names and indices for use with pcsc_transmit.
    Requires pyscard to be installed (pip install pyscard).
    """
    try:
        readers_fn, _, _ = _load_pcsc()
        reader_list = [str(r) for r in readers_fn()]
    except RuntimeError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:
        return json.dumps({"error": f"PC/SC error: {exc}"})

    if not reader_list:
        return json.dumps({"readers": [], "note": "No PC/SC readers detected."})

    return json.dumps({"readers": [{"index": i, "name": name} for i, name in enumerate(reader_list)]}, indent=2)


@mcp.tool(annotations=TOUCHES_CARD)
async def pcsc_transmit(
    hex_apdu: str,
    reader_index: int = 0,
    reader_name: str = "",
    timeout_ms: int = _PCSC_TRANSMIT_TIMEOUT_MS,
    ctx: Context | None = None,
) -> str:
    """Transmit a raw APDU to a physical smart card via PC/SC and return the response.

    Connects to the reader, transmits the APDU, reads the response, and disconnects.
    Each call is atomic; no persistent connection is held, so a secure-channel
    flow that spans several APDUs will not work here. Use card_bridge_transmit
    through a running Card Bridge for anything that needs session state.

    hex_apdu: hex-encoded APDU bytes (e.g. '00A4040000').
    reader_index: which reader to use (default 0). Ignored if reader_name is set.
    reader_name: case-insensitive substring match against reader names.
    timeout_ms: max wait for card response (default 5000).
    Requires pyscard (pip install pyscard) and a physical reader + card.
    Requires YGGDRASIM_MCP_ALLOW_CARD. Irreversible instructions additionally
    require YGGDRASIM_MCP_ALLOW_DESTRUCTIVE; call apdu_risk first if unsure.
    """
    # Classify before touching hardware, so a refusal costs nothing.
    clean_early = hex_apdu.strip().replace(" ", "").replace(":", "").replace("0x", "")
    try:
        verdict = classify_apdu(bytes.fromhex(clean_early))
    except ValueError:
        return json.dumps({"error": "Invalid hex APDU."})
    refusal = _apdu_refusal(verdict)
    if refusal is not None:
        return refusal
    declined = await _confirm_destructive(
        ctx, verdict, f"local reader {reader_name or reader_index}"
    )
    if declined is not None:
        return declined

    try:
        readers_fn, share_exclusive, exclusive_wrapper = _load_pcsc()
    except RuntimeError as exc:
        return json.dumps({"error": str(exc)})

    # Enumeration can fail outright when pcscd is down or the caller lacks
    # access. An MCP client needs that as a readable result, not a traceback.
    try:
        available = list(readers_fn())
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"PC/SC error: {exc}"})
    if not available:
        return json.dumps({"error": "No PC/SC readers available."})

    # Select reader
    if reader_name:
        needle = reader_name.casefold()
        matches = [r for r in available if needle in str(r).casefold()]
        if not matches:
            names = [str(r) for r in available]
            return json.dumps({"error": f"No reader matched '{reader_name}'. Available: {names}"})
        selected = matches[0]
    else:
        if reader_index < 0 or reader_index >= len(available):
            return json.dumps({"error": f"Reader index {reader_index} out of range (0-{len(available) - 1})."})
        selected = available[reader_index]

    # Parse APDU
    clean = hex_apdu.strip().replace(" ", "").replace(":", "").replace("0x", "")
    try:
        apdu_bytes = bytes.fromhex(clean)
    except ValueError:
        return json.dumps({"error": "Invalid hex APDU."})

    # Connect
    try:
        connection = selected.createConnection()
        if exclusive_wrapper is not None:
            connection = exclusive_wrapper(connection)
        connection.connect(mode=share_exclusive)
    except Exception as exc:
        return json.dumps({"error": f"Failed to connect to '{selected}': {exc}"})

    # Transmit with timeout (matches Tools/HilBridge/pcsc.py pattern)
    apdu_list = list(apdu_bytes)
    result_holder: list[tuple[list[int], int, int]] = []
    error_holder: list[Exception] = []

    def _do_transmit() -> None:
        try:
            result_holder.append(connection.transmit(apdu_list))
        except Exception as exc:
            error_holder.append(exc)

    worker = threading.Thread(target=_do_transmit, daemon=True)
    worker.start()
    worker.join(timeout=max(0.1, timeout_ms / 1000.0))

    # Disconnect
    try:
        connection.disconnect()
    except Exception:
        pass

    if worker.is_alive():
        return json.dumps({"error": f"PC/SC transmit timed out after {timeout_ms}ms."})

    if error_holder:
        return json.dumps({"error": f"PC/SC transmit failed: {error_holder[0]}"})

    if not result_holder:
        return json.dumps({"error": "PC/SC transmit returned no result."})

    response_list, sw1, sw2 = result_holder[0]
    response_bytes = bytes(response_list)

    result = {
        "reader": str(selected),
        "apdu_sent": hex_apdu,
        "response_data": response_bytes.hex().upper() if response_bytes else "",
        "SW1": f"0x{sw1:02X}",
        "SW2": f"0x{sw2:02X}",
    }

    # Add status word meaning
    sw_int = (sw1 << 8) | sw2
    if sw_int in STATUS_WORDS:
        result["status"] = STATUS_WORDS[sw_int]
    elif sw1 == 0x61:
        result["status"] = f"Success. {sw2} bytes available."
    elif sw1 == 0x6C:
        result["status"] = f"Wrong Le. Correct: {sw2}."
    elif sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        result["status"] = f"Verification failed. {sw2 & 0x0F} retries left."
    else:
        result["status"] = "See SW1/SW2."

    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Profile package (heavy imports stay lazy so the server starts without pySim)
# ---------------------------------------------------------------------------


_WORKBOOK_SUFFIXES = frozenset({".xlsx", ".xlsm", ".xls", ".ods"})


def _workbook_needs_a_plugin(path: Path) -> str:
    """Explain the workbook route, gated on whether a plugin supplies it.

    Excel-to-SAIP generation is not part of the published core. Whether an
    agent can proceed depends entirely on a private plugin being present,
    so say which case this is rather than emitting one fixed refusal.
    """

    state = ensure_plugin_extensions()
    plugin_tools = list(state.get("tools") or [])
    # A provider may name its converter via ``workbook_tool``; without that
    # the core cannot know which of its tools handles a workbook, so it
    # lists them all and lets the caller read the descriptions.
    named = state.get("workbook_tool")
    if named:
        plugin_tools = [named] + [t for t in plugin_tools if t != named]
    if plugin_tools:
        return json.dumps(
            {
                "error": (
                    f"{path.name!r} is a workbook, not a SAIP package, so it "
                    "cannot be linted directly."
                ),
                "plugin_available": True,
                "next_step": (
                    "A generator plugin is loaded. Convert the workbook with "
                    "one of its tools, then lint the SAIP package it writes."
                ),
                "plugin_tools": plugin_tools,
            },
            indent=2,
        )
    return json.dumps(
        {
            "error": (
                f"{path.name!r} is a workbook, not a SAIP package, and no "
                "Excel-to-SAIP generator plugin is loaded."
            ),
            "plugin_available": False,
            "plugin_loading_enabled": _plugin_loading_enabled(),
            "next_step": (
                "Install a generator plugin under the runtime root and start "
                f"the server with {'' if _plugin_loading_enabled() else 'YGGDRASIM_ALLOW_PLUGINS=1, then '}"
                "call plugin_status to confirm it registered."
            ),
        },
        indent=2,
    )


@mcp.tool(annotations=READS_FILES)
def saip_lint(file_path: str, strict: bool = False) -> str:
    """Lint a SAIP profile package and return the YRL-* findings as JSON.

    Accepts the same inputs as Package > Open: binary DER, ASCII hex text,
    ASN.1 value notation, or transcode JSON. Excel workbooks are not SAIP
    packages and are refused.

    file_path: path to the package.
    strict: raise informational findings to their full severity.
    Returns the lint report: score, severity summary, and each finding with
    its code, spec citation, path, message, and recommendation.
    """
    resolved = Path(file_path).expanduser()
    if not resolved.is_file():
        return json.dumps({"error": f"No such file: {resolved}"})

    # A workbook is not a SAIP package. Converting one needs a generator
    # plugin, so answer differently depending on whether that plugin is
    # actually installed instead of refusing identically either way.
    if resolved.suffix.lower() in _WORKBOOK_SUFFIXES:
        return _workbook_needs_a_plugin(resolved)

    try:
        from yggdrasim_common.gui_server.actions.saip import _load_package_payload_impl
        from Tools.ProfilePackage.lint_engine import SaipProfileLinter
    except ImportError as exc:
        return json.dumps(
            {"error": f"SAIP support is unavailable in this install: {exc}"}
        )

    try:
        payload = _load_package_payload_impl(resolved)
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Could not load {resolved.name}: {exc}"})

    try:
        report = SaipProfileLinter(strict=bool(strict)).lint_decoded_document(
            payload.get("decoded_document") or {},
            resolved.name,
        )
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Lint failed for {resolved.name}: {exc}"})

    result = report.to_dict()
    warnings = payload.get("warnings") or []
    if warnings:
        result["load_warnings"] = warnings
    return json.dumps(result, indent=2)


# ---------------------------------------------------------------------------
# Structure decoding
#
# ``ber_tlv_lookup`` names a single tag and ``apdu_parse`` splits a command
# header; both stay as they are. What follows parses whole structures, which
# is a different question.
# ---------------------------------------------------------------------------


def _clean_hex(raw: str) -> bytes:
    text = str(raw or "").strip().replace(" ", "").replace(":", "").replace("\n", "")
    if text.lower().startswith("0x"):
        text = text[2:]
    return bytes.fromhex(text)


@mcp.tool(annotations=READ_ONLY)
def asn1_decode(hex_data: str) -> str:
    """Recursively decode BER/DER TLV or a full APDU into a named tree.

    Deeper than ber_tlv_lookup: every nested tag is resolved against the
    GSMA/3GPP tag index with its spec source, so a whole EuiccInfo2 or
    ProfileInstallationResult comes back as structure rather than hex.

    hex_data: hex string, with or without spaces.
    """
    try:
        payload = _clean_hex(hex_data)
    except ValueError:
        return json.dumps({"error": "Invalid hex input."})
    if not payload:
        return json.dumps({"error": "Empty input."})

    try:
        from Tools.Asn1TlvDecode.main import DecodeError, decode_bytes
    except ImportError as exc:
        return json.dumps({"error": f"ASN.1 decoder unavailable: {exc}"})

    try:
        return json.dumps(decode_bytes(payload), indent=2)
    except DecodeError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Decode failed: {exc}"})


_SGP32_DECODERS = {
    "euicc_info1": "decode_euicc_info1_summary",
    "notifications": "decode_notifications_response",
    "rat_rules": "decode_rat_rules",
    "eim_configuration": "decode_eim_configuration_entries",
    "get_certs": "decode_get_certs_response",
}


@mcp.tool(annotations=READ_ONLY)
def sgp32_decode(kind: str, hex_response: str) -> str:
    """Decode an SGP.32 / SGP.22 response body into structured fields.

    kind: one of euicc_info1, notifications, rat_rules, eim_configuration,
        get_certs.
    hex_response: the response bytes as hex.
    """
    selected = str(kind or "").strip().lower()
    if selected not in _SGP32_DECODERS:
        return json.dumps(
            {
                "error": f"Unknown kind {kind!r}.",
                "known": sorted(_SGP32_DECODERS),
            }
        )
    try:
        payload = _clean_hex(hex_response)
    except ValueError:
        return json.dumps({"error": "Invalid hex input."})

    try:
        from SCP03.logic import sgp32_decode as decoders
    except ImportError as exc:
        return json.dumps({"error": f"SGP.32 decoders unavailable: {exc}"})

    try:
        decoded = getattr(decoders, _SGP32_DECODERS[selected])(payload)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"{selected} decode failed: {exc}"})
    return json.dumps({"kind": selected, "decoded": decoded}, indent=2, default=str)


@mcp.tool(annotations=READ_ONLY)
def bpp_segment(hex_bpp: str) -> str:
    """Show how a Bound Profile Package splits into ES10b STORE DATA segments.

    Follows SGP.22 Annex M: the A0 ConfigureISDPRequest ships wrapped, and
    each A1/A2/A3 container header is its own segment ahead of its members.
    Useful when an eUICC reports a premature ProfileInstallationResult and
    you need to see the framing it was actually sent.

    hex_bpp: the BF36 Bound Profile Package as hex.
    """
    try:
        payload = _clean_hex(hex_bpp)
    except ValueError:
        return json.dumps({"error": "Invalid hex input."})

    try:
        from SCP11.local_access.session import LocalIsdrSession
    except ImportError as exc:
        return json.dumps({"error": f"SCP11 support unavailable: {exc}"})

    try:
        # Segmentation is a pure function of the bytes; no channel is touched.
        segments = LocalIsdrSession(apdu_channel=None)._segment_bound_profile_package(
            payload
        )
    except ValueError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Segmentation failed: {exc}"})

    return json.dumps(
        {
            "segment_count": len(segments),
            "segments": [
                {
                    "index": index,
                    "tag": segment[:2].hex().upper()
                    if len(segment) > 1 and (segment[0] & 0x1F) == 0x1F
                    else segment[:1].hex().upper(),
                    "length": len(segment),
                    "hex": segment.hex().upper(),
                }
                for index, segment in enumerate(segments, start=1)
            ],
        },
        indent=2,
    )


@mcp.tool(annotations=READS_FILES)
def session_diff(left_path: str, right_path: str) -> str:
    """Diff the APDU traces of two shell session recordings.

    Answers "the same script ran against two cards, where did they stop
    agreeing?". Exchanges are aligned on the command APDU, so one extra
    exchange on a side does not make everything after it look different.

    left_path: baseline recording (.yaml/.yml/.json).
    right_path: recording to compare against the baseline.
    """
    try:
        from yggdrasim_common.session_diff import SessionDiffError, diff_recordings
    except ImportError as exc:
        return json.dumps({"error": f"Session diff unavailable: {exc}"})

    try:
        return json.dumps(diff_recordings(left_path, right_path).to_json(), indent=2)
    except SessionDiffError as exc:
        return json.dumps({"error": str(exc)})


@mcp.tool(annotations=TOUCHES_CARD)
async def card_bridge_transmit(
    apdu_url: str,
    hex_apdu: str,
    token_file: str = "",
    timeout_seconds: int = 30,
    ctx: Context | None = None,
) -> str:
    """Transmit an APDU to a remote card through a Card Bridge or Remote Lab relay.

    Same hazard as pcsc_transmit, one network hop further out: this reaches
    whatever rig the URL points at, so YGGDRASIM_MCP_ALLOW_CARD gates it too.

    apdu_url: the relay endpoint, e.g. http://127.0.0.1:8642/apdu.
    hex_apdu: hex-encoded APDU bytes.
    token_file: path to the bearer-token file (0600). For a Remote Lab rig
        this is the session token, not the bridge's own token.
    timeout_seconds: how long to wait for the card.
    """
    url = str(apdu_url or "").strip()
    if not url.lower().startswith(("http://", "https://")):
        return json.dumps({"error": "apdu_url must be an http(s) URL."})
    try:
        payload_bytes = _clean_hex(hex_apdu)
    except ValueError:
        return json.dumps({"error": "Invalid hex APDU."})
    if not payload_bytes:
        return json.dumps({"error": "Empty APDU."})

    verdict = classify_apdu(payload_bytes)
    refusal = _apdu_refusal(verdict)
    if refusal is not None:
        return refusal
    declined = await _confirm_destructive(ctx, verdict, url)
    if declined is not None:
        return declined

    token = ""
    if str(token_file or "").strip():
        try:
            from yggdrasim_common.remote_lab.security import read_token_file

            token = read_token_file(token_file)
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"Could not read token file: {exc}"})

    try:
        from yggdrasim_common.card_backend import _request_card_relay_json

        response = _request_card_relay_json(
            url,
            method="POST",
            request_json={"apdu": payload_bytes.hex().upper()},
            auth_token=token,
            timeout_seconds=max(1, int(timeout_seconds)),
        )
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Relay request failed: {exc}"})

    status = str(response.get("sw") or response.get("status") or "").upper()
    if len(status) == 4:
        try:
            response["statusMeaning"] = STATUS_WORDS.get(
                int(status, 16), "See SW1/SW2."
            )
        except ValueError:
            pass
    return json.dumps(response, indent=2, default=str)


# ---------------------------------------------------------------------------
# Resources
#
# The reference tables an agent would otherwise burn a tool call per lookup
# on. Reading them whole is cheaper and lets the model cite an exact entry.
# ---------------------------------------------------------------------------


@mcp.resource("yggdrasim://reference/status-words")
def status_word_table() -> str:
    """Every status word this server can name, as JSON."""

    return json.dumps(
        {f"{code:04X}": meaning for code, meaning in sorted(STATUS_WORDS.items())},
        indent=2,
    )


@mcp.resource("yggdrasim://reference/ber-tlv-tags")
def ber_tlv_tag_table() -> str:
    """Every BER-TLV tag this server can name, with its spec citation."""

    return json.dumps(
        {f"{tag:04X}": name for tag, name in sorted(BER_TLV_TAGS.items())},
        indent=2,
    )


@mcp.resource("yggdrasim://reference/spec-sections")
def spec_section_table() -> str:
    """The spec-section index."""

    return json.dumps(SPEC_SECTIONS, indent=2)


@mcp.resource("yggdrasim://reference/test-identifier-ranges")
def test_identifier_table() -> str:
    """Standards-reserved test ranges to use instead of real allocations."""

    # The table stores compiled patterns; expose the source text instead.
    return json.dumps(
        {
            name: {
                key: (value.pattern if hasattr(value, "pattern") else value)
                for key, value in entry.items()
            }
            for name, entry in TEST_IDENTIFIER_RANGES.items()
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Prompts
#
# Generic diagnostic workflows only. Anything that encodes operator
# specifics (real PLMNs, house profile rules, rig inventory) belongs in a
# private plugin, not here.
# ---------------------------------------------------------------------------


@mcp.prompt()
def triage_failed_profile_download(symptom: str = "") -> str:
    """Walk an SGP.22/SGP.32 profile download failure back to its cause."""

    return f"""Triage this profile download failure, one step at a time.

Reported symptom: {symptom or "(none given)"}

1. Establish where it stopped. If you have a session recording from a
   working run and one from the failing run, call session_diff on the pair
   first; the first divergence usually names the cause outright.
2. Decode the last response the eUICC actually returned. Use asn1_decode
   for a raw TLV, or sgp32_decode when you know the response kind.
3. Resolve the status word with status_word_lookup. 6A82, 6985, and 6982
   point at very different problems, so do not skip this.
4. If the eUICC reported a ProfileInstallationResult that looks premature,
   suspect BPP framing: run bpp_segment on the package and check the
   A1/A2/A3 container headers ship as their own segments per SGP.22
   Annex M. A first bare 86 TLV is the classic cause.
5. If the package itself is suspect, run saip_lint and read the FAIL
   findings before the WARN ones.

State the evidence for your conclusion, and say plainly when the evidence
does not support one."""


@mcp.prompt()
def explain_apdu_exchange(apdu: str = "", response: str = "") -> str:
    """Explain one APDU exchange in full, command and response."""

    return f"""Explain this APDU exchange.

Command : {apdu or "(none given)"}
Response: {response or "(none given)"}

Use apdu_parse for the command header, asn1_decode for any TLV payload on
either side, and status_word_lookup for the trailing status word. Name the
spec section that defines the command where you can. Say what the card was
being asked to do, what it answered, and whether that answer is expected."""


@mcp.prompt()
def review_profile_package(file_path: str = "") -> str:
    """Review a SAIP profile package for problems worth acting on."""

    return f"""Review the SAIP profile package at: {file_path or "(path not given)"}

1. Run saip_lint. Read FAIL findings first, then WARN.
2. For each finding, quote the YRL code and the spec citation it carries.
3. Separate genuine defects from findings that are merely strict: a
   template with unresolved placeholders will produce findings that are
   expected rather than wrong.
4. If the operator has house rules beyond the baseline, they belong in a
   policy pack rather than in your judgement; say so instead of inventing
   a rule.

Finish with the shortest list of things actually worth fixing."""


@mcp.tool(annotations=READ_ONLY)
def apdu_risk(hex_apdu: str) -> str:
    """Say whether an APDU is read, write, or irreversible, without sending it.

    Check here before pcsc_transmit or card_bridge_transmit when you are not
    certain what a command does. Nothing is transmitted and no card is
    touched, so this is safe to call with the card gates closed.

    hex_apdu: hex-encoded APDU bytes.
    """
    try:
        payload = _clean_hex(hex_apdu)
    except ValueError:
        return json.dumps({"error": "Invalid hex APDU."})

    verdict = classify_apdu(payload)
    return json.dumps(
        {
            **verdict,
            "would_be_sent": _apdu_refusal(verdict) is None,
            "card_access_enabled": card_access_allowed(),
            "destructive_enabled": destructive_allowed(),
            "note": (
                "Irreversible on a real card; a consumed retry counter does "
                "not come back."
                if verdict["risk"] == "destructive"
                else "Classification is by instruction byte; an unrecognised "
                "instruction is reported as write, not read."
            ),
        },
        indent=2,
    )


#: A whole-package diff can exceed a useful response size.
_MAX_DIFF_ENTRIES = 200


def _clip_value(value: Any, limit: int = 120) -> Any:
    """Keep one changed node from dominating the response."""

    text = value if isinstance(value, str) else repr(value)
    if len(text) <= limit:
        return value
    return f"{text[:limit]}... ({len(text)} chars)"


@mcp.tool(annotations=READS_FILES)
def saip_diff(left_path: str, right_path: str) -> str:
    """Diff two SAIP profile packages structurally.

    Reports what changed between two packages: added, removed, changed,
    and moved nodes, each with a dotted path into the decoded tree.
    Accepts the same inputs as saip_lint.

    left_path: baseline package.
    right_path: package to compare against the baseline.
    """
    left = Path(left_path).expanduser()
    right = Path(right_path).expanduser()
    for candidate in (left, right):
        if not candidate.is_file():
            return json.dumps({"error": f"No such file: {candidate}"})
        if candidate.suffix.lower() in _WORKBOOK_SUFFIXES:
            return _workbook_needs_a_plugin(candidate)

    try:
        from yggdrasim_common.gui_server.actions.saip import _load_package_payload_impl
        from Tools.ProfilePackage.saip_diff_engine import diff_saip_documents
    except ImportError as exc:
        return json.dumps({"error": f"SAIP support is unavailable: {exc}"})

    documents = []
    for candidate in (left, right):
        try:
            documents.append(
                (_load_package_payload_impl(candidate) or {}).get("decoded_document") or {}
            )
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"Could not load {candidate.name}: {exc}"})

    try:
        summary = diff_saip_documents(documents[0], documents[1])
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Diff failed: {exc}"})

    return json.dumps(
        {
            "left": left.name,
            "right": right.name,
            "identical": summary.is_empty,
            "counts": {
                "added": summary.added,
                "removed": summary.removed,
                "changed": summary.changed,
                "moved": summary.moved,
                "total": summary.total,
            },
            # Bounded: a full package diff can run to thousands of nodes.
            "entries": [
                {
                    "path": entry.path,
                    "op": entry.op,
                    "left": _clip_value(entry.value_a),
                    "right": _clip_value(entry.value_b),
                }
                for entry in summary.entries[:_MAX_DIFF_ENTRIES]
            ],
            "entries_truncated": max(0, summary.total - _MAX_DIFF_ENTRIES),
        },
        indent=2,
        default=str,
    )


@mcp.tool(annotations=READS_FILES)
def metadata_lint(file_path: str) -> str:
    """Lint an SGP.22 profile metadata document.

    Reports the StoreMetadata and UpdateMetadata encodings the document
    produces, plus any custom tags it carries.

    file_path: path to the metadata JSON.
    """
    resolved = Path(file_path).expanduser()
    if not resolved.is_file():
        return json.dumps({"error": f"No such file: {resolved}"})

    try:
        from SCP11.local_access.session import LocalIsdrSession
    except ImportError as exc:
        return json.dumps({"error": f"SCP11 support is unavailable: {exc}"})

    try:
        # Resolve first: a relative path is interpreted against the runtime
        # metadata directory, which would silently lint a different file.
        session = LocalIsdrSession(apdu_channel=None)
        report = session.lint_metadata(str(resolved.resolve()))
    except FileNotFoundError as exc:
        return json.dumps({"error": str(exc)})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Metadata lint failed: {exc}"})

    linted = str(report.get("metadata_path") or "")
    if linted and Path(linted).resolve() != resolved.resolve():
        report["warning"] = (
            f"Runtime resolution linted {linted} rather than the requested path."
        )
    return json.dumps(report, indent=2, default=str)


@mcp.tool(annotations=READS_FILES)
def eim_package_lint(file_path: str) -> str:
    """Validate an SGP.32 eIM package document against the ES2+ schema.

    Reports errors, warnings, the package type and version, and the
    per-check spec results.

    file_path: path to the eIM package JSON.
    """
    resolved = Path(file_path).expanduser()
    if not resolved.is_file():
        return json.dumps({"error": f"No such file: {resolved}"})

    try:
        from SCP11.eim_local.eim_package_codec import (
            lint_eim_package_document,
            load_eim_package_document,
        )
    except ImportError as exc:
        return json.dumps({"error": f"eIM support is unavailable: {exc}"})

    try:
        document = load_eim_package_document(str(resolved))
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Could not load {resolved.name}: {exc}"})

    try:
        return json.dumps(lint_eim_package_document(document), indent=2, default=str)
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"eIM package lint failed: {exc}"})


# ---------------------------------------------------------------------------
# Shell batch execution
#
# The operator shells accept a non-interactive ``--cmd "A; B; EXIT"`` batch,
# which is a far smaller surface than reimplementing them. Two constraints
# make it safe to hand an agent.
#
# Only file-backed shells are offered. SCP03 opens a PC/SC reader during
# startup, before any verb runs, so exposing it would put card access behind
# a tool whose name says nothing about cards.
#
# Verbs are allow-listed rather than deny-listed. The shell carries 77 of
# them, several of which launch a TUI that would hang a batch, so an unknown
# verb is refused instead of assumed harmless.
# ---------------------------------------------------------------------------

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _looks_like_a_relative_path(token: str) -> bool:
    """A bare or relative path argument, which the shell resolves its own way."""

    candidate = token.strip().strip("'\"")
    if not candidate or candidate.startswith("-"):
        return False
    if Path(candidate).is_absolute():
        return False
    return "/" in candidate or Path(candidate).suffix.lower() in {
        ".der", ".json", ".txt", ".hex", ".asn", ".asn1", ".csv", ".yaml", ".yml",
    }


def _relative_path_arguments(batch: list[str]) -> list[str]:
    """Path-shaped arguments the shell may resolve against its own directories."""

    flagged: list[str] = []
    for command in batch:
        for token in command.split()[1:]:
            if _looks_like_a_relative_path(token):
                flagged.append(token)
    return flagged


SHELL_WRITE_ENV = "YGGDRASIM_MCP_ALLOW_SHELL_WRITE"

#: Refused in every shell: these execute a file of commands, so nothing
#: inside them ever reaches the verb gate.
_COMMAND_FILE_VERBS = frozenset({"RUN", "SCRIPT"})

#: Refused in every shell: a tool argument reaches the model provider, so a
#: verb taking key material would put a Ki in a transcript.
_SECRET_ARGUMENT_VERBS = frozenset({"DERIVE-OPC"})


@dataclass(frozen=True)
class _ShellSpec:
    """One exposed shell and how each of its verbs is treated."""

    module: str
    summary: str
    #: True when the shell opens a PC/SC reader during startup.
    card: bool
    read: frozenset
    write: frozenset
    destructive: frozenset
    interactive: frozenset = frozenset()


#: Only shells whose verbs were enumerated in full appear here. Guessing a
#: classification for a card shell is how an agent wipes a card.
_SHELLS: dict[str, _ShellSpec] = {
    "profile_package": _ShellSpec(
        module="Tools.ProfilePackage.main",
        summary="SAIP profile package inspection and authoring (files only)",
        card=False,
        read=frozenset({
            "CHECK", "DIFF", "DIFF-PRESET", "DUMP", "HELP", "INFO", "INSPECT",
            "LINT", "LIST", "LIST-AKA", "LIST-TOKENS", "PRESETS",
            "PREVIEW-PRESET", "PROFILE-DIR", "PWD", "RELEASE-GATE", "STATUS",
            "TOKENS", "TREE", "TYPE", "USE", "OPEN", "EXIT", "QUIT",
        }),
        write=frozenset({
            "ADD", "ADD-TOKEN", "APPLY", "APPLY-SIDECAR", "APPLY-TEMPLATE",
            "APPLY-TOKENS", "ENCODE-JSON", "EXPORT", "EXPORT-CSV",
            "EXPORT-SIDECAR", "EXPORT-TOKENS", "EXPORT-TOKENS-CSV",
            "EXTRACT-APPS", "GENERATE-BATCH", "GENERATE-PROFILE",
            "GENERATE-TEMPLATE", "IMPORT-CSV", "IMPORT-TOKENS-CSV",
            "NEW-PROFILE", "NEW-TEMPLATE", "RENAME", "RENAME-TOKEN",
            "RETOKENISE", "RETOKENISE-LENGTHS", "RETOKENIZE",
            "RETOKENIZE-LENGTHS", "SET", "SET-TOKEN", "SPLIT", "TRANSCODE-DIR",
        }),
        destructive=frozenset({
            "DELETE", "REMOVE", "REMOVE-NAA", "REMOVE-TOKEN",
            "PROVISION-AKA", "RANDOMIZE-AKA",
        }),
        interactive=frozenset({
            "DIFF-TUI", "NEW-PROFILE-WIZARD", "TRANSCODE-TUI", "TUI",
            "WIZARD", "WATCH-SIMCARD", "QA",
        }),
    ),
    "scp03": _ShellSpec(
        module="SCP03",
        summary="Card admin: filesystem, registry, GlobalPlatform (DRIVES A CARD)",
        card=True,
        read=frozenset({
            "AIDS", "ARR", "ATR", "BINDS", "CERT-INFO", "GET-IOT", "GUIDE",
            "HELP", "INFO", "KEYS", "LIST", "LIST-IOT", "OTA", "PROFILE-DIFF",
            "READ", "RECORD", "SCAN", "SELECT", "SHOW", "VALIDATE", "EXIT",
            "QA", "DEBUG", "VERBOSE",
        }),
        write=frozenset({
            "AUTH-SD", "CLEAR-GOLD-PROFILE", "DUMP-FS", "EXPORT-EUICC",
            "GOLD-PROFILE", "LOGOUT", "RESET", "SCP02-SD", "SCP03-SD",
            "SET-AID-ALIAS", "SET-DEFAULT", "SET-GOLD-PROFILE", "STK",
            "UPDATE",
        }),
        destructive=frozenset({
            # Applet lifecycle, raw card writes, and key-bag export.
            "EXTRADITE", "INSTALL", "INSTALL-APP", "INSTALL-CAP",
            "INSTALL-EXTRADITION", "INSTALL-FILE", "INSTALL-FOR-INSTALL",
            "INSTALL-FOR-LOAD", "INSTALL-INSTALL", "INSTALL-INSTANCE",
            "INSTALL-LOAD", "INSTALL-PERSONALIZE", "INSTALL-REGISTRY",
            "INSTALL-SELECTABLE", "LOAD", "LOAD-CAP", "MAKE-SELECTABLE",
            "PERSONALIZE", "REGISTRY-UPDATE", "STORE-DATA", "EXPORT-KEYBAG",
        }),
    ),
    "scp11_local_access": _ShellSpec(
        module="SCP11.local_access.main",
        summary="Local eUICC profile management over ES10 (DRIVES A CARD)",
        card=True,
        read=frozenset({
            "CERTS", "DISCOVER", "DISCOVER-VIA-LOCAL-SNAPSHOT",
            "DISCOVER-VIA-SGP22-MANAGER", "EID", "EIM-DISCOVER", "ENABLED",
            "EXPLAIN-LAST", "GET-METADATA", "HELP", "INFO", "LIST", "METADATA",
            "METADATA-LINT", "PROFILE", "SCAN", "SMDP-CERTS", "STATUS",
            "EXIT", "QUIT", "QA",
        }),
        write=frozenset({
            "CANCEL", "DISABLE", "DISABLE-PROFILE", "ENABLE", "ENABLE-PROFILE",
            "RECORD", "START", "STOP", "STORE-METADATA",
            "STORE-METADATA-CUSTOM", "STORE-METADATA-CUSTOM-ALL",
            "UPDATE-METADATA",
        }),
        destructive=frozenset({
            "DELETE", "DELETE-PROFILE", "LOAD-PROFILE", "METADATA-CLEAR",
            "METADATA-RESET", "PROFILE-CLEAR", "PROFILE-RESET",
            "EXPORT-KEYBAG",
        }),
    ),
}

_SHELL_TIMEOUT_SECONDS = 120
_SHELL_OUTPUT_LIMIT = 60_000


def shell_write_allowed() -> bool:
    """Whether verbs that write files may run."""

    return _env_on(SHELL_WRITE_ENV)


def classify_shell_command(command: str, shell: str = "profile_package") -> dict[str, Any]:
    """Classify one shell command by its leading verb."""

    spec = _SHELLS.get(shell)
    verb = str(command or "").strip().split()[0].upper() if command.strip() else ""
    if not verb:
        return {"verb": "", "risk": "empty"}
    if spec is None:
        return {"verb": verb, "risk": "unknown_shell"}
    if verb in _COMMAND_FILE_VERBS:
        return {"verb": verb, "risk": "command_file"}
    if verb in _SECRET_ARGUMENT_VERBS:
        return {"verb": verb, "risk": "secret_argument"}
    if verb in spec.interactive:
        return {"verb": verb, "risk": "interactive"}
    if verb in spec.destructive:
        return {"verb": verb, "risk": "destructive"}
    if verb in spec.read:
        return {"verb": verb, "risk": "read"}
    if verb in spec.write:
        return {"verb": verb, "risk": "write"}
    return {"verb": verb, "risk": "unknown"}


def _shell_batch_refusal(commands: list[str], shell: str = "profile_package") -> str | None:
    """Return a refusal for the first command that may not run, else None."""

    spec = _SHELLS[shell]
    # Checked before the process starts: SCP03 connects to a reader during
    # startup, so even HELP would touch hardware.
    if spec.card and not card_access_allowed():
        return json.dumps({
            "error": (
                f"Refused: the {shell} shell opens a card reader during "
                f"startup, so it needs {CARD_ACCESS_ENV}=1 even to run HELP."
            ),
            "shell": shell,
            "drives_a_card": True,
        })

    for command in commands:
        verdict = classify_shell_command(command, shell)
        risk = verdict["risk"]
        if risk == "empty":
            continue
        if risk == "command_file":
            return json.dumps({
                "error": (
                    f"Refused: {verdict['verb']} executes a file of commands, "
                    "which would carry any verb past this gate unchecked."
                ),
                "verb": verdict["verb"],
            })
        if risk == "secret_argument":
            return json.dumps({
                "error": (
                    f"Refused: {verdict['verb']} takes key material as an "
                    "argument, and a tool argument reaches the model provider."
                ),
                "verb": verdict["verb"],
            })
        if risk == "destructive" and not destructive_allowed():
            return json.dumps({
                "error": (
                    f"Refused: {verdict['verb']} is destructive and cannot be "
                    f"undone. It needs {CARD_ACCESS_ENV}=1 and "
                    f"{DESTRUCTIVE_ENV}=1."
                ),
                "verb": verdict["verb"],
                "risk": "destructive",
            })
        if risk == "interactive":
            return json.dumps({
                "error": (
                    f"Refused: {verdict['verb']} opens an interactive view and "
                    "would hang a non-interactive batch."
                ),
                "verb": verdict["verb"],
            })
        if risk == "unknown":
            return json.dumps({
                "error": (
                    f"Refused: {verdict['verb']} is not a recognised verb for "
                    f"the {shell} shell. Unknown verbs are refused rather than "
                    "assumed safe; run HELP to see what is available."
                ),
                "verb": verdict["verb"],
            })
        if risk == "write" and not shell_write_allowed():
            return json.dumps({
                "error": (
                    f"Refused: {verdict['verb']} writes files. Set "
                    f"{SHELL_WRITE_ENV}=1 to permit it."
                ),
                "verb": verdict["verb"],
                "risk": "write",
            })
    return None


@mcp.tool(annotations=ToolAnnotations(
    readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=True,
))
def shell_run(
    shell: str,
    commands: str,
    timeout_seconds: int = _SHELL_TIMEOUT_SECONDS,
) -> str:
    """Run a batch of operator-shell commands and return the output.

    WARNING: two of these shells drive a real card. With the opt-ins set,
    verbs reachable here can install applets, write keys, disable or delete
    a profile, and export a key bag. None of that can be undone. Use a
    throwaway test card, never one carrying live credentials.

    shell: one of profile_package (files only), scp03 (DRIVES A CARD),
        scp11_local_access (DRIVES A CARD). Run "HELP; EXIT" against a
        shell to see its verbs.
    commands: semicolon-separated batch, executed left to right in one
        non-interactive process. State does not survive between calls, so
        put a whole flow in one batch and pass absolute paths, for example
        "USE /abs/profile.der; INFO; TREE; LINT; EXIT".
    timeout_seconds: how long to allow the batch (default 120).

    Gating, in order. A card-driving shell needs YGGDRASIM_MCP_ALLOW_CARD,
    checked before the process starts because those shells connect to a
    reader during startup. Verbs that write need
    YGGDRASIM_MCP_ALLOW_SHELL_WRITE. Destructive verbs additionally need
    YGGDRASIM_MCP_ALLOW_DESTRUCTIVE. Unknown verbs, interactive verbs, and
    verbs that execute a command file are always refused.
    """
    shell = str(shell or "").strip().lower()
    spec = _SHELLS.get(shell)
    if spec is None:
        return json.dumps({
            "error": f"Unknown shell {shell!r}.",
            "known": {name: entry.summary for name, entry in _SHELLS.items()},
        })

    batch = [part.strip() for part in str(commands or "").split(";")]
    if not any(batch):
        return json.dumps({"error": "No commands given."})

    refusal = _shell_batch_refusal(batch, shell)
    if refusal is not None:
        return refusal

    import subprocess

    argv = [sys.executable, "-W", "ignore::RuntimeWarning", "-m",
            spec.module, "--cmd", str(commands)]
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=max(1, min(int(timeout_seconds), 600)),
            cwd=str(REPO_ROOT),
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": f"Batch timed out after {timeout_seconds}s."})
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Could not run the {shell} shell: {exc}"})

    # The shell paints its output; colour codes are noise to a caller.
    stdout = _ANSI_ESCAPE.sub("", completed.stdout or "")
    stderr = _ANSI_ESCAPE.sub("", completed.stderr or "")
    payload: dict[str, Any] = {
        "shell": shell,
        "drives_a_card": spec.card,
        "exit_code": completed.returncode,
        "verbs": [classify_shell_command(c, shell)["verb"] for c in batch if c.strip()],
        "write_enabled": shell_write_allowed(),
        "destructive_enabled": destructive_allowed(),
        "output": stdout[:_SHELL_OUTPUT_LIMIT],
        "output_truncated": max(0, len(stdout) - _SHELL_OUTPUT_LIMIT),
    }
    if stderr.strip():
        payload["stderr"] = stderr[:4000]

    # A relative path is resolved against the shell's own profile and
    # transcode directories, not the working directory. Left unflagged, a
    # caller can ask about one package and be answered about another.
    relative = _relative_path_arguments(batch)
    if relative:
        payload["warning"] = (
            "Relative path argument(s) "
            + ", ".join(sorted(set(relative))[:4])
            + ": this shell resolves those against its own directories, so it "
            "may act on a different file. Pass absolute paths."
        )
    if "Path not found" in stdout:
        payload["path_not_found"] = True
    return json.dumps(payload, indent=2)


@mcp.tool(annotations=PROBES_WORLD)
def runtime_status() -> str:
    """Report the runtime root, build flavor, and any live service state.

    Read-only. Services are started and stopped by an operator, not from
    here: stopping a rig mid-session is a different class of risk from a
    bad APDU and the value does not justify it.

    Secrets are never included. Remote Lab devices come back through the
    registry's redacted view, which reports only whether a token file
    exists rather than where it is or what it contains.
    """
    report: dict[str, Any] = {"services": {}}

    try:
        from yggdrasim_common.runtime_paths import runtime_path, runtime_root

        report["runtime_root"] = runtime_root()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Runtime paths unavailable: {exc}"})

    try:
        from yggdrasim_common.flavor import get_flavor, get_flavor_source

        report["flavor"] = get_flavor()
        report["flavor_source"] = get_flavor_source()
    except Exception:  # noqa: BLE001
        report["flavor"] = "unknown"

    try:
        from yggdrasim_common.__about__ import __version__

        report["version"] = __version__
    except Exception:  # noqa: BLE001
        pass

    # HIL supervisor: a status document written by the running supervisor.
    hil: dict[str, Any] = {"running": False}
    try:
        from Tools.HilBridge.supervisor import SUPERVISOR_STATE_FILENAME

        state_file = Path(runtime_path("state", SUPERVISOR_STATE_FILENAME))
        hil["state_path"] = str(state_file)
        if state_file.is_file():
            payload = json.loads(state_file.read_text(encoding="utf-8"))
            hil["running"] = True
            for key in ("pid", "status", "started_at", "usb_vidpid", "host", "port"):
                if key in payload:
                    hil[key] = payload[key]
        else:
            hil["note"] = "No supervisor state document; the HIL bridge is not running."
    except ImportError as exc:
        hil["note"] = f"HIL support unavailable: {exc}"
    except Exception as exc:  # noqa: BLE001
        hil["note"] = f"Could not read supervisor state: {exc}"
    report["services"]["hil_bridge"] = hil

    # Remote Lab: registry of known rigs, tokens redacted by the registry.
    lab: dict[str, Any] = {"devices": [], "count": 0}
    try:
        from yggdrasim_common.remote_lab.registry import list_devices, registry_path

        lab["registry_path"] = registry_path()
        devices = list_devices()
        lab["devices"] = devices
        lab["count"] = len(devices)
        if not devices:
            lab["note"] = "No rigs registered."
    except ImportError as exc:
        lab["note"] = f"Remote Lab support unavailable: {exc}"
    except Exception as exc:  # noqa: BLE001
        lab["note"] = f"Could not read the rig registry: {exc}"
    report["services"]["remote_lab"] = lab

    return json.dumps(report, indent=2, default=str)


@mcp.tool(annotations=READ_ONLY)
def plugin_status() -> str:
    """Report which optional plugin-backed capabilities this server has.

    Call this before assuming a capability exists. Tools that depend on a
    private plugin refuse when it is absent, and this says which of them
    are usable right now and which extra tools a plugin has contributed.

    Nothing here loads or executes a plugin beyond what the server already
    did at startup.
    """
    state = ensure_plugin_extensions()
    extra = list(state.get("tools") or [])
    return json.dumps(
        {
            "extensions_active": bool(state.get("registered")),
            "capability": MCP_EXTENSION_CAPABILITY,
            "plugin_tools": extra,
            "plugin_loading_enabled": _plugin_loading_enabled(),
            "errors": state.get("errors") or {},
            "note": (
                "Plugin-provided tools are listed above and can be called "
                "directly."
                if extra
                else "No plugin extensions are registered; only the built-in "
                "tools are available."
            ),
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Private extensions
#
# Everything above is generic. Operator specifics -- real PLMNs, house
# profile rules, rig inventory -- belong in a plugin under the runtime
# root, which is never published. A plugin registers the capability below
# and gets the live FastMCP instance to decorate.
# ---------------------------------------------------------------------------

MCP_EXTENSION_CAPABILITY = "mcp_extensions"

#: Populated by :func:`ensure_plugin_extensions`; read by the gate below.
_EXTENSION_STATE: dict[str, Any] = {}


def load_plugin_extensions(server: Any = None) -> dict[str, Any]:
    """Let a private plugin add tools, resources, and prompts.

    Plugin loading is opt-in (``YGGDRASIM_ALLOW_PLUGINS=1``) and the server
    must start regardless, so every step here reports rather than raises.
    Returns a report the caller can log.
    """

    target = mcp if server is None else server
    report: dict[str, Any] = {
        "capability": MCP_EXTENSION_CAPABILITY,
        "registered": False,
        "errors": {},
    }

    try:
        from yggdrasim_common.plugin_runtime import get_capability, plugin_load_errors
    except ImportError as exc:
        report["errors"]["import"] = str(exc)
        return report

    try:
        provider = get_capability(MCP_EXTENSION_CAPABILITY)
    except Exception as exc:  # noqa: BLE001
        report["errors"]["lookup"] = str(exc)
        return report

    try:
        report["errors"].update(plugin_load_errors())
    except Exception:  # noqa: BLE001
        pass

    if provider is None:
        return report

    # Same health contract the GUI action registry honours: a plugin that
    # declares its actions unavailable is skipped, not half-registered.
    health = getattr(provider, "health", None)
    if callable(health):
        try:
            health_report = health()
        except Exception as exc:  # noqa: BLE001
            report["errors"]["health"] = f"health check failed: {exc}"
            return report
        if isinstance(health_report, dict) and health_report.get("actions_available") is False:
            issues = "; ".join(
                str(item) for item in (health_report.get("dependency_issues") or ()) if str(item)
            )
            report["errors"]["health"] = "actions unavailable" + (f": {issues}" if issues else "")
            return report

    register = getattr(provider, "register", None)
    if not callable(register):
        report["errors"]["contract"] = (
            f"{MCP_EXTENSION_CAPABILITY} provider must expose register(mcp)"
        )
        return report

    before = set(_tool_names(target))
    try:
        register(target)
    except Exception as exc:  # noqa: BLE001
        report["errors"]["register"] = str(exc)
        return report

    report["registered"] = True
    report["tools"] = sorted(set(_tool_names(target)) - before)
    hinted = getattr(provider, "workbook_tool", "")
    if isinstance(hinted, str) and hinted:
        report["workbook_tool"] = hinted
    _EXTENSION_STATE.update(report)
    return report


def _plugin_loading_enabled() -> bool:
    """Whether the runtime is allowed to import plugins at all."""

    try:
        from yggdrasim_common.plugin_runtime import _plugin_loading_allowed

        return bool(_plugin_loading_allowed())
    except Exception:  # noqa: BLE001
        return False


def _tool_names(server: Any) -> list[str]:
    """Best-effort tool inventory across FastMCP versions and test stubs."""

    registry = getattr(server, "tools", None)
    if isinstance(registry, dict):
        return list(registry)
    manager = getattr(server, "_tool_manager", None)
    listing = getattr(manager, "list_tools", None)
    if callable(listing):
        try:
            return [getattr(t, "name", "") for t in listing()]
        except Exception:  # noqa: BLE001
            return []
    return []


def ensure_plugin_extensions(server: Any = None) -> dict[str, Any]:
    """Load private extensions once, and report the same state to every caller.

    ``run_cli`` is not the only entry point: a client may list tools without
    ever reaching it, and a tool needs to know whether a plugin-backed path
    exists before refusing work. Loading here keeps those answers consistent.
    """

    if _EXTENSION_STATE.get("loaded"):
        return dict(_EXTENSION_STATE)
    report = load_plugin_extensions(server)
    report["loaded"] = True
    _EXTENSION_STATE.clear()
    _EXTENSION_STATE.update(report)
    return dict(_EXTENSION_STATE)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def run_cli() -> int:
    """Console-script entry point: serve MCP over stdio."""

    if not card_access_allowed():
        _LOGGER.info(
            "card tools disabled; set %s=1 to enable pcsc_transmit",
            CARD_ACCESS_ENV,
        )

    extensions = load_plugin_extensions()
    if extensions["registered"]:
        _LOGGER.info("registered private MCP extensions from a runtime plugin")
    for stage, detail in extensions["errors"].items():
        _LOGGER.warning("MCP extension %s: %s", stage, detail)

    mcp.run(transport="stdio")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
