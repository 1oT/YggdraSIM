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

# Two orthogonal questions, one variable each.
#
#   ACCESS_ENV  what may be done: read (the default) or write
#   CARD_ACCESS_ENV  whether hardware may be reached at all
#
# They are separate because "may this agent change anything" and "may it
# touch my card" are different decisions. A profile author wants write
# without a reader; someone reading a card wants the reader without writes.
ACCESS_ENV = "YGGDRASIM_MCP_ACCESS"
CARD_ACCESS_ENV = "YGGDRASIM_MCP_ALLOW_CARD"

#: Permits verbs that execute a file of commands. Off by default because the
#: verb classifier cannot see inside such a file, so nothing in it is checked.
SCRIPT_FILES_ENV = "YGGDRASIM_MCP_ALLOW_SCRIPT_FILES"

ACCESS_READ = "read"
ACCESS_WRITE = "write"

_TRUTHY = ("1", "true", "yes", "on")


def _env_on(name: str) -> bool:
    return str(os.environ.get(name, "")).strip().lower() in _TRUTHY


def access_mode() -> str:
    """The server's access level: ``read`` by default, ``write`` when set."""

    raw = str(os.environ.get(ACCESS_ENV, "")).strip().lower()
    if raw in (ACCESS_WRITE, "readwrite", "read-write", "rw"):
        return ACCESS_WRITE
    return ACCESS_READ


def write_allowed() -> bool:
    """Whether anything may be changed: files, cards, or configuration.

    One switch rather than a ladder. Everything an operator can do from a
    shell is reachable at this level, including operations that cannot be
    undone, so the documentation warns rather than the code subdividing.
    """

    return access_mode() == ACCESS_WRITE


def card_access_allowed() -> bool:
    """Whether tools that reach a physical card are enabled."""

    return _env_on(CARD_ACCESS_ENV)


def script_files_allowed() -> bool:
    """Whether verbs that execute a file of commands may run.

    Deliberately its own switch. Such a file bypasses verb classification
    entirely, so enabling it is a statement that the caller trusts whatever
    the file contains.
    """

    return _env_on(SCRIPT_FILES_ENV)


# The risk table lives in yggdrasim_common.apdu_risk so the card-behaviour
# prober and this server cannot disagree about what a command does.
from yggdrasim_common.apdu_risk import classify_apdu  # noqa: E402


def _status_word_meaning(sw1: int, sw2: int) -> str:
    """Resolve SW1/SW2, including the families that encode a value in SW2."""

    sw_int = (sw1 << 8) | sw2
    if sw_int in STATUS_WORDS:
        return STATUS_WORDS[sw_int]
    if sw1 == 0x61:
        return f"Success. {sw2} bytes available."
    if sw1 == 0x6C:
        return f"Wrong Le. Correct: {sw2}."
    if sw1 == 0x63 and (sw2 & 0xF0) == 0xC0:
        return f"Verification failed. {sw2 & 0x0F} retries left."
    return "See SW1/SW2."


def _apdu_refusal(verdict: dict[str, Any], *, simulated: bool = False) -> str | None:
    """Return a refusal payload when this APDU may not be sent, else None.

    ``simulated`` waives the card gate only: the simulator has no hardware
    to protect, but it does carry state, so writes still need write access.
    """
    if not simulated and not card_access_allowed():
        return _card_access_denied()
    if verdict["risk"] in ("write", "destructive") and not write_allowed():
        irreversible = verdict["risk"] == "destructive"
        return json.dumps(
            {
                "error": (
                    f"Refused: {verdict['name']} changes the card, and this "
                    f"server is read-only. Set {ACCESS_ENV}={ACCESS_WRITE} to "
                    "permit it."
                ),
                "ins": verdict["ins"],
                "risk": verdict["risk"],
                "access_mode": access_mode(),
                "hint": (
                    "Retry counters do not reset and a terminated card does "
                    "not recover. Use a throwaway test card."
                    if irreversible
                    else "An unrecognised instruction is treated as a write, "
                    "because not having seen it is not evidence it is safe."
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

# ETSI TS 102 221 clause 10.2.1 and GlobalPlatform Card Specification
# 2.3.1 table 11-10. '61XX', '6CXX', '63CX', '91XX' and '92XX' carry a
# value in SW2 and are handled by status_word_lookup rather than listed.
STATUS_WORDS: dict[int, str] = {
    0x9000: "Success",
    0x9300: "SIM Application Toolkit is busy; command cannot be executed at present",
    0x6281: "Part of returned data may be corrupted",
    0x6282: "End of file/record reached before reading Le bytes, or unsuccessful search",
    0x6283: "Selected file invalidated",
    0x6285: "Selected file in termination state",
    0x62F1: "More data available",
    0x62F2: "More data available and proactive command pending",
    0x62F3: "Response data available",
    0x6300: "Authentication failed",
    0x6310: "More data available (GlobalPlatform GET STATUS continuation)",
    0x63F1: "More data expected",
    0x63F2: "More data expected and proactive command pending",
    0x6400: "State of non-volatile memory unchanged / no specific diagnosis",
    0x6500: "State of non-volatile memory changed, no information given",
    0x6581: "Memory problem",
    0x6700: "Wrong length",
    0x6800: "Function in CLA not supported, no information given",
    0x6881: "Logical channel not supported or not active",
    0x6882: "Secure messaging not supported",
    0x6900: "Command not allowed, no information given",
    0x6981: "Command incompatible with file structure",
    0x6982: "Security status not satisfied",
    0x6983: "Authentication/PIN method blocked",
    0x6984: "Referenced data invalidated",
    0x6985: "Conditions of use not satisfied",
    0x6986: "Command not allowed (no EF selected)",
    0x6989: "Command not allowed: secure channel, security not satisfied",
    0x6A80: "Incorrect parameters in the data field",
    0x6A81: "Function not supported",
    0x6A82: "File not found / Applet not found",
    0x6A83: "Record not found",
    0x6A84: "Not enough memory space",
    0x6A86: "Incorrect parameters P1-P2",
    0x6A87: "Lc inconsistent with P1-P2",
    0x6A88: "Referenced data not found",
    0x6B00: "Wrong parameter(s) P1-P2",
    0x6D00: "Instruction code not supported or invalid",
    0x6E00: "Class not supported",
    0x6F00: "Technical problem, no precise diagnosis",
    0x9850: "INCREASE cannot be performed, max value reached",
    0x9862: "Authentication error, application specific",
    0x9863: "Security session or association expired",
    0x9864: "Minimum UICC suspension time is too long",
}

# Names are the ASN.1 type or field the tag carries. Clause numbers are
# given only where the specification was checked; several ES10b functions
# share a clause and a wrong number is worse than none.
BER_TLV_TAGS: dict[int, str] = {
    0xBF20: "EUICCInfo1 / GetEuiccInfo1Request (SGP.22 §5.7.8 GetEUICCInfo)",
    0xBF22: "EUICCInfo2 / GetEuiccInfo2Request (SGP.22 §5.7.8 GetEUICCInfo)",
    0xBF2B: "RetrieveNotificationsList (SGP.22 §5.7.10)",
    0xBF2D: "ProfileInfoList (SGP.22 ES10c GetProfilesInfo)",
    0xBF31: "EnableProfile (SGP.22 ES10c)",
    0xBF32: "DisableProfile (SGP.22 ES10c)",
    0xBF33: "DeleteProfile (SGP.22 ES10c)",
    0xBF3C: "EuiccConfiguredData (SGP.22 ES10a)",
    0xBF3E: "GetEuiccData (SGP.22 ES10c)",
    0xBF43: "GetRat / Rules Authorisation Table (SGP.22 §5.7.22 GetRAT)",
    0xBF51: "EuiccPackageRequest or EuiccPackageResult (SGP.32 Annex D)",
    0xBF52: "IpaEuiccDataRequest or IpaEuiccDataResponse (SGP.32 Annex D)",
    0xBF55: "GetEimConfigurationData (SGP.32 §5.9.18)",
    0xBF56: "GetCerts (SGP.32 §5.9.10)",
    0xBF58: "ProfileRollbackRequest or ProfileRollbackResponse (SGP.32 Annex D)",
    0xBF5F: "GetConnectivityParameters (SGP.32 Annex D)",
    0x4F: "AID (Application Identifier -- ISO 7816-5)",
    0x5A: "ICCID (ETSI TS 102 221)",
    0x90: "profileNickname (SGP.22 ProfileInfo)",
    0x91: "serviceProviderName (SGP.22 ProfileInfo)",
    0x92: "profileName (SGP.22 ProfileInfo)",
    0x93: "iconType (SGP.22 ProfileInfo)",
    0x94: "icon (SGP.22 ProfileInfo)",
    0x95: "profileClass (SGP.22 ProfileInfo)",
    0x9F70: "profileState (SGP.22 ProfileInfo)",
    0xA9: "euiccCiPKIdListForVerification (SGP.22 EUICCInfo1 / EUICCInfo2)",
    0xAA: "euiccCiPKIdListForSigning (SGP.22 EUICCInfo1 / EUICCInfo2)",
    # Context-class tags whose meaning is fixed by the structure that
    # encloses them, not by the tag: '80' is GP KeyType inside a key
    # template and a result code elsewhere.
    0x80: "context-0 primitive; meaning depends on the enclosing structure",
    0xA0: "context-0 constructed; meaning depends on the enclosing structure",
    0xA1: "context-1 constructed; meaning depends on the enclosing structure",
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
        # TS 102 221 table 10.10 note: after a PIN verification 'X' is the
        # number of retries left; after any other command it is the number
        # of internal retries the card performed. Without the command that
        # produced it, both readings have to be given.
        count = sw2 & 0x0F
        meaning = (
            f"After PIN verification: verification failed, {count} retries remaining. "
            f"After any other command: successful, after {count} internal retries."
        )
    elif sw1 == 0x91:
        meaning = f"Success, with a proactive command pending. {sw2} bytes of response data."
    elif sw1 == 0x92:
        meaning = f"Success, with extra information about an ongoing data transfer ('{sw2:02X}')."
    else:
        meaning = "Unknown status word."

    return json.dumps({"SW1": f"0x{sw1:02X}", "SW2": f"0x{sw2:02X}", "meaning": meaning})


@mcp.tool(annotations=READ_ONLY)
def ber_tlv_lookup(tag: str) -> str:
    """Look up a BER-TLV tag by hex value and return its name and spec reference.
    Covers SGP.22 / SGP.32 ES10 tags (0xBF20-0xBF56), ISO tags (0x4F, 0x5A),
    the SGP.22 ProfileInfo fields (0x90-0x95, 0x9F70) and the eSIM CA key
    identifier lists (0xA9-0xAA).
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
    Requires YGGDRASIM_MCP_ALLOW_CARD. Anything that changes the card also
    requires YGGDRASIM_MCP_ACCESS=write; call apdu_risk first if unsure.
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

    result["status"] = _status_word_meaning(sw1, sw2)

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
    except (OSError, ValueError) as exc:
        # A recording is JSON text, so a binary or truncated file reaches
        # here as UnicodeDecodeError or JSONDecodeError, both ValueError.
        # Raising would surface as a protocol error instead of an answer.
        return json.dumps({
            "error": f"Could not read a recording: {type(exc).__name__}: {exc}",
        })


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

    # A bridge may report the status word as one hex string or as two
    # integers. Resolve either, and always add the same normalised pair the
    # other card tools return, so a caller does not branch on the shape.
    status = str(response.get("sw") or response.get("status") or "").upper()
    if len(status) != 4 and "sw1" in response and "sw2" in response:
        try:
            status = f"{int(response['sw1']):02X}{int(response['sw2']):02X}"
        except (TypeError, ValueError):
            status = ""
    if len(status) == 4:
        try:
            meaning = _status_word_meaning(int(status[:2], 16), int(status[2:], 16))
        except ValueError:
            meaning = ""
        if meaning:
            response["status_word"] = status
            response["meaning"] = meaning
            response.setdefault("statusMeaning", meaning)
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
            "access_mode": access_mode(),
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


#: Verbs that reach a card even though their shell opens no reader at
#: startup. SCP80 builds an envelope offline but SEND puts it on a card.
_CARD_REACHING_VERBS = frozenset({"SEND", "SENDRAW", "OTA"})

#: Gated on their own opt-in in every shell: these run commands this gate
#: never sees. RUN and SCRIPT take a file; RAW passes its arguments through
#: to the underlying tool as a subcommand.
_COMMAND_FILE_VERBS = frozenset({"RUN", "SCRIPT", "RAW"})

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
    #: Verbs that reach a card from a shell that opens no reader itself.
    #: Only meaningful when ``card`` is False; a card shell gates everything.
    card_verbs: frozenset = frozenset()


#: Only shells whose verbs were enumerated in full appear here. Guessing a
#: classification for a card shell is how an agent wipes a card.
_SHELLS: dict[str, _ShellSpec] = {
    "profile_package": _ShellSpec(
        module="Tools.ProfilePackage.main",
        summary="SAIP profile package inspection and authoring (files only)",
        card=False,
        read=frozenset({
            "CHECK", "DIFF", "DIFF-PRESET", "DUMP", "HELP", "INFO", "INSPECT",
            "LINT", "LIST-AKA", "LIST-TOKENS", "PRESETS", "PREVIEW-PRESET",
            "PROFILE-DIR", "PWD", "Q", "STATUS", "TREE", "USE", "OPEN",
            "EXIT", "QUIT",
        }),
        write=frozenset({
            # TOKENS dispatches its own SET / ADD / REMOVE subcommands, which
            # the leading-verb gate cannot see, so it sits at the write tier.
            # LIST-TOKENS is the read-only way to see them.
            "ADD-TOKEN", "APPLY-TEMPLATE", "APPLY-TOKENS", "ENCODE-JSON",
            "EXPORT-TOKENS", "EXPORT-TOKENS-CSV", "EXTRACT-APPS",
            "GENERATE-BATCH", "GENERATE-PROFILE", "GENERATE-TEMPLATE",
            "IMPORT-TOKENS-CSV", "NEW-PROFILE", "NEW-TEMPLATE",
            "RENAME-TOKEN", "RETOKENISE-LENGTHS", "RETOKENIZE-LENGTHS",
            "SET-TOKEN", "SPLIT", "TOKENS", "TOOL", "TRANSCODE-DIR",
        }),
        destructive=frozenset({
            "REMOVE-NAA", "REMOVE-TOKEN", "PROVISION-AKA", "RANDOMIZE-AKA",
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
            "AIDS", "APPS", "ARR", "ATR", "BINDS", "CERT-INFO", "CLS",
            "GET-IOT", "GUIDE", "HELP", "INFO", "KEYS", "LIST", "LIST-IOT",
            "OTA", "PKGS", "PROFILE-DIFF", "Q", "READ", "RECORD", "SCAN",
            "SD", "SELECT", "SHOW", "VALIDATE", "EXIT", "QA", "DEBUG",
            "VERBOSE",
        }),
        write=frozenset({
            "AUTH-SD", "CLEAR-GOLD-PROFILE", "DUMP-FS", "EXPORT-EUICC",
            "GOLD-PROFILE", "LOGOUT", "RESET", "RUN-AUTH-TEST", "SCP02-SD",
            "SCP03-SD", "SET-AID-ALIAS", "SET-DEFAULT", "SET-GOLD-PROFILE",
            "STK", "UPDATE",
        }),
        destructive=frozenset({
            # Applet lifecycle, raw card writes, and key-bag export.
            "EXTRADITE", "INSTALL", "INSTALL-APP", "INSTALL-CAP",
            "INSTALL-EXTRADITION", "INSTALL-FILE", "INSTALL-FOR-INSTALL",
            "INSTALL-FOR-LOAD", "INSTALL-INSTALL", "INSTALL-INSTANCE",
            "INSTALL-LOAD", "INSTALL-PERSONALIZE", "INSTALL-REGISTRY",
            "INSTALL-SELECTABLE", "LOAD", "LOAD-CAP", "MAKE-SELECTABLE",
            "PERSONALIZE", "REGISTRY-UPDATE", "STORE-DATA", "EXPORT-KEYBAG",
            # GP delete and SET STATUS lock/unlock.
            "DEL", "DELETE", "LOCK", "UNLOCK",
        }),
        interactive=frozenset({
            # ShellInteractiveWizards.* prompt for input, so a batch would
            # block on a terminal that is not there.
            "CONFIG", "FS-ADMIN", "GET-DATA", "MANAGE-CHANNEL", "MANAGE-PIN",
            "MANAGE-PROFILE", "PUT-KEY", "REPORT", "RUN-AUTH", "SET-STATUS",
            "WIZARD",
        }),
    ),
    "scp80": _ShellSpec(
        module="SCP80",
        summary="SCP80 OTA: build an envelope offline, or SEND it to a card",
        # Opens no reader at startup, but SEND, SENDRAW and OTA put commands
        # on a card, so those verbs carry their own card check.
        card=False,
        read=frozenset({"HELP", "HISTORY", "SHOW", "EXIT", "QUIT", "Q", "QA"}),
        write=frozenset({
            "BUILD", "ICCID", "SET", "RESET", "OTA", "SEND", "SENDRAW",
        }),
        destructive=frozenset(),
        interactive=frozenset({
            # Hands the reader to the SCP03 shell's own REPL, which then
            # waits on a terminal this batch does not have.
            "ADMIN",
        }),
    ),
    "scp11_local_access": _ShellSpec(
        module="SCP11.local_access.main",
        summary="Local eUICC profile management over ES10 (DRIVES A CARD)",
        card=True,
        read=frozenset({
            "?", "CERTS", "DISCOVER", "EIM-DISCOVER", "EXPLAIN-LAST",
            "GET-METADATA", "HELP", "INFO", "LIST", "METADATA",
            "METADATA-LINT", "PROFILE", "Q", "SCAN", "SMDP-CERTS", "STATUS",
            "EXIT", "QUIT", "QA",
        }),
        write=frozenset({
            # RECORD dispatches START / STOP / CANCEL itself; all three are
            # write-tier, so the leading verb carries the right class.
            "DISABLE", "DISABLE-PROFILE", "ENABLE", "ENABLE-PROFILE",
            "RECORD", "STORE-METADATA", "STORE-METADATA-CUSTOM",
            "STORE-METADATA-CUSTOM-ALL", "UPDATE-METADATA",
        }),
        destructive=frozenset({
            "DELETE", "DELETE-PROFILE", "LOAD-PROFILE", "METADATA-CLEAR",
            "METADATA-RESET", "PROFILE-CLEAR", "PROFILE-RESET",
            "EXPORT-KEYBAG",
        }),
    ),
    "scp11_live": _ShellSpec(
        module="SCP11.live.main",
        summary="SGP.22/SGP.32 profile download and eUICC management (DRIVES A CARD)",
        # Startup preflight enumerates PC/SC readers before any verb runs.
        card=True,
        read=frozenset({
            "?", "AIDS", "DISCOVER", "EIM-DISCOVER", "ES9-CERT-INFO",
            "GET-ALL-DATA", "GET-CERTS", "GET-EID", "GET-EIM-CONFIG",
            "GET-ES9", "GET-EUICC-INFO1", "GET-EUICC-INFO2", "GET-METADATA",
            "GET-NOTIFICATIONS", "GET-POL", "GET-RAT", "GET-SMDP", "H",
            "HELP", "HELP-ALL", "INFO", "LIST", "METADATA", "Q", "QA",
            "READ-METADATA", "SCAN", "STATUS", "EXIT", "QUIT",
        }),
        write=frozenset({
            "CLEAR-NOTIFICATIONS", "DISABLE-PROFILE", "EIM-AUTHENTICATE",
            "ENABLE-PROFILE", "REMOVE-NOTIFICATION", "SET-ES9", "SET-ES9-CA",
            "SET-ES9-TLS", "SET-POL", "SET-SMDP", "STORE-METADATA",
            "VERIFY-SCP11",
        }),
        destructive=frozenset({
            # Each of these installs a profile, wipes session state, or runs
            # a flow whose steps are chosen by the remote side.
            "DELETE-PROFILE", "DOWNLOAD", "DOWNLOAD-AC", "DOWNLOAD-PROFILE",
            "EIM-DOWNLOAD", "FLOW", "POLL", "RESET",
        }),
    ),
    "scp11_eim": _ShellSpec(
        module="SCP11.eim_local.main",
        summary="SGP.32 local eIM: author, lint, and issue eIM packages",
        # HELP and the package-authoring verbs run with no reader present.
        # The card-facing subset carries its own check through card_verbs.
        card=False,
        read=frozenset({
            "?", "COUNTERS", "DISCOVER", "EIM-CERTS", "EIM-DISCOVER",
            "EIM-PACKAGE", "EIM-PACKAGE-EXPLAIN", "EIM-PACKAGE-LINT",
            "ERROR-CODES", "GET-EIM-CONFIG", "GET-METADATA", "HANDOVER-STATUS",
            "HELP", "HOTFOLDER", "HOTFOLDER-LIST", "HOTFOLDER-METADATA",
            "INFO", "ISDR-GET-EIM-CONFIG", "LIST", "METADATA",
            "METADATA-LINT", "PATHS", "PROFILE", "Q", "QA", "RESP-LOG",
            "RESP-LOG-FILTER", "RESPONSE-LOG", "SCAN", "STATUS", "EXIT",
            "QUIT",
        }),
        write=frozenset({
            "ADD-EIM", "ADD-INITIAL-EIM", "COUNTER", "DISABLE",
            "DISABLE-PROFILE", "EIM-ACK", "EIM-ACKNOWLEDGE", "ENABLE",
            "ENABLE-PROFILE", "ERROR-CODE-SET", "HANDOVER-SET",
            "HOTFOLDER-AGGREGATE", "HOTFOLDER-EXPORT", "IPAD-DISCOVER",
            "ISDR-ADD-EIM", "ISDR-ADD-INITIAL-EIM", "NOTIF-HYGIENE",
            "RECORD", "STORE-METADATA", "UPDATE-METADATA",
        }),
        destructive=frozenset({
            # Issuing a package executes whatever that JSON carries, which
            # may be a DeleteEim or a memory reset. The classifier cannot
            # read the file, so every issue path sits at the top tier.
            "DELETE", "DELETE-EIM", "DELETE-PROFILE", "EIM-PACKAGE-CLEAR",
            "EIM-PACKAGE-ISSUE", "EIM-PACKAGE-ISSUE-ALL", "EUICC-MEMORY-RESET",
            "HOTFOLDER-CAMPAIGN", "HOTFOLDER-CLEAR", "HOTFOLDER-FETCH",
            "IPAD-LIVE", "IPAD-TEST", "ISDR-DELETE-EIM",
            "ISDR-EUICC-MEMORY-RESET", "ISDR-LOAD-PACKAGE", "ISDR-PACKAGE",
            "LOAD-EIM-PACKAGE", "LOAD-PROFILE", "METADATA-CLEAR",
            "POLL-CAMPAIGN", "PROFILE-CLEAR", "RESP-LOG-CLEAR",
        }),
        card_verbs=frozenset({
            "ADD-EIM", "ADD-INITIAL-EIM", "DELETE-EIM", "DELETE-PROFILE",
            "DISABLE", "DISABLE-PROFILE", "DISCOVER", "EIM-ACK",
            "EIM-ACKNOWLEDGE", "EIM-CERTS", "EIM-DISCOVER",
            "EIM-PACKAGE-ISSUE", "EIM-PACKAGE-ISSUE-ALL", "ENABLE",
            "ENABLE-PROFILE", "EUICC-MEMORY-RESET", "GET-EIM-CONFIG",
            "HOTFOLDER-CAMPAIGN", "HOTFOLDER-FETCH", "INFO", "IPAD-DISCOVER",
            "IPAD-LIVE", "IPAD-TEST", "ISDR-ADD-EIM", "ISDR-ADD-INITIAL-EIM",
            "ISDR-DELETE-EIM", "ISDR-EUICC-MEMORY-RESET",
            "ISDR-GET-EIM-CONFIG", "ISDR-LOAD-PACKAGE", "ISDR-PACKAGE",
            "LOAD-EIM-PACKAGE", "LOAD-PROFILE", "NOTIF-HYGIENE",
            "POLL-CAMPAIGN", "SCAN", "STORE-METADATA", "UPDATE-METADATA",
        }),
    ),
    "scp11_relay": _ShellSpec(
        module="SCP11.relay.main",
        summary="SGP.22 relay compatibility shell: ES2+/ES9+ and profile lifecycle (DRIVES A CARD)",
        # Same startup preflight as scp11_live: readers are enumerated before
        # the first verb runs, so HELP alone would touch hardware.
        card=True,
        read=frozenset({
            "?", "AIDS", "EIM-DISCOVER", "ES9-CERT-INFO", "GET-CERTS",
            "GET-EID", "GET-EIM-CONFIG", "GET-ES9", "GET-EUICC-INFO1",
            "GET-EUICC-INFO2", "GET-METADATA", "GET-NOTIFICATIONS",
            "GET-POL", "GET-RAT", "GET-SMDP", "H", "HELP", "INFO", "LIST",
            "Q", "QA", "READ-METADATA", "SCAN", "STATUS", "EXIT", "QUIT",
        }),
        write=frozenset({
            "DISABLE-PROFILE", "EIM-AUTHENTICATE", "ENABLE-PROFILE",
            "REMOVE-NOTIFICATION", "SET-ES9", "SET-ES9-CA", "SET-ES9-TLS",
            "SET-POL", "SET-SMDP", "STORE-METADATA", "VERIFY-SCP11",
        }),
        destructive=frozenset({
            # Each installs a profile or runs a flow the remote side steers.
            "DELETE-PROFILE", "DOWNLOAD-AC", "EIM-DOWNLOAD", "FLOW",
        }),
    ),
    "suci_tool": _ShellSpec(
        module="Tools.SuciTool.main",
        summary="SUCI key generation and public-key export for USIM / 5GS provisioning",
        # Key material on disk, never a card.
        card=False,
        read=frozenset({
            "DUMP", "HELP", "PWD", "Q", "QA", "QUIT", "STATUS", "USE", "EXIT",
        }),
        write=frozenset({
            # GENERATE writes a key pair. TOOL redirects which binary the
            # other verbs invoke, so it decides what actually runs.
            "GENERATE", "TOOL",
        }),
        destructive=frozenset(),
    ),
}

_SHELL_TIMEOUT_SECONDS = 120
_SHELL_OUTPUT_LIMIT = 60_000


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
        verb = verdict["verb"]
        if risk == "command_file" and not script_files_allowed():
            return json.dumps({
                "error": (
                    f"Refused: {verb} runs commands this gate cannot inspect, "
                    "so nothing it carries is classified. Set "
                    f"{SCRIPT_FILES_ENV}=1 to run them anyway."
                ),
                "verb": verb,
                "risk": "command_file",
            })
        if risk == "interactive":
            return json.dumps({
                "error": (
                    f"Refused: {verb} opens an interactive view and would hang "
                    "a non-interactive batch. This is not an access-level "
                    "question; a batch has no terminal."
                ),
                "verb": verb,
            })
        if risk == "unknown":
            return json.dumps({
                "error": (
                    f"Refused: {verb} is not a recognised verb for the {shell} "
                    "shell. Unknown verbs are refused rather than assumed "
                    "safe; run HELP to see what is available."
                ),
                "verb": verb,
            })
        # A verb that reaches a card from a shell that opens no reader at
        # startup, so the shell-level card check above did not cover it.
        reaches_card = verb in _CARD_REACHING_VERBS or verb in spec.card_verbs
        if reaches_card and not card_access_allowed():
            return json.dumps({
                "error": (
                    f"Refused: {verb} puts commands on a card, so it needs "
                    f"{CARD_ACCESS_ENV}=1."
                ),
                "verb": verb,
                "reaches_a_card": True,
            })
        if risk in ("write", "destructive", "secret_argument") and not write_allowed():
            detail = {
                "destructive": "cannot be undone",
                "secret_argument": "takes key material as an argument, which "
                                   "reaches the model provider",
            }.get(risk, "changes state")
            return json.dumps({
                "error": (
                    f"Refused: {verb} {detail}, and this server is read-only. "
                    f"Set {ACCESS_ENV}={ACCESS_WRITE} to permit it."
                ),
                "verb": verb,
                "risk": risk,
                "access_mode": access_mode(),
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

    WARNING: some of these shells drive a real card. With the opt-ins set,
    verbs reachable here can install applets, write keys, disable or delete
    a profile, send an OTA envelope, and export a key bag. None of that can
    be undone. Use a throwaway test card, never one carrying live
    credentials.

    shell: one of profile_package (SAIP authoring, files only), scp80
        (builds OTA offline; SEND/SENDRAW/OTA reach a card), scp11_eim
        (authors and lints SGP.32 eIM packages offline; the issue and
        ISDR verbs reach a card), suci_tool (SUCI key generation, files
        only), scp03 (DRIVES A CARD), scp11_live (DRIVES A CARD),
        scp11_relay (DRIVES A CARD), scp11_local_access (DRIVES A CARD).
        Run "HELP; EXIT" against a shell to see its verbs.
    commands: semicolon-separated batch, executed left to right in one
        non-interactive process. State does not survive between calls, so
        put a whole flow in one batch and pass absolute paths, for example
        "USE /abs/profile.der; INFO; TREE; LINT; EXIT".
    timeout_seconds: how long to allow the batch (default 120).

    Gating, in order. Reading is always allowed. A shell that opens a reader
    at startup, or any verb that puts commands on a card, needs
    YGGDRASIM_MCP_ALLOW_CARD. Any verb that changes state -- on disk or on a
    card -- needs YGGDRASIM_MCP_ACCESS=write, as does a verb that takes key
    material as an argument, because that argument reaches the model
    provider. RUN, SCRIPT, and RAW need YGGDRASIM_MCP_ALLOW_SCRIPT_FILES,
    separately, because what they carry is never classified. Unknown verbs
    and interactive verbs are refused at every access level.
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

    import importlib.util
    import subprocess

    # The standalone distribution ships no operator shells. Say so, rather
    # than spawning a subprocess that exits 1 with an ImportError traceback.
    # find_spec raises rather than returning None when the parent package is
    # itself missing, which is exactly the standalone case.
    try:
        shell_present = importlib.util.find_spec(spec.module) is not None
    except (ImportError, ValueError):
        shell_present = False
    if not shell_present:
        return json.dumps({
            "error": f"The {shell} shell is unavailable in this install: "
                     f"no module {spec.module}. It needs the full YggdraSIM install.",
        })

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
        "access_mode": access_mode(),
        "card_access": card_access_allowed(),
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
# Card transport control
# ---------------------------------------------------------------------------

#: An open session pins a reader handle and keeps the card powered, so the
#: registry stays small and self-expiring rather than growing per call.
_MAX_CARD_SESSIONS = 4
_CARD_SESSION_IDLE_SECONDS = 600
_CARD_SESSIONS: dict[str, dict[str, Any]] = {}


def _card_backend_module() -> Any:
    from yggdrasim_common import card_backend

    return card_backend


def _expire_idle_sessions() -> list[str]:
    """Close sessions nobody has touched, and report which ones went."""

    import time

    cutoff = time.monotonic() - _CARD_SESSION_IDLE_SECONDS
    expired = [sid for sid, entry in _CARD_SESSIONS.items() if entry["touched"] < cutoff]
    for sid in expired:
        entry = _CARD_SESSIONS.pop(sid, None)
        if entry is None:
            continue
        try:
            entry["connection"].disconnect()
        except Exception:  # noqa: BLE001 -- a dead handle is already closed
            pass
    return expired


def _atr_hex(connection: Any) -> str:
    try:
        return bytes(connection.getATR()).hex().upper()
    except Exception:  # noqa: BLE001 -- relay and sim backends may omit it
        return ""


@mcp.tool(annotations=PROBES_WORLD)
def card_backend_status() -> str:
    """Report which transport the card stack talks through, and what is open.

    Covers the three paths a command can take to a card: a local PC/SC
    reader, the simulator, or a relay. Reports the configured backend, where
    that setting came from, whether a relay marker is present, and every
    open session this server holds.

    Read-only, and works with every gate shut. Relay details come back
    redacted: whether a token is configured, never its value.
    """
    payload: dict[str, Any] = {
        "access_mode": access_mode(),
        "card_access_enabled": card_access_allowed(),
    }
    try:
        backend = _card_backend_module()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Card backend unavailable: {exc}"})

    try:
        payload["backend"] = backend.get_card_backend()
        payload["backend_source"] = backend.get_card_backend_source()
        payload["description"] = backend.describe_card_backend()
        payload["simulated"] = backend.is_simulated_card_backend()
    except Exception as exc:  # noqa: BLE001
        payload["backend_error"] = str(exc)

    try:
        marker = backend.read_card_relay_marker() or {}
        payload["relay"] = {
            "configured": bool(marker.get("apdu_url")),
            "apdu_url": str(marker.get("apdu_url", "")),
            "token_configured": bool(marker.get("token") or marker.get("token_file")),
        }
    except Exception:  # noqa: BLE001 -- no marker is the normal case
        payload["relay"] = {"configured": False}

    _expire_idle_sessions()
    payload["sessions"] = [
        {
            "session_id": sid,
            "reader": entry["reader"],
            "simulated": entry.get("simulated", False),
            "protocol": entry["protocol"],
            "atr": entry["atr"],
            "transmits": entry["transmits"],
        }
        for sid, entry in _CARD_SESSIONS.items()
    ]
    payload["session_limit"] = _MAX_CARD_SESSIONS
    return json.dumps(payload, indent=2)


@mcp.tool(annotations=TOUCHES_CARD)
def card_backend_select(backend: str, persist: bool = False) -> str:
    """Point the card stack at a reader, the simulator, or a relay.

    backend: "reader" for local PC/SC, "sim" for the built-in simulator.
    persist: also write the choice to the runtime settings file, so every
        other YggdraSIM process picks it up. Off by default, because that
        reaches beyond this server's own session.

    Selecting a backend needs YGGDRASIM_MCP_ACCESS=write. Selecting
    "reader" additionally needs YGGDRASIM_MCP_ALLOW_CARD, since it points
    the whole stack at physical hardware. Switching to "sim" is the way to
    work through this without a card present.
    """
    if not write_allowed():
        return json.dumps({
            "error": (
                "Refused: choosing a card backend changes state, and this "
                f"server is read-only. Set {ACCESS_ENV}={ACCESS_WRITE}."
            ),
            "access_mode": access_mode(),
        })
    try:
        module = _card_backend_module()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Card backend unavailable: {exc}"})

    # normalize_card_backend folds anything unrecognised to its default, so
    # a typo would quietly select the reader. Check the raw value first.
    wanted = str(backend or "").strip().lower()
    if wanted not in (module.CARD_BACKEND_READER, module.CARD_BACKEND_SIM):
        return json.dumps({
            "error": f"Unknown backend {backend!r}.",
            "known": [module.CARD_BACKEND_READER, module.CARD_BACKEND_SIM],
        })
    if wanted == module.CARD_BACKEND_READER and not card_access_allowed():
        return json.dumps({
            "error": (
                "Refused: selecting the reader backend points the card stack "
                f"at real hardware, so it needs {CARD_ACCESS_ENV}=1. The sim "
                "backend needs no card."
            ),
            "requested": wanted,
        })

    previous = module.get_card_backend()
    try:
        selected = module.set_card_backend(wanted, persist=bool(persist))
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Could not select {wanted!r}: {exc}"})
    return json.dumps({
        "previous": previous,
        "backend": selected,
        "persisted": bool(persist),
        "description": module.describe_card_backend(),
        "access_mode": access_mode(),
    }, indent=2)


@mcp.tool(annotations=TOUCHES_CARD)
def card_session_open(
    reader_index: int = 0,
    reader_name: str = "",
    protocol: str = "",
) -> str:
    """Open a card session that survives across calls, and return its id.

    pcsc_transmit connects and disconnects around a single APDU, so a
    secure-channel flow cannot work through it: the second APDU arrives on a
    card that has forgotten the first. This holds one connection open so
    SCP03, SCP11, and any select-then-read sequence run as one session.

    reader_index: which reader to use (default 0). Ignored if reader_name is set.
    reader_name: case-insensitive substring match against reader names.
    protocol: "T=0", "T=1", or "" to let the reader negotiate.

    Needs YGGDRASIM_MCP_ALLOW_CARD, because opening a session powers the
    card, unless the configured backend is the simulator. Opening is not
    itself a write: what you then send through it is classified per APDU by
    card_session_transmit.

    Close it with card_session_close. Sessions expire after 10 minutes idle,
    and at most 4 are held at once.
    """
    try:
        module = _card_backend_module()
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Card backend unavailable: {exc}"})

    simulated = False
    try:
        simulated = bool(module.is_simulated_card_backend())
    except Exception:  # noqa: BLE001
        pass
    if not simulated and not card_access_allowed():
        return _card_access_denied()

    _expire_idle_sessions()
    if len(_CARD_SESSIONS) >= _MAX_CARD_SESSIONS:
        return json.dumps({
            "error": (
                f"Refused: {_MAX_CARD_SESSIONS} sessions are already open. "
                "Close one with card_session_close first."
            ),
            "open": sorted(_CARD_SESSIONS),
        })

    index = int(reader_index)
    resolved_name = ""
    if not simulated:
        try:
            readers_fn, _share, _wrapper = _load_pcsc()
        except RuntimeError as exc:
            return json.dumps({"error": str(exc)})
        try:
            reader_list = list(readers_fn())
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"Could not enumerate readers: {exc}"})
        if not reader_list:
            return json.dumps({"error": "No smart card readers found."})
        if reader_name.strip():
            wanted = reader_name.strip().lower()
            matches = [i for i, r in enumerate(reader_list) if wanted in str(r).lower()]
            if not matches:
                return json.dumps({
                    "error": f"No reader matches {reader_name!r}.",
                    "readers": [str(r) for r in reader_list],
                })
            index = matches[0]
        if index < 0 or index >= len(reader_list):
            return json.dumps({
                "error": f"Reader index {index} is out of range.",
                "readers": [str(r) for r in reader_list],
            })
        resolved_name = str(reader_list[index])

    wanted_protocol = None
    protocol_text = str(protocol or "").strip().upper().replace(" ", "")
    if protocol_text in ("T=0", "T0"):
        wanted_protocol = 1
    elif protocol_text in ("T=1", "T1"):
        wanted_protocol = 2
    elif protocol_text:
        return json.dumps({"error": f"Unknown protocol {protocol!r}. Use T=0, T=1, or ''."})

    try:
        connection = module.create_card_connection(
            reader_index=index, protocol=wanted_protocol
        )
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Could not open a card session: {exc}"})

    import time
    import uuid

    session_id = f"card-{uuid.uuid4().hex[:12]}"
    atr = _atr_hex(connection)
    _CARD_SESSIONS[session_id] = {
        "connection": connection,
        "reader": resolved_name or ("simulator" if simulated else f"index {index}"),
        "protocol": protocol_text or "negotiated",
        "atr": atr,
        "transmits": 0,
        "simulated": simulated,
        "touched": time.monotonic(),
    }
    return json.dumps({
        "session_id": session_id,
        "reader": _CARD_SESSIONS[session_id]["reader"],
        "atr": atr,
        "protocol": _CARD_SESSIONS[session_id]["protocol"],
        "simulated": simulated,
        "description": module.describe_card_backend(),
        "note": "State survives across calls until card_session_close.",
    }, indent=2)


@mcp.tool(annotations=TOUCHES_CARD)
async def card_session_transmit(
    session_id: str,
    hex_apdu: str,
    ctx: Context | None = None,
) -> str:
    """Send one APDU through an open session, keeping the channel alive.

    session_id: from card_session_open.
    hex_apdu: hex-encoded APDU bytes (e.g. '00A4040000').

    Each APDU is classified exactly as pcsc_transmit classifies it: reads
    need YGGDRASIM_MCP_ALLOW_CARD, and anything that changes the card also
    needs YGGDRASIM_MCP_ACCESS=write. Unlike pcsc_transmit, the secure
    channel and selected file survive to the next call.
    """
    import time

    _expire_idle_sessions()
    entry = _CARD_SESSIONS.get(str(session_id or "").strip())
    if entry is None:
        return json.dumps({
            "error": f"No open session {session_id!r}. Open one with card_session_open.",
            "open": sorted(_CARD_SESSIONS),
        })

    clean = hex_apdu.strip().replace(" ", "").replace(":", "").replace("0x", "")
    try:
        apdu = bytes.fromhex(clean)
    except ValueError:
        return json.dumps({"error": "Invalid hex APDU."})
    verdict = classify_apdu(apdu)
    refusal = _apdu_refusal(verdict, simulated=bool(entry.get("simulated")))
    if refusal is not None:
        return refusal
    declined = await _confirm_destructive(ctx, verdict, f"session {session_id}")
    if declined is not None:
        return declined

    try:
        data, sw1, sw2 = entry["connection"].transmit(list(apdu))
    except Exception as exc:  # noqa: BLE001
        return json.dumps({"error": f"Transmit failed: {exc}", "session_id": session_id})

    entry["transmits"] += 1
    entry["touched"] = time.monotonic()
    status = f"{sw1:02X}{sw2:02X}"
    return json.dumps({
        "session_id": session_id,
        "status_word": status,
        "meaning": _status_word_meaning(sw1, sw2),
        "data": bytes(data).hex().upper(),
        "risk": verdict["risk"],
        "transmits": entry["transmits"],
    }, indent=2)


@mcp.tool(annotations=TOUCHES_CARD)
def card_session_close(session_id: str = "") -> str:
    """Close one open card session, or every one when session_id is empty."""

    wanted = str(session_id or "").strip()
    targets = [wanted] if wanted else sorted(_CARD_SESSIONS)
    if wanted and wanted not in _CARD_SESSIONS:
        return json.dumps({
            "error": f"No open session {wanted!r}.",
            "open": sorted(_CARD_SESSIONS),
        })
    closed, failed = [], {}
    for sid in targets:
        entry = _CARD_SESSIONS.pop(sid, None)
        if entry is None:
            continue
        try:
            entry["connection"].disconnect()
            closed.append(sid)
        except Exception as exc:  # noqa: BLE001
            failed[sid] = str(exc)
    payload: dict[str, Any] = {"closed": closed, "still_open": sorted(_CARD_SESSIONS)}
    if failed:
        # The handle is gone from the registry either way; say so plainly.
        payload["disconnect_errors"] = failed
    return json.dumps(payload, indent=2)


# ---------------------------------------------------------------------------
# Simulated card, AKMA, and YggdraCore
#
# These mirror GUI action modules that had no MCP path. The simulator is
# in-process with no hardware behind it, so reading its state is not
# gated by CARD_ACCESS_ENV; changing it still needs write access.
# ---------------------------------------------------------------------------


@mcp.tool(annotations=READ_ONLY)
def sim_card_status() -> str:
    """Report the simulated eUICC identity and profile inventory.

    Covers EID, ICCID, IMSI, the active ISD-P AID, and every profile with
    its lifecycle state. Reads the in-process simulator, so no reader and
    no YGGDRASIM_MCP_ALLOW_CARD is required.
    """
    try:
        from SIMCARD.connection import get_shared_engine
    except ImportError as error:
        return json.dumps({"error": f"simulator unavailable: {error}"})
    try:
        state = get_shared_engine().state
    except Exception as error:  # noqa: BLE001 - surface engine faults as data
        return json.dumps({"error": f"simulator failed to start: {error}"})

    profiles = [
        {
            "iccid": str(getattr(profile, "iccid", "") or ""),
            "aid": str(getattr(profile, "aid", "") or ""),
            "state": str(getattr(profile, "state", "") or ""),
            "fallback_attribute": bool(getattr(profile, "fallback_attribute", False)),
        }
        for profile in getattr(state, "profiles", [])
    ]
    return json.dumps(
        {
            "eid": str(getattr(state, "eid", "") or ""),
            "iccid": str(getattr(state, "iccid", "") or ""),
            "imsi": str(getattr(state, "imsi", "") or ""),
            "active_profile_aid": str(getattr(state, "active_profile_aid", "") or ""),
            "apdu_count": int(getattr(state, "apdu_count", 0)),
            "profile_count": len(profiles),
            "profiles": profiles,
            "eim_entries": [
                str(getattr(entry, "eim_id", "") or "")
                for entry in getattr(state, "eim_entries", [])
            ],
        },
        indent=2,
    )


@mcp.tool(annotations=READ_ONLY)
def sim_filesystem_select(path: str) -> str:
    """SELECT a file on the simulated card and return the FCP response.

    path: a hex file id or path, e.g. '3F00', '2FE2', or '3F007FFF6F07'.
    Read-only: SELECT does not change stored data.
    """
    cleaned = str(path or "").strip().replace(" ", "").upper()
    if len(cleaned) == 0 or len(cleaned) % 2 != 0:
        return json.dumps({"error": "path must be non-empty even-length hex."})
    try:
        body = bytes.fromhex(cleaned)
    except ValueError:
        return json.dumps({"error": f"path {path!r} is not valid hex."})
    try:
        from SIMCARD.connection import get_shared_engine

        engine = get_shared_engine()
    except Exception as error:  # noqa: BLE001
        return json.dumps({"error": f"simulator unavailable: {error}"})

    apdu = bytes([0x00, 0xA4, 0x00, 0x04, len(body)]) + body
    try:
        data, sw1, sw2 = engine.transmit(apdu)
    except Exception as error:  # noqa: BLE001
        return json.dumps({"error": f"transmit failed: {error}"})
    return json.dumps(
        {
            "apdu": apdu.hex().upper(),
            "status_word": f"{sw1:02X}{sw2:02X}",
            "ok": (sw1, sw2) in ((0x90, 0x00), (0x91, 0x00)),
            "fcp_hex": bytes(data).hex().upper(),
        },
        indent=2,
    )


@mcp.tool(annotations=READ_ONLY)
def akma_derive_keys(
    k_ausf_hex: str,
    supi: str,
    af_id: str = "",
    routing_indicator: str = "",
    mcc: str = "",
    mnc: str = "",
) -> str:
    """Derive AKMA keys from KAUSF and SUPI per 3GPP TS 33.535.

    Returns KAKMA and A-TID. Supplying af_id also derives the
    application-function key KAF. Supplying routing_indicator, mcc, and
    mnc together additionally formats the A-KID NAI, which needs the home
    network identifier those three carry. Pure key derivation: nothing is
    sent to a card or a network.
    """
    cleaned = str(k_ausf_hex or "").strip().replace(" ", "")
    try:
        k_ausf = bytes.fromhex(cleaned)
    except ValueError:
        return json.dumps({"error": "k_ausf_hex is not valid hex."})
    if len(k_ausf) == 0:
        return json.dumps({"error": "k_ausf_hex must be non-empty."})
    supi_value = str(supi or "").strip()
    if len(supi_value) == 0:
        return json.dumps({"error": "supi must be non-empty."})

    try:
        from SIMCARD.akma import (
            derive_a_tid,
            derive_k_af,
            derive_k_akma,
            format_a_kid,
        )
    except ImportError as error:
        return json.dumps({"error": f"AKMA helpers unavailable: {error}"})

    try:
        k_akma = derive_k_akma(k_ausf, supi_value)
        a_tid = derive_a_tid(k_ausf, supi_value)
        payload: dict[str, Any] = {
            "supi": supi_value,
            "kakma_hex": k_akma.hex().upper(),
            "a_tid_hex": a_tid.hex().upper(),
        }
        # The A-KID NAI embeds the home network identifier, so it can only
        # be formed when the caller supplies all three parts.
        routing = str(routing_indicator or "").strip()
        mcc_value = str(mcc or "").strip()
        mnc_value = str(mnc or "").strip()
        if len(routing) > 0 and len(mcc_value) > 0 and len(mnc_value) > 0:
            payload["a_kid"] = format_a_kid(
                a_tid,
                routing_indicator=routing,
                mcc=mcc_value,
                mnc=mnc_value,
            )
        if len(str(af_id or "").strip()) > 0:
            payload["af_id"] = str(af_id).strip()
            payload["kaf_hex"] = derive_k_af(k_akma, str(af_id).strip()).hex().upper()
    except (ValueError, TypeError) as error:
        return json.dumps({"error": f"AKMA derivation rejected the input: {error}"})
    return json.dumps(payload, indent=2)


@mcp.tool(annotations=READ_ONLY)
def yggdracore_status() -> str:
    """Report YggdraCore stub state: mode, subscriptions, AAnF registrations.

    Reads the in-process stubs. Returns mode 'off' when
    YGGDRASIM_5GCORE_MODE is unset, which is the default.
    """
    try:
        from Tools.YggdraCore.aanf_stub import get_default_aanf_stub
        from Tools.YggdraCore.ausf_stub import get_default_ausf_stub, yggdra_core_mode
        from Tools.YggdraCore.subscription_store import get_default_subscription_store
    except ImportError as error:
        return json.dumps({"error": f"YggdraCore unavailable: {error}"})

    try:
        payload = {
            "mode": yggdra_core_mode(),
            "subscriptions": len(get_default_subscription_store().list()),
            "aanf_entries": len(get_default_aanf_stub().snapshot()),
            "in_flight_auth_contexts": get_default_ausf_stub().in_flight_context_count(),
        }
    except Exception as error:  # noqa: BLE001
        return json.dumps({"error": f"YggdraCore stub failed: {error}"})
    return json.dumps(payload, indent=2)


@mcp.tool(annotations=TOUCHES_CARD)
def sim_execute_psmo(operation: str, iccid: str = "", aid: str = "", rollback: bool = False) -> str:
    """Build a typed SGP.32 PSMO and execute it against the simulated card.

    operation: enable, disable, delete, list_profile_info, get_rat,
    configure_immediate_enable, set_fallback_attribute,
    unset_fallback_attribute, set_default_dp_address.

    Changes simulator state, so it requires YGGDRASIM_MCP_ACCESS=write.
    Targets the in-process simulator only; no physical card is reachable
    through this tool.
    """
    if not write_allowed():
        return json.dumps({
            "error": (
                "Refused: a PSMO changes profile state, and this server is "
                f"read-only. Set {ACCESS_ENV}={ACCESS_WRITE}."
            ),
            "access_mode": access_mode(),
        })

    try:
        from SCP11.eim_local.psmo_builders import PsmoBuildError, build_psmo
    except ImportError as error:
        return json.dumps({"error": f"PSMO builders unavailable: {error}"})

    spec: dict[str, Any] = {"operation": str(operation or "").strip().lower()}
    if len(str(iccid or "").strip()) > 0:
        spec["iccid"] = str(iccid).strip()
    if len(str(aid or "").strip()) > 0:
        spec["aid"] = str(aid).strip()
    if bool(rollback) is True:
        spec["rollback"] = True

    try:
        command = build_psmo(spec)
    except PsmoBuildError as error:
        return json.dumps({"error": str(error)})

    try:
        from SIMCARD.connection import get_shared_engine

        handler = get_shared_engine().sgp
        result = handler._execute_psmo(command)
    except Exception as error:  # noqa: BLE001
        return json.dumps({"error": f"simulator execution failed: {error}"})

    return json.dumps(
        {
            "operation": spec["operation"],
            "command_hex": command.hex().upper(),
            "result_hex": bytes(result).hex().upper(),
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def run_cli() -> int:
    """Console-script entry point: serve MCP over stdio.

    The simulator, AKMA, and YggdraCore tools above close the gap with the
    GUI action modules, which could reach those surfaces when MCP could
    not.
    """

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
