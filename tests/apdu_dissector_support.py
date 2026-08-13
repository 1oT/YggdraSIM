# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.

"""Shared helpers for the APDU dissector's tshark-backed tests.

Not a test module. It builds synthetic captures and runs tshark against
the bundled Lua so the dissector suite has something real to assert on.

Two hazards this module exists to contain:

**Captures are generated, never committed.** ``CONTRIBUTING.md`` forbids
real IMSI/ICCID/EID values and vendor traces in the tree, and
``scripts/check_repo_hygiene.py`` enforces it. Every fixture here is
built at test time from ``Tools/HilBridge/protocol.py`` helpers using
identifiers from the documented test ranges, so there is nothing to leak
and nothing to keep in sync with a binary blob.

**Wireshark silently refuses ``-X lua_script:`` when running as root.**
There is no error and no warning: the script simply never loads and
every assertion about decoded fields quietly passes against stock
output. A suite that skips in that situation is worse than useless, so
:func:`lua_is_loadable` probes for it and
:func:`require_working_tshark` turns it into a hard failure when
``YGGDRASIM_REQUIRE_TSHARK=1`` is set.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
import unittest
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DISSECTOR_PATH = REPO_ROOT / "Tools" / "ApduDissector" / "lua" / "yggdrasim_apdu.lua"

REQUIRE_ENV = "YGGDRASIM_REQUIRE_TSHARK"
UNPRIVILEGED_USER_ENV = "YGGDRASIM_TSHARK_USER"

#: Identifiers from Tools/YggdraMCP/server.py TEST_IDENTIFIER_RANGES.
TEST_ICCID = "8988201234567890123"
TEST_IMSI = "001010000000001"

_TSHARK = shutil.which("tshark")


@dataclass(frozen=True)
class Exchange:
    """One command/response pair to place in a synthetic capture."""

    command: bytes
    response: bytes
    label: str = ""
    #: True when the bytes admit more than one valid ISO 7816-4 split.
    #: Length assertions skip these; the ambiguity itself is asserted
    #: separately. An instruction with no case hint is the usual cause.
    ambiguous: bool = False


def tshark_binary() -> str:
    return _TSHARK or ""


def _unprivileged_user() -> str:
    """Return a non-root account able to run tshark, or ``""``.

    Only relevant when the suite itself runs as root, which is normal in
    containers. The account is looked up rather than created; creating
    users from a test would be a surprising side effect.
    """
    override = str(os.environ.get(UNPRIVILEGED_USER_ENV, "") or "").strip()
    if override:
        return override
    for candidate in ("wsrunner", "nobody"):
        try:
            pwd.getpwnam(candidate)
        except KeyError:
            continue
        return candidate
    return ""


def _shared_config_home() -> str:
    """A world-readable Wireshark profile directory.

    ``tests/conftest.py`` points ``XDG_CONFIG_HOME`` at a root-owned
    temporary directory. An unprivileged ``su`` cannot traverse it, and
    tshark turns that into a wall of "You don't have permission to read"
    errors that look exactly like a broken dissector. Handing the
    dropped-privilege run its own readable profile keeps the failure
    modes distinguishable.
    """
    root = Path("/tmp/yggdrasim-apdu-dissector-tshark-home")
    profile = root / "wireshark"
    profile.mkdir(parents=True, exist_ok=True)
    for directory in (root, profile):
        try:
            directory.chmod(0o777)
        except OSError:
            pass
    return str(root)


def run_tshark(arguments: list[str], *, timeout: float = 60.0) -> subprocess.CompletedProcess:
    """Run tshark, dropping privileges when the caller is root.

    Wireshark refuses to load Lua scripts as root, so a root caller is
    re-dispatched through ``su`` to an unprivileged account. When no such
    account exists the command still runs and the caller sees the empty
    decode, which :func:`lua_is_loadable` reports honestly.
    """
    if not _TSHARK:
        raise RuntimeError("tshark is not installed")
    command = [_TSHARK, *arguments]
    if os.geteuid() == 0:
        user = _unprivileged_user()
        if user:
            config_home = _shared_config_home()
            quoted = " ".join(
                _shell_quote(part)
                for part in [
                    "env",
                    f"HOME={config_home}",
                    f"XDG_CONFIG_HOME={config_home}",
                    *command,
                ]
            )
            command = ["su", "-s", "/bin/sh", user, "-c", quoted]
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def _shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\\''") + "'"


def make_readable(path: Path) -> Path:
    """Let the dropped-privilege tshark reach *path*.

    ``tempfile`` creates directories mode 0700, so a capture written into
    one is unreadable by the unprivileged account even after the file
    itself is chmodded. Parent directories are opened up to the
    filesystem root, stopping at the first one that cannot be changed.
    """
    try:
        path.chmod(0o644)
    except OSError:
        return path
    for parent in path.parents:
        if str(parent) in ("/", ""):
            break
        try:
            mode = parent.stat().st_mode & 0o7777
            parent.chmod(mode | 0o755)
        except OSError:
            break
    return path


def lua_is_loadable(capture_path: Path) -> tuple[bool, str]:
    """Report whether the bundled Lua actually loads under this tshark.

    Returns ``(loadable, reason)``. The probe asserts on a field only
    this dissector defines, so a stock decode cannot make it pass.
    """
    if not _TSHARK:
        return False, "tshark is not installed"
    result = run_tshark(
        [
            "-X",
            f"lua_script:{DISSECTOR_PATH}",
            "-r",
            str(capture_path),
            "-T",
            "fields",
            "-e",
            "yapdu.frame_kind",
        ]
    )
    if "Lua Error" in result.stderr or "error loading" in result.stderr.lower():
        return False, f"the Lua failed to load: {result.stderr.strip()[:400]}"
    if result.returncode != 0:
        return False, f"tshark exited {result.returncode}: {result.stderr.strip()[:400]}"
    if not any(line.strip() for line in result.stdout.splitlines()):
        if os.geteuid() == 0 and not _unprivileged_user():
            return False, (
                "running as root and no unprivileged account is available. "
                "Wireshark refuses -X lua_script: as root without any error, "
                f"so nothing was decoded. Create an account and set "
                f"{UNPRIVILEGED_USER_ENV}, or run the suite as a normal user."
            )
        return False, "the dissector loaded but produced no yapdu fields"
    return True, ""


def require_working_tshark(capture_path: Path) -> None:
    """Skip, or fail when the caller demanded that Lua really run.

    ``YGGDRASIM_REQUIRE_TSHARK=1`` converts every skip in this suite into
    a failure. Without a CI job that sets it, the Lua tests skip on any
    machine without tshark and the dissector rots unnoticed -- the exact
    state ``tests/test_eum_diag.py`` was in, asserting against a stub.
    """
    required = str(os.environ.get(REQUIRE_ENV, "") or "").strip() == "1"
    loadable, reason = lua_is_loadable(capture_path)
    if loadable:
        return
    if required:
        raise AssertionError(
            f"{REQUIRE_ENV}=1 but the APDU dissector could not run: {reason}"
        )
    raise unittest.SkipTest(reason)


# ------------------------------------------------------------------ capture
def write_capture(path: Path, exchanges: list[Exchange], *, atr: bytes = b"") -> Path:
    """Build a GSMTAP capture from *exchanges*.

    Uses the same helpers the HIL bridge writes real captures with, so a
    fixture cannot drift away from the on-wire format it is meant to
    represent.
    """
    from Tools.HilBridge.protocol import (  # imported lazily; heavy deps
        GsmtapPcapWriter,
        build_gsmtap_packet,
        build_simtrace_apdu_payload,
    )

    writer = GsmtapPcapWriter(path=str(path))
    try:
        if atr:
            writer.write_gsmtap_packet(build_gsmtap_packet(atr, subtype=0x01))
        for exchange in exchanges:
            writer.write_gsmtap_packet(
                build_gsmtap_packet(
                    build_simtrace_apdu_payload(exchange.command, exchange.response),
                    subtype=0x00,
                )
            )
    finally:
        writer.close()
    return make_readable(path)


def write_raw_capture(path: Path, payloads: list[bytes]) -> Path:
    """Build a capture from raw GSMTAP SIM payloads.

    ``write_capture`` refuses an empty command or response, which is
    precisely what the robustness suite needs to feed the dissector, so
    malformed cases bypass ``build_simtrace_apdu_payload``.
    """
    from Tools.HilBridge.protocol import GsmtapPcapWriter, build_gsmtap_packet

    writer = GsmtapPcapWriter(path=str(path))
    try:
        for payload in payloads:
            writer.write_gsmtap_packet(build_gsmtap_packet(payload, subtype=0x00))
    finally:
        writer.close()
    return make_readable(path)


def decode_fields(capture_path: Path, field_names: list[str]) -> list[list[str]]:
    """Return one row of tab-separated field values per frame."""
    arguments = [
        "-X",
        f"lua_script:{DISSECTOR_PATH}",
        "-r",
        str(capture_path),
        "-T",
        "fields",
        "-E",
        "separator=/t",
        "-E",
        "occurrence=f",
    ]
    for name in field_names:
        arguments.extend(["-e", name])
    result = run_tshark(arguments)
    if result.returncode != 0:
        raise RuntimeError(
            f"tshark exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    rows: list[list[str]] = []
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        rows.append(line.split("\t"))
    return rows


def decode_json(capture_path: Path, *, display_filter: str = "") -> list[dict]:
    """Return the tshark ``-T json`` decode as parsed objects."""
    arguments = [
        "-X",
        f"lua_script:{DISSECTOR_PATH}",
        "-r",
        str(capture_path),
        "-T",
        "json",
    ]
    if display_filter:
        arguments.extend(["-Y", display_filter])
    result = run_tshark(arguments)
    if result.returncode != 0:
        raise RuntimeError(
            f"tshark exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    if not result.stdout.strip():
        return []
    return json.loads(result.stdout)


def decode_text(capture_path: Path, *, display_filter: str = "") -> str:
    """Return the tshark ``-V`` decode as text."""
    arguments = [
        "-X",
        f"lua_script:{DISSECTOR_PATH}",
        "-r",
        str(capture_path),
        "-V",
    ]
    if display_filter:
        arguments.extend(["-Y", display_filter])
    result = run_tshark(arguments)
    if result.returncode != 0:
        raise RuntimeError(
            f"tshark exited {result.returncode}: {result.stderr.strip()[:400]}"
        )
    return result.stdout


def swapped_bcd(digits: str) -> bytes:
    """Encode *digits* in the swapped-nibble BCD SIM files use."""
    padded = digits if len(digits) % 2 == 0 else digits + "F"
    out = bytearray()
    for index in range(0, len(padded), 2):
        low = int(padded[index], 16)
        high = int(padded[index + 1], 16)
        out.append((high << 4) | low)
    return bytes(out)


# ----------------------------------------------------------------- corpus
def standard_corpus() -> list[Exchange]:
    """A spread of exchanges covering every ISO 7816-4 case.

    Deliberately includes instructions absent from the command table so
    the splitter is exercised on the frames the Python decode view's
    instruction allowlist drops.
    """
    usim_aid = bytes.fromhex("A0000000871002FF86FF112233445566")
    return [
        # Case 4S: SELECT by AID, card answers "response ready".
        Exchange(
            bytes.fromhex("00A40404") + bytes([len(usim_aid)]) + usim_aid + b"\x00",
            bytes.fromhex("612B"),
            "select-adf-usim",
        ),
        # Case 2S: GET RESPONSE returning an FCP template. Le must equal
        # the body the card returns, or the split legitimately prefers a
        # different reading.
        Exchange(bytes.fromhex("00C0000012"), FCP_ADF_USIM + b"\x90\x00",
                 "get-response-fcp"),
        # Selecting EF.ICCID before reading it is what gives the read
        # below a file to be attributed to. Without the SELECT the
        # response body is just ten bytes.
        Exchange(
            bytes.fromhex("00A4000402") + bytes.fromhex("2FE2"),
            bytes.fromhex("6113"),
            "select-ef-iccid",
        ),
        # Case 2S: READ BINARY of EF.ICCID.
        Exchange(
            bytes.fromhex("00B000000A"),
            swapped_bcd(TEST_ICCID) + b"\x90\x00",
            "read-binary-iccid",
        ),
        # Case 3S: UPDATE BINARY, no response body.
        Exchange(
            bytes.fromhex("00D6000004") + bytes.fromhex("DEADBEEF"),
            bytes.fromhex("9000"),
            "update-binary",
        ),
        # Case 1: no body either way.
        Exchange(bytes.fromhex("00200001"), bytes.fromhex("63C2"), "verify-case-1"),
        # Case 3S: STORE DATA to the ISD-R carrying an ES10c request.
        Exchange(
            bytes.fromhex("80E291000A") + bytes.fromhex("BF2D07A0055A03010203"),
            bytes.fromhex("9000"),
            "store-data-es10c",
        ),
        # Error status with no body.
        Exchange(bytes.fromhex("00A4000402") + bytes.fromhex("6F07"),
                 bytes.fromhex("6A82"), "select-not-found"),
        # An instruction absent from the command table: the Python
        # decode view drops this frame entirely. The response carries a
        # body so the case 3 reading is the only one that fits; see
        # AMBIGUOUS_EXCHANGE for the case where it genuinely is not.
        Exchange(
            bytes.fromhex("80AB000103") + bytes.fromhex("010203"),
            bytes.fromhex("AABBCC") + b"\x90\x00",
            "unknown-instruction",
            ambiguous=True,
        ),
        # Secure-messaging class byte.
        Exchange(
            bytes.fromhex("84E2910018") + bytes(range(0x18)),
            bytes.fromhex("9000"),
            "store-data-wrapped",
        ),
        # Extended-length command (case 3E).
        Exchange(
            bytes.fromhex("00D6000000") + bytes([0x01, 0x00]) + bytes(256),
            bytes.fromhex("9000"),
            "update-binary-extended",
        ),
        # GlobalPlatform: opening a secure channel.
        Exchange(
            bytes.fromhex("8050000008") + bytes(range(8)) + b"\x00",
            INITIALIZE_UPDATE_RESPONSE + b"\x90\x00",
            "initialize-update",
        ),
        Exchange(
            bytes.fromhex("8482330010") + bytes(range(16)),
            bytes.fromhex("9000"),
            "external-authenticate",
        ),
        # GlobalPlatform: a positional INSTALL body, not TLV.
        Exchange(
            bytes.fromhex("80E60200") + bytes([len(INSTALL_FOR_LOAD)])
            + INSTALL_FOR_LOAD,
            bytes.fromhex("9000"),
            "install-for-load",
        ),
        # CAT: a FETCH answering with an OPEN CHANNEL proactive command.
        Exchange(
            bytes.fromhex("8012000000"),
            PROACTIVE_OPEN_CHANNEL + b"\x90\x00",
            "fetch-open-channel",
        ),
    ]


def _comprehension_tlv(tag: str, value: bytes) -> bytes:
    return bytes.fromhex(tag) + bytes([len(value)]) + value


#: An OPEN CHANNEL proactive command wrapped in its D0 envelope, per
#: ETSI TS 102 223 clause 6.6.27. The D0 wrapper is plain BER; only its
#: contents are COMPREHENSION-TLV.
_OPEN_CHANNEL_BODY = b"".join(
    [
        _comprehension_tlv("81", bytes.fromhex("014001")),   # OPEN CHANNEL
        _comprehension_tlv("82", bytes.fromhex("8121")),     # UICC -> channel 1
        _comprehension_tlv("35", bytes.fromhex("02030405060708")),
        _comprehension_tlv("39", bytes.fromhex("0578")),     # buffer size 1400
        _comprehension_tlv("47", b"\x03iot\x04test\x03com"),
        _comprehension_tlv("3C", bytes.fromhex("020050")),   # TCP client, port 80
        _comprehension_tlv("3E", bytes([0x21, 10, 0, 0, 1])),
    ]
)
PROACTIVE_OPEN_CHANNEL = (
    bytes.fromhex("D0") + bytes([len(_OPEN_CHANNEL_BODY)]) + _OPEN_CHANNEL_BODY
)

#: An INSTALL FOR LOAD data field: positional length-prefixed values, so
#: the TLV walker is deliberately not applied to it.
INSTALL_FOR_LOAD = (
    bytes([5]) + bytes.fromhex("0102030405")      # load file AID
    + bytes([5]) + bytes.fromhex("1112131415")    # Security Domain AID
    + bytes([0])                                  # load file data block hash
    + bytes([2]) + bytes.fromhex("C900")          # load parameters
    + bytes([0])                                  # load token
)

#: An SCP03 INITIALIZE UPDATE response: 10 bytes of key diversification
#: data, key version, SCP identifier 0x03, i-parameter, card challenge,
#: card cryptogram, sequence counter.
INITIALIZE_UPDATE_RESPONSE = (
    bytes.fromhex("00112233445566778899")   # key diversification data
    + bytes([0x30])                          # key version number
    + bytes([0x03])                          # SCP03
    + bytes([0x70])                          # i-parameter
    + bytes.fromhex("A1A2A3A4A5A6A7A8")     # card challenge
    + bytes.fromhex("B1B2B3B4B5B6B7B8")     # card cryptogram
    + bytes.fromhex("000001")                # sequence counter
)


#: A File Control Parameters template for ADF.USIM, per ETSI TS 102 221
#: clause 11.1.1.3. Declared lengths and actual content must agree: the
#: TLV walker refuses a template whose length over-claims its body, which
#: is the correct reading of malformed bytes rather than a limitation.
#:
#:   62 10                  FCP template, 16 bytes of value
#:      82 02 78 21         file descriptor: DF/ADF, shareable
#:      83 02 7F F0         file identifier 7FF0
#:      8A 01 05            life-cycle status: operational, deactivated
#:      A5 03 C0 01 00      proprietary information
FCP_ADF_USIM = bytes.fromhex("6210" "82027821" "83027FF0" "8A0105" "A503C00100")

#: A well-formed ATR: T=0 and T=15, direct convention, 15 historical
#: bytes, with a TCK that checks out. The check byte is the XOR of every
#: byte from T0 to the last historical byte inclusive.
STANDARD_ATR = bytes.fromhex("3B9F96801FC78031E073FE211B674A4C753034054BE9")

#: The same ATR with a corrupted check byte, for the expert-info path.
BAD_TCK_ATR = STANDARD_ATR[:-1] + bytes([STANDARD_ATR[-1] ^ 0x40])

#: An exchange no decoder can resolve from the bytes alone.
#:
#: "80 AB 00 01 03 01 02 03 90 00" reads equally well as case 3S -- Lc=3,
#: data 01 02 03, response 9000 -- or as case 2S with Le=3 and a
#: three-byte response body. The instruction is not in the case-hint
#: table, so there is no tie-breaker. The dissector is expected to pick
#: one, flag it, and say so rather than pretend.
AMBIGUOUS_EXCHANGE = Exchange(
    bytes.fromhex("80AB000103") + bytes.fromhex("010203"),
    bytes.fromhex("9000"),
    "ambiguous-split",
)
