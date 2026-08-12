---
title: APDU Dissector
tags:
  - subsystems
  - diagnostics
  - wireshark
  - hil
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# APDU Dissector

`Tools/ApduDissector/` is a Wireshark and tshark dissector that decodes the
GSMTAP SIM frames the HIL bridge mirrors on UDP `4729`, all the way down into
the APDU payload.

Wireshark ships a `gsm_sim` dissector, and it stops at the command header. What
it leaves behind, measured against a capture written by the HIL bridge's own
writer on TShark 4.2.2:

| Frame | Stock output | With this dissector |
|---|---|---|
| `GET RESPONSE` returning an FCP template | `[Malformed Packet]` | File type, EF structure, file identifier resolved to a path, life-cycle status |
| `STORE DATA` to the ISD-R carrying an ES10c request | `ETSI TS 102.221 e2` | `STORE DATA`, then the BER-TLV tree naming `ProfileInfoList` and its contents |
| `READ BINARY` of EF.ICCID | `Offset=0`, bytes undecoded | The ICCID |
| ATR frame | Mis-parsed as an APDU, `Unknown status word: 4ba9` | Convention, interface bytes, historical bytes, verified check byte |

## What it decodes

- **ISO/IEC 7816-4 header** -- the class byte split into logical channel,
  secure-messaging mode and chaining; the instruction resolved class-first, so
  `80 E2` is `STORE DATA` rather than the ETSI reading of `E2`; case
  classification across all seven forms including extended lengths.
- **Status words** -- from the same table the MCP server uses, plus the
  families whose SW2 is a count rather than a code. `61 2B` reads as "43 bytes
  available", `63 C2` as "2 retries left".
- **Risk class** -- from `yggdrasim_common/apdu_risk.py`, so
  `yapdu.risk == 3` is a display filter for every irreversible command in a
  capture, and each one carries an expert warning saying why.
- **BER-TLV and COMPREHENSION-TLV** -- recursive, with multi-byte tags,
  long-form and indefinite lengths, and tag names from the same tables
  `Tools/Asn1TlvDecode` uses.
- **File control templates** -- FCP, FCI and FMD with their TS 102 221
  clause 11.1.1.3 sub-tags.
- **Elementary files** -- EF.ICCID, EF.IMSI, EF.UST and EF.AD, attributed to
  the file selected in an earlier frame.
- **Command bodies** -- SELECT control bytes and target, the SFI form of
  READ/UPDATE BINARY, record number and mode, PIN key references, MANAGE
  CHANNEL operations, GET/PUT DATA tags.
- **ATR frames**, which the stock dissector reads as APDUs and gets wrong.

## Entry points

=== "Console script"

    ```bash
    yggdrasim-apdu-dissect decode --pcap capture.pcap --verbose
    yggdrasim-apdu-dissect install          # for the Wireshark GUI
    yggdrasim-apdu-dissect path             # print the .lua path
    yggdrasim-apdu-dissect probe --pcap capture.pcap
    ```

=== "Module"

    ```bash
    python -m Tools.ApduDissector decode --pcap capture.pcap \
        --fields frame.number,yapdu.command_name,yapdu.sw,yapdu.risk
    ```

=== "tshark directly"

    ```bash
    tshark -X lua_script:$(yggdrasim-apdu-dissect path) -r capture.pcap -V
    ```

## When it loads

The dissector is **not** loaded by every tshark or Wireshark invocation by
default. It is loaded automatically on the YggdraSIM-driven paths, and
becomes global for your account after a one-time `install`.

| How you start | Loaded? |
|---|---|
| HIL-bridge terminal decode view, live or `--open-pcap` | Yes, automatically |
| Wireshark launched from the HIL menu (`[B]` -> `[1]` -> start mode `[2]`) | Yes, automatically |
| `yggdrasim-apdu-dissect decode` | Yes, automatically |
| `yggdrasim-eum-diag` | Yes, automatically |
| A bare `tshark -r capture.pcap` you type yourself | Only after `install` |
| Wireshark started from the desktop or app menu | Only after `install` |

`YGGDRASIM_APDU_DISSECTOR=0` opts the automatic paths out.

## Making it global

tshark takes the script as a path; the GUI has no equivalent. `install` copies
the Lua tree into the personal plugin folder Wireshark reports for itself,
which **both** Wireshark and tshark read at startup. After this, every
invocation under your account loads it with no flags at all:

```bash
yggdrasim-apdu-dissect install --dry-run   # show what would be copied
yggdrasim-apdu-dissect install
yggdrasim-apdu-dissect uninstall           # and back out again
```

In a running Wireshark, pick up the change with **Analyze > Reload Lua
Plugins** (++ctrl+shift+l++).

Installing and passing `-X lua_script:` at the same time is harmless: the
entry point carries a load guard, because `Proto()` raises on a duplicate
name and Wireshark would otherwise refuse the whole plugin.

!!! note "Why each module bootstraps its own package.path"
    Wireshark's plugin loader executes every `.lua` file in the plugin
    directory standalone, in alphabetical order, so `cat.lua` runs before the
    entry point that is supposed to `require` it. Each module therefore puts
    its own directory on `package.path` before its first `require`. Without
    that the whole plugin is refused at startup with
    `module 'yggdrasim_apdu.util' not found`.

!!! warning "Wireshark refuses Lua scripts when running as root"
    It does so *silently*: no error, no warning, the script simply never loads
    and you get a stock decode that looks like a broken dissector. Run as a
    normal user. The CLI prints a warning when it detects this.

## Display filters worth knowing

```
yapdu.risk == 3                     every irreversible command in the capture
yapdu.sw != 0x9000                  every exchange the card did not accept
yapdu.command_name == "STORE_DATA"  eUICC traffic
yapdu.split.ambiguous == 1          exchanges the decoder could not resolve
yapdu.ef.iccid                      frames that revealed an ICCID
yapdu.cla.secure_messaging > 0      SCP-wrapped traffic
```

## How it attaches

The dissector registers against Wireshark's `gsmtap.type` dissector table for
`GSMTAP_TYPE_SIM` (`0x04`). That table hands it the payload with the GSMTAP
header already stripped, and it behaves the same whether or not the caller
passes `-d udp.port==4729,gsmtap`, which is what the HIL bridge does.

The stock `gsm_sim` dissector is *chained*, not displaced, so its 242 fields
stay filterable alongside `yapdu.*`. The exception is ATR frames, which
`gsm_sim` reads as APDUs and invents a status word from; those are withheld
from it.

Because the HIL-Bridge decode view renders `tshark -V` and PDML output, it
inherits the deeper tree with no change of its own. Set
`YGGDRASIM_APDU_DISSECTOR=0` to keep the dissector out of those calls.

## Command and response splitting

A SIMtrace SIM-APDU record puts the command APDU and the response APDU in one
frame, and ISO 7816-4 does not always say where the boundary is: a body of
`05 AA BB CC DD EE` reads equally well as case 3S or case 4S.

The dissector enumerates every structurally valid split, scores each against
the status word, the case the instruction normally uses, and the relationship
between Le and the response length, then reports which evidence decided it
(`yapdu.split.method`) and how confident it is (`yapdu.split.confidence`).
Where two readings genuinely tie, `yapdu.split.ambiguous` is set rather than
the ambiguity being hidden.

This replaces the instruction allowlist in
`Tools/HilBridge/live_decode_state.py`, which returns nothing for an
instruction it does not recognise -- so an unfamiliar command disappears from
the trace entirely.

## Secure messaging

An SCP03 or SCP11c wrapped command is broken out with no keys at all: the
C-MAC, the ciphertext, and whether the body is merely authenticated or also
encrypted. `yapdu.cla.secure_messaging > 0` finds every wrapped exchange.

Plaintext needs keys, and **Wireshark's Lua binding has no AES, no CMAC and
no hash**, so no Lua dissector can decrypt anything regardless of what it is
handed. The recovery therefore happens in Python, using the same engine the
terminal decode view uses, and the result is written to a sidecar the
dissector reads:

```bash
yggdrasim-apdu-dissect sidecar --pcap live.pcap --keybag live.keys.json
yggdrasim-apdu-dissect decode  --pcap live.pcap \
    --sidecar live.pcap.sidecar.json --verbose
```

The keybag is the one you already export with `EXPORT-KEYBAG` in the SCP03
admin shell or `SCP11.local_access`; a sibling `<pcap>*.keys.json` is picked
up automatically. In the Wireshark GUI, set the sidecar path in the
dissector's preferences instead.

Recovered plaintext is not merely displayed. The dissector re-runs its whole
decode over it, so a ciphered ES10b `STORE DATA` renders as a complete ES10b
tree rather than a blob with a note attached.

**A sidecar is bound to its capture by content, not by frame number.** Each
entry records the on-wire ciphered command, and an entry is applied only when
those bytes match the frame in front of it. A sidecar built from a different
capture therefore contributes nothing and sets
`yapdu.sm.sidecar_mismatch`, instead of attributing plaintext to the wrong
exchange. Corrupt or foreign-format sidecars collapse to one status line.

## Constant tables are generated

`Tools/ApduDissector/lua/yggdrasim_apdu/tables.lua` is generated from the
Python modules the rest of the toolkit already treats as authoritative:

```bash
python scripts/generate_apdu_dissector_tables.py --write
python scripts/generate_apdu_dissector_tables.py --check   # CI drift guard
```

Sources are `yggdrasim_common/apdu_risk.py`, `yggdrasim_common/apdu_tables.py`,
`yggdrasim_common/stk_tables.py`, `Tools/Asn1TlvDecode/main.py`,
`Tools/YggdraMCP/server.py`, `Tools/HilBridge/live_decode_state.py`,
`SIMCARD/etsi_fs.py` and `SIMCARD/gp.py`. The generated file is committed so
the Lua tree works standalone with no Python present, and
`tests/test_apdu_dissector_tables.py` fails when it drifts.

## Testing

```bash
python -m pytest tests/test_apdu_dissector_*.py
YGGDRASIM_REQUIRE_TSHARK=1 python -m pytest tests/test_apdu_dissector_*.py
```

Captures are synthesised at test time from `Tools/HilBridge/protocol.py`
helpers, so nothing binary is committed and identifiers stay inside the
documented test ranges.

Without `YGGDRASIM_REQUIRE_TSHARK=1`, the tshark-backed modules skip when
tshark is missing -- or when the suite runs as root and Wireshark refuses to
load the Lua. Set it in at least one CI job, or the dissector rots without the
suite noticing.

## Known limits

- Requires **Wireshark 3.4 or newer**; measured against 4.2.2. Re-run
  `yggdrasim-apdu-dissect probe` on a new floor version.
- Wireshark 4.2 exposes no `gsmtap.sub_type` field, and `gsmtap.*` field
  extractors return nothing inside a `gsmtap.type` subdissector, so ATR frames
  are recognised from their own bytes rather than the GSMTAP subtype. Frame
  direction is not surfaced; a SIMtrace record carries both halves anyway.
- PIN blocks and key material are reported by length only.
- An exchange whose instruction has no case hint and whose bytes fit two
  readings is decoded and flagged, not resolved. There is no information in
  the frame that would resolve it.

## See also

- [HIL Bridge](hil-bridge.md)
- [EUM Diagnostics](eum-diagnostics.md) -- `yggdrasim-eum-diag` now hands its
  captures to this dissector. Its own `dissector.lua` has been retired: it
  byte-scanned for the `BF36` tag with no TLV awareness, rendered the value as
  one opaque blob, loaded session keys it had no way to apply, and built a
  TvbRange from half the digit count of an ICCID, which breaks on any real
  19-digit one. `YGGDRASIM_EUM_SESSION_KEYS` is still honoured, and the key
  bundles are shown for reference with an explicit note that they are not
  being applied.
- `Tools/ApduDissector/WIRESHARK_ENVIRONMENT.md` -- the measured capability
  matrix behind the design
