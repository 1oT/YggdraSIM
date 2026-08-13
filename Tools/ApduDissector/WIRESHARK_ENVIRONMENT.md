<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->

# Wireshark capability findings

Measured with `Tools/ApduDissector/lua/probe_wireshark_env.lua` against
**TShark 4.2.2 (Debian `4.2.2-1.1build3`), Lua 5.2.4**. Re-run the probe on
any new floor version before trusting these answers:

```
tshark -X lua_script:Tools/ApduDissector/lua/probe_wireshark_env.lua -r any.pcap
```

## Registration

| Question | Answer |
|---|---|
| Is `gsmtap.type` a Lua-reachable `DissectorTable`? | **Yes** -- `FT_UINT8`, `BASE_HEX`, registered by `packet-gsmtap.c`. `DissectorTable.get("gsmtap.type"):add(0x04, proto)` succeeds. |
| What tvb does the subdissector receive? | **Exactly the GSMTAP payload** -- the header is already stripped. `payload:offset()` reports 58 for our captures (Ethernet 14 + IPv4 20 + UDP 8 + GSMTAP 16). |
| Does it work under `-d udp.port==4729,gsmtap`? | **Yes**, identically to the no-`-d` case. GSMTAP is the default dissector for UDP 4729 anyway, so both paths converge. |
| Is a post-dissector needed as a fallback? | **No.** The `gsmtap.type` binding covers every invocation the repo makes. Dropping the post-dissector removes the "runs on every frame in the capture" cost that `Tools/EumDiag/dissector.lua` pays. |
| Can the stock `gsm_sim` still run? | **Yes** -- `Dissector.get("gsm_sim"):call(payload, pinfo, tree)` works from inside our dissector and preserves all 242 `gsm_sim.*` fields plus its info-column text. Registering on `gsmtap.type` otherwise displaces it entirely. |

## Limitations that shape the design

**`gsmtap.sub_type` does not exist.** `packet-gsmtap.c` exposes
`gsmtap.rrc_sub_type` and `gsmtap.e1t1_sub_type` but adds no subtype field for
`GSMTAP_TYPE_SIM`. A SIM subdissector therefore cannot learn APDU (`0x00`) from
ATR (`0x01`) through a field.

**`gsmtap.*` field extractors return `nil` inside a `gsmtap.type`
subdissector** -- verified both with and without `-V`. `Field.new` succeeds at
load time for `gsmtap.type`, `gsmtap.arfcn` and `gsmtap.uplink`, but calling the
extractor during our dissection yields nothing.

Consequences, both adopted:

1. **ATR frames are detected structurally**, from the ISO 7816-3 TS byte
   (`0x3B` direct convention, `0x3F` inverse) combined with a failed C-APDU /
   R-APDU split -- not from the GSMTAP subtype.
2. **Direction is not surfaced from GSMTAP.** No `uplink` flag is readable. This
   costs nothing real: a SIMtrace SIM-APDU record carries the command and the
   response in the same frame, so direction was never a discriminator here.

**Field extractors must be constructed at file scope.** Building one inside a
dissector raises `Field_new: A Field extractor must be defined before Taps or
Dissectors get called`.

## Wireshark refuses Lua scripts when running as root

This is the most dangerous finding for CI, because it fails **silently**:

```
# as root -- no error, no warning, the script simply never loads
tshark -X lua_script:probe_wireshark_env.lua -r capture.pcap      # no PROBE output

# as an unprivileged user -- works
su -s /bin/bash someuser -c "tshark -X lua_script:... -r capture.pcap"
```

There is no diagnostic beyond the generic `Running as user "root" ... This
could be dangerous.` notice, which appears whether or not a script was
requested. A test suite that runs as root will therefore exercise **no Lua at
all** while reporting success.

`tests/apdu_dissector_support.py` detects this (`lua_is_loadable()`) and the
Lua test modules fail loudly rather than skipping when
`YGGDRASIM_REQUIRE_TSHARK=1` is set. Containers that run as root need an
unprivileged account for the Lua suite; see `run_tshark_unprivileged()`.

## Baseline: what stock Wireshark does with our captures

Recorded against a synthetic capture built from
`Tools/HilBridge/protocol.py` helpers. These are the regression targets.

| Frame | Content | Stock 4.2.2 output |
|---|---|---|
| 1 | `SELECT` ADF.USIM by AID, `61 2B` | Decoded, AID shown |
| 2 | `GET RESPONSE` returning an FCP template | **`[Malformed Packet]`** |
| 3 | `READ BINARY` of EF.ICCID | `Offset=0` only; ICCID bytes undecoded |
| 4 | `STORE DATA` to the ISD-R carrying an ES10c request | **`ETSI TS 102.221 e2`** -- the instruction is not even named, the payload is untouched |
| 5 | ATR frame (GSMTAP subtype `0x01`) | **Mis-decoded as an APDU** -- `3 9f : Unknown status word: 4ba9` |

Frames 2, 4 and 5 are outright defects in the status quo, not merely missing
depth.
