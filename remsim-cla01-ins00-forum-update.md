# osmo-remsim-client-st2: truncated T=0 APDU for CLA=01 INS=00

I observed a reproducible APDU truncation with `osmo-remsim-client-st2` 1.2.0 and SIMtrace2 cardem mode against a production Thales eSIM/UICC.

The modem sends this APDU through `AT+CSIM`:

```text
0100000003400101
```

Interpreted as an ISO 7816 command APDU, this is a valid short Case 3 command:

```text
CLA = 01
INS = 00
P1  = 00
P2  = 00
Lc  = 03
Data = 40 01 01
```

However, the HIL/RSPRO receiver sees only:

```text
0100000003
```

This is the 5-byte T=0 header only. The `Lc=03` command data bytes `400101` are missing.

## Root Cause

The SIMtrace2 firmware first reports the T=0 header:

```text
01 00 00 00 03
```

`osmo-remsim-client-st2` then calls:

```c
rc = osmo_apdu_segment_in(&ac, data->data, data->data_len,
			  data->flags & CEMU_DATA_F_TPDU_HDR);
```

For `CLA=01 INS=00`, libosmocore's generic UICC case table does not know the instruction, so `osmo_apdu_segment_in()` returns `-1`.

`user_simtrace2.c` then treats the return value as a bitmask:

```c
if (rc & APDU_ACT_TX_CAPDU_TO_CARD) {
```

Since `-1 & APDU_ACT_TX_CAPDU_TO_CARD` is true, the client forwards `sizeof(ac.hdr) + ac.lc.tot`. At that point `ac.lc.tot` is still zero, so it forwards exactly the 5-byte header:

```text
0100000003
```

This can desynchronize the modem/card state and may trigger a modem reset.

## Proposed Fix

The attached patch does two things:

1. It handles `rc < 0` before bitmasking, so unknown APDUs are not accidentally forwarded as valid 5-byte commands.
2. It adds a local `CLA=01 INS=00` override in the SIMtrace2 frontend and treats that command as Case 3, where `P3` is `Lc`.

With the override, `osmo-remsim-client-st2` requests the remaining 3 bytes from the modem and forwards the complete command:

```text
0100000003400101
```

## Local Test

I tested the decision path with a small C harness linked against the installed Osmocom libraries. The test feeds the exact T=0 split:

1. Header: `0100000003`
2. Body: `400101`

Result:

```text
apdu_dispatch.c:112 Unknown APDU case 0
original_rc=-1
fallback_rc=0x2 lc=0/3
body_rc=0x1 lc=3/3
complete=0100000003400101
```

This confirms:

- the original classifier rejects `CLA=01 INS=00`;
- the fallback correctly requests 3 modem-to-card data bytes;
- after receiving `400101`, the completed APDU is exactly `0100000003400101`.

## Notes

This patch keeps the workaround narrow:

```c
hdr[0] == 0x01 && hdr[1] == 0x00
```

If the same Thales command is later seen on other logical channels, the match could be broadened to:

```c
(hdr[0] & 0xFC) == 0x00 && hdr[1] == 0x00
```

For now I prefer the exact match because it avoids changing behavior for unrelated proprietary commands.
