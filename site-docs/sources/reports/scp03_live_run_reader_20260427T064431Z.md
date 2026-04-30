# SCP03 live command run (real PC/SC reader)

- Started:  2026-04-27T06:44:30.049011+00:00
- Finished: 2026-04-27T06:44:31.043789+00:00
- Backend:  YGGDRASIM_CARD_BACKEND=reader
- Plugins:  YGGDRASIM_DISALLOW_PLUGINS=1
- Reader:   [0] HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00
- ATR:      3B9F96803F87828031E073FE211F674554753030006537
- Allow auth tests:  False (env SCP03_LIVE_ALLOW_AUTH)
- Allow write tests: False (env SCP03_LIVE_ALLOW_WRITE)

- Total:   1
- Pass:    1
- Fail:    0
- Timeout: 0
- Skipped: 0

## Verdict matrix

| Command | Policy | Verdict | Exit | Elapsed (s) | SWs observed | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `ATR` | default | PASS | 0 | 0.995 | — | ok |

## Per-command transcripts

### `ATR` — PASS

- Category:        session
- Script:          `tests/live_scp03/ATR.in.txt`
- Started at:      2026-04-27T06:44:30.049130+00:00
- Elapsed:         0.995 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['ATR']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Reset and print a parsed ATR breakdown.
ATR
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.

=== ATR DETAILS ===
ATR: 3B 9F 96 80 3F 87 82 80 31 E0 73 FE 21 1F 67 45 54 75 30 30 00 65 37
+ TS = 3B --> Direct Convention
+ T0 = 9F, Y(1): 1001, K: 15 (historical bytes)
    TA(1) = 96 --> Fi=512, Di=32, 16 cycles/ETU
      250000 bits/s at 4 MHz, fMax for Fi = 5 MHz => 312500 bits/s
  TD(1) = 80 --> Y(i+1) = 1000, Protocol T = 0 
-----
  TD(2) = 3F --> Y(i+1) = 0011, Protocol T = 15 - Global interface bytes following 
-----
  TA(3) = 87 --> Clock stop: state H - Class accepted by the card: (3G) A 5V B 3V C 1.8V
  TB(3) = 82
+ Historical bytes: 80 31 E0 73 FE 21 1F 67 45 54 75 30 30 00 65
  Category indicator byte: 80 (compact TLV data object)
    Tag: 3, len: 1 (card service data byte)
      Card service data byte: E0
        - Application selection: by full DF name
        - Application selection: by partial DF name
        - BER-TLV data objects available in EF.DIR
    Tag: 7, len: 3 (card capabilities)
      Selection methods: FE
        - DF selection by full DF name
        - DF selection by partial DF name
        - DF selection by path
        - DF selection by file identifier
        - Implicit DF selection
        - Short EF identifier supported
        - Record number supported
      Data coding byte: 21
        - Behaviour of write functions: proprietary
        - Value 'FF' for the first byte of BER-TLV tag fields: invalid
        - Data unit in quartets: 2
      Command chaining, length fields and logical channels: 1F
        - Logical channel number assignment: by the interface device and card
        - Maximum number of logical channels: 8
    Tag: 6, len: 7 (pre-issuing data)
      Data: 45547530300065
+ TCK = 37 (correct checksum)

```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```
