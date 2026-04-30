# SCP03 live command run (real PC/SC reader)

- Started:  2026-04-27T06:44:51.923047+00:00
- Finished: 2026-04-27T06:45:16.277613+00:00
- Backend:  YGGDRASIM_CARD_BACKEND=reader
- Plugins:  YGGDRASIM_DISALLOW_PLUGINS=1
- Reader:   [0] HID Global OMNIKEY 3x21 Smart Card Reader [OMNIKEY 3x21 Smart Card Reader] 00 00
- ATR:      3B9F96803F87828031E073FE211F674554753030006537
- Allow auth tests:  False (env SCP03_LIVE_ALLOW_AUTH)
- Allow write tests: False (env SCP03_LIVE_ALLOW_WRITE)

- Total:   28
- Pass:    28
- Fail:    0
- Timeout: 0
- Skipped: 36

## Skipped (gated for reader safety)

| Command | Policy | Reason |
| --- | --- | --- |
| `AUTH-SD` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `SCP03-SD` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `SCP02-SD` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `KEYS` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `LOGOUT` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `LIST` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `LIST-IOT` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `GET-IOT` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `APPS` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `PKGS` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `SD` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `STORE-DATA` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `LOCK` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `UNLOCK` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `DEL` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `SCAN` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `UPDATE` | write | Destructive write to card; gated by SCP03_LIVE_ALLOW_AUTH=1 + SCP03_LIVE_ALLOW_WRITE=1. |
| `DUMP-FS` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `VALIDATE` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `ARR` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `CERT-INFO` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `EXPORT-EUICC` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `EXPORT-KEYBAG` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `PROFILE-DIFF` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `REPORT` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `MANAGE-PROFILE` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `GET-DATA` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `PUT-KEY` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `SET-STATUS` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `MANAGE-CHANNEL` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `WIZARD` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `FS-ADMIN` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `MANAGE-PIN` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `RUN-AUTH` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `STK` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |
| `OTA` | auth | Requires SCP03 SD authentication; gated by SCP03_LIVE_ALLOW_AUTH=1 (every key mismatch increments the SD lockout counter — 3 misses can brick the SD). |

## Verdict matrix

| Command | Policy | Verdict | Exit | Elapsed (s) | SWs observed | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| `RESET` | default | PASS | 0 | 0.965 | — | ok |
| `INFO` | default | PASS | 0 | 1.354 | 9000, 6982, 6A80, 6881 | ok |
| `ATR` | default | PASS | 0 | 0.928 | — | ok |
| `CLS` | default | PASS | 0 | 0.91 | — | ok |
| `SELECT` | default | PASS | 0 | 0.902 | 9000 | ok |
| `READ` | default | PASS | 0 | 0.944 | 9000 | ok |
| `RECORD` | default | PASS | 0 | 0.958 | 9000 | ok |
| `RUN-AUTH-TEST` | default | PASS | 0 | 0.88 | — | ok |
| `DERIVE-OPC` | default | PASS | 0 | 0.83 | — | ok |
| `DECODE` | default | PASS | 0 | 0.834 | — | ok |
| `SHOW` | default | PASS | 0 | 0.827 | — | ok |
| `AIDS` | default | PASS | 0 | 0.829 | — | ok |
| `SET-AID-ALIAS` | default | PASS | 0 | 0.823 | — | ok |
| `SET-DEFAULT` | default | PASS | 0 | 0.824 | — | ok |
| `SET-GOLD-PROFILE` | default | PASS | 0 | 0.85 | — | ok |
| `GOLD-PROFILE` | default | PASS | 0 | 0.824 | — | ok |
| `CLEAR-GOLD-PROFILE` | default | PASS | 0 | 0.837 | — | ok |
| `GUIDE` | default | PASS | 0 | 0.831 | — | ok |
| `HELP` | default | PASS | 0 | 0.834 | — | ok |
| `CONFIG` | default | PASS | 0 | 0.812 | — | tolerate_failure |
| `BINDS` | default | PASS | 0 | 0.816 | — | tolerate_failure |
| `RUN` | default | PASS | 0 | 0.83 | — | ok |
| `SCRIPT` | default | PASS | 0 | 0.819 | — | ok |
| `DEBUG` | default | PASS | 0 | 0.826 | — | ok |
| `VERBOSE` | default | PASS | 0 | 0.817 | — | ok |
| `EXIT` | default | PASS | 0 | 0.819 | — | ok |
| `Q` | default | PASS | 0 | 0.813 | — | ok |
| `QA` | default | PASS | 0 | 0.812 | — | ok |

## Per-command transcripts

### `RESET` — PASS

- Category:        session
- Script:          `tests/live_scp03/RESET.in.txt`
- Started at:      2026-04-27T06:44:51.923110+00:00
- Elapsed:         0.965 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Resetting card', 'Reset Successful']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Reset the card connection (cold/warm reset) and re-read ATR.
RESET
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[*] Resetting card...
[+] Reset Successful.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `INFO` — PASS

- Category:        session
- Script:          `tests/live_scp03/INFO.in.txt`
- Started at:      2026-04-27T06:44:52.888733+00:00
- Elapsed:         1.354 s
- Exit code:       0
- Timed out:       False
- SWs observed:    9000, 6982, 6A80, 6881
- SW frequency:    9000×14, 6982×2, 6A80×2, 6881×1
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['CARD INFO', 'ATR', 'ICCID']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Print card specs (ATR, ICCID, eID, SGP version). No SD auth required.
INFO
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.

=== CARD INFO ===
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[-->] 00A40004022FE2
[<--] 62178202412183022FE28A01058B032F06028002000A880110 9000
      => Success
[-->] 00B000000A
[<--] 98001032547698103285 9000
      => Success
ATR   : 3B9F96803F87828031E073FE211F674554753030006537
ICCID : 89000123456789012358
[-->] 00A4040010A0000005591010FFFFFFFF8900000200
[<--] 6F188410A0000005591010FFFFFFFF8900000200A5049F6501FF 9000
      => Success
[-->] 00CA005A00
[<--] 89049032118427504800000000003654 9000
      => Success
[-->] 80E2910003BF3E00
[<--]  6982
      => Security status not satisfied
[-->] 0070000001
[<--] 01 9000
      => Success
[-->] 01A4040010A0000005591010FFFFFFFF8900000100
[<--] 6F258410A0000005591010FFFFFFFF8900000100A5049F6501FFE0058203020500E104800206C0 9000
      => Success
[-->] 81E2910003BF3E00
[<--]  6A80
      => Incorrect parameters in data field
[-->] 0070800100
[<--]  9000
      => Success
[-->] 80AA00000DA90B8100820101830107840101
[<--]  9000
      => Success
[-->] 00A4040010A0000005591010FFFFFFFF8900000100
[<--] 6F258410A0000005591010FFFFFFFF8900000100A5049F6501FFE0058203020500E104800206C0 9000
      => Success
[-->] 80100000010C
[<--]  6982
      => Security status not satisfied
[-->] 81E2910003BF3E00
[<--]  6881
      => Logical channel not supported
[-->] 00A4040010A0000005591010FFFFFFFF8900000100
[<--] 6F258410A0000005591010FFFFFFFF8900000100A5049F6501FFE0058203020500E104800206C0 9000
      => Success
[-->] 80E2910003BF3E00
[<--]  6A80
      => Incorrect parameters in data field
[-->] 80E2910006BF3E035C015A
[<--] BF3E125A1089049032118427504800000000003654 9000
      => Success
[-->] 00A4040010A0000005591010FFFFFFFF8900000100
[<--] 6F258410A0000005591010FFFFFFFF8900000100A5049F6501FFE0058203020500E104800206C0 9000
      => Success
[-->] 80E2910003BF5500
[<--] BF55820110A082010C308201088019312E332E362E312E342E312E35333737352E312E352E312E31810F65696D312E736D2E316F742E636F6D820101840114A55BA059301306072A8648CE3D020106082A8648CE3D030107034200046FF22E775FEA4ABBBDF8C9E62B6AA9E3849CBADCFFBDB959A826CF35CC9F47AD00F70572BEE27707F69F4CEDB5272D047024B4688D873AC9111F331A453C3188A65BA059301306072A8648CE3D020106082A8648CE3D03010703420004DDE262E0D2E81AC8666E6706944EE10B49B2AB63ED5D4E0B44658DB02B9C22F341370758BC03B9E07C04DC8963A40D81AFFBEB39765C92BF8DD17074348B85CE870207808814F54172BDF98A95D65CBEB88A38A1C11D800A85C38900 9000
      => Success
eID   : 89049032118427504800000000003654
Spec  : SGP.32 (IoT)
[+] Loaded SCP03 inventory profile for ICCID 89000123456789012358.
========================================

```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `ATR` — PASS

- Category:        session
- Script:          `tests/live_scp03/ATR.in.txt`
- Started at:      2026-04-27T06:44:54.243088+00:00
- Elapsed:         0.928 s
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

### `CLS` — PASS

- Category:        session
- Script:          `tests/live_scp03/CLS.in.txt`
- Started at:      2026-04-27T06:44:55.171417+00:00
- Elapsed:         0.91 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   —
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# CLS in stdin mode is effectively a no-op (it tries to clear the screen via
# clear/cls); the test confirms it does not error out and yields a clean exit.
CLS
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `SELECT` — PASS

- Category:        fs
- Script:          `tests/live_scp03/SELECT.in.txt`
- Started at:      2026-04-27T06:44:56.081375+00:00
- Elapsed:         0.902 s
- Exit code:       0
- Timed out:       False
- SWs observed:    9000
- SW frequency:    9000×5
- Expected SW:     ['9000']
- Expected SW any: —
- Expected text:   ['3F00']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Select MF (3F00). Pure ETSI TS 102 221 SELECT, no SD auth required.
SELECT 3F00
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[-->] 00A40004022F06
[<--] 621A82054221006E0683022F068A01058B032F060480020294880130 9000
      => Success
[-->] 00B2060400
[<--] 80015EA40683010A9501088001209700FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
[+] Selected 3F00 (3F00)
--- FCP ---
    [Type]     DF (Tree)
    [Size]     113 bytes
    [Sec]      2F0606
               | UPDATE/APPEND/DEACTIVATE/ACTIVATE/TERMINATE: ADM1
               | Proprietary(0x20): Never
    [LCS]      05

```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `READ` — PASS

- Category:        fs
- Script:          `tests/live_scp03/READ.in.txt`
- Started at:      2026-04-27T06:44:56.983981+00:00
- Elapsed:         0.944 s
- Exit code:       0
- Timed out:       False
- SWs observed:    9000
- SW frequency:    9000×11
- Expected SW:     ['9000']
- Expected SW any: —
- Expected text:   ['EF (Transparent)', 'iccid:']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Select EF_ICCID (under MF) and READ BINARY the full body.
SELECT 3F00
SELECT 2FE2
READ
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[-->] 00A40004022F06
[<--] 621A82054221006E0683022F068A01058B032F060480020294880130 9000
      => Success
[-->] 00B2060400
[<--] 80015EA40683010A9501088001209700FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
[+] Selected 3F00 (3F00)
--- FCP ---
    [Type]     DF (Tree)
    [Size]     113 bytes
    [Sec]      2F0606
               | UPDATE/APPEND/DEACTIVATE/ACTIVATE/TERMINATE: ADM1
               | Proprietary(0x20): Never
    [LCS]      05

[-->] 00A40004022FE2
[<--] 62178202412183022FE28A01058B032F06028002000A880110 9000
      => Success
[-->] 00A40004022F06
[<--] 621A82054221006E0683022F068A01058B032F060480020294880130 9000
      => Success
[-->] 00B2020400
[<--] 80010190008001029700800118A40683010A950108800140A40683010A9501088401D4A40683010A950108FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
[-->] 00A40004022FE2
[<--] 62178202412183022FE28A01058B032F06028002000A880110 9000
      => Success
[<--] 62178202412183022FE28A01058B032F06028002000A880110 9000
[+] Selected 2FE2 (2FE2)
--- FCP ---
    [Type]     EF (Transparent)
    [Size]     10 bytes
    [Sec]      2F0602
               | READ: Always
               | UPDATE: Never
               | DEACTIVATE/ACTIVATE: ADM1
               | TERMINATE: ADM1
               | TERMINATE: ADM1
    [LCS]      05

[-->] 00B0000000
[<--] 98001032547698103285 9000
      => Success
Data [9000]: 98001032547698103285
          | iccid: 89000123456789012358
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `RECORD` — PASS

- Category:        fs
- Script:          `tests/live_scp03/RECORD.in.txt`
- Started at:      2026-04-27T06:44:57.928651+00:00
- Elapsed:         0.958 s
- Exit code:       0
- Timed out:       False
- SWs observed:    9000
- SW frequency:    9000×12
- Expected SW:     —
- Expected SW any: ['9000', '6981', '6A82']
- Expected text:   ['Reading All Records']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Select USIM ADF and read the EF_DIR record set.
SELECT 3F00
SELECT 2F00
RECORD ALL
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[-->] 00A40004022F06
[<--] 621A82054221006E0683022F068A01058B032F060480020294880130 9000
      => Success
[-->] 00B2060400
[<--] 80015EA40683010A9501088001209700FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
[-->] 00A40004023F00
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
      => Success
[<--] 62298202782183023F00A50C800171830400040B988701018A01058B032F0606C60990014083010183010A 9000
[+] Selected 3F00 (3F00)
--- FCP ---
    [Type]     DF (Tree)
    [Size]     113 bytes
    [Sec]      2F0606
               | UPDATE/APPEND/DEACTIVATE/ACTIVATE/TERMINATE: ADM1
               | Proprietary(0x20): Never
    [LCS]      05

[-->] 00A40004022F00
[<--] 621A8205422100260283022F008A01058B032F06048002004C8801F0 9000
      => Success
[-->] 00A40004022F06
[<--] 621A82054221006E0683022F068A01058B032F060480020294880130 9000
      => Success
[-->] 00B2040400
[<--] 800101900080011AA40683010A950108800140A40683010A9501088401D4A40683010A950108FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
[-->] 00A40004022F00
[<--] 621A8205422100260283022F008A01058B032F06048002004C8801F0 9000
      => Success
[<--] 621A8205422100260283022F008A01058B032F06048002004C8801F0 9000
[+] Selected 2F00 (2F00)
--- FCP ---
    [Type]     EF (Linear Fixed)
    [Size]     76 bytes
    [Rec]      2 records x 38 bytes
    [Sec]      2F0604
               | READ: Always
               | UPDATE/DEACTIVATE/ACTIVATE: ADM1
               | TERMINATE: ADM1
               | TERMINATE: ADM1
    [LCS]      05

[*] Reading All Records...
[-->] 00B2010426
[<--] 61184F10A0000000871002FFFFFFFF890709000050045553696DFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
Record 01 [9000]: 61184F10A0000000871002FFFFFFFF890709000050045553696DFFFFFFFFFFFFFFFFFFFFFFFF
          | AID: A0000000871002FFFFFFFF8907090000
          | Label: USim
[-->] 00B2020426
[<--] FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 9000
      => Success
Record 02 [9000]: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
          | Error: Empty Record
[*] End of file reached.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `RUN-AUTH-TEST` — PASS

- Category:        auth
- Script:          `tests/live_scp03/RUN-AUTH-TEST.in.txt`
- Started at:      2026-04-27T06:44:58.887055+00:00
- Elapsed:         0.88 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['AUTN check: OK', 'APDU check: OK', 'Offline vector check complete']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Offline 3GPP TS 35.207 Milenage vector validation. Does not touch the card
# transport, so it works regardless of authentication state.
RUN-AUTH-TEST
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
=== Milenage Test Vector (3GPP TS 35.207) ===
  RAND: 23553CBE9637A89D218AE64DAE47BF35
  Ki:   465B5CE8B199B49FAA5F0A2EE238A6BC
  OP:   CDC202D5123E20F62B6D676AC72CB318
  OPc (derived): CD63CB71954A9F4E48A5994E37A02BAF
  OPc (expected): CD63CB71954A9F4E48A5994E37A02BAF
  OPc check: OK
  RES (derived): A54211D5E3BA50BF
  RES (expected): A54211D5E3BA50BF
  RES check: OK
  CK  (derived): B40BA9A3C58B2A05BBF0D987B21BF8CB
  CK  (expected): B40BA9A3C58B2A05BBF0D987B21BF8CB
  CK  check: OK
  IK  (derived): F769BCD751044604127672711C6D3441
  IK  (expected): F769BCD751044604127672711C6D3441
  IK  check: OK
  Kc  (derived): EAE4BE823AF9A08B
  Kc  (expected): EAE4BE823AF9A08B
  Kc  check: OK
  SQN:  000000000001
  AMF:  8000
  AUTN (derived): AA689C6483718000F48B60145BEACF8E
  AUTN (expected): AA689C6483718000F48B60145BEACF8E
  AUTN check: OK
  00 88 APDU (derived): 00880081221023553CBE9637A89D218AE64DAE47BF3510AA689C6483718000F48B60145BEACF8E00
  00 88 APDU (expected): 00880081221023553CBE9637A89D218AE64DAE47BF3510AA689C6483718000F48B60145BEACF8E00
  APDU check: OK
  Response payload (derived): DB08A54211D5E3BA50BF10B40BA9A3C58B2A05BBF0D987B21BF8CB10F769BCD751044604127672711C6D344108EAE4BE823AF9A08B
  Response payload (expected): DB08A54211D5E3BA50BF10B40BA9A3C58B2A05BBF0D987B21BF8CB10F769BCD751044604127672711C6D344108EAE4BE823AF9A08B
  Response check: OK
  Response APDU (derived): DB08A54211D5E3BA50BF10B40BA9A3C58B2A05BBF0D987B21BF8CB10F769BCD751044604127672711C6D344108EAE4BE823AF9A08B9000
[*] Offline vector check complete. Use RUN-AUTH for live APDU execution.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `DERIVE-OPC` — PASS

- Category:        auth
- Script:          `tests/live_scp03/DERIVE-OPC.in.txt`
- Started at:      2026-04-27T06:44:59.767211+00:00
- Elapsed:         0.83 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['OPc:']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Derive OPc from a Ki/OP pair per 3GPP TS 35.206. Offline computation,
# no APDU traffic involved.
DERIVE-OPC 465B5CE8B199B49FAA5F0A2EE238A6BC CDC202D5123E20F62B6D676AC72CB318
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
OPc: CD63CB71954A9F4E48A5994E37A02BAF
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `DECODE` — PASS

- Category:        tools
- Script:          `tests/live_scp03/DECODE.in.txt`
- Started at:      2026-04-27T06:45:00.597155+00:00
- Elapsed:         0.834 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Tag 6F', 'Tag 82', 'Tag 83']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# BER-TLV decoder smoke test. Decodes a synthetic FCI template containing
# a file descriptor (82) and FID (83) — both well-formed.
DECODE 6F0A8204004141008302DEAD
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
Tag 6F:
  Tag 82 (L=4): 00414100
  Tag 83 (L=2): DEAD
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `SHOW` — PASS

- Category:        config
- Script:          `tests/live_scp03/SHOW.in.txt`
- Started at:      2026-04-27T06:45:01.431294+00:00
- Elapsed:         0.827 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['[KEYS]', 'scp03_kenc', '[GOLD_PROFILE]']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Display current SQLite-backed SCP03 configuration.
SHOW
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
--- Configuration (SQLite-backed SCP03 state) ---
Active ICCID: 89000123456789012358
Observed eID: 89049032118427504800000000003654
[KEYS]
  enc = 1122334455667788AABBCCDDEEFF0011
  mac = 1122334455667788AABBCCDDEEFF0011
  dek = 1122334455667788AABBCCDDEEFF0011
  kvn = 30
  aid = A000000151000000
  adm = 3132333435363738
  scp03_kenc = 1122334455667788AABBCCDDEEFF0011
  scp03_kmac = 1122334455667788AABBCCDDEEFF0011
  scp03_dek = 1122334455667788AABBCCDDEEFF0011
  scp03_kvn = 30
  scp02_enc = 1122334455667788AABBCCDDEEFF0011
  scp02_mac = 1122334455667788AABBCCDDEEFF0011
  scp02_dek = 1122334455667788AABBCCDDEEFF0011
  scp02_kvn = 20
[GOLD_PROFILE]
  path = 
  standard = SGP.32
  authenticate_sd = true
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `AIDS` — PASS

- Category:        config
- Script:          `tests/live_scp03/AIDS.in.txt`
- Started at:      2026-04-27T06:45:02.258845+00:00
- Elapsed:         0.829 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['ISDR', 'MNOSD']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# List registered AID aliases from Workspace/SCP03/aid.txt.
AIDS
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
--- AID Registry (aid.txt) ---
  ARAC       : A00000015141434C01 [ARAC]
  ARAM       : A00000015141434C00 [ARAM]
  ECASD      : A0000005591010FFFFFFFF8900000200
  ISDP0      : A0000005591010FFFFFFFF8900001000
  ISDP1      : A0000005591010FFFFFFFF8900001100
  ISDP2      : A0000005591010FFFFFFFF8900001200
  ISDP3      : A0000005591010FFFFFFFF8900001300
  ISDP4      : A0000005591010FFFFFFFF8900001400
  ISDP5      : A0000005591010FFFFFFFF8900001500
  ISDR       : A0000005591010FFFFFFFF8900000100
  MNOSD      : A000000151000000
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `SET-AID-ALIAS` — PASS

- Category:        config
- Script:          `tests/live_scp03/SET-AID-ALIAS.in.txt`
- Started at:      2026-04-27T06:45:03.087654+00:00
- Elapsed:         0.823 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['LIVE_TEST_ALIAS']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Map a temporary alias to an AID, list to confirm, then exit. The alias
# write goes to Workspace/SCP03/aid.txt; the runner snapshots/restores that
# file around the run so the workspace stays clean.
SET-AID-ALIAS LIVE_TEST_ALIAS A0000005591010FFFFFFFF8900000100
AIDS
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[+] AID alias 'LIVE_TEST_ALIAS' saved.
--- AID Registry (aid.txt) ---
  ARAC       : A00000015141434C01 [ARAC]
  ARAM       : A00000015141434C00 [ARAM]
  ECASD      : A0000005591010FFFFFFFF8900000200
  ISDP0      : A0000005591010FFFFFFFF8900001000
  ISDP1      : A0000005591010FFFFFFFF8900001100
  ISDP2      : A0000005591010FFFFFFFF8900001200
  ISDP3      : A0000005591010FFFFFFFF8900001300
  ISDP4      : A0000005591010FFFFFFFF8900001400
  ISDP5      : A0000005591010FFFFFFFF8900001500
  ISDR       : A0000005591010FFFFFFFF8900000100
  LIVE_TEST_ALIAS : A0000005591010FFFFFFFF8900000100
  MNOSD      : A000000151000000
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `SET-DEFAULT` — PASS

- Category:        config
- Script:          `tests/live_scp03/SET-DEFAULT.in.txt`
- Started at:      2026-04-27T06:45:03.911149+00:00
- Elapsed:         0.824 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Resetting configuration to defaults', 'Reset complete']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Factory reset configuration to default test keys. The runner snapshots
# Workspace/SCP03/keys.ini before the run and restores it afterwards so this
# remains non-destructive between local runs.
SET-DEFAULT
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[!] Resetting configuration to defaults...
[+] Reset complete.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `SET-GOLD-PROFILE` — PASS

- Category:        profile
- Script:          `tests/live_scp03/SET-GOLD-PROFILE.in.txt`
- Started at:      2026-04-27T06:45:04.735685+00:00
- Elapsed:         0.85 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Gold combined profile YAML path saved', 'Gold profile reference']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Persist a gold combined-YAML path. The path is synthetic / non-existent,
# so the test verifies the SQLite write side without forcing a real diff.
SET-GOLD-PROFILE reports/scp03_live_run/gold.yaml SGP.32 AUTH=Y
GOLD-PROFILE
CLEAR-GOLD-PROFILE
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[+] Gold combined profile YAML path saved to SQLite state.
    path=reports/scp03_live_run/gold.yaml
    standard=SGP.32
    authenticate_sd=true (optional 3rd arg AUTH=Y|AUTH=N)
--- Gold profile reference (SQLite [GOLD_PROFILE]) ---
  path             : reports/scp03_live_run/gold.yaml
  standard         : SGP.32
  authenticate_sd  : True
  PROFILE-DIFF reads the card and diffs against this YAML (or an override path).
[+] Cleared gold profile path (standard/auth prefs kept).
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `GOLD-PROFILE` — PASS

- Category:        profile
- Script:          `tests/live_scp03/GOLD-PROFILE.in.txt`
- Started at:      2026-04-27T06:45:05.585463+00:00
- Elapsed:         0.824 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Gold profile reference']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Show persisted gold path / standard / SD-auth flag (read-only).
GOLD-PROFILE
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
--- Gold profile reference (SQLite [GOLD_PROFILE]) ---
  path             : (not set)
  standard         : SGP.32
  authenticate_sd  : True
  PROFILE-DIFF reads the card and diffs against this YAML (or an override path).
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `CLEAR-GOLD-PROFILE` — PASS

- Category:        profile
- Script:          `tests/live_scp03/CLEAR-GOLD-PROFILE.in.txt`
- Started at:      2026-04-27T06:45:06.409378+00:00
- Elapsed:         0.837 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Cleared gold profile path']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Clear the persisted gold path (idempotent).
CLEAR-GOLD-PROFILE
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[+] Cleared gold profile path (standard/auth prefs kept).
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `GUIDE` — PASS

- Category:        system
- Script:          `tests/live_scp03/GUIDE.in.txt`
- Started at:      2026-04-27T06:45:07.246939+00:00
- Elapsed:         0.831 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['GlobalPlatform']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Render the GP topic guide (no APDU traffic).
GUIDE GP
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.

=== GlobalPlatform Architecture & APDU Guide ===
Standard: 8;;https://globalplatform.org/wp-content/uploads/2025/05/GPC_CardSpecification_v2.3.1.49_PublicRvw.pdfGPC Card Specification v2.3.18;;

1. Security Domain (SD) Architecture (GPCS 2.2, 11.1)
   The Issuer Security Domain (ISD) is the primary root of trust, possessing Token Verification and
   Authorized Management privileges. Supplementary Security Domains (SSD) govern provisioning for
   Application Providers or Controlling Authorities.
   - SELECT (00 A4 04 00): `00 A4 04 00 <Lc> <AID>`. Standard GP ISD AID: `A0 00 00 01 51 00 00 00`.
     Selecting an SD routes subsequent APDUs to its SCP handler (e.g. INITIALIZE UPDATE, EXTERNAL AUTH).
   - Privilege Bitmask (Tag C5): 0x80=Security Domain, 0x40=DAP Verification, 0x20=Delegated Management,
     0x10=Card Lock, 0x08=Card Terminate, 0x04=Default Selected, 0x02=CVM Management.

2. SCP03 Handshake: INITIALIZE UPDATE (80 50) & EXTERNAL AUTHENTICATE (84 82)
   The secure channel is established before any protected GP commands.
   - INITIALIZE UPDATE: `80 50 00 00 08 <Host_Challenge(8)>`. Sent in clear. Card returns:
     Key Version Number (1), Key Identifier (1), Key Diversification Data (10), Card Challenge (8), Card Cryptogram (8).
     Session keys (S-ENC, S-MAC, S-RMAC) are derived via NIST SP 800-108 KDF from static K-ENC/K-MAC and Host+Card challenges.
   - EXTERNAL AUTHENTICATE: `84 82 <SecLevel> 00 10 <Host_Cryptogram(8)> <MAC(8)>`. CLA 84 = secure messaging.
     Host Cryptogram = CMAC(S-MAC, derivation_data). Card verifies cryptogram; on success the channel is opened (e.g. SecLevel 0x33 = C-MAC + C-DECRYPT + R-MAC + R-ENCRYPT).

3. Registry Discovery (GET STATUS - 80 F2) (GPCS 11.3)
   The GP Registry maps Executable Load Files (ELF), Executable Modules (EM), and Applications to lifecycles.
   - APDU: `80 F2 <P1> <P2> <Lc> <Search_Criteria>`. Search_Criteria often Tag 4F (AID) with length 00 for first/next.
   - P1 (Target): 0x80 = Issuer Security Domain / Card, 0x40 = Applications, 0x20 = Load File Data, 0x10 = Executable Load File and Executable Module.
   - P2 (Sequence): 0x00 = initial block; 0x01 (or next) = subsequent block. SW 63 10 = more data (increment P2).
   - Response (Tag E3): Per-entry: AID (Tag 4F), Lifecycle State (Tag 9F70), Privileges (Tag C5). State: 00=LOADED, 01=OP_READY, 03=INSTALLED, 07=SELECTABLE, 0F=PERSONALIZED, 80=LOCKED, 83=TERMINATED.

4. GET DATA (80 CA) vs GET STATUS
   GET DATA retrieves data objects from the current application/SD; GET STATUS retrieves registry entries.
   - GET DATA: `80 CA <P1> <P2> [<Lc> <Tag_List>]`. P1|P2 = tag (e.g. 00 E0 = Key Information Template, 9F 7F = CPLC).
   - Key Information Template (00 E0): returns key version, ID, type, length for each key in the SD.

5. Object State Transitions (SET STATUS - 80 F0) (GPCS 11.10)
   Transitions lifecycle state of registry objects. Some transitions are irreversible (e.g. TERMINATED).
   - APDU: `80 F0 <P1> <P2> <Lc> [Target_AID]`. P1 = target: 0x80 (ISD/Card), 0x40 (Application), 0x20 (Load File). P2 = new state (e.g. 0x07 Selectable, 0x80 Locked).

6. Key Rotation & Wrapping (PUT KEY - 80 D8) (GPCS 11.8)
   Static keys in the SD are updated via PUT KEY. Key material is encrypted (wrapped) so it is never sent in clear.
   - APDU: `80 D8 <P1_Old_KVN> <P2_Key_ID> <Lc> <KeyData>`. P1=00 provisions a new KVN.
   - Key block (per key): Key Type (88=AES, 81/82/83=DES), Key Length (10/18/20 for AES), Encrypted Key (DEK-wrapped), KCV Length (03), KCV (e.g. first 3 bytes of AES-ECB(key, 0x01..01)).
   - DEK: The Data Encryption Key (K-DEK) is used to wrap key material (e.g. AES-ECB per GPCS). Session keys are derived from K-ENC/K-MAC only.

7. Data Personalization (STORE DATA - 80 E2) (GPCS 11.11)
   Pushes Data Grouping Identifiers (DGIs) or TLVs into the SD/Application. Multi-block: use P2 block number.
   - APDU: `80 E2 <P1> <P2> <Lc> <Data>`. P1: 0x00 = more blocks, 0x80 = last block. P2 = block number (00, 01, 02...).
   - DGI (Tag 90): Personalization data in TLV form; e.g. Tag 4F (ISD AID), Tag 66 (Card Recognition Data).

8. Logical Channels (MANAGE CHANNEL - 00 70) (ISO 7816-4)
   Multiple applications can be active without closing the secure channel. Basic channel = 0.
   - Open: `00 70 00 00 01`. Response data contains the new channel number.
   - Close: `00 70 80 <Channel_Number> 00`.
   - CLA: For extended length and channel: CLA = 0x00 | (channel & 0x03). Commands on that channel use this CLA.


[Press Enter to return to shell]: [!] Command Execution Error: EOF when reading a line
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `HELP` — PASS

- Category:        system
- Script:          `tests/live_scp03/HELP.in.txt`
- Started at:      2026-04-27T06:45:08.078258+00:00
- Elapsed:         0.834 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['YggdraSIM Command Reference', 'Session & Card Info']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Print the SCP03 command reference.
HELP
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.

=== YggdraSIM Command Reference ===
Note: Admin secure channel support now includes SCP03 and SCP02 for Security Domain authentication. SCP11 provisioning and relay flows live in the dedicated SCP11 modules.

[ Session & Card Info ]
  AUTH-SD        : Legacy alias for SCP03-SD.
  SCP03-SD       : Authenticate with Security Domain using SCP03.
  SCP02-SD       : Authenticate with Security Domain using SCP02.
  RESET          : Reset the card connection (ATR).
  INFO           : Print card specifications (ATR, ICCID, eID, SGP version).
  ATR            : Reset and print a parsed ATR breakdown.
  KEYS [AID]     : Retrieve key information for current or specified AID.
  LOGOUT         : Close the secure session.
  CLS            : Clear the terminal screen.
  OTA            : Switch to SCP80 Over-The-Air toolkit.
  STK [Commands] : Enter the SCP03 STK subsystem (INIT/SMS/CALL/DATA simulation shell).

[ GlobalPlatform Execution Wizards ]
  WIZARD         : Unified installer for Applets, Packages, and Extradition.
  PUT-KEY        : Rotate, add, or replace cryptographic keys.
  SET-STATUS     : Modify lifecycle state of Card, Applet, or Load File.
  MANAGE-CHANNEL : Open or close logical channels.
  GET-DATA       : Retrieve registry (APPS/PKGS/SD), CPLC, or custom tags.
  APPS           : Shortcut to retrieve Applications registry.
  PKGS           : Shortcut to retrieve Packages registry.
  SD             : Shortcut to retrieve Security Domains registry.
  LOCK <AID>     : Shortcut to set state to LOCKED (0x80).
  UNLOCK <AID>   : Shortcut to set state to SELECTABLE (0x07).
  DEL <AID>      : Shortcut to delete an object.
  STORE-DATA     : <Hex> [P1] [P2] - Send raw STORE DATA payload.

[ Telecom & eSIM (SGP.22 / SGP.32 / SGP.02) - retrieval + local profile state ]
  LIST           : List eSIM profiles (GetProfilesInfo, SGP.22/SGP.32).
  MANAGE-PROFILE : Spec-aware wizard with separate SGP.22, SGP.32, and SGP.02 command sets.
                   Local STORE DATA reads retry via base channel, then logical channel 1, then STK mode.
  RUN-AUTH       : Execute GSM, USIM, or ISIM authentication algorithms.
  RUN-AUTH-TEST  : Run offline 3GPP TS 35.207 Milenage vector validation.
  DERIVE-OPC     : <Ki_hex> <OP_hex> - Derive OPc per 3GPP TS 35.206.

[ SCP11 module map ]
  Main menu [3]  : SCP11 live relay shell (LPAd/IPAd/IPAe).
  Main menu [4]  : SCP11 test relay shell (LPAd/IPAd).
  Main menu [5]  : SCP11 local access shell (LOAD-PROFILE workflow).

[ Security & PIN Management ]
  MANAGE-PIN     : Unified wizard to Verify, Change, Enable, Disable, or Unblock PINs.

[ Environment Configuration ]
  CONFIG         : Wizard to update SCP03 keys, SCP02 keys, ADM, or Target AID.
  SHOW           : Display current SQLite-backed SCP03 configuration.
  AIDS           : List registered AID aliases from `Workspace/SCP03/aid.txt`.
  SET-AID-ALIAS  : <Name> <AID> - Map a friendly name to an AID.
  SET-DEFAULT    : Factory reset configuration to default test keys.
  BINDS          : Manage custom macro commands and parameters.

[ File System Operations ]
  SCAN           : Traverse and discover the UICC file tree.
  REPORT         : Unified report wizard (FS dump, FS YAML, eUICC YAML, or combined FS+eUICC YAML).
  SET-GOLD-PROFILE: <path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|N] - Persist gold combined YAML path in SQLite state for PROFILE-DIFF.
  GOLD-PROFILE   : Show persisted gold path, GSMA standard, and SD-auth flag.
  CLEAR-GOLD-PROFILE: Clear the persisted path (keeps standard/auth keys).
  PROFILE-DIFF   : [gold.yaml] [STANDARD] [AUTH=Y|N] - Capture live FS+eUICC+MNO-SD and diff vs gold (timestamps stripped).
  VALIDATE       : [ALL|MF|USIM|ISIM] [ProfileDump.yaml|ProfileDump.json] - Validate active profile FS structure against the profile interoperability spec.
  SELECT         : <Path/FID> - Select a DF or EF.
  READ [Path]    : Read binary data from the selected EF.
  RECORD         : <N/ALL/Start-End> [Path] - Read record(s) from a linear fixed/cyclic EF.
  UPDATE         : BINARY <Hex> | RECORD <N> <Hex> - Write data to an EF.
  FS-ADMIN       : Administrative tasks (Activate, Delete, Create, Terminate, Resize).

[ System & Developer ]
  GUIDE [Topic]  : Show documentation (Topics: GP, ETSI, GSMA, INSTALL, SECURITY, OTA, CONFIG, SAIP, SUCI, CLI).
  DECODE         : <Hex> - Parse and decode a raw BER-TLV string.
  RUN / SCRIPT   : <File> [Out.yaml] - Execute a batch script of APDU commands.
  EXPORT-KEYBAG  : [Path.keys.json] [Label] - Dump active SCP03 session keys for HIL offline replay.
  DEBUG/VERBOSE  : Toggle raw APDU hex transmission logging.
  HELP           : Display this menu.
  EXIT / Q       : Disconnect reader and leave SCP03 shell.
  QA             : Disconnect reader and exit YggdraSIM.
==========================================

```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `CONFIG` — PASS

- Category:        wizard
- Script:          `tests/live_scp03/CONFIG.in.txt`
- Started at:      2026-04-27T06:45:08.912339+00:00
- Elapsed:         0.812 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Environment Configuration', 'EOF when reading a line']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# CONFIG is the keyset/AID rotation wizard. Sends EOF immediately after
# invocation.
CONFIG
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.

--- Environment Configuration ---
> Update [1=SCP03 ENC, 2=SCP03 MAC, 3=SCP03 DEK, 4=SCP03 KVN, 5=SCP02 ENC, 6=SCP02 MAC, 7=SCP02 DEK, 8=SCP02 KVN, 9=ADM, 10=AID]: [!] Command Execution Error: EOF when reading a line
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `BINDS` — PASS

- Category:        wizard
- Script:          `tests/live_scp03/BINDS.in.txt`
- Started at:      2026-04-27T06:45:09.724485+00:00
- Elapsed:         0.816 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['Binder engine']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# BINDS opens the macro/binds manager. Sends EOF immediately after
# invocation.
BINDS
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[!] Binder engine not initialized.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `RUN` — PASS

- Category:        script
- Script:          `tests/live_scp03/RUN.in.txt`
- Started at:      2026-04-27T06:45:10.540502+00:00
- Elapsed:         0.83 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['[SCRIPT:', 'Command Reference']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Run a batch script. The runner generates reports/scp03_live_run/run.script
# with HELP/EXIT lines before invoking this test, so we can verify the
# scripted dispatch path end-to-end.
RUN reports/scp03_live_run/run.script
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[*] Running script: reports/scp03_live_run/run.script

[SCRIPT:1] > HELP

=== YggdraSIM Command Reference ===
Note: Admin secure channel support now includes SCP03 and SCP02 for Security Domain authentication. SCP11 provisioning and relay flows live in the dedicated SCP11 modules.

[ Session & Card Info ]
  AUTH-SD        : Legacy alias for SCP03-SD.
  SCP03-SD       : Authenticate with Security Domain using SCP03.
  SCP02-SD       : Authenticate with Security Domain using SCP02.
  RESET          : Reset the card connection (ATR).
  INFO           : Print card specifications (ATR, ICCID, eID, SGP version).
  ATR            : Reset and print a parsed ATR breakdown.
  KEYS [AID]     : Retrieve key information for current or specified AID.
  LOGOUT         : Close the secure session.
  CLS            : Clear the terminal screen.
  OTA            : Switch to SCP80 Over-The-Air toolkit.
  STK [Commands] : Enter the SCP03 STK subsystem (INIT/SMS/CALL/DATA simulation shell).

[ GlobalPlatform Execution Wizards ]
  WIZARD         : Unified installer for Applets, Packages, and Extradition.
  PUT-KEY        : Rotate, add, or replace cryptographic keys.
  SET-STATUS     : Modify lifecycle state of Card, Applet, or Load File.
  MANAGE-CHANNEL : Open or close logical channels.
  GET-DATA       : Retrieve registry (APPS/PKGS/SD), CPLC, or custom tags.
  APPS           : Shortcut to retrieve Applications registry.
  PKGS           : Shortcut to retrieve Packages registry.
  SD             : Shortcut to retrieve Security Domains registry.
  LOCK <AID>     : Shortcut to set state to LOCKED (0x80).
  UNLOCK <AID>   : Shortcut to set state to SELECTABLE (0x07).
  DEL <AID>      : Shortcut to delete an object.
  STORE-DATA     : <Hex> [P1] [P2] - Send raw STORE DATA payload.

[ Telecom & eSIM (SGP.22 / SGP.32 / SGP.02) - retrieval + local profile state ]
  LIST           : List eSIM profiles (GetProfilesInfo, SGP.22/SGP.32).
  MANAGE-PROFILE : Spec-aware wizard with separate SGP.22, SGP.32, and SGP.02 command sets.
                   Local STORE DATA reads retry via base channel, then logical channel 1, then STK mode.
  RUN-AUTH       : Execute GSM, USIM, or ISIM authentication algorithms.
  RUN-AUTH-TEST  : Run offline 3GPP TS 35.207 Milenage vector validation.
  DERIVE-OPC     : <Ki_hex> <OP_hex> - Derive OPc per 3GPP TS 35.206.

[ SCP11 module map ]
  Main menu [3]  : SCP11 live relay shell (LPAd/IPAd/IPAe).
  Main menu [4]  : SCP11 test relay shell (LPAd/IPAd).
  Main menu [5]  : SCP11 local access shell (LOAD-PROFILE workflow).

[ Security & PIN Management ]
  MANAGE-PIN     : Unified wizard to Verify, Change, Enable, Disable, or Unblock PINs.

[ Environment Configuration ]
  CONFIG         : Wizard to update SCP03 keys, SCP02 keys, ADM, or Target AID.
  SHOW           : Display current SQLite-backed SCP03 configuration.
  AIDS           : List registered AID aliases from `Workspace/SCP03/aid.txt`.
  SET-AID-ALIAS  : <Name> <AID> - Map a friendly name to an AID.
  SET-DEFAULT    : Factory reset configuration to default test keys.
  BINDS          : Manage custom macro commands and parameters.

[ File System Operations ]
  SCAN           : Traverse and discover the UICC file tree.
  REPORT         : Unified report wizard (FS dump, FS YAML, eUICC YAML, or combined FS+eUICC YAML).
  SET-GOLD-PROFILE: <path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|N] - Persist gold combined YAML path in SQLite state for PROFILE-DIFF.
  GOLD-PROFILE   : Show persisted gold path, GSMA standard, and SD-auth flag.
  CLEAR-GOLD-PROFILE: Clear the persisted path (keeps standard/auth keys).
  PROFILE-DIFF   : [gold.yaml] [STANDARD] [AUTH=Y|N] - Capture live FS+eUICC+MNO-SD and diff vs gold (timestamps stripped).
  VALIDATE       : [ALL|MF|USIM|ISIM] [ProfileDump.yaml|ProfileDump.json] - Validate active profile FS structure against the profile interoperability spec.
  SELECT         : <Path/FID> - Select a DF or EF.
  READ [Path]    : Read binary data from the selected EF.
  RECORD         : <N/ALL/Start-End> [Path] - Read record(s) from a linear fixed/cyclic EF.
  UPDATE         : BINARY <Hex> | RECORD <N> <Hex> - Write data to an EF.
  FS-ADMIN       : Administrative tasks (Activate, Delete, Create, Terminate, Resize).

[ System & Developer ]
  GUIDE [Topic]  : Show documentation (Topics: GP, ETSI, GSMA, INSTALL, SECURITY, OTA, CONFIG, SAIP, SUCI, CLI).
  DECODE         : <Hex> - Parse and decode a raw BER-TLV string.
  RUN / SCRIPT   : <File> [Out.yaml] - Execute a batch script of APDU commands.
  EXPORT-KEYBAG  : [Path.keys.json] [Label] - Dump active SCP03 session keys for HIL offline replay.
  DEBUG/VERBOSE  : Toggle raw APDU hex transmission logging.
  HELP           : Display this menu.
  EXIT / Q       : Disconnect reader and leave SCP03 shell.
  QA             : Disconnect reader and exit YggdraSIM.
==========================================


[SCRIPT:2] > EXIT
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `SCRIPT` — PASS

- Category:        script
- Script:          `tests/live_scp03/SCRIPT.in.txt`
- Started at:      2026-04-27T06:45:11.370845+00:00
- Elapsed:         0.819 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['[SCRIPT:', 'Command Reference']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Same as RUN, but invoked through the SCRIPT alias.
SCRIPT reports/scp03_live_run/run.script
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[*] Running script: reports/scp03_live_run/run.script

[SCRIPT:1] > HELP

=== YggdraSIM Command Reference ===
Note: Admin secure channel support now includes SCP03 and SCP02 for Security Domain authentication. SCP11 provisioning and relay flows live in the dedicated SCP11 modules.

[ Session & Card Info ]
  AUTH-SD        : Legacy alias for SCP03-SD.
  SCP03-SD       : Authenticate with Security Domain using SCP03.
  SCP02-SD       : Authenticate with Security Domain using SCP02.
  RESET          : Reset the card connection (ATR).
  INFO           : Print card specifications (ATR, ICCID, eID, SGP version).
  ATR            : Reset and print a parsed ATR breakdown.
  KEYS [AID]     : Retrieve key information for current or specified AID.
  LOGOUT         : Close the secure session.
  CLS            : Clear the terminal screen.
  OTA            : Switch to SCP80 Over-The-Air toolkit.
  STK [Commands] : Enter the SCP03 STK subsystem (INIT/SMS/CALL/DATA simulation shell).

[ GlobalPlatform Execution Wizards ]
  WIZARD         : Unified installer for Applets, Packages, and Extradition.
  PUT-KEY        : Rotate, add, or replace cryptographic keys.
  SET-STATUS     : Modify lifecycle state of Card, Applet, or Load File.
  MANAGE-CHANNEL : Open or close logical channels.
  GET-DATA       : Retrieve registry (APPS/PKGS/SD), CPLC, or custom tags.
  APPS           : Shortcut to retrieve Applications registry.
  PKGS           : Shortcut to retrieve Packages registry.
  SD             : Shortcut to retrieve Security Domains registry.
  LOCK <AID>     : Shortcut to set state to LOCKED (0x80).
  UNLOCK <AID>   : Shortcut to set state to SELECTABLE (0x07).
  DEL <AID>      : Shortcut to delete an object.
  STORE-DATA     : <Hex> [P1] [P2] - Send raw STORE DATA payload.

[ Telecom & eSIM (SGP.22 / SGP.32 / SGP.02) - retrieval + local profile state ]
  LIST           : List eSIM profiles (GetProfilesInfo, SGP.22/SGP.32).
  MANAGE-PROFILE : Spec-aware wizard with separate SGP.22, SGP.32, and SGP.02 command sets.
                   Local STORE DATA reads retry via base channel, then logical channel 1, then STK mode.
  RUN-AUTH       : Execute GSM, USIM, or ISIM authentication algorithms.
  RUN-AUTH-TEST  : Run offline 3GPP TS 35.207 Milenage vector validation.
  DERIVE-OPC     : <Ki_hex> <OP_hex> - Derive OPc per 3GPP TS 35.206.

[ SCP11 module map ]
  Main menu [3]  : SCP11 live relay shell (LPAd/IPAd/IPAe).
  Main menu [4]  : SCP11 test relay shell (LPAd/IPAd).
  Main menu [5]  : SCP11 local access shell (LOAD-PROFILE workflow).

[ Security & PIN Management ]
  MANAGE-PIN     : Unified wizard to Verify, Change, Enable, Disable, or Unblock PINs.

[ Environment Configuration ]
  CONFIG         : Wizard to update SCP03 keys, SCP02 keys, ADM, or Target AID.
  SHOW           : Display current SQLite-backed SCP03 configuration.
  AIDS           : List registered AID aliases from `Workspace/SCP03/aid.txt`.
  SET-AID-ALIAS  : <Name> <AID> - Map a friendly name to an AID.
  SET-DEFAULT    : Factory reset configuration to default test keys.
  BINDS          : Manage custom macro commands and parameters.

[ File System Operations ]
  SCAN           : Traverse and discover the UICC file tree.
  REPORT         : Unified report wizard (FS dump, FS YAML, eUICC YAML, or combined FS+eUICC YAML).
  SET-GOLD-PROFILE: <path> [SGP.32|SGP.22|SGP.02] [AUTH=Y|N] - Persist gold combined YAML path in SQLite state for PROFILE-DIFF.
  GOLD-PROFILE   : Show persisted gold path, GSMA standard, and SD-auth flag.
  CLEAR-GOLD-PROFILE: Clear the persisted path (keeps standard/auth keys).
  PROFILE-DIFF   : [gold.yaml] [STANDARD] [AUTH=Y|N] - Capture live FS+eUICC+MNO-SD and diff vs gold (timestamps stripped).
  VALIDATE       : [ALL|MF|USIM|ISIM] [ProfileDump.yaml|ProfileDump.json] - Validate active profile FS structure against the profile interoperability spec.
  SELECT         : <Path/FID> - Select a DF or EF.
  READ [Path]    : Read binary data from the selected EF.
  RECORD         : <N/ALL/Start-End> [Path] - Read record(s) from a linear fixed/cyclic EF.
  UPDATE         : BINARY <Hex> | RECORD <N> <Hex> - Write data to an EF.
  FS-ADMIN       : Administrative tasks (Activate, Delete, Create, Terminate, Resize).

[ System & Developer ]
  GUIDE [Topic]  : Show documentation (Topics: GP, ETSI, GSMA, INSTALL, SECURITY, OTA, CONFIG, SAIP, SUCI, CLI).
  DECODE         : <Hex> - Parse and decode a raw BER-TLV string.
  RUN / SCRIPT   : <File> [Out.yaml] - Execute a batch script of APDU commands.
  EXPORT-KEYBAG  : [Path.keys.json] [Label] - Dump active SCP03 session keys for HIL offline replay.
  DEBUG/VERBOSE  : Toggle raw APDU hex transmission logging.
  HELP           : Display this menu.
  EXIT / Q       : Disconnect reader and leave SCP03 shell.
  QA             : Disconnect reader and exit YggdraSIM.
==========================================


[SCRIPT:2] > EXIT
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `DEBUG` — PASS

- Category:        system
- Script:          `tests/live_scp03/DEBUG.in.txt`
- Started at:      2026-04-27T06:45:12.190165+00:00
- Elapsed:         0.826 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['VERBOSE / DEBUG Mode is now ON', 'VERBOSE / DEBUG Mode is now OFF']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Toggle raw APDU hex transmission logging on, then off again.
DEBUG
DEBUG
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[*] VERBOSE / DEBUG Mode is now OFF.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `VERBOSE` — PASS

- Category:        system
- Script:          `tests/live_scp03/VERBOSE.in.txt`
- Started at:      2026-04-27T06:45:13.016609+00:00
- Elapsed:         0.817 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   ['VERBOSE / DEBUG Mode is now ON', 'VERBOSE / DEBUG Mode is now OFF']
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# VERBOSE alias of DEBUG. Toggle on/off.
VERBOSE
VERBOSE
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
[*] VERBOSE / DEBUG Mode is now OFF.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `EXIT` — PASS

- Category:        lifecycle
- Script:          `tests/live_scp03/EXIT.in.txt`
- Started at:      2026-04-27T06:45:13.833274+00:00
- Elapsed:         0.819 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   —
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Single-command session: just leave the shell.
EXIT
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `Q` — PASS

- Category:        lifecycle
- Script:          `tests/live_scp03/Q.in.txt`
- Started at:      2026-04-27T06:45:14.652287+00:00
- Elapsed:         0.813 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   —
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# Q alias of EXIT.
Q
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```

### `QA` — PASS

- Category:        lifecycle
- Script:          `tests/live_scp03/QA.in.txt`
- Started at:      2026-04-27T06:45:15.465883+00:00
- Elapsed:         0.812 s
- Exit code:       0
- Timed out:       False
- SWs observed:    —
- Expected SW:     —
- Expected SW any: —
- Expected text:   —
- SW assertion:    pass
- Text assertion:  pass
- Exit assertion:  pass

Stdin script:

```
# QA raises QuitAllRequested. The SCP03 __main__ catches it and exits 0,
# so the runner accepts a clean exit here.
QA
```

Stdout (ANSI stripped):

```
[*] CONNECTED
[*] VERBOSE / DEBUG Mode is now ON.
```

Stderr (ANSI stripped):

```
[SCP03] WARNING: shipped demo keys active for slots: scp03_kenc, scp03_kmac, scp03_dek, scp02_enc, scp02_mac, scp02_dek. Never use these against a real card. Set YGGDRASIM_ALLOW_DEMO_KEYS=1 to silence this warning, or YGGDRASIM_REQUIRE_NON_DEMO_KEYS=1 to fail fast when placeholders are present.
```
