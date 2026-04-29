# SIMCARD module pre-v1 review

> **Status note (post-v1, 2026)**: this document is the snapshot taken
> immediately before the v1 tag. The bug list below (B-01..B-12) was
> the gating set for v1.0 closure; subsequent fixes and the post-v1
> 5G-AKA / AKMA / SUCI / `GET IDENTITY` extensions live in
> `SIMCARD/aka_5g.py`, `SIMCARD/akma.py`, `SIMCARD/suci.py`, and
> `SIMCARD/identity.py` and are tracked separately. New bugs found
> after v1 should be filed in `V2_ROADMAP.md` (or, if scoped narrowly,
> `NEW_FEATURE_IDEAS.md`) rather than appended here.

Scope: `SIMCARD/` (simulated ICC/eUICC engine). Cross-checked against:

- ETSI TS 102 221 v17.2.0 — UICC-Terminal interface
- ETSI TS 102 223 v17.1.0 — Card Application Toolkit (CAT)
- 3GPP TS 31.102 v17 — USIM application
- 3GPP TS 33.102 Annex B–C — Milenage c2/c3 conversions, SQN
- 3GPP TS 35.206 Annex 3 — Milenage core
- 3GPP TS 35.231 / 35.232 / 35.233 — TUAK spec + test sets
- GlobalPlatform Card Spec v2.3.1 + Amendment D — SCP03
- GSMA SGP.22 / SGP.32 — eUICC RSP / IoT eUICC
- ISO 7816-4 §7 — MANAGE CHANNEL, SELECT FILE

Golden reference used: **HID OMNIKEY 3x21 + inserted USIM** (ATR
`3B9F96803F87828031E073FE211F67455475323008653D`). Live APDU sequence
captured via a guarded compare script (kept off-repo; located at
`/tmp/ygg-golden/compare.py`).

## 1. Test state at the time of the review

| Target                                   | Tests | Result |
|------------------------------------------|------:|--------|
| `tests/test_simcard_tuak_kat.py`         | 12    | PASS   |
| `tests/test_simcard_auth_toolkit.py`     | 8     | PASS   |
| `tests/test_simcard_es10c_surface.py`    | 10    | PASS   |
| `tests/test_simcard_toolkit_poll_bridge.py` | 1  | PASS   |
| `tests/test_simcard_backend.py` (48 cases) | 48  | PASS   |

No failing node ids. TUAK implementation is byte-exact against TS 35.232
test set 1. Milenage c2/c3 code-paths are covered by
`test_simcard_auth_toolkit.py`.

## 2. Golden-card vs. simulator APDU delta (live capture)

APDUs issued to both a live USIM and the in-process simulator. Abridged:

| Label                         | Real card | Simulator     | Note                                   |
|-------------------------------|-----------|---------------|----------------------------------------|
| SELECT MF (3F00) by FID       | `61 2B`   | `9000` + FCP  | T=0 vs. T=1 shape — expected          |
| SELECT MF P1=0x08 (path)      | `61 2B`   | `9000` + FCP  | Simulator ignores P1 (see B-01)        |
| SELECT MF P2=0x0C (no resp.)  | `9000`    | `9000` + FCP  | Simulator ignores P2 (see B-01)        |
| SELECT EF.ICCID by FID        | `61 18`   | `9000` + FCP  | OK                                     |
| READ BIN EF.ICCID Le=0A       | `9000`+10B| `9000`+10B    | Shape match, payloads differ (data)    |
| STATUS `80F20000`             | `6C 2B`   | `9000`        | Sim routes P1=0x00 to STK; see B-05    |
| GET DATA `80CA9F7F`           | `6D 00`   | `6A 88`       | Different SW, both "no data" (B-07)    |
| MANAGE CHANNEL open Le=0      | `6C 01`   | `9000`+01     | Sim does not advertise Le (B-06)       |
| SELECT ADF.USIM wrong AID     | `6A 82`   | `6A 82`       | MATCH                                  |

Aggregate: 0 false-positives (sim never says 9000 when real returns
`6A xx`); 1 missing status-class signal (B-05); 2 ISO 7816-3 protocol
shape differences that are purely T=0 vs. T=1 and expected behaviour for
a software-emulated T=1 card.

## 3. Bugs and spec divergences

Severity: **B** = blocker for v1, **H** = high, **M** = medium, **L** =
low, **N** = nice-to-have.

### B-01 [H] `SELECT` does not honour P1/P2

`SIMCARD/engine.py:182`:

```python
if ins == 0xA4:
    return self.fs.select(data)
```

The dispatch throws away P1 and P2. ETSI TS 102 221 §11.1.1 defines:

| P1     | Selection target                   |
|--------|------------------------------------|
| `0x00` | MF, DF or EF by FID (default)      |
| `0x01` | Child DF under current DF          |
| `0x02` | EF under current DF                |
| `0x03` | Parent DF of current DF            |
| `0x04` | By DF name (AID), incl. partial    |
| `0x08` | Path from MF                       |
| `0x09` | Path from current DF               |

P2 low-nibble gates the response template:

| P2     | Response body         |
|--------|------------------------|
| `0x00` | FCI (tag 6F)          |
| `0x04` | FCP (tag 62)          |
| `0x08` | FMD (tag 64)          |
| `0x0C` | No response data      |

`EtsiFileSystem.select` at `SIMCARD/etsi_fs.py:824` currently only
discriminates `len(selector) == 2` (FID) vs `else` (AID). Path-based
SELECT (`08 3F 00 7F FF 6F 07`) is silently misinterpreted as AID and
returns `6A 82`. Partial-AID selection, parent-DF selection (P1=0x03)
and FMD retrieval (P2=0x08) are unsupported.

**Observed impact**: real RSP stacks and legacy MNO test tools use
`SELECT P2=0x04` extensively to pull FCP without FCI wrapping. Today
the simulator always returns the same FCP-in-FCI hybrid, and
`golden-card no-response SELECT (P2=0x0C)` returns 10 bytes of data the
real card does not emit.

### B-02 [M] `READ BINARY` ignores SFI addressing

`SIMCARD/engine.py:183-185`:

```python
if ins == 0xB0:
    offset = (p1 << 8) | p2
    return self.fs.read_binary(offset=offset, le=le_value)
```

ETSI TS 102 221 §11.1.3: when P1 bit 8 is 1, P1[5:0] is the SFI and P2 is
the byte offset (0..255). The simulator treats the SFI byte as the high
byte of the offset, which pushes `offset` beyond the file size and
returns `6B 00`. EF.ICCID (SFI 0x02) and EF.DIR (SFI 0x1E) both expose
SFI-addressable reads in production, and several BIP/OTA stacks use SFI
reads to avoid the SELECT round-trip.

### B-03 [M] `READ RECORD` ignores P2 mode bits

`SIMCARD/engine.py:186-187`:

```python
if ins == 0xB2:
    return self.fs.read_record(record_number=p1, le=le_value)
```

ETSI TS 102 221 §11.1.5 P2 encodes:

- Bits 7..3 = SFI (when non-zero)
- Bits 2..0 = mode: `0x02` next, `0x03` previous, `0x04` absolute,
  `0x05` from start, `0x06` next cyclic, `0x07` previous cyclic.

The simulator assumes absolute (P2 `0x04`) unconditionally. Next/previous
record iteration against EF.SMS, EF.MSISDN, EF.PLMNwAcT and similar
linear-fixed EFs will therefore return wrong records without any error
indication.

### B-04 [H] No CLA class check anywhere in the dispatcher

`SIMCARD/engine.py:172-232` only reads CLA bits 7..6 (via `cla & 0x80`)
for a few commands. Real ISO 7816 cards reject unknown CLAs with
`6E 00`. A caller issuing `DE A4 00 04 02 3F 00` (invalid CLA, valid
INS=A4) gets a successful SELECT today instead of `6E 00`. This is the
main reason the `except Exception → 6F 00` fallback exists as a safety
net; a proper CLA filter would make the fallback unreachable.

### B-05 [M] `80 F2 00 00` STATUS is always routed to toolkit handler

`SIMCARD/engine.py:205-217`:

```python
is_gp_status = p1 not in (0x00, 0x01)
if (cla & 0x80) and self.toolkit.should_handle_status() and is_gp_status is False:
    return self.toolkit.handle_status(p1, p2, data)
```

Per GP Card Spec v2.3.1 §11.4.2, `GET STATUS` P1 values are `0x80`
(ISD), `0x40` (Applications/SSD), `0x20` (ELF), `0x10`
(ELF+Modules), `0x02` (ISD default). The current `is_gp_status = p1 not in
(0x00, 0x01)` heuristic is largely correct, but does **not** cover the
CLA-agnostic diagnostic `80 F2 00 00` that terminals emit during cold
insertion to distinguish STK-capable from non-STK cards. Expected SW
without proactive state is `91 00` or `6C xx`; the simulator replies
`9000` with no payload, which a real modem cannot disambiguate from
"no STK support".

### B-06 [L] `MANAGE CHANNEL` does not honour Le

`SIMCARD/engine.py:234-261`. Open-channel returns a 1-byte channel id
with `9000` but never consults Le. Real cards emit `6C 01` on a Case 2S
call with Le=0 so the terminal can re-issue with Le=0x01. Without this
some T=0 libraries loop or error out. Low impact in a T=1 simulator but
worth gating.

### B-07 [L] `GET DATA` for unknown tags returns `6A 88` instead of `6D 00`

`SIMCARD/gp.py:handle_get_data` → `6A 88` (Referenced data not found)
for every tag outside its allowlist. GP v2.3.1 §11.3 uses `6A 88` for
"tag understood but data not present" and `6A 80` / `6A 81` for other
errors. For a tag the card does not understand (`80 CA 9F 7F` on
non-ISD context) real cards return `6D 00`. Minor SW taxonomy gap.

### B-08 [M] SCP03 `i`-byte value and sequence-counter branch

`SIMCARD/scp03.py:64-70`:

```python
i_parameter = 0x03
key_info = bytes([expected_kvn, 0x03, i_parameter])
response = (b"\x00" * 10) + key_info + card_challenge + card_cryptogram
if (i_parameter & 0x10) == 0:
    self.state.scp03_sequence_counter = (...)
    response += self.state.scp03_sequence_counter.to_bytes(3, "big")
```

GP Amd D §7.1.1.4.3 states that the 3-byte sequence counter SHALL be
appended **only** when the pseudo-random card challenge option is in
use — in the v1.1.1/v1.2 i-byte table, bit b3 (value `0x04`) selects
pseudo-random. The code conditions on `i & 0x10` (bit b5, the R-MAC
support bit in v1.2 / R-ENCRYPTION in v1.1.1). Additionally, the chosen
`i_parameter = 0x03` sets bits b1 and b2 which are both RFU in
published versions of Amd D.

The host-side implementation at `SCP03/crypto/session.py` reads the card
challenge at offset `[13:21]` which only matches the simulator's layout
if the counter bytes land *after* the cryptogram, so the
mutual wire format is internally consistent. Against a real SGP.22 eUICC
the card will either omit or include the counter depending on the
actual `i` it advertises, and the host parser will silently misread
offset 21+ bytes in the non-matching case.

**Verification requested before changing**: run a `list_gp_keys` /
`INITIALIZE UPDATE` trace against a production eUICC (you have one
on the OMNIKEY) to confirm the expected `i` byte value and counter
presence, then align the simulator and the host parser.

### B-09 [L] Broad `except Exception → 6F 00`

`SIMCARD/engine.py:163-164`. Acceptable as an outer guard against bugs in
quirks or SGP paths, but the coding standard requires exceptions to be
logged or narrowed. Recommend: capture exception to `state.apdu_history`
or a bounded fault ring and re-raise in a debug mode (env
`YGGDRASIM_SIMCARD_DEBUG=1`).

### B-10 [L] `scp03.is_wrapped_command` relies solely on CLA bit 2

`SIMCARD/scp03.py:31-41`. GP v2.3.1 §11.1.4 says CLA bit 2 indicates
C-MAC present, and bit 3 indicates C-DECRYPTION. The current check
forces MAC-wrap semantics on any authenticated APDU whose CLA has bit 2
set even when the host deliberately issues a plaintext APDU (ClearC-APDU
case during `DELETE`-key workflows). Rare, but will block legitimate GP
flows. Consider `bool((command[0] & 0x0C) != 0 and session.security_level
& 0x03)`.

### B-11 [L] `parse_apdu` case-4S trailing Le tolerance

`SIMCARD/utils.py:207-210`: when Lc byte says `n`, the parser tolerates
`len(body) > 1 + lc` and picks the *last* trailing byte as Le. A real
card rejects ill-formed APDUs with `67 00`. Impact: fuzzing drops a
malformed frame on the card and sees `9000` when it should see `67 00`.

### B-12 [N] Simulator ATR is synthetic

`SIMCARD/state.py:7`: ATR
`3B9F96801FC78031A073BE21136743200718000001A5`. 15 historical bytes
(led by the ISO 7816-4 `80 31` category indicator + COMPACT-TLV),
TCK=0xA5 verified against `XOR(T0..lastHist)`. The shape is now
ISO 7816-3 §8.2 conformant; the content still does not reflect an
actual eUICC ATR (no SGP.22 `Card Capabilities` historical byte, no
EUM-specific OS marker string). Cosmetic from a v1 review angle,
but hoisting the ATR to a quirks override default that mirrors the
golden card would make HIL-bridge tests deterministic.

NB: an earlier draft of the constant was 20 bytes — it lost the
`80 31` prefix and shipped with no TCK at all. Real modems behind
the HIL bridge (SIMtrace2 + osmo-remsim-client-st2) timed out the
ATR sequence and refused to issue any APDU on cold boot.

## 4. Non-divergences (explicitly OK)

- **Milenage c2/c3**: matches TS 33.102 Annex B.3/B.4 byte-for-byte
  (`SIMCARD/auth.py:96-98`).
- **TUAK state layout / INSTANCE / byte reversal / pad `1F…80`**:
  matches TS 35.231 §6 and passes TS 35.232 TS1 KAT
  (`tests/test_simcard_tuak_kat.py`).
- **USIM AUTHENTICATE response TLVs** (`DB 08 … 10 CK 10 IK 08 Kc`,
  AUTS framed as `DC 0E …`): matches TS 31.102 §7.1.2.1.
- **CHV VERIFY / UNBLOCK retry accounting**: matches TS 102 221 §11.1.9
  (`63 Cx` semantics, `6983` on block).
- **SQN window**: minimal `<` check is weaker than the 32-element window
  mandated by TS 33.102 Annex C.2 but adequate for a local simulator.
- **Logical channels**: ISO 7816-4 §7.1.2 compliance for MANAGE CHANNEL
  open/close is correct (`SIMCARD/engine.py:234-261`).
- **STORE DATA block counter (P1=0x11 chaining)**: GP §11.11 compliant.

## 5. Architecture observations (not bugs)

- `SIMCARD/sgp.py` is 2 376 lines. Same flag as `V1_RELEASE_AUDIT.md`
  S-15. Worth splitting into: `sgp/es10c.py`, `sgp/es10b.py`,
  `sgp/bpp.py`, `sgp/metadata.py`. No runtime changes required.
- `SIMCARD/quirks.py:load_quirk_registry` `exec`s user-supplied Python
  from a path. Document the trust model in README / install notes.
  Functionally fine; security-model caveat only.
- `SIMCARD.connection._SHARED_ENGINE` global keeps an engine alive for
  the process lifetime keyed by five path inputs. Reload semantics
  rebuild the engine when any path changes. Document that multiple
  concurrent sessions share state.
- `SimulatedCardConnection.connect` calls `engine.reset()` every time,
  which wipes STK / SCP03 / SGP transient state but keeps persistent
  profile/eUICC store. Intended; worth a comment block in
  `connection.py`.

## 6. Suggested pre-v1 action list

Grouped to allow separate, reviewable commits. None of these require
moving test material or breaking public surface.

1. **B-01**: rewrite `_dispatch` SELECT arm to forward P1/P2; rewrite
   `EtsiFileSystem.select` to branch on P1; add P2 → response-template
   gating in `build_fcp`. Add two tests: one for path-based SELECT,
   one for `P2=0x0C` no-response SELECT.
2. **B-02** + **B-03**: extend `read_binary` and `read_record` signatures
   to take raw P1/P2 and interpret SFI + mode. Add KAT-style tests.
3. **B-04**: add a minimal CLA acceptance list at the top of
   `_dispatch` and return `6E 00` for anything outside it.
4. **B-05**: make `should_handle_status` also require a CLA != 0x80
   or a non-zero P1 before claiming the APDU for STK.
5. **B-06**: honour Le on MANAGE CHANNEL open (`6C 01` when Le=0).
6. **B-07**: narrow `GET DATA` returns to `6D 00` for genuinely
   unknown tags; keep `6A 88` only for tags we understand but lack.
7. **B-08**: capture a real eUICC `INITIALIZE UPDATE` response
   (OMNIKEY + production eUICC you have plugged in), derive the
   expected `i` byte and counter presence, realign both simulator and
   host parser. Do **not** land this without the capture.
8. **B-09**: wire the broad `except Exception` into a bounded fault
   ring surfaced via `state.apdu_history`; gate re-raise behind
   `YGGDRASIM_SIMCARD_DEBUG=1`.
9. **B-10**: tighten `is_wrapped_command` CLA mask to `0x0C`.
10. **B-11**: reject Case-4S APDUs where `len(body) > 1 + lc + 1` with
    `67 00` instead of silently picking the last byte.
11. **B-12** (cosmetic): expose ATR override cleanly from quirks; ship a
    reference `sim_quirks_goldencard.py` that mirrors whatever golden
    eUICC you ship tests against.

## 7. Golden-card harness

`/tmp/ygg-golden/compare.py` is the ad-hoc probe I used. It is **not**
kept in repo. Recommend: move it to `tests/golden/compare_simcard.py`
gated by an env var (e.g. `YGGDRASIM_GOLDEN_READER=1`) so CI skips it
but an operator can run it locally against any reader. That gives us a
single-command regression harness against a physical USIM/eUICC for
every future APDU-surface change.

This compare script issues ≤ 20 Case-1/2 APDUs, does not touch PIN or
key material, does not cross a SCP03 secure channel, and caps output to
~20 rows to avoid terminal floods.
