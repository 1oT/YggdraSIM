---
title: SIMCARD Simulator
tags:
  - subsystems
  - simulator
  - simcard
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# SIMCARD Simulator

`SIMCARD/` is the simulator backend used when the operator shells run without
physical card hardware. It implements a card-side APDU surface, a filesystem,
a profile store, a toolkit engine, and an eUICC-style store. The card-facing
shells can target it in place of a PC/SC reader through the launcher's
`--card-backend sim` flag.

!!! info "Underlying concept"
    Start with [Secure Element Primer](../concepts/secure-element-primer.md)
    for the APDU and filesystem mental model this simulator implements.

## When to use it

- shell development without physical hardware available
- deterministic test fixtures for CI or local regression runs
- reproducing specific card-side BF55 eIM identity configurations
- exercising `LOAD-PROFILE` and related flows against a predictable eUICC
- exploring SAIP installation without risking a real card

## Entry points

The simulator is selected through the launcher:

```bash
python main/main.py --card-backend sim
python main/main.py --card-backend sim --sim-eim-identity /path/to/card_side_eim_identity.json
```

Individual subsystem entries accept the same backend selection when launched
through the wrapper menu.

## What the simulator implements

- an APDU dispatcher that speaks ISO 7816-4 case 1-4 commands
- an ETSI TS 102 221-shaped filesystem covering MF, DFs, ADFs, and EFs
- the full PIN lifecycle: VERIFY (`0x20`), CHANGE (`0x24`), DISABLE
  (`0x26`), ENABLE (`0x28`) and UNBLOCK (`0x2C`) with proper retry
  bookkeeping per TS 102 221 §11.1.9–11.1.12
- ISO 7816-4 / TS 102 221 §11.1.7 `GET CHALLENGE` (`0x84`) returning
  `Le` random bytes (or 256 when `Le=0`) and persisting them in
  `state.last_challenge_bytes` for OTA / SCP03 freshness
- TS 102 221 §11.1.13 / §11.1.14 file lifecycle: `DEACTIVATE FILE`
  (`0x04`) / `ACTIVATE FILE` (`0x44`) flip the lifecycle byte
  (FCP `8A`) of the currently selected EF/DF between `0x05`
  (operational-activated) and `0x04` (operational-deactivated);
  READ / UPDATE on a deactivated file return `62 83`. The MF
  itself rejects `DEACTIVATE FILE` with `69 86`.
- TS 102 221 §11.1.16 / §11.1.17 / §11.1.18 lifecycle terminators:
  `TERMINATE EF` (`INS 0xE8` CLA bit 8 cleared), `TERMINATE DF`
  (`INS 0xE6` CLA bit 8 cleared) and `TERMINATE CARD USAGE`
  (`INS 0xFE`). The first two flip the file's `8A` byte to `0x0C`
  (terminated, irreversible) -- a subsequent `ACTIVATE FILE` is
  rejected with `69 85`. `TERMINATE CARD USAGE` sets a global
  `state.terminated_card_usage` flag; afterwards every command
  except `STATUS` (`INS 0xF2`) returns `6F 00` so the IFD can
  still detect presence but cannot drive the card.
- TS 102 221 §11.1.8 `INCREASE` (`INS 0x32`) on cyclic EFs. The
  most recent record is treated as a big-endian unsigned integer;
  the request body (1-record-length bytes) is interpreted as the
  increment value. The response carries the new value followed by
  the increment value, both padded to the record width. Errors:
  non-cyclic target (`69 81`), empty body (`67 00`), increment
  overflow (`63 00`), deactivated / terminated file (`62 83`).
- TS 102 221 §11.1.7 `SEARCH RECORD` (`0xA2`) on linear-fixed EFs.
  Mode `0x04` is forward simple search, mode `0x05` is backward,
  mode `0x06` collapses to forward simple search. The response
  carries the matching record numbers (1 byte each); empty pattern
  returns `6A 80`, no match returns `6A 83`, transparent EFs
  return `69 81`.
- TS 102 221 §11.1.5 `STATUS` (`INS 0xF2` CLA bit 8 cleared) with
  the full ISO/ETSI sub-function matrix:

  | P1   | semantic                                  |
  |------|-------------------------------------------|
  | 0x00 | no indication (default polling probe)     |
  | 0x01 | application initialised in the terminal   |
  | 0x02 | terminal will terminate the session       |

  | P2   | response payload                          |
  |------|-------------------------------------------|
  | 0x00 | full FCP of the currently selected node   |
  | 0x01 | DF name (AID) of the current ADF only     |
  | 0x0C | empty (no data) -- pure status probe      |

  Invalid P1/P2 combinations return `6A 86`. `P1=0x02` performs the
  §11.1.5.4 session-termination steps: PIN-verified flags drop, the
  SCP03 session resets, the toolkit pending-fetch queue clears, the
  STORE DATA buffer is reset, and any logical channel above 0 is
  released. CLA bit 8 set keeps the historical GP GET STATUS / STK
  STATUS dispatch.
- TS 102 221 §11.1.12 `GET RESPONSE` (`INS 0xC0`). Backed by
  `state.last_response_buffer`. Quirk layers populate the buffer
  whenever they convert a `90 00` reply into the legacy `61 LL`
  handshake; subsequent GET RESPONSE drains the buffer atomically.
  An empty buffer returns `69 85` ("conditions of use not
  satisfied"). Le greater than the buffered length returns
  `6C LL` (with LL = remaining bytes) leaving the buffer untouched.
  Le less than the buffered length returns the requested prefix
  with `61 LL` (remainder); successive GET RESPONSE rounds drain
  the buffer until SW=`90 00`.
- TS 102 221 §11.1.4 `UPDATE BINARY` (`INS 0xD6`) and §11.1.6
  `UPDATE RECORD` (`INS 0xDC`) honour SFI-based addressing on par
  with READ. UPDATE BINARY: P1 bit 8 set selects the EF in the
  current DF via the lower 5 bits of P1, and P2 carries the byte
  offset (0..255). UPDATE RECORD: P2 bits 7..3 carry the SFI (0 =
  current EF), bits 2..0 the access mode. SFI resolution walks up
  from the current node when it is itself an EF, so a sequence of
  SFI-style accesses against different EFs in the same DF resolves
  correctly without an intermediate full SELECT.
- TS 102 221 §11.1.22 `SUSPEND UICC` (`0x76`). `P1=0x00` SUSPEND
  parses the `80` minimum / `81` maximum duration TLVs, clamps
  max to be ≥ min, and replies with the negotiated durations plus
  an 8-byte `82` resume token. `P1=0x01` RESUME validates the
  quoted token against `state.last_suspend_token`; mismatches
  return `69 85` without invalidating the resume context, so the
  modem can retry. `P2 ≠ 0x00` always returns `6A 86`.
- TS 102 221 §11.1.14 `RETRIEVE DATA` (`INS 0xCB`) and §11.1.15
  `SET DATA` (`INS 0xDB`). The 16-bit data-object tag is encoded
  as `P1||P2`. The simulator backs both with
  `state.card_data_objects`, lazily seeded with Card Capabilities
  (tag `0x0066`, §10.1.2), Application Identifier (`0x004F`),
  Card Service Data (`0x0043`) and Extended Card Resources
  (`0xFF21`). `RETRIEVE DATA` returns the entry wrapped as a
  primitive TLV (`tag || length || value`) using BER short-form
  length when possible. Unknown tags reply with `6A 88`. `SET DATA`
  with an empty body removes the entry to mirror the §11.1.15.4
  erase semantics; otherwise the body replaces the cached value.
  This surface is independent of the GlobalPlatform `GET DATA`
  (CLA=`80`, INS=`CA`) handler.
- ETSI TS 102 222 §6.5 `DELETE FILE` (`INS 0xE4`). Admin-scope,
  SCP03-gated. The body carries the target FID under TLV `83`;
  an empty body falls back to the currently selected EF / DF.
  Deleting a DF cascades through every descendant in
  ``state.nodes`` so the runtime tree never holds an orphan.
  MF deletion is rejected with `69 86`; non-operational targets
  (lifecycle byte ≠ `0x05`) are rejected with `62 83` to mirror
  commercial-card guard rails.
- ETSI TS 102 222 §6.3 `CREATE FILE` (`INS 0xE0`) and §6.4
  `RESIZE FILE` (`INS 0xD4`). Both are gated behind an
  authenticated SCP03 session (`6982` otherwise) so secure-channel
  audit always precedes a runtime tree mutation. CREATE FILE
  parses an FCP TLV (root `62`) with children `82` File
  Descriptor, `83` File ID, `80` File Size and `8A` Lifecycle.
  Supported file descriptor bytes are `0x01` transparent EF,
  `0x02` linear-fixed EF and `0x06` cyclic EF; for record EFs the
  descriptor's bytes 3..5 carry record length and count. The new
  EF is appended as a child of the currently selected DF and
  registered under its 2-byte FID; collisions inside the parent
  DF return `6A 89` ("file already exists"), unsupported sizes
  exceeding 64 KiB return `6A 84` and a malformed FCP returns
  `6A 80`. RESIZE FILE re-computes the data buffer (transparent
  EFs are truncated or padded with `0xFF`) or the record list
  (record EFs grow / shrink in record-count units); when the
  body omits a `83` FID the simulator targets the current EF,
  matching commercial-card behaviour.
- 3GPP TS 31.102 §7.1.2.1.2 / §7.1.2.1.3 `AUTHENTICATE` GBA
  variants. `P2=0x84` (GBA Bootstrap) reuses the regular UMTS
  AKA Milenage path, including AUTS / sync-failure recovery, and
  on success caches `Ks = CK||IK` plus a synthesised B-TID of
  the form `<rand-hex>@bsf.simulator` into `state.gba_ks` /
  `state.gba_b_tid`. `state.gba_key_lifetime` is set to the
  TS 33.220 §4.4.6 default of 86400 seconds. `P2=0x85` (GBA
  Security Context) parses the `L_NAF || NAF_Id || L_IMPI || IMPI`
  body, runs the TS 33.220 §B.0 KDF (HMAC-SHA-256 keyed with `Ks`,
  static `gba-me` salt, RAND from the most recent bootstrap), and
  returns `DB 20 || Ks_(ext)NAF`. The result is also stashed in
  `state.gba_naf_records[NAF_Id|IMPI]` for offline introspection.
  Calling `P2=0x85` without a prior bootstrap returns `69 85`;
  malformed input returns `67 00`.
- a card-side GP registry, SCP03 / SCP80 secure-messaging, and ISD-R
  interaction
- a profile store that tracks installed profiles and their lifecycle
- an ETSI TS 102 223 Toolkit / BIP runtime that routes envelopes by
  root tag (D1 SMS-PP, D2 Cell Broadcast, D3 Menu Selection, D4 Call
  Control, D5 MO-SMS Control, D6 Event Download, D7 Timer Expiration,
  D8 USSD Download)
- a Milenage / TUAK 3GPP TS 35.205 / 35.231 AKA core
- a 5G authentication stack:
    - 3GPP TS 33.501 5G AKA (`AUTHENTICATE`, `RES*`)
    - 3GPP TS 33.402 EAP-AKA'
    - 3GPP TS 33.535 AKMA key derivation (`K_AKMA`, `A-KID`)
    - 3GPP TS 33.501 §C.3 SUCI calculation (Profile A and Profile B)
    - 3GPP TS 31.102 §7.1.2.4 `GET IDENTITY` (USIM-side SUCI build)
- a BF55 eIM identity surface that mirrors what a real eUICC advertises
- an SGP.32 ES10b.LoadEuiccPackage path that verifies the eIM signature,
  enforces counter / EID checks, executes the inner PSMO/eCO batch, and
  emits a signed `EuiccPackageResult` into the notification list

## SGP.32 ES10b.LoadEuiccPackage (BF51)

The `BF51 EuiccPackageRequest` STORE DATA payload is dispatched in
`SIMCARD/sgp.py::_handle_load_euicc_package`. The full verification ladder
is implemented in line with SGP.32 v1.2 §5.9.1 / §2.11.1.1:

1. Decode `BF51 → euiccPackageSigned (30) || eimSignature (5F37)` via
   `SIMCARD/sgp32_packages.py::decode_euicc_package_request`.
2. Look up the targeted `eimId` in `state.eim_entries`. Unknown eIM →
   `euiccPackageErrorUnsigned [2]`, optionally carrying the configured
   `associationToken`.
3. Verify the 64-byte raw `r||s` ECDSA signature with SHA-256 against
   `euiccPackageSigned || (84 01 00 | associationToken)`. Bad signature
   → `euiccPackageErrorUnsigned [2]`.
4. Compare `eidValue` against the eUICC's own EID. Mismatch →
   `euiccPackageErrorSigned [1]` with code `invalidEid (3)`.
5. Range-check `counterValue`: `> 0x7FFFFF` →
   `counterValueOutOfRange (6)`; `<=` stored counter →
   `replayError (4)`. Both are signed errors.
6. Run the inner `psmoList [0]` / `ecoList [1]` SEQUENCE OF
   sequentially. Each element is dispatched by `_execute_psmo` /
   `_execute_eco`. The first failure aborts with a final
   `processingTerminated` `EuiccResultData` and the remainder is
   dropped, matching §5.9.1 paragraph "first failure".
7. Allocate a fresh `seqNumber` from the shared notification counter,
   sign the assembled `euiccPackageResultSigned [0]`, persist a
   `SimEuiccPackageResultEntry` into `state.euicc_package_results`, and
   advance `eim_entry.counter_value`.

### Package-level constraints (§2.11.1.1)

The package executor pre-validates the inner list before running it:

- At most one `enable` PSMO per package. A second `enable` aborts the
  package with `enableResult 83 / 7F undefinedError` followed by
  `processingTerminated 02 / 02 unknownOrDamagedCommand`.
- At most one `disable` PSMO per package, mirrored as
  `disableResult 84 / 7F` + `processingTerminated`.
- `listProfileInfo` MUST NOT follow `enable`, `disable` or `delete` in
  the same package. If it does, the simulator emits
  `BF2D 03 02 01 0B` (`profileChangeOngoing(11)`) and aborts with
  `processingTerminated`.

### Supported PSMO operations

| Tag | Operation | Result tag |
| --- | --- | --- |
| `A3` | `enableProfile` (with optional `81` `rollbackFlag` NULL) | `83 enableResult` |
| `A4` | `disableProfile` | `84 disableResult` |
| `A5` | `deleteProfile` | `85 deleteResult` |
| `BF2D` | `listProfileInfo` | `BF2D ProfileInfoListResponse` |
| `A6` | `getRAT` | `A6` (empty placeholder) |
| `A7` | `configureImmediateEnable` | `87 configureImmediateEnableResult` |
| `A8` | `setFallbackAttribute` | `8D setFallbackAttributeResult` |
| `A9` | `unsetFallbackAttribute` | `8E unsetFallbackAttributeResult` |
| `BF65` | `setDefaultDpAddress` | `BF65` with `80 ok(0)` / `80 invalidParam(1)` |

`enable.rollbackFlag` is parsed and persisted: when present, the newly
enabled profile is marked `rollback_armed` and the previously-enabled
AID is captured in `state.previous_enabled_aid` so a later
`ES10b.ProfileRollback` can revert atomically.

`setFallbackAttribute` / `unsetFallbackAttribute` operate on the
`fallback_attribute` flag carried per `SimProfileEntry` and respect the
`iccidOrAidNotFound (1)`, `fallbackNotAllowed (2)` and
`fallbackProfileEnabled (3)` error codes from §2.11.2.1.

`configureImmediateEnable` persists `state.immediate_enable_flag`,
`state.immediate_enable_smdp_oid` (decoded to dotted form) and
`state.immediate_enable_smdp_address` so subsequent reads via
`GetEimConfigurationData` see the latest values.

### Supported eCO operations

| Tag | Operation | Result tag |
| --- | --- | --- |
| `A8` | `addEim` (CHOICE, EXPLICIT) | `A8` with inner `02 code` or `84 associationToken` |
| `A9` | `deleteEim` | `89 02 code` (`0` ok, `1` eimNotFound, `2` lastEimDeleted) |
| `AA` | `updateEim` | `8A 02 code` |
| `AB` | `listEim` (CHOICE, EXPLICIT) | `AB` with `30` SEQUENCE OF eIM rows |

The result tags `89` (`deleteEim`) and `8A` (`updateEim`) are primitive
context-specific because their carrier types are INTEGER under
AUTOMATIC TAGS. The constructed forms `A9` / `AA` are reserved for the
*command* side of the same numbers.

### Standalone ES10b / ES10c surfaces

These are dispatched outside the BF51 package envelope:

| Tag | Function | Behaviour |
| --- | --- | --- |
| `BF34` | `ES10c.eUICCMemoryReset` (SGP.22 v3 §5.7.19) | Same bit-string semantics as BF64 minus the IoT-specific bits 5/6. Returns `BF34 80 01 RR` with `ok(0)` when at least one Profile / SM-DP+ datum was cleared, `nothingToDelete(1)` otherwise, `undefinedError(127)` when `resetOptions` is missing. |
| `BF55` | `ES10b.GetEimConfigurationData` (§5.9.18) | Returns the stored eIM list. When the request carries the `searchCriteria.eimId [0] UTF8String` filter, the response is restricted to the matching row (or empty if no match). |
| `BF58` | `ProfileRollback` (sniffed via primitive BOOLEAN body) | Reverts an `enable.rollbackFlag` swap; emits `cmdResult 80` `ok(0)` / `rollbackNotAllowed(1)`. Falls back to legacy UpdateEim STORE DATA when the body is constructed. |
| `BF59` | `ConfigureImmediateProfileEnabling` (§5.9.17) | Sniffed from the legacy delete-eIM path: empty body, or `[0]` NULL, or any of `[1]` OID / `[2]` UTF8String present routes here. Persists `state.immediate_enable_flag` plus optional `defaultSmdpOid` / `defaultSmdpAddress`. Returns `BF59 80 01 RR` with `ok(0)`, or `associatedEimAlreadyExists(2)` when eIMs are configured. |
| `BF5A` | `ImmediateEnable` (§5.9.15) | Requires `state.immediate_enable_flag` to be set, otherwise `immediateEnableNotAvailable(1)`. Selects the most recently-installed disabled Profile, swaps it into the enabled slot and emits the standard `enable` / `disable` notifications. Returns `noSessionContext(4)` when there is no candidate. |
| `BF5B` | `EnableEmergencyProfile` (§5.9.22) | Returns `ecallNotAvailable(8)` when `iot_specific_info.ecall_supported` is `False` or no Profile carries `ecall_indication`. Returns `profileNotInDisabledState(2)` when the Emergency Profile is already enabled, or `undefinedError(127)` for malformed `refreshFlag`. On success, disables the currently enabled Profile, enables the Emergency Profile, latches `state.emergency_profile_active` plus `state.emergency_pre_aid`, and intentionally suppresses notifications per spec. |
| `BF5C` | `DisableEmergencyProfile` (§5.9.23) | Returns `profileNotInEnabledState(2)` when no Emergency Profile is currently enabled, or `undefinedError(127)` for malformed `refreshFlag`. On success, restores the Profile recorded in `state.emergency_pre_aid`, clears the sticky flag, and emits the disable+enable notifications allowed by §5.9.23. |
| `BF5D` | `ExecuteFallbackMechanism` | Swaps the currently-enabled profile with the profile carrying `fallback_attribute`. Records `previous_enabled_aid` so `BF5E` can return. |
| `BF5E` | `ReturnFromFallback` | Disables the currently-enabled fallback profile and re-enables `previous_enabled_aid`. |
| `BF5F` | `GetConnectivityParameters` (§5.9.24) | Reads the active Profile's `connectivity_params_http`. Empty bytes ⇒ `connectivityParametersError parametersNotAvailable(1)`. Populated ⇒ `ConnectivityParameters { httpParams [1] OCTET STRING }`. The same OCTET STRING is reused for CoAP per §5.9.24. |
| `BF64` | `ES10b.eUICCMemoryReset` (SGP.32 §5.9.5) | Acts on every defined `resetOptions` bit: `0` deletes operational, `1`/`3` test, `4` provisioning Profiles; `2` clears `state.default_dp_address`; `5` reseeds `eim_entries` from the default identity; `6` clears the immediate-enable configuration. Notifications for deleted Profiles are queued. The response keeps the legacy `BF6400` empty form for backwards compatibility with the eim-local regression suite, while the side-effects on state remain spec-mandated. |
| `BF65` | `SetDefaultDpAddress` (SGP.32 §5.9.25) | IoT-side counterpart of SGP.22 v3 `BF3F`. Updates `state.default_dp_address` from `[0] UTF8String`; an empty body resets the address. Returns `BF65 80 01 NN` with `ok(0)` or `undefinedError(127)` (oversized / malformed). |

Each of the BF58/BF5B/BF5C/BF5D/BF5E/BF59/BF5A/BF65 responses follows
the `[N] SEQUENCE { result [0] INTEGER }` shape from §5.9.15 – §5.9.25,
encoded as `BFxx LL 80 01 NN`. `BF5F` is the only CHOICE in this group:
the success branch wraps `httpParams` under context `81`, the error
branch reuses `80 01 NN` for the `connectivityParametersError` enum.

### Result list and acknowledgement

- `BF2B RetrieveNotificationsList` returns notifications under `A0` and
  also resolves any `searchCriteria.seqNumber` against
  `state.euicc_package_results`, returning the matching `A2` body.
- The dedicated package-result list path returns `BF2B → A2 → SEQUENCE OF
  euiccPackageResultSigned`. An empty list still emits `BF2B → A2 (empty)`
  so the IPA can distinguish "drained" from "no path".
- `BF30 RemoveNotificationFromList` drains both `state.notifications`
  and `state.euicc_package_results` keyed on `seqNumber`, then triggers
  an eUICC store sync so deletions survive a reset.

### Persistent state

`SIMCARD/state.py::SimCardState` carries the SGP.32 fields persisted
through the eUICC manifest (`SIMCARD/euicc_store.py`):

- `euicc_package_results: list[SimEuiccPackageResultEntry]` — signed
  result blobs awaiting IPA acknowledgement.
- `association_token_counter: int` — monotonic counter used by
  `addEim` to allocate fresh association tokens.
- `immediate_enable_flag`, `immediate_enable_smdp_oid`,
  `immediate_enable_smdp_address` — populated by
  `configureImmediateEnable` and read back by
  `GetEimConfigurationData`.
- `previous_enabled_aid` — captured during a `enable.rollbackFlag`
  swap or a `BF5D` fallback swap so `BF58` / `BF5E` can revert.
- `emergency_profile_active`, `emergency_pre_aid` — sticky
  bookkeeping for `BF5B` / `BF5C`. Spec-mandated: the Emergency
  Profile remains enabled across resets, so this state lives in the
  eUICC manifest rather than the volatile session.

`SimProfileEntry` adds the following flags persisted by
`SIMCARD/profile_store.py`:

- `fallback_attribute: bool` — set by PSMO `setFallbackAttribute`.
- `rollback_armed: bool` — set by `enable.rollbackFlag` and cleared on
  successful `ProfileRollback` / `ExecuteFallbackMechanism`.
- `ecall_indication: bool` — marks the Profile that BF5B / BF5C
  operate on. Sourced from SAIP profile metadata at install time, or
  set explicitly by tooling/tests.
- `connectivity_params_http: bytes` — TCA Profile Interoperability
  HTTP/CoAP parameters returned by `BF5F`.

Each `SimEimEntry` keeps its own `counter_value` and
`association_token`, so replay protection is per-eIM and survives
restarts.

## GP GET DATA tag coverage

`SIMCARD/gp.py::GpLogic.handle_get_data` handles the tags universally
probed by management tools and modems:

| `P1 P2` | Tag | Body |
| --- | --- | --- |
| `00 5A` | EID (`5A`) | Full EID OCTET STRING; SGP.22 §5.6.2.1 anchor. |
| `00 42` | IIN (`42`) | First four EID bytes per GP §H.4. |
| `00 45` | CIN (`45`) | Full EID echoed as the card image number per GP §H.5. |
| `00 66` | Card Recognition Data (`66`) | GP §H.2 `73` template carrying CRD OID, GP version (2.3.1), card identification scheme, SCP03 with the live `i` byte, plus `65`/`66` placeholders. |
| `9F 7F` | CPLC (`9F7F`) | 42-byte ETSI TS 102 226 / GP §H lifecycle blob seeded from EID + ICCID. |
| `00 E0` | Key Information Template | KVN-aware AES-128 record set (`C0 04 ID KVN 88 10`). |
| `FF 21` | Extended Card Resources (`FF21`) | GP §H.6 template carrying `81` system-app count (1 byte), `82` free NVM (3 bytes), `83` free RAM (2 bytes), seeded from `state.euicc_info.ext_card_resources`. RAM management tools probe this before issuing INSTALL [for load] to size CAP files. |
| `FF 40` | Vendor reserved | Empty TLV; kept for legacy probes. |

Anything else returns `6A 88` per ISO 7816-4. Each tag is deterministic
across reboots so external fingerprinters key off a stable signature.

## STK envelope routing

`SIMCARD/toolkit.py::ToolkitLogic.handle_envelope` dispatches by the
BER root tag. Each branch records the envelope into
`state.toolkit.envelope_history`; the response shape follows the
relevant section of TS 102 223 / TS 31.111:

| Tag | Envelope | Response |
| --- | --- | --- |
| `D1` | SMS-PP Download | Routed to the SCP80 fallback (`Scp80Logic.handle_envelope`) which queues a POR proactive command and returns `91 LL`. |
| `D2` | Cell Broadcast Download | `90 00`, no body. |
| `D3` | Menu Selection | `90 00`, no body. |
| `D4` | Call Control by USIM | `80 01 00` (Allowed, no modification) per TS 31.111 §7.3.1. |
| `D5` | MO Short Message Control | `80 01 00` per TS 31.111 §7.3.2. |
| `D6` | Event Download | Existing local handler that updates `state.toolkit` and queues follow-up proactive commands. |
| `D7` | Timer Expiration | `90 00`, no body. |
| `D8` | USSD Download | `80 01 00` per TS 31.111 §7.3.3. |
| other | Legacy passthrough | Falls through to the SCP80 handler so plaintext OTA traffic keeps working. |

When a proactive command queues into `state.pending_fetch_queue` while
processing an envelope, the response is upgraded to `91 LL` regardless
of the tag, matching the TS 102 223 SW2 chaining behaviour.

### PROVIDE LOCAL INFORMATION (proactive type `0x26`)

`ToolkitLogic.queue_provide_local_information` enqueues a TS 102 223
§6.4.15 PROVIDE LOCAL INFORMATION proactive command. The qualifier
selects the requested datum (per §6.6.15):

| Qualifier | Meaning |
| --- | --- |
| `0x00` | Location information (LAI + cell ID) |
| `0x01` | IMEI |
| `0x03` | Date / time / time-zone |
| `0x04` | Language |
| `0x06` | Access technology |
| `0x08` | IMEISV |
| `0x0D` | Battery state |

The terminal reply (`TERMINAL RESPONSE`) carries the requested data
under the matching TS 102 223 §8 tags. `_apply_terminal_response`
dispatches a successful PROVIDE LOCAL INFORMATION reply to a state
latch so an STK applet (or a test) can read the most recent value
back from `state.toolkit`:

| TR tag (CR / non-CR) | Field |
| --- | --- |
| `13` / `93` | `state.toolkit.location_information` |
| `14` / `94` | `state.toolkit.imei` |
| `26` / `A6` | `state.toolkit.date_time_timezone` |
| `2D` / `AD` | `state.toolkit.language` |
| `62` / `E2` | `state.toolkit.imeisv` |
| `5C` / `DC` | `state.toolkit.battery_state` |

Failed responses (general result code != `0x00` / `0x01`) are not
latched, so partial / terminal-busy replies do not clobber a
previously known good value.

### Event Download routing

`ToolkitLogic._handle_event_download` maintains `state.toolkit`
bookkeeping for the events the simulator can react to:

| Event code | Spec | Latch |
| --- | --- | --- |
| `0x03` | TS 102 223 §7.4.3 Location Status | `location_information` |
| `0x07` | TS 102 223 §7.4.7 Idle Screen Available | `idle_screen_available` |
| `0x09` | TS 102 223 §7.4.9 Browser Termination | `last_browser_termination_cause` |
| `0x0B` | TS 102 223 §7.4.11 Channel Status | `open_channel_active` |
| `0x0F` | 3GPP TS 31.111 §7.5.13 Network Rejection | `last_network_rejection_cause` |

Every received event also updates `last_event_code` and appends
to `event_history` so the order and number of received events is
introspectable from a test harness.

### TIMER MANAGEMENT (proactive type `0x27`)

`ToolkitLogic.queue_timer_management` enqueues a TS 102 223 §6.4.27
TIMER MANAGEMENT proactive command. The qualifier selects the
sub-function per §6.6.27:

| Qualifier | Sub-function | Body |
| --- | --- | --- |
| `0x00` | start | Timer Identifier TLV (`A4`) + Timer Value TLV (`A5`, BCD HH/MM/SS) |
| `0x01` | deactivate | Timer Identifier TLV (`A4`) only |
| `0x02` | get current value | Timer Identifier TLV (`A4`) only |

The TR-side latch (`_apply_timer_management_response`) updates
`state.toolkit.timer_table[timer_id]`:

- `start` writes the requested setpoint at queue-time (so the
  registry is populated even if the terminal omits the echo TLV) and
  re-confirms it on a successful TR.
- `deactivate` removes the entry when the TR result is success.
- `get current value` updates the stored value from the TR's
  `A5` TLV (BCD HH/MM/SS decoded back into seconds).

Failed responses (general result code outside `0x00..0x01`) leave
`timer_table` untouched.

The matching `D7` TIMER EXPIRATION envelope (3GPP TS 31.111 §7.5.6)
is decoded by `_apply_timer_expiration`: the inner `A4` Timer
Identifier TLV is latched into
`state.toolkit.last_expired_timer_id` and the corresponding
`timer_table` entry is removed. Envelopes without a Timer
Identifier are accepted and logged but do not mutate state.

### TERMINAL PROFILE bring-up strategy

`ToolkitLogic._bootstrap_commands` is the single seam that decides
which proactive commands are queued the first time the terminal
issues `8010` TERMINAL PROFILE. The shape is operator-controlled
through the `toolkit` block in
`Workspace/SIMCARD/isdr_config.json` (parsed by
`SIMCARD/euicc_store.py::apply_euicc_state_payload`):

| Field | Meaning |
| --- | --- |
| `timer_management_seconds` | Initial timer setpoint, encoded as BCD HH/MM/SS in TLV `A5`. |
| `timer_management_id` | Timer identifier carried in TLV `A4`. Clamped to the ETSI 1..8 range. |
| `poll_interval_seconds` | Setpoint used when the strategy includes the legacy POLL INTERVAL heartbeat. |
| `provide_imei` | When `true` (default) the bootstrap also queues a PROVIDE LOCAL INFORMATION (IMEI) proactive command after the polling trigger, mirroring real eUICC bring-up. |

Defaults (`SimToolkitState`) match the JSON template, so a fresh
manual configuration.


`_apply_timer_expiration` drives the SGP.32 §3.5 polling
cadence. Each `D7` envelope queues a two-leg BIP cycle followed
by a TIMER MANAGEMENT START re-arm. The first leg is a DNS
resolution against a public resolver (default `192.0.2.53`); the
second is the ESipa exchange against the resolved eIM IP.

#### Cold-cache cycle (no resolved IP yet)

   with qualifier `0x03` (immediate + automatic reconnection).
   The cellular APN travels under TLV `47` (Network Access Name,
   §8.70 label-list encoding), the resolver IPv4 under TLV `3E`
   (Other Address, §8.59 type byte `0x21`), and the alpha id
   (TLV `05`) is present-but-empty so the modem can still label
   the bearer in its UI without forcing user-visible text.
2. **SEND DATA** with the AAAA query for the eIM FQDN (RFC 1035
   wire format, transaction id seeded from
3. **SEND DATA** with the A query for the same FQDN.
4. **RECEIVE DATA** drains the resolver's first answer.
5. **RECEIVE DATA** drains the resolver's second answer. The
   first usable A-record lands in
6. **CLOSE CHANNEL** tears the resolver bearer down. If the DNS
   leg produced an IPv4 address, the toolkit chains directly
   into the eIM leg below; otherwise the cycle returns to idle
7. **TIMER MANAGEMENT START** re-arms the cadence.

#### Warm-cache cycle (resolved IP already cached)

1. **OPEN CHANNEL** TCP_CLIENT_REMOTE → `<resolved_ip>:443`
   with qualifier `0x01`. APN under TLV `47`, IPv4 destination
   under TLV `3E` (type byte `0x21`).
2. **SEND DATA** carrying the configured ESipa request payload
   (default: HTTP/1.1 `POST /gsma/rsp2/asn1` wrapping a
   `BF4F GetEimPackageRequest`).
3. **RECEIVE DATA** to drain the eIM's response (parsed as
   SGP.32 outer TLVs).
4. **CLOSE CHANNEL** ends the bearer.
5. **TIMER MANAGEMENT START** re-arms the cadence.

The DNS and eIM legs share the same APN. APN priority is:
1. SAIP profile EF.ACL (`6F57`) — set automatically by the
   filesystem rebuild whenever a profile is enabled.
3. `internet.apn` workspace fallback.

(`"bpp"` / `"env"` / `"default"`).

#### OPEN CHANNEL failure recovery

When the modem fails the OPEN CHANNEL TR (e.g. result `0x20`
"BIP error", info `0x04` "no service"), the toolkit drains the
SEND DATA / RECEIVE DATA / TIMER MANAGEMENT / CLOSE CHANNEL
commands the IPA had already queued behind it so the modem does
not have to FETCH guaranteed-failure commands (`0x3A03` "channel
id not valid") before the next timer expires.
phase machine all reset on the same code path.

When the modem fails a SEND DATA or RECEIVE DATA TR mid-cycle
(general result `0x3A` "Bearer Independent Protocol error" is
the common case for misbehaving UDP/TCP stacks), the toolkit
drains the still-pending SEND/RECEIVE/TIMER follow-ups but
preserves the trailing CLOSE CHANNEL so the bearer is torn down
records a `phase|origin|result|info` summary into
counter resets to zero on the next cycle that successfully
dispatches at least one EuiccPackage into ISD-R.

#### TIMER MANAGEMENT yield between SEND and RECEIVE DATA

ETSI TS 102 223 §6.6.21 + reference IPA traces show that real
the SEND DATA burst and deactivate it once the matching
RECEIVE DATA flight has been drained. The proactive yield gives
the modem its FETCH/STATUS polling window so bytes from the
network actually land in the bearer buffer before the eUICC
issues RECEIVE DATA. Skipping the yield makes the modem return
general result `0x3A` ("Bearer Independent Protocol error") on
every RECEIVE DATA because no data has arrived yet.

The simulator now mirrors this behaviour:

* The DNS leg queues
  `OPEN/SEND/SEND/TIMER(start)/RECV/RECV/TIMER(stop)/CLOSE`.
* The plain-HTTP eIM leg queues
  `OPEN/SEND/TIMER(start)/RECV/TIMER(stop)/CLOSE`.
  RECEIVE DATA dispatch and disarms it before the next SEND
  DATA flight (or CLOSE CHANNEL).

tracks the runtime arm state for the TLS path.

All TIMER MANAGEMENT proactives use the comprehension-clear
TLV form (`24` Timer Identifier, `25` Timer Value) and
RECEIVE DATA uses the comprehension-clear form (`37` Channel
Data Length); reference cards emit those tags without the CR
bit set and some modems silently drop the proactive when the
CR-set form (`A4` / `A5` / `B7`) is used.

#### BIP follow-up device-identities patching

ETSI TS 102 223 §6.6.27/28/29 require the destination device on
SEND DATA / RECEIVE DATA / CLOSE CHANNEL commands to identify
the channel opened by the matching OPEN CHANNEL -- encoded as
`0x20 + channel_id` in the device-identities TLV (channel 1 →
`0x21`, ..., channel 7 → `0x27`). Sending the generic terminal
identifier (`0x82`) instead causes the modem to reject every
follow-up with general-result `0x3A` / additional-info `0x03`
("Channel identifier not valid").

OPEN/SEND/RECEIVE/CLOSE batch up-front, the destination byte on
the follow-ups is initially encoded as `0x82`. Once the
OPEN CHANNEL TR returns the assigned channel id in the
channel-status TLV (`38 02 [byte1] [byte2]`, channel id =
`byte1 & 0x07`), the toolkit captures it on
`toolkit.open_channel_id` and walks the still-pending queue to
patch the destination byte of every BIP follow-up in place. The
patch stops at the first non-BIP entry so unrelated traffic from
extensions is left untouched. The field resets to `0` on
CLOSE CHANNEL (success or failure) and on OPEN CHANNEL failure
so the next cycle starts clean.

resolved (no override, no `state.eim_entries[*].eim_fqdn`, no
workspace eIM identity) the BIP sequence is skipped and only the
timer re-arm is queued so the cadence keeps running while a test
fixture is being staged.

#### In-card TLS-1.2 handshake (Stage 2)

default) the eIM leg above runs the TLS-1.2
**ECDHE-ECDSA-AES128-GCM-SHA256** handshake entirely inside the
card. The modem stays a transparent byte pipe -- no MITM, no
re-wrapping -- which mirrors what every reference IPA on real
hardware emits.

The handshake state machine is reactive: only the OPEN CHANNEL
is enqueued up-front. After the bearer comes up, the toolkit's
TR handlers drive a SEND/RECEIVE DATA loop:

1. **OPEN CHANNEL TR success** → instantiate the `CardTlsClient`
   (memory-BIO `ssl.SSLObject` pinned to TLS-1.2 + cipher suite
   0xC02B), call `do_handshake()`, drain the resulting
   ClientHello bytes, slice them into ≤240-byte SEND DATA
   chunks. Phase advances to `eim_tls_handshake`.
2. **SEND DATA TR success (during handshake)** → if more
   outbound bytes are buffered (multi-chunk flight), keep
   shipping them; otherwise queue a RECEIVE DATA so the modem
   can hand back the eIM's response.
3. **RECEIVE DATA TR success (during handshake)** → if the TR
   reported `channel_data_length > 0` (more bytes still
   buffered in the modem) keep draining; otherwise feed the
   accumulated bytes to the TLS engine, advance the handshake,
   and either ship more outbound flights or wait for more
   inbound.
4. Once the handshake completes, the configured ESipa request
   payload is encrypted and shipped as the next SEND DATA.
   Phase = `eim_request`.
5. **RECEIVE DATA TR success (during eim_recv)** → buffer until
   the modem signals "drained", feed the TLS engine, decrypt
   the application data, dispatch each SGP.32 outer TLV through
   `set_eim_package_dispatcher` (same contract as the
   plain-HTTP path), then queue CLOSE CHANNEL.

Trust-anchor priority for the chain validator:

1. Every `state.eim_entries[*].trusted_tls_public_key_data`
   (DER, seeded by `_load_sim_eim_certificate_der` from
   `eim_identity.json::trusted_tls_cert_path`).
2. When no trust anchor is provisioned the engine falls back to
   `ssl.CERT_NONE` so the simulator still emits valid TLS bytes
   for diagnostics. Operators tighten the chain by populating
   the eIM identity JSON.

Aborts:

* TLS handshake failure (`SSLError` from `do_handshake()`)
  drains any queued follow-ups and queues a single CLOSE CHANNEL
  so the bearer is shut cleanly.
  default 16) prevents an unresponsive eIM from looping the
  RECEIVE DATA polls forever; on overflow the cycle aborts with
  the same CLOSE CHANNEL teardown.

The Stage-1 plain-HTTP fallback is preserved for tests and lab
restores the linear OPEN/SEND/RECEIVE/CLOSE queue from before
the TLS engine was wired in.

### ESipa request body — `BF4F` GetEimPackageRequest

SGP.32 v1.2 §6.5.2.1 `GetEimPackageRequest` (BF4F) wrapped in
HTTP/1.1 framing:

- `5A` 16-byte EID (mandatory).
- `80` notifyStateChange flag, `81` stateChangeCause, `82` rPlmn
  BCD — all optional, omitted by default.

`Content-Type` is `application/x-gsma-rsp-asn1` and
`X-Admin-Protocol` is `gsma/rsp/v2.2.0` so the modem's HTTP
client routes it to `/gsma/rsp2/asn1`. The body can still be
that escape hatch is the way an integration test injects a
`BF39` InitiateAuthenticationRequestEsipa or any other ESipa
opener.

### ESipa response dispatch on RECEIVE DATA

through the **RECEIVE DATA** terminal response are the eIM's
ESipa payload (SGP.32 §6.5). The toolkit:

   and cleared on the **CLOSE CHANNEL** TR (success *or* failure;
   the bearer is gone either way).
2. Strips any leading HTTP envelope (`HTTP/1.1 ...\r\n\r\n`) the
   bearer left in the buffer.
3. Walks the residue as a chain of SGP.32 outer TLVs and forwards
   each recognised `BFxx` package into ISD-R via the dispatcher
   wired by `SimulatedSimCardEngine`
   (`self.toolkit.set_eim_package_dispatcher(self.sgp.handle_store_data)`),
   which is exactly the path a real terminal would take when the
   IPA fans the eIM payload out as STORE DATA on ISD-R.
4. Records the outer tag of every successfully dispatched package
   R-APDU bytes the SGP layer returned in

The dispatcher allow-list covers the full SGP.32/SGP.22 tag range
the SGP layer can handle (BF21/25/29/2A/2B/2D/2E/30/31/32/33/34/
36/38/3C/3F/41/45/50..5F/64/65). New tags are added to the
allow-list whenever `SgpLogic.handle_store_data` learns a new
opcode. The dispatcher is decoupled from `SgpLogic` so unit
tests can build a `ToolkitLogic` in isolation; the engine wiring
is the only place that introduces the dependency. Failures from
the dispatcher (raised exceptions, `6Axx` SW pairs) are isolated
to their package and do not abort the rest of the chain.

### LoadCRL — `BF35` (SGP.22 §5.7.13)

The eUICC accepts CRL DER blobs pushed by the RSP server. Each
non-empty `BF35` STORE DATA payload is appended to
`state.loaded_crls`; the response is `BF35` with an inner
`80 01 00` (`ok(0)`). Empty bodies return `81 01 02`
(`invalidSignature(2)`). Revocation is not enforced today, but
the persistence path lets a future enforcer walk the list
without touching transport. The dispatcher allow-list includes
`BF35` so an eIM-side push relayed over BIP forwards directly to
the SGP layer.

### ESipa result follow-up — `BF50` ProvideEimPackageResult

After the dispatcher consumed at least one package and produced
non-empty response bytes, the IPA injects a fresh **SEND DATA**
(plus a follow-up RECEIVE DATA to drain the eIM's
acknowledgement) directly in front of the still-pending CLOSE
CHANNEL. The injected SEND DATA carries an SGP.32 v1.2 §6.5.2.1
`ProvideEimPackageResult` (BF50) body wrapping:

- `5A` EID,
- one or more `BF51` / `BF52` / `BF54` per-package results;
  bare ISD-R responses that are not already prefixed with one
  of those tags are wrapped in `BF51` (`LoadEuiccPackage` result)
  per the default-CHOICE rule.

so the IPA cannot cascade itself if the eIM's acknowledgement
happens to contain BF50 bytes -- real eIMs reply with an empty
body or a tiny ack TLV and the latch resets only on the next
cycle (CLOSE CHANNEL TR).

operator introspection; the latter survives the cycle teardown
so a test can confirm "the IPA shipped the eIM the expected
result for cycle N".

#### Error CHOICE — `BF50` with `[0]` EimPackageResultErrorCode

When *every* dispatched package failed (the SGP layer returned a
non-9000 SW pair, or the dispatcher itself raised), the IPA
emits the error branch of the SGP.32 v1.2 §6.5.2.1 EimPackageResult
CHOICE instead of `BF51`/`BF52`/`BF54`:

```
BF50 LL { 5A 10 <EID>  80 05 30 03 02 01 XX }
```

where `XX` is the EimPackageResultErrorCode the IPA inferred.
The `_sw_to_eim_package_error_code()` static maps the card's
SW pair to `1` (invalidPackageFormat — `6A80`/`6A82`/`6985`),
`2` (unknownPackage — `6A88`), or `127` (undefinedError —
parallel `[(outer_tag, error_code), ...]` audit trail to the

#### PendingNotification piggyback

After the per-package result chain (or in place of it on a
failure-only cycle, provided notifications exist), the IPA
appends a `BF2B`/`A0 ...` retrieve-all chunk drained from
`state.notifications`. The notifications themselves are NOT
cleared from the eUICC; the eIM is expected to acknowledge them
via a follow-up `RemoveNotificationFromList` (BF30) before they
go away. This mirrors a real card: notifications stay pinned
until explicitly cleared, so the eIM and eUICC share the same


Two integration suites pin the IPA contract end-to-end:

- **Mode A (ISD-R discovery + AddInitialEim)** --
  `tests/test_simcard_local_eim_loopback.py`. Drives
  `EimLocalSession.discover_card()` and
  `EimLocalSession.add_initial_eim()` against the
  `SimulatedCardConnection` PC/SC shim. The `EimLocalSession` is
  the same code path the local eIM uses against a production
  eUICC; passing here guarantees the simulator answers every
  `BFxx` ISD-R surface the eIM relies on (BF20/22/2D/2E/3C/43/2B/55/56)
  and the BF57 AddInitialEim STORE DATA round-trip lands a new
  entry in `state.eim_entries`.

- **Mode B (RECEIVE DATA dispatch / fake-modem)** --
  in-test FETCH/TR loop impersonates the modem, returns a canned
  ESipa payload through RECEIVE DATA, and asserts that the
  payload is fan-out into ISD-R. The engine-level test runs
  against the real `SimulatedSimCardEngine` and verifies that an
  `AddEim` (BF58) ESipa response actually creates a new
  `SimEimEntry` in the simulator after the BIP cycle closes.

Together these two layers mean: if the production eIM produced an
ESipa payload the local eIM can produce, the simulator will
process it the same way a real eUICC does -- the bearer (TLS,
HTTP framing, DNS) is the modem's responsibility and the
simulator does not need to mock that.

### MORE TIME / POLLING OFF / DECLARE SERVICE

Three small queueables round out the round-7 proactive surface:

- `queue_more_time` (TS 102 223 §6.4.2, command type `0x02`) --
  reserved-qualifier proactive command an STK applet uses to ask
  the terminal for a longer response window.
- `queue_polling_off` (TS 102 223 §6.4.7, command type `0x04`) --
  on a successful TR the simulator sets
  `state.toolkit.polling_off_active = True` so a follow-up SET UP
  IDLE MODE TEXT or POLL INTERVAL helper can decide whether to
  re-arm polling.
- `queue_declare_service` (TS 102 223 §6.4.34, command type `0x47`)
  -- the supplied service-record blob is appended to
  `state.toolkit.declared_services` at queue-time and is also
  shipped under TLV `61` in the proactive command body.

### Service discovery (`0x45` / `0x46` / `0x47`)

Round-8 completes the TS 102 223 §6.4.32..§6.4.34 service-discovery
triplet:

- `queue_service_search` (proactive `0x45`) ships the requested
  service-record (TLV `61`) plus an optional device-filter (TLV
  `63`). On a successful TR the matching service-record blob is
  latched into `state.toolkit.last_service_search_result`; a
  failed TR clears the field so a polling applet can distinguish
  "no match yet" from "match removed".
- `queue_get_service_information` (proactive `0x46`) carries the
  service-record TLV `61` identifying which entry to fetch. The
  TR-side latch stores the returned service-information blob
  (TLV `62` / `E2`) in
  `state.toolkit.last_service_information`. The `0x62` /
  `0xE2` tag also doubles as the IMEISV TLV in PROVIDE LOCAL
  INFORMATION; the parser stashes both interpretations and the
  apply layer picks the right one based on the originating
  command type.
- `queue_declare_service` (round-7) keeps populating
  `state.toolkit.declared_services` so the search/info handlers
  can be replayed against the previously declared records.

### Multi-card terminal (`0x30` / `0x31` / `0x32` / `0x33`)

TS 102 223 §6.4.11..§6.4.14 multi-card proactives:

- `queue_perform_card_apdu` (`0x30`) ships the C-APDU under
  TLV `A4` and overrides the device-identities pair to target a
  specific reader id. Successful TRs latch the R-APDU under
  `state.toolkit.last_card_apdu_response` and record the reader
  id in `last_card_apdu_reader`.
- `queue_power_on_card` (`0x32`) / `queue_power_off_card` (`0x31`)
  add or remove the targeted reader from
  `state.toolkit.powered_card_readers`. Failed responses leave the
  set untouched so a state-machine driving a multi-card flow can
  retry without flipping the membership.
- `queue_get_reader_status` (`0x33`) accepts qualifier `0x00`
  (reader id list) or `0x01` (single reader status). Successful
  TRs concatenate every `E0` reader-information template from the
  response into `state.toolkit.last_reader_status` for offline
  inspection.

### Cell Broadcast / Menu Selection envelope decode (round 11)

Round-11 promotes the previously "record-only" `D2` and `D3`
envelopes to fully decoded latches:

- **3GPP TS 23.041 §9.4.1 Cell Broadcast Download (`D2`).** The
  CB Page TLV (`8C`, fixed 88 bytes) is parsed into the spec
  fields and exposed on `state.toolkit`:
  - `last_cb_serial_number` (bytes 0..1, big-endian).
  - `last_cb_message_id` (bytes 2..3).
  - `last_cb_dcs` (byte 4).
  - `last_cb_page_parameter` (byte 5; high nibble = total
    pages, low nibble = current page).
  - `last_cb_content` (bytes 6..; padding `0x0D` retained).
  - `last_cb_page_raw` always carries the full TLV value so an
    STK applet can re-decode using a vendor-specific path.
  - `cb_pages_received` increments per envelope so a
    multi-page broadcast can be tallied.
- **ETSI TS 102 223 §7.5.6 Menu Selection (`D3`).** The Item
  Identifier TLV (`10` / `90`) is decoded into
  `state.toolkit.last_menu_item_id` and appended to
  `menu_selections`. A standalone Help Request TLV (`15` / `95`,
  zero-length) flips `last_menu_help_request`.

### EF.SPDI + UST service-number correction (round 27)

Round-22 introduced a real spec-correctness bug in
`_encode_ef_ust_default`: the inline comment said
"50 PNN, 51 OPL" and the code therefore set bits **50** and
**51**. Per 3GPP TS 31.102 §4.2.8 those two services are:

* **50** -- *Reserved (and shall be ignored)*
* **51** -- Service Provider Display Information (SPDI)

PNN and OPL are services **45** and **46**. So the simulator
was simultaneously (a) advertising a reserved bit, (b)
advertising SPDI without a backing EF (every read of
`6FCD` would have hit `6A 82`), and (c) failing to advertise
PNN / OPL even though both EFs are seeded.

Round-27 makes EF.UST honest with respect to the on-card
file system:

| Service | TS 31.102 meaning | Round-27 action |
| ------- | ----------------- | --------------- |
| 45 | PLMN Network Name (PNN) | **Set** -- backing EF.PNN seeded since baseline |
| 46 | Operator PLMN List (OPL) | **Set** -- backing EF.OPL seeded since baseline |
| 50 | Reserved | **Cleared** |
| 51 | SP Display Information (SPDI) | **Set + backed** -- new EF.SPDI seed |

`EF.SPDI` (`6FCD`, transparent) is seeded with the empty-list
scaffold `A3 02 80 00` per §4.2.66, so the modem reads a
well-formed TLV before the operator pushes a populated SPDI
record. The pre-existing round-21 baseline test had inherited
the wrong service-number list and was repaired in the same
patch (`tests/test_simcard_gap21_coverage.py`).

### Legacy GSM (CLA=A0) cold-attach compatibility

Some basebands -- particularly older Quectel BG95 / BG96 / EC25
families and Cinterion / Telit derivatives -- still issue 3GPP
TS 11.11 / TS 51.011 ``CLA=A0`` commands during the SIM cold-attach
sequence even when the card answers as a UICC. Two compatibility
hooks keep that boot path unblocked:

1. ``SimulatedSimCardEngine._is_supported_cla`` accepts the
   ``0xA0..0xAF`` family and routes those APDUs through the same
   handlers as the modern ``CLA=00`` surface. INS values overlap
   1:1 between TS 11.11 §9 and TS 102 221 §11, so READ BINARY,
   READ RECORD, VERIFY etc. all dispatch correctly. The upper
   ``0xB0+`` proprietary range still returns ``6E 00``.
2. ``rebuild_runtime_filesystem`` synthesises a ``DF.GSM`` (FID
   ``7F20``) stub under ``MF`` whenever the active profile's image
   does not already supply one. Real-world dual-mode UICCs always
   present this DF so a 2G-style probe succeeds before the modem
   discovers ``ADF.USIM`` via ``EF.DIR``. Profiles imported before
   the SAIP ``genericFileManagement`` consumer landed do not carry
   a 7F20 node; the stub keeps those legacy stores attaching
   cleanly without forcing a re-import.

Regression coverage lives in
``tests/test_simcard_legacy_gsm_modem_attach.py``, which scripts
the captured cold-attach byte sequence through the HIL bridge
wrapper.

### SAIP §8.3.5 explicit `Fcp.linkPath` aliases

The TCA Profile Interoperability v2.3.1 specification carries a
explicit encoding for cross-DF aliases inside the Bound Profile
Package. Every `Fcp` SEQUENCE may include a
`linkPath [PRIVATE 7] OCTET STRING (SIZE (0..8))` field whose body
is the concatenation of 2-byte File Identifiers walking from the MF
down to the file the slot is meant to mirror. A typical operator
BPP carries 30+ of these aliases:

- `ADF.USIM/EF.IMSI` `linkPath = 7F20 6F07` -> `MF/DF.GSM/EF.IMSI`
- `ADF.USIM/EF.AD`   `linkPath = 7F20 6FAD` -> `MF/DF.GSM/EF.AD`
- `ADF.USIM/EF.SPN`  `linkPath = 7F20 6F46` -> `MF/DF.GSM/EF.SPN`
- `ADF.USIM/EF.HPPLMN` `linkPath = 7F20 6F31` -> `MF/DF.GSM/EF.HPLMN`
- `ADF.USIM/EF.SMS`  `linkPath = 7F10 6F3C` -> `MF/DF.TELECOM/EF.SMS`
- `ADF.USIM/EF.SMSP` `linkPath = 7F10 6F42` -> `MF/DF.TELECOM/EF.SMSP`
- `ADF.USIM/EF.MSISDN` `linkPath = 7F10 6F40` -> `MF/DF.TELECOM/EF.MSISDN`
- `ADF.USIM/EF.FDN`  `linkPath = 7F10 6F3B` -> `MF/DF.TELECOM/EF.FDN`
- `ADF.ISIM/EF.SMS / SMSP / SMSR / SMSS` -> `MF/DF.TELECOM/...`
- `ADF.USIM/DF.GSM-ACCESS/EF.Kc / EF.KcGPRS` -> `MF/DF.GSM/EF.Kc / EF.KcGPRS`

The pipeline plumbs the field end-to-end:

1. `SIMCARD/saip_profile.py::_decode_fcp_link_path` consumes the
   `[PRIVATE 7]` OCTET STRING from every FCP, splits it into 2-byte
   FIDs, and stores the upper-case hex tuple on
   `SimProfileFsNode.link_path`. Both the EF-section consumer (PE
   `usim`, `opt-usim`, `isim`, `opt-isim`, `gsm-access`, `telecom`,
   `mf`, `df-...`) and the `genericFileManagement` consumer go
   through the same helper. Empty OCTET STRINGs are mapped to the
   empty tuple per §8.3.5 ("turn this template link file into an
   independent file"); odd-length payloads are dropped silently as
   malformed.
2. `SIMCARD/profile_store.py` round-trips `link_path` through the
   on-disk JSON store as a list of 4-character hex tokens, so a
   profile imported under one process and reloaded under another
   keeps the same alias graph.
3. `SIMCARD/etsi_fs.py` projects `link_path` from
   `SimProfileFsNode` onto `SimFileNode` at
   `rebuild_runtime_filesystem` time, then runs
   `_apply_explicit_file_links_from_profile` BEFORE the Annex H
   mirror. The resolver walks each link MF-down through
   `_resolve_link_path_target`, copies `data`, `records` and
   `structure` from the resolved target into the link slot, and
   syncs the SFI when the slot did not already learn one from the
   FCP. Three invariants protect the issuer:
   - Issuer-supplied content always wins. A slot that already
     carries bytes is treated as "link overridden at creation
     time" and skipped. Same rule the on-card link resolver in
     real cards applies after `CREATE FILE`.
   - Self-references and unresolvable paths are silent no-ops.
     Cycles cannot deadlock the rebuild and a malformed BPP never
     aborts profile activation.
   - Unresolved targets are deferred. Annex H mirror and SAIP
     template defaults still get a chance to populate the slot
     downstream, so a partially decoded BPP degrades gracefully.

The pass is purely a runtime alias resolver: `lifecycle_state`,
`write_acl` and other policy bits stay on the link slot itself
because they are properties of *the alias*, not of the underlying
file.

Regression coverage in `tests/test_simcard_saip_link_path.py` pins
the OCTET-STRING decoder, the runtime resolver, the
"USIM-only EF (no link, no peer) preserved verbatim" contract, and
an end-to-end replay against the operator BPP fixture that asserts
every USIM-side EF.IMSI / EF.AD / EF.SPN / EF.SMS / EF.SMSP /
EF.MSISDN bound to a DF.GSM or DF.TELECOM target now exposes the
canonical bytes through the ADF SELECT path -- including the
production SFI READ BINARY (`00B0870009`) that originally returned
`9000` with an empty body.

### TS 31.102 Annex H "shared EFs" (DF.GSM <-> ADF.USIM mirror)

3GPP TS 31.102 Annex H Table H.1 lists the Elementary Files that
must surface identical content irrespective of whether the modem
is reading them under DF.GSM (legacy SIM context) or ADF.USIM
(modern UICC context). Real-world operator BPPs lean on this
contract heavily: a typical TCA Profile Interoperability §3.5.5
profile only ships the canonical bytes of EF.IMSI (`6F07`),
EF.AD (`6FAD`), EF.LOCI (`6F7E`), EF.FPLMN (`6F7B`), EF.SPN
(`6F46`), EF.LI (`6F05`), EF.HPLMN-related EFs and a handful of
others under DF.GSM, and registers an empty FCP-only stub under
ADF.USIM. Real cards then mirror the bytes between the two DF
contexts at runtime.

`SIMCARD/etsi_fs.py::_mirror_shared_efs_between_df_gsm_and_adf_usim`
implements that mirror as a final pass inside
`rebuild_runtime_filesystem`. The pass:

1. Walks every EF child of `MF/DF.GSM` and keeps the ones whose
   FID is in `_TS_31_102_ANNEX_H_SHARED_EFS` (the curated subset
   of Annex H Table H.1 that modems actually probe on cold attach
   -- IMSI, AD, ECC, LOCI, FPLMN, SPN, LI, HPLMN, GID1/GID2, PUCT,
   PSLOCI, EPSLOCI, EPSNSC, NETPAR, PNN, OPL, MBDN, CFIS, ACC).
2. For every ADF whose label / name resolves to USIM, walks the
   subtree and matches each EF by FID against the DF.GSM table.
3. Mirrors `data`, `records` and `structure` from DF.GSM into
   the USIM-side EF -- but **only** when the USIM-side EF is
   genuinely empty (no `data` bytes and no non-empty records).

The USIM-side payload is never overwritten when the issuer
explicitly populated it, so an operator that ships distinct
USIM-side bytes keeps full authority. Unknown 6Fxx FIDs that
happen to coexist under both DFs (vendor-private EFs, repurposed
slots) are left untouched because they are not in the shared-EF
table.

This is the fix that unblocks the production HIL trace where
`READ BINARY` against EF.IMSI under ADF.USIM (issued by the modem
via SFI=0x07 selection mode) used to return `9000` with no body
once the operator BPP overrode the lab default. Regression
coverage lives in `tests/test_simcard_shared_ef_mirror.py`,
including a slot that replays the SFI READ BINARY against the
real `89880000000466311335` BPP fixture.

### TCA Profile Interoperability §3.5 / §9 template default fill-in

After the Annex H mirror has run, `rebuild_runtime_filesystem`
calls `_apply_saip_template_defaults_to_runtime` to layer in the
**SAIP / TS 31.102 §9 template default values** for every EF the
issuer left as a skeleton FCP. Operator BPPs routinely register a
`createFCP` for files like `EF.AD`, `EF.HPPLMN`, `EF.PSLOCI`,
`EF.LOCI`, `EF.EPSLOCI`, `EF.START-HFN`, `EF.THRESHOLD`,
`EF.Keys`, `EF.KeysPS`, `EF.FPLMN`, `EF.NETPAR`, `EF.EPSNSC`,
`EF.PL`, `EF.UMPC`, ... without any matching `fillFileContent`,
because the TCA Profile Interoperability §3.5 contract says the
card materialises the template default at runtime. Without this
pass the modem reads `9000` with an empty body, which historically
caused `00B0830004` (SFI=0x03 -> EF.AD) to return `6A82` -- the EF
existed in the FCP tree but had no SFI registered because the
issuer never spelled it out.

The pass builds a one-shot `(parent_DF_runtime_name, FID) ->
FileTemplate` registry from pySim's
`FilesAtMF`, `FilesUsimMandatory[V2]`, `FilesUsimOptional[V2|V3]`,
`FilesIsimMandatory`, `FilesIsimOptional[v2]`,
`FilesUsimDfGsmAccess`, `FilesUsimDf5GS[v2|v3|v4]`,
`FilesUsimDfSaip` and `FilesTelecom` tables (i.e. the ANNEX A
"File Structure Templates Definition" tables of the SAIP /
TCA Profile Interoperability v2.3.1 specification). For every EF
node it then:

1. **Synchronises FCP metadata always.** Missing `sfi` is copied
   from the template (e.g. EF.AD = 0x03, EF.IMSI = 0x07,
   EF.HPPLMN = 0x12, EF.UST = 0x04). Missing `structure` is set to
   `transparent` / `linear-fixed` / `cyclic` / `ber-tlv` based on
   the template's `file_type`. SFI sync runs even when the issuer
   supplied content because SFIs are FCP-level metadata, not
   payload, and the modem's short-form `READ BINARY` (TS 102 221
   §11.1.4) silently breaks without them.
2. **Skips data fill-in when the EF already has bytes.** Issuer
   bytes (BPP `fillFileContent` overrides, Annex H mirror) always
   win. The fill-in only fires when both `data` is empty and every
   record is empty.
3. **Refuses to fabricate `content_rqd=True` EFs.** Template
   entries marked `content_rqd=True` (EF.IMSI, EF.UST, EF.SPN,
   EF.ECC, EF.GID1/2, EF.ACC, EF.EST, EF.PNN, EF.OPL, EF.MBDN,
   ...) are intentionally left empty so a broken BPP fails fast
   instead of letting the modem attach with stale lab content.
4. **Expands the default pattern to the FCP-declared size.**
   Patterns like `FF...FF`, `00FF...FF`, `07FF...FF` are passed
   through pySim's `FileTemplate.expand_default_value_pattern(length)`
   so the rendered bytes match the issuer-side byte-perfect view.

Order of layering inside `rebuild_runtime_filesystem` is
`default tree -> BPP overrides -> explicit Fcp.linkPath aliases ->
DF.GSM<->ADF.USIM Annex H mirror -> SAIP template defaults`, so
issuer intent at every level survives intact and only genuinely
empty slots get the spec default. The Annex H mirror sits behind
the explicit-link pass so a BPP that uses the modern §8.3.5
`linkPath` encoding does not get its targets shadowed by the older
convention-based mirror, and the template defaults sit last so any
slot still empty after both alias passes still materialises with
spec-correct bytes.

Regression coverage in
`tests/test_simcard_saip_template_defaults.py` pins the registry
shape, the fill-in invariants (issuer wins, `content_rqd=True`
never auto-populated, SFIs always synced), and an end-to-end
replay of the `89880000000466311335` cold-attach SFI `READ BINARY`
sequence (`00B0830004` -> EF.AD `00000002`, `00B0870009` ->
EF.IMSI from BPP, `00B0920001` -> EF.HPPLMN).

### pySim integration (Phases A-E)

`SIMCARD/saip_pysim_specs.py` is the bridge between the simulator
and the upstream pySim SAIP toolkit. It is intentionally
fail-soft: every helper degrades to a no-op when pySim is not
installed so the simulator continues to boot in stripped
deployments.

| Phase | Surface                          | Helper / module                                                                | Test suite                                     |
| ----- | -------------------------------- | ------------------------------------------------------------------------------ | ---------------------------------------------- |
| A     | `_FILE_SPECS` template overlay   | `apply_pysim_augmentations`, `pysim_alias_specs_for`                            | `tests/test_simcard_file_specs_registry.py`     |
| B     | FCP descriptor decoding          | `decode_fcp_attributes` (wraps `pySim.esim.saip.File.from_fileDescriptor`)      | `tests/test_simcard_saip_fcp_decoder.py`        |
| C     | `ProfileElement*` consumers      | `pysim_pe_wrapper`, `pysim_sd_keys`, `pysim_normalize_aka_decoded`              | `tests/test_simcard_saip_pe_wrappers.py`        |
| D     | `genericFileManagement` walker   | `pysim_gfm_walk` + `_materialize_gfm_via_pysim` + local fallback                | `tests/test_simcard_saip_gfm_walker.py`         |
| E     | TS service-name tables           | `pysim_service_table`, `apply_pysim_service_table_overlay_to_inspector`         | `tests/test_simcard_saip_service_tables.py`     |

The template-overlay layer lifts pySim's `ProfileTemplateRegistry` snapshots
(`FilesAtMF`, `FilesUsimMandatory[V2]`, `FilesUsimOptional[V2|V3]`,
`FilesIsimMandatory`, `FilesIsimOptional[v2]`, `FilesUsimDfGsmAccess`,
`FilesUsimDf5GS[v2|v3|v4]`, `FilesUsimDfSaip`, `FilesTelecom`)
into the simulator's flat `_FILE_SPECS` table without touching
hand-curated parent-context anchors. `pysim_alias_specs_for`
keys aliases by `(FID, canonical EF name)` so files that share a
FID across DFs (`ef-pbc` 4F09 in DF.PHONEBOOK vs `ef-supinai`
4F09 in DF.5GS) cannot collide.

The FCP-decoder layer routes every BPP / GFM `fileDescriptor` blob through
`pySim.esim.saip.File.from_fileDescriptor`, then projects the
result onto `FcpAttributes` (typed dataclass with `fid_hex`,
`structure`, `arr`, `lcsi`, `fill_pattern`, `link_path`, ...).
SFI assignments still flow from the template-overlay layer --
pySim stores the raw `shortEFID` byte rather than the unpacked
SFI defined by TS 102 221 §13.2, so descriptor-derived SFIs are
deliberately not used to populate `SimProfileFsNode.sfi`.

The PE-wrapper layer wraps `pinCodes`, `pukCodes`, `securityDomain`,
`rfm` and `akaParameter` PEs through `pysim_pe_wrapper`, which
constructs the matching pySim subclass and runs `_post_decode`.
`pysim_sd_keys` returns frozen `PySimSdKeySnapshot`s with the
`KeyUsageQualifier` bit-struct collapsed to a single GP byte and
the `KeyType` enum string mapped to the GP §11.1.8 byte (e.g.
`aes` -> `0x88`). `pysim_normalize_aka_decoded` replays
`ProfileElementAKA._fixup_sqnInit_dec` so the asn1tools
`'0x000000000000'` default for `sqnInit` materialises into the
TS 33.102 §6.3.7 32-element list of 6-byte zeros.

The GFM-walker layer rewrites `_consume_generic_file_management` on top
of `ProfileElementGFM`. `pysim_gfm_walk` replicates pySim's
stream processing (`filePath`, `createFCP`, `fillFileOffset`,
`fillFileContent`, `linkPath` extension) and emits a tuple of
typed `GfmEntry` records. `_materialize_gfm_via_pysim` projects
those onto `SimProfileFsNode`s with canonical path labels and
preserves the simulator's `df_anchor` semantics (a `createFCP`
for DF/ADF promotes the parent chain so subsequent EFs without
an explicit `filePath` resolve under it). The original local
walker is retained as `_consume_generic_file_management_local`
fallback for when pySim is absent or returns an empty walk.

The service-table layer replaces the inspector's hand-curated bit -> name
dictionaries (`Tools/ProfilePackage/saip_asn1_decode._UST_SERVICE_NAMES`,
`_EST_SERVICE_NAMES`, `_ISIM_SERVICE_NAMES`) with the
authoritative pySim maps (`pySim.ts_31_102.EF_UST_map`,
`EF_EST_map`, `EF_5G_PROSE_ST_map`, `pySim.ts_31_103.EF_IST_map`,
`pySim.ts_51_011.EF_SST_map`). The overlay is applied at
`SIMCARD.saip_profile` import time via
`apply_pysim_service_table_overlay_to_inspector`, so a live-card
dump and a SAIP-inspector pass annotate the same bit indices
with the same service strings. Local-only entries (e.g. the
inspector's MexE / VST / MST / CSIM tables for which pySim has
no upstream equivalent) survive untouched.

### EF.PSISMSC + UST service 91 (round 26)

3GPP TS 31.102 §4.2.81 places `EF.PSISMSC` (`6FE5`) under
`ADF.USIM` to publish the SIP URI of the SM-SC used by
**SM-over-IP** messaging (TS 23.204). The EF is gated by
**EF.UST service 91 ("Support for SM-over-IP")**; round-26
flips the service bit on and seeds a backing record so a
modem keying IMS-SMS discovery off that bit no longer trips
`6A 82`.

| FID  | Name      | Structure              | Default                                                |
| ---- | --------- | ---------------------- | ------------------------------------------------------ |
| `6FE5` | EF.PSISMSC | linear-fixed, 64 B / record | TLV `80 LL 00 <SIP URI>` + `FF` padding (URI rooted in MCC 001 / MNC 01 test PLMN) |

The default URI is shaped per TS 23.003 (`sip:smsc@ims.mnc001.mcc001.3gppnetwork.org`)
so a paired modem reading the EF before any OTA provisioning
gets a well-formed end-point. Operators overwrite the record
via UPDATE RECORD once provisioning lands.

### DF.GSM-ACCESS + EF.Kc / EF.KcGPRS (round 25)

Round-25 closes a third UST/EF coherence gap, this time on the
**USIM** side. `EF.UST` advertises **service 27 (GSM access)**,
which per 3GPP TS 31.102 §4.4.3 obliges the card to expose
`DF.GSM-ACCESS` (`5F3B`) under `ADF.USIM` with at least the two
ciphering-key EFs the modem caches across inter-RAT fallbacks
(5G/4G -> 2G/2.5G).

| FID  | Name        | Structure          | Default                                 |
| ---- | ----------- | ------------------ | --------------------------------------- |
| `5F3B` | DF.GSM-ACCESS | DF                | -                                       |
| `4F20` | EF.Kc       | transparent, 9 B  | 8x `0x00` Kc + CKSN `0x07` ("no key")  |
| `4F52` | EF.KcGPRS   | transparent, 9 B  | 8x `0x00` Kc + CKSN `0x07` ("no key")  |

CKSN value `0x07` is the "no key set" sentinel from TS 24.008
§10.5.1.2. The modem reading either EF before AKA has run sees
the sentinel and triggers a fresh authentication instead of
encrypting traffic with stale state.

### ISIM SMS-storage EFs (round 24)

`EF.IST` byte 0 = `0xFF` also flips on **service 6 (SMS
storage in ISIM)**, **service 7 (SMS status reports in ISIM)**,
and **service 8 (SM-over-IP)** per 3GPP TS 31.103 §4.2.7. As
with round-23's GBA pair, services 6 and 7 require dedicated
EFs under `ADF.ISIM`; round-24 closes that coherence gap.

| FID  | Name    | Structure        | Default                          | Spec |
| ---- | ------- | ---------------- | -------------------------------- | --- |
| `6F3C` | EF.SMS  | linear-fixed, 176 B / record | `0x00` status + 175 B FF padding | TS 31.103 §4.2.13 |
| `6F43` | EF.SMSS | transparent, 2 B | `0x00` last TP-MR + `0xFF` cap-exceeded flag | TS 31.103 §4.2.14 |
| `6F47` | EF.SMSR | linear-fixed, 30 B / record | `0x00` link byte + 29 B FF padding | TS 31.103 §4.2.15 |

Encoders are shared with the USIM-side seeds (rounds 20 / 21),
so a modem reading SMS storage from either app sees the same
default record shape.

### ISIM GBA-supporting EFs (round 23)

`EF.IST` (3GPP TS 31.103 §4.2.7) is seeded with byte 0 = `0xFF`,
which advertises **service 2 (GBA)** as available + activated.
A spec-conformant card with that bit set must also expose the
two GBA storage EFs; previously the simulator was returning
`6A 82` on both, which would stall every bootstrap a paired ME
attempted.

| FID | Name | Structure | Default | Spec |
| --- | --- | --- | --- | --- |
| `6FD5` | EF.GBABP | transparent, 6 bytes | `80 00 81 00 82 00` (empty B-TID / Ks_NAF / Lifetime TLVs) | TS 31.103 §4.2.10 |
| `6FD7` | EF.GBANL | linear-fixed, 28 bytes per record | one all-FF placeholder row | TS 31.103 §4.2.11 |

The empty-TLV scaffold for EF.GBABP gives a deterministic
6-byte read before any successful Ks_NAF derivation, then
allows a normal UPDATE BINARY once the bootstrap completes.
EF.GBANL is structured as a record EF so the modem can append
per-NAF rows via UPDATE RECORD without resizing.

### EF.EHPLMNPI + EF.CFIS seeds (round 22)

Round-22 closes two more spec-mandated EFs that the simulator
was returning ``6A 82`` for:

| FID | Name | Structure | Default | Spec |
| --- | --- | --- | --- | --- |
| `6FDB` | EF.EHPLMNPI | transparent, 1 byte | `0x00` (HPLMN-only display) | TS 31.102 §4.2.84 |
| `6FCB` | EF.CFIS | linear-fixed, 16 bytes | MSP `0x01`, CFU off, 12-byte FF dial body, FF/FF CCP+Ext7 | TS 31.102 §4.2.64 |

`_encode_ef_ust_default` now also flips on:

| Service | Description | Provider in this simulator |
| --- | --- | --- |
| 49 | Call Forwarding Indication Status (CFIS) | EF.CFIS seeded round 22 |
| 71 | Equivalent HPLMN Presentation Indication | EF.EHPLMNPI seeded round 22 |

EF.CFIS records carry the spec-shaped layout (`MSP ID | CFU
status | length | TON-NPI | 10-byte BCD body | CCP | Ext7`) so
modems UPDATE RECORD over the placeholder slot to switch CFU
on without resizing the EF.

### EF.UST service-bit alignment + EF.SMSR / EF.SDN seeds (round 21)

Round-21 finishes wiring up the EFs and envelopes that the
previous two rounds added. Before round-21 the simulator was
serving EF.LND, EF.ICI, EF.OCI, EF.ICT, EF.OCT, EF.SMS,
EF.SMSP, EF.MSISDN and decoding D4 / D5 envelopes -- but the
USIM Service Table (TS 31.102 §4.2.8) didn't advertise the
matching service numbers, so a modem honouring EF.UST would
skip those reads entirely.

`_encode_ef_ust_default` now also enables:

| Service | Description | Provider in this simulator |
| --- | --- | --- |
| 4 | Service Dialling Numbers (SDN) | EF.SDN seeded round 21 |
| 8 | Outgoing Call Information / Timer | EF.OCI + EF.OCT (round 20) |
| 9 | Incoming Call Information / Timer | EF.ICI + EF.ICT (round 20) |
| 10 | SMS storage | EF.SMS (round 20) |
| 11 | SMS Status Reports | EF.SMSR seeded round 21 |
| 12 | SMS Parameters | EF.SMSP (pre-existing) |
| 21 | MSISDN | EF.MSISDN (pre-existing) |
| 30 | Call Control by USIM | D4 envelope decoder (round 19) |
| 31 | MO-SMS Control by USIM | D5 envelope decoder (round 19) |
| 55 | Last Number Dialled | EF.LND (round 19) |

The pre-existing 5G attach baseline (services 19, 27, 33, 38,
50, 51, 122, 124, 125, 126, 129, 130) is kept verbatim.

Two more linear-fixed EFs are seeded under `ADF.USIM` to back
the new service bits:

| FID | Name | Structure | Default | Spec |
| --- | --- | --- | --- | --- |
| `6F47` | EF.SMSR | linear-fixed, 30 bytes | one record: link `0x00` (unused) + 29 × `0xFF` (TPDU pad) | TS 31.102 §4.2.28 |
| `6F49` | EF.SDN | linear-fixed, 22 bytes | one all-FF record | TS 31.102 §4.2.46 |

### Call-history and SMS-storage EFs (round 20)

Round-20 closes the family of EFs that real USIMs always ship
pre-allocated and that the modem reads during voice / SMS init:

| FID | Name | Structure | Default | Spec |
| --- | --- | --- | --- | --- |
| `6F3C` | EF.SMS | linear-fixed, 176 bytes | one record: status `0x00` (free) + 175 × `0xFF` (TPDU pad) | TS 31.102 §4.2.25 |
| `6F80` | EF.ICI | cyclic, 30 bytes (Y=8 alpha + 22-byte body) | one all-FF record | TS 31.102 §4.2.20 |
| `6F81` | EF.OCI | cyclic, 30 bytes | one all-FF record | TS 31.102 §4.2.21 |
| `6F82` | EF.ICT | cyclic, 3 bytes (BE seconds counter) | one zeroed record | TS 31.102 §4.2.22 |
| `6F83` | EF.OCT | cyclic, 3 bytes | one zeroed record | TS 31.102 §4.2.23 |

Round-19 already taught READ RECORD / UPDATE RECORD how to
service cyclic EFs, so the new seeds plug straight into the
existing code path: UPDATE RECORD mode `03` rotates the cyclic
ring on EF.ICI / EF.OCI / EF.ICT / EF.OCT, and the canonical
linear-fixed UPDATE RECORD path handles EF.SMS slots.

### Operator-side envelope decoders (round 19)

Round-19 closes three operator-control envelopes that previously
returned a canned "Allowed, no modification" reply without
actually decoding the body. The simulator now extracts the
spec-anchored TLVs into `SimToolkitState` so an STK applet (or a
test harness watching the state object) can correlate the
intercept without parsing `envelope_history` by hand:

| Envelope | Spec | Decoded fields | Counter |
| --- | --- | --- | --- |
| `D4` Call Control by USIM | TS 31.111 §7.3.1.1 | `last_cc_address` (BCD digits), `last_cc_address_ton_npi`, `last_cc_capability_params` (TLV `07`/`87`), `last_cc_subaddress` (`08`/`88`), `last_cc_location_information` (`13`/`93`) | `cc_envelopes_received` |
| `D5` MO Short Message Control | TS 31.111 §7.3.2.1 / §7.3.2.2 | `last_mo_sms_destination_address` + TON/NPI (first Address TLV = RP-DA), `last_mo_sms_sc_address` + TON/NPI (second Address TLV = RP-OA), `last_mo_sms_location_information` | `mo_sms_envelopes_received` |
| `D8` USSD Download | TS 31.111 §7.3.3 | `last_ussd_download_dcs`, `last_ussd_download_raw`, `last_ussd_download_text` (best-effort decoded via `_decode_text_string`) | `ussd_downloads_received` |

The reply path is unchanged -- each envelope continues to return
the canned `80 01 00` Result TLV ("Allowed, no modification")
because vendor-specific override logic belongs in an STK applet
rather than the simulator core.

### Cyclic record I/O + EF.LND (round 19)

`read_record` and `update_record` previously rejected every
cyclic EF with `69 81` ("command incompatible with file
structure"), forcing tests to fall back on transparent reads.
Round-19 brings the implementation in line with TS 102 221
§11.1.5 / §11.1.6:

- READ RECORD on a cyclic EF accepts modes `02` next, `03`
  previous and `04` absolute. Per Table 11.16, P1 = 0 with mode
  `04` returns the current (most-recent) record.
- UPDATE RECORD on a cyclic EF accepts only mode `03`
  ("previous"). The card overwrites what was the oldest slot and
  rotates the ring so the new record becomes the most-recent
  entry. Other modes return `69 81` to mirror commercial UICC
  behaviour.

`EF.LND` (FID `6F44`, TS 31.102 §4.2.32) is now seeded under
`ADF.USIM` with one all-FF 22-byte record (8-byte alpha + 14-byte
dial body). Modems can immediately READ RECORD against it
instead of getting `6A 82` on the first call-history scan.

### Maintenance-class proactive TR latches (round 18)

Round-18 closes four maintenance-flavoured proactive TRs whose
result codes were either dropped on the floor (SET UP EVENT LIST)
or had no dedicated latch alongside the existing rich-payload
handler (POLLING OFF / TIMER MANAGEMENT / PROVIDE LOCAL
INFORMATION):

| Proactive | Spec | Result attribute | Notes |
| --- | --- | --- | --- |
| `SET UP EVENT LIST` (`0x05`) | TS 102 223 §6.4.16 / §6.6.16 | `state.toolkit.last_set_up_event_list_result` | Was previously not dispatched at all; the event-list registration body went out and the TR was silently swallowed. |
| `POLLING OFF` (`0x04`) | TS 102 223 §6.4.4 / §6.6.4 | `state.toolkit.last_polling_off_result` | The existing `polling_off_active` boolean is still set on success; the result-code latch additionally records terminal-busy / unable outcomes. |
| `TIMER MANAGEMENT` (`0x27`) | TS 102 223 §6.4.27 / §6.6.27 | `state.toolkit.last_timer_management_result` | The existing `_apply_timer_management_response` continues to mutate `timer_table` from the echoed timer-id / timer-value TLVs. |
| `PROVIDE LOCAL INFORMATION` (`0x26`) | TS 102 223 §6.4.15 / §6.6.15 | `state.toolkit.last_provide_local_information_result` plus `last_provide_local_information_qualifier` (echoed request type) | The rich-payload handler keeps populating `imei`, `imeisv`, `language`, `date_time_timezone`, `location_information`, `battery_state`, `access_technology`. |

### Additional USIM EFs (round 18)

Three more attach-relevant EFs are now seeded under `ADF.USIM` so
the modem stops getting `6A 82` on the early PLMN-selection /
network-parameter reads:

| FID | Name | Encoding |
| --- | --- | --- |
| `6F31` | EF.HPPLMN | TS 31.102 §4.2.6. One byte (HPLMN search timer in 6-minute units). Default `0x05` = 30 minutes. |
| `6FC4` | EF.NETPAR | TS 31.102 §4.2.34. 16-byte transparent body for cached network parameters. Default all-FF (no cached state). |
| `6FDC` | EF.LRPLMNSI | TS 31.102 §4.2.86. One byte. Default `0x00` = first attempt after power on (modem will run a full PLMN scan). |

### Event-download apply-side latches (round 17)

Round-17 wires four spec-anchored event downloads that previously
only got as far as parsing -- their decoded TLVs never reached the
apply layer. The parser now extracts Frames Information (`49` /
`C9`) and Card Reader Status (`A0` / `20`) directly off the `D6`
envelope, and `_handle_event_download` ships the values into
`SimToolkitState`:

| Event code | Spec | Latches |
| --- | --- | --- |
| `0x03` Location Status | TS 102 223 §7.4.4 | `last_location_status` (0=normal, 1=limited, 2=no service) + `location_status_changes` events-received counter. |
| `0x06` Card Reader Status | TS 102 223 §7.4.7 | `last_card_reader_status` (raw byte: bits 7..6 present/powered, bits 0..3 reader id) + `last_card_reader_id` (decoded id) + `card_reader_status_events`. |
| `0x09` Data Available (overlay) | TS 102 223 §7.4.10 | When the envelope carries TLV `37` Channel Length, `last_data_available_channel_length`, optional `last_data_available_channel_status` (TLV `38`), and `data_available_events` are latched. The existing browser-termination-cause path on the same code is unaffected. |
| `0x10` Frames Information Change | TS 102 223 §7.4.16 | `last_frames_information` is overwritten with the new TLV `49` blob and `frames_information_changes` increments on every event (including empty payloads, mirroring `display_parameters_changes`). |

The `0x09` overlay accepts envelopes that carry both
`browser_termination_cause` and `channel_length`, so a vendor that
overloads the same opcode for both purposes does not lose either
side of the dispatch.

### User-input proactive TR latches (round 16)

Round-16 closes the user-facing STK proactive TR-side gaps. The
parser now extracts the Text String TLV (`0D` / `8D`) and the
Item Identifier TLV (`10` / `90`) from terminal responses, and
six previously-queueable proactives gained dedicated latches:

| Proactive | Result attribute | Payload attributes |
| --- | --- | --- |
| `DISPLAY TEXT` (`0x21`) | `state.toolkit.last_display_text_result` | -- |
| `GET INKEY` (`0x22`) | `state.toolkit.last_get_inkey_result` | `last_get_inkey_text` (decoded char) + `last_get_inkey_dcs`. No-response / back results preserve the prior text. |
| `GET INPUT` (`0x23`) | `state.toolkit.last_get_input_result` | `last_get_input_text` (decoded string, blank inputs explicitly recorded as `""`) + `last_get_input_dcs`. UCS-2 input is decoded transparently. |
| `SELECT ITEM` (`0x24`) | `state.toolkit.last_select_item_result` | `last_select_item_id` (chosen item byte). Back / no-response keeps the previously chosen id. |
| `SET UP MENU` (`0x25`) | `state.toolkit.last_set_up_menu_result` | -- |
| `SET UP IDLE MODE TEXT` (`0x28`) | `state.toolkit.last_set_up_idle_mode_text_result` | -- |

The Text String decoder honours the standard DCS bytes:
`0x00` / `0x04` 8-bit ASCII, `0x08` UCS-2/BE, falling back to a
best-effort UTF-8 decode for vendor-specific values.

### Voice / SMS USIM EFs (round 15)

Round-15 finishes the attach-ready USIM EF set with the
voicemail trio plus the subscriber MSISDN slot:

| FID | Name | Structure | Encoding |
| --- | --- | --- | --- |
| `6F40` | EF.MSISDN | linear-fixed | TS 31.102 §4.2.40 Mobile Subscriber Number. One 22-byte slot (8-byte alpha + 1 length + 1 TON/NPI + 10 BCD + CCP + EXT5), all-FF so the modem can UPDATE RECORD over it. |
| `6FC9` | EF.MBI | linear-fixed | TS 31.102 §4.2.55 Mailbox Identifier. One 4-byte record `01 00 00 00` -- voicemail points at EF.MBDN slot 1, fax / email / other disabled. |
| `6FC7` | EF.MBDN | linear-fixed | TS 31.102 §4.2.56 Mailbox Dialling Numbers. One 22-byte slot mirroring the EF.MSISDN layout, all-FF (no voicemail dial string yet). |
| `6FCA` | EF.MWIS | linear-fixed | TS 31.102 §4.2.57 Message Waiting Indication Status. One 5-byte record (`00 00 00 00 00`): no waiting flags, no message counters. |

The combined effect: a paired modem reaching for "what's my
phone number / where's my voicemail / are there waiting
messages?" gets deterministic stub values instead of `6A 82`.

### REFRESH / SET UP CALL TR latches (round 15)

Two more long-standing TR-side gaps closed:

| Proactive | Result attribute | Payload attributes |
| --- | --- | --- |
| `REFRESH` (`0x01`) | `state.toolkit.last_refresh_result` | `last_refresh_mode` (qualifier byte echoed; spec values 0x00..0x08) and `refresh_attempts` (monotonic counter incremented per TR irrespective of outcome). |
| `SET UP CALL` (`0x10`) | `state.toolkit.last_set_up_call_result` | `last_set_up_call_address` (digits decoded from TLV `86`) and `last_set_up_call_additional` (Additional Information TLV `1A` / `9A` -- typically a 2-byte network-cause pair). |

Both latches honour failure responses: REFRESH still increments
the attempt counter so a polling tool knows the TR fired even
when the result is `0x32` ("command beyond ME's capabilities");
SET UP CALL stores the cause blob so a follow-up applet can
distinguish "user busy" from "network busy" without re-queueing
the proactive.

### Additional USIM EFs (round 14)

Round-14 closes a pair of long-standing gaps in the attach-ready
ADF.USIM image. A blank simulator now ships these as standard:

| FID | Name | Structure | Encoding |
| --- | --- | --- | --- |
| `6F3E` | EF.GID1 | transparent | TS 31.102 §4.2.10 Group Identifier Level 1. Default `FF FF FF FF`; UPDATE gated on ADM. |
| `6F3F` | EF.GID2 | transparent | TS 31.102 §4.2.11 Group Identifier Level 2. Default `FF FF FF FF`; UPDATE gated on ADM. |
| `6F42` | EF.SMSP | linear-fixed | TS 31.102 §4.2.27 SMS Parameters. One 40-byte slot: 12-byte alpha + parameter-indicators (`FF`) + 12-byte destination + 12-byte SC + PID + DCS + Validity, all initialised to `FF` so the modem is free to UPDATE RECORD. |
| `6F43` | EF.SMSS | transparent | TS 31.102 §4.2.9 SMS Status. Two bytes: TP-MR=`00` and memory-capacity flag=`FF` (no capacity-exceeded notification owed). |

Modems that previously fell back to "no GID" or "no SMSP" paths
now read deterministic stub values; tests that exercise SMS-MO
flows can UPDATE RECORD into EF.SMSP without first having to
seed the EF themselves.

### LAUNCH BROWSER TR latch (round 14)

ETSI TS 102 223 §6.6.21 ``LAUNCH BROWSER`` only echoes a result
code on the TR side -- the follow-on browser-termination cause
arrives separately as event `0x07` (already wired to
`last_browser_termination_cause`). Round-14 adds an independent
result latch:

| Proactive | Result attribute | Notes |
| --- | --- | --- |
| `LAUNCH BROWSER` (`0x15`) | `state.toolkit.last_launch_browser_result` | Records the raw TR result byte (`0x00` = command performed, `0x20+` = terminal-side rejection / busy). |

The latch is independent of `last_browser_termination_cause`, so
tests can distinguish "browser refused to start" (non-zero
launch result) from "browser ran and the user closed it later"
(launch result `0x00`, termination cause set when the BROWSER
TERMINATION envelope arrives).

### Terminal Capability TLV decode (round 13)

ETSI TS 102 221 §11.1.19 ``TERMINAL CAPABILITY`` (CLA=0x80,
INS=0xAA) carries a sequence of optional COMPREHENSION-TLV
items describing terminal-side support. Round-13 decodes the
well-known sub-tags into dedicated ``state.toolkit`` fields so
an applet / test can answer "does the terminal advertise
extended logical channels?" without walking the raw blob list:

| Sub-tag | Latched into | Meaning |
| --- | --- | --- |
| `0x80` | `terminal_power_supply` | TS 102 221 §11.1.19 byte 0 (logical-channel power class). |
| `0x81` | `terminal_extended_logical_channels` | Maximum number of additional channels (`0xFF` = at least 19). |
| `0x83` | `terminal_additional_interfaces` | Additional Interfaces Support (raw blob; varies per terminal). |
| `0x87` / `0xA1` | `terminal_euicc_capabilities` | SGP.22 §3.4.2 eUICC related capabilities (RSP version + SVN). |
| `0xA9` | `terminal_eutran_secure_channel` | E-UTRAN secure-channel keyset hint (raw blob). |

The raw payload is still appended to ``terminal_capabilities``
so existing introspection paths keep working. Truncated TLVs
abort the loop without crashing the dispatcher.

### Additional ISIM EFs (round 13)

Round-13 augments the ADF.ISIM tree (FID `7FF2`) with two more
spec-mandated EFs:

| FID | Name | Structure | Encoding |
| --- | --- | --- | --- |
| `6F07` | EF.IST | transparent | TS 31.103 §4.2.7 service table. Byte 0 advertises bits 1..8 = 0xFF (P-CSCF address, GBA, HTTP Digest, GBA local key establishment, P-CSCF discovery for IMS LBO, SM storage, SM status reports, SM-over-IP). |
| `6F09` | EF.PCSCF | linear-fixed | TS 31.103 §4.2.8 record format `80 LL <type><address>` where the type byte (`00`) marks the address as an FQDN. The seeded record advertises `pcscf.<realm>` derived from the IMPI. |

The new EFs are registered for both fresh boots and downloaded
profiles, so a paired modem can run IMS bootstrap without
external provisioning.

### MORE TIME / POLL INTERVAL TR latches (round 13)

ETSI TS 102 223 §6.4.2 ``MORE TIME`` and §6.4.3 ``POLL INTERVAL``
were already queueable but lacked dedicated TR-side handlers.
Round-13 wires both:

| Proactive | Result attribute | Payload attribute |
| --- | --- | --- |
| `MORE TIME` (`0x02`) | `state.toolkit.last_more_time_result` | -- |
| `POLL INTERVAL` (`0x03`) | `state.toolkit.last_poll_interval_result` | `last_poll_interval_negotiated_seconds` (decoded from TLV `04` / `84` Duration) + `last_poll_interval_negotiated_raw` (raw 2-byte value). |

`POLL INTERVAL` decodes the Duration TLV (TS 102 223 §8.8) per
the unit byte: `0x00` minutes, `0x01` seconds, `0x02`
tenths-of-second. Failed TRs reset the duration cache so a
subsequent test can distinguish "terminal accepted some
cadence" from "terminal rejected the request".

### IMS AKA via `AUTHENTICATE` P2=0x82 (round 12)

3GPP TS 31.103 §7.1 specifies that the ISIM application performs
its own AKA challenge/response under the same Milenage parameters
as the USIM. Round-12 wires `internal_authenticate(p2=0x82, ...)`
in `SIMCARD/auth.py` so it delegates to `_run_usim_authentication`
verbatim:

- The card decodes RAND / AUTN, runs Milenage f1..f5, returns the
  spec UMTS-AKA response (RES, CK, IK, optionally Kc).
- A paired modem can therefore issue
  `AUTHENTICATE` with P2=0x82 against ADF.ISIM during SIP REGISTER
  challenge handling without a custom carve-out.
- Unknown P2 values still return `6A 86`.

### ISIM EFs (round 12)

Round-12 augments the ADF.ISIM tree (FID `7FF2`, AID
`A0000000871004FF86FF112233445566`) with the three EFs that the
IMS layer of a paired modem expects to read at registration time:

| FID | Name | Structure | Encoding |
| --- | --- | --- | --- |
| `6F02` | EF.IMPI | transparent | UTF-8 NAI (existing) |
| `6F04` | EF.IMPU | linear-fixed | TS 31.103 §4.2.2 record format `80 LL <URI>`, padded to 64 bytes with `0xFF`. Two records seeded: `sip:<impi>` and `tel:+1-555-0100`. |
| `6F03` | EF.DOMAIN | transparent | TLV `80 LL <home realm>`. The realm is extracted from the IMPI suffix when present, else falls back to `ims.mnc001.mcc999.3gppnetwork.org`. |
| `6FAD` | EF.AD (ISIM-side) | transparent | 4 bytes mirroring the USIM-side layout (MS Op Mode, Add'l Info, MNC length). |

These EFs are part of the default profile image, so a fresh
simulator boot already exposes them without requiring custom
provisioning JSON.

### Call-lifecycle event downloads (round 12)

`_handle_event_download` now decodes the three TS 102 223 §7.4.0
.. §7.4.2 call events:

| Event code | Latched into |
| --- | --- |
| `0x00` MT Call | `state.toolkit.last_mt_call_transaction_id` (TLV `1C` / `9C` byte 0), `last_mt_call_address` (TLV `06` / `86` decoded BCD digits), `last_mt_call_subaddress` (TLV `08` / `88` raw). `call_active` is reset to False because the call has only been notified. |
| `0x01` Call Connected | `state.toolkit.last_call_connected_transaction_id`; `call_active` -> True. |
| `0x02` Call Disconnected | `state.toolkit.last_call_disconnected_transaction_id`, optional `last_call_disconnected_cause` (TLV `1A` / `9A` Cause); `call_active` -> False. |

A polling STK applet can therefore correlate the full call cycle
without scraping `event_history`.

### Misc event downloads (round 12)

| Event code | Behaviour |
| --- | --- |
| `0x04` User Activity | `state.toolkit.user_activity_count` increments monotonically. The event carries no payload of interest. |
| `0x0D` Access Technology Change | `state.toolkit.last_access_technology` caches the new RAT byte (TS 102 223 §8.61: `0x00` GSM, `0x03` UTRAN, `0x08` E-UTRAN, `0x0A` NG-RAN). `access_technology_changes` increments only when the value actually changed. The COMPREHENSION-TLV tag `3F` / `BF` is read by a dedicated single-byte / single-length scanner because the BER walker would otherwise mis-parse it as a multi-byte tag (TS 101 220 §7.1.1.1). |
| `0x0E` Display Parameters Change | `state.toolkit.last_display_parameters` caches the raw TLV `46` / `C6` payload; `display_parameters_changes` increments on every event so polling can derive a delta. |

### Proactive terminal-response latches (round 11)

The following proactives now expose a dedicated TR-side latch.
Each latch records the result code (TLV `83` byte 0); commands
that carry payload TLVs additionally cache the spec field they
return:

| Proactive | Result attribute | Payload attribute |
| --- | --- | --- |
| `SEND SS` (`0x11`) | `state.toolkit.last_send_ss_result` | `last_send_ss_response` (TLV `89` SS string raw) + `last_send_ss_additional` (TLV `1A` cause bytes) |
| `SEND USSD` (`0x12`) | `state.toolkit.last_send_ussd_result` | `last_send_ussd_response_text` + `last_send_ussd_response_dcs` (decoded TLV `8A` payload; cleared on TR failure) |
| `SEND SHORT MESSAGE` (`0x13`) | `state.toolkit.last_send_short_message_result` | -- |
| `SEND DTMF` (`0x14`) | `state.toolkit.last_send_dtmf_result` | -- |
| `PLAY TONE` (`0x20`) | `state.toolkit.last_play_tone_result` | -- |
| `LANGUAGE NOTIFICATION` (`0x35`) | `state.toolkit.last_language_notification_result` | -- |

### Display frames (`0x60` / `0x61`)

Round-10 adds the TS 102 223 §6.4.36 / §6.4.37 frame management
proactives:

- `queue_set_frames(frame_identifier, frame_layout, default_frame_identifier)`
  (`0x60`) emits a SET FRAMES command body with TLVs `47` Frame
  Identifier, `48` Frame Layout (§8.80 structured geometry) and
  `49` Default Frame Identifier. The TR latch caches both the
  layout and the default identifier into
  `state.toolkit.last_set_frames_layout` /
  `last_set_frames_default_id` only on success; failed TRs leave
  the previous values untouched. Tag `47` is multiplexed with
  Network Access Name (§8.70); the parser stashes both
  interpretations and the apply layer disambiguates by command
  type.
- `queue_get_frames_status` (`0x61`) emits an empty body. The TR
  carries a Frames Information TLV (`49` / `C9`) that the apply
  layer caches into `state.toolkit.last_frames_information`. The
  parser interprets a single-byte `49` as a default-frame
  identifier (proactive context) and a multi-byte `49` as the
  Frames Information blob (TR context).

### Event Download additions

Round-8 extends `_handle_event_download` with three event codes
from TS 102 223 §7.4.10 / §7.4.12:

| Event code | Latched into |
| --- | --- |
| `0x0A` SS event   | `state.toolkit.last_ss_event_data` (TLV `89` payload) |
| `0x0B` USSD event | `state.toolkit.last_ussd_event_data` + `last_ussd_event_dcs` (TLV `8A` byte 0 = DCS, bytes 1.. = text) |
| `0x0C` Local Connection | `state.toolkit.local_connection_active` -- True when TLV `40` byte 0 high nibble = `0x80` (established), False on `0x00` (terminated) |
| `0x13` HCI Connectivity (round-9) | `state.toolkit.hci_connectivity_active` -- shares TLV `40` decoding with Local Connection: high nibble `0x80` marks the HCI gate as connected, `0x00` as disconnected |
| `0x16` Contactless State Request (round-10) | `state.toolkit.contactless_active` -- TLV `40` high nibble `0x80` activates the contactless front-end, `0x00` deactivates it |
| `0x18` IMS Registration (round-10) | `state.toolkit.ims_registered` from TLV `B9` byte 0 (`0x01` registered, `0x00` deregistered) and `state.toolkit.last_ims_event_data` from the optional registered URI (TLV `BA`) |
| `0x19` IMS Incoming Data (round-10) | `state.toolkit.last_ims_event_data` -- IMS / SIP payload from TLV `BA` |

`last_event_code` is still the most recently observed event so
existing telemetry that polls a single field keeps working.

### RUN AT COMMAND terminal-response latch (round-9)

`ToolkitLogic.queue_run_at_command` already sends the proactive
command (TS 102 223 §6.4.16, type `0x34`) with the AT string under
TLV `A8`. Round-9 wires the matching TR-side decode: the AT
Response (TLV `A9` / context-specific `29`) is parsed into
`response_fields["at_response"]` and dispatched to
`_apply_run_at_command_response`. On success the bytes are cached
in `state.toolkit.last_at_response` and a best-effort utf-8
decode lands in `state.toolkit.last_at_response_text`; failed TRs
(`result_code != 0`) leave both fields untouched so a polling
applet keeps the previous good reply.

### LAUNCH BROWSER (proactive type `0x15`)

`ToolkitLogic.queue_launch_browser` enqueues a TS 102 223 §6.4.26
LAUNCH BROWSER proactive command. The Annex A TLVs emitted are:

- `30` Browser Identity (1 byte; `0x00` = default browser).
- `31` URL as UTF-8 octets.
- `85` Alpha Identifier (optional).
- `32` Gateway/Proxy text string (optional).

The default qualifier is `0x02` ("use the default URL"); pass
`qualifier=0x03` to force "open URL in the existing browser session"
per §6.6.26. `_parse_proactive_command` round-trips these tags into
`browser_identity`, `browser_url`, `alpha_identifier` and
`browser_gateway_proxy` so terminal-side fixtures can assert the
issued command without re-implementing the TLV walker.

## SAIP profileHeader.connectivityParameters

`SIMCARD/saip_profile.py::_consume_profile_element` captures the
`profileHeader.connectivityParameters` field verbatim and stores it on
`SimProfileImage.connectivity_params_http`. `SIMCARD/profile_import.py`
copies the same bytes into `SimProfileEntry.connectivity_params_http`
when the profile is installed, so SGP.32 §5.9.24
`ES10b.GetConnectivityParameters` returns the operator-provided TLV
stream a real card would emit. Both the JSON image (`profile_image.json`)
and the manifest persist the bytes hex-encoded so reboots keep the
mapping stable.

## 5G authentication stack

The 5G authentication surface lives across a small group of dedicated
modules:

| Module | Responsibility |
| --- | --- |
| `SIMCARD/auth.py` | Milenage / TUAK base + `AUTHENTICATE` dispatch |
| `SIMCARD/aka_5g.py` | 5G AKA and EAP-AKA' branch selection, `RES*` derivation |
| `SIMCARD/akma.py` | TS 33.535 `K_AKMA` / `A-KID` derivation |
| `SIMCARD/suci.py` | TS 33.501 §C.3 SUCI Profile A and Profile B encoders |
| `SIMCARD/identity.py` | TS 31.102 §7.1.2.4 `GET IDENTITY` SUCI build path |

The complementary core-side surface lives under `Tools/YggdraCore/`,
which exposes an in-process AUSF / AAnF pair plus a FastAPI loopback
launcher (`YGGDRASIM_5GCORE_MODE=stub`). See the operator-surfaces
table on the [home page](../index.md) for the entry points.
*(post-v1 staging — not part of this release.)*

## Identity files

| Path | Role |
| --- | --- |
| `Workspace/SIMCARD/eim_identity.json` | simulator default BF55 eIM identity |
| `Workspace/SIMCARD/isdr_config.json` | full card-side eIM layout with `eim_entries` |
| `--sim-eim-identity <path>` | one-shot override of the default BF55 identity |

Changing a Local eIM shell identity does not rewrite the simulator's BF55
row. Keep the two sides aligned on purpose.

## State the simulator writes

The simulator persists its card-side state under the writable runtime root.
Per-simulator-instance artifacts include:

- profile store contents
- eUICC store contents (EID, certs, runtime markers)
- BF55 identity selection

## Common recipes

### Launch a live relay against the simulator

```bash
python main/main.py --card-backend sim
# ... in the launcher menu, pick SCP11 Live ...
```

### One-shot local-access load against the simulator

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/test_metadata.json
LOAD-PROFILE
EXIT
EOF
```

with the launcher started in simulator backend mode beforehand.

### Pin a specific card-side eIM identity for a run

```bash
python main/main.py \
    --card-backend sim \
    --sim-eim-identity Workspace/SIMCARD/eim_identity_lab_alpha.json
```

## Pitfalls

- The simulator is not a silicon-grade model. Timing, side-channel, and
  some edge-case error responses are deliberately idealized.
- Simulator state persists unless deliberately reset. Expect state from the
  last session unless the simulator backend is cleared.
- The `SIMCARD` backend is selected through `--card-backend sim` on the
  launcher. Individual subsystem entries do not independently negotiate
  simulator vs PC/SC.

## Related pages

- [Secure Element Primer](../concepts/secure-element-primer.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- [SCP11 Local Access](scp11-local-access.md)
- [SCP11 eIM Local](scp11-eim-local.md)

## Spec anchors

- SGP.32 v1.2 §2.11.1.1 EuiccPackageRequest
- SGP.32 v1.2 §2.11.2.1 EuiccPackageResult
- SGP.32 v1.2 §5.9.1 ES10b.LoadEuiccPackage
- SGP.32 v1.2 §5.9.11 ES10b.RetrieveNotificationsList
- SGP.32 v1.2 §5.9.5 ES10b.eUICCMemoryReset (BF64)
- SGP.32 v1.2 §5.9.15 ES10b.ImmediateEnable (BF5A)
- SGP.32 v1.2 §5.9.16 ES10b.ProfileRollback (BF58)
- SGP.32 v1.2 §5.9.17 ES10b.ConfigureImmediateProfileEnabling (BF59)
- SGP.32 v1.2 §5.9.18 ES10b.GetEimConfigurationData (BF55)
- SGP.32 v1.2 §5.9.20 ES10b.ExecuteFallbackMechanism (BF5D)
- SGP.32 v1.2 §5.9.21 ES10b.ReturnFromFallback (BF5E)
- SGP.32 v1.2 §5.9.22 ES10b.EnableEmergencyProfile (BF5B)
- SGP.32 v1.2 §5.9.23 ES10b.DisableEmergencyProfile (BF5C)
- SGP.32 v1.2 §5.9.24 ES10b.GetConnectivityParameters (BF5F)
- SGP.32 v1.2 §5.9.25 ES10b.SetDefaultDpAddress (BF65)
- SGP.22 v3.1 §5.7.18 ES10b.RemoveNotificationFromList
- SGP.22 v3.1 §5.7.19 ES10c.eUICCMemoryReset (BF34)
- ETSI TS 102 221 §11.1.7 GET CHALLENGE (INS 0x84)
- ETSI TS 102 221 §11.1.7 SEARCH RECORD (INS 0xA2)
- ETSI TS 102 221 §11.1.10 CHANGE PIN (INS 0x24)
- ETSI TS 102 221 §11.1.11 DISABLE PIN (INS 0x26)
- ETSI TS 102 221 §11.1.12 ENABLE PIN (INS 0x28)
- ETSI TS 102 221 §11.1.13 DEACTIVATE FILE (INS 0x04)
- ETSI TS 102 221 §11.1.14 ACTIVATE FILE (INS 0x44)
- ETSI TS 102 221 §11.1.22 SUSPEND UICC (INS 0x76)
- GlobalPlatform Card Spec v2.3.1 §H.2 Card Recognition Data (`66`)
- GlobalPlatform Card Spec v2.3.1 §H.4 IIN (`42`)
- GlobalPlatform Card Spec v2.3.1 §H.5 CIN (`45`)
- GlobalPlatform Card Spec v2.3.1 Amendment B §H.6 Extended Card Resources (`FF21`)
- ETSI TS 102 226 / GP §H Card Production Lifecycle Data (`9F7F`)
- ETSI TS 102 223 §6.4.26 LAUNCH BROWSER (proactive type `0x15`)
- 3GPP TS 31.111 §7.1.1 SMS-PP Download (envelope `D1`)
- 3GPP TS 31.111 §7.1.2 Cell Broadcast Download (envelope `D2`)
- 3GPP TS 31.111 §7.3.1 Call Control by USIM (envelope `D4`)
- 3GPP TS 31.111 §7.3.2 MO Short Message Control (envelope `D5`)
- 3GPP TS 102 223 §7.1.7 Timer Expiration (envelope `D7`)
- 3GPP TS 31.111 §7.3.3 USSD Download (envelope `D8`)
- TCA Profile Interoperability §3.4.2 profileHeader.connectivityParameters
