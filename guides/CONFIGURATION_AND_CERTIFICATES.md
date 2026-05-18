# Configuration and Certificates

Operator guide for every place YggdraSIM consumes operator-owned material:
certificates, private keys, secure-channel keysets, simulator personality
files, identity records, encryption envelopes, and protected diagnostic
inputs.

This is the canonical reference. Other documents (per-folder READMEs,
subsystem pages, the how-to mirror at
[`site-docs/how-to/load-certificates-and-config.md`](../site-docs/how-to/load-certificates-and-config.md))
defer to the schemas and selection rules described here.

> **Treatment of bundled `Workspace/` material.**
> Everything that ships under `Workspace/`, `SCP11/SGP.26_test_Certs/`,
> and the `state/inventory_crypto.json` defaults is **starter material**.
> It exists so the toolkit can boot, run the unit tests, and execute a
> first-light download against the in-tree fake eIM and Local SM-DP+.
> Replace, override, or relocate it before any non-test use.

## Decision tree

Pick the row that matches what you have. The right column is where to
read next.

| You have …                                                                    | Read                                                                        |
| ----------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| operator DPauth / DPpb cert + key for `LOAD-PROFILE` against `ISD-R`          | [§ SCP11 RSP certificates (local-access)](#scp11-rsp-certificates-local-access)         |
| operator DPauth / DPpb cert + key for the eIM local profile-loading path      | [§ SCP11 RSP certificates (eim-local)](#scp11-rsp-certificates-eim-local)               |
| operator-issued eIM signing certificate (for `ADD-INITIAL-EIM` / `ADD-EIM`)   | [§ Local eIM signing certificates](#local-eim-signing-certificates)                     |
| your own simulated card identity (EID, ATR, AIDs, default DP, CI PKID)        | [§ Simulator personality (ISD-R config)](#simulator-personality-isd-r-config)           |
| your own simulated default eIM identity used on first boot                    | [§ Simulator default eIM identity (BF55)](#simulator-default-eim-identity-bf55)         |
| your own SCP03 keyset / KVN / AID / ADM PIN                                   | [§ SCP03 keysets and admin parameters](#scp03-keysets-and-admin-parameters)             |
| OTA / SCP80 secrets keyed per ICCID                                           | [§ SCP80 OTA parameters](#scp80-ota-parameters)                                         |
| SUCI Profile A / B home-network keys for the simulated USIM                   | [§ SUCI key files](#suci-key-files)                                                     |
| K / OPc / AMF / SQN / MCC / MNC / RID for a 5G AKA test subscriber *(post-v1 staging)* | [§ YggdraCore subscription material](#yggdracore-subscription-material)                 |
| ShS-ENC / ShS-MAC / DEK from an EUM database for a failing PCAP               | [§ EUM session-key bundles](#eum-session-key-bundles)                                   |
| an SCP03 / SCP11c session you want re-decoded from a saved pcap               | [§ HIL pcap keybags](#hil-pcap-keybags)                                                 |
| an `ADD-EIM` / profile-download trigger JSON package                          | [§ eIM packages and hotfolder](#eim-packages-and-hotfolder)                             |
| an ICCID / IMSI you want the APDU mutation fuzzer to be allowed to touch     | [§ APDU fuzzer allow-list](#apdu-fuzzer-allow-list)                                     |
| a custom plugin                                                               | [§ Plugins](#plugins)                                                                    |
| a need to encrypt every persisted secret at rest                              | [§ Inventory crypto (`gpg` envelope)](#inventory-crypto-gpg-envelope)                   |
| a need to relocate or freeze the writable runtime root                        | [§ Runtime root and Workspace](#runtime-root-and-workspace)                              |

## Where things live

```
$RUNTIME_ROOT/                              <-- defaults to repo root in source checkouts
                                                or YggdraSIM-data next to the exe in frozen builds
                                                (override: $YGGDRASIM_RUNTIME_ROOT)
├── plugins/                                <-- runtime-loaded plugins (opt-in, see § Plugins)
├── state/
│   ├── device_inventory.sqlite3            <-- per-card SCP03 / SCP80 inventory (encrypted optional)
│   ├── inventory_crypto.json               <-- envelope + recipients config
│   └── inventory_crypto.json.corrupt.<ts>  <-- quarantined config from a bad parse
├── SCP11/
│   ├── SGP.26_test_Certs/                  <-- bundled SGP.26 fixture inventory (test-only)
│   ├── local_access/certs/                 <-- operator drop-ins for LOAD-PROFILE  (see § SCP11 RSP)
│   └── eim_local/
│       ├── certs/                          <-- DPauth/DPpb drop-ins for eIM local
│       └── certs/eim/                      <-- eIM signing certs + OpenSSL templates
└── Workspace/
    ├── SCP03/                              <-- starter SCP03 keys + AID/FID/binds
    ├── SIMCARD/
    │   ├── isdr_config.json                <-- ISD-R / ECASD / MNO-SD personality
    │   ├── eim_identity.json               <-- default BF55 identity (first boot)
    │   ├── sim_quirks.py                   <-- simulator quirks (gated; see env flags)
    │   ├── euicc_store/<EID>/              <-- per-EID persistent eUICC state
    │   └── profile_store/<AID>/            <-- per-profile artifacts
    ├── LocalEIM/
    │   ├── certs/eim/                      <-- mirror of the eIM signing dropzone
    │   ├── certs/addeim/                   <-- AddEim identity sheets + templates
    │   ├── eim_packages/                   <-- AddEim / profile-download trigger JSON
    │   └── eim_identity.json               <-- Local eIM persona
    └── LocalSMDPP/
        ├── profile/                        <-- bound profile packages
        ├── profile/metadata/               <-- per-profile metadata
        └── certs/                          <-- (alias of SCP11/local_access/certs)
```

## SCP11 RSP certificates (local-access)

**Consumer.** `SCP11/local_access` (the `LOAD-PROFILE` shell against
`ISD-R`).

**Drop-in folder.** `SCP11/local_access/certs/`.

**Selection model.** The shell scans both this folder and the bundled
`SCP11/SGP.26_test_Certs/Valid Test Cases/`, then picks the best
matching pair for the card in the following preference order:

1. operator drop-in is preferred over bundled SGP.26 fixtures
2. `DP2auth` / `DP2pb` SGP.26 names are deprioritised in favour of
   `DPauth` / `DPpb`
3. records whose `AKI` already matches `root_ci_ski` win over indirect
   chains
4. variant group / variant name lexical order
5. role / curve / certificate path lexical order

The card-side allow-list comes from `GetEuiccConfiguredData` (the eUICC
publishes its `allowed_ci_pkids`); only certs whose
`root_ci_pkid` lands inside that list are considered. The
`prefer_curve` knob (`NIST` by default) breaks ties between `secp256r1`
and `brainpoolP256r1` material.

**Filenames.** Any readable filename works. The legacy SGP.26 names
remain valid:

- `CERT.DPauth.ECDSA.der`  / `SK.DPauth.ECDSA.pem`
- `CERT.DPpb.ECDSA.der`    / `SK.DPpb.ECDSA.pem`

For non-legacy names, drop a sidecar JSON file beside the certificate
(see schema below). The DPauth pair is **mandatory** for
`AuthenticateServer`. The DPpb pair is **optional** but used when the
local flow signs `PrepareDownload`-side payloads.

**Sidecar schema (`<certificate>.meta.json` or `<stem>.meta.json`).**

| Field               | Type   | Required | Notes                                                                               |
| ------------------- | ------ | -------- | ----------------------------------------------------------------------------------- |
| `role`              | string | optional | `auth` or `pb`. Inferred from the filename when omitted (`*DPauth*`, `*DPpb*`).     |
| `private_key_path`  | string | optional | Absolute, or relative to the certificate's directory. Falls back to `SK.<stem>.pem`. |
| `root_ci_pkid`      | string | optional | Hex SKI. Falls back to the certificate's `AKI`, then to the configured default.     |
| `server_address`    | string | optional | Operator-side SM-DP+ address surfaced into the eIM activation code.                 |
| `smdp_address`      | string | optional | Alias for `server_address`.                                                         |

Worked example. `operator-alpha-auth.cert.der` paired with
`operator-alpha-auth.key.pem`:

```json
{
  "role": "auth",
  "private_key_path": "operator-alpha-auth.key.pem",
  "root_ci_pkid": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
  "server_address": "local.smdpp.operator.example"
}
```

**Verification.**

```bash
yggdrasim-scp11-local-access --cmd "STATUS; CERTS; EXIT"
```

`CERTS` (alias `SMDP-CERTS`) lists every record discovered, marks the
source (`local_override` vs `sgp26_bundle`), and shows which pair the
selector would use against the active card. Add `--json` or `--yaml`
to the verb for machine-readable output.

**Cross-references.**

- Schema fields are defined in [`SCP11/local_access/cert_store.py`](../SCP11/local_access/cert_store.py).
- The hardware-side download recipe lives in
  [`site-docs/how-to/download-a-profile-local.md`](../site-docs/how-to/download-a-profile-local.md).

## SCP11 RSP certificates (eim-local)

**Consumer.** `SCP11/eim_local` (the eIM local profile-loading path).

**Drop-in folder.** `SCP11/eim_local/certs/`.

The drop-in pattern, sidecar fields, fallback rules, and inventory
selector are **identical** to local-access (above) — the eim-local
shell reuses the same record schema. The only behavioural difference is
that the selected `server_address` from the chosen DPauth record is
mirrored into the eIM activation code when the package does not pin a
different `smdp_address`.

**Verification.** The eim-local shell does not expose a dedicated
DPauth / DPpb inventory verb (the selector is exercised silently by
the flow). Use `STATUS` to confirm the runtime state and rely on
`LOAD-PROFILE` succeeding as the functional probe:

```bash
yggdrasim-scp11-eim-local --cmd "STATUS; LOAD-PROFILE; EXIT"
```

For the eIM **signing** inventory under `certs/eim/`, use the
dedicated verb covered in the next section.

## Local eIM signing certificates

**Consumer.** `SCP11/eim_local` for `ADD-INITIAL-EIM` / `ADD-EIM`.

**Drop-in folder.** `SCP11/eim_local/certs/eim/`. Mirrored at
`Workspace/LocalEIM/certs/eim/`.

This zone holds the **signing** certificates the local eIM uses when it
emits `AddEim` payloads, plus optional CA / TLS material. The bundled
`openssl_eim_*.cnf` templates are local generation aids and stay in-tree.

**Selection model.** `EimCertificateStore` (see
[`SCP11/eim_local/eim_cert_store.py`](../SCP11/eim_local/eim_cert_store.py))
loads every `.der` / `.pem` / `.crt` / `.cer` file under the local zone
and the bundled SGP.26 fixtures. Each file is classified as `signing`,
`tls`, or `ci`:

1. metadata `role` wins outright when present
2. files under `**/CI/**` or named `cert_ci_*` are classified as `ci`
3. certificates with `basicConstraints CA:TRUE` or
   `keyUsage keyCertSign` are classified as `ci`
4. names containing `tls` are classified as `tls`
5. everything else is `signing`

When `resolve_signing_record` is asked for a usable signing leaf, the
ordering is:

1. records that match both the card's `allowed_ci_pkids` and the eIM
   identity's `preferred_ci_pkids`
2. records that match `allowed_ci_pkids` only
3. records that match `preferred_ci_pkids` only
4. record whose normalized path equals the identity default
5. records explicitly passed as a fallback path
6. names containing `ACCEPTED` (rep. of an explicit acceptance test)
7. records sourced from the local drop-in directory over SGP.26 bundle
8. records that have a discoverable private key
9. records on the preferred curve
10. records with a non-empty `root_ci_pkids` set
11. lexical fallback (basename, then full path)

**Sidecar schema (`<certificate>.meta.json` or `<stem>.meta.json`).**

| Field                | Type            | Required | Notes                                                                  |
| -------------------- | --------------- | -------- | ---------------------------------------------------------------------- |
| `role`               | string          | optional | `signing`, `tls`, or `ci`. Inferred per the rules above.               |
| `private_key_path`   | string          | optional | Absolute, or relative to the certificate's directory.                  |
| `root_ci_pkid`       | string          | optional | Hex SKI. Single value form.                                            |
| `root_ci_pkids`      | list of strings | optional | List form; merged with the single value.                               |
| `subject_cn`         | string          | optional | Fallback when the X.509 parser cannot produce a Subject CN.            |
| `subject` / `issuer` | string          | optional | RFC 4514 strings; only used when the certificate cannot be parsed.     |
| `curve`              | string          | optional | `NIST` or `BRP`. Falls back to AKI / SKI / curve OID inference.        |
| `ski` / `aki`        | string          | optional | Hex; only used when the certificate cannot be parsed.                  |

The `addeim/` companion directory under both zones holds an
`eim_identity.template.json` plus `SIMULATED_EIM_IDENTITY.md` — the
canonical record sheet for the bundled fake eIM identity. Use the
identity sheet verbatim when registering YggdraSIM as a peer eIM with
another portal; replace every PEM block with operator-owned material
before any non-test use.

**Custodial reminders.**

1. The bundled identity sheet contains **public** PEM blocks only. The
   matching private keys never leave the YggdraSIM host.
2. Production GSMA CI roots must not be dropped here. Use the SGP.26
   Test CI under `Variant O/CI/` for test trust, or your own private
   CI for closed labs.
3. The HSM-backed signer seam (planned, not part of this release) is the
   future home for keys that must stay outside the filesystem
   altogether.

## Simulator personality (ISD-R config)

**Consumer.** The simulated card backend (`SIMCARD/engine.py`).

**File.** `Workspace/SIMCARD/isdr_config.json`.
**Override env var.** `YGGDRASIM_SIM_ISDR_CONFIG` — absolute path.

This file seeds the EID, ATR, AIDs, the default SM-DP+ address, the
eUICC-side allowed CI list, and the SCP03 / SCP80 keysets used by the
**simulated** card (it is independent of the SCP03 admin shell's reader
keyset, see [§ SCP03 keysets and admin parameters](#scp03-keysets-and-admin-parameters)).

**Schema (current shape — first-boot template):**

```json
{
  "eid": "89045967676472615349763031303005",
  "atr_hex": "3B9F96801FC78031A073BE21136743200718000001A5",
  "default_dp_address": "rsp.example.com",
  "root_ci_pkid_hex": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
  "isdr":   { "aid": "A0000005591010FFFFFFFF8900000100", "label": "ISDR"  },
  "ecasd":  { "aid": "A0000005591010FFFFFFFF8900000200", "label": "ECASD" },
  "mno_sd": { "aid": "A000000151000000",                 "label": "MNO-SD" },
  "scp03_keys":     { "kenc_hex": "...", "kmac_hex": "...", "dek_hex": "...", "kvn": 48 },
  "scp80_security": { "spi": "1621", "kic": "15", "kid": "15", "tar": "B00000",
                      "key_enc_hex": "...", "key_mac_hex": "..." },
  "configured_data": {
    "root_smds_address": "lpa.ds.gsma.com",
    "additional_root_smds_addresses": ["smds2.example", "smds3.example"],
    "allowed_ci_pkids_hex":            ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
    "ci_list_hex":                     ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"]
  },
  "toolkit": {
    "poll_strategy":               "timer",
    "timer_management_seconds":    30,
    "timer_management_id":         1,
    "timer_management_auto_rearm": true,
    "poll_interval_seconds":       60,
    "provide_imei":                true,
    "ipa_poll": {
      "enabled":             true,
      "eim_fqdn":            "",
      "eim_port":            443,
      "transport_type":      2,
      "buffer_size":         1024,
      "receive_size":        250,
      "alpha_id":            "",
      "apn":                 "internet.apn",
      "dns_server":          "8.8.8.8",
      "request_payload_hex": ""
    }
  }
}
```

**Field guidance.**

1. `eid` is the 32-hex-digit eUICC identifier (TS 23.003 §10). Choose a
   namespace your lab does not collide with. The shipped default
   `89045967676472615349763031303005` keeps the SGP.02 §2.2.2 telecom MII
   prefix `89`, decodes to `\x89\x04YggdraSIv0100\x05` in any hex viewer
   (so `xxd`/Wireshark captures self-document the build), and carries a
   correct ITU-T E.118 / SGP.22 §4.11.2 Luhn check digit (`5`). Replace
   it before any production-adjacent run.
2. `atr_hex` is replayed verbatim by the simulated reader. Match the
   profile under test (a USIM-only card without a NAA selector should
   not advertise EAP-AKA' capability bits).
3. `default_dp_address` populates the eUICC's `defaultDpAddress` for
   activation-code / RSP flows.
4. `root_ci_pkid_hex` is the SKI the simulator publishes as its single
   default trust anchor. `configured_data.allowed_ci_pkids_hex` and
   `ci_list_hex` extend the published `GetEuiccConfiguredData` view.
5. `scp03_keys` are the **on-card** SCP03 keyset for the bundled MNO-SD
   profile. The reader-side admin keyset is separate (see
   [§ SCP03 keysets and admin parameters](#scp03-keysets-and-admin-parameters)).
6. `scp80_security` defines the static per-card OTA parameters for the
   simulated MNO-SD. The SCP80 admin shell's per-ICCID overrides take
   precedence at runtime.
7. `toolkit` selects the STK proactive bring-up shape and is parsed by
   `SIMCARD/euicc_store.py::apply_euicc_state_payload`:
   - `poll_strategy` — one of `"timer"`, `"poll_interval"`, `"both"`,
     `"off"`. Default `"timer"` arms an ME timer per ETSI TS 102 223
     §6.6.21 (TIMER MANAGEMENT START) so the modem returns a TIMER
     EXPIRATION (D7) envelope on cadence; this is the trigger SGP.32
     IPA-poll relies on. `"poll_interval"` falls back to the legacy
     §6.6.5 POLL INTERVAL heartbeat. `"both"` queues both proactive
     commands at TERMINAL PROFILE. `"off"` emits no proactive bring-up.
   - `timer_management_seconds` — initial timer value (1..86399 s).
   - `timer_management_id` — ETSI timer identifier `1..8`. Out-of-range
     values are clamped.
   - `timer_management_auto_rearm` — when `true` (default), each
     `D7` TIMER EXPIRATION envelope re-queues a fresh TIMER MANAGEMENT
     START so polling continues without applet-side housekeeping.
   - `poll_interval_seconds` — POLL INTERVAL setpoint used when
     `poll_strategy` includes the legacy heartbeat.
   - `provide_imei` — when `true` (default) the bootstrap also queues
     a PROVIDE LOCAL INFORMATION (IMEI) proactive command after the
     timer/poll trigger, mirroring real eUICC bring-up.
   - `ipa_poll` — SGP.32 §3.5 IPA-poll BIP trigger. When enabled
     (default), every TIMER EXPIRATION (`D7`) envelope drives a
     two-leg BIP exchange before the timer re-arms:
     1. **DNS leg** — OPEN CHANNEL UDP_REMOTE → `dns_server:53`,
        SEND DATA AAAA query, SEND DATA A query, RECEIVE DATA × 2,
        CLOSE CHANNEL.
     2. **eIM leg** — OPEN CHANNEL TCP_CLIENT_REMOTE →
        `<resolved_ip>:eim_port`, SEND DATA (ESipa request),
        RECEIVE DATA, CLOSE CHANNEL.

     The eIM leg is only queued once the DNS leg writes a usable
     A-record into `toolkit.ipa_poll_resolved_ip`. The cache
     persists across cycles, so steady-state polling skips the
     DNS leg until the operator clears the cache or a new APN
     forces a re-resolve.

     - `eim_fqdn` — explicit eIM host name. Empty string falls back
       to `state.eim_entries[0].eim_fqdn`, then to the workspace
       `eim_identity.json` default; if all three are empty the
       sequence is skipped (only the timer re-arm is emitted).
     - `eim_port` — TCP destination port for the eIM leg
       (default 443).
     - `transport_type` — TS 102 223 §8.70 protocol code for the
       eIM leg. `2` = TCP CLIENT REMOTE (default). Use `6` if the
       modem firmware demands explicit TLS-over-TCP signalling.
     - `buffer_size` — OPEN CHANNEL TLV `39` value applied to
       both legs (default 1024).
     - `receive_size` — RECEIVE DATA TLV `B7` byte count
       (1..255, default 250).
     - `alpha_id` — Alpha Identifier shown in the modem's STK UI.
       Default empty (matching reference IPA behaviour: the TLV is
       still emitted as `05 00` so the modem can label the
       bearer).
     - `apn` — cellular APN emitted under TLV `47` (Network
       Access Name) on every OPEN CHANNEL. Default
       `"internet.apn"`. Active SAIP profile EF.ACL (`6F57`)
       overrides this when the profile gets enabled (the
       filesystem rebuild copies the first APN into
       `toolkit.ipa_poll_apn` and sets
       `toolkit.ipa_poll_apn_source = "bpp"`). The env override
       `YGGDRASIM_SIM_IPA_POLL_APN` wins when no profile-side APN
       is published.
     - `dns_server` — IPv4 of the public resolver the IPA targets
       in the DNS leg. Default `"8.8.8.8"` (Google). Override via
       env flag `YGGDRASIM_SIM_IPA_POLL_DNS_SERVER` for closed-lab
       deployments with a captive resolver.
     - `request_payload_hex` — explicit hex-encoded body delivered
       under SEND DATA TLV `36` on the eIM leg. Empty (default)
       emits a minimal HTTP/1.1 `POST /gsma/rsp2/asn1` header
       wrapping a `BF4F GetEimPackageRequest`. When
       `tls_enabled` is `true` (the default) the bytes are
       encrypted by the in-card TLS-1.2 engine before they
       reach the bearer.

   The simulator also runs a TLS-1.2 client inside the card on
   the eIM leg by default. The handshake uses
   **ECDHE-ECDSA-AES128-GCM-SHA256** (cipher suite 0xC02B), the
   modem stays a transparent byte pipe between SEND/RECEIVE DATA
   and the eIM, and the chain validator pins
   `eim_identity.json::trusted_tls_cert_path` as the trust
   anchor. The engine falls back to `CERT_NONE` when no anchor is
   configured so an unconfigured workspace still emits valid TLS
   wire bytes for diagnostics; operators tighten the chain by
   populating the eIM identity JSON. Disable the in-card TLS
   path (e.g. when the modem itself terminates TLS) by setting
   `toolkit.ipa_poll.tls_enabled = false`.

**Verification.**

The unified launcher's read-only preflight covers the simulator's
boot path:

```bash
yggdrasim --doctor
```

For a targeted check that the file parses and is consumed by the
simulator, run an SCP03 status probe — the shell prints the resolved
EID, the AIDs the SD wraps to, and reports any keyset mismatch:

```bash
YGGDRASIM_CARD_BACKEND=sim yggdrasim-scp03 --cmd "STATUS; EXIT"
```

## Simulator default eIM identity (BF55)

**Consumer.** The simulated card on first boot, when the card-side
`BF55` eIM identity has not yet been programmed.

**File.** `Workspace/SIMCARD/eim_identity.json`.
**Override env var.** `YGGDRASIM_SIM_EIM_IDENTITY` — absolute path.

```json
{
  "display_name": "Simulator default eIM identity",
  "eim_id": "2.25.311782205282738360923618091971140414400",
  "eim_id_type": "oid",
  "eim_fqdn": "yggdrasim.eim.test.1ot.com",
  "eim_endpoint": "https://yggdrasim.eim.test.1ot.com/gsma/rsp2/asn1",
  "euicc_ci_pk_id": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
  "eim_public_key_cert_path": "",
  "trusted_tls_cert_path": ""
}
```

**Field guidance.**

1. `eim_id_type` accepts `oid`, `fqdn`, or `proprietary`.
2. `eim_public_key_cert_path` and `trusted_tls_cert_path` may stay
   empty for first-light boot. Populate them when you need the
   simulator to publish a bound BF55 identity that downstream `ADD-EIM`
   flows can verify.
3. `euicc_ci_pk_id` must match a CI SKI in
   `isdr_config.json.configured_data.allowed_ci_pkids_hex`.
4. The matching Local eIM identity (used by the local eIM **shell**,
   not by the simulated card) lives at
   `Workspace/LocalEIM/eim_identity.json` and is produced from
   `Workspace/LocalEIM/certs/addeim/eim_identity.template.json`.

## SCP03 keysets and admin parameters

**Consumer.** `SCP03/` admin shell (against either a physical reader or
the simulator's MNO-SD).

**File.** `Workspace/SCP03/keys.ini`.
**Companion files.** `aid.txt`, `fids.txt`, `binds.json` (per-shell
state).
**Shipped seeds.** First-run defaults live under `SCP03/seeds/`
(`keys.ini`, `aid.txt`, `fids.txt`, `binds.json`). They are copied into
`Workspace/SCP03/` exactly once, on first launch, and never overwrite an
existing runtime file. The shipped `keys.ini` carries the publicly-known
GlobalPlatform demo placeholder (`1122334455667788AABBCCDDEEFF0011` and
ADM `3132333435363738`) — replace it before talking to any production
card.

```ini
[KEYS]
enc = 1122334455667788AABBCCDDEEFF0011
mac = 1122334455667788AABBCCDDEEFF0011
dek = 1122334455667788AABBCCDDEEFF0011
kvn = 30
aid = A000000151000000
adm = 3132333435363738

[GOLD_PROFILE]
path =
standard = SGP.32
authenticate_sd = false
```

**Field guidance.**

1. `enc`, `mac`, `dek` are 16-byte keys in lowercase or uppercase hex.
2. `kvn` is decimal; the on-card keyset version. Mismatches between the
   shell and the simulator's
   `isdr_config.json.scp03_keys.kvn` will surface as `INITIALIZE
   UPDATE` failures with `6982` / `6A88`.
3. `aid` is the security-domain AID the shell binds to; defaults to
   the MNO-SD AID.
4. `adm` is the administrative PIN sent by `VERIFY ADM`. Hex.
5. `[GOLD_PROFILE]` configures the optional gold-profile fixture used
   by the lifecycle cheatsheet.

**Per-card overrides.** When the SQLite inventory at
`state/device_inventory.sqlite3` holds a per-card SCP03 record
(keyed by ICCID under namespace `iccid/<ICCID>/scp03`), the
inventory record wins over `keys.ini`. The mapping is populated as
a side effect of running the SCP03 shell against a card: connecting
binds to the active ICCID, and any subsequent `CONFIG` write (the
SCP03 admin wizard for keys / KVN / AID / ADM) lands in both the
module-level state *and* the per-ICCID inventory namespace.

To rotate keys for the active card from inside the shell:

```text
SCP03> CONFIG       # interactive wizard, prompts for ENC/MAC/DEK/KVN/AID/ADM
SCP03> SHOW         # confirm the resolved (SQLite-backed) values
SCP03> EXIT
```

The file-based defaults are the booting fallback only. There is no
top-level `INVENTORY-LOAD` / `INVENTORY-SET-KEYS` verb — the
`CONFIG` / `SHOW` pair is the user-facing surface, with the
SQLite-backed persistence handled implicitly by the shell.

**Encryption posture.** When inventory crypto is enabled
(see [§ Inventory crypto](#inventory-crypto-gpg-envelope)), the
inventory record is encrypted at rest and `keys.ini` is the only
plaintext keyset on disk. Move it inside the encryption envelope by
deleting the `[KEYS]` section once a per-card record exists.

## SCP80 OTA parameters

**Consumer.** `SCP80/` admin shell.

**Per-card primary store.** `state/device_inventory.sqlite3`. Every
ICCID gets its own SCP80 record (SPI / `kic_indicator` / `kid_indicator`
/ TAR / `kic` / `kid` / static counter / `cla` / `sender` / SMS sizing)
under namespace `iccid/<ICCID>/scp80`. Slot semantics follow ETSI TS
102 225 §5.1.1: `kic` / `kid` hold the 16-byte ciphering and integrity
keys; `kic_indicator` / `kid_indicator` hold the 1-byte indicator bytes
that select algorithm + key index in the Command Packet header. The
SCP80 admin shell uses lowercase verbs (`iccid`, `set`, `show`, `quit`)
to manage it:

```bash
yggdrasim-scp80 --cmd "iccid <ICCID>; set kic <16-byte-hex>; set kid <16-byte-hex>; set kic_indicator <hex>; set kid_indicator <hex>; show; quit"
```

Pre-rename ini files using `key_enc` / `key_mac` (and `kic` / `kid` for
the indicator bytes) are auto-migrated on load and rewritten to the
current schema on the next save. A one-shot stderr notice records each
rename so operators can see which legacy keys were translated.

`iccid <ICCID>` binds the shell to a card identity (which loads the
per-ICCID record if one exists, or seeds one from current defaults
otherwise). `set <key> <value>` writes through to the SQLite-backed
record on `quit` / `qa` (or any `save`-triggering exit path).

**Legacy starter file.** `Workspace/SCP80/ota_config.ini` (auto-seeded
from a bundled default on first run) is consulted only when the
inventory has no record for the active ICCID. Treat it as bootstrap
material; the inventory is the source of truth.

**Verification.**

```bash
yggdrasim-scp80 --cmd "iccid <ICCID>; show; quit"
```

## SUCI key files

**Consumer.** `Tools/SuciTool` (the SUCI helper shell) and the
simulated USIM (when answering `GET IDENTITY` and emitting SUCI Profile
A / B output).

**Selection model.** The shell holds a single active key file, set
through `USE <path>`; the path is resolved relative to the runtime
workspace. `STATUS` shows the active selection. The external
`suci-keytool` binary is consulted to generate keys; configure or
override the binary path with the `TOOL` verb.

```text
yggdrasim-suci-tool --cmd "USE keys/operator-alpha.key; STATUS; DUMP; EXIT"
```

**Curves.** `secp256r1` (Profile A), `curve25519` (Profile B).

**Custodial guidance.**

1. SUCI key files are short — 32 bytes of private material. Treat them
   as keys, not as configuration: 0600 on disk, exclude from any
   inventory exports, and rotate per the operator's home-network
   policy.
2. The simulated USIM's response to `AUTHENTICATE` for SUCI uses the
   same private material. When the simulator advertises a different
   home-network identity than the SUCI tool's active key, downstream
   verifiers will reject the resulting SUCI.

## YggdraCore subscription material

> **Status: post-v1 staging.** Not part of the v1.0.0 frozen release tag.

**Consumer.** The in-process AUSF / AAnF stubs under `Tools/YggdraCore/`.

**Storage.** Process-local
([`Tools/YggdraCore/subscription_store.py`](../Tools/YggdraCore/subscription_store.py)).
There is no on-disk format; subscriber records live for the lifetime of
the launcher.

**Schema.** `SubscriptionRecord` requires:

| Field               | Type   | Length     | Notes                                                                |
| ------------------- | ------ | ---------- | -------------------------------------------------------------------- |
| `supi`              | string | 1..256     | Identifies the subscriber (`imsi-MCCMNCMSIN` form is conventional).  |
| `k`                 | bytes  | 16         | Subscriber key (TS 35.205).                                          |
| `opc`               | bytes  | 16         | Operator-variant constant.                                           |
| `amf`               | bytes  | 2          | Authentication management field.                                     |
| `sqn`               | bytes  | 6          | Sequence number; bumped per successful authentication.               |
| `mcc`               | string | 3 digits   | Mobile country code.                                                 |
| `mnc`               | string | 2..3 digit | Mobile network code.                                                 |
| `routing_indicator` | string | 1..4 digit | RID for SUCI / SUPI routing (TS 23.003).                             |
| `akma_enabled`      | bool   | -          | Mirrors the AKMA indication the UDM would send the AUSF.             |

**Seeding from a script.**

```python
from Tools.YggdraCore.subscription_store import get_default_subscription_store

store = get_default_subscription_store()
store.upsert(
    supi="imsi-001010000000001",
    k=bytes.fromhex("0123456789ABCDEFFEDCBA9876543210"),
    opc=bytes.fromhex("CD63CB71954A155A5DC83A7BFD11A41C"),
    amf=b"\x80\x00",
    sqn=b"\x00\x00\x00\x00\x00\x01",
    mcc="001",
    mnc="01",
    routing_indicator="0",
    akma_enabled=True,
)
```

**Bring-your-own Open5GS.** When `YGGDRASIM_5GCORE_MODE=byo`, the
[`open5gs_bridge`](../Tools/YggdraCore/open5gs_bridge.py) provisions the
same record into a real Open5GS subscriber database via `pymongo`. The
caller selects the Mongo URI and database name through the bridge's
constructor; no environment file is consulted.

**Custody.** `K` and `OPc` are long-term subscriber secrets. The stub
keeps them in process memory only; `public_view()` redacts both. When
moving to the BYO bridge, the destination Mongo database is the
authoritative store — protect it accordingly.

## EUM session-key bundles

**Consumer.** `Tools/EumDiag` (the EUM / SM-DP+ diagnostic tool) and
the bundled Lua dissector at
[`Tools/EumDiag/dissector.lua`](../Tools/EumDiag/dissector.lua).

**File.** A JSON repository chosen by the operator. The dissector
locates it through `YGGDRASIM_EUM_SESSION_KEYS=<absolute path>`.

**Schema.** `yggdrasim-eum-session-keys/v1` — an ICCID-indexed object:

```json
{
  "format": "yggdrasim-eum-session-keys/v1",
  "entries": {
    "8901260000000000001": {
      "iccid": "8901260000000000001",
      "shs_enc_hex": "AABBCCDDEEFF00112233445566778899",
      "shs_mac_hex": "00112233445566778899AABBCCDDEEFF",
      "dek_hex":     "0F0E0D0C0B0A09080706050403020100",
      "comment":     "Operator alpha — failing download 2026-04-12"
    }
  }
}
```

**Field guidance.**

1. `shs_enc_hex` and `shs_mac_hex` are AES-128, 16 bytes each.
2. `dek_hex` is optional; populate it when the BPP includes PPR
   elements protected by a DEK.
3. The repository writer (`yggdrasim-eum-diag store-keys`) chmods the
   file to `0600` on POSIX. Any group/other-readable mode is reported
   on load.

**Authoring.**

```bash
yggdrasim-eum-diag store-keys \
    --iccid 8901260000000000001 \
    --shs-enc AABBCCDDEEFF00112233445566778899 \
    --shs-mac 00112233445566778899AABBCCDDEEFF \
    --dek 0F0E0D0C0B0A09080706050403020100 \
    --keys-out ~/secrets/eum-keys.json
```

**Replaying through tshark.** `inject-keys` accepts either the
per-bundle CLI flags or `--bundle-file <repo>`; the latter is
preferred when the repository was authored ahead of time:

```bash
export YGGDRASIM_EUM_SESSION_KEYS=~/secrets/eum-keys.json
yggdrasim-eum-diag inject-keys \
    --bundle-file ~/secrets/eum-keys.json \
    --pcap ~/captures/failing-example.pcapng
```

For pure offline BPP decoding without a pcap, use `decode-bpp --bpp
<bf36.der> --keys <repo>`.

**Custody.** ShS-ENC / ShS-MAC are session secrets, but they are
sufficient to decrypt the per-session BPP traffic. Treat the
repository file the same as a long-term key bundle: keep it on the
analyst host only, never inside a shared CI runner.

## HIL pcap keybags

**Consumer.** `Tools/HilBridge.live_decode_tui` and `scp_replay.py`
when re-opening a saved pcap.

**File.** `<pcap>.keys.json` (or `<pcap-stem>.keys.json`), produced by
the `EXPORT-KEYBAG` shell verb or the `--dump-keybag` CLI flag.

**Schema.** `KeybagExportEntry` (see
[`Tools/HilBridge/scp_keybag_export.py`](../Tools/HilBridge/scp_keybag_export.py))
serialised as a list of session entries. Each entry holds:

| Field                        | Type    | Notes                                                  |
| ---------------------------- | ------- | ------------------------------------------------------ |
| `label`                      | string  | Free-form tag for the session (`scp03-live`, etc.).    |
| `protocol`                   | string  | `scp03` or `scp11c`.                                   |
| `s_enc_hex`                  | string  | Session ENC key (hex).                                 |
| `s_mac_hex`                  | string  | Session MAC key (hex).                                 |
| `s_rmac_hex`                 | string  | Session R-MAC key (hex). May be empty.                 |
| `match_aid_hex`              | string  | AID the session is bound to.                           |
| `match_card_session_index`   | integer | Card-side session index (when known).                  |
| `match_first_frame`          | integer | Pcap frame index where this session starts.            |
| `initial_ssc`                | integer | Initial SSC for SCP03.                                 |
| `initial_chaining_hex`       | string  | Chaining state seed (hex). Defaults to `00..00`.       |

**Auto-discovery.** The replay TUI looks for a sibling
`<pcap>.keys.json` (and `<pcap-stem>.keys.json`) before falling back
to a `--keybag` argument. Drop the keybag next to the pcap and no
extra flags are needed.

**Custody.** Session keys are short-lived but still grant full plaintext
visibility into the pcap. Delete the keybag when the diagnostic is done.

## eIM packages and hotfolder

**Consumer.** `SCP11/eim_local` (the eIM local shell).

**Folders.**

- `SCP11/eim_local/eim_packages/` — operator-authored package library.
- `SCP11/eim_local/eim_packages/templates/` — package templates.
- `SCP11/eim_local/eim_packages/hotfolder/` — runtime queue ingested
  by `HOTFOLDER-FETCH`.

**Package shape.** JSON object with the fields listed in
`SCP11/eim_local/eim_packages/README.md`. The most common operator
fields are:

| Field                 | Notes                                                                          |
| --------------------- | ------------------------------------------------------------------------------ |
| `package_type`        | `add_initial_eim`, `add_eim`, `profile_download_trigger`, etc.                 |
| `package_version`     | `1`.                                                                           |
| `spec_target`         | `SGP.32`.                                                                      |
| `cert_der_path`       | Operator-provided certificate file (PEM and DER both accepted).                |
| `profile_path`        | BPP path for download triggers.                                                |
| `bip_endpoints`       | `eim`, `smdpp` HTTPS endpoints.                                                |
| `optional_tags`       | `include`, `tag_hex`, `value_hex` triples for spec-defined optional TLVs.      |
| `additional_tlvs`     | Same shape as `optional_tags`, used for vendor-specific extensions.            |

**Queueing rules.** The effective hotfolder queue merges fixed poll
fixtures with any `.json` files under the hotfolder directory, ordered
by `runtime.queue_id`, then top-level `queue_id`, then
`runtime.transaction_id_hex`, then numeric filename prefix, then
lexical fallback. Exposure verbs:

```text
HOTFOLDER-LIST [dir]   # preview
HOTFOLDER-POLL [dir]   # JSON for external harness integration
HOTFOLDER-FETCH [dir]  # execute the queue
```

## APDU fuzzer allow-list

**Consumer.** `Tools/ApduFuzz` (the opt-in APDU mutation fuzzer).

**Configuration model.** Command-line only. No file is consulted.

| Flag                    | Purpose                                                                  |
| ----------------------- | ------------------------------------------------------------------------ |
| `--i-mean-it`           | Hard gate. Required before any APDU is sent.                             |
| `--allow-iccid <ICCID>` | Allow-list a card ICCID. Repeatable.                                     |
| `--allow-imsi <IMSI>`   | Allow-list an IMSI. Repeatable.                                          |
| `--crash-dump-root <dir>` | Override the directory crash dumps land in (defaults under runtime root). |

The fuzzer aborts before sending the first APDU when the `i-mean-it`
gate is missing or when the card identifier is not in the allow-list.
**Never** point the fuzzer at a production card.

## Plugins

**Consumer.** The unified launcher's plugin runtime.

**Folder.** `<runtime-root>/plugins/`.

**Loading model.**

1. Plugins load by default since the loader-default flip; opt out with
   `YGGDRASIM_ALLOW_PLUGINS=0` or hard-lock with
   `YGGDRASIM_DISALLOW_PLUGINS=1` (intended for attestation / CI /
   air-gapped builds).
2. Each plugin lives in its own subdirectory with a manifest. See
   [`site-docs/how-to/write-a-plugin.md`](../site-docs/how-to/write-a-plugin.md)
   for the manifest schema and lifecycle.
3. Plugins are imported at launcher startup. Changing the env flag in
   a running process does **not** retroactively load or unload plugins.

## Inventory crypto (`gpg` envelope)

**Consumer.** Anything that goes through
[`yggdrasim_common.inventory_crypto`](../yggdrasim_common/inventory_crypto.py)
— the SQLite inventory writer, the cert store sidecar reader, and the
SCP03 / SCP80 secret writers.

**File.** `state/inventory_crypto.json`.

```json
{
  "enabled": false,
  "provider": "gpg",
  "plaintext_fallback_writes": false,
  "gpg": {
    "binary": "gpg",
    "gpg_key_file": "",
    "recipients": [],
    "timeout_seconds": 120
  }
}
```

**Field guidance.**

1. `enabled` flips the envelope on. When `true`, every secret write
   goes through `gpg --encrypt`. Plaintext reads are still accepted (so
   an existing unencrypted file stays readable), and a re-write through
   the secret-write path will rewrap it.
2. `provider` is `gpg` today. The seam exists for future providers
   (PKCS#11, KMS); requesting any other value raises.
3. `plaintext_fallback_writes` is a strict-mode escape hatch. When the
   gate is `false` (the default) and the GPG provider is ready, the
   writer **refuses** to drop plaintext on disk. Enable only when you
   accept the risk and have a compensating control.
4. `gpg.recipients` is a list of fingerprints (or any
   `--recipient`-acceptable identifier). Whitespace-only entries and
   `# comments` are ignored.
5. `gpg.gpg_key_file` may point to a file, one recipient per line. The
   path **must resolve inside the same directory as
   `inventory_crypto.json`** — anything outside is refused. This stops
   a tampered config from siphoning recipients out of an arbitrary
   filesystem location.
6. `gpg.timeout_seconds` caps every single `gpg` call. Default 120 s.

**Step-by-step enablement.**

1. List a usable recipient.

    ```bash
    gpg --list-keys --with-colons | rg '^uid'
    ```

2. Edit `state/inventory_crypto.json`.

    ```json
    {
      "enabled": true,
      "provider": "gpg",
      "gpg": { "binary": "gpg", "recipients": ["YOUR_FPR_HERE"] }
    }
    ```

3. Re-launch and trigger a write (any SCP03 inventory write will do).
   The corresponding row in
   `state/device_inventory.sqlite3` is now wrapped in a
   `__ygg_inventory_encrypted__` envelope and the on-disk bytes start
   with `-----BEGIN PGP MESSAGE-----`.

4. Verify with the unified launcher's preflight (the `gpg` probe will
   report `ok` once the binary is reachable; the inventory write
   itself is the proof the envelope took):

    ```bash
    yggdrasim --doctor
    ```

**Error recovery.** A corrupt `inventory_crypto.json` is renamed to
`inventory_crypto.json.corrupt.<unix-timestamp>` and the process boots
with defaults. Inspect the sidecar to recover the operator's last
written shape.

## Runtime root and Workspace

**Consumer.** Every subsystem.

The runtime root is the writable parent of `plugins/`, `state/`, and
`Workspace/`. Resolution order:

1. `YGGDRASIM_RUNTIME_ROOT` (absolute path; persisted to
   `~/.yggdrasim/env_overrides.json` so the override survives across
   runs without creating a chicken-and-egg with the resolver).
2. Source checkouts: the repository root.
3. Frozen builds: a sibling directory called `YggdraSIM-data` next to
   the executable, falling back to `~/YggdraSIM-data`.

**Why override.**

- Frozen builds shipped in read-only locations.
- Test harnesses isolating runs.
- Operating multiple personalities (e.g. one per customer) on the same
  host without cross-contamination.

**Verification.**

```bash
yggdrasim --doctor
```

The doctor's `workspace` probe confirms the resolved root and that the
required subdirectories exist and are writable.

## Bring-your-own keys checklist

A short pre-flight list before pushing any operator material into a
non-test environment.

1. **DPauth / DPpb pairs.** Drop into the appropriate
   `SCP11/<flavor>/certs/` zone, with sidecar `.meta.json` when the
   filename does not match the legacy SGP.26 names. Verify with
   the local-access shell's `CERTS` verb (functional probe for
   eim-local: a successful `LOAD-PROFILE`).
2. **eIM signing certificates.** Drop into
   `SCP11/eim_local/certs/eim/` with sidecar metadata. Verify with
   the eim-local shell's `EIM-CERTS` verb.
3. **Simulator personality.** Replace the bundled
   `isdr_config.json` and `eim_identity.json` with operator-owned
   values, **or** point `YGGDRASIM_SIM_ISDR_CONFIG` /
   `YGGDRASIM_SIM_EIM_IDENTITY` at files outside the repository.
4. **SCP03 keysets.** Migrate `keys.ini` into the per-card SQLite
   inventory and turn on inventory crypto. Delete the `[KEYS]` section
   from `keys.ini` once the per-card record exists.
5. **SCP80 keysets.** Same migration path: per-ICCID inventory record,
   then drop the legacy `ota_config.ini`.
6. **SUCI keys.** Author per home-network. Never reuse a Profile A / B
   key file across operators.
7. **YggdraCore subscribers.** Provision through `upsert(...)` or the
   BYO Open5GS bridge. Stub state is intentionally non-persistent. (post-v1 staging — not part of this release.)
8. **EUM session keys.** Author with `yggdrasim-eum-diag store-keys`,
   chmod 0600, point `YGGDRASIM_EUM_SESSION_KEYS` at the file.
9. **HIL keybags.** Drop next to the pcap; auto-discovery picks them
   up. Delete after use.
10. **Inventory crypto.** Turn on before any non-test card is bound. A
    cleanly-encrypted inventory is the difference between a stolen
    laptop and a stolen lab.
11. **Plugins.** Disable in attestation builds with
    `YGGDRASIM_DISALLOW_PLUGINS=1`. Audit every plugin you do load;
    the runtime executes plugin code.
12. **Workspace seed material.** Treat every committed sample as test
    fixtures. Replace, override, or relocate before non-test use.

## What lives where (cross-reference)

| Topic                               | Definitive doc                                                                              |
| ----------------------------------- | ------------------------------------------------------------------------------------------- |
| Environment flag registry           | [`yggdrasim_common/env_flags.py`](../yggdrasim_common/env_flags.py)                         |
| SCP11 cert sidecar code paths       | [`SCP11/local_access/cert_store.py`](../SCP11/local_access/cert_store.py),                  |
|                                     | [`SCP11/eim_local/eim_cert_store.py`](../SCP11/eim_local/eim_cert_store.py)                 |
| Inventory crypto envelope           | [`yggdrasim_common/inventory_crypto.py`](../yggdrasim_common/inventory_crypto.py)           |
| EUM session-key contract            | [`Tools/EumDiag/session_keys.py`](../Tools/EumDiag/session_keys.py)                         |
| HIL keybag schema                   | [`Tools/HilBridge/scp_keybag_export.py`](../Tools/HilBridge/scp_keybag_export.py)           |
| YggdraCore subscriber store *(post-v1 staging)* | [`Tools/YggdraCore/subscription_store.py`](../Tools/YggdraCore/subscription_store.py)       |
| Runtime root resolution             | [`yggdrasim_common/runtime_paths.py`](../yggdrasim_common/runtime_paths.py)                 |
| AddEim identity sheet               | [`Workspace/LocalEIM/certs/addeim/SIMULATED_EIM_IDENTITY.md`](../Workspace/LocalEIM/certs/addeim/SIMULATED_EIM_IDENTITY.md) |
| HSM seam (planned)                  | not part of this release                                          |
