---
title: Load Certificates and Configuration
tags:
  - how-to
  - security
  - certificates
  - configuration
---

# Load Certificates and Configuration

## Goal

Bring operator-owned material — certificates, private keys,
secure-channel keysets, simulator personality files, identity records,
encryption envelopes, and protected diagnostic inputs — into YggdraSIM
without touching any in-tree starter material.

This page is the **task-driven mirror** of the canonical operator
guide
[`guides/CONFIGURATION_AND_CERTIFICATES.md`](../../guides/CONFIGURATION_AND_CERTIFICATES.md)
at the repository root. The schemas, sidecar shapes, fallback rules,
and selection orders are normative there; this page picks the most
common flows and walks through them as numbered recipes.

!!! warning "Bundled `Workspace/` material is starter material"

    Everything that ships under `Workspace/`, `SCP11/SGP.26_test_Certs/`,
    and the `state/inventory_crypto.json` defaults is starter material.
    It is there so the toolkit can boot, run the unit tests, and execute
    a first-light download against the in-tree fake eIM and Local
    SM-DP+. Replace, override, or relocate it before any non-test use.

## Decision tree

| You have …                                                                    | Jump to                                                                  |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------ |
| operator DPauth / DPpb cert + key for `LOAD-PROFILE` against `ISD-R`          | [Recipe 1](#recipe-1-bring-your-own-rsp-certs-local-access)              |
| operator DPauth / DPpb cert + key for the eIM local profile-loading path      | [Recipe 2](#recipe-2-bring-your-own-rsp-certs-eim-local)                 |
| operator-issued eIM signing certificate                                       | [Recipe 3](#recipe-3-load-an-operator-eim-signing-certificate)           |
| your own simulated card identity (EID, ATR, AIDs, default DP, CI PKID)        | [Recipe 4](#recipe-4-replace-the-simulator-personality)                  |
| your own simulated default eIM identity used on first boot                    | [Recipe 5](#recipe-5-replace-the-simulator-default-eim-identity)         |
| your own SCP03 / SCP80 keysets                                                | [Recipe 6](#recipe-6-load-scp03-and-scp80-keysets)                       |
| SUCI Profile A / B home-network keys                                          | [Recipe 7](#recipe-7-load-suci-keys)                                     |
| K / OPc / AMF / SQN / MCC / MNC / RID for a 5G AKA test subscriber            | [Recipe 8](#recipe-8-seed-a-yggdracore-subscription)                     |
| ShS-ENC / ShS-MAC / DEK from an EUM database for a failing PCAP               | [Recipe 9](#recipe-9-attach-eum-session-keys-to-a-pcap)                  |
| a need to encrypt every persisted secret at rest                              | [Recipe 10](#recipe-10-turn-on-inventory-encryption)                     |
| a need to relocate or freeze the writable runtime root                        | [Recipe 11](#recipe-11-relocate-the-runtime-root)                        |

## Prerequisites

- A working YggdraSIM install (`yggdrasim --doctor` exits cleanly).
- A directory outside the repository to hold operator-owned material
  (the recipes refer to it as `~/yggdra-secrets`, but the layout is
  yours to choose).
- For recipes that touch the inventory: `gpg` with at least one
  recipient available.

## Recipe 1: Bring-your-own RSP certs (local-access)

Replace the bundled SGP.26 test fixtures used by `LOAD-PROFILE` against
`ISD-R` with operator-owned DPauth / DPpb material.

1. Drop the operator material into the local-access cert zone.

    ```bash
    cp ~/yggdra-secrets/op-alpha-auth.cert.der  SCP11/local_access/certs/
    cp ~/yggdra-secrets/op-alpha-auth.key.pem   SCP11/local_access/certs/
    cp ~/yggdra-secrets/op-alpha-pb.cert.der    SCP11/local_access/certs/
    cp ~/yggdra-secrets/op-alpha-pb.key.pem     SCP11/local_access/certs/
    ```

2. Author a sidecar metadata file beside each certificate. The selector
   reads either `<certificate>.meta.json` or
   `<stem>.meta.json`.

    ```json title="SCP11/local_access/certs/op-alpha-auth.cert.meta.json"
    {
      "role": "auth",
      "private_key_path": "op-alpha-auth.key.pem",
      "root_ci_pkid": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
      "server_address": "local.smdpp.operator.example"
    }
    ```

3. Verify the inventory with the local-access shell's `CERTS` verb
   (alias `SMDP-CERTS`).

    ```bash
    yggdrasim-scp11-local-access --cmd "STATUS; CERTS; EXIT"
    ```

    Expected: the new records appear with `source=local_override`,
    they win over the SGP.26 bundle, and the active card's
    `allowed_ci_pkids` accept the chosen `root_ci_pkid`. Add `--json`
    or `--yaml` to `CERTS` for a machine-readable inventory dump.

4. Run a download against a card.

    ```bash
    yggdrasim-scp11-local-access --cmd "LOAD-PROFILE; EXIT"
    ```

**Reference.** Selector code: `SCP11/local_access/cert_store.py` — the
full sidecar schema (every field) lives in the canonical operator
guide.

## Recipe 2: Bring-your-own RSP certs (eim-local)

Identical drop-in pattern as Recipe 1, but the destination is
`SCP11/eim_local/certs/`. The eim-local shell mirrors the selected
DPauth `server_address` into the eIM activation code when the package
does not pin a different `smdp_address`.

The eim-local shell does not expose a dedicated DPauth/DPpb inventory
verb (the selector is exercised silently when the flow runs). Verify
functionally:

```bash
yggdrasim-scp11-eim-local --cmd "STATUS; LOAD-PROFILE; EXIT"
```

## Recipe 3: Load an operator eIM signing certificate

Replace the bundled fake-eIM signing certificates with operator-issued
material for `ADD-INITIAL-EIM` / `ADD-EIM`.

1. Drop the certificate (and matching key, if held in-band) into
   `SCP11/eim_local/certs/eim/`. The mirror at
   `Workspace/LocalEIM/certs/eim/` is consulted by the same selector.

2. Author a sidecar metadata file. The eIM cert store classifies files
   as `signing`, `tls`, or `ci`; spell out the role explicitly so the
   selector does not have to guess.

    ```json title="SCP11/eim_local/certs/eim/op-alpha-eim.cert.meta.json"
    {
      "role": "signing",
      "private_key_path": "op-alpha-eim.key.pem",
      "root_ci_pkids": ["F54172BDF98A95D65CBEB88A38A1C11D800A85C3"],
      "subject_cn": "operator-alpha.eim.example",
      "curve": "NIST"
    }
    ```

3. Verify with the eim-local shell's `EIM-CERTS` verb.

    ```bash
    yggdrasim-scp11-eim-local --cmd "STATUS; EIM-CERTS; EXIT"
    ```

    Expected: `source=local_eim_dir`, `role=signing`, the chosen
    `root_ci_pkids` intersect the active eIM identity's preferred CI
    list. Add `--json` or `--yaml` for machine-readable output, or
    pass a package path / cert path positional to preview how the
    selector would resolve a specific call site.

**Reference.** Selector code: `SCP11/eim_local/eim_cert_store.py`.

## Recipe 4: Replace the simulator personality

Set the EID, ATR, AIDs, default SM-DP+ address, eUICC-side allowed CI
list, and on-card SCP03 / SCP80 keysets used by the **simulated** card.

1. Author the file outside the repository.

    ```json title="~/yggdra-secrets/operator-isdr.json"
    {
      "eid": "89...your 32 hex digits...",
      "atr_hex": "3B9F96801FC78031A073BE21136743200718000001A5",
      "default_dp_address": "rsp.operator.example",
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
      }
    }
    ```

2. Point the simulator at it.

    ```bash
    export YGGDRASIM_SIM_ISDR_CONFIG=~/yggdra-secrets/operator-isdr.json
    ```

3. Boot the simulator and confirm the load. The unified launcher's
   read-only preflight covers the simulator boot path; an SCP03
   status probe against the simulator confirms the file is being
   consumed:

    ```bash
    yggdrasim --doctor
    YGGDRASIM_CARD_BACKEND=sim yggdrasim-scp03 --cmd "STATUS; EXIT"
    ```

The original `Workspace/SIMCARD/isdr_config.json` is untouched. Drop
the env var to fall back to the bundled starter material.

## Recipe 5: Replace the simulator default eIM identity

Used on first boot, when the card's `BF55` eIM identity has not yet
been programmed. Authoring follows the same pattern as Recipe 4, with
the override env var `YGGDRASIM_SIM_EIM_IDENTITY` and the schema below:

```json
{
  "display_name": "Operator alpha lab",
  "eim_id": "2.25....",
  "eim_id_type": "oid",
  "eim_fqdn": "eim.operator.example",
  "eim_endpoint": "https://eim.operator.example/gsma/rsp2/asn1",
  "euicc_ci_pk_id": "F54172BDF98A95D65CBEB88A38A1C11D800A85C3",
  "eim_public_key_cert_path": "/path/to/eim_signing.pem",
  "trusted_tls_cert_path": "/path/to/eim_tls.pem"
}
```

`euicc_ci_pk_id` must match a CI SKI in the simulator's
`configured_data.allowed_ci_pkids_hex`.

## Recipe 6: Load SCP03 and SCP80 keysets

Two stages: file-based defaults, then the per-card SQLite inventory
(authoritative).

1. **File-based default (boot).** Edit
   `Workspace/SCP03/keys.ini`. The four secret fields are 16-byte hex.

    ```ini
    [KEYS]
    enc = ...your 32 hex chars...
    mac = ...your 32 hex chars...
    dek = ...your 32 hex chars...
    kvn = 30
    aid = A000000151000000
    adm = 3132333435363738
    ```

    `kvn` must match the on-card keyset version (the simulated card's
    `isdr_config.json.scp03_keys.kvn`); a mismatch surfaces as
    `INITIALIZE UPDATE` returning `6982` / `6A88`.

2. **Per-card inventory (runtime).** Connect the SCP03 admin shell
   to a card; the shell auto-binds to the active ICCID and seeds a
   per-card record on first use. To rotate the active card's keyset
   in place, use the `CONFIG` wizard:

    ```text
    SCP03> CONFIG
    ... wizard prompts for ENC / MAC / DEK / KVN / AID / ADM ...
    SCP03> SHOW
    SCP03> EXIT
    ```

    `CONFIG` writes through to both the module-level state and the
    per-ICCID inventory namespace (`iccid/<ICCID>/scp03`); on the
    next connect to the same card, that record is loaded ahead of
    `keys.ini`. Delete the `[KEYS]` section in `keys.ini` once the
    per-card record is the source of truth.

3. **SCP80 OTA parameters.** The SCP80 shell follows the same
   pattern with lowercase verbs:

    ```bash
    yggdrasim-scp80 --cmd "iccid <ICCID>; set kic <hex>; set kid <hex>; set spi <hex>; show; quit"
    ```

    `set` updates the active SCP80 config; `show` prints the
    resolved values. The per-ICCID record is persisted to
    `iccid/<ICCID>/scp80` and is preferred over the legacy
    `Workspace/SCP80/ota_config.ini` on the next bind.

4. **Encrypt the inventory at rest.** Continue with [Recipe
   10](#recipe-10-turn-on-inventory-encryption).

## Recipe 7: Load SUCI keys

The SUCI helper holds **one** active key file at a time. The path is
resolved relative to the runtime workspace.

```text
yggdrasim-suci-tool --cmd "USE keys/operator-alpha.key; STATUS; DUMP; EXIT"
```

`secp256r1` (Profile A) and `curve25519` (Profile B) are supported.
The `TOOL` verb prints the active `suci-keytool` binary path; override
it with `TOOL <path>` when the binary lives outside the standard
search.

!!! note "Custodial reminder"

    SUCI key files are 32 bytes of long-term home-network material.
    Keep them at 0600, never share across operators, and rotate per the
    home-network's policy. They never belong inside the inventory
    encryption envelope — they are operator key material, not stored
    application state.

## Recipe 8: Seed a YggdraCore subscription

> **Status: R2-005, post-v1.0.0 staging.** Tracked in [V2_ROADMAP.md](../../V2_ROADMAP.md). The v1.0.0 frozen tree (tag `v1.0.0`) does not include this surface.

The in-process AUSF / AAnF stub holds subscribers in memory only.
There is no on-disk format.

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

`K` and `OPc` are exactly 16 bytes; `AMF` is 2; `SQN` is 6; `MCC` is
3 digits; `MNC` is 2 or 3 digits; `RID` is 1..4 digits. The store
auto-bumps `SQN` on every successful authentication (TS 33.102 Annex
C) and refuses overflow.

For BYO Open5GS (`YGGDRASIM_5GCORE_MODE=byo`), the same record shape
provisions a real subscriber DB through `pymongo`; pass the Mongo URI
and database name to `Open5gsBridge` directly.

## Recipe 9: Attach EUM session keys to a pcap

Use this to drive the bundled Lua dissector against a stuck profile
download.

1. Write the repository.

    ```bash
    yggdrasim-eum-diag store-keys \
        --iccid 8901260000000000001 \
        --shs-enc AABBCCDDEEFF00112233445566778899 \
        --shs-mac 00112233445566778899AABBCCDDEEFF \
        --dek    0F0E0D0C0B0A09080706050403020100 \
        --keys-out ~/secrets/eum-keys.json
    ```

    The writer chmods the file to `0600` on POSIX; any
    group/other-readable mode is reported on load.

2. Run the dissector against the failing pcap, reusing the stored
   repository.

    ```bash
    export YGGDRASIM_EUM_SESSION_KEYS=~/secrets/eum-keys.json
    yggdrasim-eum-diag inject-keys \
        --bundle-file ~/secrets/eum-keys.json \
        --pcap ~/captures/failing-2026-04-12.pcapng
    ```

    `inject-keys` accepts either the per-bundle CLI flags
    (`--iccid / --shs-enc / --shs-mac / --dek`) or `--bundle-file`
    pointing at an existing repository JSON. The bundled Lua
    dissector reads the same file from
    `YGGDRASIM_EUM_SESSION_KEYS`, so exporting the env var lets
    additional `tshark` / Wireshark sessions decode the same pcap
    without re-running `inject-keys`.

3. For an offline BPP decode without the pcap, use:

    ```bash
    yggdrasim-eum-diag decode-bpp \
        --bpp ~/captures/bf36.der \
        --keys ~/secrets/eum-keys.json
    ```

The repository is keyed by ICCID, so a single file may carry every
session under investigation.

## Recipe 10: Turn on inventory encryption

The full step-by-step recipe lives at
[`enable-inventory-encryption.md`](enable-inventory-encryption.md). The
short form:

1. Identify a recipient: `gpg --list-keys --with-colons | rg '^uid'`
2. Edit `state/inventory_crypto.json`:

    ```json
    {
      "enabled": true,
      "provider": "gpg",
      "gpg": { "binary": "gpg", "recipients": ["YOUR_FPR_HERE"] }
    }
    ```

3. Trigger any inventory write (running the SCP03 shell against a
   card and exiting cleanly is enough — it will write the per-card
   `scp03` namespace), then confirm the on-disk bytes start with
   `-----BEGIN PGP MESSAGE-----`.
4. Verify with `yggdrasim --doctor` (the `gpg` probe must report
   `ok`); the resulting on-disk bytes are the actual proof the
   envelope took.

`plaintext_fallback_writes` is the strict-mode escape hatch — leave it
`false` so the writer refuses to drop plaintext on disk while the GPG
provider is ready.

## Recipe 11: Relocate the runtime root

```bash
export YGGDRASIM_RUNTIME_ROOT=/var/lib/operator-alpha/yggdra
mkdir -p "$YGGDRASIM_RUNTIME_ROOT"
yggdrasim --doctor
```

The doctor's `workspace` probe confirms the resolved root and that
`plugins/`, `state/`, and `Workspace/` exist underneath it.

The override is persisted to `~/.yggdrasim/env_overrides.json` so the
choice survives across runs without creating a chicken-and-egg with
the resolver. Source checkouts default to the repository root; frozen
builds default to a sibling `YggdraSIM-data` directory next to the
executable, falling back to `~/YggdraSIM-data`.

## Bring-your-own keys checklist

A concise pre-flight list before pushing any operator material into a
non-test environment:

1. **DPauth / DPpb pairs.** Drop into
   `SCP11/<flavor>/certs/` with sidecar `.meta.json`. Verify with
   the local-access shell's `CERTS` verb (or, for eim-local, by
   running `LOAD-PROFILE` and checking the result).
2. **eIM signing certificates.** Drop into
   `SCP11/eim_local/certs/eim/`. Verify with the eim-local shell's
   `EIM-CERTS` verb.
3. **Simulator personality.** Author externally; point
   `YGGDRASIM_SIM_ISDR_CONFIG` / `YGGDRASIM_SIM_EIM_IDENTITY` at the
   files.
4. **SCP03 keysets.** Migrate `keys.ini` into the per-card SQLite
   inventory; turn on inventory crypto; delete the `[KEYS]` section.
5. **SCP80 keysets.** Per-ICCID inventory record; drop legacy
   `ota_config.ini`.
6. **SUCI keys.** Author per home-network. Never reuse across
   operators.
7. **YggdraCore subscribers.** Provision through `upsert(...)` or the
   BYO Open5GS bridge. Stub state is intentionally non-persistent. (R2-005, post-v1.0.0 staging — see V2_ROADMAP.md.)
8. **EUM session keys.** Author with `yggdrasim-eum-diag store-keys`,
   chmod 0600, point `YGGDRASIM_EUM_SESSION_KEYS` at the file.
9. **HIL keybags.** Drop next to the pcap; auto-discovery picks them
   up. Delete after use.
10. **Inventory crypto.** Turn on before any non-test card is bound.
11. **Plugins.** Disable in attestation builds with
    `YGGDRASIM_DISALLOW_PLUGINS=1`.
12. **Workspace seed material.** Treat every committed sample as a
    test fixture. Replace, override, or relocate before non-test use.

## Validation

For each recipe above, the canonical "did it stick?" probes are:

| Surface                       | Probe                                                                  |
| ----------------------------- | ---------------------------------------------------------------------- |
| SCP11 RSP certs               | `yggdrasim-scp11-local-access --cmd "STATUS; CERTS; EXIT"`             |
| eIM signing certs             | `yggdrasim-scp11-eim-local --cmd "STATUS; EIM-CERTS; EXIT"`            |
| Simulator personality         | `YGGDRASIM_CARD_BACKEND=sim yggdrasim-scp03 --cmd "STATUS; EXIT"`      |
| SCP03 keysets                 | `yggdrasim-scp03 --cmd "SHOW; EXIT"`                                   |
| SCP80 keysets                 | `yggdrasim-scp80 --cmd "iccid <ICCID>; show; quit"`                    |
| SUCI keys                     | `yggdrasim-suci-tool --cmd "STATUS; EXIT"`                             |
| Inventory crypto              | `yggdrasim --doctor` (look for the `gpg` probe row)                    |
| Runtime root                  | `yggdrasim --doctor` (look for the `workspace` probe row)              |

## Related documentation

- [Configuration and Certificates (canonical operator guide)](../../guides/CONFIGURATION_AND_CERTIFICATES.md)
- [Enable Inventory Encryption](enable-inventory-encryption.md)
- [Download a Profile (Local Access)](download-a-profile-local.md)
- [Diagnostics Toolbox](diagnostics-toolbox.md)
- [Runtime Root reference](../reference/runtime-root.md)
- [State schema reference](../reference/state-schema.md)
