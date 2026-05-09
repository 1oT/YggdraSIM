---
title: SCP11 Local Access
tags:
  - subsystems
  - scp11
  - local-access
---

# SCP11 Local Access

`SCP11/local_access/` is the direct local `ISD-R` shell. Each card-touching
command opens a fresh local SCP11 session, executes the exact ES10 exchange
it implies, and closes the session in cleanup. Use it when there is no relay
and the workflow is a direct ES10b / ES10c / metadata operation against a
physical or simulated eUICC.

!!! info "Underlying concept"
    Start with [RSP Architecture](../concepts/rsp-architecture.md). This
    shell speaks the ES10 family directly, without an LPAd in the middle.

## When to use it

- `DISCOVER`, `INFO`, `STATUS`, `CERTS`, `SMDP-CERTS`
- `LOAD-PROFILE`, `PROFILE`, `METADATA`, `METADATA-LINT`
- `STORE-METADATA`, `STORE-METADATA-CUSTOM`, `UPDATE-METADATA`
- `ENABLE-PROFILE`, `DISABLE-PROFILE`, `DELETE-PROFILE`
- any one-shot local SCP11 session that does not need an SM-DP+ session

## Entry points

=== "Module"

    ```bash
    python -m SCP11.local_access
    python -m SCP11.local_access --cmd "DISCOVER; STATUS; EXIT"
    python -m SCP11.local_access --stdin <<'EOF'
    PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
    LOAD-PROFILE
    EXIT
    EOF
    ```

=== "Console script"

    ```bash
    yggdrasim-scp11-local-access
    ```

=== "From the launcher"

    `python main/main.py` and pick the SCP11 Local Access entry.

## Command surface, grouped

### Discovery and inspection

| Command | Purpose |
| --- | --- |
| `DISCOVER` | scan for eUICC, ISD-R, certificates, and basic state |
| `INFO` | print session and card snapshot |
| `STATUS` | print the shell's current configuration |
| `CERTS` | list card-aware certificates |
| `SMDP-CERTS` | list available SM-DP+ certificate chains |

### Profile provisioning

| Command | Purpose |
| --- | --- |
| `PROFILE <path>` | pick the profile input (DER/BPP/UPP or hex text) |
| `METADATA <path>` | pick the metadata JSON |
| `METADATA-LINT` | lint the selected metadata JSON |
| `STORE-METADATA` | store metadata on the card |
| `STORE-METADATA-CUSTOM [args]` | store a single custom metadata tag |
| `STORE-METADATA-CUSTOM-ALL` | store the full custom metadata set |
| `UPDATE-METADATA` | update metadata on an already-loaded profile |
| `LOAD-PROFILE` | full local SCP11 + PrepareDownload + LoadBPP flow |

### Profile state control

| Command | Purpose |
| --- | --- |
| `ENABLE-PROFILE` | enable the selected profile |
| `DISABLE-PROFILE` | disable the selected profile |
| `DELETE-PROFILE` | delete the selected profile |

### HIL / diagnostics

| Command / flag | Purpose |
| --- | --- |
| `EXPORT-KEYBAG [Path.keys.json] [Label]` | dump the last-built SCP11c BSP snapshot (S-ENC, S-MAC, MAC chain, block number, AID) into a keybag JSON for offline HIL pcap decryption |
| `python -m SCP11.local_access --dump-keybag <path>` | non-interactive launcher flag that runs the same export at the end of the batch (or standalone if no `--cmd` / `--stdin` is given) |

See [Session key export](#session-key-export) below and the HIL Bridge
[offline replay flow](hil-bridge.md#offline-pcap-replay).

## Runtime dependencies

- a PC/SC reader with an eUICC, or the simulator backend
- local SCP11 certificate material under `SCP11/local_access/certs/` or
  under the writable runtime root
- the shared SQLite inventory for per-EID selection state
- no network access is required

## State the shell writes

| Location | Contents |
| --- | --- |
| `state/device_inventory.sqlite3` | per-EID profile, metadata, and cert choices |
| `SCP11/local_access/certs/` | drop-in certificate material |
| `SCP11/local_access/profile/` | profile input tree |
| `SCP11/local_access/profile/metadata/` | metadata JSON tree |

## Common recipes

### One-shot load a profile

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/test_metadata.json
LOAD-PROFILE
EXIT
EOF
```

### Compact status snapshot

```bash
python -m SCP11.local_access --cmd "DISCOVER; STATUS; CERTS --json; EXIT"
```

### Enable and delete

```text
[Local SMDPP] > ENABLE-PROFILE
[Local SMDPP] > STATUS
[Local SMDPP] > DISABLE-PROFILE
[Local SMDPP] > DELETE-PROFILE
```

## Session key export

`EXPORT-KEYBAG` snapshots the last-built pySim BSP session into a
keybag JSON compatible with the HIL Bridge offline-replay decoder.
The BSP is (re)built by any verb that needs a secure channel —
`LOAD-PROFILE`, `ENABLE-PROFILE`, `DISABLE-PROFILE`, `DELETE-PROFILE`,
`STORE-METADATA`, `UPDATE-METADATA`, etc. — so run the desired verb
first, then export.

### Interactive shell

```text
[Local SMDPP] > LOAD-PROFILE
[Local SMDPP] > EXPORT-KEYBAG Workspace/hil/captures/session-2026-04-20.keys.json case-1234
```

Arguments (both optional):

- `OutputPath.keys.json` — destination file. Defaults to a
  timestamped path under `Workspace/SCP11/local_access/keybags/` when
  omitted.
- `Label` — free-form identifier written to the entry for operator
  cross-referencing.

The handler refuses cleanly if:

- no local SCP11 session has been initialized yet
- the session exists but no BSP snapshot has been captured (no
  BSP-building verb has run during the session)

### Non-interactive launcher flag

```bash
python -m SCP11.local_access --dump-keybag \
    Workspace/hil/captures/session-2026-04-20.keys.json
```

Combines cleanly with `--cmd` / `--stdin`: the `EXPORT-KEYBAG` line is
appended to the batch, runs after the last command, and writes the
keybag. If no batch is provided, the export runs standalone.

### Session snapshot data

The shell's `LocalSessionState` keeps the BSP material after every
build via `_snapshot_session_bsp`:

- `last_bsp_s_enc_hex` — BSP session S-ENC
- `last_bsp_s_mac_hex` — BSP session S-MAC
- `last_bsp_mac_chain_hex` — MAC chaining value
- `last_bsp_block_nr` — per-session block counter
- `last_bsp_aid_hex` — AID under which the BSP was built
- `last_bsp_protocol` — `"SCP11c"`

`EXPORT-KEYBAG` reads directly from this snapshot, so it is safe to
run even after the BSP has been torn down by the verb that built it.

See [HIL Bridge — Keybag JSON schema](hil-bridge.md#keybag-json-schema)
for the complete file structure and
[Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md) for
how the keybag feeds into the decoded-APDU TUI.

## Pitfalls

- Each command opens a fresh local session. Do not assume an earlier
  authenticated state carries forward into the next verb.
- Metadata linting is advisory. A JSON that lints clean can still be rejected
  by the card if a field is out of the card's acceptable range.
- `LOAD-PROFILE` requires both `PROFILE` and (often) `METADATA` to be set
  for the current session. `STATUS` confirms the choices.
- Certificate matching uses the card's allowed CI PKID set. Drop-in custom
  certificates must live in a directory the loader scans; see
  [Runtime Root](../reference/runtime-root.md).

## Related pages

- [RSP Architecture](../concepts/rsp-architecture.md)
- [SCP11 Live Relay](scp11-live.md)
- [Download a Profile (Local Access)](../how-to/download-a-profile-local.md)
- [Enable, Disable, Delete a Profile](../how-to/enable-disable-delete-profile.md)
- [HIL Bridge — offline pcap replay](hil-bridge.md#offline-pcap-replay)
- [Replay a HIL pcap offline](../how-to/replay-hil-pcap-offline.md)
