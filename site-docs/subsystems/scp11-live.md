---
title: SCP11 Live Relay
tags:
  - subsystems
  - scp11
  - live
  - relay
---

# SCP11 Live Relay

`SCP11/live/` is the production-like relay shell. It assumes live-default
certificate trust, live-default endpoints, and a relay-first operator model.
Use it when the workflow runs through an SM-DP+ or an eIM and should behave
the way a shipping LPA/IPA would.

!!! info "Underlying concept"
    Read [RSP Architecture](../concepts/rsp-architecture.md) first. The
    LPAd / IPAd / IPAe split there is what the command surface reflects.

## When to use it

- `DOWNLOAD-PROFILE` driven by an activation code
- `DISCOVER` and `DOWNLOAD` for IPAd-style pulls
- optional plugin-backed relay-side `POLL` for IPAe polling campaigns
- setting SM-DP+, ES9+, or ES9+ CA parameters for the session
- running notification synchronization around transactional flows

## Entry points

=== "Module"

    ```bash
    python -m SCP11.live
    python -m SCP11.live --cmd "DISCOVER; STATUS; EXIT"
    ```

=== "Console script"

    ```bash
    yggdrasim-scp11-live
    ```

=== "From the launcher"

    `python main/main.py` and pick the SCP11 Live entry.

## Command surface, grouped

### Session and diagnostics

| Command | Purpose |
| --- | --- |
| `STATUS` | print live session snapshot |
| `LIST` | list known SM-DP+, ES9+, and CA entries |
| `RESET` | reset session state to defaults |
| `HELP` | print the grouped help surface |

### LPAd

| Command | Purpose |
| --- | --- |
| `DOWNLOAD-PROFILE <activation>` | run the full activation-code download flow |

### IPAd

| Command | Purpose |
| --- | --- |
| `DISCOVER` | contact SM-DP+ for pending events |
| `DOWNLOAD [matchingId]` | pull a specific profile event |

### IPAe (plugin-backed)

| Command | Purpose |
| --- | --- |
| `POLL [attempts] [window] [-t 20s] [-s 5] [--debug]` | plugin-backed relay poll |
| `EIM-POLL` | retained alias for `POLL` |

### Profile state

| Command | Purpose |
| --- | --- |
| `ENABLE-PROFILE` | enable the selected profile |
| `DISABLE-PROFILE` | disable the selected profile |
| `DELETE-PROFILE` | delete the selected profile |

### Endpoints and trust

| Command | Purpose |
| --- | --- |
| `SET-SMDP <host>` | set the SM-DP+ endpoint |
| `SET-ES9 <host>` | set the ES9+ endpoint |
| `SET-ES9-TLS <on/off>` | control TLS for ES9+ |
| `SET-ES9-CA <path>` | pin the CA used by ES9+ |
| `ES9-CERT-INFO` | inspect the ES9+ certificate chain |

### Compatibility probes

| Command | Purpose |
| --- | --- |
| `FLOW` | scripted relay flow probe |
| `EIM-AUTHENTICATE` | relay-side eIM authentication probe |

### HIL / diagnostics

| Launcher flag | Purpose |
| --- | --- |
| `--dump-keybag <path>` | **no-op stub**. SCP11c BSP keys are derived inside the eUICC during BPP processing and never reach the host, so they cannot be exported from the live relay. The flag prints a clear message pointing at `SCP11.local_access` (for host-derived BSPs) or SCP03 (for SCP03 session keys), then exits with code `2`. |

For actual keybag exports see
[SCP11 Local Access](scp11-local-access.md#session-key-export) and
[SCP03](scp03.md#session-key-export).

## Runtime dependencies

- a PC/SC reader with an eUICC, or a relay transport endpoint for the card
- certificate material under `SCP11/` and under the writable runtime root
- network reachability to the chosen SM-DP+ or eIM
- optional `polling` plugin for `POLL`

## State the shell writes

| Location | Contents |
| --- | --- |
| `state/device_inventory.sqlite3` | per-EID live session settings |
| runtime root `plugins/` | optional `polling` plugin code and artifacts |

## Common recipes

### Fast preflight

```bash
python -m SCP11.live --cmd "DISCOVER; STATUS; LIST; EXIT"
```

### Download with an activation code

```text
[eSIM Live] > DOWNLOAD-PROFILE LPA:1$example.smdp.example.com$ABCDEF123456
```

### Poll with the plugin-backed path

```text
[eSIM Live] > POLL 5 60s -t 20s -s 5
```

Without the plugin, the `POLL` verb is either hidden or emits a clean runtime
error explaining that the capability is optional.

## Pitfalls

- An expired or untrusted ES9+ certificate fails at `InitiateAuthentication`
  with a clear server-side error. Check `SET-ES9-CA` and `ES9-CERT-INFO`.
- Notifications left on the card block subsequent transactions. Let the shell
  synchronize them, or force it via the notification verbs.
- `DOWNLOAD-PROFILE` requires that the card supports the CI PKID that the
  SM-DP+ advertises. Mismatches fail early with a `CI PKID unavailable`
  response.
- The optional plugin capability is loaded from the active runtime root. If
  you are on a frozen build, drop the plugin into the runtime root's
  `plugins/` tree, not the source tree.

## Related pages

- [RSP Architecture](../concepts/rsp-architecture.md)
- [SCP11 Test Relay](scp11-test.md)
- [SCP11 Local Access](scp11-local-access.md)
- [Download a Profile (Live Relay)](../how-to/download-a-profile-live.md)
- [HIL Bridge — offline pcap replay](hil-bridge.md#offline-pcap-replay)
