---
title: Download a Profile (Live Relay)
tags:
  - how-to
  - scp11
  - live
---

# Download a Profile (Live Relay)

## Goal

Drive an activation-code download through `SCP11/live` against a live
SM-DP+, install the BPP on the eUICC, and let the shell reconcile
notifications so SM-DP+ sees the result.

## Prerequisites

- a PC/SC reader with a compatible eUICC, or a simulator backend
- an activation code of shape `LPA:1$<smdp-host>$<matching-id>`
- network reachability to the SM-DP+ host
- `SCP11/live` can resolve the trust chain the SM-DP+ serves (live-default
  trust assumed)

## Steps

1. Open the shell and confirm the session is in a good shape.

    ```bash
    python -m SCP11.live --cmd "STATUS; DISCOVER; EXIT"
    ```

    Both `STATUS` and `DISCOVER` should return without errors. Persist
    endpoints if needed.

2. Run the download.

    ```bash
    python -m SCP11.live --cmd "DOWNLOAD-PROFILE LPA:1\$example.smdp.example.com\$ABCDEF123456; STATUS; EXIT"
    ```

    The shell drives:

    1. `InitiateAuthentication` against the SM-DP+
    2. `AuthenticateServer` / `AuthenticateClient` with the eUICC
    3. `PrepareDownload`
    4. `GetBoundProfilePackage`
    5. `LoadBoundProfilePackage` against the `ISD-R`
    6. notification hygiene with SM-DP+

3. Validate the result.

    ```bash
    python -m SCP11.local_access --cmd "DISCOVER; STATUS; EXIT"
    ```

    The new profile should appear in the listing as `DISABLED`.

4. Optional: enable the new profile. See
   [Enable, Disable, Delete a Profile](enable-disable-delete-profile.md).

## Validation

Look for:

- the shell's final `InstallResult: ok` line
- no notifications left hanging on the card after the shell returns
- a new `ICCID` visible in `STATUS`

## Common failures

| Symptom | Likely cause |
| --- | --- |
| `CI PKID unavailable` at AuthenticateClient | the card does not trust the SM-DP+'s CI chain. Check `ES9-CERT-INFO` and `SET-ES9-CA`. |
| TLS failure at `InitiateAuthentication` | network or pinned CA issue. Check `SET-ES9-TLS` and `SET-ES9-CA`. |
| BPP install fails mid-stream | insufficient free memory on the eUICC, or a corrupt BPP segment. Retry. |
| Notification left on card | `HandleNotification` failed. Re-run the shell; notification hygiene is automatic. |

## Related pages

- [SCP11 Live Relay](../subsystems/scp11-live.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- `guides/PROFILE_LIFECYCLE_CLI_CHEATSHEET.md`
