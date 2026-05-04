---
title: Download a Profile (Local Access)
tags:
  - how-to
  - scp11
  - local-access
---

# Download a Profile (Local Access)

## Goal

Load a prebuilt profile package onto a physical or simulated eUICC through
the direct local `ISD-R` path, without any relay or SM-DP+ session.

## Prerequisites

- a PC/SC reader with a compatible eUICC, or the simulator backend
- a profile package file under `Workspace/LocalSMDPP/profile/` or any
  accessible path
- optional metadata JSON under `Workspace/LocalSMDPP/profile/metadata/`
- local SCP11 certificate material under `SCP11/local_access/certs/` or the
  writable runtime root

## Steps

1. Confirm the card is visible.

    ```bash
    python -m SCP11.local_access --cmd "DISCOVER; STATUS; CERTS; EXIT"
    ```

    `DISCOVER` returns the eUICC EID, and `CERTS` lists the certificate set
    the card will accept.

2. Select the profile and the metadata.

    ```text
    [Local SMDPP] > PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
    [Local SMDPP] > METADATA Workspace/LocalSMDPP/profile/metadata/test_metadata.json
    [Local SMDPP] > STATUS
    ```

    `STATUS` should now show both selections.

3. Load the profile.

    ```text
    [Local SMDPP] > LOAD-PROFILE
    ```

    The shell opens a fresh local SCP11 session, drives `AuthenticateServer`,
    `PrepareDownload`, and `LoadBoundProfilePackage`, then closes the
    session.

4. Validate.

    ```text
    [Local SMDPP] > DISCOVER
    [Local SMDPP] > STATUS
    ```

    A new entry should show up as `DISABLED`.

## One-shot form

```bash
python -m SCP11.local_access --stdin <<'EOF'
PROFILE Workspace/LocalSMDPP/profile/test_profile.txt
METADATA Workspace/LocalSMDPP/profile/metadata/test_metadata.json
LOAD-PROFILE
EXIT
EOF
```

## Common failures

| Symptom | Likely cause |
| --- | --- |
| `CI PKID unavailable` at AuthenticateServer | certificate chain not trusted by the card. Adjust `SCP11/local_access/certs/` or the runtime-root equivalent. |
| `BPP segment rejected` | the package is malformed. Lint with [Profile Package](../subsystems/profile-package.md). |
| `No profile selected` from `LOAD-PROFILE` | `PROFILE <path>` was not issued in this session. |
| Silent success but profile missing | you targeted a different card than expected. Check `STATUS` and reader selection. |

## Related pages

- [SCP11 Local Access](../subsystems/scp11-local-access.md)
- [RSP Architecture](../concepts/rsp-architecture.md)
- [Inspect and Transcode SAIP](inspect-and-transcode-saip.md)
