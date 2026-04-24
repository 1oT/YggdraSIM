---
title: Enable Inventory Encryption
tags:
  - how-to
  - security
  - state
---

# Enable Inventory Encryption

## Goal

Turn on the optional `gpg`-backed encryption envelope for the shared SQLite
inventory so stored per-card payloads are encrypted at rest.

## Prerequisites

- a working `gpg` binary and a usable `gpg-agent` or keyring
- a recipient key (your own key is a valid choice)
- write access to `state/inventory_crypto.json`

## Default behavior

Out of the box, `state/inventory_crypto.json` has `enabled: false`. Payloads
are stored in clear in the SQLite database. This is deliberate to keep
onboarding simple. Sensitive labs should enable encryption as soon as the
first real card state is written.

## Steps

1. Generate or identify a GPG recipient.

    ```bash
    gpg --list-keys --with-colons | grep '^uid'
    ```

    Pick a key fingerprint or identifier.

2. Edit `state/inventory_crypto.json` to enable the envelope.

    ```json
    {
      "enabled": true,
      "provider": "gpg",
      "recipients": ["YOUR_GPG_RECIPIENT"],
      "gpg": {
        "binary": "gpg",
        "timeout_seconds": 120
      }
    }
    ```

    Save it. The `gpg.binary` and `gpg.timeout_seconds` keys are
    optional; they default to `"gpg"` on `PATH` and `120` seconds
    respectively. Raise the timeout if your deployment uses a smart
    card–backed key that needs a physical touch or a slow
    `pinentry`.

3. Trigger a write-path operation so stored payloads get enveloped.

    ```bash
    python -m SCP03 --cmd "AUTH-SD; EXIT"
    ```

    The next write into per-card inventory state lands enveloped.

4. Verify that subsequent reads still work end-to-end.

    ```bash
    python -m SCP11.live --cmd "STATUS; EXIT"
    ```

    The shell should resolve per-EID state via the envelope transparently.

## Migrating existing unencrypted state

Existing cleartext rows remain cleartext until the subsystem rewrites them.
To force a full pass, run a status or discovery command per module that
writes state (SCP03 `AUTH-SD`, SCP80 `iccid` binding, SCP11 `DISCOVER`).
Each rewrite re-envelopes the row.

## Pitfalls

- If `gpg-agent` is not reachable, decryption will fail at read time and the
  shell will surface a clean error. Keep the agent running or configure
  `GNUPGHOME` explicitly.
- Every `gpg` call is bounded by `gpg.timeout_seconds` (default `120 s`)
  so a stuck `pinentry` or a removed smart-card dongle will surface a
  `RuntimeError` instead of hanging the shell indefinitely. Raise the value
  if you legitimately need a longer interactive window.
- The envelope wraps payloads, not the whole database file. Metadata columns
  stay in the clear so identity lookup by `ICCID` or `EID` continues to
  work.
- Rotating the recipient key requires a full-rewrite pass after the
  `recipients` list changes.

## Related pages

- [Architecture](../architecture.md)
- [State Schema](../reference/state-schema.md)
- [Runtime Root](../reference/runtime-root.md)
