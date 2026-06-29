---
title: Troubleshooting
tags:
  - reference
  - troubleshooting
---
<!--
SPDX-License-Identifier: GPL-3.0-or-later
Copyright (c) 2026 1oT OÜ. Authored by Hampus Hellsberg.
-->


# Troubleshooting

Symptoms, likely causes, and fixes. Group by subsystem. When a fix is
non-trivial, the row links to the page that explains it in full.

## General

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `ModuleNotFoundError: SCP03` etc. when running `python -m SCP03` | editable install not active | run `python -m pip install -e .` from the repo root |
| `yggdrasim-*` command not found | entry points not registered | re-run editable install, or use `python -m ...` |
| launcher cannot find runtime material after a frozen build | wrong runtime root | set `YGGDRASIM_RUNTIME_ROOT` or check `YggdraSIM-data` placement. See [Runtime Root](runtime-root.md). |
| unsure whether the environment is wired correctly before triaging | optional dependency or reader missing | run `python main/main.py --doctor` for a read-only preflight covering Python, `cryptography`, `pycryptodomex`, `asn1tools`, the optional `pysim/` tree, SQLite, `textual`, PC/SC readers, and `gpg`. Exit code is `1` on any warning/failure so the helper is CI-safe. |
| need to pin down which suite version is running | multiple installs or editable vs frozen builds | run `python main/main.py --version` (value comes from `yggdrasim_common/__about__.py` and always matches `pyproject.toml`). |

## PC/SC and reader

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `SCardListReaders: no readers available` | `pcscd` not running | start `pcscd`, check reader USB |
| `Shared mode not available` / `Card reader in use` | reader owned by another process | close other shells; check if the HIL bridge is running |
| Card never ATRs | card seated wrong, damaged, or not powered | reseat, try a different reader |

## Universal GUI Command Center

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `--gui` is unavailable | GUI extras not installed in the active environment | install `python -m pip install -e '.[gui]'`, or use `.[full,gui]` on a Linux lab host |
| browser reaches the server but actions return unauthorized | missing or wrong GUI bearer token | read the token path printed by `--web-server`, keep the server bound to loopback, and reconnect through the SSH tunnel |
| Host shell panel is disabled | host shell is intentionally opt-in | set `YGGDRASIM_GUI_HOST_SHELL=1` only on a trusted workstation |
| live APDU dock is empty | no local HIL relay or Card Bridge relay is active | start a local HIL session on Linux or the Card Bridge flow from the GUI. See [Universal GUI Command Center](../subsystems/gui-command-center.md). |

## Card Bridge and remote APDU streaming

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `/ping` works but `/apdu` returns `401` | bearer token missing on the consumer side | copy the token file with mode `0600` and pass `--remote-card-token-file`; see [Remote APDU Streaming](../how-to/remote-apdu-streaming.md) |
| `429 Too many authentication failures` | repeated bad tokens from the same peer | wait for the lockout window, then retry with the correct token |
| `Connection refused` from the HIL rig | SSH forward is missing or bound on the wrong host | confirm `ssh -L` or `ssh -R` is still running and that the rig can reach `http://127.0.0.1:8642/ping` |
| APDUs hang during long eUICC work | tunnel latency or timeout too low | raise `--apdu-timeout-ms` on the HIL bridge or supervisor |
| remote HIL service starts but RemSIM exits immediately | `osmo-remsim-client-st2` missing or wrong path | install the RemSIM client or configure the absolute binary path. See [Install RemSIM / APDU Streaming](../how-to/install-remsim-apdu-streaming.md). |

## SCP03

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `6982` on `EXTERNAL AUTHENTICATE` | wrong keyset | verify `Workspace/SCP03/keys.ini` or the migrated inventory entry |
| `6A82` on `SELECT <FID>` | file not currently active or wrong path | walk from `3F00`, use a path instead of a bare FID |
| `6985` on `PUT-KEY` | no live authenticated session | run `AUTH-SD` first |
| eUICC retrieval commands return `6A88` | wrong SD selected | `SELECT` the ISD-R first, then retry |

## SCP80

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Response PoR returns a counter error | SPI counter mode mismatch | align SPI with what the card last saw; reset counter if allowed |
| Applet silently swallows payload | wrong TAR | verify TAR; pick the correct applet or RFM engine |
| `6988` on secured packet | integrity bits rejected | match `CC` / `DS` / ciphering requirements on both sides |

## SCP11 eSIM management relay

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `CI PKID unavailable` at AuthenticateClient | SM-DP+ chain not trusted by the card | check `ES9-CERT-INFO`, `SET-ES9-CA`, pick a CI the card trusts |
| TLS error at `InitiateAuthentication` | pinned CA or clock skew | check `SET-ES9-TLS`, `SET-ES9-CA`, host clock |
| `self-signed certificate in certificate chain` on a freshly-seen eIM/SM-DP+ FQDN | no local trust anchor yet for this host | the client runs a TOFU chain read, verifies it against a local bundle, and persists the result. If you previously set `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION=1`, unset it so auto-learn can bootstrap; subsequent runs will be fully pinned against the persisted bundle. |
| BPP install fails mid-stream | insufficient memory or bad BPP segment | retry, free space, or relint the source package |

### TLS trust-posture knobs

Three env flags govern SCP11 TLS posture. All three are unset by default.

| Env flag | Role | Default | When to set |
| --- | --- | --- | --- |
| `YGGDRASIM_SCP11_ALLOW_INSECURE_TLS` | Opt-in to unpinned *request* traffic (real ES9 POSTs, transport channel). Triggers a one-shot stderr warning banner per caller. | unset → refused | Dev boxes running against SGP.26 test vectors only. Never against a production RSP server. |
| `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS` | Hard-lock: refuse unpinned request traffic even if `ALLOW_INSECURE_TLS=1` is also set. | unset → opt-in still possible | Fleet or CI where nobody should ever downgrade a request. |
| `YGGDRASIM_SCP11_REQUIRE_PINNED_TLS_INTROSPECTION` | Hard-lock: refuse the read-only TOFU chain read that auto-learns new trust anchors. Use only when no new anchor may be learned at runtime. | unset → auto-learn allowed | Air-gapped or attestation-only deployments; pre-seed anchors under `SCP11/<tree>/certs` instead. |

Auto-learn is intentionally the default. Popping in a new eUICC or registering against a new eIM FQDN works without any env dance: the client TOFUs the chain once, persists it as a local bundle, and every subsequent call verifies against that bundle with full pinning.

### Plugin loader knobs

Plugins under the active runtime root's `plugins/` directory are refused by default because they are executable local Python. Set `YGGDRASIM_ALLOW_PLUGINS=1` only for plugin packages you intend to run.

| Env flag | Role | Default | When to set |
| --- | --- | --- | --- |
| `YGGDRASIM_ALLOW_PLUGINS` | Opt-in knob. `1`/`true`/`yes`/`on` imports plugins; unset, false, or unrecognised values refuse them. | unset → plugins refused | Source checkouts or lab runtimes that intentionally load local plugins. |
| `YGGDRASIM_DISALLOW_PLUGINS` | Hard-lock: refuse every plugin even when `ALLOW_PLUGINS=1` is also set. | unset → still requires `ALLOW_PLUGINS=1` | Attestation / CI / air-gapped deployments where no out-of-tree code may execute. |

On first successful load the manager prints a one-line stderr banner naming each loaded plugin entry, e.g. `[plugins] loaded 1: my_plugin/ (YGGDRASIM_ALLOW_PLUGINS=1; set YGGDRASIM_DISALLOW_PLUGINS=1 to hard-lock plugin loading).`. If you do not see that line and plugin-owned commands are missing, the loader was refused by the default-deny posture or by one of the env flags above.

## SCP11 local access

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `CI PKID unavailable` at AuthenticateServer | certificate chain not trusted | drop the correct certs into `SCP11/local_access/certs/` or runtime root |
| `No profile selected` | missing `PROFILE <path>` in this session | issue `PROFILE` before `LOAD-PROFILE` |
| Metadata store rejected | field out of card's accepted range | lint metadata, adjust JSON |

## SCP11 eIM local

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `ADD-INITIAL-EIM` rejected | BF55 row already populated or overwrite not allowed | check `Workspace/SIMCARD/isdr_config.json` simulator-side, or use `ADD-EIM` |
| optional relay verbs absent from SCP11 shells | local command extension not loaded | same opt-in and hard-lock checks as above. |
| Hotfolder empty after drop | wrong directory | confirm the runtime root `SCP11/eim_local/eim_packages/hotfolder/` |

## HIL bridge

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| supervisor `usbPresent: false` | SIMtrace2 not enumerated | check `dmesg`, `lsusb`, USB permissions |
| relay never reports `status: ok` | `osmo-remsim-client-st2` failing | check its stderr, verify firmware |
| missing `atr` in relay state | card not powered or inserted | reseat card |
| `reader busy` in a YggdraSIM shell | direct PC/SC handle used while bridge owns the reader | route through the relay |
| `Card source: remote` never appears | bridge is still using local PC/SC mode | pass `--remote-card-url` and `--remote-card-token-file` to the bridge or supervisor |

## Profile package

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `hex parse failed` on `.txt` input | separators or `0x` prefixes | strip to pure hex |
| Lint flags PE ordering | non-compliant PE order | reorder in the TUI or in the source |
| `RAW` unavailable | external `saip-tool` not on `PATH` | set path with `TOOL <path>` |

## Runtime root and state

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `state/device_inventory.sqlite3` created in an unexpected place | `YGGDRASIM_RUNTIME_ROOT` or frozen-build resolution | check [Runtime Root](runtime-root.md) |
| GPG decrypt fails at read time | agent not running or wrong `GNUPGHOME` | start agent, set `GNUPGHOME` |
| `RuntimeError: GPG inventory {encryption,decryption} timed out; check gpg-agent / pinentry availability.` | smart-card-backed recipient, stuck `pinentry`, or dead `gpg-agent` | restart `gpg-agent`, clear `pinentry`, or raise `gpg.timeout_seconds` in `state/inventory_crypto.json`. See [Enable Inventory Encryption](../how-to/enable-inventory-encryption.md). |

## Related pages

- [FAQ](faq.md)
- [Glossary](glossary.md)
- [Runtime Root](runtime-root.md)
- [State Schema](state-schema.md)
- [Remote APDU Streaming](../how-to/remote-apdu-streaming.md)
- [Install RemSIM / APDU Streaming](../how-to/install-remsim-apdu-streaming.md)
