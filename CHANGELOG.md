# Changelog

All notable changes to YggdraSIM are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
honours [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for
the public API surface — the launcher, the documented CLI shells, the
SCP03 / SCP11 / SCP80 / SIMCARD module entry points, and the
`yggdrasim_common` helpers consumed by external integrators.

Internal helpers (modules under leading-underscore names, undocumented
SAIP wrappers, and any path explicitly marked
`work-in-progress` in `V2_ROADMAP.md`) may change without notice
between minor releases.

## [Unreleased]

### Added

- R2-005 Tools tier staging (work-in-progress per `V2_ROADMAP.md`):
  in-process `Tools/YggdraCore/` stubs (subscription store, AUSF
  stub, AAnF stub, FastAPI loopback, BYO Open5GS bridge);
  `Tools/Sunrise6G/` QoD / Location / models stubs; local-loopback
  `Tools/CardBridge/` HTTP card-relay daemon. The HTTP / CLI surface
  hardening, BYO-Open5GS resilience checks, and the public docs
  pass for these modules are still pending — they are not part of
  the v1.0.0 promise.

## [1.0.0] — 2026-04-29

First SemVer-tagged release. Cut at git tag `v1.0.0`. Pinned commit
exposes a frozen v1 footprint; the v2 staging continues on `main`.

### Added

- Default eUICC identity is now the BCD-clean self-documenting marker
  `89045967676472615349763031303005` (decodes as
  `\x89\x04YggdraSIv0100\x05` in any hex viewer; SGP.02 §2.2.2 telecom
  MII `89` retained; ITU-T E.118 / SGP.22 §4.11.2 Luhn = 5).
- SIMCARD 5G core: TS 33.501 Annex A AKA helpers (`SIMCARD/aka_5g.py`),
  TS 33.535 AKMA (`SIMCARD/akma.py`), TS 33.501 §C.3 SUCI Profile A & B
  with EF.SUCI_Calc_Info codec (`SIMCARD/suci.py`), TS 31.102 §7.1.2.4
  `GET IDENTITY` handler (`SIMCARD/identity.py`).
- IPA poll over DNS resolution (`SIMCARD/ipa_poll_dns.py`) and TLS
  transport (`SIMCARD/ipa_tls.py`); SAIP pySIM specs bridge
  (`SIMCARD/saip_pysim_specs.py`); SGP.32 package surfaces
  (`SIMCARD/sgp32_packages.py`); modem write persistence; shared EF
  mirror; legacy GSM modem attach path; FCP decoder; GFM walker;
  service-table staging.
- SAIP PE editors (`Tools/ProfilePackage/saip_pe_editors/`); SAIP
  profile diff engine and loader; AT-simlink modem bridge
  (`Tools/HilBridge/at_simlink.py`); APDU relay auth.
- SCP03 STK ETSI defaults / conformance, service-table decoders /
  staging, card-backend relay-token plumbing, doctor card-relay
  probe.
- SCP11 shared profile-actions module, card-overview renderer,
  eim_local live-delete auto-disable.
- yggdrasim_common: APDU recorder + WebSocket stream, card-bridge
  bearer-token helper (`card_bridge_auth.py`), Nord palette,
  remote-card argument parsing.
- Documentation: configuration & certificates guide, GUI host shell
  guide, "Load certificates and config" how-to recipe.
- `tests/live_scp03/` golden inputs for the SCP03 admin shell.
- Demo scripts under `scripts/demos/` covering 3GPP attach, eIM
  polling, and profile lifecycle.

### Changed

- `pyproject.toml` version moves from CalVer `2026.4.10` to SemVer
  `1.0.0`. Both `yggdrasim_common.__about__` and the launcher's
  `--version` resolve to the new value through the existing dynamic
  pyproject lookup.
- HilBridge live decode TUI: ISO/IEC 7816-4 `MANAGE CHANNEL`
  (INS=0x70) is now classified into the STK group ahead of the BIP
  marker scan, so `MANAGE CHANNEL Operation=Open Channel` frames no
  longer fall into the unbound-channel tail in the decoded-APDU view.
- All hard-coded EID test fixtures that used to pin the previous
  default updated to the new BCD marker; tests that exercise
  `isdr_config` overrides keep their distinct fixtures.

### Removed

- `bridge` and `modem` zero-byte scratch files at the repo root.
- Legacy `YggdraSIM-docs-oneot.zip` documentation snapshot. The
  same content is canonically tracked in `site-docs/`.

### Security / Repo Hygiene

- `reports/` is now ignored. Live SCP03 capture reports contain
  derived session keys (s_enc / s_mac / s_rmac) and chaining
  values; pushing them to a shared remote was a foot-gun. The
  `reports/.gitkeep` placeholder documents the intended layout.

[Unreleased]: https://example.invalid/yggdrasim/compare/v1.0.0...HEAD
[1.0.0]: https://example.invalid/yggdrasim/releases/tag/v1.0.0
